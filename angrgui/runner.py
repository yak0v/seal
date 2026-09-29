"""
The dynamic side: turn a function's *assumptions* into an initial angr state,
install the *checks*, explore, and collect the paths (as a tree) plus every hit.

A "run spec" (what the UI sends) looks like:

{
  "func_addr": 0x401196,
  "args": [                       # per argument, how to seed it
     {"name":"count","mode":"symbolic","size":4,"signed":false},
     {"name":"size","mode":"concrete","value":8,"size":4}
  ],
  "buffers": [                    # symbolic memory a pointer arg points at
     {"arg":"hdr","size":16}
  ],
  "assumptions": ["count < 0x100000", "size != 0"],   # exprlang constraints
  "stdin": {"mode":"symbolic","size":8},              # optional
  "checks": [ ...check specs... ],
  "limits": {"steps":200,"active":400,"seconds":30,"find":null,"avoid":[]}
}
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import angr
import claripy

from .checks import CheckContext, build_check, Hit
from .exprlang import make_evaluator, as_bool, ExprError

log = logging.getLogger("angrgui.runner")

_SIZE_TO_REG = None


@dataclass
class PathNode:
    id: int
    addr: int
    parent: int | None
    depth: int
    kind: str = "active"          # active|deadended|found|avoided|errored|pruned|unconstrained
    block_addrs: list = field(default_factory=list)
    label: str = ""
    hit_ids: list = field(default_factory=list)

    def to_json(self):
        return {
            "id": self.id, "addr": self.addr, "parent": self.parent, "depth": self.depth,
            "kind": self.kind, "label": self.label,
            "blocks": [hex(b) for b in self.block_addrs[-6:]], "hits": self.hit_ids,
        }


class Run:
    """One exploration job. Runs on a background thread; progress-pollable."""

    def __init__(self, binary, spec: dict):
        self.binary = binary
        self.spec = spec
        self.project = binary.project
        self.arch = binary.arch
        self.func_addr = spec["func_addr"]
        self.func = binary.get_function(self.func_addr)

        self.status = "pending"       # pending|running|done|error|cancelled
        self.error: str | None = None
        self.progress = {"step": 0, "active": 0, "deadended": 0, "found": 0,
                         "hits": 0, "elapsed": 0.0, "message": "queued"}
        self._cancel = threading.Event()
        self._lock = threading.Lock()

        self.checks = []
        self._state_checks = []
        self.hits: list[Hit] = []
        self.nodes: dict[int, PathNode] = {}
        self._node_counter = 0
        self._seen_leaves: set = set()          # id(state) of leaves already classified
        self.start_time = None
        self.summary: dict = {}

    # ------------------------------------------------------------------ control
    def cancel(self):
        self._cancel.set()

    def start(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()
        return t

    # ----------------------------------------------------------- state building
    def _arg_bv(self, argspec, index):
        size = int(argspec.get("size") or self.arch.bytes)
        bits = size * 8
        name = argspec.get("name") or f"arg{index}"
        mode = argspec.get("mode", "symbolic")
        if mode == "concrete":
            val = int(argspec.get("value", 0))
            return claripy.BVV(val & ((1 << bits) - 1), bits), False
        return claripy.BVS(name, bits), True

    def _build_state(self):
        opts = {
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        }
        args = self.spec.get("args", [])
        arg_asts = []
        named = {}
        for i, a in enumerate(args):
            bv, symbolic = self._arg_bv(a, i)
            arg_asts.append(bv)
            named[a.get("name") or f"arg{i}"] = bv

        # Point the requested pointer arguments at fresh symbolic buffers.
        buffers = {}
        for b in self.spec.get("buffers", []):
            argname = b["arg"]
            size = int(b.get("size", 64))
            buf = claripy.BVS(f"{argname}_buf", size * 8)
            buffers[argname] = (buf, size)

        prototype = self._prototype(args, buffers)
        state = self.project.factory.call_state(
            self.func_addr, *arg_asts, prototype=prototype, add_options=opts)

        # Allocate + fill buffers, repoint the pointer args.
        base = 0x600000
        for argname, (buf, size) in buffers.items():
            addr = base
            base += (size + 0xfff) & ~0xfff
            state.memory.store(addr, buf, endness="Iend_BE")
            named[f"{argname}_buf"] = buf
            # overwrite the corresponding register/stack slot with the pointer
            idx = next((i for i, a in enumerate(args) if a.get("name") == argname), None)
            if idx is not None:
                self._set_arg(state, idx, claripy.BVV(addr, self.arch.bits), prototype)

        # stdin
        stdin_spec = self.spec.get("stdin")
        stdin_sym = None
        if stdin_spec and stdin_spec.get("mode") == "symbolic":
            n = int(stdin_spec.get("size", 16))
            stdin_sym = claripy.BVS("stdin", n * 8)
            simfile = angr.SimFileStream(name="stdin", content=stdin_sym, has_end=True)
            state.posix.stdin = simfile
            state.globals["angrgui_stdin"] = stdin_sym

        state.globals["angrgui_vars"] = named
        state.globals["angrgui_locals"] = self._locals_map()

        # assumptions
        applied = []
        for src in self.spec.get("assumptions", []):
            src = src.strip()
            if not src:
                continue
            try:
                ast = as_bool(make_evaluator(state)(src))
                state.add_constraints(ast)
                applied.append(src)
            except ExprError as e:
                raise ValueError(f"assumption {src!r}: {e}")
        self.summary["assumptions_applied"] = applied
        return state

    def _prototype(self, args, buffers):
        parts = []
        for a in args:
            nm = a.get("name")
            if nm in buffers:
                parts.append("void *")
            else:
                sz = int(a.get("size") or self.arch.bytes)
                signed = a.get("signed", True)
                parts.append({1: "char", 2: "short", 4: "int", 8: "long long"}.get(sz, "long long")
                             if signed else
                             {1: "unsigned char", 2: "unsigned short", 4: "unsigned int",
                              8: "unsigned long long"}.get(sz, "unsigned long long"))
        proto = f"long long f({', '.join(parts) or 'void'})"
        return proto

    def _set_arg(self, state, index, value, prototype):
        cc = self.project.factory.cc()
        try:
            locs = cc.arg_locs(self.project.factory.function_prototype(prototype)
                               if isinstance(prototype, str) else prototype)
            loc = locs[index]
            loc.set_value(state, value)
        except Exception:
            # fall back to the SysV integer registers
            regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            if index < len(regs):
                setattr(state.regs, regs[index], value)

    def _locals_map(self):
        out = {}
        for v in self.binary.dwarf_vars(self.func_addr):
            if v.sort == "stack":
                out[v.name] = {"offset": v.frame_offset(self.arch.bytes), "size": v.size or self.arch.bytes}
        return out

    # ------------------------------------------------------------------ checks
    def _make_context(self):
        lo = self.func_addr
        hi = self.func_addr + (self.func.size or 0x1000)
        rets = self.binary.return_block_heads(self.func_addr)

        def line_for(addr):
            e = self.binary.line_for(addr)
            return {"file": e[0].split("/")[-1], "line": e[1]} if e else None

        def path_of(state):
            return [hex(a) for a in list(state.history.bbl_addrs)[-8:]]

        return CheckContext(
            target_func_lo=lo, target_func_hi=hi, return_addrs=rets,
            line_for=line_for, path_of=path_of, on_hit=self._on_hit,
            block_head=self.binary.block_head,
        )

    def _on_hit(self, hit: Hit):
        with self._lock:
            self.hits.append(hit)
            self.progress["hits"] = len(self.hits)

    # ------------------------------------------------------------------- tree
    def _new_node(self, addr, parent, depth, kind="active"):
        nid = self._node_counter
        self._node_counter += 1
        node = PathNode(id=nid, addr=addr, parent=parent, depth=depth, kind=kind)
        f = self.binary.cfg.kb.functions
        e = self.binary.line_for(addr)
        node.label = f"{addr:#x}" + (f"  ·  {e[0].split('/')[-1]}:{e[1]}" if e else "")
        self.nodes[nid] = node
        return node

    # -------------------------------------------------------------------- run
    def _run(self):
        self.start_time = time.time()
        try:
            self.status = "running"
            self.progress["message"] = "building initial state"
            state = self._build_state()

            ctx = self._make_context()
            self._state_checks = []
            for cspec in self.spec.get("checks", []):
                if not cspec.get("enabled", True):
                    continue
                chk = build_check(cspec, ctx)
                chk.install(state)
                self.checks.append(chk)
                # every check except the expr-driven overflow check observes block heads
                if chk.kind != "int_overflow":
                    self._state_checks.append(chk)

            self.progress["message"] = "exploring"
            simgr = self.project.factory.simgr(state, save_unconstrained=True)

            root = self._new_node(self.func_addr, None, 0)
            state.globals["angrgui_node"] = root.id

            limits = self.spec.get("limits", {})
            max_steps = int(limits.get("steps", 200))
            max_active = int(limits.get("active", 400))
            max_seconds = float(limits.get("seconds", 30))
            loop_bound = int(limits.get("loop_bound", 12) or 0)
            find = limits.get("find")
            avoid = set(limits.get("avoid", []) or [])
            if find:
                find = int(find)

            # Bound loop iterations so a loop with a symbolic trip count can't unroll
            # forever; over-the-bound states go to the 'spinning' stash.
            if loop_bound > 0:
                try:
                    from angr.exploration_techniques import LoopSeer
                    simgr.use_technique(LoopSeer(
                        cfg=self.binary.cfg, functions=[self.func],
                        bound=loop_bound, limit_concrete_loops=False))
                except Exception as e:  # best effort
                    log.warning("loop bounding unavailable: %s", e)

            step = 0
            while simgr.active and step < max_steps:
                if self._cancel.is_set():
                    self.status = "cancelled"
                    break
                if time.time() - self.start_time > max_seconds:
                    self.progress["message"] = "time budget reached"
                    break

                simgr.step()
                self._absorb(simgr, find, avoid)

                step += 1
                with self._lock:
                    self.progress.update(
                        step=step, active=len(simgr.active),
                        deadended=len(simgr.deadended),
                        found=len(getattr(simgr, "found", [])),
                        elapsed=round(time.time() - self.start_time, 2),
                    )
                if len(simgr.active) > max_active:
                    # keep the search bounded; stash the overflow
                    extra = simgr.active[max_active:]
                    simgr.active[:] = simgr.active[:max_active]
                    for s in extra:
                        n = s.globals.get("angrgui_node")
                        if n is not None and n in self.nodes:
                            self.nodes[n].kind = "pruned"

            if self.status == "running":
                self.status = "done"
            self.progress["message"] = f"finished ({self.status})"
            self._finalize(simgr)
        except Exception as e:
            self.status = "error"
            self.error = f"{type(e).__name__}: {e}"
            log.exception("run failed")
            self.progress["message"] = self.error

    def _absorb(self, simgr, find, avoid):
        # Gather every fresh successor from this step, tagged with its fate.
        succ: list[tuple] = [(s, "active") for s in simgr.active]
        for stash, kind in (("deadended", "deadended"), ("errored", "errored"),
                            ("unconstrained", "unconstrained"), ("spinning", "pruned")):
            for item in getattr(simgr, stash, []):
                st = item.state if stash == "errored" else item
                if id(st) in self._seen_leaves:
                    continue
                self._seen_leaves.add(id(st))
                succ.append((st, kind))

        # Count successors per parent node so we can tell branches from straight lines.
        parent_count: dict = {}
        for s, _ in succ:
            pn = s.globals.get("angrgui_node")
            parent_count[pn] = parent_count.get(pn, 0) + 1

        for s, fate in succ:
            pn = s.globals.get("angrgui_node")
            if pn is None or pn not in self.nodes:
                node = self._new_node(s.addr, None, 0)
                s.globals["angrgui_node"] = node.id
                cur = node.id
            elif parent_count.get(pn, 1) > 1:
                # the parent split here: every successor gets its own child node
                child = self._new_node(s.addr, pn, self.nodes[pn].depth + 1)
                s.globals["angrgui_node"] = child.id
                cur = child.id
            else:
                cur = pn
            node = self.nodes[cur]
            node.addr = s.addr
            node.block_addrs = list(s.history.bbl_addrs)
            node.label = self._label(s.addr)
            if fate != "active":
                node.kind = fate
            if find and s.addr == find:
                node.kind = "found"
            if s.addr in avoid:
                node.kind = "avoided"
            # state-point checks (assert/reach/avoid/custom) observe states at block
            # boundaries, where register and memory reads are committed and reliable
            for chk in self._state_checks:
                chk.note_state(s)

    def _label(self, addr):
        e = self.binary.line_for(addr)
        return f"{addr:#x}" + (f"  ·  {e[0].split('/')[-1]}:{e[1]}" if e else "")

    def _finalize(self, simgr):
        # attach hit ids to the nodes whose path reaches them
        for i, h in enumerate(self.hits):
            for nid, node in self.nodes.items():
                if h.addr in [int(x, 16) if isinstance(x, str) else x for x in node.block_addrs] \
                        or node.addr == h.addr:
                    node.hit_ids.append(i)
        self.summary.update({
            "status": self.status,
            "steps": self.progress["step"],
            "active": len(simgr.active),
            "deadended": len(simgr.deadended),
            "errored": len(getattr(simgr, "errored", [])),
            "unconstrained": len(getattr(simgr, "unconstrained", [])),
            "found": len(getattr(simgr, "found", [])),
            "hits": len(self.hits),
            "nodes": len(self.nodes),
            "elapsed": self.progress["elapsed"],
        })

    # ---------------------------------------------------------------- reporting
    def snapshot(self):
        with self._lock:
            return {
                "status": self.status,
                "error": self.error,
                "progress": dict(self.progress),
                "summary": self.summary,
                "hits": [h.to_json() for h in self.hits],
                "tree": [n.to_json() for n in self.nodes.values()],
            }
