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

from .checks import CheckContext, build_check, Hit, witness_of
from .exprlang import make_evaluator, as_bool, ExprError
from .pretty import printer_for_state

log = logging.getLogger("angrgui.runner")


@dataclass
class PathNode:
    """One stretch of execution between two branch points.

    The root starts at the function entry; every time a state splits (a branch
    whose direction depends on the inputs), each side gets a child node labelled
    with the condition the inputs must satisfy to go that way.
    """
    id: int
    addr: int                     # where this stretch starts
    parent: int | None
    depth: int
    kind: str = "active"          # active|deadended|found|avoided|errored|pruned|unconstrained
    cond: str | None = None       # readable branch condition that leads here
    decided_at: dict | None = None  # the branch instruction + its source line
    block_addrs: list = field(default_factory=list)   # blocks executed in this stretch
    cur: int | None = None        # where the state is now
    end: dict | None = None       # leaves: {"reason", "text"}
    ret: str | None = None        # leaves that returned: the return value
    example: dict | None = None   # leaves: concrete inputs that drive execution down this path
    hit_ids: list = field(default_factory=list)


class Run:
    """One exploration job. Runs on a background thread; progress-pollable."""

    def __init__(self, binary, spec: dict, on_event=None):
        self.binary = binary
        self.spec = spec
        self.on_event = on_event      # optional callback(type, **data) for the live feed
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
        self._printer = str
        self._return_addr = None
        self._loop_bound = 0

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
        if self.spec.get("limits", {}).get("skip_calls"):
            # don't descend into called functions: a call returns a fresh unconstrained
            # value, so exploration stays in the target function and its branches show.
            opts.add(angr.options.CALLLESS)
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

        # stdin has to be handed to call_state: swapping state.posix.stdin afterwards
        # leaves the file uninitialised and the first state copy crashes
        stdin_spec = self.spec.get("stdin")
        stdin_sym = None
        extra = {}
        if stdin_spec and stdin_spec.get("mode") == "symbolic":
            n = int(stdin_spec.get("size", 16))
            stdin_sym = claripy.BVS("stdin", n * 8)
            extra["stdin"] = angr.SimFileStream(name="stdin", content=stdin_sym, has_end=True)

        prototype = self._prototype(args, buffers)
        state = self.project.factory.call_state(
            self.func_addr, *arg_asts, prototype=prototype, add_options=opts, **extra)
        if stdin_sym is not None:
            named["stdin"] = stdin_sym
            state.globals["angrgui_stdin"] = stdin_sym

        # symbolic files: the program reads a named file whose contents we make symbolic
        # (a CTF "file checker" reads e.g. .password). Registered in the state filesystem,
        # so fopen()/open() of that name return our symbolic content.
        file_syms = {}
        for fspec in self.spec.get("files", []) or []:
            fname = fspec.get("name") or "input"
            n = int(fspec.get("size", 16))
            fb = claripy.BVS(f"file_{fname}", n * 8)
            state.fs.insert(fname, angr.SimFile(fname, content=fb, size=n))
            file_syms[fname] = fb
        state.globals["angrgui_files"] = file_syms

        # Allocate + fill buffers, repoint the pointer args.
        base = self.binary.scratch_base()
        for argname, (buf, size) in buffers.items():
            addr = base
            base += (size + 0xfff) & ~0xfff
            state.memory.store(addr, buf, endness="Iend_BE")
            named[f"{argname}_buf"] = buf
            named[argname] = claripy.BVV(addr, self.arch.bits)   # the pointer itself is concrete
            # overwrite the corresponding register/stack slot with the pointer
            idx = next((i for i, a in enumerate(args) if a.get("name") == argname), None)
            if idx is not None:
                self._set_arg(state, idx, claripy.BVV(addr, self.arch.bits), prototype)

        state.globals["angrgui_vars"] = named
        state.globals["angrgui_argv"] = arg_asts    # ordered, for the a1.. / arg0.. aliases
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

    # ----------------------------------------------------------- call models (hooks)
    MODEL_REGION = 0x40000      # size of each buffer a hooked allocator hands back

    def _make_model_proc(self, m):
        """A SimProcedure that replaces a called function with a simple model:
        return a fresh symbolic value, a constant, one of the arguments, or a freshly
        allocated buffer (whose logical size is one argument, tracked for OOB checks)."""
        kind = m.get("kind", "symbolic")
        bits = self.arch.bits
        region = self.MODEL_REGION
        # SysV AMD64 integer argument registers, in order (this tool targets x86-64)
        ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")

        def remember(state, name, val):
            vs = dict(state.globals.get("angrgui_vars", {}))
            vs[name] = val
            state.globals["angrgui_vars"] = vs

        def argval(state, i):
            return getattr(state.regs, ARG_REGS[i]) if i < len(ARG_REGS) else claripy.BVV(0, bits)

        if kind == "concrete":
            val = int(m.get("value", 0)) & ((1 << bits) - 1)
            class P(angr.SimProcedure):
                def run(self):
                    return claripy.BVV(val, bits)
        elif kind == "return_arg":
            idx = int(m.get("arg", 0))
            class P(angr.SimProcedure):
                def run(self):
                    return argval(self.state, idx)
        elif kind == "alloc":
            sidx = int(m.get("size_arg", 0))
            nm = m.get("name")
            class P(angr.SimProcedure):
                def run(self):
                    size = argval(self.state, sidx)
                    base = self.state.heap.allocate(region)
                    allocs = self.state.globals.get("angrgui_allocs", ())
                    self.state.globals["angrgui_allocs"] = allocs + ((base, size, base + region),)
                    if nm:
                        remember(self.state, nm, claripy.BVV(base, bits))
                    return claripy.BVV(base, bits)
        else:   # "symbolic" (default)
            nm = m.get("name") or (str(m.get("func")) + "_ret")
            rb = int(m.get("bits") or bits)
            class P(angr.SimProcedure):
                def run(self):
                    v = claripy.BVS(nm, rb)
                    remember(self.state, nm, v)
                    return v
        P.display_name = "model_" + str(m.get("func"))
        return P()

    def _install_models(self, state):
        self._hooked = []
        for m in (self.spec.get("models") or []):
            target = m.get("func")
            if not target:
                continue
            try:
                proc = self._make_model_proc(m)
                if isinstance(target, str) and target.lower().startswith("0x"):
                    addr = int(target, 16)
                    self.project.hook(addr, proc, replace=True)
                elif isinstance(target, int):
                    addr = target
                    self.project.hook(addr, proc, replace=True)
                else:
                    addr = self.project.hook_symbol(target, proc, replace=True)
                self._hooked.append(addr)
            except Exception as e:
                log.warning("could not model %r: %s", target, e)

    def _unhook(self):
        for a in getattr(self, "_hooked", []):
            try:
                self.project.unhook(a)
            except Exception:
                pass
        self._hooked = []

    def _prototype(self, args, buffers):
        parts = []
        for a in args:
            nm = a.get("name")
            if nm in buffers:
                parts.append("void *")
            elif a.get("float"):
                parts.append("float" if int(a.get("size") or 8) == 4 else "double")
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

    def _emit(self, kind, **data):
        if self.on_event:
            try:
                self.on_event(kind, **data)
            except Exception:
                pass

    def _on_hit(self, hit: Hit, state):
        with self._lock:
            # the state carries the id of the tree node (path stretch) it belongs to
            nid = state.globals.get("angrgui_node") if state is not None else None
            hit.extra["node"] = nid
            self.hits.append(hit)
            if nid in self.nodes:
                self.nodes[nid].hit_ids.append(len(self.hits) - 1)
            self.progress["hits"] = len(self.hits)
        self._emit("finding", func=self.func_addr, check_kind=hit.kind, addr=hit.addr, detail=hit.message)

    # ------------------------------------------------------------------- tree
    def _new_node(self, addr, parent, depth, kind="active"):
        nid = self._node_counter
        self._node_counter += 1
        node = PathNode(id=nid, addr=addr, parent=parent, depth=depth, kind=kind, cur=addr)
        self.nodes[nid] = node
        return node

    def _branch_condition(self, state) -> str | None:
        """The constraint(s) this step added: what the inputs must satisfy to come here."""
        cons = []
        for c in state.history.recent_constraints:
            c = getattr(c, "ast", c)
            if isinstance(c, claripy.ast.Bool) and c.symbolic:
                cons.append(c)
        if not cons:
            g = state.history.jump_guard
            if isinstance(g, claripy.ast.Bool) and g.symbolic:
                cons.append(g)
        if not cons:
            return None
        # show the whole condition (a generous cap guards only pathological cases)
        fmt = (lambda c: self._printer(c, limit=4000)) if self._printer is not str else str
        return " && ".join(fmt(c) for c in cons)

    def _decision_point(self, parent: PathNode) -> dict | None:
        """The branch instruction that ended the parent's stretch, with its source line."""
        if not parent.block_addrs:
            return None
        try:
            ins = self.project.factory.block(parent.block_addrs[-1]).instruction_addrs[-1]
        except Exception:
            return None
        return {"addr": ins, **(self.binary.source_at(ins) or {})}

    def _close(self, node: PathNode, state, fate: str, error: str | None = None):
        """Record how a leaf path ended, and a concrete input that gets there."""
        last = node.block_addrs[-1] if node.block_addrs else node.addr
        if fate == "deadended" and state.addr == self._return_addr:
            node.end = {"reason": "returned", "text": "returned"}
            try:
                rv = getattr(state.regs, self.arch.register_names[self.arch.ret_offset])
                node.ret = self._fmt_value(state, rv)
            except Exception:
                pass
        elif fate == "deadended" and state.history.jumpkind == "Ijk_Exit":
            name = self.binary.name_at(last) or "exit"
            node.end = {"reason": "exit", "text": f"called {name}(), the program stops"}
        elif fate == "deadended":
            node.end = {"reason": "ended", "text": "execution ended"}
        elif fate == "pruned":
            node.end = {"reason": "loop_bound",
                        "text": f"stopped: a loop ran more than {self._loop_bound} times (loop bound)"}
        elif fate == "unconstrained":
            node.end = {"reason": "unconstrained",
                        "text": "jumped to an address the inputs control (possible control-flow hijack)"}
        elif fate == "errored":
            node.end = {"reason": "error", "text": "angr error: " + (error or "unknown")}
        try:
            node.example = witness_of(state) or None
        except Exception:
            node.example = None

    def _ret_insn(self, state) -> int:
        """Address of the return instruction the state just executed (for reporting)."""
        for b in reversed(list(state.history.bbl_addrs)):
            if self.binary.get_function(self.func_addr) and self.func_addr <= b < self.func_addr + (self.func.size or 0x1000):
                try:
                    return self.project.factory.block(b).instruction_addrs[-1]
                except Exception:
                    return b
        return self.func_addr

    def _fmt_value(self, state, v) -> str:
        if not v.symbolic:
            n = state.solver.eval(v)
            if (1 << 31) <= n < (1 << 32):
                return f"{n:#x} (= {n - (1 << 32)} as int)"
            return str(n) if n < 4096 else hex(n)
        return self._printer(v)

    # -------------------------------------------------------------------- run
    def _run(self):
        self.start_time = time.time()
        try:
            self.status = "running"
            self.progress["message"] = "building initial state"
            state = self._build_state()
            self._install_models(state)

            ctx = self._make_context()
            self._state_checks = []
            for cspec in self.spec.get("checks", []):
                if not cspec.get("enabled", True):
                    continue
                chk = build_check(cspec, ctx)
                chk.install(state)
                self.checks.append(chk)
                # breakpoint-driven checks (overflow / narrowing / float / oob) run from
                # their inspect hooks; the rest observe block heads via note_state
                if not getattr(chk, "installs_breakpoint", False):
                    self._state_checks.append(chk)

            self.progress["message"] = "exploring"
            simgr = self.project.factory.simgr(state, save_unconstrained=True)

            root = self._new_node(self.func_addr, None, 0)
            state.globals["angrgui_node"] = root.id
            self._printer = printer_for_state(state)
            self._return_addr = self.project.simos.return_deadend

            limits = self.spec.get("limits", {})
            max_steps = int(limits.get("steps", 200))
            max_active = int(limits.get("active", 400))
            max_seconds = float(limits.get("seconds", 30))
            loop_bound = int(limits.get("loop_bound", 12) or 0)
            self._loop_bound = loop_bound
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
                            node = self.nodes[n]
                            node.kind = "pruned"
                            node.end = {"reason": "dropped",
                                        "text": f"dropped: more than {max_active} paths were active at once (max active)"}
                            node.example = witness_of(s) or None

            if self.status == "running":
                self.status = "done"
            self.progress["message"] = f"finished ({self.status})"
            self._finalize(simgr)
        except Exception as e:
            self.status = "error"
            self.error = f"{type(e).__name__}: {e}"
            log.exception("run failed")
            self.progress["message"] = self.error
        finally:
            self._unhook()                 # models are installed on the shared project
        self._emit("run_status", func=self.func_addr, status=self.status,
                   hits=len(self.hits), error=self.error)

    def _absorb(self, simgr, find, avoid):
        # Gather every fresh successor from this step, tagged with its fate.
        succ: list[tuple] = [(s, "active", None) for s in simgr.active]
        for stash, kind in (("deadended", "deadended"), ("errored", "errored"),
                            ("unconstrained", "unconstrained"), ("spinning", "pruned")):
            for item in getattr(simgr, stash, []):
                st = item.state if stash == "errored" else item
                if id(st) in self._seen_leaves:
                    continue
                self._seen_leaves.add(id(st))
                succ.append((st, kind, str(item.error) if stash == "errored" else None))

        # Count successors per parent node so we can tell branches from straight lines.
        parent_count: dict = {}
        for s, _, _ in succ:
            pn = s.globals.get("angrgui_node")
            parent_count[pn] = parent_count.get(pn, 0) + 1

        extended = set()
        for s, fate, err in succ:
            pn = s.globals.get("angrgui_node")
            recent = list(s.history.recent_bbl_addrs)
            if pn is None or pn not in self.nodes:
                node = self._new_node(s.addr, None, 0)
                node.block_addrs.extend(recent)
                s.globals["angrgui_node"] = node.id
            elif parent_count.get(pn, 1) > 1:
                # the parent split here: the block that branched belongs to the parent,
                # and every successor starts its own child stretch
                parent = self.nodes[pn]
                if pn not in extended:
                    parent.block_addrs.extend(recent)
                    extended.add(pn)
                node = self._new_node(s.addr, pn, parent.depth + 1)
                node.cond = self._branch_condition(s)
                node.decided_at = self._decision_point(parent)
                s.globals["angrgui_node"] = node.id
            else:
                node = self.nodes[pn]
                node.block_addrs.extend(recent)
            node.cur = s.addr
            if fate != "active":
                node.kind = fate
                self._close(node, s, fate, err)
            if find and s.addr == find:
                node.kind = "found"
            if s.addr in avoid:
                node.kind = "avoided"
            # state-point checks (assert/reach/avoid/custom) observe states at block
            # boundaries, where register and memory reads are committed and reliable
            for chk in self._state_checks:
                chk.note_state(s)
            # at_return asserts are evaluated once the state has actually returned,
            # where the return register is final (it may be set inside the return block)
            if fate == "deadended" and s.addr == self._return_addr:
                ret_site = self._ret_insn(s)
                for chk in self._state_checks:
                    chk.note_return(s, ret_site)

    def _finalize(self, simgr):
        # paths still active when the budget ran out
        for s in simgr.active:
            node = self.nodes.get(s.globals.get("angrgui_node"))
            if node is not None and node.end is None:
                node.end = {"reason": "unfinished",
                            "text": "not finished: stopped by the step / time limit (or cancelled)"}
                node.example = witness_of(s) or None
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
    def _node_json(self, n: PathNode) -> dict:
        blocks = n.block_addrs[:400]
        lines, calls = [], []
        for b in blocks:
            for ln in self.binary.block_source_lines(b):
                if ln not in lines:
                    lines.append(ln)
            if b != self.func_addr:
                name = self.binary.name_at(b)
                if name and name not in calls:
                    calls.append(name)
        return {
            "id": n.id, "parent": n.parent, "depth": n.depth, "kind": n.kind,
            "addr": n.addr, "cur": n.cur, "start": self.binary.source_at(n.addr),
            "cond": n.cond, "decided_at": n.decided_at,
            "blocks": blocks, "lines": lines, "calls": calls,
            "end": n.end, "ret": n.ret, "example": n.example, "hits": list(n.hit_ids),
        }

    def snapshot(self):
        with self._lock:
            return {
                "status": self.status,
                "error": self.error,
                "progress": dict(self.progress),
                "summary": self.summary,
                "hits": [h.to_json() for h in self.hits],
                "tree": [self._node_json(n) for n in list(self.nodes.values())],
            }
