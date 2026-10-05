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

ROLE
----
``Run`` owns one exploration: it builds the initial ``SimState`` from the spec,
installs the checks, drives the ``SimulationManager``, records the path tree +
findings, and emits live events. ``trace_assignments`` is a separate concrete
re-execution used only to annotate decompilation lines with per-line values.

WHY IT'S LIKE THIS
------------------
* **Two ways to build the start state (``_build_state``).** A fresh *call_state*
  (symbolic args — the classic CTF/library workflow) OR a *snapshot* seed when the
  spec carries ``initial_state.kind == "snapshot"`` (concolic: start from a REAL
  captured machine state and make only the marked fields symbolic). The snapshot path
  is what lets SEAL analyse deep, context-heavy code (e.g. a CoreGraphics rasterizer)
  without the state explosion of all-symbolic inputs.
* **``_set_arg`` is arch-aware on purpose.** It used to hard-code x86-64 arg registers
  (``rdi``/``rsi``/…) and crashed with ``KeyError: 'rdi'`` on AArch64. It now resolves
  argument locations from the calling convention / prototype, falling back to the
  per-arch register list — so the same run spec works on x86-64 and arm64(e).
* **Snapshot seeding has a sharp subtlety (``_build_state_from_snapshot``).** The
  captured ``regs`` dict *includes* ``pc`` (the capture address). If we blindly set every
  register, that ``pc`` would overwrite the ``blank_state(addr=...)`` start address — so a
  caller could never seed MID-function. We therefore SKIP ``pc``/``ip`` in the register
  loop and set ``pc`` authoritatively from the snapshot's top-level ``pc``. This is what
  makes "start at the xtn, not the function entry" work.
* **In-SEAL slide rebasing.** If the snapshot carries ``image.slide`` (it came from a
  live, ASLR-slid process), ``_build_state_from_snapshot`` rebases it into the binary's
  file-address space via ``snapshot/rebase.py`` *before* using it — because cle keeps the
  Mach-O at file addresses (see ``engine.py`` on why ``base_addr`` can't do this).
* **``trace_assignments`` mirrors the run concretely.** It re-executes the chosen path
  with concrete inputs to read the value written on each line. It now honors a snapshot
  ``initial_state`` too, pinning the symbolic fields to the finding's witness so the
  per-line values reflect the real seeded run, not a fresh call.

EXTENDING
---------
* New input kind (e.g. symbolic env/argv): add it to the spec, seed it in
  ``_build_state`` (call_state branch) and surface the name so it appears in witnesses.
* New call-model kind: see ``_install_models`` / the models handling and ``checks`` /
  ``server`` where models are declared.
* New start-state source (another capture format): emit the neutral snapshot shape and
  reuse ``_build_state_from_snapshot``; don't special-case it in the explore loop.

PITFALLS
--------
* ``skip_calls`` (CALLLESS) BYPASSES call models — a call returns an unconstrained
  value instead of running the model. For model-dependent bugs, leave it OFF and model
  every heavy call, or the run won't stay bounded.
* A snapshot seed is only self-consistent in ONE address space. If ``image.slide`` is
  wrong/missing, pc and code pointers won't line up with the loaded binary and the run
  dies early (e.g. an IR-decode error in unrelated code).
* The explorer prunes to a single path when inputs are concrete (``trace_assignments``);
  don't reuse that helper for multi-path analysis.
"""
from __future__ import annotations

import logging
import re
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
        self._skip_ret_names: dict = {}        # call-site addr -> readable name for its skipped-call return

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

    def _build_state_from_snapshot(self, snap: dict, opts: set):
        """Concolic seed: start from a REAL execution state (registers + memory captured
        from a live run) and overlay fresh symbolic values only on the fields the caller
        marks as attacker-controlled. Everything else stays concrete, so exploration
        follows realistic paths instead of treating every input as unknown."""
        # If the snapshot carries an image slide (captured from a live, ASLR-slid
        # process), rebase it into this binary's file-address space so pc / pointers
        # line up with the loaded code. SEAL does this itself — callers pass the raw
        # captured snapshot plus {"image": {"slide", "file_lo", "file_hi"}}.
        img = snap.get("image") or {}
        if img.get("slide"):
            try:
                from .snapshot.rebase import rebase as _rebase
                mo = self.project.loader.main_object
                lo = int(img.get("file_lo", mo.min_addr))
                hi = int(img.get("file_hi", mo.max_addr))
                snap = _rebase(snap, int(img["slide"]), lo, hi)
            except Exception as e:
                log.warning("snapshot rebase failed: %s", e)

        pc = int(snap.get("pc", self.func_addr))
        state = self.project.factory.blank_state(addr=pc, add_options=opts)
        # Set the captured registers, but never let a saved pc/ip in `regs` clobber the
        # start address: `pc` (above) is authoritative so a caller can seed mid-function.
        for r, v in (snap.get("regs") or {}).items():
            if r.lower() in ("pc", "ip"):
                continue
            try:
                setattr(state.regs, r, claripy.BVV(int(v), self.arch.bits))
            except Exception as e:
                log.warning("snapshot reg %s: %s", r, e)
        state.regs.pc = claripy.BVV(pc, self.arch.bits)
        # A snapshot's LR points into the real CALLER. Once this function returns we are
        # done analysing it, so terminate the path at the return address rather than
        # decoding on into the caller — whose code/PAC we have not set up, which would
        # error (unhooked arm64e `retab`) or run unbounded. Clean "returned" leaf instead.
        try:
            rr = snap.get("regs") or {}
            lr = rr.get("lr", rr.get("x30"))
            if lr is not None and not self.project.is_hooked(int(lr)):
                self.project.hook(int(lr), angr.SIM_PROCEDURES["stubs"]["PathTerminator"](), replace=False)
        except Exception as e:
            log.warning("snapshot return-terminator: %s", e)
        for m in (snap.get("mem") or []):
            try:
                state.memory.store(int(m["addr"]), bytes.fromhex(m["hex"]))
            except Exception as e:
                log.warning("snapshot mem @%s: %s", m.get("addr"), e)
        named = {}
        for s in (snap.get("symbolic") or []):       # attacker-controlled -> symbolic overlay
            nm = s.get("name") or "sym"
            bv = claripy.BVS(nm, int(s.get("size", self.arch.bytes)) * 8)
            named[nm] = bv
            try:
                if s.get("reg"):
                    setattr(state.regs, s["reg"], bv)
                elif s.get("addr") is not None:
                    state.memory.store(int(s["addr"]), bv, endness=self.arch.memory_endness)
            except Exception as e:
                log.warning("snapshot symbolic %s: %s", nm, e)
        state.globals["angrgui_vars"] = named
        state.globals["angrgui_argv"] = list(named.values())
        state.globals["angrgui_locals"] = {}
        state.globals["angrgui_bufmembers"] = {}
        return state

    def _build_state(self):
        opts = {
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        }
        if self.spec.get("limits", {}).get("skip_calls"):
            # don't descend into called functions: a call returns a fresh unconstrained
            # value, so exploration stays in the target function and its branches show.
            opts.add(angr.options.CALLLESS)
        snap = self.spec.get("initial_state")
        if snap and snap.get("kind") == "snapshot":
            return self._build_state_from_snapshot(snap, opts)
        args = self.spec.get("args", [])
        arg_asts = []
        named = {}
        for i, a in enumerate(args):
            bv, symbolic = self._arg_bv(a, i)
            arg_asts.append(bv)
            named[a.get("name") or f"arg{i}"] = bv

        # Point the requested pointer arguments at fresh symbolic buffers (optionally
        # with a struct layout: specific members set to symbolic names or fixed values).
        buffers = {}
        for b in self.spec.get("buffers", []):
            argname = b["arg"]
            size = int(b.get("size", 64))
            buf = claripy.BVS(f"{argname}_buf", size * 8)
            buffers[argname] = (buf, size, b.get("layout") or [])

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
        for argname, (buf, size, layout) in buffers.items():
            addr = base
            base += (size + 0xfff) & ~0xfff
            state.memory.store(addr, buf, endness="Iend_BE")   # the whole region starts symbolic
            named[f"{argname}_buf"] = buf
            named[argname] = claripy.BVV(addr, self.arch.bits)   # the pointer itself is concrete
            # a struct layout overwrites specific members (fixed value or named symbolic),
            # leaving unlisted bytes symbolic; stored little-endian so integers read right.
            for mb in layout:
                try:
                    moff = int(mb.get("offset", 0)); msz = int(mb.get("size") or self.arch.bytes)
                    bits = max(8, msz * 8)
                    if mb.get("mode") == "fixed":
                        mv = claripy.BVV(int(mb.get("value", 0)) & ((1 << bits) - 1), bits)
                    else:
                        mnm = mb.get("name") or f"{argname}.{moff:x}"
                        mv = claripy.BVS(mnm, bits); named[mnm] = mv
                    state.memory.store(addr + moff, mv, endness=self.arch.memory_endness)
                except Exception as e:
                    log.warning("buffer %s member at +%s: %s", argname, mb.get("offset"), e)
            # overwrite the corresponding register/stack slot with the pointer
            idx = next((i for i, a in enumerate(args) if a.get("name") == argname), None)
            if idx is not None:
                self._set_arg(state, idx, claripy.BVV(addr, self.arch.bits), prototype)

        state.globals["angrgui_vars"] = named
        state.globals["angrgui_argv"] = arg_asts    # ordered, for the a1.. / arg0.. aliases
        state.globals["angrgui_locals"] = self._locals_map()

        # map buffer byte offsets to struct member names, so conditions read
        # e.g. `tif->tif_mode` instead of `tif_buf[16]`
        bufmembers = {}
        for b in self.spec.get("buffers", []):
            arg = b.get("arg")
            mm = b.get("member_map")
            if not mm:
                mm = [[int(m.get("offset", 0)), int(m.get("size") or 1),
                       m.get("name") or f"{arg}.m{int(m.get('offset', 0))}"] for m in (b.get("layout") or [])]
            if mm:
                bufmembers[f"{arg}_buf"] = sorted(mm, key=lambda x: x[0])
        state.globals["angrgui_bufmembers"] = bufmembers

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

    def _model_compute(self, m):
        """Build a closure ``state -> claripy.BV`` giving this model's return value
        (and applying any constraints it entails): a constant, one argument, a fresh
        symbolic value, a symbolic value restricted to a set/predicate, an expression
        over the arguments, or a freshly allocated buffer (size = one argument)."""
        kind = m.get("kind", "symbolic")
        bits = self.arch.bits
        mask = (1 << bits) - 1
        region = self.MODEL_REGION
        ro = self.arch.ret_offset
        # SysV AMD64 integer argument registers, in order (this tool targets x86-64)
        ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")

        def remember(state, name, val):
            vs = dict(state.globals.get("angrgui_vars", {}))
            vs[name] = val
            state.globals["angrgui_vars"] = vs

        def argval(state, i):
            return getattr(state.regs, ARG_REGS[i]) if i < len(ARG_REGS) else claripy.BVV(0, bits)

        def coerce(v):
            if isinstance(v, int):
                return claripy.BVV(v & mask, bits)
            if v.size() < bits:
                return v.zero_extend(bits - v.size())
            if v.size() > bits:
                return v[bits - 1:0]
            return v

        site = m.get("site")
        site_i = (int(site, 0) if isinstance(site, str) else int(site)) if site is not None else None
        label = str(m.get("func") or (f"site_{site_i:x}" if site_i is not None else "call"))

        if kind == "concrete":
            val = int(m.get("value", 0)) & mask
            def compute(state):
                return claripy.BVV(val, bits)
        elif kind == "return_arg":
            idx = int(m.get("arg", 0))
            def compute(state):
                return coerce(argval(state, idx))
        elif kind == "alloc":
            sidx = int(m.get("size_arg", 0))
            nm = m.get("name")
            def compute(state):
                size = argval(state, sidx)
                base = state.heap.allocate(region)
                allocs = state.globals.get("angrgui_allocs", ())
                state.globals["angrgui_allocs"] = allocs + ((base, size, base + region),)
                if nm:
                    remember(state, nm, claripy.BVV(base, bits))
                return claripy.BVV(base, bits)
        elif kind == "constrained":      # symbolic, restricted to a value set and/or a predicate
            nm = m.get("name") or (label + "_ret")
            vals = [int(x) & mask for x in (m.get("values") or [])]
            pred = m.get("constraint")   # a boolean expr over `ret` (and args)
            def compute(state):
                v = claripy.BVS(nm, bits)
                cons = []
                if vals:
                    cons.append(claripy.Or(*[v == x for x in vals]))
                if pred:
                    state.registers.store(ro, v)                 # bind `ret` to this value
                    state.globals["angrgui_argv"] = [argval(state, i) for i in range(len(ARG_REGS))]
                    cons.append(as_bool(make_evaluator(state)(pred)))
                for c in cons:
                    state.add_constraints(c)
                remember(state, nm, v)
                return v
        elif kind == "expr":             # return = an expression over the arguments
            expr = m.get("expr") or "0"
            def compute(state):
                saved = state.globals.get("angrgui_argv")
                state.globals["angrgui_argv"] = [argval(state, i) for i in range(len(ARG_REGS))]
                try:
                    v = make_evaluator(state)(expr)
                finally:
                    if saved is None:
                        state.globals.pop("angrgui_argv", None)
                    else:
                        state.globals["angrgui_argv"] = saved
                return coerce(v)
        else:                            # "symbolic" (default)
            nm = m.get("name") or (label + "_ret")
            def compute(state):
                v = claripy.BVS(nm, bits)
                remember(state, nm, v)
                return v
        return compute

    def _make_model_proc(self, m):
        """A SimProcedure that replaces a whole called function with a model."""
        compute = self._model_compute(m)
        class P(angr.SimProcedure):
            def run(self):
                return compute(self.state)
        P.display_name = "model_" + str(m.get("func") or "call")
        return P()

    def _install_models(self, state):
        self._hooked = []
        for m in (self.spec.get("models") or []):
            try:
                if m.get("site") is not None:
                    self._install_site_model(m)
                    continue
                target = m.get("func")
                explicit = m.get("addr")
                if explicit is None and not target:
                    continue
                proc = self._make_model_proc(m)
                if explicit is not None:                 # hook a known address directly
                    addr = int(explicit, 16) if isinstance(explicit, str) else int(explicit)
                    self.project.hook(addr, proc, replace=True)
                elif isinstance(target, str) and target.lower().startswith("0x"):
                    addr = int(target, 16)
                    self.project.hook(addr, proc, replace=True)
                elif isinstance(target, int):
                    addr = target
                    self.project.hook(addr, proc, replace=True)
                else:
                    addr = self.project.hook_symbol(target, proc, replace=True)
                self._hooked.append(addr)
            except Exception as e:
                log.warning("could not model %r: %s", m, e)

    def _install_site_model(self, m):
        """Replace a single (usually indirect) call *instruction* with a model: a
        length-hook runs our function in place of the call and execution resumes right
        after it with the modelled return value in the return register — the call
        target is never taken. This is how an indirect call through a pointer is handled."""
        site = m["site"]
        site = int(site, 16) if isinstance(site, str) else int(site)
        insn = next((i for i in self.project.factory.block(site).capstone.insns if i.address == site), None)
        compute = self._model_compute(m)
        ro = self.arch.ret_offset
        def site_hook(state):
            state.registers.store(ro, compute(state))
        self.project.hook(site, site_hook, length=(insn.size if insn else self.arch.bytes), replace=True)
        self._hooked.append(site)

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
        # Proper path: place the value in the Nth argument's real location, honouring
        # the arch ABI (x86-64 SysV, AArch64 AAPCS64 with its separate int/FP banks).
        try:
            proto = prototype
            if isinstance(prototype, str):
                proto = angr.types.parse_signature(prototype).with_arch(self.arch)
            cc.arg_locs(proto)[index].set_value(state, value)
            return
        except Exception:
            pass
        # Fallback: the arch's integer argument registers (cc.ARG_REGS is x0..x7 on
        # AArch64, rdi/rsi/... on AMD64), then a hard-coded per-family list.
        regs = list(getattr(cc, "ARG_REGS", None) or [])
        if not regs:
            if self.arch.name.startswith("AMD64"):
                regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            elif self.arch.name.startswith("AARCH64"):
                regs = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
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

    def _resolve_addr(self, s):
        """``s.addr``, but tolerant of a symbolic instruction pointer.

        A symbolic IP means the state is about to jump somewhere the inputs
        influence — typically a call through a symbolic function pointer (e.g.
        a struct field we left symbolic). angr keeps such a state *active* when
        the target still has a few concrete solutions, but ``s.addr`` resolves
        the IP with ``eval_one`` and raises SimValueError when there is not
        exactly one. Return ``(addr, symbolic_ip?)`` using a representative
        concrete target so one such state can't abort the whole exploration.
        """
        try:
            return s.addr, False
        except Exception:
            try:
                return s.solver.min(s.regs._ip), True
            except Exception:
                hist = list(s.history.bbl_addrs)
                return (hist[-1] if hist else self.func_addr), True

    def _indirect_call_site(self, s):
        """If the state is stuck on a `call [reg+…]` through a pointer, return
        ``(addr, op_str, line)`` of that call; else None."""
        try:
            hist = list(s.history.bbl_addrs)
            site = hist[-1] if hist else None
            if site is None:
                return None
            last = self.project.factory.block(site).capstone.insns[-1]
            if last.mnemonic == "call" and "[" in (last.op_str or ""):
                line = None
                try:
                    e = self.binary.nearest_line(last.address)
                    line = e[1] if e else None
                except Exception:
                    pass
                return last.address, (last.op_str or "").strip(), line
        except Exception:
            pass
        return None

    def _symbolic_ip_fate(self, s) -> str:
        """A symbolic IP from a call through a function pointer is an *unknown call
        target* (we just don't know which function to run — model it), not a
        control-flow hijack. A symbolic ret/jump is treated as a hijack."""
        return "unknown_call" if self._indirect_call_site(s) else "unconstrained"

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
        elif fate == "unknown_call":
            site = self._indirect_call_site(state)
            if site:
                a, op, line = site
                where = f"{a:#x}" + (f" (line {line})" if line else "")
                node.end = {"reason": "unknown_call", "site": a, "line": line,
                            "text": f"can't continue here: the call at {where} goes through a function pointer "
                                    f"the inputs leave undetermined ({op}) — assign a model for this call site "
                                    f"(Call models → indirect call), or set that struct field to a concrete function."}
            else:
                node.end = {"reason": "unknown_call",
                            "text": "can't continue: an indirect call's target is undetermined — model the call."}
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
                # On-demand arm64e PAC support: a path can error by reaching a pointer-
                # auth instruction libVEX can't decode OUTSIDE the statically scanned
                # range (a tail-call target / helper the code jumps to). Hook it and
                # revive the path, so a run isn't bounded to code we scanned up front.
                if simgr.errored and getattr(self.arch, "name", "") == "AARCH64":
                    from . import angr_arm_patch
                    self._pac_rescued = getattr(self, "_pac_rescued", 0)
                    keep = []
                    for er in list(simgr.errored):
                        st = getattr(er, "state", None)
                        addr = getattr(st, "addr", None) if st is not None else None
                        msg = str(getattr(er, "error", "")).lower()
                        if (addr is not None and self._pac_rescued < 500
                                and ("decod" in msg or "no bytes" in msg or "nodecode" in msg)
                                and angr_arm_patch.hook_pac_at(self.project, addr)):
                            simgr.active.append(st)
                            self._pac_rescued += 1
                        else:
                            keep.append(er)
                    simgr.errored[:] = keep
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

    def _callee_label(self, site: int) -> str:
        """A readable name for what a skipped call at this block returns: the callee
        name for a direct call; for an indirect call (through a pointer) the source
        line of the call, so it reads e.g. `ret_L312` and can be found in the code."""
        try:
            last = self.project.factory.block(site).capstone.insns[-1]
            op = (last.op_str or "").strip()
            if last.mnemonic == "call":
                if re.fullmatch(r"0x[0-9a-fA-F]+", op):          # direct: call 0x....
                    tgt = int(op, 16)
                    nm = self.binary.name_at(tgt) or f"sub_{tgt:x}"
                    return f"{nm}_ret"
                try:                                             # indirect: name by its source line
                    e = self.binary.nearest_line(last.address)
                    if e:
                        return f"ret_L{e[1]}"
                except Exception:
                    pass
                m = re.search(r"\[([^\]]+)\]", op)               # fallback: the pointer operand
                inner = (m.group(1) if m else op)
                return "ret_" + re.sub(r"[^A-Za-z0-9]+", "_", inner).strip("_")
        except Exception:
            pass
        return "call_ret"

    def _skip_ret_name(self, s) -> str:
        """Stable, unique display name for the value a given skipped call returns.
        Keyed by call site so the same call reads the same across paths; a second
        call site to the same callee gets an index appended."""
        hist = list(s.history.bbl_addrs)
        site = hist[-1] if hist else 0
        if site in self._skip_ret_names:
            return self._skip_ret_names[site]
        base = self._callee_label(site)
        name, n, used = base, 1, set(self._skip_ret_names.values())
        while name in used:
            n += 1
            name = f"{base}{n}"
        self._skip_ret_names[site] = name
        return name

    def _name_skipped_rets(self, states):
        """CALLLESS writes an Unconstrained value angr names 'fake_ret_value' for
        every skipped call, so unrelated returns look identical in branch
        conditions. Give each a name derived from its callee instead. The value is
        still freshly unconstrained (same semantics) — only the label changes, and
        it is renamed before the next block consumes it (e.g. `cmp eax, 4`)."""
        if not self.spec.get("limits", {}).get("skip_calls"):
            return
        ro = self.arch.ret_offset
        for s in states:
            try:
                if s.history.jumpkind != "Ijk_FakeRet":
                    continue
                rv = s.registers.load(ro, self.arch.bytes)
                if rv.op != "BVS" or "fake_ret_value" not in rv.args[0]:
                    continue
                s.registers.store(ro, claripy.BVS(self._skip_ret_name(s), self.arch.bits))
            except Exception:
                pass

    def _absorb(self, simgr, find, avoid):
        # Rename CALLLESS return values (fake_ret_value) to their callee before the
        # next step's compare consumes them, so branch conditions stay distinct/readable.
        self._name_skipped_rets(simgr.active)
        # Gather every fresh successor from this step, tagged with its fate.
        succ: list[tuple] = [(s, "active", None) for s in simgr.active]
        for stash, kind in (("deadended", "deadended"), ("errored", "errored"),
                            ("unconstrained", "unconstrained"), ("spinning", "pruned")):
            for item in getattr(simgr, stash, []):
                st = item.state if stash == "errored" else item
                if id(st) in self._seen_leaves:
                    continue
                self._seen_leaves.add(id(st))
                k = kind
                # an "unconstrained" state stuck on a call through a pointer isn't a
                # hijack — it's an undetermined call target the user should model
                if stash == "unconstrained" and self._indirect_call_site(st):
                    k = "unknown_call"
                succ.append((st, k, str(item.error) if stash == "errored" else None))

        # Count successors per parent node so we can tell branches from straight lines.
        parent_count: dict = {}
        for s, _, _ in succ:
            pn = s.globals.get("angrgui_node")
            parent_count[pn] = parent_count.get(pn, 0) + 1

        extended = set()
        hijacked = []            # active states with a symbolic IP: close and stop stepping
        for s, fate, err in succ:
            addr, sym_ip = self._resolve_addr(s)
            # A symbolic instruction pointer on an otherwise-active state is a
            # control-flow hijack: the inputs decide where execution jumps.
            # Treat it as a leaf (angr's "unconstrained" outcome) rather than
            # letting it crash or spin, and take it out of the active search.
            if sym_ip and fate == "active":
                fate = self._symbolic_ip_fate(s)
                hijacked.append(s)
            pn = s.globals.get("angrgui_node")
            recent = list(s.history.recent_bbl_addrs)
            if pn is None or pn not in self.nodes:
                node = self._new_node(addr, None, 0)
                node.block_addrs.extend(recent)
                s.globals["angrgui_node"] = node.id
            elif parent_count.get(pn, 1) > 1:
                # the parent split here: the block that branched belongs to the parent,
                # and every successor starts its own child stretch
                parent = self.nodes[pn]
                if pn not in extended:
                    parent.block_addrs.extend(recent)
                    extended.add(pn)
                node = self._new_node(addr, pn, parent.depth + 1)
                node.cond = self._branch_condition(s)
                node.decided_at = self._decision_point(parent)
                s.globals["angrgui_node"] = node.id
            else:
                node = self.nodes[pn]
                node.block_addrs.extend(recent)
            node.cur = addr
            if fate != "active":
                node.kind = fate
                self._close(node, s, fate, err)
            if find and addr == find:
                node.kind = "found"
            if addr in avoid:
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

        # Stop stepping states whose IP the inputs control — they are recorded
        # as hijack leaves above; re-stepping a symbolic IP would only crash or
        # fan out uselessly.
        if hijacked:
            drop = set(map(id, hijacked))
            simgr.active[:] = [s for s in simgr.active if id(s) not in drop]

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


def trace_assignments(binary, spec: dict, example: dict, max_steps: int = 6000) -> dict:
    """Re-execute a function with the example's concrete inputs and record, per
    instruction address, the value written to its destination register (and memory
    stores). That is the concrete value of the variable assigned on each source line,
    on this path — used to annotate assignment lines in the decompilation.

    Returns {hex_addr: {"reg": name, "val": hex, "store": {"addr","val"}?}}.
    """
    import angr
    import claripy

    cspec = dict(spec)
    init = spec.get("initial_state")
    if init and init.get("kind") == "snapshot":
        # Concolic seed: start from the same captured state, but pin each
        # attacker-controlled field to this finding's witness value so the trace
        # follows exactly this path (fully concrete -> one path, values resolve).
        snap = dict(init)
        regs = dict(snap.get("regs") or {})
        mem = [dict(m) for m in (snap.get("mem") or [])]
        remaining = []
        for s in (snap.get("symbolic") or []):
            nm = s.get("name") or "sym"
            ex = (example or {}).get(nm)
            v = ex.get("u") if isinstance(ex, dict) else None
            if v is None:
                remaining.append(s)
                continue
            if s.get("reg"):
                regs[s["reg"]] = int(v)
            elif s.get("addr") is not None:
                size = int(s.get("size", binary.arch.bytes))
                mem.append({"addr": int(s["addr"]),
                            "hex": int(v).to_bytes(size, "little").hex()})
            else:
                remaining.append(s)
        snap["regs"], snap["mem"], snap["symbolic"] = regs, mem, remaining
        cspec["initial_state"] = snap
        cspec["args"] = []
    else:
        cargs = []
        for a in spec.get("args", []):
            ex = (example or {}).get(a.get("name") or "")
            v = ex.get("u") if isinstance(ex, dict) else None
            cargs.append({**a, "mode": "concrete", "value": int(v or 0)})
        cspec["args"] = cargs
    cspec["checks"] = []

    run = Run(binary, cspec)
    state = run._build_state()
    run._install_models(state)                    # honour alloc/return models (e.g. malloc)
    arch = binary.arch
    SKIP = {"ip", "pc", "sp", "xsp", "bp", "x29", "lr", "x30", "cc_op", "cc_dep1",
            "cc_dep2", "cc_ndep", "nzcv", "cpsr", "fpcr", "fpsr", "qc"}
    regvals, memvals = {}, {}

    def on_rw(s):
        ia = s.scratch.ins_addr
        if ia is None:
            return
        try:
            off = s.inspect.reg_write_offset
            if isinstance(off, claripy.ast.Base):
                off = s.solver.eval(off)
            expr = s.inspect.reg_write_expr
            size = max(1, expr.size() // 8)
            name = arch.translate_register_name(off, size)
            if not name or name in SKIP:
                return
            regvals[ia] = {"reg": name, "val": hex(s.solver.eval(expr))}
        except Exception:
            pass

    def on_mw(s):
        ia = s.scratch.ins_addr
        if ia is None:
            return
        try:
            memvals[ia] = {"addr": hex(s.solver.eval(s.inspect.mem_write_address)),
                           "val": hex(s.solver.eval(s.inspect.mem_write_expr))}
        except Exception:
            pass

    state.inspect.b("reg_write", when=angr.BP_AFTER, action=on_rw)
    state.inspect.b("mem_write", when=angr.BP_BEFORE, action=on_mw)
    simgr = binary.project.factory.simgr(state)
    steps = 0
    while simgr.active and steps < max_steps:
        simgr.step()
        steps += 1
        if len(simgr.active) > 1:                 # inputs are concrete; keep a single path
            del simgr.active[1:]

    out = {}
    for ia, rv in regvals.items():
        out[hex(ia)] = dict(rv)
    for ia, mv in memvals.items():
        out.setdefault(hex(ia), {})["store"] = mv
    return out
