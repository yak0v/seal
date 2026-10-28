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


class CorePages(angr.SimStatePlugin):
    """Per-state record of which pages we've already faulted in from the process core, so
    demand-paging fills each page at most once per state and never clobbers a later write.
    Deep-copied on fork (each path tracks its own fills) — a global set would wrongly mark a
    page 'present' for a sibling that branched before it was faulted in."""
    def __init__(self, filled=None):
        super().__init__()
        self.filled = set(filled) if filled else set()

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return CorePages(self.filled)


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
        # A safe function size even when the CFG function object is missing (get_function
        # can return None for some stripped/edge functions) — so a run never crashes at
        # setup. Prefer the CFG size, then the lazy index's size estimate, then a default.
        self.func_size = 0x1000
        try:
            if self.func is not None and self.func.size:
                self.func_size = self.func.size
            else:
                ent = next((e for e in getattr(binary, "_index", []) if e["addr"] == self.func_addr), None)
                if ent and ent.get("size"):
                    self.func_size = ent["size"]
        except Exception:
            pass

        self.status = "pending"       # pending|running|done|error|cancelled
        self.error: str | None = None
        self.progress = {"step": 0, "active": 0, "deadended": 0, "found": 0,
                         "hits": 0, "elapsed": 0.0, "message": "queued"}
        self._cancel = threading.Event()
        self._lock = threading.Lock()

        self.checks = []
        self._state_checks = []
        self._setup_notes: list[str] = []       # diagnostics gathered while installing checks
        self._wild_deref: dict = {}              # arg name -> count of reads through an un-set-up pointer
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
        self._branches: dict = {}              # branch block addr -> {taken:set, sym:bool}: concrete-gate tracking
        self._concretized: list = []           # lossy symbolic-address concretizations (under-report warning)
        self._conc_seen: set = set()
        self._auto_backed: set = set()          # pointer args auto-backed with a symbolic region (limits.auto_pointers)

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

    def _restore_flags(self, state, val: int) -> None:
        """Set the condition flags from a captured flags register (CPSR/NZCV/eflags).

        angr has no plain ``cpsr``/``eflags`` register — it computes flags lazily from a
        VEX thunk. For ARM/AArch64 the COPY op (op==0) makes the flags read straight out
        of cc_dep1, where NZCV sit in bits 31:28 — exactly the CPSR/NZCV layout — so we
        copy the top nibble across. For x86 angr exposes an ``eflags`` setter that drives
        the thunk for us."""
        an = (getattr(self.arch, "name", "") or "").upper()
        if an.startswith("ARM") or an in ("AARCH64",):
            bits = self.arch.bits
            state.regs.cc_op   = claripy.BVV(0, bits)                 # {ARM64G,ARMG}_CC_OP_COPY
            state.regs.cc_dep1 = claripy.BVV(val & 0xF0000000, bits)  # NZCV in bits 31:28
            state.regs.cc_dep2 = claripy.BVV(0, bits)
            state.regs.cc_ndep = claripy.BVV(0, bits)
        elif an in ("X86", "AMD64"):
            state.regs.eflags = claripy.BVV(val, self.arch.bits)
        else:
            setattr(state.regs, "flags", claripy.BVV(val, self.arch.bits))

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

        _regs = snap.get("regs") or {}
        # pc: top-level `pc` is authoritative (a caller can seed mid-function); if it's
        # absent, fall back to the CAPTURED pc in regs (a raw lldb dump has no top-level
        # pc) rather than silently restarting at the function entry.
        _IP = ("pc", "ip", "rip", "eip")
        _pc = snap.get("pc")
        if _pc is None:
            _pc = next((_regs[k] for k in _regs if k.lower() in _IP), None)
        pc = int(_pc) if _pc is not None else self.func_addr
        state = self.project.factory.blank_state(addr=pc, add_options=opts)
        # Set the captured registers. Map common capture names to angr's (lldb calls
        # x29/x30 fp/lr), and size each value by the register's REAL width so a 128-bit
        # NEON reg (v0..v31) isn't truncated to 64 bits.
        _ALIAS = {"fp": "x29", "lr": "x30", "w0": None}   # (sub-regs handled below)
        # Condition flags aren't a plain register in angr: AArch64/ARM model NZCV through
        # the VEX flag thunk (cc_op/cc_dep1/...) and x86 through eflags. A plain
        # setattr(state.regs, "cpsr", ...) therefore throws and silently drops the flags,
        # which diverges any snapshot seeded right before a flag-dependent branch.
        _FLAG_REGS = ("cpsr", "nzcv", "pstate", "spsr", "eflags", "rflags", "flags")
        regmap = getattr(self.arch, "registers", {}) or {}
        for r, v in _regs.items():
            rl = r.lower()
            if rl in _IP:
                continue
            if rl in _FLAG_REGS:
                try:
                    self._restore_flags(state, int(v))
                except Exception as e:
                    log.warning("snapshot flags %s: %s", r, e)
                continue
            name = _ALIAS.get(rl, rl) or rl
            try:
                bits = regmap[name][1] * 8 if name in regmap else self.arch.bits
                setattr(state.regs, name, claripy.BVV(int(v) & ((1 << bits) - 1), bits))
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
        mem_overlays = []                             # (addr, bv) symbolic fields in memory
        floatvars = {}                                # name -> float layout ("f32","f64","f32x2",…)
        for s in (snap.get("symbolic") or []):       # attacker-controlled -> symbolic overlay
            nm = s.get("name") or "sym"
            sz = int(s.get("size", self.arch.bytes))
            bv = claripy.BVS(nm, sz * 8)
            named[nm] = bv
            fl = s.get("float")                       # mark float/vector regs so the witness
            if fl:                                    # shows a number, not a raw byte blob
                floatvars[nm] = fl if isinstance(fl, str) else ("f64" if sz >= 8 else "f32")
            try:
                if s.get("reg") and s.get("offset") is None:
                    setattr(state.regs, s["reg"], bv)       # whole register symbolic
                else:
                    # a memory field: an absolute addr, OR relative to a register/base — e.g.
                    # {"base":"x0","offset":"0xb0"} = the field at x0+0xb0 — so you don't have
                    # to hand-compute runtime addresses (which a reviewer found error-prone).
                    if s.get("addr") is not None and s.get("base") is None:
                        addr = int(s["addr"], 0) if isinstance(s["addr"], str) else int(s["addr"])
                    else:
                        base = s.get("base") or s.get("reg")
                        bval = state.solver.eval(getattr(state.regs, base))
                        off = s.get("offset", 0)
                        addr = bval + (int(off, 0) if isinstance(off, str) else int(off))
                    state.memory.store(addr, bv, endness=self.arch.memory_endness)
                    mem_overlays.append((addr, bv))          # re-applied over faulted core pages
            except Exception as e:
                log.warning("snapshot symbolic %s: %s", nm, e)
        state.globals["angrgui_floatvars"] = floatvars
        state.globals["angrgui_vars"] = named
        state.globals["angrgui_argv"] = list(named.values())
        state.globals["angrgui_locals"] = {}
        state.globals["angrgui_bufmembers"] = {}
        # Lazy page-in from a process core (if this snapshot has one): nothing is pre-loaded;
        # pages fault in from the core on first access. Installed AFTER the symbolic overlays
        # so it can re-apply them on top of a faulted page (else reading a struct field would
        # pull its concrete core value back over the field we just made symbolic).
        if snap.get("core"):
            try:
                self._install_core_paging(state, snap["core"], mem_overlays, img)
            except Exception as e:
                log.warning("core paging unavailable: %s", e)
        return state

    def _install_core_paging(self, state, core_path, mem_overlays, img):
        """Fault pages in from a process core on demand (see CorePages / snapshot/core.py).

        On every memory access to a CONCRETE address that isn't part of the loaded image,
        read that page from the core and store it before the access completes — so the real
        bytes are there wherever execution goes, with nothing pre-loaded. The loaded image's
        own addresses are served by cle (we skip them). A symbolic address is left alone."""
        from .snapshot.core import MachOCore
        core = MachOCore(core_path)
        self._core = core                          # keep the mmap alive for the run
        loader = self.project.loader
        endn = self.arch.memory_endness
        overlays = list(mem_overlays or [])        # (addr, bv) to keep symbolic over faulted pages
        slide = int((img or {}).get("slide", 0))
        # WRITABLE ranges of the loaded image (file addresses): their runtime values live in
        # the core at file+slide, so we fault those from the core too — otherwise a global the
        # program changed at runtime would read the binary's ORIGINAL on-disk value (#3). Code
        # and read-only data stay as cle loaded them (same as the binary, and static).
        writ = []
        try:
            for sec in loader.main_object.sections:
                if getattr(sec, "is_writable", False) and not getattr(sec, "is_executable", False):
                    writ.append((sec.min_addr, sec.max_addr))
        except Exception:
            pass
        def in_writable_image(pg):
            return any(lo <= pg <= hi for lo, hi in writ)
        state.register_plugin("core_pages", CorePages())

        def fill(s, which):
            insp = s.inspect
            addr_bv = getattr(insp, which + "_address", None)
            len_bv = getattr(insp, which + "_length", None)
            if addr_bv is None or getattr(addr_bv, "symbolic", False):
                return                             # only page concrete addresses
            try:
                a = s.solver.eval(addr_bv)
                n = int(s.solver.eval(len_bv)) if len_bv is not None else 8
            except Exception:
                return
            n = max(1, min(int(n), 0x2000))
            filled = s.core_pages.filled
            pg, last = a & ~0xFFF, (a + n - 1) & ~0xFFF
            while pg <= last:
                if pg not in filled:
                    filled.add(pg)
                    in_img = loader.find_object_containing(pg) is not None
                    # heap/stack -> core at this (live) address; image writable data -> core at
                    # file+slide (runtime values); image code/rodata -> leave to cle.
                    src = (pg + slide) if in_img else pg
                    if (not in_img) or in_writable_image(pg):
                        data = core.read_page(src)
                        if data:
                            try:
                                s.memory.store(pg, data)
                                for oa, obv in overlays:            # keep symbolic fields symbolic
                                    if pg <= oa < pg + 0x1000:
                                        s.memory.store(oa, obv, endness=endn)
                            except Exception:
                                pass
                pg += 0x1000

        state.inspect.b("mem_read", when=angr.BP_BEFORE, action=lambda s: fill(s, "mem_read"))
        state.inspect.b("mem_write", when=angr.BP_BEFORE, action=lambda s: fill(s, "mem_write"))

    def _build_state(self):
        opts = {
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        }
        if self.spec.get("limits", {}).get("symbolic_addrs"):
            # Opt-in: keep attacker-controlled memory ADDRESSES symbolic instead of pinning
            # them to one value. By default angr concretizes a symbolic index, so a later
            # access on the same index (notably an OOB WRITE after an OOB READ) is masked and
            # under-reported. With this on, the index stays symbolic and the oob checks see
            # its full range — at the cost of more solver work, so it's off by default.
            for o in ("SYMBOLIC_WRITE_ADDRESSES", "CONSERVATIVE_READ_STRATEGY"):
                if hasattr(angr.options, o):
                    opts.add(getattr(angr.options, o))
        if self.spec.get("limits", {}).get("skip_calls", True):
            # DEFAULT ON: don't descend into called functions — a call returns a fresh
            # unconstrained value, so exploration stays in the target function and its
            # branches show (and a run can't hang stepping into a huge callee). A
            # model-based run that needs real calls sets skip_calls:false explicitly.
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
        # with a struct layout: specific members set to symbolic names, fixed values,
        # or POINTERS to their own sub-region — see _fill_region).
        # Resolve a buffer's `arg` to an actual declared argument — accept the arg NAME or
        # a positional alias (a0/a1… or arg0/arg1…). Without this, a buffer written as
        # {arg:"a0"} against an argument named "p" silently fails to anchor: the pointer
        # stays a wild symbolic address, the struct reads as unconstrained, and the run
        # explores a single bogus path. (A mismatch is left as-is so it's still visible.)
        def _resolve_argname(ref):
            for a in args:
                if a.get("name") == ref:
                    return ref
            # a1../arg0.. aliases OR a bare integer index (arg:0) -> that arg's name
            m = re.fullmatch(r"(?:a|arg)?(\d+)", str(ref))
            if m and 0 <= int(m.group(1)) < len(args):
                i = int(m.group(1))
                return args[i].get("name") or f"arg{i}"
            return str(ref)        # always a string: it becomes a BVS name/prefix
        buffers = {}
        sized_bufs = {}             # argname -> the arg whose SYMBOLIC value is this buffer's length
        for b in self.spec.get("buffers", []):
            argname = _resolve_argname(b["arg"])
            buffers[argname] = (int(b.get("size", 64)), b.get("layout") or [])
            if b.get("size_from"):  # buffer's logical size = a symbolic length the code trusts
                sized_bufs[argname] = _resolve_argname(b["size_from"])

        # Opt-in (limits.auto_pointers): auto-back every symbolic pointer-sized arg that
        # has no explicit buffer with a symbolic region, so a function that dereferences a
        # pointer arg is analysable WITHOUT hand-declaring each buffer, and the pointee is
        # attacker-controlled. This is a deliberate ASSUMPTION — that the pointer is valid
        # and points to a controllable region of this size — which is WRONG for an
        # internal/fixed pointer, so _diagnose flags any run that relied on it.
        # args the server already injected a TYPED auto-pointer buffer for (real struct
        # layout); still count them as auto-backed so the run is flagged assumption-based.
        self._auto_backed = set(self.spec.get("_auto_ptr_args", []))
        if self.spec.get("limits", {}).get("auto_pointers"):
            wb = self.arch.bytes
            for i, a in enumerate(args):
                nm = a.get("name") or f"arg{i}"
                if (a.get("mode", "symbolic") == "symbolic" and not a.get("float")
                        and int(a.get("size") or wb) == wb and nm not in buffers):
                    buffers[nm] = (self.AUTO_PTR_REGION, [])     # untyped -> flat symbolic region
                    self._auto_backed.add(nm)

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

        # Allocate + fill buffers, repoint the pointer args. A bump allocator over the
        # scratch region hands out a page-aligned block per buffer AND per pointer-member
        # sub-region (see _fill_region), so a struct with pointer members actually has
        # real memory behind each pointer instead of a wild symbolic address.
        self._scratch_next = self.binary.scratch_base()
        self._member_maps = {}                      # region-name -> [[off,size,name],...] for display
        sym_allocs = []                             # (base, symbolic_len, physical_end) for the oob check
        for argname, (size, layout) in buffers.items():
            addr = self._alloc_region(size)
            self._fill_region(state, addr, size, layout, named, argname, 0)
            named[argname] = claripy.BVV(addr, self.arch.bits)   # the pointer itself is concrete
            # overwrite the corresponding register/stack slot with the pointer
            idx = next((i for i, a in enumerate(args) if a.get("name") == argname), None)
            if idx is not None:
                self._set_arg(state, idx, claripy.BVV(addr, self.arch.bits), prototype)
            # SYMBOLIC-SIZE buffer: its logical size is the SYMBOLIC length the code trusts (a
            # length arg), not the fixed `size` (which is just the physical backing). Register it
            # as a TRACKED allocation whose size is that symbolic length, so an oob_read/oob_write
            # (no base, modeled mode) solves "can an access exceed the length?" over ALL lengths —
            # catching the length-underflow / off-by-one / only-breaks-at-a-specific-size class that
            # a single fixed size misses. Tying the size to the length the code ACTUALLY uses (not a
            # fresh var) is what keeps it sound: the OOB fires only where the code's size handling
            # is genuinely wrong. The triggering length shows up in the witness as that arg.
            if argname in sized_bufs:
                lenv = named.get(sized_bufs[argname])
                if isinstance(lenv, claripy.ast.BV):
                    sym_allocs.append((addr, lenv, addr + size))
        if sym_allocs:
            state.globals["angrgui_allocs"] = tuple(sym_allocs)

        state.globals["angrgui_vars"] = named
        state.globals["angrgui_argv"] = arg_asts    # ordered, for the a1.. / arg0.. aliases
        state.globals["angrgui_locals"] = self._locals_map()

        # map buffer byte offsets to struct member names (incl. nested sub-regions),
        # so conditions read e.g. `tif->tif_mode` instead of `tif_buf[16]`. _fill_region
        # collected these recursively; honour any explicit member_map override too.
        bufmembers = dict(self._member_maps)
        for b in self.spec.get("buffers", []):
            mm = b.get("member_map")
            if mm:
                bufmembers[f"{b.get('arg')}_buf"] = sorted(mm, key=lambda x: x[0])
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

        # AUTONOMIC VALIDATION CHECK: if the function dereferences a pointer-width
        # symbolic arg that has NO buffer set up, the reads go to unmapped/zero memory
        # and the whole analysis is meaningless (the exact "can't validate this function"
        # trap). Record which arg variables are such un-set-up pointers, watch for reads
        # through them, and surface it in the diagnostics.
        self._wild_deref = {}
        self._deref_candidates = {}            # claripy var name -> arg name
        buffer_args = set(buffers.keys())
        for i, a in enumerate(args):
            nm = a.get("name") or f"arg{i}"
            if (a.get("mode", "symbolic") == "symbolic" and not a.get("float")
                    and int(a.get("size") or self.arch.bytes) == self.arch.bytes
                    and nm not in buffer_args):
                bv = named.get(nm)
                if isinstance(bv, claripy.ast.BV) and bv.symbolic:
                    for v in bv.variables:
                        self._deref_candidates[v] = nm
        if self._deref_candidates:
            cand = set(self._deref_candidates)
            lo, hi = self.func_addr, self.func_addr + self.func_size

            def _on_wild_read(st):
                try:
                    ia = st.scratch.ins_addr
                    if ia is None or not (lo <= ia < hi):
                        return
                    wa = st.inspect.mem_read_address
                    if isinstance(wa, claripy.ast.BV) and wa.symbolic:
                        for v in (wa.variables & cand):
                            nm = self._deref_candidates[v]
                            self._wild_deref[nm] = self._wild_deref.get(nm, 0) + 1
                except Exception:
                    pass
            state.inspect.b("mem_read", when=angr.BP_BEFORE, action=_on_wild_read)
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
        # Integer argument registers for THIS arch's ABI (AArch64 AAPCS64 x0..x7,
        # x86-64 SysV rdi/rsi/...): a model that reads its callee's args (return_arg,
        # alloc size, an expr/predicate over args) must read the right bank, or it reads
        # nonexistent x86 registers on arm64 and the model silently breaks.
        ARG_REGS = tuple(self._int_arg_regs())

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

    def _install_concretization_watch(self, state):
        """When angr accesses memory through a SYMBOLIC address it pins it to one concrete
        value (its default strategy). If that address was genuinely multi-valued — an
        attacker-influenced index — the pin loses information: a LATER check on the same
        index can under-report (e.g. an out-of-bounds WRITE never fires because an earlier
        READ already pinned the index to an in-bounds value). Record such lossy events,
        deduped and capped, so the run can WARN instead of silently missing the primitive."""
        CAP = 8
        lo, hi = self.func_addr, self.func_addr + self.func_size

        def on_conc(s):
            if len(self._concretized) >= CAP:
                return
            try:
                expr = s.inspect.address_concretization_expr
                if expr is None or not expr.symbolic:
                    return
                ins = s.scratch.ins_addr
                if ins is None or not (lo <= ins < hi):
                    return
                action = getattr(s.inspect, "address_concretization_action", None)
                key = (ins, action)
                if key in self._conc_seen:
                    return
                if len(s.solver.eval_upto(expr, 2)) < 2:      # effectively one address -> not lossy
                    return
                self._conc_seen.add(key)
                self._concretized.append({"addr": ins, "action": action})
            except Exception:
                pass

        state.inspect.b("address_concretization", when=angr.BP_BEFORE, action=on_conc)

    def _install_models(self, state):
        self._hooked = []
        models = self.spec.get("models") or []
        # A call model only fires if the call is actually taken; skip_calls (CALLLESS,
        # the default) skips every call, so a function/addr-target model is bypassed.
        # Warn instead of silently ignoring it — this costs real debugging time.
        if (models and self.spec.get("limits", {}).get("skip_calls", True)
                and any(m.get("site") is None for m in models)):
            self._setup_notes.append(
                "call model(s) are set but skip_calls is ON, which bypasses them (the "
                "calls are skipped, so the hooks never fire). Set limits.skip_calls=false "
                "to use the models — note that then OTHER, unmodeled calls are stepped into.")
        for m in models:
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

    # ------------------------------------------------------------------ buffers / structs
    PTR_MAX_DEPTH = 5                        # cap recursive pointer expansion (cycles/blowup)
    AUTO_PTR_REGION = 0x1000                 # symbolic region size behind an auto-backed pointer arg

    def _alloc_region(self, size: int) -> int:
        """Hand out the next page-aligned scratch block of at least `size` bytes."""
        addr = self._scratch_next
        self._scratch_next += (max(int(size), 1) + 0xfff) & ~0xfff
        return addr

    def _fill_region(self, state, addr, size, layout, named, prefix, depth):
        """Lay out a buffer/struct at `addr`: start the whole region symbolic, then apply
        each member. A member is a fixed value, a fresh symbolic field, OR a POINTER —
        in which case a sub-region is allocated, its concrete address stored into the
        member, and this recurses into the sub-region's own layout (depth-capped). That
        is what makes `struct {char *buf; int len;}` / linked structs actually analysable:
        the pointer has real memory behind it instead of a wild symbolic address."""
        pbits = self.arch.bits
        blob = claripy.BVS(prefix, max(8, int(size)) * 8)
        state.memory.store(addr, blob, endness="Iend_BE")   # whole region starts symbolic
        named[f"{prefix}_buf"] = blob
        mmap = []
        for mb in (layout or []):
            try:
                moff = int(mb.get("offset", 0))
                msz = int(mb.get("size") or self.arch.bytes)
                bits = max(8, msz * 8)
                mode = mb.get("mode")
                mnm = mb.get("name") or f"{prefix}.{moff:x}"
                if mode == "pointer":
                    tgt = mb.get("target") or {}
                    if depth < self.PTR_MAX_DEPTH and (tgt.get("size") or tgt.get("layout")):
                        tsize = int(tgt.get("size") or 64)
                        sub = self._alloc_region(tsize)
                        state.memory.store(addr + moff, claripy.BVV(sub, pbits),
                                           endness=self.arch.memory_endness)
                        named[mnm] = claripy.BVV(sub, pbits)        # the member pointer value
                        self._fill_region(state, sub, tsize, tgt.get("layout") or [],
                                          named, mnm, depth + 1)     # recurse into *member
                    else:                                           # depth cap / no target: leave symbolic
                        mv = claripy.BVS(mnm, pbits); named[mnm] = mv
                        state.memory.store(addr + moff, mv, endness=self.arch.memory_endness)
                elif mode == "fixed":
                    mv = claripy.BVV(int(mb.get("value", 0)) & ((1 << bits) - 1), bits)
                    state.memory.store(addr + moff, mv, endness=self.arch.memory_endness)
                else:
                    mv = claripy.BVS(mnm, bits); named[mnm] = mv
                    state.memory.store(addr + moff, mv, endness=self.arch.memory_endness)
                mmap.append([moff, msz, mnm])
            except Exception as e:
                log.warning("region %s member at +%s: %s", prefix, mb.get("offset"), e)
        if mmap:
            self._member_maps[f"{prefix}_buf"] = sorted(mmap, key=lambda x: x[0])

    def _int_arg_regs(self) -> list:
        """This arch's integer argument registers in order (AArch64 x0..x7, AMD64
        rdi/rsi/...). Prefers the calling convention's own ARG_REGS, with a per-family
        fallback. Shared by argument setup and call models so both read the same bank."""
        try:
            regs = list(getattr(self.project.factory.cc(), "ARG_REGS", None) or [])
        except Exception:
            regs = []
        if regs:
            return regs
        if self.arch.name.startswith("AARCH64"):
            return ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
        return ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

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
        # Fallback: the arch's integer argument registers.
        regs = self._int_arg_regs()
        if index < len(regs):
            setattr(state.regs, regs[index], value)

    def _locals_map(self):
        out = {}
        for v in self.binary.dwarf_vars(self.func_addr):
            if v.sort == "stack":
                out[v.name] = {"offset": v.frame_offset(self.arch.bytes), "size": v.size or self.arch.bytes}
        return out

    # ------------------------------------------------------------------ checks
    def _anchor_oob_to_buffer(self, cspec: dict) -> dict:
        """An oob_read/oob_write check with no explicit `base` falls back to its
        "modeled" mode (watch hooked allocations). If the scenario instead declares
        a buffer on a pointer arg — and nothing is allocating via an `alloc` model —
        anchor the check to that buffer automatically, so the natural setup
        (declare a sized buffer, add an oob check) fires without the user having to
        repeat base+size on the check. Ambiguous (multiple buffers) is left alone."""
        if cspec.get("kind") not in ("oob_read", "oob_write") or cspec.get("base"):
            return cspec
        all_bufs = self.spec.get("buffers") or []
        # A size_from buffer is a TRACKED allocation with a SYMBOLIC length — the oob check must
        # stay in modeled mode so it tests against that symbolic size (anchoring it to the fixed
        # physical size would defeat the whole point). Treat it like an alloc model.
        has_alloc = (any(m.get("kind") == "alloc" for m in (self.spec.get("models") or []))
                     or any(b.get("size_from") for b in all_bufs))
        bufs = [b for b in all_bufs if b.get("arg") and b.get("size") and not b.get("size_from")]
        if has_alloc:
            return cspec                       # modeled mode is intended; don't override
        if len(bufs) == 1:
            b = bufs[0]
            c = dict(cspec)
            c["base"] = b["arg"]
            c["size"] = int(b["size"])
            return c
        # nothing to anchor to (no base, no single buffer, no alloc model): the check
        # cannot fire. Record a diagnostic so the run doesn't just silently find nothing.
        name = cspec.get("name") or cspec.get("id") or cspec["kind"]
        if len(bufs) > 1:
            self._setup_notes.append(
                f"{cspec['kind']} check '{name}' has no base and {len(bufs)} buffers are "
                f"declared — ambiguous; set base+size on the check (or declare one buffer).")
        else:
            self._setup_notes.append(
                f"{cspec['kind']} check '{name}' has nothing to anchor to — give it base+size, "
                f"declare a buffer on a pointer arg, or add an 'alloc' call model. It cannot fire as-is.")
        return cspec

    def _make_context(self):
        lo = self.func_addr
        hi = self.func_addr + self.func_size
        rets = self.binary.return_block_heads(self.func_addr)

        def line_for(addr):
            # nearest_line (not the exact line_for): the DWARF line table only marks
            # where each statement starts, so the instruction that actually overflows/
            # narrows often continues a line and has no entry of its own. Map it to the
            # nearest preceding entry in the same function so findings carry a source line.
            e = self.binary.nearest_line(addr)
            return {"file": e[0].split("/")[-1], "line": e[1]} if e else None

        def path_of(state):
            return [hex(a) for a in list(state.history.bbl_addrs)[-8:]]

        return CheckContext(
            target_func_lo=lo, target_func_hi=hi, return_addrs=rets,
            line_for=line_for, path_of=path_of, on_hit=self._on_hit,
            block_head=self.binary.block_head,
            cancelled=self._cancel.is_set,     # checks bail immediately once cancel is requested
        )

    def _emit(self, kind, **data):
        if self.on_event:
            try:
                self.on_event(kind, **data)
            except Exception:
                pass

    def _declared_var_names(self, state) -> set:
        """The claripy variable names of every input SEAL itself made symbolic (args,
        buffers and their members, snapshot overlays, stdin, files). Anything in a
        finding's constraints that is NOT in here is engine-introduced — most often an
        unconstrained return from a skipped call — which is what separates a CONFIRMED
        finding (driven by real inputs) from a CONDITIONAL one."""
        declared: set = set()
        for ast in (state.globals.get("angrgui_vars") or {}).values():
            if isinstance(ast, claripy.ast.Base):
                declared |= ast.variables
        so = state.globals.get("angrgui_stdin")
        if isinstance(so, claripy.ast.Base):
            declared |= so.variables
        for fb in (state.globals.get("angrgui_files") or {}).values():
            if isinstance(fb, claripy.ast.Base):
                declared |= fb.variables
        return declared

    def _classify_finding(self, state, hit=None) -> tuple[str, list]:
        """(confidence, depends_on). 'confirmed' = the finding depends only on declared
        inputs. 'conditional' = it also depends on an unconstrained value SEAL did not
        control — a skipped call's return (named after its callee) or a raw fake_ret — so
        it only holds IF that call can produce the needed value; depends_on names them.
        Dependency = the path constraints UNION the triggering expression's own variables
        (extra._dep), so a bug driven by an unconstrained return is caught even when no
        branch constrained it (e.g. buf[clip()] with no guard on the return)."""
        if state is None:
            return "unknown", []
        declared = self._declared_var_names(state)
        dep: set = set()
        for c in state.solver.constraints:
            try:
                dep |= c.variables
            except Exception:
                pass
        if hit is not None:
            dep |= set(hit.extra.get("_dep", []))
        skip_labels = set(self._skip_ret_names.values())
        culprits: list = []
        for v in (dep - declared):
            lbl = next((l for l in skip_labels if v == l or v.startswith(l + "_")), None)
            if lbl is not None:
                culprits.append(lbl)
            elif "fake_ret_value" in v:
                culprits.append("an unmodeled call return")
        if culprits:
            return "conditional", sorted(set(culprits))
        return "confirmed", []

    def _on_hit(self, hit: Hit, state):
        with self._lock:
            # the state carries the id of the tree node (path stretch) it belongs to
            nid = state.globals.get("angrgui_node") if state is not None else None
            hit.extra["node"] = nid
            try:
                conf, deps = self._classify_finding(state, hit)
                hit.extra["confidence"] = conf
                if deps:
                    hit.extra["depends_on"] = deps
            except Exception:
                pass
            hit.extra.pop("_dep", None)       # internal: don't leak var names to output
            self.hits.append(hit)
            hit.id = f"f{len(self.hits)}"     # stable per-run finding id (#7): reference as (run_id, id)
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

    def _is_hooked(self, addr) -> bool:
        try:
            return self.project.is_hooked(int(addr))
        except Exception:
            return False

    def _addr_mapped(self, addr) -> bool:
        """Is `addr` inside some loaded object? A concrete IP that isn't means execution
        branched into a module we don't have (an unloaded dyld-cache dylib)."""
        if not isinstance(addr, int):
            return True
        try:
            return self.project.loader.find_object_containing(addr) is not None
        except Exception:
            return True                              # unsure -> don't treat as unmapped

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
        # Cap each condition to a readable length. A branch on symbolic floating-point
        # (aa_lineto's clamp/compare) stringifies to thousands of chars of fp gibberish
        # that is unreadable anyway AND froze the GUI when rendered across the path tree.
        # Short readable conditions (flags & 0x30000, outcodes) are well under this.
        fmt = (lambda c: self._printer(c, limit=240)) if self._printer is not str else str
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
        elif fate == "left_image":
            nm = self.binary.name_at(last)
            node.end = {"reason": "left_image",
                        "text": ("tail-called out of the loaded image"
                                 + (f" from {nm}" if nm else "")
                                 + " — the branch target is in a module not loaded here (e.g. an "
                                 "unloaded dyld-cache dylib). The path ends cleanly instead of "
                                 "erroring on unmapped code.")}
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
            if self.func_addr <= b < self.func_addr + self.func_size:
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
            # Per-query solver timeout so a single pathological Z3 solve can't hang a
            # step forever — otherwise the cancel/time checks between steps never run and
            # the run looks "stuck" and unkillable (#3). Child states inherit this.
            try:
                state.solver._solver.timeout = 60_000   # ms
            except Exception as e:
                log.warning("could not set solver timeout: %s", e)
            self._install_models(state)
            self._install_concretization_watch(state)

            ctx = self._make_context()
            self._state_checks = []
            for cspec in self.spec.get("checks", []):
                if not cspec.get("enabled", True):
                    continue
                cspec = self._anchor_oob_to_buffer(cspec)
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

            # Observe the ENTRY block before stepping: the initial state's block is
            # never a post-step successor, so a reach/avoid/assert/custom check pinned
            # anywhere in the entry block would otherwise be silently missed.
            for chk in self._state_checks:
                try:
                    chk.note_state(state)
                except Exception:
                    pass

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
            if loop_bound > 0 and self.func is not None:
                try:
                    from angr.exploration_techniques import LoopSeer
                    simgr.use_technique(LoopSeer(
                        cfg=self.binary.cfg_for(self.func_addr), functions=[self.func],
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
                # throttled live progress to the activity feed, so a run reads as "N paths
                # being explored" rather than looking stuck (#6).
                now = time.time()
                if now - getattr(self, "_last_progress", 0) >= 0.7:
                    self._last_progress = now
                    self._emit("run_progress", func=self.func_addr, step=step,
                               active=len(simgr.active), deadended=len(simgr.deadended),
                               hits=len(self.hits))
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
            # x86 `call`, arm64 branch-with-link (`bl` direct, `blr`/`blraa..` indirect).
            if last.mnemonic == "call" or last.mnemonic.startswith("bl"):
                opc = op.lstrip("#").strip()                     # arm64 prints `bl #0x...`
                if re.fullmatch(r"0x[0-9a-fA-F]+", opc):         # direct: call/bl <addr>
                    tgt = int(opc, 16)
                    nm = (self.binary.name_at(tgt) or f"sub_{tgt:x}").lstrip("_")
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

    def _direct_target(self, site: int):
        """The target address of a direct call (`bl 0x..`/`call 0x..`) at this block,
        else None (indirect call)."""
        try:
            last = self.project.factory.block(site).capstone.insns[-1]
            if last.mnemonic == "call" or last.mnemonic.startswith("bl"):
                opc = (last.op_str or "").strip().lstrip("#").strip()
                if re.fullmatch(r"0x[0-9a-fA-F]+", opc):
                    return int(opc, 16)
        except Exception:
            pass
        return None

    def _apply_return_bounds(self, state, site: int, retbv):
        """Constrain a skipped call's return to what the user says it can be (values /
        min / max). This RESOLVES a 'conditional' finding in the default skip_calls=ON
        workflow: instead of leaving the return wild, say e.g. aa_clip_edge returns <=3
        and the out-of-bounds index can no longer occur (the finding is dismissed) — or
        it still can (confirmed). Matched by callee name substring or call-target address."""
        bounds = self.spec.get("return_bounds") or []
        if not bounds:
            return
        tgt = self._direct_target(site)
        name = ((self.binary.name_at(tgt) if tgt is not None else "") or "").lstrip("_")
        label = (self._skip_ret_names.get(site) or self._callee_label(site) or "")
        bits = retbv.size()
        mask = (1 << bits) - 1
        for b in bounds:
            call = str(b.get("call", "")).strip()
            if not call:
                continue
            if call.lower().startswith("0x"):
                try:
                    hit = (tgt is not None and int(call, 16) == tgt)
                except ValueError:
                    hit = False
            else:
                low = call.lower().lstrip("_")
                hit = low in name.lower() or low in label.lower()
            if not hit:
                continue
            try:
                if b.get("values") is not None:
                    vs = [int(x) & mask for x in b["values"]]
                    if vs:
                        state.add_constraints(claripy.Or(*[retbv == v for v in vs]))
                if b.get("min") is not None:
                    state.add_constraints(claripy.UGE(retbv, int(b["min"]) & mask))
                if b.get("max") is not None:
                    state.add_constraints(claripy.ULE(retbv, int(b["max"]) & mask))
            except Exception:
                pass

    def _name_skipped_rets(self, states):
        """CALLLESS writes an Unconstrained value angr names 'fake_ret_value' for
        every skipped call, so unrelated returns look identical in branch
        conditions. Give each a name derived from its callee instead. The value is
        still freshly unconstrained (same semantics) — only the label changes, and
        it is renamed before the next block consumes it (e.g. `cmp eax, 4`). When the
        scenario declares return_bounds for the callee, also constrain the return there
        — that is how a 'conditional' finding is resolved without leaving skip_calls."""
        if not self.spec.get("limits", {}).get("skip_calls", True):
            return
        ro = self.arch.ret_offset
        for s in states:
            try:
                if s.history.jumpkind != "Ijk_FakeRet":
                    continue
                rv = s.registers.load(ro, self.arch.bytes)
                if rv.op != "BVS" or "fake_ret_value" not in rv.args[0]:
                    continue
                hist = list(s.history.bbl_addrs)
                site = hist[-1] if hist else 0
                nb = claripy.BVS(self._skip_ret_name(s), self.arch.bits)
                s.registers.store(ro, nb)
                self._apply_return_bounds(s, site, nb)
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
            elif (fate == "active" and isinstance(addr, int) and addr != self._return_addr
                  and not self._is_hooked(addr) and not self._addr_mapped(addr)):
                # concrete IP in NO loaded object (and not our return sentinel / a hook):
                # a tail-call / branch into code we don't have (an unloaded dyld-cache
                # dylib, a PLT stub's target in another image). skip_calls only skips
                # CALLs, not tail branches, so without this the path errors on unmapped
                # bytes. End it cleanly as "left the image" instead.
                fate = "left_image"
                hijacked.append(s)
            self._note_branch(s)
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
            if self._cancel.is_set():          # stop running checks once cancel is requested
                break
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
        # an explicit reason the run STOPPED (not just status), so a retrieved run says
        # whether it finished exploring or was cut off by a limit (#8).
        lim = self.spec.get("limits", {}) or {}
        max_steps = int(lim.get("steps", 200)); max_seconds = float(lim.get("seconds", 30))
        find = lim.get("find")
        if self.status == "cancelled":
            stopped = "cancelled"
        elif self.status == "error":
            stopped = "errored: " + (self.error or "unknown")[:120]
        elif find and getattr(simgr, "found", []):
            stopped = "reached the find target"
        elif not simgr.active:
            stopped = "explored all reachable paths (complete)"
        elif self.progress["step"] >= max_steps:
            stopped = f"hit the step limit ({max_steps}) — raise 'steps' to explore deeper"
        elif self.progress["elapsed"] >= max_seconds * 0.9:
            stopped = f"hit the time budget ({max_seconds:g}s) — raise 'seconds'"
        else:
            stopped = "stopped"
        self.summary.update({
            "status": self.status,
            "stopped": stopped,
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
        self.summary["coverage"] = self._coverage()
        trunc = self._truncation()
        if trunc:
            self.summary["truncation"] = trunc
        covered = set()
        for n in self.nodes.values():
            covered |= set(n.block_addrs)
        gates = self._concrete_gates(covered)
        if gates:
            self.summary["concrete_gates"] = gates
        # how trustworthy the findings are, at a glance (see _classify_finding)
        conf = {"confirmed": 0, "conditional": 0}
        for h in self.hits:
            conf[h.extra.get("confidence", "confirmed")] = \
                conf.get(h.extra.get("confidence", "confirmed"), 0) + 1
        if self.hits:
            self.summary["confidence"] = {k: v for k, v in conf.items() if v}
        notes = self._diagnose(simgr)
        if notes:
            self.summary["notes"] = notes

    def _note_branch(self, s):
        """Record, per branch block, which targets were taken and whether the guard
        was ever symbolic. A static 2-way branch that was only ever taken one way
        with a CONCRETE guard is gated by fixed state (a snapshot field / a value the
        inputs don't reach) — the other side can't be explored until that field is
        made symbolic. (A branch seen with a symbolic guard is input-dependent; not a gate.)"""
        try:
            g = s.history.jump_guard
            src = s.history.jump_source
        except Exception:
            return
        if g is None or src is None:
            return
        try:
            src = int(src if isinstance(src, int) else s.solver.eval(src))
        except Exception:
            return
        if not (self.func_addr <= src < self.func_addr + self.func_size):
            return
        rec = self._branches.setdefault(src, {"taken": set(), "sym": False})
        try:
            tgt = s.history.jump_target
            if tgt is not None:
                rec["taken"].add(int(tgt if isinstance(tgt, int) else s.solver.eval(tgt)))
        except Exception:
            pass
        try:
            if g.symbolic:
                rec["sym"] = True
        except Exception:
            pass

    def _static_branch_edges(self, src: int) -> set:
        """The two static successors of a conditional-branch block: {taken_target,
        fallthrough}. Empty if the block does not end in a conditional branch."""
        try:
            blk = self.project.factory.block(src)
            last = blk.capstone.insns[-1]
            mn = last.mnemonic
            cond = (mn.startswith("b.") or mn in ("cbz", "cbnz", "tbz", "tbnz")
                    or (mn.startswith("j") and mn != "jmp"))      # arm64 + x86 conditional jumps
            if not cond:
                return set()
            m = re.search(r"(0x[0-9a-fA-F]+)\s*$", last.op_str or "")
            if not m:
                return set()
            return {int(m.group(1), 16), blk.addr + blk.size}       # target + fallthrough
        except Exception:
            return set()

    def _reg_num(self, tok: str):
        """Register number ignoring width: w8/x8 -> '8', so a cbz on w8 matches a load
        into x8. None for sp/non-GP operands."""
        m = re.fullmatch(r"[wx](\d{1,2}|zr)", (tok or "").strip().lower())
        return m.group(1) if m else None

    def _containing_block(self, addr: int) -> int:
        """Start of the function block that contains `addr` (jump_source is the branch
        INSTRUCTION, which may sit at the end of a multi-instruction block)."""
        try:
            starts = [b for b in self.func.block_addrs_set if b <= addr]
            return max(starts) if starts else addr
        except Exception:
            return addr

    def _gate_field_candidates(self, src: int) -> list:
        """The field(s) whose concrete value decides this branch, as ready-to-paste
        symbolic specs {base, offset, size}. We find the register the branch tests
        (directly for cbz/tbz, via the preceding cmp/tst for b.<cond>) and the load that
        defines it — so the suggestion is the EXACT gating field, not every load in the block."""
        _SZ = {"ldrb": 1, "ldrsb": 1, "ldrh": 2, "ldrsh": 2, "ldrsw": 4}
        try:
            insns = self.project.factory.block(self._containing_block(src)).capstone.insns
        except Exception:
            return []
        if not insns:
            return []
        last = insns[-1]
        mn = last.mnemonic
        tested = set()
        if mn in ("cbz", "cbnz", "tbz", "tbnz"):
            tested.add(self._reg_num((last.op_str or "").split(",")[0]))
        elif mn.startswith("b.") or (mn.startswith("j") and mn != "jmp"):
            for i in reversed(insns[:-1]):                         # the flag-setting compare
                if i.mnemonic in ("cmp", "cmn", "tst", "ccmp", "subs", "ands", "adds"):
                    for tok in re.split(r"[,\s]+", i.op_str or ""):
                        rn = self._reg_num(tok)
                        if rn:
                            tested.add(rn)
                    break
        tested.discard(None)

        def parse_load(i):
            dst = (i.op_str or "").split(",")[0].strip()
            size = _SZ.get(i.mnemonic, 8 if dst.startswith(("x", "d", "q")) else 4)
            m = re.search(r"\[\s*(\w+)\s*(?:,\s*#(-?0x[0-9a-fA-F]+|-?\d+))?\s*\]", i.op_str or "")
            if not m or m.group(1) == "sp":                       # skip stack spills
                return None
            return {"base": m.group(1), "offset": hex(int(m.group(2) or "0", 0)), "size": size,
                    "_dst": self._reg_num(dst)}

        # The LIVE definition of each tested register is the LAST load into it before the
        # branch (earlier writes are overwritten — e.g. the two canary `ldr x8,[x8,..]`
        # loads are superseded by `ldr w8,[x0,#0xb4]`, which is the real gating field).
        last_def, allloads, seen = {}, [], set()
        for i in insns:
            if not i.mnemonic.startswith("ld"):
                continue
            c = parse_load(i)
            if c is None:
                continue
            dst = c.pop("_dst")
            if dst is not None:
                last_def[dst] = c
            key = (c["base"], c["offset"])
            if key not in seen:
                seen.add(key)
                allloads.append(c)
        precise = [last_def[r] for r in tested if r in last_def]
        return (precise or allloads)[:6]

    def _gate_test_text(self, src: int) -> str:
        """The branch's own test, e.g. 'cbz w8' or 'tst w8, #0x30000; b.eq' — so even
        when the deciding value is computed (not a single load) the agent sees what to
        read in the decompilation to find the gating field."""
        try:
            insns = self.project.factory.block(self._containing_block(src)).capstone.insns
            last = insns[-1]
            txt = f"{last.mnemonic} {last.op_str}".strip()
            if last.mnemonic.startswith("b.") and len(insns) > 1:
                p = insns[-2]
                txt = f"{p.mnemonic} {p.op_str}; {txt}".strip()
            return txt
        except Exception:
            return ""

    def _concrete_gates(self, covered: set) -> list:
        """Static 2-way branches only ever taken one way with a concrete guard, whose
        other side was never reached: the inputs can't currently steer them. Each entry
        says where, which side was missed, and which fields to make symbolic to open it."""
        gates = []
        for src, rec in self._branches.items():
            if rec["sym"]:                               # input-dependent branch, not a gate
                continue
            edges = self._static_branch_edges(src)
            if len(edges) < 2:
                continue
            missed = [e for e in (edges - rec["taken"])
                      if e not in covered and self.func_addr <= e < self.func_addr + self.func_size]
            if not missed:
                continue
            gates.append({
                "at": hex(src),
                "test": self._gate_test_text(src),
                "always_went": hex(min(rec["taken"])) if rec["taken"] else None,
                "never_reached": hex(min(missed)),
                "make_symbolic": self._gate_field_candidates(src),
            })
        gates.sort(key=lambda g: g["at"])
        return gates[:8]

    def _coverage(self) -> dict:
        """How much of the TARGET function the run actually explored. A 0-finding run
        at 100% coverage is a real negative; at 40% it just didn't look — this is the
        signal that tells those two apart. `unreached` lists the function's own blocks
        no path entered (capped), so the user can see WHERE exploration fell short."""
        covered: set = set()
        for n in self.nodes.values():
            covered |= set(n.block_addrs)
        try:
            total = set(self.func.block_addrs_set) if self.func is not None else set()
        except Exception:
            total = set()
        if not total:
            return {"blocks_covered": len(covered), "blocks_total": None, "pct": None}
        covered_in = covered & total
        unreached = sorted(total - covered_in)
        return {
            "blocks_total": len(total),
            "blocks_covered": len(covered_in),
            "pct": round(100 * len(covered_in) / len(total)),
            "unreached": [hex(a) for a in unreached[:50]],
            "unreached_total": len(unreached),
        }

    def _truncation(self) -> dict | None:
        """The boundedness blind spot, made first-class: loops whose iteration count the
        inputs drive were cut at loop_bound, so iterations BEYOND the bound — where a copy
        sized by an attacker-controlled count tends to overflow — were never explored.

        This is sound to report as input-dependent: LoopSeer runs with
        limit_concrete_loops=False, so a concrete-trip loop is NOT bounded; every path that
        ends in a loop_bound leaf is therefore a loop whose trip count isn't concrete. A
        0-finding run with truncation is 'didn't look past N iterations', not 'safe'."""
        sites: dict = {}
        cut = 0
        for n in self.nodes.values():
            if (n.end or {}).get("reason") != "loop_bound":
                continue
            cut += 1
            body = n.block_addrs[-1] if n.block_addrs else n.addr
            if body not in sites:
                sites[body] = {"addr": hex(body), **(self.binary.source_at(body) or {})}
        if not cut:
            return None
        return {
            "bound": self._loop_bound,
            "paths_cut": cut,
            "sites": list(sites.values())[:10],
            "loops": len(sites),
        }

    def _diagnose(self, simgr) -> list[str]:
        """Human-readable hints about why a run turned out the way it did — so a
        run that finds nothing explains itself instead of leaving the agent guessing."""
        notes = list(self._setup_notes)
        # The big "can't actually validate this function" signal: it dereferenced a
        # pointer arg that has no buffer behind it, so reads hit unmapped/zero memory.
        if self._wild_deref:
            who = ", ".join(f"{a} ({n} read{'s' if n != 1 else ''})"
                            for a, n in sorted(self._wild_deref.items(), key=lambda kv: -kv[1]))
            notes.append(
                f"the function dereferenced pointer arg(s) with NO buffer set up — {who}. "
                f"Those reads go to unmapped/zero memory, so this run is NOT a meaningful "
                f"validation: declare a buffer for each such arg (configure buffers:[{{arg,size}}]), "
                f"and for a struct arg give pointer members their own target (nested buffers). "
                f"Or set limits.auto_pointers=true to auto-back every pointer arg with a symbolic "
                f"region (finds bugs in the pointed-to data; treat results as leads — see below).")
        if self._auto_backed:
            typed = set(self.spec.get("_auto_ptr_args", []))
            how = []
            if typed:
                how.append(f"{', '.join(sorted(typed))} by their struct type (named fields, pointer "
                           f"members expanded)")
            flat = self._auto_backed - typed
            if flat:
                how.append(f"{', '.join(sorted(flat))} with a flat {self.AUTO_PTR_REGION}-byte region")
            notes.append(
                f"auto_pointers backed pointer arg(s): {'; '.join(how)}. Any finding here ASSUMES each "
                f"pointer is valid and points to attacker-controlled memory — true for a real input "
                f"buffer, FALSE for an internal/fixed pointer. Treat these as leads: confirm the pointer "
                f"is actually attacker-influenced before trusting the bug.")
        enabled_checks = [c for c in self.spec.get("checks", []) if c.get("enabled", True)]
        unconstrained = len(getattr(simgr, "unconstrained", []))
        errored = len(getattr(simgr, "errored", []))
        if unconstrained:
            notes.append(f"{unconstrained} path(s) went unconstrained (the instruction pointer "
                         f"became symbolic — usually an unresolved/indirect call). Turn on skip_calls "
                         f"or add call models so exploration stays in the function.")
        if errored:
            # surface the ACTUAL errors, deduplicated — on arm64 an
            # UnsupportedIROpError/decode error names the exact op to add to
            # angr_arm_patch.py, which is far more useful than a bare count.
            counts: dict[str, int] = {}
            for rec in getattr(simgr, "errored", []):
                try:
                    e = rec.error
                    msg = f"{type(e).__name__}: {e}"
                except Exception:
                    msg = "unknown error"
                counts[msg] = counts.get(msg, 0) + 1
            top = "; ".join(m[:140] + (f" (x{c})" if c > 1 else "")
                            for m, c in sorted(counts.items(), key=lambda kv: -kv[1])[:3])
            notes.append(f"{errored} path(s) errored out: {top or 'unknown error'}. "
                         f"UnsupportedIROpError / UnsupportedDirtyError / decode error = angr can't model "
                         f"that op or helper: a NEON op or arm64e instruction can be added in "
                         f"angr_arm_patch.py; an x86 x87/SIMD dirty helper (e.g. loadF80le, long double) "
                         f"is an angr limitation with no easy fix — avoid that path or pick another function. "
                         f"A memory error may need a buffer/model; skip_calls avoids stepping into library code.")
        # Findings that only hold because an UNMODELED call could return the right value
        # are leads, not confirmed bugs — say so and name the call(s) to model next.
        cond = [h for h in self.hits if h.extra.get("confidence") == "conditional"]
        if cond:
            calls = sorted({c for h in cond for c in h.extra.get("depends_on", [])})
            bare = sorted({c[:-4] if c.endswith("_ret") else c for c in calls})
            notes.append(
                f"{len(cond)} of {len(self.hits)} finding(s) are CONDITIONAL: the triggering "
                f"value depends on the unconstrained return of a skipped call "
                f"({', '.join(calls) or 'an unmodeled call'}), so it only holds IF that call can "
                f"return the needed value. Resolve it with constrain_return(call=\""
                f"{bare[0] if bare else '<callee>'}\", max=... / values=[...]) and re-run: if the "
                f"bound rules out the triggering value the finding is dismissed, else confirmed.")
        # Concrete gates: branches the inputs can't currently steer — the #1 reason a
        # snapshot run misses the bug (a fixed field selects the safe side). Name them
        # and hand over the exact field(s) to make symbolic to open the other side.
        gates = self.summary.get("concrete_gates") or []
        if gates and (len(self.hits) == 0 or (self.summary.get("coverage") or {}).get("pct", 100) < 100):
            g = gates[0]
            specs = g.get("make_symbolic") or []
            hint = ""
            if specs:
                ex = specs[0]
                hint = (f" The branch reads e.g. [{ex['base']}, {ex['offset']}]; add it to "
                        f"load_snapshot symbolic as {{\"base\":\"{ex['base']}\",\"offset\":\"{ex['offset']}\","
                        f"\"name\":\"gate\",\"size\":{ex['size']}}} (see make_symbolic in summary.concrete_gates "
                        f"for all candidates) and re-run.")
            notes.append(
                f"{len(gates)} branch(es) were decided by CONCRETE state and their other side never "
                f"explored — e.g. the branch at {g['at']} always went to {g['always_went']} and never "
                f"reached {g['never_reached']}. That is a fixed value gating the path, not a dead end: "
                f"make the field that selects it symbolic.{hint}")
        # Lossy address concretization: a symbolic index got pinned, so a later check on
        # it can under-report (notably an OOB write masked by an earlier OOB read). Only
        # surface it when symbolic_addrs is OFF — if it's already on, the mitigation is
        # applied and pointing at it would be misleading.
        if self._concretized and not self.spec.get("limits", {}).get("symbolic_addrs"):
            first = self._concretized[0]
            act = first.get("action") or "access"
            notes.append(
                f"{len(self._concretized)} symbolic memory address(es) were pinned to one value "
                f"during the run (first: a {act} at {hex(first['addr'])}). angr concretizes a "
                f"symbolic access to a single address, so a LATER check on that same index can "
                f"UNDER-REPORT — e.g. an out-of-bounds WRITE may not fire because an earlier READ "
                f"already pinned the index. FIX: set limits.symbolic_addrs=true to keep the index "
                f"symbolic so the checks see its full range (costs more solver time).")
        # Coverage: a 0-finding run that only reached part of the function is NOT a clean bill.
        cov = self.summary.get("coverage") or {}
        if cov.get("pct") is not None and cov["pct"] < 100:
            tail = ""
            if len(self.hits) == 0:
                tail = (" — a no-finding result here does NOT mean the function is safe; the "
                        "unreached blocks may hold the bug (raise 'steps'/'loop_bound', relax "
                        "assumptions, or make a gating input symbolic to reach them).")
            notes.append(f"explored {cov['pct']}% of the function "
                         f"({cov['blocks_covered']}/{cov['blocks_total']} blocks){tail}")
        # Boundedness: a loop with an input-dependent trip count was cut at loop_bound, so
        # iterations beyond the bound were never explored. This is the exact gap bounded
        # symbolic execution has that formal methods don't — a bug that needs > bound
        # iterations (a copy sized by an attacker-controlled count) is NOT covered here.
        trunc = self.summary.get("truncation")
        if trunc:
            where = ""
            s0 = (trunc.get("sites") or [{}])[0]
            if s0.get("line"):
                where = f" (first at {s0.get('addr')}, line {s0['line']})"
            elif s0.get("addr"):
                where = f" (first at {s0['addr']})"
            notes.append(
                f"BOUNDED: {trunc['paths_cut']} path(s) hit the loop bound — a loop whose "
                f"iteration count the inputs drive was cut at {trunc['bound']} iterations{where}. "
                f"angr only unrolled it {trunc['bound']} times, so a bug that needs MORE iterations "
                f"(e.g. a copy/write sized by an attacker-controlled count) is NOT covered. Raise "
                f"limits.loop_bound to probe deeper (costs more paths/time); a 0-finding result here "
                f"is 'didn't look past {trunc['bound']} iterations', not 'safe'.")
        if len(self.hits) == 0 and enabled_checks and not self._setup_notes:
            # a setup note already names a concrete cause; only guess further when there isn't one.
            sym_args = any(a.get("mode", "symbolic") == "symbolic" for a in self.spec.get("args", []))
            has_input = (sym_args or self.spec.get("buffers") or self.spec.get("stdin")
                         or self.spec.get("files") or self.spec.get("initial_state"))
            # A check's site was REACHED but never triggered (e.g. a narrowing was executed
            # but the value always fit) — the single most useful thing to say, because it
            # means a CONCRETE field is gating the vulnerable branch, not that there's no bug.
            near = {}
            for c in self.checks:
                for a, t in getattr(c, "near", {}).items():
                    near.setdefault(a, t)
            if not has_input:
                notes.append("no findings, and no symbolic inputs were set (no symbolic args, buffers, "
                             "stdin, files, or seeded state) — there is nothing for the checks to solve over.")
            elif near:
                sites = ", ".join(f"{t or 'site'} @ {hex(a)}" for a, t in list(near.items())[:4])
                notes.append(f"no findings, BUT a check site WAS REACHED and just never triggered on any "
                             f"explored path: {sites}. That usually means a bug is there but a CONCRETE "
                             f"input is gating the vulnerable branch — make the field(s) that SELECT the "
                             f"branch symbolic too, not only the obvious attacker input (for a snapshot, "
                             f"mark the gating struct field/flag symbolic as well).")
            elif self.progress["step"] <= 2 and not simgr.active:
                notes.append("no findings, and exploration stopped almost immediately — the check sites "
                             "may be unreachable from the entry, or the step limit is too low.")
            else:
                notes.append("no findings — the checks ran but nothing triggered. If you expected a hit, "
                             "widen limits, relax assumptions, or confirm the check targets the right site.")
        return notes

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


def trace_assignments(binary, spec: dict, example: dict, max_steps: int = 6000,
                      until_addr: int | None = None) -> dict:
    """Re-execute a function with the example's concrete inputs and record, per
    instruction address, the concrete values involved: the destination register
    written (an assignment), memory stores, AND the operand registers/memory READ
    (so EVERY value on a line is visible, not just the assignment result — #4). If
    `until_addr` is given (the finding's address), the trace stops the first time it
    reaches there, so values reflect the loop ITERATION that caused the finding.

    Returns {hex_addr: {"reg","val","store"?, "reads": {reg:val,...}, "load": {addr,val}?}}.
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
    # Skip calls while tracing: we only want per-line values IN this function, and
    # library-call internals aren't its source lines. Crucially, with the finding's
    # CONCRETE inputs a call like memset(dst, c, size) can have a huge concrete size
    # (e.g. an overflow witness ~1.7e9) and executing it for real would try to write
    # gigabytes — CPU-bound under the GIL, hanging the whole server. CALLLESS avoids it.
    cspec["limits"] = {**(cspec.get("limits") or {}), "skip_calls": True}

    run = Run(binary, cspec)
    state = run._build_state()
    run._install_models(state)                    # honour alloc/return models (e.g. malloc)
    arch = binary.arch
    SKIP = {"ip", "rip", "eip", "pc", "sp", "rsp", "esp", "xsp", "bp", "x29", "lr", "x30",
            "cc_op", "cc_dep1", "cc_dep2", "cc_ndep", "nzcv", "cpsr", "fpcr", "fpsr", "qc",
            "d", "ac", "id", "fs", "gs", "fs_const", "gs_const"}
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

    reads, loads = {}, {}
    hit = {"until": False}

    def on_rr(s):                                 # operand register READ (feeds this line)
        ia = s.scratch.ins_addr
        if ia is None:
            return
        if until_addr is not None and ia == until_addr:
            hit["until"] = True
        try:
            off = s.inspect.reg_read_offset
            if isinstance(off, claripy.ast.Base):
                off = s.solver.eval(off)
            length = s.inspect.reg_read_length or arch.bytes
            if isinstance(length, claripy.ast.Base):
                length = s.solver.eval(length)
            name = arch.translate_register_name(off, int(length))
            if not name or name in SKIP:
                return
            val = s.inspect.reg_read_expr
            reads.setdefault(ia, {})[name] = hex(s.solver.eval(val)) if val is not None else None
        except Exception:
            pass

    def on_mr(s):                                 # memory LOAD (a deref / struct member read)
        ia = s.scratch.ins_addr
        if ia is None:
            return
        try:
            val = s.inspect.mem_read_expr
            loads[ia] = {"addr": hex(s.solver.eval(s.inspect.mem_read_address)),
                         "val": hex(s.solver.eval(val)) if val is not None else None}
        except Exception:
            pass

    state.inspect.b("reg_write", when=angr.BP_AFTER, action=on_rw)
    state.inspect.b("mem_write", when=angr.BP_BEFORE, action=on_mw)
    state.inspect.b("reg_read", when=angr.BP_AFTER, action=on_rr)
    state.inspect.b("mem_read", when=angr.BP_AFTER, action=on_mr)
    simgr = binary.project.factory.simgr(state)
    steps = 0
    deadline = time.time() + 20                   # never let annotation hang the server
    while simgr.active and steps < max_steps and time.time() < deadline:
        simgr.step()
        steps += 1
        if len(simgr.active) > 1:                 # inputs are concrete; keep a single path
            del simgr.active[1:]
        if hit["until"]:                          # reached the finding — stop at this iteration
            break

    out = {}
    for ia, rv in regvals.items():
        out[hex(ia)] = dict(rv)
    for ia, mv in memvals.items():
        out.setdefault(hex(ia), {})["store"] = mv
    for ia, rd in reads.items():
        out.setdefault(hex(ia), {})["reads"] = rd
    for ia, ld in loads.items():
        out.setdefault(hex(ia), {})["load"] = ld
    return out
