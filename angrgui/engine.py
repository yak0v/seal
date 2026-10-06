"""
Static side of the tool: load a binary with angr, list functions, disassemble,
recover DWARF variables and source lines, and describe the per-function CFG.

ROLE
----
``Binary`` is SEAL's "static model": everything the GUI/MCP read *about* a program
without executing it — the function list, disassembly, CFG, DWARF vars, names and
source lines. The dynamic/symbolic side lives in ``runner.py``; this file never
explores, it only describes. (``backend.AngrBackend`` wraps a ``Binary`` + runs.)

WHY IT'S LIKE THIS
------------------
* **Lazy mode.** A whole-binary ``CFGFast`` is fine for a small ELF but hopeless on
  a ~13k-function iOS/macOS dyld-cache dylib (minutes-to-never, gigabytes). So for
  big binaries we DON'T build a global CFG. We index every function cheaply from the
  symbol table (``_build_index``) and build each function's CFG *on demand* the first
  time it's selected (``analyze_function`` → scoped ``CFGFast(regions=[(fa, fa+size)])``
  + ``CompleteCallingConventions`` + ``angr_arm_patch.patch_pac`` over just that range).
  ``auto_lazy`` trips on >2000 function symbols or >3 MB of code; ``lazy=False`` forces
  the classic global CFG for small ELFs so the x86 workflow is unchanged.
* **Mach-O function discovery.** ``cle`` does NOT reliably set ``is_function`` on Mach-O
  symbols, so ``_build_index`` can't filter on it — instead it treats any symbol that
  lands in an executable segment as a function and derives each extent from the gap to
  the next symbol. That is why the index logic looks at segment membership, not flags.
* **ARM64 support is applied here.** ``angr_arm_patch.apply()`` runs on every load so
  NEON IR ops exist; ``patch_pac`` is applied per analysed function range so arm64e PAC
  instructions in that function decode. Both are no-ops/harmless on x86-64.
* **``base_addr`` exists but is a near-dead option for Mach-O.** It is threaded into
  ``angr.Project(main_opts={"base_addr": ...})`` so an ELF/PIE can be loaded at a chosen
  base, but cle's **Mach-O backend ignores it** (it keeps the image at its file vmaddrs,
  ``min_addr`` stays 0). That is exactly why a live, ASLR-slid snapshot is reconciled by
  rebasing the SNAPSHOT down to file addresses (``snapshot/rebase.py`` + the hook in
  ``runner._build_state_from_snapshot``) rather than by sliding the loaded image up.

EXTENDING
---------
* New static view (e.g. string refs, xrefs): add a method on ``Binary`` and surface it
  through ``backend``/``server``; keep it lazy-friendly (don't force a global CFG).
* New architecture's "arith" highlighting: extend ``ARITH_MNEMONICS`` (x86) / the arch
  equivalent used by the overflow check hinting.
* Teaching angr a new ARM64 op or arch quirk belongs in ``angr_arm_patch.py``, not here.

PITFALLS
--------
* Don't call ``self.cfg`` expecting a global CFG in lazy mode — it's ``None`` until a
  function is analysed. Use ``get_function`` / ``analyze_function`` which populate it.
* ``get_function`` lazily analyses and returns ``None`` (not raise) for a bad/unknown
  address — a cold ``Explore`` of an un-analysed function used to 500 because of this.
* Function extents in lazy mode are gap-estimates; a symbol-less region may be missed.
"""
from __future__ import annotations

import bisect
import logging
import os
from dataclasses import dataclass
from typing import Any

import angr
import cle

log = logging.getLogger("angrgui.engine")

for _name in ("angr", "cle", "pyvex", "claripy"):
    logging.getLogger(_name).setLevel(logging.ERROR)

# x86 mnemonics whose result is a candidate for an overflow check.
ARITH_MNEMONICS = {
    "add", "sub", "imul", "mul", "inc", "dec", "neg", "adc", "sbb", "shl", "sal", "lea",
}


@dataclass
class DwarfVar:
    name: str
    sort: str            # 'stack' | 'global' | 'unknown'
    offset: int          # stack: offset from CFA; global: absolute address
    size: int
    signed: bool
    type_name: str
    line: int | None = None
    is_param: bool = False

    def frame_offset(self, arch_bytes: int) -> int:
        # cle reports stack vars relative to the CFA; rbp = CFA - 2*word on x86-64.
        return self.offset + 2 * arch_bytes

    def to_json(self, arch_bytes: int) -> dict:
        d = {
            "name": self.name, "sort": self.sort, "size": self.size, "signed": self.signed,
            "type": self.type_name, "line": self.line, "is_param": self.is_param,
        }
        if self.sort == "stack":
            d["cfa_offset"] = self.offset
            d["bp_offset"] = self.frame_offset(arch_bytes)
        elif self.sort == "global":
            d["addr"] = self.offset
        return d


def _resolve_type(t) -> tuple[str, int, bool]:
    name = getattr(t, "name", None) or "?"
    cur, seen = t, 0
    while cur is not None and seen < 8:
        seen += 1
        if isinstance(cur, cle.backends.elf.variable_type.PointerType):
            return name, getattr(cur, "byte_size", 8) or 8, False
        if isinstance(cur, cle.backends.elf.variable_type.BaseType):
            base = str(getattr(cur, "name", "") or "").lower()
            enc = str(getattr(cur, "encoding", "") or "").lower()
            # DW_ATE_signed / DW_ATE_signed_char == signed; otherwise fall back to the name.
            if "unsigned" in base or "unsigned" in enc or base.startswith("_bool") or base == "bool":
                signed = False
            elif "signed" in enc or base in ("char",) or "int" in base or base in ("long", "short", "long long"):
                signed = True
            else:
                signed = True
            return name, getattr(cur, "byte_size", 0) or 0, signed
        cur = getattr(cur, "type", None)
    return name, getattr(t, "byte_size", 0) or 0, False


class Binary:
    """A loaded binary plus everything static we compute about it."""

    def __init__(self, path: str, progress=None, target_funcs=None, lazy=None, base_addr=None):
        """Lazy mode (default for large binaries, e.g. a 9.5 MB iOS dyld-cache dylib):
        instead of a whole-binary CFGFast (impractical for ~17k functions), index every
        function from the symbol table and build each one's control-flow graph ON DEMAND
        when it is first selected/analysed. `target_funcs` pre-analyses specific ones;
        `lazy=False` forces the classic whole-binary CFG (used for small ELFs).

        `base_addr` loads the image at this absolute base instead of its preferred one.
        Use it to match a live-process slide so a captured snapshot's pc and code
        pointers line up with the loaded binary (concolic seeding of a real run)."""
        self.path = os.path.abspath(path)
        self.base_addr = base_addr
        self._progress = progress or (lambda msg: None)
        self._progress("loading binary")
        # Teach angr the ARM64 NEON IR ops it ships without, so SEAL can also handle
        # arm64(e) targets. Harmless for x86-64 (only adds missing ops); idempotent.
        try:
            from . import angr_arm_patch
            angr_arm_patch.apply()
        except Exception as e:  # never let the patch break loading
            log.warning("angr ARM patch not applied: %s", e)
        main_opts = {"base_addr": base_addr} if base_addr is not None else {}
        self.project = angr.Project(self.path, auto_load_libs=False, load_debug_info=True,
                                    main_opts=main_opts)
        self.arch = self.project.arch
        self.target_funcs = list(target_funcs) if target_funcs else None

        mo = self.project.loader.main_object
        nfunc_syms = sum(1 for s in mo.symbols if s.is_function)
        code_span = (mo.max_addr - mo.min_addr)
        auto_lazy = nfunc_syms > 2000 or code_span > 3_000_000
        self.lazy = auto_lazy if lazy is None else lazy
        self._cfgs: dict[int, object] = {}       # func addr -> its scoped CFGFast
        self._analyzed: set[int] = set()
        self._regions: list[tuple] = []          # accumulated CFG regions (see analyze_function)
        self._index: list[dict] = []             # all functions (lazy): {addr,name,size}
        self._index_addrs: list[int] = []
        self._name_by_addr: dict[int, str] = {}

        if self.lazy:
            self._build_index()
            self.cfg = None
            self._progress(f"indexed {len(self._index)} functions (on-demand CFG)")
            for fa in (self.target_funcs or []):
                self.analyze_function(fa)
        else:
            self._progress("recovering control flow (CFGFast)")
            self.cfg = self.project.analyses.CFGFast(normalize=True, data_references=False)
            self._progress("recovering calling conventions")
            try:
                self.project.analyses.CompleteCallingConventions(recover_variables=False)
            except Exception as e:  # best effort
                log.warning("calling convention analysis failed: %s", e)
        self._progress("reading DWARF debug info")
        self.dwarf_functions = self._collect_dwarf()
        self.addr_to_line = getattr(self.project.loader.main_object, "addr_to_line", {}) or {}
        self._source_cache: dict[str, list[str] | None] = {}
        self._progress("ready")

    # ------------------------------------------------------- lazy per-function CFG
    def _build_index(self):
        """Index every function from the symbol table (addr, name, size). Function
        extents come from the gap to the next symbol, so each function's CFG can later
        be built over exactly its own byte range."""
        mo = self.project.loader.main_object
        # cle doesn't reliably flag is_function on Mach-O, so treat any named symbol that
        # lands in an executable segment as a function start.
        exec_ranges = [(s.vaddr, s.vaddr + s.memsize) for s in mo.segments if s.is_executable]

        def in_exec(a):
            return any(lo <= a < hi for lo, hi in exec_ranges)

        seen = {}
        for s in mo.symbols:
            a = s.rebased_addr
            if not s.name or a == 0:
                continue
            if not (getattr(s, "is_function", False) or in_exec(a)):
                continue
            seen.setdefault(a, s.name)
        addrs = sorted(seen)
        for i, a in enumerate(addrs):
            nxt = addrs[i + 1] if i + 1 < len(addrs) else (mo.max_addr + 1)
            self._index.append({"addr": a, "name": seen[a], "size": max(4, min(nxt - a, 0x40000))})
        self._index_addrs = addrs
        self._name_by_addr = seen

    def _containing(self, addr: int) -> int | None:
        if not self._index_addrs:
            return None
        i = bisect.bisect_right(self._index_addrs, addr) - 1
        return self._index_addrs[i] if i >= 0 else None

    def analyze_function(self, fa: int):
        """Build (and cache) the CFG for one function, then make it the current CFG.
        Idempotent; cheap on a cache hit."""
        if fa in self._analyzed:
            self.cfg = self._cfgs.get(fa, self.cfg)
            return self.cfg
        ent = next((e for e in self._index if e["addr"] == fa), None)
        size = ent["size"] if ent else 0x8000
        self._progress(f"analysing function @ {hex(fa)}")
        # ACCUMULATE regions: a fresh CFGFast rebuilds kb.functions for only the regions
        # it is given, EVICTING every previously-analysed function (so a second analyse
        # made the first "no such function"). Re-run over the union of all analysed
        # regions so the knowledge base keeps every function we've looked at.
        region = (fa, fa + size)
        if region not in self._regions:
            self._regions.append(region)
        cfg = self.project.analyses.CFGFast(
            regions=list(self._regions), normalize=True, data_references=False)
        try:
            self.project.analyses.CompleteCallingConventions(recover_variables=False)
        except Exception as e:
            log.warning("calling convention analysis failed @ %s: %s", hex(fa), e)
        try:
            from . import angr_arm_patch
            angr_arm_patch.patch_pac(self.project, fa, fa + size)
        except Exception as e:
            log.warning("PAC hooking skipped @ %s: %s", hex(fa), e)
        self._cfgs[fa] = cfg
        self._analyzed.add(fa)
        self.cfg = cfg
        return cfg

    def _ensure(self, addr: int):
        """Lazily analyse the function containing `addr` and make it current."""
        if not self.lazy:
            return
        fa = self._containing(addr)
        if fa is not None:
            self.analyze_function(fa)

    # ------------------------------------------------------------------ meta
    @property
    def word_bytes(self) -> int:
        return self.arch.bytes

    def info(self) -> dict:
        mo = self.project.loader.main_object
        return {
            "path": self.path,
            "name": os.path.basename(self.path),
            "arch": self.arch.name,
            "bits": self.arch.bits,
            "entry": self.project.entry,
            "pie": bool(getattr(mo, "pic", False)),
            "has_dwarf": bool(self.dwarf_functions),
            "has_lines": bool(self.addr_to_line),
            "function_count": len(self._index) if self.lazy else len(self.user_functions()),
        }

    def scratch_base(self) -> int:
        """Where symbolic input buffers go: above everything the loader mapped
        (binary, libraries, angr's extern objects), so they can't overlap real data."""
        top = self.project.loader.max_addr + 1
        return (top + 0xfffff) & ~0xfffff

    # ------------------------------------------------------------- functions
    def user_functions(self):
        if self.lazy:
            # only the functions analysed so far have a Function object
            out = [self.project.kb.functions.get_by_addr(fa)
                   for fa in sorted(self._analyzed) if self.project.kb.functions.contains_addr(fa)]
            return out
        out = []
        for f in self.cfg.kb.functions.values():
            if f.is_plt or f.is_simprocedure or f.is_syscall or f.is_alignment:
                continue
            if f.binary is not self.project.loader.main_object:
                continue
            out.append(f)
        out.sort(key=lambda f: f.addr)
        return out

    @staticmethod
    def _is_named_str(name: str) -> bool:
        return bool(name) and not name.startswith(("sub_", "frame_dummy", "register_tm", "deregister_tm"))

    def _is_named(self, f) -> bool:
        # Prefer functions with a real symbol name over compiler stubs.
        return not f.name.startswith(("sub_", "_", "frame_dummy", "register_tm", "deregister_tm"))

    def function_list(self) -> list[dict]:
        if self.lazy:
            # all functions, straight from the symbol index (no CFG needed to list)
            out = []
            for e in self._index:
                out.append({
                    "addr": e["addr"], "name": e["name"], "size": e["size"],
                    "block_count": 0,            # filled in once the function is analysed
                    "has_source": False, "named": self._is_named_str(e["name"]),
                    "returning": True, "args": [],
                })
            return out
        out = []
        for f in self.user_functions():
            dw = self.dwarf_functions.get(f.addr)
            out.append({
                "addr": f.addr,
                "name": f.name,
                "size": f.size,
                "block_count": len(f.block_addrs_set),
                "has_source": bool(dw),
                "named": self._is_named(f),
                "returning": bool(f.returning),
                "args": self._arg_summary(f, dw),
            })
        return out

    def _arg_summary(self, f, dw) -> list[dict]:
        """Best-effort argument list from DWARF, else from the calling convention."""
        if dw:
            params = [v for v in dw if v.is_param]
            if params:
                return [{"name": v.name, "type": v.type_name, "size": v.size, "signed": v.signed}
                        for v in params]
        proto = f.prototype
        if proto is not None and proto.args:
            return [{"name": f"arg{i}", "type": str(a), "size": (a.size or self.arch.bits) // 8,
                     "signed": True} for i, a in enumerate(proto.args)]
        return []

    def get_function(self, addr: int):
        # Lazily analyse the function at `addr` (not just the one containing it) so a
        # cold run on a never-selected function works. Return None if it still can't be
        # found — angr's get_by_addr raises KeyError, but callers expect None.
        if self.lazy and addr not in self._analyzed and self._name_by_addr.get(addr) is not None:
            self.analyze_function(addr)
        else:
            self._ensure(addr)
        kb = self.project.kb.functions
        if kb.contains_addr(addr):
            return kb.get_by_addr(addr)
        try:
            return kb.get_by_addr(addr)
        except KeyError:
            return None

    def block_head(self, addr: int) -> int:
        """The start address of the basic block containing `addr` (or addr itself)."""
        self._ensure(addr)
        node = self.cfg.model.get_any_node(addr, anyaddr=True)
        if node is not None:
            return node.addr
        return addr

    def return_block_heads(self, func_addr: int) -> list[int]:
        f = self.get_function(func_addr)
        heads = []
        for block_addr in sorted(f.block_addrs_set):
            try:
                block = self.project.factory.block(block_addr)
                if block.vex.jumpkind == "Ijk_Ret":
                    heads.append(block_addr)
            except Exception:
                pass
        return heads

    # ----------------------------------------------------------------- dwarf
    def _collect_dwarf(self) -> dict[int, list[DwarfVar]]:
        mo = self.project.loader.main_object
        cus = getattr(mo, "compilation_units", None)
        if not cus:
            return {}
        out: dict[int, list[DwarfVar]] = {}
        for cu in cus:
            for low_pc, sp in cu.functions.items():
                vars_: list[DwarfVar] = []
                for v in sp.local_variables:
                    tname, tsize, signed = _resolve_type(v.type)
                    sort = "unknown"
                    off = 0
                    if v.sort == "stack":
                        sort, off = "stack", int(v.addr) if v.addr is not None else 0
                    elif v.sort == "global":
                        sort, off = "global", int(getattr(v, "rebased_addr", 0) or 0)
                    is_param = getattr(v, "decl_line", None) == getattr(sp, "source_line", None)
                    vars_.append(DwarfVar(
                        name=v.name or "?", sort=sort, offset=off, size=tsize or 0,
                        signed=signed, type_name=tname, line=getattr(v, "decl_line", None),
                        is_param=is_param,
                    ))
                out[int(low_pc)] = vars_
        return out

    def dwarf_vars(self, func_addr: int) -> list[DwarfVar]:
        return self.dwarf_functions.get(func_addr, [])

    # ----------------------------------------------------------------- source
    def _source_lines(self, filepath: str) -> list[str] | None:
        if filepath in self._source_cache:
            return self._source_cache[filepath]
        lines = None
        for cand in (filepath, os.path.join(os.path.dirname(self.path), os.path.basename(filepath))):
            if os.path.isfile(cand):
                try:
                    with open(cand, "r", errors="replace") as fh:
                        lines = fh.read().splitlines()
                    break
                except OSError:
                    pass
        self._source_cache[filepath] = lines
        return lines

    def line_for(self, addr: int) -> tuple[str, int] | None:
        entry = self.addr_to_line.get(addr)
        if not entry:
            return None
        fp, ln = next(iter(entry))
        return fp, ln

    def nearest_line(self, addr: int) -> tuple[str, int] | None:
        """Line of `addr`, or of the closest preceding instruction in the same function.

        The DWARF line table only marks where each statement *starts*, so e.g. the
        conditional jump ending an `if` has no entry of its own.
        """
        e = self.line_for(addr)
        if e:
            return e
        if not hasattr(self, "_line_addrs"):
            self._line_addrs = sorted(self.addr_to_line)
        i = bisect.bisect_right(self._line_addrs, addr) - 1
        if i < 0:
            return None
        prev = self._line_addrs[i]
        f = self.project.kb.functions.floor_func(addr)
        if f is None or not (f.addr <= prev <= addr):
            return None
        return self.line_for(prev)

    def source_at(self, addr: int) -> dict | None:
        """{file, line, text} for the source line an address comes from."""
        e = self.nearest_line(addr)
        if not e:
            return None
        text = self._source_lines(e[0])
        return {"file": os.path.basename(e[0]), "line": e[1],
                "text": text[e[1] - 1].strip() if text and 0 < e[1] <= len(text) else None}

    def block_source_lines(self, block_addr: int) -> list[int]:
        """Source line numbers covered by the instructions of one basic block."""
        cache = self.__dict__.setdefault("_block_lines", {})
        if block_addr not in cache:
            lines = []
            try:
                self._ensure(block_addr)
                f = self.project.kb.functions.floor_func(block_addr)
                leaders = sorted(f.block_addrs_set) if f is not None else [block_addr]
                addrs = ([ins.address for ins in self._owned_capstone(block_addr, leaders)]
                         if block_addr in leaders
                         else list(self.project.factory.block(block_addr).instruction_addrs))
                for a in addrs:
                    e = self.line_for(a)
                    if e and e[1] not in lines:
                        lines.append(e[1])
                if not lines and self.project.loader.main_object.contains_addr(block_addr):
                    e = self.nearest_line(block_addr)
                    if e:
                        lines.append(e[1])
            except Exception:
                pass
            cache[block_addr] = lines
        return cache[block_addr]

    def name_at(self, addr: int) -> str | None:
        """Name of the function / PLT stub / angr SimProcedure starting at addr.

        A real SYMBOL wins over a hook's display name: we PAC-hook real function entries
        (pacibsp), so `is_hooked` is true for ordinary functions — reporting the hook name
        ("_Nop") there would mislabel e.g. aa_lineto. Only fall back to the hook name for
        addresses that have no symbol (pure SimProcedure stubs)."""
        nm = self._name_by_addr.get(addr)
        if nm:
            return nm
        if self.project.is_hooked(addr):
            return self.project.hooked_by(addr).display_name
        if self.lazy:
            if self.project.kb.functions.contains_addr(addr):
                return self.project.kb.functions.get(addr).name
            return None
        f = self.cfg.kb.functions.get(addr)
        return f.name if f is not None else None

    # -------------------------------------------------------------- disassemble
    def _owned_capstone(self, block_addr: int, leaders: list[int]):
        """Capstone instructions of a block, truncated at the next block leader.

        angr's basic blocks can overlap: `factory.block(addr)` lifts a full
        straight-line run, so a block whose tail is shared with a later block
        (a common function epilogue, say) extends past that later block's
        leader. Cap each block at the next leader so every instruction belongs
        to exactly one block and none are emitted twice.
        """
        i = bisect.bisect_right(leaders, block_addr)
        nxt = leaders[i] if i < len(leaders) else None
        insns = self.project.factory.block(block_addr).capstone.insns
        return [ins for ins in insns if nxt is None or ins.address < nxt]

    def disassemble(self, func_addr: int) -> dict:
        f = self.get_function(func_addr)
        leaders = sorted(f.block_addrs_set)
        insns = []
        for block_addr in leaders:
            for ins in self._owned_capstone(block_addr, leaders):
                src = self.line_for(ins.address)
                insns.append({
                    "addr": ins.address,
                    "mnemonic": ins.mnemonic,
                    "op_str": ins.op_str,
                    "text": f"{ins.mnemonic} {ins.op_str}".strip(),
                    "size": ins.size,
                    "block": block_addr,
                    "arith": ins.mnemonic in ARITH_MNEMONICS,
                    "is_call": ins.mnemonic in ("call", "bl", "blx"),
                    "src_line": src[1] if src else None,
                    "src_file": os.path.basename(src[0]) if src else None,
                })
        insns.sort(key=lambda i: i["addr"])
        src_view = self._source_view(f)
        return {
            "addr": f.addr,
            "name": self.name_at(f.addr) or f.name,   # symbol name, not the PAC-hook's "_Nop"
            "instructions": insns,
            "source": src_view,
            "call_targets": self._call_targets(f),
        }

    def _instruction_addrs(self, f):
        leaders = sorted(f.block_addrs_set)
        for block_addr in leaders:
            for ins in self._owned_capstone(block_addr, leaders):
                yield ins.address

    def _source_view(self, f) -> dict | None:
        lines_hit = {}
        for addr in self._instruction_addrs(f):
            e = self.line_for(addr)
            if e:
                lines_hit.setdefault(e[0], {})[e[1]] = addr
        if not lines_hit:
            return None
        fp = max(lines_hit, key=lambda k: len(lines_hit[k]))
        text = self._source_lines(fp)
        if not text:
            return {"file": os.path.basename(fp), "available": False, "line_addrs": lines_hit[fp]}
        nums = sorted(lines_hit[fp])
        lo, hi = max(1, nums[0] - 1), min(len(text), nums[-1] + 1)
        rows = [{"n": n, "text": text[n - 1], "addr": lines_hit[fp].get(n)} for n in range(lo, hi + 1)]
        return {"file": os.path.basename(fp), "available": True, "rows": rows}

    def _call_targets(self, f) -> dict:
        out = {}
        for callsite, target in f.get_call_sites_and_targets() if hasattr(f, "get_call_sites_and_targets") else []:
            pass
        # simpler: walk transition graph edges of kind 'call'
        for src, dst, data in f.transition_graph.edges(data=True):
            if data.get("type") == "call":
                tgt = getattr(dst, "addr", None)
                name = None
                tf = self.project.kb.functions.get(tgt) if tgt else None
                if tf is not None:
                    name = tf.name
                out[getattr(src, "addr", 0)] = {"target": tgt, "name": name}
        return out

    # --------------------------------------------------------------------- cfg
    def cfg_graph(self, func_addr: int) -> dict:
        f = self.get_function(func_addr)
        leaders = sorted(f.block_addrs_set)
        nodes, edges = [], []
        for block_addr in leaders:
            owned = self._owned_capstone(block_addr, leaders)
            head = [{"addr": ins.address, "text": f"{ins.mnemonic} {ins.op_str}".strip()} for ins in owned]
            end = owned[-1].address if owned else block_addr
            size = (owned[-1].address + owned[-1].size - block_addr) if owned else 0
            nodes.append({"addr": block_addr, "size": size, "insns": head, "end": end})
        etype = {"transition": "flow", "call": "call", "fake_return": "return", "return": "return"}
        for src, dst, data in f.transition_graph.edges(data=True):
            sa, da = getattr(src, "addr", None), getattr(dst, "addr", None)
            if sa is None or da is None:
                continue
            if da not in f.block_addrs_set and data.get("type") != "call":
                continue
            edges.append({"src": sa, "dst": da, "kind": etype.get(data.get("type"), "flow"),
                          "jumpkind": data.get("jumpkind")})
        return {"addr": f.addr, "name": f.name, "nodes": nodes, "edges": edges}
