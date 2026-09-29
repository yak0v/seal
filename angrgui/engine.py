"""
Static side of the tool: load a binary with angr, list functions, disassemble,
recover DWARF variables and source lines, and describe the per-function CFG.
"""
from __future__ import annotations

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

    def __init__(self, path: str, progress=None):
        self.path = os.path.abspath(path)
        self._progress = progress or (lambda msg: None)
        self._progress("loading binary")
        self.project = angr.Project(self.path, auto_load_libs=False, load_debug_info=True)
        self.arch = self.project.arch
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
            "function_count": len(self.user_functions()),
        }

    # ------------------------------------------------------------- functions
    def user_functions(self):
        out = []
        for f in self.cfg.kb.functions.values():
            if f.is_plt or f.is_simprocedure or f.is_syscall or f.is_alignment:
                continue
            if f.binary is not self.project.loader.main_object:
                continue
            out.append(f)
        out.sort(key=lambda f: f.addr)
        return out

    def _is_named(self, f) -> bool:
        # Prefer functions with a real symbol name over compiler stubs.
        return not f.name.startswith(("sub_", "_", "frame_dummy", "register_tm", "deregister_tm"))

    def function_list(self) -> list[dict]:
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
        return self.cfg.kb.functions.get_by_addr(addr)

    def block_head(self, addr: int) -> int:
        """The start address of the basic block containing `addr` (or addr itself)."""
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

    # -------------------------------------------------------------- disassemble
    def disassemble(self, func_addr: int) -> dict:
        f = self.get_function(func_addr)
        insns = []
        for block_addr in sorted(f.block_addrs_set):
            block = self.project.factory.block(block_addr)
            for ins in block.capstone.insns:
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
            "name": f.name,
            "instructions": insns,
            "source": src_view,
            "call_targets": self._call_targets(f),
        }

    def _instruction_addrs(self, f):
        for block_addr in sorted(f.block_addrs_set):
            block = self.project.factory.block(block_addr)
            yield from block.instruction_addrs

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
                tf = self.cfg.kb.functions.get(tgt) if tgt else None
                if tf is not None:
                    name = tf.name
                out[getattr(src, "addr", 0)] = {"target": tgt, "name": name}
        return out

    # --------------------------------------------------------------------- cfg
    def cfg_graph(self, func_addr: int) -> dict:
        f = self.get_function(func_addr)
        nodes, edges = [], []
        for block_addr in sorted(f.block_addrs_set):
            block = self.project.factory.block(block_addr)
            head = []
            for ins in block.capstone.insns:
                head.append({"addr": ins.address, "text": f"{ins.mnemonic} {ins.op_str}".strip()})
            nodes.append({"addr": block_addr, "size": block.size, "insns": head,
                          "end": block.instruction_addrs[-1] if block.instruction_addrs else block_addr})
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
