"""
Render claripy ASTs (branch conditions, return values) as short, readable
expressions over the user's input names, in the same syntax the expression
language accepts:  `cmd == 2`,  `x s> 1000`,  `u16(x) + 8 < u16(x)`,  `stdin[0] <= 4`.

angr names symbolic variables `cmd_3_32`; the run knows which BVS belongs to
which argument / buffer / stdin, so we map them back.  A few idioms VEX emits
(sign-bit tests, sign extension spelled as a Concat of repeated bits) are
recognised and folded into the form a human would write.
"""
from __future__ import annotations

import re

import claripy

CMP = {
    "__eq__": "==", "__ne__": "!=",
    "__lt__": "<", "__le__": "<=", "__gt__": ">", "__ge__": ">=",
    "ULT": "<", "ULE": "<=", "UGT": ">", "UGE": ">=",
    "SLT": "s<", "SLE": "s<=", "SGT": "s>", "SGE": "s>=",
}
FLIP = {"==": "==", "!=": "!=", "<": ">", "<=": ">=", ">": "<", ">=": "<=",
        "s<": "s>", "s<=": "s>=", "s>": "s<", "s>=": "s<="}
NEGATE = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<",
          "s<": "s>=", "s<=": "s>", "s>": "s<=", "s>=": "s<"}
ARITH = {
    "__add__": "+", "__sub__": "-", "__mul__": "*", "__floordiv__": "/", "__truediv__": "/",
    "__mod__": "%", "SDiv": "s/", "SMod": "s%", "__and__": "&", "__or__": "|", "__xor__": "^",
    "__lshift__": "<<", "LShR": ">>", "__rshift__": "s>>",
}
COMMUTATIVE = {"+", "*", "&", "|", "^"}

_ANGR_VAR = re.compile(r"^(?P<base>.+?)(?:_\d+)+$")


class Names:
    """Maps claripy variable names to display names.

    kind 'value' = a number (argument), 'bytes' = a byte string (buffer, stdin),
    where byte 0 is the most significant byte of the BVS.
    """

    def __init__(self, named: dict | None = None, byte_names=()):
        self.map: dict[str, tuple[str, str]] = {}
        for user, ast in (named or {}).items():
            if isinstance(ast, claripy.ast.Base) and ast.op == "BVS":
                kind = "bytes" if user in byte_names or user.endswith("_buf") or user == "stdin" else "value"
                self.map[ast.args[0]] = (user, kind)

    def lookup(self, var_name: str) -> tuple[str, str]:
        if var_name in self.map:
            return self.map[var_name]
        if var_name.startswith("packet_") and "_stdin" in var_name:
            return "stdin", "bytes"
        if var_name.startswith("unconstrained_ret_"):
            fn = _ANGR_VAR.match(var_name[len("unconstrained_ret_"):])
            return f"{fn.group('base') if fn else var_name}()", "value"
        m = _ANGR_VAR.match(var_name)
        return (m.group("base") if m else var_name), "value"


def _num(v: int, bits: int, signed=False) -> str:
    if signed and bits and v >> (bits - 1):
        v -= 1 << bits
    if -4096 < v < 4096:
        return str(v)
    return ("-" + hex(-v)) if v < 0 else hex(v)


def _zext_inner(e):
    """The value inside a zero-extension (ZeroExt, or Concat with a leading 0), else None."""
    if e.op == "ZeroExt" and e.args[0] > 0:
        return e.args[1]
    if e.op == "Concat" and len(e.args) == 2 and e.args[0].op == "BVV" and e.args[0].args[0] == 0:
        return e.args[1]
    return None


def _signbit_of(e):
    """If e is a 1-bit test of some value's sign bit, return that value."""
    if e.op != "Extract" or e.args[0] != e.args[1]:
        return None
    hi, _, inner = e.args
    if hi == inner.size() - 1 and hi > 0:
        return inner
    if hi == 0 and inner.op == "LShR" and inner.args[1].op == "BVV":
        shifted, amount = inner.args[0], inner.args[1].args[0]
        if _zext_inner(shifted) is not None:     # (no `or`: bool() on an AST raises)
            shifted = _zext_inner(shifted)
        if amount == shifted.size() - 1:
            return shifted
    return None


def _sext_concat(e):
    """Concat(b, b, ..., X[hi:lo]) with every b == X[hi:hi]  ->  (X[hi:lo], total bits)."""
    if e.op != "Concat" or len(e.args) < 2:
        return None
    last = e.args[-1]
    if last.op != "Extract":
        return None
    hi = last.args[0]
    for b in e.args[:-1]:
        if not (b.op == "Extract" and b.args[0] == hi and b.args[1] == hi and b.args[2] is last.args[2]):
            return None
    return last


class Printer:
    def __init__(self, names: Names, limit=160):
        self.names = names
        self.limit = limit

    def __call__(self, ast, limit=None) -> str:
        try:
            s, _ = self.p(ast)
        except Exception:  # never let pretty-printing break a run
            s = str(ast)
        lim = self.limit if limit is None else limit
        return s if len(s) <= lim else s[: lim - 1] + "…"

    # returns (text, is_atom)
    def p(self, e, signed_ctx=False):
        op = e.op
        if op == "BoolV":
            return ("true" if e.args[0] else "false"), True
        if op == "BVV":
            return _num(e.args[0], e.size(), signed_ctx), True
        if op == "BVS":
            name, _ = self.names.lookup(e.args[0])
            return name, True
        if op in CMP:
            return self.cmp(CMP[op], e.args[0], e.args[1]), False
        if op == "Not":
            inner = e.args[0]
            if inner.op in CMP:
                return self.cmp(NEGATE[CMP[inner.op]], inner.args[0], inner.args[1]), False
            return "!" + self.wrap(inner), True
        if op in ("And", "Or"):
            j = " && " if op == "And" else " || "
            return j.join(self.wrap(a) for a in e.args), False
        if op == "If":
            c, a, b = e.args
            return f"{self.wrap(c)} ? {self.wrap(a)} : {self.wrap(b)}", False
        if op in ARITH:
            sym = ARITH[op]
            args = list(e.args)
            if sym in COMMUTATIVE and len(args) == 2 and args[0].op == "BVV" and args[1].op != "BVV":
                args.reverse()
            return f" {sym} ".join(self.wrap(a, sym.startswith("s")) for a in args), False
        if op == "__neg__":
            return "-" + self.wrap(e.args[0]), True
        if op == "__invert__":
            return "~" + self.wrap(e.args[0]), True
        inner = _zext_inner(e)
        if inner is not None:
            return self.p(inner)              # value-preserving for unsigned reads
        if op == "SignExt":
            return f"s{e.size()}({self.p(e.args[1])[0]})", True
        if op == "Extract":
            return self.extract(e), True
        if op == "Concat":
            last = _sext_concat(e)
            if last is not None:
                return f"s{e.size()}({self.extract(last)})", True
            parts = list(e.args)
            if len(parts) >= 2 and parts[-1].op == "BVV" and parts[-1].args[0] == 0:
                shift = parts.pop().size()          # Concat(x, 0#k)  ==  x << k
                if len(parts) > 1 and parts[0].op == "BVV" and parts[0].args[0] == 0:
                    parts.pop(0)
                if len(parts) == 1:
                    return f"{self.wrap(parts[0])} << {shift}", False
            return "concat(" + ", ".join(self.p(a)[0] for a in e.args) + ")", True
        if op == "Reverse":
            return f"bswap({self.p(e.args[0])[0]})", True
        return f"{op}(" + ", ".join(self.p(a)[0] if isinstance(a, claripy.ast.Base) else str(a)
                                     for a in e.args) + ")", True

    def wrap(self, e, signed_ctx=False):
        s, atom = self.p(e, signed_ctx)
        return s if atom else f"({s})"

    def extract(self, e):
        hi, lo, inner = e.args
        if inner.op == "BVS":
            name, kind = self.names.lookup(inner.args[0])
            n = inner.size()
            if kind == "bytes" and (hi + 1) % 8 == 0 and lo % 8 == 0:
                first = (n - 1 - hi) // 8
                count = (hi - lo + 1) // 8
                return f"{name}[{first}]" if count == 1 else f"{name}[{first}:{first + count}]"
        if lo == 0 and hi + 1 in (8, 16, 32, 64):
            return f"u{hi + 1}({self.p(inner)[0]})"
        return f"{self.wrap(inner)}[{hi}:{lo}]"

    def cmp(self, sym, a, b):
        # sign-bit tests:  signbit(x) != 0  ->  x s< 0
        for x, c in ((a, b), (b, a)):
            v = _signbit_of(x)
            if v is not None and c.op == "BVV" and sym in ("==", "!="):
                negative = (c.args[0] == 1) == (sym == "==")
                return f"{self.wrap(v)} {'s<' if negative else 's>='} 0"
        # constant on the left reads backwards: 1 < count  ->  count > 1
        if a.op == "BVV" and b.op != "BVV":
            a, b, sym = b, a, FLIP[sym]
        signed = sym.startswith("s")
        # a zero-extended value compared with a small non-negative constant has the
        # same answer signed or unsigned; show the simpler unsigned form
        if signed and _zext_inner(a) is not None and b.op == "BVV" and not b.args[0] >> (b.size() - 1):
            sym, signed = sym[1:], False
        return f"{self.wrap(a, signed)} {sym} {self.wrap(b, signed)}"


def printer_for_state(state) -> Printer:
    named = state.globals.get("angrgui_vars", {}) if "angrgui_vars" in state.globals else {}
    return Printer(Names(named))
