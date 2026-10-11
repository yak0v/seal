"""
A tiny expression language that turns strings like

    count < 0x1000
    arg1 != 0 && arg1 s< 100
    [rbp - 8]:4 == total + 1
    u32(rax) >= len(buf)

into claripy ASTs over a given angr state.  It is used for

  * assumptions on the initial state ("constraints"),
  * assert checks at an instruction or at return,
  * ad-hoc evaluation from custom Python checks.

Identifiers resolve, in this order, to
  1. names bound by the run (function arguments, buffers, stdin) - state.globals['angrgui_vars']
  2. DWARF local variables of the function - state.globals['angrgui_locals'] (loaded from the frame)
  3. CPU registers (rax, edi, ...)
  4. `ret` - the return value register, at FULL register width (rax, 64-bit on
     x86-64). A function returning a 32-bit int leaves the high bits zero, so wrap
     narrower returns to width — `s32(ret)` / `u32(ret)` — or a signed test like
     `ret s>= 0` is always true.

Comparisons are unsigned by default; prefix with `s` for signed (s<, s<=, s>, s>=) or with
`f` for FLOATING-POINT (f<, f<=, f>, f>=, f==, f!=). A float compare reinterprets each
operand's bits as a 32/64-bit IEEE float; float literals like `1.0`/`3.14` are supported.
Widths are matched automatically by zero-extending the narrower side.

ROLE
    The one place SEAL parses user/agent-written boolean and arithmetic expressions.
    Assumptions (constraints on the entry state) and `assert` checks are just strings
    in this language; both the GUI and the MCP accept them verbatim and hand them here.
    Grammar: C-like precedence — ternary `?:`, `||`, `&&`, `!`, comparisons, `| ^ &`,
    shifts, `+ -`, `* / %`, unary `- ~`, then atoms (numbers, names, `f(args)`,
    `name:width`, `[addr]:size` memory reads). Output is always a claripy AST (or a
    Python int for pure-constant sub-expressions), evaluated against one angr state.

WHY IT'S LIKE THIS
    - Hand-rolled tokenizer + recursive-descent parser (no eval, no third-party dep):
      the input comes from outside SEAL, so it must never execute arbitrary Python,
      and the grammar is tiny enough that a parser is simpler than taming a library.
    - Unsigned by default with explicit `s`-prefixed signed operators, because binary
      analysis is mostly unsigned (addresses, sizes) and silent sign choices hide bugs
      — see PITFALLS. The tokenizer deliberately orders `s<`/`s>`/... before the
      identifier rule and requires a trailing comparison char so a name like `size`
      or a bare `s` is never mistaken for a signed operator.
    - Name resolution order (vars bound by the run → DWARF locals → registers → `ret`
      → positional `arg0..`/`a1..`) mirrors how a reverse engineer thinks: prefer the
      meaningful name the run gave a value, fall back to raw machine state.

EXTENDING
    - New function (like `mem`, `u32`, `zext`): add it to the `funcs` dict built in
      `make_evaluator()`; it receives already-evaluated claripy ASTs / ints and returns
      a BV. That is the cheapest extension point and needs no grammar change.
    - New operator / syntax: add it to TOKEN_RE, then to the relevant precedence level
      in `Parser` (p_or/p_and/.../p_mul) and give it a builder method. Keep precedence
      explicit; don't reuse a token char that already means something else.
    - New resolvable name space: extend `resolve()` in `make_evaluator()`.

PITFALLS
    - Signedness is explicit and defaults to UNSIGNED. `a s< 0` and `a < 0` ask
      different questions and both parse — a wrong choice silently changes which
      inputs satisfy the constraint, so it won't error, it'll just mislead.
    - Widths auto-match by zero-extending the narrower side; if you need sign-extended
      matching, say so with `s8..s64`/`sext`, or the high bits are wrong.
    - `mem(addr,size)` / `[addr]:size` read the *current* state's memory with the
      arch endianness — results depend on when in the path the expression is evaluated.
    - Returning a bool-ish AST vs a BV matters to callers; `as_bool()` normalizes a
      value to a constraint (nonzero), used where a bare number is treated as a test.
"""
from __future__ import annotations

import re
from typing import Any, Callable

import claripy

# Order matters: the signed comparison operators start with 's', so they must be
# tried BEFORE the identifier rule, and they require a following <,>,= so a name
# like `size` or `s` is never mistaken for an operator.
TOKEN_RE = re.compile(
    r"\s*(?:(?P<fnum>\d+\.\d+)"                       # float literal (1.0, 3.14) — before int
    r"|(?P<num>0x[0-9a-fA-F]+|0b[01]+|\d+)"
    # signed (s..) and FLOAT (f..) comparison operators, before the identifier rule
    r"|(?P<op>s<=|s>=|s<|s>|f<=|f>=|f<|f>|f==|f!=|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^~!<>()\[\]:,?])"
    r"|(?P<id>[A-Za-z_][A-Za-z0-9_.]*))"
)

CMP_OPS = {"<", "<=", ">", ">=", "==", "!=", "s<", "s<=", "s>", "s>=",
           "f<", "f<=", "f>", "f>=", "f==", "f!="}
FCMP_OPS = {"f<", "f<=", "f>", "f>=", "f==", "f!="}


class ExprError(ValueError):
    pass


def tokenize(src: str):
    pos = 0
    out = []
    while pos < len(src):
        if src[pos:].strip() == "":
            break
        m = TOKEN_RE.match(src, pos)
        if not m:
            raise ExprError(f"unexpected character {src[pos]!r} at {pos}")
        pos = m.end()
        if m.group("fnum") is not None:
            out.append(("fnum", float(m.group("fnum"))))
        elif m.group("num") is not None:
            out.append(("num", int(m.group("num"), 0)))
        elif m.group("id") is not None:
            out.append(("id", m.group("id")))
        else:
            out.append(("op", m.group("op")))
    out.append(("eof", None))
    return out


_FRNE = claripy.fp.RM.RM_NearestTiesEven


def _as_double(x):
    """Coerce an operand to a 64-bit float for a float comparison: an int/float literal
    becomes that value; a BV is REINTERPRETED (its IEEE bits) as a 32- or 64-bit float
    and widened to double; an FP is widened if needed."""
    if isinstance(x, (int, float)):
        return claripy.FPV(float(x), claripy.FSORT_DOUBLE)
    if isinstance(x, claripy.ast.FP):
        return x if x.sort == claripy.FSORT_DOUBLE else claripy.fpToFP(_FRNE, x, claripy.FSORT_DOUBLE)
    if x.size() == 64:
        return x.raw_to_fp()
    if x.size() == 32:
        return claripy.fpToFP(_FRNE, x.raw_to_fp(), claripy.FSORT_DOUBLE)
    raise ExprError(f"cannot compare a {x.size()}-bit value as a float (need 32 or 64 bits)")


def _bv(x, bits=64):
    if isinstance(x, int):
        return claripy.BVV(x & ((1 << bits) - 1), bits)
    return x


def _match(a, b, signed=False):
    """Bring two operands to a common width."""
    if isinstance(a, int) and isinstance(b, int):
        return a, b
    if isinstance(a, int):
        a = _const_like(a, b.size(), signed)
    if isinstance(b, int):
        b = _const_like(b, a.size(), signed)
    if isinstance(a, claripy.ast.Bool) or isinstance(b, claripy.ast.Bool):
        return a, b
    if a.size() < b.size():
        a = a.sign_extend(b.size() - a.size()) if signed else a.zero_extend(b.size() - a.size())
    elif b.size() < a.size():
        b = b.sign_extend(a.size() - b.size()) if signed else b.zero_extend(a.size() - b.size())
    return a, b


def _const_like(v: int, bits: int, signed: bool):
    if v < 0:
        v &= (1 << bits) - 1
    return claripy.BVV(v & ((1 << bits) - 1), bits)


def _truth(x):
    if isinstance(x, claripy.ast.Bool):
        return x
    if isinstance(x, int):
        return claripy.BoolV(bool(x))
    return x != 0


_CMP = {
    "<": claripy.ULT, "<=": claripy.ULE, ">": claripy.UGT, ">=": claripy.UGE,
    "s<": claripy.SLT, "s<=": claripy.SLE, "s>": claripy.SGT, "s>=": claripy.SGE,
}
_BINOPS = {
    "|": lambda a, b: a | b, "^": lambda a, b: a ^ b, "&": lambda a, b: a & b,
    "<<": lambda a, b: a << b,
    ">>": lambda a, b: claripy.LShR(a, b) if not isinstance(a, int) else a >> b,
    "+": lambda a, b: a + b, "-": lambda a, b: a - b, "*": lambda a, b: a * b,
    "/": lambda a, b: a // b if isinstance(a, int) else a / b,
    "%": lambda a, b: a % b,
}


class ClaripyOps:
    """Semantics of the operators: build claripy ASTs (python ints for constants)."""

    def or_(self, a, b):
        return claripy.Or(_truth(a), _truth(b))

    def and_(self, a, b):
        return claripy.And(_truth(a), _truth(b))

    def not_(self, a):
        return claripy.Not(_truth(a))

    def ite(self, c, a, b):
        a, b = _match(a, b)
        if isinstance(a, int):
            a = _bv(a, b.size() if not isinstance(b, int) else 64)
        if isinstance(b, int):
            b = _bv(b, a.size())
        return claripy.If(_truth(c), a, b)

    def fconst(self, v):
        return claripy.FPV(float(v), claripy.FSORT_DOUBLE)

    def cmp(self, op, a, b):
        if op in FCMP_OPS:                           # FLOAT comparison: reinterpret bits as fp
            fa, fb = _as_double(a), _as_double(b)
            return {"f<": claripy.fpLT, "f<=": claripy.fpLEQ, "f>": claripy.fpGT,
                    "f>=": claripy.fpGEQ, "f==": claripy.fpEQ,
                    "f!=": lambda x, y: claripy.Not(claripy.fpEQ(x, y))}[op](fa, fb)
        signed = op.startswith("s")
        a, b = _match(a, b, signed)
        if isinstance(a, int):
            return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b, "==": a == b, "!=": a != b}[op.lstrip("s")]
        if op == "==":
            return a == b
        if op == "!=":
            return a != b
        return _CMP[op](a, b)

    def binop(self, op, a, b):
        a, b = _match(a, b)
        return _BINOPS[op](a, b)

    def neg(self, a):
        return -a

    def inv(self, a):
        return ~a


class Parser:
    """Recursive-descent parser; `ops` decides what the operators build
    (claripy ASTs here, Python source in codegen.py)."""

    def __init__(self, src: str, resolver: Callable[[str], Any], funcs: dict[str, Callable] | None = None,
                 ops=None):
        self.toks = tokenize(src)
        self.i = 0
        self.resolve = resolver
        self.funcs = funcs or {}
        self.ops = ops or ClaripyOps()

    # -- helpers --------------------------------------------------------
    def peek(self):
        return self.toks[self.i]

    @staticmethod
    def _desc(t):
        return "end of input" if t[0] == "eof" else repr(t[1])

    def take(self, kind=None, val=None):
        t = self.toks[self.i]
        if kind and t[0] != kind or (val is not None and t[1] != val):
            raise ExprError(f"expected {val or kind}, got {self._desc(t)}")
        self.i += 1
        return t

    def is_op(self, *vals):
        t = self.peek()
        return t[0] == "op" and t[1] in vals

    # -- grammar --------------------------------------------------------
    def parse(self):
        e = self.p_ternary()
        if self.peek()[0] != "eof":
            raise ExprError(f"unexpected {self._desc(self.peek())}")
        return e

    def p_ternary(self):
        c = self.p_or()
        if self.is_op("?"):
            self.take()
            a = self.p_ternary()
            self.take("op", ":")
            b = self.p_ternary()
            return self.ops.ite(c, a, b)
        return c

    def p_or(self):
        a = self.p_and()
        while self.is_op("||"):
            self.take()
            a = self.ops.or_(a, self.p_and())
        return a

    def p_and(self):
        a = self.p_not()
        while self.is_op("&&"):
            self.take()
            a = self.ops.and_(a, self.p_not())
        return a

    def p_not(self):
        if self.is_op("!"):
            self.take()
            return self.ops.not_(self.p_not())
        return self.p_cmp()

    def p_cmp(self):
        a = self.p_bor()
        if self.peek()[0] == "op" and self.peek()[1] in CMP_OPS:
            op = self.take()[1]
            b = self.p_bor()
            return self.ops.cmp(op, a, b)
        return a

    def _binary(self, sub, ops):
        a = sub()
        while self.peek()[0] == "op" and self.peek()[1] in ops:
            op = self.take()[1]
            a = self.ops.binop(op, a, sub())
        return a

    def p_bor(self):
        return self._binary(self.p_bxor, {"|"})

    def p_bxor(self):
        return self._binary(self.p_band, {"^"})

    def p_band(self):
        return self._binary(self.p_shift, {"&"})

    def p_shift(self):
        return self._binary(self.p_add, {"<<", ">>"})

    def p_add(self):
        return self._binary(self.p_mul, {"+", "-"})

    def p_mul(self):
        return self._binary(self.p_unary, {"*", "/", "%"})

    def p_unary(self):
        if self.is_op("-"):
            self.take()
            return self.ops.neg(self.p_unary())
        if self.is_op("~"):
            self.take()
            return self.ops.inv(self.p_unary())
        return self.p_atom()

    def p_atom(self):
        t = self.peek()
        if t[0] == "fnum":
            self.take()
            return self.ops.fconst(t[1])
        if t[0] == "num":
            self.take()
            return t[1]
        if t[0] == "id":
            self.take()
            name = t[1]
            if self.is_op("("):
                self.take()
                args = []
                if not self.is_op(")"):
                    args.append(self.p_ternary())
                    while self.is_op(","):
                        self.take()
                        args.append(self.p_ternary())
                self.take("op", ")")
                if name not in self.funcs:
                    raise ExprError(f"unknown function {name}()")
                return self.funcs[name](*args)
            return self.resolve(name)
        if self.is_op("("):
            self.take()
            e = self.p_ternary()
            self.take("op", ")")
            return e
        if self.is_op("["):
            self.take()
            addr = self.p_or()
            self.take("op", "]")
            size = 8
            if self.is_op(":"):
                self.take()
                size = self.take("num")[1]
            return self.funcs["mem"](addr, size)
        raise ExprError(f"unexpected {self._desc(t)}")


def make_evaluator(state):
    """Return eval(expr_string) -> claripy AST for the given state."""
    arch = state.arch
    variables = state.globals.get("angrgui_vars", {})
    argv = state.globals.get("angrgui_argv", [])
    locals_ = state.globals.get("angrgui_locals", {})
    try:
        bp = state.regs.bp
    except Exception:  # architectures without a frame pointer alias
        bp = None

    def mem(addr, size=8):
        addr = _bv(addr, arch.bits)
        if isinstance(size, claripy.ast.Base):
            size = state.solver.eval_one(size)
        return state.memory.load(addr, size, endness=arch.memory_endness)

    def resolve(name: str):
        if name in variables:
            return variables[name]
        if name in locals_ and bp is not None:
            off, size = locals_[name]["offset"], locals_[name]["size"]
            return state.memory.load(bp + off, size, endness=arch.memory_endness)
        if name == "ret":
            return getattr(state.regs, arch.register_names[arch.ret_offset])
        if name in arch.registers:
            return getattr(state.regs, name)
        # arg0.. (our name) and a1.. (IDA's decompiler name for parameters) both
        # resolve positionally to the function's arguments at entry.
        m = re.fullmatch(r"arg(\d+)", name)
        if m and int(m.group(1)) < len(argv):
            return argv[int(m.group(1))]
        m = re.fullmatch(r"a(\d+)", name)
        if m and 1 <= int(m.group(1)) <= len(argv):
            return argv[int(m.group(1)) - 1]
        raise ExprError(f"unknown name {name!r}")

    def width(bits):
        def f(x):
            x = _bv(x, bits)
            if x.size() > bits:
                return x[bits - 1:0]
            if x.size() < bits:
                return x.zero_extend(bits - x.size())
            return x
        return f

    def swidth(bits):
        def f(x):
            x = _bv(x, bits)
            if x.size() > bits:
                return x[bits - 1:0]
            if x.size() < bits:
                return x.sign_extend(bits - x.size())
            return x
        return f

    funcs = {
        "mem": mem,
        "u8": width(8), "u16": width(16), "u32": width(32), "u64": width(64),
        "s8": swidth(8), "s16": swidth(16), "s32": swidth(32), "s64": swidth(64),
        "zext": lambda x, n: _bv(x).zero_extend(int(n)),
        "sext": lambda x, n: _bv(x).sign_extend(int(n)),
        "bv": lambda v, n: claripy.BVV(int(v), int(n)),
    }

    def evaluate(src: str):
        e = Parser(src, resolve, funcs).parse()
        if isinstance(e, int):
            e = claripy.BVV(e, 64)
        return e

    return evaluate


def validate_expr(src: str) -> set[str]:
    """Parse ``src`` for SYNTAX without a live angr state, so assumptions and assert
    expressions can be checked the moment they're written instead of only when a run
    fails. Any identifier resolves to a dummy value (names are resolved for real only
    at run time, against the state), so this catches malformed input — bad operators,
    unbalanced parens, unknown functions — not unknown variable names. Returns the set
    of identifiers referenced; raises ExprError on a syntax error."""
    used: set[str] = set()

    def resolve(name):
        used.add(name)
        return claripy.BVS("_v", 64)        # any name is acceptable for a syntax check

    def _mem(addr, size=8):
        n = int(size) if isinstance(size, int) else 8
        return claripy.BVS("_mem", max(8, n * 8))

    funcs = {
        "mem": _mem,
        "u8": lambda x: _bv(x, 8), "u16": lambda x: _bv(x, 16),
        "u32": lambda x: _bv(x, 32), "u64": lambda x: _bv(x, 64),
        "s8": lambda x: _bv(x, 8), "s16": lambda x: _bv(x, 16),
        "s32": lambda x: _bv(x, 32), "s64": lambda x: _bv(x, 64),
        "zext": lambda x, n: _bv(x).zero_extend(int(n)),
        "sext": lambda x, n: _bv(x).sign_extend(int(n)),
        "bv": lambda v, n: claripy.BVV(int(v), int(n)),
    }
    Parser(src, resolve, funcs).parse()
    return used


def as_bool(ast):
    return _truth(ast)
