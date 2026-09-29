"""
The check framework.

A *check* watches a symbolic run for a condition and records "hits" with a
concrete witness (a set of input values that make the condition true).  Checks
are installed as angr `inspect` breakpoints so they observe every state the
explorer produces, without changing the search.

Built-in kinds
--------------
int_overflow : an add / sub / mul can wrap (unsigned) or step outside the
               signed range, at one instruction or across a whole function.
assert       : a boolean expression can be FALSE at a program point
               (i.e. an invariant that symbolic execution can violate).
reach        : some path reaches an address (a "can we get here?" question).
avoid        : record + optionally prune paths that reach an address.
custom       : a user Python snippet `def check(state, api): -> dict | None`.

Each hit is a dict:
    {check_id, kind, addr, message, witness: {name: value}, extra: {...}}
"""
from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

import angr
import claripy

from .exprlang import ExprError, make_evaluator, as_bool

log = logging.getLogger("angrgui.checks")

# claripy AST ops we treat as (potentially) overflowing N-bit arithmetic.
AST_OVERFLOW_OPS = {"__add__": "+", "__sub__": "-", "__mul__": "*"}

# capstone mnemonics that correspond to real integer arithmetic (used to filter out
# the address arithmetic VEX generates inside loads/stores).
ARITH_MNEMONICS = {"add", "adc", "sub", "sbb", "imul", "mul", "inc", "dec", "neg", "lea"}


def _overflow_condition(op_char: str, a, b, signed: bool):
    """Boolean AST, true when the N-bit op a<op>b overflows for the given signedness."""
    n = a.size()
    ext = (lambda x: x.sign_extend(n)) if signed else (lambda x: x.zero_extend(n))
    aw, bw = ext(a), ext(b)
    if op_char == "+":
        wres, narrow = aw + bw, a + b
    elif op_char == "-":
        wres, narrow = aw - bw, a - b
    elif op_char == "*":
        wres, narrow = aw * bw, a * b
    else:
        raise ValueError(op_char)
    return wres != ext(narrow)


# --------------------------------------------------------------------------- Check base
@dataclass
class Hit:
    check_id: str
    kind: str
    addr: int
    message: str
    witness: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)

    def to_json(self):
        return {
            "check_id": self.check_id, "kind": self.kind, "addr": self.addr,
            "message": self.message, "witness": self.witness, "extra": self.extra,
        }


class BaseCheck:
    kind = "base"

    def __init__(self, spec: dict, ctx: "CheckContext"):
        self.spec = spec
        self.id = spec.get("id", "check")
        self.name = spec.get("name", self.kind)
        self.enabled = spec.get("enabled", True)
        self.ctx = ctx
        self.hits: list[Hit] = []
        self._seen: set = set()

    def install(self, state):
        """Install any angr inspect breakpoints this check needs. Default: none.

        Expression-level checks (int_overflow) override this. State-point checks
        (assert / reach / avoid / custom) instead implement note_state(), which the
        runner calls for every active successor at a block boundary, where register
        and memory reads are fully committed and therefore reliable.
        """
        return

    def note_state(self, state):
        """Called by the runner for each active state at a block boundary."""
        return

    # -- helpers shared by subclasses ----------------------------------
    def _witness(self, state) -> dict:
        """Concrete values for every named input, if the path is satisfiable."""
        out = {}
        names = state.globals.get("angrgui_vars", {})
        if not state.solver.satisfiable():
            return out
        for nm, ast in names.items():
            if isinstance(ast, claripy.ast.Base) and ast.symbolic:
                try:
                    v = state.solver.eval(ast)
                    out[nm] = _fmt(v, ast.size())
                except Exception:
                    pass
        # stdin, if any
        so = state.globals.get("angrgui_stdin")
        if so is not None:
            try:
                data = state.solver.eval(so, cast_to=bytes)
                out["stdin"] = data.hex()
            except Exception:
                pass
        return out

    def _witness_with(self, state, extra_constraints) -> dict:
        """Witness under additional constraints (a fresh copy, so the run is untouched)."""
        tmp = state.copy()
        for c in extra_constraints:
            tmp.add_constraints(c)
        return self._witness(tmp)

    def _record(self, state, addr, message, witness=None, extra=None, dedup_key=None):
        key = dedup_key if dedup_key is not None else (addr, message)
        if key in self._seen:
            return
        self._seen.add(key)
        self.hits.append(Hit(self.id, self.kind, addr, message,
                             witness or {}, extra or {}))
        self.ctx.on_hit(self.hits[-1])


def _fmt(v: int, bits: int) -> dict:
    signed = v if v < (1 << (bits - 1)) else v - (1 << bits)
    return {"u": v, "s": signed, "hex": hex(v), "bits": bits}


# --------------------------------------------------------------------------- int_overflow
class IntOverflowCheck(BaseCheck):
    kind = "int_overflow"

    def __init__(self, spec, ctx):
        super().__init__(spec, ctx)
        self.addr = spec.get("addr")            # None => whole function
        self.signed = spec.get("signed", "either")   # 'signed'|'unsigned'|'either'
        self.func_addr = spec.get("func_addr")

    def _modes(self):
        if self.signed == "signed":
            return [("signed", True)]
        if self.signed == "unsigned":
            return [("unsigned", False)]
        return [("unsigned", False), ("signed", True)]

    def install(self, state):
        # We watch VEX expression *results*: for an N-bit add/sub/mul the claripy AST
        # carries its operands as .args, which is reliable (unlike mid-block registers).
        state.inspect.b("expr", when=angr.BP_AFTER, action=self._on_expr)

    def _mnemonic_at(self, state, ins_addr):
        try:
            block = state.project.factory.block(ins_addr, num_inst=1)
            insn = block.capstone.insns[0]
            return insn.mnemonic, f"{insn.mnemonic} {insn.op_str}".strip()
        except Exception:
            return None, None

    def _on_expr(self, state):
        r = state.inspect.expr_result
        if r is None or not isinstance(r, claripy.ast.BV):
            return
        op_char = AST_OVERFLOW_OPS.get(r.op)
        if op_char is None:
            return
        args = r.args
        if len(args) != 2:
            return
        a, b = args
        if not (isinstance(a, claripy.ast.BV) and isinstance(b, claripy.ast.BV)):
            return
        n = r.size()
        if a.size() != n or b.size() != n:
            return                      # widening op (e.g. 32x32->64) can't overflow
        if not (a.symbolic or b.symbolic):
            return                      # constant fold, nothing to solve

        ins_addr = state.scratch.ins_addr
        if ins_addr is None:
            return
        if self.addr is not None:
            if ins_addr != self.addr:
                return
        else:
            if not self.ctx.in_target_function(ins_addr):
                return
            mn, _ = self._mnemonic_at(state, ins_addr)
            if mn not in ARITH_MNEMONICS:
                return                  # skip address arithmetic inside other insns

        mn, text = self._mnemonic_at(state, ins_addr)
        for label, signed in self._modes():
            try:
                cond = _overflow_condition(op_char, a, b, signed)
                if not state.solver.satisfiable(extra_constraints=[cond]):
                    continue
            except Exception:
                continue
            witness = self._witness_with(state, [cond])
            opvals = self._concrete_ops(state, (a, b), cond)
            shown = op_char.join(v["hex"] for v in opvals) if opvals else "..."
            msg = f"{label} overflow possible at {text or hex(ins_addr)}  ({shown})"
            self._record(state, ins_addr, msg, witness,
                         extra={"mnemonic": mn, "op": op_char, "signedness": label,
                                "operands": opvals, "src_line": self.ctx.line_for(ins_addr),
                                "result_bits": n, "path": self.ctx.path_of(state)},
                         dedup_key=(ins_addr, label, op_char))

    def _concrete_ops(self, state, operands, cond):
        tmp = state.copy()
        tmp.add_constraints(cond)
        out = []
        if not tmp.solver.satisfiable():
            return out
        for o in operands:
            try:
                out.append(_fmt(tmp.solver.eval(o), o.size()))
            except Exception:
                out.append({"hex": "?"})
        return out


# --------------------------------------------------------------------------- assert
class AssertCheck(BaseCheck):
    kind = "assert"

    def __init__(self, spec, ctx):
        super().__init__(spec, ctx)
        self.at_return = spec.get("at_return", False)
        self.expr = spec["expr"]
        # Where to evaluate: a set of block-head addresses, or None => every block head.
        if self.at_return:
            self.points = set(ctx.return_addrs)
        elif spec.get("addr") is not None:
            self.points = {ctx.block_head(int(spec["addr"]))}
        else:
            self.points = None      # every block head in the target function

    def note_state(self, state):
        addr = state.addr
        if self.points is None:
            if not self.ctx.in_target_function(addr):
                return
        elif addr not in self.points:
            return
        try:
            ast = as_bool(make_evaluator(state)(self.expr))
        except ExprError as e:
            self._record(state, addr, f"assert expression error: {e}",
                         dedup_key=("err", str(e)))
            return
        except Exception:
            return
        neg = claripy.Not(ast) if isinstance(ast, claripy.ast.Bool) else (ast == 0)
        try:
            if not state.solver.satisfiable(extra_constraints=[neg]):
                return
        except Exception:
            return
        witness = self._witness_with(state, [neg])
        self._record(state, addr, f"assert can be false: {self.expr}", witness,
                     extra={"expr": self.expr, "src_line": self.ctx.line_for(addr),
                            "path": self.ctx.path_of(state)},
                     dedup_key=(addr, self.expr))


# --------------------------------------------------------------------------- reach / avoid
class ReachCheck(BaseCheck):
    kind = "reach"
    verb = "reached"

    def __init__(self, spec, ctx):
        super().__init__(spec, ctx)
        self.addr = int(spec["addr"])
        self.prune = spec.get("prune", False)

    def note_state(self, state):
        if state.addr != self.addr:
            return
        witness = self._witness(state)
        self._record(state, self.addr, f"{self.verb} {self.addr:#x}", witness,
                     extra={"src_line": self.ctx.line_for(self.addr),
                            "path": self.ctx.path_of(state)}, dedup_key=self.addr)


class AvoidCheck(ReachCheck):
    kind = "avoid"
    verb = "hit avoided address"


# --------------------------------------------------------------------------- custom
CUSTOM_TEMPLATE = '''\
# Custom check. Runs at every instruction (or, set WHEN below).
# Return a dict {"message": str, "addr": int (optional)} to record a hit, else None.
# `state` is the live angr SimState. `api` gives helpers:
#   api.eval("expr")        -> claripy AST over this state (same mini-language as asserts)
#   api.sat(bool_ast)       -> is it satisfiable on this path?
#   api.witness(bool_ast)   -> {name: value} making bool_ast true, or {}
#   api.reg("rax"), api.mem(addr, size)
def check(state, api):
    return None
'''


class CustomCheck(BaseCheck):
    kind = "custom"

    def __init__(self, spec, ctx):
        super().__init__(spec, ctx)
        self.code = spec.get("code", "")
        self.points = {ctx.block_head(int(spec["addr"]))} if spec.get("addr") is not None else None
        self._fn = None
        self._err = None
        self._loaded = False
        try:
            ns: dict = {}
            exec(compile(self.code, f"<custom:{self.id}>", "exec"), ns)
            self._fn = ns.get("check")
            if not callable(self._fn):
                self._err = "no callable check(state, api) defined"
        except Exception:
            self._err = traceback.format_exc(limit=3)

    def note_state(self, state):
        addr = state.addr
        if self._err:
            if not self._loaded:
                self._loaded = True
                self._record(state, addr, f"custom check failed to load: {self._err}",
                             dedup_key="loaderr")
            return
        if self.points is None:
            if not self.ctx.in_target_function(addr):
                return
        elif addr not in self.points:
            return
        api = _CustomAPI(state, self)
        try:
            res = self._fn(state, api)
        except Exception:
            self._record(state, addr, f"custom check raised: {traceback.format_exc(limit=2)}",
                         dedup_key=("raise", addr))
            return
        if res:
            haddr = res.get("addr", addr)
            self._record(state, haddr, res.get("message", "custom hit"),
                         res.get("witness", api.last_witness),
                         extra={"src_line": self.ctx.line_for(haddr),
                                "path": self.ctx.path_of(state), **res.get("extra", {})},
                         dedup_key=(haddr, res.get("message")))


class _CustomAPI:
    def __init__(self, state, check):
        self.state = state
        self._check = check
        self.last_witness = {}

    def eval(self, expr: str):
        return make_evaluator(self.state)(expr)

    def sat(self, cond) -> bool:
        return self.state.solver.satisfiable(extra_constraints=[cond])

    def witness(self, cond=None):
        cs = [cond] if cond is not None else []
        self.last_witness = self._check._witness_with(self.state, cs)
        return self.last_witness

    def reg(self, name):
        return getattr(self.state.regs, name)

    def mem(self, addr, size=8):
        return self.state.memory.load(addr, size, endness=self.state.arch.memory_endness)


CHECK_TYPES = {
    "int_overflow": IntOverflowCheck,
    "assert": AssertCheck,
    "reach": ReachCheck,
    "avoid": AvoidCheck,
    "custom": CustomCheck,
}


def build_check(spec: dict, ctx: "CheckContext") -> BaseCheck:
    cls = CHECK_TYPES.get(spec["kind"])
    if cls is None:
        raise ValueError(f"unknown check kind {spec['kind']!r}")
    return cls(spec, ctx)


@dataclass
class CheckContext:
    """Shared services the checks need from the runner."""
    target_func_lo: int
    target_func_hi: int
    return_addrs: list
    line_for: Callable[[int], Any]
    path_of: Callable
    on_hit: Callable[[Hit], None]
    block_head: Callable[[int], int]

    def in_target_function(self, addr: int) -> bool:
        return self.target_func_lo <= addr < self.target_func_hi
