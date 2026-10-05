"""Unit tests for the expression mini-language (no angr needed for parsing)."""
import os
import sys

import claripy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from angrgui.exprlang import Parser, ExprError, _match  # noqa: E402


def _resolve(names):
    def r(n):
        if n not in names:
            raise ExprError("unknown name " + n)
        return names[n]
    return r


def _funcs():
    def width(bits):
        def f(x):
            x = x if hasattr(x, "size") else claripy.BVV(int(x), bits)
            return x[bits - 1:0] if x.size() > bits else x.zero_extend(bits - x.size()) if x.size() < bits else x
        return f
    return {"u8": width(8), "u16": width(16), "u32": width(32), "u64": width(64),
            "s8": width(8), "s16": width(16), "s32": width(32), "s64": width(64)}


def ev(src, names=None):
    names = names or {}
    return Parser(src, _resolve(names), _funcs()).parse()


def test_arithmetic_constants():
    assert ev("1 + 2 * 3") == 7
    assert ev("(1 + 2) * 3") == 9
    assert ev("0x10 - 1") == 15


def test_ternary():
    x = claripy.BVS("x", 64)
    ast = ev("x == 0 ? 10 : 20", {"x": x})
    s = claripy.Solver(); s.add(x == 0)
    assert s.eval(ast, 1)[0] == 10
    s2 = claripy.Solver(); s2.add(x == 5)
    assert s2.eval(ast, 1)[0] == 20
    # nested / inside parens
    ast2 = ev("(x & 1) == 0 ? 1 : 2", {"x": x})
    s3 = claripy.Solver(); s3.add(x == 4)
    assert s3.eval(ast2, 1)[0] == 1


def test_comparison_on_symbols():
    x = claripy.BVS("x", 32)
    ast = ev("x < 0x100", {"x": x})
    assert isinstance(ast, claripy.ast.Bool)
    # unsigned compare
    s = claripy.Solver()
    s.add(ast)
    assert s.satisfiable()


def test_signed_vs_unsigned():
    x = claripy.BVS("x", 32)
    us = ev("x < 0", {"x": x})       # unsigned: never true
    sg = ev("x s< 0", {"x": x})      # signed: true for negatives
    s1 = claripy.Solver(); s1.add(us)
    s2 = claripy.Solver(); s2.add(sg)
    assert not s1.satisfiable()
    assert s2.satisfiable()


def test_boolean_ops():
    x = claripy.BVS("x", 32)
    ast = ev("x != 0 && x < 10", {"x": x})
    s = claripy.Solver(); s.add(ast)
    assert s.satisfiable()
    assert s.eval(x, 1)[0] in range(1, 10)


def test_width_helpers():
    x = claripy.BVS("x", 32)
    ast = ev("u8(x) == 0xff", {"x": x})
    assert isinstance(ast, claripy.ast.Bool)


def test_errors():
    for bad in ("1 +", "(1 + 2", "1 2"):
        try:
            ev(bad)
            assert False, bad
        except ExprError:
            pass
