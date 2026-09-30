"""
The readable path tree (conditions, endings, example inputs) and the generated
angr scripts, checked against the sample binary.
"""
import logging
import os
import re
import subprocess
import sys

import claripy
import pytest

logging.disable(logging.WARNING)
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from angrgui.codegen import ExprCompiler, generate_script, Code   # noqa: E402
from angrgui.engine import Binary                                  # noqa: E402
from angrgui.exprlang import make_evaluator, as_bool                # noqa: E402
from angrgui.runner import Run                                     # noqa: E402

BIN = os.path.join(ROOT, "samples", "vuln")


@pytest.fixture(scope="module")
def binary():
    if not os.path.exists(BIN):
        subprocess.check_call(["make", "-C", os.path.join(ROOT, "samples")])
    return Binary(BIN, progress=lambda m: None)


def _addr(binary, name):
    return [f for f in binary.function_list() if f["name"] == name][0]["addr"]


def _sym(name, signed=True):
    return {"name": name, "mode": "symbolic", "size": 4, "signed": signed}


def _run(binary, spec, timeout=60):
    r = Run(binary, spec)
    r.start().join(timeout=timeout)
    return r.snapshot()


ROUTE = {"args": [_sym("cmd"), _sym("x")],
         "limits": {"steps": 60, "active": 300, "seconds": 30, "loop_bound": 8}}


# ------------------------------------------------------------------ path tree
def test_route_tree_reads_like_the_source(binary):
    abort = [f.addr for f in binary.cfg.kb.functions.values() if f.name == "abort"][0]
    snap = _run(binary, {"func_addr": _addr(binary, "route"), **ROUTE,
                         "checks": [{"id": "r", "kind": "reach", "addr": abort, "enabled": True}]})
    assert snap["status"] == "done"
    nodes = {n["id"]: n for n in snap["tree"]}
    conds = {n["cond"] for n in snap["tree"]}
    # branch conditions are phrased over the argument names, in exprlang syntax
    assert {"cmd == 2", "x s> 1000", "x == 0x1092", "x s< 0"} <= conds

    leaf = next(n for n in snap["tree"] if n["cond"] == "x == 0x1092")
    assert leaf["end"]["reason"] == "exit" and "abort" in leaf["end"]["text"]
    assert leaf["decided_at"]["line"] == 66 and "4242" in leaf["decided_at"]["text"]
    assert leaf["example"]["cmd"]["s"] == 2 and leaf["example"]["x"]["s"] == 4242
    # the finding is attached to the node where it happened
    hit = snap["hits"][0]
    assert hit["extra"]["node"] == leaf["id"] and leaf["hits"] == [0]

    # every finished path says how it ended; returned ones carry the return value
    leaves = [n for n in snap["tree"] if not any(m["parent"] == n["id"] for m in snap["tree"])]
    assert all(n["end"] for n in leaves)
    returned = [n for n in leaves if n["end"]["reason"] == "returned"]
    assert any(n["ret"] == "1000" for n in returned)

    # walking up from a leaf gives the whole path condition
    chain, cur = [], leaf
    while cur["parent"] is not None:
        chain.append(cur["cond"])
        cur = nodes[cur["parent"]]
    assert "cmd == 2" in chain and "x s> 1000" in chain


def test_loop_bound_and_overflow_node(binary):
    fa = _addr(binary, "alloc_msg")
    snap = _run(binary, {"func_addr": fa, "args": [_sym("count", False), _sym("size", False)],
                         "assumptions": ["count != 0", "size != 0"],
                         "checks": [{"id": "ov", "kind": "int_overflow", "signed": "unsigned", "enabled": True}],
                         "limits": {"steps": 80, "seconds": 30, "loop_bound": 4}})
    assert snap["status"] == "done"
    assert any(n["end"] and n["end"]["reason"] == "loop_bound" for n in snap["tree"])
    assert any(n["cond"] == "count > 2" for n in snap["tree"])
    # the overflow at the imul happens before any branch: on the root stretch
    ov = [h for h in snap["hits"] if h["kind"] == "int_overflow"]
    assert ov and ov[0]["extra"]["node"] == 0


def test_assert_at_return_reads_final_value(binary):
    """An `at_return` assert must read the return value AFTER the return block runs.
    scale() returns a*b+100; the counterexample to `ret != 0` must really make it 0."""
    fa = _addr(binary, "scale")
    snap = _run(binary, {"func_addr": fa,
                         "args": [_sym("a"), _sym("b")],
                         "checks": [{"id": "z", "kind": "assert", "expr": "ret != 0",
                                     "at_return": True, "enabled": True}],
                         "limits": {"steps": 20, "seconds": 20, "loop_bound": 6}})
    assert snap["status"] == "done"
    hits = [h for h in snap["hits"] if h["kind"] == "assert"]
    assert hits, "expected ret to be makeable 0"
    w = hits[0]["witness"]
    assert (w["a"]["s"] * w["b"]["s"] + 100) & 0xffffffff == 0


def test_symbolic_stdin(binary):
    """Symbolic stdin used to crash the first state copy; now the branches depend on it."""
    snap = _run(binary, {"func_addr": _addr(binary, "main"), "args": [],
                         "stdin": {"mode": "symbolic", "size": 8},
                         "checks": [{"id": "r", "kind": "reach", "addr": _addr(binary, "route"), "enabled": True}],
                         "limits": {"steps": 40, "seconds": 30, "loop_bound": 4}})
    assert snap["status"] == "done", snap["error"]
    assert any(n["cond"] == "stdin[0] == 2" for n in snap["tree"])
    assert "stdin" in snap["hits"][0]["witness"]


# ------------------------------------------------------------------ codegen: expressions
EXPRS = [
    "count != 0", "count < 0x1000", "x s< -5", "x s>= 0 && count <= 7", "!(count == 3) || x == 1",
    "count * 3 + x > 100", "(count >> 2) & 0xff == 3", "count / 3 % 7 == 1", "-x == 5", "~count != 0",
    "u8(count) == 0xff", "s16(x) s< 0", "u64(count) + 1 == 0x100000000", "zext(count, 32) == 5",
    "rdi + 1 == 5", "u32(rax) s> 3", "[0x601000]:4 == count", "1 + 2 == 3", "count",
]


@pytest.mark.parametrize("src", EXPRS)
def test_generated_expression_matches_evaluator(binary, src):
    st = binary.project.factory.blank_state()
    count, x = claripy.BVS("count", 32), claripy.BVS("x", 32)
    st.globals["angrgui_vars"] = {"count": count, "x": x}
    st.globals["angrgui_locals"] = {}
    expected = as_bool(make_evaluator(st)(src))

    comp = ExprCompiler(binary.arch, {"count": Code("count", 32), "x": Code("x", 32)}, {})
    code = comp.boolean(src)
    got = eval(code, {"claripy": claripy, "state": st, "count": count, "x": x})
    if not expected.symbolic and not got.symbolic:   # claripy won't And two constants
        assert expected.is_true() == got.is_true(), code
        return
    s = claripy.Solver()
    # equivalent: neither can be true while the other is false
    assert not s.satisfiable(extra_constraints=[claripy.And(expected, claripy.Not(got))]), code
    assert not s.satisfiable(extra_constraints=[claripy.And(got, claripy.Not(expected))]), code


# ------------------------------------------------------------------ codegen: whole scripts
def _run_script(binary, tmp_path, spec, name):
    path = tmp_path / f"{name}.py"
    path.write_text(generate_script(binary, spec))
    out = subprocess.run([sys.executable, str(path)], capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr[-2000:]
    return out.stdout


def test_script_reaches_abort(binary, tmp_path):
    abort = [f.addr for f in binary.cfg.kb.functions.values() if f.name == "abort"][0]
    out = _run_script(binary, tmp_path, {"func_addr": _addr(binary, "route"), **ROUTE,
                                         "checks": [{"id": "r", "kind": "reach", "addr": abort}]}, "route")
    assert "cmd=0x2, x=0x1092" in out and "1 finding(s)" in out


def test_script_overflow_assert_and_custom(binary, tmp_path):
    fa = _addr(binary, "alloc_msg")
    rows = binary.disassemble(fa)["source"]["rows"]
    at = next(r["addr"] for r in rows if "malloc(total)" in r["text"])
    imul = next(i["addr"] for i in binary.disassemble(fa)["instructions"] if i["mnemonic"] == "imul")
    custom = ("def check(state, api):\n"
              "    cond = api.eval('total > 0x7fffffff')\n"
              "    if api.sat(cond):\n"
              "        return {'message': 'total over INT_MAX'}\n")
    spec = {"func_addr": fa, "args": [_sym("count", False), _sym("size", False)],
            "assumptions": ["count != 0", "size != 0"],
            "checks": [{"id": "ov", "kind": "int_overflow", "addr": imul, "signed": "unsigned"},
                       {"id": "as", "kind": "assert", "expr": "total < 0x10000", "addr": at},
                       {"id": "cu", "kind": "custom", "code": custom, "addr": at}],
            "limits": {"steps": 30, "seconds": 30, "loop_bound": 4}}
    out = _run_script(binary, tmp_path, spec, "alloc")
    assert "[ov]" in out and "[as]" in out and "[cu]" in out
    # the overflow witness really overflows 32 bits
    m = re.search(r"\[ov\].*\n\s+inputs: count=(0x[0-9a-f]+), size=(0x[0-9a-f]+)", out)
    assert (int(m.group(1), 16) * int(m.group(2), 16)) >> 32

    # same findings as the GUI's runner
    snap = _run(binary, spec)
    assert {h["check_id"] for h in snap["hits"]} == {"ov", "as", "cu"}


def test_script_symbolic_stdin(binary, tmp_path):
    out = _run_script(binary, tmp_path, {
        "func_addr": _addr(binary, "main"), "args": [], "stdin": {"mode": "symbolic", "size": 8},
        "checks": [{"id": "r", "kind": "reach", "addr": _addr(binary, "scale")}],
        "limits": {"steps": 40, "seconds": 30, "loop_bound": 4}}, "main")
    # reaching scale() needs cmd == 3 in the first stdin byte
    assert re.search(r"stdin=b'\\x03", out), out
