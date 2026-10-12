"""
End-to-end tests against the compiled sample binary. Run with:  pytest -q
They double as the verification that the overflow / assert / reach machinery
actually finds the planted bugs.
"""
import logging
import os
import subprocess
import sys

import pytest

logging.disable(logging.WARNING)
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from angrgui.engine import Binary          # noqa: E402
from angrgui.runner import Run             # noqa: E402

BIN = os.path.join(ROOT, "samples", "vuln")


def _build():
    if not os.path.exists(BIN):
        subprocess.check_call(["make", "-C", os.path.join(ROOT, "samples")])


@pytest.fixture(scope="module")
def binary():
    _build()
    return Binary(BIN, progress=lambda m: None)


def _addr(binary, name):
    return [f for f in binary.function_list() if f["name"] == name][0]["addr"]


def _line_addr(binary, func_addr, snippet):
    """First instruction of the source line containing `snippet` (layout-independent)."""
    rows = binary.disassemble(func_addr)["source"]["rows"]
    return next(r["addr"] for r in rows if snippet in r["text"] and r["addr"] is not None)


def _run(binary, spec, timeout=45):
    r = Run(binary, spec)
    r.start().join(timeout=timeout)
    return r.snapshot()


# ---------------------------------------------------------------- static
def test_functions_and_dwarf(binary):
    names = {f["name"] for f in binary.function_list()}
    assert {"alloc_msg", "frame_size", "scale", "route", "checksum", "main"} <= names
    vs = {v.name: v for v in binary.dwarf_vars(_addr(binary, "alloc_msg"))}
    assert "count" in vs and vs["count"].size == 4 and vs["count"].signed is False
    assert "a" == binary.dwarf_vars(_addr(binary, "scale"))[0].name


def test_disassembly_marks_arith(binary):
    d = binary.disassemble(_addr(binary, "alloc_msg"))
    assert any(i["mnemonic"] == "imul" and i["arith"] for i in d["instructions"])
    assert d["source"]["available"] and d["source"]["rows"]


def test_cfg_has_branches(binary):
    g = binary.cfg_graph(_addr(binary, "route"))
    assert len(g["nodes"]) > 5 and len(g["edges"]) >= len(g["nodes"])


def test_disassembly_blocks_do_not_overlap(binary):
    """angr's basic blocks can overlap (shared function epilogues); the flattened
    disassembly must still list each instruction once, owned by exactly one block."""
    import bisect
    for fn in binary.function_list():
        d = binary.disassemble(fn["addr"])
        insns = d["instructions"]
        addrs = [i["addr"] for i in insns]
        assert len(addrs) == len(set(addrs)), f"duplicate instruction in {fn['name']}"
        leaders = sorted(binary.get_function(fn["addr"]).block_addrs_set)
        prev_block = -1
        for i in insns:                      # insns are sorted by address
            owner = leaders[bisect.bisect_right(leaders, i["addr"]) - 1]
            assert i["block"] == owner, f"{hex(i['addr'])} owned by wrong block in {fn['name']}"
            assert i["block"] >= prev_block   # block ids never go backwards down the listing
            prev_block = i["block"]
        # the CFG view is likewise free of overlap-duplicated instructions
        cfg_addrs = [ins["addr"] for n in binary.cfg_graph(fn["addr"])["nodes"] for ins in n["insns"]]
        assert len(cfg_addrs) == len(set(cfg_addrs)), f"duplicate CFG instruction in {fn['name']}"


# ---------------------------------------------------------------- overflow
def test_unsigned_overflow_at_instruction(binary):
    fa = _addr(binary, "alloc_msg")
    imul = [i for i in binary.disassemble(fa)["instructions"] if i["mnemonic"] == "imul"][0]
    snap = _run(binary, {
        "func_addr": fa,
        "args": [{"name": "count", "mode": "symbolic", "size": 4, "signed": False},
                 {"name": "size", "mode": "symbolic", "size": 4, "signed": False}],
        "assumptions": ["count != 0", "size != 0"],
        "checks": [{"id": "ov", "kind": "int_overflow", "addr": imul["addr"],
                    "signed": "unsigned", "enabled": True}],
        "limits": {"steps": 60, "active": 150, "seconds": 30, "loop_bound": 8},
    })
    assert snap["status"] == "done"
    hits = [h for h in snap["hits"] if h["kind"] == "int_overflow"]
    assert hits, "expected an overflow finding"
    w = hits[0]["witness"]
    # the witness must actually overflow 32 bits
    assert (w["count"]["u"] * w["size"]["u"]) >> 32 != 0


def test_function_wide_signed_overflow(binary):
    fa = _addr(binary, "scale")
    snap = _run(binary, {
        "func_addr": fa,
        "args": [{"name": "a", "mode": "symbolic", "size": 4, "signed": True},
                 {"name": "b", "mode": "symbolic", "size": 4, "signed": True}],
        "checks": [{"id": "ov", "kind": "int_overflow", "signed": "signed", "enabled": True}],
        "limits": {"steps": 30, "seconds": 25, "loop_bound": 8},
    })
    assert snap["status"] == "done"
    assert any(h["extra"]["signedness"] == "signed" for h in snap["hits"])


def test_no_overflow_is_clean(binary):
    """checksum has no arithmetic that can overflow given its guard; expect no hits."""
    fa = _addr(binary, "checksum")
    snap = _run(binary, {
        "func_addr": fa,
        "args": [{"name": "data", "mode": "symbolic", "size": 8, "signed": False},
                 {"name": "n", "mode": "symbolic", "size": 4, "signed": False}],
        "buffers": [{"arg": "data", "size": 64}],
        "checks": [{"id": "ov", "kind": "int_overflow", "signed": "unsigned", "enabled": True}],
        "limits": {"steps": 40, "seconds": 25, "loop_bound": 6},
    })
    assert snap["status"] == "done"
    # the shift/xor checksum uses no add/sub/mul on tainted data, so nothing should fire
    assert snap["summary"]["hits"] == 0


# ---------------------------------------------------------------- assert
def test_assert_can_be_false(binary):
    fa = _addr(binary, "alloc_msg")
    snap = _run(binary, {
        "func_addr": fa,
        "args": [{"name": "count", "mode": "symbolic", "size": 4, "signed": False},
                 {"name": "size", "mode": "symbolic", "size": 4, "signed": False}],
        "assumptions": ["count != 0", "size != 0"],
        "checks": [{"id": "a", "kind": "assert", "expr": "total < 0x10000",
                    "addr": _line_addr(binary, fa, "malloc(total)"), "enabled": True}],
        "limits": {"steps": 20, "seconds": 20, "loop_bound": 6},
    })
    assert snap["status"] == "done"
    assert any(h["kind"] == "assert" for h in snap["hits"])


# ---------------------------------------------------------------- reach
def test_reach_abort(binary):
    abort = [f.addr for f in binary.cfg.kb.functions.values() if f.name == "abort"][0]
    fa = _addr(binary, "route")
    snap = _run(binary, {
        "func_addr": fa,
        "args": [{"name": "cmd", "mode": "symbolic", "size": 4, "signed": True},
                 {"name": "x", "mode": "symbolic", "size": 4, "signed": True}],
        "checks": [{"id": "r", "kind": "reach", "addr": abort, "enabled": True}],
        # reaching INTO a called function (abort) needs calls stepped, not skipped
        "limits": {"steps": 60, "active": 300, "seconds": 30, "loop_bound": 8, "skip_calls": False},
    })
    assert snap["status"] == "done"
    reach = [h for h in snap["hits"] if h["kind"] == "reach"]
    assert reach, "expected to reach abort()"
    w = reach[0]["witness"]
    assert w["cmd"]["s"] == 2 and w["x"]["s"] == 4242


# ---------------------------------------------------------------- custom
def test_custom_check(binary):
    fa = _addr(binary, "alloc_msg")
    code = (
        "def check(state, api):\n"
        "    cond = api.eval('total > 0x7fffffff')\n"
        "    if api.sat(cond):\n"
        "        return {'message': 'total over INT_MAX', 'witness': api.witness(cond)}\n"
        "    return None\n"
    )
    snap = _run(binary, {
        "func_addr": fa,
        "args": [{"name": "count", "mode": "symbolic", "size": 4, "signed": False},
                 {"name": "size", "mode": "symbolic", "size": 4, "signed": False}],
        "assumptions": ["count != 0", "size != 0"],
        "checks": [{"id": "c", "kind": "custom", "code": code, "addr": _line_addr(binary, fa, "malloc(total)"), "enabled": True}],
        "limits": {"steps": 15, "seconds": 15, "loop_bound": 5},
    })
    assert snap["status"] == "done"
    assert any(h["kind"] == "custom" for h in snap["hits"])


# ---------------------------------------------------------------- paths
def test_path_tree_branches(binary):
    fa = _addr(binary, "route")
    snap = _run(binary, {
        "func_addr": fa,
        "args": [{"name": "cmd", "mode": "symbolic", "size": 4, "signed": True},
                 {"name": "x", "mode": "symbolic", "size": 4, "signed": True}],
        "checks": [{"id": "r", "kind": "reach", "addr": _addr(binary, "route") + 4, "enabled": True}],
        "limits": {"steps": 40, "active": 200, "seconds": 25, "loop_bound": 8},
    })
    kinds = {n["kind"] for n in snap["tree"]}
    parents = {n["parent"] for n in snap["tree"] if n["parent"] is not None}
    assert len(snap["tree"]) > 3
    assert len(parents) >= 2  # the switch produced real branching
