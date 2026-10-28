"""
Regression tests for the "trust layer" added to a run's summary and findings:
finding confidence (confirmed vs conditional), coverage, and the arch-aware
argument-register helper that call models rely on. Uses samples/checks_sample
(x86-64), mirroring test_new_checks. Skips if the sample can't be built.
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

BIN = os.path.join(ROOT, "samples", "checks_sample")


@pytest.fixture(scope="module")
def binary():
    if not os.path.exists(BIN):
        try:
            subprocess.check_call(["make", "-C", os.path.join(ROOT, "samples"), "checks_sample"])
        except Exception as e:
            pytest.skip(f"cannot build checks_sample: {e}")
    return Binary(BIN, progress=lambda m: None)


def _addr(binary, name):
    return [f for f in binary.function_list() if f["name"] == name][0]["addr"]


def _run(binary, spec, timeout=45):
    r = Run(binary, spec)
    r.start().join(timeout=timeout)
    return r.snapshot()


def _oob_read_spec(binary):
    return {
        "func_addr": _addr(binary, "oob_r"),
        "args": [{"name": "buf", "mode": "symbolic", "size": 8},
                 {"name": "i", "mode": "symbolic", "size": 4}],
        "checks": [{"id": "r", "kind": "oob_read", "base": "buf", "size": 16, "enabled": True}],
        "limits": {"steps": 40, "active": 60, "seconds": 30},
    }


def test_coverage_reported(binary):
    """Every run reports how much of the target it explored, with sane numbers."""
    snap = _run(binary, _oob_read_spec(binary))
    assert snap["status"] == "done"
    cov = snap["summary"].get("coverage")
    assert cov is not None, "summary must carry coverage"
    assert cov["blocks_total"] and cov["blocks_total"] >= 1
    assert 0 <= cov["blocks_covered"] <= cov["blocks_total"]
    assert 0 <= cov["pct"] <= 100
    assert cov["pct"] == round(100 * cov["blocks_covered"] / cov["blocks_total"])
    assert isinstance(cov.get("unreached", []), list)


def test_finding_confidence_confirmed(binary):
    """A finding driven only by a symbolic input (no skipped-call return) is CONFIRMED,
    and the summary tallies it under confidence."""
    snap = _run(binary, _oob_read_spec(binary))
    hits = [h for h in snap["hits"] if h["kind"] == "oob_read"]
    assert hits, "expected an oob_read finding"
    # the index i is a declared symbolic input, so the finding depends on no skipped call
    assert all(h["extra"].get("confidence") == "confirmed" for h in hits)
    assert all(not h["extra"].get("depends_on") for h in hits)
    conf = snap["summary"].get("confidence") or {}
    assert conf.get("confirmed", 0) >= 1
    assert conf.get("conditional", 0) == 0


def test_int_arg_regs_matches_arch(binary):
    """The shared argument-register helper (used by both arg setup and call models)
    returns this arch's ABI integer registers — x86-64 SysV here."""
    r = Run(binary, {"func_addr": _addr(binary, "div_z"), "args": [], "limits": {}})
    regs = r._int_arg_regs()
    assert regs[:4] == ["rdi", "rsi", "rdx", "rcx"]


# -- scan_sinks: pure static sink detection (arm64 + x86 mnemonics) -------------
from angrgui.server import scan_sink_instructions   # noqa: E402


def _ins(mn, op, at=0x1000, is_call=False, call_name=None):
    return {"addr": at, "mnemonic": mn, "op_str": op, "text": f"{mn} {op}".strip(),
            "is_call": is_call, "call_name": call_name}


def test_scan_sinks_synthetic():
    kinds = lambda s: {x["kind"] for x in s}
    # arm64 NEON narrowing -> ready-to-add narrowing_cast check
    s = scan_sink_instructions([_ins("xtn", "v0.2s, v0.2d", 0x10)])
    assert s and s[0]["kind"] == "narrowing_cast"
    assert s[0]["suggested_check"] == {"kind": "narrowing_cast", "addr": "0x10"}
    # arm64 division -> assert divisor != 0 (last operand)
    s = scan_sink_instructions([_ins("udiv", "w0, w1, w2", 0x20)])
    assert s[0]["kind"] == "divide_by_zero"
    assert s[0]["suggested_check"]["expr"] == "w2 != 0"
    # x86 division -> assert on the single operand
    s = scan_sink_instructions([_ins("idiv", "ecx", 0x30)])
    assert s[0]["kind"] == "divide_by_zero" and s[0]["suggested_check"]["expr"] == "ecx != 0"
    # arm64 scaled-index pointer arithmetic -> oob_index
    assert kinds(scan_sink_instructions([_ins("add", "x9, x9, w0, uxtw #3", 0x40)])) == {"oob_index"}
    # x86 [base + index*scale] memory access -> oob_index
    assert kinds(scan_sink_instructions([_ins("mov", "eax, [rdi + rsi*4]", 0x50)])) == {"oob_index"}
    # memory-unsafe call -> dangerous_call
    s = scan_sink_instructions([_ins("bl", "#0x5000", 0x60, is_call=True, call_name="_memcpy")])
    assert s[0]["kind"] == "dangerous_call"
    # a plain move is not a sink
    assert scan_sink_instructions([_ins("mov", "x0, x1", 0x70)]) == []


def test_scan_sinks_on_sample(binary):
    """div_z contains an integer division; the scanner flags it as divide_by_zero."""
    d = binary.disassemble(_addr(binary, "div_z"))
    sinks = scan_sink_instructions(d["instructions"])
    assert any(s["kind"] == "divide_by_zero" for s in sinks), \
        f"expected a divide_by_zero sink in div_z, got {[s['kind'] for s in sinks]}"


# -- conditional confidence, return_bounds, concrete_gates (samples/trust_sample) ----
TRUST_BIN = os.path.join(ROOT, "samples", "trust_sample")


@pytest.fixture(scope="module")
def trust():
    if not os.path.exists(TRUST_BIN):
        try:
            subprocess.check_call(["make", "-C", os.path.join(ROOT, "samples"), "trust_sample"])
        except Exception as e:
            pytest.skip(f"cannot build trust_sample: {e}")
    return Binary(TRUST_BIN, progress=lambda m: None)


def _via_return_spec(trust, return_bounds=None):
    # via_return(buf, a, b): buf[clip_count(a,b)] = a  -- index from a SKIPPED call
    spec = {
        "func_addr": _addr(trust, "via_return"),
        "args": [{"name": "buf", "mode": "symbolic", "size": 8},
                 {"name": "a", "mode": "symbolic", "size": 4},
                 {"name": "b", "mode": "symbolic", "size": 4}],
        "buffers": [{"arg": "buf", "size": 16}],
        "checks": [{"id": "w", "kind": "oob_write", "enabled": True}],
        "limits": {"steps": 60, "active": 80, "seconds": 30, "skip_calls": True},
    }
    if return_bounds is not None:
        spec["return_bounds"] = return_bounds
    return spec


def test_finding_confidence_conditional(trust):
    """The oob_write index comes from the skipped call clip_count, so the finding is
    CONDITIONAL and names that callee in depends_on."""
    snap = _run(trust, _via_return_spec(trust))
    hits = [h for h in snap["hits"] if h["kind"] == "oob_write"]
    assert hits, "expected an oob_write finding (index from the skipped clip_count)"
    assert hits[0]["extra"].get("confidence") == "conditional"
    assert any("clip_count" in d for d in (hits[0]["extra"].get("depends_on") or []))
    assert (snap["summary"].get("confidence") or {}).get("conditional", 0) >= 1


def test_return_bounds_resolve_conditional(trust):
    """Bounding the skipped call's return resolves the lead: max<=3 (in-bounds for a
    4-slot buffer) dismisses it; allowing >=5 keeps it. Proves the bound is a real
    constraint, not blanket suppression."""
    dismissed = _run(trust, _via_return_spec(trust, [{"call": "clip_count", "max": 3}]))
    assert not [h for h in dismissed["hits"] if h["kind"] == "oob_write"], \
        "max<=3 should make buf[n] in-bounds and dismiss the oob_write"
    kept = _run(trust, _via_return_spec(trust, [{"call": "clip_count", "values": [5]}]))
    assert [h for h in kept["hits"] if h["kind"] == "oob_write"], \
        "a return of 5 indexes out of a 4-slot buffer; the oob_write must remain"


def test_concrete_gate_reported(trust):
    """gated(p,i) guards p[i] behind `if (g_mode)`; g_mode is concrete 0 from scratch, so
    the guarded side is never explored — a concrete gate the run must surface."""
    snap = _run(trust, {
        "func_addr": _addr(trust, "gated"),
        "args": [{"name": "p", "mode": "symbolic", "size": 8},
                 {"name": "i", "mode": "symbolic", "size": 4}],
        "buffers": [{"arg": "p", "size": 64}],
        "limits": {"steps": 40, "active": 60, "seconds": 30, "skip_calls": True},
    })
    gates = snap["summary"].get("concrete_gates") or []
    assert gates, "expected a concrete_gate for the g_mode-guarded branch"
    assert all("test" in g and "never_reached" in g for g in gates)


def _by_pointee_spec(trust, auto):
    spec = {
        "func_addr": _addr(trust, "by_pointee"),
        "args": [{"name": "p", "mode": "symbolic", "size": 8}],
        "limits": {"steps": 40, "active": 60, "seconds": 30, "skip_calls": True},
    }
    if auto:
        spec["limits"]["auto_pointers"] = True
    return spec


def test_auto_pointers_reaches_pointee_gated_code(trust):
    """by_pointee guards a block behind `if (p[0] == 0x5a)`. Without a backing region p[0]
    reads 0 and the block is unreachable (a concrete gate); with limits.auto_pointers the
    pointee is symbolic and the block is reached — the point of the feature."""
    off = _run(trust, _by_pointee_spec(trust, auto=False))
    on = _run(trust, _by_pointee_spec(trust, auto=True))
    assert off["summary"]["coverage"]["pct"] < 100
    assert off["summary"].get("concrete_gates"), "the pointee branch should be a concrete gate when off"
    assert on["summary"]["coverage"]["blocks_covered"] > off["summary"]["coverage"]["blocks_covered"]
    # a run that relied on auto-backing says so, so the findings read as leads
    assert any("auto_pointers backed" in n for n in on["summary"].get("notes", []))


def _at_index_spec(trust, size_from):
    # at_index(buf, n, i): returns buf[i] under a buggy `i <= n` bound (off-by-one at i==n).
    buf = {"arg": "buf", "size": 4096}
    if size_from:
        buf["size_from"] = "n"
    return {
        "func_addr": _addr(trust, "at_index"),
        "args": [{"name": "buf", "mode": "symbolic", "size": 8},
                 {"name": "n", "mode": "symbolic", "size": 4},
                 {"name": "i", "mode": "symbolic", "size": 4}],
        "buffers": [buf],
        "assumptions": ["n < 10"],        # a SMALL length, well inside the 4096 physical buffer
        "checks": [{"id": "r", "kind": "oob_read", "enabled": True}],
        "limits": {"steps": 40, "active": 80, "seconds": 30, "skip_calls": True},
    }


def test_symbolic_size_finds_off_by_one_that_fixed_size_misses(trust):
    """Tying the buffer's logical size to the symbolic length the code trusts (size_from)
    catches a size-dependent off-by-one (buf[n] with a `i<=n` bound) even for a tiny length;
    a fixed buffer size misses it because buf[n] is well inside the physical buffer. This is
    the 'only breaks at a specific size' class that single-fixed-size exploration can't see."""
    fixed = _run(trust, _at_index_spec(trust, size_from=False))
    sized = _run(trust, _at_index_spec(trust, size_from=True))
    assert not [h for h in fixed["hits"] if h["kind"] == "oob_read"], \
        "a fixed size should NOT flag buf[n] for n<10 inside a 4096-byte buffer"
    hits = [h for h in sized["hits"] if h["kind"] == "oob_read"]
    assert hits, "size_from=n should catch the off-by-one at buf[n]"
    w = hits[0].get("witness", {})
    assert w.get("n", {}).get("u") == w.get("i", {}).get("u")   # the trigger is i == n (one past)


def test_auto_pointers_off_by_default(trust):
    """The capability must be opt-in: a default run does not auto-back, so nothing changes
    for existing scenarios/tests."""
    snap = _run(trust, _by_pointee_spec(trust, auto=False))
    assert not any("auto_pointers backed" in n for n in snap["summary"].get("notes", []))
