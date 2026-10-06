"""
End-to-end tests for the newer built-in checks (div_by_zero, null_deref, oob_read)
against samples/checks_sample. Mirrors test_engine_and_checks.py. Skips if the sample
can't be built (no x86-64 cross-compiler).
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


def test_div_by_zero(binary):
    """div_z(a, b) = a / b — the check must find b == 0 even though angr assumes the
    divisor is non-zero (it prunes the div-by-zero path)."""
    snap = _run(binary, {
        "func_addr": _addr(binary, "div_z"),
        "args": [{"name": "a", "mode": "symbolic", "size": 4},
                 {"name": "b", "mode": "symbolic", "size": 4}],
        "checks": [{"id": "d", "kind": "div_by_zero", "enabled": True}],
        "limits": {"steps": 40, "active": 60, "seconds": 30},
    })
    assert snap["status"] == "done"
    hits = [h for h in snap["hits"] if h["kind"] == "div_by_zero"]
    assert hits, "expected a div_by_zero finding"
    assert hits[0]["witness"]["b"]["u"] == 0      # the witness zeroes the divisor


def test_null_deref(binary):
    """null_d(p) = *p + 1 — fires when the pointer argument can be NULL."""
    snap = _run(binary, {
        "func_addr": _addr(binary, "null_d"),
        "args": [{"name": "p", "mode": "symbolic", "size": 8}],
        "checks": [{"id": "n", "kind": "null_deref", "enabled": True}],
        "limits": {"steps": 40, "active": 60, "seconds": 30},
    })
    assert snap["status"] == "done"
    hits = [h for h in snap["hits"] if h["kind"] == "null_deref"]
    assert hits, "expected a null_deref finding"
    assert hits[0]["extra"].get("access") == "read"


def test_oob_read(binary):
    """oob_r(buf, i) = buf[i] — with buf declared as a 16-byte buffer, i can index out."""
    snap = _run(binary, {
        "func_addr": _addr(binary, "oob_r"),
        "args": [{"name": "buf", "mode": "symbolic", "size": 8},
                 {"name": "i", "mode": "symbolic", "size": 4}],
        "checks": [{"id": "r", "kind": "oob_read", "base": "buf", "size": 16, "enabled": True}],
        "limits": {"steps": 40, "active": 60, "seconds": 30},
    })
    assert snap["status"] == "done"
    hits = [h for h in snap["hits"] if h["kind"] == "oob_read"]
    assert hits, "expected an oob_read finding"


def test_no_false_positive_div(binary):
    """With the divisor fixed non-zero, div_by_zero must NOT fire (no false positive)."""
    snap = _run(binary, {
        "func_addr": _addr(binary, "div_z"),
        "args": [{"name": "a", "mode": "symbolic", "size": 4},
                 {"name": "b", "mode": "concrete", "value": 7, "size": 4}],
        "checks": [{"id": "d", "kind": "div_by_zero", "enabled": True}],
        "limits": {"steps": 40, "active": 60, "seconds": 30},
    })
    assert snap["status"] == "done"
    assert not [h for h in snap["hits"] if h["kind"] == "div_by_zero"]
