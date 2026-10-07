"""
End-to-end test for the float_anomaly check against samples/float_sample. Mirrors
test_new_checks. Skips if the sample can't be built (no x86-64 cross-compiler).
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

BIN = os.path.join(ROOT, "samples", "float_sample")


@pytest.fixture(scope="module")
def binary():
    if not os.path.exists(BIN):
        try:
            subprocess.check_call(["make", "-C", os.path.join(ROOT, "samples"), "float_sample"])
        except Exception as e:
            pytest.skip(f"cannot build float_sample: {e}")
    return Binary(BIN, progress=lambda m: None)


def _addr(binary, name):
    return [f for f in binary.function_list() if f["name"] == name][0]["addr"]


def _run(binary, spec, timeout=45):
    r = Run(binary, spec)
    r.start().join(timeout=timeout)
    return r.snapshot()


@pytest.mark.parametrize("fn,size", [("divf", 4), ("muld", 8), ("subd", 8)])
def test_float_anomaly(binary, fn, size):
    """divf(a/b), muld(a*b), subd(a-b) can each produce NaN / +-Inf for some inputs."""
    snap = _run(binary, {
        "func_addr": _addr(binary, fn),
        "args": [{"name": "a", "mode": "symbolic", "size": size, "float": True},
                 {"name": "b", "mode": "symbolic", "size": size, "float": True}],
        "checks": [{"id": "f", "kind": "float_anomaly", "enabled": True}],
        "limits": {"steps": 40, "active": 60, "seconds": 30},
    })
    assert snap["status"] == "done"
    hits = [h for h in snap["hits"] if h["kind"] == "float_anomaly"]
    assert hits, f"expected a float_anomaly finding in {fn}"
