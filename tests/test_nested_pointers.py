"""
Nested pointer-member support: a struct arg whose members are themselves pointers
to buffers / sub-structs. Against samples/struct_sample. Skips if it can't build.
"""
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from angrgui.engine import Binary          # noqa: E402
from angrgui.runner import Run             # noqa: E402

BIN = os.path.join(ROOT, "samples", "struct_sample")


@pytest.fixture(scope="module")
def binary():
    if not os.path.exists(BIN):
        try:
            subprocess.check_call(["make", "-C", os.path.join(ROOT, "samples"), "struct_sample"])
        except Exception as e:
            pytest.skip(f"cannot build struct_sample: {e}")
    return Binary(BIN, progress=lambda m: None)


def _addr(binary, name):
    return [f for f in binary.function_list() if f["name"] == name][0]["addr"]


def _run(binary, spec, timeout=45):
    r = Run(binary, spec)
    r.start().join(timeout=timeout)
    return r.snapshot()


def test_pointer_member_has_real_backing(binary):
    """readmsg(struct msg *m, i) = m->data[i]: the `data` pointer member points at a
    real 16-byte sub-buffer, so an oob_read anchored to it (base=the member name) fires."""
    snap = _run(binary, {
        "func_addr": _addr(binary, "readmsg"),
        "args": [{"name": "m", "mode": "symbolic", "size": 8},
                 {"name": "i", "mode": "symbolic", "size": 4}],
        "buffers": [{"arg": "m", "size": 16, "layout": [
            {"offset": 0, "size": 8, "mode": "pointer", "name": "data", "target": {"size": 16}}]}],
        "checks": [{"id": "r", "kind": "oob_read", "base": "data", "size": 16, "enabled": True}],
        "limits": {"steps": 40, "active": 60, "seconds": 30},
    })
    assert snap["status"] == "done"
    assert [h for h in snap["hits"] if h["kind"] == "oob_read"], "expected oob_read through the pointer member"


def test_two_pointer_hops(binary):
    """second(struct node *n) = n->next->val: two pointer hops; the deep `val` member
    resolves symbolically and reaches the return."""
    snap = _run(binary, {
        "func_addr": _addr(binary, "second"),
        "args": [{"name": "n", "mode": "symbolic", "size": 8}],
        "buffers": [{"arg": "n", "size": 16, "layout": [
            {"offset": 0, "size": 8, "mode": "pointer", "name": "next", "target": {"size": 16, "layout": [
                {"offset": 8, "size": 4, "mode": "symbolic", "name": "val"}]}}]}],
        "checks": [{"id": "a", "kind": "assert", "expr": "s32(ret) == 0x1337", "at_return": True, "enabled": True}],
        "limits": {"steps": 40, "active": 60, "seconds": 30},
    })
    assert snap["status"] == "done"
    assert [h for h in snap["hits"] if h["kind"] == "assert"], "expected the deep member to reach the return"
