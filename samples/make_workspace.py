#!/usr/bin/env python3
"""Write the example project (vuln.angrgui.json) for a freshly built samples/vuln.

Addresses depend on the toolchain that built the binary, so they are looked up
from its symbols and DWARF line info rather than hardcoded.

    python make_workspace.py vuln
"""
import json
import logging
import os
import sys

logging.disable(logging.WARNING)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from angrgui.engine import Binary          # noqa: E402
from angrgui.workspace import SUFFIX       # noqa: E402

LIMITS = {"active": 200, "loop_bound": 10}


def main(path):
    b = Binary(path)
    funcs = {f["name"]: f["addr"] for f in b.function_list()}
    abort = next(f.addr for f in b.cfg.kb.functions.values() if f.name == "abort")

    def mnemonic_addr(func, mnemonic):
        insns = b.disassemble(funcs[func])["instructions"]
        return next(i["addr"] for i in insns if i["mnemonic"] == mnemonic)

    def u32(name, signed=False):
        return {"name": name, "mode": "symbolic", "size": 4, "signed": signed}

    def entry(func, args, checks, limits, assumptions=()):
        fa = funcs[func]
        for c in checks:
            c["func_addr"] = fa
        return str(fa), {"args": args, "buffers": [], "assumptions": list(assumptions),
                         "stdin": None, "checks": checks, "limits": {**LIMITS, **limits}}

    functions = dict([
        entry("alloc_msg", [u32("count"), u32("size")], [
            {"id": "ov1", "kind": "int_overflow", "addr": mnemonic_addr("alloc_msg", "imul"),
             "signed": "either", "enabled": True, "name": "count*size overflow"},
            {"id": "as1", "kind": "assert", "expr": "total < 0x10000", "addr": None,
             "at_return": False, "enabled": False, "name": "total < 64KB"},
        ], {"steps": 80, "seconds": 30}, assumptions=["count != 0", "size != 0"]),
        entry("scale", [u32("a", True), u32("b", True)], [
            {"id": "ov2", "kind": "int_overflow", "addr": None, "signed": "signed",
             "enabled": True, "name": "whole-function signed overflow"},
        ], {"steps": 40, "seconds": 25}),
        entry("route", [u32("cmd", True), u32("x", True)], [
            {"id": "rc1", "kind": "reach", "addr": abort, "enabled": True, "name": "reach abort()"},
        ], {"steps": 60, "active": 300, "seconds": 30}),
    ])
    out = os.path.abspath(path) + SUFFIX
    with open(out, "w") as fh:
        json.dump({"functions": functions, "meta": {"note": "example project shipped with the tool"}},
                  fh, indent=2)
    print(f"wrote {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "vuln")
