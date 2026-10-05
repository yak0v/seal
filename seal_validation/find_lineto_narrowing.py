"""SEAL finds CVE-2026-86950's root cause (the truncating narrow in aa_lineto) on the
REAL, live-vulnerable macOS CoreGraphics — as a standalone numerical artifact, no write
or pipeline needed.

Chain: capture a live snapshot of aa_lineto (snapshot/live_bp.py) -> rebase it to the
binary's file addresses (angrgui.snapshot.rebase) -> seed SEAL at the fcvtzs/xtn ->
symbolize the scaled coordinate -> SEAL's narrowing_cast check flags the xtn truncation.
"""
import sys, json, time, logging
sys.path.insert(0, ".")
for n in ("angr", "cle", "pyvex", "claripy"): logging.getLogger(n).setLevel("CRITICAL")
from angrgui.engine import Binary
from angrgui.runner import Run
from angrgui.snapshot.rebase import rebase

SLIDE = 0x10984000                      # aa_lineto live slide (from snapshot/live_bp.py)
XTN = 0x186a24fd0                       # xtn.2s v0, v0  — the truncating narrow
snap = rebase(json.load(open("seal_validation/snapshot/cg_lineto.json")),
              SLIDE, 0x1869d6000, 0x1feea7fff)
b = Binary("seal_validation/snapshot/macos_cg/CoreGraphics", target_funcs=[snap["pc"]])

snap = dict(snap)
snap["pc"] = XTN
snap["symbolic"] = [{"reg": "v0", "name": "coord_i64", "size": 16}]   # the scaled coord lanes
spec = {"func_addr": 0x186a24e80,
        "initial_state": {"kind": "snapshot", **snap},
        "checks": [{"kind": "narrowing_cast", "enabled": True}],
        "limits": {"steps": 6, "active": 50, "seconds": 60, "skip_calls": True}}
run = Run(b, spec); run.start()
t = time.time()
while run.status in ("pending", "running") and time.time() - t < 70: time.sleep(0.5)
print("status=%s  findings=%d" % (run.status, len(run.hits)))
for h in run.hits:
    hj = h.to_json()
    print("  [%s] %s" % (hj.get("kind"), hj.get("message")))
    w = (hj.get("witness") or {}).get("coord_i64", {})
    print("     witness lane bytes:", w.get("hex"))
