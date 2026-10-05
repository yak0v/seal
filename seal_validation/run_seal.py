import sys, json, time
sys.path.insert(0, ".")
import logging
for n in ("angr","cle","pyvex","claripy"): logging.getLogger(n).setLevel("ERROR")
from angrgui.engine import Binary
from angrgui.runner import Run

print(">> SEAL: loading harness (Binary = angr.Project + CFGFast + DWARF)...", flush=True)
b = Binary("seal_validation/glyph_harness")
print("   info:", json.dumps(b.info()), flush=True)
sym = b.project.loader.find_symbol("render_glyph")
fa = sym.rebased_addr
print("   render_glyph @", hex(fa), flush=True)

spec = {
  "func_addr": fa,
  "args": [{"name": "coord", "mode": "symbolic", "size": 8, "signed": True}],
  "assumptions": [],
  "models": [{"func": "malloc", "kind": "alloc", "size_arg": 0, "name": "cov"}],
  "checks": [
    {"kind": "narrowing_cast", "enabled": True},
    {"kind": "oob_write",      "enabled": True},   # modeled: checks malloc'd buffers
    {"kind": "float_anomaly",  "enabled": True},
  ],
  "limits": {"steps": 300, "active": 400, "seconds": 90, "skip_calls": False},
}
print(">> SEAL: starting symbolic exploration + checks...", flush=True)
run = Run(b, spec)
run.start()
t0=time.time()
while run.status in ("pending","running") and time.time()-t0 < 150:
    time.sleep(1)
print("   status:", run.status, "| progress:", json.dumps(run.progress), flush=True)
print("\n================ SEAL FINDINGS ================", flush=True)
hits = getattr(run, "hits", [])
if not hits:
    print("   (no findings)")
for h in hits:
    try: hj = h.to_json()
    except Exception: hj = {"repr": str(h)}
    print(json.dumps(hj, default=str)[:1200], flush=True)
# path summary
snap = run.snapshot()
leaves = [n for n in snap["tree"] if not any(m["parent"]==n["id"] for m in snap["tree"])]
from collections import Counter
reasons = Counter((n.get("end") or {}).get("reason","?") for n in leaves)
print("\n>> paths:", len(snap["tree"]), "nodes,", len(leaves), "leaves, reasons:", dict(reasons), flush=True)
