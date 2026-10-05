import sys, json, time, logging
sys.path.insert(0, ".")
for n in ("angr","cle","pyvex","claripy"): logging.getLogger(n).setLevel("CRITICAL")
from angrgui.engine import Binary
from angrgui.runner import Run
b = Binary("seal_validation/glyph_harness")
fa = b.project.loader.find_symbol("render_glyph").rebased_addr
spec = {"func_addr": fa,
  "args":[{"name":"coord","mode":"symbolic","size":8,"signed":True}],
  "models":[{"func":"malloc","kind":"alloc","size_arg":0,"name":"cov"}],
  "checks":[{"kind":"narrowing_cast","enabled":True},{"kind":"oob_write","enabled":True}],
  "limits":{"steps":200,"active":200,"seconds":60,"skip_calls":False}}
run = Run(b, spec); run.start()
t0=time.time()
while run.status in ("pending","running") and time.time()-t0<120: time.sleep(1)
print("status:", run.status, "| progress:", json.dumps(run.progress))
print("\n===== FINDINGS =====")
for h in getattr(run,"hits",[]):
    try: hj=h.to_json()
    except Exception: hj={"repr":str(h)}
    k=hj.get("kind"); msg=hj.get("message"); wit=hj.get("witness"); line=(hj.get("extra") or {}).get("src_line")
    print(f"[{k}] {msg}")
    print(f"     witness={json.dumps(wit,default=str)}  src={json.dumps(line)}")
