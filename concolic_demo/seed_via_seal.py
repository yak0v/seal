import sys, json, time, logging
sys.path.insert(0, ".")
for n in ("angr","cle","pyvex","claripy"): logging.getLogger(n).setLevel("CRITICAL")
from angrgui.engine import Binary
from angrgui.runner import Run
snap = json.load(open("/tmp/snapshot.json"))
buf, size = snap["canvas"]["buf"], snap["canvas"]["size"]
b = Binary("concolic_demo/demo")
spec = {
  "func_addr": snap["pc"],
  "initial_state": {"kind": "snapshot", "pc": snap["pc"], "regs": snap["regs"],
                    "mem": snap["mem"], "symbolic": [{"reg": "x1", "name": "coord", "size": 8}]},
  "checks": [{"kind": "oob_write", "base": hex(buf), "size": size, "enabled": True}],
  "limits": {"steps": 60, "active": 100, "seconds": 30, "skip_calls": True},
}
run = Run(b, spec); run.start()
t = time.time()
while run.status in ("pending", "running") and time.time() - t < 60: time.sleep(0.5)
print("SEAL run via snapshot seed -> status", run.status, "| findings", len(run.hits))
for h in run.hits[:3]:
    hj = h.to_json()
    print("  ", hj.get("kind"), "|", hj.get("message"), "| witness", json.dumps(hj.get("witness"), default=str)[:140])
