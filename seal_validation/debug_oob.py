import sys, json, logging
sys.path.insert(0, ".")
for n in ("angr","cle","pyvex","claripy"): logging.getLogger(n).setLevel("CRITICAL")
import angr, claripy
from angrgui.engine import Binary
from angrgui.runner import Run
b = Binary("seal_validation/glyph_harness")
fa = b.project.loader.find_symbol("render_glyph").rebased_addr
spec = {"func_addr": fa,
  "args":[{"name":"coord","mode":"symbolic","size":8,"signed":True}],
  "models":[{"func":"malloc","kind":"alloc","size_arg":0,"name":"cov"}],
  "checks":[], "limits":{"steps":300,"active":400,"seconds":60,"skip_calls":False}}
run = Run(b, spec)
st = run._build_state()
run._install_models(st)
print("hooked:", [hex(a) if isinstance(a,int) else a for a in getattr(run,'_hooked',[])])
print("MODEL_REGION:", hex(run.MODEL_REGION))
# watch every memory write: report address, whether it hits a tracked alloc, and OOB satisfiability
findings=[]
def on_w(state):
    wa = state.inspect.mem_write_address
    allocs = state.globals.get("angrgui_allocs", ())
    if not isinstance(wa, claripy.ast.BV) or not allocs: return
    for (base,size,end) in allocs:
        base=base if isinstance(base,claripy.ast.BV) else claripy.BVV(base,64)
        size=size if isinstance(size,claripy.ast.BV) else claripy.BVV(size,64)
        oob = claripy.UGT(wa+1, base+size)
        belongs = claripy.And(claripy.UGE(wa, base), claripy.ULT(wa, end if isinstance(end,claripy.ast.BV) else claripy.BVV(end,64)))
        try:
            sat = state.solver.satisfiable(extra_constraints=[belongs, oob])
        except Exception as e:
            sat = "err:"+str(e)[:40]
        findings.append({"ins":hex(state.scratch.ins_addr or 0),"wa_sym":wa.symbolic,"oob_sat":sat})
st.inspect.b("mem_write", when=angr.BP_BEFORE, action=on_w)
simgr = b.project.factory.simgr(st)
simgr.explore(find=lambda s: False, n=200)  # just run forward a bounded number of steps
print("deadended:", len(simgr.deadended), "active:", len(simgr.active), "errored:", len(simgr.errored))
print("mem-write observations:", json.dumps(findings[:12]))
