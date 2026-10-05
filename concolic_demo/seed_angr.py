import sys, json, logging
sys.path.insert(0, ".")
for n in ("angr","cle","pyvex","claripy"): logging.getLogger(n).setLevel("CRITICAL")
import angr, claripy
from angrgui import angr_arm_patch; angr_arm_patch.apply()

snap = json.load(open("/tmp/snapshot.json"))
buf, size = snap["canvas"]["buf"], snap["canvas"]["size"]
p = angr.Project("concolic_demo/demo", auto_load_libs=False)

st = p.factory.blank_state(addr=snap["pc"])
for r, v in snap["regs"].items():                 # real registers from the live run
    try: setattr(st.regs, r, v)
    except Exception: pass
for m in snap["mem"]:                              # real memory (Canvas + its buffer)
    st.memory.store(m["addr"], bytes.fromhex(m["hex"]))

coord = claripy.BVS("coord", 64)                   # the ONE user-controlled input -> symbolic
st.regs.x1 = coord

hits = []
def on_w(s):
    wa = s.inspect.mem_write_address
    if not isinstance(wa, claripy.ast.BV): return
    anchored = claripy.And(claripy.UGE(wa, buf), claripy.ULT(wa, buf + 0x200000))
    oob = claripy.Or(claripy.ULT(wa, buf), claripy.UGE(wa, buf + size))
    try:
        if s.solver.satisfiable(extra_constraints=[anchored, oob]): hits.append((s.copy(), wa))
    except Exception: pass
st.inspect.b("mem_write", when=angr.BP_BEFORE, action=on_w)

sm = p.factory.simgr(st)
sm.run(n=40)
print("paths explored:  active=%d deadended=%d errored=%d" % (len(sm.active), len(sm.deadended), len(sm.errored)))
print("concrete context from the snapshot:  buf=%#x  size=%d  origin=%d" % (buf, size, int.from_bytes(bytes.fromhex(snap['mem'][0]['hex'])[12:16],'little')))
if hits:
    s, wa = hits[0]
    s.add_constraints(claripy.Or(claripy.ULT(wa, buf), claripy.UGE(wa, buf + size)))
    c = s.solver.min(coord)                        # smallest coordinate that drives the write OOB
    s.add_constraints(coord == c)                  # pin it, then read where the write actually lands
    off = s.solver.eval(wa) - buf
    print("OOB write FOUND -> smallest triggering coord = %#x (%d); write lands at buf+%d (size %d)" % (c, c, off, size))
    # show it's a precise threshold, not 'every path'
    safe = st.copy(); safe.add_constraints(claripy.And(claripy.UGE(coord, 0), claripy.ULT(coord, 0x104000)))
    print("coords < 0x104000 stay in bounds (threshold = (size+origin)<<12 = %#x)" % ((size+4)<<12))
else:
    print("no OOB found")
