import json, lldb
def dump(frame, bp_loc, extra, internal_dict):
    p = frame.GetThread().GetProcess()
    regs = {}
    for rset in frame.GetRegisters():
        for r in rset:
            try: regs[r.GetName()] = r.GetValueAsUnsigned()
            except Exception: pass
    err = lldb.SBError()
    def rd(a, n):
        d = p.ReadMemory(a, n, err)
        return d.hex() if err.Success() and d else None
    gv = lambda n: frame.FindRegister(n).GetValueAsUnsigned()
    x0, sp = gv("x0"), gv("sp")
    snap = {"arch": "AARCH64", "func": "aa_merge_scanline_edge",
            "regs": regs, "mem": {hex(x0): rd(x0, 4096), hex(sp): rd(sp, 4096)}}
    open("/tmp/snap.json", "w").write(json.dumps(snap))
    print("SNAPSHOT x0=%#x x1=%#x x3=%#x regs=%d mem_ok=%s" %
          (x0, gv("x1"), gv("x3"), len(regs), all(v for v in snap["mem"].values())))
    return False     # stop at the first hit
