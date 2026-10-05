import json, lldb
OFF = 0x4ee80          # aa_lineto offset from CoreGraphics __TEXT base (unslid)
def __lldb_init_module(debugger, d):
    debugger.HandleCommand("command script add -f capture.setup aa_setup")
def _cg_text_base(target):
    for m in target.module_iter():
        if m.GetFileSpec().GetFilename() == "CoreGraphics":
            return m.FindSection("__TEXT").GetLoadAddress(target)
    return None
def setup(debugger, command, result, internal_dict):
    t = debugger.GetSelectedTarget()
    base = _cg_text_base(t)
    addr = base + OFF
    bp = t.BreakpointCreateByAddress(addr)
    bp.SetScriptCallbackFunction("capture.dump")
    print("AA_BP @ %#x  (CG __TEXT %#x + %#x)  locations=%d" % (addr, base, OFF, bp.GetNumLocations()))
def dump(frame, loc, extra, d):
    p = frame.GetThread().GetProcess(); t = p.GetTarget()
    base = _cg_text_base(t)
    regs = {}
    for rset in frame.GetRegisters():
        for r in rset:
            try: regs[r.GetName()] = r.GetValueAsUnsigned()
            except Exception: pass
    err = lldb.SBError()
    def rd(a, n):
        b = p.ReadMemory(a, n, err); return b.hex() if (err.Success() and b) else None
    gv = lambda n: frame.FindRegister(n).GetValueAsUnsigned()
    x0, sp = gv("x0"), gv("sp")
    snap = {"arch": "AARCH64", "func": "aa_lineto", "cg_text_base": base, "aa_offset": OFF,
            "regs": regs,
            "mem": {hex(x0): rd(x0, 8192), hex(sp): rd(sp, 8192)}}
    open("/tmp/snap.json", "w").write(json.dumps(snap))
    print("SNAPSHOT: pc=%#x x0(state)=%#x sp=%#x regs=%d mem_ok=%s" %
          (gv("pc"), x0, sp, len(regs), all(v for v in snap["mem"].values())))
    return False
