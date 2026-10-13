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
            try:
                u = r.GetValueAsUnsigned()
                # GetValueAsUnsigned truncates / fails for 128-bit NEON regs (v0..v31) —
                # read the raw bytes instead so vector state is captured, not dropped.
                data = r.GetData()
                nbytes = data.GetByteSize() if data else 0
                if nbytes > 8:
                    e2 = lldb.SBError()
                    raw = data.ReadRawData(e2, 0, nbytes)
                    regs[r.GetName()] = int.from_bytes(bytes(raw), "little") if e2.Success() else u
                else:
                    regs[r.GetName()] = u
            except Exception:
                pass
    err = lldb.SBError()
    def rd(a, n):
        # Read page by page and keep whatever is mapped: a fixed-size read that runs off
        # the end of a region (e.g. 8 KiB up from sp overruns the top of the stack into
        # the guard page) makes ReadMemory fail the WHOLE request and drops the valid
        # bytes. Stop at the first unreadable page instead and return what we got.
        PAGE = 0x1000
        out = bytearray()
        off = 0
        while off < n:
            e = lldb.SBError()
            chunk = p.ReadMemory(a + off, min(PAGE, n - off), e)
            if not (e.Success() and chunk):
                break
            out += chunk
            off += len(chunk)
        return out.hex() if out else None
    gv = lambda n: frame.FindRegister(n).GetValueAsUnsigned()
    x0, sp = gv("x0"), gv("sp")
    snap = {"arch": "AARCH64", "func": "aa_lineto", "cg_text_base": base, "aa_offset": OFF,
            "pc": gv("pc"),                          # top-level pc (SEAL's restore prefers this)
            "regs": regs,
            "mem": {hex(x0): rd(x0, 8192), hex(sp): rd(sp, 8192)}}
    open("/tmp/snap.json", "w").write(json.dumps(snap))
    print("SNAPSHOT: pc=%#x x0(state)=%#x sp=%#x regs=%d mem_ok=%s" %
          (gv("pc"), x0, sp, len(regs), all(v for v in snap["mem"].values())))
    return False
