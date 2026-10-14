"""General concolic-snapshot capture (lldb). Function-agnostic.

Stop the process wherever you want to seed from, then run `seal_snapshot` (optionally with
an output path). It dumps:

  * every register (general + the 128-bit NEON/vector regs, read as raw bytes), and
  * the process's DATA MEMORY IMAGE — every readable region that is writable or anonymous
    (heap, stack, __DATA, __bss, mmap'd data), plus the regions of the module you're in.

WHY the whole image, not "follow x0"
------------------------------------
A snapshot is only sound if the real bytes are present wherever execution OR a symbolic
value can reach. Chasing concrete pointers out of one argument register misses (a) other
pointer arguments, (b) anything reachable only after you make a field symbolic, and (c)
globals/stack. So we record all of the process's own data instead of guessing a reachable
set. Executable/code regions and other modules' read-only file-backed regions are skipped
by default — angr loads the target's code itself, and the shared cache is gigabytes; pass
`full` to include read-only file-backed regions too.

USAGE (lldb)
    (lldb) command script import seal_validation/snapshot/capture.py
    (lldb) breakpoint set --address <addr of the function to seed from>
    (lldb) run                      # or: process continue, until you're stopped there
    (lldb) seal_snapshot            # -> /tmp/snap.json   (or: seal_snapshot /path out.json full)

Then feed /tmp/snap.json to SEAL: it computes the image slide from the module map and
rebases (see angrgui/snapshot/rebase.py).
"""
import json
import lldb

PER_REGION_CAP = 256 * 1024 * 1024       # skip a single region bigger than this (report it)
TOTAL_CAP = 2 * 1024 * 1024 * 1024        # stop once we've captured this much in total


def __lldb_init_module(debugger, d):
    debugger.HandleCommand("command script add -f capture.seal_snapshot seal_snapshot")
    # kept for backwards compat with the old aa_lineto workflow:
    debugger.HandleCommand("command script add -f capture.setup aa_setup")
    debugger.HandleCommand("command script add -f capture.aa_break aa_break")
    debugger.HandleCommand("command script add -f capture.seal_bp seal_bp")


def seal_bp(debugger, command, result, internal_dict):
    """seal_bp <hex offset from CoreGraphics __TEXT base> — set a stopping breakpoint there."""
    t = debugger.GetSelectedTarget()
    base = next((m.FindSection("__TEXT").GetLoadAddress(t) for m in t.module_iter()
                 if m.GetFileSpec().GetFilename() == "CoreGraphics"), None)
    if base is None:
        print("CoreGraphics not loaded yet"); return
    off = int(command.strip(), 16)
    bp = t.BreakpointCreateByAddress(base + off)
    print("SEAL_BP @ %#x  (CG __TEXT %#x + %#x)  locations=%d" % (base + off, base, off, bp.GetNumLocations()))


def aa_break(debugger, command, result, internal_dict):
    """Set a plain (stopping) breakpoint at aa_lineto — so a script can stop there and then
    choose how to snapshot (e.g. `seal_snapshot /tmp/snap.json core`)."""
    t = debugger.GetSelectedTarget()
    base = next((m.FindSection("__TEXT").GetLoadAddress(t) for m in t.module_iter()
                 if m.GetFileSpec().GetFilename() == "CoreGraphics"), None)
    if base is None:
        print("CoreGraphics not loaded yet"); return
    bp = t.BreakpointCreateByAddress(base + OFF)
    print("AA_BP @ %#x  locations=%d" % (base + OFF, bp.GetNumLocations()))


# ----------------------------------------------------------------- registers
def _dump_regs(frame):
    regs = {}
    for rset in frame.GetRegisters():
        for r in rset:
            try:
                data = r.GetData()
                nbytes = data.GetByteSize() if data else 0
                if nbytes > 8:                    # 128-bit NEON: read raw bytes, don't truncate
                    e = lldb.SBError()
                    raw = data.ReadRawData(e, 0, nbytes)
                    regs[r.GetName()] = int.from_bytes(bytes(raw), "little") if e.Success() else r.GetValueAsUnsigned()
                else:
                    regs[r.GetName()] = r.GetValueAsUnsigned()
            except Exception:
                pass
    return regs


# -------------------------------------------------------------------- memory
def _read_region(proc, base, size):
    """Read a region page-by-page, keeping whatever is mapped (a fixed read that runs off
    the end fails the WHOLE request in lldb)."""
    PAGE = 0x1000
    out = bytearray()
    off = 0
    while off < size:
        e = lldb.SBError()
        chunk = proc.ReadMemory(base + off, min(PAGE, size - off), e)
        if not (e.Success() and chunk):
            break
        out += chunk
        off += len(chunk)
    return bytes(out)


def _readable_regions(proc):
    """[(base, end, writable, executable, name), ...] for every readable region."""
    out = []
    regions = proc.GetMemoryRegions()
    info = lldb.SBMemoryRegionInfo()
    for i in range(regions.GetSize()):
        if regions.GetMemoryRegionAtIndex(i, info) and info.IsReadable():
            out.append((info.GetRegionBase(), info.GetRegionEnd(),
                        info.IsWritable(), info.IsExecutable(), info.GetName() or ""))
    out.sort()
    return out


PAC_MASK = (1 << 48) - 1          # arm64e: strip the pointer-authentication bits (high bits)
BFS_BUDGET = 64 * 1024 * 1024     # hard ceiling on reachable-capture total
BFS_DEPTH = 3                     # hops to follow from the arguments (bounds the global-graph blow-up)


def _capture_full(proc, regions):
    """The whole data image: every readable region that's writable or anonymous (heap,
    stack, __DATA, __bss, mmap'd data). Skips code and read-only file-backed (shared cache)."""
    mem, skipped, total = [], [], 0
    for base, end, writable, executable, name in regions:
        size = end - base
        if executable:
            skipped.append([hex(base), size, "exec"]); continue
        if name and not writable:
            skipped.append([hex(base), size, "ro-file"]); continue
        if size > PER_REGION_CAP:
            skipped.append([hex(base), size, "too-big"]); continue
        if total + size > TOTAL_CAP:
            skipped.append([hex(base), size, "total-cap"]); continue
        data = _read_region(proc, base, size)
        if data:
            mem.append({"addr": base, "hex": data.hex()}); total += len(data)
    return mem, total, skipped


def _capture_reachable(proc, regions, seeds):
    """BFS the memory reachable from `seeds` (the register values): read a window around
    each valid pointer and scan the bytes for more pointers, following them (PAC-masked),
    bounded by BFS_BUDGET. This captures every argument's structs and what they point to —
    not just x0 — without dumping the whole process."""
    def region_of(p):
        lo, hi = 0, len(regions) - 1
        while lo <= hi:
            m = (lo + hi) >> 1
            if regions[m][0] <= p < regions[m][1]:
                return regions[m]
            if p < regions[m][0]:
                hi = m - 1
            else:
                lo = m + 1
        return None
    def resolve(p):                                  # a valid data pointer, or None
        for cand in (p, p & PAC_MASK):
            r = region_of(cand)
            if r and not r[3]:                       # in a readable, non-executable region
                return cand
        return None

    mem, total = [], 0
    queue = [(resolve(p), 0) for p in seeds if resolve(p) is not None]
    seen = set()                                     # page addresses already captured
    while queue and total < BFS_BUDGET:
        p, depth = queue.pop(0)
        start = p & ~0xFFF
        if start in seen:
            continue
        seen.add(start)
        e = lldb.SBError()
        data = proc.ReadMemory(start, 0x1000, e)     # one page per pointer; BFS follows the rest
        if not (e.Success() and data):
            continue
        data = bytes(data)
        mem.append({"addr": start, "hex": data.hex()}); total += len(data)
        if depth >= BFS_DEPTH:
            continue                                 # captured the page, but don't recurse deeper
        for off in range(0, len(data) - 7, 8):       # scan the page for more pointers
            q = int.from_bytes(data[off:off + 8], "little")
            if q:
                qr = resolve(q)
                if qr is not None and (qr & ~0xFFF) not in seen:
                    queue.append((qr, depth + 1))
    return mem, total, []


def _capture_memory(proc, target, frame, mode):
    regions = _readable_regions(proc)
    if mode == "full":
        return _capture_full(proc, regions)
    # reachable (default): seed from the ARGUMENT registers (AAPCS64 x0-x7) + the frame/link
    # regs, and BFS their pointer graph (depth-bounded). Also grab the stack frame directly,
    # since the pointers don't reach spilled locals.
    gvr = lambda n: frame.FindRegister(n).GetValueAsUnsigned()
    seeds = []
    for n in ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x29", "x30"):
        try: seeds.append(gvr(n))
        except Exception: pass
    mem, total, _ = _capture_reachable(proc, regions, seeds)
    sp = gvr("sp")
    stack = _read_region(proc, sp & ~0xFFF, 0x8000)   # the current stack frame
    if stack:
        mem.append({"addr": sp & ~0xFFF, "hex": stack.hex()}); total += len(stack)
    return mem, total, []


def _modules(target):
    """Each loaded module's live __TEXT base + name, so SEAL can compute the slide."""
    out = []
    for m in target.module_iter():
        try:
            fn = m.GetFileSpec().GetFilename()
            sec = m.FindSection("__TEXT")
            base = sec.GetLoadAddress(target) if sec else lldb.LLDB_INVALID_ADDRESS
            if base != lldb.LLDB_INVALID_ADDRESS:
                out.append({"name": fn, "text": base})
        except Exception:
            pass
    return out


# --------------------------------------------------------------------- command
def seal_snapshot(debugger, command, result, internal_dict):
    # seal_snapshot [outfile] [full|core]
    args = command.split()
    mode = "core" if "core" in args else ("full" if "full" in args else "reachable")
    out_path = next((a for a in args if a not in ("full", "core")), "/tmp/snap.json")
    t = debugger.GetSelectedTarget()
    proc = t.GetProcess()
    frame = proc.GetSelectedThread().GetFrameAtIndex(0)

    regs = _dump_regs(frame)
    gv = lambda n: frame.FindRegister(n).GetValueAsUnsigned()
    pc = gv("pc")
    snap = {"arch": "AARCH64", "pc": pc, "regs": regs, "modules": _modules(t)}

    if mode == "core":
        # COMPLETE + lazy: save a process core; SEAL faults pages in from it on demand,
        # so nothing is pre-captured and every address has its real bytes (see
        # angrgui/snapshot/core.py).
        core_path = (out_path[:-5] if out_path.endswith(".json") else out_path) + ".core"
        debugger.HandleCommand("process save-core " + core_path)
        snap["core"] = core_path
        snap["capture"] = {"mode": "core", "core": core_path}
        with open(out_path, "w") as fh:
            json.dump(snap, fh)
        print("SNAPSHOT %s  pc=%#x regs=%d  core=%s" % (out_path, pc, len(regs), core_path))
        return False

    mem, total, skipped = _capture_memory(proc, t, frame, mode)
    snap["mem"] = mem
    snap["capture"] = {"mode": mode, "regions": len(mem), "bytes": total, "skipped": skipped}
    with open(out_path, "w") as fh:
        json.dump(snap, fh)
    print("SNAPSHOT %s  pc=%#x regs=%d  mem: %d regions, %.2f MB (%s)  (skipped %d)"
          % (out_path, pc, len(regs), len(mem), total / 1e6, mode, len(skipped)))
    return False


# ----------------------------------------------- legacy aa_lineto convenience
OFF = 0x4ee80          # aa_lineto offset from CoreGraphics __TEXT base (unslid)


def setup(debugger, command, result, internal_dict):
    t = debugger.GetSelectedTarget()
    base = next((m.FindSection("__TEXT").GetLoadAddress(t) for m in t.module_iter()
                 if m.GetFileSpec().GetFilename() == "CoreGraphics"), None)
    if base is None:
        print("CoreGraphics not loaded yet"); return
    bp = t.BreakpointCreateByAddress(base + OFF)
    bp.SetScriptCallbackFunction("capture._bp_snapshot")
    print("AA_BP @ %#x  (CG __TEXT %#x + %#x)  locations=%d" % (base + OFF, base, OFF, bp.GetNumLocations()))


def _bp_snapshot(frame, loc, extra, d):
    seal_snapshot(frame.GetThread().GetProcess().GetTarget().GetDebugger(), "/tmp/snap.json", None, d)
    return True        # one-shot: stop after the first capture (don't re-capture every hit)
