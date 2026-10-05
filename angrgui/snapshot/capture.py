"""
SEAL concolic snapshot capture (lldb).

Capture the *concrete* machine state at a point in a live process — all general
registers plus the memory they (transitively) point at — and write it as a SEAL
``initial_state`` snapshot::

    {"pc": <int>,
     "regs": {"x0": <int>, ...},
     "mem":  [{"addr": <int>, "hex": "..."}, ...],
     "symbolic": [{"reg"|"addr", "name", "size"}, ...]}   # attacker-controlled fields

SEAL then seeds exactly this state and makes only the ``symbolic`` fields unknown,
so exploration follows the real path instead of treating every input as symbolic
(see ``runner._build_state_from_snapshot``). This is the general version of the
one-off demo script: it is not tied to any struct layout — it discovers memory by
following pointers out of the registers.

Usage (inside lldb, host arch arm64 or x86_64)::

    (lldb) command script import angrgui/snapshot/capture.py
    (lldb) b render                 # or:  b aa_merge_scanline_edge
    (lldb) run <args>
    (lldb) seal_snapshot --out /tmp/snapshot.json --sym x1:coord

Flags:
    --out PATH        where to write the snapshot JSON (default /tmp/snapshot.json)
    --sym SPEC        attacker-controlled fields, comma list:  x1:coord, 0x16fd..:len
    --stack N         bytes of stack to capture from sp (default 1024)
    --window N        bytes to capture at each discovered pointer (default 256)
    --depth N         pointer-following levels (default 2; 0 = registers' targets only)
    --region A:S ...  extra explicit regions to capture (hex addr : size), repeatable
    --max-regions N   cap on number of memory regions (default 128)
    --max-bytes N     cap on total captured bytes (default 1 MiB)

The capture is read-only; it never modifies the target. ARM64 pointer-auth (PAC)
bits are masked off before a pointer is dereferenced, so arm64e targets work.

ROLE
----
The *producer* of concolic seeds. It runs INSIDE lldb (it can't live in SEAL — only a
debugger can freeze a real process) and emits the neutral snapshot JSON that
``runner._build_state_from_snapshot`` consumes. It records the image ASLR ``slide`` so
SEAL can rebase the snapshot to the loaded binary's file addresses (see
``snapshot/rebase.py``).

WHY IT'S LIKE THIS
------------------
* **Arch-neutral + pointer-following.** It doesn't know the target's struct layout; it
  BFS-follows pointers out of the registers (and the stack window) to capture whatever
  memory the code will actually touch, so one tool works on any binary.
* **PAC masking.** On arm64e, pointers in registers/memory carry auth bits; they're
  masked before dereferencing or the reads fail.
* **It records the slide, SEAL does the rebase.** We capture raw runtime addresses and
  hand SEAL the slide, rather than rebasing here — keeps the capture dumb and the
  address math in one place (``rebase.py``), reused by every seed.

EXTENDING
---------
* Different capture environment (a remote/gdb stub, a core dump): emit the SAME snapshot
  shape and SEAL seeds it unchanged.
* Capture more context (e.g. a specific heap arena): add ``--region`` entries or raise
  ``--depth``/``--window`` — but mind ``--max-bytes``/``--max-regions``.

PITFALLS
--------
* **Break at the TRUE function entry** (lldb ``--skip-prologue false``). Past the
  prologue the argument registers are often already spilled to the stack and dead, so
  symbolizing ``x0``/``x1`` later would have no effect — mark the stack slot instead.
* Over-wide capture (huge ``--window``/``--depth``) bloats the snapshot and can pull in
  unrelated memory; keep it to what the analysed code reaches.
* The snapshot is only valid for the exact binary build captured; its ``slide`` only
  makes sense against the image that produced it.
"""
import json
import shlex

try:
    import lldb
except ImportError:                      # importable for linting outside lldb
    lldb = None

# user virtual addresses on Darwin fit in 48 bits; mask off PAC / tag bits so a
# signed (arm64e) or tagged pointer still dereferences to the real page.
_VA_MASK = (1 << 48) - 1
# values below this are almost never real pointers (nulls, small ints, errno...)
_MIN_PTR = 0x1000


def _gp_registers(frame):
    """{name: unsigned} for the General Purpose register set, arch-neutral."""
    out = {}
    for regset in frame.GetRegisters():
        nm = (regset.GetName() or "").lower()
        if "general" not in nm:          # skip fp/vector/exception sets
            continue
        for r in regset:
            if r.GetValue() is None:
                continue
            try:
                out[r.GetName()] = r.GetValueAsUnsigned()
            except Exception:
                pass
    return out


def _read(proc, addr, n):
    err = lldb.SBError()
    data = proc.ReadMemory(addr, n, err)
    return data if err.Success() and data else None


def _merge(regions):
    """Merge overlapping / touching [addr, addr+len) byte regions, keeping real bytes."""
    items = sorted(regions.items())
    out = []
    for addr, data in items:
        if out and addr <= out[-1][0] + len(out[-1][1]):
            base, prev = out[-1]
            end = max(base + len(prev), addr + len(data))
            buf = bytearray(end - base)
            buf[:len(prev)] = prev
            buf[addr - base: addr - base + len(data)] = data
            out[-1] = (base, bytes(buf))
        else:
            out.append((addr, data))
    return out


def seal_snapshot(debugger, command, result, internal_dict):
    args = shlex.split(command or "")
    opts = {"out": "/tmp/snapshot.json", "sym": "", "stack": 1024,
            "window": 256, "depth": 2, "max-regions": 128, "max-bytes": 1 << 20}
    regions_cli = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--region":
            regions_cli.append(args[i + 1]); i += 2; continue
        key = a[2:] if a.startswith("--") else None
        if key in opts:
            opts[key] = args[i + 1]; i += 2; continue
        i += 1
    for k in ("stack", "window", "depth", "max-regions", "max-bytes"):
        opts[k] = int(opts[k])

    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    thread = proc.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    if not frame.IsValid():
        result.SetError("no valid frame — is the process stopped at a breakpoint?")
        return

    regs = _gp_registers(frame)
    pc = frame.GetPC()
    sp = frame.GetSP()
    regs.setdefault("pc", pc)
    regs.setdefault("sp", sp)

    captured = {}          # addr -> bytes
    total = [0]
    win, maxb, maxr = opts["window"], opts["max-bytes"], opts["max-regions"]

    def grab(addr, size):
        addr &= _VA_MASK
        if addr < _MIN_PTR or len(captured) >= maxr or total[0] >= maxb:
            return None
        size = min(size, maxb - total[0])
        # probe down to a readable sub-range (pages near the edge may be unmapped)
        data = _read(proc, addr, size)
        while data is None and size > 16:
            size //= 2
            data = _read(proc, addr, size)
        if data is None:
            return None
        if addr not in captured or len(data) > len(captured[addr]):
            total[0] += len(data) - len(captured.get(addr, b""))
            captured[addr] = data
        return data

    # stack window
    if opts["stack"] > 0:
        grab(sp, opts["stack"])
    # explicit regions
    for spec in regions_cli:
        a, _, s = spec.partition(":")
        grab(int(a, 16), int(s, 0) if s else win)

    # BFS pointer-following out of the registers
    frontier = [v for v in regs.values()]
    for _ in range(opts["depth"] + 1):
        nxt = []
        for v in frontier:
            data = grab(v, win)
            if not data:
                continue
            for off in range(0, len(data) - 7, 8):      # scan 8-byte LE slots for pointers
                p = int.from_bytes(data[off:off + 8], "little") & _VA_MASK
                if p >= _MIN_PTR and p not in captured:
                    nxt.append(p)
        frontier = nxt
        if not frontier:
            break

    symbolic = []
    for tok in (opts["sym"] or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        k, _, name = tok.partition(":")
        k, name = k.strip(), (name.strip() or "sym")
        if k.lower().startswith("0x"):
            symbolic.append({"addr": int(k, 16), "name": name, "size": 8})
        else:
            symbolic.append({"reg": k, "name": name, "size": 8})

    # Record the ASLR slide of the image that holds pc, so a seeding tool can load
    # the binary at the same base and have pc / code pointers line up.
    image = {}
    try:
        sb = target.ResolveLoadAddress(pc)
        sec = sb.GetSection()
        if sec.IsValid():
            image = {"module": sb.GetModule().GetFileSpec().GetFilename(),
                     "section": sec.GetName(),
                     "slide": sb.GetLoadAddress(target) - sb.GetFileAddress(),
                     "pc_file": sb.GetFileAddress()}
    except Exception as e:
        log = e  # best effort; leave image empty

    mem = [{"addr": a, "hex": d.hex()} for a, d in _merge(captured)]
    snap = {"pc": pc, "regs": regs, "mem": mem, "symbolic": symbolic, "image": image}
    with open(opts["out"], "w") as fh:
        json.dump(snap, fh)
    result.AppendMessage(
        "SNAPSHOT_WRITTEN %s  pc=%#x  regs=%d  mem=%d regions / %d bytes  symbolic=%s"
        % (opts["out"], pc, len(regs), len(mem), total[0],
           ",".join(s.get("reg") or hex(s["addr"]) for s in symbolic) or "(none)"))


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        "command script add -f %s.seal_snapshot seal_snapshot" % __name__)
    print("seal_snapshot command installed — stop at a breakpoint, then: seal_snapshot --sym x1:coord")
