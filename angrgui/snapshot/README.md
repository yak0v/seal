# SEAL concolic snapshot capture

`capture.py` is an lldb script that records the **concrete machine state** at a
point in a live process — all general registers plus the memory they transitively
point at — as a SEAL `initial_state` snapshot. SEAL then seeds exactly this state
and makes only the fields you mark attacker-controlled symbolic, so exploration
follows the real path instead of treating every input as unknown (concolic).

## Capture

```
lldb <program>
(lldb) command script import angrgui/snapshot/capture.py
(lldb) breakpoint set --name <func> --skip-prologue false   # entry, so arg regs are still live
(lldb) run <args>
(lldb) seal_snapshot --out snapshot.json --sym x1:coord
```

**Break at the true entry** (`--skip-prologue false`). Past the prologue the
argument registers are often spilled to the stack and dead, so symbolizing `x1`
would no longer propagate — mark the stack slot instead (`--sym 0xADDR:coord`).

Flags: `--out`, `--sym reg:name|0xADDR:name,...`, `--stack N` (bytes from sp,
default 1024), `--window N` (bytes at each discovered pointer, default 256),
`--depth N` (pointer-follow levels, default 2), `--region A:S` (extra explicit
region, repeatable), `--max-regions`, `--max-bytes`.

The capture is read-only and never modifies the target. ARM64e pointer-auth (PAC)
bits are masked before a pointer is dereferenced.

## Seed SEAL

In the State tab: **Load snapshot…**, paste the JSON, list the symbolic fields.
Or via the run spec:

```python
spec = {"func_addr": snap["pc"],
        "initial_state": {"kind": "snapshot", **snap},   # pc, regs, mem, symbolic
        "checks": [...], "limits": {...}}
```

## Address matching

The snapshot's `pc`/pointers must match the binary SEAL loads. lldb launches with
ASLR disabled by default, so a locally-run binary's runtime addresses equal its
static ones. To seed a binary you cannot run on this host (e.g. an iOS arm64e
framework), capture on a host/device that runs that exact build and load the same
build in SEAL.
