# SEAL validation + ARM64 support for CVE-2026-86950

Goal: find out whether **SEAL** (this project's angr-based symbolic bug-hunter)
can find a real-world vulnerability — Apple CoreGraphics **CVE-2026-86950**, an
out-of-bounds write in the anti-aliased glyph rasterizer (`aa_*`).

## TL;DR status

| Question | Answer |
|---|---|
| Is the bug findable by symbolic execution in principle? | **Yes** — it's a reachable OOB write from attacker-controlled input. |
| Does SEAL find it on a tractable x86-64 reproduction? | **Yes** — `narrowing_cast` + `oob_write` fire with a witness (see below). |
| Can SEAL run on the *real* arm64e CoreGraphics out of the box? | **No** — angr/VEX lacks several ARM64 NEON ops and can't decode arm64e PAC instructions. |
| Is that a conceptual limit or an engineering gap? | **Engineering gap.** We are closing it incrementally (see `angrgui/angr_arm_patch.py`). |
| Does the real `aa_lineto` execute symbolically after the patch? | **Yes — end to end, zero remaining walls** (NEON ops + PAC hooks). |
| **Does SEAL find a real OOB write in the real arm64e binary?** | **YES.** On `aa_merge_scanline_edge` it found an out-of-bounds coverage write with a concrete PoC coordinate (see "Phase 2"). |

## Phase 2 — SEAL finds a real OOB write on the unpatched binary

Target: `aa_merge_scanline_edge(short *buf, int a2, …, int a4, …)` @ `0x183c6fb28` —
the real coverage-rasterization leaf, which writes `buf[min(a2,a4) >> 12]`. Driven
through SEAL's own pipeline (`Binary(target_funcs=[…])` + `Run` + `oob_write`),
symbolic coordinates, 512-byte buffer:

```
oob_write @ 0x183c6fb80: "address can leave the 512-byte buffer"
  witness:  a2 = 0x7e000001, a4 = 0x7e800000
  write_addr = 0x2d41fc000  (base 0x2d4100000 + 0xfc000 ~= 1 MB past a 512-byte buffer)
```

SEAL solved a concrete coordinate that drives the coverage write ~1 MB out of
bounds — the CVE's mechanism (oversized coordinates → OOB coverage write) on the
actual binary. Reaching the full `cache_render` call tree from the glyph entry is
still open (path explosion through `CGRunner`/clipper); this leaf proves the
capability end to end.

### Two SEAL bugs fixed en route (both real, arch-general)

- `runner._set_arg` was **x86-only** (hardcoded `rdi/rsi/…`, wrong
  `function_prototype()` call) → crashed on AArch64. Now ABI/arch-aware.
- `checks.BufferBoundsCheck._check_region` explicit mode used `belongs AND oob`
  with `belongs = fully-in-bounds`, a contradiction → **explicit-mode `oob_write`
  never fired**. Now anchors the write to the buffer by a window and flags when it
  can leave `[base, base+size)` (also catches paths where the index is *already*
  forced out of range).

## Files

- `glyph_harness.c` / `glyph_harness` — a ~20-line x86-64 ELF reproduction of the
  bug's logic: 64-bit→32-bit **narrowing truncation** → width miscalculation →
  **undersized `malloc`** → **out-of-bounds write**.
- `run_seal.py`, `run_seal2.py` — drive SEAL's real pipeline (`engine.Binary` +
  `runner.Run` + checks) headless against the harness.
- `../angrgui/angr_arm_patch.py` — **portable** runtime patches that add the
  missing ARM64 NEON IR ops and hook arm64e PAC instructions (see below).

## What SEAL found (on the x86-64 reproduction)

Running `run_seal2.py`:

```
[narrowing_cast]  glyph_harness.c:14   int32_t fx = (int32_t)wide;
                  "narrowing 64->32 bits may lose data"
[oob_write]       glyph_harness.c:22   cov[GLYPH_SPAN] = 0xFF;
                  "out-of-bounds write ... address can leave its allocated buffer"
   witness (both):  coord = 0x100000  (= 2^20)
```

The witness is the real mechanism: `2^20 * 4096 = 2^32` → `(int32_t)` truncates to
`0` → `width_px = 1` → `malloc(1)` → writing pixel 200 overflows. SEAL discovered
that input itself.

## Why the real arm64e binary doesn't work out of the box

CoreGraphics (extracted from an iOS 27.0 dyld_shared_cache, see `../ipsw/`) is
**arm64e**. The vulnerable functions use NEON FP/vector instructions. angr:

1. **Missing NEON IR-op handlers** — e.g. `Iop_NarrowUn64to32x2` (`xtn`, the exact
   truncation in `aa_lineto`), `Iop_ZeroHI64ofV128`. angr raises
   `UnsupportedIROpError`.
2. **Undecodable arm64e PAC instructions** — e.g. `retab` (bytes `ff0f5fd6`) at the
   function epilogue. libVEX can't decode pointer-authentication ops at all.
3. **Scale** — whole-binary `CFGFast` over a 9.5 MB / 16,821-function dylib is
   impractical; analyze single functions instead.

None of these is conceptual — they're gaps in angr's ARM64 support.

## The portable fix — `angrgui/angr_arm_patch.py`

Runtime monkeypatch, **no edits to installed angr** (so it survives reinstalls and
works on any machine that has this repo). Usage:

```python
from angrgui import angr_arm_patch
angr_arm_patch.apply()                       # adds the missing NEON IR ops (idempotent)
angr_arm_patch.patch_pac(project, start, end)  # hooks arm64e PAC ops in a range
```

Coverage was determined by **scanning the whole CoreGraphics `.text`** (1,317,533
instructions, 293 distinct mnemonics) and mapping each to its VEX ops — not
guesswork. Implemented (`apply()`, 23 ops registered):

- `NarrowUn` family (XTN truncate), `QNarrowUn` family (SQXTN/UQXTN/SQXTUN
  saturating narrow), `ZeroHI64/96/112ofV128`, `Reverse{8,16,32}sIn*` (REV
  byte/element reverse), `SqrtF32/F64`.
- **PAC** (`patch_pac()`): `retaa`/`retab`→`ret`; `braa`/`blraa`/…→branch/call to
  the target register; `paci*`/`auti*`/`pacd*`/`autd*`/`pacga`/`xpac*`→nop.

**Known gaps** (whole-binary scan shows only these NEON ops remain, all rare
x1–x6, in codec/colour math — not the glyph path): the `Qand*Narrow` /
`Sh` / `Rsh` / `QShlNsat` saturating/rounding-shift family, plus LSE atomics
(`ldadd`/`cas`/`ldapr`) and `udf` that libVEX can't decode. These are left for
**on-demand** implementation — a wrong saturating-shift handler would silently
corrupt analysis, worse than a clean error. The module docstring lists them.

### Single-function loading

`engine.Binary(path, target_funcs=[addr, …])` scopes `CFGFast` to just those
functions' ranges (callees still reachable at execution time) and auto-hooks PAC
over them — so a 9.5 MB dylib loads in seconds instead of never. Whole-binary
remains the default when `target_funcs` is omitted (x86 workflow unchanged).

## Reproduce on another machine

```bash
# 1. deps (this repo's venv already has angr/claripy/capstone)
python -m pip install -r requirements.txt       # or use the project .venv

# 2. x86-64 validation (needs zig for the cross-compile, or any x86-64 gcc)
zig cc -target x86_64-linux-gnu -g -O0 -o seal_validation/glyph_harness seal_validation/glyph_harness.c
python seal_validation/run_seal2.py

# 3. ARM64 experiment (needs ../ipsw/CoreGraphics_out/CoreGraphics)
#    apply the patch, then drive single functions — see /tmp scripts or runner usage.
```

The ARM patch is pure-Python and ships in `angrgui/`, so step 3 needs no
per-machine changes beyond having this repo + the extracted CoreGraphics binary.
