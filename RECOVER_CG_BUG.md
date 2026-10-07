# Recovering the CoreGraphics bug with SEAL — a walkthrough (GUI)

This guide reproduces, from a **fresh start of SEAL**, the finding at the heart of
**CVE-2026-86950** — a 64→32-bit **narrowing truncation** in Apple CoreGraphics'
anti-aliased rasterizer. SEAL recovers it symbolically, from the function's
entry, with no pre-seeded state and no prior knowledge of the answer.

> **Companion:** [`RECOVER_CG_BUG_MCP.md`](RECOVER_CG_BUG_MCP.md) does the same thing
> through the MCP / HTTP API instead of the GUI. Both were validated against the
> real arm64e binary and produce the same finding.

---

## 0. What you are looking for

| | |
|---|---|
| **Function** | `_aa_lineto` @ file address `0x186a24e80` |
| **Binary** | `CoreGraphics` (arm64e, extracted from an iOS dyld_shared_cache) |
| **Bug class** | `narrowing_cast` — a 64→32-bit truncation that drops set bits |
| **Exact site** | `0x186a24fd0`: `xtn v0.2s, v0.2d` ("narrowing 64→32 bits may lose data") |
| **Mechanism** | an oversized coordinate is truncated by `xtn`, miscalculating a span width that later drives an out-of-bounds coverage write (the CVE's root cause). |

SEAL finds this in **seconds**, from the function entry, with a concrete witness.

---

## 1. Prerequisites

1. **The SEAL repo and its Python deps** (angr / claripy / capstone / fastapi).
   The project `.venv` already has them; otherwise `pip install -r requirements.txt`.
2. **Your own copy of the arm64e `CoreGraphics` binary.** It is **not** shipped in
   this repo (Apple-proprietary; git-ignored). You supply it one of two ways:
   - as a file on disk (extracted from a dyld_shared_cache), **or**
   - straight from an **IDA** instance that already has it open — see §2b.

> **No ARM setup needed.** SEAL's portable ARM64 patch (`angrgui/angr_arm_patch.py`)
> adds the missing NEON IR ops (including `xtn`/`NarrowUn`) and hooks the arm64e
> **PAC** instructions automatically when you load a scoped function. That patch is
> what makes a 9.5 MB arm64e dylib run at all — including letting *skip calls* step
> across arm64e's authenticated indirect calls (`blraa`), which is essential here.

---

## 2. Start SEAL, scoped to the function

A whole-binary CFG over a 9.5 MB dylib is impractical, so launch SEAL **scoped** to
the one function. From the repo root:

```bash
python run.py --binary /path/to/CoreGraphics --target-func 0x186a24e80 --port 8770
```

This loads only `_aa_lineto`'s range (callees are still reachable at run time),
applies the NEON ops patch, and auto-hooks PAC over the function. It finishes in
seconds. Then open **http://127.0.0.1:8770/** in your browser.

### 2b. (Alternative) Import the binary straight from IDA

If you have IDA open on CoreGraphics and don't want to point SEAL at a file:

1. Top bar → **IDA: off** → **Connect to IDA**. Enter the server URL
   (e.g. `http://<ida-host>:8744/mcp`) and **Connect**. No binary need be loaded first.
2. In the same dialog, click **⬇ Import binary from IDA**. SEAL pulls IDA's input
   file (copying it if the path is reachable, otherwise streaming the bytes over the
   MCP) and loads it. You'll also get IDA's real function names.

> You can combine this with scoping by passing `--target-func 0x186a24e80` at launch,
> or just import and then analyze the function on demand.

---

## 3. Select the function

In the left **Functions** list, type `aa_lineto` (or the address `0x186a24e80`) in
the filter and click it. The center panel shows its disassembly (or, with IDA
connected, its decompilation). You're now looking at `_aa_lineto`.

---

## 4. Set up the inputs (the "fresh" scenario)

In the **Setup** panel on the right:

1. **Arguments.** `_aa_lineto` takes three pointer/word arguments. Add three
   symbolic arguments with the **+ argument** button so you have:

   | name | mode | size |
   |------|----------|------|
   | `a0` | symbolic | 8 |
   | `a1` | symbolic | 8 |
   | `a2` | symbolic | 8 |

   (If IDA/DWARF gave a prototype, these may already be present — just confirm all
   three are **symbolic**.)

2. **Buffer behind `a0`.** `a0` is a pointer; give it something to point at. Add a
   buffer of **256 bytes** bound to `a0` (symbolic). This lets SEAL explore reads
   through the edge/coordinate structure the function walks.

3. **Skip calls.** In the **Run** section, tick **skip calls (explore only this
   function)**. This keeps exploration inside `_aa_lineto` instead of descending the
   whole render tree — and it is the setting the arm64e PAC-call fix makes work.

4. **Limits** (defaults are fine). Reasonable values: `max steps 400`,
   `max active 400`, `seconds 180`, `loop bound 12`.

---

## 5. Add the detector

In the **Checks** panel:

1. Click **+ detect**.
2. Choose **Narrowing cast (lossy)** — "value truncated to a smaller int,
   dropping set bits."
3. Leave the address blank so it watches the **whole function** (SEAL will flag
   every narrowing site it reaches, including the `xtn`).
4. **Add check.**

> Checks are shared across scenarios, so this one applies no matter which scenario
> is active.

---

## 6. Explore

Click **▶ Explore paths** in the Run section.

Watch the **activity feed**: it shows paths being enumerated live (active / ended /
findings), so you can tell it's working rather than stuck. The **Cancel** button
stops it at any time. For this function it finishes in a few seconds.

---

## 7. Read the result

The **Findings** list fills in. The one that matters:

```
narrowing_cast @ 0x186a24fd0
  "narrowing 64->32 bits may lose data at xtn v0.2s, v0.2d"
```

That is CVE-2026-86950's truncation: a 64-bit coordinate narrowed to 32 bits by the
NEON `xtn`. (You'll also see a few companion narrowings nearby, e.g. the 16→8-bit
colour-channel extracts — expected noise from the same pass.)

**Click the finding.** SEAL jumps to the exact line in the decompilation, highlights
it, and shows the **example input** (the concrete values that drive this path) as
chips at the top — the variable names are highlighted, and long buffer values open
in a scrollable viewer when clicked. A representative witness:

```
a1 = 0x0
a2 = 0x0
a0_buf = <256-byte solution that reaches the xtn>   (click to expand)
```

You now have: the vulnerable instruction, the path to it, and a concrete input that
exercises it — recovered from a blank slate.

---

## 8. (Optional) Make the path realistic with a concolic snapshot

The run above is fully symbolic from entry — it needs nothing external. If you want
SEAL to follow the *exact* path a real glyph render takes (realistic pointers and
edge data), you can seed it with a **live snapshot** captured at the function's
entry under lldb. This is a refinement, **not** a requirement for the finding above.
See **PART 7 — Concolic seeding from a real run** in the in-app guide
(the **?/Guide** panel) and `seal_validation/snapshot/` for the capture scripts.

---

## 9. Troubleshooting

- **A path ends at the first `bl`, no exploration.** You're on an older build. The
  arm64e PAC-call fix (skip-calls across `blraa`/`blraaz`) is required; make sure
  you're on the current tree.
- **`UnsupportedIROpError` on a NEON op.** The ARM patch applies automatically on a
  scoped load. If you loaded the whole binary a different way, ensure
  `angr_arm_patch.apply()` has run and PAC is hooked over the function's range.
- **Nothing found / paths die immediately.** Confirm `a0` has a buffer bound to it
  and all three args are **symbolic**, and that **skip calls** is on.
- **The binary won't load / is huge.** Always launch with `--target-func
  0x186a24e80` (or import then analyze on demand). Whole-binary CFG on this dylib is
  not practical.

---

*Research use only. This reproduces a known, disclosed issue on a binary you supply,
for defensive and educational analysis.*
