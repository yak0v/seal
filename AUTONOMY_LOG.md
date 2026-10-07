# Autonomous usability session — 2026-10-08

Branch: `autonomy-2026-10-08` (on the `seal` remote).

**Mandate (from the user, going offline ~8h):** keep working without asking
questions; invent features and improvements; run detailed usability
investigations *through the MCP* (not the internal HTTP routes) across varied use
cases; for each, judge whether the experience is good/comfortable and apply
fixes/new features where it isn't; when out of work, run another experiment /
search the literature for symbolic-execution use cases and apply them. Document
everything here.

**Ground rules I'm holding to** (from project memory + prior feedback):
- Drive the tool the way a user/agent would — via MCP `tools/call` only; no
  reaching into internals to fake a result.
- Never shortcut analysis to dodge an engine limit; fix the real gap instead.
- Research/education targets only (the bundled `samples/*`), never hunting new
  real-world vulnerabilities.
- Verify every claim against the running tool before writing it down.

Experiments run against a dedicated server instance (`samples/*` on port 8775)
so the CoreGraphics session on 8770 is left undisturbed. Each entry records: the
use case, how it felt over MCP, the friction found, and what I changed.

---

## How each experiment is scored

For every use case I note a **comfort** read — could a competent user/agent reach
the goal over MCP without guessing, re-reading docs, or hitting a dead end? Then
**friction** (what got in the way) and **action** (fix/feature/none).

---
<!-- EXPERIMENTS APPENDED BELOW -->

## Experiment 1 — "find the integer overflow in `vuln`" (agent, blind)

**Use case:** a fresh agent is pointed at `samples/vuln` (x86-64) and told to find
an integer-overflow bug, with no prior setup.

**MCP path I drove:** `get_status` → `list_functions` → `get_function alloc_msg`
→ `add_scenario`/`select_scenario` → `configure` (symbolic args) →
`add_check {"kind":"int_overflow"}` (no address) → `run` → `get_run`.

**Result:** comfortable. The whole-function `int_overflow` check (no address
needed) found the `imul` at `0x400636` with **both** signed and unsigned witnesses
(`count=0xff7ff9ff, size=0x69a8bfff`). Checked and the finding really appears.

**Friction found:** `list_functions` returned *all* 15 functions, 9 of which are
CRT/`_start`/`sub_` noise. On `samples/vuln` that's survivable; on a real binary
(CoreGraphics = 13,623 functions) the raw dump is unusable for an agent — and the
tool had only a substring `query`, no "skip the noise" filter, and no signal for
when the list was capped by `limit`.

**Action — feature:** added an `only` filter to `list_functions`
(`named` | `source` | `configured` | `interesting` | `all`) and changed its
return to `{total, shown, truncated, functions[]}` so an agent knows when results
were capped. Updated the tool schema, the in-app GUIDE (core loop + recipe that
had assumed a bare list), and verified over MCP: `only:"interesting"` cuts
`vuln` from 15 → the 6 real functions; `test_mcp_server` still green (3 passed).

## Experiment 2 — "reach `abort()` in `vuln.route`" (CTF-style reach)

**Use case:** find the input that drives the branchy dispatcher `route` to its
`abort()` call (planted answer: `cmd=2, x=4242`).

**MCP path:** `disassemble route` (locate the call) → `add_scenario` →
`configure` (symbolic `cmd`,`x`) → `add_check {"kind":"reach","addr":"0x4007be"}`
→ `run` → `get_run`.

**Result:** the `reach` check solved `cmd=2, x=4242` (`0x1092`) in 0.4s — exactly
the planted input. Checked and the witness really appears.

**Friction found:** to pick the reach address the agent must read the
disassembly, but a call to an imported function showed as a bare
`call 0x4004c0` — nothing said that target is `abort`. On a no-source/stripped
binary that leaves the agent guessing which call is the dangerous one. (The
engine computed callee names in `call_targets`, but keyed by the transition-graph
callsite address, which doesn't line up with the call *instruction*, so the MCP
`disassemble` text never showed them.)

**Action — feature + fix:** resolve each **direct** call's operand target to a
name at disassembly time (`_direct_call_target` + hardened `_callee_name` that
falls back through `kb.functions` → `loader.find_symbol` → PLT `reverse_plt`),
expose it as a per-instruction `call_name`, and annotate the MCP `disassemble`
text as `call 0x4004c0  <abort>`. Verified over MCP: all three direct calls in
`route` now read `<abort>`, `<scale>`, `<frame_size>`. Full suite 68 passed.
(`call_name` is now on every instruction, so the GUI disassembly view can show
the same annotation — noted for a later GUI pass.)

## Experiment 3 — memory-safety hunt on `checks_sample` (div/null/oob)

**Use case:** point an agent at `samples/checks_sample` and have it find the three
planted memory bugs — `div_z` (÷0), `null_d` (NULL deref), `oob_r` (OOB read).
Also exercises `load_binary` over MCP.

**MCP path:** `load_binary` → `list_functions only:interesting` → for each:
`get_function` (args auto-detected) → `add_check {kind}` → `run` → `get_run`.

**What worked well:** `load_binary` over MCP is clean; the new `only:interesting`
filter surfaced exactly `div_z, null_d, oob_r, main`; args auto-detected from
DWARF with correct names/sizes (`a,b` / `p` / `buf,i`). `div_by_zero` and
`null_deref` fired first try with clear witnesses (`b=0`; `p=0xfff`). Checked —
both findings really appear.

**Friction found (real):** `oob_read` added the obvious way
(`add_check {"kind":"oob_read"}`) found **nothing**, silently. The check needs a
region to be "out of"; without an explicit `base`+`size` it falls back to
"modeled" mode (watch `alloc`-model allocations), of which `oob_r` has none. Even
declaring `buf` as a buffer didn't help, because modeled mode confines its anchor
to `[base,end)` and so only catches *straddling* reads, not a far `buf[0x2c00]`.
Nothing told the agent any of this — the worst kind of UX (a silent no-op).

**Action — feature:** a no-`base` `oob_read`/`oob_write` check now auto-anchors to
a **single declared buffer** (explicit mode, ±window anchor), unless an `alloc`
model is present (then modeled mode is clearly intended and left alone); ambiguous
(multiple buffers) is left as-is. So the natural setup — declare `buf` as a 16-byte
buffer, add `oob_read` — now fires (`i=0x1ffff`, reads far past the buffer).
Updated the `oob_read`/`oob_write` CHECK_KINDS docs to spell out the three ways to
anchor (explicit base+size / single declared buffer / modeled alloc) and that with
none it cannot fire. Verified over MCP: all three checks now FOUND via their
natural paths; full suite 68 passed (explicit + modeled oob tests unchanged).

**Still open (noted):** a check that ends up with no anchor at all still no-ops
silently — a run-summary "this check had nothing to anchor to" note would close
the loop. Deferred to a later pass.

## Experiment 4 — real CVE flow: `jsonc_printbuf` (CVE-2020-12762)

**Use case:** analyze `printbuf_memappend(struct printbuf *p, char *buf, int size)`
— whose `p->bpos + size + 1` overflows `int` — the way an agent would without IDA:
declare `p` as a 16-byte buffer (so its members go symbolic) and hunt `int_overflow`.

**MCP path:** `load_binary` → `get_function` (args + struct pointer auto-detected
from DWARF) → `configure` (p,buf as buffers, skip_calls) → `add_check int_overflow`
→ `run` → `get_run`.

**Result:** the real CVE overflow is found — `add eax, 1` at the
`p->bpos + size + 1` site, witness `size = 0x7fffffff` (INT_MAX → +1 wraps).
Checked and it really appears.

**Friction found:** the run returned **12** `int_overflow` hits with near-identical
headlines (`add X+Y`), several of which were 64-bit `add rcx,rax` / `add rax,rdx`
— i.e. **pointer arithmetic** (`p->buf + p->bpos` for the memcpy/store), flagged
only because the symbolic struct made the `buf` *pointer* member a wild symbolic
value. The real 32-bit value overflow was buried, and the headline gave no way to
tell signal from address-math noise (the distinguishing data — `result_bits`,
`src_line` — was in `extra` but not surfaced).

**Action — improvement:** the `int_overflow` message now leads with the **result
width and source location**, e.g. `signed 32-bit overflow ... add eax, 1
[jsonc_printbuf.c:34]` (the CVE line) vs `64-bit overflow ... add rcx, rax
[jsonc_printbuf.c:39]` (the memcpy pointer add). Added a triage tip to the
`int_overflow` CHECK_KINDS doc (a 64-bit add is usually address arithmetic).
Verified over MCP: the headlines now separate the line-34 value overflow from the
line-39/41 pointer math at a glance. Full suite 68 passed (no test tied to the
message text).

**Note for later:** the deeper cause is that a declared struct buffer makes
*pointer* members symbolic. A future setup-side nicety: when declaring a buffer
without a layout, offer to keep 8-byte slots that look like pointers concrete, or
lean on the existing get_struct/layout path when IDA is connected.

## Experiment 5 (feature) — run diagnostics: "why did this run find nothing?"

**Motivation:** the sharpest recurring friction across Experiments 1–4 is the
*silent no-op* — a run completes, finds nothing, and the agent/user is left
guessing whether the bug isn't there, the setup is wrong, or the tool misbehaved.
Exp 3's `oob_read` was the worst case.

**Feature:** a run's `summary.notes` now explains an empty or surprising result:
- an `oob_read`/`oob_write` check that has nothing to anchor to (no base, no single
  buffer, no `alloc` model) — the exact Exp 3 trap, now named at setup time;
- the ambiguous case (no base + multiple buffers);
- no symbolic inputs at all (nothing to solve over);
- paths that went **unconstrained** (IP hijacked → suggest skip_calls / models) or
  **errored**;
- exploration that stopped almost immediately (sites unreachable / step limit low).
Generic guesses are suppressed when a concrete setup note already names the cause,
so the banner stays signal, not noise. A healthy run emits no notes.

**Surfaced in both faces of the app:** `get_run().summary.notes` for agents (tool
description updated), and a styled "⚠ why this run turned out this way" banner in
the GUI Paths panel for humans.

**Verified:**
- Over MCP: unanchored `oob_read` → one precise note; concrete-input run → "no
  symbolic inputs" note; healthy `div_by_zero` → `notes: null`.
- In the browser (real `renderTree`): the banner renders with the notes text, no
  console errors.
- Tests green (full suite 68 earlier; mcp+checks subset 7 after the doc edits).

## Experiment 6 — symbolic stdin + the `reach` block-head trap (`vuln.main`)

**Use case:** `main` reads 8 bytes from stdin and dispatches; drive it with
symbolic stdin and `reach` a specific call site.

**What worked:** symbolic stdin flows cleanly — the path tree branches on
`stdin[0] == 4` etc., and witnesses render stdin as a byte string
(`"0000000000000000"`). The Exp-2 call-naming also helped here (`<read>`,
`<route>`, `<alloc_msg>` in the disassembly). The Exp-5 diagnostics fired on an
unreachable target ("no findings — the checks ran but nothing triggered").

**Friction found (real bug):** `reach` at the obvious target — the `call`
instruction (`0x40084c`, `0x400874`) — silently never fired, while `reach` at the
*next* address (`0x400851`, a block head) did. Cause: `reach`/`avoid` matched only
basic-block **leaders** (`state.addr == target`), but a `call` is the *last*
instruction of its block. An agent naturally points reach at the instruction of
interest, so this was a silent miss with no explanation.

**Action — fix:** `reach`/`avoid` now match the target **anywhere in a traversed
block** (`target in state.block().instruction_addrs`), not just at the head.
Verified over MCP: `reach 0x40084c` and `reach 0x400874` now fire with stdin
witnesses. Updated the reach/avoid CHECK_KINDS docs ("addr may be any
instruction, e.g. a call site"). Full suite 68 passed.

**Minor (left as-is):** `reach` at the function's own entry address doesn't fire
(exploration starts there; "reaching" the entry is degenerate) — not worth a
special case.

## Experiment 7 — crackme on a stripped binary (`machine`)

**Use case:** the classic symbolic-execution crackme — find the input that reaches
the "valid" block — on a fully stripped binary (106 funcs, 0 symbols), matching the
literature's top use cases (input-to-reach-block / crackme solving;
see sources below).

**Result:** comfortable. `sub_400650(user, code)` with a `reach` check solved
`user=0xe05a, code=0x0` reaching the target block `0x40069b` in one run; witness is
clean. Checked and it really appears. `list_functions only:interesting` surfaced
the two configured functions despite zero symbols.

**Friction found (inherent):** on a stripped binary with no workspace, an agent
faces 106 anonymous `sub_` functions and `only:named`/`only:source` are empty —
nothing to triage by. The data (`blocks`) was in the list but the agent had to sort
it themselves.

**Action — small aid:** `list_functions` gains `sort` (`size` = biggest first,
plus `name`) and now reports each function's `size`, so "show me the meaty logic"
is one call. Verified: `sort:size` surfaces `sub_400e40` (321 blocks) first. For
real names, the #9 IDA-import path remains the better answer.

Sources: [angr examples](https://docs.angr.io/examples),
[OWASP MASTG — Symbolic Execution](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0037/).
