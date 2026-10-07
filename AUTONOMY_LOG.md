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
