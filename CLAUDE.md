# SEAL — project conventions

## CORE RULE: dual human/agent parity (non-negotiable)

SEAL has two front ends — the **web GUI** (for a human) and the **MCP server** (for an
agent). They are two views of the **same** session and state, and they must stay at parity.

- **Everything a human can do in the GUI must be doable by the agent over MCP**, and
  **everything the agent can do over MCP must be doable / visible by the human in the GUI.**
- **All state is visible in the web GUI** — every binary, function, scenario, argument,
  buffer, assumption, call model, return bound, check, run, finding, and every field of a
  run's result (confidence, coverage, concrete gates, notes, witnesses, paths).
- **If something is only reachable or visible through the agent, it does not exist.** A
  feature is not "done" until it is a first-class part of BOTH surfaces.

### What this means for every change

When you add or change a capability, in the SAME change:
1. Expose it as an **MCP tool / spec field** (agent can invoke it).
2. Expose it in the **GUI** (`angrgui/static/`) — a control to invoke it AND a place its
   state/result is shown. Not just dumped into free-text `summary.notes`: structured
   fields get structured, legible UI (badges, sections, actionable buttons).
3. Keep the **neutral data contract** (`backend.py`) as the single source both surfaces
   read from, so they can't drift.
4. Document it for both audiences — the human `📖 Docs` and the agent `🤖 Clanker docs`
   (the embedded GUIDE in `server.py`).

A change that touches only `server.py`/`runner.py`/`checks.py` without a corresponding
`angrgui/static/` surface is incomplete by definition.

## Other working rules
- Validate on REAL functions through the app/MCP, never headless shortcuts (see memory).
- Never cheat an analysis to dodge an engine limit — fix the engine.
- State push status after every commit.
