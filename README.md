# SEAL — Symbolic Execution Analysis Lab

A visual, agent-drivable front end for [angr](https://angr.io), built for bug hunting.
Instead of writing a throwaway Python script for every function you want to symbolically
execute, you set up and explore everything through a GUI — and/or let an AI agent drive
the exact same session over MCP while you watch it happen live.

SEAL runs **one function at a time** with its inputs left unknown ("symbolic") and asks a
solver questions — *can execution reach X? can this multiply overflow? can this write land
outside the buffer?* — returning, for every yes, the **concrete inputs (a "witness")** that
trigger it. It works on **x86-64 and ARM64/arm64e** (iOS/macOS system binaries included).

![code view with a finding](docs/code_with_hit.png)

- **Per-function setup** — which arguments are symbolic and how wide, constraints they must
  satisfy, pointers to symbolic buffers or laid-out structs, symbolic stdin/files, and
  **concolic seeding** from a captured real execution (so only attacker-controlled inputs
  stay unknown and bugs become precise conditions instead of "every path").
- **The paths angr explored**, as a tree overlaid on the control-flow graph, with per-line
  concrete values and source lines.
- **Checks** you attach and reuse: integer overflow, narrowing cast (incl. NEON `xtn`),
  float anomaly, out-of-bounds write, reachability (reach/avoid), assertions, and custom
  Python predicates. Every finding carries a witness.
- **Live, shared, multi-user session** — an AI agent driving SEAL over its built-in **MCP**
  server and a human in the GUI see and steer the same analysis. Many agents and the human
  can work on different functions at once (state is serialized, so nothing clobbers); an
  agent moves your view only when it explicitly asks you to look (`show_function`), never on
  every run. Runs, the human's review verdicts, free-text notes, and a shared TODO queue of
  functions to test next are all **stored and persist across restarts** — a documentation
  surface and a control panel for the agents (the GUI's **Notebook** tab).

Everything you set up for a binary is saved next to it (`<binary>.angrgui.json`), so a
project persists across restarts.

## Install & run

```bash
pip install -r requirements.txt            # angr, fastapi, uvicorn, ...  (Python ≥ 3.10)
python run.py --binary <path> --port 8770  # open http://127.0.0.1:8770
# a huge dyld-shared-cache dylib: pre-analyze just the function you want
python run.py --binary CoreGraphics --target-func 0x186a24e80 --port 8770
```

Then: pick a function → set up its initial state → add checks → **Run**. Findings appear with
a concrete witness (the exact inputs that trigger them).

Run the tests with `python -m pytest tests/ -q`.

## Drive it from an AI agent (MCP)

SEAL exposes a built-in MCP server at `http://<host>:<port>/mcp` (Streamable HTTP, no auth).
Point your MCP client at it and call **`get_guide`** first — it returns the full operating
manual (the same text behind the GUI's **🤖 Clanker docs** button). The typical loop:

```
list_functions → get_function → disassemble/decompile → configure/add_assumption/add_check
→ run → get_run   (poll until status "done"; read each finding's witness)
```

Everything the agent does streams to the GUI's live Activity feed. By default the agent's
runs do **not** move your view (so several agents can work at once); turn *follow agent* on to
have your view track it, or let the agent call `show_function` when it wants your eyes on a
specific result. Stored runs, your review verdicts (good / bad / refine), notes, and the
shared TODO queue live in the **Notebook** tab and over MCP (`list_runs`, `list_reviews`,
`review_run`, `add_target`, …), so the human and the agents coordinate through one workspace.

## The checks

| Check | Answers | 
|---|---|
| **int_overflow** | can an `add`/`sub`/`mul` wrap past the type width? |
| **narrowing_cast** | is a value truncated to a smaller int, losing data? (incl. arm64 NEON `xtn`) |
| **div_by_zero** | can the inputs drive an integer division/remainder's divisor to zero? |
| **float_anomaly** | can a float op produce NaN/±Inf? |
| **oob_write** | can a write land outside `[base, base+size)` (or outside a modeled allocation)? |
| **oob_read** | can a read fall outside the buffer (out-of-bounds read / info leak)? |
| **null_deref** | can a pointer be driven into the null page on a read/write? |
| **assert** | can this invariant be made *false* on some path? (counterexample) |
| **reach / avoid** | does any path reach this address? / flag paths that do |
| **custom** | your own `def check(state, api): ...` predicate |

Add any check for the whole function or pin it to one instruction. Every finding carries a
**witness**: concrete inputs solved so they actually trigger the condition on that path.

## ARM64 / arm64e

angr/libVEX ship without several NEON IR ops and can't decode arm64e pointer-authentication
instructions. `angrgui/angr_arm_patch.py` fixes both at runtime (no edits to installed angr),
so SEAL runs on real iOS/macOS binaries. Large dyld-shared-cache dylibs load in a "lazy" mode
(functions indexed; each CFG built on demand) so a 9 MB framework opens in seconds. See
`docs/ARCHITECTURE.md` §6.

## Concolic seeding (snapshots)

For a function deep inside a real library, start from a **snapshot of a real execution** and
make only the attacker-controlled fields symbolic. `angrgui/snapshot/capture.py` (an lldb
script) dumps a live process's registers + pointer-reachable memory in SEAL's `initial_state`
shape; SEAL rebases and seeds it (even mid-function). See `docs/ARCHITECTURE.md` §7 and the
tiny self-contained proof in `concolic_demo/`.

## What's in the repo / for contributors

Start with **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** — the full developer map (data
flow, the framework-agnostic backend seam, every subsystem's *why / how to extend / pitfalls*).
Every module under `angrgui/` also carries a `ROLE / WHY IT'S LIKE THIS / EXTENDING / PITFALLS`
docstring. `seal_validation/` documents a worked validation against the already-published,
patched **CVE-2026-86950** in CoreGraphics (research/education scope only — not for hunting
novel 0-days or building exploits).

> **Note on inputs:** proprietary binaries (extracted Apple frameworks under `ipsw/`, the macOS
> CoreGraphics build), their IDA databases, large captured snapshots, and `node_modules/` are
> **git-ignored** — they are inputs you supply, not source. See `.gitignore`.
