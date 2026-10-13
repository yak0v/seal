# SEAL — Architecture & Developer Guide

> SEAL (Symbolic Execution Analysis Lab) is a visual, agent-drivable front-end over
> [angr](https://angr.io) symbolic execution for hunting bugs and reachability facts in
> **one function at a time** of a compiled binary. A FastAPI backend drives angr; a
> vanilla-JS GUI and an MCP server are two clients of the same session, so a human and an
> AI agent watch and drive the same analysis live.

This document is the map for a developer or agent picking the project up cold. Read it
first, then the per-module docstrings (every module under `angrgui/` has a
`ROLE / WHY IT'S LIKE THIS / EXTENDING / PITFALLS` header). For the *agent* operating
manual (how to drive SEAL over MCP), see the `GUIDE` string in `angrgui/server.py` — the
same text the `get_guide` MCP tool and the GUI's "🤖 Clanker docs" modal serve.

---

## 1. The big picture

```
            ┌─────────────────────────── one FastAPI process (server.py) ───────────────────────────┐
   Human ── │  GET /, /app.js        ── GUI (static/app.js + index.html), framework-IGNORANT         │
   (GUI)    │  GET /api/...          ── load / function / run / values / events(SSE)                 │
            │                                                                                        │
   Agent ── │  POST /mcp (JSON-RPC)  ── MCP tools: list_functions, configure, run, get_run, ...      │
   (MCP)    │                                                                                        │
            │         both clients mutate the SAME _Session S and publish to the SAME EventBus       │
            │                                   │                                                    │
            │                                   ▼                                                    │
            │   backend.py  Backend (ABC) ── AngrBackend ──►  engine.Binary  +  runner.Run           │
            │   (the neutral JSON contract: the ONLY vocabulary the GUI/MCP know)                    │
            └────────────────────────────────────────────────────────────────────────────────────────┘
                                                │
                                                ▼
                                         angr / claripy / cle / pyvex   (+ angr_arm_patch for arm64e)
```

Two ideas hold the whole thing together:

1. **One session, two clients, one event bus.** Whatever an agent does over MCP and
   whatever the human does in the GUI both mutate the single in-memory `_Session S` and
   both publish to the same `EventBus`. The GUI subscribes to the bus over SSE
   (`/api/events`), so the human *watches the agent work in real time* and the view
   auto-follows the agent's function/run. This is a core product goal, not a nicety.

2. **A neutral data contract behind a backend seam.** The GUI and MCP never import angr.
   They speak a small, framework-agnostic JSON vocabulary (BinaryInfo, FunctionSummary,
   RunSpec, RunSnapshot, PathNode, Finding, Value, PathValues) defined and documented in
   `angrgui/backend.py`. angr lives behind `AngrBackend`. A second engine (Triton, QBDI,
   a concolic executor) can be added by implementing `Backend` and emitting those shapes —
   without touching the GUI.

---

## 2. Repository layout

```
run.py                     entry point: python run.py --binary <path> [--target-func 0x..] --port 8770
angrgui/
  server.py                FastAPI app: HTTP routes + MCP server + SSE EventBus + the agent GUIDE
  backend.py               Backend ABC + AngrBackend + registry; the NEUTRAL JSON CONTRACT (read its docstring)
  engine.py                Binary: load a program, index/analyze functions, disassemble, DWARF, arm64e patch
  runner.py                Run: build the initial state (incl. nested-pointer buffers + snapshot regs/flags), install checks, explore paths, classify path ends, collect findings; trace_assignments
  checks.py                the check kinds (reach/avoid/assert/int_overflow/narrowing_cast/div_by_zero/float_anomaly/oob_write/oob_read/null_deref/custom)
  exprlang.py              the assumption/assert expression language -> claripy ASTs (hand-rolled parser, no eval; int + float compares)
  pretty.py                format claripy ASTs + witness values for humans (inverse of exprlang)
  workspace.py             per-binary project file (<binary>.angrgui.json): scenarios + shared checks + stored runs/reviews/targets, lock-serialized, migration
  codegen.py               export a standalone runnable angr script from a function's config (transparency)
  idamcp.py                optional IDA bridge (MCP client): names, Hex-Rays pseudocode, struct layouts
  angr_arm_patch.py        portable runtime patch: missing NEON IR ops + arm64e PAC hooks (no edits to installed angr)
  snapshot/
    capture.py             lldb script: dump a live process's regs + pointer-reachable memory as an initial_state snapshot
    rebase.py              rebase a live (ASLR-slid) snapshot into the binary's file-address space
  static/
    app.js, index.html     the GUI (vanilla JS); consumes the neutral contract + SSE; framework-ignorant; Notebook/control-panel tab (runs, reviews, targets), busy indicator, check-detail + per-line value views
seal_validation/           the CVE-2026-86950 validation harness + the live-capture scripts + notes (see §8)
  snapshot/live_bp.py      lldb helper: break by ADDRESS in a dyld-shared-cache image (name resolution hangs)
concolic_demo/             a tiny self-contained example proving concolic snapshot seeding (demo.c + demo)
tests/                     pytest suite (exprlang, paths/codegen, nested pointers, snapshot flags, …) — 81 tests
docs/                      this guide + screenshots
```

---

## 3. Data & control flow

### Loading a binary
`load_binary(path)` → `make_backend("angr", path=...)` → `engine.Binary(path, target_funcs=?)`.
- `Binary` applies `angr_arm_patch.apply()` (idempotent), then `angr.Project(...)`.
- **Lazy mode** auto-engages for big binaries (>2000 function symbols or >3 MB of code):
  instead of a whole-binary `CFGFast` (impractical for a ~13k-function dyld-cache dylib),
  functions are *indexed* from the symbol/segment table and each one's CFG is built **on
  demand** when first selected. `target_funcs=[...]` pre-analyzes specific ones.
- Mach-O quirk: cle does **not** reliably set `is_function`, so functions are indexed by
  executable-segment membership instead.

### Setting up and running a function
GUI/MCP edits are stored by `workspace.py` as the function's config: a list of
**scenarios** (each a full initial state) plus **shared checks**. `run` flattens the
*active* scenario + shared checks into a `RunSpec` and hands it to `runner.Run`:
- `Run._build_state()` builds the angr initial state — either a **call state** with
  symbolic args (the default "fresh call") or, if `initial_state.kind == "snapshot"`, a
  **concolic seed** from a captured real state (see §7).
- Checks are instantiated and installed. Breakpoint-driven checks (overflow, narrowing,
  float, oob) hook `state.inspect`; reach/avoid/assert observe block heads.
- A `simgr` explores under step/active/time/loop limits. Findings accumulate with their
  concrete **witness** (solved inputs). Everything streams to the EventBus as it happens.
- The result is a `RunSnapshot`: status, findings, and the path **tree** (nodes, examples,
  leaf classifications: deadended / returned / **unconstrained** / errored).

### Reading results
`get_run(run_id)` returns the snapshot. `path_values(run_id, node)` re-executes that path
concretely (`runner.trace_assignments`) to get the value assigned at each instruction — the
GUI overlays these on the disassembly/decompilation so the human sees real values per line.

---

## 4. The neutral contract & the backend seam (`backend.py`)

The single most important design rule: **the GUI and MCP are framework-ignorant.** They
only ever see the JSON shapes documented at the top of `backend.py`. `AngrBackend` adapts
`engine.Binary` + `runner.Run` + `trace_assignments` to those shapes.

**To add another engine** (e.g. Triton/QBDI/concolic): implement the `Backend` ABC
(`binary`, `runs`, `start_run(run_id, spec, on_event)`, `run_snapshot`, `run_values`,
`cancel_run`, `new_run_id`), emit the contract shapes, and `register_backend("triton", ...)`.
Nothing in `app.js` or the MCP layer changes. `server.py` holds `S.backend`; `S.binary` and
`S.runs` are compatibility properties over it.

---

## 5. Key subsystems (why + how to extend + pitfalls)

Each module's own docstring has the detail; this is the cross-cutting summary.

- **engine.py** — *why* lazy/arm64e (above). *Extend:* `get_function` lazily analyzes and
  returns `None` (doesn't raise) on failure. *Pitfall:* `self.cfg` is `None` in lazy mode;
  `base_addr` is threaded through but **cle's Mach-O backend ignores it** — that's why we
  rebase snapshots instead of loading at a slide (§7).

- **runner.py** — *why:* `_set_arg` is arch-aware (it was x86-only and crashed with
  `KeyError 'rdi'` on AArch64). The concolic seeder `_build_state_from_snapshot` skips
  `pc`/`ip` when applying captured registers so a saved `pc` can't clobber the chosen
  start address — **this is what makes mid-function seeding work** — and restores each
  register at its real width (so a 128-bit NEON reg isn't truncated) and the condition
  flags via `_restore_flags` (angr has no plain `cpsr`/`eflags` register: NZCV live in the
  VEX flag thunk, so a naive `setattr` drops them and diverges a mid-branch seed).
  *Nested-pointer buffers:* a buffer `layout` member with `mode:"pointer"` is materialized
  into a REAL sub-region (recursively, depth-capped) so `p->data[i]` / `p->next->val`
  deref correctly instead of hitting a wild symbolic address; the member name resolves to
  the sub-region address so an oob check can anchor to it. *Path-end classification:* each
  successor is labelled (returned / deadended / unconstrained / `left_image` — a tail-call
  to an address in no loaded object, ended cleanly rather than treated as an error), and the
  run `summary.stopped` says WHY exploration stopped (complete / step limit / timeout / …).
  *Pitfall:* `skip_calls` (CALLLESS) **bypasses call models** — don't enable it when you
  rely on modeled allocs.

- **checks.py** — *extend:* subclass `BaseCheck` and register it in the kind→class map;
  set `installs_breakpoint = True` and hook `state.inspect` for per-operation checks.
  *Why (two real fixes):* `oob_write` used to test `belongs AND oob` (contradictory → never
  fired) and now anchors the write to the buffer and asks whether it *can* leave the range;
  `narrowing_cast` now matches **NEON vector-lane** truncation (`xtn` emits a
  `Concat` of lane-`Extract`s from a 128-bit vector) as well as scalar C casts. *Pitfall:*
  these checks pattern-match claripy AST shapes, so they are coupled to how ops are lifted —
  if `angr_arm_patch` changes an op's emitted shape, re-check the matcher.

- **exprlang.py / pretty.py** — the expression language used by assumptions and `assert`
  (parser → claripy) and its inverse (AST → text). *Pitfall:* comparisons are **unsigned by
  default**; signed variants are `s`-prefixed. `pretty` output must stay valid exprlang
  syntax because some flows round-trip a printed condition back in as an assumption.

- **workspace.py** — a function's setup = **scenarios** (per-reach initial state) + **shared
  checks**, saved next to the binary as `<binary>.angrgui.json`. `SCEN_FIELDS` is the
  authoritative per-scenario field list (note `initial_state` lives there). *Extend:* a new
  per-scenario field must be added to `SCEN_FIELDS` (and the GUI/MCP that read it) or it is
  silently dropped on save. *Shared collaborative state:* the file also stores **runs**
  (full findings + metadata, durable so results survive a restart and are visible to the
  user and other agents), **reviews** (the user's good/bad/refine verdict + note on a run),
  and **targets** (the shared TODO queue). *Concurrency:* all mutation goes through an
  **`RLock`** with a single `_save_locked`, and config edits use an atomic read-modify-write
  (`update_function`) — so several agents (plus the human) editing *different* functions
  never corrupt the file or clobber each other. *Pitfall:* never write the JSON outside the
  lock, and keep per-run records append-mostly (don't rewrite history another agent may be
  reading).

- **server.py** — HTTP + MCP + the `EventBus`. *Why:* `/` and `/app.js` are served with
  no-cache headers so a plain reload shows edits. The SSE `/api/events` endpoint tolerates a
  **stale Last-Event-ID from a previous server process** (after a restart it resumes from
  "now" instead of waiting for a sequence that will never arrive) — without this, a tab
  silently receives nothing after a restart. *Extend an MCP tool:* add a `_mcp_*` handler, a
  `TOOL_DEFS` entry (name + inputSchema), and a dispatch entry; publish to the bus so the GUI
  reflects it. *Run persistence:* a finished run is persisted via `_persist_run_record`
  (so `list_runs`/`get_run` serve it after a restart or from another process); the
  review/target endpoints (`review_run`, `note_run`, `list_reviews`, `add_target`,
  `list_targets`, `resolve_target`) and `show_function` (publishes a `focus` event — the
  one thing that moves the human's view) round-trip through the workspace.

- **idamcp.py** — optional IDA bridge for names/pseudocode/structs (angr still does all the
  analysis). *Pitfall:* `decompile`/`get_struct` need a live IDA connection; IDA's load base
  must match SEAL's (load the **same build** in both). IDA is often reached over a forward to
  a VM, hence the `host_header` nuance.

- **codegen.py** — exports a standalone runnable angr script from a config (transparency /
  portability). *Pitfall:* it must stay in sync with `runner.py`; it currently emits only a
  `call_state` (no snapshot seed, no models, no skip_calls) — extend it when you change how
  the runner builds state.

- **GUI (static/app.js, index.html)** — framework-ignorant; renders the neutral contract and
  the live SSE feed. State is in a single `A` object. *View movement:* "follow agent" is
  **off by default** (`A.followAgent`), so an agent's runs don't yank the human's screen and
  many agents can work at once; only a `focus` event from `show_function` (or the human
  opting into follow) navigates the view. *Also here:* the Notebook/control-panel tab
  (`renderNotebook` — run history, review buttons, notes, target queue), a **busy indicator**
  (`setBusy`, instrumented `api()`), the **check-detail** view (`openCheckDetail`), and the
  **per-line value** overlay (reads/loads/stores from `path_values`). *Pitfall:* the GUI is
  loaded once per tab, so JS changes need a reload; server changes need a restart.

---

## 6. ARM64 / arm64e support (`angr_arm_patch.py`)

angr/libVEX ship without several NEON IR ops and cannot decode arm64e pointer-auth
instructions, which blocks real iOS/macOS binaries. `angr_arm_patch` fixes this at runtime
(no edits to the installed angr, so it survives reinstalls and is portable):

- **`apply()`** registers handlers for the missing NEON ops (NarrowUn/`xtn`, saturating
  QNarrowUn, ZeroHI*ofV128, byte/element Reverse, and vector `Sqrt` — the scalar handler
  accepts angr's per-lane `_auto_vectorize` calls so `Sqrt64Fx2`/`Sqrt32Fx4` work; `Mul64Fx2`
  and the f16↔f32 conversions were already covered). Idempotent; call before any lifting. It
  also calls **`patch_lmdb_max_dbs()`**, which raises the `max_dbs` angr's `RuntimeDb` opens
  its LMDB with (hardcoded to 10 — a big binary with many analyses hits `MDB_DBS_FULL`) by
  intercepting `lmdb.open`; version-proof, as SEAL doesn't use lmdb itself.
- **`patch_pac(project, start, end)`** hooks PAC instructions over a range: `retaa/retab`→`ret`,
  `braa/blraa/…`→branch/call to the target register, `paci*/auti*/xpac*`→nop.
- **Deliberate gaps:** some saturating/rounding-shift ops, LSE atomics, and `udf` are *not*
  implemented, because a *wrong* saturating handler would silently corrupt analysis — a clean
  `UnsupportedIROpError` is safer. Add a real handler when you hit one in a hot path. Coverage
  was chosen by scanning the whole target `.text`, not by guessing.

---

## 7. Concolic seeding from a real run (the snapshot workflow)

A "fresh call" (symbolic args, empty memory) is wrong and intractable for a function deep
inside a real library. **Concolic seeding** starts from a snapshot of a *real* execution and
makes only the attacker-controlled fields symbolic, so exploration follows realistic paths and
the bug becomes a *precise* condition instead of "every path."

End-to-end:

1. **Capture** (`angrgui/snapshot/capture.py`, an lldb script): stop at the function, run
   `seal_snapshot`. It is function-agnostic. It dumps every register (incl. the 128-bit NEON
   regs) and, by default, the memory **reachable from the argument registers** (x0-x7 + frame
   regs) — BFS over concrete pointers, arm64e PAC-masked, depth-bounded (so a dense global
   graph doesn't explode), plus the stack frame. `seal_snapshot <out> full` instead dumps the
   whole data image (every writable/anonymous readable region) — complete but large (hundreds
   of MB on a real process). It also records each module's live __TEXT base so SEAL can compute
   the slide. NOTE: the reachable graph on a complex process is dense; the depth-bounded default
   captures the arguments' structures and nearby pointers, not a guaranteed-complete closure —
   for that use `full`, or (future) lazy page-in from a core. **Break at the true
   function entry** (`--skip-prologue false`) or the argument registers are already spilled and
   dead. For a dyld-shared-cache image, set the breakpoint by **address** using
   `seal_validation/snapshot/live_bp.py` (`seal_setbp <Module> <file_addr>`), because breaking
   by a stripped local symbol name hangs on symbolication.
2. **Rebase** (`angrgui/snapshot/rebase.py`): the snapshot holds runtime (ASLR-slid) addresses,
   but SEAL loads the binary at its **file** addresses (cle ignores a load base for Mach-O). So
   the snapshot is slid *down* by the slide — pc, registers, memory-region bases, and in-image
   pointer slots; heap/stack are left alone. `runner._build_state_from_snapshot` does this
   automatically when the snapshot carries `image.slide` (it derives the file range from the
   loaded object). Registers are set at their real width, and the condition flags (CPSR/
   NZCV on arm64, eflags on x86) are restored through the VEX flag thunk — not as a plain
   register, which angr doesn't expose — so a snapshot seeded right before a flag-dependent
   branch takes the correct edge.
3. **Seed**: put the (raw, runtime) snapshot in the scenario's `initial_state`
   (`{kind:"snapshot", pc, regs, mem, symbolic:[{reg|addr, name, size}], image:{slide,...}}`),
   mark the attacker-controlled fields symbolic, add checks, run. `pc` may be *mid-function*.

`concolic_demo/` proves the idea on a tiny self-contained binary; `seal_validation/` applies it
to real CoreGraphics (§8).

---

## 8. Worked case: CVE-2026-86950 on real CoreGraphics

The validation target is Apple CoreGraphics' anti-aliased glyph rasterizer. `aa_lineto`
converts a scaled coordinate float→int with `fcvtzs.2d` (saturates to int64) then **`xtn`**
(truncates to int32 **without** saturation), so a large coordinate wraps to a bad value — the
CVE's root cause. `aa_moveto` uses the safe saturating `fcvtzs w` for contrast.

SEAL finds this **on the real arm64e binary, on this Mac** (no VM): this machine's own macOS
CoreGraphics is the unpatched build and runs natively, so we capture a live snapshot of
`aa_lineto` (`seal_validation/snapshot/*`), rebase it, seed SEAL at the `xtn` with the scaled
coordinate symbolic, and the `narrowing_cast` check fires with a witness whose lane high-bits
are non-zero (the value the truncation corrupts). See `seal_validation/README.md` for the full
story and the bugs fixed en route (arm64e NEON/PAC support, arch-aware args, the `oob_write`
and vector-`narrowing_cast` fixes, the snapshot `pc`-clobber fix, in-SEAL rebasing).

**Scope:** this is validation against an already-published, patched CVE for research. Do not
use SEAL to hunt novel 0-days in live software or build weaponized exploits.

---

## 9. How to extend (quick index)

| Goal | Where | Notes |
|---|---|---|
| Add a **check kind** | `checks.py` | subclass `BaseCheck`, register in the kind map; hook `state.inspect` for per-op checks |
| Add an **MCP tool** | `server.py` | `_mcp_*` handler + `TOOL_DEFS` entry + dispatch; publish to the bus |
| Add an **analysis engine** | `backend.py` | implement `Backend`, emit the neutral contract, `register_backend` |
| Add a missing **NEON op / PAC case** | `angr_arm_patch.py` | add a handler; verify emitted AST shape vs any matcher in `checks.py` |
| Add a **per-scenario field** | `workspace.py` (`SCEN_FIELDS`) + GUI/MCP | else it's dropped on save |
| Add an **expression operator** | `exprlang.py` (+ `pretty.py` for the inverse) | keep signed/unsigned explicit |
| Extend the **agent manual** | `server.py` `GUIDE` | single source of truth; the GUI modal just renders it |
| Support a new **capture environment** | `snapshot/capture.py`, `snapshot/live_bp.py` | keep the emitted shape = `initial_state` |

---

## 10. Common pitfalls (consolidated)

- **Server vs tab lifecycle:** server-side changes need a server restart; `app.js`/`index.html`
  changes need a browser reload (served no-cache). A restart drops SSE connections; the
  stale-id fix lets tabs resume, but the GUI's in-memory state can be stale until a reload.
- **Too little symbolic** → nothing found; **too much symbolic** → path explosion / "every path"
  (use concolic seeding + assumptions).
- **`skip_calls` bypasses models.** Model heavy calls *and* leave skip_calls off, or the run
  won't stay bounded.
- **Concolic address mismatch:** a snapshot's addresses only line up with the binary you ran;
  include `image.slide` so SEAL rebases, and capture at the true entry.
- **Check matchers are AST-shape-coupled** to how ops are lifted (esp. the arm64e NEON patch).
- **`codegen` can drift** from `runner`; it doesn't emit snapshot seeds/models yet.
- **Don't push proprietary inputs.** The binaries (`ipsw/`, the macOS CoreGraphics), IDA
  databases, `node_modules/`, and large captures are git-ignored; they are inputs, not source.

---

## 11. Running & testing

```bash
python run.py --binary <path> --port 8770          # open http://127.0.0.1:8770
python run.py --binary <big.dylib> --target-func 0x186a24e80 --port 8770   # pre-analyze a function
python -m pytest tests/ -q                          # 57 tests
```

Drive it from an agent by pointing an MCP client at `http://127.0.0.1:8770/mcp` and calling
`get_guide` first (the full operating manual). Everything the agent does appears live in the GUI.
