# angr bug hunter

A visual, click-driven front end for [angr](https://angr.io) built for bug
hunting. Instead of writing a throwaway Python script for every function you
want to symbolically execute, you manage everything visually:

- **per-function assumptions** about the initial state — which arguments are
  symbolic, how wide they are, what constraints they must satisfy, whether an
  argument points at a symbolic buffer, whether stdin is symbolic;
- **the paths angr explored**, drawn as a tree and overlaid on the
  control-flow graph, annotated with source lines;
- **checks** you attach to a function and reuse — the built-in one is an
  **integer-overflow** check you add by clicking the arithmetic instruction (or
  the source line) you care about, plus assertions, reachability checks, and
  your own Python predicates.

Everything you set up for a binary is saved next to it (`<binary>.angrgui.json`)
so a project persists across restarts.

![code view with a finding](docs/code_with_hit.png)

## Install & run

```bash
pip install -r requirements.txt          # angr, fastapi, uvicorn
python run.py                            # serve http://127.0.0.1:8000
# or load a binary immediately and open a tab:
python run.py --binary samples/vuln --open
```

Then: **Open binary** → pick a function → set up its initial state on the right
→ add checks → **Run**. Findings show up with a concrete witness (the exact
input values that trigger them).

There is a small deliberately buggy sample included:

```bash
make -C samples          # builds samples/vuln (needs gcc)
```

## The checks

| Check | What it answers | How you add it |
|-------|-----------------|----------------|
| **integer overflow** | can this `add`/`sub`/`mul` wrap (unsigned) or leave the signed range? | click **+ overflow** on an arithmetic instruction, or add one for the whole function |
| **assert** | can this invariant be made *false* on some path? | **+ assert**, write an expression like `total < 0x10000` |
| **reach** | does any path reach this address? | **reach** on any instruction (works for library calls like `abort` too) |
| **avoid** | which paths reach an address you wanted to avoid? | **avoid** on any instruction |
| **custom** | anything else | **+ custom**, write `def check(state, api): ...` |

Every finding carries a **witness**: concrete argument (and stdin) values,
solved so that they actually trigger the condition on that path.

### How overflow detection works (and why it's reliable)

The overflow check does **not** read CPU registers inside an instruction
breakpoint — mid-block register and memory values are not committed under
angr's block-at-a-time VEX engine, so they read stale. Instead it watches the
**result of each VEX arithmetic expression**: for an N-bit `add`/`sub`/`mul`
the resulting claripy AST carries its two operands, and the check asks the
solver whether, under the current path constraints, the widened result can
differ from the N-bit result. If yes, that's a reachable overflow, and the same
query yields the witness. Assertions, reach/avoid and custom checks are
evaluated at **block boundaries**, where register and memory reads *are*
committed, so they're reliable too.

## The expression language

Used for assumptions and assertions (and `api.eval(...)` in custom checks):

```
count < 0x1000              unsigned compare
arg0 s>= 0 && arg0 s< 100   signed compare (prefix s), boolean &&, ||, !
total == count * size       + - * / % & | ^ << >>
u32(rax) != 0               width casts: u8/u16/u32/u64, s8..s64
[rbp - 8]:4 >= len          memory load: [addr]:size (bytes)
ret                         the return-value register
```

Names resolve to: the arguments you named, DWARF locals (when the binary has
debug info), CPU registers, and `ret`.

## Custom checks

```python
def check(state, api):
    # runs at each block boundary (or at one address if you pinned it)
    cond = api.eval("total > 0x7fffffff")
    if api.sat(cond):
        return {"message": "total can exceed INT_MAX",
                "witness": api.witness(cond)}
    return None
```

`api` gives you `eval("expr")`, `sat(cond)`, `witness(cond)`, `reg("rax")`,
`mem(addr, size)`. Custom checks run arbitrary Python in the server process —
only load projects you trust.

## Layout

```
run.py                 launcher
angrgui/
  engine.py            load binary, CFG, DWARF vars, disassembly, source mapping
  runner.py            build initial state from assumptions, explore, collect path tree
  checks.py            the check framework (overflow / assert / reach / avoid / custom)
  exprlang.py          the expression mini-language
  workspace.py         per-binary saved assumptions + checks
  server.py            FastAPI backend
  static/              the single-page UI (index.html, app.js, vendored dagre)
samples/vuln.c         deliberately buggy demo program
tests/                 pytest suite that finds the planted bugs
```

## Notes & limits

- The instruction-level overflow check targets x86/x86-64 (it reads capstone
  mnemonics to skip address arithmetic); the VEX-level detection itself is
  architecture-independent, so function-wide scans still work elsewhere, just
  with more noise.
- Symbolic execution explores loops; a **loop bound** (default 12) keeps a loop
  with a symbolic trip count from unrolling forever. Raise `max steps`,
  `seconds` and `loop bound` for deeper searches.
- angr prints a one-time warning that `unicorn` is unavailable — harmless, it
  just falls back to the standard engine.

## Tests

```bash
pytest -q          # builds samples/vuln, then finds each planted bug
```
