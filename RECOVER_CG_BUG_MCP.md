# Recovering the CoreGraphics bug with SEAL — via MCP

This guide reproduces **CVE-2026-86950** — a 64→32-bit **narrowing truncation** in
Apple CoreGraphics' anti-aliased rasterizer — programmatically, through SEAL's
**MCP** interface. It is the API-driven twin of [`RECOVER_CG_BUG.md`](RECOVER_CG_BUG.md)
(the GUI walkthrough). Both were validated against the real arm64e binary and
produce the same finding, from the function entry, with no pre-seeded state.

---

## 0. Target

| | |
|---|---|
| **Function** | `_aa_lineto` @ `0x186a24e80` (file address) |
| **Binary** | `CoreGraphics` (arm64e, from an iOS dyld_shared_cache) |
| **Check** | `narrowing_cast` (whole function) |
| **Expected finding** | `narrowing_cast @ 0x186a24fd0` — `"narrowing 64->32 bits may lose data at xtn v0.2s, v0.2d"` |

SEAL's portable ARM64 patch (NEON ops incl. `xtn`/`NarrowUn`, plus arm64e **PAC**
hooks so *skip-calls* steps across `blraa`) is applied automatically on a scoped
load — no ARM setup required. You supply your own `CoreGraphics` (it is git-ignored;
Apple-proprietary).

---

## 1. Transport

SEAL speaks MCP (JSON-RPC 2.0) over `POST http://127.0.0.1:8770/mcp`. Start the
server **scoped to the function** (a whole-binary CFG on a 9.5 MB dylib is
impractical):

```bash
python run.py --binary /path/to/CoreGraphics --target-func 0x186a24e80 --port 8770
```

A `tools/call` request looks like:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call",
 "params":{"name":"get_status","arguments":{}}}
```

The result text (usually JSON) is in `result.content[0].text`.

### Tools used here

| tool | purpose |
|------|---------|
| `get_status` | confirm the binary is loaded |
| `get_function` | inspect the function's current setup |
| `add_scenario` / `select_scenario` | start a clean, snapshot-free scenario |
| `configure` | set args, buffers, limits (incl. `skip_calls`) |
| `add_check` | add the `narrowing_cast` detector |
| `run` → `get_run` | explore and read findings (with concrete witnesses) |
| `path_values` | per-line concrete values on a chosen path (optional) |

> **Loading from IDA instead of a path (optional).** If IDA has the binary open:
> `ida_connect {"url":"http://<host>:8744/mcp"}` then `ida_import {}` — SEAL pulls
> IDA's input file (copying it, or streaming the bytes over the MCP) and loads it.

---

## 2. The recovery, step by step

A brand-new scenario starts with **no seeded state** (`initial_state: null`) — this
is the honest, fully-symbolic reproduction.

```jsonc
// 1) clean scenario (no snapshot, no args)
add_scenario     {"addr":"0x186a24e80","name":"recover"}
select_scenario  {"addr":"0x186a24e80","scenario":"recover"}

// 2) three symbolic args; a0 points at a 256-byte symbolic buffer; skip calls on
configure {"addr":"0x186a24e80","patch":{
  "args":[{"name":"a0","mode":"symbolic","size":8},
          {"name":"a1","mode":"symbolic","size":8},
          {"name":"a2","mode":"symbolic","size":8}],
  "buffers":[{"arg":"a0","size":256}],
  "limits":{"steps":400,"active":400,"seconds":180,"loop_bound":12,"skip_calls":true}
}}

// 3) watch for lossy narrowing across the whole function
add_check {"addr":"0x186a24e80","check":{"kind":"narrowing_cast"}}

// 4) explore
run {"addr":"0x186a24e80"}        // -> {"run_id":"..."}
get_run {"run_id":"<id>"}          // poll until status != "running"
```

---

## 3. Copy-paste driver (stdlib only)

```python
import json, time, urllib.request

URL = "http://127.0.0.1:8770/mcp"; _id = [0]
def mcp(name, args, timeout=200):
    _id[0] += 1
    body = json.dumps({"jsonrpc":"2.0","id":_id[0],"method":"tools/call",
                       "params":{"name":name,"arguments":args}}).encode()
    r = json.load(urllib.request.urlopen(
        urllib.request.Request(URL, body, {"Content-Type":"application/json"}), timeout=timeout))
    t = r["result"]["content"][0]["text"]
    try: return json.loads(t)
    except Exception: return t

A = "0x186a24e80"
assert mcp("get_status", {}).get("loaded"), "load CoreGraphics first (--binary ... --target-func 0x186a24e80)"

mcp("add_scenario",    {"addr": A, "name": "recover"})
mcp("select_scenario", {"addr": A, "scenario": "recover"})
mcp("configure", {"addr": A, "patch": {
    "args": [{"name": n, "mode": "symbolic", "size": 8} for n in ("a0","a1","a2")],
    "buffers": [{"arg": "a0", "size": 256}],
    "limits": {"steps":400,"active":400,"seconds":180,"loop_bound":12,"skip_calls":True},
}})
mcp("add_check", {"addr": A, "check": {"kind": "narrowing_cast"}})

rid = mcp("run", {"addr": A})["run_id"]
while True:
    g = mcp("get_run", {"run_id": rid})
    if g.get("status") not in ("pending","running"): break
    time.sleep(1)

print("summary:", g["summary"])
for h in g["findings"]:
    if h["addr"] == 0x186a24fd0:
        print("FOUND", hex(h["addr"]), h["message"])
        print("witness:", json.dumps(h["witness"]))
```

---

## 4. Expected output

```
summary: {"status":"done","steps":13,"active":0,"deadended":5,"errored":0,
          "unconstrained":0,"found":0,"hits":7,"nodes":9,"elapsed":...}
FOUND 0x186a24fd0 narrowing 64->32 bits may lose data at xtn v0.2s, v0.2d
witness: {"a1":{"hex":"0x0",...},"a2":{"hex":"0x0",...},"a0_buf":{"hex":"0x...","bits":2048}}
```

The finding record (`get_run().findings[]`) carries everything you need:

```jsonc
{
  "kind": "narrowing_cast",
  "addr": 6553751504,                 // 0x186a24fd0
  "message": "narrowing 64->32 bits may lose data at xtn v0.2s, v0.2d",
  "witness": { "a1": {...}, "a2": {...}, "a0_buf": {"hex":"0x...","bits":2048} },
  "extra": { "from_bits": 64, "to_bits": 32, "mnemonic": "xtn",
             "path": ["0x186a24e80","0x186a24e84","0x186a24fbc"], "node": 1 }
}
```

- **`unconstrained: 0`** confirms the arm64e PAC hooks are working — no path was
  lost to an unresolved authenticated branch.
- **`a0_buf`** is the concrete 256-byte input that drives the truncating `xtn`.
- **`extra.path`** / **`extra.node`** identify the path; feed `node` to
  `path_values {"run_id":"<id>","node":<n>}` for per-instruction concrete values.

---

## 5. Notes

- **No snapshot required.** A fresh scenario's `initial_state` is `null`; the finding
  above is purely symbolic from the entry. (`configure` cannot *clear* an existing
  `initial_state` — a `null` in the patch is ignored — so start a **new scenario**
  rather than trying to blank out a seeded one.)
- **Optional concolic seeding.** To follow the exact path of a real glyph render, set
  `initial_state` to a live snapshot captured at the entry — see **PART 7** of the
  in-app guide (`get_guide {}`) and `seal_validation/snapshot/`. It narrows paths but
  is not needed to surface the `xtn`.
- **`run` uses the active scenario's saved setup** — it takes only `addr`. Change
  inputs with `configure` / `add_check` / `select_scenario`, not by passing them to
  `run`.
- The full in-app guide (check kinds, concolic seeding, limits, models) is available
  any time via `get_guide {}`.

---

*Research use only. This reproduces a known, disclosed issue on a binary you supply,
for defensive and educational analysis.*
