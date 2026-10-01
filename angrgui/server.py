"""
FastAPI backend for the angr bug-hunting GUI.

Endpoints (all JSON unless noted):

  GET  /                          -> the single-page UI
  GET  /api/state                 -> what's currently loaded
  POST /api/load                  {"path": "..."}      load a binary
  GET  /api/browse?path=...       -> directory listing for the file picker
  GET  /api/functions             -> function list
  GET  /api/function/{addr}       -> disassembly + source + dwarf vars + saved config
  GET  /api/cfg/{addr}            -> control-flow graph of a function
  PUT  /api/function/{addr}/config  save assumptions + checks for a function
  POST /api/run                   {"func_addr":..., ...runspec...}  start a run
  GET  /api/run/{run_id}          -> live snapshot (progress, tree, hits)
  POST /api/run/{run_id}/cancel   -> cancel
  GET  /api/custom-template       -> starter code for a custom check
  POST /api/script                {...runspec...}  -> equivalent standalone angr script
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
import logging
import urllib.parse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .engine import Binary
from .runner import Run
from .workspace import Workspace
from .checks import CUSTOM_TEMPLATE
from .codegen import generate_script
from .idamcp import IdaSession, MCPError, DEFAULT_URL

log = logging.getLogger("angrgui.server")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")

app = FastAPI(title="angr bug-hunting GUI")


class _Session:
    """Holds the one loaded binary, its workspace, and active runs."""
    def __init__(self):
        self.binary: Binary | None = None
        self.workspace: Workspace | None = None
        self.runs: dict[str, Run] = {}
        self.last_run: dict[int, str] = {}       # func_addr -> most recent run_id
        self.load_status = {"loading": False, "message": "", "error": None}
        self.ida = None                     # optional angrgui.idamcp.IdaSession


S = _Session()


# --------------------------------------------------------------------------- event bus
class EventBus:
    """A tiny in-process pub/sub for the live activity feed. Actions (from the GUI or
    from an agent over MCP) publish here; the GUI subscribes over SSE and both see the
    same events, so the human watches whatever an agent does."""

    def __init__(self, keep=500):
        self._events: list[dict] = []
        self._seq = 0
        self._keep = keep
        self._cv = threading.Condition()

    def publish(self, kind: str, message: str = "", **data) -> dict:
        with self._cv:
            self._seq += 1
            ev = {"seq": self._seq, "type": kind, "ts": round(time.time(), 3),
                  "message": message, **data}
            self._events.append(ev)
            del self._events[:-self._keep]
            self._cv.notify_all()
        return ev

    def stream(self, after: int):
        while True:
            with self._cv:
                batch = [e for e in self._events if e["seq"] > after]
                if not batch:
                    self._cv.wait(timeout=15)
                    batch = [e for e in self._events if e["seq"] > after]
                if batch:
                    after = batch[-1]["seq"]
            if batch:
                for e in batch:
                    yield e
            else:
                yield None      # heartbeat so the SSE connection stays alive


BUS = EventBus()


def _fname(addr) -> str:
    """A display name for a function address (IDA name if known, else angr's)."""
    if S.binary is None:
        return hex(addr)
    if S.ida is not None and S.ida._names and addr in S.ida._names:
        return S.ida._names[addr]
    f = S.binary.get_function(addr)
    return f.name if f is not None else hex(addr)


# --------------------------------------------------------------------------- models
class LoadReq(BaseModel):
    path: str


class RunReq(BaseModel):
    func_addr: int
    args: list = []
    buffers: list = []
    assumptions: list = []
    stdin: dict | None = None
    files: list = []
    checks: list = []
    limits: dict = {}


class ConfigReq(BaseModel):
    # new (scenarios) shape
    checks: list = []
    scenarios: list | None = None
    active: int = 0
    # legacy flat initial state (older clients / direct callers)
    args: list = []
    buffers: list = []
    assumptions: list = []
    stdin: dict | None = None
    files: list = []
    limits: dict = {}

    def to_struct(self) -> dict:
        d = self.model_dump()
        if d.get("scenarios"):
            return {"checks": d["checks"], "scenarios": d["scenarios"], "active": d.get("active", 0)}
        sc = {"name": "Default"}
        for k in ("args", "buffers", "assumptions", "stdin", "files", "limits"):
            sc[k] = d[k]
        return {"checks": d["checks"], "scenarios": [sc], "active": 0}


# --------------------------------------------------------------------------- helpers
def _need_binary() -> Binary:
    if S.binary is None:
        raise HTTPException(400, "no binary loaded")
    return S.binary


# --------------------------------------------------------------------------- routes
@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(STATIC, "index.html")) as fh:
        return fh.read()


@app.get("/app.js")
def app_js():
    from fastapi.responses import Response
    with open(os.path.join(STATIC, "app.js")) as fh:
        return Response(fh.read(), media_type="application/javascript")


@app.get("/api/state")
def state():
    out = {"loaded": S.binary is not None, "load_status": S.load_status}
    if S.binary is not None:
        out["binary"] = S.binary.info()
    return out


@app.get("/api/browse")
def browse(path: str = ""):
    base = path or os.getcwd()
    base = os.path.abspath(os.path.expanduser(base))
    if not os.path.isdir(base):
        base = os.path.dirname(base) or "/"
    try:
        entries = []
        for name in sorted(os.listdir(base)):
            full = os.path.join(base, name)
            try:
                is_dir = os.path.isdir(full)
                size = os.path.getsize(full) if not is_dir else 0
                is_elf = False
                if not is_dir and size > 4:
                    with open(full, "rb") as fh:
                        is_elf = fh.read(4) == b"\x7fELF"
                entries.append({"name": name, "path": full, "dir": is_dir,
                                "size": size, "elf": is_elf})
            except OSError:
                pass
        return {"cwd": base, "parent": os.path.dirname(base), "entries": entries}
    except OSError as e:
        raise HTTPException(400, str(e))


@app.post("/api/load")
def load(req: LoadReq):
    path = os.path.abspath(os.path.expanduser(req.path))
    if not os.path.isfile(path):
        raise HTTPException(404, f"not a file: {path}")
    S.load_status = {"loading": True, "message": "starting", "error": None}

    def progress(msg):
        S.load_status["message"] = msg

    try:
        S.binary = Binary(path, progress=progress)
        S.workspace = Workspace(path)
        S.runs.clear()
        S.load_status = {"loading": False, "message": "ready", "error": None}
        BUS.publish("load", f"loaded {os.path.basename(path)}", path=path,
                    functions=len(S.binary.user_functions()))
    except Exception as e:
        S.binary = None
        S.load_status = {"loading": False, "message": "", "error": f"{type(e).__name__}: {e}"}
        raise HTTPException(500, S.load_status["error"])
    return {"binary": S.binary.info()}


@app.get("/api/functions")
def functions():
    b = _need_binary()
    fns = b.function_list()
    saved = S.workspace.all()["functions"] if S.workspace else {}
    for f in fns:
        raw = saved.get(str(f["addr"]))
        cfg = Workspace._migrate(raw) if raw else None
        f["configured"] = bool(cfg and (cfg.get("checks") or
                                        any(s.get("assumptions") for s in cfg.get("scenarios", []))))
        f["check_count"] = len(cfg.get("checks", [])) if cfg else 0
        f["scenario_count"] = len(cfg.get("scenarios", [])) if cfg else 1
    _apply_ida_names(fns)
    return {"functions": fns}


_GENERIC_IDA = ("sub_", "nullsub_", "unknown_", "unknown", "loc_", "off_", "def_", "j_", "nullsub")


def _apply_ida_names(fns):
    """Overlay IDA's *real* function names (when connected) onto the angr list.

    IDA auto-names unknown functions `sub_<ADDR>` just like angr, so those carry
    no information (and differ only in hex case); only surface a name once IDA —
    or the user, by renaming in IDA — actually knows what the function is.
    """
    if S.ida is None or S.ida._names is None:
        return
    for f in fns:
        nm = S.ida._names.get(f["addr"])
        if nm and not nm.lower().startswith(_GENERIC_IDA):
            f["ida_name"] = nm
            f["named"] = True


@app.get("/api/function/{addr}")
def function(addr: int):
    b = _need_binary()
    fn = b.get_function(addr)
    if fn is None:
        raise HTTPException(404, "no such function")
    disasm = b.disassemble(addr)
    dwarf = [v.to_json(b.word_bytes) for v in b.dwarf_vars(addr)]
    cfg = S.workspace.get_function(addr) if S.workspace else Workspace._default_func()
    # seed default args from DWARF / calling convention into the active scenario
    sc = cfg["scenarios"][cfg["active"]]
    if not sc.get("args"):
        for a in [f for f in b.function_list() if f["addr"] == addr][0]["args"]:
            sc.setdefault("args", []).append({
                "name": a["name"], "mode": "symbolic",
                "size": a["size"] or b.word_bytes, "signed": a.get("signed", True),
            })
    return {"disasm": disasm, "dwarf": dwarf, "config": cfg,
            "return_heads": [hex(h) for h in b.return_block_heads(addr)],
            "last_run": S.last_run.get(addr)}


@app.get("/api/cfg/{addr}")
def cfg(addr: int):
    b = _need_binary()
    if b.get_function(addr) is None:
        raise HTTPException(404, "no such function")
    return b.cfg_graph(addr)


@app.put("/api/function/{addr}/config")
def save_config(addr: int, req: ConfigReq):
    _need_binary()
    if S.workspace is None:
        raise HTTPException(400, "no workspace")
    _store_config(addr, req.to_struct())
    return {"ok": True}


def _store_config(addr: int, cfg: dict, source: str = "gui"):
    cfg = Workspace._migrate(cfg)
    prev = S.workspace.get_function(addr)
    S.workspace.set_function(addr, cfg)
    # a concise activity line describing what changed (for the active scenario)
    sc = cfg["scenarios"][cfg["active"]]
    na, nc = len(sc.get("assumptions", [])), len(cfg.get("checks", []))
    if source != "gui":
        BUS.publish("config", f"{source} configured {_fname(addr)}: "
                    f"{na} assumption(s), {nc} check(s)", func=addr,
                    assumptions=sc.get("assumptions", []),
                    checks=[c.get("name") or c.get("kind") for c in cfg.get("checks", [])])


@app.post("/api/run")
def run(req: RunReq):
    return {"run_id": _start_run(req.model_dump())}


def _start_run(spec: dict, source: str = "gui") -> str:
    b = _need_binary()
    if b.get_function(spec["func_addr"]) is None:
        raise HTTPException(404, "no such function")
    run_id = uuid.uuid4().hex[:12]

    def on_event(kind, **data):
        msg = {"finding": lambda: f"finding: {data.get('check_kind')} at {data.get('addr', 0):#x} — {data.get('detail', '')}",
               "run_status": lambda: f"run of {_fname(spec['func_addr'])} {data.get('status')} "
                                     f"({data.get('hits', 0)} finding(s))"}.get(kind, lambda: kind)()
        BUS.publish(kind, msg, run_id=run_id, **data)

    r = Run(b, spec, on_event=on_event)
    S.runs[run_id] = r
    S.last_run[spec["func_addr"]] = run_id
    r.start()
    BUS.publish("run", f"{source} started a run of {_fname(spec['func_addr'])}",
                func=spec["func_addr"], run_id=run_id,
                checks=[c.get("name") or c.get("kind") for c in spec.get("checks", []) if c.get("enabled", True)])
    return run_id


@app.get("/api/events")
def events(request: Request, after: int | None = None):
    # A fresh page load should NOT replay history (old runs would yank the UI around);
    # start from "now". EventSource auto-reconnect sends Last-Event-ID, which we resume from.
    resume = request.headers.get("last-event-id")
    start = int(resume) if resume and resume.isdigit() else (after if after is not None else BUS._seq)

    def gen():
        yield "retry: 2000\n\n"
        for e in BUS.stream(start):
            yield ": ping\n\n" if e is None else f"id: {e['seq']}\ndata: {json.dumps(e)}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/api/run/{run_id}")
def run_status(run_id: str):
    r = S.runs.get(run_id)
    if r is None:
        raise HTTPException(404, "no such run")
    return r.snapshot()


@app.post("/api/run/{run_id}/cancel")
def run_cancel(run_id: str):
    r = S.runs.get(run_id)
    if r is None:
        raise HTTPException(404, "no such run")
    r.cancel()
    return {"ok": True}


# --------------------------------------------------------------------------- IDA MCP
class IdaConnectReq(BaseModel):
    url: str = DEFAULT_URL
    host_header: str | None = None      # override Host (for a port-forwarded ida-pro-mcp)


@app.get("/api/ida/status")
def ida_status():
    return S.ida.status() if S.ida is not None else {"connected": False}


@app.post("/api/ida/connect")
def ida_connect(req: IdaConnectReq):
    b = _need_binary()
    # ida-pro-mcp rejects a non-loopback Host (DNS-rebind guard). When the URL is a
    # remote/forwarded address, default the Host header to loopback so it accepts us.
    host_header = req.host_header
    if host_header is None:
        try:
            h = urllib.parse.urlparse(req.url).hostname or ""
            if h not in ("localhost", "127.0.0.1", "::1", ""):
                host_header = "127.0.0.1"
        except Exception:
            pass
    sess = IdaSession(req.url, host_header=host_header)
    sess.client.timeout = 120           # open/analysis of a real binary can be slow
    try:
        st = sess.connect(b.path)       # official: opens by path; community: uses the open GUI
        sess.function_names()           # pull names up front so the list can show them
    except MCPError as e:
        raise HTTPException(502, str(e))
    S.ida = sess
    st = sess.status()
    BUS.publish("ida", f"connected to IDA ({st.get('server')}, {st.get('name_count')} names)", **st)
    return st


@app.post("/api/ida/disconnect")
def ida_disconnect():
    S.ida = None
    return {"connected": False}


@app.get("/api/ida/decompile/{addr}")
def ida_decompile(addr: int, force: bool = False):
    if S.ida is None:
        raise HTTPException(400, "not connected to IDA")
    try:
        return S.ida.decompile(addr, force=force)
    except MCPError as e:
        raise HTTPException(502, str(e))


@app.post("/api/ida/refresh")
def ida_refresh():
    if S.ida is None:
        raise HTTPException(400, "not connected to IDA")
    try:
        return S.ida.refresh()
    except MCPError as e:
        raise HTTPException(502, str(e))


@app.post("/api/script")
def script(req: RunReq):
    b = _need_binary()
    if b.get_function(req.func_addr) is None:
        raise HTTPException(404, "no such function")
    return {"code": generate_script(b, req.model_dump())}


# --------------------------------------------------------------------------- MCP server
# Expose the tool as an MCP server so an agent can drive it (list functions, set
# assumptions/checks, run, read results) while a human watches the GUI: agent
# actions go through the same session S and publish to the same event bus, so the
# GUI reflects them live. Minimal Streamable-HTTP MCP, stdlib JSON only.
MCP_PROTOCOL = "2025-06-18"


def _addr(x) -> int:
    if isinstance(x, int):
        return x
    s = str(x).strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def _mcp_functions(query=None, limit: int = 200):
    fns = functions()["functions"]
    if query:
        q = str(query).lower()
        fns = [f for f in fns if q in f["name"].lower()
               or q in (f.get("ida_name") or "").lower() or q in hex(f["addr"])]
    return [{"addr": hex(f["addr"]), "name": f.get("ida_name") or f["name"],
             "blocks": f["block_count"], "args": len(f["args"]),
             "checks": f.get("check_count", 0), "has_source": f["has_source"]}
            for f in fns[:int(limit)]]


def _mcp_get_function(addr):
    a = _addr(addr)
    d = function(a)
    # agents see the flattened active scenario (initial state + shared checks),
    # plus the list of scenario names and which one is active.
    return {"addr": hex(a), "name": d["disasm"]["name"],
            "config": Workspace.flatten(d["config"]),
            "has_source": bool(d["disasm"].get("source")),
            "return_heads": d["return_heads"]}


def _mcp_disassemble(addr):
    b = _need_binary()
    d = b.disassemble(_addr(addr))
    lines = [f"{i['addr']:#x}  {i['text']}" + (f"    ; {i['src_file']}:{i['src_line']}" if i.get('src_line') else "")
             for i in d["instructions"]]
    return {"addr": hex(_addr(addr)), "name": d["name"], "text": "\n".join(lines)}


def _coerce_check(c, a):
    c = dict(c)
    if c.get("addr") is not None:                  # agents pass "0x..." strings
        c["addr"] = _addr(c["addr"])
    c.setdefault("id", uuid.uuid4().hex[:6])
    c.setdefault("enabled", True)
    c["func_addr"] = a
    return c


def _mcp_configure(addr, patch: dict):
    """Patch the ACTIVE scenario's initial state; checks are shared across scenarios."""
    _need_binary()
    a = _addr(addr)
    cfg = S.workspace.get_function(a)                   # structured
    sc = cfg["scenarios"][cfg["active"]]
    for k in ("args", "buffers", "assumptions", "stdin", "files", "limits"):
        if k in patch and patch[k] is not None:
            sc[k] = {**sc.get("limits", {}), **patch[k]} if k == "limits" else patch[k]
    if patch.get("checks") is not None:
        cfg["checks"] = [_coerce_check(c, a) for c in patch["checks"]]
    _store_config(a, cfg, source="agent")
    return _mcp_get_function(a)["config"]


def _mcp_add(addr, *, assumption=None, check=None):
    _need_binary()
    a = _addr(addr)
    cfg = S.workspace.get_function(a)
    sc = cfg["scenarios"][cfg["active"]]
    if assumption is not None:
        sc["assumptions"] = list(sc.get("assumptions", [])) + [assumption]
    if check is not None:
        cfg["checks"] = list(cfg.get("checks", [])) + [_coerce_check(check, a)]
    _store_config(a, cfg, source="agent")
    return _mcp_get_function(a)["config"]


def _mcp_run(addr):
    a = _addr(addr)
    flat = Workspace.flatten(S.workspace.get_function(a))   # the active scenario
    spec = {"func_addr": a, "args": flat.get("args") or [], "buffers": flat.get("buffers") or [],
            "assumptions": [x for x in (flat.get("assumptions") or []) if x.strip()],
            "stdin": flat.get("stdin"), "files": flat.get("files") or [], "limits": flat.get("limits") or {},
            "checks": [c for c in flat.get("checks", []) if c.get("enabled", True)]}
    if not spec["checks"]:
        raise HTTPException(400, "no enabled checks on this function; add one first")
    return {"run_id": _start_run(spec, source="agent")}


def _mcp_get_run(run_id):
    r = S.runs.get(run_id)
    if r is None:
        raise HTTPException(404, "no such run")
    snap = r.snapshot()
    tree = [{"id": n["id"], "parent": n["parent"], "cond": n["cond"], "kind": n["kind"],
             "end": (n["end"] or {}).get("reason"), "hits": n["hits"]} for n in snap["tree"]]
    return {"status": snap["status"], "error": snap["error"], "summary": snap["summary"],
            "findings": snap["hits"], "paths": tree}


def _mcp_decompile(addr):
    if S.ida is None:
        raise HTTPException(400, "not connected to IDA (connect via the GUI or ida.connect)")
    return S.ida.decompile(_addr(addr))


_A = {"addr": {"type": "string", "description": "function address, e.g. \"0x400650\", or name"}}
TOOL_DEFS = [
    {"name": "get_status", "description": "What binary is loaded and whether IDA is connected.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "list_functions", "description": "List functions (optionally filtered by name/address substring).",
     "inputSchema": {"type": "object", "properties": {
         "query": {"type": "string"}, "limit": {"type": "integer", "default": 200}}}},
    {"name": "get_function", "description": "A function's saved setup (initial state, assumptions, checks, limits).",
     "inputSchema": {"type": "object", "properties": _A, "required": ["addr"]}},
    {"name": "disassemble", "description": "Disassembly text of a function.",
     "inputSchema": {"type": "object", "properties": _A, "required": ["addr"]}},
    {"name": "decompile", "description": "IDA Hex-Rays pseudocode of a function (requires IDA connected).",
     "inputSchema": {"type": "object", "properties": _A, "required": ["addr"]}},
    {"name": "configure", "description": "Set parts of a function's setup. patch may contain any of: "
     "args, buffers, assumptions (list of expression strings), stdin, checks, limits "
     "(e.g. {\"steps\":80,\"seconds\":30,\"skip_calls\":true}). Replaces the given keys.",
     "inputSchema": {"type": "object", "properties": {**_A, "patch": {"type": "object"}}, "required": ["addr", "patch"]}},
    {"name": "add_assumption", "description": "Append one assumption (an expression that must hold at entry, "
     "e.g. \"a1 & 0xff == 0x5a\"). Names: the argument names, a1../arg0.. (parameters), registers, ret.",
     "inputSchema": {"type": "object", "properties": {**_A, "expr": {"type": "string"}}, "required": ["addr", "expr"]}},
    {"name": "add_check", "description": "Append one check. check is an object like "
     "{\"kind\":\"int_overflow\",\"addr\":\"0x..\",\"signed\":\"either\"} or "
     "{\"kind\":\"assert\",\"expr\":\"total < 0x1000\",\"at_return\":true} or "
     "{\"kind\":\"reach\",\"addr\":\"0x..\"}.",
     "inputSchema": {"type": "object", "properties": {**_A, "check": {"type": "object"}}, "required": ["addr", "check"]}},
    {"name": "run", "description": "Run the enabled checks on a function using its saved setup. Returns a run_id.",
     "inputSchema": {"type": "object", "properties": _A, "required": ["addr"]}},
    {"name": "get_run", "description": "Results of a run: status, findings (with concrete witnesses), and the path tree.",
     "inputSchema": {"type": "object", "properties": {"run_id": {"type": "string"}}, "required": ["run_id"]}},
]

# documented check kinds (what add_check accepts); kept in sync with checks.py
CHECK_KINDS = [
    {"kind": "reach", "summary": "record any path that reaches an address",
     "fields": {"addr": "0x.. (required)"}},
    {"kind": "avoid", "summary": "record + flag paths that reach an address (a 'bad' location)",
     "fields": {"addr": "0x.. (required)"}},
    {"kind": "assert", "summary": "a boolean that must always hold; a finding is any input that breaks it",
     "fields": {"expr": "expression (required)", "addr": "0x.. (optional point; omit for return)",
                "at_return": "true to check at function return"}},
    {"kind": "int_overflow", "summary": "integer add/sub/mul whose result overflows (wraps)",
     "fields": {"addr": "0x.. (optional; omit to scan every add/sub/mul)",
                "signed": "either | unsigned | signed"}},
    {"kind": "narrowing_cast", "summary": "a value truncated to a smaller int type (int->short, ->char, 64->32) where the dropped high bits can be non-zero",
     "fields": {"addr": "0x.. (optional; omit to scan the whole function)"}},
    {"kind": "float_anomaly", "summary": "a floating-point add/sub/mul/div whose result can be NaN or +/-Inf (from special or extreme inputs)",
     "fields": {"addr": "0x.. (optional; omit to scan the whole function)"}},
    {"kind": "oob_write", "summary": "a memory write whose address can fall outside a declared buffer [base, base+size)",
     "fields": {"base": "expression for the buffer start, e.g. a1 or rsp-0x40 (required)",
                "size": "buffer size in bytes (required)", "addr": "0x.. (optional single write instruction)"}},
    {"kind": "custom", "summary": "your own Python predicate run at a point (advanced)",
     "fields": {"code": "python (required)", "addr": "0x.. (optional point)"}},
]

_MCP_TOOLS = {
    "get_status": lambda a: _mcp_status_payload(),
    "list_functions": lambda a: _mcp_functions(a.get("query"), a.get("limit", 200)),
    "get_function": lambda a: _mcp_get_function(a["addr"]),
    "disassemble": lambda a: _mcp_disassemble(a["addr"]),
    "decompile": lambda a: _mcp_decompile(a["addr"]),
    "configure": lambda a: _mcp_configure(a["addr"], a["patch"]),
    "add_assumption": lambda a: _mcp_add(a["addr"], assumption=a["expr"]),
    "add_check": lambda a: _mcp_add(a["addr"], check=a["check"]),
    "run": lambda a: _mcp_run(a["addr"]),
    "get_run": lambda a: _mcp_get_run(a["run_id"]),
}


def _mcp_status_payload():
    out = {"loaded": S.binary is not None}
    if S.binary:
        out["binary"] = S.binary.info()
    out["ida"] = S.ida.status() if S.ida is not None else {"connected": False}
    return out


def _handle_mcp(msg: dict):
    method, rid, params = msg.get("method"), msg.get("id"), (msg.get("params") or {})
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": MCP_PROTOCOL, "capabilities": {"tools": {}},
            "serverInfo": {"name": "angr-bug-hunter", "version": "0.1"},
            "instructions": "Drive angr symbolic execution: list_functions, get_function, "
                            "add_assumption/add_check/configure, run, get_run. A human watches "
                            "the same session in the GUI."}}
    if method and method.startswith("notifications/"):
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOL_DEFS}}
    if method == "tools/call":
        name, args = params.get("name"), (params.get("arguments") or {})
        fn = _MCP_TOOLS.get(name)
        if fn is None:
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": f"unknown tool {name}"}], "isError": True}}
        try:
            result = fn(args)
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]}}
        except HTTPException as e:
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": str(e.detail)}], "isError": True}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}], "isError": True}}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"unknown method {method}"}}


@app.post("/mcp")
async def mcp_endpoint(request: Request):
    body = await request.json()
    resp = _handle_mcp(body)
    if resp is None:
        return Response(status_code=202)
    if "text/event-stream" in (request.headers.get("accept") or ""):
        return Response(f"event: message\ndata: {json.dumps(resp)}\n\n", media_type="text/event-stream")
    return JSONResponse(resp)


@app.get("/api/custom-template")
def custom_template():
    from .checks import CUSTOM_TEMPLATE
    return {"template": CUSTOM_TEMPLATE}


@app.get("/api/agent-docs")
def agent_docs(request: Request):
    """Everything an agent needs to drive this tool over MCP: the live tool list,
    the connection details, the expression language and the available checks."""
    base = str(request.base_url).rstrip("/")
    return {
        "server_name": "angr-bug-hunter",
        "protocol": MCP_PROTOCOL,
        "mcp_url": base + "/mcp",
        "transport": "MCP Streamable HTTP (POST JSON-RPC; responses are JSON or SSE)",
        "tools": TOOL_DEFS,
        "check_kinds": CHECK_KINDS,
    }


if os.path.isdir(os.path.join(STATIC, "vendor")):
    app.mount("/vendor", StaticFiles(directory=os.path.join(STATIC, "vendor")), name="vendor")
