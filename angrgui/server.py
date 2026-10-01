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
    if s.lower().startswith("0x"):
        return int(s, 16)
    try:
        return int(s)
    except ValueError:
        pass
    # resolve a function name (angr's or IDA's), as the tool schemas promise
    if S.binary is not None:
        for f in functions()["functions"]:
            if s in (f.get("name"), f.get("ida_name")):
                return f["addr"]
    raise HTTPException(400, f"not an address or known function name: {s!r}")


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
    for k in ("args", "buffers", "assumptions", "stdin", "files", "limits", "models"):
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


def _mcp_add_model(addr, model):
    """Append a call model (hook) to the active scenario."""
    _need_binary()
    a = _addr(addr)
    cfg = S.workspace.get_function(a)
    sc = cfg["scenarios"][cfg["active"]]
    sc["models"] = list(sc.get("models", [])) + [dict(model)]
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


# -- scenarios: a function's several initial-state setups (checks are shared) ---------
def _scenario_index(cfg, scenario):
    """Resolve a scenario given as an index (int / numeric string) or a name."""
    scs = cfg["scenarios"]
    if scenario is None:
        return cfg["active"]
    try:
        i = int(scenario)
        if 0 <= i < len(scs):
            return i
    except (TypeError, ValueError):
        pass
    for i, s in enumerate(scs):
        if s.get("name") == scenario:
            return i
    raise HTTPException(404, f"no scenario {scenario!r}; have {[s.get('name') for s in scs]}")


def _mcp_add_scenario(addr, name=None, duplicate=False):
    _need_binary()
    a = _addr(addr)
    cfg = S.workspace.get_function(a)
    sc = Workspace._default_scenario(name or f"Scenario {len(cfg['scenarios']) + 1}")
    if duplicate:
        cur = cfg["scenarios"][cfg["active"]]
        for k in ("args", "buffers", "assumptions", "stdin", "files", "limits"):
            sc[k] = json.loads(json.dumps(cur.get(k)))
    cfg["scenarios"].append(sc)
    cfg["active"] = len(cfg["scenarios"]) - 1        # the new scenario becomes active
    _store_config(a, cfg, source="agent")
    return _mcp_get_function(a)["config"]


def _mcp_select_scenario(addr, scenario):
    _need_binary()
    a = _addr(addr)
    cfg = S.workspace.get_function(a)
    cfg["active"] = _scenario_index(cfg, scenario)
    _store_config(a, cfg, source="agent")
    return _mcp_get_function(a)["config"]


def _mcp_delete_scenario(addr, scenario):
    _need_binary()
    a = _addr(addr)
    cfg = S.workspace.get_function(a)
    if len(cfg["scenarios"]) <= 1:
        raise HTTPException(400, "a function needs at least one scenario")
    cfg["scenarios"].pop(_scenario_index(cfg, scenario))
    cfg["active"] = min(cfg["active"], len(cfg["scenarios"]) - 1)
    _store_config(a, cfg, source="agent")
    return _mcp_get_function(a)["config"]


def _mcp_rename_scenario(addr, scenario, name):
    _need_binary()
    a = _addr(addr)
    cfg = S.workspace.get_function(a)
    cfg["scenarios"][_scenario_index(cfg, scenario)]["name"] = name
    _store_config(a, cfg, source="agent")
    return _mcp_get_function(a)["config"]


def _mcp_load_binary(path):
    load(LoadReq(path=path))                          # synchronous: analyses before returning
    return _mcp_status_payload()


def _mcp_list_files(directory=None):
    return browse(directory or "")


def _mcp_cancel_run(run_id):
    return run_cancel(run_id)


def _mcp_ida_connect(url=None, host_header=None):
    return ida_connect(IdaConnectReq(url=url or DEFAULT_URL, host_header=host_header))


def _mcp_ida_disconnect():
    return ida_disconnect()


def _mcp_ida_refresh():
    return ida_refresh()


def _mcp_remove_assumption(addr, index=None, expr=None):
    _need_binary()
    a = _addr(addr)
    cfg = S.workspace.get_function(a)
    sc = cfg["scenarios"][cfg["active"]]
    asm = sc.get("assumptions", [])
    if expr is not None:
        sc["assumptions"] = [x for x in asm if x != expr]
    elif index is not None and 0 <= int(index) < len(asm):
        asm.pop(int(index))
    else:
        raise HTTPException(400, "give an assumption index or exact expr to remove")
    _store_config(a, cfg, source="agent")
    return _mcp_get_function(a)["config"]


def _mcp_remove_check(addr, check):
    _need_binary()
    a = _addr(addr)
    cfg = S.workspace.get_function(a)
    checks = cfg.get("checks", [])
    idx = None
    try:                                              # by index
        i = int(check)
        if 0 <= i < len(checks):
            idx = i
    except (TypeError, ValueError):
        pass
    if idx is None:                                   # by id or name
        idx = next((i for i, c in enumerate(checks) if c.get("id") == check or c.get("name") == check), None)
    if idx is None:
        raise HTTPException(404, f"no check {check!r}; have {[c.get('name') or c.get('id') for c in checks]}")
    checks.pop(idx)
    _store_config(a, cfg, source="agent")
    return _mcp_get_function(a)["config"]


def _mcp_export_scenario(addr):
    """The active scenario's setup, shared checks, and latest run — the same bundle
    the GUI's Export produces, for the agent to keep or report."""
    _need_binary()
    a = _addr(addr)
    flat = Workspace.flatten(S.workspace.get_function(a))
    fn = next((f for f in S.binary.function_list() if f["addr"] == a), None)
    run = None
    rid = S.last_run.get(a)
    if rid and rid in S.runs:
        snap = S.runs[rid].snapshot()
        run = {"id": rid, "status": snap["status"], "findings": snap["hits"],
               "paths": [{"id": n["id"], "parent": n["parent"], "cond": n["cond"],
                          "end": (n["end"] or {}).get("reason"), "hits": n["hits"]} for n in snap["tree"]]}
    return {
        "binary": S.binary.info(),
        "function": {"addr": hex(a), "name": fn and (fn.get("ida_name") or fn["name"])},
        "scenario_name": flat["scenarios"][flat["active"]],
        "scenario": {k: flat.get(k) for k in ("args", "buffers", "assumptions", "stdin", "files", "limits")},
        "checks": flat.get("checks", []),
        "run": run,
    }


def _mcp_guide():
    return {"guide": GUIDE}


GUIDE = r"""# angr bug hunter — guide for agents

## What this tool does (plain terms)
It runs ONE function with its inputs left UNKNOWN ("symbolic") and asks a solver
questions like: "can execution reach address X?", "can this add overflow?", "can
this write land outside a buffer?". For every YES it returns a CONCRETE set of
inputs (a "witness") that makes it happen. You do not write exploits or guess
inputs — you declare what is unknown, declare what to look for, then read back the
exact inputs the solver found. A human watches the same session live in a GUI.

## The loop (do these in order)
1. get_status                              — is a binary loaded? is IDA connected?
   (load_binary(path) yourself if needed; list_files(dir) to find a path.)
2. list_functions(query)                   — pick a function; note its "addr".
3. get_function(addr)                       — see its setup. Arguments are symbolic by default.
4. decompile(addr) or disassemble(addr)     — read the code to decide what to check.
5. configure / add_assumption / add_check   — set up inputs and what to look for.
6. run(addr) -> {"run_id": ...}             — starts exploring in the background.
7. get_run(run_id)                          — POLL until status is "done" (or "error"); read findings.

## Worked example — find the input that reaches a "win" block
list_functions -> {"addr":"0x400666","name":"main"}; decompile shows it prints
"Congrats!" at 0x400743 only for the right input.

  add_check({"addr":"0x400666","check":{"kind":"reach","addr":"0x400743"}})
  run({"addr":"0x400666"})                 -> {"run_id":"ab12..."}
  get_run({"run_id":"ab12..."})            # repeat until status=="done"
  -> {"status":"done",
      "findings":[{"kind":"reach","addr":4196675,"message":"reached 0x400743",
                   "witness":{"arg0":{"hex":"0x5","s":5}, ".password":"IW{...}"}}]}
  The "witness" is the answer: those inputs drive execution to 0x400743.

## Declaring inputs (configure patch, or add_assumption)
- Arguments are symbolic by default. Make one FIXED: configure {"args":[{"name":"n","mode":"concrete","value":16,"size":4}]}.
- Floating-point param: add "float":true to the arg (required for float checks).
- Pointer to a symbolic buffer: {"buffers":[{"arg":"buf","size":64}]}.
- Symbolic stdin:  {"stdin":{"mode":"symbolic","size":32}}.
- Symbolic file the program reads: {"files":[{"name":".password","size":20}]}.
- Constrain inputs: add_assumption(addr, "arg0 s> 0").  Limits: configure {"limits":{"steps":300,"seconds":60,"skip_calls":true}}.

## Checks — add_check(addr, check). ADD AT LEAST ONE before run (run errors otherwise).
- reach          {"kind":"reach","addr":"0x.."}           any path that gets here
- avoid          {"kind":"avoid","addr":"0x.."}           flag paths that hit a bad address
- assert         {"kind":"assert","expr":"total < 0x1000","at_return":true}   an invariant that must hold
- int_overflow   {"kind":"int_overflow","signed":"either|signed|unsigned"}    add/sub/mul that wraps
- narrowing_cast {"kind":"narrowing_cast"}                 value truncated to a smaller int, losing data
- float_anomaly  {"kind":"float_anomaly"}                  result can be NaN or +/-Inf
- oob_write      {"kind":"oob_write","base":"a1","size":16}  a write outside [base, base+size)
Add "addr":"0x.." to any of the last four to check one instruction; omit it to scan the whole function.

## Expression language (used by assumptions and assert "expr")
names: argument names, a1../arg0.. (parameters), registers (rdi, eax), ret (return value)
compare: == != < <= > >=  (unsigned). Prefix s for signed: s< s<= s> s>=
arith/bitwise: + - * / % & | ^ ~ << >>   (s>> arithmetic shift, s/ s% signed)
widths: u8/u16/u32/u64 (low bits, unsigned), s8/s16/s32/s64 (sign-extend). memory: mem(addr, size)
examples:  "a1 & 0xff == 0x5a"    "u32(x) + 8 < u32(x)"    "ret s>= 0"

## Modeling calls (hooks) — for bugs that span library calls
When the analysed function calls others (malloc, size helpers, read/write), you usually
don't want to execute their real code. `skip_calls` returns "anything" (useless if you
care about the result), and stepping in is expensive. Instead MODEL a call with add_model
(or configure {"models":[...]}). Kinds:
  - {"func":"TIFFScanlineSize","kind":"symbolic","name":"size","bits":64}  # fresh symbolic return
  - {"func":"_TIFFmalloc","kind":"alloc","size_arg":0}      # allocate a buffer sized by arg0, TRACKED
  - {"func":"TIFFReadScanline","kind":"concrete","value":0} # no-op returning success
  - {"func":"foo","kind":"return_arg","arg":0}              # return the first argument
Then an oob_write check with NO base checks every write against the tracked allocations —
so "model malloc as alloc + add oob_write" finds heap overflows (e.g. CVE-2017-5225).
IMPORTANT: skip_calls BYPASSES models, so leave it off and model every heavy call the
function makes (reads/writes/allocs), or the run won't stay bounded.

## Scenarios (optional)
A function can have several scenarios — different ways it is reached, each with its
own initial state; the checks are SHARED. configure/add_assumption/run act on the
ACTIVE scenario. Tools: add_scenario(name,duplicate), select_scenario, rename_scenario, delete_scenario.

## Gotchas
- Addresses in: hex string "0x400743" or a function name. Addresses out (in findings): integers.
- run is ASYNC — always poll get_run until status is "done" or "error".
- A witness maps input name -> value: {"hex","s"} for a number, a byte string for stdin/files. That IS the triggering input.
- Found nothing? Widen limits, or check your assumptions aren't over-constraining. remove_assumption / remove_check undo mistakes.
- decompile needs IDA (get_status.ida.connected); else use disassemble. ida_connect(url) connects.
- Call get_guide any time to reread this.
"""

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
    {"name": "run", "description": "Run the enabled checks on a function using its active scenario's setup. Returns a run_id.",
     "inputSchema": {"type": "object", "properties": _A, "required": ["addr"]}},
    {"name": "get_run", "description": "Results of a run: status, findings (with concrete witnesses), and the path tree.",
     "inputSchema": {"type": "object", "properties": {"run_id": {"type": "string"}}, "required": ["run_id"]}},
    {"name": "load_binary", "description": "Load an ELF binary by absolute path (replaces the current one). Analyses before returning.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "add_scenario", "description": "Add a scenario (a separate initial-state setup) to a function and make it active. "
     "duplicate=true copies the active scenario's initial state. Checks are shared across scenarios.",
     "inputSchema": {"type": "object", "properties": {**_A, "name": {"type": "string"}, "duplicate": {"type": "boolean"}}, "required": ["addr"]}},
    {"name": "select_scenario", "description": "Make a scenario active (by name or index). configure/add_assumption/run act on the active scenario.",
     "inputSchema": {"type": "object", "properties": {**_A, "scenario": {"type": "string", "description": "name or index"}}, "required": ["addr", "scenario"]}},
    {"name": "rename_scenario", "description": "Rename a scenario (by name or index).",
     "inputSchema": {"type": "object", "properties": {**_A, "scenario": {"type": "string"}, "name": {"type": "string"}}, "required": ["addr", "scenario", "name"]}},
    {"name": "delete_scenario", "description": "Delete a scenario (by name or index). A function keeps at least one.",
     "inputSchema": {"type": "object", "properties": {**_A, "scenario": {"type": "string"}}, "required": ["addr", "scenario"]}},
    {"name": "get_guide", "description": "A full how-to for this tool: what it does, the step-by-step loop, a worked "
     "example, the expression language, every check kind, and gotchas. Read this first if unsure.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "list_files", "description": "List a directory (to find a binary to load_binary). ELF files are flagged.",
     "inputSchema": {"type": "object", "properties": {"directory": {"type": "string"}}}},
    {"name": "cancel_run", "description": "Stop a run that is still exploring.",
     "inputSchema": {"type": "object", "properties": {"run_id": {"type": "string"}}, "required": ["run_id"]}},
    {"name": "remove_assumption", "description": "Remove one assumption from the active scenario, by index or exact expr.",
     "inputSchema": {"type": "object", "properties": {**_A, "index": {"type": "integer"}, "expr": {"type": "string"}}, "required": ["addr"]}},
    {"name": "remove_check", "description": "Remove one shared check, by id, name, or index.",
     "inputSchema": {"type": "object", "properties": {**_A, "check": {"type": "string", "description": "id, name, or index"}}, "required": ["addr", "check"]}},
    {"name": "export_scenario", "description": "Bundle the active scenario's setup, the shared checks, and the latest run's "
     "findings + paths — the same data the GUI's Export produces.",
     "inputSchema": {"type": "object", "properties": _A, "required": ["addr"]}},
    {"name": "ida_connect", "description": "Connect to an IDA MCP server for real names + Hex-Rays decompilation. "
     "url defaults to the configured one; host_header is auto-set to loopback for forwarded servers.",
     "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}, "host_header": {"type": "string"}}}},
    {"name": "ida_disconnect", "description": "Disconnect from IDA.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "ida_refresh", "description": "Re-pull names + decompilation from IDA (after you changed the IDB).",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "add_model", "description": "Model (hook) a function the target calls, so it isn't stepped into. "
     "model = {\"func\":\"name or 0x..\",\"kind\":...}. kinds: "
     "{\"kind\":\"symbolic\",\"name\":\"ret\",\"bits\":64} (fresh symbolic return); "
     "{\"kind\":\"concrete\",\"value\":0}; {\"kind\":\"return_arg\",\"arg\":0}; "
     "{\"kind\":\"alloc\",\"size_arg\":0,\"name\":\"buf\"} (allocate a buffer sized by that arg, tracked for oob_write). "
     "NOTE: skip_calls bypasses models, so to keep a run bounded, model every heavy call the function makes.",
     "inputSchema": {"type": "object", "properties": {**_A, "model": {"type": "object"}}, "required": ["addr", "model"]}},
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
    {"kind": "oob_write", "summary": "a memory write that can fall outside a buffer. Explicit: give base+size. Modeled: omit base to check writes against every buffer an 'alloc' call model handed out (heap overflows).",
     "fields": {"base": "expression for the buffer start, e.g. a1 or rsp-0x40 (omit for modeled mode)",
                "size": "buffer size in bytes (with base)", "addr": "0x.. (optional single write instruction)"}},
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
    "load_binary": lambda a: _mcp_load_binary(a["path"]),
    "add_scenario": lambda a: _mcp_add_scenario(a["addr"], a.get("name"), a.get("duplicate", False)),
    "select_scenario": lambda a: _mcp_select_scenario(a["addr"], a["scenario"]),
    "rename_scenario": lambda a: _mcp_rename_scenario(a["addr"], a["scenario"], a["name"]),
    "delete_scenario": lambda a: _mcp_delete_scenario(a["addr"], a["scenario"]),
    "get_guide": lambda a: _mcp_guide(),
    "list_files": lambda a: _mcp_list_files(a.get("directory")),
    "cancel_run": lambda a: _mcp_cancel_run(a["run_id"]),
    "remove_assumption": lambda a: _mcp_remove_assumption(a["addr"], a.get("index"), a.get("expr")),
    "remove_check": lambda a: _mcp_remove_check(a["addr"], a["check"]),
    "export_scenario": lambda a: _mcp_export_scenario(a["addr"]),
    "ida_connect": lambda a: _mcp_ida_connect(a.get("url"), a.get("host_header")),
    "ida_disconnect": lambda a: _mcp_ida_disconnect(),
    "ida_refresh": lambda a: _mcp_ida_refresh(),
    "add_model": lambda a: _mcp_add_model(a["addr"], a["model"]),
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
            "instructions": (
                "This server drives angr symbolic execution: it runs ONE function with "
                "its inputs left symbolic (unknown) and finds CONCRETE inputs that reach a "
                "location or trigger a bug. You declare what's unknown and what to look for; "
                "it returns the exact inputs ('witness') that make it happen. A human watches "
                "live in a GUI.\n"
                "FIRST: call get_guide for the full how-to (workflow, worked example, "
                "expression language, all check kinds, gotchas).\n"
                "Loop: get_status -> list_functions -> get_function -> (configure/add_assumption/"
                "add_check) -> run -> poll get_run until status=='done'. You MUST add at least one "
                "check before run. run is async. Addresses go in as hex strings or names.")}}
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
        "guide": GUIDE,
    }


if os.path.isdir(os.path.join(STATIC, "vendor")):
    app.mount("/vendor", StaticFiles(directory=os.path.join(STATIC, "vendor")), name="vendor")
