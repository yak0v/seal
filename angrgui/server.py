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
import re
import tempfile
import threading
import time
import uuid
import logging
import urllib.parse

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .engine import Binary
from .runner import Run
from .backend import make_backend, AngrBackend
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
    """Holds the active analysis backend, its workspace, and run bookkeeping. The
    backend (angr today, another framework tomorrow) owns the binary + runs; `binary`
    and `runs` stay as compatibility views so the rest of the server is backend-agnostic."""
    def __init__(self):
        self.backend = None                      # backend.Backend or None
        self.workspace: Workspace | None = None
        self.last_run: dict[int, str] = {}       # func_addr -> most recent run_id
        self.load_status = {"loading": False, "message": "", "error": None}
        self.ida = None                     # optional angrgui.idamcp.IdaSession

    @property
    def binary(self):
        return self.backend.binary if self.backend is not None else None

    @binary.setter
    def binary(self, b):
        if b is None:
            self.backend = None
        else:
            self.backend = AngrBackend(binary=b)   # wrap a directly-assigned Binary (tests/callers)

    @property
    def runs(self) -> dict:
        return self.backend.runs if self.backend is not None else {}

    @runs.setter
    def runs(self, d):                           # reset the backend's runs (callers/tests)
        if self.backend is not None:
            self.backend.runs.clear()
            self.backend.runs.update(d or {})


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
    target_funcs: list[int] | None = None   # scope analysis to these funcs (big arm64 dylibs)


class RunReq(BaseModel):
    func_addr: int
    args: list = []
    buffers: list = []
    assumptions: list = []
    stdin: dict | None = None
    files: list = []
    checks: list = []
    limits: dict = {}
    models: list = []
    initial_state: dict | None = None        # concolic seed: {kind:"snapshot", pc, regs, mem, symbolic}


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
_NOCACHE = {"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"}


@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(STATIC, "index.html")) as fh:
        return HTMLResponse(fh.read(), headers=_NOCACHE)   # always serve fresh; a plain reload shows edits


@app.get("/app.js")
def app_js():
    from fastapi.responses import Response
    with open(os.path.join(STATIC, "app.js")) as fh:
        return Response(fh.read(), media_type="application/javascript", headers=_NOCACHE)


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
        S.backend = make_backend("angr", path=path, progress=progress, target_funcs=req.target_funcs)
        S.workspace = Workspace(path)
        S.last_run.clear()
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


@app.get("/api/models")
def get_models():
    """The global function-return model registry (by_name + by_site)."""
    if S.workspace is None:
        return {"by_name": {}, "by_site": {}}
    return S.workspace.function_models()


@app.post("/api/models")
def set_models(fm: dict = Body(...)):
    if S.workspace is None:
        raise HTTPException(400, "no workspace")
    S.workspace.set_function_models(fm)
    BUS.publish("models", "function-return models updated",
                names=list((fm.get("by_name") or {}).keys()),
                sites=list((fm.get("by_site") or {}).keys()))
    return S.workspace.function_models()


def _merge_global_models(spec: dict) -> dict:
    """Fold the workspace's global function-return models (applied whenever a
    function / call site is reached) into this run's per-analysis models."""
    if S.workspace is None:
        return spec
    fm = S.workspace.function_models()
    models = list(spec.get("models") or [])
    for name, mdl in (fm.get("by_name") or {}).items():
        if mdl and mdl.get("enabled", True):
            models.append({**mdl, "func": mdl.get("func") or name})
    for site, mdl in (fm.get("by_site") or {}).items():
        if mdl and mdl.get("enabled", True):
            models.append({**mdl, "site": mdl.get("site") or site})
    spec["models"] = models
    return spec


def _arg_struct_type(func_addr: int, argname: str) -> str | None:
    """Resolve a pointer argument's struct type from IDA's decompiled signature,
    e.g. argument `tif` of `TIFFRewriteDirectory(TIFF *tif)` -> "TIFF"."""
    if S.ida is None:
        return None
    try:
        code = S.ida.decompile(func_addr).get("code", "")
    except Exception:
        return None
    m = re.search(r"\(([^)]*)\)", code or "")
    if not m:
        return None
    for param in m.group(1).split(","):
        pm = re.match(r"\s*(.+?)[\s*]+([A-Za-z_]\w*)\s*$", param)
        if pm and pm.group(2) == argname:
            typ = re.sub(r"\b(const|struct|volatile|unsigned|signed)\b", "", pm.group(1))
            typ = typ.replace("*", "").strip()
            return typ or None
    return None


def _enrich_buffer_members(spec: dict) -> dict:
    """Give each pointer buffer a byte-offset -> struct-member-name map so branch
    conditions read `tif->tif_mode` instead of `tif_buf[16]`. Members the user loaded
    (layout) are used as-is; otherwise the buffer's struct type — explicit, or resolved
    from IDA's signature — is fetched from IDA and used for naming."""
    for b in spec.get("buffers", []) or []:
        if b.get("member_map") or b.get("layout") or S.ida is None:
            continue
        st = b.get("struct_type") or _arg_struct_type(spec.get("func_addr"), b.get("arg"))
        if not st:
            continue
        try:
            data = S.ida.struct_layout(st)
            arg = b.get("arg")
            b["struct_type"] = st
            b["member_map"] = [[int(m["offset"]), int(m["size"]) or 1, f"{arg}->{m['name']}"]
                               for m in data.get("members", [])]
        except Exception:
            pass
    return spec


def _start_run(spec: dict, source: str = "gui") -> str:
    if S.backend is None:
        raise HTTPException(400, "no binary loaded")
    if S.backend.binary.get_function(spec["func_addr"]) is None:
        raise HTTPException(404, "no such function")
    _merge_global_models(spec)
    _enrich_buffer_members(spec)
    run_id = S.backend.new_run_id()

    def on_event(kind, **data):
        msg = {"finding": lambda: f"finding: {data.get('check_kind')} at {data.get('addr', 0):#x} — {data.get('detail', '')}",
               "run_progress": lambda: f"exploring {_fname(spec['func_addr'])}: {data.get('active', 0)} paths active, "
                                       f"step {data.get('step', 0)}, {data.get('deadended', 0)} ended, {data.get('hits', 0)} finding(s)",
               "run_status": lambda: f"run of {_fname(spec['func_addr'])} {data.get('status')} "
                                     f"({data.get('hits', 0)} finding(s))"}.get(kind, lambda: kind)()
        BUS.publish(kind, msg, run_id=run_id, **data)

    S.backend.start_run(run_id, spec, on_event=on_event)   # backend owns the run object
    S.last_run[spec["func_addr"]] = run_id
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
    # A Last-Event-ID larger than our current seq means it came from a PREVIOUS server
    # process (the bus reset on restart): resume from now so new events still flow,
    # instead of waiting forever for a seq this fresh bus will never reach.
    if start > BUS._seq:
        start = BUS._seq

    def gen():
        yield "retry: 2000\n\n"
        for e in BUS.stream(start):
            yield ": ping\n\n" if e is None else f"id: {e['seq']}\ndata: {json.dumps(e)}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/api/run/{run_id}")
def run_status(run_id: str):
    snap = S.backend.run_snapshot(run_id) if S.backend else None
    if snap is None:
        raise HTTPException(404, "no such run")
    return snap


def _leaf_example(snap: dict, node: int) -> dict:
    """The concrete inputs of a path: the node's own example, else any leaf under it,
    else any leaf in the run."""
    tree = snap["tree"]
    byid = {n["id"]: n for n in tree}
    kids = {}
    for n in tree:
        if n["parent"] is not None:
            kids.setdefault(n["parent"], []).append(n["id"])
    nd = byid.get(node)
    if nd and nd.get("example"):
        return nd["example"]
    stack = [node] if nd else [n["id"] for n in tree if n["parent"] is None]
    while stack:
        cur = byid.get(stack.pop())
        if cur and cur.get("example"):
            return cur["example"]
        stack.extend(kids.get(cur["id"], []) if cur else [])
    for n in tree:
        if n.get("example"):
            return n["example"]
    return {}


@app.get("/api/run/{run_id}/values")
def run_values(run_id: str, node: int):
    """Per-instruction destination values on a path: {hex_addr: {reg, val, store?}},
    computed by re-executing the function with that path's concrete example inputs.
    Lets the UI show the value of the variable assigned on each decompilation line."""
    snap = S.backend.run_snapshot(run_id) if S.backend else None
    if snap is None:
        raise HTTPException(404, "no such run")
    example = _leaf_example(snap, node)
    return {"node": node, "values": S.backend.run_values(run_id, example)}


@app.post("/api/run/{run_id}/cancel")
def run_cancel(run_id: str):
    if not (S.backend and S.backend.cancel_run(run_id)):
        raise HTTPException(404, "no such run")
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
    # A binary need not be loaded first (#9): you can connect to IDA and then import
    # the binary straight from it. When one *is* loaded, pass its path so the official
    # server attaches to the matching database.
    b = S.binary
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
        st = sess.connect(b.path if b else None)  # official: opens/attaches by path; community: uses the open GUI
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


@app.get("/api/ida/input")
def ida_input_info():
    """What IDA knows about its input file — so the GUI can show name/size before import."""
    if S.ida is None:
        raise HTTPException(400, "not connected to IDA")
    try:
        return S.ida.input_file_info()
    except MCPError as e:
        raise HTTPException(502, str(e))


@app.post("/api/ida/import")
def ida_import():
    """Pull the binary straight from the connected IDA (its input file) and load it,
    so the user needn't open the file in SEAL separately (#9)."""
    if S.ida is None:
        raise HTTPException(400, "not connected to IDA")
    try:
        info = S.ida.input_file_info()
    except MCPError as e:
        raise HTTPException(502, str(e))
    name = info.get("name") or "ida_binary"
    dest_dir = os.path.join(tempfile.gettempdir(), "seal_ida_import")
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, name)
    S.load_status = {"loading": True, "message": f"fetching {name} from IDA", "error": None}

    def progress(got, total):
        pct = f" {got * 100 // total}%" if total else ""
        S.load_status["message"] = f"fetching {name} from IDA:{pct} ({got} bytes)"
        BUS.publish("ida", f"importing {name}: {got} bytes{pct}", got=got, total=total)

    try:
        fetched = S.ida.fetch_input_file(dest, progress=progress)
    except MCPError as e:
        S.load_status = {"loading": False, "message": "", "error": str(e)}
        raise HTTPException(502, str(e))
    BUS.publish("ida", f"fetched {name} ({fetched.get('size')} bytes, {fetched.get('via')}); loading")
    load(LoadReq(path=dest))            # analyse + install as the current binary
    return {"binary": S.binary.info(), "source": fetched}


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


@app.get("/api/ida/structs")
def ida_structs():
    if S.ida is None:
        raise HTTPException(400, "not connected to IDA")
    try:
        return {"structs": S.ida.list_structs()}
    except MCPError as e:
        raise HTTPException(502, str(e))


@app.get("/api/ida/struct/{name}")
def ida_struct(name: str):
    if S.ida is None:
        raise HTTPException(400, "not connected to IDA")
    try:
        return S.ida.struct_layout(name)
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


def _mcp_functions(query=None, limit: int = 200, only=None):
    """List functions. `query` is a name/address substring; `only` cuts noise:
    "named" (has a real symbol, not sub_/CRT), "source" (has DWARF line info),
    "configured" (already has checks/assumptions set), "interesting" (any of those)
    — invaluable on big stripped binaries where the raw list is thousands of CRT
    stubs. Returns totals so an agent knows when the list was capped by `limit`."""
    fns = functions()["functions"]
    if query:
        q = str(query).lower()
        fns = [f for f in fns if q in f["name"].lower()
               or q in (f.get("ida_name") or "").lower() or q in hex(f["addr"])]
    if only and str(only).lower() not in ("all", ""):
        o = str(only).lower()
        def keep(f):
            named = bool(f.get("named"))
            src = bool(f.get("has_source"))
            conf = bool(f.get("configured") or f.get("check_count"))
            if o in ("named",):       return named
            if o in ("source", "has_source"): return src
            if o in ("configured",):  return conf
            if o in ("interesting", "user"):  return named or src or conf
            return True               # unknown filter: don't hide anything
        fns = [f for f in fns if keep(f)]
    total = len(fns)
    shown = fns[:int(limit)]
    return {"total": total, "shown": len(shown), "truncated": total > len(shown),
            "functions": [{"addr": hex(f["addr"]), "name": f.get("ida_name") or f["name"],
                           "blocks": f["block_count"], "args": len(f["args"]),
                           "checks": f.get("check_count", 0),
                           "has_source": f["has_source"], "named": bool(f.get("named"))}
                          for f in shown]}


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
    for k in ("args", "buffers", "assumptions", "stdin", "files", "limits", "models", "initial_state"):
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
            "models": flat.get("models") or [], "initial_state": flat.get("initial_state"),
            "checks": [c for c in flat.get("checks", []) if c.get("enabled", True)]}
    # checks are optional: with none, this just enumerates the paths (control-flow exploration)
    return {"run_id": _start_run(spec, source="agent")}


def _mcp_get_run(run_id):
    r = S.runs.get(run_id)
    if r is None:
        raise HTTPException(404, "no such run")
    snap = r.snapshot()
    # expose the end REASON plus its human text, so an agent can see WHY a path ended —
    # e.g. the exact angr/decode error or the undetermined indirect-call site — not just
    # a bare "error"/"unknown_call" code.
    tree = [{"id": n["id"], "parent": n["parent"], "cond": n["cond"], "kind": n["kind"],
             "end": (n["end"] or {}).get("reason"), "detail": (n["end"] or {}).get("text"),
             "hits": n["hits"]} for n in snap["tree"]]
    return {"status": snap["status"], "error": snap["error"], "summary": snap["summary"],
            "findings": snap["hits"], "paths": tree}


def _mcp_path_values(run_id, node):
    return run_values(run_id, int(node))          # {node, values: {addr: {reg,val,store?}}}


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


GUIDE = r"""# SEAL (Symbolic Execution Analysis Lab) — operating skill for agents

You are driving SEAL, a tool that finds bugs and reachability facts in ONE function
of a compiled binary using **symbolic execution** (the angr engine), behind a visual
GUI that a human is watching live. This document is your complete manual. Read it
once, top to bottom; it assumes you have never used SEAL or symbolic execution
before. Everything you do over MCP also appears in the human's GUI in real time.

════════════════════════════════════════════════════════════════════════
PART 1 — THE MENTAL MODEL (read this, it prevents 90% of mistakes)
════════════════════════════════════════════════════════════════════════

Normal execution: you give a function concrete inputs, it runs one path, you see one
result. Symbolic execution: you leave some inputs UNKNOWN (called "symbolic"), and
the engine explores MANY paths at once, tracking a set of algebraic constraints on
those unknowns for each path. When you ask a question — "can execution reach address
X?", "can this multiply overflow?", "can this store land outside the buffer?" — the
engine hands the constraints to a solver (Z3). If the answer is YES, it gives you a
**witness**: concrete values for the unknown inputs that actually make it happen.

So your job is NOT to write an exploit or guess inputs. Your job is three steps:
  (1) DECLARE what is unknown      (make the inputs you want to vary "symbolic"),
  (2) DECLARE what to look for     (add one or more "checks"),
  (3) RUN, then READ THE WITNESS   (the concrete inputs the solver found).

The witness is the whole point. A finding without reading its witness is useless.

Critical truths that trip up every new agent:
  • A FIXED (concrete) input can never expose a bug that depends on that input. If you
    want the solver to find a bad `size`, `size` must be SYMBOLIC. If everything is
    fixed, every path is concrete and SEAL finds nothing interesting.
  • But TOO MUCH symbolic is the opposite failure: if every input and the entire
    surrounding memory is unknown, the engine sees astronomically many paths ("path
    explosion") and either times out or reports that "every path" looks dangerous
    (useless). The art is making ONLY the attacker-controlled thing symbolic and
    keeping realistic context concrete. (This is what "concolic" seeding in PART 7 is
    for.)
  • `run` is ASYNCHRONOUS. It returns a run_id immediately; the exploration happens in
    the background. You MUST poll `get_run(run_id)` until status is "done" or "error"
    before the findings are complete.
  • One function at a time. SEAL analyses a single function's body; calls out to other
    functions are either stepped into, skipped, or modeled (PART 9) — your choice.

════════════════════════════════════════════════════════════════════════
PART 2 — CONNECT
════════════════════════════════════════════════════════════════════════

SEAL exposes a built-in MCP server (Streamable HTTP) at the /mcp endpoint of the same
host/port as the GUI (e.g. http://127.0.0.1:8770/mcp). No authentication. Do the
standard handshake: initialize → tools/list → tools/call. The initialize response's
`instructions` field, and the `get_guide` tool, both return THIS document — reread it
any time.

Everything you call is published to the GUI's live "Activity" feed, and with "follow
agent" on (default) the human's view auto-jumps to the function you configure and the
run you start. You are performing for an audience; narrate nothing, just operate — the
GUI shows them what you did.

════════════════════════════════════════════════════════════════════════
PART 3 — THE CORE LOOP (the happy path, in order)
════════════════════════════════════════════════════════════════════════

1. get_status
     Is a binary loaded? Is IDA connected (for names/decompilation)? If no binary,
     load one yourself: list_files(dir) to browse, then load_binary(absolute_path).
2. list_functions(query, only, limit)
     Find your target by name or address substring. Returns {total, shown, truncated,
     functions:[...]} — iterate the "functions" list; "truncated" means raise limit or
     narrow the query. Note each entry's integer "addr". For a big stripped binary most
     functions are "sub_<addr>" with named:false — pass only:"interesting" (or "source"
     / "named" / "configured") to skip the CRT/library noise, or connect IDA for names.
3. get_function(addr)
     Read the current setup: the active scenario's initial state (args, buffers,
     assumptions, stdin, files, limits, models, initial_state), the shared checks, and
     the list of scenario names. Arguments are symbolic by default.
4. disassemble(addr)   (or decompile(addr) if IDA is connected)
     READ THE CODE. Decide which inputs matter and where the interesting
     operations/branches are. You cannot check well what you have not read.
5. configure(addr, patch)  /  add_assumption(addr, expr)  /  add_check(addr, check)
     Declare inputs (what is symbolic vs fixed, buffers, structs, stdin, files),
     constrain them to realistic ranges, and declare what to look for.
6. run(addr)  ->  {"run_id": "..."}
     Starts exploring in the background.
7. get_run(run_id)
     POLL until status == "done" (or "error"). Then read `findings`: each has a kind,
     an address, a message, a `witness` (the triggering inputs), and belongs to a node
     in the `tree` (the path tree). Optionally call path_values(run_id, node) for the
     concrete value assigned on each line of that path.

That is the whole loop. Everything below is detail for doing step 5 well and reading
step 7 correctly.

════════════════════════════════════════════════════════════════════════
PART 4 — DECLARING INPUTS (the `configure` patch, and add_assumption)
════════════════════════════════════════════════════════════════════════

`configure(addr, patch)` replaces the given keys of the ACTIVE scenario. The patch may
contain any of: args, buffers, assumptions, stdin, files, limits, models,
initial_state. (checks are shared, not per-scenario, but configure also accepts a
"checks" key as a convenience.)

ARGS — the function's parameters. Each: {"name","mode","size","value","float"}.
  • mode "symbolic" (default): the solver may choose any value. This is what exposes
    bugs. size is in BYTES (4 = 32-bit, 8 = 64-bit).
  • mode "concrete": a fixed value you supply in "value". Use for context you know.
  • "float": true marks a floating-point parameter (REQUIRED before a float_anomaly
    check or any FP reasoning works on it).
  Example: configure(a, {"args":[{"name":"n","mode":"concrete","value":16,"size":4},
                                  {"name":"buf","mode":"symbolic","size":8}]})

BUFFERS — point a pointer argument at a fresh buffer whose CONTENTS are symbolic (the
pointer itself is a concrete scratch address). {"arg","size","layout"}.
  • Plain symbolic buffer: {"buffers":[{"arg":"buf","size":64}]}.
  • Struct layout: when the pointer is to a struct, call get_struct("TYPE") (needs IDA)
    to get the member offsets/sizes/types, then set specific members and leave the rest
    symbolic:
      {"buffers":[{"arg":"p","size":<sizeof>,"layout":[
         {"offset":12,"size":4,"mode":"sym","name":"p_size"},   # named symbolic member
         {"offset":8, "size":4,"mode":"fixed","value":0}]}]}    # pinned member
    Named symbolic members show up in witnesses by name — much more readable.

STDIN / FILES — for programs that read input:
  • Symbolic stdin: {"stdin":{"mode":"symbolic","size":32}}.
  • A symbolic file the program opens by name (e.g. a CTF password file):
    {"files":[{"name":".password","size":20}]}.

ASSUMPTIONS — constrain the unknowns so the solver stays in realistic territory and
doesn't report absurd witnesses. add_assumption(addr, "arg0 s> 0"). They are boolean
expressions that must hold at entry (see PART 8 for the language). Over-constraining is
a common reason you "find nothing" — if a run is empty, suspect your assumptions first.

LIMITS — bound the exploration. configure(a, {"limits":{...}}):
  • steps: max simulation steps (default ~200). Raise for deep functions.
  • active: max simultaneous paths kept (default ~400). Raise for wide branching.
  • seconds: wall-clock cap.
  • skip_calls: true makes calls to other functions return a fresh unconstrained value
    instead of being executed — keeps exploration inside the target function. BUT it
    BYPASSES models (PART 9), so don't set it when you rely on modeled allocations.
  • loop_bound: cap iterations of a loop with a symbolic trip count (stops infinite
    unrolling). find / avoid: optional target/forbidden addresses for directed search.

════════════════════════════════════════════════════════════════════════
PART 5 — CHECKS (what to look for).  add_check(addr, check); or remove_check.
════════════════════════════════════════════════════════════════════════

With NO checks, `run` simply enumerates the reachable paths (useful to see control
flow). Add checks to hunt specific conditions. Every check may take an optional
"addr" to pin it to ONE instruction; omit "addr" to scan the whole function.

  • reach   {"kind":"reach","addr":"0x.."}
        A finding for any path that reaches that address. Witness = the inputs that get
        there. THE tool for "what input makes it print the flag / hit this branch".
  • avoid   {"kind":"avoid","addr":"0x.."}
        Flags (and marks) paths that reach a bad address.
  • assert  {"kind":"assert","expr":"total < 0x1000","at_return":true}
        An invariant that must ALWAYS hold. A finding is any input that BREAKS it (the
        counterexample). "at_return":true evaluates it at the function's return.
  • int_overflow  {"kind":"int_overflow","signed":"either|signed|unsigned"}
        An add/sub/mul whose result wraps past the type width. Witness = operands that
        wrap (e.g. a size near INT_MAX). Classic size-computation bug.
  • div_by_zero  {"kind":"div_by_zero"}
        An integer division/remainder whose divisor the inputs can make zero. Witness =
        the input that zeroes the divisor.
  • narrowing_cast  {"kind":"narrowing_cast"}
        A value truncated to a smaller integer where the dropped high bits can be
        non-zero (information lost). Catches BOTH ordinary C casts (long→int) AND NEON
        vector-lane truncation like arm64 `xtn` (this is the root cause of the
        CoreGraphics CVE we validate — a float→int64 that is then truncated to int32
        without saturation). Witness = the input that makes the high bits non-zero.
  • float_anomaly  {"kind":"float_anomaly"}
        A floating-point op whose result can be NaN or ±Inf. Mark the relevant arg
        "float":true first.
  • oob_write  {"kind":"oob_write","base":"a1","size":16}
        A memory write that can land outside [base, base+size). "base" may be an
        argument name / expression and "size" its length. OMIT base to check every
        write against the allocations tracked by your alloc models (PART 9) — that is
        how you find heap overflows across library calls.
  • oob_read   {"kind":"oob_read","base":"a1","size":16}
        Same as oob_write but for a memory READ that can fall outside the buffer — an
        out-of-bounds read / information leak. Same fields and modeled mode.
  • null_deref  {"kind":"null_deref"}
        A memory read/write through a pointer the inputs can drive into the null page.
        angr zero-fills unmapped memory, so these never crash on their own — this check
        surfaces them. Witness = the input that makes the pointer NULL. Optional "page"
        widens the near-null window (default 0x1000).
  • custom  {"kind":"custom","addr":"0x..","code":"def check(state, api): ..."}
        Run your own Python predicate at a point; return a dict to record a finding.

════════════════════════════════════════════════════════════════════════
PART 6 — READING RESULTS (don't skip this — it's half the job)
════════════════════════════════════════════════════════════════════════

get_run(run_id) returns:
  • status: "pending" | "running" | "done" | "error" | "cancelled". POLL until it's
    not pending/running.
  • findings: a list. Each: {kind, addr (integer), message, witness, extra, node}.
  • tree: the path tree — nodes with ids, parent links, the block addresses on each
    path, and per-leaf an "example" (inputs for that path) and a classification
    (deadended / returned / unconstrained / errored).
  • summary: counts.

THE WITNESS maps each input NAME to its value:
  • a number → {"hex": "0x..", "s": <signed decimal>, "bits": N}. That is the exact
    value the solver chose. For a narrowing/overflow finding it's the value that
    triggers the bug; for a reach it's the input that gets there.
  • stdin / a file → a byte string.
Read it and report it — it is the proof.

"unconstrained" leaves are a strong signal: execution reached a state where the
instruction pointer itself became attacker-controlled (e.g. a jump through a symbolic
function pointer) — a control-flow-hijack lead. The leaf still carries an example.

path_values(run_id, node): for the chosen path, the concrete value assigned at each
instruction — {addr: {reg, val, store}}. This is what the GUI overlays on the
decompilation/disassembly so the human sees the real value on each line.

cancel_run(run_id): stop a run still exploring. export_scenario(addr): bundle the
active scenario + shared checks + the latest run's findings into a portable blob.

════════════════════════════════════════════════════════════════════════
PART 7 — CONCOLIC SEEDING FROM A REAL RUN (initial_state / snapshots)
════════════════════════════════════════════════════════════════════════

The default start is a "fresh call": the engine builds a call state with symbolic
arguments and otherwise-empty memory. That's fine for small, self-contained functions.
But for a function deep inside a real library, a fresh call is both WRONG (the real
surrounding structs/buffers aren't there) and INTRACTABLE (everything is symbolic →
path explosion). The fix is CONCOLIC seeding: start from a snapshot of a REAL execution
(concrete registers + memory captured from a live process), and make ONLY the
attacker-controlled fields symbolic. Then exploration follows realistic paths and the
bug condition comes out as a PRECISE threshold instead of "every path".

You set this with the scenario's `initial_state`:
  {"kind":"snapshot",
   "pc":   <start address>,                      # where to begin (may be mid-function)
   "regs": {"x0":..., "x1":..., "sp":..., ...},  # concrete registers from the capture
   "mem":  [{"addr":..., "hex":"...."}, ...],    # concrete memory regions
   "symbolic":[{"reg":"x1","name":"coord","size":8},   # fields to make symbolic:
               {"addr":0x.., "name":"len","size":4}],  #   a register OR a memory addr
   "image":{"slide":0x.., "file_lo":0x.., "file_hi":0x..}}  # optional, see rebasing

Two things SEAL does for you here:
  • It will seed MID-function: `pc` is authoritative even though `regs` also contains a
    saved pc — so you can start right at the instruction you care about.
  • REBASING: a snapshot captured from a live process holds runtime (ASLR-slid)
    addresses, but SEAL loads the binary at its FILE addresses. If you include
    "image":{"slide",...}, SEAL rebases the snapshot down into file-address space for
    you (pc, registers, memory region bases, and pointer slots inside the bytes; heap
    and stack addresses are left alone). You pass the raw captured snapshot + the
    slide; SEAL does the math.

HOW TO CAPTURE A SNAPSHOT (outside SEAL — lldb can't run inside it): the repo ships
angrgui/snapshot/capture.py (an lldb script that dumps registers + pointer-reachable
memory in exactly this shape and records the image slide) and live_bp.py (break by
ADDRESS in a shared-cache image — breaking by a stripped local symbol name hangs).
Capture at the TRUE function entry (lldb: --skip-prologue false) or the argument
registers will already be spilled and dead. See docs/ARCHITECTURE.md "Concolic
seeding" for the full workflow. Then feed the JSON straight into initial_state.

════════════════════════════════════════════════════════════════════════
PART 8 — THE EXPRESSION LANGUAGE (assumptions and assert "expr")
════════════════════════════════════════════════════════════════════════

names:    argument names, a1../arg0.. (parameters), registers (rdi, eax, x0…), ret
          (the return value), and mem(addr, size) to read memory.
compare:  == != < <= > >=   are UNSIGNED. Prefix s for signed: s< s<= s> s>=.
          (Getting signedness wrong silently changes the result — be deliberate.)
arith/bitwise:  + - * / % & | ^ ~ << >>    (s>> arithmetic shift; s/ s% signed div/mod)
widths:   u8/u16/u32/u64 take the low N bits unsigned; s8/s16/s32/s64 sign-extend.
examples: "a1 & 0xff == 0x5a"      "u32(x) + 8 < u32(x)"      "ret s>= 0"

════════════════════════════════════════════════════════════════════════
PART 9 — MODELING CALLS (bugs that span library calls)
════════════════════════════════════════════════════════════════════════

When your function calls others (malloc, size helpers, read/write), executing their
real code is slow and often impossible (no real heap, missing deps). `skip_calls`
returns "anything" which is useless if the result matters. Instead MODEL the call with
add_model(addr, model) (or configure {"models":[...]}):
  • {"func":"TIFFScanlineSize","kind":"symbolic","name":"size","bits":64}  fresh symbolic return
  • {"func":"_TIFFmalloc","kind":"alloc","size_arg":0}        allocate a buffer sized by arg0, TRACKED
  • {"func":"read","kind":"concrete","value":0}               no-op returning a fixed value
  • {"func":"foo","kind":"return_arg","arg":0}                return the Nth argument
An `oob_write` check with NO base then checks every write against the TRACKED
allocations — so "model malloc as alloc + add oob_write" finds heap overflows across
calls. IMPORTANT: skip_calls BYPASSES models, so when you model calls, leave skip_calls
OFF and model every heavy call (allocs/reads/writes) so the run stays bounded.

════════════════════════════════════════════════════════════════════════
PART 10 — SCENARIOS
════════════════════════════════════════════════════════════════════════

A function can have several SCENARIOS — different ways it is reached, each with its own
initial state (args, buffers, stdin, files, assumptions, limits, models, initial_state).
The CHECKS are SHARED across scenarios. configure / add_assumption / run always act on
the ACTIVE scenario. Manage with add_scenario(name, duplicate?), select_scenario,
rename_scenario, delete_scenario (each by name or index). Use scenarios to compare,
e.g., a fresh-call setup vs a concolic-snapshot setup of the same function.

════════════════════════════════════════════════════════════════════════
PART 11 — ARM64 / arm64e NOTES (iOS / macOS system binaries)
════════════════════════════════════════════════════════════════════════

SEAL runs on arm64 and arm64e, not just x86-64. At load it applies a portable runtime
patch (angrgui/angr_arm_patch.py) that teaches angr the NEON vector IR ops it ships
without (XTN/narrowing, saturating-narrow, byte-reverse, etc.) and hooks arm64e
pointer-authentication instructions (pacibsp/retab/braa/…) which libVEX cannot decode.
Big dyld-shared-cache dylibs (tens of thousands of functions) load in "lazy" mode:
functions are indexed from the symbol/segment table and each one's control-flow graph
is built on demand when you select it — so a 9 MB framework opens in seconds. A few
rare NEON ops (some saturating/rounding shifts, LSE atomics) are intentionally NOT
implemented: a wrong handler would silently corrupt analysis, so SEAL raises a clean
error instead — if you hit one in a hot path, it needs a real handler added.

════════════════════════════════════════════════════════════════════════
PART 12 — RECIPES (copy the shape, get real addresses from list_functions)
════════════════════════════════════════════════════════════════════════

A · Reach a target (CTF "find the input that wins")
   f = list_functions("check")["functions"][0]
   decompile(f.addr)                                   # find the "you win" block @ 0x4012f0
   configure(f.addr, {"args":[{"name":"key","mode":"symbolic","size":8}]})
   add_check(f.addr, {"kind":"reach","addr":0x4012f0})
   rid = run(f.addr).run_id ; poll get_run(rid)
   # finding "reach"; witness {key: 0x5365637265743121} → that input gets there.

B · Integer overflow (size computation wraps past 2³²)
   configure(a, {"args":[{"name":"size","mode":"symbolic","size":4},
                         {"name":"len","mode":"symbolic","size":4}]})
   add_assumption(a, "size < 0x80000000")              # keep it realistic
   add_check(a, {"kind":"int_overflow","signed":false})
   rid = run(a).run_id ; poll get_run(rid)
   # finding: size+len wraps; witness size≈0xffffffff, len=1 → tiny alloc, huge copy.

C · Narrowing cast / the CoreGraphics-CVE shape (float→int truncation)
   # concolic: start at the narrowing instruction with the scaled coordinate symbolic
   configure(a, {"initial_state":{"kind":"snapshot","pc":0x<runtime xtn>,
                   "regs":{...captured...},"mem":[...captured...],
                   "symbolic":[{"reg":"v0","name":"coord","size":16}],
                   "image":{"slide":0x10984000,"file_lo":0x..,"file_hi":0x..}}})
   add_check(a, {"kind":"narrowing_cast"})
   rid = run(a).run_id ; poll get_run(rid)
   # finding "narrowing 64->32 bits may lose data at xtn …"; witness = the lanes whose
   # high bits are non-zero → the value the truncation corrupts.

D · Heap overflow across library calls
   add_model(a, {"func":"_TIFFmalloc","kind":"alloc","size_arg":0,"name":"buf"})
   add_model(a, {"func":"TIFFScanlineSize","kind":"symbolic","bits":32})
   configure(a, {"limits":{"skip_calls":false}})       # models only run if calls aren't skipped
   add_check(a, {"kind":"oob_write"})                   # no base → vs tracked allocations
   rid = run(a).run_id ; poll get_run(rid)
   # finding: a scanline size writes past the modeled buffer; witness = that size.

E · Invariant / assertion (prove a property or get a counterexample)
   configure(a, {"args":[{"name":"n","mode":"symbolic","size":4}]})
   add_check(a, {"kind":"assert","expr":"ret s>= 0","at_return":true})
   rid = run(a).run_id ; poll get_run(rid)
   # if the invariant can be false: finding with the n that makes the return negative.

════════════════════════════════════════════════════════════════════════
PART 13 — GOTCHAS (the list of things that will waste your time)
════════════════════════════════════════════════════════════════════════

• Addresses IN are a hex string "0x400743" or a function name; addresses OUT (in
  findings) are integers.
• run is ASYNC — always poll get_run until status is "done"/"error" before trusting
  findings.
• No findings? In order: (1) is the input you care about actually SYMBOLIC? (2) are
  your assumptions over-constraining? (3) raise limits (steps/active/seconds); (4) did
  the run even reach the code — check the tree. remove_assumption / remove_check undo.
• Too many/garbage findings or a timeout? You made too much symbolic — pin realistic
  context (concrete args, or concolic snapshot) and constrain with assumptions.
• skip_calls BYPASSES models. If you modeled allocs/reads and see nothing, skip_calls
  is probably on.
• decompile needs IDA connected (get_status.ida.connected). Otherwise use disassemble.
  ida_connect(url) connects to a running IDA's MCP (often on another host/VM).
• A float check needs the arg marked "float":true first.
• For concolic seeding, pass the slide in initial_state.image and SEAL rebases; capture
  at the true function entry or the argument registers are already dead.
• Call get_guide any time to reread this whole manual.
"""

_A = {"addr": {"type": "string", "description": "function address, e.g. \"0x400650\", or name"}}
TOOL_DEFS = [
    {"name": "get_status", "description": "What binary is loaded and whether IDA is connected.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "list_functions", "description": "List functions. `query` filters by name/address substring. "
     "`only` cuts CRT/library noise: \"named\" | \"source\" | \"configured\" | \"interesting\" (any of those) | "
     "\"all\" (default) — essential on big stripped binaries. Returns {total, shown, truncated, functions[]} so "
     "you know when the list was capped by `limit`.",
     "inputSchema": {"type": "object", "properties": {
         "query": {"type": "string"}, "limit": {"type": "integer", "default": 200},
         "only": {"type": "string", "enum": ["all", "named", "source", "configured", "interesting"]}}}},
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
    {"name": "run", "description": "Explore the function's paths using its active scenario, watching for the enabled checks (checks are optional — with none it just enumerates paths). Returns a run_id.",
     "inputSchema": {"type": "object", "properties": _A, "required": ["addr"]}},
    {"name": "path_values", "description": "Per-instruction destination values on one path (node id from get_run's paths): "
     "{addr: {reg, val, store}} — the concrete value of the variable assigned on each decompilation line for that path.",
     "inputSchema": {"type": "object", "properties": {"run_id": {"type": "string"}, "node": {"type": "integer"}}, "required": ["run_id", "node"]}},
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
    {"name": "ida_import", "description": "Import the binary straight from the connected IDA: pulls IDA's input file "
     "(copying it if its path is reachable here, otherwise streaming the bytes over the MCP) and loads it, so you "
     "don't have to open the binary in SEAL separately. Connect first (ida_connect); no binary need be loaded.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "get_struct", "description": "A struct type's member layout from IDA (name, offset, size, type; pointer/nested-struct "
     "members flagged). Use it to set up a pointer-to-struct argument: point the arg at a symbolic buffer and fill "
     "members via configure buffers[].layout.",
     "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
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
    {"kind": "div_by_zero", "summary": "an integer division/remainder whose divisor the inputs can make zero (faults on x86; returns 0 on arm64 but still a logic bug)",
     "fields": {"addr": "0x.. (optional; omit to scan the whole function)"}},
    {"kind": "float_anomaly", "summary": "a floating-point add/sub/mul/div whose result can be NaN or +/-Inf (from special or extreme inputs)",
     "fields": {"addr": "0x.. (optional; omit to scan the whole function)"}},
    {"kind": "oob_write", "summary": "a memory write that can fall outside a buffer. Explicit: give base+size. Modeled: omit base to check writes against every buffer an 'alloc' call model handed out (heap overflows).",
     "fields": {"base": "expression for the buffer start, e.g. a1 or rsp-0x40 (omit for modeled mode)",
                "size": "buffer size in bytes (with base)", "addr": "0x.. (optional single write instruction)"}},
    {"kind": "oob_read", "summary": "like oob_write but for a memory READ that can fall outside a buffer (out-of-bounds read / info leak). Same fields as oob_write.",
     "fields": {"base": "expression for the buffer start (omit for modeled mode)",
                "size": "buffer size in bytes (with base)", "addr": "0x.. (optional single read instruction)"}},
    {"kind": "null_deref", "summary": "a memory read/write through a pointer the inputs can drive into the null page (a null-pointer dereference). angr zero-fills unmapped memory so these never crash on their own — this surfaces them.",
     "fields": {"addr": "0x.. (optional single instruction; omit to scan the whole function)",
                "page": "size of the near-null window in bytes (default 0x1000)"}},
    {"kind": "custom", "summary": "your own Python predicate run at a point (advanced)",
     "fields": {"code": "python (required)", "addr": "0x.. (optional point)"}},
]

_MCP_TOOLS = {
    "get_status": lambda a: _mcp_status_payload(),
    "list_functions": lambda a: _mcp_functions(a.get("query"), a.get("limit", 200), a.get("only")),
    "get_function": lambda a: _mcp_get_function(a["addr"]),
    "disassemble": lambda a: _mcp_disassemble(a["addr"]),
    "decompile": lambda a: _mcp_decompile(a["addr"]),
    "configure": lambda a: _mcp_configure(a["addr"], a["patch"]),
    "add_assumption": lambda a: _mcp_add(a["addr"], assumption=a["expr"]),
    "add_check": lambda a: _mcp_add(a["addr"], check=a["check"]),
    "run": lambda a: _mcp_run(a["addr"]),
    "get_run": lambda a: _mcp_get_run(a["run_id"]),
    "path_values": lambda a: _mcp_path_values(a["run_id"], a["node"]),
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
    "ida_import": lambda a: ida_import(),
    "add_model": lambda a: _mcp_add_model(a["addr"], a["model"]),
    "get_struct": lambda a: (S.ida.struct_layout(a["name"]) if S.ida else _err_no_ida()),
}


def _err_no_ida():
    raise HTTPException(400, "not connected to IDA")


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
            "serverInfo": {"name": "seal", "version": "0.1"},
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
        "server_name": "seal",
        "protocol": MCP_PROTOCOL,
        "mcp_url": base + "/mcp",
        "transport": "MCP Streamable HTTP (POST JSON-RPC; responses are JSON or SSE)",
        "tools": TOOL_DEFS,
        "check_kinds": CHECK_KINDS,
        "guide": GUIDE,
    }


if os.path.isdir(os.path.join(STATIC, "vendor")):
    app.mount("/vendor", StaticFiles(directory=os.path.join(STATIC, "vendor")), name="vendor")
