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
"""
from __future__ import annotations

import os
import uuid
import logging

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .engine import Binary
from .runner import Run
from .workspace import Workspace
from .checks import CUSTOM_TEMPLATE

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
        self.load_status = {"loading": False, "message": "", "error": None}


S = _Session()


# --------------------------------------------------------------------------- models
class LoadReq(BaseModel):
    path: str


class RunReq(BaseModel):
    func_addr: int
    args: list = []
    buffers: list = []
    assumptions: list = []
    stdin: dict | None = None
    checks: list = []
    limits: dict = {}


class ConfigReq(BaseModel):
    args: list = []
    buffers: list = []
    assumptions: list = []
    stdin: dict | None = None
    checks: list = []
    limits: dict = {}


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
        cfg = saved.get(str(f["addr"]))
        f["configured"] = bool(cfg and (cfg.get("checks") or cfg.get("assumptions")))
        f["check_count"] = len(cfg.get("checks", [])) if cfg else 0
    return {"functions": fns}


@app.get("/api/function/{addr}")
def function(addr: int):
    b = _need_binary()
    fn = b.get_function(addr)
    if fn is None:
        raise HTTPException(404, "no such function")
    disasm = b.disassemble(addr)
    dwarf = [v.to_json(b.word_bytes) for v in b.dwarf_vars(addr)]
    cfg = S.workspace.get_function(addr) if S.workspace else Workspace._default_func()
    # seed default args from DWARF / calling convention if the user hasn't set any
    if not cfg.get("args"):
        for a in [f for f in b.function_list() if f["addr"] == addr][0]["args"]:
            cfg.setdefault("args", []).append({
                "name": a["name"], "mode": "symbolic",
                "size": a["size"] or b.word_bytes, "signed": a.get("signed", True),
            })
    return {"disasm": disasm, "dwarf": dwarf, "config": cfg,
            "return_heads": [hex(h) for h in b.return_block_heads(addr)]}


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
    S.workspace.set_function(addr, req.model_dump())
    return {"ok": True}


@app.post("/api/run")
def run(req: RunReq):
    b = _need_binary()
    if b.get_function(req.func_addr) is None:
        raise HTTPException(404, "no such function")
    run_id = uuid.uuid4().hex[:12]
    spec = req.model_dump()
    r = Run(b, spec)
    S.runs[run_id] = r
    r.start()
    return {"run_id": run_id}


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


@app.get("/api/custom-template")
def custom_template():
    from .checks import CUSTOM_TEMPLATE
    return {"template": CUSTOM_TEMPLATE}


if os.path.isdir(os.path.join(STATIC, "vendor")):
    app.mount("/vendor", StaticFiles(directory=os.path.join(STATIC, "vendor")), name="vendor")
