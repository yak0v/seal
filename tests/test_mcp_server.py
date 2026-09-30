"""
The built-in MCP server: an agent can list functions, configure a function
(assumptions/checks/limits), run, and read results — all against the same
session the GUI uses, with actions published to the live event bus.

Exercised by calling the JSON-RPC handler directly (no HTTP needed).
"""
import json
import os
import subprocess
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import angrgui.server as srv                        # noqa: E402
from angrgui.engine import Binary                   # noqa: E402
from angrgui.workspace import Workspace             # noqa: E402

BIN = os.path.join(ROOT, "samples", "vuln")


@pytest.fixture(scope="module")
def loaded():
    if not os.path.exists(BIN):
        subprocess.check_call(["make", "-C", os.path.join(ROOT, "samples")])
    srv.S.binary = Binary(BIN, progress=lambda m: None)
    srv.S.workspace = Workspace(BIN + ".mcptest")
    srv.S.runs = {}
    yield srv
    try:
        os.remove(BIN + ".mcptest.angrgui.json")
    except OSError:
        pass


def _call(tool, args):
    msg = srv._handle_mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": tool, "arguments": args}})
    result = msg["result"]
    text = "".join(b["text"] for b in result["content"])
    assert not result.get("isError"), text
    try:
        return json.loads(text)
    except ValueError:
        return text


def _addr(binary, name):
    return [f for f in binary.function_list() if f["name"] == name][0]["addr"]


def test_initialize_and_tools_list(loaded):
    init = srv._handle_mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init["result"]["serverInfo"]["name"] == "angr-bug-hunter"
    names = {t["name"] for t in srv._handle_mcp(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]}
    assert {"list_functions", "configure", "add_assumption", "add_check", "run", "get_run"} <= names
    assert srv._handle_mcp({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_agent_flow_reaches_abort(loaded):
    fa = _addr(loaded.S.binary, "route")
    abort = [f.addr for f in loaded.S.binary.cfg.kb.functions.values() if f.name == "abort"][0]

    events = []
    loaded.BUS._events.clear()

    cfg = _call("configure", {"addr": hex(fa), "patch": {
        "args": [{"name": "cmd", "mode": "symbolic", "size": 4, "signed": True},
                 {"name": "x", "mode": "symbolic", "size": 4, "signed": True}],
        "checks": [{"kind": "reach", "addr": hex(abort)}],
        "limits": {"steps": 60, "active": 300, "seconds": 30, "loop_bound": 8}}})
    assert cfg["checks"][0]["addr"] == abort          # hex string coerced to int

    _call("add_assumption", {"addr": hex(fa), "expr": "cmd s>= 0"})
    fn = _call("get_function", {"addr": hex(fa)})
    assert fn["config"]["assumptions"] == ["cmd s>= 0"]

    run_id = _call("run", {"addr": hex(fa)})["run_id"]
    for _ in range(60):
        res = _call("get_run", {"run_id": run_id})
        if res["status"] in ("done", "error"):
            break
        time.sleep(0.5)
    assert res["status"] == "done", res.get("error")
    reach = [h for h in res["findings"] if h["kind"] == "reach"]
    assert reach and reach[0]["witness"]["cmd"]["s"] == 2 and reach[0]["witness"]["x"]["s"] == 4242
    assert res["paths"], "expected a path tree"

    # the whole thing was published to the event bus (what the GUI shows live)
    kinds = [e["type"] for e in loaded.BUS._events]
    assert "config" in kinds and "run" in kinds and "run_status" in kinds and "finding" in kinds


def test_skip_calls_lets_a_caller_branch(loaded):
    """main() calls route/alloc_msg; skip_calls keeps exploration in main so it branches."""
    fa = _addr(loaded.S.binary, "main")
    _call("configure", {"addr": hex(fa), "patch": {
        "args": [], "stdin": {"mode": "symbolic", "size": 8},
        "checks": [{"kind": "reach", "addr": hex(fa + 4)}],
        "limits": {"steps": 40, "seconds": 20, "loop_bound": 6, "skip_calls": True}}})
    run_id = _call("run", {"addr": hex(fa)})["run_id"]
    for _ in range(50):
        res = _call("get_run", {"run_id": run_id})
        if res["status"] in ("done", "error"):
            break
        time.sleep(0.5)
    assert res["status"] == "done", res.get("error")
    # with calls skipped, main's own dispatch on the stdin bytes produces branches
    assert len([p for p in res["paths"] if p["cond"]]) >= 2
