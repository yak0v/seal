"""
The IDA MCP client, exercised against fake Streamable-HTTP MCP servers that
mimic both supported IDA servers:

* "official" Hex-Rays ida-mcp: initialize + session id, list_databases /
  open_database / execute_python returning {result, stdout, stderr};
* "community" mrexodia/ida-pro-mcp: list_funcs / decompile tools.

No real IDA is needed; this verifies the transport, flavor auto-detection, and
the names/decompilation parsing so the integration works against the real
servers unchanged (both were also verified live).
"""
import base64
import hashlib
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from angrgui.idamcp import IdaSession, MCPClient, MCPError   # noqa: E402

FUNCS = [[0x400650, "validate"], [0x4006f0, "dispatch"], [0x400230, "main"]]
INPUT_BYTES = bytes(range(256)) * 37 + b"\xde\xad\xbe\xef"   # the fake IDA's "input file"
INPUT_PATH = "/ida-host/only/target.bin"                     # not reachable on this machine
PSEUDOCODE = "int __fastcall validate(unsigned int user, unsigned int code)\n{\n  return 0;\n}"


class _Base(BaseHTTPRequestHandler):
    FLAVOR = "official"

    def log_message(self, *a):
        pass

    def _send(self, obj, sse, session=None):
        body = json.dumps(obj).encode()
        self.send_response(200)
        if session:
            self.send_header("Mcp-Session-Id", session)
        self.send_header("Content-Type", "text/event-stream" if sse else "application/json")
        self.end_headers()
        self.wfile.write(b"event: message\ndata: " + body + b"\n\n" if sse else body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        method, rid = req.get("method"), req.get("id")
        if method == "initialize":
            name = "ida" if self.FLAVOR == "official" else "ida-pro-mcp"
            return self._send({"jsonrpc": "2.0", "id": rid,
                               "result": {"protocolVersion": "2025-11-25",
                                          "serverInfo": {"name": name},
                                          "capabilities": {"tools": {}}}},
                              sse=False, session="sess-123")
        if method == "notifications/initialized":
            self.send_response(202); self.end_headers(); return
        if method == "tools/list":
            default = (["list_databases", "open_database", "execute_python"]
                       if self.FLAVOR == "official" else ["list_funcs", "decompile", "rename"])
            names = getattr(self, "TOOLS", None) or default
            return self._send({"jsonrpc": "2.0", "id": rid,
                               "result": {"tools": [{"name": t, "inputSchema": {}} for t in names]}},
                              sse=True)
        if method == "tools/call":
            p = req["params"]
            out = self._tool(p["name"], p.get("arguments", {}))
            return self._send({"jsonrpc": "2.0", "id": rid,
                               "result": {"structuredContent": out,
                                          "content": [{"type": "text", "text": json.dumps(out)}]}},
                              sse=True)
        self._send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "no"}}, sse=False)


class FakeOfficial(_Base):
    FLAVOR = "official"

    def _tool(self, name, args):
        if name == "list_databases":
            return {"instances": []}
        if name == "open_database":
            return {"instance_id": "db-1", "backend": "idalib", "status": "current"}
        if name == "execute_python":
            code = args.get("code", "")
            if "idautils.Functions" in code:
                return {"result": json.dumps(FUNCS), "stdout": "", "stderr": ""}
            if "base64.b64encode" in code:                 # read_input_file chunk
                off = int(re.search(r"seek\((\d+)\)", code).group(1))
                ln = int(re.search(r"read\((\d+)\)", code).group(1))
                data = INPUT_BYTES[off:off + ln]
                return {"result": json.dumps({"b64": base64.b64encode(data).decode(),
                                              "n": len(data)}), "stdout": "", "stderr": ""}
            if "get_input_file_path" in code:              # input_file_info
                return {"result": json.dumps({"path": INPUT_PATH, "name": "target.bin",
                                              "size": len(INPUT_BYTES),
                                              "md5": hashlib.md5(INPUT_BYTES).hexdigest(),
                                              "readable": True}), "stdout": "", "stderr": ""}
            if "decompile" in code:
                return {"result": json.dumps({"start": 0x400650, "kind": "pseudocode",
                                              "code": PSEUDOCODE}), "stdout": "", "stderr": ""}
        return {"result": "null", "stdout": "", "stderr": ""}


class FakeCommunity(_Base):
    FLAVOR = "community"
    # metadata-only server: no python-eval tool, but a get_metadata tool
    TOOLS = ["list_funcs", "decompile", "rename", "get_metadata"]

    def _tool(self, name, args):
        if name == "list_funcs":
            data = [{"addr": hex(ea), "name": nm, "size": "0x10"} for ea, nm in FUNCS]
            return {"result": [{"data": data}]}
        if name == "decompile":
            return {"addr": args.get("addr"), "code": PSEUDOCODE, "line_count": 3}
        if name == "get_metadata":
            return {"result": {"path": INPUT_PATH, "module": "target.bin",
                               "size": len(INPUT_BYTES),
                               "md5": hashlib.md5(INPUT_BYTES).hexdigest()}}
        return {}


class FakeCommunityEval(_Base):
    """A richer community server (like mrexodia/ida-pro-mcp with py_eval): runs
    arbitrary IDAPython that sets `result`. This mirrors the real server #9 was
    validated against, which streams input-file bytes over py_eval."""
    FLAVOR = "community"
    TOOLS = ["list_funcs", "decompile", "rename", "py_eval", "get_bytes"]

    def _tool(self, name, args):
        if name == "list_funcs":
            data = [{"addr": hex(ea), "name": nm, "size": "0x10"} for ea, nm in FUNCS]
            return {"result": [{"data": data}]}
        if name == "decompile":
            return {"addr": args.get("addr"), "code": PSEUDOCODE, "line_count": 3}
        if name == "py_eval":
            code = args.get("code", "")
            if "base64.b64encode" in code:                 # read_input_file chunk
                off = int(re.search(r"seek\((\d+)\)", code).group(1))
                ln = int(re.search(r"read\((\d+)\)", code).group(1))
                data = INPUT_BYTES[off:off + ln]
                return {"result": json.dumps({"b64": base64.b64encode(data).decode(),
                                              "n": len(data)})}
            if "get_input_file_path" in code:              # input_file_info
                return {"result": json.dumps({"path": INPUT_PATH, "name": "target.bin",
                                              "size": len(INPUT_BYTES),
                                              "md5": hashlib.md5(INPUT_BYTES).hexdigest(),
                                              "readable": True})}
        return {}


def _serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture()
def official():
    srv = _serve(FakeOfficial)
    yield f"http://127.0.0.1:{srv.server_address[1]}/mcp"
    srv.shutdown()


@pytest.fixture()
def community():
    srv = _serve(FakeCommunity)
    yield f"http://127.0.0.1:{srv.server_address[1]}/mcp"
    srv.shutdown()


@pytest.fixture()
def community_eval():
    srv = _serve(FakeCommunityEval)
    yield f"http://127.0.0.1:{srv.server_address[1]}/mcp"
    srv.shutdown()


def test_handshake_and_session(official):
    c = MCPClient(official)
    assert c.initialize()["protocolVersion"] == "2025-11-25"
    assert c.session_id == "sess-123"


def test_official_flavor(official):
    s = IdaSession(official)
    st = s.connect("/somewhere/machine")
    assert st["flavor"] == "official" and s.instance_id == "db-1"
    names = s.function_names()
    assert names[0x400650] == "validate" and names[0x4006f0] == "dispatch"
    assert s.function_names() is names                     # cached
    assert s.decompile(0x400650)["kind"] == "pseudocode"


def test_community_flavor(community):
    s = IdaSession(community)
    st = s.connect()                                       # no path needed: uses the open GUI
    assert st["flavor"] == "community" and st["server"] == "ida-pro-mcp"
    names = s.function_names()
    assert names[0x400650] == "validate" and len(names) == 3
    d = s.decompile(0x400650)
    assert d["kind"] == "pseudocode" and "validate(" in d["code"]
    assert s.decompile(0x400650) is s._decomp[0x400650]    # cached


def test_official_input_info_and_stream_fetch(official, tmp_path):
    # #9: pull the binary straight from IDA. The fake reports a path that isn't
    # reachable on this machine, so fetch streams the bytes over the MCP.
    s = IdaSession(official)
    s.connect("/ida-host/only/target.bin")
    info = s.input_file_info()
    assert info["size"] == len(INPUT_BYTES) and info["name"] == "target.bin"
    chunk = s.read_input_file(10, 32)
    assert chunk == INPUT_BYTES[10:42]
    dest = tmp_path / "target.bin"
    res = s.fetch_input_file(str(dest))
    assert res["via"] == "mcp-stream" and res["size"] == len(INPUT_BYTES)
    assert dest.read_bytes() == INPUT_BYTES                # byte-for-byte reconstruction


def test_fetch_prefers_local_copy_when_path_reachable(official, tmp_path):
    # When IDA's input path IS reachable here (shared folder / same host), copy it
    # instead of streaming — no transfer.
    real = tmp_path / "on-disk.bin"
    real.write_bytes(INPUT_BYTES)
    s = IdaSession(official)
    s.connect("/ida-host/only/target.bin")
    s.input_file_info = lambda: {"path": str(real), "name": "on-disk.bin",
                                 "size": len(INPUT_BYTES), "readable": True}
    dest = tmp_path / "copied.bin"
    res = s.fetch_input_file(str(dest))
    assert res["via"] == "local-path" and dest.read_bytes() == INPUT_BYTES


def test_community_metadata_only_input_info(community):
    # a community server with no python-eval tool: info via get_metadata, but it
    # cannot stream bytes, so fetch of an unreachable path must fail cleanly.
    s = IdaSession(community)
    s.connect()
    info = s.input_file_info()
    assert info["size"] == len(INPUT_BYTES) and info["path"] == INPUT_PATH
    with pytest.raises(MCPError):
        s.fetch_input_file("/tmp/should-not-be-written")


def test_community_py_eval_stream_fetch(community_eval, tmp_path):
    # the real-world case (#9 validated against this): a community server with
    # py_eval streams the input file byte-for-byte when its path isn't reachable here.
    s = IdaSession(community_eval)
    s.connect()
    assert s.flavor == "community"
    info = s.input_file_info()
    assert info["size"] == len(INPUT_BYTES) and info["name"] == "target.bin"
    dest = tmp_path / "target.bin"
    res = s.fetch_input_file(str(dest))
    assert res["via"] == "mcp-stream"
    assert dest.read_bytes() == INPUT_BYTES


def test_unreachable_server_raises_cleanly():
    with pytest.raises(MCPError):
        IdaSession("http://127.0.0.1:9/mcp").connect("/somewhere/machine")
