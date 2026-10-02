"""
Optional connection to the official Hex-Rays IDA MCP server, to enrich a
stripped binary with IDA's function names and Hex-Rays decompilation.

The IDA MCP server is a normal MCP server. Start it in HTTP mode next to a
running IDA (or on its own; it can open a headless idalib worker):

    uvx ida-mcp http --host 127.0.0.1 --port 8737

and point this at http://127.0.0.1:8737/mcp .

It is a *code-mode* server: rather than a fixed `decompile` tool it exposes
`execute_python(code, ...)`, where `db` is the current ida-domain Database and
classic IDAPython (`idautils`, `ida_hexrays`, ...) is available. So we get names
and pseudocode by running small IDAPython snippets and reading back the result.

This module speaks the MCP "Streamable HTTP" transport with the standard
library only (no new dependency), and is written to fail softly: if IDA is not
reachable the GUI just keeps angr's `sub_<addr>` names.
"""
from __future__ import annotations

import itertools
import json
import os
import re
import threading
import urllib.error
import urllib.request

PROTOCOL_VERSION = "2025-11-25"
CLIENT_INFO = {"name": "angr-bug-hunter", "version": "0.1"}
DEFAULT_URL = "http://127.0.0.1:8737/mcp"


class MCPError(Exception):
    pass


class MCPClient:
    """A minimal synchronous MCP client over Streamable HTTP (stdlib only)."""

    def __init__(self, url: str, timeout: float = 30.0, host_header: str | None = None):
        self.url = url
        self.timeout = timeout
        # ida-pro-mcp guards against DNS rebinding by rejecting any Host header that
        # isn't the loopback address it listens on. When we reach it through a port
        # forward (e.g. a VM's LAN IP -> 127.0.0.1:13337), send the Host it expects.
        self.host_header = host_header
        self.session_id: str | None = None
        self._ids = itertools.count(1)
        self._initialized = False

    # -- transport ------------------------------------------------------
    def _headers(self) -> dict:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.host_header:
            h["Host"] = self.host_header
        if self._initialized:
            h["MCP-Protocol-Version"] = PROTOCOL_VERSION
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def _post(self, payload: dict, want_result: bool):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(self.url, data=data, headers=self._headers(), method="POST")
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:300]
            raise MCPError(f"IDA MCP HTTP {e.code} at {self.url}: {body}") from None
        except (urllib.error.URLError, OSError) as e:
            raise MCPError(f"cannot reach IDA MCP at {self.url}: {e}") from None
        # the initialize response carries the session id we must echo afterwards
        sid = resp.headers.get("Mcp-Session-Id")
        if sid:
            self.session_id = sid
        try:
            if not want_result:
                resp.read(64)                    # a notification: drain a little, ignore
                return None
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if "text/event-stream" in ctype:
                return self._read_sse(resp, payload.get("id"))
            body = resp.read().decode("utf-8", "replace")
            return json.loads(body) if body.strip() else None
        finally:
            resp.close()

    @staticmethod
    def _read_sse(resp, want_id):
        """Read SSE events until the JSON-RPC response with our id arrives."""
        data_lines: list[str] = []
        for raw in resp:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
            elif line == "":                      # blank line terminates one event
                if data_lines:
                    try:
                        msg = json.loads("\n".join(data_lines))
                    except ValueError:
                        msg = None
                    data_lines = []
                    if isinstance(msg, dict) and msg.get("id") == want_id:
                        return msg
        # stream ended; try any trailing buffered event
        if data_lines:
            try:
                return json.loads("\n".join(data_lines))
            except ValueError:
                pass
        raise MCPError("IDA MCP closed the stream without a response")

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        rid = next(self._ids)
        msg = self._post({"jsonrpc": "2.0", "id": rid, "method": method,
                          "params": params or {}}, want_result=True)
        if not isinstance(msg, dict):
            raise MCPError(f"no response to {method}")
        if msg.get("error"):
            err = msg["error"]
            raise MCPError(f"{method}: {err.get('message', err)}")
        return msg.get("result", {})

    def _notify(self, method: str, params: dict | None = None):
        self._post({"jsonrpc": "2.0", "method": method, "params": params or {}}, want_result=False)

    # -- protocol -------------------------------------------------------
    def initialize(self):
        result = self._rpc("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        })
        self._initialized = True
        self._notify("notifications/initialized")
        return result

    def list_tools(self) -> list[str]:
        return [t["name"] for t in self._rpc("tools/list", {}).get("tools", [])]

    def call_tool(self, name: str, arguments: dict):
        """Call a tool; return its structured result if it has one, else joined text."""
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise MCPError(f"tool {name} failed: {_content_text(result)}")
        if result.get("structuredContent") is not None:
            return result["structuredContent"]
        text = _content_text(result)
        try:
            return json.loads(text)
        except (ValueError, TypeError):
            return text


def _content_text(result: dict) -> str:
    parts = []
    for block in result.get("content", []) or []:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(block.get("text", ""))
    return "\n".join(parts)


# --------------------------------------------------------------------- IDA session
# IDAPython run against the open database via execute_python. Classic IDAPython
# is used (stable across versions); each snippet defines run(db) and returns a
# JSON string, which comes back as structuredContent["result"].

_NAMES_CODE = r"""
def run(db):
    import json, idautils, idc, ida_funcs
    out = []
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if f is None:
            continue
        out.append([int(f.start_ea), idc.get_func_name(f.start_ea) or ""])
    return json.dumps(out)
"""

_DECOMP_CODE = r"""
def run(db):
    import json, ida_funcs, ida_lines
    ea = %d
    f = ida_funcs.get_func(ea)
    if f is None:
        return json.dumps({"error": "no function at %%#x" %% ea})
    try:
        import ida_hexrays
        ida_hexrays.init_hexrays_plugin()
        cf = ida_hexrays.decompile(f.start_ea)
        if cf is None:
            raise RuntimeError("decompiler returned nothing")
        lines = [ida_lines.tag_remove(s.line) for s in cf.get_pseudocode()]
        return json.dumps({"start": int(f.start_ea), "kind": "pseudocode",
                           "code": "\n".join(lines)})
    except Exception as e:
        # no decompiler licence / failure: fall back to disassembly
        import idautils, idc
        rows = []
        for head in idautils.FuncItems(f.start_ea):
            rows.append("%%08x  %%s" %% (head, idc.GetDisasm(head)))
        return json.dumps({"start": int(f.start_ea), "kind": "disassembly",
                           "code": "\n".join(rows), "note": "decompiler unavailable: %%s" %% e})
"""


class IdaSession:
    """A connection to IDA via an MCP server, with cached lookups.

    Two IDA MCP servers are supported and auto-detected from the tools they
    advertise:

    * "community" (mrexodia/ida-pro-mcp): direct `list_funcs` / `decompile`
      tools that read the binary open in the IDA GUI. Works on IDA >= 8.3.
    * "official" (Hex-Rays ida-mcp): a code-mode server whose `execute_python`
      runs IDAPython against a database it opens. Needs IDA >= 9.4.
    """

    def __init__(self, url: str, host_header: str | None = None):
        self.url = url
        self.client = MCPClient(url, host_header=host_header)
        self.flavor: str | None = None
        self.server: str | None = None
        self.instance_id: str | None = None   # official only
        self.db_path: str | None = None
        self.backend: str | None = None
        self._names: dict[int, str] | None = None
        self._decomp: dict[int, dict] = {}
        self._lock = threading.Lock()

    # -- connection -----------------------------------------------------
    def connect(self, binary_path: str | None = None) -> dict:
        info = self.client.initialize()
        self.server = (info.get("serverInfo") or {}).get("name")
        tools = set(self.client.list_tools())
        if "list_funcs" in tools and "decompile" in tools:
            self.flavor = "community"          # reads the open IDA GUI; nothing to open
            self.backend = "gui"
            self.db_path = binary_path
        elif "execute_python" in tools:
            self.flavor = "official"
            self._attach_official(binary_path)
        else:
            raise MCPError(f"{self.url} is an MCP server but not a recognised IDA one "
                           f"(tools: {sorted(tools)[:6]}…)")
        return self.status()

    def _attach_official(self, binary_path):
        want = os.path.basename(binary_path) if binary_path else None
        for inst in _instances(self.client.call_tool("list_databases", {})):
            p = inst.get("path") or ""
            if want and os.path.basename(p) == want:
                self.instance_id, self.backend, self.db_path = (
                    inst.get("instance_id"), inst.get("backend"), p)
                return
        if not binary_path:
            raise MCPError("no database open in IDA; give a binary path to open one")
        opened = self.client.call_tool("open_database", {"path": binary_path, "set_current": True})
        self.instance_id = opened.get("instance_id") if isinstance(opened, dict) else None
        self.backend = opened.get("backend") if isinstance(opened, dict) else None
        self.db_path = binary_path

    def status(self) -> dict:
        return {
            "connected": self.flavor is not None,
            "url": self.url,
            "server": self.server,
            "flavor": self.flavor,
            "backend": self.backend,
            "db_path": self.db_path,
            "name_count": len(self._names) if self._names else 0,
        }

    # -- official: run IDAPython via execute_python ---------------------
    def _run(self, code: str):
        args = {"code": code}
        if self.instance_id:
            args["instance_id"] = self.instance_id
        res = self.client.call_tool("execute_python", args)
        payload = res.get("result", "") if isinstance(res, dict) else res
        if isinstance(res, dict) and res.get("stderr") and not payload:
            raise MCPError(res["stderr"].strip()[:300])
        if isinstance(payload, (dict, list)):
            return payload
        try:
            return json.loads(payload)
        except (ValueError, TypeError):
            raise MCPError(f"unexpected execute_python result: {str(payload)[:200]}")

    # -- data (flavor-dispatched) ---------------------------------------
    def function_names(self, refresh: bool = False) -> dict[int, str]:
        with self._lock:
            if self._names is not None and not refresh:
                return self._names
            if self.flavor == "community":
                res = self.client.call_tool("list_funcs", {"queries": [{"filter": "*", "count": 0}]})
                self._names = {}
                for row in _community_rows(res):
                    try:
                        self._names[int(str(row["addr"]), 16)] = row.get("name") or ""
                    except (KeyError, ValueError):
                        pass
            else:
                self._names = {int(ea): name for ea, name in self._run(_NAMES_CODE) if name}
            return self._names

    def decompile(self, ea: int, force: bool = False) -> dict:
        with self._lock:
            if ea in self._decomp and not force:
                return self._decomp[ea]
            if self.flavor == "community":
                # keep the per-line /*0xADDR*/ markers: the GUI uses them to map
                # pseudocode lines to addresses and overlay coverage / findings.
                res = self.client.call_tool("decompile", {"addr": hex(ea), "include_addresses": True})
                if isinstance(res, dict) and isinstance(res.get("result"), dict):
                    res = res["result"]
                if isinstance(res, dict) and res.get("code"):
                    out = {"requested": ea, "kind": "pseudocode", "code": res["code"]}
                else:
                    out = {"requested": ea, "kind": "error", "code": "", "note": str(res)[:200]}
            else:
                out = self._run(_DECOMP_CODE % ea)
                out.setdefault("requested", ea)
            # IDA decompiles the function *containing* the address, which may not be a
            # function angr split at the same place; report what IDA actually returned.
            fn = _func_name_from_code(out.get("code", ""))
            out["func"] = fn
            names = self._names or {}
            start = next((a for a, n in names.items() if n == fn), None) if fn else None
            out["func_start"] = start
            out["mismatch"] = bool(start is not None and start != ea)
            self._decomp[ea] = out
            return out

    def struct_layout(self, name: str) -> dict:
        """The member layout of a struct type from IDA (name, offset, size, type),
        with pointer/nested-struct members flagged for recursive expansion. Uses the
        plugin's py_eval (IDAPython); raises if that tool isn't available."""
        code = (
            "import ida_typeinf, json\n"
            "NAME = " + json.dumps(name) + "\n"
            "til = ida_typeinf.get_idati()\n"
            "t = ida_typeinf.tinfo_t()\n"
            "ok = t.get_named_type(til, NAME)\n"
            "members = []\n"
            "size = 0\n"
            "if ok:\n"
            "    size = t.get_size()\n"
            "    u = ida_typeinf.udt_type_data_t()\n"
            "    if t.get_udt_details(u):\n"
            "        for m in u:\n"
            "            mt = m.type\n"
            "            tn = ''\n"
            "            try:\n"
            "                if mt.is_ptr():\n"
            "                    po = mt.get_pointed_object()\n"
            "                    tn = str(po.get_type_name() or '') if po is not None else ''\n"
            "                elif mt.is_struct():\n"
            "                    tn = str(mt.get_type_name() or '')\n"
            "            except Exception:\n"
            "                pass\n"
            "            members.append({'name': m.name, 'offset': m.offset//8, 'size': m.size//8,\n"
            "                            'type': str(mt), 'is_ptr': bool(mt.is_ptr()),\n"
            "                            'is_struct': bool(mt.is_struct()), 'type_name': tn})\n"
            "result = json.dumps({'name': NAME, 'size': size, 'members': members, 'found': bool(ok)})\n"
        )
        try:
            res = self.client.call_tool("py_eval", {"code": code})
        except MCPError as e:
            raise MCPError(f"struct inspection needs the IDA 'py_eval' tool, which this server lacks ({e})")
        s = res.get("result") if isinstance(res, dict) else res
        try:
            data = json.loads(s)
        except Exception:
            raise MCPError(f"could not read struct layout from IDA: {str(s)[:200]}")
        if not data.get("found"):
            raise MCPError(f"no type named {name!r} in IDA")
        return data

    def refresh(self) -> dict:
        """Drop caches and re-pull names — after renaming/retyping in IDA."""
        with self._lock:
            self._names = None
            self._decomp = {}
        self.function_names(refresh=True)
        return self.status()


def _instances(listing) -> list[dict]:
    if isinstance(listing, dict):
        return listing.get("instances", []) or []
    return []


def _func_name_from_code(code: str) -> str | None:
    """The function name from a decompiled signature: the identifier before '('."""
    head = code.split("{", 1)[0]
    m = re.search(r"([A-Za-z_]\w*)\s*\(", head)
    return m.group(1) if m else None


def _community_rows(res) -> list[dict]:
    """list_funcs returns {result:[{data:[{addr,name,size},...]}, ...]} (or variants)."""
    if isinstance(res, dict):
        res = res.get("result", res)
    rows: list[dict] = []
    if isinstance(res, list):
        for page in res:
            if isinstance(page, dict) and isinstance(page.get("data"), list):
                rows.extend(d for d in page["data"] if isinstance(d, dict))
            elif isinstance(page, dict) and "addr" in page:
                rows.append(page)
    elif isinstance(res, dict) and isinstance(res.get("data"), list):
        rows.extend(d for d in res["data"] if isinstance(d, dict))
    return rows
