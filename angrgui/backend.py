"""
SEAL's analysis-backend seam.

The GUI and the HTTP/MCP server speak ONE neutral vocabulary — functions, runs,
a path tree, findings, per-line values, constraints — and never import a specific
analysis framework. A *backend* turns that vocabulary into work. angr is the first
backend (``AngrBackend``); a future Triton / QBDI / concolic backend implements the
same ``Backend`` interface and the GUI/MCP keep working unchanged.

THE NEUTRAL DATA CONTRACT  (plain JSON-able dicts — this is what every backend emits
and what the GUI/MCP consume; keep these shapes stable across backends)
----------------------------------------------------------------------------------
BinaryInfo      {path, name, arch, bits, entry, pie, has_dwarf, has_lines, function_count}
FunctionSummary {addr:int, name:str, size:int, block_count:int, named:bool,
                 returning:bool, has_source:bool, args:[{name,type,size,signed}]}
RunSpec         what to analyse (backend-agnostic):
                {func_addr:int,
                 initial_state:{kind:"call"|"snapshot", ...},   # how the start state is built
                 args:[{name,mode:"symbolic"|"concrete",size,signed,value?,float?}],
                 buffers:[{arg,size,layout?}], assumptions:[expr], stdin?, files?,
                 models:[...call models...], checks:[{kind,...}],
                 limits:{steps,active,seconds,skip_calls,loop,find?,avoid?}}
RunSnapshot     {status:"pending"|"running"|"done"|"error"|"cancelled",
                 error, progress:{...}, summary:{...},
                 hits:[Finding], tree:[PathNode]}
PathNode        {id, parent, depth, kind, addr, cur, start:{file,line,text}?,
                 cond:str?, decided_at:{addr,line}?, blocks:[int], lines:[int],
                 calls:[str], end:{reason,text,...}?, ret:str?,
                 example:{var->Value}?, hits:[id]}
Finding         {check_id, kind, addr:int, message, witness:{var->Value},
                 extra:{node:int, path:[...], write_addr?, buffer_base?, buffer_size?, ...}}
Value           a concrete input/witness value: {u:int, s:int, hex:str, bits:int}
                (byte inputs — stdin/files/buffers — are plain strings instead)
PathValues      {hex_addr: {reg:str, val:hex} | {store:{addr:hex,val:hex}}}
                the value assigned on each line of a path (for the decompilation overlay)

A backend MAY also expose static views (disassembly, CFG, DWARF vars, names, source
lines). Those live on ``Backend.binary`` — the "static model" object — whose method
surface is the contract in :class:`StaticModel` below. angr's ``engine.Binary``
already satisfies it; another backend supplies a compatible object.

WHY IT'S LIKE THIS
------------------
The seam exists so the GUI and MCP are framework-ignorant: they only ever touch the
neutral JSON contract above, never an angr/claripy object. That is the single rule
that lets a new engine drop in without touching the front-end or the ~26 server
call-sites (``server.S.backend`` is the one handle; ``S.binary``/``S.runs`` are compat
shims over it).

EXTENDING  (add a framework — Triton, QBDI, a concolic engine, …)
-----------------------------------------------------------------
1. Subclass :class:`Backend`; implement ``binary`` (a :class:`StaticModel`), ``runs``,
   ``start_run(run_id, spec, on_event)``, ``run_snapshot``, ``run_values``, ``cancel_run``.
2. Emit ONLY the neutral shapes (BinaryInfo / FunctionSummary / RunSnapshot / PathNode /
   Finding / Value / PathValues). Translate your engine's concepts INTO them; never leak
   engine types outward.
3. ``register_backend("name", factory)`` and select it via ``make_backend(kind="name")``.
   Nothing in the GUI/MCP should need editing.

PITFALLS
--------
* The contract is the API. If a field's meaning drifts (e.g. ``Finding.addr`` becomes a
  hex string instead of int), every backend and the whole front-end silently disagree —
  keep these shapes stable and typed as documented.
* ``start_run`` is async/background in spirit; stream progress via ``on_event`` and let
  ``run_snapshot`` report status — don't block.
* A backend that can't provide a static view still needs a ``binary`` satisfying
  :class:`StaticModel` (even if some methods raise ``NotImplementedError``); the server
  assumes it exists.
"""
from __future__ import annotations

import abc
import uuid
from typing import Any, Callable, Protocol, runtime_checkable


@runtime_checkable
class StaticModel(Protocol):
    """The static-analysis surface a backend's ``.binary`` must provide. These return
    the neutral shapes above (FunctionSummary lists, disasm dicts, CFG dicts, …)."""
    arch: Any

    def info(self) -> dict: ...
    def function_list(self) -> list[dict]: ...
    def get_function(self, addr: int): ...
    def disassemble(self, addr: int) -> dict: ...
    def cfg_graph(self, addr: int) -> dict: ...
    def return_block_heads(self, addr: int) -> list[int]: ...
    def dwarf_vars(self, addr: int) -> list: ...


class Backend(abc.ABC):
    """One analysis framework behind SEAL. Owns a static model (:attr:`binary`) and
    the lifecycle of *runs* (symbolic/concolic explorations). Everything it returns is
    the neutral contract documented at the top of this module."""

    #: short identifier, e.g. "angr", "triton"
    name: str = "backend"

    # -- static model -------------------------------------------------------
    @property
    @abc.abstractmethod
    def binary(self) -> StaticModel: ...

    @property
    @abc.abstractmethod
    def runs(self) -> dict: ...

    def info(self) -> dict:
        return self.binary.info()

    def function_list(self) -> list[dict]:
        return self.binary.function_list()

    # -- run lifecycle (the framework-specific core) ------------------------
    @abc.abstractmethod
    def start_run(self, run_id: str, spec: dict, on_event: Callable | None = None) -> str:
        """Begin an exploration; return run_id. Progress is reported via on_event(kind, **data)."""

    @abc.abstractmethod
    def run_snapshot(self, run_id: str) -> dict | None:
        """Current RunSnapshot for a run, or None if unknown."""

    @abc.abstractmethod
    def run_values(self, run_id: str, example: dict) -> dict:
        """PathValues for a path, given that path's concrete `example` inputs."""

    @abc.abstractmethod
    def cancel_run(self, run_id: str) -> bool: ...

    @staticmethod
    def new_run_id() -> str:
        return uuid.uuid4().hex[:12]


class AngrBackend(Backend):
    """angr implementation: wraps ``engine.Binary`` (static model) and ``runner.Run``
    (explorations). Thin — it delegates to the existing angr code."""

    name = "angr"

    def __init__(self, binary=None, path: str | None = None, progress=None, **opts):
        if binary is None:
            from .engine import Binary
            binary = Binary(path, progress=progress, target_funcs=opts.get("target_funcs"))
        self._binary = binary
        self._runs: dict = {}

    @property
    def binary(self):
        return self._binary

    @property
    def runs(self) -> dict:
        return self._runs

    def start_run(self, run_id: str, spec: dict, on_event: Callable | None = None) -> str:
        from .runner import Run
        r = Run(self._binary, spec, on_event=on_event)
        self._runs[run_id] = r
        r.start()
        return run_id

    def run_snapshot(self, run_id: str) -> dict | None:
        r = self._runs.get(run_id)
        return r.snapshot() if r is not None else None

    def run_values(self, run_id: str, example: dict) -> dict:
        from .runner import trace_assignments
        r = self._runs.get(run_id)
        return trace_assignments(self._binary, r.spec, example) if r is not None else {}

    def cancel_run(self, run_id: str) -> bool:
        r = self._runs.get(run_id)
        if r is None:
            return False
        r.cancel()
        return True


#: registry of available backends, by name
_BACKENDS: dict[str, type[Backend]] = {"angr": AngrBackend}


def register_backend(name: str, cls: type[Backend]) -> None:
    _BACKENDS[name] = cls


def make_backend(kind: str = "angr", **opts) -> Backend:
    """Construct a backend by name (default angr). Future: make_backend('triton', …)."""
    try:
        cls = _BACKENDS[kind]
    except KeyError:
        raise ValueError(f"unknown analysis backend {kind!r}; have {sorted(_BACKENDS)}")
    return cls(**opts)
