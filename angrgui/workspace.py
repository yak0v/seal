"""
Per-binary workspace: the assumptions and checks the user has set up for each
function, saved as JSON next to the binary (``<binary>.angrgui.json``) so a
project survives restarts.

A function's setup is split into *scenarios* and shared *checks*.  A scenario is
one way of reaching the function — its own initial state (arguments, symbolic
stdin / files, assumptions, limits).  The checks (reach / avoid / assert / …)
are shared across all scenarios of the function; only the initial state changes
when you switch scenario.  Stored shape::

    {"checks": [...],
     "scenarios": [{"name", "args", "buffers", "assumptions", "stdin", "files", "limits"}, ...],
     "active": 0}

Older project files stored the initial state flat alongside the checks; those are
migrated into a single "Default" scenario on load.
"""
from __future__ import annotations

import json
import os
import threading

SUFFIX = ".angrgui.json"

# the initial-state fields that live on a scenario (everything except checks)
SCEN_FIELDS = ("args", "buffers", "assumptions", "stdin", "files", "limits", "models")


class Workspace:
    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.store_path = self.binary_path + SUFFIX
        self._lock = threading.Lock()
        self.data = {"functions": {}, "meta": {}}
        self.load()

    def load(self):
        if os.path.isfile(self.store_path):
            try:
                with open(self.store_path) as fh:
                    self.data = json.load(fh)
                self.data.setdefault("functions", {})
                self.data.setdefault("meta", {})
            except (OSError, ValueError):
                pass

    def save(self):
        with self._lock:
            tmp = self.store_path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(self.data, fh, indent=2)
            os.replace(tmp, self.store_path)

    # ------------------------------------------------------------- per function
    def get_function(self, addr: int) -> dict:
        """The function's setup in the structured (scenarios) shape."""
        return self._migrate(self.data["functions"].get(str(addr)))

    def set_function(self, addr: int, cfg: dict):
        self.data["functions"][str(addr)] = self._migrate(cfg)
        self.save()

    # ------------------------------------------------------------- shape helpers
    @staticmethod
    def _default_scenario(name: str = "Default") -> dict:
        return {"name": name, "args": [], "buffers": [], "assumptions": [],
                "stdin": None, "files": [], "limits": {}, "models": []}

    @staticmethod
    def _default_func() -> dict:
        return {"checks": [], "scenarios": [Workspace._default_scenario()], "active": 0}

    @staticmethod
    def _migrate(cfg: dict | None) -> dict:
        """Accept either the new (scenarios) or the old (flat) shape -> new shape."""
        cfg = dict(cfg or {})
        if cfg.get("scenarios"):
            out = {"checks": list(cfg.get("checks", [])),
                   "scenarios": [Workspace._clean_scenario(s, i) for i, s in enumerate(cfg["scenarios"])],
                   "active": int(cfg.get("active", 0) or 0)}
            out["active"] = max(0, min(out["active"], len(out["scenarios"]) - 1))
            return out
        # legacy flat -> one "Default" scenario carrying the initial state
        sc = Workspace._default_scenario()
        for k in SCEN_FIELDS:
            if k in cfg:
                sc[k] = cfg[k]
        return {"checks": list(cfg.get("checks", [])), "scenarios": [sc], "active": 0}

    @staticmethod
    def _clean_scenario(s: dict, i: int) -> dict:
        out = Workspace._default_scenario(s.get("name") or f"Scenario {i + 1}")
        for k in SCEN_FIELDS:
            if k in s:
                out[k] = s[k]
        return out

    @staticmethod
    def active_scenario(cfg: dict) -> dict:
        cfg = Workspace._migrate(cfg)
        return cfg["scenarios"][cfg["active"]]

    @staticmethod
    def flatten(cfg: dict, idx: int | None = None) -> dict:
        """Merge one scenario's initial state with the shared checks into the flat
        shape used by the runner, script generator and MCP tools."""
        cfg = Workspace._migrate(cfg)
        if idx is None:
            idx = cfg["active"]
        idx = max(0, min(idx, len(cfg["scenarios"]) - 1))
        sc = cfg["scenarios"][idx]
        out = {k: sc.get(k) for k in SCEN_FIELDS}
        out["checks"] = list(cfg.get("checks", []))
        # scenario metadata so agents can see / pick among them
        out["scenarios"] = [s.get("name") or f"Scenario {j + 1}" for j, s in enumerate(cfg["scenarios"])]
        out["active"] = idx
        return out

    def all(self) -> dict:
        return self.data
