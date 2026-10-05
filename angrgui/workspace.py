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

ROLE
    The persistence + shape layer for a function's analysis setup. It owns the
    split between per-reach SCENARIOS and SHARED checks, migrates old project files
    to the current shape, and flattens a scenario down to the flat dict the rest of
    SEAL (runner, codegen, MCP) actually consumes. It stores nothing about results —
    only the setup — in ``<binary>.angrgui.json`` beside the binary.

WHY IT'S LIKE THIS
    - Scenarios vs. shared checks: the SAME function is often reached several ways
      (different args / stdin / a concolic snapshot seed), but you want to hunt for
      the same bugs in all of them. So initial state is per-scenario and checks are
      shared — switching scenario changes only how the function is entered.
    - SCEN_FIELDS is the single source of truth for "what is initial state". Every
      place that copies/cleans/flattens a scenario iterates SCEN_FIELDS, so adding a
      field in one spot keeps migrate/clean/flatten consistent. Note `initial_state`
      is in it: the concolic snapshot seed ({kind:"snapshot", pc, regs, mem, symbolic})
      lives ON THE SCENARIO, which is why a seeded setup survives restarts.
    - `flatten()` exists because the runner/codegen/MCP want one flat dict (one
      scenario's state + the shared checks + scenario metadata), not the nested
      structured shape — the structured shape is for editing, the flat shape for use.
    - Saved next to the binary (not in a central DB) so a project is self-contained
      and portable: copy the binary + its .angrgui.json and the setup travels.
    - Atomic save (write tmp + os.replace) so a crash mid-save can't corrupt a project.

EXTENDING
    - New per-scenario initial-state field: add it to SCEN_FIELDS (here) AND teach the
      GUI/MCP that read & write it. `_migrate`, `_clean_scenario` and `flatten` all key
      off SCEN_FIELDS, so they pick it up automatically.
    - New shape migration: handle the old shape inside `_migrate` and keep returning
      the current structured shape; every read path goes through `_migrate`, so one
      place covers load, get and set.

PITFALLS
    - Don't add an initial-state field anywhere but SCEN_FIELDS — a field not listed
      there is silently dropped by `_clean_scenario`/`flatten` and won't persist.
    - Checks are shared: writing checks onto a scenario (instead of cfg["checks"]) is
      wrong; they belong at the function level.
    - `flatten()`'s "scenarios" key is a list of NAMES (plus "active"), not the full
      scenario objects — consumers that want the state read the flat fields directly.
    - `get_function` always returns a migrated copy; mutate and hand back via
      `set_function` — don't assume you're holding the stored object.
"""
from __future__ import annotations

import json
import os
import threading

SUFFIX = ".angrgui.json"

# the initial-state fields that live on a scenario (everything except checks)
SCEN_FIELDS = ("args", "buffers", "assumptions", "stdin", "files", "limits", "models", "initial_state")


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

    # ---------------------------------------- global function-return models
    # Models that apply whenever a function is called, across every analysis:
    #   by_name[func]  -> {kind, ...}      replaces a statically-called function
    #   by_site[hexad] -> {kind, ...}      replaces one (usually indirect) call site
    def function_models(self) -> dict:
        fm = self.data.setdefault("function_models", {})
        fm.setdefault("by_name", {})
        fm.setdefault("by_site", {})
        return fm

    def set_function_models(self, fm: dict):
        self.data["function_models"] = {"by_name": dict((fm or {}).get("by_name") or {}),
                                        "by_site": dict((fm or {}).get("by_site") or {})}
        self.save()

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
