"""
Session store: everything SEAL knows about analysing one binary, in a single
SQLite file (``<binary>.sdb`` — a "seal db") so a whole session survives restarts
and can be saved/loaded explicitly.

A session holds:
  - **meta**: which binary this session is for (path + sha256 + size), the IDA URL,
    timestamps, and the global function-return models.
  - **functions**: each function's setup, split into per-reach *scenarios* and shared
    *checks* (see the shape notes below).
  - **runs**: every run's record (findings + summary + metadata) AND its FULL snapshot
    (the path tree), so clicking a past run still works after a restart.
  - **targets**: the TODO queue of functions to test next.

A function's setup is split into *scenarios* and shared *checks*.  A scenario is one
way of reaching the function — its own initial state (arguments, symbolic stdin /
files, assumptions, limits, snapshot seed).  The checks are shared across all
scenarios; only the initial state changes when you switch scenario.  Structured shape::

    {"checks": [...],
     "scenarios": [{"name", "args", "buffers", "assumptions", "stdin", "files", "limits",
                    "models", "initial_state", "return_bounds"}, ...],
     "active": 0}

WHY SQLite (not the old one-JSON-file)
    - The NEW thing here is storing full run snapshots (large path trees), many of them.
      JSON rewrote the WHOLE file on every change (and config saves are constant), and
      had to parse every tree just to list runs. SQLite writes only the changed row and
      lists runs from lightweight columns, loading a tree only when that run is opened.
    - Shared access (human GUI + agents over MCP) is serialised safely; a crash mid-write
      leaves the DB consistent (transactional) instead of corrupting the whole project.
    - It is one portable file (``.sdb``) the user can Save As / Load as a named session.

MIGRATION
    Opening a binary whose session is still the legacy ``<binary>.angrgui.json`` (and no
    ``.sdb`` yet) imports it automatically, so existing projects are not lost.

EXTENDING
    - New per-scenario initial-state field: add it to SCEN_FIELDS. `_migrate`,
      `_clean_scenario` and `flatten` all key off it.
    - The public API (get/set/update_function, add_run/runs/get_run_record/update_run,
      targets, function_models, flatten/migrate) is unchanged from the JSON version, so
      callers and tests keep working; storage is the only thing that moved.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time

SUFFIX = ".sdb"
LEGACY_SUFFIX = ".angrgui.json"
FORMAT_VERSION = 1
MAX_RUNS = 1000               # cap stored run records (newest kept)
MAX_SNAPSHOTS = 250           # cap stored full snapshots (newest kept); older runs keep their record

# the initial-state fields that live on a scenario (everything except checks)
SCEN_FIELDS = ("args", "buffers", "assumptions", "stdin", "files", "limits", "models", "initial_state", "return_bounds")


def _sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


class Workspace:
    def __init__(self, binary_path: str, store_path: str | None = None):
        self.binary_path = os.path.abspath(binary_path) if binary_path else None
        # the session file: an explicit store_path, else <binary>.sdb beside the binary.
        self.store_path = os.path.abspath(store_path) if store_path else (self.binary_path + SUFFIX)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.store_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        self._import_legacy_if_empty()
        self._init_meta()

    # ------------------------------------------------------------------ schema / meta
    def _init_schema(self):
        with self._lock:
            self._conn.executescript(
                "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);"
                "CREATE TABLE IF NOT EXISTS functions (addr TEXT PRIMARY KEY, config TEXT);"
                "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, func INTEGER, when_ REAL, "
                "  record TEXT, snapshot TEXT);"
                "CREATE INDEX IF NOT EXISTS runs_func ON runs(func);"
                "CREATE INDEX IF NOT EXISTS runs_when ON runs(when_);"
                "CREATE TABLE IF NOT EXISTS targets (func INTEGER PRIMARY KEY, data TEXT);")
            self._conn.commit()

    def _init_meta(self):
        now = time.time()
        with self._lock:
            if self._get_meta("format_version") is None:
                self._set_meta("format_version", FORMAT_VERSION)
                self._set_meta("created", now)
            # record the binary identity so a loaded session knows what it is for
            if self.binary_path and os.path.isfile(self.binary_path):
                if self._get_meta("binary_path") is None:
                    self._set_meta("binary_path", self.binary_path)
                    self._set_meta("binary_size", os.path.getsize(self.binary_path))
                    self._set_meta("binary_sha256", _sha256(self.binary_path))
            elif self.binary_path and self._get_meta("binary_path") is None:
                self._set_meta("binary_path", self.binary_path)

    def _get_meta(self, key: str):
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else None

    def _set_meta(self, key: str, value):
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                               (key, json.dumps(value)))
            self._conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('modified', ?)",
                               (json.dumps(time.time()),))
            self._conn.commit()

    def get_meta(self, key: str):
        with self._lock:
            return self._get_meta(key)

    def set_meta(self, key: str, value):
        self._set_meta(key, value)

    def info(self) -> dict:
        """A summary of this session (for GUI/MCP): the binary it is for, counts, times."""
        with self._lock:
            nf = self._conn.execute("SELECT COUNT(*) c FROM functions").fetchone()["c"]
            nr = self._conn.execute("SELECT COUNT(*) c FROM runs").fetchone()["c"]
            ns = self._conn.execute("SELECT COUNT(*) c FROM runs WHERE snapshot IS NOT NULL").fetchone()["c"]
            return {
                "store_path": self.store_path,
                "binary_path": self._get_meta("binary_path"),
                "binary_sha256": self._get_meta("binary_sha256"),
                "binary_size": self._get_meta("binary_size"),
                "ida_url": self._get_meta("ida_url"),
                "created": self._get_meta("created"),
                "modified": self._get_meta("modified"),
                "functions_configured": nf, "runs": nr, "runs_with_snapshot": ns,
            }

    def binary_matches(self, path: str) -> tuple[bool, str]:
        """Does `path` look like the binary this session is for? Returns (ok, reason)."""
        want = self._get_meta("binary_sha256")
        if not want:
            return True, "no checksum recorded"
        got = _sha256(path)
        if got is None:
            return False, "binary not readable"
        return (got == want), ("checksum matches" if got == want else "binary CHANGED since the session was saved")

    # ------------------------------------------------------------------ legacy import
    def _import_legacy_if_empty(self):
        """If this .sdb is new (no functions) and a legacy <binary>.angrgui.json exists,
        import it so existing projects are not lost."""
        with self._lock:
            has = self._conn.execute("SELECT 1 FROM functions LIMIT 1").fetchone()
            if has:
                return
        legacy = (self.binary_path + LEGACY_SUFFIX) if self.binary_path else None
        if not (legacy and os.path.isfile(legacy)):
            return
        try:
            with open(legacy) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return
        for addr, cfg in (data.get("functions") or {}).items():
            try:
                self.set_function(int(addr), cfg)
            except Exception:
                pass
        for rec in (data.get("runs") or []):
            try:
                self.add_run(dict(rec))
            except Exception:
                pass
        for t in (data.get("targets") or []):
            try:
                self.add_target(int(t["func"]), t.get("note"), t.get("by", "user"))
                if t.get("status") and t["status"] != "open":
                    self.update_target(int(t["func"]), status=t["status"])
            except Exception:
                pass
        fm = data.get("function_models")
        if fm:
            self.set_function_models(fm)

    # ---------------------------------------- global function-return models
    def function_models(self) -> dict:
        with self._lock:
            fm = self._get_meta("function_models") or {}
        fm.setdefault("by_name", {})
        fm.setdefault("by_site", {})
        return fm

    def set_function_models(self, fm: dict):
        self._set_meta("function_models", {"by_name": dict((fm or {}).get("by_name") or {}),
                                           "by_site": dict((fm or {}).get("by_site") or {})})

    # ------------------------------------------------------------- per function
    def get_function(self, addr: int) -> dict:
        """The function's setup in the structured (scenarios) shape."""
        with self._lock:
            row = self._conn.execute("SELECT config FROM functions WHERE addr=?", (str(addr),)).fetchone()
        return self._migrate(json.loads(row["config"]) if row else None)

    def set_function(self, addr: int, cfg: dict):
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO functions(addr, config) VALUES (?, ?)",
                               (str(addr), json.dumps(self._migrate(cfg))))
            self._conn.commit()
            self._touch()

    def update_function(self, addr: int, mutate):
        """Atomic read-modify-write of one function's setup (concurrency-safe)."""
        with self._lock:
            row = self._conn.execute("SELECT config FROM functions WHERE addr=?", (str(addr),)).fetchone()
            cfg = self._migrate(json.loads(row["config"]) if row else None)
            mutate(cfg)
            cfg = self._migrate(cfg)
            self._conn.execute("INSERT OR REPLACE INTO functions(addr, config) VALUES (?, ?)",
                               (str(addr), json.dumps(cfg)))
            self._conn.commit()
            self._touch()
            return cfg

    # ------------------------------------------------------------- run records + snapshots
    def add_run(self, record: dict):
        rid = record.get("id")
        if not rid:
            return
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO runs(id, func, when_, record, snapshot) "
                               "VALUES (?, ?, ?, ?, COALESCE((SELECT snapshot FROM runs WHERE id=?), NULL))",
                               (rid, int(record["func"]) if record.get("func") is not None else None,
                                float(record.get("when", time.time())), json.dumps(record), rid))
            # prune oldest records beyond the cap
            self._conn.execute(
                "DELETE FROM runs WHERE id IN (SELECT id FROM runs ORDER BY when_ DESC LIMIT -1 OFFSET ?)",
                (MAX_RUNS,))
            self._conn.commit()
            self._touch()

    def runs(self, func_addr: int | None = None) -> list:
        with self._lock:
            if func_addr is not None:
                rows = self._conn.execute("SELECT record FROM runs WHERE func=? ORDER BY when_ ASC",
                                          (int(func_addr),)).fetchall()
            else:
                rows = self._conn.execute("SELECT record FROM runs ORDER BY when_ ASC").fetchall()
        return [json.loads(r["record"]) for r in rows]

    def get_run_record(self, run_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT record FROM runs WHERE id=?", (run_id,)).fetchone()
        return json.loads(row["record"]) if row else None

    def update_run(self, run_id: str, **fields) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT record FROM runs WHERE id=?", (run_id,)).fetchone()
            if not row:
                return None
            rec = json.loads(row["record"]); rec.update(fields)
            self._conn.execute("UPDATE runs SET record=? WHERE id=?", (json.dumps(rec), run_id))
            self._conn.commit()
            self._touch()
            return rec

    def save_run_snapshot(self, run_id: str, snapshot: dict):
        """Persist a run's FULL snapshot (path tree + findings) so it still opens after a
        restart. Capped: only the most recent MAX_SNAPSHOTS keep their (large) snapshot;
        older runs keep their lightweight record."""
        with self._lock:
            if not self._conn.execute("SELECT 1 FROM runs WHERE id=?", (run_id,)).fetchone():
                return
            self._conn.execute("UPDATE runs SET snapshot=? WHERE id=?", (json.dumps(snapshot), run_id))
            # drop snapshots (keep records) beyond the newest MAX_SNAPSHOTS
            self._conn.execute(
                "UPDATE runs SET snapshot=NULL WHERE id IN ("
                "  SELECT id FROM runs WHERE snapshot IS NOT NULL ORDER BY when_ DESC LIMIT -1 OFFSET ?)",
                (MAX_SNAPSHOTS,))
            self._conn.commit()
            self._touch()

    def get_run_snapshot(self, run_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT snapshot FROM runs WHERE id=?", (run_id,)).fetchone()
        return json.loads(row["snapshot"]) if (row and row["snapshot"]) else None

    # ------------------------------------------------------------- targets / TODO
    def add_target(self, func: int, note: str | None = None, by: str = "user") -> dict:
        with self._lock:
            row = self._conn.execute("SELECT data FROM targets WHERE func=?", (int(func),)).fetchone()
            if row:
                rec = json.loads(row["data"])
                if note is not None:
                    rec["note"] = note
                rec["status"] = "open"
            else:
                rec = {"func": int(func), "note": note, "by": by, "status": "open"}
            self._conn.execute("INSERT OR REPLACE INTO targets(func, data) VALUES (?, ?)",
                               (int(func), json.dumps(rec)))
            self._conn.commit()
            self._touch()
            return dict(rec)

    def targets(self, status: str | None = None) -> list:
        with self._lock:
            rows = self._conn.execute("SELECT data FROM targets").fetchall()
        out = [json.loads(r["data"]) for r in rows]
        return [t for t in out if status is None or t.get("status") == status]

    def update_target(self, func: int, **fields) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT data FROM targets WHERE func=?", (int(func),)).fetchone()
            if not row:
                return None
            rec = json.loads(row["data"]); rec.update(fields)
            self._conn.execute("UPDATE targets SET data=? WHERE func=?", (json.dumps(rec), int(func)))
            self._conn.commit()
            self._touch()
            return rec

    # ------------------------------------------------------------- save / load session
    def save_as(self, path: str) -> str:
        """Write a copy of this whole session (meta, functions, runs + snapshots, targets)
        to `path` (a .sdb). Returns the absolute path."""
        path = os.path.abspath(os.path.expanduser(path))
        if not path.endswith(SUFFIX):
            path += SUFFIX
        with self._lock:
            dest = sqlite3.connect(path)
            try:
                self._conn.backup(dest)       # consistent copy even while in use
            finally:
                dest.close()
        return path

    def _touch(self):
        self._conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('modified', ?)",
                           (json.dumps(time.time()),))
        self._conn.commit()

    def close(self):
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

    def all(self) -> dict:
        """Reconstruct the legacy nested dict (functions/runs/targets/meta) — kept for the
        few callers that want the whole thing (e.g. 'configure every function' views)."""
        with self._lock:
            funcs = {r["addr"]: json.loads(r["config"])
                     for r in self._conn.execute("SELECT addr, config FROM functions").fetchall()}
            runs = [json.loads(r["record"])
                    for r in self._conn.execute("SELECT record FROM runs ORDER BY when_ ASC").fetchall()]
            targets = [json.loads(r["data"]) for r in self._conn.execute("SELECT data FROM targets").fetchall()]
            meta = {r["key"]: json.loads(r["value"]) for r in self._conn.execute("SELECT key, value FROM meta").fetchall()}
        return {"functions": funcs, "runs": runs, "targets": targets, "meta": meta,
                "function_models": meta.get("function_models", {})}

    # ------------------------------------------------------------- shape helpers
    @staticmethod
    def _default_scenario(name: str = "Default") -> dict:
        return {"name": name, "args": [], "buffers": [], "assumptions": [],
                "stdin": None, "files": [],
                # skip_calls ON by default — stay inside the target function (see runner).
                "limits": {"skip_calls": True}, "models": []}

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
        out["scenarios"] = [s.get("name") or f"Scenario {j + 1}" for j, s in enumerate(cfg["scenarios"])]
        out["active"] = idx
        return out
