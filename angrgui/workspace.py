"""
Per-binary workspace: the assumptions and checks the user has set up for each
function, saved as JSON next to the binary (``<binary>.angrgui.json``) so a
project survives restarts.
"""
from __future__ import annotations

import json
import os
import threading

SUFFIX = ".angrgui.json"


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
        return self.data["functions"].get(str(addr), self._default_func())

    def set_function(self, addr: int, cfg: dict):
        self.data["functions"][str(addr)] = cfg
        self.save()

    @staticmethod
    def _default_func() -> dict:
        return {"args": [], "buffers": [], "assumptions": [], "stdin": None,
                "checks": [], "limits": {}}

    def all(self) -> dict:
        return self.data
