"""Scenario model: migration of legacy flat setups, flatten of the active scenario,
and that checks are shared while initial state is per-scenario."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from angrgui.workspace import Workspace


def test_legacy_flat_migrates_to_single_default_scenario():
    legacy = {"args": [{"name": "x", "mode": "symbolic"}],
              "assumptions": ["x > 0"], "stdin": {"mode": "symbolic", "size": 8},
              "checks": [{"kind": "reach", "addr": 0x400000}], "limits": {"steps": 99}}
    cfg = Workspace._migrate(legacy)
    assert cfg["active"] == 0
    assert len(cfg["scenarios"]) == 1
    sc = cfg["scenarios"][0]
    assert sc["name"] == "Default"
    assert sc["args"][0]["name"] == "x"
    assert sc["assumptions"] == ["x > 0"]
    assert sc["limits"]["steps"] == 99
    # checks live at the top level (shared), not inside the scenario
    assert cfg["checks"][0]["addr"] == 0x400000
    assert "checks" not in sc


def test_structured_passthrough_clamps_active():
    cfg = Workspace._migrate({"checks": [], "active": 9, "scenarios": [
        {"name": "A", "assumptions": ["a==1"]}, {"name": "B", "assumptions": ["b==2"]}]})
    assert cfg["active"] == 1                      # clamped into range
    assert [s["name"] for s in cfg["scenarios"]] == ["A", "B"]


def test_flatten_merges_active_scenario_with_shared_checks():
    cfg = {"checks": [{"kind": "reach", "addr": 1}],
           "active": 1,
           "scenarios": [{"name": "entry", "assumptions": ["a==0"]},
                         {"name": "deep", "assumptions": ["a==5"], "args": [{"name": "a"}]}]}
    flat = Workspace.flatten(cfg)
    assert flat["assumptions"] == ["a==5"]        # the active (index 1) scenario
    assert flat["args"][0]["name"] == "a"
    assert flat["checks"][0]["addr"] == 1          # shared checks come through
    assert flat["scenarios"] == ["entry", "deep"]  # names for the switcher
    assert flat["active"] == 1
    # a specific index can be requested
    assert Workspace.flatten(cfg, 0)["assumptions"] == ["a==0"]


def test_roundtrip_through_save_and_get(tmp_path):
    binp = tmp_path / "bin"
    binp.write_bytes(b"\x7fELF")
    ws = Workspace(str(binp))
    ws.set_function(0x1000, {"checks": [{"kind": "avoid", "addr": 2}],
                             "active": 0, "scenarios": [
                                 {"name": "one", "assumptions": ["x>0"]},
                                 {"name": "two", "assumptions": ["x<0"]}]})
    again = Workspace(str(binp))                   # reload from disk
    cfg = again.get_function(0x1000)
    assert [s["name"] for s in cfg["scenarios"]] == ["one", "two"]
    assert cfg["checks"][0]["kind"] == "avoid"


def test_run_snapshot_and_record_survive_reopen(tmp_path):
    """A run's record AND its full snapshot persist in the .sdb, so reopening (a restart)
    still has the data — this is the bug the session store fixes."""
    binp = tmp_path / "bin"; binp.write_bytes(b"\x7fELF")
    ws = Workspace(str(binp))
    ws.add_run({"id": "run1", "func": 0x1000, "when": 1.0, "status": "done",
                "summary": {"hits": 1}, "findings": [{"kind": "oob_write"}]})
    ws.save_run_snapshot("run1", {"status": "done", "tree": [{"id": 0}], "hits": [{"kind": "oob_write"}],
                                  "summary": {"hits": 1}})
    again = Workspace(str(binp))                   # reopen from disk (= restart)
    assert [r["id"] for r in again.runs()] == ["run1"]
    assert again.runs(0x1000)[0]["findings"][0]["kind"] == "oob_write"
    snap = again.get_run_snapshot("run1")
    assert snap and snap["tree"] == [{"id": 0}]


def test_runs_scoped_by_function(tmp_path):
    binp = tmp_path / "bin"; binp.write_bytes(b"\x7fELF")
    ws = Workspace(str(binp))
    ws.add_run({"id": "a", "func": 0x10, "when": 1.0})
    ws.add_run({"id": "b", "func": 0x20, "when": 2.0})
    assert {r["id"] for r in ws.runs(0x10)} == {"a"}
    assert {r["id"] for r in ws.runs(0x20)} == {"b"}
    assert {r["id"] for r in ws.runs()} == {"a", "b"}


def test_save_as_copies_whole_session(tmp_path):
    binp = tmp_path / "bin"; binp.write_bytes(b"\x7fELF")
    ws = Workspace(str(binp))
    ws.set_function(0x1000, {"checks": [{"kind": "reach", "addr": 5}], "scenarios": [{"name": "s"}], "active": 0})
    ws.add_run({"id": "r", "func": 0x1000, "when": 1.0})
    ws.save_run_snapshot("r", {"tree": [{"id": 0}], "hits": []})
    dest = str(tmp_path / "mysession.sdb")
    out = ws.save_as(dest)
    assert out == dest
    loaded = Workspace(None, store_path=dest)
    assert loaded.get_function(0x1000)["checks"][0]["addr"] == 5
    assert loaded.get_run_snapshot("r")["tree"] == [{"id": 0}]
    assert loaded.get_meta("binary_path") == os.path.abspath(str(binp))


def test_legacy_json_is_imported(tmp_path):
    import json
    binp = tmp_path / "bin"; binp.write_bytes(b"\x7fELF")
    legacy = str(binp) + ".angrgui.json"
    with open(legacy, "w") as fh:
        json.dump({"functions": {"4096": {"checks": [{"kind": "avoid", "addr": 9}],
                   "scenarios": [{"name": "old"}], "active": 0}},
                   "runs": [{"id": "old1", "func": 4096, "when": 1.0}]}, fh)
    ws = Workspace(str(binp))                      # fresh .sdb -> imports the legacy json
    assert ws.get_function(4096)["checks"][0]["addr"] == 9
    assert [r["id"] for r in ws.runs()] == ["old1"]
