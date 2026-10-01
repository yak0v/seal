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
