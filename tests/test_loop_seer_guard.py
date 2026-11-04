"""
angr's LoopSeer.successors indexes its per-loop trip-count lists with [-1] for addresses
it never seeded — a loop EXIT node that isn't a body node, or a loop first entered
mid-body (what a concolic snapshot seed does when `pc` lands inside a loop). The list is
empty, `[-1]` raises IndexError, and it propagates out of simgr.step() and kills the whole
run. runner._SafeLoopSeer subclasses LoopSeer so that slip degrades to an unbounded step
for that one state instead of aborting the run. This pins that recovery contract.
"""
import os
import sys

import pytest
from angr.exploration_techniques import LoopSeer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from angrgui.runner import _SafeLoopSeer          # noqa: E402


def test_safe_loop_seer_is_a_loopseer_subclass():
    Cls = _SafeLoopSeer()
    assert issubclass(Cls, LoopSeer)


def test_safe_loop_seer_recovers_from_indexerror(monkeypatch):
    Cls = _SafeLoopSeer()
    seer = Cls.__new__(Cls)                       # skip __init__ (needs a real cfg)

    # Force the upstream bookkeeping to raise the empty-list IndexError.
    def boom(self, simgr, state, **kw):
        raise IndexError("list index out of range")
    monkeypatch.setattr(LoopSeer, "successors", boom)

    class FakeSimgr:
        def successors(self, state, **kw):
            return "RECOVERED"

    before = Cls.glitches
    out = seer.successors(FakeSimgr(), object())
    assert out == "RECOVERED"                     # fell back to a clean unbounded step
    assert Cls.glitches == before + 1             # and recorded the glitch


def test_safe_loop_seer_passes_through_normally(monkeypatch):
    Cls = _SafeLoopSeer()
    seer = Cls.__new__(Cls)

    monkeypatch.setattr(LoopSeer, "successors",
                        lambda self, simgr, state, **kw: "NORMAL")

    class FakeSimgr:
        def successors(self, state, **kw):
            raise AssertionError("fallback must not run when super() succeeds")

    before = Cls.glitches
    assert seer.successors(FakeSimgr(), object()) == "NORMAL"
    assert Cls.glitches == before                 # no glitch recorded on the happy path


def test_safe_loop_seer_does_not_swallow_other_errors(monkeypatch):
    Cls = _SafeLoopSeer()
    seer = Cls.__new__(Cls)

    monkeypatch.setattr(LoopSeer, "successors",
                        lambda self, simgr, state, **kw: (_ for _ in ()).throw(ValueError("x")))

    with pytest.raises(ValueError):               # only IndexError is a bookkeeping slip
        seer.successors(object(), object())
