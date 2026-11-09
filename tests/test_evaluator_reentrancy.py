"""
make_evaluator reads memory to evaluate expressions (an assumption, an assert, or an oob
check's `base`). The oob_read/oob_write checks observe via mem_read/mem_write inspect
breakpoints and invoke the evaluator from INSIDE those callbacks. A plain state.memory.load
inside a mem_read BP_BEFORE callback re-fires the breakpoint, so an oob_read whose base
dereferences memory re-enters its own handler without bound (RecursionError kills the run).
The evaluator's loads must pass inspect=False/disable_actions=True; these tests pin that.
"""
import os
import sys

import angr
import claripy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from angrgui.exprlang import make_evaluator          # noqa: E402


def _state():
    proj = angr.load_shellcode(b"\x90", arch="AMD64")
    st = proj.factory.blank_state()
    st.memory.store(0x5000, claripy.BVV(0xdeadbeef, 32), endness=st.arch.memory_endness)
    st.scratch.ins_addr = 0x400000
    st.globals["angrgui_vars"] = {}
    return st


def test_baseline_plain_load_refires_breakpoint():
    """Sanity: a plain load inside the callback DOES re-fire (the hazard is real)."""
    st = _state()
    seen = {"n": 0}

    def on_read(state):
        seen["n"] += 1
        if seen["n"] <= 4:                             # bound the probe
            state.memory.load(0x5000, 4, endness=state.arch.memory_endness)

    st.inspect.b("mem_read", when=angr.BP_BEFORE, action=on_read)
    st.memory.load(0x5000, 4, endness=st.arch.memory_endness)
    assert seen["n"] > 1                               # re-entered


def test_evaluator_mem_does_not_refire_breakpoint():
    """make_evaluator('mem(...)') from inside a mem_read callback must NOT re-enter."""
    st = _state()
    seen = {"n": 0}

    def on_read(state):
        seen["n"] += 1
        if seen["n"] > 20:                             # safety net if the fix regresses
            return
        make_evaluator(state)("mem(0x5000, 4)")        # as the oob handler evaluates `base`

    st.inspect.b("mem_read", when=angr.BP_BEFORE, action=on_read)
    st.memory.load(0x5000, 4, endness=st.arch.memory_endness)
    assert seen["n"] == 1                              # fired once; the inner load was silent


def test_evaluator_still_reads_the_right_value():
    """Suppressing inspect/actions must not change the value the evaluator returns."""
    st = _state()
    v = make_evaluator(st)("mem(0x5000, 4)")
    assert st.solver.eval(v) == 0xdeadbeef
