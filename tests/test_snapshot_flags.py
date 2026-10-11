"""
Snapshot restore must carry the condition flags (CPSR/NZCV on arm64, eflags on x86).
angr has no plain cpsr register — flags live in a VEX thunk — so a naive setattr drops
them silently and any snapshot seeded right before a flag-dependent branch diverges.
Run._restore_flags copies NZCV into the thunk; here we read them back through the same
ccall the B.cond decoder uses.
"""
import os
import sys

import angr
import claripy
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from angrgui import angr_arm_patch          # noqa: E402
from angrgui.runner import Run              # noqa: E402

angr_arm_patch.apply()


class _FakeRun:
    """Just enough of a Runner to exercise _restore_flags (it only reads self.arch)."""
    def __init__(self, arch):
        self.arch = arch


def _cond(state, cond):
    """Evaluate an AArch64 condition code against the state's current flag thunk."""
    from angr.engines.vex.claripy import ccall
    cno = claripy.BVV((cond << 4) | 0, 64)   # (cond, op=COPY)
    r = ccall.arm64g_calculate_condition(state, cno,
                                         state.regs.cc_dep1, state.regs.cc_dep2, state.regs.cc_ndep)
    v = r[0] if isinstance(r, tuple) else r
    return state.solver.eval(v)


def test_aarch64_nzcv_restored_from_cpsr():
    proj = angr.load_shellcode(b"\x1f\x20\x03\xd5", arch="AARCH64")   # nop
    st = proj.factory.blank_state()
    # CPSR 0x60000000 -> N=0 Z=1 C=1 V=0
    Run._restore_flags(_FakeRun(proj.arch), st, 0x60000000)
    EQ, NE, CS, CC, MI = 0, 1, 2, 3, 4
    assert _cond(st, EQ) == 1          # Z==1
    assert _cond(st, NE) == 0
    assert _cond(st, CS) == 1          # C==1
    assert _cond(st, CC) == 0
    assert _cond(st, MI) == 0          # N==0


def test_aarch64_negative_flag_restored():
    proj = angr.load_shellcode(b"\x1f\x20\x03\xd5", arch="AARCH64")
    st = proj.factory.blank_state()
    # CPSR 0x80000000 -> N=1 only
    Run._restore_flags(_FakeRun(proj.arch), st, 0x80000000)
    assert _cond(st, 4) == 1           # MI (N==1)
    assert _cond(st, 0) == 0           # EQ (Z==0)


def test_x86_eflags_restored():
    proj = angr.load_shellcode(b"\x90", arch="AMD64")   # nop
    st = proj.factory.blank_state()
    # ZF is bit 6 (0x40); set it and read it back through the eflags thunk.
    Run._restore_flags(_FakeRun(proj.arch), st, 0x40)
    zf = st.solver.eval(st.regs.flags & 0x40)
    assert zf == 0x40
