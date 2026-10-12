"""
Regression for the single-node-CFG bug: analysing one function must not corrupt the
CFG of a function already analysed.

The cause was arm64e-specific — we PAC-hook a function's entry (pacibsp) AFTER recovering
it, and a later function's analysis used to re-run CFGFast over a SHARED knowledge base;
that re-run hit the earlier function's now-hooked entry as a SimProcedure stub and
collapsed it to a single block. The fix gives each function its own KnowledgeBase, built
once. This test reproduces the exact sequence on the real CoreGraphics arm64e binary and
is skipped when that (git-ignored) input isn't present.
"""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

CG = os.path.join(ROOT, "seal_validation", "snapshot", "macos_cg", "CoreGraphics")

MOVETO = 0x186a243f4
LINETO = 0x186a24e80
CLOSE = 0x186a24548


@pytest.fixture(scope="module")
def cg():
    if not os.path.exists(CG):
        pytest.skip("CoreGraphics arm64e binary not present (git-ignored input)")
    from angrgui.engine import Binary
    return Binary(CG, progress=lambda m: None, target_funcs=[MOVETO])


def _nblocks(binary, fa):
    f = binary.get_function(fa)
    return len(f.block_addrs_set) if f is not None else 0


def test_analysing_others_does_not_collapse_an_earlier_cfg(cg):
    before = _nblocks(cg, MOVETO)
    assert before > 1, "aa_moveto should recover as multiple blocks"
    # analysing neighbours (one of them adjacent + called by moveto) must not touch moveto
    cg.get_function(CLOSE)
    cg.get_function(LINETO)
    after = _nblocks(cg, MOVETO)
    assert after == before, f"aa_moveto CFG collapsed {before} -> {after} after analysing others"


def test_neon_heavy_functions_recover_fully(cg):
    # these NEON/float functions previously came back as 0 or 1 node
    for fa in (MOVETO, LINETO, 0x186a246d0, 0x186a6739c):   # moveto, lineto, cubeto, quadto
        assert _nblocks(cg, fa) > 1, f"{hex(fa)} did not recover a full CFG"
