"""
The arm64 per-lane VARIABLE shift handlers (SSHL/USHL -> Iop_Sh<lw>{S,U}x<cnt>) in
angr_arm_patch. This pins them bit-exact against an INDEPENDENT ARM-semantics reference
across every lane width, both signs, and edge shift amounts (0, +/-lanewidth, the signed
byte extremes). A wrong shift handler would silently corrupt findings, so this must stay
exact — see the module's "a wrong handler is worse than none" pitfall.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import claripy                                  # noqa: E402
from angrgui import angr_arm_patch              # noqa: E402
import angr.engines.vex.claripy.irop as irop    # noqa: E402

angr_arm_patch.apply()

CASES = {
    "Iop_Sh8Sx16": (8, 16, True), "Iop_Sh8Ux16": (8, 16, False),
    "Iop_Sh16Sx8": (16, 8, True), "Iop_Sh16Ux8": (16, 8, False),
    "Iop_Sh32Sx4": (32, 4, True), "Iop_Sh32Ux4": (32, 4, False),
    "Iop_Sh64Sx2": (64, 2, True), "Iop_Sh64Ux2": (64, 2, False),
}


def _ref_lane(val, sh_byte, lw, signed):
    """ARM SSHL/USHL on one lane: shift = signed low byte; >=0 left, <0 right (arith for S)."""
    shift = sh_byte - 256 if sh_byte >= 128 else sh_byte
    mask = (1 << lw) - 1
    if shift >= 0:
        return (val << shift) & mask
    r = -shift
    if signed:
        sval = val - (1 << lw) if (val >> (lw - 1)) & 1 else val
        return (sval >> r) & mask                       # python >> on neg is arithmetic
    return (val >> r) & mask if r < lw else 0


def _ref_bidir(val, sh_byte, lw, signed, rounding, saturating):
    """ARM SRSHL/URSHL/SQSHL/UQSHL/SQRSHL/UQRSHL on one lane (the generalised reference,
    cross-checked against native NEON hardware over 72000 vectors). Returns (result, Q)."""
    shift = sh_byte - 256 if sh_byte >= 128 else sh_byte
    mask = (1 << lw) - 1
    sval = val - (1 << lw) if (signed and (val >> (lw - 1)) & 1) else val
    if shift >= 0:
        res = sval << shift
    else:
        n = -shift
        res = ((sval if signed else val) + ((1 << (n - 1)) if rounding else 0)) >> n
    q = 0
    if saturating:
        hi, lo = ((1 << (lw - 1)) - 1, -(1 << (lw - 1))) if signed else ((1 << lw) - 1, 0)
        if res > hi:
            res, q = hi, 1
        elif res < lo:
            res, q = lo, 1
    return res & mask, q


def _pack(vals, lw):
    out = 0
    for i, v in enumerate(vals):
        out |= (v & ((1 << lw) - 1)) << (lw * i)
    return out


RSH = {"Iop_Rsh8Sx16": (8, 16, True), "Iop_Rsh8Ux16": (8, 16, False),
       "Iop_Rsh16Sx8": (16, 8, True), "Iop_Rsh16Ux8": (16, 8, False),
       "Iop_Rsh32Sx4": (32, 4, True), "Iop_Rsh32Ux4": (32, 4, False),
       "Iop_Rsh64Sx2": (64, 2, True), "Iop_Rsh64Ux2": (64, 2, False)}
# generic_name -> (signed, rounding)
QANDQ = {"QandUQsh": (False, False), "QandSQsh": (True, False),
         "QandUQRsh": (False, True), "QandSQRsh": (True, True)}
QWIDTHS = {8: 16, 16: 8, 32: 4, 64: 2}


def _ev(op, data, amt):
    return claripy.backends.concrete.eval(irop.operations[op]._calculate([data, amt]), 1)[0]


def test_every_op_registered():
    for nm in CASES:
        assert nm in irop.operations, f"{nm} must be registered by apply()"


def test_variable_shift_bit_exact_vs_arm_reference():
    random.seed(7)
    for name, (lw, cnt, signed) in CASES.items():
        tw = lw * cnt
        edges = [0, 1, 2, lw - 1, lw, lw + 1, 0x7f, 0x80, 0x81, 0xff, 0xc0]
        for _ in range(200):
            dv = [random.choice([0, 1, 1 << (lw - 1), (1 << lw) - 1, random.getrandbits(lw)])
                  for _ in range(cnt)]
            sv = [random.choice(edges + [random.getrandbits(8)]) for _ in range(cnt)]
            got = _ev(name, claripy.BVV(_pack(dv, lw), tw), claripy.BVV(_pack(sv, lw), tw))
            exp = _pack([_ref_lane(dv[i], sv[i] & 0xff, lw, signed) for i in range(cnt)], lw)
            assert got == exp, f"{name} data={[hex(x) for x in dv]} sh={sv} got={hex(got)} exp={hex(exp)}"


def test_rounding_shift_bit_exact():
    """Iop_Rsh* (SRSHL/URSHL): rounding variable shift, non-saturating, V128."""
    random.seed(8)
    for name, (lw, cnt, signed) in RSH.items():
        assert name in irop.operations
        tw = lw * cnt
        edges = [0, 1, 2, lw - 1, lw, lw + 1, 0x7f, 0x80, 0x81, 0xff, 0xc0]
        for _ in range(120):
            dv = [random.choice([0, 1, 1 << (lw - 1), (1 << lw) - 1, random.getrandbits(lw)]) for _ in range(cnt)]
            sv = [random.choice(edges + [random.getrandbits(8)]) for _ in range(cnt)]
            got = _ev(name, claripy.BVV(_pack(dv, lw), tw), claripy.BVV(_pack(sv, lw), tw))
            exp = _pack([_ref_bidir(dv[i], sv[i] & 0xff, lw, signed, True, False)[0] for i in range(cnt)], lw)
            assert got == exp, f"{name} data={[hex(x) for x in dv]} sh={sv} got={hex(got)} exp={hex(exp)}"


def test_saturating_shift_result_and_q_bit():
    """Iop_Qand{U,S}Q{,R}sh*: saturating (maybe rounding) shift. V256 = [upper128|result128],
    Q (any-lane-saturated) is bit 0 of the upper V128."""
    random.seed(9)
    for gname, (signed, rounding) in QANDQ.items():
        for lw, cnt in QWIDTHS.items():
            name = f"Iop_{gname}{lw}x{cnt}"
            assert name in irop.operations, name
            tw = lw * cnt
            edges = [0, 1, 2, lw - 1, lw, lw + 1, 0x7f, 0x80, 0x81, 0xff, 0xc0]
            for _ in range(80):
                dv = [random.choice([0, 1, 1 << (lw - 1), (1 << lw) - 1, random.getrandbits(lw)]) for _ in range(cnt)]
                sv = [random.choice(edges + [random.getrandbits(8)]) for _ in range(cnt)]
                v = _ev(name, claripy.BVV(_pack(dv, lw), tw), claripy.BVV(_pack(sv, lw), tw))
                res = v & ((1 << 128) - 1)
                q = (v >> 128) & 1
                lanes = [_ref_bidir(dv[i], sv[i] & 0xff, lw, signed, rounding, True) for i in range(cnt)]
                assert res == _pack([x[0] for x in lanes], lw), f"{name} result mismatch"
                assert q == (1 if any(x[1] for x in lanes) else 0), f"{name} Q mismatch"
                assert (v >> 129) == 0, f"{name} upper V128 must be zero except Q"


def test_symbolic_shift_is_solver_reasoned():
    """USHL stays symbolic and the solver can invert it (no premature concretization)."""
    op = irop.operations["Iop_Sh32Ux4"]
    data, amt = claripy.BVS("d", 128), claripy.BVS("a", 128)
    r = op._calculate([data, amt])
    assert r.symbolic and r.length == 128
    s = claripy.Solver()
    s.add([data[31:0] == 1, amt[7:0] == 4, r[31:0] == 0x10])   # 1 << 4 == 0x10
    assert s.satisfiable()
    s2 = claripy.Solver()
    s2.add([data[31:0] == 0x80000000, amt[7:0] == 0xff, r[31:0] == 0x40000000])  # >> 1 logical
    assert s2.satisfiable()
