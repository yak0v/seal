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


def _ref_sat(val, sh_byte, lw, in_signed, sat_signed, rounding, out_lw):
    """Generalised saturating-shift reference (hardware-verified): shift by the signed
    sh_byte, then clamp to the sat_signed range of out_lw bits. Covers QShlNsat (left,
    out_lw==lw) and the saturating-narrow ops (right, out_lw<lw). Returns (result, Q)."""
    shift = sh_byte - 256 if sh_byte >= 128 else sh_byte
    sval = val - (1 << lw) if (in_signed and (val >> (lw - 1)) & 1) else val
    if shift >= 0:
        res = sval << shift
    else:
        n = -shift
        res = ((sval if in_signed else val) + ((1 << (n - 1)) if rounding else 0)) >> n
    hi, lo = ((1 << (out_lw - 1)) - 1, -(1 << (out_lw - 1))) if sat_signed else ((1 << out_lw) - 1, 0)
    q = 0
    if res > hi:
        res, q = hi, 1
    elif res < lo:
        res, q = lo, 1
    return res & ((1 << out_lw) - 1), q


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


QSHLNSAT = {"SS": (True, True), "UU": (False, False), "SU": (True, False)}  # (in_signed, sat_signed)


def test_qshlnsat_immediate_saturating_left_shift():
    """Iop_QShlNsat{SS,SU,UU}<lw>x<cnt>: SQSHL/UQSHL/SQSHLU #imm — saturating LEFT shift by a
    scalar immediate (args[1]), V128 result. Verified vs native hardware over 1400 vectors."""
    random.seed(13)
    for tag, (insig, satsig) in QSHLNSAT.items():
        for lw, cnt in QWIDTHS.items():
            name = f"Iop_QShlNsat{tag}{lw}x{cnt}"
            assert name in irop.operations, name
            tw = lw * cnt
            for _ in range(60):
                dv = [random.choice([0, 1, 1 << (lw - 1), (1 << (lw - 1)) - 1, (1 << lw) - 1, random.getrandbits(lw)]) for _ in range(cnt)]
                n = random.choice([0, 1, 2, lw - 1] + [random.randrange(0, lw)])
                v = _ev2(name, claripy.BVV(_pack(dv, lw), tw), claripy.BVV(n, 8))
                exp = _pack([_ref_sat(dv[i], n, lw, insig, satsig, False, lw)[0] for i in range(cnt)], lw)
                assert (v & ((1 << tw) - 1)) == exp, f"{name} n={n} dv={[hex(x) for x in dv]}"


# narrow op name -> (src, dst, in_signed, sat_signed, rounding)
NARROW = {
    "Iop_QandQShrNnarrow16Uto8Ux8": (16, 8, False, False, False),
    "Iop_QandQShrNnarrow32Uto16Ux4": (32, 16, False, False, False),
    "Iop_QandQShrNnarrow64Uto32Ux2": (64, 32, False, False, False),
    "Iop_QandQSarNnarrow16Sto8Sx8": (16, 8, True, True, False),
    "Iop_QandQSarNnarrow32Sto16Ux4": (32, 16, True, False, False),
    "Iop_QandQRSarNnarrow64Sto32Sx2": (64, 32, True, True, True),
    "Iop_QandQRShrNnarrow32Uto16Ux4": (32, 16, False, False, True),
    "Iop_QandQRSarNnarrow16Sto8Ux8": (16, 8, True, False, True),
}


def test_saturating_narrow_shift_right():
    """Iop_QandQ{,R}{Sar,Shr}Nnarrow...: saturating (maybe rounding) shift-right + narrow.
    (V128,I8)->V128: low half = narrowed lanes, Q = LSB of the upper half."""
    random.seed(17)
    for name, (src, dst, insig, satsig, rnd) in NARROW.items():
        assert name in irop.operations, name
        cnt = 128 // src
        for _ in range(60):
            dv = [random.choice([0, 1, 1 << (src - 1), (1 << (src - 1)) - 1, (1 << src) - 1, random.getrandbits(src)]) for _ in range(cnt)]
            n = random.randrange(1, dst + 1)                      # ARM narrow shift range 1..dst
            v = _ev2(name, claripy.BVV(_pack(dv, src), 128), claripy.BVV(n, 8))
            lanes = [_ref_sat(dv[i], (256 - n) & 0xff, src, insig, satsig, rnd, dst) for i in range(cnt)]
            res = v & ((1 << (dst * cnt)) - 1)
            assert res == _pack([x[0] for x in lanes], dst), f"{name} n={n} dv={[hex(x) for x in dv]}"
            assert ((v >> 64) & 1) == (1 if any(x[1] for x in lanes) else 0), f"{name} Q n={n}"
            assert (v >> 65) == 0, f"{name} upper bits above Q must be 0"


def _ev2(op, a, b):
    return claripy.backends.concrete.eval(irop.operations[op]._calculate([a, b]), 1)[0]


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
