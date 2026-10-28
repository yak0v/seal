"""
Non-shift arm64 NEON integer/FP handlers in angr_arm_patch (Cnt, Cls, Left, Widen,
Interleave, Avg, ... added family by family). Each handler is pinned against a pure-int
reference that was itself cross-checked against this machine's native NEON hardware.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import claripy                                  # noqa: E402
from angrgui import angr_arm_patch              # noqa: E402
import angr.engines.vex.claripy.irop as irop    # noqa: E402

angr_arm_patch.apply()


def _pack(vals, lw):
    out = 0
    for i, v in enumerate(vals):
        out |= (v & ((1 << lw) - 1)) << (lw * i)
    return out


def _ev(op, *args):
    return claripy.backends.concrete.eval(irop.operations[op]._calculate(list(args)), 1)[0]


def _lanes(v, lw, cnt):
    return [(v >> (lw * i)) & ((1 << lw) - 1) for i in range(cnt)]


# ---------------- Batch A: Cnt / Cls / Left / Widen / Interleave / Avg ----------------

def test_cnt_popcount():
    random.seed(1)
    for name, cnt in [("Iop_Cnt8x16", 16), ("Iop_Cnt8x8", 8)]:
        assert name in irop.operations
        for _ in range(50):
            dv = [random.getrandbits(8) for _ in range(cnt)]
            got = _lanes(_ev(name, claripy.BVV(_pack(dv, 8), 8 * cnt)), 8, cnt)
            assert got == [bin(x).count("1") for x in dv]


def _cls(x, lw):
    s = x >> (lw - 1) & 1
    n = 0
    for i in range(lw - 2, -1, -1):
        if (x >> i) & 1 == s:
            n += 1
        else:
            break
    return n


def test_cls_leading_sign_bits():
    random.seed(2)
    for lw, cnt in [(8, 16), (16, 8), (32, 4), (8, 8), (16, 4), (32, 2)]:
        name = f"Iop_Cls{lw}x{cnt}"
        assert name in irop.operations
        for _ in range(40):
            dv = [random.choice([0, (1 << lw) - 1, 1 << (lw - 1), random.getrandbits(lw)]) for _ in range(cnt)]
            got = _lanes(_ev(name, claripy.BVV(_pack(dv, lw), lw * cnt)), lw, cnt)
            assert got == [_cls(x, lw) for x in dv], f"{name} {[hex(x) for x in dv]} -> {got}"


def test_left_x_or_negx():
    random.seed(3)
    for lw in (8, 16, 32, 64):
        name = f"Iop_Left{lw}"
        assert name in irop.operations
        for _ in range(40):
            x = random.getrandbits(lw)
            got = _ev(name, claripy.BVV(x, lw))
            assert got == (x | ((-x) & ((1 << lw) - 1))) & ((1 << lw) - 1)


def test_widen_low_lanes():
    random.seed(4)
    for sw, dw, cnt, signed in [(8, 16, 8, True), (8, 16, 8, False), (16, 32, 4, True),
                                (16, 32, 4, False), (32, 64, 2, True), (32, 64, 2, False)]:
        name = f"Iop_Widen{sw}{'S' if signed else 'U'}to{dw}x{cnt}"
        assert name in irop.operations
        full = 128 // sw
        for _ in range(40):
            dv = [random.getrandbits(sw) for _ in range(full)]
            got = _lanes(_ev(name, claripy.BVV(_pack(dv, sw), 128)), dw, cnt)
            exp = []
            for i in range(cnt):
                v = dv[i]
                if signed and (v >> (sw - 1)) & 1:
                    v -= (1 << sw)
                exp.append(v & ((1 << dw) - 1))
            assert got == exp, f"{name} {[hex(x) for x in dv[:cnt]]} -> {[hex(x) for x in got]}"


def test_interleave_even_odd():
    random.seed(5)
    for lw, cnt in [(8, 16), (16, 8), (32, 4), (8, 8), (16, 4)]:
        for parity in ("Even", "Odd"):
            name = f"Iop_Interleave{parity}Lanes{lw}x{cnt}"
            assert name in irop.operations, name
            base = 1 if parity == "Odd" else 0
            picks = [i for i in range(cnt) if i % 2 == base]
            for _ in range(30):
                a1 = [random.getrandbits(lw) for _ in range(cnt)]
                a2 = [random.getrandbits(lw) for _ in range(cnt)]
                got = _lanes(_ev(name, claripy.BVV(_pack(a1, lw), lw * cnt), claripy.BVV(_pack(a2, lw), lw * cnt)), lw, cnt)
                exp = []
                for p in picks:          # result[2k]=arg2, result[2k+1]=arg1
                    exp += [a2[p], a1[p]]
                assert got == exp, f"{name} -> {got} exp {exp}"


def test_avg_rounding_halving_add():
    random.seed(6)
    for lw, cnt in [(8, 16), (16, 8), (32, 4), (64, 2)]:
        for signed in (True, False):
            name = f"Iop_Avg{lw}{'S' if signed else 'U'}x{cnt}"
            assert name in irop.operations, name
            for _ in range(40):
                a = [random.getrandbits(lw) for _ in range(cnt)]
                b = [random.getrandbits(lw) for _ in range(cnt)]
                got = _lanes(_ev(name, claripy.BVV(_pack(a, lw), lw * cnt), claripy.BVV(_pack(b, lw), lw * cnt)), lw, cnt)
                exp = []
                for i in range(cnt):
                    av = a[i] - (1 << lw) if (signed and (a[i] >> (lw - 1)) & 1) else a[i]
                    bv = b[i] - (1 << lw) if (signed and (b[i] >> (lw - 1)) & 1) else b[i]
                    exp.append(((av + bv + 1) >> 1) & ((1 << lw) - 1))
                assert got == exp, f"{name} -> {got} exp {exp}"


# ---------------- Batch B: pairwise (PwAdd / PwMax / PwMin / PwAddL) ----------------

def _pw(a, b, lw, cnt, kind, signed):
    def foo(x, y):
        if kind == "Add":
            return (x + y) & ((1 << lw) - 1)
        if signed:
            x = x - (1 << lw) if (x >> (lw - 1)) & 1 else x
            y = y - (1 << lw) if (y >> (lw - 1)) & 1 else y
        return (max(x, y) if kind == "Max" else min(x, y)) & ((1 << lw) - 1)
    out = []
    for src in (a, b):
        for k in range(0, cnt, 2):
            out.append(foo(src[k], src[k + 1]))
    return out


def test_pairwise_add_max_min():
    random.seed(11)
    specs = [("Iop_PwAdd8x16", 8, 16, "Add", None), ("Iop_PwAdd16x8", 16, 8, "Add", None),
             ("Iop_PwAdd32x4", 32, 4, "Add", None), ("Iop_PwAdd8x8", 8, 8, "Add", None),
             ("Iop_PwAdd16x4", 16, 4, "Add", None), ("Iop_PwAdd32x2", 32, 2, "Add", None)]
    for lw, cnt in [(8, 8), (16, 4), (32, 2)]:
        for k in ("Max", "Min"):
            for s in (True, False):
                specs.append((f"Iop_Pw{k}{lw}{'S' if s else 'U'}x{cnt}", lw, cnt, k, s))
    for name, lw, cnt, kind, signed in specs:
        assert name in irop.operations, name
        for _ in range(40):
            a = [random.getrandbits(lw) for _ in range(cnt)]
            b = [random.getrandbits(lw) for _ in range(cnt)]
            got = _lanes(_ev(name, claripy.BVV(_pack(a, lw), lw * cnt), claripy.BVV(_pack(b, lw), lw * cnt)), lw, cnt)
            assert got == _pw(a, b, lw, cnt, kind, bool(signed)), f"{name}"


def test_pairwise_add_long():
    random.seed(12)
    specs = []
    for sw, cnt in [(8, 16), (16, 8), (32, 4), (8, 8), (16, 4), (32, 2)]:
        for s in (True, False):
            specs.append((f"Iop_PwAddL{sw}{'S' if s else 'U'}x{cnt}", sw, cnt, s))
    specs.append(("Iop_PwAddL64Ux2", 64, 2, False))
    for name, sw, cnt, signed in specs:
        assert name in irop.operations, name
        dw = 2 * sw
        for _ in range(40):
            a = [random.getrandbits(sw) for _ in range(cnt)]
            got = _lanes(_ev(name, claripy.BVV(_pack(a, sw), sw * cnt)), dw, cnt // 2)
            exp = []
            for k in range(0, cnt, 2):
                x, y = a[k], a[k + 1]
                if signed:
                    x = x - (1 << sw) if (x >> (sw - 1)) & 1 else x
                    y = y - (1 << sw) if (y >> (sw - 1)) & 1 else y
                exp.append((x + y) & ((1 << dw) - 1))
            assert got == exp, f"{name}"


# ---------------- Batch C: QDMulHi / QRDMulHi / QDMull / NarrowBin / Polynomial ----------------

def _sq(x, lw):
    return x - (1 << lw) if (x >> (lw - 1)) & 1 else x


def _sat_s(v, w):
    hi, lo = (1 << (w - 1)) - 1, -(1 << (w - 1))
    return (hi if v > hi else lo if v < lo else v) & ((1 << w) - 1)


def test_qdmulhi_qrdmulhi():
    random.seed(21)
    for lw, cnt in [(16, 8), (32, 4), (16, 4), (32, 2)]:
        for rnd in (False, True):
            name = f"Iop_{'QRDMulHi' if rnd else 'QDMulHi'}{lw}Sx{cnt}"
            assert name in irop.operations, name
            for _ in range(50):
                a = [random.choice([0, 1, (1 << (lw - 1)), (1 << (lw - 1)) - 1, (1 << lw) - 1, random.getrandbits(lw)]) for _ in range(cnt)]
                b = [random.choice([0, 1, (1 << (lw - 1)), (1 << (lw - 1)) - 1, (1 << lw) - 1, random.getrandbits(lw)]) for _ in range(cnt)]
                got = _lanes(_ev(name, claripy.BVV(_pack(a, lw), lw * cnt), claripy.BVV(_pack(b, lw), lw * cnt)), lw, cnt)
                exp = []
                for i in range(cnt):
                    d = _sq(a[i], lw) * _sq(b[i], lw) * 2
                    if rnd:
                        d += 1 << (lw - 1)
                    exp.append(_sat_s(d >> lw, lw))
                assert got == exp, f"{name} a={a} b={b}"


def test_qdmull():
    random.seed(22)
    for lw, cnt in [(16, 4), (32, 2)]:
        name = f"Iop_QDMull{lw}Sx{cnt}"
        dw = 2 * lw
        assert name in irop.operations
        for _ in range(50):
            a = [random.choice([0, 1, 1 << (lw - 1), (1 << lw) - 1, random.getrandbits(lw)]) for _ in range(cnt)]
            b = [random.choice([0, 1, 1 << (lw - 1), (1 << lw) - 1, random.getrandbits(lw)]) for _ in range(cnt)]
            got = _lanes(_ev(name, claripy.BVV(_pack(a, lw), lw * cnt), claripy.BVV(_pack(b, lw), lw * cnt)), dw, cnt)
            exp = [_sat_s(_sq(a[i], lw) * _sq(b[i], lw) * 2, dw) for i in range(cnt)]
            assert got == exp, f"{name}"


def test_narrowbin_truncating():
    random.seed(23)
    for name, src, dst, cnt in [("Iop_NarrowBin16to8x16", 16, 8, 16), ("Iop_NarrowBin16to8x8", 16, 8, 8),
                                ("Iop_NarrowBin32to16x4", 32, 16, 4), ("Iop_NarrowBin32to16x8", 32, 16, 8),
                                ("Iop_NarrowBin64to32x4", 64, 32, 4)]:
        assert name in irop.operations, name
        half = cnt // 2
        for _ in range(30):
            a1 = [random.getrandbits(src) for _ in range(half)]
            a2 = [random.getrandbits(src) for _ in range(half)]
            got = _lanes(_ev(name, claripy.BVV(_pack(a1, src), src * half), claripy.BVV(_pack(a2, src), src * half)), dst, cnt)
            exp = [x & ((1 << dst) - 1) for x in a2] + [x & ((1 << dst) - 1) for x in a1]
            assert got == exp, f"{name}"


def _polymul(a, b, bw):
    r = 0
    for i in range(bw):
        if (b >> i) & 1:
            r ^= a << i
    return r


def test_polynomial_mul():
    random.seed(24)
    for _ in range(40):
        a = [random.getrandbits(8) for _ in range(16)]
        b = [random.getrandbits(8) for _ in range(16)]
        got = _lanes(_ev("Iop_PolynomialMul8x16", claripy.BVV(_pack(a, 8), 128), claripy.BVV(_pack(b, 8), 128)), 8, 16)
        assert got == [_polymul(a[i], b[i], 8) & 0xff for i in range(16)]
    for _ in range(40):
        a = [random.getrandbits(8) for _ in range(8)]
        b = [random.getrandbits(8) for _ in range(8)]
        got = _lanes(_ev("Iop_PolynomialMull8x8", claripy.BVV(_pack(a, 8), 64), claripy.BVV(_pack(b, 8), 64)), 16, 8)
        assert got == [_polymul(a[i], b[i], 8) & 0xffff for i in range(8)]


# ---------------- Batch D: QAddExt (SUQADD / USQADD) ----------------

def test_qaddext_suqadd_usqadd():
    random.seed(31)
    for lw, cnt in [(8, 16), (16, 8), (32, 4), (64, 2)]:
        # (name, left_signed, right_signed, sat_signed)
        for name, lsig, rsig, ssig in [(f"Iop_QAddExtUSsatSS{lw}x{cnt}", False, True, True),
                                       (f"Iop_QAddExtSUsatUU{lw}x{cnt}", True, False, False)]:
            assert name in irop.operations, name
            for _ in range(40):
                L = [random.choice([0, 1, 1 << (lw - 1), (1 << lw) - 1, random.getrandbits(lw)]) for _ in range(cnt)]
                R = [random.choice([0, 1, 1 << (lw - 1), (1 << lw) - 1, random.getrandbits(lw)]) for _ in range(cnt)]
                got = _lanes(_ev(name, claripy.BVV(_pack(L, lw), lw * cnt), claripy.BVV(_pack(R, lw), lw * cnt)), lw, cnt)
                exp = []
                for i in range(cnt):
                    la = _sq(L[i], lw) if lsig else L[i]
                    rb = _sq(R[i], lw) if rsig else R[i]
                    s = la + rb
                    if ssig:
                        s = _sat_s(s, lw)
                    else:
                        s = max(0, min((1 << lw) - 1, s)) & ((1 << lw) - 1)
                    exp.append(s & ((1 << lw) - 1))
                assert got == exp, f"{name} L={L} R={R} got={got} exp={exp}"


# ---------------- NEON FP: sqrt, compares, recip/rsqrt step, maxnum/minnum, FP pairwise ----------------
import struct as _struct


def _f32(bits):
    return _struct.unpack("<f", _struct.pack("<I", bits & 0xffffffff))[0]


def _f32b(x):
    return _struct.unpack("<I", _struct.pack("<f", x))[0]


def test_fp_sqrt_vector():
    for name, lw, cnt, vals in [("Iop_Sqrt32Fx4", 32, 4, [4.0, 9.0, 2.0, 0.25])]:
        assert name in irop.operations
        got = _lanes(_ev(name, claripy.BVV(_pack([_f32b(v) for v in vals], 32), 128)), 32, 4)
        import math
        for g, v in zip(got, vals):
            assert abs(_f32(g) - math.sqrt(v)) < 1e-6


def test_fp_compare_masks():
    gt = irop.operations["Iop_CmpGT32Fx4"]
    a = claripy.BVV(_pack([_f32b(2.0), _f32b(1.0), _f32b(float("nan")), _f32b(-1.0)], 32), 128)
    b = claripy.BVV(_pack([_f32b(1.0), _f32b(2.0), _f32b(0.0), _f32b(-2.0)], 32), 128)
    got = _lanes(claripy.backends.concrete.eval(gt._calculate([a, b]), 1)[0], 32, 4)
    assert got == [0xffffffff, 0, 0, 0xffffffff]           # 2>1, 1>2 no, nan no, -1>-2
    un = irop.operations["Iop_CmpUN32Fx4"]
    got = _lanes(claripy.backends.concrete.eval(un._calculate([a, b]), 1)[0], 32, 4)
    assert got == [0, 0, 0xffffffff, 0]                    # only the NaN lane is unordered


def test_fp_recip_rsqrt_step():
    rs = irop.operations["Iop_RecipStep32Fx4"]
    a = claripy.BVV(_pack([_f32b(3.0), _f32b(0.0), _f32b(1.0), _f32b(2.0)], 32), 128)
    b = claripy.BVV(_pack([_f32b(0.5), _f32b(float("inf")), _f32b(1.0), _f32b(1.0)], 32), 128)
    got = _lanes(claripy.backends.concrete.eval(rs._calculate([a, b]), 1)[0], 32, 4)
    assert abs(_f32(got[0]) - 0.5) < 1e-6                  # 2 - 3*0.5
    assert _f32(got[1]) == 2.0                             # 0*inf special -> 2.0
    assert abs(_f32(got[2]) - 1.0) < 1e-6                  # 2 - 1
    rsq = irop.operations["Iop_RSqrtStep32Fx4"]
    got = _lanes(claripy.backends.concrete.eval(rsq._calculate([a, b]), 1)[0], 32, 4)
    assert _f32(got[1]) == 1.5                             # 0*inf special -> 1.5


def test_fp_maxnum_minnum():
    mx = irop.operations["Iop_MaxNumF32"]
    assert _f32(claripy.backends.concrete.eval(mx._calculate([claripy.BVV(_f32b(1.0), 32), claripy.BVV(_f32b(float("nan")), 32)]), 1)[0]) == 1.0
    mn = irop.operations["Iop_MinNumF32"]
    assert _f32(claripy.backends.concrete.eval(mn._calculate([claripy.BVV(_f32b(5.0), 32), claripy.BVV(_f32b(2.0), 32)]), 1)[0]) == 2.0


def test_fp_pairwise():
    pa = irop.operations["Iop_PwAdd32Fx2"]
    a = claripy.BVV(_pack([_f32b(1.0), _f32b(2.0)], 32), 64)
    b = claripy.BVV(_pack([_f32b(3.0), _f32b(4.0)], 32), 64)
    got = _lanes(claripy.backends.concrete.eval(pa._calculate([a, b]), 1)[0], 32, 2)
    assert abs(_f32(got[0]) - 3.0) < 1e-6 and abs(_f32(got[1]) - 7.0) < 1e-6


# ---------------- NEON FP conversions ----------------

def test_int_to_float():
    s = irop.operations["Iop_I32StoFx4"]
    got = _lanes(claripy.backends.concrete.eval(s._calculate([claripy.BVV(_pack([5, (-5) & 0xffffffff, 0, 100], 32), 128)]), 1)[0], 32, 4)
    assert [_f32(g) for g in got] == [5.0, -5.0, 0.0, 100.0]
    u = irop.operations["Iop_I32UtoFx4"]
    got = _lanes(claripy.backends.concrete.eval(u._calculate([claripy.BVV(_pack([0xffffffff, 1, 0, 2], 32), 128)]), 1)[0], 32, 4)
    assert _f32(got[0]) == 4294967296.0 and _f32(got[1]) == 1.0


def test_float_to_int_saturating():
    s = irop.operations["Iop_QFtoI32Sx4_RZ"]
    inp = [_f32b(3.9), _f32b(-3.9), _f32b(1e30), _f32b(float("nan"))]
    got = _lanes(claripy.backends.concrete.eval(s._calculate([claripy.BVV(_pack(inp, 32), 128)]), 1)[0], 32, 4)
    assert got[0] == 3                              # round toward zero
    assert got[1] == (-3) & 0xffffffff
    assert got[2] == 0x7fffffff                     # saturate to INT_MAX
    assert got[3] == 0                              # NaN -> 0
    u = irop.operations["Iop_QFtoI32Ux4_RZ"]
    inp = [_f32b(2.5), _f32b(-1.0), _f32b(1e30), _f32b(5.0)]
    got = _lanes(claripy.backends.concrete.eval(u._calculate([claripy.BVV(_pack(inp, 32), 128)]), 1)[0], 32, 4)
    assert got == [2, 0, 0xffffffff, 5]             # neg -> 0, overflow -> UINT_MAX


def test_fixed_point_roundtrip():
    f2x = irop.operations["Iop_F32ToFixed32Sx4_RZ"]
    # 1.5 with 8 fraction bits -> 1.5 * 256 = 384
    got = _lanes(claripy.backends.concrete.eval(f2x._calculate([claripy.BVV(_pack([_f32b(1.5), _f32b(-2.0), _f32b(0.0), _f32b(1.0)], 32), 128), claripy.BVV(8, 8)]), 1)[0], 32, 4)
    assert got[0] == 384 and got[1] == ((-512) & 0xffffffff) and got[3] == 256
    x2f = irop.operations["Iop_Fixed32SToF32x4_RN"]
    got = _lanes(claripy.backends.concrete.eval(x2f._calculate([claripy.BVV(_pack([384, 256, 0, 128], 32), 128), claripy.BVV(8, 8)]), 1)[0], 32, 4)
    assert [_f32(g) for g in got] == [1.5, 1.0, 0.0, 0.5]
