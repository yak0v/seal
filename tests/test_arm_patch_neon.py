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
