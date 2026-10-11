"""
The arm64 half-precision (f16) conversion handlers in angr_arm_patch are bit-level
bitvector implementations (claripy has no 16-bit float type). This pins them bit-exact
against numpy.float16. Skips if numpy isn't installed.
"""
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
np = pytest.importorskip("numpy")

import claripy                              # noqa: E402
from angrgui import angr_arm_patch          # noqa: E402
import angr.engines.vex.claripy.irop as irop  # noqa: E402

angr_arm_patch.apply()


def _ev(op, bv):
    return claripy.backends.concrete.eval(irop.operations[op]._calculate([bv]), 1)[0]


def test_f16_to_f32_matches_numpy():
    """Exact over a representative set incl. subnormals, inf, nan, boundaries."""
    sample = list(range(0, 0x10000, 37)) + [0, 1, 0x3c00, 0x7bff, 0x7c00, 0x7e00,
                                            0x8000, 0xfbff, 0xfc00, 0x03ff, 0x0400]
    bad = 0
    for u in sample:
        want = struct.unpack("<I", struct.pack("<f", float(np.frombuffer(struct.pack("<H", u), np.float16)[0])))[0]
        got = _ev("Iop_F16toF32", claripy.BVV(u, 16))
        wf = np.frombuffer(struct.pack("<I", want), np.float32)[0]
        gf = np.frombuffer(struct.pack("<I", got), np.float32)[0]
        if np.isnan(wf) and np.isnan(gf):
            continue
        bad += (got != want)
    assert bad == 0


def test_f32_to_f16_matches_numpy():
    """Round-to-nearest-even over round-trip anchors, boundaries and ties."""
    vals = [1.0, -1.0, 2.5, -2.5, 65504.0, 65536.0, 1e-5, 6e-8, 1e-10, 0.0, -0.0,
            float("inf"), float("-inf"), 3.14159, 0.333333, 1024.0, 0.00006103515625]
    bits = [struct.unpack("<I", struct.pack("<f", v))[0] for v in vals]
    bits += [struct.unpack("<I", struct.pack("<f", float(np.frombuffer(struct.pack("<H", u), np.float16)[0])))[0]
             for u in range(0, 0x10000, 101)]
    bad = 0
    for b in bits:
        want = int.from_bytes(np.float16(np.frombuffer(struct.pack("<I", b), np.float32)[0]).tobytes(), "little")
        got = _ev("Iop_F32toF16", claripy.BVV(b, 32))
        wf = np.frombuffer(struct.pack("<H", want), np.float16)[0]
        gf = np.frombuffer(struct.pack("<H", got), np.float16)[0]
        if np.isnan(wf) and np.isnan(gf):
            continue
        bad += (got != want)
    assert bad == 0


def test_f32_to_f16_x4_lanes():
    """The 4-lane vector form converts each 32-bit lane independently."""
    lanes = [1.0, 2.0, -3.0, 0.5]
    inp = 0
    for i, v in enumerate(lanes):
        inp |= struct.unpack("<I", struct.pack("<f", v))[0] << (32 * i)
    got = _ev("Iop_F32toF16x4", claripy.BVV(inp, 128))
    exp = 0
    for i, v in enumerate(lanes):
        exp |= int.from_bytes(np.float16(np.float32(v)).tobytes(), "little") << (16 * i)
    assert got == exp


def test_vector_fp_sqrt():
    """NEON vector FSQRT (Iop_Sqrt64Fx2 / Sqrt32Fx4) — angr lane-splits to the scalar
    sqrt handler, which must accept a per-lane FP. Was broken (args[0] on an FP)."""
    import struct
    import claripy
    from angrgui import angr_arm_patch
    from angr.engines.vex.claripy.irop import vexop_to_simop
    angr_arm_patch.apply()

    def vsqrt(name, vals, fmt, lb):
        b = b"".join(struct.pack(fmt, x) for x in vals)
        v = claripy.BVV(int.from_bytes(b, "little"), 128)
        rv = claripy.backends.concrete.eval(vexop_to_simop(name).calculate(v), 1)[0].to_bytes(16, "little")
        return [struct.unpack(fmt, rv[i * lb:i * lb + lb])[0] for i in range(len(vals))]

    assert vsqrt("Iop_Sqrt64Fx2", [4.0, 9.0], "<d", 8) == [2.0, 3.0]
    assert vsqrt("Iop_Sqrt32Fx4", [4.0, 9.0, 16.0, 25.0], "<f", 4) == [2.0, 3.0, 4.0, 5.0]
    # symbolic doesn't crash
    assert vexop_to_simop("Iop_Sqrt64Fx2").calculate(claripy.BVS("a", 128)).size() == 128
