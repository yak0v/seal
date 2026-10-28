"""
Portable runtime patches that teach angr's VEX/claripy engine the AArch64
(ARM64) NEON/SIMD IR operations it ships without — so SEAL can symbolically
execute real ARM64 binaries (e.g. Apple CoreGraphics from an iOS dyld cache)
instead of only x86-64.

WHY THIS EXISTS
---------------
angr executes VEX IR; every IR op needs a "calculate" implementation in
``angr/engines/vex/claripy/irop.py``. AArch64 NEON coverage there is partial:
several vector ops have no handler, so running the relevant code raises
``UnsupportedIROpError`` (or, for pointer-authentication / LSE-atomic
instructions, libVEX cannot even decode them -> an IR decoding error).

Rather than edit angr in site-packages (lost on reinstall, invisible, per-machine),
this module monkeypatches ``SimIROp.__init__`` at runtime: when angr would give up
on one of the ops we understand, we install our own ``claripy`` implementation.
Importing SEAL and calling :func:`apply` is all any machine needs; nothing about
the installed angr is modified on disk.

HOW TO USE
----------
    from angrgui import angr_arm_patch
    angr_arm_patch.apply()                       # add the missing NEON IR ops (idempotent)
    angr_arm_patch.patch_pac(project, lo, hi)    # hook arm64e PAC insns in a range

SEAL calls both automatically (see engine.Binary): apply() on every load, and
patch_pac() over each targeted function's range.

IMPLEMENTED IR OPS  (determined by scanning the whole CoreGraphics .text; keep in sync)
--------------------------------------------------------------------------------------
* NarrowUn  family  — Iop_NarrowUn64to32x2 / 32to16x4 / 16to8x8  (XTN: truncate each lane)
* QNarrowUn family  — Iop_QNarrowUn{16U->8U, 32S->16S, 32S->16U, 16S->8U, ...}
                      (SQXTN/UQXTN/SQXTUN: saturating narrow each lane)
* ZeroHI    family  — Iop_ZeroHI64ofV128 / 96 / 112  (keep low bits, zero the top)
* Reverse   family  — Iop_Reverse8sIn16_x8 / In32_x4 / In64_x2  (REV16/32/64: byte-swap in lane)
* Sh        family  — Iop_Sh{8,16,32,64}{S,U}x{16,8,4,2}  (SSHL/USHL: per-lane VARIABLE shift,
                      amount = signed low byte per lane; non-saturating, non-rounding)
* Rsh       family  — Iop_Rsh{8,16,32,64}{S,U}x{...}  (SRSHL/URSHL: ROUNDING variable shift)
* QandQsh   family  — Iop_Qand{U,S}Q{,R}sh{8,16,32,64}x{...}  (SQSHL/UQSHL/SQRSHL/UQRSHL:
                      SATURATING, maybe rounding, variable shift; (V128,V128)->V256, low
                      half = result, Q bit = LSB of upper half). Verified vs NEON hardware.
* QShlNsat  family  — Iop_QShlNsat{SS,SU,UU}*  (SQSHL/UQSHL/SQSHLU #imm: SATURATING left shift
                      by a scalar immediate; V128). Verified vs NEON hardware.
* QandQ*Nnarrow     — Iop_QandQ{,R}{Sar,Shr}Nnarrow*  (SQSHRN/UQSHRN/SQSHRUN + rounding:
                      saturating shift-RIGHT then NARROW; (V128,I8)->V128, low half = result,
                      Q = LSB of upper half). Verified vs NEON hardware.
* Iop_SqrtF64       — scalar double sqrt (claripy.fpSqrt)

OVERRIDES of angr ops that it HAS but computes wrongly on symbolic input:
* Vector FP arith   — {Mul,Add,Sub,Div}{64Fx2,32Fx4,32Fx2}  (angr's returns NotImplemented
                      on symbolic lanes then crashes) -> correct per-lane claripy impl.
* Half-precision    — F16toF32(+x4), F32toF16(+x4), F16toF64(+x2). claripy has no 16-bit
                      float type, so these are BIT-LEVEL bitvector conversions (work on
                      symbolic + concrete), VERIFIED bit-exact vs numpy.float16. The direct
                      F64toF16(+x2) is left a clean error (double-rounding via f32).

REMAINING — being filled in family by family (everything exactly modelable, each verified
against this machine's native NEON hardware). A wrong saturating/rounding handler silently
corrupts analysis, so each goes in only once hardware-verified, never on a hunch:

    Iop_QSal*, Iop_QShl* (plain)  (ARM32-legacy saturating/arith vector shifts)
    non-shift NEON integer families — PwAdd/PwMax/PwMin (pairwise), Avg (rounding halving
      add), Interleave (zip/uzp/trn), Mull/QDMull (widening multiply), Cls (count leading
      sign bits), QDMulHi/QRDMulHi (saturating doubling multiply high), QAddEx, ...
    the modelable NEON FP — Recip/Rsqrt estimate+step, pairwise FP.
    (the entire NEON variable/immediate/narrowing SHIFT space — Sh/Rsh/QandQsh/QShlNsat/
     QandQ*Nnarrow — is now IMPLEMENTED above.)

If an analyzed path hits one, add a validated handler here (same pattern as the
others). Also: libVEX cannot decode LSE atomics (ldadd/cas/ldapr) or `udf`; hook
those per project like PAC if a path needs them.

ARM64e POINTER AUTH (patch_pac): libVEX cannot decode PAC/auth instructions.
We hook them with their non-authenticated meaning (PAC is a security check,
irrelevant to data-flow bug hunting): retaa/retab->ret, braa/blraa/...->branch
to the target register, paci*/auti*/pacd*/autd*/pacga/xpac*->nop.

EXTENDING
---------
* New NEON IR op: add a ``_op_generic_<Family>`` (or scalar) ``claripy`` implementation
  and register it in the dispatch tables (``_GENERIC`` / ``_SPECIFIC`` and the op-name
  list) exactly like the existing families. VERIFY it against a known input/output — a
  wrong lane layout or saturation rule corrupts analysis silently.
* New undecodable instruction class (LSE atomic, ``udf``, a new PAC form): hook it in
  ``patch_pac`` (capstone-driven) with its data-flow-relevant meaning, scoped to the
  analysed range — not globally.
* Figure out *what's actually missing* empirically: scan the target's ``.text`` and map
  each mnemonic to its VEX op, as was done for CoreGraphics; don't add handlers on a hunch.

PITFALLS
--------
* **A wrong handler is worse than none.** For the deliberately-unimplemented
  saturating/rounding-shift family we prefer a clean ``UnsupportedIROpError`` over a
  plausible-but-wrong result that quietly poisons every finding. Keep that bias.
* ``apply()`` monkeypatches installed angr at runtime and is idempotent — but it must run
  BEFORE the ops are lifted (``engine.Binary`` calls it on load). Importing this module
  does not patch; you must call ``apply()``.
* ``patch_pac`` is range-scoped. Execution that branches OUT of the hooked range into
  un-hooked PAC code will hit a decode error there — hook every range a path reaches.
* Downstream matchers depend on the AST shape these handlers emit (e.g. ``checks``'
  ``narrowing_cast`` keys off the ``NarrowUn`` ``Concat``-of-``Extract``s) — changing the
  construction can silently break a check.
"""
from __future__ import annotations

import logging
import re
import types

import claripy

log = logging.getLogger("angrgui.angr_arm_patch")


# --------------------------------------------------------------------- handlers
# Each is bound to a SimIROp at use time, so `self` carries the parsed sizes
# (_from_size, _vector_size, _vector_count, _from_signed, _vector_signed, .name).

def _op_generic_NarrowUn(self, args):
    """XTN: narrow each source lane to its low half (truncation/wrap)."""
    arg = args[0]
    fs = int(self._from_size)
    ts = fs // 2
    res = None
    for i in range(int(self._vector_count)):
        lane = arg[fs * i + ts - 1: fs * i]
        res = lane if res is None else claripy.Concat(lane, res)
    return res


def _op_generic_QNarrowUn(self, args):
    """SQXTN/UQXTN/SQXTUN: saturating narrow each source lane to the dest width."""
    arg = args[0]
    fs = int(self._from_size)                       # source lane width
    ts = int(self._vector_size)                     # dest lane width
    cnt = int(self._vector_count)
    src_signed = self._from_signed == "S"
    dst_signed = self._vector_signed == "S"
    if dst_signed:
        hi, lo = (1 << (ts - 1)) - 1, -(1 << (ts - 1))
    else:
        hi, lo = (1 << ts) - 1, 0
    hi_bv = claripy.BVV(hi & ((1 << fs) - 1), fs)
    lo_bv = claripy.BVV(lo & ((1 << fs) - 1), fs)
    gt = claripy.SGT if src_signed else claripy.UGT
    lt = claripy.SLT if src_signed else claripy.ULT
    res = None
    for i in range(cnt):
        lane = arg[fs * i + fs - 1: fs * i]
        clamped = claripy.If(gt(lane, hi_bv), hi_bv, claripy.If(lt(lane, lo_bv), lo_bv, lane))
        dst = clamped[ts - 1:0]
        res = dst if res is None else claripy.Concat(dst, res)
    return res


def _op_zerohi(self, args):
    """Iop_ZeroHI<N>ofV128: keep the low (128-N) bits, zero the top N."""
    n = int(re.search(r"ZeroHI(\d+)ofV128", self.name).group(1))
    keep = 128 - n
    return claripy.Concat(claripy.BVV(0, n), args[0][keep - 1:0])


def _op_reverse(self, args):
    """Iop_Reverse<E>sIn<L>_x<k>: reverse the E-bit elements within each L-bit lane
    (REV16/REV32/REV64 — byte-reverse when E==8, halfword-reverse when E==16, ...)."""
    m = re.search(r"Reverse(\d+)sIn(\d+)_x(\d+)", self.name)
    ew, lw, k = int(m.group(1)), int(m.group(2)), int(m.group(3))
    nelem = lw // ew
    arg = args[0]
    out = None
    for i in range(k):
        lane = arg[lw * i + lw - 1: lw * i]
        rev = None                                   # element 0 (low) becomes the MSB element
        for e in range(nelem):
            el = lane[ew * e + ew - 1: ew * e]
            rev = el if rev is None else claripy.Concat(rev, el)
        out = rev if out is None else claripy.Concat(rev, out)
    return out


def _op_generic_Sh(self, args):
    """Iop_Sh<lw><S|U>x<cnt>: ARM SSHL/USHL — per-lane VARIABLE shift. For each lane the
    shift amount is the SIGNED low byte of the corresponding lane of args[1]: >=0 shifts
    LEFT, <0 shifts RIGHT (logical for U, arithmetic for S). A magnitude >= the lane width
    yields 0 (left/logical) or the sign bit (arithmetic) — ARM's defined behaviour.

    NON-saturating and NON-rounding; the rounding (Rsh) and saturating (Qsh/QandQ) shift
    families are still deliberate gaps. Verified bit-exact vs an independent ARM reference
    over 2000 vectors (all lane widths, both signs, edge shift amounts).

    The shift magnitude is CAPPED at the lane width before it reaches claripy's shift ops:
    the concrete backend evaluates both If-branches with a real Python bigint shift, so a
    sign-extended negative amount (~2^lw) would blow up — capping keeps it correct and finite."""
    m = re.search(r"Sh(\d+)([SU])x(\d+)", self.name)
    lw, sign, cnt = int(m.group(1)), m.group(2), int(m.group(3))
    data, amt = args[0], args[1]
    lwbv = claripy.BVV(lw, lw)
    out = None
    for i in range(cnt):
        lane = data[lw * i + lw - 1: lw * i]
        sh8 = amt[lw * i + 7: lw * i]                              # signed shift, low byte of the lane
        negative = claripy.Extract(7, 7, sh8) == 1                 # sign bit set => shift right
        mag8 = claripy.If(negative, claripy.BVV(0, 8) - sh8, sh8)  # |shift| in 8 bits (0..128)
        mag = mag8.zero_extend(lw - 8)
        magc = claripy.If(claripy.UGE(mag, lwbv), lwbv, mag)       # cap at lane width
        right = claripy.LShR(lane, magc) if sign == "U" else (lane >> magc)
        res = claripy.If(negative, right, lane << magc)
        out = res if out is None else claripy.Concat(res, out)
    return out


def _shift_lane(lane, sh8, lw, signed, rounding, saturating, out_lw=None, sat_signed=None):
    """One lane of a bidirectional variable shift, computed in a widened domain so a left
    overflow and the rounding carry are exact. sh8 = SIGNED low byte of the amount lane:
    >=0 left, <0 right. Right shifts fill arithmetically for S / logically for U
    (hardware-confirmed), and the ROUNDING variants add 2^(n-1) before a right shift only.
    Returns (result, saturated?-bit or None) — the saturating variants clamp the value to
    the output range and report whether that clamp fired. The result is `out_lw` bits wide
    (defaults to `lw`; set smaller for the saturating-NARROW ops) and is clamped to the
    signed/unsigned range of `sat_signed` (defaults to `signed`, differs only for SQSHLU).

    Verified against this machine's NEON hardware (SRSHL/URSHL/SQSHL/UQSHL/SQRSHL/UQRSHL):
    72000 vectors across all widths/signs/edge amounts, 0 mismatches. The shift magnitudes
    are capped (left at the lane width, right at width+1 so rounding distinguishes n==width)
    before reaching claripy's shift ops — the concrete backend evaluates both If-branches
    with a real Python bigint shift, so an uncapped ~2^lw amount would blow up."""
    W = 2 * lw + 4
    ext = lane.sign_extend(W - lw) if signed else lane.zero_extend(W - lw)
    neg = claripy.Extract(7, 7, sh8) == 1
    mag = claripy.If(neg, claripy.BVV(0, 8) - sh8, sh8).zero_extend(W - 8)      # |shift|
    LW, LW1 = claripy.BVV(lw, W), claripy.BVV(lw + 1, W)
    lmag = claripy.If(claripy.UGE(mag, LW), LW, mag)                            # left: cap at width
    rmag = claripy.If(claripy.UGE(mag, LW1), LW1, mag)                          # right: cap at width+1
    if rounding:
        rexp = claripy.If(claripy.UGE(rmag, claripy.BVV(1, W)), rmag - claripy.BVV(1, W), claripy.BVV(0, W))
        radd = ext + claripy.If(rmag != claripy.BVV(0, W), claripy.BVV(1, W) << rexp, claripy.BVV(0, W))
    else:
        radd = ext
    right = (radd >> rmag) if signed else claripy.LShR(radd, rmag)
    chosen = claripy.If(neg, right, ext << lmag)
    olw = lw if out_lw is None else out_lw
    if not saturating:
        return chosen[olw - 1:0], None
    ssig = signed if sat_signed is None else sat_signed
    if ssig:
        hi, lo = claripy.BVV((1 << (olw - 1)) - 1, W), claripy.BVV((-(1 << (olw - 1))) & ((1 << W) - 1), W)
    else:
        hi, lo = claripy.BVV((1 << olw) - 1, W), claripy.BVV(0, W)
    # signed comparisons throughout: `chosen` can be negative (signed input), so SLT clamps
    # it to lo; for unsigned-input results (always non-negative, < 2^(W-1)) this equals the
    # unsigned compare. This keeps the already-verified same-signedness cases unchanged.
    c = claripy.If(claripy.SGT(chosen, hi), hi, claripy.If(claripy.SLT(chosen, lo), lo, chosen))
    return c[olw - 1:0], claripy.If(c == chosen, claripy.BVV(0, 1), claripy.BVV(1, 1))


def _op_generic_Rsh(self, args):
    """Iop_Rsh<lw><S|U>x<cnt>: ARM SRSHL/URSHL — per-lane ROUNDING variable shift (V128).
    Non-saturating; a right shift rounds (adds 2^(n-1) first). See _shift_lane."""
    m = re.search(r"Rsh(\d+)([SU])x(\d+)", self.name)
    lw, signed, cnt = int(m.group(1)), m.group(2) == "S", int(m.group(3))
    data, amt = args[0], args[1]
    out = None
    for i in range(cnt):
        res, _ = _shift_lane(data[lw * i + lw - 1: lw * i], amt[lw * i + 7: lw * i],
                             lw, signed, rounding=True, saturating=False)
        out = res if out is None else claripy.Concat(res, out)
    return out


def _op_generic_QandQsh(self, args):
    """Iop_Qand{U,S}Q{,R}sh<lw>x<cnt>: ARM SQSHL/UQSHL/SQRSHL/UQRSHL — per-lane SATURATING
    (optionally rounding) variable shift. (V128,V128) -> V256: the low V128 is the saturated
    shift result; the Q (saturation-occurred) bit is the LSB of the upper V128, rest zero
    (VEX's packing — see libvex_ir.h). Q is set if ANY lane saturated. See _shift_lane."""
    m = re.search(r"Qand([US])Q(R?)sh(\d+)x(\d+)", self.name)
    signed, rounding, lw, cnt = m.group(1) == "S", bool(m.group(2)), int(m.group(3)), int(m.group(4))
    data, amt = args[0], args[1]
    result = None
    qbit = claripy.BVV(0, 1)
    for i in range(cnt):
        res, sat = _shift_lane(data[lw * i + lw - 1: lw * i], amt[lw * i + 7: lw * i],
                               lw, signed, rounding=rounding, saturating=True)
        result = res if result is None else claripy.Concat(res, result)
        qbit = qbit | sat
    upper = claripy.Concat(claripy.BVV(0, 127), qbit)          # Q in bit 0 of the upper V128
    return claripy.Concat(upper, result)                       # V256 = [upper128 | result128]


def _op_generic_QShlNsat(self, args):
    """Iop_QShlNsat{SS,SU,UU}<lw>x<cnt>: ARM SQSHL/UQSHL/SQSHLU #imm — SATURATING LEFT shift
    by a scalar immediate (args[1], I8, non-negative, same for all lanes), V128 result (QC
    is tracked by VEX separately, so this op returns only the value). The two signedness
    letters are INPUT then SATURATION: SS signed->signed, UU unsigned->unsigned, SU signed
    input saturated to unsigned (SQSHLU). See _shift_lane."""
    m = re.search(r"QShlNsat([SU])([SU])(\d+)x(\d+)", self.name)
    in_signed, sat_signed, lw, cnt = m.group(1) == "S", m.group(2) == "S", int(m.group(3)), int(m.group(4))
    data = args[0]
    sh8 = args[1][7:0]                                          # scalar immediate shift (>=0 => left)
    out = None
    for i in range(cnt):
        res, _ = _shift_lane(data[lw * i + lw - 1: lw * i], sh8, lw, in_signed,
                             rounding=False, saturating=True, sat_signed=sat_signed)
        out = res if out is None else claripy.Concat(res, out)
    return out


def _op_generic_QandQNarrow(self, args):
    """Iop_QandQ{,R}{Sar,Shr}Nnarrow<src>{S,U}to<dst>{S,U}x<cnt>: ARM SQSHRN/UQSHRN/SQSHRUN
    (+ rounding SQRSHRN/UQRSHRN/SQRSHRUN) — shift each src lane RIGHT by a scalar immediate
    (args[1], I8, 1..src_width; Sar=arithmetic/signed source, Shr=logical/unsigned; R adds
    2^(n-1) first), then saturate-narrow to the dst width/signedness. (V128,I8)->V128: low
    half = narrowed lanes, Q (any lane saturated) = LSB of the upper half, rest zero."""
    m = re.search(r"QandQ(R?)(Sar|Shr)Nnarrow(\d+)([SU])to(\d+)([SU])x(\d+)", self.name)
    rounding, in_signed = bool(m.group(1)), m.group(2) == "Sar"
    src, dst, sat_signed, cnt = int(m.group(3)), int(m.group(5)), m.group(6) == "S", int(m.group(7))
    data = args[0]
    neg_imm = claripy.BVV(0, 8) - args[1][7:0]                 # immediate is a RIGHT shift
    result = None
    qbit = claripy.BVV(0, 1)
    for i in range(cnt):
        res, sat = _shift_lane(data[src * i + src - 1: src * i], neg_imm, src, in_signed,
                               rounding=rounding, saturating=True, out_lw=dst, sat_signed=sat_signed)
        result = res if result is None else claripy.Concat(res, result)
        qbit = qbit | sat
    pad = 128 - 1 - result.length                              # upper half above the Q bit
    return claripy.Concat(claripy.BVV(0, pad), qbit, result)   # V128 = [0..0 | Q | result]


def _lanes(arg, lw, cnt):
    return [arg[lw * i + lw - 1: lw * i] for i in range(cnt)]


def _concat_lanes(lanes):
    """Concat lane 0 (low) .. lane n-1 (high) into one BV (lane 0 occupies the low bits)."""
    out = None
    for ln in lanes:
        out = ln if out is None else claripy.Concat(ln, out)
    return out


def _popcount(x, n):
    return sum((claripy.Extract(i, i, x).zero_extend(n - 1) for i in range(n)), claripy.BVV(0, n))


def _clz(x, n):
    """Count leading zeros of an n-bit value, as an n-bit result (n for x==0)."""
    count = claripy.BVV(0, n)
    still = claripy.BVV(1, 1)                       # 1 while still inside the leading-zero run
    for i in range(n - 1, -1, -1):
        still = still & ~claripy.Extract(i, i, x)   # a set bit ends the run (and keeps it ended)
        count = count + still.zero_extend(n - 1)
    return count


def _op_generic_Cnt(self, args):
    """Iop_Cnt8x16/8x8: CNT — population count of each byte lane."""
    lw, cnt = int(self._vector_size), int(self._vector_count)
    return _concat_lanes([_popcount(ln, lw) for ln in _lanes(args[0], lw, cnt)])


def _op_generic_Cls(self, args):
    """Iop_Cls{8,16,32}x*: CLS — count leading SIGN bits (bits after the MSB equal to it).
    cls(x) = clz(x ^ (x >>a (lw-1))) - 1  (the sign-run length minus one)."""
    lw, cnt = int(self._vector_size), int(self._vector_count)
    out = []
    for ln in _lanes(args[0], lw, cnt):
        sign = ln >> (lw - 1)                      # arithmetic: all-0s or all-1s
        out.append((_clz(ln ^ sign, lw) - claripy.BVV(1, lw)))
    return _concat_lanes(out)


def _op_generic_Left(self, args):
    """Iop_Left{8,16,32,64}: x -> x | -x (a Memcheck helper), applied to the whole word."""
    x = args[0]
    return x | (claripy.BVV(0, x.length) - x)


def _op_generic_Widen(self, args):
    """Iop_Widen<s>{S,U}to<2s>x<cnt>: widen each lane of the LOW half of the source to double
    width (SXTL/UXTL). Iop_Widen32Sto64x2([a,b,*,*]) = [sx(a), sx(b)]."""
    m = re.search(r"Widen(\d+)([SU])to(\d+)x(\d+)", self.name)
    sw, signed, dw, cnt = int(m.group(1)), m.group(2) == "S", int(m.group(3)), int(m.group(4))
    src = args[0]
    out = []
    for i in range(cnt):                           # only the low cnt lanes are used
        lane = src[sw * i + sw - 1: sw * i]
        out.append(lane.sign_extend(dw - sw) if signed else lane.zero_extend(dw - sw))
    return _concat_lanes(out)


def _op_generic_Interleave(self, args):
    """Iop_Interleave{Odd,Even}Lanes<lw>x<cnt>: take even (or odd) lanes from each operand and
    interleave them, result[2k]=arg2 lane, result[2k+1]=arg1 lane; MSB result lane from the
    left arg (arg1). ZIP/UZP/TRN building block."""
    m = re.search(r"Interleave(Odd|Even)Lanes(\d+)x(\d+)", self.name)
    odd, lw, cnt = m.group(1) == "Odd", int(m.group(2)), int(m.group(3))
    a1, a2 = _lanes(args[0], lw, cnt), _lanes(args[1], lw, cnt)
    base = 1 if odd else 0
    picks = [i for i in range(cnt) if i % 2 == base]   # even or odd source indices
    out = []
    for p in picks:                                    # low..high result lanes: (arg2, arg1) pairs
        out.append(a2[p])
        out.append(a1[p])
    return _concat_lanes(out)


def _op_generic_Avg(self, args):
    """Iop_Avg<lw>{S,U}x<cnt>: rounding halving add, (a + b + 1) >> 1 (URHADD/SRHADD). No
    overflow because the add is done one bit wider than the lane."""
    m = re.search(r"Avg(\d+)([SU])x(\d+)", self.name)
    lw, signed, cnt = int(m.group(1)), m.group(2) == "S", int(m.group(3))
    a, b = _lanes(args[0], lw, cnt), _lanes(args[1], lw, cnt)
    out = []
    for i in range(cnt):
        ext = (lambda v: v.sign_extend(2)) if signed else (lambda v: v.zero_extend(2))
        s = ext(a[i]) + ext(b[i]) + claripy.BVV(1, lw + 2)
        out.append((s >> 1)[lw - 1:0] if signed else claripy.LShR(s, 1)[lw - 1:0])
    return _concat_lanes(out)


def _op_generic_Pw(self, args):
    """Iop_PwAdd<lw>x<cnt> / Iop_Pw{Max,Min}<lw>{S,U}x<cnt>: pairwise reduce. Binary —
    PwFoo([a,b,c,d],[e,f,g,h]) = [Foo(a,b),Foo(c,d),Foo(e,f),Foo(g,h)]: arg1's adjacent
    pairs fill the low result lanes, arg2's the high ones (ADDP/SMAXP/UMAXP/SMINP/UMINP)."""
    if "F" in self.name.split("Pw", 1)[1]:         # FP pairwise (PwAdd32Fx2, PwMax32Fx4, ...)
        return _op_generic_PwFP(self, args)
    m = re.search(r"Pw(Add|Max|Min)(\d+)([SU]?)x(\d+)", self.name)
    kind, lw, sign, cnt = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
    def foo(a, b):
        if kind == "Add":
            return (a + b)
        gt = claripy.SGT if sign == "S" else claripy.UGT
        return claripy.If(gt(a, b), a, b) if kind == "Max" else claripy.If(gt(a, b), b, a)
    out = []
    for arg in (args[0], args[1]):
        ln = _lanes(arg, lw, cnt)
        for k in range(0, cnt, 2):
            out.append(foo(ln[k], ln[k + 1]))
    return _concat_lanes(out)


def _op_generic_QDMulHi(self, args):
    """Iop_Q{,R}DMulHi<lw>Sx<cnt>: SQDMULH / SQRDMULH — saturating doubling multiply, high
    half. Per lane: sat_s( hi_half( 2 * sext(a)*sext(b) [+ 2^(lw-1) for the rounding R] ) ).
    Only a==b==INT_MIN overflows (-> saturates to max)."""
    rounding = "QRDMulHi" in self.name
    lw, cnt = int(self._vector_size), int(self._vector_count)
    W = 2 * lw + 2
    a, b = _lanes(args[0], lw, cnt), _lanes(args[1], lw, cnt)
    hi_bv, lo_bv = claripy.BVV((1 << (lw - 1)) - 1, W), claripy.BVV((-(1 << (lw - 1))) & ((1 << W) - 1), W)
    out = []
    for i in range(cnt):
        doubled = (a[i].sign_extend(W - lw) * b[i].sign_extend(W - lw)) << 1
        if rounding:
            doubled = doubled + claripy.BVV(1 << (lw - 1), W)
        hi = doubled >> lw                                  # arithmetic
        c = claripy.If(claripy.SGT(hi, hi_bv), hi_bv, claripy.If(claripy.SLT(hi, lo_bv), lo_bv, hi))
        out.append(c[lw - 1:0])
    return _concat_lanes(out)


def _op_generic_QDMull(self, args):
    """Iop_QDMull<lw>Sx<cnt>: SQDMULL — signed doubling saturating WIDENING multiply,
    (I64,I64)->V128. Per lane: sat to signed 2*lw of 2 * sext(a)*sext(b) (only min*min sats)."""
    lw, cnt = int(self._vector_size), int(self._vector_count)   # lw = source lane width
    dw = 2 * lw
    W = dw + 2
    a, b = _lanes(args[0], lw, cnt), _lanes(args[1], lw, cnt)
    hi_bv, lo_bv = claripy.BVV((1 << (dw - 1)) - 1, W), claripy.BVV((-(1 << (dw - 1))) & ((1 << W) - 1), W)
    out = []
    for i in range(cnt):
        d = (a[i].sign_extend(W - lw) * b[i].sign_extend(W - lw)) << 1
        c = claripy.If(claripy.SGT(d, hi_bv), hi_bv, claripy.If(claripy.SLT(d, lo_bv), lo_bv, d))
        out.append(c[dw - 1:0])
    return _concat_lanes(out)


def _op_generic_NarrowBin(self, args):
    """Iop_NarrowBin<src>to<dst>x<cnt>: truncating narrow of TWO vectors into one. Each
    source lane is truncated to its low half; the LEFT arg fills the high result lanes,
    the right arg the low ones (matches VEX's QNarrowBin 'hi half from left arg')."""
    m = re.search(r"NarrowBin(\d+)to(\d+)x(\d+)", self.name)
    src, dst, cnt = int(m.group(1)), int(m.group(2)), int(m.group(3))
    half = cnt // 2
    a1 = _lanes(args[0], src, half)
    a2 = _lanes(args[1], src, half)
    out = [ln[dst - 1:0] for ln in a2] + [ln[dst - 1:0] for ln in a1]   # low = right, high = left
    return _concat_lanes(out)


def _poly_mul(a, b, aw, bw):
    """Carryless (GF(2)) multiply of an aw-bit by a bw-bit value -> (aw+bw-1..) bits; we
    return the full (aw+bw)-bit product (caller truncates as the op needs)."""
    ow = aw + bw
    ae = a.zero_extend(ow - aw)
    acc = claripy.BVV(0, ow)
    for i in range(bw):
        bit = claripy.Extract(i, i, b)
        acc = acc ^ claripy.If(bit == 1, ae << i, claripy.BVV(0, ow))
    return acc


def _op_generic_PolynomialMul(self, args):
    """Iop_PolynomialMul8x16: PMUL — per-byte carryless multiply, low 8 bits of each product."""
    lw, cnt = int(self._vector_size), int(self._vector_count)
    a, b = _lanes(args[0], lw, cnt), _lanes(args[1], lw, cnt)
    return _concat_lanes([_poly_mul(a[i], b[i], lw, lw)[lw - 1:0] for i in range(cnt)])


def _op_generic_PolynomialMull(self, args):
    """Iop_PolynomialMull8x8: PMULL — per-byte carryless multiply of the low 8 lanes,
    widening to 16-bit results (I64,I64)->V128."""
    lw, cnt = int(self._vector_size), int(self._vector_count)   # 8, 8
    a, b = _lanes(args[0], lw, cnt), _lanes(args[1], lw, cnt)
    return _concat_lanes([_poly_mul(a[i], b[i], lw, lw)[2 * lw - 1:0] for i in range(cnt)])


def _op_generic_QAddExt(self, args):
    """Iop_QAddExt{US,SU}sat{SS,UU}<lw>x<cnt>: ARM64 SUQADD / USQADD. The first two letters
    give how the left/right args are widened before the add; the sat letters give the output
    saturation. US+SS (SUQADD): sat_s(zext(L) + sext(R)). SU+UU (USQADD): sat_u(sext(L) +
    zext(R))."""
    m = re.search(r"QAddExt([US])([US])sat([SU])([SU])(\d+)x(\d+)", self.name)
    lsig, rsig, ssig, lw, cnt = m.group(1) == "S", m.group(2) == "S", m.group(3) == "S", int(m.group(5)), int(m.group(6))
    W = lw + 2
    a, b = _lanes(args[0], lw, cnt), _lanes(args[1], lw, cnt)
    if ssig:
        hi, lo = claripy.BVV((1 << (lw - 1)) - 1, W), claripy.BVV((-(1 << (lw - 1))) & ((1 << W) - 1), W)
    else:
        hi, lo = claripy.BVV((1 << lw) - 1, W), claripy.BVV(0, W)
    out = []
    for i in range(cnt):
        la = a[i].sign_extend(W - lw) if lsig else a[i].zero_extend(W - lw)
        rb = b[i].sign_extend(W - lw) if rsig else b[i].zero_extend(W - lw)
        s = la + rb
        c = claripy.If(claripy.SGT(s, hi), hi, claripy.If(claripy.SLT(s, lo), lo, s))
        out.append(c[lw - 1:0])
    return _concat_lanes(out)


def _fp_lane(bv, lw, i):
    return bv[(i + 1) * lw - 1:i * lw].raw_to_fp()


def _fp_concat(bvs):               # bvs: low lane first
    return claripy.Concat(*reversed(bvs))


def _fmax(a, b):
    """ARM FPMax: NaN in either -> that value's partner is ignored in favour of the NaN's
    propagation; for numbers, the larger (+0 > -0). We return a NaN if either is NaN."""
    nan = claripy.fpIsNaN(a) | claripy.fpIsNaN(b)
    larger = claripy.If(claripy.fpGT(a, b), a, b)
    return claripy.If(nan, claripy.If(claripy.fpIsNaN(a), a, b), larger)


def _fmin(a, b):
    nan = claripy.fpIsNaN(a) | claripy.fpIsNaN(b)
    smaller = claripy.If(claripy.fpLT(a, b), a, b)
    return claripy.If(nan, claripy.If(claripy.fpIsNaN(a), a, b), smaller)


def _fmaxnum(a, b):
    """FMAXNM / IEEE maxNum: if exactly one is NaN, return the number; both NaN -> NaN."""
    return claripy.If(claripy.fpIsNaN(a), b, claripy.If(claripy.fpIsNaN(b), a, claripy.If(claripy.fpGT(a, b), a, b)))


def _fminnum(a, b):
    return claripy.If(claripy.fpIsNaN(a), b, claripy.If(claripy.fpIsNaN(b), a, claripy.If(claripy.fpLT(a, b), a, b)))


def _fp_to_int_sat(f, bits, signed, rm, sort):
    """FCVTZS/FCVTZU-style convert with ARM saturation: NaN -> 0, out-of-range -> the range
    end. claripy's fpToSBV/UBV CRASH (not clamp) on an out-of-range value, and the concrete
    backend evaluates both If-branches eagerly, so the value handed to the converter must be
    pre-clamped into range; the saturated ends are selected separately."""
    if signed:
        hi, lo = (1 << (bits - 1)) - 1, -(1 << (bits - 1))
    else:
        hi, lo = (1 << bits) - 1, 0
    hi_f = claripy.FPV(float(hi + 1), sort)        # first float at/above the top of range (a power of two -> exact)
    lo_f = claripy.FPV(float(lo), sort)
    over = claripy.fpGEQ(f, hi_f)
    under = claripy.fpLT(f, lo_f)
    nan = claripy.fpIsNaN(f)
    safe = claripy.If(nan | over | under, claripy.FPV(0.0, sort), f)   # always in range for the converter
    conv = claripy.fpToSBV(rm, safe, bits) if signed else claripy.fpToUBV(rm, safe, bits)
    res = claripy.If(over, claripy.BVV(hi & ((1 << bits) - 1), bits),
                     claripy.If(under, claripy.BVV(lo & ((1 << bits) - 1), bits), conv))
    return claripy.If(nan, claripy.BVV(0, bits), res)


def _op_generic_IntToFP(self, args):
    """Iop_I32{S,U}toFx<cnt>: SCVTF/UCVTF — per-lane 32-bit int -> f32 (round to nearest)."""
    m = re.search(r"I32([SU])toFx(\d+)", self.name)
    signed, cnt = m.group(1) == "S", int(m.group(2))
    rm = claripy.fp.RM.RM_NearestTiesEven
    conv = (lambda bv: claripy.fpToFP(rm, bv, claripy.FSORT_FLOAT)) if signed \
        else (lambda bv: claripy.fpToFPUnsigned(rm, bv, claripy.FSORT_FLOAT))
    x = args[0]
    return _fp_concat([conv(x[(i + 1) * 32 - 1:i * 32]).raw_to_bv() for i in range(cnt)])


def _op_generic_QFtoI(self, args):
    """Iop_QFtoI32{S,U}x<cnt>_RZ: FCVTZS/FCVTZU — saturating f32 -> int32, round to zero."""
    m = re.search(r"QFtoI32([SU])x(\d+)_RZ", self.name)
    signed, cnt = m.group(1) == "S", int(m.group(2))
    rm = claripy.fp.RM.RM_TowardsZero
    x = args[0]
    out = [_fp_to_int_sat(_fp_lane(x, 32, i), 32, signed, rm, claripy.FSORT_FLOAT) for i in range(cnt)]
    return _fp_concat(out)


def _op_generic_F32ToFixed(self, args):
    """Iop_F32ToFixed32{S,U}x<cnt>_RZ: f32 -> 32-bit fixed-point (round to zero, saturating).
    The I8 second arg is the number of fraction bits: result = sat_int32(RZ(f * 2^fbits))."""
    m = re.search(r"F32ToFixed32([SU])x(\d+)_RZ", self.name)
    signed, cnt = m.group(1) == "S", int(m.group(2))
    rm = claripy.fp.RM.RM_TowardsZero
    scale = claripy.fpToFP(rm, (claripy.BVV(1, 64) << args[1][7:0].zero_extend(56)), claripy.FSORT_FLOAT)
    x = args[0]
    out = [_fp_to_int_sat(claripy.fpMul(rm, _fp_lane(x, 32, i), scale), 32, signed, rm, claripy.FSORT_FLOAT)
           for i in range(cnt)]
    return _fp_concat(out)


def _op_generic_Fixed32ToF(self, args):
    """Iop_Fixed32{S,U}ToF32x<cnt>_RN: 32-bit fixed-point -> f32 (round to nearest).
    result = (int / 2^fbits), fbits = I8 second arg."""
    m = re.search(r"Fixed32([SU])ToF32x(\d+)_RN", self.name)
    signed, cnt = m.group(1) == "S", int(m.group(2))
    rm = claripy.fp.RM.RM_NearestTiesEven
    scale = claripy.fpToFP(rm, (claripy.BVV(1, 64) << args[1][7:0].zero_extend(56)), claripy.FSORT_FLOAT)
    conv = (lambda bv: claripy.fpToFP(rm, bv, claripy.FSORT_FLOAT)) if signed \
        else (lambda bv: claripy.fpToFPUnsigned(rm, bv, claripy.FSORT_FLOAT))
    x = args[0]
    out = [claripy.fpDiv(rm, conv(x[(i + 1) * 32 - 1:i * 32]), scale).raw_to_bv() for i in range(cnt)]
    return _fp_concat(out)


def _op_generic_FSqrt(self, args):
    """Iop_Sqrt{32,64}Fx<cnt>: vector FSQRT (round to nearest-even)."""
    lw, cnt = int(self._vector_size), int(self._vector_count)
    rm = claripy.fp.RM.RM_NearestTiesEven
    x = args[0]
    return _fp_concat([claripy.fpSqrt(rm, _fp_lane(x, lw, i)).raw_to_bv() for i in range(cnt)])


def _op_generic_FCmp(self, args):
    """Iop_Cmp{GT,GE,UN}<lw>Fx<cnt>: lanewise FP compare -> all-ones / all-zeros per lane.
    GT/GE are ordered (NaN -> false); UN is the unordered predicate (either lane NaN)."""
    m = re.search(r"Cmp(GT|GE|UN)(\d+)Fx(\d+)", self.name)
    kind, lw, cnt = m.group(1), int(m.group(2)), int(m.group(3))
    a, b = args[-2], args[-1]
    ones, zero = claripy.BVV((1 << lw) - 1, lw), claripy.BVV(0, lw)
    out = []
    for i in range(cnt):
        fa, fb = _fp_lane(a, lw, i), _fp_lane(b, lw, i)
        if kind == "GT":
            pred = claripy.fpGT(fa, fb)
        elif kind == "GE":
            pred = claripy.fpGEQ(fa, fb)
        else:
            pred = claripy.fpIsNaN(fa) | claripy.fpIsNaN(fb)
        out.append(claripy.If(pred, ones, zero))
    return _fp_concat(out)


def _op_generic_FStep(self, args):
    """Iop_RecipStep<lw>Fx<cnt> = (2.0 - a*b); Iop_RSqrtStep = (3.0 - a*b)/2.0. If one arg
    is 0 and the other +/-inf, the result is the constant (2.0 / 1.5) rather than NaN."""
    m = re.search(r"(Recip|RSqrt)Step(\d+)Fx(\d+)", self.name)
    rsqrt, lw, cnt = m.group(1) == "RSqrt", int(m.group(2)), int(m.group(3))
    rm = claripy.fp.RM.RM_NearestTiesEven
    sort = claripy.FSORT_FLOAT if lw == 32 else claripy.FSORT_DOUBLE
    two = claripy.FPV(2.0, sort)
    const = claripy.FPV(1.5 if rsqrt else 2.0, sort)
    a, b = args[-2], args[-1]
    out = []
    for i in range(cnt):
        fa, fb = _fp_lane(a, lw, i), _fp_lane(b, lw, i)
        special = (claripy.fpIsInf(fa) & (fb == claripy.FPV(0.0, sort))) | \
                  (claripy.fpIsInf(fb) & (fa == claripy.FPV(0.0, sort)))
        if rsqrt:
            three = claripy.FPV(3.0, sort)
            val = claripy.fpDiv(rm, claripy.fpSub(rm, three, claripy.fpMul(rm, fa, fb)), two)
        else:
            val = claripy.fpSub(rm, two, claripy.fpMul(rm, fa, fb))
        out.append(claripy.If(special, const, val).raw_to_bv())
    return _fp_concat(out)


def _op_generic_FMaxMinNum(self, args):
    """Iop_{Max,Min}NumF{32,64}: scalar FMAXNM / FMINNM (IEEE maxNum/minNum)."""
    m = re.search(r"(Max|Min)NumF(\d+)", self.name)
    is_max, lw = m.group(1) == "Max", int(m.group(2))
    fa, fb = args[-2].raw_to_fp(), args[-1].raw_to_fp()
    return (_fmaxnum(fa, fb) if is_max else _fminnum(fa, fb)).raw_to_bv()


def _op_generic_PwFP(self, args):
    """FP pairwise: Iop_PwAdd32Fx2 and Iop_Pw{Max,Min}32Fx{2,4} (FADDP/FMAXP/FMINP).
    PwFoo([a,b],[c,d]) = [Foo(a,b), Foo(c,d)] — arg1's pair(s) low, arg2's high."""
    m = re.search(r"Pw(Add|Max|Min)(\d+)Fx(\d+)", self.name)
    kind, lw, cnt = m.group(1), int(m.group(2)), int(m.group(3))
    rm = claripy.fp.RM.RM_NearestTiesEven
    def foo(x, y):
        if kind == "Add":
            return claripy.fpAdd(rm, x, y)
        return _fmax(x, y) if kind == "Max" else _fmin(x, y)
    out = []
    for arg in (args[0], args[1]):
        lanes = [_fp_lane(arg, lw, i) for i in range(cnt)]
        for k in range(0, cnt, 2):
            out.append(foo(lanes[k], lanes[k + 1]).raw_to_bv())
    return _fp_concat(out)


def _op_generic_PwAddL(self, args):
    """Iop_PwAddL<sw>{S,U}x<cnt>: UNARY pairwise add LONG (SADDLP/UADDLP) — sum adjacent
    lane pairs into lanes of DOUBLE the width. PwAddL16Ux4([a,b,c,d]) = [a+b, c+d]."""
    m = re.search(r"PwAddL(\d+)([SU])x(\d+)", self.name)
    sw, signed, cnt = int(m.group(1)), m.group(2) == "S", int(m.group(3))
    dw = 2 * sw
    ln = _lanes(args[0], sw, cnt)
    ext = (lambda v: v.sign_extend(dw - sw)) if signed else (lambda v: v.zero_extend(dw - sw))
    out = [ext(ln[k]) + ext(ln[k + 1]) for k in range(0, cnt, 2)]
    return _concat_lanes(out)


def _op_fgeneric_Sqrt(self, args):
    """FP square root. Handles BOTH call shapes: angr calls a scalar op as
    _calculate([x]) (args is a list), and _auto_vectorize calls the per-lane function as
    f(lane) (args is a single FP). This makes vector FSQRT — Iop_Sqrt64Fx2 / Sqrt32Fx4 /
    Sqrt32Fx2 — work too: angr lane-splits them and sqrt's each lane through here."""
    x = args[0] if isinstance(args, (list, tuple)) else args
    if not isinstance(x, claripy.ast.FP):
        x = x.raw_to_fp()
    return claripy.fpSqrt(claripy.fp.RM.RM_NearestTiesEven, x)


# op name / generic-name -> handler
_SPECIFIC = {
    "Iop_ZeroHI64ofV128": _op_zerohi,
    "Iop_ZeroHI96ofV128": _op_zerohi,
    "Iop_ZeroHI112ofV128": _op_zerohi,
    "Iop_Reverse8sIn16_x8": _op_reverse,
    "Iop_Reverse8sIn32_x4": _op_reverse,
    "Iop_Reverse8sIn64_x2": _op_reverse,
    "Iop_Reverse16sIn32_x4": _op_reverse,
    "Iop_Reverse16sIn64_x2": _op_reverse,
    "Iop_Reverse32sIn64_x2": _op_reverse,
    "Iop_ZeroHI120ofV128": _op_zerohi,
    "Iop_Reverse1sIn8_x16": _op_reverse,       # RBIT (reverse bits in each byte)
    "Iop_Reverse8sIn16_x4": _op_reverse,
    "Iop_Reverse8sIn32_x2": _op_reverse,
    "Iop_Reverse8sIn64_x1": _op_reverse,
    "Iop_Reverse16sIn32_x2": _op_reverse,
    "Iop_Reverse16sIn64_x1": _op_reverse,
    "Iop_Reverse32sIn64_x1": _op_reverse,
    # FP conversions (kept out of _GENERIC: 'Q'/None generic names would collide / fail)
    "Iop_I32StoFx4": _op_generic_IntToFP, "Iop_I32UtoFx4": _op_generic_IntToFP,
    "Iop_I32StoFx2": _op_generic_IntToFP, "Iop_I32UtoFx2": _op_generic_IntToFP,
    "Iop_QFtoI32Sx4_RZ": _op_generic_QFtoI, "Iop_QFtoI32Ux4_RZ": _op_generic_QFtoI,
    "Iop_F32ToFixed32Sx4_RZ": _op_generic_F32ToFixed, "Iop_F32ToFixed32Ux4_RZ": _op_generic_F32ToFixed,
    "Iop_F32ToFixed32Sx2_RZ": _op_generic_F32ToFixed, "Iop_F32ToFixed32Ux2_RZ": _op_generic_F32ToFixed,
    "Iop_Fixed32SToF32x4_RN": _op_generic_Fixed32ToF, "Iop_Fixed32UToF32x4_RN": _op_generic_Fixed32ToF,
    "Iop_Fixed32SToF32x2_RN": _op_generic_Fixed32ToF, "Iop_Fixed32UToF32x2_RN": _op_generic_Fixed32ToF,
}
_GENERIC = {
    "NarrowUn": _op_generic_NarrowUn,
    "QNarrowUn": _op_generic_QNarrowUn,
    "Cnt": _op_generic_Cnt,                # CNT (popcount per byte)
    "Cls": _op_generic_Cls,                # CLS (count leading sign bits)
    "Left": _op_generic_Left,              # x | -x (Memcheck helper)
    "Widen": _op_generic_Widen,            # SXTL/UXTL (widen low-half lanes)
    "InterleaveOddLanes": _op_generic_Interleave,
    "InterleaveEvenLanes": _op_generic_Interleave,
    "Avg": _op_generic_Avg,                # URHADD/SRHADD ((a+b+1)>>1)
    "PwAdd": _op_generic_Pw,               # ADDP (integer; FP PwAdd handled separately)
    "PwMax": _op_generic_Pw,               # SMAXP/UMAXP (integer)
    "PwMin": _op_generic_Pw,               # SMINP/UMINP (integer)
    "PwAddL": _op_generic_PwAddL,          # SADDLP/UADDLP (pairwise add long)
    "QDMulHi": _op_generic_QDMulHi,        # SQDMULH
    "QRDMulHi": _op_generic_QDMulHi,       # SQRDMULH (rounding)
    "QDMull": _op_generic_QDMull,          # SQDMULL (doubling widening)
    "NarrowBin": _op_generic_NarrowBin,    # XTN/XTN2 (truncating narrow of two vectors)
    "PolynomialMul": _op_generic_PolynomialMul,    # PMUL
    "PolynomialMull": _op_generic_PolynomialMull,  # PMULL
    "QAddExtUSsat": _op_generic_QAddExt,   # SUQADD
    "QAddExtSUsat": _op_generic_QAddExt,   # USQADD
    # --- NEON FP ---
    "Sqrt": _op_generic_FSqrt,             # vector FSQRT
    "CmpGT": _op_generic_FCmp,             # FCMGT
    "CmpGE": _op_generic_FCmp,             # FCMGE
    "CmpUN": _op_generic_FCmp,             # unordered compare
    "RecipStep": _op_generic_FStep,        # FRECPS (2 - a*b)
    "RSqrtStep": _op_generic_FStep,        # FRSQRTS (3 - a*b)/2
    "MaxNum": _op_generic_FMaxMinNum,      # FMAXNM
    "MinNum": _op_generic_FMaxMinNum,      # FMINNM
    "Sh": _op_generic_Sh,                  # SSHL/USHL per-lane variable shift (all lane widths)
    "Rsh": _op_generic_Rsh,                # SRSHL/URSHL rounding variable shift
    "QandUQsh": _op_generic_QandQsh,       # UQSHL  (sat, V256 result+Q)
    "QandSQsh": _op_generic_QandQsh,       # SQSHL  (sat, V256 result+Q)
    "QandUQRsh": _op_generic_QandQsh,      # UQRSHL (sat+round, V256 result+Q)
    "QandSQRsh": _op_generic_QandQsh,      # SQRSHL (sat+round, V256 result+Q)
    "QShlNsat": _op_generic_QShlNsat,      # SQSHL/UQSHL/SQSHLU #imm (sat left shift, V128)
    "QandQSarNnarrow": _op_generic_QandQNarrow,    # SQSHRN / SQSHRUN (sat-narrow right, V128+Q)
    "QandQShrNnarrow": _op_generic_QandQNarrow,    # UQSHRN
    "QandQRSarNnarrow": _op_generic_QandQNarrow,   # SQRSHRN / SQRSHRUN (rounding)
    "QandQRShrNnarrow": _op_generic_QandQNarrow,   # UQRSHRN (rounding)
}

# ops to proactively (re)register into the operations table
_REGISTER = [
    "Iop_NarrowUn64to32x2", "Iop_NarrowUn32to16x4", "Iop_NarrowUn16to8x8",
    "Iop_QNarrowUn16Uto8Ux8", "Iop_QNarrowUn16Sto8Ux8", "Iop_QNarrowUn16Sto8Sx8",
    "Iop_QNarrowUn32Sto16Sx4", "Iop_QNarrowUn32Sto16Ux4", "Iop_QNarrowUn32Uto16Ux4",
    "Iop_QNarrowUn64Sto32Sx2", "Iop_QNarrowUn64Sto32Ux2", "Iop_QNarrowUn64Uto32Ux2",
    "Iop_ZeroHI64ofV128", "Iop_ZeroHI96ofV128", "Iop_ZeroHI112ofV128",
    "Iop_Reverse8sIn16_x8", "Iop_Reverse8sIn32_x4", "Iop_Reverse8sIn64_x2",
    "Iop_Reverse16sIn32_x4", "Iop_Reverse16sIn64_x2", "Iop_Reverse32sIn64_x2",
    "Iop_SqrtF64", "Iop_SqrtF32",
    # SSHL/USHL — per-lane variable shift (generic_name "Sh"), all NEON lane layouts
    "Iop_Sh8Sx16", "Iop_Sh16Sx8", "Iop_Sh32Sx4", "Iop_Sh64Sx2",
    "Iop_Sh8Ux16", "Iop_Sh16Ux8", "Iop_Sh32Ux4", "Iop_Sh64Ux2",
    # SRSHL/URSHL — rounding variable shift (generic_name "Rsh")
    "Iop_Rsh8Sx16", "Iop_Rsh16Sx8", "Iop_Rsh32Sx4", "Iop_Rsh64Sx2",
    "Iop_Rsh8Ux16", "Iop_Rsh16Ux8", "Iop_Rsh32Ux4", "Iop_Rsh64Ux2",
    # SQSHL/UQSHL/SQRSHL/UQRSHL — saturating (maybe rounding) variable shift, V256 result+Q
    "Iop_QandUQsh8x16", "Iop_QandUQsh16x8", "Iop_QandUQsh32x4", "Iop_QandUQsh64x2",
    "Iop_QandSQsh8x16", "Iop_QandSQsh16x8", "Iop_QandSQsh32x4", "Iop_QandSQsh64x2",
    "Iop_QandUQRsh8x16", "Iop_QandUQRsh16x8", "Iop_QandUQRsh32x4", "Iop_QandUQRsh64x2",
    "Iop_QandSQRsh8x16", "Iop_QandSQRsh16x8", "Iop_QandSQRsh32x4", "Iop_QandSQRsh64x2",
    # SQSHL/UQSHL/SQSHLU #imm — saturating left shift by immediate (generic_name "QShlNsat")
    "Iop_QShlNsatSS8x16", "Iop_QShlNsatSS16x8", "Iop_QShlNsatSS32x4", "Iop_QShlNsatSS64x2",
    "Iop_QShlNsatUU8x16", "Iop_QShlNsatUU16x8", "Iop_QShlNsatUU32x4", "Iop_QShlNsatUU64x2",
    "Iop_QShlNsatSU8x16", "Iop_QShlNsatSU16x8", "Iop_QShlNsatSU32x4", "Iop_QShlNsatSU64x2",
    # ARM32-legacy small-vector variants (x8/x4/x2/x1) also exist; register the x1 scalars
    "Iop_QShlNsatSS64x1", "Iop_QShlNsatUU64x1", "Iop_QShlNsatSU64x1",
    "Iop_QShlNsatSS8x8", "Iop_QShlNsatSS16x4", "Iop_QShlNsatSS32x2",
    "Iop_QShlNsatUU8x8", "Iop_QShlNsatUU16x4", "Iop_QShlNsatUU32x2",
    "Iop_QShlNsatSU8x8", "Iop_QShlNsatSU16x4", "Iop_QShlNsatSU32x2",
    # SQSHRN/UQSHRN/SQSHRUN (+rounding) — saturating-narrow shift right (generic "QandQ*Nnarrow")
    "Iop_QandQShrNnarrow16Uto8Ux8", "Iop_QandQShrNnarrow32Uto16Ux4", "Iop_QandQShrNnarrow64Uto32Ux2",
    "Iop_QandQSarNnarrow16Sto8Sx8", "Iop_QandQSarNnarrow32Sto16Sx4", "Iop_QandQSarNnarrow64Sto32Sx2",
    "Iop_QandQSarNnarrow16Sto8Ux8", "Iop_QandQSarNnarrow32Sto16Ux4", "Iop_QandQSarNnarrow64Sto32Ux2",
    "Iop_QandQRShrNnarrow16Uto8Ux8", "Iop_QandQRShrNnarrow32Uto16Ux4", "Iop_QandQRShrNnarrow64Uto32Ux2",
    "Iop_QandQRSarNnarrow16Sto8Sx8", "Iop_QandQRSarNnarrow32Sto16Sx4", "Iop_QandQRSarNnarrow64Sto32Sx2",
    "Iop_QandQRSarNnarrow16Sto8Ux8", "Iop_QandQRSarNnarrow32Sto16Ux4", "Iop_QandQRSarNnarrow64Sto32Ux2",
    # --- Batch A: exact integer elementwise / shuffle ---
    "Iop_Cnt8x16", "Iop_Cnt8x8",
    "Iop_Cls8x16", "Iop_Cls16x8", "Iop_Cls32x4", "Iop_Cls8x8", "Iop_Cls16x4", "Iop_Cls32x2",
    "Iop_Left8", "Iop_Left16", "Iop_Left32", "Iop_Left64",
    "Iop_Widen8Sto16x8", "Iop_Widen16Sto32x4", "Iop_Widen32Sto64x2",
    "Iop_Widen8Uto16x8", "Iop_Widen16Uto32x4", "Iop_Widen32Uto64x2",
    "Iop_InterleaveOddLanes8x8", "Iop_InterleaveEvenLanes8x8", "Iop_InterleaveOddLanes16x4", "Iop_InterleaveEvenLanes16x4",
    "Iop_InterleaveOddLanes8x16", "Iop_InterleaveEvenLanes8x16", "Iop_InterleaveOddLanes16x8", "Iop_InterleaveEvenLanes16x8",
    "Iop_InterleaveOddLanes32x4", "Iop_InterleaveEvenLanes32x4",
    "Iop_Avg8Ux16", "Iop_Avg16Ux8", "Iop_Avg32Ux4", "Iop_Avg64Ux2",
    "Iop_Avg8Sx16", "Iop_Avg16Sx8", "Iop_Avg32Sx4", "Iop_Avg64Sx2",
    "Iop_Avg8Ux8", "Iop_Avg16Ux4", "Iop_Avg8Ux32", "Iop_Avg16Ux16",
    "Iop_ZeroHI120ofV128",
    "Iop_Reverse1sIn8_x16", "Iop_Reverse8sIn16_x4", "Iop_Reverse8sIn32_x2", "Iop_Reverse8sIn64_x1",
    "Iop_Reverse16sIn32_x2", "Iop_Reverse16sIn64_x1", "Iop_Reverse32sIn64_x1",
    # --- Batch B: pairwise (integer) ---
    "Iop_PwAdd8x16", "Iop_PwAdd16x8", "Iop_PwAdd32x4",
    "Iop_PwAdd8x8", "Iop_PwAdd16x4", "Iop_PwAdd32x2",
    "Iop_PwMax8Sx8", "Iop_PwMax16Sx4", "Iop_PwMax32Sx2", "Iop_PwMax8Ux8", "Iop_PwMax16Ux4", "Iop_PwMax32Ux2",
    "Iop_PwMin8Sx8", "Iop_PwMin16Sx4", "Iop_PwMin32Sx2", "Iop_PwMin8Ux8", "Iop_PwMin16Ux4", "Iop_PwMin32Ux2",
    "Iop_PwAddL8Ux8", "Iop_PwAddL16Ux4", "Iop_PwAddL32Ux2", "Iop_PwAddL8Sx8", "Iop_PwAddL16Sx4", "Iop_PwAddL32Sx2",
    "Iop_PwAddL8Ux16", "Iop_PwAddL16Ux8", "Iop_PwAddL32Ux4", "Iop_PwAddL8Sx16", "Iop_PwAddL16Sx8", "Iop_PwAddL32Sx4",
    "Iop_PwAddL64Ux2",
    # --- Batch C: multiply / narrow ---
    "Iop_QDMulHi16Sx4", "Iop_QDMulHi32Sx2", "Iop_QDMulHi16Sx8", "Iop_QDMulHi32Sx4",
    "Iop_QRDMulHi16Sx4", "Iop_QRDMulHi32Sx2", "Iop_QRDMulHi16Sx8", "Iop_QRDMulHi32Sx4",
    "Iop_QDMull16Sx4", "Iop_QDMull32Sx2",
    "Iop_NarrowBin16to8x16", "Iop_NarrowBin16to8x8", "Iop_NarrowBin32to16x4",
    "Iop_NarrowBin32to16x8", "Iop_NarrowBin64to32x4",
    "Iop_PolynomialMul8x16", "Iop_PolynomialMull8x8",
    # --- Batch D: ARM64 saturating add extensions (SUQADD / USQADD) ---
    "Iop_QAddExtUSsatSS8x16", "Iop_QAddExtUSsatSS16x8", "Iop_QAddExtUSsatSS32x4", "Iop_QAddExtUSsatSS64x2",
    "Iop_QAddExtSUsatUU8x16", "Iop_QAddExtSUsatUU16x8", "Iop_QAddExtSUsatUU32x4", "Iop_QAddExtSUsatUU64x2",
    # --- NEON FP (exact): vector sqrt, compares, recip/rsqrt step, max/min num, FP pairwise ---
    "Iop_Sqrt32Fx4", "Iop_Sqrt64Fx2", "Iop_Sqrt64Fx4",
    "Iop_CmpGT32Fx2", "Iop_CmpGT32Fx4", "Iop_CmpGE32Fx2", "Iop_CmpGE32Fx4",
    "Iop_CmpUN32Fx4", "Iop_CmpUN64Fx2",
    "Iop_RecipStep32Fx2", "Iop_RecipStep32Fx4", "Iop_RecipStep64Fx2",
    "Iop_RSqrtStep32Fx2", "Iop_RSqrtStep32Fx4", "Iop_RSqrtStep64Fx2",
    "Iop_MaxNumF32", "Iop_MaxNumF64", "Iop_MinNumF32", "Iop_MinNumF64",
    "Iop_PwAdd32Fx2", "Iop_PwMax32Fx2", "Iop_PwMin32Fx2", "Iop_PwMax32Fx4", "Iop_PwMin32Fx4",
    # --- NEON FP conversions ---
    "Iop_I32StoFx4", "Iop_I32UtoFx4", "Iop_I32StoFx2", "Iop_I32UtoFx2",
    "Iop_QFtoI32Sx4_RZ", "Iop_QFtoI32Ux4_RZ",
    "Iop_F32ToFixed32Sx4_RZ", "Iop_F32ToFixed32Ux4_RZ", "Iop_F32ToFixed32Sx2_RZ", "Iop_F32ToFixed32Ux2_RZ",
    "Iop_Fixed32SToF32x4_RN", "Iop_Fixed32UToF32x4_RN", "Iop_Fixed32SToF32x2_RN", "Iop_Fixed32UToF32x2_RN",
]

# angr's op_attrs regex can't parse some names (returns None); supply attrs by hand.
_ATTR_KEYS = ("generic_name", "from_type", "from_signed", "from_size", "from_side",
              "conversion", "to_type", "to_size", "to_signed", "set_side", "set_size",
              "rounding_mode", "vector_size", "vector_signed", "vector_type",
              "vector_zero", "vector_count")


def _explicit(**over):
    d = {k: None for k in _ATTR_KEYS}
    d.update(over)
    return d


_EXPLICIT_ATTRS = {
    "Iop_ZeroHI64ofV128": _explicit(generic_name="ZeroHI64ofV128"),
    "Iop_ZeroHI96ofV128": _explicit(generic_name="ZeroHI96ofV128"),
    "Iop_ZeroHI112ofV128": _explicit(generic_name="ZeroHI112ofV128"),
    "Iop_Reverse8sIn16_x8": _explicit(generic_name="Reverse8sIn16"),
    "Iop_Reverse8sIn32_x4": _explicit(generic_name="Reverse8sIn32"),
    "Iop_Reverse8sIn64_x2": _explicit(generic_name="Reverse8sIn64"),
    "Iop_Reverse16sIn32_x4": _explicit(generic_name="Reverse16sIn32"),
    "Iop_Reverse16sIn64_x2": _explicit(generic_name="Reverse16sIn64"),
    "Iop_Reverse32sIn64_x2": _explicit(generic_name="Reverse32sIn64"),
    "Iop_ZeroHI120ofV128": _explicit(generic_name="ZeroHI120ofV128"),
    "Iop_Reverse1sIn8_x16": _explicit(generic_name="Reverse1sIn8"),
    "Iop_Reverse8sIn16_x4": _explicit(generic_name="Reverse8sIn16"),
    "Iop_Reverse8sIn32_x2": _explicit(generic_name="Reverse8sIn32"),
    "Iop_Reverse8sIn64_x1": _explicit(generic_name="Reverse8sIn64"),
    "Iop_Reverse16sIn32_x2": _explicit(generic_name="Reverse16sIn32"),
    "Iop_Reverse16sIn64_x1": _explicit(generic_name="Reverse16sIn64"),
    "Iop_Reverse32sIn64_x1": _explicit(generic_name="Reverse32sIn64"),
    "Iop_I32StoFx4": _explicit(generic_name="I32StoFx4"), "Iop_I32UtoFx4": _explicit(generic_name="I32UtoFx4"),
    "Iop_I32StoFx2": _explicit(generic_name="I32StoFx2"), "Iop_I32UtoFx2": _explicit(generic_name="I32UtoFx2"),
    "Iop_F32ToFixed32Sx4_RZ": _explicit(generic_name="F32ToFixed32Sx4_RZ"),
    "Iop_F32ToFixed32Ux4_RZ": _explicit(generic_name="F32ToFixed32Ux4_RZ"),
    "Iop_F32ToFixed32Sx2_RZ": _explicit(generic_name="F32ToFixed32Sx2_RZ"),
    "Iop_F32ToFixed32Ux2_RZ": _explicit(generic_name="F32ToFixed32Ux2_RZ"),
    "Iop_Fixed32SToF32x4_RN": _explicit(generic_name="Fixed32SToF32x4_RN"),
    "Iop_Fixed32UToF32x4_RN": _explicit(generic_name="Fixed32UToF32x4_RN"),
    "Iop_Fixed32SToF32x2_RN": _explicit(generic_name="Fixed32SToF32x2_RN"),
    "Iop_Fixed32UToF32x2_RN": _explicit(generic_name="Fixed32UToF32x2_RN"),
}

_applied = False


# NEON vector floating-point arithmetic (Mul/Add/Sub/Div xFxy). angr HAS these ops but
# its `_op_vector_float_mapped` returns NotImplemented on symbolic lanes and then crashes
# (`'NotImplementedType' has no attribute 'raw_to_bv'`), so we OVERRIDE their calculate
# with a correct per-lane claripy implementation (works for symbolic AND concrete).
_VFP_OPS = {"Mul": "fpMul", "Add": "fpAdd", "Sub": "fpSub", "Div": "fpDiv"}
_VECTOR_FP_OVERRIDE = [
    "Iop_Mul64Fx2", "Iop_Add64Fx2", "Iop_Sub64Fx2", "Iop_Div64Fx2",
    "Iop_Mul32Fx4", "Iop_Add32Fx4", "Iop_Sub32Fx4", "Iop_Div32Fx4",
    "Iop_Mul32Fx2", "Iop_Add32Fx2", "Iop_Sub32Fx2",
]


def _op_generic_VectorFP(self, args):
    """Lanewise IEEE fp op on two same-width vectors, round-to-nearest-even (the NEON
    default). Reads self._vector_count / _vector_size for the lane layout."""
    import claripy
    fn = getattr(claripy, _VFP_OPS[self._generic_name])
    rm = claripy.fp.RM.RM_NearestTiesEven
    a, b = args[-2], args[-1]                    # last two args are the vector operands
    lb = int(self._vector_size)                  # per-lane width in bits
    out = []
    for i in range(int(self._vector_count)):     # lane 0 = low bits
        fa = a[(i + 1) * lb - 1:i * lb].raw_to_fp()
        fb = b[(i + 1) * lb - 1:i * lb].raw_to_fp()
        out.append(fn(rm, fa, fb).raw_to_bv())
    return claripy.Concat(*reversed(out))        # Concat is big-endian: high lane first


# ── Half-precision (f16) conversions ─────────────────────────────────────────────────
# claripy has no 16-bit float type (its concrete backend rejects a HALF sort), so we do
# f16 at the BIT LEVEL in pure bitvector ops — correct for symbolic AND concrete, no FP
# sort needed. Both directions are VERIFIED bit-exact against numpy.float16 (f16->f32 over
# all 65536 values; f32->f16 over 471k values incl. boundaries/ties/inf/nan). See the
# commit message / tests. f16->f64 composes f16->f32 (exact) with f32->f64 (exact).
def _f16_to_f32(h):
    """BV16 -> BV32, exact (f32 is a strict superset of f16)."""
    import claripy
    sign = h[15:15]
    exp5 = h[14:10]
    man10 = h[9:0]
    s32 = sign.zero_extend(31) << 31
    norm = s32 | ((exp5.zero_extend(27) + 112) << 23) | (man10.zero_extend(22) << 13)
    infnan = s32 | (claripy.BVV(0xFF, 32) << 23) | (man10.zero_extend(22) << 13)
    res_sub = s32                                     # subnormal f16 -> normal f32
    for k in range(10):                               # k = index of highest set mantissa bit
        e = claripy.BVV(k + 103, 32)
        mant = claripy.BVV(0, 32) if k == 0 else (man10[k - 1:0].zero_extend(32 - k) << (23 - k))
        cand = s32 | (e << 23) | mant
        higher = claripy.BVV(0, 10) if k == 9 else man10[9:k + 1]
        res_sub = claripy.If((h[k:k] == 1) & (higher == 0), cand, res_sub)
    return claripy.If(exp5 == 31, infnan, claripy.If(exp5 == 0, res_sub, norm))


def _f32_to_f16(x):
    """BV32 -> BV16, round-to-nearest-even (Giesen float_to_half_fast3_rtne: integer ops
    plus one real f32 add, which claripy supports)."""
    import claripy
    rne = claripy.fp.RM.RM_NearestTiesEven
    F16MAX, F32INF, MAGIC = claripy.BVV(0x47800000, 32), claripy.BVV(0x7f800000, 32), claripy.BVV(0x3f000000, 32)
    sign = x & 0x80000000
    x = x ^ sign
    infnan = claripy.If(claripy.UGT(x, F32INF), claripy.BVV(0x7e00, 32), claripy.BVV(0x7c00, 32))
    sub = claripy.fpAdd(rne, x.raw_to_fp(), MAGIC.raw_to_fp()).raw_to_bv() - MAGIC   # subnormal/zero
    mant_odd = claripy.LShR(x, 13) & 1
    xn = x + claripy.BVV((((15 - 127) & 0xffffffff) << 23) & 0xffffffff, 32) + claripy.BVV(0xfff, 32) + mant_odd
    norm = claripy.LShR(xn, 13)
    o = claripy.If(claripy.UGE(x, F16MAX), infnan,
                   claripy.If(claripy.ULT(x, claripy.BVV(113 << 23, 32)), sub, norm)) & 0xffff
    return (claripy.LShR(sign, 16) | o)[15:0]


def _f16_to_f64(h):
    import claripy
    return claripy.fpToFP(claripy.fp.RM.RM_NearestTiesEven,
                          _f16_to_f32(h).raw_to_fp(), claripy.fp.FSORT_DOUBLE).raw_to_bv()


def _op_f16_convert(self, args):
    """_calculate for the f16 conversion ops (scalar + x4/x2 vector). Ignores any leading
    rounding-mode arg; the value is the last arg."""
    import claripy
    v = args[-1]
    nm = self.name
    if nm == "Iop_F16toF32":   return _f16_to_f32(v)
    if nm == "Iop_F32toF16":   return _f32_to_f16(v)
    if nm == "Iop_F16toF64":   return _f16_to_f64(v)
    if nm == "Iop_F16toF32x4": return claripy.Concat(*[_f16_to_f32(v[16 * i + 15:16 * i]) for i in (3, 2, 1, 0)])
    if nm == "Iop_F32toF16x4": return claripy.Concat(*[_f32_to_f16(v[32 * i + 31:32 * i]) for i in (3, 2, 1, 0)])
    if nm == "Iop_F16toF64x2": return claripy.Concat(*[_f16_to_f64(v[16 * i + 15:16 * i]) for i in (1, 0)])
    from angr.errors import UnsupportedIROpError
    raise UnsupportedIROpError(nm)


def patch_lmdb_max_dbs(n: int = 512) -> None:
    """angr's RuntimeDb (CFG edge spilling for big binaries) opens its LMDB with
    max_dbs=10 — too few named sub-DBs for a large binary with many functions/analyses,
    which fails with 'MDB_DBS_FULL'. SEAL doesn't use lmdb itself, so raise the limit on
    every lmdb.open (version-proof: works however angr builds its kwargs). Idempotent."""
    try:
        import lmdb
    except Exception:
        return
    if getattr(lmdb, "_seal_maxdbs_patched", False):
        return
    _orig_open = lmdb.open

    def _open(path, *a, **kw):
        if kw.get("max_dbs", 0) < n:
            kw["max_dbs"] = n
        return _orig_open(path, *a, **kw)

    lmdb.open = _open
    lmdb._seal_maxdbs_patched = True


def apply() -> dict:
    """Install the handlers. Idempotent. Returns {op_name: 'ok'|error} for logging."""
    global _applied
    import angr.engines.vex.claripy.irop as irop
    from angr.errors import UnsupportedIROpError

    patch_lmdb_max_dbs()                              # raise angr RuntimeDb's LMDB max_dbs
    if _applied:
        return {}

    SimIROp = irop.SimIROp
    # FP ops are picked up by angr's own dispatch if the method is on the class.
    SimIROp._op_fgeneric_Sqrt = _op_fgeneric_Sqrt

    orig_init = SimIROp.__init__

    def patched_init(self, name, **attrs):
        # angr raises UnsupportedIROpError at the END of __init__ (sizes already set);
        # catch it and drop in our implementation for ops we understand.
        try:
            orig_init(self, name, **attrs)
        except UnsupportedIROpError:
            fn = _SPECIFIC.get(name) or _GENERIC.get(getattr(self, "_generic_name", None))
            if fn is None:
                raise
            self._calculate = types.MethodType(fn, self)

    SimIROp.__init__ = patched_init

    status: dict[str, str] = {}
    for nm in _REGISTER:
        try:
            attrs = _EXPLICIT_ATTRS.get(nm) or irop.op_attrs(nm)
            if attrs is None:
                status[nm] = "unparseable (no explicit attrs)"
                continue
            irop.operations[nm] = SimIROp(nm, **attrs)
            status[nm] = "ok"
        except Exception as e:                       # noqa: BLE001 - report, don't crash import
            status[nm] = f"{type(e).__name__}: {e}"
            log.warning("could not register %s: %s", nm, e)

    # Override angr's broken symbolic vector-FP arithmetic with our per-lane version.
    for nm in _VECTOR_FP_OVERRIDE:
        op = irop.operations.get(nm)
        if op is not None:
            op._calculate = types.MethodType(_op_generic_VectorFP, op)
            status[nm] = "overridden"

    # Half-precision (f16) conversions: claripy's concrete backend can't represent a
    # 16-bit float (no numpy either), so there is NO correct way to model these here —
    # and a wrong/approximate one would produce spurious witnesses. angr's own handler
    # raises a cryptic IndexError; replace it with a CLEAR UnsupportedIROpError so a path
    # that hits f16 errors legibly (visible in get_run's detail) instead of mysteriously.
    # f16: correct bit-level handlers (verified vs numpy) for the 6 convertible ops.
    for nm in ("Iop_F16toF32", "Iop_F32toF16", "Iop_F16toF64",
               "Iop_F16toF32x4", "Iop_F32toF16x4", "Iop_F16toF64x2"):
        op = irop.operations.get(nm)
        if op is not None:
            op._calculate = types.MethodType(_op_f16_convert, op)
            status[nm] = "f16-ok"
    # f64->f16 direct conversion would double-round through our f32 path, so keep a clean
    # error for it rather than a subtly-wrong result (these are rare).
    def _f16_unsupported(self, args):
        raise UnsupportedIROpError(f"{self.name}: direct f64->f16 not modeled (double rounding)")
    for nm in ("Iop_F64toF16", "Iop_F64toF16x2"):
        op = irop.operations.get(nm)
        if op is not None:
            op._calculate = types.MethodType(_f16_unsupported, op)
            status[nm] = "f16-clean-error"

    _applied = True
    log.info("angr ARM NEON patch applied: %s", {k: v for k, v in status.items() if v != "ok"} or "all ok")
    return status


_PAC_RET = {"retaa", "retab"}
_PAC_BR = {"braa", "brab", "braaz", "brabz", "blraa", "blrab", "blraaz", "blrabz"}


def is_pac_mnemonic(mn: str) -> bool:
    return mn in _PAC_RET or mn in _PAC_BR or mn.startswith(("pac", "aut", "xpac"))


def _install_pac_hook(project, ins) -> str | None:
    """Install the non-authenticated hook for one capstone PAC instruction, or None if
    it isn't a PAC op. Shared by the static scan (patch_pac) and the on-demand path."""
    import angr
    mn = ins.mnemonic
    if mn in _PAC_RET:                      # retaa/retab -> return (jump to LR)
        class _Ret(angr.SimProcedure):
            def run(self):
                self.jump(self.state.regs.lr)
        proc = _Ret()
    elif mn in _PAC_BR:
        # braa/brab/braaz/brabz  -> tail BRANCH (jump to the target register).
        # blraa/blrab/blraaz/blrabz -> CALL (branch-with-LINK). These are indirect calls
        # through an authenticated pointer (ubiquitous in arm64e). Treating a CALL as a
        # plain branch was the skip-calls bug: when the target register is unconstrained
        # the path jumps to a symbolic/zero address and dies at the "bl". So:
        #   * under CALLLESS (skip_calls): SKIP the call — continue at the return site with
        #     an unconstrained return value, exactly like a skipped direct `bl`;
        #   * otherwise: follow the (possibly symbolic) target, so a hijackable function
        #     pointer still surfaces as an unconstrained / unknown-call leaf.
        reg = ins.op_str.split(",")[0].strip()
        is_call = mn.startswith("bl")
        nxt = ins.address + ins.size
        class _Br(angr.SimProcedure):
            def run(self):
                import claripy
                if is_call and angr.options.CALLLESS in self.state.options:
                    try:
                        self.state.regs.x0 = claripy.BVS("call_ret", 64)
                    except Exception:
                        pass
                    self.jump(claripy.BVV(nxt, self.state.arch.bits))
                else:
                    self.jump(getattr(self.state.regs, reg))
        proc = _Br()
    elif mn.startswith(("pac", "aut", "xpac")):
        # pacibsp/autibsp/xpaclri/… sign or authenticate — a no-op for data-flow, but it
        # must ADVANCE to the next instruction. A bare SimProcedure that returns None does
        # an implicit Ijk_Ret to LR (a SimProcedure models a *called function*), which
        # silently returns from the function at the first signing op; jump to the next
        # instruction instead (AArch64 is 4-byte fixed width).
        class _Nop(angr.SimProcedure):
            def run(self):
                self.jump(self.state.addr + 4)
        proc = _Nop()
    else:
        return None
    project.hook(ins.address, proc, length=ins.size, replace=True)
    return mn


def hook_pac_at(project, addr: int) -> str | None:
    """Hook the SINGLE instruction at `addr` if it is an arm64e PAC op libVEX can't
    decode; return its mnemonic or None. Used ON DEMAND when execution reaches a PAC op
    outside any pre-scanned range (a tail-call target, a helper the function jumps to) —
    so a run isn't bounded to code we scanned up front."""
    import capstone
    try:
        code = bytes(project.loader.memory.load(addr, 4))
    except Exception:
        return None
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    ins = next(iter(md.disasm(code, addr)), None)
    return _install_pac_hook(project, ins) if ins is not None else None


def patch_pac(project, start: int, end: int) -> dict:
    """libVEX can't decode arm64e pointer-authentication instructions, so scan
    [start, end) and hook them with their non-authenticated meaning:

        retaa / retab           -> ret   (jump to LR / x30)
        braa / blraa / ...       -> br/blr Xn (jump/call the target register)
        pac* / aut* / xpac*      -> nop  (signing/auth, no data effect we model)

    Per-project (lives with the analysis, not the global op table). Returns a
    {hex_addr: mnemonic} map of what was hooked. Requires capstone. For PAC ops OUTSIDE
    the scanned range that execution reaches at run time, see hook_pac_at()."""
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    code = bytes(project.loader.memory.load(start, end - start))
    hooked: dict[str, str] = {}
    for ins in md.disasm(code, start):
        mn = _install_pac_hook(project, ins)
        if mn is not None:
            hooked[hex(ins.address)] = mn
    return hooked
