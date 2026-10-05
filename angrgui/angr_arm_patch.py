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
* Iop_SqrtF64       — scalar double sqrt (claripy.fpSqrt)

KNOWN GAPS — implemented on demand, not speculatively (a wrong NEON
saturating/rounding-shift implementation would silently corrupt analysis, which
is worse for bug-hunting than a clean UnsupportedIROpError). A whole-.text scan
of CoreGraphics shows only these remain, all rare (x1-x6, in codec/colour math,
not the glyph-geometry path):

    Iop_QandQSarNnarrow* / QandQRShrNnarrow* / QandQShrNnarrow*  (SQSHRN/UQRSHRN: shift+saturate+narrow, sets QC)
    Iop_Sh32Sx4 / Sh32Ux4        (SSHL/USHL: per-lane variable shift)
    Iop_Rsh16Ux8                 (URSHR: rounding shift right)
    Iop_QShlNsatSS64x2           (SQSHL #imm: saturating left shift)

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


def _op_fgeneric_Sqrt(self, args):
    """Scalar/vector FP square root (SqrtF64/F32)."""
    return claripy.fpSqrt(claripy.fp.RM.RM_NearestTiesEven, args[0])


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
}
_GENERIC = {
    "NarrowUn": _op_generic_NarrowUn,
    "QNarrowUn": _op_generic_QNarrowUn,
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


def apply() -> dict:
    """Install the handlers. Idempotent. Returns {op_name: 'ok'|error} for logging."""
    global _applied
    import angr.engines.vex.claripy.irop as irop
    from angr.errors import UnsupportedIROpError

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
    elif mn in _PAC_BR:                      # braa/blraa/… -> jump/call the target register
        reg = ins.op_str.split(",")[0].strip()
        class _Br(angr.SimProcedure):
            def run(self):
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
