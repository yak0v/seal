"""
The check framework.

A *check* watches a symbolic run for a condition and records "hits" with a
concrete witness (a set of input values that make the condition true).  Checks
are installed as angr `inspect` breakpoints so they observe every state the
explorer produces, without changing the search.

Built-in kinds
--------------
int_overflow : an add / sub / mul can wrap (unsigned) or step outside the
               signed range, at one instruction or across a whole function.
assert       : a boolean expression can be FALSE at a program point
               (i.e. an invariant that symbolic execution can violate).
reach        : some path reaches an address (a "can we get here?" question).
avoid        : record + optionally prune paths that reach an address.
custom       : a user Python snippet `def check(state, api): -> dict | None`.

Each hit is a dict:
    {check_id, kind, addr, message, witness: {name: value}, extra: {...}}

ROLE
----
Every check subclasses ``BaseCheck``. Two flavours:
* **breakpoint-driven** (``installs_breakpoint = True``): installs angr ``inspect``
  hooks (``expr`` / ``mem_write`` / …) and fires as states are built — e.g.
  ``int_overflow``, ``narrowing_cast``, ``float_anomaly``, ``oob_write``. These see
  sub-expressions the explorer never stashes.
* **state-observing** (``installs_breakpoint = False``): inspected at block heads via
  ``note_state`` — e.g. ``reach`` / ``avoid`` / ``assert``.
A check records a hit only when the condition is actually *satisfiable* and attaches a
concrete ``witness`` (``_witness_with``) proving it.

WHY IT'S LIKE THIS
------------------
* **``oob_write`` is anchor+oob, not "belongs AND oob".** The explicit-mode region test
  used to require the write to be both inside the buffer AND outside it — a contradiction,
  so it NEVER fired. It now *anchors* the write to the buffer over a window and flags when
  the address can leave ``[base, base+size)`` (also catching writes already forced out of
  range). See ``_check_region``.
* **``narrowing_cast`` understands NEON vector narrowing, not just scalar C casts.** The
  scalar case is ``Extract(small-1:0, inner)`` with standard widths. But a real ARM ``xtn``
  (our ``angr_arm_patch`` ``NarrowUn`` handler) emits ``Concat`` of per-lane low-half
  ``Extract``s whose ``inner`` is a **128-bit vector** — so the old scalar-only check was
  blind to it and found nothing on the exact CVE-2026-86950 instruction. ``_narrowing``
  now matches BOTH shapes and reports the per-lane 2N→N narrowing. See ``_narrowing``.
* **Checks observe, they don't steer.** Installing as inspect hooks means a check never
  changes the search — add/remove one and the path set is identical, only the findings
  differ.

EXTENDING  (add a new check kind)
---------------------------------
1. Subclass ``BaseCheck``; set ``kind`` and ``installs_breakpoint``.
2. For a breakpoint check, implement ``install(state)`` (register the inspect hook) and an
   ``_on_*`` handler that calls ``self._record(...)`` with a satisfiable witness; for a
   state check, implement the per-state hook used by ``note_state``.
3. Register the class in ``CHECK_TYPES`` (the kind→class dict near the bottom) so
   ``build_check`` can construct it; add its schema to the MCP/GUI docs.

PITFALLS
--------
* Only record when ``state.solver.satisfiable([cond])`` — an unsatisfiable condition is
  not a finding. Always attach the witness that proves it (dedup with ``dedup_key``).
* ``narrowing_cast``/``int_overflow`` read claripy AST structure; a change to how
  ``angr_arm_patch`` builds an op (e.g. the ``Concat`` lane order) can silently stop a
  match — keep the handler and the matcher in sync.
* Breakpoint checks fire on EVERY sub-expression; keep handlers cheap and bail fast on
  the common no-match case.
"""
from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

import angr
import claripy

from .exprlang import ExprError, make_evaluator, as_bool

log = logging.getLogger("angrgui.checks")

# claripy AST ops we treat as (potentially) overflowing N-bit arithmetic.
AST_OVERFLOW_OPS = {"__add__": "+", "__sub__": "-", "__mul__": "*"}

# capstone mnemonics that correspond to real integer arithmetic (used to filter out
# the address arithmetic VEX generates inside loads/stores).
ARITH_MNEMONICS = {"add", "adc", "sub", "sbb", "imul", "mul", "inc", "dec", "neg", "lea"}


def _overflow_condition(op_char: str, a, b, signed: bool):
    """Boolean AST, true when the N-bit op a<op>b overflows for the given signedness."""
    n = a.size()
    ext = (lambda x: x.sign_extend(n)) if signed else (lambda x: x.zero_extend(n))
    aw, bw = ext(a), ext(b)
    if op_char == "+":
        wres, narrow = aw + bw, a + b
    elif op_char == "-":
        wres, narrow = aw - bw, a - b
    elif op_char == "*":
        wres, narrow = aw * bw, a * b
    else:
        raise ValueError(op_char)
    return wres != ext(narrow)


# --------------------------------------------------------------------------- Check base
@dataclass
class Hit:
    check_id: str
    kind: str
    addr: int
    message: str
    witness: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)
    id: str | None = None          # stable per-run finding id (e.g. "f1"), set when recorded

    def to_json(self):
        return {
            "id": self.id,
            "check_id": self.check_id, "kind": self.kind, "addr": self.addr,
            "message": self.message, "witness": self.witness, "extra": self.extra,
        }


class BaseCheck:
    kind = "base"
    installs_breakpoint = False     # True => driven by an inspect breakpoint, not note_state

    def __init__(self, spec: dict, ctx: "CheckContext"):
        self.spec = spec
        self.id = spec.get("id", "check")
        self.name = spec.get("name", self.kind)
        self.enabled = spec.get("enabled", True)
        self.ctx = ctx
        self.hits: list[Hit] = []
        self._seen: set = set()
        self.near: dict = {}     # addr -> text: sites reached but not triggered (for diagnostics)

    def install(self, state):
        """Install any angr inspect breakpoints this check needs. Default: none.

        Expression-level checks (int_overflow) override this. State-point checks
        (assert / reach / avoid / custom) instead implement note_state(), which the
        runner calls for every active successor at a block boundary, where register
        and memory reads are fully committed and therefore reliable.
        """
        return

    def note_state(self, state):
        """Called by the runner for each active state at a block boundary."""
        return

    def note_return(self, state, ret_site):
        """Called by the runner once a state has returned from the target function,
        where the return register holds its final value. ret_site is the address of
        the return instruction. Default: nothing (only at_return asserts use this)."""
        return

    # -- helpers shared by subclasses ----------------------------------
    def _witness(self, state) -> dict:
        return witness_of(state)

    def _witness_with(self, state, extra_constraints) -> dict:
        """Witness under additional constraints (a fresh copy, so the run is untouched)."""
        tmp = state.copy()
        for c in extra_constraints:
            tmp.add_constraints(c)
        return self._witness(tmp)

    def _record(self, state, addr, message, witness=None, extra=None, dedup_key=None, trigger=None):
        key = dedup_key if dedup_key is not None else (addr, message)
        if key in self._seen:
            return
        self._seen.add(key)
        extra = dict(extra or {})
        # Variables of the TRIGGERING expression (the OOB address, the narrowed value,
        # the asserted condition). The confidence classifier unions these with the path
        # constraints — so a finding whose triggering VALUE is an unconstrained skipped
        # call return is still seen as conditional even when no branch constrained it.
        if trigger is not None:
            tvars: set = set()
            for t in (trigger if isinstance(trigger, (list, tuple)) else [trigger]):
                try:
                    tvars |= t.variables
                except Exception:
                    pass
            if tvars:
                extra["_dep"] = sorted(tvars)
        self.hits.append(Hit(self.id, self.kind, addr, message, witness or {}, extra))
        self.ctx.on_hit(self.hits[-1], state)


def witness_of(state) -> dict:
    """Concrete values for every named input, if the path is satisfiable.

    All scalar/member values come from ONE joint model via a single `batch_eval`, so they
    are mutually consistent (they satisfy the finding TOGETHER) — but it is still just one
    solver call. The previous version evaluated each input in its own constrained query on
    a fresh state copy; with a dozen named struct members that was ~14 solves + a copy PER
    FINDING, firing on every narrowing check on every path, which made a single step take
    tens of seconds (the run looked hung and cancel — only checked between steps — couldn't
    land). batch_eval restores both joint consistency and speed."""
    out = {}
    names = state.globals.get("angrgui_vars", {})
    floatvars = state.globals.get("angrgui_floatvars", {}) or {}

    def _decode_floats(v, bits, fs):
        """Reinterpret an integer value's bits as floats per layout fs."""
        import struct as _s
        try:
            b = int(v).to_bytes(max(bits // 8, 1), "little")
            if fs in ("f32", "float"):   return [_s.unpack("<f", b[:4])[0]]
            if fs in ("f64", "double"):  return [_s.unpack("<d", b[:8])[0]]
            if fs == "f32x2":            return list(_s.unpack("<ff", b[:8]))
            if fs == "f64x2":            return list(_s.unpack("<dd", b[:16]))
            if fs == "f32x4":            return list(_s.unpack("<ffff", b[:16]))
        except Exception:
            return None
        return None

    # Collect (key, bv, bits, floatspec). Named struct members FIRST, so we know which
    # buffers actually got named fields — a buffer's raw blob is hidden below only if its
    # fields genuinely replaced it (otherwise suppressing it would hide the state entirely).
    items = []
    covered = set()
    for bufname, members in (state.globals.get("angrgui_bufmembers") or {}).items():
        buf = names.get(bufname)
        if not (isinstance(buf, claripy.ast.Base) and buf.op == "BVS"):
            continue
        n = buf.size()
        for m in members[:96]:
            off, size, mname = m[0], m[1], m[2]
            is_float = len(m) > 3 and bool(m[3])
            if not (1 <= size <= 8) or off * 8 + size * 8 > n:
                continue
            try:
                parts = [buf[n - 1 - 8 * (off + i):n - 8 * (off + i) - 8] for i in range(size)]
                bv = parts[0] if size == 1 else claripy.Concat(*reversed(parts))
                if bv.symbolic:                       # only report fields the inputs actually fix
                    fspec = ("f64" if size == 8 else "f32") if is_float else None
                    items.append((mname, bv, size * 8, fspec))
                    covered.add(bufname)
            except Exception:
                pass
    for nm, ast in names.items():
        if nm in covered:                # raw buffer blob -> shown as its named members instead
            continue
        if isinstance(ast, claripy.ast.Base) and ast.symbolic:
            items.append((nm, ast, ast.size(), floatvars.get(nm)))   # float regs -> decoded below

    if items:
        asts = [it[1] for it in items]
        try:
            vals = list(state.solver.batch_eval(asts, 1)[0])   # ONE joint model
        except Exception:
            vals = [state.solver.eval(a) for a in asts]        # fallback (per-var; may not be joint)
        for (key, _bv, bits, fspec), v in zip(items, vals):
            cell = _fmt(int(v), bits)
            if fspec:
                fl = _decode_floats(int(v), bits, fspec)
                if fl is not None:
                    # A symbolic coordinate can solve to a non-finite IEEE value (±inf / nan
                    # — e.g. the CoreGraphics aa_lineto coordinate). Those are not JSON
                    # compliant: starlette's encoder (allow_nan=False) 500s the whole run
                    # result, and json.dumps's default emits bare Infinity (invalid JSON a
                    # JS/strict client rejects). Keep the lane legible by tagging it.
                    cell["floats"] = [_json_safe_float(x) for x in fl]
            out[key] = cell

    # byte inputs (stdin / files) — evaluated separately; these are independent of the
    # scalar overflow constraints in practice, and batch_eval over bytes is awkward.
    so = state.globals.get("angrgui_stdin")
    if so is not None:
        try:
            out["stdin"] = state.solver.eval(so, cast_to=bytes).hex()
        except Exception:
            pass
    else:
        try:
            data = state.posix.dumps(0)
            if data:
                out["stdin"] = data.hex()
        except Exception:
            pass
    for fname, fb in (state.globals.get("angrgui_files") or {}).items():
        try:
            out["file:" + fname] = state.solver.eval(fb, cast_to=bytes).hex()
        except Exception:
            pass
    return out


def _fmt(v: int, bits: int) -> dict:
    signed = v if v < (1 << (bits - 1)) else v - (1 << bits)
    return {"u": v, "s": signed, "hex": hex(v), "bits": bits}


def _json_safe_float(x):
    """A finite float passes through; a non-finite one (±inf / nan) becomes a string tag
    so the value survives JSON on both surfaces. The GUI's fmtFloat already renders a
    non-numeric lane as-is, so this stays legible."""
    import math
    if isinstance(x, float) and not math.isfinite(x):
        return "-inf" if x == float("-inf") else ("inf" if x == float("inf") else "nan")
    return x


# --------------------------------------------------------------------------- int_overflow
class IntOverflowCheck(BaseCheck):
    kind = "int_overflow"
    installs_breakpoint = True

    def __init__(self, spec, ctx):
        super().__init__(spec, ctx)
        self.addr = spec.get("addr")            # None => whole function
        self.signed = spec.get("signed", "either")   # 'signed'|'unsigned'|'either'
        self.func_addr = spec.get("func_addr")

    def _modes(self):
        if self.signed == "signed":
            return [("signed", True)]
        if self.signed == "unsigned":
            return [("unsigned", False)]
        return [("unsigned", False), ("signed", True)]

    def install(self, state):
        # We watch VEX expression *results*: for an N-bit add/sub/mul the claripy AST
        # carries its operands as .args, which is reliable (unlike mid-block registers).
        state.inspect.b("expr", when=angr.BP_AFTER, action=self._on_expr)

    def _mnemonic_at(self, state, ins_addr):
        try:
            block = state.project.factory.block(ins_addr, num_inst=1)
            insn = block.capstone.insns[0]
            return insn.mnemonic, f"{insn.mnemonic} {insn.op_str}".strip()
        except Exception:
            return None, None

    def _on_expr(self, state):
        if self.ctx.is_cancelled():
            return
        insp = state.inspect
        r = insp.attrs.expr_result if hasattr(insp, "attrs") else insp.expr_result
        if r is None or not isinstance(r, claripy.ast.BV):
            return
        op_char = AST_OVERFLOW_OPS.get(r.op)
        if op_char is None:
            return
        args = r.args
        if len(args) != 2:
            return
        a, b = args
        if not (isinstance(a, claripy.ast.BV) and isinstance(b, claripy.ast.BV)):
            return
        n = r.size()
        if a.size() != n or b.size() != n:
            return                      # widening op (e.g. 32x32->64) can't overflow
        if not (a.symbolic or b.symbolic):
            return                      # constant fold, nothing to solve

        ins_addr = state.scratch.ins_addr
        if ins_addr is None:
            return
        if self.addr is not None:
            if ins_addr != self.addr:
                return
        else:
            if not self.ctx.in_target_function(ins_addr):
                return
            mn, _ = self._mnemonic_at(state, ins_addr)
            if mn not in ARITH_MNEMONICS:
                return                  # skip address arithmetic inside other insns

        mn, text = self._mnemonic_at(state, ins_addr)
        for label, signed in self._modes():
            try:
                cond = _overflow_condition(op_char, a, b, signed)
                if not state.solver.satisfiable(extra_constraints=[cond]):
                    continue
            except Exception:
                continue
            witness = self._witness_with(state, [cond])
            opvals = self._concrete_ops(state, (a, b), cond)
            shown = op_char.join(v["hex"] for v in opvals) if opvals else "..."
            loc = self.ctx.line_for(ins_addr)
            # surface the source location + result width in the headline: an agent
            # triaging many hits can tell a 32-bit value overflow (often the real
            # bug) from a 64-bit add that is usually pointer/address arithmetic.
            if isinstance(loc, dict) and loc.get("line"):
                where = f" [{loc.get('file')}:{loc['line']}]"
            elif isinstance(loc, (tuple, list)) and len(loc) == 2:
                where = f" [{loc[0]}:{loc[1]}]"
            else:
                where = ""
            msg = f"{label} {n}-bit overflow possible at {text or hex(ins_addr)}{where}  ({shown})"
            self._record(state, ins_addr, msg, witness,
                         extra={"mnemonic": mn, "op": op_char, "signedness": label,
                                "operands": opvals, "src_line": loc,
                                "result_bits": n, "path": self.ctx.path_of(state)},
                         dedup_key=(ins_addr, label, op_char), trigger=(a, b))

    def _concrete_ops(self, state, operands, cond):
        tmp = state.copy()
        tmp.add_constraints(cond)
        out = []
        if not tmp.solver.satisfiable():
            return out
        for o in operands:
            try:
                out.append(_fmt(tmp.solver.eval(o), o.size()))
            except Exception:
                out.append({"hex": "?"})
        return out


# --------------------------------------------------------------------------- assert
class AssertCheck(BaseCheck):
    kind = "assert"

    def __init__(self, spec, ctx):
        super().__init__(spec, ctx)
        self.at_return = spec.get("at_return", False)
        self.expr = spec["expr"]
        # Where to evaluate. at_return is handled separately (note_return), because the
        # return value may be computed *inside* the return block (e.g. a cmov at -O2),
        # so it is only final once the state has actually returned -- not at the block head.
        if self.at_return:
            self.points = set()     # nothing at block heads; see note_return
        elif spec.get("addr") is not None:
            self.points = {ctx.block_head(int(spec["addr"]))}
        else:
            self.points = None      # every block head in the target function

    def note_state(self, state):
        addr = state.addr
        if self.points is None:
            if not self.ctx.in_target_function(addr):
                return
        elif addr not in self.points:
            return
        self._evaluate(state, addr)

    def note_return(self, state, ret_site):
        # called once the state has returned; registers (including the return value) are final
        if self.at_return:
            self._evaluate(state, ret_site)

    def _evaluate(self, state, addr):
        try:
            ast = as_bool(make_evaluator(state)(self.expr))
        except ExprError as e:
            self._record(state, addr, f"assert expression error: {e}",
                         dedup_key=("err", str(e)))
            return
        except Exception:
            return
        neg = claripy.Not(ast) if isinstance(ast, claripy.ast.Bool) else (ast == 0)
        try:
            if not state.solver.satisfiable(extra_constraints=[neg]):
                return
        except Exception:
            return
        witness = self._witness_with(state, [neg])
        self._record(state, addr, f"assert can be false: {self.expr}", witness,
                     extra={"expr": self.expr, "src_line": self.ctx.line_for(addr),
                            "path": self.ctx.path_of(state)},
                     dedup_key=(addr, self.expr),
                     trigger=(ast if isinstance(ast, claripy.ast.Base) else None))


# --------------------------------------------------------------------------- reach / avoid
class ReachCheck(BaseCheck):
    kind = "reach"
    verb = "reached"

    def __init__(self, spec, ctx):
        super().__init__(spec, ctx)
        self.addr = int(spec["addr"])
        self.prune = spec.get("prune", False)

    def note_state(self, state):
        if not self._reaches(state):
            return
        witness = self._witness(state)
        self._record(state, self.addr, f"{self.verb} {self.addr:#x}", witness,
                     extra={"src_line": self.ctx.line_for(self.addr),
                            "path": self.ctx.path_of(state)}, dedup_key=self.addr)

    def _reaches(self, state):
        # Match the target anywhere in the block being executed, not only at the block
        # head — so an agent can point reach/avoid at *any* instruction (e.g. a `call`
        # that ends a block), not just basic-block leaders.
        if state.addr == self.addr:
            return True
        try:
            return self.addr in state.block().instruction_addrs
        except Exception:
            return False


class AvoidCheck(ReachCheck):
    kind = "avoid"
    verb = "hit avoided address"


# --------------------------------------------------------------------------- custom
CUSTOM_TEMPLATE = '''\
# Custom check. Runs at every instruction (or, set WHEN below).
# Return a dict {"message": str, "addr": int (optional)} to record a hit, else None.
# `state` is the live angr SimState. `api` gives helpers:
#   api.eval("expr")        -> claripy AST over this state (same mini-language as asserts)
#   api.sat(bool_ast)       -> is it satisfiable on this path?
#   api.witness(bool_ast)   -> {name: value} making bool_ast true, or {}
#   api.reg("rax"), api.mem(addr, size)
def check(state, api):
    return None
'''


class CustomCheck(BaseCheck):
    kind = "custom"

    def __init__(self, spec, ctx):
        super().__init__(spec, ctx)
        self.code = spec.get("code", "")
        self.points = {ctx.block_head(int(spec["addr"]))} if spec.get("addr") is not None else None
        self._fn = None
        self._err = None
        self._loaded = False
        try:
            ns: dict = {}
            exec(compile(self.code, f"<custom:{self.id}>", "exec"), ns)
            self._fn = ns.get("check")
            if not callable(self._fn):
                self._err = "no callable check(state, api) defined"
        except Exception:
            self._err = traceback.format_exc(limit=3)

    def note_state(self, state):
        addr = state.addr
        if self._err:
            if not self._loaded:
                self._loaded = True
                self._record(state, addr, f"custom check failed to load: {self._err}",
                             dedup_key="loaderr")
            return
        if self.points is None:
            if not self.ctx.in_target_function(addr):
                return
        elif addr not in self.points:
            return
        api = _CustomAPI(state, self)
        try:
            res = self._fn(state, api)
        except Exception:
            self._record(state, addr, f"custom check raised: {traceback.format_exc(limit=2)}",
                         dedup_key=("raise", addr))
            return
        if res:
            haddr = res.get("addr", addr)
            self._record(state, haddr, res.get("message", "custom hit"),
                         res.get("witness", api.last_witness),
                         extra={"src_line": self.ctx.line_for(haddr),
                                "path": self.ctx.path_of(state), **res.get("extra", {})},
                         dedup_key=(haddr, res.get("message")))


class _CustomAPI:
    def __init__(self, state, check):
        self.state = state
        self._check = check
        self.last_witness = {}

    def eval(self, expr: str):
        return make_evaluator(self.state)(expr)

    def sat(self, cond) -> bool:
        return self.state.solver.satisfiable(extra_constraints=[cond])

    def witness(self, cond=None):
        cs = [cond] if cond is not None else []
        self.last_witness = self._check._witness_with(self.state, cs)
        return self.last_witness

    def reg(self, name):
        return getattr(self.state.regs, name)

    def mem(self, addr, size=8):
        return self.state.memory.load(addr, size, endness=self.state.arch.memory_endness)


# --------------------------------------------------------------------------- narrowing_cast
# standard C integer widths; a narrowing cast truncates to a smaller one.
_STD_WIDTHS = {8, 16, 32, 64}


class NarrowingCastCheck(BaseCheck):
    """A value truncated to a smaller integer type (int->short, long->int, ->char …)
    where the discarded high bits can be non-zero, i.e. information is lost."""
    kind = "narrowing_cast"
    installs_breakpoint = True

    def __init__(self, spec, ctx):
        super().__init__(spec, ctx)
        self.addr = spec.get("addr")            # None => whole function

    def install(self, state):
        state.inspect.b("expr", when=angr.BP_AFTER, action=self._on_expr)

    # Instructions that genuinely narrow a value. The VECTOR (Concat) shape only ever
    # comes from these NEON ops, so it is allow-listed; anything else producing a
    # Concat-of-low-halves (logical masks, byte shuffles) is not a narrowing cast.
    _NARROW_VEC = {
        "xtn", "xtn2", "uqxtn", "uqxtn2", "sqxtn", "sqxtn2", "sqxtun", "sqxtun2",
        "shrn", "shrn2", "rshrn", "rshrn2", "sqshrn", "uqshrn", "sqrshrn", "uqrshrn",
        "addhn", "addhn2", "subhn", "subhn2", "raddhn", "raddhn2", "rsubhn", "rsubhn2",
        "fcvtn", "fcvtn2", "fcvtxn", "fcvtxn2",
        "fcvtzs", "fcvtzu", "fcvtns", "fcvtnu", "fcvtms", "fcvtmu",
        "fcvtps", "fcvtpu", "fcvtas", "fcvtau",
    }
    # Scalar bit-reshuffles that are NOT narrowing casts even though a truncated
    # sub-expression of theirs can look like one.
    _NOT_NARROW_SCALAR = {
        "and", "ands", "orr", "orn", "eor", "eon", "bic", "bics", "mvn",
        "bfi", "bfc", "bfxil", "bfm", "sbfm", "ubfm", "sbfiz", "ubfiz", "sbfx", "ubfx",
        "movk", "movn", "movz", "mov", "mvni", "lsl", "lslv", "lsr", "lsrv",
        "asr", "asrv", "ror", "rorv", "extr", "rev", "rev16", "rev32", "rbit",
        "clz", "cls", "dup", "ins", "umov", "smov",
        # compares / conditionals / branches only CONSUME a (possibly narrowed) value —
        # the narrowing, if any, is at the instruction that produced it, not here.
        "cmp", "cmn", "tst", "ccmp", "ccmn", "cbz", "cbnz", "tbz", "tbnz",
        "csel", "cset", "csetm", "csinc", "csinv", "csneg", "cinc", "cinv", "cneg",
        "b", "br", "blr", "bl", "ret", "beq", "bne",
    }

    def _is_narrowing_insn(self, mn, shape):
        if not mn:
            return False
        mn = mn.lower()
        if shape == "vector":
            return mn in self._NARROW_VEC
        return mn not in self._NOT_NARROW_SCALAR

    @staticmethod
    def _narrowing(r):
        """Recognise a truncating narrow and return (small, big, fulls, shape) or None.

        Two shapes:
          * scalar C cast  -> Extract(small-1:0, inner)          [inner wider, same value]
          * NEON xtn lane  -> Concat(inner[2k·s+s-1:2k·s] ...)   [low half of each 2s-wide
            lane of one vector] — our angr_arm_patch NarrowUn handler emits exactly this.
        `fulls` are the full (pre-narrow) values, one per lane; the caller flags a finding
        when some lane's value cannot fit the narrow width (truncation changes it)."""
        if not isinstance(r, claripy.ast.BV):
            return None
        if r.op == "Extract":                       # scalar: Extract(small-1 : 0, inner)
            hi, lo, inner = r.args
            if lo != 0 or not isinstance(inner, claripy.ast.BV):
                return None
            small, big = hi + 1, inner.size()
            if small >= big or small not in _STD_WIDTHS or big not in _STD_WIDTHS:
                return None
            if not inner.symbolic:
                return None
            return small, big, [inner], "scalar"
        if r.op == "Concat":
            # NEON lane-narrowing (xtn/vmovn/…): the result is a Concat of per-lane low
            # halves. The shape VARIES after claripy simplification — a lane may be a bare
            # Extract of one vector register (every lane symbolic), an Extract of that
            # lane's own already-folded source (e.g. fcvtzs: `fpToSBV(…)[31:0]`), or a
            # constant (a lane that folded to a concrete value, e.g. a zeroed high lane).
            # So treat each lane INDEPENDENTLY rather than requiring one common inner: a
            # lane that is the low `small` bits of a value at least `2*small` wide drops
            # that value's next `small` bits. (This is why the earlier one-inner matcher
            # missed the real CoreGraphics xtn, whose high lane folds to a constant.)
            args = r.args
            if len(args) < 2:
                return None
            small = args[0].size()
            if small not in _STD_WIDTHS or any(a.size() != small for a in args):
                return None
            fulls = []
            for a in args:
                if a.op == "Extract" and isinstance(a.args[2], claripy.ast.BV):
                    hi, lo, X = a.args
                    if hi - lo + 1 == small and X.size() >= lo + 2 * small:
                        full = X[lo + 2 * small - 1: lo]        # the 2*small-bit value this lane narrows
                        if full.symbolic:
                            fulls.append(full)
                        continue
                if a.symbolic:                  # a symbolic lane that isn't a clean low-half
                    return None                 # Extract -> not a recognizable lane-narrowing
            if not fulls:
                return None
            return small, 2 * small, fulls, "vector"
        return None

    def _on_expr(self, state):
        if self.ctx.is_cancelled():            # user cancelled — stop doing solver work NOW
            return
        insp = state.inspect
        r = insp.attrs.expr_result if hasattr(insp, "attrs") else insp.expr_result
        nar = self._narrowing(r)
        if nar is None:
            return
        small, big, fulls, shape = nar
        ins_addr = state.scratch.ins_addr
        if ins_addr is None:
            return
        if self.addr is not None:
            if ins_addr != self.addr:
                return
        elif not self.ctx.in_target_function(ins_addr):
            return
        # Already recorded this narrowing site? Skip everything below — the capstone
        # decode, the satisfiability solve, and the witness solve would all just be
        # deduped away. The narrowing breakpoint fires for the SAME xtn on every path, and
        # on an FP-heavy function those per-path solves are what make a run crawl and look
        # hung (so cancel, checked only between steps, can't land). Dedup FIRST.
        if (ins_addr, big, small) in self._seen:
            return
        # Gate by the actual INSTRUCTION. The expr breakpoint fires on every VEX
        # sub-expression, so bit-manipulation (and/orr/bic/bfxil/lsr…) and byte
        # reassembly produce Concat/Extract shapes that LOOK like a narrow but aren't —
        # that is how `and w8, w8, #0xffff0000` was being reported as a 16->8 narrowing.
        # A real narrowing cast is one of a known set of instructions; require it.
        mn = text = None
        try:
            insn = state.project.factory.block(ins_addr, num_inst=1).capstone.insns[0]
            mn, text = insn.mnemonic, f"{insn.mnemonic} {insn.op_str}".strip()
        except Exception:
            pass
        if not self._is_narrowing_insn(mn, shape):
            return
        # A finding only if the narrowing can ACTUALLY lose data — i.e. the value does not
        # fit the narrow type, so truncating and sign-extending back changes it. Testing
        # merely "dropped high bits != 0" over-reports: narrowing -1 (all-ones high bits)
        # to int32 is still -1 — lossless. We want the inputs that make the value genuinely
        # out of range (the real CVE-class overflow), not a benign negative.
        def _lossy(full):
            kept = full[small - 1:0]
            return full != claripy.SignExt(full.size() - small, kept)
        conds = [_lossy(f) for f in fulls]
        cond = conds[0] if len(conds) == 1 else claripy.Or(*conds)
        try:
            if not state.solver.satisfiable(extra_constraints=[cond]):
                # Reached a narrowing instruction, but on this path the value always fits —
                # record it so a 0-finding run can say "reached X but never lossy" instead of
                # a blank "nothing triggered" (a concrete field is likely gating the overflow).
                self.near[ins_addr] = text or mn or "narrowing"
                return
        except Exception:
            return
        witness = self._witness_with(state, [cond])
        loc = self.ctx.line_for(ins_addr)
        if isinstance(loc, dict) and loc.get("line"):
            where = f" [{loc.get('file')}:{loc['line']}]"
        elif isinstance(loc, (tuple, list)) and len(loc) == 2:
            where = f" [{loc[0]}:{loc[1]}]"
        else:
            where = ""
        msg = f"narrowing {big}->{small} bits may lose data at {text or hex(ins_addr)}{where}"
        self._record(state, ins_addr, msg, witness,
                     extra={"from_bits": big, "to_bits": small, "mnemonic": mn,
                            "src_line": loc, "path": self.ctx.path_of(state)},
                     dedup_key=(ins_addr, big, small), trigger=list(fulls))


# --------------------------------------------------------------------------- float_anomaly
_FP_OPS = {"fpAdd": "+", "fpSub": "-", "fpMul": "*", "fpDiv": "/"}


class FloatAnomalyCheck(BaseCheck):
    """A floating-point operation whose result can be NaN or +/-Inf — the sort of
    'weird' value that comes from special or extreme inputs (0/0, inf-inf, overflow)."""
    kind = "float_anomaly"
    installs_breakpoint = True

    def __init__(self, spec, ctx):
        super().__init__(spec, ctx)
        self.addr = spec.get("addr")

    def install(self, state):
        state.inspect.b("expr", when=angr.BP_AFTER, action=self._on_expr)

    @staticmethod
    def _find_fp_ops(root):
        """FP arithmetic nodes anywhere in an AST. SSE scalar ops (divsd/addsd…) wrap
        the fp result back into a BV (fpToIEEEBV inside a Concat), so the fpAdd/fpDiv
        is a sub-expression, not the top node."""
        out, seen, stack, steps = [], set(), [root], 0
        while stack and steps < 4000:
            n = stack.pop(); steps += 1
            if not hasattr(n, "op") or id(n) in seen:
                continue
            seen.add(id(n))
            if n.op in _FP_OPS and isinstance(n, claripy.ast.FP):
                out.append(n)
            for a in n.args:
                if hasattr(a, "op"):
                    stack.append(a)
        return out

    def _on_expr(self, state):
        if self.ctx.is_cancelled():
            return
        insp = state.inspect
        r = insp.attrs.expr_result if hasattr(insp, "attrs") else insp.expr_result
        if r is None or not hasattr(r, "op"):
            return
        if not (isinstance(r, claripy.ast.FP) or (isinstance(r, claripy.ast.BV) and r.size() in (32, 64, 128))):
            return
        if not r.symbolic:
            return
        ins_addr = state.scratch.ins_addr
        if ins_addr is None:
            return
        if self.addr is not None:
            if ins_addr != self.addr:
                return
        elif not self.ctx.in_target_function(ins_addr):
            return
        for node in self._find_fp_ops(r):
            if not node.symbolic:
                continue
            for label, pred in (("NaN", claripy.fpIsNaN), ("infinite", claripy.fpIsInf)):
                try:
                    cond = pred(node)
                    if not state.solver.satisfiable(extra_constraints=[cond]):
                        continue
                except Exception:
                    continue
                witness = self._witness_with(state, [cond])
                msg = f"floating-point result can be {label} ({_FP_OPS.get(node.op, '?')}) at {hex(ins_addr)}"
                self._record(state, ins_addr, msg, witness,
                             extra={"anomaly": label, "op": _FP_OPS.get(node.op),
                                    "src_line": self.ctx.line_for(ins_addr), "path": self.ctx.path_of(state)},
                             dedup_key=(ins_addr, label, node.op))


# --------------------------------------------------------------------------- oob_write
class BufferBoundsCheck(BaseCheck):
    """A memory write whose address can fall outside a buffer. Two modes:

    * explicit: `base` is an expression (a pointer arg a1, rsp-0x40, a literal) and
      `size` the byte count — check writes against [base, base+size).
    * modeled: no `base` — check writes against every buffer handed out by a hooked
      allocator (an `alloc` call model), i.e. heap overflows of modeled allocations.
    """
    kind = "oob_write"
    installs_breakpoint = True

    def __init__(self, spec, ctx):
        super().__init__(spec, ctx)
        self.base_expr = spec.get("base") or None     # None => check modeled allocations
        self.size = int(spec.get("size", 0))
        self.addr = spec.get("addr")            # restrict to one access instruction, optional
        # Same bounds logic for reads (oob_read: info-leak) and writes (oob_write: corruption).
        self.access = "read" if spec.get("kind") == "oob_read" else "write"
        self.kind = spec.get("kind") or self.kind

    def install(self, state):
        ev = "mem_read" if self.access == "read" else "mem_write"
        state.inspect.b(ev, when=angr.BP_BEFORE, action=self._on_write)

    def _on_write(self, state):
        ins_addr = state.scratch.ins_addr
        if ins_addr is None:
            return
        if self.addr is not None:
            if ins_addr != self.addr:
                return
        elif not self.ctx.in_target_function(ins_addr):
            return
        if self.access == "read":
            wa = state.inspect.mem_read_address
            wl = state.inspect.mem_read_length
        else:
            wa = state.inspect.mem_write_address
            wl = state.inspect.mem_write_length
        if wa is None or not isinstance(wa, claripy.ast.BV):
            return
        if wl is None:
            expr = state.inspect.mem_write_expr if self.access == "write" else None
            wl = (expr.size() // 8) if expr is not None else 1
        bits = wa.size()
        length = wl if isinstance(wl, claripy.ast.BV) else claripy.BVV(int(wl), bits)
        if length.size() != bits:
            length = length.zero_extend(bits - length.size()) if length.size() < bits else length[bits - 1:0]

        if self.base_expr is not None:
            try:
                base = make_evaluator(state)(self.base_expr)
            except ExprError as e:
                self._record(state, ins_addr, f"buffer base expression error: {e}", dedup_key=("err", str(e)))
                return
            except Exception:
                return
            base = base.zero_extend(bits - base.size()) if base.size() < bits else base[bits - 1:0]
            self._check_region(state, ins_addr, wa, length, base, claripy.BVV(self.size, bits),
                               None, f"the {self.size}-byte buffer")
        else:
            # modeled mode: each tracked allocation is (base, logical_size, region_end)
            for (base, size, end) in state.globals.get("angrgui_allocs", ()):
                base_bv = base if isinstance(base, claripy.ast.BV) else claripy.BVV(base, bits)
                end_bv = end if isinstance(end, claripy.ast.BV) else claripy.BVV(end, bits)
                size_bv = size if isinstance(size, claripy.ast.BV) else claripy.BVV(size, bits)
                if size_bv.size() != bits:
                    size_bv = size_bv.zero_extend(bits - size_bv.size()) if size_bv.size() < bits else size_bv[bits - 1:0]
                self._check_region(state, ins_addr, wa, length, base_bv, size_bv, end_bv, "its allocated buffer")

    def _check_region(self, state, ins_addr, wa, length, base, size_bv, end, label):
        # A finding = the write [wa, wa+length) is ANCHORED to this buffer (its address
        # derives from base — it lands within a generous window around base, which rules
        # out unrelated pointers) and CAN leave [base, base+size). We deliberately do NOT
        # require it to also be in-bounds: on a path whose constraints already force the
        # index out of range, the write is a *definite* overflow and must still fire.
        REGION = 0x100000                    # 1 MiB window = "derived from this buffer"
        if end is not None:                  # modeled allocation: confine to its region
            anchor = claripy.And(claripy.UGE(wa, base), claripy.ULT(wa, end))
        elif wa.symbolic:                    # explicit buffer, symbolic index: window both sides of base
            anchor = claripy.And(claripy.UGE(wa, base - REGION), claripy.ULT(wa, base + REGION))
        else:
            # explicit buffer, CONCRETE address (a loop index or memcpy offset, base+k):
            # anchor tightly at/just-past the buffer so an overflow fires, while an
            # unrelated constant address (a stack spill before/far from base) does not.
            GUARD = claripy.BVV(0x1000, size_bv.size())
            anchor = claripy.And(claripy.UGE(wa, base), claripy.ULT(wa, base + size_bv + GUARD))
        oob = claripy.Or(claripy.ULT(wa, base), claripy.UGT(wa + length, base + size_bv))
        try:
            if not state.solver.satisfiable(extra_constraints=[anchor, oob]):
                return
        except Exception:
            return
        region = [anchor]
        witness = self._witness_with(state, region + [oob])
        where = base_v = size_v = None
        try:
            tmp = state.copy()
            for c in region:
                tmp.add_constraints(c)
            tmp.add_constraints(oob)
            where = tmp.solver.eval(wa); base_v = tmp.solver.eval(base); size_v = tmp.solver.eval(size_bv)
        except Exception:
            pass
        msg = f"out-of-bounds {self.access} at {hex(ins_addr)}: address can leave {label}"
        self._record(state, ins_addr, msg, witness,
                     extra={"write_addr": (hex(where) if where is not None else None),
                            "buffer_base": (hex(base_v) if base_v is not None else None),
                            "buffer_size": size_v if size_v is not None else self.size,
                            "src_line": self.ctx.line_for(ins_addr), "path": self.ctx.path_of(state)},
                     dedup_key=(ins_addr, base_v), trigger=wa)


class NullDerefCheck(BaseCheck):
    """A memory read or write through a pointer the inputs can drive into the null page
    — a null-pointer dereference. Fires when the access address is SYMBOLIC and can be
    made to fall in [0, PAGE). angr zero-fills unmapped memory, so these never crash on
    their own; this check surfaces them. Add "addr" to pin one instruction; omit it to
    scan the whole function. Set "page" to widen the "near-null" window (default 0x1000)."""
    kind = "null_deref"
    installs_breakpoint = True

    def __init__(self, spec, ctx):
        super().__init__(spec, ctx)
        self.addr = spec.get("addr")
        self.page = int(spec.get("page", 0x1000))

    def install(self, state):
        state.inspect.b("mem_read", when=angr.BP_BEFORE, action=lambda s: self._on_access(s, "read"))
        state.inspect.b("mem_write", when=angr.BP_BEFORE, action=lambda s: self._on_access(s, "write"))

    def _on_access(self, state, access):
        ins_addr = state.scratch.ins_addr
        if ins_addr is None:
            return
        if self.addr is not None:
            if ins_addr != self.addr:
                return
        elif not self.ctx.in_target_function(ins_addr):
            return
        a = (state.inspect.mem_read_address if access == "read"
             else state.inspect.mem_write_address)
        # only attacker-influenced (symbolic) pointers — concrete stack/global accesses
        # are not null-deref candidates and keep the hook cheap.
        if a is None or not isinstance(a, claripy.ast.BV) or not a.symbolic:
            return
        cond = claripy.ULT(a, self.page)
        try:
            if not state.solver.satisfiable(extra_constraints=[cond]):
                return
        except Exception:
            return
        witness = self._witness_with(state, [cond])
        where = None
        try:
            tmp = state.copy()
            tmp.add_constraints(cond)
            where = tmp.solver.eval(a)
        except Exception:
            pass
        msg = f"null-pointer {access} at {hex(ins_addr)}: the address can be NULL"
        self._record(state, ins_addr, msg, witness,
                     extra={"access": access, "addr": hex(where) if where is not None else None,
                            "src_line": self.ctx.line_for(ins_addr), "path": self.ctx.path_of(state)},
                     dedup_key=(ins_addr, access))


class DivByZeroCheck(BaseCheck):
    """An integer division or remainder whose DIVISOR the inputs can make zero. On x86
    this faults (SIGFPE); on arm64 sdiv/udiv return 0 instead of trapping, but a
    zero-divisor is still a strong logic-bug signal. Add "addr" to pin one instruction."""
    kind = "div_by_zero"
    installs_breakpoint = True
    _DIV_OPS = {"__floordiv__", "SDiv", "__mod__", "SMod"}   # UDiv / SDiv / URem / SMod

    def __init__(self, spec, ctx):
        super().__init__(spec, ctx)
        self.addr = spec.get("addr")

    def install(self, state):
        state.inspect.b("expr", when=angr.BP_AFTER, action=self._on_expr)

    def _on_expr(self, state):
        if self.ctx.is_cancelled():
            return
        insp = state.inspect
        r = insp.attrs.expr_result if hasattr(insp, "attrs") else insp.expr_result
        if not isinstance(r, claripy.ast.BV):
            return
        # Find the division node. Its position in the result varies by arch: a clean top
        # op on arm64 (SDiv), nested under an If on a trapping model, or under an Extract
        # on x86 (idiv is 64/32->32, so the quotient is Extract(31:0, sext(n) /s sext(d))).
        # Bounded DFS through the wrapper ops that can sit above a division.
        _WRAP = {"If", "Extract", "Concat", "SignExt", "ZeroExt", "__add__", "__sub__"}
        divnode = None
        stack, seen = [(r, 0)], 0
        while stack and seen < 40:
            node, depth = stack.pop(); seen += 1
            if not isinstance(node, claripy.ast.BV):
                continue
            if node.op in self._DIV_OPS and len(node.args) >= 2 \
                    and isinstance(node.args[1], claripy.ast.BV) and node.args[1].symbolic:
                divnode = node
                break
            if depth < 5 and node.op in _WRAP:
                stack.extend((a, depth + 1) for a in node.args)
        if divnode is None:
            return
        divisor = divnode.args[1]
        ins_addr = state.scratch.ins_addr
        if ins_addr is None:
            return
        if self.addr is not None:
            if ins_addr != self.addr:
                return
        elif not self.ctx.in_target_function(ins_addr):
            return
        # angr executes a division by ASSUMING the divisor is non-zero: it adds a
        # `divisor != 0` constraint to the path, silently PRUNING the div-by-zero case.
        # So the state we see already forbids it. Test `divisor == 0` against the path
        # constraints MINUS that auto-added guard, and build the witness from that relaxed
        # solver (the state's own solver can't produce divisor==0).
        cond = divisor == 0
        guard = divisor != 0
        try:
            # Drop the auto-added divisor-nonzero guard by LOGICAL equivalence, not by
            # identity: angr stores it simplified (e.g. `b != 5`) while our guard is
            # `(b-5) != 0` — same meaning, different AST. A constraint is the guard iff it
            # is equivalent to `divisor != 0` (their XOR is unsatisfiable).
            others = []
            for c in state.solver.constraints:
                try:
                    is_guard = not claripy.Solver().satisfiable(extra_constraints=[c != guard])
                except Exception:
                    is_guard = (c.cache_key == guard.cache_key)
                if not is_guard:
                    others.append(c)
            relaxed = claripy.Solver()
            if others:
                relaxed.add(others)
            if not relaxed.satisfiable(extra_constraints=[cond]):
                return
        except Exception:
            return
        witness = {}
        try:
            relaxed.add(cond)
            for nm, ast in (state.globals.get("angrgui_vars") or {}).items():
                if isinstance(ast, claripy.ast.Base) and getattr(ast, "symbolic", False):
                    witness[nm] = _fmt(relaxed.eval(ast, 1)[0], ast.size())
        except Exception:
            pass
        self._record(state, ins_addr, f"division by zero at {hex(ins_addr)}: the divisor can be 0",
                     witness, extra={"src_line": self.ctx.line_for(ins_addr), "path": self.ctx.path_of(state)},
                     dedup_key=(ins_addr,), trigger=divisor)


CHECK_TYPES = {
    "int_overflow": IntOverflowCheck,
    "div_by_zero": DivByZeroCheck,
    "narrowing_cast": NarrowingCastCheck,
    "float_anomaly": FloatAnomalyCheck,
    "oob_write": BufferBoundsCheck,
    "oob_read": BufferBoundsCheck,
    "null_deref": NullDerefCheck,
    "assert": AssertCheck,
    "reach": ReachCheck,
    "avoid": AvoidCheck,
    "custom": CustomCheck,
}


def build_check(spec: dict, ctx: "CheckContext") -> BaseCheck:
    cls = CHECK_TYPES.get(spec["kind"])
    if cls is None:
        raise ValueError(f"unknown check kind {spec['kind']!r}")
    return cls(spec, ctx)


@dataclass
class CheckContext:
    """Shared services the checks need from the runner."""
    target_func_lo: int
    target_func_hi: int
    return_addrs: list
    line_for: Callable[[int], Any]
    path_of: Callable
    on_hit: Callable[[Hit, Any], None]   # (hit, state it was found on)
    block_head: Callable[[int], int]
    cancelled: Callable[[], bool] = None  # True once the user asked to cancel the run

    def in_target_function(self, addr: int) -> bool:
        return self.target_func_lo <= addr < self.target_func_hi

    def is_cancelled(self) -> bool:
        try:
            return bool(self.cancelled and self.cancelled())
        except Exception:
            return False
