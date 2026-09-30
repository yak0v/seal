"""
Turn a function's setup (initial state + assumptions + checks + limits) into a
standalone angr script that does the same thing the GUI's runner does, so you
can see what your clicks mean in angr terms, copy it, and extend it.

Expressions from the mini-language (assumptions, asserts) are compiled to the
equivalent claripy code by running the same parser with a code-emitting backend.
"""
from __future__ import annotations

import keyword
import os
import re

from .exprlang import ExprError, Parser, _truth

ARITH_MNEMONICS = ("add", "adc", "sub", "sbb", "imul", "mul", "inc", "dec", "neg", "lea")
RESERVED = {"angr", "claripy", "time", "sys", "os", "project", "cfg", "state", "simgr", "report",
            "findings", "INPUTS", "STDIN", "FUNC", "FUNC_END", "RETURN_ADDR", "BLOCK_CHECKS", "overflows", "api"}


# --------------------------------------------------------------------------- expressions
class Code:
    """A fragment of Python source that evaluates to a claripy value.

    bits: width of the bit-vector, or None for a Bool."""

    def __init__(self, src: str, bits: int | None, atom: bool = True):
        self.src, self.bits, self.atom = src, bits, atom

    def w(self) -> str:
        return self.src if self.atom else f"({self.src})"


def lit(v: int) -> str:
    if isinstance(v, bool):
        return str(v)
    return str(v) if -10 < v < 10 else ("-" + hex(-v) if v < 0 else hex(v))


_PY_CMP = {"<": "claripy.ULT", "<=": "claripy.ULE", ">": "claripy.UGT", ">=": "claripy.UGE",
           "s<": "claripy.SLT", "s<=": "claripy.SLE", "s>": "claripy.SGT", "s>=": "claripy.SGE"}


def _truth_code(x):
    if isinstance(x, Code):
        return x if x.bits is None else Code(f"{x.w()} != 0", None, False)
    return Code(f"claripy.BoolV({bool(x)})", None)


def _match_code(a, b, signed=False):
    """Same width rules as exprlang._match: ints adopt the other side's width (claripy
    does that when it coerces a Python int), narrower bit-vectors are extended."""
    if not isinstance(a, Code) or not isinstance(b, Code):
        return a, b
    if a.bits is None or b.bits is None:
        return a, b
    ext = "sign_extend" if signed else "zero_extend"
    if a.bits < b.bits:
        a = Code(f"{a.w()}.{ext}({b.bits - a.bits})", b.bits)
    elif b.bits < a.bits:
        b = Code(f"{b.w()}.{ext}({a.bits - b.bits})", a.bits)
    return a, b


def _operand(x) -> str:
    return x.w() if isinstance(x, Code) else lit(x)


class CodeOps:
    """exprlang operator semantics, emitting Python source instead of building ASTs."""

    def or_(self, a, b):
        return Code(f"claripy.Or({_truth_code(a).src}, {_truth_code(b).src})", None)

    def and_(self, a, b):
        return Code(f"claripy.And({_truth_code(a).src}, {_truth_code(b).src})", None)

    def not_(self, a):
        return Code(f"claripy.Not({_truth_code(a).src})", None)

    def cmp(self, op, a, b):
        if not isinstance(a, Code) and not isinstance(b, Code):
            return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b, "==": a == b, "!=": a != b}[op.lstrip("s")]
        a, b = _match_code(a, b, op.startswith("s"))
        if op in ("==", "!="):
            return Code(f"{_operand(a)} {op} {_operand(b)}", None, False)
        return Code(f"{_PY_CMP[op]}({_operand(a)}, {_operand(b)})", None)

    def binop(self, op, a, b):
        if not isinstance(a, Code) and not isinstance(b, Code):
            from .exprlang import _BINOPS
            return _BINOPS[op](a, b)
        a, b = _match_code(a, b)
        bits = a.bits if isinstance(a, Code) else b.bits
        if op == ">>":
            return Code(f"claripy.LShR({_operand(a)}, {_operand(b)})", bits)
        return Code(f"{_operand(a)} {op} {_operand(b)}", bits, False)

    def neg(self, a):
        return Code(f"-{_operand(a)}", a.bits) if isinstance(a, Code) else -a

    def inv(self, a):
        return Code(f"~{_operand(a)}", a.bits) if isinstance(a, Code) else ~a


class ExprCompiler:
    """Compiles mini-language strings to claripy source over a variable called `state`."""

    def __init__(self, arch, variables: dict[str, Code], locals_: dict[str, dict], argv=None):
        self.arch = arch
        self.variables = variables
        self.locals = locals_
        self.argv = argv or []
        self.bp = arch.register_names.get(arch.bp_offset) if hasattr(arch, "bp_offset") else None

    def _resolve(self, name: str) -> Code:
        arch = self.arch
        if name in self.variables:
            return self.variables[name]
        m = re.fullmatch(r"arg(\d+)", name)
        if m and int(m.group(1)) < len(self.argv) and self.argv[int(m.group(1))] is not None:
            return self.argv[int(m.group(1))]
        m = re.fullmatch(r"a(\d+)", name)
        if m and 1 <= int(m.group(1)) <= len(self.argv) and self.argv[int(m.group(1)) - 1] is not None:
            return self.argv[int(m.group(1)) - 1]
        if name in self.locals and self.bp:
            off, size = self.locals[name]["offset"], self.locals[name]["size"]
            sign = "-" if off < 0 else "+"
            return Code(f"state.memory.load(state.regs.{self.bp} {sign} {lit(abs(off))}, {size}, "
                        f"endness=state.arch.memory_endness)", size * 8)
        if name == "ret":
            reg = arch.register_names[arch.ret_offset]
            return Code(f"state.regs.{reg}", arch.registers[reg][1] * 8)
        if name in arch.registers:
            return Code(f"state.regs.{name}", arch.registers[name][1] * 8)
        raise ExprError(f"unknown name {name!r}")

    def _funcs(self):
        def bv(x, bits):
            return x if isinstance(x, Code) else Code(f"claripy.BVV({lit(x)}, {bits})", bits)

        def width(bits, signed):
            def f(x):
                x = bv(x, bits)
                if x.bits > bits:
                    return Code(f"{x.w()}[{bits - 1}:0]", bits)
                if x.bits < bits:
                    return Code(f"{x.w()}.{'sign' if signed else 'zero'}_extend({bits - x.bits})", bits)
                return x
            return f

        def ext(kind):
            def f(x, n):
                if isinstance(n, Code):
                    raise ExprError(f"{kind}ext() width must be a number")
                x = bv(x, 64)
                return Code(f"{x.w()}.{'zero' if kind == 'z' else 'sign'}_extend({n})", x.bits + n)
            return f

        def mem(addr, size=8):
            if isinstance(size, Code):
                raise ExprError("memory load size must be a number")
            return Code(f"state.memory.load({_operand(addr)}, {size}, endness=state.arch.memory_endness)",
                        size * 8)

        def bvv(v, n):
            if isinstance(v, Code) or isinstance(n, Code):
                raise ExprError("bv(value, bits) takes numbers")
            return Code(f"claripy.BVV({lit(v)}, {n})", n)

        funcs = {"mem": mem, "zext": ext("z"), "sext": ext("s"), "bv": bvv}
        for b in (8, 16, 32, 64):
            funcs[f"u{b}"] = width(b, False)
            funcs[f"s{b}"] = width(b, True)
        return funcs

    def value(self, src: str) -> str:
        e = Parser(src, self._resolve, self._funcs(), CodeOps()).parse()
        if not isinstance(e, Code):
            return f"claripy.BVV({lit(int(e))}, 64)"
        return e.src

    def boolean(self, src: str) -> str:
        e = Parser(src, self._resolve, self._funcs(), CodeOps()).parse()
        if not isinstance(e, Code):
            return _truth_code(bool(e)).src
        return _truth_code(e).src


# --------------------------------------------------------------------------- script
def _pyname(name: str, taken: set) -> str:
    n = re.sub(r"\W", "_", name) or "arg"
    if n[0].isdigit():
        n = "_" + n
    if keyword.iskeyword(n) or n in RESERVED:
        n += "_"
    while n in taken:
        n += "_"
    taken.add(n)
    return n


def _c_type(size: int, signed: bool) -> str:
    base = {1: "char", 2: "short", 4: "int", 8: "long long"}.get(size, "long long")
    return base if signed else f"unsigned {base}"


def _where(binary, addr) -> str:
    src = binary.source_at(addr)
    if not src:
        return f"{addr:#x}"
    text = re.sub(r"\s*(/\*.*?\*/|//.*)$", "", src.get("text") or "").strip()
    return f"{addr:#x} ({src['file']}:{src['line']}" + (f": {text}" if text else "") + ")"


def _indent(code: str, n: int) -> str:
    return "\n".join((" " * n + ln) if ln.strip() else "" for ln in code.splitlines())


def generate_script(binary, spec: dict) -> str:
    """Python source of a standalone angr script equivalent to one GUI run."""
    arch = binary.arch
    fa = int(spec["func_addr"])
    func = binary.get_function(fa)
    fname = func.name if func is not None else f"sub_{fa:x}"
    fend = fa + ((func.size if func is not None else 0) or 0x1000)
    args = spec.get("args", []) or []
    buffers = {b["arg"]: int(b.get("size", 64)) for b in spec.get("buffers", []) or []}
    stdin = spec.get("stdin") if (spec.get("stdin") or {}).get("mode") == "symbolic" else None
    checks = [c for c in spec.get("checks", []) or [] if c.get("enabled", True)]
    limits = spec.get("limits", {}) or {}
    max_steps = int(limits.get("steps", 200))
    max_active = int(limits.get("active", 400))
    max_seconds = float(limits.get("seconds", 30))
    loop_bound = int(limits.get("loop_bound", 12) or 0)
    dwarf_types = {v.name: v.type_name for v in binary.dwarf_vars(fa) if v.is_param}

    out: list[str] = []
    emit = out.append
    taken: set = set()
    variables: dict[str, Code] = {}

    emit(f'''#!/usr/bin/env python3
"""
Standalone angr script for {fname}() in {os.path.basename(binary.path)}, generated by
angr bug hunter from the function's setup: initial state, assumptions, checks
and limits. It explores the same paths and reports the same findings as the GUI
(the GUI also records the path tree for display).

    python {fname}_angr.py
"""
import logging
import time

import angr
import claripy

logging.getLogger("angr").setLevel(logging.ERROR)   # hide angr's chatty warnings

BINARY = {binary.path!r}
FUNC = {fa:#x}          # {fname}
FUNC_END = {fend:#x}      # first address past the function

project = angr.Project(BINARY, auto_load_libs=False)
RETURN_ADDR = project.simos.return_deadend   # where a state lands once it returns
''')

    # ------------------------------------------------------------------ initial state
    emit("# " + "=" * 70 + " initial state")
    emit("# Each symbolic input is a fresh bit-vector: the solver may pick any value")
    emit("# for it that satisfies the path's constraints.")
    call_args, proto = [], []
    buf_base = binary.scratch_base()
    buf_lines = []
    input_names = []
    for i, a in enumerate(args):
        uname = a.get("name") or f"arg{i}"
        size = int(a.get("size") or arch.bytes)
        bits = size * 8
        signed = bool(a.get("signed", True))
        py = _pyname(uname, taken)
        ctype = dwarf_types.get(uname)
        if uname in buffers:
            n = buffers[uname]
            bpy = _pyname(uname + "_buf", taken)
            emit(f"{bpy} = claripy.BVS({(uname + '_buf')!r}, {n} * 8)   # the {n} bytes `{uname}` points at")
            emit(f"{py} = claripy.BVV({buf_base:#x}, {arch.bits})   # `{uname}`: pointer to {bpy}")
            buf_lines.append(f"state.memory.store({py}, {bpy})   # byte 0 of {bpy} goes to the lowest address")
            buf_base += (n + 0xfff) & ~0xfff
            variables[uname] = Code(py, arch.bits)
            variables[uname + "_buf"] = Code(bpy, n * 8)
            input_names.append((uname + "_buf", bpy))
            proto.append("void *")
        elif a.get("mode") == "concrete":
            val = int(a.get("value", 0)) & ((1 << bits) - 1)
            emit(f"{py} = claripy.BVV({lit(val)}, {bits})   # `{uname}`, fixed value" + (f" ({ctype})" if ctype else ""))
            variables[uname] = Code(py, bits)
            proto.append(_c_type(size, signed))
        else:
            emit(f"{py} = claripy.BVS({uname!r}, {bits})   # `{uname}`, symbolic "
                 f"{'signed' if signed else 'unsigned'} {bits}-bit" + (f" ({ctype})" if ctype else ""))
            variables[uname] = Code(py, bits)
            input_names.append((uname, py))
            proto.append(_c_type(size, signed))
        call_args.append(py)
    if stdin:
        n = int(stdin.get("size", 16))
        emit(f"STDIN = claripy.BVS('stdin', {n} * 8)   # symbolic stdin, {n} bytes")
        variables["stdin"] = Code("STDIN", n * 8)
    else:
        emit("STDIN = None")
    emit("INPUTS = {" + ", ".join(f"{u!r}: {p}" for u, p in input_names) + "}   # reported with every finding")
    emit("")
    emit("# Start executing at FUNC as if it had been called with these arguments")
    emit("# (placed in registers / on the stack per the calling convention).")
    emit("# Registers and memory nobody initialised read as zero instead of fresh symbols.")
    emit("state = project.factory.call_state(")
    emit(f"    FUNC{''.join(', ' + c for c in call_args)},")
    emit(f"    prototype={('long long f(' + (', '.join(proto) or 'void') + ')')!r},")
    if stdin:
        emit("    stdin=angr.SimFileStream(name='stdin', content=STDIN, has_end=True),")
    _opts = ["angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS",
             "angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY"]
    if limits.get("skip_calls"):
        _opts.append("angr.options.CALLLESS")   # skip calls: each returns an unconstrained value
    emit("    add_options={" + ", ".join(_opts) + "},")
    emit(")")
    for ln in buf_lines:
        emit(ln)

    locals_ = {}
    for v in binary.dwarf_vars(fa):
        if v.sort == "stack":
            locals_[v.name] = {"offset": v.frame_offset(arch.bytes), "size": v.size or arch.bytes}
    argv = [variables.get(a.get("name") or f"arg{i}") for i, a in enumerate(args)]
    comp = ExprCompiler(arch, variables, locals_, argv)

    assumptions = [x.strip() for x in spec.get("assumptions", []) or [] if x.strip()]
    if assumptions:
        emit("")
        emit("# Assumptions: constraints every explored path must satisfy.")
        for src in assumptions:
            try:
                emit(f"state.add_constraints({comp.boolean(src)})   # {src}")
            except ExprError as e:
                emit(f"# could not translate assumption {src!r}: {e}")

    # ------------------------------------------------------------------ checks
    emit("")
    emit("# " + "=" * 70 + " checks")
    emit('''findings, _seen = [], set()


def report(check_id, addr, message, state, extra_constraints=()):
    """Record a finding once, with concrete inputs that make it happen."""
    if (check_id, addr, message) in _seen:
        return
    _seen.add((check_id, addr, message))
    s = state.copy()
    s.add_constraints(*extra_constraints)
    witness = {}
    if s.solver.satisfiable():
        witness = {name: s.solver.eval(v) for name, v in INPUTS.items() if v.symbolic}
        if STDIN is not None:
            witness["stdin"] = s.solver.eval(STDIN, cast_to=bytes)
        elif s.posix.dumps(0):
            witness["stdin"] = s.posix.dumps(0)   # angr's default stdin, as far as it was read
    findings.append({"check": check_id, "addr": addr, "message": message, "inputs": witness})
    shown = ", ".join(f"{k}={v:#x}" if isinstance(v, int) else f"{k}={v!r}" for k, v in witness.items())
    print(f"[{check_id}] {addr:#x}: {message}\\n      inputs: {shown}")
''')
    block_checks = []
    expr_attr = "state.inspect.expr_result"
    try:
        from angr.state_plugins.inspect import SimInspector
        if hasattr(SimInspector(), "attrs"):
            expr_attr = "state.inspect.attrs.expr_result"
    except Exception:
        pass

    if any(c["kind"] == "int_overflow" for c in checks):
        emit('''
OVERFLOW_OPS = {"__add__": "+", "__sub__": "-", "__mul__": "*"}
ARITH_MNEMONICS = {''' + ", ".join(repr(m) for m in ARITH_MNEMONICS) + '''}


def overflows(op, a, b, signed):
    """Bool AST: the N-bit `a op b` differs from the exact result computed at 2N bits."""
    n = a.size()
    ext = (lambda x: x.sign_extend(n)) if signed else (lambda x: x.zero_extend(n))
    wide = {"__add__": ext(a) + ext(b), "__sub__": ext(a) - ext(b), "__mul__": ext(a) * ext(b)}[op]
    narrow = {"__add__": a + b, "__sub__": a - b, "__mul__": a * b}[op]
    return wide != ext(narrow)
''')

    for c in checks:
        label = str(c.get("id", "check"))            # shown in reports
        cid = _pyname(label, set())                   # used in Python identifiers
        title = c.get("name") or c["kind"]
        kind = c["kind"]
        addr = c.get("addr")
        emit("")
        if kind == "int_overflow":
            modes = {"signed": [("signed", True)], "unsigned": [("unsigned", False)]}.get(
                c.get("signed", "either"), [("unsigned", False), ("signed", True)])
            where = f"the instruction at {_where(binary, int(addr))}" if addr is not None else \
                "every add/sub/mul instruction in the function"
            emit(f"# [{label}] {title}: can {where} overflow?")
            emit("# angr calls this after it evaluates each VEX expression. An add/sub/mul")
            emit("# result is an AST holding its two operands, so we ask the solver whether")
            emit("# those operands can overflow on the current path.")
            emit(f"def check_{cid}(state):")
            emit("    ins = state.scratch.ins_addr")
            if addr is not None:
                emit(f"    if ins != {int(addr):#x}:")
                emit("        return")
            else:
                emit("    if ins is None or not FUNC <= ins < FUNC_END:")
                emit("        return")
            emit(f"    r = {expr_attr}")
            emit("    if r is None or r.op not in OVERFLOW_OPS or len(r.args) != 2:")
            emit("        return")
            emit("    a, b = r.args")
            emit("    if a.size() != r.size() or b.size() != r.size() or not (a.symbolic or b.symbolic):")
            emit("        return   # widening multiply (can't overflow) or constant")
            if addr is None:
                emit("    insn = project.factory.block(ins, num_inst=1).capstone.insns[0]")
                emit("    if insn.mnemonic not in ARITH_MNEMONICS:")
                emit("        return   # address arithmetic inside a load/store, not real math")
            emit(f"    for kind, signed in {modes!r}:")
            emit("        cond = overflows(r.op, a, b, signed)")
            emit("        if state.solver.satisfiable(extra_constraints=[cond]):")
            emit('            report(' + repr(label) + ', ins, f"{kind} overflow in {OVERFLOW_OPS[r.op]}", state, [cond])')
            emit("")
            emit("")
            emit(f"state.inspect.b('expr', when=angr.BP_AFTER, action=check_{cid})")
            continue

        # block-boundary checks: run on every new state after each step, where
        # register and memory values are committed
        if kind == "assert":
            at_return = bool(c.get("at_return"))
            if at_return:
                where = "the point the function returns"
            elif addr is not None:
                where = _where(binary, binary.block_head(int(addr)))
            else:
                where = "every block of the function"
            expr = c.get("expr", "")
            emit(f"# [{label}] {title}: can `{expr}` be FALSE at {where}?")
            try:
                cond = comp.boolean(expr)
            except ExprError as e:
                emit(f"# could not translate {expr!r}: {e}")
                continue
            emit(f"def check_{cid}(state):")
            if at_return:
                # gate on the state having returned: the return value may be set inside
                # the return block, so it is only final once state.addr is RETURN_ADDR
                emit("    if state.addr != RETURN_ADDR:")
            elif addr is not None:
                emit(f"    if state.addr != {binary.block_head(int(addr)):#x}:")
            else:
                emit("    if not FUNC <= state.addr < FUNC_END:")
            emit("        return")
            emit(f"    holds = {cond}")
            emit("    if state.solver.satisfiable(extra_constraints=[claripy.Not(holds)]):")
            emit(f"        report({label!r}, state.addr, {('assert can be false: ' + expr)!r}, state, [claripy.Not(holds)])")
        elif kind in ("reach", "avoid"):
            verb = "reached" if kind == "reach" else "hit avoided address"
            emit(f"# [{label}] {title}: does any path get to {_where(binary, int(addr))}"
                 + (f" ({binary.name_at(int(addr))})" if binary.name_at(int(addr)) else "") + "?")
            emit(f"def check_{cid}(state):")
            emit(f"    if state.addr == {int(addr):#x}:")
            emit(f"        report({label!r}, state.addr, {(verb + ' ' + hex(int(addr)))!r}, state)")
        elif kind == "custom":
            points = [binary.block_head(int(addr))] if addr is not None else None
            where = _where(binary, points[0]) if points else "every block of the function"
            code = c.get("code", "")
            renamed = re.sub(r"^def\s+check\s*\(", f"def custom_{cid}(", code, count=1, flags=re.M)
            emit(f"# [{label}] {title}: your Python check, run at {where}")
            emit(renamed.rstrip())
            emit("")
            emit("")
            emit(f"def check_{cid}(state):")
            if points is None:
                emit("    if not FUNC <= state.addr < FUNC_END:")
            else:
                emit(f"    if state.addr != {points[0]:#x}:")
            emit("        return")
            emit("    api = Api(state)")
            emit(f"    res = custom_{cid}(state, api)")
            emit("    if res:")
            emit(f"        report({label!r}, res.get('addr', state.addr), res.get('message', 'custom hit'), state)")
        else:
            emit(f"# [{label}] unknown check kind {kind!r}, skipped")
            continue
        block_checks.append(f"check_{cid}")
        emit("")

    if any(c["kind"] == "custom" for c in checks):
        locals_repr = "{" + ", ".join(f"{k!r}: {v!r}" for k, v in locals_.items()) + "}"
        emit('''

class Api:
    """The `api` object custom checks receive. eval() uses angr bug hunter's
    expression language, so this part needs the angrgui package importable."""

    def __init__(self, state):
        import sys
        sys.path.insert(0, ''' + repr(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) + ''')
        state.globals["angrgui_vars"] = {''' + ", ".join(f"{u!r}: {c.src}" for u, c in variables.items()) + '''}
        state.globals["angrgui_locals"] = ''' + locals_repr + '''
        self.state = state

    def eval(self, expr):
        from angrgui.exprlang import make_evaluator
        return make_evaluator(self.state)(expr)

    def sat(self, cond):
        return self.state.solver.satisfiable(extra_constraints=[cond])

    def witness(self, cond=None):
        s = self.state.copy()
        if cond is not None:
            s.add_constraints(cond)
        return {k: s.solver.eval(v) for k, v in INPUTS.items()} if s.solver.satisfiable() else {}

    def reg(self, name):
        return getattr(self.state.regs, name)

    def mem(self, addr, size=8):
        return self.state.memory.load(addr, size, endness=self.state.arch.memory_endness)
''')

    emit("")
    emit("BLOCK_CHECKS = [" + ", ".join(block_checks) + "]   # run on each new state after every step")

    # ------------------------------------------------------------------ explore
    emit("")
    emit("# " + "=" * 70 + " explore")
    emit("simgr = project.factory.simgr(state, save_unconstrained=True)")
    if loop_bound > 0:
        emit(f"# Stop a path once a loop in FUNC has run {loop_bound} times, so a loop whose")
        emit("# trip count depends on the inputs can't unroll forever ('spinning' stash).")
        emit("cfg = project.analyses.CFGFast(normalize=True, data_references=False)")
        emit("simgr.use_technique(angr.exploration_techniques.LoopSeer(")
        emit(f"    cfg=cfg, functions=[cfg.kb.functions[FUNC]], bound={loop_bound}, limit_concrete_loops=False))")
    emit(f'''
MAX_STEPS, MAX_ACTIVE, MAX_SECONDS = {max_steps}, {max_active}, {max_seconds:g}
seen = set()


def new_states():
    """States the last step produced: the active ones plus paths that just ended."""
    fresh = list(simgr.active)
    for stash in ("deadended", "unconstrained", "spinning", "errored"):
        for s in simgr.stashes.get(stash, []):
            s = getattr(s, "state", s)          # errored entries wrap their state
            if id(s) not in seen:
                seen.add(id(s))
                fresh.append(s)
    return fresh


start, step = time.time(), 0
while simgr.active and step < MAX_STEPS and time.time() - start < MAX_SECONDS:
    simgr.step()          # every active state executes one basic block; branches split it
    step += 1
    for s in new_states():
        for check in BLOCK_CHECKS:
            check(s)
    if len(simgr.active) > MAX_ACTIVE:
        simgr.active[:] = simgr.active[:MAX_ACTIVE]   # drop the excess to keep the search bounded

print(f"\\n{{step}} steps in {{time.time() - start:.1f}}s: "
      f"{{len(simgr.deadended)}} paths ended, {{len(simgr.active)}} still active, "
      f"{{len(simgr.stashes.get('spinning', []))}} stopped by the loop bound, "
      f"{{len(simgr.unconstrained)}} unconstrained, {{len(simgr.errored)}} errored")
print(f"{{len(findings)}} finding(s)")
''')
    return "\n".join(out)
