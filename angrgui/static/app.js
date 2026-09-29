"use strict";
// ------------------------------------------------------------------ tiny helpers
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const el = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else if (k === "html") e.innerHTML = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) e.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid !== null && kid !== undefined)
    e.append(kid.nodeType ? kid : document.createTextNode(kid));
  return e;
};
const hx = (n) => "0x" + (n >>> 0).toString(16);
const hx64 = (n) => "0x" + BigInt(n).toString(16);

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).detail || msg; } catch (e) {}
    throw new Error(msg);
  }
  return r.json();
}
const jpost = (p, body) => api(p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
const jput = (p, body) => api(p, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

function toast(msg, bad) {
  const t = el("div", { class: "toast" + (bad ? " bad" : "") }, msg);
  $("#toastHost").append(t);
  setTimeout(() => t.remove(), 3200);
}

// ------------------------------------------------------------------ app state
const A = {
  binary: null,
  functions: [],
  fn: null,          // selected function {addr,name,...}
  detail: null,      // /api/function response
  config: null,      // editable per-function config
  run: null,         // {id, snapshot}
  pollTimer: null,
  selectedHit: null,
  cfgCache: {},
};

// ==================================================================== boot
window.addEventListener("DOMContentLoaded", init);

async function init() {
  $("#openBtn").addEventListener("click", openBrowser);
  $("#fnSearch").addEventListener("input", renderFunctions);
  $("#onlyNamed").addEventListener("change", renderFunctions);
  $$(".tab").forEach(t => t.addEventListener("click", () => selectTab(t.dataset.tab)));
  await refreshState();
}

async function refreshState() {
  const s = await api("/api/state");
  if (s.loaded) {
    A.binary = s.binary;
    $("#binfo").textContent = `${s.binary.name}  ·  ${s.binary.arch}  ·  ${s.binary.function_count} funcs` +
      (s.binary.has_dwarf ? "  ·  DWARF" : "  ·  no debug info");
    $("#hint").textContent = "Pick a function → set up its state → add checks → Run.";
    await loadFunctions();
  } else {
    $("#binfo").textContent = "no binary loaded";
    openBrowser();
  }
}

// ==================================================================== file browser
async function openBrowser(startPath) {
  let cwd = startPath || "";
  const host = $("#modalHost");
  const listBox = el("div", { style: "min-height:320px" });
  const cwdLabel = el("div", { class: "mono faint", style: "margin-bottom:8px;word-break:break-all" });

  async function go(path) {
    let data;
    try { data = await api("/api/browse?path=" + encodeURIComponent(path || "")); }
    catch (e) { toast(e.message, true); return; }
    cwd = data.cwd;
    cwdLabel.textContent = data.cwd;
    listBox.replaceChildren();
    listBox.append(row("📁", "..", () => go(data.parent), false));
    for (const en of data.entries) {
      if (en.dir) listBox.append(row("📁", en.name, () => go(en.path), false));
    }
    for (const en of data.entries) {
      if (!en.dir) listBox.append(row(en.elf ? "🎯" : "📄", en.name,
        en.elf ? () => doLoad(en.path) : null, en.elf, en.size));
    }
  }
  function row(icon, name, onclick, isElf, size) {
    const r = el("div", { class: "fbrow" + (isElf ? " elf" : "") },
      el("span", { class: "ic" }, icon), el("span", { class: "grow" }, name),
      size ? el("span", { class: "faint" }, fmtSize(size)) : null);
    if (onclick) r.addEventListener("click", onclick);
    else r.style.opacity = ".5";
    return r;
  }
  async function doLoad(path) {
    m.remove();
    const busy = modal("Loading", el("div", { class: "col", style: "gap:10px" },
      el("div", {}, "Analyzing ", el("b", {}, path.split("/").pop())),
      el("div", { class: "prog" }, el("i", { style: "width:60%" })),
      el("div", { class: "faint mono", id: "loadMsg" }, "starting…")), []);
    const poll = setInterval(async () => {
      try { const s = await api("/api/state"); if (s.load_status?.message) $("#loadMsg").textContent = s.load_status.message; } catch (e) {}
    }, 400);
    try {
      await jpost("/api/load", { path });
      clearInterval(poll); busy.remove();
      A.fn = A.detail = A.config = A.run = null;
      await refreshState();
      toast("Loaded " + path.split("/").pop());
    } catch (e) { clearInterval(poll); busy.remove(); toast("Load failed: " + e.message, true); }
  }
  const m = modal("Open ELF binary", el("div", {}, cwdLabel, listBox),
    [el("button", { onclick: () => m.remove() }, "Cancel")]);
  host.append(m);
  go(cwd);
}
const fmtSize = (n) => n > 1e6 ? (n / 1e6).toFixed(1) + "M" : n > 1e3 ? (n / 1e3).toFixed(1) + "K" : n + "B";

// ==================================================================== functions list
async function loadFunctions() {
  const r = await api("/api/functions");
  A.functions = r.functions;
  $("#fnCount").textContent = r.functions.length;
  renderFunctions();
}
function renderFunctions() {
  const q = $("#fnSearch").value.toLowerCase();
  const onlyNamed = $("#onlyNamed").checked;
  const box = $("#fnList"); box.replaceChildren();
  const list = A.functions.filter(f =>
    (!onlyNamed || f.named) && (!q || f.name.toLowerCase().includes(q) || hx64(f.addr).includes(q)));
  if (!list.length) { box.append(el("div", { class: "empty" }, "No matching functions.")); return; }
  for (const f of list) {
    const node = el("div", { class: "fn" + (f.named ? "" : " unnamed") + (A.fn && A.fn.addr === f.addr ? " sel" : "") },
      el("div", { class: "nm" }, f.name),
      el("div", { class: "sub" },
        el("span", {}, hx64(f.addr)),
        el("span", {}, f.block_count + " blk"),
        f.args.length ? el("span", {}, f.args.length + " arg") : null,
        f.check_count ? el("span", { class: "pill ok" }, f.check_count + " ✓") : null,
        f.has_source ? el("span", { class: "pill info" }, "src") : null));
    node.addEventListener("click", () => selectFunction(f));
    box.append(node);
  }
}

// ==================================================================== select function
async function selectFunction(f) {
  A.fn = f; A.run = null; A.selectedHit = null;
  stopPolling();
  renderFunctions();
  $("#pane-code").innerHTML = '<div class="empty">Loading…</div>';
  const d = await api("/api/function/" + f.addr);
  A.detail = d;
  A.config = normalizeConfig(d.config, d);
  renderCode();
  renderRight();
  renderCFG();
  selectTab("code");
  $("#pane-paths").innerHTML = '<div class="empty">Run a check to see the paths angr explored.</div>';
}

function normalizeConfig(cfg, d) {
  cfg = cfg || {};
  cfg.args = cfg.args || [];
  cfg.buffers = cfg.buffers || [];
  cfg.assumptions = cfg.assumptions || [];
  cfg.checks = cfg.checks || [];
  cfg.stdin = cfg.stdin || null;
  cfg.limits = Object.assign({ steps: 150, active: 300, seconds: 30, loop_bound: 12, find: null, avoid: [] }, cfg.limits || {});
  return cfg;
}

async function saveConfig() {
  if (!A.fn) return;
  try { await jput(`/api/function/${A.fn.addr}/config`, A.config); }
  catch (e) { toast("save failed: " + e.message, true); }
  const f = A.functions.find(x => x.addr === A.fn.addr);
  if (f) { f.check_count = A.config.checks.length; f.configured = true; renderFunctions(); }
}

function selectTab(name) {
  $$(".tab").forEach(t => t.classList.toggle("sel", t.dataset.tab === name));
  $$(".tabpane").forEach(p => p.classList.toggle("sel", p.id === "pane-" + name));
  if (name === "cfg") renderCFG();
}

// ==================================================================== code view
function renderCode() {
  const d = A.detail, di = d.disasm;
  const pane = $("#pane-code"); pane.replaceChildren();
  const wrap = el("div", { class: "codewrap" });

  // source strip (if available)
  if (di.source && di.source.available) {
    const sc = el("div", { style: "border-bottom:1px solid var(--line);padding-bottom:6px;margin-bottom:6px" });
    sc.append(el("div", { class: "blocklabel" }, "source · " + di.source.file));
    for (const r of di.source.rows) {
      const line = el("div", { class: "srcline" + (r.addr ? " has" : "") },
        el("span", { class: "ln" }, String(r.n)),
        el("span", { class: "tx" }, r.text || " "));
      if (r.addr) { line.dataset.addr = r.addr; line.title = "maps to " + hx64(r.addr); }
      sc.append(line);
    }
    wrap.append(sc);
  }

  // disassembly grouped by block
  let curBlock = null;
  for (const ins of di.instructions) {
    if (ins.block !== curBlock) {
      curBlock = ins.block;
      wrap.append(el("div", { class: "blocklabel" }, "block " + hx64(curBlock)));
    }
    const acts = el("span", { class: "acts" });
    if (ins.arith) acts.append(btn("+ overflow", () => addOverflowCheck(ins), "primary tiny"));
    acts.append(btn("assert", () => openAssertModal(ins.addr), "tiny"));
    acts.append(btn("reach", () => addReachCheck(ins.addr, "reach"), "tiny"));
    acts.append(btn("⋯", () => openInsnMenu(ins), "tiny ghost"));

    const row = el("div", { class: "insn" + (ins.arith ? " arith" : ""), "data-addr": ins.addr },
      el("span", { class: "ad" }, hx64(ins.addr)),
      el("span", { class: "mn" }, ins.mnemonic),
      el("span", { class: "op" }, ins.op_str + (ins.is_call && di.call_targets[ins.addr] ? "   ; " + (di.call_targets[ins.addr].name || "") : "")),
      ins.src_line ? el("span", { class: "faint", style: "flex:0 0 auto;margin-right:6px" }, ":" + ins.src_line) : null,
      acts);
    wrap.append(row);
  }
  pane.append(wrap);
  highlightHits();
}
const btn = (label, on, cls) => el("button", { class: cls || "tiny", onclick: (e) => { e.stopPropagation(); on(); } }, label);

function openInsnMenu(ins) {
  const host = $("#modalHost");
  const m = modal("At " + hx64(ins.addr) + "  " + ins.mnemonic + " " + ins.op_str,
    el("div", { class: "col", style: "gap:8px" },
      ins.arith ? menuItem("Integer-overflow check here", "flag this add/sub/mul as possibly wrapping", () => { m.remove(); addOverflowCheck(ins); }) : null,
      menuItem("Assert an invariant here", "a boolean that should always hold at this point", () => { m.remove(); openAssertModal(ins.addr); }),
      menuItem("Reach check", "record any path that reaches this address", () => { m.remove(); addReachCheck(ins.addr, "reach"); }),
      menuItem("Avoid check", "record (and mark) paths that reach this address", () => { m.remove(); addReachCheck(ins.addr, "avoid"); }),
      menuItem("Custom Python check here", "run your own predicate at this point", () => { m.remove(); openCustomModal(ins.addr); })),
    [el("button", { onclick: () => m.remove() }, "Close")]);
  host.append(m);
}
const menuItem = (title, sub, on) => {
  const r = el("div", { class: "fbrow", style: "flex-direction:column;align-items:flex-start;gap:2px;padding:10px" },
    el("div", { style: "font-weight:600;font-family:var(--sans)" }, title),
    el("div", { class: "faint", style: "font-family:var(--sans)" }, sub));
  r.addEventListener("click", on); return r;
};

// ==================================================================== add checks
function uid() { return Math.random().toString(36).slice(2, 8); }
function addCheck(c) {
  c.id = c.id || uid(); c.enabled = true; c.func_addr = A.fn.addr;
  A.config.checks.push(c);
  saveConfig(); renderRight();
  toast(c.kind + " check added");
}
function addOverflowCheck(ins) {
  addCheck({ kind: "int_overflow", addr: ins.addr, signed: "either",
             name: `overflow @ ${hx64(ins.addr)}`,
             note: ins.mnemonic + " " + ins.op_str + (ins.src_line ? "  (line " + ins.src_line + ")" : "") });
}
function addReachCheck(addr, kind) {
  addCheck({ kind, addr, name: `${kind} ${hx64(addr)}` });
}

// ==================================================================== right panel
function renderRight() {
  $("#rTitle").textContent = A.fn ? A.fn.name : "Setup";
  const body = $("#rBody"); body.replaceChildren();
  if (!A.fn) { body.append(el("div", { class: "empty" }, "Pick a function.")); return; }

  body.append(sectionState());
  body.append(sectionAssumptions());
  body.append(sectionChecks());
  body.append(sectionRun());
  body.append(sectionHits());
}

function sectionState() {
  const s = el("div", { class: "sec" });
  s.append(el("h3", {}, "Initial state", el("span", { class: "grow" }),
    el("span", { class: "faint", style: "text-transform:none;font-weight:400" }, "how each argument starts")));
  const b = el("div", { class: "body" });

  A.config.args.forEach((a, i) => {
    const nameI = el("input", { class: "name", value: a.name || ("arg" + i), oninput: e => { a.name = e.target.value; scheduleSave(); } });
    const modeS = el("select", { onchange: e => { a.mode = e.target.value; renderRight(); scheduleSave(); } });
    ["symbolic", "concrete"].forEach(m => modeS.append(el("option", { value: m, selected: a.mode === m ? "" : null }, m)));
    const sizeS = el("select", { onchange: e => { a.size = +e.target.value; scheduleSave(); } });
    [1, 2, 4, 8].forEach(sz => sizeS.append(el("option", { value: sz, selected: a.size === sz ? "" : null }, sz + "B")));
    let last;
    if (a.mode === "concrete") {
      last = el("input", { value: a.value ?? 0, placeholder: "value", oninput: e => { a.value = parseIntLoose(e.target.value); scheduleSave(); }, style: "width:78px" });
    } else {
      last = el("label", { class: "row", style: "font-size:11px;color:var(--dim);gap:3px" },
        el("input", { type: "checkbox", checked: a.signed ? "" : null, style: "width:auto", onchange: e => { a.signed = e.target.checked; scheduleSave(); } }), "signed");
    }
    b.append(el("div", { class: "arg" }, nameI, modeS, sizeS, last));
    // buffer toggle for pointer-ish args
    const isBuf = A.config.buffers.some(x => x.arg === a.name);
    const bufRow = el("label", { class: "row", style: "font-size:11px;color:var(--faint);margin:-2px 0 8px 2px;gap:4px" },
      el("input", { type: "checkbox", checked: isBuf ? "" : null, style: "width:auto", onchange: e => toggleBuffer(a.name, e.target.checked) }),
      "points at a symbolic buffer",
      isBuf ? el("input", { value: (A.config.buffers.find(x => x.arg === a.name) || {}).size || 64, style: "width:56px;margin-left:4px", oninput: e => { const bb = A.config.buffers.find(x => x.arg === a.name); if (bb) { bb.size = +e.target.value; scheduleSave(); } } }) : null,
      isBuf ? el("span", {}, "bytes") : null);
    b.append(bufRow);
  });

  // stdin
  const stdinOn = !!A.config.stdin;
  b.append(el("label", { class: "row", style: "font-size:12px;margin-top:4px;gap:5px" },
    el("input", { type: "checkbox", checked: stdinOn ? "" : null, style: "width:auto", onchange: e => { A.config.stdin = e.target.checked ? { mode: "symbolic", size: 16 } : null; renderRight(); scheduleSave(); } }),
    "symbolic stdin",
    stdinOn ? el("input", { value: A.config.stdin.size, style: "width:56px", oninput: e => { A.config.stdin.size = +e.target.value; scheduleSave(); } }) : null,
    stdinOn ? el("span", { class: "faint" }, "bytes") : null));
  s.append(b);
  return s;
}
function toggleBuffer(argName, on) {
  A.config.buffers = A.config.buffers.filter(x => x.arg !== argName);
  if (on) A.config.buffers.push({ arg: argName, size: 64 });
  renderRight(); scheduleSave();
}
const parseIntLoose = (v) => { v = (v || "").trim(); if (!v) return 0; return v.startsWith("0x") ? parseInt(v, 16) : parseInt(v, 10) || 0; };

function sectionAssumptions() {
  const s = el("div", { class: "sec" });
  s.append(el("h3", {}, "Assumptions", el("span", { class: "grow" }),
    btn("+ add", () => { A.config.assumptions.push(""); renderRight(); }, "tiny")));
  const b = el("div", { class: "body" });
  if (!A.config.assumptions.length) b.append(el("div", { class: "faint", style: "font-size:11px" }, "Constraints on the initial state, e.g. ", el("code", {}, "count < 0x1000"), " · ", el("code", {}, "size != 0"), " · ", el("code", {}, "arg0 s> 0")));
  A.config.assumptions.forEach((a, i) => {
    b.append(el("div", { class: "assume" },
      el("input", { value: a, placeholder: "expression that must hold", oninput: e => { A.config.assumptions[i] = e.target.value; scheduleSave(); } }),
      btn("✕", () => { A.config.assumptions.splice(i, 1); renderRight(); scheduleSave(); }, "tiny ghost")));
  });
  s.append(b);
  return s;
}

function sectionChecks() {
  const s = el("div", { class: "sec" });
  s.append(el("h3", {}, "Checks", el("span", { class: "grow" }),
    btn("+ overflow", () => openOverflowModal(), "tiny"),
    btn("+ assert", () => openAssertModal(null), "tiny"),
    btn("+ custom", () => openCustomModal(null), "tiny")));
  const b = el("div", { class: "body" });
  if (!A.config.checks.length) b.append(el("div", { class: "faint", style: "font-size:11px" }, "No checks yet. Click ", el("b", {}, "+ overflow"), " on an arithmetic instruction in the code view, or add one here."));
  A.config.checks.forEach((c, i) => b.append(renderCheck(c, i)));
  s.append(b);
  return s;
}
function renderCheck(c, i) {
  const box = el("div", { class: "check" + (c.enabled ? "" : " dis") });
  const kindPill = { int_overflow: "warn", assert: "warn", reach: "info", avoid: "warn", custom: "info" }[c.kind] || "info";
  box.append(el("div", { class: "top" },
    el("input", { type: "checkbox", checked: c.enabled ? "" : null, style: "width:auto", onchange: e => { c.enabled = e.target.checked; saveConfig(); renderRight(); } }),
    el("span", { class: "pill " + kindPill }, c.kind.replace("_", " ")),
    el("span", { class: "kind grow" }, c.name || ""),
    c.addr ? btn("↧", () => { selectTab("code"); scrollToAddr(c.addr); }, "tiny ghost") : null,
    btn("✕", () => { A.config.checks.splice(i, 1); saveConfig(); renderRight(); }, "tiny ghost")));
  const desc = describeCheck(c);
  if (desc) box.append(el("div", { class: "desc" }, desc));
  return box;
}
function describeCheck(c) {
  if (c.kind === "int_overflow") return (c.addr ? hx64(c.addr) + "  " : "whole function  ") + "· " + (c.signed || "either") + (c.note ? "  · " + c.note : "");
  if (c.kind === "assert") return (c.at_return ? "at return: " : c.addr ? hx64(c.addr) + ": " : "every block: ") + c.expr;
  if (c.kind === "reach" || c.kind === "avoid") return "address " + hx64(c.addr);
  if (c.kind === "custom") return (c.addr ? "at " + hx64(c.addr) : "every block") + " · " + (c.code || "").split("\n").filter(l => l.trim() && !l.trim().startsWith("#")).slice(0, 1).join("").slice(0, 60);
  return "";
}

// ==================================================================== run section
function sectionRun() {
  const s = el("div", { class: "sec" });
  s.append(el("h3", {}, "Run"));
  const b = el("div", { class: "body" });
  const L = A.config.limits;
  const lim = el("div", { style: "display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:8px" },
    limInput("max steps", "steps", L), limInput("max active", "active", L),
    limInput("seconds", "seconds", L), limInput("loop bound", "loop_bound", L));
  b.append(lim);

  const running = A.run && (A.run.snapshot?.status === "running" || A.run.snapshot?.status === "pending");
  const runBtn = el("button", { class: "primary", style: "width:100%;padding:8px", onclick: startRun }, "▶  Run checks");
  const cancelBtn = el("button", { style: "width:100%;padding:8px", onclick: cancelRun }, "■  Cancel");
  b.append(running ? cancelBtn : runBtn);

  if (A.run) {
    const snap = A.run.snapshot || {};
    const p = snap.progress || {};
    const pct = Math.min(100, (p.step || 0) / (A.config.limits.steps || 1) * 100);
    b.append(el("div", { class: "prog", style: "margin-top:10px" }, el("i", { style: `width:${pct}%` })));
    b.append(el("div", { class: "stats" },
      el("span", {}, "step ", el("b", {}, p.step ?? 0)),
      el("span", {}, "active ", el("b", {}, p.active ?? 0)),
      el("span", {}, "ended ", el("b", {}, p.deadended ?? 0)),
      el("span", {}, "hits ", el("b", {}, p.hits ?? 0)),
      el("span", {}, (p.elapsed ?? 0) + "s")));
    b.append(el("div", { class: "faint mono", style: "font-size:11px;margin-top:4px" }, snap.status + " · " + (p.message || "")));
    if (snap.error) b.append(el("div", { class: "pill bad", style: "margin-top:6px;display:block" }, snap.error));
  }
  s.append(b);
  return s;
}
function limInput(label, key, L) {
  return el("label", { class: "col", style: "font-size:11px;color:var(--dim);gap:3px" }, label,
    el("input", { value: L[key], oninput: e => { L[key] = +e.target.value; scheduleSave(); } }));
}

async function startRun() {
  if (!A.config.checks.some(c => c.enabled)) { toast("add at least one check first", true); return; }
  await saveConfig();
  const spec = {
    func_addr: A.fn.addr,
    args: A.config.args,
    buffers: A.config.buffers,
    assumptions: A.config.assumptions.filter(x => x.trim()),
    stdin: A.config.stdin,
    checks: A.config.checks.filter(c => c.enabled),
    limits: A.config.limits,
  };
  try {
    const r = await jpost("/api/run", spec);
    A.run = { id: r.run_id, snapshot: { status: "pending", progress: { message: "queued" } } };
    A.selectedHit = null;
    renderRight();
    startPolling();
    selectTab("paths");
  } catch (e) { toast("run failed: " + e.message, true); }
}
async function cancelRun() {
  if (!A.run) return;
  try { await jpost(`/api/run/${A.run.id}/cancel`, {}); } catch (e) {}
}
function startPolling() {
  stopPolling();
  A.pollTimer = setInterval(pollRun, 500);
  pollRun();
}
function stopPolling() { if (A.pollTimer) { clearInterval(A.pollTimer); A.pollTimer = null; } }
async function pollRun() {
  if (!A.run) return;
  let snap;
  try { snap = await api("/api/run/" + A.run.id); } catch (e) { stopPolling(); return; }
  A.run.snapshot = snap;
  renderRight();
  renderTree();
  highlightHits();
  if (["done", "error", "cancelled"].includes(snap.status)) {
    stopPolling();
    const n = snap.summary?.hits || 0;
    toast(n ? `${n} hit${n > 1 ? "s" : ""} found` : "run finished — no hits");
  }
}

// ==================================================================== hits
function sectionHits() {
  const s = el("div", { class: "sec" });
  const hits = A.run?.snapshot?.hits || [];
  s.append(el("h3", {}, "Findings", el("span", { class: "grow" }), hits.length ? el("span", { class: "pill bad" }, hits.length) : el("span", { class: "faint", style: "font-weight:400;text-transform:none" }, "none yet")));
  const b = el("div", { class: "body" });
  if (!hits.length) b.append(el("div", { class: "faint", style: "font-size:11px" }, "Run to collect findings. Each finding comes with concrete input values that trigger it."));
  hits.forEach((h, i) => b.append(renderHit(h, i)));
  s.append(b);
  return s;
}
function renderHit(h, i) {
  const kindCls = h.kind === "reach" ? "reach" : h.kind === "assert" ? "assert" : "";
  const box = el("div", { class: "hit " + kindCls });
  box.append(el("div", { class: "h1" },
    el("span", { class: "pill " + (h.kind === "reach" ? "info" : "bad") }, h.kind.replace("_", " ")),
    el("span", { class: "grow mono", style: "font-size:11px" }, hx64(h.addr)),
    h.extra?.src_line ? el("span", { class: "faint" }, h.extra.src_line.file + ":" + h.extra.src_line.line) : null));
  box.append(el("div", { class: "msg" }, h.message));
  const wit = Object.entries(h.witness || {}).filter(([k, v]) => typeof v === "object");
  if (wit.length) {
    box.append(el("div", { class: "wit" }, "witness: " + wit.map(([k, v]) => `${k}=${v.hex}${v.s !== v.u ? `(${v.s})` : ""}`).join("  ")));
  }
  if (h.witness?.stdin) box.append(el("div", { class: "wit" }, "stdin=" + h.witness.stdin));
  box.addEventListener("click", () => { A.selectedHit = i; selectTab("code"); scrollToAddr(h.addr); highlightHits(); renderTree(); });
  return box;
}

// ==================================================================== code highlight
function scrollToAddr(addr) {
  const row = $(`.insn[data-addr="${addr}"]`, $("#pane-code"));
  if (row) { row.scrollIntoView({ block: "center", behavior: "smooth" }); row.classList.add("oncur"); setTimeout(() => row.classList.remove("oncur"), 1500); }
}
function highlightHits() {
  const pane = $("#pane-code"); if (!pane) return;
  $$(".insn", pane).forEach(r => r.classList.remove("hit"));
  const hits = A.run?.snapshot?.hits || [];
  for (const h of hits) {
    const row = $(`.insn[data-addr="${h.addr}"]`, pane);
    if (row) row.classList.add("hit");
  }
}

// ==================================================================== path tree
function renderTree() {
  const pane = $("#pane-paths"); if (!pane) return;
  const snap = A.run?.snapshot;
  if (!snap || !snap.tree || !snap.tree.length) { pane.innerHTML = '<div class="empty">No paths yet.</div>'; return; }
  const nodes = snap.tree;
  const byId = {}; nodes.forEach(n => byId[n.id] = n);
  const children = {}; nodes.forEach(n => { if (n.parent !== null) (children[n.parent] = children[n.parent] || []).push(n); });
  const roots = nodes.filter(n => n.parent === null || !(n.parent in byId));

  const legend = el("div", { style: "padding:10px 12px;display:flex;gap:12px;flex-wrap:wrap;border-bottom:1px solid var(--line)" });
  [["active", "still exploring"], ["deadended", "returned/ended"], ["found", "target reached"], ["avoided", "avoided addr"], ["unconstrained", "control lost"], ["errored", "error"]].forEach(([k, t]) =>
    legend.append(el("span", { class: "row", style: "font-size:11px;color:var(--dim);gap:4px" }, el("span", { class: "dot " + k, style: "width:9px;height:9px;border-radius:50%;display:inline-block" }), t)));

  const box = el("div", { id: "tree" });
  const wrap = el("div"); wrap.append(legend, box);
  pane.replaceChildren(wrap);

  function walk(n, depth) {
    const hasHit = n.hits && n.hits.length;
    const row = el("div", { class: "tnode" + (hasHit ? " hashit" : ""), style: `padding-left:${depth * 16 + 10}px` },
      el("span", { class: "dot " + n.kind, title: n.kind }),
      el("span", {}, n.label || hx64(n.addr)),
      hasHit ? el("span", { class: "pill bad", style: "margin-left:6px" }, "hit") : null);
    row.addEventListener("click", () => {
      if (n.hits && n.hits.length) { A.selectedHit = n.hits[0]; selectTab("code"); scrollToAddr((snap.hits[n.hits[0]] || {}).addr); highlightHits(); }
    });
    box.append(row);
    (children[n.id] || []).sort((a, b) => a.addr - b.addr).forEach(c => walk(c, depth + 1));
  }
  roots.forEach(r => walk(r, 0));
  const sum = snap.summary || {};
  box.append(el("div", { class: "faint mono", style: "padding:12px;font-size:11px" },
    `${sum.nodes || nodes.length} path nodes · ${sum.deadended || 0} ended · ${sum.active || 0} active · ${sum.unconstrained || 0} unconstrained`));
}

let saveTimer = null;
function scheduleSave() { clearTimeout(saveTimer); saveTimer = setTimeout(saveConfig, 500); }

// ==================================================================== modal helper
function modal(title, bodyNode, footerButtons) {
  const bg = el("div", { class: "modal-bg" });
  const m = el("div", { class: "modal" },
    el("div", { class: "mh" }, el("span", {}, title), el("button", { class: "ghost tiny", onclick: () => bg.remove() }, "✕")),
    el("div", { class: "mb" }, bodyNode),
    (footerButtons && footerButtons.length) ? el("div", { class: "mf" }, ...footerButtons) : null);
  bg.append(m);
  bg.addEventListener("click", e => { if (e.target === bg) bg.remove(); });
  bg.remove = () => bg.parentNode && bg.parentNode.removeChild(bg);
  return bg;
}

// ==================================================================== overflow modal
function openOverflowModal() {
  const arithInsns = (A.detail.disasm.instructions || []).filter(i => i.arith);
  const sel = el("select", {});
  sel.append(el("option", { value: "" }, "— whole function (all add/sub/mul) —"));
  arithInsns.forEach(i => sel.append(el("option", { value: i.addr },
    `${hx64(i.addr)}  ${i.mnemonic} ${i.op_str}` + (i.src_line ? `  (line ${i.src_line})` : ""))));
  const signed = el("select", {});
  [["either", "either signed or unsigned"], ["unsigned", "unsigned wrap only"], ["signed", "signed overflow only"]]
    .forEach(([v, t]) => signed.append(el("option", { value: v }, t)));
  const body = el("div", {},
    field("Where", sel, "Pick one arithmetic instruction, or scan every add/sub/mul in the function."),
    field("Overflow kind", signed, "Unsigned = the result wraps past 2ⁿ. Signed = it leaves the signed range."));
  const m = modal("Add integer-overflow check", body, [
    el("button", { onclick: () => m.remove() }, "Cancel"),
    el("button", { class: "primary", onclick: () => {
      const addr = sel.value ? +sel.value : null;
      const ins = arithInsns.find(i => i.addr === addr);
      addCheck({ kind: "int_overflow", addr, signed: signed.value,
        name: addr ? `overflow @ ${hx64(addr)}` : "overflow (whole function)",
        note: ins ? ins.mnemonic + " " + ins.op_str : "" });
      m.remove();
    } }, "Add check")]);
  $("#modalHost").append(m);
}

// ==================================================================== assert modal
function openAssertModal(addr) {
  const where = el("select", {});
  where.append(el("option", { value: "at_return" }, "at function return"));
  if (addr) where.append(el("option", { value: "addr", selected: "" }, "at " + hx64(addr)));
  where.append(el("option", { value: "every" }, "at every block"));
  const expr = el("input", { placeholder: "e.g. total >= count", style: "width:100%" });
  const body = el("div", {},
    field("Invariant that should always hold", expr,
      "The check fires when angr can make it FALSE. Names: arguments, DWARF locals, registers, and " +
      "<code>ret</code>. Ops: <code>+ - * / % & | ^ << >></code>, compares <code>== != < <= > >=</code> " +
      "(prefix <code>s</code> for signed: <code>s<</code>). Widths: <code>u32(x)</code>, <code>s16(x)</code>. Memory: <code>[rsp+8]:4</code>."),
    field("Evaluate", where, "Assertions read committed state, so they are evaluated at block boundaries."));
  const m = modal("Add assertion", body, [
    el("button", { onclick: () => m.remove() }, "Cancel"),
    el("button", { class: "primary", onclick: () => {
      if (!expr.value.trim()) { toast("enter an expression", true); return; }
      const w = where.value;
      addCheck({ kind: "assert", expr: expr.value.trim(),
        at_return: w === "at_return", addr: w === "addr" ? addr : null,
        name: "assert: " + expr.value.trim().slice(0, 28) });
      m.remove();
    } }, "Add check")]);
  $("#modalHost").append(m);
  setTimeout(() => expr.focus(), 50);
}

// ==================================================================== custom modal
async function openCustomModal(addr) {
  let tpl = "def check(state, api):\n    return None\n";
  try { tpl = (await api("/api/custom-template")).template; } catch (e) {}
  const ta = el("textarea", { style: "width:100%;min-height:220px" }, tpl);
  const where = el("select", {});
  if (addr) where.append(el("option", { value: "addr", selected: "" }, "at " + hx64(addr)));
  where.append(el("option", { value: "every" }, "at every block in this function"));
  const body = el("div", {},
    field("Python predicate", ta,
      "Return a dict <code>{message, witness?}</code> to record a finding, or None. " +
      "<code>api.eval(\"expr\")</code>, <code>api.sat(cond)</code>, <code>api.witness(cond)</code>, " +
      "<code>api.reg(\"rax\")</code>, <code>api.mem(addr,size)</code>."),
    field("Run", where, ""));
  const m = modal("Add custom check", body, [
    el("button", { onclick: () => m.remove() }, "Cancel"),
    el("button", { class: "primary", onclick: () => {
      addCheck({ kind: "custom", code: ta.value, addr: where.value === "addr" ? addr : null,
        name: "custom" + (addr ? " @ " + hx64(addr) : "") });
      m.remove();
    } }, "Add check")]);
  $("#modalHost").append(m);
}

function field(label, node, help) {
  return el("div", { class: "field" }, el("label", {}, label), node,
    help ? el("div", { class: "help", html: help }) : null);
}

// ==================================================================== CFG
async function renderCFG() {
  const pane = $("#pane-cfg");
  if (!A.fn) { pane.innerHTML = '<div class="empty">Select a function.</div>'; return; }
  if (!pane.classList.contains("sel") && pane.dataset.addr == A.fn.addr) return;
  pane.dataset.addr = A.fn.addr;
  let g = A.cfgCache[A.fn.addr];
  if (!g) {
    pane.innerHTML = '<div class="empty">Laying out graph…</div>';
    try { g = await api("/api/cfg/" + A.fn.addr); A.cfgCache[A.fn.addr] = g; }
    catch (e) { pane.innerHTML = '<div class="empty">CFG error: ' + e.message + '</div>'; return; }
  }
  drawCFG(pane, g);
}
function drawCFG(pane, g) {
  const gr = new dagre.graphlib.Graph({ multigraph: true });
  gr.setGraph({ rankdir: "TB", nodesep: 26, ranksep: 34, marginx: 20, marginy: 20 });
  gr.setDefaultEdgeLabel(() => ({}));
  const hitAddrs = new Set((A.run?.snapshot?.hits || []).map(h => h.addr));
  const pathBlocks = new Set();
  if (A.selectedHit != null && A.run?.snapshot?.hits[A.selectedHit]) {
    (A.run.snapshot.hits[A.selectedHit].extra?.path || []).forEach(a => pathBlocks.add(parseInt(a, 16)));
  }
  const LINE_H = 14, CHAR_W = 6.4, PAD = 10;
  for (const n of g.nodes) {
    const lines = n.insns.slice(0, 8).map(i => `${hx64(i.addr).slice(2)}  ${i.text}`);
    if (n.insns.length > 8) lines.push(`… +${n.insns.length - 8}`);
    const w = Math.max(120, Math.min(460, Math.max(...lines.map(l => l.length)) * CHAR_W + PAD * 2));
    const h = lines.length * LINE_H + PAD * 2 + 14;
    gr.setNode(n.addr, { label: hx64(n.addr), lines, width: w, height: h, insns: n.insns });
  }
  let ei = 0;
  for (const e of g.edges) {
    if (gr.hasNode(e.src) && gr.hasNode(e.dst)) gr.setEdge(e.src, e.dst, { kind: e.kind }, "e" + (ei++));
  }
  dagre.layout(gr);
  const W = gr.graph().width || 400, H = gr.graph().height || 300;
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("width", W); svg.setAttribute("height", H);
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.style.cssText = "display:block;background:var(--bg)";
  // defs: arrow
  svg.innerHTML = `<defs><marker id="arr" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
    <path d="M0,0 L7,3 L0,6 Z" fill="#5a6577"/></marker>
    <marker id="arrhi" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
    <path d="M0,0 L7,3 L0,6 Z" fill="#f85149"/></marker></defs>`;
  // edges
  gr.edges().forEach(eid => {
    const e = gr.edge(eid);
    const pts = e.points;
    const hiEdge = pathBlocks.has(+eid.v) && pathBlocks.has(+eid.w);
    let d = `M${pts[0].x},${pts[0].y}`;
    for (let i = 1; i < pts.length; i++) d += ` L${pts[i].x},${pts[i].y}`;
    const color = e.kind === "call" ? "#7c5cff" : e.kind === "return" ? "#3fb950" : "#5a6577";
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", d);
    p.setAttribute("fill", "none");
    p.setAttribute("stroke", hiEdge ? "#f85149" : color);
    p.setAttribute("stroke-width", hiEdge ? 2.5 : 1.3);
    if (e.kind === "call") p.setAttribute("stroke-dasharray", "4 3");
    p.setAttribute("marker-end", hiEdge ? "url(#arrhi)" : "url(#arr)");
    svg.append(p);
  });
  // nodes
  gr.nodes().forEach(id => {
    const n = gr.node(id);
    const gEl = document.createElementNS(NS, "g");
    gEl.setAttribute("transform", `translate(${n.x - n.width / 2},${n.y - n.height / 2})`);
    const onPath = pathBlocks.has(+id);
    const hasHit = n.insns.some(i => hitAddrs.has(i.addr));
    const rect = document.createElementNS(NS, "rect");
    rect.setAttribute("width", n.width); rect.setAttribute("height", n.height);
    rect.setAttribute("rx", 7);
    rect.setAttribute("fill", hasHit ? "#241318" : onPath ? "#17233a" : "#161b22");
    rect.setAttribute("stroke", hasHit ? "#f85149" : onPath ? "#4c9aff" : "#2a3140");
    rect.setAttribute("stroke-width", (hasHit || onPath) ? 2 : 1);
    rect.style.cursor = "pointer";
    rect.addEventListener("click", () => { selectTab("code"); scrollToAddr(+id); });
    gEl.append(rect);
    const head = document.createElementNS(NS, "text");
    head.setAttribute("x", 8); head.setAttribute("y", 14);
    head.setAttribute("fill", hasHit ? "#f85149" : "#9aa7b4");
    head.setAttribute("font-family", "var(--mono)"); head.setAttribute("font-size", "10");
    head.setAttribute("font-weight", "700");
    head.textContent = n.label;
    gEl.append(head);
    n.lines.forEach((ln, i) => {
      const t = document.createElementNS(NS, "text");
      t.setAttribute("x", 8); t.setAttribute("y", 14 + 14 + i * LINE_H);
      t.setAttribute("fill", "#c9d3de"); t.setAttribute("font-family", "monospace"); t.setAttribute("font-size", "10.5");
      t.textContent = ln;
      gEl.append(t);
    });
    svg.append(gEl);
  });
  // pan/zoom
  const holder = el("div", { style: "width:100%;height:100%;overflow:auto;position:relative" });
  const toolbar = el("div", { style: "position:sticky;top:0;left:0;z-index:2;padding:6px 10px;display:flex;gap:8px;align-items:center;background:linear-gradient(180deg,#0e1117,transparent)" },
    el("span", { class: "faint", style: "font-size:11px" }, `${g.nodes.length} blocks`),
    A.selectedHit != null ? el("span", { class: "pill bad" }, "path to finding highlighted") : el("span", { class: "faint", style: "font-size:11px" }, "click a finding to trace its path"));
  holder.append(toolbar, svg);
  pane.replaceChildren(holder);
}
