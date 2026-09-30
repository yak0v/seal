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
  selNode: null,        // selected path-tree node id
  collapsed: new Set(), // folded path-tree node ids
  pathHighlight: null,  // Set of block addrs on the selected path
  scriptCode: "",
  scriptJump: null,
  ida: { connected: false },
  decompCache: {},
  _assume: null,
  activity: [],
  actOpen: false,
  followAgent: true,
};

// ==================================================================== boot
window.addEventListener("DOMContentLoaded", init);

async function init() {
  $("#openBtn").addEventListener("click", openBrowser);
  $("#fnSearch").addEventListener("input", renderFunctions);
  $("#onlyNamed").addEventListener("change", renderFunctions);
  $$(".tab").forEach(t => t.addEventListener("click", () => selectTab(t.dataset.tab)));
  $("#idaBtn").addEventListener("click", openIdaModal);
  $("#actBtn").addEventListener("click", toggleActivity);
  $("#followChk").addEventListener("change", e => { A.followAgent = e.target.checked; });
  refreshIdaStatus();
  connectEvents();
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
  // stripped binary: almost nothing has a symbol name, so don't hide the sub_* functions
  if (r.functions.filter(f => f.named).length < 10) $("#onlyNamed").checked = false;
  renderFunctions();
}
function renderFunctions() {
  const q = $("#fnSearch").value.toLowerCase();
  const onlyNamed = $("#onlyNamed").checked;
  const box = $("#fnList"); box.replaceChildren();
  const list = A.functions.filter(f =>
    (!onlyNamed || f.named) && (!q || f.name.toLowerCase().includes(q) || (f.ida_name||"").toLowerCase().includes(q) || hx64(f.addr).includes(q)));
  if (!list.length) { box.append(el("div", { class: "empty" }, "No matching functions.")); return; }
  for (const f of list) {
    const node = el("div", { class: "fn" + (f.named ? "" : " unnamed") + (A.fn && A.fn.addr === f.addr ? " sel" : "") },
      el("div", { class: "nm" }, f.ida_name ? el("span", { class: "idanm" }, f.ida_name) : f.name),
      el("div", { class: "sub" },
        el("span", {}, hx64(f.addr)),
        f.ida_name ? el("span", { class: "idatag" }, "IDA") : null,
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
  A.fn = f; A.run = null; A.selectedHit = null; A.selNode = null; A.pathHighlight = null; A.collapsed.clear();
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
  renderTree(true);
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
  if ($("#pane-script").classList.contains("sel")) renderScript();
  const f = A.functions.find(x => x.addr === A.fn.addr);
  if (f) { f.check_count = A.config.checks.length; f.configured = true; renderFunctions(); }
}

function selectTab(name) {
  $$(".tab").forEach(t => t.classList.toggle("sel", t.dataset.tab === name));
  $$(".tabpane").forEach(p => p.classList.toggle("sel", p.id === "pane-" + name));
  if (name === "code" && A.detail) renderCode();
  if (name === "cfg") renderCFG($("#pane-cfg").dataset.stale === "1");
  if (name === "script") renderScript();
  if (name === "paths") renderTree(true);
  if (name === "decomp") renderDecomp();
}

// ==================================================================== code view
function renderCode() {
  const d = A.detail, di = d.disasm;
  const pane = $("#pane-code"); pane.replaceChildren();
  const abar = assumptionsBar(); if (abar) pane.append(abar);
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

    const row = el("div", { class: "insn" + (ins.arith ? " arith" : ""), "data-addr": ins.addr, "data-block": ins.block },
      el("span", { class: "ad" }, hx64(ins.addr)),
      el("span", { class: "mn" }, ins.mnemonic),
      el("span", { class: "op" }, annotate(ins.op_str), ins.is_call && di.call_targets[ins.addr] ? "   ; " + (di.call_targets[ins.addr].name || "") : ""),
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
  $("#rTitle").textContent = A.fn ? (A.fn.ida_name || A.fn.name) : "Setup";
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
    el("button", { class: "tiny ghost", title: "show this setup as angr code", onclick: () => showInScript("= initial state") }, "</> angr")));
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
  const argNames = (A.config.args || []).map(a => a.name).filter(Boolean);
  b.append(el("div", { class: "faint", style: "font-size:11px;margin-bottom:6px" },
    "Constraints on the initial argument values. Names you can use: ",
    ...(argNames.length ? argNames.map(n => el("code", {}, n)).flatMap(c => [c, " "]) : [el("code", {}, "arg0"), " "]),
    "· also ", el("code", {}, "a1"), "…/", el("code", {}, "arg0"), "… (the parameters), registers (", el("code", {}, "rdi"),
    "), and ", el("code", {}, "ret"), ". e.g. ", el("code", {}, "a1 & 0xff == 0x5a")));
  A.config.assumptions.forEach((a, i) => {
    b.append(el("div", { class: "assume" },
      el("span", { class: "adot", style: `background:${ASSUME_COLORS[i % ASSUME_COLORS.length]}` }),
      el("input", { value: a, placeholder: "expression that must hold", oninput: e => { A.config.assumptions[i] = e.target.value; scheduleSave(); scheduleAssumeRefresh(); } }),
      btn("✕", () => { A.config.assumptions.splice(i, 1); renderRight(); scheduleSave(); refreshAssumptionViews(); }, "tiny ghost")));
  });
  s.append(b);
  return s;
}

function sectionChecks() {
  const s = el("div", { class: "sec" });
  s.append(el("h3", {}, "Checks", el("span", { class: "grow" }),
    el("button", { class: "tiny ghost", title: "show these checks as angr code", onclick: () => showInScript("= checks") }, "</>"),
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
  b.append(el("label", { class: "row", style: "font-size:12px;gap:6px;margin-bottom:8px",
      title: "Don't descend into called functions — each call returns an unconstrained value. Keeps exploration in this function so its branches show in the path tree." },
    el("input", { type: "checkbox", checked: L.skip_calls ? "" : null, style: "width:auto",
      onchange: e => { L.skip_calls = e.target.checked; scheduleSave(); } }),
    "skip calls ", el("span", { class: "faint" }, "(explore only this function)")));

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
  try {
    const r = await jpost("/api/run", currentSpec());
    A.run = { id: r.run_id, snapshot: { status: "pending", progress: { message: "queued" } } };
    A.selectedHit = null; A.selNode = null; A.pathHighlight = null; A.collapsed.clear();
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
  if (Object.keys(h.witness || {}).length) box.append(el("div", { class: "wit" }, "inputs: " + fmtWitness(h.witness)));
  const node = h.extra?.node;
  if (node != null) box.append(el("button", { class: "tiny ghost", style: "margin-top:4px",
    onclick: e => { e.stopPropagation(); A.selNode = node; updatePathHighlight(); selectTab("paths"); } }, "show its path"));
  box.addEventListener("click", () => {
    A.selectedHit = i;
    if (node != null) { A.selNode = node; updatePathHighlight(); }
    selectTab("code"); scrollToAddr(h.addr); renderTree(true);
  });
  return box;
}

// ==================================================================== code highlight
function scrollToAddr(addr) {
  const row = $(`.insn[data-addr="${addr}"]`, $("#pane-code"));
  if (row) { row.scrollIntoView({ block: "center", behavior: "smooth" }); row.classList.add("oncur"); setTimeout(() => row.classList.remove("oncur"), 1500); }
}
function highlightHits() {
  const pane = $("#pane-code"); if (!pane) return;
  $$(".insn", pane).forEach(r => {
    r.classList.remove("hit");
    r.classList.toggle("onpath", !!A.pathHighlight && A.pathHighlight.has(+r.dataset.block));
  });
  const hits = A.run?.snapshot?.hits || [];
  for (const h of hits) {
    const row = $(`.insn[data-addr="${h.addr}"]`, pane);
    if (row) row.classList.add("hit");
  }
}

// ==================================================================== path tree
// Each tree node is one stretch of execution between two splits. The root starts at
// the function entry; whenever a branch depends on the symbolic inputs, angr follows
// both sides and each side becomes a child, labelled with the condition it requires.
const END_STYLE = {
  returned: ["ok", "returned"], exit: ["warn", "exit"], ended: ["", "ended"],
  loop_bound: ["", "loop bound"], dropped: ["", "dropped"], unconstrained: ["bad", "hijackable"],
  error: ["warn", "error"], unfinished: ["info", "unfinished"], running: ["info", "running"],
};
let treeKey = "";

function renderTree(force) {
  const pane = $("#pane-paths"); if (!pane) return;
  const snap = A.run?.snapshot;
  if (!snap || !snap.tree || !snap.tree.length) {
    treeKey = "";
    pane.innerHTML = snap && ["pending", "running"].includes(snap.status)
      ? '<div class="empty">Exploring…</div>' : '<div class="empty">Run the checks to see the paths angr explored.</div>';
    return;
  }
  const key = snap.status + "|" + JSON.stringify(snap.tree).length + "|" + snap.hits.length + "|" + A.selNode + "|" + [...A.collapsed].join(",");
  if (!force && key === treeKey) return;
  treeKey = key;

  const T = pathModel(snap);
  let wrap = $("#pathsWrap", pane);
  if (!wrap) {
    wrap = el("div", { id: "pathsWrap" }, el("div", { id: "treeCol" }), el("div", { id: "detailCol" }));
    pane.replaceChildren(wrap);
  }
  const treeCol = $("#treeCol", wrap), detailCol = $("#detailCol", wrap);
  const keepScroll = treeCol.scrollTop;
  treeCol.replaceChildren(pathsHelp(), checksBar(), pathsSummary(T, snap));
  const box = el("div", { class: "ptree" });
  T.roots.forEach(r => box.append(renderPathNode(T, r, snap)));
  treeCol.append(box);
  treeCol.scrollTop = keepScroll;
  detailCol.replaceChildren(...(T.byId[A.selNode] ? [renderPathDetail(T, snap)] : []));
}

function pathModel(snap) {
  const byId = {}, kids = {};
  snap.tree.forEach(n => { byId[n.id] = n; });
  snap.tree.forEach(n => { if (n.parent !== null && byId[n.parent]) (kids[n.parent] = kids[n.parent] || []).push(n); });
  // finished branches first, so the side that keeps going comes last and its subtree reads downward
  for (const k in kids) kids[k].sort((a, b) => ((kids[a.id] ? 1 : 0) - (kids[b.id] ? 1 : 0)) || a.id - b.id);
  const roots = snap.tree.filter(n => n.parent === null || !byId[n.parent]);
  // number the finished paths (leaves) in display order
  const leafNo = {};
  let k = 0;
  const walk = n => { if (!kids[n.id]) leafNo[n.id] = ++k; (kids[n.id] || []).forEach(walk); };
  roots.forEach(walk);
  // nodes that lie on the way to a finding
  const toHit = new Set();
  snap.tree.forEach(n => { if (n.hits.length) for (let c = n; c; c = byId[c.parent]) toHit.add(c.id); });
  const chain = id => { const out = []; for (let c = byId[id]; c; c = byId[c.parent]) out.unshift(c); return out; };
  return { byId, kids, roots, leafNo, toHit, chain };
}

function pathsHelp() {
  let hidden = false;
  try { hidden = localStorage.getItem("pathsHelpHidden") === "1"; } catch (e) {}
  const toggle = el("button", { class: "tiny ghost", onclick: () => {
    try { localStorage.setItem("pathsHelpHidden", hidden ? "0" : "1"); } catch (e) {}
    renderTree(true);
  } }, hidden ? "how to read this?" : "hide");
  if (hidden) return el("div", { class: "phelp small" }, toggle);
  const fn = A.fn ? `${A.fn.name}(${A.config.args.map(a => a.name).join(", ")})` : "the function";
  return el("div", { class: "phelp" }, el("div", { class: "row", style: "align-items:flex-start" },
    el("div", { class: "grow", html:
      `<b>How to read this.</b> angr runs <code>${esc(fn)}</code> with your symbolic inputs. ` +
      `At every branch whose direction depends on those inputs it takes <b>both</b> sides, so the run splits in two. ` +
      `Each row is one stretch of execution between splits:` +
      `<ul><li><span class="cond">condition</span>: what the inputs must satisfy to take this side, next to the source line that decided it.</li>` +
      `<li>Read a path top to bottom. The inputs must satisfy <i>all</i> the conditions on the way down.</li>` +
      `<li>Rows that end a path (<b>#1, #2…</b>) say how it ended and give example inputs that drive the program down it.</li>` +
      `<li><span class="pill bad">finding</span> marks where a check fired; the <span class="tohit-key">red rail</span> leads to it.</li></ul>` +
      `Click a row to see the whole path and highlight it in the code and the control-flow graph.` }),
    toggle));
}

function describeCheckShort(c) {
  const nm = c.name || c.kind.replace("_", " ");
  if (c.kind === "assert") return "assert " + (c.expr || "");
  if (c.kind === "int_overflow") return nm + (c.addr ? " @" + hx64(c.addr) : " (whole fn)") + " · " + (c.signed || "either");
  if (c.kind === "reach" || c.kind === "avoid") return c.kind + " " + (c.addr != null ? hx64(c.addr) : "");
  if (c.kind === "custom") return nm;
  return nm;
}
function checksBar() {
  const cs = (A.config && A.config.checks || []).filter(c => c.enabled);
  if (!cs.length) return el("span", { class: "hidden" });
  const bar = el("div", { class: "checksbar" }, el("span", { class: "albl" }, "checks run"));
  const cls = { int_overflow: "warn", assert: "warn", reach: "info", avoid: "warn", custom: "info" };
  for (const c of cs) bar.append(el("span", { class: "chchip " + (cls[c.kind] || "info") }, describeCheckShort(c)));
  return bar;
}
function pathsSummary(T, snap) {
  const leaves = snap.tree.filter(n => !T.kids[n.id]);
  const counts = {};
  leaves.forEach(n => { const r = leafReason(n, snap); counts[r] = (counts[r] || 0) + 1; });
  const names = { returned: "returned", exit: "exited the program", ended: "ended", loop_bound: "stopped by the loop bound",
    dropped: "dropped (max active)", unconstrained: "hijackable jump", error: "errored", unfinished: "unfinished", running: "still running" };
  const parts = Object.entries(counts).map(([r, c]) => el("span", { class: "pill " + (END_STYLE[r]?.[0] || "") }, `${c} ${names[r] || r}`));
  const hits = snap.hits.length;
  return el("div", { class: "psum" },
    el("b", {}, `${leaves.length} path${leaves.length === 1 ? "" : "s"}:`), ...parts,
    el("span", { class: "grow" }),
    hits ? el("span", { class: "pill bad" }, `${hits} finding${hits > 1 ? "s" : ""}`) : el("span", { class: "faint" }, "no findings"));
}
const leafReason = (n, snap) => n.end?.reason || (["running", "pending"].includes(snap.status) ? "running" : "unfinished");

function renderPathNode(T, n, snap) {
  const kids = T.kids[n.id] || [];
  const collapsed = A.collapsed.has(n.id);
  const row = el("div", { class: "prow" + (A.selNode === n.id ? " sel" : "") });
  const caret = kids.length
    ? el("span", { class: "caret", title: collapsed ? "expand" : "collapse", onclick: e => {
        e.stopPropagation();
        A.collapsed.has(n.id) ? A.collapsed.delete(n.id) : A.collapsed.add(n.id);
        renderTree(true);
      } }, collapsed ? "▸" : "▾")
    : el("span", { class: "caret leafno" }, "#" + T.leafNo[n.id]);

  const head = el("div", { class: "phead1" }, caret);
  if (n.parent === null) {
    head.append(el("span", { class: "startlbl" }, "start"),
      el("span", { class: "mono" }, `${A.fn?.name || hx64(n.addr)}(${A.config.args.map(a => a.name).join(", ")})`));
    const asm = snap.summary?.assumptions_applied || [];
    if (asm.length) head.append(el("span", { class: "where" }, "assuming " + asm.join(", ")));
  } else {
    head.append(el("span", { class: "cond", title: "the inputs must satisfy this to take this side of the branch" },
      n.cond || "(no input-dependent condition)"));
    if (n.decided_at?.line) head.append(el("span", { class: "where", title: "decided at " + hx64(n.decided_at.addr) },
      `${n.decided_at.file}:${n.decided_at.line}  ${n.decided_at.text || ""}`));
  }
  head.append(el("span", { class: "grow" }));
  if (n.hits.length) head.append(el("span", { class: "pill bad" }, n.hits.length > 1 ? `${n.hits.length} findings` : "finding"));
  if (!kids.length) {
    const r = leafReason(n, snap);
    const st = END_STYLE[r] || ["info", r];
    head.append(el("span", { class: "pill " + st[0] }, r === "exit" ? (n.calls.slice(-1)[0] || "exit") + "()" : st[1]));
  }
  row.append(head);

  const sub = [];
  if (n.lines.length) sub.push("runs " + lineRanges(n.lines));
  if (n.calls.length) sub.push("calls " + n.calls.map(c => c + "()").join(", "));
  if (!kids.length && n.end?.reason === "returned" && n.ret) sub.push("returns " + n.ret);
  if (!kids.length && n.end && !["returned", "exit"].includes(n.end.reason)) sub.push(n.end.text);
  if (kids.length && collapsed) sub.push(`${countLeaves(T, n)} paths folded`);
  const line2 = el("div", { class: "psub" }, sub.join("  ·  "));
  if (!kids.length && n.example && Object.keys(n.example).length)
    line2.append(el("span", { class: "ex" }, (sub.length ? "  ·  " : "") + "e.g. " + fmtWitness(n.example)));
  row.append(line2);
  row.addEventListener("click", () => selectPathNode(n.id));

  const node = el("div", { class: "pnode" }, row);
  if (kids.length && !collapsed) {
    const box = el("div", { class: "pkids" });
    kids.forEach(k => box.append(el("div", { class: "pkid" + (T.toHit.has(k.id) ? " tohit" : "") }, renderPathNode(T, k, snap))));
    node.append(box);
  }
  return node;
}
const countLeaves = (T, n) => (T.kids[n.id] || []).reduce((a, k) => a + (T.kids[k.id] ? countLeaves(T, k) : 1), 0);

function lineRanges(lines) {
  // keep execution order, but merge runs of consecutive numbers: 33, 34, 35 -> 33–35
  const out = [];
  for (const ln of lines) {
    const last = out[out.length - 1];
    if (last && ln === last[1] + 1) last[1] = ln; else out.push([ln, ln]);
  }
  return (out.length === 1 && out[0][0] === out[0][1] ? "line " : "lines ") +
    out.map(([a, b]) => a === b ? a : `${a}–${b}`).join(", ");
}

function selectPathNode(id) {
  A.selNode = A.selNode === id ? null : id;
  updatePathHighlight();
  renderTree(true);
}

function updatePathHighlight() {
  // the blocks executed from the function entry down to the selected node
  const snap = A.run?.snapshot;
  A.pathHighlight = null;
  if (snap && snap.tree && A.selNode != null) {
    const T = pathModel(snap);
    if (T.byId[A.selNode]) A.pathHighlight = new Set(T.chain(A.selNode).flatMap(n => n.blocks));
  }
  highlightHits();
  if ($("#pane-decomp").classList.contains("sel")) renderDecomp();   // re-tint decompilation lines (cached, no refetch)
  const cfgPane = $("#pane-cfg");
  if (cfgPane.classList.contains("sel")) renderCFG(true); else cfgPane.dataset.stale = "1";
}

function renderPathDetail(T, snap) {
  const n = T.byId[A.selNode];
  if (!n) return el("div", { class: "empty" }, "Click a row to see the whole path: every condition on the way, what ran, and how it ended.");
  const chain = T.chain(n.id);
  const leaf = !T.kids[n.id];
  const d = el("div", { class: "pdetail" });
  d.append(el("div", { class: "row" },
    el("h4", { class: "grow" }, leaf ? `Path #${T.leafNo[n.id]}` : (n.parent === null ? "Function entry" : "Partial path (splits further below)")),
    el("button", { class: "tiny ghost", onclick: () => selectPathNode(n.id) }, "✕")));

  const conds = chain.filter(c => c.parent !== null);
  const asm = snap.summary?.assumptions_applied || [];
  d.append(el("div", { class: "dlabel" }, conds.length || asm.length ? "To get here the inputs must satisfy all of" : "No conditions: every run starts here"));
  asm.forEach(a => d.append(el("div", { class: "dcond" }, el("span", { class: "cond" }, a), el("span", { class: "where" }, "your assumption"))));
  conds.forEach(c => d.append(el("div", { class: "dcond" }, el("span", { class: "cond" }, c.cond || "?"),
    c.decided_at?.line ? el("span", { class: "where" }, `${c.decided_at.file}:${c.decided_at.line}  ${c.decided_at.text || ""}`) : null)));

  const text = {};
  (A.detail?.disasm?.source?.rows || []).forEach(r => { text[r.n] = r.text; });
  const allLines = chain.flatMap(c => c.lines);
  if (allLines.length) {
    d.append(el("div", { class: "dlabel" }, "Source lines executed, in order"));
    const src = el("div", { class: "dsrc" });
    const seen = new Set();
    allLines.forEach(ln => {
      if (seen.has(ln)) return;
      seen.add(ln);
      src.append(el("div", {}, el("span", { class: "ln" }, ln), el("span", {}, (text[ln] ?? "").trim() || "(in a called function)")));
    });
    d.append(src);
  }
  const calls = [...new Set(chain.flatMap(c => c.calls))];
  if (calls.length) d.append(el("div", { class: "dlabel" }, "Calls  ",
    el("span", { class: "mono", style: "text-transform:none;color:var(--ink);letter-spacing:0" }, calls.map(c => c + "()").join(", "))));

  if (leaf) {
    d.append(el("div", { class: "dlabel" }, "How it ended"));
    d.append(el("div", { class: "dend" }, n.end ? n.end.text + (n.end.reason === "returned" && n.ret ? ": " + n.ret : "")
      : (leafReason(n, snap) === "running" ? "still running" : "not finished")));
    if (n.example && Object.keys(n.example).length) {
      d.append(el("div", { class: "dlabel" }, "Example input that takes this path"));
      const tb = el("div", { class: "dex" });
      Object.entries(n.example).forEach(([k, v]) => tb.append(el("div", {}, el("span", { class: "k" }, k), el("span", {}, fmtOne(k, v)))));
      d.append(tb);
    }
  }
  const hits = chain.flatMap(c => c.hits);
  if (hits.length) {
    d.append(el("div", { class: "dlabel" }, "Findings on this path"));
    hits.forEach(i => { const h = snap.hits[i]; if (h) d.append(renderHit(h, i)); });
  }
  d.append(el("div", { class: "row", style: "margin-top:14px;gap:6px" },
    el("button", { class: "tiny", onclick: () => { selectTab("code"); scrollToAddr(n.blocks[0] ?? n.addr); } }, "Show in code"),
    el("button", { class: "tiny", onclick: () => selectTab("cfg") }, "Show on control-flow graph")));
  return d;
}

// ---------------------------------------------------------------- value formatting
function fmtOne(name, v) {
  if (typeof v === "string") return bytesPretty(v);            // stdin, hex-encoded bytes
  if (!v || !v.hex) return String(v);
  if (v.bits > 64) return bytesPretty(BigInt(v.hex).toString(16).padStart(v.bits / 4, "0"));
  const arg = A.config?.args.find(a => a.name === name);
  const signed = arg ? arg.signed !== false : false;
  const u = BigInt(v.hex), top = 1n << BigInt(v.bits - 1);
  const s = signed && u >= top ? u - (1n << BigInt(v.bits)) : u;
  const abs = s < 0n ? -s : s;
  return abs < 100000n ? s.toString() : v.hex + (signed && s < 0n ? ` (${s})` : "");
}
function fmtWitness(w) {
  return Object.entries(w).map(([k, v]) => `${k}=${fmtOne(k, v)}`).join(", ");
}
function bytesPretty(hex) {
  let out = "";
  for (let i = 0; i < hex.length; i += 2) {
    const b = parseInt(hex.slice(i, i + 2), 16);
    out += b >= 0x20 && b < 0x7f && b !== 0x5c && b !== 0x22 ? String.fromCharCode(b) : "\\x" + hex.slice(i, i + 2);
  }
  return '"' + out + '"';
}
const esc = (t) => String(t).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// ---------------------------------------------------------------- decompilation overlay
const _DECOMP_MARK = /\s*\/\*(0x[0-9a-fA-F]+)\*\/\s*$/;
function stripMarks(code) { return (code || "").replace(/\s*\/\*0x[0-9a-fA-F]+\*\/\s*$/gm, ""); }
function decompAddrBlock() {
  const m = {};
  for (const ins of (A.detail && A.detail.disasm ? A.detail.disasm.instructions : [])) m[ins.addr] = ins.block;
  return m;
}
function renderDecompLines(code, into) {
  const a2b = decompAddrBlock();
  const path = A.pathHighlight;                       // Set of block addrs, or null
  const hits = new Set((A.run && A.run.snapshot ? A.run.snapshot.hits : []).map(h => h.addr));
  const hitBlocks = new Set([...hits].map(a => a2b[a]).filter(b => b != null));
  for (const raw of code.split("\n")) {
    const m = _DECOMP_MARK.exec(raw);
    const addr = m ? parseInt(m[1], 16) : null;
    const text = m ? raw.slice(0, m.index) : raw;
    const div = el("div", { class: "cline" });
    if (addr != null) {
      div.dataset.addr = addr;
      div.title = hx64(addr);
      const blk = a2b[addr];
      if (path && blk != null && path.has(blk)) div.classList.add("onpath");
      if (hits.has(addr) || (blk != null && hitBlocks.has(blk))) div.classList.add("hitline");
      div.addEventListener("click", () => { selectTab("code"); scrollToAddr(addr); });
    }
    highlightC(text.length ? text : " ", div);
    into.append(div);
  }
}

// ==================================================================== angr script
let scriptSeq = 0;
async function renderScript() {
  const pane = $("#pane-script");
  if (!A.fn) { pane.innerHTML = '<div class="empty">Select a function to see its setup as an angr script.</div>'; return; }
  const seq = ++scriptSeq;
  let code;
  try { code = (await jpost("/api/script", currentSpec())).code; }
  catch (e) { pane.innerHTML = '<div class="empty">Could not generate the script: ' + esc(e.message) + '</div>'; return; }
  if (seq !== scriptSeq) return;
  A.scriptCode = code;
  const keep = $(".scode", pane)?.scrollTop || 0;
  const pre = el("pre", { class: "scode" });
  highlightPython(code, pre);
  const bar = el("div", { class: "sbar" },
    el("div", { class: "grow", html:
      "Your setup as a standalone <b>angr</b> script, doing the same steps the GUI performs. It updates as you edit. " +
      "<span class='faint'>Initial state → <code>BVS</code> + <code>call_state</code> · assumptions → <code>add_constraints</code> · " +
      "overflow checks → an <code>inspect</code> breakpoint on every VEX expression · assert / reach / custom → checked on each new state after every step.</span>" }),
    el("button", { class: "tiny", onclick: () => navigator.clipboard.writeText(A.scriptCode).then(() => toast("copied")) }, "Copy"),
    el("button", { class: "tiny", onclick: downloadScript }, "Download .py"));
  pane.replaceChildren(el("div", { class: "swrap" }, bar, pre));
  pre.scrollTop = keep;
  if (A.scriptJump) { scrollScriptTo(A.scriptJump); A.scriptJump = null; }
}
function currentSpec() {
  return {
    func_addr: A.fn.addr, args: A.config.args, buffers: A.config.buffers,
    assumptions: A.config.assumptions.filter(x => x.trim()), stdin: A.config.stdin,
    checks: A.config.checks.filter(c => c.enabled), limits: A.config.limits,
  };
}
function downloadScript() {
  const a = el("a", { href: URL.createObjectURL(new Blob([A.scriptCode], { type: "text/x-python" })),
    download: `${A.fn.name}_angr.py` });
  document.body.append(a); a.click(); a.remove();
}
function scrollScriptTo(marker) {
  const pre = $("#pane-script .scode"); if (!pre || !A.scriptCode) return;
  const idx = A.scriptCode.split("\n").findIndex(l => l.includes(marker));
  if (idx >= 0) pre.scrollTop = Math.max(0, idx * 18 - 8);
}
function showInScript(marker) { A.scriptJump = marker; selectTab("script"); }

const PY_TOKEN = /(#[^\n]*)|("""[\s\S]*?"""|'''[\s\S]*?'''|f?"(?:\\.|[^"\\\n])*"|f?'(?:\\.|[^'\\\n])*')|\b(def|class|return|if|elif|else|for|while|in|not|and|or|import|from|as|None|True|False|is|lambda|try|except|continue|break|pass|with|global)\b|\b(0x[0-9a-fA-F]+|\d+(?:\.\d+)?)\b/g;
function highlightPython(code, into) {
  let last = 0, m;
  PY_TOKEN.lastIndex = 0;
  while ((m = PY_TOKEN.exec(code))) {
    if (m.index > last) into.append(document.createTextNode(code.slice(last, m.index)));
    into.append(el("span", { class: "py-" + (m[1] ? "c" : m[2] ? "s" : m[3] ? "k" : "n") }, m[0]));
    last = PY_TOKEN.lastIndex;
  }
  into.append(document.createTextNode(code.slice(last)));
}

// ==================================================================== IDA MCP
async function refreshIdaStatus() {
  try { A.ida = await api("/api/ida/status"); } catch (e) { A.ida = { connected: false }; }
  updateIdaBtn();
}
function updateIdaBtn() {
  const b = $("#idaBtn");
  if (A.ida && A.ida.connected) {
    b.classList.add("on");
    b.textContent = "IDA: " + (A.ida.server || "on") + (A.ida.name_count ? ` (${A.ida.name_count})` : "");
  } else { b.classList.remove("on"); b.textContent = "IDA: off"; }
}
function openIdaModal() {
  let url = "";
  try { url = localStorage.getItem("idaUrl") || ""; } catch (e) {}
  const input = el("input", { value: url, placeholder: "http://<vm-ip>:8744/mcp", style: "width:100%" });
  const status = el("div", { class: "faint mono", style: "font-size:11px;margin-top:6px" },
    A.ida && A.ida.connected ? `connected · ${A.ida.server || ""} · ${A.ida.flavor || ""} · ${A.ida.name_count || 0} names` : "not connected");
  const body = el("div", {},
    field("IDA MCP server URL", input,
      "Point at a running IDA MCP server. Official Hex-Rays: <code>http://127.0.0.1:8737/mcp</code> (IDA ≥9.4). " +
      "Community <b>mrexodia/ida-pro-mcp</b>: run its bridge, e.g. <code>http://&lt;vm-ip&gt;:8744/mcp</code> (IDA ≥8.3). " +
      "The binary open in IDA must be the same one loaded here."),
    status);
  const connect = el("button", { class: "primary", onclick: async () => {
    const u = input.value.trim(); if (!u) { toast("enter a URL", true); return; }
    try { localStorage.setItem("idaUrl", u); } catch (e) {}
    connect.disabled = true; connect.textContent = "Connecting…";
    try {
      A.ida = await jpost("/api/ida/connect", { url: u });
      updateIdaBtn();
      await loadFunctions();
      if (A.fn) renderDecomp();
      toast(`IDA connected: ${A.ida.name_count} names`);
      m.remove();
    } catch (e) { toast("connect failed: " + e.message, true); connect.disabled = false; connect.textContent = "Connect"; }
  } }, "Connect");
  const foot = [connect];
  if (A.ida && A.ida.connected) {
    foot.unshift(el("button", { onclick: async () => {
      await jpost("/api/ida/disconnect", {}); A.ida = { connected: false }; updateIdaBtn(); await loadFunctions(); m.remove(); toast("IDA disconnected");
    } }, "Disconnect"));
    // re-pull names + decompilation after you change or reload something in IDA
    foot.unshift(el("button", { class: "primary", onclick: async () => { m.remove(); await refreshIda(); } }, "↻ Refresh from IDA"));
  }
  foot.unshift(el("button", { onclick: () => m.remove() }, "Close"));
  const m = modal("Connect to IDA", body, foot);
  $("#modalHost").append(m);
  setTimeout(() => input.focus(), 50);
}

// ==================================================================== decompilation
async function renderDecomp(force) {
  const pane = $("#pane-decomp");
  if (!A.fn) { pane.innerHTML = '<div class="empty">Select a function.</div>'; return; }
  if (!A.ida || !A.ida.connected) {
    pane.replaceChildren(el("div", { class: "empty" },
      "Not connected to IDA. ", el("button", { class: "tiny", onclick: openIdaModal }, "Connect to IDA"),
      el("div", { style: "margin-top:8px" }, "Then IDA's decompilation of the selected function shows here.")));
    return;
  }
  let d = A.decompCache[A.fn.addr];
  if (!d || force) {
    pane.innerHTML = '<div class="empty">Decompiling ' + esc(A.fn.name) + '…</div>';
    try { d = await api("/api/ida/decompile/" + A.fn.addr + (force ? "?force=1" : "")); }
    catch (e) { pane.innerHTML = '<div class="empty">Decompile failed: ' + esc(e.message) + '</div>'; return; }
    A.decompCache[A.fn.addr] = d;
  }
  A._assume = assumeModel();
  // IDA decompiles the function containing the address; show the function IDA
  // actually returned, and flag it when angr's function boundary differs.
  const idaFn = d.func || (A.fn.ida_name || A.fn.name);
  const bar = el("div", { class: "decompbar" },
    el("span", {}, "IDA · "),
    el("span", { class: "fn" }, idaFn + (d.func_start != null ? "  " + hx64(d.func_start) : "")),
    el("span", { class: "grow" }),
    d.kind && d.kind !== "pseudocode" ? el("span", { class: "pill warn" }, d.kind) : null,
    el("button", { class: "tiny", title: "re-pull names + decompilation from IDA", onclick: refreshIda }, "↻ Refresh"),
    el("button", { class: "tiny", onclick: () => navigator.clipboard.writeText(stripMarks(d.code)).then(() => toast("copied")) }, "Copy"));
  const pre = el("pre", { class: "ccode" });
  if (d.mismatch) pre.append(el("div", { class: "pill warn", style: "display:block;margin-bottom:8px;white-space:normal" },
    `angr selected ${A.fn.name} (${hx64(A.fn.addr)}), but IDA has that address inside ${idaFn}` +
    (d.func_start != null ? ` (${hx64(d.func_start)})` : "") + " — showing IDA's function."));
  renderDecompLines(d.code || "(empty)", pre);
  if (d.note) pre.prepend(el("div", { class: "faint", style: "margin-bottom:6px" }, d.note));
  pane.replaceChildren(el("div", { class: "decompwrap" }, bar, assumptionsBar(), pre));
}

async function refreshIda() {
  try {
    A.ida = await jpost("/api/ida/refresh", {});
    A.decompCache = {};                       // drop the client-side pseudocode cache too
    updateIdaBtn();
    await loadFunctions();
    if (A.fn) {
      const nf = A.functions.find(f => f.addr === A.fn.addr);
      if (nf) A.fn = nf;                     // pick up the refreshed ida_name
      renderRight();                          // right-panel title
      renderFunctions();                      // left-list selection label
      if ($("#pane-decomp").classList.contains("sel")) renderDecomp(true);
    }
    toast(`refreshed from IDA (${A.ida.name_count} names)`);
  } catch (e) { toast("refresh failed: " + e.message, true); }
}
const C_TOKEN = /(\/\*[\s\S]*?\*\/|\/\/[^\n]*)|\b(if|else|while|for|do|return|switch|case|break|continue|goto|default|sizeof)\b|\b(__int64|__int32|__int16|__int8|int|char|short|long|unsigned|signed|void|bool|float|double|_BYTE|_WORD|_DWORD|_QWORD|__fastcall|__cdecl|__stdcall|struct|const)\b/g;
function highlightC(code, into) {
  let last = 0, m;
  C_TOKEN.lastIndex = 0;
  while ((m = C_TOKEN.exec(code))) {
    if (m.index > last) into.append(annotate(code.slice(last, m.index)));
    into.append(el("span", { class: m[1] ? "cm" : m[2] ? "kw" : "ty" }, m[0]));
    last = C_TOKEN.lastIndex;
  }
  into.append(annotate(code.slice(last)));
}

// ==================================================================== assumptions overlay
// Show the function's assumptions above every view, colour-coded, and tint the
// variables they mention wherever those tokens appear (decompilation, disassembly).
// a1 (IDA's parameter name) <-> arg0 (ours) <-> the name you gave the arg are aliased,
// so an assumption written with any of them lights up whichever the view shows.
const ASSUME_COLORS = ["#f0883e", "#3fb950", "#a371f7", "#58a6ff", "#f778ba", "#e3b341", "#39c5cf", "#db6d28"];
const _EXPR_FUNCS = new Set(["u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "mem", "zext", "sext", "bv", "ret", "true", "false"]);

function exprVars(expr) {
  const out = new Set(); let m; const re = /[A-Za-z_]\w*/g;
  while ((m = re.exec(expr || ""))) if (!_EXPR_FUNCS.has(m[0])) out.add(m[0]);
  return out;
}
function aliasesOf(v) {
  const out = new Set([v]);
  const args = (A.config && A.config.args) || [];
  let idx = args.findIndex(a => a.name === v);
  const ma = /^a(\d+)$/.exec(v), mg = /^arg(\d+)$/.exec(v);
  if (idx < 0 && ma) idx = +ma[1] - 1;
  if (idx < 0 && mg) idx = +mg[1];
  if (idx >= 0) { out.add("a" + (idx + 1)); out.add("arg" + idx); if (args[idx] && args[idx].name) out.add(args[idx].name); }
  return out;
}
function assumeModel() {
  const list = ((A.config && A.config.assumptions) || [])
    .map((e, i) => ({ expr: (e || "").trim(), i, color: ASSUME_COLORS[i % ASSUME_COLORS.length], vars: exprVars(e) }))
    .filter(a => a.expr);
  const tok = {};                         // token text -> [assumption, ...]
  for (const a of list) {
    a.tokens = new Set();
    for (const v of a.vars) for (const t of aliasesOf(v)) { a.tokens.add(t); (tok[t] = tok[t] || []).push(a); }
  }
  return { list, tok };
}
function assumptionsBar() {
  A._assume = assumeModel();
  const { list } = A._assume;
  if (!list.length) return null;
  const bar = el("div", { class: "assumebar" }, el("span", { class: "albl" }, "assuming"));
  for (const a of list)
    bar.append(el("span", { class: "achip", style: `--ac:${a.color}`,
      title: (a.vars.size > 1 ? "involves " : "on ") + [...a.vars].join(", ") }, a.expr));
  return bar;
}
function annotate(text) {                  // wrap tokens that appear in an assumption
  const tok = (A._assume || assumeModel()).tok;
  const frag = document.createDocumentFragment();
  let last = 0, m; const re = /[A-Za-z_]\w*/g;
  while ((m = re.exec(text))) {
    const hits = tok[m[0]];
    if (!hits) continue;
    if (m.index > last) frag.append(document.createTextNode(text.slice(last, m.index)));
    frag.append(el("span", { class: "avar", style: `--ac:${hits[0].color}`,
      title: hits.map(a => a.expr).join("  ;  ") }, m[0]));
    last = re.lastIndex;
  }
  frag.append(document.createTextNode(text.slice(last)));
  return frag;
}
function refreshAssumptionViews() {
  A._assume = assumeModel();
  const sel = $(".tab.sel");
  const active = sel ? sel.dataset.tab : null;
  if (active === "code") renderCode();
  else if (active === "decomp") renderDecomp();
  else if (active === "cfg") renderCFG(true);
}
let assumeTimer = null;
function scheduleAssumeRefresh() { clearTimeout(assumeTimer); assumeTimer = setTimeout(refreshAssumptionViews, 350); }

// ==================================================================== live activity feed
// Subscribe to the backend event bus. Every action — yours or an agent's over MCP —
// arrives here, so when an agent sets assumptions or runs a check you watch it happen.
function connectEvents() {
  try {
    const es = new EventSource("/api/events");
    es.onopen = () => setLiveDot(true);
    es.onerror = () => setLiveDot(false);
    es.onmessage = (m) => { try { handleEvent(JSON.parse(m.data)); } catch (e) {} };
    A._es = es;
  } catch (e) {}
}
function setLiveDot(on) { const b = $("#actBtn"); if (b) b.classList.toggle("live", on); }

function handleEvent(ev) {
  A.activity.unshift(ev);
  if (A.activity.length > 120) A.activity.pop();
  if (!A.actOpen) { A._actUnseen = (A._actUnseen || 0) + 1; }
  renderActivity();
  if (ev.type === "config" && ev.func != null) onAgentConfig(ev.func);
  else if (ev.type === "run" && ev.func != null) onAgentRun(ev);
  else if (ev.type === "ida") refreshIdaStatus();
  else if (ev.type === "load") refreshState();
}

async function onAgentConfig(addr) {
  await loadFunctions();
  if (A.followAgent && (!A.fn || A.fn.addr !== addr)) {
    const f = A.functions.find(x => x.addr === addr);
    if (f) { await selectFunction(f); return; }
  }
  if (A.fn && A.fn.addr === addr) await reloadDetail();
}
async function reloadDetail() {
  try {
    const d = await api("/api/function/" + A.fn.addr);
    A.detail = d; A.config = normalizeConfig(d.config, d);
    renderRight(); refreshAssumptionViews();
  } catch (e) {}
}
async function onAgentRun(ev) {
  if (!A.followAgent) { toast(ev.message || "agent started a run"); return; }
  const f = A.functions.find(x => x.addr === ev.func);
  if (f && (!A.fn || A.fn.addr !== ev.func)) await selectFunction(f);
  A.run = { id: ev.run_id, snapshot: { status: "pending", progress: { message: "agent run" } } };
  A.selNode = null; A.pathHighlight = null; A.collapsed.clear();
  renderRight(); startPolling(); selectTab("paths");
}

function renderActivity() {
  const log = $("#actLog"); if (!log) return;
  log.replaceChildren();
  if (!A.activity.length) { log.append(el("div", { class: "faint", style: "padding:10px" }, "No activity yet.")); return; }
  for (const ev of A.activity.slice(0, 60)) {
    const t = new Date((ev.ts || 0) * 1000).toLocaleTimeString();
    log.append(el("div", { class: "actrow " + ev.type },
      el("span", { class: "actdot" }),
      el("span", { class: "acttime" }, t),
      el("span", { class: "actmsg" }, ev.message || ev.type)));
  }
  const badge = $("#actBadge");
  if (badge) { badge.textContent = A._actUnseen || 0; badge.style.display = (!A.actOpen && A._actUnseen) ? "inline-block" : "none"; }
}
function toggleActivity() {
  A.actOpen = !A.actOpen;
  $("#actPanel").classList.toggle("open", A.actOpen);
  if (A.actOpen) { A._actUnseen = 0; renderActivity(); }
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
async function renderCFG(force) {
  const pane = $("#pane-cfg");
  if (!A.fn) { pane.innerHTML = '<div class="empty">Select a function.</div>'; return; }
  if (!force && !pane.classList.contains("sel") && pane.dataset.addr == A.fn.addr) return;
  pane.dataset.stale = "";
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
  const pathBlocks = A.pathHighlight || new Set();
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
    <path d="M0,0 L7,3 L0,6 Z" fill="#4c9aff"/></marker></defs>`;
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
    p.setAttribute("stroke", hiEdge ? "#4c9aff" : color);
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
    A.pathHighlight ? el("span", { class: "pill info" }, "selected path highlighted (blue)") : el("span", { class: "faint", style: "font-size:11px" }, "select a row in Paths, or a finding, to trace its path here"));
  holder.append(toolbar, svg);
  const abar = assumptionsBar();
  pane.replaceChildren(...(abar ? [abar] : []), holder);
  // bring the highlighted path into view
  const on = gr.nodes().filter(id => pathBlocks.has(+id)).map(id => gr.node(id));
  if (on.length) {
    const minX = Math.min(...on.map(n => n.x - n.width / 2)), maxX = Math.max(...on.map(n => n.x + n.width / 2));
    const minY = Math.min(...on.map(n => n.y - n.height / 2));
    holder.scrollLeft = Math.max(0, (minX + maxX) / 2 - holder.clientWidth / 2);
    holder.scrollTop = Math.max(0, minY - 40);
  }
}
