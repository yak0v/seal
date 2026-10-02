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
  func: null,        // structured per-function setup {checks, scenarios[], active}
  config: null,      // live view onto the active scenario (+ shared checks)
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
  $("#themeBtn").addEventListener("click", openThemeMenu);
  $("#docsBtn").addEventListener("click", openDocsModal);
  $("#leftCollapse").addEventListener("click", () => setPanelCollapsed("left", true));
  $("#rightCollapse").addEventListener("click", () => setPanelCollapsed("right", true));
  $("#leftExpand").addEventListener("click", () => setPanelCollapsed("left", false));
  $("#rightExpand").addEventListener("click", () => setPanelCollapsed("right", false));
  ["left", "right"].forEach(s => { try { if (localStorage.getItem("collapse:" + s) === "1") setPanelCollapsed(s, true); } catch (e) {} });
  $("#followChk").addEventListener("change", e => { A.followAgent = e.target.checked; });
  $("#bottomClose").addEventListener("click", () => {
    const bp = $("#bottomPanel"); bp.classList.toggle("collapsed");
    $("#bottomClose").textContent = bp.classList.contains("collapsed") ? "▴" : "▾";
  });
  applyTheme();
  initSplitters();
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
      A.fn = A.detail = A.config = A.func = A.run = null;
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
  // after a page reload, re-open the function you were on (restores its run/paths)
  if (!A.fn) {
    let last = null;
    try { last = +localStorage.getItem("lastFn:" + (A.binary && A.binary.name)); } catch (e) {}
    const f = last && A.functions.find(x => x.addr === last);
    if (f) selectFunction(f);
  }
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
  try { localStorage.setItem("lastFn:" + (A.binary && A.binary.name), f.addr); } catch (e) {}
  stopPolling();
  renderFunctions();
  $("#pane-code").innerHTML = '<div class="empty">Loading…</div>';
  const d = await api("/api/function/" + f.addr);
  A.detail = d;
  A.func = normalizeFunc(d.config); bindConfig(); A._vars = null;
  // re-attach the most recent run for this function (survives a page reload)
  if (d.last_run) {
    try {
      const snap = await api("/api/run/" + d.last_run);
      A.run = { id: d.last_run, snapshot: snap };
      if (["pending", "running"].includes(snap.status)) startPolling();
    } catch (e) { A.run = null; }
  }
  renderCode();
  renderRight();
  selectTab(A.ida && A.ida.connected ? "decomp" : "code");   // decompilation is the main view when IDA is on
  renderDock();                                               // graph + paths, always visible
}

// The function's setup is structured as shared `checks` plus a list of
// `scenarios` (each one a different way of reaching the function, with its own
// initial state). A.func holds the structure; A.config is a live view onto the
// active scenario, with the shared checks array exposed as A.config.checks so
// all the existing per-field editors keep working unchanged.
const SCEN_FIELDS = ["name", "args", "buffers", "assumptions", "stdin", "files", "limits"];
function normalizeScenario(s, i) {
  s = s || {};
  s.name = s.name || ("Scenario " + (i + 1));
  s.args = s.args || [];
  s.buffers = s.buffers || [];
  s.assumptions = s.assumptions || [];
  s.stdin = s.stdin || null;
  s.files = s.files || [];
  s.limits = Object.assign({ steps: 150, active: 300, seconds: 30, loop_bound: 12, find: null, avoid: [] }, s.limits || {});
  return s;
}
function normalizeFunc(cfg) {
  cfg = cfg || {};
  if (!cfg.scenarios || !cfg.scenarios.length) {       // legacy flat -> one scenario
    cfg = { checks: cfg.checks || [], active: 0, scenarios: [{
      name: "Default", args: cfg.args, buffers: cfg.buffers, assumptions: cfg.assumptions,
      stdin: cfg.stdin, files: cfg.files, limits: cfg.limits }] };
  }
  cfg.checks = cfg.checks || [];
  cfg.scenarios.forEach((s, i) => normalizeScenario(s, i));
  cfg.active = Math.max(0, Math.min(cfg.active || 0, cfg.scenarios.length - 1));
  return cfg;
}
function bindConfig() {                                 // expose active scenario (+ shared checks) as A.config
  const sc = A.func.scenarios[A.func.active];
  sc.checks = A.func.checks;
  A.config = sc;
}
function scenarioCopy(s) {                              // deep-copy only the initial-state fields (no checks)
  const o = {};
  for (const k of SCEN_FIELDS) o[k] = JSON.parse(JSON.stringify(k === "name" ? s[k] : (s[k] ?? null)));
  return o;
}
function structPayload() {
  return { checks: A.func.checks, active: A.func.active,
           scenarios: A.func.scenarios.map(scenarioCopy) };
}

function switchScenario(i) {
  if (i === A.func.active) return;
  A.func.active = Math.max(0, Math.min(i, A.func.scenarios.length - 1));
  bindConfig(); A._vars = null;
  renderRight(); refreshAssumptionViews(); saveConfig();
  toast("scenario: " + A.config.name);
}
function addScenario(duplicate) {
  const base = duplicate ? scenarioCopy(A.config) : normalizeScenario({}, A.func.scenarios.length);
  base.name = duplicate ? (A.config.name + " copy") : ("Scenario " + (A.func.scenarios.length + 1));
  A.func.scenarios.push(base);
  switchScenario(A.func.scenarios.length - 1);
}
function deleteScenario(i) {
  if (A.func.scenarios.length <= 1) { toast("a function needs at least one scenario", true); return; }
  A.func.scenarios.splice(i, 1);
  A.func.active = Math.min(A.func.active, A.func.scenarios.length - 1);
  bindConfig(); A._vars = null; renderRight(); refreshAssumptionViews(); saveConfig();
}
function renameScenario(i, name) {
  A.func.scenarios[i].name = name.trim() || A.func.scenarios[i].name;
  saveConfig(); renderRight();
  if ($("#pane-decomp") && $("#pane-decomp").classList.contains("sel")) renderDecomp();
}

async function saveConfig() {
  if (!A.fn) return;
  try { await jput(`/api/function/${A.fn.addr}/config`, structPayload()); }
  catch (e) { toast("save failed: " + e.message, true); }
  if ($("#pane-script").classList.contains("sel")) renderScript();
  const f = A.functions.find(x => x.addr === A.fn.addr);
  if (f) { f.check_count = A.func.checks.length; f.configured = true; f.scenario_count = A.func.scenarios.length; renderFunctions(); }
}

// export the active scenario — its setup, the shared checks, and the latest run's
// findings + paths — to a JSON file for later investigation or sharing with an agent.
function hitExport(h) {
  return { kind: h.kind, addr: h.addr != null ? hx64(h.addr) : null, message: h.message,
           witness: h.witness, src_line: h.extra && h.extra.src_line };
}
function exportScenario() {
  const sc = A.config, snap = A.run && A.run.snapshot;
  const payload = {
    tool: "seal", exported_at: new Date().toISOString(),
    binary: A.binary ? { name: A.binary.name, path: A.binary.path, arch: A.binary.arch, bits: A.binary.bits } : null,
    function: A.fn ? { addr: hx64(A.fn.addr), name: A.fn.ida_name || A.fn.name } : null,
    scenario: sc ? { name: sc.name, args: sc.args, buffers: sc.buffers,
                     assumptions: (sc.assumptions || []).filter(x => x && x.trim()),
                     stdin: sc.stdin, files: sc.files, limits: sc.limits } : null,
    checks: (A.func && A.func.checks) || [],
    run: snap ? {
      id: A.run.id, status: snap.status,
      findings: (snap.hits || []).map(hitExport),
      paths: (snap.tree || []).map(n => ({ id: n.id, parent: n.parent, cond: n.cond,
        end: (n.end || {}).reason, ret: n.ret, example: n.example, hits: n.hits })),
    } : null,
  };
  const fname = `${(A.fn && (A.fn.ida_name || A.fn.name)) || "function"}.${(sc && sc.name) || "scenario"}.angrgui.json`
    .replace(/[^\w.\-]/g, "_");
  const a = el("a", { href: URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" })), download: fname });
  document.body.append(a); a.click(); a.remove();
  toast("exported " + fname + (snap ? " (with results)" : " (no run yet)"));
}

// ------------------------------------------------------------------ scenarios UI
function scenarioChip(cls) {                            // a clickable pill: active scenario + switcher
  const n = A.func ? A.func.scenarios.length : 1;
  return el("button", { class: "scenchip " + (cls || ""), title: "switch or manage scenarios",
    onclick: (e) => { e.stopPropagation(); openScenarioMenu(e.currentTarget); } },
    el("span", { class: "scdot" }), A.config.name,
    n > 1 ? el("span", { class: "sccount" }, n) : null, el("span", { class: "sccar" }, "▾"));
}
function scenarioTitle() {
  const frag = document.createDocumentFragment();
  frag.append(el("span", { class: "rfn" }, A.fn.ida_name || A.fn.name), scenarioChip("intitle"));
  return frag;
}
function openScenarioMenu(anchor) {
  if ($("#scenMenu")) { $("#scenMenu").remove(); return; }
  const m = el("div", { class: "popmenu scenmenu", id: "scenMenu" });
  m.append(el("div", { class: "vmlbl", style: "padding:2px 6px 4px" }, "scenarios of " + (A.fn.ida_name || A.fn.name)));
  A.func.scenarios.forEach((s, i) => {
    const row = el("div", { class: "popitem scrow" + (i === A.func.active ? " on" : "") },
      el("span", { class: "scdot" }),
      el("span", { class: "grow scname", title: "switch to this scenario", onclick: () => { m.remove(); switchScenario(i); } }, s.name),
      i === A.func.active ? el("span", { class: "chk" }, "✓") : null,
      el("button", { class: "tiny ghost scact", title: "rename", onclick: (e) => { e.stopPropagation(); startRename(row, i); } }, "✎"),
      A.func.scenarios.length > 1 ? el("button", { class: "tiny ghost scact", title: "delete", onclick: (e) => { e.stopPropagation(); m.remove(); deleteScenario(i); } }, "✕") : null);
    m.append(row);
  });
  m.append(el("div", { class: "popsep" }));
  m.append(el("div", { class: "popitem add", onclick: () => { m.remove(); addScenario(false); } }, "+ New scenario"));
  m.append(el("div", { class: "popitem add", onclick: () => { m.remove(); addScenario(true); } }, "⎘ Duplicate current"));
  m.append(el("div", { class: "popitem add", onclick: () => { m.remove(); exportScenario(); } }, "⤓ Export scenario + results"));
  document.body.append(m);
  const r = anchor.getBoundingClientRect();
  m.style.top = Math.min(r.bottom + 6, window.innerHeight - m.offsetHeight - 10) + "px";
  m.style.left = Math.max(8, Math.min(r.left, window.innerWidth - m.offsetWidth - 10)) + "px";
  const close = (e) => { if (!m.contains(e.target) && e.target !== anchor && !anchor.contains(e.target)) { m.remove(); document.removeEventListener("mousedown", close); } };
  setTimeout(() => document.addEventListener("mousedown", close), 0);
}
function startRename(row, i) {
  const span = row.querySelector(".scname");
  const inp = el("input", { class: "screname", value: A.func.scenarios[i].name });
  span.replaceWith(inp); inp.focus(); inp.select();
  let done = false;
  const finish = (save) => { if (done) return; done = true; if (save) renameScenario(i, inp.value); $("#scenMenu") && $("#scenMenu").remove(); };
  inp.addEventListener("keydown", e => { if (e.key === "Enter") finish(true); if (e.key === "Escape") finish(false); });
  inp.addEventListener("blur", () => finish(true));
}
function scenarioBar() {                                // sits on top of the Initial state section
  return el("div", { class: "scenbar" },
    el("span", { class: "scenlbl" }, "scenario"),
    el("button", { class: "scensel", title: "switch or manage scenarios", onclick: (e) => openScenarioMenu(e.currentTarget) },
      el("span", { class: "scdot" }), el("span", { class: "grow" }, A.config.name),
      A.func.scenarios.length > 1 ? el("span", { class: "sccount" }, A.func.scenarios.length) : null,
      el("span", { class: "sccar" }, "▾")),
    el("button", { class: "tiny ghost", title: "add a new scenario", onclick: () => addScenario(false) }, "+"));
}

function selectTab(name) {
  // paths and the graph now live in the always-visible dock, not as tabs
  if (name === "paths" || name === "cfg") { renderDock(); return; }
  $$("#mainView .tab").forEach(t => t.classList.toggle("sel", t.dataset.tab === name));
  $$("#mainView .tabpane").forEach(p => p.classList.toggle("sel", p.id === "pane-" + name));
  if (name === "code" && A.detail) renderCode();
  if (name === "script") renderScript();
  if (name === "decomp") renderDecomp();
}

// the docked graph + paths, always visible beside the main code view
function renderDock() {
  renderPathGraph();
  renderTree(true);
}

// ==================================================================== code view
function renderCode() {
  const d = A.detail, di = d.disasm;
  const pane = $("#pane-code"); pane.replaceChildren();
  A._vars = varModel();
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
  const t = $("#rTitle"); t.replaceChildren(A.fn ? scenarioTitle() : document.createTextNode("Setup"));
  const body = $("#rBody"); body.replaceChildren();
  if (!A.fn) { body.append(el("div", { class: "empty" }, "Pick a function.")); return; }

  body.append(sectionState());
  body.append(sectionAssumptions());
  body.append(sectionModels());
  body.append(sectionChecks());
  body.append(sectionRun());
  body.append(sectionHits());
  $$(".sec", body).forEach(makeCollapsible);
}

// clicking a section header collapses/expands it (remembered per section)
function makeCollapsible(sec) {
  const h3 = sec.querySelector("h3"), bodyEl = sec.querySelector(".body");
  if (!h3 || !bodyEl) return;
  const key = "sec:" + ((h3.firstChild && h3.firstChild.textContent) || "").trim();
  let collapsed = false; try { collapsed = localStorage.getItem(key) === "1"; } catch (e) {}
  const chev = el("span", { class: "secchev" }, collapsed ? "▸" : "▾");
  h3.insertBefore(chev, h3.firstChild);
  if (collapsed) sec.classList.add("collapsed");
  h3.addEventListener("click", ev => {
    if (ev.target.closest("button") || ev.target.closest("input") || ev.target.closest("select")) return;
    const now = !sec.classList.contains("collapsed");
    sec.classList.toggle("collapsed", now);
    chev.textContent = now ? "▸" : "▾";
    try { localStorage.setItem(key, now ? "1" : "0"); } catch (e) {}
  });
}

function sectionState() {
  const s = el("div", { class: "sec" });
  s.append(el("h3", {}, "Initial state", el("span", { class: "grow" }),
    el("button", { class: "tiny ghost", title: "show this setup as angr code", onclick: () => showInScript("= initial state") }, "</> angr")));
  const b = el("div", { class: "body" });
  b.append(scenarioBar());                               // pick which scenario's initial state you're editing

  A.config.args.forEach((a, i) => {
    const nameI = el("input", { class: "name", value: a.name || ("arg" + i), oninput: e => { a.name = e.target.value; scheduleSave(); } });
    const setMode = m => { a.mode = m; renderRight(); scheduleSave(); };
    const modeS = el("div", { class: "seg" },
      el("div", { class: "segbtn" + (a.mode !== "concrete" ? " on" : ""), onclick: () => setMode("symbolic") }, "sym"),
      el("div", { class: "segbtn" + (a.mode === "concrete" ? " on" : ""), onclick: () => setMode("concrete") }, "fixed"));
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
    // float toggle: passes this argument in an SSE register as a symbolic float/double
    if (a.mode !== "concrete") {
      b.append(el("label", { class: "row", style: "font-size:11px;color:var(--faint);margin:-2px 0 8px 2px;gap:4px" },
        el("input", { type: "checkbox", checked: a.float ? "" : null, style: "width:auto",
          onchange: e => { a.float = e.target.checked; if (a.float && ![4, 8].includes(a.size)) a.size = 8; scheduleSave(); renderRight(); } }),
        "floating-point ", a.float ? el("span", { class: "faint" }, a.size === 4 ? "(float)" : "(double)") : el("span", { class: "faint" }, "(for float-point checks)")));
    }
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

  // symbolic files: the program reads a named file whose contents angr solves for
  (A.config.files || []).forEach((f, i) => {
    b.append(el("div", { class: "row", style: "font-size:12px;gap:5px;margin-top:4px" },
      el("span", { class: "faint" }, "file"),
      el("input", { value: f.name, placeholder: ".password", style: "flex:1;min-width:0", oninput: e => { f.name = e.target.value; scheduleSave(); } }),
      el("input", { value: f.size, style: "width:52px", oninput: e => { f.size = +e.target.value; scheduleSave(); } }),
      el("span", { class: "faint" }, "bytes"),
      btn("✕", () => { A.config.files.splice(i, 1); renderRight(); scheduleSave(); }, "tiny ghost")));
  });
  b.append(el("button", { class: "tiny", style: "margin-top:4px",
    title: "make a file's contents symbolic (angr solves for what it must contain)",
    onclick: () => { A.config.files = A.config.files || []; A.config.files.push({ name: "", size: 32 }); renderRight(); scheduleSave(); } }, "+ symbolic file"));
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
  A.config.assumptions.forEach((a, i) => {
    b.append(el("div", { class: "assume" },
      el("span", { class: "adot", style: `background:${ASSUME_COLORS[i % ASSUME_COLORS.length]}` }),
      el("input", { value: a, placeholder: "expression that must hold", oninput: e => { A.config.assumptions[i] = e.target.value; scheduleSave(); scheduleAssumeRefresh(); } }),
      btn("✕", () => { A.config.assumptions.splice(i, 1); renderRight(); scheduleSave(); refreshAssumptionViews(); }, "tiny ghost")));
  });
  s.append(b);
  return s;
}

// Call models (hooks): replace a function the target calls with a simple model, so
// it isn't stepped into (or skipped-to-unconstrained). Essential for cross-call bugs.
const MODEL_KIND_DESC = {
  symbolic: "returns a fresh symbolic value",
  concrete: "returns a constant",
  return_arg: "returns one of its arguments",
  alloc: "allocates a buffer sized by one arg (tracked for OOB-write)",
};
function describeModel(m) {
  if (m.kind === "concrete") return `→ ${m.value ?? 0}`;
  if (m.kind === "symbolic") return `→ symbolic ${m.name || "ret"}${m.bits ? " (" + m.bits + "b)" : ""}`;
  if (m.kind === "return_arg") return `→ arg${m.arg ?? 0}`;
  if (m.kind === "alloc") return `→ alloc(arg${m.size_arg ?? 0})${m.name ? " as " + m.name : ""}`;
  return "";
}
function sectionModels() {
  const s = el("div", { class: "sec" });
  s.append(el("h3", {}, "Call models", el("span", { class: "grow" }),
    btn("+ model", () => openModelModal(), "tiny")));
  const b = el("div", { class: "body" });
  const models = A.config.models || (A.config.models = []);
  if (!models.length) b.append(el("div", { class: "faint", style: "font-size:11px" },
    "Replace a function this one calls with a model, so it isn't stepped into. Needed for bugs that span library calls (e.g. model malloc + size functions, then check for OOB writes)."));
  models.forEach((m, i) => {
    b.append(el("div", { class: "modelrow" },
      el("span", { class: "mono mfn", title: MODEL_KIND_DESC[m.kind] || "" }, m.func || "(unset)"),
      el("span", { class: "msum" }, describeModel(m)),
      btn("✎", () => openModelModal(i), "tiny ghost"),
      btn("✕", () => { models.splice(i, 1); renderRight(); scheduleSave(); }, "tiny ghost")));
  });
  s.append(b);
  return s;
}
function openModelModal(editIdx) {
  const models = A.config.models || (A.config.models = []);
  const m = editIdx != null ? { ...models[editIdx] } : { kind: "symbolic", func: "" };
  const funcI = el("input", { value: m.func || "", placeholder: "function name or 0x…", style: "width:100%;box-sizing:border-box" });
  // suggestions: functions this one calls (from the disassembly's call targets)
  const dl = el("datalist", { id: "modelFuncs" });
  calledFunctionNames().forEach(n => dl.append(el("option", { value: n })));
  funcI.setAttribute("list", "modelFuncs");
  const kindS = el("select", {});
  Object.entries(MODEL_KIND_DESC).forEach(([k, d]) => kindS.append(el("option", { value: k, selected: m.kind === k ? "" : null }, k + " — " + d)));
  const params = el("div", { style: "margin-top:8px" });
  const rebuild = () => {
    params.replaceChildren();
    const k = kindS.value;
    if (k === "symbolic") {
      params.append(field("Symbol name (shows in witnesses)", el("input", { value: m.name || "", placeholder: "e.g. scanline_size", oninput: e => m.name = e.target.value })),
        field("Return width (bits)", el("input", { value: m.bits || 64, oninput: e => m.bits = parseIntLoose(e.target.value) || 64, style: "width:90px" })));
    } else if (k === "concrete") {
      params.append(field("Return value", el("input", { value: m.value ?? 0, oninput: e => m.value = parseIntLoose(e.target.value), style: "width:120px" }), "e.g. 0 for success, or a NULL/handle."));
    } else if (k === "return_arg") {
      params.append(field("Argument index", el("input", { value: m.arg ?? 0, oninput: e => m.arg = parseIntLoose(e.target.value), style: "width:90px" }), "0 = first argument."));
    } else if (k === "alloc") {
      params.append(field("Size argument index", el("input", { value: m.size_arg ?? 0, oninput: e => m.size_arg = parseIntLoose(e.target.value), style: "width:90px" }), "which argument holds the allocation size."),
        field("Name the pointer (optional)", el("input", { value: m.name || "", placeholder: "e.g. out_buf", oninput: e => m.name = e.target.value })));
    }
  };
  kindS.addEventListener("change", () => { m.kind = kindS.value; rebuild(); });
  rebuild();
  const body = el("div", {},
    field("Function to model", funcI, "A function the analysed function calls. Tip: angr's skip-calls bypasses models, so model every heavy call (reads/writes/allocs) to keep the run bounded."),
    field("Behavior", kindS), params);
  const mo = modal(editIdx != null ? "Edit call model" : "Add call model", body, [
    el("button", { onclick: () => mo.remove() }, "Cancel"),
    el("button", { class: "primary", onclick: () => {
      m.func = funcI.value.trim(); m.kind = kindS.value;
      if (!m.func) { toast("enter the function to model", true); return; }
      if (editIdx != null) models[editIdx] = m; else models.push(m);
      mo.remove(); renderRight(); scheduleSave();
    } }, editIdx != null ? "Save" : "Add model")]);
  $("#modalHost").append(mo);
}
function calledFunctionNames() {
  const names = new Set();
  const byAddr = {};
  (A.functions || []).forEach(f => byAddr[f.addr] = f.ida_name || f.name);
  for (const ins of (A.detail?.disasm?.instructions || [])) {
    if (/call/.test(ins.mnemonic) && /^0x[0-9a-f]+$/i.test((ins.op_str || "").trim())) {
      const t = parseInt(ins.op_str, 16); if (byAddr[t]) names.add(byAddr[t]);
    }
  }
  return [...names].sort();
}

function sectionChecks() {
  const s = el("div", { class: "sec" });
  s.append(el("h3", {}, "Checks", el("span", { class: "grow" }),
    el("button", { class: "tiny ghost", title: "show these checks as angr code", onclick: () => showInScript("= checks") }, "</>"),
    el("button", { class: "tiny", onclick: (e) => openDetectMenu(e.currentTarget) }, "+ detect ▾"),
    btn("+ assert", () => openAssertModal(null), "tiny"),
    btn("+ custom", () => openCustomModal(null), "tiny")));
  const b = el("div", { class: "body" });
  if (!A.config.checks.length) b.append(el("div", { class: "faint", style: "font-size:11px" }, "No checks yet. Use ", el("b", {}, "+ detect"), " for a bug class, ", el("b", {}, "+ assert"), " for an invariant, or add checks from the code view."));
  A.config.checks.forEach((c, i) => b.append(renderCheck(c, i)));
  s.append(b);
  return s;
}
function renderCheck(c, i) {
  const box = el("div", { class: "check" + (c.enabled ? "" : " dis") });
  const kindPill = { int_overflow: "warn", narrowing_cast: "warn", float_anomaly: "warn", oob_write: "bad",
                     assert: "warn", reach: "info", avoid: "warn", custom: "info" }[c.kind] || "info";
  box.append(el("div", { class: "top" },
    el("input", { type: "checkbox", checked: c.enabled ? "" : null, style: "width:auto", onchange: e => { c.enabled = e.target.checked; saveConfig(); renderRight(); } }),
    el("span", { class: "pill " + kindPill }, c.kind.replace("_", " ")),
    el("input", { class: "kind grow ckname", value: c.name || "", placeholder: "name…", title: "rename this check",
      oninput: e => { c.name = e.target.value; scheduleSave(); } }),
    c.addr ? btn("↧", () => showAddr(c.addr), "tiny ghost") : null,
    btn("✕", () => { A.config.checks.splice(i, 1); saveConfig(); renderRight(); }, "tiny ghost")));
  const desc = describeCheck(c);
  if (desc) box.append(el("div", { class: "desc" }, desc));
  return box;
}
function describeCheck(c) {
  if (c.kind === "int_overflow") return (c.addr ? hx64(c.addr) + "  " : "whole function  ") + "· " + (c.signed || "either") + (c.note ? "  · " + c.note : "");
  if (c.kind === "narrowing_cast") return (c.addr ? hx64(c.addr) : "whole function") + " · value truncated to a smaller int loses data";
  if (c.kind === "float_anomaly") return (c.addr ? hx64(c.addr) : "whole function") + " · result can be NaN / ±Inf";
  if (c.kind === "oob_write") return `write outside ${c.base}[${c.size}]` + (c.addr ? " at " + hx64(c.addr) : "");
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
  const runBtn = el("button", { class: "primary", style: "width:100%;padding:8px", onclick: startRun,
    title: "explore the paths; any enabled checks are watched for along the way" }, "▶  Explore paths");
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
  const wit = h.witness || {};
  const scalars = Object.entries(wit).filter(([k, v]) => typeof v === "object");
  const byteInputs = Object.entries(wit).filter(([k, v]) => typeof v === "string" && v);
  if (scalars.length) box.append(el("div", { class: "wit" }, "inputs: " + scalars.map(([k, v]) => `${k}=${fmtOne(k, v)}`).join(", ")));
  for (const [k, v] of byteInputs) {                 // file / stdin contents = the solution
    const label = k.startsWith("file:") ? k.slice(5) + " =" : k + " =";
    box.append(el("div", { class: "wit solution" }, label + " " + bytesPretty(v.replace(/(00)+$/, ""))));
  }
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
    const isBranch = !!A.branchPts && A.branchPts.has(+r.dataset.addr);
    r.classList.toggle("branchpt", isBranch);
    if (isBranch) r.title = "branch taken on this flow: " + (A.branchCond[+r.dataset.addr] || "?");
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
  const pane = $("#dockPaths"); if (!pane) return;
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
  const view = pathsView();
  const keepScroll = pane.scrollTop;
  const summary = pathsSummary(T, snap);
  summary.append(pathsViewToggle());
  pane.replaceChildren(checksBar(), summary);
  if (view === "tree") {
    pane.classList.add("treemode");
    const host = el("div", { class: "ptreegraph" });
    pane.append(host);
    drawPathTree(host, T, snap);
  } else {
    pane.classList.remove("treemode");
    const box = el("div", { class: "ptree" });
    T.roots.forEach(r => box.append(renderPathNode(T, r, snap)));
    pane.append(box);
    pane.scrollTop = keepScroll;
  }
  updateBottomDetail();
}
function pathsView() { try { return A.pathsView || (A.pathsView = localStorage.getItem("pathsView") || "list"); } catch (e) { return A.pathsView || "list"; } }
function pathsViewToggle() {
  const mk = (v, label) => el("div", { class: "segbtn" + (pathsView() === v ? " on" : ""),
    onclick: () => { A.pathsView = v; try { localStorage.setItem("pathsView", v); } catch (e) {} A._ptreeSig = null; renderTree(true); } }, label);
  return el("div", { class: "seg pathsview", title: "show the explored paths as an indented list or a branching tree" }, mk("list", "List"), mk("tree", "Tree"));
}

// the path tree drawn as an actual branching tree (nodes + edges), with pan/zoom
function drawPathTree(pane, T, snap) {
  if (typeof dagre === "undefined") { pane.textContent = "tree layout unavailable"; return; }
  const NS = "http://www.w3.org/2000/svg";
  const short = (s, n) => (s && s.length > n ? s.slice(0, n - 1) + "…" : (s || ""));
  const gr = new dagre.graphlib.Graph();
  gr.setGraph({ rankdir: "TB", nodesep: 16, ranksep: 30, marginx: 14, marginy: 14 });
  gr.setDefaultEdgeLabel(() => ({}));
  const CW = 6.3, PAD = 9;
  snap.tree.forEach(n => {
    const leaf = !T.kids[n.id];
    let label, sub;
    if (n.parent === null) { label = "start"; sub = `${A.fn ? (A.fn.ida_name || A.fn.name) : "fn"}(${((A.config && A.config.args) || []).map(a => a.name).join(", ")})`; }
    else { label = short(n.cond || "(branch)", 42); sub = n.decided_at && n.decided_at.line ? "line " + n.decided_at.line : ""; }
    if (leaf) { const r = leafReason(n, snap); sub = (END_STYLE[r] ? END_STYLE[r][1] : r) + (n.hits.length ? " · finding" : ""); if (n.parent === null) label = "start"; }
    const w = Math.max(64, Math.min(280, Math.max(label.length, sub.length) * CW + PAD * 2));
    gr.setNode(n.id, { label, sub, leaf, node: n, width: w, height: 32 });
  });
  snap.tree.forEach(n => { if (n.parent !== null && T.byId[n.parent]) gr.setEdge(n.parent, n.id); });
  dagre.layout(gr);
  const W = gr.graph().width || 300, H = gr.graph().height || 200;

  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("width", "100%"); svg.setAttribute("height", "100%");
  svg.style.cssText = "display:block;background:var(--bg);cursor:grab;touch-action:none;user-select:none";
  svg.innerHTML = `<defs><marker id="ptarr" markerWidth="7" markerHeight="7" refX="6" refY="2.5" orient="auto"><path d="M0,0 L6,2.5 L0,5 Z" fill="var(--line2)"/></marker></defs>`;
  const viewport = document.createElementNS(NS, "g");
  svg.append(viewport);

  const nodeEls = {};
  gr.edges().forEach(eid => {
    const e = gr.edge(eid), pts = e.points;
    let d = `M${pts[0].x},${pts[0].y}`;
    for (let i = 1; i < pts.length; i++) d += ` L${pts[i].x},${pts[i].y}`;
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", d); p.setAttribute("fill", "none"); p.setAttribute("stroke", "var(--line2)");
    p.setAttribute("stroke-width", "1.3"); p.setAttribute("marker-end", "url(#ptarr)");
    viewport.append(p);
  });
  gr.nodes().forEach(id => {
    const g = gr.node(id);
    const gEl = document.createElementNS(NS, "g");
    gEl.setAttribute("transform", `translate(${g.x - g.width / 2},${g.y - g.height / 2})`);
    gEl.style.cursor = "pointer";
    const rect = document.createElementNS(NS, "rect");
    rect.setAttribute("width", g.width); rect.setAttribute("height", g.height); rect.setAttribute("rx", 6);
    gEl.append(rect);
    const t1 = document.createElementNS(NS, "text");
    t1.setAttribute("x", 8); t1.setAttribute("y", g.sub ? 13 : 19);
    t1.setAttribute("font-family", "var(--mono)"); t1.setAttribute("font-size", "11"); t1.setAttribute("font-weight", "600");
    t1.textContent = g.label; gEl.append(t1);
    let t2 = null;
    if (g.sub) {
      t2 = document.createElementNS(NS, "text");
      t2.setAttribute("x", 8); t2.setAttribute("y", 25);
      t2.setAttribute("font-family", "var(--sans)"); t2.setAttribute("font-size", "9.5");
      t2.textContent = g.sub; gEl.append(t2);
    }
    gEl.addEventListener("click", () => { if (!dragged) selectPathNode(+id); });
    nodeEls[id] = { rect, t1, t2, node: g.node, leaf: g.leaf };
    viewport.append(gEl);
  });

  function recolor() {
    const css = getComputedStyle(document.documentElement);
    const v = (k, fb) => (css.getPropertyValue(k).trim() || fb);
    const node = v("--panel2", "#1a1e25"), line2 = v("--line2", "#30363f"), ink = v("--ink"), dim = v("--dim");
    const accent = v("--accent", "#4c9aff"), bad = v("--bad", "#f85149"), ok = v("--ok", "#3fb950"), warn = v("--warn", "#e3b341");
    const tint = (hex, a) => { const m = /^#?([0-9a-f]{6})$/i.exec(hex); if (!m) return hex; const x = parseInt(m[1], 16); return `rgba(${x >> 16 & 255},${x >> 8 & 255},${x & 255},${a})`; };
    const sel = A.selNode, onChain = new Set(sel != null && T.byId[sel] ? T.chain(sel).map(c => c.id) : []);
    for (const id in nodeEls) {
      const ne = nodeEls[id], n = ne.node, seld = +id === sel, hit = n.hits.length > 0;
      const reason = ne.leaf ? leafReason(n, snap) : null;
      let stroke = line2, fill = node, accentCol = null;
      if (hit) { accentCol = bad; }
      else if (ne.leaf) { accentCol = reason === "returned" ? ok : reason === "unconstrained" ? bad : (reason === "exit" || reason === "error") ? warn : line2; }
      if (seld) stroke = accent; else if (onChain.has(+id)) stroke = accent; else if (accentCol) stroke = accentCol;
      fill = seld ? tint(accent, .18) : hit ? tint(bad, .14) : node;
      ne.rect.setAttribute("fill", fill);
      ne.rect.setAttribute("stroke", stroke);
      ne.rect.setAttribute("stroke-width", (seld || onChain.has(+id) || hit) ? 2 : 1);
      ne.t1.setAttribute("fill", hit ? bad : ink);
      if (ne.t2) ne.t2.setAttribute("fill", dim);
    }
  }

  // pan + zoom, view persisted across re-renders (keyed to the tree's structure)
  const sig = snap.tree.length + ":" + JSON.stringify(snap.tree).length;
  const fresh = A._ptreeSig !== sig;
  const view = (!fresh && A._ptreeView) ? A._ptreeView : (A._ptreeView = { x: 12, y: 14, k: 1 });
  A._ptreeSig = sig;
  const apply = () => viewport.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.k})`);
  let dragging = false, dragged = false, sx = 0, sy = 0;
  svg.addEventListener("mousedown", ev => { dragging = true; dragged = false; sx = ev.clientX; sy = ev.clientY; svg.style.cursor = "grabbing"; });
  const onMove = ev => { if (!dragging) return; const dx = ev.clientX - sx, dy = ev.clientY - sy; if (Math.abs(dx) + Math.abs(dy) > 3) dragged = true; view.x += dx; view.y += dy; sx = ev.clientX; sy = ev.clientY; apply(); };
  const onUp = () => { dragging = false; svg.style.cursor = "grab"; };
  window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
  svg.addEventListener("wheel", ev => {
    ev.preventDefault();
    const r = svg.getBoundingClientRect(), mx = ev.clientX - r.left, my = ev.clientY - r.top;
    const f = ev.deltaY < 0 ? 1.12 : 1 / 1.12, nk = Math.max(0.2, Math.min(3, view.k * f));
    view.x = mx - (mx - view.x) * (nk / view.k); view.y = my - (my - view.y) * (nk / view.k); view.k = nk; apply();
  }, { passive: false });

  pane.replaceChildren(svg);
  apply();
  if (fresh) requestAnimationFrame(() => {
    const r = svg.getBoundingClientRect(); if (!r.width) return;
    view.k = Math.max(0.25, Math.min(1, (r.width - 24) / W));
    view.x = (r.width - W * view.k) / 2; view.y = 12; apply();
  });
  recolor();
}

// the selected path's detail, shown in the resizable bottom panel (distinct from the tree)
function updateBottomDetail() {
  const inner = $("#bottomInner"); if (!inner) return;
  const snap = A.run?.snapshot;
  const T = snap && snap.tree ? pathModel(snap) : null;
  if (!T || A.selNode == null || !T.byId[A.selNode]) {
    inner.replaceChildren(el("div", { class: "empty" }, "Click a path in the dock to see its full detail here."));
    $("#bottomTtl").textContent = "Path detail";
    return;
  }
  inner.replaceChildren(renderPathDetail(T, snap));
  const n = T.byId[A.selNode];
  $("#bottomTtl").textContent = "Path detail · " + (T.kids[n.id] ? "branch point" : "path #" + T.leafNo[n.id]);
  $("#bottomPanel").classList.remove("collapsed");
  $("#bottomClose").textContent = "▾";
}

// the control-flow graph, docked above the paths, highlighting the selected path
async function renderPathGraph() {
  const box = $("#dockGraph"); if (!box || !A.fn) return;
  let g = A.cfgCache[A.fn.addr];
  if (!g) {
    box.innerHTML = '<div class="empty">laying out graph…</div>';
    try { g = await api("/api/cfg/" + A.fn.addr); A.cfgCache[A.fn.addr] = g; }
    catch (e) { box.innerHTML = '<div class="empty">graph unavailable</div>'; return; }
  }
  drawCFG(box, g);
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
  // short by design; each row is one stretch between branches, blue = the input condition
  return el("div", { class: "phelp small" },
    "Each row is a stretch of execution; ", el("span", { class: "cond" }, "blue"),
    " is the input condition to take it. Click a row to highlight its path in the graph →");
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
      el("span", { class: "mono" }, `${A.fn?.name || hx64(n.addr)}(${((A.config && A.config.args) || []).map(a => a.name).join(", ")})`));
    const asm = snap.summary?.assumptions_applied || [];
    if (asm.length) head.append(el("span", { class: "where" }, "assuming " + asm.join(", ")));
  } else {
    head.append(el("span", { class: "cond", title: (n.cond ? n.cond + "\n\n" : "") + "the inputs must satisfy this to take this side of the branch (full text in Path detail below)" },
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

  const line2 = el("div", { class: "psub" });
  const chip = (text, cls) => line2.append(el("span", { class: "pchip" + (cls ? " " + cls : "") }, text));
  if (n.lines.length) chip("runs " + lineRanges(n.lines));
  if (n.calls.length) chip("calls " + n.calls.map(c => c + "()").join(", "));
  if (!kids.length && n.end?.reason === "returned" && n.ret) chip("returns " + n.ret, "ret");
  if (!kids.length && n.end && !["returned", "exit"].includes(n.end.reason)) chip(n.end.text);
  if (kids.length && collapsed) chip(`${countLeaves(T, n)} paths folded`);
  if (!kids.length && n.example && Object.keys(n.example).length) chip("e.g. " + fmtWitness(n.example), "ex");
  if (line2.childNodes.length) row.append(line2);
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
  // the blocks executed from the function entry down to the selected node, plus the
  // branch decisions taken along the way (the conditional at each split, and which side)
  const snap = A.run?.snapshot;
  A.pathHighlight = null; A.branchPts = null; A.branchBlocks = null; A.branchCond = null;
  if (snap && snap.tree && A.selNode != null) {
    const T = pathModel(snap);
    if (T.byId[A.selNode]) {
      const chain = T.chain(A.selNode);
      A.pathHighlight = new Set(chain.flatMap(n => n.blocks));
      A.branchPts = new Set(); A.branchBlocks = new Set(); A.branchCond = {}; A.branchBlockCond = {};
      const a2b = decompAddrBlock();
      chain.forEach(n => {
        if (n.parent !== null && n.decided_at && n.decided_at.addr != null) {
          const ad = n.decided_at.addr;
          A.branchPts.add(ad);
          A.branchCond[ad] = n.cond || "";
          const bl = a2b[ad];
          if (bl != null) { A.branchBlocks.add(bl); A.branchBlockCond[bl] = n.cond || ""; }
        }
      });
    }
  }
  highlightHits();
  if ($("#pane-decomp").classList.contains("sel")) renderDecomp();   // re-tint decompilation lines (cached, no refetch)
  renderPathGraph();                                                  // the docked graph, always visible
}

function renderPathDetail(T, snap) {
  const n = T.byId[A.selNode];
  if (!n) return el("div", { class: "empty" }, "Click a path to see its detail here.");
  const chain = T.chain(n.id);
  const leaf = !T.kids[n.id];

  // laid out horizontally (columns) so the whole detail fits without scrolling
  const conds = chain.filter(c => c.parent !== null);
  const asm = snap.summary?.assumptions_applied || [];
  const colA = el("div", { class: "pcol" }, el("div", { class: "dlabel" }, "To get here, the inputs satisfy"));
  if (!conds.length && !asm.length) colA.append(el("div", { class: "faint" }, "no conditions — every run starts here"));
  asm.forEach(a => colA.append(el("div", { class: "dcond" }, el("span", { class: "cond" }, a), el("span", { class: "where" }, "assumption"))));
  conds.forEach(c => colA.append(el("div", { class: "dcond" }, el("span", { class: "cond" }, c.cond || "?"),
    c.decided_at?.line ? el("span", { class: "where" }, `${c.decided_at.file}:${c.decided_at.line} ${c.decided_at.text || ""}`) : null)));

  const colB = el("div", { class: "pcol" });
  const calls = [...new Set(chain.flatMap(c => c.calls))];
  colB.append(el("div", { class: "dlabel" }, "Outcome"));
  colB.append(el("div", { class: "dend" }, leaf
    ? (n.end ? n.end.text + (n.end.reason === "returned" && n.ret ? ": " + n.ret : "") : (leafReason(n, snap) === "running" ? "still running" : "not finished"))
    : "splits further below"));
  if (calls.length) colB.append(el("div", { class: "pchip", style: "margin-top:6px" }, "calls " + calls.map(c => c + "()").join(", ")));
  if (leaf && n.example && Object.keys(n.example).length) {
    colB.append(el("div", { class: "dlabel", style: "margin-top:10px" }, "Example input"));
    const tb = el("div", { class: "dex" });
    Object.entries(n.example).forEach(([k, v]) => tb.append(el("div", {}, el("span", { class: "k" }, k), el("span", {}, fmtOne(k, v)))));
    colB.append(tb);
  }

  // findings live with the outcome (the graph + paths list now holds the right-hand column)
  const hits = chain.flatMap(c => c.hits);
  colB.append(el("div", { class: "dlabel", style: "margin-top:12px" }, hits.length ? "Findings on this path" : "Findings"));
  if (!hits.length) colB.append(el("div", { class: "faint" }, "none on this path"));
  hits.forEach(i => { const h = snap.hits[i]; if (h) colB.append(renderHit(h, i)); });
  colB.append(el("div", { class: "row", style: "margin-top:10px;gap:6px;flex-wrap:wrap" },
    A.ida && A.ida.connected ? el("button", { class: "tiny", onclick: () => selectTab("decomp") }, "Show in decompilation") : null,
    el("button", { class: "tiny", onclick: () => { selectTab("code"); scrollToAddr(n.blocks[0] ?? n.addr); } }, "Show in disassembly")));

  return el("div", { class: "pdetail cols" }, el("div", { class: "pcols" }, colA, colB));
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
      div.title = hx64(addr) + " — click for checks";
      const blk = a2b[addr];
      if (path && blk != null && path.has(blk)) div.classList.add("onpath");
      if (A.branchBlocks && blk != null && A.branchBlocks.has(blk)) {
        div.classList.add("branchpt");
        div.title = hx64(addr) + " — branch taken on this flow: " + (A.branchBlockCond[blk] || "?");
      }
      if (hits.has(addr) || (blk != null && hitBlocks.has(blk))) div.classList.add("hitline");
      highlightC(text.length ? text : " ", div);
      const acts = el("span", { class: "clacts" },
        btn("reach", () => addReachCheck(addr, "reach"), "tiny"),
        btn("⋯", () => openAddrMenu(addr), "tiny ghost"));
      div.append(acts);
    } else {
      highlightC(text.length ? text : " ", div);
    }
    into.append(div);
  }
}

// "graphite" = default (no data-theme). bg = page colour swatch, dot = accent.
const THEMES = [
  { id: "ocean", name: "Ocean", bg: "#0b1620", dot: "#36c6c0" },
  { id: "abyss", name: "Abyss", bg: "#07131e", dot: "#2ec5d3" },
  { id: "lagoon", name: "Lagoon", bg: "#0a1a1e", dot: "#3fd6b0" },
  { id: "tide", name: "Tide", bg: "#0c1824", dot: "#5bb3e6" },
  { id: "graphite", name: "Graphite", bg: "#0c0e12", dot: "#46d07e" },
  { id: "navy", name: "Navy", bg: "#0e1117", dot: "#4c9aff" },
  { id: "slate", name: "Slate", bg: "#111318", dot: "#9a86ff" },
  { id: "forest", name: "Forest", bg: "#0c130e", dot: "#5fd38a" },
  { id: "grape", name: "Grape", bg: "#120e18", dot: "#b58cff" },
  { id: "crimson", name: "Crimson", bg: "#140d10", dot: "#ff6b7a" },
  { id: "amber", name: "Amber", bg: "#141007", dot: "#f0b541" },
  { id: "nord", name: "Nord", bg: "#2e3440", dot: "#88c0d0" },
  { id: "mono", name: "Mono", bg: "#0d0d0d", dot: "#d0d0d0" },
  // popular editor themes, using their real palettes
  { id: "dracula", name: "Dracula", bg: "#282a36", dot: "#bd93f9" },
  { id: "monokai", name: "Monokai", bg: "#272822", dot: "#a6e22e" },
  { id: "onedark", name: "One Dark", bg: "#282c34", dot: "#61afef" },
  { id: "solarized", name: "Solarized", bg: "#002b36", dot: "#2aa198" },
  { id: "gruvbox", name: "Gruvbox", bg: "#282828", dot: "#fabd2f" },
  { id: "tokyonight", name: "Tokyo Night", bg: "#1a1b26", dot: "#7aa2f7" },
  { id: "nightowl", name: "Night Owl", bg: "#011627", dot: "#82aaff" },
];
function curTheme() { try { return localStorage.getItem("theme") || "ocean"; } catch (e) { return "ocean"; } }
function applyTheme() {
  const t = curTheme();
  if (t === "graphite") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
  // the graph is rendered with fixed colors from CSS vars; re-draw on theme change
  const b = $("#dockGraph"); if (b && b._cfg) { delete b._cfg; renderPathGraph(); }
}
function setTheme(id) {
  try { localStorage.setItem("theme", id); } catch (e) {}
  applyTheme();
}
function openThemeMenu() {
  if ($("#themeMenu")) { $("#themeMenu").remove(); return; }
  const cur = curTheme();
  const btn = $("#themeBtn"), r = btn.getBoundingClientRect();
  const m = el("div", { class: "popmenu", id: "themeMenu" });
  THEMES.forEach(th => {
    m.append(el("div", { class: "popitem" + (th.id === cur ? " on" : ""), onclick: () => { setTheme(th.id); m.remove(); } },
      el("span", { class: "swatch", style: `background:${th.bg}` }, el("i", { style: `background:${th.dot}` })),
      el("span", { class: "grow" }, th.name),
      th.id === cur ? el("span", { class: "chk" }, "✓") : null));
  });
  document.body.append(m);
  m.style.top = (r.bottom + 6) + "px";
  m.style.left = Math.max(8, r.right - m.offsetWidth) + "px";
  const close = (e) => { if (!m.contains(e.target) && e.target !== btn) { m.remove(); document.removeEventListener("mousedown", close); } };
  setTimeout(() => document.addEventListener("mousedown", close), 0);
}

const PANEL_FOR = { left: "left", right: "right", dock: "dock" };
function initSplitters() {
  // horizontal splitters resize a side panel's width
  for (const sp of $$(".splitter")) {
    const target = sp.dataset.target, panel = $("#" + PANEL_FOR[target]);
    try { const w = localStorage.getItem("panelW:" + target); if (w) panel.style.width = w; } catch (e) {}
    sp.addEventListener("mousedown", ev => {
      ev.preventDefault(); sp.classList.add("dragging");
      const startX = ev.clientX, startW = panel.getBoundingClientRect().width;
      const leftGrows = target === "left";                 // left panel grows with +dx; right/dock with -dx
      const move = e => { const dx = e.clientX - startX; panel.style.width = Math.max(160, Math.min(1100, startW + (leftGrows ? dx : -dx))) + "px"; };
      const up = () => {
        sp.classList.remove("dragging");
        window.removeEventListener("mousemove", move); window.removeEventListener("mouseup", up);
        try { localStorage.setItem("panelW:" + target, panel.style.width); } catch (e) {}
        regraph();
      };
      window.addEventListener("mousemove", move); window.addEventListener("mouseup", up);
    });
  }
  // the vertical splitter sets the docked graph's height
  for (const sp of $$(".splitter-h")) {
    const target = sp.dataset.target;                 // "dockv" (graph height) or "bottom" (bottom panel)
    const box = target === "bottom" ? $("#bottomPanel") : $("#dockGraph");
    const grow = target === "bottom" ? -1 : 1;        // the bottom panel grows when dragging up
    try { const h = localStorage.getItem("h:" + target); if (h) box.style.height = h; } catch (e) {}
    sp.addEventListener("mousedown", ev => {
      ev.preventDefault(); sp.classList.add("dragging");
      const startY = ev.clientY, startH = box.getBoundingClientRect().height;
      const move = e => { box.style.height = Math.max(60, startH + grow * (e.clientY - startY)) + "px"; };
      const up = () => {
        sp.classList.remove("dragging");
        window.removeEventListener("mousemove", move); window.removeEventListener("mouseup", up);
        try { localStorage.setItem("h:" + target, box.style.height); } catch (e) {}
        if (target !== "bottom") regraph();
      };
      window.addEventListener("mousemove", move); window.addEventListener("mouseup", up);
    });
  }
}
function regraph() { const b = $("#dockGraph"); if (b && b._cfg) delete b._cfg; renderPathGraph(); }

// hide a side panel off to the edge, leaving a button to bring it back
function setPanelCollapsed(side, collapsed) {
  const panel = $("#" + side); if (!panel) return;
  panel.classList.toggle("collapsed", collapsed);
  const sp = $(`.splitter[data-target="${side}"]`); if (sp) sp.style.display = collapsed ? "none" : "";
  const exp = $("#" + side + "Expand"); if (exp) exp.classList.toggle("hidden", !collapsed);
  try { localStorage.setItem("collapse:" + side, collapsed ? "1" : "0"); } catch (e) {}
  regraph();   // the dock/graph width changed
}

function showAddr(addr) {
  // jump to an address and flash it — prefer the decompilation when IDA is connected
  if (A.ida && A.ida.connected) {
    selectTab("decomp");
    setTimeout(() => {
      const line = $(`#pane-decomp .cline[data-addr="${addr}"]`);
      if (line) { line.scrollIntoView({ block: "center", behavior: "smooth" }); line.classList.add("flash"); setTimeout(() => line.classList.remove("flash"), 1400); }
      else { selectTab("code"); scrollToAddr(addr); }
    }, 350);
  } else { selectTab("code"); scrollToAddr(addr); }
}

function openAddrMenu(addr) {
  const m = modal("At " + hx64(addr), el("div", { class: "col", style: "gap:8px" },
    menuItem("Reach check", "record any path that reaches this line", () => { m.remove(); addReachCheck(addr, "reach"); }),
    menuItem("Avoid check", "record + mark paths that reach this line", () => { m.remove(); addReachCheck(addr, "avoid"); }),
    menuItem("Assert here", "a boolean that should always hold at this point", () => { m.remove(); openAssertModal(addr); }),
    menuItem("Custom Python check here", "run your own predicate at this point", () => { m.remove(); openCustomModal(addr); }),
    menuItem("Show in disassembly", "jump to this address in the code view", () => { m.remove(); selectTab("code"); scrollToAddr(addr); })),
    [el("button", { onclick: () => m.remove() }, "Close")]);
  $("#modalHost").append(m);
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
    files: (A.config.files || []).filter(f => f.name), checks: A.config.checks.filter(c => c.enabled), limits: A.config.limits,
    models: (A.config.models || []).filter(m => m.func),
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
  // keep the scroll position when re-rendering the same function (e.g. a flow click
  // re-tints the lines); reset it only when switching to a different function
  const sameFn = pane._fnAddr === A.fn.addr;
  const keepScroll = sameFn ? (($(".ccode", pane) || {}).scrollTop || 0) : 0;
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
  A._assume = assumeModel(); A._vars = varModel();
  // IDA decompiles the function containing the address; show the function IDA
  // actually returned, and flag it when angr's function boundary differs.
  const idaFn = d.func || (A.fn.ida_name || A.fn.name);
  const bar = el("div", { class: "decompbar" },
    el("span", {}, "IDA · "),
    el("span", { class: "fn" }, idaFn + (d.func_start != null ? "  " + hx64(d.func_start) : "")),
    scenarioChip("inbar"),
    el("span", { class: "grow" }),
    el("span", { class: "varlegend", title: "argument variables are marked in the code; click one to constrain it or flip it between symbolic and fixed" },
      el("i", { class: "sym" }, "symbolic"), el("i", { class: "set" }, "fixed")),
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
  pre.scrollTop = keepScroll;
  pane._fnAddr = A.fn.addr;
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
// which decompilation tokens are the function's input arguments, and whether
// each is symbolic (free for angr to search) or fixed to a concrete value.
// a1 (IDA) <-> arg0 (ours) <-> your name all resolve to the same slot.
function varModel() {
  const tok = {};
  const args = (A.config && A.config.args) || [];
  args.forEach((a, idx) => {
    const info = { name: a.name || ("arg" + idx), idx, mode: a.mode, value: a.value, size: a.size, signed: a.signed };
    for (const t of aliasesOf(info.name)) tok[t] = info;
    tok["a" + (idx + 1)] = info; tok["arg" + idx] = info;
  });
  return tok;
}
function fmtArgVal(info) {
  const v = info.value ?? 0;
  return (typeof v === "number" && v >= 16) ? "0x" + v.toString(16) + " (" + v + ")" : String(v);
}

function annotate(text) {                  // mark argument variables + assumption tokens
  const atok = (A._assume || assumeModel()).tok;
  const vtok = A._vars || (A._vars = varModel());
  const frag = document.createDocumentFragment();
  let last = 0, m; const re = /[A-Za-z_]\w*/g;
  while ((m = re.exec(text))) {
    const word = m[0];
    const ahits = atok[word], vinfo = vtok[word];
    if (!ahits && !vinfo) continue;
    if (m.index > last) frag.append(document.createTextNode(text.slice(last, m.index)));
    if (vinfo) {
      const sym = vinfo.mode !== "concrete";
      const sp = el("span", { class: "dvar " + (sym ? "sym" : "set"),
        title: sym ? `${vinfo.name}: symbolic (${vinfo.size || 8} bytes) — click to add a constraint`
                   : `${vinfo.name} = ${fmtArgVal(vinfo)} — click to change or constrain`,
        onclick: (e) => { e.stopPropagation(); openVarMenu(vinfo, e); } }, word);
      if (ahits) { sp.style.setProperty("--ac", ahits[0].color); sp.classList.add("av"); sp.title += "  ·  in: " + ahits.map(a => a.expr).join("  ;  "); }
      frag.append(sp);
    } else {
      frag.append(el("span", { class: "avar", style: `--ac:${ahits[0].color}`,
        title: ahits.map(a => a.expr).join("  ;  ") }, word));
    }
    last = re.lastIndex;
  }
  frag.append(document.createTextNode(text.slice(last)));
  return frag;
}

// click a variable in the decompilation: flip symbolic/fixed or add a constraint on it
function openVarMenu(info0, ev) {
  $("#varMenu")?.remove();
  const a = (A.config.args || [])[info0.idx]; if (!a) return;
  const info = { name: a.name || ("arg" + info0.idx), idx: info0.idx, mode: a.mode, value: a.value, size: a.size, signed: a.signed };
  const m = el("div", { class: "popmenu vmenu", id: "varMenu" });
  const sym = a.mode !== "concrete";
  m.append(el("div", { class: "vmhead" }, el("b", {}, info.name),
    el("span", { class: "faint" }, sym ? "symbolic · free to search" : "fixed = " + fmtArgVal(info))));
  // symbolic / fixed toggle
  const seg = el("div", { class: "seg", style: "margin:2px 0 8px" },
    el("div", { class: "segbtn" + (sym ? " on" : ""), onclick: () => { a.mode = "symbolic"; afterVarChange(); } }, "symbolic"),
    el("div", { class: "segbtn" + (!sym ? " on" : ""), onclick: () => { a.mode = "concrete"; afterVarChange(); } }, "fixed"));
  m.append(seg);
  if (!sym) {
    const vi = el("input", { value: a.value ?? 0, placeholder: "value", style: "width:100%;box-sizing:border-box;margin-bottom:8px",
      oninput: e => { a.value = parseIntLoose(e.target.value); scheduleSave(); scheduleAssumeRefresh(); } });
    m.append(el("div", { class: "vmlbl" }, "fixed value"), vi);
  }
  // add a constraint referencing this variable
  m.append(el("div", { class: "vmlbl" }, "constrain " + info.name));
  const ci = el("input", { placeholder: info.name + " > 0", style: "width:100%;box-sizing:border-box" });
  const addC = () => { const v = ci.value.trim(); if (!v) return; A.config.assumptions.push(v); m.remove(); renderRight(); scheduleSave(); refreshAssumptionViews(); toast("added assumption: " + v); };
  ci.addEventListener("keydown", e => { if (e.key === "Enter") addC(); });
  m.append(ci);
  const quick = el("div", { class: "row", style: "gap:5px;margin-top:6px;flex-wrap:wrap" });
  for (const q of ["> 0", "== 0", "!= 0", "< 0"]) quick.append(el("button", { class: "tiny ghost", onclick: () => { ci.value = info.name + " " + q; } }, info.name + " " + q));
  m.append(quick);
  m.append(el("div", { class: "row", style: "justify-content:flex-end;margin-top:8px;gap:6px" },
    el("button", { class: "tiny ghost", onclick: () => m.remove() }, "Cancel"),
    el("button", { class: "tiny primary", onclick: addC }, "Add constraint")));

  function afterVarChange() { scheduleSave(); A._vars = null; renderRight(); refreshAssumptionViews(); openVarMenu(info, ev); }

  document.body.append(m);
  const x = ev ? ev.clientX : 200, y = ev ? ev.clientY : 200;
  m.style.left = Math.min(x, window.innerWidth - m.offsetWidth - 10) + "px";
  m.style.top = Math.min(y + 8, window.innerHeight - m.offsetHeight - 10) + "px";
  setTimeout(() => ci.focus(), 0);
  const close = (e) => { if (!m.contains(e.target) && !e.target.classList?.contains("dvar")) { m.remove(); document.removeEventListener("mousedown", close); } };
  setTimeout(() => document.addEventListener("mousedown", close), 0);
}
function refreshAssumptionViews() {
  A._assume = assumeModel();
  const sel = $("#mainView .tab.sel");
  const active = sel ? sel.dataset.tab : null;
  if (active === "code") renderCode();
  else if (active === "decomp") renderDecomp();
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
    A.detail = d; A.func = normalizeFunc(d.config); bindConfig(); A._vars = null;
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

// ==================================================================== agent docs
async function openDocsModal() {
  let d = {};
  try { d = await api("/api/agent-docs"); } catch (e) {}
  const origin = location.origin;
  const mcpUrl = d.mcp_url || (origin + "/mcp");
  const h = (t) => el("h4", { class: "dh" }, t);
  const p = (...k) => el("p", { class: "dp" }, ...k);
  const code = (t) => el("code", {}, t);
  const pre = (t) => el("pre", { class: "dcode" }, t);
  const body = el("div", { class: "docbody" });

  body.append(
    p(el("b", {}, "SEAL"), " (Symbolic Execution Analysis Lab) drives ", el("b", {}, "angr"),
      " symbolic execution behind a visual UI. An agent sets up a function's initial state, adds checks, runs them, and reads back concrete inputs that trigger each finding — while a human watches every action live in this window."));

  body.append(h("1 · Connect"));
  body.append(p("The tool exposes a built-in ", el("b", {}, "MCP server"), " (", (d.transport || "Streamable HTTP"), "). Point your MCP client at:"));
  body.append(pre(mcpUrl));
  body.append(p("Protocol ", code(d.protocol || "2025-06-18"), ", server name ", code(d.server_name || "seal"),
    ". Standard MCP handshake: ", code("initialize"), " → ", code("tools/list"), " → ", code("tools/call"),
    ". No auth. Everything you do appears in the GUI's ", el("b", {}, "Activity"), " feed in real time, and the human can follow along (the view auto-jumps to your runs)."));

  body.append(h("2 · Typical workflow"));
  const ol = el("ol", { class: "dol" });
  [["list_functions", "find the function to analyse (by name or address substring)."],
   ["get_function", "read its current setup (initial state, assumptions, checks, limits)."],
   ["decompile / disassemble", "read the code to decide what to check."],
   ["configure / add_assumption / add_check", "mark arguments symbolic or fixed, constrain inputs, and add checks."],
   ["run", "execute the enabled checks; returns a run_id."],
   ["get_run", "poll until status is done/error, then read findings — each carries a concrete witness (the exact inputs that trigger it) and the path tree."]].forEach(([t, s]) =>
    ol.append(el("li", {}, code(t), " — " + s)));
  body.append(ol);

  body.append(h("3 · Tools"));
  const tbl = el("table", { class: "dtbl" });
  tbl.append(el("tr", {}, el("th", {}, "tool"), el("th", {}, "what it does")));
  (d.tools || []).forEach(t => {
    const req = (t.inputSchema && t.inputSchema.required) || [];
    tbl.append(el("tr", {},
      el("td", {}, code(t.name), req.length ? el("div", { class: "dargs" }, "args: " + req.join(", ")) : null),
      el("td", {}, t.description)));
  });
  body.append(tbl);

  body.append(h("4 · Checks (add_check)"));
  (d.check_kinds || []).forEach(c => {
    const fields = Object.entries(c.fields || {}).map(([k, v]) => `${k}: ${v}`).join("  ·  ");
    body.append(el("div", { class: "dcheck" },
      el("span", { class: "pill info" }, c.kind), " ", c.summary,
      fields ? el("div", { class: "dargs" }, fields) : null));
  });
  body.append(p("Example: ", code('add_check(addr, {"kind":"assert","expr":"total < 0x1000","at_return":true})')));

  body.append(h("5 · Expression language"));
  body.append(p("Used by assumptions and by ", code("assert"), " checks, over the input names:"));
  const el2 = el("ul", { class: "dul" });
  [["names", "the argument names, plus a1../arg0.. (parameters), registers (rdi, eax…), and ret (return value)."],
   ["compare", "== != < <= > >=  (unsigned); prefix s for signed: s< s<= s> s>="],
   ["arith / bitwise", "+ - * / %  & | ^ ~ << >>  (s>> = arithmetic shift, s/ s% = signed)"],
   ["widths", "u8/u16/u32/u64 read N low bits unsigned; s8/s16/s32/s64 sign-extend"],
   ["memory", "mem(addr, size) reads memory; e.g. mem(a1, 4)"],
   ["example", 'a1 & 0xff == 0x5a   ·   u32(x) + 8 < u32(x)   ·   ret s>= 0']].forEach(([k, v]) =>
    el2.append(el("li", {}, el("b", {}, k + ": "), v)));
  body.append(el2);

  body.append(h("6 · Scenarios"));
  body.append(p("A function can have several ", el("b", {}, "scenarios"), " — different ways it is reached, each with its own initial state (args, stdin, files, assumptions, limits). ",
    "The checks are ", el("b", {}, "shared"), " across scenarios. ", code("get_function"), " reports the scenario names and which is active; ",
    code("configure"), ", ", code("add_assumption"), " and ", code("run"), " all act on the ", el("b", {}, "active"), " one."));
  body.append(p("Manage them with ", code("add_scenario"), " (optionally ", code("duplicate"), " the active one; the new scenario becomes active), ",
    code("select_scenario"), ", ", code("rename_scenario"), " and ", code("delete_scenario"), " — each takes a scenario name or index."));

  if (d.guide) {
    body.append(h("7 · The agent's own guide"));
    body.append(p("An agent calls ", code("get_guide"), " (or reads the handshake ", code("instructions"),
      ") to get this self-contained how-to — the same text, with a worked example:"));
    body.append(el("pre", { class: "dcode", style: "white-space:pre-wrap;max-height:320px;overflow:auto;color:var(--ink)" }, d.guide));
  }

  const m = modal("Clanker documentation", body, [el("button", { class: "primary", onclick: () => m.remove() }, "Close")]);
  m.querySelector(".modal").classList.add("docs");
  $("#modalHost").append(m);
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

// ==================================================================== detect menu + numeric/float/memory checks
function openDetectMenu(anchor) {
  if ($("#detectMenu")) { $("#detectMenu").remove(); return; }
  const m = el("div", { class: "popmenu", id: "detectMenu" });
  m.append(el("div", { class: "vmlbl", style: "padding:2px 8px 4px" }, "detect a bug class"));
  [["Integer overflow / wrap", "add / sub / mul whose result wraps", openOverflowModal],
   ["Narrowing cast (lossy)", "value truncated to a smaller int, dropping set bits", openNarrowingModal],
   ["Floating-point anomaly", "result can be NaN or ±Inf", openFloatModal],
   ["Out-of-bounds write", "a write that can leave a declared buffer", openOobModal]].forEach(([t, s, fn]) =>
    m.append(el("div", { class: "popitem", style: "flex-direction:column;align-items:flex-start;gap:1px",
      onclick: () => { m.remove(); fn(); } }, el("span", {}, t), el("span", { class: "dargs" }, s))));
  document.body.append(m);
  const r = anchor.getBoundingClientRect();
  m.style.top = (r.bottom + 6) + "px";
  m.style.left = Math.max(8, Math.min(r.left, window.innerWidth - m.offsetWidth - 10)) + "px";
  const close = (e) => { if (!m.contains(e.target) && e.target !== anchor) { m.remove(); document.removeEventListener("mousedown", close); } };
  setTimeout(() => document.addEventListener("mousedown", close), 0);
}

function insnPicker(filterFn) {
  const sel = el("select", {});
  sel.append(el("option", { value: "" }, "— whole function —"));
  (A.detail.disasm.instructions || []).filter(filterFn || (() => true)).forEach(i =>
    sel.append(el("option", { value: i.addr }, `${hx64(i.addr)}  ${i.mnemonic} ${i.op_str}`)));
  return sel;
}

function openNarrowingModal() {
  const sel = insnPicker();
  const body = el("div", {}, field("Where", sel,
    "Scan the whole function, or one instruction. Flags a value truncated to a smaller integer type (int→short, long→int, →char) where the discarded high bits can be non-zero — i.e. data is lost."));
  const m = modal("Detect narrowing casts", body, [
    el("button", { onclick: () => m.remove() }, "Cancel"),
    el("button", { class: "primary", onclick: () => {
      const addr = sel.value ? +sel.value : null;
      addCheck({ kind: "narrowing_cast", addr, name: addr ? `narrowing @ ${hx64(addr)}` : "narrowing cast (whole function)" });
      m.remove();
    } }, "Add check")]);
  $("#modalHost").append(m);
}

function openFloatModal() {
  const sel = insnPicker();
  const body = el("div", {},
    field("Where", sel, "Scan the whole function, or one instruction."),
    el("div", { class: "help" }, "Flags a floating-point add/sub/mul/div whose result can be NaN or ±Inf (from special or extreme inputs: 0/0, x/0, overflow). ",
      el("b", {}, "Tip:"), " mark the relevant arguments as ", el("b", {}, "float"), " in Initial state so their values are symbolic."));
  const m = modal("Detect floating-point anomalies", body, [
    el("button", { onclick: () => m.remove() }, "Cancel"),
    el("button", { class: "primary", onclick: () => {
      const addr = sel.value ? +sel.value : null;
      addCheck({ kind: "float_anomaly", addr, name: addr ? `float @ ${hx64(addr)}` : "float anomaly (whole function)" });
      m.remove();
    } }, "Add check")]);
  $("#modalHost").append(m);
}

function openOobModal() {
  const base = el("input", { placeholder: "a1   ·   rsp-0x40   ·   0x601080", style: "width:100%;box-sizing:border-box" });
  const size = el("input", { value: "64", style: "width:90px" });
  const sel = insnPicker();
  const body = el("div", {},
    field("Buffer start", base, "Expression for the buffer's base address: a pointer argument (a1/arg0/your name), a register expression (rsp-0x40), or a literal address."),
    field("Buffer size (bytes)", size, "A write whose address can land outside [base, base+size) is reported — with the input that takes it there."),
    field("Where (optional)", sel, "Restrict to one write instruction, or watch every write in the function."));
  const m = modal("Detect out-of-bounds writes", body, [
    el("button", { onclick: () => m.remove() }, "Cancel"),
    el("button", { class: "primary", onclick: () => {
      const b = base.value.trim();
      if (!b) { toast("enter the buffer's base address/expression", true); return; }
      const sz = parseIntLoose(size.value);
      if (!sz) { toast("enter the buffer size in bytes", true); return; }
      const addr = sel.value ? +sel.value : null;
      addCheck({ kind: "oob_write", base: b, size: sz, addr, name: `OOB write · ${b}[${sz}]` });
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
async function renderCFG(force) {         // legacy CFG tab; the graph now lives in the dock
  const pane = $("#pane-cfg");
  if (!pane) return renderPathGraph();
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
  // if this function's graph is already laid out here, only recolor (keeps pan/zoom/position)
  if (pane._cfg && pane._cfg.addr === g.addr) { pane._cfg.recolor(); return; }
  if (pane._cfg && pane._cfg.cleanup) pane._cfg.cleanup();

  const gr = new dagre.graphlib.Graph({ multigraph: true });
  gr.setGraph({ rankdir: "TB", nodesep: 26, ranksep: 34, marginx: 20, marginy: 20 });
  gr.setDefaultEdgeLabel(() => ({}));
  const LINE_H = 16, CHAR_W = 7.3, PAD = 11;
  for (const n of g.nodes) {
    const lines = n.insns.slice(0, 8).map(i => i.text);     // instructions only; addresses dropped
    if (n.insns.length > 8) lines.push(`… +${n.insns.length - 8}`);
    const w = Math.max(120, Math.min(460, Math.max(...lines.map(l => l.length)) * CHAR_W + PAD * 2));
    const h = lines.length * LINE_H + PAD * 2 + 16;
    gr.setNode(n.addr, { label: hx64(n.addr), lines, width: w, height: h, insns: n.insns });
  }
  let ei = 0;
  for (const e of g.edges) if (gr.hasNode(e.src) && gr.hasNode(e.dst)) gr.setEdge(e.src, e.dst, { kind: e.kind }, "e" + (ei++));
  dagre.layout(gr);
  const W = gr.graph().width || 400, H = gr.graph().height || 300;
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("width", "100%"); svg.setAttribute("height", "100%");
  svg.style.cssText = "display:block;background:var(--bg);cursor:grab;touch-action:none;user-select:none";
  svg.innerHTML = `<defs><marker id="arr" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
    <path d="M0,0 L7,3 L0,6 Z" fill="#5a6577"/></marker>
    <marker id="arrhi" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
    <path d="M0,0 L7,3 L0,6 Z" fill="#4c9aff"/></marker></defs>`;
  const viewport = document.createElementNS(NS, "g");
  svg.append(viewport);

  const edgeEls = [], nodeEls = {};
  gr.edges().forEach(eid => {
    const e = gr.edge(eid), pts = e.points;
    let d = `M${pts[0].x},${pts[0].y}`;
    for (let i = 1; i < pts.length; i++) d += ` L${pts[i].x},${pts[i].y}`;
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", d); p.setAttribute("fill", "none");
    if (e.kind === "call") p.setAttribute("stroke-dasharray", "4 3");
    viewport.append(p);
    edgeEls.push({ p, v: +eid.v, w: +eid.w, kind: e.kind });
  });
  gr.nodes().forEach(id => {
    const n = gr.node(id);
    const gEl = document.createElementNS(NS, "g");
    gEl.setAttribute("transform", `translate(${n.x - n.width / 2},${n.y - n.height / 2})`);
    const rect = document.createElementNS(NS, "rect");
    rect.setAttribute("width", n.width); rect.setAttribute("height", n.height); rect.setAttribute("rx", 7);
    rect.style.cursor = "pointer";
    gEl.append(rect);
    const head = document.createElementNS(NS, "text");
    head.setAttribute("x", 9); head.setAttribute("y", 15);
    head.setAttribute("font-family", "var(--mono)"); head.setAttribute("font-size", "10.5"); head.setAttribute("font-weight", "700");
    head.textContent = n.label;
    gEl.append(head);
    const lineEls = [];
    n.lines.forEach((ln, i) => {
      const t = document.createElementNS(NS, "text");
      t.setAttribute("x", 9); t.setAttribute("y", 32 + i * LINE_H);
      t.setAttribute("font-family", "var(--mono)"); t.setAttribute("font-size", "12.5");
      t.textContent = ln;
      gEl.append(t);
      lineEls.push(t);
    });
    nodeEls[+id] = { rect, head, insns: n.insns, lineEls };
    viewport.append(gEl);
  });

  function recolor() {
    const pathBlocks = A.pathHighlight || new Set();
    const hitAddrs = new Set((A.run?.snapshot?.hits || []).map(h => h.addr));
    // pull colours from the active theme so nodes stay distinct from the background
    const css = getComputedStyle(document.documentElement);
    const v = (name, fb) => (css.getPropertyValue(name).trim() || fb);
    const node = v("--panel2", "#1a1e25"), line2 = v("--line2", "#30363f");
    const ink = v("--ink", "#e8ecf1"), dim = v("--dim", "#98a1ad");
    const accent = v("--accent", "#4c9aff"), accent2 = v("--accent2", "#7c5cff"), bad = v("--bad", "#f85149");
    const branchBlocks = A.branchBlocks || new Set();
    const tint = (hex, a) => { const m = /^#?([0-9a-f]{6})$/i.exec(hex); if (!m) return hex; const n = parseInt(m[1], 16); return `rgba(${n >> 16 & 255},${n >> 8 & 255},${n & 255},${a})`; };
    for (const addr in nodeEls) {
      const ne = nodeEls[addr], onPath = pathBlocks.has(+addr), hasHit = ne.insns.some(i => hitAddrs.has(i.addr)), isBranch = branchBlocks.has(+addr);
      ne.rect.setAttribute("fill", hasHit ? tint(bad, .16) : isBranch ? tint(accent2, .18) : onPath ? tint(accent, .16) : node);
      ne.rect.setAttribute("stroke", hasHit ? bad : isBranch ? accent2 : onPath ? accent : line2);
      ne.rect.setAttribute("stroke-width", (hasHit || onPath || isBranch) ? 2 : 1);
      ne.head.setAttribute("fill", hasHit ? bad : isBranch ? accent2 : dim);
      (ne.lineEls || []).forEach(t => t.setAttribute("fill", ink));
    }
    for (const e of edgeEls) {
      const hi = pathBlocks.has(e.v) && pathBlocks.has(e.w);
      const color = e.kind === "call" ? accent2 : e.kind === "return" ? v("--ok", "#3fb950") : "#5a6577";
      e.p.setAttribute("stroke", hi ? accent : color);
      e.p.setAttribute("stroke-width", hi ? 2.5 : 1.3);
      e.p.setAttribute("marker-end", hi ? "url(#arrhi)" : "url(#arr)");
    }
  }

  // pan (drag) + zoom (wheel), like a disassembler graph view
  const view = { x: 12, y: 16, k: 1 };
  const apply = () => viewport.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.k})`);
  let dragging = false, dragged = false, sx = 0, sy = 0;
  const onDown = ev => { dragging = true; dragged = false; sx = ev.clientX; sy = ev.clientY; svg.style.cursor = "grabbing"; };
  const onMove = ev => { if (!dragging) return; const dx = ev.clientX - sx, dy = ev.clientY - sy; if (Math.abs(dx) + Math.abs(dy) > 3) dragged = true; view.x += dx; view.y += dy; sx = ev.clientX; sy = ev.clientY; apply(); };
  const onUp = () => { dragging = false; svg.style.cursor = "grab"; };
  const onWheel = ev => {
    ev.preventDefault();
    const r = svg.getBoundingClientRect(), mx = ev.clientX - r.left, my = ev.clientY - r.top;
    const f = ev.deltaY < 0 ? 1.12 : 1 / 1.12, nk = Math.max(0.15, Math.min(3, view.k * f));
    view.x = mx - (mx - view.x) * (nk / view.k); view.y = my - (my - view.y) * (nk / view.k); view.k = nk; apply();
  };
  svg.addEventListener("mousedown", onDown);
  window.addEventListener("mousemove", onMove);
  window.addEventListener("mouseup", onUp);
  svg.addEventListener("wheel", onWheel, { passive: false });
  for (const addr in nodeEls) nodeEls[addr].rect.addEventListener("click", () => { if (!dragged) { selectTab("code"); scrollToAddr(+addr); } });

  pane.replaceChildren(svg);
  pane._cfg = { addr: g.addr, recolor, view,
    cleanup: () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); } };

  // initial fit: scale to the panel, center on the highlighted path if there is one
  requestAnimationFrame(() => {
    const r = svg.getBoundingClientRect();
    view.k = Math.max(0.2, Math.min(1, (r.width - 24) / W));
    const pathBlocks = A.pathHighlight || new Set();
    const on = gr.nodes().filter(id => pathBlocks.has(+id)).map(id => gr.node(id));
    if (on.length) {
      const cx = (Math.min(...on.map(n => n.x - n.width / 2)) + Math.max(...on.map(n => n.x + n.width / 2))) / 2;
      const minY = Math.min(...on.map(n => n.y - n.height / 2));
      view.x = r.width / 2 - cx * view.k; view.y = 20 - minY * view.k;
    } else { view.x = (r.width - W * view.k) / 2; view.y = 12; }
    apply();
  });
  recolor();
}
