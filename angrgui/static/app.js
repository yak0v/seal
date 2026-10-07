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
  loopCollapsed: new Set(), // folded loop regions (by entry node id)
  pathHighlight: null,  // Set of block addrs on the selected path
  scriptCode: "",
  scriptJump: null,
  ida: { connected: false },
  decompCache: {},
  _assume: null,
  activity: [],
  actOpen: false,
  followAgent: true,
  models: { by_name: {}, by_site: {} },   // global function-return models (apply to every run)
};

// ---- global function-return models (persisted in the workspace, applied to all runs)
async function loadModels() {
  try {
    const r = await api("/api/models");
    A.models = { by_name: r.by_name || {}, by_site: r.by_site || {} };
  } catch (e) { A.models = { by_name: {}, by_site: {} }; }
}
let _modelSaveT = null;
function saveModels() {
  clearTimeout(_modelSaveT);
  _modelSaveT = setTimeout(() => { jpost("/api/models", A.models).catch(() => {}); }, 250);
}
const modelForName = (name) => name && A.models.by_name[name];
const modelForSite = (addr) => addr != null && A.models.by_site[hx64(addr)];

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
  $("#humanDocsBtn").addEventListener("click", openHumanDocs);
  $("#leftCollapse").addEventListener("click", () => setPanelCollapsed("left", true));
  $("#rightCollapse").addEventListener("click", () => setPanelCollapsed("right", true));
  $("#leftExpand").addEventListener("click", () => setPanelCollapsed("left", false));
  $("#rightExpand").addEventListener("click", () => setPanelCollapsed("right", false));
  ["left", "right"].forEach(s => { try { if (localStorage.getItem("collapse:" + s) === "1") setPanelCollapsed(s, true); } catch (e) {} });
  $$("#viewMode .segbtn").forEach(x => x.addEventListener("click", () => setViewMode(x.dataset.mode)));
  try { setViewMode(localStorage.getItem("viewMode") || "setup", true); } catch (e) {}
  try { A.pathsOrient = localStorage.getItem("pathsOrient") || "horizontal"; } catch (e) { A.pathsOrient = "horizontal"; }
  $$("#pathsToggle .segbtn").forEach(x => x.addEventListener("click", () => {
    // idempotent: clicking a side always selects that orientation and shows the strip;
    // re-clicking the active one keeps it (use the × on the strip to hide)
    A.pathsOrient = x.dataset.orient; try { localStorage.setItem("pathsOrient", A.pathsOrient); } catch (e) {}
    if (A.pathsDock) setPathsOrient(A.pathsOrient); else setPathsDock(true);
  }));
  $("#pbClose").addEventListener("click", () => setPathsDock(false));
  // code text size (decompilation / disassembly / angr script)
  const applyCodeFs = () => { $("#mainView").style.setProperty("--code-fs", A.codeFs + "px"); try { localStorage.setItem("codeFs", A.codeFs); } catch (e) {} };
  try { A.codeFs = Math.max(8, Math.min(28, +localStorage.getItem("codeFs") || 12)); } catch (e) { A.codeFs = 12; }
  $("#fsDown").addEventListener("click", () => { A.codeFs = Math.max(8, A.codeFs - 1); applyCodeFs(); });
  $("#fsUp").addEventListener("click", () => { A.codeFs = Math.min(28, A.codeFs + 1); applyCodeFs(); });
  applyCodeFs();
  try { setPathsDock(localStorage.getItem("pathsDock") === "1", true); } catch (e) { setPathsDock(false, true); }
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
  await loadModels();
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
  A.fn = f; A.run = null; A.selectedHit = null; A.selNode = null; A.pathHighlight = null; A.collapsed.clear(); A.loopCollapsed.clear(); A.cfgExpanded = new Set();
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
  selectTab("decomp");   // decompilation is always the default view
  renderDock();                                               // graph + paths, always visible
}

// The function's setup is structured as shared `checks` plus a list of
// `scenarios` (each one a different way of reaching the function, with its own
// initial state). A.func holds the structure; A.config is a live view onto the
// active scenario, with the shared checks array exposed as A.config.checks so
// all the existing per-field editors keep working unchanged.
const SCEN_FIELDS = ["name", "args", "buffers", "assumptions", "stdin", "files", "limits", "initial_state"];
function normalizeScenario(s, i) {
  s = s || {};
  s.name = s.name || ("Scenario " + (i + 1));
  s.args = s.args || [];
  s.buffers = s.buffers || [];
  s.assumptions = s.assumptions || [];
  s.stdin = s.stdin || null;
  s.files = s.files || [];
  s.limits = Object.assign({ steps: 150, active: 300, seconds: 30, loop_bound: 12, find: null, avoid: [] }, s.limits || {});
  s.initial_state = s.initial_state || null;   // null = fresh call (symbolic args); else {kind:"snapshot",...}
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
  if (name === "state") renderState();
}

// ===================================================================== State tab
// View the function's INITIAL STATE: a fresh symbolic call (default), or a concolic
// snapshot (real registers + memory captured from a live run) with the attacker-
// controlled fields symbolized. Also the place to load a snapshot.
function activeScenario() {
  return A.func && A.func.scenarios ? A.func.scenarios[A.func.active] : null;
}
function renderState() {
  const pane = $("#pane-state"); if (!pane) return;
  if (!A.fn || !A.func) { pane.replaceChildren(el("div", { class: "empty" }, "Select a function.")); return; }
  const sc = activeScenario();
  const init = sc && sc.initial_state;
  const wrap = el("div", { class: "statewrap" });

  const bar = el("div", { class: "decompbar" },
    el("span", {}, "Initial state · "),
    el("span", { class: "fn" }, init && init.kind === "snapshot" ? "concolic snapshot" : "fresh call (symbolic args)"),
    el("span", { class: "grow" }),
    el("button", { class: "tiny", onclick: openSnapshotGuide, title: "How to capture a snapshot" }, "ⓘ How to capture"),
    el("button", { class: "tiny primary", onclick: openSnapshotLoader }, "Load snapshot…"),
    init ? el("button", { class: "tiny", onclick: clearInitialState }, "Clear → fresh call") : null);
  wrap.append(bar);

  if (!init || init.kind !== "snapshot") {
    const t = el("div", { class: "statebox" },
      el("div", { class: "faint", style: "margin-bottom:6px" },
        "No snapshot. The run starts from a fresh call with the arguments below symbolic — so every input is unknown and many paths look feasible."));
    const args = (sc.args || []);
    if (args.length) {
      const tbl = el("table", { class: "statetbl" });
      args.forEach(a => tbl.append(el("tr", {}, el("td", {}, a.name), el("td", {}, a.mode || "symbolic"),
        el("td", {}, a.mode === "concrete" ? String(a.value ?? 0) : "symbolic"))));
      t.append(tbl);
    }
    wrap.append(t);
    pane.replaceChildren(wrap);
    return;
  }

  // snapshot view: PC, symbolic overlays, registers, memory
  const sym = init.symbolic || [];
  const symKey = {};                         // reg/addr -> symbolic name
  sym.forEach(s => { if (s.reg) symKey["reg:" + s.reg] = s.name; if (s.addr != null) symKey["mem:" + s.addr] = s.name; });

  // Editable symbolic set — add/remove without reloading the snapshot. Each pill opens the
  // edit form; the "+ mark symbolic" button adds a new field; or just click a variable in
  // the decompilation. (snapSymbolicForm persists + re-renders.)
  const symBox = el("div", { style: "margin-top:4px" }, el("b", {}, "symbolic (attacker-controlled): "));
  if (sym.length) sym.forEach(s => {
    const label = (s.reg || hx64(s.addr)) + " = " + (s.name || "sym");
    symBox.append(el("span", { class: "pill bad", style: "margin-right:4px;cursor:pointer",
      title: "click to edit this symbolic field", onclick: (e) => snapSymbolicForm(init, s, e) },
      label, el("span", { style: "margin-left:6px;opacity:.7",
        onclick: (e) => { e.stopPropagation(); init.symbolic = (init.symbolic || []).filter(x => x !== s); A._vars = null; saveConfig().then(() => { renderState(); rerenderCodeViews(); toast("removed " + (s.name || "field")); }); } }, "✕")));
  });
  else symBox.append(el("span", { class: "faint" }, "nothing symbolic yet — click a variable in the decompilation, or:"));
  symBox.append(el("button", { class: "tiny primary", style: "margin-left:6px",
    onclick: (e) => snapSymbolicForm(init, {}, e) }, "+ mark symbolic"));

  wrap.append(el("div", { class: "statebox" },
    el("div", {}, el("b", {}, "PC: "), el("span", { class: "mono" }, hx64(init.pc)),
      el("span", { class: "faint", style: "margin-left:10px" }, "the run starts here; click a variable in the decompilation to make it symbolic")),
    symBox));

  const regs = init.regs || {};
  const rtbl = el("table", { class: "statetbl" });
  rtbl.append(el("tr", {}, el("th", {}, "register"), el("th", {}, "value"), el("th", {}, "")));
  Object.keys(regs).forEach(r => {
    const isSym = symKey["reg:" + r];
    rtbl.append(el("tr", { class: isSym ? "symrow" : "" },
      el("td", { class: "mono" }, r),
      el("td", { class: "mono" }, isSym ? "symbolic" : hx64(regs[r])),
      el("td", {}, isSym ? el("span", { class: "pill bad" }, isSym) : "")));
  });
  wrap.append(el("div", { class: "statelbl" }, "registers (concrete, from the live run)"), rtbl);

  const mem = init.mem || [];
  if (mem.length) {
    const mtbl = el("table", { class: "statetbl" });
    mtbl.append(el("tr", {}, el("th", {}, "address"), el("th", {}, "bytes"), el("th", {}, "preview")));
    mem.forEach(m => mtbl.append(el("tr", {},
      el("td", { class: "mono" }, hx64(m.addr)),
      el("td", {}, String((m.hex || "").length / 2)),
      el("td", { class: "mono faint" }, (m.hex || "").slice(0, 32) + ((m.hex || "").length > 32 ? "…" : "")))));
    wrap.append(el("div", { class: "statelbl" }, "memory regions (concrete)"), mtbl);
  }
  pane.replaceChildren(wrap);
}

async function clearInitialState() {
  const sc = activeScenario(); if (!sc) return;
  sc.initial_state = null;
  await saveConfig();
  renderState();
  toast("initial state reset to fresh call");
}

function openSnapshotLoader() {
  const sc = activeScenario(); if (!sc) return;
  const cur = sc.initial_state && sc.initial_state.kind === "snapshot" ? sc.initial_state : null;
  const ta = el("textarea", { class: "snapjson", placeholder: '{"pc":..., "regs":{...}, "mem":[{"addr":...,"hex":"..."}]}',
    style: "width:100%;height:160px;font-family:var(--mono);font-size:11px" },
    cur ? JSON.stringify({ pc: cur.pc, regs: cur.regs, mem: cur.mem }, null, 1) : "");
  const symIn = el("input", { type: "text", placeholder: "symbolic fields, e.g.  x1:coord, 0x16fdff000:len",
    style: "width:100%;font-family:var(--mono)", value: (cur && (cur.symbolic || []).map(s => (s.reg || hx64(s.addr)) + ":" + (s.name || "sym")).join(", ")) || "" });
  const applyBtn = el("button", { class: "primary" }, "Apply");
  const bg = modal("Load snapshot", el("div", {},
    el("div", { class: "faint", style: "margin-bottom:6px" }, "Paste a snapshot JSON (registers + memory from a real run, e.g. the lldb capture). Then list the attacker-controlled fields to make symbolic."),
    el("div", { class: "statelbl" }, "snapshot JSON"), ta,
    el("div", { class: "statelbl", style: "margin-top:8px" }, "symbolic fields  (reg:name or 0xADDR:name, comma-separated)"), symIn),
    [applyBtn]);
  ($("#modalHost") || document.body).append(bg);
  applyBtn.onclick = () => {
    let snap;
    try { snap = JSON.parse(ta.value); } catch (e) { toast("invalid JSON: " + e.message, true); return; }
    const symbolic = symIn.value.split(",").map(s => s.trim()).filter(Boolean).map(tok => {
      const [k, name] = tok.split(":").map(x => x.trim());
      return /^0x/i.test(k) ? { addr: parseInt(k, 16), name: name || "sym", size: 8 } : { reg: k, name: name || "sym", size: 8 };
    });
    sc.initial_state = { kind: "snapshot", pc: snap.pc, regs: snap.regs || {}, mem: snap.mem || [], symbolic };
    bg.remove();
    saveConfig().then(() => { renderState(); toast("snapshot loaded — Explore to run seeded"); });
  };
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

  // example inputs for the selected path, pinned at the top where the args arrive
  wrap.append(el("div", { class: "codeinputs", id: "codeInputs", style: "display:none" }));

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
    if (/call/.test(ins.mnemonic)) acts.append(btn("ƒ model", () => modelCall(ins), "tiny"));
    acts.append(btn("assert", () => openAssertModal(ins.addr), "tiny"));
    acts.append(btn("reach", () => addReachCheck(ins.addr, "reach"), "tiny"));
    acts.append(btn("⋯", () => openInsnMenu(ins), "tiny ghost"));

    const row = el("div", { class: "insn" + (ins.arith ? " arith" : ""), "data-addr": ins.addr, "data-block": ins.block },
      el("span", { class: "ad" }, hx64(ins.addr)),
      el("span", { class: "mn" }, ins.mnemonic),
      el("span", { class: "op" }, annotate(ins.op_str), ins.is_call && di.call_targets[ins.addr] ? "   ; " + (di.call_targets[ins.addr].name || "") : ""),
      callModelTag(ins),
      ins.src_line ? el("span", { class: "faint", style: "flex:0 0 auto;margin-right:6px" }, ":" + ins.src_line) : null,
      acts);
    // concrete value written here on the selected (seeded) path
    const av = A.pathAsgn && A.pathAsgn["0x" + ins.addr.toString(16)];
    if (av) {
      const val = av.store ? av.store.val : av.val;
      const dst = av.store ? "[" + av.store.addr + "]" : av.reg;
      if (val != null) row.append(el("span", { class: "cvals asgn", style: "flex:0 0 auto" }, `  ${dst} = ${val}`));
    }
    wrap.append(row);
  }
  pane.append(wrap);
  highlightHits();
}
const btn = (label, on, cls) => el("button", { class: cls || "tiny", onclick: (e) => { e.stopPropagation(); on(); } }, label);

function openInsnMenu(ins) {
  const host = $("#modalHost");
  const isCall = /call/.test(ins.mnemonic);
  const direct = isCall && /^0x[0-9a-fA-F]+$/.test((ins.op_str || "").trim());
  const callTargetName = direct ? funcNameAt(parseInt(ins.op_str, 16)) : null;
  const m = modal("At " + hx64(ins.addr) + "  " + ins.mnemonic + " " + ins.op_str,
    el("div", { class: "col", style: "gap:8px" },
      // model a call's return value
      (isCall && direct && callTargetName) ? menuItem("Set return model for " + callTargetName + "()",
        "replace this function with a modelled return, wherever it is called", () => { m.remove(); openReturnModelEditor({ name: callTargetName, addr: parseInt(ins.op_str, 16) }); }) : null,
      (isCall && !direct) ? menuItem("Model this indirect call", "replace this call-through-pointer with a modelled return",
        () => { m.remove(); openReturnModelEditor({ site: ins.addr, siteText: ins.mnemonic + " " + ins.op_str }); }) : null,
      ins.arith ? menuItem("Integer-overflow check here", "flag this add/sub/mul as possibly wrapping", () => { m.remove(); addOverflowCheck(ins); }) : null,
      menuItem("Assert an invariant here", "a boolean that should always hold at this point", () => { m.remove(); openAssertModal(ins.addr); }),
      menuItem("Reach check", "record any path that reaches this address", () => { m.remove(); addReachCheck(ins.addr, "reach"); }),
      menuItem("Avoid check", "record (and mark) paths that reach this address", () => { m.remove(); addReachCheck(ins.addr, "avoid"); }),
      menuItem("Custom Python check here", "run your own predicate at this point", () => { m.remove(); openCustomModal(ins.addr); })),
    [el("button", { onclick: () => m.remove() }, "Close")]);
  host.append(m);
}
function funcNameAt(addr) {
  const f = (A.functions || []).find(x => x.addr === addr);
  return f ? (f.ida_name || f.name) : null;
}
// open the right model editor for a call instruction (named function vs indirect site)
function modelCall(ins) {
  const direct = /^0x[0-9a-fA-F]+$/.test((ins.op_str || "").trim());
  const name = direct ? funcNameAt(parseInt(ins.op_str, 16)) : null;
  if (name) return openReturnModelEditor({ name, addr: parseInt(ins.op_str, 16) });
  return openReturnModelEditor({ site: ins.addr, siteText: ins.mnemonic + " " + ins.op_str });
}
// a tag shown next to a call in the code when a return model is set for it
function callModelTag(ins) {
  if (!/call/.test(ins.mnemonic)) return null;
  const direct = /^0x[0-9a-fA-F]+$/.test((ins.op_str || "").trim());
  let mdl = null, target = null;
  if (direct) { const nm = funcNameAt(parseInt(ins.op_str, 16)); mdl = modelForName(nm); if (mdl) target = { name: nm, addr: parseInt(ins.op_str, 16) }; }
  if (!mdl) { mdl = modelForSite(ins.addr); if (mdl) target = { site: ins.addr, siteText: ins.mnemonic + " " + ins.op_str }; }
  if (!mdl) return null;
  return el("span", { class: "modeltag", title: "modelled return — click to edit",
    onclick: (e) => { e.stopPropagation(); openReturnModelEditor(target); } }, "ƒ " + describeRetModel(mdl));
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
  body.append(sectionReturnModel());
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
    const bufr = A.config.buffers.find(x => x.arg === a.name);
    // One mutually-exclusive mode per argument: a scalar the solver chooses
    // (symbolic), a constant you supply (fixed), or a pointer at a symbolic
    // buffer / struct (buffer). "buffer" overrides the pointer value, so it
    // can't coexist with symbolic/fixed — hence a single 3-way selector.
    const curMode = bufr ? "buffer" : (a.mode === "concrete" ? "fixed" : "symbolic");
    const setMode = m => {
      if (m === "buffer") { toggleBuffer(a.name, true); return; }          // toggleBuffer re-renders
      if (bufr) A.config.buffers = A.config.buffers.filter(x => x.arg !== a.name);
      a.mode = (m === "fixed") ? "concrete" : "symbolic";
      renderRight(); scheduleSave();
    };
    const seg = (m, label, title) => el("div", { class: "segbtn" + (curMode === m ? " on" : ""), title, onclick: () => setMode(m) }, label);
    const modeS = el("div", { class: "seg" },
      seg("symbolic", "sym", "the solver chooses this value"),
      seg("fixed", "fixed", "a constant you supply"),
      seg("buffer", "buffer", "a pointer at a symbolic buffer / struct"));
    const sizeS = el("select", { onchange: e => { a.size = +e.target.value; scheduleSave(); } });
    [1, 2, 4, 8].forEach(sz => sizeS.append(el("option", { value: sz, selected: a.size === sz ? "" : null }, sz + "B")));
    let last = null;
    if (curMode === "fixed")
      last = el("input", { value: a.value ?? 0, placeholder: "value", oninput: e => { a.value = parseIntLoose(e.target.value); scheduleSave(); }, style: "width:78px" });
    else if (curMode === "symbolic")
      last = el("label", { class: "row", style: "font-size:11px;color:var(--dim);gap:3px" },
        el("input", { type: "checkbox", checked: a.signed ? "" : null, style: "width:auto", onchange: e => { a.signed = e.target.checked; scheduleSave(); } }), "signed");
    // buffer mode hides the byte-size select (pointer width is fixed); the buffer size lives below
    b.append(el("div", { class: "arg" }, nameI, modeS, curMode === "buffer" ? null : sizeS, last));
    // float toggle: passes this argument in an SSE register as a symbolic float/double
    if (curMode === "symbolic") {
      b.append(el("label", { class: "row", style: "font-size:11px;color:var(--faint);margin:-2px 0 8px 2px;gap:4px" },
        el("input", { type: "checkbox", checked: a.float ? "" : null, style: "width:auto",
          onchange: e => { a.float = e.target.checked; if (a.float && ![4, 8].includes(a.size)) a.size = 8; scheduleSave(); renderRight(); } }),
        "floating-point ", a.float ? el("span", { class: "faint" }, a.size === 4 ? "(float)" : "(double)") : el("span", { class: "faint" }, "(for float-point checks)")));
    }
    // buffer details: size + struct-layout editor (only in buffer mode)
    if (bufr) {
      b.append(el("div", { class: "row", style: "font-size:11px;color:var(--faint);margin:-2px 0 8px 2px;gap:4px;flex-wrap:wrap" },
        el("span", {}, "buffer"),
        el("input", { value: bufr.size || 64, style: "width:52px", oninput: e => { bufr.size = +e.target.value; scheduleSave(); } }),
        el("span", {}, "bytes · pointer is concrete, contents symbolic"),
        el("button", { class: "tiny", style: "margin-left:4px", title: "define struct members (from IDA or custom)",
          onclick: () => openStructEditor(a.name) },
          (bufr.layout && bufr.layout.length) ? `⚙ struct (${bufr.layout.length})` : "⚙ as struct")));
    }
  });

  // add an argument by hand — essential on stripped binaries where the calling
  // convention recovers 0 args (so there's nothing to click otherwise).
  b.append(el("button", { class: "tiny", style: "margin-top:2px",
    title: "add a function argument (symbolic by default)",
    onclick: () => {
      A.config.args = A.config.args || [];
      A.config.args.push({ name: "arg" + A.config.args.length, mode: "symbolic", size: 8 });
      renderRight(); scheduleSave();
    } }, "+ argument"));

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

// edit the struct a pointer argument points at: load the member layout from IDA (or
// build an anonymous one), choose sym/fixed + value per member, expand nested structs.
function openStructEditor(argName) {
  const bufr = A.config.buffers.find(x => x.arg === argName);
  if (!bufr) return;
  bufr.layout = bufr.layout || [];
  // A real combobox: a text field + a dropdown LIST of every struct IDA knows.
  // Click the caret (or focus) to open the whole list; typing filters it live;
  // click an entry (or Enter on the highlighted one) to load it.
  const combo = el("div", { class: "combo" });
  const typeI = el("input", { value: bufr.struct_type || "", placeholder: "choose or type a struct…", autocomplete: "off" });
  const caret = el("div", { class: "combo-caret", title: "show all structs" }, "▾");
  const listEl = el("div", { class: "combo-list", style: "display:none" });
  combo.append(typeI, caret, listEl);
  let allStructs = [];
  let activeIdx = -1;
  let loadErr = null;
  const highlight = (name, q) => {
    const i = q ? name.toLowerCase().indexOf(q) : -1;
    if (i < 0) return name;
    return [name.slice(0, i), el("span", { class: "cm-hit" }, name.slice(i, i + q.length)), name.slice(i + q.length)];
  };
  const matchesNow = () => {
    const q = typeI.value.trim().toLowerCase();
    return allStructs.filter(n => n.toLowerCase().includes(q));
  };
  const renderList = () => {
    const q = typeI.value.trim().toLowerCase();
    const matches = matchesNow();
    listEl.replaceChildren();
    if (!allStructs.length) {
      listEl.append(el("div", { class: "combo-empty" }, loadErr ? "IDA not connected — type a name and press Load" : "loading structs from IDA…"));
      return;
    }
    listEl.append(el("div", { class: "combo-head" }, matches.length + " of " + allStructs.length + " structs"));
    if (!matches.length) { listEl.append(el("div", { class: "combo-empty" }, "no match — press Load to try this name anyway")); return; }
    matches.slice(0, 300).forEach((n, i) => listEl.append(el("div", {
      class: "combo-item" + (i === activeIdx ? " active" : ""),
      // mousedown (not click) so it fires before the input's blur hides the list
      onmousedown: e => { e.preventDefault(); typeI.value = n; closeList(); loadFromIda(); },
    }, ...[].concat(highlight(n, q)))));
  };
  const openList = () => { listEl.style.display = ""; renderList(); };
  const closeList = () => { listEl.style.display = "none"; activeIdx = -1; };
  const toggleList = () => { listEl.style.display === "none" ? (typeI.focus(), openList()) : closeList(); };
  caret.addEventListener("mousedown", e => { e.preventDefault(); toggleList(); });
  typeI.addEventListener("focus", openList);
  typeI.addEventListener("input", () => { activeIdx = -1; openList(); });
  typeI.addEventListener("blur", () => setTimeout(closeList, 150));
  typeI.addEventListener("keydown", e => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (listEl.style.display === "none") { openList(); return; }
      const n = matchesNow().length;
      activeIdx = e.key === "ArrowDown" ? Math.min(activeIdx + 1, n - 1) : Math.max(activeIdx - 1, 0);
      renderList();
      listEl.querySelectorAll(".combo-item")[activeIdx]?.scrollIntoView({ block: "nearest" });
    } else if (e.key === "Enter") {
      e.preventDefault();
      const matches = matchesNow();
      if (activeIdx >= 0 && matches[activeIdx]) typeI.value = matches[activeIdx];
      closeList(); loadFromIda();
    } else if (e.key === "Escape") { closeList(); }
  });
  // populate the list with every struct IDA knows, so the user picks instead of recalling a name
  (async () => {
    try {
      const r = await api("/api/ida/structs");
      allStructs = r.structs || [];
      typeI.placeholder = allStructs.length ? `choose or type a struct (${allStructs.length})…` : "struct type name, e.g. TIFF";
    } catch (e) { loadErr = e; typeI.placeholder = "IDA not connected — type a name, e.g. TIFF"; }
    if (listEl.style.display !== "none") renderList();
  })();
  const tbl = el("div", { class: "structtbl" });
  const sizeI = el("input", { value: bufr.size || 64, style: "width:72px", oninput: e => { bufr.size = +e.target.value; scheduleSave(); } });

  const render = () => {
    bufr.layout.sort((a, b) => a.offset - b.offset);
    tbl.replaceChildren(el("div", { class: "strow sthead" },
      el("span", { class: "stoff" }, "offset"), el("span", { class: "grow" }, "member"),
      el("span", { class: "sttype" }, "type"), el("span", { class: "stmode" }, "value"), el("span", { style: "width:40px" })));
    if (!bufr.layout.length) { tbl.append(el("div", { class: "faint", style: "padding:10px" }, "No members yet — Load a struct from IDA above, or + member for a custom layout.")); return; }
    bufr.layout.forEach((m, i) => tbl.append(memberRow(m, i)));
  };
  const memberRow = (m, i) => {
    const sym = m.mode !== "fixed";
    return el("div", { class: "strow" + (m.is_struct ? " nest" : "") },
      el("input", { class: "stoff mono", value: m.offset, title: "byte offset", oninput: e => { m.offset = parseIntLoose(e.target.value); scheduleSave(); } }),
      el("input", { class: "stname grow", value: m.name || "", oninput: e => { m.name = e.target.value; scheduleSave(); } }),
      el("input", { class: "stsz mono", value: m.size || 1, title: "size (bytes)", oninput: e => { m.size = parseIntLoose(e.target.value) || 1; scheduleSave(); } }),
      el("span", { class: "sttype mono faint", title: m.type || "" }, (m.type || "").slice(0, 16) + (m.is_ptr ? " *" : "")),
      el("div", { class: "seg stseg" },
        el("div", { class: "segbtn" + (sym ? " on" : ""), onclick: () => { m.mode = "sym"; scheduleSave(); render(); } }, "sym"),
        el("div", { class: "segbtn" + (!sym ? " on" : ""), onclick: () => { m.mode = "fixed"; scheduleSave(); render(); } }, "fix")),
      sym ? el("span", { class: "faint stvalph" }, "symbolic")
          : el("input", { class: "stval mono", value: m.value ?? 0, oninput: e => { m.value = parseIntLoose(e.target.value); scheduleSave(); } }),
      (m.is_struct && m.type_name) ? btn("⤷", () => expandMember(m, i), "tiny ghost", "expand nested struct into its fields") : null,
      btn("✕", () => { bufr.layout.splice(i, 1); scheduleSave(); render(); }, "tiny ghost"));
  };
  async function expandMember(m, i) {
    try {
      const sd = await api("/api/ida/struct/" + encodeURIComponent(m.type_name));
      const subs = (sd.members || []).map(s => ({ offset: m.offset + s.offset, size: s.size,
        name: (m.name || argName) + "." + s.name, mode: "sym", type: s.type, is_ptr: s.is_ptr, is_struct: s.is_struct, type_name: s.type_name }));
      bufr.layout.splice(i, 1, ...subs);
      scheduleSave(); render();
    } catch (e) { toast("expand failed: " + e.message, true); }
  }
  async function loadFromIda() {
    const name = typeI.value.trim(); if (!name) { toast("enter a struct type name", true); return; }
    try {
      const sd = await api("/api/ida/struct/" + encodeURIComponent(name));
      bufr.struct_type = name;
      bufr.size = Math.max(bufr.size || 0, sd.size || 0); sizeI.value = bufr.size;
      bufr.layout = (sd.members || []).map(s => ({ offset: s.offset, size: s.size, name: argName + "." + s.name,
        mode: "sym", type: s.type, is_ptr: s.is_ptr, is_struct: s.is_struct, type_name: s.type_name }));
      scheduleSave(); render(); toast(`loaded ${name}: ${bufr.layout.length} members, ${sd.size} bytes`);
    } catch (e) { toast("load failed: " + e.message, true); }
  }
  const body = el("div", {},
    field("Struct type (from IDA)", el("div", { class: "row" }, combo, btn("Load", loadFromIda, "tiny primary"),
      btn("Label only", () => { const nm = typeI.value.trim(); if (!nm) { toast("pick a struct first", true); return; } bufr.struct_type = nm; scheduleSave(); toast(`buffer bytes will be labelled as ${nm} members in conditions`); }, "tiny")),
      "<b>Load</b> pulls the members in as editable rows (each becomes a symbolic/fixed field). <b>Label only</b> just records the type, so the whole buffer stays one symbolic blob but branch conditions read <code>tif-&gt;member</code> instead of <code>tif_buf[16]</code>. Click ▾ to browse every struct IDA knows."),
    el("div", { class: "row", style: "margin:8px 0 2px" }, el("span", { class: "faint" }, "buffer size"), sizeI, el("span", { class: "faint grow" }, "bytes"),
      btn("+ member", () => { bufr.layout.push({ offset: 0, size: 4, name: argName + ".m" + bufr.layout.length, mode: "sym" }); scheduleSave(); render(); }, "tiny")),
    tbl);
  render();
  const m = modal("Struct editor · " + argName, body, [el("button", { class: "primary", onclick: () => { renderRight(); m.remove(); } }, "Done")]);
  m.querySelector(".modal").classList.add("docs");
  $("#modalHost").append(m);
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
  models.forEach((m, i) => {
    const label = m.site != null ? hx64(m.site) : (m.func || "(unset)");
    b.append(el("div", { class: "modelrow" },
      el("span", { class: "mono mfn", title: RETMODEL_KINDS[m.kind] || "" }, m.site != null ? label + " (indirect)" : label + "()"),
      el("span", { class: "msum" }, describeRetModel(m)),
      btn("✎", () => openModelModal(i), "tiny ghost"),
      btn("✕", () => { models.splice(i, 1); renderRight(); scheduleSave(); }, "tiny ghost")));
  });
  s.append(b);
  return s;
}
function openModelModal(editIdx, preset) {
  const models = A.config.models || (A.config.models = []);
  const m = editIdx != null ? { ...models[editIdx] } : (preset ? { kind: "symbolic", ...preset } : { kind: "symbolic", func: "" });
  const isSite = m.site != null;
  // target: a named function (pick from the dropdown) OR an indirect call site (address)
  const targetSeg = el("div", { class: "seg" },
    el("div", { class: "segbtn" + (!isSite ? " on" : ""), "data-t": "func" }, "named function"),
    el("div", { class: "segbtn" + (isSite ? " on" : ""), "data-t": "site" }, "indirect call (by address)"));
  const combo = comboBox(allFunctionItems(), m.func || "", "choose or type a function (or 0x…)…");
  const siteCombo = comboBox(indirectCallSites().map(siteItemLabel), m.site != null ? hx64(m.site) : "", "choose an indirect call site in this function…");
  const targetWrap = el("div");
  const kindS = el("select", {});
  Object.entries(RETMODEL_KINDS).forEach(([k, d]) => kindS.append(el("option", { value: k, selected: m.kind === k ? "" : null }, k + " — " + d)));
  const params = el("div", { style: "margin-top:8px" });
  let mode = isSite ? "site" : "func";
  const drawTarget = () => {
    targetWrap.replaceChildren(mode === "site"
      ? field("Indirect call site", siteCombo.wrap, "Pick a <code>call [reg+…]</code> (through a function pointer) in this function. You can also click <b>ƒ model</b> on the call in the code view.")
      : field("Function to model", combo.wrap, "Any function the analysis calls — pick from the list (includes library/implicit functions) or type a name / 0x address."));
  };
  targetSeg.querySelectorAll(".segbtn").forEach(b => b.addEventListener("click", () => {
    mode = b.dataset.t; targetSeg.querySelectorAll(".segbtn").forEach(x => x.classList.toggle("on", x === b)); drawTarget();
  }));
  drawTarget();
  kindS.addEventListener("change", () => { m.kind = kindS.value; fillModelFields(m, params); });
  fillModelFields(m, params);
  const body = el("div", {},
    field("What to model", targetSeg, "angr's skip-calls bypasses models, so model the calls that matter (size/alloc/read-write, or a pointer call it can't resolve)."),
    targetWrap, field("Behavior", kindS), params);
  const mo = modal(editIdx != null ? "Edit call model" : "Add call model", body, [
    el("button", { onclick: () => mo.remove() }, "Cancel"),
    el("button", { class: "primary", onclick: () => {
      m.kind = kindS.value;
      if (mode === "site") {
        const a = parseIntLoose((siteCombo.get().split(/\s+/)[0]) || ""); if (!a) { toast("choose the indirect call site", true); return; }
        m.site = a; delete m.func;
      } else {
        const f = combo.get(); if (!f) { toast("choose the function to model", true); return; }
        m.func = f; delete m.site;
      }
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

// ==================================================================== global return models
const RETMODEL_KINDS = {
  concrete: "returns a constant",
  symbolic: "returns a fresh symbolic value",
  constrained: "symbolic, limited to a set of values (and/or a predicate)",
  expr: "returns an expression of the arguments",
  return_arg: "returns one of its arguments",
  alloc: "allocates a buffer sized by one arg (tracked for OOB-write)",
};
function describeRetModel(m) {
  if (!m) return "";
  if (m.kind === "concrete") return "→ " + (m.value ?? 0);
  if (m.kind === "symbolic") return "→ symbolic " + (m.name || "ret");
  if (m.kind === "constrained") return "→ ∈ {" + (m.values || []).join(", ") + "}" + (m.constraint ? " · " + m.constraint : "");
  if (m.kind === "expr") return "→ " + (m.expr || "");
  if (m.kind === "return_arg") return "→ arg" + (m.arg ?? 0);
  if (m.kind === "alloc") return "→ alloc(arg" + (m.size_arg ?? 0) + ")";
  return "→ " + m.kind;
}
// the per-kind field editor, shared by the call-model and return-model editors
function fillModelFields(m, params) {
  params.replaceChildren();
  const k = m.kind;
  if (k === "concrete")
    params.append(field("Return value", el("input", { value: m.value ?? 0, oninput: e => m.value = parseIntLoose(e.target.value), style: "width:140px" }), "e.g. 0 for success / failure, or a NULL/handle."));
  else if (k === "symbolic")
    params.append(field("Symbol name (shows in witnesses & conditions)", el("input", { value: m.name || "", placeholder: "e.g. scanline_size", oninput: e => m.name = e.target.value })),
      field("Return width (bits)", el("input", { value: m.bits || 64, oninput: e => m.bits = parseIntLoose(e.target.value) || 64, style: "width:90px" })));
  else if (k === "constrained")
    params.append(
      field("Allowed values (comma-separated)", el("input", { value: (m.values || []).join(", "), placeholder: "e.g. 0, 1", oninput: e => { m.values = e.target.value.split(",").map(x => x.trim()).filter(x => s_num(x)).map(x => parseIntLoose(x)); } }), "The return is symbolic but limited to this set — the solver won't explore other values."),
      field("Extra predicate (optional)", el("input", { value: m.constraint || "", placeholder: "e.g. ret s>= 0 && ret s< 100", oninput: e => m.constraint = e.target.value, style: "width:100%;box-sizing:border-box" }), "A boolean over <code>ret</code> (and arg0, arg1…)."));
  else if (k === "expr")
    params.append(field("Return = expression of the arguments", el("input", { value: m.expr || "", placeholder: "e.g. arg0 & 1   ·   arg0 == 0 ? 0 : 1", oninput: e => m.expr = e.target.value, style: "width:100%;box-sizing:border-box" }), "Replace the function with a formula over <code>arg0, arg1…</code> (ternary <code>cond ? a : b</code> supported)."));
  else if (k === "return_arg")
    params.append(field("Argument index", el("input", { value: m.arg ?? 0, oninput: e => m.arg = parseIntLoose(e.target.value), style: "width:90px" }), "0 = first argument."));
  else if (k === "alloc")
    params.append(field("Size argument index", el("input", { value: m.size_arg ?? 0, oninput: e => m.size_arg = parseIntLoose(e.target.value), style: "width:90px" }), "which argument holds the allocation size."),
      field("Name the pointer (optional)", el("input", { value: m.name || "", placeholder: "e.g. out_buf", oninput: e => m.name = e.target.value })));
}
// a reusable filterable dropdown (combobox): items = array of strings; returns {wrap, get}
function comboBox(items, value, placeholder) {
  const combo = el("div", { class: "combo" });
  const input = el("input", { value: value || "", placeholder: placeholder || "choose or type…", autocomplete: "off" });
  const caret = el("div", { class: "combo-caret", title: "show all" }, "▾");
  const list = el("div", { class: "combo-list", style: "display:none" });
  combo.append(input, caret, list);
  let active = -1;
  const matches = () => { const q = input.value.trim().toLowerCase(); return items.filter(n => n.toLowerCase().includes(q)); };
  const render = () => {
    const q = input.value.trim().toLowerCase(), ms = matches();
    list.replaceChildren();
    list.append(el("div", { class: "combo-head" }, ms.length + " of " + items.length));
    if (!ms.length) { list.append(el("div", { class: "combo-empty" }, "no match — type a name/0x… anyway")); return; }
    ms.slice(0, 300).forEach((n, i) => {
      const hit = q ? n.toLowerCase().indexOf(q) : -1;
      const label = hit < 0 ? n : [n.slice(0, hit), el("span", { class: "cm-hit" }, n.slice(hit, hit + q.length)), n.slice(hit + q.length)];
      list.append(el("div", { class: "combo-item" + (i === active ? " active" : ""),
        onmousedown: e => { e.preventDefault(); input.value = n; close(); } }, ...[].concat(label)));
    });
  };
  const open = () => { list.style.display = ""; render(); };
  const close = () => { list.style.display = "none"; active = -1; };
  caret.addEventListener("mousedown", e => { e.preventDefault(); list.style.display === "none" ? (input.focus(), open()) : close(); });
  input.addEventListener("focus", open);
  input.addEventListener("input", () => { active = -1; open(); });
  input.addEventListener("blur", () => setTimeout(close, 150));
  input.addEventListener("keydown", e => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); if (list.style.display === "none") { open(); return; } const n = matches().length; active = e.key === "ArrowDown" ? Math.min(active + 1, n - 1) : Math.max(active - 1, 0); render(); list.querySelectorAll(".combo-item")[active]?.scrollIntoView({ block: "nearest" }); }
    else if (e.key === "Enter") { e.preventDefault(); const ms = matches(); if (active >= 0 && ms[active]) input.value = ms[active]; close(); }
    else if (e.key === "Escape") close();
  });
  return { wrap: combo, get: () => input.value.trim() };
}
// all functions (named + unnamed) as dropdown items: "name  0xADDR"
function allFunctionItems() {
  return (A.functions || []).map(f => (f.ida_name || f.name)).filter(Boolean).sort();
}
// indirect call sites in the current function (call through a register/pointer)
function indirectCallSites() {
  const out = [];
  for (const i of (A.detail && A.detail.disasm ? A.detail.disasm.instructions : [])) {
    if (/call/.test(i.mnemonic) && /\[/.test(i.op_str || "")) out.push({ addr: i.addr, text: i.op_str, line: i.src_line });
  }
  return out;
}
const siteItemLabel = (s) => `${hx64(s.addr)}  ${s.text}${s.line ? "  ·L" + s.line : ""}`;
// target: {name, addr} for a statically-named function, or {site, siteText} for one call site.
function openReturnModelEditor(target) {
  const isSite = target.site != null;
  const key = isSite ? hx64(target.site) : target.name;
  const store = isSite ? A.models.by_site : A.models.by_name;
  const existing = store[key];
  const m = existing ? { ...existing } : { kind: isSite ? "concrete" : "symbolic", enabled: true };
  const kindS = el("select", {});
  Object.entries(RETMODEL_KINDS).forEach(([k, d]) => kindS.append(el("option", { value: k, selected: m.kind === k ? "" : null }, k + " — " + d)));
  const params = el("div", { style: "margin-top:8px" });
  const rebuild = () => fillModelFields(m, params);
  kindS.addEventListener("change", () => { m.kind = kindS.value; rebuild(); });
  rebuild();
  const head = isSite
    ? el("div", { class: "help", html: `Replace the <b>indirect call</b> at <code>${hx64(target.site)}</code>${target.siteText ? " (<code>" + esc(target.siteText) + "</code>)" : ""} with this return — handy for a call through a function pointer whose target angr can't resolve. Applies at this call site, in every run.` })
    : el("div", { class: "help", html: `Replace <b>${esc(target.name)}</b> with this return <b>wherever it is called</b>, in every analysis.` });
  const body = el("div", {}, head, field("Behavior", kindS), params);
  const foot = [
    existing ? el("button", { onclick: () => { delete store[key]; saveModels(); mo.remove(); afterModelChange(); toast("model removed"); } }, "Remove") : null,
    el("button", { onclick: () => mo.remove() }, "Cancel"),
    el("button", { class: "primary", onclick: () => {
      m.kind = kindS.value; m.enabled = true;
      if (isSite) m.site = target.site;
      else { m.func = target.name; if (target.addr != null) m.addr = target.addr; }
      store[key] = m; saveModels(); mo.remove(); afterModelChange(); toast("return model saved");
    } }, existing ? "Save" : "Add model"),
  ];
  const mo = modal((existing ? "Edit" : "Set") + " return model · " + (isSite ? hx64(target.site) : target.name), body, foot);
  $("#modalHost").append(mo);
}
const s_num = (s) => s !== "" && !isNaN(parseIntLoose(s));
function afterModelChange() {
  renderRight();
  if ($("#pane-code") && $("#pane-code").classList.contains("sel")) renderCode();
  if ($("#pane-decomp") && $("#pane-decomp").classList.contains("sel")) renderDecomp(true);
}
// the Setup-panel section for THIS function's own return model (+ any indirect-call
// models that live inside its body)
function sectionReturnModel() {
  const s = el("div", { class: "sec" });
  const name = A.fn.ida_name || A.fn.name;
  const mdl = modelForName(name);
  s.append(el("h3", {}, "Return model", el("span", { class: "grow" }),
    btn(mdl ? "✎ edit" : "+ set", () => openReturnModelEditor({ name, addr: A.fn.addr }), "tiny")));
  const b = el("div", { class: "body" });
  if (mdl) {
    b.append(el("div", { class: "modelrow" },
      el("span", { class: "mono mfn" }, name + "()"),
      el("span", { class: "msum" }, describeRetModel(mdl)),
      btn("✕", () => { delete A.models.by_name[name]; saveModels(); afterModelChange(); }, "tiny ghost")));
  }
  const lo = A.fn.addr, hi = A.fn.addr + (A.fn.size || 0x100000);
  const sites = Object.entries(A.models.by_site).filter(([h]) => { const a = parseInt(h, 16); return a >= lo && a < hi; });
  if (sites.length) {
    b.append(el("div", { class: "dlabel", style: "margin-top:10px" }, "Indirect calls modelled in this function"));
    sites.forEach(([h, m]) => b.append(el("div", { class: "modelrow" },
      el("span", { class: "mono mfn", style: "cursor:pointer", onclick: () => showAddr(parseInt(h, 16)) }, h),
      el("span", { class: "msum" }, describeRetModel(m)),
      btn("✎", () => openReturnModelEditor({ site: parseInt(h, 16) }), "tiny ghost"),
      btn("✕", () => { delete A.models.by_site[h]; saveModels(); afterModelChange(); }, "tiny ghost"))));
  }
  s.append(b);
  return s;
}

function sectionChecks() {
  const s = el("div", { class: "sec" });
  s.append(el("h3", {}, "Checks", el("span", { class: "grow" }),
    el("button", { class: "tiny ghost", title: "show these checks as angr code", onclick: () => showInScript("= checks") }, "</>"),
    el("button", { class: "tiny", onclick: (e) => openDetectMenu(e.currentTarget) }, "+ detect ▾"),
    btn("+ assert", () => openAssertModal(null), "tiny"),
    btn("+ custom", () => openCustomModal(null), "tiny")));
  const b = el("div", { class: "body" });
  A.config.checks.forEach((c, i) => b.append(renderCheck(c, i)));
  s.append(b);
  return s;
}
function renderCheck(c, i) {
  const box = el("div", { class: "check" + (c.enabled ? "" : " dis") });
  const kindPill = { int_overflow: "warn", narrowing_cast: "warn", float_anomaly: "warn", div_by_zero: "warn",
                     oob_write: "bad", oob_read: "bad", null_deref: "bad",
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
  if (c.kind === "oob_read") return `read outside ${c.base}[${c.size}]` + (c.addr ? " at " + hx64(c.addr) : "");
  if (c.kind === "null_deref") return (c.addr ? hx64(c.addr) : "whole function") + " · read/write through a NULL-able pointer";
  if (c.kind === "div_by_zero") return (c.addr ? hx64(c.addr) : "whole function") + " · divisor can be 0";
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
    A.selectedHit = null; A.selNode = null; A.pathHighlight = null; A.collapsed.clear(); A.loopCollapsed.clear();
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
  const scalars = Object.entries(wit).filter(([k, v]) => typeof v === "object" && !k.includes("->"));
  const byteInputs = Object.entries(wit).filter(([k, v]) => typeof v === "string" && v);
  if (scalars.length) box.append(el("div", { class: "wit" },
    el("span", { class: "faint" }, "inputs: "), ...scalars.map(([k, v]) => valChip(k, fmtOne(k, v)))));
  for (const [k, v] of byteInputs) {                 // file / stdin contents = the solution
    const name = k.startsWith("file:") ? k.slice(5) : k;
    box.append(el("div", { class: "wit solution" }, valChip(name, bytesPretty(v.replace(/(00)+$/, "")))));
  }
  const node = h.extra?.node;
  if (node != null) box.append(el("button", { class: "tiny ghost", style: "margin-top:4px",
    onclick: e => { e.stopPropagation(); A.selNode = node; updatePathHighlight(); selectTab("paths"); } }, "show its path"));
  box.addEventListener("click", () => {
    A.selectedHit = i;
    if (node != null) { A.selNode = node; updatePathHighlight(); }
    showAddr(h.addr);           // prefer the decompilation when IDA is connected (#1)
    renderTree(true);
  });
  return box;
}

// ==================================================================== code highlight
function scrollToAddr(addr) {
  const row = $(`.insn[data-addr="${addr}"]`, $("#pane-code"));
  if (row) { row.scrollIntoView({ block: "center", behavior: "smooth" }); row.classList.add("oncur"); setTimeout(() => row.classList.remove("oncur"), 1500); }
}
// The findings to light red RIGHT NOW: a clicked finding lights only its own line;
// a clicked path lights the findings that occur on that path (matched by node); no
// selection => nothing. Shared by the disassembly and decompilation views so they
// never diverge. Returns { addr -> hit }.
function litFindings() {
  const hits = (A.run && A.run.snapshot && A.run.snapshot.hits) || [];
  const m = {};
  if (A.selectedHit != null && hits[A.selectedHit]) {
    const h = hits[A.selectedHit]; m[h.addr] = h;
  } else if (A.pathNodeIds) {
    for (const h of hits) {
      const nd = h.extra && h.extra.node;
      if (nd != null && A.pathNodeIds.has(nd)) m[h.addr] = h;
    }
  }
  return m;
}
// the concrete inputs of the currently selected path/finding (the "example"),
// shown once at the top of the function where the arguments arrive.
function selectedInputs() {
  const hits = (A.run && A.run.snapshot && A.run.snapshot.hits) || [];
  if (A.selectedHit != null && hits[A.selectedHit]) return hits[A.selectedHit].witness;
  if (A.selNode != null && A.run && A.run.snapshot && A.run.snapshot.tree) {
    const n = A.run.snapshot.tree.find(x => x.id === A.selNode);
    if (n && n.example && Object.keys(n.example).length) return n.example;
    const first = Object.values(litFindings())[0];
    if (first) return first.witness;
  }
  return null;
}
function fmtInputs(wit) {
  return Object.entries(wit || {})
    .filter(([k, v]) => typeof v === "object" && v && !k.includes("->")
                        && !/_buf$/.test(k) && !/^(stdin|file:)/.test(k))   // skip buffer blobs / stdin / files
    .map(([k, v]) => `${k} = ${fmtOne(k, v)}`);
}

// A scrollable viewer for a long value (a buffer, a long byte string) — so it doesn't
// overflow a panel as an unclickable blob (#4). Click any truncated value to open it.
function openValueBox(title, text) {
  text = String(text);
  const ta = el("textarea", { readonly: "",
    style: "width:100%;height:min(55vh,340px);box-sizing:border-box;font-family:var(--mono);font-size:11px;white-space:pre-wrap;word-break:break-all" });
  ta.value = text;
  const copy = el("button", { class: "tiny" }, "⧉ Copy");
  copy.onclick = () => (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject())
    .then(() => toast("copied")).catch(() => toast("copy failed; select the text", true));
  const m = modal(title, el("div", {}, el("div", { class: "faint", style: "margin-bottom:4px" }, text.length + " characters"), ta),
    [copy, el("button", { class: "primary", onclick: () => m.remove() }, "Close")]);
  $("#modalHost").append(m);
}

// One input as a chip: the variable NAME highlighted (so it isn't a text blob, #3) and the
// value — truncated + click-to-expand when long (#4).
function valChip(name, valStr) {
  valStr = String(valStr);
  const LONG = 44;
  const val = valStr.length > LONG
    ? el("span", { class: "ci-val long", title: "click to view all " + valStr.length + " characters",
        onclick: (e) => { e.stopPropagation(); openValueBox(name, valStr); } }, valStr.slice(0, LONG) + "… ⤢")
    : el("span", { class: "ci-val" }, valStr);
  return el("span", { class: "ci-chip" }, el("span", { class: "ci-name" }, name), el("span", { class: "ci-eq" }, " = "), val);
}

// DOM version of fmtInputs: highlighted-name chips with expandable long values.
function fmtInputEls(wit) {
  return Object.entries(wit || {})
    .filter(([k, v]) => typeof v === "object" && v && !k.includes("->")
                        && !/_buf$/.test(k) && !/^(stdin|file:)/.test(k))
    .map(([k, v]) => valChip(k, fmtOne(k, v)));
}
function highlightHits() {
  const pane = $("#pane-code"); if (!pane) return;
  const path = A.pathHighlight;            // blocks on the selected path (or null)
  const litByAddr = litFindings();

  // the example inputs for this path, at the top (near where the args arrive)
  const banner = $("#codeInputs", pane);
  if (banner) {
    const chips = fmtInputEls(selectedInputs());
    banner.replaceChildren();
    if (chips.length) {
      banner.append(el("span", { class: "cilbl" }, "example inputs on this path:"),
                    el("span", { class: "civals" }, ...chips));
      banner.style.display = "";
    } else banner.style.display = "none";
  }

  $$(".insn", pane).forEach(r => {
    const addr = +r.dataset.addr, blk = +r.dataset.block;
    r.classList.toggle("onpath", !!path && path.has(blk));
    const h = litByAddr[addr];
    r.classList.toggle("hit", !!h);
    const old = r.querySelector(".exannot"); if (old) old.remove();
    if (h) {                               // on the offending line, the value of what it writes to
      const tgt = h.extra && h.extra.write_addr
        ? `dest = ${h.extra.write_addr}  (outside ${h.extra.buffer_base || "buf"} + ${h.extra.buffer_size ?? "?"})`
        : "";
      if (tgt) r.append(el("span", { class: "exannot" }, "  ; " + tgt));
    }
    const isBranch = !!A.branchPts && A.branchPts.has(addr);
    r.classList.toggle("branchpt", isBranch);
    if (isBranch) r.title = "branch taken on this flow: " + (A.branchCond[addr] || "?");
  });
}

// ==================================================================== path tree
// Each tree node is one stretch of execution between two splits. The root starts at
// the function entry; whenever a branch depends on the symbolic inputs, angr follows
// both sides and each side becomes a child, labelled with the condition it requires.
const END_STYLE = {
  returned: ["ok", "returned"], exit: ["warn", "exit"], ended: ["", "ended"],
  loop_bound: ["", "loop bound"], dropped: ["", "dropped"], unconstrained: ["bad", "hijackable"],
  unknown_call: ["warn", "unknown call"], error: ["warn", "error"], unfinished: ["info", "unfinished"], running: ["info", "running"],
};
let treeKey = "";

function renderTree(force) {
  const pane = pathsPaneEl(); if (!pane) return;
  const snap = A.run?.snapshot;
  if (!snap || !snap.tree || !snap.tree.length) {
    treeKey = "";
    pane.innerHTML = snap && ["pending", "running"].includes(snap.status)
      ? '<div class="empty">Exploring…</div>' : '<div class="empty">Run the checks to see the paths angr explored.</div>';
    return;
  }
  const key = snap.status + "|" + JSON.stringify(snap.tree).length + "|" + snap.hits.length + "|" + A.selNode + "|" + [...A.collapsed].join(",") + "|L" + [...A.loopCollapsed].join(",");
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

// find loops in the path tree: a node whose starting block was already executed by
// an ancestor is the loop header revisited (angr unrolls loops into repeated stretches).
function detectLoops(snap) {
  const byId = {}; snap.tree.forEach(n => byId[n.id] = n);
  const ancOrSelf = (aId, x) => { for (let c = x; c; c = byId[c.parent]) if (c.id === aId) return true; return false; };
  // group by the shallowest node that shares each reentry's block addr (the loop entry)
  const byEntry = {};
  snap.tree.forEach(n => {
    let entry = null;                               // shallowest strict ancestor with n's addr
    for (let c = byId[n.parent]; c; c = byId[c.parent]) if (c.addr === n.addr) entry = c;
    if (!entry) return;                             // not a loop reentry
    (byEntry[entry.id] = byEntry[entry.id] || { entry, header: n.addr, reentries: [] }).reentries.push(n);
  });
  const loops = [];
  for (const eid in byEntry) {
    const L = byEntry[eid], E = L.entry;
    // the loop spine: the entry down through every node that still leads to another iteration
    const nodeIds = new Set();
    snap.tree.forEach(x => {
      if (!ancOrSelf(E.id, x)) return;
      if (L.reentries.some(R => ancOrSelf(x.id, R))) nodeIds.add(x.id);
    });
    let iters = 1;                                  // header visits along the deepest chain
    L.reentries.forEach(R => { let c = 0; for (let p = R; p; p = byId[p.parent]) { if (p.addr === L.header) c++; if (p.id === E.id) break; } iters = Math.max(iters, c); });
    loops.push({ entryId: E.id, parentId: E.parent, header: L.header,
      line: (E.start && E.start.line) || (byId[L.reentries[0].id].start || {}).line || null,
      nodeIds, iters });
  }
  // every block inside a loop body repeats each iteration, so each would look like its
  // own loop. Keep only maximal regions: one box per real loop (the back-edge target).
  loops.sort((a, b) => b.nodeIds.size - a.nodeIds.size);
  const kept = [];
  for (const L of loops) {
    if (kept.some(K => [...L.nodeIds].every(id => K.nodeIds.has(id)))) continue;
    kept.push(L);
  }
  return kept;
}

// build the node list actually drawn: collapsed loops become one synthetic "⟳ loop" node
function displayTree(snap, loops) {
  const collapsed = loops.filter(L => A.loopCollapsed.has(L.entryId));
  if (!collapsed.length) return { nodes: snap.tree, loops, loopByEntry: {} };
  const hidden = new Set(), ownerOf = {}, loopByEntry = {};
  collapsed.forEach(L => { loopByEntry[L.entryId] = L; L.nodeIds.forEach(id => { hidden.add(id); ownerOf[id] = L.entryId; }); });
  const nodes = [];
  snap.tree.forEach(n => {
    if (loopByEntry[n.id]) nodes.push({ ...n, __loop: loopByEntry[n.id], end: null, hits: [] });
    else if (!hidden.has(n.id)) nodes.push({ ...n });
  });
  nodes.forEach(n => { if (!n.__loop && n.parent != null && hidden.has(n.parent)) n.parent = ownerOf[n.parent]; });
  return { nodes, loops, loopByEntry };
}

// the path tree drawn as an actual branching tree (nodes + edges), with pan/zoom
function drawPathTree(pane, T, snap) {
  if (typeof dagre === "undefined") { pane.textContent = "tree layout unavailable"; return; }
  const NS = "http://www.w3.org/2000/svg";
  const short = (s, n) => (s && s.length > n ? s.slice(0, n - 1) + "…" : (s || ""));
  const gr = new dagre.graphlib.Graph();
  // horizontal (left→right) in the wide Paths strip, top-down in the narrow dock
  // in the strip, the toggle picks horizontal (left→right) vs vertical (top→down); the narrow dock is always top→down
  const lr = A.pathsDock && A.pathsOrient !== "vertical";
  gr.setGraph({ rankdir: lr ? "LR" : "TB", nodesep: 16, ranksep: lr ? 46 : 30, marginx: 14, marginy: 14 });
  gr.setDefaultEdgeLabel(() => ({}));
  // loop boxes: fold detected loops to synthetic nodes, keep expanded ones for box overlay
  const loops = detectLoops(snap);
  const disp = displayTree(snap, loops);
  const dnodes = disp.nodes, dById = {}; dnodes.forEach(n => dById[n.id] = n);
  const dKids = {}; dnodes.forEach(n => { if (n.parent != null && dById[n.parent]) (dKids[n.parent] = dKids[n.parent] || []).push(n.id); });
  const CW = 6.3, PAD = 9;
  dnodes.forEach(n => {
    const leaf = !dKids[n.id];
    let label, sub;
    if (n.__loop) { label = "⟳ loop ×" + n.__loop.iters; sub = n.__loop.line ? "line " + n.__loop.line + " · click to expand" : "click to expand"; }
    else if (n.parent === null) { label = "start"; sub = `${A.fn ? (A.fn.ida_name || A.fn.name) : "fn"}(${((A.config && A.config.args) || []).map(a => a.name).join(", ")})`; }
    else { label = short(n.cond || "(branch)", 42); sub = n.decided_at && n.decided_at.line ? "line " + n.decided_at.line : ""; }
    if (leaf && !n.__loop) { const r = leafReason(n, snap); sub = (END_STYLE[r] ? END_STYLE[r][1] : r) + (n.hits.length ? " · finding" : ""); if (n.parent === null) label = "start"; }
    const w = Math.max(64, Math.min(280, Math.max(label.length, sub.length) * CW + PAD * 2));
    gr.setNode(n.id, { label, sub, leaf, node: n, loop: n.__loop || null, width: w, height: 32 });
  });
  dnodes.forEach(n => { if (n.parent != null && dById[n.parent]) gr.setEdge(n.parent, n.id); });
  dagre.layout(gr);
  const expandedLoops = loops.filter(L => !A.loopCollapsed.has(L.entryId) && [...L.nodeIds].every(id => gr.hasNode(id)));
  const W = gr.graph().width || 300, H = gr.graph().height || 200;

  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("width", "100%"); svg.setAttribute("height", "100%");
  svg.style.cssText = "display:block;background:var(--bg);cursor:grab;touch-action:none;user-select:none";
  svg.innerHTML = `<defs><marker id="ptarr" markerWidth="7" markerHeight="7" refX="6" refY="2.5" orient="auto"><path d="M0,0 L6,2.5 L0,5 Z" fill="var(--line2)"/></marker></defs>`;
  const viewport = document.createElementNS(NS, "g");
  svg.append(viewport);

  // labeled boxes around expanded loops (drawn first, so they sit behind the nodes)
  expandedLoops.forEach(L => {
    let x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9;
    L.nodeIds.forEach(id => { const g = gr.node(id); if (!g) return; x0 = Math.min(x0, g.x - g.width / 2); y0 = Math.min(y0, g.y - g.height / 2); x1 = Math.max(x1, g.x + g.width / 2); y1 = Math.max(y1, g.y + g.height / 2); });
    if (x1 < x0) return;
    const PADB = 10, hdr = 15;
    const box = document.createElementNS(NS, "g");
    const rect = document.createElementNS(NS, "rect");
    rect.setAttribute("x", x0 - PADB); rect.setAttribute("y", y0 - PADB - hdr);
    rect.setAttribute("width", x1 - x0 + PADB * 2); rect.setAttribute("height", y1 - y0 + PADB * 2 + hdr);
    rect.setAttribute("rx", 8); rect.setAttribute("fill", "var(--accent)"); rect.setAttribute("fill-opacity", "0.05");
    rect.setAttribute("stroke", "var(--accent)"); rect.setAttribute("stroke-opacity", "0.5");
    rect.setAttribute("stroke-width", "1.2"); rect.setAttribute("stroke-dasharray", "5 3");
    box.append(rect);
    const lbl = document.createElementNS(NS, "text");
    lbl.setAttribute("x", x0 - PADB + 8); lbl.setAttribute("y", y0 - PADB - hdr + 11);
    lbl.setAttribute("font-family", "var(--sans)"); lbl.setAttribute("font-size", "10"); lbl.setAttribute("font-weight", "600");
    lbl.setAttribute("fill", "var(--accent)");
    lbl.textContent = `⟳ loop${L.line ? " · line " + L.line : ""} · ${L.iters} iteration${L.iters === 1 ? "" : "s"} · ▸ collapse`;
    lbl.style.cursor = "pointer";
    lbl.addEventListener("click", ev => { ev.stopPropagation(); if (!dragged) { A.loopCollapsed.add(L.entryId); renderTree(true); } });
    box.append(lbl);
    viewport.append(box);
  });

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
    gEl.addEventListener("click", () => { if (dragged) return; if (g.loop) { A.loopCollapsed.delete(g.loop.entryId); renderTree(true); } else selectPathNode(+id); });
    nodeEls[id] = { rect, t1, t2, node: g.node, leaf: g.leaf, loop: g.loop };
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
      if (ne.loop) {
        ne.rect.setAttribute("fill", tint(accent, .12));
        ne.rect.setAttribute("stroke", accent);
        ne.rect.setAttribute("stroke-width", "1.5"); ne.rect.setAttribute("stroke-dasharray", "4 2");
        ne.t1.setAttribute("fill", accent); if (ne.t2) ne.t2.setAttribute("fill", dim);
        continue;
      }
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
  const inner = detailPaneEl(); if (!inner) return;
  const paths = A.pathsDock;
  const snap = A.run?.snapshot;
  const T = snap && snap.tree ? pathModel(snap) : null;
  if (!T || A.selNode == null || !T.byId[A.selNode]) {
    inner.replaceChildren(el("div", { class: "empty" }, paths ? "Click a path on the left to see its detail here." : "Click a path in the dock to see its full detail here."));
    if (!paths && $("#bottomTtl")) $("#bottomTtl").textContent = "Path detail";
    return;
  }
  inner.replaceChildren(renderPathDetail(T, snap));
  const n = T.byId[A.selNode];
  if (!paths) {
    $("#bottomTtl").textContent = "Path detail · " + (T.kids[n.id] ? "branch point" : "path #" + T.leafNo[n.id]);
    $("#bottomPanel").classList.remove("collapsed");
    $("#bottomClose").textContent = "▾";
  }
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
    dropped: "dropped (max active)", unconstrained: "hijackable jump", unknown_call: "unknown call target", error: "errored", unfinished: "unfinished", running: "still running" };
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
  A.selectedHit = null;                 // path selection lights the findings ON this path
  updatePathHighlight();
  renderTree(true);
}

function updatePathHighlight() {
  // the blocks executed from the function entry down to the selected node, plus the
  // branch decisions taken along the way (the conditional at each split, and which side)
  const snap = A.run?.snapshot;
  A.pathHighlight = null; A.pathNodeIds = null; A.branchPts = null; A.branchBlocks = null; A.branchCond = null;
  A.pathAsgn = null;
  if (snap && snap.tree && A.selNode != null) {
    const T = pathModel(snap);
    if (T.byId[A.selNode]) {
      const chain = T.chain(A.selNode);
      A.pathHighlight = new Set(chain.flatMap(n => n.blocks));
      A.pathNodeIds = new Set(chain.map(n => n.id));
      A.branchPts = new Set(); A.branchBlocks = new Set(); A.branchCond = {}; A.branchBlockCond = {}; A.branchBlockInsn = {};
      const a2b = decompAddrBlock();
      chain.forEach(n => {
        if (n.parent !== null && n.decided_at && n.decided_at.addr != null) {
          const ad = n.decided_at.addr;
          A.branchPts.add(ad);
          A.branchCond[ad] = n.cond || "";
          const bl = a2b[ad];
          if (bl != null) { A.branchBlocks.add(bl); A.branchBlockCond[bl] = n.cond || ""; A.branchBlockInsn[bl] = ad; }
        }
      });
    }
  }
  highlightHits();
  if ($("#pane-decomp").classList.contains("sel")) renderDecomp();   // re-tint decompilation lines (cached, no refetch)
  renderPathGraph();                                                  // the docked graph, always visible
  loadPathValues();                                                  // per-line assigned values for this path (async)
}

// Fetch the concrete value assigned on each line for the selected path, then re-tint.
async function loadPathValues() {
  const id = A.run && A.run.id, node = A.selNode;
  if (id == null || node == null) return;
  const key = id + ":" + node;
  A._pvCache = A._pvCache || {};
  try {
    A.pathAsgn = A._pvCache[key] || (A._pvCache[key] = (await api(`/api/run/${id}/values?node=${node}`)).values || {});
  } catch (e) { A.pathAsgn = null; return; }
  if (A.selNode === node) {   // still the same selection
    if ($("#pane-decomp").classList.contains("sel")) renderDecomp();
    if ($("#pane-code").classList.contains("sel")) renderCode();   // disasm also shows per-line values
  }
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
  // offer to model an undetermined indirect-call target right here
  if (leaf && n.end && n.end.reason === "unknown_call" && n.end.site != null)
    colB.append(el("button", { class: "tiny primary", style: "margin-top:6px",
      onclick: () => openModelModal(null, { kind: "symbolic", site: n.end.site }) }, "ƒ model this call"));
  if (calls.length) colB.append(el("div", { class: "pchip", style: "margin-top:6px" }, "calls " + calls.map(c => c + "()").join(", ")));
  // top-level inputs only (args / stdin / buffer); per-struct-field values annotate the code view
  const exTop = leaf && n.example ? Object.entries(n.example).filter(([k]) => !k.includes("->")) : [];
  if (exTop.length) {
    colB.append(el("div", { class: "dlabel", style: "margin-top:10px" }, "Example input"));
    const tb = el("div", { class: "dex" });
    exTop.forEach(([k, v]) => {
      const vs = String(fmtOne(k, v)), long = vs.length > 44;
      tb.append(el("div", {}, el("span", { class: "k" }, k),
        el("span", long ? { class: "long", title: "click to view all " + vs.length + " chars",
            onclick: () => openValueBox(k, vs) } : {}, long ? vs.slice(0, 44) + "… ⤢" : vs)));
    });
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
// The concrete values the inputs take on the currently-selected flow (its witness),
// formatted for display. A branch node borrows a representative descendant leaf's witness.
function selectedPathValues() {
  const snap = A.run && A.run.snapshot;
  if (!snap || !snap.tree || A.selNode == null) return null;
  const T = pathModel(snap);
  let n = T.byId[A.selNode];
  if (!n) return null;
  while (n && (!n.example || !Object.keys(n.example).length) && T.kids[n.id] && T.kids[n.id].length)
    n = T.byId[T.kids[n.id][0].id];
  const ex = n && n.example;
  if (!ex || !Object.keys(ex).length) return null;
  const out = {};
  for (const [k, v] of Object.entries(ex)) out[k] = (typeof v === "string") ? bytesPretty(v) : fmtOne(k, v);
  return { vals: out, ret: (T.byId[A.selNode] && T.byId[A.selNode].ret) };
}
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function decompAddrBlock() {
  const m = {};
  for (const ins of (A.detail && A.detail.disasm ? A.detail.disasm.instructions : [])) m[ins.addr] = ins.block;
  return m;
}
function renderDecompLines(code, into) {
  const a2b = decompAddrBlock();
  const path = A.pathHighlight;                       // Set of block addrs, or null
  const lit = litFindings();                          // addr -> hit, selection-based, per-line
  // pass 1: parse each source line into {text, addr, blk}
  const rows = code.split("\n").map(raw => {
    const m = _DECOMP_MARK.exec(raw);
    const addr = m ? parseInt(m[1], 16) : null;
    return { text: m ? raw.slice(0, m.index) : raw, addr, blk: addr != null ? a2b[addr] : null };
  });
  // For a branch line on the path, did its "then" body actually run? We look at the
  // next source line in a *different* block (skipping braces / same-block lines) and
  // check whether that block is on the selected path — robust against jump-polarity.
  const branchTaken = (i) => {
    if (!path) return null;
    const myBlk = rows[i].blk;
    for (let j = i + 1; j < rows.length; j++) {
      if (rows[j].addr == null || rows[j].blk == null || rows[j].blk === myBlk) continue;
      return path.has(rows[j].blk);
    }
    return null;
  };
  // A branch block can hold several source lines (an assignment + the `if` that ends it).
  // Only the line that actually *is* the branch — nearest to its conditional-jump
  // instruction — should carry the taken/not-taken badge.
  const branchRow = {};   // block addr -> row index of its decision line
  if (A.branchBlocks) {
    A.branchBlocks.forEach(blk => {
      const insn = A.branchBlockInsn ? A.branchBlockInsn[blk] : null;
      let best = -1, bestAddr = -1;
      rows.forEach((r, i) => {
        if (r.blk === blk && r.addr != null && (insn == null || r.addr <= insn) && r.addr > bestAddr) { bestAddr = r.addr; best = i; }
      });
      if (best >= 0) branchRow[blk] = best;
    });
  }
  // concrete values of the flow's inputs, to annotate the code where they appear
  const pvd = path ? selectedPathValues() : null;
  const pv = pvd && pvd.vals;
  // annotate inputs: scalar args/locals (whole-word), and struct fields like tif->tif_diroff
  // (substring). Skip the raw buffer blob and stdin/file byte strings.
  const pvKeys = pv ? Object.keys(pv).filter(k => !/_buf$/.test(k) && !/^(stdin|file:)/.test(k)) : [];
  const valAnnot = (line, onPath) => {
    if (!pv || !onPath) return null;
    const parts = [];
    for (const k of pvKeys) {
      const isField = /[.>]/.test(k);                 // tif->field / tif.field -> substring match
      const re = isField ? new RegExp(reEsc(k)) : new RegExp("(^|[^\\w.])" + reEsc(k) + "([^\\w]|$)");
      if (re.test(line)) parts.push(k + " = " + pv[k]);
    }
    if (/\breturn\b/.test(line) && pvd.ret) parts.push("⇒ " + pvd.ret);
    return parts.length ? el("span", { class: "cvals", title: "values on the selected flow" }, parts.join("   ")) : null;
  };
  // source line (DWARF) for the gutter: nearest instruction at or before the address —
  // matches the disassembly's `:NNN` and the `ret_L<line>` names in the path conditions
  const slArr = [];
  for (const ins of (A.detail && A.detail.disasm ? A.detail.disasm.instructions : [])) if (ins.src_line) slArr.push([ins.addr, ins.src_line]);
  slArr.sort((a, b) => a[0] - b[0]);
  const srcLineAt = (addr) => {
    let lo = 0, hi = slArr.length - 1, res = null;
    while (lo <= hi) { const m = (lo + hi) >> 1; if (slArr[m][0] <= addr) { res = slArr[m][1]; lo = m + 1; } else hi = m - 1; }
    return res;
  };
  let lastSl = null;
  rows.forEach((r, i) => {
    const div = el("div", { class: "cline" });
    const gutter = el("span", { class: "clnum" });
    const content = el("span", { class: "cltext" });
    if (r.addr != null) {
      div.dataset.addr = r.addr;
      div.title = hx64(r.addr) + " — click for checks";
      const sl = srcLineAt(r.addr);
      if (sl != null) { gutter.textContent = sl; if (sl === lastSl) gutter.classList.add("dup"); lastSl = sl; }  // dim repeats of the same source line
      const blk = r.blk;
      const onPath = !!(path && blk != null && path.has(blk));
      if (onPath) div.classList.add("onpath");
      let badge = null;
      if (A.branchBlocks && blk != null && A.branchBlocks.has(blk) && branchRow[blk] === i) {
        div.classList.add("branchpt");
        div.title = hx64(r.addr) + " — branch on this flow: " + (A.branchBlockCond[blk] || "?");
        const taken = branchTaken(i);
        if (taken !== null)
          badge = el("span", { class: "cbadge " + (taken ? "taken" : "nottaken"),
            title: "on the selected path, this branch was " + (taken ? "taken" : "not taken") },
            taken ? "✓ taken" : "✗ not taken");
      }
      const litH = lit[r.addr];                       // red only the finding's own line, on selection
      if (litH) div.classList.add("hitline");
      highlightC(r.text.length ? r.text : " ", content);
      if (badge) content.append(badge);
      if (litH && litH.extra && litH.extra.write_addr)  // offending line: the value it writes to
        content.append(el("span", { class: "exannot" },
          `  ; dest = ${litH.extra.write_addr} (outside ${litH.extra.buffer_base || "buf"} + ${litH.extra.buffer_size ?? "?"})`));
      // value of the variable assigned on this line, on the selected path
      const av = A.pathAsgn && A.pathAsgn["0x" + r.addr.toString(16)];
      if (av && !litH) {
        const m = r.text.match(/^\s*(\*?[A-Za-z_]\w*(?:\[[^\]]*\])?)\s*(?:[|&^+\-*/<>%]*=)(?!=)/);
        const val = av.store ? av.store.val : av.val;
        if (m && val != null) content.append(el("span", { class: "cvals asgn" }, `  ${m[1]} = ${val}`));
      }
      const vals = valAnnot(r.text, onPath);
      if (vals) content.append(vals);
      div.append(gutter, content);
      div.append(el("span", { class: "clacts" },
        btn("reach", () => addReachCheck(r.addr, "reach"), "tiny"),
        btn("⋯", () => openAddrMenu(r.addr), "tiny ghost")));
    } else {
      highlightC(r.text.length ? r.text : " ", content);
      div.append(gutter, content);
    }
    into.append(div);
  });
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
  // recolor the graph in place (keeps pan/zoom) — only node fills/edges follow the theme;
  // the instruction syntax colours are fixed, so no re-layout is needed
  const b = $("#dockGraph"); if (b && b._cfg) b._cfg.recolor();
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

const PANEL_FOR = { left: "left", right: "right", center: "centerCol", pbdetail: "pbDetail" };
function initSplitters() {
  // vertical splitters resize a column's width
  for (const sp of $$(".splitter")) {
    const target = sp.dataset.target, panel = $("#" + PANEL_FOR[target]);
    if (!panel) continue;
    try { const w = localStorage.getItem("panelW:" + target); if (w) panel.style.width = w; } catch (e) {}
    sp.addEventListener("mousedown", ev => {
      ev.preventDefault(); sp.classList.add("dragging");
      const startX = ev.clientX, startW = panel.getBoundingClientRect().width;
      const leftGrows = target === "left" || target === "center";   // left/code grow with +dx; right with -dx
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
    const target = sp.dataset.target;                 // "dockv" (graph height), "bottom", or "pathsbottom"
    const box = target === "bottom" ? $("#bottomPanel") : target === "pathsbottom" ? $("#pathsBottom") : $("#dockGraph");
    if (!box) continue;
    const grow = (target === "bottom" || target === "pathsbottom") ? -1 : 1;  // bottom strips grow when dragging up
    try { const h = localStorage.getItem("h:" + target); if (h) box.style.height = h; } catch (e) {}
    sp.addEventListener("mousedown", ev => {
      ev.preventDefault(); sp.classList.add("dragging");
      const startY = ev.clientY, startH = box.getBoundingClientRect().height;
      const move = e => { box.style.height = Math.max(60, startH + grow * (e.clientY - startY)) + "px"; };
      const up = () => {
        sp.classList.remove("dragging");
        window.removeEventListener("mousemove", move); window.removeEventListener("mouseup", up);
        try { localStorage.setItem("h:" + target, box.style.height); } catch (e) {}
        if (target === "dockv") regraph();
      };
      window.addEventListener("mousemove", move); window.addEventListener("mouseup", up);
    });
  }
}
function regraph() { const b = $("#dockGraph"); if (b && b._cfg) delete b._cfg; renderPathGraph(); }

// a quick layout preset: Setup (configure, both panels) vs Explore (paths, Setup
// hidden + wider graph/paths dock + the path-detail panel open)
function setViewMode(mode, initial) {
  A.viewMode = mode;
  try { localStorage.setItem("viewMode", mode); } catch (e) {}
  const bottom = $("#bottomPanel"), bclose = $("#bottomClose");
  if (mode === "explore") {
    // Explore: maximise the code + graph by hiding BOTH side panels
    setPanelCollapsed("left", true);
    setPanelCollapsed("right", true);
    if (bottom) { bottom.classList.remove("collapsed"); if (bclose) bclose.textContent = "▾"; }
  } else {
    // Setup: both side panels shown
    setPanelCollapsed("left", false);
    setPanelCollapsed("right", false);
    if (bottom && !initial) { bottom.classList.add("collapsed"); if (bclose) bclose.textContent = "▴"; }
  }
  $$("#viewMode .segbtn").forEach(x => x.classList.toggle("on", x.dataset.mode === mode));
  regraph();
}

// The Paths strip is an INDEPENDENT toggle (works in either Setup or Explore): a wide
// bottom panel with the path tree (laid left→right) above the path detail.
function setPathsDock(on, initial) {
  A.pathsDock = on;
  try { localStorage.setItem("pathsDock", on ? "1" : "0"); } catch (e) {}
  document.body.classList.toggle("paths", on);
  syncPathsToggle();
  // the paths move between #dockPaths and #pbPaths (and change orientation), so re-render
  A._ptreeSig = null;
  renderTree(true);
  updateBottomDetail();
  regraph();
}
function setPathsOrient(orient) {
  A.pathsOrient = orient;
  try { localStorage.setItem("pathsOrient", orient); } catch (e) {}
  syncPathsToggle();
  A._ptreeSig = null;
  renderTree(true);
}
// one segment highlighted only while the strip is open, showing which layout is active
function syncPathsToggle() {
  $$("#pathsToggle .segbtn").forEach(x => x.classList.toggle("on", A.pathsDock && x.dataset.orient === A.pathsOrient));
}

// the paths list/tree and the path detail live in different containers depending on
// whether the Paths strip is open: the right-hand dock, or the wide bottom strip.
function pathsPaneEl() { return A.pathsDock ? $("#pbPaths") : $("#dockPaths"); }
function detailPaneEl() { return A.pathsDock ? $("#pbDetail") : $("#bottomInner"); }

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
      // exact line for this address, else the nearest decompiled line at or before it
      // (a finding's instruction may sit between pseudocode lines) — so the right line
      // always highlights, not "something nearby".
      let line = $(`#pane-decomp .cline[data-addr="${addr}"]`);
      if (!line) {
        let best = null, bestA = -1;
        $$(`#pane-decomp .cline[data-addr]`).forEach(el => {
          const a = +el.dataset.addr;
          if (a <= addr && a > bestA) { bestA = a; best = el; }
        });
        line = best;
      }
      if (line) { line.scrollIntoView({ block: "center", behavior: "smooth" }); line.classList.add("flash"); setTimeout(() => line.classList.remove("flash"), 1400); }
      else { selectTab("code"); scrollToAddr(addr); }
    }, 350);
  } else { selectTab("code"); scrollToAddr(addr); }
}

function openAddrMenu(addr) {
  // calls on this source line (same block) can have their return modelled
  const a2b = decompAddrBlock();
  const blk = a2b[addr];
  const calls = (A.detail?.disasm?.instructions || []).filter(i =>
    /call/.test(i.mnemonic) && (i.addr === addr || (blk != null && a2b[i.addr] === blk)));
  const callItems = calls.map(ins => {
    const direct = /^0x[0-9a-fA-F]+$/.test((ins.op_str || "").trim());
    const nm = direct ? funcNameAt(parseInt(ins.op_str, 16)) : null;
    const label = nm ? ("Set return model for " + nm + "()") : ("Model the indirect call (" + ins.op_str + ")");
    return menuItem(label, "replace this call's return value with a model", () => { m.remove(); modelCall(ins); });
  });
  const m = modal("At " + hx64(addr), el("div", { class: "col", style: "gap:8px" },
    ...callItems,
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
    models: (A.config.models || []).filter(m => m.func || m.site != null),
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
  const input = el("input", { value: url, placeholder: "http://<host>:<port>/mcp", style: "width:100%" });
  const status = el("div", { class: "faint mono", style: "font-size:11px;margin-top:6px" },
    A.ida && A.ida.connected ? `connected · ${A.ida.server || ""} · ${A.ida.flavor || ""} · ${A.ida.name_count || 0} names` : "not connected");
  const body = el("div", {},
    field("IDA MCP server URL", input,
      "Point at a running IDA MCP server — <code>http://&lt;host&gt;:&lt;port&gt;/mcp</code>. Use <code>127.0.0.1</code> when IDA runs on this machine, " +
      "or the host's IP/name when it's elsewhere (e.g. a VM). Official Hex-Rays default: <code>http://127.0.0.1:8737/mcp</code> (IDA ≥9.4); " +
      "community <b>mrexodia/ida-pro-mcp</b> commonly <code>…:8744/mcp</code> (IDA ≥8.3). " +
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
  // example inputs for the selected path, pinned at the top (where the args arrive)
  const inChips = fmtInputEls(selectedInputs());
  const inbar = inChips.length
    ? el("div", { class: "codeinputs" },
        el("span", { class: "cilbl" }, "example inputs on this path:"),
        el("span", { class: "civals" }, ...inChips))
    : null;
  pane.replaceChildren(el("div", { class: "decompwrap" }, bar, inbar, assumptionsBar(), pre));
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
// The calling-convention argument registers, so a decompiled argument (a1, a2, …) can
// be mapped to the register it arrives in when the initial state is a concolic SNAPSHOT
// (snapshots mark symbolic fields by register/address, not by "arg").
function abiArgRegs() {
  const arch = (A.binary && A.binary.arch) || "";
  if (/AARCH64|ARM64/i.test(arch)) return ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
  if (/AMD64|X86_64|X64/i.test(arch)) return ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
  return [];
}
// The active scenario's snapshot initial_state, or null (fresh-call mode).
function activeSnapshot() {
  const i = A.config && A.config.initial_state;
  return i && i.kind === "snapshot" ? i : null;
}

function varModel() {
  const tok = {};
  const snap = activeSnapshot();
  if (snap) {
    // SNAPSHOT mode: there are no "args" — symbolic inputs are fields of initial_state.
    // Make (a) the ABI argument registers clickable via their decompiler names (a1..),
    // so you can symbolize an argument by clicking it, and (b) every current symbolic
    // field clickable by the name you gave it, so it shows tinted and can be edited.
    abiArgRegs().forEach((reg, idx) => {
      const ex = (snap.symbolic || []).find(s => s.reg === reg);
      const info = { snap: true, reg, name: ex ? ex.name : ("a" + (idx + 1)),
                     size: ex ? ex.size : 8, mode: ex ? "symbolic" : "concrete" };
      tok["a" + (idx + 1)] = info; tok["arg" + idx] = info;
      if (ex) for (const t of aliasesOf(ex.name)) tok[t] = info;
    });
    (snap.symbolic || []).forEach(s => {
      const info = { snap: true, reg: s.reg, addr: s.addr, name: s.name, size: s.size || 8, mode: "symbolic" };
      for (const t of aliasesOf(s.name)) tok[t] = info;
      if (s.reg) tok[s.reg] = info;
    });
    return tok;
  }
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
// re-render whichever code view is showing so symbolic tinting / values update in place
function rerenderCodeViews() {
  if ($("#pane-code") && $("#pane-code").classList.contains("sel")) renderCode();
  if ($("#pane-decomp") && $("#pane-decomp").classList.contains("sel") && typeof renderDecomp === "function") renderDecomp();
}

// The one place to add/edit/remove a SNAPSHOT symbolic field — no reload of the snapshot
// needed. Reached by clicking a variable/argument in the code, or "+ mark symbolic" in the
// State tab. `prefill` may carry {name, reg, addr, size} guessed from the clicked token.
function snapSymbolicForm(snap, prefill, ev) {
  $("#varMenu")?.remove();
  prefill = prefill || {};
  // the field already in the symbolic list that this click refers to (by name, reg, or addr)
  const existing = (snap.symbolic || []).find(s =>
    (prefill.name && s.name === prefill.name) ||
    (prefill.reg && s.reg === prefill.reg) ||
    (prefill.addr != null && s.addr === prefill.addr));
  const f = existing || {};
  const m = el("div", { class: "popmenu vmenu", id: "varMenu" });
  m.append(el("div", { class: "vmhead" }, el("b", {}, f.name || prefill.name || "mark symbolic"),
    el("span", { class: "faint" }, existing ? "symbolic — attacker-controlled" : "currently concrete (from the snapshot)")));
  m.append(el("div", { class: "faint", style: "margin-bottom:6px;font-size:11px" },
    "Make this field unknown so the solver searches over it. Bind it to the register it lives in, or to a memory address."));

  m.append(el("div", { class: "vmlbl" }, "name (shows up in the witness)"));
  const nameI = el("input", { value: f.name || prefill.name || "", placeholder: "coord", style: "width:100%;box-sizing:border-box;margin-bottom:6px" });
  m.append(nameI);

  m.append(el("div", { class: "vmlbl" }, "bind to"));
  const kind = (f.addr != null) ? "addr" : "reg";
  const kindS = el("select", { style: "width:100%;box-sizing:border-box;margin-bottom:6px" },
    el("option", { value: "reg", selected: kind === "reg" ? "" : null }, "register"),
    el("option", { value: "addr", selected: kind === "addr" ? "" : null }, "memory address"));
  const bindI = el("input", {
    value: f.addr != null ? ("0x" + f.addr.toString(16)) : (f.reg || prefill.reg || ""),
    placeholder: "x1 / v0  ·  or  0x16fdfe670", style: "width:100%;box-sizing:border-box;margin-bottom:6px" });
  m.append(kindS, bindI);

  m.append(el("div", { class: "vmlbl" }, "size (bytes)"));
  const sizeI = el("input", { value: f.size || prefill.size || 8, style: "width:100%;box-sizing:border-box;margin-bottom:6px" });
  m.append(sizeI);

  const persist = (msg) => { m.remove(); A._vars = null; saveConfig().then(() => { renderState(); rerenderCodeViews(); toast(msg); }); };
  const apply = () => {
    const name = (nameI.value.trim() || "sym");
    const bind = bindI.value.trim();
    if (!bind) { toast("enter a register or address to bind to", true); return; }
    const nf = { name, size: parseInt(sizeI.value) || 8 };
    if (kindS.value === "addr") nf.addr = parseInt(bind, 16); else nf.reg = bind;
    // drop any prior field this one replaces (same clicked target, same name, or same binding)
    snap.symbolic = (snap.symbolic || []).filter(s =>
      s !== existing && s.name !== name &&
      !(nf.reg && s.reg === nf.reg) && !(nf.addr != null && s.addr === nf.addr) &&
      !(prefill.reg && s.reg === prefill.reg) && !(prefill.name && s.name === prefill.name));
    snap.symbolic.push(nf);
    persist("marked " + name + " symbolic");
  };
  const buttons = el("div", { class: "row", style: "justify-content:flex-end;margin-top:8px;gap:6px" });
  if (existing) buttons.append(el("button", { class: "tiny ghost", onclick: () => {
    snap.symbolic = (snap.symbolic || []).filter(s => s !== existing);
    persist("removed " + (existing.name || "field"));
  } }, "Remove"));
  buttons.append(el("button", { class: "tiny ghost", onclick: () => m.remove() }, "Cancel"),
                 el("button", { class: "tiny primary", onclick: apply }, existing ? "Update" : "Make symbolic"));
  m.append(buttons);

  document.body.append(m);
  const x = ev ? ev.clientX : window.innerWidth / 2, y = ev ? ev.clientY : 160;
  m.style.left = Math.min(x, window.innerWidth - m.offsetWidth - 10) + "px";
  m.style.top = Math.min(y + 8, window.innerHeight - m.offsetHeight - 10) + "px";
  setTimeout(() => nameI.focus(), 0);
  const close = (e) => { if (!m.contains(e.target) && !e.target.classList?.contains("dvar")) { m.remove(); document.removeEventListener("mousedown", close); } };
  setTimeout(() => document.addEventListener("mousedown", close), 0);
}

// "How do I generate a snapshot?" — the capture workflow, shown from the State tab.
function openSnapshotGuide() {
  const code = (t) => el("code", {}, t);
  const pre = (t) => el("pre", { class: "dcode", style: "white-space:pre-wrap" }, t);
  const body = el("div", { class: "docbody" });
  body.append(el("p", { class: "dp" },
    el("b", {}, "What a snapshot is. "),
    "A concolic seed: a dump of a REAL run's registers + memory, so SEAL starts this function" +
    " from a realistic state and you make only the attacker-controlled fields symbolic. That turns" +
    " a bug from “every path looks dangerous” into a precise condition."));
  body.append(el("p", { class: "dp" }, el("b", {}, "1 · Capture it with lldb"),
    " — the repo ships an lldb script that dumps exactly the shape SEAL loads:"));
  body.append(pre(
    "# attach lldb to (or launch) the process that runs this function, then:\n" +
    "(lldb) command script import angrgui/snapshot/capture.py\n" +
    "# stop at the TRUE function entry (args are live there). For a normal symbol:\n" +
    "(lldb) breakpoint set --name <func> --skip-prologue false\n" +
    "(lldb) run <args>\n" +
    "(lldb) seal_snapshot --out snapshot.json --sym x1:coord\n" +
    "#   --sym marks attacker-controlled fields (reg:name or 0xADDR:name), comma-separated"));
  body.append(el("p", { class: "dp" }, el("b", {}, "For a dyld-shared-cache image"),
    " (iOS/macOS framework), break by ADDRESS — a local symbol name hangs lldb:"));
  body.append(pre(
    "(lldb) command script import seal_validation/snapshot/live_bp.py\n" +
    "(lldb) b main\n(lldb) run\n" +
    "(lldb) seal_setbp CoreGraphics 0x186a24e80   # the file address of the function\n" +
    "(lldb) continue\n" +
    "(lldb) seal_snapshot --out snapshot.json --sym x1:coord"));
  body.append(el("p", { class: "dp" }, el("b", {}, "2 · Load it"), " — use ",
    code("Load snapshot…"), " here and paste ", code("snapshot.json"), ". A live capture holds" +
    " ASLR-slid addresses; include the ", code("image.slide"), " the capture prints and SEAL rebases it" +
    " to the binary's file addresses automatically."));
  body.append(el("p", { class: "dp" }, el("b", {}, "3 · Make inputs symbolic"), " — click a variable or" +
    " argument in the decompilation (or use ", code("+ mark symbolic"), " below) to add it to the snapshot's" +
    " symbolic set without reloading. Then add a check and Explore."));
  body.append(el("p", { class: "dp faint" }, "Full details, including the exact CoreGraphics CVE walkthrough, are in ",
    code("docs/ARCHITECTURE.md"), " §7 and ", code("angrgui/snapshot/"), "."));
  const m = modal("How to generate a snapshot", body, [el("button", { class: "primary", onclick: () => m.remove() }, "Close")]);
  m.querySelector(".modal").classList.add("docs");
  $("#modalHost").append(m);
}

function openVarMenu(info0, ev) {
  $("#varMenu")?.remove();
  const snap = activeSnapshot();
  if (snap) { snapSymbolicForm(snap, info0, ev); return; }   // concolic: edit initial_state.symbolic
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
    es.onopen = () => {
      setLiveDot(true);
      // (Re)connect — including after a server restart — so resync the loaded binary and
      // function list; the server may now have a different binary than this tab last saw.
      if (A._everConnected) { refreshState(); loadFunctions(); }
      A._everConnected = true;
    };
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
  A.selNode = null; A.pathHighlight = null; A.collapsed.clear(); A.loopCollapsed.clear();
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
// concise, human-facing docs (what SEAL is + how to use it), with small diagrams.
function openHumanDocs() {
  const h = (t) => el("h4", { class: "dh" }, t);
  const p = (...k) => el("p", { class: "dp" }, ...k);
  const b = (t) => el("b", {}, t);
  const code = (t) => el("code", {}, t);
  const svg = (markup, style) => { const d = el("div", { class: "docsvg", style: style || "" }); d.innerHTML = markup; return d; };
  // a framed "screenshot" of a real UI component (reuses the app's own classes)
  const shot = (label, ...kids) => el("div", { class: "uishot" }, el("div", { class: "uibar" }, label), ...kids);
  const cap = (...k) => el("div", { class: "uicap" }, ...k);
  const annot = (n, ...k) => el("div", { class: "annot" }, el("span", { class: "anum" }, "" + n), el("span", {}, ...k));
  const body = el("div", { class: "docbody" });

  body.append(p(b("SEAL"), " (Symbolic Execution Analysis Lab) runs one function with its inputs left ", b("unknown"),
    " and finds the ", b("concrete inputs"), " that reach a location or trigger a bug — a visual front-end over ", b("angr"),
    " symbolic execution, with IDA for names and decompilation. This page is a start-from-zero tour; no prior angr knowledge assumed."));

  // ---- the window at a glance (labeled layout "picture") ----
  body.append(h("The window at a glance"));
  const lbox = (n, title, sub) => el("div", { class: "lbox" }, el("span", { class: "ln" }, "" + n), el("b", {}, title), sub ? el("div", { style: "margin-top:3px" }, sub) : null);
  body.append(el("div", { class: "applayout" },
    el("div", { class: "lbox lbar" }, el("span", { class: "ln" }, "1"), el("b", {}, "Top bar"), " — open binary · IDA status · ", el("b", {}, "Setup / Explore"), " view toggle · 📖 Docs · 🤖 Clanker docs · Theme"),
    el("div", { class: "lrow lmid" },
      lbox(2, "Functions", "every function in the binary; filter by name"),
      el("div", { class: "lbox lgrow" }, el("span", { class: "ln" }, "3"), el("b", {}, "Center"), " — Decompilation · Disassembly · generated angr script, and the ", el("b", {}, "CFG graph"), ". Click a line to add reach / avoid / checks."),
      lbox(4, "Setup", "initial state · assumptions · call models · checks · Run")),
    el("div", { class: "lrow lbot" }, el("div", { class: "lbox" }, el("span", { class: "ln" }, "5"), el("b", {}, "Bottom dock"), " — ", el("b", {}, "Findings / paths"), " (list or tree) and the ", el("b", {}, "Path detail"), " for whichever path you click."))));
  body.append(cap("The ", b("Setup"), " view (shown) is for configuring; the ", b("Explore"), " view rearranges the same panels for reading paths. Collapse either side with ", b("« / »"), "."));

  // ---- workflow pipeline ----
  body.append(h("The five-step workflow"));
  const step = (t) => el("span", { class: "pipe-step" }, t);
  const arr = () => el("span", { class: "pipe-arr" }, "→");
  body.append(el("div", { class: "pipeline" },
    step("1 · pick a function"), arr(), step("2 · set its inputs"), arr(), step("3 · add checks"), arr(),
    step("4 · explore paths"), arr(), step("5 · read findings")));
  body.append(p("Steps 3 is ", b("optional"), " — with no checks, ", b("Explore paths"), " just enumerates every path the inputs can take. Add checks when you are hunting a specific bug class."));

  // ---- the idea + a tiny path tree ----
  body.append(h("The idea in one picture"));
  body.append(el("div", { class: "docrow" },
    el("div", { class: "grow" }, p("At each branch whose condition depends on an unknown input, execution ", b("forks"),
      " and follows both sides — building a ", b("tree"), " of paths. Each leaf is an outcome; each finding comes with a concrete ", b("witness"),
      ": the exact input values that take that path and trigger it.")),
    svg(`<svg viewBox="0 0 120 92" width="120" height="92" aria-hidden="true">
      <g fill="none" stroke="var(--line2)" stroke-width="1.5">
        <path d="M60 18 V34 M60 34 L30 52 M60 34 L90 52 M30 52 V68 M90 52 L72 68 M90 52 L108 68"/></g>
      <circle cx="60" cy="14" r="5" fill="var(--green)"/>
      <circle cx="30" cy="52" r="5" fill="var(--ok)"/>
      <circle cx="30" cy="72" r="5" fill="var(--ok)"/>
      <circle cx="90" cy="52" r="5" fill="var(--accent2)"/>
      <circle cx="72" cy="72" r="5" fill="var(--ok)"/>
      <circle cx="108" cy="72" r="5" fill="var(--bad)"/>
      <text x="2" y="90" font-size="7" fill="var(--faint)" font-family="var(--sans)">green=returned · purple=branch · red=finding</text>
    </svg>`, "flex:0 0 auto")));

  // ---- setting up inputs, with a mock argument row ----
  body.append(h("Step 2 · setting up inputs"));
  body.append(p("Each argument gets one ", b("mutually-exclusive"), " mode (a single 3-way switch):"));
  // a faithful mock of an argument row in each of the three modes
  const seg3 = (on) => el("div", { class: "seg" },
    el("div", { class: "segbtn" + (on === "sym" ? " on" : "") }, "sym"),
    el("div", { class: "segbtn" + (on === "fixed" ? " on" : "") }, "fixed"),
    el("div", { class: "segbtn" + (on === "buffer" ? " on" : "") }, "buffer"));
  body.append(shot("Initial state · one argument, three modes",
    el("div", { class: "arg", style: "grid-template-columns:minmax(0,1fr) auto 54px auto" },
      el("input", { class: "name", value: "count", disabled: "" }), seg3("sym"),
      el("select", { disabled: "" }, el("option", {}, "4B")),
      el("label", { class: "row", style: "font-size:11px;color:var(--dim);gap:3px" }, el("input", { type: "checkbox", disabled: "", style: "width:auto" }), "signed")),
    el("div", { class: "arg", style: "grid-template-columns:minmax(0,1fr) auto 54px auto" },
      el("input", { class: "name", value: "size", disabled: "" }), seg3("fixed"),
      el("select", { disabled: "" }, el("option", {}, "4B")),
      el("input", { value: "8", disabled: "", style: "width:78px" })),
    el("div", { class: "arg", style: "grid-template-columns:minmax(0,1fr) auto" },
      el("input", { class: "name", value: "tif", disabled: "" }), seg3("buffer")),
    el("div", { class: "row", style: "font-size:11px;color:var(--faint);margin:2px 0 0 2px;gap:4px;flex-wrap:wrap" },
      el("span", {}, "buffer"), el("input", { value: "1080", disabled: "", style: "width:52px" }),
      el("span", {}, "bytes · pointer is concrete, contents symbolic"),
      el("button", { class: "tiny", disabled: "", style: "margin-left:4px" }, "⚙ struct (69)"))));
  const ul = el("ul", { class: "dul" });
  [[b("sym"), " (symbolic) — the value is unknown; the solver chooses it. This is what makes a bug ", b("searchable"), ". Optionally ", code("signed"), " / ", code("floating-point"), "."],
   [b("fixed"), " — pin the argument to a constant you type."],
   [b("buffer"), " — the argument is a ", b("pointer"), ": SEAL allocates a real buffer, points the argument at it, and leaves its contents symbolic. The pointer itself is concrete; the bytes it points at are unknown. (This replaces the old separate “points at a symbolic buffer” checkbox — it can’t coexist with sym/fixed, so it’s now the third mode.)"]].forEach(x => ul.append(el("li", {}, ...x)));
  body.append(ul);

  // ---- struct editor picture ----
  body.append(p("In ", b("buffer"), " mode, ", b("⚙ struct"), " opens the struct editor. Type to filter the dropdown of structs IDA knows (you needn’t remember the exact name), ", b("Load"), " the layout, then set each member symbolic or fixed; ⤷ expands a nested struct into its fields."));
  const strow = (off, name, type, mode, val) => el("div", { class: "strow" },
    el("input", { class: "stoff mono", value: off, disabled: "", style: "width:46px" }),
    el("input", { class: "stname grow", value: name, disabled: "" }),
    el("input", { class: "stsz mono", value: "8", disabled: "", style: "width:34px" }),
    el("span", { class: "sttype mono faint" }, type),
    el("div", { class: "seg stseg" }, el("div", { class: "segbtn" + (mode === "sym" ? " on" : "") }, "sym"), el("div", { class: "segbtn" + (mode === "fix" ? " on" : "") }, "fix")),
    mode === "sym" ? el("span", { class: "faint stvalph" }, "symbolic") : el("input", { class: "stval mono", value: val, disabled: "" }));
  const tbl = el("div", { class: "structtbl" },
    el("div", { class: "strow sthead" }, el("span", { class: "stoff" }, "offset"), el("span", { class: "grow" }, "member"), el("span", { class: "sttype" }, "type"), el("span", {}, "value")),
    strow("0", "tif.tif_fd", "int", "sym", ""),
    strow("8", "tif.tif_name", "char *", "sym", ""),
    strow("16", "tif.tif_flags", "uint32", "fix", "0x4"));
  body.append(shot("Struct editor · tif (from IDA)",
    el("div", { class: "row", style: "gap:6px" }, el("input", { value: "start typing to filter 312 structs…", disabled: "", style: "flex:1" }), el("button", { class: "tiny primary", disabled: "" }, "Load")),
    tbl));

  // ---- other input sources ----
  body.append(p("Beyond arguments: ", b("stdin / symbolic files"), " make program input symbolic (e.g. a ", code(".password"), " a CTF reads); ",
    b("assumptions"), " constrain inputs with expressions (e.g. ", code("count < 0x100000"), "); ",
    b("call models"), " replace a function the target calls (malloc, size helpers, read/write) with a simple stand-in, so bugs that span library calls stay tractable."));

  // ---- looking for bugs ----
  body.append(h("Step 3 · looking for bugs (optional)"));
  body.append(annot("+", b("+ detect"), " — a bug-class check: integer overflow/wrap, narrowing cast, floating-point anomaly (NaN/±Inf), or out-of-bounds write (including heap overflows of modeled allocations)."));
  body.append(annot("+", b("+ assert"), " — an invariant that should always hold; the check fires when the solver can make it false (e.g. ", code("total >= count"), " at return)."));
  body.append(annot("+", b("+ custom"), " — your own Python predicate over the state."));
  body.append(annot("⌖", "From the ", b("code view"), ", click any line to add ", b("reach"), " (find an input that gets here) or ", b("avoid"), " (prune paths that hit it)."));

  // ---- reading results ----
  body.append(h("Steps 4–5 · explore, then read findings"));
  body.append(p("Press ", b("Explore paths"), ". The ", b("bottom dock"), " fills with every explored path as a ", b("list"), " or a branching ", b("tree"),
    " (toggle at the dock’s top-right). Click one and ", b("Path detail"), " shows the branch conditions to get there, the outcome, and — for a finding — the ", b("witness"),
    " (concrete inputs). As you click, the ", b("code"), " and ", b("graph"), " highlight that flow (blue) and the exact branches it took (purple)."));
  body.append(cap("Outcomes you’ll see on leaves: ", b("returned"), " (ran to completion), ", b("exit"), ", ",
    b("hijack"), " (a jump the inputs control — e.g. a call through a symbolic function pointer), ",
    b("loop bound / max active"), " (search limits), and any ", b("finding"), " a check raised."));

  // ---- getting around ----
  body.append(h("Getting around"));
  body.append(p(b("Scenarios"), " keep several initial-state setups per function (checks are shared); switch via the chip by the function name. The ",
    b("Setup / Explore"), " toggle (top bar) swaps a configuring layout for a path-reading one. Collapse either side panel with ", b("« / »"),
    ", and pick a colour theme from ", b("Theme"), ". Need IDA names/decompilation? Connect via the IDA button (see Clanker docs for the port-forward)."));

  body.append(el("div", { class: "dnote" }, "Driving SEAL from an AI agent? See ", b("🤖 Clanker docs"), " for the MCP tools, worked tool-call walkthroughs, the full guide and caveats."));

  const m = modal("SEAL — overview", body, [el("button", { class: "primary", onclick: () => m.remove() }, "Close")]);
  m.querySelector(".modal").classList.add("docs");
  $("#modalHost").append(m);
}

async function openDocsModal() {
  let d = {};
  try { d = await api("/api/agent-docs"); } catch (e) {}
  const origin = location.origin;
  const mcpUrl = d.mcp_url || (origin + "/mcp");
  const guide = d.guide || "(the server did not return a guide — check /api/agent-docs)";
  const code = (t) => el("code", {}, t);
  const body = el("div", { class: "docbody" });

  // The agent docs are deliberately NOT structured like the human Docs. They are ONE
  // flat skill — the exact text an agent gets from get_guide / the initialize handshake —
  // so a human can copy it straight into their agent. Keep this modal a thin presenter of
  // that single source of truth (server.py GUIDE); don't re-document features here.
  body.append(el("p", { class: "dp" },
    el("b", {}, "SEAL agent skill."),
    " SEAL's complete operating manual for an AI agent driving it over MCP, as one flat" +
    " document on purpose. Paste it straight into your agent as a skill / system note, or" +
    " point an MCP client at the endpoint below — the agent then gets the identical text" +
    " from the ", code("get_guide"), " tool and in the ", code("initialize"), " handshake."));

  body.append(el("div", { class: "dp", style: "display:flex;gap:8px;align-items:center;flex-wrap:wrap" },
    el("b", {}, "MCP endpoint:"), el("code", {}, mcpUrl),
    el("span", { class: "faint" }, (d.transport || "Streamable HTTP") + (d.protocol ? " · " + d.protocol : "") + " · no auth")));

  const copyGuide = el("button", { class: "tiny primary" }, "⧉ Copy the whole skill");
  copyGuide.onclick = () => (navigator.clipboard ? navigator.clipboard.writeText(guide) : Promise.reject())
    .then(() => toast("skill copied — paste it into your agent")).catch(() => toast("copy failed; select the text below", true));
  const copyEp = el("button", { class: "tiny" }, "⧉ Copy endpoint");
  copyEp.onclick = () => (navigator.clipboard ? navigator.clipboard.writeText(mcpUrl) : Promise.reject())
    .then(() => toast("endpoint copied")).catch(() => {});
  body.append(el("div", { style: "display:flex;gap:8px;margin:4px 0 10px" }, copyGuide, copyEp));

  // the skill itself, verbatim and scrollable
  body.append(el("pre", { class: "dcode", style: "white-space:pre-wrap;max-height:62vh;overflow:auto;color:var(--ink);line-height:1.45" }, guide));

  // a live, accurate tool list (names + required args) straight from THIS server — a quick
  // lookup appendix, not a re-explanation; schemas come from tools/list over MCP.
  if ((d.tools || []).length) {
    body.append(el("div", { class: "faint", style: "margin:12px 0 4px" }, "Live tool list on this server (names + required args; full schemas via tools/list):"));
    const tbl = el("table", { class: "dtbl" });
    tbl.append(el("tr", {}, el("th", {}, "tool"), el("th", {}, "what it does")));
    (d.tools || []).forEach(t => {
      const req = (t.inputSchema && t.inputSchema.required) || [];
      tbl.append(el("tr", {},
        el("td", {}, code(t.name), req.length ? el("div", { class: "dargs" }, "args: " + req.join(", ")) : null),
        el("td", {}, t.description)));
    });
    body.append(tbl);
  }

  const m = modal("Clanker documentation — agent skill", body, [el("button", { class: "primary", onclick: () => m.remove() }, "Close")]);
  m.querySelector(".modal").classList.add("docs");
  $("#modalHost").append(m);
}
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
   ["Divide by zero", "an integer division/remainder whose divisor can be 0", openDivZeroModal],
   ["Floating-point anomaly", "result can be NaN or ±Inf", openFloatModal],
   ["Out-of-bounds write", "a write that can leave a declared buffer", () => openOobModal("oob_write")],
   ["Out-of-bounds read", "a read that can leave a declared buffer (info leak)", () => openOobModal("oob_read")],
   ["Null-pointer dereference", "a read/write through a pointer the inputs can make NULL", openNullDerefModal]].forEach(([t, s, fn]) =>
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

function openOobModal(kind) {
  kind = kind || "oob_write";
  const rw = kind === "oob_read" ? "read" : "write";
  const base = el("input", { placeholder: "a1   ·   rsp-0x40   ·   0x601080", style: "width:100%;box-sizing:border-box" });
  const size = el("input", { value: "64", style: "width:90px" });
  const sel = insnPicker();
  const body = el("div", {},
    field("Buffer start", base, "Expression for the buffer's base address: a pointer argument (a1/arg0/your name), a register expression (rsp-0x40), or a literal address."),
    field("Buffer size (bytes)", size, `A ${rw} whose address can land outside [base, base+size) is reported — with the input that takes it there.`),
    field("Where (optional)", sel, `Restrict to one ${rw} instruction, or watch every ${rw} in the function.`));
  const m = modal(`Detect out-of-bounds ${rw}s`, body, [
    el("button", { onclick: () => m.remove() }, "Cancel"),
    el("button", { class: "primary", onclick: () => {
      const b = base.value.trim();
      if (!b) { toast("enter the buffer's base address/expression", true); return; }
      const sz = parseIntLoose(size.value);
      if (!sz) { toast("enter the buffer size in bytes", true); return; }
      const addr = sel.value ? +sel.value : null;
      addCheck({ kind, base: b, size: sz, addr, name: `OOB ${rw} · ${b}[${sz}]` });
      m.remove();
    } }, "Add check")]);
  $("#modalHost").append(m);
}

function openDivZeroModal() {
  const sel = insnPicker();
  const body = el("div", {}, field("Where", sel,
    "Scan the whole function, or one instruction. Flags an integer division or remainder whose divisor the inputs can make zero — including the case angr normally prunes by assuming the divisor is non-zero. The witness zeroes the divisor."));
  const m = modal("Detect divide-by-zero", body, [
    el("button", { onclick: () => m.remove() }, "Cancel"),
    el("button", { class: "primary", onclick: () => {
      const addr = sel.value ? +sel.value : null;
      addCheck({ kind: "div_by_zero", addr, name: addr ? `div0 @ ${hx64(addr)}` : "divide by zero (whole function)" });
      m.remove();
    } }, "Add check")]);
  $("#modalHost").append(m);
}

function openNullDerefModal() {
  const sel = insnPicker();
  const body = el("div", {}, field("Where", sel,
    "Scan the whole function, or one instruction. Flags a memory read/write through a pointer the inputs can drive into the null page. angr zero-fills unmapped memory, so these never crash on their own — this surfaces them. The witness makes the pointer NULL."));
  const m = modal("Detect null-pointer dereferences", body, [
    el("button", { onclick: () => m.remove() }, "Cancel"),
    el("button", { class: "primary", onclick: () => {
      const addr = sel.value ? +sel.value : null;
      addCheck({ kind: "null_deref", addr, name: addr ? `null deref @ ${hx64(addr)}` : "null deref (whole function)" });
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
// IDA-style disassembler syntax colours for the graph's instruction text
// (the node fills / background / highlights follow the active theme — see recolor).
const IDA = {
  // maximum-brightness neon disassembler palette (on the dark node boxes)
  mn: "#66d9ff", reg: "#4dffe8", num: "#ccff4d", kw: "#ff6ae8", pun: "#d2dcea", sym: "#ffe84d",
};
// Binary Ninja dark theme (exact values from its dark.bntheme): neutral-gray canvas,
// lighter rectangular nodes with a thin light-gray outline + a delicate black shadow.
const BN = { bg: "#2a2a2a", node: "#4a4a4a", border: "#909090", head: "#b4b4b4" };
// colour utilities for the graphs: parse any css colour to [r,g,b]; blend toward white / another colour
function _rgb(c) {
  let m = /^#?([0-9a-f]{3})$/i.exec(c);
  if (m) { const h = m[1]; return [h[0] + h[0], h[1] + h[1], h[2] + h[2]].map(x => parseInt(x, 16)); }
  m = /^#?([0-9a-f]{6})$/i.exec(c); if (m) { const n = parseInt(m[1], 16); return [n >> 16 & 255, n >> 8 & 255, n & 255]; }
  m = /rgba?\(([^)]+)\)/i.exec(c); if (m) return m[1].split(",").slice(0, 3).map(x => +x.trim());
  return [26, 30, 37];
}
const _hex = ([r, g, b]) => "#" + [r, g, b].map(x => Math.max(0, Math.min(255, Math.round(x))).toString(16).padStart(2, "0")).join("");
function lighten(c, amt) { const [r, g, b] = _rgb(c); return _hex([r + (255 - r) * amt, g + (255 - g) * amt, b + (255 - b) * amt]); }
function mix(a, b, t) { const A = _rgb(a), B = _rgb(b); return _hex([A[0] + (B[0] - A[0]) * t, A[1] + (B[1] - A[1]) * t, A[2] + (B[2] - A[2]) * t]); }
const X86_REG = /^(?:[re]?[a-d]x|[re]?[sd]i|[re]?[sb]p|r(?:8|9|1[0-5])[dwb]?|[a-d][lh]|sil|dil|bpl|spl|[xyz]mm\d+|rip|eip|ip|[er]?flags|st\d?|mm[0-7]|k[0-7]|cr\d+|dr\d+|tr\d+|[cdefgs]s)$/i;
const X86_SIZE = /^(?:byte|word|dword|qword|tbyte|oword|xmmword|ymmword|zmmword|ptr|offset|short|near|far)$/i;
// split an instruction's text into coloured tokens (mnemonic, registers, numbers, …)
function asmSpans(line) {
  const out = [];
  const re = /(\s+)|(0x[0-9a-fA-F]+|\b\d+\b)|([\[\](),:+\-*])|([A-Za-z_.$@][\w.$@]*)/g;
  let m, first = true;
  while ((m = re.exec(line))) {
    if (m[1]) { out.push({ s: m[1], cls: "ws" }); continue; }
    if (m[2]) { out.push({ s: m[2], cls: "num" }); continue; }
    if (m[3]) { out.push({ s: m[3], cls: "pun" }); continue; }
    const w = m[4];
    if (first) { out.push({ s: w, cls: "mn" }); first = false; }
    else if (X86_REG.test(w)) out.push({ s: w, cls: "reg" });
    else if (X86_SIZE.test(w)) out.push({ s: w, cls: "kw" });
    else out.push({ s: w, cls: "sym" });
  }
  return out;
}

function drawCFG(pane, g) {
  // if this function's graph is already laid out here, only recolor (keeps pan/zoom/position)
  if (pane._cfg && pane._cfg.addr === g.addr) { pane._cfg.recolor(); return; }
  if (pane._cfg && pane._cfg.cleanup) pane._cfg.cleanup();

  const gr = new dagre.graphlib.Graph({ multigraph: true });
  gr.setGraph({ rankdir: "TB", nodesep: 26, ranksep: 34, marginx: 20, marginy: 20 });
  gr.setDefaultEdgeLabel(() => ({}));
  const LINE_H = 16, CHAR_W = 7.3, PAD = 11, CAP = 8;
  const expanded = (A.cfgExpanded || (A.cfgExpanded = new Set()));
  for (const n of g.nodes) {
    // long blocks are capped to CAP instructions with a clickable "+N" line; an expanded
    // node (#7) shows them all with a "collapse" line. expandLine = index of that line.
    const showAll = expanded.has(n.addr), truncated = n.insns.length > CAP;
    const lines = (showAll ? n.insns : n.insns.slice(0, CAP)).map(i => i.text);
    let expandLine = -1;
    if (truncated && !showAll) { lines.push(`… +${n.insns.length - CAP} more — click to expand`); expandLine = lines.length - 1; }
    else if (truncated && showAll) { lines.push("▲ collapse"); expandLine = lines.length - 1; }
    const w = Math.max(120, Math.min(560, Math.max(...lines.map(l => l.length)) * CHAR_W + PAD * 2));
    const h = lines.length * LINE_H + PAD * 2 + 16;
    gr.setNode(n.addr, { label: hx64(n.addr), lines, width: w, height: h, insns: n.insns, expandLine });
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
    <path d="M0,0 L7,3 L0,6 Z" fill="#8b93a2"/></marker>
    <marker id="arrhi" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
    <path d="M0,0 L7,3 L0,6 Z" fill="#4c9aff"/></marker>
    <filter id="nodeshadow" x="-10%" y="-10%" width="120%" height="130%">
      <feDropShadow dx="0" dy="1.2" stdDeviation="1.6" flood-color="#000000" flood-opacity="0.55"/></filter></defs>`;
  const viewport = document.createElementNS(NS, "g");
  svg.append(viewport);

  // #7: toggle a node between capped (8 insns) and fully expanded, then re-lay-out the
  // graph (node heights change). cfgExpanded is reset when the function changes.
  const toggleExpand = (addr) => {
    const s = A.cfgExpanded || (A.cfgExpanded = new Set());
    s.has(addr) ? s.delete(addr) : s.add(addr);
    if (pane._cfg && pane._cfg.cleanup) pane._cfg.cleanup();
    delete pane._cfg;
    drawCFG(pane, g);
  };

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
    rect.setAttribute("width", n.width); rect.setAttribute("height", n.height); rect.setAttribute("rx", 6);  // rounded, like the paths graph
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
      t.setAttribute("xml:space", "preserve");
      if (i === n.expandLine) {              // the "+N more" / "collapse" control line
        t.setAttribute("fill", "var(--accent)");
        t.style.cursor = "pointer";
        t.textContent = ln;
        t.addEventListener("click", ev => { ev.stopPropagation(); toggleExpand(+id); });
      } else {
        // syntax-highlight each instruction into coloured tspans (IDA-style)
        asmSpans(ln).forEach(sp => {
          const ts = document.createElementNS(NS, "tspan");
          ts.setAttribute("xml:space", "preserve");
          if (sp.cls !== "ws") ts.setAttribute("fill", IDA[sp.cls]);
          ts.textContent = sp.s;
          t.append(ts);
        });
      }
      gEl.append(t);
      lineEls.push(t);
    });
    nodeEls[+id] = { rect, head, insns: n.insns, lineEls };
    viewport.append(gEl);
  });

  function recolor() {
    // node fills / borders follow the active (dark) theme; the selected path, the
    // branch decisions and the findings are tinted + bordered so they stand out.
    // Instruction text keeps its syntax-highlighted tspan colours (not overwritten).
    const pathBlocks = A.pathHighlight || new Set();
    const hitAddrs = new Set((A.run?.snapshot?.hits || []).map(h => h.addr));
    const css = getComputedStyle(document.documentElement);
    const v = (name, fb) => (css.getPropertyValue(name).trim() || fb);
    // theme colours, matching the paths graph; path/branch/finding highlights tint the fill + border
    const node = v("--panel2", "#1a1e25"), line2 = v("--line2", "#30363f"), dim = v("--dim", "#98a1ad");
    const accent = v("--accent", "#4c9aff"), accent2 = v("--accent2", "#7c5cff"), bad = v("--bad", "#f85149");
    const branchBlocks = A.branchBlocks || new Set();
    const tint = (hex, a) => { const m = /^#?([0-9a-f]{6})$/i.exec(hex); if (!m) return hex; const n = parseInt(m[1], 16); return `rgba(${n >> 16 & 255},${n >> 8 & 255},${n & 255},${a})`; };
    for (const addr in nodeEls) {
      const ne = nodeEls[addr], onPath = pathBlocks.has(+addr), hasHit = ne.insns.some(i => hitAddrs.has(i.addr)), isBranch = branchBlocks.has(+addr);
      ne.rect.setAttribute("fill", hasHit ? tint(bad, .16) : isBranch ? tint(accent2, .18) : onPath ? tint(accent, .16) : node);
      ne.rect.setAttribute("stroke", hasHit ? bad : isBranch ? accent2 : onPath ? accent : line2);
      ne.rect.setAttribute("stroke-width", (hasHit || onPath || isBranch) ? 2 : 1);
      ne.head.setAttribute("fill", hasHit ? bad : isBranch ? accent2 : dim);
    }
    for (const e of edgeEls) {
      const hi = pathBlocks.has(e.v) && pathBlocks.has(e.w);
      const color = e.kind === "call" ? accent2 : e.kind === "return" ? v("--ok", "#3fb950") : "#8b93a2";
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
