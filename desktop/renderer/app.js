// spectrIDA Desktop — renderer logic. Talks to the local FastAPI backend.
let API = "http://127.0.0.1:8737";
let state = { binary: null, binaryPath: null, fn: null };

const $ = (s) => document.querySelector(s);
const el = (t, c, txt) => { const e = document.createElement(t); if (c) e.className = c; if (txt != null) e.textContent = txt; return e; };

async function api(path, opts) {
  const r = await fetch(API + path, opts);
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
  return r.json();
}

const dynClass = (s) => s === "candidate_crash" ? "crash" : s === "needs_state" ? "state" : s === "exercised_clean" ? "clean" : "";
const dynLabel = (s) => ({ candidate_crash: "candidate crash", needs_state: "needs state", exercised_clean: "clean", inconclusive: "inconclusive" }[s] || s);

// ── boot ──────────────────────────────────────────────────────
// window.ghost is the Electron preload bridge. Use a differently-named local ref —
// a top-level `const ghost` would collide with the global `ghost` property the
// bridge defines and throw "already declared", killing the whole script. Guard
// every use so the renderer also runs in a plain browser (dev/screenshot).
const bridge = window.ghost || {};
async function boot() {
  if (bridge.backendUrl) { try { API = await bridge.backendUrl(); } catch (_) {} }
  if (bridge.onBackendReady) bridge.onBackendReady(() => connect());
  connect();
}
async function connect() {
  try {
    const h = await api("/health");
    setStatus(h.ok);
    if (h.ok) loadBinaries();
  } catch (_) {
    setStatus(false);
    setTimeout(connect, 1500);
  }
}
function setStatus(ok) {
  const s = $("#status");
  s.className = "status " + (ok ? "on" : "off");
  $("#status-text").textContent = ok ? "graph online" : "waiting for backend…";
}

// ── binaries ──────────────────────────────────────────────────
async function loadBinaries() {
  const bins = await api("/binaries");
  const list = $("#bin-list"); list.innerHTML = "";
  $("#bin-count").textContent = bins.length;
  bins.filter(b => b.funcs > 0).forEach(b => {
    const item = el("div", "bin-item");
    item.appendChild(el("div", "bi-name", b.tag));
    const stats = el("div", "bi-stats");
    stats.innerHTML = `<span><b>${b.funcs.toLocaleString()}</b> funcs</span>` +
      `<span class="named">${b.named.toLocaleString()} named</span>` +
      (b.analyzed ? `<span>${b.analyzed} run</span>` : "");
    item.appendChild(stats);
    item.onclick = () => selectBinary(b, item);
    list.appendChild(item);
  });
}
function selectBinary(b, item) {
  document.querySelectorAll(".bin-item").forEach(x => x.classList.remove("active"));
  item.classList.add("active");
  state.binary = b.tag; state.binaryPath = b.path;
  $("#search").value = "";
  loadFunctions("");
}

// ── functions ─────────────────────────────────────────────────
let searchTimer;
$("#search").addEventListener("input", (e) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => loadFunctions(e.target.value.trim()), 180);
});
async function loadFunctions(q) {
  if (!state.binary) return;
  const list = $("#fn-list");
  const fns = await api(`/functions?binary=${encodeURIComponent(state.binary)}&q=${encodeURIComponent(q)}&limit=200`);
  list.innerHTML = "";
  $("#search-hint").textContent = fns.length >= 200 ? "200+" : `${fns.length}`;
  if (!fns.length) { list.appendChild(el("div", "empty", "no functions")); return; }
  fns.forEach(f => {
    const item = el("div", "fn-item");
    const sub = !f.name || f.name.startsWith("sub_");
    const name = el("div", "fi-name" + (sub ? " sub" : "")); name.textContent = f.name || "sub_" + f.address;
    const right = el("div"); right.style.display = "flex"; right.style.alignItems = "center"; right.style.gap = "8px";
    if (f.dyn) { const d = el("span", "fi-dyn dyn-" + (f.dyn === "candidate_crash" ? "crash" : f.dyn === "needs_state" ? "state" : "clean")); right.appendChild(d); }
    right.appendChild(el("span", "fi-addr", f.address));
    item.appendChild(name); item.appendChild(right);
    item.onclick = () => { document.querySelectorAll(".fn-item").forEach(x => x.classList.remove("active")); item.classList.add("active"); openFunction(f.address); };
    list.appendChild(item);
  });
}

// ── detail ────────────────────────────────────────────────────
async function openFunction(addr) {
  const fn = await api(`/function?binary=${encodeURIComponent(state.binary)}&addr=${addr}`);
  state.fn = fn;
  $("#detail-empty").hidden = true;
  $("#detail-body").hidden = false;
  $("#fn-name").innerHTML = escapeHtml(fn.name || "sub_" + fn.address).replace(/(::|_)/g, '<span class="spectral">$1</span>');
  $("#fn-addr").textContent = fn.address;
  $("#fn-size").textContent = (fn.size || 0) + " B";
  const dyn = fn.dyn_status;
  const dchip = $("#fn-dyn");
  if (dyn) { dchip.hidden = false; dchip.textContent = dynLabel(dyn); dchip.className = "chip " + dynClass(dyn); }
  else { dchip.hidden = true; }
  $("#tab-pseudo").textContent = fn.pseudocode || "// no pseudocode cached";
  $("#tab-disasm").textContent = (fn.disasm || []).map(d => `${d.address}  ${d.text}`).join("\n") || "; no disassembly cached";
  renderXrefs(fn);
  $("#dyn-result").textContent = ""; $("#dyn-result").className = "dyn-result";
  setTab("pseudo");
}
function renderXrefs(fn) {
  const box = $("#tab-xrefs"); box.innerHTML = "";
  const col = (title, items) => {
    const c = el("div", "xref-col"); c.appendChild(el("h4", null, title));
    if (!items.length) c.appendChild(el("div", "xref-empty", "none"));
    items.forEach(x => {
      const it = el("div", "xref-item");
      it.innerHTML = `${escapeHtml(x.name || "sub_" + x.address)} <span class="xa">${x.address}</span>`;
      it.onclick = () => openFunction(x.address);
      c.appendChild(it);
    });
    return c;
  };
  box.appendChild(col("Callers ← ", fn.callers || []));
  box.appendChild(col("Callees → ", fn.callees || []));
}
function setTab(name) {
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  $("#tab-pseudo").hidden = name !== "pseudo";
  $("#tab-disasm").hidden = name !== "disasm";
  $("#tab-xrefs").hidden = name !== "xrefs";
}
document.querySelectorAll(".tab").forEach(t => t.onclick = () => setTab(t.dataset.tab));

// ── dynamic tools ─────────────────────────────────────────────
document.querySelectorAll(".btn.dyn").forEach(b => b.onclick = () => runDynamic(b.dataset.tool));
async function runDynamic(tool) {
  if (!state.fn) return;
  const out = $("#dyn-result");
  out.className = "dyn-result busy";
  out.textContent = { emulate: "emulating", hunt: "hunting crashes", live: "tracing live" }[tool] + " ";
  try {
    let res, verdict, note;
    const body = JSON.stringify({ binary: state.binary, addr: state.fn.address, binary_path: state.binaryPath });
    if (tool === "emulate") {
      res = await api("/dynamic/emulate", { method: "POST", headers: { "Content-Type": "application/json" }, body });
      verdict = res.verdict; note = res.note;
    } else if (tool === "hunt") {
      res = await api("/dynamic/hunt", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ binary: state.binary, addr: state.fn.address, binary_path: state.binaryPath, rounds: 300 }) });
      verdict = res.verdict; note = `${res.unique_crashes} crash site(s), ${res.rounds} rounds`;
    } else {
      res = await api("/dynamic/live", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ binary: state.binary, addresses: [state.fn.address], binary_path: state.binaryPath, seconds: 3 }) });
      verdict = res.total_calls > 0 ? "live" : "no calls"; note = `${res.total_calls} live call(s)`;
    }
    out.className = "dyn-result " + dynClass(verdict);
    out.textContent = `${dynLabel(verdict)} — ${note}`;
    // refresh the dyn chip + list dot
    if (tool !== "live") openFunction(state.fn.address);
  } catch (e) {
    out.className = "dyn-result crash";
    out.textContent = "error: " + e.message;
  }
}

// ── index modal ───────────────────────────────────────────────
const modal = $("#index-modal");
$("#index-btn").onclick = () => { modal.hidden = false; resetModal(); };
$("#modal-close").onclick = () => modal.hidden = true;
modal.onclick = (e) => { if (e.target === modal) modal.hidden = true; };
let pending = null;
function resetModal() { pending = null; $("#dz-path").textContent = ""; $("#start-index").disabled = true; $("#index-progress").hidden = true; $("#ip-fill").style.width = "0"; }
$("#browse-btn").onclick = async () => { if (!bridge.pickBinary) return; const p = await bridge.pickBinary(); if (p) setPending(p); };
function setPending(p) { pending = p; $("#dz-path").textContent = p; $("#start-index").disabled = false; }
const dz = $("#dropzone");
["dragover", "dragenter"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add("over"); }));
["dragleave", "drop"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove("over"); }));
dz.addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if (f) setPending(f.path); });

$("#start-index").onclick = async () => {
  if (!pending) return;
  $("#index-progress").hidden = false;
  $("#start-index").disabled = true;
  const line = $("#ip-line"), fill = $("#ip-fill");
  line.textContent = "starting…"; fill.style.width = "8%";
  try {
    const { job_id } = await api("/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ path: pending }) });
    let pct = 8;
    const poll = setInterval(async () => {
      const j = await api(`/jobs/${job_id}`);
      line.textContent = j.progress || j.status;
      pct = Math.min(pct + 4, 92); fill.style.width = pct + "%";
      if (j.status === "done") { clearInterval(poll); fill.style.width = "100%"; line.textContent = j.progress; setTimeout(() => { modal.hidden = true; loadBinaries(); }, 900); }
      else if (j.status === "error") { clearInterval(poll); fill.style.background = "var(--crash)"; line.textContent = "failed: " + (j.error || "").slice(0, 90); }
    }, 1200);
  } catch (e) { line.textContent = "error: " + e.message; }
};

function escapeHtml(s) { return String(s).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }

boot();
