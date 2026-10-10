"use strict";
/* Spoor dashboard. No framework, no network beyond this machine. */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
const esc = (v) => (v == null ? "" : String(v)).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (n) => (n == null || n === "" ? "" : Number(n).toLocaleString("en-US"));
const enc = encodeURIComponent;

function bytes(n) {
  n = Number(n || 0);
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + " " + u[i];
}
function dur(s) {
  if (s == null) return "";
  s = Math.max(0, Math.round(s));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h ${m}m`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

async function api(path, opts = {}) {
  const r = await fetch(path, {
    method: opts.method || (opts.body ? "POST" : "GET"),
    headers: { "Content-Type": "application/json" },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: "same-origin",
  });
  if (r.status === 401) { location.reload(); throw new Error("not signed in"); }
  let j = null;
  try { j = await r.json(); } catch (e) { j = { error: r.statusText }; }
  if (!r.ok) throw new Error((j && j.error) || r.statusText);
  return j;
}

let toastTimer = null;
function toast(msg, err) {
  let t = $(".toast");
  if (!t) { t = document.createElement("div"); document.body.appendChild(t); }
  t.className = "toast" + (err ? " err" : "");
  t.textContent = msg;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.remove(), err ? 7000 : 3500);
}

const S = { state: null, slug: null, view: "overview", param: null, c: null, timer: null, fl: null, fsel: null, src: null, askTimer: null };
const FIELDS = [["", "(not used)"], ["ts", "Timestamp"], ["date", "Date (separate)"], ["time", "Time (separate)"], ["tz", "Per-row timezone"],
  ["ip", "IP address"], ["port", "Source port"], ["account", "Account / user"], ["action", "Event / activity"], ["status", "Result / status"],
  ["user_agent", "User agent"], ["device", "Device / platform"], ["location", "Provider location"], ["counterparty", "Counterparty"],
  ["direction", "Direction"], ["amount", "Amount"], ["currency", "Currency / asset"]];
const CATS = ["", "login", "login_failed", "logout", "account_change", "registration", "communication", "transaction", "other"];
const ZONES = ["UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Phoenix", "America/Los_Angeles", "America/Anchorage",
  "Pacific/Honolulu", "Europe/London", "Europe/Berlin", "Europe/Kyiv", "Europe/Moscow", "Asia/Shanghai", "Asia/Tokyo", "UTC-08:00", "UTC-05:00"];
const STAGE_SHORT = { prepare: "Hash", scan: "Map", ingest: "Read", index: "Index", analyze: "Analyse", report1: "Report", verify: "Verify", narrative: "AI draft", report2: "Final" };

/* ------------------------------------------------------------------ routing */
function route() {
  const parts = (location.hash || "#/").slice(2).split("/").map(decodeURIComponent);
  clearInterval(S.timer); S.timer = null;
  clearInterval(S.askTimer); S.askTimer = null;
  closeLayer();
  if (parts[0] === "c" && parts[1]) {
    const changed = S.slug !== parts[1];
    S.slug = parts[1];
    S.view = parts[2] || "overview";
    S.param = parts.slice(3).join("/") || null;
    if (changed) { S.c = null; S.fl = null; }
    renderCase();
  } else {
    S.slug = null;
    renderHome();
  }
}
window.addEventListener("hashchange", route);

async function loadState() {
  S.state = await api("/api/state");
  const m = $("#model");
  const l = S.state.llm || {};
  if (l.ok) m.innerHTML = `<span class="dot ok"></span><span>Local model ready: ${esc(l.model)}</span>`;
  else m.innerHTML = `<span class="dot bad"></span><span title="${esc(l.error)}">No local model - analysis still runs, without the AI summary</span>`;
  return S.state;
}

/* ------------------------------------------------------------------ home */
async function renderHome() {
  const app = $("#app");
  app.innerHTML = `<div class="home"><p class="muted">Loading…</p></div>`;
  const st = await loadState();
  const rows = st.cases.map((c) => `<tr class="click" data-go="#/c/${enc(c.slug)}/overview"><td><b>${esc(c.name)}</b><div class="small muted">${esc(c.description)}</div></td><td>${esc(c.examiner)}</td><td class="small">${esc(c.created)}</td></tr>`).join("");
  app.innerHTML = `<div class="home">
    <h1>Cases</h1>
    ${st.cases.length ? `<div class="tblwrap"><table class="t"><thead><tr><th>Case</th><th>Examiner</th><th>Created</th></tr></thead><tbody>${rows}</tbody></table></div>`
      : `<div class="empty">No cases yet. Create one below, then add the folder that holds the returns.</div>`}
    <div class="panel" style="margin-top:24px">
      <h2>New case</h2>
      <div class="row">
        <div class="field"><label for="nc-name">Case name</label><input id="nc-name" type="text" size="30" placeholder="e.g. Operation Example"></div>
        <div class="field"><label for="nc-ex">Examiner</label><input id="nc-ex" type="text" size="22"></div>
        <div class="field"><label for="nc-tz">Local time zone for display</label><input id="nc-tz" type="text" size="20" list="zones" value="${esc(st.settings.display_tz || "America/New_York")}"></div>
        <button class="btn go" data-act="new-case">Create case</button>
      </div>
      <div class="field" style="margin-top:12px"><label for="nc-desc">Description (optional)</label><input id="nc-desc" type="text" size="70"></div>
    </div>
    <div class="panel">
      <h2>How it works</h2>
      <p>Add the returns (a folder, files or ZIPs). Spoor hashes every file, works out each file's layout and timezone, reads every record with its exact location in the original file, and runs IP, timing, login and link analyses. Every finding cites the records behind it, and those citations are re-checked against the original files. If a local model is installed, it drafts a summary from the findings; each drafted sentence is checked value by value and removed if anything in it is not in the cited findings.</p>
      <p><button class="btn" data-act="demo">Try it on fictional demo data</button> <span class="small muted">Creates a practice case from made-up returns bundled with Spoor and starts the analysis.</span></p>
      <p class="muted small">Cases are stored in ${esc(st.settings.cases_dir)}. Nothing leaves this computer.</p>
    </div>
    <datalist id="zones">${ZONES.map((z) => `<option value="${z}">`).join("")}</datalist>
  </div>`;
}

/* ------------------------------------------------------------------ case shell */
const VIEWS = [["overview", "Overview"], ["sources", "Sources"], ["findings", "Findings"], ["lookup", "Look up"], ["ask", "Ask"], ["reports", "Reports"], ["settings", "Settings"]];

async function renderCase() {
  const app = $("#app");
  if (!S.state) await loadState();
  if (!$(".wrap") || $(".wrap").dataset.slug !== S.slug) {
    app.innerHTML = `<div class="wrap" data-slug="${esc(S.slug)}">
      <nav class="rail" id="rail"></nav>
      <main class="main"><div id="casehead"></div><div id="trailbox"></div><div id="view"></div></main></div>`;
  }
  try {
    S.c = await api(`/api/case/${enc(S.slug)}`);
  } catch (e) {
    app.innerHTML = `<div class="home"><div class="alertbox">${esc(e.message)}</div><a href="#/">Back to cases</a></div>`;
    return;
  }
  $("#rail").innerHTML = `<a class="back" href="#/">All cases</a><div class="case-name">${esc(S.c.info.name)}</div>` +
    VIEWS.map(([k, t]) => `<a href="#/c/${enc(S.slug)}/${k}" class="${S.view === k ? "on" : ""}">${t}</a>`).join("");
  renderHead();
  renderTrail();
  const v = $("#view");
  v.innerHTML = `<p class="muted">Loading…</p>`;
  const fn = { overview: viewOverview, sources: viewSources, findings: viewFindings, lookup: viewLookup, ask: viewAsk, reports: viewReports, settings: viewSettings }[S.view] || viewOverview;
  try { await fn(v); } catch (e) { v.innerHTML = `<div class="alertbox">${esc(e.message)}</div>`; }
  schedulePoll();
}

function currentJob() {
  const jobs = (S.c && S.c.jobs) || [];
  return jobs.find((j) => j.kind === "run") || null;
}
function running(j) { return j && (j.status === "running" || j.status === "starting" || j.status === "queued"); }

function renderHead() {
  const j = currentJob();
  const llmOk = S.state && S.state.llm && S.state.llm.ok;
  const pend = S.c.counts.pending;
  $("#casehead").innerHTML = `<div class="trailhead">
    <h1 style="margin:0">${esc(S.c.info.name)}</h1><span class="grow"></span>
    ${running(j) ? `<button class="btn stop" data-act="cancel">Stop</button>` :
      `<label class="check" title="${llmOk ? "" : "No local model found - the analysis runs without the AI summary"}"><input type="checkbox" id="use-llm" ${llmOk ? "checked" : "disabled"}> AI-drafted summary</label>
       <button class="btn go" data-act="run" ${S.c.counts.sources ? "" : "disabled"}>${j && (j.status === "interrupted" || j.status === "cancelled" || j.status === "error") ? "Resume analysis" : (S.c.counts.findings ? (pend ? "Run again (files changed)" : "Run again") : "Run analysis")}</button>`}
  </div>`;
}

function renderTrail() {
  const box = $("#trailbox");
  const j = currentJob();
  if (!j) { box.innerHTML = ""; return; }
  const stages = j.stages || [];
  const done = new Set(j.stages_done || []);
  const isRun = running(j);
  const marks = stages.map(([k, label], i) => {
    let cls = done.has(k) ? "done" : "";
    if (isRun && j.stage_no === i + 1) cls = "now";
    if (j.status === "error" && j.stage_no === i + 1) cls = "fail";
    const lastDone = done.has(k) && !(stages[i + 1] && done.has(stages[i + 1][0]));
    return `<div class="st ${cls} ${lastDone ? "last" : ""}" title="${esc(label)}"><div class="pt"></div><span>${esc(STAGE_SHORT[k] || label)}</span></div>`;
  }).join("");
  let line = "", pct = null;
  if (isRun) {
    const st = stages[(j.stage_no || 1) - 1];
    pct = j.total ? Math.min(100, (100 * j.done) / j.total) : null;
    const amt = j.unit === "bytes" ? (j.total ? `${bytes(j.done)} of ${bytes(j.total)}` : "") : (j.total ? `${fmt(Math.round(j.done))} of ${fmt(j.total)} ${esc(j.unit || "")}` : "");
    const rate = j.rate ? (j.unit === "bytes" ? `${bytes(j.rate)}/s` : `${j.rate.toFixed(1)} ${esc(j.unit || "")}/s`) : "";
    line = `<b>${esc(st ? st[1] : j.stage)}</b>${pct != null ? ` - ${pct.toFixed(1)}%` : ""}${amt ? `, ${amt}` : ""}${rate ? `, ${rate}` : ""}${j.eta_s ? `, about ${dur(j.eta_s)} left in this stage` : ""}`;
  }
  const head = isRun ? `Job #${j.id} running since ${esc(j.started_at || j.created_at)}` :
    j.status === "done" ? `Last analysis finished ${esc(j.finished_at || "")}` :
    j.status === "error" ? `Last analysis failed: ${esc(j.error || "")}` :
    j.status === "interrupted" ? `Last analysis was interrupted (computer restarted or the worker stopped). Resume continues where it stopped.` :
    j.status === "cancelled" ? `Last analysis was stopped. Resume continues where it stopped.` : `Job #${j.id}: ${esc(j.status)}`;
  box.innerHTML = `<div class="trailbox ${isRun ? "" : "idle"}"><div class="small ${j.status === "error" ? "" : "muted"}">${head}</div>
    <div class="trail" style="--n:${stages.length}">${marks}</div>
    ${isRun ? `<div class="meter"><i style="width:${pct == null ? 4 : pct}%"></i></div><div class="now-line">${line}<br>${esc(j.message || "")}</div>
      <div class="now-line">You can close this window; the analysis keeps running. Progress is also written to PROGRESS.md in the case folder.</div>` : ""}
  </div>`;
}

function schedulePoll() {
  clearInterval(S.timer);
  const j = currentJob();
  const fast = running(j);
  S.timer = setInterval(async () => {
    try {
      const r = await api(`/api/case/${enc(S.slug)}/jobs`);
      const before = currentJob();
      S.c.jobs = r.jobs;
      S.c.status_text = r.status_text;
      const now = currentJob();
      renderTrail();
      if (running(before) && !running(now)) {
        toast(now && now.status === "done" ? "Analysis finished." : `Analysis ${now ? now.status : "stopped"}.`, now && now.status === "error");
        renderCase();
      } else if (!running(before) && running(now)) {
        renderHead();
        schedulePoll();
      }
      if (S.view === "overview" && $("#statustext")) $("#statustext").textContent = r.status_text;
    } catch (e) { /* server restarting - try again next tick */ }
  }, fast ? 3000 : 15000);
}

/* ------------------------------------------------------------------ overview */
async function viewOverview(v) {
  const c = S.c;
  const k = c.counts;
  const cc = c.citation_check;
  const nar = c.narrative;
  if (!k.sources) {
    v.innerHTML = `<div class="empty"><b>No returns added yet.</b><br>Go to <a href="#/c/${enc(S.slug)}/sources">Sources</a> and add the folder (or ZIP) that holds the subpoena returns. Spoor reads CSV, TSV, Excel, JSON, HTML, PDF, text and ZIP files.</div>`;
    return;
  }
  const keys = c.key_findings.map((f) => `<tr class="click" data-go="#/c/${enc(S.slug)}/findings/${f.fid}"><td class="mono nw">${f.fid}</td><td><b>${esc(f.title)}</b><div class="small">${esc(f.statement)}</div></td></tr>`).join("");
  v.innerHTML = `
    <div class="stats">
      <div><b>${fmt(k.ingested)} / ${fmt(k.sources)}</b><span>files analysed</span></div>
      <div><b>${fmt(k.events)}</b><span>records</span></div>
      <div><b>${fmt(k.findings)}</b><span>findings</span></div>
      <div><b>${fmt(k.p1)}</b><span>priority 1</span></div>
      <div><b>${c.span && c.span[0] ? esc(c.span[0].slice(0, 10)) + " to " + esc(c.span[1].slice(0, 10)) : "-"}</b><span>time span (UTC)</span></div>
    </div>
    ${k.pending && !running(currentJob()) ? `<div class="flagbox">${fmt(k.pending)} file(s) are new or have changed settings. Run the analysis to include them.</div>` : ""}
    ${cc ? `<div class="${cc.fail ? "alertbox" : "okbox"}">Citation check ${esc(cc.run_at)}: ${fmt(cc.pass)} of ${fmt(cc.total)} cited records were re-read from the original files and matched${cc.fail ? `; <b>${fmt(cc.fail)} did not match</b> - see REVIEW.md` : ""}${cc.unverifiable ? `; ${fmt(cc.unverifiable)} could not be checked` : ""}.${cc.hashes ? ` Source hashes: ${fmt(cc.hashes.match)} unchanged${cc.hashes.mismatch ? `, <b>${fmt(cc.hashes.mismatch)} CHANGED</b>` : ""}${cc.hashes.missing ? `, ${fmt(cc.hashes.missing)} missing` : ""}.` : ""}</div>` : ""}
    ${nar ? `<div class="okbox">AI-drafted summary (${esc(nar.model)}): ${fmt(nar.accepted)} sentences kept after verification${nar.flagged ? `, ${fmt(nar.flagged)} of them flagged for your judgment` : ""}; ${fmt(nar.rejected)} removed. They are in REPORT.md; the removed ones are listed in REVIEW.md.</div>` : ""}
    ${c.report_ready ? `<p><a href="#/c/${enc(S.slug)}/reports/REPORT.md"><b>Read the report</b></a> &nbsp; <a href="#/c/${enc(S.slug)}/reports/REVIEW.md">Review checklist</a> &nbsp; <button class="btn small" data-act="open-folder">Open the report folder</button></p>` : ""}
    <h2 style="margin-top:22px">Priority-1 findings</h2>
    ${keys ? `<div class="tblwrap"><table class="t"><tbody>${keys}</tbody></table></div>` : `<p class="muted">None yet. Run the analysis to produce findings.</p>`}
    <h2 style="margin-top:22px">Status</h2>
    <pre class="raw" id="statustext">${esc(c.status_text)}</pre>`;
}

/* ------------------------------------------------------------------ sources */
async function viewSources(v) {
  if (S.param) return viewSource(v, S.param);
  const r = await api(`/api/case/${enc(S.slug)}/sources`);
  const rows = r.sources.filter((s) => s.status !== "container").map((s) => {
    const flags = Object.entries(s.flags || {}).map(([k, n]) => `${esc(k)} ${fmt(n)}`).join(", ");
    return `<tr class="click" data-go="#/c/${enc(S.slug)}/sources/${s.label}">
      <td class="mono nw">${s.label}</td><td><b>${esc(s.name)}</b>${s.parent ? `<div class="small muted">${esc(s.display)}</div>` : ""}</td>
      <td>${esc(s.kind)}</td><td class="num">${bytes(s.size)}</td>
      <td><span class="status ${esc(s.status)}">${esc(s.status)}</span>${s.changed ? ` <span class="status flagged">settings changed</span>` : ""}${s.error ? `<div class="small" style="color:var(--p1)">${esc(s.error)}</div>` : ""}</td>
      <td class="num">${fmt(s.rows)}</td>
      <td>${s.tz ? esc(s.tz) + (s.tz_assumed ? ` <span class="status flagged">assumed</span>` : "") : ""}</td>
      <td class="small">${s.ts_failed ? `<span style="color:var(--p1)">${fmt(s.ts_failed)} unparsed times</span> ` : ""}${flags}</td></tr>`;
  }).join("");
  v.innerHTML = `
    <div class="panel">
      <h2>Add returns</h2>
      <div class="row">
        <div class="field" style="flex:1;min-width:280px"><label for="src-path">File or folder on this computer</label>
          <input id="src-path" type="text" style="width:100%" placeholder="e.g. D:\\Returns\\Google_2024-0412"></div>
        <button class="btn" data-act="browse">Browse…</button>
        <button class="btn go" data-act="add-src">Add</button>
      </div>
      <div class="row" style="margin-top:10px">
        <label class="check"><input type="checkbox" id="src-rec" checked> Include subfolders</label>
        <div class="field"><label for="src-pw">ZIP password (if the ZIP is encrypted)</label><input id="src-pw" type="password" size="22" autocomplete="off"></div>
      </div>
      <p class="small muted">Files are read in place and never changed. Each is hashed (SHA-256) before it is read; ZIPs are extracted into the case folder. Open a file below to check how it will be read.</p>
    </div>
    ${rows ? `<div class="tblwrap"><table class="t"><thead><tr><th>Label</th><th>File</th><th>Kind</th><th class="num">Size</th><th>Status</th><th class="num">Records</th><th>Timezone</th><th>Notes</th></tr></thead><tbody>${rows}</tbody></table></div>`
      : `<div class="empty">No files yet.</div>`}`;
}

async function viewSource(v, label) {
  const r = await api(`/api/case/${enc(S.slug)}/source/${enc(label)}`);
  const s = r.source;
  const cfg = s.config || {};
  S.src = { label, cfg: JSON.parse(JSON.stringify(cfg)), samples: r.samples };
  const tabs = (cfg.tables || []).map((t, ti) => tableEditor(t, ti, r.samples[t.name] || {})).join("");
  v.innerHTML = `
    <p><a href="#/c/${enc(S.slug)}/sources">All sources</a></p>
    <h2>${esc(label)} - ${esc(s.name)}</h2>
    <table class="t" style="max-width:1000px;margin-bottom:16px"><tbody>
      <tr><td class="muted">Path</td><td class="mono">${esc(s.path)}</td></tr>
      <tr><td class="muted">SHA-256</td><td class="mono">${esc(s.sha256 || "not hashed yet")}</td></tr>
      <tr><td class="muted">Status</td><td><span class="status ${esc(s.status)}">${esc(s.status)}</span> ${fmt(s.rows)} records ${s.error ? `<span style="color:var(--p1)">${esc(s.error)}</span>` : ""}</td></tr>
      <tr><td class="muted">Detected</td><td>${(r.notes || []).map(esc).join("<br>")}</td></tr>
    </tbody></table>
    ${!cfg.tables ? `<div class="empty">This file has not been scanned yet. Run the analysis (the first stages detect its layout), then come back to check the mapping.</div>` : `
    <div class="panel">
      <h3>Time zone for times that carry no offset of their own</h3>
      <div class="row">
        <div class="field"><label for="ed-tz">Time zone</label><input id="ed-tz" type="text" size="24" list="zones2" value="${esc(cfg.tz)}"></div>
        <label class="check"><input type="checkbox" id="ed-tzass" ${cfg.tz_assumed ? "checked" : ""}> This is an assumption (not stated in the return)</label>
      </div>
      <p class="small muted">Basis: ${esc(cfg.tz_basis)}${(cfg.tz_conflicts || []).length ? `<br>Other hints: ${esc(cfg.tz_conflicts.join("; "))}` : ""}</p>
      <datalist id="zones2">${ZONES.map((z) => `<option value="${z}">`).join("")}</datalist>
      <div class="row">
        <div class="field"><label for="ed-acct">Account for rows that name none</label><input id="ed-acct" type="text" size="34" value="${esc(cfg.default_account || "")}"></div>
        <span class="small muted">${esc(cfg.default_account_basis || "")}</span>
      </div>
      ${(r.preamble || []).length ? `<details style="margin-top:10px"><summary class="small">Lines before the data (used for these hints)</summary><div class="lines" style="margin-top:6px">${r.preamble.map((p) => `<div><span>${esc(p[0])}</span><span>${esc(p[1])}</span></div>`).join("")}</div></details>` : ""}
    </div>
    ${tabs}
    <div class="row" style="margin:16px 0">
      <button class="btn" data-act="preview">Preview how it will be read</button>
      <button class="btn go" data-act="save-src">Save settings</button>
      <label class="check"><input type="checkbox" id="ed-skip" ${cfg.skip ? "checked" : ""}> Leave this file out of the analysis</label>
    </div>
    <div id="preview"></div>`}`;
}

function tableEditor(t, ti, smp) {
  const heads = t.headers || [];
  const m = t.mapping || {};
  const inv = {};
  Object.entries(m).forEach(([f, h]) => (inv[h] = f));
  const sampleOf = (i) => (smp.samples || []).slice(0, 4).map((r) => r[i]).filter((x) => x !== "" && x != null).map((x) => esc(String(x).slice(0, 60))).join(" | ");
  const grid = t.mode === "table" ? `<div class="mapgrid"><div class="hd">Column</div><div class="hd">Read as</div><div class="hd">Sample values</div>
    ${heads.map((h, i) => `<div><b>${esc(h)}</b></div><div><select data-map="${ti}" data-col="${esc(h)}">${FIELDS.map(([k, l]) => `<option value="${k}" ${inv[h] === k ? "selected" : ""}>${l}</option>`).join("")}</select></div><div class="samples">${sampleOf(i)}</div>`).join("")}
  </div>` : `<p class="small muted">Free text: each line with a timestamp, IP address or identifier becomes a record.</p>
    <div class="row"><div class="field"><label>Pair an IP line with the nearest timestamp line within</label><input type="text" size="4" data-pair="${ti}" value="${esc(t.pair_window || 0)}"> lines (0 = off)</div></div>`;
  return `<div class="panel">
    <div class="row" style="justify-content:space-between"><h3 style="margin:0">${esc(t.name)}</h3>
      <div class="row">
        ${t.mode === "table" || t.mode === "skip" ? `<div class="field"><label>Read this part as</label><select data-mode="${ti}"><option value="table" ${t.mode === "table" ? "selected" : ""}>Table</option><option value="skip" ${t.mode === "skip" ? "selected" : ""}>Skip it</option></select></div>` : `<div class="field"><label>Read this part as</label><select data-mode="${ti}"><option value="text" ${t.mode === "text" ? "selected" : ""}>Free text</option><option value="skip" ${t.mode === "skip" ? "selected" : ""}>Skip it</option></select></div>`}
        <div class="field"><label>Numeric dates</label><select data-order="${ti}">${["MDY", "DMY", "YMD"].map((o) => `<option ${t.date_order === o ? "selected" : ""}>${o}</option>`).join("")}</select></div>
        <div class="field"><label>Rows with no event type are</label><select data-cat="${ti}">${CATS.map((c) => `<option value="${c}" ${(t.default_category || "") === c ? "selected" : ""}>${c || "(left as other)"}</option>`).join("")}</select></div>
      </div></div>
    ${t.date_order_note ? `<div class="flagbox small">${esc(t.date_order_note)}</div>` : ""}
    ${t.default_category ? `<p class="small muted">Event type basis: ${esc(t.default_category_basis || "")}</p>` : ""}
    ${grid}
    ${(t.mapping_notes || []).length ? `<details style="margin-top:8px"><summary class="small">Why these columns were chosen</summary><ul class="small">${t.mapping_notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul></details>` : ""}
  </div>`;
}

function collectSourceConfig() {
  const cfg = JSON.parse(JSON.stringify(S.src.cfg));
  cfg.tz = $("#ed-tz").value.trim() || "UTC";
  cfg.tz_assumed = $("#ed-tzass").checked;
  cfg.default_account = $("#ed-acct").value.trim();
  cfg.skip = $("#ed-skip").checked;
  (cfg.tables || []).forEach((t, ti) => {
    const mode = $(`[data-mode="${ti}"]`);
    if (mode) t.mode = mode.value;
    const order = $(`[data-order="${ti}"]`);
    if (order) t.date_order = order.value;
    const cat = $(`[data-cat="${ti}"]`);
    if (cat) t.default_category = cat.value;
    const pair = $(`[data-pair="${ti}"]`);
    if (pair) t.pair_window = parseInt(pair.value || "0", 10) || 0;
    const sels = $$(`[data-map="${ti}"]`);
    if (sels.length) {
      const m = {};
      sels.forEach((s) => { if (s.value) m[s.value] = s.dataset.col; });
      t.mapping = m;
    }
  });
  return cfg;
}

async function doPreview() {
  const box = $("#preview");
  box.innerHTML = `<p class="muted">Reading the first records…</p>`;
  try {
    const r = await api(`/api/case/${enc(S.slug)}/source/${enc(S.src.label)}/preview`, { body: { config: collectSourceConfig() } });
    if (!r.rows.length) { box.innerHTML = `<div class="empty">No records found with these settings.</div>`; return; }
    if (r.rows[0].error) { box.innerHTML = `<div class="alertbox">${esc(r.rows[0].error)}</div>`; return; }
    box.innerHTML = `<h3>Preview: first ${r.rows.length} records</h3><div class="tblwrap"><table class="t"><thead><tr><th>Citation</th><th>As written</th><th>UTC</th><th>Basis</th><th>IP</th><th>Account</th><th>Type</th><th>Event</th><th>Identifiers</th></tr></thead><tbody>
      ${r.rows.map((x) => `<tr><td><code class="cite" data-cite="${esc(x.cite)}">${esc(x.cite)}</code></td><td class="mono">${esc(x.ts_raw)}</td><td class="mono">${esc(x.ts_utc)}${x.ts_flag ? `<div class="status flagged">${esc(x.ts_flag)}</div>` : ""}</td><td class="small">${esc(x.tz_basis)}</td><td class="mono nw">${esc(x.ip)}${x.port ? ":" + esc(x.port) : ""}<div class="small muted">${esc(x.ip_class)}</div></td><td>${esc(x.account)}</td><td>${esc(x.category)}</td><td class="small">${esc(x.action)}</td><td class="small mono">${esc((x.identifiers || []).join(" "))}</td></tr>`).join("")}
    </tbody></table></div>`;
  } catch (e) { box.innerHTML = `<div class="alertbox">${esc(e.message)}</div>`; }
}

async function doSaveSource() {
  try {
    const r = await api(`/api/case/${enc(S.slug)}/source/${enc(S.src.label)}/config`, { body: { config: collectSourceConfig() } });
    toast(r.note || "Saved.");
    renderCase();
  } catch (e) { toast(e.message, true); }
}

/* ------------------------------------------------------------------ findings */
async function viewFindings(v) {
  if (!S.fl) S.fl = { category: "", priority: "", q: "" };
  const qs = new URLSearchParams(S.fl).toString();
  const r = await api(`/api/case/${enc(S.slug)}/findings?${qs}`);
  if (!r.findings.length && !S.fl.q && !S.fl.category && !S.fl.priority) {
    v.innerHTML = `<div class="empty">No findings yet. Run the analysis; findings appear when the "Analyse" stage finishes (the report is written straight after, before the slower AI stage).</div>`;
    return;
  }
  let cur = null;
  const items = r.findings.map((f) => {
    const head = f.category !== cur ? `<div class="cat">${esc((cur = f.category))}</div>` : "";
    return `${head}<div class="fitem p${f.priority} ${S.param === f.fid ? "sel" : ""}" data-go="#/c/${enc(S.slug)}/findings/${f.fid}">
      <div class="id">${f.fid}${f.priority === 1 ? ` <span class="prio p1">priority 1</span>` : ""}</div><div class="ti">${esc(f.title)}</div></div>`;
  }).join("");
  v.innerHTML = `<div class="row" style="margin-bottom:12px">
      <div class="field"><label for="ff-q">Search findings</label><input id="ff-q" type="search" size="30" value="${esc(S.fl.q)}" placeholder="IP, account, word or F012"></div>
      <div class="field"><label for="ff-cat">Category</label><select id="ff-cat"><option value="">All</option>${r.categories.map((c) => `<option ${S.fl.category === c ? "selected" : ""}>${esc(c)}</option>`).join("")}</select></div>
      <div class="field"><label for="ff-pr">Priority</label><select id="ff-pr"><option value="">All</option><option value="1" ${S.fl.priority === "1" ? "selected" : ""}>1 only</option><option value="2" ${S.fl.priority === "2" ? "selected" : ""}>1 and 2</option></select></div>
      <button class="btn" data-act="filter">Filter</button><span class="muted small">${fmt(r.findings.length)} shown</span></div>
    <div class="split"><div class="flist">${items || `<p class="muted" style="padding:12px">Nothing matches.</p>`}</div><div id="fdetail"></div></div>`;
  if (S.param) showFinding(S.param);
  else $("#fdetail").innerHTML = `<div class="empty">Choose a finding to see its evidence, the records quoted from the original files, and the query that reproduces it.</div>`;
}

function factsTables(facts) {
  const t = (facts.tables || []).slice();
  if (facts.columns) t.unshift({ title: "", columns: facts.columns, rows: facts.rows || [], total_rows: facts.total_rows });
  return t;
}

async function showFinding(fid) {
  const box = $("#fdetail");
  box.innerHTML = `<p class="muted">Loading ${esc(fid)}…</p>`;
  const f = await api(`/api/case/${enc(S.slug)}/finding/${enc(fid)}`);
  const checks = {};
  (f.checks || []).forEach((c) => (checks[c.cite] = c));
  const ev = f.evidence.map((e) => {
    const ck = checks[e.cite];
    return `<tr><td>${esc(e.role)}</td><td><code class="cite" data-cite="${esc(e.cite)}">${esc(e.cite)}</code>${ck ? `<div><span class="status ${esc(ck.status)}" title="${esc(ck.detail)}">${ck.status === "pass" ? "re-read: matches" : esc(ck.status)}</span></div>` : ""}</td>
      <td class="mono small nw">${esc(e.ts_utc)}<div class="muted">${esc(e.ts_raw)}</div></td><td class="mono small nw">${esc(e.ip)}</td><td class="small">${esc(e.account)}</td><td class="small">${esc(e.action || e.category)}</td>
      <td class="raw small">${esc((e.raw || "").slice(0, 400))}</td></tr>`;
  }).join("");
  const tabs = factsTables(f.facts).map((t) => `${t.title ? `<h3>${esc(t.title)}${t.total_rows && t.total_rows > t.rows.length ? ` <span class="small muted">(${fmt(t.rows.length)} of ${fmt(t.total_rows)})</span>` : ""}</h3>` : ""}
    <div class="tblwrap" style="margin-bottom:14px"><table class="t"><thead><tr>${t.columns.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>
    ${t.rows.map((r) => `<tr>${r.map((x) => `<td class="small">${esc(Array.isArray(x) ? x.join(", ") : x)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`).join("");
  box.innerHTML = `<div class="panel">
    <div class="small muted">${esc(f.fid)}, ${esc(f.category)}</div>
    <h2>${esc(f.title)}</h2>
    <div class="prio ${f.priority === 1 ? "p1" : ""}">Priority ${f.priority}</div>
    <p class="statement">${esc(f.statement)}</p>
    ${(f.cites || []).map((c) => `<div class="small">Also cites <code class="cite" data-cite="${esc(c.cite)}">${esc(c.cite)}</code> ${esc(c.text)}</div>`).join("")}
    <h3 style="margin-top:16px">Evidence (${fmt(f.evidence.length)} records)</h3>
    ${ev ? `<div class="tblwrap"><table class="t"><thead><tr><th>Role</th><th>Citation</th><th>UTC / as written</th><th>IP</th><th>Account</th><th>Event</th><th>Verbatim record</th></tr></thead><tbody>${ev}</tbody></table></div>` : `<p class="muted small">This finding rests on the file-level facts above.</p>`}
    <p class="small muted">Click a citation to open that place in the original file.</p>
    ${tabs}
    ${f.export ? `<p><a href="/case/${enc(S.slug)}/file/${esc(f.export.replace(/^.*?exports/, "exports"))}">Download ${esc(f.export)}</a></p>` : ""}
    ${f.sql ? `<h3>Reproduce</h3><pre class="sql">${esc(f.sql)}</pre><p class="small muted">Read-only SQL against case.db (any SQLite browser can run it).</p>` : ""}
  </div>`;
}

/* ------------------------------------------------------------------ lookup */
async function viewLookup(v) {
  v.innerHTML = `<div class="panel"><h2>Look up</h2>
    <div class="row">
      <div class="field"><label for="lk-kind">What</label><select id="lk-kind"><option value="ip">IP address or range (CIDR)</option><option value="account">Account (use * as wildcard)</option><option value="identifier">Email, phone, crypto address, MAC…</option><option value="text">Any text in the records</option><option value="time">Time window only</option></select></div>
      <div class="field" style="flex:1;min-width:240px"><label for="lk-q">Value</label><input id="lk-q" type="text" style="width:100%" placeholder="e.g. 203.0.113.5 or 198.51.100.0/24"></div>
      <div class="field"><label for="lk-from">From (UTC)</label><input id="lk-from" type="text" size="19" placeholder="2024-04-01"></div>
      <div class="field"><label for="lk-to">To (UTC)</label><input id="lk-to" type="text" size="19" placeholder="2024-04-30 23:59"></div>
      <button class="btn go" data-act="lookup">Look up</button>
    </div><p class="small muted">Direct database queries - no AI involved. Every row cites its place in the original file.</p></div>
    <div id="lk-out"></div>`;
}

async function doLookup(save) {
  const body = { kind: $("#lk-kind").value, q: $("#lk-q").value.trim(), from: $("#lk-from").value.trim(), to: $("#lk-to").value.trim() };
  const out = $("#lk-out");
  if (save) {
    try { const r = await api(`/api/case/${enc(S.slug)}/lookup/save`, { body }); toast(`Saved to ${r.file}`); } catch (e) { toast(e.message, true); }
    return;
  }
  out.innerHTML = `<p class="muted">Searching…</p>`;
  try {
    const qs = new URLSearchParams({ kind: body.kind, q: body.q, from: body.from, to: body.to, limit: 1000 }).toString();
    const r = await api(`/api/case/${enc(S.slug)}/lookup?${qs}`);
    out.innerHTML = `<div class="panel"><p><b>${esc(r.summary)}</b></p>
      <div class="row"><button class="btn small" data-act="lookup-save">Save as Markdown</button></div>
      <details style="margin-top:8px"><summary class="small">Query</summary><pre class="sql">${esc(r.sql)}</pre></details></div>
      ${r.rows.length ? `<div class="tblwrap"><table class="t"><thead><tr><th>Citation</th><th>UTC</th><th>Account</th><th>Type</th><th>Event</th><th>IP</th><th>Network</th><th>Verbatim record</th></tr></thead><tbody>
      ${r.rows.map((x) => `<tr><td><code class="cite" data-cite="${esc(x.cite)}">${esc(x.cite)}</code></td><td class="mono small nw">${esc(x.ts_utc)}</td><td class="small">${esc(x.account)}</td><td class="small">${esc(x.category)}</td><td class="small">${esc(x.action)}</td><td class="mono small nw">${esc(x.ip)}${x.port ? ":" + esc(x.port) : ""}</td><td class="small">${esc([x.network, x.country].filter(Boolean).join(" "))}</td><td class="raw small">${esc(x.raw)}</td></tr>`).join("")}
      </tbody></table></div>` : ""}`;
  } catch (e) { out.innerHTML = `<div class="alertbox">${esc(e.message)}</div>`; }
}

/* ------------------------------------------------------------------ ask */
async function viewAsk(v) {
  const r = await api(`/api/case/${enc(S.slug)}/asks`);
  const llmOk = S.state.llm && S.state.llm.ok;
  v.innerHTML = `<div class="panel"><h2>Ask a question</h2>
    ${llmOk ? "" : `<div class="flagbox">No local model is reachable, so questions cannot be answered. Look up still works.</div>`}
    <div class="field"><label for="ask-q">Question about the records</label><textarea id="ask-q" rows="2" style="width:100%" placeholder="e.g. Which IPs logged in to jdoe.trader@example.com between 2024-04-10 and 2024-04-20?"></textarea></div>
    <button class="btn go" data-act="ask" ${llmOk ? "" : "disabled"}>Ask</button>
    <p class="small muted">The local model writes one read-only database query. The answer you see is that query's result, with citations; the query is shown so you can check or re-run it. On this computer a question takes about one to three minutes.</p></div>
    <div class="split"><div class="flist">${r.asks.map((a) => `<div class="fitem ${String(a.id) === S.param ? "sel" : ""}" data-go="#/c/${enc(S.slug)}/ask/${a.id}"><div class="id">Q${String(a.id).padStart(3, "0")} <span class="status ${esc(a.status)}">${esc(a.status)}</span></div><div class="ti">${esc(a.question)}</div></div>`).join("") || `<p class="muted" style="padding:12px">No questions yet.</p>`}</div>
    <div id="ask-out">${S.param ? "" : `<div class="empty">Answers appear here.</div>`}</div></div>`;
  if (S.param) showAsk(S.param);
}

async function showAsk(id) {
  const box = $("#ask-out");
  const a = await api(`/api/case/${enc(S.slug)}/ask/${enc(id)}`);
  clearInterval(S.askTimer);
  if (a.status === "queued" || a.status === "running") {
    box.innerHTML = `<div class="panel"><h3>${esc(a.question)}</h3><p class="muted">${esc((a.job && a.job.message) || "Waiting for the model…")}</p></div>`;
    S.askWaiting = id;
    S.askTimer = setInterval(() => showAsk(id), 4000);
    return;
  }
  if (S.askWaiting === id) { S.askWaiting = null; renderCase(); return; }
  if (a.status === "error") { box.innerHTML = `<div class="panel"><h3>${esc(a.question)}</h3><div class="alertbox">${esc(a.error)}</div></div>`; return; }
  const ok = (a.summary || []).filter((s) => s.status !== "rejected" && s.text);
  const rej = (a.summary || []).filter((s) => s.status === "rejected" && s.text);
  const cols = a.columns || [];
  box.innerHTML = `<div class="panel"><h3>${esc(a.question)}</h3>
    ${ok.length ? `<div class="okbox">${ok.map((s) => `<div>${s.status === "flagged" ? "⚑ " : ""}${esc(s.text)} <span class="small muted">(${esc((s.cites || []).join(", "))})</span></div>`).join("")}<div class="small muted">Model summary, verified against the rows below.</div></div>` : ""}
    ${rej.length ? `<details><summary class="small">${rej.length} summary sentence(s) removed by verification</summary><ul class="small">${rej.map((s) => `<li><del>${esc(s.text)}</del> - ${esc((s.reasons || []).join("; "))}</li>`).join("")}</ul></details>` : ""}
    <h3>Query</h3><pre class="sql">${esc(a.sql)}</pre><p class="small muted">${esc(a.explanation || "")}</p>
    <h3>Result: ${fmt(a.row_count)} row(s)${a.truncated ? " (first 500)" : ""}</h3>
    ${cols.length ? `<div class="tblwrap"><table class="t"><thead><tr><th>#</th>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>
      ${(a.rows || []).map((r, i) => `<tr><td class="mono small nw">R${i + 1}</td>${r.map((x, k) => /cite/.test(cols[k]) && x ? `<td><code class="cite" data-cite="${esc(x)}">${esc(x)}</code></td>` : `<td class="small">${esc(x)}</td>`).join("")}</tr>`).join("")}
    </tbody></table></div>` : ""}
    <p class="small muted">Saved as report/questions/Q${String(a.id).padStart(3, "0")}.md</p></div>`;
}

/* ------------------------------------------------------------------ reports */
const REPORT_NAMES = { "REPORT.md": "Report", "REVIEW.md": "Review checklist", "FINDINGS.md": "Findings", "EVIDENCE.md": "Evidence",
  "SOURCES.md": "Sources", "TIMELINE.md": "Timeline", "METHODS.md": "Methods", "CITATION_CHECK.md": "Citation check" };
async function viewReports(v) {
  const r = await api(`/api/case/${enc(S.slug)}/reports`);
  if (!r.files.length) { v.innerHTML = `<div class="empty">No report yet. It is written as soon as the analysis stage finishes.</div>`; return; }
  const file = S.param || "REPORT.md";
  v.innerHTML = `<div class="row" style="margin-bottom:10px"><button class="btn small" data-act="open-folder">Open the report folder</button>
      <button class="btn small" data-act="rewrite">Rewrite report</button><span class="small muted">Markdown files - open them in any editor or viewer.</span></div>
    <div class="tabs">${r.files.map((f) => `<a href="#/c/${enc(S.slug)}/reports/${esc(f.file)}" class="${f.file === file.split("#")[0] ? "on" : ""}">${esc(REPORT_NAMES[f.file] || f.file.replace(/\.md$/, ""))}</a>`).join("")}</div>
    <div id="rep" class="report"><p class="muted">Loading…</p></div>
    ${r.exports.length ? `<div class="panel" style="margin-top:16px"><h3>Exports (CSV)</h3>${r.exports.map((e) => `<a href="/case/${enc(S.slug)}/file/${esc(e)}">${esc(e.replace("exports/", ""))}</a>`).join(" &nbsp; ")}</div>` : ""}`;
  const [fname, anchor] = file.split("#");
  const rep = await api(`/api/case/${enc(S.slug)}/report?file=${enc(fname)}`);
  const box = $("#rep");
  box.innerHTML = rep.html;
  const base = fname.includes("/") ? fname.slice(0, fname.lastIndexOf("/") + 1) : "";
  $$("img", box).forEach((im) => {
    const src = im.getAttribute("src");
    if (src && !/^(https?:|\/)/.test(src)) im.src = `/case/${enc(S.slug)}/file/${base}${src}`;
  });
  $$("a", box).forEach((a) => {
    const h = a.getAttribute("href") || "";
    if (/^https?:/.test(h)) { a.target = "_blank"; a.rel = "noopener"; return; }
    if (h.startsWith("#")) { a.dataset.anchor = h.slice(1); return; }
    const m = h.match(/^([^#]*\.md)(#.*)?$/);
    if (m) { a.setAttribute("href", `#/c/${enc(S.slug)}/reports/${base}${m[1]}${m[2] ? "#" + m[2].slice(1) : ""}`); return; }
    if (h && !h.startsWith("#")) a.setAttribute("href", `/case/${enc(S.slug)}/file/${base}${h}`);
  });
  if (anchor) { const t = document.getElementById(anchor); if (t) t.scrollIntoView(); }
}

/* ------------------------------------------------------------------ settings */
async function viewSettings(v) {
  const c = S.c;
  const st = S.state;
  const p = c.params;
  const label = (k) => k.replace(/_/g, " ");
  const llm = st.settings.llm;
  const models = (st.llm && st.llm.models) || [];
  v.innerHTML = `<div class="panel"><h2>Case</h2>
    <div class="row"><div class="field"><label for="cs-ex">Examiner</label><input id="cs-ex" type="text" value="${esc(c.info.examiner || "")}"></div>
    <div class="field"><label for="cs-tz">Local time zone for display</label><input id="cs-tz" type="text" list="zones3" value="${esc(c.info.display_tz || "")}"></div>
    <div class="field" style="flex:1"><label for="cs-desc">Description</label><input id="cs-desc" type="text" style="width:100%" value="${esc(c.info.description || "")}"></div></div>
    <datalist id="zones3">${ZONES.map((z) => `<option value="${z}">`).join("")}</datalist>
    <h3 style="margin-top:14px">Analysis settings</h3>
    <div class="mapgrid" style="grid-template-columns: 260px 160px 1fr">${Object.keys(st.params_default).map((k) => {
      const dv = st.params_default[k];
      const input = typeof dv === "boolean" ? `<select data-param="${k}"><option value="true" ${p[k] ? "selected" : ""}>yes</option><option value="false" ${!p[k] ? "selected" : ""}>no</option></select>`
        : `<input type="text" size="10" data-param="${k}" value="${esc(p[k])}">`;
      return `<div>${esc(label(k))}</div><div>${input}</div><div class="small muted">default ${esc(dv)}</div>`;
    }).join("")}</div>
    <p class="small muted">Changes apply to the next run. Every change is written to the case audit log.</p>
    <button class="btn go" data-act="save-case">Save case settings</button></div>
    <div class="panel"><h2>Local model (all cases)</h2>
      <div class="row"><div class="field"><label for="lm-url">Model server address (this computer)</label><input id="lm-url" type="text" size="30" value="${esc(llm.url)}"></div>
      <div class="field"><label for="lm-model">Model</label><select id="lm-model"><option value="auto" ${llm.model === "auto" ? "selected" : ""}>Choose automatically</option>${models.map((m) => `<option ${llm.model === m ? "selected" : ""}>${esc(m)}</option>`).join("")}</select></div>
      <div class="field"><label for="lm-thr">CPU threads</label><input id="lm-thr" type="text" size="4" value="${esc(llm.num_thread)}"></div>
      <div class="field"><label for="lm-ctx">Context size</label><input id="lm-ctx" type="text" size="6" value="${esc(llm.num_ctx)}"></div>
      <label class="check"><input type="checkbox" id="lm-on" ${llm.enabled ? "checked" : ""}> Use the model</label></div>
      <p class="small">${st.llm && st.llm.ok ? `Connected: ${models.length} model(s) installed.` : `<span style="color:var(--p1)">Not reachable: ${esc(st.llm && st.llm.error)}</span>`}</p>
      <button class="btn go" data-act="save-llm">Save and test</button></div>`;
}

/* ------------------------------------------------------------------ layers: source viewer, folder browser */
function closeLayer() { const l = $("#layer"); if (l) l.innerHTML = ""; }

async function openCite(cite) {
  const layer = $("#layer");
  layer.innerHTML = `<div class="shade" data-act="close"></div><aside class="drawer" role="dialog" aria-label="Source record"><button class="btn small close" data-act="close">Close</button><p class="muted">Opening ${esc(cite)}…</p></aside>`;
  try {
    const r = await api(`/api/case/${enc(S.slug)}/context?cite=${enc(cite)}`);
    $(".drawer").innerHTML = `<button class="btn small close" data-act="close">Close</button>
      <h2 class="mono" style="font-size:18px">${esc(cite)}</h2>
      <p><b>${esc(r.file)}</b><br><span class="small mono">${esc(r.path)}</span><br><span class="small">SHA-256 at ingest <span class="mono">${esc(r.sha256)}</span></span></p>
      <p class="small muted">Read from the original file just now. The cited ${r.lines.length > 1 ? "line is" : "record is"} highlighted.</p>
      <div class="lines">${r.lines.map((l) => `<div class="${l.hit ? "hit" : ""}"><span>${esc(l.n)}</span><span>${esc(l.text)}</span></div>`).join("") || `<div><span></span><span>(nothing to show)</span></div>`}</div>
      ${r.record != null ? `<h3 style="margin-top:16px">Stored at ingest</h3><pre class="raw">${esc(r.record)}</pre>` : ""}`;
  } catch (e) { $(".drawer").innerHTML = `<button class="btn small close" data-act="close">Close</button><div class="alertbox">${esc(e.message)}</div>`; }
}

async function openBrowser(path) {
  const layer = $("#layer");
  try {
    const r = await api(`/api/fs?path=${enc(path || "")}`);
    layer.innerHTML = `<div class="shade" data-act="close"></div><div class="modal fs" role="dialog" aria-label="Choose a folder">
      <h3>Choose a file or folder</h3><p class="mono small">${esc(r.path || "This computer")}</p>
      ${r.parent !== null && r.parent !== undefined ? `<a data-fs="${esc(r.parent)}">.. (up)</a>` : ""}
      ${r.dirs.map((d) => `<a data-fs="${esc(r.path ? r.path.replace(/[\\/]$/, "") + (r.path.includes("\\") ? "\\" : "/") + d : d)}">${esc(d)}</a>`).join("")}
      ${r.files.slice(0, 200).map((f) => `<a data-pick="${esc(r.path.replace(/[\\/]$/, "") + (r.path.includes("\\") ? "\\" : "/") + f.name)}" class="small">${esc(f.name)} <span class="muted">${bytes(f.size)}</span></a>`).join("")}
      <div class="row" style="margin-top:12px"><button class="btn go" data-pick="${esc(r.path)}" ${r.path ? "" : "disabled"}>Use this folder</button><button class="btn" data-act="close">Cancel</button></div></div>`;
  } catch (e) { toast(e.message, true); }
}

/* ------------------------------------------------------------------ events */
document.addEventListener("click", async (e) => {
  const cite = e.target.closest("code.cite, .cite[data-cite]");
  if (cite) { e.preventDefault(); openCite(cite.dataset.cite || cite.textContent.trim()); return; }
  const go = e.target.closest("[data-go]");
  if (go) { location.hash = go.dataset.go; return; }
  const fs = e.target.closest("[data-fs]");
  if (fs) { openBrowser(fs.dataset.fs); return; }
  const pick = e.target.closest("[data-pick]");
  if (pick) { const i = $("#src-path"); if (i) i.value = pick.dataset.pick; closeLayer(); return; }
  const anc = e.target.closest("a[data-anchor]");
  if (anc) { e.preventDefault(); const t = document.getElementById(anc.dataset.anchor); if (t) t.scrollIntoView({ behavior: "smooth" }); return; }
  const a = e.target.closest("[data-act]");
  if (!a) return;
  const act = a.dataset.act;
  try {
    if (act === "close") closeLayer();
    else if (act === "demo") {
      a.disabled = true;
      const r = await api("/api/demo", { body: {} });
      toast("Demo case created; the analysis is running.");
      location.hash = `#/c/${enc(r.slug)}/overview`;
    } else if (act === "new-case") {
      const r = await api("/api/cases", { body: { name: $("#nc-name").value, examiner: $("#nc-ex").value, display_tz: $("#nc-tz").value, description: $("#nc-desc").value } });
      location.hash = `#/c/${enc(r.slug)}/sources`;
    } else if (act === "add-src") {
      a.disabled = true;
      const r = await api(`/api/case/${enc(S.slug)}/sources`, { body: { path: $("#src-path").value, recursive: $("#src-rec").checked, zip_password: $("#src-pw").value } });
      toast(`Added ${r.added.length} file(s)${r.skipped.length ? `, skipped ${r.skipped.length} already added` : ""}. Run the analysis to read them.`);
      renderCase();
    } else if (act === "browse") openBrowser($("#src-path").value);
    else if (act === "run") {
      const llm = $("#use-llm") ? $("#use-llm").checked : false;
      await api(`/api/case/${enc(S.slug)}/run`, { body: { llm } });
      toast("Analysis started. It runs in the background - you can close the browser.");
      renderCase();
    } else if (act === "cancel") {
      await api(`/api/case/${enc(S.slug)}/cancel`, { body: {} });
      toast("Stopping at the next checkpoint. Resume later to continue.");
    } else if (act === "preview") doPreview();
    else if (act === "save-src") doSaveSource();
    else if (act === "filter") {
      S.fl = { q: $("#ff-q").value.trim(), category: $("#ff-cat").value, priority: $("#ff-pr").value };
      renderCase();
    } else if (act === "lookup") doLookup(false);
    else if (act === "lookup-save") doLookup(true);
    else if (act === "ask") {
      const q = $("#ask-q").value.trim();
      if (!q) return;
      const r = await api(`/api/case/${enc(S.slug)}/ask`, { body: { question: q } });
      location.hash = `#/c/${enc(S.slug)}/ask/${r.ask}`;
    } else if (act === "open-folder") {
      const r = await api(`/api/case/${enc(S.slug)}/open-folder`, { body: { which: "report" } });
      toast(`Opened ${r.path}`);
    } else if (act === "rewrite") {
      await api(`/api/case/${enc(S.slug)}/report`, { body: {} });
      toast("Rewriting the report…");
      setTimeout(renderCase, 2500);
    } else if (act === "save-case") {
      const params = {};
      $$("[data-param]").forEach((i) => (params[i.dataset.param] = i.tagName === "SELECT" ? i.value === "true" : i.value));
      await api(`/api/case/${enc(S.slug)}/settings`, { body: { examiner: $("#cs-ex").value, display_tz: $("#cs-tz").value, description: $("#cs-desc").value, params } });
      toast("Saved. Applies to the next run.");
    } else if (act === "save-llm") {
      const r = await api("/api/settings", { body: { llm: { url: $("#lm-url").value.trim(), model: $("#lm-model").value, num_thread: parseInt($("#lm-thr").value, 10) || 8, num_ctx: parseInt($("#lm-ctx").value, 10) || 8192, enabled: $("#lm-on").checked } } });
      toast(r.llm.ok ? `Model server reachable: ${r.llm.model}` : `Not reachable: ${r.llm.error}`, !r.llm.ok);
      await loadState();
      renderCase();
    }
  } catch (err) {
    toast(err.message, true);
  } finally {
    if (act === "add-src") a.disabled = false;
  }
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeLayer();
  if (e.key === "Enter" && e.target && e.target.id === "lk-q") doLookup(false);
  if (e.key === "Enter" && e.target && e.target.id === "ff-q") { S.fl = { q: e.target.value.trim(), category: $("#ff-cat").value, priority: $("#ff-pr").value }; renderCase(); }
});

route();
