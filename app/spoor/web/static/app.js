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
  ["direction", "Direction"], ["amount", "Amount"], ["currency", "Currency / asset"],
  ["orig", "Telecom: originating number"], ["term", "Telecom: terminating number"], ["duration", "Telecom: duration"],
  ["cell", "Telecom: first cell / sector"], ["cell_last", "Telecom: last cell / sector"], ["lat", "Telecom: site latitude"],
  ["lon", "Telecom: site longitude"], ["azimuth", "Telecom: sector azimuth"], ["beamwidth", "Telecom: beamwidth"],
  ["site_name", "Telecom: site name"], ["imei", "Telecom: IMEI"], ["imsi", "Telecom: IMSI"]];
const CATS = ["", "login", "login_failed", "logout", "account_change", "registration", "communication", "transaction", "other"];
const ZONES = ["UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Phoenix", "America/Los_Angeles", "America/Anchorage",
  "Pacific/Honolulu", "Europe/London", "Europe/Berlin", "Europe/Kyiv", "Europe/Moscow", "Asia/Shanghai", "Asia/Tokyo", "UTC-08:00", "UTC-05:00"];
const STAGE_SHORT = { prepare: "Hash", scan: "Map", ingest: "Read", index: "Index", analyze: "Analyse", report1: "Report", figures: "Figures", verify: "Verify", narrative: "AI draft", report2: "Final" };

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
const VIEWS = [["overview", "Overview"], ["returns", "Returns"], ["sources", "Files"], ["findings", "Findings"], ["crossref", "Cross-reference"], ["map", "Map"], ["links", "Links"], ["lookup", "Look up"], ["ask", "Ask"], ["reports", "Reports"], ["settings", "Settings"]];

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
  const fn = { overview: viewOverview, returns: viewReturns, crossref: viewCrossref, map: viewMap, links: viewLinks, sources: viewSources, findings: viewFindings, lookup: viewLookup, ask: viewAsk, reports: viewReports, settings: viewSettings }[S.view] || viewOverview;
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
       <button class="btn go" data-act="run" ${S.c.counts.sources ? "" : "disabled"}>${j && (j.status === "interrupted" || j.status === "cancelled" || j.status === "error") ? "Resume analysis" : (S.c.counts.findings ? (pend || S.c.returns_changed ? "Run again (returns changed)" : "Run again") : "Run analysis")}</button>`}
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
  const failed = (c.analysis_errors || []).length ? `<div class="alertbox"><b>${c.analysis_errors.length} analysis module${c.analysis_errors.length > 1 ? "s" : ""} failed in the last run - the report is incomplete.</b> ${esc(c.analysis_errors.map((x) => x[0] + ": " + x[1]).join("; "))}. Run the analysis again; see REVIEW.md.</div>` : "";
  if (!k.sources) {
    v.innerHTML = `<div class="empty"><b>No returns added yet.</b><br>Go to <a href="#/c/${enc(S.slug)}/sources">Sources</a> and add the folder (or ZIP) that holds the subpoena returns. Spoor reads CSV, TSV, Excel, JSON, HTML, PDF, text and ZIP files.</div>`;
    return;
  }
  const keys = c.key_findings.map((f) => `<tr class="click" data-go="#/c/${enc(S.slug)}/findings/${f.fid}"><td class="mono nw">${f.fid}</td><td><b>${esc(f.title)}</b><div class="small">${esc(f.statement)}</div></td></tr>`).join("");
  v.innerHTML = `${failed}
    <div class="stats">
      <div><b>${fmt(k.ingested)} / ${fmt(k.sources)}</b><span>files analysed</span></div>
      <div><b>${fmt(k.events)}</b><span>records</span></div>
      <div><b>${fmt(k.findings)}</b><span>findings</span></div>
      <div><b>${fmt(k.p1)}</b><span>priority 1</span></div>
      <div><b>${c.span && c.span[0] ? esc(c.span[0].slice(0, 10)) + " to " + esc(c.span[1].slice(0, 10)) : "-"}</b><span>time span (UTC)</span></div>
    </div>
    ${S.c.returns_changed && !running(currentJob()) ? `<div class="flagbox">The set of returns has changed since the last analysis (<a href="#/c/${enc(S.slug)}/returns">see Returns</a>). The report below still reflects the old set - run the analysis again.</div>` : ""}
    ${k.pending && !running(currentJob()) ? `<div class="flagbox">${fmt(k.pending)} file(s) are new or have changed settings. Run the analysis to include them.</div>` : ""}
    ${cc ? `<div class="${cc.fail ? "alertbox" : "okbox"}">Citation check ${esc(cc.run_at)}: ${fmt(cc.pass)} of ${fmt(cc.total)} cited records were re-read from the original files and matched${cc.fail ? `; <b>${fmt(cc.fail)} did not match</b> - see REVIEW.md` : ""}${cc.unverifiable ? `; ${fmt(cc.unverifiable)} could not be checked` : ""}.${cc.hashes ? ` Source hashes: ${fmt(cc.hashes.match)} unchanged${cc.hashes.mismatch ? `, <b>${fmt(cc.hashes.mismatch)} CHANGED</b>` : ""}${cc.hashes.missing ? `, ${fmt(cc.hashes.missing)} missing` : ""}.` : ""}</div>` : ""}
    ${nar ? `<div class="okbox">AI-drafted summary (${esc(nar.model)}): ${fmt(nar.accepted)} sentences kept after verification${nar.flagged ? `, ${fmt(nar.flagged)} of them flagged for your judgment` : ""}; ${fmt(nar.rejected)} removed. They are in REPORT.md; the removed ones are listed in REVIEW.md.</div>` : ""}
    ${c.report_ready ? `<p><a href="#/c/${enc(S.slug)}/reports/REPORT.md"><b>Read the report</b></a> &nbsp; <a href="#/c/${enc(S.slug)}/reports/REVIEW.md">Review checklist</a> &nbsp; <button class="btn small" data-act="open-folder">Open the report folder</button></p>` : ""}
    <h2 style="margin-top:22px">Priority-1 findings</h2>
    ${keys ? `<div class="tblwrap"><table class="t"><tbody>${keys}</tbody></table></div>` : `<p class="muted">None yet. Run the analysis to produce findings.</p>`}
    <h2 style="margin-top:22px">Status</h2>
    <pre class="raw" id="statustext">${esc(c.status_text)}</pre>`;
}


/* ------------------------------------------------------------------ returns */
async function viewReturns(v) {
  const r = await api(`/api/case/${enc(S.slug)}/returns`);
  const act = r.returns.filter((x) => x.state === "active"), out = r.returns.filter((x) => x.state === "excluded"), gone = r.returns.filter((x) => x.state === "removed");
  const row = (x) => {
    const files = x.files.map((f) => `<tr><td class="mono nw small">${esc(f.label)}</td><td class="small">${esc(f.name)}</td><td class="small muted">${esc(f.kind)}</td><td class="small"><span class="status ${esc(f.status)}">${esc(f.status)}</span></td><td class="num small">${fmt(f.rows)}</td>
      <td class="small"><select data-move="${esc(f.label)}" aria-label="Move ${esc(f.label)} to another return"><option value="">move to…</option>${r.returns.filter((o) => o.label !== x.label && o.state !== "removed").map((o) => `<option value="${esc(o.label)}">${esc(o.label)} ${esc(o.name)}</option>`).join("")}<option value="__new">a new return</option></select></td></tr>`).join("");
    return `<div class="panel ret ${x.state}" data-ret="${esc(x.label)}">
      <div class="row" style="align-items:baseline">
        <h3 style="margin:0"><span class="mono">${esc(x.label)}</span> &nbsp;<span class="retname">${esc(x.name)}</span></h3><span class="grow"></span>
        ${x.state === "active" ? `<button class="btn small" data-ract="exclude" data-ref="${esc(x.label)}" ${r.running ? "disabled" : ""} title="Leave this return out of the next analysis. Nothing is deleted; you can put it back.">Leave out</button>`
          : x.state === "excluded" ? `<button class="btn small go" data-ract="include" data-ref="${esc(x.label)}" ${r.running ? "disabled" : ""}>Put back</button>`
          : `<button class="btn small go" data-ract="restore" data-ref="${esc(x.label)}">Restore</button>`}
        <button class="btn small" data-ract="rename" data-ref="${esc(x.label)}" data-name="${esc(x.name)}">Rename</button>
        ${x.state !== "removed" ? `<button class="btn small" data-ract="remove" data-ref="${esc(x.label)}" ${r.running ? "disabled" : ""} title="Hide this return. The files are never touched; Restore brings it back.">Remove</button>` : ""}
      </div>
      <div class="small muted" style="margin:4px 0 6px">${x.state === "excluded" ? `<b style="color:var(--flag)">Left out of the next analysis</b> (${esc(x.state_at || "")}${x.note ? ": " + esc(x.note) : ""}). ` : ""}${x.state === "removed" ? `<b>Removed</b> ${esc(x.state_at || "")}. ` : ""}${x.files.length} file(s)${x.state === "active" ? `, ${fmt(x.records)} records` : ""}${x.first_utc ? `, ${esc(x.first_utc.slice(0, 10))} to ${esc(x.last_utc.slice(0, 10))}` : ""} · <span class="mono">${esc(x.root || "")}</span></div>
      <details><summary class="small">Files in this return</summary><div class="tblwrap" style="margin-top:6px"><table class="t"><tbody>${files}</tbody></table></div></details>
    </div>`;
  };
  v.innerHTML = `
    <h2>Returns</h2>
    <p class="muted">A return is one provider's response. Every record, identifier and citation in the report says which return it came from. To drop a return that turned out to be useless, press <b>Leave out</b> and run the analysis again: the report, figures and cross-reference are rebuilt without it. <b>Put back</b> reads it again. Files are never changed or deleted.</p>
    ${r.changed && !r.running ? `<div class="flagbox">The return set has changed. <button class="btn small go" data-act="run">Run the analysis again</button> The current report still reflects the old set.</div>` : ""}
    ${r.running ? `<div class="flagbox">An analysis is running; changes to the returns can be made when it finishes.</div>` : ""}
    ${act.length ? act.map(row).join("") : `<div class="empty">No active returns. Add files on the Files screen, or put a return back.</div>`}
    ${out.length ? `<h3 style="margin-top:20px">Left out of the analysis (${out.length})</h3>${out.map(row).join("")}` : ""}
    ${gone.length ? `<details style="margin-top:16px"><summary class="small">Removed (${gone.length})</summary>${gone.map(row).join("")}</details>` : ""}`;
}

async function returnAction(el) {
  const act = el.dataset.ract, ref = el.dataset.ref;
  let body = { action: act, ref };
  if (act === "exclude") {
    const why = prompt(`Leave ${ref} out of the next analysis?\n\nOptional note (kept in the audit log and shown in the report):`, "");
    if (why === null) return;
    body.reason = why;
  } else if (act === "remove") {
    if (!confirm(`Remove ${ref} from this case's list? The files are not touched, and Restore brings it back.`)) return;
  } else if (act === "rename") {
    const n = prompt(`New name for ${ref}:`, el.dataset.name || "");
    if (!n) return;
    body.name = n;
  }
  await api(`/api/case/${enc(S.slug)}/returns`, { body });
  toast(act === "rename" ? "Renamed." : "Saved. Run the analysis again for it to take effect.");
  renderCase();
}

async function moveSource(sel) {
  if (!sel.value) return;
  const body = { action: "move", source: sel.dataset.move, to: sel.value === "__new" ? "" : sel.value };
  if (sel.value === "__new") { const n = prompt("Name for the new return:", ""); if (n === null) return; body.name = n; }
  await api(`/api/case/${enc(S.slug)}/returns`, { body });
  toast(`${sel.dataset.move} moved. Run the analysis again for it to take effect.`);
  renderCase();
}

/* ------------------------------------------------------------------ sources */
async function viewSources(v) {
  if (S.param) return viewSource(v, S.param);
  const r = await api(`/api/case/${enc(S.slug)}/sources`);
  const rows = r.sources.filter((s) => s.status !== "container").map((s) => {
    const flags = Object.entries(s.flags || {}).map(([k, n]) => `${esc(k)} ${fmt(n)}`).join(", ");
    return `<tr class="click" data-go="#/c/${enc(S.slug)}/sources/${s.label}">
      <td class="mono nw">${s.label}${s.ret ? `<div class="small muted">${esc(s.ret)}</div>` : ""}</td><td><b>${esc(s.name)}</b>${s.parent ? `<div class="small muted">${esc(s.display)}</div>` : ""}</td>
      <td>${esc(s.kind)}</td><td class="num">${bytes(s.size)}</td>
      <td><span class="status ${esc(s.status)}">${esc(s.status)}</span>${s.changed ? ` <span class="status flagged">settings changed</span>` : ""}${s.error ? `<div class="small" style="color:var(--p1)">${esc(s.error)}</div>` : ""}</td>
      <td class="num">${fmt(s.rows)}</td>
      <td>${s.tz ? esc(s.tz) + (s.tz_assumed ? ` <span class="status flagged">assumed</span>` : "") : ""}</td>
      <td class="small">${s.ts_failed ? `<span style="color:var(--p1)">${fmt(s.ts_failed)} unparsed times</span> ` : ""}${flags}</td></tr>`;
  }).join("");
  v.innerHTML = `
    <div class="panel">
      <h2>Add returns</h2>
      <p class="small muted" style="margin-top:0">Add a folder that holds one sub-folder (or ZIP) per provider and each becomes its own return (R01, R02, …). A folder of loose files, or a single file, is one return. You can rename, regroup or leave out any return on the <a href="#/c/${enc(S.slug)}/returns">Returns</a> screen.</p>
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
    ${rows ? `<div class="tblwrap"><table class="t"><thead><tr><th>File / return</th><th>Name</th><th>Kind</th><th class="num">Size</th><th>Status</th><th class="num">Records</th><th>Timezone</th><th>Notes</th></tr></thead><tbody>${rows}</tbody></table></div>`
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
    ${f.sql ? `<h3>Reproduce</h3><pre class="sql">${esc(f.sql)}</pre><p class="small muted">Read-only SQL against case.db (any SQLite browser can run it).</p>` : (f.sql_failure ? `<div class="alertbox"><b>Reproduce query unavailable:</b> ${esc(f.sql_failure)}. Check this finding against its cited records by hand.</div>` : "")}
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
const REPORT_NAMES = { "REPORT.md": "Analysis", "CROSSREF.md": "Cross-return", "REPORT-FULL.md": "Full detail", "FIGURES.md": "Figures", "REVIEW.md": "Review checklist", "FINDINGS.md": "Findings", "EVIDENCE.md": "Evidence",
  "SOURCES.md": "Sources", "TIMELINE.md": "Timeline", "METHODS.md": "Methods", "CITATION_CHECK.md": "Citation check" };
function fixReportLinks(box, fname) {
  const base = fname.includes("/") ? fname.slice(0, fname.lastIndexOf("/") + 1) : "";
  $$("img", box).forEach((im) => {
    const src = im.getAttribute("src");
    if (src && !/^(https?:|\/)/.test(src)) im.src = `/case/${enc(S.slug)}/file/${base}${src}`;
    if (src && /^figures\/FIG\d+[\w-]*\.svg$/.test(src)) inlineFigure(im);
  });
  $$("a", box).forEach((a) => {
    const h = a.getAttribute("href") || "";
    if (/^https?:/.test(h)) { a.target = "_blank"; a.rel = "noopener"; return; }
    if (h.startsWith("#")) { a.dataset.anchor = h.slice(1); return; }
    const m = h.match(/^([^#]*\.md)(#.*)?$/);
    if (m) { a.setAttribute("href", `#/c/${enc(S.slug)}/reports/${base}${m[1]}${m[2] ? "#" + m[2].slice(1) : ""}`); return; }
    if (h && !h.startsWith("#")) a.setAttribute("href", `/case/${enc(S.slug)}/file/${base}${h}`);
  });
}
async function viewReports(v) {
  const r = await api(`/api/case/${enc(S.slug)}/reports`);
  if (!r.files.length) { v.innerHTML = `<div class="empty">No report yet. It is written as soon as the analysis stage finishes.</div>`; return; }
  const file = S.param || "REPORT.md";
  v.innerHTML = `<div class="row" style="margin-bottom:10px"><button class="btn small" data-act="open-folder">Open the report folder</button>
      <button class="btn small" data-act="rewrite">Rewrite report</button><span class="small muted">Markdown files - open them in any editor or viewer.</span></div>
    <div class="tabs">${r.files.map((f) => `<a href="#/c/${enc(S.slug)}/reports/${esc(f.file)}" class="${f.file === file.split("#")[0] ? "on" : ""}">${esc(REPORT_NAMES[f.file] || f.file.replace(/\.md$/, ""))}</a>`).join("")}</div>
    <div id="rep" class="report"><p class="muted">Loading…</p></div>
    ${r.exports.length ? `<div class="panel" style="margin-top:16px"><h3>Exports (CSV, KML, GeoJSON)</h3>${r.exports.map((e) => `<a href="/case/${enc(S.slug)}/file/${esc(e)}">${esc(e.replace("exports/", ""))}</a>`).join(" &nbsp; ")}</div>` : ""}`;
  const [fname, anchor] = file.split("#");
  const rep = await api(`/api/case/${enc(S.slug)}/report?file=${enc(fname)}`);
  const box = $("#rep");
  box.innerHTML = rep.html;
  fixReportLinks(box, fname);
  if (anchor) { const t = document.getElementById(anchor); if (t) t.scrollIntoView(); }
}

/* Figures are shown inline so their markers can open the cited record. Only Spoor's own figure files are inlined,
   and only after removing anything active (scripts, foreign content, event handlers, links). */
async function inlineFigure(im) {
  try {
    const r = await fetch(im.src, { credentials: "same-origin" });
    if (!r.ok) return;
    const doc = new DOMParser().parseFromString(await r.text(), "image/svg+xml");
    const svg = doc.documentElement;
    if (!svg || svg.nodeName.toLowerCase() !== "svg" || doc.querySelector("parsererror")) return;
    svg.querySelectorAll("script, foreignObject, iframe, image, a, use").forEach((n) => n.remove());
    svg.querySelectorAll("*").forEach((n) => [...n.attributes].forEach((a) => {
      if (/^on/i.test(a.name) || /href$/i.test(a.name)) n.removeAttribute(a.name);
    }));
    svg.classList.add("figure");
    svg.removeAttribute("width");
    svg.removeAttribute("height");
    const node = document.importNode(svg, true);
    node.setAttribute("tabindex", "0");
    im.replaceWith(node);
  } catch (e) { /* keep the plain image */ }
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
    <div class="mapgrid" style="grid-template-columns: 260px 160px 1fr">${Object.keys(st.params_default).filter((k) => !Array.isArray(st.params_default[k])).map((k) => {
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
  if (cite) { e.preventDefault(); openCite(cite.dataset.cite || cite.getAttribute("data-cite") || cite.textContent.trim()); return; }
  const fnd = e.target.closest("svg.figure [data-finding]");
  if (fnd) { location.hash = `#/c/${enc(S.slug)}/findings/${enc(fnd.getAttribute("data-finding"))}`; return; }
  const go = e.target.closest("[data-go]");
  if (go) { location.hash = go.dataset.go; return; }
  const fs = e.target.closest("[data-fs]");
  if (fs) { openBrowser(fs.dataset.fs); return; }
  const pick = e.target.closest("[data-pick]");
  if (pick) { const i = $("#src-path"); if (i) i.value = pick.dataset.pick; closeLayer(); return; }
  const anc = e.target.closest("a[data-anchor]");
  if (anc) { e.preventDefault(); const t = document.getElementById(anc.dataset.anchor); if (t) t.scrollIntoView({ behavior: "smooth" }); return; }
  const ra = e.target.closest("[data-ract]");
  if (ra) { try { await returnAction(ra); } catch (err) { toast(err.message, true); } return; }
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
document.addEventListener("change", async (e) => {
  const m = e.target.closest("select[data-move]");
  if (m) { try { await moveSource(m); } catch (err) { toast(err.message, true); } }
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeLayer();
  if (e.key === "Enter" && e.target && e.target.id === "lk-q") doLookup(false);
  if (e.key === "Enter" && e.target && e.target.id === "ff-q") { S.fl = { q: e.target.value.trim(), category: $("#ff-cat").value, priority: $("#ff-pr").value }; renderCase(); }
});

async function viewCrossref(v) {
  const r = await api(`/api/case/${enc(S.slug)}/reports`);
  if (!r.files.some((f) => f.file === "CROSSREF.md")) {
    v.innerHTML = `<div class="empty">No cross-return page yet. It is written when two or more returns are included and the analysis has run. ${S.c && S.c.counts && S.c.counts.returns > 1 ? "Run the analysis to produce it." : "Add another return in Files to compare."}</div>`;
    return;
  }
  const rep = await api(`/api/case/${enc(S.slug)}/report?file=CROSSREF.md`);
  v.innerHTML = `<div class="row" style="margin-bottom:10px"><span class="small muted">Only what the returns have in common. Checks that found nothing are in the analysis, Appendix A. Exclude a return in Returns and run again to re-compare.</span></div><div class="report" id="xrep">${rep.html}</div>`;
  fixReportLinks($("#xrep"), "CROSSREF.md");
}

const SVGNS = "http://www.w3.org/2000/svg";
const MAP_COLORS = ["#0072b2", "#e69f00", "#009e73", "#d55e00", "#cc79a7", "#56b4e9", "#b3a000", "#444444"];
function mapSvg(d, W, H) {
  const pts = [];
  d.sites.forEach((s) => pts.push([s.lat, s.lon]));
  d.targets.forEach((t) => t.points.forEach((p) => pts.push([p[0], p[1]])));
  d.estimates.forEach((p) => pts.push([p[0], p[1]]));
  let la0 = Math.min(...pts.map((p) => p[0])), la1 = Math.max(...pts.map((p) => p[0]));
  let lo0 = Math.min(...pts.map((p) => p[1])), lo1 = Math.max(...pts.map((p) => p[1]));
  const kx = Math.cos(((la0 + la1) / 2) * Math.PI / 180);
  let w = Math.max((lo1 - lo0) * kx, 0.004), h = Math.max(la1 - la0, 0.004);
  const pad = 36, sc = Math.min((W - 2 * pad) / w, (H - 2 * pad) / h);
  const cx = (lo0 + lo1) / 2, cy = (la0 + la1) / 2;
  const X = (lo) => W / 2 + (lo - cx) * kx * sc, Y = (la) => H / 2 - (la - cy) * sc;
  const kmPerDeg = 111.32, pxPerKm = sc / kmPerDeg;
  let km = [0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500].find((k) => k * pxPerKm >= 70) || 500;
  const o = [`<svg xmlns="${SVGNS}" viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Cell sites and records, no basemap" style="background:var(--sheet);border:1px solid var(--rule);border-radius:6px">`];
  o.push(`<rect x="${pad / 2}" y="${pad / 2}" width="${W - pad}" height="${H - pad}" fill="none" stroke="#bbb" stroke-dasharray="3 4"/>`);
  d.sites.forEach((s) => {
    const sx = X(s.lon), sy = Y(s.lat), seen = {};
    s.cells.forEach((c) => {
      if (c.az == null || seen[c.az + "/" + c.bw]) return; seen[c.az + "/" + c.bw] = 1;
      const L = Math.max(14, Math.min(46, pxPerKm * 1.0)), a0 = (c.az - (c.bw || 60) / 2) * Math.PI / 180, a1 = (c.az + (c.bw || 60) / 2) * Math.PI / 180;
      const p0 = [sx + L * Math.sin(a0), sy - L * Math.cos(a0)], p1 = [sx + L * Math.sin(a1), sy - L * Math.cos(a1)];
      o.push(`<path d="M${sx},${sy} L${p0[0]},${p0[1]} A${L},${L} 0 0 1 ${p1[0]},${p1[1]} Z" fill="#888" fill-opacity=".18" stroke="#777" stroke-width=".7"><title>${esc(c.cell)} azimuth ${c.az} (wedge length is a drawing aid)</title></path>`);
    });
    o.push(`<rect x="${sx - 4}" y="${sy - 4}" width="8" height="8" fill="#333"><title>${esc((s.name || s.cells[0].cell) + " - " + s.n + " record(s) - " + s.cells.map((c) => c.cell).join(", "))}</title></rect>`);
  });
  d.targets.forEach((t, i) => {
    const col = MAP_COLORS[i % MAP_COLORS.length];
    t.points.forEach((p) => o.push(`<circle cx="${X(p[1]).toFixed(1)}" cy="${Y(p[0]).toFixed(1)}" r="3" fill="${col}" fill-opacity=".55"><title>${esc(t.target + " " + (p[2] || "") + " UTC, cell " + (p[3] || "?") + (p[4] ? ", " + p[4] : "") + " " + (p[5] || ""))}</title></circle>`));
  });
  d.estimates.forEach((p) => o.push(`<path d="M${X(p[1]) - 4},${Y(p[0]) - 4} l8,8 m0,-8 l-8,8" stroke="#c0392b" stroke-width="1.6"><title>${esc("device estimate " + (p[2] || "") + " UTC " + (p[3] || "") + " " + (p[5] || "") + " " + (p[6] || ""))}</title></path>`));
  const bx = pad, by = H - pad / 2 - 6, bl = km * pxPerKm;
  o.push(`<g font-size="12" fill="#333"><line x1="${bx}" y1="${by}" x2="${bx + bl}" y2="${by}" stroke="#333" stroke-width="2"/><text x="${bx}" y="${by - 6}">${km} km</text>`);
  o.push(`<text x="${W - pad}" y="${pad - 10}" text-anchor="end">N &#8593;</text></g></svg>`);
  return o.join("");
}
async function viewMap(v) {
  const d = await api(`/api/case/${enc(S.slug)}/map`);
  const st = d.status;
  if (!st.telecom) { v.innerHTML = `<div class="empty">${esc(st.reason || "No telecom records in this case.")}</div>`; return; }
  if (!st.map) {
    v.innerHTML = `<div class="alertbox">No map can be drawn. ${esc(st.reason)}</div><p class="small muted">Nothing is guessed: records without coordinates are left off the map. The records themselves are in the Findings and in exports/telecom_records.csv.</p>`;
    return;
  }
  const names = d.targets.map((t, i) => `<span class="small" style="margin-right:14px"><span style="display:inline-block;width:10px;height:10px;border-radius:5px;background:${MAP_COLORS[i % MAP_COLORS.length]};margin-right:5px"></span>${esc(t.target)} (${t.records.toLocaleString()} record${t.records === 1 ? "" : "s"}${t.drawn < t.records ? `, ${t.drawn} shown` : ""})</span>`).join("");
  v.innerHTML = `<div class="small muted" style="margin-bottom:8px">Each dot is the <b>cell site that served a record</b>, not the phone's position. Squares are cell sites; grey wedges are sector directions (length is a drawing aid, not coverage); red crosses are carrier position estimates for the device. No basemap is drawn (nothing leaves this computer). ${st.reason ? esc(st.reason) + " " : ""}${d.kml ? `For streets and satellite imagery open the KML in Google Earth Pro: <a href="/case/${enc(S.slug)}/file/exports/telecom.kml">telecom.kml</a> &middot; <a href="/case/${enc(S.slug)}/file/exports/telecom.geojson">telecom.geojson</a> (QGIS/ArcGIS).` : ""}</div>
    <div style="margin-bottom:8px">${names}</div>${mapSvg(d, 1100, 640)}
    <div class="small muted" style="margin-top:6px">${d.sites.length} cell site${d.sites.length === 1 ? "" : "s"} used; ${st.located.toLocaleString()} of ${st.records.toLocaleString()} telecom records located. Hover a point for its time, cell, return and citation.</div>`;
}

/* ------------------------------------------------------------------ links (contact chains) */
const LK = { slug: null, sel: [], extra: "", hops: null, slack: 0, devices: false, res: null, focus: null };
async function viewLinks(v) {
  const ch = await api(`/api/case/${enc(S.slug)}/links`);
  if (!ch.telecom) { v.innerHTML = `<div class="empty">No telecom records in this case. Links work on call-detail records and tower dumps.</div>`; return; }
  if (LK.slug !== S.slug) Object.assign(LK, { slug: S.slug, sel: [], extra: "", hops: ch.max_hops || 6, slack: 0, devices: false, res: null, focus: null });
  const box = (id, label, sub) => `<label class="lkopt"><input type="checkbox" data-lk="${esc(id)}" ${LK.sel.includes(id) ? "checked" : ""}> <span class="mono">${esc(label)}</span> <span class="small muted">${esc(sub)}</span></label>`;
  v.innerHTML = `<div class="lkgrid"><div class="panel lkside">
      <h3>Link these</h3>
      <div class="small muted" style="margin-bottom:6px">Pick two or more. Every pair is searched.</div>
      <div class="lkhead small">Targets (their records are in the case)</div>
      ${ch.targets.map((t) => box(t.id, t.id, `${fmt(t.contacts)} contacts`)).join("")}
      ${ch.dumps.length ? `<div class="lkhead small">Tower dumps</div>` + ch.dumps.map((d) => box(d.id, d.label, `${fmt(d.phones)} phones`)).join("") : ""}
      <div class="field" style="margin-top:8px"><label for="lk-extra">Other numbers (any format, comma separated)</label><input id="lk-extra" type="text" value="${esc(LK.extra)}" placeholder="e.g. 571-555-0160"></div>
      <div class="row" style="gap:10px;margin-top:6px">
        <div class="field"><label for="lk-hops">Longest chain</label><select id="lk-hops">${[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((n) => `<option ${n === LK.hops ? "selected" : ""}>${n}</option>`).join("")}</select></div>
        <div class="field"><label for="lk-slack">Also longer by</label><select id="lk-slack">${[0, 1, 2].map((n) => `<option ${n === LK.slack ? "selected" : ""}>${n}</option>`).join("")}</select></div>
      </div>
      <label class="lkopt"><input type="checkbox" id="lk-dev" ${LK.devices ? "checked" : ""}> same handset (IMEI) counts as a link</label>
      <div class="row" style="margin-top:10px"><button class="btn go" data-act="lk-run">Find chains</button></div>
      <div class="lkhead small" style="margin-top:14px">Saved groups (reported on every run)</div>
      ${(ch.sets || []).map((g, i) => `<div class="small lkset"><a href="#" data-lkload="${i}">${esc(g.name)}</a> <span class="muted">${esc(g.members.length)} members</span> <a href="#" class="muted" data-lkdel="${esc(g.name)}">delete</a></div>`).join("") || `<div class="small muted">None yet.</div>`}
      <div class="row" style="margin-top:6px"><input id="lk-name" type="text" size="14" placeholder="group name"><button class="btn small" data-act="lk-save">Save selection</button></div>
      <p class="small muted" style="margin-top:12px">A hop is a call or text between two numbers in the records. Short codes and numbers in contact with more than ${esc(ch.hub_max)} others are not used as links; a tower dump is only an endpoint. A chain shows contact, not that anything passed along it.</p>
    </div><div id="lk-out">${LK.res ? "" : `<div class="empty">Choose numbers on the left and press <b>Find chains</b>.</div>`}</div></div>`;
  v._ch = ch;
  if (LK.res) drawLinks();
}
function lkSeeds() {
  const extra = ($("#lk-extra") ? $("#lk-extra").value : LK.extra).split(/[,;\n]+/).map((x) => x.trim()).filter(Boolean);
  return [...LK.sel, ...extra];
}
async function lkRun() {
  LK.extra = $("#lk-extra").value; LK.hops = +$("#lk-hops").value; LK.slack = +$("#lk-slack").value; LK.devices = $("#lk-dev").checked;
  const seeds = lkSeeds();
  if (seeds.length < 2) { toast("Choose at least two.", true); return; }
  $("#lk-out").innerHTML = `<p class="muted">Searching…</p>`;
  try {
    LK.res = await api(`/api/case/${enc(S.slug)}/links`, { body: { seeds, max_hops: LK.hops, slack: LK.slack, devices: LK.devices } });
    LK.focus = null;
    drawLinks();
  } catch (e) { $("#lk-out").innerHTML = `<div class="alertbox">${esc(e.message)}</div>`; }
}
function lkLayout(r, W, H) {
  const pos = {}, seeds = r.seeds, n = seeds.length, cx = W / 2, cy = H / 2 - 20, R = Math.min(W, H - 60) * 0.42;
  seeds.forEach((s, i) => { const a = -Math.PI / 2 + (2 * Math.PI * i) / n; pos[s] = [cx + R * Math.cos(a), cy + R * Math.sin(a)]; });
  if (n === 2) { pos[seeds[0]] = [W * 0.1, cy - 20]; pos[seeds[1]] = [W * 0.9, cy - 20]; }
  // start every other node on the straight line between the ends of the first chain it is on, at its place along it
  const placed = new Set(seeds);
  r.pairs.forEach((pr) => pr.paths.forEach((p, k) => p.forEach((id, i) => {
    if (placed.has(id)) return;
    const A = pos[pr.a], B = pos[pr.b], t = i / (p.length - 1), off = ((k % 5) - 2) * 26;
    const dx = B[0] - A[0], dy = B[1] - A[1], L = Math.hypot(dx, dy) || 1;
    pos[id] = [A[0] + dx * t - (dy / L) * off, A[1] + dy * t + (dx / L) * off]; placed.add(id);
  })));
  r.nodes.forEach((nd, i) => { if (!pos[nd.id]) pos[nd.id] = [cx + 30 * Math.cos(i), cy + 30 * Math.sin(i)]; });
  // a few rounds of spring layout (deterministic: no random numbers), chosen numbers stay put
  const ids = r.nodes.map((x) => x.id), k = Math.sqrt((W * H) / Math.max(4, ids.length)) * 0.55;
  for (let it = 0; it < 220; it++) {
    const d = {}; ids.forEach((a) => (d[a] = [0, 0]));
    for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) {
      const a = ids[i], b = ids[j], dx = pos[a][0] - pos[b][0], dy = pos[a][1] - pos[b][1], dist = Math.max(8, Math.hypot(dx, dy)), f = (k * k) / dist;
      d[a][0] += (dx / dist) * f; d[a][1] += (dy / dist) * f; d[b][0] -= (dx / dist) * f; d[b][1] -= (dy / dist) * f;
    }
    r.edges.forEach((e) => {
      const dx = pos[e.a][0] - pos[e.b][0], dy = pos[e.a][1] - pos[e.b][1], dist = Math.max(8, Math.hypot(dx, dy)), f = (dist * dist) / k;
      d[e.a][0] -= (dx / dist) * f; d[e.a][1] -= (dy / dist) * f; d[e.b][0] += (dx / dist) * f; d[e.b][1] += (dy / dist) * f;
    });
    const temp = 40 * (1 - it / 220) + 1;
    ids.forEach((a) => {
      if (seeds.includes(a)) return;
      const L = Math.hypot(d[a][0], d[a][1]) || 1;
      pos[a][0] = Math.min(W - 40, Math.max(40, pos[a][0] + (d[a][0] / L) * Math.min(L, temp)));
      pos[a][1] = Math.min(H - 64, Math.max(30, pos[a][1] + (d[a][1] / L) * Math.min(L, temp)));
    });
  }
  return pos;
}
function lkSvg(r, W, H) {
  const pos = lkLayout(r, W, H), nd = Object.fromEntries(r.nodes.map((x) => [x.id, x]));
  const on = new Set(), onE = new Set();
  if (LK.focus) r.pairs.forEach((pr) => pr.paths.forEach((p) => { if (p.includes(LK.focus)) { p.forEach((x) => on.add(x)); p.slice(1).forEach((x, i) => onE.add([p[i], x].sort().join("|"))); } }));
  const dim = (yes) => (LK.focus && !yes ? ' opacity=".18"' : "");
  const o = [`<svg id="lk-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Contact chains" style="background:#fff;border:1px solid var(--rule);border-radius:6px;font-family:system-ui,sans-serif">`];
  r.edges.forEach((e) => {
    const [x1, y1] = pos[e.a], [x2, y2] = pos[e.b], w = 1 + Math.min(5, Math.log2(e.records)), key = [e.a, e.b].sort().join("|");
    const dash = e.via.includes("cdr") ? "" : ' stroke-dasharray="5 4"';
    o.push(`<g${dim(onE.has(key))}><line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="#6b7a73" stroke-width="${w}"${dash}><title>${esc(`${e.a} - ${e.b}: ${e.records} record(s) (${e.calls} calls, ${e.texts} texts) ${e.first_utc || ""} to ${e.last_utc || ""} UTC; ${e.returns.join(", ")}; ${e.first_cite || ""}${e.last_cite && e.last_cite !== e.first_cite ? " .. " + e.last_cite : ""}`)}</title></line>`
      + `<text x="${(x1 + x2) / 2}" y="${(y1 + y2) / 2 - 4}" font-size="13" text-anchor="middle" fill="#405048" paint-order="stroke" stroke="#fff" stroke-width="3">${e.records}</text></g>`);
  });
  r.nodes.forEach((n) => {
    const [x, y] = pos[n.id], lab = n.kind === "dump" ? n.label : n.id;
    let shape;
    if (n.kind === "dump") shape = `<rect x="${x - 11}" y="${y - 11}" width="22" height="22" fill="#8a8f8c" stroke="#333"/>`;
    else if (n.kind === "handset") shape = `<path d="M${x},${y - 11} l11,11 l-11,11 l-11,-11 z" fill="#cdb46a" stroke="#333"/>`;
    else shape = `<circle cx="${x}" cy="${y}" r="${n.chosen ? 12 : n.returned ? 9 : 6}" fill="${n.chosen ? "#2f6b55" : n.returned ? "#24343a" : "#fff"}" stroke="${n.chosen ? "#c0392b" : "#24343a"}" stroke-width="${n.chosen ? 3 : 1.5}"/>`;
    o.push(`<g class="lknode" data-lknode="${esc(n.id)}" style="cursor:pointer"${dim(on.has(n.id))}>${shape}<title>${esc(`${n.label} - ${n.kind}${n.returned ? " (records returned)" : ""}, ${n.degree} different contacts`)}</title>`
      + `<text x="${x}" y="${y + (n.chosen ? 28 : 21)}" font-size="${n.chosen ? 16 : 13}" font-weight="${n.chosen ? 700 : 400}" text-anchor="middle" fill="#1d2a26" paint-order="stroke" stroke="#fff" stroke-width="3">${esc(lab.length > 34 ? lab.slice(0, 33) + "…" : lab)}</text></g>`);
  });
  o.push(`<g font-size="13" fill="#405048"><text x="12" y="${H - 14}">● chosen  ● number with records returned  ○ contact  ■ tower dump${r.edges.some((e) => e.via.includes("handset")) ? "  ◆ handset" : ""} · line number = records · dashed = seen only in a dump / handset · click a number to show its chains</text></g></svg>`);
  return o.join("");
}
function drawLinks() {
  const r = LK.res, out = $("#lk-out");
  if (!out) return;
  const E = {}; r.edges.forEach((e) => (E[[e.a, e.b].sort().join("|")] = e));
  const hop = (a, b) => E[[a, b].sort().join("|")];
  const lab = (id) => { const n = r.nodes.find((x) => x.id === id); return n ? n.label : id; };
  const pairRows = r.pairs.map((pr) => `<tr><td class="mono">${esc(lab(pr.a))}</td><td class="mono">${esc(lab(pr.b))}</td><td>${pr.hops == null ? `<span class="muted">not linked within ${r.max_hops}</span>` : pr.hops}</td><td>${pr.paths.length}${pr.more ? "+" : ""}</td></tr>`).join("");
  const keep = (p) => !LK.focus || p.includes(LK.focus);
  const chains = r.pairs.filter((pr) => pr.paths.some(keep)).map((pr) => `<h4 class="mono" style="margin:14px 0 4px">${esc(lab(pr.a))} ↔ ${esc(lab(pr.b))}: ${pr.hops} hop${pr.hops === 1 ? "" : "s"}${pr.more ? " (first " + pr.paths.length + " chains)" : ""}</h4>`
    + pr.paths.filter(keep).map((p) => `<div class="lkchain">${p.map((id, i) => {
      const node = `<a href="#" class="mono" data-lkfocus="${esc(id)}">${esc(lab(id))}</a>`;
      if (!i) return node;
      const e = hop(p[i - 1], id);
      return ` <span class="lkhop">—${e.records}${e.returns.length ? " · " + esc(e.returns.join(",")) : ""} <code class="cite" data-cite="${esc(e.first_cite)}">${esc(e.first_cite)}</code>${e.last_cite && e.last_cite !== e.first_cite ? ` <code class="cite" data-cite="${esc(e.last_cite)}">${esc(e.last_cite)}</code>` : ""}—</span> ${node}`;
    }).join("")}</div>`).join("")).join("");
  const thr = r.through.slice(0, 15).map((t) => `<tr><td class="mono"><a href="#" data-lkfocus="${esc(t.node)}">${esc(lab(t.node))}</a></td><td>${t.pairs.length}</td><td>${t.paths}</td></tr>`).join("");
  out.innerHTML = `${r.missing && r.missing.length ? `<div class="alertbox">Not in the records: ${esc(r.missing.join(", "))}</div>` : ""}
    <div class="row" style="margin-bottom:6px"><span class="small muted">${LK.focus ? `Showing chains through <b>${esc(lab(LK.focus))}</b> - <a href="#" data-lkfocus="">show all</a>` : "Click a number to show only its chains."}</span>
      <span style="flex:1"></span><button class="btn small" data-act="lk-svg">Download picture (SVG)</button><button class="btn small" data-act="lk-csv">Download chains (CSV)</button></div>
    ${r.edges.length ? lkSvg(r, 1100, Math.max(520, 140 + 26 * r.nodes.length > 760 ? 760 : 140 + 26 * r.nodes.length)) : ""}
    <div class="lkcols"><div class="panel"><h3>Pairs</h3><table class="t"><tr><th>from</th><th>to</th><th>hops</th><th>chains</th></tr>${pairRows}</table></div>
    ${thr ? `<div class="panel"><h3>Numbers on the most chains</h3><table class="t"><tr><th>number</th><th>pairs linked</th><th>chains</th></tr>${thr}</table></div>` : ""}</div>
    <div class="panel"><h3>Chains, hop by hop</h3><div class="small muted">Each hop: records between the two numbers · returns · first and last record (click to open it).</div>${chains || `<p class="muted">No chain within ${r.max_hops} hops.</p>`}</div>
    ${r.left_out.length ? `<div class="small muted" style="margin-top:8px">Not used as links: ${esc(r.left_out.slice(0, 20).map((x) => `${x.node} (${x.reason})`).join("; "))}</div>` : ""}`;
}
function lkCsv() {
  const r = LK.res, E = {}; r.edges.forEach((e) => (E[[e.a, e.b].sort().join("|")] = e));
  const L = [["from_end", "to_end", "pair_hops", "chain", "hop", "number_a", "number_b", "records", "calls", "texts", "first_utc", "last_utc", "returns", "first_cite", "last_cite"]];
  r.pairs.forEach((pr) => pr.paths.forEach((p, k) => p.slice(1).forEach((b, i) => {
    const e = E[[p[i], b].sort().join("|")];
    L.push([pr.a, pr.b, pr.hops, k + 1, i + 1, p[i], b, e.records, e.calls, e.texts, e.first_utc, e.last_utc, e.returns.join(" "), e.first_cite, e.last_cite]);
  })));
  return L.map((row) => row.map((x) => { const s = x == null ? "" : String(x); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; }).join(",")).join("\n") + "\n";
}
function lkDownload(name, text, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}
document.addEventListener("change", (e) => {
  const c = e.target.closest("input[data-lk]");
  if (!c) return;
  const id = c.dataset.lk;
  LK.sel = c.checked ? [...LK.sel.filter((x) => x !== id), id] : LK.sel.filter((x) => x !== id);
});
document.addEventListener("click", async (e) => {
  const t = e.target.closest("[data-act^='lk-'], [data-lkfocus], [data-lknode], [data-lkload], [data-lkdel]");
  if (!t) return;
  e.preventDefault();
  if (t.dataset.lkfocus !== undefined || t.dataset.lknode !== undefined) { const id = t.dataset.lkfocus ?? t.dataset.lknode; LK.focus = id && LK.focus !== id ? id : null; drawLinks(); return; }
  if (t.dataset.lkload !== undefined) {
    const g = ($("#view")._ch || {}).sets[+t.dataset.lkload];
    const known = new Set([...(($("#view")._ch || {}).targets || []).map((x) => x.id), ...(($("#view")._ch || {}).dumps || []).map((x) => x.id)]);
    LK.sel = g.members.filter((m) => known.has(m)); LK.extra = g.members.filter((m) => !known.has(m)).join(", ");
    LK.hops = g.max_hops || LK.hops; LK.slack = g.slack || 0; LK.res = null;
    await viewLinks($("#view")); lkRun(); return;
  }
  if (t.dataset.lkdel !== undefined) { await api(`/api/case/${enc(S.slug)}/links/save`, { body: { name: t.dataset.lkdel, delete: true } }); toast("Group deleted."); viewLinks($("#view")); return; }
  const act = t.dataset.act;
  if (act === "lk-run") lkRun();
  else if (act === "lk-svg") lkDownload("contact-chains.svg", $("#lk-svg").outerHTML, "image/svg+xml");
  else if (act === "lk-csv") lkDownload("contact-chains.csv", lkCsv(), "text/csv");
  else if (act === "lk-save") {
    const name = $("#lk-name").value.trim(), members = lkSeeds();
    if (!name) { toast("Give the group a name.", true); return; }
    try { await api(`/api/case/${enc(S.slug)}/links/save`, { body: { name, members, max_hops: +$("#lk-hops").value, slack: +$("#lk-slack").value } }); toast("Saved - it will be in the report after the next run."); viewLinks($("#view")); }
    catch (err) { toast(err.message, true); }
  }
});

route();
