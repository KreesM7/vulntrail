"use strict";
const $ = id => document.getElementById(id);
const state = {runs: [], run: null, offset: 0, total: 0, limit: 10, findingPage: 0, busy: false};
function element(tag, value, className) {
  const node = document.createElement(tag);
  if (value !== undefined) node.textContent = String(value);
  if (className) node.className = className;
  return node;
}
function date(value) { const parsed = new Date(value); return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString(); }
function notify(message) { $("notice").textContent = message; }
function clearError() { $("error").hidden = true; $("error").textContent = ""; }
function fail(error) {
  $("error").textContent = error.message || "The local operation could not complete.";
  $("error").hidden = false; $("error").focus();
}
async function api(path, options = {}) {
  const response = await fetch(path, {...options, credentials: "same-origin", headers: {
    "X-VulnTrail-Client": "dashboard", ...options.headers
  }});
  if (!response.ok) {
    let message = "The local request failed.";
    try { message = (await response.json()).error.message; } catch (_) {}
    if (response.status === 401) signedOut();
    const error = new Error(message); error.status = response.status; throw error;
  }
  return response;
}
async function json(path, options) { return (await api(path, options)).json(); }
function signedOut() { $("workspace").hidden = true; $("login-panel").hidden = false; $("logout").hidden = true; state.run = null; }
function signedIn() { $("workspace").hidden = false; $("login-panel").hidden = true; $("logout").hidden = false; }
function setBusy(busy) {
  state.busy = busy; $("scan").disabled = busy || !$("target").value;
  $("scan").textContent = busy ? "Scanning…" : "Run scan";
  $("target").disabled = busy; $("refresh").disabled = busy;
}
async function status() {
  const result = await json("/ui/api/status");
  const selected = $("target").value;
  $("target").replaceChildren();
  for (const name of result.targets) { const option = element("option", name); option.value = name; $("target").append(option); }
  if (result.targets.includes(selected)) $("target").value = selected;
  $("mode").textContent = result.offline ? "Backend offline mode" : "Backend online mode";
  $("scan-help").textContent = result.targets.length ? "Each scan creates a new run. Backend coverage may be incomplete." : "No targets configured. Add a local target in your configuration file.";
  setBusy(result.running); return result;
}
async function history(selectId) {
  $("history-loading").hidden = false; $("runs").setAttribute("aria-busy", "true");
  try {
    const result = await json(`/ui/api/runs?limit=${state.limit}&offset=${state.offset}`);
    state.runs = result.items; state.total = result.total;
    $("run-total").textContent = `${result.total} stored`;
    $("runs").replaceChildren();
    if (!result.items.length) $("runs").append(element("p", state.total ? "No runs on this page. Return to the previous page." : "No evidence yet. Run a configured target or import a supported report with the CLI.", "empty"));
    for (const run of result.items) {
      const button = element("button", undefined, "run-item");
      button.dataset.runId = run.id;
      button.setAttribute("aria-current", String(state.run?.id === run.id));
      button.append(element("strong", run.target), element("small", date(run.started_at)));
      const bottom = element("span", undefined, "run-bottom");
      bottom.append(element("span", `${run.finding_count} findings`), element("span", `${run.backend} · ${run.status}`));
      button.append(bottom); button.addEventListener("click", () => loadRun(run.id).catch(fail)); $("runs").append(button);
    }
    $("previous").disabled = state.offset === 0;
    $("next").disabled = state.offset + state.limit >= state.total;
    $("page-label").textContent = state.total ? `${state.offset + 1}–${Math.min(state.offset + state.limit, state.total)} of ${state.total}` : "0 runs";
    compareOptions();
    if (selectId) await loadRun(selectId);
  } finally { $("history-loading").hidden = true; $("runs").removeAttribute("aria-busy"); }
}
function field(container, label, value) { container.append(element("dt", label), element("dd", value)); }
async function loadRun(id) {
  clearError(); notify("Loading run details…");
  const run = await json(`/ui/api/runs/${encodeURIComponent(id)}`);
  state.run = run; state.findingPage = 0;
  $("detail-empty").hidden = true; $("detail").hidden = false;
  $("run-title").textContent = run.target; $("run-id").textContent = run.id;
  $("run-status").textContent = `${run.backend} / ${run.status}`;
  $("metadata").replaceChildren();
  field($("metadata"), "Started", date(run.started_at));
  field($("metadata"), "Completed", date(run.completed_at));
  field($("metadata"), "Database updated", run.data_updated_at ? date(run.data_updated_at) : "Unknown — scan time is not database age");
  field($("metadata"), "Backend version", run.backend_version || "Not recorded");
  field($("metadata"), "Coverage", run.coverage.length ? run.coverage.join(" · ") : "No supported coverage recorded");
  field($("metadata"), "Source digest", run.source_digest || "Not recorded");
  if (run.enrichment?.length) field($("metadata"), "Enrichment", run.enrichment.map(item => `${item.source || "Local feed"} · ${item.source_date || "date unknown"}`).join("; "));
  $("warnings").replaceChildren();
  for (const warning of run.warnings) $("warnings").append(element("p", warning));
  $("warnings").hidden = !run.warnings.length;
  $("search").value = ""; $("severity").value = ""; $("comparison-output").replaceChildren();
  for (const button of $("runs").querySelectorAll("button")) button.setAttribute("aria-current", String(button.dataset.runId === id));
  compareOptions(); findings(); notify(`Loaded ${run.findings.length} findings from ${run.status} run.`);
}
function findings() {
  if (!state.run) return;
  const query = $("search").value.trim().toLowerCase(); const severity = $("severity").value;
  const filtered = state.run.findings.filter(f => (!severity || f.severity === severity) && (!query || [f.package, f.vulnerability_id, f.location, f.ecosystem].join(" ").toLowerCase().includes(query)));
  const pages = Math.max(1, Math.ceil(filtered.length / 50)); state.findingPage = Math.min(state.findingPage, pages - 1);
  $("findings").replaceChildren();
  for (const finding of filtered.slice(state.findingPage * 50, (state.findingPage + 1) * 50)) {
    const row = element("tr"); const severityCell = element("td");
    severityCell.append(element("span", finding.priority, "priority"), element("span", finding.severity, `badge ${finding.severity}`));
    const idCell = element("td"); const button = element("button", finding.vulnerability_id);
    button.addEventListener("click", () => showFinding(finding)); idCell.append(button);
    const packageCell = element("td", finding.package); packageCell.append(element("div", finding.ecosystem, "muted"));
    row.append(severityCell, idCell, packageCell, element("td", `${finding.version || "unknown"} → ${finding.fixed_version || "not supplied"}`));
    $("findings").append(row);
  }
  if (!filtered.length) { const cell = element("td", state.run.findings.length ? "No findings match these filters." : "No findings were observed. Review this run’s status and coverage before drawing conclusions."); cell.colSpan = 4; const row = element("tr"); row.append(cell); $("findings").append(row); }
  $("finding-count").textContent = `${filtered.length} of ${state.run.findings.length} findings`;
  $("finding-page").textContent = `${state.findingPage + 1} / ${pages}`;
  $("finding-previous").disabled = !state.findingPage;
  $("finding-next").disabled = state.findingPage >= pages - 1;
}
function showFinding(finding) {
  $("finding-title").textContent = finding.vulnerability_id; $("finding-detail").replaceChildren();
  for (const [label, value] of [["Package", finding.package], ["Ecosystem", finding.ecosystem], ["Installed", finding.version || "Unknown"], ["Fixed version", finding.fixed_version || "Not supplied"], ["Severity", finding.severity], ["Priority", finding.priority], ["Location", finding.location || "Not supplied"], ["Source", finding.source], ["Known exploited", finding.kev ? "Listed in supplied KEV feed" : "Not marked by supplied data"], ["EPSS", finding.epss === null ? "Not supplied" : `${(finding.epss * 100).toFixed(2)}%`]]) field($("finding-detail"), label, value);
  $("finding-description").textContent = finding.description || "No description supplied by the backend.";
  $("finding-references").replaceChildren();
  for (const url of finding.urls) { if (!/^https?:\/\//i.test(url)) continue; const link = element("a", url); link.href = url; link.target = "_blank"; link.rel = "noopener noreferrer"; $("finding-references").append(link); }
  $("finding-dialog").showModal(); $("close-dialog").focus();
}
function compareOptions() {
  const selected = $("before").value; $("before").replaceChildren();
  for (const run of state.runs.filter(run => run.id !== state.run?.id)) { const option = element("option", `${run.target} · ${date(run.started_at)} · ${run.status}`); option.value = run.id; $("before").append(option); }
  if ([...$("before").options].some(option => option.value === selected)) $("before").value = selected;
  $("compare").disabled = !state.run || !$("before").value;
}
$("login-form").addEventListener("submit", async event => {
  event.preventDefault(); clearError(); const value = $("token").value; $("token").value = "";
  try { await json("/ui/session", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:value})}); signedIn(); await status(); await history(); notify("Connected to local evidence."); $("target").focus(); } catch(error) { fail(error); }
});
$("logout").addEventListener("click", async () => { try { await json("/ui/session", {method:"DELETE"}); signedOut(); notify("Signed out."); $("token").focus(); } catch(error) { fail(error); } });
$("refresh").addEventListener("click", async () => { clearError(); try { await status(); await history(); if(state.run) await loadRun(state.run.id); notify("Local evidence refreshed."); } catch(error) { fail(error); } });
$("scan").addEventListener("click", async () => {
  if (state.busy || !$("target").value) return; clearError(); setBusy(true); notify("Scanning configured target. Keep this window open; retrying creates another run.");
  try { const run = await json("/ui/api/scans", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target:$("target").value})}); state.offset = 0; await history(run.id); notify(`Scan recorded with status: ${run.status}.`); } catch(error) { fail(error); } finally { setBusy(false); }
});
$("previous").addEventListener("click", () => {state.offset = Math.max(0,state.offset-state.limit);history().catch(fail);});
$("next").addEventListener("click", () => {state.offset += state.limit;history().catch(fail);});
for(const id of ["search","severity"]) $(id).addEventListener(id === "search" ? "input" : "change", () => {state.findingPage = 0;findings();});
$("finding-previous").addEventListener("click", () => {state.findingPage--;findings();});
$("finding-next").addEventListener("click", () => {state.findingPage++;findings();});
$("close-dialog").addEventListener("click", () => $("finding-dialog").close());
for(const button of document.querySelectorAll(".export")) button.addEventListener("click", async () => {
  clearError(); if(!state.run) return;
  try { const response = await api(`/ui/api/runs/${encodeURIComponent(state.run.id)}/report?format=${button.dataset.format}`); const url = URL.createObjectURL(await response.blob()); const link = element("a"); link.href = url; link.download = `vulntrail-${state.run.id}.${button.dataset.format}`; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url),1000); notify("Evidence export downloaded."); } catch(error) { fail(error); }
});
$("delete").addEventListener("click", async () => {
  if(!state.run || !window.confirm(`Permanently delete local evidence run ${state.run.id}? Export it first if you need a copy.`)) return;
  clearError(); try { await json(`/ui/api/runs/${encodeURIComponent(state.run.id)}`, {method:"DELETE"}); state.run = null; $("detail").hidden = true; $("detail-empty").hidden = false; $("run-status").textContent = ""; state.offset = 0; await history(); notify("Local run evidence deleted."); } catch(error) { fail(error); }
});
$("compare").addEventListener("click", async () => {
  clearError(); if(!state.run || !$("before").value) return;
  try { const result = await json(`/ui/api/comparisons?before=${encodeURIComponent($("before").value)}&after=${encodeURIComponent(state.run.id)}`); const output = $("comparison-output"); output.replaceChildren(element("p", result.comparable ? "Coverage is comparable. Findings no longer observed still require verification." : `Coverage is not comparable: ${result.reason}`));
    for(const [key,label] of [["added","Added"],["persistent","Persistent"],["no_longer_observed","No longer observed"],["unresolved","Unresolved"]]) { const values = result[key] || []; const details = element("details"); details.append(element("summary",`${label}: ${values.length}`)); const list = element("ul"); for(const finding of values) list.append(element("li",`${finding.vulnerability_id} · ${finding.package} ${finding.version} · ${finding.location || finding.ecosystem}`)); details.append(list); output.append(details); }
  } catch(error) { fail(error); }
});
(async () => { try { await status(); signedIn(); await history(); notify("Connected to local evidence."); } catch(error) { if(error.status === 401) {clearError();notify("Enter your local token to connect.");} else fail(error); } })();
