// Operations / Health — the product lane over the health-check plane (ADR 0056 P2).
//
// A health check declares what to observe about ONE target (a System, an environment, an automation
// or a serving surface) and how; each evaluation is an admitted HealthCheckResult, and a failing one
// files a support incident through the incident plane's own admission when the check's policy says
// so. This lane reads both collections from the daemon on every request and keeps no copy. Its writes
// are the plane's own: declare, evaluate now, pause / resume / archive — each a form post the serve
// re-encodes with the caller's organization as owner and a per-render idempotency key.
//
// What is NOT here, named on the page instead of simulated: scheduled evaluation (a monitor-mode
// automation that names a check is registered by canon, but nothing fires it yet), snooze, and watch
// levels (who hears about which outcome).
import crypto from "node:crypto";
import { callerOwnerRef, escHtml as esc } from "../surfaces/kit.mjs";
import { isJustificationPrompt, justificationPayload, renderJustificationPrompt } from "./justification-prompt.mjs";

export const HEALTH_ROUTE = "/operations/health";
export const HEALTH_LANE = "/__ioi/operations/health";

const OUTCOME_PILL = { passed: "ok", warning: "warn", failed: "warn", errored: "warn", not_applicable: "muted", not_computable: "muted" };
const OUTCOME_WORD = { passed: "Passed", warning: "Warning", failed: "Failed", errored: "Errored", not_applicable: "Not applicable", not_computable: "Not computable" };
const SEVERITIES = ["informational", "minor", "major", "critical"];
const FILE_ON = [["never", "Never file an issue"], ["failed", "File an issue when it fails"], ["failed_or_errored", "File an issue when it fails or cannot run"]];
const ENABLEMENTS = ["enabled", "paused", "archived"];

// An admitted instant, to the second, in UTC — the record keeps the full precision.
const when = (iso) => { const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/u.exec(String(iso || "")); return m ? `${m[1]} ${m[2]} UTC` : String(iso || "—"); };
// Long references (a 64-hex environment id) break anywhere rather than widen the page; every table
// scrolls inside its own box; the form stacks at a phone width.
const HEALTH_CSS = `<style>.hc-scroll{overflow-x:auto;max-width:100%}.hc-scroll table{width:100%;min-width:640px}.hc-scroll code{word-break:break-all}.hc-scroll .pill{white-space:nowrap}.hc-verbs{display:flex;flex-wrap:wrap;gap:6px}.hc-verbs form{margin:0}form.grid[data-health-new]>*{min-width:0}form.grid[data-health-new] input,form.grid[data-health-new] select{width:100%;max-width:100%;box-sizing:border-box}@media (max-width:640px){form.grid[data-health-new]{grid-template-columns:1fr!important}}</style>`;
const tailOf = (ref, scheme) => String(ref || "").startsWith(scheme) ? String(ref).slice(scheme.length) : "";
const checkTail = (ref) => tailOf(ref, "health-check://") || String(ref || "");

function outcomePill(outcome, extra = "") {
  if (!outcome) return `<span class="pill muted"${extra}>Not evaluated</span>`;
  return `<span class="pill ${OUTCOME_PILL[outcome] || "muted"}" data-health-outcome="${esc(outcome)}"${extra}>${esc(OUTCOME_WORD[outcome] || outcome)}</span>`;
}

// A target reference, linked to the surface that owns it.
function targetLink(ref) {
  const r = String(ref || "");
  const system = tailOf(r, "system://");
  if (system) return `<a href="/systems/${system.split("/").map(encodeURIComponent).join("/")}"><code>${esc(r)}</code></a>`;
  const automation = tailOf(r, "automation://");
  if (automation) return `<a href="/__ioi/automations/${encodeURIComponent(automation)}"><code>${esc(r)}</code></a>`;
  if (r.startsWith("environment://")) return `<a href="/__ioi/environments"><code>${esc(r)}</code></a>`;
  return `<code>${esc(r || "—")}</code>`;
}

function evidenceLink(ref) {
  const r = String(ref || "");
  const aex = tailOf(r, "automation-execution://");
  if (aex) return `<a href="/__ioi/run-timeline/${encodeURIComponent(aex)}"><code>${esc(r)}</code></a>`;
  const run = tailOf(r, "automation-run://");
  if (run) return `<a href="/automations?run=${encodeURIComponent(r)}"><code>${esc(r)}</code></a>`;
  return targetLink(r);
}

function incidentLink(ref) {
  const tail = tailOf(ref, "support-incident://");
  if (!tail) return "—";
  return `<a href="/operations/issues?lane=all&amp;issue=${encodeURIComponent(tail)}" data-health-incident="${esc(ref)}">issue →</a>`;
}

function probeText(check) {
  if (check.check_kind === "command_exit") {
    const p = check.probe || {};
    return `runs <code>${esc(p.command || "")}</code> in ${targetLink(p.environment_ref)}; exit 0 passes`;
  }
  if (check.check_kind === "automation_run_outcome") return "reads the automation's latest run";
  return esc(check.check_kind || "—");
}

function hidden(name, value) {
  return `<input type="hidden" name="${esc(name)}" value="${esc(value)}">`;
}

// One check's row verbs. A verb the check cannot take says why beside it, never a silent no-op.
function checkActions(check, canWrite, why) {
  const id = checkTail(check.health_check_id);
  const nonce = () => hidden("nonce", crypto.randomUUID());
  const form = (action, fields, label, cls = "act ghost", attrs = "") => `<form method="post" action="${HEALTH_LANE}/${action}" style="display:inline">${hidden("id", id)}${fields}${nonce()}<button class="${cls}" type="submit"${attrs}>${label}</button></form>`;
  if (!canWrite) return `<span class="sub" style="margin:0">${esc(why)}</span>`;
  const verbs = [];
  if (check.enablement === "enabled") {
    verbs.push(form("evaluate", "", "Evaluate now", "act", ` data-health-evaluate="${esc(id)}"`));
    verbs.push(form("enablement", hidden("enablement", "paused"), "Pause", "act ghost", ` data-health-pause="${esc(id)}"`));
  } else if (check.enablement === "paused") {
    verbs.push(`<button class="act" type="button" aria-disabled="true" disabled title="Paused checks are not evaluated">Evaluate now</button> <span class="sub" style="margin:0" data-health-disabled-reason="${esc(id)}">paused — resume it to evaluate it</span>`);
    verbs.push(form("enablement", hidden("enablement", "enabled"), "Resume", "act ghost", ` data-health-resume="${esc(id)}"`));
  }
  if (check.enablement !== "archived") verbs.push(form("enablement", hidden("enablement", "archived"), "Archive", "act danger", ` data-health-archive="${esc(id)}"`));
  else verbs.push(form("enablement", hidden("enablement", "enabled"), "Restore", "act ghost", ` data-health-restore="${esc(id)}"`));
  return verbs.join(" ");
}

function resultsTable(results, { showCheck = false, checkNames = new Map() } = {}) {
  if (!results.length) return `<div class="empty" data-health-results-empty="1">No results yet — a result is recorded each time the check is evaluated.</div>`;
  const rows = results.map((r) => `<tr data-health-result="${esc(r.result_id || "")}">
    ${showCheck ? `<td><a href="${HEALTH_ROUTE}?check=${encodeURIComponent(checkTail(r.health_check_ref))}">${esc(checkNames.get(r.health_check_ref) || checkTail(r.health_check_ref))}</a></td>` : ""}
    <td>${outcomePill(r.outcome)}</td>
    <td>${esc(when(r.observed_at))}</td>
    <td>${r.exit_code == null ? "—" : esc(String(r.exit_code))}</td>
    <td>${esc(r.redacted_summary || "")}</td>
    <td>${(r.evidence_refs || []).map(evidenceLink).join("<br>") || "—"}</td>
    <td>${incidentLink(r.support_incident_ref)}</td>
  </tr>`).join("");
  return `<div class="hc-scroll"><table data-health-results="1"><thead><tr>${showCheck ? "<th>Check</th>" : ""}<th>Outcome</th><th>Observed</th><th>Exit</th><th>Summary</th><th>Evidence</th><th>Issue</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

// The Health block another surface embeds for one target (the System workspace). Pure: it renders
// what it is given and links the lane for everything else.
export function renderTargetHealth(targetRef, checks, results) {
  const mine = checks.filter((c) => c.target_ref === targetRef && c.enablement !== "archived");
  const theirs = results.filter((r) => r.target_ref === targetRef).slice(0, 10);
  const newHref = `${HEALTH_ROUTE}?target=${encodeURIComponent(targetRef)}#new-check`;
  if (!mine.length && !theirs.length) {
    return `<div class="empty" data-target-health="${esc(targetRef)}" data-target-health-empty="1">No health check observes this yet. <a href="${esc(newHref)}">Declare one in Operations / Health →</a></div>`;
  }
  const latest = new Map();
  for (const r of results) if (!latest.has(r.health_check_ref)) latest.set(r.health_check_ref, r);
  const rows = mine.map((c) => {
    const last = latest.get(c.health_check_id);
    return `<tr data-target-health-check="${esc(c.health_check_id)}"><td><a href="${HEALTH_ROUTE}?check=${encodeURIComponent(checkTail(c.health_check_id))}">${esc(c.display_name || checkTail(c.health_check_id))}</a></td><td>${outcomePill(last?.outcome)}</td><td>${esc(last ? when(last.observed_at) : "—")}</td><td>${esc(c.enablement || "")}</td></tr>`;
  }).join("");
  const names = new Map(checks.map((c) => [c.health_check_id, c.display_name]));
  return `${HEALTH_CSS}<div data-target-health="${esc(targetRef)}"><div class="hc-scroll"><table><thead><tr><th>Check</th><th>Latest</th><th>Observed</th><th>State</th></tr></thead><tbody>${rows}</tbody></table></div>
    <h3 style="font-size:13px;margin:14px 0 6px">Recent results</h3>${resultsTable(theirs, { showCheck: true, checkNames: names })}
    <p class="sub" style="margin:8px 0 0"><a href="${esc(newHref)}">Add a check →</a> · <a href="${HEALTH_ROUTE}">All checks in Operations / Health →</a></p></div>`;
}

function newCheckForm(data, values, canWrite, why) {
  const v = values || {};
  const opt = (value, label, selected) => `<option value="${esc(value)}"${selected ? " selected" : ""}>${esc(label)}</option>`;
  const target = v.target || "";
  const group = (label, items) => items.length ? `<optgroup label="${esc(label)}">${items.map(([ref, name]) => opt(ref, name ? `${name} — ${ref}` : ref, ref === target)).join("")}</optgroup>` : "";
  const known = new Set([...data.systems, ...data.environments, ...data.automations].map(([ref]) => ref));
  const otherValue = v.target_ref || (target && !known.has(target) ? target : "");
  const targets = `<select name="target" data-health-field="target">${opt("", "Choose what to observe…", !target)}${group("Systems", data.systems)}${group("Environments", data.environments)}${group("Automations", data.automations)}${opt("__other", "Another reference…", target === "__other" || Boolean(otherValue))}</select>`;
  const disabled = canWrite ? "" : " disabled";
  // A SELECT WITH NOTHING TO CHOOSE IS NOT A CHOICE (R-240, verifier hygiene, 2026-09-29): with no environment on the
  // deployment this rendered a live select whose only option was its placeholder — opened, it offered nothing, and the
  // dead-control census read it click_failed. It now renders disabled and says why, in the unified gap contract.
  const noEnvironment = data.environments.length === 0;
  const envWhy = "No environment exists on this deployment yet, so there is none for a command check to run in — create one under Environments first";
  const envGap = noEnvironment ? ` disabled aria-disabled="true" title="${esc(envWhy)}" data-ioi-disabled-reason="${esc(envWhy)}"` : disabled;
  const envs = `<select name="environment_ref" data-health-field="environment_ref"${envGap}>${opt("", noEnvironment ? "No environment yet" : "Choose an environment…", !v.environment_ref)}${data.environments.map(([ref, name, phase]) => opt(ref, `${name || ref}${phase ? ` (${phase})` : ""}`, ref === v.environment_ref)).join("")}</select>`;
  return `<form method="post" action="${HEALTH_LANE}/new" id="new-check" data-health-new="1" class="grid" style="grid-template-columns:180px 1fr">
    ${hidden("nonce", v.nonce || crypto.randomUUID())}
    <label for="hc-name">Name</label><input id="hc-name" name="display_name" maxlength="160" value="${esc(v.display_name || "")}" placeholder="Lending service answers"${disabled}>
    <label>Target</label><div>${targets}<input name="target_ref" value="${esc(otherValue)}" placeholder="or another reference: system://… · environment://…" style="margin-top:6px;width:100%;box-sizing:border-box"${disabled}></div>
    <label for="hc-kind">How to check</label><select id="hc-kind" name="check_kind" data-health-field="check_kind"${disabled}>${opt("command_exit", "Run a command in an environment — exit 0 passes", (v.check_kind || "command_exit") === "command_exit")}${opt("automation_run_outcome", "Read an automation's latest run", v.check_kind === "automation_run_outcome")}</select>
    <label>Environment</label><div>${envs}<div class="sub" style="margin:4px 0 0">For a command check: the command runs there, under that environment's guardrails. Its output is not kept — only the exit code.</div></div>
    <label for="hc-cmd">Command</label><input id="hc-cmd" name="command" maxlength="2000" value="${esc(v.command || "")}" placeholder="curl -fsS http://127.0.0.1:8080/healthz"${disabled}>
    <label for="hc-sev">Severity</label><select id="hc-sev" name="severity"${disabled}>${SEVERITIES.map((s) => opt(s, s, (v.severity || "minor") === s)).join("")}</select>
    <label for="hc-file">When it fails</label><select id="hc-file" name="file_on"${disabled}>${FILE_ON.map(([value, label]) => opt(value, label, (v.file_on || "failed") === value)).join("")}</select>
    <span></span><div><button class="act" type="submit"${disabled}>Declare check</button>${canWrite ? "" : ` <span class="sub" style="margin:0" data-health-new-disabled="1">${esc(why)}</span>`}</div>
  </form>`;
}

const NAMED_GAPS = [
  ["health_check_cadence_awaits_monitor_dispatch", "Scheduled evaluation", "checks run when someone presses Evaluate now; a monitor-mode automation that evaluates a check on a cadence is registered by canon but nothing fires it yet"],
  ["health_check_snooze_absent", "Snooze", "a check can be paused, not snoozed until a time"],
  ["health_check_watch_levels_absent", "Watch levels", "who is told about which outcome is not configurable; failures reach people through the issues they file"],
];

// The page. `data` is the daemon's answers for this request; nothing is derived that the daemon did
// not publish except the latest result per check, which is the newest of that check's own results.
export function renderOperationsHealth(data, opts = {}) {
  const { checks = [], results = [], owner = "", readError = null, signInHref = "" } = data;
  const q = opts.query || new URLSearchParams();
  const canWrite = Boolean(owner) && !readError;
  const why = readError ? "the health checks could not be read, so nothing can be changed" : "your sign-in belongs to no organization of this deployment, so a check would have no owner";
  const notice = q.get("note") ? `<div class="card" style="display:block" data-health-notice="${q.get("ok") === "1" ? "ok" : "err"}"><span class="pill ${q.get("ok") === "1" ? "ok" : "warn"}" style="margin:0 8px 0 0">${q.get("ok") === "1" ? "Done" : "Not done"}</span>${esc(q.get("note"))}</div>` : "";
  const head = `${HEALTH_CSS}<h1>Operations / Health</h1>
    <p class="sub">What is observed about your Systems, environments and automations, and how each observation came out. A check names one target and one probe; every evaluation is an admitted result with its evidence, and a failing check files an issue when its policy says so. <a href="/__ioi/operations">← Operations</a> · <a href="/operations/issues">Issues →</a></p>`;
  if (readError) {
    return head + notice + `<div class="empty" data-health-read-error="${esc(readError.code || "")}">The health checks could not be read — <code>${esc(readError.code || "unavailable")}</code>: ${esc(readError.message || "")}.${signInHref ? ` <a href="${esc(signInHref)}" target="_top">Sign in</a> to see your checks.` : ""} Nothing is shown in their place.</div>`;
  }
  const latest = new Map();
  for (const r of results) if (!latest.has(r.health_check_ref)) latest.set(r.health_check_ref, r);
  const live = checks.filter((c) => c.enablement !== "archived");
  const archived = checks.filter((c) => c.enablement === "archived");
  const tally = {};
  for (const c of live) {
    const k = c.enablement === "paused" ? "paused" : (latest.get(c.health_check_id)?.outcome || "not_evaluated");
    tally[k] = (tally[k] || 0) + 1;
  }
  const chipOrder = [["failed", "warn"], ["errored", "warn"], ["warning", "warn"], ["passed", "ok"], ["not_computable", "muted"], ["not_applicable", "muted"], ["not_evaluated", "muted"], ["paused", "muted"]];
  const chips = live.length
    ? `<div class="row" data-health-tally="1" style="margin:0 0 14px">${chipOrder.filter(([k]) => tally[k]).map(([k, cls]) => `<span class="pill ${cls}" style="margin:0" data-health-tally-${esc(k)}="${tally[k]}">${tally[k]} ${esc(k === "not_evaluated" ? "not evaluated" : k === "paused" ? "paused" : (OUTCOME_WORD[k] || k).toLowerCase())}</span>`).join("")}</div>`
    : "";
  const row = (c) => {
    const last = latest.get(c.health_check_id);
    const id = checkTail(c.health_check_id);
    return `<tr data-health-check="${esc(c.health_check_id)}" data-health-enablement="${esc(c.enablement || "")}">
      <td><a href="${HEALTH_ROUTE}?check=${encodeURIComponent(id)}"><b>${esc(c.display_name || id)}</b></a><div class="sub" style="margin:2px 0 0;font-size:11px"><code>${esc(c.health_check_id)}</code></div></td>
      <td>${targetLink(c.target_ref)}</td>
      <td style="font-size:12.5px">${probeText(c)}<div class="sub" style="margin:2px 0 0;font-size:11px">${esc(c.severity || "")} · ${esc((FILE_ON.find(([k]) => k === c.incident_policy?.file_on) || ["", "never files an issue"])[1].toLowerCase())}</div></td>
      <td>${outcomePill(last?.outcome)}<div class="sub" style="margin:2px 0 0;font-size:11px">${esc(last ? when(last.observed_at) : "")}</div></td>
      <td><span class="pill ${c.enablement === "enabled" ? "ok" : "muted"}" style="margin:0">${esc(c.enablement || "")}</span></td>
      <td><div class="hc-verbs">${checkActions(c, canWrite, why)}</div></td>
    </tr>`;
  };
  const table = (list, attr) => `<div class="hc-scroll"><table ${attr}><thead><tr><th>Check</th><th>Target</th><th>Probe</th><th>Latest</th><th>State</th><th></th></tr></thead><tbody>${list.map(row).join("")}</tbody></table></div>`;
  const checksBlock = live.length
    ? table(live, `data-health-checks="${live.length}"`)
    : `<div class="empty" data-health-empty="1">No health checks yet. Declare one below — name what to observe and how; it is evaluated when you press Evaluate now.</div>`;
  const archivedBlock = archived.length ? `<details style="margin:10px 0 0"><summary class="sub">${archived.length} archived</summary>${table(archived, `data-health-archived="${archived.length}"`)}</details>` : "";
  const selectedId = q.get("check") || "";
  let detail = "";
  if (selectedId) {
    const ref = `health-check://${checkTail(selectedId)}`;
    const check = checks.find((c) => c.health_check_id === ref);
    detail = check
      ? `<h2 id="check-detail" data-health-detail="${esc(ref)}">${esc(check.display_name || selectedId)} — results</h2><p class="sub" style="margin:-4px 0 10px">Observes ${targetLink(check.target_ref)}; ${probeText(check)}. Declared ${esc(when(check.created_at))}.</p>${resultsTable(results.filter((r) => r.health_check_ref === ref))}`
      : `<div class="empty" data-health-detail-missing="1">No health check <code>${esc(selectedId)}</code> is visible to you.</div>`;
  }
  const values = { ...(opts.values || {}) };
  if (!values.target && q.get("target")) values.target = q.get("target");
  const dialogError = opts.error ? `<div class="card" style="display:block" data-health-new-error="1"><span class="pill warn" style="margin:0 8px 0 0">Not declared</span>${esc(opts.error)}</div>` : "";
  const gaps = `<h2>Not built yet</h2><ul class="sub" data-health-named-gaps="${NAMED_GAPS.length}">${NAMED_GAPS.map(([code, label, text]) => `<li data-named-gap="${esc(code)}"><b>${esc(label)}</b> — ${esc(text)}.</li>`).join("")}</ul>`;
  const recent = results.length ? `<h2>Recent results</h2>${resultsTable(results.slice(0, 15), { showCheck: true, checkNames: new Map(checks.map((c) => [c.health_check_id, c.display_name])) })}` : "";
  return head + notice + chips + `<h2>Checks</h2>` + checksBlock + archivedBlock + detail + recent
    + `<h2>New check</h2>` + dialogError + newCheckForm(data, values, canWrite, why) + gaps;
}

// ---- Serving: reads and form lanes. `deps` carries the serve's daemon client and helpers so this
// module holds no transport of its own.
async function readJson(daemonFetch, path) {
  try {
    const r = await daemonFetch(path);
    return { status: r.status, body: await r.json().catch(() => ({})) };
  } catch (e) {
    return { status: 0, body: {}, networkError: String(e && e.message || e) };
  }
}

async function loadHealthData({ daemonFetch }) {
  const [checksR, resultsR, whoR, envR, autoR, sysR] = await Promise.all([
    readJson(daemonFetch, "/v1/hypervisor/health-checks"),
    readJson(daemonFetch, "/v1/hypervisor/health-check-results"),
    readJson(daemonFetch, "/v1/hypervisor/auth/whoami"),
    readJson(daemonFetch, "/v1/hypervisor/environments-summary?limit=60&phase=live"),
    readJson(daemonFetch, "/v1/hypervisor/automations"),
    readJson(daemonFetch, "/v1/hypervisor/autonomous-systems/projection?view=compact"),
  ]);
  let readError = null;
  if (checksR.networkError) readError = { code: "daemon_unreachable", message: checksR.networkError };
  else if (checksR.status !== 200 || checksR.body.ok === false) {
    const b = checksR.body || {};
    readError = { code: b.code || b.error?.code || b.error?.message || `http_${checksR.status}`, message: b.message || b.error?.message || "" };
  }
  const environments = (envR.body.environments || []).map((e) => [`environment://${e.id || e.environment_id}`, e.spec?.name || e.name || "", e.status?.phase || e.phase || ""]).filter(([ref]) => ref !== "environment://undefined");
  const automations = (autoR.body.automations || []).map((a) => [`automation://${a.automation_id}`, a.name || ""]);
  const systems = (sysR.status === 200 && Array.isArray(sysR.body.systems) ? sysR.body.systems : []).map((s) => [s.system_id, s.display_name || ""]).filter(([ref]) => ref);
  return {
    checks: checksR.body.health_checks || [],
    results: resultsR.body.health_check_results || [],
    owner: whoR.body?.authenticated === false ? "" : callerOwnerRef(whoR.body || {}),
    readError,
    signInHref: readError && /principal_required/u.test(readError.code) ? `/__ioi/login?next=${encodeURIComponent(HEALTH_ROUTE)}` : "",
    environments, automations, systems,
  };
}

async function writeJson(daemonFetch, path, payload) {
  try {
    const r = await daemonFetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
    return { status: r.status, body: await r.json().catch(() => ({})) };
  } catch {
    return { status: 0, body: {} };
  }
}

const accepted = (r) => r.status >= 200 && r.status < 300 && r.body && r.body.ok === true;

// Returns true when it answered the request.
export async function handleOperationsHealth(req, res, pathname, body, deps) {
  const { daemonFetch, whyRefused, send } = deps;
  if (pathname === HEALTH_LANE && req.method === "GET") {
    const query = new URL(req.url, "http://x").searchParams;
    send(res, 200, renderOperationsHealth(await loadHealthData(deps), { query }));
    return true;
  }
  if (!pathname.startsWith(`${HEALTH_LANE}/`) || req.method !== "POST") return false;
  const f = new URLSearchParams(body.toString());
  const back = (ok, note, check) => {
    const qs = new URLSearchParams({ ...(check ? { check } : {}), ok: ok ? "1" : "0", note });
    res.writeHead(303, { Location: `${HEALTH_ROUTE}?${qs}${check ? "#check-detail" : ""}`, "Cache-Control": "no-store" });
    res.end();
  };
  const who = await readJson(daemonFetch, "/v1/hypervisor/auth/whoami");
  // An anonymous whoami still names the local operator (with authenticated:false), so the owner is
  // taken only from a signed-in answer.
  const signedOut = who.status === 401 || who.body?.authenticated === false || /principal_required/u.test(JSON.stringify(who.body || {}));
  const owner = signedOut ? "" : callerOwnerRef(who.body || {});
  const noOwner = signedOut ? "you are signed out — sign in and try again" : "your sign-in belongs to no organization of this deployment";
  const action = pathname.slice(HEALTH_LANE.length + 1);
  if (action === "new") {
    const values = Object.fromEntries(["nonce", "display_name", "target", "target_ref", "check_kind", "environment_ref", "command", "severity", "file_on"].map((k) => [k, (f.get(k) || "").slice(0, k === "command" ? 2000 : 300)]));
    const refuse = async (error) => send(res, 200, renderOperationsHealth(await loadHealthData(deps), { query: new URLSearchParams(), values, error }));
    const target = values.target === "__other" || !values.target ? values.target_ref.trim() : values.target;
    if (!values.display_name.trim()) return refuse("give the check a name."), true;
    if (!target) return refuse("name what the check observes — pick a target, or write another object's reference."), true;
    if (values.check_kind === "command_exit" && (!values.environment_ref || !values.command.trim())) return refuse("a command check needs the environment it runs in and the command to run."), true;
    if (!owner) return refuse(`${noOwner}, so the check would have no owner.`), true;
    const payload = {
      owner_ref: owner, idempotency_key: `health-check-${values.nonce || crypto.randomUUID()}`,
      display_name: values.display_name.trim(), target_ref: target, check_kind: values.check_kind || "command_exit",
      severity: values.severity || "minor", incident_policy: { file_on: values.file_on || "failed" },
      ...(values.check_kind === "automation_run_outcome" ? {} : { probe: { environment_ref: values.environment_ref, command: values.command.trim() } }),
      ...justificationPayload(f),
    };
    const r = await writeJson(daemonFetch, "/v1/hypervisor/health-checks", payload);
    // A Governance checkpoint on declaring a check answers with its prompt (ADR 0056 P5).
    if (isJustificationPrompt(r.status, r.body)) {
      send(res, 200, renderJustificationPrompt({ action: `${HEALTH_LANE}/new`, carried: f, reply: r.body, backHref: HEALTH_ROUTE, what: "Declaring this health check" }));
      return true;
    }
    if (!accepted(r)) return refuse(`${whyRefused(r.body)}.`), true;
    const id = checkTail(r.body.health_check?.health_check_id);
    back(true, r.body.replayed ? "This check was already declared — the same form was submitted twice, so nothing new was written." : "Declared. Press Evaluate now to observe it.", id);
    return true;
  }
  const id = checkTail((f.get("id") || "").slice(0, 200));
  if (!/^hc_[0-9a-f]{1,64}$/u.test(id)) return back(false, "That is not a health check.", ""), true;
  if (!owner) return back(false, `Not changed: ${noOwner}.`, id), true;
  const key = `${action}-${f.get("nonce") || crypto.randomUUID()}`;
  if (action === "evaluate") {
    const r = await writeJson(daemonFetch, `/v1/hypervisor/health-checks/${encodeURIComponent(id)}/evaluate`, { owner_ref: owner, idempotency_key: `health-check-${key}` });
    if (!accepted(r)) return back(false, `Not evaluated: ${whyRefused(r.body)}.`, id), true;
    const result = r.body.health_check_result || {};
    const filed = result.support_incident_ref ? " An issue was filed." : "";
    return back(true, `${OUTCOME_WORD[result.outcome] || result.outcome}: ${result.redacted_summary || ""}.${filed}`, id), true;
  }
  if (action === "enablement") {
    const to = f.get("enablement") || "";
    if (!ENABLEMENTS.includes(to)) return back(false, "Not changed: that is not a state a check can be in.", id), true;
    const r = await writeJson(daemonFetch, `/v1/hypervisor/health-checks/${encodeURIComponent(id)}/enablement`, { owner_ref: owner, idempotency_key: `health-check-${key}`, enablement: to });
    if (!accepted(r)) return back(false, `Not changed: ${whyRefused(r.body)}.`, id), true;
    return back(true, `The check is now ${r.body.health_check?.enablement || to}.`, id), true;
  }
  return false;
}
