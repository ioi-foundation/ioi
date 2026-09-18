// Missions — operational read model over the GoalRun plane, its results, and the run queue.
//
// Re-typed 2026-09-18 (R-178 slice S4d-3, R-191). This surface used to project the hosted
// OutcomeRoom graph across thirteen daemon planes; eleven of them were deleted with the room
// plane (S4a, S4c-2) and the GoalRun family stopped naming rooms in S4d-2. It now reads exactly
// what the daemon still serves — GoalRuns, the generic WorkResults, and the operations run
// queue — and renders no room, participation, frontier, claim, offer or challenge vocabulary.
// A GoalRun's membership in an ioi.ai orchestration is shown as the ref the composing
// application stamped (`orchestration_ref`), never resolved here: the orchestration record is
// application vocabulary and this surface reaches no application seam.
//
// It declares no actions. It projects daemon-owned records without minting acceptance, verdict,
// settlement, execution, or federation authority.
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { canonicalTimelineRef, escHtml, proofLink, selectionQuery } from "../kit.mjs";
import { readJsonWithDeadline } from "../plane-read.mjs";

const ROUTE = "/__ioi/missions";
const DEFAULT_PLANE_TIMEOUT_MS = 3_000;
const OPEN_RUN = new Set(["draft", "active", "paused"]);

export const MISSIONS_APP_ICON_URI = `data:image/svg+xml,${encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="2.4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></svg>',
)}`;

export const meta = {
  slug: "missions",
  route: ROUTE,
  verifier: "scripts/verify-hypervisor-app-parity-missions.mjs",
  certification: "n/a",
};

const unavailablePlane = (status, code) => ({
  ok: false,
  status,
  code,
  rows: [],
  payload: null,
});

const isRecord = (value) => !!value && typeof value === "object" && !Array.isArray(value);
const nonEmptyString = (value) => typeof value === "string" && value.trim().length > 0;
const fieldMatches = (record, field, pattern) => nonEmptyString(record[field]) && pattern.test(record[field]);
const optionalFieldMatches = (record, field, pattern) => record[field] == null || fieldMatches(record, field, pattern);
const everyArrayEntry = (values, validator) => Array.isArray(values) && values.every(validator);

const GOAL_REF = /^goal:\/\/(?!.*\.\.)[^\s?#]{1,160}$/;
const GOAL_RUN_ID = /^[A-Za-z0-9_-]{1,160}$/;
const WORK_RESULT_REF = /^work-result:\/\/wr_[0-9a-f]+$/;
// The composition's own scope, stamped by the ioi.ai application through the GoalRun plane's
// membership route (R-190). This surface renders it and resolves nothing behind it.
const ORCHESTRATION_REF = /^app-scope:\/\/ioi-ai\/orchestration\/[^\s]{1,400}$/;

const hasStatus = (record) => nonEmptyString(record.status);
const rowValidators = {
  goal_runs: (row) => isRecord(row)
    && fieldMatches(row, "goal_run_id", GOAL_RUN_ID)
    && fieldMatches(row, "goal_ref", GOAL_REF)
    && optionalFieldMatches(row, "orchestration_ref", ORCHESTRATION_REF)
    && hasStatus(row)
    && (row.blockers === undefined
      || everyArrayEntry(row.blockers, (blocker) => isRecord(blocker) && nonEmptyString(blocker.reason_code))),
  work_results: (row) => isRecord(row)
    && fieldMatches(row, "work_result_id", WORK_RESULT_REF)
    && fieldMatches(row, "work_subject_ref", GOAL_REF)
    && hasStatus(row),
};

const operationRunValid = (row) => isRecord(row)
  && nonEmptyString(row.execution_id)
  && hasStatus(row)
  && (row.timeline_ref == null || canonicalTimelineRef(row.timeline_ref) !== "");

async function readCollection(fetchImpl, daemon, path, key, validateRow, timeoutMs) {
  try {
    const { response, payload } = await readJsonWithDeadline(fetchImpl, `${daemon}${path}`, timeoutMs);
    if (!response.ok) {
      return unavailablePlane(response.status, payload?.error?.code || "plane_unavailable");
    }
    if (!Array.isArray(payload?.[key]) || !payload[key].every(validateRow)) {
      return unavailablePlane(response.status, "plane_payload_invalid");
    }
    return { ok: true, status: response.status, code: "", rows: payload[key], payload };
  } catch (error) {
    return unavailablePlane(0, error?.code === "plane_timeout" ? "plane_timeout" : "daemon_unavailable");
  }
}

async function readOperations(fetchImpl, daemon, timeoutMs) {
  try {
    const { response, payload } = await readJsonWithDeadline(fetchImpl, `${daemon}/v1/hypervisor/operations`, timeoutMs);
    if (!response.ok) {
      return unavailablePlane(response.status, payload?.error?.code || "plane_unavailable");
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)
      || !payload.runs || typeof payload.runs !== "object" || Array.isArray(payload.runs)
      || !Array.isArray(payload.runs.recent) || !Array.isArray(payload.runs.failures)
      || !payload.runs.recent.every(operationRunValid) || !payload.runs.failures.every(operationRunValid)
      || !Number.isFinite(payload.runs.total)) {
      return unavailablePlane(response.status, "plane_payload_invalid");
    }
    return { ok: true, status: response.status, code: "", rows: [], payload };
  } catch (error) {
    return unavailablePlane(0, error?.code === "plane_timeout" ? "plane_timeout" : "daemon_unavailable");
  }
}
const hasUniqueKeys = (plane, field) => new Set(plane.rows.map((row) => row[field])).size === plane.rows.length;

// The relationships this surface can check WITHOUT reaching another owner's plane: identity is
// unique on both planes, and a result whose subject names a GoalRun this list holds must name a
// run that exists. A result whose subject is NOT in the list is not an error — the GoalRun list
// is a projection of the caller's own runs, and a result may belong to a subject outside it —
// so it renders as unattributed rather than as a broken edge.
function validateModelRelationships(model) {
  const runsByGoal = new Map(model.goalRuns.rows.map((row) => [row.goal_ref, row]));
  const checks = [
    ["goalRuns", [], () => hasUniqueKeys(model.goalRuns, "goal_run_id")
      && new Set(model.goalRuns.rows.map((row) => row.goal_ref)).size === model.goalRuns.rows.length],
    ["results", [], () => hasUniqueKeys(model.results, "work_result_id")],
  ];
  for (const [plane, dependencies, check] of checks) {
    const dependencyUnavailable = dependencies.some((name) => !model[name].ok);
    if (!model[plane].ok || dependencyUnavailable) continue;
    if (!check()) {
      model[plane] = unavailablePlane(model[plane].status, "plane_relationship_invalid");
    }
  }
  model.unattributedResults = model.results.ok && model.goalRuns.ok
    ? model.results.rows.filter((row) => !runsByGoal.has(row.work_subject_ref)).length
    : 0;
  return model;
}

export async function load(ctx) {
  const fetchImpl = ctx.fetch || globalThis.fetch;
  const requestedTimeout = Number(ctx.planeTimeoutMs);
  const timeoutMs = Number.isFinite(requestedTimeout) && requestedTimeout > 0
    ? Math.min(Math.floor(requestedTimeout), 30_000)
    : DEFAULT_PLANE_TIMEOUT_MS;
  const specs = [
    ["goalRuns", "/v1/goal-orchestration/goal-runs", "goal_runs"],
    ["results", "/v1/hypervisor/work-results", "work_results"],
  ];
  const [values, operations] = await Promise.all([
    Promise.all(specs.map(([, path, key]) => readCollection(fetchImpl, ctx.daemon, path, key, rowValidators[key], timeoutMs))),
    readOperations(fetchImpl, ctx.daemon, timeoutMs),
  ]);
  const model = Object.fromEntries(specs.map(([name], index) => [name, values[index]]));
  model.operations = operations;
  return validateModelRelationships(model);
}

const value = (record, key, fallback = "") => String(record?.[key] ?? fallback);
const shortRef = (reference) => {
  const raw = String(reference || "");
  if (raw.length <= 34) return raw;
  return `${raw.slice(0, 18)}…${raw.slice(-12)}`;
};
const timestamp = (raw) => {
  const ms = Date.parse(raw || "");
  if (!Number.isFinite(ms)) return raw || "—";
  return new Date(ms).toLocaleString("en", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
};
const statusTone = (status) => {
  const normalized = String(status || "").toLowerCase();
  if (["active", "complete", "completed", "admitted", "resolved"].includes(normalized)) return "ok";
  if (["blocked", "failed", "revoked", "superseded"].includes(normalized)) return "danger";
  if (["draft", "paused", "verifying", "course_correcting", "waiting_on_user"].includes(normalized)) return "warn";
  return "muted";
};
const statusPill = (status) => `<span class="ms-pill ${statusTone(status)}">${escHtml(status || "unknown")}</span>`;
const resultsFor = (model, goalRef) => model.results.rows.filter((row) => value(row, "work_subject_ref") === goalRef);
const objective = (run) => value(run, "normalized_goal", value(run, "goal_ref", "Untitled run"));

function planeNotice(name, plane) {
  if (plane.ok) return "";
  return `<div class="ms-plane-error" role="status"><b>${escHtml(name)}</b> unavailable — <code>${escHtml(plane.code)}</code>. Counts for this plane are not treated as zero.</div>`;
}

const planeCount = (plane, rows = plane.rows) => plane.ok ? rows.length : "—";

function metric(label, count, tone = "") {
  const key = label.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const dataValue = count === "—" ? "unknown" : String(count);
  return `<div class="ms-metric ${tone}" data-missions-metric="${escHtml(key)}" data-value="${escHtml(dataValue)}"><strong>${escHtml(String(count))}</strong><span>${escHtml(label)}</span></div>`;
}

function renderRunList(runs, selectedRef, status, model) {
  const hrefFor = (run) => selectionQuery(ROUTE, {
    goal: value(run, "goal_run_id"),
    status: status === "all" ? "" : status,
  });
  if (!model.goalRuns.ok) {
    return `<div class="ms-empty"><b>Run list unavailable.</b><span>The GoalRun plane could not be read; no empty-state inference was made.</span></div>`;
  }
  if (!runs.length) {
    return `<div class="ms-empty"><b>No goal runs in this view.</b><span>The daemon returned no GoalRun records matching this status.</span></div>`;
  }
  return `<div class="ms-run-list" role="list">${runs.map((run) => {
    const reference = value(run, "goal_run_id");
    const results = resultsFor(model, value(run, "goal_ref"));
    const blockers = Array.isArray(run.blockers) ? run.blockers.length : 0;
    return `<a role="listitem" class="ms-run-row${reference === selectedRef ? " selected" : ""}" href="${hrefFor(run)}" aria-current="${reference === selectedRef ? "true" : "false"}">
      <span class="ms-run-state">${statusPill(value(run, "status"))}</span>
      <span class="ms-run-copy"><strong>${escHtml(objective(run))}</strong><span>${escHtml(shortRef(value(run, "goal_ref")))} · ${escHtml(value(run, "continuation_state", "open"))}</span></span>
      <span class="ms-run-counts"><b>${planeCount(model.results, results)}</b> results ${blockers ? `<b class="danger">${blockers}</b> blockers` : ""}</span>
    </a>`;
  }).join("")}</div>`;
}

function renderResults(run, model) {
  const rows = resultsFor(model, value(run, "goal_ref"));
  if (!model.results.ok) return planeNotice("WorkResults", model.results);
  if (!rows.length) {
    return `<div class="ms-empty compact"><b>No results for this run.</b><span>The generic WorkResult plane holds no record whose work subject is this run.</span></div>`;
  }
  return `<div class="ms-evidence">
    <div class="ms-evidence-head"><span>WorkResult</span><span>Outcome</span><span>Status</span><span>Proof</span></div>
    ${rows.map((row) => `<div class="ms-evidence-row">
      <span><code>${escHtml(shortRef(value(row, "work_result_id")))}</code></span>
      <span>${escHtml(value(row, "outcome_class", "—"))}</span>
      <span>${statusPill(value(row, "status"))}</span>
      <span>${proofLink(value(row, "work_result_id"))}</span>
    </div>`).join("")}
  </div>`;
}

function renderRunDetail(run, model, selectionProblem = null) {
  if (selectionProblem) {
    const message = selectionProblem.code === "goal_run_not_found"
      ? "That GoalRun is not in the daemon's list."
      : "That GoalRun exists but is filtered out of this view.";
    return `<div class="ms-detail empty-detail" data-missions-selection="${escHtml(selectionProblem.code)}"><div><b>Nothing selected.</b><p>${escHtml(message)}</p></div></div>`;
  }
  if (!run) {
    return `<div class="ms-detail empty-detail" data-missions-selection="none"><div><b>Nothing selected.</b><p>Choose a goal run to inspect its facts, results and blockers.</p></div></div>`;
  }
  const blockers = Array.isArray(run.blockers) ? run.blockers : [];
  const membership = value(run, "orchestration_ref");
  return `<div class="ms-detail" data-missions-selected-run="${escHtml(value(run, "goal_run_id"))}">
    <h2>${escHtml(objective(run))}</h2>
    <div class="ms-facts">
      <div><span>status</span><b>${escHtml(value(run, "status"))}</b></div>
      <div><span>continuation</span><b>${escHtml(value(run, "continuation_state", "open"))}</b></div>
      <div><span>admission path</span><b>${escHtml(value(run, "admission_path_status", "—"))}</b></div>
      <div><span>orchestration</span><b data-missions-orchestration="${escHtml(membership || "none")}">${escHtml(membership ? shortRef(membership) : "none")}</b></div>
      <div><span>updated</span><b>${escHtml(timestamp(value(run, "updated_at")))}</b></div>
    </div>
    <div class="ms-section"><div class="ms-section-title"><h3>Results</h3><span>generic WorkResults whose work subject is this run</span></div>${renderResults(run, model)}</div>
    <div class="ms-section"><div class="ms-section-title"><h3>Blockers</h3><span data-missions-blockers="${blockers.length}">${blockers.length} recorded</span></div>
      ${blockers.length ? `<div class="ms-work-list">${blockers.map((blocker) => `<div class="ms-work-row"><b>${escHtml(String(blocker.reason_code || "unknown"))}</b><span>${escHtml(String(blocker.detail || ""))}</span></div>`).join("")}</div>`
        : `<div class="ms-empty compact"><b>No blockers.</b><span>The run records none.</span></div>`}
    </div>
    <footer class="ms-contract"><b>Read-only by contract.</b> This surface renders daemon truth. Membership in an ioi.ai orchestration is the ref the composing application stamped; it is not resolved here, and nothing on this page accepts, verdicts, settles, executes or federates.</footer>
  </div>`;
}

function renderLegacyOperations(model) {
  const operations = model.operations.payload || {};
  const runs = operations.runs || {};
  const recent = Array.isArray(runs.recent) ? runs.recent : [];
  const failures = Array.isArray(runs.failures) ? runs.failures : [];
  const goalRuns = model.goalRuns.rows;
  const blocked = goalRuns.filter((run) => Array.isArray(run.blockers) && run.blockers.length);
  const incidentCount = failures.length + blocked.length;
  const incidentsReady = model.operations.ok && model.goalRuns.ok;
  const runRows = recent.map((run) => {
    const timeline = canonicalTimelineRef(run.timeline_ref);
    return `<div class="ms-op-row"><span><b>${escHtml(run.name || run.execution_id || "mission run")}</b><small>${escHtml(shortRef(run.project_id || ""))}</small></span>${statusPill(run.status)}<time>${escHtml(timestamp(run.started_at))}</time>${timeline ? proofLink({ href: timeline, label: "Timeline", external: true }) : "<span>—</span>"}</div>`;
  }).join("");
  const incidentRows = [
    ...failures.map((run) => ({ kind: "run failure", subject: run.name || run.execution_id, reason: run.status, time: run.finished_at || run.started_at, proof: canonicalTimelineRef(run.timeline_ref) })),
    ...blocked.slice(0, 50).map((run) => ({ kind: "blocker", subject: run.normalized_goal || run.goal_ref || run.goal_run_id, reason: run.blockers?.[0]?.reason_code, time: run.updated_at || run.created_at, proof: run.goal_run_id ? `/__ioi/run-timeline/goal-run/${encodeURIComponent(run.goal_run_id)}` : "" })),
  ];
  const capDisclosure = incidentsReady && incidentRows.length < incidentCount
    ? ` · showing first ${incidentRows.length} of ${incidentCount}`
    : "";
  return `<div class="ms-legacy">
    <div class="ms-section"><div class="ms-section-title"><h3 id="missions-queue">Run queue</h3><span>${model.operations.ok ? `recent mission runs (${recent.length} of ${runs.total || 0})` : "run count unavailable"}</span></div>${model.operations.ok ? (runRows || `<div class="ms-empty compact"><b>No mission runs yet.</b><span>The daemon run queue is honestly empty.</span></div>`) : planeNotice("Operations run queue", model.operations)}</div>
    <div class="ms-section"><div class="ms-section-title"><h3 id="missions-incidents">Incidents &amp; blockers</h3><span>run failures + mission blockers needing remediation (${incidentsReady ? incidentCount : "unknown"})${capDisclosure} · <a href="/__ioi/missions/incidents">Open incident inbox</a></span></div>
      ${!incidentsReady ? planeNotice("Mission incidents", !model.operations.ok ? model.operations : model.goalRuns) : incidentRows.length ? `<div class="ms-op-list">${incidentRows.map((incident) => `<div class="ms-op-row"><span><b>${escHtml(incident.kind)}</b><small>${escHtml(incident.subject || "—")}</small></span>${statusPill(incident.reason)}<time>${escHtml(timestamp(incident.time))}</time>${incident.proof ? proofLink({ href: incident.proof, label: "Proof", external: true }) : "<span>—</span>"}</div>`).join("")}</div>` : `<div class="ms-empty compact"><b>No incidents.</b><span>No failed mission runs and no blocked mission runs right now.</span></div>`}
    </div>
    <footer class="ms-contract"><b>Operational boundary.</b> Hosted admission only; this surface grants no acceptance, verdict, settlement, execution, or federation authority. Unsupported reference lanes — creating/assigning incidents, editing job/build definitions, board/kanban views, SLA and escalation policy, comments, and assignees — remain named gaps. Substrate/infra incidents (storage repair, provider failover) live in <a href="/__ioi/operations">Operations</a>. Reference captures remain secondary baselines: <a href="/__apps/jobs">Builds</a> · <a href="/__apps/incidents">Issues</a>.</footer>
  </div>`;
}

export function render(model, ctx) {
  const allRuns = model.goalRuns.rows;
  const statuses = [...new Set(allRuns.map((run) => value(run, "status")).filter(Boolean))].sort();
  const requestedStatus = ctx.url.searchParams.get("status") || "all";
  const status = requestedStatus === "all" || statuses.includes(requestedStatus) ? requestedStatus : "all";
  const runs = status === "all" ? allRuns : allRuns.filter((run) => value(run, "status") === status);
  const requestedRun = ctx.url.searchParams.get("goal") || "";
  const exactRequestedRun = requestedRun
    ? allRuns.find((run) => value(run, "goal_run_id") === requestedRun)
    : null;
  const selectionProblem = requestedRun && !exactRequestedRun
    ? { code: "goal_run_not_found" }
    : requestedRun && !runs.includes(exactRequestedRun)
      ? { code: "goal_run_filter_mismatch" }
      : null;
  const selected = requestedRun
    ? (selectionProblem ? null : exactRequestedRun)
    : runs.find((run) => OPEN_RUN.has(value(run, "status"))) || runs[0] || null;
  const selectedRef = selected ? value(selected, "goal_run_id") : "";
  const openRuns = allRuns.filter((run) => OPEN_RUN.has(value(run, "status")));
  const blockedRuns = allRuns.filter((run) => Array.isArray(run.blockers) && run.blockers.length);
  const filters = ["all", ...statuses].map((entry) => `<a role="tab" aria-selected="${entry === status}" class="ms-filter${entry === status ? " active" : ""}" href="${selectionQuery(ROUTE, { goal: selectedRef, status: entry === "all" ? "" : entry })}">${escHtml(entry)}</a>`).join("");
  const globalRail = ctx.embed ? "" : ioiGlobalRailHtml({
    label: "Missions", href: ROUTE, iconUri: MISSIONS_APP_ICON_URI,
  });
  const CSS = `
    :root{color-scheme:dark;--surface-base:28 28 28;--surface-01:22 21 21;--surface-03:31 31 31;--surface-hover:255 255 255;--content-primary:250 250 250;--content-secondary:163 163 163;--content-muted:115 115 115;--content-strong:212 212 212;--content-link:139 171 252;--content-negative:255 83 90;--border-base:64 64 64;--border-strong:82 82 82;--border-brand:94 138 253;--status-ok:108 255 100;--status-warn:254 154 91;--status-danger:255 83 90}
    @media(prefers-color-scheme:light){:root{color-scheme:light;--surface-base:250 250 250;--surface-01:255 255 255;--surface-03:245 245 245;--surface-hover:0 0 0;--content-primary:31 31 31;--content-secondary:82 82 82;--content-muted:115 115 115;--content-strong:64 64 64;--content-link:0 72 255;--content-negative:173 0 2;--border-base:225 225 225;--border-strong:212 212 212;--border-brand:47 105 253;--status-ok:28 125 44;--status-warn:154 82 12;--status-danger:173 0 2}}
    *{box-sizing:border-box}body{margin:0;background:rgb(var(--surface-base));color:rgb(var(--content-primary));font:14px/1.45 "ABC Diatype",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:rgb(var(--content-link));text-decoration:none}button,a{transition:background-color .15s ease,color .15s ease,border-color .15s ease,transform .15s ease}code{font:11px/1.4 "ABC Diatype Mono",ui-monospace,monospace;color:rgb(var(--content-secondary));word-break:break-all}
    ${IOI_GRAIL_CSS}
    .ms-shell{display:flex;min-height:100svh}.ms-main{flex:1;min-width:0}.ms-top{position:sticky;top:0;z-index:5;display:flex;align-items:center;justify-content:space-between;gap:20px;height:64px;padding:0 24px;border-bottom:1px solid rgb(var(--border-base));background:rgb(var(--surface-base)/.92);backdrop-filter:blur(16px)}.ms-title{display:flex;align-items:baseline;gap:10px}.ms-title h1{font-size:20px;line-height:1;margin:0;font-weight:500}.ms-title span{color:rgb(var(--content-muted));font-size:12px}.ms-actions{display:flex;align-items:center;gap:8px}.ms-action{display:inline-flex;align-items:center;height:32px;padding:0 12px;border:1px solid rgb(var(--border-base));border-radius:8px;color:rgb(var(--content-primary));background:rgb(var(--surface-01));font-size:12px}.ms-action:hover{border-color:rgb(var(--border-brand));transform:translateY(-1px)}
    .ms-summary{display:flex;align-items:stretch;border-bottom:1px solid rgb(var(--border-base));padding:0 24px}.ms-metric{display:flex;flex-direction:column;gap:2px;min-width:112px;padding:16px 22px 14px 0;margin-right:22px;border-right:1px solid rgb(var(--border-base))}.ms-metric:last-child{border-right:0}.ms-metric strong{font-size:20px;line-height:1.1;font-weight:500}.ms-metric span{color:rgb(var(--content-muted));font-size:11px}.ms-metric.attention strong{color:rgb(var(--status-warn))}
    .ms-tabs{display:flex;align-items:center;gap:2px;padding:12px 24px;border-bottom:1px solid rgb(var(--border-base));overflow:auto}.ms-filter{display:inline-flex;align-items:center;gap:7px;height:30px;padding:0 10px;border-radius:7px;color:rgb(var(--content-secondary));white-space:nowrap}.ms-filter span{font-size:10px;color:rgb(var(--content-muted))}.ms-filter:hover,.ms-filter.active{background:rgb(var(--surface-hover)/.07);color:rgb(var(--content-primary))}
    .ms-workspace{display:grid;grid-template-columns:minmax(280px,340px) minmax(0,1fr);min-height:calc(100svh - 178px)}.ms-sidebar{border-right:1px solid rgb(var(--border-base));background:rgb(var(--surface-01));min-width:0}.ms-sidebar-head{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid rgb(var(--border-base));color:rgb(var(--content-muted));font-size:11px;text-transform:uppercase}.ms-run-list{display:flex;flex-direction:column}.ms-run-row{display:grid;grid-template-columns:auto minmax(0,1fr);gap:8px 10px;padding:14px 16px;border-bottom:1px solid rgb(var(--border-base));color:inherit;position:relative}.ms-run-row:hover{background:rgb(var(--surface-hover)/.05)}.ms-run-row.selected{background:rgb(var(--surface-hover)/.08)}.ms-run-row.selected:before{content:"";position:absolute;inset:0 auto 0 0;width:2px;background:rgb(var(--border-brand))}.ms-run-copy{min-width:0}.ms-run-copy strong,.ms-run-copy span{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ms-run-copy strong{font-weight:500}.ms-run-copy span{color:rgb(var(--content-muted));font-size:11px;margin-top:3px}.ms-run-counts{grid-column:2;color:rgb(var(--content-muted));font-size:10px}.ms-run-counts b{color:rgb(var(--content-secondary));font-weight:500}.ms-run-counts em{color:rgb(var(--status-warn));font-style:normal;margin-left:5px}
    .ms-detail{min-width:0;padding:24px 28px 64px;animation:ms-enter .18s ease-out both}.ms-detail.empty-detail{display:grid;place-items:center;color:rgb(var(--content-muted))}.empty-detail div{display:flex;flex-direction:column;gap:4px;text-align:center}.ms-detail-head{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;padding-bottom:18px;border-bottom:1px solid rgb(var(--border-base))}.ms-eyebrow{color:rgb(var(--content-muted));font-size:10px;text-transform:uppercase;margin-bottom:6px}.ms-detail-head h2{font-size:24px;line-height:1.2;font-weight:500;margin:0}.ms-detail-head p{font:11px/1.4 ui-monospace,monospace;color:rgb(var(--content-muted));margin:6px 0 0;word-break:break-all}.ms-detail-actions{display:flex;align-items:center;gap:10px}.ioi-proof-link{font-size:12px}
    .ms-pill{display:inline-flex;align-items:center;height:20px;padding:0 7px;border:1px solid rgb(var(--border-base));border-radius:999px;color:rgb(var(--content-secondary));font-size:10px;white-space:nowrap}.ms-pill.ok{color:rgb(var(--status-ok));border-color:rgb(var(--status-ok)/.35)}.ms-pill.warn{color:rgb(var(--status-warn));border-color:rgb(var(--status-warn)/.35)}.ms-pill.danger{color:rgb(var(--status-danger));border-color:rgb(var(--status-danger)/.35)}
    .ms-facts{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:0;border-bottom:1px solid rgb(var(--border-base))}.ms-facts div{display:flex;flex-direction:column;gap:3px;padding:13px 12px 13px 0}.ms-facts span{color:rgb(var(--content-muted));font-size:10px;text-transform:uppercase}.ms-facts strong{font-size:12px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ms-run-metrics,.ms-supply{display:flex;align-items:stretch;margin-top:4px}.ms-run-metrics .ms-metric,.ms-supply .ms-metric{min-width:0;flex:1}
    .ms-section{padding-top:24px}.ms-section-title{display:flex;align-items:baseline;justify-content:space-between;gap:14px;margin-bottom:10px}.ms-section-title h3{font-size:13px;font-weight:500;margin:0}.ms-section-title span{color:rgb(var(--content-muted));font-size:11px}.ms-two-col{display:grid;grid-template-columns:minmax(0,1fr) minmax(260px,.72fr);gap:28px}
    .ms-work-list,.ms-person-list,.ms-challenges,.ms-op-list{border-top:1px solid rgb(var(--border-base))}.ms-work-row{padding:11px 0;border-bottom:1px solid rgb(var(--border-base))}.ms-work-main{display:grid;grid-template-columns:auto minmax(140px,1fr) auto;align-items:center;gap:10px}.ms-work-main strong{font-weight:500}.ms-work-meta{display:flex;gap:14px;padding:5px 0 0 69px;color:rgb(var(--content-muted));font-size:10px}.ms-claim-lineage{display:flex;flex-wrap:wrap;gap:6px;padding:8px 0 0 69px}.ms-claim-lineage>span{display:flex;align-items:center;gap:6px;padding:3px 7px 3px 3px;border:1px solid rgb(var(--border-base));border-radius:999px;background:rgb(var(--surface-03))}.ms-claim-lineage .ms-pill{height:18px}.ms-person{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid rgb(var(--border-base))}.ms-avatar{display:grid;place-items:center;width:28px;height:28px;border-radius:50%;background:rgb(var(--surface-03));color:rgb(var(--content-secondary));font-size:11px}.ms-person strong,.ms-person small{display:block}.ms-person strong{font-size:12px;font-weight:500}.ms-person small{color:rgb(var(--content-muted));font-size:10px;margin-top:2px}
    .ms-evidence{border-top:1px solid rgb(var(--border-base))}.ms-evidence-head,.ms-evidence-row{display:grid;grid-template-columns:minmax(170px,1.3fr) 100px minmax(130px,1fr) 110px;align-items:center;gap:12px;padding:9px 0;border-bottom:1px solid rgb(var(--border-base))}.ms-evidence-head{color:rgb(var(--content-muted));font-size:10px;text-transform:uppercase}.ms-evidence-row>span:first-child b,.ms-evidence-row>span:first-child small{display:block}.ms-evidence-row b{font-size:11px;font-weight:500}.ms-evidence-row small,.ms-evidence-row time{color:rgb(var(--content-muted));font-size:10px}.ms-challenge{display:grid;grid-template-columns:auto minmax(160px,1fr) auto;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid rgb(var(--border-base))}.ms-challenge.unresolved{box-shadow:inset 2px 0 0 rgb(var(--status-warn));padding-left:10px}.ms-challenge strong,.ms-challenge small{display:block}.ms-challenge strong{font-size:12px;font-weight:500}.ms-challenge small{font-size:10px;color:rgb(var(--content-muted));margin-top:2px}.ms-boundary,.ms-contract{color:rgb(var(--content-muted));font-size:11px}.ms-contract{margin-top:26px;padding-top:14px;border-top:1px solid rgb(var(--border-base))}
    .ms-empty{display:flex;flex-direction:column;gap:4px;padding:22px;color:rgb(var(--content-muted))}.ms-empty.compact{padding:14px 0;border-top:1px solid rgb(var(--border-base))}.ms-empty b{color:rgb(var(--content-secondary));font-weight:500}.ms-plane-error{padding:11px 12px;border-left:2px solid rgb(var(--status-warn));background:rgb(var(--status-warn)/.06);color:rgb(var(--content-secondary));font-size:11px}.ms-op-row{display:grid;grid-template-columns:minmax(180px,1fr) 100px 120px 80px;align-items:center;gap:12px;padding:9px 0;border-bottom:1px solid rgb(var(--border-base))}.ms-op-row b,.ms-op-row small{display:block}.ms-op-row b{font-size:11px;font-weight:500}.ms-op-row small,.ms-op-row time{font-size:10px;color:rgb(var(--content-muted))}.ms-legacy{padding:0 28px 48px;border-top:1px solid rgb(var(--border-base))}
    @keyframes ms-enter{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}@media(max-width:980px){.ms-workspace{grid-template-columns:1fr}.ms-sidebar{border-right:0}.ms-detail{padding:22px 18px}.ms-facts{grid-template-columns:repeat(2,minmax(0,1fr))}.ms-two-col{grid-template-columns:1fr}.ms-summary{max-width:100%;min-width:0;overflow-x:auto}.ms-evidence-head,.ms-evidence-row{grid-template-columns:minmax(150px,1fr) 90px 100px}.ms-evidence-head span:nth-child(3),.ms-evidence-row code{display:none}}@media(max-width:640px){.ms-top{height:auto;min-height:64px;padding:12px 14px;align-items:flex-start;flex-wrap:wrap;gap:8px}.ms-title span{display:none}.ms-actions{width:100%;flex-wrap:wrap}.ms-actions .ms-action:first-child{display:none}.ms-summary,.ms-tabs{padding-left:14px;padding-right:14px}.ms-detail-head{flex-direction:column}.ms-detail-actions{width:100%;justify-content:space-between}.ms-work-meta,.ms-claim-lineage{padding-left:0;flex-wrap:wrap}.ms-legacy{padding-left:18px;padding-right:18px}.ms-op-row{grid-template-columns:1fr auto}.ms-op-row time,.ms-op-row>a{display:none}}
  `;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Missions · Hypervisor</title><style>${CSS}</style></head><body><div class="ms-shell">${globalRail}<main class="ms-main" data-missions-work-graph="goal-runs">
    <header class="ms-top"><div class="ms-title"><h1>Missions</h1><span>Goal runs and their results</span></div><div class="ms-actions"><a class="ms-action" href="${selectionQuery(ROUTE, { goal: selectedRef, status: status === "all" ? "" : status })}">Refresh</a></div></header>
    <div class="ms-summary">${metric("goal runs", planeCount(model.goalRuns))}${metric("open", planeCount(model.goalRuns, openRuns))}${metric("results", planeCount(model.results))}${metric("blocked runs", planeCount(model.goalRuns, blockedRuns), blockedRuns.length ? "danger" : "")}${metric("unattributed results", model.results.ok && model.goalRuns.ok ? model.unattributedResults : "—")}</div>
    ${planeNotice("GoalRun plane", model.goalRuns)}
    ${planeNotice("WorkResult plane", model.results)}
    <nav class="ms-tabs" role="tablist" aria-label="Goal run status filters">${filters}</nav>
    <div class="ms-workspace"><aside class="ms-sidebar"><div class="ms-sidebar-head"><span>Goal runs</span><span>${planeCount(model.goalRuns, runs)}</span></div>${renderRunList(runs, selectedRef, status, model)}</aside>${renderRunDetail(selected, model, selectionProblem)}</div>
    ${renderLegacyOperations(model)}
  </main></div></body></html>`;
}

// Read-only-by-contract: no actions and no handleAction export.
export const actions = [];
