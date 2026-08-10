// Automations — the canonical /automations surface packet (W2.1 §5 PR 1, next-legs II Leg 4).
//
// One module, two mounts (canonical /automations + the fresh legacy lane
// /__ioi/automations-cockpit), REHOMING the T2 cockpit grammar READ-FIRST over the daemon
// automations family: spec list (project-first cards), spec detail (spec grid, read-only
// pipeline projection, steps, run history, webhook trigger band, canvas), and the New-automation
// form — every read through the shared read client (typed degradation, honest-empty, zero
// fixture rows).
//
// VERBS — only what the daemon actually owns, and only through the lanes that already own them.
// The family's owned verb set (hypervisor-daemon.rs router, orchestration_routes.rs):
//   create            POST   /v1/hypervisor/automations            (project_ref REQUIRED)
//   patch             PATCH  /v1/hypervisor/automations/:id        (pause/resume = {enabled};
//                                                                   there is NO separate
//                                                                   activate/pause route — the
//                                                                   enabled flag IS the lane)
//   delete            DELETE /v1/hypervisor/automations/:id
//   run now           POST   /v1/hypervisor/automations/:id/runs   (alias :id/start)
//   run history       GET    /v1/hypervisor/automations/:id/runs
//   webhook trigger   POST   /v1/hypervisor/automations/:id/webhook (own-token auth)
//   webhook rotate    POST   /v1/hypervisor/automations/:id/webhook-rotate (show-once token)
//   webhook events    GET    /v1/hypervisor/automations/:id/webhook-events (receipted rows)
//   execution read    GET    /v1/hypervisor/automation-executions/:id (+ POST :id/cancel)
// The rendered forms post to the seed cockpit's OWN action lanes (/__ioi/automations…) — the
// wiring the T2 grammar ships today. This packet adds NO second mutation path: spec mutations on
// this family cross UNRECEIPTED (the daemon returns {ok, automation} with no admission
// envelope), which is the brief's NAMED DEFECT (surfaces/automations.md §6 — the fix is the W2
// lease-client wave WITH the daemon receipt family, never a surface-side invention). Declaring
// module actions would launder that gap through the fail-closed action runtime; stating it is
// the honest ceiling of this leg.
//
// TYPED ABSENCES stated, never simulated:
//   - spec versioning/revisions: NO daemon route (HypervisorAutomationSpec revisioning +
//     AutomationInstallationBinding are the W3 backend build, canon :3856-3897) — the Versions
//     control renders disabled with the machine-readable reason.
//   - run→Session/GoalRun lineage: execution records carry environment_id only (no
//     session_refs/goal_run_refs, no subject_attachments anywhere in daemon code) — the lineage
//     control renders disabled naming the W3 lineage build.
//   - monitor grammar (condition-over-object-set → effect): trigger kinds are
//     manual/time/webhook only; no object-set trigger family exists — named on the list band.
//
// BOUNDARIES held:
//   - Scheduler HEALTH is Operations-owned (/__ioi/operations + /v1/hypervisor/scheduler/status)
//     — this surface renders NO scheduler-health rows (no liveness, no heartbeat, no tick data);
//     per-spec schedule fields (schedule_spec/next_run_at/last_run_at) are spec truth and stay.
//   - Monitors ("Automate") stays a LINK to the protected seed route /__ioi/automations/monitors.
//   - Machinery/process-graphs stay OUT entirely — OQ-2 (machinery ownership) is unruled; no
//     registry transfer, no state-machines read, no rehome here.
import { escHtml } from "../kit.mjs";

const esc = escHtml;
const enc = encodeURIComponent;
const LEGACY_ROUTE = "/__ioi/automations-cockpit";
const CANONICAL_ROUTE = "/automations";
// The seed cockpit's wired action lanes (seed preservation: these keep serving until the W4
// cutover and are the ONLY mutation path this packet renders — no second spine).
const SEED_LANE = "/__ioi/automations";

export const meta = {
  slug: "automations",
  route: LEGACY_ROUTE,
  verifier: "scripts/verify-hypervisor-automations-journey.mjs",
  certification: "n/a",
};

const VERSIONS_GAP_REASON = "no daemon route exists — the automations family owns no spec revisioning/versions route (flat mutable ioi.hypervisor.automation-workflow.v1 record; content-hashed revisions + registry_status + AutomationInstallationBinding are the W3 backend build per surfaces/automations.md §5); typed absence, never simulated";
const LINEAGE_GAP_REASON = "no daemon fields exist — automation-execution records carry environment_id only (no session_refs/goal_run_refs, no subject_attachments row anywhere in daemon code); run→Session/GoalRun lineage is the W3 lineage build; typed absence, never simulated";
const MONITOR_GRAMMAR_GAP_REASON = "no daemon route exists — trigger kinds are manual/time/webhook only; the condition-over-object-set trigger family (over /v1/hypervisor/odk/materialized-object-sets) and the effect library are the W3 monitor-grammar build; the wizard stays on the protected monitors seed, disabled in place";
const UNRECEIPTED_DEFECT_NOTE = "Named defect (W2 pull): spec mutations on this family cross UNRECEIPTED — the daemon answers {ok, automation} with no admission receipt. The verbs above post through the seed cockpit lanes (the wiring that exists); the W2 lease-client wave lands receipts WITH the daemon receipt family. Nothing here invents a second mutation path.";

// ---------------------------------------------------------------------------------------------
// load — every read is a typed-degradation projection through the shared read client, riding the
// request-scoped daemon capability when the runtime supplies one (the caller's own envelope is
// the read identity; anonymous stays anonymous — under the family's current loopback-dev posture
// reads answer unauthenticated, and that truth is recorded as the journey verifier's FINDING row,
// never masked here).
export async function load(ctx) {
  const { createReadClient } = await import("../read-client.mjs");
  const client = typeof ctx.daemonFetch === "function"
    ? createReadClient({ daemon: "", fetchImpl: ctx.daemonFetch })
    : createReadClient({ daemon: ctx.daemon });
  const sp = ctx.url.searchParams;
  const model = {
    project: (sp.get("project") || "").trim(),
    automationId: (sp.get("automation") || "").trim(),
    view: (sp.get("view") || "").trim(),
  };
  model.projects = await client.read("/v1/hypervisor/projects");
  if (model.view === "new") return model;
  if (model.automationId) {
    model.automation = await client.read(`/v1/hypervisor/automations/${enc(model.automationId)}`);
    model.runs = await client.read(`/v1/hypervisor/automations/${enc(model.automationId)}/runs`);
    model.webhookEvents = await client.read(`/v1/hypervisor/automations/${enc(model.automationId)}/webhook-events`);
    return model;
  }
  model.automations = await client.read(`/v1/hypervisor/automations${model.project ? `?project_ref=${enc(model.project)}` : ""}`);
  return model;
}

// ---------------------------------------------------------------------------------------------
// render helpers — the cockpit grammar's own vocabulary plus the packet's typed-degradation and
// disabled-named-gap fragments.
const degraded = (result) => `<div class="empty">unavailable — <code>${esc(result?.code || "daemon_unavailable")}</code> (${esc(result?.message || "the plane did not answer")})</div>`;
const disabledCtl = (label, reason) => `<button class="act ghost" type="button" disabled data-ioi-disabled-reason="${esc(reason)}">${esc(label)}</button>`;
const rowsOf = (result, key) => (result?.ok ? (Array.isArray(result.payload?.[key]) ? result.payload[key] : []) : null);

function projectsById(model) {
  const byId = {};
  for (const p of rowsOf(model.projects, "projects") || []) byId[p.project_id] = p;
  return byId;
}
function projectName(a, byId) {
  const pid = a.project_ref || a.project_id || "";
  return (byId[pid] && byId[pid].name) || pid || "—";
}
function scheduleHuman(sched) {
  if (!sched || typeof sched !== "object") return "manual (no schedule)";
  if (sched.type === "cron" || sched.cron) return `cron ${sched.cron} (${sched.timezone || "UTC"})`;
  if (sched.every_hours) return `every ${sched.every_hours}h`;
  if (sched.every_minutes) return `every ${sched.every_minutes}m`;
  if (sched.every_seconds || sched.interval_seconds) return `every ${sched.every_seconds || sched.interval_seconds}s`;
  return "scheduled";
}
// The one boundary note this surface renders about scheduling health — a LINK, never data rows.
const OPERATIONS_BOUNDARY_NOTE = `<p class="sub" style="margin:14px 0 0">Scheduler health is <b>Operations-owned</b> — tick heartbeat and execution-health rows render on <a href="/__ioi/operations">Operations</a>, never here. The schedule fields on each spec (its own <code>schedule_spec</code> / next / last run) are spec truth and stay.</p>`;

// ---- list view ----------------------------------------------------------------------------------
function listView(model, base) {
  const byId = projectsById(model);
  const automations = rowsOf(model.automations, "automations");
  const filtName = model.project ? projectName({ project_ref: model.project }, byId) : "";
  const newHref = `${base}?view=new${model.project ? `&project=${enc(model.project)}` : ""}`;
  const count = automations === null ? 0 : automations.length;
  // Owner-surface contract preserved from the T2 readout: daemon automation records are the truth
  // (real specs, triggers, steps, projects); the captured monitor wizard is a SECONDARY reference
  // grammar — a linked walkthrough, never rows here.
  const head = `<h1 id="automations-owner">Automations</h1>
    <p class="sub">Durable orchestration — each automation is a daemon-owned spec that hangs off a project, runs over a real environment, and records a tamper-evident transcript. The <b>${count}</b> record${count === 1 ? "" : "s"} below ${model.project ? `(filtered to <b>${esc(filtName)}</b> · <a href="${base}">show all</a>)` : "across all projects"} are daemon truth. <span class="sub">The <a href="/__ioi/automations/monitors">Automate overview →</a> is the certified reference-faithful landing over this same plane (#51). The <a href="/__apps/monitors">monitor-wizard capture ↗</a> is a secondary reference grammar for authoring condition→effect monitors — a linked walkthrough, not a rebound surface; its example rows are never shown here as daemon automations.</span></p>
    <div class="row"><a class="act" href="${newHref}">+ New automation</a><a class="act ghost" href="/__apps/monitors">Monitor-wizard capture (reference) →</a></div>`;
  let body = "";
  if (automations === null) {
    body = degraded(model.automations);
  } else if (!automations.length) {
    body = `<div class="empty">No daemon automations yet${model.project ? " for this project" : ""} — create one to get started. (The monitor-wizard capture stays a reference; it never fabricates automations here.)</div>`;
  } else {
    body = automations.map((a) => {
      const enabled = a.enabled !== false;
      const steps = Array.isArray(a.steps) ? a.steps.length : 0;
      const model_ = a.model || "default model";
      const trigger = (a.trigger && (a.trigger.kind || a.trigger.trigger_kind)) || a.trigger_kind || "manual";
      return `<a class="card automation-card" href="${base}?automation=${enc(a.automation_id)}"><div class="main">
        <div class="name">${esc(a.name || a.automation_id)}<span class="pill ${enabled ? "ok" : "muted"}">${enabled ? "enabled" : "disabled"}</span><span class="pill muted">${esc(trigger)}</span></div>
        <div class="meta">${esc(projectName(a, byId))} · ${esc(String(model_))} · ${steps} step${steps === 1 ? "" : "s"} · <code style="font-size:10.5px">${esc(a.automation_id)}</code></div>
        </div><span class="act ghost">Open →</span></a>`;
    }).join("");
  }
  const gaps = `<h2 id="named-absences">What this family does not own yet</h2>
    <div class="gapcard">
      ${disabledCtl("Versions", VERSIONS_GAP_REASON)} ${disabledCtl("Monitor wizard (condition → effect)", MONITOR_GRAMMAR_GAP_REASON)}
      <p class="sub" style="margin:8px 0 0;text-transform:none;letter-spacing:0">There is no separate activate/pause route either — pause/resume IS <code>PATCH {enabled}</code> on the spec, the family's own lane, wired on each detail page. ${esc(UNRECEIPTED_DEFECT_NOTE)}</p>
    </div>${OPERATIONS_BOUNDARY_NOTE}`;
  return head + body + gaps;
}

// ---- detail view --------------------------------------------------------------------------------
function detailView(model, base) {
  const d = model.automation;
  if (!d?.ok) return `<h2>Automation ${esc(model.automationId)}</h2>${degraded(d)}`;
  if (d.payload?.ok === false || !d.payload?.automation) {
    return `<p><a href="${base}">← Automations</a></p><h1>Automation not found</h1><div class="empty">not found — <code>${esc(d.payload?.reason || d.payload?.error?.code || "automation not found")}</code>. Nothing is inferred; the id may have been deleted.</div>`;
  }
  const a = d.payload.automation;
  const byId = projectsById(model);
  const runs = rowsOf(model.runs, "runs");
  const id = a.automation_id;
  const enabled = a.enabled !== false;
  const pid = a.project_ref || a.project_id || "";
  const v = (x) => (x == null || x === "" ? "—" : (typeof x === "string" ? esc(x) : esc(JSON.stringify(x))));
  const connectors = Array.isArray(a.connector_refs) && a.connector_refs.length ? a.connector_refs.map((c) => `<code>${esc(String(c))}</code>`).join(" ") : "—";
  const steps = Array.isArray(a.steps) && a.steps.length
    ? `<h2>Steps</h2>` + a.steps.map((s, i) => `<div class="card"><div class="main"><div class="name">${i + 1}. ${esc(s.kind || "step")}</div><div class="meta"><code>${esc((s.prompt || s.command || s.title || "").slice(0, 200))}</code></div></div></div>`).join("")
    : `<h2>Steps</h2><div class="empty">No steps declared.</div>`;
  // Read-only pipeline projection (the 09-pipeline-builder grammar donation): trigger → declared
  // steps → latest run outcome → proof. Rendered from spec + run records only.
  const latest = (runs || [])[0];
  const pnodes = [
    [`trigger · ${a.trigger_kind || "manual"}`, "muted"],
    ...(Array.isArray(a.steps) ? a.steps.map((s, i) => [`${i + 1} · ${s.kind || "step"}`, "ok"]) : []),
    latest ? [`last run · ${latest.status || "—"}`, latest.status === "done" ? "ok" : latest.status === "failed" ? "warn" : "muted"] : ["no runs yet", "muted"],
  ];
  const pipeline = `<div id="auto-pipeline" style="margin:0 0 16px"><div class="sub" style="margin:0 0 6px;text-transform:uppercase;letter-spacing:.04em;font-size:11px">Pipeline <span style="text-transform:none;letter-spacing:0">— read-only view of the declared spec; the authoring canvas below edits via the daemon, it does not become the automation</span></div>
    <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">${pnodes.map(([label, cls], i) => `${i ? `<span style="color:#5f626b">→</span>` : ""}<span class="pill ${cls}" style="padding:5px 12px">${esc(label)}</span>`).join("")}${latest ? ` <a href="/__ioi/run-timeline/${enc(latest.execution_id || "")}" target="_blank" rel="noopener" style="margin-left:6px">proof ↗</a>` : ""}</div></div>`;
  const runRows = runs === null
    ? degraded(model.runs)
    : (runs.length
      ? `<table><thead><tr><th>Run</th><th>Status</th><th>Started</th><th>Steps (done/failed)</th><th>Proof</th></tr></thead><tbody>` +
        runs.map((r) => {
          const c = r.counts || {};
          const st = r.status || "—";
          const pill = st === "done" ? "ok" : st === "failed" ? "warn" : "muted";
          return `<tr><td><code>${esc(r.execution_id || "")}</code></td><td><span class="pill ${pill}">${esc(st)}</span></td><td>${esc(r.started_at || "")}</td><td>${c.done || 0}/${c.failed || 0}</td><td><a href="/__ioi/run-timeline/${enc(r.execution_id || "")}" target="_blank" rel="noopener">timeline ↗</a></td></tr>`;
        }).join("") + `</tbody></table>`
      : `<div class="empty">No runs yet — use “Run now”.</div>`);
  const runGaps = `<div class="gapcard" style="margin-top:14px">
      ${disabledCtl("Serving Session / GoalRun lineage", LINEAGE_GAP_REASON)} ${disabledCtl("Versions", VERSIONS_GAP_REASON)}
    </div>`;
  const sched = a.schedule_spec && typeof a.schedule_spec === "object" ? a.schedule_spec : null;
  const schedHuman = scheduleHuman(sched);
  const back = `<p><a href="${base}${pid ? `?project=${enc(pid)}` : ""}">← Automations</a></p>`;
  // Lifecycle verbs — the daemon-owned set, posted through the seed cockpit lanes (the wiring
  // that owns them today; the 302 lands on the legacy detail, the same grammar).
  const pauseResume = sched
    ? (enabled
        ? `<form class="inline" method="post" action="${SEED_LANE}/${enc(id)}/pause"><button class="act ghost" type="submit">⏸ Pause schedule</button></form>`
        : `<form class="inline" method="post" action="${SEED_LANE}/${enc(id)}/resume"><button class="act" type="submit">▶ Resume schedule</button></form>`)
    : "";
  const actions = `<div class="row">
    <form class="inline" method="post" action="${SEED_LANE}/${enc(id)}/run"><button class="act" type="submit">▶ Run now</button></form>
    ${pauseResume}
    <a class="act ghost" href="/projects/${enc(pid)}" target="_blank" rel="noopener">Open project ↗</a>
    <form class="inline" method="post" action="${SEED_LANE}/${enc(id)}/delete" onsubmit="return confirm('Delete this automation?')"><button class="act danger" type="submit">Delete</button></form>
  </div>`;
  const spec = `<dl class="grid">
    <dt>Project</dt><dd><a href="/projects/${enc(pid)}" target="_blank" rel="noopener">${esc(projectName(a, byId))}</a> <code>${esc(pid)}</code></dd>
    <dt>Trigger</dt><dd>${v(a.trigger_kind || "manual")}</dd>
    <dt>Schedule</dt><dd>${esc(schedHuman)}${sched ? ` · ${enabled ? "active" : "paused"}` : ""}</dd>
    <dt>Next run</dt><dd>${v(a.next_run_at)}</dd>
    <dt>Last run</dt><dd>${v(a.last_run_at)}</dd>
    <dt>Agent</dt><dd>${v(a.agent_ref)}</dd>
    <dt>Model</dt><dd>${v(a.model)}</dd>
    <dt>Reasoning</dt><dd>${v(a.reasoning)}</dd>
    <dt>Harness</dt><dd>${v(a.harness_profile_ref)}</dd>
    <dt>Connectors</dt><dd>${connectors}</dd>
    <dt>Memory</dt><dd>${v(a.memory_profile_ref)}</dd>
    <dt>Authority policy</dt><dd>${v(a.authority_policy_ref)}</dd>
    <dt>Runtime policy</dt><dd>${v(a.default_runtime_policy_ref)}</dd>
    <dt>Env class</dt><dd>${v(a.environment_class_id)}</dd>
  </dl>`;
  // Webhook trigger band — endpoint + receipted event feed reads; rotate stays show-once on the
  // seed lane (the secret is revealed exactly once there and only its hash persists).
  const wev = model.webhookEvents?.ok ? model.webhookEvents.payload : null;
  const evRows = ((wev?.events) || []).slice(0, 10).map((e) => {
    const acc = e.accepted === true;
    return `<tr><td>${esc(e.received_at || "")}</td><td><span class="pill ${acc ? "ok" : "warn"}">${acc ? "accepted" : "rejected"}</span></td><td>${esc(e.reason || "")}</td><td>${e.receipt_id ? `<code>${esc(e.receipt_id)}</code>` : "—"}</td><td>${e.run_ref ? `<a href="/__ioi/run-timeline/${enc(e.run_ref)}" target="_blank" rel="noopener">timeline ↗</a>` : "—"}</td></tr>`;
  }).join("");
  const eventsTable = model.webhookEvents?.ok
    ? (evRows ? `<table><thead><tr><th>Received</th><th>Result</th><th>Reason</th><th>Receipt</th><th>Run</th></tr></thead><tbody>${evRows}</tbody></table>` : `<div class="empty">No trigger events yet.</div>`)
    : degraded(model.webhookEvents);
  const webhookSection = a.webhook_url
    ? `<h2>Webhook trigger</h2>
       <dl class="grid">
         <dt>Endpoint</dt><dd><code>POST ${esc(a.webhook_url)}</code></dd>
         <dt>Auth</dt><dd>header <code>X-IOI-Trigger-Token: &lt;secret&gt;</code> · secret shown once on rotate</dd>
         <dt>Triggers</dt><dd>${wev ? `${wev.accepted_count || 0} accepted · ${wev.rejected_count || 0} rejected` : "—"}</dd>
       </dl>
       <div class="row"><form class="inline" method="post" action="${SEED_LANE}/${enc(id)}/webhook-rotate"><button class="act ghost" type="submit">↻ Rotate secret</button></form></div>
       ${eventsTable}`
    : `<h2>Webhook trigger</h2><p class="sub">Trigger this automation from an external service with an authenticated webhook (the secret is sealed; only its hash is stored — it is shown exactly once, on the rotate reveal).</p>
       <form class="inline" method="post" action="${SEED_LANE}/${enc(id)}/webhook-rotate"><button class="act" type="submit">Enable webhook trigger</button></form>`;
  // Canvas — the spec editor projection, rehomed with its seed wiring: saves PATCH the daemon
  // record through the seed lane (the family's owned patch verb; unreceipted — the named defect).
  const schedType = sched ? ((sched.type === "cron" || sched.cron) ? "cron" : "interval") : "manual";
  const intN = sched ? (sched.every_hours || sched.every_minutes || sched.every_seconds || sched.interval_seconds || "") : "";
  const intU = sched ? (sched.every_hours ? "hours" : (sched.every_seconds || sched.interval_seconds) ? "seconds" : "minutes") : "minutes";
  const cronExpr = sched && sched.cron ? sched.cron : "";
  const cronTz = (sched && sched.timezone) || "UTC";
  const cronTzOpts = ["UTC", "-08:00", "-07:00", "-06:00", "-05:00", "-04:00", "+01:00", "+02:00", "+05:30", "+08:00", "+09:00", "+10:00"]
    .map((z) => `<option value="${z}"${z === cronTz ? " selected" : ""}>${z === "UTC" ? "UTC (+00:00)" : "UTC" + z}</option>`).join("");
  const lastRun = (runs && runs[0]) || null;
  const runCls = lastRun ? (lastRun.status === "done" ? "ok" : lastRun.status === "failed" ? "warn" : "") : "";
  const triggerSummary = schedHuman + (a.webhook_url ? " + webhook" : "");
  const agentSummary = `${a.model || "default model"}${a.reasoning ? " · " + a.reasoning : ""}`;
  const connSummary = Array.isArray(a.connector_refs) && a.connector_refs.length ? a.connector_refs.join(", ") : "none";
  const memSummary = a.memory_profile_ref || "default";
  const authSummary = a.authority_policy_ref || "default";
  const stepCount = Array.isArray(a.steps) ? a.steps.length : 0;
  const deliverySummary = `${stepCount} step${stepCount === 1 ? "" : "s"}${lastRun ? " · last run " + (lastRun.status || "") : ""}`;
  const cnode = (key, icon, title, summary, cls) => `<div class="cnode ${cls || ""}" data-node="${key}" onclick="ioiNode('${key}')"><div class="ct">${icon} ${esc(title)}</div><div class="cs">${esc(summary)}</div></div>`;
  const cgraph = `<div class="cgraph">
    <div class="clane">${cnode("trigger", "⏱", "Trigger", triggerSummary, runCls)}</div><div class="cedge">→</div>
    <div class="clane">${cnode("agent", "🤖", "Agent run", agentSummary, runCls)}</div><div class="cedge">→</div>
    <div class="clane">${cnode("connectors", "🔌", "Connectors", connSummary, "")}${cnode("memory", "🧠", "Memory", memSummary, "")}${cnode("authority", "🛡", "Authority", authSummary, "")}</div><div class="cedge">→</div>
    <div class="clane">${cnode("delivery", "📤", "Delivery", deliverySummary, "")}</div>
  </div>`;
  const fi = (cid, label, value, ph) => `<div class="field"><label>${label}</label><input id="${cid}" value="${esc(value || "")}" placeholder="${ph || ""}"></div>`;
  const firstStep = (Array.isArray(a.steps) && a.steps[0]) || {};
  const inspectors =
    `<div class="cinsp" id="insp-trigger" style="display:none"><h3>Trigger</h3>
       <div class="field"><label>Type</label><select id="cv-sched-type" onchange="cvSchedToggle()"><option value="manual"${schedType === "manual" ? " selected" : ""}>Manual only</option><option value="interval"${schedType === "interval" ? " selected" : ""}>Interval</option><option value="cron"${schedType === "cron" ? " selected" : ""}>Cron</option></select></div>
       <div id="cv-int" style="display:${schedType === "interval" ? "block" : "none"}"><div class="field"><label>Run every</label><input id="cv-interval-n" type="number" min="0" value="${schedType === "interval" ? esc(String(intN || 0)) : "15"}"></div><div class="field"><label>Unit</label><select id="cv-interval-unit"><option value="minutes"${intU === "minutes" ? " selected" : ""}>minutes</option><option value="hours"${intU === "hours" ? " selected" : ""}>hours</option><option value="seconds"${intU === "seconds" ? " selected" : ""}>seconds</option></select></div></div>
       <div id="cv-crn" style="display:${schedType === "cron" ? "block" : "none"}"><div class="field"><label>Cron</label><input id="cv-cron" value="${esc(cronExpr)}" placeholder="0 9 * * 1-5" oninput="cvCronPreview()"></div><div class="field"><label>Timezone</label><select id="cv-cron-tz" onchange="cvCronPreview()">${cronTzOpts}</select></div><div class="sub" style="margin:0" id="cv-cron-preview"></div></div>
       <div class="row"><button class="act" onclick="ioiNodeSave('trigger')">Save</button> <span class="cmsg" id="msg-trigger"></span></div></div>` +
    `<div class="cinsp" id="insp-agent" style="display:none"><h3>Agent run</h3>${fi("cv-model", "Model", a.model, "qwen2.5:7b")}<div class="field"><label>Reasoning</label><select id="cv-reasoning"><option value=""${!a.reasoning ? " selected" : ""}>(default)</option><option value="low"${a.reasoning === "low" ? " selected" : ""}>low</option><option value="medium"${a.reasoning === "medium" ? " selected" : ""}>medium</option><option value="high"${a.reasoning === "high" ? " selected" : ""}>high</option></select></div>${fi("cv-agent", "Agent ref", a.agent_ref, "agent:default")}${fi("cv-harness", "Harness profile", a.harness_profile_ref, "harness:…")}<div class="row"><button class="act" onclick="ioiNodeSave('agent')">Save</button> <span class="cmsg" id="msg-agent"></span></div></div>` +
    `<div class="cinsp" id="insp-connectors" style="display:none"><h3>Connectors</h3>${fi("cv-connectors", "Connector refs (comma-separated)", Array.isArray(a.connector_refs) ? a.connector_refs.join(", ") : "", "connector:github, connector:linear")}<div class="row"><button class="act" onclick="ioiNodeSave('connectors')">Save</button> <span class="cmsg" id="msg-connectors"></span></div></div>` +
    `<div class="cinsp" id="insp-memory" style="display:none"><h3>Memory</h3>${fi("cv-memory", "Memory profile ref", a.memory_profile_ref, "memory:project-default")}<div class="row"><button class="act" onclick="ioiNodeSave('memory')">Save</button> <span class="cmsg" id="msg-memory"></span></div></div>` +
    `<div class="cinsp" id="insp-authority" style="display:none"><h3>Authority</h3>${fi("cv-authority", "Authority policy ref", a.authority_policy_ref, "authority:operator")}${fi("cv-runtime", "Runtime policy ref", a.default_runtime_policy_ref, "runtime-policy:local")}<div class="row"><button class="act" onclick="ioiNodeSave('authority')">Save</button> <span class="cmsg" id="msg-authority"></span></div></div>` +
    `<div class="cinsp" id="insp-delivery" style="display:none"><h3>Delivery (first step)</h3><div class="field"><label>Step kind</label><select id="cv-step-kind"><option value="agent"${firstStep.kind !== "command" ? " selected" : ""}>agent (prompt)</option><option value="command"${firstStep.kind === "command" ? " selected" : ""}>command (shell)</option></select></div><div class="field"><label>Step body</label><textarea id="cv-step-body">${esc(firstStep.prompt || firstStep.command || "")}</textarea></div><div class="row"><button class="act" onclick="ioiNodeSave('delivery')">Save</button> <span class="cmsg" id="msg-delivery"></span></div></div>` +
    `<div class="cinsp" id="insp-none"><h3>Canvas</h3><p class="sub" style="margin:0">Click a node to edit it. Saving writes the automation spec via the daemon — the Canvas edits the automation, it does not become the automation.</p></div>`;
  const canvas = `<div class="canvas">${cgraph}<div>${inspectors}</div></div>`;
  const canvasScript = `<script>
    function ioiTab(t){['overview','runs','webhook','canvas'].forEach(function(k){var p=document.getElementById('panel-'+k);if(p)p.style.display=(k===t)?'block':'none';var b=document.querySelector('.tab[data-tab="'+k+'"]');if(b)b.classList.toggle('active',k===t);});}
    function val(id){var e=document.getElementById(id);return e?e.value:'';}
    function ioiNode(key){var none=document.getElementById('insp-none');if(none)none.style.display='none';['trigger','agent','connectors','memory','authority','delivery'].forEach(function(k){var n=document.querySelector('[data-node="'+k+'"]');if(n)n.classList.toggle('sel',k===key);var i=document.getElementById('insp-'+k);if(i)i.style.display=(k===key)?'block':'none';});}
    function cvSchedToggle(){var t=val('cv-sched-type'),i=document.getElementById('cv-int'),c=document.getElementById('cv-crn');if(i)i.style.display=t==='interval'?'block':'none';if(c)c.style.display=t==='cron'?'block':'none';}
    function cvCronPreview(){var c=(val('cv-cron')||'').trim(),tz=val('cv-cron-tz'),el=document.getElementById('cv-cron-preview');if(!el)return;if(!c){el.textContent='';return;}fetch('${SEED_LANE}/cron-preview?cron='+encodeURIComponent(c)+'&tz='+encodeURIComponent(tz)+'&n=3').then(function(r){return r.json();}).then(function(d){el.textContent=d.ok?('next: '+d.runs.join('  ·  ')):('⚠ '+d.error);});}
    function ioiNodeSave(node){var body={};
      if(node==='trigger'){var t=val('cv-sched-type');if(t==='interval'){var n=parseInt(val('cv-interval-n')||'0',10)||0,u=val('cv-interval-unit');body.schedule_spec=n>0?(u==='hours'?{every_hours:n}:u==='seconds'?{every_seconds:n}:{every_minutes:n}):null;}else if(t==='cron'){var cc=(val('cv-cron')||'').trim();body.schedule_spec=cc?{type:'cron',cron:cc,timezone:val('cv-cron-tz')}:null;}else{body.schedule_spec=null;}}
      else if(node==='agent'){body.model=val('cv-model')||null;body.reasoning=val('cv-reasoning')||null;body.agent_ref=val('cv-agent')||null;body.harness_profile_ref=val('cv-harness')||null;}
      else if(node==='connectors'){body.connector_refs=(val('cv-connectors')||'').split(',').map(function(s){return s.trim();}).filter(Boolean);}
      else if(node==='memory'){body.memory_profile_ref=val('cv-memory')||null;}
      else if(node==='authority'){body.authority_policy_ref=val('cv-authority')||null;body.default_runtime_policy_ref=val('cv-runtime')||null;}
      else if(node==='delivery'){var sk=val('cv-step-kind'),sb=(val('cv-step-body')||'').trim();body.steps=sb?[sk==='command'?{kind:'command',command:sb}:{kind:'agent',prompt:sb}]:[];}
      var msg=document.getElementById('msg-'+node);if(msg)msg.textContent='saving…';
      fetch('${SEED_LANE}/${enc(id)}/patch',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.json();}).then(function(d){if(d&&d.ok===false){if(msg)msg.textContent='⚠ '+((d.error&&d.error.message)||d.reason||'invalid');}else{location.reload();}}).catch(function(){if(msg)msg.textContent='save failed';});}
  </script>`;
  return `${back}<h1>${esc(a.name || id)}<span class="pill ${enabled ? "ok" : "muted"}">${enabled ? "enabled" : "disabled"}</span></h1>
    <p class="sub">${esc(a.description || "")}</p>${pipeline}${actions}
    <div class="tabs">
      <button class="tab active" data-tab="overview" onclick="ioiTab('overview')">Overview</button>
      <button class="tab" data-tab="runs" onclick="ioiTab('runs')">Runs</button>
      <button class="tab" data-tab="webhook" onclick="ioiTab('webhook')">Webhook</button>
      <button class="tab" data-tab="canvas" onclick="ioiTab('canvas')">Canvas</button>
    </div>
    <div class="tab-panel" id="panel-overview">${spec}${steps}${runGaps}${OPERATIONS_BOUNDARY_NOTE}</div>
    <div class="tab-panel" id="panel-runs" style="display:none"><h2>Run history</h2>${runRows}${runGaps}</div>
    <div class="tab-panel" id="panel-webhook" style="display:none">${webhookSection}</div>
    <div class="tab-panel" id="panel-canvas" style="display:none">${canvas}</div>
    ${canvasScript}`;
}

// ---- new-automation view ------------------------------------------------------------------------
function newView(model, base) {
  const projects = rowsOf(model.projects, "projects");
  const projectId = model.project;
  const backHref = `${base}${projectId ? `?project=${enc(projectId)}` : ""}`;
  if (projects === null) {
    return `<p><a href="${backHref}">← Automations</a></p><h1>New automation</h1>${degraded(model.projects)}<p class="sub">The project plane did not answer — an automation must hang off a project (<code>project_ref</code> is required), so the form is withheld rather than guessed.</p>`;
  }
  const opts = projects.map((p) => `<option value="${esc(p.project_id)}"${p.project_id === projectId ? " selected" : ""}>${esc(p.name || p.project_id)}</option>`).join("");
  const tzOptions = ["UTC", "-08:00", "-07:00", "-06:00", "-05:00", "-04:00", "+01:00", "+02:00", "+05:30", "+08:00", "+09:00", "+10:00"]
    .map((z) => `<option value="${z}">${z === "UTC" ? "UTC (+00:00)" : "UTC" + z}</option>`).join("");
  const projectField = projects.length
    ? `<div class="field"><label>Project (required — the automation's durable container)</label><select name="project_ref" required>${opts}</select></div>`
    : `<div class="field"><label>Project</label><input name="project_ref" value="${esc(projectId)}" placeholder="project:my-app" required></div>`;
  return `<p><a href="${backHref}">← Automations</a></p>
    <h1>New automation</h1><p class="sub">A project-scoped spec the daemon runs over a real environment. Start with one step; you can run it manually right away. The create posts through the seed cockpit lane — the daemon-owned create verb; the reply carries no admission receipt (the named W2 defect).</p>
    <form method="post" action="${SEED_LANE}">
      ${projectField}
      <div class="field"><label>Name</label><input name="name" placeholder="Nightly CONTRIBUTING note" required></div>
      <div class="field"><label>Description</label><input name="description" placeholder="What this automation does"></div>
      <div class="field"><label>Schedule</label>
        <select name="schedule_type" id="ioi-sched-type" onchange="ioiSchedToggle()">
          <option value="manual">Manual only</option>
          <option value="interval">Interval</option>
          <option value="cron">Cron</option>
        </select>
      </div>
      <div id="ioi-sched-interval" style="display:none">
        <div class="two">
          <div class="field"><label>Run every</label><input name="interval_n" type="number" min="0" value="15"></div>
          <div class="field"><label>Unit</label><select name="interval_unit"><option value="minutes">minutes</option><option value="hours">hours</option><option value="seconds">seconds</option></select></div>
        </div>
      </div>
      <div id="ioi-sched-cron" style="display:none">
        <div class="two">
          <div class="field"><label>Cron (min hour dom month dow)</label><input name="cron" id="ioi-cron-expr" placeholder="0 9 * * 1-5" oninput="ioiCronPreview()"></div>
          <div class="field"><label>Timezone</label><select name="cron_tz" id="ioi-cron-tz" onchange="ioiCronPreview()">${tzOptions}</select></div>
        </div>
        <div class="field"><label>Next runs (UTC)</label><div id="ioi-cron-preview" class="sub" style="margin:0">enter a cron expression…</div></div>
      </div>
      <div class="two">
        <div class="field"><label>Model</label><input name="model" placeholder="qwen2.5:7b"></div>
        <div class="field"><label>Reasoning</label><select name="reasoning"><option value="">(default)</option><option value="low">low</option><option value="medium">medium</option><option value="high">high</option></select></div>
      </div>
      <div class="two">
        <div class="field"><label>Max concurrency</label><input name="max_concurrency" type="number" min="1" value="1"></div>
        <div class="field"><label>On failure</label><select name="failure_policy"><option value="continue">continue scheduling</option><option value="disable">disable on failure</option></select></div>
      </div>
      <div class="field"><label>Agent ref</label><input name="agent_ref" placeholder="agent:default"></div>
      <div class="two">
        <div class="field"><label>Connector refs (comma-separated)</label><input name="connector_refs" placeholder="connector:github, connector:linear"></div>
        <div class="field"><label>Memory profile ref</label><input name="memory_profile_ref" placeholder="memory:project-default"></div>
      </div>
      <div class="two">
        <div class="field"><label>Step kind</label><select name="step_kind"><option value="agent">agent (prompt)</option><option value="command">command (shell)</option></select></div>
        <div class="field"><label>&nbsp;</label><div class="sub" style="margin:0;font-size:12px">First step runs when you click Run now.</div></div>
      </div>
      <div class="field"><label>Step body</label><textarea name="step_body" placeholder="e.g. Write a CONTRIBUTING.md for this repo."></textarea></div>
      <div class="row"><button class="act" type="submit">Create automation</button></div>
    </form>
    <script>
      function ioiSchedToggle(){var t=document.getElementById('ioi-sched-type').value;document.getElementById('ioi-sched-interval').style.display=(t==='interval')?'block':'none';document.getElementById('ioi-sched-cron').style.display=(t==='cron')?'block':'none';}
      function ioiCronPreview(){var c=document.getElementById('ioi-cron-expr').value.trim(),tz=document.getElementById('ioi-cron-tz').value,el=document.getElementById('ioi-cron-preview');if(!c){el.textContent='enter a cron expression…';return;}fetch('${SEED_LANE}/cron-preview?cron='+encodeURIComponent(c)+'&tz='+encodeURIComponent(tz)+'&n=3').then(function(r){return r.json();}).then(function(d){el.textContent=d.ok?('next: '+d.runs.join('  ·  ')):('⚠ '+d.error);}).catch(function(){el.textContent='preview unavailable';});}
    </script>`;
}

// ---------------------------------------------------------------------------------------------
export function render(model, ctx) {
  const base = ctx.url.pathname.startsWith("/__ioi/") ? LEGACY_ROUTE : CANONICAL_ROUTE;
  let title = "Automations";
  let inner = "";
  if (model.view === "new") {
    title = "New automation";
    inner = newView(model, base);
  } else if (model.automationId) {
    const record = model.automation?.ok && model.automation.payload?.automation ? model.automation.payload.automation : null;
    title = record?.name || "Automation";
    inner = detailView(model, base);
  } else {
    inner = listView(model, base);
  }
  // The seed cockpit shell's CSS, carried verbatim so the rehomed grammar keeps its pixels; the
  // legacy /__ioi/automations lanes keep their own copy untouched until the W4 cutover.
  const css = `:root{color-scheme:dark}
  body{margin:0;background:#0c0d10;color:#e6e7ea;font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
  .wrap{max-width:920px;margin:0 auto;padding:40px 24px 80px}
  a{color:#8ab4ff}
  .brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#6f7280;margin-bottom:8px}
  h1{font-size:26px;margin:0 0 6px;letter-spacing:-.02em}
  .sub{color:#9a9da6;margin:0 0 22px;max-width:680px}
  .row{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:0 0 22px}
  .act{padding:8px 14px;border-radius:8px;border:0;background:#fff;color:#111;font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
  .act:hover{background:#eee}
  .act.ghost{background:transparent;color:#cbd0da;border:1px solid #2a2c33}
  .act.ghost:hover{color:#fff;border-color:#3a3d45}
  .act.danger{background:transparent;color:#e06a6a;border:1px solid #5c2a2a}
  .act.danger:hover{background:#2a1212}
  .act[disabled]{opacity:.45;cursor:not-allowed}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#878a93;margin:26px 0 10px;font-weight:600}
  .card{display:flex;align-items:center;gap:14px;padding:14px 16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin-bottom:8px;text-decoration:none;color:inherit}
  a.card:hover{border-color:#3a82f6;background:#191b21}
  .card .main{flex:1;min-width:0}
  .card .name{font-weight:600;color:#fff}
  .card .meta{color:#878a93;font-size:12.5px;margin-top:3px}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;border:1px solid;white-space:nowrap;margin-left:8px}
  .ok{color:#46c277;border-color:#235c3b;background:#11281b}
  .warn{color:#d6a13a;border-color:#5c4a23;background:#28220f}
  .muted{color:#9a9da6;border-color:#2a2c33}
  .empty{color:#6f7280;padding:18px;border:1px dashed #24262d;border-radius:12px}
  .gapcard{padding:14px 16px;border:1px dashed #5c4a23;border-radius:12px;background:#15130c;margin:0 0 18px}
  .grid{display:grid;grid-template-columns:160px 1fr;gap:8px 16px;padding:16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin:0 0 18px}
  .grid dt{color:#878a93;font-size:12.5px}
  .grid dd{margin:0;color:#e6e7ea}
  code{font-size:11.5px;color:#aab;background:#0e0f13;padding:1px 5px;border-radius:4px}
  pre{background:#0e0f13;border:1px solid #24262d;border-radius:8px;padding:12px;overflow:auto;font:11.5px/1.5 ui-monospace,monospace;color:#cdd1d8;white-space:pre-wrap;word-break:break-all}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;color:#878a93;font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;padding:6px 10px;border-bottom:1px solid #24262d}
  td{padding:8px 10px;border-bottom:1px solid #1b1d23}
  .tabs{display:flex;gap:4px;border-bottom:1px solid #24262d;margin:22px 0 18px}
  .tab{background:transparent;border:0;border-bottom:2px solid transparent;color:#9a9da6;font:inherit;font-weight:600;padding:9px 14px;cursor:pointer}
  .tab:hover{color:#e6e7ea}
  .tab.active{color:#fff;border-bottom-color:#3a82f6}
  .canvas{display:grid;grid-template-columns:1fr 300px;gap:18px;align-items:start}
  .cgraph{display:flex;align-items:center;gap:6px;overflow-x:auto;padding:10px;border:1px solid #24262d;border-radius:12px;background:#101216;min-height:200px}
  .clane{display:flex;flex-direction:column;gap:10px}
  .cedge{color:#4a4d55;font-size:20px;flex:0 0 auto}
  .cnode{min-width:150px;max-width:180px;padding:11px 13px;border:1px solid #2a2c33;border-radius:10px;background:#15171c;cursor:pointer}
  .cnode:hover{border-color:#3a82f6}
  .cnode.sel{border-color:#3a82f6;box-shadow:0 0 0 1px #3a82f6 inset}
  .cnode.ok{border-left:3px solid #46c277}
  .cnode.warn{border-left:3px solid #d6a13a}
  .cnode .ct{font-weight:600;color:#fff;font-size:12.5px}
  .cnode .cs{color:#878a93;font-size:11.5px;margin-top:4px;word-break:break-word}
  .cinsp{padding:14px;border:1px solid #24262d;border-radius:12px;background:#15171c}
  .cinsp h3{margin:0 0 10px;font-size:13px}
  .cmsg{font-size:12px;color:#d6a13a}
  .field{margin:0 0 14px}
  .field label{display:block;color:#c7c9cf;font-size:12.5px;margin-bottom:5px}
  .field input,.field select,.field textarea{width:100%;box-sizing:border-box;padding:10px;border-radius:9px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit}
  .field textarea{min-height:84px;resize:vertical}
  .two{display:grid;grid-template-columns:1fr 1fr;gap:0 16px}
  form.inline{display:inline}
  @media(max-width:760px){.grid{grid-template-columns:120px 1fr}.canvas{grid-template-columns:1fr}table{display:block;overflow-x:auto;max-width:100%}}`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · Hypervisor</title><style>${css}</style></head><body><div class="wrap"><div class="brand">IOI Hypervisor</div>${inner}</div></body></html>`;
}
