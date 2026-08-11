// Operations — the canonical /operations PARTIAL PRE-W3 COCKPIT SLICE (next-legs V Leg 4).
//
// SCOPE RULING (bounds every claim in this file): this is NOT Operations completion.
// SURF-operations REMAINS OPEN — its manifest acceptance (detect an injected runtime/provider/
// storage fault, open a typed incident, preview authority, execute remediation/failover, emit
// receipts/events, verify owner-app readback, rehearse restart/rollback/support export) needs
// the W3.2 fault matrix and the W3.3 snapshot/archive/restore semantics, and its seed gate
// carries the scheduler residual. This slice delivers exactly: the canonical mount over a
// read-first cockpit composed from the daemon read families that EXIST TODAY, typed
// disabled-named-gaps for every W3.2/W3.3-owned action, and typed route-missing absences for
// the W3 rollup projections. Evidence: scripts/verify-hypervisor-operations-cockpit.mjs
// (check:operations-cockpit — deliberately NOT a "-journey": the Operations journey is
// SURF-operations' to earn behind W3.2/W3.3).
//
// SEED RESIDUAL, stated typed: the retained Scheduler capture in
// apps/hypervisor/seed-ux-provenance.v1.json is provenance-qualified but its stable replay
// renders Page-not-found, so the scheduler source stays typed-blocked in the seed gate — a
// block record never opens work, and neither the error page nor the canonical shell is ever
// substituted for the seed. Scheduler OBJECT truth (schedules, triggers, concurrency, failure
// policy) is Automations-owned; scheduler HEALTH is Operations-owned — both renders below hold
// that split. The T2 readout at /__ioi/operations is the rehome source and keeps serving
// untouched (seed-preservation invariant).
//
// TYPED W3 ABSENCES stated, never simulated (surfaces/operations.md §2 route-missing rows):
//   - unified infrastructure-jobs projection (subjects via subject_attachments) — no such
//     route exists; this page composes per-family reads and never merges them into a
//     fabricated jobs rollup;
//   - RPO/RTO + degraded/partition posture rollup — route-missing;
//   - capacity/utilization overview — route-missing (pool fields exist; no overview route).
//
// READ-FIRST BY CONTRACT: this slice declares zero actions. Canon: "Operations performs
// admitted provider, placement, fencing, failover, and member actions" — but every such verb
// on this estate is W3.2/W3.3-owned acceptance surface (fault injection, remediation,
// failover execution, archive custody ops), so each renders as a typed disabled-named-gap
// naming the daemon routes that exist, the reason, and the owning unit. Automation-run
// remediation (re-run/pause/resume) is Automations-owned authority and its canonical mount is
// live — those render as LIVE deep-links to /automations, never as gaps and never as verbs
// minted here. The per-plane availability idiom is contract: an unavailable plane renders
// "unknown, not zero", and a full daemon outage renders a typed unavailability page with zero
// fabricated counts (the canon fallback-fixture rule, api.md:167-169).
import { escHtml } from "../kit.mjs";

const esc = escHtml;

const LEGACY_ROUTE = "/__ioi/operations-cockpit";
const CANONICAL_ROUTE = "/operations";

// The protected T2 rehome source — keeps serving untouched until the W4 cutover.
const SEED_READOUT = "/__ioi/operations";
// LIVE deep-link targets on this estate (bound canonical mounts).
const LINK_AUTOMATIONS = "/automations";
const LINK_WORK = "/work";

const SCOPE_MARKER = "partial-pre-w3-cockpit-slice";
const SCOPE_NOTE = "Partial pre-W3 cockpit slice — NOT Operations completion. SURF-operations remains open: its full acceptance (injected-fault detection, typed incident open, authority preview, remediation/failover execution, receipts, readback, restart/rollback/support export) is W3.2/W3.3-owned, and its seed gate carries the typed-blocked scheduler residual. This slice composes only the daemon read families that exist today.";

const JOBS_ROLLUP_ABSENCE = "typed W3 absence — no unified infrastructure-jobs projection route exists at the daemon (route-missing; surfaces/operations.md §2). The W3 build binds job subjects via subject_attachments; until it lands this page renders each family separately and never merges them into a fabricated jobs rollup.";
const RPO_RTO_ABSENCE = "typed W3 absence — no RPO/RTO + degraded/partition posture rollup route exists at the daemon (route-missing). Composable posture stays per-family (failover, incidents, substrate); a rollup this page invented would be a simulated projection, so none renders.";
const CAPACITY_ABSENCE = "typed W3 absence — no capacity/utilization overview route exists at the daemon (route-missing). Resource-pool records carry capacity fields, but the cross-pool overview is the W3 projection's to mint; this page will not derive one.";

const FAULT_REMEDIATION_GAP = "disabled-named-gap — owning unit W3.2 (runtime-node and provider execution, admission, health, recovery: the fault matrix). SURF-operations' acceptance opens a typed incident and executes remediation against an injected runtime/provider/storage fault; no typed incident-open or infrastructure-remediation verb is wired on this pre-W3 slice. The environment incident records below are REAL daemon reads (GET /v1/hypervisor/incidents · GET /v1/hypervisor/recovery-attempts); only the authority-crossing verbs wait on W3.2.";
const FAILOVER_EXECUTION_GAP = "disabled-named-gap — owning unit W3.2 (with the W3.3 restore ladder behind it). The daemon owns POST /v1/hypervisor/failover/run, POST /v1/hypervisor/failover/plans/:id/arm|disarm and POST /v1/hypervisor/failover/evaluate today, and every run parks wallet-gated at awaiting_authority_* — never automatic authority. This pre-W3 slice wires no authority-crossing verb: failover execution is SURF-operations acceptance surface that lands with the W3.2/W3.3 fault-injection/remediation matrix. The run and plan records below are REAL daemon reads.";
const ARCHIVE_CUSTODY_GAP = "disabled-named-gap — owning unit W3.3 (snapshot, archive, backup, storage-profile, export, restore semantics). The daemon owns POST /v1/hypervisor/storage-archive-ops (export/verify/restore/repair, sealed-before-write, wallet-gated crossing) and the storage-backend credential/preflight lanes today; this pre-W3 slice wires none of them — a fresh-daemon restore with custody, retention, and deletion proof is W3.3's acceptance. The backend and incident records below are REAL daemon reads.";

const SCHEDULER_SPLIT_NOTE = "Scheduler HEALTH is Operations-owned (this pane); scheduler OBJECT truth — schedules, triggers, concurrency, failure policy — is Automations-owned and lives at";
const SEED_RESIDUAL_NOTE = "seed residual, typed: the retained Scheduler capture stays typed-blocked in seed-ux-provenance.v1.json (stable replay renders Page-not-found) — a block record never opens work, blocked renders are never substituted, and this pane is canon-first over the daemon scheduler-status family, claiming no seed parity.";

// ---------------------------------------------------------------------------------------------
// load — every read through the shared read client on the request-scoped identity capability.
// ELEVEN per-family reads, every one a route that exists at the daemon TODAY (the operations
// brief's §2 map); no home-cockpit-style rollup exists to read, so none is read.
export async function load(ctx) {
  const { createReadClient } = await import("../read-client.mjs");
  const client = typeof ctx.daemonFetch === "function"
    ? createReadClient({ daemon: "", fetchImpl: ctx.daemonFetch })
    : createReadClient({ daemon: ctx.daemon });
  const [
    scheduler, operations, failoverRuns, failoverPlans, incidents, recovery,
    providers, spend, storageBackends, storageIncidents, substrate,
  ] = await Promise.all([
    client.read("/v1/hypervisor/scheduler/status"),
    client.read("/v1/hypervisor/operations"),
    client.read("/v1/hypervisor/failover/runs"),
    client.read("/v1/hypervisor/failover/plans"),
    client.read("/v1/hypervisor/incidents"),
    client.read("/v1/hypervisor/recovery-attempts"),
    client.read("/v1/hypervisor/providers"),
    client.read("/v1/hypervisor/provider-spend/reconciliation"),
    client.read("/v1/hypervisor/storage-backends"),
    client.read("/v1/hypervisor/storage-incidents"),
    client.read("/v1/hypervisor/substrate/status"),
  ]);
  return {
    scheduler, operations, failoverRuns, failoverPlans, incidents, recovery,
    providers, spend, storageBackends, storageIncidents, substrate,
  };
}

// No actions, deliberately: every Operations verb on this estate is W3.2/W3.3 acceptance
// surface (typed disabled-named-gaps below), and automation-run remediation is Automations'
// authority reached by live deep-link. A verb declared here would wire authority this slice
// must not hold.
export const actions = [];

// ---------------------------------------------------------------------------------------------
const pill = (text, cls) => `<span class="pill ${cls}">${esc(text)}</span>`;
const scopeBanner = () => `<div class="scope" data-ioi-scope="${SCOPE_MARKER}">${esc(SCOPE_NOTE)}</div>`;
const degraded = (result, plane) => `<div class="empty" data-ioi-degraded="${esc(result?.code || "daemon_unavailable")}" data-ioi-degraded-plane="${esc(plane)}">unavailable — <code>${esc(result?.code || "daemon_unavailable")}</code> (${esc(result?.message || "the plane did not answer")}). An unavailable plane renders <b>unknown, not zero</b> — zeros are never shown as truth.</div>`;
const gapButton = (label, gap, unit, reason) => `<button class="act ghost" type="button" disabled data-ioi-named-gap="${esc(gap)}" data-ioi-owning-unit="${esc(unit)}" data-ioi-disabled-reason="${esc(reason)}">${esc(label)}</button>`;

// ---- scheduler health (Operations owns HEALTH; Automations owns the OBJECT) -----------------
function schedulerPane(scheduler, operations) {
  const head = `<h2 id="ops-scheduler">Scheduler health</h2>
    <p class="sub">${esc(SCHEDULER_SPLIT_NOTE)} <a href="${LINK_AUTOMATIONS}" data-ioi-scheduler-object-link>Automations →</a>. ${esc(SEED_RESIDUAL_NOTE)}</p>
    <div class="seedblocked" data-ioi-seed-blocked="scheduler">scheduler seed source: typed-blocked in the seed gate (never substituted)</div>`;
  const health = (() => {
    if (!scheduler?.ok) return degraded(scheduler, "scheduler/status");
    const p = scheduler.payload || {};
    const liveness = String(p.liveness || "unknown");
    const cls = liveness === "live" ? "ok" : liveness === "stale" ? "warn" : "muted";
    const hb = p.heartbeat && typeof p.heartbeat === "object" ? p.heartbeat : null;
    return `<div class="card"><div class="main">
      <div class="name">loop liveness <span class="pill ${cls}" data-ioi-scheduler-liveness="${esc(liveness)}">${esc(liveness)}</span>${typeof p.age_seconds === "number" ? ` ${pill(`${p.age_seconds}s since last tick`, "muted")}` : ""}</div>
      <div class="meta">${hb ? `last tick <code>${esc(String(hb.last_tick_at || ""))}</code> · ` : ""}heartbeat-derived (<code>GET /v1/hypervisor/scheduler/status</code>) — proves the last completed tick, never that the loop will tick again. Records-derived schedule posture: <code>GET /v1/hypervisor/operations</code>.</div>
    </div></div>`;
  })();
  const specs = (() => {
    if (!operations?.ok) return degraded(operations, "operations");
    const scheduled = Array.isArray(operations.payload?.scheduler?.automations) ? operations.payload.scheduler.automations : [];
    if (!scheduled.length) return `<div class="empty" data-ioi-honest-empty="scheduled-specs">No scheduled automations (<code>GET /v1/hypervisor/operations</code> scheduler posture) — honest absence, never fabricated.</div>`;
    return `<div class="row">${pill(`${scheduled.length} scheduled`, "muted")}</div>` +
      `<table><thead><tr><th>Automation</th><th>Enabled</th><th>Schedule</th><th>Next</th><th>Last</th><th>Object truth</th></tr></thead><tbody>` +
      scheduled.slice(0, 8).map((a) => `<tr data-ioi-scheduled-spec-row>
        <td>${esc(a.name || a.automation_id || "automation")} <code>${esc(a.automation_id || "")}</code></td>
        <td>${a.enabled === false ? pill("paused", "warn") : pill("enabled", "ok")}</td>
        <td><code>${esc(JSON.stringify(a.schedule_spec ?? null))}</code></td>
        <td>${esc(String(a.next_run_at ?? "—"))}</td>
        <td>${esc(String(a.last_run_at ?? "—"))}</td>
        <td><a href="${LINK_AUTOMATIONS}">Automations →</a></td>
      </tr>`).join("") + `</tbody></table>`;
  })();
  return `${head}${health}${specs}`;
}

// ---- execution health (runs / needs-attention / webhooks over the automation substrate) -----
function executionPane(operations) {
  const head = `<h2 id="ops-execution">Execution health</h2>
    <p class="sub">The execution-health projection over the automation substrate (<code>GET /v1/hypervisor/operations</code>): what fired, what failed, what needs attention. Remediation (re-run · pause · resume) is <b>Automations-owned authority</b> — reached live at <a href="${LINK_AUTOMATIONS}" data-ioi-remediation-delegation>Automations →</a>, never minted here. Governed-work rollup: <a href="${LINK_WORK}">Work →</a>.</p>`;
  if (!operations?.ok) return `${head}${degraded(operations, "operations")}`;
  const runs = operations.payload?.runs || {};
  const counts = `<div class="row">
      ${pill(`${Number(runs.total || 0)} total`, "muted")}
      ${pill(`${Number(runs.done || 0)} done`, "ok")}
      ${pill(`${Number(runs.running || 0)} running`, "muted")}
      ${pill(`${Number(runs.failed || 0)} failed`, Number(runs.failed || 0) > 0 ? "warn" : "muted")}
    </div>`;
  const failures = Array.isArray(runs.failures) ? runs.failures : [];
  const failedRows = failures.length
    ? failures.slice(0, 6).map((r) => `<div class="card" data-ioi-failed-run-row>
        <div class="main"><div class="name">failed — ${esc(r.name || r.automation_id || r.execution_id || "run")} ${pill("needs attention", "warn")}</div>
        <div class="meta"><code>${esc(r.execution_id || "")}</code>${r.finished_at ? ` · ${esc(r.finished_at)}` : ""}</div></div>
        <a class="act ghost" href="${LINK_AUTOMATIONS}">remediate via Automations →</a></div>`).join("")
    : `<div class="empty" data-ioi-honest-empty="runs">No failed runs — real zeros stated as absence (<code>GET /v1/hypervisor/operations</code>), never invented rows.</div>`;
  const wh = operations.payload?.webhooks || {};
  const webhookLine = `<div class="card"><div class="main"><div class="name">webhook health ${pill(`${Number(wh.accepted || 0)} accepted`, "ok")} ${pill(`${Number(wh.rejected || 0)} rejected`, Number(wh.rejected || 0) > 0 ? "warn" : "muted")}</div>
      <div class="meta">trigger-event admissions over the automation substrate — evidence rows, never authority.</div></div></div>`;
  const gap = `<div class="gapcard">${gapButton("Open typed incident", "w3-fault-remediation", "W3.2", FAULT_REMEDIATION_GAP)}
      ${gapButton("Execute infrastructure remediation", "w3-fault-remediation", "W3.2", FAULT_REMEDIATION_GAP)}
      <p class="sub" style="margin:8px 0 0;text-transform:none;letter-spacing:0">${esc(FAULT_REMEDIATION_GAP)}</p></div>`;
  return `${head}${counts}${failedRows}${webhookLine}${gap}`;
}

// ---- cross-provider failover posture --------------------------------------------------------
function failoverPane(failoverRuns, failoverPlans) {
  const head = `<h2 id="ops-failover">Cross-provider failover</h2>
    <p class="sub">Runs and plan posture over daemon truth (<code>GET /v1/hypervisor/failover/runs</code> · <code>GET /v1/hypervisor/failover/plans</code>). Every wallet-gated crossing parks at <code>awaiting_authority_*</code> with the exact challenge echoed — <b>never automatic authority</b>; a refused run is fail-closed evidence, not an error to hide.</p>`;
  const runsBody = (() => {
    if (!failoverRuns?.ok) return degraded(failoverRuns, "failover/runs");
    const runs = Array.isArray(failoverRuns.payload?.runs) ? failoverRuns.payload.runs : [];
    if (!runs.length) return `<div class="empty" data-ioi-honest-empty="failover-runs">No failover runs (<code>GET /v1/hypervisor/failover/runs</code>) — honest absence, never fabricated.</div>`;
    return runs.slice(0, 6).map((r) => {
      const status = String(r.status || "unknown");
      const parked = status.startsWith("awaiting_authority");
      const cls = parked ? "warn" : status === "refused" ? "warn" : status === "complete" ? "ok" : "muted";
      const refusal = r.refusal && typeof r.refusal === "object" ? String(r.refusal.reason || "") : "";
      return `<div class="card" data-ioi-failover-run-row>
        <div class="main"><div class="name"><code>${esc(r.run_ref || r.run_id || "")}</code> ${pill(parked ? `parked — ${status.replace("awaiting_authority_", "")}` : status, cls)}</div>
        <div class="meta">${esc(r.failure_condition || "")}${r.environment_ref ? ` · <code>${esc(r.environment_ref)}</code>` : ""}${refusal ? ` · refusal <code>${esc(refusal)}</code> (fail-closed)` : ""}</div></div>
      </div>`;
    }).join("");
  })();
  const plansBody = (() => {
    if (!failoverPlans?.ok) return degraded(failoverPlans, "failover/plans");
    const plans = Array.isArray(failoverPlans.payload?.plans) ? failoverPlans.payload.plans : [];
    if (!plans.length) return `<div class="empty" data-ioi-honest-empty="failover-plans">No failover plans (<code>GET /v1/hypervisor/failover/plans</code>) — honest absence, never fabricated.</div>`;
    return plans.slice(0, 6).map((p) => `<div class="card" data-ioi-failover-plan-row>
        <div class="main"><div class="name"><code>${esc(p.plan_ref || p.plan_id || "")}</code> ${pill(String(p.readiness || "unknown"), p.readiness === "ready_daemon_custody" ? "ok" : "warn")}</div>
        <div class="meta"><code>${esc(p.environment_ref || "")}</code> · a plan is preparation evidence; every mutation it leads to is wallet-gated at execution time</div></div>
      </div>`).join("");
  })();
  const gap = `<div class="gapcard">${gapButton("Run failover", "w3-failover-execution", "W3.2", FAILOVER_EXECUTION_GAP)}
      ${gapButton("Arm plan", "w3-failover-execution", "W3.2", FAILOVER_EXECUTION_GAP)}
      ${gapButton("Disarm plan", "w3-failover-execution", "W3.2", FAILOVER_EXECUTION_GAP)}
      ${gapButton("Evaluate conditions", "w3-failover-execution", "W3.2", FAILOVER_EXECUTION_GAP)}
      <p class="sub" style="margin:8px 0 0;text-transform:none;letter-spacing:0">${esc(FAILOVER_EXECUTION_GAP)}</p></div>`;
  return `${head}${runsBody}${plansBody}${gap}`;
}

// ---- environment failure incidents + recovery attempts --------------------------------------
function incidentsPane(incidents, recovery) {
  const head = `<h2 id="ops-incidents">Environment incidents &amp; recovery</h2>
    <p class="sub">Environment failure incidents and recovery attempts over daemon truth (<code>GET /v1/hypervisor/incidents</code> · <code>GET /v1/hypervisor/recovery-attempts</code>) — the infrastructure lane; logical incidents live with Work.</p>`;
  const incBody = (() => {
    if (!incidents?.ok) return degraded(incidents, "incidents");
    const rows = Array.isArray(incidents.payload?.incidents) ? incidents.payload.incidents : [];
    if (!rows.length) return `<div class="empty" data-ioi-honest-empty="incidents">No environment failure incidents (<code>GET /v1/hypervisor/incidents</code>) — honest absence, never fabricated.</div>`;
    return rows.slice(0, 6).map((i) => `<div class="card" data-ioi-incident-row>
        <div class="main"><div class="name">${esc(i.kind || i.failure_condition || "incident")} ${pill(String(i.status || "open"), "warn")}</div>
        <div class="meta"><code>${esc(i.environment_ref || i.incident_id || "")}</code>${i.opened_at ? ` · ${esc(i.opened_at)}` : ""}</div></div>
      </div>`).join("");
  })();
  const recBody = (() => {
    if (!recovery?.ok) return degraded(recovery, "recovery-attempts");
    const rows = Array.isArray(recovery.payload?.recoveryAttempts) ? recovery.payload.recoveryAttempts : [];
    if (!rows.length) return `<div class="empty" data-ioi-honest-empty="recovery-attempts">No recovery attempts (<code>GET /v1/hypervisor/recovery-attempts</code>) — honest absence, never fabricated.</div>`;
    return rows.slice(0, 6).map((r) => `<div class="card" data-ioi-recovery-row>
        <div class="main"><div class="name">recovery ${pill(String(r.status || r.outcome || "attempted"), "muted")}</div>
        <div class="meta"><code>${esc(r.environment_ref || r.attempt_id || "")}</code></div></div>
      </div>`).join("");
  })();
  return `${head}${incBody}${recBody}`;
}

// ---- provider health + customer-borne spend -------------------------------------------------
function providersPane(providers) {
  const head = `<h2 id="ops-providers">Provider health</h2>`;
  if (!providers?.ok) return `${head}${degraded(providers, "providers")}`;
  const rows = Array.isArray(providers.payload?.providers) ? providers.payload.providers : [];
  const spendRule = String(providers.payload?.spend_rule || "BYO provider spend is customer-borne; the hypervisor records, governs, estimates, and reconciles — never hidden markup");
  const body = rows.length
    ? rows.slice(0, 10).map((p) => `<div class="card" data-ioi-provider-row>
        <div class="main"><div class="name"><code>${esc(p.provider_ref || "")}</code> ${pill(String(p.status || "unknown"), p.status === "available" || p.status === "credential_verified" ? "ok" : "muted")}</div>
        <div class="meta">${esc(p.reason || "")}</div></div>
      </div>`).join("")
    : `<div class="empty" data-ioi-honest-empty="providers">No providers registered (<code>GET /v1/hypervisor/providers</code>) — honest absence, never fabricated.</div>`;
  return `${head}<p class="sub" data-ioi-spend-rule>${esc(spendRule)}</p>${body}`;
}

// ---- spend reconciliation -------------------------------------------------------------------
function spendPane(spend) {
  const head = `<h2 id="ops-spend">Provider spend reconciliation</h2>`;
  if (!spend?.ok) return `${head}${degraded(spend, "provider-spend/reconciliation")}`;
  const p = spend.payload || {};
  const b = p.budget || {};
  const warned = Array.isArray(p.incomplete_teardown_warnings) ? p.incomplete_teardown_warnings : [];
  const warnRows = warned.length
    ? warned.slice(0, 4).map((w) => `<div class="card" data-ioi-teardown-warning-row><div class="main"><div class="name">incomplete teardown ${pill("warning", "warn")}</div><div class="meta"><code>${esc(String(w.exposure_ref || ""))}</code> · ${esc(String(w.warning || ""))}</div></div></div>`).join("")
    : "";
  return `${head}
    <p class="sub">Reserved estimates are never presented as spend; estimates stay unsettled until the customer's own provider bill (<code>GET /v1/hypervisor/provider-spend/reconciliation</code>).</p>
    <div class="row">
      ${pill(`headroom ${Number(b.remaining_headroom ?? 0)}`, "muted")}
      ${pill(`actual spent ${Number(b.spent ?? 0)}`, "muted")}
      ${pill(`reserved (open estimates) ${Number(b.reserved_open_estimates ?? 0)}`, "muted")}
      ${pill(`open exposures ${Number(p.estimated_open_exposure_rate?.open_count ?? 0)}`, "muted")}
      ${pill(`teardown finalized ${Number(p.teardown_finalized?.count ?? 0)}`, "muted")}
      ${pill(`unsettled ${Number(p.unsettled_estimates?.count ?? 0)}`, "muted")}
    </div>${warnRows}`;
}

// ---- storage custody ------------------------------------------------------------------------
function storagePane(storageBackends, storageIncidents) {
  const head = `<h2 id="ops-storage">Storage custody</h2>
    <p class="sub">Backend health over daemon truth (<code>GET /v1/hypervisor/storage-backends</code> · <code>GET /v1/hypervisor/storage-incidents</code>). Custody rule, stated in-surface: storage backends hold payload bytes; they do not own operational truth — daemon-admitted sha256 state roots remain restore truth.</p>`;
  const backendsBody = (() => {
    if (!storageBackends?.ok) return degraded(storageBackends, "storage-backends");
    const rows = Array.isArray(storageBackends.payload?.backends) ? storageBackends.payload.backends : [];
    if (!rows.length) return `<div class="empty" data-ioi-honest-empty="storage-backends">No storage backends (<code>GET /v1/hypervisor/storage-backends</code>) — honest absence, never fabricated.</div>`;
    return rows.slice(0, 6).map((b) => {
      const state = String(b.health?.state || "unknown");
      return `<div class="card" data-ioi-storage-backend-row>
        <div class="main"><div class="name">${esc(b.display_name || b.account_id || "backend")} ${pill(b.kind || "", "muted")} ${pill(state, state === "available" ? "ok" : "warn")}</div>
        <div class="meta"><code>${esc(b.account_ref || "")}</code> · ${Number(b.health?.objects || 0)} object(s) · ${Number(b.health?.open_incidents || 0)} open incident(s)</div></div>
      </div>`;
    }).join("");
  })();
  const incidentsBody = (() => {
    if (!storageIncidents?.ok) return degraded(storageIncidents, "storage-incidents");
    const rows = Array.isArray(storageIncidents.payload?.incidents) ? storageIncidents.payload.incidents : [];
    const repairs = Array.isArray(storageIncidents.payload?.repair_receipts) ? storageIncidents.payload.repair_receipts : [];
    const inc = rows.length
      ? rows.slice(0, 4).map((i) => `<div class="card" data-ioi-storage-incident-row><div class="main"><div class="name">availability incident ${pill(String(i.status || "open"), "warn")}</div><div class="meta"><code>${esc(i.archive_ref || i.incident_id || "")}</code></div></div></div>`).join("")
      : `<div class="empty" data-ioi-honest-empty="storage-incidents">No open storage incidents — honest absence, never fabricated.</div>`;
    const rep = repairs.length ? `<div class="row">${pill(`${repairs.length} repair receipt(s)`, "muted")}</div>` : "";
    return `${inc}${rep}`;
  })();
  const gap = `<div class="gapcard">${gapButton("Export archive", "w3-archive-custody-ops", "W3.3", ARCHIVE_CUSTODY_GAP)}
      ${gapButton("Verify archive", "w3-archive-custody-ops", "W3.3", ARCHIVE_CUSTODY_GAP)}
      ${gapButton("Restore", "w3-archive-custody-ops", "W3.3", ARCHIVE_CUSTODY_GAP)}
      ${gapButton("Repair", "w3-archive-custody-ops", "W3.3", ARCHIVE_CUSTODY_GAP)}
      <p class="sub" style="margin:8px 0 0;text-transform:none;letter-spacing:0">${esc(ARCHIVE_CUSTODY_GAP)}</p></div>`;
  return `${head}${backendsBody}${incidentsBody}${gap}`;
}

// ---- substrate status chip ------------------------------------------------------------------
function substratePane(substrate) {
  const head = `<h2 id="ops-substrate">Substrate status</h2>`;
  if (!substrate?.ok) return `${head}${degraded(substrate, "substrate/status")}`;
  const p = substrate.payload || {};
  const errs = Number(p.errors || 0);
  return `${head}<div class="card"><div class="main">
      <div class="name">admission engine ${pill(`${Number(p.admitted || 0)} admitted`, "ok")} <span class="pill ${errs > 0 ? "warn" : "muted"}" data-ioi-substrate-errors="${errs}">${errs} error(s)</span></div>
      <div class="meta">${esc(String(p.mode || ""))}${p.engine_open_error ? ` · open error: <code>${esc(String(p.engine_open_error))}</code>` : ""}</div>
    </div></div>`;
}

// ---- the typed W3 rollup absences -----------------------------------------------------------
function rollupAbsences() {
  return `<div class="gapcard" data-ioi-w3-absence="infrastructure_jobs_projection">
      <b>Unified infrastructure-jobs projection absent — a typed W3 absence (route-missing).</b>
      <p class="sub" style="margin:6px 0 0;text-transform:none;letter-spacing:0">${esc(JOBS_ROLLUP_ABSENCE)}</p>
    </div>
    <div class="gapcard" data-ioi-w3-absence="rpo_rto_rollup">
      <b>RPO/RTO + degraded/partition rollup absent — a typed W3 absence (route-missing).</b>
      <p class="sub" style="margin:6px 0 0;text-transform:none;letter-spacing:0">${esc(RPO_RTO_ABSENCE)}</p>
    </div>
    <div class="gapcard" data-ioi-w3-absence="capacity_utilization_overview">
      <b>Capacity/utilization overview absent — a typed W3 absence (route-missing).</b>
      <p class="sub" style="margin:6px 0 0;text-transform:none;letter-spacing:0">${esc(CAPACITY_ABSENCE)}</p>
    </div>`;
}

// ---- full daemon outage: the canon fallback-fixture rule, held verbatim ---------------------
const READ_KEYS = [
  "scheduler", "operations", "failoverRuns", "failoverPlans", "incidents", "recovery",
  "providers", "spend", "storageBackends", "storageIncidents", "substrate",
];
function daemonUnreachable(model) {
  return READ_KEYS.every((key) => {
    const r = model[key];
    return r && r.ok === false && (r.code === "daemon_unavailable" || r.code === "read_timeout" || r.status === 0);
  });
}

function unavailableView(model) {
  const first = model.scheduler;
  return `<div class="gapcard" data-ioi-daemon-unavailable="true">
      <b>Daemon unreachable — infrastructure posture unavailable.</b>
      <p class="sub" style="margin:6px 0 0;text-transform:none;letter-spacing:0">Every read failed typed (<code>${esc(first?.code || "daemon_unavailable")}</code>). Zero counts are fabricated and zero rows are shown rather than fixtures — the canon fallback-fixture rule (api.md:167-169): a fixture source must be visible and must never be presented as admitted runtime truth, so nothing is presented at all. The page returns when the daemon answers.</p>
    </div>
    <div class="row">
      <a class="act ghost" href="${LINK_AUTOMATIONS}">Automations →</a>
      <a class="act ghost" href="${LINK_WORK}">Work →</a>
    </div>`;
}

// ---------------------------------------------------------------------------------------------
export function render(model, ctx) {
  const inner = daemonUnreachable(model)
    ? `${scopeBanner()}${unavailableView(model)}${rollupAbsences()}`
    : `${scopeBanner()}${rollupAbsences()}
      ${schedulerPane(model.scheduler, model.operations)}
      ${executionPane(model.operations)}
      ${failoverPane(model.failoverRuns, model.failoverPlans)}
      ${incidentsPane(model.incidents, model.recovery)}
      ${providersPane(model.providers)}
      ${spendPane(model.spend)}
      ${storagePane(model.storageBackends, model.storageIncidents)}
      ${substratePane(model.substrate)}`;
  const css = `:root{color-scheme:dark}
  body{margin:0;background:#0c0d10;color:#e6e7ea;font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
  .wrap{max-width:920px;margin:0 auto;padding:40px 24px 80px}
  a{color:#8ab4ff}
  .brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#6f7280;margin-bottom:8px}
  h1{font-size:26px;margin:0 0 6px;letter-spacing:-.02em}
  .sub{color:#9a9da6;margin:0 0 22px;max-width:720px;overflow-wrap:anywhere}
  .row{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:0 0 22px}
  .act{padding:8px 14px;border-radius:8px;border:0;background:#fff;color:#111;font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
  .act:hover{background:#eee}
  .act.ghost{background:transparent;color:#cbd0da;border:1px solid #2a2c33}
  .act.ghost:hover{color:#fff;border-color:#3a3d45}
  .act[disabled]{opacity:.45;cursor:not-allowed}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#878a93;margin:26px 0 10px;font-weight:600}
  .card{display:flex;align-items:center;gap:14px;padding:14px 16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin-bottom:8px;text-decoration:none;color:inherit}
  .card .main{flex:1;min-width:0}
  .card .name{font-weight:600;color:#fff}
  .card .meta{color:#878a93;font-size:12.5px;margin-top:3px;overflow-wrap:anywhere}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;border:1px solid;white-space:nowrap;margin-left:8px}
  .ok{color:#46c277;border-color:#235c3b;background:#11281b}
  .warn{color:#d6a13a;border-color:#5c4a23;background:#28220f}
  .muted{color:#9a9da6;border-color:#2a2c33}
  .empty{color:#6f7280;padding:18px;border:1px dashed #24262d;border-radius:12px;overflow-wrap:anywhere;margin-bottom:8px}
  .gapcard{padding:14px 16px;border:1px dashed #5c4a23;border-radius:12px;background:#15130c;margin:0 0 18px;overflow-wrap:anywhere}
  .scope{padding:10px 14px;border:1px solid #2a3a5c;border-radius:10px;background:#0e1420;color:#9db4d8;font-size:12.5px;margin:0 0 18px;overflow-wrap:anywhere}
  .seedblocked{padding:8px 12px;border:1px dashed #5c4a23;border-radius:8px;background:#15130c;color:#b8a06a;font-size:12px;margin:0 0 12px;overflow-wrap:anywhere}
  code{font-size:11.5px;color:#aab;background:#0e0f13;padding:1px 5px;border-radius:4px}
  table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:8px}
  th{text-align:left;color:#878a93;font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;padding:6px 10px;border-bottom:1px solid #24262d}
  td{padding:8px 10px;border-bottom:1px solid #1b1d23;overflow-wrap:anywhere}
  @media(max-width:760px){.wrap{padding:24px 14px 56px}.card{align-items:flex-start}table{display:block;overflow-x:auto;max-width:100%}}`;
  const head = `<h1 id="ops-owner">Operations</h1>
    <p class="sub">The infrastructure cockpit — scheduler health, execution health, cross-provider failover, environment incidents, provider health, customer-borne spend, storage custody, substrate status — read-first over the daemon families that exist today. The <a href="${SEED_READOUT}">T2 Operations readout →</a> is the rehome source and keeps serving untouched (seed-preservation invariant).</p>`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Operations · Hypervisor</title><style>${css}</style></head><body><div class="wrap"><div class="brand">IOI Hypervisor</div>${head}${inner}</div></body></html>`;
}

export const meta = {
  slug: "operations",
  route: LEGACY_ROUTE,
  verifier: "scripts/verify-hypervisor-operations-cockpit.mjs",
  certification: "n/a",
};
