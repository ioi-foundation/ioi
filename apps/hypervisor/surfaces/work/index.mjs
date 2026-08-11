// Work — the canonical /work PARTIAL PRE-W3 COCKPIT SLICE (next-legs IV Leg 3).
//
// SCOPE RULING (bounds every claim in this file): this is NOT Work completion. W3.1 owns the
// admission→harness→run→events/receipts→stop/archive/recovery/replay chain; SURF-work and W3.1
// REMAIN OPEN. This slice delivers exactly: the canonical mounts (/work, /work/sessions,
// /work/new-session on fresh legacy lanes), the jobs/incidents cockpit grammar rehomed
// READ-FIRST onto the landing (rows link to the protected seeds, which keep serving untouched
// — seed-preservation invariant), the session verbs the daemon owns TODAY, and TYPED ABSENCES
// for everything W3.1 owns. Evidence: scripts/verify-hypervisor-work-cockpit.mjs
// (check:work-cockpit — deliberately NOT a "-journey": the Work journey is W3.1's to earn).
//
// The daemon session family as it exists TODAY (hypervisor-daemon.rs router, verified at the
// bytes):
//   list       GET    /v1/hypervisor/sessions
//   create     POST   /v1/hypervisor/sessions          (202 + session_create_projection.v1
//                                                       with provision receipt_ref; owner is
//                                                       daemon-resolved, client owner_ref refused)
//   overview   GET    /v1/hypervisor/sessions/overview (W0.6 counts-first, owner-filtered)
//   get        GET    /v1/hypervisor/sessions/:id
//   events     GET    /v1/hypervisor/sessions/:id/events   (SSE, real signals only)
//   execute    POST   /v1/hypervisor/sessions/:id/execute  (Lane A run-chain entry — NOT wired
//                                                           here; the positive loop is W3.1)
//   ports      POST   /v1/hypervisor/sessions/:id/ports/revoke
//   teardown   DELETE /v1/hypervisor/sessions/:id     (receipted; lifecycle_state torn_down)
//
// TYPED W3 ABSENCES stated, never simulated:
//   - subject attachment: create HARDCODES `subject_attachments: []` on the session record
//     (lifecycle_routes.rs, the C-1 comment: "Create accepts no attachment inputs yet (W3 C-1
//     backend row), so the honest state is the empty set"). This slice accepts NO subject input
//     and `project_ref` is a session field that NEVER masquerades as a subject attachment — the
//     verifier pins the record's attachments empty even when project_ref was supplied.
//   - stop/archive: NO /v1/hypervisor/sessions/:id/{stop,archive} route exists. The
//     session-execution-bindings family owns :id/{stop,archive,restore} at the daemon, but those
//     bind the execution chain W3.1 owns — this slice consumes neither.
//   - launch/terminal/replay/recovery: the delta ledger's `HarnessSessionExecutionChain` row
//     (docs/architecture/_meta/canon-to-code-delta.md — Recipe→Binding→Launch→Spawn→Readiness→
//     TerminalAttach) records NO typed HarnessSessionLaunch producer and no canonical chain
//     consumption; per its conformance column nothing here may stand in for a missing
//     owner-produced predecessor, so these verbs render disabled with the machine-readable
//     reason, never a build target.
//
// THE ADMITTED BINDING: harness/model-route binding is ADMITTED AT CREATE — the daemon derives
// and records it on the session record; every binding cell below renders the RECORD's truth
// ("selection is session truth recorded at create, never UI state", the T2 sessions-root
// grammar this view rehomes).
import { escHtml } from "../kit.mjs";

const esc = escHtml;
const enc = encodeURIComponent;

const LEGACY_LANDING = "/__ioi/work-cockpit";
const LEGACY_SESSIONS = "/__ioi/work-sessions";
const LEGACY_NEW_SESSION = "/__ioi/work-new-session";
const CANONICAL_LANDING = "/work";
const CANONICAL_SESSIONS = "/work/sessions";
const CANONICAL_NEW_SESSION = "/work/new-session";

// The protected seeds this landing's grammar is rehomed from (read-first). They keep serving
// untouched until the W4 cutover — rows here LINK to them exactly where the cockpit does.
const SEED_JOBS = "/__ioi/missions";
const SEED_INCIDENTS = "/__ioi/missions/incidents";

const SESSIONS_PLANE = "/v1/hypervisor/sessions";
const CREATE_PROJECTION_SCHEMA = "ioi.hypervisor.session_create_projection.v1";
const SCOPE_MARKER = "partial-pre-w3-cockpit-slice";
const SCOPE_NOTE = "Partial pre-W3 cockpit slice — NOT Work completion. W3.1 owns the admission→harness→run→events/receipts→stop/archive/recovery/replay chain; SURF-work and W3.1 remain open.";

const SUBJECT_ABSENCE_REASON = "typed W3 absence — the daemon HARDCODES subject_attachments: [] on every session record (lifecycle_routes.rs C-1: create accepts no attachment inputs yet; the W3 C-1 backend row owns attachment inputs + filters). No subject input exists on this slice, and project_ref is a session field that never masquerades as a subject attachment.";
const STOP_ARCHIVE_ABSENCE_REASON = "typed W3 absence — no /v1/hypervisor/sessions/:id/stop or /archive route exists at the daemon. The session-execution-bindings family owns :id/stop and :id/archive, but those bind the execution chain W3.1 owns; this pre-W3 slice consumes neither.";
const TEARDOWN_UNWIRED_REASON = "daemon verb exists (DELETE /v1/hypervisor/sessions/:id — receipted teardown, lifecycle_state torn_down) but its cockpit wiring belongs to the W3.1 Work completion, not this partial pre-W3 cockpit slice; disabled with the verb named, never half-wired.";
const LAUNCH_CHAIN_ABSENCE_REASON = "typed W3 absence — the HarnessSessionExecutionChain delta row (canon-to-code-delta.md) records NO typed HarnessSessionLaunch producer: recipe/binding routes are pure planners without persistence and no end-to-end chain consumption exists. Per that row's conformance proof, no planner record, generic execution receipt, terminal event, or caller-supplied proof ref may stand in for the missing owner-produced predecessor — so launch/terminal/replay/recovery render disabled, never simulated.";

// ---------------------------------------------------------------------------------------------
// load — every read through the shared read client on the request-scoped identity capability
// (the caller's own envelope is the read identity; the daemon owner-filters session truth
// BEFORE counts).
export async function load(ctx) {
  const { createReadClient } = await import("../read-client.mjs");
  const client = typeof ctx.daemonFetch === "function"
    ? createReadClient({ daemon: "", fetchImpl: ctx.daemonFetch })
    : createReadClient({ daemon: ctx.daemon });
  const path = ctx.url.pathname;
  const sp = ctx.url.searchParams;
  const model = {
    view: path === LEGACY_SESSIONS || path === CANONICAL_SESSIONS
      ? "sessions"
      : path === LEGACY_NEW_SESSION || path === CANONICAL_NEW_SESSION
        ? "new-session"
        : "landing",
    result: {
      acted: sp.get("acted") || "",
      receipt: sp.get("receipt") || "",
      record: sp.get("record") || "",
      status: sp.get("result") || "",
      refused: sp.get("refused") || "",
      reason: sp.get("reason") || "",
    },
  };
  if (model.view === "landing") {
    model.overview = await client.read(`${SESSIONS_PLANE}/overview`, { expectSchema: "ioi.hypervisor.sessions-overview.v1" });
    model.goalRuns = await client.read("/v1/goal-orchestration/goal-runs");
    model.operations = await client.read("/v1/hypervisor/operations");
    return model;
  }
  if (model.view === "sessions") {
    model.overview = await client.read(`${SESSIONS_PLANE}/overview`, { expectSchema: "ioi.hypervisor.sessions-overview.v1" });
    model.sessions = await client.read(SESSIONS_PLANE, { expectSchema: "ioi.hypervisor.sessions-list.v1" });
    model.sessionRef = (sp.get("session") || "").trim();
    if (model.sessionRef) {
      model.session = await client.read(`${SESSIONS_PLANE}/${enc(model.sessionRef)}`);
    }
    return model;
  }
  // new-session: the optional project CONTEXT select (a session field — never a subject).
  model.projects = await client.read("/v1/hypervisor/projects");
  return model;
}

// ---------------------------------------------------------------------------------------------
// actions — exactly ONE mutation: the admitted-session create the daemon owns today. The 202
// projection is admission evidence (schema_version + provision receipt_ref) or the action fails
// closed. No subject field is declared: subject attachment is W3 C-1 scope.
const CREATE_AUTHORITY = {
  plane: "hypervisor.sessions",
  operation: "POST /v1/hypervisor/sessions (owner daemon-resolved; harness/model-route binding admitted at create; subject_attachments hardcoded empty — W3 C-1)",
};
export const actions = [
  { id: "create-session", method: "POST", route: "/actions/create-session", fields: ["initial_input", "project_ref"], fieldMax: 4096, context: [], authority: CREATE_AUTHORITY, receipt: CREATE_PROJECTION_SCHEMA, confirm: false, success: "return-to-surface", refusal: "typed-banner" },
];

export async function handleAction({ action, fields, daemonFetch }) {
  if (typeof daemonFetch !== "function") {
    return { kind: "failure", http: 500, code: "identity_capability_missing", message: "the action runtime supplied no request-scoped daemon capability — refusing to create without the caller's identity" };
  }
  if (action.id !== "create-session") {
    return { kind: "failure", http: 500, code: "action_unknown", message: `undeclared action '${action.id}'` };
  }
  const body = {};
  if (fields.initial_input) body.initial_input = fields.initial_input;
  if (fields.project_ref) body.project_ref = fields.project_ref;
  const response = await daemonFetch(SESSIONS_PLANE, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }).catch(() => null);
  if (!response) return { kind: "failure", http: 502, code: "daemon_unavailable", message: "the daemon did not answer — no session was created" };
  const payload = await response.json().catch(() => null);
  if (!payload) return { kind: "failure", http: 502, code: "daemon_reply_unreadable", message: `the daemon answered ${response.status} without a readable body — do not trust the create` };
  if (payload.error || !response.ok) {
    // The daemon's typed refusal, VERBATIM (session_authenticated_principal_required /
    // session_authentication_required / session_create_* / ...).
    const code = payload.error?.code || payload.code || `http_${response.status}`;
    const message = payload.error?.message || payload.message || payload.reason || "refused — no session was created";
    return { kind: "refusal", http: response.status || 409, code, message };
  }
  // Admission evidence or nothing: the 202 must carry the declared projection schema plus the
  // provision receipt ref. Anything less fails closed.
  const receiptRef = typeof payload.receipt_ref === "string" ? payload.receipt_ref : "";
  const sessionRef = typeof payload.session_ref === "string" ? payload.session_ref : "";
  if (payload.schema_version !== CREATE_PROJECTION_SCHEMA || !receiptRef.startsWith("receipt://") || !sessionRef) {
    return { kind: "failure", http: 502, code: "receipt_missing", message: `the create answered ${response.status} without the ${CREATE_PROJECTION_SCHEMA} record + provision receipt_ref admission evidence — failing closed (do not trust the create)` };
  }
  return {
    kind: "success",
    status: payload.idempotent_replay === true ? "replayed" : "provisioned",
    created: sessionRef,
    receipt_ref: receiptRef,
    // The action runtime bounds return paths to the legacy lanes — the PRG lands on the
    // legacy sessions view (the same module, the same grammar; the automations precedent).
    redirect: `${LEGACY_SESSIONS}?session=${enc(sessionRef)}`,
  };
}

// ---------------------------------------------------------------------------------------------
// render helpers — the cockpit grammar's typed-degradation and disabled-named-absence fragments.
const degraded = (result) => `<div class="empty" data-ioi-degraded="${esc(result?.code || "daemon_unavailable")}">unavailable — <code>${esc(result?.code || "daemon_unavailable")}</code> (${esc(result?.message || "the plane did not answer")})</div>`;
const disabledCtl = (label, reason) => `<button class="act ghost" type="button" disabled data-ioi-disabled-reason="${esc(reason)}">${esc(label)}</button>`;
const pill = (text, cls) => `<span class="pill ${cls}">${esc(text)}</span>`;
const scopeBanner = () => `<div class="scope" data-ioi-scope="${SCOPE_MARKER}">${esc(SCOPE_NOTE)}</div>`;

function resultBanner(result) {
  if (result.refused) {
    return `<div id="ap-result" class="banner warn" data-ioi-refusal-code="${esc(result.refused)}"><b>Refused</b> — <code>${esc(result.refused)}</code>${result.reason ? ` · ${esc(result.reason)}` : ""}. State unchanged; the daemon's typed refusal renders verbatim.</div>`;
  }
  if (result.acted) {
    return `<div id="ap-result" class="banner ok" data-ioi-acted="${esc(result.acted)}"><b>Admitted</b> — <code>${esc(result.acted)}</code> · ${esc(result.status || "")} · record <code>${esc(result.record)}</code> · receipt <code>${esc(result.receipt)}</code></div>`;
  }
  return "";
}

const lifecyclePill = (state) => pill(state || "unknown", state === "provisioned" ? "ok" : state === "torn_down" ? "muted" : "warn");

// The admitted-binding cell: RECORD truth only ("selection is session truth recorded at
// create, never UI state") — the T2 sessions-root vocabulary, rehomed.
function bindingCell(hb) {
  if (!hb || typeof hb !== "object" || (!hb.profile_ref && !hb.harness)) {
    return `<span class="sub" data-ioi-binding="execute-time-default">execute-time default</span>`;
  }
  const bits = [];
  if (hb.harness) bits.push(`<code>${esc(String(hb.harness))}</code>`);
  if (hb.profile_ref) bits.push(`<code>${esc(String(hb.profile_ref))}</code>`);
  if (hb.model_route_ref) bits.push(`<code>${esc(String(hb.model_route_ref))}</code>`);
  if (hb.admission_id) bits.push(`adm <code>${esc(String(hb.admission_id))}</code>`);
  return `<span data-ioi-binding="admitted-at-create">${bits.join(" · ")}</span>`;
}

// ---- landing (/work — the Active root): rehomed jobs/incidents cockpit grammar, read-first ----
const TERMINAL_RUN_STATES = new Set(["complete", "completed", "done", "succeeded", "failed", "cancelled", "canceled"]);

// The incidents inbox's OWN derivation (renderIncidentsPort, rehomed read-first): real run
// failures + GoalRun blockers, open/closed lanes — never authored, never fabricated.
function deriveIncidents(goalRuns, operations) {
  const gr = goalRuns?.ok && Array.isArray(goalRuns.payload?.goal_runs) ? goalRuns.payload.goal_runs : [];
  const failures = operations?.ok && Array.isArray(operations.payload?.runs?.failures) ? operations.payload.runs.failures : [];
  const blockers = gr.filter((r) => Array.isArray(r.blockers) && r.blockers.length).map((r) => {
    const b = r.blockers[0] || {};
    return {
      kind: "Blocker",
      title: `${b.reason_code || "blocked"} · ${r.goal_run_id || r.goal_ref || "goal-run"}`,
      updated: r.updated_at || r.created_at || "",
      closed: TERMINAL_RUN_STATES.has(String(r.status || "").toLowerCase()),
      proof: r.goal_run_id ? `/__ioi/run-timeline/goal-run/${enc(r.goal_run_id)}` : "/__ioi/work-ledger",
    };
  });
  const failed = failures.map((r) => ({
    kind: "Run failure",
    title: `${r.status || "failed"} · ${r.name || r.execution_id || "run"}`,
    updated: r.finished_at || r.started_at || "",
    closed: false,
    proof: "/__ioi/work-ledger",
  }));
  const incidents = blockers.concat(failed);
  return {
    open: incidents.filter((i) => !i.closed),
    closed: incidents.filter((i) => i.closed),
    all: incidents,
  };
}

function landingView(model, routes) {
  const ov = model.overview;
  const total = ov?.ok ? Number(ov.payload?.total || 0) : null;
  const byState = ov?.ok && ov.payload?.by_lifecycle_state ? ov.payload.by_lifecycle_state : {};
  const stateChips = Object.entries(byState).map(([state, n]) => pill(`${state} ${n}`, state === "provisioned" ? "ok" : "muted")).join(" ");
  const sessionsBand = `<h2 id="work-sessions-band">Sessions</h2>
    ${ov?.ok
      ? `<div class="card"><div class="main"><div class="name">${total} session${total === 1 ? "" : "s"} ${stateChips}</div>
         <div class="meta">owner-filtered before counts (W0.6 overview) · admitted harness binding is session truth recorded at create</div></div>
         <a class="act" href="${routes.sessions}">Open Sessions →</a><a class="act ghost" href="${routes.newSession}">+ New session</a></div>`
      : `${degraded(ov)}<div class="row"><a class="act ghost" href="${routes.sessions}">Open Sessions →</a><a class="act ghost" href="${routes.newSession}">+ New session</a></div>`}`;

  // Run queue — the jobs cockpit's grammar (goal-orchestration runs), rows LINK to the
  // protected seed exactly where the cockpit renders them.
  const gr = model.goalRuns?.ok && Array.isArray(model.goalRuns.payload?.goal_runs) ? model.goalRuns.payload.goal_runs : null;
  const queueRows = gr === null
    ? degraded(model.goalRuns)
    : (gr.length
      ? gr.slice(0, 8).map((r) => {
        const st = String(r.status || "—");
        const cls = TERMINAL_RUN_STATES.has(st.toLowerCase()) ? (st.toLowerCase().startsWith("fail") ? "warn" : "ok") : "muted";
        return `<div class="card"><div class="main"><div class="name"><code>${esc(r.goal_run_id || "")}</code> ${pill(st, cls)}</div>
          <div class="meta">${esc(r.goal_ref || "")}${r.created_at ? ` · ${esc(r.created_at)}` : ""}</div></div>
          <a class="act ghost" href="${SEED_JOBS}#missions-queue">queue →</a></div>`;
      }).join("")
      : `<div class="empty">No goal-orchestration runs — the queue reads real daemon runs and never fabricates rows.</div>`);
  const queue = `<h2 id="work-run-queue">Run queue</h2>
    <p class="sub">The jobs cockpit's run-queue grammar, rehomed read-first — the <a href="${SEED_JOBS}">protected Jobs cockpit seed →</a> keeps serving untouched (seed-preservation invariant).</p>${queueRows}`;

  // Incidents & blockers — the incidents inbox's derivation, rehomed read-first with its lane
  // grammar (open/closed/all counts); rows link to the protected seed's lanes.
  const lanes = deriveIncidents(model.goalRuns, model.operations);
  const incidentsDegraded = !model.goalRuns?.ok && !model.operations?.ok;
  const laneChip = (key, label) => `<a class="pill muted" href="${SEED_INCIDENTS}?lane=${key}">${label} ${lanes[key].length}</a>`;
  const incidentRows = lanes.open.slice(0, 8).map((i) => `<div class="card"><div class="main">
      <div class="name">${esc(i.title)} ${pill(i.kind, i.kind === "Blocker" ? "warn" : "muted")}</div>
      <div class="meta">${i.updated ? `${esc(i.updated)} · ` : ""}<a href="${esc(i.proof)}">proof ↗</a></div></div>
      <a class="act ghost" href="${SEED_INCIDENTS}">inbox →</a></div>`).join("");
  const incidents = `<h2 id="work-incidents">Incidents &amp; blockers</h2>
    <p class="sub">The incidents inbox's derivation, rehomed read-first — real run failures + GoalRun blockers, never authored; the <a href="${SEED_INCIDENTS}">protected Incidents inbox seed →</a> keeps serving untouched.</p>
    ${incidentsDegraded
      ? degraded(model.operations)
      : `<div class="row">${laneChip("open", "Open")} ${laneChip("closed", "Closed")} ${laneChip("all", "All")}</div>
         ${incidentRows || `<div class="empty">No open incidents — no failed runs and no blocked goal-runs right now. This band reads real daemon truth; it never fabricates incidents.</div>`}`}`;

  // The eight typed canon views: Sessions is live in this slice; the rest resolve as honest
  // v2 shell pages until their SURF-work waves land.
  const viewLink = (href, label, live) => (live
    ? `<a class="act" href="${href}">${label}</a>`
    : `<a class="act ghost" href="${href}" data-ioi-view-state="shell-only">${label}</a>`);
  const views = `<h2 id="work-typed-views">Typed views</h2>
    <p class="sub">Canon: eight typed views, policy-filtered read model — never one universal Work status. This slice serves <b>Sessions</b>; the other views stay honest shell pages until their waves land (SURF-work remains open).</p>
    <div class="row">${viewLink(routes.sessions, "Sessions", true)}${viewLink("/work/goals", "Goals", false)}${viewLink("/work/rooms", "Rooms", false)}${viewLink("/work/queues", "Queues", false)}${viewLink("/work/reviews", "Reviews", false)}${viewLink("/work/incidents", "Incidents", false)}${viewLink("/work/history", "History", false)}</div>
    <p class="sub">Adjacent owned readouts: <a href="/__ioi/work-ledger">Work Ledger</a> · <a href="/__ioi/run-timeline">Run Timeline</a> · <a href="/__ioi/sessions">Sessions root readout (T2)</a> — rehome sources, all still serving.</p>`;

  return `<h1 id="work-owner">Work</h1>
    <p class="sub">The unified core workspace over governed work — a policy-filtered READ MODEL across typed subjects (Sessions, GoalRuns, AutomationRuns, WorkRuns, OutcomeRooms), never a canonical Work object. Bare <code>/sessions</code> answers a typed 410 whose replacement is <a href="${routes.sessions}">${CANONICAL_SESSIONS}</a>.</p>
    ${scopeBanner()}${sessionsBand}${queue}${incidents}${views}`;
}

// ---- sessions view (/work/sessions) ---------------------------------------------------------
function sessionsView(model, routes) {
  const banner = resultBanner(model.result);
  const ov = model.overview;
  const overviewBand = ov?.ok
    ? (() => {
      const p = ov.payload || {};
      const stateChips = Object.entries(p.by_lifecycle_state || {}).map(([state, n]) => pill(`${state} ${n}`, state === "provisioned" ? "ok" : "muted")).join(" ");
      const att = p.subject_attachments || {};
      const gaps = Array.isArray(p.gaps) ? p.gaps : [];
      return `<div class="card"><div class="main">
        <div class="name">${Number(p.total || 0)} session${Number(p.total || 0) === 1 ? "" : "s"} ${stateChips}</div>
        <div class="meta">subject attachments: ${Number(att.sessions_with_attachments || 0)} session(s) carry attachments — <span data-ioi-w3-absence="subject_attachments">honestly empty until the W3 C-1 attachment inputs land</span></div>
        ${gaps.map((g) => `<div class="meta">daemon-named gap: ${esc(String(g))}</div>`).join("")}
        </div><a class="act" href="${routes.newSession}">+ New session</a></div>`;
    })()
    : degraded(ov);

  const list = model.sessions;
  const rows = list?.ok && Array.isArray(list.payload?.sessions) ? list.payload.sessions : null;
  const table = rows === null
    ? degraded(list)
    : (rows.length
      ? `<table><thead><tr><th>Session</th><th>Lifecycle</th><th>Admitted binding</th><th>Project</th><th>Created</th><th>Open</th></tr></thead><tbody>` +
        rows.map((s) => `<tr>
          <td><code>${esc(s.session_ref || "")}</code></td>
          <td>${lifecyclePill(s.lifecycle_state)}</td>
          <td>${bindingCell(s.harness_binding)}</td>
          <td>${s.project_ref ? `<code>${esc(String(s.project_ref))}</code>` : "—"}</td>
          <td>${esc(s.created_at || "")}</td>
          <td><a href="${routes.sessions}?session=${enc(s.session_ref || "")}">facts →</a></td>
        </tr>`).join("") + `</tbody></table>`
      : `<div class="empty">No sessions for this principal yet — session truth is owner-filtered before counts. Create one from <a href="${routes.newSession}">New session</a>.</div>`);

  const detail = model.sessionRef ? sessionDetail(model) : "";

  return `<p><a href="${routes.landing}">← Work</a></p><h1 id="work-sessions-owner">Work / Sessions</h1>
    <p class="sub">Every governed session with its lifecycle facts and ADMITTED harness binding — selection is session truth recorded at create, never UI state. Reads: the sessions list + the W0.6 counts-first overview, owner-filtered before counts.</p>
    ${scopeBanner()}${banner}
    <h2>Overview (W0.6)</h2>${overviewBand}
    <h2>Sessions</h2>${table}${detail}`;
}

function sessionDetail(model) {
  const res = model.session;
  if (!res?.ok) {
    return `<h2 id="session-detail">Session ${esc(model.sessionRef)}</h2>${res?.kind === "not_found"
      ? `<div class="empty">not found — <code>${esc(res.code)}</code>. Nothing is inferred; the ref may have been torn down and pruned.</div>`
      : degraded(res)}`;
  }
  const s = res.payload?.session || {};
  const v = (x) => (x == null || x === "" ? "—" : (typeof x === "string" ? esc(x) : esc(JSON.stringify(x))));
  const receipts = Array.isArray(s.latest_receipt_refs) && s.latest_receipt_refs.length
    ? s.latest_receipt_refs.map((r) => `<code>${esc(String(r))}</code>`).join(" ")
    : "—";
  const env = s.environment_status && typeof s.environment_status === "object" ? s.environment_status : {};
  const attachments = Array.isArray(s.subject_attachments) ? s.subject_attachments : [];
  const attachmentsCell = attachments.length
    ? attachments.map((a) => `<code>${esc(JSON.stringify(a))}</code>`).join(" ")
    : `<span data-ioi-w3-absence="subject_attachments">empty — ${esc(SUBJECT_ABSENCE_REASON)}</span>`;
  // Verbs: what the daemon owns today vs the typed W3.1 absences — disabled with the
  // machine-readable reason, never simulated, never half-wired.
  const verbs = `<h2 id="session-verbs">Verbs</h2>
    <p class="sub">Daemon-owned today: create (wired above) · list/overview/get (these reads) · events (SSE at <code>GET ${SESSIONS_PLANE}/:id/events</code>, real signals only) · execute (the Lane A run-chain entry — W3.1's chain) · ports/revoke · teardown. Everything else is a typed absence.</p>
    <div class="gapcard">
      ${disabledCtl("Tear down", TEARDOWN_UNWIRED_REASON)}
      ${disabledCtl("Stop", STOP_ARCHIVE_ABSENCE_REASON)}
      ${disabledCtl("Archive", STOP_ARCHIVE_ABSENCE_REASON)}
      ${disabledCtl("Launch harness run", LAUNCH_CHAIN_ABSENCE_REASON)}
      ${disabledCtl("Terminal", LAUNCH_CHAIN_ABSENCE_REASON)}
      ${disabledCtl("Replay", LAUNCH_CHAIN_ABSENCE_REASON)}
      ${disabledCtl("Recovery", LAUNCH_CHAIN_ABSENCE_REASON)}
    </div>`;
  return `<h2 id="session-detail">Session facts</h2>
    <dl class="grid">
      <dt>Session</dt><dd><code>${esc(s.session_ref || model.sessionRef)}</code></dd>
      <dt>Lifecycle</dt><dd>${lifecyclePill(s.lifecycle_state)}</dd>
      <dt>Admitted binding</dt><dd>${bindingCell(s.harness_binding)} <span class="sub">· admitted at create — session truth, never UI state</span></dd>
      <dt>Model route</dt><dd>${s.model_route_binding && s.model_route_binding.route_ref ? `<code>${esc(String(s.model_route_binding.route_ref))}</code>` : v(s.model_route_binding && s.model_route_binding.model_route_ref)}</dd>
      <dt>Project (session field)</dt><dd>${v(s.project_ref)} <span class="sub">· never a subject attachment</span></dd>
      <dt>Subject attachments</dt><dd>${attachmentsCell}</dd>
      <dt>Environment</dt><dd>${v(s.environment_ref)}</dd>
      <dt>Workspace</dt><dd>${v(s.workspace_root)}${s.custody_posture ? ` · ${esc(String(s.custody_posture))}` : ""}</dd>
      <dt>Environment phase</dt><dd>${v(env.phase || env.state)}</dd>
      <dt>Owner</dt><dd>${v(s.owner_ref)}</dd>
      <dt>Created</dt><dd>${v(s.created_at)}</dd>
      <dt>Receipts</dt><dd>${receipts}</dd>
    </dl>${verbs}`;
}

// ---- new-session view (/work/new-session) ---------------------------------------------------
function newSessionView(model, routes) {
  const banner = resultBanner(model.result);
  const projects = model.projects?.ok && Array.isArray(model.projects.payload?.projects) ? model.projects.payload.projects : null;
  const projectField = projects && projects.length
    ? `<select name="project_ref"><option value="">(none)</option>${projects.map((p) => `<option value="${esc(p.project_id)}">${esc(p.name || p.project_id)}</option>`).join("")}</select>`
    : `<input name="project_ref" placeholder="project:my-app (optional)">`;
  return `<p><a href="${routes.landing}">← Work</a></p><h1 id="work-new-session-owner">Work / New Session</h1>
    <p class="sub">The one-click Work action: create exactly one bounded, governed session through daemon admission. The owner is daemon-resolved from the caller's identity; the harness/model-route binding is ADMITTED AT CREATE and read back as session truth on <a href="${routes.sessions}">Work / Sessions</a>; the 202 carries the provision receipt.</p>
    ${scopeBanner()}${banner}
    <div class="gapcard" data-ioi-w3-absence="subject_attachments">
      <b>No subject input exists on this form — a typed W3 absence.</b>
      <p class="sub" style="margin:6px 0 0;text-transform:none;letter-spacing:0">${esc(SUBJECT_ABSENCE_REASON)}</p>
    </div>
    <form method="post" action="${LEGACY_NEW_SESSION}/actions/create-session">
      <input type="hidden" name="return" value="${LEGACY_NEW_SESSION}">
      <div class="field"><label>Initial input (optional — recorded on the session transcript, disposition session_only_non_goal)</label><textarea name="initial_input" placeholder="What this session is for…"></textarea></div>
      <div class="field"><label>Project context (optional — a session FIELD; never a subject attachment)</label>${projectField}</div>
      <div class="row"><button class="act" type="submit">Create session</button></div>
    </form>`;
}

// ---------------------------------------------------------------------------------------------
export function render(model, ctx) {
  const legacy = ctx.url.pathname.startsWith("/__ioi/");
  const routes = legacy
    ? { landing: LEGACY_LANDING, sessions: LEGACY_SESSIONS, newSession: LEGACY_NEW_SESSION }
    : { landing: CANONICAL_LANDING, sessions: CANONICAL_SESSIONS, newSession: CANONICAL_NEW_SESSION };
  let title = "Work";
  let inner = "";
  if (model.view === "sessions") {
    title = "Work / Sessions";
    inner = sessionsView(model, routes);
  } else if (model.view === "new-session") {
    title = "Work / New Session";
    inner = newSessionView(model, routes);
  } else {
    inner = landingView(model, routes);
  }
  // The owned cockpit shell CSS (the automations/T2 cockpit grammar this slice rehomes),
  // carried so the grammar keeps its pixels; the seed lanes keep their own copies untouched.
  const css = `:root{color-scheme:dark}
  body{margin:0;background:#0c0d10;color:#e6e7ea;font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
  .wrap{max-width:920px;margin:0 auto;padding:40px 24px 80px}
  a{color:#8ab4ff}
  .brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#6f7280;margin-bottom:8px}
  h1{font-size:26px;margin:0 0 6px;letter-spacing:-.02em}
  .sub{color:#9a9da6;margin:0 0 22px;max-width:680px;overflow-wrap:anywhere}
  .card .meta{overflow-wrap:anywhere}
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
  .card .meta{color:#878a93;font-size:12.5px;margin-top:3px}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;border:1px solid;white-space:nowrap;margin-left:8px}
  a.pill{margin-left:0;text-decoration:none}
  .ok{color:#46c277;border-color:#235c3b;background:#11281b}
  .warn{color:#d6a13a;border-color:#5c4a23;background:#28220f}
  .muted{color:#9a9da6;border-color:#2a2c33}
  .empty{color:#6f7280;padding:18px;border:1px dashed #24262d;border-radius:12px;overflow-wrap:anywhere}
  .gapcard{padding:14px 16px;border:1px dashed #5c4a23;border-radius:12px;background:#15130c;margin:0 0 18px;overflow-wrap:anywhere}
  .scope{padding:10px 14px;border:1px solid #2a3a5c;border-radius:10px;background:#0e1420;color:#9db4d8;font-size:12.5px;margin:0 0 18px;overflow-wrap:anywhere}
  .banner{padding:12px 14px;border-radius:10px;margin:0 0 18px;font-size:13px;overflow-wrap:anywhere}
  .banner.ok{border:1px solid #235c3b;background:#11281b;color:#bfe8cd}
  .banner.warn{border:1px solid #5c4a23;background:#28220f;color:#e8d9ac}
  .grid{display:grid;grid-template-columns:200px 1fr;gap:8px 16px;padding:16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin:0 0 18px}
  .grid dt{color:#878a93;font-size:12.5px}
  .grid dd{margin:0;color:#e6e7ea;word-break:break-word}
  code{font-size:11.5px;color:#aab;background:#0e0f13;padding:1px 5px;border-radius:4px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;color:#878a93;font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;padding:6px 10px;border-bottom:1px solid #24262d}
  td{padding:8px 10px;border-bottom:1px solid #1b1d23}
  .field{margin:0 0 14px}
  .field label{display:block;color:#c7c9cf;font-size:12.5px;margin-bottom:5px}
  .field input,.field select,.field textarea{width:100%;box-sizing:border-box;padding:10px;border-radius:9px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit}
  .field textarea{min-height:84px;resize:vertical}
  @media(max-width:760px){.grid{grid-template-columns:130px 1fr}table{display:block;overflow-x:auto;max-width:100%}}`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · Hypervisor</title><style>${css}</style></head><body><div class="wrap"><div class="brand">IOI Hypervisor</div>${inner}</div></body></html>`;
}

export const meta = {
  slug: "work",
  route: LEGACY_LANDING,
  verifier: "scripts/verify-hypervisor-work-cockpit.mjs",
  certification: "n/a",
};
