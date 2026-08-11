// Home — the canonical /home PARTIAL PRE-W3 COCKPIT SLICE (next-legs IV Leg 4).
//
// SCOPE RULING (bounds every claim in this file): this is NOT Home completion. SURF-home and
// W3.1 REMAIN OPEN. The manifest SURF-home acceptance (owner-backed resumable/blocked/failed/
// approval-requiring/completed work as counts and rows that deep-link correctly; full state
// survival) is the FULL bar — this slice delivers the pre-W3 subset only. Evidence:
// scripts/verify-hypervisor-home-cockpit.mjs (check:home-cockpit — deliberately NOT a
// "-journey"; the Home journey is SURF-home's to earn).
//
// GREENFIELD, TYPED NON-PARITY: no provenance-qualified seed exists for Home — two recovery
// passes promoted zero candidates — so this build rides the owner-authorized
// greenfield-authorized-non-parity lane recorded in apps/hypervisor/seed-ux-provenance.v1.json
// (home record). It claims no seed preservation and no parity; it is canon-first over
// docs/architecture/components/hypervisor/core-clients-surfaces.md (§ Home: default command
// and resume surface; Home may draft work but must NOT become the durable owner of anything).
// The live /ai explorer readout is a CURRENT LIVE ENTRY, untouched — never a substitute seed.
//
// TYPED W3 ABSENCES stated, never simulated:
//   - `GET /v1/hypervisor/home-cockpit` (ioi.hypervisor.home_cockpit_projection.v1,
//     api.md:132-169) and `GET /v1/hypervisor/session-operations` (api.md:171-181) are
//     route-missing at the daemon — the W3 build list owns them. This slice therefore composes
//     the SAME per-family reads the live /ai explorer composes, server-side over the shared
//     read client; the metrics strip that needs the projection stays a named absence, never a
//     fabricated rollup.
//   - The canonical /operations mount is NOT live on this estate: no surface row binds it.
//     Parked-at-wallet-gate and failed-run rows render their REAL counts (failover/operations
//     reads) but their owning-surface links are disabled-named-gap — named, never a dead link.
//
// READ-ONLY BY CONTRACT: Home launches; it owns no object and performs no mutation. New
// Session is Work's affordance ADVERTISED here (navigation to /work/new-session — the
// identity-carrying create lane lives with Work); the Applications grid renders the compiler
// projection's truth and nothing the projection wouldn't admit (the #241 refusal-set approach
// guards folded owner names). The canon fallback-fixture rule (api.md:167-169) is held
// verbatim: a daemon outage renders a typed unavailability page with ZERO fabricated counts —
// nothing is shown rather than fixtures.
import { escHtml } from "../kit.mjs";

const esc = escHtml;
const enc = encodeURIComponent;

const LEGACY_ROUTE = "/__ioi/home-cockpit";
const CANONICAL_ROUTE = "/home";

// LIVE deep-link targets on this estate (each one a bound canonical mount or served subtree).
const LINK_APPROVALS = "/governance/approvals";
const LINK_SESSIONS = "/work/sessions";
const LINK_NEW_SESSION = "/work/new-session";
const LINK_PROJECTS = "/projects";
const LINK_APPLICATIONS = "/applications";
const LINK_AI_ENTRY = "/ai";

const SCOPE_MARKER = "partial-pre-w3-cockpit-slice";
const SCOPE_NOTE = "Partial pre-W3 cockpit slice — NOT Home completion. SURF-home and W3.1 remain open; the manifest SURF-home acceptance is the full bar and this slice delivers the pre-W3 subset. The home-cockpit projection route is a typed W3 absence (stated below), and the /ai explorer readout keeps serving untouched as a current live entry.";

const HOME_PROJECTION_ABSENCE = "typed W3 absence — GET /v1/hypervisor/home-cockpit (ioi.hypervisor.home_cockpit_projection.v1) and GET /v1/hypervisor/session-operations are route-missing at the daemon (the W3 build list owns them). This page composes the same per-family reads the live /ai explorer composes; the metrics strip that needs the projection stays a named absence, never a fabricated rollup.";
const OPERATIONS_GAP_REASON = "disabled-named-gap — the canonical Operations mount is not live on this estate: no Operations surface module binds /operations (the route serves only the W0.1 substrate shell today). The parked/failed-run counts on this pane are REAL daemon truth (GET /v1/hypervisor/failover/runs · GET /v1/hypervisor/operations), but their owning-surface deep-links stay disabled until the Operations mount lands; a named gap, never a dead link and never a fabricated destination.";

const PROJECTION_PATH = "/v1/hypervisor/product-surface-projections";
const PROJECTION_SCHEMA = "ioi.hypervisor.product_surface_projection.v1";

// The folded-owner refusal set (#241, the Applications launcher approach): these names owned
// surfaces once and were folded into canonical owners. A projection entry carrying one renders
// as a typed defect refusal, never as a peer tile. This module renders server-side, so the
// names below reach the page only inside that refusal.
const RETIRED_OWNER_NAMES = new Set(["Missions", "Marketplace", "Workbench", "Agent Studio"]);

export const meta = {
  slug: "home",
  route: LEGACY_ROUTE,
  verifier: "scripts/verify-hypervisor-home-cockpit.mjs",
  certification: "n/a",
};

// ---------------------------------------------------------------------------------------------
// load — every read through the shared read client on the request-scoped identity capability
// (the caller's own envelope rides every read; the daemon owner-filters session truth before
// this page ever sees it). Seven owner-backed reads, the same families the live explorer
// composes — REAL routes only, no home-cockpit rollup exists to read (typed W3 absence).
export async function load(ctx) {
  const { createReadClient } = await import("../read-client.mjs");
  const client = typeof ctx.daemonFetch === "function"
    ? createReadClient({ daemon: "", fetchImpl: ctx.daemonFetch })
    : createReadClient({ daemon: ctx.daemon });
  const [whoami, approvals, failover, operations, sessions, projects, projection] = await Promise.all([
    client.read("/v1/hypervisor/auth/whoami"),
    client.read("/v1/hypervisor/governance/approval-requests"),
    client.read("/v1/hypervisor/failover/runs"),
    client.read("/v1/hypervisor/operations"),
    client.read("/v1/hypervisor/sessions", { expectSchema: "ioi.hypervisor.sessions-list.v1" }),
    client.read("/v1/hypervisor/projects"),
    client.read(PROJECTION_PATH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ context: { launcher: "home" } }),
      expectSchema: PROJECTION_SCHEMA,
    }),
  ]);
  return { whoami, approvals, failover, operations, sessions, projects, projection };
}

// No actions, deliberately: Home creates nothing. New Session is Work's affordance (canon
// :1478-1482 — Home can ASK Core to create a New Session; the create lane lives at
// /work/new-session), Activate Goal is GoalRun's (absent here — W2 scope). Declaring an
// action here would make Home mint an object it must never own.
export const actions = [];

// ---------------------------------------------------------------------------------------------
const pill = (text, cls) => `<span class="pill ${cls}">${esc(text)}</span>`;
const scopeBanner = () => `<div class="scope" data-ioi-scope="${SCOPE_MARKER}">${esc(SCOPE_NOTE)}</div>`;
const degraded = (result, plane) => `<div class="empty" data-ioi-degraded="${esc(result?.code || "daemon_unavailable")}" data-ioi-degraded-plane="${esc(plane)}">unavailable — <code>${esc(result?.code || "daemon_unavailable")}</code> (${esc(result?.message || "the plane did not answer")}). A down read renders its typed absence; zeros are never shown as truth.</div>`;
const disabledGapLink = (label) => `<button class="act ghost" type="button" disabled data-ioi-named-gap="operations-mount" data-ioi-disabled-reason="${esc(OPERATIONS_GAP_REASON)}">${esc(label)}</button>`;

const lifecyclePill = (state) => pill(state || "unknown", state === "provisioned" ? "ok" : state === "torn_down" ? "muted" : "warn");

// ---- governed-work band ---------------------------------------------------------------------
function approvalsPane(res) {
  const head = `<h2 id="home-approvals">Approvals waiting</h2>`;
  if (!res?.ok) return `${head}${degraded(res, "governance/approval-requests")}`;
  const pending = (Array.isArray(res.payload?.approval_requests) ? res.payload.approval_requests : [])
    .filter((a) => a.status === "pending");
  if (!pending.length) {
    return `${head}<div class="empty" data-ioi-honest-empty="approvals">No approvals waiting — all clear. This count reads real governance truth (<code>GET /v1/hypervisor/governance/approval-requests</code>); it never fabricates rows.</div>
      <div class="row"><a class="act ghost" href="${LINK_APPROVALS}">Open Governance / Approvals →</a></div>`;
  }
  const rows = pending.slice(0, 5).map((a) => `<a class="card" data-ioi-approval-row href="${LINK_APPROVALS}">
      <div class="main"><div class="name">${esc(a.request_kind || "approval")} ${pill("pending", "warn")}</div>
      <div class="meta"><code>${esc(a.subject_ref || "")}</code>${a.requested_at ? ` · ${esc(a.requested_at)}` : ""}</div></div>
      <span class="act ghost">review →</span></a>`).join("");
  return `${head}<div class="row">${pill(`${pending.length} waiting`, "warn")}</div>${rows}
    <div class="row"><a class="act ghost" href="${LINK_APPROVALS}">Open Governance / Approvals →</a></div>`;
}

function parkedAndFailedPane(failover, operations) {
  const head = `<h2 id="home-parked-failed">Runs parked at the wallet gate · failed runs</h2>
    <p class="sub">Counts are real daemon truth. Their owning surface is Operations, whose canonical mount is not live yet — the Operations links on this pane are a <b>disabled named gap</b>, never a dead link.</p>
    <div class="row">${disabledGapLink("Open Operations →")}</div>`;
  const parkedBody = (() => {
    if (!failover?.ok) return degraded(failover, "failover/runs");
    const parked = (Array.isArray(failover.payload?.runs) ? failover.payload.runs : [])
      .filter((r) => String(r.status || "").startsWith("awaiting_authority"));
    if (!parked.length) return `<div class="empty" data-ioi-honest-empty="parked-runs">No runs parked at a wallet gate (<code>GET /v1/hypervisor/failover/runs</code>, <code>awaiting_authority_*</code>) — all clear, never fabricated.</div>`;
    return `<div class="row">${pill(`${parked.length} parked`, "warn")}</div>` + parked.slice(0, 5).map((r) => `<div class="card" data-ioi-parked-row>
        <div class="main"><div class="name">parked — ${esc(String(r.status || "").replace("awaiting_authority_", ""))} ${pill("blocked", "warn")}</div>
        <div class="meta">${esc(r.failure_condition || "run")}${r.environment_ref ? ` · <code>${esc(r.environment_ref)}</code>` : ""}</div></div>
        ${disabledGapLink("Operations →")}</div>`).join("");
  })();
  const failedBody = (() => {
    if (!operations?.ok) return degraded(operations, "operations");
    const failures = Array.isArray(operations.payload?.runs?.failures) ? operations.payload.runs.failures : [];
    if (!failures.length) return `<div class="empty" data-ioi-honest-empty="failed-runs">No failed runs (<code>GET /v1/hypervisor/operations</code>) — all clear, never fabricated.</div>`;
    return `<div class="row">${pill(`${failures.length} failed`, "warn")}</div>` + failures.slice(0, 5).map((r) => `<div class="card" data-ioi-failed-row>
        <div class="main"><div class="name">failed — ${esc(r.name || r.automation_id || r.execution_id || "run")} ${pill("failed", "warn")}</div>
        <div class="meta">${esc(r.project_id || "—")}${r.finished_at ? ` · ${esc(r.finished_at)}` : ""}</div></div>
        ${disabledGapLink("Operations →")}</div>`).join("");
  })();
  return `${head}${parkedBody}${failedBody}`;
}

// ---- resume band ----------------------------------------------------------------------------
function sessionsPane(res) {
  const head = `<h2 id="home-recent-sessions">Recent sessions</h2>`;
  if (!res?.ok) return `${head}${degraded(res, "sessions")}`;
  const sessions = Array.isArray(res.payload?.sessions) ? res.payload.sessions : [];
  if (!sessions.length) {
    return `${head}<div class="empty" data-ioi-honest-empty="sessions">No sessions for this principal yet — session truth is owner-filtered by the daemon before this page sees it. Start one from <a href="${LINK_NEW_SESSION}">New Session</a>.</div>
      <div class="row"><a class="act ghost" href="${LINK_SESSIONS}">Open Work / Sessions →</a></div>`;
  }
  const rows = sessions.slice(0, 5).map((s) => `<a class="card" data-ioi-session-row href="${LINK_SESSIONS}?session=${enc(s.session_ref || "")}">
      <div class="main"><div class="name"><code>${esc(s.session_ref || "")}</code> ${lifecyclePill(s.lifecycle_state)}</div>
      <div class="meta">${s.project_ref ? `<code>${esc(String(s.project_ref))}</code> · ` : ""}${esc(s.created_at || "")}</div></div>
      <span class="act ghost">resume →</span></a>`).join("");
  return `${head}<div class="row">${pill(`${sessions.length} session${sessions.length === 1 ? "" : "s"}`, "muted")}</div>${rows}
    <div class="row"><a class="act ghost" href="${LINK_SESSIONS}">Open Work / Sessions →</a></div>`;
}

function projectsPane(res) {
  const head = `<h2 id="home-recent-projects">Recent projects</h2>`;
  if (!res?.ok) return `${head}${degraded(res, "projects")}`;
  const projects = Array.isArray(res.payload?.projects) ? res.payload.projects : [];
  if (!projects.length) {
    return `${head}<div class="empty" data-ioi-honest-empty="projects">No projects yet — honest absence (<code>GET /v1/hypervisor/projects</code>), nothing substituted.</div>
      <div class="row"><a class="act ghost" href="${LINK_PROJECTS}">Open Projects →</a></div>`;
  }
  const rows = projects.slice(0, 5).map((p) => `<a class="card" data-ioi-project-row href="${LINK_PROJECTS}">
      <div class="main"><div class="name">${esc(p.name || p.project_id || "project")}</div>
      <div class="meta"><code>${esc(p.project_id || p.id || "")}</code>${p.created_at ? ` · ${esc(p.created_at)}` : ""}</div></div>
      <span class="act ghost">open →</span></a>`).join("");
  return `${head}<div class="row">${pill(`${projects.length} project${projects.length === 1 ? "" : "s"}`, "muted")}</div>${rows}
    <div class="row"><a class="act ghost" href="${LINK_PROJECTS}">Open Projects →</a></div>`;
}

// ---- applications grid (projection truth only — the #241 refusal-set approach) --------------
function applicationsPane(res) {
  const head = `<h2 id="home-applications">Applications</h2>`;
  if (!res?.ok) {
    return `${head}${degraded(res, "product-surface-projections")}
      <p class="sub">Zero tiles render on a failed projection read: a launcher tile implies launch adjudication, and this pane never fabricates launchability — membership comes only from <code>POST ${esc(PROJECTION_PATH)}</code>.</p>
      <div class="row"><a class="act ghost" href="${LINK_APPLICATIONS}">Open Applications →</a></div>`;
  }
  const entries = Array.isArray(res.payload?.application_entries) ? res.payload.application_entries : [];
  const tiles = entries.map((entry) => {
    const name = String(entry.display_name || entry.identity_ref || "");
    if (RETIRED_OWNER_NAMES.has(name)) {
      // Folded owners never reappear as peers — a typed defect refusal, never a tile.
      return `<div class="card defect" data-ioi-retired-owner-defect="${esc(name)}">
          <div class="main"><div class="name">retired owner name refused</div>
          <div class="meta">the projection emitted a folded owner name as a peer entry — this grid refuses to render it as an application; the canonical owner carries this surface (defect: report against the compiler feed)</div></div>
        </div>`;
    }
    const launchRoute = typeof entry.resolved_launch_route === "string" && entry.resolved_launch_route.startsWith("/")
      ? entry.resolved_launch_route
      : null;
    if (entry.launchable === true && launchRoute !== null) {
      return `<a class="card launch" data-ioi-entry-name="${esc(name)}" data-ioi-launchable="true" href="${esc(launchRoute)}">
          <div class="main"><div class="name">${esc(name)}</div>
          <div class="meta">launch → <code>${esc(launchRoute)}</code></div></div>
          <span class="pill ok">launchable</span></a>`;
    }
    const reasons = Array.isArray(entry.disabled_reason_codes) && entry.disabled_reason_codes.length
      ? entry.disabled_reason_codes.map((c) => `<code>${esc(String(c))}</code>`).join(" ")
      : "—";
    return `<div class="card" data-ioi-entry-name="${esc(name)}" data-ioi-launchable="false">
        <div class="main"><div class="name">${esc(name)}</div>
        <div class="meta">not launchable — reasons: ${reasons}</div></div>
        <span class="pill warn">not launchable</span></div>`;
  }).join("");
  const grid = entries.length
    ? tiles
    : `<div class="empty" data-ioi-honest-empty="applications">The compiled projection returned zero application entries — honest absence, nothing is substituted.</div>`;
  return `${head}
    <p class="sub">Compiler-projection truth only (<code>POST ${esc(PROJECTION_PATH)}</code>): launchable tiles navigate to their surface, ineligible tiles state their exact typed reasons, and nothing renders that the projection wouldn't admit (folded owner names are a refusal set). The <a href="${LINK_APPLICATIONS}">Applications launcher →</a> is the full catalog.</p>
    ${grid}`;
}

// ---- full daemon outage: the canon fallback-fixture rule, held verbatim ---------------------
const READ_KEYS = ["whoami", "approvals", "failover", "operations", "sessions", "projects", "projection"];
function daemonUnreachable(model) {
  return READ_KEYS.every((key) => {
    const r = model[key];
    return r && r.ok === false && (r.code === "daemon_unavailable" || r.code === "read_timeout" || r.status === 0);
  });
}

function unavailableView(model) {
  const first = model.whoami;
  return `<div class="gapcard" data-ioi-daemon-unavailable="true">
      <b>Daemon unreachable — governed-work status unavailable.</b>
      <p class="sub" style="margin:6px 0 0;text-transform:none;letter-spacing:0">Every read failed typed (<code>${esc(first?.code || "daemon_unavailable")}</code>). Zero counts are fabricated and zero rows are shown rather than fixtures — the canon fallback-fixture rule (api.md:167-169): a fixture source must be visible and must never be presented as admitted runtime truth, so nothing is presented at all. The page returns when the daemon answers.</p>
    </div>
    <div class="row">
      <a class="act ghost" href="${LINK_APPROVALS}">Governance / Approvals →</a>
      <a class="act ghost" href="${LINK_SESSIONS}">Work / Sessions →</a>
      <a class="act ghost" href="${LINK_PROJECTS}">Projects →</a>
      <a class="act ghost" href="${LINK_APPLICATIONS}">Applications →</a>
    </div>`;
}

// ---------------------------------------------------------------------------------------------
export function render(model, ctx) {
  const who = model.whoami?.ok
    ? (model.whoami.payload?.principal?.name || model.whoami.payload?.principal?.principal_id || model.whoami.payload?.principal_ref || "")
    : "";
  const identityLine = model.whoami?.ok
    ? `signed in as <code>${esc(String(who || "principal"))}</code>`
    : `identity read unavailable — <code>${esc(model.whoami?.code || "daemon_unavailable")}</code> (typed absence, never a guessed name)`;
  const getStarted = `<div class="row">
      <a class="act" href="${LINK_NEW_SESSION}" data-ioi-new-session-entry>+ New Session</a>
      <a class="act ghost" href="${LINK_APPLICATIONS}">Applications</a>
      <a class="act ghost" href="${LINK_PROJECTS}">Projects</a>
      <a class="act ghost" href="${LINK_AI_ENTRY}">Explorer readout (/ai)</a>
    </div>
    <p class="sub">New Session is Work's affordance advertised here — Home asks Core to create it at <code>${LINK_NEW_SESSION}</code> and never mints the object itself. Home owns no truth: every row routes to its owning surface.</p>`;
  const projectionAbsence = `<div class="gapcard" data-ioi-w3-absence="home_cockpit_projection">
      <b>Metrics strip absent — a typed W3 absence.</b>
      <p class="sub" style="margin:6px 0 0;text-transform:none;letter-spacing:0">${esc(HOME_PROJECTION_ABSENCE)}</p>
    </div>`;
  const inner = daemonUnreachable(model)
    ? `${scopeBanner()}${unavailableView(model)}${projectionAbsence}`
    : `${scopeBanner()}${getStarted}${projectionAbsence}
      ${approvalsPane(model.approvals)}
      ${parkedAndFailedPane(model.failover, model.operations)}
      ${sessionsPane(model.sessions)}
      ${projectsPane(model.projects)}
      ${applicationsPane(model.projection)}`;
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
  a.card.launch:hover{border-color:#3a82f6;background:#191b21}
  .card.defect{border-color:#5c2323;background:#221111}
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
  code{font-size:11.5px;color:#aab;background:#0e0f13;padding:1px 5px;border-radius:4px}
  @media(max-width:700px){.wrap{padding:24px 14px 56px}.card{align-items:flex-start}}`;
  const head = `<h1 id="home-owner">Home</h1>
    <p class="sub">The default command and resume surface — owner-backed counts and rows from real daemon routes, deep-linking into the owning surfaces. ${identityLine}.</p>`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Home · Hypervisor</title><style>${css}</style></head><body><div class="wrap"><div class="brand">IOI Hypervisor</div>${head}${inner}</div></body></html>`;
}
