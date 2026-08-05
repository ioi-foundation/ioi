// W0.1 v2 route shell (bring-to-life run) — THE canonical target-route table.
//
// ONE data table (not scattered ifs) declaring every route in the canonical v2 route ledger
// (docs/architecture/components/hypervisor/core-clients-surfaces.md § "Canonical Target Routes"),
// plus `/work/sessions` (Sessions is a typed Work view, never a peer application). The serve
// layer dispatches GETs on these exact paths through `v2RouteFor()` and renders the honest
// surface shell page: surface name · canonical route · owner kind · what already serves it
// today (legacy readouts keep serving untouched until each surface's Wave 1 rehome / Wave 4
// cutover) · named build state. NO fixture data, NO fabricated rows, NO fake counts — the
// "honest absence" pattern from the run charter's standing rules
// (internal-docs/overhaul/2026-08-05-hypervisor-bring-to-life-run.md).
//
// Row shape:
//   route          canonical path (exact match)
//   surface        display name from the route ledger
//   kind           owner kind: core workspace | owner application | substrate | typed Work view |
//                  one-click action | authentication entry | reserved owner application
//   rule           the route-ledger rule column, verbatim where present
//   waves          this surface's wave assignments (internal-docs/implementation/surfaces/_index.md)
//   build_state    named build state — what is real NOW, what wave builds the rest
//   serving_today  [{ href, label, note }] — the live lanes that serve this surface today;
//                  empty array == honest absence (nothing serves it; the page says so)
//   disposition    "shell"      → render the W0.1 shell page (default)
//                  "vendor_spa" → declared here, deliberately passed through: the vendored SPA
//                                 already serves the canonical experience at this exact route
//                  "reserved"   → registered planned + nonlaunchable; page states that
import { escHtml } from "../surfaces/kit.mjs";

export const V2_ROUTE_TABLE = [
  {
    route: "/home",
    surface: "Home",
    kind: "core workspace",
    rule: "—",
    waves: "W0.1 · W1",
    build_state: "shell-only (W0.1) — Wave 1 read-first build pending (surfaces/home.md §5); the explorer Home rehomes here",
    serving_today: [
      { href: "/ai", label: "Explorer Home", note: "owned read-first governed-work explorer at `/` and `/ai` — composes seven daemon reads, fabricates nothing" },
      { href: "/__ioi/home", label: "Home full readout", note: "legacy native readout; rehomes into this route in Wave 1" },
    ],
  },
  {
    route: "/work/new-session",
    surface: "New Session",
    kind: "one-click action (Work)",
    rule: "remains a one-click action",
    waves: "W0.1 · W1",
    build_state: "shell-only (W0.1) — the live composer serves the action today; rehomes here with the Work build (surfaces/work.md §5)",
    serving_today: [
      { href: "/ai#new-session", label: "New Session composer", note: "the live one-click composer with the governed launcher (admission, receipts, isolation named before the effectful call)" },
    ],
  },
  {
    route: "/systems",
    surface: "Systems",
    kind: "core workspace",
    rule: "no fabricated System rows before honest read models",
    waves: "W1 · W3 (interface-binding plane)",
    build_state: "shell-only (W0.1) — System interface-binding plane has zero rows/routes today; Wave 3 backend build (surfaces/systems.md §5). Per canon, no System rows are fabricated before honest read models exist",
    serving_today: [
      { href: "/__ioi/systems", label: "Systems readout", note: "system-genesis surface over daemon truth" },
    ],
  },
  {
    route: "/projects",
    surface: "Projects",
    kind: "core workspace",
    rule: "existing Project context is preserved",
    waves: "W1",
    build_state: "the vendored SPA Projects workspace serves this canonical route today (one of the two v2 routes already resolving); Wave 1 rehome per surfaces/projects.md §5",
    serving_today: [
      { href: "/projects", label: "Projects workspace", note: "the wired vendored SPA page at this exact canonical route — passed through, not replaced (canon: existing Project context is preserved)" },
    ],
    disposition: "vendor_spa",
  },
  {
    route: "/applications",
    surface: "Applications",
    kind: "core workspace",
    rule: "one catalog/compiler projection",
    waves: "W0.2 · W1",
    build_state: "compiler-fed (W0.2) — nav/catalog/palette/launch render the compiled product-surface projection (scripts/surface-compiler.mjs); the three hand-maintained catalogs are retired as authorities; the Wave 1 build lands the full workspace page (surfaces/applications.md §5)",
    serving_today: [
      { href: "/__ioi/applications", label: "Applications estate readout", note: "renders the compiled product-surface projection (W0.2)" },
      { href: "/__ioi/home", label: "Estate launcher", note: "the owned launcher lanes — fed by the same compiled projection as of W0.2" },
    ],
  },
  {
    route: "/work",
    surface: "Work",
    kind: "core workspace",
    rule: "typed views only; Sessions is /work/sessions",
    waves: "W0.6 · W1 · W3 (lineage) · W4 (Cut #2)",
    build_state: "shell-only (W0.1) — typed Work views land in Wave 1 (surfaces/work.md §5); Sessions is the typed view at /work/sessions, never a peer application",
    serving_today: [
      { href: "/work/sessions", label: "Sessions (typed Work view)", note: "resolves as of W0.1; bare /sessions is retired with a typed 410" },
      { href: "/__ioi/missions", label: "Jobs readout", note: "goal-orchestration run queue (absorbed into Work)" },
      { href: "/__ioi/missions/incidents", label: "Incidents inbox", note: "run-failure + goal-blocker inbox (absorbed into Work)" },
      { href: "/__ioi/work-ledger", label: "Work Ledger", note: "the owned proof stream" },
      { href: "/__ioi/run-timeline", label: "Run Timeline", note: "owned governed-work timeline" },
    ],
  },
  {
    route: "/work/sessions",
    surface: "Work / Sessions",
    kind: "typed Work view (core workspace: Work)",
    rule: "Sessions is a Work view, never a peer application; bare /sessions is retired with a typed 410 (no redirect alias)",
    waves: "W0.6 (sessions/overview) · W1 · W4 (execution loop Cut #2)",
    build_state: "shell-only (W0.1) — the typed view renders daemon session truth in Wave 1; lineage family is a Wave 3 backend build (surfaces/work.md §5)",
    serving_today: [
      { href: "/__ioi/sessions", label: "Sessions root readout", note: "session lifecycle facts + admitted harness bindings over daemon truth; rehomes into this view in Wave 1" },
      { href: "/__ioi/run-timeline", label: "Run Timeline", note: "per-run governed-work timeline" },
    ],
  },
  {
    route: "/settings",
    surface: "Settings",
    kind: "core workspace (projection-only, writes-through-owners)",
    rule: "core workspace; panes project canonical owner records",
    waves: "W0.5 · W4",
    build_state: "shell-only at the root (W0.1) — the vendored Settings sections keep serving at /settings/<section>; W0.5 lands identity truth, Wave 4 completes the workspace (surfaces/settings.md §5)",
    serving_today: [
      { href: "/settings/members", label: "Settings · Members", note: "vendored section, adapter-backed — keeps serving untouched" },
      { href: "/settings/policies", label: "Settings · Policies", note: "vendored section, adapter-backed — keeps serving untouched" },
      { href: "/settings/security", label: "Settings · Security", note: "vendored section, adapter-backed — keeps serving untouched" },
    ],
  },
  {
    route: "/sign-in",
    surface: "Sign in",
    kind: "authentication entry",
    rule: "authentication entry; not an application registration",
    waves: "W0.1",
    build_state: "shell-only (W0.1) — the owned login page serves authentication today and rehomes here at cutover",
    serving_today: [
      { href: "/__ioi/login", label: "Sign in", note: "owned login: password + SSO (OIDC PKCE via the daemon)" },
    ],
  },
  {
    route: "/studio",
    surface: "Studio",
    kind: "owner application",
    rule: "—",
    waves: "W1 · W3 (blueprints)",
    build_state: "shell-only (W0.1) — Wave 1 read-first build, blueprints family is a Wave 3 backend build (surfaces/studio.md §5)",
    serving_today: [
      { href: "/__ioi/studio/designer", label: "Solution Designer", note: "protected ported seed (daemon-wired)" },
      { href: "/__ioi/studio/machinery", label: "Machinery", note: "protected ported seed (daemon-wired); machinery moves to Automations in the paired Wave 1 PR" },
    ],
  },
  {
    route: "/automations",
    surface: "Automations",
    kind: "owner application",
    rule: "shell placement and application identity resolve to the same registration",
    waves: "W0.6 (scheduler read) · W1 · W2",
    build_state: "shell-only (W0.1) — Wave 1 read-first build (surfaces/automations.md §5). The click-capture hijack that rewrote this canonical route into /__ioi/automations was retired at W0.1 (canon wins); the legacy readout stays reachable below",
    serving_today: [
      { href: "/__ioi/automations", label: "Automations readout", note: "project-first automations over the daemon scheduler; rehomes into this route in Wave 1" },
      { href: "/__ioi/automations/monitors", label: "Automate / monitors", note: "protected ported seed (daemon-wired)" },
    ],
  },
  {
    route: "/ontology",
    surface: "Ontology",
    kind: "owner application",
    rule: "—",
    waves: "W1 · W2",
    build_state: "shell-only (W0.1) — Wave 1 read-first build (surfaces/ontology.md §5); unreceipted-delete defect is fixed early in that leg",
    serving_today: [
      { href: "/__ioi/ontology/manager", label: "Ontology Manager", note: "protected ported seed (daemon-wired)" },
      { href: "/__ioi/ontology/explorer", label: "Object Explorer", note: "protected ported seed (daemon-wired)" },
      { href: "/__ioi/odk", label: "ODK object planes", note: "ontology / recipe / descriptor / manifest planes (dev kit)" },
    ],
  },
  {
    route: "/data",
    surface: "Data",
    kind: "owner application",
    rule: "—",
    waves: "W1 · W2 · W3 (sources CRUD)",
    build_state: "shell-only (W0.1) — Wave 1 read-first build (surfaces/data.md §5)",
    serving_today: [
      { href: "/__ioi/data/sources", label: "Data Connection", note: "protected ported seed (daemon-wired)" },
      { href: "/__ioi/pipeline", label: "Pipeline Builder", note: "protected ported seed (daemon-wired, workflow-complete)" },
    ],
  },
  {
    route: "/governance",
    surface: "Governance",
    kind: "owner application",
    rule: "—",
    waves: "W0.6 (unified inbox) · W1 · W2",
    build_state: "shell-only (W0.1) — W0.6 folds the disjoint decision planes into one approvals inbox; Wave 1 read-first build (surfaces/governance.md §5)",
    serving_today: [
      { href: "/__ioi/governance", label: "Governance cockpit readout", note: "read projection + named gaps over governance object planes" },
      { href: "/__ioi/governance/approvals", label: "Approvals", note: "protected ported seed (daemon-wired, transition-capable)" },
    ],
  },
  {
    route: "/provenance",
    surface: "Provenance",
    kind: "owner application",
    rule: "—",
    waves: "W1",
    build_state: "shell-only (W0.1) — Wave 1 read-first build (surfaces/provenance.md §5); today's readouts are local-operator-only, the unified receipt-stream projection is a Wave 3 backend build",
    serving_today: [
      { href: "/__ioi/work-ledger", label: "Work Ledger", note: "the owned receipt/proof stream" },
      { href: "/__ioi/lineage", label: "Lineage", note: "protected ported seed (substrate-bound)" },
      { href: "/__ioi/run-timeline", label: "Run Timeline", note: "owned governed-work timeline" },
    ],
  },
  {
    route: "/evaluations",
    surface: "Evaluations",
    kind: "owner application",
    rule: "—",
    waves: "W1 · W3 (epochs/holdouts/challenges)",
    build_state: "shell-only (W0.1) — Wave 1 read-first build; the live receiptless-mutation defect is fixed first (surfaces/evaluations.md §5)",
    serving_today: [
      { href: "/__ioi/evaluations", label: "Evaluations owner surface", note: "eval-suite library over daemon truth (declaration-only)" },
      { href: "/__ioi/evaluations/evalsuites", label: "Eval Suites", note: "protected ported seed (daemon-wired)" },
    ],
  },
  {
    route: "/improvement",
    surface: "Improvement",
    kind: "owner application",
    rule: "—",
    waves: "W1 · W2 · W3 (agendas/campaigns)",
    build_state: "shell-only (W0.1) — Wave 1 read-first build; approve/reject receipts gate the Wave 2 verb rehome (surfaces/improvement.md §5)",
    serving_today: [
      { href: "/__ioi/improvement/changes", label: "Upgrade Assistant", note: "protected ported seed (daemon-wired)" },
    ],
  },
  {
    route: "/foundry",
    surface: "Foundry",
    kind: "owner application",
    rule: "—",
    waves: "W1 · W2",
    build_state: "shell-only (W0.1) — Wave 1 read-first build (surfaces/foundry.md §5); training/dataset route families do not exist anywhere today (Wave 3 build-list)",
    serving_today: [
      { href: "/__ioi/foundry", label: "Foundry readout", note: "draft specs / run plans over the real model substrate (inert)" },
      { href: "/__ioi/foundry/models", label: "Model Catalog", note: "protected ported seed (daemon-wired); honest availability" },
    ],
  },
  {
    route: "/packages",
    surface: "Packages",
    kind: "owner application",
    rule: "Marketplace is the optional mode at /packages/marketplace",
    waves: "W3 (registry family — biggest build)",
    build_state: "shell-only (W0.1) — the packages/* registry family (package, immutable release, install bindings, deprecation/disable/recall/revocation + receipts) is the biggest Wave 3 backend build (surfaces/packages.md §5), around the existing install-admission planner",
    serving_today: [
      { href: "/__ioi/marketplace", label: "Marketplace readout", note: "draft listing/publish/admission object plane (admission-only)" },
      { href: "/__ioi/marketplace/listings", label: "Marketplace listings", note: "protected ported seed (daemon-wired); re-files over the registry in Wave 3" },
    ],
  },
  {
    route: "/developer-workspace",
    surface: "Developer Workspace",
    kind: "owner application",
    rule: "—",
    waves: "W1",
    build_state: "shell-only (W0.1) — Wave 1 rehome; three lanes, not one route (surfaces/developer-workspace.md §5). The per-environment workbench serves at /details/<environment> and /workspaces/<environment> today",
    serving_today: [
      { href: "/__ioi/code", label: "Code Repositories", note: "repos over project truth + SCM posture" },
      { href: "/__ioi/workbench", label: "Workbench readout", note: "owned workbench lane" },
    ],
  },
  {
    route: "/developer-console",
    surface: "Developer Console",
    kind: "owner application",
    rule: "—",
    waves: "W2",
    build_state: "shell-only (W0.1) — Wave 2 build (surfaces/developer-console.md §5); conformance / developer-app registration families are on the Wave 3 build-list",
    serving_today: [
      { href: "/__ioi/odk", label: "ODK dev kit planes", note: "ontology / recipe / descriptor / manifest on-ramps" },
      { href: "/__ioi/domain-apps", label: "Domain apps", note: "DomainApp over ODK descriptor; governed mount/serve ladder" },
    ],
  },
  {
    route: "/environments",
    surface: "Environments",
    kind: "substrate",
    rule: "—",
    waves: "W1 · W2",
    build_state: "shell-only (W0.1) — Wave 1 read-first build (surfaces/environments.md §5); W0.5 deletes the two adapter lies (logs-token fabrication, mark-active no-op)",
    serving_today: [
      { href: "/__ioi/environments", label: "Environments readout", note: "environment lifecycle facts over daemon truth" },
    ],
  },
  {
    route: "/operations",
    surface: "Operations",
    kind: "substrate",
    rule: "—",
    waves: "W1 · W2",
    build_state: "shell-only (W0.1) — Wave 1 read-first build (surfaces/operations.md §5); unified infrastructure-jobs projection is a Wave 3 backend build",
    serving_today: [
      { href: "/__ioi/operations", label: "Operations readout", note: "runs / failures / failover posture over daemon truth" },
    ],
  },
  {
    route: "/embodied-systems",
    surface: "Embodied Systems",
    kind: "conditional specialist owner application (reserved)",
    rule: "planned and nonlaunchable",
    waves: "none — no build scheduled in this run",
    build_state: "reserved — deployment-neutral `planned` registration; explicitly NONLAUNCHABLE until built. This route is a registration placeholder, not a product surface; it owns no readout, no brief, and no UI work",
    serving_today: [],
    disposition: "reserved",
  },
];

// Routes the UI must stop soft-404ing into the SPA: the daemon already refuses them typed
// (hypervisor-daemon.rs /sessions → handle_retired_hypervisor_route, which answers 410 with
// canonical_replacement_route). W0.1 surfaces those semantics in the serving lane — a typed 410
// page with an explicit link, never a redirect alias (ADR 0022 Decision 2: no compatibility
// aliases). Scope note: only /sessions is retired at W0.1; other legacy paths cut over per-app
// in Wave 4.
export const RETIRED_UI_ROUTES = {
  "/sessions": "/work/sessions",
};

const BY_ROUTE = new Map(V2_ROUTE_TABLE.map((r) => [r.route, r]));
export function v2RouteFor(pathname) {
  return BY_ROUTE.get(pathname) || null;
}

// The exact refusal record shape the daemon emits for a retired route
// (crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs handle_retired_hypervisor_route).
export function retiredUiRouteRefusal(requested, replacement) {
  return {
    schema_version: "ioi.hypervisor.route_retirement_refusal.v1",
    code: "hypervisor.route_retired",
    requested_route: requested,
    canonical_replacement_route: replacement,
    read_performed: false,
    mutation_performed: false,
    final_invocation_performed: false,
  };
}

const PAGE_CSS = `
  :root{color-scheme:dark}
  body{margin:0;background:#0c0d10;color:#e6e7ea;font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
  .wrap{max-width:820px;margin:0 auto;padding:48px 24px 80px}
  a{color:#8ab4ff}
  .brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#6f7280;margin-bottom:8px}
  h1{font-size:26px;margin:0 0 6px;letter-spacing:-.02em}
  .sub{color:#9a9da6;margin:0 0 22px;max-width:680px}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#878a93;margin:26px 0 10px;font-weight:600}
  .grid{display:grid;grid-template-columns:170px 1fr;gap:8px 16px;padding:16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin:0 0 18px}
  .grid dt{color:#878a93;font-size:12.5px}
  .grid dd{margin:0;color:#e6e7ea}
  .card{display:flex;align-items:center;gap:14px;padding:14px 16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin-bottom:8px;text-decoration:none;color:inherit}
  a.card:hover{border-color:#3a82f6;background:#191b21}
  .card .main{flex:1;min-width:0}
  .card .name{font-weight:600;color:#fff}
  .card .meta{color:#878a93;font-size:12.5px;margin-top:3px}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;border:1px solid;white-space:nowrap;margin-left:8px;vertical-align:2px}
  .muted{color:#9a9da6;border-color:#2a2c33}
  .warn{color:#d6a13a;border-color:#5c4a23;background:#28220f}
  .empty{color:#6f7280;padding:18px;border:1px dashed #24262d;border-radius:12px}
  code{font-size:11.5px;color:#aab;background:#0e0f13;padding:1px 5px;border-radius:4px}
  pre{background:#0e0f13;border:1px solid #24262d;border-radius:8px;padding:12px;overflow:auto;font:11.5px/1.5 ui-monospace,monospace;color:#cdd1d8;white-space:pre-wrap;word-break:break-all}
  .foot{color:#6f7280;font-size:12.5px;margin-top:28px;border-top:1px solid #1b1d23;padding-top:14px}`;

function pageShell(title, inner) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escHtml(title)} · Hypervisor</title>
<style>${PAGE_CSS}</style></head><body><div class="wrap">${inner}</div></body></html>`;
}

// W0.2: estate-navigation band on every shell page, rendered from the compiled product-surface
// projection (scripts/surface-compiler.mjs — daemon registration records via
// POST /v1/hypervisor/product-surface-projections). Honest absence: daemon down → the band says
// so and shows the safe static first-party inventory with launch state unknown; compiled not
// supplied at all → a named absence line, never a hand list.
function navBand(row, compiled) {
  const esc = escHtml;
  if (!compiled) {
    return `<div class="empty">Compiled product-surface projection not available for this render — navigation is omitted rather than hand-listed.</div>`;
  }
  const link = (s) => {
    const here = s.route === row.route;
    const label = `${s.icon ? s.icon + " " : ""}${s.name}`;
    if (here) return `<span class="pill muted" title="this page">${esc(label)}</span>`;
    const title = s.launchable ? s.route : `${s.route} — ${(s.disabled_reason_codes || []).join(", ") || "not launchable"}`;
    return `<a class="pill muted" style="text-decoration:none" href="${esc(s.route)}" title="${esc(title)}">${esc(label)}${s.launchable ? "" : " ·⃠"}</a>`;
  };
  const down = compiled.daemon?.available !== true
    ? `<p class="sub" style="margin:8px 0 0">Daemon unavailable (<code>${esc(compiled.daemon?.code || "daemon_unavailable")}</code>) — this band shows the safe static first-party inventory; launch state is honestly unknown, nothing is fabricated.</p>`
    : "";
  const wraps = (items) => `<div style="display:flex;flex-wrap:wrap;gap:6px">${items.join("")}</div>`;
  return `${wraps((compiled.workspaces || []).map(link))}
    <div style="height:8px"></div>
    ${wraps((compiled.applications || []).map(link))}${down}`;
}

// The honest W0.1 surface shell page. States what exists; fabricates nothing. `compiled` is the
// W0.2 compiled product-surface projection feeding the navigation band.
export function renderV2RouteShellPage(row, compiled) {
  const esc = escHtml;
  const reserved = row.disposition === "reserved";
  const serving = (row.serving_today || [])
    .map((s) => `<a class="card" href="${esc(s.href)}"><div class="main"><div class="name">${esc(s.label)}</div><div class="meta">${esc(s.note)}</div></div><span class="pill muted">${esc(s.href)}</span></a>`)
    .join("");
  const servingBlock = serving
    ? `${serving}<p class="sub" style="margin-top:10px">These lanes keep serving untouched; they rehome into this route at this surface's Wave&nbsp;1 build / Wave&nbsp;4 cutover — nothing is deleted or redirected at W0.1.</p>`
    : `<div class="empty">Nothing serves this surface today. This page states that honestly — no fixture rows, no fabricated counts, no placeholder data.</div>`;
  return pageShell(
    row.surface,
    `<div class="brand">IOI Hypervisor · v2 route shell (W0.1)</div>
    <h1>${esc(row.surface)}${reserved ? '<span class="pill warn">reserved · nonlaunchable</span>' : ""}</h1>
    <p class="sub">${
      reserved
        ? "This owner application is registered <b>planned</b> and is <b>nonlaunchable until built</b>. The route is reserved by the canonical route ledger; no surface, readout, or build exists or is scheduled in the current run."
        : "Honest surface shell: this canonical route resolves as of W0.1. The panes below name what is real today; everything else arrives wave by wave — nothing here is fabricated."
    }</p>
    <h2>Registration</h2>
    <dl class="grid">
      <dt>Canonical route</dt><dd><code>${esc(row.route)}</code></dd>
      <dt>Owner kind</dt><dd>${esc(row.kind)}</dd>
      <dt>Route-ledger rule</dt><dd>${esc(row.rule)}</dd>
      <dt>Wave assignments</dt><dd>${esc(row.waves)}</dd>
      <dt>Build state</dt><dd>${esc(row.build_state)}</dd>
    </dl>
    <h2>Serving this surface today</h2>
    ${servingBlock}
    <h2>Estate navigation — compiled product-surface projection (W0.2)</h2>
    ${navBand(row, compiled)}
    <div class="foot">Route declared in the canonical target-route ledger (core-clients-surfaces.md § Canonical Target Routes) and resolved by the W0.1 route table (<code>apps/hypervisor/scripts/v2-route-shell.mjs</code>); navigation compiled by <code>apps/hypervisor/scripts/surface-compiler.mjs</code>. <a href="/ai">← Home</a></div>`,
  );
}

// Typed-410 page for a retired UI route — surfaces the daemon's refusal semantics verbatim and
// points (a link, never a redirect) at the canonical replacement.
export function renderRetiredUiRoutePage(requested, replacement) {
  const esc = escHtml;
  const refusal = retiredUiRouteRefusal(requested, replacement);
  return pageShell(
    "Route retired",
    `<div class="brand">IOI Hypervisor · typed route retirement</div>
    <h1>410 · <code>${esc(requested)}</code> is retired</h1>
    <p class="sub">This path no longer resolves — per ADR 0022 Decision 2 there are no compatibility aliases, so a retired path fails with a typed refusal rather than redirecting. The canonical replacement is <a href="${esc(replacement)}"><code>${esc(replacement)}</code></a> (Sessions is a typed Work view, never a peer application).</p>
    <h2>Refusal record (daemon semantics)</h2>
    <pre>${esc(JSON.stringify(refusal, null, 2))}</pre>
    <div class="foot"><a href="${esc(replacement)}">Go to <code>${esc(replacement)}</code> →</a> · <a href="/ai">← Home</a></div>`,
  );
}
