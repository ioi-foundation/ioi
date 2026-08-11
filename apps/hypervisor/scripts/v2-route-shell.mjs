// W0.1 v2 route shell (bring-to-life run) — THE canonical target-route table.
//
// ONE data table (not scattered ifs) declaring every route in the canonical v2 route ledger
// (docs/architecture/components/hypervisor/core-clients-surfaces.md § "Canonical Target Routes"),
// plus `/work/sessions` (Sessions is a typed Work view, never a peer application). The serve
// layer dispatches GETs on these exact paths through `v2RouteFor()` and renders the honest
// surface shell page: surface name · canonical route · owner kind · what already serves it
// today (legacy readouts keep serving untouched until each surface's Wave 1 rehome / Wave 4
// cutover) · named build state. NO fixture data, NO fabricated rows, NO fake counts — a
// surface with nothing real behind it renders honest absence and says so, never a
// simulated body (docs/architecture/_meta/doc-classes.md status doctrine applies).
//
// Row shape:
//   route          canonical path (exact match owns the root; W1.3 adds segment-boundary
//                  deep-link resolution — see resolveV2Route)
//   surface        display name from the route ledger
//   kind           owner kind: core workspace | owner application | substrate | typed Work view |
//                  one-click action | authentication entry | reserved owner application
//   rule           the route-ledger rule column, verbatim where present
//   deep_links     "passthrough" → subpaths under this root are NOT captured (vendored
//                  sections keep serving, e.g. /settings/members). Absent → subpaths resolve
//                  to this row's shell page with the deep link named honestly (W1.3);
//                  vendor_spa rows fall through structurally regardless.
//   waves          this surface's wave assignments — advisory labels from the private
//                  implementation program (gitignored); nothing tracked depends on them
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
    build_state: "W2.1 partial pre-W3 cockpit slice landed (next-legs IV Leg 3) — the bound Work surface module serves this canonical route: create exactly ONE admitted session via POST /v1/hypervisor/sessions on the identity-carrying action lane (202 + provision receipt), NO subject input (subject_attachments is hardcoded empty at the daemon — the typed W3 C-1 absence is stated on the form; project_ref stays a session field, never a subject attachment). NOT Work completion: W3.1 owns the launch/run chain and SURF-work remains open",
    serving_today: [
      { href: "/work/new-session", label: "New Session (canonical)", note: "bound Work surface module — the one-click admitted create; typed W3 absences stated" },
      { href: "/__ioi/work-new-session", label: "New Session (legacy lane)", note: "same module on the fresh legacy lane; keeps serving until the W4 cutover" },
      { href: "/ai#new-session", label: "New Session composer", note: "the live composer with the governed launcher — keeps serving untouched until the Work cutover" },
    ],
  },
  {
    route: "/systems",
    surface: "Systems",
    kind: "core workspace",
    rule: "no fabricated System rows before honest read models",
    waves: "W1 · W3 (interface-binding plane)",
    build_state: "W2.1 greenfield workspace landed (next-legs III Leg 4) — the bound surface module serves this canonical route: inventory + detail over the daemon's autonomous-system read projection VERBATIM (honest_empty and the fail-closed system_projection_source_incomplete stop pass through untouched — the route rule holds by construction); genesis compose and sequence-zero cross through the shared CapabilityLease client (403 challenge commitments, 428 credential lane, receipted crossings); the remaining family verbs are read-first or disabled with a named reason; Interfaces stays the OQ-9 disabled named gap until the W3 interface-binding plane lands. Greenfield-authorized non-parity lane (seed-ux-provenance.v1.json)",
    serving_today: [
      { href: "/systems", label: "Systems workspace (canonical)", note: "bound surface module — projection truth verbatim, lease-client crossings, typed refusal ladder" },
      { href: "/__ioi/systems-workspace", label: "Systems workspace (legacy lane)", note: "same module on the fresh legacy lane; keeps serving until the W4 cutover" },
      { href: "/__ioi/systems", label: "Systems genesis readout", note: "the M1.6/M1.7 system-genesis cockpit over daemon truth; keeps serving untouched until the W4 cutover" },
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
    build_state: "W2.1 greenfield launcher landed (next-legs III Leg 3) — the bound surface module serves this canonical route: a READ-ONLY launcher over the one compiled product-surface projection joined live with the package registry (typed ineligibility verbatim, reserved registrations declared nonlaunchable, recall removes rows by derivation on every read). Greenfield-authorized non-parity lane (seed-ux-provenance.v1.json); the W0.2 compiled navigation band keeps feeding the shell pages",
    serving_today: [
      { href: "/applications", label: "Applications launcher (canonical)", note: "bound surface module — compiler+registry truth only; launch is navigation, never a mutation" },
      { href: "/__ioi/applications-launcher", label: "Applications launcher (legacy lane)", note: "same module on the fresh legacy lane; keeps serving until the W4 cutover" },
      { href: "/__ioi/applications", label: "Applications estate readout", note: "renders the compiled product-surface projection (W0.2); keeps serving untouched until the W4 cutover" },
      { href: "/__ioi/home", label: "Estate launcher", note: "the owned launcher lanes — fed by the same compiled projection as of W0.2" },
    ],
  },
  {
    route: "/work",
    surface: "Work",
    kind: "core workspace",
    rule: "typed views only; Sessions is /work/sessions",
    waves: "W0.6 · W1 · W3 (lineage) · W4 (Cut #2)",
    build_state: "W2.1 partial pre-W3 cockpit slice landed (next-legs IV Leg 3) — the bound Work surface module serves this canonical route: the jobs/incidents cockpit grammar rehomed READ-FIRST (rows link to the protected seeds, which keep serving untouched — seed-preservation invariant) plus the sessions rollup. NOT Work completion: W3.1 owns the admission→harness→run→events/receipts→stop/archive/recovery/replay chain; the other typed views stay honest shell pages (SURF-work remains open)",
    serving_today: [
      { href: "/work", label: "Work cockpit (canonical)", note: "bound Work surface module — partial pre-W3 cockpit slice; read-first rehomed cockpit grammar, typed W3 absences" },
      { href: "/__ioi/work-cockpit", label: "Work cockpit (legacy lane)", note: "same module on the fresh legacy lane; keeps serving until the W4 cutover" },
      { href: "/work/sessions", label: "Sessions (typed Work view)", note: "module-served; bare /sessions is retired with a typed 410" },
      { href: "/__ioi/missions", label: "Jobs readout", note: "protected seed — goal-orchestration run queue (absorbed into Work); keeps serving untouched" },
      { href: "/__ioi/missions/incidents", label: "Incidents inbox", note: "protected seed — run-failure + goal-blocker inbox (absorbed into Work); keeps serving untouched" },
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
    build_state: "W2.1 partial pre-W3 cockpit slice landed (next-legs IV Leg 3) — the bound Work surface module serves this canonical route: sessions list + the W0.6 counts-first overview (owner-filtered before counts) + per-session lifecycle facts with the ADMITTED harness binding rendered as session truth recorded at create, never UI state. Typed W3 absences pinned: subject_attachments hardcoded empty (C-1), no session-level stop/archive route, no typed HarnessSessionLaunch producer (launch/terminal/replay/recovery disabled with the machine-readable reason). NOT Work completion — W3.1 owns the execution chain; lineage family stays the Wave 3 backend build",
    serving_today: [
      { href: "/work/sessions", label: "Work / Sessions (canonical)", note: "bound Work surface module — lifecycle facts + admitted bindings over daemon truth; typed W3 absences" },
      { href: "/__ioi/work-sessions", label: "Work / Sessions (legacy lane)", note: "same module on the fresh legacy lane; keeps serving until the W4 cutover" },
      { href: "/__ioi/sessions", label: "Sessions root readout", note: "the T2 readout this view's grammar was rehomed from; keeps serving untouched until the W4 cutover" },
      { href: "/__ioi/run-timeline", label: "Run Timeline", note: "per-run governed-work timeline" },
    ],
  },
  {
    route: "/settings",
    surface: "Settings",
    kind: "core workspace (projection-only, writes-through-owners)",
    deep_links: "passthrough",
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
    build_state: "W2.1 rehome landed — the bound surface module serves this canonical route (spec list/detail/new read-first over the shared read client; daemon-owned verbs through the seed cockpit lanes; receipts are the W2 lease-client wave per surfaces/automations.md §5). Legacy lanes keep serving until the W4 cutover",
    serving_today: [
      { href: "/automations", label: "Automations (canonical)", note: "rehomed module at the canonical route — read-first cockpit over the daemon automations family" },
      { href: "/__ioi/automations", label: "Automations readout (legacy lane)", note: "keeps serving untouched until the W4 cutover" },
      { href: "/__ioi/automations/monitors", label: "Automate / monitors", note: "protected ported seed (daemon-wired)" },
    ],
  },
  {
    route: "/ontology",
    surface: "Ontology",
    kind: "owner application",
    rule: "—",
    waves: "W1 · W2",
    build_state: "W2.1 rehome step 1 landed — the Manager serves canonically at /ontology/schema and the Explorer at /ontology/explore (same modules; legacy /__ioi lanes keep serving until the W4 cutover). Unreceipted-delete defect fixed (packet 6); remaining waves per surfaces/ontology.md §5",
    serving_today: [
      { href: "/ontology/schema", label: "Ontology Manager (canonical)", note: "rehomed module at the canonical route — receipted semantic authoring over admitted ontologies" },
      { href: "/ontology/explore", label: "Object Explorer (canonical)", note: "rehomed module at the canonical route — read-only instance/exploration lens" },
      { href: "/__ioi/ontology/manager", label: "Ontology Manager (legacy lane)", note: "keeps serving untouched until the W4 cutover" },
      { href: "/__ioi/ontology/explorer", label: "Object Explorer (legacy lane)", note: "keeps serving untouched until the W4 cutover" },
      { href: "/__ioi/odk", label: "ODK object planes", note: "ontology / recipe / descriptor / manifest planes (dev kit)" },
    ],
  },
  {
    route: "/data",
    surface: "Data",
    kind: "owner application",
    rule: "—",
    waves: "W1 · W2 · W3 (sources CRUD)",
    build_state: "W2.1 rehome step 1 — Data Connection serves canonically at /data/sources and the Pipeline/Recipe Builder at /data/recipes (same modules; legacy /__ioi lanes serving until the W4 cutover); reads ride the shared client. Wave 1 read-first build continues per surfaces/data.md §5",
    serving_today: [
      { href: "/data/sources", label: "Data Connection (canonical)", note: "rehomed source-declaration module at the canonical route" },
      { href: "/data/recipes", label: "Recipe / Pipeline Builder (canonical)", note: "rehomed pipeline module at the canonical route" },
      { href: "/__ioi/data/sources", label: "Data Connection (legacy lane)", note: "keeps serving until the W4 cutover" },
      { href: "/__ioi/pipeline", label: "Pipeline Builder (legacy lane)", note: "keeps serving until the W4 cutover" },
    ],
  },
  {
    route: "/governance",
    surface: "Governance",
    kind: "owner application",
    rule: "—",
    waves: "W0.6 (unified inbox) · W1 · W2",
    build_state: "W2.1 rehome step 1 — Approvals serves canonically at /governance/approvals (same module; legacy /__ioi lane serving until the W4 cutover) and now shows the unified cross-plane approvals-inbox projection. Wave 1 read-first cockpit build continues per surfaces/governance.md §5",
    serving_today: [
      { href: "/governance/approvals", label: "Approvals (canonical)", note: "rehomed transition-capable inbox; folds every decision plane via the approvals-inbox projection, decisions execute on each plane's own route" },
      { href: "/__ioi/governance", label: "Governance cockpit readout", note: "read projection + named gaps over governance object planes" },
      { href: "/__ioi/governance/approvals", label: "Approvals (legacy lane)", note: "keeps serving until the W4 cutover" },
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
    waves: "W3 (registry foundation live; lifecycle + registration open)",
    build_state: "partial backend — /v1/hypervisor/packages now admits owner-scoped ODK package candidates, immutable canonical release records, disabled installation bindings, and CAS/idempotent uninstall receipts through Agentgres. Still open: extension_application registration, compiler/System/serving bindings, executable artifact materialization, and deprecate/recall/revoke lifecycle.",
    serving_today: [
      { href: "/__ioi/marketplace", label: "Marketplace readout", note: "draft listing/publish/admission object plane (admission-only)" },
      { href: "/__ioi/marketplace/listings", label: "Marketplace listings", note: "protected ported seed (daemon-wired); re-files over the registry in Wave 3" },
    ],
  },
  {
    route: "/packages/marketplace",
    surface: "Packages / Marketplace",
    kind: "optional mode (owner application: Packages)",
    rule: "Marketplace is the optional mode at /packages/marketplace",
    waves: "W1.3 (route resolves) · W3 (re-files over the registry)",
    build_state:
      "route resolves as of W1.3 (DEF-ROUTE-1 closed: the ledger rule named this path without a route behind it). The marketplace object plane serves admission-only draft listings today; the mode re-files over the package registry in Wave 3",
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

// W1.3 deep-link grammar. Route lookup was exact-root-only, so no detail or deep-link
// path under any canonical surface resolved (G-7, definition-of-done.md). Resolution is
// longest-prefix on SEGMENT boundaries ("/data" owns "/data/sources", never "/database"):
//   exact row match                       → { row, subpath: "" }   (unchanged behavior)
//   subpath under a row                   → { row, subpath }       (the owner's shell page
//                                            renders the deep link honestly — typed, named,
//                                            never a soft-404 into the SPA)
//   subpath under deep_links:"passthrough"→ null                   (vendored sections keep
//                                            serving, e.g. /settings/members)
//   anything under a vendor_spa row       → null                   (the SPA owns it)
// Back-stack preservation is structural: resolution never redirects (ADR 0022 Decision 2 —
// no aliases), so history entries are always the requested path itself. Hash fragments never
// reach the server and ride the client untouched; query strings pass through to the renderer.
export function resolveV2Route(pathname) {
  const exact = BY_ROUTE.get(pathname);
  if (exact) {
    if (exact.disposition === "vendor_spa") return null;
    return { row: exact, subpath: "" };
  }
  let prefix = pathname;
  for (;;) {
    const cut = prefix.lastIndexOf("/");
    if (cut <= 0) return null;
    prefix = prefix.slice(0, cut);
    const row = BY_ROUTE.get(prefix);
    if (!row) continue;
    if (row.disposition === "vendor_spa" || row.deep_links === "passthrough") return null;
    return { row, subpath: pathname.slice(prefix.length + 1) };
  }
}

// W1.3: a retired root retires its whole subtree — /sessions/<id> answers the same typed 410
// as /sessions, with the deep link carried onto the canonical replacement. A link, never a
// redirect alias.
export function retiredUiRouteFor(pathname) {
  for (const [retired, replacement] of Object.entries(RETIRED_UI_ROUTES)) {
    if (pathname === retired) return { requested: pathname, replacement };
    if (pathname.startsWith(`${retired}/`)) {
      return { requested: pathname, replacement: `${replacement}${pathname.slice(retired.length)}` };
    }
  }
  return null;
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
  .grid dd{margin:0;min-width:0;color:#e6e7ea;overflow-wrap:anywhere}
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
  .foot{color:#6f7280;font-size:12.5px;margin-top:28px;border-top:1px solid #1b1d23;padding-top:14px}
  @media(max-width:700px){
    .wrap{padding:28px 16px 56px}
    .grid{grid-template-columns:minmax(0,1fr);gap:3px;padding:14px}
    .grid dt:not(:first-child){margin-top:8px}
    .card{align-items:flex-start;padding:13px 14px}
    code{overflow-wrap:anywhere;word-break:break-word}
  }`;

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

// The honest surface shell page. States what exists; fabricates nothing. `compiled` is the
// W0.2 compiled product-surface projection feeding the navigation band. `options` (W1.3):
//   subpath  the deep-link remainder under the canonical root ("" for the root itself) —
//            named honestly in the registration grid, never soft-404ed
//   embed    render without estate chrome (brand, navigation band, footer) for embedding;
//            the body content is identical — embedding changes chrome, never truth
//   query    the requested query string (no leading "?"), preserved verbatim on the page
export function renderV2RouteShellPage(row, compiled, options = {}) {
  const esc = escHtml;
  const { subpath = "", embed = false, query = "" } = options;
  const reserved = row.disposition === "reserved";
  const requestedPath = subpath ? `${row.route}/${subpath}` : row.route;
  const requested = query ? `${requestedPath}?${query}` : requestedPath;
  const serving = (row.serving_today || [])
    .map((s) => `<a class="card" href="${esc(s.href)}"><div class="main"><div class="name">${esc(s.label)}</div><div class="meta">${esc(s.note)}</div></div><span class="pill muted">${esc(s.href)}</span></a>`)
    .join("");
  const servingBlock = serving
    ? `${serving}<p class="sub" style="margin-top:10px">These lanes keep serving untouched; they rehome into this route at this surface's Wave&nbsp;1 build / Wave&nbsp;4 cutover — nothing is deleted or redirected at W0.1.</p>`
    : `<div class="empty">Nothing serves this surface today. This page states that honestly — no fixture rows, no fabricated counts, no placeholder data.</div>`;
  const deepLinkRows = subpath
    ? `<dt>Requested deep link</dt><dd><code>${esc(requested)}</code></dd>
      <dt>Deep-link state</dt><dd>resolves to this surface's canonical root (W1.3 deep-link grammar); detail rendering for <code>${esc(subpath)}</code> lands with this surface's wave build — the lanes below are what serve this surface today</dd>`
    : "";
  return pageShell(
    row.surface,
    `<main data-ioi-surface-route="${esc(row.route)}" data-ioi-surface-owner="${esc(row.kind)}"${subpath ? ` data-ioi-surface-subpath="${esc(subpath)}"` : ""}${embed ? ' data-ioi-embed="1"' : ""}>
    ${embed ? "" : '<div class="brand">IOI Hypervisor · v2 route shell (W0.1)</div>'}
    <h1>${esc(row.surface)}${reserved ? '<span class="pill warn">reserved · nonlaunchable</span>' : ""}</h1>
    <p class="sub">${
      reserved
        ? "This owner application is registered <b>planned</b> and is <b>nonlaunchable until built</b>. The route is reserved by the canonical route ledger; no surface, readout, or build exists or is scheduled in the current run."
        : "Honest surface shell: this canonical route resolves as of W0.1. The panes below name what is real today; everything else arrives wave by wave — nothing here is fabricated."
    }</p>
    <h2>Registration</h2>
    <dl class="grid">
      <dt>Canonical route</dt><dd><code>${esc(row.route)}</code></dd>${deepLinkRows}
      <dt>Owner kind</dt><dd>${esc(row.kind)}</dd>
      <dt>Route-ledger rule</dt><dd>${esc(row.rule)}</dd>
      <dt>Wave assignments</dt><dd>${esc(row.waves)}</dd>
      <dt>Build state</dt><dd>${esc(row.build_state)}</dd>
    </dl>
    <h2>Serving this surface today</h2>
    ${servingBlock}
    ${embed ? "" : `<h2>Estate navigation — compiled product-surface projection (W0.2)</h2>
    ${navBand(row, compiled)}
    <div class="foot">Route declared in the canonical target-route ledger (core-clients-surfaces.md § Canonical Target Routes) and resolved by the route table (<code>apps/hypervisor/scripts/v2-route-shell.mjs</code>); navigation compiled by <code>apps/hypervisor/scripts/surface-compiler.mjs</code>. <a href="/ai">← Home</a></div>`}
    </main>`,
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
