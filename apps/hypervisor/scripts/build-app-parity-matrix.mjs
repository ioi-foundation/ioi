#!/usr/bin/env node
// Reference UX Port — parity matrix generator (post-#31 reset).
//
// The Reference UX Port program (post-#31 reset doctrine: port the reference shell first, IOI substrate
// underneath, IOI-native UX later). This reads the canonical seed inventory + the capture-state
// starting-points artifact and emits a single per-seed PARITY MATRIX with an honest `parity_class`
// overlay — the program-level record of how far each application seed has travelled from "captured
// shell" to "daemon-bound IOI surface".
//
// parity_class taxonomy (honest, never a false "covered"):
//   reference_capture — the /__apps/<slug> reference baseline serves; NOT yet bound to daemon truth
//   daemon_bound      — an IOI-owned surface renders the reference grammar over REAL daemon truth
//   queued            — named as the next daemon-bound target (owner binding declared, not built)
// The captured boot state (boots_* / shell_only / blocked_missing_capture) is carried verbatim from
// the inventory as `capture_state` — it is NOT a parity claim, only what the local capture does.
//
// Deliberately data-driven: no per-seed truth is invented here; the overlay is a small explicit map.
// Usage: node apps/hypervisor/scripts/build-app-parity-matrix.mjs [--check]
//   --check → exit 1 if the committed matrix is stale (for CI / the verifier).

import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SEED_INVENTORY } from "./harvest-seed-inventory.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const startingPoints = JSON.parse(readFileSync(path.join(appRoot, "harvest-starting-points.json"), "utf8"));
const captureState = Object.fromEntries((startingPoints.seeds || []).map((s) => [s.slug, s.classification]));

// ─── Reference UX Port taxonomy (reset, PR #31) ───────────────────────────────────────────────
// Presentation-layer rebase: the surfaces below are dark IOI surfaces over daemon truth. They are
// valuable SUBSTRATE, but they are NOT reference UX parity — they use the custom automationsShell,
// not a ported reference shell. So they are `substrate_bound`, not the old (retired) `daemon_bound`.
// A seed only becomes true parity (`daemon_wired`) once its reference UX shell is ported,
// source-neutralized, wired to daemon truth, and passes the Playwright visual + structural harness.
//
//   reference_capture     — /__apps/<slug> serves; no IOI port exists.
//   substrate_bound       — a dark IOI surface renders daemon truth (valuable, NOT UX parity).
//   reference_port_pending — selected for porting; reference screenshots + selectors captured.
//   reference_ported      — source-neutral reference shell/layout ported, still static/minimally wired.
//   daemon_wired          — ported UX wired to daemon truth AND passes visual/structural parity (TRUE parity).
//
// substrate_surface = the existing dark IOI surface (kept as substrate/admin/debug view).
const SUBSTRATE_BOUND = {
  lineage: { substrate_surface: "/__ioi/lineage", binding: "ODK materialization provenance (MaterializedObjectSet → run → session → lease → projection → mapping → datasource, resolved to live ladder refs; per-object source hashes + mapped_from; pre-output + registration receipts; Provenance proof-stream edges where available)", note: "Monocle lineage grammar over real provenance; upstream ladder refs resolved to live records; no fake nodes for unmaterialized ontologies; freeform resource-search / graph-expansion / cross-tenant catalog = named gaps" },
  // Canon: Work Ledger evolves into Provenance — Vertex is a Provenance graph/exploration lens.
  vertex: { substrate_surface: "/__ioi/vertex", surface_name: "Provenance", binding: "a Provenance graph/exploration lens over materialized object sets, projections, objects, and the threaded proof-stream odk_materialization edges (cross-plane: ODK ↔ Provenance)", note: "Vertex graph grammar (nodes · relations · neighborhood) over real cross-plane materialized truth; no fake nodes for unmaterialized ontologies; freeform graph canvas / arbitrary path-finding / cross-tenant object search / saved explorations = named gaps" },
  // Missions owner-family: jobs + incidents seeds bound to /__ioi/missions (the owner surface for
  // suite/run work). Operations stays substrate/infra. Both are the SAME owner surface, two lanes.
  jobs: { substrate_surface: "/__ioi/missions", surface_name: "Missions", binding: "the Missions run/job queue — the real operations run queue (recent runs, statuses, run counts) + scheduled missions, table/list grammar over daemon truth", note: "run-queue lane of the Missions owner surface; honest empty when no runs; freeform job-definition editing / board views / arbitrary filtering = named gaps; substrate/infra scheduler health stays in Operations" },

  // Evaluations owner-family: only evalsuites binds in this cut (analysis + quiver stay reference_capture).
  // The eval-suite library renders the INERT daemon eval-suite contract (a declaration; no scoring).
  // Evaluations owner-family: evalsuites was PROMOTED to daemon_wired by #54 (the sixth
  // origin-alignment port — see DAEMON_WIRED below). analysis + quiver stay reference_capture.
  // Studio owner-family: designer was PROMOTED to daemon_wired by #49 (the first origin-alignment
  // port — see DAEMON_WIRED below). machinery/workshop/module stay reference_capture.
  // Studio machinery: the process/state-machine DEFINITION plane (a new inert daemon contract).
  // Definition-only — no run/step/scheduling/binding. workshop + module stay reference_capture.
  // Studio machinery: PROMOTED to daemon_wired by #50 (the second origin-alignment port — see
  // DAEMON_WIRED below). workshop + module stay reference_capture.
  // NOTE: Governance/approvals is NOT here — #36 PROMOTED it to `daemon_wired` (a FAITHFUL light faceted-
  // inbox port over the real ApprovalRequest queue; see DAEMON_WIRED below), not substrate_bound.
  // Foundry owner-family: only models binds in this cut (modelstudio + inference stay reference_capture).
  // The Foundry landing's Model Catalog already renders the real model-route registry; this formalizes it.
};
// Port-progress overlays — a seed advances reference_port_pending → reference_ported → daemon_wired
// as its reference UX shell is captured, ported, and finally wired + parity-verified against a VALID
// reference. `reference_workspace` = the mirror path the Playwright harness opens
// (`:9225<capture_base>`), also carried on every row.
const REFERENCE_PORT_PENDING = {};
// A reference shell/layout ported + wired to daemon truth, but NOT yet promoted to daemon_wired —
// here because parity VERIFICATION does not pass the HARDENED harness (#34): either the local
// reference errors, OR the ported shell is a substrate-native redesign that does not reproduce the
// reference's theme + IA landmarks (region-name overlap alone is NOT parity). port_surface = the
// ported IOI surface; `parity_blocked` names why. `reference_landmarks` (when present) is the IA
// label set the hardened harness requires in BOTH the reference and the candidate.
const REFERENCE_PORTED = {
  // (explorer #46, monitors #51, sources #52, changes #53, workspaces each passed through this
  // stage on their way to certification + daemon_wired promotion. The stage exists for
  // ports-in-flight.)
};
// TRUE reference UX parity — a FAITHFUL port of the reference UX (same theme + IA + layout) wired to
// daemon truth, that PASSES the HARDENED Playwright harness (visual_parity: region geometry + theme
// match + reproduction of the reference's IA landmarks) against a VALID (non-errored) reference.
// `reference_landmarks` = the reference's IA label set the hardened harness requires in BOTH sides.
const DAEMON_WIRED = {
  // Widgets (widgets): the FIFTEENTH faithful port — the EIGHTH from the origin-alignment queue
  // and the FIRST Developer-Console-family certified surface. The #44 sweep proved the Custom
  // Widgets landing data-bearing on the capture-origin lane while the proxy renders no data
  // (origin baked into a JS chunk the index-fold cannot reach — the documented adopt-lane gap);
  // reference_url_override stamps the honest lane. A READ-ONLY registry lens over the ODK
  // surface-descriptor plane (registration itself stays an ODK dev-kit lane).
  widgets: { port_surface: "/__ioi/developer-console/widgets", surface_name: "Developer Console", reference_url_override: "http://localhost:9225/workspace/custom-widgets/", reference_landmarks: ["Custom Widgets", "New widget set", "Develop custom frontend widgets for use within Foundry applications.", "Recents", "Favorites", "Files", "Creator", "Last edited by", "Last viewed"], binding: "faithful port of the reference Custom Widgets landing over the estate's real widget/extension registration plane — dark global rail + topbar (violet widgets tile · Custom Widgets · New-widget-set-to-ODK / Help) + white h1 band + the View pill row (Recents active · Favorites named-gap) + the sources-family table whose rows are REAL ODK surface descriptors (name · ref · composition pattern · ontology binding · status · created date; creator/edited/viewed columns HONEST em-dashes — no principal or view tracking on the registry; honest empty state when nothing is registered) + below-the-fold the registry census (patterns/status chips from the records) with the registration boundary declared", note: "TRUE parity under the HARDENED gate: light Custom-Widgets landing reference-faithful shell at /__ioi/developer-console/widgets against the ORIGIN-ALIGNED data-clean reference (reference_url_override localhost:9225/workspace/custom-widgets/ — the #44 needs_origin_alignment finding; the /__apps/widgets proxy lane stays documented-insufficient: the capture bakes its origin into a JS chunk the index-fold cannot reach, so the proxy renders no data); the EIGHTH origin-alignment-queue port and the FIRST Developer-Console-family certified surface — a NEW dedicated port route over the EXISTING ODK surface-descriptor registry; a READ-ONLY registration lens — THE BOUNDARY IS THE HARD LINE: no descriptor authoring, no widget building, no generated UI artifact on this surface (New widget set ROUTES to the /__ioi/odk dev kit where the daemon's ontology-bound descriptor-create authority lives; the Developer Console owner surface is the /__ioi/connections cockpit, linked first-class both ways); the reference's build-in-environment vs scaffold-externally dev-kit fork (generated SDK/CLI) is vendor chrome the estate does not bind — a named gap declared in place; favorites / principal + view tracking / Help = named gaps disabled in place" },

  // Workspaces (workspaces): the FOURTEENTH faithful port — the SEVENTH from the origin-alignment
  // queue and the FIRST Workbench-family certified surface. The #44 sweep proved the Code
  // Workspaces launchpad data-bearing on the capture-origin lane while the proxy renders no data;
  // reference_url_override stamps the honest lane. A READ-ONLY launchpad projection over the
  // estate's real session plane (no creation/provisioning semantics on this surface).
  workspaces: { port_surface: "/__ioi/workbench/workspaces", surface_name: "Workbench", reference_url_override: "http://localhost:9225/workspace/code-workspaces/", reference_landmarks: ["Code Workspaces", "Running workspaces", "Launch code workspaces that run open-source IDEs and notebooks.", "Recents", "Favorites", "Created by me", "VS Code", "Jupyter", "RStudio", "New workspace", "Explore reference examples"], binding: "faithful port of the reference Code Workspaces launchpad over the estate's real session projection — dark global rail + topbar (orange workspace tile · Code Workspaces · store dropdown / New-workspace-to-owner / Help) + white h1 band + the overlapping Running-workspaces card whose interior is the projection's REAL non-terminal census (provisioned sessions with refs; the reference's empty-state copy renders only when truly empty) + the View pill row (Recents active · All wired to ?view=all · Favorites / Created-by-me / VS Code / Jupyter / RStudio as named-gap chrome — foreign editor taxonomy) + the sources-family table whose rows are REAL sessions (session ref · lifecycle pill · workspace root · environment/editor refs · created date; creator/edited columns HONEST em-dashes — no principal or edit tracking on the projection) + the marketplace-examples band (verbatim capture chrome) + below-the-fold the session-catalog census (daemon total · lifecycle chips · the estate's REAL editor kinds from the probed editor-target registry)", note: "TRUE parity under the HARDENED gate: light Code-Workspaces launchpad reference-faithful shell at /__ioi/workbench/workspaces against the ORIGIN-ALIGNED data-clean reference (reference_url_override localhost:9225/workspace/code-workspaces/ — the #44 needs_origin_alignment finding; the /__apps/workspaces proxy lane stays documented-insufficient: renders no data); the SEVENTH origin-alignment-queue port and the FIRST Workbench-family certified surface — a NEW dedicated port route over the EXISTING session projection; a READ-ONLY launchpad — THE BOUNDARY IS THE HARD LINE: no session creation, no environment provisioning, no editor-open semantics on this surface (New workspace ROUTES to the /__ioi/workbench owner surface, linked first-class both ways with /__ioi/sessions + /__ioi/environments); the reference's VS Code/Jupyter/RStudio filter taxonomy is FOREIGN — named-gap chrome, with the estate's real editor kinds rendered from the daemon editor-target registry (probed open posture); favorites / identity-scoped filters / marketplace installs / Help = named gaps disabled in place" },
  // #34 — Ontology Manager (schema): a FAITHFUL source-neutral port of the reference Ontology Manager —
  // a DARK global platform rail + a LIGHT app rail (Discover / Proposals / History · Resources: object/
  // property/link/action/value types + functions · Health issues / Cleanup / Ontology configuration) +
  // a LIGHT header (title · ontology switcher · "Search resources…" · New) + a LIGHT card-first body
  // ("Object types recently modified" as object-type cards), then the typed schema detail below. Light
  // theme + card-first IA + the reference's landmark labels, wired to the REAL ODK CanonicalObjectModel.
  // READ-ONLY (authoring + object materialization stay in /__ioi/odk). The /__apps/schema reference
  // BOOTS (light, non-errored), so the HARDENED harness certifies visual_parity → daemon_wired. This is
  // the first surface to clear the hardened gate; #33 approvals was reclassified reference_ported.
  schema: { port_surface: "/__ioi/ontology/manager", surface_name: "Ontology", reference_workspace: "/workspace/ontology/", reference_landmarks: ["Ontology Manager", "Discover", "Resources", "Object types", "Properties", "Link types", "Action types", "Value types", "Functions", "Health"], binding: "faithful port of the reference Ontology Manager over the real ODK CanonicalObjectModel — dark global rail + light app rail (Discover/Proposals/History · Resources object/property/link/action/value types + functions · Health/Cleanup/Configuration) + light header (ontology switcher · search · New) + light card-first body (object-type cards with per-type object + dependent counts), then typed schema detail + configuration; every cell is daemon truth", note: "TRUE parity (#34) under the HARDENED gate: light two-rail reference-faithful shell (matches the reference theme + IA landmarks + card-first body), NOT a native redesign; passes the hardened Playwright harness (theme + landmarks + geometry) against the VALID /__apps/schema reference; READ-ONLY over daemon truth — authoring/create-edit + object materialization stay in the /__ioi/odk substrate (linked first-class); in-canvas schema editing / Proposals / Shared properties / Groups / Interfaces / Cleanup / action+function execution = named gaps in place; Object Explorer is the sibling #35 cut" },
  // #36 — Approvals inbox: PROMOTED reference_ported → daemon_wired. The #33 port was a dark native
  // inbox; #34's hardened gate correctly refused it. This cut REBUILDS it as a FAITHFUL LIGHT FACETED
  // inbox matching the reference /__apps/approvals (dark global rail + a light Quick-filters/Additional-
  // filters sidebar + a light request list with status pills + an on-select right detail), over the
  // SAME real ApprovalRequest queue + the existing approve/reject/revoke transitions (no new semantics).
  // The reference boots data-clean (real request rows, light), so the hardened harness certifies
  // visual_parity → the SECOND daemon_wired, closing the #34 reclassification loop.
  approvals: { port_surface: "/__ioi/governance/approvals", surface_name: "Governance", reference_workspace: "/workspace/approvals-app/", reference_landmarks: ["Approvals", "Quick filters", "Your inbox", "Created by you", "All requests", "Additional filters", "Request type", "Status"], binding: "faithful port of the reference Approvals inbox over the real daemon ApprovalRequest queue — dark global rail + a light faceted sidebar (Quick filters: Your inbox / Created by you / All requests with live counts · Additional filters: Status wired to ?status=, Request type / Created by / Assigned to you / Project / Users-or-groups / Groups as faithful named-gap facets) + a light request list (kind · subject · id · created · status pill) + an on-select right detail with approve/reject/revoke; every populated cell is daemon truth", note: "TRUE parity (#36) under the HARDENED gate: light faceted-inbox reference-faithful shell (matches the reference theme + IA landmarks + faceted layout), NOT the earlier dark native shell; passes the hardened Playwright harness against the VALID data-clean /__apps/approvals reference; decisions are the existing daemon transitions (no new governance semantics); reviewer-assignment / delegation / comments / SLA / audit-export + the unwired facets = named gaps disabled in place; substrate table stays at /__ioi/governance?tab=approvals" },
  // #39 — Pipeline Builder: PROMOTED reference_ported → daemon_wired. #38 proved the reference DATA is
  // complete (the matching-origin canvas is data-clean); this cut RE-PORTS /__ioi/pipeline from the earlier
  // DARK native builder shell to a FAITHFUL LIGHT Pipeline Builder and ALIGNS the reference lane. Two edits
  // made promotion honest: (1) the port is now LIGHT (matches the reference theme; #34's theme gate had
  // correctly blocked the dark shell) and reproduces the reference IA landmarks; (2) the harness reference
  // is the ORIGIN-ALIGNED data-clean canvas (reference_url_override → localhost:9225 …/sandbox/…, matching
  // the app's absolute fetch origin, NOT the CORS-broken 127.0.0.1 proxy) with a reference-only preCapture
  // hook dismissing the "What's new" onboarding modal for a legible contact sheet. The hardened harness
  // then certifies visual_parity (theme light/light + landmarks 10/10 + regions 1.0, both sides valid).
  // #48 — Marketplace browse (listings): the SEVENTH faithful port — the LAST data_clean
  // candidate; the clean-reference pool is now EMPTY and the wave pivots to origin alignment.
  listings: { substrate_surface: "/__ioi/marketplace", port_surface: "/__ioi/marketplace/listings", surface_name: "Marketplace", reference_workspace: "/workspace/marketplace/", reference_landmarks: ["Marketplace", "Discover and install Foundry products", "Stores", "Name", "Products", "Install your first product", "Choose a product to install", "Configure product inputs", "Install and explore", "Installations"], binding: "faithful port of the reference Marketplace browse over the real daemon marketplace substrate — dark global rail + light header (app chip · Marketplace · product search · Installations · Help as named gaps) + hero (title · Discover subtitle · reference illustration) + the Stores table whose single row IS the estate's governed listing plane with its live product count + the install-first-product wizard band as reference chrome (installing is a named gap — products enter through draft → admitted review → open release on the substrate)", note: "TRUE parity (#48) under the HARDENED gate: light Marketplace-browse reference-faithful shell at /__ioi/marketplace/listings over the real listing plane — the LAST data_clean candidate from the #44 ranking, completing the clean-reference pool (the wave pivots to origin-alignment seeds next); the reference's Stores lane is REBOUND to the same substrate; /__ioi/marketplace substrate intact and linking first-class; product search / store search / Installations / Help / install wizard / store sharing / sorting = named gaps disabled in place; NO publish/install/hire/settle/runtime semantics — products enter only through draft → admitted review → open release on the substrate" },

  // #54 — Evalsuites (evalsuites): the THIRTEENTH faithful port — the SIXTH from the
  // origin-alignment queue and the FIRST Evaluations-family certified surface. The #44 sweep
  // proved the AIP Evals landing data-bearing on the capture-origin lane while the proxy renders
  // no data; reference_url_override stamps the honest lane. A DECLARATION LIBRARY: suites declare
  // WHAT they would assess under WHAT admissibility — nothing scores or executes.
evalsuites: { substrate_surface: "/__ioi/evaluations", port_surface: "/__ioi/evaluations/evalsuites", surface_name: "Evaluations", reference_url_override: "http://localhost:9225/workspace/evals/", reference_landmarks: ["AIP Evals", "New evaluation suite", "Create evaluation suites for LLM-backed use-cases.", "Recents", "Favorites", "FILES", "CREATOR", "LAST EDITED BY", "LAST VIEWED", "Explore reference examples"], binding: "faithful port of the reference AIP Evals landing over the inert daemon eval-suite plane — dark global rail + light app header (teal evals tile · AIP Evals · New-evaluation-suite / Help as named gaps) + hero band (title · one-line description · verbatim illustration under the reference's own white-gradient content overlay) + the View row (Recents active · Favorites gap) + the viewport-height-ruled Recents table whose rows are the REAL declared suites (name · ref · subject scopes · declared/complete health · status · created date; em-dashes where the plane records no principal/view tracking) + the marketplace-examples band (verbatim capture chrome) + below-the-fold full suite-library truth (subject scopes · rubric refs · evidence requirements · consent requirements · candidate refs, verbatim daemon records)", note: "TRUE parity (#54) under the HARDENED gate: light AIP-Evals landing reference-faithful shell at /__ioi/evaluations/evalsuites against the ORIGIN-ALIGNED data-clean reference (reference_url_override localhost:9225/workspace/evals/ — the #44 needs_origin_alignment finding; the What's-new modal dismissed by a reference-only pre-capture hook; the /__apps/evalsuites proxy lane stays documented-insufficient: renders no data); the SIXTH origin-alignment-queue port and the FIRST Evaluations-family certified surface — a NEW dedicated port route over the SAME inert eval-suite plane; a DECLARATION LIBRARY — THE ASSESSMENT BOUNDARY IS THE HARD LINE: health = declared-completeness NEVER a score; no EvalRun execution, no scoring, no verdicts, no judge runs, no scorecards, no auto-mining, no promotion; candidate refs stay LOCAL allowlisted schemes (the plane rejects external URLs fail-closed); suite authoring here / favorites / example installs = named gaps disabled in place; the /__ioi/evaluations owner surface + /__ioi/feedback sublane stay intact, linked first-class both ways" },
  // #53 — Changes (changes): the TWELFTH faithful port — the FIFTH from the origin-alignment
  // queue and the FIRST Improvement-family certified surface. The #44 sweep proved the Upgrade
  // Assistant data-bearing on the capture-origin lane (13 upgrades) while the proxy renders thin
  // data; reference_url_override stamps the honest lane. A PROJECTION port: the inbox renders the
  // EXISTING improvement-proposal plane (no mutation/apply/deploy/release execution semantics).
changes: { port_surface: "/__ioi/improvement/changes", surface_name: "Improvement", reference_url_override: "http://localhost:9225/workspace/upgrade-assistant/", reference_landmarks: ["Upgrade Assistant", "Admin view", "Assignee view", "Active", "Past due", "Archived", "Filters", "UPGRADE PROGRESS", "UPGRADE TYPE", "SORT"], binding: "faithful port of the reference Upgrade Assistant inbox over the real improvement-proposal plane — dark global rail + app header (upgrade tile · 1-organization group / Admin view / Assignee view / Help as named gaps) + the slate info banner + Active/Past-due/Archived tab lanes (LIVE ?lane= links: active = non-rejected · archived = rejected · past-due honestly empty, no due-date concept) + the Filters sidebar (UPGRADE PROGRESS radios WIRED to ?filter= — requiring-my-action = pending review; the reference's UPGRADE-TYPE taxonomy + due-date SORT as named-gap facets; counts are live data, masked) + the grouped list (Pre-published = pending/approved not-yet-applied · Published = applied) whose rows are REAL proposals (signal · proposal_ref · target_ref · kind pill · state + gate posture · approval/release/simulation refs as the proof trail)", note: "TRUE parity (#53) under the HARDENED gate: light Upgrade-Assistant inbox reference-faithful shell at /__ioi/improvement/changes against the ORIGIN-ALIGNED data-clean reference (reference_url_override localhost:9225/workspace/upgrade-assistant/ — the #44 needs_origin_alignment finding; the What's-new modal dismissed by a reference-only pre-capture hook; the /__apps/changes proxy lane stays documented-insufficient: renders thin data); the FIFTH origin-alignment-queue port and the FIRST Improvement-family certified surface — a NEW dedicated port route over the EXISTING improvement-proposal plane; a READ-ONLY improvement projection — NO mutation/apply/deploy/release execution semantics; proposing/simulating/approving/applying/release-gate control stay on /__ioi/agent-studio#improvement-proposals (linked first-class both ways); organization scoping / principal assignment / due dates / name search / upgrade-type taxonomy / due-date sorting = named gaps disabled in place" },
  // #52 — Sources (sources): the ELEVENTH faithful port — the FOURTH from the origin-alignment
  // queue, the Data-family landing. The #44 sweep proved the Data Connection landing data-bearing
  // on the capture-origin lane while the proxy lane renders no data; reference_url_override stamps
  // the honest lane. THE AUTHORITY BOUNDARY IS THE POINT: a DECLARED source catalog over the real
  // registry — no extraction, no connection test, no live connector read, no materialization here.
sources: { port_surface: "/__ioi/data/sources", surface_name: "Data", reference_url_override: "http://localhost:9225/workspace/data-ingestion-app/", reference_landmarks: ["Data Connection", "Sources", "Syncs", "Agents", "Listeners", "External stacks", "New source", "Synchronize and manage data flows between Foundry and external systems.", "Set up new connections", "Explore reference examples"], binding: "faithful port of the reference Data Connection landing over the real DataSource registry — dark global rail + tabbed app header (Data Connection · Sources live · Syncs/Agents/Listeners/External-stacks as named gaps · store dropdown / New source / Help as named gaps · the sync-counter cluster bound to REAL ODK materializing-run statuses) + hero band (title · description · verbatim illustration under the reference's own white-gradient content overlay) + the Set-up-new-connections card (verbatim option-card strip: vendor onboarding chrome, NOT an extraction affordance) + the View row + the Recents table whose rows are the REAL declared sources (name · source_ref · kind · credential_posture · lifecycle · created date · the wired:false flag; endpoints rendered scheme+host+path ONLY) + the marketplace-examples band + below-the-fold the declared-catalog census with the daemon's own ingestion note VERBATIM", note: "TRUE parity (#52) under the HARDENED gate: light Data-Connection landing reference-faithful shell at /__ioi/data/sources against the ORIGIN-ALIGNED data-clean reference (reference_url_override localhost:9225/workspace/data-ingestion-app/ — the #44 needs_origin_alignment finding; the What's-new modal dismissed by a reference-only pre-capture hook; the /__apps/sources proxy lane stays documented-insufficient: renders no data); the FOURTH origin-alignment-queue port and the FIRST Data-family LANDING surface (pipeline is the Data ladder) — a NEW dedicated port route over the EXISTING DataSource registry; THE AUTHORITY BOUNDARY IS THE HARD LINE: declared sources only, no extraction, no connection test, no live connector read, no materialization semantics on this surface (the governed path stays the ODK ladder); credential VALUES never render (postures only; endpoints stripped of userinfo/query/fragment); New-source here / live-connection setup / upload / synthesis / Syncs-Agents-Listeners-External-stacks / store menu / example installs = named gaps disabled in place" },
  // #51 — Monitors (monitors): the TENTH faithful port — the THIRD from the origin-alignment
  // queue and the FIRST Automations-family certified surface. The #44 sweep proved the Automate
  // overview data-bearing on the capture-origin lane while the proxy lane fails with the
  // favorites-load error; reference_url_override stamps the honest lane. A PROJECTION port: the
  // overview renders the EXISTING automation plane (no new scheduler/execution semantics).
monitors: { port_surface: "/__ioi/automations/monitors", surface_name: "Automations", reference_url_override: "http://localhost:9225/workspace/object-monitoring/", reference_landmarks: ["Automate", "Overview", "Automations", "New automation", "Create and manage automations", "Getting started", "View all automations", "Create your first automation", "Get started by creating a new automation", "Explore reference examples"], binding: "faithful port of the reference Automate overview over the real automation plane — dark global rail + tabbed app header (Automate · Overview active · Automations → the real owner substrate · store dropdown / New automation / Help as named gaps) + hero band under the reference's own white-gradient content overlay + Getting-started band (View-all → the substrate) with the wizard card (verbatim 3-step illustration strip) + the template-card gallery + marketplace-examples band (verbatim capture strips, vendor chrome) + below-the-fold REAL truth: Active-automations stat band (live counts: user-executed · notifications = honest named-gap 0 · paused via enabled=false), the Recently-viewed table (one row per real automation: id · project · trigger · steps census · created date; CREATOR = the real executor_identity.ref) and the Recently-triggered feed (real executions: status · time · execution/environment refs as proof)", note: "TRUE parity (#51) under the HARDENED gate: light Automate-overview reference-faithful shell at /__ioi/automations/monitors against the ORIGIN-ALIGNED data-clean reference (reference_url_override localhost:9225/workspace/object-monitoring/ — the #44 needs_origin_alignment finding; the /__apps/monitors proxy lane stays documented-insufficient: a favorites-load failure + CORS-blocked session lanes); the THIRD origin-alignment-queue port and the FIRST Automations-family certified surface — a NEW dedicated port route (monitors had no prior IOI surface), built as a read-only projection over the EXISTING automation plane (authoring/pause/resume/run history stay on /__ioi/automations, linked first-class both ways); the wizard/template/example strips are verbatim capture chrome (vendor content, never estate data); NO new scheduler or execution semantics; New-automation here / store menu / template docs / marketplace example installs / notification subscriptions = named gaps disabled in place" },
  // #50 — Machinery (machinery): the NINTH faithful port — the SECOND from the origin-alignment
  // queue. The #44 sweep proved the reference data-bearing on the capture-origin lane while the
  // proxy lane fails its Marketplace-examples fetch; reference_url_override stamps the honest lane
  // and the shell certifies pixel parity against it. THE SEMANTIC BOUNDARY IS THE POINT: the
  // certified shell is a LANDING over inert definitions — no execution surface was created.
machinery: { substrate_surface: "/__ioi/studio/machinery", surface_name: "Studio", reference_url_override: "http://localhost:9225/workspace/machinery-app/", reference_landmarks: ["Machinery", "New graph", "Build, manage and monitor your business processes with precision. Streamline operations and drive efficiency through strategic automations.", "Recents", "Favorites", "FILES", "CREATOR", "LAST EDITED BY", "LAST VIEWED", "Explore reference examples"], binding: "faithful port of the reference Machinery landing over the inert daemon state-machine plane — dark global rail + light app header (machinery tile · Recent-installations store dropdown · New graph · Help as named gaps) + hero band (title · description · verbatim reference illustration under the reference's own white-gradient content overlay) + the View row (Recents active · Favorites gap) + the viewport-height-ruled Recents table whose rows are the REAL state-machine DEFINITIONS (name · ref · created/updated dates · declared states/transitions/guards census · health/status; declared owner_refs rendered honestly, em-dashes where the plane records no principal/view tracking) + the Explore-reference-examples band (the reference's own marketplace example cards, verbatim capture chrome) + below-the-fold full DEFINITION truth (states initial/normal/final · transitions from→to/event/guard · guards · declared inputs/outputs · owners · history · the daemon's own authority_note)", note: "TRUE parity (#50) under the HARDENED gate: light Machinery landing reference-faithful shell at /__ioi/studio/machinery against the ORIGIN-ALIGNED data-clean reference (reference_url_override localhost:9225/workspace/machinery-app/ — the #44 needs_origin_alignment finding; the /__apps/machinery proxy lane stays documented-insufficient: its Marketplace-examples fetch fails on the proxy origin); the SECOND origin-alignment-queue port — the old dark definition view is REBUILT in place as the faithful light landing shell over the SAME inert #30 state-machine plane (states/transitions/guards/inputs/outputs/owners/history/health preserved below the fold with real records + the daemon's own authority_note verbatim); the hero illustration + marketplace-examples strip are verbatim capture chrome (the reference's own example content, never estate data and never an execution claim); DEFINITION-ONLY IS THE HARD BOUNDARY — no run/step/execute, no current_state, no scheduling, no Automations/Missions/ODK binding, no fake process-graph execution; graph authoring (New graph) / Recent-installations store menu / favorites / marketplace example installs / simulation / versioning = named gaps disabled in place (a later authority-crossing cut)" },
  // #49 — Solution Designer (designer): the EIGHTH faithful port — the FIRST from the
  // origin-alignment queue (post-#48 pivot). The #44 sweep proved the reference data-bearing on the
  // capture-origin lane while the proxy lane manufactures CORS noise + a favorites-load failure;
  // reference_url_override stamps the honest lane and the shell certifies pixel parity against it.
designer: { substrate_surface: "/__ioi/studio/designer", surface_name: "Studio", reference_url_override: "http://localhost:9225/workspace/solution-design/", reference_landmarks: ["Solution Designer", "New Diagram", "Have a workflow in mind? Use AIP Architect to help you plan it.", "Start planning", "Explore our library of reference solution architecture diagrams", "Browse all", "Recents", "Favorites", "Open Diagram", "LAST VIEWED"], binding: "faithful port of the reference Solution Designer landing over real ODK composition truth — dark global rail + light app header (app chip · Solution Designer · New Diagram/Help as named gaps) + hero band (title · description · verbatim reference illustration) + the AIP-architect banner card (Start planning as a named gap) + the template-gallery card (the reference's own static template-library strip, verbatim capture chrome) + the View row (Recents active · Favorites gap · Open Diagram gap) + the Recents table whose rows are the REAL domain ontologies (the estate's solution designs: ref + created/updated dates + concept/component/resource census; honest em-dashes where the ODK plane records no principal/view tracking) + below-the-fold full composition truth (COM concepts · mapping/policy-view/projection components · materialized-set/domain-app resources, real refs)", note: "TRUE parity (#49) under the HARDENED gate: light Solution-Designer landing reference-faithful shell at /__ioi/studio/designer against the ORIGIN-ALIGNED data-clean reference (reference_url_override localhost:9225/workspace/solution-design/ — the #44 needs_origin_alignment finding; the /__apps/designer proxy lane stays documented-insufficient: cross-origin :9225 chunk fetches manufacture CORS noise + a favorites-load failure); the FIRST origin-alignment-queue port after the #48 clean-pool close — the old dark substrate canvas is REBUILT in place as the faithful light landing shell over the SAME composition truth (concepts/components/resources preserved below the fold with real refs); the hero illustration + template-gallery strip are verbatim capture chrome (the reference's own static template library, never estate data); rows are REAL domain ontologies with honest em-dashes where the ODK plane records no principal/view tracking; in-canvas authoring / New-Open Diagram / save-open / drag-to-reference / AIP Architect planning / favorites / template Browse-all / machinery process-graph execution / workshop+module builders = named gaps disabled in place" },
  // #47 — Model Catalog (models): the SIXTH faithful port — the FIRST Foundry-family certified
  // surface, the second port chosen by the #44 sweep ranking (models was rank #1 remaining).
  models: { substrate_surface: "/__ioi/foundry", port_surface: "/__ioi/foundry/models", surface_name: "Foundry", reference_workspace: "/workspace/model-catalog/", reference_landmarks: ["Model Catalog", "IOI-provided models", "Registered models", "Compare models", "Browse large language models in Foundry", "Filters", "LIFECYCLE STATUS", "Clear", "MODEL CREATOR", "Additional"], binding: "faithful port of the reference Model Catalog over the real daemon model-route registry — dark global rail + light header (app chip · Model Catalog · IOI-provided/Registered tabs) + hero (title · Browse subtitle · Compare-models gap) + a pinned Filters card (name search + Lifecycle Status/Type/Model creator facets whose ROWS are live route truth) + the Additional-models card list (one card per real route: identity + default marker · availability state + probe evidence + staleness · weight custody · credential posture · lifecycle/admission); route administration stays in Agent Studio (linked)", note: "TRUE parity (#47) under the HARDENED gate: light Model-Catalog reference-faithful shell at /__ioi/foundry/models over the REAL daemon model-route registry — the FIRST Foundry-family certified surface; the /__apps/models reference's catalog lanes are REBOUND to the same registry (the #44 sweep classified it data_clean on those lanes); /__ioi/foundry substrate intact and linking first-class; Registered-models tab / Compare / name search / facet filtering / model detail / fine-tuning / playground / inference / deployment = named gaps disabled in place; route administration stays in Agent Studio" },
  // #46 — Object Explorer: the FIFTH faithful port — the CORRECTION promotion (the #44 sweep
  // proved the #35 blocker wrong; the reference was data-clean all along behind the origin/hostname
  // mismatch). Completes the Ontology pair with #34 schema.
  explorer: { port_surface: "/__ioi/ontology/explorer", surface_name: "Ontology", reference_workspace: "/workspace/hubble/", reference_url_override: "http://localhost:9225/workspace/hubble/", reference_landmarks: ["Object Explorer search", "Filter by...", "Shortcuts", "Recents", "Favorites", "Your object sets", "Object type catalog", "Relevancy", "Object set catalog", "New exploration"], binding: "faithful port of the reference Object Explorer over real ODK truth — dark global rail (Ontology context) + exploration tab bar + centered 'Object Explorer search' hero (Filter-by/object-search as named gaps) + Shortcuts (the real top materialized sets) + the object-type CATALOG (name · status · object count from materialized sets · link usage · description=ontology) across ALL live DomainOntologies with a WORKING server-side ?q= filter + the object-set CATALOG over real materialized sets; every populated cell is daemon truth", note: "TRUE parity (#46) under the HARDENED gate: light Object-Explorer reference-faithful shell against the ORIGIN-ALIGNED data-clean Hubble reference (reference_url_override localhost:9225/workspace/hubble/ — the #44 sweep finding; #35's 'blank reference' blocker was an origin mismatch, CORRECTED, not a missing backend); REAL daemon rows only (never the capture's 55 example types); completes the Ontology pair with #34 schema — first-class linked with /__ioi/ontology/manager both ways + from /__ioi/odk; object-instance search / Filter-by facets / Recents / Favorites / Relevancy sort / type-group+application lanes / exploration tabs / ontology selector / per-user set lanes = named gaps disabled in place" },
  // #45 — Incidents: the FOURTH faithful port and the FIRST chosen by the #44 clean-sweep
  // ranking (rank #1: data_clean reference + existing Missions daemon substrate + low-risk
  // table/inbox grammar). The issues-app reference's data sits one status-lane click deep
  // (the #44 finding) — REFERENCE_PRE_CAPTURE.incidents clicks the Closed lane (status UI
  // only; error text is read BEFORE the hook) and ioi_url_override deep-links ?lane=closed
  // so both sides render the same lane state.
  incidents: { substrate_surface: "/__ioi/missions", port_surface: "/__ioi/missions/incidents", ioi_url_override: "/__ioi/missions/incidents?lane=closed", surface_name: "Missions", reference_workspace: "/workspace/issues-app/", reference_landmarks: ["Open", "Closed", "All", "Filters", "Priority", "Assignees", "Reporters", "Mentions", "Labels", "Support types"], binding: "faithful port of the reference Issues inbox over the real Missions incident truth — dark global rail + light header (app chip · Issues · search · New · settings) + a light status/filter sidebar (Open/Closed/All lanes with live counts · Priority/Assignees/Reporters/Mentions/Labels/Support-types/date facets as faithful named-gap filters) + the incident list (real GoalRun blockers + run failures: reason code · subject id · created age · kind pill · proof link into the run timeline); open = blockers on non-terminal runs + failed runs, closed = blockers recorded on terminal runs — every row is daemon truth", note: "TRUE parity (#45) under the HARDENED gate: light status-lane issues-inbox reference-faithful shell at /__ioi/missions/incidents, over REAL daemon incidents (never the capture's example rows); honest empty lanes; creating/assigning incidents, priorities, SLA, comments, saved filters, facet filtering, bulk selection = named gaps disabled in place; the /__ioi/missions substrate overview stays intact and links the inbox first-class; substrate/infra incidents (storage repair, provider failover) stay in Operations" },
  pipeline: { port_surface: "/__ioi/pipeline", surface_name: "Data", reference_workspace: "/workspace/builder/", reference_url_override: "http://localhost:9225/workspace/builder/ri.eddie.main.pipeline.e73d6ae7-f6fe-4ac5-82a2-320d9f188590/sandbox/a082bef2-8826-4e6c-8925-871bcdb56c44", reference_landmarks: ["Add data", "Reusables", "Transform", "Legend", "Pipeline outputs", "Selection preview", "Suggestions", "Pipeline warnings", "Edit output settings", "Tools"], binding: "faithful LIGHT port of the reference Pipeline Builder over the real ODK authority ladder (DataSource → Object mapping → Policy gate → Transform plan → Read projection → Lease+session → MaterializedObjectSet) as the graph node cards; a Legend panel (Input Data / Data Cleaning / Calculations / Output Dataset) + a right 'Pipeline outputs' panel (read projection + column mapping + Output settings) + a 'Selection preview' tray, all from daemon truth (live/declared/missing per stage, preview rows + output schema from the real projection + materialized set)", note: "TRUE parity (#39) under the HARDENED gate: /__ioi/pipeline REBUILT as a faithful LIGHT Pipeline Builder (dark global rail + light header w/ build state + light tool cluster [Tools/Select/Remove/Layout/Text · Add data · Reusables · Transform/AIP/Edit] + light central graph canvas with the ODK-ladder node cards + a Legend panel + a right 'Pipeline outputs' panel w/ Output settings/Edit output settings + a bottom Selection preview / Suggestions / Pipeline warnings tray), NOT the earlier dark native shell (which #34's theme gate correctly refused); passes the hardened Playwright harness (theme light/light + landmarks 10/10 + regions 1.0) against the ORIGIN-ALIGNED data-clean reference canvas (reference_url_override localhost:9225 …/sandbox/…, the What's-new modal dismissed via a reference-only preCapture hook), whose data completeness is the precondition proven by verify-pipeline-reference-data-clean.mjs (reference_data_complete=true, #38); Build+Preview wired to the real ODK ladder; Schedule/Deploy + freeform canvas authoring (drag-connect / transform code editor / scheduling / deploy) = named gaps disabled in place; no new daemon semantics" },
};

function parityClass(slug) {
  if (DAEMON_WIRED[slug]) return "daemon_wired";
  if (REFERENCE_PORTED[slug]) return "reference_ported";
  if (REFERENCE_PORT_PENDING[slug]) return "reference_port_pending";
  if (SUBSTRATE_BOUND[slug]) return "substrate_bound";
  return "reference_capture";
}
const OVERLAY_FOR = (slug) => DAEMON_WIRED[slug] || REFERENCE_PORTED[slug] || REFERENCE_PORT_PENDING[slug] || SUBSTRATE_BOUND[slug] || null;

// SHELL PIXEL CERTIFICATION (PR #40 wave; re-scoped per the PR #41 finding) — a STRONGER evidence layer
// on TOP of daemon_wired, never a replacement for it or for daemon truth. The captured references carry
// Palantir EXAMPLE data while the IOI ports render LIVE daemon truth, so FULL-BODY pixel parity is the
// wrong bar (it would reward faking IOI data to match a screenshot). The certified target is instead
// "pixel-identical SHELL, semantically-truthful BODY": a slug appears here ONLY after the shell-pixel
// harness (harness-reference-pixel-parity.mjs) certifies it at the required viewports — visual gates
// (#34/#39) AND the certified SHELL (rail/header/app-rail/toolbar/panels) diff ≤ the shell budget AND
// shell region bboxΔ ≤ 8px AND the certified shell covers a real fraction of the image — with the
// live-data BODY excluded by design and its truth verified SEMANTICALLY by the per-surface verifier.
// Value = the COMMITTED evidence file the harness writes on a genuine (non-pinned, full-viewport-set)
// certification: `pixel-certifications/<slug>.json` (.artifacts/ is gitignored, so an uncommitted pointer
// can never carry a claim). The invariant below PARSES the file; the pixel verifier deep-checks its
// recorded thresholds against the harness THRESHOLDS.
const SHELL_PIXEL_CERTIFIED = {
  // #41 — Ontology Manager: the FIRST shell-pixel certification. Deterministic alignment took the shell
  // from 11.51% raw chrome diff to the measured floor (anchors 0,0 · container bbox 0px · identical
  // platform fonts · zero run-to-run variance): 1440x900 dilated 1.05% / raw 1.73%, 1920x1080 dilated
  // 0.88% / raw 1.46% — under the calibrated budgets (dilated ≤ 1.25%, raw ≤ 3.0%). Body = live ODK
  // truth, verified semantically by verify-hypervisor-ontology-manager.mjs. Mobile: not supported by the
  // reference (fixed 230px rail ≈ 59% of a 390px viewport).
  schema: "pixel-certifications/schema.json",
  // #42 — Approvals: the SECOND shell-pixel certification. Rail via the shared ioiGlobalRailHtml (bbox 0);
  // faceted sidebar rebuilt to the reference (no top navbar — the title lives in the sidebar; glyph-box
  // alignment via the baseline micro-pass: 40px section headers with centered glyphs, 35px QF rows with
  // the reference's inbox/follower/form icons + blue selected-row border + hairline divider, exact
  // 15.4297px label line-height stopping per-pair drift). The reference CENTERS its 1210px content block
  // right of the rail at wide viewports — reproduced (offset 0 @1440, +240 @1920) with content-anchored
  // shell rects + rect masks. Captured filter state (blue-active selects, counts) masked as dynamic data
  // on both sides; over-mask guard clean. 1440x900 dilated 1.14% / raw 1.96%, 1920x1080 dilated 0.89% /
  // raw 1.53%, bbox 0. Body = live ApprovalRequest daemon truth (approve/reject/revoke preserved).
  approvals: "pixel-certifications/approvals.json",
  // #43 — Pipeline Builder: the THIRD shell-pixel certification and the first CANVAS-app shell (floating
  // cards over a live graph body, not a table/sidebar). Shell = shared rail (per-reference rv-pipe
  // variant: badges, no View-all/star, gradient AIP, full-bleed #1c2127 active row, muted account chip) ·
  // reference header (File/Settings/Help menus + hairline dividers + slate Batch tag; the fluid middle is
  // the reference's captured SESSION STATE, masked on both sides, and carries the port's live
  // Build/Preview controls; Actions|divider|Share right cluster) · segmented-button tool card (ring
  // shadows, exact 15px cluster gaps, wrapping 3 group-rows @1440 → one row @1920 with 30/15px gaps,
  // verbatim reference icon paths incl. the gradient AIP logo, per-icon reference fills) · Legend card
  // (#f6f7f9 + #cbccd0 border, 14px category chips in the reference palette, 70px truncating names) ·
  // float/zoom button stacks · right outputs panel (ring-shadow buttons, segmented Edit-output-settings,
  // white 50px icon strip with 40px boxes + hairline group dividers) · bottom tray tabs (hairline
  // separators, rgba(138,187,255,.4) active, live-suggestions pill region masked). Live ODK values
  // (breadcrumb names, batch count, output card/stat, legend counts, settings values) masked as dynamic
  // data on both sides; the canvas graph is the live body, excluded by design and verified semantically
  // by verify-hypervisor-app-parity-pipeline.mjs. 1440x900 dilated 0.94% / raw 1.96%, 1920x1080 dilated
  // 0.84% / raw 1.82%, bbox 0 — no threshold movement.
  pipeline: "pixel-certifications/pipeline.json",
  // #45 — Incidents: the FOURTH shell-pixel certification, the first driven by the #44
  // sweep ranking. Fixed-left issues-inbox shell (sidebar/list x identical across
  // viewports); glyph-anchored status lanes + filter facets (boxed name inputs whose ink
  // sits at x259, Blueprint 16px checkbox indicators, italic filtered-by cluster, exact
  // 83.4px row pitch left as the excluded live body). Certified on the Closed-lane state
  // both sides (reference pre-capture clicks status UI only; port deep-links ?lane=closed).
  // 1440x900 dilated 1.09% / raw 2.29%, 1920x1080 dilated 0.87% / raw 1.98%, bbox 0 — no
  // threshold movement. Body = REAL daemon incidents (blockers/failures), verified
  // semantically by verify-hypervisor-app-parity-incidents.mjs.
  incidents: "pixel-certifications/incidents.json",
  // #54 — Evalsuites: the THIRTEENTH shell-pixel certification — the sixth origin-alignment-queue
  // port, certified on the FIRST measured run (the second zero-fix certification: the splash kit
  // is converged). Splash shell: shared rail (rv-pipe + rv-dsg) · header (teal tile
  // rgba(0,112,103,.1) + inset hairline, success New-evaluation-suite + outlined Help as named
  // gaps) · 88px hero with the VERBATIM illustration under the reference's own 1040px
  // white-gradient overlay · View row · table ring + header with the measured viewport rule
  // max(360px, 100vh − 604px) · the examples band (strip reused from #50). Suite ROWS = masked
  // data (captured tutorials vs live declared suites). 1440x900 dilated 0.76% / raw 1.46%,
  // 1920x1080 dilated 0.62% / raw 1.29%, bbox 0 — no threshold movement. Body = the real inert
  // eval-suite plane, verified semantically by verify-hypervisor-app-parity-evalsuites.mjs
  // (declarations, never assessment).
  evalsuites: "pixel-certifications/evalsuites.json",
  // #53 — Changes: the TWELFTH shell-pixel certification — the fifth origin-alignment-queue port,
  // the first Improvement-family surface. Fixed-left inbox shell: shared rail (rv-pipe + rv-dsg) ·
  // app header (upgrade tile · bare org-group / Admin-view / Assignee-view / Help — the tile
  // TOP-aligned in the 51px header, the 0.5px centering shift was a real fix) · slate info banner
  // (flex-start + fixed padding so the text holds position at both viewports while the ? icon
  // lands right) · Active/Past-due/Archived tab bar · Filters sidebar (search + section headers +
  // radio/checkbox controls; the facet COUNT column is masked live data) · the list card chrome
  // (heading/sub + column band + the card's white lower frame certified as container chrome, the
  // grouped rows masked as data inside it). 1440x900 dilated 1.18% / raw 1.55%, 1920x1080 dilated
  // 0.86% / raw 1.08%, bbox 0 — no threshold movement. Body = real improvement-proposal plane,
  // verified semantically by verify-hypervisor-app-parity-changes.mjs (projection, never execution).
  changes: "pixel-certifications/changes.json",
  // #52 — Sources: the ELEVENTH shell-pixel certification — the fourth origin-alignment-queue
  // port. Landing shell: shared rail (rv-pipe + rv-dsg) · 48px tabbed header (Data Connection ·
  // five tabs · store dropdown / New source / Help; the sync-counter cluster = MASKED data bound
  // to REAL materializing-run statuses) · 143px hero with the VERBATIM illustration under the
  // reference's own 1040px white-gradient overlay · Set-up-new-connections card with the VERBATIM
  // option-card strip (962x222 — vendor onboarding chrome, NOT an extraction affordance) · View
  // row · table ring + header with the measured viewport rule max(360px, 100vh − 648px) · the
  // examples band (strip reused from #50). Source ROWS = masked data (captured tutorials vs live
  // declared sources; endpoints render scheme+host+path only). Two measured fixes: the header's
  // 1px height overflow (flex-basis + border → explicit height:48px) and the table viewport rule.
  // 1440x900 dilated 0.67% / raw 1.24%, 1920x1080 dilated 0.76% / raw 1.21%, bbox 0 — no
  // threshold movement. Body = the real DataSource registry, verified semantically by
  // verify-hypervisor-app-parity-sources.mjs (declared catalog, never extraction).
  sources: "pixel-certifications/sources.json",
  // #51 — Monitors: the TENTH shell-pixel certification — the third origin-alignment-queue port,
  // certified on the FIRST measured run (zero fix rounds — the playbook converged): the Automate
  // overview's in-viewport content is ENTIRELY vendor chrome (tabbed header + 940px white-gradient
  // hero overlay + wizard/template/example VERBATIM strips), so the shell carries NO in-viewport
  // data masks and the largest certified fraction of the wave (0.872 @1440). The live-data regions
  // (Active-automations stats · Recently-viewed table · Recently-triggered feed) sit below the fold
  // at both viewports — real automation-plane truth, verified semantically. 1440x900 dilated 0.73%
  // / raw 1.47%, 1920x1080 dilated 0.58% / raw 1.90%, bbox 0 — no threshold movement. Body =
  // real automation plane, verified by verify-hypervisor-app-parity-monitors.mjs.
  monitors: "pixel-certifications/monitors.json",
  // #50 — Machinery: the NINTH shell-pixel certification — the second origin-alignment-queue
  // port. Landing shell: shared rail (rv-pipe + rv-dsg) · app header (machinery tile
  // rgba(20,126,179,.1) + inset hairline, Recent-installations store dropdown + success New-graph
  // + outlined Help as named gaps) · 106px hero band with the VERBATIM reference illustration under
  // the reference's own 1040px white-gradient content overlay (the #49 find, same splash component)
  // · View row (bp6 round tags, no Open-Diagram on this splash) · table ring + header row with the
  // reference's viewport height rule max(360px, 100vh − 624px) · the Explore-reference-examples
  // band with the VERBATIM capture strip (562x272 crop of the two marketplace example cards —
  // vendor chrome, not estate data, not an execution claim; 1px ring-row alignment was the one
  // measured fix: raw 3.49% → 1.67%). Machine ROWS = excluded live body (real state-machine
  // DEFINITIONS vs captured tutorials). 1440x900 dilated 0.70% / raw 1.67%, 1920x1080 dilated
  // 0.57% / raw 1.45%, bbox 0 — no threshold movement. Body = inert definition truth, verified
  // semantically by verify-hypervisor-app-parity-studio-machinery.mjs (definitions, never execution).
  machinery: "pixel-certifications/machinery.json",
  // #49 — Solution Designer: the EIGHTH shell-pixel certification — the first origin-alignment-queue
  // port. Landing-page shell: shared rail (rv-pipe + rv-dsg variant: View-all present, 30/5px secrow
  // rhythm, rgba(45,114,210,.1) app tile) · app header (50px designer tile + inset hairline, success
  // New-Diagram + outlined Help as named gaps at the reference's 8px paddings) · hero band with the
  // VERBATIM reference illustration UNDER the reference's own 1040px content overlay
  // (linear-gradient(90deg,#fff 575px,transparent) — the load-bearing find: the gradient is what hides
  // the illustration's left elements at 1440) · AIP-architect banner card (#7961db ring) · template-
  // gallery card with the VERBATIM capture strip (961x202 crop — the reference's static template
  // library, vendor chrome not estate data) · View row (bp6 round tags) · table ring + header row.
  // Diagram ROWS = masked data (captured tutorials vs live ontology compositions). 1440x900 dilated
  // 0.66% / raw 1.21%, 1920x1080 dilated 0.56% / raw 1.12%, bbox 0 — no threshold movement. Body =
  // real composition truth, verified semantically by verify-hypervisor-app-parity-studio-designer.mjs.
  designer: "pixel-certifications/designer.json",
  // #46 — Object Explorer: the FIFTH shell-pixel certification — the correction promotion, against
  // the origin-aligned Hubble reference. Tab-bar header · centered search hero (grouped outer-ring
  // + shared drop shadow) · shortcuts band · catalog heading/filter/sort band + table header ·
  // object-set band; catalog/set ROWS = excluded live body. Content rule: max-width 1400,
  // width calc(100% − 121px) — the ODD width reproduces the reference's half-pixel layout origin
  // (x290.5 @1440), which is what collapsed the diffuse text-fringe diff. 1440x900 dilated 0.73% /
  // raw 2.91%, 1920x1080 dilated 0.86% / raw 2.56%, bbox 0 — no threshold movement.
  explorer: "pixel-certifications/explorer.json",
  // #47 — Model Catalog: the SIXTH shell-pixel certification — the first Foundry-family surface
  // and the tightest margins of the wave (fully fixed-left layout + facet sections as PINNED
  // SHELL SLOTS with the live-truth rows masked as data). 1440x900 dilated 0.28% / raw 1.6%,
  // 1920x1080 dilated 0.22% / raw 1.4%, bbox 0 — no threshold movement.
  models: "pixel-certifications/models.json",
  // #48 — Marketplace browse: the SEVENTH shell-pixel certification — closes the data_clean
  // pool. Hero band with the verbatim reference illustration · rebound Stores table (row =
  // masked live data, chrome compared incl. the x990 column divider) · install-wizard band
  // with absolutely-pinned reference illustrations. Content = the approvals rule (1210px
  // centered block). 1440x900 dilated 1.17% / raw 1.52%, 1920x1080 dilated 1.11% / raw 1.45%,
  // bbox <= 3 — no threshold movement.
  listings: "pixel-certifications/listings.json",
  workspaces: "pixel-certifications/workspaces.json",
  widgets: "pixel-certifications/widgets.json",
};

// ---- PR #44: the ESTATE REFERENCE CLEAN SWEEP (committed evidence written by
// harness-reference-clean-sweep.mjs from real Playwright renders over the LOCAL
// mirror lanes). Stamps reference_clean_state / _reason / _artifact on every
// seed. parity_class is NEVER derived from it — cleanliness describes the
// REFERENCE, not the port.
const CLEAN_SWEEP_STATES = new Set([
  "data_clean", "shell_clean_only", "blank_reference", "errored_reference",
  "cors_origin_mismatch", "missing_chunk", "modal_blocked", "data_failed",
  "needs_backend_reharvest", "needs_origin_alignment", "unknown_blocked",
]);
let CLEAN_SWEEP = null;
try { CLEAN_SWEEP = JSON.parse(readFileSync(path.join(appRoot, "reference-clean-sweep.json"), "utf8")); } catch { /* pre-sweep generation stays valid */ }
const cleanRowOf = (slug) => (CLEAN_SWEEP && Array.isArray(CLEAN_SWEEP.seeds) ? CLEAN_SWEEP.seeds.find((x) => x.slug === slug) : null);

const rows = SEED_INVENTORY.map((e) => {
  const cls = parityClass(e.slug);
  const row = {
    owner: e.owner,
    slug: e.slug,
    app_route: `/__apps/${e.slug}`,
    capture_base: e.captureBase,
    grammar: e.grammar,
    tier: e.tier,
    parity_class: cls,
    capture_state: captureState[e.slug] || "unknown",
    reference_capture: `/__apps/${e.slug}`,
    reference_workspace: e.captureBase,
    note: e.note,
  };
  const clean = cleanRowOf(e.slug);
  if (clean) {
    row.reference_clean_state = clean.clean_state;
    row.reference_clean_reason = clean.reason;
    row.reference_clean_artifact = "reference-clean-sweep.json";
  }
  const overlay = OVERLAY_FOR(e.slug);
  if (overlay) {
    Object.assign(row, overlay);
    // The ONE canonical field the Playwright harness opens as the IOI candidate for EVERY port-state
    // (substrate_bound → its substrate_surface; a ported state → its port_surface). Guaranteed present
    // for every non-reference_capture row (validated below) so no port-state can escape the harness.
    row.candidate_surface = overlay.port_surface || overlay.substrate_surface || null;
    if (overlay.ioi_url_override) row.ioi_url_override = overlay.ioi_url_override;
    // Shell pixel certification is carried on every port-state row (false unless granted above), with the
    // certifying artifact path when true — an evidence pointer, not prose. `body_semantic_truth` is
    // asserted independently by the per-surface verifier (this flag only asserts the SHELL was certified).
    row.shell_pixel_certified = Object.prototype.hasOwnProperty.call(SHELL_PIXEL_CERTIFIED, e.slug);
    if (row.shell_pixel_certified) row.shell_pixel_certification_artifact = SHELL_PIXEL_CERTIFIED[e.slug];
  }
  return row;
});

// INVARIANT (PR #44): the clean sweep may only carry known states; daemon_wired
// seeds must be data_clean CERTIFIED CONTROLS (their references are the calibration
// standard — a daemon_wired row whose reference is not clean means either the sweep
// heuristics or the certification is wrong, and generation must not paper over it);
// reference_ported rows may stay blocked but must NAME the blocker. The sweep never
// changes parity_class (cleanliness describes the reference, not the port).
if (CLEAN_SWEEP) {
  if (!Array.isArray(CLEAN_SWEEP.seeds) || CLEAN_SWEEP.seeds.length !== rows.length) {
    console.error(`FATAL: reference-clean-sweep.json covers ${(CLEAN_SWEEP.seeds || []).length} seeds but the inventory has ${rows.length} — re-run the sweep (node scripts/harness-reference-clean-sweep.mjs).`);
    process.exit(2);
  }
  for (const r of rows) {
    if (!r.reference_clean_state) { console.error(`FATAL: seed '${r.slug}' missing from reference-clean-sweep.json — the sweep must cover every seed.`); process.exit(2); }
    if (!CLEAN_SWEEP_STATES.has(r.reference_clean_state)) { console.error(`FATAL: seed '${r.slug}' carries unknown reference_clean_state '${r.reference_clean_state}'.`); process.exit(2); }
    if (!r.reference_clean_reason) { console.error(`FATAL: seed '${r.slug}' reference_clean_state has no reference_clean_reason — every classification must be evidence-backed prose.`); process.exit(2); }
    if (r.parity_class === "daemon_wired" && (r.reference_clean_state !== "data_clean" || !r.shell_pixel_certified)) {
      console.error(`FATAL: daemon_wired seed '${r.slug}' must be a data_clean certified control (state=${r.reference_clean_state}, certified=${r.shell_pixel_certified}).`);
      process.exit(2);
    }
    // reference_ported rows may stay clean-blocked or port-pending — the global
    // reason check above already forces them to NAME why (explorer: the origin-
    // alignment finding). No stronger constraint: promotion is a port PR's job.
  }
}

// INVARIANT: shell_pixel_certified is a layer ON TOP of daemon_wired — a row may not claim it without
// first being a certified faithful port, and its evidence file must EXIST, PARSE, and actually certify
// THIS slug's SHELL from a NON-pinned run. Fail generation loudly otherwise (adversarial review: presence
// of a pointer string is not evidence; the committed file is).
for (const r of rows) {
  if (r.shell_pixel_certified && r.parity_class !== "daemon_wired") {
    console.error(`FATAL: seed '${r.slug}' claims shell_pixel_certified but is ${r.parity_class} (shell pixel certification strengthens daemon_wired, never substitutes for it).`);
    process.exit(2);
  }
  if (r.shell_pixel_certified) {
    if (!r.shell_pixel_certification_artifact || !/^pixel-certifications\/[a-z0-9-]+\.json$/.test(r.shell_pixel_certification_artifact)) {
      console.error(`FATAL: seed '${r.slug}' shell_pixel_certification_artifact must be a committed pixel-certifications/<slug>.json path (got: ${r.shell_pixel_certification_artifact}).`);
      process.exit(2);
    }
    let cert = null;
    try { cert = JSON.parse(readFileSync(path.join(appRoot, r.shell_pixel_certification_artifact), "utf8")); } catch (e) { console.error(`FATAL: seed '${r.slug}' certification file unreadable/unparsable: ${String(e.message || e).slice(0, 80)}`); process.exit(2); }
    if (cert.schema !== "ioi.hypervisor.shell-pixel-certification.v1" || cert.slug !== r.slug || cert.shell_pixel_certified !== true || cert.viewports_pinned !== false) {
      console.error(`FATAL: seed '${r.slug}' certification file does not shell-certify this slug from a non-pinned run (schema=${cert.schema} slug=${cert.slug} certified=${cert.shell_pixel_certified} pinned=${cert.viewports_pinned}).`);
      process.exit(2);
    }
  }
}

// INVARIANT: every port-state row MUST carry a candidate_surface — otherwise a future daemon_wired /
// reference_ported / reference_port_pending seed could silently escape the harness and claim parity
// unverified. Fail generation loudly if the overlay forgot it.
const PORT_STATES = new Set(["substrate_bound", "reference_port_pending", "reference_ported", "daemon_wired"]);
for (const r of rows) {
  if (PORT_STATES.has(r.parity_class) && !r.candidate_surface) {
    console.error(`FATAL: seed '${r.slug}' is ${r.parity_class} but has no candidate_surface (add port_surface/substrate_surface to its overlay).`);
    process.exit(2);
  }
}

const byClass = rows.reduce((m, r) => ((m[r.parity_class] = (m[r.parity_class] || 0) + 1), m), {});
const matrix = {
  schema_version: "ioi.hypervisor.app-parity-matrix.v2",
  phase: "Reference UX Port",
  doctrine: "Reference UX port first (port the source-neutralized reference shell/layout) → daemon truth inside that UX (wire panels, tables, graph nodes, toolbars, drawers, empty + disabled states) → IOI-native redesign later. The dark IOI surfaces built #3–#30 are substrate, not parity.",
  pixel_rule: "`shell_pixel_certified` (per port-state row) is a STRONGER evidence layer on TOP of daemon_wired: PIXEL-IDENTICAL SHELL, SEMANTICALLY-TRUTHFUL BODY. Because the captured references carry Palantir EXAMPLE data while the IOI ports render LIVE daemon truth, full-body pixel parity is NOT the target (it would reward faking IOI data). The shell-pixel harness (harness-reference-pixel-parity.mjs) certifies the surface at the required viewports (1440x900 + 1920x1080, + 390x844 only if the reference supports mobile): the #34/#39 visual gates AND the certified SHELL (rail/header/app-rail/toolbar/panel chrome) diff ≤ the shell budget AND shell region bboxΔ ≤ 8px AND the certified shell covers a real fraction of the image — with the live-data BODY EXCLUDED by design and its truth verified SEMANTICALLY by the per-surface verifier (body_semantic_truth: same container placement + grammar + live count cross-checks + real-substrate existence + named gaps). Over-masking the shell fails closed. shell_pixel_certified never replaces daemon_wired, the visual gate, or daemon truth; a true row carries a committed shell_pixel_certification_artifact.",
  parity_rule: "Only `daemon_wired` counts as TRUE reference UX parity: a FAITHFUL port of the reference UX (same theme + IA + layout) wired to daemon truth that passes the HARDENED Playwright harness — `visual_parity` = region geometry + theme (light/dark) match + reproduction of the reference's IA landmarks. Region-name overlap alone is NOT parity (#34 review). `substrate_bound` = a dark IOI surface (custom automationsShell) over daemon truth — valuable substrate, NOT parity. `reference_ported` = a shell ported + wired but not certified under the hardened gate (errored reference OR a native redesign that does not reproduce the reference theme + IA). A surface must not claim parity without side-by-side screenshots + the hardened harness pass.",
  reset_note: "PR #31 presentation-layer rebase: the former `daemon_bound` class is retired; its 10 surfaces are reclassified `substrate_bound`, with all daemon planes / fail-closed contracts / truth verifiers preserved. #34 review HARDENED the parity gate (theme + IA landmarks, not just region names): #34 Ontology Manager is the first FAITHFUL light two-rail port to certify `daemon_wired`; #33 approvals was reclassified `reference_ported` (a wired but native-dark shell), then #36 RE-PORTED it as a FAITHFUL light faceted inbox and PROMOTED it back to `daemon_wired` — the second faithful port. #35 Object Explorer is `reference_ported` (blank/failed local Hubble reference). #32 pipeline was `reference_ported`; #38 RE-BASELINED its blocker (data complete, CORS/origin-blocked — origin alignment, NOT the fresh-session re-harvest #37 wrongly prescribed); #39 then PROMOTED it to `daemon_wired` — the THIRD faithful port — by RE-PORTING /__ioi/pipeline to a faithful LIGHT Pipeline Builder (the earlier dark shell was correctly refused by #34's theme gate) AND aligning the harness reference to the origin-matched data-clean canvas (reference_url_override localhost:9225 …/sandbox/…, modal dismissed); the hardened harness certifies visual_parity (light/light + landmarks 10/10 + regions 1.0).",
  estate_backstop: {
    executable_seeds: rows.length,
    note: "The 39 executable seeds are the migration queue; the 45-app local-composition crosswalk is the estate backstop so coverage does not shrink.",
    crosswalk: "internal-docs/reverse-engineering/palantir/local-composition-application-crosswalk.md",
    reference_mirror: "http://127.0.0.1:9225 (proxied token-injected via serve /__apps/<slug>)",
  },
  generated_from: ["apps/hypervisor/scripts/harvest-seed-inventory.mjs", "apps/hypervisor/harvest-starting-points.json"],
  total_seeds: rows.length,
  by_parity_class: byClass,
  legend: {
    reference_capture: "the /__apps/<slug> reference baseline serves; no IOI port exists",
    substrate_bound: "a dark IOI surface (custom shell) renders REAL daemon truth — valuable substrate, NOT reference UX parity",
    reference_port_pending: "selected for porting; reference screenshots + selectors captured (not yet ported)",
    reference_ported: "source-neutral reference shell/layout ported, still static or minimally wired",
    daemon_wired: "ported reference UX wired to daemon truth AND passing visual/structural parity — the ONLY true-parity state",
    capture_state: "what the LOCAL CAPTURE does when booted (boots_*/shell_only/blocked_missing_capture) — NOT a parity claim",
  },
  seeds: rows,
  _doc: "Generated by build-app-parity-matrix.mjs. Do not hand-edit; change the inventory / the SUBSTRATE_BOUND + REFERENCE_PORT_PENDING/REFERENCE_PORTED/DAEMON_WIRED overlays and regenerate. Run with --check to fail on staleness.",
};

const outPath = path.join(appRoot, "harvest-app-parity-matrix.json");
const rendered = JSON.stringify(matrix, null, 2) + "\n";

if (process.argv.includes("--check")) {
  let current = "";
  try { current = readFileSync(outPath, "utf8"); } catch { /* missing */ }
  if (current !== rendered) {
    console.error("STALE: harvest-app-parity-matrix.json is out of date — run: node apps/hypervisor/scripts/build-app-parity-matrix.mjs");
    process.exit(1);
  }
  console.log(`app parity matrix current — ${rows.length} seeds · ${JSON.stringify(byClass)}`);
} else {
  writeFileSync(outPath, rendered);
  console.log(`wrote harvest-app-parity-matrix.json — ${rows.length} seeds · ${JSON.stringify(byClass)}`);
}
