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
  incidents: { substrate_surface: "/__ioi/missions", surface_name: "Missions", binding: "the Missions incident/remediation inbox — real run failures + GoalRun blockers, each linking to its own proof/timeline, status-lane grammar over daemon truth", note: "incident lane of the Missions owner surface; honest empty when no failures/blockers; create/assign incidents / SLA / comments = named gaps; substrate/infra incidents (storage repair, provider failover) stay in Operations" },
  // Evaluations owner-family: only evalsuites binds in this cut (analysis + quiver stay reference_capture).
  // The eval-suite library renders the INERT daemon eval-suite contract (a declaration; no scoring).
  evalsuites: { substrate_surface: "/__ioi/evaluations", surface_name: "Evaluations", binding: "the eval-suite library — the inert daemon eval-suite contract (a suite declares subject_scope + evidence/consent requirements + named candidate handoffs) over real assessment subjects (Missions runs/failures/blockers) + the consent ladder + feedback candidate source, table/list grammar over daemon truth", note: "declaration-only owner surface; /__ioi/feedback kept as a compatibility sublane; honest empty when no suites; EvalRun execution / scoring / verdicts / judge / scorecards / auto-mining / analysis+quiver canvases / promotion = named gaps" },
  // Studio owner-family: only designer binds in this cut (machinery/workshop/module stay reference_capture).
  // A dedicated /__ioi/studio/designer surface; the /__ioi/agent-studio owner links to it (no rename).
  designer: { substrate_surface: "/__ioi/studio/designer", surface_name: "Studio", binding: "the system-design canvas — a read-only typed concept/component/resource map over real ODK composition (an ontology's object/value/action/link types = concepts; connector mappings + policy views + projections = components; materialized object sets + domain-app surface descriptors = resources)", note: "read-only design map; owner surface stays /__ioi/agent-studio (no route rename); honest empty when an ontology has no concepts/components/resources; in-canvas authoring / save-open / drag-to-reference / load-lineage / machinery process-graph execution / workshop+module builders = named gaps" },
  // Studio machinery: the process/state-machine DEFINITION plane (a new inert daemon contract).
  // Definition-only — no run/step/scheduling/binding. workshop + module stay reference_capture.
  machinery: { substrate_surface: "/__ioi/studio/machinery", surface_name: "Studio", binding: "the process/state-machine definition view — a read-only rendering of the inert daemon state-machine plane (declared states initial/normal/final, transitions from→to with event + guard, declared guards, inputs/outputs, owners, health empty|incomplete|ready, and edit history)", note: "DEFINITION-ONLY, read-only surface; a new inert daemon contract with fail-closed writes; owner surface stays /__ioi/agent-studio; honest empty/incomplete when a machine is under-declared; execution / stepping a running instance / scheduling / Automations-Missions-ODK binding / in-canvas graph authoring / simulation / versioning = named gaps (a later authority-crossing cut)" },
  // NOTE: Governance/approvals is NOT here — #36 PROMOTED it to `daemon_wired` (a FAITHFUL light faceted-
  // inbox port over the real ApprovalRequest queue; see DAEMON_WIRED below), not substrate_bound.
  // Foundry owner-family: only models binds in this cut (modelstudio + inference stay reference_capture).
  // The Foundry landing's Model Catalog already renders the real model-route registry; this formalizes it.
  models: { substrate_surface: "/__ioi/foundry", surface_name: "Foundry", binding: "the model registry — the Foundry Model Catalog over the real daemon model-route registry (per-route honest availability from probe evidence + staleness, weight custody, credential posture, admission trail, and admitted session-binding usage), plus the substrate stats and the draft Foundry specs/run-plans where they connect", note: "catalog grammar over real model-route truth; route administration lives in Agent Studio (linked); honest empty when no routes; fine-tuning / prompt playground / live inference evals / deployment automation / training runs / unbacked model cards = named gaps" },
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
  // #35 — Object Explorer: a FAITHFUL light port of the reference Object Explorer (dark global rail +
  // "Object Explorer search" header w/ Filter/Search bar + Shortcuts strip + Object type CATALOG table +
  // Object set CATALOG) wired to the REAL ODK truth (object types across ontologies, materialized object
  // sets, per-type object + usage counts, a working server-side object-type filter). Paired with #34
  // Ontology Manager (linked first-class both ways). BLOCKED from daemon_wired by a broken REFERENCE:
  // the local /workspace/hubble capture does NOT cleanly boot — the /__apps/explorer proxy renders a
  // BLANK body, and the mirror rendered directly shows the IA but every data lane reads "Failed to load"
  // (the static mirror has no backend). So the hardened harness has no valid reference to certify
  // visual_parity against. daemon_wired awaits a re-harvest of /workspace/hubble with a working backend.
  explorer: { port_surface: "/__ioi/ontology/explorer", surface_name: "Ontology", reference_workspace: "/workspace/hubble/", parity_blocked: "local /workspace/hubble reference does not cleanly boot — the /__apps/explorer proxy renders a blank body and the mirror's data lanes render 'Failed to load' (no backend); no valid reference to certify visual_parity until a re-harvest", binding: "faithful Object Explorer shell over real ODK truth — an object-type CATALOG (name · status · objects · usage · ontology · description) across all ontologies + a working server-side type filter, an object-set CATALOG over real materialized object sets (name · ontology · object type · object count), and Shortcuts; every populated cell is daemon truth", note: "reference_ported (#35): faithful light Object-Explorer shell (global rail + search header + Shortcuts + object-type catalog + object-set catalog), wired to real object types + materialized sets, first-class linked to /__ioi/ontology/manager; READ-ONLY; object-instance full-text search / faceted Filter-by / Recents / Favorites / sort / type-group+application tabs / Created-by-me+Shared-with-me = named gaps disabled in place; NOT daemon_wired — the local Hubble reference is blank/failed, so the hardened harness cannot certify parity" },
};
// TRUE reference UX parity — a FAITHFUL port of the reference UX (same theme + IA + layout) wired to
// daemon truth, that PASSES the HARDENED Playwright harness (visual_parity: region geometry + theme
// match + reproduction of the reference's IA landmarks) against a VALID (non-errored) reference.
// `reference_landmarks` = the reference's IA label set the hardened harness requires in BOTH sides.
const DAEMON_WIRED = {
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
  const overlay = OVERLAY_FOR(e.slug);
  if (overlay) {
    Object.assign(row, overlay);
    // The ONE canonical field the Playwright harness opens as the IOI candidate for EVERY port-state
    // (substrate_bound → its substrate_surface; a ported state → its port_surface). Guaranteed present
    // for every non-reference_capture row (validated below) so no port-state can escape the harness.
    row.candidate_surface = overlay.port_surface || overlay.substrate_surface || null;
  }
  return row;
});

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
