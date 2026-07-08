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
  // Governance owner-family: only approvals binds in this cut. The Governance owner surface already
  // renders the review-inbox queue over real ApprovalRequest records; this formalizes it in the matrix.
  // Foundry owner-family: only models binds in this cut (modelstudio + inference stay reference_capture).
  // The Foundry landing's Model Catalog already renders the real model-route registry; this formalizes it.
  models: { substrate_surface: "/__ioi/foundry", surface_name: "Foundry", binding: "the model registry — the Foundry Model Catalog over the real daemon model-route registry (per-route honest availability from probe evidence + staleness, weight custody, credential posture, admission trail, and admitted session-binding usage), plus the substrate stats and the draft Foundry specs/run-plans where they connect", note: "catalog grammar over real model-route truth; route administration lives in Agent Studio (linked); honest empty when no routes; fine-tuning / prompt playground / live inference evals / deployment automation / training runs / unbacked model cards = named gaps" },
};
// Port-progress overlays — a seed advances reference_port_pending → reference_ported → daemon_wired
// as its reference UX shell is captured, ported, and finally wired + parity-verified against a VALID
// reference. #32 (Pipeline Builder) begins the first `reference_ported` shell; `daemon_wired` stays 0
// until a valid (non-errored) reference boots to certify parity. `reference_workspace` = the mirror
// path the Playwright harness opens (`:9225<capture_base>`), also carried on every row.
const REFERENCE_PORT_PENDING = {};
// A source-neutral reference shell/layout ported + wired to daemon truth, but NOT yet promoted to
// daemon_wired — here because parity VERIFICATION is blocked (the local reference errors / is
// unavailable). port_surface = the ported IOI surface; parity_blocked names why.
const REFERENCE_PORTED = {
  // #32 — Pipeline Builder: the builder shell ported source-neutrally (rail · header · graph toolbar ·
  // canvas with ODK-ladder node cards · right output panel · bottom tray) and fully wired to the real
  // ODK ladder. BLOCKED from daemon_wired: every /workspace/builder/* route in the local mirror
  // (incl. the crosswalk's example RID) renders "An error occurred" — only the global platform nav
  // renders, so there is NO valid builder reference to prove structural parity against. The harness
  // now guards this (an errored reference can never yield a parity pass). daemon_wired awaits a
  // working builder capture (re-harvest of /workspace/builder with an installed pipeline example).
  pipeline: { port_surface: "/__ioi/pipeline", surface_name: "Data", reference_workspace: "/workspace/builder/", parity_blocked: "local /workspace/builder/* reference errors ('An error occurred') — no valid builder canvas captured; daemon_wired blocked until a working builder reference is re-harvested", binding: "ported Pipeline Builder shell over the real ODK authority ladder (DataSource → ... → MaterializedObjectSet) as canvas node cards; live/declared/missing per stage from daemon truth; preview rows + output schema from the real projection + materialized set", note: "shell ported + wired (source-neutral builder shell: rail/header/toolbar/canvas/right/tray, NOT automationsShell; Build+Preview supported, Schedule+Deploy disabled in place); NOT daemon_wired — parity verification blocked on an errored local reference" },
};
// TRUE reference UX parity — a ported source-neutral reference shell wired to daemon truth that PASSES
// the Playwright visual + structural harness AGAINST A VALID (non-errored) reference.
const DAEMON_WIRED = {
  // #33 — Approvals inbox: the /workspace/approvals-app/ shell ported source-neutrally (left rail of
  // inbox views · header · toolbar · request table · right detail panel · bottom tray), NOT
  // automationsShell, over the REAL daemon ApprovalRequest queue with the existing approve/reject/
  // revoke transitions (no new semantics). The reference BOOTS (non-errored), so the harness certifies
  // structural parity → FIRST true daemon_wired. Substrate table kept at ?tab=approvals.
  approvals: { port_surface: "/__ioi/governance/approvals", surface_name: "Governance", reference_workspace: "/workspace/approvals-app/", binding: "ported Approvals-inbox shell over the real daemon ApprovalRequest queue — a left rail of inbox views (Needs decision / Approved / Rejected / Revoked / All with live counts), header (pending count + oldest age), a request table (kind · target · blast radius from would_call/required_authority_refs · age · status · in-row approve/reject/revoke), and a right detail panel (by-status + named gaps); every cell is daemon truth", note: "FIRST true parity (#33): source-neutral Approvals-inbox shell (rail/header/toolbar/body/right/tray), NOT automationsShell; passes the Playwright harness against the VALID /__apps/approvals reference; decisions are the existing daemon transitions (no new governance semantics); reviewer-assignment / delegation / comments / SLA / audit-export = named gaps disabled in place; substrate table stays at /__ioi/governance?tab=approvals" },
  // #34 — Ontology Manager (schema): the /workspace/ontology/ schema-workbench shell ported
  // source-neutrally (left rail of ontologies + schema-section nav · header with ontology/health/counts ·
  // toolbar · body of typed schema sections: object/value/link/action types + functions + health ·
  // right detail panel: configuration + resources · bottom tray), NOT automationsShell, over the REAL
  // ODK CanonicalObjectModel. Read-only schema view — authoring + object materialization stay in the
  // /__ioi/odk substrate. The /__apps/schema reference BOOTS (non-errored), so the harness certifies
  // structural parity → daemon_wired. Object Explorer (explorer seed) is the sibling #35 cut.
  schema: { port_surface: "/__ioi/ontology/manager", surface_name: "Ontology", reference_workspace: "/workspace/ontology/", binding: "ported Ontology-Manager schema workbench over the real ODK CanonicalObjectModel — a left rail of ontologies (live health pills) + schema-section nav, header (domain · version · health status · object/instance counts), typed schema sections (object types with per-type object counts, properties, value types, link types, actions, functions, health/gaps/instances), and a right panel (configuration ref/revision/receipts/history + resources materialized sets/projections + estate rollup); every cell is daemon truth", note: "true parity (#34): source-neutral schema-workbench shell (rail/header/toolbar/body/right/tray), NOT automationsShell; passes the Playwright harness against the VALID /__apps/schema reference; READ-ONLY over daemon truth — authoring/create-edit + object materialization stay in the /__ioi/odk substrate (linked first-class); in-canvas schema editing / action+function execution / orphan-reference cleanup = named gaps disabled in place; Object Explorer is the sibling #35 cut" },
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
  parity_rule: "Only `daemon_wired` counts as TRUE reference UX parity: a ported, source-neutral reference shell wired to daemon truth that passes the Playwright visual + structural harness (global shell rail, header, toolbar, body, right panel, bottom tray). `substrate_bound` = a dark IOI surface (custom automationsShell) over daemon truth — valuable substrate, NOT parity. A surface must not claim parity without side-by-side screenshots + structural assertions.",
  reset_note: "PR #31 presentation-layer rebase: the former `daemon_bound` class is retired. Its 10 surfaces are reclassified `substrate_bound`; the daemon planes, fail-closed contracts, and truth verifiers are all preserved. #32 (Pipeline Builder) begins the first `reference_ported` shell; `daemon_wired` remains 0 until a valid (non-errored) reference boots to certify parity.",
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
