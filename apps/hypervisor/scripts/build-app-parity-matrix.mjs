#!/usr/bin/env node
// Application UX Parity Baseline — matrix generator.
//
// The estate-wide parity program (phase doctrine: reference UX parity first, IOI substrate
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

// The ONLY per-seed overlay — everything else is a reference capture until a cut binds it.
// daemon_surface = the IOI-owned surface that renders the reference grammar over daemon truth.
const DAEMON_BOUND = {
  pipeline: { daemon_surface: "/__ioi/pipeline", binding: "ODK authority ladder (DataSource → ConnectorMapping → PolicyBoundDataView → TransformationRun → OntologyProjection → CapabilityLease → ConnectorSession → MaterializedObjectSet)", note: "the ODK ladder rendered as a datasource→transform→output pipeline; supported lanes = daemon truth, freeform authoring/schedule/deploy = named gaps" },
  lineage: { daemon_surface: "/__ioi/lineage", binding: "ODK materialization provenance (MaterializedObjectSet → run → session → lease → projection → mapping → datasource, resolved to live ladder refs; per-object source hashes + mapped_from; pre-output + registration receipts; Provenance proof-stream edges where available)", note: "Monocle lineage grammar over real provenance; upstream ladder refs resolved to live records; no fake nodes for unmaterialized ontologies; freeform resource-search / graph-expansion / cross-tenant catalog = named gaps" },
  // Canon: Work Ledger evolves into Provenance — Vertex is a Provenance graph/exploration lens.
  vertex: { daemon_surface: "/__ioi/vertex", surface_name: "Provenance", binding: "a Provenance graph/exploration lens over materialized object sets, projections, objects, and the threaded proof-stream odk_materialization edges (cross-plane: ODK ↔ Provenance)", note: "Vertex graph grammar (nodes · relations · neighborhood) over real cross-plane materialized truth; no fake nodes for unmaterialized ontologies; freeform graph canvas / arbitrary path-finding / cross-tenant object search / saved explorations = named gaps" },
  // Missions owner-family: jobs + incidents seeds bound to /__ioi/missions (the owner surface for
  // suite/run work). Operations stays substrate/infra. Both are the SAME owner surface, two lanes.
  jobs: { daemon_surface: "/__ioi/missions", surface_name: "Missions", binding: "the Missions run/job queue — the real operations run queue (recent runs, statuses, run counts) + scheduled missions, table/list grammar over daemon truth", note: "run-queue lane of the Missions owner surface; honest empty when no runs; freeform job-definition editing / board views / arbitrary filtering = named gaps; substrate/infra scheduler health stays in Operations" },
  incidents: { daemon_surface: "/__ioi/missions", surface_name: "Missions", binding: "the Missions incident/remediation inbox — real run failures + GoalRun blockers, each linking to its own proof/timeline, status-lane grammar over daemon truth", note: "incident lane of the Missions owner surface; honest empty when no failures/blockers; create/assign incidents / SLA / comments = named gaps; substrate/infra incidents (storage repair, provider failover) stay in Operations" },
  // Evaluations owner-family: only evalsuites binds in this cut (analysis + quiver stay reference_capture).
  // The eval-suite library renders the INERT daemon eval-suite contract (a declaration; no scoring).
  evalsuites: { daemon_surface: "/__ioi/evaluations", surface_name: "Evaluations", binding: "the eval-suite library — the inert daemon eval-suite contract (a suite declares subject_scope + evidence/consent requirements + named candidate handoffs) over real assessment subjects (Missions runs/failures/blockers) + the consent ladder + feedback candidate source, table/list grammar over daemon truth", note: "declaration-only owner surface; /__ioi/feedback kept as a compatibility sublane; honest empty when no suites; EvalRun execution / scoring / verdicts / judge / scorecards / auto-mining / analysis+quiver canvases / promotion = named gaps" },
  // Studio owner-family: only designer binds in this cut (machinery/workshop/module stay reference_capture).
  // A dedicated /__ioi/studio/designer surface; the /__ioi/agent-studio owner links to it (no rename).
  designer: { daemon_surface: "/__ioi/studio/designer", surface_name: "Studio", binding: "the system-design canvas — a read-only typed concept/component/resource map over real ODK composition (an ontology's object/value/action/link types = concepts; connector mappings + policy views + projections = components; materialized object sets + domain-app surface descriptors = resources)", note: "read-only design map; owner surface stays /__ioi/agent-studio (no route rename); honest empty when an ontology has no concepts/components/resources; in-canvas authoring / save-open / drag-to-reference / load-lineage / machinery process-graph execution / workshop+module builders = named gaps" },
  // Governance owner-family: only approvals binds in this cut. The Governance owner surface already
  // renders the review-inbox queue over real ApprovalRequest records; this formalizes it in the matrix.
  approvals: { daemon_surface: "/__ioi/governance?tab=approvals", surface_name: "Governance", binding: "the approvals decision queue — the review-inbox grammar over real daemon ApprovalRequest records (status-count inbox chips, blast radius from would_call/required_authority_refs, age, per-row inspector drawer, in-row approve/reject/revoke transitions); release controls, kill switches, cohorts, improvement gates render as supporting Governance context", note: "real decision queue on the Governance owner surface; honest empty when no requests; reviewer assignment / delegation / threaded comments / SLA-escalation / identity-team review workflows / audit exports = named gaps" },
};
// Named-next targets (owner binding declared; surface not built yet).
const QUEUED = {};

function parityClass(slug) {
  if (DAEMON_BOUND[slug]) return "daemon_bound";
  if (QUEUED[slug]) return "queued";
  return "reference_capture";
}

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
    note: e.note,
  };
  if (DAEMON_BOUND[e.slug]) Object.assign(row, DAEMON_BOUND[e.slug]);
  if (QUEUED[e.slug]) Object.assign(row, QUEUED[e.slug]);
  return row;
});

const byClass = rows.reduce((m, r) => ((m[r.parity_class] = (m[r.parity_class] || 0) + 1), m), {});
const matrix = {
  schema_version: "ioi.hypervisor.app-parity-matrix.v1",
  phase: "Application UX Parity Baseline",
  doctrine: "reference UX parity first (local capture, no live re-harvest, no invented daemon truth), IOI substrate underneath (bind supported lanes to daemon truth, keep unsupported lanes as honest named gaps), IOI-native UX later",
  generated_from: ["apps/hypervisor/scripts/harvest-seed-inventory.mjs", "apps/hypervisor/harvest-starting-points.json"],
  total_seeds: rows.length,
  by_parity_class: byClass,
  legend: {
    reference_capture: "the /__apps/<slug> reference baseline serves; not yet bound to daemon truth",
    daemon_bound: "an IOI-owned surface renders the reference grammar over REAL daemon truth (supported lanes daemon-true, unsupported = named gaps)",
    queued: "named as the next daemon-bound target (owner binding declared, surface not built yet)",
    capture_state: "what the LOCAL CAPTURE does when booted (boots_*/shell_only/blocked_missing_capture) — NOT a parity claim",
  },
  seeds: rows,
  _doc: "Generated by build-app-parity-matrix.mjs. Do not hand-edit; change the inventory / the DAEMON_BOUND+QUEUED overlay and regenerate. Run with --check to fail on staleness.",
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
