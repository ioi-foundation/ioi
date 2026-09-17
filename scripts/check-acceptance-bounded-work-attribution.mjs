#!/usr/bin/env node
// ACC-5 · bounded work is defined, executed, and attributed — the composed journey runner.
//
// A clause table over scripts/lib/acceptance-journey.mjs. Every ACC-5 clause names the existing
// done-bar that proves it, executed sequentially on ONE basis, or the unit that still owes the
// proof as a TYPED ABSENCE.
//
//   node scripts/check-acceptance-bounded-work-attribution.mjs [--mutation-batteries] [--mutation] [--evidence <out.json>]

import { runJourney, app, rootScript, cargoTest, bounded } from "./lib/acceptance-journey.mjs";

const DAEMON_SUITE = bounded(cargoTest("ioi-node", ["--bin", "hypervisor-daemon"]), 90);
const absent = (unit, check, what) => ({ what: `${what} — ${check} (${unit}) is To be authored`, owner: unit });

const CLAUSES = [
  { id: "1", clause: "A non-software result is expressible: a WorkResult and an OutcomeDelta carry a result that is not a patch, and the software profile is one profile rather than the contract", unit: "M04.1", checks: [rootScript("check:generic-work-result-seam")], battery: { ...rootScript("mutate:generic-work-result-seam"), cost: "minutes" } },
  { id: "2", clause: "The four automation objects have four lifetimes: editing a template does not change a running automation; a run freezes the exact template, spec and binding it activated", unit: "M04.2", checks: [app("check:automations-journey")] },
  { id: "3", clause: "Skills split three ways: an immutable manifest, a revisioned owner-scope binding and an exact run-scoped snapshot; the run replays with the snapshot it had", unit: "M04.3", checks: [app("check:skill-contracts")] },
  { id: "4", clause: "A GoalRun admits with its bindings: admitted state root, receipt obligations, source context and authority scopes are on the admitted record for the general surface", unit: "M04.4", checks: [app("check:goal-profile-contracts"), app("check:m3-goalrun-plane"), bounded(app("check:m4-goalrun-activation-plane"), 40)] },
  { id: "5", clause: "Execution composes the daemon's primitives: the run's steps resolve through thread, fork, managed-session, harness-binding and launch-recipe admission, and the receipts show it", unit: "M04.5", checks: [app("check:launch-chain")] },
  { id: "6", clause: "Simple work collapses: a simple task takes the direct path; parallelism appears only where uncertainty, expected value, independence or verification need justifies it, and the justification is recorded (the M3 direct lane and the admission-path selection that never silently downgrades collective work)", unit: "M04.4 · M04.5", provenBy: "4" },
  { id: "7", clause: "Lifecycle survives cancellation: cancel before effect, during work, restart mid-run — the lifecycle record, its projection and its cancellation fanout converge on readback (38 pinned, source-bound tests)", unit: "M04.6", checks: [rootScript("check:work-lifecycle-integrity")], battery: { ...rootScript("mutate:work-lifecycle-integrity"), cost: "minutes" } },
  { id: "8", clause: "Concurrent child work cannot oversubscribe an ancestor: reservations are exact-head, per-dimension and disjoint, preserve protected capacity, narrow every ancestor bound and transfer atomically on reassignment", unit: "M04.10", checks: [app("check:work-lifecycle-reservations")] },
  { id: "9", clause: "Context is leased application state, not copied authority: GoalRun owns ContextCell, ContextLease and ContextHandoff revisions; restart reproduces the least-context view; handoff creates a candidate re-evaluated under receiver policy", unit: "M04.11", checks: [bounded(app("check:context-lease-handoff-lifecycle"), 30), bounded(app("mutate:context-lease-handoff-lifecycle"), 20)] },
  { id: "10", clause: "A composition instantiates only existing owners, and lineage outlives its creator: a daemon-derived collective-resolution receipt freezes the exact dependency closure without registering a new profile owner; lifecycle.status = active satisfies no check; removal transfers no ownership", unit: "M04.12", absences: [absent("M04.12", "check:collective-artifact-runtime-lifecycle", "the collective-resolution receipt, the artifact lifecycle verbs (observe/reuse/fork/activate/quarantine/repair/replace/retire) and the caretaker object have no code")] },
  { id: "N1", negative: true, clause: "Application state grants no execution, wallet, connector, storage, model or physical authority", unit: "M04.4", provenBy: "4" },
  { id: "N2", negative: true, clause: "No coding-specific field enters the universal result contract", unit: "M04.1", provenBy: "1" },
  // The MCP half is a TYPED ABSENCE rather than a claim: clause 9's gate asserts that no MCP tool
  // reaches the context families, so the refusals it proves are proven on the only path that reaches
  // them, and the MCP matrix belongs to M01.10/M01.11 when a tool does.
  { id: "N3", negative: true, clause: "No context handoff copies raw payload truth, executable/kernel state or authority; widening, stale, revoked, wrong-recipient and cross-tenant reads refuse identically through native and MCP paths", unit: "M04.11", provenBy: "9", absences: [absent("M01.10 · M01.11", "check:mcp-non-tool-normalization", "the MCP half of this matrix: clause 9's gate asserts that NO MCP tool reaches the context families today, so there is no MCP path on which to refuse anything; the native refusals are complete and the MCP matrix arrives with the MCP gateway's own units")] },
  { id: "N4", negative: true, clause: "A resolved composition registers no new profile owner; an active artifact, chat, participant or surviving process is never execution or authority truth", unit: "M04.12", absences: [absent("M04.12", "check:collective-artifact-runtime-lifecycle", "the composition negatives")] },
  { id: "E", clause: "Journey evidence: session authority and the daemon suite", unit: "M04", checks: [app("check:session-authority"), DAEMON_SUITE] },
];

await runJourney({
  gate: "ACC-5",
  title: "bounded work is defined, executed, and attributed",
  doc: "internal-docs/implementation/acceptance/journey-05-bounded-work-and-attribution.md",
  clauses: CLAUSES,
});
