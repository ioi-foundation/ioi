#!/usr/bin/env node
// ACC-8 · evidence survives the system that made it — the composed journey runner.
//
// A clause table over scripts/lib/acceptance-journey.mjs. Every ACC-8 clause names the existing
// done-bar that proves it, executed sequentially on ONE basis. Clause 6 carries the journey
// document's own 2026-09-13 disposition: the managed lane's bytes have an owner, but whether the
// canonical retention plane REACHES them is unmeasured — recorded as a typed absence, not counted.
// check:verifier-floors runs LAST because it reads the census the journey verifiers emit.
//
//   node scripts/check-acceptance-evidence-replay.mjs [--mutation-batteries] [--mutation] [--evidence <out.json>]

import { runJourney, app, rootScript } from "./lib/acceptance-journey.mjs";

const CLAUSES = [
  { id: "1", clause: "The assurance ladder is explicit: attested → evidenced → verified → accepted → adjudicated → settled, each transition naming its actor, its evidence and what it does not assert", unit: "M06.1", checks: [app("check:assurance-ladder-lifecycle")], battery: { ...app("mutate:assurance-ladder-lifecycle"), cost: "multi-hour" } },
  { id: "2", clause: "Negative results survive: inconclusive, invalid, exploit-finding, superseded, disputed and no-fault outcomes are retained and queryable after restart", unit: "M06.1", provenBy: "1" },
  { id: "3", clause: "A receipt is evidence, not a verdict: no consumer treats a receipt as correctness, acceptance or settlement (the transition seam and the WorkResult resolver/projection)", unit: "M06.1", provenBy: "1", checks: [app("check:assurance-transition-receipt"), app("check:verified-work-graph")] },
  { id: "4", clause: "An evidence bundle reproduces a decision on a fresh daemon: admitted record, state root, receipts, inputs by ref and the refusals it produced — with no daemon, through the standalone offline relying party", unit: "M06.4", checks: [rootScript("check:portable-evidence-replay")], battery: { ...rootScript("mutate:portable-evidence-replay"), cost: "minutes" } },
  { id: "5", clause: "Restore proves semantic continuity, not blob presence: the restored system answers the same questions with the same meanings, and a deletion made before the backup stays deleted after the restore", unit: "M09.4 · M06.4", checks: [rootScript("check:canonical-environment-backup"), app("check:backup-restore")] },
  { id: "6", clause: "Every backup byte has an owner and is reachable by the retention plane; a lane whose bytes retention cannot reach is a finding", unit: "M06.3 · M09.4", checks: [app("check:environment-custody"), app("check:env-lease-authority")], absences: [{ what: "whether the canonical retention plane REACHES the managed lane's bytes is unmeasured: retention_routes.rs names hypervisor-environment-backups and no other family while the managed lane carries its own managed_backup_retention_expired vocabulary (journey document disposition, 2026-09-13) — two retention mechanisms over two byte planes is exactly what this clause asks about", owner: "M06.3 remainder (register R-138)" }] },
  { id: "7", clause: "Provenance assertions are objects with source, evidence, uncertainty and contradiction handling, not a rendering of logs", unit: "M05.3", checks: [app("check:provenance-assertion-graph")], battery: { ...app("mutate:provenance-assertion-graph"), cost: "multi-hour" } },
  { id: "N1", negative: true, clause: "No gate is its own oracle: an expectation is a committed pin compared against a fresh computation (the census population is entailed from rustc's own dep-info, both directions)", unit: "M06.5", checks: [rootScript("check:admission-census-entailment")], battery: { ...rootScript("mutate:admission-census-entailment"), cost: "minutes" } },
  { id: "N2", negative: true, clause: "A coverage gap is a finding, never indistinguishable from safety (resolution over the census is total, failures counted by cause)", unit: "M06.5", provenBy: "N1" },
  { id: "E", clause: "Journey evidence: admission evidence provenance, then the verifier-family census floor over the journey verifiers that just ran", unit: "M06", checks: [rootScript("check:admission-evidence"), app("check:verifier-floors")] },
];

await runJourney({
  gate: "ACC-8",
  title: "evidence survives the system that made it",
  doc: "internal-docs/implementation/acceptance/journey-08-evidence-and-replay.md",
  clauses: CLAUSES,
});
