#!/usr/bin/env node
// ACC-7 · continuity and useful distribution across nodes — the composed journey runner.
//
// A clause table over scripts/lib/acceptance-journey.mjs. The journey names "real failure domains";
// what exists today proves the membership/fencing/recovery planes on one host and the reservation
// plane's partition/rejoin semantics; the two-failure-domain distribution proof is M12.6's and is a
// TYPED ABSENCE until it lands.
//
//   node scripts/check-acceptance-continuity-distribution.mjs [--mutation-batteries] [--mutation] [--evidence <out.json>]

import { runJourney, app, rootScript, cargoTest, bounded } from "./lib/acceptance-journey.mjs";

const DAEMON_SUITE = bounded(cargoTest("ioi-node", ["--bin", "hypervisor-daemon"]), 90);
const AGENTGRES_SUITE = bounded(cargoTest("agentgres"), 60);
const absent = (unit, check, what) => ({ what: `${what} — ${check} (${unit}) is To be authored`, owner: unit });

const CLAUSES = [
  { id: "1", clause: "Join is admission, not arrival: a node joins through admission, catch-up and root verification; membership is observed separately from desired topology", unit: "M02.3", checks: [rootScript("check:system-deployment-membership-plane")], battery: { ...rootScript("mutate:system-deployment-membership-plane"), cost: "minutes" } },
  { id: "2", clause: "Promotion is fenced: a promoted or replacement writer takes a new epoch and the prior writer cannot write after fencing — demonstrated, not asserted", unit: "M02.4", checks: [rootScript("check:ordering-finality-recovery")], battery: { ...rootScript("mutate:ordering-finality-recovery"), cost: "minutes" } },
  { id: "3", clause: "Authority does not change: before and after failover the same grants authorize the same effects and nothing more (recovery without authority widening or owner-truth transfer)", unit: "M04.10", provenBy: "4" },
  { id: "4", clause: "Work is placed, not duplicated: typed role-to-membership assignments and allocation leases put work on a node; a partition produces reassignment under policy rather than two executions", unit: "M04.10 · M12.6", checks: [app("check:work-lifecycle-reservations")], absences: [absent("M12.6", "check:horizon-2-distributed-work", "typed role assignments, watermarks and coordination epochs across two failure domains")] },
  { id: "5", clause: "Ambiguous and duplicate effects reconcile rather than being retried into existence twice", unit: "M06.8 · M12.6", checks: [rootScript("check:recognized-effect-publication-order")], battery: { ...rootScript("mutate:recognized-effect-publication-order"), cost: "minutes" }, absences: [absent("M12.6", "check:horizon-2-distributed-work", "duplicate/ambiguous-effect reconciliation across two failure domains")] },
  { id: "6", clause: "Replay converges: the same admitted sequence replays to the same root on both domains", unit: "M06.4 · M12.6", checks: [rootScript("check:portable-evidence-replay")], battery: { ...rootScript("mutate:portable-evidence-replay"), cost: "minutes" }, absences: [absent("M12.6", "check:horizon-2-distributed-work", "replay to the same root on a SECOND domain")] },
  { id: "7", clause: "Drain and removal are lifecycle, not incident: a node leaves with its obligations discharged (the membership plane's drain/removal transition chains)", unit: "M02.3", provenBy: "1" },
  { id: "N1", negative: true, clause: "No AIIP appears anywhere in this journey: same-system distribution is native L0", unit: "M12.6", structural: (clauses) => { const labels = clauses.flatMap((c) => [...(c.checks ?? []), ...(Array.isArray(c.battery) ? c.battery : c.battery ? [c.battery] : [])].map((k) => k.label)); const aiip = labels.filter((l) => /aiip/iu.test(l)); return { ok: aiip.length === 0, detail: `${labels.length} composed commands, none an AIIP lane${aiip.length ? `: ${aiip.join(", ")}` : ""}` }; } },
  { id: "N2", negative: true, clause: "A single-node profile fails closed or restores under its declared proof contract rather than borrowing another profile's recovery", unit: "M09.4 · M02.4", checks: [rootScript("check:canonical-environment-backup"), app("check:backup-restore")] },
  { id: "E", clause: "Journey evidence: the Agentgres suite, the daemon suite and work items", unit: "M02 · M04", checks: [rootScript("check:work-items"), AGENTGRES_SUITE, DAEMON_SUITE] },
];

await runJourney({
  gate: "ACC-7",
  title: "continuity and useful distribution across nodes",
  doc: "internal-docs/implementation/acceptance/journey-07-continuity-and-distribution.md",
  clauses: CLAUSES,
});
