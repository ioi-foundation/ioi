#!/usr/bin/env node
// ACC-2 · a bounded system is constituted and governed — the composed journey runner.
//
// A clause table over scripts/lib/acceptance-journey.mjs (see that file for the postures). Every
// ACC-2 clause names the existing done-bar that proves it, executed sequentially on ONE basis, or
// the unit that still owes the proof as a TYPED ABSENCE.
//
//   node scripts/check-acceptance-bounded-system-genesis.mjs
//   node scripts/check-acceptance-bounded-system-genesis.mjs --mutation-batteries
//   node scripts/check-acceptance-bounded-system-genesis.mjs --mutation
//   node scripts/check-acceptance-bounded-system-genesis.mjs --evidence <out.json>

import { runJourney, rootScript, node, cargoTest, bounded } from "./lib/acceptance-journey.mjs";

const DAEMON_SUITE = bounded(cargoTest("ioi-node", ["--bin", "hypervisor-daemon"]), 90);
const AGENTGRES_SUITE = bounded(cargoTest("agentgres"), 60);
// The sequence-zero lane boots a real single-validator cluster (Solo profile) and runs the M1.5
// named-continuity journey: genesis admitted once, constitutional amendment (M1.5c ELIGIBILITY /
// PROTECTED CLAUSE / MACHINE FLOOR / WRONG SCOPE / AMEND / REPLAY), succession, migration ack,
// dissolution ladder. It is the executable behind clauses 1, 3 and 4.
const SEQUENCE_ZERO = bounded(node("apps/hypervisor/scripts/verify-hypervisor-system-sequence-zero-materialization.mjs"), 120);
const absent = (unit, check, what) => ({ what: `${what} — ${check} (${unit}) is To be authored`, owner: unit });

const CLAUSES = [
  { id: "1", clause: "Genesis is admitted, once: a manifest compiles through genesis into one system_id with sequence-zero materialization; a replay of genesis is refused and the refusal is receipted", unit: "M02.1", checks: [rootScript("test:system-genesis-compiler"), SEQUENCE_ZERO] },
  { id: "2", clause: "The constitution decides: a transition the constitution forbids is refused because the constitution says so, proven by mutating the constitution and watching the decision change", unit: "M02.2", checks: [rootScript("check:constitutional-oracle-plane")], battery: { ...rootScript("mutate:constitutional-oracle-plane"), cost: "minutes" } },
  { id: "3", clause: "A protected amendment executes: proposal → protected transition → amendment execution → new effective constitution, with the prior revision preserved and addressable (the lane's M1.5c PROTECTED CLAUSE, AMEND and REPLAY assertions)", unit: "M02.1 · M02.2", provenBy: "1" },
  { id: "4", clause: "Named continuity is a record, not an inference: succession, migration and dissolution each produce a disposition record (the lane's M1.5d assertions)", unit: "M02.1", provenBy: "1" },
  { id: "5", clause: "An external fact enters through a declared oracle/evidence profile or it does not enter (the system_oracle population: exact scopes, signer substitution refused, contradiction fails closed, stale evidence never admitted)", unit: "M02.2", provenBy: "2" },
  { id: "6", clause: "Enrollment is declared and revocable: the system states its tier and remains fully operable at ioi_compatible with no L1, fee, token or IOI assurance dependency", unit: "M02.5", checks: [bounded(rootScript("check:network-enrollment-continuity-plane"), 180)], battery: { ...rootScript("mutate:network-enrollment-continuity-plane"), cost: "minutes" } },
  { id: "7", clause: "Systems renders it and owns none of it: the projection shows identity, constitution, lifecycle and desired-versus-observed topology, and mutating through the projection is impossible", unit: "M02.3 · M08.9", checks: [rootScript("check:system-deployment-membership-plane")], battery: { ...rootScript("mutate:system-deployment-membership-plane"), cost: "minutes" }, absences: [absent("M08.9", "check:systems-work-projections", "the Systems projection's truth-owner nonmutation proof (desired-versus-observed is proven by the membership plane; that the projection cannot mutate is not)")] },
  { id: "N1", negative: true, clause: "Adding a node does not widen authority or change finality (membership admission structurally refuses writer authority; writer promotion is its own fenced family)", unit: "M02.3", provenBy: "7" },
  { id: "N2", negative: true, clause: "A narrower run-scoped policy cannot widen an admitted system revision", unit: "M02.2", absences: [{ what: "no named test proves that a run-scoped policy cannot widen an admitted system revision: system_policy_routes.rs carries no widening assertion (measured 2026-09-14, zero hits for widen/narrower/run-scoped) — the module owner lists ACC-2 as closed by M02.1/M02.2/M02.5, so this is a journey-only remainder owned by M02.2", owner: "M02.2 (remainder, register R-138)" }] },
  { id: "E", clause: "Journey evidence: work items, the Agentgres suite and the daemon suite", unit: "M02", checks: [rootScript("check:work-items"), AGENTGRES_SUITE, DAEMON_SUITE] },
];

await runJourney({
  gate: "ACC-2",
  title: "a bounded system is constituted and governed",
  doc: "internal-docs/implementation/acceptance/journey-02-bounded-system-genesis.md",
  clauses: CLAUSES,
});
