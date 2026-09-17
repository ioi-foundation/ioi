#!/usr/bin/env node
// ACC-1 · the effect boundary holds — the composed journey runner.
//
// A clause table over scripts/lib/acceptance-journey.mjs: every ACC-1 clause names the existing
// done-bar that proves it, executed sequentially on ONE basis against each verifier's own real
// daemon with fixtures disabled, or names the unit that still owes the proof as a TYPED ABSENCE.
//
//   node scripts/check-acceptance-effect-boundary.mjs
//   node scripts/check-acceptance-effect-boundary.mjs --mutation-batteries   # + the source-planting batteries
//   node scripts/check-acceptance-effect-boundary.mjs --mutation             # self-drill
//   node scripts/check-acceptance-effect-boundary.mjs --evidence <out.json>

import fs from "node:fs";
import path from "node:path";
import { runJourney, app, rootScript, cargoTest, bounded, ROOT } from "./lib/acceptance-journey.mjs";

const DAEMON_SUITE = bounded(cargoTest("ioi-node", ["--bin", "hypervisor-daemon"]), 90);

// R-18 (register, 2026-09-08): `handle_cloud_job_execute` in cloud_job_routes.rs carries four
// discarded writes. It was the decentralized-cloud program's until 2026-09-17, when that product
// left this repository (R-182) — the handler and its module did NOT leave, so the finding is now
// this program's to close rather than to coordinate. CI isolates its two gates in a job nothing
// needs.
// R-136 (2026-09-14, MVP owner, owner-reversible): the same fence applies here — the two gates RUN,
// and a red that consists of EXACTLY that one handler / that one source file is fenced and does not
// hold the MVP gate (ADR 0053: the product track keeps its own release accounting). Any second
// handler or file un-fences the check, which is how this program found its own five discarded
// writes in environment_routes.rs and provider_routes.rs on 2026-09-14 and fixed them.
const R18_HANDLER = "handle_cloud_job_execute";
const R18_SOURCE = "crates/node/src/bin/hypervisor_daemon_routes/cloud_job_routes.rs";
const R18_REGISTRY = "docs/architecture/_meta/mutation-event-foundation-coverage.v1.json";
const r18Fence = (what, matches) => ({
  ruling: "R-18 fenced for the MVP by R-136 (2026-09-14, MVP owner); re-owned to this program by R-182 (2026-09-17) when decentralized.cloud left the repository and its handler did not",
  owner: "MVP finish-line program",
  what,
  holdsGate: false,
  matches,
});
const handlersFence = r18Fence(
  `the handler-classification delta is exactly [${R18_HANDLER}]`,
  ({ stdout }) => {
    const report = JSON.parse(stdout);
    const delta = report.registry_delta ?? {};
    return JSON.stringify(delta.in_source_but_absent_from_registry) === JSON.stringify([R18_HANDLER])
      && JSON.stringify(delta.in_registry_but_no_longer_present) === "[]";
  },
);
const foundationFence = r18Fence(
  `the discarded-write census differs from the registry in exactly one source file, ${path.basename(R18_SOURCE)}`,
  ({ stdout }) => {
    const report = JSON.parse(stdout);
    const registry = JSON.parse(fs.readFileSync(path.resolve(ROOT, R18_REGISTRY), "utf8"));
    const declared = registry.direct_persistence_indicator_census?.by_source ?? {};
    const found = {};
    for (const m of report.modules ?? []) if (m.discarded_direct_persist_results > 0) found[m.source] = m.discarded_direct_persist_results;
    const keys = new Set([...Object.keys(declared), ...Object.keys(found)]);
    const deltas = [...keys].filter((k) => (declared[k] ?? 0) !== (found[k] ?? 0));
    return deltas.length === 1 && deltas[0] === R18_SOURCE;
  },
);

const absent = (unit, check, what) => ({ what: `${what} — ${check} (${unit}) is To be authored`, owner: unit });

const CLAUSES = [
  { id: "1", clause: "Every execution path is guarded: the same typed guardrail decision and refusal shape apply to the mounted exec path, task runs, environment health/readiness, supervisor operations and provider operations", unit: "M01.1", checks: [app("check:command-execution-guardrails")] },
  { id: "2", clause: "Enforcement is declared, not inferred: the run emits an enforcement coverage declaration naming what ran, and a gap appears as a positive finding", unit: "M01.2", checks: [app("check:enforcement-coverage-producer")] },
  { id: "3", clause: "A tool call resolves a contract before it invokes; the contract's declared effect boundary is what is enforced", unit: "M01.3", checks: [app("check:runtime-tool-contract-admission")] },
  { id: "4", clause: "MCP is a transport: a tool arriving over MCP normalizes to the same contract; resources, prompts, elicitation, tasks and Apps normalize to their canonical owners or fail typed-unavailable", unit: "M01.4 · M01.10", checks: [app("check:mcp-transport-normalization")], absences: [absent("M01.10", "check:mcp-non-tool-normalization", "the non-tool primitives (resource → leased view/artifact/memory projection, prompt → untrusted import, elicitation → typed input, task → HarnessInvocation handle, App → sandboxed extension surface) positive paths and native equivalence; today all fourteen routes are mounted on the typed-unavailable refusal")] },
  { id: "5", clause: "The session chain is one chain: recipe → binding → launch → spawn → readiness → terminal attach admitted as a unit, no orphaned host process and no unreceipted attach on partial failure", unit: "M01.5", checks: [app("check:launch-chain")] },
  { id: "6", clause: "A 2xx without its durable effect and receipt is a failure, asserted by counting the artifact", unit: "M01.6", checks: [app("check:governed-effect-assurance-floor")] },
  { id: "7", clause: "Proposal provenance is resolved, not asserted: the final invoker consumes an opaque daemon-issued proposal record bound to principal, request, resource, freshness and nonce", unit: "M01.8", checks: [app("check:provider-proposal-provenance")] },
  { id: "8", clause: "The outward gateway is least privilege: one immutable versioned HypervisorMCPGatewayProfile binds subject, key, origin, use, refs, exposure hash, privacy, budget, rate, expiry, revocation and receipt obligations", unit: "M01.11", absences: [absent("M01.11", "check:hypervisor-mcp-gateway-profile", "register/issue/admit/narrow/revoke of the v2 profile kinds and native-versus-MCP admission parity; today both gateway routes refuse typed-unavailable and no schema is registered")] },
  { id: "N1", negative: true, clause: "A second admission path planted in the daemon's own source is refused", unit: "M03.4", checks: [app("check:ontology-admission-census")], battery: { ...app("mutate:ontology-admission-census"), cost: "minutes" } },
  { id: "N2", negative: true, clause: "A request with no principal does not acquire one", unit: "M01 · admission evidence", checks: [rootScript("check:admission-evidence")] },
  { id: "N3", negative: true, clause: "A refusal is paired with a count of the durable thing it must not have produced", unit: "M01.6", provenBy: "6" },
  { id: "N4", negative: true, clause: "An inline proposal carrying the expected daemon-source literal, a replayed proposal ref and a cross-principal substituted ref are each refused before provider or credential use", unit: "M01.8", provenBy: "7" },
  { id: "N5", negative: true, clause: "A resource URI cannot grant access, a prompt cannot become trusted instruction, elicitation cannot approve, an MCP task cannot become GoalRun or receipt identity, an App cannot acquire host/runtime truth", unit: "M01.10", absences: [absent("M01.10", "check:mcp-non-tool-normalization", "the five non-tool negative mutations")] },
  { id: "N6", negative: true, clause: "Missing, unknown, cross-kind, unauthenticated, candidate-key/origin/basis, budget/rate/expiry, upstream-state and widened-successor gateway mutations refuse; no profile exposes a master surface, ambient context, raw secret or cross-tenant capability", unit: "M01.11", absences: [absent("M01.11", "check:hypervisor-mcp-gateway-profile", "the gateway mutation matrix")] },
  { id: "E1", clause: "Journey evidence: mutation-event coverage of every daemon handler (both gates run; an R-18-only red is fenced and printed, never hidden)", unit: "M01 · R-18 fence", checks: [{ ...rootScript("check:mutation-foundation"), fence: foundationFence }, { ...rootScript("check:mutation-handlers"), fence: handlersFence }] },
  { id: "E2", clause: "Journey evidence: the daemon's own test suite", unit: "M01", checks: [DAEMON_SUITE] },
];

await runJourney({
  gate: "ACC-1",
  title: "the effect boundary holds",
  doc: "internal-docs/implementation/acceptance/journey-01-effect-boundary.md",
  clauses: CLAUSES,
});
