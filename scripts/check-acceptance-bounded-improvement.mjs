#!/usr/bin/env node
// ACC-12 · improvement is proposed, judged, and never self-promoting — the composed runner.
//
// A clause table over scripts/lib/acceptance-journey.mjs. What exists today: the apply-time
// governance gates (a high-impact learned improvement cannot apply without a fresh simulation, an
// approved ApprovalRequest and an open ReleaseControl), what-if simulation replay, the compiled
// learning boundary and the registered Foundry contracts. The governance spine's five objects,
// role separation, the evaluation plane, the construction cycle and collective qualification are
// TYPED ABSENCES owned by M10.1 / M10.2 / M10.4 / M10.8 / M10.9.
//
//   node scripts/check-acceptance-bounded-improvement.mjs [--mutation-batteries] [--mutation] [--evidence <out.json>]

import { runJourney, app, rootScript, cargoTest, bounded } from "./lib/acceptance-journey.mjs";

const DAEMON_SUITE = bounded(cargoTest("ioi-node", ["--bin", "hypervisor-daemon"]), 90);
const absent = (unit, check, what) => ({ what: `${what} — ${check} (${unit}) is To be authored`, owner: unit });
// The two improvement verifiers the units cite (verify-hypervisor-improvement-governance-gates.mjs,
// verify-hypervisor-improvement-simulation-replay.mjs) default to the SHARED development daemon at
// 127.0.0.1:8765 plus a served shell at :4173, need an operator session token in
// IOI_HYPERVISOR_DAEMON_SESSION and drive Playwright, and neither is registered as an npm script
// (measured 2026-09-14, R-137). They are not isolated and are therefore NOT composed here — a red
// from "no daemon at :8765" would misattribute the clause. M10.1 owes the isolated wrapper.
const NOT_ISOLATED = "the cited verifier targets the shared daemon at 127.0.0.1:8765 and a served shell at :4173 with an operator session token and Playwright; it is not isolated and is not composed";

const CLAUSES = [
  { id: "1", clause: "The direct path still works: a one-shot bounded change goes through UpgradeProposal with no campaign anywhere near it (the apply-time gates: simulation, approval, release control)", unit: "M10.1", absences: [{ what: `verify-hypervisor-improvement-governance-gates.mjs — ${NOT_ISOLATED}`, owner: "M10.1 (isolated wrapper owed by check:improvement-governance-spine)" }, absent("M10.1", "check:improvement-governance-spine", "the immutable owner-scoped ImprovementGovernanceProfile / Agenda / Campaign / EvaluationEpoch / exposure-ledger / order-cutoff objects — none of the five is registered, typed or routed")] },
  { id: "2", clause: "Search cannot redefine the epoch: the order-0 epoch is frozen before search begins and an attempt to change it from inside search is refused", unit: "M10.2", absences: [absent("M10.2", "check:improvement-role-separation", "the frozen EvaluationEpoch to mutate does not exist (M10.1)")] },
  { id: "3", clause: "Judgment cannot mutate or activate the candidate: the evaluator's only output is a judgment; a planted activation call from the evaluator is caught", unit: "M10.2", absences: [absent("M10.2", "check:improvement-role-separation", "the judge-role mutation")] },
  { id: "4", clause: "Authority cannot fabricate evidence: a promotion attempted without the exposure ledger's records is refused (today: without a fresh simulation, an approved ApprovalRequest and an open ReleaseControl)", unit: "M10.1 · M10.2", absences: [{ what: `the apply-time refusals live in verify-hypervisor-improvement-governance-gates.mjs — ${NOT_ISOLATED}`, owner: "M10.1" }, absent("M10.2", "check:improvement-role-separation", "the exposure-ledger half — the ledger object is M10.1's and does not exist")] },
  { id: "5", clause: "Selection produces eligibility only: the target owner's own governance, activation, monitoring and recovery path promotes, and the campaign owns no production mutation", unit: "M10.1", absences: [absent("M10.1", "check:improvement-governance-spine", "the campaign-owns-no-production-mutation proof; the campaign object does not exist")] },
  { id: "6", clause: "Negative and inconclusive results are retained and reproducible, and a candidate archive is not a promotion queue", unit: "M10.2 · M10.4", absences: [absent("M10.4", "check:governed-evaluation-plane", "EvalRun / result / scorecard execution — the suite plane is declaration-only by design and has no run endpoint")] },
  { id: "7", clause: "The learning boundary is the most restrictive intersection: source rights, consent, data views, boundary profile, custody posture, route rights, evidence eligibility, retention/export policy and jurisdiction; cross-tenant and provider secondary learning denied by default", unit: "M10.3", checks: [app("check:institutional-learning-boundary")], battery: { ...app("mutate:institutional-learning-boundary"), cost: "multi-hour" } },
  { id: "8", clause: "Permission does not travel: eligibility for one target does not extend to a policy, evaluator, Agenda, workflow or cross-tenant service", unit: "M10.3", provenBy: "7" },
  { id: "9", clause: "Model-swap continuity is measured: institutional state and evals survive a provider's removal, or model-neutral routing is not claimed", unit: "M10.4", absences: [absent("M10.4", "check:governed-evaluation-plane", "the provider-removal continuity contract with a declared equivalence envelope — zero lines exist")] },
  { id: "10", clause: "Optimization is a subordinate receipted cycle: each CapabilityConstructionCycle freezes target owner, baseline, component snapshot, policies, budgets and stop rule; preserves parented trials; turns a finding into a new candidate", unit: "M10.8", absences: [absent("M10.8", "check:capability-construction-cycle", "CapabilityConstructionCycleEnvelope and OptimizationTargetAdapter have zero artifacts and no accepted tracked decision")] },
  { id: "11", clause: "Campaign and GoalRun refs are conditional: a campaign-coordinated cycle binds its frozen EvaluationEpoch; an ordinary bounded cycle may leave them null while still binding the released evaluation contract", unit: "M10.8", absences: [absent("M10.8", "check:capability-construction-cycle", "the conditional-ref rule")] },
  { id: "12", clause: "Mounted cognition is replaceable: optimizer_ref is a worker, conductor or runtime actor; changing the model behind it cannot rewrite target, evidence, authority, budget or evaluator identity", unit: "M10.8", absences: [absent("M10.8", "check:capability-construction-cycle", "mounted-cognition substitution")] },
  { id: "13", clause: "Collective machinery earns its complexity: a frozen epoch compares the exact collective composition against a matched cheaper baseline under declared estimands with the full knockout matrix", unit: "M10.9", absences: [absent("M10.9", "check:collective-controller-qualification", "matched baseline, estimand and knockout matrix — zero lines exist")] },
  { id: "N1", negative: true, clause: "No Foundry surface claims a family whose wire contract is unregistered", unit: "M10.5", checks: [app("check:foundry-spec-contracts")] },
  { id: "N2", negative: true, clause: "No performance claim ships without its complete model/recipe/software/hardware/topology fingerprint set and time-to-quality evidence", unit: "M10.5", provenBy: "N1" },
  { id: "N3", negative: true, clause: "No optimizer evaluates, promotes, activates, publishes or authorizes its own output; no failed/inconclusive trial disappears; an exhausted cycle ends as honest bounded non-success", unit: "M10.8", absences: [absent("M10.8", "check:capability-construction-cycle", "the optimizer negatives")] },
  { id: "N4", negative: true, clause: "No participant count, unmatched aggregate score, active ArtifactRef or surviving process qualifies Collective mode or persistent authority", unit: "M10.9", absences: [absent("M10.9", "check:collective-controller-qualification", "the qualification negatives")] },
  { id: "E", clause: "Journey evidence: architecture contracts and docs, work items, the daemon suite", unit: "M10 · M12.5", checks: [rootScript("check:architecture-contracts"), rootScript("check:architecture-docs"), rootScript("check:work-items"), DAEMON_SUITE], absences: [{ what: `verify-hypervisor-improvement-simulation-replay.mjs (M12.5's partial evidence) — ${NOT_ISOLATED}`, owner: "M12.5 / M10.1" }] },
];

await runJourney({
  gate: "ACC-12",
  title: "improvement is proposed, judged, and never self-promoting",
  doc: "internal-docs/implementation/acceptance/journey-12-bounded-improvement.md",
  clauses: CLAUSES,
});
