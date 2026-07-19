# ADR 0018: Adopt Bounded Recursive Improvement Campaigns Without An RSI Engine

- Status: Accepted
- Date: 2026-07-15
- Owners: bounded autonomous Systems / Hypervisor Improvement / Goal Kernel / Foundry / Evaluations / Governance / daemon runtime / Agentgres
- Refines: ADR 0010, ADR 0015, ADR 0016, and ADR 0017

## Context

IOI already had immutable GoalRunProfiles, durable GoalRuns, an Improvement
Proposal Plane, Foundry candidates and evaluations, target-owner governance,
release controls, receipts, and learning-boundary policy. Those parts could
support bounded improvement but did not identify the owner of a multi-epoch,
adaptive improvement program.

Without that distinction, several unsafe or overloaded interpretations remained
possible: making GoalRun the campaign database, turning a HarnessProfile into a
global self-rewriting harness, allowing an optimizer to redefine its own
evaluator, treating repeated holdout queries as free, or calling any successful
self-edit “recursive self-improvement.”

## Decision

IOI adopts **Bounded Recursive Improvement Campaign** as an optional domain
lifecycle for adaptive or multi-epoch capability improvement:

```text
ImprovementAgenda revision
  -> admitted ImprovementCampaign
       -> coordinating and child GoalRuns
       -> immutable candidates and Findings
       -> frozen EvaluationEpochs and exposure accounting
       -> order-cutoff, reproduction, and claim evidence
       -> UpgradeProposal
  -> target-owner decision, activation, monitoring, and recovery
```

The stable ownership split is:

| Primitive | Sole responsibility |
| --- | --- |
| `GoalRunProfile` | Reusable immutable pursuit method. |
| `GoalRun` | One admitted bounded pursuit and its live coordination. |
| `ImprovementCampaign` | Multi-epoch candidate, evaluation, cutoff, selection, promotion-lineage, and recovery-reference lifecycle. |
| `ImprovementAgenda` | Immutable-by-revision, non-executable portfolio of targets, hypotheses, falsifiers, and investigation priorities. |

An ImprovementCampaign is not mandatory. Ordinary bounded changes may proceed
from evidence through a typed successor patch and evaluation directly to an
`UpgradeProposal`. A Campaign is used when adaptive search, multiple epochs,
cumulative evaluation exposure, candidate archives, higher-order retargeting,
or qualified recursive-improvement claims require durable domain state.

Every Campaign binds one immutable `ImprovementGovernanceProfile`. The profile
owns mutable/protected target posture, order/depth/generation ceilings,
inherited resource/statistical/exposure reservation policy, evaluator
separation, stopping, promotion-authority, and effect-recovery requirements. A
System constitution protects its System-scoped binding; a non-System owner may
bind the same profile family without thereby creating a System or bounded-DAS
claim. The profile is policy, not Campaign state or authority.

Every Campaign separates Search, Judgment, and Authority as logical trust
functions. Search proposes candidates but cannot alter active evaluation truth,
the resource meter, authority, or release. Judgment evaluates under frozen
policy but cannot mutate or promote the candidate. Authority admits scope and
activates or recovers releases but cannot fabricate evidence. These functions
do not create new runtime planes; higher assurance requires proportionately
stronger independence.

Higher-order improvement is path-relative retargeting. Target improvement
order, pursuit-method order, target and candidate generation, active nesting
depth, transfer tier, and claim class remain distinct. Every admitted target
graph and active stack is finite and acyclic, with inherited resource,
statistical-risk, evaluation-exposure, authority, and learning-rights ceilings.
The architecture's ability to represent later sequential orders is not a claim
of infinite recursion or guaranteed gain.

Each EvaluationEpoch freezes its target/base, task distribution, evaluators,
visible/sealed/transfer suites, methodology, constraints, custody, and budgets.
Adaptive access spends append-only exposure and false-promotion budgets.
Candidate, evaluator, and campaign-controller changes are never co-promoted on
evidence they jointly redefined.

Orders exchange typed, learning-eligible evidence through immutable
`ImprovementOrderCutoffReceipt` lineage, not live-state merging. Each cutoff
moves evidence one adjacent order, prevents same-wave circular validation, and
can support only an owner-qualified successor proposal. Activated successors
apply to future cohorts; active runs and frozen epochs are never reinterpreted.

Campaign output remains subject to the target owner's ordinary path.
Constitutional, authority, shutdown, membership, and protected safety targets
use protected amendment paths. Activation binds monitoring and the appropriate
rollback, recall, containment, compensation, and irreversible-effect posture.

Improvement claims use an immutable evidence ladder:
`bounded_optimization`, `self_targeted_improvement`,
`net_positive_recursive_improvement`, `ignition_evidence`, and
`inflection_evidence`. Claim artifacts grant no authority and remain qualified
by their frozen methodology, target path, orders/generations, transfer tier,
budgets, evaluators, reproductions, limitations, and later validity records.

## Invariants

- Improvement evidence never self-promotes.
- A candidate cannot control its evaluator, resource meter, promotion
  authority, or recovery ancestor.
- Search cannot change the utility regime that selects its current generation.
- Protected bounds cannot be weakened by campaign success.
- Budgets, exposure, authority, and learning rights narrow or remain equal down
  the ancestor chain; changing candidate or order never resets them.
- A cutoff, selection, score, claim, consensus, payment, or receipt is not
  activation authority.
- Negative, exploit, disputed, and irreversible-effect evidence remains visible
  according to policy.
- Claim strength never exceeds the exact still-valid evidence and frozen
  methodology that support it.

## Rejected Alternatives

- A universal RSI engine, global meta-harness, recursive harness, or generic
  self-rewriting agent.
- Making every improvement an ImprovementCampaign or removing the direct
  UpgradeProposal path.
- Making GoalRunProfile, GoalRun, Foundry, Agentgres, or Hypervisor Improvement
  the owner of campaign domain state.
- Creating a new authority plane, truth store, runtime, L1 execution path, or
  mandatory product application for improvement.
- Mandating one search algorithm, Pareto implementation, statistical test, or
  scalar fitness function as architecture doctrine.
- Treating arbitrarily high representable order, one benchmark gain, or one
  self-targeted edit as demonstrated recursive improvement.

## Consequences

- IOI gains a durable owner for multi-epoch improvement without overloading the
  goal-pursuit, step-resolution, workflow, training, or upgrade primitives.
- Hypervisor Improvement becomes the Campaign cockpit while Foundry builds and
  evaluates, Governance activates, Provenance explains, and Work renders the
  underlying GoalRuns and execution.
- Evaluation exposure, false-promotion risk, evaluator validity, learning
  eligibility, negative knowledge, and effect recovery become first-class
  campaign concerns.
- Implementations must report partial support honestly. The canonical doctrine
  is accepted, but end-to-end Campaign conformance and recursive-improvement
  evidence remain planned until the required vertical proof gates pass.

## Canonical References

- `docs/architecture/foundations/bounded-recursive-improvement.md`
- `docs/architecture/foundations/common-objects-and-envelopes.md`
- `docs/architecture/foundations/governed-autonomous-systems.md`
- `docs/architecture/foundations/verifiable-bounded-agency.md`
- `docs/architecture/foundations/institutional-learning-boundary.md`
- `docs/architecture/components/daemon-runtime/improvement-governance-gates.md`
- `docs/architecture/components/hypervisor/foundry.md`
