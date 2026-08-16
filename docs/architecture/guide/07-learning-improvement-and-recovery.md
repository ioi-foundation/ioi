# 07 — Learning, Improvement, And Recovery Under Bounds

Status: architecture guide chapter (non-owning synthesis).
Canonical owner: this file for the reading order and narrative sequencing of
institutional learning, bounded improvement, model substitution, and effect
recovery only; every subject is owned by the linked owner doc, which wins on
any point of substance.
Supersedes: none (originates no doctrine).
Superseded by: none.
Last alignment pass: 2026-08-16.
Doctrine status: canonical
Implementation status: mixed (narrative over built, partial, planned, and
speculative subjects; status truth lives in
[`canon-to-code-delta.md`](../_meta/canon-to-code-delta.md) and the
[`work-items/`](../_meta/work-items/) records)
Last implementation audit: 2026-08-16

An institution that cannot learn is a cost center; an institution that learns
without bounds is the failure mode this architecture exists to prevent. This
chapter is how the two are reconciled.

## What The Institution Keeps

The enterprise thesis, stated by its owner
[`institutional-learning-boundary.md`](../foundations/institutional-learning-boundary.md):

> Foundation models are replaceable cognition supply. The institution's
> ontology, memory, corrections, evaluations, workflows, evidence, policies,
> lineage, and eligible derived capability are durable institutional
> intelligence governed by the institution's declared boundary.

`InstitutionalLearningBoundaryProfile` is the versioned, machine-readable
contract behind that promise. It compiles source rights, data-view policy,
model-route rights, custody, training eligibility, retention, export, and
revocation into one fail-closed decision context — a cross-cutting policy
compilation over the existing owners, never a new runtime, truth store, or
authority plane. The narrowing path runs organization default → project →
bounded-system revision → immutable run snapshot; a child may narrow but never
silently widen a parent, and the effective permission is always the most
restrictive intersection. Missing, expired, or conflicting rights deny the
disputed use. Creation inside the boundary establishes no right to train on,
distill, publish, or transfer the material — source rights precede learning
rights, and inference permission never implies improvement rights.

Provider secondary use and cross-tenant learning are denied by default.
`Standard` may use disclosed, policy-qualified provider-trust routes;
`Private` requires custody-proven containment for protected plaintext (owner:
[`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md)).
A receipt proves an IOI-admitted crossing or a blocked attempt — never a
provider's hidden internal behavior. And moving parameters, gradients, or
distillates of protected material across a sovereign boundary is a
**declassification event** requiring resolved rights and receipts, because a
weight delta, unlike a work product, carries no lineage that could ever be
attributed, revoked, or adjudicated afterward.

## Where Memory Lives

`MemorySpace` is portable vault truth; `MemoryProjection` is the filtered
harness/model/worker view; adapter-local memory is cache rather than the
institution's brain. Durable, behavior-affecting memory crosses into Agentgres
through admitted context mutations with policy, authority, and receipts —
which is what keeps a persistent agent portable across model routes,
harnesses, and deployments. Owners:
[`portable-memory-vault.md`](../components/daemon-runtime/portable-memory-vault.md),
[`doctrine.md`](../components/agentgres/doctrine.md).

## Improvement Without Self-Escalation

Improvement is proposal-driven, and the invariant that carries the whole plane
is owned by
[`bounded-recursive-improvement.md`](../foundations/bounded-recursive-improvement.md):

> Improvement evidence never self-promotes.

A bounded one-shot change moves directly from eligible evidence and evaluation
to an `UpgradeProposal` decided by the target owner's ordinary governance.
Adaptive search, repeated sealed evaluation, multiple epochs, candidate
archives, or any qualified recursive-improvement claim instead binds an
optional `ImprovementCampaign`, which separates three logical trust functions:
**Search** proposes and executes candidates but cannot redefine the active
evaluation regime; **Judgment** evaluates under a frozen `EvaluationEpoch`,
metering sealed exposure, but cannot mutate or activate the candidate;
**Authority** admits and activates but cannot fabricate evidence. Budgets,
statistical risk, exposure, and learning rights are inherited ceilings that
never reset down the chain, and a candidate can never control the evaluator,
meter, promotion authority, or recovery path that would make it canonical.
What evidence may enter any of this is gated per subject by
`LearningEvidenceEligibility`; Foundry builds candidates from individually
eligible evidence only, Evaluations owns judgment validity, and Governance
owns promotion, rollback, recall, and containment.

## Replaceable Cognition, For Real

Model neutrality is credible only when tested. Every enterprise profile
defines a **Model Independence Test**: baseline on Model A; hard-disable it
along with provider-native thread state and hidden memory; mount a
policy-qualified Model B through the same contracts; restore only
institution-controlled, rights-eligible state; rerun the declared evaluations
and publish the delta and verdict. Passing proves bounded operational
continuity above the declared threshold — not that all models are equivalent.
Owner:
[`institutional-learning-boundary.md`](../foundations/institutional-learning-boundary.md).

## Recovery Is Typed, Everywhere

Chapter 02 introduced the recovery postures for one effect; they generalize to
everything this chapter touches. Ambiguous external effects reconcile before
retry; compensation is a separately authorized action with its own receipts;
restore is never reconciliation; revocation is transitive operational state,
not historical erasure — and no deletion record by itself proves a trained
model forgot anything. For embodied systems the same honesty is physical: the
slower mission/governance plane proposes bounded envelopes while deterministic
motion and an independent runtime-assurance stratum hold the final local veto
— model output is never an actuator command, safety heartbeat, or
emergency-stop authority. Owners:
[`invariants.md`](../foundations/invariants.md),
[`physical-action-safety.md`](../foundations/physical-action-safety.md),
[`embodied-runtime.md`](../components/daemon-runtime/embodied-runtime.md).

## Owners For This Chapter

- [`institutional-learning-boundary.md`](../foundations/institutional-learning-boundary.md)
  — the learning boundary, portability, and model independence.
- [`bounded-recursive-improvement.md`](../foundations/bounded-recursive-improvement.md)
  — campaigns, epochs, exposure, and the claim ladder.
- [`portable-memory-vault.md`](../components/daemon-runtime/portable-memory-vault.md)
  — MemorySpace and projections.
- [`foundry.md`](../components/hypervisor/foundry.md),
  [`evaluations.md`](../components/hypervisor/evaluations.md),
  [`improvement.md`](../components/hypervisor/improvement.md) — the builder,
  judge, and cockpit surfaces.
- [`physical-action-safety.md`](../foundations/physical-action-safety.md) —
  the physical recovery and veto boundary.
