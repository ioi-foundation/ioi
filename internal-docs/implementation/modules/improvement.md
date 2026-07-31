---
module_id: improvement
module_class: method
title: Bounded improvement
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M8]
canon_owners:
  - docs/architecture/foundations/bounded-recursive-improvement.md
  - docs/architecture/components/hypervisor/improvement.md
  - docs/architecture/components/hypervisor/evaluations.md
  - docs/architecture/components/hypervisor/foundry.md
  - docs/architecture/components/daemon-runtime/improvement-governance-gates.md
  - docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md
  - docs/architecture/components/hypervisor/core-clients-surfaces.md
  - docs/conformance/hypervisor-core/work-lifecycle.md
  - docs/decisions/0018-bounded-recursive-improvement-campaign-taxonomy.md
---

# Bounded Improvement

## What this module owns

The reusable method for making something in a System improvable without letting the search process
judge, promote, or re-scope itself: target and order discipline, claim discipline, the distribution
of improvement duties across owner applications, and the conditions under which higher-order work
stays inactive. It is a method only — it orders no work, carries no status, and is never a
sequencer; sequencing lives in [`sequence.v1.json`](../program/sequence.v1.json), status in the
work-item record.

## Pulled by

[`sequence.v1.json`](../program/sequence.v1.json) declares one binding for module id `improvement`:
**M8**, alongside `learning-boundary`, `supply-and-commerce`, and `campaign-experiment-method`.
Experiment freezing, evaluator-integrity mechanics, and the fault battery belong to
[`campaign-experiment-method.md`](./campaign-experiment-method.md) and are not repeated here. The M9
and M13+ horizons below stay in scope as maturity horizons, but the sequencer records no
`improvement` binding at those stages; the stage that takes a horizon binds it in `sequence.v1.json`
first.

## Canon owners

| Canon owner | What it governs here |
| --- | --- |
| [`foundations/bounded-recursive-improvement.md`](../../../docs/architecture/foundations/bounded-recursive-improvement.md) | Campaign admission and lifecycle, improvement orders and finite recursion, epochs and exposure, cross-order synchronization, learning eligibility, promotion and effect recovery, the evidence-claim ladder, required invariants, non-claims, and the conformance gate. |
| [`components/hypervisor/improvement.md`](../../../docs/architecture/components/hypervisor/improvement.md) | Improvement as campaign cockpit: agenda, campaign, target/order graph, candidate archive, cutoff timeline, upgrade handoff, product surface shape, and claim language. |
| [`components/hypervisor/evaluations.md`](../../../docs/architecture/components/hypervisor/evaluations.md) | Evaluations duty: epoch freeze, suites, custody, exposure, judgment, evaluator validity, challenge, re-verification, and export. |
| [`components/hypervisor/foundry.md`](../../../docs/architecture/components/hypervisor/foundry.md) | Foundry duty: candidate and evaluator asset construction, admitted experimental jobs, scorecards, archives, reproduction, and promotion-bundle assembly. |
| [`daemon-runtime/improvement-governance-gates.md`](../../../docs/architecture/components/daemon-runtime/improvement-governance-gates.md) | Governance duty: admission and protected-target decisions, exact target-base and conflict checks, impact classification, budgets, approval and release control, canary, cohort, stop, rollback, recall, and escalation. |
| [`daemon-runtime/events-receipts-delivery-bundles.md`](../../../docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md) | Provenance duty: receipts, checkpointing, and delivery-bundle shape carrying ancestry, attempts, eligibility, cutoffs, decisions, disputes, and claims. |
| [`conformance/hypervisor-core/work-lifecycle.md`](../../../docs/conformance/hypervisor-core/work-lifecycle.md) | Work duty: coordinating and child runs, sessions, reviews, queues, incidents, exact-head transition replay, cancellation fanout, and archive continuity. |
| [`components/hypervisor/core-clients-surfaces.md`](../../../docs/architecture/components/hypervisor/core-clients-surfaces.md) | Surface registration and role-scoped placement for the Improvement, Evaluations, Foundry, Governance, Work, Provenance, Systems, and Packages projections. |
| [`ADR 0018`](../../../docs/decisions/0018-bounded-recursive-improvement-campaign-taxonomy.md) | The accepted campaign taxonomy and the decision that claim artifacts grant no authority. |

## Retained obligations

- **Distributed owners.** Improvement truth is never centralized in one application. Bounded
  recursive improvement owns meaning; Improvement, Evaluations, Foundry, Governance, Work, and
  Provenance each hold the duty named above. A work item pulling this module names every owner it
  crosses and never relocates one owner's duty into another.
- **Horizon 1 — order-zero Campaign (M8).** The first useful proof is a single-System,
  target-order-0 software or pursuit-method Campaign: immutable governance profile, revisioned
  agenda, finite campaign, exact target base, frozen `EvaluationEpoch`, append-only exposure ledger,
  order cutoff, and evidence claim, with Search, Judgment, and Authority separately identified and
  only a target-owner `UpgradeProposal` emitted. The lightweight direct one-shot path is preserved
  for work needing no Campaign; a Campaign is optional target domain state, not a mandatory wrapper.
- **Horizon 2 — product integration (M9).** Improvement becomes legible without becoming ambient
  power: the dedicated route stays inside the existing Applications catalog, adds no application or
  permanent rail item, and ships no universal self-improve control. Every displayed claim binds
  baseline, target/order path, generations, fixed budgets and environments, model/tool/profile
  versions, epoch, exposure posture, accepted and rejected attempts, evaluator changes, statistical
  method, transfer tier, reproduction posture, complexity, monitorability, recovery posture, and
  limitations; partial, disputed, downgraded, and absent claims render honestly.
- **Horizon 3 — optional higher-order research (M13+).** Higher orders, multi-node execution,
  multi-party evaluation, public claims, and embodied targets are separate assurance escalations,
  not implicit properties of the first slice. Higher-order and recursive-seat work remains inactive
  until the order-0 Campaign and the target-owner proposal handoff pass.
- **Order and claim discipline.** `target_improvement_order` is a path-relative semantic rank
  against a frozen, version-unrolled target graph — not process nesting, not a permanent component
  property, not proof of recursion. Target order, pursuit-method order, target generation, candidate
  generation, active nesting depth, transfer tier, and claim class stay orthogonal and are never
  substituted for one another. Budgets, deadlines, authority, statistical risk, exposure, and
  learning rights are inherited ceilings that narrow or hold down the ancestor chain, never
  resetting on a new order, branch, or candidate. Claim strength never exceeds the frozen
  methodology, transfer, reproduction, independence, and still-valid evaluator evidence; a later
  looser definition never upgrades earlier evidence.
- **Cross-order synchronization.** Orders synchronize through immutable evidence cutoffs, not
  live-state merging: one adjacent target-order edge per cutoff, no same-wave descendant validating
  its own ancestor patch, eligibility decided under source rights and learning policy, and patches
  applying only to future cohorts and immutable successor revisions.
- **Reference detail.** The preserved discovery plan supplies the statistical, evaluator-integrity,
  multi-order, and adversarial experiment detail behind this method; its exact body, SHA-256
  `8b632560b22198636a40f2097523e5b5ec4297718dd2260a5dcffaea0451ecea`, is retained at
  [`_archive/pre-unification-baseline/…-discovery-plan.md`](../_archive/pre-unification-baseline/bounded-recursive-improvement-campaign-discovery-plan.md).
  It schedules no phases of its own, activates nothing, and owns no doctrine.
- **Nonclaims this method carries.** Pulling it establishes no end-to-end Campaign implementation,
  no recursive self-improvement, no ignition or inflection, no monotonic or perpetual gain, no
  evaluator truth, no elimination of Goodharting, no model-internal alignment result, and no
  guaranteed recovery from irreversible effects. Campaign coordination grants no wallet authority;
  candidate selection creates proposal eligibility only.

## Applying it in a work item

- Name the target, its incumbent base identity, the target-order path against the frozen target
  graph, the protected boundaries held outside campaign authority, and the inherited ceilings the
  item may spend.
- Bind each crossed owner duty to its canon path in the record's canon refs, covering whichever of
  Improvement, Evaluations, Foundry, Governance, Work, and Provenance the item touches.
- Declare the intended `ImprovementEvidenceClaim` class before observation and carry the evidence
  bounding it: reproduced selection against the unchanged epoch, retained negative and inconclusive
  results, exposure-ledger and cutoff refs.
- Record the handoff explicitly — `UpgradeProposal` ref, the governance path admitting or refusing
  it, and the canary, rollback, recall, and effect-recovery route — with no self-promotion path
  anywhere.
- Carry the preserved one-shot path as a proven alternative, evidencing that work needing no
  Campaign is not forced through one.
- State nonclaims explicitly, including that no higher-order or recursive-seat capability is claimed
  and that order-zero evidence closes no higher horizon.

## Terminal evidence

The method's contribution closes when retained evidence shows, for the declared target: a frozen
campaign, epoch, exposure, and cutoff set the candidate could not mutate; reproduced selection
against the unchanged epoch; retained negative, invalid, and challenged results; a target-owner
proposal the owner's ordinary governance path accepted or refused with receipts; a demonstrated
rollback, recall, or effect-recovery route; and a claim artifact no stronger than that evidence
wherever projected. The literal exit and its binding record belong to the stage's work items, not to
this module.

## Canon gaps

- `ignition_evidence` and `inflection_evidence` are defined by reference to "a separately defined
  recursive-seat portfolio" and "a separately defined methodology" that no canon file defines, so
  work reaching Horizon 3 has no admissible criteria to bind. Owner to resolve:
  [`foundations/bounded-recursive-improvement.md`](../../../docs/architecture/foundations/bounded-recursive-improvement.md).
- The assurance escalation from an order-zero Campaign to higher orders, multi-node execution,
  multi-party evaluation, or public claims is named as separate but its entry criteria are unstated,
  leaving this module's inactivity condition without a testable release condition. Owners to resolve:
  the same foundation and
  [`ADR 0018`](../../../docs/decisions/0018-bounded-recursive-improvement-campaign-taxonomy.md).
