---
module_id: supply-and-commerce
module_class: method
title: Model-neutral supply and commercial truth
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M8, M14]
legacy_id: WP-SUPPLY
canon_owners:
  - docs/architecture/components/model-router/doctrine.md
  - docs/architecture/components/model-router/api-byok-mounting.md
  - docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md
  - docs/architecture/domains/ioi-ai/control-plane.md
  - docs/architecture/components/hypervisor/identity-access-and-metering.md
  - docs/architecture/components/hypervisor/providers-and-environments.md
  - docs/architecture/foundations/institutional-learning-boundary.md
  - docs/architecture/domains/marketplace-neutrality.md
  - docs/architecture/domains/sas/service-marketplace.md
  - docs/conformance/hypervisor-core/managed-work-billing.md
---

# Model-Neutral Supply And Commercial Truth

## What this module owns

The reusable method for sourcing cognition and compute under a resolved rights
contract, and for stating commercial truth about what that supply costs and what
a customer is sold: portfolio posture, the routing-policy-versus-product
distinction, the bidirectional rights contract every candidate resolves, the
separation of Work Credits from money-like instruments, and the evidence bar a
recurring allowance clears before commercialization. It is a method only — it
never orders work, never carries status, and is never a sequencer.

## Pulled by

[`sequence.v1.json`](../program/sequence.v1.json) binds this module to **M8**
(Enterprise Learning And Bounded Improvement — provider-exit proof) and **M14**
(Connected/Secured Services And Demand-Gated L1 — public economics) via
`modules[].applies_to_stages`. No other binding exists here; the retiring
source's further touch points sit under [Canon gaps](#canon-gaps).

## Canon owners

| Canon owner | What it governs here |
| --- | --- |
| [`model-router/doctrine.md`](../../../docs/architecture/components/model-router/doctrine.md) | Routing-policy semantics, supply portfolio, aggregator posture, named-human-seat prohibition, `ModelRouteRightsContract` shape and fail-closed rules |
| [`model-router/api-byok-mounting.md`](../../../docs/architecture/components/model-router/api-byok-mounting.md) | Wire shape for route-rights, commercial posture, credential principal, mount mode, BYOK/BYOA brokering |
| [`economic-flywheel-and-pricing-boundaries.md`](../../../docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md) | Work Credit semantics, fee-basis legitimacy, pricing/settlement boundaries, allowance-commercialization preconditions, margin thesis |
| [`ioi-ai/control-plane.md`](../../../docs/architecture/domains/ioi-ai/control-plane.md) | The single Goal Space subscription, its bounded Work Credit grant, separately funded Network/Open budgets |
| [`identity-access-and-metering.md`](../../../docs/architecture/components/hypervisor/identity-access-and-metering.md) | Deployment-local meter, budget enforcement, receipt-derived usage, debit reconciliation duties |
| [`providers-and-environments.md`](../../../docs/architecture/components/hypervisor/providers-and-environments.md) | Provider and environment integration posture behind any supply choice |
| [`institutional-learning-boundary.md`](../../../docs/architecture/foundations/institutional-learning-boundary.md) | Learning ownership, portability, and model independence that make provider substitution possible |
| [`marketplace-neutrality.md`](../../../docs/architecture/domains/marketplace-neutrality.md) | Routing/marketplace neutrality, contribution accounting, fee legitimacy for procured supply |
| [`sas/service-marketplace.md`](../../../docs/architecture/domains/sas/service-marketplace.md) | Service orders as a separately funded commercial vehicle for externally procured work |
| [`managed-work-billing.md`](../../../docs/conformance/hypervisor-core/managed-work-billing.md) | Conformance semantics for the managed-work ledger bundle a commercial claim must satisfy |

## Retained obligations

- **Product shape.** Sell one Goal Space subscription covering conductor,
  durable goal state, memory, policy, collaboration, receipts, replay, support,
  and a bounded grant of non-transferable Work Credits.
- **Policies are not products.** Treat `Auto`/1-of-N, `Pinned`, and
  `Compare`/N-of-N as routing policies rather than node products or subscription
  identities; a fallback that changes route does not change what was sold.
- **No borrowed seats.** Never pool, browser-automate, share, or resell
  named-human model workspace subscriptions as production worker capacity
  without an agreement that explicitly permits the exact use.
- **Portfolio sourcing.** Source managed cognition from direct APIs,
  negotiated/dedicated capacity, open/self-hosted weights, customer BYOK/BYOA,
  and explicitly permitted OEM/reseller paths; use aggregators as replaceable
  breadth/overflow adapters, never as sole inference authority or business model.
- **Bidirectional rights.** Resolve a versioned bidirectional rights contract
  per provider/model candidate, covering access, automation, downstream use,
  credential principal, privacy/retention, region, fallback, price, parameters,
  provider use of customer material, and customer use of outputs. The two
  directions are independent; unresolved members fail closed for the purpose.
- **Credit separation.** Keep managed Work Credits separate from provider
  tokens, cash, payouts, bonds, settlement assets, and any IOI native asset.
- **Contributor funding.** Fund Network/Open contributors from a separate goal
  budget, bounty, procurement cap, or service order — never by silently draining
  an included managed-work allowance.
- **Commercialization bar.** Commercialize a recurring allowance only after
  route-attempt telemetry, supplier/broker cost, IOI fee basis, adjustments,
  overage consent, provider-statement reconciliation, p50/p90/p95 COGS, fallback
  amplification, accepted outcomes per dollar, and cohort margin are bounded.
- **Margin thesis.** Durable margin is governed orchestration, routing, learning
  ownership, assurance, private deployment, recovery, and outcome coordination —
  not opaque token resale. Any pricing, packaging, or supply decision that
  survives only by concealing token spread contradicts this method.

## Applying it in a work item

- Name the table's owners in `canon_owners`, with `canon_snapshot` digests taken
  before the claim is written.
- Bound `falsifiable_claim` to one commercial posture (`direct`, `aggregator`,
  `customer_byok`, `customer_byoa`, `self_hosted`) and one access mode; list the
  postures not claimed in `out_of_scope` and `remaining_nonclaims`.
- Carry the resolved `ModelRouteRightsContract` identity — `contract_hash`,
  `admitted_policy_hash`, validity window, status — into `contract_families`
  and `evidence_refs` as repo paths.
- Freeze route-attempt counts, supplier/broker cost, fee basis, p50/p90/p95
  COGS, fallback amplification, accepted outcomes per dollar, and cohort margin
  in `metrics_and_frozen_thresholds` before observation.
- Name the final invoker for every effect that spends, reserves, debits, or
  refunds in `consequential_effects_and_final_invokers`, including the step that
  reconciles receipt-derived usage against provider statements.
- Put the separation refusals in `adversarial_or_fault_proof`: a named-human-seat
  route refused for unattended production use, an unresolved rights member
  refused at admission, a Work Credit debit refused without required billing
  evidence, and a Network/Open task refused against an included allowance.

## Terminal evidence

The method's contribution closes when a bounded supply posture is exercised end
to end against a resolved rights contract; a ledger bundle conforming to
[`managed-work-billing.md`](../../../docs/conformance/hypervisor-core/managed-work-billing.md)
is reconstructed from retained receipts rather than an internal event log; the
frozen commercial metrics are reported from that reconstruction with negative
and inconclusive results retained; and every separation refusal above is
demonstrated as a denial before invocation. Absent any of these, the remaining
commercial claim is recorded as a nonclaim.

## Canon gaps

- **Stage reach.** The retiring source named rights/baseline work, route
  integration, first-product proof, and external procurement as places this
  method applies, while the sequencer binds M8 and M14. Whether additional
  `applies_to_stages` entries are warranted belongs to the build-order and
  claim-horizon owner,
  [`_meta/execution-horizons.md`](../../../docs/architecture/_meta/execution-horizons.md),
  with the outcome recorded in `sequence.v1.json`.
- **Rights-contract lifecycle enforcement.** Canon defines the status enum
  (`active | quarantined | expired | superseded | revoked`) and requires
  resolution before admission, but does not name the revalidation point, the
  required behavior for an admitted run, lease, or fallback chain whose contract
  transitions mid-flight, or the metering consequence. Owners:
  [`model-router/doctrine.md`](../../../docs/architecture/components/model-router/doctrine.md)
  (enforcement locus) and
  [`identity-access-and-metering.md`](../../../docs/architecture/components/hypervisor/identity-access-and-metering.md)
  (metering consequence).
