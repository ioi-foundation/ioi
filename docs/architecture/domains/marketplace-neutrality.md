# Marketplace Neutrality and Contribution Accounting Specification

Status: canonical architecture authority.
Canonical owner: this file for marketplace neutrality, contribution accounting, and anti-cannibalization doctrine.
Supersedes: overlapping plan prose when marketplace neutrality or attribution conflicts.
Superseded by: none.
Last alignment pass: 2026-05-30.

## Canonical Definition

**Marketplace neutrality, MoW router neutrality, and contribution accounting are the economic layer that prevents the Default Harness Profile or first-party marketplace from cannibalizing worker, training, benchmark, and service markets.**

This is the missing incentive facet required for a real Internet of Intelligence economy.

## Core Problem

If the Default Harness Profile becomes “good enough at everything,” it can cannibalize marketplace workers.

If the Default Harness Profile forces users into paid services, users will route around it.

If worker logic is silently absorbed into the Default Harness Profile, providers will stop contributing.

If MoW routing silently prefers first-party workers, benchmark claims, or
bundled defaults, Sparse Worker Categories stop rewarding real utility.

Therefore:

> **The Default Harness Profile must be a neutral daemon-executed orchestration profile, not the privileged competitor to every worker or service.**

## Neutral Routing Doctrine

For a task, the runtime may choose or recommend:

```text
default_harness_profile
installed_worker
marketplace_worker
service_outcome
hybrid_composition
ask_user
```

Routing must be explainable:

- expected quality;
- cost;
- privacy;
- latency;
- required tools;
- worker reputation;
- local ability;
- service guarantee;
- user preference.

The user should retain the right to run locally/default unless the task requires licensed data, external authority, hosted service, or third-party authority.

## MoW Router Neutrality

MoW router neutrality applies the same rule to worker selection. The runtime,
marketplace, or service router must not silently substitute a first-party or
default worker when another worker is materially better under the declared
routing policy.

A routing decision that affects payment, reputation, trust, settlement, or
dispute posture should emit a RoutingDecisionReceipt with:

```yaml
RoutingDecisionReceipt:
  routing_decision_id: route_...
  task_id: task://...
  router_id: worker://... | runtime://... | system://... | domain://...
  intent_hash: hash
  candidate_set_commitment: hash
  routing_policy_hash: hash
  selected_domain_or_worker: system://... | domain://... | worker://... | service://... | runtime://...
  authority_scope: []
  cost_bound: optional
  reason_code: string
  fallback_policy: optional
  contribution_policy_ref: optional
  receipt_obligations: []
```

Routing preference must be based on declared policy, benchmark performance,
receipt completeness, cost, privacy, trust posture, installed status, runtime
availability, or user preference. If a default worker is selected, the reason
must be legible in the receipt.

## Anti-Cannibalization Rules

1. No silent cloning of worker internals into the Default Harness Profile.
2. Worker packages declare visibility/license rights.
3. The Default Harness Profile cannot rank itself first by platform fiat.
4. Worker/service usage emits contribution receipts.
5. Marketplace workers compete on specialization, quality, price, privacy, support, and outcome guarantees.
6. Service redirection is opt-in unless the user explicitly ordered a managed service.

## Contribution Objects

Agentgres should define:

```text
MarketplaceRoutingDecision
MoWRoutingDecision
WorkerInvocation
ContributionReceipt
UsageReceipt
AttributionGraph
QualityDelta
RewardClaim
ReputationUpdate
ServiceHandoff
LicenseEnvelope
WorkerTrainingRecord
BenchmarkSubmission
```

## ContributionReceipt

A contribution receipt should record:

```yaml
ContributionReceipt:
  contributor_id: ai://workers.runtime-auditor
  contributor_type: worker
  version: 1.0.3
  task_id: task_123
  run_id: run_456
  contribution_type: verification | generation | planning | data | tool | service
  routing_decision_ref: optional
  sparse_worker_category: optional
  benchmark_profile_ref: optional
  downstream_outcome_ref: optional
  dispute_status: none | pending | upheld | rejected | no_fault
  input_refs:
    - artifact_a
  output_refs:
    - artifact_b
  quality_delta: +0.18
  license_terms: usage_metered
  reward_basis: service_order_789
  receipt_hash: ...
```

## Worker/Service Router

The router should evaluate:

- task class;
- risk;
- local/default ability;
- installed workers;
- marketplace workers;
- managed services;
- quality history;
- price;
- SLA;
- privacy constraints;
- user autonomy preference.

It should output an explainable decision and user options.

Subscription credits, outcome escrows, royalties, and benchmark rewards should
be distributed by verified ContributionReceipts. They must not be popularity,
attention, or raw-token pools.

## Relationship to IOI L1

IOI L1 may store:

- contribution root;
- reward root;
- reputation root;
- license/install rights;
- payout settlement;
- disputes.

Agentgres stores detailed contribution accounting.

## Why This Completes the IoI Economy

The Internet of Intelligence needs incentives for intelligence sharing. This layer answers:

- who contributed intelligence;
- how it was used;
- whether it improved the outcome;
- how reputation accrues;
- how payment/reward accrues;
- why providers should participate without fear of appropriation.

## Invariants

1. No material external contribution without attribution.
2. No Default Harness Profile appropriation of private worker logic.
3. No forced service tollbooth for ordinary local-capable tasks.
4. No payout/reputation update without usage/quality evidence.
5. No marketplace ranking without measurable quality/reputation signals.
6. No MoW routing preference without a declared policy basis and challengeable
   receipt trail.
7. No worker-training capability claim without training lineage and evaluation
   evidence.

## One-Line Doctrine

> **The platform must route intelligence, not absorb it.**
