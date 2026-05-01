# Marketplace Neutrality and Contribution Accounting Specification

Status: canonical architecture authority.
Canonical owner: this file for marketplace neutrality, contribution accounting, and anti-cannibalization doctrine.
Supersedes: overlapping plan prose when marketplace neutrality or attribution conflicts.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Canonical Definition

**Marketplace neutrality and contribution accounting are the economic layer that prevents the default harness from cannibalizing the worker and service markets.**

This is the missing incentive facet required for a real Internet of Intelligence economy.

## Core Problem

If the default harness becomes “good enough at everything,” it can cannibalize marketplace workers.

If the default harness forces users into paid services, users will route around it.

If worker logic is silently absorbed into the default harness, providers will stop contributing.

Therefore:

> **The default harness must be a neutral execution substrate, not the privileged competitor to every worker or service.**

## Neutral Routing Doctrine

For a task, the runtime may choose or recommend:

```text
default_harness
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

## Anti-Cannibalization Rules

1. No silent cloning of worker internals into default harness.
2. Worker packages declare visibility/license rights.
3. The default harness cannot rank itself first by platform fiat.
4. Worker/service usage emits contribution receipts.
5. Marketplace workers compete on specialization, quality, price, privacy, support, and outcome guarantees.
6. Service redirection is opt-in unless the user explicitly ordered a managed service.

## Contribution Objects

Agentgres should define:

```text
MarketplaceRoutingDecision
WorkerInvocation
ContributionReceipt
UsageReceipt
AttributionGraph
QualityDelta
RewardClaim
ReputationUpdate
ServiceHandoff
LicenseEnvelope
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
2. No default-harness appropriation of private worker logic.
3. No forced service tollbooth for ordinary local-capable tasks.
4. No payout/reputation update without usage/quality evidence.
5. No marketplace ranking without measurable quality/reputation signals.

## One-Line Doctrine

> **The platform must route intelligence, not absorb it.**
