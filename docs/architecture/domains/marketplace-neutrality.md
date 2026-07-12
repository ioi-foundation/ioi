# Marketplace Neutrality and Contribution Accounting Specification

Status: canonical architecture authority.
Canonical owner: this file for marketplace neutrality, first-party seed-supply neutrality, contribution and derivation accounting, assurance-state attribution, and anti-cannibalization doctrine.
Supersedes: overlapping plan prose when marketplace neutrality or attribution conflicts.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: planned (neutrality covenant; routing, affiliation, contribution, assurance, challenge, and settlement receipts not implemented)
Last implementation audit: 2026-07-05

## Canonical Definition

**Marketplace neutrality, MoW router neutrality, and assurance-aware
contribution accounting prevent the Default Harness Profile, ioi.ai conductor,
IOI seed fleet, or first-party marketplaces from appropriating worker,
training, benchmark, verifier, and service markets.**

This is the missing incentive facet required for a real Internet of Intelligence economy.

The marketplace neutrality covenant is:

> **Open substrate, paid network. Routing and reputation are earned from verified
> work, not claimed capability, paid placement, or platform fiat.**

## Core Problem

If the Default Harness Profile becomes “good enough at everything,” it can cannibalize marketplace workers.

If the Default Harness Profile forces users into paid services, users will route around it.

If worker logic is silently absorbed into the Default Harness Profile, providers will stop contributing.

If MoW routing silently prefers first-party workers, benchmark claims, or
bundled defaults, Sparse Worker Categories stop rewarding real utility.

Therefore:

> **HarnessProfiles must be neutral daemon-executed or daemon-mediated
> step-resolution contracts. The Default Harness Profile is the reference
> scaffold/fallback, not the privileged competitor to every worker or service.**

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
- user preference;
- worker publisher and operator affiliation;
- model, provider, runtime, verifier, and coordinator dependencies;
- attempted routes, fallback/escalation, and assurance requirements.

The user should retain the right to run locally/default unless the task requires licensed data, external authority, hosted service, or third-party authority.

`Auto` / `1-of-N`, `Pinned`, and `Compare` / `N-of-N` remain neutral routing
policies over the same candidate market. Auto may use a cheap-first verified
cascade; Pinned honors a user-selected eligible route; Compare accounts for all
declared attempts and verifier/synthesis work. First-party defaults may win only
on the same declared cost, privacy, locality, evidence, availability, and user-
preference criteria as third-party supply.

## MoW Router Neutrality

MoW router neutrality applies the same rule to worker selection. The runtime,
marketplace, or service router must not silently substitute a first-party or
default worker when another worker is materially better under the declared
routing policy.

A routing decision that affects payment, reputation, trust, settlement, or
dispute posture must emit the canonical
[`RoutingDecisionReceipt`](../components/daemon-runtime/events-receipts-delivery-bundles.md#routing-decision-receipts)
over the shared `RoutingDecisionEnvelope`. The decision and receipt must bind
the candidate set and affiliations, policy, selected domain/Worker composition,
model/provider/runtime dependencies, authority and cost bounds, actual attempts,
fallbacks/escalations, verifier path, contribution policy, and reason code.

Routing preference must be based on declared policy, benchmark performance,
receipt completeness, cost, privacy, trust posture, installed status, runtime
availability, or user preference. If a default worker is selected, the reason
must be legible in the receipt.

Paid listing, admission, certification, managed hosting, or promotion fees may
exist only when they fund distribution, benchmark/eval compute, trust and safety,
procurement, hosting, or commercial operations. They must not silently alter
routing eligibility, reputation, benchmark claims, or first-party preference.

An IOI-operated planner, builder, verifier, critic, synthesizer, benchmark, or
challenge fleet may seed cold-start liquidity, but every composition must be
named, versioned, costed, affiliation-disclosed, and routed through the same
contracts. Ten IOI-owned workers across ten nodes and several model vendors
remain one party. IOI may not market that fleet as independent federation or
let it circularly act as coordinator, paid worker, sole verifier, ranking
authority, and settlement judge for one consequential outcome.

## Anti-Cannibalization Rules

1. No silent cloning of worker internals into the Default Harness Profile.
2. Worker packages declare visibility/license rights.
3. The Default Harness Profile cannot rank itself first by platform fiat.
4. Worker/service usage emits contribution receipts.
5. Marketplace workers compete on specialization, quality, price, privacy, support, and outcome guarantees.
6. Service redirection is opt-in unless the user explicitly ordered a managed service.
7. Paid promotion cannot buy RoutingDecisionReceipt preference.
8. Unverified listings must not be presented as benchmarked or production-ready
   workers.
9. First-party seed workers must disclose affiliation, subsidy, model/provider/
   runtime dependencies, and actual cost class and remain replaceable without a
   pursuit-contract change.
10. A first-party coordinator, worker, verifier, ranking authority, and
    settlement judge must not collapse into one undisclosed conflict of
    interest for consequential work.
11. Participant messages, artifacts, findings, semantic mappings, and verifier
    suggestions remain tainted inputs until the owning admission and assurance
    path accepts them; routing popularity is never automatic promotion.
12. Sybil clusters, shared ownership, correlated model/provider dependencies,
    reciprocal review, and collusion signals must remain visible to routing,
    verifier-independence, reputation, and settlement policy.

## Contribution Objects

Agentgres should define:

```text
MarketplaceRoutingDecision
MoWRoutingDecision
WorkerInvocation
ContributionReceipt
ContributionClaim
UsageReceipt
AttributionGraph
DerivationGraph
QualityDelta
VerificationDecision
AcceptanceDecision
VerifierChallenge
RewardClaim
ReputationUpdate
ServiceHandoff
LicenseEnvelope
WorkerTrainingRecord
BenchmarkSubmission
```

In an `OutcomeRoom` / CollaborativeWorkGraph, these records follow the
frontier, claim, attempt, finding, verifier-challenge, WorkResult, and admitted
OutcomeDelta lineage across independently governed domains. The room or ioi.ai
conductor may synthesize a user-facing result, but it cannot erase the Worker,
resource provider, verifier, semantic mapper, reviewer, or service contribution
that made the accepted outcome possible.

## ContributionReceipt

The field-level schema is the canonical
[`ContributionReceipt`](../components/daemon-runtime/events-receipts-delivery-bundles.md#contribution-receipts).
It binds the accountable contributor and operator/affiliations; Worker and
package version; model/provider/runtime attribution without turning a model
endpoint into an actor; Goal/room/task/run/attempt/result/delta lineage;
contribution type; routing/category/benchmark refs; evidence, verifier rule,
acceptance, adjudication, assurance, dispute, inputs/outputs, uncertainty,
applicability, license, reward basis, settlement, and receipt hash.

`ContributionReceipt` attributes a claim; it does not automatically establish
correctness, causality, value, reputation, or payout. Marketplace projections
must preserve the assurance ladder:

```text
receipt / attestation
-> evidence bundle
-> verification under named rule/version
-> customer or domain acceptance
-> challenge / adjudication when invoked
-> settlement
```

Positive execution is not the only valuable work. Review, debugging,
independent replication, a durable negative or inconclusive result, an exploit
or integrity report, resource provision, derivation, curation, verifier
hardening, and synthesis may eliminate false paths or make another outcome
possible. Attribution and reward policy should recognize accepted marginal
information and derivation without inventing precise quality value before the
verifier and acceptor can support it.

Independent verification means independent enough for the declared risk, not
merely a differently named process. Policy should consider publisher/operator
affiliation, shared model/provider/runtime dependencies, common training or
memory, reciprocal review, and economic conflicts. High-risk work may require
separation of execution, verification, acceptance, and adjudication duties.

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
be distributed only from contribution records that reached the required
verification, acceptance, and dispute state. They must not be popularity,
attention, message-count, self-report, or raw-token pools. Work Credits are
non-transferable product budget units; worker payouts use the approved
marketplace or settlement rail and must not silently turn unused seat credits
into cash claims.

## Relationship to IOI L1

IOI L1 may store:

- contribution root;
- reward root;
- reputation root;
- license/install rights;
- payout settlement;
- disputes.

Agentgres domains store detailed contribution, attempt, assurance, challenge,
and routing accounting. IOI L1 receives sparse roots only when portable rights,
reputation, bonds, dispute finality, or economic settlement adds value. There is
no chain, token transfer, or public commitment required per worker, GoalRun,
attempt, ContributionReceipt, or OutcomeRoom update.

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
8. No generic fee on a local or self-hosted run that does not use marketplace
   matching, managed hosting, settlement, or network routing.
9. No reputation, payout, or routing-weight update from a bare
   `ContributionReceipt`; the declared evidence, verification, acceptance,
   adjudication, and settlement state must be satisfied.
10. No winning-run-only attribution where accepted derivation, review,
    debugging, replication, negative information, integrity reporting, resource
    provision, verifier hardening, or synthesis materially contributed.
11. No first-party seed fleet presented as independent parties, and no hidden
    first-party conflict across coordination, paid execution, sole verification,
    ranking, and settlement judgment.
12. No automatic promotion of participant input into durable memory, ontology,
    routing policy, authority, marketplace rank, production capability, or
    settlement merely because it is signed, repeated, or popular.
13. No quality or independence claim that hides common publisher/operator,
    model/provider/runtime, memory/training, reciprocal-review, or economic
    dependencies.
14. No L1 transaction or standalone blockchain per worker, GoalRun, attempt,
    receipt, or room update by default.

## One-Line Doctrine

> **The platform must route intelligence without absorbing it: affiliation,
> derivation, negative and verifying work, assurance state, challenge, and
> sparse settlement remain attributable to the actual contributors.**
