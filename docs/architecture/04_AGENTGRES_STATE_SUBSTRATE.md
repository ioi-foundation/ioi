# Agentgres State Substrate Specification

## Canonical Definition

**Agentgres is the per-domain state-retention and state-change substrate for canonical Web4 applications.**

It records what happened, what changed, why it changed, who authorized it, what evidence supports it, how it can be queried, and how future agents can reuse it.

Agentgres does not run on IOI L1. It runs inside application-domain kernel deployments.

## Core Doctrine

> **All state changes are patches. All accepted patches settle into truth. All truth is queryable from the nearest verifiable view.**

Database doctrine:

> **Rows are views. Settled state is truth.**

## What Agentgres Owns

Agentgres owns per-domain operational truth:

- canonical operation log;
- deterministic object state;
- patch/change lifecycle;
- runs;
- tasks;
- orders;
- workflow state;
- delivery bundles;
- artifacts refs;
- receipts;
- policy decision records;
- quality ledgers;
- contribution accounting;
- projections;
- subscriptions;
- search/ranking views;
- import/export state;
- backup/restore metadata.

## What Agentgres Does Not Own

Agentgres does not own:

- raw secrets;
- root user authority;
- raw wallet keys;
- payment keys;
- connector refresh tokens;
- IOI L1 smart-contract settlement;
- Filecoin/CAS payload bytes;
- the physical compute resource;
- every local UI hover/draft state;
- private working memory unless promoted.

wallet.network owns authority. Autopilot/IOI daemon owns execution. Filecoin/CAS owns payload availability. IOI L1 owns public settlement and rights.

## State Lifecycle

Every consequential change follows:

```text
Intent
→ Scope
→ Patch
→ Validate
→ Merge
→ Settle
→ Project
→ Query
→ Retain
```

### Intent

A user, agent, workflow, or service declares a desired change.

### Scope

wallet.network, policy, or domain rules grant the actor a bounded scope.

### Patch

The actor proposes a concrete change to state, files, documents, services, or artifacts.

### Validate

Agentgres/domain runtime validates schema, policy, constraints, receipts, expected state, and evidence.

### Merge

The patch is merged according to object-specific concurrency and merge policy.

### Settle

Accepted patch becomes canonical domain state.

### Project

Relations, materialized views, dashboards, subscriptions, and search/ranking projections update.

### Query

Apps and agents query local, checkpointed, projection, live, or proof-bound views.

### Retain

State, receipts, evidence, quality, and contribution are retained for replay, audit, reuse, and dispute.

## Native Objects

Core object families:

```text
Agent
Worker
Service
Task
Run
Order
StandingOrder
Patch
ScopeLease
PolicyDecision
Receipt
ArtifactRef
ArtifactBundle
EvidenceSet
DeliveryBundle
QualityRecord
ContributionReceipt
ProjectionDefinition
ProjectionCheckpoint
DisputeRecord
```

## Database Surface

Agentgres should provide:

- object state;
- native relations;
- constraints;
- indexes;
- transactions;
- materialized projections;
- subscriptions;
- SQL-compatible reads where appropriate;
- schema/migration lifecycle;
- backup/restore;
- operator inspection.

It should absorb practical database responsibilities without turning mutable rows into final truth.

## Read Paths

Agentgres supports local-first and zero-to-idle reads:

```text
local cache
→ verified static snapshot/checkpoint
→ projection checkpoint + delta
→ live domain runtime
→ canonical write authority only when needed
```

Reads should wake shared runtime only when freshness, policy, key release, proof, live tail, or missing projections require it.

## Domain Examples

### aiagent.xyz Agentgres

- worker listings;
- versions;
- install records;
- usage receipts;
- quality ledgers;
- contribution accounting;
- search/ranking projections;
- reputation state.

### sas.xyz Agentgres

- service listings;
- service orders;
- SLA/delivery state;
- provider/customer state;
- delivery bundles;
- dispute evidence;
- payout mirrors;
- service quality records.

## Interaction with IOI L1

Agentgres synchronizes with IOI L1 contracts for:

- rights;
- licenses;
- escrows;
- bonds;
- payouts;
- disputes;
- reputation/contribution roots;
- manifest commitments.

Agentgres does not post every event or receipt to IOI L1.

## Invariants

1. No model output directly mutates canonical truth.
2. No consequential state change without persisted intent/policy/evidence path.
3. No projection is canonical truth unless explicitly defined as commit-critical.
4. No raw secret storage in Agentgres.
5. No split-brain app state outside the domain Agentgres authority.
6. No marketplace contribution without attribution when used materially.

## One-Line Doctrine

> **Agentgres gives intelligence memory: it makes autonomous work durable, queryable, composable, auditable, and settleable.**

