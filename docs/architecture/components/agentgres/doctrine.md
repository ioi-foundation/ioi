# Agentgres State Substrate Specification

Status: canonical architecture authority.
Canonical owner: this file for high-level Agentgres doctrine; low-level runtime objects live in [`agentgres-api-and-object-model.md`](./agentgres-api-and-object-model.md).
Supersedes: overlapping plan prose when Agentgres state ownership conflicts.
Superseded by: none.
Last alignment pass: 2026-05-01.

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

## Preserved Detailed Agentgres Spec Module

The following module preserves the detailed Agentgres v2.0 design context from the former `docs/specs/agentgres-spec.md`. It is retained for architecture memory and implementation detail. If it conflicts with the canonical doctrine above or the low-level object model in `agentgres-api-and-object-model.md`, the canonical architecture sections above and the low-level object model win.

---

# Agentgres v2.0

## State Changes Are Patches. Truth Is Settled.

## 0. One-Line Definition

**Agentgres is a local-first, zero-to-idle state fabric where humans and agents
propose scoped changes, the system validates and settles them into canonical
truth, and applications query the nearest verifiable projection.**

Agentgres unifies three things modern autonomous software currently stitches
together by hand:

```text
database state
+ collaborative change management
+ verifiable query/projection runtime
```

The agent doctrine:

> Agents do not directly mutate truth. Agents propose scoped patches. The
> fabric validates, merges, receipts, and settles them.

The database doctrine:

> Rows are views. Settled state is truth.

The runtime doctrine:

> React apps should render from local verified state first, wake shared runtime
> authority only when necessary, and let unused serving planes idle to zero.

Agentgres is the application-state expression of the IOI fractal blockchain
kernel: local actors propose bounded changes, ordering domains settle canonical
roots, and portable projections carry verified state outward.

---

# 1. Core Decision

Agentgres is not merely a Postgres replacement.

It is a replacement for the:

```text
Postgres
+ Git
+ Google Docs
+ workflow engine
+ sync engine
+ audit log
+ object metadata
+ policy glue
```

stack that agentic software otherwise assembles by hand.

The decision:

> **Agentgres must become the default state architecture for autonomous
> software: a system where every consequential state change is proposed as a
> scoped patch, settled into canonical truth, retained with receipts and
> artifacts, and queried through local, projected, SQL-shaped, or proof-bound
> views.**

Agentgres should absorb the core reasons teams use Postgres:

- relations
- schemas
- constraints
- indexes
- transactions
- SQL-shaped reads
- migrations
- backup and restore
- operator tooling
- durability
- ecosystem compatibility

It should also absorb the reasons teams reach for Git, Google Docs, workflow
engines, sync engines, and audit systems:

- branching
- live collaboration
- patches
- merge decisions
- semantic diffs
- scope leases
- validation
- provenance
- receipts
- artifact lineage
- offline/local-first state
- resumable subscriptions
- policy-bound execution
- replayable history

Agentgres is not "Postgres but decentralized."

It is:

> **a patch-native, queryable, replayable, local-first, chain-settled state
> fabric for humans and agents.**

---

# 2. What Changed From Database-First Framing

The database-first direction centered the row:

> Rows are views. The chain is truth.

Agentgres keeps that doctrine, but moves one layer deeper.

The new center is not the row.
The new center is not even the operation log.
The new center is the **state-change lifecycle**.

```text
Intent
-> Scope
-> Patch
-> Validate
-> Merge
-> Settle
-> Project
-> Query
-> Retain
```

That lifecycle applies to:

- SQL writes
- SDK mutations
- document edits
- code patches
- schema migrations
- workflow transitions
- agent tool results
- approval decisions
- policy changes
- file promotions
- artifact publication
- marketplace listing updates
- knowledge revisions
- UI-local state promotion

The database surface is one expression of a broader principle:

> **All important state changes are governed patches before they become settled
> truth.**

---

# 3. Product-Level Framing

Use one public name:

> **Agentgres**

Do not expose separate branded subsystems unless necessary.

Internally, Agentgres has functional arms:

```text
Change
Truth
Query
Client
Files
Policy
Ops
```

These are not separate products. They are responsibilities of one state fabric.

| Arm | Responsibility |
| --- | --- |
| Change | Intents, leases, patches, live edits, semantic diffs, merge decisions |
| Truth | Operation log, deterministic object state, constraints, indexes, transactions, state roots |
| Query | Relations, projections, SQL, subscriptions, query planning, consistency levels |
| Client | React/local-first runtime, cache, mutation queue, offline replay, hydration |
| Files | Files, artifacts, bundles, checkpoints, evidence, private availability |
| Policy | Authorization, approvals, key release, validation receipts, query receipts |
| Ops | Migrations, backup/restore, repair, replay, import/export, observability |

Public description:

> **Agentgres stores state as settled changes, serves it as relations and
> projections, and lets React apps run locally until authority is needed.**

---

# 4. Replacement Target

Agentgres replaces this stack:

```text
React app
  -> local UI store
  -> API client
  -> ORM
  -> Postgres
  -> Redis/cache
  -> websocket server
  -> job queue
  -> workflow engine
  -> object storage
  -> Git or patch store
  -> audit tables
  -> sync engine
  -> search index
  -> custom policy glue
  -> migration scripts
  -> admin/BI replicas
```

with:

```text
React app
  -> local UI state
  -> embedded Agentgres client runtime
  -> local verified cache/projections
  -> patch/change lifecycle
  -> canonical settlement
  -> relations, SQL, projections, subscriptions
  -> file/artifact/receipt substrate
  -> wakeable shared runtime authority
  -> optional external sinks
```

The goal is not to eliminate every specialized system.

The goal is to make Agentgres the **central state-retention and state-change
architecture** so that Postgres, Git, workflow engines, cache layers, sync
systems, and audit tables become optional adapters rather than the core
substrate.

---

# 5. Core Thesis

Existing systems each own one part of the problem.

Postgres answers:

> Where does application state live?

Git answers:

> How do file changes version over time?

Google Docs answers:

> How do multiple people edit shared state live?

Workflow engines answer:

> How do long-running processes move forward?

Sync engines answer:

> How does local state reconcile with shared state?

Audit logs answer:

> What happened and who did it?

Agentgres answers:

> **How do humans and agents create, revise, merge, prove, retain, and query all
> consequential state?**

That is the category.

---

# 6. Fundamental Rule

The constitutional rule of Agentgres:

> **No consequential actor directly mutates canonical truth.**

Instead:

```text
actor or agent
-> declares intent
-> receives or requests scope
-> produces patch operations
-> validates patch
-> merges patch
-> settles accepted patch into canonical state
-> updates relations/projections/subscriptions
-> emits receipts
```

A patch may be:

- a code diff
- a row update
- a document edit
- a workflow transition
- a schema migration
- a file promotion
- a generated artifact filing
- a policy update
- a marketplace listing change
- an execution result

The unification is the point.

---

# 7. Agentgres State Lifecycle

Every meaningful change follows this lifecycle.

## 7.1 Intent

An actor declares what they want to change.

```yaml
intent:
  actor: agent:planner_17
  goal: "advance run after validation"
  target:
    object: Run
    id: run_123
  risk_class: low
  expected_effect:
    status: awaiting_approval
```

Intent is not authority. It is a request to begin change.

## 7.2 Scope

The fabric determines what the actor may touch.

Scope may be granted by:

- capability
- lease
- role
- approval
- policy
- ownership
- task assignment
- collaboration session

```yaml
scope_lease:
  lease_id: lease_abc
  actor: agent:planner_17
  resources:
    - Run:run_123
    - Approval:*
  permissions:
    - read
    - propose_patch
    - validate
  expires_at: 2026-04-29T19:00:00Z
```

Scope prevents blind collision.

## 7.3 Patch

The actor proposes concrete changes.

Patch operations may be text-level, object-level, relation-level,
document-level, AST-level, schema-level, workflow-level, or artifact-level.

```yaml
patch:
  patch_id: patch_789
  intent_id: intent_456
  base:
    object: Run
    id: run_123
    head: h_old
  operations:
    - op: advance_state
      field: status
      from: running
      to: awaiting_approval
    - op: attach_receipt
      receipt: validation_receipt_55
```

## 7.4 Validate

Validation checks:

- syntax
- schema
- constraints
- policy
- authorization
- semantic correctness
- dependency freshness
- artifact availability
- tests or simulations
- receipts
- migration compatibility
- key-release requirements

```yaml
validation:
  patch_id: patch_789
  checks:
    - run_status_transition_valid: pass
    - actor_can_advance_run: pass
    - required_validation_receipt_present: pass
    - no_conflicting_head_change: pass
  result: pass
```

## 7.5 Merge

The patch is merged against the current candidate or canonical state.

Merge may be:

- trivial
- structural
- semantic
- policy-gated
- human-reviewed
- agent-reviewed
- rejected
- repaired
- rebased

```yaml
merge_decision:
  patch_id: patch_789
  base_head: h_old
  current_head: h_current
  outcome: accepted
  merge_strategy: compare_and_set_head
```

## 7.6 Settle

Accepted patches become canonical operations.

```yaml
canonical_operation:
  op_id: op_999
  patch_id: patch_789
  object: Run
  id: run_123
  transition: RunAdvanced
  new_head: h_new
  state_root: root_abc
```

Settlement produces truth.

## 7.7 Project

Settled operations update derived surfaces:

- native relations
- materialized projections
- SQL views
- local caches
- subscriptions
- dashboards
- search indexes
- timeline views
- approval inboxes
- receipts

## 7.8 Query

Applications query the nearest valid source:

- local cache
- local projection
- static checkpoint
- materialized relation
- live runtime
- canonical state
- proof-bound receipt path

## 7.9 Retain

The system retains:

- operation history
- patch history
- merge decisions
- validation receipts
- artifacts
- projections
- checkpoints
- state roots
- backup snapshots
- policy decisions

Retention is not only final state.

Agentgres retains the history of how truth came to be.

---

# 8. Change Arm

The Change arm makes Git-style patches and Docs-style collaboration native to
Agentgres.

It owns:

- intents
- work items
- scope leases
- patch branches
- live edit sessions
- semantic patch operations
- conflict sets
- dependency graphs
- validation plans
- merge proposals
- merge decisions
- repair patches

## 8.1 Change Objects

Core change objects:

```text
Intent
WorkItem
ScopeLease
PatchBranch
LiveEditSession
PatchOperation
SemanticDiff
ConflictSet
DependencySet
ValidationPlan
ValidationReceipt
MergeProposal
MergeDecision
RepairPatch
SettlementCommit
```

## 8.2 Patch Branches

A patch branch is a proposed state branch.

It may be:

- local
- session-scoped
- collaborative
- agent-owned
- human-reviewed
- speculative
- accepted
- rejected
- superseded
- settled

Patch branches are not Git branches, though they may export to Git.

They are generalized branches over any state object.

## 8.3 Live Edit Sessions

For collaborative work, a patch branch may have a live operation stream.

This supports Docs-style interaction:

- live presence
- cursors/selections where relevant
- operation streaming
- incremental merge previews
- conflict prediction
- region ownership
- semantic awareness
- validation feedback

For code, operations may be:

```text
insert_text
delete_range
replace_range
rename_symbol
move_function
update_import
regenerate_file
update_call_sites
```

For documents:

```text
insert_block
delete_block
edit_section
attach_citation
move_paragraph
update_heading
```

For database objects:

```text
set_field
advance_state
attach_artifact
create_reference
archive_object
```

## 8.4 Scope Leases

Agentgres should avoid unbounded concurrent edits by requiring scope.

Scope may target:

- object
- relation
- file
- document section
- code symbol
- schema
- workflow run
- artifact bundle
- policy
- projection definition

```yaml
scope:
  resource: Document:doc_123#section:pricing
  actor: agent:copy_editor
  permissions:
    - propose_patch
    - edit_text
  expires_at: 2026-04-29T19:00:00Z
  conflict_policy: block_conflicting_writes
```

## 8.5 Semantic Conflict Detection

Textual conflict is not enough.

Agentgres should detect semantic conflicts such as:

- state transition invalid
- stale object head
- schema mismatch
- generated artifact stale
- API contract broken
- required receipt missing
- migration incompatible
- file privacy class violated
- policy changed during patch
- dependency patch superseded
- hidden cross-domain transaction cost

## 8.6 Merge Policies

Merge policy is declared per object class, relation, file type, or patch type.

Examples:

```text
append_only
compare_and_set_head
branch_and_merge
proposal_and_promotion
lease_governed
schema_migration
generated_artifact_regenerate
human_review_required
```

Merge is not only a mechanical operation.

Merge is a policy-bound settlement decision.

---

# 9. Truth Arm

The Truth arm owns canonical state.

Canonical truth is:

```text
ordered operation log
+ deterministic object transitions
+ commit-critical constraints
+ commit-critical indexes
+ schema version
+ policy version
+ state roots
```

Truth is not:

- arbitrary mutable rows
- local speculative state
- projection state
- cached query results
- unvalidated patches
- staging ingress rows
- unsynced app UI state

## 9.1 Canonical Operation Log

Every settled change becomes one or more canonical operations.

Operations bind:

- operation id
- patch id
- actor
- capability scope
- object class
- object id
- expected prior state/head
- transition
- constraint results
- policy result
- schema version
- resulting state root
- receipt references

## 9.2 Canonical Object State

Objects are the semantic authority layer.

Object classes may include:

```text
Tenant
User
Role
Policy
PolicyDecision
Task
Run
Approval
ExecutionRequest
ExecutionReceipt
Document
Revision
ArtifactRef
ArtifactBundle
EvidenceSet
PromotionRequest
PatchBranch
LiveEditSession
ValidationReceipt
MergeDecision
ProjectionDefinition
ProjectionCheckpoint
RepairTicket
```

## 9.3 Object Concurrency Classes

Every object class declares a concurrency class:

```text
append_only
compare_and_set_head
lease_governed
branch_and_merge
proposal_and_promotion
escrow_governed
schema_versioned
```

Default rule:

> High-value state must not silently use last-write-wins.

## 9.4 Constraints

Constraints are protocol objects.

Constraint types:

```text
primary_key
unique
reference_exists
reference_not_deleted
non_null
check
enum
range
cardinality
state_machine_transition
ownership
capability_required
privacy_class_allowed
temporal_validity
idempotency_key_unique
lease_exclusive
promotion_precondition
schema_compatibility
artifact_available
receipt_required
```

Constraint enforcement modes:

```text
commit_critical
nearline_detect_and_repair
projection_quality
advisory
```

Constitutional rule:

> Any constraint that protects canonical correctness must run on the canonical
> commit path.

## 9.5 Indexes

Index classes:

### Constraint Indexes

Commit-critical indexes for correctness:

- primary key
- uniqueness
- idempotency
- active lease lookup
- reference existence
- capability revocation

### Serving Indexes

Indexes for query speed:

- task boards
- run history
- approval inbox
- file browser
- listing filters
- document search

### Projection Indexes

Indexes attached to materialized projections.

### Local Client Indexes

Indexes maintained in browser/device storage.

## 9.6 Transactions

Agentgres supports transaction classes:

```text
single_domain_serializable
single_domain_snapshot_isolated
constraint_checked_commit
read_only_snapshot
multi_domain_saga
multi_domain_escrow
local_speculative_transaction
```

### Single-Domain Transaction

Fully atomic and serializable inside one ordering domain.

### Multi-Domain Saga

Protocol-visible, compensatable workflow across domains.

### Multi-Domain Escrow

Bounded cross-domain atomicity using reserved rights or leases.

### Local Speculative Transaction

Optimistic local state before settlement.

Agentgres must not claim global serializability unless the workload explicitly
pays for a global ordering domain.

---

# 10. Query Arm

The Query arm serves state.

It owns:

- native relations
- materialized projections
- SQL compatibility
- typed queries
- agent-native queries
- subscriptions
- query planner
- read consistency
- local/static/live/proof-bound read paths

## 10.1 Rows Are Views

Rows are query surfaces over settled state.

Every database-visible row must be able to answer:

- which canonical object produced me?
- which operation last changed me?
- which patch or merge decision led to me?
- which schema version interpreted me?
- which constraints protect me?
- which state root or watermark am I bound to?
- am I canonical, projected, local, speculative, stale, or external?

## 10.2 Native Relations

Agentgres exposes table-shaped relations.

Relation authority classes:

```text
canonical_object_backed
projection_materialized
local_speculative
external_imported
staging_ingress
```

Example:

```yaml
relation: runs
authority_class: canonical_object_backed
source_object: Run
primary_key: run_id
columns:
  run_id: uuid
  tenant_id: uuid
  task_id: uuid
  status: enum[pending,running,awaiting_approval,failed,completed]
  created_at: timestamp
  updated_at: timestamp
  head: object_head
  last_operation_id: operation_id
  agentgres_state_root: root
  agentgres_watermark: sequence
indexes:
  - primary(run_id)
  - index(tenant_id, created_at desc)
  - index(tenant_id, status, updated_at desc)
constraints:
  - non_null(run_id)
  - reference_exists(tenant_id, tenants.tenant_id)
  - check(status in allowed_run_statuses)
```

## 10.3 SQL Compatibility

Agentgres should support SQL-shaped reads over declared relations and
projections.

V1 SQL reads should support:

- `SELECT`
- `WHERE`
- `ORDER BY`
- `LIMIT`
- keyset pagination
- simple joins over declared relations
- aggregates over materialized projections
- `COUNT`
- `GROUP BY`
- read consistency hints
- `EXPLAIN`
- metadata columns

Example:

```sql
SELECT id, status, created_at
FROM runs
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT 50
WITH CONSISTENCY session_consistent;
```

SQL writes are allowed only when they compile into patch/change operations.

Example:

```sql
UPDATE runs
SET status = 'awaiting_approval'
WHERE run_id = $1
AND head = $2;
```

Compiles into:

```yaml
intent: advance_run
patch:
  target: Run
  id: $1
  expected_head: $2
  operation:
    set status: awaiting_approval
validation:
  - run_status_transition_valid
  - actor_can_advance_run
settlement:
  canonical_operation: RunAdvanced
```

SQL is an interface, not the authority model.

Agentgres SQL is a compatibility and ergonomics surface over declared relations
and projections. It is not a promise that every arbitrary Postgres workload can
move unchanged.

## 10.4 Query Planner

Agentgres plans over more than tables.

It chooses among:

- local cache
- local speculative state
- verified static snapshots
- projection checkpoints
- materialized relations
- constraint indexes
- serving indexes
- canonical state
- live runtime
- encrypted files plus key release
- proof/receipt paths

Planner output includes:

```yaml
selected_source: local_projection
fallback_source: runtime_projection
wake_required: false
projection_id: runs_by_tenant
index_used: runs_by_tenant_created_at
consistency: session_consistent
freshness_ms: 38
receipt_mode: disabled
```

This is one of Agentgres' central moats: it can plan across local, static,
projected, live, private, and proof-bound sources instead of only tables and
indexes.

## 10.5 Read Consistency Levels

Every query declares or inherits a consistency level:

```text
local_cached
local_speculative
checkpoint_consistent
projection_consistent
state_root_consistent
session_consistent
linearized_domain
proof_bound
```

Every result should expose metadata:

```json
{
  "consistency": "projection_consistent",
  "projection_id": "approval_inbox",
  "projection_version": 7,
  "canonical_watermark": "tenant:123:seq:88371",
  "freshness_ms": 42,
  "state_root": "root_hash",
  "schema_version": 12
}
```

## 10.6 Materialized Projections

Materialized projections are database-grade derived views.

They declare:

```yaml
projection_id: approval_inbox
version: 5
source_objects:
  - Approval
  - Run
  - Task
output_relation: approval_inbox_items
update_mode: nearline_incremental
freshness_slo_ms: 250
checkpoint_interval: 10000 operations
retention_window: 30 days
indexes:
  - assignee_status_created_at
```

Refresh modes:

```text
synchronous_constraint
nearline_incremental
async_incremental
lazy_on_read
scheduled_rebuild
manual_rebuild
```

Projection invariants:

- reproducible
- checkpointable
- portable
- inspectable
- rebuildable
- freshness-bound
- query-plannable
- versioned

## 10.7 Subscriptions

Subscriptions are live queries over projections.

They support:

- resume tokens
- checkpoint rebase
- delta replay
- at-least-once delivery
- deterministic dedupe
- projection version binding
- capability scope binding

---

# 11. Client Arm

The Client arm is mandatory.

Agentgres is designed for React apps with local stores and zero-to-idle
serving.

## 11.1 React App Model

A React app should have two state layers.

### Ephemeral React/UI State

Owned by the app:

- panel layout
- selected tab
- hover/focus
- modal state
- unsaved input text
- transient filters
- drag state
- visual-only state

### Agentgres Local Runtime State

Owned by Agentgres:

- durable local cache
- local relations
- local projections
- local indexes
- mutation queue
- patch branches
- live edit sessions
- subscription cursors
- offline replay state
- verified snapshots
- checkpoint lineage
- receipts
- artifact manifests
- promoted drafts
- local/session/shared boundary state

## 11.2 Client Runtime Responsibilities

The embedded runtime owns:

- schema verification
- manifest verification
- local cache hydration
- IndexedDB/OPFS persistence
- local query planning
- local relation materialization
- speculative transactions
- patch creation
- mutation queueing
- offline replay
- subscription resume
- checkpoint hydration
- delta replay
- artifact hash verification
- decrypt request handling
- conflict resolution
- local repair
- generated query/mutation bindings

## 11.3 React API Shape

Example:

```ts
const agentgres = await openAgentgres({
  app: "ai://autopilot",
  persistence: "indexeddb",
  sync: "wakeable",
});
```

Query:

```ts
const runs = await agentgres.query.runs.list({
  tenant_id,
  consistency: "local_cached",
});
```

Subscribe:

```ts
const sub = agentgres.subscribe.approvals.inbox({
  tenant_id,
  assignee_id,
  resume: true,
});
```

Patch-style change:

```ts
const patch = await agentgres.patch.create({
  target: { object: "Document", id: "doc_123", region: "section:pricing" },
  intent: "revise pricing copy",
});

await patch.editText({ replace: "...", with: "..." });
await patch.validate();
await patch.propose();
```

Direct mutation convenience:

```ts
await agentgres.change.runs.advance({
  run_id,
  expected_head,
  transition: "awaiting_approval",
});
```

Direct mutations are syntactic sugar over the patch lifecycle.

## 11.4 Browser as First Read Replica

The browser/device is the first read replica.

Normal reads should resolve locally when:

- cache is fresh enough
- policy permits
- consistency requirement allows
- projection version matches
- required artifacts are available
- no live tail is required

The embedded runtime should make the app usable during:

- network interruption
- runtime sleep
- node failover
- projection catch-up
- offline work
- delayed settlement

---

# 12. Zero-to-Idle Architecture

Agentgres should minimize always-hot runtime requirements.

## 12.1 Read Path

Normal read path:

```text
React asks Agentgres client
-> local cache/projection checked
-> verified snapshot/checkpoint checked
-> static delta checked
-> live runtime woken only if needed
```

Runtime wake boundaries:

- canonical write settlement
- live subscription tail beyond static deltas
- private key release
- proof-heavy receipt generation
- missing/stale projection
- side-effecting execution
- repair/rebuild
- migration activation
- policy reevaluation that cannot be local

## 12.2 App Open Flow

```text
React boots
-> Agentgres client opens local store
-> verifies app manifest and schema
-> hydrates latest local projection
-> renders immediately if valid
-> checks static checkpoint/delta freshness
-> wakes runtime only if stale, live, private, or write path needed
```

## 12.3 Runtime Idle Flow

A shared runtime may idle when:

- no pending writes
- no live subscriptions requiring tail
- no key release
- no proof-heavy queries
- no active rebuilds
- no repair tasks
- no side-effecting executions

## 12.4 Reconnect Flow

```text
client presents resume token
-> runtime validates capability and revocation
-> streams deltas since last ack if available
-> otherwise serves checkpoint rebase
-> client rehydrates local projections
-> live stream resumes
```

This is central to the product:

> Agentgres should feel online, local, and reactive without requiring an
> always-hot database server for every read.

---

# 13. Files, Artifacts, and Receipts Arm

Agentgres treats files and artifacts as state-adjacent first-class objects.

## 13.1 Files and Artifacts

A file is user-facing.
An artifact is protocol-facing.

Refs bind:

- content hash
- size
- media type
- privacy class
- availability policy
- access policy
- retention policy
- provenance
- source operation
- source patch
- source run/task
- encryption envelope

Privacy classes:

```text
local_ephemeral
scoped_private
shared_encrypted
public_plaintext
```

Core rule:

> File availability and file readability are separate concerns.

Ciphertext may be broadly available by hash while plaintext remains
capability-gated.

## 13.2 Artifact Bundles

Bundles group related artifacts:

- screenshots
- traces
- generated reports
- notebooks
- code bundles
- export packages
- validation outputs
- evidence sets
- projection checkpoints

## 13.3 Receipts

Receipts bind important actions to evidence.

Receipt types:

```text
PatchReceipt
ValidationReceipt
MergeReceipt
SettlementReceipt
QueryReceipt
ExecutionReceipt
PromotionReceipt
ProjectionReceipt
PolicyDecisionReceipt
MigrationReceipt
BackupReceipt
RepairReceipt
```

A receipt may bind:

- actor
- action
- intent
- patch
- policy
- validation result
- source state root
- result state root
- artifact bundle
- query result commitment
- projection checkpoint
- capability scope

---

# 14. Policy Arm

Policy governs:

- read visibility
- patch scope
- mutation authorization
- transaction admission
- merge eligibility
- settlement eligibility
- SQL endpoint access
- subscription access
- file/artifact access
- key release
- export
- promotion
- retention
- repair
- migration
- side effects

Every important policy decision can emit:

```yaml
PolicyDecision:
  actor: agent:planner_17
  action: settle_patch
  resource: Run:run_123
  capability_scope: tenant_member
  policy_hash: p_abc
  decision: allow
  constraints:
    - lease_valid
    - actor_can_advance_run
    - validation_receipt_present
  expiry: 2026-04-29T19:00:00Z
  receipt_ref: receipt_123
```

Policy should be unified across database state, files, queries, patches, agents,
and execution.

---

# 15. Execution and Side Effects

Agents do not only edit state. They act.

Agentgres must model side effects as receipted, policy-bound flows.

Execution lifecycle:

```text
ExecutionIntent
-> ExecutionRequest
-> Approval or CapabilityLease
-> Attempt
-> ExecutionReceipt
-> Result Patch
-> Validation
-> Settlement
```

External side effects must not be confused with canonical mutation.

Example:

```yaml
execution_request:
  tool: send_email
  actor: agent:ops_4
  risk_class: medium
  input_refs:
    - Document:draft_email
  required_approval: human
  idempotency_key: idemp_123
```

After execution:

```yaml
execution_receipt:
  request_id: request_123
  outcome: sent
  external_ref: provider_message_456
  evidence_bundle: bundle_789
```

The result may then be patched into canonical state.

---

# 16. Schema and Migration

Agentgres schema is canonical.

Schema includes:

- object classes
- relations
- patch types
- mutation aliases
- constraints
- indexes
- projections
- policies
- file/artifact classes
- migration plans
- generated client APIs

Migration classes:

```text
additive
transform
projection
constraint_introduction
index_backfill
breaking
historical_replay
policy_migration
client_schema_migration
```

Every migration exposes:

- source schema
- target schema
- affected objects
- affected relations
- affected patches
- affected indexes
- affected projections
- validation status
- backfill status
- activation point
- rollback or repair plan
- migration receipt

No migration may silently reinterpret canonical history.

---

# 17. Storage Architecture

Agentgres should not bind semantics to one storage engine.

It defines storage planes:

```text
canonical operation log
canonical object state
patch branches
live edit sessions
constraint indexes
serving indexes
projection checkpoints
projection delta logs
local client cache
artifact manifests
receipts
backup snapshots
```

## 17.1 Storage Invariant

> Storage engines do not define Agentgres semantics. Agentgres operations,
> patches, constraints, state roots, schemas, and receipts define semantics.

## 17.2 Local Client Profile

For browsers/devices:

- IndexedDB or OPFS
- local relations
- local projections
- local indexes
- mutation queue
- patch state
- subscription cursors
- artifact manifests
- checkpoint cache

## 17.3 Embedded Node Profile

For small/medium nodes:

- append-only operation segments
- embedded key-value/object store
- constraint indexes
- serving indexes
- projection checkpoints
- local artifact store

## 17.4 High-Ingest Server Profile

For server deployments:

- append-only operation log segments
- LSM-class engine for high-write indexes/projections
- object storage or CAS for artifacts/checkpoints
- replicated checkpoints
- partition-aware ordering domains

## 17.5 Canonical Commit Hot Path

May include:

- operation validation
- policy checks required for validity
- deterministic object transition
- commit-critical constraints
- commit-critical indexes
- log append
- state root update
- minimal projection delta

Must not include by default:

- heavy search indexing
- semantic enrichment
- broad fanout
- proof-heavy receipt generation
- large file transfer
- expensive projection rebuilds
- analytical aggregation

---

# 18. Ordering, Partitioning, and Scaling

Agentgres must be honest about write scaling.

Single ordering domains do not scale writes by adding replicas.

Every high-volume object class declares:

```yaml
partition_key: tenant_id
ordering_scope: tenant
ownership_rule: home_region_or_shard
```

Default rule:

> Serialize only within the smallest correctness-preserving domain.

Write scaling comes from:

- tenant partitioning
- object-family partitioning
- explicit sharding
- sagas
- escrow
- scoped ordering
- deterministic merge rules

Read scaling comes from:

- local client caches
- static snapshots
- projection checkpoints
- materialized views
- replicas
- subscription workers
- CDN/CAS/object storage for artifacts

Agentgres must not hide global coordination behind friendly APIs.

---

# 19. Import, Export, and Compatibility

Agentgres must be able to meet developers where they are.

## 19.1 Postgres Migration

Stages:

1. Mirror existing Postgres schema and data into Agentgres relations.
2. Dual-write with divergence detection and receipts.
3. Agentgres authority with Postgres as sink.
4. SQL endpoint cutover for read consumers.
5. Postgres retirement or retention as analytics/legacy target.

Migration tooling supports:

- schema introspection
- data import
- constraint mapping
- index mapping
- relation mapping
- patch/mutation mapping
- backfill validation
- row-to-object lineage
- divergence reports
- rollback

## 19.2 Git Compatibility

For code/state repositories, Agentgres should support:

- import from Git
- export to Git commits
- patch branches to Git branches
- validation receipts as commit metadata or notes
- merge receipts
- generated artifact receipts
- immutable audit trails

Git may remain an export/archive format.

Agentgres owns the live, leased, semantic collaboration model.

## 19.3 SQL Compatibility

SQL is an interface, not the authority model.

SQL reads query declared relations/projections.

SQL writes compile into Agentgres patches.

## 19.4 External Sinks

Agentgres may export to:

- Postgres
- warehouse
- search engines
- object stores
- Git
- analytics systems
- reporting tools

External sinks are not canonical authority unless explicitly imported through a
governed ingress flow.

---

# 20. Operator Tooling

Agentgres must be inspectable.

Required commands:

```bash
agentgres schema inspect
agentgres schema migrate
agentgres relation inspect runs
agentgres object inspect Run run_123
agentgres object history Run run_123
agentgres patch inspect patch_789
agentgres patch validate patch_789
agentgres patch merge patch_789
agentgres operation inspect op_999
agentgres transaction inspect tx_123
agentgres constraint validate unique_task_slug_per_tenant
agentgres index backfill runs_by_tenant_created_at
agentgres projection lag
agentgres projection rebuild approval_inbox
agentgres query explain "SELECT ..."
agentgres backup create
agentgres restore verify
agentgres tenant export tenant_123
agentgres artifact verify bundle_123
agentgres receipt inspect receipt_123
agentgres repair backlog
```

Operator surfaces expose:

- canonical height
- state root
- schema version
- patch backlog
- validation backlog
- merge queue
- migration status
- constraint health
- index health
- projection lag
- checkpoint debt
- subscription lag
- repair backlog
- artifact availability
- policy latency
- key-release latency
- local/static read hit rate
- runtime wake rate

If operators cannot inspect it, Agentgres cannot replace Postgres, Git, or
workflow systems.

---

# 21. Developer Experience

Developer experience is the migration weapon.

Agentgres must ship:

- schema DSL
- generated TypeScript SDK
- generated Rust SDK
- generated SQL metadata
- migration generator
- local dev server
- test harness
- seed data tools
- fixture replay
- deterministic simulation
- visual studio/admin console
- SQL endpoint
- Postgres import/export
- Git import/export
- React bindings
- offline/local-first bindings
- patch authoring UI
- query planner explain
- receipt viewer

A developer should be able to start with:

```bash
agentgres init
agentgres dev
agentgres schema create
agentgres generate
```

Define:

```yaml
object: Task
relation: tasks
patches:
  - create
  - update_status
  - archive
queries:
  - list_by_tenant
  - board
```

Then get:

```ts
agentgres.query.tasks.listByTenant(...)
agentgres.change.tasks.create(...)
agentgres.patch.tasks.updateStatus(...)
agentgres.subscribe.tasks.board(...)
```

And:

```sql
SELECT * FROM tasks WHERE tenant_id = $1;
```

Agentgres must feel easier than:

```text
Postgres + ORM + Redis + Temporal + S3 + Git + websocket server + sync engine + audit tables
```

If Agentgres is more correct but harder, existing stacks win.

---

# 22. Benchmarks That Matter

Agentgres should benchmark against stitched stacks, not single systems.

## 22.1 CRUD Benchmark

- users
- tenants
- tasks
- unique constraints
- references
- pagination
- dashboard counts
- migrations
- backup/restore

Goal:

> Ordinary app development should not force teams back to Postgres.

## 22.2 Agent Workflow Benchmark

- tasks
- runs
- approvals
- retries
- execution receipts
- artifacts
- timeline
- repair

Goal:

> Agentgres should beat Postgres plus workflow/audit glue.

## 22.3 Live Collaboration Benchmark

- multiple agents editing the same document/code/object
- scope leases
- semantic conflict detection
- validation
- merge decisions
- settlement

Goal:

> Agentgres should beat Git branch chaos for agent swarms.

## 22.4 Local-First Benchmark

- offline mutation
- reconnect
- checkpoint hydration
- subscription resume
- local reads
- conflict resolution

Goal:

> Agentgres should make local-first behavior native.

## 22.5 Zero-to-Idle Benchmark

- app open from local cache
- static checkpoint render
- no-runtime read success rate
- runtime wake frequency
- runtime idle recovery
- live tail reconnect

Goal:

> Most steady-state reads should not require an always-hot server.

## 22.6 Migration Benchmark

- import Postgres
- map schema
- map constraints
- expose SQL
- cut over writes
- validate divergence

Goal:

> Migration should be credible, not theoretical.

---

# 23. Minimum Viable Agentgres v2

The first serious version should ship a complete vertical slice, not every
possible feature.

Required foundation:

- canonical operation log
- deterministic object state
- patch lifecycle
- scope leases
- validation receipts
- merge decisions
- canonical settlement
- native relations
- primary keys
- unique constraints
- reference constraints
- check constraints
- commit-critical indexes
- serving indexes
- single-domain transactions
- local speculative transactions
- read consistency levels
- generated TypeScript SDK
- React bindings
- embedded client runtime
- IndexedDB/OPFS persistence
- SQL read endpoint
- limited SQL write-to-patch compiler
- materialized projections
- subscriptions with resume
- schema migrations
- backup/restore
- artifact refs
- lightweight receipts
- Postgres import
- Git export for code patches
- Agentgres Studio/CLI
- query explain
- projection lag
- patch/merge inspection

Deferred:

- arbitrary SQL parity
- global serializable transactions
- full Postgres wire compatibility
- advanced semantic code merge
- broad encrypted search
- fully general graph queries
- automatic multi-region split/merge
- proof-heavy receipts by default
- public chain anchoring as mandatory
- universal Git replacement

V1 goal:

> Build one serious production app where Postgres, Git-based agent coordination,
> custom sync, audit tables, and workflow glue all feel like the old way.

---

# 24. Failure Modes

Agentgres fails if:

- patch lifecycle feels bolted on
- relations feel bolted on
- SQL is too weak for migration
- client runtime is optional or fragmented
- local-first conflicts are mysterious
- scope leases are too heavy for normal work
- developers must manually manage projections
- migrations are harder than Postgres migrations
- operator tooling is poor
- validation receipts become bureaucracy
- merge semantics are unclear
- projection lag surprises users
- cross-domain coordination is hidden
- backup/restore cannot verify artifacts and receipts
- Git export loses important provenance
- Postgres remains necessary for ordinary relational reads
- every app invents its own change lifecycle
- the system is architecturally superior but ergonomically inferior

Most dangerous failure mode:

> Agentgres becomes a beautiful theory of state change that developers avoid
> because Postgres and Git are easier.

---

# 25. Success Criteria

Agentgres succeeds when a team can build an application with:

- users
- tenants
- roles
- tasks
- runs
- approvals
- documents
- code patches
- artifacts
- generated files
- notifications
- dashboards
- subscriptions
- SQL reporting
- migrations
- backup/restore
- local-first offline behavior
- multi-agent collaboration
- validation-gated merges
- receipts
- zero-to-idle serving

without deploying Postgres as authority, without using Git as the live agent
coordination layer, and without building custom sync/audit/workflow glue.

It succeeds when:

1. agents propose scoped patches instead of directly mutating truth
2. accepted patches settle into deterministic canonical state
3. rows become views over settled truth
4. relations replace ordinary app tables
5. projections replace hand-built materialized views
6. embedded client runtime replaces custom sync/cache glue
7. patch branches replace ad hoc agent workspaces
8. validation receipts replace informal CI/audit conventions
9. file/artifact refs replace blob metadata tables
10. subscriptions replace custom websocket state
11. SQL endpoint replaces most read-only Postgres consumers
12. migration tooling makes Postgres cutover credible
13. Git remains the compatibility/archive substrate, not the live coordination layer
14. zero-to-idle serving becomes normal
15. developers find Agentgres easier than the stitched stack

---

# 26. Sharpest Bottom Line

**Agentgres is the state layer for autonomous software.**

It generalizes the best parts of Postgres, Git, and Google Docs:

- Postgres gives relations, constraints, transactions, and SQL.
- Git gives history, branches, patches, and commits.
- Google Docs gives live concurrent collaboration.
- Agentgres adds scopes, validation, policy, receipts, deterministic settlement,
  local-first projections, and zero-to-idle serving.

The final doctrine:

> **All state changes are patches. All accepted patches settle into truth. All
> truth is queryable from the nearest verifiable view.**

That is the Agentgres v2 thesis.

---

# 27. Addendum: Git and IDE Overlay Implementation Plan

Agentgres should not modify the underlying VS Code OSS Git integration or the
`.git` working tree semantics as the initial implementation move.

The safer and stronger architecture:

> **Build Agentgres on top of traditional Git as an overlay/sidecar
> coordination layer, then settle/export back into normal Git commits when
> appropriate.**

That preserves compatibility with:

- VS Code OSS
- Cursor
- Antigravity-style IDEs
- Git CLI
- GitHub/GitLab
- existing repositories
- existing hooks
- existing branch workflows
- existing uncommitted local changes

It also lets Autopilot add agent-native behavior without corrupting the
expectations of a normal repository.

## 27.1 Layer Split

Think of the implementation as three layers:

```text
Normal workspace directory
  -> files on disk
  -> .git directory
  -> existing VS Code Git extension / SCM UI

Agentgres workspace overlay
  -> patch branches
  -> scope leases
  -> agent work items
  -> semantic diffs
  -> validation receipts
  -> merge receipts
  -> conflict prediction
  -> provenance

Settlement/export layer
  -> applies accepted patches to working tree
  -> stages files
  -> creates normal Git commits
  -> optionally writes Agentgres receipt metadata
```

Git remains the lowest common denominator artifact/history format.

Agentgres becomes the coordination and settlement brain.

## 27.2 Why Not Modify VS Code or Git Directly

Changing underlying Git behavior risks breaking the thing users trust most:
a repository opened in VS Code, terminal Git, another IDE, or CI should show the
same working tree and the same Git state.

If Autopilot changes Git semantics too early, it creates dangerous edge cases:

- VS Code shows one set of changes while Agentgres thinks another state is canonical.
- Another IDE edits the same files while Agentgres has a lease.
- Git CLI reset/rebase/stash invalidates Agentgres assumptions.
- Existing hooks and branch protection behave unexpectedly.
- Users lose trust because `.git` no longer means normal Git.
- Third-party tooling breaks because state is hidden outside normal Git expectations.

Early Agentgres should avoid that risk.

## 27.3 Build Above Git, Observe Everything

The better approach is an overlay that watches Git and the filesystem.

Agentgres should observe:

- current branch
- HEAD commit
- working tree status
- index/staged files
- untracked files
- ignored files
- file change events
- external edits
- stashes/rebases/resets/checkouts
- merge conflicts
- lock files
- Git hook outcomes

Then Agentgres maps that into its own state:

```text
Git working tree changed externally
-> Agentgres detects drift
-> invalidates affected leases/patches
-> rebases or marks conflicts
-> updates live workspace/projections
-> asks for validation/repair if needed
```

This is what lets multiple IDEs coexist.

## 27.4 Sidecar Model

Agentgres metadata should live outside `.git` initially.

For repo-local metadata:

```text
repo/
  .git/
  .agentgres/
    workspace.db
    patches/
    receipts/
    leases/
    projections/
    snapshots/
    metadata.json
```

For private/local agent state:

```text
~/.agentgres/workspaces/<repo-fingerprint>/
```

Best approach:

- local sidecar metadata for project-portable state when desired
- global workspace store for private/local agent state
- optional Git-tracked metadata only for things the user intentionally wants to share

Do not put all Agentgres metadata into Git by default. Agent traces, prompts,
receipts, and local patch branches can be noisy or sensitive.

## 27.5 Git Interaction Adapters

Agentgres should treat Git as an external state surface with adapters.

### Read Adapter

Reads current Git state:

```text
HEAD
branch
index
working tree diff
untracked files
merge state
submodules
remotes
```

### Write Adapter

Applies accepted changes through normal mechanisms:

```text
write files
git add
git commit
git stash
git branch
git switch
git merge
```

### Receipt Adapter

Optionally attaches metadata:

```text
commit trailers
git notes
sidecar receipt refs
signed tags
artifact bundles
```

Example commit trailer:

```text
Agentgres-Patch: patch_abc123
Agentgres-Validation: receipt_def456
Agentgres-Merge: merge_789
```

### Drift Adapter

Detects external changes:

```text
VS Code edit
terminal git reset
external IDE patch
manual merge
branch switch
```

Then updates Agentgres state accordingly.

## 27.6 Key Design Rule

> **Agentgres must never assume it exclusively owns the working tree.**

It should assume the repository is shared with humans, other IDEs, Git CLI, and
other agents.

Therefore every Agentgres patch should bind to:

```text
repo fingerprint
base commit
base file hashes
target paths/regions/symbols
expected prior content
scope lease
validation status
```

Before settlement, Agentgres checks whether those expectations still hold.

If not:

```text
rebase
repair
conflict
reject
ask for review
```

## 27.7 Leases Without Breaking Git

Leases should be advisory/overlay-level at first, not filesystem locks.

Example:

```text
Agent A leases src/auth/session.ts:function validateSession
Agent B can still technically edit the file in VS Code
Agentgres detects external edit
Agentgres marks lease contaminated/conflicted
Agentgres rebases or blocks settlement
```

Do not use hard file locks by default. They will annoy developers and break
normal IDE workflows.

Use three lease modes:

```text
advisory
  warn on conflict, do not block external tools

managed
  Autopilot agents respect leases internally

exclusive
  optional mode for fully controlled workspaces/CI sandboxes
```

For normal developer machines, use advisory plus managed leases.

For autonomous adaptive work graph sandboxes, use exclusive leases.

## 27.8 Best Workflow

### Open Repo Normally

The user opens a normal Git repo in Autopilot/VS Code OSS.

VS Code Git integration works as usual.

### Index Workspace

Agentgres records:

```text
repo root
HEAD
branch
file hashes
language graph
current working tree changes
```

### Start Work

Agentgres creates:

```text
WorkItem
ScopeLease
PatchBranch
ValidationPlan
```

This is overlay state, not necessarily a Git branch.

### Edit in Virtual Patch Space or Working Tree

Safer mode:

```text
agent patch branch
-> semantic diff
-> validation
-> apply to working tree on approval
```

Faster mode:

```text
file edit
-> Agentgres patch record
-> validation
-> user review
-> git commit
```

Support both. Default to virtual patches for multi-agent work.

### Validate

Agentgres runs:

```text
format
lint
typecheck
tests
semantic checks
scope checks
receipt checks
```

### Settle

Accepted patches apply to the working tree, stage files, and commit through
normal Git:

```text
Agentgres patch accepted
-> apply files
-> git add
-> git commit
-> attach receipt metadata
```

### Preserve Compatibility

Open the same repo in VS Code, another IDE, or terminal Git, and it is still
just Git.

## 27.9 Agentgres Patch Branches Are Not Git Branches

Agentgres patch branches do not need to be Git branches.

Git branches are coarse and visible globally. Agentgres may need many
micro-branches:

```text
candidate patch A
candidate patch B
repair patch
validation patch
generated artifact patch
doc-only patch
test-only patch
```

Represent these internally as Agentgres patch branches. Create Git branches only
when useful for human or external tooling.

Rule:

```text
Agentgres patch branch != Git branch
```

But it can export to one.

## 27.10 Existing Local Changes

This is critical.

When a repository already has uncommitted changes, Agentgres should classify
them:

```text
clean base
tracked modified
staged
untracked
conflicted
ignored
external dirty
```

Then each patch must choose a base mode:

```text
base_on_HEAD
base_on_working_tree
base_on_staged_index
base_on_named_snapshot
```

Safety defaults:

- if clean: base on `HEAD`
- if dirty: create a `WorkspaceSnapshot` of the current working tree
- bind the patch to that snapshot
- never overwrite unrelated dirty files

Agentgres should explicitly track:

```text
This patch was authored against:
- HEAD abc123
- plus local modifications hash xyz789
```

That avoids destroying user work.

## 27.11 Coexisting With Other IDEs

Use a filesystem watcher plus Git status watcher.

When external changes happen:

```text
ExternalChangeDetected
  path: src/foo.ts
  previous_hash: h1
  new_hash: h2
  source: unknown/external
  affected_patches:
    - patch_123
  action:
    - rebase_required
```

Agentgres then marks affected patches:

```text
clean
stale
conflicted
contaminated
needs_rebase
needs_revalidation
```

This is where Agentgres adds value over Git.

## 27.12 Adapter Strategy

Adapters are the right solve.

Define:

```text
GitAdapter
  read/write normal Git state

VSCodeAdapter
  integrate with SCM UI, file explorer, diagnostics, editors

AgentPatchAdapter
  manage patch branches, leases, validation, merge receipts

WorkspaceAdapter
  observe files, language server, symbols, diagnostics

SettlementAdapter
  commit, tag, note, push, PR

ExternalIDEAdapter
  initially detect through filesystem/Git drift rather than direct integration
```

Do not require every IDE to speak Agentgres initially. Make Agentgres robust to
tools that only speak files plus Git.

## 27.13 VS Code OSS Integration

Use VS Code OSS as the familiar workbench:

- SCM panel still shows Git changes.
- Agentgres panel shows patch branches, work items, leases, and validations.
- Diff editor can show Agentgres semantic diffs.
- Problems panel can include validation diagnostics.
- Timeline can show patch/receipt history.
- Source Control can include "Settle Patch as Git Commit."
- File decorations can show leased/conflicted/agent-edited files.

Under the hood, the VS Code Git extension remains untouched by default.

Autopilot adds a parallel Agentgres view, not a replacement for Git SCM.

Recommended architecture:

```text
VS Code OSS Workbench
  |-- normal Git extension / SCM
  |-- Agentgres activity panel
  |-- patch branches view
  |-- leases/conflicts view
  |-- validation receipts view
  `-- settlement/commit actions

Workspace Directory
  |-- files
  |-- .git
  `-- optional .agentgres pointer/config

Agentgres Runtime
  |-- Git adapter
  |-- file watcher
  |-- language graph
  |-- patch store
  |-- lease manager
  |-- validation runner
  |-- merge engine
  `-- settlement adapter
```

## 27.14 When to Modify Git Behavior

Modify Git behavior only later, and only in controlled contexts.

Possible later enhancements:

- custom Git merge driver
- custom diff driver
- Git notes for receipts
- pre-commit hook for Agentgres validation
- post-commit hook to bind receipts
- virtual filesystem for patch previews
- worktree-based isolation
- sparse checkout integration
- LFS/artifact adapter
- commit signing with Agentgres receipt root

These should be optional integrations, not baseline assumptions.

## 27.15 Implementation Phases

### Phase 1: Observe and Overlay

- leave Git untouched
- read Git status
- watch files
- create Agentgres patch records
- validate changes
- show patch/receipt UI

### Phase 2: Virtual Patch Branches

- agent edits in overlay
- preview semantic diff
- apply to working tree only on acceptance
- support rebase against external changes

### Phase 3: Git Settlement

- accepted patches become normal Git commits
- attach receipt metadata
- optional Git notes/tags/trailers
- generate PRs

### Phase 4: Deep IDE Integration

- VS Code activity panel
- SCM decorations
- lease indicators
- validation receipts
- semantic merge UI

### Phase 5: Optional Git Extensions

- hooks
- merge drivers
- receipt signing
- worktree isolation
- custom conflict drivers

## 27.16 Implementation Doctrine

Build on top of existing Git/VS Code infrastructure, not by replacing it at the
root.

The doctrine:

> **Git remains the compatibility substrate. Agentgres becomes the
> coordination, validation, and settlement layer above it.**

The implementation shape:

```text
normal .git stays normal
VS Code Git integration stays normal
Agentgres watches, overlays, leases, validates, and settles
accepted patches export back into normal Git commits
```

That gives Agentgres the best of both worlds: no ecosystem breakage, plus a path
to a much better multi-agent workflow.
