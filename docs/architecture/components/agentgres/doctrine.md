# Agentgres State Substrate Specification

Status: canonical architecture authority.
Canonical owner: this file for high-level Agentgres doctrine; low-level runtime objects live in [`agentgres-api-and-object-model.md`](./api-object-model.md), and Postgres bridge/readiness guarantees live in [`postgres-bridge-and-readiness-contract.md`](./postgres-bridge-and-readiness-contract.md).
Supersedes: overlapping plan prose when Agentgres state ownership conflicts.
Superseded by: none.
Last alignment pass: 2026-06-23.
Doctrine status: canonical
Implementation status: partial (runtime state store and object planes in the daemon; branch lane partial — thread forks, run replay, counterfactual what-if replay, and workspace snapshot/restore custody exist; the five branch/staged-effect durable objects are planned)
Implementation refs:
  - `crates/services/src/agentic/runtime/`
Last implementation audit: 2026-07-05

## Canonical Definition

**Agentgres is the canonical operational state substrate for Web4 domains.**

It records what happened, what changed, why it changed, who authorized it, what
evidence supports it, how it can be queried, and how future workers or agents
can reuse it.

In the Hypervisor/daemon canon, the Hypervisor Daemon is the hypervisor/control plane
for autonomous execution and Agentgres is the operational truth substrate behind
that control plane. Hypervisor App, Hypervisor Web, CLI/headless clients,
optional TUI views, and application surfaces such as Workbench, Foundry, and
Environments views may render Agentgres-backed projections, but they must not become the
canonical state store.

In the machine-economy canon, Agentgres is the local/domain operational truth
substrate for governed autonomous-system chains and Hypervisor Node settlement
domains. It records proposals, module invocations, local settlement records,
receipt roots, upgrade decisions, state roots, and replayable projections before
selected commitments are anchored to IOI L1.

Agentgres does not run on IOI L1. It runs inside application-domain kernel deployments.

## Core Doctrine

> **All state changes are patches. All accepted patches settle into truth. All truth is queryable from the nearest verifiable view.**

Database doctrine:

> **Rows are views. Settled state is truth.**

Postgres bridge doctrine:

> **Agentgres may expose Postgres-compatible projections and SQL-facing bridges, but its source of truth is operation-backed state, not mutable relational rows.**

State/payload doctrine:

> **Agentgres is the ledger of what is true; storage backends are warehouses for the bytes that prove it.**

Portable state doctrine:

> **Agentgres is not merely a mutable database. It treats state as operation-derived, root-addressed, and exportable into encrypted content-addressed archives. This allows workers, runtimes, and domains to suspend, migrate, restore, and verify state without making any blob store the canonical authority.**

Agent execution branch doctrine:

> **Git versions code. Agentgres versions autonomous work.**

Agentgres must treat serious agent work as branchable, replayable execution
state, not only as an event log after the run finishes. A branch may include
source diffs, but it is broader than Git: it binds the workspace snapshot,
operation/effect trace, memory projection, tool and connector leases, model
route, harness session, artifact refs, policy posture, authority decisions,
receipt roots, and replay metadata for a bounded line of work.

The default shape is:

```text
agent proposes effects
  -> Agentgres records intent and outcome refs
  -> effects remain staged until admission/authority/merge policy accepts them
  -> execution branches compare alternatives without overwriting canonical heads
  -> canonical heads advance only through expected-head merge and receipts
  -> rejected branches remain evidence, training signal, or replay material
```

**Admission freshness rule.** A staged effect is not an authority time
capsule. The policy/authority decisions captured at stage time are evidence of
what was held then; admission re-validates every staged effect against the
*current* revocation epoch, grant expiry, and policy hash at merge time
(INV-1, INV-5 — [`../../foundations/invariants.md`](../../foundations/invariants.md);
revocation epochs are owned by
[`../wallet-network/doctrine.md`](../wallet-network/doctrine.md)). Stale,
expired, or revoked authority forces re-authorization before the effect can
materialize, and the admission receipt binds the revocation epoch it checked.
The same rule governs replay: a replayed effect executes under fresh authority
and mints new receipts — replay never re-spends an old grant or reuses old
receipts as proof of a new crossing.

**Merge strategy classes.** Admission-shaped merge is the default, but not
every object head needs adjudication. A `BranchMergePlan` resolves each
touched object head into one of three classes:

```text
exclusive_owner
  exactly one branch wrote this head since the fork point
  merge is trivially safe; admit on expected-head check alone
  (the overwhelmingly common case for agent state — ownership partitioning
  is the throughput lever, not global ordering)

declared_commutative
  the object class explicitly declares commutative merge semantics
  (append-sets, counters, monotone accumulators); auto-mergeable,
  but only where the class declaration says so — never inferred

adjudicated
  everything else: policy evaluation, verification gates, or human review
  decide; this is the default when no other class applies
```

State merge is never text merge: no diff3-for-memory, no heuristic conflict
resolution inside canonical truth. A head that cannot be classified is
`adjudicated`. The freshness rule above applies to all three classes.

Implementation status (this lane): partial. Thread forks (`thread.forked`),
run replay, counterfactual what-if replay (improvement simulation), and
workspace snapshot/restore custody exist in the daemon today; the durable
`AgentExecutionTrace` / `AgentExecutionBranch` / `StagedEffect` /
`BranchCheckpoint` / `BranchMergePlan` objects are planned over that substrate
(see [`../../_meta/implementation-matrix.md`](../../_meta/implementation-matrix.md)).

This does not replace Git. Git remains the source-code version-control system.
Agentgres records the autonomous-work state around Git: why the branch exists,
what the agent saw, what it attempted, what authority it held, which effects
were staged, which receipts prove the path, and which merge/admission decision
made it canonical.

Agentgres should be described publicly as a canonical state substrate with a
Postgres bridge. Builder-facing docs may call it a Postgres-compatible
operational substrate for worker-produced state. Avoid unqualified "Postgres
replacement" language unless the context is an internal ambition. The precise
claim is that Agentgres replaces row-centric databases as canonical truth when
state is produced by workers, scoped authority, artifacts, receipts,
projections, and settlement mirrors.

## Substrate Contract Doctrine

Implementation status (this section): planned contract over the existing
daemon state store; the deterministic Rust `plan_*`/`project_*` cores already
have the required admission shape.

**The substrate contract is the product; engines are implementations.** The
Agentgres contract is five verbs — `append` (operation log), `validate`
(admission), `advance-head` (expected-head commit), `root` (state
commitment), `project` (derived views) — plus archive/restore from the
artifact-ref plane. Any engine hosting those verbs under the invariants is an
Agentgres substrate. Postgres is the reference **projection and durability
host**, never the admission owner: the admission path must not depend on
mutable relational rows being truth (INV-10).

**Ownership-partitioned serialization.** Truth is partitioned by ownership so
that admission of shared canonical heads is the *only* serialization point:
one deterministic writer per domain; execution branches are exclusively owned
until merge and proceed lock-free in parallel; a `BranchMergePlan` settles a
branch's staged effects as one batched admission. Global ordering is never
required across domains. (This is the generalized lesson of owned-object
fastpaths in high-throughput systems: exclusive ownership needs no
coordination; only shared-state admission does.)

**Determinism rule.** The admission core is a deterministic state machine:
no wall clock, no ambient randomness, no thread nondeterminism inside
admission logic. Nondeterminism enters only as recorded operation inputs.
This is what makes replay exact, counterfactual simulation honest, and the
substrate testable under accelerated-time deterministic simulation
(FoundationDB/TigerBeetle-class fault injection). Determinism is preserved
from day one; it cannot be retrofitted.

**Batch rooting rule.** State roots are computed per admitted batch, never
per operation; receipts bind operation *ranges* to roots (as
`AgentExecutionTrace.operation_range` already does). Root-per-op write
amplification is a rejected design. Merkleization is incremental and
content-addressed so branches share structure and diffs are computable
(Prolly-tree / JMT-class structures when the dedicated engine lands).

**Performance contract.** Agentgres's performance metrics are, in order:

```text
1. admission latency        p99 of the effect gate on the agent's critical path
2. projection freshness     watermark lag from admitted op to queryable view
3. fork/checkpoint/restore  branch creation is O(delta), not O(copy)
```

Raw TPS is explicitly not the contract; agent workloads are
thousands-of-admissions-per-second with heavy per-op policy evaluation, and
a substrate that wins the three metrics above beats one that wins benchmarks.

**Scale-down doctrine.** Agentgres scales down before it scales out: an
embedded engine profile (SQLite/libSQL/redb-class) may host the substrate
contract for local-first daemon deployments, with the Postgres bridge
appearing in server/org deployments. Local-first custody of governed truth
on a laptop daemon is a differentiator, not a degraded mode.

**Lineage and the cautionary tale.** The architectural ancestry is
Datomic-class (immutable facts, single-writer transactor, reads scaled
through peers, time-travel queries) plus what that lineage never had:
authority binding, receipts, branches, merkle roots, and sealed archives.
The failure mode to avoid is QLDB-class: an immutable ledger without an
ecosystem or query story dies regardless of correctness. Therefore the
Postgres wire bridge is survival strategy, not compatibility concession, and
"immutable ledger" is never the headline — governed, receipted,
Postgres-compatible operational truth is.

**SQL writes as intents.** On the bridge, `SELECT` is a plain projection
read with a freshness watermark; a write arriving over the Postgres wire is
never a direct mutation — it becomes a proposed operation that enters the
same intent → validate → policy/authority → admission → receipt pipeline as
any worker effect. "It speaks Postgres, but every write is governed,
receipted, and replayable" is the bridge's product claim; the contract shape
is owned by
[`postgres-bridge-and-readiness-contract.md`](./postgres-bridge-and-readiness-contract.md).

Time-travel reads (`AS OF` over the operation log, XTDB/Datomic-class) are a
planned projection capability: "what did the agent know when it decided" is
an audit/dispute surface, not a novelty.

## Product Presentation

Agentgres is an owner term, not default product copy. Product surfaces should
usually speak in terms of **Work Ledger**, **run history**, **evidence**,
**receipts**, **state history**, **archives**, and **replay**. The Agentgres
name belongs in builder, protocol, audit, export, and implementation contexts
where the user needs to understand the state substrate, Postgres bridge,
operation log, state roots, archive/restore validity, or projection mechanics.

Examples:

```text
Product surface: Review evidence for this run.
Admin surface: Export work-ledger receipts for this project.
Developer surface: Inspect Agentgres operation refs and projection watermarks.
Protocol surface: Verify Agentgres state root and archive refs.
```

This keeps product flows readable without weakening the rule that Agentgres owns
admitted operational truth.

## What Agentgres Owns

Agentgres owns per-domain operational truth:

- hot operational state;
- canonical operation log;
- deterministic object state;
- object heads;
- commit-critical constraints;
- commit-critical indexes;
- schema and migration lifecycle;
- operation-log durability and replay state;
- patch/change lifecycle;
- runs;
- tasks;
- worker installs;
- managed worker/agent instances;
- governed autonomous-system chain records;
- Hypervisor Node local settlement records;
- service module manifests and registry roots;
- module invocation records;
- proposal queues;
- upgrade decisions;
- runtime subscription and usage state;
- orders;
- workflow state;
- domain ontologies;
- canonical object models;
- data recipes;
- connector mappings;
- policy-bound data views;
- transformation runs and receipt refs;
- evaluation dataset refs;
- ontology-aware projection definitions;
- ontology-to-worker plans;
- Worker Training specs;
- training lineage;
- dataset commitments;
- context mutations and supersession graphs;
- post-training cycles;
- promotion and rollback decisions;
- benchmark and evaluation state;
- MoW routing decisions;
- delivery bundles;
- artifact refs;
- receipt metadata;
- policy decision records;
- quality ledgers;
- contribution accounting;
- execution traces;
- execution branches;
- staged effects;
- branch checkpoints;
- branch merge/admission plans;
- projections;
- subscriptions;
- search/ranking views;
- import/export state;
- sealed state archive refs;
- backup/restore metadata.

## What Agentgres Does Not Own

Agentgres does not own:

- raw secrets;
- root user authority;
- raw wallet keys;
- payment keys;
- connector refresh tokens;
- IOI L1 smart-contract settlement;
- storage backend payload bytes;
- sealed archive bytes;
- raw source-system payload authority;
- connector mapping authority without an admitted authority grant, policy
  decision, or governance owner ref;
- first-party product pricing, billing strategy, or separate SKU ownership;
- the physical compute resource;
- every local UI hover/draft state;
- private working memory unless promoted;
- draft, fuzzy, local, or speculative memory that has not crossed an admission boundary;
- retrieval candidates, embeddings, full-text indexes, or wiki projections as canonical truth.

Authority providers and domain governance own permission decisions. wallet.network
is the portable delegated authority provider for secrets, provider credentials,
external effects, spend, decryption, declassification, restore/apply,
high-risk approvals, and other portable or consequential authority. Hypervisor
and domain/application governance may own local policy decisions that do not
cross those boundaries. Agentgres records authority refs, policy decisions, and
governance owner refs, and enforces them at admission time, but it is not the
authority provider.

Hypervisor Daemon runtime nodes own execution. Hypervisor clients and
application surfaces own UX/projections. AIIP owns autonomous-work interop
semantics. Storage backends own payload byte availability. IOI L1 owns public
settlement and rights. Hypervisor Nodes coordinate local settlement and interop,
but their operational truth is still recorded through Agentgres/domain
operations rather than client UI state.

Agentgres may record usage, payout, royalty, billing, entitlement, dispute,
settlement, and ContributionReceipt state for the domains it serves. Recording
economic truth does not make Agentgres the monetization surface. In the
first-party stack, routine Agentgres writes, projections, refs, and receipts are
bundled substrate under the product surface that depends on them.

## Memory And Agent Wiki Boundary

Agentgres is not the whole agent brain. It is the canonical state substrate for
admitted truth.

The long-term memory architecture has four distinct planes:

```text
Harness/runtime hot state
  active cognition, scratch state, temporary observations, in-flight plans

Agent Wiki / ioi-memory context plane
  durable semantic memory, wiki pages, preferences, procedures, doctrine,
  route notes, known failures, retrieval surfaces, and local recall policy

Agentgres
  accepted memory mutations, wiki commits, provenance, policy decisions,
  receipts, object heads, projections, archives, and restore metadata

Artifact/storage and projection planes
  wiki source documents, long traces, screenshots, datasets, model artifacts,
  embeddings, full-text indexes, graph views, and archive bytes
```

The live product-memory name is `ioi-memory` and the user-facing/product
surface should be called **Agent Wiki** or **memory**.

The Agent Wiki governs what agents can know, retrieve, and remember. Agentgres
governs which memory changes become canonical, authorized, versioned,
replayable, portable, projected, auditable, or settlement-relevant.

Memory should cross into Agentgres when it becomes:

- user-approved or admin-approved;
- durable across sessions;
- behavior-affecting;
- shared across devices, workers, projects, orgs, or domains;
- policy-relevant;
- training-, evaluation-, benchmark-, or routing-relevant;
- package-, deployment-, promotion-, or restore-relevant;
- supported by evidence, provenance, or receipts;
- subject to supersession, contradiction, deletion, retention, or export rules.

The canonical admission object for semantic memory updates is
`ContextMutation` or an equivalent Agentgres operation. A memory mutation may
add, supersede, contradict, deprecate, activate, archive, or forget a fact,
preference, doctrine item, route rule, procedure, evaluation lesson, or failure
lesson. The mutation should bind evidence refs, authority, policy, receipt refs,
scope, visibility, validity window, and any artifact refs for large wiki
payloads.

Do not model the system as:

```text
all memory = Agentgres rows
```

Model it as:

```text
the agent thinks in the harness
the agent remembers through Agent Wiki / ioi-memory
the agent commits durable memory through Agentgres operations
the agent retrieves through rebuildable projections
the agent stores large memory payloads in artifact storage
authority providers and local/domain policy authorize memory read, mutation,
export, forget, and restore; wallet.network supplies that authority when the
operation requires portable delegated authority, secrets, decrypt/export,
external account access, or high-risk approval
```

## State And Payload Boundary

Encrypted blob-backed state bundles are a defining Agentgres format. Agentgres
should make them first-class without making blob storage the canonical live
database.

Agentgres state MUST NOT be reduced to opaque storage blobs, and Agentgres must
not store agent state in Filecoin/CAS, S3, local disk, or any other storage
backend as canonical live state.

Agentgres stores canonical state in its own domain-local state-engine substrate.
Storage backends such as Filecoin/CAS store large immutable payloads,
artifacts, evidence bundles, checkpoints, snapshots, packages, and archival
data. Agentgres stores refs and commitments to those payloads.

Do not model the system as:

```text
state = storage blobs
```

Model it as:

```text
canonical truth =
  accepted operations
  + object heads
  + state roots
  + receipts
  + local settlement records
  + archive refs

portable state format =
  encrypted content-addressed state archive
  + state root
  + object heads
  + schema version
  + policy hash
  + authority metadata
  + receipt refs
  + replay/import metadata

serving layer =
  projections
  + query surfaces
  + subscriptions
  + SQL bridge

storage backends =
  local disk
  + S3
  + Filecoin/CAS
  + Postgres/SQLite/RocksDB/custom log
```

Agentgres remains the state machine, query substrate, and artifact-ref
meaning/admission/validity plane. Storage backends remain the payload-byte,
archive-byte, and evidence availability layer.

## Storage Engine and SQL Bridge Posture

Agentgres is storage-engine pluggable. It may run over Postgres, SQLite,
RocksDB, object stores, a custom append-only log, or another durable engine.
Those engines provide persistence mechanics; they do not define the Agentgres
authority model.

The canonical Agentgres contract is defined by accepted operations, domain
sequence, object heads, state roots, constraints, invariants, receipts,
projection checkpoints, and replay/recovery guarantees.

SQL and Postgres-compatible surfaces should be read-first over named
projections. Limited SQL writes may be introduced only when they compile into
ordinary Agentgres operations with unambiguous schema, policy, authority, and
constraint handling. Arbitrary SQL writes must not bypass operation settlement.

## Worker Training, Benchmarks, and MoW State

Agentgres owns the canonical operational truth for Worker Training and MoW
routing inside each domain. It records:

- DomainOntology, CanonicalObjectModel, DataRecipe, ConnectorMapping,
  PolicyBoundDataView, TransformationRun, EvaluationDataset,
  OntologyProjection, and OntologyToWorkerPlan state;
- WorkerTraining specs and lifecycle state;
- dataset commitments and source refs;
- accepted/rejected curation summaries;
- training lineage refs;
- context mutation refs and supersession graphs;
- post-training cycle state;
- adapter, route-policy, evaluation, and package promotion decisions;
- EvaluationReceipt and BenchmarkReceipt refs;
- Sparse Worker Category submissions;
- routing candidate-set commitments;
- RoutingDecisionReceipt refs;
- contribution policy refs;
- quality and reputation records;
- payout, royalty, and dispute state derived from ContributionReceipts.

Agentgres does not own the large dataset bytes, trace bundle bytes, model
checkpoint bytes, or sealed archive bytes. Those remain storage backend
payloads referenced by hash/CID. Agentgres also does not grant training or
data-use authority. Authority comes from domain governance and the relevant
authority provider; wallet.network supplies portable delegated authority,
secret custody, key leases, and external or high-risk data permissions when
those boundaries are involved.

Domain Ontologies and Data Recipes are the semantic data plane that makes
Worker Training durable. A worker should not train on raw connector payloads or
unstructured blobs when an ontology exists. The canonical path is:

```text
source refs
-> ConnectorMapping
-> DataRecipe
-> TransformationRun
-> ontology-bound objects / EvaluationDataset / OntologyProjection
-> WorkerTraining / Benchmark / MoW routing
```

Agentgres records this path as operations, object heads, lineage refs,
projection checkpoints, and transformation receipts. Storage backends store
large source snapshots, transformed payloads, datasets, and projection
checkpoint bytes. Domain governance and authority providers decide whether a
worker, runtime, or service may read, transform, train on, evaluate with,
export, publish, or route over the data; wallet.network supplies that decision
path when portable delegated authority, secrets, decryption, external account
access, or high-risk approval is required.

Training improves a worker's capability record. It does not expand the worker's
authority. Any trained worker still needs a manifest, policy envelope, and
bounded authority grants before it can act.

For runtime and agent state, the correct model is:

```text
hot Agentgres state
-> sealed encrypted snapshot/export
-> storage backend payload bytes
-> verified rehydration/import back into hot Agentgres when needed
```

### Agentgres Owns

```text
hot operational state
canonical operation log
object heads
worker installs
managed worker instances
runtime subscriptions
Worker Training specs
training lineage
dataset commitments
benchmark/evaluation state
MoW routing decisions
indexes
constraints
projections
subscriptions
receipt metadata
artifact refs
delivery state
quality/contribution ledgers
sealed state archive refs
restore policy and receipt metadata
```

### Storage Backends Own

```text
worker packages
model artifacts
large files
reports
screenshots/videos
evidence bundles
trace bundles
projection checkpoints
historical snapshots
encrypted archives
sealed state archive bytes
```

## Why State Is Not Storage Blobs

Storage backends such as Filecoin/CAS are optimized for byte availability.
Agentgres needs to manage mutable logical state over immutable evidence.

Agentgres requires:

- low-latency reads;
- transaction admission;
- constraint checks;
- object-head compare-and-set;
- indexes;
- materialized projections;
- subscriptions;
- query planning;
- local-first sync;
- repair/replay;
- small frequent state transitions;
- ordering-domain semantics.

If every state mutation becomes "write a new blob to storage," the system loses
the database properties that make Agentgres useful.

## Layered Storage Path

The scalable path is layered:

```text
1. Hot Agentgres state engine
   Recent canonical operations, object heads, indexes, active projections.

2. Warm Agentgres log/checkpoint store
   Operation segments, projection deltas, receipt metadata, snapshots.

3. Cold durable storage backend plane
   Large immutable payloads, sealed encrypted bundles, checkpoint files, trace
   archives, evidence bundles.

4. IOI L1 contract layer
   Registry, rights, escrow, settlement, dispute roots, selected commitments.
```

Operational flow:

```text
hot state in Agentgres domain storage
-> periodic checkpoints/snapshots to cold artifact storage
-> sealed state archives to Filecoin/CAS or equivalent durable blob stores
-> receipt/evidence bundles to storage backends
-> selected economic/trust commitments to IOI L1
-> local/client projections for read scale
```

## Sealed State Archives And Rehydration

Agentgres may export inactive, idle, suspended, or terminal runtime state into
encrypted content-addressed archives. These archives are portable sealed state
artifacts, not replacements for canonical Agentgres truth.

The lifecycle is:

```text
hot runtime
-> checkpoint periodically
-> idle, suspend, or terminal boundary
-> emit sealed state archive
-> store encrypted archive bytes by CID/hash
-> keep canonical refs and lifecycle metadata hot
-> later verify, decrypt, and rehydrate through Agentgres operations
```

Hot Agentgres retains small canonical records:

```text
Run id
Task id
current lifecycle status
latest state root
archive CID/hash
policy hash
schema version
owner/tenant authority
restore permissions
retention policy
settlement refs
dispute refs
restore/import receipts
```

Cold archives may contain heavier state:

```text
task state
working memory selected for retention
patch branches
tool traces
model/tool transcripts
artifact refs
projection checkpoints
replay metadata
large file snapshots
evidence bundles
```

Supported archive profiles include:

```text
full snapshot
snapshot plus incremental diffs
operation-log segment archive
projection checkpoint archive
evidence bundle archive
migration bundle
zero-to-idle checkpoint
```

Archive payloads must bind to the originating domain, schema version, state
root, policy hash, object heads, authority context, and encryption envelope.
The public claim should be conservative: hybrid post-quantum sealed state
archives, not unbreakable storage.

Restore/import flow:

```text
AgentStateRestoreRequested
-> authority verified through wallet.network/policy
-> archive fetched by CID/hash
-> archive hash verified
-> archive decrypted through an authorized key lease
-> schema, version, state root, and policy validated
-> Run, TaskState, ArtifactRefs, PatchBranches rehydrated
-> projections rebuilt or resumed
-> RestoreReceiptRecorded
```

Restore must not silently mutate runtime truth. Rehydration creates Agentgres
operations and receipts so replay, dispute, and accountability remain intact.

Secrets should be represented by wallet.network references or sealed key leases,
not embedded as raw secret material in archives:

```text
archive may contain:
  secret_ref: wallet.network://secret/api-key-openai

archive should not contain:
  raw OpenAI API key
```

This preserves the split:

```text
Agentgres = canonical hot state, archive refs, receipts
authority providers/local governance = permission decisions
wallet.network = portable delegated authority, secrets, restore/key leases
storage backends = encrypted durable bytes
dcrypt = hybrid/PQ sealing layer
```

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
Worker
ManagedWorkerInstance
Service
Task
Run
Order
StandingOrder
SchemaDefinition
SchemaMigration
ConstraintDefinition
InvariantDefinition
IndexDefinition
Patch
ScopeLease
PolicyDecision
Receipt
ArchiveReceipt
RestoreReceipt
ArtifactRef
ArtifactBundle
AgentStateArchive
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
- Web4 invariants;
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
- managed worker instances;
- runtime subscriptions;
- usage receipts;
- quality ledgers;
- contribution accounting;
- search/ranking projections;
- reputation state.

### sas.xyz Agentgres

- service listings;
- service orders;
- outcome workspaces;
- runtime assignment refs;
- compute session refs;
- SLA/delivery state;
- provider/customer state;
- delivery bundles;
- dispute evidence;
- payout mirrors;
- service quality records.

### ioi.ai Agentgres

- account/runtime profile refs;
- device registrations;
- sealed archive refs;
- latest state-root pointers;
- restore lifecycle records;
- publishing flow records;
- remote compute entitlement refs;
- sync metadata;
- lightweight runtime status.

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

## Anti-Patterns

Do not model Agentgres as:

```text
all memory
all payload bytes
a mutable Postgres table pile
a thin index over storage backend blobs
an IOI L1 contract
a replacement for wallet.network authority
a replacement for daemon execution
a retrieval/vector index as canonical truth
a silent local-file restore mechanism
```

Correct model:

```text
Agentgres owns admitted operational truth
Agent Wiki / ioi-memory owns semantic memory and retrieval surfaces
accepted operations define truth
object heads and state roots make truth replayable
artifact refs define payload meaning
storage backends hold bytes
authority providers and local/domain policy authorize read, write, decrypt,
export, forget, and restore, with wallet.network mandatory when the operation
requires portable delegated authority, secrets, decryption leases,
declassification, external effects, spend, restore/apply, or other
consequential authority
```

## Related Canon

- [`api-object-model.md`](./api-object-model.md): low-level Agentgres APIs,
  object classes, operation logs, runtime state, and archives.
- [`artifact-ref-plane.md`](./artifact-ref-plane.md): ArtifactRef,
  PayloadRef, EvidenceBundle, DeliveryBundle, AgentStateArchive refs,
  lifecycle, policy, authority, receipts, replay/import metadata, and restore
  validity.
- [`postgres-bridge-and-readiness-contract.md`](./postgres-bridge-and-readiness-contract.md):
  Postgres bridge, storage-engine posture, durability, and recovery.
- [`projection-system-reference.md`](./projection-system-reference.md):
  canonical-state/projection taxonomy and legacy terminology boundary.
- [`../daemon-runtime/default-harness-profile.md`](../daemon-runtime/default-harness-profile.md):
  daemon-executed profile that admits runtime truth through Agentgres.
- [`../../_meta/implementation-matrix.md`](../../_meta/implementation-matrix.md):
  concept-to-durable-form implementation index.

## Invariants

1. No model output directly mutates canonical truth.
2. No consequential state change without persisted intent/policy/evidence path.
3. No projection is canonical truth unless explicitly defined as commit-critical.
4. No raw secret storage in Agentgres.
5. No split-brain app state outside the domain Agentgres admission boundary.
6. No marketplace contribution without attribution when used materially.
7. No durable behavior-affecting memory mutation without an Agentgres operation
   such as `ContextMutation` and a policy/authority/receipt path.
8. No retrieval, embedding, full-text, graph, or wiki projection is canonical
   memory truth unless it is rebuildable from accepted Agentgres operations and
   artifact refs.

## One-Line Doctrine

> **Agentgres gives autonomous work admitted memory: it makes durable truth queryable, composable, auditable, portable, and settleable.**

## Detailed Agentgres Reference Module

The detailed Agentgres v2.0 design module (the former
`docs/specs/agentgres-spec.md`: lifecycle/change/truth/query/client arms,
zero-to-idle, storage architecture, benchmarks, operator tooling, DX, and
the Git/IDE overlay implementation plan) is archived verbatim at
[`../../_archive/specs/agentgres-v2-reference.md`](../../_archive/specs/agentgres-v2-reference.md).
It is supporting implementation detail, not a parallel architecture
variant; where it disagrees with the canonical sections above or the
low-level object model in [`api-object-model.md`](./api-object-model.md),
the canonical sections win.
