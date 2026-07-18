# Agentgres Postgres Bridge and Readiness Contract

Status: canonical architecture authority.
Canonical owner: this file for Agentgres Postgres bridge posture, database-readiness guarantees, consistency names, durability expectations, schema/migration lifecycle, replication profile, recovery profile, and operator surface.
Supersedes: loose "Postgres replacement" language when compatibility or database guarantees are discussed.
Superseded by: none.
Last alignment pass: 2026-05-14.
Doctrine status: canonical
Implementation status: planned (bridge posture design; file marks roadmap claims itself)
Last implementation audit: 2026-07-05

## Canonical Definition

Agentgres is the canonical operational state substrate for Web4 domains. It may
expose Postgres-compatible projections and SQL-facing bridges, but its source of
truth is operation-backed state, not mutable relational rows.

Public positioning:

> **Agentgres is a canonical state substrate with a Postgres bridge.**

Builder-facing positioning:

> **Agentgres is a Postgres-compatible operational substrate for worker-produced state.**

Avoid naked "Agentgres is a Postgres replacement" language in canonical docs.
The stronger claim is narrower and more defensible: Agentgres replaces
row-centric databases as canonical truth when application state is produced by
workers, scoped authority, artifacts, receipts, projections, and settlement
mirrors.

Agentgres also replaces mutable-row assumptions with operation-backed state plus
sealed, encrypted, content-addressed state artifacts. This is part of the
product identity, not just an implementation detail. It is secondary only in
the canonicality hierarchy: blob archives are portable state artifacts, while
accepted operations, object heads, state roots, receipts, and archive refs remain
the authority.

## What Agentgres Replaces

Agentgres is designed to replace the app-specific pile of:

- mutable relational rows as canonical truth;
- ad hoc audit tables;
- unstructured event logs;
- background job state;
- workflow run state;
- agent memory checkpoints;
- tool-call traces;
- receipt/evidence indexes;
- settlement mirrors;
- quality/reputation ledgers;
- custom projection rebuild scripts;
- client-side caches pretending to be truth.

It replaces those with:

```text
accepted operations
-> object heads
-> domain state roots
-> constraints and invariants
-> receipts and artifact refs
-> projections and subscriptions
-> replay, restore, and verification
```

## What Agentgres Does Not Replace

Agentgres should not be positioned as the only storage plane.

Non-replacements:

- blob/object storage for payload bytes;
- storage backends such as Filecoin/CAS for content-addressed artifact availability;
- wallet.network for authority, secrets, key leases, and approvals;
- the declared external settlement service for public/economic settlement and
  rights; IOI L1 only for explicitly enrolled, selected services;
- OLAP warehouses for heavy analytical scans;
- vector databases when a dedicated vector engine is the right serving plane;
- local UI hover/draft state;
- every embedded app cache;
- every generic SQL table when row-centric CRUD is sufficient.

Postgres remains excellent for row-centric application state. Agentgres becomes
necessary when the truth of the application is a replayable, authority-scoped,
receipt-backed operation performed by a worker.

## State Artifact Hierarchy

Agentgres separates canonical truth, portable state format, serving layer, and
storage plane.

```text
Canonical truth:
  accepted operations
  object heads
  state roots
  receipts
  archive refs

Portable state format:
  encrypted content-addressed state archives / blobs
  state root
  object heads
  schema version
  policy hash
  authority metadata
  receipt refs
  replay/import metadata

Serving layer:
  projections
  query surfaces
  subscriptions
  SQL bridge

Storage plane:
  local disk
  S3
  Filecoin/CAS
  object stores
  provider/customer blob stores
  Postgres
  SQLite
  RocksDB
  custom append-only log
```

The archive is the portable sealed state artifact. Agentgres records what the
archive is, what state it represents, which authority context or policy is
required to decrypt it, which operation produced it, and whether restore/import
has satisfied the required validation checks. It does not grant decrypt
authority by itself.

## Storage Engine Posture

Agentgres is storage-engine pluggable.

It may initially run over durable engines such as Postgres, SQLite, RocksDB,
object stores, or a custom append-only log. These are storage engines, not the
Agentgres admission and state model.

The canonical Agentgres contract is defined by:

- accepted operations;
- operation sequence;
- object heads;
- state roots;
- projection checkpoints;
- constraint and invariant results;
- receipt refs;
- artifact refs;
- recovery guarantees.

An implementation may use Postgres pragmatically without making Postgres the
identity of Agentgres.

## Commit Log and Durability

The canonical durability unit is the accepted operation at a domain sequence.

An operation is acknowledged only after the implementation has durably recorded
enough information to replay or reject it deterministically:

- domain id;
- domain sequence;
- operation id;
- actor id;
- operation type;
- object class and object id;
- schema version;
- policy hash;
- authority grant refs;
- expected heads or expected state root;
- payload hash and payload refs;
- receipt refs available at admission time;
- resulting object head;
- resulting state root or state-root delta commitment.

Storage engines may implement this with WAL, append-only segments, transactional
tables, or another durable commit protocol. The implementation detail can vary;
the contract cannot.

Crash recovery must replay accepted operations to a declared domain sequence,
reconstruct object heads, verify state-root continuity, and rebuild or verify
projection checkpoints.

## Consistency Levels

Agentgres uses native consistency names with familiar database intuition.

```text
cached_projection
  May be stale. Suitable for UI, search, previews, and low-risk browsing.

projection_consistent
  Read is served from a named projection at a declared projection watermark.

snapshot_consistent
  Multiple reads observe the same projection or state snapshot.

state_root_consistent
  Read is bound to a specific domain state root.

linearized_domain
  Read observes all accepted operations up to the latest committed domain sequence.

serializable_domain
  Operation set is evaluated as if applied in a single valid serial order.
```

Writes that require business safety should bind expected heads, expected state
roots, constraint versions, policy hashes, and authority grants. If a conflict
is detected, the caller must retry, rebase, repair, or route to review rather
than silently overwrite truth.

## Constraints and Web4 Invariants

SQL-style constraints protect object validity. Web4 invariants protect
consequential action validity.

Basic constraint classes:

- required field;
- schema type;
- unique key;
- foreign ref;
- check;
- exclusion rule;
- cardinality;
- temporal range.

Web4 invariant classes:

- authority invariant;
- receipt invariant;
- settlement invariant;
- policy invariant;
- temporal invariant;
- projection invariant;
- state-root invariant;
- artifact integrity invariant;
- policy monotonicity invariant.

Canonical object classes for this layer should include:

```text
ConstraintDefinition
InvariantDefinition
InvariantCheck
ConstraintViolationReceipt
DeferredConstraint
UniqueKey
ForeignRef
ExclusionRule
TemporalInvariant
```

Constraint and invariant failures are not just errors. When consequential, they
must be recordable as receipts or operation rejection evidence.

## Index Families

Agentgres indexes exist to serve projections, verification, replay, and
operator/debug workflows.

Canonical index families:

- object-head index;
- relation index;
- temporal index;
- graph-edge index;
- authority index;
- receipt index;
- artifact-ref index;
- ontology/object-model index;
- data-recipe lineage index;
- state-root index;
- full-text index;
- vector/ref index;
- projection-watermark index;
- settlement-mirror index.

Indexes are derived serving structures. They accelerate queries, but they do
not become canonical truth unless the index definition and checkpoint are
operation-backed and replay-verifiable.

## Schema and Migration Lifecycle

Schema evolution is operation-backed.

Canonical migration lifecycle:

```text
SchemaProposed
-> SchemaValidated
-> BackfillPlanned
-> ProjectionRebuilt
-> MigrationCommitted
```

Rollback or failed migration lifecycle:

```text
MigrationRejected
MigrationRolledBack
ProjectionRebuildFailed
SchemaDeprecated
```

A migration should bind:

- old schema version;
- new schema version;
- migration operation refs;
- affected object classes;
- affected projection definitions;
- backfill plan;
- constraint/invariant diff;
- compatibility window;
- verification receipts;
- rollback or repair plan.

## Projection Query and SQL Bridge

Agentgres may expose SQL-facing and Postgres-compatible query surfaces over
named projections.

Compatibility scope:

```text
Phase 1:
  SQL reads over named projections.

Phase 2:
  Limited inserts/updates compiled into Agentgres operations when schema,
  policy, authority, and constraint rules are unambiguous.

Phase 3:
  Broader compatibility for selected Postgres clients, ORMs, and BI tools.
```

Non-goal:

```text
arbitrary SQL writes that bypass operation settlement
```

The adoption rule:

> **You can point familiar tools at projection tables, but canonical writes still go through Agentgres operations.**

### SQL Writes as Intents (planned bridge contract)

Implementation status (this contract): planned; doctrine owner is
[`doctrine.md`](./doctrine.md) (Substrate Contract Doctrine).

A write arriving over the Postgres wire is never a direct mutation. The
bridge compiles it into a proposed operation and runs the same pipeline as
any worker effect:

```text
SQL INSERT/UPDATE/DELETE
  -> compiled ProposedOperation (schema + constraint resolution)
  -> validate (admission rules, expected heads)
  -> policy/authority evaluation by the operation's risk class
     (canonical ladder: ../../foundations/canonical-enums.md)
  -> admitted operation + receipt, or refusal with named reason
  -> projection update (visible to subsequent SQL reads with watermark)
```

Contract points:

- `SELECT` is a projection read and carries freshness metadata; it never
  blocks on admission.
- A refused write surfaces as a SQL error naming the refusal reason
  (policy, authority, constraint, expected-head conflict) — never a silent
  drop, never a fake success.
- Writes that require step-up authority fail with a named
  approval-required error carrying the approval ref; the bridge does not
  hold sessions open waiting for human approval.
- Bulk/batch writes compile into batched operations and settle under the
  batch-rooting rule; per-row receipts are not minted when a range receipt
  covers the batch.
- No bridge path may bypass operation settlement (the Non-goal above is
  load-bearing; INV-10).

The product claim this contract earns: **it speaks Postgres, but every
write is governed, receipted, and replayable.**

Projection query support should cover:

- named projections;
- stable cursors;
- pagination;
- joins across projection-owned relations;
- aggregates over projection state;
- time-travel reads by sequence or state root where supported;
- graph traversal hooks;
- full-text and vector/ref hooks;
- explain plans;
- index visibility;
- projection freshness metadata.

## Specialized Projection Engines and External Serving Planes

Agentgres projections may be served by specialized engines when a dedicated
serving plane is better than a generic relational projection. Postgres is one
compatibility bridge, not the privileged long-term shape of every read path.

Incremental view maintenance (DBSP/differential-dataflow-class engines) is
the preferred realization of the projection freshness contract: projections
maintained incrementally from the operation log with an explicit, queryable
watermark, instead of periodic rebuilds. Projection freshness lag is a
first-class performance metric (see `doctrine.md`, Performance contract).

Projection engine families may include:

- relational projections: Postgres, SQLite, embedded SQL stores;
- local replica and sync projections: IndexedDB, OPFS, SQLite/Turso,
  CRDT-backed document stores, Zero-style partial sync, Electric-style
  streams/sync;
- search projections: Typesense, Meilisearch, or equivalent full-text/faceted
  search engines;
- vector and retrieval projections: Qdrant, LanceDB, or equivalent vector,
  hybrid, and multimodal retrieval engines;
- OLAP projections: ClickHouse, DuckDB, MotherDuck, Parquet/object-store
  tables, or equivalent columnar analytics engines;
- stream projections and hot transport: NATS JetStream, Redpanda, or
  equivalent replayable stream systems;
- cache and materialized lookup projections: Valkey, Dragonfly, embedded
  key-value stores, or equivalent low-latency serving engines;
- time-series projections: QuestDB, ClickHouse, or equivalent telemetry
  engines;
- ledger and accounting projections: TigerBeetle or equivalent purpose-built
  accounting engines.

These engines are projection accelerators and serving planes, not canonical
truth. Any external projection engine must be:

- rebuildable from Agentgres accepted operations, object heads, artifact refs,
  receipt refs, projection definitions, and checkpoints;
- checkpointed with a projection watermark and source operation range;
- invalidatable when schema, policy, index, or projection definitions change;
- incapable of accepting canonical writes directly;
- annotated with consistency, freshness, and rebuild metadata.

No external projection engine may bypass operation settlement. If a serving
engine exposes a write-like interface for developer ergonomics, that write must
compile into an Agentgres operation and pass policy, authority, schema,
constraint, invariant, expected-head, and receipt checks before it changes
domain truth.

Projection engine checkpoints should expose:

- projection id;
- engine family and adapter id;
- source operation range;
- domain sequence watermark;
- schema version;
- policy hash where relevant;
- projection/index definition hash;
- rebuild status;
- freshness SLO;
- verification receipt refs where required.

The operating rule is:

> **Every fast serving plane may be stale, disposable, or rebuildable; no fast
> serving plane may become the authority for domain truth.**

## Subscriptions

Subscriptions are projection-native.

They should support:

- projection watermark updates;
- object-head changes;
- operation append notifications;
- receipt availability notifications;
- run/event tailing;
- LISTEN/NOTIFY-style compatibility where useful;
- replay-and-tail streams.

Subscription delivery may be at-least-once. Consumers must use operation ids,
domain sequences, projection watermarks, and cursors for idempotency.

## Replication and Deployment Profiles

Domain-local does not mean single-node forever. It means the domain owns its
truth boundary.

Canonical deployment progression:

```text
v0:
  single-node local Agentgres

v1:
  hosted single-writer domain

v1.5:
  replicated read projections

v2:
  multi-node HA domain

v3:
  cross-domain federation and stronger distributed recovery
```

Until a multi-writer protocol is explicitly specified, canonical writes should
be modeled as single-writer per domain or explicitly serialized through a domain
leader. Read replicas and projection replicas may lag, but must expose
watermarks and consistency level.

Receipt finality and projection freshness are separate concepts. A receipt may
be final while a read projection is still catching up.

## Recovery and PITR Roadmap

Agentgres recovery is sequence-first.

Current canonical recovery claims:

- crash recovery;
- restore to domain sequence N;
- projection rebuild from verified checkpoints;
- receipt/root verification through sequence N;
- proof that accepted operations through N replay to the expected state root.

Roadmap claims, not baseline claims unless implemented:

- restore to arbitrary timestamp T;
- cross-node automatic failover;
- proof no accepted operation was lost across all distributed failures;
- generalized multi-writer conflict repair.

Restore must be operation-backed. It must not silently mutate canonical truth.

## Operator Surface

The canonical operator namespace is `ioi agentgres`. A standalone `agentgres`
binary may become an alias later.

Core command families:

```bash
ioi agentgres status
ioi agentgres doctor
ioi agentgres explain
ioi agentgres replay
ioi agentgres verify-root
ioi agentgres diff-heads
ioi agentgres rebuild-projection
ioi agentgres restore
ioi agentgres inspect-receipt
ioi agentgres migrate
ioi agentgres vacuum
ioi agentgres archive
ioi agentgres export
ioi agentgres import
```

Operator tooling is not secondary. Postgres earned trust through durability,
debuggability, repairability, and operational ergonomics. Agentgres must do the
same for operation-backed domains.

## Compatibility Targets

Adoption priority:

1. psql-compatible read surface.
2. BI tools over projections.
3. Drizzle and Prisma read models.
4. LISTEN/NOTIFY-style subscriptions.
5. PostgREST-style API generation.
6. GraphQL over projections.
7. Supabase-style APIs.

Do not lead with backend-as-a-service framing. The first wedge is familiar
query and operations tooling over Agentgres projections.

## Benchmark Classes

Define benchmark classes before making performance claims.

Canonical benchmark classes:

- operation append throughput;
- object-head conflict rate;
- transaction conflict resolution;
- projection rebuild latency;
- projection freshness lag;
- subscription fanout;
- replay throughput;
- restore to sequence N;
- receipt verification throughput;
- artifact reference resolution;
- SQL projection query latency;
- policy/invariant evaluation overhead.

Numbers should be published only when measured against declared hardware,
storage engine, schema, projection set, and consistency level.

## General App-Data Profile

Agentgres must support ordinary app objects as well as machine-economy objects.

The general app-data profile should cover:

- users;
- teams;
- projects;
- invoices;
- messages;
- comments;
- feature flags;
- audit logs;
- webhooks;
- notifications;
- settings.

These objects still follow Agentgres doctrine: operation-backed writes,
constraints/invariants, projections, subscriptions, and replayable recovery.

## Non-Goals

Agentgres does not promise:

- full arbitrary Postgres write compatibility;
- silent mutation through SQL bypasses;
- one storage engine forever;
- replacement of blob storage, OLAP, vector search, wallet authority, or L1 settlement;
- multi-writer HA until the domain protocol specifies it;
- timestamp PITR or automatic failover before implementation backs those claims.

## One-Line Doctrine

> **Agentgres may look like Postgres at the query edge, but its truth is accepted operations, its serving unit is the projection, its safety unit is the invariant, and its recovery unit is the replayable domain sequence.**
