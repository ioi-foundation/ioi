# Fractal Query Fabric (FQF) v0.5

## A Kernel-Native Canonical State, Projection, and Query Fabric for Agentic Applications

Historical note: earlier revisions of this spec described `SCS` as a separate
context plane. The live repository now uses `ioi-memory` for product-memory
flows and no longer ships an `SCS` crate.

## 1. Executive Summary

Fractal Query Fabric (`FQF`) is the proposed canonical state, projection, and query fabric for IOI-native applications.

It is not:

- SQL on a blockchain
- a decentralized Supabase clone
- a replacement for every local UI store
- a resurrection of the old `SCS` memory story

It is:

- a kernel-native fabric for canonical operations and object state
- a projection system that materializes app-facing read models
- a receiptable query surface for agentic and user-facing applications
- the durable authority layer for IOI-native apps that would otherwise default to Postgres/Supabase
- when anchored on IOI mainnet, part of a larger `L0` story for global `ai://` registry, publication, and trust roots

The architectural shift is:

> canonical truth lives in the fractal kernel; projections are first-class runtime artifacts; queries are capability-scoped and optionally receiptable; relational tables are only one projection family among many.

Performance doctrine:

> `FQF` is an append-first, projection-decoupled, deterministically replayable state fabric whose hot path remains narrower than its proof, query, and projection surfaces.

Scaling north star:

> `FQF` should scale by minimizing global truth, maximizing local read termination, and making every expensive derived artifact portable, replayable, and independently scalable.

If successful, this is not "the death of Postgres" in general. It is the first credible displacement of Postgres as the default authority layer for IOI-style agentic applications.

## 2. Decision

This spec adopts the following position:

- `Yes`: build `FQF` as the shared canonical state and projection fabric for IOI-native apps.
- `No`: do not reintroduce `SCS` as a separate context plane; live product memory uses `ioi-memory`.
- `Yes`: support React apps via local-first app stores plus `FQF` sync/query/mutation.
- `No`: do not make every query, cache, or UI interaction part of canonical state.
- `No`: do not turn `FQF` into a universal replacement for every database workload.

## 3. Why This Exists

The current web application default is:

- React frontend
- hosted Postgres as authority
- blob storage for assets
- realtime layer bolted on
- vector store bolted on
- app-specific sync/cache logic bolted on

That stack is serviceable for CRUD software. It is weak for agentic software because:

- memory is ad hoc
- provenance is weak
- canonical execution truth is weak
- permissions are bolt-on
- multi-node serving is awkward
- portability is poor
- proof-sensitive reads are not first-class

IOI already has the beginnings of a better split:

- kernel-managed canonical state and proofs in the chain/state APIs
- durable storage via `redb` + WAL
- `ioi-memory` as the runtime-backed memory substrate for product flows

Relevant current anchors in the repo:

- kernel topology and memory-runtime role: `README.md`
- canonical chain and anchored state interfaces: `crates/api/src/chain/mod.rs`
- state manager and verifier traits: `crates/api/src/state/mod.rs`
- durable storage with WAL: `crates/storage/README.md`
- deterministic execution and canonical flush: `crates/execution/README.md`
- runtime-backed memory implementation: `crates/memory/src/lib.rs`
- typed `ContextSlice` transport model: `crates/ipc/src/data.rs`
- strict mHNSW certifying retrieval contract: `docs/commitment/tree/mhnsw/README.md`

`FQF` should build on that foundation, not fight it.

## 4. Core Thesis

Traditional application stacks treat:

- mutable rows as truth
- files as external blobs
- indexes as hidden implementation details
- queries as untrusted reads

`FQF` rejects that for IOI-native applications.

In `FQF`:

- canonical truth = operation log + deterministic state transitions
- canonical app objects = kernel-managed object state
- blobs = hash-addressed artifacts with explicit metadata and policy
- projections = explicit, versioned runtime artifacts
- queries = scoped runtime acts with optional receipts
- tables = one projection family
- SQL = optional compatibility surface
- canonical commit path must remain narrower than projection, proof, and query-serving layers

## 5. Relationship to Existing IOI Components

## 5.1 Chain State

Chain state remains the deepest canonical truth.

The current chain API already models:

- anchored historical state
- live state
- proven membership queries
- deterministic block preparation and commit

That remains the foundation.

For `ai://`, this spec should also frame `IOI mainnet` as the public `L0` layer when global coordination is required.

`L0` should own:

- root `ai://` namespace commitments
- publisher and identity trust anchors
- manifest and version publication commitments
- runtime or resolver bootstrapping records
- shared receipt and projection anchor commitments where cross-runtime trust matters

`L0` should not own:

- routine app serving
- local-first UI state
- most projection execution
- most subscription delivery

That split is important. `L0` is the root registry and trust anchor, not the place where every sovereign runtime must do all of its serving work.

## 5.2 Storage

The storage crate already separates:

- durability via WAL
- indexing into `redb`

`FQF` must preserve and harden that spirit:

- canonical mutations must append to a replayable operation log before or alongside deterministic state application
- durable commit should prefer sequential write patterns, batched flushes, and bounded write amplification
- secondary indexes, ranking views, subscription fanout state, and non-essential query structures must not block canonical commit unless explicitly designated commit-critical
- projection artifacts must be rebuildable from canonical operations and deterministic projection definitions
- canonical durability and projection durability may have different cadences so long as replay and checkpoint semantics remain sound
- compaction, checkpointing, and archival must not sacrifice canonical reproducibility, replay integrity, or auditability

## 5.3 SCS

`SCS` remains the context plane.

It already owns:

- append-only memory frames
- `ContextSlice`
- mHNSW retrieval
- retrieval proof/certification
- scrub-on-export / PII airlock semantics

`FQF` must reference SCS interactions, not absorb SCS itself.

## 6. Performance Design Doctrine

`FQF` must preserve the performance characteristics of the kernel's deterministic execution pipeline.

It must not collapse canonical commit, projection maintenance, proof generation, and app-facing query serving into one synchronous cost center.

No single ordering domain scales without bound. `FQF` should scale by ensuring each bottleneck is partitionable, cacheable, replayable, relocatable, or explicitly paid for.

The design doctrine is:

- canonical commit path must remain append-first, replayable, and narrow
- projection maintenance must be decoupled from canonical commit whenever correctness permits
- query receipts and proof generation must be policy-gated and not imposed on trivial or high-frequency reads by default
- ingestion, ordering, partitioning, and batching are first-class system concerns, not incidental implementation details
- ordering, projection compute, query serving, subscription delivery, artifact transfer, and proof generation must remain independently scalable planes with explicit interfaces and independent backpressure behavior
- projection freshness is a separate service-level property from canonical commit latency
- the system should optimize for deterministic state/log throughput first, then layer richer read models on top
- when the system is overloaded, it must degrade derived work before canonical correctness or ordering integrity

Primary rule:

> **Do not place work on the canonical hot path unless it is required for deterministic state transition correctness.**

Scaling statutes:

- write authority must remain narrower than read-serving, projection-serving, and subscription-serving capacity
- any canonical domain expected to exceed single-ordering-domain throughput must define partitioning semantics before launch
- anything expensive to maintain continuously must be checkpointable, portable, and replayable or it will become the bottleneck

## 7. Hot Path and Derived Path Separation

`FQF` must distinguish four execution paths.

### Hot Path

The minimum synchronous path required to accept, order, validate, and durably commit a canonical mutation.

May include:

- capability and policy checks required for validity
- deterministic state transition execution
- append to canonical operation log
- canonical object state update
- minimal commit metadata required for replay and sequencing

Should not include by default:

- heavyweight ranking recomputation
- large fanout subscription delivery
- non-critical secondary index maintenance
- expensive proof construction
- analytical aggregation
- semantic candidate generation
- broad cache invalidation sweeps

### Near-Hot Path

Work that should follow canonical commit quickly but may be batched or processed asynchronously.

Examples:

- projection delta application
- lightweight index updates
- changefeed publication
- checkpoint scheduling

### Async Derived Path

Work that may lag canonical truth while remaining deterministically derivable.

Examples:

- complex relational rebuilds
- graph recomputation
- ranking refreshes
- recommendation candidate generation
- proof-ready export bundles
- analytical summaries

### Cold Path

Rare or export-oriented work.

Examples:

- settlement anchors
- dispute bundles
- historical recomputation
- full projection rebuild
- archival compaction

## 8. Execution and Ingestion Alignment

Where possible, `FQF` should inherit the kernel's concurrency and ingestion model rather than introducing a separate serialized application-state bottleneck.

Implementation direction:

- canonical mutations should be schedulable as parallel deterministic work where independence permits
- validation and replay of conflicting mutations should follow the kernel's ordered deterministic semantics
- ingestion should support batched admission, cheap prechecks, and contention-aware partitioning
- externally initiated mutations should carry replay-safe semantics through idempotency keys, nonce or counter binding, or equivalent canonical dedupe rules
- ordering and flush should preserve deterministic batch commit semantics
- projection workers should consume canonical batches or checkpoints rather than forcing one-by-one synchronous downstream maintenance

Important consequence:

> `FQF` must not reintroduce a single-threaded app-state serialization layer above a parallel kernel execution engine.

## 9. Ordering Domains and Partitionability

`FQF` should support explicit ordering domains so unrelated canonical object families or tenant scopes do not contend on one global application-level sequencer when global total ordering is unnecessary.

The design should allow:

- partitioned object namespaces
- tenant-scoped ordering domains
- projection-local change sequences
- deterministic merge rules where cross-domain coordination is required

All high-volume canonical domains must declare:

- a partition key
- an ordering scope
- an ownership rule

Global ordering is opt-in and must be justified by correctness, not convenience.

Global ordering should be reserved for:

- operations whose correctness depends on shared total order
- root-level publication and settlement commitments
- cross-domain state transitions requiring single-order semantics

Default principle:

> **Prefer scoped determinism over unnecessary global serialization.**

Single-ordering-domain rule:

> Additional replicas may scale reads, subscriptions, and projection throughput for one ordering domain, but they do not increase per-domain write throughput. Write scaling requires partitioning across multiple ordering domains or shards with distinct ordering authorities.

Serialization rule:

- strong serialization should be applied only within the smallest correctness-preserving domain
- cross-domain workflows should prefer sagas, escrow, and compensating transitions over global synchronous transactions
- no application-facing abstraction may silently require global joins, global locks, or full-fabric scans on the steady-state hot path

Operational scaling rule:

- hot keys, hot tenants, hot ordering domains, and skewed partitions must be observable and support deterministic split, rebalance, or isolate actions
- rebalance and ownership movement should be modeled as protocol-visible procedures rather than fragile operator-only side effects
- high-volume tenants and service classes must be isolatable into separate ordering domains, serving pools, and projection budgets

## 10. Canonical Scope of FQF

`FQF` is the authority layer for shared application state and durable app-facing read models.

It is the authority layer for shared application truth, but not every derived view or read artifact is commit-critical.

It should be the authority for:

- service publication
- version activation
- deployment pointers
- install events
- run state
- approvals and capability leases
- billing events
- moderation events
- listing and marketplace state
- tenant bindings
- artifact references
- projection definitions and checkpoints
- subscription definitions

It should not be the authority for:

- local panel layout
- input drafts
- temporary selection state
- ephemeral hover/focus state
- purely local optimistic UI bookkeeping

## 11. Layered Architecture

## L0. Canonical Chain State

The deterministic operation log and state root substrate.

Holds:

- ordered operations
- block/epoch transitions
- state roots
- identities
- `ai://` namespace and publication anchors
- manifest and resolver trust commitments
- canonical service/version state
- approvals and capability commitments
- receipt roots
- settlement/dispute references

Primary property:

- replayable canonical truth

## L1. Canonical Object Layer

A semantic object model over canonical state.

Example object classes:

- `Service`
- `Version`
- `Run`
- `Receipt`
- `Approval`
- `CapabilityLease`
- `TenantBinding`
- `Listing`
- `ArtifactRef`
- `DeploymentPointer`
- `ProjectionDefinition`
- `ProjectionCheckpoint`
- `SubscriptionDefinition`

Primary property:

- object-first truth, not row-first truth

## L2. Blob / Artifact Substrate

Hash-addressed immutable artifacts referenced by canonical state.

Backends may include:

- local disk
- attached SSD/NVMe
- cloud object storage
- CAS/IPFS/Filecoin
- hybrid storage

The kernel stores:

- content hash / CID
- provenance
- serving policy
- access policy
- retention policy

Primary property:

- artifacts are verified by hash, not trusted by provider

## L3. FQF Core

The projection, indexing, subscription, and query-receipt subsystem.

Maintains:

- deterministic derived read models
- projection logs and checkpoints
- derived indexes
- changefeeds
- app-facing subscriptions
- optional query receipt artifacts

Primary property:

- derived, fast, queryable views over canonical truth

Important constraint:

- `FQF` is kernel-native, but not every query must become a consensus concern
- canonical hot path must remain narrower than projection, proof, and query-serving surfaces

## L4. Query Surface

The app- and agent-facing query API.

Exposes:

- typed queries
- typed mutations
- subscriptions/changefeeds
- capability-scoped reads
- provenance-aware reads
- optional SQL compatibility
- optional GraphQL-like adapters

Primary property:

- developer and agent ergonomics

## L5. Extensibility Layer

Optional domain-specific extensions.

Can support:

- custom projection definitions
- custom ranking functions
- vertical query adapters
- Wasm or plugin-based projection logic

Primary property:

- extensibility without turning the kernel into "just another contract host"

## Separate Plane. SCS

Owns:

- semantic memory
- context slices
- retrieval proofs
- redaction lineage
- retention classes
- tombstones and key shredding semantics

Primary property:

- what the agent can know

## 12. Fractal Scope Model

`FQF` is fractal by design.

The same object and query semantics should work across three scopes.

## 12.1 Local Scope

Examples:

- local Autopilot state
- local installs
- local receipts
- local dashboards
- local projections

## 12.2 Session Scope

Examples:

- collaborative workspace state
- temporary worker slices
- session-scoped projections
- short-lived subscriptions
- shared task state

## 12.3 Global Scope

Examples:

- service publication
- marketplace state
- version anchors
- billing commitments
- trust anchors
- receipt roots

## 12.4 Fractal Rule

The semantics should remain stable across scopes; only these vary:

- visibility
- retention
- latency profile
- proof requirements
- serving topology

## 13. Projection Families

Relational projections are necessary, but they are not the center.

`FQF` must support multiple projection families.

All projection families must be defined as deterministic functions over canonical operations or canonical object snapshots.

Every `ProjectionDefinition` must support one or both of:

- incremental delta application from ordered canonical change streams
- checkpoint-based restoration followed by bounded replay

Every `ProjectionDefinition` must declare:

- `update_mode`: `commit_coupled | nearline | async | lazy`
- `freshness_slo_ms`
- `checkpoint_interval`
- `rebuild_policy`
- `retention_window`
- `fanout_class`
- `proof_mode`

Each projection family must also declare whether it is:

- commit-coupled
- nearline
- async
- lazy
- rebuildable-on-demand

Projection doctrine:

- every portable projection is reproducible from canonical operations, deterministic projection definitions, and verified checkpoints
- no projection may be treated as irreplaceable system truth
- any expensive projection that cannot be maintained continuously must still be checkpointable, portable, and replayable

## 13.1 Relational Projections

For:

- dashboards
- admin tables
- billing summaries
- reports
- search/filter/pagination

## 13.2 Graph Projections

For:

- service dependency graphs
- capability graphs
- workflow topology
- tenant/provider graphs
- lineage graphs

## 13.3 Timeline / Event Projections

For:

- run timelines
- operation feeds
- moderation queues
- audit trails
- activity histories

## 13.4 Semantic Projections

For:

- hybrid symbolic + semantic retrieval
- grouping
- recommendation candidate sets
- intent-bound discovery

Note:

- semantic memory itself stays in `SCS`
- `FQF` may still maintain semantic projections over canonical object metadata

## 13.5 Capability Projections

For:

- what this principal can access
- what this lease permits
- what this run can see
- what this connector can do

## 13.6 Ranking / Search Projections

For:

- marketplace ranking
- trust score views
- service discovery
- relevance scoring
- top-k candidate sets

## 13.7 UI / Runtime State Projections

For:

- active version resolution
- deployment routing
- environment overlays
- install status
- cross-device synchronization views

## 14. Query Model

## 14.1 Query Families

### Intent-Bound Queries

Examples:

- find services compatible with this intent and trust posture
- find runs relevant to this goal
- find admissible tools for this session

### Provenance-Aware Queries

Examples:

- what evidence produced this result
- what policy allowed this action
- what changed since this receipt root

### Capability-Aware Queries

Examples:

- what can this session access
- which artifacts are visible to this tenant
- which actions are allowed under this lease

### Hybrid Symbolic + Semantic Queries

Examples:

- exact filters plus semantic ranking
- structured lookup plus candidate expansion
- deterministic constraints plus retrieval shortlist

### Subscription-Native Queries

Examples:

- watch changes to this service lineage
- stream updates to this dashboard view
- subscribe to this approval queue

Query execution should prefer checkpoint-bound determinism over ad hoc proof-heavy execution when the same trust property can be achieved from a projection checkpoint or state anchor.

Read termination rule:

- steady-state reads should terminate on local projections or verified checkpoints within declared freshness SLOs rather than round-tripping to ordering authority
- queries that cross partitions, require fanout over multiple projection families, or demand proof-ready execution must be explicit, classed, and budgeted
- expensive distributed work must not be disguised as a normal local read

## 14.2 Query as Runtime Capability

A query is not just a raw read.

Significant queries may bind:

- query hash
- caller capability scope
- source state root or projection checkpoint
- projection version
- result commitment
- optional proof mode

This allows queries to become auditable when they matter.

## 15. Query Receipts

## 15.1 Policy

Not every query should emit a heavyweight receipt.

The correct model is policy-driven:

- trivial local UI reads: no receipt
- high-frequency app reads: no receipt or lightweight bind-only receipt
- important local agent reads: checkpoint-bound or lightweight receipt
- trust-sensitive or settlement-sensitive reads: full proof-ready receipt
- dispute-sensitive reads: full proof-ready receipt

Receipt generation modes must support:

- disabled
- lightweight bind-only
- checkpoint-bound
- sampled
- full proof-ready

Full receipts must be exception-elevated, not baseline.

## 15.2 Receipt Contents

A query receipt may bind:

- query hash
- query family
- scope
- source state root or projection checkpoint
- projection/index version
- capability scope
- result commitment
- optional proof reference

## 15.3 Proof Levels

### Level 0

Local trusted query, no exported proof.

### Level 1

Bind result to a specific state root or projection checkpoint.

### Level 2

Prove the query execution or critical ranking result.

Important alignment note:

- current `SCS` retrieval is stricter than this and already certifying by default
- `FQF` should not weaken the `SCS` retrieval contract

## 16. Indexes as Protocol Objects

This is one of the core shifts.

Indexes should not be treated purely as hidden database internals.

Protocol-visible index artifacts should have:

- stable id
- projection family
- source object classes
- update policy
- visibility policy
- checkpoint semantics
- subscription policy
- proof policy

Important boundary:

- not every cache is a protocol object
- only portable, governed, shared projection/index artifacts should be promoted to this level

## 17. Transport and Payload Discipline

`FQF` implementations should preserve the kernel's split between small control-plane messages and large data-plane payloads.

Guidance:

- small mutations, control metadata, and subscription control frames may use ordinary RPC transport
- large snapshots, checkpoints, context-adjacent payloads, and bulk projection transfers should support shared-memory, mmap, or equivalent zero-copy or reduced-copy transport when colocated
- checkpoint artifacts and bulk deltas should be hash-addressed and resumable
- the protocol should avoid requiring repeated full-payload serialization for large projection snapshots or replay windows
- canonical mutations should carry bounded metadata and references to large artifacts rather than embedding large payloads directly in the hot path
- projection computation, checkpoint restore, ranking refresh, and read-heavy serving should preferentially execute where required canonical batches, checkpoints, or artifacts are already available

This discipline matters if `FQF` wants to preserve the kernel's transport gains instead of wrapping them in expensive serialization ceremony.

## 18. React Application Model

This is the downstream application model for:

- `Autopilot`
- `aiagent.xyz`
- `sas.xyz`
- future `ai://` applications

## 18.1 Local-First Rule

A React app should have:

- an in-memory local app store
- optional persistent browser/device cache via `IndexedDB` or `OPFS`
- an `FQF` client for canonical queries, mutations, and subscriptions

The local store owns:

- drafts
- optimistic state
- panel layout
- temporary filters
- cached query results
- offline queue metadata

`FQF` owns:

- durable shared state
- cross-node truth
- projections
- subscriptions
- capabilities and receipts

Client continuity rule:

- the local-first client store should be treated as the first read replica for interactive UX
- UI continuity should survive transient node failure, projection catch-up, and network interruption without requiring every interaction to hit canonical authority

## 18.2 What Replaces Supabase-Like Authority

The replacement stack is:

- React UI
- local-first app store
- kernel runtime
- `FQF` for canonical authority
- blob/artifact substrate for immutable assets
- optional `SCS` for agent memory

That is the right substitution target, not "Postgres for everything."

## 18.3 Shared Client Runtime Requirement

This only works if all apps share one app-facing runtime:

- typed schemas
- query client
- mutation queue
- subscription client
- optimistic update support
- invalidation and sync rules
- auth/capability scoping

Without that, each app will rebuild ad hoc client infrastructure and the paradigm shift will fail operationally.

## 19. `ai://` Application Model

An `ai://` application may package:

- React UI bundle
- manifest
- service/version metadata
- policy bindings
- projection bindings
- artifact references

## 19.1 `L0` Registry and Trust Anchor Role

For public `ai://` interoperability, the spec should explicitly model `IOI mainnet` as the `L0` root layer.

That means:

- `L0` is the global registry and trust anchor
- sovereign runtimes publish upward into `L0`
- clients and routers resolve downward from `L0` into serving runtimes

The closest analogy is not "a blockchain app store." It is a combined:

- root namespace registry
- publication transparency log
- trust-anchor layer
- resolver bootstrap layer

In practical `ai://` terms, `L0` should anchor:

- namespace ownership or delegation
- publisher identity commitments
- manifest root hashes
- version pointers
- runtime endpoint or resolver metadata
- policy or trust-profile anchors where needed

Then sovereign runtimes or child execution domains serve:

- the actual React bundles
- the `FQF` projections
- the live subscriptions
- the local or tenant-scoped execution state

That is the right separation between:

- `L0` as global coordination
- `L1` runtimes as execution and serving domains

## 19.2 Standards-Facing Surface

If IOI ever makes an external standards push, the most credible interoperability surface is not the entire chain design.

It is the protocol surface around:

- `ai://` URI and resolution semantics
- manifest and version resolution
- publisher identity and trust anchors
- portable capability or session token envelopes
- resumable subscription semantics
- receipt and proof envelopes
- runtime health and failover metadata

That is the part of the architecture that benefits from standards framing. The internal economic model and chain internals do not need to be the first thing exposed.

The application should be portable across nodes so long as nodes share:

- canonical state roots
- matching manifests and version pointers
- required projection definitions
- required artifacts by hash

This enables:

- installable apps
- portable serving
- multi-node serving of the same instance
- kernel-resolved application state without central hosted SQL authority

## 20. Multi-Node Serving

Multiple nodes should be able to serve the same logical application instance if they share:

- the same canonical roots
- the same object state
- the same projection definitions/checkpoints
- the same artifacts by hash

Serving should preserve a strict split between write authority and derived read-model serving:

- reads may be served widely
- projections may trail canonical truth within declared freshness bounds
- writes must hit ordering authority or an authorized forwarding path
- subscription continuity should prefer delta replay over snapshot rebuild when possible
- checkpoint shipping is a throughput primitive, not merely a resilience primitive

Locality rule:

- writes should route to the authoritative home region or shard for their ordering domain
- read-serving and projection-serving nodes may scale geographically subject to declared freshness and replay policies

That makes application serving:

- portable
- local-first
- edge-friendly
- less dependent on a single database authority

Projection portability is not only a failover feature; it is a throughput feature, because expensive read models can be restored from verified checkpoints rather than continuously recomputed from raw history on every serving node.

This is one of the strongest reasons to pursue `FQF`.

## 21. Distributed Runtime Serving Protocol

This section maps the concrete runtime mechanics required to make the multi-node serving claim true in practice.

The target end state is:

- a React app can reconnect to any healthy runtime node
- subscriptions can resume without replaying the whole world
- auth and capability state does not require sticky server sessions
- projections can be rebuilt or restored deterministically
- routing can fail over nodes without breaking app continuity
- write authority remains narrower than projection serving and subscription delivery
- plane-specific overload should degrade derived work before canonical correctness

This section intentionally aligns with patterns already present in the repo:

- cursor-based recovery and bounded sweeps in `docs/autopilot/notifications.md`
- persisted subscription worker state in `apps/autopilot/src-tauri/src/kernel/connectors/subscriptions.rs`
- delegated session auth in `crates/types/src/app/mod.rs`
- approval-token audience/replay/revocation bindings in `crates/types/src/app/action.rs`
- lease and receipt-commit sequencing in `crates/types/src/app/wallet_network/session.rs`

## 21.1 Resumable Subscriptions

Every durable `FQF` subscription must be defined as a protocol-visible object with:

- `subscription_id`
- `projection_id`
- `projection_version`
- `query_family`
- `filter_hash`
- `capability_scope_hash`
- `resume_policy`
- `retention_window`
- `delivery_mode`

Every projection-backed changefeed must emit a monotonic sequence within one projection lineage:

- `change_seq`
- `change_key`
- `projection_id`
- `projection_version`
- `source_state_anchor`
- `checkpoint_id` when applicable

The serving model should be:

- server pushes deltas when a live stream is available
- server also supports cursor-based catch-up
- client persists the latest contiguous acknowledgment in its local-first store
- reconnect never assumes affinity to the previous node

The subscription resume token should be opaque to the client but semantically bind:

- `subscription_id`
- `projection_id`
- `projection_version`
- `filter_hash`
- `capability_scope_hash`
- `session_id` or `lease_id`
- `runtime_audience`
- `last_acked_seq`
- `last_checkpoint_id`
- `expires_at`
- `nonce`
- `counter`

The token must be signed so any healthy node can validate it without consulting node-local session memory.

Resume flow:

1. Client reconnects with `resume_token`.
2. New node validates signature, expiry, revocation epoch, audience, and capability scope.
3. If the node still has the change log after `last_acked_seq`, it streams deltas from `last_acked_seq + 1`.
4. If the node no longer has that gap but has a valid projection checkpoint, it returns `rebase_from_checkpoint` plus the checkpoint reference and the next sequence floor.
5. Client hydrates from the checkpoint snapshot, reapplies newer deltas, and continues streaming.
6. If no ready checkpoint exists locally, the node either restores a replicated checkpoint or deterministically rebuilds the projection before resuming.

Resume policy rule:

- catch-up and resume should prefer incremental deltas when the gap is available
- checkpoint or snapshot rebase should be used only when the delta gap exceeds retention, availability, or freshness policy

Delivery semantics should be:

- at-least-once
- deterministic dedupe by `change_key`
- contiguous ack tracking by highest applied `change_seq`
- resumable across node failure

This mirrors the existing direction in Autopilot connector subscriptions, which already persist per-subscription progress and recover workers from durable state instead of keeping progress only in memory.

## 21.2 Stateless or Portable Session Auth and Capability Tokens

`FQF` must not rely on sticky node-local sessions for app reads, mutations, or subscriptions.

The correct model is signed portable authority artifacts modeled after the existing:

- `SessionAuthorization`
- `SessionLease`
- `ApprovalToken`

Portable session or capability tokens should carry:

- `session_id` or `lease_id`
- `subject_id`
- `issuer_id`
- `policy_hash`
- `capability_subset`
- `constraints_subset`
- `projection_scope`
- `expires_at`
- `revocation_epoch`
- `audience`
- `nonce`
- `counter`
- signature block

Validation on any node should be stateless except for canonical revocation and policy lookups:

- verify signature
- verify chain/runtime audience
- verify expiry
- verify revocation epoch
- verify capability subset and projection scope
- verify usage or spend limits when applicable

Important audience rule:

- portable read/subscription tokens should target the logical runtime or application instance, not one physical node
- executor-specific or one-shot sensitive actions should still use stricter audience-bound approvals on top of the portable token

That preserves both properties we want:

- cross-node failover for normal app continuity
- narrow executor binding for high-risk operations

Practical split:

- use portable session or lease tokens for reads, subscriptions, and routine mutations
- layer one-shot or short-lease approval tokens for sensitive capability execution

This is consistent with the current codebase, where `SessionAuthorization` delegates authority, while `ApprovalToken` remains tightly bound by audience, nonce, counter, and revocation epoch.

## 21.3 Deterministic Projection Rebuild and Replicated Checkpoints

Every portable projection must be reproducible from:

- canonical operations
- a deterministic `ProjectionDefinition`
- a total ordering rule over source changes

To make failover fast, `FQF` should support both deterministic rebuild and replicated checkpoints.

Each `ProjectionCheckpoint` should include:

- `checkpoint_id`
- `projection_id`
- `projection_version`
- `source_state_anchor`
- `source_height` or equivalent watermark
- `end_seq`
- `snapshot_artifact_hash`
- optional index or projection root
- created timestamp
- signer or proof reference

Checkpoint artifacts should live in the artifact substrate and be verified by hash before use.

Recovery modes:

- `hot restore`: load the newest verified checkpoint and replay only the delta after `end_seq`
- `warm restore`: fetch a replicated checkpoint from another node or blob backend, verify it, then replay forward
- `cold rebuild`: replay the canonical operation stream from genesis or an earlier anchor when no usable checkpoint exists

Compatibility rule:

- delta replay is valid only when `projection_version` matches
- version mismatch requires checkpoint rebase or full rebuild

Operational policy:

- hot projections should publish replicated checkpoints on a schedule and at upgrade boundaries
- cold projections may rebuild lazily
- node readiness must expose whether a projection is `ready`, `catching_up`, `rebuilding`, or `stale`

This is where `FQF` becomes much stronger than a normal cache. Projection state is portable because it is both hash-addressed and reproducible from canonical truth.

## 21.4 Routing and Health Above Runtime Nodes

Distributed serving needs a routing layer above runtime nodes.

That router does not own truth. It owns:

- node discovery
- liveness checks
- readiness checks
- failover decisions
- traffic steering

Router rule:

- routers may steer traffic based on locality, projection freshness, lag, and readiness
- routers must not become hidden sources of truth
- routers route, runtimes serve, ordering authorities order

Each serving node should expose health metadata for the logical app instance:

- `runtime_id`
- `app_instance_id`
- `manifest_hash`
- `state_anchor`
- `height`
- `projection_status[]`
- `changefeed_watermarks[]`
- `artifact_availability`
- `can_accept_reads`
- `can_accept_writes`
- `can_accept_subscriptions`
- `sequencer_role` or `write_forwarding_target`

Routing policy:

- reads may go to any healthy node with a sufficiently fresh projection
- subscriptions may go to any healthy node that can validate the token and resume from the requested checkpoint or sequence
- writes should go to the sequencer or to nodes authorized to forward writes into canonical ordering
- unhealthy or stale nodes should be drained before they are removed

Failure policy:

- if a node fails, the client reconnects through the router with the same session and resume tokens
- router selects another node whose manifest, state anchor lineage, and projection readiness satisfy the request
- resumed stream continues from delta or checkpoint rebase instead of full session restart

This is the piece that makes the sovereign runtime feel more like a resilient network and less like a single database-backed server.

## 21.5 Combined End-to-End Flow

Normal path:

1. User opens an `ai://` app backed by a local-first React store.
2. Client obtains a portable session or capability token scoped to the runtime and required projections.
3. Router sends the client to a healthy node with the required manifest and projection readiness.
4. Node serves an initial snapshot or checkpoint plus a live delta stream.
5. Client persists local cache, latest `change_seq`, and latest `resume_token`.

Failover path:

1. Current serving node fails or is drained.
2. Client reconnects through the router with the same portable token and latest `resume_token`.
3. New node validates auth statelessly from canonical state and revocation data.
4. New node resumes from retained delta if possible.
5. Otherwise it serves a verified checkpoint rebase and then continues the live stream.
6. User keeps the same logical app session without depending on one runtime node or one Postgres instance.

## 22. What FQF Replaces

## 22.1 Canonical Domains

These should move into kernel-native canonical object state:

- service publication
- version activation
- installs
- approvals
- capability leases
- billing events
- moderation decisions
- deployment pointers
- marketplace listing state
- tenant bindings

## 22.2 Derived Read Models

These should be maintained as `FQF` projections:

- dashboards
- search/filter views
- billing summaries
- moderation queues
- ranking/search outputs
- provider/admin views
- cross-device sync views

## 22.3 Blobs

These stay in the artifact substrate:

- manifests
- package bundles
- React bundles
- screenshots
- generated reports
- evidence bundles
- media

## 23. Performance-Sensitive Canonical Mutation Classes

Not all canonical mutations should be treated as the same throughput class.

`FQF` should distinguish at least three performance-sensitive classes.

## 23.1 Class A: Append-Heavy Event Domains

Examples:

- run events
- billing events
- moderation events
- subscription changes
- activity feeds

Target behavior:

- append-first
- batched
- projection-decoupled

## 23.2 Class B: Mutable Object Domains

Examples:

- service state
- version activation
- tenant bindings
- approvals
- capability leases

Target behavior:

- deterministic object transition
- conflict-aware concurrency
- scoped serialization only where required

## 23.3 Class C: Anchor and Registry Domains

Examples:

- global namespace commitments
- trust anchors
- root publication records

Target behavior:

- lower frequency
- higher proof and finality expectations

## 24. What FQF Does Not Replace

`FQF` should not replace:

- local UI stores
- temporary offline caches
- specialized low-level analytics engines where appropriate
- `SCS`
- all forms of object/blob storage

## 25. Applicability

## 25.1 Autopilot

Potential canonical state:

- local installs and pins
- approvals
- receipts
- recurring task state
- local service bindings

Potential projections:

- active context dashboards
- run history
- task queues
- Atlas read models
- trust/proof summaries

## 25.2 `aiagent.xyz`

Potential canonical state:

- listings
- installs
- version anchors
- trust anchors
- marketplace receipts

Potential projections:

- listing cards
- category views
- ranking/search
- trust badge views
- review aggregates

## 25.3 `sas.xyz`

Potential canonical state:

- service publication
- lane/target declarations
- pricing commitments
- deployment pointers
- billing events
- tenant policy events

Potential projections:

- deployment dashboards
- provider dashboards
- customer state views
- billing views
- admin and moderation screens

## 26. Migration Strategy

## 26.1 Phase 1. Canonical Truth First

Move durable business truth to kernel-native state for:

- services and versions
- approvals and leases
- receipts
- installs
- billing and moderation events

Use simple derived query layers initially.

## 26.2 Phase 2. Shared Projection Runtime

Introduce:

- projection definitions
- deterministic derived read models
- projection checkpoints
- subscriptions/changefeeds
- typed React bindings

Target:

- `Autopilot`
- `aiagent.xyz`
- `sas.xyz`

## 26.3 Phase 3. Supabase/Postgres Authority Displacement

Make `FQF` the authority layer for IOI-native app state.

At this point:

- Postgres may still exist as compatibility or reporting infrastructure
- but it is no longer the primary source of truth

## 26.4 Phase 4. Proof-Sensitive Views

Add stronger receipt/proof support for:

- trust badges
- ranking outputs
- billing exports
- dispute-sensitive reports
- high-stakes agent routing or recommendation views

## 27. Performance Success Metrics

`FQF` performance must be evaluated across separate dimensions rather than a single vanity throughput number.

Required metrics include:

- canonical mutation ingest TPS
- durable committed TPS
- per-domain write throughput
- per-domain write contention
- projection freshness lag
- projection backlog by family
- subscription resume latency
- checkpoint restore latency
- checkpoint debt
- replay debt
- multi-node catch-up lag
- read QPS by projection family
- write amplification per canonical mutation
- rebuild cost per projection size
- hot-key contention degradation
- hot-partition skew
- memory overhead per active projection or subscription

Observability rule:

- metrics must be exposed by plane rather than collapsed into one headline number
- read scale, projection scale, subscription scale, and per-domain write scale must be reported distinctly

Design rule:

> A high canonical TPS number alone is insufficient if it is achieved by pushing unbounded work into projection lag, checkpoint debt, or rebuild debt.

## 28. Success Criteria

`FQF` succeeds when IOI-native applications can:

1. store canonical shared app state without Postgres as authority
2. expose durable app-facing read models without bespoke backend glue
3. maintain local-first React UX via local app stores and cached projections
4. subscribe to realtime canonical changes
5. serve the same logical app instance across multiple nodes
6. package and resolve applications via `ai://` artifacts and manifests
7. keep `SCS` separate as the context plane
8. emit receipts for important queries and projections
9. preserve a minimal canonical hot path while allowing richer projections to lag within declared freshness bounds
10. restore or move hot projections from verified checkpoints instead of forcing raw-history recomputation on every node

## 29. Performance Anti-Goals

`FQF` should not:

- synchronously maintain every projection on canonical commit
- require proof-ready artifacts for every read
- force global ordering for unrelated tenant or object domains
- serialize large snapshots through small-message RPC paths when a bulk transfer path exists
- conflate canonical durability with immediate availability of every derived read model
- rebuild portable projections from raw history on every node restart when verified checkpoints are available
- imply that replicas increase write throughput for a single ordering domain
- hide cross-partition or proof-heavy work behind local-read abstractions

## 30. Failure Modes

`FQF` fails if:

- it tries to make every query canonical
- it collapses `SCS` into general app state
- it ignores local-first client ergonomics
- it becomes slower or more complex than a normal app stack without compensating gains
- it forces proof-heavy costs on every read path
- it forces commit-coupled maintenance of derived views that should be nearline or async
- it reintroduces unnecessary global serialization for unrelated workloads
- it launches a high-volume canonical domain without partition semantics
- it confuses read scale or projection scale with per-domain write scale
- each app has to invent its own cache, sync, and subscription model

## 31. Sharpest One-Line Definition

**Fractal Query Fabric is a kernel-native high-throughput canonical state and projection fabric for agentic applications, where operations are truth, the canonical hot path stays minimal, projections are portable derived artifacts, queries are capability-scoped and selectively receiptable, and React apps pair local-first stores with shared canonical state instead of relying on Postgres as authority.**

## 32. Bottom Line

This is a credible paradigm shift if and only if:

- `SCS` remains the context plane
- chain/object state remains canonical truth
- `FQF` becomes the shared app-state and projection authority
- canonical commit stays append-first, replayable, and narrower than derived read-model work
- React apps get excellent local-first client tooling
- multiple nodes can serve the same app instance from the same roots, projections, and artifacts

Under those conditions, `FQF` is not a database novelty.

It is the first serious attempt to make agent-native applications run on:

- kernel-native truth
- protocol-defined projections
- portable `ai://` bundles
- local-first UX

instead of the standard hosted Postgres-centered application stack.
