# Fractal Query Fabric (FQF) v0.5

## A Kernel-Native Canonical State, Projection, and Query Fabric for Agentic Applications

Historical note: earlier revisions of this spec described `SCS` as a separate
context plane. The live repository now uses `ioi-memory` for product-memory
flows and no longer ships an `SCS` crate.

## 1. Executive Summary

Fractal Query Fabric (`FQF`) is the proposed canonical state, projection, and
query fabric for agentic applications where receipts, replay, multi-node
continuity, capability-scoped reads, and portable execution state are
load-bearing.

It is especially aimed at IOI-native runtimes, `ai://` applications, and the
platform teams building the substrate beneath them.

It is not:

- SQL on a blockchain
- a decentralized Supabase clone
- a general replacement for Postgres-backed CRUD apps
- a replacement for every local UI store
- a resurrection of the old `SCS` memory story

It is:

- a kernel-native fabric for canonical operations and object state
- a projection system that materializes app-facing read models
- a receiptable query surface for agentic and user-facing applications
- a shared substrate for runs, tasks, approvals, artifacts, promotions, and durable knowledge
- the durable authority layer for IOI-native agentic systems that would otherwise be assembled from Postgres/Supabase plus workflow, sync, and audit glue
- a system that may ship with a first-party Postgres projection driver for SQL interoperability without treating Postgres as canonical authority or a runtime dependency
- when anchored on IOI mainnet, part of a larger `L0` story for global `ai://` registry, publication, and trust roots

The wedge is not "better database infrastructure."

It is:

> a substrate where meaningful reads, executions, promotions, and projections
> can produce verifiable evidence instead of relying on bespoke audit glue.

The architectural shift is:

> canonical truth lives in the fractal kernel; projections are first-class
> runtime artifacts; queries are capability-scoped and optionally receiptable;
> relational tables are only one projection family among many.

Performance doctrine:

> `FQF` is an append-first, projection-decoupled, deterministically replayable state fabric whose hot path remains narrower than its proof, query, and projection surfaces.

Scaling north star:

> `FQF` should scale by minimizing global truth, maximizing local read termination, and making every expensive derived artifact portable, replayable, and independently scalable.

This is not about displacing Postgres for ordinary software. It is about giving
agentic runtimes a substrate they do not currently have as a coherent product
or protocol category.

### 1.1 Market Fit

The market is narrower than "apps that would otherwise default to Postgres."
Most apps do not need this architecture and should not pay its complexity tax.

The real target is systems where these properties are load-bearing:

- replayable canonical truth
- native receipts and evidence trails
- resumable multi-node continuity
- capability-scoped reads and mutations
- portable execution and projection state

That is a smaller market than general application backends, but it is real,
growing quickly, and currently underserved.

### 1.2 Primary Buyer and Builder

Primary buyer for `FQF` v1:

- platform teams building agentic runtimes, orchestration fabrics, or sovereign application substrates

Primary operators:

- runtime teams responsible for continuity, policy, audit, upgrade, and repair behavior across nodes

Primary downstream builders:

- `ai://` application developers who want a shared substrate instead of assembling Postgres, workflow engines, ad hoc projection layers, and custom audit logic

V1 prioritization rule:

- optimize first for platform teams and runtime operators
- make application ergonomics excellent, but do not let general app-backend expectations blur the core market

### 1.3 Comparison Landscape

`FQF` should be read against the current default options for agentic systems,
not against the median CRUD stack.

- Durable Objects get colocated mutable coordination right, but they do not center the model on portable projection checkpoints, formal promotion, or native receipt lineage.
- Convex gets reactive app queries and developer ergonomics right, but it is not organized around a canonical operation log, evidence-grade receipts, or artifact privacy classes.
- Postgres plus Temporal is the practical default for serious workflow systems, but truth fragments across mutable rows, workflow history, caches, and bespoke projection glue.
- EventStore or CQRS-style stacks get replay and projections right, but usually stop short of capability-scoped reads, artifact privacy, portable session continuity, and promotion as protocol.
- Materialize and similar systems are powerful derived-view engines, but they are not the canonical authority and do not solve the receipt, policy, or promotion problem.

The competition is therefore less "one database" and more the stitched stack of:

- mutable OLTP authority
- workflow/event history
- custom projection machinery
- custom auth scoping
- custom audit and receipt infrastructure

### 1.4 Four Load-Bearing Properties

The spec is strongest when it centers four properties:

1. Canonical operation log plus deterministic object state as truth.
2. Portable projection checkpoints as a throughput primitive, not just a recovery tool.
3. Promotion as protocol rather than application convention.
4. Artifact privacy classes that separate ciphertext availability from plaintext readability.

Receipts are the organizing property across all four. They are not one feature
among many. They are the reason the fabric is materially different.

## 2. Decision

This spec adopts the following position:

- `Yes`: build `FQF` as the shared canonical state and projection fabric for IOI-native agentic runtimes and applications that need evidence-grade continuity.
- `No`: do not reintroduce `SCS` as a separate context plane; live product memory uses `ioi-memory`.
- `Yes`: let shared durable knowledge evolve toward wiki-shaped canonical objects, artifact references, and projections where that materially improves portability, provenance, and cumulative value.
- `Yes`: support artifact privacy classes where public availability of ciphertext is separable from plaintext readability.
- `Yes`: support React apps via local-first app stores plus `FQF` sync/query/mutation.
- `Yes`: ship a first-party Postgres projection driver as a blessed interoperability adapter for SQL-facing tools, APIs, and migrations.
- `No`: do not put working-memory scratch state, execution-local caches, or enrichment internals on the canonical hot path.
- `No`: do not silently promote ephemeral gig/task data into shared canonical wiki state.
- `No`: do not make every query, cache, or UI interaction part of canonical state.
- `No`: do not make Postgres a required dependency, privileged authority layer, or semantic write path for canonical state.
- `No`: do not turn `FQF` into a universal replacement for every database workload.

## 3. Why This Exists

The current default stack for serious agentic applications is still assembled
from parts:

- React frontend
- hosted Postgres as authority
- workflow engine or durable job runner
- blob storage for assets
- realtime layer bolted on
- vector store bolted on
- app-specific sync/cache logic bolted on

That stack is serviceable for CRUD software and adequate for some workflow
systems. It is weak for agentic software when the system must preserve evidence,
continuity, and portable state as first-class runtime properties.

The weaknesses are structural:

- truth fragments across mutable rows, workflow history, caches, and app code
- provenance and receipts are added after the fact
- promotion from local/session work into shared truth is implicit application logic
- multi-node continuity relies on sticky serving paths or bespoke repair logic
- artifact privacy and readable plaintext policy are usually conflated
- projection portability is treated as cache management rather than substrate design

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

## 3.1 Three Decisive Advantages

The argument for `FQF` should land on three claims.

1. Canonical truth is replayable.

   `FQF` treats the deterministic operation log and deterministic object
   transitions as authority. That is stronger than mutable-row truth for
   receipts, dispute resolution, historical reconstruction, and deterministic
   replay.

2. Projections are portable.

   Relational, graph, timeline, ranking, and capability read models become
   explicit versioned artifacts with checkpoints, replay, and cross-node
   movement. This turns projection state into a throughput primitive instead of
   disposable server-local glue.

3. Receipts are native.

   Queries, executions, promotions, and projections can all bind to canonical
   anchors, capability scope, and evidence surfaces. This makes verifiable
   explanation part of the substrate rather than an audit bolt-on.

Everything else in the spec should support those three claims or get out of
their way.

## 3.2 Why General Agentic Work Is The Category Center

`FQF` should be read first as a substrate for general agentic work, not as a
knowledge-base product.

If `FQF` is going to matter, it must model operational agent state just as
naturally as it models durable knowledge.

That means treating these as first-class concerns too:

- tasks and work orders
- runs and long-lived execution state
- approvals, reviews, and checkpoints
- branches, drafts, and promotion requests
- evidence bundles, generated outputs, and export artifacts
- recurring automations, gig executions, and marketplace work products

The broader architectural claim is:

1. The same substrate should support both "do work" and "remember work."

   Agentic systems do not divide cleanly into operational state on one side and
   knowledge state on the other. Runs produce artifacts, artifacts become
   evidence, evidence becomes reusable knowledge, and reusable knowledge shapes
   future runs.

2. Promotion between scopes is a general primitive, not a wiki-only primitive.

   Local scratch output, session collaboration output, reviewed shared work
   products, and durable published knowledge should all use one consistent
   promotion model governed by policy.

3. Artifact-native execution is a broader advantage than knowledge management.

   Reports, traces, notebooks, generated code bundles, spreadsheets, screenshots,
   receipts, and compiled wiki pages are all better modeled as artifacts plus
   canonical references than as oversized row payloads or opaque blob sidecars.

4. Projection-backed work surfaces are as important as knowledge surfaces.

   Task queues, approval inboxes, run timelines, review lanes, branch views,
   operator dashboards, and deployment boards should be normal `FQF`
   projections, not bespoke backend glue.

5. The architecture should make it easy to stay ephemeral, become collaborative,
   or become durable.

   A private gig can remain local. A collaborative run can live at session
   scope. A reviewed output can be promoted to shared operational state. A
   durable result can later become shared knowledge. That progression is the
   real power of the fabric.

## 3.3 Wiki-Shaped Knowledge Is An Important Example, Not The Market Definition

Wiki-shaped knowledge systems are a strong example of where `FQF` gets
particularly compelling, but they are not the category center.

They matter because they stress the same core properties:

- raw sources remain inspectable artifacts
- compiled pages and revisions accumulate as canonical objects
- backlinks, citations, and lineage become normal projections
- outputs can be filed back into shared state with explicit provenance
- large derived views can move across nodes through checkpoints and replay

The wiki story is therefore evidence that the general substrate works. It
should be presented as a powerful example, not as the main market definition.

## 4. Core Thesis

Traditional application stacks treat:

- mutable rows as truth
- files as external blobs
- indexes as hidden implementation details
- queries as untrusted reads

`FQF` rejects that for agentic systems that need evidence-grade continuity.

In `FQF`:

- canonical truth = operation log + deterministic state transitions
- canonical app objects = kernel-managed object state
- blobs = hash-addressed artifacts with explicit metadata and policy
- projections = explicit, versioned runtime artifacts
- queries = scoped runtime acts with optional receipts
- tables = one projection family
- SQL = optional compatibility surface exposed through adapters, never the canonical storage mode
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

## 5.3 `ioi-memory` and the Path to `ioi-wiki`

`ioi-memory` is the live runtime-backed memory substrate today.

It currently owns or stages:

- thread checkpoints and transcript hydration
- working/core memory sections
- archival records and retrieval inputs
- local artifact and evidence blobs
- enrichment job staging and execution-local caches

Important subsets of that surface may evolve into broader shared work and
wiki-shaped knowledge subsystems over time.

That future shape would promote shared, durable, inspectable work and knowledge into:

- task, run, review, and promotion objects
- wiki spaces, documents, and revisions
- source manifests and ingestion lineage
- citation, backlink, and derived-from edges
- generated reports, slide decks, plots, and filed-back answers
- knowledge-oriented projection checkpoints and sync surfaces

Boundary rule:

- local working memory, transient execution state, and execution-local caches remain runtime-owned
- shared durable work or knowledge that must survive across nodes should graduate into canonical `FQF` objects plus artifact references and projections
- enrichment outputs such as summaries, embeddings, link suggestions, contradiction scans, and retrieval candidate sets remain derived artifacts unless explicitly promoted by policy

`FQF` should therefore integrate cleanly with `ioi-memory` as it exists today
while leaving room for a future `ioi-wiki` evolution that makes wiki-shaped
knowledge a first-class product surface.

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
- wiki compilation from raw sources
- broad cache invalidation sweeps

### Near-Hot Path

Work that should follow canonical commit quickly but may be batched or processed asynchronously.

Examples:

- projection delta application
- lightweight index updates
- changefeed publication
- checkpoint scheduling
- backlink/citation delta application
- source-ingest metadata updates

### Async Derived Path

Work that may lag canonical truth while remaining deterministically derivable.

Examples:

- complex relational rebuilds
- graph recomputation
- ranking refreshes
- recommendation candidate generation
- wiki page compilation and refiling
- summary, entity, and fact extraction
- embedding refresh and retrieval candidate generation
- link suggestion and inconsistency scans
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
- task and recurring-work definitions
- execution intents, requests, and receipts
- run and workflow state
- branch and promotion state
- deployment pointers
- install events
- approvals and capability leases
- policy definitions and important policy decisions
- billing events
- moderation events
- listing and marketplace state
- tenant bindings
- artifact references
- artifact bundles and evidence sets
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
- `Task`
- `Intent`
- `Workspace`
- `Run`
- `Worker`
- `Receipt`
- `ExecutionRequest`
- `ExecutionLease`
- `ExecutionReceipt`
- `Approval`
- `Review`
- `SessionBranch`
- `CapabilityLease`
- `PolicyDecision`
- `TenantBinding`
- `Listing`
- `ArtifactRef`
- `ArtifactBundle`
- `EvidenceSet`
- `PromotionRequest`
- `RepairTicket`
- `DeploymentPointer`
- `ProjectionDefinition`
- `ProjectionCheckpoint`
- `SubscriptionDefinition`

Primary property:

- object-first truth, not row-first truth

### Concurrency and Merge Classes

`FQF` should not leave concurrency semantics implicit at the application layer.

Every canonical object class should declare one of a small number of explicit
concurrency classes:

- `append_only`: facts and events accumulate without in-place overwrite
- `compare_and_set_head`: a canonical head advances only from an expected prior
  version or anchor
- `lease_governed`: mutation requires a valid claim, approval, or exclusive
  lease for a bounded time window
- `branch_and_merge`: drafts may diverge and later merge through explicit merge
  policy
- `proposal_and_promotion`: state may be proposed freely, but shared canonical
  adoption requires review or promotion policy

Default architectural rule:

- high-value work and knowledge objects must not silently rely on generic
  last-write-wins semantics

Examples:

- run events, source-ingest events, and receipts are usually `append_only`
- task heads, run heads, deployment pointers, and wiki page heads are usually
  `compare_and_set_head`
- approvals, execution claims, and worker ownership are usually
  `lease_governed`
- drafts, plans, wiki revisions, and collaborative outputs may be
  `branch_and_merge`
- local/session artifacts and proposed outputs that want to become shared truth
  are `proposal_and_promotion`

Conflict material should be explicit:

- expected prior head or version
- branch lineage or merge base
- conflict policy id
- actor capability scope
- review or approval references when required

The point is not to eliminate conflict. The point is to make conflict handling a
protocol property instead of hidden backend behavior.

### Promotion Protocol

Promotion between scopes should be a first-class protocol, not an application
convention.

Any movement from:

- local to session
- local or session to shared operational state
- local or session to shared wiki knowledge
- private to shared encrypted
- shared work product to durable published knowledge

should be modeled as an explicit promotion flow.

Promotion is one of the hardest things to fake with application glue and one of
the strongest sources of leverage in `FQF`.

It is the point where the system answers questions such as:

- what local or session work is eligible to become shared truth
- what evidence supports that move
- what policy, review, or approval path is required
- what exactly changed when promotion was accepted

#### Promotion Objects

A `PromotionRequest` should bind:

- `promotion_id`
- source scope
- target scope
- source object refs and/or artifact bundle refs
- evidence set refs when present
- requested canonical mutations
- requested head changes or object creations
- requested privacy-class or retention changes
- policy hash
- actor identity and capability scope
- idempotency key
- expected prior heads or merge base where relevant
- requested reviewers or approvers when required
- review policy or promotion policy id
- reason, automation source, or upstream run reference
- created-at / expires-at bounds

Promotion results should be explicit:

- proposed
- admitted
- needs review
- approved
- committed
- rejected
- needs additional evidence
- expired
- superseded

Promotion rule:

- shared canonical work state and shared durable knowledge must not be created
  by silent scope leakage
- promotion is the protocol boundary that turns useful local/session work into
  durable shared truth

#### Promotion Flow

Minimum flow:

1. Create `PromotionRequest` against stable source refs, bundle refs, and
   optional evidence refs.
2. Run admission checks for capability scope, policy eligibility, privacy-class
   changes, and required approvals.
3. If policy requires human or delegated review, route the request into explicit
   review state rather than allowing silent background mutation.
4. Reviewers inspect a stable evidence snapshot, not mutable draft state.
5. Approval artifacts or review decisions bind back to the exact
   `PromotionRequest`.
6. Commit applies the requested canonical mutations only if preconditions still
   hold, including expected heads, policy version, and required approvals.
7. Commit creates or advances the shared canonical objects and emits a
   `PromotionReceipt`.

Commit rule:

- promotion commit must be idempotent
- promotion commit must fail explicitly if source lineage, expected heads, or
  required approvals no longer match
- promotion must not silently mutate source artifacts or source drafts in place
- when promotion creates a shared head, the resulting lineage must point back to
  the admitted request and supporting evidence

Review rule:

- review should bind to evidence bundles, receipts, and immutable artifacts
  rather than loose comments over mutable state
- approval and rejection should themselves be canonical objects when they matter
  for governance, audit, or later appeal

#### Promotion Receipt

When important, promotion should emit a `PromotionReceipt` that explains:

- promotion id and outcome
- what moved
- which source refs, bundle refs, or evidence refs were considered
- why it was admissible
- what policy authorized it
- which reviews or approvals were satisfied
- what new shared objects or heads were created
- what privacy-class or retention changes occurred
- what canonical anchors bind the result

### Bundle and Evidence Model

Agentic work rarely produces only one file at a time.

`FQF` should therefore treat bundles and evidence sets as first-class objects
above individual artifact refs.

`ArtifactBundle` is the portable grouping object for related immutable payloads,
such as:

- screenshots, traces, and logs from one run
- notebook, report, and chart outputs from one analysis
- draft wiki revisions plus source excerpts and generated images
- export packages for delivery or handoff

An `ArtifactBundle` should bind:

- stable bundle id
- member artifact refs by role
- manifest or index artifact when present
- source run/task/review/promotion refs
- privacy class and serving policy

`EvidenceSet` is the semantic binding object that says which bundles, receipts,
and references support a claim, execution result, review, or promotion.

Design rule:

- reviews, exports, promotions, and high-value outputs should point at bundles
  or evidence sets rather than loose file lists
- bundle transport and verification should reuse the same artifact-by-hash
  discipline as single artifacts

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

### Artifact Privacy Classes

`FQF` should treat artifact privacy as a first-class contract, not an
application afterthought.

At minimum, artifact refs should support these privacy classes:

- `local_ephemeral`: runtime-local artifacts used for scratch work, private gigs,
  or teardown-oriented execution; not replicated or promoted by default
- `scoped_private`: encrypted artifacts intended for one runtime, tenant, or
  bounded collaboration scope
- `shared_encrypted`: ciphertext may be fetched, cached, mirrored, or served
  widely by hash, while plaintext remains restricted by access policy and key
  release policy
- `public_plaintext`: readable by anyone with the artifact reference

Core rule:

- artifact availability and artifact readability are separate concerns
- public or semi-public availability of ciphertext must not be mistaken for
  public readability of plaintext

### Key Release and Decryption Semantics

Artifact privacy should compose with the IOI capability plane rather than
inventing a separate secret model.

Implementation direction:

- canonical state binds the artifact hash, privacy class, access policy, and
  key-envelope or equivalent decryption policy reference
- decryption rights should be released through capability-, lease-, or
  approval-bound flows rather than static node-local session memory
- trusted runtimes should prefer transient unwrap or operation-scoped decrypt
  capability over exporting long-lived raw keys to untrusted agents
- revocation should govern future key release even though it cannot revoke
  plaintext already disclosed to an authorized reader

This is where `wallet.network`-style capability control becomes particularly
useful: the artifact can be durable and portable while plaintext access remains
policy-bounded, auditable, and revocable for future reads.

### Metadata Leakage and Privacy Limits

Encrypted artifacts still leak some things unless the system explicitly works to
hide them.

Likely residual leakage includes:

- artifact existence
- rough size
- creation/update timing
- linkage between repeated references to the same ciphertext
- access-pattern hints from reads or checkpoint movement

Therefore:

- `FQF` should support metadata classes and minimal-metadata artifact refs
- size padding and delayed publication should be available for sensitive domains
- the architecture must not overclaim privacy just because payload bytes are encrypted

V1 recommendation:

- do not require searchable encryption or public proof of hidden plaintext
- instead allow authorized runtimes to decrypt within policy and build scoped
  projections or retrieval views from plaintext when necessary

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
- typed execution requests
- subscriptions/changefeeds
- capability-scoped reads
- policy and promotion explanations
- provenance-aware reads
- optional SQL compatibility via projection adapters
- optional GraphQL-like adapters

Primary property:

- developer and agent ergonomics

### Unified Policy Decision Surface

`FQF` should not fragment policy evaluation across unrelated subsystems.

The same decision surface should govern:

- read visibility
- execution authorization
- decryption and key release
- promotion eligibility
- export or share permissions
- retention and teardown obligations
- repair permissions for sensitive domains

When a decision matters, the system should be able to surface a structured
`PolicyDecision` binding:

- subject or actor
- action
- resource or object set
- scope
- policy hash
- constraints and approvals considered
- decision result
- expiry or reevaluation horizon

Design rule:

- if an action can be denied, promoted, decrypted, exported, or billed, it
  should be explainable through the same policy surface

### Execution and Side-Effect Model

General agentic systems do not stop at data mutation. They request and perform
side effects.

`FQF` should treat side-effecting work as a first-class protocol flow:

1. declare intent
2. create an `ExecutionRequest`
3. obtain any required approvals or `ExecutionLease`
4. perform the attempt under idempotency and budget rules
5. emit an `ExecutionReceipt`
6. optionally promote the result into shared operational state or knowledge

An execution request should bind:

- target service, tool, or capability
- idempotency key
- effect class and risk class
- input object refs and/or bundle refs
- budget class
- expected output refs or output policy
- rollback hint or compensation strategy when applicable

Execution rule:

- canonical mutation and external side effect must not be conflated
- sensitive execution should require narrow approval or lease artifacts even
  when normal reads and subscriptions use portable runtime tokens
- side effects should be idempotent, compensatable, or receipted strongly
  enough that replay and retry behavior are well-defined

This is one of the main differences between a good state fabric and a superior
agentic runtime.

## L5. Extensibility Layer

Optional domain-specific extensions.

Can support:

- custom projection definitions
- custom ranking functions
- vertical query adapters
- Wasm or plugin-based projection logic

Primary property:

- extensibility without turning the kernel into "just another contract host"

## Separate Plane. Runtime Working Memory and Knowledge Enrichment

Owns:

- thread checkpoints and transcript hydration
- working/core memory sections and runtime registers
- execution-local cache entries
- local mirrors, compaction state, and transient worker state
- enrichment staging, embeddings, and retrieval inputs before promotion
- local privacy and redaction handling for runtime-owned data

Primary property:

- what the runtime is currently doing and what the agent is working on right now

Boundary note:

- shared durable wiki knowledge may graduate into `FQF`
- local working memory must not be forced into canonical truth just because it is useful to the runtime

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
- local run branches
- private gig/task execution
- local encrypted artifacts pending teardown

## 12.2 Session Scope

Examples:

- collaborative workspace state
- temporary worker slices
- session-scoped projections
- short-lived subscriptions
- shared task state
- collaborative run and review state
- bounded private collaboration over encrypted artifacts

## 12.3 Global Scope

Examples:

- service publication
- published automations and marketplace gigs
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
- promotion policy

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

Relational projections matter because a large amount of surrounding software
already expects a SQL-shaped read surface.

Design rule:

- relational projections are explicit derived artifacts over canonical `FQF` truth
- they are not an alternate authority path
- `FQF` can project into Postgres, but `FQF` does not run on Postgres
- a first-party Postgres driver is recommended as an interoperability bridge, not as a default dependency

### Postgres Projection Driver

`FQF` should define a blessed Postgres projection driver for:

- existing APIs and admin panels
- BI, analytics, and reporting tools
- ORM-heavy integration layers
- incremental migration from legacy application stacks

Placement rule:

- the Postgres driver sits after projection runtime, not underneath canonical state
- it consumes named projection outputs; it does not interpret or finalize business truth

Driver invariants:

- one-way authority: Postgres receives derived state from `FQF`; it never defines canonical truth
- no semantic writes: managed Postgres relations must not mutate canonical state directly
- deterministic derivation: the same canonical history, projection definition, and projection version must emit the same relational result
- explicit freshness: every exposed rowset must bind to projection lineage and canonical watermark metadata
- receipt lineage: query receipts, when offered, must root to `FQF` snapshot or projection lineage rather than arbitrary SQL transaction state
- rebuildability: Postgres materialization must be disposable and reconstructible from canonical state plus projection definitions and checkpoints

Driver responsibilities:

- subscribe to named projection outputs by `projection_id` and `projection_version`
- emit deterministic schemas, tables, views, or materialized views from projection definitions
- publish lag, health, schema-version, and checkpoint metadata explicitly
- preserve provenance columns or companion metadata such as `fqf_projection_id`, `fqf_projection_version`, `fqf_canonical_watermark`, and optional `fqf_snapshot_root`
- support rebuild from checkpoint restore plus bounded replay or full canonical replay
- fence, reject, or ignore direct semantic writes to adapter-managed relations

Driver non-responsibilities:

- canonical ordering
- authority over business state
- settlement or finalization
- canonical policy enforcement
- semantic conflict resolution

Recommended exposure patterns:

- append-only event tables for chronological consumers
- current-state tables for operational APIs and dashboards
- stable SQL views over adapter-managed storage for compatibility cutovers

Legacy write compatibility rule:

- if a legacy system can only "write to Postgres," it must write into a staging or inbox schema that translates rows into formal `FQF` intents
- that staging schema is a compatibility ingress surface, not authority

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

- embeddings, semantic candidate sets, and retrieval inputs may live in `ioi-memory` or a successor runtime knowledge layer until explicitly promoted
- `FQF` may still maintain semantic projections over canonical object metadata, artifact manifests, and promoted knowledge nodes

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

## 13.8 Workflow / Workcell Projections

For:

- task queues and work boards
- run and worker timelines
- approval/review inboxes
- branch and promotion views
- operator and supervisor dashboards
- deployment and handoff surfaces

Doctrine:

- the same projection runtime that serves wiki views should also serve work
  execution views
- operational projections should remain portable, resumable, and policy-scoped

## 13.9 Wiki / Knowledge Projections

For:

- wiki page and revision heads
- backlink and citation views
- concept/topic indexes
- source coverage and lineage dashboards
- stale-page queues
- output filing and review views
- wiki synchronization feeds

Doctrine:

- raw files live as artifacts
- shared wiki documents and revisions become canonical objects when they matter as shared truth
- retrieval, search, recommendation, and enrichment views over the wiki remain projections unless promoted by policy
- private or gig-oriented outputs should remain local or session-scoped unless explicitly promoted

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

### Workflow-Native Queries

Examples:

- what is blocked, pending review, or ready to run
- what changed in this branch since the last approval
- which artifacts and receipts were produced by this run
- what should be promoted from session scope to shared scope

### Execution-Native Queries

Examples:

- which execution requests are runnable under current policy and budget
- why did this run stall, retry, or require escalation
- what side effects were attempted, committed, compensated, or abandoned
- which outputs belong to this execution receipt or evidence set

### Policy and Promotion Queries

Examples:

- why was this action, decrypt, or export denied
- why was this promotion rejected or held for review
- which approvals or leases are still missing
- what would change if this bundle were promoted to shared scope

### Hybrid Symbolic + Semantic Queries

Examples:

- exact filters plus semantic ranking
- structured lookup plus candidate expansion
- deterministic constraints plus retrieval shortlist

### Knowledge-Native Queries

Examples:

- what sources support this page or answer
- what changed since this wiki revision
- which pages should be updated because this source changed
- find contradictions, missing links, or stale summaries

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

Receipts are not a side feature. They are one of the main reasons `FQF`
exists.

The distinct promise is that significant reads, executions, promotions, and
projection surfaces can all be bound to verifiable evidence. Query receipts are
the read-side expression of that broader property.

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

- parts of the repo's retrieval history have explored stricter certifying modes for proof-sensitive cases
- `FQF` should not weaken any retrieval mode that explicitly claims certification, evidence binding, or proof-sensitive semantics

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
- encrypted artifact payloads should move independently of decryption rights
- decryption material or unwrap grants should travel only through the capability-controlled path, not inside bulk artifact transport

This discipline matters if `FQF` wants to preserve the kernel's transport gains instead of wrapping them in expensive serialization ceremony.

### Workload Scheduling and Budget Discipline

`FQF` also needs explicit workload control if it wants to be a better runtime,
not just a richer storage model.

At minimum, these work classes should have independently observable queues,
budgets, and degradation rules:

- canonical ingress
- projection maintenance
- subscription delivery
- checkpoint publication and restore
- enrichment and semantic indexing
- execution attempts
- proof-heavy queries
- decryption and key release
- export and promotion work
- teardown and repair work

Budget rule:

- execution requests and heavy queries should declare a budget class
- overload should degrade enrichment, rebuild, export, and proof-heavy work
  before it compromises canonical correctness or basic subscription continuity
- budget exhaustion must be visible to operators and explainable to agents

This keeps the system honest under pressure instead of pretending every queue is
equally important.

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

Promotion and privacy rule:

- local work should remain local by default
- private gig/task flows may complete entirely in local or session scope
- moving outputs into shared wiki state or shared encrypted artifacts must be an explicit promotion step

Client continuity rule:

- the local-first client store should be treated as the first read replica for interactive UX
- UI continuity should survive transient node failure, projection catch-up, and network interruption without requiring every interaction to hit canonical authority

## 18.2 What Replaces Supabase-Like Authority

The replacement stack is:

- React UI
- local-first app store
- kernel runtime
- `FQF` for canonical authority
- optional Postgres projection driver for SQL interoperability and legacy integration
- blob/artifact substrate for immutable assets
- runtime working memory via `ioi-memory` or its successor knowledge-runtime surface

That is the right substitution target, not "Postgres for everything." The
adapter is a bridge, not a base.

## 18.3 Shared Client Runtime Requirement

This only works if all apps share one app-facing runtime:

- typed schemas
- query client
- mutation queue
- execution client
- promotion client
- subscription client
- optimistic update support
- invalidation and sync rules
- bundle hydration and materialization rules
- policy explanation surfaces
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

This section is an optional IOI-network profile, not part of the minimum claim
required for `FQF` to make sense as a runtime fabric.

`FQF` does not require a global `L0` registry in order to be coherent as a
local, tenant-scoped, or sovereign runtime substrate.

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

## 21.6 Repair, Reconciliation, and Drift Control

Portable projections and artifact-backed execution make repair a normal part of
the runtime, not an embarrassment to hide.

Failure and drift surfaces include:

- projection lag or corruption
- stuck or replay-expired subscriptions
- missing artifact replicas or incomplete bundles
- failed decrypt or key-release paths
- promotion requests that lost required evidence or approvals
- local/session teardown that did not complete on schedule
- divergent local caches after reconnect

The architecture should support explicit repair flows such as:

- replay missing deltas
- rebase from checkpoint
- rebuild projection from canonical history
- rehydrate missing bundle members
- reevaluate policy or approval state
- retry, cancel, or expire promotion requests
- garbage collect expired local artifacts and execution-local state

When repair matters operationally, it should be visible as a protocol object or
ticket, not only as a hidden log line.

Each serving domain should expose:

- repair backlog by class
- oldest unresolved drift age
- last successful checkpoint validation
- last successful teardown sweep
- artifact completeness by bundle class

Rule:

- the system should be able to explain not only normal reads and writes, but
  also why a degraded surface is degraded and what repair path is in flight

## 21.7 Compatibility Profiles and Rolling Upgrades

The spec is now broad enough that it should distinguish mandatory core behavior
from optional extension profiles.

Core portable profile:

- canonical objects and operation replay
- artifact refs and bundle refs
- projection definitions, checkpoints, and resumable subscriptions
- portable session/capability tokens
- promotion protocol
- execution requests and receipts
- policy decision explanations

Optional extension profiles:

- encrypted artifact and key-release profile
- proof-sensitive query and receipt profile
- semantic or enrichment-heavy projection profile
- SQL/Postgres interoperability profile
- large-checkpoint and bulk-transport profile

Every runtime node should advertise:

- supported protocol version
- supported profile set
- projection and query family versions
- incompatible feature gates, if any

Rolling upgrade rule:

- nodes may serve the same logical instance only when their overlapping profile
  set is sufficient for the requested operation
- profile mismatches must fail explicitly rather than silently misinterpreting
  checkpoints, tokens, or bundle semantics
- upgrade boundaries should prefer checkpoint publish and version pinning over
  ad hoc mixed semantics

## 22. What FQF Replaces

## 22.1 Canonical Domains

These should move into kernel-native canonical object state:

- service publication
- version activation
- task templates and recurring-work definitions
- execution intents, requests, leases, and receipts
- run state and workflow checkpoints
- installs
- approvals
- capability leases
- policy definitions and important policy decisions
- branch, review, and promotion state
- billing events
- moderation decisions
- deployment pointers
- marketplace listing state
- tenant bindings
- wiki spaces and knowledge namespaces
- wiki document identities and revision heads
- source manifests and ingestion lineage
- citation/backlink/derived-from edges
- bundle and evidence-set identities
- output filing and publication state

## 22.2 Derived Read Models

These should be maintained as `FQF` projections:

- dashboards
- search/filter views
- SQL/Postgres interoperability surfaces rooted in named projections
- task queues and approval inboxes
- run timelines and worker views
- execution queues and attempt views
- branch and promotion boards
- policy explanation and promotion review views
- billing summaries
- moderation queues
- ranking/search outputs
- provider/admin views
- cross-device sync views
- backlink and citation views
- topic and lineage graphs
- stale-page and review queues
- source coverage dashboards
- knowledge sync and recent-changes feeds

## 22.3 Blobs

These stay in the artifact substrate:

- manifests
- package bundles
- React bundles
- screenshots
- generated reports
- evidence bundles
- execution traces and delivery packages
- media
- source articles, papers, datasets, and downloaded media
- wiki markdown revisions
- generated slide decks and plots
- notebooks, code bundles, and structured work products
- encrypted gig/task outputs that are portable but not publicly readable

## 23. Performance-Sensitive Canonical Mutation Classes

Not all canonical mutations should be treated as the same throughput class.

`FQF` should distinguish at least three performance-sensitive classes.

## 23.1 Class A: Append-Heavy Event Domains

Examples:

- run events
- task state transitions
- billing events
- moderation events
- subscription changes
- activity feeds
- wiki revision events
- source-ingest events

Target behavior:

- append-first
- batched
- projection-decoupled

## 23.2 Class B: Mutable Object Domains

Examples:

- service state
- version activation
- task heads
- run heads
- tenant bindings
- approvals
- capability leases
- wiki page heads
- publication pointers
- merge and review state

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

## 24. What FQF Refuses To Be

`FQF` is not:

- an OLTP database
- a graph database
- a search engine
- a pub/sub broker
- a workflow engine
- a blob store

It is a canonical state and projection substrate from which relational, graph,
ranking, subscription, workflow, and evidence surfaces can be derived.

## 24.1 What It Still Does Not Replace

`FQF` should not replace:

- local UI stores
- temporary offline caches
- runtime working-memory sections and transcript checkpoints
- execution-local caches and staging queues
- the actual external systems invoked by execution requests
- the capability-control plane that governs key release and sensitive approvals
- specialized low-level analytics engines where appropriate
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

## 25.4 General Agentic Workflows

Potential canonical state:

- task definitions and run state
- execution requests and receipts
- branch, review, and promotion state
- approvals and capability leases
- operator handoff state
- output artifact refs and export state

Potential projections:

- task queues and kanban-style work boards
- run histories and worker timelines
- execution queues, receipts, and escalation views
- approval/review inboxes
- branch, diff, and promotion views
- operator dashboards and escalation views

## 25.5 Wiki-Shaped Knowledge Bases

Potential canonical state:

- wiki spaces and access policy
- document identities and revision heads
- source manifests and ingestion lineage
- citation/backlink/derived-from edges
- output filing and review state
- promotion policies for private vs shared artifacts

Potential projections:

- compiled wiki page views
- backlink and citation graphs
- concept/topic maps
- stale-page and contradiction queues
- source coverage dashboards
- hybrid symbolic + semantic knowledge views

## 26. Migration Strategy

## 26.1 Phase 1. Canonical Truth First

Move durable business truth to kernel-native state for:

- services and versions
- tasks, runs, branches, and approvals
- execution requests, receipts, and policy decisions
- approvals and leases
- receipts
- installs
- billing and moderation events
- wiki space and document identities
- revision heads and source manifests
- artifact privacy-class and promotion-policy bindings

Use simple derived query layers initially.

## 26.2 Phase 2. Shared Projection Runtime

Introduce:

- projection definitions
- deterministic derived read models
- projection checkpoints
- subscriptions/changefeeds
- typed React bindings
- task, run, approval, and promotion projections
- execution, policy, and repair projections
- wiki index, backlink, and lineage projections
- knowledge-oriented sync feeds
- privacy-class-aware artifact refs and transport

Target:

- `Autopilot`
- `aiagent.xyz`
- `sas.xyz`
- emerging wiki-shaped knowledge surfaces

## 26.3 Phase 3. Supabase/Postgres Authority Displacement

Make `FQF` the authority layer for IOI-native app state.

At this point:

- Postgres may still exist as compatibility or reporting infrastructure
- the first-party Postgres driver should be easy to enable but not required for canonical operation
- SQL consumers should read explicit projection version, watermark, and lag metadata rather than treating adapter state as self-authorizing truth
- legacy write compatibility, when needed, should flow through staging/inbox translation into formal `FQF` ingress
- but it is no longer the primary source of truth
- `ioi-memory` becomes increasingly local/runtime-facing as shared durable knowledge moves into canonical wiki objects, artifact refs, and projections
- private gig/task flows can stay local or session-scoped without creating durable shared wiki residue unless promoted

## 26.4 Phase 4. Proof-Sensitive Views

Add stronger receipt/proof support for:

- trust badges
- ranking outputs
- billing exports
- dispute-sensitive reports
- high-stakes agent routing or recommendation views
- citation-sensitive knowledge exports
- knowledge lineage and source-support views

## 27. Performance Success Metrics

`FQF` performance must be evaluated across separate dimensions rather than a single vanity throughput number.

Required metrics include:

- canonical mutation ingest TPS
- durable committed TPS
- per-domain write throughput
- per-domain write contention
- projection freshness lag
- projection backlog by family
- knowledge-enrichment backlog by kind
- wiki compilation lag from source ingest to filed revision
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
- private-artifact key-release latency
- policy-decision latency by class
- execution admission latency by budget class
- repair backlog and mean time to recovery
- teardown completion latency for ephemeral gig/task runs

Observability rule:

- metrics must be exposed by plane rather than collapsed into one headline number
- read scale, projection scale, subscription scale, and per-domain write scale must be reported distinctly

Design rule:

> A high canonical TPS number alone is insufficient if it is achieved by pushing unbounded work into projection lag, checkpoint debt, or rebuild debt.

## 28. Success Criteria

`FQF` succeeds when agentic runtimes and applications that need evidence-grade
continuity can:

1. store canonical shared app state without Postgres as authority
2. expose durable app-facing read models, including SQL-facing interoperability surfaces, without bespoke backend glue
3. maintain local-first React UX via local app stores and cached projections
4. subscribe to realtime canonical changes
5. serve the same logical app instance across multiple nodes
6. package and resolve applications via `ai://` artifacts and manifests
7. model tasks, runs, approvals, branches, promotions, and artifacts as first-class shared state
8. support wiki-shaped shared knowledge where raw sources, compiled pages, and filed-back outputs accumulate in one artifact and projection fabric
9. keep runtime working memory and enrichment staging separate from canonical shared knowledge
10. support artifact privacy classes where ciphertext availability and plaintext readability are not conflated
11. allow private gig/task flows to run, export, and tear down without implicit promotion into shared canonical wiki state
12. treat promotion across scopes as a formal protocol rather than ad hoc app logic
13. treat side-effecting execution as a first-class, receipted, policy-bound flow
14. unify read, execute, decrypt, export, and promote decisions behind one explainable policy surface
15. emit receipts for important queries, executions, promotions, and projections
16. preserve a minimal canonical hot path while allowing richer projections to lag within declared freshness bounds
17. restore or move hot projections from verified checkpoints instead of forcing raw-history recomputation on every node
18. expose repair, drift, and rolling-upgrade behavior as explicit runtime concerns instead of hidden operator folklore

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
- make promotion or side-effect execution semantics application-specific guesswork
- let every app invent its own policy explanation or retry model

## 30. Failure Modes

`FQF` fails if:

- it tries to make every query canonical
- it collapses runtime working memory or enrichment staging into general app state
- it confuses public ciphertext availability with public plaintext readability
- it ignores local-first client ergonomics
- it becomes slower or more complex than a normal app stack without compensating gains
- it forces proof-heavy costs on every read path
- it forces commit-coupled maintenance of derived views that should be nearline or async
- it reintroduces unnecessary global serialization for unrelated workloads
- it launches a high-volume canonical domain without partition semantics
- it confuses read scale or projection scale with per-domain write scale
- it treats every embedding, summary, or enrichment result as canonical hot-path truth
- it files private gig/task outputs into shared wiki state by default
- it becomes a knowledge-only niche and fails to model general operational agent state cleanly
- each app has to invent its own cache, sync, and subscription model
- it makes Postgres a required dependency for normal canonical operation
- it lets adapter-managed Postgres relations become a backdoor write path or a hidden fallback source of truth
- side-effecting execution remains a bespoke app-layer concern without shared receipts, idempotency, or approval semantics
- promotion across scopes remains implicit and leaks private/session work into shared state
- repair and upgrade behavior are too implicit for operators or agents to reason about safely

## 31. Sharpest One-Line Definition

**Fractal Query Fabric is a kernel-native high-throughput canonical state and projection fabric for agentic applications, where operations are truth, the canonical hot path stays minimal, runs/tasks/executions/approvals/artifacts/knowledge all share one object-first substrate, promotions and side effects are formal protocol flows, projections are portable derived artifacts, policy is explainable, and React apps pair local-first stores with shared canonical state instead of relying on Postgres as authority.**

## 32. Bottom Line

This is a credible paradigm shift if and only if:

- runtime working memory and enrichment staging remain separate from shared canonical knowledge
- chain/object state remains canonical truth
- `FQF` becomes the shared app-state, work-state, wiki-state, and projection authority
- promotions, executions, and policy decisions become protocol-visible instead of bespoke backend glue
- canonical commit stays append-first, replayable, and narrower than derived read-model work
- React apps get excellent local-first client tooling
- multiple nodes can serve the same app instance from the same roots, projections, and artifacts
- repair, budget, and upgrade behavior stay explicit enough for operators and agents to trust the runtime

Under those conditions, `FQF` is not a database novelty.

It is the first serious attempt to make agent-native applications run on:

- kernel-native truth
- protocol-defined projections
- portable `ai://` bundles
- local-first UX

instead of the standard hosted Postgres-centered application stack.
