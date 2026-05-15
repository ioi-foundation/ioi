# FQF Agentic Runtime And Wiki Evolution Master Guide Plan

Last updated: 2026-04-05
Owner: active Codex session
Status: living plan

## Purpose

This is the single canonical implementation guide for:

- building `FQF` as the shared canonical state and projection fabric
- making it a superior general architecture for agentic work, not only a knowledge substrate
- evolving shared durable knowledge toward a wiki-shaped authority model
- narrowing `ioi-memory` toward runtime working memory, checkpoints, cache, and staging
- adding privacy-preserving artifact modes where ciphertext availability can be wider than plaintext readability
- formalizing promotion, execution, policy, and repair as protocol-visible runtime concerns
- sequencing the rollout so performance, portability, and product clarity improve together

## Current Read

The honest state today is:

- `FQF` is a strong architectural spec, but not yet the shared runtime authority
- `ioi-memory` is the live local/runtime memory substrate and currently carries checkpoints, archival records, artifacts, execution cache, and enrichment jobs
- the repo now has enough product context to stop treating "memory" as the final abstraction
- the stronger initial wedge is a living wiki or knowledge base where sources, compiled pages, and filed-back outputs accumulate
- the broader architectural target still has to cover runs, tasks, approvals, branches, promotions, and artifact-native work products just as well
- the spec now also expects explicit execution semantics, policy explanation, bundle/evidence portability, repair, and compatibility profiles

The strategic move is therefore:

- keep local runtime memory as a real subsystem
- promote shared operational work and shared durable knowledge into canonical objects plus artifacts and projections
- treat promotion, execution, and policy decisions as protocol-visible flows rather than bespoke app glue
- make privacy class and promotion policy explicit instead of implicit
- use the wiki wedge to sharpen the architecture without letting it collapse into a knowledge-only niche

## Target End State

The end state should look like this:

- `FQF` is authoritative for shared app/work/wiki state
- runs, tasks, execution intents, approvals, branches, promotions, policy decisions, and publication state are canonical objects
- raw sources, work outputs, wiki revisions, reports, slide decks, plots, traces, and evidence live as hash-addressed artifacts
- wiki spaces, documents, revisions, lineage edges, and publication heads are canonical objects when durable shared knowledge matters
- task boards, run histories, execution queues, approval inboxes, policy views, backlinks, topic maps, search views, recent-changes feeds, and coverage dashboards are portable projections
- enrichment work such as chunking, summaries, embeddings, link suggestions, and contradiction scans is async derived work
- local runtime memory remains separate for working context, checkpoints, execution cache, and transient worker state
- artifact availability is separable from plaintext readability through privacy class and key-release policy
- gig/task workflows can complete in local or session scope and tear down without silently creating shared wiki residue
- promotion across scopes is explicit and receiptable
- repair, drift, and rolling-upgrade behavior are explicit runtime concerns rather than operator folklore
- multiple nodes can serve the same logical application, workspace, or knowledge base from shared roots, artifacts, checkpoints, and delta streams

## Architecture Split

### 1. Local runtime working memory

Owns:

- transcript hydration and thread checkpoints
- working/core memory sections
- execution-local caches
- transient worker state
- local compaction state

### 2. Canonical operational state

Owns:

- task and recurring-work definitions
- intents, execution requests, execution leases, and execution receipts
- run and worker state
- approvals, reviews, and leases
- policy definitions and important policy decisions
- branch, promotion, and release state
- workspace and handoff state

### 3. Canonical wiki / knowledge state

Owns:

- wiki spaces and access policy
- document identities and revision heads
- source manifests and ingestion lineage
- citation/backlink/derived-from edges
- output filing and review state

### 4. Artifact substrate

Owns:

- raw source files
- wiki markdown revisions
- images, datasets, screenshots, and media
- generated reports, slide decks, plots, traces, evidence sets, and export bundles
- projection checkpoints and large replay snapshots
- artifact privacy classes, metadata classes, and key-envelope refs

### 5. Projection runtime

Owns:

- task queues, run histories, execution queues, approval inboxes, and branch/review boards
- policy explanation and promotion review views
- page-head views
- backlink and citation views
- topic and lineage graphs
- recent-changes and stale-page queues
- search/filter/ranking views
- synchronization feeds
- repair, drift, and compatibility health surfaces

### 6. Enrichment plane

Owns:

- chunking
- summaries, facts, and entities
- embeddings and retrieval candidate sets
- link suggestion
- contradiction and staleness scans
- promotion proposals for derived knowledge
- non-canonical advisory outputs for execution, promotion, and repair

## Boundary Map From Current `ioi-memory`

| Current facet | Future home | Notes |
| --- | --- | --- |
| transcript checkpoints | local runtime working memory | stays runtime-local unless explicitly exported |
| core memory sections | local runtime working memory | not canonical by default |
| archival records | split | local recall stays local; shared operational or knowledge state graduates into canonical objects/artifacts |
| artifact records and blobs | artifact substrate | should become content-addressed, policy-bound, privacy-classed, and portable |
| thread events | mostly local, selectively canonical | only promote when shared truth matters |
| execution cache | local runtime working memory | never a canonical hot-path concern |
| enrichment jobs | enrichment plane | async by default, with explicit promotion rules |

Naming direction:

- near term: keep `ioi-memory` as the live implementation package
- medium term: introduce `ioi-wiki` as the knowledge-facing product/runtime concept
- long term: let "memory" become one facet of a broader agentic runtime where operational state and durable knowledge are both first-class

## Guardrails

- do not force every useful runtime datum into canonical truth
- do not put enrichment, embeddings, or search-refresh work on the canonical hot path
- do not treat row-shaped storage as the deepest abstraction when the product is file- and revision-native
- do not pretend multi-node artifact distribution is the same thing as multi-master write authority
- do not confuse public ciphertext availability with public plaintext readability
- do not leak raw long-lived decryption keys to untrusted agents when transient decrypt capability will do
- do not hide stale or low-trust enrichment outputs behind authoritative-looking reads
- do not make gig/task outputs shared by default
- do not rename packages early if the architectural split is not implemented yet
- do not let execution semantics remain app-local if the runtime claims to be a general agentic substrate
- do not let repair, retry, and upgrade behavior depend on undocumented operator intuition

## Workstreams

### 1. Canonical object model

Deliver:

- `Task`
- `Intent`
- `Run`
- `Worker`
- `ExecutionRequest`
- `ExecutionLease`
- `ExecutionReceipt`
- `Approval`
- `Review`
- `Workspace`
- `SessionBranch`
- `PromotionRequest`
- `PolicyDecision`
- `WikiSpace`
- `WikiDocument`
- `WikiRevision`
- `ArtifactRef`
- `ArtifactBundle`
- `EvidenceSet`
- `SourceManifest`
- `LinkEdge`
- `OutputDoc`
- `MergeProposal`
- `RepairTicket`

Also define:

- concurrency classes by object family
- promotion result states
- merge/conflict material required for high-value objects

### 2. Artifact and encryption substrate

Deliver:

- hash-addressed artifact refs
- artifact manifests and provenance
- artifact privacy classes: `local_ephemeral`, `scoped_private`, `shared_encrypted`, `public_plaintext`
- metadata classes and padding strategy for sensitive domains
- envelope/key policy model
- capability- or lease-bound key release
- checkpoint shipping and verification
- resumable artifact fetch rules
- bundle manifests and evidence-set references
- explicit separation between artifact movement and decryption rights

### 3. Projection runtime

Deliver:

- task queues, approval inboxes, and operator boards
- run histories, worker timelines, and escalation views
- execution queues, attempt histories, and side-effect receipts
- branch, diff, and promotion views
- policy explanation and promotion-review views
- page-head and recent-changes projections
- backlink and citation projections
- topic/lineage graph projections
- coverage and staleness dashboards
- resumable sync feeds
- drift, repair, and compatibility health views

### 4. Execution and policy runtime

Deliver:

- intent declaration and execution-request flow
- approval- and lease-bound execution semantics
- idempotency, retry, and compensation contract
- unified policy-decision surface for read/execute/decrypt/export/promote
- promotion receipts and policy explanations
- budget classes for heavy execution and query work

### 5. Enrichment runtime

Deliver:

- deterministic scheduling boundary between canonical writes and async enrichment
- chunking and summary pipelines
- fact/entity extraction
- embeddings and retrieval candidate generation
- link suggestion and contradiction scanning
- explicit promotion path from derived result to canonical work artifact or wiki revision

### 6. Query and subscription runtime

Deliver:

- typed task/run/execution/approval/branch/workspace/wiki queries
- workflow-native, execution-native, policy/promotion, and knowledge-native query families
- resumable changefeeds
- local-first cache bindings
- receipt classes for provenance-sensitive reads
- privacy-aware reads that distinguish artifact visibility from decryption entitlement

### 7. Repair, compatibility, and workload control

Deliver:

- repair-ticket model for projections, artifacts, promotions, and teardown drift
- explicit rebuild, replay, and rehydrate flows
- workload budgets and degradation rules by plane
- compatibility-profile advertisement and version gating
- rolling-upgrade rules for mixed-version serving domains

### 8. Migration and compatibility

Deliver:

- a data-classification pass over current `ioi-memory` surfaces
- adapters for importing shared operational work and shared durable knowledge into canonical objects
- a compatibility window where local runtime features keep using `ioi-memory`
- a narrowing plan so `ioi-memory` ends up focused on runtime-local concerns
- explicit promotion controls from local/session artifact classes into shared work state or shared wiki state

### 9. Operations and assurance

Deliver:

- projection and enrichment metrics by plane
- execution admission and policy-decision latency metrics
- replay and rebuild tests
- checkpoint restore tests
- artifact verification tests
- multi-node resume and failover proof points
- repair and teardown verification tests
- compatibility-profile and rolling-upgrade proof points
- key-release auditability and revocation tests
- teardown verification for ephemeral gig/task runs

## Phased Plan

### Phase 0. Contract And Vocabulary Freeze

Goal:

- settle the conceptual split between local runtime memory, canonical operational state, canonical wiki state, artifacts, projections, and enrichment

Outputs:

- glossary for operational and wiki-shaped canonical objects
- concurrency-class vocabulary for object families
- promotion rules for when derived work or derived knowledge becomes canonical
- execution, approval, and policy-decision vocabulary
- explicit non-goals for what remains runtime-local
- privacy-class and metadata-class taxonomy
- compatibility-profile vocabulary for required vs optional runtime features

Exit criteria:

- the spec, plan, and implementation vocabulary agree

### Phase 1. FQF Substrate

Goal:

- implement the minimal canonical object, artifact-ref, projection-definition, and checkpoint substrate needed for real shared authority

Outputs:

- canonical operation log bindings
- canonical object persistence hooks
- artifact refs and hash verification
- bundle and evidence-set contracts
- projection definitions and checkpoint contracts
- artifact privacy-class fields and key-envelope references

Exit criteria:

- a non-trivial canonical object family can be written, replayed, and projected without Postgres as authority

### Phase 2. Canonical Operational Model

Goal:

- make general agentic work state a first-class canonical object family

Outputs:

- tasks, runs, execution requests, approvals, reviews, branches, promotions, and workspace state
- run/output artifact refs and evidence bindings
- recurring-work and gig execution mutations
- handoff and escalation semantics
- object-family concurrency and merge rules
- explicit promotion state machine
- policy decisions for promote/export/execute/decrypt when material

Exit criteria:

- a non-trivial task/run/execution/approval workflow can execute on canonical state without bespoke backend glue

### Phase 3. Wiki Canonical Model

Goal:

- make wiki-shaped knowledge a first-class canonical object family layered naturally on top of the broader work substrate

Outputs:

- spaces, documents, revisions, lineage edges, and publication heads
- ingest and revise mutations
- output filing mutations
- merge/review semantics for concurrent or offline authoring
- explicit promotion semantics from `local_ephemeral` or `scoped_private` into shared wiki state
- bundle/evidence attachment model for source support and output filing

Exit criteria:

- a source can be ingested, revised into wiki form, and tracked canonically as shared truth

### Phase 4. Projection And Sync Runtime

Goal:

- make both operational work and wiki knowledge usable through portable read models and live continuity

Outputs:

- task, run, execution, approval, branch, and operator projections
- policy explanation, promotion review, and repair views
- page-head, backlink, citation, topic, and recent-changes projections
- subscription/changefeed support
- checkpoint shipping for hot projections
- local-first client bindings
- privacy-aware sync behavior that can move ciphertext without automatically exposing plaintext

Exit criteria:

- a client can hydrate from a checkpoint, receive deltas, and resume on another node

### Phase 5. Enrichment Plane

Goal:

- make knowledge compilation and operational assistance first-class async derived work

Outputs:

- run summarization, state explanation, and promotion candidate jobs
- execution advisory and repair advisory jobs
- chunking and summary jobs
- embedding and retrieval-candidate refresh
- link suggestion and contradiction scans
- source coverage and stale-page analysis
- promotion proposal flow into canonical work artifacts and canonical wiki revisions
- rules for whether enrichment products remain local/session-scoped or become shared derived artifacts

Exit criteria:

- enrichment work improves both agentic operations and durable knowledge without bloating the canonical hot path

### Phase 6. Policy, Budget, And Repair Runtime

Goal:

- make the runtime explainable and survivable under pressure, failure, and upgrade

Outputs:

- unified policy-decision objects and explanation surfaces
- workload-budget classes and overload behavior by plane
- repair tickets, replay/rebuild flows, and teardown verification
- compatibility-profile advertisement and rolling-upgrade rules

Exit criteria:

- the runtime can explain denials, degrade gracefully, repair drift explicitly, and survive rolling upgrades without hidden semantics

### Phase 7. `ioi-memory` To `ioi-wiki` Migration

Goal:

- evolve the product center from generic memory to explicit wiki-shaped knowledge

Outputs:

- classification of current `ioi-memory` data into "stay local" vs "promote to canonical wiki"
- import/migration paths for archival records and artifacts that represent shared durable knowledge
- narrowing of `ioi-memory` to checkpoints, working memory, cache, and staging
- introduction of `ioi-wiki` as the product/runtime concept when the architecture is real enough to justify it
- gig/task teardown policy for local plaintext, caches, and transient projections

Exit criteria:

- the main shared knowledge workflow no longer depends on `ioi-memory` being the authority layer

### Phase 8. Multi-Node Serving And Artifact Distribution

Goal:

- make the application and the wiki truly portable across serving nodes

Outputs:

- projection checkpoint replication
- delta replay and resume tokens
- encrypted artifact push/pull by hash
- node health and freshness reporting
- router-level failover behavior
- shared-encrypted mode where ciphertext is portable but key release remains capability-bound

Exit criteria:

- one logical application/workspace/wiki instance can survive node loss without session reset or full recomputation

### Phase 9. Proof-Sensitive And Governance Hardening

Goal:

- support higher-trust work, knowledge, and export surfaces

Outputs:

- run/evidence receipts
- source-support and citation receipts
- lineage-bound export bundles
- stronger governance and review policy over promotion
- trust-sensitive query classes

Exit criteria:

- provenance-sensitive knowledge views are explainable, auditable, and policy-bound

## Decision Gates

The program should pause and decide explicitly at these points:

1. What is the smallest canonical operational plus wiki object model that still supports the product?
2. What gets promoted from enrichment output into canonical work state or canonical wiki state, and who authorizes that promotion?
3. What is the default concurrency model for edits and promotions: single-authoritative head, branch/merge, or policy-dependent?
4. What is the v1 execution contract for idempotency, retries, compensation, and approval/lease binding?
5. How much policy explanation must be first-class in v1, and what can remain implementation detail?
6. What encryption/search tradeoff is acceptable for v1?
7. Which artifact privacy classes are mandatory in v1, and which are optional?
8. What metadata leakage is acceptable for `shared_encrypted` mode?
9. Which compatibility profiles are mandatory for interoperable multi-node serving?
10. When is the architecture real enough that `ioi-wiki` should become the public package/product name?

## Success Criteria

This plan succeeds when IOI can:

- run tasks, gigs, approvals, and long-lived workflows on the same canonical substrate as artifacts and knowledge
- execute side-effecting work through first-class requests, leases, receipts, and policy explanations
- ingest raw sources as artifacts
- compile them into a living wiki through async enrichment
- ask questions against that wiki and file outputs back into the corpus
- serve the same logical application and knowledge base across multiple nodes
- keep runtime working memory separate from shared canonical knowledge
- move work across local, session, shared operational, and shared knowledge scopes through explicit promotion protocol
- store artifacts in classes ranging from local ephemeral to shared encrypted without collapsing those modes together
- move ciphertext widely when useful while keeping plaintext access capability-bound
- run gig/task workflows that can tear down without unintended shared wiki promotion
- explain policy, provenance, and repair state for important work and knowledge views without imposing proof-heavy costs on every read
- keep overload, repair, and rolling-upgrade behavior explicit enough that operators and agents can trust the runtime
