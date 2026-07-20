# Agentgres State Substrate Specification

Status: canonical architecture authority.
Canonical owner: this file for high-level Agentgres doctrine; low-level runtime objects live in [`agentgres-api-and-object-model.md`](./api-object-model.md), and Postgres bridge/readiness guarantees live in [`postgres-bridge-and-readiness-contract.md`](./postgres-bridge-and-readiness-contract.md).
Supersedes: overlapping plan prose when Agentgres state ownership conflicts.
Superseded by: none.
Last alignment pass: 2026-07-19.
Doctrine status: canonical
Implementation status: partial (the runtime state store and multiple daemon object planes are live; thread forks, run replay, counterfactual what-if replay, and workspace snapshot/restore custody are implementation precedents. `ReceiptCheckpoint`/`ReceiptProofBundle` schemas, fixtures, invariants, and generated projections are present, while portable verifiers and Agentgres checkpoint admission/emission/export remain planned. Hosted OutcomeRoom participation, frontier/claim, offer/matching, Attempt/Finding, WorkResult/OutcomeDelta, and VerifierChallenge planes are merged. Per-System writer-transition/fencing control, room discovery, portable exit, federation, acceptance/verdict/settlement, branch/staged-effect object families, and the bounded-improvement Agenda/Campaign/Epoch/exposure/claim spine remain planned.)
Implementation refs:
  - `crates/services/src/agentic/runtime/`
Last implementation audit: 2026-07-16

## Canonical Definition

**Agentgres is the canonical operational state substrate for Web4 domains.**

It records what happened, what changed, why it changed, who authorized it, what
evidence supports it, how it can be queried, and how future workers or agents
can reuse it.

In the Hypervisor/daemon canon, the Hypervisor Daemon is the hypervisor/control plane
for autonomous execution and Agentgres is the operational truth substrate behind
that control plane. Hypervisor App, Hypervisor Web, CLI/headless clients,
optional TUI views, and application surfaces such as Developer Workspace, Foundry, and
Environments views may render Agentgres-backed projections, but they must not become the
canonical state store.

In the machine-economy canon, Agentgres is the local/domain operational truth
substrate for governed autonomous-system chains and Hypervisor Node settlement
domains. It records proposals, module invocations, state-transition commitment records,
receipt roots, upgrade decisions, state roots, and replayable projections before
selected commitments are anchored to IOI L1.

Agentgres does not run on IOI L1. It runs inside application-domain kernel deployments.

For collaborative pursuit, Agentgres remains per-domain truth. An
`OutcomeRoom` may project a shared work frontier across one or more Agentgres
domains, but there is no implicitly global mutable Agentgres graph. Every room
declares either one hosted admission domain or a versioned federated admission
policy with ordering, merge, quorum/adjudication, conflict, and failover
semantics. Each participant keeps private context and local operations in its
home domain; AIIP carries signed permitted refs and updates between domains.

## Core Doctrine

> **All state changes are patches. Accepted patches become domain operational
> truth. That truth is queryable through the nearest policy-permitted,
> verifiable view.**

Here, "truth" means the operational fact that a named domain admitted a state
change under declared policy. It does not turn a finding, model judgment,
semantic assertion, or external-world claim into universal truth. Those claims
retain provenance, uncertainty, contradiction, verification, acceptance, and
dispute state.

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

An execution branch may implement an `Attempt` for software, research,
ontology mutation, incident response, service delivery, evaluation, or an
embodied mission. Positive, negative, inconclusive, invalid, exploit-finding,
and superseded attempts remain durable evidence when retention policy admits
their informational or audit value.

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
were staged, which boundary facts the receipts bind, and which merge/admission decision
made it canonical.

Agentgres should be described publicly as a canonical state substrate with a
Postgres bridge. Builder-facing docs may call it a Postgres-compatible
operational substrate for worker-produced state. Avoid unqualified "Postgres
replacement" language unless the context is an internal ambition. The precise
claim is that Agentgres replaces row-centric databases as canonical truth when
state is produced by workers, scoped authority, artifacts, receipts,
projections, and settlement mirrors.

## Substrate Contract Doctrine

Implementation status (this section): partial — engine v0 exists
(`crates/agentgres`: five-verb trait, append-only op log,
single-writer group commit, batch rooting, O(1) fork/checkpoint; done-bar
`verify-agentgres-substrate-bench.mjs`, 13/13). Baseline on the dev box
(Core Ultra 9 275HX, consumer NVMe, ext4/LVM, fsync-honest): 8.6k
admissions/s per domain at 64 in-flight (target 5k: met), fork 0.4ms
(target <1s: met), engine ceiling 261k ops/s at p99 0.10ms without fsync.
Named blocker on the p99<5ms target: this box's raw `fdatasync` floor is
~5.4ms — the gap is device flush, not the engine; enterprise NVMe with
power-loss protection resolves it (p50 already rides the floor exactly).

Session 2 landed the single-box flush combiner and the first real-truth
shadow: the multiplexed multi-domain log (`mux.rs`) shares one file and one
fsync across many domains while every domain keeps an independent head map,
sequence, and root chain (the file is an I/O artifact, never a truth
coupling — per-domain heads are proven independent of batch interleaving).
Measured: 8 domains through one combined-flush log reach 20.8k aggregate
admissions/s on the same box where 8 separate logs plateaued at 8.8k
(2.4×; 88% of the group-commit theoretical bound). And the engine has now
carried real daemon truth read-only: `substrate-shadow` ingested all 4,287
persisted `ioi.hypervisor.provider-receipt.v1` records with complete
coverage, a deterministic double-run (identical final root), and verified
recovery — the shadow-first step of the migration doctrine.

Session 3 CUT the first family over (user decision: no downstream users,
avoid split brain): `provider-receipts` truth IS the substrate engine.
`persist_record` for promoted families admits into the mux log at
`<data_dir>/substrate/` (fail-closed with named errors — no legacy JSON is
written); `read_record_dir` serves the writer-thread last-write-wins
projection (never a torn tail); on first open, legacy JSON records are
BACKFILLED once, idempotently, in canonical `(at, record_id)` order, and
the legacy files remain on disk as inert history. All three read sites and
the single write site route through those two shared helpers, so the cut
is total by construction. WAL recovery truncates torn/unacked tails to the
last valid frame boundary. `GET /v1/hypervisor/substrate/status` projects
engine roots, admission/backfill counters, and residual-legacy counts; the
dual-write soak lane (`IOI_SUBSTRATE_DUAL_WRITE=1` + domains env) remains
for FUTURE families, with `substrate-parity` as their promotion bar. The
engine crate is `crates/agentgres`. Proven live: daemon smoke boots
against a seeded data dir, backfills, serves receipts from the engine, and
recovers the engine log across restart with a stable root. Mux domains
fork into single-domain engines (checkpoint → seed, parent untouched) and
project per-domain. Done-bar: `verify-agentgres-substrate-bench.mjs`
(30/30; 12-test unit battery including torn-tail truncation).

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

**Durability classes and replication-as-durability.** Every admission ack
carries a durability class (owner:
[`../../foundations/canonical-enums.md`](../../foundations/canonical-enums.md)
— `buffered | device_flush | replicated_same_host | quorum_replicated`).
Device flush is ONE durability mechanism, not the definition: the end-state
ack policy is replicate-then-ack — a batch's exact appended log bytes ship
to peer(s) before acking, device flush runs as background hygiene on an
independent fd on both sides, and correctness reduces to byte equality
(byte-identical logs replay identical roots by construction). This removes
the device-flush floor from the ack critical path entirely, which is what
makes the fractal claim real: domains → engines → flush domains → nodes,
single-writer at every level, the only latency on the ack path being the
peer round-trip. Honesty caps apply: same-host peers can never yield
`quorum_replicated`, and a failed replica link degrades acks loudly to the
base label. Measured on the dev box (two processes, loopback,
`replicated_same_host`): 220k admissions/s at p99 0.75ms single domain;
8-domain aggregate 221.7k/s at p99 1.1ms — CPU-bound, no longer
flush-bound (the same box's flush-per-ack ceiling was 8.6k–20.8k). All
three performance-contract metrics are met under replicated semantics.

**HA without consensus (built).** The pre-consensus production posture is
fenced primary/standby over static membership: writer EPOCHS persist in
the log as fencing frames (they ship byte-identically to replicas and do
not touch domain root chains); the protocol handshake carries epoch and
log length, so a late or restarted replica CATCHES UP by offset streaming
before live batches, a replica that is AHEAD refuses overwrite (promote
it instead), and a deposed primary is fenced at handshake or mid-stream
NACK — split brain is structurally refused on every replica. PROMOTION is
operator-driven and receipted (`ioi.agentgres.writer-promotion.v1` minted
at epoch+1; the replica dir is already a valid engine dir). Multi-replica
fan-out acks against a static quorum; `quorum_replicated` requires every
acking peer to be DECLARED failure-independent (same-host peers cap at
`replicated_same_host` — measured: two same-host replicas at quorum 2/2
still cap, 200k adm/s at p99 0.89ms). The daemon adopts this behind env
(`IOI_SUBSTRATE_REPLICA_ADDRS` + `IOI_SUBSTRATE_ASYNC_FLUSH=1` +
`IOI_SUBSTRATE_ACK_QUORUM`; default remains device-flush sync, and async
without a connected replica FAIL-SAFES to per-batch sync, loudly).
Deliberately NOT built (consensus tier, gated after the same-system multi-node
proof, both gates named:
a real multi-node customer needing automated-failover SLAs AND a running
deterministic-simulation harness): leader election, view changes, dynamic
membership, automated failover. Options stay open: VSR-under-DST or a
proven consensus library for the control plane over this data plane —
the epochs built here are exactly what either consumes.

**Bounded-DAS deployment binding.** The built static primary/standby mechanism
is the first implementation anchor for
`AutonomousSystemDeploymentProfileEnvelope`,
`AutonomousSystemNodeMembershipEnvelope`, and
`AutonomousSystemFailoverProfileEnvelope`; it does not yet implement those
public system-control objects or dynamic membership APIs. The existing writer
maps to `admission_writer`, a caught-up promotable replica maps to
`hot_standby` plus `state_replica`, and the promotion receipt supplies evidence
for the new writer epoch. Desired topology remains distinct from observed
membership/readiness. Operator promotion is not automatic failover, static
quorum replication is not consensus, and several IOI-operated replicas are not
independent parties (`INV-22` through `INV-24`).

The mux epoch and a System writer epoch are deliberately separate. The mux
`current_epoch` fences writers of one Agentgres storage log and rides its
replication protocol; it does not identify a logical System, bind that System's
membership or authority, or admit connector/wallet/provider/domain effects.
The target per-System `AutonomousSystemWriterEpochTransition` sits above
storage, advances through its declared durable continuity CAS, and supplies the
active fence checked by each System-scoped consequential-resource PEP. A
storage epoch may eventually persist or replicate that transition, but can
never substitute for it. Current master contains no per-System transition
store, derived active-fence projection, public transition/promotion route,
automatic failover controller, or System-scoped consequential-resource PEP
coverage. The static mux writer epoch is implementation precedent only and
must not be presented as a completed bounded-DAS fencing plane.

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
usually speak in terms of **Provenance**, **run history**, **evidence**,
**receipts**, **state history**, **archives**, and **replay** (the legacy
Work Ledger name survives only in admin/protocol language and route
compatibility). The Agentgres
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
- Hypervisor Node state-transition commitment records;
- service module manifests and registry roots;
- module invocation records;
- proposal queues;
- upgrade decisions;
- admitted improvement-governance profile revisions and active owner-scope
  bindings, including constitution bindings when System-scoped;
- immutable Improvement Agenda revisions and release/supersession lineage;
- Improvement Campaign contracts, append-only operation heads, and derived
  lifecycle projections;
- frozen Evaluation Epoch roots, challenges, closure, and invalidation lineage;
- evaluation-exposure reservations, spend, returns, contamination, rotation,
  and ledger heads;
- Improvement Order Cutoff receipts;
- immutable Improvement Evidence Claims plus dispute, downgrade, withdrawal,
  and supersession lineage;
- runtime subscription and usage state;
- orders;
- workflow state;
- domain ontologies;
- canonical object models;
- data recipes;
- connector mappings;
- policy-bound data views;
- admitted `InstitutionalLearningBoundaryProfile` revisions and effective
  scope snapshots;
- per-subject learning-evidence eligibility decisions, including training and
  non-training improvement uses;
- transformation runs and receipt refs;
- evaluation dataset refs;
- ontology-aware projection definitions;
- ontology-to-worker plans;
- Worker Training specs;
- training lineage;
- source-rights, derivative-obligation, and revocation-impact lineage refs;
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
- OutcomeRooms and hosted/federated room-admission policy refs;
- versioned, policy-filtered OutcomeRoom discovery projections;
- typed room participation requests and admission/denial decisions;
- portable participant-state bundles, claim-release, export, acknowledgement,
  supersession, and revocation state;
- room participant leases;
- work-frontier items and claim leases;
- resource/capability offers and allocation decisions;
- positive, negative, inconclusive, invalid, exploit-finding, and superseded
  attempts;
- provenance-bearing findings and contradictions;
- verifier challenges, rule versions, adjudication, and re-verification state;
- generic WorkResults and proposed/admitted OutcomeDeltas;
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
- ownership, license, consent, provider/customer learning rights, or
  permission to train, distill, export, publish, or reuse a recorded subject;
- connector mapping authority without an admitted authority grant, policy
  decision, or governance owner ref;
- first-party product pricing, billing strategy, or separate SKU ownership;
- the physical compute resource;
- every local UI hover/draft state;
- private working memory unless promoted;
- draft, fuzzy, local, or speculative memory that has not crossed an admission boundary;
- retrieval candidates, embeddings, full-text indexes, or wiki projections as canonical truth;
- a globally mutable shared collaboration graph across sovereign domains;
- raw room chat, message-board consensus, or leaderboards as admission truth;
- the authority to admit an Improvement Campaign, select its protected target,
  choose or alter its frozen evaluator truth, or promote its candidate;
- sealed holdout cases, labels, evaluator internals, or protected feedback
  payloads merely because it records their commitments, custody, and exposure
  receipts;
- a mutable candidate archive, Campaign status, remaining-budget counter, or
  claim-support graph outside rebuildable projections over admitted operations.

Authority providers and domain governance own permission decisions.
wallet.network is the portable delegated authority provider for its owned
secrets, provider credentials, external effects, spend, decryption,
declassification, portable/cross-domain/high-risk restore/apply, and high-risk
approval scopes. Hypervisor and domain/application governance may own local
policy decisions that do not cross those boundaries. Agentgres records
authority refs, policy decisions, and governance owner refs, and enforces them
at admission time, but it is not the authority provider.

Hypervisor Daemon runtime nodes own execution. Hypervisor clients and
application surfaces own UX/projections. AIIP owns autonomous-work interop
semantics. Storage backends own payload byte availability. The declared
external settlement service owns its public/economic settlement and rights;
IOI L1 does so only for explicitly enrolled, selected services. Hypervisor
Nodes coordinate local operational finality and interop, but their operational truth is
still recorded through Agentgres/domain operations rather than client UI state.

Agentgres may record usage, payout, royalty, billing, entitlement, dispute,
settlement, and ContributionReceipt state for the domains it serves. Recording
economic truth does not make Agentgres the monetization surface. In the
first-party stack, routine Agentgres writes, projections, refs, and receipts are
bundled substrate under the product surface that depends on them.

## Institutional Learning Boundary

Agentgres is the admitted truth and lineage substrate beneath an enterprise or
other institutional learning boundary. It records the effective
`InstitutionalLearningBoundaryProfile` revision, individual evidence
eligibility, source/model-route rights refs, policy decisions, transformation
and derivative edges, retention/revocation state, promotion/export refs, and
the receipts that bind observed boundary actions. Product surfaces may derive a
learning-flow, exposure, derivative-impact, or model-swap-readiness projection
from those records.

Agentgres does not grant any of those rights and does not make a broad profile
override a restrictive source. Admission computes the most restrictive
intersection selected by the owning policy, and durable records retain the
inputs to that decision. Agentgres also does not store protected dataset,
trace, checkpoint, adapter, model, or export payload bytes merely because it
records their refs and commitments; storage backends keep the bytes under the
bound custody and retention policy.

Revocation is transitive operational state, not historical erasure. A source
revocation may block future reads or training, quarantine a view or artifact,
recall a release, require re-evaluation, or trigger rebuild/retraining from an
eligible corpus. Prior receipts and lineage remain immutable evidence subject
to their visibility/retention policy. A deletion, recall, quarantine, retrain,
or receipt does not by itself prove model unlearning or hidden external-provider
behavior; a verified-unlearning claim needs its own declared method, property,
evaluation, verifier, and assurance result.

Provider-native threads, vector stores, hosted memory, eval stores, or tuning
services cannot be the only durable copy of institution-owned accepted memory,
evals, corrections, ontology state, or derivative lineage. Agentgres-backed
state plus policy-permitted artifact archives/exports must preserve a
provider-independent reconstruction path. This rule does not claim or require
access to provider-owned weights or hidden state.

For model-swap continuity, Agentgres records the frozen system/profile/state
root, policy-filtered memory projection, incumbent and candidate route refs,
eval/scorecard receipts, observed results, canary, rollback, and promotion
decision. It does not declare models equivalent or authorize the swap; Foundry
and Evaluations produce evidence, Governance owns release gates, and the daemon
admits execution.

The same boundary applies to bounded improvement. `LearningEvidenceEligibility`
is the one admitted decision for reusing a Finding, trace, correction, receipt,
or artifact in model training or in pursuit-method, workflow, evaluator,
Agenda, policy, memory, package, or tool improvement.
`TrainingEvidenceEligibility` is its training-oriented compatibility profile
over that same object ID, never a second truth. Live sealed evaluation material remains
ineligible learning evidence until its owning rotation/declassification policy
releases it; recording a commitment or access receipt does not reveal or
declassify the payload.

Agentgres records Campaign contracts and operations, frozen Epoch roots,
exposure-ledger entries, cutoff receipts, candidate Attempts, evidence Claims,
and the UpgradeProposal/Decision lineage that follows. It can rebuild candidate
DAGs, archives, remaining-budget/exposure views, synchronization lineage, and
claim-support projections. It does not decide which target may improve, alter
an active Epoch, grade its own evidence, or make a candidate canonical.

## Memory And Agent Wiki Boundary

Agentgres is not the whole agent brain. It is the canonical state substrate for
admitted truth.

The long-term memory architecture has four distinct planes:

```text
HarnessInvocation/runtime hot state
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
  + state-transition commitment records
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
- effective institutional-learning-boundary revisions, individual eligibility
  decisions, source/model-route rights refs, derivative-lineage roots, and
  revocation-impact decisions;
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

4. Optional declared external settlement layer
   Registry, rights, escrow, settlement, dispute roots, or selected public
   commitments. IOI L1 is one enrolled service set.
```

Operational flow:

```text
hot state in Agentgres domain storage
-> periodic checkpoints/snapshots to cold artifact storage
-> sealed state archives to Filecoin/CAS or equivalent durable blob stores
-> receipt/evidence bundles to storage backends
-> selected economic/trust commitments to the declared external settlement
   profile; IOI L1 only for explicitly enrolled services
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
OutcomeRoom
OutcomeRoomDiscovery
RoomParticipationRequest
ParticipantStateBundle
RoomParticipantLease
ResourceOffer
CapabilityOffer
WorkFrontierItem
WorkClaimLease
Attempt
Finding
VerifierChallenge
WorkResult
OutcomeDelta
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

- Goal Space and OutcomeRoom refs;
- discoverable room projections, participation requests/decisions, and portable
  participant-state bundles when ioi.ai is the declared owner/host;
- hosted room frontier, participant, claim, attempt, finding, verifier,
  outcome-delta, contribution, and replay state when ioi.ai's named domain is
  the declared admission host;
- local projections of federated room state when another domain or federation
  policy owns shared admission;
- GoalRun, plan, attempt-summary, and cross-session outcome-graph refs;
- account/runtime profile refs;
- device registrations;
- sealed archive refs;
- latest state-root pointers;
- restore lifecycle records;
- publishing flow records;
- remote compute entitlement refs;
- sync metadata;
- lightweight runtime status.

## Interaction with External Settlement Services

When a system selects an external settlement profile, Agentgres may synchronize
the selected service's contracts or ledgers for:

- rights;
- licenses;
- escrows;
- bonds;
- payouts;
- disputes;
- reputation/contribution roots;
- manifest commitments.

IOI L1 is valid only under an active connected/secured enrollment that selected
the service. Agentgres does not post every event or receipt to any external
rail.

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
a globally mutable OutcomeRoom graph with no declared admission owner
room chat, self-reported scores, or participant consensus as canonical truth
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
declassification, external effects, spend, or another wallet-owned high-risk
scope; ordinary locally authorized restore/apply does not require wallet.network
by definition
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
9. No recorded learning-boundary profile, eligibility decision, source-rights
   ref, provider contract, or receipt grants a use beyond its declared scope;
   the most restrictive applicable constraint controls.
10. No provider-native thread, vector store, memory, eval, or tuning service is
    the sole durable copy of institution-owned accepted learning state needed
    for provider-independent operation.
11. No receipt, deletion record, quarantine, recall, or retraining record proves
    hidden provider behavior or model unlearning beyond the explicit verified
    property it binds.
12. No Campaign operation, projection, score, or evidence Claim grants target
    authority or replaces target-owner UpgradeProposal/Decision admission.
13. No candidate may rewrite the frozen Epoch, exposure ledger, ancestor
    budget, evaluator boundary, or recovery path by advancing Campaign state.
14. No live sealed evaluation material becomes learning evidence merely because
    its commitment, custody, access, or result receipt is recorded.
15. No Campaign status, candidate archive, remaining-budget/exposure counter,
    synchronization view, or claim-support graph is canonical unless rebuildable
    from admitted objects, operations, and receipts.

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
