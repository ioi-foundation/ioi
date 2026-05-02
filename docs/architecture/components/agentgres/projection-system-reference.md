# Canonical State and Projection System (CSPS)

Status: preserved taxonomy reference; Agentgres state doctrine remains weighted to [`agentgres-state-substrate.md`](./agentgres-state-substrate.md) when terminology or mechanics disagree.
Context owner: this file for the generic Canonical State and Projection System category above Agentgres/FQF-style state systems.
Supersedes: `docs/specs/formal/canonical-state-and-projection-system-whitepaper.md`.
Superseded by: none.
Last alignment pass: 2026-05-01.

**Status:** Working taxonomy  
**Scope:** Category definition, not product spec  
**Applies to:** IOI `FQF` and similar future systems

## Abstract

This paper proposes a new system taxonomy: the **Canonical State and Projection System** (`CSPS`).

`CSPS` names a class of software systems whose center of gravity is not the relational table, the document, the object row, or the event log in isolation. Instead, the center is:

- canonical state transitions
- deterministic object state
- first-class projections
- query and subscription runtimes over those projections
- durable checkpoints, receipts, and capability-scoped access

This category is needed because existing labels such as `RDBMS`, `ODBMS`, `MMDBMS`, `DDBMS`, and even `event-sourced system` each describe part of the design space, but none describe the full architecture cleanly.

The motivating claim is simple:

> A system whose source of truth is canonical state, whose application-facing interface is projection-native, and whose runtime model includes subscriptions, receipts, checkpoints, and scoped query semantics is no longer well-described as a database management system in the classic sense.

For IOI, this taxonomy provides the generic category above `Fractal Query Fabric` (`FQF`). `FQF` is an architecture and eventual implementation. `CSPS` is the class of system it belongs to.

## 1. Why a New Taxonomy Is Needed

Modern software still inherits the default mental model of:

- application server
- relational database as authority
- blob store for files
- caches and indexes as hidden implementation details
- realtime as a bolt-on layer
- vector search as a separate bolt-on layer

That model remains effective for CRUD-heavy software. It becomes strained when systems need:

- canonical replayable operations
- multiple durable projection families
- long-running agentic workflows
- capability-scoped reads and writes
- portable application serving across multiple nodes
- explicit receipts and proofs
- local-first clients with shared canonical state

In such systems, the classical database categories stop fitting well.

## 2. Why Existing Categories Are Not Enough

### 2.1 `RDBMS`

`RDBMS` implies a row-first worldview:

- tables are primary
- schemas are central
- SQL is the dominant interface
- indexes are secondary accelerators

That is not the right center for a `CSPS`.

### 2.2 `ODBMS`

`ODBMS` gets closer on object semantics, but still under-describes:

- explicit projection families
- subscriptions
- checkpoints
- receipts
- scoped query/runtime semantics

### 2.3 `MMDBMS`

`MMDBMS` is the least wrong existing category because it admits multiple models. But it is still too storage-shaped. It does not capture that projections themselves are protocol-visible and operationally central.

### 2.4 `DDBMS`

`DDBMS` only tells you the system is distributed. It says almost nothing about the canonical state model or projection runtime.

### 2.5 Event-Sourced / CQRS System

Architecturally, this gets much closer. Many `CSPS` designs will be event-sourced and projection-heavy. But this still describes a pattern, not a complete systems category. It usually does not imply:

- protocol-visible projections
- portable checkpoints
- query receipts
- capability-scoped subscriptions
- artifact-aware state

## 3. Definition

A **Canonical State and Projection System** (`CSPS`) is:

> a system in which canonical truth is maintained through deterministic state transitions, while application-facing reads, subscriptions, and derived views are served through explicit, versioned projections rather than being treated as incidental indexes over row-centric storage.

The short definition is:

> **A `CSPS` is a system where canonical state is the source of truth and projections are first-class runtime artifacts.**

## 4. Core Properties of a CSPS

A system belongs to this category if most of the following are true.

### 4.1 Canonical state is primary

Truth is anchored in canonical operations and deterministic object state, not in mutable table rows as the primary conceptual unit.

### 4.2 Projections are first-class

Relational views, graphs, timelines, rankings, subscriptions, and other read models are explicitly defined runtime artifacts, not merely hidden indexes.

### 4.3 Query is projection-native

Application reads target named projections, checkpoints, or scoped query surfaces rather than assuming direct table access is the fundamental interface.

### 4.4 Subscriptions are native

Realtime delivery is not a sidecar convenience. It is a core part of the read model and must work with replay, resumability, and projection versioning.

### 4.5 Checkpoints are portable

Projection state can be reconstructed or restored deterministically through:

- canonical state replay
- verified checkpoints
- delta catch-up

### 4.6 Capability scoping is explicit

Reads, writes, and subscriptions can be constrained by policy, leases, sessions, or other scoped authority artifacts rather than being mediated only by app-layer session state.

### 4.7 Artifacts are part of the model

Files, bundles, evidence, UI packages, and other immutable blobs are not “outside the system.” They are addressable, policy-aware artifacts referenced by canonical state.

## 5. What a CSPS Is Not

A `CSPS` is not necessarily:

- a blockchain
- a replacement for every local UI store
- a replacement for every OLAP engine
- a SQL database with better indexing
- a vector database
- a generic event log with dashboards

It may expose SQL compatibility. It may use an event log. It may be distributed. Those traits are compatible, but none of them are the defining category center.

## 6. Minimal Layer Model

Most `CSPS` implementations can be understood in four layers.

### 6.1 Canonical State Layer

Maintains deterministic truth:

- operations
- object transitions
- roots or anchors
- policy and authority state

### 6.2 Artifact Layer

Stores immutable referenced objects:

- bundles
- manifests
- evidence
- UI assets
- reports

### 6.3 Projection Layer

Maintains explicit derived views:

- relational projections
- graph projections
- timeline projections
- ranking projections
- capability projections

### 6.4 Query and Subscription Layer

Exposes:

- scoped reads
- mutations
- resumable subscriptions
- receipts
- checkpoint-aware recovery

## 7. Projection-Native, Not Table-Native

The most important distinction in this taxonomy is that a `CSPS` is **projection-native**.

That means:

- tables are one projection family
- they are not the mandatory center of the system
- graph or timeline views may be equally fundamental
- application clients can bind directly to projections
- subscriptions are anchored to projection lineage, not only raw row changes

This is the conceptual shift that makes `CSPS` different from an `RDBMS` with extra features.

## 8. Relationship to Agentic Systems

Agentic applications intensify the need for this category because they often require:

- durable, replayable state across long-running workflows
- multiple concurrent derived views of the same canonical state
- contextual memory that is adjacent to, but distinct from, application truth
- capability-scoped execution
- explicit receipts, checkpoints, and intervention trails

In other words, agentic systems do not merely need “a database.” They need a runtime substrate where state, projections, subscriptions, and scoped authority are all native.

That is why `CSPS` is especially relevant to agentic and local-first systems.

## 9. Relationship to IOI

Within IOI, this taxonomy should be applied as follows:

- `CSPS` = the category
- `FQF` = IOI’s architecture/spec for a `CSPS`
- `SCS` = adjacent context plane, not the `CSPS` itself
- `wallet.network` = authority and capability-control plane that constrains access to `CSPS` surfaces

For IOI specifically:

- canonical chain/object state provides the deepest truth layer
- `FQF` is the proposed canonical state and projection fabric over that truth
- `SCS` remains separate because context memory and general application state are not the same problem

This separation is important:

> `SCS` governs what an agent can know.  
> `CSPS` governs what the system can store, derive, query, and serve as canonical application truth.

## 10. Local-First and Distributed Serving

A `CSPS` fits especially well with local-first clients because it allows a clean split:

- local app store for drafts, optimistic state, and ephemeral UI
- canonical state and projections for shared truth
- resumable subscriptions for continuity
- portable checkpoints for recovery
- scoped authority artifacts instead of sticky server sessions

That is why a `CSPS` can support applications that are:

- local-first at the UX layer
- canonical at the shared-state layer
- distributed at the serving layer

## 11. Criteria for Identifying a CSPS

If you need a decision rule, ask these questions:

1. Is canonical state the primary source of truth?
2. Are projections first-class artifacts rather than incidental indexes?
3. Can clients bind to named or versioned projections?
4. Are subscriptions and replay semantics part of the core query model?
5. Are checkpoints and deterministic rebuild part of the serving contract?
6. Is authority scoped through explicit capability/session/policy semantics?

If the answer is “yes” to most of these, the system is likely better described as a `CSPS` than as an `RDBMS`.

## 12. Naming Stack

This taxonomy should not be confused with a product or implementation name.

Recommended naming stack:

- **taxonomy:** `Canonical State and Projection System` (`CSPS`)
- **architecture/spec:** `Fractal Query Fabric` (`FQF`)
- **implementation/crate:** `fqf`
- **context plane:** `SCS`
- **compatibility layer:** optional SQL or Postgres-facing bridge if desired

That separation matters because it allows the category to remain stable even if one implementation changes names later.

## 13. Implications

Adopting this taxonomy has three benefits.

### 13.1 It clarifies the design target

Teams stop arguing about whether the system is “really a database” and can instead evaluate whether the canonical state, projection, and subscription semantics are coherent.

### 13.2 It decouples compatibility from identity

SQL compatibility can exist without collapsing the category back into `RDBMS`.

### 13.3 It gives the ecosystem a language for a real systems shift

If systems of this shape become more common, the industry needs a name for them that is more accurate than:

- “database with projections”
- “event-sourced backend”
- “multimodel store”
- “blockchain app runtime”

`CSPS` is intended to fill that gap.

## 14. Sharpest One-Line Definition

**A Canonical State and Projection System is a software system where canonical state is the source of truth and projections are first-class runtime artifacts for queries, subscriptions, checkpoints, and application serving.**

## 15. Bottom Line

The point of `CSPS` is not to invent jargon for its own sake.

The point is to describe a real architectural shift:

- away from row-first authority
- toward canonical state
- away from hidden indexing
- toward projection-native runtime design
- away from sticky backend sessions and bespoke sync stacks
- toward scoped, replayable, checkpoint-aware application state systems

That is a distinct class of system.

It deserves its own name.
