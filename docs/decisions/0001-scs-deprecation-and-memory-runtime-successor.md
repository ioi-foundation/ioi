# ADR 0001: Remove SCS And Adopt `ioi-memory` For Product Memory

- Status: Accepted
- Date: 2026-03-25
- Owners: Agentic runtime / Autopilot / Validator

## Context

`SCS` started as a broad context substrate intended to cover durable local
storage, semantic recall, encrypted archival state, and proof-oriented
retrieval. The product and runtime have since evolved toward a cleaner
separation of concerns:

- thread execution needs resumable checkpoints and bounded working state
- agent memory needs explicit core and archival layers
- artifacts and evidence need separate blob-oriented storage
- policy and governance surfaces need committed chain-visible state, not local
  mirrors

As the codebase evolved, `SCS` became both too broad and too implicit for the
live product architecture. The clean-room direction for memory means we are not
preserving `SCS` as the primary abstraction and we are not carrying forward a
backward-compatibility import path for local `.scs` product state.

## Decision

We remove `SCS` as the product-memory architecture.

The accepted successor architecture is:

- a LangGraph-shaped runtime centered on checkpoints plus a durable memory store
- a Letta-shaped ontology with distinct `working`, `core`, and `archival`
  memory layers
- a Zep-shaped background enrichment pipeline for summaries, facts, entities,
  and embeddings
- runtime-owned memory policy, not pure model self-management

The concrete implementation boundary is `ioi-memory` in `crates/memory`, built
around `MemoryRuntime` and typed stores for:

- transcript and thread checkpoints
- typed checkpoint mirrors such as `desktop.agent_state.v1`
- core-memory sections and runtime-injected registers
- archival records plus embeddings for retrieval
- artifact and evidence blobs

## Explicit Non-Goals

- no new product features should be added on top of `SCS`
- no `SCS -> ioi-memory` importer will be built for product state
- no prompt-time secret storage in always-injected core memory
- no use of runtime checkpoints as substitutes for committed chain-state policy
  inputs

## Authority Boundaries

The runtime and chain have different jobs:

- `ioi-memory` is authoritative for product-memory reads, checkpoints,
  retrieval, compaction, and local evidence blobs
- committed chain state remains authoritative for validator policy enforcement,
  firewall checks, and approval/gate readiness that must bind to on-chain
  pending hashes

This boundary is intentional. Runtime checkpoints are mirrors and operational
state; they are not consensus inputs.

## Consequences

### Immediate

- all new desktop-agent, Autopilot, and local-runtime memory features target
  `ioi-memory`
- `SCS` is removed from live product-memory paths and from the Cargo workspace
- docs, fixtures, and receipts should stop describing `SCS` as the live memory
  substrate

### Near-Term

- add background enrichment jobs to `ioi-memory`
- decide whether checkpoint enumeration belongs in `ioi-memory` or whether
  session discovery should remain chain-state-driven
- finish cleaning architecture-facing vocabulary that still implies live `SCS`

### Long-Term

- `ioi-memory` remains the only product-memory crate
- any future proof-oriented retrieval or evidence utilities must justify their
  own narrow package boundaries instead of reviving `SCS` as a catch-all memory
  abstraction

## Migration Policy

- new work must use `MemoryRuntime`-shaped abstractions
- migrations should prefer clean replacement over compatibility shims
- any remaining raw-state readers must document why they are consensus-sensitive
- the living execution tracker remains
  `docs/plans/memory-runtime-plan.md`
