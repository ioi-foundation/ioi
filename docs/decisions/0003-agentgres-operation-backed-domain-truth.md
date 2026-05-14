# ADR 0003: Define Agentgres As Operation-Backed Domain Truth

- Status: Accepted
- Date: 2026-05-14
- Owners: Agentgres / runtime state / Filecoin-CAS / database bridge

## Context

Agentgres sits between runtime execution, domain state, artifacts, projections,
SQL-facing tools, and settlement mirrors. That boundary needs a precise
canonicality decision.

Rejected interpretations:

- Agentgres as ordinary app storage.
- Agentgres state as opaque Filecoin/CAS blobs.
- Agentgres as a naked Postgres replacement.
- Agentgres as an event stream rather than a canonical operation/state
  substrate.

Each reading weakens the architecture. Worker-produced state needs replayable
operations, object heads, receipts, authority, projections, and settlement
mirrors. Payload availability and SQL compatibility are important, but neither
is the source of truth.

## Decision

Agentgres is the canonical operational state substrate for Web4 domains.

Its source of truth is operation-backed state:

- accepted operations;
- object heads;
- state roots;
- constraints and invariants;
- receipt metadata;
- artifact refs;
- projection checkpoints;
- replay/recovery guarantees.

Filecoin/CAS stores immutable payload bytes, sealed archive bytes, packages,
evidence bundles, trace bundles, snapshots, checkpoints, and large artifacts.
It does not own live Agentgres state.

Agentgres may expose Postgres-compatible projections and SQL-facing bridges,
but canonical writes must go through Agentgres operations unless a bridge write
explicitly compiles into an operation with schema, policy, authority, and
constraint checks.

Events are observation streams. For serious runs, Agentgres operation logs plus
receipts/artifacts are canonical.

## Consequences

- Public positioning should describe Agentgres as a canonical state substrate
  with a Postgres bridge, not as "Postgres replacement" without qualification.
- Filecoin/CAS refs are evidence and availability, not state authority.
- Sealed State Archives are first-class portable state artifacts, but restore
  is operation-backed through Agentgres.
- Query and SQL surfaces are projection-oriented serving layers.
- Runtime scorecards, task state, stop conditions, handoff quality, semantic
  impact, probes, and uncertainty records are operational records that can
  influence execution when admitted into Agentgres.

## Canonical References

- `docs/architecture/components/agentgres/doctrine.md`
- `docs/architecture/components/agentgres/api-object-model.md`
- `docs/architecture/components/agentgres/postgres-bridge-and-readiness-contract.md`
- `docs/architecture/components/filecoin-cas/doctrine.md`
- `docs/architecture/components/filecoin-cas/api-artifact-refs.md`
- `docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md`
