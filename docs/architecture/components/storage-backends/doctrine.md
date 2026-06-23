# Storage Backends Doctrine

Status: canonical architecture authority.
Canonical owner: this file for storage backend byte-store doctrine underneath Agentgres-governed artifact refs.
Supersedes: component-level Filecoin/CAS wording when it implies storage backends own artifact meaning, authority, lifecycle, restore validity, or operational truth.
Superseded by: none.
Last alignment pass: 2026-05-30.

## Canonical Definition

**Storage backends hold payload bytes. They do not own operational truth.**

Storage backends provide availability, locality, durability, cost posture, and
retrieval mechanics for payloads referenced by Agentgres. Agentgres owns the
artifact identity, lifecycle, policy linkage, authority linkage, receipt
linkage, replay/import metadata, archive/restore validity, state-root validity,
and content-addressed commitments.

```text
Agentgres artifact-ref plane
  owns meaning, refs, lifecycle, policy, receipts, restore validity

Storage backends
  hold bytes behind those refs
```

## Owns

Storage backends own:

- byte persistence;
- byte retrieval;
- byte replication where configured;
- byte availability status from their own perspective;
- storage-specific addressing such as paths, bucket keys, object IDs, CIDs, or
  provider URIs;
- storage-specific retention and deletion mechanics;
- storage-specific cost, latency, region, and durability behavior.

## Does Not Own

Storage backends do not own:

- Agentgres operational truth;
- artifact identity;
- artifact lifecycle status in the domain;
- accepted operations;
- object heads;
- state roots;
- policy admission;
- wallet authority;
- decryption authority;
- archive restore validity;
- replay/import validity;
- delivery acceptance;
- marketplace settlement;
- IOI L1 commitments.

## Supported Backend Classes

```text
local_disk
  private or device-local payload bytes, caches, local archives, local evidence

s3 / object_store
  cloud object storage, enterprise buckets, regional replicated payloads

filecoin
  durable content-addressed storage deals and decentralized availability

cas / ipfs
  content-addressed object availability, package distribution, gateway-backed
  retrieval, local or remote pinning

provider_blob
  model/provider/runtime-hosted blob storage for tool outputs, traces, or
  temporary large payloads

customer_vpc_blob
  customer-controlled enterprise storage inside VPC or private cloud boundaries

storage_engine
  Postgres, SQLite, RocksDB, append-only logs, or similar engines when used as
  payload engines rather than Agentgres admission/validity
```

## Lifecycle

```text
Agentgres or daemon chooses storage policy
  -> payload bytes are written to backend
  -> backend returns location/CID/object metadata
  -> daemon verifies hash/size/media type
  -> Agentgres records ArtifactRef/PayloadRef
  -> receipts bind payload, policy, authority, and operation
  -> backend may later be checked, replicated, migrated, archived, or replaced
```

Backend availability changes are facts to admit or observe, not truth changes by
themselves:

```text
payload missing
  -> ArtifactAvailabilityIncident proposed in Agentgres
  -> Agentgres lifecycle status becomes missing or invalid where applicable
  -> blocker or repair action opens if work depends on it
  -> replica/backend fallback may run
  -> repair receipt records verification/repair outcome
  -> Agentgres operation admits repaired refs or unrecoverable state
```

Backends may report successful retrieval, failed retrieval, proof status,
replica health, deal state, object metadata, or deletion state. Those reports
are evidence. They do not repair artifact truth until Agentgres admits the
repair operation and receipt.

## Artifact Availability Incidents

Storage failures that affect replay, restore, delivery, dispute, verification,
or user-visible state must be surfaced through Agentgres:

```text
missing bytes
invalid hash or CID
decrypt failure
stale replica
backend timeout
expired storage lease
retention mismatch
policy-incompatible storage location
```

The canonical response is:

```text
detect failure
  -> open ArtifactAvailabilityIncident
  -> quarantine invalid refs or dependent projections if needed
  -> try configured replica/backend/archive fallback
  -> verify commitments and wallet-controlled decryptability
  -> emit ArtifactRepairReceipt
  -> admit repaired refs or unrecoverable status through Agentgres
```

## Backend Selection Policy

Backend choice should consider:

- privacy class;
- local-only requirements;
- encrypted/shared availability;
- region or customer-boundary requirements;
- expected read/write volume;
- cost and latency;
- retention policy;
- deletion or redaction needs;
- archive durability;
- marketplace/public availability;
- restore requirements;
- verifier and replay access.

## Conformance Checks

An implementation conforms when:

1. Storage writes for serious runs return hashable, verifiable payload
   commitments.
2. Storage locations are recorded through Agentgres `ArtifactRef` or
   `PayloadRef`, not treated as truth by URL.
3. Backend-specific metadata does not replace Agentgres lifecycle, policy,
   authority, or receipt metadata.
4. Archive restore uses Agentgres restore/import operations.
5. Filecoin/CAS/S3/local disk/object stores can be swapped or replicated without
   changing what the payload means.
6. Missing, invalid, stale, or unavailable payloads open
   `ArtifactAvailabilityIncident` records when they affect admitted work.
7. Repair from replica, archive, or replacement payload requires an
   `ArtifactRepairReceipt` and Agentgres operation before projections or restore
   paths treat it as valid.

## Anti-Patterns

Do not:

- model Filecoin/CAS/S3/local disk/object stores as authority layers;
- use `cas.put` / `cas.get` as runtime authority operations;
- trust CDN URLs without content commitments and Agentgres refs;
- restore from storage bytes without Agentgres state-root validation;
- silently overwrite missing/corrupt payload bytes and call the artifact
  repaired;
- treat a successful backend fetch, Filecoin deal, gateway response, or object
  metadata row as restore validity;
- put raw private plaintext in public stores without wallet-controlled
  encryption;
- let package availability imply package install authority;
- let a storage backend decide delivery acceptance or dispute state.

## Related Canon

- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md):
  canonical artifact-ref meaning and archive/restore validity.
- [`filecoin-cas.md`](./filecoin-cas.md): Filecoin/CAS storage backend profile.
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md): Agentgres operational
  state substrate.
- [`../daemon-runtime/default-harness-profile.md`](../daemon-runtime/default-harness-profile.md):
  HarnessProfile semantics and Default Harness Profile reference
  scaffold/fallback behavior for step resolution that emits refs and receipts.
