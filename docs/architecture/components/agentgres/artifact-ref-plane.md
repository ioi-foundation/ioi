# Agentgres Artifact-Ref Plane

Status: canonical architecture authority.
Canonical owner: this file for Agentgres-governed artifact refs, payload refs, evidence bundles, delivery bundles, sealed state archive refs, content-addressed commitments, artifact lifecycle, policy/authority/receipt linkage, replay/import metadata, restore validity, and relationship to storage backends.
Supersedes: `components/filecoin-cas/*` when those files appear to own artifact meaning, authority, lifecycle, or restore validity.
Superseded by: none.
Last alignment pass: 2026-05-30.

## Canonical Definition

**The Agentgres artifact-ref plane is the canonical reference, lifecycle, and
meaning layer for payload bytes used by IOI domains.**

Agentgres does not store every large payload byte. It records what a payload is,
why it exists, which operation produced it, which policy and authority governed
it, which receipts prove it, which state root or object heads it binds, and how
it can be verified, replayed, imported, restored, redacted, archived, or revoked.

Storage backends hold bytes. Agentgres defines what those bytes mean.

```text
Agentgres operation
  -> ArtifactRef / PayloadRef / ArchiveRef
  -> policy + authority + receipt + state-root linkage
  -> selected storage backend payload bytes
  -> projections, replay, import, restore, delivery, or audit
```

## Owns

The Agentgres artifact-ref plane owns:

- `ArtifactRef`;
- `PayloadRef`;
- `EvidenceBundle`;
- `DeliveryBundle` artifact identity and acceptance linkage;
- `AgentStateArchive` refs, state roots, object heads, restore/import metadata,
  lifecycle status, and validity;
- content-addressed commitments such as CID, SHA-256, manifest root, bundle
  root, and payload hash;
- artifact lifecycle: `proposed`, `active`, `verified`, `redacted`, `archived`,
  `revoked`, `missing`, `invalid`;
- policy hash, schema version, retention policy, privacy class, and redaction
  status;
- authority context, decrypt authority requirement, export authority
  requirement, and restore authority requirement;
- producing operation, producing actor, run/task/domain linkage, and lineage;
- receipt refs, trace refs, verification refs, and settlement refs when
  applicable;
- replay/import metadata;
- projection checkpoint refs;
- restore validity and state-root validity;
- payload availability status as observed by Agentgres-backed checks.

## Does Not Own

The Agentgres artifact-ref plane does not own:

- raw payload bytes;
- raw secrets or wallet keys;
- physical durability guarantees of a specific storage vendor;
- Filecoin deal execution;
- S3 bucket policy by itself;
- local filesystem mutation by itself;
- CDN trust;
- IOI L1 public settlement;
- model inference;
- daemon execution semantics.

Those belong to storage backends, wallet.network, IOI L1, model backends, and
the IOI daemon respectively.

## Minimal Implementation Objects

### ArtifactRef

```yaml
ArtifactRef:
  artifact_id: artifact://...
  domain_id: agentgres://domain/...
  producing_operation_ref: agentgres://operation/...
  producing_actor:
    worker:... | service_engine:... | runtime:... | wallet:...
  role:
    large_payload | evidence | trace | checkpoint | sealed_state_archive |
    delivery_bundle | package | screenshot | dataset | tool_result |
    model_trace | ontology_pack | data_recipe | projection_checkpoint
  content:
    cid: bafy... | null
    sha256: sha256:...
    manifest_root: sha256:... | null
    bundle_root: sha256:... | null
    media_type: application/json | text/plain | image/png | ...
    size_bytes: integer
  storage:
    storage_backend:
      local_disk | s3 | filecoin | cas | ipfs | object_store |
      provider_blob | customer_vpc_blob | storage_engine
    storage_uri_ref: string | null
    replication_policy: string | null
    retention_policy: string | null
  policy:
    policy_hash: sha256:...
    schema_version: string
    privacy_class: public | internal | confidential | secret
    redaction_status: none | redacted | tombstoned
    encryption_ref: wallet.network://sealed-key/... | null
  authority:
    authority_context_ref: grant://...
    decrypt_authority_required: boolean
    export_authority_required: boolean
    restore_authority_required: boolean
  lineage:
    run_ref: run:... | null
    task_ref: task:... | null
    object_refs:
      - agentgres://object/...
    state_root: sha256:...
    receipt_refs:
      - receipt://...
    trace_refs:
      - trace://...
  lifecycle:
    status:
      proposed | active | verified | redacted | archived |
      revoked | missing | invalid
    created_at: timestamp
    updated_at: timestamp
```

### PayloadRef

`PayloadRef` is the operation-local pointer to large payload bytes. It may
remain embedded inside an Agentgres operation until lifecycle, query, replay, or
settlement pressure requires promotion to `ArtifactRef`.

```yaml
PayloadRef:
  cid: bafy... | null
  sha256: sha256:...
  media_type: application/json
  size_bytes: integer
  role:
    large_payload | evidence | trace | checkpoint |
    sealed_state_archive | package | delivery_bundle
  artifact_ref: artifact://... | null
```

### EvidenceBundle

```yaml
EvidenceBundle:
  bundle_id: evidence://...
  domain_id: agentgres://domain/...
  claim_refs:
    - claim:...
  artifact_refs:
    - artifact://...
  receipt_refs:
    - receipt://...
  verification_refs:
    - receipt://...
  bundle_root: sha256:...
  policy_hash: sha256:...
  producing_operation_ref: agentgres://operation/...
```

### DeliveryBundle

`DeliveryBundle` is a delivery-facing bundle whose artifact identity and
acceptance/dispute linkage are Agentgres-governed. Payload members still live in
storage backends.

```yaml
DeliveryBundle:
  delivery_bundle_id: delivery_bundle://...
  order_ref: service_order:... | null
  run_ref: run:...
  artifact_refs:
    - artifact://...
  evidence_bundle_refs:
    - evidence://...
  receipt_refs:
    - receipt://...
  acceptance_state:
    proposed | accepted | disputed | remediated | rejected
  settlement_refs:
    - settlement://...
```

### AgentStateArchive

`AgentStateArchive` is an Agentgres-governed archive record. The encrypted
archive bytes are payloads; the archive's meaning, validity, and restore path
are Agentgres truth.

```yaml
AgentStateArchive:
  archive_id: archive://...
  domain_id: agentgres://domain/...
  actor_id:
    worker:... | service_engine:... | runtime:...
  base_state_root: sha256:...
  object_heads:
    Run:run_123: sha256:...
    TaskState:task_456: sha256:...
  archive_payload_ref: artifact://...
  archive_cid: bafy... | null
  archive_sha256: sha256:...
  storage_backend:
    filecoin | cas | ipfs | s3 | local_disk | object_store | provider_blob
  contents:
    - task_state
    - working_memory
    - patch_branches
    - tool_trace
    - artifact_refs
    - projection_checkpoint
    - replay_metadata
  encryption:
    scheme: hybrid-pq | envelope | tee_sealed
    recipient: wallet://user_or_org
    key_ref: wallet.network://sealed-key/...
  policy_hash: sha256:...
  authority_context_ref: grant://...
  receipt_refs:
    - receipt://...
  replay_import_metadata_ref: artifact://...
  schema_version: string
  lifecycle:
    status:
      proposed | active | verified | archived |
      revoked | missing | invalid | restored
```

## Lifecycle

```text
payload-producing action proposed
  -> authority / policy gate
  -> payload bytes written to selected storage backend
  -> hash/CID/manifest/bundle root computed
  -> Agentgres ArtifactRef or PayloadRef proposed
  -> receipt emitted
  -> Agentgres operation accepted or rejected
  -> projections and retrieval indexes catch up
  -> artifact can be verified, read, exported, archived, redacted, or restored
```

Archive restore is never silent local mutation:

```text
AgentStateRestoreRequested
  -> archive ref loaded from Agentgres
  -> authority/decryption checked through wallet.network
  -> payload fetched from storage backend
  -> hash/CID verified
  -> archive decrypted
  -> state root and object heads verified
  -> StateImported operation proposed
  -> ProjectionRebuilt
  -> RestoreReceiptRecorded
```

## Admission / Settlement Boundary

A payload ref crosses the Agentgres admission boundary when the payload:

- supports a claim, decision, delivery, archive, replay, import, restore, or
  policy decision;
- affects user-visible or domain-visible state;
- may be reused by workers, services, verifiers, marketplaces, or L1
  settlement;
- must survive restore, export, audit, redaction, dispute, or retention policy;
- participates in worker training, evaluation, benchmark, routing, or package
  promotion.

Private scratch bytes may remain runtime-local until they become evidence,
delivery material, training material, archive material, or admitted operational
truth.

## Events And Receipts

Meaningful artifact transitions produce receipts or Agentgres operations:

```text
ArtifactRecorded
ArtifactVerified
ArtifactRead
ArtifactExported
ArtifactRedacted
ArtifactRevoked
ArtifactMissing
EvidenceBundleCreated
DeliveryBundleProposed
DeliveryBundleAccepted
DeliveryBundleDisputed
AgentStateArchiveCreated
AgentStateRestoreRequested
ArchiveFetched
ArchiveHashVerified
ArchiveDecrypted
StateImported
ProjectionRebuilt
RestoreReceiptRecorded
```

Receipt metadata should include actor, authority chain, policy hash, payload
hash/CID, artifact refs, operation refs, resource usage, and result state.

## Relationship To Storage Backends

Storage backends are byte stores selected by policy, cost, privacy, locality,
durability, and availability:

```text
local disk
S3 / object stores
Filecoin
CAS / IPFS
provider blob stores
customer VPC blob stores
Postgres / SQLite / RocksDB / append-only logs when used as payload engines
```

They may be replicated, stale, unavailable, deleted, migrated, mirrored, or
replaced. Agentgres remains the authority over which payloads matter, which refs
are valid, which lifecycle state applies, and which restore/import operations
are allowed.

## Conformance Checks

An implementation conforms when:

1. Every admitted large payload has an Agentgres `ArtifactRef` or operation
   `PayloadRef`.
2. Every artifact ref binds hash/CID, role, producing operation, policy,
   authority context, receipt refs, and lifecycle status.
3. Storage URLs are never trusted without hash/CID and receipt/policy checks.
4. Archive restore runs through Agentgres operations and wallet.network
   authority checks.
5. Missing or invalid payloads become lifecycle states and/or blockers rather
   than silent success.
6. Projections, indexes, and retrieval systems can be rebuilt from Agentgres
   operations, refs, receipts, and storage payloads.

## Anti-Patterns

Do not:

- treat Filecoin, CAS, IPFS, S3, local disk, object stores, or CDNs as truth;
- write raw blobs for serious runs without Agentgres refs;
- restore an archive by mutating local files without Agentgres restore/import
  operations;
- use a CDN URL as a trust root;
- store raw secrets in artifact payloads without wallet-controlled encryption;
- let package, dataset, trace, or checkpoint bytes become authoritative because
  they are content-addressed;
- collapse Agent Wiki / `ioi-memory` into random Agentgres blob rows;
- put ordinary artifact bytes or full traces on IOI L1.

## Related Canon

- [`doctrine.md`](./doctrine.md): Agentgres state substrate doctrine.
- [`api-object-model.md`](./api-object-model.md): Agentgres object and
  operation model.
- [`../storage-backends/doctrine.md`](../storage-backends/doctrine.md): storage
  backend byte-store doctrine.
- [`../storage-backends/filecoin-cas.md`](../storage-backends/filecoin-cas.md):
  Filecoin/CAS backend profile.
- [`../daemon-runtime/default-harness-profile.md`](../daemon-runtime/default-harness-profile.md):
  daemon-executed loop-native profile that creates artifact refs during work.
- [`../daemon-runtime/events-receipts-delivery-bundles.md`](../daemon-runtime/events-receipts-delivery-bundles.md):
  receipt, trace, and delivery bundle semantics.
