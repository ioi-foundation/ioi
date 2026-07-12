# Filecoin / CAS / IPFS Backend Profile

Status: canonical storage-backend profile.
Canonical owner: this file for Filecoin/CAS/IPFS payload availability behavior underneath Agentgres-governed artifact refs.
Supersedes: product prose that presents Filecoin/CAS as a peer architecture
authority component.
Superseded by: none.
Last alignment pass: 2026-05-30.
Doctrine status: canonical
Implementation status: built (sealed archive custody with preflight probes and done-bar)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/`
Last implementation audit: 2026-07-05

## Canonical Definition

**Filecoin/CAS/IPFS is a payload availability backend. It is not an authority
layer.**

Filecoin, CAS, IPFS, and CDN gateways can store or distribute content-addressed
payload bytes for packages, evidence, traces, checkpoints, delivery bundles,
training data, benchmarks, model artifacts, ontology packs, and sealed state
archive bytes. They do not decide what is true, who may use the payload, whether
an archive can be restored, or whether a delivery is accepted.

Agentgres owns those meanings through artifact refs, policy/authority linkage,
receipt, lineage, lifecycle, and restore/import metadata.

## Owns

Filecoin/CAS/IPFS owns or provides:

- content-addressed byte availability;
- CIDs and retrieval paths;
- pinning, deals, replication, or gateway access depending on backend;
- package and payload distribution;
- durability posture for immutable payloads;
- public or encrypted object availability.

## Does Not Own

Filecoin/CAS/IPFS does not own:

- Agentgres state;
- artifact identity in an IOI domain;
- package install authority;
- worker or service license rights;
- wallet-controlled decryption;
- archive restore validity;
- delivery acceptance;
- marketplace settlement;
- IOI L1 public commitments.

## Typical Payloads

Filecoin/CAS/IPFS may store:

- worker packages;
- service packages;
- workflow packages;
- encrypted capsules;
- model artifacts and checkpoints;
- ontology packs and data recipe payloads;
- connector mapping payloads;
- transformation outputs;
- training datasets;
- evaluation datasets;
- curated example corpora;
- benchmark suites and reports;
- generated files, notebooks, screenshots, video, CAD/Blender artifacts;
- evidence bundles;
- trace bundles;
- projection checkpoints;
- receipt bundles;
- delivery bundle payload members;
- sealed state archive bytes;
- static app bundles.

## Reference Flow

```text
daemon/runtime creates payload
  -> payload is hashed and optionally encrypted
  -> payload is stored on Filecoin/CAS/IPFS or gateway-backed storage
  -> CID/hash/size/media type are verified
  -> Agentgres records ArtifactRef or PayloadRef
  -> receipts bind operation, authority, policy, and payload commitment
```

## Package Flow

```text
publisher uploads signed/encrypted package to Filecoin/CAS/IPFS
  -> manifest root is recorded by package registry, Agentgres, or L1 when needed
  -> daemon downloads through gateway or pinned source
  -> daemon verifies hash/signature/manifest
  -> wallet.network grants install/invoke authority
  -> package executes only if policy permits
```

Package availability is not install authority. Install authority comes from
wallet.network, package policy, registry/listing rights, and daemon gates.

## Delivery Artifact Flow

```text
worker/service produces delivery payload
  -> daemon hashes/encrypts payload
  -> stores bytes through Filecoin/CAS/IPFS if policy chooses it
  -> Agentgres records ArtifactRef, DeliveryBundle linkage, and receipt
  -> sas.xyz, aiagent.xyz, Hypervisor, or another surface displays delivery state
  -> user/verifier fetches and verifies payload through Agentgres refs
```

## Sealed State Archive Flow

```text
Agentgres identifies archive-worthy state
  -> daemon/domain kernel exports and seals archive bytes
  -> Filecoin/CAS/IPFS stores encrypted archive bytes by CID/hash
  -> Agentgres records AgentStateArchive ref, object heads, state root,
     policy hash, authority context, replay/import metadata, and receipts
  -> authority providers and local/domain policy control decryption and restore
     authority; wallet.network supplies that path when portable delegated
     authority, secret custody, or decryption leases are required
  -> daemon rehydrates only through Agentgres restore/import operations
```

The archive bytes are durable payloads. They are not live Agentgres state.

## Verification

Consumers must verify:

- expected CID/hash;
- media type and size;
- manifest or bundle root;
- signature where applicable;
- Agentgres artifact lifecycle status;
- policy and privacy class;
- wallet authority for decrypt/export/restore;
- receipt linkage.

## Availability Incidents And Repair

Filecoin deals, IPFS pins, CAS objects, and gateway responses are availability
evidence. They are not artifact truth and they are not restore validity by
themselves.

```text
CID retrieval fails
or provider deal expires
or gateway returns bytes with wrong hash
or replica is stale
or encrypted archive cannot decrypt
  -> Agentgres opens ArtifactAvailabilityIncident
  -> invalid refs are quarantined where needed
  -> replica, pin, deal renewal, archive fallback, or replacement payload is tried
  -> CID/hash/manifest/decryption/policy are verified
  -> ArtifactRepairReceipt records the repair attempt
  -> Agentgres admits repaired refs or unrecoverable lifecycle state
```

A renewed Filecoin deal, new pin, or replacement CID may preserve availability.
It does not preserve canonical meaning unless Agentgres links the new payload
commitment to the artifact, receipt chain, policy hash, authority context, and
state root.

## Anti-Patterns

Do not:

- call Filecoin/CAS the artifact authority plane;
- treat a CID as sufficient proof of policy, authority, or provenance;
- use a gateway URL as trust;
- restore an `AgentStateArchive` directly from bytes;
- treat deal renewal, pinning, or gateway retrieval as an Agentgres repair;
- publish private plaintext to public availability layers;
- put ordinary operational truth on Filecoin/CAS as opaque state blobs;
- model Filecoin/CAS as a peer runtime substrate beside Agentgres.

## Implementation Status

The hypervisor daemon implements this profile as the storage leg after the
external-compute trio: bounded `StorageBackendAccount` kinds (`local_disk`,
`cas`, `ipfs`, `filecoin`; S3/customer-VPC are later siblings), REAL preflight
probes, wallet-gated archive export/restore over daemon-custody snapshot
material, sealed bytes (Argon2id KDF + AEAD under the wallet-secret
passphrase) before every backend write, commitment records
(address/CID/hash/size/media type) as availability evidence, storage receipts
in the Work Ledger record family (`storage_custody`; protocol terminology —
rendered by the Provenance application), `ArtifactAvailabilityIncident` +
`ArtifactRepairReceipt` semantics exactly as above, and storage candidates on
the decentralized.cloud candidate plane (`storage.archive` / `storage.cas`)
that state availability-is-not-restore-truth. Restore admits ONLY after
fetch + commitment hash + decrypt + admitted state_root all verify. ipfs/
filecoin live modes block named without credentials/config; the local
deterministic CAS fixture is unmistakably labelled and never claims network
availability. Done-bar: `verify-hypervisor-filecoin-cas-archive-custody.mjs`.

## Related Canon

- [`doctrine.md`](./doctrine.md): storage backend doctrine.
- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md):
  artifact meaning, lifecycle, policy/authority linkage, receipts, and
  restore/import validity.
- [`../agentgres/api-object-model.md`](../agentgres/api-object-model.md):
  Agentgres operation and object model.
- [`../daemon-runtime/events-receipts-delivery-bundles.md`](../daemon-runtime/events-receipts-delivery-bundles.md):
  delivery bundle, event, receipt, and trace semantics.
