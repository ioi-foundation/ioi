# Filecoin / CAS / IPFS Backend Profile

Status: canonical storage-backend profile.
Canonical owner: this file for Filecoin/CAS/IPFS payload availability behavior underneath Agentgres-governed artifact refs.
Supersedes: `components/filecoin-cas/*` when those files present Filecoin/CAS as a peer architecture authority component.
Superseded by: none.
Last alignment pass: 2026-05-30.

## Canonical Definition

**Filecoin/CAS/IPFS is a payload availability backend. It is not an authority
layer.**

Filecoin, CAS, IPFS, and CDN gateways can store or distribute content-addressed
payload bytes for packages, evidence, traces, checkpoints, delivery bundles,
training data, benchmarks, model artifacts, ontology packs, and sealed state
archive bytes. They do not decide what is true, who may use the payload, whether
an archive can be restored, or whether a delivery is accepted.

Agentgres owns those meanings through artifact refs, policy, authority, receipt,
lineage, lifecycle, and restore/import metadata.

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
  -> wallet.network controls decryption and restore authority
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

## Anti-Patterns

Do not:

- call Filecoin/CAS the artifact authority plane;
- treat a CID as sufficient proof of policy, authority, or provenance;
- use a gateway URL as trust;
- restore an `AgentStateArchive` directly from bytes;
- publish private plaintext to public availability layers;
- put ordinary operational truth on Filecoin/CAS as opaque state blobs;
- model Filecoin/CAS as a peer runtime substrate beside Agentgres.

## Related Canon

- [`doctrine.md`](./doctrine.md): storage backend doctrine.
- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md):
  artifact meaning, lifecycle, policy, receipt, and restore authority.
- [`../agentgres/api-object-model.md`](../agentgres/api-object-model.md):
  Agentgres operation and object model.
- [`../daemon-runtime/events-receipts-delivery-bundles.md`](../daemon-runtime/events-receipts-delivery-bundles.md):
  delivery bundle, event, receipt, and trace semantics.
