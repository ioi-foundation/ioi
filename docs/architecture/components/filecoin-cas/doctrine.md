# Filecoin / CAS / CDN Artifact Plane Specification

Status: canonical architecture authority.
Canonical owner: this file for artifact/payload availability doctrine; low-level artifact APIs live in [`filecoin-cas-api-and-artifact-refs.md`](./api-artifact-refs.md).
Supersedes: overlapping artifact-storage prose when payload authority conflicts.
Superseded by: none.
Last alignment pass: 2026-05-02.

## Canonical Definition

**The Filecoin/CAS/CDN plane provides immutable payload availability for canonical Web4 packages, artifacts, evidence, receipts, checkpoints, and delivery bundles.**

It stores bytes. It does not define truth by itself.

Trust comes from:

- content hashes;
- signed manifests;
- Agentgres refs;
- receipt bundles;
- IOI L1 commitments when applicable.

## Relationship To Agentgres

Filecoin/CAS is not the live Agentgres database. It is the
content-addressed payload and evidence availability layer.

Agentgres stores canonical operational state in its own domain-local state
engine: operations, object heads, constraints, indexes, projections,
subscriptions, receipt metadata, delivery state, and quality/contribution
ledgers. Filecoin/CAS stores immutable payload bytes and large bundles that
Agentgres references by hash/CID.

The boundary is:

```text
Agentgres:
  hot operational state
  canonical operation log
  object heads
  indexes
  constraints
  projections
  subscriptions
  receipt metadata
  artifact refs
  delivery state
  quality/contribution ledgers

Filecoin / CAS / CDN:
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
```

Snapshots and projection checkpoints stored here are immutable evidence/export
objects. They can accelerate repair, replay, audit, cold storage, or client
hydration, but they do not replace the Agentgres operation log or live object
state.

## What It Stores

The artifact plane may store:

- worker packages;
- service packages;
- encrypted capsules;
- workflow packages;
- model artifacts;
- reports;
- screenshots;
- generated files;
- notebooks;
- CAD/Blender artifacts;
- delivery bundles;
- evidence bundles;
- trace bundles;
- projection checkpoints;
- receipt bundles;
- manifests;
- static app bundles.

## What It Does Not Store as Authority

It does not own:

- canonical application state;
- Agentgres object heads;
- Agentgres indexes or projections;
- Agentgres subscription state;
- Agentgres transaction admission;
- wallet authority;
- IOI L1 settlement;
- worker license rights;
- service escrow state;
- policy approval decisions;
- runtime execution truth.

Those belong to Agentgres, wallet.network, IOI L1, and runtimes.

## File vs Artifact

- **File**: user-facing payload someone opens, exports, attaches, or receives.
- **Artifact**: protocol-level immutable payload, bundle member, checkpoint, receipt, manifest, or generated output.

Both should be content-addressed.

## Artifact Reference

Agentgres should store refs, not bytes:

```yaml
ArtifactRef:
  id: artifact_123
  cid: bafy...
  sha256: ...
  media_type: application/pdf
  size: 1048576
  privacy_class: scoped_private
  provenance:
    run_id: run_123
    worker_id: ai://workers.foo
  access_policy: policy_hash
  receipt_refs:
    - receipt_abc
```

## Privacy Classes

```text
public_plaintext
shared_encrypted
scoped_private
local_ephemeral
```

Rules:

1. Availability and readability are separate.
2. Public ciphertext is not public plaintext.
3. Key release is wallet/policy controlled.
4. Sensitive plaintext should not be stored in public artifact systems unencrypted.

## CDN Role

A CDN/gateway may serve content for latency, but it is not trusted.

Autopilot or browser clients must verify:

- CID/hash;
- manifest signature;
- expected size/media type;
- privacy policy;
- receipt linkage when applicable.

## Worker Package Flow

```text
publisher uploads signed/encrypted package to Filecoin/CAS
→ manifest root committed via aiagent.xyz / IOI L1 contract
→ Autopilot/daemon downloads through CDN/gateway
→ runtime verifies hash/signature
→ wallet.network approves authority grants
→ package executes if policy permits
```

## Delivery Artifact Flow

```text
worker/service produces artifact
→ daemon hashes/encrypts payload
→ stores payload in Filecoin/CAS/CDN
→ Agentgres records ArtifactRef and receipt
→ sas.xyz/aiagent.xyz displays delivery state
→ user verifies/downloads artifact
```

## Invariants

1. No artifact is trusted by URL alone.
2. No package installs without manifest/hash verification.
3. No private plaintext without policy-controlled key release.
4. No deletion assumption for public/shared storage; design privacy accordingly.
5. Bulky evidence belongs here, not on IOI L1.

## One-Line Doctrine

> **Filecoin/CAS makes Web4 payloads available; Agentgres and IOI commitments make them meaningful.**
