# Filecoin/CAS API and Artifact Refs

Status: canonical low-level reference.
Canonical owner: this file for artifact refs, package refs, artifact bundle APIs, and artifact verification flow.
Supersedes: overlapping artifact API examples in plans/specs when ref or bundle fields conflict.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

Filecoin/CAS/CDN is the payload availability layer. It stores packages, worker capsules, model artifacts, delivery artifacts, evidence bundles, trace bundles, projection checkpoints, and large immutable payloads. Trust comes from hashes, signatures, manifests, and receipts, not from the CDN itself.

## ArtifactRef

```json
{
  "artifact_id": "artifact_123",
  "cid": "bafy...",
  "sha256": "...",
  "size_bytes": 123456,
  "media_type": "application/pdf",
  "filename": "runtime-audit.pdf",
  "privacy_class": "public | internal | private | encrypted",
  "encryption": {
    "mode": "none | envelope | threshold | tee_sealed",
    "key_ref": "wallet://key_ref_optional"
  },
  "provenance": {
    "domain_id": "agentgres://domain/sas.xyz",
    "run_id": "run_123",
    "receipt_id": "receipt_123"
  },
  "availability": {
    "primary": "filecoin",
    "mirrors": ["https://cdn.sas.xyz/ipfs/bafy..."],
    "pinning_policy": "30d | 1y | permanent | customer_controlled"
  }
}
```

## PackageRef

```json
{
  "package_id": "pkg_123",
  "package_type": "worker | service | workflow | model | connector",
  "cid": "bafy...",
  "sha256": "...",
  "manifest_root": "sha256:...",
  "publisher_signature": "base64...",
  "license_terms_root": "sha256:...",
  "encryption": {
    "mode": "none | marketplace_envelope | tee_required"
  }
}
```

## API Surface

```http
POST /v1/artifacts/init-upload
PUT  /v1/artifacts/{artifact_id}/content
POST /v1/artifacts/{artifact_id}/commit
GET  /v1/artifacts/{artifact_id}
GET  /v1/artifacts/{artifact_id}/content
GET  /v1/artifacts/by-cid/{cid}
POST /v1/artifact-bundles
GET  /v1/artifact-bundles/{bundle_id}
POST /v1/packages
GET  /v1/packages/{package_id}
GET  /v1/packages/by-cid/{cid}
```

## Artifact Bundle

```json
{
  "bundle_id": "bundle_123",
  "bundle_type": "delivery | evidence | trace | package | projection_checkpoint",
  "artifacts": ["artifact://..."],
  "bundle_root": "sha256:...",
  "privacy_class": "private",
  "provenance": {
    "run_id": "run_123",
    "delivery_id": "delivery_123"
  }
}
```

## Verification Flow

```text
client receives ArtifactRef
→ fetches from CDN/Filecoin gateway
→ checks CID/hash
→ checks signature or receipt root
→ checks wallet/network access policy for decryption
→ displays or downloads
```

## Non-Negotiables

1. CDN URLs are convenience mirrors, not trust roots.
2. Every package/artifact must be content-addressed.
3. Private artifacts must separate availability from readability.
4. Agentgres stores artifact metadata and provenance; Filecoin/CAS stores payloads.
5. L1 contracts store only roots or commitments, not payloads.
