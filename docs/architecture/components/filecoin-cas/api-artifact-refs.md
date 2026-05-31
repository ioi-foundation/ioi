# Deprecated: Filecoin/CAS API and Artifact Refs

Status: deprecated redirect.
Canonical owner: none; this path is retained for historical links only.
Superseded by: [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md) and [`../storage-backends/filecoin-cas.md`](../storage-backends/filecoin-cas.md).
Last alignment pass: 2026-05-30.

Low-level artifact refs are now Agentgres canon, not Filecoin/CAS canon.

Use:

- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md)
  for `ArtifactRef`, `PayloadRef`, bundle refs, archive refs, lifecycle,
  policy, authority, receipts, replay/import metadata, and restore validity.
- [`../storage-backends/filecoin-cas.md`](../storage-backends/filecoin-cas.md)
  for Filecoin/CAS/IPFS byte availability behavior.

Correct API posture:

```text
artifact.put / artifact.get / artifact.verify
  -> operate through Agentgres-governed refs
  -> selected storage backends hold bytes
```

Do not model standalone `cas.put` / `cas.get` as runtime authority operations.
