# Deprecated: Filecoin/CAS Component Doctrine

Status: deprecated redirect.
Canonical owner: none; this path is retained for historical links only.
Superseded by: [`../storage-backends/filecoin-cas.md`](../storage-backends/filecoin-cas.md) and [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md).
Last alignment pass: 2026-05-30.

This file used to describe Filecoin/CAS as the artifact plane. That wording is
now deprecated because it can make Filecoin/CAS look like a peer authority
component beside Agentgres.

Use the current canon instead:

- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md)
  owns `ArtifactRef`, `PayloadRef`, `EvidenceBundle`, `DeliveryBundle`,
  `AgentStateArchive`, artifact lifecycle, policy/authority/receipt linkage,
  replay/import metadata, restore validity, state-root validity, and
  content-addressed commitments.
- [`../storage-backends/doctrine.md`](../storage-backends/doctrine.md)
  defines storage backends as payload byte stores only.
- [`../storage-backends/filecoin-cas.md`](../storage-backends/filecoin-cas.md)
  defines Filecoin/CAS/IPFS as one storage backend profile.

Correct boundary:

```text
Agentgres artifact-ref plane = meaning, refs, lifecycle, policy, receipts, restore validity
Storage backends              = payload bytes
Filecoin/CAS/IPFS             = one content-addressed storage backend profile
```

Anti-pattern:

```text
Filecoin/CAS = artifact authority layer
```
