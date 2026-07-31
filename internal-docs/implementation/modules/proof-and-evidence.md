---
module_id: proof-and-evidence
module_class: method
title: Portable evidence and compositional assurance
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M0, M1, M2, M3, M5, M9, M10, M11, M12, M13, M14]
legacy_id: WP-PROOF
canon_owners:
  - docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md
  - docs/architecture/components/daemon-runtime/platform-operability.md
  - docs/architecture/components/daemon-runtime/api.md
  - docs/architecture/components/agentgres/doctrine.md
  - docs/architecture/components/agentgres/artifact-ref-plane.md
  - docs/architecture/components/storage-backends/doctrine.md
  - docs/architecture/components/storage-backends/filecoin-cas.md
  - docs/architecture/components/hypervisor/providers-and-environments.md
  - docs/architecture/components/wallet-network/api-authority-scopes.md
  - docs/architecture/foundations/common-objects-and-envelopes.md
  - docs/architecture/foundations/governed-autonomous-systems.md
  - docs/architecture/foundations/verifiable-bounded-agency.md
  - docs/architecture/foundations/ecosystem-assurance-certification-liability.md
  - docs/architecture/foundations/security-privacy-policy-invariants.md
  - docs/conformance/hypervisor-core/attestation-assurance.md
  - docs/conformance/hypervisor-core/dispute-rails.md
  - docs/conformance/hypervisor-core/managed-work-billing.md
  - docs/architecture/_meta/source-of-truth-map.md
---

# Portable Evidence And Compositional Assurance

## What this module owns

This module owns one reusable method: how a cut produces evidence a party outside the producing runtime can check, and how
separate pieces compose into a bounded claim without any single receipt or attestation carrying more meaning than the
boundary fact it binds. It orders no work, holds no status, and is never a sequencer — the stages that pull it decide when
it applies, their records decide what has been proved, canon owns the doctrine, and [`program/rules.md`](../program/rules.md)
states the proof floor once.

## Pulled by

[`sequence.v1.json`](../program/sequence.v1.json) binds this module to M0, M1, M2, M3, M5, M9, M10, M11, M12, M13, and M14
via `modules[].applies_to_stages` for id `proof-and-evidence`. That file is the only source of the binding: a stage not
listed there pulls this method only after the sequencer gains the edge, and no stage acquires it by citing this file. The
retiring master guide carried legacy `WP-PROOF` with the span "M1–M14"; that span is provenance, not a binding.

## Canon owners

| Canon owner | What it governs here |
| --- | --- |
| [`daemon-runtime/events-receipts-delivery-bundles.md`](../../../docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md) | Receipt-type registry and lifecycle; the ladder from receipt/attestation through evidence, verification, acceptance, adjudication, and settlement; receipt JCS body hashing, the append-only accumulator, signed checkpoints, inclusion/consistency witnesses, offline receipt-proof export; external-effect retry and ambiguous-effect reconciliation. |
| [`daemon-runtime/platform-operability.md`](../../../docs/architecture/components/daemon-runtime/platform-operability.md) and [`daemon-runtime/api.md`](../../../docs/architecture/components/daemon-runtime/api.md) | `TemporalVerificationProfile`, valid-as-of versus currentness, checkpoint and revocation freshness, bounded offline holdover, degraded-mode consequences, fault matrices; the environment-ops, backup, route-binding, change-plan prepare/apply/cancel, and cleanup-obligation routes whose outcomes this method binds. |
| [`agentgres/doctrine.md`](../../../docs/architecture/components/agentgres/doctrine.md) and [`agentgres/artifact-ref-plane.md`](../../../docs/architecture/components/agentgres/artifact-ref-plane.md) | Operation, exact head, and root semantics — accepted truth as distinct from what is merely stored; artifact and payload refs, `EvidenceBundle` and `DeliveryBundle`, archive refs, availability incidents, repair receipts, restore/import validity. |
| [`storage-backends/doctrine.md`](../../../docs/architecture/components/storage-backends/doctrine.md) and [`storage-backends/filecoin-cas.md`](../../../docs/architecture/components/storage-backends/filecoin-cas.md) | Storage backends as byte custody carrying no meaning, lifecycle, or integrity authority; the CAS/IPFS/Filecoin profile for archived evidence bytes and their availability. |
| [`hypervisor/providers-and-environments.md`](../../../docs/architecture/components/hypervisor/providers-and-environments.md) | Snapshot, manifest-complete backup, artifact-byte retrieval and hashing, staged restore prepare/apply/cancel, forward-only activation, cleanup and archive posture. |
| [`wallet-network/api-authority-scopes.md`](../../../docs/architecture/components/wallet-network/api-authority-scopes.md) | Signer identity, `AuthorityKeySet`, revocation snapshots, and grant scope as verification inputs. |
| [`foundations/objects/evidence-and-delivery.md`](../../../docs/architecture/foundations/objects/evidence-and-delivery.md) | Portable `ReceiptEnvelope` base fields, shared receipt identity/ref contract, dispute envelopes, and the ref identities (including `worktree://`) used for provenance. |
| [`foundations/governed-autonomous-systems.md`](../../../docs/architecture/foundations/governed-autonomous-systems.md), [`foundations/verifiable-bounded-agency.md`](../../../docs/architecture/foundations/verifiable-bounded-agency.md), [`foundations/ecosystem-assurance-certification-liability.md`](../../../docs/architecture/foundations/ecosystem-assurance-certification-liability.md), and [`foundations/security-privacy-policy-invariants.md`](../../../docs/architecture/foundations/security-privacy-policy-invariants.md) | Compositional external-world evidence admission, qualified operational determinations, fact-class policy, source independence and correlation, freshness, contradiction, challenge, assertion consequence scope; independent-party verification as a separately accountable principal, taint of participant-supplied results, consensus-is-evidence boundary; assurance stages, conformance profiles, certification claims, verifier independence, challenge/adjudication posture; retention, redaction, privacy class, and export constraints on retained evidence. |
| [`conformance/attestation-assurance.md`](../../../docs/conformance/hypervisor-core/attestation-assurance.md), [`conformance/dispute-rails.md`](../../../docs/conformance/hypervisor-core/dispute-rails.md), and [`conformance/managed-work-billing.md`](../../../docs/conformance/hypervisor-core/managed-work-billing.md) | Attester / Verifier-Appraiser / Relying-Party separation, nonce and workload/build binding, endorsement and reference-value appraisal, deterministic evidence narrowing, re-attestation and revocation posture; disputed and no-fault outcomes, deterministic default/remedy selection, bond conservation, dispute receipt duties; settlement as a stage distinct from acceptance and adjudication. |
| [`_meta/source-of-truth-map.md`](../../../docs/architecture/_meta/source-of-truth-map.md) | Which domain owner supplies the evidence obligations for a domain-specific fact, so a cut crossing a domain pack satisfies that owner in addition to the shared owners above. |

## Retained obligations

1. **Keep the six assurance stages distinct.** Receipt, evidence, verification, acceptance, adjudication,
   and settlement are separate states. A cut that reaches one may not report, project, or infer a later one.
2. **Protect the verification inputs.** Exact bodies, refs, and roots; signer, key-set, and revocation inputs;
   checkpoint freshness; artifact availability; and verifier independence are each protected. Any one of them
   substituted, stale, unavailable, or supplied by the party under evaluation invalidates the proof.
3. **Bind environment continuity end to end.** Every completed environment backup binds a manifest whose referenced
   artifacts *and* actual streamed bytes are verified — not the manifest alone, and not a size or count check. Restore,
   activation, route, and cleanup outcomes each bind to their exact preconditions and to the duties left open afterward.
4. **Preserve unfavourable evidence.** Negative, invalid, inconclusive, exploit, superseded, disputed, and no-fault
   evidence is retained on the same durable path as favourable evidence; a narrowing or refuting result is not waste.
5. **Prove selected exports offline.** For the exports a stage selects, an outside consumer verifies without
   access to the producer's database, resolving only declared immutable or independently trusted inputs.
6. **Keep the byte/meaning split.** Storage backends hold bytes; Agentgres refs hold meaning, lifecycle, and
   integrity. Possessing bytes is never possessing truth, and replication never transfers authority.
7. **Prevent compositional overclaim.** No single receipt or attestation may let a reader infer an unsupported real-world
   truth claim; a world claim stands on admitted, independent, fresh, non-contradicted evidence with its scope stated.
8. **Record the evidence index.** The stage evidence index records:

   ```text
   stage_id / work_item_id
   selected_profile and frozen thresholds
   owner and contract revisions
   code revision / worktree provenance
   generated schema/projection hashes
   positive and adversarial test refs
   Agentgres operation/head/root/checkpoint refs
   authority/policy/revocation/fence refs
   artifact and offline proof bundle refs
   product screenshots or recordings as non-authoritative evidence
   metrics and nonclaims
   applicable PG gate refs
   reviewer and decision
   owning work-item-record ref and status-transaction date
   ```

## Applying it in a work item

- `evidence_refs[]` names repository paths that exist and carry the expected-path literals for the index fields
  above; run output belongs in `adversarial_or_fault_proof`, never there.
- `adversarial_or_fault_proof` states in literal terms the substitution, refusal, restart/replay, and fault
  probes run against the exact artifacts, including which of the six ladder stages each probe stopped at.
- `canon_owners[]` names the owners above the cut crossed; `code_anchors[]` names the emitting and verifying files.
- Where an offline export is claimed: the export bundle ref, the trusted key-set and revocation-snapshot refs
  it resolves, and the independent verifier path that consumed it without producer database access.
- Where a backup, restore, activation, route, or cleanup outcome is claimed: the manifest ref, the
  streamed-byte verification result, and every duty the outcome leaves open.
- `remaining_nonclaims[]` records the unfavourable results retained under obligation 4 and the world-claims
  obligation 7 forbids inferring.

## Terminal evidence

This method contributes to a stage exit when the stage's evidence index is complete, selected exports verify offline, an
independent party reproduces the selected result, restart and replay reconstruct the same accepted truth, substitution and
refusal probes fail closed at the correct ladder stage, and the assurance stage each claim rests on is named explicitly.
Satisfying the method for one cut bounds that cut's claim only; it proves no other cut, no stage exit by itself, and no
later ladder stage.

## Canon gaps

- **Offline verification beyond receipts.** `events-receipts-delivery-bundles.md` defines a portable offline export profile
  for receipts (`ReceiptCheckpoint`, `ReceiptProofBundle`) and states that it does not replace `EvidenceBundle` or
  `DeliveryBundle`, while `agentgres/artifact-ref-plane.md` owns those bundles without an offline-verification contract.
  Obligation 5 applies to selected exports generally; those two owners should resolve whether a bundle-level offline
  profile exists and what an outside consumer must resolve.
- **Byte identity of retained estate evidence.**
  [`_meta/work-items/README.md`](../../../docs/architecture/_meta/work-items/README.md) requires each `evidence_refs[]` path
  to exist, which is a path check rather than a byte-identity binding, and canon does not state whether retained
  implementation evidence must also be admitted as content-addressed refs under `agentgres/artifact-ref-plane.md`. Those
  two owners should resolve it.
- **Canonical form of the evidence index.** The field list in obligation 8 has no registered contract identity or named
  canonical owner; it is inherited prose. [`_meta/work-items/README.md`](../../../docs/architecture/_meta/work-items/README.md)
  should resolve whether the index is a work-item record field set, a separate private artifact, or both.
- **Retention floor for unfavourable evidence.** Canon makes durability of negative, inconclusive, invalid,
  exploit-finding, and superseded attempts conditional on policy admitting their informational or audit value, and places
  the disputed and no-fault classes with `conformance/dispute-rails.md`, while obligation 4 asserts an unconditional duty
  for evidence a claim rests on. `events-receipts-delivery-bundles.md` and `foundations/security-privacy-policy-invariants.md`
  should resolve the floor and its interaction with redaction and retention policy.
