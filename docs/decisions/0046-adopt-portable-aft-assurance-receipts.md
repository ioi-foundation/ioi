# ADR 0046: Adopt Portable AFT Assurance Receipts

- Status: Accepted and implemented for the M7 v1 receipt/verifier boundary
- Date: 2026-09-03
- Owners: AFT assurance, source-neutral finality, consequence verification
- Refines: ADRs 0041, 0044, and 0045
- Confidence: canonical-byte, PQ-signature, negative-corpus and independent-
  implementation checks pass; integrated production emission is M8

## Context

A runtime-local authorization decision is not portable evidence. A third party
must be able to reconstruct the decision without an IOI node, database, clock,
or network lookup, and must receive a precise refusal instead of a partially
trusted result when any constituent is unknown or inconsistent.

## Decision

`PortableAssuranceReceiptV1` is the closed interop envelope. It carries the
effect manifest and policy, configuration/key snapshot, complete source-neutral
runtime-v3 finality bundle, consequence/resource evidence, optional M6
collateral package, requested anchors, claimed achieved vector, exact T10/T11
transformation trace, verifier identity, canonical receipt hash, and ML-DSA-44
signature. ADR 0047 extends the same v1 closed profile with payload-scoped PQ
channel coverage, unanimous rooted terminal-seal enrollment/shares, and PQ
endpoint evidence; absence of any required constituent refuses rather than
decoding as the stronger profile.

The `ioi-receipt-proof-verify` CLI verifies canonical bytes offline against a
separately provisioned trust-policy artifact. It
reverifies the embedded ordering/availability/finality certificates, derives
externalization only from the exact atomic resource record, re-runs the
distinct-collateral verifier, exact-compares the transformation trace and
achieved vector, evaluates the manifest policy, and reports verified
constituents. Unknown schema, verifier, algorithm, or transformation refuses.

An independent clean-room utility imports no IOI crate. It reproduces the
closed JCS subset, hash/binding, arbitrary-precision collateral, transform and
policy checks, while a separately compiled RustCrypto oracle verifies the
production dcrypt ML-DSA signature. Committed canonical/economic golden vectors
pin the cross-implementation representation.

## Consequences

- Assurance becomes an offline-verifiable evidence object rather than a node
  API response.
- The verifier accepts only canonical RFC 8785/JCS bytes; pretty-printed or
  semantically equivalent noncanonical JSON refuses.
- Receipt issuance uses a PQ envelope signature. The embedded runtime-v3
  issuer signature remains independently visible in the primitive meet; M8
  must not claim end-to-end PQ until that complete demonstrated chain is PQ.
- Per ADR 0048, the CLI is a clean portable-assurance-v1 surface; v2/runtime-v3
  compatibility dispatch is removed.
- Receipt-contained roots never nominate their own authority. Acceptance
  requires externally pinned network, configuration, epoch, terminal key
  root, receipt signer, anchors, and relying-party guarantee requirements.

## Rejected alternatives

### Resolve missing evidence from a live node

Rejected because it makes air-gapped verification impossible and changes the
evidence after issuance.

### Trust the receipt's achieved vector or transformation labels

Rejected because either would reintroduce evidence laundering. Both are exact-
compared with verifier-derived results.

### Accept any JSON serialization of the same object

Rejected because cross-language hashes and signatures require one byte form.
