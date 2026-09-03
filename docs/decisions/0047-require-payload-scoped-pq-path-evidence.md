# ADR 0047: Require Payload-Scoped PQ Path Evidence

- Status: Accepted and implemented for the M8 portable-receipt profile
- Date: 2026-09-03
- Owners: AFT assurance, PQ channel, terminal seal, consequence verification
- Refines: ADRs 0042, 0043, 0044, and 0046
- Confidence: production and clean-room positive/negative verification passes;
  independent cryptographic/custody/channel review remains release-blocking

## Context

A protocol requirement or a `pq=true` label cannot prove which authenticated
channel carried a particular authorization. Likewise, a terminal-signature
public key carried by a receipt cannot enroll itself, and a PQ adapter label
cannot authenticate the external endpoint. Consensus bytes are compatible
with both a fully PQ transport execution and an execution containing a
classically authenticated edge. Release therefore needs proof of the complete
demonstrated path, not inferred cryptographic posture.

## Decision

The portable M8 profile derives `channel_pq=true` only from a versioned,
payload-scoped full-mesh proof over the exact static finality membership. For
every unordered member pair, `PqChannelCompletionEvidenceV1` carries the
ML-KEM-768 handshake transcript, rooted ML-DSA-44 endpoint identities, signed
key completion, the exact finality-bundle hash, and both endpoint completion
attestations. Missing, duplicate, foreign, singly attested, mutated, or
classical edges refuse. T12 states the positive theorem and L-PQCH states the
matching indistinguishability lower bound.

The same receipt also carries:

- unanimous ML-DSA-44 configuration votes enrolling the terminal-key manifest;
- one identity/configuration/epoch/domain/slot-bound SLH-DSA-SHA2-128s share
  from every static finality member over a terminal root that includes the
  finality, manifest, intent, execution, outcome, and reconciliation roots;
- a resource-profile-rooted ML-DSA-44 endpoint signature over the exact atomic
  idempotency-register outcome.

Only after all three verifiers pass may the meet derive
`end_to_end_pq=true`. These are coordinate-specific verified transforms; the
receipt's claimed vector and transform labels remain untrusted inputs and are
exact-compared with recomputation.

## Consequences

- The result is transferable, offline-verifiable evidence for one authorized
  payload. It is not a claim about historical traffic, delivery, secrecy of
  erased traffic keys, adaptive security, or unobserved sessions.
- Full-mesh evidence is intentionally expensive and suited to the pessimistic
  terminal path. A smaller topology requires its own theorem and verifier; it
  cannot reuse this profile by assertion.
- The clean-room verifier imports no IOI crate. It independently reconstructs
  the decision and uses RustCrypto/fips205 implementations for ML-DSA and
  SLH-DSA checks, including validly re-enveloped negative receipts.
- Independent review of providers, custody, and channel construction remains
  a separate release gate; interoperability and duplicate implementations do
  not replace it.

## Rejected alternatives

### Infer channel PQ from the consensus profile

Rejected by L-PQCH: identical consensus bytes can traverse different channel
stacks.

### Let a terminal share enroll its own public key

Rejected because possession of an arbitrary signing key is not configuration
membership. The exact manifest root needs unanimous rooted enrollment votes.

### Treat the adapter's PQ boolean as endpoint evidence

Rejected because it authenticates no endpoint action. The resource profile
must root the endpoint key and the endpoint must sign the exact consequence.
