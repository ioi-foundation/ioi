# ADR 0043: Adopt Mutually Authenticated ML-KEM AFT Channels

- Status: Accepted for M1 implementation; not yet production-authorized
- Date: 2026-09-01
- Owners: AFT networking, cryptographic identity, assurance receipts
- Refines: ADR 0041 `channel_pq` accounting and ADR 0042 live-key choice
- Confidence: primitive/profile choice accepted; swarm integration, review and
  interoperability evidence remain release blockers

## Context

The existing libp2p transport uses Ed25519-authenticated Noise. The separate
`hybrid_kem_tls` wrapper adds a hybrid KEM-derived application key after a
classical TLS handshake, but it authenticates neither peer with a
post-quantum signature. Neither path can establish `channel_pq=true`, whose
v1 definition requires both post-quantum confidentiality and post-quantum peer
authentication.

The normative standards are NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA):

- <https://csrc.nist.gov/pubs/fips/203/final>
- <https://csrc.nist.gov/pubs/fips/204/final>

## Decision

### 1. The normative profile is `aft-pq-channel-v1`

The profile uses ephemeral ML-KEM-768 for key establishment, ML-DSA-44 for
mutual peer authentication, HMAC-SHA-256 extract/expand for transcript-bound
directional traffic keys, and ChaCha20-Poly1305 for record protection.

The repository may combine ML-KEM with a classical ECDH contribution as
defense in depth. The PQ claim depends on ML-KEM and ML-DSA, not on the
classical component. BLS, Ed25519, TLS certificates, libp2p peer ids and Noise
keys cannot satisfy either PQ coordinate.

### 2. The handshake is mutually authenticated and downgrade-free

The initiator signs a client hello containing the exact profile/version,
network, configuration, epoch, both stable member identities, both transport
endpoint bindings, an OS-random nonce, and its ephemeral KEM public key. The
responder verifies that signature against the rooted enrolled ML-DSA key,
encapsulates to the ephemeral key, and signs the complete server transcript,
including a second nonce and the KEM ciphertext. The initiator verifies the
rooted responder key and returns a signed key-confirmation finish. No 0-RTT
application data is accepted.

There is one algorithm tuple in v1. Unknown versions, algorithms, roles,
members, configurations, transcript hashes and enrollment bindings fail
closed; there is no in-band negotiation to a classical profile.

### 3. Traffic authority is per pair and per transcript

Directional keys bind the full authenticated transcript. Records bind the
transcript hash, direction, monotonically increasing sequence number and
content type as AEAD associated data. Nonce exhaustion, counter rollback,
replay and out-of-order delivery fail closed. Rekeying creates a new handshake
and cannot inherit the old channel's assurance without its own proof.

The normative AFT path sends consensus traffic through direct pairwise
protected channels. Classical gossipsub may remain a discovery or best-effort
transport, but evidence received solely over it cannot establish the private
PQ-channel assumption required by the asynchronous profile.

### 4. Enrollment remains explicit

ML-DSA public keys are authenticated by the rooted validator/configuration
snapshot. A public key carried in a handshake authenticates nothing by itself.
Transport endpoint ids are transcript labels that prevent channel splicing;
they are not PQ identities and do not replace enrollment.

### 5. Claims remain blocked through integration and review

The profile earns `channel_pq=true` only after the production swarm gates AFT
consensus traffic on a completed v1 session, encrypts every such record with
its pairwise key, rejects unauthenticated/classical fallback, persists the
required replay state, and passes interoperability, fuzz, benchmark and
independent-review gates.

## Consequences

- Handshake messages are substantially larger because ML-DSA public keys and
  signatures are not aggregated.
- Each validator pair needs session state; this matches the private
  authenticated-channel assumption of the initial static-adversary ACS
  profile.
- A classical libp2p connection can carry the handshake bytes without becoming
  a load-bearing cryptographic assumption. Harvested classical transport
  ciphertext does not reveal PQ-protected AFT records.
- A node without an enrolled ML-DSA identity cannot participate in the
  normative PQ profile. It may use an explicitly named classical profile whose
  receipts keep `channel_pq=false`.

## Rejected alternatives

### Relabel the hybrid TLS wrapper

Rejected because its peer authentication is classical. A PQ KEM alone does
not establish a PQ-authenticated channel.

### Treat signed consensus votes as a channel

Rejected. Vote signatures authenticate individual messages but provide no
confidential pairwise channel, key confirmation, traffic replay state or ACS
private-channel abstraction.

### Rely on libp2p Noise and Ed25519

Rejected for the normative PQ profile. They may remain defense-in-depth and
transport compatibility layers with no contribution to `channel_pq`.

## M1 acceptance gates

- Canonical handshake and record formats with cross-scope mutation tests.
- Rooted enrollment verification and mutual key confirmation.
- Production pairwise session integration and classical-fallback refusal.
- Crash/restart replay discipline, malformed-input fuzzing and representative
  pair-count benchmarks.
- Independent cryptographic review findings resolved or carried as an explicit
  release blocker.
