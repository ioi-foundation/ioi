# ADR 0042: Select SLH-DSA For AFT Terminal Seals

- Status: Accepted for M1 implementation; release remains blocked on
  independent cryptographic review and the M1 evidence gates
- Date: 2026-09-01
- Owners: AFT terminal-seal cryptography / validator key custody / portable
  verification
- Refines: ADR 0041's primitive-specific PQ accounting
- Does not amend: the unanimous seal threshold, T1's journal-discipline
  assumption, the live-ordering signature profile, or any deployment selection
- Confidence: standards choice accepted; the Rust implementation and custody
  integration are not yet release-authorized

## Context

AFT terminal shares are infrequent, attributable, near-unanimous statements.
Their cryptographic priorities differ from live votes: conservative
post-quantum assumptions, small enrolled public keys, portable verification,
forward key retirement, and safe failure matter more than signature latency.

The existing R9 reference signer uses a fresh Ed25519 key derived from a hash
ratchet. It verifies a public key carried by the share itself and therefore
does not authenticate configuration membership. Its in-memory state update is
also not an atomic durable reservation. It is neither the target PQ signature
nor an acceptable production custody design.

The standardized hash-based candidates are:

- LMS/HSS, specified by RFC 8554 and profiled by NIST SP 800-208;
- XMSS/XMSS-MT, specified by RFC 8391 and profiled by NIST SP 800-208; and
- stateless SLH-DSA, standardized by NIST FIPS 205.

NIST explicitly warns that stateful hash signatures require careful state
management. SP 800-208's approved profile additionally requires key and
signature generation inside non-exporting hardware cryptographic modules. AFT
must not describe a software-only LMS or XMSS implementation as conforming to
that NIST profile.

Primary standards:

- NIST FIPS 205: <https://csrc.nist.gov/pubs/fips/205/final>
- NIST SP 800-208: <https://csrc.nist.gov/pubs/sp/800/208/final>
- RFC 8554: <https://www.rfc-editor.org/rfc/rfc8554>
- RFC 8391: <https://www.rfc-editor.org/rfc/rfc8391>

## Decision

### 1. The normative terminal primitive is SLH-DSA-SHA2-128s

`SealShareV2` uses the pure-message form of SLH-DSA-SHA2-128s from FIPS 205,
with AFT's canonical, domain-separated signing payload as the message. AFT
assigns a versioned internal algorithm identifier; it does not represent that
identifier as an IANA assignment.

The “s” parameter set is selected because terminal evidence is stored and
transmitted by every signer. Its approximately 7.8 KiB signature is materially
smaller than the corresponding “f” variant. Terminal signing latency is
profile-scoped and must be measured; it is not inherited by the live tier.

This is a standard algorithm selection, not a claim that any particular
library or binary is FIPS 140 validated.

### 2. AFT schedules one independently enrolled SLH-DSA key per seal slot

SLH-DSA is stateless and is not cryptographically harmed by repeated signing.
AFT nevertheless limits each enrolled key to one terminal slot. This provides
explicit forward retirement, bounds key exposure, and makes state-policy
violations independently attributable without inventing a new signature
scheme.

The configuration's key-root manifest authenticates the first scheduled key
commitment for each `(network, configuration, epoch, conflict domain, member)`
scope. Every accepted share must match the current enrolled commitment and
must sign the next-key commitment. A public key merely included in the share
never authenticates membership.

The commitment binds at least:

- protocol and schema version;
- network, configuration, epoch, and conflict domain;
- member identity and member index;
- seal slot/index;
- exact signature suite and public key; and
- predecessor/current state commitment.

### 3. Reserve durably before signing

The signer uses an advance-before-sign transaction:

1. authenticate the current persisted record against the enrolled commitment;
2. atomically compare-and-swap the durable generation and state commitment to
   the next slot, consuming the current key;
3. only after that commit, sign the v2 payload with the reserved in-memory key;
4. zeroize the retired secret and temporary material where the platform and
   selected library support it; and
5. publish the share or record a burned slot.

A crash after step 2 may lose a seal opportunity, but it cannot authorize a
retry at the spent slot. Exhaustion and missing next-key material fail closed.
Rollback is detected when the persisted generation or state commitment does
not match the compare-and-swap anchor.

Local file locking or atomic rename alone cannot detect a snapshot cloned to a
different host. Production clone detection therefore requires a durable
single-writer compare-and-swap anchor outside the clonable signer blob, or a
hardware monotonic counter. A backend without that capability is a
non-production test profile and cannot satisfy the M1 custody claim.

### 4. ML-DSA remains the live-vote choice

Live votes use the repository's FIPS-204-shaped ML-DSA implementation under a
separate profile and benchmark. Terminal SLH-DSA evidence does not turn a
classical live certificate, BLS optimization, channel, or endpoint PQ.

### 5. The first implementation is review-blocked

The available pure-Rust RustCrypto SLH-DSA implementation states that it has
not received an independent audit. AFT may integrate it behind exact known-
answer and interoperability tests, but no production release or “fully PQ”
claim is permitted until independent cryptographic review findings are
resolved or the implementation is replaced by an equivalently reviewed,
conforming provider.

The dependency must be version-pinned. Unknown algorithm identifiers,
parameter sets, encodings, or context variants fail closed. BLS paths remain
explicitly `pq=false`.

## Consequences

- Clone or rollback bugs cannot expose a one-time-signature leaf, because the
  terminal primitive is stateless; they remain serious journal-discipline and
  equivocation faults and are detected by the external state anchor.
- Signatures are large and signing is slow compared with Ed25519 or ML-DSA.
  This cost is isolated to terminal seals and published per profile.
- A crashed advance-before-sign operation burns a slot. It never rolls back or
  silently substitutes a weaker certificate.
- The configuration/key-root manifest and its history become load-bearing
  portable-verification inputs.
- Secure erasure is defense in depth for retired per-slot secrets, not the
  basis for claiming that SLH-DSA itself is stateful or forward-secure.

## Rejected alternatives

### LMS/HSS as the software default

Rejected for the initial normative profile because reuse of a stateful leaf is
cryptographically catastrophic, software snapshot/clone management is a hard
deployment precondition, and the currently available Rust implementations do
not remove the independent-review gate. LMS/HSS remains eligible for a future
hardware-backed profile that satisfies SP 800-208's custody requirements.

### XMSS/XMSS-MT as the software default

Rejected for the same state-reuse and custody reasons, with greater
implementation complexity and a less mature Rust integration surface. It may
also be reconsidered only as a separately named hardware-backed profile.

### AFT-specific one-time or few-time signatures

Rejected. AFT will not invent a hash-signature construction. The one-key-per-
slot rule is key-use policy around standardized SLH-DSA, not a new signature
scheme.

### One long-lived SLH-DSA key

Rejected because it would discard the existing key-evolution and erasure
discipline, make state-policy violations harder to localize, and fail to bind
the required current and next commitments.

## M1 acceptance gates

This decision is not M1 completion. M1 still requires `SealShareV2`, enrolled
manifest verification, external durable compare-and-swap state, crash/clone/
rollback/exhaustion tests, FIPS 205 known-answer and independent
interoperability vectors, fuzzing, published benchmarks, PQ live votes, a PQ
peer-authentication channel profile, and resolved independent review findings.
