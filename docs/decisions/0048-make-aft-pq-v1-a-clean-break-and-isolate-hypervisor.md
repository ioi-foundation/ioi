# ADR 0048: Make AFT PQ v1 a clean break and isolate Hypervisor

- Status: Accepted
- Date: 2026-09-03
- Owners: AFT production admission / portable assurance / Hypervisor build
- Refines: ADRs 0041, 0042, 0043, 0046, and 0047
- Supersedes: production use of guardian-majority, Asymptote, nested-guardian,
  scalar-assurance migration, BLS placeholder aggregation, and receipt-proof
  v2 compatibility through the AFT portable-verification CLI

## Context

AFT PQ v1 has no downstream production network whose rolling wire
compatibility must be preserved. Carrying old guardian modes, placeholder BLS
aggregation, scalar-to-vector promotion, and multi-schema CLI admission into
the first production profile would enlarge both its attack surface and its
claim surface. It would also make the Hypervisor application compile consensus
and terminal-seal dependencies it never initializes.

The hash-only asynchronous path is not legacy fallback. It is the normative
randomized progress mechanism after the optimistic path reaches the
configuration-scoped failed-view threshold. Removing it would remove AFT's
asynchronous termination claim.

Portable evidence has a separate trust-boundary problem: a self-contained
receipt can prove internal consistency but cannot nominate the roots by which
a relying party trusts it. Acceptance must therefore depend on external,
pinned trust input.

## Decision

1. `classic_bft` is the only admitted AFT production safety mode. Historical
   guardian-majority, Asymptote, and nested-guardian code may remain as
   non-admitted research/reference code while it is disentangled, but no
   production profile, executable configuration, or assurance receipt may
   select it.
2. The hash-only common-coin/ACS path remains mandatory. It activates after
   three certified failed views, has no private threshold setup, and does not
   silently downgrade any guarantee coordinate.
3. The unused BLS aggregation placeholder and scalar-to-`GuaranteeVectorV1`
   promotion API are removed. Production code emits and verifies the vector
   directly.
4. `ioi-receipt-proof-verify` accepts only the complete portable-assurance v1
   schema. It no longer acts as a compatibility frontend for v2 or runtime-v3
   bundles.
5. A portable receipt is authorized only against a separate canonical trust
   policy pinning network, configuration, epoch, terminal key root, allowed
   receipt signer, anchors, and the relying party's required guarantees.
   Receipt-only verification is not an authorization operation.
6. SLH-DSA terminal seals and portable assurance are explicit Cargo features.
   The direct full-node consensus, validator, execution, networking, state,
   storage, transaction, and client edges are activated only when a
   kernel-node profile requests them. Hypervisor therefore excludes
   `ioi-consensus`, `ioi-validator`, and SLH-DSA, while retaining the
   client/state/storage code transitively required by wallet/runtime services
   it actually calls.
7. Hypervisor wallet-key loading accepts only the current encrypted
   `IOI-GKEY` envelope with an explicitly supplied password. Raw keys, legacy
   envelopes, and interactive fallback are not admitted.
8. AFT PQ v1 is a genesis/new-network cutover. No rolling mixed-version wire
   compatibility or timeout-based downgrade is claimed.

## Consequences

- A production AFT validator has one named PQ consensus profile: ML-DSA live
  votes, the hash-only asynchronous path, mutually authenticated ML-KEM
  channels, and SLH-DSA terminal seals.
- Reviewers can treat old guardian material as excluded reference surface,
  not as a hidden production alternative. Complete source deletion can follow
  after the remaining shared theorem machinery is separated.
- Offline receipt consumers must provision a trust-policy artifact out of
  band. This is intentional: portability removes runtime dependence, not the
  need for a trust root.
- The Hypervisor default build omits `ioi-consensus` and `ioi-validator`; its
  remaining client/state dependency comes through wallet/runtime services it
  calls and is not removed without first splitting those service crates.
- Existing experimental networks must restart from a new genesis if they move
  to AFT PQ v1.

## Rejected alternatives

### Remove the hash-only path

Rejected because it is the liveness construction, not a compatibility mode.
The optimistic path alone requires eventual synchrony and cannot support the
stated asynchronous-progress profile.

### Let a receipt carry its own trust roots

Rejected because a separately generated configuration can be perfectly
self-consistent. Cryptographic validity without externally selected roots is
inspection, not authority.

### Delete all historical guardian source immediately

Rejected for this cut because shared canonical-collapse theorem and test
machinery is still physically colocated with the old engine. Production
admission is closed now; source extraction and deletion may proceed as a
separate mechanical refactor without delaying Hypervisor or weakening AFT.
