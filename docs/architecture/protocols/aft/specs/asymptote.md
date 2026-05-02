# Asymptote

`Asymptote` is the scalable two-tier finality mode in the Aft Fault Tolerance
family.

It keeps block transport and tentative `BaseFinal` progression on the
`GuardianMajority` hot path, then upgrades selected slots to a stronger
irreversible-effect settlement state through a second deterministic sealing
plane.

## Core Idea

`Asymptote` separates:

- chain progression
- sealing evidence collection
- irreversible-effect release

The model is:

- `BaseFinal`: validator majority QC plus guardian committee certificate
- `SealedFinal`: `BaseFinal` plus either
  - witness-backed certification across the required strata, or
  - deterministic equal-authority observer close with an empty canonical
    challenge surface
- `Abort`: the sealing plane found objective evidence that blocks sealed
  release for the slot

Irreversible effects can additionally carry a proof-carrying `SealObject` that
binds the committed intent, guardian slot metadata, policy hash, replay
nullifier, and observer/witness sealing surface into a compact verifier-friendly
object.

This keeps chain progression fast while making irreversible release fail-closed.

## Public State Continuity Instance

`Asymptote` is the sealing-specific instance of AFT's broader `public state
continuity with extractable obstructions` target.

For the closed sealing boundary

```text
∂_h^seal = (
  root_{h-1},
  base_certificate_h,
  transcript_commitment_h,
  challenge_commitment_h,
  policy_h
)
```

the relevant theorem is not merely that one close proof may verify. It is that
the slot admits at most one canonical collapse object:

```text
Collapse(∂_h^seal) ∈ { Close(X_h), Abort(Ω_h) }
```

where `Ω_h` is the canonical observer challenge surface.

In `Asymptote`, the positive witness is the canonical close proof over the
transcript and challenge commitments, and the negative witness is the objective
observer challenge surface that forces `Abort`.

## Slot States

- `Pending`
- `BaseFinal`
- `Sealing`
- `Abort`
- `SealedFinal`
- `Escalated`
- `Invalid`

All honest nodes must derive the same state from the same admissible evidence.

## Evidence Collapse

The slot-local collapse function is deterministic verification of the canonical
evidence set:

- guardian quorum certificate
- validator QC
- witness certificates, or canonical observer transcripts/challenges
- registry policy and epoch seed
- transparency-log checkpoints and append-only proofs
- optional divergence signals

The runtime accepts `BaseFinal` blocks immediately for throughput. It then
collects sealing evidence asynchronously and republishes the same block with a
`sealed_finality_proof` once either:

- the required witness strata have each contributed a valid assigned witness
  certificate, or
- the canonical observer surface resolves to a valid canonical close or a valid
  canonical abort

This keeps settlement deterministic: ambiguity collapses to `Abort`, not to
heuristic retry or partial settlement.

## Witness Assignment

Witness committees are selected deterministically per required certification
stratum from the active witness set by combining:

- epoch seed
- producer account id
- slot `(height, view)`
- reassignment depth
- witness stratum id
- witness manifest hash

Assignments are unique and ordered. `Asymptote` requires one committee per
configured certification stratum on the witness-backed sealing path.

## Deterministic Observer Sealing

The normative equal-authority observer lane is `CanonicalChallengeV1`.

Observer assignments are selected deterministically from the active validator
set by combining:

- epoch seed
- producer account id
- slot `(height, view)`
- observer round
- observer account id

The producer is excluded from its own observer pool. The runtime may further
filter assignments through the configured correlation budget.

Each assigned observer derives its local result from the canonical
`AsymptoteObserverObservationRequest` and publishes exactly one of:

- a guardian-backed `AsymptoteObserverTranscript`
- an objective `AsymptoteObserverChallenge`

The public observer surface is carried by:

- `AsymptoteObserverTranscript`
- `AsymptoteObserverTranscriptCommitment`
- `AsymptoteObserverChallenge`
- `AsymptoteObserverChallengeCommitment`
- `AsymptoteObserverCanonicalClose`
- `AsymptoteObserverCanonicalAbort`

The current admissible challenge basis is:

- `MissingTranscript`
- `TranscriptMismatch`
- `VetoTranscriptPresent`
- `ConflictingTranscript`
- `InvalidCanonicalClose`

Each admissible observer challenge is public-evidence-only:

- assignment-scoped challenges carry the offending assignment
- request-mismatch challenges carry the offending observation request
- transcript-based challenges carry the offending guardian-backed transcript
- `InvalidCanonicalClose` carries the offending canonical close object
- `InvalidCanonicalClose`

The observer acceptance rule is:

```text
AcceptObserverSealedFinal(slot) iff
  BaseFinal(slot)
  and VerifyTranscriptCommitment(slot)
  and VerifyChallengeCommitment(slot)
  and VerifyCanonicalClose(slot)
  and ChallengeSurface(slot) = ∅
  and TranscriptSurface(slot) covers every deterministic assignment
```

The observer abort rule is:

```text
AcceptObserverAbort(slot) iff
  BaseFinal(slot)
  and VerifyTranscriptCommitment(slot)
  and VerifyChallengeCommitment(slot)
  and VerifyCanonicalAbort(slot)
  and ChallengeSurface(slot) ≠ ∅
```

This is challenge-dominant by construction:

- `SealedFinal` is impossible when the canonical challenge surface is non-empty
- `CanonicalClose` and `CanonicalAbort` may not coexist
- every honest validator that observes the same transcript and challenge
  surface derives the same negative object locally

The implementation correspondence for this lane is:

- shared types and hashes in
  [`guardianized.rs`](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/guardianized.rs)
- observer derivation and challenge origination in
  [`guardian.rs`](/home/heathledger/Documents/ioi/repos/ioi/crates/validator/src/common/guardian.rs)
- canonical publication in
  [`finalize.rs`](/home/heathledger/Documents/ioi/repos/ioi/crates/validator/src/standard/orchestration/finalize.rs)
- registry persistence in
  [`mod.rs`](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/guardian_registry/mod.rs)
- consensus verification in
  [`mod.rs`](/home/heathledger/Documents/ioi/repos/ioi/crates/consensus/src/aft/guardian_majority/mod.rs)

The registry path is now accountable rather than archival-only:

- deterministic observer challenges are replay-deduplicated as canonical
  evidence
- `MissingTranscript` and `ConflictingTranscript` penalize the assigned
  observer
- `TranscriptMismatch`, `VetoTranscriptPresent`, and
  `InvalidCanonicalClose` penalize the producer / positive close path
- those membership updates are policy-controlled aftermath only:
  best-effort quarantine and next-epoch eviction may be enabled, delayed, or
  disabled without changing the slot-local close-or-abort result

## Observer Theorem

The machine-checked `Asymptote` formal model now proves the deterministic
observer kernel:

- base certificates are unique per slot
- canonical observer close objects are unique per slot
- canonical observer close and canonical observer abort cannot coexist
- a challenge-dominated slot cannot release a sealed irreversible effect

This is the observer-lane analogue of canonical ordering:

- public evidence
- canonical commitments
- negative-authority dominance
- deterministic local close-or-abort derivation from the same public surface

## Legacy Sampled Comparison

The old sampled affirmative observer lane had the analytical tail bound:

```text
P_unsafe(s) <= p_beacon_bias * p_veto_suppression * Π_j (1 - h)^(k_j)
```

For equal committee size `k` repeated across `r` independent rounds:

```text
P_unsafe(s) <= p_beacon_bias * p_veto_suppression * (1 - h)^(k r)
```

That formula remains historically accurate for the superseded sampled
affirmative lane. It is not the normative sealed-release theorem for
`CanonicalChallengeV1`.

Under `CanonicalChallengeV1`, sampling determines duties, not safety. Safety
comes from the canonical public transcript surface, the canonical public
challenge surface, and the close-or-abort split implied by those surfaces.

Under the accountable-adversary variant, the same challenge surface also
supplies penalty-bearing evidence, so the observer theorem is no longer merely
about rejecting unsafe release; it is also about making unsafe release attempts
accountable and epoch-removing.

## Sealed Effects

The secure-egress control plane can require a `FinalityTier` for each effect:

- `BaseFinal`: fast path
- `SealedFinal`: requires a valid `SealedFinalityProof`

For proof-enabled irreversible effects, the guardian emits a `SealObject`
inside the canonical receipt. The current reference implementation uses a
`HashBindingV1` proof family:

- `EffectIntent` commits the external effect before execution
- `EffectPublicInputs` bind the committed guardian counter, trace, measurement,
  replay nullifier, and `canonical_collapse_hash`
- `EffectProofEnvelope` is a compact verifier-specific proof blob
- `SealObject` packages verifier metadata, canonical intent, public inputs, and
  proof bytes

Under the live runtime, a `SealedFinal` secure-egress request now carries both
the `SealedFinalityProof` and the slot's `CanonicalCollapseObject`. The
guardian-side effect builder and downstream receipt verifier both recompute the
same `canonical_collapse_hash` from that collapse object and the proof-carried
observer surface, so a challenge-dominated or otherwise mismatched slot cannot
authorize irreversible release.

The release rule is deterministic over the sealing surface. In particular, the
observer path binds:

- the canonical transcript root
- the canonical challenge root
- the canonical close-or-abort outcome
- the protocol-wide canonical collapse object hash

The runtime helper `sealed_finality_proof_observer_binding` is consumed by the
guardian-side effect builder and by effect verifiers so that a
challenge-dominated slot cannot authorize irreversible release.

## Policy

The on-chain `AsymptotePolicy` controls:

- required witness strata
- escalation witness strata
- equal-authority observer rounds
- equal-authority observer committee size
- observer sealing mode
- observer challenge window
- max reassignment depth
- checkpoint freshness
- finality tier for high-risk effects

## Non-Claim

`Asymptote` should be described as:

- a deterministic guardian-backed base-finality protocol
- a deterministic witness- or observer-backed sealed-release protocol under
  explicit public-evidence assumptions
- a fail-closed settlement discipline for irreversible effects

It should not be described as a classical unconditional “99% Byzantine fault
tolerance” theorem.

The old sampling formula remains only as historical analytical context for the
superseded affirmative sampled-observer lane. The normative observer claim is
the deterministic `CanonicalChallengeV1` close-or-abort theorem.
