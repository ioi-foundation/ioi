# Deterministic Observer Sealing

`CanonicalChallengeV1` is the normative equal-authority observer lane for
`Asymptote`.

It replaces sampled affirmative authority with a proof-carrying public surface:

- deterministic observer assignments
- assignment-scoped observer transcripts
- assignment-scoped observer challenges
- transcript and challenge commitments
- exactly one canonical outcome object:
  `AsymptoteObserverCanonicalClose` or `AsymptoteObserverCanonicalAbort`

The observer lane is therefore no longer:

- "all sampled observers returned `ok`"

It is now:

- "the public transcript surface is canonical for the slot, the public
  challenge surface is canonical for the slot, and the slot carries the unique
  close-or-abort outcome implied by that surface"

## Public Objects

The observer theorem surface is carried by these shared types in
`crates/types/src/app/guardianized.rs`:

- `AsymptoteObserverAssignment`
- `AsymptoteObserverObservationRequest`
- `AsymptoteObserverStatement`
- `AsymptoteObserverTranscript`
- `AsymptoteObserverTranscriptCommitment`
- `AsymptoteObserverChallenge`
- `AsymptoteObserverChallengeCommitment`
- `AsymptoteObserverCanonicalClose`
- `AsymptoteObserverCanonicalAbort`

`SealedFinalityProof` carries the full transcript and challenge surface
directly, plus the transcript commitment, challenge commitment, and exactly one
canonical outcome object. The proof may not carry both close and abort, and it
may not carry neither.

## Admissible Challenge Basis

Observer challenges are objective negative-authority objects. The current
challenge basis is:

- `MissingTranscript`
  An assigned observer did not contribute a canonical transcript for its slot.
- `TranscriptMismatch`
  The observation request presented to the observer does not match the
  canonical slot-bound request.
- `VetoTranscriptPresent`
  A valid guardian-backed transcript binds the canonical slot surface and
  carries a non-`Ok` verdict or veto kind.
- `ConflictingTranscript`
  A valid guardian-backed transcript exists for the assignment but conflicts
  with the canonical slot-bound statement or assignment.
- `InvalidCanonicalClose`
  A carried canonical close object does not match the canonical transcript /
  challenge surface implied by the slot and therefore must be challenge-
  dominated into abort.

Every admissible challenge is carried by public evidence:

- an assignment
- an offending observation request, or
- an offending transcript
- an offending canonical close

The challenge `evidence_hash` must match that carried public evidence exactly.

## Acceptance Rules

`SealedFinal` on the observer lane is accepted iff:

```text
AcceptObserverSealedFinal(slot) iff
  BaseFinal(slot)
  and VerifyTranscriptCommitment(slot)
  and VerifyChallengeCommitment(slot)
  and VerifyCanonicalClose(slot)
  and ChallengeSurface(slot) = ∅
  and TranscriptSurface(slot) covers every deterministic assignment
```

`Abort` on the observer lane is accepted iff:

```text
AcceptObserverAbort(slot) iff
  BaseFinal(slot)
  and VerifyTranscriptCommitment(slot)
  and VerifyChallengeCommitment(slot)
  and VerifyCanonicalAbort(slot)
  and ChallengeSurface(slot) ≠ ∅
```

The close-or-abort split is exclusive:

- `AsymptoteObserverCanonicalClose` is valid only when the canonical challenge
  surface is empty.
- `AsymptoteObserverCanonicalAbort` is valid only when the canonical challenge
  surface is non-empty.
- a slot may carry exactly one of them

This is the observer-lane equivalent of omission dominance in canonical
ordering. A dominant challenge kills close. It does not merely reduce a
confidence bound.

## Runtime Construction

The runtime derives and verifies the observer surface in four places.

### 1. Observer-side derivation

`GuardianContainer::observe_asymptote_request` in
`crates/validator/src/common/guardian.rs` no longer treats a coordinator-authored
`Ok` statement as the authority source.

Instead, the observer:

- receives the canonical `AsymptoteObserverObservationRequest`
- derives the local observer statement for that request
- returns either a guardian-backed transcript or an objective challenge

### 2. Producer-side canonicalization

`GuardianContainer::sign_consensus_with_guardian` in
`crates/validator/src/common/guardian.rs` gathers the observer surface for the
slot.

For each deterministic assignment it:

- issues the canonical observation request
- collects either a transcript or a challenge
- converts missing, conflicting, or vetoing responses into objective challenge
  objects

The producer then computes:

- `canonical_asymptote_observer_assignments_hash`
- `canonical_asymptote_observer_transcripts_hash`
- `canonical_asymptote_observer_challenges_hash`

If the challenge surface is empty and every assignment contributed a canonical
`Ok` transcript, the proof carries `AsymptoteObserverCanonicalClose`.

Otherwise the proof is forced to `BaseFinal` / `Abort` and carries
`AsymptoteObserverCanonicalAbort`.

### 3. Finalize-path publication

`canonicalize_observer_sealed_finality_proof` and
`publish_canonical_observer_artifacts` in
`crates/validator/src/standard/orchestration/finalize.rs` publish the public
observer surface into `guardian_registry`.

The canonical publication verbs are:

- `publish_asymptote_observer_transcript@v1`
- `publish_asymptote_observer_transcript_commitment@v1`
- `report_asymptote_observer_challenge@v1`
- `publish_asymptote_observer_challenge_commitment@v1`
- `publish_asymptote_observer_canonical_close@v1`
- `publish_asymptote_observer_canonical_abort@v1`

The proof-carried surface is sufficient for immediate block verification. The
registry copy is the durable public audit surface.

The registry surface is now also accountable:

- objective observer challenges are replay-deduplicated as canonical evidence
- accountability is kind-specific:
  `MissingTranscript` / `ConflictingTranscript` blame the assigned observer,
  while `TranscriptMismatch` / `VetoTranscriptPresent` /
  `InvalidCanonicalClose` blame the producer / positive close path
- policy-controlled membership updates are aftermath only:
  `guardian_registry` may apply best-effort current-epoch quarantine and stage
  next-epoch eviction, but canonical abort / challenge dominance remains valid
  even when those updates are disabled, delayed, or skipped

### 4. Consensus verification

`GuardianMajorityEngine::verify_asymptote_canonical_observer_sealed_finality`
in `crates/consensus/src/aft/guardian_majority/mod.rs` verifies:

- deterministic observer assignments
- transcript surface coverage and assignment binding
- challenge surface coverage and evidence binding
- transcript and challenge commitments
- canonical close or canonical abort
- on-chain registry copies when they already exist

Any non-empty canonical challenge surface blocks `SealedFinal`.

## Sealed-Effect Binding

Irreversible effects bind to the observer surface through
`sealed_finality_proof_observer_binding` in
`crates/types/src/app/guardianized.rs`.

The guardian-side effect builder and the gateway verifier consume that binding:

- `build_http_egress_seal_object` in
  `crates/validator/src/common/guardian.rs`
- `verify_seal_object` in
  `crates/validator/src/standard/workload/drivers/verified_http.rs`

The seal therefore commits not just to generic sealed finality, but to the
exact canonical observer transcript root, challenge root, and canonical outcome
for the slot. A challenge-dominated slot cannot authorize a sealed irreversible
effect.

## Theorem

The observer theorem for `CanonicalChallengeV1` is:

```text
Theorem (Deterministic Equal-Authority Observer Sealing)
Assume:
  1. deterministic observer assignment is sound,
  2. guardian-backed observer transcripts and challenges are signature-sound,
  3. transcript and challenge commitments are canonical,
  4. the close-or-abort outcome object is unique for the canonical surface,
  5. the registry / log publication surface is append-only once published,
  6. honest validators run the same deterministic transcript/challenge and
     close-or-abort derivation over the public observer surface,
  7. sealed-effect verifiers bind to that observer surface.

Then arbitrary behavior by all other validators cannot create:
  a. a conflicting valid canonical observer close for the slot,
  b. coexistence of a valid canonical close and a valid canonical abort, or
  c. a valid sealed irreversible effect release for a challenge-dominated slot.
```

This is the observer-lane analogue of canonical ordering:

- public evidence
- canonical commitments
- negative-authority dominance
- every honest validator that observes the same public surface derives the same
  close-or-abort result

Under the accountable-adversary variant, those same public challenges become
penalty-bearing objective faults rather than passive audit artifacts.

## Relationship To The Legacy Sampled Lane

The old sampled affirmative observer lane had a high-confidence tail bound of
the form:

```text
P_unsafe(s) <= p_beacon_bias * p_veto_suppression * Π_j (1 - h)^(k_j)
```

That formula remains a valid description of the old lane's analytical
compromise-resistance story. It is not the theorem carried by
`CanonicalChallengeV1`.

For `CanonicalChallengeV1`, observer sealing is deterministic at the admitted
object boundary. Sampling remains only a deterministic duty-assignment rule,
not the source of safety.
