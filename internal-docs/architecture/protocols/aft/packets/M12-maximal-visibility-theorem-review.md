# M12 maximal-visibility independent theorem-review packet

Status: **R2 AUTOMATED REVIEW RETURNED `REPAIR_REQUIRED`; R3 RETEST PENDING**.

This packet asks an independent distributed-computing reviewer to attack the
exact M11 task and the L-MAX role-switching lower-bound candidate. It is not
the P4.5a implementation/cryptography audit and neither review substitutes for
the other.

## Immutable review target

- Repository: `ioi-foundation/ioi`.
- Candidate ref: annotated tag
  `aft-maximal-visibility-lower-bound-candidate-r3-2026-09-03`.
- Reviewed predecessor (retained for audit):
  `aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03`, for which the
  context-isolated Daybreak review returned `REPAIR_REQUIRED`.
- Superseded predecessor (retained for audit):
  `aft-maximal-visibility-lower-bound-candidate-2026-09-03`.
- Exact commit: resolve the tag and record its full hash in the commissioning
  record and final review. The candidate cannot self-contain its own hash.
- Normative task: `../specs/maximal_consensus_task.md`.
- Lower-bound candidate: `../specs/maximal_visibility_viability.md`.
- Dated prior-art/task comparison:
  `../specs/maximal_prior_art_comparison_2026-09-03.md`.
- Mechanization: `../formal/maximal_visibility/`.

Any substantive repair creates a new candidate and requires the reviewer to
name the retested commit.

## Independence

The final report must identify the reviewer, relevant qualifications, and any
relationship or conflict. The reviewer must not have authored the candidate,
must select their own proof method, and must report objections and failed
attacks as well as agreement. Under ADR 0049, the owner has explicitly accepted
a context-isolated `gpt-daybreak-blue-latest` review for this owner-controlled
gate. Its automated nature must remain explicit; it is not human academic peer
review, institutional certification, or external professional assurance.

## Questions the review must answer

1. Does the M11 task correctly prevent `f=n-1` agreement from becoming
   vacuous while keeping decision termination, input inclusion, effect
   liveness, availability, and external verification separate?
2. Is transferable non-conflict the right minimum external meaning for a
   proof that can authorize irreversible effects? If not, specify a weaker
   property that remains non-vacuous and explain its consequence semantics.
3. Is `Support(pi)` a sound abstraction for every finite proof produced only
   by configured participant software? Identify any non-member information
   source the abstraction omits.
4. Does the role-switched execution preserve the verifier's roots, instance,
   inputs, proof bytes, and admissible fault assignment?
5. Does randomized almost-sure termination permit fixing the finite random
   tapes used by the counterexecution while retaining unconditional safety?
6. Does known synchrony, authenticated broadcast, Dolev–Strong, reliable
   broadcast, or a failure detector invalidate any step? Distinguish local
   decision agreement from a live transferable non-`Abort` certificate.
7. Can a canonical public state distinguish `E_a`, `E_b`, and `E_*` without
   importing a linearizable selector, trusted publisher/clock/erasure service,
   external consensus, TEE, or bounded Byzantine resource?
8. Is the conclusion genuinely broader than the threshold-specific L2 and
   temporal L-S bounds? State the exact class of protocols it does and does
   not cover.
9. Do the `n=2` proof and generalization to arbitrary `n>=2` hold? Attempt a
   concrete counterexample protocol rather than relying only on terminology.
10. If the conjunction is impossible, identify the minimal assumption or
    property change needed for each plausible alternative.
11. Audit every row and cited primary source in the dated prior-art comparison.
    Identify an omitted construction or a task mismatch that changes L-MAX;
    do not treat the comparison itself as evidence of novelty.

## Required attacks

At minimum, attempt escapes based on:

- authenticated synchronous Byzantine agreement and multi-sender broadcast;
- randomized asynchronous agreement;
- append-only sets, CRDTs, reliable broadcast, availability certificates,
  data-availability sampling, and content-addressed storage;
- first-seen/first-published rules and linearizable registers;
- failure detectors, clocks, leases, VDFs, and key evolution/erasure;
- proof-of-work, proof-of-stake, deposits, or economic selection;
- external chains, notaries, relays, and storage services;
- the modeled atomic idempotency register at the consequence boundary; and
- noninteractive proofs or accumulators over allegedly complete public state.

For every proposed escape, identify who emits the distinguishing bit, why a
Byzantine instance cannot simulate/fork it, and why the sole correct member can
obtain it while all other configured members are silent.

## Reproduction

From a clean checkout of the exact candidate:

```text
bash .github/scripts/run_aft_formal_checks.sh --census-only
bash .github/scripts/run_aft_formal_checks.sh --maximal-visibility-only
```

Expected bounded evidence:

- `n=2`: all 256 acceptance families checked; `Dilemma` invariant holds;
- `n=3`: all 65,536 acceptance families checked; `Dilemma` invariant holds;
- conflict-qualified task model: each singleton value remains authorized while
  a joint conflicting submission authorizes at most one value;
- mutation: TLC reports `Invariant ExternalNonConflict is violated`; the
  harness treats that exact counterexample as success; and
- selector mutation: TLC reports `Invariant ParticipantOnlyVerifier is
  violated` when a downstream CAS receipt is fed into verification.

The reviewer should add their own formalization. Passing bounded TLC models is
not a proof of the general theorem.

## Disposition

The report must return exactly one primary disposition:

- `UPHELD`: the task and L-MAX proof are sound under the stated scope;
- `REPAIR_REQUIRED`: a repairable ambiguity or proof gap exists, with exact
  affected text and a required retest; or
- `REFUTED`: a concrete counterexample construction satisfies every fixed M11
  requirement without an excluded authority.

An `UPHELD` report permits M12 to record
`PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`; it does not permit M13-M18 or the target
headline. The owner must then explicitly choose whether to relax a property or
add and name a stronger assumption. A `REFUTED` report returns the concrete
construction to the `PASS_CONSTRUCTION` campaign; it does not by itself admit
the construction.

Every finding and response remains in the final attributable report. The
implementers may disagree, but may not erase or silently reclassify an
objection.
