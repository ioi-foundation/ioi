# Maximal visibility viability models

`MaximalVisibilityDilemma.tla` enumerates arbitrary acceptance families over
proof support sets. It checks that no family can simultaneously accept a proof
produced by every possible sole-honest member while all others are silent and
force every conflicting accepted-proof pair to depend on every possible
honest identity. The registered configurations cover `n=2` and `n=3`.

`RoleSwitchConflict.tla` is the mutation witness. Once singleton proof support
is admitted for silent-`n-1` progress, a Byzantine identity replays the proof
it could produce in the role-switched sole-honest execution. TLC must find the
`ExternalNonConflict` violation. The formal harness treats absence of this
counterexample as a gate failure.

`ConflictQualifiedLiveness.tla` checks the repaired task boundary: each valid
value submitted alone remains live even when every peer is silent, while a
rooted conflict rule may authorize at most one value when both are submitted.
The task does not require authorization of both conflicting submissions.

`ExternalSelectorMutation.tla` distinguishes replayable client bytes in
`Common(pi)` from non-member selecting acts in `ExternalSupport(pi)`. Its
mutation feeds a downstream atomic-register receipt into `Verify`; TLC must
then violate `ParticipantOnlyVerifier`, proving that this escape changes the
authority model rather than satisfying the participant-only premise.

Focused reproduction:

```text
bash .github/scripts/run_aft_formal_checks.sh --maximal-visibility-only
```

These bounded models support the general L-MAX proof in
`../../specs/maximal_visibility_viability.md`; they do not replace independent
theorem review or establish a positive construction.

The mechanized support-set abstraction deliberately does not model a
linearizable first-writer service, trusted clock, external chain, or other
non-member selector. Adding one would trivially supply an ordering bit while
changing the M11 authority model. The independent review packet requires any
proposed escape to name and charge that dependency.
