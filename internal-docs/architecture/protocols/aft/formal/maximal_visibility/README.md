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

Focused reproduction:

```text
bash .github/scripts/run_aft_formal_checks.sh --maximal-visibility-only
```

These bounded models support the general L-MAX proof in
`../../specs/maximal_visibility_viability.md`; they do not replace independent
theorem review or establish a positive construction.
