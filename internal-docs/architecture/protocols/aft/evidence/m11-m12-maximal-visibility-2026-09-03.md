# M11/M12 maximal-visibility local evidence — 2026-09-03

Status: **M11 LOCAL SPEC COMPLETE; M12 INDEPENDENT REVIEW PENDING**.

## Deliverables

- Exact task/adversary/verifier model:
  `../specs/maximal_consensus_task.md`.
- Canonical-public-state contract and L-MAX lower-bound candidate:
  `../specs/maximal_visibility_viability.md`.
- Bounded models and mutation witness: `../formal/maximal_visibility/`.
- Independent review handoff:
  `../packets/M12-maximal-visibility-theorem-review.md`.

## Focused formal result

Command:

```text
bash .github/scripts/run_aft_formal_checks.sh --maximal-visibility-only
```

Result: **PASS**.

- Formal census: 42 modules = 29 executed + 13 explicitly manual.
- `MaximalVisibilityDilemma`, `n=2`: 512 generated / 256 distinct states,
  depth 1; no error.
- `MaximalVisibilityDilemma`, `n=3`: 131,072 generated / 65,536 distinct
  states, depth 1; no error.
- `RoleSwitchConflict`: the expected `ExternalNonConflict` invariant violation
  was observed; the harness would fail if the mutation unexpectedly passed or
  failed for another reason.
- Temporary `TLAPS.tla` links were removed/restored; the focused run left no
  symlink delta.

The model enumerates arbitrary value-indexed acceptance families of member
support sets, rather than one fixed threshold. The prose proof supplies the
general role-switching argument; bounded enumeration is supporting evidence,
not a substitute for independent proof review.

## Local disposition

No tested canonical-public-state design escapes the following fork:

1. a finite non-`Abort` proof available from any possible sole correct member
   can be reproduced by that identity when it is Byzantine in a role-switched
   admissible execution, yielding conflicting accepted proofs; or
2. preventing that replay requires support from every possible correct
   identity (all `n` members) or a new external selecting authority, causing
   permanent-withholder nontermination or violating the target constraints.

Accordingly no maximal production profile is authorized. M12 remains in
progress until an independent reviewer returns `UPHELD`, `REPAIR_REQUIRED`, or
`REFUTED` against the immutable lower-bound candidate.
