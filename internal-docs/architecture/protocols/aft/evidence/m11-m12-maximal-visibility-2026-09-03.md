# M11/M12 maximal-visibility local evidence — 2026-09-03

Status: **M11 LOCAL SPEC COMPLETE; M12 INDEPENDENT REVIEW PENDING**.

Current review candidate: annotated tag
`aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03`. The predecessor
tag without `-r2` remains immutable audit evidence.

## Deliverables

- Exact task/adversary/verifier model:
  `../specs/maximal_consensus_task.md`.
- Canonical-public-state contract and L-MAX lower-bound candidate:
  `../specs/maximal_visibility_viability.md`.
- Dated primary-source comparison and construction attack:
  `../specs/maximal_prior_art_comparison_2026-09-03.md`.
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

## Prior-art attack and repair

Primary sources were checked for Dolev–Strong authenticated synchronous BA,
FLP, DLS partial synchrony, Bracha RBC, HoneyBadger/ACS, DAG-Rider,
Narwhal/Tusk, fraud/data-availability proofs, LazyLedger, Herlihy's consensus
hierarchy, and Geeq user validation. The resulting dated matrix records the
model, validity, liveness, availability, external-verifier, and effect
semantics separately.

No checked construction supplies the disputed non-`Abort` transferable proof
from any possible sole correct identity while preventing a role-switched
Byzantine identity from reproducing its own accepted bytes. The strongest
escape, a shared linearizable first-publication object, supplies exactly the
selecting bit but is consensus-powerful external state rather than ordinary
dissemination.

The attack exposed three clarifications now included in the R2 task/proof:

1. the value task must admit two conflicting externally valid values under one
   fixed context rather than becoming valid-by-definition;
2. non-member public inputs are held fixed in the paired executions, and any
   non-reproducible selecting output is charged as an external authority; and
3. the role-switched Byzantine remains silent until the correct member emits
   its proof, so known delivery bounds cannot prevent the replay.

The comparison is local research evidence, not an exhaustive novelty claim or
independent validation. The review packet now requires the theorist to audit
each row and attempt an omitted construction.

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
