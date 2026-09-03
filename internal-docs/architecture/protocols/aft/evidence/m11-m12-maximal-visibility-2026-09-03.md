# M11/M12 maximal-visibility local evidence — 2026-09-03

Status: **M11 COMPLETE; M12 R3 AUTOMATED REVIEW RETURNED `UPHELD`;
`PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`**.

Current review candidate: annotated tag
`aft-maximal-visibility-lower-bound-candidate-r3-2026-09-03`. The R2 candidate
and predecessor tag without `-r2` remain immutable audit evidence.

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

- Formal census: 44 modules = 31 executed + 13 explicitly manual.
- `MaximalVisibilityDilemma`, `n=2`: 512 generated / 256 distinct states,
  depth 1; no error.
- `MaximalVisibilityDilemma`, `n=3`: 131,072 generated / 65,536 distinct
  states, depth 1; no error.
- `RoleSwitchConflict`: the expected `ExternalNonConflict` invariant violation
  was observed; the harness would fail if the mutation unexpectedly passed or
  failed for another reason.
- `ConflictQualifiedLiveness`: three distinct task states checked; no error.
  Each value submitted alone remains authorized, while a rooted conflict rule
  authorizes at most one value when both are submitted.
- `ExternalSelectorMutation`: the expected `ParticipantOnlyVerifier`
  invariant violation was observed when an external CAS receipt entered proof
  verification.
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

The first context-isolated Daybreak review of R2 returned `REPAIR_REQUIRED`.
The automated provenance is governed by ADR 0049 and is not represented as
human peer review. Its findings are retained in the review record. R3 applies
all requested repairs:

1. effect liveness now has the same rooted conflict/policy exception as input
   inclusion, plus an explicit solo-input liveness obligation;
2. verifier freshness inputs are rooted or explicit and held common;
3. participant support, common replayable inputs, and external selecting acts
   are separate sets;
4. the atomic register is downstream only, and feeding its receipt into
   verification is classified as an external-selector construction;
5. the prior-art wording and source pins are repaired; and
6. the requested positive task-boundary and negative selector-mutation models
   are in the standing harness.

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

The same context-isolated reviewer returned `UPHELD` against the immutable R3
candidate. Accordingly M12 closes as `PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`.
No maximal production profile is authorized and M13-M18 remain blocked. The
program can resume only after an explicit owner decision changes a required
property or permits and names an added authority/assumption.
