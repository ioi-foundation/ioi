# M12b QUV R4 local evidence

Status: local repair evidence after the R3 independent `REPAIR_REQUIRED`
disposition; not independent review, an arbitrary-`n` proof, production
admission, or a public consensus claim.

Date: 2026-09-03.

## Findings repaired

The exact R3 review recorded two findings:

- `QUV-M12B-001` (critical): Q-A3 allowed a different timely correct member
  for each operation. With two correct members processing `X,Y` and `Y,X`,
  two verifiers that each see only a different singleton snapshot can both
  accept.
- `QUV-M12B-002` (medium): the combined safety/liveness counter made part of
  the reported liveness result vacuous and omitted fresh correct state for
  dishonest-owner and unowned modes.

R4 repairs the specification by requiring every correct member's complete
round trip to fit `delta_rt` for every honest executor operation. This is a
safety-critical assumption, not evidence inferred from silence. R4 also adds
separate exactly-one-candidate liveness campaigns for every authority mode and
multi-correct serialization rows.

## Reproduction

Command:

```text
bash .github/scripts/run_aft_formal_checks.sh --quv-only
```

Corrected full-space run on 2026-09-03:

| Authority | Mode | Cases | Conflicts/failures |
|---|---:|---:|---:|
| honest | synchronous safety | 24,576 | 0 |
| dishonest owner | synchronous safety | 2,281,472 | 0 |
| unowned | synchronous safety | 2,281,472 | 0 |
| honest | exactly-one-candidate liveness | 32,768 | 0 |
| dishonest owner | exactly-one-candidate liveness | 32,768 | 0 |
| unowned | exactly-one-candidate liveness | 32,768 | 0 |
| dishonest owner | all correct timely, `H=2` | 4 | 0 |
| unowned | all correct timely, `H=2` | 4 | 0 |
| dishonest owner | all correct timely, `H=3` | 8 | 0 |
| unowned | all correct timely, `H=3` | 8 | 0 |
| dishonest owner | different timely witness mutation, `H=2` | 16 | 2 |
| unowned | different timely witness mutation, `H=2` | 16 | 2 |
| dishonest owner | one-way deadline mutation | 2,281,472 | 33,328 |
| unowned | one-way deadline mutation | 2,281,472 | 172,192 |
| dishonest owner | reply-before-durable mutation | 13,688,832 | 47,104 |
| dishonest owner | unbound reply replay | 1,283,328 | 16,384 |
| dishonest owner | stale same-slot replay | 1,283,328 | 0 |

Every liveness campaign includes an initially empty correct conflict set as
well as the already-recorded singleton state. Byzantine replies are absent or
carry only the submitted candidate, so the campaigns quantify the declared
no-valid-conflict premise rather than silently testing a conflict execution.

The final pre-freeze full run returned `ALL EXPECTATIONS MET` in 1 minute
47.45 seconds; maximum reported resident set was 11,440 KiB.

Repository artifact hashes before the immutable-candidate freeze:

```text
0081949f5ff363b5af9baa4270413efd94aef806a99e148f3a95618f187e1a85  formal/maximal_visibility/quv_timed_model_r4.py
ddf7775bb5a0a00eff0dbdf20c673bd9658cbb356af40948a7fe054666e5984d  formal/maximal_visibility/quv_timed_results_r4.json
```

The annotated candidate tag is authoritative after freeze.

## Supported boundary

The bounded evidence supports the internal consistency of these statements:

- all correct member replies being timely is sufficient in the enumerated
  multi-correct opposite-order schedules;
- merely having some potentially different timely correct reply per operation
  is insufficient, and the mutation exhibits the counterexample;
- every enumerated exactly-one-candidate synchronous schedule terminates for
  every authority mode, including fresh correct state; and
- complete round-trip timing, durable write-before-reply, and cross-context
  binding remain load-bearing.

It does not prove arbitrary `n`, arbitrary concurrency, bounded queueing under
query flooding, process-level durable I/O, restart/reconfiguration, canonical
ordering, portable receipts, or irreversible-effect correctness. It also does
not transform QUV into Byzantine consensus. Those are M13Q and later
obligations if independent R4 review returns `PASS_CONSTRUCTION`.
