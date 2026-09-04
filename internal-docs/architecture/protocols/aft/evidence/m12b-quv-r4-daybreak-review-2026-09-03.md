# M12b QUV R4 Daybreak review

Principal disposition: `PASS_CONSTRUCTION`.

This was an owner-authorized independent automated review under ADR 0049. It
is not human peer review, institutional certification, or professional
assurance.

Date: 2026-09-03.

## Candidate identity

```text
tag:        aft-quv-v0-construction-candidate-r4-2026-09-03
tag object: 8bb1ebc6adf29ba7598e77e4c566a30e0e922c52
commit:     c76cc88d354bfdc62df7d16244cb3f9cc0a7821f
message:    AFT QUV v0 construction candidate R4 (2026-09-03)
```

The reviewer used a fresh detached checkout at
`/tmp/aft-m12b-quv-r4-review.Hl1CBZ/repo`; it remained clean and the shared
checkout was untouched.

## Finding disposition

- `QUV-M12B-001` — critical, resolved. Q-A3 now covers every honest operation
  and every correct member, so any fixed correct member is a common
  serialization witness. The later conflicting request at that member
  discloses both candidates. In unowned mode, every acceptance must match that
  member's immutable first winner. The `H=2` and `H=3` opposite-order positive
  rows found zero conflicts; the split-witness mutation recovered two
  conflicts in 16 cases for both equivocating-owner and unowned modes.
- `QUV-M12B-002` — medium, resolved. Separate liveness campaigns cover honest-
  owner, dishonest-owner, and unowned modes; fresh and pre-populated correct
  state; and Byzantine silence or non-conflicting replies. Each mode checked
  32,768 cases with zero failures.

No new open findings were identified. Byzantine injection cannot remove timely
correct snapshots; silence cannot block under Q-A3. Flooding, durable I/O,
reply delivery, and clock error are charged to Q-A3/Q-A9. Rollback, premature
replies, garbage collection, configuration turnover, executor crash windows,
and cross-context replay remain explicit assumptions or later-gate
obligations.

## Independent reproduction

| Gate | Result | Elapsed | Maximum RSS |
|---|---|---:|---:|
| formal census | pass | 0.04 s | 10,984 KiB |
| maximal-visibility models | pass with expected counterexamples | 45.80 s | 261,684 KiB |
| QUV R4 model | `ALL EXPECTATIONS MET`; structural JSON match | 1:48.31 | 11,384 KiB |

Environment: Linux 6.17.9 x86_64, Python 3.12.3, Bash 5.2.21, OpenJDK
21.0.10.

```text
0081949f5ff363b5af9baa4270413efd94aef806a99e148f3a95618f187e1a85  quv_timed_model_r4.py
ddf7775bb5a0a00eff0dbdf20c673bd9658cbb356af40948a7fe054666e5984d  quv_timed_results_r4.json
f4b1e9855d6a8c404d98a3d962e9a9900133a45716318f527e5c9911683108eb  run_aft_formal_checks.sh
```

## Gate effect

M12b passes as a construction and M13Q may begin. The disposition does not
establish Byzantine consensus, ordering/effect composition, production
readiness, asynchronous safety, portable finality, or M14Q-M18Q. M12a's
offline byte-only lower bound remains intact.
