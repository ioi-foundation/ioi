# M5 event-substrate retained gate bytes

All gates produced by fresh detached processes in a DEDICATED DETACHED WORKTREE
at the exact commit, with `CARGO_INCREMENTAL=0`. Every log carries
`IOI_MEASURED_COMMIT` in its own bytes, and `check-claims-coverage` refuses any
log that declares no commit, or a commit that is neither the packet HEAD nor an
ANCESTOR of it whose entire measured-to-HEAD delta is retained evidence. Both
clauses bind: tree equality is not history.

- measured commit: `46a60482f49c8215b80d4247c1a2e50fab72bcc6`
- this evidence commit is its child, and the delta between them is evidence
  ONLY — which is the condition the fixpoint rule requires.

| file | gate | result |
|---|---|---|
| m4-aggregate.log | M4 outcome-room system spine | 98/98 PASS (exit 0) |
| m4-activation.log | M4 GoalRun activation plane | 44/44 PASS (exit 0) |
| m5-genericity.log | M5 event-substrate genericity | 63/63 PASS (exit 0) |
| agentgres-tests.log | agentgres lib tests | 50/50 PASS (exit 0) |
| boundary-tests.log | injection boundary + stream homing | 2/2 PASS (exit 0) |
| m0.log | M0 supplied-snapshot check | 1603 entries, exit verified (exit 0) |
| check-estate.log | estate integrity | PASS (exit 0) |
| attestation-chain.log | anchor append-only + bindings resolve | PASS (exit 0) |

## Supplied build inputs

`node_modules` and `target` are symlinked from the main checkout. Every source
byte under test is the worktree's own checkout; only build inputs are shared.
Named because each has produced a failure that reads as a regression and is not
one: missing `ajv`, root filesystem exhaustion from unbounded incremental cache,
and the verifiers' in-worktree binary lookup that `CARGO_TARGET_DIR` does not
satisfy.

## Ops constraint in force

`CARGO_INCREMENTAL=0` for gate runs. Unbounded incremental cache reached 352G
and drove the root filesystem to 100%, failing the wallet fixture with exit 101
— a poisoned signal that reads as a code regression.
