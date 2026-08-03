# M5 event-substrate retained gate bytes

Produced by fresh detached processes in a DEDICATED DETACHED WORKTREE at the
exact commit under review — never from the shared checkout. A gate green in a
working tree can be green on uncommitted bytes; that is a defect class in this
program's ledger, and this directory exists so the claim cannot be made that
way.

- source commit: `f34ca84cb`
- worktree: detached, clean (0 dirty paths) at that commit

## Two dependencies supplied to the worktree, stated rather than left implicit

`node_modules` and `target/` are symlinked from the main checkout. That is
supplying build inputs, not measuring from the shared checkout: every source
byte under test is the worktree's own checkout of `f34ca84cb`, which is clean.
Both are stated because both caused environmental failures that could have been
misread as regressions:

1. The first detached run failed `ERR_MODULE_NOT_FOUND` — the M4 verifiers
   import `ajv` and the fresh worktree had no `node_modules`.
2. The second failed the wallet fixture build with exit 101. The cause was the
   ROOT FILESYSTEM AT 100% — the worktree's own `target/` had grown to 31G.
   Not a code regression.
3. The third failed `current_daemon_build_missing_binary`: the verifiers look
   for `target/debug/hypervisor-daemon` INSIDE the worktree, which
   `CARGO_TARGET_DIR` does not satisfy.

| file | gate | result |
|---|---|---|
| m5-genericity.log | M5 event-substrate genericity | 55/55 PASS (exit 0) |
| agentgres-tests.log | agentgres lib tests | 50/50 PASS (exit 0) |
| boundary-tests.log | injection boundary + stream homing | 2/2 PASS (exit 0) |
| m4-activation.log | M4 GoalRun activation plane | 44/44 PASS (exit 0) |
| m4-aggregate.log | M4 outcome-room system spine | 98/98 PASS (exit 0) |

All five gates completed at this commit from the detached worktree. The M4
aggregate finished after the prior handoff was written; it is reported here
only because it COMPLETED — the earlier note withholding it stood because an
interrupted run is not a result, not because the result was unwelcome.
