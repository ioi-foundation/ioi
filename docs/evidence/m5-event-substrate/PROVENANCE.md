# M5 event-substrate retained gate bytes

Produced by fresh detached processes in a DEDICATED DETACHED WORKTREE at the
exact commit under review — never from the shared checkout. A gate green in a
working tree can be green on uncommitted bytes; that is a defect class in this
program's ledger, and this directory exists so the claim cannot be made that
way.

- source commit: `348503942`
- worktree: detached at that commit, with one untracked path — the supplied
  `target` symlink. Stated rather than claimed pristine: `.gitignore` has
  `target/`, which matches a directory and not a symlink, so git reports it.
  No source byte differs from the commit.

## Results

| file | gate | result |
|---|---|---|
| m4-aggregate.log | M4 outcome-room system spine | 98/98 PASS (exit 0) |
| m4-activation.log | M4 GoalRun activation plane | 44/44 PASS (exit 0) |
| m5-genericity.log | M5 event-substrate genericity | 60/60 PASS (exit 0) |
| agentgres-tests.log | agentgres lib tests | 50/50 PASS (exit 0) |
| boundary-tests.log | injection boundary + stream homing | 2/2 PASS (exit 0) |
| m0.log | M0 supplied-snapshot check | 1603 entries, exit verified |

## Supplied build inputs, and why they are named

`node_modules` and `target` are symlinked from the main checkout. That supplies
build inputs; it does not move the measurement surface, because every source
byte under test is the worktree's own checkout. Both are named because both
produced failures that would otherwise read as regressions:

1. `ERR_MODULE_NOT_FOUND` — the M4 verifiers and the M0 checker import `ajv`,
   absent from a fresh worktree.
2. Wallet fixture exit 101 — the ROOT FILESYSTEM AT 100%. Not a code fault. The
   accumulated `target/debug/incremental` had reached 352G and was cleared.
3. `current_daemon_build_missing_binary` — the verifiers look for
   `target/debug/hypervisor-daemon` INSIDE the worktree, which
   `CARGO_TARGET_DIR` does not satisfy.

## Hydration

`check-estate` and `check-claims-coverage` run green from a fresh detached
worktree with NO generator run and NO symlinks — proven after the fix that
tracked `NOW.md` and `program-state.v1.json`, which were ignored while every
other generated artifact beside them was tracked. M0's checker still requires
`node_modules` for `ajv`, which is a dependency rather than a hydration gap.
