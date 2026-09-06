# Scoped committed-manifest locator repair

15 runtime-finality, 21 QUV runtime and 2 executor tests passed; CLI, format,
runner syntax and the new conditional locator proof/model gate passed. The
proof has 10 discharged obligations and the model 35 distinct states. Required
duplicate-overwrite and premature-recovery countermodels fail their invariants.
Production identity/duplicate/recovery omission controls each fail the intended
regression (exit 101), and exact selected sources are restored and hash-verified.

The regression checks one selected-block read per valid lookup, no reads for
absent/duplicate IDs, wrong committed locators, changed selected blocks and
duplicate preservation on reopen. Source authorities are rederived on lookup.
The initial formal census failure is retained; both modules and their gates
are now included in the default full harness and M16Q artifact list.

Run run_checks.py for the scoped checks; run_mutations.py temporarily removes
local defensive rules and restores the exact source in finally. No concurrent
source writers may run. This is dirty-worktree selected-source evidence, not
a clean immutable qualification. Startup/history and index memory, global
resource/service/retention and complete transition refinement remain open.
All 13 whole findings remain OPEN; no R2/review/M18Q admission follows.
