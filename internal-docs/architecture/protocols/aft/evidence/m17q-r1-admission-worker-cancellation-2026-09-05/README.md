# Admission-worker cancellation ownership


### Admission worker ownership across forced abort (2026-09-05)

The new forced-abort test failed against the prior scheduler: the outer event
Task ended, but its blocked admission callback remained alive. The validator's
existing two-second shutdown grace explicitly permits aborting that outer task.
An owned abort-handle guard now requests worker cancellation when the event-drain
future is dropped or unwinds. Normal shutdown still cancels and joins the worker;
non-cancellation join errors encountered during cleanup emit the existing worker-
failure diagnostic rejected by the process gate.

Fourteen runtime tests passed, including normal blocked-worker shutdown and the
new forced outer-task abort. Removing the guard reproduces the callback-lifetime
timeout; restored source passes. The runner requires the new named regression.
Evidence: `evidence/m17q-r1-admission-worker-cancellation-2026-09-05/`.

Cancellation takes effect when the async task can be cancelled; it is not forced
preemption of synchronous code. It covers the admission callback, not already
spawned durable member work, atomic storage writes or external effects. Those
retain their existing semantics and still require complete restart/refinement
qualification. The preceding process pass is historical for its recorded source;
no process run of this repair or whole R1 closure/clean R2 is claimed.

CLI compilation, Rust formatting, runner syntax, strict-checker self-tests and
diff checks passed. Final source hashes and raw results are retained.


### Current scheduler reconfiguration checks (2026-09-05)

Both disjoint and overlapping handoff/recovery campaigns passed with exit 0 and
unchanged selected sources during each run. Each checker confirms four successor
executors with their own live acceptance and exactly all four expected old-member
replies. The largest valid-reply observations were 939ms (disjoint) and 911ms
(overlap), within each fixture's declared envelope. The strengthened checkers
found no admission overflow, unexpected admission-worker stop or preparation-
service-expiry marker. The disjoint run finished before checker strengthening;
its initial and stronger recheck hashes are retained separately. Runtime source
was not changed by that recheck.

The overlapping fixture kills and restarts the common old/successor member,
requires the local install-gate recovery diagnostic and a publicly retrievable
block two heights beyond its pre-restart tip, then requires a signer-role refusal
diagnostic from a restarted retired member. These assertions passed. They are specific restart/role checks, not full
restart scheduling, storage rollback resistance or transition refinement.
Raw evidence is in `evidence/m17q-r1-admission-worker-cancellation-2026-09-05/`.

These current-runtime results cover the scheduler and ownership changes on the
handoff path. They do not retroactively explain earlier failures, qualify the
latest foreground/saturation campaign, establish worst-case timing or close any
whole R1 finding. Full mutation/refinement, aggregate bounds and clean R2 remain
open. No theorem assumption or non-portability boundary changes.


### Current scheduler foreground campaign (2026-09-05)

The foreground process campaign after the cancellation-ownership repair passed
(exit 0, unchanged selected sources). The strengthened checker confirms all four
sole-correct placements, all four concurrent saturation operations, one conflict
acceptance with one typed rejection and non-mutation, unrelated effect execution,
and unchanged terminal-result retrieval beyond the committed expiry fence
(observed height 66 > 65). Four-way workload overlap was 4674.706ms. Worker checks
matched 16 independent preparation starts and 12 accepted completions across all
four workers, with no scheduling/service-failure markers. Refusals are not progress.

Raw logs, exact source/command hashes and checker results are retained under
`evidence/m17q-r1-admission-worker-cancellation-2026-09-05/foreground-process/`.
This supersedes the earlier pending foreground status only. Previous failed runs
remain unexplained and retained. These selected assertions do not establish
worst-case timing, aggregate readiness, full transition/restart/storage refinement,
clean R2, or closure of any whole R1 finding. No theorem assumption changes.
