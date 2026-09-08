# Final shared admission release


### Shared admission lifetime and final release observation (2026-09-05)

The startup/dispatch future now retains an admission share independently of the
pending-operation table. Deadline removal of pending state cannot open the lane
while that future is still waiting. Its share is released on return or cancellation;
blocking reservation/head-commit closures retain their existing independent shares.
The final shared QuvActiveAdmissionV0 owner releases the actual semaphore before
sampling the release time. This separate operation_admission_released diagnostic
records whether release was strictly before the rooted active deadline; equality
or lateness emits operation_service_expired. Elapsed microseconds are recorded
without narrowing the integer. The earlier operation_finished sample remains a
finalizer/outcome check, not a claim that all admission shares have disappeared.

All 18 runtime tests pass on final source. The new regressions cover pending removal
while dispatch waits, both normal completion and cancellation, actual semaphore
availability at clock observation, and before/equal/after release deadlines.
Removing startup retention, observing before semaphore release, or admitting release
at deadline equality makes its regression fail; restored source passes. The CLI
aft_e2e target compiled before the final private predicate extraction; final runtime
compilation/tests cover that extraction. Exact commands and hashes are retained in
`evidence/m17q-r1-final-admission-release-2026-09-05/`.

Process gates require successful release diagnostics for selected operations and a
matching final release for every recorded completed operation, including unrelated
nonces. They reject late/unbudgeted release, duplicate records and missing releases.
Workload overlap remains capped by the decision interval; delayed release does not
inflate overlap. Main checker self-tests pass 2 positive/26 negative process and
1 positive/38 negative component cases; handoff passes 1 positive/30 negative cases.
Removing either all-completions release gate makes its self-test fail.

This repairs local ownership and conservative release observation. A delayed clock
sample after actual release can produce a conservative overrun; it cannot certify
late actual release as timely. Crashes without a completed/released record are not
qualified by that match. Selection, scheduler resumption, fair queueing, actual
storage completion and restart still need aggregate bounds/refinement. The prior
v3 process pass is historical for its recorded source. Current-source process
qualification, clean R2 and all whole R1 findings remain open. No audit diagnostic
or timeout independently authorizes another executor or constitutes progress.


### Final-release foreground process evidence (2026-09-05)

The unchanged-source foreground campaign passed the process test and all three
evidence gates. All four sole-correct placements, four saturation operations,
one conflict acceptance with one typed rejection/non-mutation, unrelated execution,
and unchanged terminal-result retrieval at height 70 beyond expiry 65 passed.
Four-way workload overlap was 3777.211ms. Worker diagnostics matched 18 starts
and 15 accepted completions. Every one of the 26 recorded completed operations
had a matching successful final admission release; 32 release records were retained
in total, including releases without a completed-operation record.

The largest observed active release duration was 7,142,340 microseconds
(preparation); the foreground maximum was 6,818,118 microseconds. These are runtime
monotonic observations sampled after final semaphore release, not a worst-case
service bound or aggregate queue/readiness proof. Raw component logs, release rows,
source/checker hashes and terminal dispositions are retained under
`evidence/m17q-r1-final-admission-release-2026-09-05/foreground-process/`.

This validates selected foreground assertions and release-record completeness on
the recorded repair source. Handoff/restart qualification of the current root and
lifetime changes, full refinement/resource bounds, clean R2 and closure of all
whole R1 findings remain open. Earlier failures remain retained and unexplained.

`analyze_admission_releases.py` reproduces the retained foreground release measurements from hashed component logs. Its 1 positive and 8 negative self-tests pass; the reproduced counts/maxima match the initial retained summary. This analyzer does not qualify a worst-case bound.


### Failed disjoint campaign after final-release repair (2026-09-05)

The current-source disjoint campaign failed (exit 101, no recorded source changes):
successor node 4 did not observe required post-QUV height 5. The mandatory handoff
evidence checker rejected the failed campaign. The separate release analyzer passed;
that component result is not a handoff/progress pass. Four successor live-acceptance
audit records match the expected old root/domain/member set, but post-install
progress remains required. Validator-20400's retained consensus progress records
end after beginning a height-3 proposal; other successor logs contain later admitted
height diagnostics. The exact stalled boundary is not yet isolated, and public
status values must not be conflated with those internal diagnostic heights.

Raw logs, failed terminal result, rejected checker result and partial source-bound
analysis remain under `evidence/m17q-r1-final-admission-release-2026-09-05/disjoint-process/`.
No assertion is relaxed, no retry is substituted for this failure, and no freeze or
refusal is counted as progress. Post-install production/finality boundaries require
investigation before requalification. Overlapping-handoff qualification of this
repair is still outstanding. All whole R1 findings and clean R2 remain open.
