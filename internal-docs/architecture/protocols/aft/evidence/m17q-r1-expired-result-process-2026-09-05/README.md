# Expired result RPC campaign — local validation passed

The first sole-correct fixture now has an upper fence 64 committed heights above
the setup height. Its first execution and immediate replay retain their existing
checks. At the end of the campaign, the harness waits beyond that fence and
requests the same effect again. It requires byte-identical receipt output,
portable_final_receipt=false, and a server result-height diagnostic strictly
above the manifest's upper fence. The deadline is part of the registered
manifest; there is no runtime expiry override or clock mutation.

The RPC result-only branch reports ioi-quv-result-height from the committed
admission snapshot used to prepare the result. The harness preserves metadata
for this assertion. This diagnostic is not signed receipt authority or permission
to invoke another effect. The expired_result row says result=recorded, not a new
execution. Mandatory evidence checking requires this row; its missing, unchanged-
receipt failure, unexpired-height and mislabelled-execution cases are rejected.

The CLI test target compiled. Checker self-tests passed (26 campaign negatives
and 23 overlap negatives, plus positive cases). The production run is active;
started.json binds source hashes, command and environment. Earlier process
results remain attached to their earlier source revisions. No complete R1,
M16Q R2 or release admission is established by this campaign alone.

The full Agentgres library suite passed on this revision: 109 tests, zero ignored.
agentgres-full.log and agentgres-full-check.json retain the complete result.
The production campaign remains in release build at this observation; all 27
recorded source hashes match. This is not a terminal process disposition.

Final disposition: the process test and mandatory evidence checker passed. The
expired result was returned unchanged at committed height 69 beyond expiry 65,
in 20 ms. All sole-correct placements and immediate replays passed, as did exact
workload member coverage (2170 ms maximum valid reply), bounded four-way overlap,
two typed conflict refusals with zero effects, and unrelated execution. All 27
recorded source hashes matched at completion. Earlier active observations above
are historical; this paragraph records the terminal result. Full R2 remains open.
