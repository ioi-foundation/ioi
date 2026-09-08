# Separately locked live QUV operations


### Separately locked verifier-operation table (2026-09-05)

The QUV event loop captures the live-operation table once. Reply handling now
acquires that table directly, without acquiring the main orchestration context.
Startup and dispatch reuse its captured handle. Abort and finalization remove
entries from the same table; operation permits remain owned through their prior
completion boundaries. Table guards are released before invoking abort, and the
reply path never acquires the main context while holding a table guard. Existing
rooted revalidation at startup/finalization and monotonic observation/deadline
checks remain in force. Keeping an entry until a delayed finalizer runs cannot
extend the rooted reply interval.

Twelve runtime tests passed. The added regression drives the actual reply handler
through a captured table while its handle owner's lock is held, checks exact
transport identity, sends a stale nonce before the correct reply, and verifies
that an event after removal cannot recreate an operation. Its fixture signature
verifier and explicit finish time test routing only, not PQ security or real-time
authorization. Removing transport binding or using an arbitrary table entry
instead of exact nonce lookup fails the intended assertions; restored source
passes. The M16Q runner requires this regression.

Evidence: `evidence/m17q-r1-verifier-operation-table-2026-09-05/`. A new process
measurement is required for this source. A preceding PUSHQUERY admission can
still wait for the main context inside the event loop; entry/dispatch/finalization
scheduling and aggregate readiness are not bounded by this change. Full process
contention controls, restart/storage qualification, refinement, whole R1 closure
and clean R2 remain open. The earlier process pass remains historical evidence.

CLI compilation, Rust formatting, runner syntax and diff checks also passed.
Final source hashes and raw regression/control logs are retained.


### Captured-handle/table process result (2026-09-05)

The revised-source campaign terminated with exit 0 and unchanged recorded
sources. Strict evidence checks confirm all four sole-correct placements, four
saturation effects with 4868.970ms common workload overlap, one accepted conflict
candidate and one typed rejection with resource non-mutation, and unrelated-effect
execution with exact participation. Expired-result retrieval first observed
unchanged nonportable bytes at admitted height 65 (equal to the fence), then
succeeded only at height 66. This exercises the fixture's pending-equality path.
Sixteen accepted preparation completions across all four workers are matched to
preceding reservations, own live queries and active service diagnostics; eighteen
started and the other two starts are not credited as completions.

All 21 remote foreground replies have the added boundary diagnostics. Observed
maxima were 0.029ms from durable-work return to reply-command preparation,
0.011ms between reply-command preparation/sending, and 0.020ms from verifier
handler entry to routing. These are small in this sample after removing the
corresponding main-context accesses, not a causal or worst-case timing proof.
The largest remaining observed event-forwarding-to-handler gap was 998.006ms.
PUSHQUERY admission in the shared QUV event loop still needs main-context access;
the remaining queue delay must be isolated and bounded, not hidden by this pass.

Evidence: `evidence/m17q-r1-verifier-operation-table-2026-09-05/process/`.
Earlier failed campaigns remain failed. Aggregate readiness/fairness, process
contention controls, restart/storage bounds, full refinement, whole R1 closure
and clean R2 remain open. The measured stages and previous failures do not
establish a counterexample under the fixed complete-timely-processing premise.
