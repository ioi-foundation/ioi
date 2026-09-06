# Durable admission ownership


### Durable operation admission ownership on cancellation (2026-09-05)

The runtime now shares the operation's active admission permit with its blocking
preparation-reservation and accepted-head-commit closures. Cancelling or timing
out the async waiter cannot release admission while either already-started
closure still runs. The blocking share is released when that closure returns or
unwinds. The pending operation/finalizer retains its own share through normal
cleanup. This changes local scheduling ownership; it adds no new authorization
source and does not cancel, roll back or duplicate durable work.

All 15 QUV runtime tests passed. The new named regression blocks durable work,
cancels its async owner, requires the next foreground admission to remain pending,
then releases the work and requires admission to recover. Removing the closure's
permit retention makes that pending assertion fail; restored source passes.
Both production blocking boundaries use this checked helper. The M16Q runtime
phase now requires this exact test. Raw results and hashes are retained under
`evidence/m17q-r1-durable-admission-ownership-2026-09-05/`.

The store mutex already serialized writes, but that did not retain operation
admission after waiter cancellation. This repair closes that ownership gap, not
the elapsed-service bound: stalled blocking work correctly retains admission and
can still prevent progress. Rooted timing qualification must include actual
storage completion; a timeout/refusal cannot substitute for it. The repair does
not cover unrelated inbound member work or prove full storage/restart refinement.
Earlier process passes remain historical for their exact source hashes. Affected
process campaigns, full R2 and all whole R1 findings remain open.


### Durable-admission repair foreground qualification (2026-09-05)

The post-repair foreground campaign terminated with exit 0 and no recorded source
changes. The strict checker confirms all four sole-correct placements, four
concurrent saturation operations, one conflict acceptance and one typed rejection
with non-mutation, unrelated effect execution, and unchanged terminal-result
retrieval at committed height 67 beyond expiry height 65. Four-way workload
overlap was 4974.655ms. Worker diagnostics matched 17 starts and 13 accepted
completions across all four workers; no scheduling/service-failure markers were
found. All three retained evidence checks passed. The reply-stage analyzer found
21 remote replies with no missing stages; host timestamps are observations,
not a proof of worst-case latency or authority.

Evidence: `evidence/m17q-r1-durable-admission-ownership-2026-09-05/foreground-process/`;
`check_foreground.py` rechecks only a terminal retained run and never launches
another campaign. This qualifies the selected foreground assertions for the
recorded repair source. It does not qualify handoff/restart after this repair,
derive aggregate queue/readiness bounds, explain earlier failures, provide full
transition refinement, complete R2, or close any whole R1 finding.
