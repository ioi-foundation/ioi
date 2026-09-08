# Finite QUV admission-order component evidence

The source-grounded abstraction starts when the single preparation worker has
joined the active semaphore queue. There is at most one queued foreground request
per enrolled domain, plus an optional active operation. Later foreground arrivals
append; cancellation removes only that foreground entry. Starting an operation
releases its waiting-domain capacity, as in `quv/admission.rs`.

For one and two domains, TLC checks type/uniqueness, at most D foreground starts
before the queued worker, and eventual worker admission assuming weak fairness
of active release and queue service. Positive state counts are 18 and 101. The
control removes FIFO choice and violates the predecessor bound with one domain:
a newly arrived request overtakes the worker after the first foreground start.
This is a finite component model, not an arbitrary-domain theorem, Rust transition
refinement, qualified time bound, or proof of head/effect progress. Cancelling the
worker or shutting down is outside this admitted-worker obligation.

The initial model omitted terminal stuttering and TLC reported a deadlock after
successful worker service. Its source, outputs, and result are retained under
`initial-terminal-deadlock/`. The corrected explicit terminal step passes both
positive configurations; the no-FIFO control fails the named invariant.

The canonical copies are in `formal/concurrency/`. The full formal runner and
M16Q now require the two positives and named control; focused reproduction is:

```sh
bash .github/scripts/run_aft_formal_checks.sh --quv-admission-order-only
```

That focused run passed. Existing production regression
`admission_serializes_and_preserves_queued_worker_order` exercises the real FIFO
semaphore and per-domain waiting limit. This turn did not change runtime source
or rerun its already-passing tests. The model does not prove that the executable
implements all abstract transitions.

Even an arbitrary-D ordering proof would not establish QueueBound: actual active
release, wake-to-service scheduling, context/store acquisition, candidate selection,
rotation, crash/restart and refusal handling still need bounded implementations
and qualification. Rooted operation budgets are rejection/measurement rules;
they cannot force an already-running durable write to release on time. All whole
R1 findings, aggregate readiness/resource qualification, clean R2 and fresh review
remain open. No authorization or synchrony premise changes.
