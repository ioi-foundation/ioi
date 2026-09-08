# Bounded push admission and reply draining


### Bounded PUSHQUERY admission worker (2026-09-05)

The event drain no longer awaits PUSHQUERY admission. It sends push events to
one admission worker through a finite channel and continues handling replies
through the separately locked operation table. The production channel capacity
is twice the protocol member cap, covering the capped old/successor union; there
is one active admission callback in addition to queued events. Existing transport
per-account admission and runtime per-account durable-work limits remain in force.
This introduces no unbounded per-event admission-task spawning.

Queue overflow is explicitly reported and attempts nonce-aware retirement of the
unadmitted transport lane through the reserved command sender. That retirement
can itself fail and is logged; overflow is never qualified progress. Unexpected
worker exit stops event routing and emits a distinct diagnostic. The mandatory
process checker rejects either overflow or worker-stop diagnostics, including
those unrelated to the saturation nonces. Shutdown closes the queue, cancels and
joins the admission worker. Existing already-spawned durable work follows its
previous lifecycle; shutdown does not count it as completed. No admission worker
is started when QUV policies are absent.

The actual driver regression blocks a push callback while requiring a subsequent
reply to be observed, verifies the exact finite queue overflow, and verifies
shutdown of the blocked worker. Restoring serial callback processing fails on
reply progress; increasing capacity fails the exact-overflow assertion. The
checker control removing admission-failure rejection also fails its self-test.
These are local scheduling/evidence controls, not cryptographic or process timing
qualification. Evidence: `evidence/m17q-r1-bounded-push-admission-2026-09-05/`.

Main-context admission and durable member service must still fit the rooted
complete-processing envelope. Independent draining prevents one dependency but
does not establish that bound, byte/rate/lifetime quotas, aggregate readiness or
fairness. A fresh process run, full refinement, whole R1 closure and clean R2
remain open. Earlier exact-source passes and failures retain their dispositions.

Final checks: 13 runtime tests passed; serial-admission and enlarged-capacity
controls failed at their intended assertions; restored driver passed. The
checker self-test has 2 positive/26 negative process cases and 1 positive/25
negative overlap/component cases. Removed admission-failure detection fails
that checker. CLI compilation, Rust formatting, shell syntax and diff checks
passed. These controls remain local evidence, not a complete production
mutation/refinement campaign or clean R2 admission.


### Bounded-admission process result (2026-09-05)

The recorded bounded-admission source passed the process campaign with exit 0
and unchanged selected hashes. Strict process and worker-service checkers passed,
including rejection checks for overflow and unexpected admission-worker exit.
All four sole-correct placements and four saturation effects executed; workload
overlap was 4373.699ms. One conflict candidate executed, the other received a
typed rejection with resource non-mutation; unrelated execution and unchanged
terminal replay beyond expiry (admitted height 66, fence 65) also passed.
Thirteen of sixteen preparation starts had accepted completions matched to their
own live queries and active-service diagnostics; other starts are not credited.

All 21 remote foreground replies had complete stage diagnostics. The largest
observed event-forwarding-to-handler-entry gap was 36.217ms. This is a shared-host
sample, not a causal improvement proof or a worst-case bound. Evidence is in
`evidence/m17q-r1-bounded-push-admission-2026-09-05/process/`.

Subsequent source inspection found that forced abort of the outer event task
could detach its admission worker. The validator has a two-second task shutdown
grace followed by abort, so this is an existing lifecycle boundary. A local
regression reproduced the detached blocked callback and is being repaired in
`evidence/m17q-r1-admission-worker-cancellation-2026-09-05/`. This process pass does
not cover that forced-abort boundary or qualify the subsequent repair. All whole
R1 findings, full restart/refinement, aggregate bounds and clean R2 remain open.
