# QUV reply boundary diagnostics

These local diagnostics investigate the retained expiry-observation campaign's
late reply. They change no admission, deadline, durable-state or effect rule.
They cannot qualify a service envelope or make a late reply valid.

The existing `member_work_completed` event is emitted inside the blocking durable
worker. `member_work_returned` follows completion of its task on the async caller.
`reply_command_waiting` follows process completion and encoding, before acquiring
the context for a commander clone. `reply_command_sending` follows that lock.
`reply_command_sent` means admission to the command channel only, not durable
outbox admission or network delivery.

`reply_network_admitted` follows authenticated decoding and nonce/member lane
admission at the receiver, before its event-channel send. `reply_event_forwarded`
reports completion of that send. These network events use `nonce_bytes`, a debug
array of the exact 32 nonce bytes; runtime events use hexadecimal `nonce`.
`reply_handler_entered` precedes the verifier's context lock; `reply_routed`
follows that lock. The verifier still observes using its own monotonic clock.

Host timestamps only support local diagnostic ordering. Outbox serialization,
transport, event queues, context contention and scheduler delays must still be
isolated and bounded before timing admission. No new process result is claimed.

An initial compilation failed because networking does not depend on `hex`.
The events now log existing bytes directly without adding a dependency; the
failed log and initial hashes are retained separately.

Nine runtime tests, three QUV outbox tests and the authenticated routing test
passed. Formatting and diff checks passed. A new instrumented process campaign
is still required to collect the added boundaries; no timing repair is claimed.


### Instrumented reply-path process result (2026-09-05)

The campaign in `evidence/m17q-r1-reply-boundary-diagnostics-2026-09-05/process/`
terminated with exit 0 and unchanged recorded sources. The strict checker confirms
all four sole-correct placements, four saturation effects with 4153.826ms common
workload overlap, one conflict acceptance and one typed rejection with resource
non-mutation, unrelated-effect execution with exact participation, and unchanged
terminal receipt retrieval at admitted height 70 beyond expiry fence 65.
Seventeen preparation operations started; fourteen accepted completions across
all four workers match preceding reservations, own live-query audits and active
service checks. No completion is credited to the remaining starts.

The boundary analyzer reports 21 remote replies across 11 foreground operations
with all added remote stages present. Observed maxima include 1657.767ms between
async durable-work return and reply-command preparation (spanning the preparation
notification context lock and encoding), 287.859ms acquiring the command sender,
and 1350.235ms between verifier-handler entry and routing under the context lock.
Command-channel admission itself took at most 0.023ms in these samples. These are
host-clock observations, not worst-case bounds or isolated causal measurements.
They identify context contention as a concrete repair target, without establishing
the cause of the earlier uninstrumented late reply.

The strengthened expiry fixture now has a local process pass. Earlier expired-
result and missing-participation campaigns remain failed; this pass does not
retroactively explain or qualify them. Child readiness, aggregate timing/fairness,
restart/storage bounds, full refinement, whole R1 closure and clean R2 remain open.
