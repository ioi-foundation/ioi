# R1 local remediation evidence — 2026-09-04

Status: **IN PROGRESS; not M16Q qualification or finding closure**.

Base commit: `24a9888e3b88383c18dfbfea0f2e7fa44b99fa64`, with pre-existing
uncommitted repairs preserved. The exact local QUV source hash, command,
toolchain, timestamps, result, and log hash are in `quv-core-result.json`.

## Timing boundary — QUV-M17Q-003

Reply admission now discards post-deadline observations before retention.
Finalization retains its independent cutoff check. Full monotonic precision
is used, including the equal-deadline case; audit encoding in milliseconds
cannot enlarge the live interval. Focused tests cover one nanosecond before,
exactly at, and one nanosecond after cutoff, delayed finalization, and the
production observation method's operation clock. The retained core run passed
16 tests, with one explicitly ignored performance benchmark.

This is deterministic local unit evidence. The clock test moves the private
start instant; it does not substitute for a delayed-process qualification run.
Production mutations, formal operational refinement, clean R2 qualification,
and independent review remain required. Finding 003 remains open.

## Claim boundary — QUV-M17Q-008, 009, 013

Both production executor entry points now re-derive authorization from current
committed admission after the live QUV wait and hold the runtime-finality guard
through the synchronous claim/call. Receipt matching is reapplied through
`authorize`; the token remains the executor's live process-local continuation.
The consequence store carries its consumed binding, height, and deadline to
the final receipt load, checks that binding and fence again, computes the claim
root before the immediate deadline check, and refuses an expired continuation
on a resumed Claimed-to-InFlight path as well.

The longer finality critical section includes durable I/O and the external
resource call. Its latency, lock ordering, and impact on ordering/QUV scheduling
must be measured in R2; this implementation fact does not establish Q-A3/Q-A9.
The retained unit test exercises the store's Claimed restart boundary directly
with test-only continuations and requires typed expiry failures plus zero
resource invocations/mutations. Production admission for a Claimed retry and
fresh network reauthorization remain separate unfinished gates.

Validation: all 17 consequence library tests passed; validator compilation
passed with default features and with `consensus-aft`. `local-checks.json`
records those exact commands, source hashes, and log hashes. The QUV core recheck after the consequence changes also passed 16 tests
with one ignored benchmark (`quv-core-after-claim-changes.log`). Formatting, diff whitespace, theorem-Assumes, and
claim-discipline checks pass. No critical/high finding is closed; no candidate
is frozen or admitted by this local evidence.
