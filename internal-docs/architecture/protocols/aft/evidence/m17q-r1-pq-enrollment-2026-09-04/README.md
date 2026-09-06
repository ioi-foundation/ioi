# R1 PQ carrier enrollment validation — 2026-09-04

Status: local repair; **findings 007, 011, and 012 remain OPEN**.

Unproven discovery metadata now has an explicit four-per-account / 4096-total
capacity limit and a 30-second monotonic admission lifetime. Refreshes do not
extend the original lifetime. Expiry removes provisional enrollment,
capability, pending handshake, and ephemeral session state. The swarm cleans
up expired/evicted carriers' ephemeral retry handles on its periodic tick;
protected durable outbox records are not deleted by this cleanup.

Successful application-ready authentication removes the provisional timestamp
and evicts other account aliases. Identical authenticated refreshes remain
idempotent; identity/capability changes to an authenticated enrollment require
explicit configuration/manager replacement. Account-addressed outbox routing
requires an application-ready authenticated carrier.

## Evidence

`initial-tests.log` retains the first run: 15 pass, two failures. Its fixtures
expected routing immediately after unproven discovery and retained unproven
enrollment after disconnect. Those expectations conflicted with the existing
R1 fail-closed discovery repair. The fixtures now retain their restart and
stale-response assertions while requiring renewed enrollment and a complete
cryptographic handshake before routing. The following full networking run,
`networking-tests.log`, passed 20 tests.

A final global-capacity test was then added. `final-command.json`,
`final-result.json`, and `final-networking-tests.log` record the final run,
with exact dirty-tree source hashes, command, toolchain, times, and log hash.
The final run passed all 21 networking tests, with none ignored or filtered.
The global bound test holds private test timestamps in the future to isolate
capacity from wall-clock expiry on slow hosts; a separate expiry test sets
one timestamp to the cutoff and checks rejection, cleanup, and fresh enrollment.

Coverage includes per-account and global bounds, non-extending refresh,
pending-key removal, subsequent fresh enrollment, retained authenticated
carriers, unproven alias eviction, rejection of authenticated metadata changes,
real handshake/AEAD routing, stale server responses, outbox restart, reserved
QUV queue capacity, nonce-specific push retirement, reply replacement, and
cross-configuration refusal. All are local library tests.

## Remaining obligations

The caps are local implementation limits, not rooted fair admission quotas or
proof of Q-A3/Q-A9. Provisional capacity exhaustion can refuse a legitimate
new carrier; repeated attempts and expiry races still need a qualified
admission/timing envelope. The nominal 500 ms maintenance interval does not
prove scheduling timeliness. These unit tests do not establish process-level
flood, silent-recipient, nonce/reply-lane, disconnect, crash, or restart
qualification. Existing transport fixes still require those campaigns,
transition-level refinement, clean full R2, and exact-candidate independent
review. No finding is closed and no release claim is admitted here.
