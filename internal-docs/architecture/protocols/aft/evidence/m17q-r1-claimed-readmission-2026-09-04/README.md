# R1 Claimed readmission — 2026-09-04

Status: local validation passed; findings 009/010/013 remain OPEN.

Both production executors call `ConsequenceStore::authorize` before starting
QUV and again after receiving the live continuation. That API previously
refused every online receipt after `Authorized`, preventing a durable `Claimed`
retry even though the execution boundary supported it.

Readmission now permits `Authorized` or `Claimed` only with exact manifest and
guarantee roots and an initial authorization trace commitment matching the
currently derived admission. It writes no receipt. The public binding API also
permits `Claimed`; the returned requirement carries no authority. Execution
still requires a fresh process-local continuation, current fence checks, and
matching live binding. InFlight and later phases remain refused by this path.

## Evidence

`check.json` retains the dirty-tree base, source/lockfile hashes, command, times,
exit code, and log hash. All 17 consequence tests passed. The restarted Claimed
regression now exercises the public admission and requirement methods. It
requires exact ReplayConflict on changed admission, unchanged durable bytes,
OnlineAuthorizationRequired without a continuation, zero calls/mutations on
expired height or continuation, and one call/mutation for a valid retry.

The earlier test's private binding helper bypassed the public admission gap.
The revised positive regression would fail with the former unconditional
Claimed refusal. The changed-admission negative assertion guards the new
load-bearing trace comparison.

## Remaining scope

This is local API/restart evidence, not a killed-process network retry campaign
or runtime transition refinement. Both production entry points must still be
qualified with fresh live member participation, current admission/height races,
continuation expiry across durable flush, and ambiguous-call reconciliation.
No terminal replay fairness or domain-head progression claim follows. The
existing critical-section latency cost remains unqualified. Clean R2 and fresh
review of an immutable candidate are required before admission.
`portable_final_receipt=false` remains fixed.
