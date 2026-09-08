# Outbox persistence-error quarantine — local validation passed

All existing durable outbox transitions now share a commit boundary. If staging,
write, sync, rename, or parent-directory sync returns an error, the current
outbox instance refuses further enqueue, ACK, and retirement operations, and
supplies no front entry or recipient list. Reopening reads and validates disk
state before allowing further work. This prevents a stale in-memory snapshot
from overwriting an uncertain publication outcome. Already cached network
transmissions are not recalled by this local storage guard.

The regression exercises a real staging-file error and an injected error after
the real writer publishes a replacement. Both must refuse retries even after
the immediate error condition clears. Disk bytes remain unchanged until reopen;
reopen observes the appropriate old/new state and supports enqueue/ACK again.
The post-publication test is fault injection, not a reproduced power-loss or
failed-fsync event. Full power-loss/restart scheduling remains unqualified.

This is conservative refusal after storage failure, not effect liveness. It
adds no automatic downgrade or portable authorization. It does not establish
rooted storage quotas, incremental WAL behavior, rollback resistance, or sustained
silent-recipient timing. Finding 011 and all other open R1 findings remain open.
The mandatory runner's existing pq_channel test filter includes this regression.

Validation: the targeted regression passed, followed by all 22 networking
library tests (zero ignored). `networking.log` and `networking-check.json` retain
the complete suite result. Source/lock hashes, rustc version, formatting, diff,
claim-discipline and theorem-Assumes checks are retained beside it. This dirty-
checkout local result does not replace clean full M16Q R2 qualification.
