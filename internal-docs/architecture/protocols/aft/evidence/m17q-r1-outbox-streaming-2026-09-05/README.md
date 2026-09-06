# Outbox staging and serialization memory

Transaction staging now shares immutable entries via Arc. It copies an entry
index, not all pending payload bytes. The durable writer encodes through a
64 KiB buffer, without constructing a complete encoded-state Vec. A custom
SCALE output adapter retains the first I/O error instead of panicking, and
persistence returns it before snapshot replacement. Existing quarantine applies.

Twenty channel regressions passed on the production change. The subsequent
new regression separately passed: streamed bytes equal the old v2 encoding,
actual persisted bytes agree, staging shares payload storage, and an injected
writer failure returns the original error without continuing encoder writes.
Formatting and runner syntax passed. Source snapshots and exact commands/logs
are retained; this is selected dirty-worktree evidence, not clean R2.

The representation mapping erases Arc ownership and preserves the same ordered
entry values and SCALE bytes. Sharing is safe because production entries are
immutable. Temporary snapshot staging requires O(number of entries) pointer
storage plus a fixed encoder buffer, rather than another copy of all payloads.
Retained payload memory, front-message encoding/copy costs, aggregate bounds,
full-file recovery allocation and complete snapshot disk writes remain.
No physical allocation, incremental I/O or complete timing/refinement theorem
is established. All whole R1 findings and M16Q–M18Q gates remain open.
