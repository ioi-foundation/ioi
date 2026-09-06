# PQ durable admission plaintext boundary

The outbox now applies the existing record layer's 16 MiB encoded plaintext
limit before message hashing, state cloning or durable insertion. Recovery uses
the same validation. The wire limit is unchanged; no new quota refusal affects
a payload the record layer could previously send.

The defensive regression persists and reopens an exactly fitting payload,
refuses a one-byte oversized payload without file/state mutation, and refuses
an oversized recovery fixture without changing it. Twenty channel tests, six
record-layer tests, the final boundary regression, formatting and runner syntax
passed. Exact commands, selected source hashes/copies and raw logs are retained.
This is scoped dirty-worktree evidence, not clean M16Q R2.

The inductive obligation is that empty initialization, validated insertion and
removal-only transitions preserve sendable retained entries; recovery checks
every entry before exposing the outbox. Full production refinement remains open.
This does not bound aggregate outbox bytes, pre-decode allocation, full-snapshot
rewrite cost, physical allocation or fair service. Existing per-recipient count
limits are not an aggregate physical resource profile. All whole R1 findings,
R2, fresh independent review and M18Q admission remain open.
