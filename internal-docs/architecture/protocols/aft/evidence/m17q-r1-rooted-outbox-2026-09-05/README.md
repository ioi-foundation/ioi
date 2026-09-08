# Rooted outbox recipient scope

Production channel configuration now supplies the complete old/staged account
set from validated membership before peer discovery. The runtime rotation
factory derives it from the replacement set; initial QUV startup includes the
staged successor. The channel manager requires its own account in that set.
Outbox enqueue and peer enrollment refuse undeclared accounts. Recovery checks
scope membership before payload decoding, caps the entry count at N*1026 for
N declared accounts, and enforces per-recipient counts while streaming.

The new regression queues a declared recipient before discovery, refuses an
undeclared enqueue/enrollment without mutation, refuses recovery under a
narrowed account set, and reopens under the original declaration. The existing
provisional-capacity test initially failed because its synthetic accounts had
not been declared. The fixture now declares that generic-PQ account universe
before admission; its capacity assertions remain unchanged. Failure logs are
retained. Final checks passed: 24 channel tests, 21 runtime tests, swarm admission,
CLI compilation, formatting and runner syntax. Exact commands and selected
source copies/hashes are retained. No immutable checkout or complete R2 claimed.

The declared set is supplied by the existing trusted local membership-validation
boundary; it is not learned from carrier claims, and does not identify an honest
member or create authorization. Candidate and endpoint capability checks remain
required. The on-disk v2 schema is unchanged; narrowing the set cannot erase
retained entries to bypass refusal. Reconfiguration/retirement must preserve its
separate authority and recovery obligations.

Inductive obligation: empty state, rooted insertion and removal-only transitions
preserve recipient membership and per-recipient count; recovery rechecks these.
The finite count is not a physical byte reservation. N*1026 entries at the wire
maximum can still be very large. Rooted byte/rate/service reservations, incremental
persistence, safe retention and full refinement remain open. All 13 whole R1
findings and M16Q–M18Q admission gates remain open.
