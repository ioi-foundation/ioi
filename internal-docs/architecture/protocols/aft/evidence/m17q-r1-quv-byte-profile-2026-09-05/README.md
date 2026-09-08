# Rooted QUV outbox byte profile

The v5-outbox-budget policy root commits normal count/byte capacity and QUV
count/frame/byte capacity. Each declared recipient has at most 1,024 normal
entries with 16 MiB aggregate encoded payloads, plus one QUV request and one
reply, each at most 16 KiB. Normal backlog cannot spend the separate 32 KiB
QUV payload budget. Live preflight and both recovery formats check class bytes
and lane uniqueness; recovery does so incrementally before retaining each entry.
Over-budget retained state refuses before cleanup/conversion and remains intact.

The record layer enforces the OnlineAuthorization frame cap on seal/open without
consuming sequence state on refusal. Normal record types keep their old wire
limit. Synthetic worst-case representation fixtures occupy 4,131 request bytes
and 10,915 two-candidate reply bytes under the candidate/ML-DSA-44 width bounds;
these fixtures are not valid signatures or live acceptance evidence.

The coherent selected-source run passed without source drift: 70 QUV core tests
(one benchmark ignored), 29 channel tests, 21 runtime tests, CLI compilation,
formatting, runner syntax and the formal reserve gate. A separate final-source
record-layer run passed seven tests. Seventeen TLAPS obligations prove the
abstract byte/lane bounds; the 12-state positive model passes and the shared-
budget mutation violates EmptyLaneHasCapacity. The initial build failed missing
public-constant documentation; the initial proof omitted explicit use of its
existing Profile facts. Both failures and the original proof are retained.

Raw logs, commands, selected source copies/hashes and tool versions are retained.
Narrative docs are excluded from that source set. This is a dirty-worktree source
subset, not immutable full M16Q R2. Earlier v4 process/benchmark evidence does
not qualify the new root or limits. No policy/custody reset or mixed-profile
migration is admitted.

The bound N*(16 MiB+32 KiB) concerns encoded pending payloads. Physical blocks,
inodes/directory growth, entry/index metadata, allocator overhead, temporary
records, migration copies and incoming/active work are additional obligations.
Logical capacity is not physical preallocation. The proof does not establish
actual service timing, the complete runtime bridge, correct-member participation
under full resource pressure, or externalization. All 13 whole R1 findings,
clean R2, fresh independent review and M18Q admission remain open.
