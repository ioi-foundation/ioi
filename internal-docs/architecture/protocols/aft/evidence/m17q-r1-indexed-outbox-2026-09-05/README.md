# Indexed PQ outbox production repair

Production persistence now uses an ordered `AFTPQI03` queue index and immutable
entry files. Logical scope/entry schema remains v2; PQ wire bytes are unchanged.
A commit writes only newly retained payload files, then atomically replaces the
index, then removes retired files. Other payload inodes and modification times
remain unchanged. Uncertain writes still quarantine the manager. The ordered
index, not directory contents, determines the recovered pending queue.

Recovery validates the complete rooted index and every referenced commitment
before garbage collection. A corrupt referenced entry prevents cleanup. Orphans
from interrupted staging cannot add messages or revive retired requests. Valid
legacy snapshots are converted during startup, before live admission; a crash
before index replacement retains the old snapshot, and a crash after replacement
retains the new queue. The legacy converter is specific to transport persistence,
not member conflict custody. New directories sync their complete ancestry before
staging files; a required syscall-order checker includes a removed-sync control.

Final scoped checks passed: 27 channel tests, 21 runtime tests, CLI compilation,
swarm admission, 9 TLAPS obligations, a 79-state positive model and two required
ordering mutations. The model includes partial payload staging and orphan cleanup.
The new tests exercise interrupted conversion, both commit boundaries, corruption
before cleanup, and preservation of unrelated payload files. The initial run
failed because indexed recovery still dispatched to the v2 decoder and a format
fixture asserted v2 bytes for the new index. The dispatcher was repaired and the
v2 golden test explicitly writes its legacy fixture; its byte assertions remain.
Initial failures and successive results are retained, not qualified as passing.

Source copies/hashes, raw commands, logs and tool versions are retained. This is
a selected dirty-worktree snapshot, not a clean immutable checkout or full M16Q.
No fresh independent review, process qualification, performance claim or M18Q
admission is inferred from these checks.

The abstract proof assumes atomic durable index replacement and correct file
semantics; it does not establish physical power-loss behavior or complete Rust
refinement. The trace proves issued syscall ordering only. Message commitments
are hashes, not custody MACs, and neither index nor queued bytes authorize effects.

Remaining costs include O(pending entries) index work, one-record encoding buffers,
linear recovery/conversion, physical blocks/inodes/directory growth, concurrent
transport/consequence storage, rooted rate/service limits and aggregate reserved
capacity. File deletion need not shrink directory allocation. All 13 whole R1
findings remain open; this backend change is an intermediate production repair.
