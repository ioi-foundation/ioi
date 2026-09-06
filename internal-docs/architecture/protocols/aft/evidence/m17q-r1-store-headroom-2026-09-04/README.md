# R1 store headroom repair — 2026-09-04

Status: local repair validated; **finding 006 remains OPEN**.

The absolute 512 MiB encoded-store ceiling now applies on write as well as
read. The atomic writer checks it before creating/truncating a staged file.
Member insertion projects exact SCALE growth, including compact map/vector
length prefixes, before cloning the next complete state or computing its MAC.
The resulting state receives a second exact-size check. Handoff installation
also checks the next encoded state before authenticating and persisting it.
An oversized update returns typed `StoreCapacityExceeded`, preserving the
prior durable state/anchor and in-memory generation/head.

## Validation scope

`command.json` records the local test command, dirty-tree base, exact source
and lockfile hashes, toolchain, and live session used to capture the result.
The run passed 21 tests with one explicitly ignored performance benchmark.
`result.json` and `quv-core.log` retain the outcome and log hash.

The tests exercise:

- one-byte-short refusal with unchanged state, anchor, head, generation, and
  absent temporary file;
- exact-fit successful insertion, duplicate reply at capacity without a new
  generation, rejection of further growth, and successful reopen;
- projected-versus-actual SCALE sizes across map lengths 63/64 and
  16383/16384, and candidate-vector lengths 63/64;
- atomic-writer oversize refusal preserving both an existing destination and
  pre-existing temporary file, then an exact-fit durable write.

Small limits in private test entry points exercise the same production guard
without allocating a 512 MiB fixture. This is not a full-capacity performance
campaign. Existing per-slot and map entry count limits still apply separately.

## Remaining obligations

This absolute ceiling is not a rooted per-domain quota or a fair admission
mechanism. Computing current encoded size still traverses retained state;
cloning, MAC calculation, and rewriting remain whole-store operations. No
incremental authenticated WAL, compaction, bounded authority lifetime, or
sustained flood/restart timing guarantee is established by this repair.
Storage exhaustion remains a refusal and is never counted as inclusion or
effect liveness. Finding 006 needs those remaining changes, complete process
and formal qualification, clean R2 evidence, and fresh exact-candidate review.
No M16Q/M17Q/M18Q gate is closed by this local evidence.
