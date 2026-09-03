# M3 hash-async durable-journal benchmark — 2026-09-02

Status: reproducible durability-component evidence, not a network-latency or
end-to-end fallback claim.

## Scope

This benchmark isolates the production `DurableHashAsyncNode` encrypted WAL,
per-event file sync, external rollback-anchor sync, terminal checkpoint
compaction, and exact terminal reopen. Three honest nodes execute the exact
`n=4, f=1, q=3` protocol while the fourth member is silent. Honest deliveries
alternate between the front and back of the queue. It excludes ML-DSA,
strict-PQ channel protection, sockets, block execution, and Agentgres
admission; those costs have separate evidence.

Each sample persisted 585 accepted/rejected protocol events and processed 573
deliveries. Decision plus terminal compaction took 15.013–16.746 seconds, with
a median of 16.585 seconds. Reopening all three encrypted terminal checkpoints
took 0.615–0.711 milliseconds. The three compacted journals occupied 6,945
bytes total (2,315 bytes per node).

This result shows that synchronous per-message durability dominates the
four-node core on this host. The cost is deliberately paid before acting on a
message so restart cannot change an accepted outcome. It also shows that the
terminal form is bounded and cheap to reload. No favorable latency claim is
made from three local samples.

## Environment and reproduction

The host and toolchain are the same as the other 2026-09-02 M1/M3 evidence:
Linux x86_64, Intel Core Ultra 9 275HX, rustc 1.93.1, optimized workspace
release profile, baseline `ef20d4ff5a7e486ece3dc3410d9c7e6d6eda9eba` plus
the recorded M0–M3 worktree.

```text
cargo run --release -p ioi-consensus --features aft --example aft_hash_async_journal_bench -- 3
```

The versioned raw rows are retained in
`m3-hash-async-journal-benchmark-2026-09-02.jsonl`.
