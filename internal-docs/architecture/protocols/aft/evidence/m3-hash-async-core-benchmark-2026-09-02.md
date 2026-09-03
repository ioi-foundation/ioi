# M3 hash-only fallback core benchmark — 2026-09-02

Status: reproducible component evidence, not a production network latency
claim and not an end-to-end fallback drill.

## Scope

The benchmark runs the runtime-neutral hash-only RBC/RA/ASKS/gather/VABA/ACS
core with the exact AFT geometry `n = 3f + 1`, `q = n - f`. The first `f`
members are modeled as permanently silent after membership is fixed; all
traffic addressed to them is counted and dropped. Honest deliveries alternate
between the front and back of the reliable-channel queue. Proposal payloads are
immutable references, so the stated 1024-byte payload length is committed but
payload bytes do not travel through the control protocol.

The measurements include canonical SCALE control-message encoding. They do
not include ML-DSA availability/order/executed-block signatures, durable WAL
or external-anchor fsync, PQ channel encryption, socket scheduling, block
execution, or receipt admission. Those costs must remain separate rather than
being hidden in this component result.

## Results

| n | f | q | samples | wire messages | encoded wire bytes | wall p50 | wall p95 | observed peak RSS |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 1 | 3 | 5 | 579 | 70,206 | 11.132 ms | 13.548 ms | 2,788 KiB |
| 16 | 5 | 11 | 5 | 32,300 | 7,043,995 | 438.983 ms | 443.262 ms | 7,964 KiB |
| 64 | 21 | 43 | 3 | 1,960,476 | 1,181,476,254 | 31.768 s | 31.887 s | 330,560 KiB |
| 130 | 43 | 87 | 1 | 16,269,738 | 18,399,942,090 | 320.468 s | single observation | 3,870,428 KiB |

Every run converged at VABA view 1 with one common ordering root. Process CPU
closely tracked wall time, confirming that this in-memory run was CPU-bound.
The `n=130` case is the first exact `3f+1` geometry at or above the required
128-member boundary. Its single upper-bound observation is intentionally not
presented as a latency distribution.

The result supports keeping this construction as the pessimistic asynchronous
fallback. It does not support a low-latency or low-bandwidth claim, and it
identifies control-message aggregation and retained-state compaction as
material engineering targets before release.

## Environment

- baseline commit: `ef20d4ff5a7e486ece3dc3410d9c7e6d6eda9eba`, plus the M0–M3 worktree
- OS: Linux 6.17.9-76061709-generic x86_64
- CPU: Intel Core Ultra 9 275HX, 24 online logical CPUs
- compiler: rustc 1.93.1 (01f6ddf75 2026-02-11)
- Cargo: 1.93.1 (083ac5135 2025-12-15)
- build: release profile from the repository workspace

## Reproduction

```text
cargo run --release -p ioi-consensus --features aft --example aft_hash_async_bench -- 4,4,4,4,4,16,16,16,16,16,64,64,64,130
```

The program emits one versioned JSON object per run. The retained raw output is
`m3-hash-async-core-benchmark-2026-09-02.jsonl` in this directory. Peak RSS is
read from Linux `/proc/self/status`; on another operating system it is reported
as zero rather than estimated.
