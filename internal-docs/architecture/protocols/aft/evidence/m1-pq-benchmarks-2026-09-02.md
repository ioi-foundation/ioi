# M1 PQ primitive benchmark evidence — 2026-09-02

Status: reproducible development-host evidence, not a cross-platform capacity
claim.

Baseline: `ef20d4ff5a7e486ece3dc3410d9c7e6d6eda9eba` plus the M0/M1 working
slice recorded in `../IMPLEMENTATION_LEDGER.md`.

Host and toolchain:

- x86_64, Intel Core Ultra 9 275HX, 24 online physical cores;
- rustc 1.93.1 (`01f6ddf75 2026-02-11`);
- cargo 1.93.1 (`083ac5135 2025-12-15`);
- optimized workspace benchmark profile;
- Criterion 0.5.1, plotters backend.

## Results

| Operation | Samples / iterations | 95% estimate reported by Criterion |
|---|---:|---:|
| ML-DSA-44 key generation | 20 / about 12,000 | 410.94–412.93 µs |
| ML-DSA-44 live-vote signing | 20 / 40 | 142.80–143.36 ms |
| ML-DSA-44 live-vote verification | 20 / about 7,980 | 631.34–635.49 µs |
| SLH-DSA-SHA2-128s terminal signing | 10 / 55 | 100.20–100.76 ms |
| SLH-DSA-SHA2-128s terminal verification | 10 / about 49,000 | 102.62–102.87 µs |
| Full authenticated PQ channel handshake (ephemeral ML-KEM + ML-DSA mutual authentication and confirmation) | 20 / 20 | 474.91–476.25 ms |
| PQ record seal + open, 1,024-byte payload | 20 / about 330,000 | 15.124–15.184 µs |
| PQ record seal + open, 65,536-byte payload | 20 / about 6,300 | 811.07–814.39 µs |

Wire sizes measured from the selected providers:

| Suite | Public key | Signature |
|---|---:|---:|
| ML-DSA-44 | 1,312 bytes | 2,420 bytes |
| SLH-DSA-SHA2-128s | 32 bytes | 7,856 bytes |

The ML-DSA signing result is large enough to be a live-tier capacity risk and
must be included in M2/M3 end-to-end throughput measurements. No latency
superlative is supported by this primitive-only run. The channel benchmark
measures the production channel primitives but excludes libp2p scheduling,
socket transit, retransmission and durable outbox I/O. It separates the
one-time authenticated handshake from steady-state AEAD record protection:
the former is the material setup cost on this host.

## Reproduction

```sh
cargo bench -p ioi-crypto --bench aft_pq_crypto -- --noplot
cargo bench -p ioi-validator --bench aft_pq_terminal_seal -- --noplot
```

Criterion's generated local statistics live under `target/criterion/` and are
recreated by the commands above; build output is intentionally not committed.
