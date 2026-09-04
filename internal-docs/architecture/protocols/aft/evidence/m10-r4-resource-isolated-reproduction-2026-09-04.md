# M10 R4 resource-isolated owner reproduction

> Local owner-side reproduction evidence only. This run is not independent
> review and does not override the adverse Daybreak R4 disposition.

## Result

The exact R4 candidate and exact acceptance fixture passed when run alone from
the independent reviewer's detached clone, with no concurrent workspace build.

```text
Candidate commit: 25d9f11711d341c88689ba2862e55e325f68b085
Detached clone:   /tmp/ioi-m10-r4-audit.muYRia/audit
Test result:      1 passed; 0 failed; 2 filtered out
Fixture time:     585.49s
Command time:     776.35s
Exit:             0
Maximum RSS:      5,623,448 KiB
```

Command:

```sh
/usr/bin/time -f 'elapsed=%e exit=%x maxrss_kb=%M' \
  env RUST_TEST_THREADS=1 \
  cargo test --locked -p ioi-cli --test aft_e2e \
  --features consensus-aft,vm-wasm,state-iavl \
  test_aft_pq_hash_fallback_executes_virtual_block -- --nocapture
```

Observed acceptance sequence:

- all four initial ML-DSA signer processes started;
- the cluster reached a common tip;
- the production-generated speculative height-4 projection was observed;
- the hash-only fallback completed and emitted all required metrics;
- all four cold-restart signer processes started;
- the restarted cluster reached a common tip;
- height 7 completed; and
- recovered-height and authenticated post-restart assertions passed.

## Disposition

This pass and the independent R4 timeout are both retained. Together they show
that the 240-second post-restart acceptance condition is not reliably
reproducible in the current harness/environment. The independent R4 run
overlapped a separate dependency-heavy Rust build on the same host, while this
run did not; resource contention is therefore a plausible explanation, not a
proved waiver.

`AFT-M10-003` remains open. R5 must retain bounded per-node orchestration logs
and probe every validator's reported height and H4-H7 block availability on
timeout. A fresh immutable R5 candidate then requires a clean independent run
without competing build workloads.
