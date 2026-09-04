# M10 R4 signer-startup remediation local evidence

Status: local repair evidence for `AFT-M10-003`; independent exact-tag retest
required before M10 admission.

Date: 2026-09-03.

## Repair

The test signing-oracle harness now:

- uses a finite 120-second default readiness bound instead of the 20-second
  bound that failed under four-validator cold-restart load;
- pins the same 120-second bound explicitly in both PQ four-validator release
  fixtures;
- polls child exit status while waiting, so an early signer failure is not
  misreported as a timeout; and
- on timeout, kills and reaps the child while preserving exit status, kill
  error, stdout, stderr, and the exact elapsed bound.

This is a host-resource/test-harness deadline. It does not change an AFT
protocol timeout, quorum, certificate, fallback trigger, or cryptographic
profile.

Pre-freeze hashes:

```text
5e9c68802a642a4b3962d038daffc2b1c62ff1309af8d886f985140382cd6823  crates/cli/src/testing/signing_oracle.rs
5649415e587a782810bce8184df396a036fc9c2c9c6a21b6f736967da648f252  crates/cli/tests/aft_e2e.rs
```

## Local reproduction

Compile gate:

```text
cargo check --locked -p ioi-cli \
  --features consensus-aft,vm-wasm,state-iavl --tests
```

Result: pass.

Exact previously failing fixture:

```text
RUST_TEST_THREADS=1 cargo test --locked -p ioi-cli --test aft_e2e \
  --features consensus-aft,vm-wasm,state-iavl \
  test_aft_pq_hash_fallback_executes_virtual_block -- --nocapture
```

Result:

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out
finished in 1098.02s
```

The run:

1. provisioned all four encrypted PQ signer processes;
2. formed and synchronized the four-validator cluster;
3. staged the production-generated speculative height-4 workload;
4. forced three timeout views and completed hash-only fallback;
5. replaced height 4 with the canonical virtual envelope;
6. resumed native ML-DSA production at height 5 and emitted every required
   fallback metric;
7. shut down all validators and signer processes;
8. reopened the same stable state, reprovisioned all four signers, and
   reconverged; and
9. satisfied the fixture's recovered-height-4 and post-restart height-7
   assertions.

The host was concurrently contended, so this run exercises the exact condition
that defeated R3. It is local evidence only; the R4 tag must receive an
independent repeat before `AFT-M10-003` closes.
