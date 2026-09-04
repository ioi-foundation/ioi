# M10 R5 automated Daybreak qualification report

Status: `PASS` for the exact R5 candidate. `AFT-M10-003` is closed.

This is an owner-authorized automated OpenAI Codex Daybreak review under ADR
0049. It is not human peer review, professional assurance, institutional
certification, or cryptographic certification.

Date: 2026-09-04.

## Immutable target

```text
tag:                  aft-pq-v1-review-candidate-r5-2026-09-04
annotated tag object: 3149d3404193864df992b482363625fe031f2f22
commit:               5445fbbbd170819af9124f5566c06e33d24222dd
tree:                 d554a6e84f78166bfcf0f19da085334acbed6643
tag signature:        none
review clone:         /tmp/ioi-m10-r5-audit.hzluAm/audit
```

The detached review checkout was clean before and after the review. The shared
checkout and external state were not modified by the reviewer.

Frozen file hashes:

```text
f576f3b65b17bb4a19e9582df856390cf8a6d47c79cae823e12bde61ad408cc1  Cargo.lock
1ac90ec322eca87211f7db3a155f2c2689b1e61d9acec1af1fc2bcd5d1c74d1a  rust-toolchain.toml
5e9c68802a642a4b3962d038daffc2b1c62ff1309af8d886f985140382cd6823  crates/cli/src/testing/signing_oracle.rs
ffcbf431aa146a179ea99cab5b8f10132aef97363ff7fc19781521bdbc286c7f  crates/cli/tests/aft_e2e.rs
e66cc0b64c3a006bf05e542fa0716564ac9bd12620e03858a28f063e989c1c97  tools/aft-pq-interop/Cargo.lock
```

## Isolation and build provenance

Preflight `/tmp/ioi-m10-r5-preflight.hzluAm.log` recorded
`active_build=0` and `active_fixture=0`. Post-run process census found no
remaining Cargo, rustc, validator, workload, guardian, or signer process.

The run intentionally reused an R2 `CARGO_TARGET_DIR`, so the test executable's
path contained `ioi-m10-r2-audit`. Direct `/proc` ancestry established that it
was the R5 process, not a concurrent stale fixture: R5 `time` launched R5
`cargo test`, which launched the test and the R5 validators and signers. Exact
R5 recompilation was established by the executable's post-start modification
time, its R5-only diagnostic strings, node-profile commit marker, and SHA-256:

```text
fb0d0851e76c1848ce5ee2f1471b80885d0c8e0fe495d51d14928b3ccc64ea28
```

## Source review

R4 to R5 changes only `crates/cli/tests/aft_e2e.rs`. Production consensus,
networking, validator, cryptography, types, and finality code are unchanged.
The new timeout path retains up to 256 orchestration lines per node and probes
every node's height plus H4-H7 availability, view, and signature length.

The four-validator, full-mesh PQ, `ClassicBft`, ML-DSA-44, no-downgrade,
30-second view timeout, three-failed-view fallback, H4 fallback, 900-second H5
allowance, and 240-second H7 allowance parameters are unchanged.

Individual diagnostic RPC probes do not yet carry explicit per-call deadlines.
This is a non-blocking diagnostic limitation and did not affect the passing
path.

## Reproduction

| Command or surface | Result |
|---|---|
| exact tag-object verification | pass |
| `cargo fmt --all -- --check` | pass, 8.01 seconds |
| `git diff --check` | pass |
| locked CLI test compile | pass, 113.33 seconds |
| exact four-validator fixture | pass |
| final clean status and process census | pass |

Fixture result:

```text
test result: ok. 1 passed; 0 failed; 2 filtered out
fixture time: 997.25 seconds
command elapsed: 1147.81 seconds
maximum RSS: 5,768,940 KiB
exit: 0
```

The reviewer observed all eight successful signer starts, both shared-tip
readiness events, the full-mesh initial cluster, speculative H4 projection,
forced three-view fallback traffic, canonical H4 replacement and H5 advance,
every required fallback metric, cold restart and renewed shared-tip
convergence, recovered-H4 hash equality, a non-empty ML-DSA H6 signature, and
H7 within the unchanged allowance.

Transcript:

```text
path:   /tmp/ioi-m10-r5-e2e.hzluAm.log
size:   129773 bytes
sha256: f481dba6dd7367c07f2331de03cde3f40e5c8002e4fdaf710c8f1388a265e10e
```

## Finding disposition

`AFT-M10-003`, prior severity medium, is **closed** for R5. The R3 and R4
failures remain valid historical evidence of contention sensitivity; R5 meets
the commissioned clean-resource qualification condition. No critical, high,
or medium M10 finding remains open.

This review does not establish human peer review, provider correctness,
side-channel resistance, adaptive-corruption security, arbitrary-network
delivery, snapshot-safe custody, generic external-resource at-most-once
behavior, or performance under competing host builds.

**Final disposition: `PASS`.**
