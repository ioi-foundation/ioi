# M10 R4 automated independent remediation retest

> Automated AI review only. Reviewer: owner-authorized, context-isolated
> OpenAI Codex Daybreak agent. This is not human peer review, professional
> assurance, institutional certification, or cryptographic certification.

## Disposition

**REPAIR_REQUIRED**

All four initial and four cold-restart signers started successfully. However,
the restarted cluster did not reach height 7 within the unchanged 240-second
allowance.

`AFT-M10-003` remains **open, medium**. The remediation changed no protocol
code or parameters, so `REJECT_REMEDIATION` is not warranted.

## Independence and isolation

The reviewer did not author the candidate, selected and reproduced the checks
independently, received no suppression instruction, and reports the adverse
result without waiver.

```text
Tag:        aft-pq-v1-review-candidate-r4-2026-09-03
Tag object: e813ec2ce6cd353b26ddac4c189527a80c4d57c2
Type:       annotated tag
Commit:     25d9f11711d341c88689ba2862e55e325f68b085
Message:    AFT PQ v1 review candidate R4 (2026-09-03)
Signature:  none
```

Disposable detached clone:

```text
/tmp/ioi-m10-r4-audit.muYRia/audit
HEAD=25d9f11711d341c88689ba2862e55e325f68b085
status=## HEAD (no branch)
```

The shared checkout and external state were not modified.

Frozen hashes matched the candidate evidence:

```text
5e9c68802a642a4b3962d038daffc2b1c62ff1309af8d886f985140382cd6823  crates/cli/src/testing/signing_oracle.rs
5649415e587a782810bce8184df396a036fc9c2c9c6a21b6f736967da648f252  crates/cli/tests/aft_e2e.rs
```

## Source inspection

`IOI_TEST_SIGNER_STARTUP_TIMEOUT_SECS`:

- parses as positive `u64`;
- defaults to 120 seconds for absent, malformed, negative, overflowing, or zero
  input;
- is pinned to 120 seconds in both four-validator PQ fixtures; and
- polls at 100-millisecond intervals.

Every readiness poll uses `try_wait()`. Early exit reports status, stdout, and
stderr and reaps through `wait_with_output()`.

On timeout, the harness records any kill error, kills and reaps the child, then
reports timeout, final status, kill result, stdout, and stderr. Successful
guards also kill and wait in `Drop`.

The live test did not exercise these negative diagnostic branches because all
eight signers became ready.

The R3-to-R4 diff contains no changes under consensus, networking, validator,
types, crypto, finality, or Agentgres. Only the signer harness and two fixture
timeout pins changed.

Unchanged parameters include:

- four validators;
- `ClassicBft`;
- ML-DSA-44;
- full-mesh PQ;
- 30-second pacemaker timeout;
- three failed views before hash fallback;
- fallback at height 4;
- 900-second height-5 allowance;
- 240-second restart/height-7 allowance; and
- downgrade disabled.

## Commands

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS, 8.74s |
| `git diff --check` | PASS |
| Locked CLI test compilation | PASS, 141.72s |
| Exact four-validator fixture | **FAIL 101** |

Fixture:

```sh
RUST_TEST_THREADS=1 cargo test --locked -p ioi-cli --test aft_e2e \
  --features consensus-aft,vm-wasm,state-iavl \
  test_aft_pq_hash_fallback_executes_virtual_block -- --nocapture
```

## Fixture results

Passed:

- four initial encrypted signer starts;
- full-mesh shared-tip convergence;
- height 3;
- staged height-4 projection;
- scoped PQ timeout votes through view 3;
- height-5 hash-fallback re-entry;
- canonical virtual height 4 and typed async-parent/native ML-DSA assertions;
- required fallback metrics;
- four cold-restart signer starts; and
- restarted shared-tip convergence.

Failed:

```text
Error: Timeout waiting for height to reach 7
FAILED

test result: FAILED. 0 passed; 1 failed
finished in 1273.08s
elapsed=1458.47 exit=101
```

Because height 7 was not reached, recovered virtual-height-4 and authenticated-
height-6 assertions were not executed.

## Finding disposition

### AFT-M10-003 — Integrated restart artifact

- Severity: medium
- State: open
- Impact: release-artifact reproducibility and post-restart liveness evidence
- Safety: no independent safety violation demonstrated

The signer-startup defect is repaired, but the complete acceptance condition
remains unmet.

Required remediation:

- diagnose the restarted cluster's failure to reach height 7;
- preserve validator height/status and logs on timeout;
- demonstrate recovered virtual height 4 and authenticated ML-DSA production
  after restart; and
- freeze and independently retest a new immutable candidate.

## Environment

```text
Linux 6.17.9-76061709-generic x86_64
git 2.43.0
rustc/cargo 1.93.1
Python 3.12.3
```

Pinned providers remained `dcrypt 4.0.1`, `ml-dsa 0.1.1`,
`slh-dsa 0.2.0-rc.5`, `chacha20poly1305 0.10.1`, `zeroize 1.8.2`, and
`fips205 0.4.1`.

Prior limitations remain: this establishes neither human review, provider
correctness, side-channel resistance, adaptive security, arbitrary-network
delivery, snapshot-safe custody, nor generic at-most-once behavior.

**Final result: REPAIR_REQUIRED. AFT-M10-003 and Gate 15 remain open.**
