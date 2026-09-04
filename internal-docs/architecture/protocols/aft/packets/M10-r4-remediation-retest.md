# M10 R4 remediation retest commission

Status: commissioning packet; automated review under ADR 0049, not human peer
review or external certification.

## Candidate identity

```text
tag: aft-pq-v1-review-candidate-r4-2026-09-03
tag_object: resolve from annotated tag
commit: resolve by dereferencing exact tag
```

The reviewer must use a fresh clone or detached checkout at the exact annotated
tag and record the tag object, commit, environment, hashes, and clean status.

## Scope

Read:

- `evidence/m10-r3-daybreak-retest-2026-09-03.md`
- `evidence/m10-r4-signer-startup-local-evidence-2026-09-03.md`
- `crates/cli/src/testing/signing_oracle.rs`
- the two PQ four-validator fixtures in `crates/cli/tests/aft_e2e.rs`
- ADRs 0048 and 0049

Reproduce at minimum:

```text
cargo fmt --all -- --check
git diff --check
cargo check --locked -p ioi-cli \
  --features consensus-aft,vm-wasm,state-iavl --tests
RUST_TEST_THREADS=1 cargo test --locked -p ioi-cli --test aft_e2e \
  --features consensus-aft,vm-wasm,state-iavl \
  test_aft_pq_hash_fallback_executes_virtual_block -- --nocapture
```

The retest must verify all four initial signer starts, height-5 fallback
re-entry, all four cold-restart signer starts, recovered virtual height 4, and
post-restart height 7. It must also inspect early-exit and timeout diagnostics,
finite bound parsing, child reaping, and whether the repair changed any
protocol parameter.

Return `PASS_REMEDIATION`, `REPAIR_REQUIRED`, or `REJECT_REMEDIATION`, with
finding IDs, severity, evidence, and required action. A pass closes only
`AFT-M10-003`; other M10 release claims remain bounded by the exact R3 review
and its stated limitations.
