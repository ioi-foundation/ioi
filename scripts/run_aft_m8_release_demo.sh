#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# Real four-validator process drill: three failed views force the default
# hash-only fallback, a virtual block is admitted, all nodes cold-restart, and
# a native PQ child resumes without a synthetic QC.
RUST_TEST_THREADS=1 cargo test --locked -p ioi-cli --test aft_e2e \
  --features consensus-aft,vm-wasm,state-iavl \
  test_aft_pq_hash_fallback_executes_virtual_block -- --nocapture

# Portable PQ issuer/envelope, no-laundering and complete offline decision.
cargo test --locked -p ioi-finality --features portable-assurance \
  runtime_v3_hash_async_supports_pq_checkpoint_issuer_without_downgrade --lib
RECEIPT_DIR="$(mktemp -d)"
trap 'rm -rf -- "${RECEIPT_DIR}"' EXIT
AFT_PORTABLE_RECEIPT_OUTPUT="${RECEIPT_DIR}/complete-v1.json" \
  AFT_PORTABLE_TRUST_OUTPUT="${RECEIPT_DIR}/external-trust-v1.json" \
  AFT_PORTABLE_NEGATIVE_OUTPUT_DIR="${RECEIPT_DIR}/negative" \
  cargo test --locked -p ioi-finality --features portable-assurance portable_assurance --lib

# Mixed-domain runtime boundary: one seal-required domain remains stalled while
# three unrelated effects continue, including crash/ambiguity reconciliation;
# the rest of the consequence corpus checks every one-mutation boundary.
cargo test --locked -p agentgres consequence::tests --lib

# Independent representation/economic verifier and separately compiled PQ
# implementation oracle.
cargo build --locked --quiet --manifest-path tools/aft-pq-interop/Cargo.toml
python3 tools/aft-assurance-cleanroom/verify.py \
  --receipt "${RECEIPT_DIR}/complete-v1.json" \
  --trust "${RECEIPT_DIR}/external-trust-v1.json" \
  --negative-dir "${RECEIPT_DIR}/negative" \
  --pq-oracle tools/aft-pq-interop/target/debug/aft-pq-interop
cargo run --locked --quiet --manifest-path tools/aft-pq-interop/Cargo.toml

# All protocol formal models, including cross-domain non-interference.
bash .github/scripts/run_aft_formal_checks.sh
