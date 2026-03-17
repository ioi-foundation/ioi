#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

cargo test -q -p ioi-consensus --features aft guardian_majority_safety_holds_below_quorum_intersection_budget -- --nocapture
cargo test -q -p ioi-consensus --features aft experimental_nested_guardian_accepts_deterministically_assigned_witness_certificate -- --nocapture
bash .github/scripts/run_aft_formal_checks.sh

echo "Local aft cluster gate passed."
