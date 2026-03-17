#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

cargo test -q -p ioi-consensus --features aft stale_registry_reads_prevent_quorum -- --nocapture
cargo test -q -p ioi-consensus --features aft delayed_checkpoints_pause_experimental_finalization -- --nocapture
cargo test -q -p ioi-consensus --features aft mixed_version_epoch_upgrade_requires_epoch_convergence -- --nocapture
cargo test -q -p ioi-services rejects_unsafe_odd_sized_guardian_committee_under_production_policy -- --nocapture

echo "Adversarial aft gate passed."
