#!/usr/bin/env bash
# AFT-CB R4c gate: the release tree contains NO mock succinct-proof
# constructor and NO simulated fallback on the succinct continuity lane.
#
#   1. no `fn new_mock` anywhere under the zk driver or its consumers'
#      release sources (a mock constructor deleted must STAY deleted);
#   2. no `impl Default for SuccinctDriver` (the Default that routed to
#      the mock is the same defect under another name);
#   3. the driver's non-native SuccinctSp1V1 arm is a refusal: the
#      refusal string is present, and `SimulatedGroth16` does not appear
#      inside the canonical-collapse continuity impl;
#   4. the governed pin constant exists and matches vkey.json (the
#      cfg-audit TEST asserts the same at runtime; this is the static
#      floor).
#
# Mutation-tested per AFT-CB standing rule 3: reintroducing
# `fn new_mock` (or the Default impl) must turn this gate RED.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DRIVER_SRC="$ROOT/crates/plugins/zk-driver-succinct/src"
fail=0
err() { echo "FAIL: $1"; fail=1; }

# 1. No mock constructors in release sources (tests excluded: tests may
#    construct adversarial fixtures, but a *constructor named mock* is
#    barred even there — the fixture builder is not a driver constructor).
hits=$(grep -rn "fn new_mock" \
  "$DRIVER_SRC" \
  "$ROOT/crates/plugins/ibc-service/src" \
  "$ROOT/crates/consensus/src" \
  "$ROOT/crates/validator/src" \
  "$ROOT/crates/node/src" 2>/dev/null || true)
[[ -z "$hits" ]] || err "mock constructor present:
$hits"

# 2. No Default impl for the driver.
hits=$(grep -rn "impl Default for SuccinctDriver" "$DRIVER_SRC" 2>/dev/null || true)
[[ -z "$hits" ]] || err "SuccinctDriver regained a Default impl:
$hits"

# 3. The non-native continuity arm refuses; no simulated delegation in
#    the continuity impl. Extract the CanonicalCollapseContinuityVerifier
#    impl block and inspect it.
lib="$DRIVER_SRC/lib.rs"
impl_block=$(awk '/^impl CanonicalCollapseContinuityVerifier for SuccinctDriver/,/^}/' "$lib")
[[ -n "$impl_block" ]] || err "continuity verifier impl not found in lib.rs"
grep -q "no simulated fallback" <<<"$impl_block" \
  || err "continuity impl lost its non-native refusal (AFT-CB R4c string missing)"
if grep -q "SimulatedGroth16" <<<"$impl_block"; then
  err "continuity impl delegates to SimulatedGroth16 — the simulated fallback is back"
fi

# 4. Pin constant present and equal to the governed document.
pin_const=$(grep -oP 'CANONICAL_COLLAPSE_CONTINUITY_VKEY_PIN: &str =\s*\n?\s*"\K0x[0-9a-f]{64}' -z "$DRIVER_SRC/config.rs" | tr -d '\0' || true)
[[ -n "$pin_const" ]] || err "governed pin constant missing from config.rs"
pin_doc=$(python3 -c "import json;print(json.load(open('$ROOT/crates/aft-proofs/vkey.json'))['vkey_bytes32'])")
if [[ -n "$pin_const" && "$pin_const" != "$pin_doc" ]]; then
  err "pin drift: config.rs=$pin_const vkey.json=$pin_doc"
fi

if [[ $fail -ne 0 ]]; then
  echo "check_aft_no_mock_proof: FAILED"
  exit 1
fi
echo "no-mock-proof OK: no mock constructor, no Default driver, non-native lane refuses, pin matches vkey.json ($pin_doc)"
