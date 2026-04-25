#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PATTERN='run_studio_graph|Model \(Legacy\)|swarmPatchReceipts|validate_review_request_compat|legacy_deterministic_tool_name|(^|[^[:alnum:]_])receipts\.json|useSessionLegacyPresentation|route_pii_decision\(|route_pii_decision_with_assist\(|inspect_and_route_with\(|inspect_and_route_with_provider\('

matches="$(
  rg -n "$PATTERN" \
    crates apps packages README.md package.json \
    --glob '!**/target/**' \
    --glob '!**/node_modules/**' \
    --glob '!**/dist/**' \
    --glob '!apps/sas-xyz/archive/**' \
    || true
)"

if [[ -n "$matches" ]]; then
  printf '%s\n' "Clean-break debt guard failed. Active-code legacy matches remain:" >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi

printf '%s\n' "Clean-break debt guard passed."
