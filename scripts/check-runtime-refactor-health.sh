#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ACTIVE_GLOBS=(
  --glob '!target/**'
  --glob '!node_modules/**'
  --glob '!dist/**'
  --glob '!docs/**'
  --glob '!AGENTIC_RUNTIME_AUDIT.md'
  --glob '!CLEAN_BREAK_CODE_DEBT_AUDIT.md'
  --glob '!CLEAN_BREAK_IMPLEMENTATION_PLAN.md'
  --glob '!CLEAN_BREAK_IMPLEMENTATION_PROGRESS.md'
  --glob '!REFACTOR_PROGRESS.md'
  --glob '!scripts/check-runtime-refactor-health.sh'
  --glob '!scripts/check-clean-break-debt.sh'
)

LEGACY_PATTERN='AUTOPILOT_STUDIO_|IOI_STUDIO_|STUDIO_ARTIFACT_|studio_artifact_|studio-proof-trace|STUDIO ROUTE CONTRACT|run_studio_graph|Model \(Legacy\)|swarmPatchReceipts|validate_review_request_compat|legacy_deterministic_tool_name|(^|[^[:alnum:]_])receipts\.json|useSessionLegacyPresentation'

echo "[refactor-health] checking active legacy naming and compatibility debt"
if rg -n "$LEGACY_PATTERN" . "${ACTIVE_GLOBS[@]}"; then
  echo "[refactor-health] active legacy/debt matches found" >&2
  exit 1
fi

studio_matches="$(
  rg -n '\bstudio\b|studio_|Studio' . "${ACTIVE_GLOBS[@]}" |
    grep -v 'visual studio code' || true
)"
if [[ -n "$studio_matches" ]]; then
  echo "$studio_matches"
  echo "[refactor-health] active Studio naming found outside documented historical surfaces" >&2
  exit 1
fi

echo "[refactor-health] reporting active files over 2000 lines"
large_files="$(
  find apps crates scripts -type f \
    \( -name '*.rs' -o -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.mjs' -o -name '*.css' \) \
    ! -path '*/target/*' ! -path '*/node_modules/*' ! -path '*/dist/*' \
    -print0 |
  xargs -0 wc -l |
  awk '$1 > 2000 && $2 != "total" { print $1 " " $2 }' |
  sort -nr
)"

if [[ -n "$large_files" ]]; then
  echo "$large_files"
  echo "[refactor-health] large files are tracked as refactor debt in docs/runtime/refactor-boundaries.md"
fi

echo "[refactor-health] ok"
