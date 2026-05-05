#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

fail() {
  echo "contract-invariants: $*" >&2
  exit 1
}

if command -v rg >/dev/null 2>&1; then
  search_fixed() {
    rg -n --fixed-strings "$1" "${@:2}" >/dev/null
  }
  search_regex() {
    rg -n "$1" "${@:2}" >/dev/null
  }
else
  search_fixed() {
    grep -nF -- "$1" "${@:2}" >/dev/null
  }
  search_regex() {
    grep -nE -- "$1" "${@:2}" >/dev/null
  }
fi

required_files=(
  "docs/conformance/agentic-runtime/CIRC.md"
  "docs/conformance/agentic-runtime/CEC.md"
  "docs/architecture/_meta/vocabulary.md"
  "docs/architecture/foundations/common-objects-and-envelopes.md"
)

for file in "${required_files[@]}"; do
  [[ -f "$file" ]] || fail "missing required file: $file"
done

required_paths=(
  "crates/types/src/app/agentic/security/intent.rs"
  "crates/types/src/app/agentic/tools/agent_tool.rs"
  "crates/types/src/app/events.rs"
  "crates/ipc/proto/public/v1/public.proto"
  "crates/ipc/proto/control/v1/control.proto"
)

for path in "${required_paths[@]}"; do
  [[ -f "$path" ]] || fail "canonical contract path not found: $path"
done

# Block known stale path references that caused drift.
for stale in \
  "crates/types/src/workloads/spec.rs" \
  "crates/services/src/search/mod.rs"; do
  if search_fixed "$stale" \
    docs/conformance/agentic-runtime/CIRC.md \
    docs/conformance/agentic-runtime/CEC.md \
    docs/architecture/_meta/vocabulary.md \
    docs/architecture/foundations/common-objects-and-envelopes.md; then
    fail "stale path reference detected in docs: $stale"
  fi
done

# Freeze current vocabulary and ontology anchors.
for term in intent policy evidence receipt; do
  search_regex "^- \`${term}\`:" docs/architecture/_meta/vocabulary.md \
    || fail "runtime vocabulary term missing or malformed: ${term}"
done
for term in Intent Capability Tool; do
  search_regex "^- \`${term}\`:" docs/conformance/agentic-runtime/CIRC.md \
    || fail "CIRC ontology term missing or malformed: ${term}"
done
search_fixed "TaskEnvelope" docs/architecture/foundations/common-objects-and-envelopes.md \
  || fail "common object envelope missing TaskEnvelope"
search_fixed "lease ref" docs/architecture/foundations/common-objects-and-envelopes.md \
  || fail "common object envelope missing lease reference"

# Optional local guard when CODEX.txt is present (file is gitignored in this repo).
if [[ -f "CODEX.txt" ]]; then
  for stale in \
    "crates/types/src/workloads/spec.rs" \
    "crates/services/src/search/mod.rs"; do
    if search_fixed "$stale" CODEX.txt; then
      fail "stale path reference detected in CODEX.txt: $stale"
    fi
  done
fi

echo "contract-invariants: OK"
