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
  "docs/CIRC.md"
  "docs/CEC.md"
  "docs/CONTRACT_GLOSSARY.md"
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

# Ensure glossary path anchors are present and frozen.
for anchor in \
  "crates/types/src/app/agentic/security/intent.rs" \
  "crates/types/src/app/agentic/tools/agent_tool.rs" \
  "crates/types/src/app/events.rs" \
  "crates/ipc/proto/public/v1/public.proto" \
  "crates/ipc/proto/control/v1/control.proto"; do
  search_fixed "$anchor" docs/CONTRACT_GLOSSARY.md \
    || fail "glossary missing canonical path reference: ${anchor}"
done

# Block known stale path references that caused drift.
for stale in \
  "crates/types/src/workloads/spec.rs" \
  "crates/services/src/search/mod.rs"; do
  if search_fixed "$stale" docs/CIRC.md docs/CEC.md docs/CONTRACT_GLOSSARY.md; then
    fail "stale path reference detected in docs: $stale"
  fi
done

# Freeze glossary terms.
for term in Intent Capability Tool Workload Lease; do
  search_regex "^- \\*\\*${term}\\*\\*:" docs/CONTRACT_GLOSSARY.md \
    || fail "glossary term missing or malformed: ${term}"
done

# Optional local guard when CODEX.txt is present (file is gitignored in this repo).
if [[ -f "CODEX.txt" ]]; then
  search_fixed "docs/CIRC.md" CODEX.txt || fail "CODEX.txt missing docs/CIRC.md invariant reference"
  search_fixed "docs/CEC.md" CODEX.txt || fail "CODEX.txt missing docs/CEC.md invariant reference"
  search_fixed "docs/CONTRACT_GLOSSARY.md" CODEX.txt || fail "CODEX.txt missing docs/CONTRACT_GLOSSARY.md reference"
  search_fixed "crates/types/src/app/events.rs" CODEX.txt || fail "CODEX.txt missing canonical workload type path reference"
  for stale in \
    "crates/types/src/workloads/spec.rs" \
    "crates/services/src/search/mod.rs"; do
    if search_fixed "$stale" CODEX.txt; then
      fail "stale path reference detected in CODEX.txt: $stale"
    fi
  done
fi

echo "contract-invariants: OK"
