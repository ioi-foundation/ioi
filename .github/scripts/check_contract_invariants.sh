#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

fail() {
  echo "contract-invariants: $*" >&2
  exit 1
}

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
  rg -n --fixed-strings "$anchor" docs/CONTRACT_GLOSSARY.md >/dev/null \
    || fail "glossary missing canonical path reference: ${anchor}"
done

# Block known stale path references that caused drift.
for stale in \
  "crates/types/src/workloads/spec.rs" \
  "crates/services/src/search/mod.rs"; do
  if rg -n --fixed-strings "$stale" docs/CIRC.md docs/CEC.md docs/CONTRACT_GLOSSARY.md >/dev/null; then
    fail "stale path reference detected in docs: $stale"
  fi
done

# Freeze glossary terms.
for term in Intent Capability Tool Workload Lease; do
  rg -n "^- \\*\\*${term}\\*\\*:" docs/CONTRACT_GLOSSARY.md >/dev/null \
    || fail "glossary term missing or malformed: ${term}"
done

# Optional local guard when CODEX.txt is present (file is gitignored in this repo).
if [[ -f "CODEX.txt" ]]; then
  rg -n --fixed-strings "docs/CIRC.md" CODEX.txt >/dev/null || fail "CODEX.txt missing docs/CIRC.md invariant reference"
  rg -n --fixed-strings "docs/CEC.md" CODEX.txt >/dev/null || fail "CODEX.txt missing docs/CEC.md invariant reference"
  rg -n --fixed-strings "docs/CONTRACT_GLOSSARY.md" CODEX.txt >/dev/null || fail "CODEX.txt missing docs/CONTRACT_GLOSSARY.md reference"
  rg -n --fixed-strings "crates/types/src/app/events.rs" CODEX.txt >/dev/null || fail "CODEX.txt missing canonical workload type path reference"
  for stale in \
    "crates/types/src/workloads/spec.rs" \
    "crates/services/src/search/mod.rs"; do
    if rg -n --fixed-strings "$stale" CODEX.txt >/dev/null; then
      fail "stale path reference detected in CODEX.txt: $stale"
    fi
  done
fi

echo "contract-invariants: OK"
