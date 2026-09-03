#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

SOURCE="crates/agentgres/src/consequence.rs"

require_pattern() {
  local pattern="$1"
  local description="$2"
  if ! rg -U -q -- "${pattern}" "${SOURCE}"; then
    echo "AFT production-authorization gate failed: ${description}" >&2
    exit 1
  fi
}

require_pattern 'pub fn authorize\([[:space:][:print:]]*achieved: &VerifiedGuaranteeV1' \
  'ConsequenceStore::authorize no longer requires opaque VerifiedGuaranteeV1'
require_pattern 'manifest\.required_guarantees\.is_satisfied_by\(achieved\)' \
  'effect policy is not evaluated against the opaque verified vector'
require_pattern 'AcceptedEffectAuthorizationV1::from_committed|pub fn from_committed' \
  'the Agentgres-committed authorization constructor is absent'
require_pattern 'verify_runtime_bundle_v3\(&committed\.record\.bundle\)' \
  'committed runtime-v3 evidence is not reverified at the consequence boundary'
require_pattern 'manifest\.irreversible && !manifest\.resource_profile\.contract\.supports_at_most_once\(\)' \
  'irreversible effects are not fenced by the modeled atomic resource contract'

if rg -q 'GuaranteeVectorV1' "${SOURCE}"; then
  echo 'AFT production-authorization gate failed: raw GuaranteeVectorV1 reached consequence authorization' >&2
  exit 1
fi

mapfile -t invocation_files < <(
  rg -l 'invoke_atomic\(' crates --glob '*.rs' --glob '!**/tests.rs' --glob '!**/tests/**' | sort
)
if [[ "${#invocation_files[@]}" -ne 1 || "${invocation_files[0]}" != "${SOURCE}" ]]; then
  echo 'AFT production-authorization gate failed: external mutation exists outside the governed consequence boundary' >&2
  printf '  %s\n' "${invocation_files[@]}" >&2
  exit 1
fi

mapfile -t resource_trait_files < <(
  rg -l '(^|[[:space:]])(pub )?trait ExternalResourceV1|impl ExternalResourceV1' \
    crates --glob '*.rs' --glob '!**/tests.rs' --glob '!**/tests/**' | sort
)
if [[ "${#resource_trait_files[@]}" -ne 1 || "${resource_trait_files[0]}" != "${SOURCE}" ]]; then
  echo 'AFT production-authorization gate failed: production ExternalResourceV1 surface escaped its audited owner' >&2
  printf '  %s\n' "${resource_trait_files[@]}" >&2
  exit 1
fi

echo 'AFT production authorization OK: one external-mutation owner; opaque GuaranteeVectorV1 verification and atomic-resource fence are mandatory'
