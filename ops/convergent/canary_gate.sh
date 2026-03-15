#!/usr/bin/env bash
set -euo pipefail

REQUIRED_ENV_VARS=(
  CONVERGENT_GUARDIAN_CERT_P95_MS
  CONVERGENT_REGISTRY_LAG_MS
  CONVERGENT_CHECKPOINT_LAG_MS
)

for name in "${REQUIRED_ENV_VARS[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "missing required env var: ${name}" >&2
    exit 1
  fi
done

if (( CONVERGENT_GUARDIAN_CERT_P95_MS > 2000 )); then
  echo "guardian certificate latency p95 too high: ${CONVERGENT_GUARDIAN_CERT_P95_MS}ms" >&2
  exit 1
fi

if (( CONVERGENT_REGISTRY_LAG_MS > 60000 )); then
  echo "registry lag too high: ${CONVERGENT_REGISTRY_LAG_MS}ms" >&2
  exit 1
fi

if (( CONVERGENT_CHECKPOINT_LAG_MS > 60000 )); then
  echo "checkpoint lag too high: ${CONVERGENT_CHECKPOINT_LAG_MS}ms" >&2
  exit 1
fi

echo "Convergent canary gate passed."
