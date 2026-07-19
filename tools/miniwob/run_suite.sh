#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ -z "${COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR:-}" ]]; then
  echo "COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR must point at a MiniWoB++ checkout." >&2
  exit 1
fi

export COMPUTER_USE_SUITE_MODE="${COMPUTER_USE_SUITE_MODE:-agent}"
export COMPUTER_USE_SUITE_AGENT_BACKEND="${COMPUTER_USE_SUITE_AGENT_BACKEND:-live_http}"
export COMPUTER_USE_SUITE_TASK_SET="${COMPUTER_USE_SUITE_TASK_SET:-smoke}"
export COMPUTER_USE_SUITE_PYTHON="${COMPUTER_USE_SUITE_PYTHON:-python3}"

cd "${REPO_ROOT}"

cargo test \
  -p ioi-cli \
  --test computer_use_suite_e2e \
  computer_use_suite_from_env \
  -- \
  --ignored \
  --nocapture
