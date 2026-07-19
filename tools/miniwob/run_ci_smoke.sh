#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

export COMPUTER_USE_SUITE_MODE="${COMPUTER_USE_SUITE_MODE:-agent}"
export COMPUTER_USE_SUITE_AGENT_BACKEND="${COMPUTER_USE_SUITE_AGENT_BACKEND:-live_http}"
export COMPUTER_USE_SUITE_TASK_SET="${COMPUTER_USE_SUITE_TASK_SET:-smoke}"

cd "${REPO_ROOT}"

cargo test -p ioi-cli --test computer_use_suite_e2e --no-run
"${SCRIPT_DIR}/run_suite.sh"
