#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MODE="${1:-x11}"
if [[ $# -gt 0 ]]; then
  shift
fi
EXTRA_TAURI_ARGS=("$@")

BASIC_QUERY="${AUTOPILOT_BASIC_QUERY:-Summarize what you can help me do in this repository in one short paragraph.}"

echo "Launching Autopilot desktop with real inference."
echo "Use this basic dry-run query once the shell is ready:"
echo "  ${BASIC_QUERY}"

cd "$ROOT_DIR"
AUTOPILOT_LOCAL_GPU_DEV=1 \
AUTOPILOT_RESET_DATA_ON_BOOT="${AUTOPILOT_RESET_DATA_ON_BOOT:-1}" \
bash apps/autopilot/scripts/dev-desktop.sh "$MODE" "${EXTRA_TAURI_ARGS[@]}"
