#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MODE="${1:-x11}"
if [[ $# -gt 0 ]]; then
  shift
fi
EXTRA_ARGS=("$@")

BASIC_QUERY="${HYPERVISOR_BASIC_QUERY:-Summarize what you can help me do in this repository in one short paragraph.}"

echo "Launching Hypervisor Code editor adapter host with real inference."
echo "Use this basic dry-run query once the shell is ready:"
echo "  ${BASIC_QUERY}"

cd "$ROOT_DIR"
export HYPERVISOR_LOCAL_GPU_DEV=1
export HYPERVISOR_RESET_DATA_ON_BOOT="${HYPERVISOR_RESET_DATA_ON_BOOT:-1}"

if [[ "$MODE" == "wayland" ]]; then
  npm run dev:hypervisor-code-editor-adapter-host:wayland -- "${EXTRA_ARGS[@]}"
else
  npm run dev:hypervisor-code-editor-adapter-host -- "${EXTRA_ARGS[@]}"
fi
