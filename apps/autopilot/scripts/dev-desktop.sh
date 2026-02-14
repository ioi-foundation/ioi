#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MODE="${1:-x11}"
if [[ $# -gt 0 ]]; then
  shift
fi
EXTRA_TAURI_ARGS=("$@")

DEV_URL="${DEV_URL:-http://127.0.0.1:1428}"
AUTO_START_DEV_SERVER="${AUTO_START_DEV_SERVER:-1}"
TAURI_WATCH="${AUTOPILOT_TAURI_WATCH:-0}"
TAURI_CONFIG="{\"build\":{\"beforeDevCommand\":\"\",\"devUrl\":\"${DEV_URL}\"}}"

if [[ "$MODE" == "x11" ]]; then
  mode_prefix=(env -u WAYLAND_DISPLAY XDG_SESSION_TYPE=x11 GDK_BACKEND=x11 WINIT_UNIX_BACKEND=x11)
elif [[ "$MODE" == "wayland" ]]; then
  mode_prefix=(env)
else
  echo "Unknown mode '$MODE' (expected: x11|wayland)"
  exit 1
fi

dev_server_pid=""
cleanup() {
  if [[ -n "$dev_server_pid" ]] && kill -0 "$dev_server_pid" >/dev/null 2>&1; then
    kill "$dev_server_pid" >/dev/null 2>&1 || true
    wait "$dev_server_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if ! curl -fsS "$DEV_URL" >/dev/null 2>&1; then
  if [[ "$AUTO_START_DEV_SERVER" != "1" ]]; then
    echo "Dev server not reachable at $DEV_URL"
    echo "Set AUTO_START_DEV_SERVER=1 or start the frontend manually."
    exit 1
  fi

  dev_port="${DEV_URL##*:}"
  echo "Starting isolated Vite dev server on port ${dev_port}..."
  (
    cd "$ROOT_DIR"
    npm run dev --workspace=apps/autopilot -- --host 127.0.0.1 --port "$dev_port" --strictPort
  ) >/tmp/autopilot-dev-server.log 2>&1 &
  dev_server_pid=$!

  ready=0
  for _ in $(seq 1 90); do
    if curl -fsS "$DEV_URL" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done

  if [[ "$ready" != "1" ]]; then
    echo "Timed out waiting for dev server at $DEV_URL"
    echo "See /tmp/autopilot-dev-server.log"
    exit 1
  fi
fi

tauri_args=(dev --config "$TAURI_CONFIG")
if [[ "$TAURI_WATCH" != "1" ]]; then
  tauri_args+=(--no-watch)
fi
tauri_args+=("${EXTRA_TAURI_ARGS[@]}")

(
  cd "$ROOT_DIR"
  # COSMIC/X11 dev defaults:
  # - unmanaged right-dock avoids compositor recenter/tiling overrides
  # - shell-dock fullscreen stays off unless explicitly requested
  "${mode_prefix[@]}" \
    AUTOPILOT_COSMIC_UNMANAGED_RIGHT_DOCK="${AUTOPILOT_COSMIC_UNMANAGED_RIGHT_DOCK:-1}" \
    AUTOPILOT_COSMIC_SHELL_DOCK="${AUTOPILOT_COSMIC_SHELL_DOCK:-0}" \
    npm run tauri --workspace=apps/autopilot -- "${tauri_args[@]}"
)
