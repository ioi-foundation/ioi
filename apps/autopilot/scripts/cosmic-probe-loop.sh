#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LOG_ROOT="${LOG_ROOT:-$ROOT_DIR/.tmp/cosmic-probe}"
DURATION_SECONDS="${DURATION_SECONDS:-25}"
MODE="${1:-x11}"
DEV_URL="${DEV_URL:-http://127.0.0.1:1428}"
AUTO_START_DEV_SERVER="${AUTO_START_DEV_SERVER:-1}"
TAURI_CONFIG="{\"build\":{\"beforeDevCommand\":\"\",\"devUrl\":\"${DEV_URL}\"}}"

timestamp="$(date +%Y%m%d-%H%M%S)"
run_dir="$LOG_ROOT/$timestamp-$MODE"
mkdir -p "$run_dir"

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
    echo "Set AUTO_START_DEV_SERVER=1 or start frontend manually."
    exit 1
  fi

  dev_port="${DEV_URL##*:}"
  echo "Starting isolated Vite dev server on port ${dev_port}..."
  (
    cd "$ROOT_DIR"
    npm run dev --workspace=apps/autopilot -- --host 127.0.0.1 --port "$dev_port" --strictPort
  ) >"$run_dir/dev-server.log" 2>&1 &
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
    echo "See $run_dir/dev-server.log"
    exit 1
  fi
fi

if [[ "$MODE" == "x11" ]]; then
  mode_prefix=(env -u WAYLAND_DISPLAY XDG_SESSION_TYPE=x11 GDK_BACKEND=x11 WINIT_UNIX_BACKEND=x11)
elif [[ "$MODE" == "wayland" ]]; then
  mode_prefix=(env)
else
  echo "Unknown mode '$MODE' (expected: x11|wayland)"
  exit 1
fi

summary_pattern="Linux spotlight docking backend|Layout dock=|COSMIC compositor is overriding|Wayland layer-shell|runtime fallback|Could not find X11 window to focus|Reconciled COSMIC tiling exceptions|\\[Autopilot\\].*failed|\\[Autopilot\\].*Error"

run_case() {
  local name="$1"
  shift || true
  local log_file="$run_dir/$name.log"

  echo ""
  echo "=== $name ==="
  echo "log: $log_file"

  (
    cd "$ROOT_DIR"
    "${mode_prefix[@]}" "$@" timeout "${DURATION_SECONDS}s" \
      npm run tauri --workspace=apps/autopilot -- dev --no-watch --config "$TAURI_CONFIG"
  ) >"$log_file" 2>&1 || true

  if ! rg -n "$summary_pattern" "$log_file"; then
    echo "(no summary lines matched)"
  fi
}

if [[ "$MODE" == "x11" ]]; then
  run_case "x11-default"
  run_case "x11-managed" AUTOPILOT_COSMIC_UNMANAGED_RIGHT_DOCK=0
  run_case "x11-shelldock" AUTOPILOT_COSMIC_UNMANAGED_RIGHT_DOCK=0 AUTOPILOT_COSMIC_SHELL_DOCK=1
else
  run_case "wayland-default"
  run_case "wayland-force-legacy" AUTOPILOT_WAYLAND_FORCE_LEGACY=1
  run_case "wayland-layer-shell-off" AUTOPILOT_WAYLAND_LAYER_SHELL=0
fi

echo ""
echo "Probe run complete: $run_dir"
