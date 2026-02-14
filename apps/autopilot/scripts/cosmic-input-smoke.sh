#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LOG_ROOT="${LOG_ROOT:-$ROOT_DIR/.tmp/cosmic-input-smoke}"
MODE="${1:-x11}"
DEV_URL="${DEV_URL:-http://127.0.0.1:1428}"
AUTO_START_DEV_SERVER="${AUTO_START_DEV_SERVER:-1}"
TAURI_TIMEOUT_SECONDS="${TAURI_TIMEOUT_SECONDS:-40}"
TEXT="${TEXT:-probe$(date +%s)}"
TAURI_CONFIG="{\"build\":{\"beforeDevCommand\":\"\",\"devUrl\":\"${DEV_URL}\"}}"

timestamp="$(date +%Y%m%d-%H%M%S)"
run_dir="$LOG_ROOT/$timestamp-$MODE"
mkdir -p "$run_dir"
tauri_log="$run_dir/tauri.log"
dev_log="$run_dir/dev-server.log"

dev_server_pid=""
tauri_pid=""

cleanup() {
  if [[ -n "$tauri_pid" ]] && kill -0 "$tauri_pid" >/dev/null 2>&1; then
    kill "$tauri_pid" >/dev/null 2>&1 || true
    wait "$tauri_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$dev_server_pid" ]] && kill -0 "$dev_server_pid" >/dev/null 2>&1; then
    kill "$dev_server_pid" >/dev/null 2>&1 || true
    wait "$dev_server_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if ! curl -fsS "$DEV_URL" >/dev/null 2>&1; then
  if [[ "$AUTO_START_DEV_SERVER" != "1" ]]; then
    echo "Dev server not reachable at $DEV_URL"
    exit 1
  fi

  dev_port="${DEV_URL##*:}"
  echo "Starting isolated Vite dev server on port ${dev_port}..."
  (
    cd "$ROOT_DIR"
    npm run dev --workspace=apps/autopilot -- --host 127.0.0.1 --port "$dev_port" --strictPort
  ) >"$dev_log" 2>&1 &
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
    echo "Timed out waiting for dev server; see $dev_log"
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

echo "Launching Tauri (${MODE})..."
(
  cd "$ROOT_DIR"
  "${mode_prefix[@]}" AUTOPILOT_INPUT_PROBE_LOG=1 timeout "${TAURI_TIMEOUT_SECONDS}s" \
    npm run tauri --workspace=apps/autopilot -- dev --no-watch --config "$TAURI_CONFIG"
) >"$tauri_log" 2>&1 &
tauri_pid=$!

setup_ready=0
for _ in $(seq 1 90); do
  if rg -q "\[Autopilot\] Setup complete\." "$tauri_log"; then
    setup_ready=1
    break
  fi
  if ! kill -0 "$tauri_pid" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if [[ "$setup_ready" != "1" ]]; then
  echo "Tauri app did not reach setup-ready state; see $tauri_log"
  exit 1
fi

echo "Injecting text into spotlight window: $TEXT"
if [[ "$MODE" == "x11" ]]; then
  DISPLAY="${DISPLAY:-:1}" python3 "$ROOT_DIR/apps/autopilot/scripts/x11_type_probe.py" \
    --title "Autopilot" \
    --text "$TEXT" \
    --press-enter \
    --startup-timeout 8
else
  if ! command -v wtype >/dev/null 2>&1; then
    echo "Wayland input injection requires 'wtype', which is not installed."
    echo "Install wtype or use x11 mode for unattended input probes."
    exit 3
  fi
  wtype "$TEXT"
  wtype -k Return
fi

# Allow event loop to process input + submit.
sleep 2

if kill -0 "$tauri_pid" >/dev/null 2>&1; then
  kill "$tauri_pid" >/dev/null 2>&1 || true
  wait "$tauri_pid" >/dev/null 2>&1 || true
fi
tauri_pid=""

if rg -q "\[Autopilot\]\[InputProbe\] start_task" "$tauri_log" && rg -q "intent='${TEXT}'" "$tauri_log"; then
  echo "PASS: input reached start_task"
  echo "log: $tauri_log"
  exit 0
fi

if rg -q "\[Autopilot\]\[InputProbe\] continue_task" "$tauri_log" && rg -q "input='${TEXT}'" "$tauri_log"; then
  echo "PASS: input reached continue_task"
  echo "log: $tauri_log"
  exit 0
fi

echo "FAIL: probe text did not reach start_task/continue_task"
echo "log: $tauri_log"
exit 2
