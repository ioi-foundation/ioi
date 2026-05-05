#!/usr/bin/env bash
set -uo pipefail

FEATURES="${IOI_RELIABILITY_FEATURES:-consensus-aft vm-wasm state-iavl}"
ARTIFACT_ROOT="${IOI_RELIABILITY_ARTIFACT_ROOT:-.artifacts/reliability_phase0}"

mkdir -p "${ARTIFACT_ROOT}"
declare -a FAILURES=()

if command -v dbus-run-session >/dev/null 2>&1 && command -v xvfb-run >/dev/null 2>&1; then
  DISPLAY_CMD=(dbus-run-session -- xvfb-run -a)
elif command -v xvfb-run >/dev/null 2>&1; then
  DISPLAY_CMD=(xvfb-run -a)
elif [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]]; then
  DISPLAY_CMD=()
else
  echo "Phase-0 reliability gate requires xvfb-run or an active DISPLAY/WAYLAND session." >&2
  exit 1
fi

run_with_display() {
  if [[ ${#DISPLAY_CMD[@]} -gt 0 ]]; then
    "${DISPLAY_CMD[@]}" "$@"
  else
    "$@"
  fi
}

run_step() {
  local name="$1"
  shift

  echo "[phase0-gate] ${name}"
  if "$@"; then
    echo "[phase0-gate] pass: ${name}"
  else
    echo "[phase0-gate] fail: ${name}" >&2
    FAILURES+=("${name}")
  fi
}

run_browser_reliability() {
  run_with_display \
    env \
      IOI_RELIABILITY_REQUIRE_DISPLAY=1 \
      IOI_RELIABILITY_ARTIFACT_DIR="${PWD}/${ARTIFACT_ROOT}/browser" \
      cargo test --locked -p ioi-cli --test reliability_suite_e2e --features "${FEATURES}" \
      "reliability_suite::browser_snapshot_click::browser_snapshot_then_click_element_updates_fixture" \
      -- --ignored --exact --nocapture
}

run_gui_reliability() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required for GUI reliability fixture." >&2
    return 1
  fi

  if ! python3 - <<'PY' >/dev/null 2>&1
import tkinter
PY
  then
    echo "GUI reliability requires python tkinter (python3-tk) to run the fixture app." >&2
    return 1
  fi

  run_with_display \
    env \
      IOI_RELIABILITY_REQUIRE_GUI=1 \
      IOI_RELIABILITY_ARTIFACT_DIR="${PWD}/${ARTIFACT_ROOT}/gui" \
      cargo test --locked -p ioi-cli --test reliability_suite_e2e --features "${FEATURES}" \
      "reliability_suite::gui_snapshot_click::gui_snapshot_then_click_element_emits_click_input" \
      -- --ignored --exact --nocapture
}

run_shell_reliability() {
  cargo test --locked -p ioi-cli --test reliability_suite_e2e --features "${FEATURES}" \
    "reliability_suite::sys_exec_session::sys_exec_session_continuity_reset_failure_receipts_and_anti_loop" \
    -- --ignored --exact --nocapture
}

run_web_reliability() {
  cargo test --locked -p ioi-cli --test reliability_suite_e2e --features "${FEATURES}" \
    "reliability_suite::web_retrieval::web_retrieval_and_net_fetch_emit_deterministic_receipts_and_anti_loop" \
    -- --ignored --exact --nocapture
}

run_step "browser reliability" run_browser_reliability
run_step "gui reliability" run_gui_reliability
run_step "shell continuity reliability" run_shell_reliability
run_step "web retrieval reliability" run_web_reliability

if [[ ${#FAILURES[@]} -gt 0 ]]; then
  echo "[phase0-gate] failed steps: ${FAILURES[*]}" >&2
  exit 1
fi

echo "[phase0-gate] completed"
