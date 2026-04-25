#!/usr/bin/env python3
"""Exercise Autopilot Home onboarding in the real desktop shell.

The probe validates the Home surface as a product route rather than a static
mock: it launches the Tauri desktop app into Home, maximizes the parent window,
captures the onboarding layout, changes appearance, routes through the command
palette, and hands off to the contained direct OpenVSCode Workspace.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from desktop_capture import capture_window_with_fallback
from desktop_workspace_activity_probe import click_window_ratio, window_geometry
from desktop_workspace_probe import (
    DEFAULT_PROFILE,
    DEFAULT_WEB_ROOT,
    WINDOW_SEARCH_PATTERN,
    close_matching_windows,
    focus_workspace_view,
    launch_dev_desktop,
    now_stamp,
    read_log_tail,
    terminate_existing_desktop_instances,
    terminate_process_group,
    wait_for_window,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT / "docs/evidence/route-hierarchy/live-home-onboarding-layout-parity"
)
DEFAULT_DEV_URL = DEFAULT_WEB_ROOT
BROWSER_CAPTURE_URL = f"{DEFAULT_WEB_ROOT}/?view=home"
WINDOW_WAIT_TIMEOUT_SECS = 90.0
POST_WINDOW_SETTLE_SECS = 4.0
ACTION_SETTLE_SECS = 1.4
NEXT_SECTION_CLICK = (0.237, 0.809)
WORKSPACE_STEP_ACTION_CLICK = (0.177, 0.637)

EXPECTED_STEP_CAPTURES = [
  "01-setup-theme",
  "02-setup-ui-density",
  "03-setup-language-extensions",
  "04-setup-command-palette",
  "05-setup-quick-open",
  "06-fundamentals-extensions",
  "07-fundamentals-terminal",
  "08-fundamentals-debug",
  "09-fundamentals-git",
  "10-fundamentals-tasks",
  "11-fundamentals-shortcuts",
  "12-accessibility-help",
]

STEP_COMMAND_LABELS = {
  "03-setup-language-extensions": "Home: Browse Language Extensions",
  "04-setup-command-palette": "Home: Open Command Palette",
  "05-setup-quick-open": "Home: Quick Open A File",
  "06-fundamentals-extensions": "Home: Browse Extensions",
  "07-fundamentals-terminal": "Home: Open Terminal",
  "08-fundamentals-debug": "Home: Run Project",
  "09-fundamentals-git": "Home: Open Source Control",
  "10-fundamentals-tasks": "Home: Run Tasks",
  "11-fundamentals-shortcuts": "Home: Open Keyboard Shortcuts",
  "12-accessibility-help": "Home: Open Accessibility Help",
}

FORBIDDEN_FIRST_RUN_STRINGS = [
  "chat-home-checklist",
  "chat-home-context",
  "chat-home-source-card",
  "Current scope",
  "Quick routes",
]


def run(
  cmd: list[str],
  *,
  check: bool = True,
  capture_output: bool = True,
  text: bool = True,
) -> subprocess.CompletedProcess[str]:
  completed = subprocess.run(
    cmd,
    check=False,
    capture_output=capture_output,
    text=text,
  )
  if check and completed.returncode != 0:
    raise RuntimeError(
      f"Command failed ({completed.returncode}): {' '.join(cmd)}\n"
      f"stdout:\n{completed.stdout}\n"
      f"stderr:\n{completed.stderr}"
    )
  return completed


def maximize_window(window_id: int) -> None:
  run(["wmctrl", "-ir", hex(window_id), "-b", "add,maximized_vert,maximized_horz"], check=False)
  run(
    [
      "xdotool",
      "windowmove",
      str(window_id),
      "0",
      "32",
      "windowsize",
      str(window_id),
      "1920",
      "976",
    ],
    check=False,
  )
  time.sleep(0.4)


def send_keys(window_id: int, *keys: str) -> None:
  run(["xdotool", "windowactivate", str(window_id)], check=False)
  run(["xdotool", "key", *keys], check=False)
  time.sleep(ACTION_SETTLE_SECS)


def type_text(window_id: int, text: str) -> None:
  run(["xdotool", "windowactivate", str(window_id)], check=False)
  run(["xdotool", "type", "--delay", "8", text], check=False)
  time.sleep(ACTION_SETTLE_SECS)


def capture_step(
  window_id: int,
  output_root: Path,
  step_id: str,
  *,
  browser_url: str | None = BROWSER_CAPTURE_URL,
) -> dict[str, Any]:
  print(f"[home-onboarding] capture {step_id}", flush=True)
  screenshot_path = output_root / f"{step_id}.png"
  capture_result = capture_window_with_fallback(
    window_id,
    screenshot_path,
    browser_url=browser_url,
  )
  return {
    "id": step_id,
    "screenshot": str(screenshot_path) if screenshot_path.exists() else None,
    "capture_mode": capture_result.mode,
    "capture_error": capture_result.error,
    "capture_diagnostics": capture_result.diagnostics,
  }


def focus_onboarding_step(window_id: int, command_label: str) -> None:
  send_keys(window_id, "ctrl+k")
  type_text(window_id, command_label)
  send_keys(window_id, "Return")
  time.sleep(ACTION_SETTLE_SECS)


def static_negative_layout_assertions() -> dict[str, bool]:
  component_path = (
    PROJECT_ROOT
    / "apps/autopilot/src/surfaces/Home/HomeWalkthroughDocument.tsx"
  )
  component_text = component_path.read_text(encoding="utf-8")
  return {
    forbidden: forbidden not in component_text
    for forbidden in FORBIDDEN_FIRST_RUN_STRINGS
  }


def screenshot_digest(step: dict[str, Any]) -> str | None:
  screenshot = step.get("screenshot")
  if not screenshot:
    return None
  screenshot_path = Path(str(screenshot))
  if not screenshot_path.exists():
    return None
  return hashlib.sha256(screenshot_path.read_bytes()).hexdigest()


def distinct_route_screenshot_count(steps: list[dict[str, Any]]) -> int:
  digests = {
    digest
    for step in steps
    if step.get("id") in EXPECTED_STEP_CAPTURES
    for digest in [screenshot_digest(step)]
    if digest
  }
  return len(digests)


def digest_for_step(steps: list[dict[str, Any]], step_id: str) -> str | None:
  for step in steps:
    if step.get("id") == step_id:
      return screenshot_digest(step)
  return None


def assertions_pass(value: Any) -> bool:
  if isinstance(value, bool):
    return value
  if isinstance(value, dict):
    return all(assertions_pass(child) for child in value.values())
  if isinstance(value, list):
    return all(assertions_pass(child) for child in value)
  return True


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
    "--output-root",
    default=str(DEFAULT_OUTPUT_ROOT),
    help=f"Directory to retain screenshots and receipts. Default: {DEFAULT_OUTPUT_ROOT}",
  )
  parser.add_argument(
    "--window-name",
    default=WINDOW_SEARCH_PATTERN,
    help=f"Window title pattern to target. Default: {WINDOW_SEARCH_PATTERN!r}",
  )
  parser.add_argument(
    "--timeout-secs",
    type=float,
    default=WINDOW_WAIT_TIMEOUT_SECS,
    help="How long to wait for the desktop window to appear.",
  )
  parser.add_argument(
    "--profile",
    default=DEFAULT_PROFILE,
    help=f"Desktop profile to launch. Default: {DEFAULT_PROFILE}",
  )
  parser.add_argument(
    "--dev-url",
    default=DEFAULT_DEV_URL,
    help=f"Dev server URL to start. Default: {DEFAULT_DEV_URL}",
  )
  return parser.parse_args()


def main() -> int:
  args = parse_args()
  output_root = Path(args.output_root).expanduser() / now_stamp()
  output_root.mkdir(parents=True, exist_ok=True)
  log_path = output_root / "desktop.log"

  close_matching_windows(args.window_name)
  terminate_existing_desktop_instances()
  os.environ["VITE_AUTOPILOT_RESET_HOME_ONBOARDING"] = "1"

  process = launch_dev_desktop(
    args.profile,
    log_path,
    args.dev_url,
    workspace_host="direct-openvscode",
    initial_view="home",
  )
  print("[home-onboarding] launched desktop shell", flush=True)

  probe_error: str | None = None
  window_id: int | None = None
  steps: list[dict[str, Any]] = []

  try:
    window_id = wait_for_window(args.window_name, timeout_secs=args.timeout_secs)
    if window_id is None:
      raise RuntimeError(f"Timed out waiting for a window matching {args.window_name!r}")
    print(f"[home-onboarding] window {window_id} ready", flush=True)

    focus_workspace_view(window_id)
    time.sleep(POST_WINDOW_SETTLE_SECS)
    steps.append(capture_step(window_id, output_root, "00-normal-first-run"))

    maximize_window(window_id)
    time.sleep(POST_WINDOW_SETTLE_SECS)
    geometry = window_geometry(window_id)

    steps.append(capture_step(window_id, output_root, EXPECTED_STEP_CAPTURES[0]))

    click_window_ratio(window_id, *NEXT_SECTION_CLICK)
    steps.append(capture_step(window_id, output_root, EXPECTED_STEP_CAPTURES[1]))

    for step_id in EXPECTED_STEP_CAPTURES[2:]:
      focus_onboarding_step(window_id, STEP_COMMAND_LABELS[step_id])
      steps.append(capture_step(window_id, output_root, step_id))

    focus_onboarding_step(window_id, "Home: Browse Language Extensions")
    steps.append(capture_step(window_id, output_root, "13-palette-language-route"))

    click_window_ratio(window_id, *WORKSPACE_STEP_ACTION_CLICK)
    time.sleep(8.0)
    steps.append(
      capture_step(
        window_id,
        output_root,
        "14-workspace-handoff-contained",
        browser_url=f"{DEFAULT_WEB_ROOT}/?view=workspace",
      )
    )
  except Exception as error:
    probe_error = str(error)
    geometry = window_geometry(window_id) if window_id is not None else {}
  finally:
    terminate_process_group(process)

  assertions = {
    "normal_first_run_captured": any(step["id"] == "00-normal-first-run" and step["screenshot"] for step in steps),
    "fullscreen_setup_theme_captured": any(step["id"] == "01-setup-theme" and step["screenshot"] for step in steps),
    "expected_walkthrough_steps_captured": all(
      any(step["id"] == expected_step and step["screenshot"] for step in steps)
      for expected_step in EXPECTED_STEP_CAPTURES
    ),
    "command_palette_route_captured": any(step["id"] == "13-palette-language-route" and step["screenshot"] for step in steps),
    "workspace_handoff_captured": any(step["id"] == "14-workspace-handoff-contained" and step["screenshot"] for step in steps),
    "next_section_advanced": digest_for_step(steps, "01-setup-theme") != digest_for_step(steps, "02-setup-ui-density"),
    "walkthrough_routes_advanced": distinct_route_screenshot_count(steps) >= 10,
    "workspace_handoff_advanced": digest_for_step(steps, "13-palette-language-route") != digest_for_step(steps, "14-workspace-handoff-contained"),
    "static_negative_first_run_layout": static_negative_layout_assertions(),
  }
  if probe_error is None and not assertions_pass(assertions):
    probe_error = "One or more onboarding layout assertions failed."

  bundle = {
    "captured_at": datetime.now(timezone.utc).isoformat(),
    "profile": args.profile,
    "windowId": window_id,
    "parentGeometry": geometry,
    "probe_error": probe_error,
    "steps": steps,
    "assertions": assertions,
    "log_tail": read_log_tail(log_path),
  }
  result_path = output_root / "result.json"
  result_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
  print(f"[home-onboarding] results: {result_path}", flush=True)
  return 0 if probe_error is None else 1


if __name__ == "__main__":
  sys.exit(main())
