#!/usr/bin/env python3
"""Validate the Autopilot Home skip flow and zero-state dashboard."""

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
  PROJECT_ROOT / "docs/evidence/route-hierarchy/live-home-zero-state"
)
DEFAULT_DEV_URL = DEFAULT_WEB_ROOT
HOME_CAPTURE_URL = f"{DEFAULT_WEB_ROOT}/?view=home"
WORKSPACE_CAPTURE_URL = f"{DEFAULT_WEB_ROOT}/?view=workspace"
WINDOW_WAIT_TIMEOUT_SECS = 90.0
POST_WINDOW_SETTLE_SECS = 4.0
ACTION_SETTLE_SECS = 1.3
SKIP_CLICK = (0.95, 0.073)
SEARCH_CLICK = (0.46, 0.158)
OPEN_WORKSPACE_CLICK = (0.281, 0.342)


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


def capture_step(
  window_id: int,
  output_root: Path,
  step_id: str,
  *,
  browser_url: str | None = HOME_CAPTURE_URL,
) -> dict[str, Any]:
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


def source_assertions() -> dict[str, bool]:
  home_path = PROJECT_ROOT / "apps/autopilot/src/surfaces/Home/HomeView.tsx"
  walkthrough_path = (
    PROJECT_ROOT
    / "apps/autopilot/src/surfaces/Home/HomeWalkthroughDocument.tsx"
  )
  css_path = PROJECT_ROOT / "apps/autopilot/src/surfaces/Home/Home.css"
  source = "\n".join(
    [
      home_path.read_text(encoding="utf-8"),
      walkthrough_path.read_text(encoding="utf-8"),
      css_path.read_text(encoding="utf-8"),
    ]
  )
  return {
    "skip_button_present": "Skip for now" in source
    and 'data-home-action="home.skipForNow"' in source,
    "autopilot_zero_state_present": 'data-home-dashboard-variant="autopilot-zero-state"' in source,
    "reference_brand_removed": all(
      forbidden not in source
      for forbidden in ["Palantir", "Foundry", "AIP Logic", "Newsletter"]
    ),
    "search_routes_to_palette": 'data-home-action="palette.open"' in source,
    "recommended_surfaces_autopilot_owned": "Recommended surfaces" in source
    and "IOI runtime authority" in source,
  }


def assertions_pass(value: Any) -> bool:
  if isinstance(value, bool):
    return value
  if isinstance(value, dict):
    return all(assertions_pass(child) for child in value.values())
  if isinstance(value, list):
    return all(assertions_pass(child) for child in value)
  return True


def screenshot_digest(steps: list[dict[str, Any]], step_id: str) -> str | None:
  for step in steps:
    if step.get("id") != step_id:
      continue
    screenshot = step.get("screenshot")
    if not screenshot:
      return None
    screenshot_path = Path(str(screenshot))
    if not screenshot_path.exists():
      return None
    return hashlib.sha256(screenshot_path.read_bytes()).hexdigest()
  return None


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

  probe_error: str | None = None
  window_id: int | None = None
  steps: list[dict[str, Any]] = []

  try:
    window_id = wait_for_window(args.window_name, timeout_secs=args.timeout_secs)
    if window_id is None:
      raise RuntimeError(f"Timed out waiting for a window matching {args.window_name!r}")

    focus_workspace_view(window_id)
    time.sleep(POST_WINDOW_SETTLE_SECS)
    steps.append(capture_step(window_id, output_root, "00-onboarding-skip-normal"))

    maximize_window(window_id)
    time.sleep(POST_WINDOW_SETTLE_SECS)
    geometry = window_geometry(window_id)
    steps.append(capture_step(window_id, output_root, "01-onboarding-skip-fullscreen"))

    click_window_ratio(window_id, *SKIP_CLICK)
    time.sleep(POST_WINDOW_SETTLE_SECS)
    steps.append(capture_step(window_id, output_root, "02-dashboard-after-skip"))

    click_window_ratio(window_id, *SEARCH_CLICK)
    time.sleep(ACTION_SETTLE_SECS)
    steps.append(capture_step(window_id, output_root, "03-dashboard-search-palette"))
    send_keys(window_id, "Escape")

    click_window_ratio(window_id, *OPEN_WORKSPACE_CLICK)
    time.sleep(8.0)
    steps.append(
      capture_step(
        window_id,
        output_root,
        "04-dashboard-workspace-handoff",
        browser_url=WORKSPACE_CAPTURE_URL,
      )
    )
  except Exception as error:
    probe_error = str(error)
    geometry = window_geometry(window_id) if window_id is not None else {}
  finally:
    terminate_process_group(process)

  assertions = {
    "source": source_assertions(),
    "onboarding_skip_captured": any(
      step["id"] == "01-onboarding-skip-fullscreen" and step["screenshot"]
      for step in steps
    ),
    "dashboard_after_skip_captured": any(
      step["id"] == "02-dashboard-after-skip" and step["screenshot"]
      for step in steps
    ),
    "search_palette_captured": any(
      step["id"] == "03-dashboard-search-palette" and step["screenshot"]
      for step in steps
    ),
    "workspace_handoff_captured": any(
      step["id"] == "04-dashboard-workspace-handoff" and step["screenshot"]
      for step in steps
    ),
    "search_palette_advanced": screenshot_digest(steps, "03-dashboard-search-palette")
    != screenshot_digest(steps, "02-dashboard-after-skip"),
    "workspace_handoff_advanced": screenshot_digest(steps, "04-dashboard-workspace-handoff")
    != screenshot_digest(steps, "02-dashboard-after-skip"),
  }
  if probe_error is None and not assertions_pass(assertions):
    probe_error = "One or more Home zero-state assertions failed."

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
  receipt_path = output_root / "receipt.md"
  receipt_path.write_text(
    "# Home zero-state evidence\n\n"
    f"- Captured at: `{bundle['captured_at']}`\n"
    f"- Probe error: `{probe_error}`\n"
    f"- Assertions pass: `{assertions_pass(assertions)}`\n"
    "- Scope: top-right onboarding skip, Autopilot-branded dashboard, search entry, workspace handoff.\n",
    encoding="utf-8",
  )
  print(f"[home-zero-state] results: {result_path}", flush=True)
  return 0 if probe_error is None else 1


if __name__ == "__main__":
  sys.exit(main())
