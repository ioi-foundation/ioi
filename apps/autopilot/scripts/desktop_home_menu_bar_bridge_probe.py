#!/usr/bin/env python3
"""Validate the Home onboarding menu-bar action targets hot OpenVSCode without route reload."""

from __future__ import annotations

import argparse
import json
import os
import re
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
    PROJECT_ROOT / "docs/evidence/route-hierarchy/live-home-onboarding-menu-bar-bridge"
)
DEFAULT_DEV_URL = DEFAULT_WEB_ROOT
WINDOW_WAIT_TIMEOUT_SECS = 120.0
POST_WINDOW_SETTLE_SECS = 6.0
ACTION_SETTLE_SECS = 1.4
MENU_BAR_ACTION_CLICK = (0.242, 0.887)

SHOW_VISIBLE_TRUE_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] show requested surface=\S+ parent=\S+ visible=true "
)
SHOW_VISIBLE_FALSE_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] show requested surface=\S+ parent=\S+ visible=false "
)
DESTROY_PATTERN = re.compile(r"\[WorkspaceDirectWebview\] destroy requested ")
QUEUED_PATTERN = re.compile(
    r"\[Workspace IDE\] bridge command queued .* command=workbench\.action\.toggleMenuBar"
)
DRAINED_PATTERN = re.compile(
    r"\[Workspace IDE\] bridge commands drained .*workbench\.action\.toggleMenuBar"
)


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


def send_keys(window_id: int, *keys: str) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    run(["xdotool", "key", *keys], check=False)
    time.sleep(ACTION_SETTLE_SECS)


def type_text(window_id: int, text: str) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    run(["xdotool", "type", "--delay", "8", text], check=False)
    time.sleep(ACTION_SETTLE_SECS)


def capture_step(window_id: int, output_root: Path, step_id: str) -> dict[str, Any]:
    screenshot_path = output_root / f"{step_id}.png"
    capture_result = capture_window_with_fallback(
        window_id,
        screenshot_path,
        browser_url=f"{DEFAULT_WEB_ROOT}/?view=home",
    )
    return {
        "id": step_id,
        "screenshot": str(screenshot_path) if screenshot_path.exists() else None,
        "captureMode": capture_result.mode,
        "captureError": capture_result.error,
        "captureDiagnostics": capture_result.diagnostics,
    }


def focus_menu_bar_step(window_id: int) -> None:
    send_keys(window_id, "ctrl+k")
    type_text(window_id, "Home: Toggle Menu Bar")
    send_keys(window_id, "Return")


def log_facts(log_path: Path) -> dict[str, Any]:
    text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    return {
        "hiddenPrewarmCount": len(SHOW_VISIBLE_FALSE_PATTERN.findall(text)),
        "visibleShowCount": len(SHOW_VISIBLE_TRUE_PATTERN.findall(text)),
        "destroyCount": len(DESTROY_PATTERN.findall(text)),
        "toggleCommandQueued": bool(QUEUED_PATTERN.search(text)),
        "toggleCommandDrained": bool(DRAINED_PATTERN.search(text)),
    }


def wait_for_hidden_prewarm(log_path: Path, *, timeout_secs: float = 90.0) -> None:
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        if log_facts(log_path)["hiddenPrewarmCount"] >= 1:
            return
        time.sleep(1.0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    parser.add_argument("--window-name", default=WINDOW_SEARCH_PATTERN)
    parser.add_argument("--timeout-secs", type=float, default=WINDOW_WAIT_TIMEOUT_SECS)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--dev-url", default=DEFAULT_DEV_URL)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_root = Path(args.output_root).expanduser() / now_stamp()
    output_root.mkdir(parents=True, exist_ok=True)
    log_path = output_root / "desktop.log"

    close_matching_windows(args.window_name)
    terminate_existing_desktop_instances()
    os.environ["VITE_AUTOPILOT_RESET_HOME_ONBOARDING"] = "1"
    os.environ.pop("AUTOPILOT_WORKSPACE_DIRECT_WEBVIEW_MODE", None)

    process = launch_dev_desktop(
        args.profile,
        log_path,
        args.dev_url,
        workspace_host="direct-openvscode",
        initial_view="home",
    )
    print("[home-menu-bar] launched desktop shell", flush=True)

    probe_error: str | None = None
    window_id: int | None = None
    parent_geometry: dict[str, int] = {}
    steps: list[dict[str, Any]] = []

    try:
        window_id = wait_for_window(args.window_name, timeout_secs=args.timeout_secs)
        if window_id is None:
            raise RuntimeError(f"Timed out waiting for a window matching {args.window_name!r}")
        focus_workspace_view(window_id)
        time.sleep(POST_WINDOW_SETTLE_SECS)
        wait_for_hidden_prewarm(log_path)

        focus_menu_bar_step(window_id)
        steps.append(capture_step(window_id, output_root, "00-menu-bar-step-focused"))

        click_window_ratio(window_id, *MENU_BAR_ACTION_CLICK)
        time.sleep(5.0)
        steps.append(capture_step(window_id, output_root, "01-toggle-stays-on-home"))
        parent_geometry = window_geometry(window_id)
    except Exception as error:
        probe_error = str(error)
        if window_id is not None:
            try:
                parent_geometry = window_geometry(window_id)
            except Exception:
                parent_geometry = {}
    finally:
        terminate_process_group(process)

    facts = log_facts(log_path)
    assertions = {
        "hidden_workbench_was_prewarmed": facts["hiddenPrewarmCount"] >= 1,
        "toggle_command_queued": facts["toggleCommandQueued"],
        "toggle_command_drained_by_workbench": facts["toggleCommandDrained"],
        "toggle_did_not_show_workspace": facts["visibleShowCount"] == 0,
        "toggle_did_not_destroy_surface": facts["destroyCount"] == 0,
        "screenshots_retained": all(step.get("screenshot") for step in steps),
    }
    if probe_error is None and not all(assertions.values()):
        probe_error = "One or more menu-bar bridge assertions failed."

    bundle = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "profile": args.profile,
        "windowId": window_id,
        "parentGeometry": parent_geometry,
        "probe_error": probe_error,
        "steps": steps,
        "facts": facts,
        "assertions": assertions,
        "log_tail": read_log_tail(log_path),
    }
    result_path = output_root / "result.json"
    result_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"[home-menu-bar] results: {result_path}", flush=True)
    return 0 if probe_error is None else 1


if __name__ == "__main__":
    sys.exit(main())
