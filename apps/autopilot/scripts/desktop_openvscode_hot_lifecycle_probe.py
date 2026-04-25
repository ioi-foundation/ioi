#!/usr/bin/env python3
"""Prove contained direct OpenVSCode stays hot across Autopilot route changes."""

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
    PROJECT_ROOT / "docs/evidence/route-hierarchy/live-openvscode-direct/hot-lifecycle"
)
DEFAULT_DEV_URL = DEFAULT_WEB_ROOT
WINDOW_WAIT_TIMEOUT_SECS = 120.0
POST_WINDOW_SETTLE_SECS = 6.0
ROUTE_SETTLE_SECS = 2.5
ACTIVITY_HOME_CLICK = (0.019, 0.095)
ACTIVITY_CHAT_CLICK = (0.019, 0.166)
ACTIVITY_WORKSPACE_CLICK = (0.019, 0.237)

SHOW_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] show requested surface=(?P<surface>\S+) "
    r"parent=(?P<parent>\S+) visible=(?P<visible>\S+) "
)
CREATED_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] created (?P<mode>\S+) "
    r"surface=(?P<surface>\S+) label=(?P<label>\S+)"
)
REUSED_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] reused (?P<mode>\S+) "
    r"surface=(?P<surface>\S+) label=(?P<label>\S+)"
)
READY_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] ready (?P<mode>\S+) "
    r"surface=(?P<surface>\S+) label=(?P<label>\S+)"
)
HIDE_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] hide requested (?P<mode>\S+) "
    r"surface=(?P<surface>\S+) label=(?P<label>\S+)"
)
DESTROY_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] destroy requested (?P<mode>\S+) "
    r"surface=(?P<surface>\S+) label=(?P<label>\S+)"
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
    time.sleep(ROUTE_SETTLE_SECS)


def click_activity_route(window_id: int, point: tuple[float, float]) -> None:
    geometry = window_geometry(window_id)
    width = geometry.get("WIDTH", 1)
    height = geometry.get("HEIGHT", 1)
    rel_x = max(1, min(width - 1, int(width * point[0])))
    rel_y = max(1, min(height - 1, int(height * point[1])))
    abs_x = geometry.get("X", 0) + rel_x
    abs_y = geometry.get("Y", 0) + rel_y
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    time.sleep(0.25)
    run(["xdotool", "mousemove", str(abs_x), str(abs_y)], check=False)
    run(["xdotool", "click", "1"], check=False)
    time.sleep(0.4)
    run(["xdotool", "mousemove", str(abs_x), str(abs_y)], check=False)
    run(["xdotool", "click", "1"], check=False)
    time.sleep(ROUTE_SETTLE_SECS)


def capture_step(
    window_id: int,
    output_root: Path,
    step_id: str,
    *,
    browser_url: str | None = None,
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
        "captureMode": capture_result.mode,
        "captureError": capture_result.error,
        "captureDiagnostics": capture_result.diagnostics,
    }


def parse_lifecycle_log(log_path: Path) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    if not log_path.exists():
        return {"events": events}

    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        for event_type, pattern in (
            ("show", SHOW_PATTERN),
            ("created", CREATED_PATTERN),
            ("reused", REUSED_PATTERN),
            ("ready", READY_PATTERN),
            ("hide", HIDE_PATTERN),
            ("destroy", DESTROY_PATTERN),
        ):
            match = pattern.search(line)
            if not match:
                continue
            event = {"type": event_type, "line": line, **match.groupdict()}
            events.append(event)
            break

    surface_ids = sorted(
        {
            str(event["surface"])
            for event in events
            if event.get("surface") is not None
        }
    )
    return {
        "events": events,
        "surfaceIds": surface_ids,
        "showEvents": [event for event in events if event["type"] == "show"],
        "createdEvents": [event for event in events if event["type"] == "created"],
        "reusedEvents": [event for event in events if event["type"] == "reused"],
        "readyEvents": [event for event in events if event["type"] == "ready"],
        "hideEvents": [event for event in events if event["type"] == "hide"],
        "destroyEvents": [event for event in events if event["type"] == "destroy"],
    }


def wait_for_prewarm(log_path: Path, *, timeout_secs: float = 90.0) -> dict[str, Any]:
    deadline = time.time() + timeout_secs
    parsed: dict[str, Any] = {}
    while time.time() < deadline:
        parsed = parse_lifecycle_log(log_path)
        has_hidden_show = any(
            event.get("visible") == "false" for event in parsed.get("showEvents", [])
        )
        if has_hidden_show and parsed.get("createdEvents") and parsed.get("readyEvents"):
            return parsed
        time.sleep(1.0)
    return parsed


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
    os.environ.pop("AUTOPILOT_WORKSPACE_DIRECT_WEBVIEW_MODE", None)

    process = launch_dev_desktop(
        args.profile,
        log_path,
        args.dev_url,
        workspace_host="direct-openvscode",
        initial_view="home",
    )
    print("[openvscode-hot] launched desktop shell", flush=True)

    probe_error: str | None = None
    window_id: int | None = None
    parent_geometry: dict[str, int] = {}
    steps: list[dict[str, Any]] = []
    lifecycle: dict[str, Any] = {}

    try:
        window_id = wait_for_window(args.window_name, timeout_secs=args.timeout_secs)
        if window_id is None:
            raise RuntimeError(f"Timed out waiting for a window matching {args.window_name!r}")
        focus_workspace_view(window_id)
        time.sleep(POST_WINDOW_SETTLE_SECS)

        lifecycle = wait_for_prewarm(log_path)
        steps.append(
            capture_step(
                window_id,
                output_root,
                "00-home-prewarmed-hidden",
                browser_url=f"{DEFAULT_WEB_ROOT}/?view=home",
            )
        )

        click_activity_route(window_id, ACTIVITY_WORKSPACE_CLICK)
        steps.append(
            capture_step(
                window_id,
                output_root,
                "01-workspace-first-show",
                browser_url=f"{DEFAULT_WEB_ROOT}/?view=workspace",
            )
        )

        click_activity_route(window_id, ACTIVITY_HOME_CLICK)
        steps.append(
            capture_step(
                window_id,
                output_root,
                "02-home-hidden-again",
                browser_url=f"{DEFAULT_WEB_ROOT}/?view=home",
            )
        )

        click_activity_route(window_id, ACTIVITY_CHAT_CLICK)
        steps.append(capture_step(window_id, output_root, "03-chat-hidden"))

        click_activity_route(window_id, ACTIVITY_WORKSPACE_CLICK)
        steps.append(
            capture_step(
                window_id,
                output_root,
                "04-workspace-return-hot",
                browser_url=f"{DEFAULT_WEB_ROOT}/?view=workspace",
            )
        )

        lifecycle = parse_lifecycle_log(log_path)
        parent_geometry = window_geometry(window_id)
    except Exception as error:
        probe_error = str(error)
        lifecycle = parse_lifecycle_log(log_path)
        if window_id is not None:
            try:
                parent_geometry = window_geometry(window_id)
            except Exception:
                parent_geometry = {}
    finally:
        terminate_process_group(process)

    show_events = lifecycle.get("showEvents", [])
    assertions = {
        "home_prewarm_created_hidden_surface": any(
            event.get("visible") == "false" for event in show_events
        )
        and len(lifecycle.get("createdEvents", [])) == 1,
        "single_surface_identity": len(lifecycle.get("surfaceIds", [])) == 1,
        "route_switch_reused_surface": len(lifecycle.get("reusedEvents", [])) >= 1,
        "workspace_was_shown_visible": any(
            event.get("visible") == "true" for event in show_events
        ),
        "route_switches_hid_surface": len(lifecycle.get("hideEvents", [])) >= 2,
        "route_switches_did_not_destroy_surface": len(lifecycle.get("destroyEvents", [])) == 0,
        "screenshots_retained": all(step.get("screenshot") for step in steps),
    }
    if probe_error is None and not all(assertions.values()):
        probe_error = "One or more hot lifecycle assertions failed."

    bundle = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "profile": args.profile,
        "windowId": window_id,
        "parentGeometry": parent_geometry,
        "probe_error": probe_error,
        "steps": steps,
        "lifecycle": lifecycle,
        "assertions": assertions,
        "log_tail": read_log_tail(log_path),
    }
    result_path = output_root / "result.json"
    result_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"[openvscode-hot] results: {result_path}", flush=True)
    return 0 if probe_error is None else 1


if __name__ == "__main__":
    sys.exit(main())
