#!/usr/bin/env python3
"""Prove first Workspace reveal fills a maximized Autopilot parent window."""

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
    launch_dev_desktop,
    now_stamp,
    read_log_tail,
    terminate_existing_desktop_instances,
    terminate_process_group,
    wait_for_window,
    window_ids_from_xdotool,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT
    / "docs/evidence/route-hierarchy/live-openvscode-direct/fullscreen-first-load"
)
DEFAULT_DEV_URL = DEFAULT_WEB_ROOT
SURFACE_WINDOW_SEARCH_PATTERN = "Autopilot Workspace Workbench"
WINDOW_WAIT_TIMEOUT_SECS = 120.0
POST_WINDOW_SETTLE_SECS = 5.0
POST_MAXIMIZE_SETTLE_SECS = 2.5
WORKSPACE_CLICK = (0.019, 0.158)
CORRECTION_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] corrected child bounds label=(?P<label>\S+) "
    r"context=(?P<context>.*?) input=\((?P<input_x>-?\d+(?:\.\d+)?), "
    r"(?P<input_y>-?\d+(?:\.\d+)?), (?P<input_width>-?\d+(?:\.\d+)?), "
    r"(?P<input_height>-?\d+(?:\.\d+)?)\) parent_size=\("
    r"(?P<parent_width>-?\d+(?:\.\d+)?), (?P<parent_height>-?\d+(?:\.\d+)?)\) "
    r"corrected=\((?P<x>-?\d+(?:\.\d+)?), (?P<y>-?\d+(?:\.\d+)?), "
    r"(?P<width>-?\d+(?:\.\d+)?), (?P<height>-?\d+(?:\.\d+)?)\)"
)
SHOW_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] show requested surface=(?P<surface>\S+) "
    r"parent=(?P<parent>\S+) visible=(?P<visible>\S+) bounds=\("
    r"(?P<x>-?\d+(?:\.\d+)?), (?P<y>-?\d+(?:\.\d+)?), "
    r"(?P<width>-?\d+(?:\.\d+)?), (?P<height>-?\d+(?:\.\d+)?)\)"
)
REPARENT_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] reparented child window surface "
    r"label=(?P<label>\S+) parent=(?P<parent>\S+) "
    r"xid=(?P<parent_xid>\d+) child_xid=(?P<child_xid>\d+) "
    r"bounds=\((?P<x>-?\d+), (?P<y>-?\d+), "
    r"(?P<width>\d+), (?P<height>\d+)\) visible=(?P<visible>\S+)"
)


def run(
    cmd: list[str],
    *,
    check: bool = True,
    capture_output: bool = True,
    text: bool = True,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=capture_output,
        text=text,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"Command failed ({completed.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return completed


def maximize_window(window_id: int) -> list[dict[str, Any]]:
    window_hex = hex(window_id)
    diagnostics: list[dict[str, Any]] = []
    for state in ("maximized_vert,maximized_horz",):
        completed = run(
            ["wmctrl", "-ir", window_hex, "-b", f"add,{state}"],
            check=False,
            timeout=5.0,
        )
        diagnostics.append(
            {
                "command": ["wmctrl", "-ir", window_hex, "-b", f"add,{state}"],
                "returncode": completed.returncode,
                "stderr": (completed.stderr or "").strip(),
            }
        )
    display = run(["xdpyinfo"], check=False, timeout=5.0)
    dimensions = re.search(r"dimensions:\s+(\d+)x(\d+)", display.stdout)
    if dimensions:
        screen_width = int(dimensions.group(1))
        screen_height = int(dimensions.group(2))
        workarea_y = 32
        workarea_height = max(1, screen_height - workarea_y)
        for cmd in (
            ["xdotool", "windowmove", "--sync", str(window_id), "0", str(workarea_y)],
            [
                "xdotool",
                "windowsize",
                "--sync",
                str(window_id),
                str(screen_width),
                str(workarea_height),
            ],
        ):
            completed = run(cmd, check=False, timeout=5.0)
            diagnostics.append(
                {
                    "command": cmd,
                    "returncode": completed.returncode,
                    "stderr": (completed.stderr or "").strip(),
                }
            )
    else:
        diagnostics.append(
            {
                "command": ["xdpyinfo"],
                "returncode": display.returncode,
                "stderr": (display.stderr or "").strip(),
                "warning": "Could not parse display dimensions for xdotool maximize fallback.",
            }
        )
    time.sleep(POST_MAXIMIZE_SETTLE_SECS)
    return diagnostics


def xwininfo_details(window_id: int) -> dict[str, Any]:
    result = run(["xwininfo", "-id", str(window_id)], check=False)
    parent_match = re.search(r"Parent window id:\s+(0x[0-9a-fA-F]+)", result.stdout)
    absolute_x = re.search(r"Absolute upper-left X:\s+(-?\d+)", result.stdout)
    absolute_y = re.search(r"Absolute upper-left Y:\s+(-?\d+)", result.stdout)
    relative_x = re.search(r"Relative upper-left X:\s+(-?\d+)", result.stdout)
    relative_y = re.search(r"Relative upper-left Y:\s+(-?\d+)", result.stdout)
    width = re.search(r"Width:\s+(\d+)", result.stdout)
    height = re.search(r"Height:\s+(\d+)", result.stdout)
    override_redirect = re.search(r"Override Redirect State:\s+([A-Za-z]+)", result.stdout)
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "parentWindowHex": parent_match.group(1) if parent_match else None,
        "parentWindowId": int(parent_match.group(1), 16) if parent_match else None,
        "absoluteX": int(absolute_x.group(1)) if absolute_x else None,
        "absoluteY": int(absolute_y.group(1)) if absolute_y else None,
        "relativeX": int(relative_x.group(1)) if relative_x else None,
        "relativeY": int(relative_y.group(1)) if relative_y else None,
        "width": int(width.group(1)) if width else None,
        "height": int(height.group(1)) if height else None,
        "overrideRedirect": override_redirect.group(1).lower() == "yes"
        if override_redirect
        else None,
    }


def wait_for_surface_fill(
    parent_window_id: int,
    *,
    timeout_secs: float = 45.0,
) -> tuple[int | None, dict[str, Any] | None, dict[str, Any]]:
    deadline = time.time() + timeout_secs
    parent_geometry = window_geometry(parent_window_id)
    last_details: dict[str, Any] | None = None
    last_surface_id: int | None = None
    while time.time() < deadline:
        surface_ids = window_ids_from_xdotool(SURFACE_WINDOW_SEARCH_PATTERN)
        for surface_id in surface_ids:
            details = xwininfo_details(surface_id)
            last_surface_id = surface_id
            last_details = details
            relative_x = int(details.get("relativeX") or 0)
            relative_y = int(details.get("relativeY") or 0)
            expected_width = max(1, int(parent_geometry.get("WIDTH", 0)) - relative_x)
            expected_height = max(1, int(parent_geometry.get("HEIGHT", 0)) - relative_y)
            width = int(details.get("width") or 0)
            height = int(details.get("height") or 0)
            if width >= expected_width - 8 and height >= expected_height - 8:
                return surface_id, details, parent_geometry
        time.sleep(0.75)
        parent_geometry = window_geometry(parent_window_id)
    return last_surface_id, last_details, parent_geometry


def parse_log(log_path: Path) -> dict[str, Any]:
    corrections: list[dict[str, Any]] = []
    shows: list[dict[str, Any]] = []
    reparents: list[dict[str, Any]] = []
    if not log_path.exists():
        return {"corrections": corrections, "shows": shows, "reparents": reparents}
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        correction_match = CORRECTION_PATTERN.search(line)
        if correction_match:
            data = correction_match.groupdict()
            corrections.append(
                {
                    **data,
                    "input": {
                        "x": float(data["input_x"]),
                        "y": float(data["input_y"]),
                        "width": float(data["input_width"]),
                        "height": float(data["input_height"]),
                    },
                    "parentSize": {
                        "width": float(data["parent_width"]),
                        "height": float(data["parent_height"]),
                    },
                    "corrected": {
                        "x": float(data["x"]),
                        "y": float(data["y"]),
                        "width": float(data["width"]),
                        "height": float(data["height"]),
                    },
                    "line": line,
                }
            )
        show_match = SHOW_PATTERN.search(line)
        if show_match:
            data = show_match.groupdict()
            shows.append(
                {
                    **data,
                    "bounds": {
                        "x": float(data["x"]),
                        "y": float(data["y"]),
                        "width": float(data["width"]),
                        "height": float(data["height"]),
                    },
                    "line": line,
                }
            )
        reparent_match = REPARENT_PATTERN.search(line)
        if reparent_match:
            data = reparent_match.groupdict()
            reparents.append(
                {
                    **data,
                    "parentXid": int(data["parent_xid"]),
                    "childXid": int(data["child_xid"]),
                    "bounds": {
                        "x": int(data["x"]),
                        "y": int(data["y"]),
                        "width": int(data["width"]),
                        "height": int(data["height"]),
                    },
                    "line": line,
                }
            )
    return {"corrections": corrections, "shows": shows, "reparents": reparents}


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
    close_matching_windows(SURFACE_WINDOW_SEARCH_PATTERN)
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
    print("[openvscode-fullscreen-first-load] launched desktop shell", flush=True)

    probe_error: str | None = None
    window_id: int | None = None
    surface_window_id: int | None = None
    parent_geometry_before: dict[str, int] = {}
    parent_geometry_after: dict[str, int] = {}
    surface_details: dict[str, Any] | None = None
    maximize_diagnostics: list[dict[str, Any]] = []
    capture: dict[str, Any] | None = None
    log_summary: dict[str, Any] = {}

    try:
        window_id = wait_for_window(args.window_name, timeout_secs=args.timeout_secs)
        if window_id is None:
            raise RuntimeError(f"Timed out waiting for a window matching {args.window_name!r}")
        time.sleep(POST_WINDOW_SETTLE_SECS)
        parent_geometry_before = window_geometry(window_id)
        maximize_diagnostics = maximize_window(window_id)
        parent_geometry_after = window_geometry(window_id)
        if parent_geometry_after.get("WIDTH", 0) <= parent_geometry_before.get("WIDTH", 0):
            raise RuntimeError(
                f"Window did not maximize: before={parent_geometry_before} after={parent_geometry_after}"
            )

        click_window_ratio(window_id, WORKSPACE_CLICK[0], WORKSPACE_CLICK[1])
        surface_window_id, surface_details, parent_geometry_after = wait_for_surface_fill(window_id)
        screenshot_path = output_root / "workspace-first-load-maximized.png"
        capture_result = capture_window_with_fallback(
            window_id,
            screenshot_path,
            browser_url=f"{DEFAULT_WEB_ROOT}/?view=workspace",
        )
        capture = {
            "path": str(screenshot_path) if screenshot_path.exists() else None,
            "mode": capture_result.mode,
            "error": capture_result.error,
            "diagnostics": capture_result.diagnostics,
        }
        log_summary = parse_log(log_path)
    except Exception as error:
        probe_error = str(error)
        log_summary = parse_log(log_path)
    finally:
        terminate_process_group(process)

    if surface_details:
        relative_x = int(surface_details.get("relativeX") or 0)
        relative_y = int(surface_details.get("relativeY") or 0)
        expected_width = max(1, int(parent_geometry_after.get("WIDTH", 0)) - relative_x)
        expected_height = max(1, int(parent_geometry_after.get("HEIGHT", 0)) - relative_y)
        surface_width = int(surface_details.get("width") or 0)
        surface_height = int(surface_details.get("height") or 0)
    else:
        relative_x = relative_y = 0
        expected_width = expected_height = surface_width = surface_height = 0
    visible_reparents = [
        event
        for event in log_summary.get("reparents", [])
        if event.get("visible") == "true"
    ]
    full_size_reparents = [
        event
        for event in visible_reparents
        if event.get("parentXid") == window_id
        and (
            surface_window_id is None
            or event.get("childXid") == surface_window_id
        )
        and event.get("bounds", {}).get("width", 0) >= expected_width - 8
        and event.get("bounds", {}).get("height", 0) >= expected_height - 8
    ]
    full_size_visible_shows = [
        event
        for event in log_summary.get("shows", [])
        if event.get("visible") == "true"
        and event.get("bounds", {}).get("width", 0) >= expected_width - 8
        and event.get("bounds", {}).get("height", 0) >= expected_height - 8
    ]

    assertions = {
        "parent_window_maximized_before_first_workspace_reveal": parent_geometry_after.get(
            "WIDTH", 0
        )
        > parent_geometry_before.get("WIDTH", 0),
        "surface_window_found": surface_window_id is not None,
        "surface_remains_child_of_parent": len(full_size_reparents) >= 1,
        "surface_starts_below_header_and_after_activity_bar": relative_x >= 44
        and relative_y >= 30,
        "surface_width_fills_parent": surface_width >= expected_width - 8,
        "surface_height_fills_parent": surface_height >= expected_height - 8,
        "fullscreen_bounds_observed_before_capture": len(full_size_reparents) >= 1
        or len(full_size_visible_shows) >= 1
        or len(log_summary.get("corrections", [])) >= 1,
        "screenshot_retained": bool(capture and capture.get("path")),
    }
    if probe_error is None and not all(assertions.values()):
        probe_error = "One or more fullscreen first-load assertions failed."

    bundle = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "profile": args.profile,
        "windowId": window_id,
        "surfaceWindowId": surface_window_id,
        "parentGeometryBeforeMaximize": parent_geometry_before,
        "parentGeometryAfterMaximize": parent_geometry_after,
        "surfaceDetails": surface_details,
        "expectedSurfaceSize": {
            "width": expected_width,
            "height": expected_height,
        },
        "actualSurfaceSize": {
            "width": surface_width,
            "height": surface_height,
        },
        "maximizeDiagnostics": maximize_diagnostics,
        "capture": capture,
        "logSummary": log_summary,
        "assertions": assertions,
        "probe_error": probe_error,
        "log_tail": read_log_tail(log_path),
    }
    result_path = output_root / "result.json"
    result_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"[openvscode-fullscreen-first-load] results: {result_path}", flush=True)
    return 0 if probe_error is None else 1


if __name__ == "__main__":
    sys.exit(main())
