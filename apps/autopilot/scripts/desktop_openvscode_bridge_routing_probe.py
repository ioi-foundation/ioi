#!/usr/bin/env python3
"""Validate OpenVSCode workbench commands route into the IOI runtime.

The contained-direct probe proves the native workbench is embedded. This probe
exercises a product behavior path across that boundary: invoke an IOI command
from the real OpenVSCode command palette, wait for the bridge request to be
queued/drained, and verify the Autopilot Chat shell receives the matching
runtime target.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from desktop_openvscode_direct_probe import (
    CLICK_SETTLE_SECS,
    SURFACE_WINDOW_SEARCH_PATTERN,
    analyze_image_region,
    capture_step,
    click_relative,
    move_pointer_off_window,
    press_escape,
    region_has_visible_detail,
    run,
    surface_point,
    wait_for_surface_log,
    wait_for_window,
    window_geometry,
)
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
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT / "docs/evidence/route-hierarchy/live-openvscode-direct/bridge-routing"
)
DEFAULT_DEV_URL = DEFAULT_WEB_ROOT
POST_WINDOW_SETTLE_SECS = 14.0
LOG_WAIT_TIMEOUT_SECS = 30.0


def read_log(log_path: Path) -> str:
    if not log_path.exists():
        return ""
    return log_path.read_text(encoding="utf-8", errors="replace")


def wait_for_log_match(
    log_path: Path,
    predicate: Callable[[str], bool],
    *,
    timeout_secs: float = LOG_WAIT_TIMEOUT_SECS,
) -> bool:
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        if predicate(read_log(log_path)):
            return True
        time.sleep(0.5)
    return predicate(read_log(log_path))


def key_focused(chord: str, *, settle_secs: float = CLICK_SETTLE_SECS) -> None:
    run(["xdotool", "key", "--clearmodifiers", chord], check=False, timeout=5.0)
    time.sleep(settle_secs)


def focus_input_window(window_id: int) -> None:
    run(["xdotool", "windowfocus", "--sync", str(window_id)], check=False, timeout=4.0)
    time.sleep(0.2)


def type_focused(text: str, *, settle_secs: float = CLICK_SETTLE_SECS) -> None:
    run(["xdotool", "type", "--delay", "8", text], check=False, timeout=15.0)
    time.sleep(settle_secs)


def execute_command_palette_command(
    window_id: int,
    bounds: dict[str, float],
    command_title: str,
) -> dict[str, Any]:
    command_center_x, command_center_y = surface_point(bounds, 0.5, 0.026)
    focus_click = click_relative(window_id, command_center_x, command_center_y)
    focus_input_window(window_id)
    key_focused("ctrl+a", settle_secs=0.2)
    type_focused(f">{command_title}", settle_secs=0.8)
    return {
        "focusClick": focus_click,
        "commandTitle": command_title,
        "entryText": f">{command_title}",
    }


def dismiss_workbench_notification(
    window_id: int,
    bounds: dict[str, float],
) -> dict[str, Any]:
    close_x, close_y = surface_point(bounds, 0.978, 0.776)
    return click_relative(window_id, close_x, close_y)


def parse_chat_launch_lines(log_text: str) -> list[str]:
    return [
        line
        for line in log_text.splitlines()
        if "[Autopilot][ChatLaunch]" in line
    ][-40:]


def parse_bridge_lines(log_text: str) -> list[str]:
    bridge_patterns = (
        "[Workspace IDE] bridge request",
        "bridge_request_received",
        "bridge_request_handled",
    )
    return [
        line
        for line in log_text.splitlines()
        if any(pattern in line for pattern in bridge_patterns)
    ][-40:]


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
    os.environ.pop("AUTOPILOT_WORKSPACE_DIRECT_WEBVIEW_MODE", None)
    process = launch_dev_desktop(
        args.profile,
        log_path,
        args.dev_url,
        "direct-openvscode",
    )
    print("[openvscode-bridge] launched Workspace desktop shell", flush=True)

    probe_error: str | None = None
    window_id: int | None = None
    target_window_id: int | None = None
    interaction_window_id: int | None = None
    target_bounds: dict[str, float] | None = None
    interaction_bounds: dict[str, float] | None = None
    surface: dict[str, Any] | None = None
    steps: list[dict[str, Any]] = []
    command: dict[str, Any] | None = None
    route_region: dict[str, Any] | None = None

    try:
        window_id = wait_for_window(args.window_name, timeout_secs=120.0)
        if window_id is None:
            raise RuntimeError(
                f"Timed out waiting for a window matching {args.window_name!r}"
            )

        focus_workspace_view(window_id)
        move_pointer_off_window()
        time.sleep(POST_WINDOW_SETTLE_SECS)
        surface = wait_for_surface_log(log_path)
        if surface is None:
            raise RuntimeError("Timed out waiting for native OpenVSCode surface log.")

        created_mode = surface.get("created", {}).get("mode")
        if created_mode == "OwnedWindow":
            target_window_id = wait_for_window(
                SURFACE_WINDOW_SEARCH_PATTERN,
                timeout_secs=30.0,
            )
            if target_window_id is None:
                raise RuntimeError("Timed out waiting for owned OpenVSCode surface.")
            owned_geometry = window_geometry(target_window_id)
            target_bounds = {
                "x": 0.0,
                "y": 0.0,
                "width": float(owned_geometry.get("WIDTH", 1)),
                "height": float(owned_geometry.get("HEIGHT", 1)),
            }
            interaction_window_id = target_window_id
            interaction_bounds = target_bounds
        else:
            target_window_id = window_id
            target_bounds = surface["bounds"]
            reparented = surface.get("reparented") or {}
            child_xid = reparented.get("childXid")
            if not child_xid:
                raise RuntimeError("Child surface did not expose a reparented child XID.")
            interaction_window_id = int(child_xid)
            interaction_bounds = {
                "x": 0.0,
                "y": 0.0,
                "width": float(surface["bounds"]["width"]),
                "height": float(surface["bounds"]["height"]),
            }

        baseline = capture_step(target_window_id, output_root, "baseline")
        steps.append({"id": "baseline", **baseline})
        notification_dismissal = dismiss_workbench_notification(
            interaction_window_id,
            interaction_bounds,
        )
        steps.append(
            {
                "id": "notification-dismissed",
                "click": notification_dismissal,
                **capture_step(
                    target_window_id,
                    output_root,
                    "notification-dismissed",
                ),
            }
        )

        command = execute_command_palette_command(
            interaction_window_id,
            interaction_bounds,
            "IOI: Open Runs",
        )
        steps.append(
            {
                "id": "command-palette-ioi-open-runs",
                **capture_step(
                    target_window_id,
                    output_root,
                    "command-palette-ioi-open-runs",
                ),
            }
        )
        focus_input_window(interaction_window_id)
        key_focused("Return", settle_secs=max(CLICK_SETTLE_SECS, 2.0))

        routed = wait_for_log_match(
            log_path,
            lambda text: (
                "bridge request queued" in text
                and "type=runs.open" in text
                and "bridge requests drained" in text
                and "types=runs.open" in text
                and '"kind":"view","view":"runs"' in text
                and "chat_pending_launch_applied" in text
            ),
            timeout_secs=LOG_WAIT_TIMEOUT_SECS,
        )
        if not routed:
            raise RuntimeError(
                "Timed out waiting for IOI Open Runs to bridge into the Chat runtime."
            )
        cleared = wait_for_log_match(
            log_path,
            lambda text: "unmapped child window" in text
            and "destroy requested Child" in text,
            timeout_secs=LOG_WAIT_TIMEOUT_SECS,
        )
        if not cleared:
            raise RuntimeError(
                "IOI Open Runs routed, but the direct OpenVSCode child did not unmap/destroy."
            )
        time.sleep(2.0)
        after_route = capture_step(
            target_window_id,
            output_root,
            "after-ioi-runs-route",
        )
        steps.append({"id": "after-ioi-runs-route", **after_route})
        if after_route.get("windowScreenshot"):
            window_size = window_geometry(target_window_id)
            route_region = analyze_image_region(
                Path(str(after_route["windowScreenshot"])),
                output_root,
                "after-route-runtime-surface",
                {
                    "x": 48.0,
                    "y": 35.0,
                    "width": max(1.0, float(window_size.get("WIDTH", 1) - 384)),
                    "height": max(1.0, float(window_size.get("HEIGHT", 1) - 70)),
                },
            )
        if route_region and not region_has_visible_detail(route_region):
            raise RuntimeError(
                "IOI Open Runs routed, but the runtime surface did not render visibly."
            )
    except Exception as error:
        probe_error = str(error)
    finally:
        terminate_process_group(process)

    log_text = read_log(log_path)
    bridge_lines = parse_bridge_lines(log_text)
    chat_launch_lines = parse_chat_launch_lines(log_text)
    acceptance = {
        "directSurfaceCreated": bool(surface and surface.get("created")),
        "defaultModeIsChild": surface.get("created", {}).get("mode") == "Child"
        if surface
        else False,
        "commandPaletteCaptured": any(
            step.get("id") == "command-palette-ioi-open-runs"
            and step.get("windowScreenshot")
            for step in steps
        ),
        "bridgeQueuedRunsOpen": bool(
            re.search(r"bridge request queued .*type=runs\.open", log_text)
        ),
        "bridgeDrainedRunsOpen": bool(
            re.search(r"bridge requests drained .*types=runs\.open", log_text)
        ),
        "chatLaunchQueuedRunsView": '"kind":"view","view":"runs"' in log_text,
        "chatLaunchApplied": "chat_pending_launch_applied" in log_text,
        "nativeSurfaceUnmapped": "unmapped child window" in log_text,
        "nativeSurfaceDestroyed": "destroy requested Child" in log_text,
        "afterRouteVisible": region_has_visible_detail(route_region or {}),
        "afterRouteCaptured": any(
            step.get("id") == "after-ioi-runs-route" and step.get("windowScreenshot")
            for step in steps
        ),
    }

    bundle = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "window_id": window_id,
        "target_window_id": target_window_id,
        "interaction_window_id": interaction_window_id,
        "target_bounds": target_bounds,
        "interaction_bounds": interaction_bounds,
        "profile": args.profile,
        "surface": surface,
        "command": command,
        "steps": steps,
        "bridgeLines": bridge_lines,
        "chatLaunchLines": chat_launch_lines,
        "routeRegion": route_region,
        "acceptance": acceptance,
        "probe_error": probe_error,
        "log_tail": read_log_tail(log_path),
    }

    result_path = output_root / "result.json"
    result_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"[openvscode-bridge] results: {result_path}", flush=True)
    return 0 if probe_error is None and all(acceptance.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
