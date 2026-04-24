#!/usr/bin/env python3
"""Validate the native direct OpenVSCode workbench surface.

This probe is intentionally separate from the legacy Workspace facade probes.
It launches the desktop shell in direct OpenVSCode mode, waits for the native
Tauri webview host to report the actual OpenVSCode surface, captures both the
parent-window image and a root-cropped compositor image, then performs a small
set of real workbench interactions against the hosted OpenVSCode surface.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from desktop_capture import capture_window_with_fallback
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
    window_ids_from_wmctrl,
    window_ids_from_xdotool,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT / "docs/evidence/route-hierarchy/live-openvscode-direct/contained"
)
DEFAULT_DEV_URL = DEFAULT_WEB_ROOT
SURFACE_WINDOW_SEARCH_PATTERN = "Autopilot Workspace Workbench"
LEGACY_SURFACE_WINDOW_SEARCH_PATTERN = "OpenVSCode Workspace"
WINDOW_WAIT_TIMEOUT_SECS = 120.0
POST_WINDOW_SETTLE_SECS = 14.0
CLICK_SETTLE_SECS = 1.4
SURFACE_LOG_TIMEOUT_SECS = 90.0
SURFACE_LOG_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] show requested surface=(?P<surface>\S+) "
    r"parent=(?P<parent>\S+) bounds=\("
    r"(?P<x>-?\d+(?:\.\d+)?), (?P<y>-?\d+(?:\.\d+)?), "
    r"(?P<width>-?\d+(?:\.\d+)?), (?P<height>-?\d+(?:\.\d+)?)\)"
)
CREATED_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] created (?P<mode>\S+) "
    r"surface=(?P<surface>\S+) label=(?P<label>\S+)"
)
READY_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] ready (?P<mode>\S+) "
    r"surface=(?P<surface>\S+) label=(?P<label>\S+)"
)
REPARENT_PATTERN = re.compile(
    r"\[WorkspaceDirectWebview\] reparented child window surface "
    r"label=(?P<label>\S+) parent=(?P<parent>\S+) "
    r"xid=(?P<parent_xid>\d+) child_xid=(?P<child_xid>\d+) "
    r"bounds=\((?P<x>-?\d+), (?P<y>-?\d+), "
    r"(?P<width>\d+), (?P<height>\d+)\)"
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


def window_geometry(window_id: int) -> dict[str, int]:
    result = run(["xdotool", "getwindowgeometry", "--shell", str(window_id)])
    geometry: dict[str, int] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key_name, _, value = line.partition("=")
        key_name = key_name.strip().upper()
        value = value.strip()
        if key_name in {"X", "Y", "WIDTH", "HEIGHT"} and value.lstrip("-").isdigit():
            geometry[key_name] = int(value)
    return geometry


def xwininfo_details(window_id: int) -> dict[str, Any]:
    result = run(["xwininfo", "-id", str(window_id)], check=False)
    parent_match = re.search(
        r"Parent window id:\s+(0x[0-9a-fA-F]+)",
        result.stdout,
    )
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


def geometry_matches(
    geometry: dict[str, int],
    expected: dict[str, int],
    *,
    tolerance: int = 2,
) -> bool:
    return (
        abs(geometry.get("X", -99999) - expected["X"]) <= tolerance
        and abs(geometry.get("Y", -99999) - expected["Y"]) <= tolerance
        and abs(geometry.get("WIDTH", -1) - expected["WIDTH"]) <= tolerance
        and abs(geometry.get("HEIGHT", -1) - expected["HEIGHT"]) <= tolerance
    )


def wait_for_geometry_match(
    window_id: int,
    expected: dict[str, int],
    *,
    timeout_secs: float = 12.0,
) -> tuple[dict[str, int], bool]:
    deadline = time.time() + timeout_secs
    last_geometry: dict[str, int] = {}
    while time.time() < deadline:
        last_geometry = window_geometry(window_id)
        if geometry_matches(last_geometry, expected):
            return last_geometry, True
        time.sleep(0.5)
    return last_geometry, geometry_matches(last_geometry, expected)


def capture_root_crop(window_id: int, output_path: Path) -> dict[str, Any]:
    geometry = window_geometry(window_id)
    required = {"X", "Y", "WIDTH", "HEIGHT"}
    if not required.issubset(geometry):
        raise RuntimeError(f"Could not determine full window geometry for {window_id}")
    crop = f"{geometry['X']},{geometry['Y']} {geometry['WIDTH']}x{geometry['HEIGHT']}"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    attempts: list[dict[str, Any]] = []
    if shutil.which("grim"):
        completed = run(
            ["grim", "-g", crop, str(output_path)],
            check=False,
            timeout=10.0,
        )
        tool = "grim"
        attempts.append(
            {
                "tool": tool,
                "returncode": completed.returncode,
                "stderr": (completed.stderr or "").strip(),
            }
        )
        if completed.returncode == 0 and output_path.exists():
            return {
                "geometry": geometry,
                "crop": crop,
                "tool": tool,
                "attempts": attempts,
                "returncode": completed.returncode,
                "stderr": (completed.stderr or "").strip(),
                "path": str(output_path),
            }

    if shutil.which("import"):
        completed = run(
            ["import", "-window", "root", "-crop", crop, str(output_path)],
            check=False,
            timeout=10.0,
        )
        tool = "import-root"
        attempts.append(
            {
                "tool": tool,
                "returncode": completed.returncode,
                "stderr": (completed.stderr or "").strip(),
            }
        )
    elif attempts:
        last_attempt = attempts[-1]
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=int(last_attempt["returncode"]),
            stdout="",
            stderr=str(last_attempt["stderr"]),
        )
        tool = str(last_attempt["tool"])
    else:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="No root screenshot tool is available.",
        )
        tool = "none"
    return {
        "geometry": geometry,
        "crop": crop,
        "tool": tool,
        "attempts": attempts,
        "returncode": completed.returncode,
        "stderr": (completed.stderr or "").strip(),
        "path": str(output_path),
    }


def wait_for_surface_log(log_path: Path) -> dict[str, Any] | None:
    deadline = time.time() + SURFACE_LOG_TIMEOUT_SECS
    last_bounds: dict[str, Any] | None = None
    created: dict[str, Any] | None = None
    ready: dict[str, Any] | None = None
    reparented: dict[str, Any] | None = None
    while time.time() < deadline:
        if log_path.exists():
            for line in log_path.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines():
                bounds_match = SURFACE_LOG_PATTERN.search(line)
                if bounds_match:
                    last_bounds = {
                        "surfaceId": bounds_match.group("surface"),
                        "parentWindowLabel": bounds_match.group("parent"),
                        "bounds": {
                            "x": float(bounds_match.group("x")),
                            "y": float(bounds_match.group("y")),
                            "width": float(bounds_match.group("width")),
                            "height": float(bounds_match.group("height")),
                        },
                        "line": line,
                    }
                created_match = CREATED_PATTERN.search(line)
                if created_match:
                    created = {
                        "mode": created_match.group("mode"),
                        "surfaceId": created_match.group("surface"),
                        "label": created_match.group("label"),
                        "line": line,
                    }
                ready_match = READY_PATTERN.search(line)
                if ready_match:
                    ready = {
                        "mode": ready_match.group("mode"),
                        "surfaceId": ready_match.group("surface"),
                        "label": ready_match.group("label"),
                        "line": line,
                    }
                reparent_match = REPARENT_PATTERN.search(line)
                if reparent_match:
                    reparented = {
                        "label": reparent_match.group("label"),
                        "parentLabel": reparent_match.group("parent"),
                        "parentXid": int(reparent_match.group("parent_xid")),
                        "childXid": int(reparent_match.group("child_xid")),
                        "bounds": {
                            "x": int(reparent_match.group("x")),
                            "y": int(reparent_match.group("y")),
                            "width": int(reparent_match.group("width")),
                            "height": int(reparent_match.group("height")),
                        },
                        "line": line,
                    }
        if last_bounds and created and ready:
            return {
                **last_bounds,
                "created": created,
                "ready": ready,
                "reparented": reparented,
            }
        time.sleep(1.0)
    return None


def click_relative(window_id: int, x: int, y: int, *, button: int = 1) -> dict[str, int]:
    geometry = window_geometry(window_id)
    width = geometry.get("WIDTH", 1)
    height = geometry.get("HEIGHT", 1)
    safe_x = max(1, min(width - 1, x))
    safe_y = max(1, min(height - 1, y))
    run(["xdotool", "windowactivate", str(window_id)], check=False, timeout=4.0)
    time.sleep(0.2)
    run(["xdotool", "mousemove", "--window", str(window_id), str(safe_x), str(safe_y)])
    run(["xdotool", "click", str(button)], check=False)
    time.sleep(CLICK_SETTLE_SECS)
    return {
        "x": safe_x,
        "y": safe_y,
        "button": button,
        "windowWidth": width,
        "windowHeight": height,
    }


def key(window_id: int, chord: str, *, settle_secs: float = CLICK_SETTLE_SECS) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False, timeout=4.0)
    time.sleep(0.2)
    run(["xdotool", "key", chord], check=False, timeout=4.0)
    time.sleep(settle_secs)


def type_text(window_id: int, text: str, *, settle_secs: float = CLICK_SETTLE_SECS) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False, timeout=4.0)
    time.sleep(0.2)
    run(["xdotool", "type", text], check=False, timeout=10.0)
    time.sleep(settle_secs)


def press_escape(window_id: int, *, settle_secs: float = 0.7) -> None:
    key(window_id, "Escape", settle_secs=settle_secs)


def move_pointer_off_window() -> None:
    run(["xdotool", "mousemove", "0", "0"], check=False)
    time.sleep(0.2)


def image_difference_metric(reference_path: Path, candidate_path: Path) -> str | None:
    if not reference_path.exists() or not candidate_path.exists():
        return None
    completed = subprocess.run(
        [
            "compare",
            "-metric",
            "RMSE",
            str(reference_path),
            str(candidate_path),
            "null:",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    output = (completed.stderr or completed.stdout or "").strip()
    return output or None


def analyze_image_region(
    image_path: Path,
    output_root: Path,
    region_id: str,
    bounds: dict[str, float],
) -> dict[str, Any]:
    width = max(1, int(round(float(bounds["width"]))))
    height = max(1, int(round(float(bounds["height"]))))
    x = max(0, int(round(float(bounds["x"]))))
    y = max(0, int(round(float(bounds["y"]))))
    crop_path = output_root / f"{region_id}.crop.png"
    convert = shutil.which("magick") or shutil.which("convert")
    identify = shutil.which("identify")
    result: dict[str, Any] = {
        "path": str(crop_path),
        "bounds": {"x": x, "y": y, "width": width, "height": height},
        "available": False,
    }
    if convert is None or identify is None or not image_path.exists():
        result["error"] = "ImageMagick convert/magick and identify are required."
        return result

    if Path(convert).name == "magick":
        crop_cmd = [
            convert,
            str(image_path),
            "-crop",
            f"{width}x{height}+{x}+{y}",
            "+repage",
            str(crop_path),
        ]
    else:
        crop_cmd = [
            convert,
            str(image_path),
            "-crop",
            f"{width}x{height}+{x}+{y}",
            "+repage",
            str(crop_path),
        ]
    crop = run(crop_cmd, check=False, timeout=10.0)
    result["cropReturncode"] = crop.returncode
    result["cropStderr"] = (crop.stderr or "").strip()
    if crop.returncode != 0 or not crop_path.exists():
        result["error"] = result["cropStderr"] or "Region crop failed."
        return result

    metrics = run(
        [
            identify,
            "-format",
            "%k %[fx:mean] %[fx:standard_deviation]",
            str(crop_path),
        ],
        check=False,
        timeout=10.0,
    )
    result["identifyReturncode"] = metrics.returncode
    result["identifyStderr"] = (metrics.stderr or "").strip()
    parts = metrics.stdout.strip().split()
    if len(parts) == 3:
        try:
            result["available"] = True
            result["uniqueColors"] = int(parts[0])
            result["mean"] = float(parts[1])
            result["stddev"] = float(parts[2])
        except ValueError:
            result["error"] = f"Could not parse region metrics: {metrics.stdout!r}"
    else:
        result["error"] = f"Could not parse region metrics: {metrics.stdout!r}"
    return result


def region_has_visible_detail(analysis: dict[str, Any]) -> bool:
    try:
        return bool(
            analysis.get("available")
            and int(analysis.get("uniqueColors", 0)) > 32
            and float(analysis.get("stddev", 0.0)) > 0.0001
        )
    except (TypeError, ValueError):
        return False


def region_is_dark_chrome(analysis: dict[str, Any]) -> bool:
    try:
        return bool(
            analysis.get("available")
            and int(analysis.get("uniqueColors", 0)) > 24
            and float(analysis.get("mean", 1.0)) < 0.25
            and float(analysis.get("stddev", 0.0)) > 0.0001
        )
    except (TypeError, ValueError):
        return False


def capture_step(
    window_id: int,
    output_root: Path,
    step_id: str,
    *,
    browser_capture_url: str | None = None,
) -> dict[str, Any]:
    window_path = output_root / f"{step_id}.window.png"
    root_path = output_root / f"{step_id}.root.png"
    window_capture = capture_window_with_fallback(
        window_id,
        window_path,
        browser_url=browser_capture_url,
    )
    root_capture = capture_root_crop(window_id, root_path)
    root_screenshot = (
        str(root_path)
        if root_path.exists() and root_capture.get("returncode") == 0
        else None
    )
    return {
        "windowScreenshot": str(window_path) if window_path.exists() else None,
        "rootScreenshot": root_screenshot,
        "windowCaptureMode": window_capture.mode,
        "windowCaptureDiagnostics": window_capture.diagnostics,
        "windowCaptureError": window_capture.error,
        "rootCapture": root_capture,
    }


def surface_point(bounds: dict[str, float], x_ratio: float, y_ratio: float) -> tuple[int, int]:
    return (
        int(round(float(bounds["x"]) + float(bounds["width"]) * x_ratio)),
        int(round(float(bounds["y"]) + float(bounds["height"]) * y_ratio)),
    )


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
        help="How long to wait for the Workspace desktop window to appear.",
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
    print("[openvscode-direct] launched Workspace desktop shell", flush=True)

    probe_error: str | None = None
    window_id: int | None = None
    target_window_id: int | None = None
    target_window_source = "parent-contained"
    target_bounds: dict[str, float] | None = None
    surface: dict[str, Any] | None = None
    steps: list[dict[str, Any]] = []
    parent_capture: dict[str, Any] | None = None
    containment: dict[str, Any] = {}

    try:
        window_id = wait_for_window(args.window_name, timeout_secs=args.timeout_secs)
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
        print(f"[openvscode-direct] surface: {surface.get('created', {}).get('mode')}", flush=True)

        created_mode = surface.get("created", {}).get("mode")
        legacy_window_ids = window_ids_from_wmctrl(LEGACY_SURFACE_WINDOW_SEARCH_PATTERN)
        if not legacy_window_ids:
            legacy_window_ids = window_ids_from_xdotool(
                LEGACY_SURFACE_WINDOW_SEARCH_PATTERN
            )
        containment["legacyOpenVsCodeWindowIds"] = legacy_window_ids
        containment["createdMode"] = created_mode
        if created_mode not in {"Child", "OwnedWindow"}:
            raise RuntimeError(
                f"Direct OpenVSCode containment requires Child or OwnedWindow mode, got {created_mode!r}."
            )
        if legacy_window_ids:
            raise RuntimeError(
                f"Direct OpenVSCode exposed legacy OpenVSCode windows: {legacy_window_ids}"
            )
        workbench_top_level_window_ids = window_ids_from_wmctrl(
            SURFACE_WINDOW_SEARCH_PATTERN
        )
        containment["workbenchTopLevelWindowIds"] = workbench_top_level_window_ids
        if created_mode == "Child" and workbench_top_level_window_ids:
            raise RuntimeError(
                "Direct child mode exposed a task-switchable workbench window: "
                f"{workbench_top_level_window_ids}"
            )
        if created_mode == "Child":
            reparented = surface.get("reparented")
            containment["reparentedChild"] = reparented
            if not reparented:
                raise RuntimeError(
                    "Direct child mode did not report a reparented native child surface."
                )
            child_xid = int(reparented["childXid"])
            child_details = xwininfo_details(child_xid)
            parent_geometry = window_geometry(window_id)
            expected_x = int(round(parent_geometry.get("X", 0) + surface["bounds"]["x"]))
            expected_y = int(round(parent_geometry.get("Y", 0) + surface["bounds"]["y"]))
            expected_geometry = {
                "X": expected_x,
                "Y": expected_y,
                "WIDTH": int(round(surface["bounds"]["width"])),
                "HEIGHT": int(round(surface["bounds"]["height"])),
            }
            child_geometry = {
                "X": child_details.get("absoluteX"),
                "Y": child_details.get("absoluteY"),
                "WIDTH": child_details.get("width"),
                "HEIGHT": child_details.get("height"),
            }
            child_relative_geometry = {
                "X": child_details.get("relativeX"),
                "Y": child_details.get("relativeY"),
                "WIDTH": child_details.get("width"),
                "HEIGHT": child_details.get("height"),
            }
            expected_relative_geometry = {
                "X": int(round(surface["bounds"]["x"])),
                "Y": int(round(surface["bounds"]["y"])),
                "WIDTH": int(round(surface["bounds"]["width"])),
                "HEIGHT": int(round(surface["bounds"]["height"])),
            }
            containment["childWindowDetails"] = child_details
            containment["childWindowGeometry"] = child_geometry
            containment["childWindowRelativeGeometry"] = child_relative_geometry
            containment["childWindowExpectedGeometry"] = expected_geometry
            containment["childWindowExpectedRelativeGeometry"] = expected_relative_geometry
            containment["childWindowParentMatchesParent"] = geometry_matches(
                child_relative_geometry,
                expected_relative_geometry,
            )
            containment["childWindowGeometryMatchesSurfaceRect"] = geometry_matches(
                child_geometry,
                expected_geometry,
            )
            containment["childWindowOverrideRedirect"] = bool(
                child_details.get("overrideRedirect")
            )
            if not containment["childWindowParentMatchesParent"]:
                raise RuntimeError(
                    f"Direct child surface relative geometry {child_relative_geometry} did not match expected parent-relative rect {expected_relative_geometry}."
                )
            if not containment["childWindowGeometryMatchesSurfaceRect"]:
                raise RuntimeError(
                    f"Direct child surface geometry {child_geometry} did not match expected containment rect {expected_geometry}."
                )
            if not containment["childWindowOverrideRedirect"]:
                raise RuntimeError("Direct child surface is still window-manager managed.")
        if created_mode == "OwnedWindow":
            target_window_id = wait_for_window(
                SURFACE_WINDOW_SEARCH_PATTERN,
                timeout_secs=30.0,
            )
            if target_window_id is None:
                raise RuntimeError("Timed out waiting for owned OpenVSCode workbench window.")
            target_window_source = "owned-window"
            parent_geometry = window_geometry(window_id)
            target_geometry = window_geometry(target_window_id)
            expected_x = int(round(parent_geometry.get("X", 0) + surface["bounds"]["x"]))
            expected_y = int(round(parent_geometry.get("Y", 0) + surface["bounds"]["y"]))
            expected_width = int(round(surface["bounds"]["width"]))
            expected_height = int(round(surface["bounds"]["height"]))
            expected_geometry = {
                "X": expected_x,
                "Y": expected_y,
                "WIDTH": expected_width,
                "HEIGHT": expected_height,
            }
            target_geometry, geometry_match = wait_for_geometry_match(
                target_window_id,
                expected_geometry,
            )
            containment["ownedWindowGeometry"] = target_geometry
            containment["ownedWindowExpectedGeometry"] = expected_geometry
            containment["ownedWindowGeometryMatchesSurfaceRect"] = geometry_match
            if not geometry_match:
                raise RuntimeError(
                    f"Owned workbench geometry {target_geometry} did not match expected containment rect."
                )
            print(
                f"[openvscode-direct] owned geometry: {target_geometry}",
                flush=True,
            )
            target_bounds = {
                "x": 0.0,
                "y": 0.0,
                "width": float(target_geometry.get("WIDTH", 1)),
                "height": float(target_geometry.get("HEIGHT", 1)),
            }
            parent_capture = capture_step(window_id, output_root, "parent-baseline")
        else:
            target_window_id = window_id
            target_bounds = surface["bounds"]

        baseline = capture_step(target_window_id, output_root, "baseline")
        steps.append({"id": "baseline", **baseline})
        print("[openvscode-direct] captured baseline", flush=True)
        baseline_root = baseline.get("rootScreenshot")
        parent_geometry = window_geometry(window_id)
        if baseline_root:
            composition_image = Path(baseline_root)
            workbench_bounds = surface["bounds"] if created_mode == "OwnedWindow" else target_bounds
            chrome_source_image = composition_image
        else:
            composition_image = Path(baseline["windowScreenshot"])
            workbench_bounds = target_bounds
            if created_mode == "Child":
                chrome_source_image = composition_image
            elif parent_capture and parent_capture.get("windowScreenshot"):
                chrome_source_image = Path(parent_capture["windowScreenshot"])
            else:
                raise RuntimeError("Parent chrome capture was unavailable.")
            containment["wholeScreenCaptureBlocked"] = True
            containment["wholeScreenCaptureBlocker"] = baseline.get("rootCapture", {})

        workbench_region = analyze_image_region(
            composition_image,
            output_root,
            "contained-workbench",
            workbench_bounds,
        )
        activity_region = analyze_image_region(
            chrome_source_image,
            output_root,
            "autopilot-activity-bar",
            {
                "x": 0.0,
                "y": float(surface["bounds"]["y"]),
                "width": max(1.0, float(surface["bounds"]["x"])),
                "height": float(surface["bounds"]["height"]),
            },
        )
        header_region = analyze_image_region(
            chrome_source_image,
            output_root,
            "autopilot-header",
            {
                "x": 0.0,
                "y": 0.0,
                "width": float(parent_geometry.get("WIDTH", 1)),
                "height": max(1.0, float(surface["bounds"]["y"])),
            },
        )
        workbench_top_region = analyze_image_region(
            composition_image,
            output_root,
            "contained-workbench-top",
            {
                "x": float(workbench_bounds["x"]),
                "y": float(workbench_bounds["y"]),
                "width": float(workbench_bounds["width"]),
                "height": min(90.0, float(workbench_bounds["height"])),
            },
        )
        containment.update(
            {
                "workbenchRegion": workbench_region,
                "workbenchTopRegion": workbench_top_region,
                "activityBarRegion": activity_region,
                "headerRegion": header_region,
                "workbenchVisible": region_has_visible_detail(workbench_region),
                "workbenchTopVisible": region_has_visible_detail(
                    workbench_top_region
                ),
                "activityBarVisible": region_is_dark_chrome(activity_region),
                "headerVisible": region_is_dark_chrome(header_region),
            }
        )
        if not containment["workbenchVisible"]:
            raise RuntimeError("Contained OpenVSCode workbench region did not render visibly.")
        if not containment["workbenchTopVisible"]:
            raise RuntimeError(
                "Contained OpenVSCode workbench did not occupy the top of the workspace rect."
            )
        if not containment["activityBarVisible"]:
            raise RuntimeError("Autopilot activity bar chrome was not visibly retained.")
        if not containment["headerVisible"]:
            raise RuntimeError("Autopilot IDE header chrome was not visibly retained.")

        interactions = [
            {"id": "activity-search", "point": (0.021, 0.215)},
            {"id": "search-query", "point": (0.155, 0.132), "text": "src-tauri"},
            {"id": "activity-scm", "point": (0.021, 0.315)},
            {"id": "activity-extensions", "point": (0.021, 0.475)},
            {"id": "activity-ioi", "point": (0.021, 0.545)},
            {"id": "activity-explorer", "point": (0.021, 0.135)},
            {"id": "explorer-context-menu", "point": (0.095, 0.165), "button": 3},
            {"id": "toolbar-back", "point": (0.265, 0.026), "pre_escape": True},
            {"id": "toolbar-forward", "point": (0.290, 0.026)},
            {"id": "command-center-query", "point": (0.500, 0.026), "text": ">toggle panel"},
            {
                "id": "split-editor-command",
                "point": (0.500, 0.026),
                "command": "workbench.action.splitEditorRight",
            },
            {
                "id": "bottom-panel-toggle",
                "point": (0.925, 0.982),
                "command": "workbench.action.togglePanel",
                "pre_escape": True,
            },
        ]
        for interaction in interactions:
            step_id = str(interaction["id"])
            point = interaction["point"]
            command = interaction.get("command")
            text = interaction.get("text")
            button = int(interaction.get("button", 1))
            print(f"[openvscode-direct] interaction: {step_id}", flush=True)
            if interaction.get("pre_escape"):
                press_escape(target_window_id)
            x, y = surface_point(target_bounds, point[0], point[1])
            click = click_relative(target_window_id, x, y, button=button)
            if button == 3:
                time.sleep(0.8)
            if text:
                type_text(target_window_id, str(text), settle_secs=0.8)
            if command:
                key(target_window_id, "ctrl+shift+p", settle_secs=1.0)
                type_text(target_window_id, str(command), settle_secs=0.8)
                key(target_window_id, "Return", settle_secs=1.8)
            capture = capture_step(target_window_id, output_root, step_id)
            rmse_window = (
                image_difference_metric(
                    Path(baseline["windowScreenshot"]),
                    Path(capture["windowScreenshot"]),
                )
                if baseline.get("windowScreenshot")
                and capture.get("windowScreenshot")
                else None
            )
            rmse_root = (
                image_difference_metric(
                    Path(baseline["rootScreenshot"]),
                    Path(capture["rootScreenshot"]),
                )
                if baseline.get("rootScreenshot")
                and capture.get("rootScreenshot")
                else None
            )
            steps.append(
                {
                    "id": step_id,
                    "click": click,
                    "surfacePoint": {"xRatio": point[0], "yRatio": point[1]},
                    "command": command,
                    "text": text,
                    "rmseVsBaselineWindow": rmse_window,
                    "rmseVsBaselineRoot": rmse_root,
                    **capture,
                }
            )
            if button == 3:
                press_escape(target_window_id)
    except Exception as error:
        probe_error = str(error)
    finally:
        terminate_process_group(process)

    bundle = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "window_id": window_id,
        "target_window_id": target_window_id,
        "target_window_source": target_window_source,
        "target_bounds": target_bounds,
        "profile": args.profile,
        "surface": surface,
        "parent_capture": parent_capture,
        "containment": containment,
        "steps": steps,
        "probe_error": probe_error,
        "negative_checks": {
            "directMode": True,
            "createdNativeSurface": bool(surface and surface.get("created")),
            "createdNativeSurfaceMode": surface.get("created", {}).get("mode")
            if surface
            else None,
            "defaultModeIsChild": containment.get("createdMode") == "Child",
            "noLegacyOpenVsCodeWindow": not containment.get("legacyOpenVsCodeWindowIds"),
            "noTaskSwitcherWorkbenchWindow": not containment.get(
                "workbenchTopLevelWindowIds"
            ),
            "childSurfaceParentedToAutopilot": bool(
                containment.get("childWindowParentMatchesParent", False)
            ),
            "childSurfaceMatchesWorkspaceRect": bool(
                containment.get("childWindowGeometryMatchesSurfaceRect", False)
            ),
            "workbenchContainedInParent": bool(containment.get("workbenchVisible")),
            "autopilotChromeRetained": bool(
                containment.get("activityBarVisible")
                and containment.get("headerVisible")
            ),
        },
        "log_tail": read_log_tail(log_path),
    }

    result_path = output_root / "result.json"
    result_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"[openvscode-direct] results: {result_path}", flush=True)

    has_capture_error = any(step.get("windowCaptureError") for step in steps)
    return 0 if not probe_error and not has_capture_error else 1


if __name__ == "__main__":
    sys.exit(main())
