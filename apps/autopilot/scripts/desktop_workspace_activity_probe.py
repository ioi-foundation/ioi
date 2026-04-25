#!/usr/bin/env python3
"""Exercise the real Workspace activity bar in the desktop shell.

This probe launches the Tauri desktop app directly into Workspace, clicks each
activity-bar section in order, and retains a screenshot bundle for each state.
It is intentionally behavior-oriented: the goal is to prove the direct
integration's activity bar is not decorative.
"""

from __future__ import annotations

import argparse
import json
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
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT / "docs/evidence/route-hierarchy/live-workspace-activity"
)
DEFAULT_DEV_URL = DEFAULT_WEB_ROOT
WINDOW_WAIT_TIMEOUT_SECS = 90.0
POST_WINDOW_SETTLE_SECS = 12.0
CLICK_SETTLE_SECS = 1.2


ACTIVITY_STEPS = [
    {
        "id": "files",
        "label": "Explorer",
        "x_ratio": 0.070,
        "y_ratio": 0.202,
    },
    {
        "id": "search",
        "label": "Search",
        "x_ratio": 0.070,
        "y_ratio": 0.265,
    },
    {
        "id": "source-control",
        "label": "Source Control",
        "x_ratio": 0.070,
        "y_ratio": 0.324,
    },
    {
        "id": "run-and-debug",
        "label": "Run and Debug",
        "x_ratio": 0.070,
        "y_ratio": 0.383,
    },
    {
        "id": "extensions",
        "label": "Extensions",
        "x_ratio": 0.070,
        "y_ratio": 0.446,
    },
    {
        "id": "ioi",
        "label": "IOI",
        "x_ratio": 0.070,
        "y_ratio": 0.515,
    },
    {
        "id": "connections",
        "label": "Connections",
        "x_ratio": 0.070,
        "y_ratio": 0.855,
    },
    {
        "id": "policy",
        "label": "Policy",
        "x_ratio": 0.070,
        "y_ratio": 0.915,
    },
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


def window_geometry(window_id: int) -> dict[str, int]:
    result = run(["xdotool", "getwindowgeometry", "--shell", str(window_id)])
    geometry: dict[str, int] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key_name, _, value = line.partition("=")
        key_name = key_name.strip().upper()
        value = value.strip()
        if key_name in {"X", "Y", "WIDTH", "HEIGHT"} and value.isdigit():
            geometry[key_name] = int(value)
    return geometry


def click_window_ratio(window_id: int, x_ratio: float, y_ratio: float) -> dict[str, int]:
    geometry = window_geometry(window_id)
    origin_x = geometry.get("X")
    origin_y = geometry.get("Y")
    width = geometry.get("WIDTH")
    height = geometry.get("HEIGHT")
    if origin_x is None or origin_y is None or not width or not height:
        raise RuntimeError(f"Could not determine geometry for window {window_id}")
    rel_x = max(1, min(width - 1, int(width * x_ratio)))
    rel_y = max(1, min(height - 1, int(height * y_ratio)))
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    run(["xdotool", "mousemove", "--window", str(window_id), str(rel_x), str(rel_y)])
    # `click --window` can miss WebKit/Tauri DOM targets on Linux/X11 even when the
    # pointer is in the right place. Clicking the current pointer location after a
    # window-relative move is the more reliable path for these workspace probes.
    run(["xdotool", "click", "1"], check=False)
    time.sleep(CLICK_SETTLE_SECS)
    return {
        "origin_x": origin_x,
        "origin_y": origin_y,
        "width": width,
        "height": height,
        "x": rel_x,
        "y": rel_y,
    }


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

    process = launch_dev_desktop(args.profile, log_path, args.dev_url)
    print("[workspace-activity] launched Workspace desktop shell", flush=True)

    probe_error: str | None = None
    window_id: int | None = None
    step_results: list[dict[str, Any]] = []

    try:
        window_id = wait_for_window(args.window_name, timeout_secs=args.timeout_secs)
        if window_id is None:
            raise RuntimeError(
                f"Timed out waiting for a window matching {args.window_name!r}"
            )

        focus_workspace_view(window_id)
        time.sleep(POST_WINDOW_SETTLE_SECS)

        baseline_path: Path | None = None

        for step in ACTIVITY_STEPS:
            print(
                f"[workspace-activity] step {step['id']} @ "
                f"({step['x_ratio']:.3f}, {step['y_ratio']:.3f})",
                flush=True,
            )
            screenshot_path = output_root / f"{step['id']}.png"
            click_point = click_window_ratio(
                window_id,
                float(step["x_ratio"]),
                float(step["y_ratio"]),
            )
            capture_result = capture_window_with_fallback(
                window_id,
                screenshot_path,
                browser_url=None,
            )
            step_bundle: dict[str, Any] = {
                "id": step["id"],
                "label": step["label"],
                "click": click_point,
                "screenshot": str(screenshot_path) if screenshot_path.exists() else None,
                "capture_mode": capture_result.mode,
                "capture_diagnostics": capture_result.diagnostics,
                "capture_error": capture_result.error,
            }
            if baseline_path is not None:
                step_bundle["rmse_vs_explorer"] = image_difference_metric(
                    baseline_path,
                    screenshot_path,
                )
            if baseline_path is None and screenshot_path.exists():
                baseline_path = screenshot_path
            step_results.append(step_bundle)
            print(
                f"[workspace-activity] captured {step['id']} -> {screenshot_path.name}",
                flush=True,
            )
    except Exception as error:
        probe_error = str(error)
    finally:
        terminate_process_group(process)

    bundle = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "window_id": window_id,
        "profile": args.profile,
        "steps": step_results,
        "probe_error": probe_error,
        "log_tail": read_log_tail(log_path),
    }

    result_path = output_root / "result.json"
    result_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"[workspace-activity] results: {result_path}", flush=True)

    has_capture_error = any(step.get("capture_error") for step in step_results)
    return 0 if not probe_error and not has_capture_error else 1


if __name__ == "__main__":
    sys.exit(main())
