#!/usr/bin/env python3
"""Exercise direct-workspace bottom panel tabs in the desktop shell."""

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
from desktop_workspace_activity_probe import (
    click_window_ratio,
    image_difference_metric,
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
    wait_for_window,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "docs/evidence/route-hierarchy/live-workspace-panel"
WINDOW_WAIT_TIMEOUT_SECS = 90.0
POST_WINDOW_SETTLE_SECS = 12.0
CLICK_SETTLE_SECS = 1.5

STEP_DEFS = [
    {"id": "baseline-hidden", "label": "Hidden panel baseline", "click": None, "expect": None},
    {
        "id": "output-open",
        "label": "Output panel opened from toolbar",
        "click": (0.988, 0.092),
        "expect": None,
    },
    {
        "id": "terminal-open",
        "label": "Terminal panel",
        "click": (0.337, 0.713),
        "expect": None,
    },
    {"id": "problems", "label": "Problems panel", "click": (0.400, 0.713), "expect": None},
    {"id": "ports", "label": "Ports panel", "click": (0.510, 0.713), "expect": None},
    {
        "id": "output-restored",
        "label": "Output panel restored",
        "click": (0.462, 0.713),
        "expect": None,
    },
    {
        "id": "output-repeat",
        "label": "Output panel repeat click",
        "click": (0.462, 0.713),
        "expect": "output-restored",
    },
    {
        "id": "panel-hidden",
        "label": "Panel hidden from open tab row",
        "click": (0.748, 0.713),
        "expect": "baseline-hidden",
    },
]


def clear_hover(window_id: int) -> None:
    geometry = window_geometry(window_id)
    origin_x = geometry.get("X")
    origin_y = geometry.get("Y")
    width = geometry.get("WIDTH")
    height = geometry.get("HEIGHT")
    if origin_x is None or origin_y is None or not width or not height:
        return

    target_x = origin_x + int(width * 0.58)
    target_y = origin_y + int(height * 0.42)
    subprocess.run(["xdotool", "mousemove", str(target_x), str(target_y)], check=False)
    time.sleep(0.15)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    parser.add_argument("--window-name", default=WINDOW_SEARCH_PATTERN)
    parser.add_argument("--timeout-secs", type=float, default=WINDOW_WAIT_TIMEOUT_SECS)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--dev-url", default=DEFAULT_WEB_ROOT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_root = Path(args.output_root).expanduser() / now_stamp()
    output_root.mkdir(parents=True, exist_ok=True)
    log_path = output_root / "desktop.log"

    close_matching_windows(args.window_name)
    terminate_existing_desktop_instances()

    process = launch_dev_desktop(args.profile, log_path, args.dev_url)
    print("[workspace-panel] launched Workspace desktop shell", flush=True)

    probe_error: str | None = None
    window_id: int | None = None
    step_results: list[dict[str, Any]] = []
    screenshots: dict[str, Path] = {}

    try:
        window_id = wait_for_window(args.window_name, timeout_secs=args.timeout_secs)
        if window_id is None:
            raise RuntimeError(
                f"Timed out waiting for a window matching {args.window_name!r}"
            )

        focus_workspace_view(window_id)
        time.sleep(POST_WINDOW_SETTLE_SECS)

        for step in STEP_DEFS:
            screenshot_path = output_root / f"{step['id']}.png"
            click_point = None
            if step["click"] is not None:
                click_point = click_window_ratio(
                    window_id,
                    float(step["click"][0]),
                    float(step["click"][1]),
                )
                time.sleep(CLICK_SETTLE_SECS)
                clear_hover(window_id)

            capture_result = capture_window_with_fallback(
                window_id,
                screenshot_path,
                browser_url=None,
            )
            screenshots[step["id"]] = screenshot_path
            result: dict[str, Any] = {
                "id": step["id"],
                "label": step["label"],
                "click": click_point,
                "screenshot": str(screenshot_path) if screenshot_path.exists() else None,
                "capture_mode": capture_result.mode,
                "capture_diagnostics": capture_result.diagnostics,
                "capture_error": capture_result.error,
            }
            expected = step["expect"]
            if expected:
                result["rmse_vs_expected"] = image_difference_metric(
                    screenshots[expected],
                    screenshot_path,
                )
            elif step["id"] != "baseline-hidden":
                result["rmse_vs_baseline"] = image_difference_metric(
                    screenshots["baseline-hidden"],
                    screenshot_path,
                )
            step_results.append(result)
            print(
                f"[workspace-panel] captured {step['id']} -> {screenshot_path.name}",
                flush=True,
            )
    except Exception as error:  # pragma: no cover - probe diagnostics
        probe_error = str(error)
        print(f"[workspace-panel] error: {probe_error}", file=sys.stderr, flush=True)
    finally:
        terminate_process_group(process)

    receipt = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "window_id": window_id,
        "profile": args.profile,
        "steps": step_results,
        "probe_error": probe_error,
        "log_tail": read_log_tail(log_path),
    }
    result_path = output_root / "result.json"
    result_path.write_text(json.dumps(receipt, indent=2))
    print(f"[workspace-panel] results: {result_path}", flush=True)

    return 0 if probe_error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
