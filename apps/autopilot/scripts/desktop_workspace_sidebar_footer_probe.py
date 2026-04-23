#!/usr/bin/env python3
"""Exercise real Explorer footer behavior in the desktop Workspace shell.

This probe proves that the direct host's Explorer footer sections are no longer
painted-only chrome. It first switches into the real Explorer container, then
targets the Outline section because it is the most stable footer control to
click deterministically in the desktop shell.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from desktop_capture import capture_window_with_fallback
from desktop_workspace_activity_probe import (
    click_window_ratio,
    image_difference_metric,
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
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT / "docs/evidence/route-hierarchy/live-workspace-sidebar-footer"
)
WINDOW_WAIT_TIMEOUT_SECS = 90.0
POST_WINDOW_SETTLE_SECS = 12.0
CLICK_SETTLE_SECS = 1.2

STEP_DEFS = [
    {
        "id": "explorer",
        "label": "Switch to Explorer",
        "click": (0.070, 0.202),
    },
    {"id": "baseline", "label": "Explorer baseline", "click": None},
    {
        "id": "outline-open",
        "label": "Open Outline footer section",
        "click": (0.110, 0.918),
    },
    {
        "id": "outline-close",
        "label": "Close Outline footer section",
        "click": (0.110, 0.842),
    },
]


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
        default=DEFAULT_WEB_ROOT,
        help=f"Dev server URL to start. Default: {DEFAULT_WEB_ROOT}",
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
    print("[workspace-sidebar-footer] launched Workspace desktop shell", flush=True)

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

            if step["id"] == "outline-open":
                result["rmse_vs_baseline"] = image_difference_metric(
                    screenshots["baseline"],
                    screenshot_path,
                )
            if step["id"] == "outline-close":
                result["rmse_vs_baseline"] = image_difference_metric(
                    screenshots["baseline"],
                    screenshot_path,
                )
                result["rmse_vs_outline_open"] = image_difference_metric(
                    screenshots["outline-open"],
                    screenshot_path,
                )

            step_results.append(result)
            print(
                f"[workspace-sidebar-footer] captured {step['id']} -> {screenshot_path.name}",
                flush=True,
            )
    except Exception as error:  # pragma: no cover - probe diagnostics
        probe_error = str(error)
        print(
            f"[workspace-sidebar-footer] error: {probe_error}",
            file=sys.stderr,
            flush=True,
        )
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
    print(f"[workspace-sidebar-footer] results: {result_path}", flush=True)

    has_capture_error = any(step.get("capture_error") for step in step_results)
    return 0 if probe_error is None and not has_capture_error else 1


if __name__ == "__main__":
    raise SystemExit(main())
