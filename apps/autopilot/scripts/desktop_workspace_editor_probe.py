#!/usr/bin/env python3
"""Exercise direct-workspace editor title controls in the desktop shell."""

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
PROBE_WORKSPACE_ROOT = PROJECT_ROOT / "apps/autopilot/src-tauri"
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "docs/evidence/route-hierarchy/live-workspace-editor"
WINDOW_WAIT_TIMEOUT_SECS = 90.0
POST_WINDOW_SETTLE_SECS = 12.0
CLICK_SETTLE_SECS = 1.5

STEP_DEFS = [
    {"id": "baseline-walkthrough", "label": "Walkthrough baseline", "click": None, "expect": None},
    {
        "id": "walkthrough-closed",
        "label": "Close walkthrough tab",
        "click": (0.505, 0.152),
        "expect": None,
    },
    {
        "id": "source-control",
        "label": "Open Source Control",
        "click": (0.070, 0.324),
        "expect": None,
    },
    {
        "id": "open-file",
        "label": "Open probe file",
        "click": (0.180, 0.220),
        "expect": None,
    },
    {
        "id": "file-tab-closed",
        "label": "Close file tab",
        "click": (0.467, 0.145),
        "expect": None,
    },
    {
        "id": "source-control-for-reopen",
        "label": "Return to Source Control",
        "click": (0.070, 0.324),
        "expect": None,
    },
    {
        "id": "file-reopened",
        "label": "Reopen probe file",
        "click": (0.180, 0.220),
        "expect": "open-file",
    },
    {
        "id": "split-from-editor-action",
        "label": "Split editor from editor title action",
        "click": (0.729, 0.154),
        "expect": None,
    },
    {
        "id": "editor-actions-menu",
        "label": "Open editor more-actions menu",
        "click": (0.756, 0.154),
        "expect": None,
    },
    {
        "id": "file-closed-via-editor-menu",
        "label": "Close editor through editor menu",
        "click": (0.687, 0.235),
        "expect": None,
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


def create_probe_file(output_root: Path) -> Path:
    PROBE_WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
    probe_path = PROBE_WORKSPACE_ROOT / f".workspace-editor-probe-{output_root.name}.ts"
    probe_path.write_text(
        "\n".join(
            [
                "export function workspaceEditorProbe(value: number): number {",
                "  return value + 1;",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return probe_path


def remove_probe_file(probe_path: Path | None) -> None:
    if probe_path is None:
        return
    try:
        probe_path.unlink(missing_ok=True)
    except OSError:
        pass


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
    probe_path = create_probe_file(output_root)

    close_matching_windows(args.window_name)
    terminate_existing_desktop_instances()

    process = launch_dev_desktop(args.profile, log_path, args.dev_url)
    print("[workspace-editor] launched Workspace desktop shell", flush=True)

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
            elif step["id"] != "baseline-walkthrough":
                result["rmse_vs_previous"] = image_difference_metric(
                    step_results[-1]["screenshot"]
                    if isinstance(step_results[-1].get("screenshot"), Path)
                    else Path(str(step_results[-1].get("screenshot"))),
                    screenshot_path,
                )
                result["rmse_vs_baseline"] = image_difference_metric(
                    screenshots["baseline-walkthrough"],
                    screenshot_path,
                )
            step_results.append(result)
            print(
                f"[workspace-editor] captured {step['id']} -> {screenshot_path.name}",
                flush=True,
            )
    except Exception as error:  # pragma: no cover - probe diagnostics
        probe_error = str(error)
        print(f"[workspace-editor] error: {probe_error}", file=sys.stderr, flush=True)
    finally:
        terminate_process_group(process)
        remove_probe_file(probe_path)

    receipt = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "window_id": window_id,
        "profile": args.profile,
        "probe_file": str(probe_path.relative_to(PROJECT_ROOT)),
        "steps": step_results,
        "probe_error": probe_error,
        "log_tail": read_log_tail(log_path),
    }
    result_path = output_root / "result.json"
    result_path.write_text(json.dumps(receipt, indent=2))
    print(f"[workspace-editor] results: {result_path}", flush=True)

    return 0 if probe_error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
