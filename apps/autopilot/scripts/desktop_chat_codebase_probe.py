#!/usr/bin/env python3
"""Validate the workbench-grade Chat shell and codebase-first composer path.

The Workspace direct probe proves the contained OpenVSCode surface. This probe
targets the other side of the roadmap: launch the real desktop app in Chat mode,
retain screenshots of the workbench-aligned shell, exercise the Chat command
palette and file-context entry point, submit a prompt through the real composer,
and verify the stored runtime intent contains the codebase context prefix.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shlex
import signal
import sqlite3
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
    now_stamp,
    read_log_tail,
    terminate_existing_desktop_instances,
    terminate_process_group,
    wait_for_window,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT / "docs/evidence/route-hierarchy/live-chat-workbench-convergence"
)
DEFAULT_DB_PATH = (
    Path.home()
    / ".local/share/ai.ioi.autopilot/profiles"
    / DEFAULT_PROFILE
    / "chat-memory.db"
)
DEFAULT_PROMPT = "Explain the active file"
POST_WINDOW_SETTLE_SECS = 8.0
CLICK_SETTLE_SECS = 0.8
PROMPT_START_TIMEOUT_SECS = 20.0


def shell_join(cmd: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in cmd)


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
            f"Command failed ({completed.returncode}): {shell_join(cmd)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return completed


def launch_chat_desktop(
    profile: str,
    log_path: Path,
    dev_url: str,
) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env.update(
        {
            "AUTOPILOT_LOCAL_GPU_DEV": "1",
            "AUTOPILOT_RESET_DATA_ON_BOOT": "1",
            "AUTOPILOT_DATA_PROFILE": profile,
            "VITE_AUTOPILOT_INITIAL_VIEW": "chat",
            "VITE_AUTOPILOT_WORKSPACE_HOST": "direct-openvscode",
            "DEV_URL": dev_url,
            "AUTOPILOT_REUSE_DEV_SERVER": "0",
            "AUTO_START_DEV_SERVER": "1",
        }
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        ["npm", "run", "dev:desktop"],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    setattr(process, "_probe_log_handle", log_handle)
    return process


def window_geometry(window_id: int) -> dict[str, int]:
    result = run(["xdotool", "getwindowgeometry", "--shell", str(window_id)])
    geometry: dict[str, int] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key in {"X", "Y", "WIDTH", "HEIGHT"} and value.strip().isdigit():
            geometry[key] = int(value.strip())
    return geometry


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
    return {"x": safe_x, "y": safe_y, "button": button}


def key(window_id: int, chord: str, *, settle_secs: float = CLICK_SETTLE_SECS) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False, timeout=4.0)
    time.sleep(0.2)
    run(["xdotool", "key", "--clearmodifiers", chord], check=False, timeout=5.0)
    time.sleep(settle_secs)


def type_text(window_id: int, text: str, *, settle_secs: float = CLICK_SETTLE_SECS) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False, timeout=4.0)
    time.sleep(0.2)
    run(["xdotool", "type", "--delay", "8", text], check=False, timeout=15.0)
    time.sleep(settle_secs)


def capture_step(
    window_id: int,
    output_root: Path,
    step_id: str,
    *,
    browser_capture_url: str,
) -> dict[str, Any]:
    screenshot_path = output_root / f"{step_id}.png"
    capture_result = capture_window_with_fallback(
        window_id,
        screenshot_path,
        browser_url=browser_capture_url,
    )
    return {
        "id": step_id,
        "screenshot": str(screenshot_path) if screenshot_path.exists() else None,
        "captureMode": capture_result.mode,
        "captureDiagnostics": capture_result.diagnostics,
        "captureError": capture_result.error,
    }


def analyze_image_region(
    image_path: Path,
    output_root: Path,
    region_id: str,
    bounds: dict[str, int],
) -> dict[str, Any]:
    crop_path = output_root / f"{region_id}.crop.png"
    result: dict[str, Any] = {
        "path": str(crop_path),
        "bounds": bounds,
        "available": False,
    }
    if not image_path.exists():
        result["error"] = "Screenshot is unavailable."
        return result
    crop = run(
        [
            "convert",
            str(image_path),
            "-crop",
            f"{bounds['width']}x{bounds['height']}+{bounds['x']}+{bounds['y']}",
            "+repage",
            str(crop_path),
        ],
        check=False,
        timeout=10.0,
    )
    result["cropReturncode"] = crop.returncode
    result["cropStderr"] = (crop.stderr or "").strip()
    if crop.returncode != 0 or not crop_path.exists():
        result["error"] = result["cropStderr"] or "Region crop failed."
        return result

    metrics = run(
        [
            "identify",
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
        with contextlib.suppress(ValueError):
            result["available"] = True
            result["uniqueColors"] = int(parts[0])
            result["mean"] = float(parts[1])
            result["stddev"] = float(parts[2])
    if not result["available"]:
        result["error"] = f"Could not parse region metrics: {metrics.stdout!r}"
    return result


def region_has_visible_detail(analysis: dict[str, Any]) -> bool:
    try:
        return bool(
            analysis.get("available")
            and int(analysis.get("uniqueColors", 0)) > 24
            and float(analysis.get("stddev", 0.0)) > 0.0001
        )
    except (TypeError, ValueError):
        return False


def load_checkpoint(db_path: Path, checkpoint_name: str) -> dict[str, Any] | None:
    if not db_path.exists():
        return None
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT payload
            FROM checkpoint_blobs
            WHERE checkpoint_name = ?
            ORDER BY updated_at_ms DESC
            LIMIT 1
            """,
            (checkpoint_name,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    payload = row["payload"]
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    return json.loads(payload)


def wait_for_contextualized_prompt(
    db_path: Path,
    original_prompt: str,
    *,
    timeout_secs: float,
) -> dict[str, Any] | None:
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        task = load_checkpoint(db_path, "autopilot.local_task.v1")
        intent = (task or {}).get("intent") or ""
        if (
            isinstance(intent, str)
            and intent.startswith("[Codebase context]")
            and original_prompt in intent
        ):
            return task
        time.sleep(1.0)
    return None


def submit_prompt(window_id: int, prompt: str) -> dict[str, Any]:
    geometry = window_geometry(window_id)
    composer_x = max(
        240,
        min(geometry.get("WIDTH", 1) - 220, int(geometry.get("WIDTH", 1) * 0.55)),
    )
    composer_y = max(
        180,
        min(geometry.get("HEIGHT", 1) - 110, int(geometry.get("HEIGHT", 1) * 0.655)),
    )
    click = click_relative(window_id, composer_x, composer_y)
    type_text(window_id, prompt, settle_secs=0.3)
    key(window_id, "Return", settle_secs=0.8)
    return {"composerClick": click, "prompt": prompt}


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
        "--db-path",
        default=str(DEFAULT_DB_PATH),
        help=f"Path to the desktop sqlite store. Default: {DEFAULT_DB_PATH}",
    )
    parser.add_argument(
        "--dev-url",
        default=DEFAULT_WEB_ROOT,
        help=f"Dev server URL to start. Default: {DEFAULT_WEB_ROOT}",
    )
    parser.add_argument(
        "--browser-capture-url",
        default=DEFAULT_WEB_ROOT,
        help="Browser URL to use if Linux/X11 native window capture is blank.",
    )
    parser.add_argument(
        "--prompt",
        default=DEFAULT_PROMPT,
        help=f"Prompt to submit through the real Chat composer. Default: {DEFAULT_PROMPT!r}",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_root = Path(args.output_root).expanduser() / now_stamp()
    output_root.mkdir(parents=True, exist_ok=True)
    log_path = output_root / "desktop.log"
    db_path = Path(args.db_path).expanduser()

    close_matching_windows(args.window_name)
    terminate_existing_desktop_instances()

    process = launch_chat_desktop(args.profile, log_path, args.dev_url)
    print("[chat-codebase] launched Chat desktop shell", flush=True)

    window_id: int | None = None
    probe_error: str | None = None
    steps: list[dict[str, Any]] = []
    regions: dict[str, Any] = {}
    submission: dict[str, Any] | None = None
    task: dict[str, Any] | None = None

    try:
        window_id = wait_for_window(args.window_name, timeout_secs=90.0)
        if window_id is None:
            raise RuntimeError(
                f"Timed out waiting for a window matching {args.window_name!r}"
            )
        focus_workspace_view(window_id)
        run(["xdotool", "mousemove", "0", "0"], check=False)
        time.sleep(POST_WINDOW_SETTLE_SECS)

        geometry = window_geometry(window_id)
        baseline = capture_step(
            window_id,
            output_root,
            "baseline",
            browser_capture_url=args.browser_capture_url,
        )
        steps.append(baseline)
        baseline_path = Path(str(baseline.get("screenshot") or ""))
        regions["activityBar"] = analyze_image_region(
            baseline_path,
            output_root,
            "activity-bar",
            {
                "x": 0,
                "y": 34,
                "width": min(52, geometry.get("WIDTH", 1)),
                "height": max(1, geometry.get("HEIGHT", 1) - 34),
            },
        )
        regions["header"] = analyze_image_region(
            baseline_path,
            output_root,
            "header",
            {
                "x": 0,
                "y": 0,
                "width": geometry.get("WIDTH", 1),
                "height": min(38, geometry.get("HEIGHT", 1)),
            },
        )
        regions["composerControls"] = analyze_image_region(
            baseline_path,
            output_root,
            "composer-controls",
            {
                "x": max(1, int(geometry.get("WIDTH", 1) * 0.26)),
                "y": max(1, int(geometry.get("HEIGHT", 1) * 0.66)),
                "width": max(1, int(geometry.get("WIDTH", 1) * 0.7)),
                "height": min(110, max(1, geometry.get("HEIGHT", 1) - int(geometry.get("HEIGHT", 1) * 0.66))),
            },
        )

        context_button_click = click_relative(
            window_id,
            max(1, int(geometry.get("WIDTH", 1) * 0.315)),
            max(1, int(geometry.get("HEIGHT", 1) * 0.71)),
        )
        steps.append(
            {
                **capture_step(
                    window_id,
                    output_root,
                    "file-context-entry",
                    browser_capture_url=args.browser_capture_url,
                ),
                "click": context_button_click,
            }
        )

        key(window_id, "Escape", settle_secs=0.4)
        key(window_id, "ctrl+k", settle_secs=0.8)
        type_text(window_id, "review", settle_secs=0.7)
        steps.append(
            capture_step(
                window_id,
                output_root,
                "command-palette-review",
                browser_capture_url=args.browser_capture_url,
            )
        )

        key(window_id, "Escape", settle_secs=0.4)
        submission = submit_prompt(window_id, args.prompt)
        task = wait_for_contextualized_prompt(
            db_path,
            args.prompt,
            timeout_secs=PROMPT_START_TIMEOUT_SECS,
        )
        steps.append(
            capture_step(
                window_id,
                output_root,
                "submitted-contextualized-prompt",
                browser_capture_url=args.browser_capture_url,
            )
        )
        if task is None:
            latest_task = load_checkpoint(db_path, "autopilot.local_task.v1")
            latest_intent = (latest_task or {}).get("intent")
            raise RuntimeError(
                "Timed out waiting for a contextualized Chat runtime intent. "
                f"Latest intent was: {latest_intent!r}"
            )

        if not region_has_visible_detail(regions["activityBar"]):
            raise RuntimeError("Chat activity bar region did not render visibly.")
        if not region_has_visible_detail(regions["header"]):
            raise RuntimeError("Chat header region did not render visibly.")
        if not region_has_visible_detail(regions["composerControls"]):
            raise RuntimeError("Chat composer controls region did not render visibly.")
    except Exception as error:
        probe_error = str(error)
    finally:
        terminate_process_group(process)

    intent = (task or {}).get("intent")
    bundle = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "window_id": window_id,
        "profile": args.profile,
        "steps": steps,
        "regions": regions,
        "submission": submission,
        "taskSummary": {
            "taskId": (task or {}).get("id"),
            "phase": (task or {}).get("phase"),
            "currentStep": (task or {}).get("current_step"),
            "intentStartsWithCodebaseContext": isinstance(intent, str)
            and intent.startswith("[Codebase context]"),
            "intentContainsPrompt": isinstance(intent, str) and args.prompt in intent,
            "intentPreview": intent[:800] if isinstance(intent, str) else None,
        },
        "acceptance": {
            "activityBarVisible": region_has_visible_detail(regions.get("activityBar", {})),
            "headerVisible": region_has_visible_detail(regions.get("header", {})),
            "composerControlsVisible": region_has_visible_detail(
                regions.get("composerControls", {}),
            ),
            "commandPaletteCaptured": any(
                step.get("id") == "command-palette-review"
                and step.get("screenshot")
                for step in steps
            ),
            "fileContextEntryCaptured": any(
                step.get("id") == "file-context-entry" and step.get("screenshot")
                for step in steps
            ),
            "composerSubmittedCodebaseContext": isinstance(intent, str)
            and intent.startswith("[Codebase context]")
            and args.prompt in intent,
        },
        "probe_error": probe_error,
        "log_tail": read_log_tail(log_path),
    }

    result_path = output_root / "result.json"
    result_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"[chat-codebase] results: {result_path}", flush=True)
    return 0 if probe_error is None else 1


if __name__ == "__main__":
    sys.exit(main())
