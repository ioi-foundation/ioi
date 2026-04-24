#!/usr/bin/env python3
"""Launch the real desktop app into Workspace and retain a GUI validation bundle.

This probe exists specifically for the direct Workspace workbench path:
- launch `npm run dev:desktop` against the Workspace route directly
- wait for the real Tauri window
- retain a screenshot, desktop log tail, and capture metadata

On Linux/X11, per-window captures can intermittently come back as uniform black
images even when WebKit is rendering correctly. The shared desktop capture
helper detects that case and falls back to a headless screenshot of the matching
Vite route so parity evidence stays usable.
"""

from __future__ import annotations

import argparse
import json
import os
import contextlib
import shlex
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from desktop_capture import capture_window_with_fallback


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PROFILE = "desktop-localgpu"
DEFAULT_WEB_ROOT = "http://127.0.0.1:1433"
DEFAULT_DEV_URL = DEFAULT_WEB_ROOT
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT / "docs/evidence/route-hierarchy/live-workspace-workbench"
)
WINDOW_SEARCH_PATTERN = "Autopilot Chat"
BROWSER_CAPTURE_URL = f"{DEFAULT_WEB_ROOT}/?view=workspace"
POLL_INTERVAL_SECS = 1.0
WINDOW_WAIT_TIMEOUT_SECS = 90.0
POST_WINDOW_SETTLE_SECS = 12.0
CAPTURE_RETRY_INTERVAL_SECS = 2.0
CAPTURE_READY_MEAN_THRESHOLD = 0.2
CAPTURE_READY_TIMEOUT_SECS = 30.0


def shell_join(cmd: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in cmd)


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
            f"Command failed ({completed.returncode}): {shell_join(cmd)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return completed


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


def window_ids_from_wmctrl(window_pattern: str) -> list[int]:
    result = run(["wmctrl", "-l"], check=False)
    ids: list[int] = []
    for line in result.stdout.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        window_hex, _, _, title = parts
        if window_pattern.lower() not in title.lower():
            continue
        try:
            ids.append(int(window_hex, 16))
        except ValueError:
            continue
    return ids


def window_ids_from_xdotool(window_pattern: str) -> list[int]:
    result = run(["xdotool", "search", "--name", window_pattern], check=False)
    lines = list(result.stdout.splitlines()) + list(result.stderr.splitlines())
    return [int(line.strip()) for line in lines if line.strip().isdigit()]


def wait_for_window(window_pattern: str, *, timeout_secs: float) -> int | None:
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        window_ids = window_ids_from_wmctrl(window_pattern)
        if not window_ids:
            window_ids = window_ids_from_xdotool(window_pattern)
        if window_ids:
            return window_ids[-1]
        time.sleep(POLL_INTERVAL_SECS)
    return None


def close_matching_windows(window_pattern: str) -> None:
    window_ids = {
        *window_ids_from_wmctrl(window_pattern),
        *window_ids_from_xdotool(window_pattern),
    }
    for window_id in window_ids:
        run(["wmctrl", "-ic", hex(window_id)], check=False)
        run(["xdotool", "windowclose", str(window_id)], check=False)
    if window_ids:
        time.sleep(1.0)


def terminate_existing_desktop_instances() -> None:
    result = run(["pgrep", "-f", "/target/debug/autopilot"], check=False)
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.isdigit():
            continue
        pid = int(line)
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGTERM)
    if result.stdout.strip():
        time.sleep(1.5)


def launch_dev_desktop(
    profile: str,
    log_path: Path,
    dev_url: str,
    workspace_host: str | None,
) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env.update(
        {
            "AUTOPILOT_LOCAL_GPU_DEV": "1",
            "AUTOPILOT_RESET_DATA_ON_BOOT": "1",
            "AUTOPILOT_DATA_PROFILE": profile,
            "VITE_AUTOPILOT_INITIAL_VIEW": "workspace",
            "DEV_URL": dev_url,
            "AUTOPILOT_REUSE_DEV_SERVER": "0",
            "AUTO_START_DEV_SERVER": "1",
        }
    )
    if workspace_host:
        env["VITE_AUTOPILOT_WORKSPACE_HOST"] = workspace_host
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


def read_log_tail(log_path: Path, max_lines: int = 160) -> list[str]:
    if not log_path.exists():
        return []
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-max_lines:]


def terminate_process_group(process: subprocess.Popen[str]) -> None:
    try:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGINT)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=5)
    finally:
        log_handle = getattr(process, "_probe_log_handle", None)
        if log_handle is not None and not log_handle.closed:
            log_handle.close()


def focus_workspace_view(window_id: int) -> None:
    run(["xdotool", "windowactivate", "--sync", str(window_id)], check=False)
    time.sleep(0.35)


def move_pointer_off_window() -> None:
    run(["xdotool", "mousemove", "0", "0"], check=False)
    time.sleep(0.2)


def capture_looks_ready(diagnostics: dict[str, Any] | None) -> bool:
    if not diagnostics:
        return False

    analysis = diagnostics.get("window_analysis")
    if not isinstance(analysis, dict):
        analysis = diagnostics.get("browser_analysis")
    if not isinstance(analysis, dict):
        return False

    mean = analysis.get("mean")
    try:
        return float(mean) >= CAPTURE_READY_MEAN_THRESHOLD
    except (TypeError, ValueError):
        return False


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
        "--browser-capture-url",
        default=os.environ.get("AUTOPILOT_DESKTOP_CAPTURE_URL", BROWSER_CAPTURE_URL),
        help=(
            "Browser URL to use when Linux/X11 window capture comes back blank. "
            f"Default: {BROWSER_CAPTURE_URL}"
        ),
    )
    parser.add_argument(
        "--dev-url",
        default=os.environ.get("AUTOPILOT_DESKTOP_DEV_URL", DEFAULT_DEV_URL),
        help=f"Dev server URL to start/reuse. Default: {DEFAULT_DEV_URL}",
    )
    parser.add_argument(
        "--workspace-host",
        default=os.environ.get("VITE_AUTOPILOT_WORKSPACE_HOST"),
        help=(
            "Workspace host override. Use 'iframe-oracle' only for retained "
            "OpenVSCode iframe comparison evidence."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_root = Path(args.output_root).expanduser() / now_stamp()
    output_root.mkdir(parents=True, exist_ok=True)
    log_path = output_root / "desktop.log"
    screenshot_path = output_root / "workspace.png"

    close_matching_windows(args.window_name)
    terminate_existing_desktop_instances()

    process = launch_dev_desktop(
        args.profile,
        log_path,
        args.dev_url,
        args.workspace_host,
    )
    print("[workspace] launched Workspace desktop shell", flush=True)

    window_id: int | None = None
    capture_mode: str | None = None
    capture_diagnostics: dict[str, Any] | None = None
    capture_error: str | None = None
    probe_error: str | None = None

    try:
        window_id = wait_for_window(
            args.window_name,
            timeout_secs=min(args.timeout_secs, WINDOW_WAIT_TIMEOUT_SECS),
        )
        if window_id is None:
            raise RuntimeError(
                f"Timed out waiting for a window matching {args.window_name!r}"
            )

        focus_workspace_view(window_id)
        move_pointer_off_window()
        time.sleep(POST_WINDOW_SETTLE_SECS)
        ready_deadline = time.time() + CAPTURE_READY_TIMEOUT_SECS
        while True:
            capture_result = capture_window_with_fallback(
                window_id,
                screenshot_path,
                browser_url=args.browser_capture_url,
            )
            capture_mode = capture_result.mode
            capture_diagnostics = capture_result.diagnostics
            capture_error = capture_result.error
            if capture_error or capture_looks_ready(capture_diagnostics):
                break
            if time.time() >= ready_deadline:
                break
            time.sleep(CAPTURE_RETRY_INTERVAL_SECS)
    except Exception as error:
        probe_error = str(error)
    finally:
        terminate_process_group(process)

    bundle = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "window_id": window_id,
        "profile": args.profile,
        "screenshot": str(screenshot_path) if screenshot_path.exists() else None,
        "capture_mode": capture_mode,
        "capture_diagnostics": capture_diagnostics,
        "window_capture_error": capture_error,
        "probe_error": probe_error,
        "log_tail": read_log_tail(log_path),
    }

    result_path = output_root / "result.json"
    result_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"[workspace] results: {result_path}", flush=True)
    return 0 if not probe_error and not capture_error else 1


if __name__ == "__main__":
    sys.exit(main())
