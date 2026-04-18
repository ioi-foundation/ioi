#!/usr/bin/env python3
"""Validate retained-session follow-ups in the real desktop app.

This probe launches the local desktop app with an initial Studio seed intent,
waits for the initial task to settle, then relaunches the desktop app with a
second seeded intent on the same profile without resetting data. The follow-up
is considered successful only when the existing session history records:

1. the follow-up user turn, and
2. a non-empty agent reply after that turn.

The resulting manifest can be validated with `validate_desktop_parity.py`.
"""

from __future__ import annotations

import argparse
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


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PROFILE = "desktop-localgpu"
DEFAULT_DB_PATH = (
    Path.home()
    / ".local/share/ai.ioi.autopilot/profiles"
    / DEFAULT_PROFILE
    / "studio-memory.db"
)
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT / "docs/evidence/route-hierarchy/live-final-gap-reuse-native-final"
)
WINDOW_SEARCH_PATTERN = "Autopilot Studio"
POLL_INTERVAL_SECS = 1.0
WINDOW_WAIT_TIMEOUT_SECS = 90.0
POST_SETTLE_CAPTURE_DELAY_SECS = 2.0


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


def safe_slug(value: str, max_len: int = 64) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not slug:
        slug = "prompt"
    return slug[:max_len].rstrip("-")


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


def focus_window(window_id: int) -> None:
    run(["xdotool", "windowactivate", "--sync", str(window_id)])
    time.sleep(0.2)


def window_geometry(window_id: int) -> dict[str, int]:
    result = run(["xdotool", "getwindowgeometry", "--shell", str(window_id)])
    geometry: dict[str, int] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key_name, _, value = line.partition("=")
        key_name = key_name.strip().upper()
        value = value.strip()
        if key_name in {"WIDTH", "HEIGHT"} and value.isdigit():
            geometry[key_name] = int(value)
    return geometry


def click_window_ratio(window_id: int, x_ratio: float, y_ratio: float) -> None:
    geometry = window_geometry(window_id)
    width = geometry.get("WIDTH")
    height = geometry.get("HEIGHT")
    if not width or not height:
        raise RuntimeError(f"Could not determine geometry for window {window_id}")
    rel_x = max(1, min(width - 1, int(width * x_ratio)))
    rel_y = max(1, min(height - 1, int(height * y_ratio)))
    run(
        [
            "xdotool",
            "mousemove",
            "--window",
            str(window_id),
            str(rel_x),
            str(rel_y),
            "click",
            "1",
        ]
    )
    time.sleep(0.2)


def key(key_spec: str, *, window_id: int | None = None) -> None:
    cmd = ["xdotool", "key"]
    if window_id is not None:
        cmd.extend(["--window", str(window_id)])
    cmd.extend(["--clearmodifiers", key_spec])
    run(cmd)


def type_text(text_value: str, *, window_id: int | None = None) -> None:
    cmd = ["xdotool", "type"]
    if window_id is not None:
        cmd.extend(["--window", str(window_id)])
    cmd.extend(["--delay", "8", text_value])
    run(cmd)


def submit_clarification_follow_up(
    window_id: int,
    prompt: str,
    *,
    option_count: int,
) -> None:
    focus_window(window_id)
    click_window_ratio(window_id, 0.5, 0.45)
    tab_stops = max(1, option_count + 1)
    for _ in range(tab_stops):
        key("Tab", window_id=window_id)
        time.sleep(0.1)
    type_text(prompt, window_id=window_id)
    time.sleep(0.2)
    key("ctrl+Return", window_id=window_id)


def capture_window(window_id: int, output_path: Path) -> str | None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            ["import", "-window", str(window_id), str(output_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=8,
        )
    except subprocess.TimeoutExpired:
        return f"Timed out capturing window {window_id}"
    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        return stderr or f"Window capture exited with {completed.returncode}"
    return None


def load_task_checkpoint(db_path: Path) -> dict[str, Any] | None:
    if not db_path.exists() or db_path.stat().st_size == 0:
        return None

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        table_row = conn.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table' AND name = 'checkpoint_blobs'
            LIMIT 1
            """
        ).fetchone()
        if table_row is None:
            return None
        row = conn.execute(
            """
            SELECT payload
            FROM checkpoint_blobs
            WHERE checkpoint_name = ?
            ORDER BY updated_at_ms DESC
            LIMIT 1
            """,
            ("autopilot.local_task.v1",),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    finally:
        conn.close()

    if row is None:
        return None

    payload = row["payload"]
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    return json.loads(payload)


def candidate_db_paths(db_path: Path) -> list[Path]:
    candidates: list[Path] = [db_path]
    if db_path.name == "studio-memory.db":
        candidates.append(db_path.parent / "kernel" / "desktop-memory.db")
    elif db_path.name == "desktop-memory.db":
        candidates.append(db_path.parent.parent / "studio-memory.db")
    deduped: list[Path] = []
    for path in candidates:
        if path not in deduped:
            deduped.append(path)
    return deduped


def load_task_checkpoint_from_candidates(db_paths: list[Path]) -> dict[str, Any] | None:
    for path in db_paths:
        task = load_task_checkpoint(path)
        if task:
            return task
    return None


def latest_task_for_prompt(db_paths: list[Path], prompt: str) -> dict[str, Any] | None:
    task = load_task_checkpoint_from_candidates(db_paths)
    if not task:
        return None
    if (task.get("intent") or "").strip() != prompt.strip():
        return None
    return task


def latest_agent_message(task: dict[str, Any] | None) -> str | None:
    if not task:
        return None
    for item in reversed(task.get("history", [])):
        if item.get("role") == "agent":
            text = (item.get("text") or "").strip()
            if text:
                return text
    return None


def merged_artifact_manifest_for_summary(
    task: dict[str, Any],
    artifact_manifest: dict[str, Any] | None,
) -> dict[str, Any]:
    merged = dict(artifact_manifest or {})
    session_manifest = (((task.get("studio_session") or {}).get("artifactManifest")) or {})
    if not isinstance(session_manifest, dict) or not session_manifest:
        return merged
    for key, value in session_manifest.items():
        if value not in (None, "", [], {}):
            merged[key] = value
    merged_verification = dict((artifact_manifest or {}).get("verification") or {})
    for key, value in (session_manifest.get("verification") or {}).items():
        if value not in (None, ""):
            merged_verification[key] = value
    if merged_verification:
        merged["verification"] = merged_verification
    return merged


def latest_route_receipt_summary(task: dict[str, Any] | None) -> dict[str, Any] | None:
    if not task:
        return None
    candidates: list[dict[str, Any]] = []
    for event in task.get("events", []):
        if (event.get("event_type") or "").strip().upper() != "RECEIPT":
            continue
        digest = event.get("digest") or {}
        details = event.get("details") or {}
        route_decision = digest.get("route_decision")
        artifact_manifest = details.get("artifactManifest") or {}
        if not (
            route_decision
            or digest.get("selected_route")
            or digest.get("route_family")
            or artifact_manifest
        ):
            continue
        artifact_manifest = merged_artifact_manifest_for_summary(task, artifact_manifest)
        verification = artifact_manifest.get("verification") or {}
        candidates.append(
            {
                "title": event.get("title"),
                "selected_route": digest.get("selected_route"),
                "route_family": digest.get("route_family"),
                "planner_authority": digest.get("planner_authority"),
                "verifier_state": digest.get("verifier_state"),
                "artifact_class": digest.get("artifact_class"),
                "route_decision": route_decision,
                "artifact_manifest_summary": {
                    "title": artifact_manifest.get("title"),
                    "renderer": artifact_manifest.get("renderer"),
                    "primary_tab": artifact_manifest.get("primaryTab"),
                    "tabs": [
                        tab.get("id")
                        for tab in artifact_manifest.get("tabs", [])
                        if isinstance(tab, dict) and tab.get("id")
                    ],
                    "lifecycle_state": verification.get("lifecycleState"),
                    "verification_status": verification.get("status"),
                    "verification_summary": verification.get("summary"),
                },
            }
        )
    if not candidates:
        return None
    candidates.sort(
        key=lambda receipt: (
            1 if receipt.get("route_decision") else 0,
            1 if receipt.get("selected_route") else 0,
            1 if "route decision" in (receipt.get("title") or "").lower() else 0,
        ),
        reverse=True,
    )
    return candidates[0]


def task_has_interactive_wait_state(task: dict[str, Any]) -> bool:
    phase = (task.get("phase") or "").strip().lower()
    if phase == "gate" and task.get("clarification_request"):
        return True
    if task.get("credential_request"):
        return True
    if task.get("gate_info") or task.get("pending_request_hash"):
        return True
    current_step = (task.get("current_step") or "").strip().lower()
    return "waiting for clarification" in current_step or "waiting for approval" in current_step


def wait_for_prompt_result(
    db_paths: list[Path],
    prompt: str,
    *,
    timeout_secs: float,
) -> dict[str, Any]:
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        task = load_task_checkpoint_from_candidates(db_paths)
        if task and (task.get("intent") or "").strip() == prompt.strip():
            phase = (task.get("phase") or "").strip().lower()
            if phase in {"complete", "failed"} or task_has_interactive_wait_state(task):
                return task
        time.sleep(POLL_INTERVAL_SECS)
    raise TimeoutError(
        f"Timed out after {timeout_secs:.0f}s waiting for prompt result: {prompt}"
    )


def last_history_index(history: list[dict[str, Any]], role: str, text: str) -> int | None:
    text = text.strip()
    for index in range(len(history) - 1, -1, -1):
        item = history[index]
        if item.get("role") != role:
            continue
        if (item.get("text") or "").strip() == text:
            return index
    return None


def first_agent_reply_after(history: list[dict[str, Any]], index: int) -> str | None:
    for item in history[index + 1 :]:
        if item.get("role") != "agent":
            continue
        text = (item.get("text") or "").strip()
        if text:
            return text
    return None


def count_history_occurrences(history: list[dict[str, Any]], role: str, text: str) -> int:
    text = text.strip()
    return sum(
        1
        for item in history
        if item.get("role") == role and (item.get("text") or "").strip() == text
    )


def parse_event_timestamp_ms(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


def latest_artifact_session_details(task: dict[str, Any] | None) -> dict[str, Any]:
    if not task:
        return {}
    studio_session = task.get("studio_session")
    if isinstance(studio_session, dict):
        return studio_session
    for event in reversed(task.get("events") or []):
        details = event.get("details") or {}
        if isinstance(details, dict) and isinstance(details.get("artifactManifest"), dict):
            return details
    return {}


def latest_artifact_revision_id(task: dict[str, Any] | None) -> str | None:
    details = latest_artifact_session_details(task)
    revision_id = (details.get("activeRevisionId") or "").strip()
    return revision_id or None


def artifact_session_ready(task: dict[str, Any] | None) -> bool:
    if not task:
        return False
    details = latest_artifact_session_details(task)
    studio_status = (details.get("status") or "").strip().lower()
    verification = details.get("artifactManifest") or {}
    verification_status = (
        ((verification.get("verification") or {}).get("lifecycleState") or "").strip().lower()
    )
    return "ready" in {studio_status, verification_status}


def follow_up_artifact_completion_present(
    task: dict[str, Any] | None,
    *,
    after_user_timestamp_ms: int | None,
    baseline_revision_id: str | None,
) -> bool:
    if not task:
        return False
    if not artifact_session_ready(task):
        return False
    current_revision_id = latest_artifact_revision_id(task)
    if (
        baseline_revision_id is not None
        and current_revision_id is not None
        and current_revision_id != baseline_revision_id
    ):
        return True
    for event in reversed(task.get("events", [])):
        if (event.get("event_type") or "").strip().upper() != "RECEIPT":
            continue
        event_timestamp_ms = parse_event_timestamp_ms(event.get("timestamp"))
        if after_user_timestamp_ms is not None and (
            event_timestamp_ms is None or event_timestamp_ms <= after_user_timestamp_ms
        ):
            continue
        title = (event.get("title") or "").strip().lower()
        if title.startswith("studio refined ") or title.startswith("studio created "):
            return True
    return False


def wait_for_follow_up_result(
    db_paths: list[Path],
    follow_up_prompt: str,
    *,
    baseline_session_id: str | None,
    baseline_revision_id: str | None,
    timeout_secs: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        task = load_task_checkpoint_from_candidates(db_paths)
        if not task:
            time.sleep(POLL_INTERVAL_SECS)
            continue

        history = task.get("history") or []
        user_index = last_history_index(history, "user", follow_up_prompt)
        user_occurrences = count_history_occurrences(history, "user", follow_up_prompt)
        if user_index is None:
            time.sleep(POLL_INTERVAL_SECS)
            continue

        reply = first_agent_reply_after(history, user_index)
        phase = (task.get("phase") or "").strip().lower()
        user_timestamp_ms = history[user_index].get("timestamp") if user_index is not None else None
        metadata = {
            "follow_up_user_occurrences": user_occurrences,
            "follow_up_user_index": user_index,
            "follow_up_agent_reply_present": bool(reply),
            "follow_up_agent_reply": reply,
            "follow_up_artifact_completion_present": follow_up_artifact_completion_present(
                task,
                after_user_timestamp_ms=user_timestamp_ms,
                baseline_revision_id=baseline_revision_id,
            ),
            "session_reused": (
                baseline_session_id is not None
                and (task.get("session_id") or task.get("id")) == baseline_session_id
            ),
        }
        if reply or metadata["follow_up_artifact_completion_present"]:
            return task, metadata
        if phase == "failed" or task_has_interactive_wait_state(task):
            return task, metadata
        time.sleep(POLL_INTERVAL_SECS)
    raise TimeoutError(
        f"Timed out after {timeout_secs:.0f}s waiting for prompt result: {follow_up_prompt}"
    )


def launch_dev_desktop(
    prompt: str,
    profile: str,
    log_path: Path,
    *,
    mcp_profile: str | None,
    reset_on_boot: bool,
    start_session_id: str | None = None,
) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env.update(
        {
            "AUTOPILOT_LOCAL_GPU_DEV": "1",
            "AUTOPILOT_DEV_START_SURFACE": "studio",
            "AUTOPILOT_DEV_START_INTENT": prompt,
            "AUTOPILOT_DATA_PROFILE": profile,
        }
    )
    if reset_on_boot:
        env["AUTOPILOT_RESET_DATA_ON_BOOT"] = "1"
    else:
        env["AUTOPILOT_RESET_DATA_ON_BOOT"] = "0"
    if mcp_profile:
        env["IOI_STUDIO_MCP_PROFILE"] = mcp_profile
    if start_session_id:
        env["AUTOPILOT_DEV_START_SESSION_ID"] = start_session_id
    else:
        env.pop("AUTOPILOT_DEV_START_SESSION_ID", None)
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


def read_log_tail(log_path: Path, max_lines: int = 120) -> list[str]:
    if not log_path.exists():
        return []
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-max_lines:]


def terminate_process_group(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    if process.poll() is not None:
        log_handle = getattr(process, "_probe_log_handle", None)
        if log_handle is not None and not log_handle.closed:
            log_handle.close()
        return
    try:
        try:
            os.killpg(process.pid, signal.SIGINT)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=15)
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


def build_result_bundle(
    prompt: str,
    screenshot_path: Path | None,
    task: dict[str, Any] | None,
    log_tail: list[str],
    *,
    window_id: int | None,
    window_capture_error: str | None,
    follow_up_submission_mode: str | None = None,
    probe_error: str | None = None,
    follow_up_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    bundle = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "prompt": prompt,
        "screenshot": str(screenshot_path) if screenshot_path else None,
        "window_id": window_id,
        "window_capture_error": window_capture_error,
        "task": task,
        "route_receipt_summary": latest_route_receipt_summary(task),
        "latest_agent_message": latest_agent_message(task),
        "log_tail": log_tail,
        "follow_up_submission_mode": follow_up_submission_mode,
        "probe_error": probe_error,
    }
    if follow_up_metadata:
        bundle["follow_up_metadata"] = follow_up_metadata
    return bundle


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initial-prompt", required=True)
    parser.add_argument("--follow-up-prompt", required=True)
    parser.add_argument(
        "--db-path",
        help=(
            "Path to the desktop sqlite store. Defaults to the selected profile's "
            "studio-memory.db."
        ),
    )
    parser.add_argument(
        "--output-root",
        default=str(DEFAULT_OUTPUT_ROOT),
        help=f"Directory to retain screenshots and receipts. Default: {DEFAULT_OUTPUT_ROOT}",
    )
    parser.add_argument(
        "--timeout-secs",
        type=float,
        default=180.0,
        help="How long to wait for each prompt to settle.",
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
        "--mcp-profile",
        help="Optional IOI_STUDIO_MCP_PROFILE override for the launched desktop app.",
    )
    return parser.parse_args()


def resolve_db_path(args: argparse.Namespace) -> Path:
    if args.db_path:
        return Path(args.db_path).expanduser()
    return (
        Path.home()
        / ".local/share/ai.ioi.autopilot/profiles"
        / args.profile
        / "studio-memory.db"
    )


def main() -> int:
    args = parse_args()
    db_paths = candidate_db_paths(resolve_db_path(args))
    output_root = Path(args.output_root).expanduser() / now_stamp()
    output_root.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, Any]] = []

    first_dir = output_root / f"01-{safe_slug(args.initial_prompt)}"
    second_dir = output_root / f"02-{safe_slug(args.follow_up_prompt)}"
    first_dir.mkdir(parents=True, exist_ok=True)
    second_dir.mkdir(parents=True, exist_ok=True)

    first_log_path = first_dir / "desktop.log"
    second_log_path = second_dir / "desktop.log"

    first_process: subprocess.Popen[str] | None = None
    second_process: subprocess.Popen[str] | None = None
    first_window_id: int | None = None
    second_window_id: int | None = None

    first_task: dict[str, Any] | None = None
    first_probe_error: str | None = None
    first_capture_error: str | None = None
    first_screenshot: Path | None = None

    second_task: dict[str, Any] | None = None
    second_probe_error: str | None = None
    second_capture_error: str | None = None
    second_screenshot: Path | None = None
    follow_up_metadata: dict[str, Any] | None = None
    follow_up_submission_mode: str | None = None
    second_log_tail: list[str] = []

    try:
        first_process = launch_dev_desktop(
            args.initial_prompt,
            args.profile,
            first_log_path,
            mcp_profile=args.mcp_profile,
            reset_on_boot=True,
        )
        print(f"[1/2] launched :: {args.initial_prompt}", flush=True)

        try:
            first_window_id = wait_for_window(
                args.window_name,
                timeout_secs=min(args.timeout_secs, WINDOW_WAIT_TIMEOUT_SECS),
            )
            first_task = wait_for_prompt_result(
                db_paths,
                args.initial_prompt,
                timeout_secs=args.timeout_secs,
            )
            if first_window_id is not None:
                time.sleep(POST_SETTLE_CAPTURE_DELAY_SECS)
                first_screenshot = first_dir / "final.png"
                first_capture_error = capture_window(first_window_id, first_screenshot)
            elif first_capture_error is None:
                first_capture_error = (
                    f"Timed out waiting for a window matching {args.window_name!r}"
                )
        except Exception as error:
            first_probe_error = str(error)
            if first_task is None:
                first_task = latest_task_for_prompt(db_paths, args.initial_prompt)
            if first_window_id is not None:
                time.sleep(POST_SETTLE_CAPTURE_DELAY_SECS)
                first_screenshot = first_dir / "final.png"
                if first_capture_error is None:
                    first_capture_error = capture_window(first_window_id, first_screenshot)
            elif first_capture_error is None:
                first_capture_error = (
                    f"Timed out waiting for a window matching {args.window_name!r}"
                )

        first_bundle = build_result_bundle(
            args.initial_prompt,
            first_screenshot,
            first_task,
            read_log_tail(first_log_path),
            window_id=first_window_id,
            window_capture_error=first_capture_error,
            probe_error=first_probe_error,
        )
        (first_dir / "result.json").write_text(
            json.dumps(first_bundle, indent=2),
            encoding="utf-8",
        )
        manifest.append(first_bundle)
        print(
            f"[1/2] {((first_task or {}).get('phase') or 'error').lower()} :: {args.initial_prompt}",
            flush=True,
        )
        if first_bundle.get("latest_agent_message"):
            print(
                f"  answer: {first_bundle['latest_agent_message'][:160]}",
                flush=True,
            )

        baseline_session_id = None
        baseline_revision_id = None
        if first_task:
            baseline_session_id = first_task.get("session_id") or first_task.get("id")
            baseline_revision_id = latest_artifact_revision_id(first_task)

        terminate_process_group(first_process)
        first_process = None

        second_process = launch_dev_desktop(
            args.follow_up_prompt,
            args.profile,
            second_log_path,
            mcp_profile=args.mcp_profile,
            reset_on_boot=False,
            start_session_id=baseline_session_id,
        )
        follow_up_submission_mode = "seed_intent_session_target_relaunch"
        print(f"[2/2] launched :: {args.follow_up_prompt}", flush=True)

        try:
            second_window_id = wait_for_window(
                args.window_name,
                timeout_secs=min(args.timeout_secs, WINDOW_WAIT_TIMEOUT_SECS),
            )
            if second_window_id is None:
                raise RuntimeError(
                    f"Timed out waiting for a window matching {args.window_name!r}"
                )
            second_task, follow_up_metadata = wait_for_follow_up_result(
                db_paths,
                args.follow_up_prompt,
                baseline_session_id=baseline_session_id,
                baseline_revision_id=baseline_revision_id,
                timeout_secs=args.timeout_secs,
            )
            if second_window_id is not None:
                time.sleep(POST_SETTLE_CAPTURE_DELAY_SECS)
                second_screenshot = second_dir / "final.png"
                second_capture_error = capture_window(second_window_id, second_screenshot)
            elif second_capture_error is None:
                second_capture_error = (
                    f"Timed out waiting for a window matching {args.window_name!r}"
                )
        except Exception as error:
            second_probe_error = str(error)
            second_task = load_task_checkpoint_from_candidates(db_paths)
            if second_task and follow_up_metadata is None:
                history = second_task.get("history") or []
                user_index = last_history_index(history, "user", args.follow_up_prompt)
                user_timestamp_ms = (
                    history[user_index].get("timestamp") if user_index is not None else None
                )
                follow_up_metadata = {
                    "follow_up_user_occurrences": count_history_occurrences(
                        history, "user", args.follow_up_prompt
                    ),
                    "follow_up_user_index": user_index,
                    "follow_up_agent_reply_present": (
                        first_agent_reply_after(history, user_index) is not None
                        if user_index is not None
                        else False
                    ),
                    "follow_up_agent_reply": (
                        first_agent_reply_after(history, user_index)
                        if user_index is not None
                        else None
                    ),
                    "follow_up_artifact_completion_present": follow_up_artifact_completion_present(
                        second_task,
                        after_user_timestamp_ms=user_timestamp_ms,
                        baseline_revision_id=baseline_revision_id,
                    ),
                    "session_reused": (
                        baseline_session_id is not None
                        and (second_task.get("session_id") or second_task.get("id"))
                        == baseline_session_id
                    ),
                }
            if second_window_id is not None:
                time.sleep(POST_SETTLE_CAPTURE_DELAY_SECS)
                second_screenshot = second_dir / "final.png"
                if second_capture_error is None:
                    second_capture_error = capture_window(second_window_id, second_screenshot)
            elif second_capture_error is None:
                second_capture_error = (
                    f"Timed out waiting for a window matching {args.window_name!r}"
                )

        second_log_tail = read_log_tail(second_log_path, max_lines=400)
        second_bundle = build_result_bundle(
            args.follow_up_prompt,
            second_screenshot,
            second_task,
            second_log_tail,
            window_id=second_window_id,
            window_capture_error=second_capture_error,
            follow_up_submission_mode=follow_up_submission_mode,
            probe_error=second_probe_error,
            follow_up_metadata=follow_up_metadata,
        )
        (second_dir / "result.json").write_text(
            json.dumps(second_bundle, indent=2),
            encoding="utf-8",
        )
        manifest.append(second_bundle)
        print(
            f"[2/2] {((second_task or {}).get('phase') or 'error').lower()} :: {args.follow_up_prompt}",
            flush=True,
        )
        if follow_up_metadata:
            print(
                "  follow-up metadata:"
                f" reused={follow_up_metadata.get('session_reused')}"
                f" user_occurrences={follow_up_metadata.get('follow_up_user_occurrences')}"
                f" reply_present={follow_up_metadata.get('follow_up_agent_reply_present')}"
                f" artifact_complete={follow_up_metadata.get('follow_up_artifact_completion_present')}",
                flush=True,
            )
        if second_bundle.get("latest_agent_message"):
            print(
                f"  answer: {second_bundle['latest_agent_message'][:160]}",
                flush=True,
            )
    finally:
        terminate_process_group(first_process)
        terminate_process_group(second_process)

    manifest_path = output_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nRetained desktop reuse-session probe results: {manifest_path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
