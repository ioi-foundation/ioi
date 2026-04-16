#!/usr/bin/env python3
"""Launch the real desktop app with a seeded Studio intent and retain evidence.

This probe avoids flaky synthetic typing by using the app's native
`AUTOPILOT_DEV_START_INTENT` launch path for Studio. Each prompt runs in an
isolated desktop session:
- reset the desktop-localgpu profile
- launch `npm run dev:desktop` with a seeded intent
- wait for the local task to settle
- capture a Studio screenshot and task JSON
- terminate the desktop process group
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
    PROJECT_ROOT / "docs/evidence/route-hierarchy/live-dev-start-intent"
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
    return [
        int(line.strip())
        for line in lines
        if line.strip().isdigit()
    ]


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


def capture_window(window_id: int, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    run(["import", "-window", str(window_id), str(output_path)])


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
    session_manifest = (
        ((task.get("studio_session") or {}).get("artifactManifest")) or {}
    )
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
        candidates.append({
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
        })
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
    if task.get("clarification_request"):
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


def load_prompts(args: argparse.Namespace) -> list[str]:
    prompts: list[str] = []
    prompts.extend(args.prompt or [])
    if args.prompt_file:
        for raw in Path(args.prompt_file).read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                prompts.append(line)
    deduped: list[str] = []
    for prompt in prompts:
        if prompt not in deduped:
            deduped.append(prompt)
    if not deduped:
        raise SystemExit("Provide at least one --prompt or --prompt-file entry.")
    return deduped


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prompt",
        action="append",
        help="Prompt to submit through the live Studio app. Repeat for multiple prompts.",
    )
    parser.add_argument(
        "--prompt-file",
        help="Text file with one prompt per line.",
    )
    parser.add_argument(
        "--db-path",
        default=str(DEFAULT_DB_PATH),
        help=f"Path to the desktop sqlite store. Default: {DEFAULT_DB_PATH}",
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


def launch_dev_desktop(
    prompt: str,
    profile: str,
    log_path: Path,
    *,
    mcp_profile: str | None,
) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env.update(
        {
            "AUTOPILOT_LOCAL_GPU_DEV": "1",
            "AUTOPILOT_RESET_DATA_ON_BOOT": "1",
            "AUTOPILOT_DEV_START_SURFACE": "studio",
            "AUTOPILOT_DEV_START_INTENT": prompt,
            "AUTOPILOT_DATA_PROFILE": profile,
        }
    )
    if mcp_profile:
        env["IOI_STUDIO_MCP_PROFILE"] = mcp_profile
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


def terminate_process_group(process: subprocess.Popen[str]) -> None:
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
    probe_error: str | None = None,
) -> dict[str, Any]:
    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "prompt": prompt,
        "screenshot": str(screenshot_path) if screenshot_path else None,
        "window_id": window_id,
        "window_capture_error": window_capture_error,
        "task": task,
        "route_receipt_summary": latest_route_receipt_summary(task),
        "latest_agent_message": latest_agent_message(task),
        "log_tail": log_tail,
        "probe_error": probe_error,
    }


def main() -> int:
    args = parse_args()
    prompts = load_prompts(args)
    db_paths = candidate_db_paths(Path(args.db_path).expanduser())
    output_root = Path(args.output_root).expanduser() / now_stamp()
    output_root.mkdir(parents=True, exist_ok=True)

    manifest: list[dict[str, Any]] = []

    for index, prompt in enumerate(prompts, start=1):
        slug = safe_slug(prompt)
        prompt_dir = output_root / f"{index:02d}-{slug}"
        prompt_dir.mkdir(parents=True, exist_ok=True)
        desktop_log_path = prompt_dir / "desktop.log"

        process = launch_dev_desktop(
            prompt,
            args.profile,
            desktop_log_path,
            mcp_profile=args.mcp_profile,
        )
        print(f"[{index}/{len(prompts)}] launched :: {prompt}", flush=True)
        screenshot_path: Path | None = None
        task: dict[str, Any] | None = None
        window_id: int | None = None
        window_capture_error: str | None = None
        probe_error: str | None = None

        try:
            window_id = wait_for_window(
                args.window_name,
                timeout_secs=min(args.timeout_secs, WINDOW_WAIT_TIMEOUT_SECS),
            )
            task = wait_for_prompt_result(
                db_paths,
                prompt,
                timeout_secs=args.timeout_secs,
            )
            if window_id is not None:
                time.sleep(POST_SETTLE_CAPTURE_DELAY_SECS)
                screenshot_path = prompt_dir / "final.png"
                capture_window(window_id, screenshot_path)
            else:
                window_capture_error = (
                    f"Timed out waiting for a window matching {args.window_name!r}"
                )
        except Exception as error:
            probe_error = str(error)
            if task is None:
                task = latest_task_for_prompt(db_paths, prompt)
            if window_id is not None:
                time.sleep(POST_SETTLE_CAPTURE_DELAY_SECS)
                screenshot_path = prompt_dir / "final.png"
                capture_window(window_id, screenshot_path)
            elif window_capture_error is None:
                window_capture_error = (
                    f"Timed out waiting for a window matching {args.window_name!r}"
                )
        finally:
            terminate_process_group(process)

        log_tail = read_log_tail(desktop_log_path)
        bundle = build_result_bundle(
            prompt,
            screenshot_path,
            task,
            log_tail,
            window_id=window_id,
            window_capture_error=window_capture_error,
            probe_error=probe_error,
        )
        (prompt_dir / "result.json").write_text(
            json.dumps(bundle, indent=2),
            encoding="utf-8",
        )
        manifest.append(bundle)

        print(
            f"[{index}/{len(prompts)}] {(task or {}).get('phase', 'error').lower()} :: {prompt}",
            flush=True,
        )
        answer = bundle.get("latest_agent_message")
        if answer:
            print(f"  answer: {answer[:160]}", flush=True)

    manifest_path = output_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nRetained desktop seed-intent probe results: {manifest_path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
