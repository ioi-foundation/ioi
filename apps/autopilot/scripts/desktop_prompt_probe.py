#!/usr/bin/env python3
"""Drive the local Autopilot desktop app with real prompts and retain receipts.

This probe is intentionally lightweight:
- it reuses a running `npm run dev:desktop` session
- it submits prompts through the real Studio window with xdotool/wmctrl
- it polls the local desktop profile sqlite store for the latest task state
- it saves a screenshot plus a JSON receipt bundle per prompt

The script is designed for parity validation, not pixel-perfect UI automation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
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
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "docs/evidence/route-hierarchy/live-desktop-parity"

WINDOW_SEARCH_PATTERN = "Autopilot Chat"
NEW_OUTCOME_X = 120
NEW_OUTCOME_Y = 150
COMPOSER_X_RATIO = 0.38
COMPOSER_MIN_X = 240
COMPOSER_MIN_Y = 180
COMPOSER_BOTTOM_OFFSET = 145
COMPOSER_SIDE_MARGIN = 220
POLL_INTERVAL_SECS = 1.0
POST_SETTLE_CAPTURE_DELAY_SECS = 2.0


@dataclass
class WindowGeometry:
    window_id: int
    x: int
    y: int
    width: int
    height: int

    def abs_point(self, rel_x: int, rel_y: int) -> tuple[int, int]:
        return self.x + rel_x, self.y + rel_y


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


def find_window(window_pattern: str) -> WindowGeometry:
    result = run(["xdotool", "search", "--name", window_pattern])
    ids = [
        int(line.strip())
        for line in result.stdout.splitlines()
        if line.strip().isdigit()
    ]
    if not ids:
        raise RuntimeError(
            "Could not find an Autopilot desktop window. Start `npm run dev:desktop` first."
        )

    window_id = ids[-1]
    geometry = run(["xdotool", "getwindowgeometry", "--shell", str(window_id)]).stdout
    values: dict[str, int] = {}
    for line in geometry.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if value.isdigit():
            values[key] = int(value)
    required = ["X", "Y", "WIDTH", "HEIGHT"]
    missing = [key for key in required if key not in values]
    if missing:
        raise RuntimeError(f"Could not parse window geometry for {window_id}: missing {missing}")
    return WindowGeometry(
        window_id=window_id,
        x=values["X"],
        y=values["Y"],
        width=values["WIDTH"],
        height=values["HEIGHT"],
    )


def focus_window(window: WindowGeometry) -> None:
    run(["xdotool", "windowactivate", "--sync", str(window.window_id)])
    time.sleep(0.2)


def click(window: WindowGeometry, rel_x: int, rel_y: int) -> None:
    run(
        [
            "xdotool",
            "mousemove",
            "--window",
            str(window.window_id),
            str(rel_x),
            str(rel_y),
        ]
    )
    run(["xdotool", "click", "1"])
    time.sleep(0.2)


def composer_point(window: WindowGeometry) -> tuple[int, int]:
    rel_x = int(window.width * COMPOSER_X_RATIO)
    rel_y = window.height - COMPOSER_BOTTOM_OFFSET
    rel_x = max(COMPOSER_MIN_X, min(window.width - COMPOSER_SIDE_MARGIN, rel_x))
    rel_y = max(COMPOSER_MIN_Y, min(window.height - COMPOSER_BOTTOM_OFFSET, rel_y))
    return rel_x, rel_y


def key(window: WindowGeometry, key_spec: str) -> None:
    run(["xdotool", "key", "--clearmodifiers", key_spec])


def type_text(window: WindowGeometry, text_value: str) -> None:
    run(
        [
            "xdotool",
            "type",
            "--delay",
            "8",
            text_value,
        ]
    )


def capture_window(window: WindowGeometry, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    run(["import", "-window", str(window.window_id), str(output_path)])


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


def latest_task_for_prompt(db_path: Path, prompt: str) -> dict[str, Any] | None:
    task = load_checkpoint(db_path, "autopilot.local_task.v1")
    if not task:
        return None
    if (task.get("intent") or "").strip() != prompt.strip():
        return None
    return task


def has_local_task_checkpoint(db_path: Path) -> bool:
    if not db_path.exists():
        return False

    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT 1
            FROM checkpoint_blobs
            WHERE checkpoint_name = ?
            LIMIT 1
            """,
            ("autopilot.local_task.v1",),
        ).fetchone()
    finally:
        conn.close()

    return row is not None


def latest_agent_message(task: dict[str, Any] | None) -> str | None:
    if not task:
        return None
    for item in reversed(task.get("history", [])):
        if item.get("role") == "agent":
            text = (item.get("text") or "").strip()
            if text:
                return text
    return None


def latest_execution_contracts(task: dict[str, Any] | None, limit: int = 8) -> list[str]:
    if not task:
        return []
    hits: list[str] = []
    for item in reversed(task.get("history", [])):
        if item.get("role") != "system":
            continue
        text = (item.get("text") or "").strip()
        if "ExecutionContract:" not in text:
            continue
        hits.append(text)
        if len(hits) >= limit:
            break
    return list(reversed(hits))


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


def wait_for_prompt_start(
    db_path: Path,
    prompt: str,
    *,
    timeout_secs: float,
) -> dict[str, Any] | None:
    deadline = time.time() + timeout_secs

    while time.time() < deadline:
        task = load_checkpoint(db_path, "autopilot.local_task.v1")
        if task:
            intent = (task.get("intent") or "").strip()
            if intent == prompt.strip():
                return task
        time.sleep(POLL_INTERVAL_SECS)

    return None


def active_operator_run(task: dict[str, Any] | None) -> dict[str, Any]:
    if not task:
        return {}
    studio_session = task.get("studio_session") or {}
    active_run = studio_session.get("activeOperatorRun") or {}
    return active_run if isinstance(active_run, dict) else {}


def operator_run_is_terminal(task: dict[str, Any] | None) -> bool:
    status = (active_operator_run(task).get("status") or "").strip().lower()
    return status in {"complete", "blocked", "failed"}


def artifact_session_ready(task: dict[str, Any] | None) -> bool:
    if not task:
        return False
    studio_session = task.get("studio_session") or {}
    studio_status = (studio_session.get("status") or "").strip().lower()
    artifact_manifest = studio_session.get("artifactManifest") or {}
    verification_status = (
        ((artifact_manifest.get("verification") or {}).get("lifecycleState") or "")
        .strip()
        .lower()
    )
    return "ready" in {studio_status, verification_status}


def wait_for_prompt_result(
    db_path: Path,
    prompt: str,
    *,
    timeout_secs: float,
) -> dict[str, Any]:
    deadline = time.time() + timeout_secs
    last_task: dict[str, Any] | None = None

    while time.time() < deadline:
        task = load_checkpoint(db_path, "autopilot.local_task.v1")
        if task:
            intent = (task.get("intent") or "").strip()
            if intent == prompt.strip():
                last_task = task
                phase = (task.get("phase") or "").strip().lower()
                current_step = (task.get("current_step") or "").strip().lower()
                if phase in {"complete", "failed"}:
                    if phase == "complete" or "ready for input" in current_step:
                        return task
                    return task
                if operator_run_is_terminal(task) or artifact_session_ready(task):
                    return task
        time.sleep(POLL_INTERVAL_SECS)

    if last_task is not None:
        return last_task
    raise TimeoutError(
        f"Timed out after {timeout_secs:.0f}s waiting for prompt result: {prompt}"
    )


def submit_prompt(
    window: WindowGeometry,
    db_path: Path,
    prompt: str,
    *,
    fresh_outcome: bool,
) -> None:
    focus_window(window)
    if fresh_outcome and has_local_task_checkpoint(db_path):
        key(window, "ctrl+n")
        time.sleep(1.6)
        focus_window(window)
        time.sleep(0.3)
    click(window, *composer_point(window))
    key(window, "ctrl+a")
    key(window, "BackSpace")
    type_text(window, prompt)
    time.sleep(0.2)
    key(window, "Return")


def result_bundle(task: dict[str, Any] | None) -> dict[str, Any]:
    outcome = task.get("studio_outcome") if task else None
    session = task.get("studio_session") if task else None
    return {
        "task_id": task.get("id") if task else None,
        "intent": task.get("intent") if task else None,
        "phase": task.get("phase") if task else None,
        "current_step": task.get("current_step") if task else None,
        "progress": task.get("progress") if task else None,
        "total_steps": task.get("total_steps") if task else None,
        "latest_agent_message": latest_agent_message(task),
        "studio_outcome": outcome,
        "studio_session_summary": {
            "session_id": session.get("sessionId") if session else None,
            "lifecycle_state": session.get("lifecycleState") if session else None,
            "verified_reply": session.get("verifiedReply") if session else None,
        },
        "route_receipt_summary": latest_route_receipt_summary(task),
        "execution_contracts": latest_execution_contracts(task),
    }


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
        default=120.0,
        help="How long to wait for each prompt to settle.",
    )
    parser.add_argument(
        "--start-timeout-secs",
        type=float,
        default=10.0,
        help="How long to wait for a submitted prompt to bind into a local task before retrying submit delivery.",
    )
    parser.add_argument(
        "--submit-attempts",
        type=int,
        default=3,
        help="How many times to retry delivering a prompt if the native shell drops the initial submit.",
    )
    parser.add_argument(
        "--window-name",
        default=WINDOW_SEARCH_PATTERN,
        help=f"Window title pattern to target. Default: {WINDOW_SEARCH_PATTERN!r}",
    )
    parser.add_argument(
        "--reuse-session",
        action="store_true",
        help="Reuse the currently active Studio outcome instead of resetting to a fresh outcome with Ctrl+N before each prompt.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    prompts = load_prompts(args)
    db_path = Path(args.db_path).expanduser()
    output_root = Path(args.output_root).expanduser() / now_stamp()
    output_root.mkdir(parents=True, exist_ok=True)

    window = find_window(args.window_name)
    manifest: list[dict[str, Any]] = []

    for index, prompt in enumerate(prompts, start=1):
        slug = safe_slug(prompt)
        prompt_dir = output_root / f"{index:02d}-{slug}"
        prompt_dir.mkdir(parents=True, exist_ok=True)

        started_task: dict[str, Any] | None = None
        for attempt in range(1, max(1, args.submit_attempts) + 1):
            submit_prompt(
                window,
                db_path,
                prompt,
                fresh_outcome=not args.reuse_session,
            )
            if attempt == 1:
                print(f"[{index}/{len(prompts)}] submitted :: {prompt}", flush=True)
            else:
                print(
                    f"[{index}/{len(prompts)}] retry {attempt}/{args.submit_attempts} :: {prompt}",
                    flush=True,
                )
            started_task = wait_for_prompt_start(
                db_path,
                prompt,
                timeout_secs=args.start_timeout_secs,
            )
            if started_task is not None:
                break

        if started_task is None:
            task = latest_task_for_prompt(db_path, prompt)
            probe_error = (
                f"Timed out after {args.start_timeout_secs:.0f}s waiting for prompt start: {prompt}"
            )
        else:
            task = started_task
            probe_error = None

        if probe_error is None:
            try:
                task = wait_for_prompt_result(
                    db_path,
                    prompt,
                    timeout_secs=args.timeout_secs,
                )
            except Exception as error:
                probe_error = str(error)
                task = latest_task_for_prompt(db_path, prompt) or task

        time.sleep(POST_SETTLE_CAPTURE_DELAY_SECS)
        screenshot_path = prompt_dir / "final.png"
        capture_window(window, screenshot_path)

        bundle = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "prompt": prompt,
            "screenshot": str(screenshot_path),
            **result_bundle(task),
            "probe_error": probe_error,
        }
        (prompt_dir / "result.json").write_text(
            json.dumps(bundle, indent=2),
            encoding="utf-8",
        )
        manifest.append(bundle)

        phase = (bundle.get("phase") or "").lower()
        status_line = f"[{index}/{len(prompts)}] {phase or 'error'} :: {prompt}"
        print(status_line, flush=True)
        answer = bundle.get("latest_agent_message")
        if answer:
            print(f"  answer: {answer[:160]}", flush=True)

    manifest_path = output_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nRetained desktop probe results: {manifest_path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
