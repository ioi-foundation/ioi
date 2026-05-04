#!/usr/bin/env python3
"""Drive the local Autopilot desktop app with real prompts and retain receipts.

This probe is intentionally lightweight:
- it reuses a running `npm run dev:desktop` session
- it submits prompts through the real ChatRuntime window with xdotool/wmctrl
- it polls the local desktop profile sqlite store for the latest task state
- it saves a screenshot plus a JSON receipt bundle per prompt

The script is designed for parity validation, not pixel-perfect UI automation.
"""

from __future__ import annotations

import argparse
import hashlib
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

from desktop_capture import capture_window_with_fallback


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PROFILE = "desktop-localgpu"
DEFAULT_DB_PATH = (
    Path.home()
    / ".local/share/ai.ioi.autopilot/profiles"
    / DEFAULT_PROFILE
    / "chat-memory.db"
)
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "docs/evidence/route-hierarchy/live-desktop-parity"

WINDOW_SEARCH_PATTERN = "Autopilot Chat"
BROWSER_CAPTURE_URL = "http://127.0.0.1:1433/"
NEW_OUTCOME_X = 115
NEW_OUTCOME_Y = 137
COMPOSER_X_RATIO = 0.38
COMPOSER_MIN_X = 240
COMPOSER_MIN_Y = 180
COMPOSER_BOTTOM_OFFSET = 75
ZERO_STATE_COMPOSER_BOTTOM_OFFSET = 225
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


def active_window_diagnostics() -> dict[str, Any]:
    try:
        active = run(["xdotool", "getactivewindow"]).stdout.strip()
        title = (
            run(["xdotool", "getwindowname", active]).stdout.strip()
            if active
            else ""
        )
        return {"active_window_id": active, "active_window_title": title}
    except Exception as error:
        return {"error": str(error)}


def click(window: WindowGeometry, rel_x: int, rel_y: int) -> None:
    abs_x, abs_y = window.abs_point(rel_x, rel_y)
    run(["xdotool", "mousemove", str(abs_x), str(abs_y)])
    run(["xdotool", "click", "1"])
    time.sleep(0.2)


def composer_point(window: WindowGeometry, *, zero_state: bool = False) -> tuple[int, int]:
    rel_x = int(window.width * COMPOSER_X_RATIO)
    bottom_offset = ZERO_STATE_COMPOSER_BOTTOM_OFFSET if zero_state else COMPOSER_BOTTOM_OFFSET
    rel_y = window.height - bottom_offset
    rel_x = max(COMPOSER_MIN_X, min(window.width - COMPOSER_SIDE_MARGIN, rel_x))
    rel_y = max(COMPOSER_MIN_Y, min(window.height - bottom_offset, rel_y))
    return rel_x, rel_y


def key(window: WindowGeometry, key_spec: str) -> None:
    run(["xdotool", "key", "--clearmodifiers", key_spec])


def type_text(window: WindowGeometry, text_value: str) -> None:
    run(
        [
            "xdotool",
            "type",
            "--clearmodifiers",
            "--delay",
            "8",
            text_value,
        ]
    )


def load_checkpoint(db_path: Path, checkpoint_name: str) -> dict[str, Any] | None:
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


def normalize_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


def text_matches_prompt(text: str | None, prompt: str) -> bool:
    normalized_text = normalize_text(text or "")
    normalized_prompt = normalize_text(prompt)
    if not normalized_text or not normalized_prompt:
        return False
    return (
        normalized_text == normalized_prompt
        or normalized_prompt in normalized_text
        or normalized_text in normalized_prompt
    )


def profile_root_for_db_path(db_path: Path) -> Path:
    if db_path.name == "desktop-memory.db" and db_path.parent.name == "kernel":
        return db_path.parent.parent
    return db_path.parent


def candidate_db_paths(db_path: Path) -> list[Path]:
    profile_root = profile_root_for_db_path(db_path)
    candidates = [
        db_path,
        profile_root / "chat-memory.db",
        profile_root / "chat-runtime-memory.db",
        profile_root / "kernel" / "desktop-memory.db",
    ]
    deduped: list[Path] = []
    for path in candidates:
        if path not in deduped:
            deduped.append(path)
    return deduped


def checkpoint_names(db_path: Path) -> list[str]:
    if not db_path.exists() or db_path.stat().st_size == 0:
        return []

    conn = sqlite3.connect(db_path)
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
            return []
        rows = conn.execute(
            """
            SELECT checkpoint_name
            FROM checkpoint_blobs
            ORDER BY updated_at_ms DESC
            LIMIT 32
            """
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()

    return [str(row[0]) for row in rows]


def load_checkpoint_from_candidates(
    db_paths: list[Path],
    checkpoint_name: str,
) -> Any | None:
    for path in db_paths:
        checkpoint = load_checkpoint(path, checkpoint_name)
        if checkpoint:
            return checkpoint
    return None


def local_sessions(db_paths: list[Path]) -> list[dict[str, Any]]:
    payload = load_checkpoint_from_candidates(db_paths, "autopilot.local_sessions.v1")
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        sessions = payload.get("sessions")
        if isinstance(sessions, list):
            return [item for item in sessions if isinstance(item, dict)]
    return []


def db_diagnostics(db_paths: list[Path]) -> dict[str, Any]:
    selected: str | None = None
    candidates: list[dict[str, Any]] = []
    session_payload = local_sessions(db_paths)
    for path in db_paths:
        exists = path.exists()
        names = checkpoint_names(path)
        has_task = "autopilot.local_task.v1" in names
        if selected is None and has_task:
            selected = str(path)
        candidates.append({
            "path": str(path),
            "exists": exists,
            "size": path.stat().st_size if exists else 0,
            "checkpoint_names": names,
            "has_local_task": has_task,
        })
    return {
        "selected_db_path": selected or (str(db_paths[0]) if db_paths else None),
        "candidates": candidates,
        "local_session_count": len(session_payload),
        "latest_sessions": [
            {
                "session_id": str(session.get("session_id") or ""),
                "title": session.get("title"),
                "timestamp": session.get("timestamp"),
                "phase": session.get("phase"),
                "current_step": session.get("current_step"),
            }
            for session in sorted(
                session_payload,
                key=lambda item: int(item.get("timestamp") or 0),
                reverse=True,
            )[:5]
            if isinstance(session, dict)
        ],
    }


def latest_task(db_paths: list[Path]) -> dict[str, Any] | None:
    return load_checkpoint_from_candidates(db_paths, "autopilot.local_task.v1")


def compact_task_summary(task: dict[str, Any] | None) -> dict[str, Any] | None:
    if not task:
        return None
    return {
        "id": task.get("id"),
        "session_id": task.get("session_id") or task.get("sessionId"),
        "intent": task.get("intent"),
        "phase": task.get("phase"),
        "current_step": task.get("current_step"),
        "history_count": len(task.get("history") or []),
        "probe_source": task.get("_probe_source") or "local_task",
    }


def observation_summary(db_paths: list[Path]) -> dict[str, Any]:
    sessions = sorted(
        local_sessions(db_paths),
        key=lambda item: int(item.get("timestamp") or 0),
        reverse=True,
    )
    return {
        "latest_task": compact_task_summary(latest_task(db_paths)),
        "latest_sessions": [
            {
                "session_id": session.get("session_id"),
                "title": session.get("title"),
                "timestamp": session.get("timestamp"),
                "phase": session.get("phase"),
                "current_step": session.get("current_step"),
            }
            for session in sessions[:3]
        ],
    }


def task_matches_prompt(task: dict[str, Any], prompt: str) -> bool:
    return text_matches_prompt(task.get("intent"), prompt)


def thread_key_for_session_id(session_id: str) -> bytes:
    return hashlib.sha256(f"autopilot::thread::{session_id}".encode("utf-8")).digest()


def transcript_messages_for_session(
    db_paths: list[Path],
    session_id: str,
) -> list[dict[str, Any]]:
    if not session_id:
        return []
    thread_key = thread_key_for_session_id(session_id)
    for path in db_paths:
        if not path.exists() or path.stat().st_size == 0:
            continue
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            table_row = conn.execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table' AND name = 'checkpoint_transcript_messages'
                LIMIT 1
                """
            ).fetchone()
            if table_row is None:
                continue
            rows = conn.execute(
                """
                SELECT role, timestamp_ms, raw_content, model_content, store_content, raw_reference
                FROM checkpoint_transcript_messages
                WHERE thread_id = ?
                ORDER BY id ASC
                """,
                (thread_key,),
            ).fetchall()
        except sqlite3.OperationalError:
            continue
        finally:
            conn.close()

        return [
            {
                "role": str(row["role"] or ""),
                "timestamp_ms": int(row["timestamp_ms"] or 0),
                "raw_content": row["raw_content"],
                "model_content": row["model_content"],
                "store_content": row["store_content"],
                "raw_reference": row["raw_reference"],
            }
            for row in rows
        ]
    return []


def history_from_transcript_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    history: list[dict[str, Any]] = []
    for row in rows:
        role = str(row.get("role") or "").strip()
        if role == "assistant":
            role = "agent"
        text = (
            row.get("store_content")
            or row.get("model_content")
            or row.get("raw_content")
            or ""
        )
        text = str(text).strip()
        if not role or not text:
            continue
        history.append({
            "role": role,
            "text": text,
            "timestamp": int(row.get("timestamp_ms") or 0),
        })
    return history


def transcript_contains_prompt(rows: list[dict[str, Any]], prompt: str) -> bool:
    for row in rows:
        if str(row.get("role") or "") != "user":
            continue
        if text_matches_prompt(
            str(row.get("store_content") or row.get("raw_content") or ""),
            prompt,
        ):
            return True
    return False


def latest_user_from_history(history: list[dict[str, Any]]) -> str | None:
    for item in reversed(history):
        if item.get("role") != "user":
            continue
        text = str(item.get("text") or "").strip()
        if text:
            return text
    return None


def task_from_session_summary(
    db_paths: list[Path],
    session: dict[str, Any],
) -> dict[str, Any]:
    session_id = str(session.get("session_id") or "")
    rows = transcript_messages_for_session(db_paths, session_id)
    history = history_from_transcript_rows(rows)
    phase = session.get("phase")
    return {
        "id": session_id,
        "session_id": session_id,
        "intent": latest_user_from_history(history) or session.get("title") or "",
        "phase": phase,
        "current_step": session.get("current_step"),
        "progress": None,
        "total_steps": None,
        "history": history,
        "events": [],
        "artifacts": [],
        "chat_session": {
            "sessionId": session_id,
            "status": phase,
            "lifecycleState": phase,
        },
        "chat_outcome": None,
        "_probe_source": "local_session_transcript",
    }


def session_index_signature(db_paths: list[Path]) -> dict[str, tuple[int, str, str, str]]:
    signature: dict[str, tuple[int, str, str, str]] = {}
    for session in local_sessions(db_paths):
        session_id = str(session.get("session_id") or "")
        if not session_id:
            continue
        signature[session_id] = (
            int(session.get("timestamp") or 0),
            str(session.get("title") or ""),
            str(session.get("phase") or ""),
            str(session.get("current_step") or ""),
        )
    return signature


def session_changed_since(
    session: dict[str, Any],
    baseline_sessions: dict[str, tuple[int, str, str, str]] | None,
) -> bool:
    if baseline_sessions is None:
        return True
    session_id = str(session.get("session_id") or "")
    current = (
        int(session.get("timestamp") or 0),
        str(session.get("title") or ""),
        str(session.get("phase") or ""),
        str(session.get("current_step") or ""),
    )
    return baseline_sessions.get(session_id) != current


def latest_session_task_for_prompt(
    db_paths: list[Path],
    prompt: str,
    *,
    baseline_sessions: dict[str, tuple[int, str, str, str]] | None = None,
) -> dict[str, Any] | None:
    sessions = sorted(
        local_sessions(db_paths),
        key=lambda item: int(item.get("timestamp") or 0),
        reverse=True,
    )
    for session in sessions:
        if not session_changed_since(session, baseline_sessions):
            continue
        session_id = str(session.get("session_id") or "")
        rows = transcript_messages_for_session(db_paths, session_id)
        if transcript_contains_prompt(rows, prompt) or text_matches_prompt(
            session.get("title"),
            prompt,
        ):
            return task_from_session_summary(db_paths, session)
    return None


def task_history_contains_prompt(task: dict[str, Any] | None, prompt: str) -> bool:
    if not task:
        return False
    if not normalize_text(prompt):
        return False
    for item in reversed(task.get("history", [])):
        if item.get("role") != "user":
            continue
        if text_matches_prompt(item.get("text"), prompt):
            return True
    return False


def prompt_has_agent_reply(task: dict[str, Any] | None, prompt: str) -> bool:
    if not task:
        return False
    if not normalize_text(prompt):
        return False
    seen_prompt = False
    for item in task.get("history", []):
        role = item.get("role")
        text = (item.get("text") or "").strip()
        if role == "user" and text_matches_prompt(text, prompt):
            seen_prompt = True
            continue
        if seen_prompt and role == "agent" and text:
            return True
    return False


def latest_task_for_prompt(
    db_paths: list[Path],
    prompt: str,
    *,
    baseline_sessions: dict[str, tuple[int, str, str, str]] | None = None,
) -> dict[str, Any] | None:
    task = latest_task(db_paths)
    if task and task_matches_prompt(task, prompt):
        return task
    return latest_session_task_for_prompt(
        db_paths,
        prompt,
        baseline_sessions=baseline_sessions,
    )


def has_local_task_checkpoint(db_paths: list[Path]) -> bool:
    return load_checkpoint_from_candidates(db_paths, "autopilot.local_task.v1") is not None


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
        ((task.get("chat_session") or {}).get("artifactManifest")) or {}
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


def is_user_visible_artifact_record(record: dict[str, Any]) -> bool:
    artifact_type = str(
        record.get("artifact_type") or record.get("artifactType") or ""
    ).upper()
    if artifact_type == "RUN_BUNDLE":
        return False

    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    path = str(record.get("path") or metadata.get("path") or "")
    title = str(record.get("title") or "")
    haystack = f"{path}\n{title}".lower()
    if "conversation-artifacts/" in haystack and "/planning/" in haystack:
        return False
    return True


def user_visible_task_artifacts(task: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not task:
        return []
    return [
        artifact
        for artifact in task.get("artifacts") or []
        if isinstance(artifact, dict) and is_user_visible_artifact_record(artifact)
    ]


def wait_for_prompt_start(
    db_paths: list[Path],
    prompt: str,
    *,
    timeout_secs: float,
    baseline_task: dict[str, Any] | None = None,
    baseline_sessions: dict[str, tuple[int, str, str, str]] | None = None,
    reuse_session: bool = False,
) -> dict[str, Any] | None:
    deadline = time.time() + timeout_secs

    while time.time() < deadline:
        task = latest_task_for_prompt(
            db_paths,
            prompt,
            baseline_sessions=baseline_sessions,
        )
        if task:
            return task
        if reuse_session:
            task = latest_task(db_paths)
            if task_history_contains_prompt(task, prompt) or operator_run_changed(
                task, baseline_task
            ):
                return task
        time.sleep(POLL_INTERVAL_SECS)

    return None


def latest_task_for_wait(
    db_paths: list[Path],
    prompt: str,
    *,
    baseline_task: dict[str, Any] | None = None,
    baseline_sessions: dict[str, tuple[int, str, str, str]] | None = None,
    reuse_session: bool = False,
) -> dict[str, Any] | None:
    task = latest_task_for_prompt(
        db_paths,
        prompt,
        baseline_sessions=baseline_sessions,
    )
    if task:
        return task
    if reuse_session:
        task = latest_task(db_paths)
        if task_history_contains_prompt(task, prompt) or operator_run_changed(
            task, baseline_task
        ):
            return task
    return None


def active_operator_run(task: dict[str, Any] | None) -> dict[str, Any]:
    if not task:
        return {}
    chat_session = task.get("chat_session") or {}
    active_run = chat_session.get("activeOperatorRun") or {}
    return active_run if isinstance(active_run, dict) else {}


def active_operator_run_signature(
    task: dict[str, Any] | None,
) -> tuple[str, int, int, str]:
    run = active_operator_run(task)
    return (
        str(run.get("runId") or ""),
        int(run.get("startedAtMs") or 0),
        int(run.get("finishedAtMs") or 0),
        str(run.get("originPromptEventId") or ""),
    )


def operator_run_changed(
    task: dict[str, Any] | None,
    baseline_task: dict[str, Any] | None,
) -> bool:
    current = active_operator_run_signature(task)
    baseline = active_operator_run_signature(baseline_task)
    return bool(current[0]) and current != baseline


def operator_run_is_terminal(task: dict[str, Any] | None) -> bool:
    status = (active_operator_run(task).get("status") or "").strip().lower()
    return status in {"complete", "blocked", "failed"}


def operator_run_is_active(task: dict[str, Any] | None) -> bool:
    run = active_operator_run(task)
    if not run.get("runId"):
        return False
    status = (run.get("status") or "").strip().lower()
    return status not in {"complete", "blocked", "failed"}


def artifact_session_ready(task: dict[str, Any] | None) -> bool:
    if not task:
        return False
    if operator_run_is_active(task):
        return False
    chat_session = task.get("chat_session") or {}
    chat_status = (chat_session.get("status") or "").strip().lower()
    artifact_manifest = chat_session.get("artifactManifest") or {}
    verification_status = (
        ((artifact_manifest.get("verification") or {}).get("lifecycleState") or "")
        .strip()
        .lower()
    )
    return "ready" in {chat_status, verification_status}


def conversation_reply_ready(task: dict[str, Any] | None) -> bool:
    if not task:
        return False
    if latest_agent_message(task):
        return True
    phase = (task.get("phase") or "").strip().lower()
    current_step = (task.get("current_step") or "").strip().lower()
    return phase == "complete" or "ready for input" in current_step


def clarification_gate_ready(task: dict[str, Any] | None) -> bool:
    if not task:
        return False
    phase = (task.get("phase") or "").strip().lower()
    return phase == "gate" and bool(
        task.get("clarification_request") or task.get("clarificationRequest")
    )


def is_conversation_route(task: dict[str, Any] | None) -> bool:
    if not task:
        return False
    chat_outcome = task.get("chat_outcome") or {}
    chat_session = task.get("chat_session") or {}
    materialization = chat_session.get("materialization") or {}
    return (
        chat_outcome.get("outcomeKind") == "conversation"
        or materialization.get("requestKind") == "conversation"
    )


def wait_for_prompt_result(
    db_paths: list[Path],
    prompt: str,
    *,
    timeout_secs: float,
    baseline_task: dict[str, Any] | None = None,
    baseline_sessions: dict[str, tuple[int, str, str, str]] | None = None,
    reuse_session: bool = False,
) -> dict[str, Any]:
    deadline = time.time() + timeout_secs
    last_task: dict[str, Any] | None = None

    while time.time() < deadline:
        task = latest_task_for_wait(
            db_paths,
            prompt,
            baseline_task=baseline_task,
            baseline_sessions=baseline_sessions,
            reuse_session=reuse_session,
        )
        if task:
            last_task = task
            if operator_run_is_active(task):
                time.sleep(POLL_INTERVAL_SECS)
                continue
            phase = (task.get("phase") or "").strip().lower()
            current_step = (task.get("current_step") or "").strip().lower()
            if reuse_session and task_history_contains_prompt(
                task, prompt
            ) and not prompt_has_agent_reply(task, prompt):
                time.sleep(POLL_INTERVAL_SECS)
                continue
            if phase in {"complete", "failed"}:
                if phase == "complete" or "ready for input" in current_step:
                    return task
                return task
            if clarification_gate_ready(task):
                return task
            if operator_run_is_terminal(task):
                return task
            if artifact_session_ready(task) and (
                not is_conversation_route(task) or conversation_reply_ready(task)
            ):
                return task
        time.sleep(POLL_INTERVAL_SECS)

    if last_task is not None:
        return last_task
    raise TimeoutError(
        f"Timed out after {timeout_secs:.0f}s waiting for prompt result: {prompt}"
    )


def submit_prompt(
    window: WindowGeometry,
    db_paths: list[Path],
    prompt: str,
    *,
    fresh_outcome: bool,
    prefer_retained_composer: bool = False,
) -> None:
    focus_window(window)
    has_existing_task = has_local_task_checkpoint(db_paths)
    has_existing_context = has_existing_task or bool(local_sessions(db_paths))
    if fresh_outcome and has_existing_context:
        click(window, NEW_OUTCOME_X, NEW_OUTCOME_Y)
        time.sleep(1.2)
        focus_window(window)
        time.sleep(0.3)
    zero_state = fresh_outcome and not (has_existing_context and prefer_retained_composer)
    click(window, *composer_point(window, zero_state=zero_state))
    key(window, "ctrl+a")
    key(window, "BackSpace")
    type_text(window, prompt)
    time.sleep(0.2)
    key(window, "Return")


def artifact_records_summary(db_paths: list[Path], limit: int = 8) -> list[dict[str, Any]]:
    for path in db_paths:
        if not path.exists() or path.stat().st_size == 0:
            continue
        conn = sqlite3.connect(path)
        try:
            table_row = conn.execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table' AND name = 'artifact_records'
                LIMIT 1
                """
            ).fetchone()
            if table_row is None:
                continue
            rows = conn.execute(
                """
                SELECT artifact_id, payload_json, created_at_ms, updated_at_ms
                FROM artifact_records
                ORDER BY updated_at_ms DESC, created_at_ms DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        except sqlite3.OperationalError:
            continue
        finally:
            conn.close()

        summaries: list[dict[str, Any]] = []
        for artifact_id, payload_json, created_at_ms, updated_at_ms in rows:
            try:
                payload = json.loads(payload_json)
            except (TypeError, json.JSONDecodeError):
                payload = {}
            metadata = payload.get("metadata") if isinstance(payload, dict) else {}
            summary = {
                "artifact_id": artifact_id,
                "title": payload.get("title") if isinstance(payload, dict) else None,
                "artifact_type": payload.get("artifact_type") if isinstance(payload, dict) else None,
                "path": metadata.get("path") if isinstance(metadata, dict) else None,
                "version": payload.get("version") if isinstance(payload, dict) else None,
                "created_at_ms": created_at_ms,
                "updated_at_ms": updated_at_ms,
            }
            if is_user_visible_artifact_record(summary):
                summaries.append(summary)
        return summaries
    return []


def runtime_facts_summary(task: dict[str, Any] | None) -> dict[str, Any]:
    if not task:
        return {
            "phase": None,
            "current_step": None,
            "route": None,
            "policy": "unknown",
            "approval": "unknown",
            "evidence_tier": "Projection",
            "settlement_state": "projection_only",
        }

    route = latest_route_receipt_summary(task) or {}
    active_run = active_operator_run(task)
    chat_session = task.get("chat_session") or {}
    materialization = chat_session.get("materialization") or {}
    execution_envelope = materialization.get("executionEnvelope") or {}
    settlement_refs: list[Any] = []
    for key_name in (
        "settlementRefs",
        "settlement_refs",
        "settlementReceipts",
        "settlement_receipts",
    ):
        value = execution_envelope.get(key_name)
        if isinstance(value, list):
            settlement_refs.extend(value)

    approval = "clear"
    if task.get("pending_request_hash") or task.get("gate_info"):
        approval = "pending"
    elif active_run.get("status"):
        approval = str(active_run.get("status"))

    visible_artifacts = user_visible_task_artifacts(task)
    evidence_tier = "Settlement receipt" if settlement_refs else "Runtime event receipt"
    if not task.get("events") and not visible_artifacts:
        evidence_tier = "Projection"

    return {
        "phase": task.get("phase"),
        "current_step": task.get("current_step"),
        "progress": task.get("progress"),
        "total_steps": task.get("total_steps"),
        "route": route.get("selected_route") or route.get("title"),
        "route_family": route.get("route_family"),
        "policy": "attached" if task.get("policy") else "not_attached",
        "approval": approval,
        "evidence_tier": evidence_tier,
        "settlement_state": "settled" if settlement_refs else "projection_only",
        "event_count": len(task.get("events") or []),
        "artifact_count": len(visible_artifacts),
        "active_operator_run_status": active_run.get("status"),
    }


def result_bundle(
    task: dict[str, Any] | None,
    *,
    db_info: dict[str, Any] | None = None,
    artifact_records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    outcome = task.get("chat_outcome") if task else None
    session = task.get("chat_session") if task else None
    return {
        "task_id": task.get("id") if task else None,
        "probe_source": task.get("_probe_source") if task else None,
        "intent": task.get("intent") if task else None,
        "phase": task.get("phase") if task else None,
        "current_step": task.get("current_step") if task else None,
        "progress": task.get("progress") if task else None,
        "total_steps": task.get("total_steps") if task else None,
        "latest_agent_message": latest_agent_message(task),
        "chat_outcome": outcome,
        "chat_session_summary": {
            "session_id": session.get("sessionId") if session else None,
            "lifecycle_state": session.get("lifecycleState") if session else None,
            "verified_reply": session.get("verifiedReply") if session else None,
        },
        "route_receipt_summary": latest_route_receipt_summary(task),
        "runtime_facts_summary": runtime_facts_summary(task),
        "artifact_records_summary": artifact_records or [],
        "db_diagnostics": db_info,
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
        help="Prompt to submit through the live ChatRuntime app. Repeat for multiple prompts.",
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
        "--browser-capture-url",
        default=os.environ.get("AUTOPILOT_DESKTOP_CAPTURE_URL", BROWSER_CAPTURE_URL),
        help=(
            "Browser URL to use when Linux/X11 window capture comes back blank. "
            f"Default: {BROWSER_CAPTURE_URL}"
        ),
    )
    parser.add_argument(
        "--reuse-session",
        action="store_true",
        help="Reuse the currently active ChatRuntime outcome instead of resetting to a fresh outcome with Ctrl+N before each prompt.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    prompts = load_prompts(args)
    db_paths = candidate_db_paths(Path(args.db_path).expanduser())
    initial_db_info = db_diagnostics(db_paths)
    print(
        "DB candidates: "
        + ", ".join(
            f"{candidate['path']} ({'task' if candidate['has_local_task'] else 'no-task'})"
            for candidate in initial_db_info["candidates"]
        ),
        flush=True,
    )
    output_root = Path(args.output_root).expanduser() / now_stamp()
    output_root.mkdir(parents=True, exist_ok=True)

    window = find_window(args.window_name)
    manifest: list[dict[str, Any]] = []

    for index, prompt in enumerate(prompts, start=1):
        slug = safe_slug(prompt)
        prompt_dir = output_root / f"{index:02d}-{slug}"
        prompt_dir.mkdir(parents=True, exist_ok=True)

        baseline_task = latest_task(db_paths) if args.reuse_session else None
        baseline_sessions = session_index_signature(db_paths)
        started_task: dict[str, Any] | None = None
        submission_attempts: list[dict[str, Any]] = []
        for attempt in range(1, max(1, args.submit_attempts) + 1):
            attempt_record: dict[str, Any] = {
                "attempt": attempt,
                "before": observation_summary(db_paths),
            }
            submit_prompt(
                window,
                db_paths,
                prompt,
                fresh_outcome=not args.reuse_session,
                prefer_retained_composer=attempt > 1,
            )
            attempt_record["window_after_submit"] = active_window_diagnostics()
            if attempt == 1:
                print(f"[{index}/{len(prompts)}] submitted :: {prompt}", flush=True)
            else:
                print(
                    f"[{index}/{len(prompts)}] retry {attempt}/{args.submit_attempts} :: {prompt}",
                    flush=True,
                )
            started_task = wait_for_prompt_start(
                db_paths,
                prompt,
                timeout_secs=args.start_timeout_secs,
                baseline_task=baseline_task,
                baseline_sessions=baseline_sessions,
                reuse_session=args.reuse_session,
            )
            attempt_record["after_wait"] = observation_summary(db_paths)
            attempt_record["started_task"] = compact_task_summary(started_task)
            submission_attempts.append(attempt_record)
            if started_task is not None:
                break

        if started_task is None:
            task = latest_task_for_wait(
                db_paths,
                prompt,
                baseline_task=baseline_task,
                baseline_sessions=baseline_sessions,
                reuse_session=args.reuse_session,
            )
            probe_error = (
                f"Timed out after {args.start_timeout_secs:.0f}s waiting for prompt start: {prompt}"
            )
        else:
            task = started_task
            probe_error = None

        if probe_error is None:
            try:
                task = wait_for_prompt_result(
                    db_paths,
                    prompt,
                    timeout_secs=args.timeout_secs,
                    baseline_task=baseline_task,
                    baseline_sessions=baseline_sessions,
                    reuse_session=args.reuse_session,
                )
            except Exception as error:
                probe_error = str(error)
                task = (
                    latest_task_for_wait(
                        db_paths,
                        prompt,
                        baseline_task=baseline_task,
                        baseline_sessions=baseline_sessions,
                        reuse_session=args.reuse_session,
                    )
                    or task
                )

        time.sleep(POST_SETTLE_CAPTURE_DELAY_SECS)
        settled_task = latest_task_for_wait(
            db_paths,
            prompt,
            baseline_task=baseline_task,
            baseline_sessions=baseline_sessions,
            reuse_session=args.reuse_session,
        )
        if settled_task is not None:
            task = settled_task
        screenshot_path = prompt_dir / "final.png"
        capture_result = capture_window_with_fallback(
            window.window_id,
            screenshot_path,
            browser_url=args.browser_capture_url,
        )

        bundle = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "prompt": prompt,
            "screenshot": str(screenshot_path),
            "capture_mode": capture_result.mode,
            "capture_diagnostics": capture_result.diagnostics,
            "window_capture_error": capture_result.error,
            "screenshots": {"final": str(screenshot_path)},
            **result_bundle(
                task,
                db_info=db_diagnostics(db_paths),
                artifact_records=artifact_records_summary(db_paths),
            ),
            "probe_error": probe_error,
            "submission_attempts": submission_attempts,
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
