#!/usr/bin/env python3
"""Launch the real desktop app with a seeded ChatRuntime intent and retain evidence.

This probe avoids flaky synthetic typing by using the app's native
`AUTOPILOT_DEV_START_INTENT` launch path for ChatRuntime. Each prompt runs in an
isolated desktop session:
- reset the desktop-localgpu profile
- launch `npm run dev:desktop` with a seeded intent
- wait for the local task to settle
- capture a ChatRuntime screenshot and task JSON
- terminate the desktop process group
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
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


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PROFILE = "desktop-localgpu"
DEFAULT_DB_PATH = (
    Path.home()
    / ".local/share/ai.ioi.autopilot/profiles"
    / DEFAULT_PROFILE
    / "chat-memory.db"
)
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT / "docs/evidence/route-hierarchy/live-dev-start-intent"
)
WINDOW_SEARCH_PATTERN = "Autopilot Chat"
BROWSER_CAPTURE_URL = "http://127.0.0.1:1433/"
POLL_INTERVAL_SECS = 1.0
WINDOW_WAIT_TIMEOUT_SECS = 240.0
POST_SETTLE_CAPTURE_DELAY_SECS = 2.0
HEARTBEAT_LOG_RE = re.compile(r"^\[Autopilot\] Block #\d+ committed \(Tx: 0\)$")
CHAT_LAUNCH_STAGE_RE = re.compile(r"\[Autopilot\]\[ChatLaunch\] stage=([^\s]+)")
THOUGHTS_DRAWER_FALLBACK_POINT = (670, 82)


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


def window_geometry(window_id: int) -> dict[str, int]:
    result = run(
        ["xdotool", "getwindowgeometry", "--shell", str(window_id)],
        check=False,
    )
    geometry: dict[str, int] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if value.isdigit():
            geometry[key] = int(value)
    return geometry


def thoughts_drawer_points(window_id: int) -> list[tuple[int, int, str, dict[str, Any]]]:
    geometry = window_geometry(window_id)
    width = geometry.get("WIDTH")
    height = geometry.get("HEIGHT")
    if width:
        candidates = [
            (
                max(360, min(width - 420, int(width * 0.45))),
                max(120, min((height or 650) - 120, (height or 650) - 144)),
                "answer_card_thoughts_action_bottom",
            ),
            (
                max(360, min(width - 420, int(width * 0.49))),
                max(120, min((height or 650) - 120, (height or 650) - 144)),
                "answer_card_thoughts_action_bottom_neighbor",
            ),
            (
                max(320, min(width - 420, int(width * 0.34))),
                260,
                "assistant_process_trigger",
            ),
            (
                max(560, min(width - 72, width - 92)),
                320,
                "answer_card_thoughts_action",
            ),
            (
                max(560, min(width - 120, width - 140)),
                320,
                "answer_card_thoughts_neighbor",
            ),
            (
                max(560, min(width - 360, int(width * 0.645))),
                174,
                "assistant_process_row_scrolled",
            ),
            (
                max(560, min(width - 360, int(width * 0.645))),
                220,
                "assistant_process_row_high",
            ),
            (
                max(560, min(width - 360, int(width * 0.645))),
                350,
                "assistant_process_row_low",
            ),
        ]
        bounded: list[tuple[int, int, str, dict[str, Any]]] = []
        for rel_x, rel_y, target in candidates:
            bounded.append((
                rel_x,
                max(48, min((height or 650) - 48, rel_y)),
                target,
                {"geometry": geometry},
            ))
        return bounded
    rel_x, rel_y = THOUGHTS_DRAWER_FALLBACK_POINT
    return [(rel_x, rel_y, "thoughts_drawer_fallback", {"geometry": geometry, "fallback": True})]


def click_window_point(window_id: int, rel_x: int, rel_y: int) -> dict[str, Any]:
    diagnostics: dict[str, Any] = {
        "method": "coordinate_fallback",
        "window_id": window_id,
        "relative_point": {"x": rel_x, "y": rel_y},
    }
    activate = run(
        ["xdotool", "windowactivate", "--sync", str(window_id)],
        check=False,
    )
    diagnostics["activate_returncode"] = activate.returncode
    move = run(
        [
            "xdotool",
            "mousemove",
            "--window",
            str(window_id),
            str(rel_x),
            str(rel_y),
        ],
        check=False,
    )
    diagnostics["move_returncode"] = move.returncode
    click = run(["xdotool", "click", "1"], check=False)
    diagnostics["click_returncode"] = click.returncode
    return diagnostics


def capture_thoughts_drawer_with_fallback(
    window_id: int,
    screenshot_path: Path,
    *,
    browser_url: str,
    baseline_path: Path | None = None,
) -> tuple[dict[str, Any], str | None, dict[str, Any] | None]:
    attempts: list[dict[str, Any]] = []
    final_error: str | None = None
    final_diagnostics: dict[str, Any] | None = None
    for index, (rel_x, rel_y, target, point_diagnostics) in enumerate(
        thoughts_drawer_points(window_id),
        start=1,
    ):
        attempt_path = (
            screenshot_path
            if index == 1
            else screenshot_path.with_name(f"{screenshot_path.stem}_{index}{screenshot_path.suffix}")
        )
        click_diagnostics = click_window_point(window_id, rel_x, rel_y)
        click_diagnostics.update(point_diagnostics)
        click_diagnostics["target"] = target
        click_diagnostics["attempt"] = index
        time.sleep(1.0)
        capture_result = capture_window_with_fallback(
            window_id,
            attempt_path,
            browser_url=browser_url,
        )
        diff_pixels = image_difference_pixels(baseline_path, attempt_path)
        opened = diff_pixels is not None and diff_pixels > 90_000
        attempt = {
            "click": click_diagnostics,
            "capture_error": capture_result.error,
            "capture_diagnostics": capture_result.diagnostics,
            "screenshot": str(attempt_path),
            "baseline_diff_pixels": diff_pixels,
            "thoughts_drawer_opened": opened,
        }
        attempts.append(attempt)
        final_error = capture_result.error
        final_diagnostics = capture_result.diagnostics
        if opened:
            if attempt_path != screenshot_path:
                screenshot_path.write_bytes(attempt_path.read_bytes())
            return {
                "method": "coordinate_fallback",
                "selected_attempt": index,
                "target": target,
                "relative_point": {"x": rel_x, "y": rel_y},
                "attempts": attempts,
                "thoughts_drawer_opened": True,
            }, final_error, final_diagnostics

    return {
        "method": "coordinate_fallback",
        "attempts": attempts,
        "thoughts_drawer_opened": False,
    }, final_error, final_diagnostics


def image_difference_pixels(left_path: Path | None, right_path: Path | None) -> int | None:
    if left_path is None or right_path is None:
        return None
    if not left_path.exists() or not right_path.exists():
        return None
    compare = shutil.which("compare")
    if compare is None:
        return None
    completed = run(
        [compare, "-metric", "AE", str(left_path), str(right_path), "null:"],
        check=False,
    )
    metric = (completed.stderr or completed.stdout or "").strip().splitlines()[-1:]
    if not metric:
        return None
    try:
        return int(float(metric[0].strip()))
    except ValueError:
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


def profile_root_for_db_path(db_path: Path) -> Path:
    if db_path.name == "desktop-memory.db" and db_path.parent.name == "kernel":
        return db_path.parent.parent
    return db_path.parent


def candidate_db_paths(db_path: Path) -> list[Path]:
    profile_root = profile_root_for_db_path(db_path)
    candidates: list[Path] = [
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


def db_diagnostics(db_paths: list[Path]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    selected: str | None = None
    for path in db_paths:
        names = checkpoint_names(path)
        exists = path.exists()
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
    }


def load_task_checkpoint_from_candidates(db_paths: list[Path]) -> dict[str, Any] | None:
    for path in db_paths:
        task = load_task_checkpoint(path)
        if task:
            return task
    return None


def task_matches_prompt(task: dict[str, Any], prompt: str) -> bool:
    intent = (task.get("intent") or "").strip()
    normalized_prompt = prompt.strip()
    if intent == normalized_prompt:
        return True
    if not intent or not normalized_prompt:
        return False
    return normalized_prompt in intent


def latest_task_for_prompt(db_paths: list[Path], prompt: str) -> dict[str, Any] | None:
    task = load_task_checkpoint_from_candidates(db_paths)
    if not task:
        return None
    if not task_matches_prompt(task, prompt):
        return None
    return task


def wait_for_prompt_start(
    db_paths: list[Path],
    prompt: str,
    *,
    timeout_secs: float,
) -> dict[str, Any] | None:
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        task = latest_task_for_prompt(db_paths, prompt)
        if task:
            return task
        time.sleep(POLL_INTERVAL_SECS)
    return None


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
    for key in ("settlementRefs", "settlement_refs", "settlementReceipts", "settlement_receipts"):
        value = execution_envelope.get(key)
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


def task_has_interactive_wait_state(task: dict[str, Any]) -> bool:
    if task.get("clarification_request"):
        return True
    if task.get("credential_request"):
        return True
    if task.get("gate_info") or task.get("pending_request_hash"):
        return True

    current_step = (task.get("current_step") or "").strip().lower()
    return "waiting for clarification" in current_step or "waiting for approval" in current_step


def active_operator_run(task: dict[str, Any] | None) -> dict[str, Any]:
    if not task:
        return {}
    chat_session = task.get("chat_session") or {}
    active_run = chat_session.get("activeOperatorRun") or {}
    return active_run if isinstance(active_run, dict) else {}


def operator_run_is_terminal(task: dict[str, Any] | None) -> bool:
    status = (active_operator_run(task).get("status") or "").strip().lower()
    return status in {"complete", "blocked", "failed"}


def artifact_session_ready(task: dict[str, Any] | None) -> bool:
    if not task:
        return False
    details = (task.get("chat_session") or {}) if isinstance(task, dict) else {}
    chat_status = (details.get("status") or "").strip().lower()
    verification = details.get("artifactManifest") or {}
    verification_status = (
        ((verification.get("verification") or {}).get("lifecycleState") or "").strip().lower()
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


def artifact_prompt_ready(task: dict[str, Any] | None) -> bool:
    if not task:
        return False
    if is_conversation_route(task):
        return conversation_reply_ready(task)
    if operator_run_is_terminal(task):
        return True
    return artifact_session_ready(task)


def wait_for_prompt_result(
    db_paths: list[Path],
    prompt: str,
    *,
    timeout_secs: float,
) -> dict[str, Any]:
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        task = load_task_checkpoint_from_candidates(db_paths)
        if task and task_matches_prompt(task, prompt):
            phase = (task.get("phase") or "").strip().lower()
            if (
                phase in {"complete", "failed"}
                or task_has_interactive_wait_state(task)
                or artifact_prompt_ready(task)
            ):
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
        default=180.0,
        help="How long to wait for each prompt to settle.",
    )
    parser.add_argument(
        "--window-timeout-secs",
        type=float,
        default=WINDOW_WAIT_TIMEOUT_SECS,
        help="How long to wait for the desktop window. Increase this for cold Tauri builds.",
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
        "--profile",
        default=DEFAULT_PROFILE,
        help=f"Desktop profile to launch. Default: {DEFAULT_PROFILE}",
    )
    parser.add_argument(
        "--mcp-profile",
        help="Optional IOI_CHAT_ARTIFACT_MCP_PROFILE override for the launched desktop app.",
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
            "AUTOPILOT_DEV_START_SURFACE": "chat",
            "AUTOPILOT_DEV_START_INTENT": prompt,
            "AUTOPILOT_DATA_PROFILE": profile,
        }
    )
    if mcp_profile:
        env["IOI_CHAT_ARTIFACT_MCP_PROFILE"] = mcp_profile
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
    filtered = [line for line in lines if not HEARTBEAT_LOG_RE.match(line.strip())]
    return filtered[-max_lines:]


def chat_launch_stage_summary(log_path: Path) -> dict[str, Any]:
    if not log_path.exists():
        return {"stage_counts": {}, "latest_stage": None, "latest_detail": None}
    counts: dict[str, int] = {}
    latest_stage: str | None = None
    latest_detail: str | None = None
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = CHAT_LAUNCH_STAGE_RE.search(line)
        if not match:
            continue
        latest_stage = match.group(1)
        counts[latest_stage] = counts.get(latest_stage, 0) + 1
        latest_detail = line.split(" detail=", 1)[1] if " detail=" in line else None
    return {
        "stage_counts": counts,
        "latest_stage": latest_stage,
        "latest_detail": latest_detail,
        "waiting_for_session_projection_count": counts.get(
            "chat_seed_intent_waiting_for_session_projection",
            0,
        ),
        "projection_bind_failed_count": counts.get(
            "chat_seed_intent_projection_bind_failed",
            0,
        ),
    }


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


def record_screenshot_path(screenshots: dict[str, str], key: str, path: Path) -> None:
    if path.exists() and path.stat().st_size > 0:
        screenshots[key] = str(path)


def build_result_bundle(
    prompt: str,
    screenshot_path: Path | None,
    task: dict[str, Any] | None,
    log_tail: list[str],
    *,
    window_id: int | None,
    capture_mode: str | None,
    capture_diagnostics: dict[str, Any] | None,
    window_capture_error: str | None,
    probe_error: str | None = None,
    screenshots: dict[str, str] | None = None,
    db_info: dict[str, Any] | None = None,
    artifact_records: list[dict[str, Any]] | None = None,
    screenshot_diagnostics: dict[str, Any] | None = None,
    launch_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "prompt": prompt,
        "screenshot": str(screenshot_path)
        if screenshot_path and screenshot_path.exists() and screenshot_path.stat().st_size > 0
        else None,
        "screenshots": screenshots or {},
        "window_id": window_id,
        "capture_mode": capture_mode,
        "capture_diagnostics": capture_diagnostics,
        "screenshot_diagnostics": screenshot_diagnostics or {},
        "chat_launch_summary": launch_summary or {},
        "window_capture_error": window_capture_error,
        "db_diagnostics": db_info,
        "task": task,
        "runtime_facts_summary": runtime_facts_summary(task),
        "artifact_records_summary": artifact_records or [],
        "route_receipt_summary": latest_route_receipt_summary(task),
        "latest_agent_message": latest_agent_message(task),
        "log_tail": log_tail,
        "probe_error": probe_error,
    }


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
        capture_mode: str | None = None
        capture_diagnostics: dict[str, Any] | None = None
        probe_error: str | None = None
        screenshots: dict[str, str] = {}
        screenshot_diagnostics: dict[str, Any] = {}

        try:
            window_id = wait_for_window(
                args.window_name,
                timeout_secs=args.window_timeout_secs,
            )
            if window_id is not None:
                startup_path = prompt_dir / "startup.png"
                startup_capture = capture_window_with_fallback(
                    window_id,
                    startup_path,
                    browser_url=args.browser_capture_url,
                )
                record_screenshot_path(screenshots, "startup", startup_path)
                window_capture_error = startup_capture.error
                capture_mode = startup_capture.mode
                capture_diagnostics = startup_capture.diagnostics

            started_task = wait_for_prompt_start(
                db_paths,
                prompt,
                timeout_secs=min(45.0, max(5.0, args.timeout_secs / 3.0)),
            )
            if started_task and window_id is not None:
                pending_path = prompt_dir / "pending.png"
                pending_capture = capture_window_with_fallback(
                    window_id,
                    pending_path,
                    browser_url=args.browser_capture_url,
                )
                record_screenshot_path(screenshots, "pending", pending_path)
                window_capture_error = pending_capture.error or window_capture_error
                capture_mode = pending_capture.mode
                capture_diagnostics = pending_capture.diagnostics

            task = wait_for_prompt_result(
                db_paths,
                prompt,
                timeout_secs=args.timeout_secs,
            )
            if window_id is not None:
                time.sleep(POST_SETTLE_CAPTURE_DELAY_SECS)
                screenshot_path = prompt_dir / "final.png"
                capture_result = capture_window_with_fallback(
                    window_id,
                    screenshot_path,
                    browser_url=args.browser_capture_url,
                )
                record_screenshot_path(screenshots, "final", screenshot_path)
                window_capture_error = capture_result.error
                capture_mode = capture_result.mode
                capture_diagnostics = capture_result.diagnostics
                thoughts_path = prompt_dir / "thoughts_drawer.png"
                (
                    thoughts_click_diagnostics,
                    thoughts_capture_error,
                    thoughts_capture_diagnostics,
                ) = capture_thoughts_drawer_with_fallback(
                    window_id,
                    thoughts_path,
                    browser_url=args.browser_capture_url,
                    baseline_path=screenshot_path,
                )
                record_screenshot_path(screenshots, "thoughts_drawer", thoughts_path)
                screenshot_diagnostics["thoughts_drawer"] = {
                    "click": thoughts_click_diagnostics,
                    "capture_error": thoughts_capture_error,
                    "capture_diagnostics": thoughts_capture_diagnostics,
                }
            else:
                window_id = wait_for_window(args.window_name, timeout_secs=15.0)
                if window_id is not None:
                    screenshot_path = prompt_dir / "final.png"
                    capture_result = capture_window_with_fallback(
                        window_id,
                        screenshot_path,
                        browser_url=args.browser_capture_url,
                    )
                    record_screenshot_path(screenshots, "final", screenshot_path)
                    window_capture_error = capture_result.error
                    capture_mode = capture_result.mode
                    capture_diagnostics = capture_result.diagnostics
                    thoughts_path = prompt_dir / "thoughts_drawer.png"
                    (
                        thoughts_click_diagnostics,
                        thoughts_capture_error,
                        thoughts_capture_diagnostics,
                    ) = capture_thoughts_drawer_with_fallback(
                        window_id,
                        thoughts_path,
                        browser_url=args.browser_capture_url,
                        baseline_path=screenshot_path,
                    )
                    record_screenshot_path(screenshots, "thoughts_drawer", thoughts_path)
                    screenshot_diagnostics["thoughts_drawer"] = {
                        "click": thoughts_click_diagnostics,
                        "capture_error": thoughts_capture_error,
                        "capture_diagnostics": thoughts_capture_diagnostics,
                    }
                else:
                    window_capture_error = (
                        f"Timed out waiting for a window matching {args.window_name!r}"
                    )
        except Exception as error:
            probe_error = str(error)
            if task is None:
                task = latest_task_for_prompt(db_paths, prompt)
            if window_id is None:
                window_id = wait_for_window(args.window_name, timeout_secs=15.0)
            if window_id is not None:
                time.sleep(POST_SETTLE_CAPTURE_DELAY_SECS)
                screenshot_path = prompt_dir / "final.png"
                capture_result = capture_window_with_fallback(
                    window_id,
                    screenshot_path,
                    browser_url=args.browser_capture_url,
                )
                record_screenshot_path(screenshots, "final", screenshot_path)
                if window_capture_error is None:
                    window_capture_error = capture_result.error
                capture_mode = capture_result.mode
                capture_diagnostics = capture_result.diagnostics
                thoughts_path = prompt_dir / "thoughts_drawer.png"
                (
                    thoughts_click_diagnostics,
                    thoughts_capture_error,
                    thoughts_capture_diagnostics,
                ) = capture_thoughts_drawer_with_fallback(
                    window_id,
                    thoughts_path,
                    browser_url=args.browser_capture_url,
                    baseline_path=screenshot_path,
                )
                record_screenshot_path(screenshots, "thoughts_drawer", thoughts_path)
                screenshot_diagnostics["thoughts_drawer"] = {
                    "click": thoughts_click_diagnostics,
                    "capture_error": thoughts_capture_error,
                    "capture_diagnostics": thoughts_capture_diagnostics,
                }
            elif window_capture_error is None:
                window_capture_error = (
                    f"Timed out waiting for a window matching {args.window_name!r}"
                )
        finally:
            terminate_process_group(process)

        log_tail = read_log_tail(desktop_log_path)
        launch_summary = chat_launch_stage_summary(desktop_log_path)
        artifact_records = artifact_records_summary(db_paths)
        bundle = build_result_bundle(
            prompt,
            screenshot_path,
            task,
            log_tail,
            window_id=window_id,
            capture_mode=capture_mode,
            capture_diagnostics=capture_diagnostics,
            window_capture_error=window_capture_error,
            probe_error=probe_error,
            screenshots=screenshots,
            db_info=db_diagnostics(db_paths),
            artifact_records=artifact_records,
            screenshot_diagnostics=screenshot_diagnostics,
            launch_summary=launch_summary,
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
