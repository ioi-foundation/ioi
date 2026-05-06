#!/usr/bin/env python3
"""Launch Autopilot directly into Model Mounts and retain GUI evidence.

This probe avoids the chat-composer automation path. It starts a fresh runtime
daemon, seeds model-mounting state through the public API, launches the desktop
shell with `view=mounts`, switches Mounts tabs with validation-only keyboard
shortcuts, captures screenshots, and writes a compact result bundle.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from desktop_capture import capture_window_with_fallback
from desktop_workspace_activity_probe import image_difference_metric
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
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "docs/evidence/model-mounts-gui-validation"
WINDOW_WAIT_TIMEOUT_SECS = 240.0
POST_WINDOW_SETTLE_SECS = 8.0
TAB_SETTLE_SECS = 1.2
CAPTURE_RETRY_INTERVAL_SECS = 1.5
CAPTURE_READY_TIMEOUT_SECS = 18.0
CAPTURE_READY_MEAN_THRESHOLD = 0.12
MOUNT_TABS = [
    ("server", "F1"),
    ("backends", "F2"),
    ("models", "F3"),
    ("providers", "F4"),
    ("downloads", "F5"),
    ("tokens", "F6"),
    ("routing", "F7"),
    ("benchmarks", "F8"),
    ("logs", "F9"),
]
MIN_DISTINCT_TAB_TRANSITIONS = 4


def shell_join(cmd: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in cmd)


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"Command failed ({completed.returncode}): {shell_join(cmd)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return completed


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request_json(
    endpoint: str,
    route: str,
    *,
    method: str = "GET",
    body: Any | None = None,
    token: str | None = None,
    timeout: float = 10.0,
) -> Any:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"accept": "application/json"}
    if body is not None:
        headers["content-type"] = "application/json"
    if token:
        headers["authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{endpoint.rstrip('/')}{route}",
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8")
            return json.loads(text) if text else None
    except urllib.error.HTTPError as error:
        text = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {route} failed: {error.code} {text}") from error


def wait_for_daemon(endpoint: str, timeout_secs: float = 20.0) -> None:
    deadline = time.time() + timeout_secs
    last_error: str | None = None
    while time.time() < deadline:
        try:
            request_json(endpoint, "/api/v1/server/status", timeout=2.0)
            return
        except Exception as error:
            last_error = str(error)
            time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for daemon at {endpoint}: {last_error}")


def start_model_mounting_daemon(output_root: Path) -> tuple[subprocess.Popen[str], str, Path]:
    state_dir = Path(tempfile.mkdtemp(prefix="ioi-model-mounts-gui-state-"))
    daemon_log = output_root / "runtime-daemon.log"
    port = reserve_port()
    endpoint = f"http://127.0.0.1:{port}"
    code = """
import { startRuntimeDaemonService } from './packages/runtime-daemon/src/index.mjs';
const service = await startRuntimeDaemonService({
  cwd: process.env.IOI_MODEL_MOUNTS_GUI_CWD,
  stateDir: process.env.IOI_MODEL_MOUNTS_GUI_STATE_DIR,
  port: Number(process.env.IOI_MODEL_MOUNTS_GUI_PORT),
});
console.log(JSON.stringify({ endpoint: service.endpoint }));
const close = async () => {
  try { await service.close(); } finally { process.exit(0); }
};
process.on('SIGINT', close);
process.on('SIGTERM', close);
await new Promise(() => {});
"""
    env = os.environ.copy()
    env.update(
        {
            "IOI_MODEL_MOUNTS_GUI_CWD": str(PROJECT_ROOT),
            "IOI_MODEL_MOUNTS_GUI_STATE_DIR": str(state_dir),
            "IOI_MODEL_MOUNTS_GUI_PORT": str(port),
            "IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS": "25",
        }
    )
    log_handle = daemon_log.open("w", encoding="utf-8")
    process = subprocess.Popen(
        ["node", "--input-type=module", "-e", code],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=log_handle,
        text=True,
        start_new_session=True,
    )
    setattr(process, "_probe_log_handle", log_handle)
    line = process.stdout.readline() if process.stdout is not None else ""
    if not line.strip():
        terminate_process_group(process)
        raise RuntimeError(f"Runtime daemon did not report an endpoint. See {daemon_log}")
    reported = json.loads(line)
    endpoint = str(reported.get("endpoint") or endpoint)
    wait_for_daemon(endpoint)
    return process, endpoint, state_dir


def seed_model_mounting_state(endpoint: str) -> dict[str, Any]:
    grant = request_json(
        endpoint,
        "/api/v1/tokens",
        method="POST",
        body={
            "audience": "autopilot-local-server",
            "allowed": [
                "model.chat:*",
                "model.responses:*",
                "model.embeddings:*",
                "model.download:*",
                "model.import:*",
                "model.load:*",
                "model.mount:*",
                "backend.control:*",
                "route.use:*",
                "route.write:*",
                "mcp.import:*",
                "mcp.call:huggingface.model_search",
                "vault.read:*",
            ],
            "denied": ["connector.gmail.send", "filesystem.write", "shell.exec"],
        },
    )
    token = str(grant["token"])
    backend_health = request_json(
        endpoint,
        "/api/v1/backends/backend.autopilot.native-local.fixture/health",
        method="POST",
    )
    catalog_search = request_json(endpoint, "/api/v1/models/catalog/search?q=autopilot&format=gguf&limit=10")
    download = request_json(
        endpoint,
        "/api/v1/models/download",
        method="POST",
        token=token,
        body={
            "model_id": "autopilot:gui-download",
            "provider_id": "provider.autopilot.local",
            "source_url": "fixture://gui/model-mounts",
            "fixture_content": "family=gui-download\\ncontext=2048\\nquantization=Q4_K_M\\n",
            "max_bytes": 262144,
        },
    )
    action_queued_download = request_json(
        endpoint,
        "/api/v1/models/download",
        method="POST",
        token=token,
        body={
            "model_id": "autopilot:gui-queued-download",
            "provider_id": "provider.autopilot.local",
            "source_url": "fixture://gui/model-mounts-queued",
            "source_label": "Fixture catalog / queued GUI validation",
            "queued_only": True,
            "max_bytes": 131072,
        },
    )
    queued_download = request_json(
        endpoint,
        "/api/v1/models/download",
        method="POST",
        token=token,
        body={
            "model_id": "autopilot:gui-canceled-download",
            "provider_id": "provider.autopilot.local",
            "source_url": "fixture://gui/model-mounts-canceled",
            "source_label": "Fixture catalog / canceled GUI validation",
            "queued_only": True,
            "max_bytes": 131072,
        },
    )
    canceled_download = request_json(
        endpoint,
        f"/api/v1/models/download/cancel/{queued_download['id']}",
        method="POST",
        token=token,
    )
    failed_download = request_json(
        endpoint,
        "/api/v1/models/download",
        method="POST",
        token=token,
        body={
            "model_id": "autopilot:gui-failed-download",
            "provider_id": "provider.autopilot.local",
            "source_url": "fixture://gui/model-mounts-failed",
            "source_label": "Fixture catalog / failed GUI validation",
            "simulate_failure": True,
            "failure_reason": "gui_validation_fixture_failure",
            "max_bytes": 131072,
        },
    )
    mcp_import = request_json(
        endpoint,
        "/api/v1/mcp/import",
        method="POST",
        token=token,
        body={
            "mcpServers": {
                "huggingface": {
                    "url": "https://example.invalid/mcp",
                    "allowed_tools": ["model_search"],
                    "headers": {"authorization": "vault://mcp.huggingface/gui-validation"},
                }
            }
        },
    )
    chat = request_json(
        endpoint,
        "/api/v1/chat",
        method="POST",
        token=token,
        body={"route_id": "route.native-local", "model": "autopilot:native-fixture", "input": "GUI validation probe"},
    )
    route_test = request_json(
        endpoint,
        "/api/v1/routes/route.native-local/test",
        method="POST",
        token=token,
        body={
            "capability": "chat",
            "model": "autopilot:native-fixture",
            "model_policy": {"privacy": "local_only", "max_cost_usd": 0.05},
        },
    )
    response = request_json(
        endpoint,
        "/api/v1/responses",
        method="POST",
        token=token,
        body={
            "route_id": "route.native-local",
            "model": "autopilot:native-fixture",
            "input": "GUI benchmark responses probe",
            "model_policy": {"privacy": "local_only", "max_cost_usd": 0.05},
        },
    )
    embedding = request_json(
        endpoint,
        "/api/v1/embeddings",
        method="POST",
        token=token,
        body={
            "route_id": "route.native-local",
            "model": "autopilot:native-fixture",
            "input": ["GUI benchmark embedding probe", "model mounts"],
            "model_policy": {"privacy": "local_only", "max_cost_usd": 0.05},
        },
    )
    snapshot = request_json(endpoint, "/api/v1/models")
    projection = request_json(endpoint, "/api/v1/projections/model-mounting")
    downloads = snapshot.get("downloads", [])
    catalog_results = snapshot.get("catalog", {}).get("results", [])
    return {
        "grant_id": grant["id"],
        "token": token,
        "backend_health_receipt": backend_health.get("lastReceiptId"),
        "catalog_variant_count": len(catalog_results),
        "catalog_search_result_count": len(catalog_search.get("results", [])),
        "download_id": download["id"],
        "download_receipt": download.get("receiptId"),
        "queued_download_id": action_queued_download["id"],
        "canceled_download_id": canceled_download["id"],
        "failed_download_id": failed_download["id"],
        "download_status_counts": {
            "completed": len([item for item in downloads if item.get("status") == "completed"]),
            "failed": len([item for item in downloads if item.get("status") == "failed"]),
            "canceled": len([item for item in downloads if item.get("status") == "canceled"]),
            "queued": len([item for item in downloads if item.get("status") == "queued"]),
        },
        "mcp_count": mcp_import["count"],
        "chat_receipt": chat["receipt_id"],
        "benchmark_route_receipt": route_test.get("receipt", {}).get("id"),
        "benchmark_response_receipt": response.get("receipt_id"),
        "benchmark_embedding_receipt": embedding.get("receipt_id"),
        "snapshot_counts": {
            "backends": len(snapshot.get("backends", [])),
            "providers": len(snapshot.get("providers", [])),
            "artifacts": len(snapshot.get("artifacts", [])),
            "receipts": len(snapshot.get("receipts", [])),
        },
        "projection_watermark": projection.get("watermark"),
        "live_provider_state": collect_live_provider_state(endpoint),
    }


def seeded_state_assertions(seed: dict[str, Any] | None, screenshots: list[dict[str, Any]]) -> dict[str, Any]:
    counts = (seed or {}).get("download_status_counts") or {}
    screenshot_tabs = {item.get("tab") for item in screenshots}
    assertions = {
        "catalogVariantsSeeded": int((seed or {}).get("catalog_variant_count") or 0) >= 1,
        "completedDownloadSeeded": int(counts.get("completed") or 0) >= 1,
        "failedDownloadSeeded": int(counts.get("failed") or 0) >= 1,
        "canceledDownloadSeeded": int(counts.get("canceled") or 0) >= 1,
        "queuedDownloadSeeded": int(counts.get("queued") or 0) >= 1,
        "downloadsScreenshotCaptured": "downloads" in screenshot_tabs,
        "logsScreenshotCaptured": "logs" in screenshot_tabs,
        "tokensScreenshotCaptured": "tokens" in screenshot_tabs,
    }
    return {
        "passed": all(assertions.values()),
        "assertions": assertions,
    }


def collect_live_provider_state(endpoint: str) -> dict[str, Any]:
    """Capture redacted live-provider facts shown by the Mounts workbench."""
    state: dict[str, Any] = {"backends": {}, "providers": {}}
    for backend_id in ["backend.lmstudio", "backend.ollama"]:
        try:
            health = request_json(endpoint, f"/api/v1/backends/{backend_id}/health", method="POST", timeout=8.0)
            state["backends"][backend_id] = {
                "kind": health.get("kind"),
                "status": health.get("status"),
                "processStatus": health.get("processStatus"),
                "baseUrl": health.get("baseUrl"),
                "lastReceiptId": health.get("lastReceiptId"),
            }
        except Exception as error:
            state["backends"][backend_id] = {"status": "error", "errorClass": type(error).__name__}
    for provider_id in ["provider.lmstudio", "provider.ollama"]:
        provider_summary: dict[str, Any] = {}
        try:
            health = request_json(endpoint, f"/api/v1/providers/{provider_id}/health", method="POST", timeout=8.0)
            provider_summary.update(
                {
                    "kind": health.get("kind"),
                    "status": health.get("status"),
                    "baseUrl": health.get("baseUrl"),
                }
            )
        except Exception as error:
            provider_summary.update({"status": "error", "errorClass": type(error).__name__})
        try:
            models = request_json(endpoint, f"/api/v1/providers/{provider_id}/models", timeout=8.0)
            provider_summary["modelCount"] = len(models) if isinstance(models, list) else 0
            provider_summary["modelIds"] = [
                str(model.get("modelId") or model.get("id"))
                for model in (models if isinstance(models, list) else [])
                if model.get("modelId") or model.get("id")
            ][:8]
        except Exception as error:
            provider_summary["modelsErrorClass"] = type(error).__name__
        try:
            loaded = request_json(endpoint, f"/api/v1/providers/{provider_id}/loaded", timeout=8.0)
            provider_summary["loadedCount"] = len(loaded) if isinstance(loaded, list) else 0
            provider_summary["loadedModelIds"] = [
                str(model.get("modelId") or model.get("id"))
                for model in (loaded if isinstance(loaded, list) else [])
                if model.get("modelId") or model.get("id")
            ][:8]
        except Exception as error:
            provider_summary["loadedErrorClass"] = type(error).__name__
        state["providers"][provider_id] = provider_summary
    return state


def launch_mounts_desktop(profile: str, log_path: Path, dev_url: str, daemon_endpoint: str) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env.update(
        {
            "AUTOPILOT_RESET_DATA_ON_BOOT": "1",
            "AUTOPILOT_DATA_PROFILE": profile,
            "VITE_AUTOPILOT_INITIAL_VIEW": "mounts",
            "VITE_AUTOPILOT_MOUNTS_INITIAL_TAB": "server",
            "VITE_AUTOPILOT_MOUNTS_DAEMON_ENDPOINT": daemon_endpoint,
            "VITE_AUTOPILOT_MOUNTS_VALIDATION_ACTIONS": "1",
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


def capture_looks_ready(diagnostics: dict[str, Any] | None) -> bool:
    if not diagnostics:
        return False
    analysis = diagnostics.get("window_analysis")
    if not isinstance(analysis, dict):
        analysis = diagnostics.get("browser_analysis")
    if not isinstance(analysis, dict):
        return False
    try:
        mean = float(analysis.get("mean"))
        stddev = float(analysis.get("stddev"))
        colors = int(analysis.get("unique_colors"))
    except (TypeError, ValueError):
        return False
    return mean >= CAPTURE_READY_MEAN_THRESHOLD and stddev > 0.0001 and colors > 16


def activate_tab(window_id: int, shortcut: str) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    time.sleep(0.15)
    press_action_shortcut(window_id, shortcut)
    time.sleep(TAB_SETTLE_SECS)


def press_action_shortcut(window_id: int, shortcut: str) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    time.sleep(0.12)
    run(["xdotool", "key", shortcut], check=False)


def prepare_tab_for_capture(window_id: int, tab: str) -> dict[str, Any]:
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    time.sleep(0.1)
    run(["xdotool", "key", "Home"], check=False)
    time.sleep(0.1)
    if tab == "downloads":
        run(["xdotool", "mousemove", "--window", str(window_id), "920", "640"], check=False)
        time.sleep(0.1)
        run(["xdotool", "click", "1"], check=False)
        time.sleep(0.1)
        for _ in range(6):
            run(["xdotool", "click", "5"], check=False)
            time.sleep(0.04)
        return {"scroll": "wheel_down", "reason": "show_catalog_variants_download_rows_and_row_actions"}
    return {"scroll": "Home"}


def mounts_browser_url(dev_url: str, daemon_endpoint: str, tab: str) -> str:
    return (
        f"{dev_url.rstrip('/')}/?view=mounts&mountsTab={urllib.parse.quote(tab)}"
        f"&mountsEndpoint={urllib.parse.quote(daemon_endpoint, safe='')}"
        "&mountsValidationActions=1"
    )


def capture_tab(window_id: int, output_root: Path, dev_url: str, daemon_endpoint: str, tab: str) -> dict[str, Any]:
    screenshot_path = output_root / f"mounts-{tab}.png"
    browser_url = mounts_browser_url(dev_url, daemon_endpoint, tab)
    deadline = time.time() + CAPTURE_READY_TIMEOUT_SECS
    latest = None
    while True:
        latest = capture_window_with_fallback(
            window_id,
            screenshot_path,
            browser_url=browser_url,
            timeout_secs=8.0,
        )
        if latest.error or capture_looks_ready(latest.diagnostics):
            break
        if time.time() >= deadline:
            break
        time.sleep(CAPTURE_RETRY_INTERVAL_SECS)
    return {
        "tab": tab,
        "screenshot": str(screenshot_path) if screenshot_path.exists() else None,
        "capture_mode": latest.mode if latest else None,
        "capture_error": latest.error if latest else "capture did not run",
        "capture_diagnostics": latest.diagnostics if latest else {},
    }


def capture_action_state(
    window_id: int,
    output_root: Path,
    dev_url: str,
    daemon_endpoint: str,
    *,
    tab: str,
    name: str,
) -> dict[str, Any]:
    screenshot_path = output_root / f"mounts-{name}.png"
    latest = capture_window_with_fallback(
        window_id,
        screenshot_path,
        browser_url=mounts_browser_url(dev_url, daemon_endpoint, tab),
        timeout_secs=8.0,
    )
    return {
        "name": name,
        "tab": tab,
        "screenshot": str(screenshot_path) if screenshot_path.exists() else None,
        "capture_mode": latest.mode,
        "capture_error": latest.error,
        "capture_diagnostics": latest.diagnostics,
    }


def screenshot_metric_is_distinct(metric: str | None) -> bool:
    if not metric:
        return False
    try:
        return float(metric.split()[0]) > 0.0
    except (IndexError, ValueError):
        return False


def find_download(snapshot: dict[str, Any], job_id: str | None) -> dict[str, Any] | None:
    if not job_id:
        return None
    for item in snapshot.get("downloads", []):
        if item.get("id") == job_id:
            return item
    return None


def receipt_has_operation(receipts: list[dict[str, Any]], operation: str, job_id: str | None = None) -> bool:
    for receipt in receipts:
        details = receipt.get("details") if isinstance(receipt.get("details"), dict) else {}
        if receipt.get("kind") != "model_lifecycle":
            continue
        if details.get("operation") != operation:
            continue
        if job_id and details.get("jobId") != job_id:
            continue
        return True
    return False


def receipt_has_detail(receipts: list[dict[str, Any]], kind: str, detail_key: str, detail_value: str) -> bool:
    for receipt in receipts:
        details = receipt.get("details") if isinstance(receipt.get("details"), dict) else {}
        if receipt.get("kind") == kind and details.get(detail_key) == detail_value:
            return True
    return False


def receipt_has_operation_detail(
    receipts: list[dict[str, Any]],
    operation: str,
    detail_key: str,
    detail_value: str,
) -> bool:
    for receipt in receipts:
        details = receipt.get("details") if isinstance(receipt.get("details"), dict) else {}
        if receipt.get("kind") == "model_lifecycle" and details.get("operation") == operation and details.get(detail_key) == detail_value:
            return True
    return False


def stream_receipt_has_details(
    receipt: dict[str, Any],
    *,
    kind: str,
    stream_kind: str,
    status: str,
) -> bool:
    details = receipt.get("details") if isinstance(receipt.get("details"), dict) else {}
    if receipt.get("kind") != kind:
        return False
    if details.get("streamKind") != stream_kind:
        return False
    if details.get("routeId") != "route.native-local":
        return False
    if details.get("selectedModel") != "autopilot:native-fixture":
        return False
    if details.get("endpointId") != "endpoint.autopilot.native-fixture":
        return False
    if details.get("streamSource") != "provider_native":
        return False
    if details.get("backendId") != "backend.autopilot.native-local.fixture":
        return False
    if details.get("providerResponseKind") not in {"native_local.chat.stream", "native_local.responses.stream"}:
        return False
    if status == "completed":
        return bool(details.get("invocationReceiptId")) and details.get("finishReason") == "stop"
    if status == "aborted":
        return (
            bool(details.get("invocationReceiptId"))
            and details.get("status") == "aborted"
            and details.get("reason") == "client_disconnect"
        )
    return False


def backend_logs_include(endpoint: str, backend_id: str, event: str) -> bool:
    records = request_json(endpoint, f"/api/v1/backends/{urllib.parse.quote(backend_id)}/logs")
    return any(record.get("event") == event for record in records if isinstance(record, dict))


def wait_for_snapshot_condition(
    endpoint: str,
    label: str,
    predicate,
    *,
    timeout_secs: float = 25.0,
    interval_secs: float = 0.5,
) -> tuple[dict[str, Any], Any]:
    deadline = time.time() + timeout_secs
    last_snapshot: dict[str, Any] | None = None
    last_error: str | None = None
    while time.time() < deadline:
        try:
            snapshot = request_json(endpoint, "/api/v1/models", timeout=6.0)
            last_snapshot = snapshot
            result = predicate(snapshot)
            if result is not None:
                return snapshot, result
        except Exception as error:
            last_error = str(error)
        time.sleep(interval_secs)
    raise RuntimeError(f"Timed out waiting for {label}. Last error: {last_error}; last snapshot: {last_snapshot}")


def wait_for_receipt_condition(
    endpoint: str,
    label: str,
    predicate,
    *,
    timeout_secs: float = 25.0,
    interval_secs: float = 0.5,
) -> list[dict[str, Any]]:
    deadline = time.time() + timeout_secs
    last_receipts: list[dict[str, Any]] = []
    last_error: str | None = None
    while time.time() < deadline:
        try:
            receipts = request_json(endpoint, "/api/v1/receipts", timeout=6.0)
            if isinstance(receipts, list):
                last_receipts = receipts
                if predicate(receipts):
                    return receipts
        except Exception as error:
            last_error = str(error)
        time.sleep(interval_secs)
    raise RuntimeError(f"Timed out waiting for {label}. Last error: {last_error}; receipt count: {len(last_receipts)}")


def wait_for_new_receipt_condition(
    endpoint: str,
    label: str,
    before_count: int,
    predicate,
    *,
    timeout_secs: float = 25.0,
    interval_secs: float = 0.5,
) -> list[dict[str, Any]]:
    return wait_for_receipt_condition(
        endpoint,
        label,
        lambda receipts: len(receipts) > before_count and predicate(receipts[before_count:]),
        timeout_secs=timeout_secs,
        interval_secs=interval_secs,
    )


def exercise_download_row_actions(
    window_id: int,
    output_root: Path,
    dev_url: str,
    endpoint: str,
    seed: dict[str, Any],
) -> dict[str, Any]:
    """Exercise the Downloads row action handlers through the live Mounts desktop surface."""

    action_screenshots: list[dict[str, Any]] = []
    opened_receipt_id = str(seed.get("download_receipt") or "")
    queued_download_id = str(seed.get("queued_download_id") or "")
    failed_download_id = str(seed.get("failed_download_id") or "")

    activate_tab(window_id, "F5")
    press_action_shortcut(window_id, "F12")
    time.sleep(1.0)
    action_screenshots.append(
        capture_action_state(
            window_id,
            output_root,
            dev_url,
            endpoint,
            tab="logs",
            name="downloads-open-receipt-logs",
        )
    )
    opened_receipt = request_json(endpoint, f"/api/v1/receipts/{urllib.parse.quote(opened_receipt_id)}")

    activate_tab(window_id, "F5")
    press_action_shortcut(window_id, "F10")
    _, canceled_download = wait_for_snapshot_condition(
        endpoint,
        "queued download to become canceled through Mounts row action",
        lambda snapshot: (
            item
            if (item := find_download(snapshot, queued_download_id)) is not None and item.get("status") == "canceled"
            else None
        ),
    )
    action_screenshots.append(
        capture_action_state(
            window_id,
            output_root,
            dev_url,
            endpoint,
            tab="downloads",
            name="downloads-after-cancel-action",
        )
    )

    activate_tab(window_id, "F5")
    before_retry = request_json(endpoint, "/api/v1/models")
    before_retry_ids = {item.get("id") for item in before_retry.get("downloads", [])}
    press_action_shortcut(window_id, "F11")

    def retry_completed(snapshot: dict[str, Any]) -> dict[str, Any] | None:
        for item in snapshot.get("downloads", []):
            if item.get("id") in before_retry_ids:
                continue
            if item.get("modelId") == "autopilot:gui-failed-download" and item.get("status") == "completed":
                return item
        return None

    _, retried_download = wait_for_snapshot_condition(
        endpoint,
        "failed download retry to create a completed replacement through Mounts row action",
        retry_completed,
    )
    action_screenshots.append(
        capture_action_state(
            window_id,
            output_root,
            dev_url,
            endpoint,
            tab="downloads",
            name="downloads-after-retry-action",
        )
    )

    receipts = request_json(endpoint, "/api/v1/receipts")
    assertions = {
        "openReceiptKeyRoutedToLogs": action_screenshots[0].get("tab") == "logs" and not action_screenshots[0].get("capture_error"),
        "openedReceiptLookupSucceeded": opened_receipt.get("id") == opened_receipt_id,
        "queuedDownloadCanceledThroughGuiAction": canceled_download.get("id") == queued_download_id
        and canceled_download.get("status") == "canceled",
        "cancelLifecycleReceiptRecorded": receipt_has_operation(receipts, "model_download_canceled", queued_download_id),
        "failedDownloadRetriedThroughGuiAction": retried_download.get("id") != failed_download_id
        and retried_download.get("status") == "completed",
        "retryLifecycleReceiptRecorded": receipt_has_operation(
            receipts,
            "model_download_completed",
            str(retried_download.get("id") or ""),
        ),
        "actionScreenshotsCaptured": all(item.get("screenshot") and not item.get("capture_error") for item in action_screenshots),
    }
    return {
        "passed": all(assertions.values()),
        "assertions": assertions,
        "openedReceiptId": opened_receipt_id,
        "queuedDownloadId": queued_download_id,
        "canceledDownloadReceipt": canceled_download.get("receiptId"),
        "failedDownloadId": failed_download_id,
        "retryDownloadId": retried_download.get("id"),
        "retryDownloadReceipt": retried_download.get("receiptId"),
        "screenshots": action_screenshots,
    }


def exercise_model_lifecycle_actions(
    window_id: int,
    output_root: Path,
    dev_url: str,
    endpoint: str,
) -> dict[str, Any]:
    """Exercise model import, mount, load, unload, drawer, and receipt navigation controls."""

    model_id = "autopilot:gui-lifecycle"
    endpoint_id = "endpoint.autopilot.gui-lifecycle"
    identifier = "gui-lifecycle-validation"
    action_screenshots: list[dict[str, Any]] = []
    observed: dict[str, list[dict[str, Any]]] = {}

    def receipts_before() -> int:
        receipts = request_json(endpoint, "/api/v1/receipts")
        return len(receipts) if isinstance(receipts, list) else 0

    def run_receipted_action(shortcut: str, label: str, condition_label: str, predicate) -> list[dict[str, Any]]:
        before_count = receipts_before()
        press_action_shortcut(window_id, shortcut)
        receipts = wait_for_new_receipt_condition(endpoint, condition_label, before_count, predicate)
        observed[label] = receipts[before_count:]
        time.sleep(1.0)
        action_screenshots.append(
            capture_action_state(
                window_id,
                output_root,
                dev_url,
                endpoint,
                tab="models",
                name=label,
            )
        )
        time.sleep(1.0)
        return observed[label]

    activate_tab(window_id, "F3")
    run_receipted_action(
        "shift+F16",
        "models-after-import-action",
        "model import receipt",
        lambda receipts: receipt_has_operation_detail(receipts, "model_import", "modelId", model_id),
    )
    run_receipted_action(
        "shift+F17",
        "models-after-mount-action",
        "model mount receipt",
        lambda receipts: receipt_has_operation_detail(receipts, "model_mount", "endpointId", endpoint_id),
    )
    run_receipted_action(
        "shift+F18",
        "models-after-load-action",
        "model load receipt",
        lambda receipts: receipt_has_operation_detail(receipts, "model_load", "modelId", model_id),
    )
    loaded_snapshot, loaded_instance = wait_for_snapshot_condition(
        endpoint,
        "GUI lifecycle loaded instance projection",
        lambda snapshot: next(
            (
                instance
                for instance in snapshot.get("instances", [])
                if instance.get("modelId") == model_id and instance.get("status") == "loaded"
            ),
            None,
        ),
    )
    run_receipted_action(
        "shift+F19",
        "models-after-unload-action",
        "model unload receipt",
        lambda receipts: receipt_has_operation_detail(receipts, "model_unload", "modelId", model_id),
    )
    final_snapshot, unloaded_instance = wait_for_snapshot_condition(
        endpoint,
        "GUI lifecycle unloaded instance projection",
        lambda snapshot: next(
            (
                instance
                for instance in snapshot.get("instances", [])
                if instance.get("modelId") == model_id and instance.get("status") == "unloaded"
            ),
            None,
        ),
    )
    receipts = request_json(endpoint, "/api/v1/receipts")
    model_receipts = [
        receipt
        for receipt in receipts
        if model_id in json.dumps(receipt, sort_keys=True)
        or endpoint_id in json.dumps(receipt, sort_keys=True)
        or identifier in json.dumps(receipt, sort_keys=True)
    ]
    opened_receipt_id = str(model_receipts[-1].get("id") if model_receipts else "")
    press_action_shortcut(window_id, "shift+F20")
    time.sleep(1.5)
    action_screenshots.append(
        capture_action_state(
            window_id,
            output_root,
            dev_url,
            endpoint,
            tab="logs",
            name="models-open-receipt-logs",
        )
    )
    opened_receipt = request_json(endpoint, f"/api/v1/receipts/{urllib.parse.quote(opened_receipt_id)}") if opened_receipt_id else {}
    replay = request_json(endpoint, f"/api/v1/receipts/{urllib.parse.quote(opened_receipt_id)}/replay") if opened_receipt_id else {}
    artifact = next((item for item in final_snapshot.get("artifacts", []) if item.get("modelId") == model_id), {})
    mounted_endpoint = next((item for item in final_snapshot.get("endpoints", []) if item.get("id") == endpoint_id), {})
    assertions = {
        "importLifecycleReceiptRecorded": len(observed.get("models-after-import-action", [])) > 0,
        "mountLifecycleReceiptRecorded": len(observed.get("models-after-mount-action", [])) > 0,
        "loadLifecycleReceiptRecorded": len(observed.get("models-after-load-action", [])) > 0,
        "unloadLifecycleReceiptRecorded": len(observed.get("models-after-unload-action", [])) > 0,
        "importedArtifactProjected": artifact.get("modelId") == model_id
        and artifact.get("state") == "installed"
        and artifact.get("format") == "gguf"
        and artifact.get("quantization") == "Q4_K_M",
        "mountedEndpointProjected": mounted_endpoint.get("id") == endpoint_id
        and mounted_endpoint.get("status") == "mounted"
        and mounted_endpoint.get("backendId") == "backend.autopilot.native-local.fixture",
        "loadedInstanceProjected": loaded_instance.get("status") == "loaded"
        and loaded_instance.get("identifier") == identifier,
        "unloadedInstanceProjected": unloaded_instance.get("status") == "unloaded"
        and unloaded_instance.get("identifier") == identifier,
        "detailDrawerMetadataProjected": artifact.get("contextWindow") == 4096
        and "chat" in (artifact.get("capabilities") or [])
        and mounted_endpoint.get("baseUrl") == "local://ioi-daemon/gui-lifecycle-validation",
        "modelReceiptTrailAvailable": len(model_receipts) >= 4,
        "receiptLinkRoutedToLogs": action_screenshots[-1].get("tab") == "logs"
        and not action_screenshots[-1].get("capture_error"),
        "openedReceiptLookupSucceeded": opened_receipt.get("id") == opened_receipt_id
        and opened_receipt.get("kind") == "model_lifecycle",
        "receiptReplaySucceeded": replay.get("receipt", {}).get("id") == opened_receipt_id,
        "actionScreenshotsCaptured": all(item.get("screenshot") and not item.get("capture_error") for item in action_screenshots),
    }
    return {
        "passed": all(assertions.values()),
        "assertions": assertions,
        "observedReceiptIds": {
            label: [receipt.get("id") for receipt in receipts_for_action]
            for label, receipts_for_action in observed.items()
        },
        "modelId": model_id,
        "endpointId": endpoint_id,
        "loadedInstanceId": loaded_instance.get("id"),
        "unloadedInstanceId": unloaded_instance.get("id"),
        "openedReceiptId": opened_receipt_id,
        "screenshots": action_screenshots,
    }


def exercise_token_mcp_actions(
    window_id: int,
    output_root: Path,
    dev_url: str,
    endpoint: str,
    seed: dict[str, Any],
) -> dict[str, Any]:
    """Exercise token, vault, and MCP controls through the live Mounts desktop surface."""

    validation_grant_id = "wallet.grant.mounts.gui.validation"
    action_screenshots: list[dict[str, Any]] = []

    def receipts_before() -> int:
        receipts = request_json(endpoint, "/api/v1/receipts")
        return len(receipts) if isinstance(receipts, list) else 0

    activate_tab(window_id, "F6")
    for shortcut, label, condition_label, predicate in [
        (
            "shift+F10",
            "tokens-after-create-action",
            "validation token create receipt",
            lambda receipts: receipt_has_detail(receipts, "permission_token", "grantId", validation_grant_id),
        ),
        (
            "shift+F11",
            "tokens-after-revoke-action",
            "validation token revoke receipt",
            lambda receipts: receipt_has_detail(receipts, "permission_token_revocation", "grantId", validation_grant_id),
        ),
        (
            "shift+F12",
            "tokens-after-mcp-import-action",
            "MCP import receipt",
            lambda receipts: receipt_has_detail(receipts, "mcp_server_import", "id", "mcp.huggingface"),
        ),
        (
            "F13",
            "tokens-after-ephemeral-mcp-action",
            "ephemeral MCP linked model receipt",
            lambda receipts: any(
                receipt.get("kind") == "model_invocation"
                and isinstance(receipt.get("details"), dict)
                and len(receipt["details"].get("toolReceiptIds") or []) > 0
                and len(receipt["details"].get("ephemeralMcpServerIds") or []) > 0
                for receipt in receipts
            ),
        ),
        (
            "F14",
            "tokens-after-vault-health-action",
            "vault health receipt",
            lambda receipts: any(receipt.get("kind") == "vault_adapter_health" for receipt in receipts),
        ),
    ]:
        before_count = receipts_before()
        press_action_shortcut(window_id, shortcut)
        wait_for_new_receipt_condition(endpoint, condition_label, before_count, predicate)
        action_screenshots.append(
            capture_action_state(
                window_id,
                output_root,
                dev_url,
                endpoint,
                tab="tokens",
                name=label,
            )
        )
        time.sleep(1.5)

    press_action_shortcut(window_id, "F15")
    time.sleep(1.5)
    latest_vault = request_json(endpoint, "/api/v1/vault/health/latest", token=str(seed.get("token") or ""))
    action_screenshots.append(
        capture_action_state(
            window_id,
            output_root,
            dev_url,
            endpoint,
            tab="tokens",
            name="tokens-after-vault-latest-action",
        )
    )

    snapshot = request_json(endpoint, "/api/v1/models")
    receipts = request_json(endpoint, "/api/v1/receipts")
    validation_tokens = [
        token for token in snapshot.get("tokens", [])
        if token.get("grantId") == validation_grant_id
    ]
    latest_validation_token = validation_tokens[-1] if validation_tokens else {}
    linked_invocations = [
        receipt for receipt in receipts
        if receipt.get("kind") == "model_invocation"
        and isinstance(receipt.get("details"), dict)
        and len(receipt["details"].get("toolReceiptIds") or []) > 0
        and len(receipt["details"].get("ephemeralMcpServerIds") or []) > 0
    ]
    tool_receipt_ids = linked_invocations[-1].get("details", {}).get("toolReceiptIds", []) if linked_invocations else []
    assertions = {
        "validationTokenCreated": receipt_has_detail(receipts, "permission_token", "grantId", validation_grant_id),
        "validationTokenRevoked": receipt_has_detail(receipts, "permission_token_revocation", "grantId", validation_grant_id)
        and (
            latest_validation_token.get("state") == "revoked"
            or bool(latest_validation_token.get("revokedAt"))
            or int(latest_validation_token.get("revocationEpoch") or 0) > 0
        ),
        "mcpImportReceiptRecorded": receipt_has_detail(receipts, "mcp_server_import", "id", "mcp.huggingface"),
        "mcpServerProjected": any(server.get("id") == "mcp.huggingface" for server in snapshot.get("mcpServers", [])),
        "ephemeralMcpRegistrationRecorded": any(receipt.get("kind") == "mcp_ephemeral_registration" for receipt in receipts),
        "ephemeralMcpToolReceiptRecorded": any(receipt.get("kind") == "mcp_tool_invocation" for receipt in receipts),
        "ephemeralMcpLinkedToModelReceipt": len(tool_receipt_ids) > 0,
        "vaultHealthReceiptRecorded": any(receipt.get("kind") == "vault_adapter_health" for receipt in receipts),
        "latestVaultHealthLookupSucceeded": latest_vault.get("receipt", {}).get("kind") == "vault_adapter_health",
        "rawTokenRedactedFromProjection": all("token" not in token for token in snapshot.get("tokens", [])),
        "vaultRefsRedactedInMcpProjection": all(
            not any(str(value).startswith("vault://") for value in (server.get("secretRefs") or {}).values())
            for server in snapshot.get("mcpServers", [])
        ),
        "actionScreenshotsCaptured": all(item.get("screenshot") and not item.get("capture_error") for item in action_screenshots),
    }
    return {
        "passed": all(assertions.values()),
        "assertions": assertions,
        "validationGrantId": validation_grant_id,
        "validationTokenIds": [token.get("id") for token in validation_tokens],
        "linkedToolReceiptIds": tool_receipt_ids,
        "latestVaultReceiptId": latest_vault.get("receipt", {}).get("id"),
        "screenshots": action_screenshots,
    }


def exercise_routing_workflow_actions(
    window_id: int,
    output_root: Path,
    dev_url: str,
    endpoint: str,
) -> dict[str, Any]:
    """Exercise route, workflow node, and Receipt Gate controls through the Mounts surface."""

    action_screenshots: list[dict[str, Any]] = []
    observed: dict[str, list[dict[str, Any]]] = {}

    def receipts_before() -> int:
        receipts = request_json(endpoint, "/api/v1/receipts")
        return len(receipts) if isinstance(receipts, list) else 0

    def run_receipted_action(shortcut: str, label: str, condition_label: str, predicate) -> None:
        before_count = receipts_before()
        press_action_shortcut(window_id, shortcut)
        receipts = wait_for_new_receipt_condition(endpoint, condition_label, before_count, predicate)
        observed[label] = receipts[before_count:]
        action_screenshots.append(
            capture_action_state(
                window_id,
                output_root,
                dev_url,
                endpoint,
                tab="routing",
                name=label,
            )
        )
        time.sleep(1.5)

    activate_tab(window_id, "F7")
    run_receipted_action(
        "F16",
        "routing-after-route-test-action",
        "route test receipt",
        lambda receipts: receipt_has_detail(receipts, "model_route_selection", "routeId", "route.local-first"),
    )
    run_receipted_action(
        "F17",
        "routing-after-route-draft-test-action",
        "route draft test receipt",
        lambda receipts: any(receipt.get("kind") == "model_route_selection" for receipt in receipts),
    )
    run_receipted_action(
        "F18",
        "routing-after-workflow-probe-action",
        "workflow node receipts",
        lambda receipts: any(receipt.get("kind") == "model_invocation" for receipt in receipts)
        and any(receipt.get("kind") == "mcp_tool_invocation" for receipt in receipts),
    )
    run_receipted_action(
        "F19",
        "routing-after-receipt-gate-pass-action",
        "Receipt Gate pass receipt",
        lambda receipts: any(receipt.get("kind") == "workflow_receipt_gate" for receipt in receipts),
    )
    run_receipted_action(
        "F20",
        "routing-after-receipt-gate-block-action",
        "Receipt Gate block receipt",
        lambda receipts: any(receipt.get("kind") == "workflow_receipt_gate_blocked" for receipt in receipts),
    )

    snapshot = request_json(endpoint, "/api/v1/models")
    receipts = request_json(endpoint, "/api/v1/receipts")
    route = next((item for item in snapshot.get("routes", []) if item.get("id") == "route.local-first"), {})
    route_receipt_id = route.get("receipt") or route.get("lastReceiptId")
    workflow_nodes = {node.get("node") for node in snapshot.get("workflowNodes", [])}
    workflow_new = observed.get("routing-after-workflow-probe-action", [])
    gate_pass_receipts = [receipt for receipt in receipts if receipt.get("kind") == "workflow_receipt_gate"]
    gate_block_receipts = [receipt for receipt in receipts if receipt.get("kind") == "workflow_receipt_gate_blocked"]
    assertions = {
        "routeTestReceiptRecorded": len(observed.get("routing-after-route-test-action", [])) > 0,
        "routeDraftTestReceiptRecorded": len(observed.get("routing-after-route-draft-test-action", [])) > 0,
        "workflowModelInvocationRecorded": any(receipt.get("kind") == "model_invocation" for receipt in workflow_new),
        "workflowMcpToolReceiptRecorded": any(receipt.get("kind") == "mcp_tool_invocation" for receipt in workflow_new),
        "receiptGatePassRecorded": len(observed.get("routing-after-receipt-gate-pass-action", [])) > 0
        and any((receipt.get("details") or {}).get("requiredToolReceiptIds") for receipt in gate_pass_receipts),
        "receiptGateBlockRecorded": len(observed.get("routing-after-receipt-gate-block-action", [])) > 0
        and any((receipt.get("details") or {}).get("failures") for receipt in gate_block_receipts),
        "workflowNodesProjected": {"Model Router", "Model Call", "Embedding", "Local Tool/MCP", "Receipt Gate"}.issubset(workflow_nodes),
        "routeProjectionUpdated": route_receipt_id not in {None, "", "none"},
        "actionScreenshotsCaptured": all(item.get("screenshot") and not item.get("capture_error") for item in action_screenshots),
    }
    return {
        "passed": all(assertions.values()),
        "assertions": assertions,
        "observedReceiptIds": {
            label: [receipt.get("id") for receipt in receipts_for_action]
            for label, receipts_for_action in observed.items()
        },
        "routeReceipt": route_receipt_id,
        "latestGateReceiptId": gate_pass_receipts[-1].get("id") if gate_pass_receipts else None,
        "latestBlockedGateReceiptId": gate_block_receipts[-1].get("id") if gate_block_receipts else None,
        "screenshots": action_screenshots,
    }


def exercise_benchmark_observability_actions(
    window_id: int,
    output_root: Path,
    dev_url: str,
    endpoint: str,
) -> dict[str, Any]:
    """Exercise benchmark run, receipt replay, and Logs focus from the Mounts surface."""

    action_screenshots: list[dict[str, Any]] = []
    observed: dict[str, list[dict[str, Any]]] = {}

    def receipts_before() -> int:
        receipts = request_json(endpoint, "/api/v1/receipts")
        return len(receipts) if isinstance(receipts, list) else 0

    def native_benchmark_invocation(receipt: dict[str, Any], summary_prefix: str | None = None) -> bool:
        details = receipt.get("details") if isinstance(receipt.get("details"), dict) else {}
        summary = str(receipt.get("summary") or "")
        if receipt.get("kind") != "model_invocation":
            return False
        if details.get("routeId") != "route.native-local":
            return False
        if details.get("endpointId") != "endpoint.autopilot.native-fixture":
            return False
        if details.get("selectedModel") != "autopilot:native-fixture":
            return False
        return summary.startswith(summary_prefix) if summary_prefix else True

    def benchmark_receipts_ready(receipts: list[dict[str, Any]]) -> bool:
        return (
            receipt_has_detail(receipts, "model_route_selection", "routeId", "route.native-local")
            and len([receipt for receipt in receipts if native_benchmark_invocation(receipt, "chat invocation")]) >= 2
            and any(native_benchmark_invocation(receipt, "responses invocation") for receipt in receipts)
            and any(native_benchmark_invocation(receipt, "embeddings invocation") for receipt in receipts)
        )

    activate_tab(window_id, "F8")
    before_count = receipts_before()
    press_action_shortcut(window_id, "shift+F13")
    receipts = wait_for_new_receipt_condition(
        endpoint,
        "benchmark route, chat, responses, and embeddings receipts",
        before_count,
        benchmark_receipts_ready,
        timeout_secs=35.0,
    )
    observed["benchmarks-after-run-action"] = receipts[before_count:]
    time.sleep(1.5)
    action_screenshots.append(
        capture_action_state(
            window_id,
            output_root,
            dev_url,
            endpoint,
            tab="benchmarks",
            name="benchmarks-after-run-action",
        )
    )

    benchmark_receipts = [receipt for receipt in request_json(endpoint, "/api/v1/receipts") if native_benchmark_invocation(receipt)]
    latest_benchmark = benchmark_receipts[-1] if benchmark_receipts else {}
    latest_benchmark_id = str(latest_benchmark.get("id") or "")

    press_action_shortcut(window_id, "shift+F14")
    time.sleep(1.5)
    replay = request_json(endpoint, f"/api/v1/receipts/{urllib.parse.quote(latest_benchmark_id)}/replay") if latest_benchmark_id else {}
    action_screenshots.append(
        capture_action_state(
            window_id,
            output_root,
            dev_url,
            endpoint,
            tab="benchmarks",
            name="benchmarks-after-replay-action",
        )
    )

    press_action_shortcut(window_id, "shift+F15")
    time.sleep(1.5)
    action_screenshots.append(
        capture_action_state(
            window_id,
            output_root,
            dev_url,
            endpoint,
            tab="logs",
            name="benchmarks-open-receipt-logs",
        )
    )
    opened_receipt = request_json(endpoint, f"/api/v1/receipts/{urllib.parse.quote(latest_benchmark_id)}") if latest_benchmark_id else {}

    snapshot = request_json(endpoint, "/api/v1/models")
    receipts = request_json(endpoint, "/api/v1/receipts")
    native_invocations = [receipt for receipt in receipts if native_benchmark_invocation(receipt)]
    chat_receipts = [receipt for receipt in native_invocations if str(receipt.get("summary") or "").startswith("chat invocation")]
    response_receipts = [receipt for receipt in native_invocations if str(receipt.get("summary") or "").startswith("responses invocation")]
    embedding_receipts = [receipt for receipt in native_invocations if str(receipt.get("summary") or "").startswith("embeddings invocation")]
    benchmark_route_receipts = [
        receipt for receipt in receipts
        if receipt.get("kind") == "model_route_selection"
        and (receipt.get("details") or {}).get("routeId") == "route.native-local"
    ]
    route = next((item for item in snapshot.get("routes", []) if item.get("id") == "route.native-local"), {})
    observability_ready = all(
        (receipt.get("details") or {}).get("backendId") == "backend.autopilot.native-local.fixture"
        and (receipt.get("details") or {}).get("grantId")
        and (receipt.get("details") or {}).get("latencyMs")
        for receipt in native_invocations[-4:]
    )
    assertions = {
        "benchmarkRouteReceiptRecorded": len(benchmark_route_receipts) > 0,
        "benchmarkChatReceiptRecorded": len(chat_receipts) >= 2,
        "benchmarkResponsesReceiptRecorded": len(response_receipts) >= 1,
        "benchmarkEmbeddingsReceiptRecorded": len(embedding_receipts) >= 1,
        "benchmarkResultProjectionUpdated": route.get("receipt") not in {None, "", "none"}
        or route.get("lastReceiptId") not in {None, "", "none"},
        "benchmarkReceiptReplaySucceeded": replay.get("receipt", {}).get("id") == latest_benchmark_id,
        "openedBenchmarkReceiptLookupSucceeded": opened_receipt.get("id") == latest_benchmark_id
        and opened_receipt.get("kind") == "model_invocation",
        "benchmarkLogsFocused": action_screenshots[-1].get("tab") == "logs"
        and not action_screenshots[-1].get("capture_error"),
        "benchmarkObservabilityPayloadAvailable": observability_ready,
        "actionScreenshotsCaptured": all(item.get("screenshot") and not item.get("capture_error") for item in action_screenshots),
    }
    return {
        "passed": all(assertions.values()),
        "assertions": assertions,
        "observedReceiptIds": {
            label: [receipt.get("id") for receipt in receipts_for_action]
            for label, receipts_for_action in observed.items()
        },
        "latestBenchmarkReceiptId": latest_benchmark_id,
        "benchmarkRouteReceiptIds": [receipt.get("id") for receipt in benchmark_route_receipts[-3:]],
        "benchmarkInvocationCounts": {
            "chat": len(chat_receipts),
            "responses": len(response_receipts),
            "embeddings": len(embedding_receipts),
        },
        "screenshots": action_screenshots,
    }


def exercise_stream_lifecycle_observability_action(
    window_id: int,
    output_root: Path,
    dev_url: str,
    endpoint: str,
) -> dict[str, Any]:
    """Exercise the Logs stream lifecycle panel with live provider-native stream receipts."""

    action_screenshots: list[dict[str, Any]] = []
    before_receipts = request_json(endpoint, "/api/v1/receipts")
    before_count = len(before_receipts) if isinstance(before_receipts, list) else 0

    activate_tab(window_id, "F9")
    press_action_shortcut(window_id, "alt+s")
    receipts = wait_for_new_receipt_condition(
        endpoint,
        "GUI stream lifecycle completed and aborted receipts",
        before_count,
        lambda new_receipts: (
            any(
                stream_receipt_has_details(
                    receipt,
                    kind="model_invocation_stream_completed",
                    stream_kind="openai_chat_completions_native_local",
                    status="completed",
                )
                for receipt in new_receipts
            )
            and any(
                stream_receipt_has_details(
                    receipt,
                    kind="model_invocation_stream_canceled",
                    stream_kind="openai_responses_native_local",
                    status="aborted",
                )
                for receipt in new_receipts
            )
        ),
        timeout_secs=35.0,
    )
    time.sleep(1.5)
    action_screenshots.append(
        capture_action_state(
            window_id,
            output_root,
            dev_url,
            endpoint,
            tab="logs",
            name="logs-after-stream-lifecycle-action",
        )
    )

    all_receipts = request_json(endpoint, "/api/v1/receipts")
    completed_receipts = [
        receipt
        for receipt in all_receipts
        if stream_receipt_has_details(
            receipt,
            kind="model_invocation_stream_completed",
            stream_kind="openai_chat_completions_native_local",
            status="completed",
        )
    ]
    aborted_receipts = [
        receipt
        for receipt in all_receipts
        if stream_receipt_has_details(
            receipt,
            kind="model_invocation_stream_canceled",
            stream_kind="openai_responses_native_local",
            status="aborted",
        )
    ]
    latest_completed = completed_receipts[-1] if completed_receipts else {}
    latest_aborted = aborted_receipts[-1] if aborted_receipts else {}
    completed_invocation_id = str((latest_completed.get("details") or {}).get("invocationReceiptId") or "")
    aborted_invocation_id = str((latest_aborted.get("details") or {}).get("invocationReceiptId") or "")
    invocation_ids = {completed_invocation_id, aborted_invocation_id} - {""}
    linked_invocations = [
        receipt
        for receipt in all_receipts
        if receipt.get("kind") == "model_invocation"
        and receipt.get("id") in invocation_ids
        and (receipt.get("details") or {}).get("streamSource") == "provider_native"
    ]
    snapshot = request_json(endpoint, "/api/v1/models")
    snapshot_text = json.dumps(snapshot, sort_keys=True)
    assertions = {
        "streamLifecycleGuiActionRecordedCompletion": len(completed_receipts) > 0,
        "streamLifecycleGuiActionRecordedAbort": len(aborted_receipts) > 0,
        "streamLifecycleCompletionLinkedInvocation": completed_invocation_id in {receipt.get("id") for receipt in linked_invocations},
        "streamLifecycleAbortLinkedInvocation": aborted_invocation_id in {receipt.get("id") for receipt in linked_invocations},
        "streamLifecycleProjectionVisibleToGui": "openai_chat_completions_native_local" in snapshot_text
        and "openai_responses_native_local" in snapshot_text
        and "client_disconnect" in snapshot_text,
        "streamLifecycleLogsScreenshotCaptured": all(item.get("screenshot") and not item.get("capture_error") for item in action_screenshots),
    }
    return {
        "passed": all(assertions.values()),
        "assertions": assertions,
        "completedStreamReceiptId": latest_completed.get("id"),
        "abortedStreamReceiptId": latest_aborted.get("id"),
        "completedInvocationReceiptId": completed_invocation_id,
        "abortedInvocationReceiptId": aborted_invocation_id,
        "observedReceiptIds": [receipt.get("id") for receipt in receipts[before_count:]],
        "screenshots": action_screenshots,
    }


def exercise_provider_backend_actions(
    window_id: int,
    output_root: Path,
    dev_url: str,
    endpoint: str,
) -> dict[str, Any]:
    """Exercise backend and provider controls through the live Mounts desktop surface."""

    backend_id = "backend.autopilot.native-local.fixture"
    provider_id = "provider.autopilot.local"
    action_screenshots: list[dict[str, Any]] = []

    activate_tab(window_id, "F2")
    for shortcut, label, tab, condition_label, predicate in [
        (
            "shift+F1",
            "backends-after-health-action",
            "backends",
            "backend health receipt",
            lambda receipts: receipt_has_operation_detail(receipts, "backend_health", "backendId", backend_id),
        ),
        (
            "shift+F2",
            "backends-after-start-action",
            "backends",
            "backend start receipt",
            lambda receipts: receipt_has_operation_detail(receipts, "backend_start", "backendId", backend_id),
        ),
        (
            "shift+F3",
            "backends-after-logs-action",
            "backends",
            "backend logs receipt",
            lambda receipts: receipt_has_operation_detail(receipts, "backend_logs_read", "backendId", backend_id),
        ),
        (
            "shift+F4",
            "backends-after-stop-action",
            "backends",
            "backend stop receipt",
            lambda receipts: receipt_has_operation_detail(receipts, "backend_stop", "backendId", backend_id),
        ),
    ]:
        press_action_shortcut(window_id, shortcut)
        wait_for_receipt_condition(endpoint, condition_label, predicate)
        action_screenshots.append(
            capture_action_state(
                window_id,
                output_root,
                dev_url,
                endpoint,
                tab=tab,
                name=label,
            )
        )
        time.sleep(1.5)

    activate_tab(window_id, "F4")
    for shortcut, label, condition_label, predicate in [
        (
            "shift+F5",
            "providers-after-health-action",
            "provider health receipt",
            lambda receipts: receipt_has_detail(receipts, "provider_health", "providerId", provider_id),
        ),
        (
            "shift+F6",
            "providers-after-models-action",
            "provider models receipt",
            lambda receipts: receipt_has_operation_detail(receipts, "provider_models_list", "providerId", provider_id),
        ),
        (
            "shift+F7",
            "providers-after-loaded-action",
            "provider loaded receipt",
            lambda receipts: receipt_has_operation_detail(receipts, "provider_loaded_list", "providerId", provider_id),
        ),
        (
            "shift+F8",
            "providers-after-start-action",
            "provider start receipt",
            lambda receipts: receipt_has_operation_detail(receipts, "provider_start", "providerId", provider_id),
        ),
        (
            "shift+F9",
            "providers-after-stop-action",
            "provider stop receipt",
            lambda receipts: receipt_has_operation_detail(receipts, "provider_stop", "providerId", provider_id),
        ),
    ]:
        press_action_shortcut(window_id, shortcut)
        wait_for_receipt_condition(endpoint, condition_label, predicate)
        action_screenshots.append(
            capture_action_state(
                window_id,
                output_root,
                dev_url,
                endpoint,
                tab="providers",
                name=label,
            )
        )
        time.sleep(1.5)

    snapshot = request_json(endpoint, "/api/v1/models")
    receipts = request_json(endpoint, "/api/v1/receipts")
    backend = next((item for item in snapshot.get("backends", []) if item.get("id") == backend_id), None)
    provider = next((item for item in snapshot.get("providers", []) if item.get("id") == provider_id), None)
    provider_artifacts = [
        item for item in snapshot.get("artifacts", [])
        if item.get("providerId") == provider_id
    ]
    assertions = {
        "backendHealthReceiptRecorded": receipt_has_operation_detail(receipts, "backend_health", "backendId", backend_id),
        "backendStartReceiptRecorded": receipt_has_operation_detail(receipts, "backend_start", "backendId", backend_id),
        "backendLogsReceiptRecorded": receipt_has_operation_detail(receipts, "backend_logs_read", "backendId", backend_id),
        "backendStopReceiptRecorded": receipt_has_operation_detail(receipts, "backend_stop", "backendId", backend_id),
        "backendStartLogRecorded": backend_logs_include(endpoint, backend_id, "backend_start"),
        "backendStopLogRecorded": backend_logs_include(endpoint, backend_id, "backend_stop"),
        "backendProjectionUpdated": bool(backend and backend.get("lastReceiptId")),
        "providerHealthReceiptRecorded": receipt_has_detail(receipts, "provider_health", "providerId", provider_id),
        "providerModelsReceiptRecorded": receipt_has_operation_detail(receipts, "provider_models_list", "providerId", provider_id),
        "providerLoadedReceiptRecorded": receipt_has_operation_detail(receipts, "provider_loaded_list", "providerId", provider_id),
        "providerStartReceiptRecorded": receipt_has_operation_detail(receipts, "provider_start", "providerId", provider_id),
        "providerStopReceiptRecorded": receipt_has_operation_detail(receipts, "provider_stop", "providerId", provider_id),
        "providerProjectionUpdated": bool(provider and provider.get("status")),
        "providerArtifactsVisible": len(provider_artifacts) >= 1,
        "actionScreenshotsCaptured": all(item.get("screenshot") and not item.get("capture_error") for item in action_screenshots),
    }
    return {
        "passed": all(assertions.values()),
        "assertions": assertions,
        "backendId": backend_id,
        "backendStatus": backend.get("status") if backend else None,
        "providerId": provider_id,
        "providerStatus": provider.get("status") if provider else None,
        "providerArtifactCount": len(provider_artifacts),
        "screenshots": action_screenshots,
    }


def scan_for_plaintext_secrets(state_dir: Path, token: str) -> dict[str, Any]:
    findings: list[str] = []
    needles = [token, "vault://mcp.huggingface/gui-validation"]
    for file_path in state_dir.rglob("*"):
        if not file_path.is_file():
            continue
        with contextlib.suppress(UnicodeDecodeError):
            text = file_path.read_text(encoding="utf-8")
            for needle in needles:
                if needle and needle in text:
                    findings.append(str(file_path))
            if re.search(r"ioi_mnt_[A-Za-z0-9_-]+", text):
                findings.append(str(file_path))
    return {
        "passed": len(findings) == 0,
        "findings": findings,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    parser.add_argument("--window-name", default=WINDOW_SEARCH_PATTERN)
    parser.add_argument("--timeout-secs", type=float, default=WINDOW_WAIT_TIMEOUT_SECS)
    parser.add_argument("--profile", default=f"{DEFAULT_PROFILE}-model-mounts")
    parser.add_argument("--dev-url", default=os.environ.get("AUTOPILOT_DESKTOP_DEV_URL", DEFAULT_WEB_ROOT))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_root = Path(args.output_root).expanduser() / now_stamp()
    output_root.mkdir(parents=True, exist_ok=True)
    desktop_log = output_root / "desktop.log"

    daemon_process: subprocess.Popen[str] | None = None
    desktop_process: subprocess.Popen[str] | None = None
    window_id: int | None = None
    daemon_endpoint: str | None = None
    state_dir: Path | None = None
    seed: dict[str, Any] | None = None
    screenshots: list[dict[str, Any]] = []
    probe_error: str | None = None
    secret_scan: dict[str, Any] | None = None
    seeded_assertions: dict[str, Any] | None = None
    model_lifecycle_action_assertions: dict[str, Any] | None = None
    download_action_assertions: dict[str, Any] | None = None
    token_mcp_action_assertions: dict[str, Any] | None = None
    routing_workflow_action_assertions: dict[str, Any] | None = None
    benchmark_observability_action_assertions: dict[str, Any] | None = None
    stream_lifecycle_action_assertions: dict[str, Any] | None = None
    provider_backend_action_assertions: dict[str, Any] | None = None

    close_matching_windows(args.window_name)
    terminate_existing_desktop_instances()

    try:
        daemon_process, daemon_endpoint, state_dir = start_model_mounting_daemon(output_root)
        seed = seed_model_mounting_state(daemon_endpoint)
        desktop_process = launch_mounts_desktop(args.profile, desktop_log, args.dev_url, daemon_endpoint)
        print("[model-mounts-gui] launched Mounts desktop shell", flush=True)

        window_id = wait_for_window(args.window_name, timeout_secs=args.timeout_secs)
        if window_id is None:
            raise RuntimeError(f"Timed out waiting for a window matching {args.window_name!r}")
        focus_workspace_view(window_id)
        time.sleep(POST_WINDOW_SETTLE_SECS)

        previous_path: Path | None = None
        distinct_transitions = 0
        for tab, shortcut in MOUNT_TABS:
            activate_tab(window_id, shortcut)
            preparation = prepare_tab_for_capture(window_id, tab)
            result = capture_tab(window_id, output_root, args.dev_url, daemon_endpoint, tab)
            result["preparation"] = preparation
            path = Path(result["screenshot"]) if result.get("screenshot") else None
            if previous_path is not None and path is not None:
                result["rmse_vs_previous"] = image_difference_metric(previous_path, path)
                if screenshot_metric_is_distinct(result["rmse_vs_previous"]):
                    distinct_transitions += 1
            if path is not None:
                previous_path = path
            screenshots.append(result)
            print(f"[model-mounts-gui] captured {tab} -> {path.name if path else 'missing'}", flush=True)

        model_lifecycle_action_assertions = exercise_model_lifecycle_actions(
            window_id,
            output_root,
            args.dev_url,
            daemon_endpoint,
        )
        print("[model-mounts-gui] exercised model lifecycle and detail controls", flush=True)
        download_action_assertions = exercise_download_row_actions(
            window_id,
            output_root,
            args.dev_url,
            daemon_endpoint,
            seed,
        )
        print("[model-mounts-gui] exercised download row actions", flush=True)
        token_mcp_action_assertions = exercise_token_mcp_actions(
            window_id,
            output_root,
            args.dev_url,
            daemon_endpoint,
            seed,
        )
        print("[model-mounts-gui] exercised token, vault, and MCP controls", flush=True)
        routing_workflow_action_assertions = exercise_routing_workflow_actions(
            window_id,
            output_root,
            args.dev_url,
            daemon_endpoint,
        )
        print("[model-mounts-gui] exercised routing and workflow controls", flush=True)
        benchmark_observability_action_assertions = exercise_benchmark_observability_actions(
            window_id,
            output_root,
            args.dev_url,
            daemon_endpoint,
        )
        print("[model-mounts-gui] exercised benchmark and observability controls", flush=True)
        stream_lifecycle_action_assertions = exercise_stream_lifecycle_observability_action(
            window_id,
            output_root,
            args.dev_url,
            daemon_endpoint,
        )
        print("[model-mounts-gui] exercised stream lifecycle observability controls", flush=True)
        provider_backend_action_assertions = exercise_provider_backend_actions(
            window_id,
            output_root,
            args.dev_url,
            daemon_endpoint,
        )
        print("[model-mounts-gui] exercised provider and backend controls", flush=True)
        secret_scan = scan_for_plaintext_secrets(state_dir, str(seed.get("token", "")))
        seeded_assertions = seeded_state_assertions(seed, screenshots)
        if any(item.get("capture_error") for item in screenshots):
            raise RuntimeError("One or more Mounts tab screenshots failed.")
        if distinct_transitions < MIN_DISTINCT_TAB_TRANSITIONS:
            raise RuntimeError(
                "Mounts tab screenshots did not show enough distinct desktop states "
                f"({distinct_transitions}/{len(MOUNT_TABS) - 1} transitions changed)."
            )
        if not secret_scan["passed"]:
            raise RuntimeError("Plaintext secret scan failed for model mounting GUI state.")
        if not seeded_assertions["passed"]:
            raise RuntimeError("Seeded Mounts GUI state did not cover catalog, failed, canceled, and receipt surfaces.")
        if not model_lifecycle_action_assertions["passed"]:
            raise RuntimeError("Mounts GUI model lifecycle controls did not update daemon projection and receipts.")
        if not download_action_assertions["passed"]:
            raise RuntimeError("Mounts GUI download row actions did not update daemon projection and receipts.")
        if not token_mcp_action_assertions["passed"]:
            raise RuntimeError("Mounts GUI token/MCP controls did not update daemon projection and receipts.")
        if not routing_workflow_action_assertions["passed"]:
            raise RuntimeError("Mounts GUI routing/workflow controls did not update daemon projection and receipts.")
        if not benchmark_observability_action_assertions["passed"]:
            raise RuntimeError("Mounts GUI benchmark/observability controls did not update daemon projection and receipts.")
        if not stream_lifecycle_action_assertions["passed"]:
            raise RuntimeError("Mounts GUI stream lifecycle observability did not show completed and aborted receipts.")
        if not provider_backend_action_assertions["passed"]:
            raise RuntimeError("Mounts GUI provider/backend controls did not update daemon projection and receipts.")
    except Exception as error:
        probe_error = str(error)
        print(f"[model-mounts-gui] error: {probe_error}", file=sys.stderr, flush=True)
    finally:
        if desktop_process is not None:
            terminate_process_group(desktop_process)
        if daemon_process is not None:
            terminate_process_group(daemon_process)

    bundle = {
        "schemaVersion": "ioi.model-mounts-gui-validation.v1",
        "capturedAt": datetime.now(timezone.utc).isoformat(),
        "windowId": window_id,
        "profile": args.profile,
        "daemonEndpoint": daemon_endpoint,
        "stateDir": str(state_dir) if state_dir else None,
        "seed": {key: value for key, value in (seed or {}).items() if key != "token"},
        "screenshots": screenshots,
        "secretScan": secret_scan,
        "seededStateAssertions": seeded_assertions,
        "modelLifecycleActionAssertions": model_lifecycle_action_assertions,
        "downloadActionAssertions": download_action_assertions,
        "tokenMcpActionAssertions": token_mcp_action_assertions,
        "routingWorkflowActionAssertions": routing_workflow_action_assertions,
        "benchmarkObservabilityActionAssertions": benchmark_observability_action_assertions,
        "streamLifecycleActionAssertions": stream_lifecycle_action_assertions,
        "providerBackendActionAssertions": provider_backend_action_assertions,
        "passed": probe_error is None,
        "probeError": probe_error,
        "desktopLogTail": read_log_tail(desktop_log),
    }
    result_path = output_root / "result.json"
    result_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"[model-mounts-gui] results: {result_path}", flush=True)
    return 0 if probe_error is None else 1


if __name__ == "__main__":
    sys.exit(main())
