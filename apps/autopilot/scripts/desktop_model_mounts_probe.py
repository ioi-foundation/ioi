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
    run(["xdotool", "key", shortcut], check=False)
    time.sleep(TAB_SETTLE_SECS)


def capture_tab(window_id: int, output_root: Path, dev_url: str, daemon_endpoint: str, tab: str) -> dict[str, Any]:
    screenshot_path = output_root / f"mounts-{tab}.png"
    browser_url = (
        f"{dev_url.rstrip('/')}/?view=mounts&mountsTab={urllib.parse.quote(tab)}"
        f"&mountsEndpoint={urllib.parse.quote(daemon_endpoint, safe='')}"
    )
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


def screenshot_metric_is_distinct(metric: str | None) -> bool:
    if not metric:
        return False
    try:
        return float(metric.split()[0]) > 0.0
    except (IndexError, ValueError):
        return False


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
            result = capture_tab(window_id, output_root, args.dev_url, daemon_endpoint, tab)
            path = Path(result["screenshot"]) if result.get("screenshot") else None
            if previous_path is not None and path is not None:
                result["rmse_vs_previous"] = image_difference_metric(previous_path, path)
                if screenshot_metric_is_distinct(result["rmse_vs_previous"]):
                    distinct_transitions += 1
            if path is not None:
                previous_path = path
            screenshots.append(result)
            print(f"[model-mounts-gui] captured {tab} -> {path.name if path else 'missing'}", flush=True)

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
