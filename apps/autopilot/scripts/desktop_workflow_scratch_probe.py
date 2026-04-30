#!/usr/bin/env python3
"""Dogfood Workflows from a blank canvas in the real desktop shell.

This probe is intentionally scratch-first. It launches the desktop app directly
into Workflows, enables the dev-only GUI dogfood bridge, and observes the app as
it creates a blank workflow, authors nodes through the same runtime APIs used by
the canvas, validates, tests, runs, resumes, and saves screenshots plus a gap ledger under
`/tmp/autopilot-heavy-workflows/<timestamp>/`.

The probe uses xdotool because it exercises the same native desktop surface a
user touches. It does not instantiate workflow templates or write workflow JSON
directly; the UI bridge calls typed workflow runtime commands and this probe only
observes screenshots and sidecars. Any missing interaction is recorded as a
product gap instead of being papered over by fixture generation.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from desktop_capture import capture_window_with_fallback
from desktop_workspace_probe import (
    DEFAULT_PROFILE,
    DEFAULT_WEB_ROOT,
    PROJECT_ROOT,
    WINDOW_SEARCH_PATTERN,
    close_matching_windows,
    launch_dev_desktop,
    read_log_tail,
    terminate_existing_desktop_instances,
    terminate_process_group,
    wait_for_window,
)


DEFAULT_OUTPUT_ROOT = Path("/tmp/autopilot-heavy-workflows")
WINDOW_WAIT_TIMEOUT_SECS = 90.0
POST_WINDOW_SETTLE_SECS = 12.0
CLICK_SETTLE_SECS = 0.75
SCRATCH_WORKFLOW_SLUG = "scratch-gui-node-composition"
SCRATCH_WORKFLOW_SLUGS = [
    SCRATCH_WORKFLOW_SLUG,
    "scratch-mcp-research-operator",
    "scratch-connector-triage-agent",
    "scratch-financial-close-assistant",
    "scratch-media-transform-agent",
    "scratch-scheduled-reporter",
    "scratch-self-improving-proposal",
    "scratch-stateful-memory-workflow",
    "scratch-subgraph-orchestration-workflow",
    "scratch-trigger-driven-workflow",
    "scratch-failed-function-resume",
]
SCRATCH_DOGFOOD_ENV = "VITE_AUTOPILOT_WORKFLOW_DOGFOOD_SCRIPT"
SCRATCH_DOGFOOD_ENV_VALUE = "scratch-heavy"
FIXTURE_VALIDATION_STATUSES = {"passed", "failed", "not_declared", "stale"}


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"Command failed ({completed.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def window_geometry(window_id: int) -> dict[str, int]:
    result = run(["xdotool", "getwindowgeometry", "--shell", str(window_id)])
    geometry: dict[str, int] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"X", "Y", "WIDTH", "HEIGHT"} and value.isdigit():
            geometry[key] = int(value)
    missing = {"X", "Y", "WIDTH", "HEIGHT"} - set(geometry)
    if missing:
        raise RuntimeError(f"Could not parse window geometry: missing {sorted(missing)}")
    return geometry


def maximize_window(window_id: int) -> None:
    run(["xdotool", "windowactivate", "--sync", str(window_id)], check=False)
    run(["wmctrl", "-ir", hex(window_id), "-b", "add,maximized_vert,maximized_horz"], check=False)
    time.sleep(0.5)


def click_ratio(window_id: int, x_ratio: float, y_ratio: float) -> dict[str, int]:
    geometry = window_geometry(window_id)
    width = geometry["WIDTH"]
    height = geometry["HEIGHT"]
    rel_x = max(1, min(width - 1, int(width * x_ratio)))
    rel_y = max(1, min(height - 1, int(height * y_ratio)))
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    run(["xdotool", "mousemove", "--window", str(window_id), str(rel_x), str(rel_y)])
    run(["xdotool", "click", "1"], check=False)
    time.sleep(CLICK_SETTLE_SECS)
    return {
        "width": width,
        "height": height,
        "x": rel_x,
        "y": rel_y,
    }


def double_click_ratio(window_id: int, x_ratio: float, y_ratio: float) -> dict[str, int]:
    geometry = window_geometry(window_id)
    width = geometry["WIDTH"]
    height = geometry["HEIGHT"]
    rel_x = max(1, min(width - 1, int(width * x_ratio)))
    rel_y = max(1, min(height - 1, int(height * y_ratio)))
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    run(["xdotool", "mousemove", "--window", str(window_id), str(rel_x), str(rel_y)])
    run(["xdotool", "click", "--repeat", "2", "--delay", "120", "1"], check=False)
    time.sleep(CLICK_SETTLE_SECS)
    return {
        "width": width,
        "height": height,
        "x": rel_x,
        "y": rel_y,
    }


def type_text(window_id: int, text: str) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    run(["xdotool", "type", "--clearmodifiers", text], check=False)
    time.sleep(CLICK_SETTLE_SECS)


def key_sequence(window_id: int, *keys: str) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    for key in keys:
        run(["xdotool", "key", "--clearmodifiers", key], check=False)
        time.sleep(0.12)
    time.sleep(CLICK_SETTLE_SECS)


def replace_text(window_id: int, text: str) -> None:
    key_sequence(window_id, "ctrl+a")
    type_text(window_id, text)


def dismiss_modal(window_id: int) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    run(["xdotool", "key", "Escape"], check=False)
    run(["xdotool", "key", "--clearmodifiers", "Home"], check=False)
    time.sleep(CLICK_SETTLE_SECS)
    click_ratio(window_id, 0.69, 0.13)
    click_ratio(window_id, 0.69, 0.16)


def dismiss_create_workflow_modal(window_id: int) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    run(["xdotool", "key", "Escape"], check=False)
    time.sleep(0.25)
    click_ratio(window_id, 0.69, 0.285)


def capture_step(window_id: int, output_dir: Path, step_id: str) -> Path:
    screenshot = output_dir / f"{step_id}.png"
    capture_window_with_fallback(window_id, screenshot, browser_url=DEFAULT_WEB_ROOT)
    return screenshot


def scratch_output_paths(slug: str = SCRATCH_WORKFLOW_SLUG) -> dict[str, Path]:
    workflow_path = PROJECT_ROOT / ".agents" / "workflows" / f"{slug}.workflow.json"
    return {
        "workflowPath": workflow_path,
        "testsPath": workflow_path.with_name(f"{slug}.tests.json"),
        "runsDir": workflow_path.with_name(f"{slug}.runs"),
        "proposalsDir": workflow_path.with_name(f"{slug}.proposals"),
        "evidencePath": workflow_path.with_name(f"{slug}.evidence.json"),
        "bindingsPath": workflow_path.with_name(f"{slug}.bindings.json"),
        "fixturesPath": workflow_path.with_name(f"{slug}.fixtures.json"),
        "checkpointsDir": workflow_path.with_name(f"{slug}.checkpoints"),
        "interruptsDir": workflow_path.with_name(f"{slug}.interrupts"),
        "packageDir": workflow_path.with_name(f"{slug}.portable"),
    }


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def is_fresh(path: Path, started_at: float) -> bool:
    return path.exists() and path.stat().st_mtime >= started_at - 2.0


def latest_json_files(path: Path) -> list[Path]:
    if not path.exists() or not path.is_dir():
        return []
    return sorted(path.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)


def collect_sidecar_summary(started_at: float, slug: str = SCRATCH_WORKFLOW_SLUG) -> dict[str, Any]:
    paths = scratch_output_paths(slug)
    summary: dict[str, Any] = {"slug": slug}
    summary.update({key: str(value) for key, value in paths.items()})
    workflow_path = paths["workflowPath"]
    tests_path = paths["testsPath"]
    runs_dir = paths["runsDir"]
    proposals_dir = paths["proposalsDir"]
    evidence_path = paths["evidencePath"]
    bindings_path = paths["bindingsPath"]
    fixtures_path = paths["fixturesPath"]
    checkpoints_dir = paths["checkpointsDir"]
    package_dir = paths["packageDir"]

    if workflow_path.exists():
        workflow = read_json(workflow_path)
        summary["workflowFresh"] = is_fresh(workflow_path, started_at)
        summary["workflowNodeIds"] = [
            node.get("id")
            for node in workflow.get("nodes", [])
            if isinstance(node, dict)
        ]
        summary["workflowEdgeCount"] = len(workflow.get("edges", []))
        summary["workflowTemplateId"] = workflow.get("metadata", {}).get("templateId")
    if tests_path.exists():
        tests = read_json(tests_path)
        summary["testsFresh"] = is_fresh(tests_path, started_at)
        summary["testIds"] = [
            test.get("id")
            for test in tests
            if isinstance(test, dict)
        ]
    run_files = latest_json_files(runs_dir)
    if run_files:
        fresh_run_files = [path for path in run_files if is_fresh(path, started_at)]
        summary["runFiles"] = [str(path) for path in run_files[:5]]
        summary["freshRunFiles"] = [str(path) for path in fresh_run_files[:5]]
        runs = []
        for path in fresh_run_files[:5]:
            with contextlib.suppress(Exception):
                run = read_json(path)
                node_runs = [
                    node_run
                    for node_run in run.get("nodeRuns", [])
                    if isinstance(node_run, dict)
                ]
                runs.append(
                    {
                        "path": str(path),
                        "status": run.get("summary", {}).get("status"),
                        "nodeRunCount": len(node_runs),
                        "inputCapturedCount": len(
                            [node_run for node_run in node_runs if "input" in node_run]
                        ),
                        "outputCapturedCount": len(
                            [node_run for node_run in node_runs if "output" in node_run]
                        ),
                        "eventCount": len(run.get("events", [])),
                        "errorNodeIds": [
                            node_run.get("nodeId")
                            for node_run in node_runs
                            if node_run.get("status") in {"error", "blocked", "failed"}
                        ],
                        "successNodeIds": [
                            node_run.get("nodeId")
                            for node_run in node_runs
                            if node_run.get("status") == "success"
                        ],
                    }
                )
        summary["freshRuns"] = runs
    if checkpoints_dir.exists():
        checkpoint_files = sorted(
            checkpoints_dir.glob("*/*.json"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        fresh_checkpoint_files = [
            path for path in checkpoint_files if is_fresh(path, started_at)
        ]
        summary["freshCheckpointFiles"] = [
            str(path) for path in fresh_checkpoint_files[:8]
        ]
        summary["freshCheckpointCount"] = len(fresh_checkpoint_files)
    fresh_runs = summary.get("freshRuns", [])
    summary["checkpointResumePassed"] = bool(
        fresh_runs
        and any(
            run.get("status") == "failed"
            and "resume-function" in set(run.get("errorNodeIds", []))
            for run in fresh_runs
            if isinstance(run, dict)
        )
        and any(
            run.get("status") == "passed"
            and "resume-function" in set(run.get("successNodeIds", []))
            for run in fresh_runs
            if isinstance(run, dict)
        )
        and summary.get("freshCheckpointCount", 0) > 0
    )
    proposal_files = latest_json_files(proposals_dir)
    if proposal_files:
        fresh_proposal_files = [path for path in proposal_files if is_fresh(path, started_at)]
        summary["proposalFiles"] = [str(path) for path in proposal_files[:5]]
        summary["freshProposalFiles"] = [str(path) for path in fresh_proposal_files[:5]]
    if evidence_path.exists():
        with contextlib.suppress(Exception):
            evidence = read_json(evidence_path)
            summary["evidenceFresh"] = is_fresh(evidence_path, started_at)
            summary["evidenceKinds"] = [
                entry.get("kind")
                for entry in evidence
                if isinstance(entry, dict)
            ][:10]
    if bindings_path.exists():
        with contextlib.suppress(Exception):
            manifest = read_json(bindings_path)
            summary["bindingManifestFresh"] = is_fresh(bindings_path, started_at)
            summary["bindingManifestSummary"] = manifest.get("summary")
            summary["bindingManifestModes"] = sorted(
                {
                    entry.get("mode")
                    for entry in manifest.get("bindings", [])
                    if isinstance(entry, dict)
                }
            )
    if fixtures_path.exists():
        with contextlib.suppress(Exception):
            fixtures = read_json(fixtures_path)
            fresh_fixtures = [
                fixture
                for fixture in fixtures
                if isinstance(fixture, dict)
                and fixture.get("createdAtMs", 0) / 1000 >= started_at - 5.0
            ]
            summary["fixturesFresh"] = is_fresh(fixtures_path, started_at)
            summary["fixtureCount"] = len(fixtures)
            summary["freshFixtureCount"] = len(fresh_fixtures)
            summary["freshFixtureInputCount"] = len(
                [fixture for fixture in fresh_fixtures if "input" in fixture]
            )
            summary["freshFixturePinnedCount"] = len(
                [fixture for fixture in fresh_fixtures if fixture.get("pinned") is True]
            )
            summary["fixtureValidationStatuses"] = sorted(
                {
                    fixture.get("validationStatus")
                    for fixture in fresh_fixtures
                    if fixture.get("validationStatus") in FIXTURE_VALIDATION_STATUSES
                }
            )
    package_manifest = package_dir / "manifest.json"
    if package_manifest.exists():
        with contextlib.suppress(Exception):
            manifest = read_json(package_manifest)
            summary["packageFresh"] = is_fresh(package_manifest, started_at)
            summary["packagePortable"] = manifest.get("portable")
            summary["packageReadinessStatus"] = manifest.get("readinessStatus")
            summary["packageFileCount"] = len(manifest.get("files", []))
    return summary


def wait_for_dogfood_sidecars(started_at: float, timeout_secs: float) -> dict[str, Any]:
    deadline = time.time() + timeout_secs
    required_nodes = {
        "scratch-source",
        "scratch-function",
        "scratch-model-binding",
        "scratch-model",
        "scratch-parser",
        "scratch-assertion",
        "scratch-gate",
        "scratch-output",
    }
    last_summary: dict[str, Any] = {}
    while time.time() < deadline:
        last_summary = collect_sidecar_summary(started_at)
        suite_summaries = {
            slug: collect_sidecar_summary(started_at, slug)
            for slug in SCRATCH_WORKFLOW_SLUGS
        }
        suite_ready = all(
            summary.get("workflowFresh")
            and summary.get("bindingManifestFresh")
            and summary.get("fixtureValidationStatuses")
            and summary.get("freshFixtureInputCount", 0) > 0
            and "passed" in {
                run.get("status")
                for run in summary.get("freshRuns", [])
                if isinstance(run, dict)
            }
            and any(
                run.get("inputCapturedCount", 0) > 0
                for run in summary.get("freshRuns", [])
                if isinstance(run, dict)
            )
            and summary.get("freshProposalFiles")
            for summary in suite_summaries.values()
        )
        node_ids = set(last_summary.get("workflowNodeIds", []))
        fresh_runs = last_summary.get("freshRuns", [])
        run_statuses = {run.get("status") for run in fresh_runs if isinstance(run, dict)}
        single_ready = (
            last_summary.get("workflowFresh")
            and last_summary.get("testsFresh")
            and last_summary.get("bindingManifestFresh")
            and last_summary.get("fixtureValidationStatuses")
            and last_summary.get("freshFixtureInputCount", 0) > 0
            and required_nodes.issubset(node_ids)
            and "passed" in run_statuses
            and any(
                run.get("inputCapturedCount", 0) > 0
                for run in fresh_runs
                if isinstance(run, dict)
            )
            and last_summary.get("freshProposalFiles")
        )
        if suite_ready or (SCRATCH_DOGFOOD_ENV_VALUE != "scratch-heavy" and single_ready):
            return {**last_summary, "suite": suite_summaries, "ready": True}
        time.sleep(1.0)
    return {**last_summary, "suite": {
        slug: collect_sidecar_summary(started_at, slug)
        for slug in SCRATCH_WORKFLOW_SLUGS
    }, "ready": False}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--dev-url", default=DEFAULT_WEB_ROOT)
    parser.add_argument("--window-name", default=WINDOW_SEARCH_PATTERN)
    parser.add_argument("--timeout-secs", type=float, default=WINDOW_WAIT_TIMEOUT_SECS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_root).expanduser() / now_stamp()
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / "desktop.log"
    gap_ledger: list[dict[str, Any]] = []
    screenshots: list[str] = []
    started_at = time.time()
    previous_dogfood_env = os.environ.get(SCRATCH_DOGFOOD_ENV)
    os.environ[SCRATCH_DOGFOOD_ENV] = SCRATCH_DOGFOOD_ENV_VALUE

    close_matching_windows(args.window_name)
    terminate_existing_desktop_instances()
    process = launch_dev_desktop(
        args.profile,
        log_path,
        args.dev_url,
        initial_view="workflows",
    )
    print(f"[workflow-scratch] launched desktop shell, evidence={output_dir}", flush=True)

    window_id: int | None = None
    try:
        window_id = wait_for_window(args.window_name, timeout_secs=args.timeout_secs)
        if window_id is None:
            raise RuntimeError(f"Timed out waiting for window {args.window_name!r}")
        maximize_window(window_id)
        time.sleep(POST_WINDOW_SETTLE_SECS)
        screenshots.append(str(capture_step(window_id, output_dir, "00-shell-initial")))

        # Initial-view env is a useful hint, but the product-safe path still
        # touches the visible Workflows activity-bar item before observing.
        click_ratio(window_id, 0.012, 0.205)
        screenshots.append(str(capture_step(window_id, output_dir, "01-workflows-open")))

        # Capture the primary creation path as a blank-canvas flow. The probe
        # does not submit this modal; the dogfood bridge below still authors
        # workflows from primitive canvas nodes through typed runtime commands.
        click_ratio(window_id, 0.79, 0.072)
        screenshots.append(str(capture_step(window_id, output_dir, "01b-create-blank-workflow-modal")))
        dismiss_create_workflow_modal(window_id)

        screenshots.append(str(capture_step(window_id, output_dir, "02-dogfood-running")))
        sidecars = wait_for_dogfood_sidecars(started_at, args.timeout_secs)
        (output_dir / "sidecar-summary.json").write_text(
            json.dumps(sidecars, indent=2),
            encoding="utf-8",
        )
        screenshots.append(str(capture_step(window_id, output_dir, "03-dogfood-complete")))

        dismiss_modal(window_id)
        click_ratio(window_id, 0.685, 0.176)
        type_text(window_id, "output")
        screenshots.append(str(capture_step(window_id, output_dir, "04-canvas-search-output")))

        double_click_ratio(window_id, 0.705, 0.36)
        screenshots.append(str(capture_step(window_id, output_dir, "05-canvas-search-configure")))
        click_ratio(window_id, 0.407, 0.187)
        screenshots.append(str(capture_step(window_id, output_dir, "05a-node-input-preview")))
        click_ratio(window_id, 0.496, 0.187)
        screenshots.append(str(capture_step(window_id, output_dir, "05b-output-bindings-editor")))

        dismiss_modal(window_id)
        key_sequence(window_id, "Escape")
        click_ratio(window_id, 0.248, 0.72)
        click_ratio(window_id, 0.225, 0.765)
        click_ratio(window_id, 0.535, 0.176)
        screenshots.append(str(capture_step(window_id, output_dir, "05c-fixture-replay-shelf")))

        click_ratio(window_id, 0.052, 0.18)
        type_text(window_id, "function")
        screenshots.append(str(capture_step(window_id, output_dir, "06-compatible-node-picker")))

        click_ratio(window_id, 0.136, 0.18)
        click_ratio(window_id, 0.989, 0.43)
        screenshots.append(str(capture_step(window_id, output_dir, "07-readiness-actions")))

        if not sidecars.get("ready"):
            gap_ledger.append(
                {
                    "id": "scratch-gui-sidecars-incomplete",
                    "workflowId": SCRATCH_WORKFLOW_SLUG,
                    "severity": "blocking",
                    "area": "gui-runtime",
                    "summary": "Scratch dogfood bridge did not produce a fresh passed run, proposal, and the expected scratch-authored nodes.",
                    "details": sidecars,
                    "status": "open",
                }
            )
        else:
            gap_ledger.append(
                {
                    "id": "scratch-heavy-gui-runtime-closed",
                    "workflowId": "scratch-heavy-suite",
                    "severity": "info",
                    "area": "gui-runtime",
                    "summary": "Scratch-heavy workflow suite was authored from primitive canvas nodes, validated, tested, run, resumed where needed, proposed, and persisted through typed workflow runtime APIs.",
                    "details": sidecars,
                    "status": "closed",
                }
            )
    except Exception as error:  # noqa: BLE001 - probe must retain evidence on failure.
        gap_ledger.append(
            {
                "id": "scratch-gui-probe-failure",
                "workflowId": SCRATCH_WORKFLOW_SLUG,
                "severity": "blocking",
                "area": "gui",
                "summary": str(error),
                "status": "open",
            }
        )
        if window_id is not None:
            with contextlib.suppress(Exception):
                screenshots.append(str(capture_step(window_id, output_dir, "error-state")))
    finally:
        receipt = {
            "outputDir": str(output_dir),
            "screenshots": screenshots,
            "gapLedgerPath": str(output_dir / "gap-ledger.json"),
            "sidecarSummaryPath": str(output_dir / "sidecar-summary.json"),
            "dogfoodEnv": {SCRATCH_DOGFOOD_ENV: SCRATCH_DOGFOOD_ENV_VALUE},
            "logTail": read_log_tail(log_path),
        }
        (output_dir / "gap-ledger.json").write_text(
            json.dumps(gap_ledger, indent=2),
            encoding="utf-8",
        )
        (output_dir / "scratch-probe-receipt.json").write_text(
            json.dumps(receipt, indent=2),
            encoding="utf-8",
        )
        terminate_process_group(process)
        if previous_dogfood_env is None:
            os.environ.pop(SCRATCH_DOGFOOD_ENV, None)
        else:
            os.environ[SCRATCH_DOGFOOD_ENV] = previous_dogfood_env

    print(json.dumps({"outputDir": str(output_dir), "gapLedger": gap_ledger}, indent=2))
    return 1 if any(entry["status"] == "open" for entry in gap_ledger) else 0


if __name__ == "__main__":
    raise SystemExit(main())
