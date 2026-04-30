#!/usr/bin/env python3
"""Exercise Workflow authoring through visible desktop GUI controls only.

This probe launches the native Autopilot shell in Workflows, creates blank
workflows, and uses visible start cards, port-local add-next affordances, node
configuration surfaces, run controls, and save/reload controls. It does not call
workflow runtime APIs directly and it does not write workflow JSON. When a GUI
step cannot be completed robustly, the probe records a gap instead of faking the
state through sidecar edits.
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


DEFAULT_OUTPUT_ROOT = Path("/tmp/autopilot-workflow-usability")
WINDOW_WAIT_TIMEOUT_SECS = 90.0
SETTLE_SECS = 0.65
POST_WINDOW_SETTLE_SECS = 8.0


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


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


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
    run(
        ["wmctrl", "-ir", hex(window_id), "-b", "add,maximized_vert,maximized_horz"],
        check=False,
    )
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
    time.sleep(SETTLE_SECS)
    return {"width": width, "height": height, "x": rel_x, "y": rel_y}


def double_click_ratio(window_id: int, x_ratio: float, y_ratio: float) -> dict[str, int]:
    geometry = window_geometry(window_id)
    width = geometry["WIDTH"]
    height = geometry["HEIGHT"]
    rel_x = max(1, min(width - 1, int(width * x_ratio)))
    rel_y = max(1, min(height - 1, int(height * y_ratio)))
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    run(["xdotool", "mousemove", "--window", str(window_id), str(rel_x), str(rel_y)])
    run(["xdotool", "click", "--repeat", "2", "--delay", "100", "1"], check=False)
    time.sleep(SETTLE_SECS)
    return {"width": width, "height": height, "x": rel_x, "y": rel_y}


def key_sequence(window_id: int, *keys: str) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    for key in keys:
        run(["xdotool", "key", "--clearmodifiers", key], check=False)
        time.sleep(0.12)
    time.sleep(SETTLE_SECS)


def type_text(window_id: int, text: str) -> None:
    run(["xdotool", "windowactivate", str(window_id)], check=False)
    run(["xdotool", "type", "--clearmodifiers", text], check=False)
    time.sleep(SETTLE_SECS)


def replace_text(window_id: int, text: str) -> None:
    key_sequence(window_id, "ctrl+a")
    type_text(window_id, text)


def capture_step(window_id: int, output_dir: Path, step_id: str) -> str:
    screenshot = output_dir / f"{step_id}.png"
    capture_window_with_fallback(window_id, screenshot, browser_url=DEFAULT_WEB_ROOT)
    return str(screenshot)


def workflow_paths(slug: str) -> dict[str, str]:
    workflow_path = PROJECT_ROOT / ".agents" / "workflows" / f"{slug}.workflow.json"
    return {
        "workflow": str(workflow_path),
        "tests": str(workflow_path.with_name(f"{slug}.tests.json")),
        "fixtures": str(workflow_path.with_name(f"{slug}.fixtures.json")),
        "runs": str(workflow_path.with_name(f"{slug}.runs")),
        "checkpoints": str(workflow_path.with_name(f"{slug}.checkpoints")),
        "evidence": str(workflow_path.with_name(f"{slug}.evidence.json")),
    }


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def collect_workflow_sidecars(slug: str, started_at: float) -> dict[str, Any]:
    paths = {key: Path(value) for key, value in workflow_paths(slug).items()}
    summary: dict[str, Any] = {
        "slug": slug,
        "paths": {key: str(value) for key, value in paths.items()},
    }
    workflow_path = paths["workflow"]
    if workflow_path.exists():
        with contextlib.suppress(Exception):
            workflow = read_json(workflow_path)
            summary["workflowFresh"] = workflow_path.stat().st_mtime >= started_at - 2.0
            summary["nodeTypes"] = [
                node.get("type") for node in workflow.get("nodes", []) if isinstance(node, dict)
            ]
            summary["nodeIds"] = [
                node.get("id") for node in workflow.get("nodes", []) if isinstance(node, dict)
            ]
            summary["edgeCount"] = len(workflow.get("edges", []))
            summary["containsLegacyArtifactNode"] = any(
                node.get("type") == "artifact"
                for node in workflow.get("nodes", [])
                if isinstance(node, dict)
            )
    fixtures_path = paths["fixtures"]
    if fixtures_path.exists():
        with contextlib.suppress(Exception):
            fixtures = read_json(fixtures_path)
            summary["fixtureCount"] = len(fixtures) if isinstance(fixtures, list) else 0
    runs_dir = paths["runs"]
    if runs_dir.exists():
        run_files = sorted(runs_dir.glob("*.json"), key=lambda item: item.stat().st_mtime)
        fresh_runs = [path for path in run_files if path.stat().st_mtime >= started_at - 2.0]
        summary["runFiles"] = [str(path) for path in fresh_runs[-5:]]
        summaries: list[dict[str, Any]] = []
        for path in fresh_runs[-5:]:
            with contextlib.suppress(Exception):
                run = read_json(path)
                node_runs = [
                    item for item in run.get("nodeRuns", []) if isinstance(item, dict)
                ]
                summaries.append(
                    {
                        "path": str(path),
                        "status": run.get("summary", {}).get("status"),
                        "nodeRunCount": len(node_runs),
                        "eventCount": len(run.get("events", [])),
                    }
                )
        summary["runs"] = summaries
    return summary


def open_new_blank_workflow(window_id: int, name: str) -> None:
    click_ratio(window_id, 0.752, 0.074)
    click_ratio(window_id, 0.50, 0.369)
    replace_text(window_id, name)
    click_ratio(window_id, 0.355, 0.739)
    time.sleep(1.2)


def close_dialog(window_id: int) -> None:
    click_ratio(window_id, 0.69, 0.157)
    key_sequence(window_id, "Escape")
    time.sleep(0.2)


def choose_empty_start(window_id: int, card_index: int) -> dict[str, int]:
    # Cards are laid out around the center of the graph surface. The probe keeps
    # the coordinates visible and records screenshots for every click.
    fixed_cards = {
        1: (0.425, 0.35),  # Manual input
        4: (0.425, 0.435),  # Chat trigger
    }
    if card_index in fixed_cards:
        return click_ratio(window_id, *fixed_cards[card_index])
    row = card_index // 3
    col = card_index % 3
    return click_ratio(window_id, 0.30 + (col * 0.126), 0.35 + (row * 0.08))


def open_add_picker_from_selected_node(window_id: int) -> None:
    # Prefer the port-local affordance by hovering/clicking the likely output
    # handle area. Selected nodes expose a visible plus beside typed ports.
    click_ratio(window_id, 0.459, 0.402)


def open_add_picker_from_chat_trigger_port(window_id: int) -> None:
    # Chat trigger starts centered in the second exercise. Use its visible
    # output port so the first downstream node is truly port-local.
    click_ratio(window_id, 0.48, 0.355)


def open_global_add_picker(window_id: int) -> None:
    # The Add control keeps compatible actions scoped to the selected node while
    # avoiding fragile clicks near the minimap or right rail.
    click_ratio(window_id, 0.047, 0.178)


def select_canvas_node(window_id: int, x_ratio: float, y_ratio: float) -> None:
    click_ratio(window_id, x_ratio, y_ratio)


def search_creator(window_id: int, query: str) -> None:
    click_ratio(window_id, 0.09, 0.205)
    replace_text(window_id, query)


def click_first_creator_result(window_id: int, *, compact: bool = False) -> None:
    # The creator drawer places result cards below the search and group chips.
    # Keep this click on the first visible card rather than the drawer chrome.
    click_ratio(window_id, 0.10, 0.45)


def exercise_manual_function_output(
    window_id: int,
    output_dir: Path,
    screenshots: list[str],
    gaps: list[dict[str, Any]],
) -> None:
    open_new_blank_workflow(window_id, "Usability primitive workflow")
    screenshots.append(capture_step(window_id, output_dir, "00-blank-workflow-start-overlay"))

    choose_empty_start(window_id, 1)
    screenshots.append(capture_step(window_id, output_dir, "01-first-step-manual-input"))
    close_dialog(window_id)

    open_add_picker_from_selected_node(window_id)
    screenshots.append(capture_step(window_id, output_dir, "02-port-local-add-next-picker"))
    search_creator(window_id, "javascript")
    screenshots.append(capture_step(window_id, output_dir, "03-action-variant-javascript-function"))
    click_first_creator_result(window_id)
    screenshots.append(capture_step(window_id, output_dir, "04-function-input-config-output-workbench"))

    # Exercise the workbench quick action instead of calling runtime APIs.
    click_ratio(window_id, 0.64, 0.38)
    screenshots.append(capture_step(window_id, output_dir, "05-function-dry-run-from-fixture"))
    close_dialog(window_id)

    select_canvas_node(window_id, 0.70, 0.42)
    open_global_add_picker(window_id)
    search_creator(window_id, "inline output")
    screenshots.append(capture_step(window_id, output_dir, "06-output-action-variant-selection"))
    click_first_creator_result(window_id)
    screenshots.append(capture_step(window_id, output_dir, "07-output-config-surface"))
    close_dialog(window_id)

    click_ratio(window_id, 0.905, 0.073)
    screenshots.append(capture_step(window_id, output_dir, "08-run-workflow"))
    time.sleep(1.5)
    screenshots.append(capture_step(window_id, output_dir, "09-successful-run-output"))
    click_ratio(window_id, 0.977, 0.073)
    screenshots.append(capture_step(window_id, output_dir, "10-saved-workflow"))

    summary = collect_workflow_sidecars("usability-primitive-workflow", time.time() - 600)
    if not summary.get("workflowFresh"):
        gaps.append(
            {
                "exercise": "A",
                "severity": "high",
                "finding": "Visible create/save path did not produce a fresh workflow sidecar.",
                "expected": "Blank workflow should save from the GUI without direct API calls.",
                "sidecarSummary": summary,
            }
        )


def exercise_chat_tool_decision(
    window_id: int,
    output_dir: Path,
    screenshots: list[str],
    gaps: list[dict[str, Any]],
) -> None:
    open_new_blank_workflow(window_id, "Usability branch workflow")
    screenshots.append(capture_step(window_id, output_dir, "11-second-blank-workflow"))

    choose_empty_start(window_id, 4)
    screenshots.append(capture_step(window_id, output_dir, "12-chat-trigger-first-step"))
    close_dialog(window_id)

    select_canvas_node(window_id, 0.425, 0.355)
    open_global_add_picker(window_id)
    search_creator(window_id, "model call")
    screenshots.append(capture_step(window_id, output_dir, "13-model-call-add-next"))
    click_first_creator_result(window_id, compact=True)
    screenshots.append(capture_step(window_id, output_dir, "14-model-config-blocker"))
    close_dialog(window_id)

    select_canvas_node(window_id, 0.70, 0.42)
    open_global_add_picker(window_id)
    search_creator(window_id, "mcp")
    screenshots.append(capture_step(window_id, output_dir, "15-plugin-tool-attachment-picker"))
    click_first_creator_result(window_id, compact=True)
    screenshots.append(capture_step(window_id, output_dir, "16-tool-binding-blocker"))
    close_dialog(window_id)

    open_global_add_picker(window_id)
    search_creator(window_id, "decision")
    screenshots.append(capture_step(window_id, output_dir, "17-decision-add-next"))
    click_first_creator_result(window_id, compact=True)
    screenshots.append(capture_step(window_id, output_dir, "18-second-workflow-validation-blockers"))

    click_ratio(window_id, 0.84, 0.073)
    screenshots.append(capture_step(window_id, output_dir, "19-readiness-blocker-repair-action"))
    close_dialog(window_id)
    click_ratio(window_id, 0.977, 0.073)
    screenshots.append(capture_step(window_id, output_dir, "20-second-workflow-saved"))
    summary = collect_workflow_sidecars("usability-branch-workflow", time.time() - 600)
    if not summary.get("workflowFresh"):
        gaps.append(
            {
                "exercise": "B",
                "severity": "medium",
                "finding": "Second scratch workflow was not saved during GUI usability probing.",
                "expected": "Branching model/tool/decision workflow should be savable even when readiness blocks live execution.",
                "sidecarSummary": summary,
            }
        )


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
    screenshots: list[str] = []
    gaps: list[dict[str, Any]] = []
    started_at = time.time()

    close_matching_windows(args.window_name)
    terminate_existing_desktop_instances()
    process = launch_dev_desktop(
        args.profile,
        log_path,
        args.dev_url,
        initial_view="workflows",
    )
    print(f"[workflow-usability] launched desktop shell, evidence={output_dir}", flush=True)

    window_id: int | None = None
    try:
        window_id = wait_for_window(args.window_name, timeout_secs=args.timeout_secs)
        if window_id is None:
            raise RuntimeError(f"Timed out waiting for window {args.window_name!r}")
        maximize_window(window_id)
        time.sleep(POST_WINDOW_SETTLE_SECS)
        screenshots.append(capture_step(window_id, output_dir, "00-shell-workflows"))

        click_ratio(window_id, 0.012, 0.205)
        screenshots.append(capture_step(window_id, output_dir, "00a-workflows-activity-open"))

        exercise_manual_function_output(window_id, output_dir, screenshots, gaps)
        exercise_chat_tool_decision(window_id, output_dir, screenshots, gaps)

        sidecars = {
            "exerciseA": collect_workflow_sidecars(
                "usability-primitive-workflow",
                started_at,
            ),
            "exerciseB": collect_workflow_sidecars(
                "usability-branch-workflow",
                started_at,
            ),
        }
        exercise_a_types = set(sidecars["exerciseA"].get("nodeTypes", []))
        if not {"source", "function", "output"}.issubset(exercise_a_types):
            gaps.append(
                {
                    "exercise": "A",
                    "severity": "high",
                    "finding": "Manual input -> function -> output graph was not present after visible GUI composition.",
                    "expectedNodeTypes": ["source", "function", "output"],
                    "sidecarSummary": sidecars["exerciseA"],
                }
            )
        if int(sidecars["exerciseA"].get("edgeCount", 0)) < 2:
            gaps.append(
                {
                    "exercise": "A",
                    "severity": "high",
                    "finding": "Manual input -> function -> output graph did not persist connected edges.",
                    "expected": "At least two typed edges from the port-local add-next flow.",
                    "sidecarSummary": sidecars["exerciseA"],
                }
            )
        exercise_b_types = set(sidecars["exerciseB"].get("nodeTypes", []))
        if not {"trigger", "model_call", "plugin_tool", "decision"}.issubset(
            exercise_b_types,
        ):
            gaps.append(
                {
                    "exercise": "B",
                    "severity": "medium",
                    "finding": "Chat trigger -> model -> tool -> decision graph was not present after visible GUI composition.",
                    "expectedNodeTypes": ["trigger", "model_call", "plugin_tool", "decision"],
                    "sidecarSummary": sidecars["exerciseB"],
                }
            )
        write_json(output_dir / "sidecar-summary.json", sidecars)
        write_json(output_dir / "gap-ledger.json", gaps)
        write_json(
            output_dir / "usability-probe-result.json",
            {
                "status": "passed" if not gaps else "gaps-recorded",
                "startedAt": started_at,
                "screenshots": screenshots,
                "gapCount": len(gaps),
                "sidecars": sidecars,
                "desktopLogTail": read_log_tail(log_path),
            },
        )
        print(f"[workflow-usability] evidence={output_dir}", flush=True)
        return 0 if not gaps else 2
    except Exception as exc:
        gap = {
            "exercise": "probe",
            "severity": "blocker",
            "finding": str(exc),
            "desktopLogTail": read_log_tail(log_path),
        }
        gaps.append(gap)
        write_json(output_dir / "gap-ledger.json", gaps)
        write_json(
            output_dir / "usability-probe-result.json",
            {
                "status": "blocked",
                "error": str(exc),
                "screenshots": screenshots,
                "gapCount": len(gaps),
                "desktopLogTail": read_log_tail(log_path),
            },
        )
        print(f"[workflow-usability] blocked: {exc}", flush=True)
        print(f"[workflow-usability] evidence={output_dir}", flush=True)
        return 1
    finally:
        terminate_process_group(process)


if __name__ == "__main__":
    raise SystemExit(main())
