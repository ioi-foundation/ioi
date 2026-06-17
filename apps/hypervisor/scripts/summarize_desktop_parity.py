#!/usr/bin/env python3
"""Summarize retained desktop parity runs against a prompt manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run_manifest",
        help="Path to a live desktop parity run manifest.json",
    )
    parser.add_argument(
        "--prompt-manifest",
        help="Optional JSON prompt manifest with question coverage metadata.",
    )
    parser.add_argument(
        "--write-md",
        help="Optional markdown output path for the generated summary.",
    )
    return parser.parse_args()


def route_line(bundle: dict[str, Any]) -> str:
    receipt = best_route_receipt(bundle)
    decision = receipt.get("route_decision") or {}
    surface = decision.get("effective_tool_surface") or {}
    primary = ", ".join(surface.get("primary_tools") or [])
    projected = ", ".join(surface.get("projected_tools") or [])
    parts = []
    if receipt.get("route_family"):
        parts.append(f"family={receipt['route_family']}")
    if receipt.get("selected_route"):
        parts.append(f"route={receipt['selected_route']}")
    if decision.get("output_intent"):
        parts.append(f"output={decision['output_intent']}")
    if primary:
        parts.append(f"primary=[{primary}]")
    elif projected:
        parts.append(f"projected=[{projected}]")
    return "; ".join(parts) or "n/a"


def verification_line(bundle: dict[str, Any]) -> str:
    receipt = best_route_receipt(bundle)
    manifest = receipt.get("artifact_manifest_summary") or {}
    if not manifest:
        return "n/a"
    parts = []
    if manifest.get("renderer"):
        parts.append(f"renderer={manifest['renderer']}")
    if manifest.get("verification_status"):
        parts.append(f"verify={manifest['verification_status']}")
    if manifest.get("lifecycle_state"):
        parts.append(f"lifecycle={manifest['lifecycle_state']}")
    return "; ".join(parts) or "n/a"


def prompt_lookup(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {entry["prompt"]: entry for entry in entries if entry.get("prompt")}


def field_from_bundle(bundle: dict[str, Any], field: str) -> Any:
    if field in bundle and bundle.get(field) is not None:
        return bundle.get(field)
    task = bundle.get("task")
    if isinstance(task, dict):
        return task.get(field)
    return None


def summarized_receipt_candidates(task: dict[str, Any]) -> list[dict[str, Any]]:
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
    candidates.sort(
        key=lambda receipt: (
            1 if receipt.get("route_decision") else 0,
            1 if receipt.get("selected_route") else 0,
            1 if "route decision" in (receipt.get("title") or "").lower() else 0,
        ),
        reverse=True,
    )
    return candidates


def best_route_receipt(bundle: dict[str, Any]) -> dict[str, Any]:
    receipt = bundle.get("route_receipt_summary") or {}
    if isinstance(bundle.get("task"), dict):
        candidates = summarized_receipt_candidates(bundle["task"])
        if candidates:
            candidate = candidates[0]
            if (
                not receipt
                or candidate.get("route_decision")
                or candidate.get("selected_route")
                or not receipt.get("route_decision")
            ):
                receipt = candidate
    return receipt


def markdown_summary(
    bundles: list[dict[str, Any]],
    prompt_entries: list[dict[str, Any]] | None,
) -> str:
    lines: list[str] = []
    lines.append("# Desktop Parity Summary")
    lines.append("")
    if prompt_entries:
        covered = sorted(
            {
                int(question_id)
                for entry in prompt_entries
                for question_id in entry.get("covers_questions", [])
            }
        )
        lines.append(
            f"- prompt entries: {len(prompt_entries)}"
        )
        lines.append(f"- covered question ids: {', '.join(str(value) for value in covered)}")
        lines.append("")

    lines.append("| Prompt | Phase | Route | Verification | Questions |")
    lines.append("|---|---|---|---|---|")

    prompt_map = prompt_lookup(prompt_entries or [])
    for bundle in bundles:
        prompt = bundle.get("prompt") or ""
        entry = prompt_map.get(prompt, {})
        question_ids = ", ".join(str(value) for value in entry.get("covers_questions", []))
        lines.append(
            "| {prompt} | {phase} | {route} | {verify} | {questions} |".format(
                prompt=prompt.replace("|", "\\|"),
                phase=(field_from_bundle(bundle, "phase") or "unknown").replace("|", "\\|"),
                route=route_line(bundle).replace("|", "\\|"),
                verify=verification_line(bundle).replace("|", "\\|"),
                questions=question_ids or "n/a",
            )
        )

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    for bundle in bundles:
        prompt = bundle.get("prompt") or ""
        answer = (bundle.get("latest_agent_message") or "").strip()
        current_step = (field_from_bundle(bundle, "current_step") or "").strip()
        lines.append(f"### {prompt}")
        lines.append("")
        lines.append(f"- phase: {field_from_bundle(bundle, 'phase') or 'unknown'}")
        lines.append(f"- current_step: {current_step or 'n/a'}")
        lines.append(f"- route: {route_line(bundle)}")
        lines.append(f"- verification: {verification_line(bundle)}")
        if answer:
            lines.append(f"- answer_excerpt: {answer[:240]}")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    bundles = load_json(Path(args.run_manifest).expanduser())
    prompt_entries = None
    if args.prompt_manifest:
        prompt_entries = load_json(Path(args.prompt_manifest).expanduser())

    summary = markdown_summary(bundles, prompt_entries)
    print(summary)
    if args.write_md:
        output_path = Path(args.write_md).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(summary, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
