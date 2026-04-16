#!/usr/bin/env python3
"""Validate retained desktop parity runs against a prompt manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_manifest", help="Path to a desktop probe manifest.json")
    parser.add_argument(
        "--prompt-manifest",
        required=True,
        help="JSON prompt manifest with coverage metadata and expectations.",
    )
    parser.add_argument(
        "--write-md",
        help="Optional markdown output path for the validation summary.",
    )
    return parser.parse_args()


def prompt_lookup(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {entry["prompt"]: entry for entry in entries if entry.get("prompt")}


def record_value(record: dict[str, Any] | None, *keys: str) -> Any:
    if not isinstance(record, dict):
        return None
    for key in keys:
        if key in record:
            return record.get(key)
    return None


def summarized_receipt_candidates(task: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for event in task.get("events", []):
        if (event.get("event_type") or "").strip().upper() != "RECEIPT":
            continue
        digest = event.get("digest") or {}
        details = event.get("details") or {}
        route_decision = digest.get("route_decision")
        if not (
            route_decision
            or digest.get("selected_route")
            or digest.get("route_family")
        ):
            continue
        candidates.append(
            {
                "title": event.get("title"),
                "digest": digest,
                "selected_route": digest.get("selected_route"),
                "route_family": digest.get("route_family"),
                "route_decision": route_decision or {},
                "details": details,
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
    task = bundle.get("task")
    if isinstance(task, dict):
        candidates = summarized_receipt_candidates(task)
        if candidates:
            return candidates[0]
    return bundle.get("route_receipt_summary") or {}


def actual_state(bundle: dict[str, Any]) -> dict[str, Any]:
    receipt = best_route_receipt(bundle)
    digest = receipt.get("digest") or {}
    decision = receipt.get("route_decision") or {}
    details = receipt.get("details") or {}
    surface = decision.get("effective_tool_surface") or {}
    domain_policy_bundle = (
        record_value(details, "domain_policy_bundle", "domainPolicyBundle")
        or record_value(digest, "domain_policy_bundle", "domainPolicyBundle")
        or record_value(decision, "domain_policy_bundle", "domainPolicyBundle")
        or {}
    )
    presentation_policy = (
        record_value(domain_policy_bundle, "presentation_policy", "presentationPolicy")
        or {}
    )
    retained_widget_state = (
        record_value(
            domain_policy_bundle, "retained_widget_state", "retainedWidgetState"
        )
        or {}
    )
    verification_contract = (
        record_value(
            domain_policy_bundle, "verification_contract", "verificationContract"
        )
        or {}
    )
    policy_contract = (
        record_value(domain_policy_bundle, "policy_contract", "policyContract") or {}
    )
    source_ranking = (
        record_value(domain_policy_bundle, "source_ranking", "sourceRanking") or []
    )
    lane_transitions = (
        record_value(details, "lane_transitions", "laneTransitions")
        or record_value(digest, "lane_transitions", "laneTransitions")
        or record_value(decision, "lane_transitions", "laneTransitions")
        or []
    )
    orchestration_state = (
        record_value(details, "orchestration_state", "orchestrationState")
        or record_value(digest, "orchestration_state", "orchestrationState")
        or record_value(decision, "orchestration_state", "orchestrationState")
        or {}
    )
    orchestration_objective = record_value(orchestration_state, "objective") or {}
    orchestration_tasks = record_value(orchestration_state, "tasks") or []
    orchestration_checkpoints = record_value(orchestration_state, "checkpoints") or []
    task = bundle.get("task") or {}
    clarification = task.get("clarification_request") or {}
    return {
        "phase": bundle.get("phase") or task.get("phase"),
        "probe_error": bundle.get("probe_error"),
        "route_family": receipt.get("route_family") or decision.get("route_family"),
        "selected_route": receipt.get("selected_route"),
        "output_intent": decision.get("output_intent"),
        "direct_answer_allowed": decision.get("direct_answer_allowed"),
        "direct_answer_blockers": decision.get("direct_answer_blockers") or [],
        "currentness_override": decision.get("currentness_override"),
        "connector_first_preference": decision.get("connector_first_preference"),
        "narrow_tool_preference": decision.get("narrow_tool_preference"),
        "file_output_intent": decision.get("file_output_intent"),
        "artifact_output_intent": decision.get("artifact_output_intent"),
        "inline_visual_intent": decision.get("inline_visual_intent"),
        "skill_prep_required": decision.get("skill_prep_required"),
        "primary_tools": surface.get("primary_tools") or [],
        "projected_tools": surface.get("projected_tools") or [],
        "broad_fallback_tools": surface.get("broad_fallback_tools") or [],
        "clarification_question": clarification.get("question"),
        "clarification_question_absent": not bool(clarification.get("question")),
        "clarification_options": [
            option.get("label")
            for option in clarification.get("options", [])
            if isinstance(option, dict) and option.get("label")
        ],
        "presentation_surface": record_value(
            presentation_policy, "primarySurface", "primary_surface"
        ),
        "widget_family": record_value(
            retained_widget_state, "widgetFamily", "widget_family"
        )
        or record_value(presentation_policy, "widgetFamily", "widget_family"),
        "policy_hidden_instruction_dependency": record_value(
            policy_contract,
            "hiddenInstructionDependency",
            "hidden_instruction_dependency",
        ),
        "source_ranking_sources": [
            source
            for source in (
                record_value(entry, "source")
                for entry in source_ranking
                if isinstance(entry, dict)
            )
            if isinstance(source, str)
        ],
        "verification_required_checks": [
            value
            for value in (
                record_value(verification_contract, "requiredChecks", "required_checks")
                or []
            )
            if isinstance(value, str)
        ],
        "lane_transition_targets": [
            target
            for target in (
                record_value(entry, "toLane", "to_lane")
                for entry in lane_transitions
                if isinstance(entry, dict)
            )
            if isinstance(target, str)
        ],
        "orchestration_objective_title": record_value(orchestration_objective, "title"),
        "orchestration_task_count": len(orchestration_tasks)
        if isinstance(orchestration_tasks, list)
        else 0,
        "orchestration_checkpoint_count": len(orchestration_checkpoints)
        if isinstance(orchestration_checkpoints, list)
        else 0,
        "latest_agent_message": bundle.get("latest_agent_message"),
        "current_step": bundle.get("current_step") or task.get("current_step"),
    }


def contains_text(actual: str | None, expected: str) -> bool:
    return expected.lower() in (actual or "").lower()


def includes_all(actual: list[str], expected: list[str]) -> bool:
    actual_lookup = [value.lower() for value in actual]
    return all(
        any(expected_value.lower() == actual_value for actual_value in actual_lookup)
        for expected_value in expected
    )


def validate_bundle(bundle: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    expectations = entry.get("expectations") or {}
    actual = actual_state(bundle)
    failures: list[str] = []

    def expect_equal(field: str) -> None:
        expected = expectations.get(field)
        if expected is None:
            return
        if actual.get(field) != expected:
            failures.append(
                f"{field}: expected {expected!r}, got {actual.get(field)!r}"
            )

    for field in [
        "phase",
        "route_family",
        "output_intent",
        "direct_answer_allowed",
        "currentness_override",
        "connector_first_preference",
        "narrow_tool_preference",
        "file_output_intent",
        "artifact_output_intent",
        "inline_visual_intent",
        "skill_prep_required",
        "presentation_surface",
        "widget_family",
        "policy_hidden_instruction_dependency",
        "clarification_question_absent",
    ]:
        expect_equal(field)

    selected_route_contains = expectations.get("selected_route_contains")
    if selected_route_contains and not contains_text(
        actual.get("selected_route"), selected_route_contains
    ):
        failures.append(
            "selected_route_contains: expected substring "
            f"{selected_route_contains!r} in {actual.get('selected_route')!r}"
        )

    clarification_contains = expectations.get("clarification_contains")
    if clarification_contains and not contains_text(
        actual.get("clarification_question"), clarification_contains
    ):
        failures.append(
            "clarification_contains: expected substring "
            f"{clarification_contains!r} in {actual.get('clarification_question')!r}"
        )

    latest_agent_message_contains = expectations.get("latest_agent_message_contains")
    if latest_agent_message_contains and not contains_text(
        actual.get("latest_agent_message"), latest_agent_message_contains
    ):
        failures.append(
            "latest_agent_message_contains: expected substring "
            f"{latest_agent_message_contains!r} in {actual.get('latest_agent_message')!r}"
        )

    blockers = expectations.get("direct_answer_blockers_include") or []
    if blockers and not includes_all(actual.get("direct_answer_blockers") or [], blockers):
        failures.append(
            "direct_answer_blockers_include: expected "
            f"{blockers!r}, got {actual.get('direct_answer_blockers')!r}"
        )

    for field in [
        "primary_tools_include",
        "projected_tools_include",
        "broad_fallback_tools_include",
        "source_ranking_sources_include",
        "verification_required_checks_include",
        "lane_transition_targets_include",
    ]:
        expected_values = expectations.get(field) or []
        if not expected_values:
            continue
        actual_field = field.replace("_include", "")
        if not includes_all(actual.get(actual_field) or [], expected_values):
            failures.append(
                f"{field}: expected {expected_values!r}, got {actual.get(actual_field)!r}"
            )

    for field in [
        "orchestration_task_count_min",
        "orchestration_checkpoint_count_min",
    ]:
        expected = expectations.get(field)
        if expected is None:
            continue
        actual_field = field.replace("_min", "")
        actual_value = actual.get(actual_field)
        if not isinstance(actual_value, int) or actual_value < expected:
            failures.append(
                f"{field}: expected >= {expected!r}, got {actual_value!r}"
            )

    return {
        "prompt": bundle.get("prompt"),
        "covers_questions": entry.get("covers_questions") or [],
        "actual": actual,
        "passed": not failures,
        "failures": failures,
    }


def markdown_summary(
    results: list[dict[str, Any]],
    total_questions: list[int],
) -> str:
    passed_count = sum(1 for result in results if result["passed"])
    lines: list[str] = []
    lines.append("# Desktop Parity Validation")
    lines.append("")
    lines.append(f"- prompts: {len(results)}")
    lines.append(f"- passed: {passed_count}")
    lines.append(f"- failed: {len(results) - passed_count}")
    lines.append(
        "- covered questions: "
        + ", ".join(str(question_id) for question_id in total_questions)
    )
    lines.append("")
    lines.append("| Prompt | Pass | Route | Output | Notes |")
    lines.append("|---|---|---|---|---|")
    for result in results:
        actual = result["actual"]
        note = "ok" if result["passed"] else "; ".join(result["failures"])
        lines.append(
            "| {prompt} | {passed} | {route} | {output} | {note} |".format(
                prompt=(result.get("prompt") or "").replace("|", "\\|"),
                passed="yes" if result["passed"] else "no",
                route=(actual.get("selected_route") or actual.get("route_family") or "n/a").replace(
                    "|", "\\|"
                ),
                output=(actual.get("output_intent") or "n/a").replace("|", "\\|"),
                note=note.replace("|", "\\|"),
            )
        )
    lines.append("")
    lines.append("## Details")
    lines.append("")
    for result in results:
        actual = result["actual"]
        lines.append(f"### {result.get('prompt')}")
        lines.append("")
        lines.append(f"- passed: {'yes' if result['passed'] else 'no'}")
        lines.append(f"- route_family: {actual.get('route_family') or 'n/a'}")
        lines.append(f"- selected_route: {actual.get('selected_route') or 'n/a'}")
        lines.append(f"- output_intent: {actual.get('output_intent') or 'n/a'}")
        lines.append(
            "- primary_tools: "
            + (", ".join(actual.get("primary_tools") or []) or "n/a")
        )
        lines.append(
            "- broad_fallback_tools: "
            + (", ".join(actual.get("broad_fallback_tools") or []) or "n/a")
        )
        lines.append(
            f"- presentation_surface: {actual.get('presentation_surface') or 'n/a'}"
        )
        lines.append(f"- widget_family: {actual.get('widget_family') or 'n/a'}")
        lines.append(
            "- source_ranking_sources: "
            + (", ".join(actual.get("source_ranking_sources") or []) or "n/a")
        )
        lines.append(
            "- lane_transition_targets: "
            + (", ".join(actual.get("lane_transition_targets") or []) or "n/a")
        )
        lines.append(
            "- verification_required_checks: "
            + (", ".join(actual.get("verification_required_checks") or []) or "n/a")
        )
        lines.append(
            f"- orchestration_task_count: {actual.get('orchestration_task_count')}"
        )
        lines.append(
            f"- orchestration_checkpoint_count: {actual.get('orchestration_checkpoint_count')}"
        )
        lines.append(
            f"- clarification: {actual.get('clarification_question') or 'n/a'}"
        )
        if actual.get("probe_error"):
            lines.append(f"- probe_error: {actual['probe_error']}")
        if not result["passed"]:
            lines.append("- failures:")
            for failure in result["failures"]:
                lines.append(f"  - {failure}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    bundles = load_json(Path(args.run_manifest).expanduser())
    prompt_entries = load_json(Path(args.prompt_manifest).expanduser())
    entry_lookup = prompt_lookup(prompt_entries)

    results: list[dict[str, Any]] = []
    covered_questions = sorted(
        {
            int(question_id)
            for entry in prompt_entries
            for question_id in entry.get("covers_questions", [])
        }
    )

    for bundle in bundles:
        prompt = bundle.get("prompt")
        entry = entry_lookup.get(prompt)
        if not entry:
            continue
        results.append(validate_bundle(bundle, entry))

    summary = markdown_summary(results, covered_questions)
    print(summary)
    if args.write_md:
        output_path = Path(args.write_md).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(summary, encoding="utf-8")

    return 0 if all(result["passed"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
