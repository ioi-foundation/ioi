#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import re
import sys
from pathlib import Path
from typing import Any


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def compact(value: str, limit: int = 240) -> str:
    text = " ".join(value.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def extract_messages(raw: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(raw)
    except Exception:
        return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def extract_system_prompt(call: dict[str, Any]) -> str:
    parts: list[str] = []
    for message in extract_messages(call.get("input_utf8", "")):
        if message.get("role") == "system" and isinstance(message.get("content"), str):
            parts.append(message["content"])
    return "\n".join(parts)


def extract_section(system_prompt: str, header: str) -> str:
    marker = f"{header}\n"
    start = system_prompt.find(marker)
    if start == -1:
        return ""
    remainder = system_prompt[start + len(marker) :]
    end_markers = [
        "\n\nRECENT BROWSER OBSERVATION:",
        "\n\nRECENT PENDING BROWSER STATE:",
        "\n\nRECENT SUCCESS SIGNAL:",
        "\n\nRECENT SESSION EVENTS:",
        "\n\nOPERATING RULES:",
        "\n\n[AVAILABLE TOOLS]",
        "\n\nMODE:",
        "\n\nSTATE:",
    ]
    end = len(remainder)
    for candidate in end_markers:
        idx = remainder.find(candidate)
        if idx != -1:
            end = min(end, idx)
    return remainder[:end].strip()


def parse_tool_call(raw: str) -> tuple[str | None, Any]:
    try:
        value = json.loads(raw)
    except Exception:
        return None, None
    if not isinstance(value, dict):
        return None, None
    return value.get("name"), value.get("arguments")


BACKTICK_TOKEN_RE = re.compile(r"`([^`]+)`")
NON_TARGET_TOKENS = {
    "agent__complete",
    "browser__click",
    "browser__click_element",
    "browser__find_text",
    "browser__hover",
    "browser__move_mouse",
    "browser__scroll",
    "browser__snapshot",
    "browser__synthetic_click",
    "browser__wait",
    "continue_with",
    "delay_ms_between_ids",
    "id",
    "ids",
    "os__focus_window",
    "system__fail",
}
GENERIC_NON_TARGET_WORDS = {
    "a",
    "an",
    "and",
    "another",
    "do",
    "not",
    "now",
    "or",
    "the",
    "then",
    "use",
    "with",
}


def referenced_semantic_tokens(text: str) -> list[str]:
    seen: set[str] = set()
    tokens: list[str] = []
    for raw in BACKTICK_TOKEN_RE.findall(text):
        token = str(raw).strip()
        if not token or any(ch.isspace() for ch in token):
            continue
        if token in NON_TARGET_TOKENS or token.startswith("x=") or token.startswith("y="):
            continue
        if "__" in token:
            continue
        if token in seen:
            continue
        seen.add(token)
        tokens.append(token)
    return tokens


def referenced_target_tokens(text: str, known_targets: list[str]) -> list[str]:
    seen: set[str] = set()
    tokens: list[str] = []
    
    def add(candidate: str) -> None:
        token = candidate.strip()
        if not token or token in seen:
            return
        seen.add(token)
        tokens.append(token)

    for token in referenced_tool_call_tokens(text):
        add(token)

    for token in known_targets:
        if not isinstance(token, str):
            continue
        candidate = token.strip()
        if not candidate or candidate in seen:
            continue
        if f"`{candidate}`" not in text:
            continue
        add(candidate)

    if tokens:
        return tokens

    for token in referenced_semantic_tokens(text):
        candidate = token.strip()
        if not candidate or candidate in seen:
            continue
        if candidate.lower() in GENERIC_NON_TARGET_WORDS:
            continue
        if candidate.startswith("#"):
            candidate = candidate[1:]
        if any(ch in candidate for ch in (" ", ",", "=", ".", ":", "|")):
            continue
        add(candidate)

    return tokens


def referenced_tool_call_tokens(text: str) -> list[str]:
    seen: set[str] = set()
    tokens: list[str] = []

    def add(candidate: str) -> None:
        token = candidate.strip()
        if not token or token in seen:
            return
        seen.add(token)
        tokens.append(token)

    for raw in BACKTICK_TOKEN_RE.findall(text):
        candidate = str(raw).strip()
        if not candidate.startswith("browser__"):
            continue
        tool_name, separator, raw_arguments = candidate.partition(" ")
        if not separator or not raw_arguments.strip().startswith("{"):
            continue
        try:
            arguments = json.loads(raw_arguments)
        except Exception:
            continue
        for token in chosen_target_tokens(
            {
                "chosen_name": tool_name,
                "chosen_arguments": arguments,
            }
        ):
            add(token)

    return tokens


def chosen_target_tokens(step: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    tokens: list[str] = []

    def add_token(value: str) -> None:
        token = value.strip()
        if not token or token in seen:
            return
        seen.add(token)
        tokens.append(token)

    def collect_from_arguments(arguments: Any, tool_name: str | None = None) -> None:
        if not isinstance(arguments, dict):
            return
        for key in ("id", "target_id", "semantic_id"):
            value = arguments.get(key)
            if isinstance(value, str):
                add_token(value)
        batch_ids = arguments.get("ids")
        if isinstance(batch_ids, list):
            for value in batch_ids:
                if isinstance(value, str):
                    add_token(value)
        for key in ("selector", "requested_selector"):
            value = arguments.get(key)
            if isinstance(value, str):
                for selector_token in selector_target_tokens(value):
                    add_token(selector_token)
        if tool_name == "browser__key":
            for action_token in browser_key_action_tokens(arguments):
                add_token(action_token)
        continue_with = arguments.get("continue_with")
        if isinstance(continue_with, dict):
            nested_name = continue_with.get("name")
            nested_arguments = continue_with.get("arguments", continue_with)
            collect_from_arguments(nested_arguments, nested_name if isinstance(nested_name, str) else None)

    arguments = step.get("chosen_arguments")
    chosen_name = step.get("chosen_name")
    collect_from_arguments(arguments, chosen_name if isinstance(chosen_name, str) else None)
    requested_id = step.get("requested_id")
    if isinstance(requested_id, str):
        add_token(requested_id)
    return tokens


def selector_target_tokens(raw_selector: str) -> list[str]:
    selector = raw_selector.strip().replace('\\"', '"').replace("&quot;", '"')
    if not selector:
        return []

    tokens: list[str] = []
    seen: set[str] = set()

    def add(token: str) -> None:
        candidate = token.strip()
        if not candidate or candidate in seen:
            return
        seen.add(candidate)
        tokens.append(candidate)

    exact_hash = re.fullmatch(r"#([A-Za-z0-9_-]+)", selector)
    if exact_hash:
        add(exact_hash.group(1))

    id_attribute = re.fullmatch(r'\[id="?([^"\]]+)"?\]', selector)
    if id_attribute:
        add(id_attribute.group(1))

    return tokens


def browser_key_action_tokens(arguments: dict[str, Any]) -> list[str]:
    key = arguments.get("key")
    if not isinstance(key, str) or not key.strip():
        return []

    modifiers = arguments.get("modifiers")
    modifier_list = [
        modifier.strip()
        for modifier in modifiers
        if isinstance(modifier, str) and modifier.strip()
    ] if isinstance(modifiers, list) else []

    if not modifier_list:
        return [key]

    return ["+".join([*modifier_list, key]), key]


def observation_summary_target_tokens(summary: str) -> list[str]:
    tokens: list[str] = []
    seen: set[str] = set()

    def add(token: str | None) -> None:
        if not isinstance(token, str):
            return
        candidate = token.strip()
        if not candidate or candidate in seen:
            return
        seen.add(candidate)
        tokens.append(candidate)

    add(target_token_from_summary(summary))
    dom_id_match = re.search(r"\bdom_id=([^ ]+)", summary)
    if dom_id_match:
        add(dom_id_match.group(1))
    selector_match = re.search(r"\bselector=([^ ]+)", summary)
    if selector_match:
        for token in selector_target_tokens(selector_match.group(1)):
            add(token)
    return tokens


def observation_target_aliases_from_summaries(summaries: list[str]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for summary in summaries:
        if not isinstance(summary, str):
            continue
        summary_tokens = observation_summary_target_tokens(summary)
        if not summary_tokens:
            continue
        canonical = summary_tokens[0]
        for token in summary_tokens:
            aliases.setdefault(token, canonical)
    return aliases


def normalize_alignment_tokens(
    tokens: list[str],
    aliases: dict[str, str] | None,
) -> set[str]:
    normalized: set[str] = set()
    alias_map = aliases or {}
    for token in tokens:
        if not isinstance(token, str):
            continue
        candidate = token.strip()
        if not candidate:
            continue
        normalized.add(alias_map.get(candidate, candidate))
    return normalized


def signal_alignment(
    referenced_tokens: list[str],
    chosen_targets: list[str],
    aliases: dict[str, str] | None = None,
) -> str | None:
    if not referenced_tokens:
        return None
    normalized_referenced = normalize_alignment_tokens(referenced_tokens, aliases)
    normalized_chosen = normalize_alignment_tokens(chosen_targets, aliases)
    if not normalized_chosen:
        return "ungrounded"
    if normalized_chosen.isdisjoint(normalized_referenced):
        return "ignored"
    return "aligned"


def target_token_from_summary(summary: str) -> str | None:
    token = summary.split()[0] if summary.split() else ""
    if not token:
        return None
    if token.startswith("id="):
        return token[3:]
    if "#" in token:
        return token.split("#", 1)[1]
    return token


def extract_observation_target_summaries(observation: str) -> list[str]:
    marker = "IMPORTANT TARGETS:"
    start = observation.find(marker)
    if start == -1:
        return []
    block = observation[start + len(marker) :]
    end_markers = ["</root>", "Use this semantic browser evidence directly"]
    end = len(block)
    for candidate in end_markers:
        idx = block.find(candidate)
        if idx != -1:
            end = min(end, idx)
    block = block[:end]
    summaries: list[str] = []
    for raw in block.split(" | "):
        summary = compact(raw, 320)
        if summary:
            summaries.append(summary)
    return summaries


def observation_target_map(observation: str) -> dict[str, str]:
    targets: dict[str, str] = {}
    for summary in extract_observation_target_summaries(observation):
        token = target_token_from_summary(summary)
        if token and token not in targets:
            targets[token] = summary
    return targets


def observation_target_map_from_summaries(summaries: list[str]) -> dict[str, str]:
    targets: dict[str, str] = {}
    for summary in summaries:
        if not isinstance(summary, str):
            continue
        for token in observation_summary_target_tokens(summary):
            if token not in targets:
                targets[token] = summary
    return targets


def observation_target_delta(
    previous_targets: dict[str, str],
    current_targets: dict[str, str],
) -> dict[str, list[str]]:
    added = [
        current_targets[token]
        for token in current_targets.keys() - previous_targets.keys()
    ]
    removed = [
        previous_targets[token]
        for token in previous_targets.keys() - current_targets.keys()
    ]
    changed = [
        f"{token}: {compact(previous_targets[token], 120)} -> {compact(current_targets[token], 120)}"
        for token in current_targets.keys() & previous_targets.keys()
        if current_targets[token] != previous_targets[token]
    ]
    return {
        "added": sorted(added),
        "removed": sorted(removed),
        "changed": sorted(changed),
    }


def derive_findings(
    timeline: list[dict[str, Any]],
    bridge_state: dict[str, Any],
    phase_timing: dict[str, Any],
) -> list[str]:
    findings: list[str] = []

    bootstrap_to_grounded = phase_timing.get("bootstrap_to_first_grounded_target_ms")
    if isinstance(bootstrap_to_grounded, int) and bootstrap_to_grounded >= 1000:
        findings.append(
            "First grounded target arrived only after "
            f"{bootstrap_to_grounded} ms from bootstrap."
        )

    non_submit_steps = [
        step
        for step in timeline
        if step.get("chosen_name") != "browser__click_element"
        or "sub" not in json.dumps(step.get("chosen_arguments"), ensure_ascii=True).lower()
    ]
    if non_submit_steps and all(
        step.get("chosen_name") == "browser__synthetic_click" for step in non_submit_steps
    ):
        findings.append(
            "All non-submit actions were direct `browser__synthetic_click` guesses."
        )

    for step in timeline:
        chosen_name = step.get("chosen_name")
        chosen_targets = chosen_target_tokens(step)
        chosen_target_set = normalize_alignment_tokens(
            chosen_targets,
            step.get("target_aliases"),
        )
        if not chosen_name:
            continue

        for field, target_field in (
            ("pending_state", "pending_targets"),
            ("success_signal", "success_targets"),
        ):
            text = step.get(field)
            referenced = step.get(target_field)
            if not isinstance(text, str) or not text.strip():
                continue
            if not isinstance(referenced, list):
                continue
            referenced_targets = {
                token for token in referenced if isinstance(token, str) and token.strip()
            }
            if not referenced_targets:
                continue
            normalized_referenced_targets = normalize_alignment_tokens(
                sorted(referenced_targets),
                step.get("target_aliases"),
            )
            if not chosen_target_set:
                findings.append(
                    f"Step {step['step_index']} received {field} target(s) "
                    f"{sorted(referenced_targets)} but chose {chosen_name} without a grounded id."
                )
                break
            if chosen_target_set.isdisjoint(normalized_referenced_targets):
                findings.append(
                    f"Step {step['step_index']} ignored {field} target(s) "
                    f"{sorted(referenced_targets)} and chose {chosen_name} {sorted(chosen_targets)}."
                )
                break

    summary = bridge_state.get("info", {})
    final_reward = bridge_state.get("reward")
    last_step = timeline[-1] if timeline else None
    if (
        isinstance(final_reward, (int, float))
        and final_reward < 0
        and isinstance(last_step, dict)
    ):
        submit_targets = [
            token for token in chosen_target_tokens(last_step) if "sub" in token.lower()
        ]
        reward_positive = any(
            isinstance(entry.get("reward"), (int, float)) and entry.get("reward") > 0
            for entry in bridge_state.get("sync_history", [])
            if isinstance(entry, dict)
        )
        if submit_targets and not reward_positive:
            findings.append(
                "Final action submitted without any positive reward transition: "
                f"{submit_targets}."
            )

    executor_status = phase_timing.get("service_executor_dispatch_status")
    executor_elapsed = phase_timing.get("service_executor_dispatch_elapsed_ms")
    if executor_status == "timeout" and isinstance(executor_elapsed, int):
        findings.append(
            "Service executor dispatch timed out after "
            f"{executor_elapsed} ms before the step could register success."
        )

    return findings


def summarize_pointer_output(raw: str) -> str:
    try:
        value = json.loads(raw)
    except Exception:
        return compact(raw)
    pointer = value.get("pointer")
    tracking = value.get("tracking")
    if not isinstance(pointer, dict):
        return compact(raw)
    parts = [f"pointer.{pointer.get('action', 'unknown')}"]
    target = pointer.get("target")
    if isinstance(target, dict):
        target_id = target.get("id")
        resolved_from = target.get("resolved_from")
        tracking_selector = target.get("tracking_selector")
        if target_id:
            parts.append(f"id={target_id}")
        if resolved_from:
            parts.append(f"resolved_from={resolved_from}")
        if tracking_selector:
            parts.append(f"tracking_selector={tracking_selector}")
    if pointer.get("x") is not None and pointer.get("y") is not None:
        parts.append(f"x={pointer.get('x')}")
        parts.append(f"y={pointer.get('y')}")
    if isinstance(tracking, dict):
        if tracking.get("duration_ms") is not None:
            parts.append(f"duration_ms={tracking.get('duration_ms')}")
        if tracking.get("samples") is not None:
            parts.append(f"samples={tracking.get('samples')}")
        if tracking.get("selector_rect_resolutions") is not None:
            parts.append(
                f"selector_rect_resolutions={tracking.get('selector_rect_resolutions')}"
            )
        if tracking.get("refresh_failures") is not None:
            parts.append(f"refresh_failures={tracking.get('refresh_failures')}")
    return ", ".join(str(part) for part in parts)


def summarize_action_result(output: str, error_class: str | None) -> str:
    if error_class:
        return f"error_class={error_class}"
    try:
        value = json.loads(output)
    except Exception:
        return summarize_pointer_output(output)
    if isinstance(value, dict) and isinstance(value.get("synthetic_click"), dict):
        click = value["synthetic_click"]
        parts = [
            f"synthetic_click x={click.get('x')}",
            f"y={click.get('y')}",
        ]
        postcondition = value.get("postcondition")
        if isinstance(postcondition, dict):
            parts.append(
                "postcondition="
                + compact(json.dumps(postcondition, ensure_ascii=True), 140)
            )
        for label in ("pre_target", "post_target"):
            target = value.get(label)
            if isinstance(target, dict):
                target_summary = {
                    key: target.get(key)
                    for key in (
                        "semantic_id",
                        "dom_id",
                        "selector",
                        "tag_name",
                        "center_point",
                    )
                    if target.get(key) is not None
                }
                if target_summary:
                    parts.append(
                        f"{label}="
                        + compact(json.dumps(target_summary, ensure_ascii=True), 180)
                    )
        return ", ".join(parts)
    return summarize_pointer_output(output)


def parse_click_action_output(output: str) -> dict[str, Any] | None:
    prefix = "Clicked element '"
    if not output.startswith(prefix):
        return None
    remainder = output[len(prefix) :]
    semantic_id, separator, remainder = remainder.partition("' via ")
    if not separator:
        return None
    delivery, verify_separator, verify_text = remainder.partition(". verify=")
    detail: dict[str, Any] = {
        "clicked_semantic_id": semantic_id,
        "delivery": delivery.strip(),
    }
    if verify_separator:
        try:
            verify = json.loads(verify_text)
        except Exception:
            verify = {"raw": verify_text}
        detail["verify"] = verify
        if isinstance(verify, dict):
            detail["verify_method"] = verify.get("method")
            detail["dispatch_succeeded"] = verify.get("dispatch_succeeded")
            detail["post_target"] = verify.get("post_target")
            detail["focused_control"] = verify.get("focused_control")
    return detail


def parse_receipt_observed_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return text


def receipt_observed_field(receipt: dict[str, Any], field: str) -> Any:
    observed = receipt.get("observed_value")
    if not isinstance(observed, dict):
        return None
    return observed.get(field)


def execution_receipt_timeline(kernel_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    for event in kernel_events:
        receipt = event.get("ExecutionContractReceipt")
        if not isinstance(receipt, dict):
            continue
        receipts.append(
            {
                "timestamp_ms": receipt.get("timestamp_ms"),
                "step_index": receipt.get("step_index"),
                "stage": receipt.get("stage"),
                "key": receipt.get("key"),
                "satisfied": receipt.get("satisfied"),
                "probe_source": receipt.get("probe_source"),
                "observed_value": parse_receipt_observed_value(
                    receipt.get("observed_value")
                ),
                "evidence_type": receipt.get("evidence_type"),
                "provider_id": receipt.get("provider_id"),
            }
        )
    receipts.sort(
        key=lambda entry: (
            entry.get("timestamp_ms") is None,
            entry.get("timestamp_ms") or 0,
            entry.get("step_index") or 0,
            str(entry.get("stage") or ""),
            str(entry.get("key") or ""),
        )
    )
    return receipts


def first_call_timing(inference_calls: list[dict[str, Any]]) -> dict[str, Any]:
    if not inference_calls:
        return {}
    call = inference_calls[0]
    chosen_name, chosen_args = parse_tool_call(str(call.get("output_utf8", "")))
    return {
        "ordinal": call.get("ordinal"),
        "method": call.get("method"),
        "started_at_ms": call.get("started_at_ms"),
        "finished_at_ms": call.get("finished_at_ms"),
        "elapsed_ms": call.get("elapsed_ms"),
        "chosen_name": chosen_name,
        "chosen_arguments": chosen_args,
    }


def phase_timing_summary(
    inference_trace: dict[str, Any],
    inference_calls: list[dict[str, Any]],
    bridge_state: dict[str, Any],
    kernel_events: list[dict[str, Any]],
) -> dict[str, Any]:
    phase_timings = inference_trace.get("phase_timings")
    if not isinstance(phase_timings, dict):
        phase_timings = {}
    sync_history = sync_history_summary(bridge_state)
    execution_receipts = execution_receipt_timeline(kernel_events)
    bootstrap_sync_ms = None
    if sync_history:
        bootstrap_sync_ms = sync_history[0].get("last_sync_ms")
    elif isinstance(bridge_state.get("last_sync_ms"), int):
        bootstrap_sync_ms = bridge_state.get("last_sync_ms")
    first_bridge_event_ms = None
    first_grounded_target_event_ms = None
    for entry in sync_history:
        event = entry.get("last_event")
        if not isinstance(event, dict):
            continue
        timestamp_ms = event.get("timestamp_ms")
        if isinstance(timestamp_ms, int):
            if first_bridge_event_ms is None:
                first_bridge_event_ms = timestamp_ms
            target_selector = str(event.get("target_selector") or "").strip().lower()
            target_id = str(event.get("target_id") or "").strip().lower()
            target_tag = str(event.get("target_tag") or "").strip().lower()
            if (
                target_selector not in ("", "html", "body")
                or target_id not in ("", "html", "body")
                or target_tag not in ("", "html", "body")
            ):
                first_grounded_target_event_ms = timestamp_ms
                break
    first_receipt_ms = None
    if execution_receipts:
        candidate = execution_receipts[0].get("timestamp_ms")
        if isinstance(candidate, int):
            first_receipt_ms = candidate
    service_phase_keys = [
        "service_prepare_tool",
        "service_determinism_context",
        "service_policy_gate",
        "service_focus_recovery",
        "service_executor_dispatch",
        "service_finalize_executor_result",
        "service_action_complete",
    ]
    first_call = first_call_timing(inference_calls)
    terminal_sync_ms = None
    if sync_history:
        candidate = sync_history[-1].get("last_sync_ms")
        if isinstance(candidate, int):
            terminal_sync_ms = candidate
    summary = {
        "bootstrap_sync_ms": bootstrap_sync_ms,
        "browser_launch_started_at_ms": phase_timings.get("browser_launch_started_at_ms"),
        "browser_launch_finished_at_ms": phase_timings.get("browser_launch_finished_at_ms"),
        "session_created_at_ms": phase_timings.get("session_created_at_ms"),
        "browser_navigation_started_at_ms": phase_timings.get(
            "browser_navigation_started_at_ms"
        ),
        "browser_navigation_finished_at_ms": phase_timings.get(
            "browser_navigation_finished_at_ms"
        ),
        "initial_bridge_ready_observed_at_ms": phase_timings.get(
            "initial_bridge_ready_observed_at_ms"
        ),
        "agent_start_service_started_at_ms": phase_timings.get(
            "agent_start_service_started_at_ms"
        ),
        "agent_start_service_finished_at_ms": phase_timings.get(
            "agent_start_service_finished_at_ms"
        ),
        "first_step_service_started_at_ms": phase_timings.get(
            "first_step_service_started_at_ms"
        ),
        "first_step_service_finished_at_ms": phase_timings.get(
            "first_step_service_finished_at_ms"
        ),
        "first_inference_started_at_ms": first_call.get("started_at_ms"),
        "first_inference_finished_at_ms": first_call.get("finished_at_ms"),
        "first_inference_elapsed_ms": first_call.get("elapsed_ms"),
        "first_inference_tool": first_call.get("chosen_name"),
        "first_execution_receipt_ms": first_receipt_ms,
        "first_bridge_input_event_ms": first_bridge_event_ms,
        "first_grounded_target_event_ms": first_grounded_target_event_ms,
        "terminal_sync_ms": terminal_sync_ms,
        "case_finished_at_ms": phase_timings.get("case_finished_at_ms"),
    }
    if isinstance(bootstrap_sync_ms, int):
        for key in [
            "initial_bridge_ready_observed_at_ms",
            "agent_start_service_started_at_ms",
            "agent_start_service_finished_at_ms",
            "first_step_service_started_at_ms",
            "first_step_service_finished_at_ms",
            "first_inference_started_at_ms",
            "first_inference_finished_at_ms",
            "first_execution_receipt_ms",
            "first_bridge_input_event_ms",
            "first_grounded_target_event_ms",
            "terminal_sync_ms",
            "case_finished_at_ms",
        ]:
            value = summary.get(key)
            if isinstance(value, int):
                summary[f"{key}_delta_from_bootstrap_ms"] = value - bootstrap_sync_ms
    def add_budget(name: str, start_key: str, end_key: str) -> None:
        start = summary.get(start_key)
        end = summary.get(end_key)
        if isinstance(start, int) and isinstance(end, int) and end >= start:
            summary[name] = end - start

    add_budget(
        "bootstrap_to_first_inference_start_ms",
        "bootstrap_sync_ms",
        "first_inference_started_at_ms",
    )
    add_budget(
        "bootstrap_to_first_grounded_target_ms",
        "bootstrap_sync_ms",
        "first_grounded_target_event_ms",
    )
    add_budget(
        "first_inference_finish_to_first_receipt_ms",
        "first_inference_finished_at_ms",
        "first_execution_receipt_ms",
    )
    add_budget(
        "first_receipt_to_first_grounded_target_ms",
        "first_execution_receipt_ms",
        "first_grounded_target_event_ms",
    )
    add_budget(
        "first_grounded_target_to_terminal_ms",
        "first_grounded_target_event_ms",
        "terminal_sync_ms",
    )
    add_budget(
        "terminal_to_step_finish_tail_ms",
        "terminal_sync_ms",
        "first_step_service_finished_at_ms",
    )
    for phase_key in service_phase_keys:
        receipt = next(
            (
                entry
                for entry in execution_receipts
                if entry.get("key") == phase_key
                and entry.get("probe_source") == "service_action_execution"
            ),
            None,
        )
        if not isinstance(receipt, dict):
            continue
        elapsed_ms = receipt_observed_field(receipt, "elapsed_ms")
        status = receipt_observed_field(receipt, "status")
        finished_at_ms = receipt_observed_field(receipt, "finished_at_ms")
        if isinstance(elapsed_ms, (int, float)):
            summary[f"{phase_key}_elapsed_ms"] = int(elapsed_ms)
        if isinstance(status, str) and status.strip():
            summary[f"{phase_key}_status"] = status
        if isinstance(finished_at_ms, int):
            summary[f"{phase_key}_finished_at_ms"] = finished_at_ms
    return summary


def build_timeline(
    inference_calls: list[dict[str, Any]],
    kernel_events: list[dict[str, Any]],
    bridge_state: dict[str, Any],
) -> list[dict[str, Any]]:
    routing_by_step: dict[int, dict[str, Any]] = {}
    result_by_step: dict[int, dict[str, Any]] = {}
    agent_step_by_step: dict[int, dict[str, Any]] = {}
    receipts_by_step: dict[int, list[dict[str, Any]]] = defaultdict(list)

    for event in kernel_events:
        if "RoutingReceipt" in event:
            receipt = event["RoutingReceipt"]
            if isinstance(receipt, dict):
                routing_by_step[int(receipt.get("step_index", 0))] = receipt
        elif "AgentActionResult" in event:
            result = event["AgentActionResult"]
            if isinstance(result, dict):
                result_by_step[int(result.get("step_index", 0))] = result
        elif "AgentStep" in event:
            agent_step = event["AgentStep"]
            if isinstance(agent_step, dict):
                agent_step_by_step[int(agent_step.get("step_index", 0))] = agent_step
        elif "ExecutionContractReceipt" in event:
            receipt = event["ExecutionContractReceipt"]
            if isinstance(receipt, dict):
                receipts_by_step[int(receipt.get("step_index", 0))].append(receipt)

    execute_calls = [
        call
        for call in inference_calls
        if call.get("method") in ("execute_inference", "execute_inference_streaming")
    ]
    step_indices = sorted(
        set(routing_by_step.keys())
        | set(result_by_step.keys())
        | set(agent_step_by_step.keys())
        | set(receipts_by_step.keys())
    )
    if not step_indices:
        step_indices = list(range(len(execute_calls)))

    call_by_step: dict[int, dict[str, Any]] = {}
    for index, step_index in enumerate(step_indices):
        if index < len(execute_calls):
            call_by_step[step_index] = execute_calls[index]

    event_transitions = bridge_event_transitions(sync_history_summary(bridge_state))
    timeline: list[dict[str, Any]] = []
    previous_observation_targets: dict[str, str] = {}
    for index, step_index in enumerate(step_indices):
        call = call_by_step.get(step_index, {})
        next_call = (
            call_by_step.get(step_indices[index + 1], {})
            if index + 1 < len(step_indices)
            else {}
        )
        routing = routing_by_step.get(step_index, {})
        result = result_by_step.get(step_index, {})
        agent_step = agent_step_by_step.get(step_index, {})
        step_receipts = receipts_by_step.get(step_index, [])
        system_prompt = extract_system_prompt(call) if call else ""
        chosen_name, chosen_args = parse_tool_call(str(call.get("output_utf8", "")))
        chosen_tool = chosen_name or routing.get("tool_name")
        chosen_arguments = (
            chosen_args if chosen_args is not None else routing.get("action_json")
        )
        observation = extract_section(system_prompt, "RECENT BROWSER OBSERVATION:")
        current_observation_targets = observation_target_map(observation)
        current_target_aliases = observation_target_aliases_from_summaries(
            list(current_observation_targets.values())
        )
        observation_delta = observation_target_delta(
            previous_observation_targets, current_observation_targets
        )
        click_detail = parse_click_action_output(str(result.get("output", ""))) if result else None
        step_start_ms = first_present_int(
            call.get("started_at_ms"),
            receipt_timestamp(step_receipts[0]) if step_receipts else None,
            int(agent_step.get("timestamp", 0) * 1000) if agent_step else None,
        )
        step_end_ms = first_present_int(
            next_call.get("started_at_ms"),
            bridge_state.get("last_sync_ms"),
        )
        requested_id = chosen_args.get("id") if isinstance(chosen_args, dict) else None
        pending_state = extract_section(system_prompt, "RECENT PENDING BROWSER STATE:")
        success_signal = extract_section(system_prompt, "RECENT SUCCESS SIGNAL:")
        recent_session_events = extract_section(system_prompt, "RECENT SESSION EVENTS:")
        clicked_semantic_id = (
            click_detail.get("clicked_semantic_id")
            if isinstance(click_detail, dict)
            else None
        )
        chosen_targets = chosen_target_tokens(
            {
                "chosen_name": chosen_tool,
                "chosen_arguments": chosen_arguments,
                "requested_id": requested_id,
            }
        )
        known_targets_set = (
            set(current_observation_targets.keys())
            | set(current_target_aliases.keys())
            | set(chosen_targets)
        )
        if isinstance(clicked_semantic_id, str):
            known_targets_set.add(clicked_semantic_id)
        known_targets = sorted(known_targets_set)
        pending_targets = referenced_target_tokens(pending_state, known_targets)
        success_targets = referenced_target_tokens(success_signal, known_targets)
        timeline.append(
            {
                "step_index": step_index,
                "agent_step_timestamp_s": agent_step.get("timestamp"),
                "inference_started_at_ms": call.get("started_at_ms"),
                "inference_finished_at_ms": call.get("finished_at_ms"),
                "inference_elapsed_ms": call.get("elapsed_ms"),
                "observation": observation,
                "observation_targets": list(current_observation_targets.values()),
                "observation_delta": observation_delta,
                "target_aliases": current_target_aliases,
                "pending_state": pending_state,
                "pending_targets": pending_targets,
                "pending_alignment": signal_alignment(
                    pending_targets,
                    chosen_targets,
                    current_target_aliases,
                ),
                "success_signal": success_signal,
                "success_targets": success_targets,
                "success_alignment": signal_alignment(
                    success_targets,
                    chosen_targets,
                    current_target_aliases,
                ),
                "recent_session_events": recent_session_events,
                "chosen_name": chosen_tool,
                "chosen_arguments": chosen_arguments,
                "chosen_targets": chosen_targets,
                "inference_raw_output": call.get("output_utf8"),
                "routing_success": routing.get("post_state", {}).get("success"),
                "routing_failure_class": routing.get("failure_class_name"),
                "action_output_summary": summarize_action_result(
                    str(result.get("output", "")),
                    result.get("error_class"),
                )
                if result
                else "",
                "action_error_class": result.get("error_class"),
                "action_click_detail": click_detail,
                "requested_id": requested_id,
                "clicked_semantic_id": clicked_semantic_id,
                "target_mismatch": (
                    isinstance(requested_id, str)
                    and isinstance(clicked_semantic_id, str)
                    and requested_id != clicked_semantic_id
                ),
                "execution_receipts": [
                    {
                        "timestamp_ms": receipt.get("timestamp_ms"),
                        "stage": receipt.get("stage"),
                        "key": receipt.get("key"),
                        "satisfied": receipt.get("satisfied"),
                    }
                    for receipt in step_receipts
                ],
                "bridge_events": event_transitions_for_window(
                    event_transitions,
                    step_start_ms,
                    step_end_ms,
                ),
            }
        )
        previous_observation_targets = current_observation_targets

    for index, step in enumerate(timeline):
        if index == 0:
            step["inference_gap_from_previous_finish_ms"] = None
        else:
            previous_finish_ms = timeline[index - 1].get("inference_finished_at_ms")
            current_start_ms = step.get("inference_started_at_ms")
            if isinstance(previous_finish_ms, int) and isinstance(current_start_ms, int):
                step["inference_gap_from_previous_finish_ms"] = (
                    current_start_ms - previous_finish_ms
                )
            else:
                step["inference_gap_from_previous_finish_ms"] = None

        current_targets = observation_target_map_from_summaries(
            step.get("observation_targets", [])
        )
        next_step = timeline[index + 1] if index + 1 < len(timeline) else None
        if next_step is None:
            step["post_action_observation_delta"] = {
                "added": [],
                "removed": [],
                "changed": [],
            }
            step["post_action_new_target_tokens"] = []
            continue

        next_targets = observation_target_map_from_summaries(
            next_step.get("observation_targets", [])
        )
        post_action_delta = observation_target_delta(current_targets, next_targets)
        step["post_action_observation_delta"] = post_action_delta
        step["post_action_new_target_tokens"] = sorted(
            next_targets.keys() - current_targets.keys()
        )
    return timeline


def first_present_int(*values: Any) -> int | None:
    for value in values:
        if isinstance(value, int):
            return value
    return None


def receipt_timestamp(receipt: dict[str, Any]) -> int | None:
    timestamp_ms = receipt.get("timestamp_ms")
    return timestamp_ms if isinstance(timestamp_ms, int) else None


def interactive_summary(bridge_state: dict[str, Any]) -> list[str]:
    items = bridge_state.get("info", {}).get("interactive_elements", [])
    if not isinstance(items, list):
        return []
    lines: list[str] = []
    for item in items[:8]:
        if not isinstance(item, dict):
            continue
        tag = item.get("tag", "node")
        item_id = item.get("id")
        selector = item.get("selector")
        text = item.get("text")
        name = item.get("name")
        parts = [str(tag)]
        if item_id:
            parts.append(f"id={item_id}")
        if selector:
            parts.append(f"selector={selector}")
        if name:
            parts.append(f"name={compact(str(name), 80)}")
        if text:
            parts.append(f"text={compact(str(text), 80)}")
        lines.append(" | ".join(parts))
    return lines


def sync_history_summary(bridge_state: dict[str, Any]) -> list[dict[str, Any]]:
    raw_history = bridge_state.get("sync_history", [])
    if not isinstance(raw_history, list):
        return []
    history: list[dict[str, Any]] = []
    for entry in raw_history:
        if not isinstance(entry, dict):
            continue
        history.append(entry)
    return history


def bridge_event_transitions(sync_history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    transitions: list[dict[str, Any]] = []
    previous_key: tuple[Any, ...] | None = None
    for entry in sync_history:
        event = entry.get("last_event")
        if not isinstance(event, dict):
            continue
        key = (
            event.get("timestamp_ms"),
            event.get("kind"),
            event.get("target_selector"),
            event.get("target_id"),
            event.get("target_tag"),
            event.get("x"),
            event.get("y"),
        )
        if key == previous_key:
            continue
        transitions.append(
            {
                "sync_index": entry.get("sync_index"),
                "sync_ms": entry.get("last_sync_ms"),
                "episode_step": entry.get("episode_step"),
                "trigger": entry.get("trigger"),
                "reward": entry.get("reward"),
                "raw_reward": entry.get("raw_reward"),
                "terminated": entry.get("terminated"),
                "truncated": entry.get("truncated"),
                "visible_text_excerpt": entry.get("visible_text_excerpt"),
                "last_event": event,
            }
        )
        previous_key = key
    return transitions


def event_transitions_for_window(
    event_transitions: list[dict[str, Any]],
    start_ms: int | None,
    end_ms: int | None,
) -> list[dict[str, Any]]:
    scoped: list[dict[str, Any]] = []
    for entry in event_transitions:
        event = entry.get("last_event")
        if not isinstance(event, dict):
            continue
        event_ms = event.get("timestamp_ms")
        if not isinstance(event_ms, int):
            event_ms = entry.get("sync_ms")
        if isinstance(start_ms, int) and isinstance(event_ms, int) and event_ms < start_ms:
            continue
        if isinstance(end_ms, int) and isinstance(event_ms, int) and event_ms >= end_ms:
            continue
        scoped.append(entry)
    return scoped


def summarize_last_event(entry: dict[str, Any]) -> str:
    event = entry.get("last_event")
    if not isinstance(event, dict):
        return ""
    parts: list[str] = []
    kind = event.get("kind")
    if kind:
        parts.append(str(kind))
    target_selector = event.get("target_selector")
    target_tag = event.get("target_tag")
    target_id = event.get("target_id")
    if target_selector:
        parts.append(f"target={target_selector}")
    elif target_id:
        parts.append(f"id={target_id}")
    elif target_tag:
        parts.append(f"tag={target_tag}")
    x = event.get("x")
    y = event.get("y")
    if x is not None and y is not None:
        parts.append(f"x={x}")
        parts.append(f"y={y}")
    timestamp_ms = event.get("timestamp_ms")
    if timestamp_ms is not None:
        parts.append(f"at={timestamp_ms}")
    return " ".join(parts)


def render_sync_history(sync_history: list[dict[str, Any]]) -> list[str]:
    if not sync_history:
        return ["- unavailable"]

    lines: list[str] = []
    previous: dict[str, Any] | None = None
    for index, entry in enumerate(sync_history):
        sync_ms = entry.get("last_sync_ms")
        delta_suffix = ""
        if previous is not None:
            previous_ms = previous.get("last_sync_ms")
            if isinstance(sync_ms, int) and isinstance(previous_ms, int):
                delta_suffix = f" (+{sync_ms - previous_ms} ms)"
        flags: list[str] = []
        if previous is None or entry.get("reward") != previous.get("reward"):
            flags.append("reward_change")
        if previous is None or entry.get("terminated") != previous.get("terminated"):
            flags.append("termination_change")
        if previous is None or entry.get("visible_text_excerpt") != previous.get(
            "visible_text_excerpt"
        ):
            flags.append("surface_change")
        if previous is None or entry.get("trigger") != previous.get("trigger"):
            flags.append("trigger_change")
        sync_index = entry.get("sync_index", index)
        focus = "/".join(
            str(part)
            for part in [entry.get("focused_tag"), entry.get("focused_id")]
            if part not in (None, "")
        )
        focus_part = f" focus={focus}" if focus else ""
        flags_part = f" flags={','.join(flags)}" if flags else ""
        last_event = summarize_last_event(entry)
        event_part = f" last_event={last_event}" if last_event else ""
        lines.append(
            "- sync "
            f"{sync_index} @ {sync_ms}{delta_suffix}: "
            f"trigger={entry.get('trigger')} "
            f"step={entry.get('episode_step')} "
            f"reward={entry.get('reward')} "
            f"raw_reward={entry.get('raw_reward')} "
            f"terminated={entry.get('terminated')} "
            f"truncated={entry.get('truncated')} "
            f"interactive={entry.get('interactive_count')} "
            f"scroll_targets={entry.get('scroll_target_count')} "
            f"dom={entry.get('dom_count')}"
            f"{focus_part}{event_part}{flags_part} "
            f"excerpt=\"{compact(str(entry.get('visible_text_excerpt', '')), 180)}\""
        )
        previous = entry
    return lines


def render_phase_timing(summary: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    ordered_keys = [
        "bootstrap_sync_ms",
        "browser_launch_started_at_ms",
        "browser_launch_finished_at_ms",
        "session_created_at_ms",
        "browser_navigation_started_at_ms",
        "browser_navigation_finished_at_ms",
        "initial_bridge_ready_observed_at_ms",
        "agent_start_service_started_at_ms",
        "agent_start_service_finished_at_ms",
        "first_step_service_started_at_ms",
        "first_inference_started_at_ms",
        "first_inference_finished_at_ms",
        "first_execution_receipt_ms",
        "first_bridge_input_event_ms",
        "first_grounded_target_event_ms",
        "terminal_sync_ms",
        "first_step_service_finished_at_ms",
        "case_finished_at_ms",
    ]
    for key in ordered_keys:
        value = summary.get(key)
        if value is None:
            continue
        delta_key = f"{key}_delta_from_bootstrap_ms"
        delta = summary.get(delta_key)
        delta_part = f" (+{delta} ms from bootstrap)" if isinstance(delta, int) else ""
        lines.append(f"- {key}: `{value}`{delta_part}")
    if summary.get("first_inference_tool"):
        lines.append(f"- first_inference_tool: `{summary['first_inference_tool']}`")
    if summary.get("first_inference_elapsed_ms") is not None:
        lines.append(
            f"- first_inference_elapsed_ms: `{summary['first_inference_elapsed_ms']}`"
        )
    derived_keys = [
        "bootstrap_to_first_inference_start_ms",
        "bootstrap_to_first_grounded_target_ms",
        "first_inference_finish_to_first_receipt_ms",
        "first_receipt_to_first_grounded_target_ms",
        "first_grounded_target_to_terminal_ms",
        "terminal_to_step_finish_tail_ms",
    ]
    for key in derived_keys:
        value = summary.get(key)
        if value is not None:
            lines.append(f"- {key}: `{value}`")
    for key in [
        "service_prepare_tool",
        "service_determinism_context",
        "service_policy_gate",
        "service_focus_recovery",
        "service_executor_dispatch",
        "service_finalize_executor_result",
        "service_action_complete",
    ]:
        elapsed = summary.get(f"{key}_elapsed_ms")
        if elapsed is None:
            continue
        status = summary.get(f"{key}_status")
        status_part = f" status=`{status}`" if status is not None else ""
        lines.append(f"- {key}_elapsed_ms: `{elapsed}`{status_part}")
    return lines or ["- unavailable"]


def render_inference_calls(inference_calls: list[dict[str, Any]]) -> list[str]:
    if not inference_calls:
        return ["- unavailable"]
    lines: list[str] = []
    previous_finished_ms = None
    for call in inference_calls:
        started_ms = call.get("started_at_ms")
        finished_ms = call.get("finished_at_ms")
        elapsed_ms = call.get("elapsed_ms")
        delta_suffix = ""
        if isinstance(started_ms, int) and isinstance(previous_finished_ms, int):
            delta_suffix = f" (+{started_ms - previous_finished_ms} ms since previous finish)"
        chosen_name, chosen_args = parse_tool_call(str(call.get("output_utf8", "")))
        tool_suffix = f" tool={chosen_name}" if chosen_name else ""
        lines.append(
            "- call "
            f"{call.get('ordinal')}: method={call.get('method')} "
            f"start={started_ms} finish={finished_ms} elapsed={elapsed_ms}"
            f"{tool_suffix}{delta_suffix}"
        )
        source_hint = call.get("source_hint")
        if isinstance(source_hint, str) and source_hint.strip():
            lines.append(f"  source={compact(source_hint, 220)}")
        if chosen_args is not None:
            lines.append(
                f"  arguments={compact(json.dumps(chosen_args, ensure_ascii=True), 220)}"
            )
        if isinstance(finished_ms, int):
            previous_finished_ms = finished_ms
    return lines


def render_execution_receipts(receipts: list[dict[str, Any]]) -> list[str]:
    if not receipts:
        return ["- unavailable"]
    lines: list[str] = []
    previous_ms = None
    for receipt in receipts:
        timestamp_ms = receipt.get("timestamp_ms")
        delta_suffix = ""
        if isinstance(timestamp_ms, int) and isinstance(previous_ms, int):
            delta_suffix = f" (+{timestamp_ms - previous_ms} ms)"
        lines.append(
            "- receipt "
            f"@ {timestamp_ms}{delta_suffix}: "
            f"step={receipt.get('step_index')} "
            f"stage={receipt.get('stage')} "
            f"key={receipt.get('key')} "
            f"satisfied={receipt.get('satisfied')}"
        )
        probe_source = receipt.get("probe_source")
        if isinstance(probe_source, str) and probe_source.strip():
            lines.append(f"  probe_source={compact(probe_source, 220)}")
        evidence_type = receipt.get("evidence_type")
        if isinstance(evidence_type, str) and evidence_type.strip():
            lines.append(f"  evidence_type={compact(evidence_type, 220)}")
        observed_value = receipt.get("observed_value")
        if observed_value is not None:
            if isinstance(observed_value, (dict, list)):
                rendered = json.dumps(observed_value, ensure_ascii=True, sort_keys=True)
            else:
                rendered = str(observed_value)
            lines.append(f"  observed={compact(rendered, 220)}")
        if isinstance(timestamp_ms, int):
            previous_ms = timestamp_ms
    return lines


def render_step_bridge_events(events: list[dict[str, Any]]) -> list[str]:
    if not events:
        return ["- none"]
    lines: list[str] = []
    for entry in events[:12]:
        last_event = summarize_last_event(entry)
        lines.append(
            "- event "
            f"sync={entry.get('sync_index')} "
            f"sync_ms={entry.get('sync_ms')} "
            f"step={entry.get('episode_step')} "
            f"trigger={entry.get('trigger')} "
            f"reward={entry.get('reward')} "
            f"terminated={entry.get('terminated')} "
            f"{last_event}"
        )
    if len(events) > 12:
        lines.append(f"- ... {len(events) - 12} more event transitions")
    return lines


def render_observation_delta(delta: dict[str, Any]) -> list[str]:
    if not isinstance(delta, dict):
        return ["- none"]
    lines: list[str] = []
    for label in ("added", "removed", "changed"):
        entries = delta.get(label)
        if not isinstance(entries, list) or not entries:
            continue
        for entry in entries[:6]:
            lines.append(f"- {label}: {entry}")
        if len(entries) > 6:
            lines.append(f"- {label}: ... {len(entries) - 6} more")
    return lines or ["- none"]


def render_step_outcome_matrix(timeline: list[dict[str, Any]]) -> list[str]:
    if not timeline:
        return ["- unavailable"]

    lines: list[str] = []
    for step in timeline:
        chosen_name = step.get("chosen_name") or "unknown"
        chosen_arguments = compact(
            json.dumps(step.get("chosen_arguments"), ensure_ascii=True),
            120,
        )
        pending_alignment = step.get("pending_alignment") or "none"
        success_alignment = step.get("success_alignment") or "none"
        gap = step.get("inference_gap_from_previous_finish_ms")
        gap_part = f", gap_since_previous_finish_ms={gap}" if isinstance(gap, int) else ""
        outcome_parts = [
            f"- step {step.get('step_index')}: tool={chosen_name}",
            f"args={chosen_arguments}",
            f"pending={pending_alignment}",
            f"success={success_alignment}",
        ]
        new_tokens = step.get("post_action_new_target_tokens")
        if isinstance(new_tokens, list) and new_tokens:
            outcome_parts.append(
                "new_targets_after_action="
                + compact(json.dumps(new_tokens, ensure_ascii=True), 120)
            )
        bridge_events = step.get("bridge_events")
        if isinstance(bridge_events, list) and bridge_events:
            first_event = summarize_last_event(bridge_events[0])
            if first_event:
                outcome_parts.append(f"first_bridge_event={compact(first_event, 100)}")
        action_output_summary = step.get("action_output_summary")
        if action_output_summary:
            outcome_parts.append(f"result={compact(str(action_output_summary), 140)}")
        lines.append(", ".join(outcome_parts) + gap_part)
    return lines


def render_markdown(
    case_dir: Path,
    inference_trace: dict[str, Any],
    inference_calls: list[dict[str, Any]],
    bridge_state: dict[str, Any],
    kernel_events: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
) -> str:
    info = bridge_state.get("info", {})
    sync_history = sync_history_summary(bridge_state)
    timing_summary = phase_timing_summary(
        inference_trace, inference_calls, bridge_state, kernel_events
    )
    findings = derive_findings(timeline, bridge_state, timing_summary)
    receipts = execution_receipt_timeline(kernel_events)
    lines = [
        "# MiniWoB Case Diagnostic",
        "",
        "## Summary",
        f"- case_dir: `{case_dir}`",
        f"- env_id: `{bridge_state.get('env_id', '')}`",
        f"- model: `{inference_trace.get('model', '')}`",
        f"- backend: `{inference_trace.get('backend', '')}`",
        f"- provider_calls: `{inference_trace.get('call_count', 0)}`",
        f"- reward: `{bridge_state.get('reward', '')}`",
        f"- raw_reward: `{info.get('raw_reward', '')}`",
        f"- terminated: `{bridge_state.get('terminated', False)}`",
        f"- truncated: `{bridge_state.get('truncated', False)}`",
        f"- episode_step: `{bridge_state.get('episode_step', '')}`",
        f"- final_trigger: `{info.get('trigger', '')}`",
        f"- final_last_event: `{summarize_last_event(info)}`",
        f"- sync_count: `{len(sync_history)}`",
        f"- query_text: `{info.get('query_text', bridge_state.get('utterance', ''))}`",
        "",
        "## Final Surface",
        f"- visible_text_excerpt: `{compact(str(info.get('visible_text_excerpt', '')), 300)}`",
        f"- page_url: `{info.get('page_url', '')}`",
        "",
        "## Findings",
    ]

    if findings:
        for finding in findings:
            lines.append(f"- {finding}")
    else:
        lines.append("- no automatic findings")

    lines.extend([
        "",
        "### Interactive Elements",
    ])

    for item in interactive_summary(bridge_state):
        lines.append(f"- {item}")

    lines.extend(["", "## Phase Timing"])
    lines.extend(render_phase_timing(timing_summary))

    lines.extend(["", "## Inference Calls"])
    lines.extend(render_inference_calls(inference_calls))

    lines.extend(["", "## Step Outcome Matrix"])
    lines.extend(render_step_outcome_matrix(timeline))

    lines.extend(["", "## Execution Receipts"])
    lines.extend(render_execution_receipts(receipts))

    lines.extend(["", "## Bridge Sync History"])
    lines.extend(render_sync_history(sync_history))

    lines.extend(["", "## Agent Timeline"])
    for step in timeline:
        chosen_arguments = json.dumps(step.get("chosen_arguments"), ensure_ascii=True)
        lines.extend(
            [
                f"### Step {step['step_index']}",
                f"- chosen_tool: `{step.get('chosen_name')}`",
                f"- chosen_arguments: `{chosen_arguments}`",
            ]
        )
        if step.get("agent_step_timestamp_s") is not None:
            lines.append(
                f"- agent_step_timestamp_s: `{step.get('agent_step_timestamp_s')}`"
            )
        if step.get("inference_started_at_ms") is not None:
            lines.append(
                f"- inference_started_at_ms: `{step.get('inference_started_at_ms')}`"
            )
        if step.get("inference_finished_at_ms") is not None:
            lines.append(
                f"- inference_finished_at_ms: `{step.get('inference_finished_at_ms')}`"
            )
        if step.get("inference_elapsed_ms") is not None:
            lines.append(f"- inference_elapsed_ms: `{step.get('inference_elapsed_ms')}`")
        if step.get("inference_gap_from_previous_finish_ms") is not None:
            lines.append(
                "- inference_gap_from_previous_finish_ms: "
                f"`{step.get('inference_gap_from_previous_finish_ms')}`"
            )
        if step.get("observation"):
            lines.append(
                f"- observation: `{compact(str(step.get('observation')), 400)}`"
            )
        observation_targets = step.get("observation_targets")
        if isinstance(observation_targets, list) and observation_targets:
            lines.append("- observation_targets:")
            for summary in observation_targets[:8]:
                lines.append(f"  - `{compact(str(summary), 220)}`")
            if len(observation_targets) > 8:
                lines.append(f"  - `... {len(observation_targets) - 8} more`")
        lines.append("- observation_delta:")
        lines.extend(render_observation_delta(step.get("observation_delta", {})))
        lines.append("- post_action_observation_delta:")
        lines.extend(
            render_observation_delta(step.get("post_action_observation_delta", {}))
        )
        post_action_new_target_tokens = step.get("post_action_new_target_tokens")
        if isinstance(post_action_new_target_tokens, list) and post_action_new_target_tokens:
            lines.append(
                f"- post_action_new_target_tokens: `{post_action_new_target_tokens}`"
            )
        if step.get("pending_state"):
            lines.append(
                f"- pending_state: `{compact(str(step.get('pending_state')), 240)}`"
            )
        pending_targets = step.get("pending_targets")
        if isinstance(pending_targets, list) and pending_targets:
            lines.append(f"- pending_targets: `{pending_targets}`")
            if step.get("pending_alignment"):
                lines.append(
                    f"- pending_alignment: `{step.get('pending_alignment')}`"
                )
        if step.get("success_signal"):
            lines.append(
                f"- success_signal: `{compact(str(step.get('success_signal')), 240)}`"
            )
        success_targets = step.get("success_targets")
        if isinstance(success_targets, list) and success_targets:
            lines.append(f"- success_targets: `{success_targets}`")
            if step.get("success_alignment"):
                lines.append(
                    f"- success_alignment: `{step.get('success_alignment')}`"
                )
        if step.get("recent_session_events"):
            lines.append(
                f"- recent_session_events: `{compact(str(step.get('recent_session_events')), 240)}`"
            )
        chosen_targets = step.get("chosen_targets")
        if isinstance(chosen_targets, list) and chosen_targets:
            lines.append(f"- chosen_targets: `{chosen_targets}`")
        lines.append(f"- routing_success: `{step.get('routing_success')}`")
        if step.get("routing_failure_class"):
            lines.append(
                f"- routing_failure_class: `{step.get('routing_failure_class')}`"
            )
        if step.get("action_output_summary"):
            lines.append(
                f"- action_result: `{compact(str(step.get('action_output_summary')), 400)}`"
            )
        if step.get("action_error_class"):
            lines.append(f"- action_error_class: `{step.get('action_error_class')}`")
        click_detail = step.get("action_click_detail")
        if isinstance(click_detail, dict):
            lines.append(
                f"- clicked_semantic_id: `{click_detail.get('clicked_semantic_id')}`"
            )
            lines.append(f"- click_delivery: `{click_detail.get('delivery')}`")
            if click_detail.get("verify_method") is not None:
                lines.append(
                    f"- click_verify_method: `{click_detail.get('verify_method')}`"
                )
            if click_detail.get("dispatch_succeeded") is not None:
                lines.append(
                    f"- click_dispatch_succeeded: `{click_detail.get('dispatch_succeeded')}`"
                )
            post_target = click_detail.get("post_target")
            if isinstance(post_target, dict):
                lines.append(
                    f"- post_target: `{compact(json.dumps(post_target, ensure_ascii=True), 220)}`"
                )
        if step.get("requested_id") is not None:
            lines.append(f"- requested_id: `{step.get('requested_id')}`")
        if step.get("clicked_semantic_id") is not None:
            lines.append(
                f"- executed_target_semantic_id: `{step.get('clicked_semantic_id')}`"
            )
        if step.get("target_mismatch"):
            lines.append(
                "- target_alignment: `requested_id differs from executed target semantic id`"
            )
        if step.get("inference_raw_output"):
            lines.append(
                f"- raw_model_output: `{compact(str(step.get('inference_raw_output')), 240)}`"
            )
        lines.append("- step_bridge_events:")
        lines.extend(render_step_bridge_events(step.get("bridge_events", [])))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def resolve_case_dir(args: argparse.Namespace) -> Path:
    if args.case_dir:
        return Path(args.case_dir).resolve()
    if args.run_dir and args.case:
        return (Path(args.run_dir) / "agent" / args.case).resolve()
    if args.latest and args.case:
        repo_root = Path(__file__).resolve().parents[2]
        run_root = repo_root / "crates" / "cli" / "target" / "computer_use_suite"
        candidates = sorted(run_root.glob("run-*"), key=lambda path: path.stat().st_mtime)
        if not candidates:
            raise SystemExit("No MiniWoB run directories found.")
        return (candidates[-1] / "agent" / args.case).resolve()
    raise SystemExit("Pass --case-dir or --run-dir with --case, or use --latest with --case.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a MiniWoB case play-by-play report.")
    parser.add_argument("--case-dir")
    parser.add_argument("--run-dir")
    parser.add_argument("--case")
    parser.add_argument("--latest", action="store_true")
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args()

    case_dir = resolve_case_dir(args)
    inference_trace = load_json(case_dir / "inference_trace.json", {})
    inference_calls = load_json(case_dir / "inference_calls.json", [])
    bridge_state = load_json(case_dir / "bridge_state.json", {})
    kernel_events = load_json(case_dir / "kernel_events.json", [])

    inference_calls = inference_calls if isinstance(inference_calls, list) else []
    kernel_events = kernel_events if isinstance(kernel_events, list) else []
    timeline = build_timeline(inference_calls, kernel_events, bridge_state)
    sync_history = sync_history_summary(bridge_state)
    receipts = execution_receipt_timeline(kernel_events)
    timing_summary = phase_timing_summary(
        inference_trace,
        inference_calls,
        bridge_state,
        kernel_events,
    )
    info = bridge_state.get("info", {})
    summary = {
        "case_dir": str(case_dir),
        "summary": {
            "env_id": bridge_state.get("env_id"),
            "model": inference_trace.get("model"),
            "backend": inference_trace.get("backend"),
            "provider_calls": inference_trace.get("call_count", 0),
            "reward": bridge_state.get("reward"),
            "raw_reward": info.get("raw_reward"),
            "terminated": bridge_state.get("terminated"),
            "truncated": bridge_state.get("truncated"),
            "episode_step": bridge_state.get("episode_step"),
            "final_trigger": info.get("trigger"),
            "final_last_event": summarize_last_event(info),
            "sync_count": len(sync_history),
            "query_text": info.get("query_text", bridge_state.get("utterance", "")),
        },
        "findings": derive_findings(timeline, bridge_state, timing_summary),
        "inference_calls": inference_calls,
        "inference_trace": inference_trace,
        "bridge_state": bridge_state,
        "phase_timing": timing_summary,
        "execution_receipts": receipts,
        "sync_history": sync_history,
        "bridge_event_transitions": bridge_event_transitions(sync_history),
        "timeline": timeline,
    }
    markdown = render_markdown(
        case_dir,
        inference_trace,
        inference_calls,
        bridge_state,
        kernel_events,
        timeline,
    )

    json_path = case_dir / "diagnostic_summary.json"
    markdown_path = case_dir / "diagnostic_summary.md"
    json_path.write_text(json.dumps(summary, indent=2))
    markdown_path.write_text(markdown)

    print(f"diagnostic_json={json_path}")
    print(f"diagnostic_markdown={markdown_path}")
    if args.stdout:
        print()
        print(markdown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
