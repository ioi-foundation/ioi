use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;
use std::collections::BTreeSet;

use super::super::types::{
    action_has_hard_error_class, contains_any, has_cec_receipt, has_cec_stage,
    has_contract_failure_evidence, has_tool_with_token, is_retry_blocked_terminal, truncate_chars,
    verification_bool, verification_u64, verification_value, ExecutionProfile, LocalCheck,
    LocalJudgeResult, QueryCase, RunObservation,
};

#[derive(Debug, Clone, Serialize)]
struct EnvironmentEvidenceReceipt {
    key: &'static str,
    observed_value: String,
    probe_source: &'static str,
    timestamp_ms: u64,
    satisfied: bool,
}

pub fn case() -> QueryCase {
    QueryCase {
        id: "find_all_pdf_files_on_my_computer_modified_in_the_last_week",
        query: "Find all PDF files on my computer modified in the last week. Use local filesystem tools to discover candidate PDFs and verify modification timestamps. Then provide a concise completion summary that lists matching absolute paths, or explicitly states that no matches were found.",
        success_definition: "Execute a local filesystem search constrained to PDF files and a last-week modification window, verify timestamp metadata, return either concrete results or explicit zero-results, and avoid unrelated mutating filesystem actions.",
        seeded_intent_id: "workspace.ops.search_local_files",
        intent_scope: IntentScopeProfile::WorkspaceOps,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::PolicyGate,
        sla_seconds: 90,
        max_steps: 18,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: true,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let mut evidence_segments = Vec::<String>::new();
    evidence_segments.push(obs.final_reply.clone());
    evidence_segments.extend(obs.verification_checks.iter().cloned());
    evidence_segments.extend(obs.event_excerpt.iter().cloned());
    evidence_segments.extend(obs.action_evidence.iter().map(|entry| {
        format!(
            "{} {} {}",
            entry.tool_name, entry.agent_status, entry.output_excerpt
        )
    }));

    let search_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_local_pdf_search_success_event(entry))
        .count();
    let search_action_failure_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_local_pdf_search_failure_event(entry))
        .count();

    let pdf_filter_hits = evidence_segments
        .iter()
        .filter(|segment| contains_pdf_filter_token(segment))
        .count();
    let recent_window_hits = evidence_segments
        .iter()
        .filter(|segment| contains_recent_window_token(segment))
        .count();
    let search_invocation_hits = evidence_segments
        .iter()
        .filter(|segment| contains_search_command_token(segment))
        .count();
    let pdf_path_hits = evidence_segments
        .iter()
        .filter(|segment| contains_pdf_path_token(segment))
        .count();
    let explicit_zero_result_signal = evidence_segments
        .iter()
        .any(|segment| contains_zero_result_marker(segment));
    let explicit_result_listing_signal = pdf_path_hits > 0;
    let result_or_zero_signal = explicit_result_listing_signal || explicit_zero_result_signal;
    let retry_blocked_terminal = is_retry_blocked_terminal(obs);
    let baseline_pdf_paths = baseline_pdf_matches(obs);
    let final_reply_pdf_paths = extract_pdf_paths(&obs.final_reply);
    let all_baseline_matches_reported = if baseline_pdf_paths.is_empty() {
        result_or_zero_signal
    } else {
        let intersection_count = baseline_pdf_paths
            .iter()
            .filter(|path| final_reply_pdf_paths.contains(*path))
            .count();
        (baseline_pdf_paths
            .iter()
            .any(|path| final_reply_pdf_paths.contains(path))
            && intersection_count >= 1)
            || (retry_blocked_terminal && result_or_zero_signal)
    };

    let action_path_seen = has_local_pdf_search_tool(&obs.action_tools);
    let routing_path_seen = has_local_pdf_search_tool(&obs.routing_tools);
    let remote_retrieval_path_seen = has_tool_with_token(&obs.action_tools, "web__search")
        || has_tool_with_token(&obs.action_tools, "web__read")
        || has_tool_with_token(&obs.routing_tools, "web__search")
        || has_tool_with_token(&obs.routing_tools, "web__read")
        || has_tool_with_token(&obs.workload_tools, "web__search")
        || has_tool_with_token(&obs.workload_tools, "web__read")
        || has_tool_with_token(&obs.action_tools, "net__fetch")
        || has_tool_with_token(&obs.routing_tools, "net__fetch")
        || has_tool_with_token(&obs.workload_tools, "net__fetch");

    let cec_discovery_seen = has_cec_stage(obs, "discovery", Some(true));
    let cec_provider_selection_seen = has_cec_stage(obs, "provider_selection", Some(true));
    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_postcondition_seen =
        has_cec_receipt(obs, "execution", "execution_artifact", Some(true))
            || has_cec_receipt(obs, "verification", "verification_commit", Some(true))
            || has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_phase_receipts_present = obs.cec_receipts.is_empty()
        || (cec_discovery_seen
            && cec_provider_selection_seen
            && cec_execution_seen
            && cec_verification_seen
            && cec_postcondition_seen);

    let host_home_dir = verification_value(obs, "host_home_dir");
    let host_discovery_probe_source = verification_value(obs, "host_discovery_probe_source");
    let host_discovery_timestamp_ms = verification_u64(obs, "host_discovery_timestamp_ms");
    let host_discovery_satisfied =
        verification_bool(obs, "host_discovery_satisfied").unwrap_or(false);

    let any_contract_failure_marker = has_contract_failure_evidence(obs);
    let unrelated_mutating_action_seen = has_unrelated_mutating_action(obs);
    let completion_evidence_present = obs.completed
        && !obs.failed
        && ((!obs.final_reply.trim().is_empty() && obs.chat_reply_count > 0)
            || search_action_success_count > 0)
        && all_baseline_matches_reported
        || (retry_blocked_terminal
            && !obs.failed
            && search_action_success_count > 0
            && search_action_failure_count == 0
            && result_or_zero_signal
            && !any_contract_failure_marker
            && !unrelated_mutating_action_seen);
    let objective_specific_pdf_last_week_search_evidence_present = search_action_success_count > 0
        && search_action_failure_count == 0
        && pdf_filter_hits > 0
        && recent_window_hits > 0
        && search_invocation_hits > 0
        && result_or_zero_signal
        && all_baseline_matches_reported
        && !any_contract_failure_marker;
    let tool_and_route_path_evidence_present =
        action_path_seen && routing_path_seen && !remote_retrieval_path_seen;
    let result_quality_evidence_present = result_or_zero_signal;

    let environment_receipts = build_environment_receipts(
        obs,
        host_home_dir.clone(),
        host_discovery_probe_source.clone(),
        host_discovery_timestamp_ms,
        host_discovery_satisfied,
        pdf_filter_hits,
        recent_window_hits,
        search_action_success_count,
        search_action_failure_count,
        result_or_zero_signal,
        cec_phase_receipts_present,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_pdf_last_week_search_evidence_present,
        tool_and_route_path_evidence_present,
        cec_phase_receipts_present,
        result_quality_evidence_present,
        !unrelated_mutating_action_seen,
        !any_contract_failure_marker,
        environment_receipts_satisfied,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_pdf_last_week_search_evidence_present && independent_channel_count >= 6;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} chat_reply_count={} reply_len={} search_action_success_count={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                obs.chat_reply_count,
                obs.final_reply.chars().count(),
                search_action_success_count
            ),
        ),
        LocalCheck::new(
            "objective_specific_pdf_last_week_search_evidence_present",
            objective_specific_pdf_last_week_search_evidence_present,
            format!(
                "search_action_success_count={} search_action_failure_count={} pdf_filter_hits={} recent_window_hits={} search_invocation_hits={} pdf_path_hits={} explicit_zero_result_signal={}",
                search_action_success_count,
                search_action_failure_count,
                pdf_filter_hits,
                recent_window_hits,
                search_invocation_hits,
                pdf_path_hits,
                explicit_zero_result_signal
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!(
                "action_tools={:?} routing_tools={:?} workload_tools={:?} remote_retrieval_path_seen={}",
                obs.action_tools, obs.routing_tools, obs.workload_tools, remote_retrieval_path_seen
            ),
        ),
        LocalCheck::new(
            "cec_phase_receipts_present",
            cec_phase_receipts_present,
            format!(
                "discovery={} provider_selection={} execution={} verification={} postcondition={} verification_checks={:?}",
                cec_discovery_seen,
                cec_provider_selection_seen,
                cec_execution_seen,
                cec_verification_seen,
                cec_postcondition_seen,
                obs.verification_checks
            ),
        ),
        LocalCheck::new(
            "result_quality_evidence_present",
            result_quality_evidence_present,
            truncate_chars(
                &format!(
                    "pdf_path_hits={} explicit_zero_result_signal={} final_reply={} action_evidence={:?}",
                    pdf_path_hits,
                    explicit_zero_result_signal,
                    obs.final_reply,
                    obs.action_evidence.iter().take(3).collect::<Vec<_>>()
                ),
                240,
            ),
        ),
        LocalCheck::new(
            "all_detected_pdf_matches_reported",
            all_baseline_matches_reported,
            format!(
                "baseline_count={} final_reply_count={} missing={:?}",
                baseline_pdf_paths.len(),
                final_reply_pdf_paths.len(),
                baseline_pdf_paths
                    .iter()
                    .filter(|path| !final_reply_pdf_paths.contains(*path))
                    .cloned()
                    .collect::<Vec<_>>()
            ),
        ),
        LocalCheck::new(
            "no_unrelated_mutating_actions",
            !unrelated_mutating_action_seen,
            truncate_chars(
                &format!(
                    "action_tools={:?} action_evidence={:?}",
                    obs.action_tools,
                    obs.action_evidence.iter().take(5).collect::<Vec<_>>()
                ),
                240,
            ),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            !any_contract_failure_marker,
            truncate_chars(
                &format!(
                    "verification_checks={:?} final_reply={} event_excerpt={:?}",
                    obs.verification_checks, obs.final_reply, obs.event_excerpt
                ),
                240,
            ),
        ),
        LocalCheck::new(
            "environment_receipts_satisfied",
            environment_receipts_satisfied,
            serialize_environment_receipts(&environment_receipts),
        ),
        LocalCheck::new(
            "independent_runtime_evidence_channels_present",
            independent_runtime_evidence_channels_present,
            format!(
                "independent_channel_count={} objective_specific_pdf_last_week_search_evidence_present={}",
                independent_channel_count, objective_specific_pdf_last_week_search_evidence_present
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn is_local_pdf_search_success_event(entry: &super::super::types::ActionEvidence) -> bool {
    if !is_local_pdf_search_related_event(entry) {
        return false;
    }
    let tool_lower = entry.tool_name.to_ascii_lowercase();
    let status_ok = entry.agent_status.eq_ignore_ascii_case("completed")
        || (tool_lower.contains("sys__exec") && entry.agent_status.eq_ignore_ascii_case("running"))
        || ((tool_lower == "filesystem__search"
            || tool_lower == "filesystem__list_directory"
            || tool_lower == "filesystem__stat")
            && entry.agent_status.eq_ignore_ascii_case("running"));
    if !status_ok {
        return false;
    }
    let output_lower = entry.output_excerpt.to_ascii_lowercase();
    !action_has_hard_error_class(entry) && sys_exec_exit_status_satisfied(&output_lower)
}

fn is_local_pdf_search_failure_event(entry: &super::super::types::ActionEvidence) -> bool {
    if !is_local_pdf_search_related_event(entry) {
        return false;
    }
    let output_lower = entry.output_excerpt.to_ascii_lowercase();
    entry.agent_status.eq_ignore_ascii_case("failed")
        || action_has_hard_error_class(entry)
        || !sys_exec_exit_status_satisfied(&output_lower)
}

fn is_local_pdf_search_related_event(entry: &super::super::types::ActionEvidence) -> bool {
    let tool_lower = entry.tool_name.to_ascii_lowercase();
    let output_lower = entry.output_excerpt.to_ascii_lowercase();
    let local_tool = tool_lower.contains("sys__exec")
        || tool_lower == "filesystem__search"
        || tool_lower == "filesystem__list_directory"
        || tool_lower == "filesystem__stat";
    local_tool
        && (contains_search_command_token(&output_lower)
            || contains_pdf_filter_token(&output_lower)
            || contains_recent_window_token(&output_lower))
}

fn sys_exec_exit_status_satisfied(output_lower: &str) -> bool {
    if !output_lower.contains("\"exit_code\":") {
        return true;
    }
    if output_lower.contains("\"exit_code\":0") {
        return true;
    }
    output_lower.contains("\"exit_code\":1") && contains_zero_result_marker(output_lower)
}

fn has_local_pdf_search_tool(tools: &[String]) -> bool {
    has_tool_with_token(tools, "sys__exec")
        || has_tool_with_token(tools, "filesystem__search")
        || has_tool_with_token(tools, "filesystem__list_directory")
        || has_tool_with_token(tools, "filesystem__stat")
}

fn build_environment_receipts(
    obs: &RunObservation,
    host_home_dir: Option<String>,
    host_discovery_probe_source: Option<String>,
    host_discovery_timestamp_ms: Option<u64>,
    host_discovery_satisfied: bool,
    pdf_filter_hits: usize,
    recent_window_hits: usize,
    search_action_success_count: usize,
    search_action_failure_count: usize,
    result_or_zero_signal: bool,
    cec_phase_receipts_present: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "host_discovery_receipt_observed",
            observed_value: format!(
                "host_home_dir={:?} host_discovery_probe_source={:?} host_discovery_timestamp_ms={:?} host_discovery_satisfied={}",
                host_home_dir,
                host_discovery_probe_source,
                host_discovery_timestamp_ms,
                host_discovery_satisfied
            ),
            probe_source: "RunObservation.verification_facts",
            timestamp_ms: host_discovery_timestamp_ms.unwrap_or(obs.run_timestamp_ms),
            satisfied: (host_discovery_satisfied
                && host_home_dir.is_some()
                && host_discovery_probe_source.is_some()
                && host_discovery_timestamp_ms.is_some())
                || obs.cec_receipts.is_empty(),
        },
        EnvironmentEvidenceReceipt {
            key: "pdf_filter_constraint_observed",
            observed_value: format!("pdf_filter_hits={}", pdf_filter_hits),
            probe_source: "KernelEvent::AgentActionResult.output_excerpt + chat__reply",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: pdf_filter_hits > 0,
        },
        EnvironmentEvidenceReceipt {
            key: "last_week_time_window_constraint_observed",
            observed_value: format!("recent_window_hits={}", recent_window_hits),
            probe_source: "KernelEvent::AgentActionResult.output_excerpt + chat__reply",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: recent_window_hits > 0,
        },
        EnvironmentEvidenceReceipt {
            key: "local_search_execution_observed",
            observed_value: format!(
                "search_action_success_count={} search_action_failure_count={} cec_phase_receipts_present={}",
                search_action_success_count, search_action_failure_count, cec_phase_receipts_present
            ),
            probe_source:
                "KernelEvent::AgentActionResult(tool=sys__exec|filesystem__search) + verification_checks",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: search_action_success_count > 0
                && search_action_failure_count == 0
                && cec_phase_receipts_present,
        },
        EnvironmentEvidenceReceipt {
            key: "search_outcome_observed",
            observed_value: format!("result_or_zero_signal={}", result_or_zero_signal),
            probe_source: "chat__reply + KernelEvent::AgentActionResult.output_excerpt",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: result_or_zero_signal,
        },
    ]
}

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}

fn contains_pdf_filter_token(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "*.pdf",
            ".pdf",
            "pdf file",
            "pdf files",
            "extension -eq '.pdf'",
            "extension -eq \".pdf\"",
            "like '*.pdf'",
            "like \".pdf\"",
            "file_filter",
        ],
    )
}

fn contains_recent_window_token(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "-mtime -7",
            "-newermt",
            "last week",
            "last 7 days",
            "within the last week",
            "within the last 7 days",
            "past week",
            "adddays(-7)",
            "dateadd(day,-7",
            "lastwritetime",
            "modified in the last week",
            "modified_epoch_ms",
        ],
    )
}

fn contains_search_command_token(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "command_history:",
            "find ",
            "fd ",
            "locate ",
            "get-childitem",
            "gci ",
            "filesystem__search",
            "filesystem__list_directory",
            "filesystem__stat",
        ],
    )
}

fn contains_pdf_path_token(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if !lower.contains(".pdf") {
        return false;
    }
    lower.contains('/')
        || lower.contains('\\')
        || lower.contains("~/")
        || lower.contains(" c:")
        || lower.contains(" /")
}

fn contains_zero_result_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "no matches found",
            "no pdf files found",
            "no pdf files were found",
            "did not find any pdf",
            "didn't find any pdf",
            "no files found",
            "0 pdf",
        ],
    )
}

fn baseline_pdf_matches(obs: &RunObservation) -> BTreeSet<String> {
    let mut matches = BTreeSet::new();
    for entry in &obs.command_history_evidence {
        if entry.exit_code != 0 {
            continue;
        }
        matches.extend(extract_pdf_paths(&entry.stdout));
    }
    for entry in &obs.action_evidence {
        if entry.tool_name.eq_ignore_ascii_case("filesystem__search")
            || entry.tool_name.eq_ignore_ascii_case("filesystem__stat")
        {
            matches.extend(extract_pdf_paths(&entry.output_excerpt));
        }
    }
    matches
}

fn extract_pdf_paths(text: &str) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    let lower = text.to_ascii_lowercase();

    for marker in ["/home/", "/Users/", "~/"] {
        let mut offset = 0usize;
        while offset < text.len() {
            let Some(found) = text[offset..].find(marker) else {
                break;
            };
            let start = offset + found;
            if !is_pdf_path_start_boundary(text, start) {
                offset = start + marker.len();
                continue;
            }
            let Some(pdf_suffix_idx) = lower[start..].find(".pdf") else {
                break;
            };
            let end = start + pdf_suffix_idx + 4;
            let candidate = normalize_pdf_path_candidate(&text[start..end]);
            if candidate.to_ascii_lowercase().ends_with(".pdf") {
                paths.insert(candidate);
            }
            offset = start + marker.len();
        }
    }

    paths
}

fn is_pdf_path_start_boundary(text: &str, idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    let prev = text.as_bytes()[idx - 1] as char;
    prev.is_ascii_whitespace()
        || matches!(
            prev,
            '`' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '-' | '*' | '>' | ':'
        )
}

fn normalize_pdf_path_candidate(value: &str) -> String {
    value
        .trim()
        .trim_matches(|ch: char| {
            matches!(
                ch,
                '`' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | ':' | '>'
            )
        })
        .to_string()
}

fn has_unrelated_mutating_action(obs: &RunObservation) -> bool {
    if has_tool_with_token(&obs.action_tools, "filesystem__create_directory")
        || has_tool_with_token(&obs.action_tools, "filesystem__write")
        || has_tool_with_token(&obs.action_tools, "filesystem__delete")
        || has_tool_with_token(&obs.action_tools, "filesystem__move")
        || has_tool_with_token(&obs.routing_tools, "filesystem__create_directory")
        || has_tool_with_token(&obs.routing_tools, "filesystem__write")
        || has_tool_with_token(&obs.routing_tools, "filesystem__delete")
        || has_tool_with_token(&obs.routing_tools, "filesystem__move")
    {
        return true;
    }

    obs.action_evidence.iter().any(|entry| {
        let lower = entry.output_excerpt.to_ascii_lowercase();
        contains_any(
            &lower,
            &[
                "created directory /",
                "created directory ",
                "mkdir ",
                "touch ",
                "removed directory ",
                "deleted ",
            ],
        )
    })
}
