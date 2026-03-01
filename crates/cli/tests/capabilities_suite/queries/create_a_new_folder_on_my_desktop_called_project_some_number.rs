use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    action_has_hard_error_class, contains_any, has_cec_receipt, has_cec_stage,
    has_contract_failure_evidence, has_tool_with_token, is_retry_blocked_terminal,
    is_timeout_terminal, truncate_chars, ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase,
    RunObservation,
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
        id: "create_a_new_folder_on_my_desktop_called_project_some_number",
        query: "Create a new folder on my desktop called \"Project_{RUN_UNIQUE_NUM}\"",
        success_definition: "Create a new desktop folder named Project <number> using command/filesystem execution, verify existence with runtime receipts, and complete without contract failures.",
        seeded_intent_id: "command.exec",
        intent_scope: IntentScopeProfile::CommandExecution,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 70,
        max_steps: 14,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: true,
        allow_timeout_completion_with_local_evidence: true,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let create_action_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_desktop_project_create_success(entry))
        .count();
    let create_action_failures = obs
        .action_evidence
        .iter()
        .filter(|entry| is_desktop_project_create_failure(entry))
        .count();
    let verification_action_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_postcreate_verification_signal(entry))
        .count();

    let mut evidence_segments = Vec::<String>::new();
    evidence_segments.push(obs.final_reply.clone());
    evidence_segments.extend(obs.event_excerpt.iter().cloned());
    evidence_segments.extend(obs.action_evidence.iter().map(|entry| {
        format!(
            "{} {} {}",
            entry.tool_name, entry.agent_status, entry.output_excerpt
        )
    }));

    let desktop_path_hits = evidence_segments
        .iter()
        .filter(|segment| contains_desktop_path_token(segment))
        .count();
    let project_number_hits = evidence_segments
        .iter()
        .filter(|segment| contains_project_number_token(segment))
        .count();

    let action_path_seen = has_create_path_tool(&obs.action_tools);
    let routing_path_seen = has_create_path_tool(&obs.routing_tools);
    let any_contract_failure_marker = has_contract_failure_evidence(obs);
    let paused_retry_blocked = is_retry_blocked_terminal(obs);

    let cec_discovery_seen = has_cec_stage(obs, "discovery", Some(true));
    let cec_provider_selection_seen = has_cec_stage(obs, "provider_selection", Some(true));
    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_phase_receipts_present = cec_discovery_seen
        && cec_provider_selection_seen
        && cec_execution_seen
        && cec_verification_seen;
    let cec_postcondition_seen =
        has_cec_receipt(obs, "execution", "execution_artifact", Some(true))
            || has_cec_receipt(obs, "verification", "verification_commit", Some(true))
            || has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let postcondition_verification_evidence_present =
        cec_postcondition_seen || verification_action_count > 0;
    let target_path_and_name_evidence_present = desktop_path_hits > 0 && project_number_hits > 0;
    let timeout_terminal = is_timeout_terminal(obs);
    let timeout_after_verified_execution = timeout_terminal
        && create_action_count > 0
        && create_action_failures == 0
        && target_path_and_name_evidence_present
        && action_path_seen
        && routing_path_seen
        && cec_phase_receipts_present
        && postcondition_verification_evidence_present
        && !any_contract_failure_marker;

    let completion_channel_present = (obs.completed
        && (create_action_count > 0 || !obs.final_reply.trim().is_empty()))
        || (paused_retry_blocked && create_action_count > 0 && !any_contract_failure_marker)
        || timeout_after_verified_execution;
    let reply_target_acknowledged = reply_acknowledges_target(&obs.final_reply);

    let environment_receipts = build_environment_receipts(
        obs,
        desktop_path_hits,
        project_number_hits,
        create_action_count,
        create_action_failures,
        cec_phase_receipts_present,
        postcondition_verification_evidence_present,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        create_action_count > 0,
        action_path_seen && routing_path_seen,
        cec_phase_receipts_present,
        postcondition_verification_evidence_present,
        reply_target_acknowledged,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        create_action_count > 0 && independent_channel_count >= 3;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_channel_present,
            format!(
                "status={} completed={} paused_retry_blocked={} timeout_terminal={} timeout_after_verified_execution={} reply_len={} create_action_count={}",
                obs.final_status,
                obs.completed,
                paused_retry_blocked,
                timeout_terminal,
                timeout_after_verified_execution,
                obs.final_reply.chars().count(),
                create_action_count
            ),
        ),
        LocalCheck::new(
            "objective_specific_folder_creation_evidence_present",
            create_action_count > 0 && target_path_and_name_evidence_present,
            format!(
                "create_action_count={} desktop_path_hits={} project_number_hits={} action_evidence_samples={:?}",
                create_action_count,
                desktop_path_hits,
                project_number_hits,
                obs.action_evidence.iter().take(3).collect::<Vec<_>>()
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            action_path_seen && routing_path_seen,
            format!(
                "action_tools={:?} routing_tools={:?}",
                obs.action_tools, obs.routing_tools
            ),
        ),
        LocalCheck::new(
            "cec_phase_receipts_present",
            cec_phase_receipts_present,
            format!(
                "discovery={} provider_selection={} execution={} verification={} verification_checks={:?}",
                cec_discovery_seen,
                cec_provider_selection_seen,
                cec_execution_seen,
                cec_verification_seen,
                obs.verification_checks
            ),
        ),
        LocalCheck::new(
            "postcondition_verification_evidence_present",
            postcondition_verification_evidence_present,
            format!(
                "cec_postcondition_seen={} verification_action_count={} verification_checks={:?}",
                cec_postcondition_seen, verification_action_count, obs.verification_checks
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
                220,
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
                "independent_channel_count={} create_action_count={} reply_target_acknowledged={}",
                independent_channel_count, create_action_count, reply_target_acknowledged
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn is_desktop_project_create_success(entry: &super::super::types::ActionEvidence) -> bool {
    let tool = entry.tool_name.to_ascii_lowercase();
    let output = entry.output_excerpt.to_ascii_lowercase();
    let fs_create_success = tool == "filesystem__create_directory"
        && entry.agent_status.eq_ignore_ascii_case("completed")
        && output.contains("created directory");
    let sys_exec_create_success =
        tool.contains("sys__exec") && command_history_indicates_directory_create_success(&output);
    let create_path_tool = fs_create_success || sys_exec_create_success;
    let create_marker = contains_any(
        &output,
        &[
            "created directory",
            "created folder",
            "mkdir",
            "new-item",
            "install -d",
            "create directory",
            "create folder",
        ],
    );

    create_path_tool
        && (create_marker || sys_exec_create_success)
        && contains_desktop_path_token(&output)
        && contains_project_number_token(&output)
}

fn is_desktop_project_create_failure(entry: &super::super::types::ActionEvidence) -> bool {
    let tool = entry.tool_name.to_ascii_lowercase();
    if tool != "filesystem__create_directory" && !tool.contains("sys__exec") {
        return false;
    }
    let output = entry.output_excerpt.to_ascii_lowercase();
    let sys_exec_nonzero_exit = tool.contains("sys__exec")
        && output.contains("\"exit_code\":")
        && !output.contains("\"exit_code\":0");
    entry.agent_status.eq_ignore_ascii_case("failed")
        || sys_exec_nonzero_exit
        || action_has_hard_error_class(entry)
        || entry
            .output_excerpt
            .to_ascii_lowercase()
            .contains("create directory failed")
}

fn is_postcreate_verification_signal(entry: &super::super::types::ActionEvidence) -> bool {
    if !entry.agent_status.eq_ignore_ascii_case("completed") {
        return false;
    }
    let tool = entry.tool_name.to_ascii_lowercase();
    let output = entry.output_excerpt.to_ascii_lowercase();
    let verification_tool = tool == "filesystem__list_directory"
        || tool == "filesystem__read_file"
        || tool.contains("sys__exec");
    if !verification_tool {
        return false;
    }
    let verification_marker = contains_any(
        &output,
        &[
            "test -d",
            "ls ",
            "find ",
            "stat ",
            "get-childitem",
            "stdout:",
            "exists",
            "[dir]",
            "verification",
        ],
    );

    verification_marker
        && contains_project_number_token(&output)
        && (contains_desktop_path_token(&output) || output.contains("[dir] project"))
}

fn command_history_indicates_directory_create_success(output_lower: &str) -> bool {
    output_lower.contains("command_history:")
        && output_lower.contains("\"exit_code\":0")
        && contains_any(
            output_lower,
            &[
                "\"command\":\"mkdir",
                "\"command\":\"new-item",
                "\"command\":\"md ",
                "\"command\":\"install -d",
            ],
        )
}

fn reply_acknowledges_target(reply: &str) -> bool {
    let lower = reply.to_ascii_lowercase();
    contains_project_number_token(&lower)
        && contains_any(&lower, &["created", "folder", "directory", "desktop"])
}

fn has_create_path_tool(tools: &[String]) -> bool {
    has_tool_with_token(tools, "filesystem__create_directory")
        || has_tool_with_token(tools, "filesystem__list_directory")
        || has_tool_with_token(tools, "sys__exec")
}

fn build_environment_receipts(
    obs: &RunObservation,
    desktop_path_hits: usize,
    project_number_hits: usize,
    create_action_count: usize,
    create_action_failures: usize,
    cec_phase_receipts_present: bool,
    postcondition_verification_evidence_present: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "desktop_path_observed",
            observed_value: format!("desktop_path_hits={}", desktop_path_hits),
            probe_source: "KernelEvent::AgentActionResult.output_excerpt + event_excerpt",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: desktop_path_hits > 0,
        },
        EnvironmentEvidenceReceipt {
            key: "project_folder_name_observed",
            observed_value: format!("project_number_hits={}", project_number_hits),
            probe_source: "KernelEvent::AgentActionResult.output_excerpt + final_reply",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: project_number_hits > 0,
        },
        EnvironmentEvidenceReceipt {
            key: "directory_creation_execution_observed",
            observed_value: format!(
                "create_action_count={} create_action_failures={}",
                create_action_count, create_action_failures
            ),
            probe_source:
                "KernelEvent::AgentActionResult(tool=filesystem__create_directory|sys__exec)",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: create_action_count > 0 && create_action_failures == 0,
        },
        EnvironmentEvidenceReceipt {
            key: "cec_phase_receipts_observed",
            observed_value: format!(
                "cec_phase_receipts_present={} cec_receipts_count={}",
                cec_phase_receipts_present,
                obs.cec_receipts.len()
            ),
            probe_source: "RunObservation.cec_receipts",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_phase_receipts_present,
        },
        EnvironmentEvidenceReceipt {
            key: "postcondition_verification_observed",
            observed_value: format!(
                "postcondition_verification_evidence_present={}",
                postcondition_verification_evidence_present
            ),
            probe_source: "RunObservation.cec_receipts + AgentActionResult verification actions",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: postcondition_verification_evidence_present,
        },
    ]
}

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}

fn contains_desktop_path_token(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("/desktop/")
        || lower.contains("\\desktop\\")
        || lower.contains("~/desktop")
        || lower.contains("$home/desktop")
        || lower.contains("/desktop")
        || lower.contains("\\desktop")
}

fn contains_project_number_token(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let needle = b"project";
    if bytes.len() < needle.len() {
        return false;
    }

    let mut idx = 0usize;
    while idx + needle.len() <= bytes.len() {
        if &bytes[idx..idx + needle.len()] != needle {
            idx = idx.saturating_add(1);
            continue;
        }

        let has_left_boundary = idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric();
        if !has_left_boundary {
            idx = idx.saturating_add(1);
            continue;
        }

        let mut cursor = idx + needle.len();
        while cursor < bytes.len() {
            let ch = bytes[cursor];
            if ch.is_ascii_digit() {
                return true;
            }
            if ch.is_ascii_alphabetic() {
                break;
            }
            cursor = cursor.saturating_add(1);
        }

        idx = idx.saturating_add(needle.len());
    }

    false
}
