use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    action_has_hard_error_class, has_cec_receipt, has_cec_stage, has_contract_failure_evidence,
    has_tool_with_token, truncate_chars, verification_bool, verification_u64, verification_value,
    ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str = "summarize_the_contents_of_the_most_recent_document_in_my_documents_folder";
const EXPECTED_FIXTURE_MODE: &str = "documents_latest_summary_fixture_v1";
const EXPECTED_LATEST_FILE_NAME: &str = "incident_update_latest.txt";

#[derive(Debug, Clone, Serialize)]
struct EnvironmentEvidenceReceipt {
    key: &'static str,
    observed_value: String,
    probe_source: String,
    timestamp_ms: u64,
    satisfied: bool,
}

pub fn case() -> QueryCase {
    QueryCase {
        id: CASE_ID,
        query: concat!(
            "Summarize the contents of the most recent document in my Documents folder. ",
            "For deterministic repeatable testing, inspect only ",
            "\"{DOCS_FIXTURE_DIR}\". ",
            "Use local deterministic filesystem tools (`filesystem__list_directory`, ",
            "`filesystem__stat`, `filesystem__read_file`) to identify the most recently modified ",
            "document by metadata and then summarize that document. ",
            "Do not use web, browser, net, or shell execution tools. ",
            "Do not modify files. Return a concise summary that includes the selected absolute path ",
            "and at least two key facts from the selected document."
        ),
        success_definition: "Identify the latest document by deterministic filesystem metadata inside the isolated Documents fixture, summarize that specific document with path + key facts, and satisfy execution/verification/cleanup evidence receipts without contract failures.",
        seeded_intent_id: "workspace.ops",
        intent_scope: IntentScopeProfile::WorkspaceOps,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 90,
        max_steps: 18,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let expected_latest_path =
        verification_value(obs, "env_receipt::documents_summary_expected_latest_path")
            .unwrap_or_default();
    let latest_observed_path =
        verification_value(obs, "env_receipt::documents_summary_latest_observed_path")
            .unwrap_or_default();
    let latest_path_satisfied = verification_bool(
        obs,
        "env_receipt::documents_summary_latest_observed_path_satisfied",
    )
    .unwrap_or(false);
    let latest_content_markers_satisfied = verification_bool(
        obs,
        "env_receipt::documents_summary_latest_content_markers_satisfied",
    )
    .unwrap_or(false);
    let expected_latest_path_matches_observed = !expected_latest_path.is_empty()
        && !latest_observed_path.is_empty()
        && expected_latest_path.eq_ignore_ascii_case(&latest_observed_path)
        && latest_path_satisfied;

    let read_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_recent_document_read_success(entry, &expected_latest_path))
        .count();
    let stat_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_recent_document_stat_success(entry, &expected_latest_path))
        .count();
    let list_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| {
            entry
                .tool_name
                .eq_ignore_ascii_case("filesystem__list_directory")
                && !entry.agent_status.eq_ignore_ascii_case("failed")
                && !action_has_hard_error_class(entry)
        })
        .count();

    let path_token = if expected_latest_path.is_empty() {
        EXPECTED_LATEST_FILE_NAME.to_string()
    } else {
        expected_latest_path.to_ascii_lowercase()
    };
    let reply_lower = obs.final_reply.to_ascii_lowercase();
    let summary_path_acknowledged = if path_token.is_empty() {
        false
    } else {
        reply_lower.contains(&path_token)
            || reply_lower.contains(EXPECTED_LATEST_FILE_NAME)
            || latest_observed_path
                .to_ascii_lowercase()
                .split('/')
                .next_back()
                .map(|name| !name.is_empty() && reply_lower.contains(name))
                .unwrap_or(false)
    };
    let summary_quality_markers = summary_marker_group_hits(&reply_lower);
    let summary_quality_satisfied = summary_quality_markers >= 2;

    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_contract_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_phase_receipts_present = cec_contract_gate_seen
        || obs.cec_receipts.is_empty()
        || (cec_execution_seen && cec_verification_seen);

    let action_path_seen = has_tool_with_token(&obs.action_tools, "filesystem__read_file")
        && has_tool_with_token(&obs.action_tools, "filesystem__stat")
        && has_tool_with_token(&obs.action_tools, "filesystem__list_directory");
    let routing_path_seen = has_tool_with_token(&obs.routing_tools, "filesystem__read_file")
        && has_tool_with_token(&obs.routing_tools, "filesystem__stat")
        && has_tool_with_token(&obs.routing_tools, "filesystem__list_directory");
    let remote_path_seen = has_tool_with_token(&obs.action_tools, "web__")
        || has_tool_with_token(&obs.routing_tools, "web__")
        || has_tool_with_token(&obs.workload_tools, "web__")
        || has_tool_with_token(&obs.action_tools, "browser__")
        || has_tool_with_token(&obs.routing_tools, "browser__")
        || has_tool_with_token(&obs.workload_tools, "browser__")
        || has_tool_with_token(&obs.action_tools, "net__fetch")
        || has_tool_with_token(&obs.routing_tools, "net__fetch")
        || has_tool_with_token(&obs.workload_tools, "net__fetch");
    let shell_exec_seen = has_tool_with_token(&obs.action_tools, "sys__exec")
        || has_tool_with_token(&obs.routing_tools, "sys__exec");
    let mutating_filesystem_action_seen = has_mutating_filesystem_action(obs);
    let tool_and_route_path_evidence_present = action_path_seen
        && routing_path_seen
        && !remote_path_seen
        && !shell_exec_seen
        && !mutating_filesystem_action_seen;

    let fixture_mode =
        verification_value(obs, "env_receipt::documents_summary_fixture_mode").unwrap_or_default();
    let fixture_probe_source =
        verification_value(obs, "env_receipt::documents_summary_fixture_probe_source")
            .unwrap_or_default();
    let fixture_timestamp_ms =
        verification_u64(obs, "env_receipt::documents_summary_fixture_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied =
        verification_bool(obs, "env_receipt::documents_summary_fixture_satisfied").unwrap_or(false);
    let seeded_files_value =
        verification_value(obs, "env_receipt::documents_summary_seeded_files").unwrap_or_default();
    let seeded_files_satisfied =
        verification_bool(obs, "env_receipt::documents_summary_seeded_files_satisfied")
            .unwrap_or(false);
    let observed_files_value =
        verification_value(obs, "env_receipt::documents_summary_observed_files")
            .unwrap_or_default();
    let observed_files_probe_source = verification_value(
        obs,
        "env_receipt::documents_summary_observed_files_probe_source",
    )
    .unwrap_or_default();
    let observed_files_timestamp_ms = verification_u64(
        obs,
        "env_receipt::documents_summary_observed_files_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let observed_files_satisfied = verification_bool(
        obs,
        "env_receipt::documents_summary_observed_files_satisfied",
    )
    .unwrap_or(false);
    let latest_observed_probe_source = verification_value(
        obs,
        "env_receipt::documents_summary_latest_observed_path_probe_source",
    )
    .unwrap_or_default();
    let latest_observed_timestamp_ms = verification_u64(
        obs,
        "env_receipt::documents_summary_latest_observed_path_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let latest_content_probe_source = verification_value(
        obs,
        "env_receipt::documents_summary_latest_content_probe_source",
    )
    .unwrap_or_default();
    let latest_content_timestamp_ms = verification_u64(
        obs,
        "env_receipt::documents_summary_latest_content_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let cleanup_probe_source =
        verification_value(obs, "env_receipt::documents_summary_cleanup_probe_source")
            .unwrap_or_default();
    let cleanup_timestamp_ms =
        verification_u64(obs, "env_receipt::documents_summary_cleanup_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let cleanup_satisfied =
        verification_bool(obs, "env_receipt::documents_summary_cleanup_satisfied").unwrap_or(false);

    let environment_receipts = build_environment_receipts(
        obs,
        fixture_mode,
        fixture_probe_source,
        fixture_timestamp_ms,
        fixture_satisfied,
        seeded_files_value,
        seeded_files_satisfied,
        observed_files_value,
        observed_files_probe_source,
        observed_files_timestamp_ms,
        observed_files_satisfied,
        latest_observed_path.clone(),
        latest_observed_probe_source,
        latest_observed_timestamp_ms,
        expected_latest_path_matches_observed,
        latest_content_probe_source,
        latest_content_timestamp_ms,
        latest_content_markers_satisfied,
        cleanup_probe_source,
        cleanup_timestamp_ms,
        cleanup_satisfied,
        cec_phase_receipts_present,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let any_contract_failure_marker = has_contract_failure_evidence(obs);
    let completion_evidence_present = obs.completed
        && !obs.failed
        && (obs.chat_reply_count > 0 || read_action_success_count > 0)
        && !obs.final_reply.trim().is_empty();
    let objective_specific_latest_document_summary_evidence_present =
        expected_latest_path_matches_observed
            && read_action_success_count > 0
            && stat_action_success_count > 0
            && list_action_success_count > 0
            && summary_path_acknowledged
            && summary_quality_satisfied
            && latest_content_markers_satisfied;

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_latest_document_summary_evidence_present,
        tool_and_route_path_evidence_present,
        cec_phase_receipts_present,
        environment_receipts_satisfied,
        !any_contract_failure_marker,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_latest_document_summary_evidence_present
            && independent_channel_count >= 5;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} chat_reply_count={} reply_len={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                obs.chat_reply_count,
                obs.final_reply.chars().count()
            ),
        ),
        LocalCheck::new(
            "objective_specific_latest_document_summary_evidence_present",
            objective_specific_latest_document_summary_evidence_present,
            format!(
                "expected_latest_path_matches_observed={} read_action_success_count={} stat_action_success_count={} list_action_success_count={} summary_path_acknowledged={} summary_quality_markers={} latest_content_markers_satisfied={}",
                expected_latest_path_matches_observed,
                read_action_success_count,
                stat_action_success_count,
                list_action_success_count,
                summary_path_acknowledged,
                summary_quality_markers,
                latest_content_markers_satisfied
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!(
                "action_tools={:?} routing_tools={:?} workload_tools={:?} remote_path_seen={} shell_exec_seen={} mutating_filesystem_action_seen={}",
                obs.action_tools,
                obs.routing_tools,
                obs.workload_tools,
                remote_path_seen,
                shell_exec_seen,
                mutating_filesystem_action_seen
            ),
        ),
        LocalCheck::new(
            "cec_phase_receipts_present",
            cec_phase_receipts_present,
            format!(
                "execution={} verification={} completion_gate={} cec_receipts={:?}",
                cec_execution_seen, cec_verification_seen, cec_contract_gate_seen, obs.cec_receipts
            ),
        ),
        LocalCheck::new(
            "environment_receipts_satisfied",
            environment_receipts_satisfied,
            serialize_environment_receipts(&environment_receipts),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            !any_contract_failure_marker,
            truncate_chars(
                &format!(
                    "verification_checks={:?} final_reply={} event_excerpt={:?}",
                    obs.verification_checks, obs.final_reply, obs.event_excerpt
                ),
                280,
            ),
        ),
        LocalCheck::new(
            "independent_runtime_evidence_channels_present",
            independent_runtime_evidence_channels_present,
            format!(
                "independent_channel_count={} objective_specific_latest_document_summary_evidence_present={}",
                independent_channel_count, objective_specific_latest_document_summary_evidence_present
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

#[allow(clippy::too_many_arguments)]
fn build_environment_receipts(
    obs: &RunObservation,
    fixture_mode: String,
    fixture_probe_source: String,
    fixture_timestamp_ms: u64,
    fixture_satisfied: bool,
    seeded_files_value: String,
    seeded_files_satisfied: bool,
    observed_files_value: String,
    observed_files_probe_source: String,
    observed_files_timestamp_ms: u64,
    observed_files_satisfied: bool,
    latest_observed_path: String,
    latest_observed_probe_source: String,
    latest_observed_timestamp_ms: u64,
    latest_path_satisfied: bool,
    latest_content_probe_source: String,
    latest_content_timestamp_ms: u64,
    latest_content_markers_satisfied: bool,
    cleanup_probe_source: String,
    cleanup_timestamp_ms: u64,
    cleanup_satisfied: bool,
    cec_phase_receipts_present: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "documents_summary_fixture_mode_observed",
            observed_value: fixture_mode.clone(),
            probe_source: fixture_probe_source,
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE)
                && fixture_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "documents_summary_seeded_files_observed",
            observed_value: seeded_files_value,
            probe_source: "harness.documents_latest_summary_fixture".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: seeded_files_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "documents_summary_observed_files_stable",
            observed_value: observed_files_value,
            probe_source: observed_files_probe_source,
            timestamp_ms: observed_files_timestamp_ms,
            satisfied: observed_files_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "documents_summary_latest_document_observed",
            observed_value: latest_observed_path,
            probe_source: latest_observed_probe_source,
            timestamp_ms: latest_observed_timestamp_ms,
            satisfied: latest_path_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "documents_summary_latest_content_markers_observed",
            observed_value: format!(
                "latest_content_markers_satisfied={}",
                latest_content_markers_satisfied
            ),
            probe_source: latest_content_probe_source,
            timestamp_ms: latest_content_timestamp_ms,
            satisfied: latest_content_markers_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "documents_summary_cec_receipts_observed",
            observed_value: format!("cec_phase_receipts_present={}", cec_phase_receipts_present),
            probe_source: "RunObservation.cec_receipts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_phase_receipts_present,
        },
        EnvironmentEvidenceReceipt {
            key: "documents_summary_fixture_cleanup_observed",
            observed_value: format!("cleanup_satisfied={}", cleanup_satisfied),
            probe_source: cleanup_probe_source,
            timestamp_ms: cleanup_timestamp_ms,
            satisfied: cleanup_satisfied,
        },
    ]
}

fn is_recent_document_read_success(
    entry: &super::super::types::ActionEvidence,
    expected_latest_path: &str,
) -> bool {
    if !entry
        .tool_name
        .eq_ignore_ascii_case("filesystem__read_file")
        || entry.agent_status.eq_ignore_ascii_case("failed")
        || action_has_hard_error_class(entry)
    {
        return false;
    }
    let lower = entry.output_excerpt.to_ascii_lowercase();
    if expected_latest_path.is_empty() {
        return lower.contains("root cause:")
            && lower.contains("mitigation:")
            && lower.contains("next step:");
    }
    let expected_lower = expected_latest_path.to_ascii_lowercase();
    (lower.contains("root cause:") && lower.contains("mitigation:") && lower.contains("next step:"))
        || lower.contains(&expected_lower)
}

fn is_recent_document_stat_success(
    entry: &super::super::types::ActionEvidence,
    _expected_latest_path: &str,
) -> bool {
    if !entry.tool_name.eq_ignore_ascii_case("filesystem__stat")
        || entry.agent_status.eq_ignore_ascii_case("failed")
        || action_has_hard_error_class(entry)
    {
        return false;
    }
    let lower = entry.output_excerpt.to_ascii_lowercase();
    lower.contains("\"modified_epoch_ms\"") && lower.contains("\"path\"")
}

fn has_mutating_filesystem_action(obs: &RunObservation) -> bool {
    [
        "filesystem__write_file",
        "filesystem__patch",
        "filesystem__delete_path",
        "filesystem__create_directory",
        "filesystem__create_zip",
        "filesystem__move_path",
        "filesystem__copy_path",
    ]
    .iter()
    .any(|token| {
        has_tool_with_token(&obs.action_tools, token)
            || has_tool_with_token(&obs.routing_tools, token)
            || has_tool_with_token(&obs.workload_tools, token)
    })
}

fn summary_marker_group_hits(summary_lower: &str) -> usize {
    let root_cause = summary_lower.contains("expired")
        && summary_lower.contains("token")
        && summary_lower.contains("ingestion");
    let mitigation = (summary_lower.contains("rotated") || summary_lower.contains("restart"))
        && summary_lower.contains("worker");
    let next_step = summary_lower.contains("30-day")
        || summary_lower.contains("expiry alert")
        || summary_lower.contains("token expiry alert");

    [root_cause, mitigation, next_step]
        .into_iter()
        .filter(|flag| *flag)
        .count()
}

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}
