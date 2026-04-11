use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    action_has_hard_error_class, has_cec_receipt, has_cec_stage, has_contract_failure_evidence,
    has_tool_with_token, truncate_chars, verification_bool, verification_u64, verification_value,
    ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str = "summarize_the_contents_of_the_most_recent_document_in_my_documents_folder";
const EXPECTED_FIXTURE_MODE: &str = "documents_latest_summary_fixture_v1";
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
            "Use local deterministic filesystem tools (`file__list`, ",
            "`file__info`, `file__read`) to identify the most recently modified ",
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
            entry.tool_name.eq_ignore_ascii_case("file__list")
                && !entry.agent_status.eq_ignore_ascii_case("failed")
                && !action_has_hard_error_class(entry)
        })
        .count();

    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_contract_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_phase_receipts_present = cec_contract_gate_seen
        || obs.cec_receipts.is_empty()
        || (cec_execution_seen && cec_verification_seen);

    let action_path_seen = has_tool_with_token(&obs.action_tools, "file__read")
        && has_tool_with_token(&obs.action_tools, "file__info")
        && has_tool_with_token(&obs.action_tools, "file__list");
    let routing_path_seen = has_tool_with_token(&obs.routing_tools, "file__read")
        && has_tool_with_token(&obs.routing_tools, "file__info")
        && has_tool_with_token(&obs.routing_tools, "file__list");
    let remote_path_seen = has_tool_with_token(&obs.action_tools, "web__")
        || has_tool_with_token(&obs.routing_tools, "web__")
        || has_tool_with_token(&obs.workload_tools, "web__")
        || has_tool_with_token(&obs.action_tools, "browser__")
        || has_tool_with_token(&obs.routing_tools, "browser__")
        || has_tool_with_token(&obs.workload_tools, "browser__")
        || has_tool_with_token(&obs.action_tools, "http__fetch")
        || has_tool_with_token(&obs.routing_tools, "http__fetch")
        || has_tool_with_token(&obs.workload_tools, "http__fetch");
    let shell_exec_seen = has_tool_with_token(&obs.action_tools, "shell__run")
        || has_tool_with_token(&obs.routing_tools, "shell__run");
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
        expected_latest_path_matches_observed && read_action_success_count > 0,
        cleanup_probe_source,
        cleanup_timestamp_ms,
        cleanup_satisfied,
        cec_phase_receipts_present,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let any_contract_failure_marker = has_contract_failure_evidence(obs);
    let completion_evidence_present =
        obs.completed && !obs.failed && (read_action_success_count > 0 || cec_contract_gate_seen);
    let objective_specific_latest_document_summary_evidence_present =
        expected_latest_path_matches_observed
            && read_action_success_count > 0
            && stat_action_success_count > 0
            && list_action_success_count > 0;

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
                "expected_latest_path_matches_observed={} read_action_success_count={} stat_action_success_count={} list_action_success_count={} latest_observed_path={}",
                expected_latest_path_matches_observed,
                read_action_success_count,
                stat_action_success_count,
                list_action_success_count,
                latest_observed_path
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
    latest_document_read_satisfied: bool,
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
            key: "documents_summary_latest_document_read_observed",
            observed_value: format!(
                "latest_document_read_satisfied={}",
                latest_document_read_satisfied
            ),
            probe_source: latest_content_probe_source,
            timestamp_ms: latest_content_timestamp_ms,
            satisfied: latest_document_read_satisfied,
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
    _expected_latest_path: &str,
) -> bool {
    entry.tool_name.eq_ignore_ascii_case("file__read")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn is_recent_document_stat_success(
    entry: &super::super::types::ActionEvidence,
    _expected_latest_path: &str,
) -> bool {
    entry.tool_name.eq_ignore_ascii_case("file__info")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn has_mutating_filesystem_action(obs: &RunObservation) -> bool {
    [
        "file__write",
        "file__edit",
        "file__delete",
        "file__create_dir",
        "file__zip",
        "file__move",
        "file__copy",
    ]
    .iter()
    .any(|token| {
        has_tool_with_token(&obs.action_tools, token)
            || has_tool_with_token(&obs.routing_tools, token)
            || has_tool_with_token(&obs.workload_tools, token)
    })
}

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}
