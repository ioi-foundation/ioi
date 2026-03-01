use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;
use std::collections::BTreeSet;

use super::super::types::{
    action_has_hard_error_class, has_cec_receipt, has_cec_stage, has_contract_failure_evidence,
    has_tool_with_token, truncate_chars, verification_bool, verification_u64, verification_value,
    ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str = "find_all_pdf_files_on_my_computer_modified_in_the_last_week";
const EXPECTED_FIXTURE_MODE: &str = "pdf_last_week_fixture_v1";

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
            "Find all PDF files modified in the last week within ",
            "\"{PDF_LAST_WEEK_FIXTURE_DIR}\". ",
            "Use local deterministic filesystem tools (`filesystem__list_directory`, ",
            "`filesystem__stat`) to discover candidate PDFs and verify their modification ",
            "timestamps. Do not use web, browser, net, or shell execution tools. ",
            "Do not modify files. Return a concise completion summary that lists each ",
            "matching absolute path on its own line."
        ),
        success_definition: "Identify the fixture-bounded PDF set modified within the last-week window using deterministic filesystem metadata, return all matching absolute paths, and satisfy CEC/environment/cleanup receipts with no contract failures.",
        seeded_intent_id: "workspace.ops.search_local_files",
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
    let fixture_mode =
        verification_value(obs, "env_receipt::pdf_last_week_fixture_mode").unwrap_or_default();
    let fixture_probe_source =
        verification_value(obs, "env_receipt::pdf_last_week_fixture_probe_source")
            .unwrap_or_default();
    let fixture_timestamp_ms =
        verification_u64(obs, "env_receipt::pdf_last_week_fixture_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied =
        verification_bool(obs, "env_receipt::pdf_last_week_fixture_satisfied").unwrap_or(false);

    let expected_paths_csv =
        verification_value(obs, "env_receipt::pdf_last_week_expected_paths").unwrap_or_default();
    let expected_count =
        verification_u64(obs, "env_receipt::pdf_last_week_expected_count").unwrap_or(0) as usize;
    let expected_paths = parse_csv_paths(&expected_paths_csv);
    let expected_paths_set = expected_paths.iter().cloned().collect::<BTreeSet<_>>();

    let observed_paths_csv =
        verification_value(obs, "env_receipt::pdf_last_week_observed_pdf_paths")
            .unwrap_or_default();
    let observed_paths = parse_csv_paths(&observed_paths_csv);
    let observed_paths_set = observed_paths.iter().cloned().collect::<BTreeSet<_>>();
    let observed_paths_probe_source = verification_value(
        obs,
        "env_receipt::pdf_last_week_observed_pdf_paths_probe_source",
    )
    .unwrap_or_default();
    let observed_paths_timestamp_ms = verification_u64(
        obs,
        "env_receipt::pdf_last_week_observed_pdf_paths_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let observed_paths_satisfied = verification_bool(
        obs,
        "env_receipt::pdf_last_week_observed_pdf_paths_satisfied",
    )
    .unwrap_or(false);

    let expected_window_start_epoch_ms = verification_u64(
        obs,
        "env_receipt::pdf_last_week_expected_window_start_epoch_ms",
    )
    .unwrap_or(0);
    let observed_window_start_epoch_ms = verification_u64(
        obs,
        "env_receipt::pdf_last_week_observed_window_start_epoch_ms",
    )
    .unwrap_or(0);
    let observed_window_probe_source = verification_value(
        obs,
        "env_receipt::pdf_last_week_observed_window_start_probe_source",
    )
    .unwrap_or_default();
    let observed_window_timestamp_ms = verification_u64(
        obs,
        "env_receipt::pdf_last_week_observed_window_start_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let observed_within_window_count = verification_u64(
        obs,
        "env_receipt::pdf_last_week_observed_within_window_count",
    )
    .unwrap_or(0) as usize;
    let observed_within_window_satisfied = verification_bool(
        obs,
        "env_receipt::pdf_last_week_observed_within_window_satisfied",
    )
    .unwrap_or(false);

    let cleanup_probe_source =
        verification_value(obs, "env_receipt::pdf_last_week_cleanup_probe_source")
            .unwrap_or_default();
    let cleanup_timestamp_ms =
        verification_u64(obs, "env_receipt::pdf_last_week_cleanup_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let cleanup_satisfied =
        verification_bool(obs, "env_receipt::pdf_last_week_cleanup_satisfied").unwrap_or(false);

    let expected_paths_reported_count = expected_paths
        .iter()
        .filter(|path| path_reported_in_reply(&obs.final_reply, path))
        .count();
    let expected_paths_reported =
        !expected_paths.is_empty() && expected_paths_reported_count == expected_paths.len();

    let list_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_list_action_success(entry))
        .count();
    let stat_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_stat_action_success(entry))
        .count();

    let observed_matches_expected = !expected_paths.is_empty()
        && expected_paths_set == observed_paths_set
        && expected_count == expected_paths.len()
        && observed_paths_satisfied;

    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_contract_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_phase_receipts_present = cec_contract_gate_seen
        || obs.cec_receipts.is_empty()
        || (cec_execution_seen && cec_verification_seen);

    let action_path_seen = has_tool_with_token(&obs.action_tools, "filesystem__list_directory")
        && has_tool_with_token(&obs.action_tools, "filesystem__stat");
    let routing_path_seen = has_tool_with_token(&obs.routing_tools, "filesystem__list_directory")
        && has_tool_with_token(&obs.routing_tools, "filesystem__stat");
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

    let any_contract_failure_marker = has_contract_failure_evidence(obs);
    let completion_evidence_present = obs.completed
        && !obs.failed
        && obs.chat_reply_count > 0
        && !obs.final_reply.trim().is_empty();

    let objective_specific_pdf_last_week_search_evidence_present = observed_matches_expected
        && expected_paths_reported
        && list_action_success_count > 0
        && stat_action_success_count >= expected_count.max(1)
        && expected_window_start_epoch_ms > 0
        && observed_window_start_epoch_ms == expected_window_start_epoch_ms
        && observed_within_window_count == expected_count
        && observed_within_window_satisfied;

    let environment_receipts = build_environment_receipts(
        obs,
        fixture_mode,
        fixture_probe_source,
        fixture_timestamp_ms,
        fixture_satisfied,
        expected_paths_csv,
        expected_count,
        expected_paths.len(),
        observed_paths_csv,
        observed_paths_probe_source,
        observed_paths_timestamp_ms,
        observed_matches_expected,
        expected_window_start_epoch_ms,
        observed_window_start_epoch_ms,
        observed_window_probe_source,
        observed_window_timestamp_ms,
        observed_within_window_count,
        observed_within_window_satisfied,
        cec_phase_receipts_present,
        cleanup_probe_source,
        cleanup_timestamp_ms,
        cleanup_satisfied,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_pdf_last_week_search_evidence_present,
        tool_and_route_path_evidence_present,
        cec_phase_receipts_present,
        environment_receipts_satisfied,
        !any_contract_failure_marker,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_pdf_last_week_search_evidence_present && independent_channel_count >= 5;

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
            "objective_specific_pdf_last_week_search_evidence_present",
            objective_specific_pdf_last_week_search_evidence_present,
            format!(
                "observed_matches_expected={} expected_paths_reported_count={} expected_count={} list_action_success_count={} stat_action_success_count={} observed_within_window_count={} observed_within_window_satisfied={}",
                observed_matches_expected,
                expected_paths_reported_count,
                expected_count,
                list_action_success_count,
                stat_action_success_count,
                observed_within_window_count,
                observed_within_window_satisfied
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
                "independent_channel_count={} objective_specific_pdf_last_week_search_evidence_present={}",
                independent_channel_count, objective_specific_pdf_last_week_search_evidence_present
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
    expected_paths_csv: String,
    expected_count: usize,
    expected_paths_len: usize,
    observed_paths_csv: String,
    observed_paths_probe_source: String,
    observed_paths_timestamp_ms: u64,
    observed_matches_expected: bool,
    expected_window_start_epoch_ms: u64,
    observed_window_start_epoch_ms: u64,
    observed_window_probe_source: String,
    observed_window_timestamp_ms: u64,
    observed_within_window_count: usize,
    observed_within_window_satisfied: bool,
    cec_phase_receipts_present: bool,
    cleanup_probe_source: String,
    cleanup_timestamp_ms: u64,
    cleanup_satisfied: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "pdf_last_week_fixture_mode_observed",
            observed_value: fixture_mode.clone(),
            probe_source: fixture_probe_source,
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE)
                && fixture_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "pdf_last_week_expected_paths_observed",
            observed_value: expected_paths_csv,
            probe_source: "harness.pdf_last_week_fixture".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: expected_count > 0 && expected_count == expected_paths_len,
        },
        EnvironmentEvidenceReceipt {
            key: "pdf_last_week_observed_paths_stable",
            observed_value: observed_paths_csv,
            probe_source: observed_paths_probe_source,
            timestamp_ms: observed_paths_timestamp_ms,
            satisfied: observed_matches_expected,
        },
        EnvironmentEvidenceReceipt {
            key: "pdf_last_week_window_constraint_observed",
            observed_value: format!(
                "expected_window_start_epoch_ms={} observed_window_start_epoch_ms={} observed_within_window_count={} observed_within_window_satisfied={}",
                expected_window_start_epoch_ms,
                observed_window_start_epoch_ms,
                observed_within_window_count,
                observed_within_window_satisfied
            ),
            probe_source: observed_window_probe_source,
            timestamp_ms: observed_window_timestamp_ms,
            satisfied: expected_window_start_epoch_ms > 0
                && observed_window_start_epoch_ms == expected_window_start_epoch_ms
                && observed_within_window_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "pdf_last_week_cec_receipts_observed",
            observed_value: format!("cec_phase_receipts_present={}", cec_phase_receipts_present),
            probe_source: "RunObservation.cec_receipts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_phase_receipts_present,
        },
        EnvironmentEvidenceReceipt {
            key: "pdf_last_week_fixture_cleanup_observed",
            observed_value: format!("cleanup_satisfied={}", cleanup_satisfied),
            probe_source: cleanup_probe_source,
            timestamp_ms: cleanup_timestamp_ms,
            satisfied: cleanup_satisfied,
        },
    ]
}

fn parse_csv_paths(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>()
}

fn path_reported_in_reply(reply: &str, path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    reply
        .to_ascii_lowercase()
        .contains(&path.to_ascii_lowercase())
}

fn is_list_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry
        .tool_name
        .eq_ignore_ascii_case("filesystem__list_directory")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn is_stat_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    if !entry.tool_name.eq_ignore_ascii_case("filesystem__stat")
        || entry.agent_status.eq_ignore_ascii_case("failed")
        || action_has_hard_error_class(entry)
    {
        return false;
    }
    let lower = entry.output_excerpt.to_ascii_lowercase();
    lower.contains("\"modified_epoch_ms\"")
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

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}
