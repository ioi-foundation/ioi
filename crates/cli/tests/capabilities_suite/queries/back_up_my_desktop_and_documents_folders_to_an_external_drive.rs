use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    action_has_hard_error_class, has_cec_receipt, has_cec_stage, has_contract_failure_evidence,
    has_tool_with_token, truncate_chars, verification_bool, verification_u64, verification_value,
    ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str = "back_up_my_desktop_and_documents_folders_to_an_external_drive";
const EXPECTED_FIXTURE_MODE: &str = "desktop_documents_backup_external_drive_fixture_v1";
const EXPECTED_DESKTOP_FILES: [&str; 3] =
    ["Projects/roadmap.md", "Screenshots/sprint.png", "todo.txt"];
const EXPECTED_DOCUMENTS_FILES: [&str; 3] = [
    "finance/q1-budget.csv",
    "reference/ops/runbook.txt",
    "report.md",
];

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
            "Back up my Desktop and Documents folders to an external drive. ",
            "For deterministic repeatable testing, treat \"{BACKUP_EXTERNAL_DRIVE_PATH}\" as the mounted external drive root and ",
            "\"{BACKUP_DESTINATION_PATH}\" as the destination backup root. ",
            "Copy only these source directories: \"~/Desktop\" to \"{BACKUP_DESTINATION_PATH}/Desktop\" and ",
            "\"~/Documents\" to \"{BACKUP_DESTINATION_PATH}/Documents\". ",
            "Execute exactly this sequence once: ",
            "(1) ensure \"{BACKUP_DESTINATION_PATH}\" exists, ",
            "(2) copy \"~/Desktop\" to \"{BACKUP_DESTINATION_PATH}/Desktop\" with overwrite=true, ",
            "(3) copy \"~/Documents\" to \"{BACKUP_DESTINATION_PATH}/Documents\" with overwrite=true, ",
            "(4) return a completion summary and stop immediately. ",
            "Do not repeat identical copy actions after they succeed and do not run additional tool calls once both copy operations succeed. ",
            "Use deterministic local filesystem tools only: `file__copy` and `file__create_dir`. ",
            "Do not use `shell__run`/`shell__start`, web, browser, or net tools. ",
            "Do not move/delete/modify source files. ",
            "After copying, verify destination trees and return a concise completion summary with absolute backup paths."
        ),
        success_definition: "Copy Desktop and Documents into the isolated external-drive backup root using deterministic filesystem primitives, with CEC receipt evidence, source-preservation/content-match verification, and cleanup receipts, without contract failures.",
        seeded_intent_id: "workspace.ops",
        intent_scope: IntentScopeProfile::WorkspaceOps,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 105,
        max_steps: 14,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let fixture_mode =
        verification_value(obs, "env_receipt::desktop_documents_backup_fixture_mode")
            .unwrap_or_default();
    let fixture_probe_source = verification_value(
        obs,
        "env_receipt::desktop_documents_backup_fixture_probe_source",
    )
    .unwrap_or_default();
    let fixture_timestamp_ms = verification_u64(
        obs,
        "env_receipt::desktop_documents_backup_fixture_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied = verification_bool(
        obs,
        "env_receipt::desktop_documents_backup_fixture_satisfied",
    )
    .unwrap_or(false);

    let seeded_desktop_files_csv = verification_value(
        obs,
        "env_receipt::desktop_documents_backup_seeded_desktop_files",
    )
    .unwrap_or_default();
    let seeded_documents_files_csv = verification_value(
        obs,
        "env_receipt::desktop_documents_backup_seeded_documents_files",
    )
    .unwrap_or_default();
    let seeded_desktop_files_satisfied = verification_bool(
        obs,
        "env_receipt::desktop_documents_backup_seeded_desktop_files_satisfied",
    )
    .unwrap_or(false);
    let seeded_documents_files_satisfied = verification_bool(
        obs,
        "env_receipt::desktop_documents_backup_seeded_documents_files_satisfied",
    )
    .unwrap_or(false);
    let destination_absent_satisfied = verification_bool(
        obs,
        "env_receipt::desktop_documents_backup_destination_absent_satisfied",
    )
    .unwrap_or(false);

    let backup_root_path = verification_value(
        obs,
        "env_receipt::desktop_documents_backup_backup_root_path",
    )
    .unwrap_or_default();
    let backup_probe_source = verification_value(
        obs,
        "env_receipt::desktop_documents_backup_backup_probe_source",
    )
    .unwrap_or_default();
    let backup_timestamp_ms = verification_u64(
        obs,
        "env_receipt::desktop_documents_backup_backup_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let backup_root_satisfied = verification_bool(
        obs,
        "env_receipt::desktop_documents_backup_backup_root_satisfied",
    )
    .unwrap_or(false);

    let backup_desktop_path = verification_value(
        obs,
        "env_receipt::desktop_documents_backup_backup_desktop_path",
    )
    .unwrap_or_default();
    let backup_desktop_satisfied = verification_bool(
        obs,
        "env_receipt::desktop_documents_backup_backup_desktop_satisfied",
    )
    .unwrap_or(false);
    let backup_desktop_files_csv = verification_value(
        obs,
        "env_receipt::desktop_documents_backup_backup_desktop_files",
    )
    .unwrap_or_default();
    let backup_desktop_files_satisfied = verification_bool(
        obs,
        "env_receipt::desktop_documents_backup_backup_desktop_files_satisfied",
    )
    .unwrap_or(false);

    let backup_documents_path = verification_value(
        obs,
        "env_receipt::desktop_documents_backup_backup_documents_path",
    )
    .unwrap_or_default();
    let backup_documents_satisfied = verification_bool(
        obs,
        "env_receipt::desktop_documents_backup_backup_documents_satisfied",
    )
    .unwrap_or(false);
    let backup_documents_files_csv = verification_value(
        obs,
        "env_receipt::desktop_documents_backup_backup_documents_files",
    )
    .unwrap_or_default();
    let backup_documents_files_satisfied = verification_bool(
        obs,
        "env_receipt::desktop_documents_backup_backup_documents_files_satisfied",
    )
    .unwrap_or(false);

    let source_desktop_files_csv = verification_value(
        obs,
        "env_receipt::desktop_documents_backup_source_desktop_files",
    )
    .unwrap_or_default();
    let source_documents_files_csv = verification_value(
        obs,
        "env_receipt::desktop_documents_backup_source_documents_files",
    )
    .unwrap_or_default();
    let source_preserved_satisfied = verification_bool(
        obs,
        "env_receipt::desktop_documents_backup_source_preserved_satisfied",
    )
    .unwrap_or(false);
    let content_match_satisfied = verification_bool(
        obs,
        "env_receipt::desktop_documents_backup_content_match_satisfied",
    )
    .unwrap_or(false);
    let scope_satisfied =
        verification_bool(obs, "env_receipt::desktop_documents_backup_scope_satisfied")
            .unwrap_or(false);

    let cleanup_probe_source = verification_value(
        obs,
        "env_receipt::desktop_documents_backup_cleanup_probe_source",
    )
    .unwrap_or_default();
    let cleanup_timestamp_ms = verification_u64(
        obs,
        "env_receipt::desktop_documents_backup_cleanup_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let cleanup_satisfied = verification_bool(
        obs,
        "env_receipt::desktop_documents_backup_cleanup_satisfied",
    )
    .unwrap_or(false);

    let backup_desktop_files = parse_csv_entries(&backup_desktop_files_csv);
    let backup_documents_files = parse_csv_entries(&backup_documents_files_csv);
    let source_desktop_files = parse_csv_entries(&source_desktop_files_csv);
    let source_documents_files = parse_csv_entries(&source_documents_files_csv);

    let expected_backup_desktop_files_present = EXPECTED_DESKTOP_FILES.iter().all(|expected| {
        backup_desktop_files
            .iter()
            .any(|observed| observed == expected)
    }) && backup_desktop_files.len()
        == EXPECTED_DESKTOP_FILES.len();
    let expected_backup_documents_files_present = EXPECTED_DOCUMENTS_FILES.iter().all(|expected| {
        backup_documents_files
            .iter()
            .any(|observed| observed == expected)
    }) && backup_documents_files.len()
        == EXPECTED_DOCUMENTS_FILES.len();
    let expected_source_desktop_files_present = EXPECTED_DESKTOP_FILES.iter().all(|expected| {
        source_desktop_files
            .iter()
            .any(|observed| observed == expected)
    }) && source_desktop_files.len()
        == EXPECTED_DESKTOP_FILES.len();
    let expected_source_documents_files_present = EXPECTED_DOCUMENTS_FILES.iter().all(|expected| {
        source_documents_files
            .iter()
            .any(|observed| observed == expected)
    }) && source_documents_files.len()
        == EXPECTED_DOCUMENTS_FILES.len();

    let copy_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_copy_action_success(entry))
        .count();
    let copy_action_failure_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_copy_action_failure(entry))
        .count();
    let create_directory_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_create_directory_action_success(entry))
        .count();
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

    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_contract_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_phase_receipts_present =
        cec_contract_gate_seen || (cec_execution_seen && cec_verification_seen);

    let action_path_seen = has_tool_with_token(&obs.action_tools, "file__copy");
    let routing_path_seen = has_tool_with_token(&obs.routing_tools, "file__copy");
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
        || has_tool_with_token(&obs.routing_tools, "shell__run")
        || has_tool_with_token(&obs.workload_tools, "shell__run");
    let disallowed_mutation_seen = has_disallowed_mutating_action(obs);
    let tool_and_route_path_evidence_present = action_path_seen
        && routing_path_seen
        && !remote_path_seen
        && !shell_exec_seen
        && !disallowed_mutation_seen;

    let any_contract_failure_marker = has_contract_failure_evidence(obs);

    let completion_evidence_present = obs.completed
        && !obs.failed
        && copy_action_success_count >= 2
        && copy_action_failure_count == 0;

    let objective_specific_backup_evidence_present = backup_root_satisfied
        && backup_desktop_satisfied
        && backup_documents_satisfied
        && backup_desktop_files_satisfied
        && backup_documents_files_satisfied
        && expected_backup_desktop_files_present
        && expected_backup_documents_files_present
        && expected_source_desktop_files_present
        && expected_source_documents_files_present
        && source_preserved_satisfied
        && content_match_satisfied
        && scope_satisfied
        && seeded_desktop_files_satisfied
        && seeded_documents_files_satisfied
        && destination_absent_satisfied;

    let environment_receipts = build_environment_receipts(
        obs,
        fixture_mode,
        fixture_probe_source,
        fixture_timestamp_ms,
        fixture_satisfied,
        seeded_desktop_files_csv,
        seeded_desktop_files_satisfied,
        seeded_documents_files_csv,
        seeded_documents_files_satisfied,
        destination_absent_satisfied,
        backup_root_path.clone(),
        backup_probe_source,
        backup_timestamp_ms,
        backup_root_satisfied,
        backup_desktop_path.clone(),
        backup_desktop_files_csv,
        backup_desktop_files_satisfied && expected_backup_desktop_files_present,
        backup_documents_path.clone(),
        backup_documents_files_csv,
        backup_documents_files_satisfied && expected_backup_documents_files_present,
        source_desktop_files_csv,
        source_documents_files_csv,
        source_preserved_satisfied,
        content_match_satisfied,
        scope_satisfied,
        cec_phase_receipts_present,
        cleanup_probe_source,
        cleanup_timestamp_ms,
        cleanup_satisfied,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_backup_evidence_present,
        tool_and_route_path_evidence_present,
        cec_phase_receipts_present,
        environment_receipts_satisfied,
        !any_contract_failure_marker,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_backup_evidence_present && independent_channel_count >= 5;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} chat_reply_count={} copy_action_success_count={} copy_action_failure_count={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                obs.chat_reply_count,
                copy_action_success_count,
                copy_action_failure_count,
            ),
        ),
        LocalCheck::new(
            "objective_specific_backup_evidence_present",
            objective_specific_backup_evidence_present,
            format!(
                "backup_root_satisfied={} backup_desktop_satisfied={} backup_documents_satisfied={} backup_desktop_files_satisfied={} backup_documents_files_satisfied={} expected_backup_desktop_files_present={} expected_backup_documents_files_present={} source_preserved_satisfied={} content_match_satisfied={} scope_satisfied={} seeded_desktop_files_satisfied={} seeded_documents_files_satisfied={} destination_absent_satisfied={}",
                backup_root_satisfied,
                backup_desktop_satisfied,
                backup_documents_satisfied,
                backup_desktop_files_satisfied,
                backup_documents_files_satisfied,
                expected_backup_desktop_files_present,
                expected_backup_documents_files_present,
                source_preserved_satisfied,
                content_match_satisfied,
                scope_satisfied,
                seeded_desktop_files_satisfied,
                seeded_documents_files_satisfied,
                destination_absent_satisfied,
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!(
                "action_tools={:?} routing_tools={:?} workload_tools={:?} remote_path_seen={} shell_exec_seen={} disallowed_mutation_seen={}",
                obs.action_tools,
                obs.routing_tools,
                obs.workload_tools,
                remote_path_seen,
                shell_exec_seen,
                disallowed_mutation_seen,
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
                "independent_channel_count={} create_directory_action_success_count={} list_action_success_count={} stat_action_success_count={}",
                independent_channel_count,
                create_directory_action_success_count,
                list_action_success_count,
                stat_action_success_count,
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
    seeded_desktop_files_csv: String,
    seeded_desktop_files_satisfied: bool,
    seeded_documents_files_csv: String,
    seeded_documents_files_satisfied: bool,
    destination_absent_satisfied: bool,
    backup_root_path: String,
    backup_probe_source: String,
    backup_timestamp_ms: u64,
    backup_root_satisfied: bool,
    backup_desktop_path: String,
    backup_desktop_files_csv: String,
    backup_desktop_files_satisfied: bool,
    backup_documents_path: String,
    backup_documents_files_csv: String,
    backup_documents_files_satisfied: bool,
    source_desktop_files_csv: String,
    source_documents_files_csv: String,
    source_preserved_satisfied: bool,
    content_match_satisfied: bool,
    scope_satisfied: bool,
    cec_phase_receipts_present: bool,
    cleanup_probe_source: String,
    cleanup_timestamp_ms: u64,
    cleanup_satisfied: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "desktop_documents_backup_fixture_mode_observed",
            observed_value: fixture_mode.clone(),
            probe_source: fixture_probe_source,
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE) && fixture_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "desktop_documents_backup_seeded_desktop_files_observed",
            observed_value: seeded_desktop_files_csv,
            probe_source: "harness.desktop_documents_backup_fixture".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: seeded_desktop_files_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "desktop_documents_backup_seeded_documents_files_observed",
            observed_value: seeded_documents_files_csv,
            probe_source: "harness.desktop_documents_backup_fixture".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: seeded_documents_files_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "desktop_documents_backup_destination_absent_precondition_observed",
            observed_value: format!(
                "destination_absent_satisfied={}",
                destination_absent_satisfied
            ),
            probe_source: "harness.desktop_documents_backup_fixture".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: destination_absent_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "desktop_documents_backup_backup_root_observed",
            observed_value: backup_root_path,
            probe_source: backup_probe_source.clone(),
            timestamp_ms: backup_timestamp_ms,
            satisfied: backup_root_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "desktop_documents_backup_backup_desktop_observed",
            observed_value: format!(
                "path={} files={}",
                backup_desktop_path, backup_desktop_files_csv
            ),
            probe_source: backup_probe_source.clone(),
            timestamp_ms: backup_timestamp_ms,
            satisfied: backup_desktop_files_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "desktop_documents_backup_backup_documents_observed",
            observed_value: format!(
                "path={} files={}",
                backup_documents_path, backup_documents_files_csv
            ),
            probe_source: backup_probe_source,
            timestamp_ms: backup_timestamp_ms,
            satisfied: backup_documents_files_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "desktop_documents_backup_postconditions_observed",
            observed_value: format!(
                "source_desktop_files={} source_documents_files={} source_preserved_satisfied={} content_match_satisfied={} scope_satisfied={}",
                source_desktop_files_csv,
                source_documents_files_csv,
                source_preserved_satisfied,
                content_match_satisfied,
                scope_satisfied
            ),
            probe_source: "harness.desktop_documents_backup_fixture.fs_probe".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: source_preserved_satisfied && content_match_satisfied && scope_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "desktop_documents_backup_cec_receipts_observed",
            observed_value: format!("cec_phase_receipts_present={}", cec_phase_receipts_present),
            probe_source: "RunObservation.cec_receipts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_phase_receipts_present,
        },
        EnvironmentEvidenceReceipt {
            key: "desktop_documents_backup_fixture_cleanup_observed",
            observed_value: format!("cleanup_satisfied={}", cleanup_satisfied),
            probe_source: cleanup_probe_source,
            timestamp_ms: cleanup_timestamp_ms,
            satisfied: cleanup_satisfied,
        },
    ]
}

fn parse_csv_entries(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>()
}

fn is_copy_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry.tool_name.eq_ignore_ascii_case("file__copy")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn is_copy_action_failure(entry: &super::super::types::ActionEvidence) -> bool {
    entry.tool_name.eq_ignore_ascii_case("file__copy")
        && (entry.agent_status.eq_ignore_ascii_case("failed") || action_has_hard_error_class(entry))
}

fn is_create_directory_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry.tool_name.eq_ignore_ascii_case("file__create_dir")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn is_list_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry.tool_name.eq_ignore_ascii_case("file__list")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn is_stat_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry.tool_name.eq_ignore_ascii_case("file__info")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn has_disallowed_mutating_action(obs: &RunObservation) -> bool {
    [
        "file__write",
        "file__edit",
        "file__delete",
        "file__zip",
        "file__move",
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
