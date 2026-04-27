use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    action_has_hard_error_class, has_cec_receipt, has_cec_stage, has_contract_failure_evidence,
    has_tool_with_token, truncate_chars, verification_bool, verification_u64, verification_value,
    ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str = "rename_every_file_in_my_downloads_folder_to_lowercase";
const EXPECTED_FIXTURE_MODE: &str = "downloads_lowercase_fixture_v1";
const EXPECTED_FINAL_FILES: [&str; 3] = ["alpha.txt", "budget 2026.pdf", "mixed_case.jpg"];

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
            "Rename files in \"~/Downloads/ioi_lowercase_{RUN_UNIQUE_NUM}\" to lowercase. ",
            "The fixture directory and initial files are already provisioned. ",
            "Use deterministic local filesystem tools only: `file__list` and ",
            "`file__move`. Perform exactly these basename renames while preserving the ",
            "directory path: \"Alpha.TXT\" -> \"alpha.txt\", \"Budget 2026.PDF\" -> ",
            "\"budget 2026.pdf\", and \"MiXeD_Case.JPG\" -> \"mixed_case.jpg\". ",
            "Do not use `shell__run`/`shell__start`, web, browser, or net tools. ",
            "Do not create/copy/delete files outside this fixture directory. ",
            "After renaming, verify the final directory entries and return a concise completion ",
            "summary that lists the absolute paths of all renamed files."
        ),
        success_definition: "Complete deterministic lowercase renames inside the isolated Downloads fixture using filesystem move/list primitives, with receipt-grounded verification and cleanup evidence and no contract failures.",
        seeded_intent_id: "workspace.ops",
        intent_scope: IntentScopeProfile::WorkspaceOps,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 95,
        max_steps: 20,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let fixture_mode = verification_value(obs, "env_evidence::downloads_lowercase_fixture_mode")
        .unwrap_or_default();
    let fixture_probe_source = verification_value(
        obs,
        "env_evidence::downloads_lowercase_fixture_probe_source",
    )
    .unwrap_or_default();
    let fixture_timestamp_ms = verification_u64(
        obs,
        "env_evidence::downloads_lowercase_fixture_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied =
        verification_bool(obs, "env_evidence::downloads_lowercase_fixture_satisfied")
            .unwrap_or(false);

    let seeded_files_csv =
        verification_value(obs, "env_evidence::downloads_lowercase_seeded_files")
            .unwrap_or_default();
    let seeded_files_satisfied = verification_bool(
        obs,
        "env_evidence::downloads_lowercase_seeded_files_satisfied",
    )
    .unwrap_or(false);

    let target_dir_path =
        verification_value(obs, "env_evidence::downloads_lowercase_target_dir_path")
            .unwrap_or_default();
    let target_dir_probe_source = verification_value(
        obs,
        "env_evidence::downloads_lowercase_target_dir_probe_source",
    )
    .unwrap_or_default();
    let target_dir_timestamp_ms = verification_u64(
        obs,
        "env_evidence::downloads_lowercase_target_dir_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let target_dir_satisfied = verification_bool(
        obs,
        "env_evidence::downloads_lowercase_target_dir_satisfied",
    )
    .unwrap_or(false);

    let entries_csv =
        verification_value(obs, "env_evidence::downloads_lowercase_entries").unwrap_or_default();
    let entries_satisfied =
        verification_bool(obs, "env_evidence::downloads_lowercase_entries_satisfied")
            .unwrap_or(false);
    let uppercase_absent_satisfied = verification_bool(
        obs,
        "env_evidence::downloads_lowercase_uppercase_absent_satisfied",
    )
    .unwrap_or(false);
    let scope_satisfied =
        verification_bool(obs, "env_evidence::downloads_lowercase_scope_satisfied")
            .unwrap_or(false);

    let cleanup_probe_source = verification_value(
        obs,
        "env_evidence::downloads_lowercase_cleanup_probe_source",
    )
    .unwrap_or_default();
    let cleanup_timestamp_ms = verification_u64(
        obs,
        "env_evidence::downloads_lowercase_cleanup_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let cleanup_satisfied =
        verification_bool(obs, "env_evidence::downloads_lowercase_cleanup_satisfied")
            .unwrap_or(false);

    let list_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_list_action_success(entry))
        .count();
    let move_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_move_action_success(entry))
        .count();

    let rename_end_state_satisfied =
        target_dir_satisfied && entries_satisfied && uppercase_absent_satisfied && scope_satisfied;

    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_contract_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_phase_receipts_present = cec_contract_gate_seen
        || obs.cec_receipts.is_empty()
        || (cec_execution_seen && cec_verification_seen);

    let action_path_seen = has_tool_with_token(&obs.action_tools, "file__list")
        && has_tool_with_token(&obs.action_tools, "file__move");
    let routing_path_seen = has_tool_with_token(&obs.routing_tools, "file__list")
        && has_tool_with_token(&obs.routing_tools, "file__move");
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
    let disallowed_mutation_seen = has_disallowed_mutating_action(obs);
    let tool_and_route_path_evidence_present = action_path_seen
        && routing_path_seen
        && !remote_path_seen
        && !shell_exec_seen
        && !disallowed_mutation_seen;

    let any_contract_failure_marker = has_contract_failure_evidence(obs);

    let completion_evidence_present =
        obs.completed && !obs.failed && (rename_end_state_satisfied || cec_contract_gate_seen);

    let objective_specific_rename_evidence_present = rename_end_state_satisfied
        && seeded_files_satisfied
        && list_action_success_count > 0
        && move_action_success_count >= EXPECTED_FINAL_FILES.len();

    let environment_receipts = build_environment_receipts(
        obs,
        fixture_mode,
        fixture_probe_source,
        fixture_timestamp_ms,
        fixture_satisfied,
        seeded_files_csv,
        seeded_files_satisfied,
        target_dir_path.clone(),
        target_dir_probe_source,
        target_dir_timestamp_ms,
        target_dir_satisfied,
        entries_csv,
        entries_satisfied,
        uppercase_absent_satisfied,
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
        objective_specific_rename_evidence_present,
        tool_and_route_path_evidence_present,
        cec_phase_receipts_present,
        environment_receipts_satisfied,
        !any_contract_failure_marker,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_rename_evidence_present && independent_channel_count >= 5;

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
            "objective_specific_rename_evidence_present",
            objective_specific_rename_evidence_present,
            format!(
                "rename_end_state_satisfied={} seeded_files_satisfied={} list_action_success_count={} move_action_success_count={} target_dir_path={}",
                rename_end_state_satisfied,
                seeded_files_satisfied,
                list_action_success_count,
                move_action_success_count,
                target_dir_path,
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
                "independent_channel_count={} objective_specific_rename_evidence_present={}",
                independent_channel_count, objective_specific_rename_evidence_present,
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
    seeded_files_csv: String,
    seeded_files_satisfied: bool,
    target_dir_path: String,
    target_dir_probe_source: String,
    target_dir_timestamp_ms: u64,
    target_dir_satisfied: bool,
    entries_csv: String,
    entries_satisfied: bool,
    uppercase_absent_satisfied: bool,
    scope_satisfied: bool,
    cec_phase_receipts_present: bool,
    cleanup_probe_source: String,
    cleanup_timestamp_ms: u64,
    cleanup_satisfied: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "downloads_lowercase_fixture_mode_observed",
            observed_value: fixture_mode.clone(),
            probe_source: fixture_probe_source,
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE)
                && fixture_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_lowercase_seeded_files_observed",
            observed_value: seeded_files_csv,
            probe_source: "harness.downloads_lowercase_fixture".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: seeded_files_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_lowercase_target_dir_observed",
            observed_value: target_dir_path,
            probe_source: target_dir_probe_source,
            timestamp_ms: target_dir_timestamp_ms,
            satisfied: target_dir_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_lowercase_entries_observed",
            observed_value: entries_csv,
            probe_source: "harness.downloads_lowercase_fixture.fs_probe".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: entries_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_lowercase_uppercase_absent_observed",
            observed_value: format!(
                "uppercase_absent_satisfied={} scope_satisfied={}",
                uppercase_absent_satisfied, scope_satisfied
            ),
            probe_source: "harness.downloads_lowercase_fixture.fs_probe".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: uppercase_absent_satisfied && scope_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_lowercase_cec_receipts_observed",
            observed_value: format!("cec_phase_receipts_present={}", cec_phase_receipts_present),
            probe_source: "RunObservation.cec_receipts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_phase_receipts_present,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_lowercase_fixture_cleanup_observed",
            observed_value: format!("cleanup_satisfied={}", cleanup_satisfied),
            probe_source: cleanup_probe_source,
            timestamp_ms: cleanup_timestamp_ms,
            satisfied: cleanup_satisfied,
        },
    ]
}

fn is_list_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry.tool_name.eq_ignore_ascii_case("file__list")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn is_move_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry.tool_name.eq_ignore_ascii_case("file__move")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn has_disallowed_mutating_action(obs: &RunObservation) -> bool {
    [
        "file__write",
        "file__edit",
        "file__delete",
        "file__zip",
        "file__copy",
    ]
    .iter()
    .any(|token| {
        has_tool_with_token(&obs.action_tools, token)
            || has_tool_with_token(&obs.routing_tools, token)
            || has_tool_with_token(&obs.workload_tools, token)
    })
}

fn serialize_environment_receipts(evidence: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(evidence).unwrap_or_else(|_| "[]".to_string())
}
