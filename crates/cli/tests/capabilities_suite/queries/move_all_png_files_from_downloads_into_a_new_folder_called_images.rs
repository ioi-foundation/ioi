use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    action_has_hard_error_class, has_cec_receipt, has_cec_stage, has_contract_failure_evidence,
    has_tool_with_token, truncate_chars, verification_bool, verification_u64, verification_value,
    ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str = "move_all_png_files_from_downloads_into_a_new_folder_called_images";
const EXPECTED_FIXTURE_MODE: &str = "downloads_png_move_fixture_v1";
const EXPECTED_PNG_FILES: [&str; 2] = ["alpha.png", "graph.png"];

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
            "Move all .png files from Downloads into a new folder called \"Images\". ",
            "For deterministic repeatable testing, treat ",
            "\"{DOWNLOADS_PNG_MOVE_FIXTURE_DIR}\" as the Downloads source directory. ",
            "Create \"Images\" inside that source directory and move only `.png` files from the ",
            "source directory into it. ",
            "The seeded `.png` files are exactly \"alpha.png\" and \"graph.png\"; both must end up ",
            "inside \"Images\". ",
            "Use this exact sequence: create Images once, move alpha.png, move graph.png, then ",
            "reply and stop. ",
            "Use deterministic local filesystem tools only: `filesystem__create_directory` and ",
            "`filesystem__move_path`. ",
            "Do not use `sys__exec`/`sys__exec_session`, web, browser, or net tools. ",
            "Do not copy/delete files and do not mutate anything outside this fixture directory. ",
            "Return a concise completion summary listing the absolute paths moved into Images."
        ),
        success_definition: "Move exactly the seeded .png files into an Images subdirectory inside the isolated Downloads fixture using deterministic filesystem primitives, with receipt-grounded execution/verification/cleanup evidence and no contract failures.",
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
    let fixture_mode =
        verification_value(obs, "env_receipt::downloads_png_move_fixture_mode").unwrap_or_default();
    let fixture_probe_source =
        verification_value(obs, "env_receipt::downloads_png_move_fixture_probe_source")
            .unwrap_or_default();
    let fixture_timestamp_ms =
        verification_u64(obs, "env_receipt::downloads_png_move_fixture_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied =
        verification_bool(obs, "env_receipt::downloads_png_move_fixture_satisfied")
            .unwrap_or(false);

    let seeded_png_files_csv =
        verification_value(obs, "env_receipt::downloads_png_move_seeded_png_files")
            .unwrap_or_default();
    let seeded_non_png_files_csv =
        verification_value(obs, "env_receipt::downloads_png_move_seeded_non_png_files")
            .unwrap_or_default();
    let seeded_png_satisfied =
        verification_bool(obs, "env_receipt::downloads_png_move_seeded_png_satisfied")
            .unwrap_or(false);
    let seeded_non_png_satisfied = verification_bool(
        obs,
        "env_receipt::downloads_png_move_seeded_non_png_satisfied",
    )
    .unwrap_or(false);

    let target_dir_path =
        verification_value(obs, "env_receipt::downloads_png_move_target_dir_path")
            .unwrap_or_default();
    let target_dir_probe_source = verification_value(
        obs,
        "env_receipt::downloads_png_move_target_dir_probe_source",
    )
    .unwrap_or_default();
    let target_dir_timestamp_ms = verification_u64(
        obs,
        "env_receipt::downloads_png_move_target_dir_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let target_dir_satisfied =
        verification_bool(obs, "env_receipt::downloads_png_move_target_dir_satisfied")
            .unwrap_or(false);

    let images_dir_path =
        verification_value(obs, "env_receipt::downloads_png_move_images_dir_path")
            .unwrap_or_default();
    let images_dir_probe_source = verification_value(
        obs,
        "env_receipt::downloads_png_move_images_dir_probe_source",
    )
    .unwrap_or_default();
    let images_dir_timestamp_ms = verification_u64(
        obs,
        "env_receipt::downloads_png_move_images_dir_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let images_dir_satisfied =
        verification_bool(obs, "env_receipt::downloads_png_move_images_dir_satisfied")
            .unwrap_or(false);

    let images_entries_csv =
        verification_value(obs, "env_receipt::downloads_png_move_images_entries")
            .unwrap_or_default();
    let images_entries_satisfied = verification_bool(
        obs,
        "env_receipt::downloads_png_move_images_entries_satisfied",
    )
    .unwrap_or(false);
    let source_entries_csv =
        verification_value(obs, "env_receipt::downloads_png_move_source_entries")
            .unwrap_or_default();
    let source_non_png_preserved_satisfied = verification_bool(
        obs,
        "env_receipt::downloads_png_move_source_non_png_preserved_satisfied",
    )
    .unwrap_or(false);
    let source_png_absent_satisfied = verification_bool(
        obs,
        "env_receipt::downloads_png_move_source_png_absent_satisfied",
    )
    .unwrap_or(false);
    let scope_satisfied =
        verification_bool(obs, "env_receipt::downloads_png_move_scope_satisfied").unwrap_or(false);

    let cleanup_probe_source =
        verification_value(obs, "env_receipt::downloads_png_move_cleanup_probe_source")
            .unwrap_or_default();
    let cleanup_timestamp_ms =
        verification_u64(obs, "env_receipt::downloads_png_move_cleanup_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let cleanup_satisfied =
        verification_bool(obs, "env_receipt::downloads_png_move_cleanup_satisfied")
            .unwrap_or(false);

    let final_reply_lower = obs.final_reply.to_ascii_lowercase();
    let reply_mentions_images_dir = !images_dir_path.is_empty()
        && final_reply_lower.contains(&images_dir_path.to_ascii_lowercase());
    let reply_mentions_expected_png_files = EXPECTED_PNG_FILES
        .iter()
        .all(|name| final_reply_lower.contains(name));

    let list_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_list_action_success(entry))
        .count();
    let create_directory_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_create_directory_action_success(entry))
        .count();
    let move_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_move_action_success(entry))
        .count();

    let png_move_end_state_satisfied = target_dir_satisfied
        && images_dir_satisfied
        && images_entries_satisfied
        && source_non_png_preserved_satisfied
        && source_png_absent_satisfied
        && scope_satisfied;

    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_contract_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_phase_receipts_present =
        cec_contract_gate_seen || (cec_execution_seen && cec_verification_seen);

    let action_path_seen = has_tool_with_token(&obs.action_tools, "filesystem__create_directory")
        && has_tool_with_token(&obs.action_tools, "filesystem__move_path");
    let routing_path_seen = has_tool_with_token(&obs.routing_tools, "filesystem__create_directory")
        && has_tool_with_token(&obs.routing_tools, "filesystem__move_path");
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
    let disallowed_mutation_seen = has_disallowed_mutating_action(obs);
    let tool_and_route_path_evidence_present = action_path_seen
        && routing_path_seen
        && !remote_path_seen
        && !shell_exec_seen
        && !disallowed_mutation_seen;

    let any_contract_failure_marker = has_contract_failure_evidence(obs);

    let completion_evidence_present = obs.completed
        && !obs.failed
        && obs.chat_reply_count > 0
        && !obs.final_reply.trim().is_empty();

    let objective_specific_png_move_evidence_present = png_move_end_state_satisfied
        && seeded_png_satisfied
        && seeded_non_png_satisfied
        && create_directory_action_success_count > 0
        && move_action_success_count >= EXPECTED_PNG_FILES.len()
        && reply_mentions_images_dir
        && reply_mentions_expected_png_files;

    let environment_receipts = build_environment_receipts(
        obs,
        fixture_mode,
        fixture_probe_source,
        fixture_timestamp_ms,
        fixture_satisfied,
        seeded_png_files_csv,
        seeded_png_satisfied,
        seeded_non_png_files_csv,
        seeded_non_png_satisfied,
        target_dir_path.clone(),
        target_dir_probe_source,
        target_dir_timestamp_ms,
        target_dir_satisfied,
        images_dir_path.clone(),
        images_dir_probe_source,
        images_dir_timestamp_ms,
        images_dir_satisfied,
        images_entries_csv,
        images_entries_satisfied,
        source_entries_csv,
        source_non_png_preserved_satisfied,
        source_png_absent_satisfied,
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
        objective_specific_png_move_evidence_present,
        tool_and_route_path_evidence_present,
        cec_phase_receipts_present,
        environment_receipts_satisfied,
        !any_contract_failure_marker,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_png_move_evidence_present && independent_channel_count >= 5;

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
            "objective_specific_png_move_evidence_present",
            objective_specific_png_move_evidence_present,
            format!(
                "png_move_end_state_satisfied={} seeded_png_satisfied={} seeded_non_png_satisfied={} list_action_success_count={} create_directory_action_success_count={} move_action_success_count={} reply_mentions_images_dir={} reply_mentions_expected_png_files={}",
                png_move_end_state_satisfied,
                seeded_png_satisfied,
                seeded_non_png_satisfied,
                list_action_success_count,
                create_directory_action_success_count,
                move_action_success_count,
                reply_mentions_images_dir,
                reply_mentions_expected_png_files,
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
                "independent_channel_count={} objective_specific_png_move_evidence_present={}",
                independent_channel_count, objective_specific_png_move_evidence_present,
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
    seeded_png_files_csv: String,
    seeded_png_satisfied: bool,
    seeded_non_png_files_csv: String,
    seeded_non_png_satisfied: bool,
    target_dir_path: String,
    target_dir_probe_source: String,
    target_dir_timestamp_ms: u64,
    target_dir_satisfied: bool,
    images_dir_path: String,
    images_dir_probe_source: String,
    images_dir_timestamp_ms: u64,
    images_dir_satisfied: bool,
    images_entries_csv: String,
    images_entries_satisfied: bool,
    source_entries_csv: String,
    source_non_png_preserved_satisfied: bool,
    source_png_absent_satisfied: bool,
    scope_satisfied: bool,
    cec_phase_receipts_present: bool,
    cleanup_probe_source: String,
    cleanup_timestamp_ms: u64,
    cleanup_satisfied: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "downloads_png_move_fixture_mode_observed",
            observed_value: fixture_mode.clone(),
            probe_source: fixture_probe_source,
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE) && fixture_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_png_move_seeded_png_files_observed",
            observed_value: seeded_png_files_csv,
            probe_source: "harness.downloads_png_move_fixture".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: seeded_png_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_png_move_seeded_non_png_files_observed",
            observed_value: seeded_non_png_files_csv,
            probe_source: "harness.downloads_png_move_fixture".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: seeded_non_png_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_png_move_target_dir_observed",
            observed_value: target_dir_path,
            probe_source: target_dir_probe_source,
            timestamp_ms: target_dir_timestamp_ms,
            satisfied: target_dir_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_png_move_images_dir_observed",
            observed_value: images_dir_path,
            probe_source: images_dir_probe_source,
            timestamp_ms: images_dir_timestamp_ms,
            satisfied: images_dir_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_png_move_images_entries_observed",
            observed_value: images_entries_csv,
            probe_source: "harness.downloads_png_move_fixture.fs_probe".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: images_entries_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_png_move_source_entries_observed",
            observed_value: source_entries_csv,
            probe_source: "harness.downloads_png_move_fixture.fs_probe".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: source_non_png_preserved_satisfied && source_png_absent_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_png_move_postconditions_observed",
            observed_value: format!(
                "source_non_png_preserved_satisfied={} source_png_absent_satisfied={} scope_satisfied={}",
                source_non_png_preserved_satisfied, source_png_absent_satisfied, scope_satisfied
            ),
            probe_source: "harness.downloads_png_move_fixture.fs_probe".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: source_non_png_preserved_satisfied
                && source_png_absent_satisfied
                && scope_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_png_move_cec_receipts_observed",
            observed_value: format!("cec_phase_receipts_present={}", cec_phase_receipts_present),
            probe_source: "RunObservation.cec_receipts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_phase_receipts_present,
        },
        EnvironmentEvidenceReceipt {
            key: "downloads_png_move_fixture_cleanup_observed",
            observed_value: format!("cleanup_satisfied={}", cleanup_satisfied),
            probe_source: cleanup_probe_source,
            timestamp_ms: cleanup_timestamp_ms,
            satisfied: cleanup_satisfied,
        },
    ]
}

fn is_list_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry
        .tool_name
        .eq_ignore_ascii_case("filesystem__list_directory")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn is_create_directory_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry
        .tool_name
        .eq_ignore_ascii_case("filesystem__create_directory")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn is_move_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry
        .tool_name
        .eq_ignore_ascii_case("filesystem__move_path")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn has_disallowed_mutating_action(obs: &RunObservation) -> bool {
    [
        "filesystem__write_file",
        "filesystem__patch",
        "filesystem__delete_path",
        "filesystem__create_zip",
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
