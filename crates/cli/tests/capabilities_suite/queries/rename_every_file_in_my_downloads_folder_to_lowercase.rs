use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    has_cec_receipt, has_cec_stage, has_contract_failure_evidence, has_tool_with_token,
    is_timeout_terminal, truncate_chars, verification_bool, verification_u64, verification_value,
    ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const EXPECTED_FIXTURE_MODE: &str = "downloads_lowercase_fixture_v1";
const TARGET_DIR_TOKEN: &str = "ioi_lowercase_";
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
        id: "rename_every_file_in_my_downloads_folder_to_lowercase",
        query: concat!(
            "Rename every file in my Downloads folder to lowercase. ",
            "For safe repeatable testing, operate only inside ",
            "\"~/Downloads/ioi_lowercase_{RUN_UNIQUE_NUM}\" and do not copy from or mutate any ",
            "other Downloads path. Create this directory and create fixture files directly in ",
            "that directory named \"Alpha.TXT\", \"Budget 2026.PDF\", and \"MiXeD_Case.JPG\". ",
            "Rename every file in that directory to lowercase by lowercasing only the basename ",
            "while preserving the directory path exactly (do not lowercase \"/Downloads\"). ",
            "Use portable shell operations available on base Linux images (for example find/tr/mv), ",
            "and do not rely on the external `rename` utility. ",
            "After renaming, verify the directory state and then provide a concise completion summary."
        ),
        success_definition: "Perform lowercase rename inside an isolated Downloads test directory with successful command execution and CEC execution receipts, without contract failures.",
        seeded_intent_id: "command.exec",
        intent_scope: IntentScopeProfile::CommandExecution,
        seed_resolved_intent: false,
        expected_pass: true,
        execution_profile: ExecutionProfile::Privileged,
        sla_seconds: 95,
        max_steps: 20,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: true,
        allow_timeout_completion_with_local_evidence: true,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let successful_command_count = obs
        .command_history_evidence
        .iter()
        .filter(|entry| entry.exit_code == 0)
        .count();

    let command_corpus = obs
        .command_history_evidence
        .iter()
        .map(|entry| format!("{}\n{}\n{}", entry.command, entry.stdout, entry.stderr))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();

    let target_scope_observed = command_corpus.contains(TARGET_DIR_TOKEN)
        || obs
            .final_reply
            .to_ascii_lowercase()
            .contains(TARGET_DIR_TOKEN);

    let rename_transformation_observed = obs.command_history_evidence.iter().any(|entry| {
        if entry.exit_code != 0 {
            return false;
        }
        let cmd = entry.command.to_ascii_lowercase();
        (cmd.contains("mv") && cmd.contains("[:upper:]") && cmd.contains("[:lower:]"))
            || (cmd.contains("rename") && cmd.contains("a-z"))
    });

    let fixture_mode = verification_value(obs, "env_receipt::downloads_lowercase_fixture_mode")
        .unwrap_or_default();
    let fixture_mode_satisfied = fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE);
    let fixture_probe_source =
        verification_value(obs, "env_receipt::downloads_lowercase_fixture_probe_source")
            .unwrap_or_default();
    let fixture_timestamp_ms =
        verification_u64(obs, "env_receipt::downloads_lowercase_fixture_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied =
        verification_bool(obs, "env_receipt::downloads_lowercase_fixture_satisfied")
            .unwrap_or(false);
    let target_dir_path =
        verification_value(obs, "env_receipt::downloads_lowercase_target_dir_path")
            .unwrap_or_default();
    let target_dir_probe_source = verification_value(
        obs,
        "env_receipt::downloads_lowercase_target_dir_probe_source",
    )
    .unwrap_or_default();
    let target_dir_timestamp_ms = verification_u64(
        obs,
        "env_receipt::downloads_lowercase_target_dir_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let target_dir_satisfied =
        verification_bool(obs, "env_receipt::downloads_lowercase_target_dir_satisfied")
            .unwrap_or(false);
    let entries_csv =
        verification_value(obs, "env_receipt::downloads_lowercase_entries").unwrap_or_default();
    let entries_satisfied =
        verification_bool(obs, "env_receipt::downloads_lowercase_entries_satisfied")
            .unwrap_or(false);
    let uppercase_absent_satisfied = verification_bool(
        obs,
        "env_receipt::downloads_lowercase_uppercase_absent_satisfied",
    )
    .unwrap_or(false);
    let scope_satisfied =
        verification_bool(obs, "env_receipt::downloads_lowercase_scope_satisfied").unwrap_or(false);
    let cleanup_probe_source =
        verification_value(obs, "env_receipt::downloads_lowercase_cleanup_probe_source")
            .unwrap_or_default();
    let cleanup_timestamp_ms =
        verification_u64(obs, "env_receipt::downloads_lowercase_cleanup_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let cleanup_satisfied =
        verification_bool(obs, "env_receipt::downloads_lowercase_cleanup_satisfied")
            .unwrap_or(false);

    let observed_entries = entries_csv
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();
    let lowercase_result_names_observed = EXPECTED_FINAL_FILES.iter().all(|expected| {
        observed_entries
            .iter()
            .any(|observed| observed.eq_ignore_ascii_case(expected))
    }) || EXPECTED_FINAL_FILES
        .iter()
        .all(|name| command_corpus.contains(&name.to_ascii_lowercase()));
    let rename_end_state_satisfied = target_dir_satisfied
        && entries_satisfied
        && lowercase_result_names_observed
        && uppercase_absent_satisfied
        && scope_satisfied;

    let cec_discovery_seen = has_cec_stage(obs, "discovery", Some(true));
    let cec_provider_selection_seen = has_cec_stage(obs, "provider_selection", Some(true));
    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_postcondition_seen =
        has_cec_receipt(obs, "execution", "execution_artifact", Some(true))
            || has_cec_receipt(obs, "verification", "verification_commit", Some(true))
            || has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_phase_receipts_present = cec_discovery_seen
        && cec_provider_selection_seen
        && cec_execution_seen
        && cec_verification_seen;

    let tool_and_route_path_evidence_present = has_tool_with_token(&obs.action_tools, "sys__exec")
        && has_tool_with_token(&obs.routing_tools, "sys__exec");

    let any_contract_failure_marker = has_contract_failure_evidence(obs);

    let timeout_terminal = is_timeout_terminal(obs);

    let timeout_after_verified_execution = timeout_terminal
        && successful_command_count > 0
        && cec_phase_receipts_present
        && cec_postcondition_seen
        && !any_contract_failure_marker;

    let completion_evidence_present =
        (obs.completed && !obs.failed && obs.chat_reply_count > 0 && successful_command_count > 0)
            || timeout_after_verified_execution;

    let objective_specific_rename_evidence_present =
        target_scope_observed && successful_command_count > 0 && rename_end_state_satisfied;

    let environment_receipts = build_environment_receipts(
        obs,
        fixture_mode,
        fixture_mode_satisfied,
        fixture_probe_source,
        fixture_timestamp_ms,
        fixture_satisfied,
        cec_phase_receipts_present,
        cec_postcondition_seen,
        successful_command_count,
        target_scope_observed,
        target_dir_path,
        target_dir_probe_source,
        target_dir_timestamp_ms,
        target_dir_satisfied,
        entries_csv,
        entries_satisfied,
        uppercase_absent_satisfied,
        scope_satisfied,
        cleanup_probe_source,
        cleanup_timestamp_ms,
        cleanup_satisfied,
        rename_transformation_observed,
        lowercase_result_names_observed,
        rename_end_state_satisfied,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_rename_evidence_present,
        tool_and_route_path_evidence_present,
        cec_phase_receipts_present && cec_postcondition_seen,
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
                "status={} completed={} failed={} chat_reply_count={} successful_command_count={}",
                obs.final_status, obs.completed, obs.failed, obs.chat_reply_count, successful_command_count,
            ),
        ),
        LocalCheck::new(
            "objective_specific_rename_evidence_present",
            objective_specific_rename_evidence_present,
            format!(
                "target_scope_observed={} rename_transformation_observed={} successful_command_count={} command_history_count={}",
                target_scope_observed,
                rename_transformation_observed || rename_end_state_satisfied,
                successful_command_count,
                obs.command_history_evidence.len(),
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!("action_tools={:?} routing_tools={:?}", obs.action_tools, obs.routing_tools),
        ),
        LocalCheck::new(
            "cec_phase_receipts_present",
            cec_phase_receipts_present && cec_postcondition_seen,
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
                260,
            ),
        ),
        LocalCheck::new(
            "independent_runtime_evidence_channels_present",
            independent_runtime_evidence_channels_present,
            format!(
                "independent_channel_count={} objective_specific_rename_evidence_present={} lowercase_result_names_observed={}",
                independent_channel_count,
                objective_specific_rename_evidence_present,
                lowercase_result_names_observed,
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn build_environment_receipts(
    obs: &RunObservation,
    fixture_mode: String,
    fixture_mode_satisfied: bool,
    fixture_probe_source: String,
    fixture_timestamp_ms: u64,
    fixture_satisfied: bool,
    cec_phase_receipts_present: bool,
    cec_postcondition_seen: bool,
    successful_command_count: usize,
    target_scope_observed: bool,
    target_dir_path: String,
    target_dir_probe_source: String,
    target_dir_timestamp_ms: u64,
    target_dir_satisfied: bool,
    entries_csv: String,
    entries_satisfied: bool,
    uppercase_absent_satisfied: bool,
    scope_satisfied: bool,
    cleanup_probe_source: String,
    cleanup_timestamp_ms: u64,
    cleanup_satisfied: bool,
    rename_transformation_observed: bool,
    lowercase_result_names_observed: bool,
    rename_end_state_satisfied: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "downloads_lowercase_fixture_mode_observed",
            observed_value: fixture_mode,
            probe_source: fixture_probe_source,
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode_satisfied && fixture_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "cec_phase_receipts_observed",
            observed_value: format!(
                "cec_phase_receipts_present={} cec_receipts={:?}",
                cec_phase_receipts_present, obs.cec_receipts
            ),
            probe_source: "RunObservation.cec_receipts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_phase_receipts_present,
        },
        EnvironmentEvidenceReceipt {
            key: "cec_postcondition_receipt_observed",
            observed_value: format!("cec_postcondition_seen={}", cec_postcondition_seen),
            probe_source: "RunObservation.cec_receipts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_postcondition_seen,
        },
        EnvironmentEvidenceReceipt {
            key: "successful_command_execution_observed",
            observed_value: format!("successful_command_count={}", successful_command_count),
            probe_source: "RunObservation.command_history_evidence".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: successful_command_count > 0,
        },
        EnvironmentEvidenceReceipt {
            key: "isolated_target_scope_observed",
            observed_value: format!("target_scope_observed={}", target_scope_observed),
            probe_source: "RunObservation.command_history_evidence.command|stdout|stderr"
                .to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: target_scope_observed,
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
            satisfied: entries_satisfied && lowercase_result_names_observed,
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
            key: "rename_transform_observed",
            observed_value: format!(
                "rename_transformation_observed={} rename_end_state_satisfied={} lowercase_result_names_observed={}",
                rename_transformation_observed, rename_end_state_satisfied, lowercase_result_names_observed
            ),
            probe_source: "RunObservation.command_history_evidence.command|stdout|stderr"
                .to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: rename_transformation_observed || rename_end_state_satisfied,
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

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}
