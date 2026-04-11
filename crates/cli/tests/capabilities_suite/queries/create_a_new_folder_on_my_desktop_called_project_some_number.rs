use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    action_has_hard_error_class, environment_bool, environment_u64, environment_value,
    has_any_tool_name, has_cec_receipt, has_cec_stage, has_contract_failure_evidence,
    is_retry_blocked_terminal, is_timeout_terminal, observation_has_any_tool_name,
    observation_has_tool_name, observation_has_tool_namespace, truncate_chars, ExecutionProfile,
    LocalCheck, LocalJudgeResult, QueryCase, RunObservation, ToolNamespace,
};

const CASE_ID: &str = "create_a_new_folder_on_my_desktop_called_project_some_number";
const EXPECTED_FIXTURE_MODE: &str = "desktop_project_create_fixture_v1";
const CREATE_TOOL_NAMES: [&str; 3] = ["file__create_dir", "shell__run", "shell__start"];
const VERIFICATION_TOOL_NAMES: [&str; 3] = ["file__list", "shell__run", "shell__start"];
const DISALLOWED_MUTATING_TOOL_NAMES: [&str; 6] = [
    "file__write",
    "file__edit",
    "file__delete",
    "file__move",
    "file__copy",
    "file__zip",
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
        query: "Create a new folder on my desktop called \"Project_{RUN_UNIQUE_NUM}\"",
        success_definition: "Create the requested desktop folder inside the isolated temp-home Desktop fixture, verify the created directory with runtime environment receipts, and complete without contract failures.",
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
    let fixture_mode =
        environment_value(obs, "env_receipt::desktop_project_fixture_mode").unwrap_or_default();
    let fixture_probe_source =
        environment_value(obs, "env_receipt::desktop_project_fixture_probe_source")
            .unwrap_or_default();
    let fixture_timestamp_ms =
        environment_u64(obs, "env_receipt::desktop_project_fixture_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied =
        environment_bool(obs, "env_receipt::desktop_project_fixture_satisfied").unwrap_or(false);
    let expected_absent_satisfied = environment_bool(
        obs,
        "env_receipt::desktop_project_expected_absent_satisfied",
    )
    .unwrap_or(false);

    let expected_path =
        environment_value(obs, "env_receipt::desktop_project_expected_path").unwrap_or_default();
    let observed_path =
        environment_value(obs, "env_receipt::desktop_project_observed_path").unwrap_or_default();
    let created_probe_source =
        environment_value(obs, "env_receipt::desktop_project_created_probe_source")
            .unwrap_or_default();
    let created_timestamp_ms =
        environment_u64(obs, "env_receipt::desktop_project_created_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let created_satisfied =
        environment_bool(obs, "env_receipt::desktop_project_created_satisfied").unwrap_or(false);

    let desktop_entries =
        environment_value(obs, "env_receipt::desktop_project_desktop_entries").unwrap_or_default();
    let desktop_entries_probe_source = environment_value(
        obs,
        "env_receipt::desktop_project_desktop_entries_probe_source",
    )
    .unwrap_or_default();
    let desktop_entries_timestamp_ms = environment_u64(
        obs,
        "env_receipt::desktop_project_desktop_entries_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let desktop_entries_satisfied = environment_bool(
        obs,
        "env_receipt::desktop_project_desktop_entries_satisfied",
    )
    .unwrap_or(false);
    let scope_satisfied =
        environment_bool(obs, "env_receipt::desktop_project_scope_satisfied").unwrap_or(false);

    let cleanup_probe_source =
        environment_value(obs, "env_receipt::desktop_project_cleanup_probe_source")
            .unwrap_or_default();
    let cleanup_timestamp_ms =
        environment_u64(obs, "env_receipt::desktop_project_cleanup_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let cleanup_satisfied =
        environment_bool(obs, "env_receipt::desktop_project_cleanup_satisfied").unwrap_or(false);

    let create_action_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_completed_action(entry, &CREATE_TOOL_NAMES))
        .count();
    let successful_command_history_count = obs
        .command_history_evidence
        .iter()
        .filter(|entry| entry.exit_code == 0 && !entry.command.trim().is_empty())
        .count();
    let verification_action_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_completed_action(entry, &VERIFICATION_TOOL_NAMES))
        .count();
    let create_action_failures = obs
        .action_evidence
        .iter()
        .filter(|entry| is_failed_action(entry, &CREATE_TOOL_NAMES))
        .count();

    let action_path_seen = has_any_tool_name(&obs.action_tools, &CREATE_TOOL_NAMES);
    let routing_path_seen = has_any_tool_name(&obs.routing_tools, &CREATE_TOOL_NAMES);
    let remote_path_seen = observation_has_tool_namespace(obs, ToolNamespace::Web)
        || observation_has_tool_namespace(obs, ToolNamespace::Browser)
        || observation_has_tool_name(obs, "http__fetch");
    let install_path_seen = observation_has_tool_name(obs, "package__install");
    let disallowed_mutation_seen =
        observation_has_any_tool_name(obs, &DISALLOWED_MUTATING_TOOL_NAMES);
    let tool_and_route_path_evidence_present = action_path_seen
        && routing_path_seen
        && !remote_path_seen
        && !install_path_seen
        && !disallowed_mutation_seen;

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
    let postcondition_verification_evidence_present =
        cec_postcondition_seen || verification_action_count > 0 || created_satisfied;

    let any_contract_failure_marker = has_contract_failure_evidence(obs);
    let paused_retry_blocked = is_retry_blocked_terminal(obs);
    let timeout_terminal = is_timeout_terminal(obs);

    let objective_specific_folder_creation_evidence_present = fixture_mode
        .eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE)
        && fixture_satisfied
        && expected_absent_satisfied
        && !expected_path.trim().is_empty()
        && expected_path.eq_ignore_ascii_case(&observed_path)
        && created_satisfied
        && desktop_entries_satisfied
        && scope_satisfied
        && (create_action_count > 0 || successful_command_history_count > 0)
        && create_action_failures == 0;

    let timeout_after_verified_execution = timeout_terminal
        && objective_specific_folder_creation_evidence_present
        && cec_phase_receipts_present
        && postcondition_verification_evidence_present
        && !any_contract_failure_marker;

    let completion_evidence_present = (obs.completed
        && !obs.failed
        && (objective_specific_folder_creation_evidence_present || cec_postcondition_seen))
        || (paused_retry_blocked
            && objective_specific_folder_creation_evidence_present
            && !any_contract_failure_marker)
        || timeout_after_verified_execution;

    let environment_receipts = build_environment_receipts(
        fixture_mode,
        fixture_probe_source,
        fixture_timestamp_ms,
        fixture_satisfied,
        expected_absent_satisfied,
        expected_path,
        observed_path,
        created_probe_source,
        created_timestamp_ms,
        created_satisfied,
        desktop_entries,
        desktop_entries_probe_source,
        desktop_entries_timestamp_ms,
        desktop_entries_satisfied,
        scope_satisfied,
        cleanup_probe_source,
        cleanup_timestamp_ms,
        cleanup_satisfied,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_folder_creation_evidence_present,
        tool_and_route_path_evidence_present,
        cec_phase_receipts_present,
        postcondition_verification_evidence_present,
        environment_receipts_satisfied,
        !any_contract_failure_marker,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_folder_creation_evidence_present && independent_channel_count >= 5;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} paused_retry_blocked={} timeout_terminal={} timeout_after_verified_execution={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                paused_retry_blocked,
                timeout_terminal,
                timeout_after_verified_execution
            ),
        ),
        LocalCheck::new(
            "objective_specific_folder_creation_evidence_present",
            objective_specific_folder_creation_evidence_present,
            format!(
                "create_action_count={} successful_command_history_count={} create_action_failures={} expected_absent_satisfied={} created_satisfied={} desktop_entries_satisfied={} scope_satisfied={}",
                create_action_count,
                successful_command_history_count,
                create_action_failures,
                expected_absent_satisfied,
                created_satisfied,
                desktop_entries_satisfied,
                scope_satisfied
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!(
                "action_tools={:?} routing_tools={:?} workload_tools={:?} remote_path_seen={} install_path_seen={} disallowed_mutation_seen={}",
                obs.action_tools,
                obs.routing_tools,
                obs.workload_tools,
                remote_path_seen,
                install_path_seen,
                disallowed_mutation_seen
            ),
        ),
        LocalCheck::new(
            "cec_phase_receipts_present",
            cec_phase_receipts_present,
            format!(
                "discovery={} provider_selection={} execution={} verification={}",
                cec_discovery_seen,
                cec_provider_selection_seen,
                cec_execution_seen,
                cec_verification_seen
            ),
        ),
        LocalCheck::new(
            "postcondition_verification_evidence_present",
            postcondition_verification_evidence_present,
            format!(
                "cec_postcondition_seen={} verification_action_count={} created_satisfied={}",
                cec_postcondition_seen, verification_action_count, created_satisfied
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
                "independent_channel_count={} objective_specific_folder_creation_evidence_present={}",
                independent_channel_count, objective_specific_folder_creation_evidence_present
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn is_completed_action(
    entry: &super::super::types::ActionEvidence,
    allowed_tool_names: &[&str],
) -> bool {
    allowed_tool_names
        .iter()
        .any(|tool_name| entry.tool_name.eq_ignore_ascii_case(tool_name))
        && entry.agent_status.eq_ignore_ascii_case("completed")
        && !action_has_hard_error_class(entry)
}

fn is_failed_action(
    entry: &super::super::types::ActionEvidence,
    allowed_tool_names: &[&str],
) -> bool {
    allowed_tool_names
        .iter()
        .any(|tool_name| entry.tool_name.eq_ignore_ascii_case(tool_name))
        && (entry.agent_status.eq_ignore_ascii_case("failed") || action_has_hard_error_class(entry))
}

#[allow(clippy::too_many_arguments)]
fn build_environment_receipts(
    fixture_mode: String,
    fixture_probe_source: String,
    fixture_timestamp_ms: u64,
    fixture_satisfied: bool,
    expected_absent_satisfied: bool,
    expected_path: String,
    observed_path: String,
    created_probe_source: String,
    created_timestamp_ms: u64,
    created_satisfied: bool,
    desktop_entries: String,
    desktop_entries_probe_source: String,
    desktop_entries_timestamp_ms: u64,
    desktop_entries_satisfied: bool,
    scope_satisfied: bool,
    cleanup_probe_source: String,
    cleanup_timestamp_ms: u64,
    cleanup_satisfied: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "desktop_project_fixture_mode_observed",
            observed_value: fixture_mode.clone(),
            probe_source: fixture_probe_source,
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE)
                && fixture_satisfied
                && expected_absent_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "desktop_project_expected_path_observed",
            observed_value: expected_path.clone(),
            probe_source: "harness.desktop_project_create_fixture".to_string(),
            timestamp_ms: fixture_timestamp_ms,
            satisfied: !expected_path.trim().is_empty(),
        },
        EnvironmentEvidenceReceipt {
            key: "desktop_project_created_observed",
            observed_value: observed_path,
            probe_source: created_probe_source,
            timestamp_ms: created_timestamp_ms,
            satisfied: created_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "desktop_project_desktop_entries_observed",
            observed_value: desktop_entries,
            probe_source: desktop_entries_probe_source,
            timestamp_ms: desktop_entries_timestamp_ms,
            satisfied: desktop_entries_satisfied && scope_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "desktop_project_cleanup_observed",
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
