use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    action_has_hard_error_class, has_cec_receipt, has_cec_stage, has_contract_failure_evidence,
    has_tool_with_token, truncate_chars, verification_bool, verification_u64, verification_value,
    ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str = "schedule_my_computer_to_shut_down_at_11_pm_tonight";
const EXPECTED_FIXTURE_MODE: &str = "shutdown_schedule_fixture_v1";
const EXPECTED_TARGET_LOCAL_TIME: &str = "23:00";
const EXPECTED_PROVIDER_IDS: [&str; 3] = ["shutdown", "systemctl", "at"];

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
            "Schedule my computer to shut down at 11 PM tonight. ",
            "Use exactly one `sys__exec` invocation to run ",
            "\"{SHUTDOWN_SCHEDULE_PROBE_PATH} --target-local 23:00\". ",
            "The fixture-backed probe performs provider discovery and writes schedule receipts; ",
            "do not invoke raw shutdown/poweroff/halt/reboot/systemctl/at commands directly. ",
            "Do not use web, browser, net, install, or filesystem mutation tools. ",
            "No additional command-exec invocations are allowed after that single command. ",
            "Return a concise completion summary that includes the selected provider and target local time."
        ),
        success_definition: "Schedule a shutdown for 11 PM local time via the isolated fixture-backed scheduling probe with a single command execution, CEC phase receipts, provider/runtime environment receipts, and deterministic cleanup evidence.",
        seeded_intent_id: "command.exec",
        intent_scope: IntentScopeProfile::CommandExecution,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 90,
        max_steps: 6,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let fixture_mode =
        verification_value(obs, "env_receipt::shutdown_schedule_fixture_mode").unwrap_or_default();
    let fixture_probe_source =
        verification_value(obs, "env_receipt::shutdown_schedule_fixture_probe_source")
            .unwrap_or_default();
    let fixture_timestamp_ms =
        verification_u64(obs, "env_receipt::shutdown_schedule_fixture_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied =
        verification_bool(obs, "env_receipt::shutdown_schedule_fixture_satisfied").unwrap_or(false);
    let run_unique_satisfied =
        verification_bool(obs, "env_receipt::shutdown_schedule_run_unique_satisfied")
            .unwrap_or(false);
    let probe_script_seeded_satisfied = verification_bool(
        obs,
        "env_receipt::shutdown_schedule_probe_script_seeded_satisfied",
    )
    .unwrap_or(false);
    let receipt_absent_satisfied = verification_bool(
        obs,
        "env_receipt::shutdown_schedule_receipt_absent_satisfied",
    )
    .unwrap_or(false);
    let provider_receipt_absent_satisfied = verification_bool(
        obs,
        "env_receipt::shutdown_schedule_provider_receipt_absent_satisfied",
    )
    .unwrap_or(false);

    let probe_script_path =
        verification_value(obs, "env_receipt::shutdown_schedule_probe_script_path")
            .unwrap_or_default();

    let provider =
        verification_value(obs, "env_receipt::shutdown_schedule_provider").unwrap_or_default();
    let provider_probe_source =
        verification_value(obs, "env_receipt::shutdown_schedule_provider_probe_source")
            .unwrap_or_default();
    let provider_timestamp_ms =
        verification_u64(obs, "env_receipt::shutdown_schedule_provider_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let provider_receipt_satisfied =
        verification_bool(obs, "env_receipt::shutdown_schedule_provider_satisfied")
            .unwrap_or(false);
    let provider_allowed = EXPECTED_PROVIDER_IDS
        .iter()
        .any(|expected| provider.eq_ignore_ascii_case(expected));
    let provider_satisfied = provider_allowed && provider_receipt_satisfied;

    let target_local_time =
        verification_value(obs, "env_receipt::shutdown_schedule_target_local_time")
            .unwrap_or_default();
    let target_local_date =
        verification_value(obs, "env_receipt::shutdown_schedule_target_local_date")
            .unwrap_or_default();
    let target_local_time_satisfied = verification_bool(
        obs,
        "env_receipt::shutdown_schedule_target_local_time_satisfied",
    )
    .unwrap_or(false);
    let now_epoch_sec =
        verification_u64(obs, "env_receipt::shutdown_schedule_now_epoch_sec").unwrap_or(0);
    let target_epoch_sec =
        verification_u64(obs, "env_receipt::shutdown_schedule_target_epoch_sec").unwrap_or(0);
    let delay_seconds =
        verification_u64(obs, "env_receipt::shutdown_schedule_delay_seconds").unwrap_or(0);
    let delay_window_satisfied =
        verification_bool(obs, "env_receipt::shutdown_schedule_delay_window_satisfied")
            .unwrap_or(false);
    let target_after_run_satisfied = verification_bool(
        obs,
        "env_receipt::shutdown_schedule_target_after_run_satisfied",
    )
    .unwrap_or(false);
    let run_unique_match_satisfied = verification_bool(
        obs,
        "env_receipt::shutdown_schedule_run_unique_match_satisfied",
    )
    .unwrap_or(false);
    let scheduled_satisfied =
        verification_bool(obs, "env_receipt::shutdown_schedule_scheduled_satisfied")
            .unwrap_or(false);

    let provider_args =
        verification_value(obs, "env_receipt::shutdown_schedule_provider_args").unwrap_or_default();
    let provider_invoked_satisfied = verification_bool(
        obs,
        "env_receipt::shutdown_schedule_provider_invoked_satisfied",
    )
    .unwrap_or(false);
    let provider_args_target_satisfied = verification_bool(
        obs,
        "env_receipt::shutdown_schedule_provider_args_target_satisfied",
    )
    .unwrap_or(false);
    let receipt_path_satisfied =
        verification_bool(obs, "env_receipt::shutdown_schedule_receipt_path_satisfied")
            .unwrap_or(false);
    let provider_receipt_path_satisfied = verification_bool(
        obs,
        "env_receipt::shutdown_schedule_provider_receipt_path_satisfied",
    )
    .unwrap_or(false);
    let scope_satisfied =
        verification_bool(obs, "env_receipt::shutdown_schedule_scope_satisfied").unwrap_or(false);

    let cleanup_probe_source =
        verification_value(obs, "env_receipt::shutdown_schedule_cleanup_probe_source")
            .unwrap_or_default();
    let cleanup_timestamp_ms =
        verification_u64(obs, "env_receipt::shutdown_schedule_cleanup_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let cleanup_satisfied =
        verification_bool(obs, "env_receipt::shutdown_schedule_cleanup_satisfied").unwrap_or(false);

    let probe_command_success_count = obs
        .command_history_evidence
        .iter()
        .filter(|entry| {
            entry.exit_code == 0
                && command_matches_probe(&entry.command, &probe_script_path)
                && entry.command.contains("--target-local")
                && entry.command.contains(EXPECTED_TARGET_LOCAL_TIME)
        })
        .count();
    let non_probe_command_count = obs
        .command_history_evidence
        .iter()
        .filter(|entry| !command_matches_probe(&entry.command, &probe_script_path))
        .count();

    let exec_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_exec_action_success(entry))
        .count();
    let hard_action_failure_count = obs
        .action_evidence
        .iter()
        .filter(|entry| action_has_hard_error_class(entry))
        .count();

    let objective_specific_shutdown_schedule_evidence_present = provider_satisfied
        && target_local_time == EXPECTED_TARGET_LOCAL_TIME
        && !target_local_date.trim().is_empty()
        && target_local_time_satisfied
        && target_after_run_satisfied
        && delay_window_satisfied
        && now_epoch_sec > 0
        && target_epoch_sec > now_epoch_sec
        && delay_seconds > 0
        && run_unique_match_satisfied
        && scheduled_satisfied
        && provider_invoked_satisfied
        && provider_args_target_satisfied
        && receipt_path_satisfied
        && provider_receipt_path_satisfied
        && scope_satisfied
        && probe_command_success_count == 1
        && non_probe_command_count == 0;

    let action_exec_path_seen = has_tool_with_token(&obs.action_tools, "sys__exec");
    let routing_exec_path_seen = has_tool_with_token(&obs.routing_tools, "sys__exec");
    let exec_session_seen = has_tool_with_token(&obs.action_tools, "sys__exec_session")
        || has_tool_with_token(&obs.routing_tools, "sys__exec_session");
    let remote_path_seen = has_tool_with_token(&obs.action_tools, "web__")
        || has_tool_with_token(&obs.routing_tools, "web__")
        || has_tool_with_token(&obs.workload_tools, "web__")
        || has_tool_with_token(&obs.action_tools, "browser__")
        || has_tool_with_token(&obs.routing_tools, "browser__")
        || has_tool_with_token(&obs.workload_tools, "browser__")
        || has_tool_with_token(&obs.action_tools, "net__fetch")
        || has_tool_with_token(&obs.routing_tools, "net__fetch")
        || has_tool_with_token(&obs.workload_tools, "net__fetch");
    let install_tool_seen = has_tool_with_token(&obs.action_tools, "sys__install_package")
        || has_tool_with_token(&obs.routing_tools, "sys__install_package")
        || has_tool_with_token(&obs.workload_tools, "sys__install_package");
    let disallowed_mutating_action_seen = has_disallowed_mutating_action(obs);
    let tool_and_route_path_evidence_present = action_exec_path_seen
        && routing_exec_path_seen
        && !exec_session_seen
        && !remote_path_seen
        && !install_tool_seen
        && !disallowed_mutating_action_seen;

    let cec_discovery_seen = has_cec_stage(obs, "discovery", Some(true));
    let cec_provider_selection_seen = has_cec_stage(obs, "provider_selection", Some(true));
    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_postcondition_seen =
        has_cec_receipt(obs, "execution", "execution_artifact", Some(true))
            && has_cec_receipt(
                obs,
                "provider_selection",
                "provider_selection_commit",
                Some(true),
            )
            && has_cec_receipt(obs, "verification", "verification_commit", Some(true));
    let cec_contract_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_phase_receipts_present = cec_discovery_seen
        && cec_provider_selection_seen
        && cec_execution_seen
        && cec_verification_seen
        && cec_postcondition_seen
        && (cec_contract_gate_seen || obs.completed);

    let any_contract_failure_marker = has_contract_failure_evidence(obs);
    let contract_failure_markers_absent =
        !any_contract_failure_marker && hard_action_failure_count == 0;

    let completion_evidence_present = obs.completed
        && !obs.failed
        && exec_action_success_count >= 1
        && (obs.chat_reply_count > 0
            || !obs.final_reply.trim().is_empty()
            || objective_specific_shutdown_schedule_evidence_present);

    let environment_receipts = vec![
        EnvironmentEvidenceReceipt {
            key: "shutdown_schedule_fixture_mode_observed",
            observed_value: fixture_mode.clone(),
            probe_source: fixture_probe_source,
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE)
                && fixture_satisfied
                && run_unique_satisfied
                && probe_script_seeded_satisfied
                && receipt_absent_satisfied
                && provider_receipt_absent_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "shutdown_schedule_provider_observed",
            observed_value: provider.clone(),
            probe_source: provider_probe_source,
            timestamp_ms: provider_timestamp_ms,
            satisfied: provider_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "shutdown_schedule_target_observed",
            observed_value: format!(
                "target_local_time={} target_local_date={} now_epoch_sec={} target_epoch_sec={} delay_seconds={}",
                target_local_time, target_local_date, now_epoch_sec, target_epoch_sec, delay_seconds
            ),
            probe_source: "harness.shutdown_schedule_fixture.receipt_probe".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: target_local_time == EXPECTED_TARGET_LOCAL_TIME
                && target_local_time_satisfied
                && target_after_run_satisfied
                && delay_window_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "shutdown_schedule_provider_invocation_observed",
            observed_value: provider_args.clone(),
            probe_source: "harness.shutdown_schedule_fixture.provider_receipt_probe".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: provider_invoked_satisfied && provider_args_target_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "shutdown_schedule_probe_command_observed",
            observed_value: format!(
                "probe_command_success_count={} non_probe_command_count={}",
                probe_command_success_count, non_probe_command_count
            ),
            probe_source: "RunObservation.command_history_evidence".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: probe_command_success_count == 1 && non_probe_command_count == 0,
        },
        EnvironmentEvidenceReceipt {
            key: "shutdown_schedule_cec_receipts_observed",
            observed_value: format!("cec_phase_receipts_present={}", cec_phase_receipts_present),
            probe_source: "RunObservation.cec_receipts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_phase_receipts_present,
        },
        EnvironmentEvidenceReceipt {
            key: "shutdown_schedule_cleanup_observed",
            observed_value: format!("cleanup_satisfied={}", cleanup_satisfied),
            probe_source: cleanup_probe_source,
            timestamp_ms: cleanup_timestamp_ms,
            satisfied: cleanup_satisfied,
        },
    ];
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_shutdown_schedule_evidence_present,
        tool_and_route_path_evidence_present,
        cec_phase_receipts_present,
        contract_failure_markers_absent,
        environment_receipts_satisfied,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_shutdown_schedule_evidence_present && independent_channel_count >= 5;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} chat_reply_count={} reply_len={} exec_action_success_count={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                obs.chat_reply_count,
                obs.final_reply.chars().count(),
                exec_action_success_count,
            ),
        ),
        LocalCheck::new(
            "objective_specific_shutdown_schedule_evidence_present",
            objective_specific_shutdown_schedule_evidence_present,
            format!(
                "provider_satisfied={} target_local_time={} target_local_time_satisfied={} target_after_run_satisfied={} delay_window_satisfied={} run_unique_match_satisfied={} scheduled_satisfied={} provider_invoked_satisfied={} provider_args_target_satisfied={} scope_satisfied={} probe_command_success_count={} non_probe_command_count={}",
                provider_satisfied,
                target_local_time,
                target_local_time_satisfied,
                target_after_run_satisfied,
                delay_window_satisfied,
                run_unique_match_satisfied,
                scheduled_satisfied,
                provider_invoked_satisfied,
                provider_args_target_satisfied,
                scope_satisfied,
                probe_command_success_count,
                non_probe_command_count,
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!(
                "action_tools={:?} routing_tools={:?} workload_tools={:?} exec_session_seen={} remote_path_seen={} install_tool_seen={} disallowed_mutating_action_seen={}",
                obs.action_tools,
                obs.routing_tools,
                obs.workload_tools,
                exec_session_seen,
                remote_path_seen,
                install_tool_seen,
                disallowed_mutating_action_seen,
            ),
        ),
        LocalCheck::new(
            "cec_phase_receipts_present",
            cec_phase_receipts_present,
            format!(
                "discovery={} provider_selection={} execution={} verification={} postcondition={} contract_gate={} cec_receipts={:?}",
                cec_discovery_seen,
                cec_provider_selection_seen,
                cec_execution_seen,
                cec_verification_seen,
                cec_postcondition_seen,
                cec_contract_gate_seen,
                obs.cec_receipts,
            ),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            contract_failure_markers_absent,
            truncate_chars(
                &format!(
                    "hard_action_failure_count={} verification_checks={:?} final_reply={} event_excerpt={:?}",
                    hard_action_failure_count,
                    obs.verification_checks,
                    obs.final_reply,
                    obs.event_excerpt
                ),
                280,
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
                "independent_channel_count={} objective_specific_shutdown_schedule_evidence_present={}",
                independent_channel_count, objective_specific_shutdown_schedule_evidence_present
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn command_matches_probe(command: &str, probe_script_path: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    let probe_lower = probe_script_path.to_ascii_lowercase();
    (!probe_lower.is_empty() && lower.contains(&probe_lower))
        || lower.contains("shutdown_schedule_probe")
}

fn has_disallowed_mutating_action(obs: &RunObservation) -> bool {
    obs.action_tools.iter().any(|tool| {
        let lower = tool.to_ascii_lowercase();
        lower.contains("filesystem__write_file")
            || lower.contains("filesystem__patch")
            || lower.contains("filesystem__delete_path")
            || lower.contains("filesystem__create_directory")
            || lower.contains("filesystem__create_zip")
            || lower.contains("filesystem__move_path")
            || lower.contains("filesystem__copy_path")
    })
}

fn is_exec_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry.tool_name.eq_ignore_ascii_case("sys__exec")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}
