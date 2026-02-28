use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    has_tool_with_token, truncate_chars, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const TARGET_DIR_TOKEN: &str = "ioi_lowercase_";
const EXPECTED_FINAL_FILES: [&str; 3] = ["alpha.txt", "budget 2026.pdf", "mixed_case.jpg"];

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
        id: "rename_every_file_in_my_downloads_folder_to_lowercase",
        query: concat!(
            "Rename every file in my Downloads folder to lowercase. ",
            "For safe repeatable testing, operate only inside ",
            "\"~/Downloads/ioi_lowercase_{RUN_UNIQUE_NUM}\" and do not copy from or mutate any ",
            "other Downloads path. Create this directory and create fixture files directly in ",
            "that directory named \"Alpha.TXT\", \"Budget 2026.PDF\", and \"MiXeD_Case.JPG\". ",
            "Rename every file in that directory to lowercase by lowercasing only the basename ",
            "while preserving the directory path exactly (do not lowercase \"/Downloads\"). ",
            "After renaming, verify the directory state and then provide a concise completion summary."
        ),
        success_definition: "Perform lowercase rename inside an isolated Downloads test directory with successful command execution and CEC execution receipts, without contract failures.",
        seeded_intent_id: "command.exec",
        intent_scope: IntentScopeProfile::CommandExecution,
        seed_resolved_intent: false,
        expected_pass: true,
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

    let lowercase_result_names_observed = EXPECTED_FINAL_FILES
        .iter()
        .all(|name| command_corpus.contains(&name.to_ascii_lowercase()));

    let cec_discovery_seen = has_verification_check(obs, "receipt::host_discovery=true")
        || has_verification_check(obs, "capability_execution_phase=discovery");
    let cec_provider_selection_seen =
        has_verification_check(obs, "receipt::provider_selection=true")
            || has_verification_check(obs, "receipt::provider_selection_commit=true")
            || has_verification_check(obs, "provider_selection_route=script_backend");
    let cec_execution_seen = has_verification_check(obs, "receipt::execution=true")
        || has_verification_check(obs, "capability_execution_phase=execution");
    let cec_verification_seen = has_verification_check(obs, "receipt::verification=true")
        || has_verification_check(obs, "capability_execution_phase=verification");
    let cec_postcondition_seen =
        has_verification_check(obs, "postcondition::execution_artifact=true")
            || obs
                .verification_checks
                .iter()
                .any(|check| check.starts_with("verification_probe_commit=sha256:"));
    let cec_phase_receipts_present = cec_discovery_seen
        && cec_provider_selection_seen
        && cec_execution_seen
        && cec_verification_seen;

    let tool_and_route_path_evidence_present = has_tool_with_token(&obs.action_tools, "sys__exec")
        && has_tool_with_token(&obs.routing_tools, "sys__exec");

    let any_contract_failure_marker = observation_has_contract_failure_marker(obs);

    let timeout_terminal = obs
        .final_status
        .to_ascii_lowercase()
        .contains("timeoutorhang")
        || has_verification_check(obs, "failure_class=TimeoutOrHang");

    let timeout_after_verified_execution = timeout_terminal
        && successful_command_count > 0
        && cec_phase_receipts_present
        && cec_postcondition_seen
        && !any_contract_failure_marker;

    let completion_evidence_present =
        (obs.completed && !obs.failed && obs.chat_reply_count > 0 && successful_command_count > 0)
            || timeout_after_verified_execution;

    let objective_specific_rename_evidence_present =
        target_scope_observed && rename_transformation_observed && successful_command_count > 0;

    let environment_receipts = build_environment_receipts(
        obs,
        cec_phase_receipts_present,
        cec_postcondition_seen,
        successful_command_count,
        target_scope_observed,
        rename_transformation_observed,
        lowercase_result_names_observed,
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
                rename_transformation_observed,
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

fn has_verification_check(obs: &RunObservation, expected: &str) -> bool {
    obs.verification_checks
        .iter()
        .any(|check| check.eq_ignore_ascii_case(expected))
}

fn build_environment_receipts(
    obs: &RunObservation,
    cec_phase_receipts_present: bool,
    cec_postcondition_seen: bool,
    successful_command_count: usize,
    target_scope_observed: bool,
    rename_transformation_observed: bool,
    lowercase_result_names_observed: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "cec_phase_receipts_observed",
            observed_value: format!(
                "cec_phase_receipts_present={} verification_checks={:?}",
                cec_phase_receipts_present, obs.verification_checks
            ),
            probe_source: "RunObservation.verification_checks",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_phase_receipts_present,
        },
        EnvironmentEvidenceReceipt {
            key: "cec_postcondition_receipt_observed",
            observed_value: format!("cec_postcondition_seen={}", cec_postcondition_seen),
            probe_source: "RunObservation.verification_checks",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_postcondition_seen,
        },
        EnvironmentEvidenceReceipt {
            key: "successful_command_execution_observed",
            observed_value: format!("successful_command_count={}", successful_command_count),
            probe_source: "RunObservation.command_history_evidence",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: successful_command_count > 0,
        },
        EnvironmentEvidenceReceipt {
            key: "isolated_target_scope_observed",
            observed_value: format!("target_scope_observed={}", target_scope_observed),
            probe_source: "RunObservation.command_history_evidence.command|stdout|stderr",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: target_scope_observed,
        },
        EnvironmentEvidenceReceipt {
            key: "rename_transform_observed",
            observed_value: format!(
                "rename_transformation_observed={} lowercase_result_names_observed={}",
                rename_transformation_observed, lowercase_result_names_observed
            ),
            probe_source: "RunObservation.command_history_evidence.command|stdout|stderr",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: rename_transformation_observed,
        },
    ]
}

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}

fn observation_has_contract_failure_marker(obs: &RunObservation) -> bool {
    let mut evidence_corpus = Vec::<String>::new();
    evidence_corpus.push(obs.final_reply.clone());
    evidence_corpus.extend(
        obs.action_evidence
            .iter()
            .map(|entry| format!("{} {}", entry.agent_status, entry.output_excerpt)),
    );
    evidence_corpus.extend(obs.verification_checks.iter().cloned());
    evidence_corpus.extend(obs.event_excerpt.iter().cloned());

    evidence_corpus
        .iter()
        .any(|segment| has_contract_failure_marker(segment))
}

fn has_contract_failure_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "execution_contract_gate_blocked=true",
        "cec_terminal_error=true",
        "execution contract unmet",
        "base_error_class=executioncontractviolation",
        "error_class=executioncontractviolation",
        "error_class=discoverymissing",
        "error_class=synthesisfailed",
        "error_class=executionfailedterminal",
        "error_class=verificationmissing",
        "error_class=postconditionfailed",
        "system::invalid_tool_call",
        "failed to parse tool call",
        "schema_validation_error=true",
        "system::intent_clarification",
        "awaiting_clarification=true",
        "failed_stage=",
        "missing_receipts=",
        "missing_postconditions=",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}
