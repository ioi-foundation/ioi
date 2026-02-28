use ioi_types::app::agentic::IntentScopeProfile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::super::types::{
    has_tool_with_token, truncate_chars, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const POSTCHECK_PREFIX: &str = "LOWERCASE_RENAME_POSTCHECK:";
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

#[derive(Debug, Clone, Deserialize)]
struct LowercaseRenamePostcheck {
    target_dir: String,
    total_files: usize,
    uppercase_remaining: usize,
    final_names: Vec<String>,
}

#[derive(Debug, Clone)]
struct PostcheckEvidence {
    receipt: LowercaseRenamePostcheck,
    command: String,
    exit_code: i32,
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
            "Use this loop shape: for each file, compute basename, lowercase basename, then move ",
            "to \"$target_dir/$lower_basename\". Then run one verification command ",
            "that prints exactly one line in this format: ",
            "LOWERCASE_RENAME_POSTCHECK:{\"target_dir\":\"...\",\"total_files\":3,",
            "\"uppercase_remaining\":0,\"final_names\":[\"alpha.txt\",\"budget 2026.pdf\",",
            "\"mixed_case.jpg\"]}. Include that receipt line in your final response."
        ),
        success_definition: "Rename all files in an isolated Downloads test directory to lowercase and prove completion using a machine-readable runtime postcheck receipt plus CEC execution receipts without contract failures.",
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
    let postcheck_evidence = extract_postcheck_evidence(obs);
    let postcheck_receipt_seen = !postcheck_evidence.is_empty();
    let successful_postcheck = postcheck_evidence
        .iter()
        .rev()
        .find(|entry| entry.exit_code == 0)
        .or_else(|| postcheck_evidence.last());

    let (
        isolated_target_dir_observed,
        expected_file_count_observed,
        lowercase_postcondition_observed,
        exact_final_names_observed,
        postcheck_command_success_observed,
        selected_target_dir,
        selected_final_names,
        selected_total_files,
        selected_uppercase_remaining,
        selected_command,
    ) = if let Some(entry) = successful_postcheck {
        (
            is_isolated_downloads_target(&entry.receipt.target_dir),
            entry.receipt.total_files == EXPECTED_FINAL_FILES.len(),
            entry.receipt.uppercase_remaining == 0,
            expected_final_file_set() == normalize_name_set(&entry.receipt.final_names),
            entry.exit_code == 0,
            entry.receipt.target_dir.clone(),
            entry.receipt.final_names.clone(),
            entry.receipt.total_files,
            entry.receipt.uppercase_remaining,
            entry.command.clone(),
        )
    } else {
        (
            false,
            false,
            false,
            false,
            false,
            String::new(),
            Vec::new(),
            0usize,
            usize::MAX,
            String::new(),
        )
    };

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
        && postcheck_receipt_seen
        && postcheck_command_success_observed
        && cec_phase_receipts_present
        && cec_postcondition_seen
        && !any_contract_failure_marker;

    let completion_evidence_present = (obs.completed
        && !obs.failed
        && (obs.chat_reply_count > 0 || postcheck_receipt_seen)
        && postcheck_command_success_observed)
        || timeout_after_verified_execution;

    let objective_specific_lowercase_rename_evidence_present = postcheck_receipt_seen
        && isolated_target_dir_observed
        && expected_file_count_observed
        && lowercase_postcondition_observed
        && postcheck_command_success_observed;

    let environment_receipts = build_environment_receipts(
        obs,
        cec_phase_receipts_present,
        cec_postcondition_seen,
        postcheck_receipt_seen,
        postcheck_command_success_observed,
        isolated_target_dir_observed,
        expected_file_count_observed,
        lowercase_postcondition_observed,
        &selected_target_dir,
        selected_total_files,
        selected_uppercase_remaining,
        &selected_final_names,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_lowercase_rename_evidence_present,
        tool_and_route_path_evidence_present,
        cec_phase_receipts_present && cec_postcondition_seen,
        environment_receipts_satisfied,
        !any_contract_failure_marker,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_lowercase_rename_evidence_present && independent_channel_count >= 5;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} chat_reply_count={} postcheck_receipt_seen={} postcheck_command_success_observed={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                obs.chat_reply_count,
                postcheck_receipt_seen,
                postcheck_command_success_observed,
            ),
        ),
        LocalCheck::new(
            "objective_specific_lowercase_rename_evidence_present",
            objective_specific_lowercase_rename_evidence_present,
            format!(
                "isolated_target_dir_observed={} expected_file_count_observed={} lowercase_postcondition_observed={} exact_final_names_observed={} target_dir={} total_files={} uppercase_remaining={} final_names={:?} command={}",
                isolated_target_dir_observed,
                expected_file_count_observed,
                lowercase_postcondition_observed,
                exact_final_names_observed,
                selected_target_dir,
                selected_total_files,
                selected_uppercase_remaining,
                selected_final_names,
                selected_command,
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!(
                "action_tools={:?} routing_tools={:?}",
                obs.action_tools, obs.routing_tools
            ),
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
                "independent_channel_count={} objective_specific_lowercase_rename_evidence_present={}",
                independent_channel_count, objective_specific_lowercase_rename_evidence_present
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn extract_postcheck_evidence(obs: &RunObservation) -> Vec<PostcheckEvidence> {
    let mut evidence = Vec::new();

    for entry in &obs.command_history_evidence {
        for stream in [&entry.stdout, &entry.stderr] {
            for raw_line in stream.lines() {
                let line = raw_line.trim();
                let Some(payload) = line.strip_prefix(POSTCHECK_PREFIX) else {
                    continue;
                };
                let Ok(receipt) = serde_json::from_str::<LowercaseRenamePostcheck>(payload.trim())
                else {
                    continue;
                };
                evidence.push(PostcheckEvidence {
                    receipt,
                    command: entry.command.clone(),
                    exit_code: entry.exit_code,
                });
            }
        }
    }

    evidence
}

fn expected_final_file_set() -> BTreeSet<String> {
    EXPECTED_FINAL_FILES
        .iter()
        .map(|name| name.to_string())
        .collect::<BTreeSet<_>>()
}

fn normalize_name_set(names: &[String]) -> BTreeSet<String> {
    names
        .iter()
        .map(|name| name.trim().to_string())
        .collect::<BTreeSet<_>>()
}

fn is_isolated_downloads_target(target_dir: &str) -> bool {
    let lower = target_dir.to_ascii_lowercase();
    let in_downloads = lower.contains("/downloads/")
        || lower.ends_with("/downloads")
        || lower.contains("\\downloads\\")
        || lower.ends_with("\\downloads")
        || lower.starts_with("~/downloads/");
    in_downloads && lower.contains(TARGET_DIR_TOKEN)
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
    postcheck_receipt_seen: bool,
    postcheck_command_success_observed: bool,
    isolated_target_dir_observed: bool,
    expected_file_count_observed: bool,
    lowercase_postcondition_observed: bool,
    selected_target_dir: &str,
    selected_total_files: usize,
    selected_uppercase_remaining: usize,
    selected_final_names: &[String],
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
            key: "postcheck_receipt_observed",
            observed_value: format!(
                "postcheck_receipt_seen={} postcheck_command_success_observed={}",
                postcheck_receipt_seen, postcheck_command_success_observed
            ),
            probe_source: "RunObservation.command_history_evidence.stdout/stderr",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: postcheck_receipt_seen && postcheck_command_success_observed,
        },
        EnvironmentEvidenceReceipt {
            key: "isolated_downloads_target_observed",
            observed_value: format!("target_dir={}", selected_target_dir),
            probe_source: "LOWERCASE_RENAME_POSTCHECK.target_dir",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: isolated_target_dir_observed,
        },
        EnvironmentEvidenceReceipt {
            key: "lowercase_postcondition_observed",
            observed_value: format!(
                "total_files={} uppercase_remaining={} final_names={:?}",
                selected_total_files, selected_uppercase_remaining, selected_final_names
            ),
            probe_source: "LOWERCASE_RENAME_POSTCHECK",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: expected_file_count_observed
                && lowercase_postcondition_observed
                && postcheck_command_success_observed,
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
