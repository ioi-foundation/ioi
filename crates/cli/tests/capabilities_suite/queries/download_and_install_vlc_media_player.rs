use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    contains_any, has_tool_with_token, truncate_chars, LocalCheck, LocalJudgeResult, QueryCase,
    RunObservation,
};

const EXPECTED_FIXTURE_MODE: &str = "apt_get_vlc_fixture_v1";

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
        id: "download_and_install_vlc_media_player",
        query: "Download and install VLC media player.",
        success_definition: "Install VLC through the package-install execution path, satisfy CEC discovery/execution/verification receipts, and prove download/install/binary postconditions through fixture-backed environment receipts.",
        seeded_intent_id: "command.exec.install_dependency",
        intent_scope: IntentScopeProfile::CommandExecution,
        seed_resolved_intent: true,
        expected_pass: true,
        sla_seconds: 120,
        max_steps: 22,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: true,
        allow_timeout_completion_with_local_evidence: true,
        local_sniff: evaluate,
    }
}

pub fn case_unseeded() -> QueryCase {
    QueryCase {
        id: "download_and_install_vlc_media_player_unseeded",
        query: "Download and install VLC media player.",
        success_definition: "Resolve and execute VLC install without seeded intent override: route through package-install execution, satisfy CEC discovery/execution/verification receipts, and prove download/install/binary postconditions through fixture-backed environment receipts.",
        seeded_intent_id: "command.exec.install_dependency",
        intent_scope: IntentScopeProfile::CommandExecution,
        seed_resolved_intent: false,
        expected_pass: true,
        sla_seconds: 120,
        max_steps: 22,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: true,
        allow_timeout_completion_with_local_evidence: true,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let install_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_vlc_install_success(entry))
        .count();
    let install_action_hard_failure_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_vlc_install_hard_failure(entry))
        .count();

    let action_install_path_seen = has_tool_with_token(&obs.action_tools, "sys__install_package");
    let routing_install_path_seen = has_tool_with_token(&obs.routing_tools, "sys__install_package");
    let tool_and_route_path_evidence_present =
        action_install_path_seen && routing_install_path_seen;

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
        && cec_verification_seen
        && cec_postcondition_seen;

    let fixture_mode =
        verification_value(obs, "env_receipt::vlc_fixture_mode=").unwrap_or_default();
    let fixture_mode_satisfied = fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE);
    let fixture_probe_source =
        verification_value(obs, "env_receipt::vlc_fixture_probe_source=").unwrap_or_default();
    let fixture_timestamp_ms = verification_u64(obs, "env_receipt::vlc_fixture_timestamp_ms=")
        .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied =
        verification_bool(obs, "env_receipt::vlc_fixture_satisfied=").unwrap_or(false);

    let download_receipt_path =
        verification_value(obs, "env_receipt::vlc_download_receipt_path=").unwrap_or_default();
    let download_receipt_probe_source =
        verification_value(obs, "env_receipt::vlc_download_receipt_probe_source=")
            .unwrap_or_default();
    let download_receipt_timestamp_ms =
        verification_u64(obs, "env_receipt::vlc_download_receipt_timestamp_ms=")
            .unwrap_or(obs.run_timestamp_ms);
    let download_receipt_satisfied =
        verification_bool(obs, "env_receipt::vlc_download_receipt_satisfied=").unwrap_or(false);

    let install_receipt_path =
        verification_value(obs, "env_receipt::vlc_install_receipt_path=").unwrap_or_default();
    let install_receipt_probe_source =
        verification_value(obs, "env_receipt::vlc_install_receipt_probe_source=")
            .unwrap_or_default();
    let install_receipt_timestamp_ms =
        verification_u64(obs, "env_receipt::vlc_install_receipt_timestamp_ms=")
            .unwrap_or(obs.run_timestamp_ms);
    let install_receipt_satisfied =
        verification_bool(obs, "env_receipt::vlc_install_receipt_satisfied=").unwrap_or(false);
    let install_receipt_value =
        verification_value(obs, "env_receipt::vlc_install_receipt_value=").unwrap_or_default();
    let install_receipt_value_satisfied =
        verification_bool(obs, "env_receipt::vlc_install_receipt_value_satisfied=")
            .unwrap_or(false)
            && install_receipt_value.eq_ignore_ascii_case("vlc");

    let vlc_binary_path =
        verification_value(obs, "env_receipt::vlc_binary_path=").unwrap_or_default();
    let vlc_binary_probe_source =
        verification_value(obs, "env_receipt::vlc_binary_probe_source=").unwrap_or_default();
    let vlc_binary_timestamp_ms = verification_u64(obs, "env_receipt::vlc_binary_timestamp_ms=")
        .unwrap_or(obs.run_timestamp_ms);
    let vlc_binary_satisfied =
        verification_bool(obs, "env_receipt::vlc_binary_satisfied=").unwrap_or(false);

    let objective_specific_vlc_install_evidence_present = install_action_success_count > 0
        && install_action_hard_failure_count == 0
        && fixture_mode_satisfied
        && fixture_satisfied
        && download_receipt_satisfied
        && install_receipt_satisfied
        && install_receipt_value_satisfied
        && vlc_binary_satisfied;

    let any_contract_failure_marker = observation_has_contract_failure_marker(obs);
    let retry_blocked_terminal = obs
        .final_status
        .to_ascii_lowercase()
        .contains("retry blocked: unchanged attemptkey for noeffectafteraction");
    let timeout_terminal = obs
        .final_status
        .to_ascii_lowercase()
        .contains("timeoutorhang")
        || has_verification_check(obs, "failure_class=TimeoutOrHang");
    let completion_evidence_present = (obs.completed
        && !obs.failed
        && (obs.chat_reply_count > 0 || install_action_success_count > 0))
        || ((retry_blocked_terminal || timeout_terminal)
            && objective_specific_vlc_install_evidence_present
            && !any_contract_failure_marker);

    let environment_receipts = build_environment_receipts(
        obs,
        fixture_mode,
        fixture_mode_satisfied,
        fixture_probe_source,
        fixture_timestamp_ms,
        fixture_satisfied,
        download_receipt_path,
        download_receipt_probe_source,
        download_receipt_timestamp_ms,
        download_receipt_satisfied,
        install_receipt_path,
        install_receipt_probe_source,
        install_receipt_timestamp_ms,
        install_receipt_satisfied,
        install_receipt_value,
        install_receipt_value_satisfied,
        vlc_binary_path,
        vlc_binary_probe_source,
        vlc_binary_timestamp_ms,
        vlc_binary_satisfied,
        cec_phase_receipts_present,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_vlc_install_evidence_present,
        tool_and_route_path_evidence_present,
        cec_phase_receipts_present,
        environment_receipts_satisfied,
        !any_contract_failure_marker,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_vlc_install_evidence_present && independent_channel_count >= 5;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} chat_reply_count={} install_action_success_count={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                obs.chat_reply_count,
                install_action_success_count
            ),
        ),
        LocalCheck::new(
            "objective_specific_vlc_install_evidence_present",
            objective_specific_vlc_install_evidence_present,
            format!(
                "install_action_success_count={} install_action_failure_count={} fixture_mode_satisfied={} fixture_satisfied={} download_receipt_satisfied={} install_receipt_satisfied={} install_receipt_value_satisfied={} vlc_binary_satisfied={}",
                install_action_success_count,
                install_action_hard_failure_count,
                fixture_mode_satisfied,
                fixture_satisfied,
                download_receipt_satisfied,
                install_receipt_satisfied,
                install_receipt_value_satisfied,
                vlc_binary_satisfied
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
            cec_phase_receipts_present,
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
            "environment_receipts_satisfied",
            environment_receipts_satisfied,
            serialize_environment_receipts(&environment_receipts),
        ),
        LocalCheck::new(
            "independent_runtime_evidence_channels_present",
            independent_runtime_evidence_channels_present,
            format!(
                "independent_channel_count={} objective_specific_vlc_install_evidence_present={}",
                independent_channel_count, objective_specific_vlc_install_evidence_present
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn is_vlc_install_success(entry: &super::super::types::ActionEvidence) -> bool {
    let output = entry.output_excerpt.to_ascii_lowercase();
    entry.tool_name.eq_ignore_ascii_case("sys__install_package")
        && output.contains("installed 'vlc'")
        && output.contains("apt-get")
        && !output.contains("error_class=")
}

fn is_vlc_install_hard_failure(entry: &super::super::types::ActionEvidence) -> bool {
    let output = entry.output_excerpt.to_ascii_lowercase();
    let duplicate_no_effect = output.contains("error_class=noeffectafteraction")
        || output.contains("skipped immediate replay")
        || output.contains("duplicate command action was blocked");
    entry.tool_name.eq_ignore_ascii_case("sys__install_package")
        && !duplicate_no_effect
        && (entry.agent_status.eq_ignore_ascii_case("failed")
            || output.contains("failed to install 'vlc'")
            || output.contains("error_class="))
}

fn has_verification_check(obs: &RunObservation, expected: &str) -> bool {
    obs.verification_checks
        .iter()
        .any(|check| check.eq_ignore_ascii_case(expected))
}

fn verification_value(obs: &RunObservation, prefix: &str) -> Option<String> {
    obs.verification_checks
        .iter()
        .find_map(|check| check.strip_prefix(prefix).map(|value| value.to_string()))
}

fn verification_bool(obs: &RunObservation, prefix: &str) -> Option<bool> {
    verification_value(obs, prefix).and_then(|value| {
        match value.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }
    })
}

fn verification_u64(obs: &RunObservation, prefix: &str) -> Option<u64> {
    verification_value(obs, prefix).and_then(|value| value.trim().parse::<u64>().ok())
}

#[allow(clippy::too_many_arguments)]
fn build_environment_receipts(
    obs: &RunObservation,
    fixture_mode: String,
    fixture_mode_satisfied: bool,
    fixture_probe_source: String,
    fixture_timestamp_ms: u64,
    fixture_satisfied: bool,
    download_receipt_path: String,
    download_receipt_probe_source: String,
    download_receipt_timestamp_ms: u64,
    download_receipt_satisfied: bool,
    install_receipt_path: String,
    install_receipt_probe_source: String,
    install_receipt_timestamp_ms: u64,
    install_receipt_satisfied: bool,
    install_receipt_value: String,
    install_receipt_value_satisfied: bool,
    vlc_binary_path: String,
    vlc_binary_probe_source: String,
    vlc_binary_timestamp_ms: u64,
    vlc_binary_satisfied: bool,
    cec_phase_receipts_present: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "vlc_fixture_mode_observed",
            observed_value: fixture_mode,
            probe_source: fixture_probe_source,
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode_satisfied && fixture_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "vlc_download_receipt_observed",
            observed_value: download_receipt_path,
            probe_source: download_receipt_probe_source,
            timestamp_ms: download_receipt_timestamp_ms,
            satisfied: download_receipt_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "vlc_install_receipt_observed",
            observed_value: install_receipt_path,
            probe_source: install_receipt_probe_source,
            timestamp_ms: install_receipt_timestamp_ms,
            satisfied: install_receipt_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "vlc_install_receipt_value_observed",
            observed_value: install_receipt_value,
            probe_source: "env_receipt::vlc_install_receipt_value".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: install_receipt_value_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "vlc_binary_observed",
            observed_value: vlc_binary_path,
            probe_source: vlc_binary_probe_source,
            timestamp_ms: vlc_binary_timestamp_ms,
            satisfied: vlc_binary_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "cec_phase_receipts_observed",
            observed_value: format!("verification_checks={:?}", obs.verification_checks),
            probe_source: "RunObservation.verification_checks".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_phase_receipts_present,
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
    contains_any(
        &lower,
        &[
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
            "failed_stage=",
        ],
    )
}
