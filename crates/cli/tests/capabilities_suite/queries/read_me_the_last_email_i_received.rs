use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    contains_any, has_tool_with_token, truncate_chars, LocalCheck, LocalJudgeResult, QueryCase,
    RunObservation,
};

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
        id: "read_me_the_last_email_i_received",
        query: "Read me the last email I received.",
        success_definition: "Read the latest inbox message through mailbox connector tooling with runtime connector setup receipts, structured message evidence, and no CEC/CIRC contract failures or mailbox fallback markers.",
        seeded_intent_id: "mail.read.latest",
        intent_scope: IntentScopeProfile::Conversation,
        seed_resolved_intent: true,
        expected_pass: true,
        sla_seconds: 90,
        max_steps: 16,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let reply_lower = obs.final_reply.to_ascii_lowercase();
    let action_output_blob = obs
        .action_evidence
        .iter()
        .map(|entry| entry.output_excerpt.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let output_lower = action_output_blob.to_ascii_lowercase();

    let mail_read_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_mail_read_latest_success_event(entry))
        .count();
    let mail_read_failure_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_mail_read_latest_failure_event(entry))
        .count();

    let mail_tool_action_seen = has_tool_with_token(&obs.action_tools, "mail_read_latest");
    let mail_tool_route_seen = has_tool_with_token(&obs.routing_tools, "mail_read_latest");
    let web_or_browser_path_seen = has_tool_with_token(&obs.routing_tools, "web__search")
        || has_tool_with_token(&obs.routing_tools, "web__read")
        || has_tool_with_token(&obs.routing_tools, "browser__")
        || has_tool_with_token(&obs.action_tools, "web__search")
        || has_tool_with_token(&obs.action_tools, "web__read")
        || has_tool_with_token(&obs.action_tools, "browser__")
        || has_tool_with_token(&obs.workload_tools, "web__search")
        || has_tool_with_token(&obs.workload_tools, "web__read");

    let structured_mail_payload_present = message_payload_fields_present(&output_lower);
    let imap_citation_present = imap_citation_present(&output_lower);
    let received_timestamp_present = output_lower.contains("\"received_at_ms\":")
        || output_lower.contains("\"received_at_utc\":");
    let mailbox_output_present = output_lower.contains("\"mailbox\":");
    let objective_specific_mail_read_evidence_present = mail_read_success_count > 0
        && structured_mail_payload_present
        && imap_citation_present
        && received_timestamp_present
        && mailbox_output_present;

    let setup_env_loaded = has_verification_check(obs, "env_receipt::mail_env_file_loaded=true");
    let setup_connector_bootstrap =
        has_verification_check(obs, "env_receipt::mail_connector_bootstrap=true");
    let setup_channel_seeded = has_verification_check(obs, "env_receipt::mail_channel_seeded=true");
    let setup_lease_seeded = has_verification_check(obs, "env_receipt::mail_lease_seeded=true");
    let setup_receipt_timestamp_present =
        verification_value(obs, "env_receipt::mail_setup_timestamp_ms=").is_some();
    let setup_mailbox = verification_value(obs, "env_receipt::mail_mailbox=");
    let setup_mailbox_binding_present = setup_mailbox
        .as_ref()
        .map(|mailbox| {
            output_lower.contains(&format!("\"mailbox\":\"{}\"", mailbox.to_ascii_lowercase()))
                || output_lower.contains(&format!(
                    "\"mailbox\": \"{}\"",
                    mailbox.to_ascii_lowercase()
                ))
        })
        .unwrap_or(false);

    let connector_environment_setup_receipts_present = setup_env_loaded
        && setup_connector_bootstrap
        && setup_channel_seeded
        && setup_lease_seeded
        && setup_receipt_timestamp_present;

    let mailbox_fallback_markers_present = has_mailbox_fallback_marker(&obs.final_reply)
        || obs
            .verification_checks
            .iter()
            .any(|check| has_mailbox_fallback_marker(check))
        || obs
            .event_excerpt
            .iter()
            .any(|line| has_mailbox_fallback_marker(line));

    let any_contract_failure_marker = observation_has_contract_failure_marker(obs);
    let completion_evidence_present = obs.completed
        && !obs.failed
        && ((!obs.final_reply.trim().is_empty() && obs.chat_reply_count > 0)
            || objective_specific_mail_read_evidence_present);
    let reply_addresses_user_request = !obs.final_reply.trim().is_empty()
        && contains_any(
            &reply_lower,
            &[
                "email", "subject", "from", "received", "latest", "last", "inbox",
            ],
        )
        && !reply_lower.contains("cannot access your mailbox")
        && !reply_lower.contains("access limitation");

    let environment_receipts = build_environment_receipts(
        obs,
        mail_read_success_count,
        mail_read_failure_count,
        connector_environment_setup_receipts_present,
        setup_mailbox.clone(),
        setup_mailbox_binding_present,
        imap_citation_present,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_mail_read_evidence_present,
        mail_tool_action_seen && mail_tool_route_seen && !web_or_browser_path_seen,
        connector_environment_setup_receipts_present && environment_receipts_satisfied,
        imap_citation_present && received_timestamp_present,
        reply_addresses_user_request,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_mail_read_evidence_present && independent_channel_count >= 4;

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
            "objective_specific_mail_read_evidence_present",
            objective_specific_mail_read_evidence_present,
            format!(
                "mail_read_success_count={} structured_mail_payload_present={} imap_citation_present={} received_timestamp_present={} mailbox_output_present={}",
                mail_read_success_count,
                structured_mail_payload_present,
                imap_citation_present,
                received_timestamp_present,
                mailbox_output_present
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            mail_tool_action_seen && mail_tool_route_seen && !web_or_browser_path_seen,
            format!(
                "mail_tool_action_seen={} mail_tool_route_seen={} web_or_browser_path_seen={} action_tools={:?} routing_tools={:?} workload_tools={:?}",
                mail_tool_action_seen,
                mail_tool_route_seen,
                web_or_browser_path_seen,
                obs.action_tools,
                obs.routing_tools,
                obs.workload_tools
            ),
        ),
        LocalCheck::new(
            "connector_environment_setup_receipts_present",
            connector_environment_setup_receipts_present,
            format!("verification_checks={:?}", obs.verification_checks),
        ),
        LocalCheck::new(
            "mailbox_binding_consistency_present",
            setup_mailbox_binding_present,
            format!(
                "setup_mailbox={:?} output_excerpt={}",
                setup_mailbox,
                truncate_chars(&action_output_blob, 220)
            ),
        ),
        LocalCheck::new(
            "source_and_quality_evidence_present",
            imap_citation_present && message_payload_fields_present(&output_lower),
            truncate_chars(&action_output_blob, 220),
        ),
        LocalCheck::new(
            "no_mailbox_fallback_markers",
            !mailbox_fallback_markers_present,
            truncate_chars(
                &format!(
                    "verification_checks={:?} final_reply={} event_excerpt={:?}",
                    obs.verification_checks, obs.final_reply, obs.event_excerpt
                ),
                260,
            ),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            !any_contract_failure_marker && mail_read_failure_count == 0,
            truncate_chars(
                &format!(
                    "mail_read_failure_count={} verification_checks={:?} final_reply={} action_output={}",
                    mail_read_failure_count, obs.verification_checks, obs.final_reply, action_output_blob
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
                "independent_channel_count={} objective_specific_mail_read_evidence_present={} reply_addresses_user_request={}",
                independent_channel_count,
                objective_specific_mail_read_evidence_present,
                reply_addresses_user_request
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn is_mail_read_latest_success_event(entry: &super::super::types::ActionEvidence) -> bool {
    let lower = entry.output_excerpt.to_ascii_lowercase();
    let status_lower = entry.agent_status.to_ascii_lowercase();
    let non_failure_status = !contains_any(
        &status_lower,
        &[
            "fail", "error", "blocked", "deny", "reject", "terminal", "abort",
        ],
    );
    is_mail_read_latest_tool_name(&entry.tool_name)
        && non_failure_status
        && !has_contract_failure_marker(&entry.output_excerpt)
        && !lower.contains("error_class=")
        && !lower.contains("\"error_class\":")
        && (imap_citation_present(&lower)
            || (lower.contains("\"mailbox\":") && lower.contains("\"message\":")))
}

fn is_mail_read_latest_failure_event(entry: &super::super::types::ActionEvidence) -> bool {
    if !is_mail_read_latest_tool_name(&entry.tool_name) {
        return false;
    }
    entry.agent_status.eq_ignore_ascii_case("failed")
        || has_contract_failure_marker(&entry.output_excerpt)
        || entry
            .output_excerpt
            .to_ascii_lowercase()
            .contains("error_class=")
}

fn is_mail_read_latest_tool_name(tool_name: &str) -> bool {
    let lower = tool_name.to_ascii_lowercase();
    lower == "wallet_network__mail_read_latest"
        || lower == "wallet_mail_read_latest"
        || lower == "mail__read_latest"
        || lower.contains("mail_read_latest")
}

fn message_payload_fields_present(lower: &str) -> bool {
    lower.contains("\"message_id\":")
        && lower.contains("\"from\":")
        && lower.contains("\"subject\":")
        && lower.contains("\"preview\":")
}

fn imap_citation_present(lower: &str) -> bool {
    lower.contains("\"citation\":\"imap://") || lower.contains("\"citation\": \"imap://")
}

fn has_verification_check(obs: &RunObservation, expected: &str) -> bool {
    obs.verification_checks
        .iter()
        .any(|check| check.eq_ignore_ascii_case(expected))
}

fn verification_value(obs: &RunObservation, prefix: &str) -> Option<String> {
    obs.verification_checks
        .iter()
        .find_map(|check| check.strip_prefix(prefix))
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

fn build_environment_receipts(
    obs: &RunObservation,
    mail_read_success_count: usize,
    mail_read_failure_count: usize,
    connector_environment_setup_receipts_present: bool,
    setup_mailbox: Option<String>,
    setup_mailbox_binding_present: bool,
    imap_citation_present: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "mail_env_bootstrap_loaded",
            observed_value: format!(
                "env_receipt::mail_env_file_loaded={}",
                has_verification_check(obs, "env_receipt::mail_env_file_loaded=true")
            ),
            probe_source: "RunObservation.verification_checks",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: has_verification_check(obs, "env_receipt::mail_env_file_loaded=true"),
        },
        EnvironmentEvidenceReceipt {
            key: "mail_connector_runtime_configured",
            observed_value: format!(
                "connector_setup_receipts_present={}",
                connector_environment_setup_receipts_present
            ),
            probe_source: "RunObservation.verification_checks",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: connector_environment_setup_receipts_present,
        },
        EnvironmentEvidenceReceipt {
            key: "mail_connector_execution_observed",
            observed_value: format!(
                "mail_read_success_count={} mail_read_failure_count={}",
                mail_read_success_count, mail_read_failure_count
            ),
            probe_source:
                "KernelEvent::AgentActionResult(tool=wallet_network__mail_read_latest|mail__read_latest)",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: mail_read_success_count > 0 && mail_read_failure_count == 0,
        },
        EnvironmentEvidenceReceipt {
            key: "mailbox_binding_observed",
            observed_value: format!(
                "setup_mailbox={:?} setup_mailbox_binding_present={}",
                setup_mailbox, setup_mailbox_binding_present
            ),
            probe_source: "env_receipt::mail_mailbox + mail_read_latest action payload",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: setup_mailbox.is_some() && setup_mailbox_binding_present,
        },
        EnvironmentEvidenceReceipt {
            key: "mail_source_citation_observed",
            observed_value: format!("imap_citation_present={}", imap_citation_present),
            probe_source: "mail_read_latest action payload citation field",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: imap_citation_present,
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

fn has_mailbox_fallback_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "mailbox_connector_path_required=true",
        "mailbox_non_connector_tool_blocked=true",
        "mailbox_invalid_tool_call_fail_fast=true",
        "mailbox_system_fail_degraded_to_reply=true",
        "cannot access your mailbox",
        "access limitation",
        "mailbox content cannot be verified without direct mailbox access",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
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
        "failed_stage=",
        "missing_receipts=",
        "missing_postconditions=",
        "wallet_network service is not active in the servicedirectory",
        "unable to resolve wallet mail channel_id",
        "unable to resolve wallet mail lease_id",
        "mail connector for mailbox",
        "no wallet mail lease binding available",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}
