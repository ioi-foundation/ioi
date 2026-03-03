use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    action_has_hard_error_class, contains_any, has_cec_receipt, has_cec_stage,
    has_contract_failure_evidence, has_tool_with_token, has_verification_pair, truncate_chars,
    verification_bool, verification_u64, verification_value, ExecutionProfile, LocalCheck,
    LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str =
    "draft_an_email_to_team_ioi_network_saying_tomorrows_standup_is_moved_to_2_pm_and_send_it";
const EXPECTED_RECIPIENT: &str = "team@ioi.network";
const EXPECTED_FIXTURE_MODE: &str = "mail_reply_mock_driver_fixture_v1";

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
        query: "Draft an email to team@ioi.network saying tomorrow's standup is moved to 2 PM and send it.",
        success_definition: "Draft and send the requested standup-update email through mailbox connector tooling using the mock-driver runtime fixture with CEC receipts, runtime environment evidence, and no CIRC/CEC fallback or contract-failure markers.",
        seeded_intent_id: "mail.reply",
        intent_scope: IntentScopeProfile::Conversation,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
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

    let mail_reply_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_mail_reply_success_event(entry))
        .count();
    let mail_reply_failure_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_mail_reply_failure_event(entry))
        .count();

    let mail_tool_action_seen = has_tool_with_token(&obs.action_tools, "mail_reply");
    let mail_tool_route_seen = has_tool_with_token(&obs.routing_tools, "mail_reply");
    let web_or_browser_path_seen = has_tool_with_token(&obs.routing_tools, "web__")
        || has_tool_with_token(&obs.routing_tools, "browser__")
        || has_tool_with_token(&obs.routing_tools, "memory__search")
        || has_tool_with_token(&obs.action_tools, "web__")
        || has_tool_with_token(&obs.action_tools, "browser__")
        || has_tool_with_token(&obs.action_tools, "memory__search")
        || has_tool_with_token(&obs.workload_tools, "web__")
        || has_tool_with_token(&obs.workload_tools, "browser__");
    let non_mail_mutating_path_seen = has_tool_with_token(&obs.action_tools, "sys__exec")
        || has_tool_with_token(&obs.routing_tools, "sys__exec")
        || has_tool_with_token(&obs.action_tools, "filesystem__")
        || has_tool_with_token(&obs.routing_tools, "filesystem__")
        || has_tool_with_token(&obs.action_tools, "sys__install_package")
        || has_tool_with_token(&obs.routing_tools, "sys__install_package")
        || has_tool_with_token(&obs.action_tools, "net__fetch")
        || has_tool_with_token(&obs.routing_tools, "net__fetch");
    let disallowed_mail_tool_seen = has_tool_with_token(&obs.action_tools, "mail_read_latest")
        || has_tool_with_token(&obs.action_tools, "mail_list_recent")
        || has_tool_with_token(&obs.action_tools, "mail_delete_spam")
        || has_tool_with_token(&obs.routing_tools, "mail_read_latest")
        || has_tool_with_token(&obs.routing_tools, "mail_list_recent")
        || has_tool_with_token(&obs.routing_tools, "mail_delete_spam")
        || has_tool_with_token(&obs.workload_tools, "mail_read_latest")
        || has_tool_with_token(&obs.workload_tools, "mail_list_recent")
        || has_tool_with_token(&obs.workload_tools, "mail_delete_spam");

    let to_field_present = output_lower.contains("\"to\":");
    let redacted_to_field_present = output_lower.contains("\"to\":\"<redacted:email>\"")
        || output_lower.contains("\"to\": \"<redacted:email>\"");
    let reply_recipient_present =
        reply_lower.contains(EXPECTED_RECIPIENT) || reply_lower.contains("<redacted:email>");
    let recipient_binding_present = output_lower
        .contains(&format!("\"to\":\"{}\"", EXPECTED_RECIPIENT))
        || output_lower.contains(&format!("\"to\": \"{}\"", EXPECTED_RECIPIENT))
        || redacted_to_field_present
        || (to_field_present && reply_recipient_present);
    let sent_message_id_present = output_lower.contains("\"sent_message_id\":");
    let mailbox_output_present = output_lower.contains("\"mailbox\":");
    let citation_field_present = output_lower.contains("\"citation\":");
    let mailto_citation_present = output_lower.contains(&format!("mailto:{}", EXPECTED_RECIPIENT))
        || (citation_field_present && output_lower.contains("<redacted:email>"))
        || citation_field_present;
    let schedule_change_evidence_present = schedule_change_phrase_present(&output_lower)
        || schedule_change_phrase_present(&reply_lower);
    let objective_specific_mail_send_evidence_present = mail_reply_success_count > 0
        && mail_reply_failure_count == 0
        && recipient_binding_present
        && sent_message_id_present
        && mailbox_output_present
        && mailto_citation_present
        && schedule_change_evidence_present;

    let setup_env_loaded = has_verification_pair(obs, "env_receipt::mail_env_file_loaded", "true");
    let setup_connector_bootstrap =
        has_verification_pair(obs, "env_receipt::mail_connector_bootstrap", "true");
    let setup_channel_seeded =
        has_verification_pair(obs, "env_receipt::mail_channel_seeded", "true");
    let setup_lease_seeded = has_verification_pair(obs, "env_receipt::mail_lease_seeded", "true");
    let setup_send_capability_seeded =
        has_verification_pair(obs, "env_receipt::mail_send_capability_seeded", "true");
    let setup_provider_driver =
        verification_value(obs, "env_receipt::mail_provider_driver").unwrap_or_default();
    let setup_provider_driver_source =
        verification_value(obs, "env_receipt::mail_provider_driver_source").unwrap_or_default();
    let setup_provider_driver_satisfied = setup_provider_driver.eq_ignore_ascii_case("mock")
        && setup_provider_driver_source.eq_ignore_ascii_case("fixture_override");
    let setup_receipt_timestamp_present =
        verification_value(obs, "env_receipt::mail_setup_timestamp_ms").is_some();

    let fixture_mode =
        verification_value(obs, "env_receipt::mail_reply_fixture_mode").unwrap_or_default();
    let fixture_probe_source =
        verification_value(obs, "env_receipt::mail_reply_fixture_probe_source").unwrap_or_default();
    let fixture_timestamp_ms =
        verification_u64(obs, "env_receipt::mail_reply_fixture_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied =
        verification_bool(obs, "env_receipt::mail_reply_fixture_satisfied").unwrap_or(false);
    let fixture_cleanup_satisfied =
        verification_bool(obs, "env_receipt::mail_reply_fixture_cleanup_satisfied")
            .unwrap_or(false);
    let fixture_run_unique_satisfied =
        verification_bool(obs, "env_receipt::mail_reply_fixture_run_unique_satisfied")
            .unwrap_or(false);

    let connector_environment_setup_receipts_present = setup_env_loaded
        && setup_connector_bootstrap
        && setup_channel_seeded
        && setup_lease_seeded
        && setup_send_capability_seeded
        && setup_provider_driver_satisfied
        && setup_receipt_timestamp_present;

    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_completion_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true)) || obs.completed;
    let cec_phase_receipts_present =
        cec_execution_seen && cec_verification_seen && cec_completion_gate_seen;

    let mailbox_runtime_fallback_markers_present =
        verification_bool(obs, "mailbox_connector_path_required").unwrap_or(false)
            || verification_bool(obs, "mailbox_non_connector_tool_blocked").unwrap_or(false)
            || verification_bool(obs, "mailbox_invalid_tool_call_fail_fast").unwrap_or(false)
            || verification_bool(obs, "mailbox_system_fail_degraded_to_reply").unwrap_or(false);
    let mailbox_response_fallback_markers_present = has_mailbox_fallback_marker(&obs.final_reply)
        || obs
            .event_excerpt
            .iter()
            .any(|line| has_mailbox_fallback_marker(line));
    let mailbox_fallback_markers_present =
        mailbox_runtime_fallback_markers_present || mailbox_response_fallback_markers_present;
    let no_mailbox_fallback_markers = !mailbox_fallback_markers_present;

    let any_contract_failure_marker =
        has_contract_failure_evidence(obs) || has_mailbox_runtime_failure_marker(obs);
    let completion_evidence_present = obs.completed
        && !obs.failed
        && ((!obs.final_reply.trim().is_empty() && obs.chat_reply_count > 0)
            || objective_specific_mail_send_evidence_present);
    let reply_addresses_user_request = !obs.final_reply.trim().is_empty()
        && contains_any(
            &reply_lower,
            &[
                "email",
                "sent",
                "standup",
                "2 pm",
                "2:00 pm",
                "moved",
                EXPECTED_RECIPIENT,
            ],
        );

    let environment_receipts = build_environment_receipts(
        obs,
        fixture_mode.clone(),
        fixture_probe_source.clone(),
        fixture_timestamp_ms,
        fixture_satisfied,
        fixture_cleanup_satisfied,
        fixture_run_unique_satisfied,
        connector_environment_setup_receipts_present,
        setup_provider_driver.clone(),
        setup_provider_driver_source.clone(),
        setup_send_capability_seeded,
        mail_reply_success_count,
        mail_reply_failure_count,
        recipient_binding_present,
        mailto_citation_present,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_mail_send_evidence_present,
        mail_tool_action_seen
            && mail_tool_route_seen
            && !web_or_browser_path_seen
            && !non_mail_mutating_path_seen
            && !disallowed_mail_tool_seen,
        connector_environment_setup_receipts_present && environment_receipts_satisfied,
        cec_phase_receipts_present,
        reply_addresses_user_request,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_mail_send_evidence_present && independent_channel_count >= 4;

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
            "objective_specific_mail_send_evidence_present",
            objective_specific_mail_send_evidence_present,
            format!(
                "mail_reply_success_count={} mail_reply_failure_count={} recipient_binding_present={} sent_message_id_present={} mailbox_output_present={} mailto_citation_present={} schedule_change_evidence_present={}",
                mail_reply_success_count,
                mail_reply_failure_count,
                recipient_binding_present,
                sent_message_id_present,
                mailbox_output_present,
                mailto_citation_present,
                schedule_change_evidence_present
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            mail_tool_action_seen
                && mail_tool_route_seen
                && !web_or_browser_path_seen
                && !non_mail_mutating_path_seen
                && !disallowed_mail_tool_seen,
            format!(
                "mail_tool_action_seen={} mail_tool_route_seen={} web_or_browser_path_seen={} non_mail_mutating_path_seen={} disallowed_mail_tool_seen={} action_tools={:?} routing_tools={:?} workload_tools={:?}",
                mail_tool_action_seen,
                mail_tool_route_seen,
                web_or_browser_path_seen,
                non_mail_mutating_path_seen,
                disallowed_mail_tool_seen,
                obs.action_tools,
                obs.routing_tools,
                obs.workload_tools
            ),
        ),
        LocalCheck::new(
            "connector_environment_setup_receipts_present",
            connector_environment_setup_receipts_present,
            format!(
                "setup_provider_driver={} setup_provider_driver_source={} verification_checks={:?}",
                setup_provider_driver, setup_provider_driver_source, obs.verification_checks
            ),
        ),
        LocalCheck::new(
            "cec_phase_receipts_present",
            cec_phase_receipts_present,
            format!("cec_receipts={:?}", obs.cec_receipts),
        ),
        LocalCheck::new(
            "no_mailbox_fallback_markers",
            no_mailbox_fallback_markers,
            truncate_chars(
                &format!(
                    "mailbox_fallback_markers_present={} verification_checks={:?} final_reply={} event_excerpt={:?}",
                    mailbox_fallback_markers_present, obs.verification_checks, obs.final_reply, obs.event_excerpt
                ),
                280,
            ),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            !any_contract_failure_marker && mail_reply_failure_count == 0,
            truncate_chars(
                &format!(
                    "mail_reply_failure_count={} verification_checks={:?} final_reply={} action_output={}",
                    mail_reply_failure_count, obs.verification_checks, obs.final_reply, action_output_blob
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
                "independent_channel_count={} objective_specific_mail_send_evidence_present={} reply_addresses_user_request={}",
                independent_channel_count,
                objective_specific_mail_send_evidence_present,
                reply_addresses_user_request
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn is_mail_reply_success_event(entry: &super::super::types::ActionEvidence) -> bool {
    let lower = entry.output_excerpt.to_ascii_lowercase();
    let status_lower = entry.agent_status.to_ascii_lowercase();
    let non_failure_status = !contains_any(
        &status_lower,
        &[
            "fail", "error", "blocked", "deny", "reject", "terminal", "abort",
        ],
    );

    is_mail_reply_tool_name(&entry.tool_name)
        && non_failure_status
        && !action_has_hard_error_class(entry)
        && (lower.contains("\"operation\":\"mail_reply@v1\"")
            || lower.contains("\"operation\": \"mail_reply@v1\""))
}

fn is_mail_reply_failure_event(entry: &super::super::types::ActionEvidence) -> bool {
    if !is_mail_reply_tool_name(&entry.tool_name) {
        return false;
    }
    entry.agent_status.eq_ignore_ascii_case("failed") || action_has_hard_error_class(entry)
}

fn is_mail_reply_tool_name(tool_name: &str) -> bool {
    let lower = tool_name.to_ascii_lowercase();
    lower == "wallet_network__mail_reply"
        || lower == "wallet_mail_reply"
        || lower == "mail__reply"
        || lower.contains("mail_reply")
}

fn schedule_change_phrase_present(text: &str) -> bool {
    let has_standup = text.contains("standup");
    let has_move_or_change = text.contains("moved")
        || text.contains("rescheduled")
        || text.contains("moved to")
        || text.contains("move to")
        || text.contains("time change")
        || text.contains("schedule change")
        || text.contains("change")
        || text.contains("change of")
        || text.contains("change in")
        || text.contains("changed");
    let has_two_pm = text.contains("2 pm")
        || text.contains("2:00 pm")
        || text.contains("2pm")
        || text.contains("14:00");
    has_standup && (has_move_or_change || has_two_pm)
}

#[allow(clippy::too_many_arguments)]
fn build_environment_receipts(
    obs: &RunObservation,
    fixture_mode: String,
    fixture_probe_source: String,
    fixture_timestamp_ms: u64,
    fixture_satisfied: bool,
    fixture_cleanup_satisfied: bool,
    fixture_run_unique_satisfied: bool,
    connector_environment_setup_receipts_present: bool,
    setup_provider_driver: String,
    setup_provider_driver_source: String,
    setup_send_capability_seeded: bool,
    mail_reply_success_count: usize,
    mail_reply_failure_count: usize,
    recipient_binding_present: bool,
    mailto_citation_present: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "mail_reply_fixture_mode_observed",
            observed_value: format!(
                "mode={} fixture_satisfied={} fixture_cleanup_satisfied={} fixture_run_unique_satisfied={}",
                fixture_mode,
                fixture_satisfied,
                fixture_cleanup_satisfied,
                fixture_run_unique_satisfied
            ),
            probe_source: if fixture_probe_source.trim().is_empty() {
                "RunObservation.verification_facts".to_string()
            } else {
                fixture_probe_source
            },
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE)
                && fixture_satisfied
                && fixture_cleanup_satisfied
                && fixture_run_unique_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "mail_connector_runtime_configured",
            observed_value: format!(
                "connector_setup_receipts_present={} provider_driver={} provider_driver_source={} setup_send_capability_seeded={}",
                connector_environment_setup_receipts_present,
                setup_provider_driver,
                setup_provider_driver_source,
                setup_send_capability_seeded
            ),
            probe_source: "RunObservation.verification_facts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: connector_environment_setup_receipts_present
                && setup_provider_driver.eq_ignore_ascii_case("mock")
                && setup_provider_driver_source.eq_ignore_ascii_case("fixture_override")
                && setup_send_capability_seeded,
        },
        EnvironmentEvidenceReceipt {
            key: "mail_reply_execution_observed",
            observed_value: format!(
                "mail_reply_success_count={} mail_reply_failure_count={}",
                mail_reply_success_count, mail_reply_failure_count
            ),
            probe_source:
                "KernelEvent::AgentActionResult(tool=wallet_network__mail_reply|mail__reply)"
                    .to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: mail_reply_success_count > 0 && mail_reply_failure_count == 0,
        },
        EnvironmentEvidenceReceipt {
            key: "mail_reply_recipient_binding_observed",
            observed_value: format!("recipient_binding_present={}", recipient_binding_present),
            probe_source: "mail_reply action payload.to".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: recipient_binding_present,
        },
        EnvironmentEvidenceReceipt {
            key: "mail_reply_citation_observed",
            observed_value: format!("mailto_citation_present={}", mailto_citation_present),
            probe_source: "mail_reply action payload.citation".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: mailto_citation_present,
        },
    ]
}

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
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

fn has_mailbox_runtime_failure_marker(obs: &RunObservation) -> bool {
    [
        "wallet_network service is not active in the servicedirectory",
        "unable to resolve wallet mail channel_id",
        "unable to resolve wallet mail lease_id",
        "mail connector for mailbox",
        "no wallet mail lease binding available",
        "lease does not authorize mail reply capability",
        "channel does not authorize mail reply capability",
        "mail_reply requires non-empty to, subject, and body",
        "smtp send failed",
    ]
    .iter()
    .any(|marker| {
        let marker = marker.to_ascii_lowercase();
        obs.final_reply.to_ascii_lowercase().contains(&marker)
            || obs
                .action_evidence
                .iter()
                .any(|entry| entry.output_excerpt.to_ascii_lowercase().contains(&marker))
            || obs
                .event_excerpt
                .iter()
                .any(|line| line.to_ascii_lowercase().contains(&marker))
    })
}
