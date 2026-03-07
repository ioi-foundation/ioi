use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    has_cec_receipt, has_cec_stage, has_contract_failure_evidence, has_tool_with_token,
    has_verification_pair, truncate_chars, uri_scheme, verification_bool, verification_u64,
    verification_value, ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase,
    RunObservation,
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
    let Some(mail) = obs.mail.as_ref() else {
        return LocalJudgeResult::from_checks(vec![
            LocalCheck::new(
                "mail_observation_present",
                false,
                "missing typed mail observation",
            ),
            LocalCheck::new(
                "completion_evidence_present",
                false,
                format!("status={} failed={}", obs.final_status, obs.failed),
            ),
        ]);
    };

    let mail_reply_success_count = mail.reply_success_count;
    let mail_reply_failure_count = mail.reply_failure_count;
    let latest_payload = mail.reply_payloads.last();
    let payload_debug = latest_payload
        .and_then(|payload| serde_json::to_string(payload).ok())
        .unwrap_or_else(|| "null".to_string());

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

    let recipient_binding_present = latest_payload
        .and_then(|payload| payload.to.as_deref())
        .map(|value| value.eq_ignore_ascii_case(EXPECTED_RECIPIENT))
        .unwrap_or(false);
    let sent_message_id_present = latest_payload
        .and_then(|payload| payload.sent_message_id.as_deref())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let mailbox_output_present = latest_payload
        .and_then(|payload| payload.mailbox.as_deref())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let mailto_citation_present = latest_payload
        .and_then(|payload| payload.citation.as_deref())
        .and_then(uri_scheme)
        .map(|scheme| scheme == "mailto")
        .unwrap_or(false);
    let payload_synthesis_receipt_present =
        has_cec_receipt(obs, "provider_selection", "payload_synthesis", Some(true));
    let objective_specific_mail_send_evidence_present = mail_reply_success_count > 0
        && mail_reply_failure_count == 0
        && recipient_binding_present
        && sent_message_id_present
        && mailbox_output_present
        && mailto_citation_present
        && payload_synthesis_receipt_present;

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

    let no_mailbox_fallback_markers = !mail.fallback_marker_present;
    let any_contract_failure_marker = has_contract_failure_evidence(obs);
    let completion_evidence_present = obs.completed
        && !obs.failed
        && (objective_specific_mail_send_evidence_present || obs.chat_reply_count > 0);

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
        no_mailbox_fallback_markers,
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
                "mail_reply_success_count={} mail_reply_failure_count={} recipient_binding_present={} sent_message_id_present={} mailbox_output_present={} mailto_citation_present={} payload_synthesis_receipt_present={} payload={}",
                mail_reply_success_count,
                mail_reply_failure_count,
                recipient_binding_present,
                sent_message_id_present,
                mailbox_output_present,
                mailto_citation_present,
                payload_synthesis_receipt_present,
                payload_debug
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
                    "fallback_marker_present={} connector_path_required={} non_connector_tool_blocked={} invalid_tool_call_fail_fast={} system_fail_degraded_to_reply={}",
                    mail.fallback_marker_present,
                    mail.connector_path_required,
                    mail.non_connector_tool_blocked,
                    mail.invalid_tool_call_fail_fast,
                    mail.system_fail_degraded_to_reply
                ),
                280,
            ),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            !any_contract_failure_marker && mail_reply_failure_count == 0,
            truncate_chars(
                &format!(
                    "mail_reply_failure_count={} contract_failure_evidence_present={} payload={}",
                    mail_reply_failure_count,
                    has_contract_failure_evidence(obs),
                    payload_debug
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
                "independent_channel_count={} objective_specific_mail_send_evidence_present={} no_mailbox_fallback_markers={}",
                independent_channel_count,
                objective_specific_mail_send_evidence_present,
                no_mailbox_fallback_markers
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
