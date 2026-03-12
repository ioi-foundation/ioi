use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    has_cec_receipt, has_cec_stage, has_contract_failure_evidence, has_tool_with_token,
    has_verification_pair, truncate_chars, uri_scheme, verification_bool, verification_u64,
    verification_value, ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str =
    "draft_an_email_to_team_ioi_network_saying_tomorrows_standup_is_moved_to_2_pm_and_send_it";
const EXPECTED_RECIPIENT: &str = "team@ioi.network";
const EXPECTED_MAIL_FIXTURE_MODE: &str = "mail_reply_mock_driver_fixture_v1";
const EXPECTED_GOOGLE_FIXTURE_MODE: &str = "google_connector_mock_fixture_v1";
const EXPECTED_GOOGLE_ACCOUNT: &str = "fixtures.google@ioi.invalid";

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
        success_definition: "Draft and send the requested standup-update email through the generic mail.reply intent using mailbox connector runtime receipts, provider-specific send receipts, and no fallback degradation.",
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
    let mail = obs.mail.as_ref();
    let google = obs.google.as_ref();
    if mail.is_none() && google.is_none() {
        return LocalJudgeResult::from_checks(vec![
            LocalCheck::new(
                "mail_or_google_observation_present",
                false,
                "missing typed mail and google observations",
            ),
            LocalCheck::new(
                "completion_evidence_present",
                false,
                format!("status={} failed={}", obs.final_status, obs.failed),
            ),
        ]);
    }

    let mail_reply_success_count = mail.map(|value| value.reply_success_count).unwrap_or(0);
    let mail_reply_failure_count = mail.map(|value| value.reply_failure_count).unwrap_or(0);
    let latest_mail_payload = mail.and_then(|value| value.reply_payloads.last());
    let mail_payload_debug = latest_mail_payload
        .and_then(|payload| serde_json::to_string(payload).ok())
        .unwrap_or_else(|| "null".to_string());

    let google_send_success_count = google
        .map(|value| value.gmail_send_success_count)
        .unwrap_or(0);
    let google_send_failure_count = google
        .map(|value| value.gmail_send_failure_count)
        .unwrap_or(0);
    let latest_google_payload = google.and_then(|value| value.gmail_send_payloads.last());
    let google_payload_debug = latest_google_payload
        .and_then(|payload| serde_json::to_string(payload).ok())
        .unwrap_or_else(|| "null".to_string());

    let mail_reply_tool_action_seen = has_tool_with_token(&obs.action_tools, "mail_reply");
    let mail_reply_tool_route_seen = has_tool_with_token(&obs.routing_tools, "mail_reply");
    let gmail_send_tool_action_seen =
        has_tool_with_token(&obs.action_tools, "connector__google__gmail_send_email");
    let gmail_send_tool_route_seen =
        has_tool_with_token(&obs.routing_tools, "connector__google__gmail_send_email");
    let system_fail_seen = has_tool_with_token(&obs.action_tools, "system__fail")
        || has_tool_with_token(&obs.routing_tools, "system__fail");
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

    let mail_recipient_binding_present = latest_mail_payload
        .and_then(|payload| payload.to.as_deref())
        .map(|value| value.eq_ignore_ascii_case(EXPECTED_RECIPIENT))
        .unwrap_or(false);
    let mail_sent_message_id_present = latest_mail_payload
        .and_then(|payload| payload.sent_message_id.as_deref())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let mail_mailbox_output_present = latest_mail_payload
        .and_then(|payload| payload.mailbox.as_deref())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let mailto_citation_present = latest_mail_payload
        .and_then(|payload| payload.citation.as_deref())
        .and_then(uri_scheme)
        .map(|scheme| scheme == "mailto")
        .unwrap_or(false);

    let google_recipient_binding_present = latest_google_payload
        .and_then(|payload| payload.to.as_deref())
        .map(|value| value.eq_ignore_ascii_case(EXPECTED_RECIPIENT))
        .unwrap_or(false);
    let google_subject_present = latest_google_payload
        .and_then(|payload| payload.subject.as_deref())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let google_body_present = latest_google_payload
        .and_then(|payload| payload.body_text.as_deref())
        .map(|value| {
            let normalized = value.to_ascii_lowercase();
            normalized.contains("standup")
                && normalized.contains("moved")
                && (normalized.contains("2 pm") || normalized.contains("2pm"))
        })
        .unwrap_or(false);
    let google_message_id_present = latest_google_payload
        .and_then(|payload| payload.message_id.as_deref())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let google_sent_label_present = latest_google_payload
        .map(|payload| {
            payload
                .label_ids
                .iter()
                .any(|label| label.eq_ignore_ascii_case("SENT"))
        })
        .unwrap_or(false);

    let verification_postcondition_present =
        has_cec_receipt(obs, "verification", "mail.reply.completed", Some(true));
    let mail_reply_provider_satisfied = mail_reply_success_count > 0
        && mail_reply_failure_count == 0
        && mail_recipient_binding_present
        && mail_sent_message_id_present
        && mail_mailbox_output_present
        && mailto_citation_present;
    let google_send_provider_satisfied = google_send_success_count > 0
        && google_send_failure_count == 0
        && verification_postcondition_present
        && google_subject_present
        && google_body_present
        && google_message_id_present
        && google_sent_label_present;
    let provider_surface = if google_send_provider_satisfied
        || gmail_send_tool_action_seen
        || gmail_send_tool_route_seen
    {
        "google_gmail_send"
    } else if mail_reply_provider_satisfied
        || mail_reply_tool_action_seen
        || mail_reply_tool_route_seen
    {
        "wallet_mail_reply"
    } else {
        "unknown"
    };
    let provider_execution_satisfied = match provider_surface {
        "google_gmail_send" => google_send_success_count > 0 && google_send_failure_count == 0,
        "wallet_mail_reply" => mail_reply_success_count > 0 && mail_reply_failure_count == 0,
        _ => false,
    };
    let provider_recipient_binding_present = match provider_surface {
        "google_gmail_send" => {
            verification_postcondition_present || google_recipient_binding_present
        }
        "wallet_mail_reply" => mail_recipient_binding_present,
        _ => false,
    };
    let provider_artifact_satisfied = match provider_surface {
        "google_gmail_send" => {
            google_message_id_present
                && google_subject_present
                && google_body_present
                && google_sent_label_present
                && verification_postcondition_present
        }
        "wallet_mail_reply" => {
            mail_sent_message_id_present && mail_mailbox_output_present && mailto_citation_present
        }
        _ => false,
    };
    let objective_specific_mail_send_evidence_present = verification_postcondition_present
        && (mail_reply_provider_satisfied || google_send_provider_satisfied);

    let setup_root_configured = has_verification_pair(
        obs,
        "env_receipt::mail_wallet_control_root_configured",
        "true",
    );
    let setup_client_registered = has_verification_pair(
        obs,
        "env_receipt::mail_wallet_capability_client_registered",
        "true",
    );
    let setup_connector_bootstrap =
        has_verification_pair(obs, "env_receipt::mail_connector_bootstrap", "true");
    let setup_binding_ready = has_verification_pair(obs, "env_receipt::mail_binding_ready", "true");
    let setup_send_capability_bound =
        has_verification_pair(obs, "env_receipt::mail_send_capability_bound", "true");
    let setup_provider_driver =
        verification_value(obs, "env_receipt::mail_provider_driver").unwrap_or_default();
    let setup_provider_driver_source =
        verification_value(obs, "env_receipt::mail_provider_driver_source").unwrap_or_default();
    let setup_provider_driver_satisfied = setup_provider_driver.eq_ignore_ascii_case("mock")
        && setup_provider_driver_source.eq_ignore_ascii_case("fixture_override");
    let setup_receipt_timestamp_present =
        verification_value(obs, "env_receipt::mail_setup_timestamp_ms").is_some();

    let mail_fixture_mode =
        verification_value(obs, "env_receipt::mail_reply_fixture_mode").unwrap_or_default();
    let mail_fixture_probe_source =
        verification_value(obs, "env_receipt::mail_reply_fixture_probe_source").unwrap_or_default();
    let mail_fixture_timestamp_ms =
        verification_u64(obs, "env_receipt::mail_reply_fixture_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let mail_fixture_satisfied =
        verification_bool(obs, "env_receipt::mail_reply_fixture_satisfied").unwrap_or(false);
    let mail_fixture_cleanup_satisfied =
        verification_bool(obs, "env_receipt::mail_reply_fixture_cleanup_satisfied")
            .unwrap_or(false);
    let mail_fixture_run_unique_satisfied =
        verification_bool(obs, "env_receipt::mail_reply_fixture_run_unique_satisfied")
            .unwrap_or(false);

    let google_fixture_mode =
        verification_value(obs, "env_receipt::google_connector_fixture_mode").unwrap_or_default();
    let google_fixture_account =
        verification_value(obs, "env_receipt::google_connector_fixture_account")
            .unwrap_or_default();
    let google_fixture_message_count =
        verification_u64(obs, "env_receipt::google_connector_fixture_message_count")
            .unwrap_or_default();
    let google_fixture_cleanup_satisfied = has_verification_pair(
        obs,
        "env_receipt::google_connector_fixture_cleanup_satisfied",
        "true",
    );
    let google_provider_selected = provider_surface == "google_gmail_send"
        || gmail_send_tool_action_seen
        || gmail_send_tool_route_seen
        || latest_google_payload.is_some();
    let connector_environment_setup_receipts_present = setup_root_configured
        && setup_client_registered
        && setup_connector_bootstrap
        && setup_binding_ready
        && setup_send_capability_bound
        && setup_provider_driver_satisfied
        && setup_receipt_timestamp_present;

    let cec_discovery_seen = has_cec_stage(obs, "discovery", Some(true));
    let cec_provider_selection_seen = has_cec_stage(obs, "provider_selection", Some(true));
    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_completion_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_phase_receipts_present = cec_discovery_seen
        && cec_provider_selection_seen
        && cec_execution_seen
        && cec_verification_seen
        && verification_postcondition_present
        && cec_completion_gate_seen;

    let mail_fallback_marker_present = mail
        .map(|value| value.fallback_marker_present)
        .unwrap_or(false);
    let mail_connector_path_required = mail
        .map(|value| value.connector_path_required)
        .unwrap_or(false);
    let mail_non_connector_tool_blocked = mail
        .map(|value| value.non_connector_tool_blocked)
        .unwrap_or(false);
    let mail_invalid_tool_call_fail_fast = mail
        .map(|value| value.invalid_tool_call_fail_fast)
        .unwrap_or(false);
    let mail_system_fail_degraded_to_reply = mail
        .map(|value| value.system_fail_degraded_to_reply)
        .unwrap_or(false);
    let no_mailbox_fallback_markers = !mail_fallback_marker_present
        && !mail_connector_path_required
        && !mail_non_connector_tool_blocked
        && !mail_invalid_tool_call_fail_fast
        && !mail_system_fail_degraded_to_reply
        && !has_verification_pair(obs, "mailbox_system_fail_degraded_to_reply", "true");
    let any_contract_failure_marker = has_contract_failure_evidence(obs);
    let completion_evidence_present = obs.completed
        && !obs.failed
        && objective_specific_mail_send_evidence_present
        && obs.chat_reply_count > 0;

    let environment_receipts = build_environment_receipts(
        obs,
        mail_fixture_mode.clone(),
        mail_fixture_probe_source.clone(),
        mail_fixture_timestamp_ms,
        mail_fixture_satisfied,
        mail_fixture_cleanup_satisfied,
        mail_fixture_run_unique_satisfied,
        connector_environment_setup_receipts_present,
        setup_provider_driver.clone(),
        setup_provider_driver_source.clone(),
        setup_send_capability_bound,
        provider_surface,
        google_provider_selected,
        google_fixture_mode.clone(),
        google_fixture_account.clone(),
        google_fixture_message_count,
        google_fixture_cleanup_satisfied,
        verification_postcondition_present,
        provider_execution_satisfied,
        provider_recipient_binding_present,
        provider_artifact_satisfied,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let tool_and_route_path_evidence_present = ((mail_reply_tool_action_seen
        && mail_reply_tool_route_seen)
        || (gmail_send_tool_route_seen
            && (gmail_send_tool_action_seen || google_send_success_count > 0)))
        && !web_or_browser_path_seen
        && !non_mail_mutating_path_seen
        && !disallowed_mail_tool_seen
        && !system_fail_seen;

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_mail_send_evidence_present,
        tool_and_route_path_evidence_present,
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
                "provider_surface={} verification_postcondition_present={} mail_reply_success_count={} mail_reply_failure_count={} mail_payload={} google_send_success_count={} google_send_failure_count={} google_payload={}",
                provider_surface,
                verification_postcondition_present,
                mail_reply_success_count,
                mail_reply_failure_count,
                truncate_chars(&mail_payload_debug, 220),
                google_send_success_count,
                google_send_failure_count,
                truncate_chars(&google_payload_debug, 220)
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!(
                "mail_reply_tool_action_seen={} mail_reply_tool_route_seen={} gmail_send_tool_action_seen={} gmail_send_tool_route_seen={} system_fail_seen={} web_or_browser_path_seen={} non_mail_mutating_path_seen={} disallowed_mail_tool_seen={} action_tools={:?} routing_tools={:?} workload_tools={:?}",
                mail_reply_tool_action_seen,
                mail_reply_tool_route_seen,
                gmail_send_tool_action_seen,
                gmail_send_tool_route_seen,
                system_fail_seen,
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
                    mail_fallback_marker_present,
                    mail_connector_path_required,
                    mail_non_connector_tool_blocked,
                    mail_invalid_tool_call_fail_fast,
                    mail_system_fail_degraded_to_reply
                ),
                280,
            ),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            !any_contract_failure_marker
                && mail_reply_failure_count == 0
                && google_send_failure_count == 0
                && !system_fail_seen,
            truncate_chars(
                &format!(
                    "mail_reply_failure_count={} google_send_failure_count={} system_fail_seen={} contract_failure_evidence_present={}",
                    mail_reply_failure_count,
                    google_send_failure_count,
                    system_fail_seen,
                    has_contract_failure_evidence(obs)
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
    mail_fixture_mode: String,
    mail_fixture_probe_source: String,
    mail_fixture_timestamp_ms: u64,
    mail_fixture_satisfied: bool,
    mail_fixture_cleanup_satisfied: bool,
    mail_fixture_run_unique_satisfied: bool,
    connector_environment_setup_receipts_present: bool,
    setup_provider_driver: String,
    setup_provider_driver_source: String,
    setup_send_capability_bound: bool,
    provider_surface: &'static str,
    google_provider_selected: bool,
    google_fixture_mode: String,
    google_fixture_account: String,
    google_fixture_message_count: u64,
    google_fixture_cleanup_satisfied: bool,
    verification_postcondition_present: bool,
    provider_execution_satisfied: bool,
    provider_recipient_binding_present: bool,
    provider_artifact_satisfied: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    let google_fixture_runtime_satisfied = google_fixture_mode
        .eq_ignore_ascii_case(EXPECTED_GOOGLE_FIXTURE_MODE)
        && google_fixture_account.eq_ignore_ascii_case(EXPECTED_GOOGLE_ACCOUNT)
        && google_fixture_message_count > 0
        && google_fixture_cleanup_satisfied;

    vec![
        EnvironmentEvidenceReceipt {
            key: "mail_reply_fixture_mode_observed",
            observed_value: format!(
                "mode={} fixture_satisfied={} fixture_cleanup_satisfied={} fixture_run_unique_satisfied={}",
                mail_fixture_mode,
                mail_fixture_satisfied,
                mail_fixture_cleanup_satisfied,
                mail_fixture_run_unique_satisfied
            ),
            probe_source: if mail_fixture_probe_source.trim().is_empty() {
                "RunObservation.verification_facts".to_string()
            } else {
                mail_fixture_probe_source
            },
            timestamp_ms: mail_fixture_timestamp_ms,
            satisfied: mail_fixture_mode.eq_ignore_ascii_case(EXPECTED_MAIL_FIXTURE_MODE)
                && mail_fixture_satisfied
                && mail_fixture_cleanup_satisfied
                && mail_fixture_run_unique_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "mail_connector_runtime_configured",
            observed_value: format!(
                "connector_setup_receipts_present={} provider_driver={} provider_driver_source={} setup_send_capability_bound={}",
                connector_environment_setup_receipts_present,
                setup_provider_driver,
                setup_provider_driver_source,
                setup_send_capability_bound
            ),
            probe_source: "RunObservation.verification_facts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: connector_environment_setup_receipts_present
                && setup_provider_driver.eq_ignore_ascii_case("mock")
                && setup_provider_driver_source.eq_ignore_ascii_case("fixture_override")
                && setup_send_capability_bound,
        },
        EnvironmentEvidenceReceipt {
            key: "mail_send_provider_surface_observed",
            observed_value: format!(
                "provider_surface={} google_provider_selected={} google_fixture_mode={} google_fixture_account={} google_fixture_message_count={} google_fixture_cleanup_satisfied={}",
                provider_surface,
                google_provider_selected,
                google_fixture_mode,
                google_fixture_account,
                google_fixture_message_count,
                google_fixture_cleanup_satisfied
            ),
            probe_source: "RunObservation.environment_receipts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: match provider_surface {
                "google_gmail_send" => google_fixture_runtime_satisfied,
                "wallet_mail_reply" => !google_provider_selected || google_fixture_runtime_satisfied,
                _ => false,
            },
        },
        EnvironmentEvidenceReceipt {
            key: "mail_send_execution_observed",
            observed_value: format!(
                "provider_surface={} provider_execution_satisfied={}",
                provider_surface, provider_execution_satisfied
            ),
            probe_source: "KernelEvent::AgentActionResult(mail_send_provider)".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: provider_execution_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "mail_send_recipient_binding_observed",
            observed_value: format!(
                "provider_surface={} recipient_binding_present={}",
                provider_surface, provider_recipient_binding_present
            ),
            probe_source: "mail_send provider payload.to".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: provider_recipient_binding_present,
        },
        EnvironmentEvidenceReceipt {
            key: "mail_send_artifact_observed",
            observed_value: format!(
                "provider_surface={} provider_artifact_satisfied={}",
                provider_surface, provider_artifact_satisfied
            ),
            probe_source: "mail_send provider payload".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: provider_artifact_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "mail_send_postcondition_observed",
            observed_value: format!(
                "provider_surface={} verification_postcondition_present={}",
                provider_surface, verification_postcondition_present
            ),
            probe_source: "ExecutionContractReceipt(verification::mail.reply.completed)".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: verification_postcondition_present,
        },
    ]
}

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}
