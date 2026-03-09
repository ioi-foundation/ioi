use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    has_contract_failure_evidence, has_tool_with_token, has_verification_pair, truncate_chars,
    uri_scheme, verification_value, ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase,
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

    let mail_read_success_count = mail.read_latest_success_count;
    let mail_read_failure_count = mail.read_latest_failure_count;
    let latest_payload = mail.read_latest_payloads.last();
    let payload_debug = latest_payload
        .and_then(|payload| serde_json::to_string(payload).ok())
        .unwrap_or_else(|| "null".to_string());

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

    let structured_mail_payload_present = latest_payload
        .map(|payload| {
            payload
                .message_id
                .as_deref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false)
                && payload
                    .from
                    .as_deref()
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false)
                && payload
                    .subject
                    .as_deref()
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false)
                && payload
                    .preview
                    .as_deref()
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    let imap_citation_present = latest_payload
        .and_then(|payload| payload.citation.as_deref())
        .and_then(uri_scheme)
        .map(|scheme| scheme == "imap")
        .unwrap_or(false);
    let received_timestamp_present = latest_payload
        .map(|payload| {
            payload.received_at_ms.is_some()
                || payload
                    .received_at_utc
                    .as_deref()
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    let mailbox_output_present = latest_payload
        .and_then(|payload| payload.mailbox.as_deref())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let objective_specific_mail_read_evidence_present = mail_read_success_count > 0
        && mail_read_failure_count == 0
        && structured_mail_payload_present
        && imap_citation_present
        && received_timestamp_present
        && mailbox_output_present;

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
    let setup_receipt_timestamp_present =
        verification_value(obs, "env_receipt::mail_setup_timestamp_ms").is_some();
    let setup_mailbox = verification_value(obs, "env_receipt::mail_mailbox")
        .map(|value| value.to_ascii_lowercase());
    let payload_mailbox = latest_payload
        .and_then(|payload| payload.mailbox.as_ref())
        .map(|value| value.to_ascii_lowercase());
    let setup_mailbox_binding_present = setup_mailbox
        .as_deref()
        .zip(payload_mailbox.as_deref())
        .map(|(expected, observed)| expected.eq_ignore_ascii_case(observed))
        .unwrap_or(false);

    let connector_environment_setup_receipts_present = setup_root_configured
        && setup_client_registered
        && setup_connector_bootstrap
        && setup_binding_ready
        && setup_receipt_timestamp_present;

    let no_mailbox_fallback_markers = !mail.fallback_marker_present;
    let any_contract_failure_marker = has_contract_failure_evidence(obs);
    let completion_evidence_present = obs.completed
        && !obs.failed
        && (objective_specific_mail_read_evidence_present || obs.chat_reply_count > 0);

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
        no_mailbox_fallback_markers,
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
                "mail_read_success_count={} mail_read_failure_count={} structured_mail_payload_present={} imap_citation_present={} received_timestamp_present={} mailbox_output_present={}",
                mail_read_success_count,
                mail_read_failure_count,
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
                "setup_mailbox={:?} payload_mailbox={:?}",
                setup_mailbox,
                payload_mailbox
            ),
        ),
        LocalCheck::new(
            "source_and_quality_evidence_present",
            imap_citation_present && structured_mail_payload_present,
            truncate_chars(&payload_debug, 220),
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
                260,
            ),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            !any_contract_failure_marker && mail_read_failure_count == 0,
            truncate_chars(
                &format!(
                    "mail_read_failure_count={} contract_failure_evidence_present={} payload={}",
                    mail_read_failure_count,
                    has_contract_failure_evidence(obs),
                    payload_debug
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
                "independent_channel_count={} objective_specific_mail_read_evidence_present={} no_mailbox_fallback_markers={}",
                independent_channel_count,
                objective_specific_mail_read_evidence_present,
                no_mailbox_fallback_markers
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
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
            key: "mail_wallet_control_plane_configured",
            observed_value: format!(
                "root_configured={} client_registered={}",
                has_verification_pair(
                    obs,
                    "env_receipt::mail_wallet_control_root_configured",
                    "true"
                ),
                has_verification_pair(
                    obs,
                    "env_receipt::mail_wallet_capability_client_registered",
                    "true"
                )
            ),
            probe_source: "RunObservation.verification_facts",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: has_verification_pair(
                obs,
                "env_receipt::mail_wallet_control_root_configured",
                "true"
            ) && has_verification_pair(
                obs,
                "env_receipt::mail_wallet_capability_client_registered",
                "true"
            ),
        },
        EnvironmentEvidenceReceipt {
            key: "mail_connector_runtime_configured",
            observed_value: format!(
                "connector_setup_receipts_present={}",
                connector_environment_setup_receipts_present
            ),
            probe_source: "RunObservation.verification_facts",
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
