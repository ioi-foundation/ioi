use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    has_cec_receipt, has_cec_stage, has_contract_failure_evidence, has_tool_with_token,
    has_verification_pair, truncate_chars, verification_values, ExecutionProfile, LocalCheck,
    LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str =
    "draft_an_email_to_team_ioi_network_saying_tomorrows_standup_is_moved_to_2_pm_and_save_it_as_a_gmail_draft";

pub fn case() -> QueryCase {
    QueryCase {
        id: CASE_ID,
        query: "Draft an email to team@ioi.network saying tomorrow's standup is moved to 2 PM and save it as a Gmail draft.",
        success_definition: "Create the requested Gmail draft through the Google connector with structured Gmail draft evidence, CEC receipts, grounded recipient evidence, and no contract-failure markers.",
        seeded_intent_id: "gmail.draft_email",
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
    let Some(google) = obs.google.as_ref() else {
        return LocalJudgeResult::from_checks(vec![
            LocalCheck::new(
                "google_observation_present",
                false,
                "missing typed google observation",
            ),
            LocalCheck::new(
                "completion_evidence_present",
                false,
                format!("status={} failed={}", obs.final_status, obs.failed),
            ),
        ]);
    };

    let latest_payload = google.gmail_draft_payloads.last();
    let payload_debug = latest_payload
        .and_then(|payload| serde_json::to_string(payload).ok())
        .unwrap_or_else(|| "null".to_string());
    let draft_succeeded =
        google.gmail_draft_success_count > 0 && google.gmail_draft_failure_count == 0;
    let subject_present = latest_payload
        .and_then(|payload| payload.subject.as_deref())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let body_request_signal_present = latest_payload
        .and_then(|payload| payload.body_text.as_deref())
        .map(|value| {
            let normalized = value.to_ascii_lowercase();
            normalized.contains("tomorrow")
                && normalized.contains("standup")
                && normalized.contains("moved")
                && (normalized.contains("2 pm") || normalized.contains("2pm"))
        })
        .unwrap_or(false);
    let message_id_present = latest_payload
        .and_then(|payload| payload.message_id.as_deref())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let draft_label_present = latest_payload
        .map(|payload| {
            payload
                .label_ids
                .iter()
                .any(|label| label.eq_ignore_ascii_case("DRAFT"))
        })
        .unwrap_or(false);
    let tool_planned_seen = obs.planned_tool_calls.iter().any(|call| {
        call.tool_name
            .eq_ignore_ascii_case("connector__google__gmail_draft_email")
    });
    let tool_route_seen =
        has_tool_with_token(&obs.routing_tools, "connector__google__gmail_draft_email");
    let system_fail_seen = has_tool_with_token(&obs.action_tools, "agent__escalate")
        || has_tool_with_token(&obs.routing_tools, "agent__escalate");
    let web_or_browser_path_seen = has_tool_with_token(&obs.routing_tools, "web__")
        || has_tool_with_token(&obs.routing_tools, "browser__")
        || has_tool_with_token(&obs.action_tools, "web__")
        || has_tool_with_token(&obs.action_tools, "browser__")
        || has_tool_with_token(&obs.workload_tools, "web__")
        || has_tool_with_token(&obs.workload_tools, "browser__");
    let non_mail_mutating_path_seen = has_tool_with_token(&obs.action_tools, "shell__run")
        || has_tool_with_token(&obs.routing_tools, "shell__run")
        || has_tool_with_token(&obs.action_tools, "file__")
        || has_tool_with_token(&obs.routing_tools, "file__")
        || has_tool_with_token(&obs.action_tools, "http__fetch")
        || has_tool_with_token(&obs.routing_tools, "http__fetch");
    let grounding_receipt_present = has_verification_pair(obs, "receipt::grounding", "true");
    let recipient_grounding_present = verification_values(obs, "grounding_slot")
        .iter()
        .any(|value| value.eq_ignore_ascii_case("to::user_literal_attested"));
    let verification_postcondition_present =
        has_cec_receipt(obs, "verification", "mail.reply.completed", Some(true));
    let discovery_receipt_present = has_cec_stage(obs, "discovery", Some(true));
    let provider_selection_receipt_present =
        has_cec_receipt(obs, "provider_selection", "provider_selection", Some(true));
    let provider_selection_commit_present = has_cec_receipt(
        obs,
        "provider_selection",
        "provider_selection_commit",
        Some(true),
    );
    let execution_receipt_present = has_cec_stage(obs, "execution", Some(true));
    let verification_receipt_present = has_cec_stage(obs, "verification", Some(true));
    let completion_gate_present =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let completion_evidence_present = obs.completed && !obs.failed;
    let no_contract_failure_markers = !has_contract_failure_evidence(obs);
    let independent_channel_count = [
        draft_succeeded,
        verification_postcondition_present,
        message_id_present && draft_label_present,
        tool_planned_seen,
        tool_route_seen,
        grounding_receipt_present && recipient_grounding_present,
    ]
    .into_iter()
    .filter(|value| *value)
    .count();

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!("status={} completed={} failed={}", obs.final_status, obs.completed, obs.failed),
        ),
        LocalCheck::new(
            "objective_specific_gmail_draft_evidence_present",
            draft_succeeded
                && verification_postcondition_present
                && subject_present
                && body_request_signal_present
                && message_id_present
                && draft_label_present,
            format!(
                "draft_success_count={} draft_failure_count={} verification_postcondition_present={} subject_present={} body_request_signal_present={} message_id_present={} draft_label_present={} payload={}",
                google.gmail_draft_success_count,
                google.gmail_draft_failure_count,
                verification_postcondition_present,
                subject_present,
                body_request_signal_present,
                message_id_present,
                draft_label_present,
                truncate_chars(&payload_debug, 260)
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_planned_seen
                && tool_route_seen
                && !system_fail_seen
                && !web_or_browser_path_seen
                && !non_mail_mutating_path_seen,
            format!(
                "tool_planned_seen={} tool_route_seen={} system_fail_seen={} web_or_browser_path_seen={} non_mail_mutating_path_seen={} planned_tool_calls={:?} routing_tools={:?} action_tools={:?} workload_tools={:?}",
                tool_planned_seen,
                tool_route_seen,
                system_fail_seen,
                web_or_browser_path_seen,
                non_mail_mutating_path_seen,
                obs.planned_tool_calls,
                obs.routing_tools,
                obs.action_tools,
                obs.workload_tools
            ),
        ),
        LocalCheck::new(
            "cec_phase_receipts_present",
            discovery_receipt_present
                && provider_selection_receipt_present
                && provider_selection_commit_present
                && grounding_receipt_present
                && verification_postcondition_present
                && execution_receipt_present
                && verification_receipt_present
                && completion_gate_present,
            format!(
                "discovery={} provider_selection={} provider_selection_commit={} grounding={} execution={} verification={} postcondition={} contract_gate={} cec_receipts={:?}",
                discovery_receipt_present,
                provider_selection_receipt_present,
                provider_selection_commit_present,
                grounding_receipt_present,
                execution_receipt_present,
                verification_receipt_present,
                verification_postcondition_present,
                completion_gate_present,
                obs.cec_receipts
            ),
        ),
        LocalCheck::new(
            "recipient_grounding_evidence_present",
            grounding_receipt_present && recipient_grounding_present,
            format!(
                "grounding_receipt_present={} grounding_slots={:?}",
                grounding_receipt_present,
                verification_values(obs, "grounding_slot")
            ),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            no_contract_failure_markers,
            format!(
                "action_error_classes={:?} verification_checks={:?}",
                obs.action_error_classes, obs.verification_checks
            ),
        ),
        LocalCheck::new(
            "independent_runtime_evidence_channels_present",
            independent_channel_count >= 5,
            format!("independent_channel_count={}", independent_channel_count),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}
