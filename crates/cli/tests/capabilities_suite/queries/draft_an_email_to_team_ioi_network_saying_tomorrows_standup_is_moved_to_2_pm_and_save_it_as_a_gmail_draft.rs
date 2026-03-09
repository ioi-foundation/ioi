use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    has_contract_failure_evidence, has_tool_with_token, has_verification_pair, truncate_chars,
    verification_u64, ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str =
    "draft_an_email_to_team_ioi_network_saying_tomorrows_standup_is_moved_to_2_pm_and_save_it_as_a_gmail_draft";
const EXPECTED_RECIPIENT: &str = "team@ioi.network";
const EXPECTED_FIXTURE_MODE: &str = "google_connector_mock_fixture_v1";
const EXPECTED_ACCOUNT: &str = "fixtures.google@ioi.invalid";

pub fn case() -> QueryCase {
    QueryCase {
        id: CASE_ID,
        query: "Draft an email to team@ioi.network saying tomorrow's standup is moved to 2 PM and save it as a Gmail draft.",
        success_definition: "Create the requested Gmail draft through the hermetic Google connector fixture with structured Gmail draft evidence, fixture receipts, and no contract-failure markers.",
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
    let recipient_binding_present = latest_payload
        .and_then(|payload| payload.to.as_deref())
        .map(|value| value.eq_ignore_ascii_case(EXPECTED_RECIPIENT))
        .unwrap_or(false);
    let subject_present = latest_payload
        .and_then(|payload| payload.subject.as_deref())
        .map(|value| {
            value.to_ascii_lowercase().contains("standup")
                && value.to_ascii_lowercase().contains("2 pm")
        })
        .unwrap_or(false);
    let body_present = latest_payload
        .and_then(|payload| payload.body_text.as_deref())
        .map(|value| value.to_ascii_lowercase().contains("moved to 2 pm"))
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
    let fixture_mode_present = has_verification_pair(
        obs,
        "env_receipt::google_connector_fixture_mode",
        EXPECTED_FIXTURE_MODE,
    );
    let fixture_account_present = has_verification_pair(
        obs,
        "env_receipt::google_connector_fixture_account",
        EXPECTED_ACCOUNT,
    );
    let message_count =
        verification_u64(obs, "env_receipt::google_connector_fixture_message_count")
            .unwrap_or_default();
    let fixture_cleanup_satisfied = has_verification_pair(
        obs,
        "env_receipt::google_connector_fixture_cleanup_satisfied",
        "true",
    );
    let completion_evidence_present = obs.completed && !obs.failed;
    let no_contract_failure_markers = !has_contract_failure_evidence(obs);

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!("status={} completed={} failed={}", obs.final_status, obs.completed, obs.failed),
        ),
        LocalCheck::new(
            "gmail_draft_payload_present",
            draft_succeeded
                && recipient_binding_present
                && subject_present
                && body_present
                && message_id_present
                && draft_label_present,
            format!(
                "draft_success_count={} draft_failure_count={} recipient_binding_present={} subject_present={} body_present={} message_id_present={} draft_label_present={} payload={}",
                google.gmail_draft_success_count,
                google.gmail_draft_failure_count,
                recipient_binding_present,
                subject_present,
                body_present,
                message_id_present,
                draft_label_present,
                truncate_chars(&payload_debug, 260)
            ),
        ),
        LocalCheck::new(
            "tool_path_evidence_present",
            tool_planned_seen && tool_route_seen,
            format!(
                "tool_planned_seen={} tool_route_seen={} planned_tool_calls={:?} routing_tools={:?}",
                tool_planned_seen, tool_route_seen, obs.planned_tool_calls, obs.routing_tools
            ),
        ),
        LocalCheck::new(
            "fixture_receipts_present",
            fixture_mode_present
                && fixture_account_present
                && message_count > 0
                && fixture_cleanup_satisfied,
            format!(
                "fixture_mode_present={} fixture_account_present={} message_count={} fixture_cleanup_satisfied={}",
                fixture_mode_present, fixture_account_present, message_count, fixture_cleanup_satisfied
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
    ];

    LocalJudgeResult::from_checks(checks)
}
