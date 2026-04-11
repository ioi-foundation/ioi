use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    has_contract_failure_evidence, has_tool_with_token, truncate_chars, ExecutionProfile,
    LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str = "create_a_google_calendar_event_for_tomorrows_standup_at_2_pm";

pub fn case() -> QueryCase {
    QueryCase {
        id: CASE_ID,
        query: "Create a Google Calendar event for tomorrow's standup at 2 PM.",
        success_definition: "Create the requested Google Calendar event through the Google connector with structured calendar event evidence, tool-path receipts, and no contract-failure markers.",
        seeded_intent_id: "calendar.create_event",
        intent_scope: IntentScopeProfile::WorkspaceOps,
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

    let latest_payload = google.calendar_create_payloads.last();
    let payload_debug = latest_payload
        .and_then(|payload| serde_json::to_string(payload).ok())
        .unwrap_or_else(|| "null".to_string());
    let calendar_create_succeeded =
        google.calendar_create_success_count > 0 && google.calendar_create_failure_count == 0;
    let event_id_present = latest_payload
        .and_then(|payload| payload.event_id.as_deref())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let calendar_id_present = latest_payload
        .and_then(|payload| payload.calendar_id.as_deref())
        .map(|value| value.eq_ignore_ascii_case("primary"))
        .unwrap_or(false);
    let summary_present = latest_payload
        .and_then(|payload| payload.summary.as_deref())
        .map(|value| value.to_ascii_lowercase().contains("standup"))
        .unwrap_or(false);
    let start_present = latest_payload
        .and_then(|payload| payload.start.as_deref())
        .map(|value| value.contains("T14:00:00"))
        .unwrap_or(false);
    let end_present = latest_payload
        .and_then(|payload| payload.end.as_deref())
        .map(|value| value.contains("T14:30:00"))
        .unwrap_or(false);
    let html_link_present = latest_payload
        .and_then(|payload| payload.html_link.as_deref())
        .map(|value| value.starts_with("https://calendar.google.com/"))
        .unwrap_or(false);
    let tool_planned_seen = obs.planned_tool_calls.iter().any(|call| {
        call.tool_name
            .eq_ignore_ascii_case("connector__google__calendar_create_event")
    });
    let tool_route_seen = has_tool_with_token(
        &obs.routing_tools,
        "connector__google__calendar_create_event",
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
            "calendar_create_payload_present",
            calendar_create_succeeded
                && event_id_present
                && calendar_id_present
                && summary_present
                && start_present
                && end_present
                && html_link_present,
            format!(
                "calendar_create_success_count={} calendar_create_failure_count={} event_id_present={} calendar_id_present={} summary_present={} start_present={} end_present={} html_link_present={} payload={}",
                google.calendar_create_success_count,
                google.calendar_create_failure_count,
                event_id_present,
                calendar_id_present,
                summary_present,
                start_present,
                end_present,
                html_link_present,
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
