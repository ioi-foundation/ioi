use super::*;
use crate::models::{
    AgentPhase, AssistantNotificationClass, AssistantNotificationStatus, ChatMessage, EventStatus,
    InterventionStatus, InterventionType, NotificationSeverity,
};

#[test]
fn latest_agent_answer_prefers_last_agent_message() {
    let history = vec![
        ChatMessage {
            role: "user".to_string(),
            text: "question".to_string(),
            timestamp: 1,
        },
        ChatMessage {
            role: "agent".to_string(),
            text: "answer 1".to_string(),
            timestamp: 2,
        },
        ChatMessage {
            role: "agent".to_string(),
            text: "answer 2".to_string(),
            timestamp: 3,
        },
    ];

    assert_eq!(latest_agent_answer(&history).as_deref(), Some("answer 2"));
}

#[test]
fn latest_chat_reply_output_extracts_output_field() {
    let events = vec![AgentEvent {
        event_id: "evt-1".to_string(),
        timestamp: "2026-02-19T00:00:00Z".to_string(),
        thread_id: "thread-a".to_string(),
        step_index: 1,
        event_type: EventType::CommandRun,
        title: "Ran chat".to_string(),
        digest: json!({ "tool_name": "chat__reply" }),
        details: json!({ "output": "final answer" }),
        artifact_refs: Vec::new(),
        receipt_ref: None,
        input_refs: Vec::new(),
        status: EventStatus::Success,
        duration_ms: None,
    }];

    assert_eq!(
        latest_chat_reply_output(&events).as_deref(),
        Some("final answer")
    );
}

#[test]
fn artifact_extension_falls_back_to_binary_when_not_utf8() {
    assert_eq!(
        artifact_file_extension(&ArtifactType::Log, &[0xff, 0xfe]),
        "bin"
    );
}

#[test]
fn scoped_interventions_include_thread_and_session_matches() {
    let mut thread_match = InterventionRecord::default();
    thread_match.item_id = "thread".to_string();
    thread_match.thread_id = Some("thread-1".to_string());

    let mut session_match = InterventionRecord::default();
    session_match.item_id = "session".to_string();
    session_match.session_id = Some("session-1".to_string());

    let mut other = InterventionRecord::default();
    other.item_id = "other".to_string();
    other.thread_id = Some("thread-2".to_string());

    let scoped = scoped_interventions_for_trace_bundle(
        &[thread_match, session_match, other],
        "thread-1",
        "session-1",
    );
    let ids = scoped
        .into_iter()
        .map(|item| item.item_id)
        .collect::<Vec<_>>();

    assert_eq!(ids, vec!["thread".to_string(), "session".to_string()]);
}

#[test]
fn workbench_activity_scope_prefers_evidence_thread() {
    let activity = AssistantWorkbenchActivityRecord {
        activity_id: "activity-1".to_string(),
        session_kind: "gmail_reply".to_string(),
        surface: "gate".to_string(),
        action: "send".to_string(),
        status: "succeeded".to_string(),
        message: "Sent reply".to_string(),
        timestamp_ms: 1,
        source_notification_id: None,
        connector_id: None,
        thread_id: Some("gmail-thread".to_string()),
        event_id: None,
        evidence_thread_id: Some("trace-thread".to_string()),
        detail: None,
    };

    assert!(workbench_activity_belongs_to_trace_scope(
        &activity,
        "trace-thread",
        "session-1",
    ));
    assert!(!workbench_activity_belongs_to_trace_scope(
        &activity,
        "other-thread",
        "session-1",
    ));
}

#[test]
fn compare_trace_bundles_surfaces_first_divergence() {
    let timestamp = "2026-04-04T12:00:00Z".to_string();
    let left_receipt = AgentEvent {
        event_id: "evt-left-2".to_string(),
        timestamp: timestamp.clone(),
        thread_id: "left-session".to_string(),
        step_index: 1,
        event_type: EventType::Receipt,
        title: "Delegated".to_string(),
        digest: json!({ "tool_name": "agent__delegate" }),
        details: json!({}),
        artifact_refs: Vec::new(),
        receipt_ref: None,
        input_refs: Vec::new(),
        status: EventStatus::Success,
        duration_ms: None,
    };
    let right_receipt = AgentEvent {
        event_id: "evt-right-2".to_string(),
        timestamp: timestamp.clone(),
        thread_id: "right-session".to_string(),
        step_index: 1,
        event_type: EventType::Receipt,
        title: "Awaited".to_string(),
        digest: json!({ "tool_name": "agent__await" }),
        details: json!({}),
        artifact_refs: Vec::new(),
        receipt_ref: None,
        input_refs: Vec::new(),
        status: EventStatus::Success,
        duration_ms: None,
    };

    let left = CanonicalTraceBundle {
        schema_version: CANONICAL_TRACE_BUNDLE_SCHEMA_VERSION,
        exported_at_utc: timestamp.clone(),
        thread_id: "left-session".to_string(),
        session_id: "left-session".to_string(),
        latest_answer_markdown: "Left answer".to_string(),
        stats: TraceBundleStats {
            event_count: 2,
            receipt_count: 1,
            artifact_count: 1,
            run_bundle_count: 0,
            report_artifact_count: 1,
            intervention_count: 1,
            assistant_notification_count: 0,
            assistant_workbench_activity_count: 0,
            included_artifact_payloads: false,
            included_artifact_payload_count: 0,
        },
        session_summary: Some(SessionSummary {
            session_id: "left-session".to_string(),
            title: "Left session".to_string(),
            timestamp: 1,
            phase: Some(AgentPhase::Running),
            current_step: Some("Planning".to_string()),
            resume_hint: Some("Resume left".to_string()),
            workspace_root: Some("/tmp/left".to_string()),
        }),
        task: None,
        history: Vec::new(),
        events: vec![
            AgentEvent {
                event_id: "evt-left-1".to_string(),
                timestamp: timestamp.clone(),
                thread_id: "left-session".to_string(),
                step_index: 0,
                event_type: EventType::InfoNote,
                title: "Started".to_string(),
                digest: json!({}),
                details: json!({}),
                artifact_refs: Vec::new(),
                receipt_ref: None,
                input_refs: Vec::new(),
                status: EventStatus::Success,
                duration_ms: None,
            },
            left_receipt.clone(),
        ],
        receipts: vec![left_receipt],
        artifacts: vec![Artifact {
            artifact_id: "artifact-left".to_string(),
            created_at: timestamp.clone(),
            thread_id: "left-session".to_string(),
            artifact_type: ArtifactType::Report,
            title: "Left report".to_string(),
            description: "Left report".to_string(),
            content_ref: "ioi-memory://artifact/artifact-left".to_string(),
            metadata: json!({}),
            version: Some(1),
            parent_artifact_id: None,
        }],
        artifact_payloads: Vec::new(),
        interventions: vec![InterventionRecord {
            item_id: "gate-left".to_string(),
            rail: Default::default(),
            intervention_type: InterventionType::ApprovalGate,
            status: InterventionStatus::Pending,
            severity: NotificationSeverity::High,
            blocking: true,
            title: "Gate".to_string(),
            summary: "Needs approval".to_string(),
            reason: None,
            recommended_action: None,
            consequence_if_ignored: None,
            created_at_ms: 1,
            updated_at_ms: 1,
            due_at_ms: None,
            expires_at_ms: None,
            snoozed_until_ms: None,
            dedupe_key: String::new(),
            thread_id: Some("left-session".to_string()),
            session_id: Some("left-session".to_string()),
            workflow_id: None,
            run_id: None,
            delivery_state: Default::default(),
            privacy: Default::default(),
            source: Default::default(),
            artifact_refs: Vec::new(),
            source_event_ids: Vec::new(),
            policy_refs: Default::default(),
            actions: Vec::new(),
            target: None,
            request_hash: None,
            policy_hash: None,
            approval_scope: None,
            sensitive_action_type: None,
            error_class: None,
            blocked_stage: None,
            retry_available: None,
            recovery_hint: None,
        }],
        assistant_notifications: Vec::new(),
        assistant_workbench_activities: Vec::new(),
    };
    let right = CanonicalTraceBundle {
        schema_version: CANONICAL_TRACE_BUNDLE_SCHEMA_VERSION,
        exported_at_utc: timestamp.clone(),
        thread_id: "right-session".to_string(),
        session_id: "right-session".to_string(),
        latest_answer_markdown: "Right answer".to_string(),
        stats: TraceBundleStats {
            event_count: 2,
            receipt_count: 1,
            artifact_count: 2,
            run_bundle_count: 0,
            report_artifact_count: 1,
            intervention_count: 0,
            assistant_notification_count: 1,
            assistant_workbench_activity_count: 0,
            included_artifact_payloads: false,
            included_artifact_payload_count: 0,
        },
        session_summary: Some(SessionSummary {
            session_id: "right-session".to_string(),
            title: "Right session".to_string(),
            timestamp: 2,
            phase: Some(AgentPhase::Complete),
            current_step: Some("Completed".to_string()),
            resume_hint: Some("Review output".to_string()),
            workspace_root: Some("/tmp/right".to_string()),
        }),
        task: None,
        history: Vec::new(),
        events: vec![
            AgentEvent {
                event_id: "evt-right-1".to_string(),
                timestamp: timestamp.clone(),
                thread_id: "right-session".to_string(),
                step_index: 0,
                event_type: EventType::InfoNote,
                title: "Started".to_string(),
                digest: json!({}),
                details: json!({}),
                artifact_refs: Vec::new(),
                receipt_ref: None,
                input_refs: Vec::new(),
                status: EventStatus::Success,
                duration_ms: None,
            },
            right_receipt.clone(),
        ],
        receipts: vec![right_receipt],
        artifacts: vec![
            Artifact {
                artifact_id: "artifact-right-1".to_string(),
                created_at: timestamp.clone(),
                thread_id: "right-session".to_string(),
                artifact_type: ArtifactType::Report,
                title: "Right report".to_string(),
                description: "Right report".to_string(),
                content_ref: "ioi-memory://artifact/artifact-right-1".to_string(),
                metadata: json!({}),
                version: Some(1),
                parent_artifact_id: None,
            },
            Artifact {
                artifact_id: "artifact-right-2".to_string(),
                created_at: timestamp.clone(),
                thread_id: "right-session".to_string(),
                artifact_type: ArtifactType::File,
                title: "Right file".to_string(),
                description: "Right file".to_string(),
                content_ref: "ioi-memory://artifact/artifact-right-2".to_string(),
                metadata: json!({}),
                version: Some(1),
                parent_artifact_id: None,
            },
        ],
        artifact_payloads: Vec::new(),
        interventions: Vec::new(),
        assistant_notifications: vec![AssistantNotificationRecord {
            item_id: "notif-right".to_string(),
            rail: Default::default(),
            notification_class: AssistantNotificationClass::ValuableCompletion,
            status: AssistantNotificationStatus::Acknowledged,
            severity: NotificationSeverity::Low,
            title: "Done".to_string(),
            summary: "Completed".to_string(),
            reason: None,
            recommended_action: None,
            consequence_if_ignored: None,
            created_at_ms: 1,
            updated_at_ms: 1,
            due_at_ms: None,
            expires_at_ms: None,
            snoozed_until_ms: None,
            dedupe_key: String::new(),
            thread_id: Some("right-session".to_string()),
            session_id: Some("right-session".to_string()),
            workflow_id: None,
            run_id: None,
            delivery_state: Default::default(),
            privacy: Default::default(),
            source: Default::default(),
            artifact_refs: Vec::new(),
            source_event_ids: Vec::new(),
            policy_refs: Default::default(),
            actions: Vec::new(),
            target: None,
            priority_score: 0.0,
            confidence_score: 0.0,
            ranking_reason: Vec::new(),
        }],
        assistant_workbench_activities: Vec::new(),
    };

    let diff = compare_canonical_trace_bundles(&left, &right);

    assert_eq!(diff.changed_section_count, 5);
    assert_eq!(diff.first_divergence_key.as_deref(), Some("session"));
    assert_eq!(diff.sections.len(), 5);
    assert!(diff
        .sections
        .iter()
        .find(|section| section.key == "workers")
        .is_some_and(|section| section.changed));
    assert!(diff
        .sections
        .iter()
        .find(|section| section.key == "artifacts")
        .is_some_and(|section| section.changed));
}
