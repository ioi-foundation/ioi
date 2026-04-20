use super::*;
use serde_json::json;

#[test]
fn serializes_agent_event_shape() {
    let event = AgentEvent {
        event_id: "evt-1".to_string(),
        timestamp: "2026-02-13T00:00:00Z".to_string(),
        thread_id: "thread-1".to_string(),
        step_index: 7,
        event_type: EventType::CommandRun,
        title: "Ran cargo test".to_string(),
        digest: json!({"tool":"cargo test"}),
        details: json!({"output":"ok"}),
        artifact_refs: vec![ArtifactRef {
            artifact_id: "art-1".to_string(),
            artifact_type: ArtifactType::Log,
        }],
        receipt_ref: Some("receipt-1".to_string()),
        input_refs: vec!["evt-0".to_string()],
        status: EventStatus::Success,
        duration_ms: Some(12),
    };

    let value = serde_json::to_value(&event).expect("serialize event");
    assert_eq!(value["event_id"], "evt-1");
    assert_eq!(value["event_type"], "COMMAND_RUN");
    assert_eq!(value["status"], "SUCCESS");
    assert_eq!(value["artifact_refs"][0]["artifact_type"], "LOG");
}

#[test]
fn serializes_artifact_shape() {
    let artifact = Artifact {
        artifact_id: "art-1".to_string(),
        created_at: "2026-02-13T00:00:00Z".to_string(),
        thread_id: "thread-1".to_string(),
        artifact_type: ArtifactType::Diff,
        title: "Large diff".to_string(),
        description: "Diff exceeded threshold".to_string(),
        content_ref: "ioi-memory://artifact/art-1".to_string(),
        metadata: json!({"files_touched": 4}),
        version: Some(1),
        parent_artifact_id: None,
    };
    let value = serde_json::to_value(&artifact).expect("serialize artifact");
    assert_eq!(value["artifact_type"], "DIFF");
    assert_eq!(value["metadata"]["files_touched"], 4);
}
