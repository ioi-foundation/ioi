use super::*;
use ioi_types::app::ActionTarget;
use serde_json::json;
use tempfile::tempdir;

#[tokio::test]
async fn native_substrate_provider_persists_context_slice_artifacts() {
    let tempdir = tempdir().expect("tempdir");
    let runtime = Arc::new(
        MemoryRuntime::open_sqlite(&tempdir.path().join("gui-memory.db")).expect("memory runtime"),
    );
    let provider = NativeSubstrateProvider::new(Some(runtime.clone()));
    let session_id = [7u8; 32];
    let intent = ActionRequest {
        target: ActionTarget::GuiScreenshot,
        params: serde_json::to_vec(&json!({})).expect("json params"),
        context: ioi_types::app::ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: 1,
    };
    let xml = br#"<window id="root"><button id="confirm">Confirm</button></window>"#;

    let slice = provider
        .get_intent_constrained_slice(&intent, 0, xml)
        .await
        .expect("persisted slice");
    let artifact_id = context_slice_artifact_id(&slice.slice_id);
    let blobs = runtime
        .load_artifact_blob(&artifact_id)
        .expect("artifact blob lookup")
        .expect("artifact blob present");
    let artifact_records = runtime
        .load_artifact_jsons(session_id)
        .expect("artifact metadata lookup");

    assert_eq!(slice.chunks, vec![xml.to_vec()]);
    assert_eq!(slice.frame_id, 0);
    assert_eq!(blobs, xml);
    assert!(artifact_records.iter().any(|record| {
        record.artifact_id == artifact_id
            && record.payload_json.contains("\"kind\":\"context_slice\"")
    }));
}
