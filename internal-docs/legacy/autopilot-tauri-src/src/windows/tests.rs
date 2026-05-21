use super::summarize_chat_launch_request;
use serde_json::json;

#[test]
fn summarizes_session_target_launch_requests() {
    let summary = summarize_chat_launch_request(&json!({
        "kind": "session-target",
        "sessionId": "session-123",
    }));

    assert_eq!(
        summary,
        json!({
            "kind": "session-target",
            "sessionId": "session-123",
        })
    );
}
