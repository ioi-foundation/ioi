use super::{
    ActionContext, ActionHashError, ActionRequest, ActionTarget, CommittedAction,
    CommittedActionError,
};

fn base_request(window_id: Option<u64>) -> ActionRequest {
    ActionRequest {
        target: ActionTarget::GuiClick,
        params: serde_jcs::to_vec(&serde_json::json!({
            "x": 10,
            "y": 20,
            "button": "left",
        }))
        .expect("params should canonicalize"),
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some([7u8; 32]),
            window_id,
        },
        nonce: 1,
    }
}

#[test]
fn action_request_hash_changes_when_window_binding_changes() {
    let a = base_request(Some(111));
    let b = base_request(Some(222));

    assert_ne!(a.try_hash().expect("hash"), b.try_hash().expect("hash"));
}

#[test]
fn action_request_try_hash_rejects_non_json_params() {
    let mut req = base_request(Some(5));
    req.params = vec![0xFF, 0xFE];

    let err = req.try_hash().expect_err("invalid json params should fail");
    assert!(matches!(err, ActionHashError::InvalidParamsJson(_)));
}

#[test]
fn committed_action_verify_rejects_policy_hash_mismatch() {
    let req = base_request(Some(1));
    let committed = CommittedAction::commit(&req, [1u8; 32], None).expect("commit");

    let err = committed
        .verify(&req, [2u8; 32], None)
        .expect_err("policy mismatch should fail");
    assert!(matches!(err, CommittedActionError::PolicyHashMismatch));
}
