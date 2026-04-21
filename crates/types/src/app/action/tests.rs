use super::{
    ActionContext, ActionHashError, ActionRequest, ActionTarget, ApprovalAuthority, ApprovalGrant,
    CommittedAction, CommittedActionError, ExecutionObservationReceipt, PolicyDecisionRecord,
    PolicyVerdict, PostconditionProof, RequiredReceiptManifest, SettlementReceiptBundle,
};
use crate::app::{account_id_from_key_material, SignatureSuite};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};

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

#[test]
fn policy_decision_record_verifies_hash_binding() {
    let req = base_request(Some(3));
    let request_hash = req.try_hash().expect("hash");
    let record = PolicyDecisionRecord::build(
        request_hash,
        [9u8; 32],
        vec!["rule.allow.fs".to_string()],
        "require_approval".to_string(),
        None,
        false,
        PolicyVerdict::Allow,
    )
    .expect("policy decision");

    record.verify().expect("policy decision verifies");
}

#[test]
fn settlement_receipt_bundle_verifies_hash_binding() {
    let req = base_request(Some(4));
    let request_hash = req.try_hash().expect("hash");
    let bundle = SettlementReceiptBundle::build(
        request_hash,
        [2u8; 32],
        [3u8; 32],
        Some([4u8; 32]),
        vec![[5u8; 32]],
        vec![[6u8; 32]],
        None,
        None,
        "authorized".to_string(),
    )
    .expect("bundle");

    bundle.verify().expect("bundle verifies");
}

#[test]
fn execution_observation_receipt_verifies_hash_binding() {
    let req = base_request(Some(5));
    let request_hash = req.try_hash().expect("hash");
    let receipt = ExecutionObservationReceipt::build(
        request_hash,
        req.target.canonical_label(),
        "execution.outcome".to_string(),
        true,
        100,
        125,
        Some("clicked button".to_string()),
        None,
        None,
        Some([8u8; 32]),
    )
    .expect("receipt");

    receipt.verify().expect("receipt verifies");
}

#[test]
fn postcondition_proof_verifies_hash_binding() {
    let req = base_request(Some(6));
    let request_hash = req.try_hash().expect("hash");
    let proof = PostconditionProof::build(
        request_hash,
        "execution.terminal_outcome".to_string(),
        true,
        Some("clicked button".to_string()),
        Some("terminal_outcome".to_string()),
        None,
        125,
    )
    .expect("proof");

    proof.verify().expect("proof verifies");
}

#[test]
fn required_receipt_manifest_verifies_hash_binding() {
    let manifest = RequiredReceiptManifest::build(
        ActionTarget::GuiClick.canonical_label(),
        vec!["execution.outcome".to_string()],
        vec!["execution.terminal_outcome".to_string()],
    )
    .expect("manifest");

    manifest.verify().expect("manifest verifies");
}

#[test]
fn approval_grant_verifies_signature_and_binding() {
    let private_key = Ed25519PrivateKey::from_bytes(&[7u8; 32]).expect("private key");
    let keypair = Ed25519KeyPair::from_private_key(&private_key).expect("keypair");
    let public_key = keypair.public_key().to_bytes();
    let authority_id =
        account_id_from_key_material(SignatureSuite::ED25519, &public_key).expect("authority id");
    let mut grant = ApprovalGrant {
        schema_version: 1,
        authority_id,
        request_hash: [1u8; 32],
        policy_hash: [2u8; 32],
        audience: [3u8; 32],
        nonce: [4u8; 32],
        counter: 1,
        expires_at: 123_456,
        max_usages: Some(1),
        window_id: Some(9),
        pii_action: None,
        scoped_exception: None,
        review_request_hash: None,
        approver_public_key: public_key,
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    };
    let signing_bytes = grant.signing_bytes().expect("signing bytes");
    grant.approver_sig = keypair
        .sign(&signing_bytes)
        .expect("sign")
        .to_bytes()
        .to_vec();

    grant.verify().expect("grant verifies");
    assert_ne!(grant.artifact_hash().expect("artifact hash"), [0u8; 32]);
}

#[test]
fn approval_authority_verifies_binding() {
    let private_key = Ed25519PrivateKey::from_bytes(&[9u8; 32]).expect("private key");
    let keypair = Ed25519KeyPair::from_private_key(&private_key).expect("keypair");
    let public_key = keypair.public_key().to_bytes();
    let authority_id =
        account_id_from_key_material(SignatureSuite::ED25519, &public_key).expect("authority id");
    let authority = ApprovalAuthority {
        schema_version: 1,
        authority_id,
        public_key,
        signature_suite: SignatureSuite::ED25519,
        expires_at: 999_999,
        revoked: false,
        scope_allowlist: vec!["desktop_agent.resume".to_string()],
    };

    authority.verify().expect("authority verifies");
}
