use super::{
    admission_committed_nonce_state, decode_account_nonce,
    lifecycle_control_can_use_tx_nonce_floor, lifecycle_step_can_be_readmitted,
    requires_ingestion_semantic_screening, should_fast_admit_rpc_transaction, tx_lifecycle_label,
    tx_status_is_rejected,
};
use crate::standard::orchestration::context::TxStatusEntry;
use ioi_ipc::public::TxStatus;
use ioi_types::app::{
    AccountId, ChainId, ChainTransaction, SignHeader, SignatureProof, SignatureSuite, StateEntry,
    SystemPayload, SystemTransaction,
};
use ioi_types::codec;

fn system_call(service_id: &str, method: &str) -> ChainTransaction {
    ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([0u8; 32]),
            nonce: 0,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: service_id.to_string(),
            method: method.to_string(),
            params: Vec::new(),
        },
        signature_proof: SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: Vec::new(),
            signature: Vec::new(),
        },
    }))
}

#[test]
fn semantic_screening_fast_admits_desktop_agent_lifecycle_controls() {
    for method in [
        "start@v1",
        "step@v1",
        "post_message@v1",
        "resume@v1",
        "deny@v1",
        "register_approval_authority@v1",
        "revoke_approval_authority@v1",
        "delete_session@v1",
    ] {
        assert!(
            !requires_ingestion_semantic_screening(&system_call("desktop_agent", method)),
            "{method} should be a validator-fast lifecycle control"
        );
    }
}

#[test]
fn semantic_screening_routes_effectful_runtime_service_calls_through_ingestion() {
    assert!(requires_ingestion_semantic_screening(&system_call(
        "desktop_agent",
        "package__install"
    )));
    assert!(requires_ingestion_semantic_screening(&system_call(
        "agentic", "start@v1"
    )));
    assert!(requires_ingestion_semantic_screening(&system_call(
        "compute_market",
        "start@v1"
    )));
}

#[test]
fn semantic_screening_keeps_unrelated_service_calls_fast_admissible() {
    assert!(!requires_ingestion_semantic_screening(&system_call(
        "wallet_network",
        "start@v1"
    )));
}

#[test]
fn rpc_admission_decodes_wrapped_account_nonce_state() {
    let wrapped = StateEntry {
        value: codec::to_bytes_canonical(&7u64).expect("encode nonce"),
        block_height: 42,
    };
    let bytes = codec::to_bytes_canonical(&wrapped).expect("encode state entry");

    assert_eq!(decode_account_nonce(&bytes), 7);
}

#[test]
fn rpc_admission_evicts_rejected_hash_before_readmit() {
    let rejected = TxStatusEntry {
        status: TxStatus::Rejected,
        error: Some("previous semantic pause".to_string()),
        block_height: None,
    };
    let pending = TxStatusEntry {
        status: TxStatus::Pending,
        error: None,
        block_height: None,
    };

    assert!(tx_status_is_rejected(Some(&rejected)));
    assert!(!tx_status_is_rejected(Some(&pending)));
    assert!(!tx_status_is_rejected(None));
}

#[test]
fn rpc_admission_allows_desktop_agent_step_readmission_by_nonce() {
    let step = system_call("desktop_agent", "step@v1");
    let start = system_call("desktop_agent", "start@v1");

    assert_eq!(tx_lifecycle_label(&step), Some("desktop_agent.step"));
    assert!(lifecycle_step_can_be_readmitted(tx_lifecycle_label(&step)));
    assert!(!lifecycle_step_can_be_readmitted(tx_lifecycle_label(
        &start
    )));
}

#[test]
fn rpc_admission_uses_step_nonce_floor_for_lifecycle_readmission() {
    let account = AccountId([9u8; 32]);
    let tx_info = Some((account, 3));
    assert_eq!(
        admission_committed_nonce_state(tx_info.as_ref(), Some("desktop_agent.step"), 0, true),
        3
    );
    assert_eq!(
        admission_committed_nonce_state(tx_info.as_ref(), Some("desktop_agent.step"), 5, true),
        5
    );
    assert_eq!(
        admission_committed_nonce_state(tx_info.as_ref(), Some("desktop_agent.step"), 0, false),
        3
    );
    assert_eq!(
        admission_committed_nonce_state(tx_info.as_ref(), Some("desktop_agent.start"), 0, true),
        0
    );
}

#[test]
fn rpc_admission_uses_nonce_floor_for_ready_lifecycle_controls() {
    let account = AccountId([9u8; 32]);
    let tx_info = Some((account, 3));

    assert!(lifecycle_control_can_use_tx_nonce_floor(Some(
        "desktop_agent.step"
    )));
    assert!(lifecycle_control_can_use_tx_nonce_floor(Some(
        "desktop_agent.resume"
    )));
    assert!(!lifecycle_control_can_use_tx_nonce_floor(Some(
        "desktop_agent.start"
    )));
    assert_eq!(
        admission_committed_nonce_state(tx_info.as_ref(), Some("desktop_agent.step"), 0, false),
        3
    );
    assert_eq!(
        admission_committed_nonce_state(tx_info.as_ref(), Some("desktop_agent.resume"), 2, false),
        3
    );
    assert_eq!(
        admission_committed_nonce_state(tx_info.as_ref(), Some("desktop_agent.start"), 0, false),
        0
    );
}

#[test]
fn rpc_admission_fast_admits_rejected_step_readmission_past_size_guard() {
    assert!(should_fast_admit_rpc_transaction(
        false,
        Some("desktop_agent.step"),
        true,
        10_000,
        512
    ));
    assert!(should_fast_admit_rpc_transaction(
        false,
        Some("desktop_agent.start"),
        true,
        10_000,
        512
    ));
    assert!(should_fast_admit_rpc_transaction(
        false,
        Some("desktop_agent.step"),
        false,
        10_000,
        512
    ));
}

#[test]
fn rpc_admission_fast_admits_lifecycle_controls_past_size_guard() {
    assert!(should_fast_admit_rpc_transaction(
        false,
        Some("desktop_agent.start"),
        false,
        10_000,
        512
    ));
    assert!(should_fast_admit_rpc_transaction(
        false,
        Some("desktop_agent.resume"),
        false,
        10_000,
        512
    ));
    assert!(!should_fast_admit_rpc_transaction(
        true,
        Some("desktop_agent.step"),
        false,
        10_000,
        512
    ));
}

#[test]
fn rpc_admission_routes_generic_transactions_through_ingestion() {
    assert!(!should_fast_admit_rpc_transaction(
        false, None, false, 0, 512
    ));
    assert!(!should_fast_admit_rpc_transaction(
        false, None, false, 10, 512
    ));
}
