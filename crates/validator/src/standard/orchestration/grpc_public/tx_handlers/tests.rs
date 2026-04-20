use super::requires_ingestion_semantic_screening;
use ioi_types::app::{
    AccountId, ChainId, ChainTransaction, SignHeader, SignatureProof, SignatureSuite,
    SystemPayload, SystemTransaction,
};

fn system_call(service_id: &str) -> ChainTransaction {
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
            method: "start@v1".to_string(),
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
fn semantic_screening_routes_desktop_agent_service_calls_through_ingestion() {
    assert!(requires_ingestion_semantic_screening(&system_call(
        "desktop_agent"
    )));
    assert!(requires_ingestion_semantic_screening(&system_call(
        "agentic"
    )));
    assert!(requires_ingestion_semantic_screening(&system_call(
        "compute_market"
    )));
}

#[test]
fn semantic_screening_keeps_unrelated_service_calls_fast_admissible() {
    assert!(!requires_ingestion_semantic_screening(&system_call(
        "wallet_network"
    )));
}
