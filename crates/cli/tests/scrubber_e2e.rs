// Path: crates/cli/tests/scrubber_e2e.rs
#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ChainTransaction, SignHeader, SignatureProof,
        SignatureSuite, SystemPayload, SystemTransaction,
    },
    codec,
    error::{TransactionError, VmError},
    keys::active_service_key,
    service_configs::{ActiveServiceMeta, Capabilities, MethodPermission},
};
use ioi_validator::firewall::{enforce_firewall, inference::HeuristicBitNet};
use libp2p::identity::Keypair;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Default)]
struct DummyOs;

#[async_trait]
impl OsDriver for DummyOs {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(None)
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(None)
    }

    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Ok(true)
    }

    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(String::new())
    }
}

fn install_desktop_agent_meta(state: &mut IAVLTree<HashCommitmentScheme>) -> anyhow::Result<()> {
    let mut methods = BTreeMap::new();
    methods.insert("post_message@v1".to_string(), MethodPermission::User);

    let meta = ActiveServiceMeta {
        id: "desktop_agent".to_string(),
        abi_version: 1,
        state_schema: "v1".to_string(),
        caps: Capabilities::empty(),
        artifact_hash: [0u8; 32],
        activated_at: 0,
        methods,
        allowed_system_prefixes: vec!["upgrade::active::".to_string()],
        generation_id: 0,
        parent_hash: None,
        author: None,
        context_filter: None,
    };

    state.insert(
        &active_service_key("desktop_agent"),
        &codec::to_bytes_canonical(&meta).map_err(|e| anyhow!(e))?,
    )?;
    Ok(())
}

fn signed_service_call(
    keypair: &Keypair,
    account_id: AccountId,
    params: Vec<u8>,
) -> anyhow::Result<ChainTransaction> {
    let public_key = keypair.public().encode_protobuf();
    let mut tx = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce: 0,
            chain_id: 1.into(),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "desktop_agent".to_string(),
            method: "post_message@v1".to_string(),
            params,
        },
        signature_proof: SignatureProof::default(),
    };

    let sign_bytes = tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
    tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature: keypair.sign(&sign_bytes)?,
    };

    Ok(ChainTransaction::System(Box::new(tx)))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pii_firewall_blocks_raw_egress_and_allows_clean_payload() -> Result<()> {
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    install_desktop_agent_meta(&mut state)?;

    let services_dir = ServiceDirectory::new(vec![]);
    let safety_model = Arc::new(HeuristicBitNet);
    let os_driver = Arc::new(DummyOs);
    let no_events: Option<tokio::sync::broadcast::Sender<ioi_types::app::KernelEvent>> = None;

    let keypair = Keypair::generate_ed25519();
    let public_key = keypair.public().encode_protobuf();
    let account_id = AccountId(account_id_from_key_material(
        SignatureSuite::ED25519,
        &public_key,
    )?);

    let sensitive_tx = signed_service_call(
        &keypair,
        account_id,
        b"Execute trade using key sk_live_1234567890abcd".to_vec(),
    )?;

    let sensitive_err = enforce_firewall(
        &mut state,
        &services_dir,
        &sensitive_tx,
        1.into(),
        1,
        0,
        false,
        true,
        safety_model.clone(),
        os_driver.clone(),
        &no_events,
    )
    .await
    .expect_err("PII-bearing payload should be blocked before execution")
    .to_string();

    println!("Firewall correctly rejected tx: {}", sensitive_err);
    assert!(
        sensitive_err.contains("PII firewall denied raw egress")
            || sensitive_err.contains("Blocked by Safety Firewall")
            || sensitive_err.contains("PII detected"),
        "unexpected rejection path: {}",
        sensitive_err
    );

    let safe_tx = signed_service_call(
        &keypair,
        account_id,
        b"Send a short hello message with no secrets".to_vec(),
    )?;

    let safe_result = enforce_firewall(
        &mut state,
        &services_dir,
        &safe_tx,
        1.into(),
        1,
        0,
        false,
        true,
        safety_model,
        os_driver,
        &no_events,
    )
    .await;

    match safe_result {
        Ok(()) => {}
        Err(TransactionError::PendingApproval(_)) => {}
        Err(other) => panic!("safe payload should not be blocked for PII: {}", other),
    }

    Ok(())
}
