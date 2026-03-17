#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::{anyhow, Result};
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_api::state::service_namespace_prefix;
use ioi_cli::testing::{
    build_test_artifacts, rpc::query_state_key, submit_transaction, submit_transaction_no_wait,
    wait_for_height, TestCluster,
};
use ioi_crypto::security::SecurityLevel;
use ioi_crypto::sign::dilithium::{MldsaKeyPair, MldsaScheme};
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use ioi_services::agentic::desktop::{AgentMode, StartAgentParams};
use ioi_services::wallet_network::{
    ApprovalConsumptionState, BumpRevocationEpochParams, ConsumeApprovalTokenParams,
    IssueSessionGrantParams, LeaseConsumptionState, SessionDelegationState,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ApprovalScope, ApprovalToken, ChainId,
        ChainTransaction, GuardianAttestation, MailConnectorAuthMode, MailConnectorConfig,
        MailConnectorEndpoint, MailConnectorProvider, MailConnectorSecretAliases,
        MailConnectorTlsMode, MailConnectorUpsertParams, MailDeleteSpamParams,
        MailDeleteSpamReceipt, MailListRecentParams, MailListRecentReceipt, MailReadLatestParams,
        MailReadLatestReceipt, MailReplyParams, MailReplyReceipt, SecretInjectionEnvelope,
        SecretInjectionGrant, SecretInjectionRequest, SecretInjectionRequestRecord, SecretKind,
        SessionChannelClose, SessionChannelCloseReason, SessionChannelDelegationRules,
        SessionChannelEnvelope, SessionChannelKeyState, SessionChannelMode, SessionChannelOpenAck,
        SessionChannelOpenConfirm, SessionChannelOpenInit, SessionChannelOpenTry,
        SessionChannelOrdering, SessionChannelRecord, SessionChannelState, SessionGrant,
        SessionLease, SessionLeaseMode, SessionReceiptCommit, SessionReceiptCommitDirection,
        SessionScope, SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
        VaultSecretRecord, VaultSurface, WalletApprovalDecision, WalletApprovalDecisionKind,
        WalletInterceptionContext,
    },
    codec,
    config::ServicePolicy,
    service_configs::MethodPermission,
};
use libp2p::identity::Keypair;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

static E2E_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
struct HybridSigner {
    ed25519: Ed25519KeyPair,
    mldsa: MldsaKeyPair,
    signer_id: [u8; 32],
}

fn new_hybrid_signer() -> Result<HybridSigner> {
    let ed25519 = Ed25519KeyPair::generate().map_err(|e| anyhow!(e.to_string()))?;
    let mldsa = MldsaScheme::new(SecurityLevel::Level2)
        .generate_keypair()
        .map_err(|e| anyhow!(e.to_string()))?;
    let mut hybrid_public_key = ed25519.public_key().to_bytes();
    hybrid_public_key.extend_from_slice(&mldsa.public_key().to_bytes());
    let signer_id =
        account_id_from_key_material(SignatureSuite::HYBRID_ED25519_ML_DSA_44, &hybrid_public_key)?;

    Ok(HybridSigner {
        ed25519,
        mldsa,
        signer_id,
    })
}

fn sign_hybrid_payload(signer: &HybridSigner, payload: &[u8]) -> Result<Vec<u8>> {
    let mut hybrid_public_key = signer.ed25519.public_key().to_bytes();
    hybrid_public_key.extend_from_slice(&signer.mldsa.public_key().to_bytes());

    let mut hybrid_signature = signer
        .ed25519
        .sign(payload)
        .map_err(|e| anyhow!(e.to_string()))?
        .to_bytes();
    hybrid_signature.extend_from_slice(
        &signer
            .mldsa
            .sign(payload)
            .map_err(|e| anyhow!(e.to_string()))?
            .to_bytes(),
    );

    codec::to_bytes_canonical(&SignatureProof {
        suite: SignatureSuite::HYBRID_ED25519_ML_DSA_44,
        public_key: hybrid_public_key,
        signature: hybrid_signature,
    })
    .map_err(|e| anyhow!(e))
}

fn sign_wallet_approval_decision(
    mut approval: WalletApprovalDecision,
    signer: &HybridSigner,
) -> Result<WalletApprovalDecision> {
    {
        let token = approval
            .approval_token
            .as_mut()
            .ok_or_else(|| anyhow!("approval decision missing approval_token"))?;
        token.approver_suite = SignatureSuite::HYBRID_ED25519_ML_DSA_44;
        token.approver_sig.clear();
    }
    let sign_bytes = encode_canonical(&approval)?;
    let signature = sign_hybrid_payload(signer, &sign_bytes)?;
    approval
        .approval_token
        .as_mut()
        .ok_or_else(|| anyhow!("approval decision missing approval_token"))?
        .approver_sig = signature;
    Ok(approval)
}

fn wallet_network_user_policy() -> ServicePolicy {
    let mut methods = BTreeMap::new();
    for method in [
        "issue_session_grant@v1",
        "store_secret_record@v1",
        "mail_connector_upsert@v1",
        "mail_connector_get@v1",
        "open_channel_init@v1",
        "open_channel_try@v1",
        "open_channel_ack@v1",
        "open_channel_confirm@v1",
        "issue_session_lease@v1",
        "mail_read_latest@v1",
        "mail_list_recent@v1",
        "mail_delete_spam@v1",
        "mail_reply@v1",
        "commit_receipt_root@v1",
        "close_channel@v1",
        "record_secret_injection_request@v1",
        "grant_secret_injection@v1",
        "record_interception@v1",
        "record_approval@v1",
        "consume_approval_token@v1",
        "panic_stop@v1",
    ] {
        methods.insert(method.to_string(), MethodPermission::User);
    }
    ServicePolicy {
        methods,
        allowed_system_prefixes: vec![],
    }
}

fn desktop_agent_user_policy() -> ServicePolicy {
    let mut methods = BTreeMap::new();
    methods.insert("start@v1".to_string(), MethodPermission::User);
    ServicePolicy {
        methods,
        allowed_system_prefixes: vec![],
    }
}

fn encode_canonical<T: Encode>(value: &T) -> Result<Vec<u8>> {
    codec::to_bytes_canonical(value).map_err(|e| anyhow!(e))
}

fn create_call_service_tx<P: Encode>(
    keypair: &Keypair,
    service_id: &str,
    method: &str,
    params: P,
    nonce: u64,
    chain_id: ChainId,
) -> Result<ChainTransaction> {
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(SignatureSuite::ED25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

    let payload = SystemPayload::CallService {
        service_id: service_id.to_string(),
        method: method.to_string(),
        params: encode_canonical(&params)?,
    };

    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
        session_auth: None,
    };
    let mut tx = SystemTransaction {
        header,
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
    tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: public_key_bytes,
        signature: keypair.sign(&sign_bytes)?,
    };
    Ok(ChainTransaction::System(Box::new(tx)))
}

async fn submit_wallet_call<P: Encode>(
    rpc_addr: &str,
    keypair: &Keypair,
    chain_id: ChainId,
    nonce: u64,
    method: &str,
    params: P,
) -> Result<()> {
    let tx = create_call_service_tx(keypair, "wallet_network", method, params, nonce, chain_id)?;
    submit_transaction(rpc_addr, &tx).await
}

fn service_key(local_key: &[u8]) -> Vec<u8> {
    [
        service_namespace_prefix("wallet_network").as_slice(),
        local_key,
    ]
    .concat()
}

fn channel_storage_key(channel_id: &[u8; 32]) -> Vec<u8> {
    [b"channel::".as_slice(), channel_id.as_slice()].concat()
}

fn channel_key_state_storage_key(channel_id: &[u8; 32]) -> Vec<u8> {
    [b"channel_key_state::".as_slice(), channel_id.as_slice()].concat()
}

fn lease_storage_key(channel_id: &[u8; 32], lease_id: &[u8; 32]) -> Vec<u8> {
    [
        b"lease::".as_slice(),
        channel_id.as_slice(),
        b"::".as_slice(),
        lease_id.as_slice(),
    ]
    .concat()
}

fn lease_consumption_storage_key(channel_id: &[u8; 32], lease_id: &[u8; 32]) -> Vec<u8> {
    [
        b"lease_consumption::".as_slice(),
        channel_id.as_slice(),
        b"::".as_slice(),
        lease_id.as_slice(),
    ]
    .concat()
}

fn mail_read_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [b"mail_read_receipt::".as_slice(), operation_id.as_slice()].concat()
}

fn mail_list_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [b"mail_list_receipt::".as_slice(), operation_id.as_slice()].concat()
}

fn mail_delete_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [b"mail_delete_receipt::".as_slice(), operation_id.as_slice()].concat()
}

fn mail_reply_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [b"mail_reply_receipt::".as_slice(), operation_id.as_slice()].concat()
}

fn session_storage_key(session_id: &[u8; 32]) -> Vec<u8> {
    [b"session::".as_slice(), session_id.as_slice()].concat()
}

fn session_delegation_storage_key(session_id: &[u8; 32]) -> Vec<u8> {
    [b"session_delegation::".as_slice(), session_id.as_slice()].concat()
}

fn receipt_commit_storage_key(
    channel_id: &[u8; 32],
    direction: SessionReceiptCommitDirection,
    end_seq: u64,
) -> Vec<u8> {
    let direction_label = match direction {
        SessionReceiptCommitDirection::LocalToRemote => b"l2r".as_slice(),
        SessionReceiptCommitDirection::RemoteToLocal => b"r2l".as_slice(),
    };
    let seq_bytes = end_seq.to_be_bytes();
    [
        b"receipt_commit::".as_slice(),
        channel_id.as_slice(),
        b"::".as_slice(),
        direction_label,
        b"::".as_slice(),
        seq_bytes.as_slice(),
    ]
    .concat()
}

fn interception_storage_key(request_hash: &[u8; 32]) -> Vec<u8> {
    [b"interception::".as_slice(), request_hash.as_slice()].concat()
}

fn approval_storage_key(request_hash: &[u8; 32]) -> Vec<u8> {
    [b"approval::".as_slice(), request_hash.as_slice()].concat()
}

fn approval_consumption_storage_key(request_hash: &[u8; 32]) -> Vec<u8> {
    [
        b"approval_consumption::".as_slice(),
        request_hash.as_slice(),
    ]
    .concat()
}

fn injection_request_storage_key(request_id: &[u8; 32]) -> Vec<u8> {
    [b"injection_request::".as_slice(), request_id.as_slice()].concat()
}

fn injection_grant_storage_key(request_id: &[u8; 32]) -> Vec<u8> {
    [b"injection_grant::".as_slice(), request_id.as_slice()].concat()
}

fn hash_channel_envelope(envelope: &SessionChannelEnvelope) -> Result<[u8; 32]> {
    let payload = codec::to_bytes_canonical(envelope).map_err(|e| anyhow!(e))?;
    let digest = Sha256::digest(&payload).map_err(|e| anyhow!(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn unique_id(label: &str) -> [u8; 32] {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos()
        .to_le_bytes();
    let mut input = Vec::with_capacity(label.len() + now_nanos.len());
    input.extend_from_slice(label.as_bytes());
    input.extend_from_slice(&now_nanos);
    let digest = Sha256::digest(&input).expect("hash");
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

async fn load_wallet_value<T: Decode>(rpc_addr: &str, local_key: &[u8]) -> Result<T> {
    let fq_key = service_key(local_key);
    let bytes = query_state_key(rpc_addr, &fq_key)
        .await?
        .ok_or_else(|| anyhow!("missing wallet state key: {}", hex::encode(&fq_key)))?;
    codec::from_bytes_canonical(&bytes).map_err(|e| anyhow!(e))
}

mod approval_token_consumption;
mod bridge_interceptions;
mod lifecycle;
mod mail_delete_spam;
mod mail_reply_draft_send_contract;
mod mail_reply_with_approval;
mod secret_injection_binding;
