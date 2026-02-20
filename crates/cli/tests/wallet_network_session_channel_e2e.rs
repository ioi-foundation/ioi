#![cfg(all(
    feature = "consensus-admft",
    feature = "vm-wasm",
    feature = "state-iavl"
))]

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
    IssueSessionGrantParams, SessionDelegationState,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ApprovalScope, ApprovalToken, ChainId,
        ChainTransaction, GuardianAttestation, SecretInjectionEnvelope, SecretInjectionGrant,
        SecretInjectionRequest, SecretInjectionRequestRecord, SecretKind, SessionChannelClose,
        SessionChannelCloseReason, SessionChannelDelegationRules, SessionChannelEnvelope,
        SessionChannelKeyState, SessionChannelMode, SessionChannelOpenAck,
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
        "open_channel_init@v1",
        "open_channel_try@v1",
        "open_channel_ack@v1",
        "open_channel_confirm@v1",
        "issue_session_lease@v1",
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

#[tokio::test]
async fn wallet_network_session_channel_lifecycle_via_real_callservice_txs() -> Result<()> {
    let _guard = E2E_TEST_LOCK.lock().expect("lock");
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Admft")
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_network_user_policy())
        .build()
        .await?;

    let test_result: Result<()> = async {
        let node = cluster.validators[0].validator();
        let rpc_addr = &node.rpc_addr;
        let keypair = &node.keypair;
        let chain_id: ChainId = 1.into();
        let mut nonce = 0u64;
        let lc_signer = new_hybrid_signer()?;
        let rc_signer = new_hybrid_signer()?;

        wait_for_height(rpc_addr, 1, Duration::from_secs(30)).await?;

        let root_session_id = unique_id("wallet_network_root_session");
        let child_session_id = unique_id("wallet_network_child_session");
        let budget_reject_session_id = unique_id("wallet_network_budget_reject");
        let depth_reject_session_id = unique_id("wallet_network_depth_reject");
        let grant_scope = SessionScope {
            expires_at_ms: 4_200_000_000_000,
            max_actions: Some(20),
            max_spend_usd_micros: Some(1_000_000),
            action_allowlist: vec![
                ioi_types::app::ActionTarget::WebRetrieve,
                ioi_types::app::ActionTarget::NetFetch,
            ],
            domain_allowlist: vec!["status.vendor-a.com".to_string()],
        };
        let root_grant = SessionGrant {
            session_id: root_session_id,
            vault_id: [0x9au8; 32],
            agent_id: "wallet-e2e-agent".to_string(),
            purpose: "wallet parity e2e".to_string(),
            scope: grant_scope.clone(),
            guardian_ephemeral_public_key: vec![1, 2, 3, 4],
            issued_at_ms: 4_100_000_000_000,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "issue_session_grant@v1",
            IssueSessionGrantParams {
                grant: root_grant,
                parent_session_id: None,
                delegation_rules: Some(SessionChannelDelegationRules {
                    max_depth: 1,
                    can_redelegate: true,
                    issuance_budget: Some(1),
                }),
            },
        )
        .await?;
        nonce += 1;

        let child_grant = SessionGrant {
            session_id: child_session_id,
            vault_id: [0x9au8; 32],
            agent_id: "wallet-e2e-agent-child".to_string(),
            purpose: "wallet parity e2e child".to_string(),
            scope: SessionScope {
                expires_at_ms: 4_150_000_000_000,
                max_actions: Some(5),
                max_spend_usd_micros: Some(250_000),
                action_allowlist: vec![ioi_types::app::ActionTarget::WebRetrieve],
                domain_allowlist: vec!["status.vendor-a.com".to_string()],
            },
            guardian_ephemeral_public_key: vec![5, 6, 7],
            issued_at_ms: 4_100_000_000_100,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "issue_session_grant@v1",
            IssueSessionGrantParams {
                grant: child_grant.clone(),
                parent_session_id: Some(root_session_id),
                delegation_rules: None,
            },
        )
        .await?;
        nonce += 1;

        let budget_reject_grant = SessionGrant {
            session_id: budget_reject_session_id,
            vault_id: [0x9au8; 32],
            agent_id: "wallet-e2e-agent-budget-reject".to_string(),
            purpose: "budget reject".to_string(),
            scope: SessionScope {
                expires_at_ms: 4_140_000_000_000,
                max_actions: Some(4),
                max_spend_usd_micros: Some(200_000),
                action_allowlist: vec![ioi_types::app::ActionTarget::WebRetrieve],
                domain_allowlist: vec!["status.vendor-a.com".to_string()],
            },
            guardian_ephemeral_public_key: vec![8, 9],
            issued_at_ms: 4_100_000_000_200,
        };
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "issue_session_grant@v1",
            IssueSessionGrantParams {
                grant: budget_reject_grant,
                parent_session_id: Some(root_session_id),
                delegation_rules: None,
            },
        )
        .await;
        nonce += 1;

        let depth_reject_grant = SessionGrant {
            session_id: depth_reject_session_id,
            vault_id: [0x9au8; 32],
            agent_id: "wallet-e2e-agent-depth-reject".to_string(),
            purpose: "depth reject".to_string(),
            scope: SessionScope {
                expires_at_ms: 4_130_000_000_000,
                max_actions: Some(3),
                max_spend_usd_micros: Some(100_000),
                action_allowlist: vec![ioi_types::app::ActionTarget::WebRetrieve],
                domain_allowlist: vec!["status.vendor-a.com".to_string()],
            },
            guardian_ephemeral_public_key: vec![10, 11],
            issued_at_ms: 4_100_000_000_300,
        };
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "issue_session_grant@v1",
            IssueSessionGrantParams {
                grant: depth_reject_grant,
                parent_session_id: Some(child_session_id),
                delegation_rules: None,
            },
        )
        .await;
        nonce += 1;

        let root_delegation: SessionDelegationState =
            load_wallet_value(rpc_addr, &session_delegation_storage_key(&root_session_id)).await?;
        assert_eq!(root_delegation.depth, 0);
        assert_eq!(root_delegation.max_depth, 1);
        assert_eq!(root_delegation.remaining_issuance_budget, Some(0));
        assert_eq!(root_delegation.children_issued, 1);
        assert!(!root_delegation.can_redelegate);

        let child_delegation: SessionDelegationState =
            load_wallet_value(rpc_addr, &session_delegation_storage_key(&child_session_id)).await?;
        assert_eq!(child_delegation.root_session_id, root_session_id);
        assert_eq!(child_delegation.depth, 1);

        let budget_reject_lookup = service_key(&session_storage_key(&budget_reject_session_id));
        let depth_reject_lookup = service_key(&session_storage_key(&depth_reject_session_id));
        assert!(query_state_key(rpc_addr, &budget_reject_lookup)
            .await?
            .is_none());
        assert!(query_state_key(rpc_addr, &depth_reject_lookup)
            .await?
            .is_none());

        let channel_id = [0x11u8; 32];
        let lease_id = [0x41u8; 32];
        let envelope = SessionChannelEnvelope {
            channel_id,
            lc_id: lc_signer.signer_id,
            rc_id: rc_signer.signer_id,
            ordering: SessionChannelOrdering::Ordered,
            mode: SessionChannelMode::RemoteRequestLocalExecution,
            policy_hash: [0x23u8; 32],
            policy_version: 7,
            root_grant_id: [0x24u8; 32],
            capability_set: vec!["email:read".to_string(), "email:search".to_string()],
            constraints: BTreeMap::from([
                ("mailbox".to_string(), "primary".to_string()),
                ("max_results".to_string(), "1".to_string()),
            ]),
            delegation_rules: SessionChannelDelegationRules {
                max_depth: 1,
                can_redelegate: false,
                issuance_budget: Some(4),
            },
            revocation_epoch: 0,
            expires_at_ms: 4_200_000_000_000,
        };
        let envelope_hash = hash_channel_envelope(&envelope)?;

        let mut open_init = SessionChannelOpenInit {
            envelope: envelope.clone(),
            lc_kem_ephemeral_pub_classical: vec![1, 2, 3],
            lc_kem_ephemeral_pub_pq: vec![4, 5, 6],
            nonce_lc: [0x31u8; 32],
            sig_hybrid_lc: Vec::new(),
        };
        let mut open_init_unsigned = open_init.clone();
        open_init_unsigned.sig_hybrid_lc.clear();
        open_init.sig_hybrid_lc =
            sign_hybrid_payload(&lc_signer, &encode_canonical(&open_init_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "open_channel_init@v1",
            open_init,
        )
        .await?;
        nonce += 1;

        let mut channel: SessionChannelRecord =
            load_wallet_value(rpc_addr, &channel_storage_key(&channel_id)).await?;
        assert_eq!(channel.state, SessionChannelState::OpenInit);
        assert_eq!(channel.envelope_hash, envelope_hash);

        let mut open_try = SessionChannelOpenTry {
            channel_id,
            envelope_hash,
            rc_attestation_evidence: vec![10, 11],
            rc_attestation_pub: vec![12, 13],
            rc_kem_ephemeral_pub_classical: vec![14, 15],
            rc_kem_ciphertext_pq: vec![16, 17],
            nonce_rc: [0x32u8; 32],
            sig_hybrid_rc: Vec::new(),
        };
        let mut open_try_unsigned = open_try.clone();
        open_try_unsigned.sig_hybrid_rc.clear();
        open_try.sig_hybrid_rc =
            sign_hybrid_payload(&rc_signer, &encode_canonical(&open_try_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "open_channel_try@v1",
            open_try,
        )
        .await?;
        nonce += 1;

        channel = load_wallet_value(rpc_addr, &channel_storage_key(&channel_id)).await?;
        assert_eq!(channel.state, SessionChannelState::OpenTry);

        let mut open_ack = SessionChannelOpenAck {
            channel_id,
            envelope_hash,
            nonce_lc2: [0x33u8; 32],
            sig_hybrid_lc: Vec::new(),
        };
        let mut open_ack_unsigned = open_ack.clone();
        open_ack_unsigned.sig_hybrid_lc.clear();
        open_ack.sig_hybrid_lc =
            sign_hybrid_payload(&lc_signer, &encode_canonical(&open_ack_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "open_channel_ack@v1",
            open_ack,
        )
        .await?;
        nonce += 1;

        channel = load_wallet_value(rpc_addr, &channel_storage_key(&channel_id)).await?;
        assert_eq!(channel.state, SessionChannelState::OpenAck);

        let mut open_confirm = SessionChannelOpenConfirm {
            channel_id,
            envelope_hash,
            nonce_rc2: [0x34u8; 32],
            sig_hybrid_rc: Vec::new(),
        };
        let mut open_confirm_unsigned = open_confirm.clone();
        open_confirm_unsigned.sig_hybrid_rc.clear();
        open_confirm.sig_hybrid_rc =
            sign_hybrid_payload(&rc_signer, &encode_canonical(&open_confirm_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "open_channel_confirm@v1",
            open_confirm,
        )
        .await?;
        nonce += 1;

        channel = load_wallet_value(rpc_addr, &channel_storage_key(&channel_id)).await?;
        assert_eq!(channel.state, SessionChannelState::Open);
        assert!(channel.opened_at_ms.is_some());

        let channel_key_state: SessionChannelKeyState =
            load_wallet_value(rpc_addr, &channel_key_state_storage_key(&channel_id)).await?;
        assert!(channel_key_state.ready);
        assert_eq!(channel_key_state.key_epoch, 1);
        assert!(channel_key_state.derived_channel_secret_hash.is_some());
        assert_eq!(channel_key_state.nonce_rc, Some([0x32u8; 32]));
        assert_eq!(channel_key_state.nonce_lc2, Some([0x33u8; 32]));
        assert_eq!(channel_key_state.nonce_rc2, Some([0x34u8; 32]));
        assert_eq!(channel_key_state.transcript_version, 1);
        assert_ne!(channel_key_state.kem_transcript_hash, [0u8; 32]);

        let mut lease = SessionLease {
            lease_id,
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0x43u8; 32],
            policy_hash: envelope.policy_hash,
            grant_id: [0x44u8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 4_150_000_000_000,
            revocation_epoch: 0,
            audience: [0x45u8; 32],
            nonce: [0x46u8; 32],
            counter: 1,
            issued_at_ms: 4_100_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut lease_unsigned = lease.clone();
        lease_unsigned.sig_hybrid_lc.clear();
        lease.sig_hybrid_lc = sign_hybrid_payload(&lc_signer, &encode_canonical(&lease_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "issue_session_lease@v1",
            lease.clone(),
        )
        .await?;
        nonce += 1;

        let stored_lease: SessionLease =
            load_wallet_value(rpc_addr, &lease_storage_key(&channel_id, &lease_id)).await?;
        assert_eq!(stored_lease.channel_id, channel_id);
        assert_eq!(
            stored_lease.capability_subset,
            vec!["email:read".to_string()]
        );
        assert_eq!(stored_lease.constraints_subset, lease.constraints_subset);

        let mut lease_counter_replay = lease.clone();
        lease_counter_replay.lease_id = [0x47u8; 32];
        lease_counter_replay.counter = 1;
        lease_counter_replay.nonce = [0x48u8; 32];
        lease_counter_replay.sig_hybrid_lc.clear();
        let mut lease_counter_replay_unsigned = lease_counter_replay.clone();
        lease_counter_replay_unsigned.sig_hybrid_lc.clear();
        lease_counter_replay.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &encode_canonical(&lease_counter_replay_unsigned)?,
        )?;
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "issue_session_lease@v1",
            lease_counter_replay,
        )
        .await;
        nonce += 1;

        let mut lease_counter_gap = lease.clone();
        lease_counter_gap.lease_id = [0x4au8; 32];
        lease_counter_gap.counter = 3;
        lease_counter_gap.nonce = [0x4bu8; 32];
        lease_counter_gap.sig_hybrid_lc.clear();
        let mut lease_counter_gap_unsigned = lease_counter_gap.clone();
        lease_counter_gap_unsigned.sig_hybrid_lc.clear();
        lease_counter_gap.sig_hybrid_lc =
            sign_hybrid_payload(&lc_signer, &encode_canonical(&lease_counter_gap_unsigned)?)?;
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "issue_session_lease@v1",
            lease_counter_gap,
        )
        .await;
        nonce += 1;

        let mut lease_nonce_replay = lease.clone();
        lease_nonce_replay.lease_id = [0x49u8; 32];
        lease_nonce_replay.counter = 2;
        lease_nonce_replay.nonce = lease.nonce;
        lease_nonce_replay.sig_hybrid_lc.clear();
        let mut lease_nonce_replay_unsigned = lease_nonce_replay.clone();
        lease_nonce_replay_unsigned.sig_hybrid_lc.clear();
        lease_nonce_replay.sig_hybrid_lc =
            sign_hybrid_payload(&lc_signer, &encode_canonical(&lease_nonce_replay_unsigned)?)?;
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "issue_session_lease@v1",
            lease_nonce_replay,
        )
        .await;
        nonce += 1;

        let lease_counter_replay_lookup =
            service_key(&lease_storage_key(&channel_id, &[0x47u8; 32]));
        let lease_counter_gap_lookup = service_key(&lease_storage_key(&channel_id, &[0x4au8; 32]));
        let lease_nonce_replay_lookup = service_key(&lease_storage_key(&channel_id, &[0x49u8; 32]));
        assert!(query_state_key(rpc_addr, &lease_counter_replay_lookup)
            .await?
            .is_none());
        assert!(query_state_key(rpc_addr, &lease_counter_gap_lookup)
            .await?
            .is_none());
        assert!(query_state_key(rpc_addr, &lease_nonce_replay_lookup)
            .await?
            .is_none());

        let mut commit = SessionReceiptCommit {
            commit_id: [0u8; 32],
            channel_id,
            direction: SessionReceiptCommitDirection::LocalToRemote,
            start_seq: 0,
            end_seq: 7,
            merkle_root: [0x51u8; 32],
            committed_at_ms: 0,
            signer_id: rc_signer.signer_id,
            sig_hybrid_sender: Vec::new(),
        };
        let mut commit_unsigned = commit.clone();
        commit_unsigned.sig_hybrid_sender.clear();
        commit.sig_hybrid_sender =
            sign_hybrid_payload(&rc_signer, &encode_canonical(&commit_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "commit_receipt_root@v1",
            commit.clone(),
        )
        .await?;
        nonce += 1;

        let stored_commit: SessionReceiptCommit = load_wallet_value(
            rpc_addr,
            &receipt_commit_storage_key(
                &channel_id,
                SessionReceiptCommitDirection::LocalToRemote,
                commit.end_seq,
            ),
        )
        .await?;
        assert_eq!(stored_commit.channel_id, channel_id);
        assert_eq!(stored_commit.end_seq, 7);
        assert_ne!(stored_commit.commit_id, [0u8; 32]);

        let mut out_of_order_commit = commit.clone();
        out_of_order_commit.commit_id = [0u8; 32];
        out_of_order_commit.start_seq = 9;
        out_of_order_commit.end_seq = 10;
        out_of_order_commit.merkle_root = [0x52u8; 32];
        out_of_order_commit.sig_hybrid_sender.clear();
        let mut out_of_order_commit_unsigned = out_of_order_commit.clone();
        out_of_order_commit_unsigned.sig_hybrid_sender.clear();
        out_of_order_commit.sig_hybrid_sender = sign_hybrid_payload(
            &rc_signer,
            &encode_canonical(&out_of_order_commit_unsigned)?,
        )?;
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "commit_receipt_root@v1",
            out_of_order_commit,
        )
        .await;
        nonce += 1;

        let out_of_order_lookup = service_key(&receipt_commit_storage_key(
            &channel_id,
            SessionReceiptCommitDirection::LocalToRemote,
            10,
        ));
        assert!(query_state_key(rpc_addr, &out_of_order_lookup)
            .await?
            .is_none());

        channel = load_wallet_value(rpc_addr, &channel_storage_key(&channel_id)).await?;
        assert_eq!(channel.state, SessionChannelState::Open);
        assert_eq!(channel.last_seq, 7);

        let mut close = SessionChannelClose {
            channel_id,
            reason: SessionChannelCloseReason::Manual,
            final_seq: 9,
            closed_at_ms: 4_100_000_100_000,
            sig_hybrid_sender: Vec::new(),
        };
        let mut close_unsigned = close.clone();
        close_unsigned.sig_hybrid_sender.clear();
        close.sig_hybrid_sender =
            sign_hybrid_payload(&lc_signer, &encode_canonical(&close_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "close_channel@v1",
            close,
        )
        .await?;
        nonce += 1;

        channel = load_wallet_value(rpc_addr, &channel_storage_key(&channel_id)).await?;
        assert_eq!(channel.state, SessionChannelState::Closed);
        assert_eq!(channel.last_seq, 9);
        assert_eq!(
            channel.close_reason,
            Some(SessionChannelCloseReason::Manual)
        );
        assert!(channel.closed_at_ms.is_some());

        let closed_channel_key_state: SessionChannelKeyState =
            load_wallet_value(rpc_addr, &channel_key_state_storage_key(&channel_id)).await?;
        assert!(!closed_channel_key_state.ready);

        let unordered_channel_id = [0x12u8; 32];
        let unordered_envelope = SessionChannelEnvelope {
            channel_id: unordered_channel_id,
            lc_id: lc_signer.signer_id,
            rc_id: rc_signer.signer_id,
            ordering: SessionChannelOrdering::Unordered,
            mode: SessionChannelMode::RemoteRequestLocalExecution,
            policy_hash: [0x33u8; 32],
            policy_version: 9,
            root_grant_id: [0x34u8; 32],
            capability_set: vec!["email:read".to_string(), "email:search".to_string()],
            constraints: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
            delegation_rules: SessionChannelDelegationRules {
                max_depth: 2,
                can_redelegate: true,
                issuance_budget: Some(8),
            },
            revocation_epoch: 0,
            expires_at_ms: 4_250_000_000_000,
        };
        let unordered_envelope_hash = hash_channel_envelope(&unordered_envelope)?;

        let mut unordered_open_init = SessionChannelOpenInit {
            envelope: unordered_envelope.clone(),
            lc_kem_ephemeral_pub_classical: vec![21, 22, 23],
            lc_kem_ephemeral_pub_pq: vec![24, 25, 26],
            nonce_lc: [0x61u8; 32],
            sig_hybrid_lc: Vec::new(),
        };
        let mut unordered_open_init_unsigned = unordered_open_init.clone();
        unordered_open_init_unsigned.sig_hybrid_lc.clear();
        unordered_open_init.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &encode_canonical(&unordered_open_init_unsigned)?,
        )?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "open_channel_init@v1",
            unordered_open_init,
        )
        .await?;
        nonce += 1;

        let mut unordered_open_try = SessionChannelOpenTry {
            channel_id: unordered_channel_id,
            envelope_hash: unordered_envelope_hash,
            rc_attestation_evidence: vec![27, 28],
            rc_attestation_pub: vec![29, 30],
            rc_kem_ephemeral_pub_classical: vec![31, 32],
            rc_kem_ciphertext_pq: vec![33, 34],
            nonce_rc: [0x62u8; 32],
            sig_hybrid_rc: Vec::new(),
        };
        let mut unordered_open_try_unsigned = unordered_open_try.clone();
        unordered_open_try_unsigned.sig_hybrid_rc.clear();
        unordered_open_try.sig_hybrid_rc =
            sign_hybrid_payload(&rc_signer, &encode_canonical(&unordered_open_try_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "open_channel_try@v1",
            unordered_open_try,
        )
        .await?;
        nonce += 1;

        let mut unordered_open_ack = SessionChannelOpenAck {
            channel_id: unordered_channel_id,
            envelope_hash: unordered_envelope_hash,
            nonce_lc2: [0x63u8; 32],
            sig_hybrid_lc: Vec::new(),
        };
        let mut unordered_open_ack_unsigned = unordered_open_ack.clone();
        unordered_open_ack_unsigned.sig_hybrid_lc.clear();
        unordered_open_ack.sig_hybrid_lc =
            sign_hybrid_payload(&lc_signer, &encode_canonical(&unordered_open_ack_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "open_channel_ack@v1",
            unordered_open_ack,
        )
        .await?;
        nonce += 1;

        let mut unordered_open_confirm = SessionChannelOpenConfirm {
            channel_id: unordered_channel_id,
            envelope_hash: unordered_envelope_hash,
            nonce_rc2: [0x64u8; 32],
            sig_hybrid_rc: Vec::new(),
        };
        let mut unordered_open_confirm_unsigned = unordered_open_confirm.clone();
        unordered_open_confirm_unsigned.sig_hybrid_rc.clear();
        unordered_open_confirm.sig_hybrid_rc = sign_hybrid_payload(
            &rc_signer,
            &encode_canonical(&unordered_open_confirm_unsigned)?,
        )?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "open_channel_confirm@v1",
            unordered_open_confirm,
        )
        .await?;
        nonce += 1;

        let sign_lease = |mut lease: SessionLease| -> Result<SessionLease> {
            let mut unsigned = lease.clone();
            unsigned.sig_hybrid_lc.clear();
            lease.sig_hybrid_lc = sign_hybrid_payload(&lc_signer, &encode_canonical(&unsigned)?)?;
            Ok(lease)
        };

        let unordered_lease_high = sign_lease(SessionLease {
            lease_id: [0x65u8; 32],
            channel_id: unordered_channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0x66u8; 32],
            policy_hash: unordered_envelope.policy_hash,
            grant_id: [0x67u8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 4_220_000_000_000,
            revocation_epoch: 0,
            audience: [0x68u8; 32],
            nonce: [0x69u8; 32],
            counter: 600,
            issued_at_ms: 4_100_000_200_000,
            sig_hybrid_lc: Vec::new(),
        })?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "issue_session_lease@v1",
            unordered_lease_high,
        )
        .await?;
        nonce += 1;

        let unordered_lease_out_of_order = sign_lease(SessionLease {
            lease_id: [0x6au8; 32],
            channel_id: unordered_channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0x66u8; 32],
            policy_hash: unordered_envelope.policy_hash,
            grant_id: [0x6bu8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 4_220_000_000_000,
            revocation_epoch: 0,
            audience: [0x68u8; 32],
            nonce: [0x6cu8; 32],
            counter: 550,
            issued_at_ms: 4_100_000_200_100,
            sig_hybrid_lc: Vec::new(),
        })?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "issue_session_lease@v1",
            unordered_lease_out_of_order,
        )
        .await?;
        nonce += 1;

        let unordered_lease_counter_replay = sign_lease(SessionLease {
            lease_id: [0x6du8; 32],
            channel_id: unordered_channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0x66u8; 32],
            policy_hash: unordered_envelope.policy_hash,
            grant_id: [0x6eu8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 4_220_000_000_000,
            revocation_epoch: 0,
            audience: [0x68u8; 32],
            nonce: [0x6fu8; 32],
            counter: 550,
            issued_at_ms: 4_100_000_200_200,
            sig_hybrid_lc: Vec::new(),
        })?;
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "issue_session_lease@v1",
            unordered_lease_counter_replay,
        )
        .await;
        nonce += 1;

        let unordered_lease_outside_window = sign_lease(SessionLease {
            lease_id: [0x70u8; 32],
            channel_id: unordered_channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0x66u8; 32],
            policy_hash: unordered_envelope.policy_hash,
            grant_id: [0x71u8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 4_220_000_000_000,
            revocation_epoch: 0,
            audience: [0x68u8; 32],
            nonce: [0x72u8; 32],
            counter: 200,
            issued_at_ms: 4_100_000_200_300,
            sig_hybrid_lc: Vec::new(),
        })?;
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "issue_session_lease@v1",
            unordered_lease_outside_window,
        )
        .await;

        let unordered_high: SessionLease = load_wallet_value(
            rpc_addr,
            &lease_storage_key(&unordered_channel_id, &[0x65u8; 32]),
        )
        .await?;
        assert_eq!(unordered_high.counter, 600);

        let unordered_out_of_order: SessionLease = load_wallet_value(
            rpc_addr,
            &lease_storage_key(&unordered_channel_id, &[0x6au8; 32]),
        )
        .await?;
        assert_eq!(unordered_out_of_order.counter, 550);

        let counter_replay_lookup =
            service_key(&lease_storage_key(&unordered_channel_id, &[0x6du8; 32]));
        let outside_window_lookup =
            service_key(&lease_storage_key(&unordered_channel_id, &[0x70u8; 32]));
        assert!(query_state_key(rpc_addr, &counter_replay_lookup)
            .await?
            .is_none());
        assert!(query_state_key(rpc_addr, &outside_window_lookup)
            .await?
            .is_none());

        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    shutdown_result?;
    test_result
}

#[tokio::test]
async fn wallet_network_secret_injection_requires_attested_request_binding() -> Result<()> {
    let _guard = E2E_TEST_LOCK.lock().expect("lock");
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Admft")
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_network_user_policy())
        .build()
        .await?;

    let test_result: Result<()> = async {
        let node = cluster.validators[0].validator();
        let rpc_addr = &node.rpc_addr;
        let keypair = &node.keypair;
        let chain_id: ChainId = 1.into();
        let mut nonce = 0u64;

        wait_for_height(rpc_addr, 1, Duration::from_secs(30)).await?;

        let secret_record = VaultSecretRecord {
            secret_id: "gmail-refresh-prod".to_string(),
            alias: "gmail".to_string(),
            kind: SecretKind::AccessToken,
            ciphertext: vec![1, 2, 3, 4],
            metadata: BTreeMap::new(),
            created_at_ms: 4_100_000_000_000,
            rotated_at_ms: None,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "store_secret_record@v1",
            secret_record,
        )
        .await?;
        nonce += 1;

        let request_id = unique_id("wallet_network_secret_injection_request");
        let premature_grant = SecretInjectionGrant {
            request_id,
            secret_id: "gmail-refresh-prod".to_string(),
            envelope: SecretInjectionEnvelope {
                algorithm: "xchacha20poly1305".to_string(),
                ciphertext: vec![9, 9, 9],
                aad: vec![],
            },
            issued_at_ms: 4_100_000_000_100,
            expires_at_ms: 4_100_000_060_000,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "grant_secret_injection@v1",
            premature_grant,
        )
        .await?;
        nonce += 1;

        let premature_lookup = service_key(&injection_grant_storage_key(&request_id));
        let premature_grant_state = query_state_key(rpc_addr, &premature_lookup).await?;
        assert!(
            premature_grant_state.is_none(),
            "grant state was persisted before attested request was recorded"
        );

        let attestation_nonce = unique_id("wallet_network_secret_injection_attestation_nonce");
        let request_record = SecretInjectionRequestRecord {
            request: SecretInjectionRequest {
                request_id,
                session_id: unique_id("wallet_network_secret_injection_session"),
                agent_id: "mail-agent".to_string(),
                secret_alias: "gmail".to_string(),
                target: ioi_types::app::ActionTarget::NetFetch,
                attestation_nonce,
                requested_at_ms: 4_100_000_000_000,
            },
            attestation: GuardianAttestation {
                quote_hash: unique_id("wallet_network_secret_injection_quote"),
                measurement_hash: unique_id("wallet_network_secret_injection_measurement"),
                guardian_ephemeral_public_key: vec![7, 7, 7],
                nonce: attestation_nonce,
                issued_at_ms: 4_099_999_999_000,
                expires_at_ms: 4_200_000_000_000,
            },
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "record_secret_injection_request@v1",
            request_record,
        )
        .await?;
        nonce += 1;

        let stored_request: SecretInjectionRequest =
            load_wallet_value(rpc_addr, &injection_request_storage_key(&request_id)).await?;
        assert_eq!(stored_request.request_id, request_id);
        assert_eq!(stored_request.secret_alias, "gmail".to_string());

        let valid_grant = SecretInjectionGrant {
            request_id,
            secret_id: "gmail-refresh-prod".to_string(),
            envelope: SecretInjectionEnvelope {
                algorithm: "xchacha20poly1305".to_string(),
                ciphertext: vec![8, 8, 8, 8],
                aad: vec![1],
            },
            issued_at_ms: 4_100_000_000_200,
            expires_at_ms: 4_100_000_060_000,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "grant_secret_injection@v1",
            valid_grant,
        )
        .await?;

        let stored_grant: SecretInjectionGrant =
            load_wallet_value(rpc_addr, &injection_grant_storage_key(&request_id)).await?;
        assert_eq!(stored_grant.request_id, request_id);
        assert_eq!(stored_grant.secret_id, "gmail-refresh-prod".to_string());

        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    shutdown_result?;
    test_result
}

#[tokio::test]
async fn wallet_network_approval_token_consumption_via_real_callservice_txs() -> Result<()> {
    let _guard = E2E_TEST_LOCK.lock().expect("lock");
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Admft")
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_network_user_policy())
        .build()
        .await?;

    let test_result: Result<()> = async {
        let node = cluster.validators[0].validator();
        let rpc_addr = &node.rpc_addr;
        let keypair = &node.keypair;
        let chain_id: ChainId = 1.into();
        let mut nonce = 0u64;
        let approval_signer = new_hybrid_signer()?;
        let tx_signer_audience = account_id_from_key_material(
            SignatureSuite::ED25519,
            &keypair.public().encode_protobuf(),
        )?;

        wait_for_height(rpc_addr, 1, Duration::from_secs(30)).await?;

        let request_hash_1 = unique_id("wallet_network_approval_request_1");
        let session_id_1 = unique_id("wallet_network_approval_session_1");

        let interception_1 = WalletInterceptionContext {
            session_id: Some(session_id_1),
            request_hash: request_hash_1,
            target: ioi_types::app::ActionTarget::WebRetrieve,
            value_usd_micros: Some(42),
            reason: "manual approval required".to_string(),
            intercepted_at_ms: 4_100_000_000_000,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "record_interception@v1",
            interception_1,
        )
        .await?;
        nonce += 1;

        let approval_1 = sign_wallet_approval_decision(
            WalletApprovalDecision {
                interception: WalletInterceptionContext {
                    session_id: Some(session_id_1),
                    request_hash: request_hash_1,
                    target: ioi_types::app::ActionTarget::WebRetrieve,
                    value_usd_micros: Some(42),
                    reason: "manual approval required".to_string(),
                    intercepted_at_ms: 4_100_000_000_000,
                },
                decision: WalletApprovalDecisionKind::ApprovedByHuman,
                approval_token: Some(ApprovalToken {
                    schema_version: 2,
                    request_hash: request_hash_1,
                    audience: tx_signer_audience,
                    revocation_epoch: 0,
                    nonce: unique_id("wallet_network_approval_token_nonce_1"),
                    counter: 1,
                    scope: ApprovalScope {
                        expires_at: 4_200_000_000_000,
                        max_usages: Some(1),
                    },
                    visual_hash: None,
                    pii_action: None,
                    scoped_exception: None,
                    approver_sig: vec![],
                    approver_suite: SignatureSuite::HYBRID_ED25519_ML_DSA_44,
                }),
                surface: VaultSurface::Desktop,
                decided_at_ms: 4_100_000_000_500,
            },
            &approval_signer,
        )?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "record_approval@v1",
            approval_1,
        )
        .await?;
        nonce += 1;

        let stored_approval: WalletApprovalDecision =
            load_wallet_value(rpc_addr, &approval_storage_key(&request_hash_1)).await?;
        assert!(stored_approval.approval_token.is_some());

        let consume_1 = ConsumeApprovalTokenParams {
            request_hash: request_hash_1,
            consumed_at_ms: 4_100_000_001_000,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "consume_approval_token@v1",
            consume_1,
        )
        .await?;
        nonce += 1;

        let consumed_once: ApprovalConsumptionState =
            load_wallet_value(rpc_addr, &approval_consumption_storage_key(&request_hash_1)).await?;
        assert_eq!(consumed_once.max_usages, 1);
        assert_eq!(consumed_once.uses_consumed, 1);
        assert_eq!(consumed_once.remaining_usages, 0);
        assert_eq!(consumed_once.bound_audience, Some(tx_signer_audience));

        let consume_again = ConsumeApprovalTokenParams {
            request_hash: request_hash_1,
            consumed_at_ms: 4_100_000_002_000,
        };
        // NOTE: this tx may still be committed even if service execution fails, so assert via state.
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "consume_approval_token@v1",
            consume_again,
        )
        .await;
        nonce += 1;

        let consumed_after_reuse: ApprovalConsumptionState =
            load_wallet_value(rpc_addr, &approval_consumption_storage_key(&request_hash_1)).await?;
        assert_eq!(consumed_after_reuse.uses_consumed, 1);
        assert_eq!(consumed_after_reuse.remaining_usages, 0);

        let request_hash_2 = unique_id("wallet_network_approval_request_2");
        let interception_2 = WalletInterceptionContext {
            session_id: None,
            request_hash: request_hash_2,
            target: ioi_types::app::ActionTarget::NetFetch,
            value_usd_micros: None,
            reason: "manual approval required".to_string(),
            intercepted_at_ms: 4_100_000_003_000,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "record_interception@v1",
            interception_2,
        )
        .await?;
        nonce += 1;

        let approval_2 = sign_wallet_approval_decision(
            WalletApprovalDecision {
                interception: WalletInterceptionContext {
                    session_id: None,
                    request_hash: request_hash_2,
                    target: ioi_types::app::ActionTarget::NetFetch,
                    value_usd_micros: None,
                    reason: "manual approval required".to_string(),
                    intercepted_at_ms: 4_100_000_003_000,
                },
                decision: WalletApprovalDecisionKind::ApprovedByHuman,
                approval_token: Some(ApprovalToken {
                    schema_version: 2,
                    request_hash: request_hash_2,
                    audience: tx_signer_audience,
                    revocation_epoch: 0,
                    nonce: unique_id("wallet_network_approval_token_nonce_2"),
                    counter: 2,
                    scope: ApprovalScope {
                        expires_at: 4_200_000_000_000,
                        max_usages: Some(1),
                    },
                    visual_hash: None,
                    pii_action: None,
                    scoped_exception: None,
                    approver_sig: vec![],
                    approver_suite: SignatureSuite::HYBRID_ED25519_ML_DSA_44,
                }),
                surface: VaultSurface::Desktop,
                decided_at_ms: 4_100_000_003_500,
            },
            &approval_signer,
        )?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "record_approval@v1",
            approval_2,
        )
        .await?;
        nonce += 1;

        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "panic_stop@v1",
            BumpRevocationEpochParams {
                reason: "e2e revoke".to_string(),
            },
        )
        .await?;
        nonce += 1;

        let consume_revoked = ConsumeApprovalTokenParams {
            request_hash: request_hash_2,
            consumed_at_ms: 4_100_000_004_000,
        };
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "consume_approval_token@v1",
            consume_revoked,
        )
        .await;

        let consumed_revoked: ApprovalConsumptionState =
            load_wallet_value(rpc_addr, &approval_consumption_storage_key(&request_hash_2)).await?;
        assert_eq!(consumed_revoked.uses_consumed, 0);
        assert_eq!(consumed_revoked.remaining_usages, 1);
        assert!(consumed_revoked.last_consumed_at_ms.is_none());

        let epoch: u64 = load_wallet_value(rpc_addr, b"revocation_epoch").await?;
        assert!(epoch >= 1);

        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    shutdown_result?;
    test_result
}

#[tokio::test]
async fn wallet_network_bridge_records_firewall_interceptions_from_ingestion() -> Result<()> {
    let _guard = E2E_TEST_LOCK.lock().expect("lock");
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Admft")
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_network_user_policy())
        .with_service_policy("desktop_agent", desktop_agent_user_policy())
        .build()
        .await?;

    let test_result: Result<()> = async {
        let node = cluster.validators[0].validator();
        let rpc_addr = &node.rpc_addr;
        let keypair = &node.keypair;
        let chain_id: ChainId = 1.into();
        let nonce = 0u64;

        wait_for_height(rpc_addr, 1, Duration::from_secs(30)).await?;

        let start_params = StartAgentParams {
            session_id: [0x91u8; 32],
            goal: "Open calculator".to_string(),
            max_steps: 1,
            parent_session_id: None,
            initial_budget: 1_000_000,
            mode: AgentMode::Agent,
        };
        let tx = create_call_service_tx(
            keypair,
            "desktop_agent",
            "start@v1",
            start_params,
            nonce,
            chain_id,
        )?;
        let request_hash = tx.hash()?;

        submit_transaction_no_wait(rpc_addr, &tx).await?;

        let lookup_key = service_key(&interception_storage_key(&request_hash));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        let mut found: Option<WalletInterceptionContext> = None;
        while tokio::time::Instant::now() < deadline {
            if let Some(bytes) = query_state_key(rpc_addr, &lookup_key).await? {
                let decoded: WalletInterceptionContext =
                    codec::from_bytes_canonical(&bytes).map_err(|e| anyhow!(e))?;
                found = Some(decoded);
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        let interception = found.ok_or_else(|| {
            anyhow!(
                "wallet_network interception record not found for request hash {}",
                hex::encode(request_hash)
            )
        })?;
        assert_eq!(interception.request_hash, request_hash);
        assert_eq!(interception.session_id, None);
        assert_eq!(
            interception.target.canonical_label(),
            "start@v1".to_string()
        );
        assert_eq!(interception.reason, "manual approval required".to_string());

        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    shutdown_result?;
    test_result
}
