#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::{anyhow, Context, Result};
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
use ioi_services::agentic::runtime::{AgentMode, StartAgentParams};
use ioi_services::wallet_network::{
    ApprovalConsumptionState, BumpRevocationEpochParams, ConsumeApprovalGrantParams,
    IssueSessionGrantParams, LeaseConsumptionState, RegisterApprovalAuthorityParams,
    SessionDelegationState,
};
use ioi_types::{
    app::{
        account_id_from_key_material,
        action::{ApprovalAuthority, ApprovalGrant},
        AccountId, ChainId, ChainTransaction, GuardianAttestation, MailConnectorAuthMode,
        MailConnectorConfig, MailConnectorEndpoint, MailConnectorProvider,
        MailConnectorSecretAliases, MailConnectorTlsMode, MailConnectorUpsertParams,
        MailDeleteSpamParams, MailDeleteSpamReceipt, MailListRecentParams, MailListRecentReceipt,
        MailReadLatestParams, MailReadLatestReceipt, MailReplyParams, MailReplyReceipt,
        SecretInjectionEnvelope, SecretInjectionGrant, SecretInjectionRequest,
        SecretInjectionRequestRecord, SecretKind, SessionChannelClose, SessionChannelCloseReason,
        SessionChannelDelegationRules, SessionChannelEnvelope, SessionChannelKeyState,
        SessionChannelMode, SessionChannelOpenAck, SessionChannelOpenConfirm,
        SessionChannelOpenInit, SessionChannelOpenTry, SessionChannelOrdering,
        SessionChannelRecord, SessionChannelState, SessionGrant, SessionLease, SessionLeaseMode,
        SessionReceiptCommit, SessionReceiptCommitDirection, SessionScope, SignHeader,
        SignatureProof, SignatureSuite, SystemPayload, SystemTransaction, VaultSecretRecord,
        VaultSurface, WalletApprovalDecision, WalletApprovalDecisionKind,
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

#[derive(Clone)]
struct ApprovalSigner {
    keypair: Ed25519KeyPair,
    authority: ApprovalAuthority,
}

fn new_approval_signer() -> Result<ApprovalSigner> {
    let keypair = Ed25519KeyPair::generate().map_err(|e| anyhow!(e.to_string()))?;
    let public_key = keypair.public_key().to_bytes();
    let authority_id = account_id_from_key_material(SignatureSuite::ED25519, &public_key)?;
    Ok(ApprovalSigner {
        keypair,
        authority: ApprovalAuthority {
            schema_version: 1,
            authority_id,
            public_key,
            signature_suite: SignatureSuite::ED25519,
            expires_at: 4_500_000_000_000,
            revoked: false,
            scope_allowlist: vec!["wallet_network.approval".to_string()],
        },
    })
}

fn signed_wallet_approval_grant(
    signer: &ApprovalSigner,
    request_hash: [u8; 32],
    policy_hash: [u8; 32],
    audience: [u8; 32],
    nonce: [u8; 32],
    counter: u64,
    max_usages: Option<u32>,
    expires_at: u64,
) -> Result<ApprovalGrant> {
    let mut grant = ApprovalGrant {
        schema_version: 1,
        authority_id: signer.authority.authority_id,
        request_hash,
        policy_hash,
        audience,
        nonce,
        counter,
        expires_at,
        max_usages,
        window_id: None,
        pii_action: None,
        scoped_exception: None,
        review_request_hash: None,
        approver_public_key: signer.authority.public_key.clone(),
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    };
    let sign_bytes = grant
        .signing_bytes()
        .map_err(|e| anyhow!("approval grant signing failed: {}", e))?;
    grant.approver_sig = signer
        .keypair
        .sign(&sign_bytes)
        .map_err(|e| anyhow!(e.to_string()))?
        .to_bytes();
    Ok(grant)
}

async fn register_wallet_approval_authority(
    cluster: &TestCluster,
    rpc_addr: &str,
    keypair: &Keypair,
    chain_id: ChainId,
    nonce: u64,
    signer: &ApprovalSigner,
) -> Result<()> {
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "register_approval_authority@v1",
        RegisterApprovalAuthorityParams {
            authority: signer.authority.clone(),
        },
    )
    .await?;
    let _ = cluster;
    Ok(())
}

#[derive(Clone)]
struct WalletMailRuntimeConfig {
    auth_mode: MailConnectorAuthMode,
    account_email: String,
    imap_host: String,
    imap_port: u16,
    imap_tls_mode: MailConnectorTlsMode,
    smtp_host: String,
    smtp_port: u16,
    smtp_tls_mode: MailConnectorTlsMode,
    imap_username: String,
    imap_secret: String,
    smtp_username: String,
    smtp_secret: String,
}

fn load_workspace_mail_env_if_present() {
    fn find_workspace_file(file_name: &str) -> Option<std::path::PathBuf> {
        let mut cursor = std::env::current_dir().ok();
        while let Some(path) = cursor.clone() {
            let candidate = path.join(file_name);
            if candidate.is_file() {
                return Some(candidate);
            }
            cursor = path.parent().map(|parent| parent.to_path_buf());
        }
        None
    }

    let Some(path) = find_workspace_file(".env") else {
        return;
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return;
    };

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || std::env::var(key).is_ok() {
            continue;
        }
        let value = value.trim().trim_matches('"').trim_matches('\'');
        if !value.is_empty() {
            std::env::set_var(key, value);
        }
    }
}

fn nonempty_env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn required_env_value(key: &str) -> Result<String> {
    nonempty_env_value(key).ok_or_else(|| anyhow!("missing required environment variable '{key}'"))
}

fn parse_u16_env(key: &str) -> Result<u16> {
    let raw = required_env_value(key)?;
    let value = raw
        .parse::<u16>()
        .map_err(|e| anyhow!("invalid {key} '{raw}': {e}"))?;
    if value == 0 {
        return Err(anyhow!("invalid {key}: value must be > 0"));
    }
    Ok(value)
}

fn parse_mail_auth_mode_env() -> Result<MailConnectorAuthMode> {
    let raw = nonempty_env_value("MAIL_E2E_AUTH_MODE");
    if let Some(value) = raw.as_deref() {
        return match value.to_ascii_lowercase().as_str() {
            "password" | "pass" => Ok(MailConnectorAuthMode::Password),
            "oauth2" | "oauth" | "xoauth2" => Ok(MailConnectorAuthMode::Oauth2),
            _ => Err(anyhow!(
                "invalid MAIL_E2E_AUTH_MODE '{}': expected password or oauth2",
                value
            )),
        };
    }

    let has_password = nonempty_env_value("MAIL_E2E_IMAP_PASSWORD").is_some()
        || nonempty_env_value("MAIL_E2E_SMTP_PASSWORD").is_some();
    let has_bearer = nonempty_env_value("MAIL_E2E_IMAP_BEARER_TOKEN").is_some()
        || nonempty_env_value("MAIL_E2E_SMTP_BEARER_TOKEN").is_some();
    if has_bearer && !has_password {
        Ok(MailConnectorAuthMode::Oauth2)
    } else {
        Ok(MailConnectorAuthMode::Password)
    }
}

fn parse_tls_mode_env(key: &str, default: MailConnectorTlsMode) -> Result<MailConnectorTlsMode> {
    let Some(raw) = nonempty_env_value(key) else {
        return Ok(default);
    };
    match raw.to_ascii_lowercase().as_str() {
        "plaintext" | "plain" => Ok(MailConnectorTlsMode::Plaintext),
        "starttls" | "start_tls" | "start-tls" => Ok(MailConnectorTlsMode::StartTls),
        "tls" | "ssl" => Ok(MailConnectorTlsMode::Tls),
        _ => Err(anyhow!(
            "invalid {key} '{}': expected plaintext, starttls, or tls",
            raw
        )),
    }
}

fn wallet_mail_runtime_env_configured() -> bool {
    [
        "MAIL_E2E_ACCOUNT_EMAIL",
        "MAIL_E2E_IMAP_HOST",
        "MAIL_E2E_SMTP_HOST",
        "MAIL_E2E_IMAP_USERNAME",
        "MAIL_E2E_SMTP_USERNAME",
        "MAIL_E2E_IMAP_PASSWORD",
        "MAIL_E2E_SMTP_PASSWORD",
        "MAIL_E2E_IMAP_BEARER_TOKEN",
        "MAIL_E2E_SMTP_BEARER_TOKEN",
    ]
    .into_iter()
    .any(|key| nonempty_env_value(key).is_some())
}

fn maybe_wallet_mail_runtime_config() -> Result<Option<WalletMailRuntimeConfig>> {
    load_workspace_mail_env_if_present();
    if !wallet_mail_runtime_env_configured() {
        return Ok(None);
    }

    let auth_mode = parse_mail_auth_mode_env()?;
    let (imap_secret, smtp_secret) = match auth_mode {
        MailConnectorAuthMode::Password => (
            required_env_value("MAIL_E2E_IMAP_PASSWORD")?,
            required_env_value("MAIL_E2E_SMTP_PASSWORD")?,
        ),
        MailConnectorAuthMode::Oauth2 => (
            required_env_value("MAIL_E2E_IMAP_BEARER_TOKEN")?,
            required_env_value("MAIL_E2E_SMTP_BEARER_TOKEN")?,
        ),
    };

    Ok(Some(WalletMailRuntimeConfig {
        auth_mode,
        account_email: required_env_value("MAIL_E2E_ACCOUNT_EMAIL")?.to_ascii_lowercase(),
        imap_host: required_env_value("MAIL_E2E_IMAP_HOST")?.to_ascii_lowercase(),
        imap_port: parse_u16_env("MAIL_E2E_IMAP_PORT")?,
        imap_tls_mode: parse_tls_mode_env("MAIL_E2E_IMAP_TLS_MODE", MailConnectorTlsMode::Tls)?,
        smtp_host: required_env_value("MAIL_E2E_SMTP_HOST")?.to_ascii_lowercase(),
        smtp_port: parse_u16_env("MAIL_E2E_SMTP_PORT")?,
        smtp_tls_mode: parse_tls_mode_env(
            "MAIL_E2E_SMTP_TLS_MODE",
            MailConnectorTlsMode::StartTls,
        )?,
        imap_username: required_env_value("MAIL_E2E_IMAP_USERNAME")?,
        imap_secret,
        smtp_username: required_env_value("MAIL_E2E_SMTP_USERNAME")?,
        smtp_secret,
    }))
}

fn wallet_mail_secret_kind(auth_mode: MailConnectorAuthMode) -> SecretKind {
    match auth_mode {
        MailConnectorAuthMode::Password => SecretKind::Password,
        MailConnectorAuthMode::Oauth2 => SecretKind::AccessToken,
    }
}

async fn store_wallet_secret_record(
    rpc_addr: &str,
    keypair: &Keypair,
    chain_id: ChainId,
    nonce: &mut u64,
    secret_id: &str,
    alias: &str,
    kind: SecretKind,
    value: &str,
) -> Result<()> {
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        *nonce,
        "store_secret_record@v1",
        VaultSecretRecord {
            secret_id: secret_id.to_string(),
            alias: alias.to_string(),
            kind,
            ciphertext: value.as_bytes().to_vec(),
            metadata: BTreeMap::new(),
            created_at_ms: 4_100_000_000_000,
            rotated_at_ms: None,
        },
    )
    .await?;
    *nonce += 1;
    Ok(())
}

fn build_wallet_mail_connector_config(
    runtime: &WalletMailRuntimeConfig,
    imap_username_alias: &str,
    imap_secret_alias: &str,
    smtp_username_alias: &str,
    smtp_secret_alias: &str,
) -> MailConnectorConfig {
    MailConnectorConfig {
        provider: MailConnectorProvider::ImapSmtp,
        auth_mode: runtime.auth_mode,
        account_email: runtime.account_email.clone(),
        sender_display_name: None,
        imap: MailConnectorEndpoint {
            host: runtime.imap_host.clone(),
            port: runtime.imap_port,
            tls_mode: runtime.imap_tls_mode,
        },
        smtp: MailConnectorEndpoint {
            host: runtime.smtp_host.clone(),
            port: runtime.smtp_port,
            tls_mode: runtime.smtp_tls_mode,
        },
        secret_aliases: MailConnectorSecretAliases {
            imap_username_alias: imap_username_alias.to_string(),
            imap_password_alias: imap_secret_alias.to_string(),
            smtp_username_alias: smtp_username_alias.to_string(),
            smtp_password_alias: smtp_secret_alias.to_string(),
        },
        metadata: BTreeMap::new(),
    }
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
        "register_approval_authority@v1",
        "revoke_approval_authority@v1",
        "consume_approval_grant@v1",
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
    submit_transaction(rpc_addr, &tx)
        .await
        .with_context(|| format!("wallet_network {method} nonce {nonce}"))
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
    [b"mail_read_evidence::".as_slice(), operation_id.as_slice()].concat()
}

fn mail_list_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [b"mail_list_evidence::".as_slice(), operation_id.as_slice()].concat()
}

fn mail_delete_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [
        b"mail_delete_evidence::".as_slice(),
        operation_id.as_slice(),
    ]
    .concat()
}

fn mail_reply_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [b"mail_reply_evidence::".as_slice(), operation_id.as_slice()].concat()
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

mod approval_grant_consumption;
mod bridge_interceptions;
mod lifecycle;
mod mail_delete_spam;
mod mail_reply_draft_send_contract;
mod mail_reply_with_approval;
mod secret_injection_binding;
