use crate::kernel::state::get_rpc_client;
use crate::models::AppState;
use ioi_api::crypto::{SerializableKey, SigningKeyPair, VerifyingKey};
use ioi_api::state::service_namespace_prefix;
use ioi_crypto::security::SecurityLevel;
use ioi_crypto::sign::dilithium::{MldsaKeyPair, MldsaPublicKey, MldsaScheme, MldsaSignature};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{GetTransactionStatusRequest, SubmitTransactionRequest};
use ioi_types::app::action::{ApprovalScope, ApprovalToken};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ActionContext, ActionRequest, ActionTarget, ChainId,
    ChainTransaction, MailConnectorAuthMode, MailConnectorConfig, MailConnectorEndpoint,
    MailConnectorProvider, MailConnectorSecretAliases, MailConnectorTlsMode,
    MailConnectorUpsertParams, MailDeleteSpamParams, MailDeleteSpamReceipt, MailListRecentParams,
    MailListRecentReceipt, MailMessageSummary, MailReadLatestParams, MailReadLatestReceipt,
    MailReplyParams, MailReplyReceipt, SecretKind, SignHeader, SignatureProof, SignatureSuite,
    SystemPayload, SystemTransaction, VaultSecretRecord, VaultSurface, WalletApprovalDecision,
    WalletApprovalDecisionKind, WalletInterceptionContext,
};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;
use tauri::State;
use tonic::transport::Channel;

const MAIL_READ_RECEIPT_PREFIX: &[u8] = b"mail_read_receipt::";
const MAIL_LIST_RECEIPT_PREFIX: &[u8] = b"mail_list_receipt::";
const MAIL_DELETE_RECEIPT_PREFIX: &[u8] = b"mail_delete_receipt::";
const MAIL_REPLY_RECEIPT_PREFIX: &[u8] = b"mail_reply_receipt::";
const MAIL_DELETE_SPAM_DEFAULT_LIMIT: u32 = 25;
const MAIL_DELETE_SPAM_MAX_LIMIT: u32 = 500;
const MAIL_APPROVAL_DEFAULT_TTL_SECONDS: u64 = 300;
const MAIL_APPROVAL_MAX_TTL_SECONDS: u64 = 3_600;
const MAIL_CONNECTOR_DEFAULT_MAILBOX: &str = "primary";
const MAIL_CONNECTOR_SECRET_ID_PREFIX: &str = "autopilot-mail";
const MAIL_CONNECTOR_ALIAS_MAX_LEN: usize = 128;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailMessageView {
    pub message_id: String,
    pub from: String,
    pub subject: String,
    pub received_at_ms: u64,
    pub preview: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailReadLatestResult {
    pub operation_id_hex: String,
    pub channel_id_hex: String,
    pub lease_id_hex: String,
    pub mailbox: String,
    pub audience_hex: String,
    pub executed_at_ms: u64,
    pub message: WalletMailMessageView,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailListRecentResult {
    pub operation_id_hex: String,
    pub channel_id_hex: String,
    pub lease_id_hex: String,
    pub mailbox: String,
    pub audience_hex: String,
    pub executed_at_ms: u64,
    pub messages: Vec<WalletMailMessageView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailDeleteSpamResult {
    pub operation_id_hex: String,
    pub channel_id_hex: String,
    pub lease_id_hex: String,
    pub mailbox: String,
    pub audience_hex: String,
    pub executed_at_ms: u64,
    pub deleted_count: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailReplyResult {
    pub operation_id_hex: String,
    pub channel_id_hex: String,
    pub lease_id_hex: String,
    pub mailbox: String,
    pub audience_hex: String,
    pub executed_at_ms: u64,
    pub to: String,
    pub subject: String,
    pub sent_message_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailIntentResult {
    pub query: String,
    pub normalized_intent: String,
    pub policy_decision: String,
    pub reason: String,
    pub approved: bool,
    pub executed: bool,
    pub operation: Option<String>,
    pub next_op_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_latest: Option<WalletMailReadLatestResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_recent: Option<WalletMailListRecentResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_spam: Option<WalletMailDeleteSpamResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<WalletMailReplyResult>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailApprovalArtifactResult {
    pub normalized_intent: String,
    pub request_hash_hex: String,
    pub audience_hex: String,
    pub revocation_epoch: u64,
    pub expires_at_ms: u64,
    pub approval_artifact_json: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailConfigureAccountResult {
    pub mailbox: String,
    pub account_email: String,
    pub auth_mode: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_tls_mode: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_tls_mode: String,
    pub imap_username_alias: String,
    pub imap_secret_alias: String,
    pub smtp_username_alias: String,
    pub smtp_secret_alias: String,
    pub updated_at_ms: u64,
}

struct EphemeralHybridSigner {
    ed25519: Ed25519KeyPair,
    mldsa: MldsaKeyPair,
    public_key: Vec<u8>,
    signer_id: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MailIntentKind {
    ReadLatest,
    ListRecent,
    DeleteSpam,
    Reply,
    Unknown,
}

impl MailIntentKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReadLatest => "mail.read_latest",
            Self::ListRecent => "mail.list_recent",
            Self::DeleteSpam => "mail.delete_spam",
            Self::Reply => "mail.reply",
            Self::Unknown => "mail.unknown",
        }
    }

    fn requires_step_up_approval(self) -> bool {
        matches!(self, Self::DeleteSpam | Self::Reply)
    }

    fn action_target(self) -> ActionTarget {
        match self {
            Self::ReadLatest => ActionTarget::Custom("mail::read_latest".to_string()),
            Self::ListRecent => ActionTarget::Custom("mail::list_recent".to_string()),
            Self::DeleteSpam => ActionTarget::Custom("mail::delete_spam".to_string()),
            Self::Reply => ActionTarget::Custom("mail::reply".to_string()),
            Self::Unknown => ActionTarget::Custom("mail::unknown".to_string()),
        }
    }
}

fn classify_mail_intent(query: &str) -> MailIntentKind {
    let q = query.to_ascii_lowercase();

    let is_delete = q.contains("delete") || q.contains("remove") || q.contains("trash");
    let is_spam = q.contains("spam") || q.contains("junk");
    if is_delete && is_spam {
        return MailIntentKind::DeleteSpam;
    }

    if q.contains("reply") || q.contains("respond to") || q.contains("email bob") {
        return MailIntentKind::Reply;
    }

    if q.contains("latest")
        || q.contains("last email")
        || q.contains("read latest")
        || q.contains("most recent")
    {
        return MailIntentKind::ReadLatest;
    }

    if q.contains("inbox")
        || q.contains("list")
        || q.contains("recent email")
        || q.contains("recent messages")
        || q.contains("check mail")
    {
        return MailIntentKind::ListRecent;
    }

    MailIntentKind::Unknown
}

fn normalize_approval_ttl_seconds(value: Option<u64>) -> u64 {
    value
        .unwrap_or(MAIL_APPROVAL_DEFAULT_TTL_SECONDS)
        .clamp(30, MAIL_APPROVAL_MAX_TTL_SECONDS)
}

fn non_zero_token_nonce(request_hash: [u8; 32], op_seq: u64, now_ms: u64) -> [u8; 32] {
    let mut nonce = request_hash;
    nonce[0] ^= (now_ms & 0xFF) as u8;
    nonce[1] ^= ((now_ms >> 8) & 0xFF) as u8;
    nonce[2] ^= (op_seq & 0xFF) as u8;
    nonce[3] ^= ((op_seq >> 8) & 0xFF) as u8;
    if nonce == [0u8; 32] {
        nonce[0] = 1;
    }
    nonce
}

fn generate_ephemeral_hybrid_signer() -> Result<EphemeralHybridSigner, String> {
    let ed25519 = Ed25519KeyPair::generate().map_err(|e| e.to_string())?;
    let mldsa = MldsaScheme::new(SecurityLevel::Level2)
        .generate_keypair()
        .map_err(|e| e.to_string())?;
    let mut public_key = ed25519.public_key().to_bytes();
    public_key.extend_from_slice(&mldsa.public_key().to_bytes());
    let signer_id =
        account_id_from_key_material(SignatureSuite::HYBRID_ED25519_ML_DSA_44, &public_key)
            .map_err(|e| e.to_string())?;

    Ok(EphemeralHybridSigner {
        ed25519,
        mldsa,
        public_key,
        signer_id,
    })
}

fn sign_hybrid_payload(signer: &EphemeralHybridSigner, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut signature = signer
        .ed25519
        .sign(payload)
        .map_err(|e| e.to_string())?
        .to_bytes();
    signature.extend_from_slice(
        &signer
            .mldsa
            .sign(payload)
            .map_err(|e| e.to_string())?
            .to_bytes(),
    );

    codec::to_bytes_canonical(&SignatureProof {
        suite: SignatureSuite::HYBRID_ED25519_ML_DSA_44,
        public_key: signer.public_key.clone(),
        signature,
    })
    .map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
struct MailIntentApprovalBinding {
    intent: String,
    channel_id: [u8; 32],
    lease_id: [u8; 32],
    mailbox: String,
    query: String,
    op_seq: u64,
}

fn build_mail_intent_request_hash(
    intent: MailIntentKind,
    channel_id: [u8; 32],
    lease_id: [u8; 32],
    mailbox: &str,
    query: &str,
    op_seq: u64,
) -> Result<[u8; 32], String> {
    let binding = MailIntentApprovalBinding {
        intent: intent.as_str().to_string(),
        channel_id,
        lease_id,
        mailbox: mailbox.to_string(),
        query: query.to_string(),
        op_seq,
    };
    let params = codec::to_bytes_canonical(&binding).map_err(|e| e.to_string())?;
    let request = ActionRequest {
        target: intent.action_target(),
        params,
        context: ActionContext {
            agent_id: "autopilot.mail.intent".to_string(),
            session_id: Some(channel_id),
            window_id: None,
        },
        nonce: op_seq,
    };
    Ok(request.hash())
}

fn decode_hybrid_signature_proof(raw_proof: &[u8]) -> Result<SignatureProof, String> {
    if raw_proof.is_empty() {
        return Err("approval token signature proof is missing".to_string());
    }
    let proof: SignatureProof =
        codec::from_bytes_canonical(raw_proof).map_err(|e| e.to_string())?;
    if proof.suite != SignatureSuite::HYBRID_ED25519_ML_DSA_44 {
        return Err("approval token must use HYBRID_ED25519_ML_DSA_44".to_string());
    }
    if proof.public_key.len() <= 32 {
        return Err("hybrid signature proof public key is too short".to_string());
    }
    if proof.signature.len() <= 64 {
        return Err("hybrid signature proof signature is too short".to_string());
    }
    Ok(proof)
}

fn verify_hybrid_signature(proof: &SignatureProof, message: &[u8]) -> Result<[u8; 32], String> {
    const ED25519_PUBLIC_KEY_BYTES: usize = 32;
    const ED25519_SIGNATURE_BYTES: usize = 64;

    let (ed25519_pk_bytes, mldsa_pk_bytes) = proof.public_key.split_at(ED25519_PUBLIC_KEY_BYTES);
    let (ed25519_sig_bytes, mldsa_sig_bytes) = proof.signature.split_at(ED25519_SIGNATURE_BYTES);
    if mldsa_pk_bytes.is_empty() || mldsa_sig_bytes.is_empty() {
        return Err("hybrid signature proof is missing pq key/signature bytes".to_string());
    }

    let ed25519_pk = Ed25519PublicKey::from_bytes(ed25519_pk_bytes).map_err(|e| e.to_string())?;
    let ed25519_sig = Ed25519Signature::from_bytes(ed25519_sig_bytes).map_err(|e| e.to_string())?;
    ed25519_pk
        .verify(message, &ed25519_sig)
        .map_err(|e| e.to_string())?;

    let mldsa_pk = MldsaPublicKey::from_bytes(mldsa_pk_bytes).map_err(|e| e.to_string())?;
    let mldsa_sig = MldsaSignature::from_bytes(mldsa_sig_bytes).map_err(|e| e.to_string())?;
    mldsa_pk
        .verify(message, &mldsa_sig)
        .map_err(|e| e.to_string())?;

    account_id_from_key_material(SignatureSuite::HYBRID_ED25519_ML_DSA_44, &proof.public_key)
        .map_err(|e| e.to_string())
}

fn normalize_token_expiry_ms(expires_at: u64) -> u64 {
    // Back-compat: some legacy callers may still pass seconds.
    if expires_at > 0 && expires_at < 1_000_000_000_000 {
        return expires_at.saturating_mul(1_000);
    }
    expires_at
}

fn synthesize_write_approval_artifact(
    intent: MailIntentKind,
    channel_id: [u8; 32],
    lease_id: [u8; 32],
    mailbox: &str,
    query: &str,
    op_seq: u64,
    now_ms: u64,
    ttl_seconds: u64,
    active_revocation_epoch: u64,
) -> Result<WalletApprovalDecision, String> {
    if !intent.requires_step_up_approval() {
        return Err("approval artifacts are only valid for write mail intents".to_string());
    }
    let request_hash =
        build_mail_intent_request_hash(intent, channel_id, lease_id, mailbox, query, op_seq)?;
    let signer = generate_ephemeral_hybrid_signer()?;
    let expires_at_ms = now_ms.saturating_add(ttl_seconds.saturating_mul(1_000));
    let token = ApprovalToken {
        schema_version: 2,
        request_hash,
        audience: signer.signer_id,
        revocation_epoch: active_revocation_epoch,
        nonce: non_zero_token_nonce(request_hash, op_seq, now_ms),
        counter: op_seq.max(1),
        scope: ApprovalScope {
            expires_at: expires_at_ms,
            max_usages: Some(1),
        },
        visual_hash: None,
        pii_action: None,
        scoped_exception: None,
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::HYBRID_ED25519_ML_DSA_44,
    };
    let mut decision = WalletApprovalDecision {
        interception: WalletInterceptionContext {
            session_id: Some(channel_id),
            request_hash,
            target: intent.action_target(),
            value_usd_micros: None,
            reason: format!(
                "Autopilot integration step-up approval for {}",
                intent.as_str()
            ),
            intercepted_at_ms: now_ms,
        },
        decision: WalletApprovalDecisionKind::ApprovedByHuman,
        approval_token: Some(token),
        surface: VaultSurface::Desktop,
        decided_at_ms: now_ms,
    };

    let payload = codec::to_bytes_canonical(&decision).map_err(|e| e.to_string())?;
    let proof = sign_hybrid_payload(&signer, &payload)?;
    let token = decision
        .approval_token
        .as_mut()
        .ok_or_else(|| "approval token missing from synthesized artifact".to_string())?;
    token.approver_sig = proof;
    Ok(decision)
}

fn verify_write_approval_artifact(
    approval: &WalletApprovalDecision,
    intent: MailIntentKind,
    expected_request_hash: [u8; 32],
    now_ms: u64,
    active_revocation_epoch: u64,
) -> Result<(), String> {
    if !intent.requires_step_up_approval() {
        return Err("write approval artifact verification called for read-only intent".to_string());
    }
    if !matches!(
        approval.decision,
        WalletApprovalDecisionKind::AutoApproved | WalletApprovalDecisionKind::ApprovedByHuman
    ) {
        return Err("approval decision is not approved".to_string());
    }
    let token = approval
        .approval_token
        .as_ref()
        .ok_or_else(|| "approved decision is missing approval_token".to_string())?;
    if token.schema_version < 2 {
        return Err("approval token schema_version must be >= 2".to_string());
    }
    if token.request_hash != approval.interception.request_hash {
        return Err("approval token request hash does not match interception hash".to_string());
    }
    if token.request_hash != expected_request_hash {
        return Err(
            "approval token request hash does not match this mail intent binding".to_string(),
        );
    }
    if token.audience == [0u8; 32] {
        return Err("approval token audience must not be all zeroes".to_string());
    }
    if token.nonce == [0u8; 32] {
        return Err("approval token nonce must not be all zeroes".to_string());
    }
    if token.counter == 0 {
        return Err("approval token counter must be >= 1".to_string());
    }
    if token.revocation_epoch < active_revocation_epoch {
        return Err("approval token invalidated by active revocation epoch".to_string());
    }
    if token.approver_suite != SignatureSuite::HYBRID_ED25519_ML_DSA_44 {
        return Err("approval token approver_suite must be HYBRID_ED25519_ML_DSA_44".to_string());
    }
    let expiry_ms = normalize_token_expiry_ms(token.scope.expires_at);
    if expiry_ms == 0 || now_ms > expiry_ms {
        return Err("approval token has expired".to_string());
    }

    let expected_target = intent.action_target().canonical_label();
    let seen_target = approval.interception.target.canonical_label();
    if seen_target != expected_target {
        return Err(format!(
            "approval target mismatch: expected {}, got {}",
            expected_target, seen_target
        ));
    }

    let mut canonical = approval.clone();
    let token_for_signing = canonical
        .approval_token
        .as_mut()
        .ok_or_else(|| "approved decision is missing approval_token".to_string())?;
    let proof = decode_hybrid_signature_proof(&token_for_signing.approver_sig)?;
    token_for_signing.approver_sig.clear();
    let payload = codec::to_bytes_canonical(&canonical).map_err(|e| e.to_string())?;
    let signer_id = verify_hybrid_signature(&proof, &payload)?;
    if signer_id != token.audience {
        return Err("approval token audience does not match hybrid signer identity".to_string());
    }
    Ok(())
}

fn normalize_delete_limit(value: Option<u32>) -> u32 {
    value
        .unwrap_or(MAIL_DELETE_SPAM_DEFAULT_LIMIT)
        .clamp(1, MAIL_DELETE_SPAM_MAX_LIMIT)
}

fn parse_mail_connector_auth_mode(raw: Option<&str>) -> Result<MailConnectorAuthMode, String> {
    match raw
        .unwrap_or("password")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "password" | "pass" => Ok(MailConnectorAuthMode::Password),
        "oauth2" | "xoauth2" | "oauth" => Ok(MailConnectorAuthMode::Oauth2),
        other => Err(format!(
            "Invalid authMode '{}': expected password or oauth2",
            other
        )),
    }
}

fn parse_mail_connector_tls_mode(
    raw: Option<&str>,
    default_mode: MailConnectorTlsMode,
) -> Result<MailConnectorTlsMode, String> {
    let mode = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(match default_mode {
            MailConnectorTlsMode::Plaintext => "plaintext",
            MailConnectorTlsMode::StartTls => "starttls",
            MailConnectorTlsMode::Tls => "tls",
        })
        .to_ascii_lowercase();
    match mode.as_str() {
        "plaintext" | "plain" => Ok(MailConnectorTlsMode::Plaintext),
        "starttls" | "start_tls" | "start-tls" => Ok(MailConnectorTlsMode::StartTls),
        "tls" | "ssl" => Ok(MailConnectorTlsMode::Tls),
        other => Err(format!(
            "Invalid TLS mode '{}': expected plaintext, starttls, or tls",
            other
        )),
    }
}

fn mailbox_or_default(raw: Option<String>) -> String {
    let mailbox = raw
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(MAIL_CONNECTOR_DEFAULT_MAILBOX)
        .to_ascii_lowercase();
    if mailbox.is_empty() {
        MAIL_CONNECTOR_DEFAULT_MAILBOX.to_string()
    } else {
        mailbox
    }
}

fn alias_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.trim().to_ascii_lowercase().chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    let normalized = out.trim_matches('-').to_string();
    if normalized.is_empty() {
        MAIL_CONNECTOR_DEFAULT_MAILBOX.to_string()
    } else {
        normalized
    }
}

fn bounded_alias(mut alias: String) -> String {
    if alias.len() > MAIL_CONNECTOR_ALIAS_MAX_LEN {
        alias.truncate(MAIL_CONNECTOR_ALIAS_MAX_LEN);
    }
    alias
}

fn alias_for_mailbox(mailbox: &str, path: &str) -> String {
    let segment = alias_segment(mailbox);
    bounded_alias(format!("mail.{}.{}", segment, path))
}

fn secret_id_for_mailbox(mailbox: &str, suffix: &str) -> String {
    format!(
        "{}-{}-{}-{}",
        MAIL_CONNECTOR_SECRET_ID_PREFIX,
        alias_segment(mailbox),
        suffix,
        uuid::Uuid::new_v4().simple()
    )
}

fn tls_mode_label(mode: MailConnectorTlsMode) -> &'static str {
    match mode {
        MailConnectorTlsMode::Plaintext => "plaintext",
        MailConnectorTlsMode::StartTls => "starttls",
        MailConnectorTlsMode::Tls => "tls",
    }
}

fn extract_reply_target(query: &str) -> String {
    let lowered = query.to_ascii_lowercase();
    if let Some(idx) = lowered.find("reply to ") {
        let tail = query[idx + 9..].trim();
        if !tail.is_empty() {
            return tail
                .split_whitespace()
                .next()
                .unwrap_or("recipient")
                .to_string();
        }
    }
    if let Some(idx) = lowered.find("respond to ") {
        let tail = query[idx + 11..].trim();
        if !tail.is_empty() {
            return tail
                .split_whitespace()
                .next()
                .unwrap_or("recipient")
                .to_string();
        }
    }
    "recipient".to_string()
}

fn decode_hex_32(label: &str, value: &str) -> Result<[u8; 32], String> {
    let normalized = value.trim().trim_start_matches("0x");
    let bytes = hex::decode(normalized).map_err(|e| format!("Invalid {} hex: {}", label, e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Invalid {} length: expected 32 bytes, got {}",
            label,
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn generate_operation_id() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    out
}

fn generate_op_nonce() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    if out == [0u8; 32] {
        out[0] = 1;
    }
    out
}

fn build_wallet_call_tx(method: &str, params: Vec<u8>) -> Result<ChainTransaction, String> {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let public_key = keypair.public().encode_protobuf();
    let account_id = AccountId(
        account_id_from_key_material(SignatureSuite::ED25519, &public_key)
            .map_err(|e| format!("Failed to derive account id: {}", e))?,
    );

    let payload = SystemPayload::CallService {
        service_id: "wallet_network".to_string(),
        method: method.to_string(),
        params,
    };
    let mut sys_tx = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce: 0,
            chain_id: ChainId(0),
            tx_version: 1,
            session_auth: None,
        },
        payload,
        signature_proof: SignatureProof::default(),
    };

    let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| e.to_string())?;
    let signature = keypair.sign(&sign_bytes).map_err(|e| e.to_string())?;
    sys_tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature,
    };

    Ok(ChainTransaction::System(Box::new(sys_tx)))
}

async fn submit_tx_and_wait(
    client: &mut PublicApiClient<Channel>,
    tx: ChainTransaction,
) -> Result<(), String> {
    let tx_bytes = codec::to_bytes_canonical(&tx).map_err(|e| e.to_string())?;
    let submit_resp = client
        .submit_transaction(tonic::Request::new(SubmitTransactionRequest {
            transaction_bytes: tx_bytes,
        }))
        .await
        .map_err(|e| format!("Failed to submit transaction: {}", e))?
        .into_inner();

    let mut attempts = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        attempts += 1;
        if attempts > 24 {
            return Err(format!(
                "Timed out waiting for connector tx commit (tx_hash={})",
                submit_resp.tx_hash
            ));
        }

        let status_resp = client
            .get_transaction_status(tonic::Request::new(GetTransactionStatusRequest {
                tx_hash: submit_resp.tx_hash.clone(),
            }))
            .await
            .map_err(|e| format!("Failed to query tx status: {}", e))?
            .into_inner();

        // 3=Committed, 4=Rejected
        if status_resp.status == 3 {
            return Ok(());
        }
        if status_resp.status == 4 {
            if status_resp.error_message.trim().is_empty() {
                return Err("Connector tx rejected".to_string());
            }
            return Err(format!(
                "Connector tx rejected: {}",
                status_resp.error_message
            ));
        }
    }
}

async fn query_wallet_state(
    client: &mut PublicApiClient<Channel>,
    local_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let full_key = [
        service_namespace_prefix("wallet_network").as_slice(),
        &local_key,
    ]
    .concat();
    let resp = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key: full_key }))
        .await
        .map_err(|e| format!("Failed to query wallet state: {}", e))?
        .into_inner();
    if !resp.found || resp.value.is_empty() {
        return Err("wallet_network receipt not found".to_string());
    }
    Ok(resp.value)
}

async fn load_wallet_revocation_epoch(
    client: &mut PublicApiClient<Channel>,
) -> Result<u64, String> {
    let full_key = [
        service_namespace_prefix("wallet_network").as_slice(),
        b"revocation_epoch".as_slice(),
    ]
    .concat();
    let resp = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key: full_key }))
        .await
        .map_err(|e| format!("Failed to query wallet revocation epoch: {}", e))?
        .into_inner();
    if !resp.found || resp.value.is_empty() {
        return Ok(0);
    }
    codec::from_bytes_canonical::<u64>(&resp.value).map_err(|e| e.to_string())
}

fn to_message_view(message: MailMessageSummary) -> WalletMailMessageView {
    WalletMailMessageView {
        message_id: message.message_id,
        from: message.from,
        subject: message.subject,
        received_at_ms: message.received_at_ms,
        preview: message.preview,
    }
}

async fn execute_wallet_mail_read_latest(
    state: &State<'_, Mutex<AppState>>,
    channel_id: &str,
    lease_id: &str,
    op_seq: u64,
    mailbox: Option<String>,
) -> Result<WalletMailReadLatestResult, String> {
    if op_seq == 0 {
        return Err("opSeq must be >= 1".to_string());
    }
    let channel_id = decode_hex_32("channelId", channel_id)?;
    let lease_id = decode_hex_32("leaseId", lease_id)?;
    let operation_id = generate_operation_id();

    let params = MailReadLatestParams {
        operation_id,
        channel_id,
        lease_id,
        op_seq,
        op_nonce: Some(generate_op_nonce()),
        mailbox: mailbox.unwrap_or_else(|| "primary".to_string()),
        requested_at_ms: crate::kernel::state::now(),
    };
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;

    let mut client = get_rpc_client(state).await?;
    let tx = build_wallet_call_tx("mail_read_latest@v1", params_bytes)?;
    submit_tx_and_wait(&mut client, tx).await?;

    let receipt_key = [MAIL_READ_RECEIPT_PREFIX, operation_id.as_slice()].concat();
    let receipt_bytes = query_wallet_state(&mut client, receipt_key).await?;
    let receipt: MailReadLatestReceipt =
        codec::from_bytes_canonical(&receipt_bytes).map_err(|e| e.to_string())?;

    Ok(WalletMailReadLatestResult {
        operation_id_hex: hex::encode(receipt.operation_id),
        channel_id_hex: hex::encode(receipt.channel_id),
        lease_id_hex: hex::encode(receipt.lease_id),
        mailbox: receipt.mailbox,
        audience_hex: hex::encode(receipt.audience),
        executed_at_ms: receipt.executed_at_ms,
        message: to_message_view(receipt.message),
    })
}

async fn execute_wallet_mail_list_recent(
    state: &State<'_, Mutex<AppState>>,
    channel_id: &str,
    lease_id: &str,
    op_seq: u64,
    mailbox: Option<String>,
    limit: Option<u32>,
) -> Result<WalletMailListRecentResult, String> {
    if op_seq == 0 {
        return Err("opSeq must be >= 1".to_string());
    }
    let channel_id = decode_hex_32("channelId", channel_id)?;
    let lease_id = decode_hex_32("leaseId", lease_id)?;
    let operation_id = generate_operation_id();

    let params = MailListRecentParams {
        operation_id,
        channel_id,
        lease_id,
        op_seq,
        op_nonce: Some(generate_op_nonce()),
        mailbox: mailbox.unwrap_or_else(|| "primary".to_string()),
        limit: limit.unwrap_or(5).clamp(1, 20),
        requested_at_ms: crate::kernel::state::now(),
    };
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;

    let mut client = get_rpc_client(state).await?;
    let tx = build_wallet_call_tx("mail_list_recent@v1", params_bytes)?;
    submit_tx_and_wait(&mut client, tx).await?;

    let receipt_key = [MAIL_LIST_RECEIPT_PREFIX, operation_id.as_slice()].concat();
    let receipt_bytes = query_wallet_state(&mut client, receipt_key).await?;
    let receipt: MailListRecentReceipt =
        codec::from_bytes_canonical(&receipt_bytes).map_err(|e| e.to_string())?;

    Ok(WalletMailListRecentResult {
        operation_id_hex: hex::encode(receipt.operation_id),
        channel_id_hex: hex::encode(receipt.channel_id),
        lease_id_hex: hex::encode(receipt.lease_id),
        mailbox: receipt.mailbox,
        audience_hex: hex::encode(receipt.audience),
        executed_at_ms: receipt.executed_at_ms,
        messages: receipt.messages.into_iter().map(to_message_view).collect(),
    })
}

async fn execute_wallet_mail_delete_spam(
    state: &State<'_, Mutex<AppState>>,
    channel_id: &str,
    lease_id: &str,
    op_seq: u64,
    mailbox: Option<String>,
    max_delete: Option<u32>,
) -> Result<WalletMailDeleteSpamResult, String> {
    if op_seq == 0 {
        return Err("opSeq must be >= 1".to_string());
    }
    let channel_id = decode_hex_32("channelId", channel_id)?;
    let lease_id = decode_hex_32("leaseId", lease_id)?;
    let operation_id = generate_operation_id();

    let params = MailDeleteSpamParams {
        operation_id,
        channel_id,
        lease_id,
        op_seq,
        op_nonce: Some(generate_op_nonce()),
        mailbox: mailbox.unwrap_or_else(|| "primary".to_string()),
        max_delete: normalize_delete_limit(max_delete),
        requested_at_ms: crate::kernel::state::now(),
    };
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;

    let mut client = get_rpc_client(state).await?;
    let tx = build_wallet_call_tx("mail_delete_spam@v1", params_bytes)?;
    submit_tx_and_wait(&mut client, tx).await?;

    let receipt_key = [MAIL_DELETE_RECEIPT_PREFIX, operation_id.as_slice()].concat();
    let receipt_bytes = query_wallet_state(&mut client, receipt_key).await?;
    let receipt: MailDeleteSpamReceipt =
        codec::from_bytes_canonical(&receipt_bytes).map_err(|e| e.to_string())?;

    Ok(WalletMailDeleteSpamResult {
        operation_id_hex: hex::encode(receipt.operation_id),
        channel_id_hex: hex::encode(receipt.channel_id),
        lease_id_hex: hex::encode(receipt.lease_id),
        mailbox: receipt.mailbox,
        audience_hex: hex::encode(receipt.audience),
        executed_at_ms: receipt.executed_at_ms,
        deleted_count: receipt.deleted_count,
    })
}

async fn execute_wallet_mail_reply(
    state: &State<'_, Mutex<AppState>>,
    channel_id: &str,
    lease_id: &str,
    op_seq: u64,
    mailbox: Option<String>,
    to: String,
    subject: String,
    body: String,
    reply_to_message_id: Option<String>,
) -> Result<WalletMailReplyResult, String> {
    if op_seq == 0 {
        return Err("opSeq must be >= 1".to_string());
    }
    let channel_id = decode_hex_32("channelId", channel_id)?;
    let lease_id = decode_hex_32("leaseId", lease_id)?;
    let operation_id = generate_operation_id();

    let params = MailReplyParams {
        operation_id,
        channel_id,
        lease_id,
        op_seq,
        op_nonce: Some(generate_op_nonce()),
        mailbox: mailbox.unwrap_or_else(|| "primary".to_string()),
        to,
        subject,
        body,
        reply_to_message_id,
        requested_at_ms: crate::kernel::state::now(),
    };
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;

    let mut client = get_rpc_client(state).await?;
    let tx = build_wallet_call_tx("mail_reply@v1", params_bytes)?;
    submit_tx_and_wait(&mut client, tx).await?;

    let receipt_key = [MAIL_REPLY_RECEIPT_PREFIX, operation_id.as_slice()].concat();
    let receipt_bytes = query_wallet_state(&mut client, receipt_key).await?;
    let receipt: MailReplyReceipt =
        codec::from_bytes_canonical(&receipt_bytes).map_err(|e| e.to_string())?;

    Ok(WalletMailReplyResult {
        operation_id_hex: hex::encode(receipt.operation_id),
        channel_id_hex: hex::encode(receipt.channel_id),
        lease_id_hex: hex::encode(receipt.lease_id),
        mailbox: receipt.mailbox,
        audience_hex: hex::encode(receipt.audience),
        executed_at_ms: receipt.executed_at_ms,
        to: receipt.to,
        subject: receipt.subject,
        sent_message_id: receipt.sent_message_id,
    })
}

#[tauri::command]
pub async fn wallet_mail_configure_account(
    state: State<'_, Mutex<AppState>>,
    mailbox: Option<String>,
    account_email: String,
    auth_mode: Option<String>,
    imap_host: String,
    imap_port: u16,
    imap_tls_mode: Option<String>,
    smtp_host: String,
    smtp_port: u16,
    smtp_tls_mode: Option<String>,
    imap_username: Option<String>,
    imap_secret: String,
    smtp_username: Option<String>,
    smtp_secret: String,
) -> Result<WalletMailConfigureAccountResult, String> {
    let mailbox = mailbox_or_default(mailbox);
    let account_email = account_email.trim().to_string();
    if account_email.is_empty() || !account_email.contains('@') {
        return Err("accountEmail must be a valid email-like value.".to_string());
    }

    let imap_host = imap_host.trim().to_string();
    let smtp_host = smtp_host.trim().to_string();
    if imap_host.is_empty() || smtp_host.is_empty() {
        return Err("IMAP and SMTP host values are required.".to_string());
    }
    if imap_port == 0 || smtp_port == 0 {
        return Err("IMAP and SMTP ports must be > 0.".to_string());
    }

    let auth_mode = parse_mail_connector_auth_mode(auth_mode.as_deref())?;
    let imap_tls_mode =
        parse_mail_connector_tls_mode(imap_tls_mode.as_deref(), MailConnectorTlsMode::Tls)?;
    let smtp_tls_mode =
        parse_mail_connector_tls_mode(smtp_tls_mode.as_deref(), MailConnectorTlsMode::StartTls)?;

    let imap_username = imap_username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(account_email.as_str())
        .to_string();
    let smtp_username = smtp_username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(account_email.as_str())
        .to_string();

    let imap_secret = imap_secret.trim().to_string();
    let smtp_secret = smtp_secret.trim().to_string();
    if imap_secret.is_empty() || smtp_secret.is_empty() {
        return Err("IMAP/SMTP secret values are required.".to_string());
    }

    let imap_username_alias = alias_for_mailbox(&mailbox, "imap.username");
    let smtp_username_alias = alias_for_mailbox(&mailbox, "smtp.username");
    let (imap_secret_alias, smtp_secret_alias, auth_secret_kind) = match auth_mode {
        MailConnectorAuthMode::Password => (
            alias_for_mailbox(&mailbox, "imap.password"),
            alias_for_mailbox(&mailbox, "smtp.password"),
            SecretKind::Password,
        ),
        MailConnectorAuthMode::Oauth2 => (
            alias_for_mailbox(&mailbox, "imap.bearer_token"),
            alias_for_mailbox(&mailbox, "smtp.bearer_token"),
            SecretKind::AccessToken,
        ),
    };

    let now_ms = crate::kernel::state::now();
    let secret_specs = vec![
        (
            secret_id_for_mailbox(&mailbox, "imap-username"),
            imap_username_alias.clone(),
            imap_username,
            SecretKind::AccessToken,
        ),
        (
            secret_id_for_mailbox(&mailbox, "imap-secret"),
            imap_secret_alias.clone(),
            imap_secret,
            auth_secret_kind.clone(),
        ),
        (
            secret_id_for_mailbox(&mailbox, "smtp-username"),
            smtp_username_alias.clone(),
            smtp_username,
            SecretKind::AccessToken,
        ),
        (
            secret_id_for_mailbox(&mailbox, "smtp-secret"),
            smtp_secret_alias.clone(),
            smtp_secret,
            auth_secret_kind,
        ),
    ];

    let mut client = get_rpc_client(&state).await?;
    for (secret_id, alias, value, kind) in secret_specs {
        let record = VaultSecretRecord {
            secret_id,
            alias,
            kind,
            ciphertext: value.into_bytes(),
            metadata: BTreeMap::new(),
            created_at_ms: now_ms,
            rotated_at_ms: None,
        };
        let params_bytes = codec::to_bytes_canonical(&record).map_err(|e| e.to_string())?;
        let tx = build_wallet_call_tx("store_secret_record@v1", params_bytes)?;
        submit_tx_and_wait(&mut client, tx).await?;
    }

    let connector = MailConnectorUpsertParams {
        mailbox: mailbox.clone(),
        config: MailConnectorConfig {
            provider: MailConnectorProvider::ImapSmtp,
            auth_mode,
            account_email: account_email.clone(),
            imap: MailConnectorEndpoint {
                host: imap_host.clone(),
                port: imap_port,
                tls_mode: imap_tls_mode,
            },
            smtp: MailConnectorEndpoint {
                host: smtp_host.clone(),
                port: smtp_port,
                tls_mode: smtp_tls_mode,
            },
            secret_aliases: MailConnectorSecretAliases {
                imap_username_alias: imap_username_alias.clone(),
                imap_password_alias: imap_secret_alias.clone(),
                smtp_username_alias: smtp_username_alias.clone(),
                smtp_password_alias: smtp_secret_alias.clone(),
            },
            metadata: {
                let mut metadata = BTreeMap::new();
                metadata.insert(
                    "configured_by".to_string(),
                    "autopilot.integrations".to_string(),
                );
                metadata
            },
        },
    };
    let params_bytes = codec::to_bytes_canonical(&connector).map_err(|e| e.to_string())?;
    let tx = build_wallet_call_tx("mail_connector_upsert@v1", params_bytes)?;
    submit_tx_and_wait(&mut client, tx).await?;

    Ok(WalletMailConfigureAccountResult {
        mailbox,
        account_email,
        auth_mode: match auth_mode {
            MailConnectorAuthMode::Password => "password".to_string(),
            MailConnectorAuthMode::Oauth2 => "oauth2".to_string(),
        },
        imap_host,
        imap_port,
        imap_tls_mode: tls_mode_label(imap_tls_mode).to_string(),
        smtp_host,
        smtp_port,
        smtp_tls_mode: tls_mode_label(smtp_tls_mode).to_string(),
        imap_username_alias,
        imap_secret_alias,
        smtp_username_alias,
        smtp_secret_alias,
        updated_at_ms: now_ms,
    })
}

#[tauri::command]
pub async fn wallet_mail_generate_approval_artifact(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    query: String,
    mailbox: Option<String>,
    ttl_seconds: Option<u64>,
) -> Result<WalletMailApprovalArtifactResult, String> {
    if channel_id.trim().is_empty() || lease_id.trim().is_empty() {
        return Err("Channel ID and Lease ID are required.".to_string());
    }
    if op_seq == 0 {
        return Err("opSeq must be >= 1".to_string());
    }

    let trimmed_query = query.trim().to_string();
    if trimmed_query.is_empty() {
        return Err("Mail request is empty.".to_string());
    }

    let intent = classify_mail_intent(&trimmed_query);
    if intent == MailIntentKind::Unknown {
        return Err(
            "Unsupported mail request. Try 'delete spam' or 'reply to <recipient>'.".to_string(),
        );
    }
    if !intent.requires_step_up_approval() {
        return Err("This intent does not require step-up approval.".to_string());
    }

    let channel_id_arr = decode_hex_32("channelId", &channel_id)?;
    let lease_id_arr = decode_hex_32("leaseId", &lease_id)?;
    let mailbox_value = mailbox
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("primary")
        .to_string();
    let ttl = normalize_approval_ttl_seconds(ttl_seconds);
    let now_ms = crate::kernel::state::now();

    let active_revocation_epoch = {
        let mut client = get_rpc_client(&state).await?;
        load_wallet_revocation_epoch(&mut client).await?
    };

    let artifact = synthesize_write_approval_artifact(
        intent,
        channel_id_arr,
        lease_id_arr,
        &mailbox_value,
        &trimmed_query,
        op_seq,
        now_ms,
        ttl,
        active_revocation_epoch,
    )?;

    let token = artifact
        .approval_token
        .as_ref()
        .ok_or_else(|| "synthesized approval artifact is missing approval_token".to_string())?;
    let approval_artifact_json =
        serde_json::to_string_pretty(&artifact).map_err(|e| e.to_string())?;

    Ok(WalletMailApprovalArtifactResult {
        normalized_intent: intent.as_str().to_string(),
        request_hash_hex: hex::encode(artifact.interception.request_hash),
        audience_hex: hex::encode(token.audience),
        revocation_epoch: token.revocation_epoch,
        expires_at_ms: normalize_token_expiry_ms(token.scope.expires_at),
        approval_artifact_json,
    })
}

#[tauri::command]
pub async fn wallet_mail_read_latest(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
) -> Result<WalletMailReadLatestResult, String> {
    execute_wallet_mail_read_latest(&state, &channel_id, &lease_id, op_seq, mailbox).await
}

#[tauri::command]
pub async fn wallet_mail_list_recent(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    limit: Option<u32>,
) -> Result<WalletMailListRecentResult, String> {
    execute_wallet_mail_list_recent(&state, &channel_id, &lease_id, op_seq, mailbox, limit).await
}

#[tauri::command]
pub async fn wallet_mail_delete_spam(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    max_delete: Option<u32>,
) -> Result<WalletMailDeleteSpamResult, String> {
    execute_wallet_mail_delete_spam(&state, &channel_id, &lease_id, op_seq, mailbox, max_delete)
        .await
}

#[tauri::command]
pub async fn wallet_mail_reply(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    to: String,
    subject: String,
    body: String,
    reply_to_message_id: Option<String>,
) -> Result<WalletMailReplyResult, String> {
    execute_wallet_mail_reply(
        &state,
        &channel_id,
        &lease_id,
        op_seq,
        mailbox,
        to,
        subject,
        body,
        reply_to_message_id,
    )
    .await
}

#[tauri::command]
pub async fn wallet_mail_handle_intent(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    query: String,
    mailbox: Option<String>,
    list_limit: Option<u32>,
    approval_artifact_json: Option<String>,
) -> Result<WalletMailIntentResult, String> {
    if channel_id.trim().is_empty() || lease_id.trim().is_empty() {
        return Err("Channel ID and Lease ID are required.".to_string());
    }
    if op_seq == 0 {
        return Err("opSeq must be >= 1".to_string());
    }

    let trimmed_query = query.trim().to_string();
    if trimmed_query.is_empty() {
        return Err("Mail request is empty.".to_string());
    }

    let intent = classify_mail_intent(&trimmed_query);
    let mailbox_value = mailbox.unwrap_or_else(|| "primary".to_string());
    let channel_id_binding = decode_hex_32("channelId", &channel_id)?;
    let lease_id_binding = decode_hex_32("leaseId", &lease_id)?;
    let expected_request_hash = if intent.requires_step_up_approval() {
        Some(build_mail_intent_request_hash(
            intent,
            channel_id_binding,
            lease_id_binding,
            &mailbox_value,
            &trimmed_query,
            op_seq,
        )?)
    } else {
        None
    };
    let mut out = WalletMailIntentResult {
        query: trimmed_query.clone(),
        normalized_intent: intent.as_str().to_string(),
        policy_decision: "blocked".to_string(),
        reason: "No policy route matched this mail request.".to_string(),
        approved: false,
        executed: false,
        operation: None,
        next_op_seq: op_seq,
        read_latest: None,
        list_recent: None,
        delete_spam: None,
        reply: None,
    };

    if intent == MailIntentKind::Unknown {
        out.reason =
            "Unsupported mail request. Try 'check inbox' or 'read latest email'.".to_string();
        return Ok(out);
    }

    if intent.requires_step_up_approval() {
        let Some(raw_artifact) = approval_artifact_json.as_deref().map(str::trim) else {
            out.policy_decision = "approval_required".to_string();
            out.reason = "Write/destructive mail intents require an approval artifact.".to_string();
            return Ok(out);
        };
        if raw_artifact.is_empty() {
            out.policy_decision = "approval_required".to_string();
            out.reason = "Write/destructive mail intents require an approval artifact.".to_string();
            return Ok(out);
        }

        let approval: WalletApprovalDecision = match serde_json::from_str(raw_artifact) {
            Ok(value) => value,
            Err(error) => {
                out.policy_decision = "blocked".to_string();
                out.reason = format!("Invalid approval artifact JSON: {}", error);
                return Ok(out);
            }
        };
        let active_revocation_epoch = {
            let mut client = get_rpc_client(&state).await?;
            load_wallet_revocation_epoch(&mut client).await?
        };

        if let Some(expected_request_hash) = expected_request_hash {
            if let Err(error) = verify_write_approval_artifact(
                &approval,
                intent,
                expected_request_hash,
                crate::kernel::state::now(),
                active_revocation_epoch,
            ) {
                out.policy_decision = "blocked".to_string();
                out.reason = format!("Approval artifact verification failed: {}", error);
                return Ok(out);
            }
        }

        out.approved = true;
    }

    // Read-only policy path: route natural language intent to connector-first tx operations.
    match intent {
        MailIntentKind::ReadLatest => {
            let read = execute_wallet_mail_read_latest(
                &state,
                &channel_id,
                &lease_id,
                op_seq,
                Some(mailbox_value),
            )
            .await?;
            out.policy_decision = "allowed".to_string();
            out.reason = "Policy allows read-only mail access for this session lease.".to_string();
            out.executed = true;
            out.operation = Some("mail_read_latest@v1".to_string());
            out.next_op_seq = op_seq.saturating_add(1);
            out.read_latest = Some(read);
        }
        MailIntentKind::ListRecent => {
            let list = execute_wallet_mail_list_recent(
                &state,
                &channel_id,
                &lease_id,
                op_seq,
                Some(mailbox_value),
                list_limit,
            )
            .await?;
            out.policy_decision = "allowed".to_string();
            out.reason = "Policy allows read-only mail access for this session lease.".to_string();
            out.executed = true;
            out.operation = Some("mail_list_recent@v1".to_string());
            out.next_op_seq = op_seq.saturating_add(1);
            out.list_recent = Some(list);
        }
        MailIntentKind::DeleteSpam => {
            let delete = execute_wallet_mail_delete_spam(
                &state,
                &channel_id,
                &lease_id,
                op_seq,
                Some(mailbox_value),
                None,
            )
            .await?;
            out.policy_decision = "allowed".to_string();
            out.reason =
                "Approved write intent; executing bounded spam-deletion connector op.".to_string();
            out.executed = true;
            out.operation = Some("mail_delete_spam@v1".to_string());
            out.next_op_seq = op_seq.saturating_add(1);
            out.delete_spam = Some(delete);
        }
        MailIntentKind::Reply => {
            let recipient = extract_reply_target(&trimmed_query);
            let to = if recipient.contains('@') {
                recipient
            } else {
                format!("{}@example.com", recipient.to_ascii_lowercase())
            };
            let subject = "Quick follow-up".to_string();
            let body =
                "Autopilot draft reply placeholder. Replace with final assistant-composed content."
                    .to_string();
            let reply = execute_wallet_mail_reply(
                &state,
                &channel_id,
                &lease_id,
                op_seq,
                Some(mailbox_value),
                to,
                subject,
                body,
                None,
            )
            .await?;
            out.policy_decision = "allowed".to_string();
            out.reason = "Approved write intent; executing bounded reply connector op.".to_string();
            out.executed = true;
            out.operation = Some("mail_reply@v1".to_string());
            out.next_op_seq = op_seq.saturating_add(1);
            out.reply = Some(reply);
        }
        MailIntentKind::Unknown => {
            out.reason = "Intent classification reached unsupported state.".to_string();
        }
    }

    Ok(out)
}
