use super::constants::{MAIL_APPROVAL_DEFAULT_TTL_SECONDS, MAIL_APPROVAL_MAX_TTL_SECONDS};
use super::intent::MailIntentKind;
use ioi_api::crypto::{SerializableKey, SigningKeyPair, VerifyingKey};
use ioi_crypto::security::SecurityLevel;
use ioi_crypto::sign::dilithium::{MldsaKeyPair, MldsaPublicKey, MldsaScheme, MldsaSignature};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};
use ioi_types::app::{
    account_id_from_key_material, ActionContext, ActionRequest, ApprovalScope, ApprovalToken,
    SignatureProof, SignatureSuite, VaultSurface, WalletApprovalDecision,
    WalletApprovalDecisionKind, WalletInterceptionContext,
};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

struct EphemeralHybridSigner {
    ed25519: Ed25519KeyPair,
    mldsa: MldsaKeyPair,
    public_key: Vec<u8>,
    signer_id: [u8; 32],
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

pub(crate) fn normalize_approval_ttl_seconds(value: Option<u64>) -> u64 {
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

pub(crate) fn build_mail_intent_request_hash(
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

pub(crate) fn normalize_token_expiry_ms(expires_at: u64) -> u64 {
    // Back-compat: some legacy callers may still pass seconds.
    if expires_at > 0 && expires_at < 1_000_000_000_000 {
        return expires_at.saturating_mul(1_000);
    }
    expires_at
}

pub(crate) fn synthesize_write_approval_artifact(
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

pub(crate) fn verify_write_approval_artifact(
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
