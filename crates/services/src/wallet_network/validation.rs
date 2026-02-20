// Path: crates/services/src/wallet_network/validation.rs

use ioi_api::crypto::{SerializableKey, VerifyingKey};
use ioi_crypto::sign::dilithium::{MldsaPublicKey, MldsaSignature};
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
use ioi_types::app::wallet_network::{
    GuardianAttestation, SecretInjectionRequest, SessionChannelClose, SessionChannelOpenAck,
    SessionChannelOpenConfirm, SessionChannelOpenInit, SessionChannelOpenTry, SessionLease,
    SessionReceiptCommit, SessionScope, WalletApprovalDecision, WalletApprovalDecisionKind,
};
use ioi_types::app::{account_id_from_key_material, ActionTarget, SignatureProof, SignatureSuite};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use parity_scale_codec::Encode;
use std::collections::{BTreeMap, HashSet};

pub(super) fn validate_narrowing(
    parent: &SessionScope,
    child: &SessionScope,
) -> Result<(), TransactionError> {
    if child.expires_at_ms > parent.expires_at_ms {
        return Err(TransactionError::Invalid(
            "child session expiry must be <= parent expiry".to_string(),
        ));
    }
    if let Some(parent_max_actions) = parent.max_actions {
        match child.max_actions {
            Some(child_max_actions) if child_max_actions <= parent_max_actions => {}
            _ => {
                return Err(TransactionError::Invalid(
                    "child max_actions must be <= parent max_actions".to_string(),
                ));
            }
        }
    }
    if let Some(parent_max_spend) = parent.max_spend_usd_micros {
        match child.max_spend_usd_micros {
            Some(child_max_spend) if child_max_spend <= parent_max_spend => {}
            _ => {
                return Err(TransactionError::Invalid(
                    "child max_spend_usd_micros must be <= parent max_spend_usd_micros".to_string(),
                ));
            }
        }
    }
    if !is_target_subset(&child.action_allowlist, &parent.action_allowlist) {
        return Err(TransactionError::Invalid(
            "child action allowlist must be a subset of parent allowlist".to_string(),
        ));
    }
    if !is_string_subset(&child.domain_allowlist, &parent.domain_allowlist) {
        return Err(TransactionError::Invalid(
            "child domain allowlist must be a subset of parent allowlist".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_secret_injection_request(
    request: &SecretInjectionRequest,
) -> Result<(), TransactionError> {
    if request.request_id == [0u8; 32] || request.session_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "secret injection request requires request_id and session_id".to_string(),
        ));
    }
    if request.agent_id.trim().is_empty() || request.secret_alias.trim().is_empty() {
        return Err(TransactionError::Invalid(
            "secret injection request requires non-empty agent_id and secret_alias".to_string(),
        ));
    }
    if request.attestation_nonce == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "secret injection request requires non-zero attestation nonce".to_string(),
        ));
    }
    if request.requested_at_ms == 0 {
        return Err(TransactionError::Invalid(
            "secret injection request requires requested_at_ms".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_guardian_attestation(
    attestation: &GuardianAttestation,
    now_ms: u64,
) -> Result<(), TransactionError> {
    if attestation.quote_hash == [0u8; 32] || attestation.measurement_hash == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "guardian attestation quote/measurement hashes must not be all zeroes".to_string(),
        ));
    }
    if attestation.guardian_ephemeral_public_key.is_empty() {
        return Err(TransactionError::Invalid(
            "guardian attestation requires guardian_ephemeral_public_key".to_string(),
        ));
    }
    if attestation.nonce == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "guardian attestation nonce must not be all zeroes".to_string(),
        ));
    }
    if attestation.issued_at_ms == 0 || attestation.expires_at_ms <= attestation.issued_at_ms {
        return Err(TransactionError::Invalid(
            "guardian attestation validity window is invalid".to_string(),
        ));
    }
    if now_ms > attestation.expires_at_ms {
        return Err(TransactionError::Invalid(
            "guardian attestation has expired".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_approval(approval: &WalletApprovalDecision) -> Result<(), TransactionError> {
    let token_present = approval.approval_token.is_some();
    match approval.decision {
        WalletApprovalDecisionKind::AutoApproved | WalletApprovalDecisionKind::ApprovedByHuman => {
            if !token_present {
                return Err(TransactionError::Invalid(
                    "approved decisions require an approval_token".to_string(),
                ));
            }
        }
        WalletApprovalDecisionKind::DeniedByHuman
        | WalletApprovalDecisionKind::RequiresHumanReview => {
            if token_present {
                return Err(TransactionError::Invalid(
                    "denied/review decisions must not include approval_token".to_string(),
                ));
            }
        }
    }

    if let Some(token) = &approval.approval_token {
        if token.request_hash != approval.interception.request_hash {
            return Err(TransactionError::Invalid(
                "approval_token request hash mismatch".to_string(),
            ));
        }
        if token.schema_version < 2 {
            return Err(TransactionError::Invalid(
                "approval_token schema_version must be >= 2".to_string(),
            ));
        }
        if token.audience == [0u8; 32] {
            return Err(TransactionError::Invalid(
                "approval_token audience must not be all zeroes".to_string(),
            ));
        }
        if token.nonce == [0u8; 32] {
            return Err(TransactionError::Invalid(
                "approval_token nonce must not be all zeroes".to_string(),
            ));
        }
        if token.counter == 0 {
            return Err(TransactionError::Invalid(
                "approval_token counter must be >= 1".to_string(),
            ));
        }
        if token.scope.expires_at == 0 {
            return Err(TransactionError::Invalid(
                "approval_token expiry must be non-zero".to_string(),
            ));
        }
        if let Some(max_usages) = token.scope.max_usages {
            if max_usages == 0 {
                return Err(TransactionError::Invalid(
                    "approval_token max_usages must be >= 1".to_string(),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_approval_token_hybrid_signature(
    approval: &WalletApprovalDecision,
) -> Result<[u8; 32], TransactionError> {
    if !matches!(
        approval.decision,
        WalletApprovalDecisionKind::AutoApproved | WalletApprovalDecisionKind::ApprovedByHuman
    ) {
        return Err(TransactionError::Invalid(
            "hybrid approval signature validation requires an approved decision".to_string(),
        ));
    }

    let mut canonical = approval.clone();
    let token = canonical.approval_token.as_mut().ok_or_else(|| {
        TransactionError::Invalid("approved decision missing approval_token".to_string())
    })?;
    if token.approver_suite != SignatureSuite::HYBRID_ED25519_ML_DSA_44 {
        return Err(TransactionError::Invalid(
            "approval_token approver_suite must be HYBRID_ED25519_ML_DSA_44".to_string(),
        ));
    }
    let proof = decode_hybrid_signature_proof(&token.approver_sig, "approval_token.approver_sig")?;
    token.approver_sig.clear();
    let payload = codec::to_bytes_canonical(&canonical)?;
    verify_hybrid_signature(&proof, &payload, "record_approval")
}

pub(super) fn validate_channel_open_init(
    open: &SessionChannelOpenInit,
    now_ms: u64,
) -> Result<(), TransactionError> {
    if open.envelope.channel_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "channel_id must not be all zeroes".to_string(),
        ));
    }
    if open.envelope.lc_id == [0u8; 32] || open.envelope.rc_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "lc_id and rc_id must not be all zeroes".to_string(),
        ));
    }
    if open.envelope.policy_hash == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "policy_hash must not be all zeroes".to_string(),
        ));
    }
    if open.envelope.root_grant_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "root_grant_id must not be all zeroes".to_string(),
        ));
    }
    if open.envelope.capability_set.is_empty() {
        return Err(TransactionError::Invalid(
            "channel capability_set must not be empty".to_string(),
        ));
    }
    if open.envelope.expires_at_ms <= now_ms {
        return Err(TransactionError::Invalid(
            "channel expiry must be in the future".to_string(),
        ));
    }
    if open.nonce_lc == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "nonce_lc must not be all zeroes".to_string(),
        ));
    }
    if open.lc_kem_ephemeral_pub_classical.is_empty() || open.lc_kem_ephemeral_pub_pq.is_empty() {
        return Err(TransactionError::Invalid(
            "open_init requires both classical and pq KEM ephemeral keys".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_channel_open_init_hybrid_signature(
    open: &SessionChannelOpenInit,
) -> Result<(), TransactionError> {
    let proof = decode_hybrid_signature_proof(&open.sig_hybrid_lc, "sig_hybrid_lc")?;
    let payload = canonical_bytes_without_signature(open, |msg| msg.sig_hybrid_lc.clear())?;
    let signer_id = verify_hybrid_signature(&proof, &payload, "open_channel_init")?;
    if signer_id != open.envelope.lc_id {
        return Err(TransactionError::Invalid(
            "open_channel_init signer does not match envelope.lc_id".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_channel_open_try_hybrid_signature(
    open_try: &SessionChannelOpenTry,
    expected_rc_id: [u8; 32],
) -> Result<(), TransactionError> {
    let proof = decode_hybrid_signature_proof(&open_try.sig_hybrid_rc, "sig_hybrid_rc")?;
    let payload = canonical_bytes_without_signature(open_try, |msg| msg.sig_hybrid_rc.clear())?;
    let signer_id = verify_hybrid_signature(&proof, &payload, "open_channel_try")?;
    if signer_id != expected_rc_id {
        return Err(TransactionError::Invalid(
            "open_channel_try signer does not match envelope.rc_id".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_channel_open_ack_hybrid_signature(
    open_ack: &SessionChannelOpenAck,
    expected_lc_id: [u8; 32],
) -> Result<(), TransactionError> {
    let proof = decode_hybrid_signature_proof(&open_ack.sig_hybrid_lc, "sig_hybrid_lc")?;
    let payload = canonical_bytes_without_signature(open_ack, |msg| msg.sig_hybrid_lc.clear())?;
    let signer_id = verify_hybrid_signature(&proof, &payload, "open_channel_ack")?;
    if signer_id != expected_lc_id {
        return Err(TransactionError::Invalid(
            "open_channel_ack signer does not match envelope.lc_id".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_channel_open_confirm_hybrid_signature(
    open_confirm: &SessionChannelOpenConfirm,
    expected_rc_id: [u8; 32],
) -> Result<(), TransactionError> {
    let proof = decode_hybrid_signature_proof(&open_confirm.sig_hybrid_rc, "sig_hybrid_rc")?;
    let payload = canonical_bytes_without_signature(open_confirm, |msg| msg.sig_hybrid_rc.clear())?;
    let signer_id = verify_hybrid_signature(&proof, &payload, "open_channel_confirm")?;
    if signer_id != expected_rc_id {
        return Err(TransactionError::Invalid(
            "open_channel_confirm signer does not match envelope.rc_id".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_channel_close_hybrid_signature(
    close: &SessionChannelClose,
    lc_id: [u8; 32],
    rc_id: [u8; 32],
) -> Result<(), TransactionError> {
    let proof = decode_hybrid_signature_proof(&close.sig_hybrid_sender, "sig_hybrid_sender")?;
    let payload = canonical_bytes_without_signature(close, |msg| msg.sig_hybrid_sender.clear())?;
    let signer_id = verify_hybrid_signature(&proof, &payload, "close_channel")?;
    if signer_id != lc_id && signer_id != rc_id {
        return Err(TransactionError::Invalid(
            "close_channel signer must be a channel participant".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_session_lease_hybrid_signature(
    lease: &SessionLease,
    expected_issuer_id: [u8; 32],
) -> Result<(), TransactionError> {
    if lease.issuer_id != expected_issuer_id {
        return Err(TransactionError::Invalid(
            "lease issuer_id must match channel envelope.lc_id".to_string(),
        ));
    }
    let proof = decode_hybrid_signature_proof(&lease.sig_hybrid_lc, "sig_hybrid_lc")?;
    let payload = canonical_bytes_without_signature(lease, |msg| msg.sig_hybrid_lc.clear())?;
    let signer_id = verify_hybrid_signature(&proof, &payload, "issue_session_lease")?;
    if signer_id != lease.issuer_id {
        return Err(TransactionError::Invalid(
            "lease signer does not match issuer_id".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_receipt_commit_hybrid_signature(
    commit: &SessionReceiptCommit,
    lc_id: [u8; 32],
    rc_id: [u8; 32],
) -> Result<(), TransactionError> {
    let proof = decode_hybrid_signature_proof(&commit.sig_hybrid_sender, "sig_hybrid_sender")?;
    let payload = canonical_bytes_without_signature(commit, |msg| msg.sig_hybrid_sender.clear())?;
    let signer_id = verify_hybrid_signature(&proof, &payload, "commit_receipt_root")?;
    if signer_id != commit.signer_id {
        return Err(TransactionError::Invalid(
            "receipt commit signer does not match signer_id".to_string(),
        ));
    }
    if signer_id != lc_id && signer_id != rc_id {
        return Err(TransactionError::Invalid(
            "receipt commit signer must be a channel participant".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn is_string_subset(child: &[String], parent: &[String]) -> bool {
    if parent.is_empty() {
        return true;
    }
    let parent_set = parent
        .iter()
        .map(|entry| entry.trim().to_ascii_lowercase())
        .filter(|entry| !entry.is_empty())
        .collect::<HashSet<_>>();
    child.iter().all(|entry| {
        let normalized = entry.trim().to_ascii_lowercase();
        !normalized.is_empty() && parent_set.contains(&normalized)
    })
}

pub(super) fn is_constraint_subset(
    child: &BTreeMap<String, String>,
    parent: &BTreeMap<String, String>,
) -> bool {
    child.iter().all(|(key, child_value)| {
        parent
            .get(key)
            .map(|parent_value| parent_value == child_value)
            .unwrap_or(false)
    })
}

fn is_target_subset(child: &[ActionTarget], parent: &[ActionTarget]) -> bool {
    if parent.is_empty() {
        return true;
    }
    let parent_set = parent
        .iter()
        .map(ActionTarget::canonical_label)
        .collect::<HashSet<_>>();
    child
        .iter()
        .map(ActionTarget::canonical_label)
        .all(|label| parent_set.contains(&label))
}

fn canonical_bytes_without_signature<T, F>(
    value: &T,
    clear_signature: F,
) -> Result<Vec<u8>, TransactionError>
where
    T: Clone + Encode,
    F: FnOnce(&mut T),
{
    let mut canonical = value.clone();
    clear_signature(&mut canonical);
    Ok(codec::to_bytes_canonical(&canonical)?)
}

fn decode_hybrid_signature_proof(
    raw_proof: &[u8],
    field_name: &str,
) -> Result<SignatureProof, TransactionError> {
    if raw_proof.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "{} must contain a hybrid signature proof",
            field_name
        )));
    }
    let proof: SignatureProof = codec::from_bytes_canonical(raw_proof)?;
    if proof.suite != SignatureSuite::HYBRID_ED25519_ML_DSA_44 {
        return Err(TransactionError::Invalid(format!(
            "{} must use HYBRID_ED25519_ML_DSA_44",
            field_name
        )));
    }
    if proof.public_key.len() <= 32 {
        return Err(TransactionError::Invalid(format!(
            "{} hybrid public key payload is too short",
            field_name
        )));
    }
    if proof.signature.len() <= 64 {
        return Err(TransactionError::Invalid(format!(
            "{} hybrid signature payload is too short",
            field_name
        )));
    }
    Ok(proof)
}

fn verify_hybrid_signature(
    proof: &SignatureProof,
    message: &[u8],
    context: &str,
) -> Result<[u8; 32], TransactionError> {
    const ED25519_PUBLIC_KEY_BYTES: usize = 32;
    const ED25519_SIGNATURE_BYTES: usize = 64;

    let (ed25519_pk_bytes, mldsa_pk_bytes) = proof.public_key.split_at(ED25519_PUBLIC_KEY_BYTES);
    let (ed25519_sig_bytes, mldsa_sig_bytes) = proof.signature.split_at(ED25519_SIGNATURE_BYTES);

    if mldsa_pk_bytes.is_empty() || mldsa_sig_bytes.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "{} hybrid signature block is missing PQ key/signature bytes",
            context
        )));
    }

    let ed25519_pk = Ed25519PublicKey::from_bytes(ed25519_pk_bytes).map_err(|e| {
        TransactionError::Invalid(format!("{} invalid ed25519 public key: {}", context, e))
    })?;
    let ed25519_sig = Ed25519Signature::from_bytes(ed25519_sig_bytes).map_err(|e| {
        TransactionError::Invalid(format!("{} invalid ed25519 signature: {}", context, e))
    })?;
    ed25519_pk.verify(message, &ed25519_sig).map_err(|e| {
        TransactionError::Invalid(format!("{} ed25519 verification failed: {}", context, e))
    })?;

    let mldsa_pk = MldsaPublicKey::from_bytes(mldsa_pk_bytes).map_err(|e| {
        TransactionError::Invalid(format!("{} invalid ml-dsa public key: {}", context, e))
    })?;
    let mldsa_sig = MldsaSignature::from_bytes(mldsa_sig_bytes).map_err(|e| {
        TransactionError::Invalid(format!("{} invalid ml-dsa signature: {}", context, e))
    })?;
    mldsa_pk.verify(message, &mldsa_sig).map_err(|e| {
        TransactionError::Invalid(format!("{} ml-dsa verification failed: {}", context, e))
    })?;

    account_id_from_key_material(SignatureSuite::HYBRID_ED25519_ML_DSA_44, &proof.public_key)
}
