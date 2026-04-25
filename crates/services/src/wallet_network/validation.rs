// Path: crates/services/src/wallet_network/validation.rs

use crate::agentic::runtime::kernel::approval::{ApprovalScopeContext, AuthorityScopeMatcher};
use crate::guardian_registry::GuardianRegistry;
use crate::wallet_network::keys::approval_authority_key;
use ioi_api::crypto::{SerializableKey, VerifyingKey};
use ioi_api::state::StateAccess;
use ioi_crypto::sign::dilithium::{MldsaPublicKey, MldsaSignature};
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
use ioi_types::app::action::{ApprovalAuthority, ApprovalGrant};
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
    state: &dyn StateAccess,
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
    if !attestation.verifier_id.trim().is_empty() && attestation.evidence.is_none() {
        return Err(TransactionError::Invalid(
            "guardian attestation verifier_id requires evidence".to_string(),
        ));
    }
    if let Some(evidence) = &attestation.evidence {
        if evidence.measurement_root != attestation.measurement_hash {
            return Err(TransactionError::Invalid(
                "guardian attestation measurement root mismatch".to_string(),
            ));
        }
        match evidence.verifier {
            ioi_types::app::GuardianAttestationVerifierKind::Structural => {}
            ioi_types::app::GuardianAttestationVerifierKind::TeeDriver => {
                if evidence.evidence.is_empty() {
                    return Err(TransactionError::Invalid(
                        "tee-driver attestation requires quote evidence".to_string(),
                    ));
                }
            }
            ioi_types::app::GuardianAttestationVerifierKind::SoftwareGuardian => {
                let manifest =
                    GuardianRegistry::load_manifest_by_hash(state, &evidence.manifest_hash)
                        .map_err(TransactionError::State)?
                        .ok_or_else(|| {
                            TransactionError::Invalid(
                                "software guardian attestation manifest not found".to_string(),
                            )
                        })?;
                if manifest.threshold == 0 || manifest.members.is_empty() {
                    return Err(TransactionError::Invalid(
                        "guardian committee manifest is invalid".to_string(),
                    ));
                }
                if !GuardianRegistry::profile_allows_measurement(
                    state,
                    &attestation.measurement_hash,
                )
                .map_err(TransactionError::State)?
                {
                    return Err(TransactionError::Invalid(
                        "guardian measurement hash is not allowed by policy".to_string(),
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate_approval(approval: &WalletApprovalDecision) -> Result<(), TransactionError> {
    let grant_present = approval.approval_grant.is_some();
    match approval.decision {
        WalletApprovalDecisionKind::AutoApproved | WalletApprovalDecisionKind::ApprovedByHuman => {
            if !grant_present {
                return Err(TransactionError::Invalid(
                    "approved decisions require an approval_grant".to_string(),
                ));
            }
        }
        WalletApprovalDecisionKind::DeniedByHuman
        | WalletApprovalDecisionKind::RequiresHumanReview => {
            if grant_present {
                return Err(TransactionError::Invalid(
                    "denied/review decisions must not include approval_grant".to_string(),
                ));
            }
        }
    }

    if approval.interception.policy_hash == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "wallet interception policy_hash must not be all zeroes".to_string(),
        ));
    }

    if let Some(grant) = &approval.approval_grant {
        if grant.request_hash != approval.interception.request_hash {
            return Err(TransactionError::Invalid(
                "approval_grant request hash mismatch".to_string(),
            ));
        }
        if grant.policy_hash != approval.interception.policy_hash {
            return Err(TransactionError::Invalid(
                "approval_grant policy hash mismatch".to_string(),
            ));
        }
        grant
            .verify()
            .map_err(|e| TransactionError::Invalid(format!("Invalid approval grant: {}", e)))?;
    }
    Ok(())
}

pub(super) fn load_registered_approval_authority(
    state: &dyn StateAccess,
    authority_id: &[u8; 32],
) -> Result<Option<ApprovalAuthority>, TransactionError> {
    match state.get(&approval_authority_key(authority_id))? {
        Some(bytes) => Ok(Some(codec::from_bytes_canonical(&bytes)?)),
        None => Ok(None),
    }
}

fn verify_approval_grant_signature(grant: &ApprovalGrant) -> Result<(), TransactionError> {
    let message = grant
        .signing_bytes()
        .map_err(|e| TransactionError::Invalid(format!("Invalid approval grant: {}", e)))?;
    match grant.approver_suite {
        ioi_types::app::SignatureSuite::ED25519 => {
            let pk = Ed25519PublicKey::from_bytes(&grant.approver_public_key).map_err(|e| {
                TransactionError::Invalid(format!("Invalid approval grant public key: {}", e))
            })?;
            let sig = Ed25519Signature::from_bytes(&grant.approver_sig).map_err(|e| {
                TransactionError::Invalid(format!("Invalid approval grant signature: {}", e))
            })?;
            pk.verify(&message, &sig).map_err(|e| {
                TransactionError::Invalid(format!(
                    "Approval grant signature verification failed: {}",
                    e
                ))
            })?;
        }
        ioi_types::app::SignatureSuite::ML_DSA_44 => {
            let pk = MldsaPublicKey::from_bytes(&grant.approver_public_key).map_err(|e| {
                TransactionError::Invalid(format!("Invalid approval grant public key: {}", e))
            })?;
            let sig = MldsaSignature::from_bytes(&grant.approver_sig).map_err(|e| {
                TransactionError::Invalid(format!("Invalid approval grant signature: {}", e))
            })?;
            pk.verify(&message, &sig).map_err(|e| {
                TransactionError::Invalid(format!(
                    "Approval grant signature verification failed: {}",
                    e
                ))
            })?;
        }
        _ => {
            return Err(TransactionError::Invalid(format!(
                "Unsupported approval grant signature suite: {}",
                grant.approver_suite.0
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_registered_approval_grant(
    state: &dyn StateAccess,
    grant: &ApprovalGrant,
    now_ms: u64,
    expected_policy_hash: [u8; 32],
    scope_context: Option<&ApprovalScopeContext>,
) -> Result<(), TransactionError> {
    grant
        .verify()
        .map_err(|e| TransactionError::Invalid(format!("Invalid approval grant: {}", e)))?;
    verify_approval_grant_signature(grant)?;
    let authority =
        load_registered_approval_authority(state, &grant.authority_id)?.ok_or_else(|| {
            TransactionError::Invalid("Approval authority is not registered".to_string())
        })?;
    authority
        .verify()
        .map_err(|e| TransactionError::Invalid(format!("Invalid approval authority: {}", e)))?;
    if authority.revoked {
        return Err(TransactionError::Invalid(
            "Approval authority has been revoked".to_string(),
        ));
    }
    if authority.signature_suite != grant.approver_suite
        || authority.public_key != grant.approver_public_key
    {
        return Err(TransactionError::Invalid(
            "Approval authority does not match approval grant signer".to_string(),
        ));
    }
    if now_ms > grant.expires_at {
        return Err(TransactionError::Invalid(
            "Approval grant has expired".to_string(),
        ));
    }
    if now_ms > authority.expires_at {
        return Err(TransactionError::Invalid(
            "Approval authority has expired".to_string(),
        ));
    }
    if grant.policy_hash != expected_policy_hash {
        return Err(TransactionError::Invalid(
            "Approval grant policy hash mismatch".to_string(),
        ));
    }
    if let Some(scope_context) = scope_context {
        AuthorityScopeMatcher::validate(&authority, scope_context).map_err(|reason| {
            TransactionError::Invalid(format!(
                "Approval grant scope validation failed: {}",
                reason
            ))
        })?;
    }
    Ok(())
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
