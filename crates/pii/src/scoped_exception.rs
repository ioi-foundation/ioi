// Submodule: scoped_exception (minting + verification)

use anyhow::Result;
use ioi_types::app::agentic::{
    EvidenceGraph, PiiClass, PiiControls, PiiScopedException, PiiTarget, RawOverrideMode,
};
use parity_scale_codec::Encode;

use crate::assist::{risk_surface_label, RiskSurface};
use crate::hashing::sha256_array;
pub use crate::review_contract::{
    DEFAULT_SCOPED_EXCEPTION_MAX_USES, DEFAULT_SCOPED_EXCEPTION_TTL_SECS,
};
use crate::review_summary::{
    canonical_class_keys, collect_low_severity_classes, has_blocking_scoped_exception_evidence,
};

pub fn scoped_exception_destination_hash(
    target: &PiiTarget,
    risk_surface: RiskSurface,
) -> [u8; 32] {
    let material = (target.clone(), risk_surface_label(risk_surface).to_string()).encode();
    sha256_array(&material).unwrap_or([0u8; 32])
}

/// Mints a locked default scoped exception for low-severity-only evidence.
pub fn mint_default_scoped_exception(
    graph: &EvidenceGraph,
    target: &PiiTarget,
    risk_surface: RiskSurface,
    decision_hash: [u8; 32],
    now_unix: u64,
    justification: &str,
) -> Result<PiiScopedException> {
    if has_blocking_scoped_exception_evidence(graph) {
        anyhow::bail!("Scoped exception denied: high-severity or secret class present.");
    }
    let allowed_classes = collect_low_severity_classes(graph);
    if allowed_classes.is_empty() {
        anyhow::bail!("Scoped exception denied: no low-severity classes in evidence.");
    }

    let destination_hash = scoped_exception_destination_hash(target, risk_surface);
    let justification_hash = sha256_array(justification.as_bytes()).unwrap_or([0u8; 32]);
    let id_material = (
        "scoped_low_severity_v1".to_string(),
        destination_hash,
        decision_hash,
        canonical_class_keys(&allowed_classes),
        justification_hash,
    )
        .encode();
    let exception_id_hash = sha256_array(&id_material).unwrap_or([0u8; 32]);

    Ok(PiiScopedException {
        exception_id: format!("scope::{}", hex::encode(exception_id_hash)),
        allowed_classes,
        destination_hash,
        action_hash: decision_hash,
        expires_at: now_unix.saturating_add(DEFAULT_SCOPED_EXCEPTION_TTL_SECS),
        max_uses: DEFAULT_SCOPED_EXCEPTION_MAX_USES,
        justification_hash,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedExceptionVerifyError {
    PolicyDisabled,
    MissingAllowedClasses,
    DestinationMismatch,
    ActionMismatch,
    Expired,
    Overused,
    IneligibleEvidence,
    ClassMismatch,
    InvalidMaxUses,
}

impl std::fmt::Display for ScopedExceptionVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            ScopedExceptionVerifyError::PolicyDisabled => "policy does not allow scoped exceptions",
            ScopedExceptionVerifyError::MissingAllowedClasses => "missing allowed classes",
            ScopedExceptionVerifyError::DestinationMismatch => "destination binding mismatch",
            ScopedExceptionVerifyError::ActionMismatch => "action binding mismatch",
            ScopedExceptionVerifyError::Expired => "exception expired",
            ScopedExceptionVerifyError::Overused => "exception overused",
            ScopedExceptionVerifyError::IneligibleEvidence => "evidence is not low-severity-only",
            ScopedExceptionVerifyError::ClassMismatch => "allowed classes mismatch evidence",
            ScopedExceptionVerifyError::InvalidMaxUses => "invalid max_uses",
        };
        write!(f, "{msg}")
    }
}

impl std::error::Error for ScopedExceptionVerifyError {}

/// Verifies a scoped exception against the current deterministic decision context.
pub fn verify_scoped_exception_for_decision(
    exception: &PiiScopedException,
    graph: &EvidenceGraph,
    target: &PiiTarget,
    risk_surface: RiskSurface,
    decision_hash: [u8; 32],
    policy: &PiiControls,
    now_unix: u64,
    uses_consumed: u32,
) -> std::result::Result<(), ScopedExceptionVerifyError> {
    if !matches!(
        policy.raw_override_mode,
        RawOverrideMode::ScopedLowSeverityOnly
    ) {
        return Err(ScopedExceptionVerifyError::PolicyDisabled);
    }
    if exception.allowed_classes.is_empty() {
        return Err(ScopedExceptionVerifyError::MissingAllowedClasses);
    }
    if exception.max_uses == 0 {
        return Err(ScopedExceptionVerifyError::InvalidMaxUses);
    }
    if uses_consumed >= exception.max_uses {
        return Err(ScopedExceptionVerifyError::Overused);
    }
    if now_unix >= exception.expires_at {
        return Err(ScopedExceptionVerifyError::Expired);
    }

    let expected_destination = scoped_exception_destination_hash(target, risk_surface);
    if expected_destination != exception.destination_hash {
        return Err(ScopedExceptionVerifyError::DestinationMismatch);
    }
    if exception.action_hash != decision_hash {
        return Err(ScopedExceptionVerifyError::ActionMismatch);
    }

    if has_blocking_scoped_exception_evidence(graph) {
        return Err(ScopedExceptionVerifyError::IneligibleEvidence);
    }
    let expected_classes = collect_low_severity_classes(graph);
    if expected_classes.is_empty() {
        return Err(ScopedExceptionVerifyError::IneligibleEvidence);
    }
    if canonical_class_keys(&expected_classes) != canonical_class_keys(&exception.allowed_classes) {
        return Err(ScopedExceptionVerifyError::ClassMismatch);
    }

    Ok(())
}

/// Mints a one-time scoped exception for low-severity raw egress.
pub fn mint_scoped_exception(
    target: &str,
    allowed_classes: Vec<PiiClass>,
    destination_metadata: &[u8],
    action_metadata: &[u8],
    justification: &str,
    now_unix: u64,
    ttl_secs: u64,
) -> PiiScopedException {
    let destination_hash = sha256_array(destination_metadata).unwrap_or([0u8; 32]);

    let action_hash = sha256_array(action_metadata).unwrap_or([0u8; 32]);

    let justification_hash = sha256_array(justification.as_bytes()).unwrap_or([0u8; 32]);

    let exception_id_material = format!(
        "scope|{}|{}|{}|{}",
        target,
        hex::encode(destination_hash),
        hex::encode(action_hash),
        hex::encode(justification_hash)
    );
    let exception_id_hash = sha256_array(exception_id_material.as_bytes())
        .map(hex::encode)
        .unwrap_or_else(|_| "scope_error".to_string());

    PiiScopedException {
        exception_id: format!("scope::{exception_id_hash}"),
        allowed_classes,
        destination_hash,
        action_hash,
        expires_at: now_unix.saturating_add(ttl_secs),
        max_uses: 1,
        justification_hash,
    }
}
