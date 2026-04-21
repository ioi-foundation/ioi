use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::keys::{
    get_approval_authority_key, get_approval_grant_key, pii,
};
use crate::agentic::runtime::service::step::incident::mark_gate_approved;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::AgentState;
use ioi_api::crypto::{SerializableKey, VerifyingKey};
use ioi_api::state::StateAccess;
use ioi_crypto::sign::dilithium::{MldsaPublicKey, MldsaSignature};
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
use ioi_pii::{
    check_exception_usage_increment_ok, decode_exception_usage_state,
    mint_default_scoped_exception, verify_scoped_exception_for_decision, RiskSurface,
    ScopedExceptionVerifyError,
};
use ioi_types::app::action::PiiApprovalAction;
use ioi_types::app::agentic::{AgentTool, PiiEgressRiskSurface, PiiReviewRequest};
use ioi_types::codec;
use ioi_types::error::TransactionError;

pub(super) struct ApprovalResult {
    pub(super) scoped_exception_override_hash: Option<[u8; 32]>,
    pub(super) explicit_pii_deny: bool,
}

fn to_shared_risk_surface(risk_surface: PiiEgressRiskSurface) -> RiskSurface {
    match risk_surface {
        PiiEgressRiskSurface::Egress => RiskSurface::Egress,
    }
}

fn load_pending_approval_grant(
    state: &dyn StateAccess,
    session_id: &[u8; 32],
) -> Result<Option<ioi_types::app::ApprovalGrant>, TransactionError> {
    let key = get_approval_grant_key(session_id);
    match state.get(&key)? {
        Some(bytes) => {
            let grant = codec::from_bytes_canonical(&bytes)
                .map_err(|e| TransactionError::Invalid(format!("Invalid approval grant: {}", e)))?;
            Ok(Some(grant))
        }
        None => Ok(None),
    }
}

fn load_registered_approval_authority(
    state: &dyn StateAccess,
    authority_id: &[u8; 32],
) -> Result<Option<ioi_types::app::ApprovalAuthority>, TransactionError> {
    let key = get_approval_authority_key(authority_id);
    match state.get(&key)? {
        Some(bytes) => {
            let authority = codec::from_bytes_canonical(&bytes).map_err(|e| {
                TransactionError::Invalid(format!("Invalid approval authority: {}", e))
            })?;
            Ok(Some(authority))
        }
        None => Ok(None),
    }
}

fn verify_approval_grant_signature(
    grant: &ioi_types::app::ApprovalGrant,
) -> Result<(), TransactionError> {
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
                TransactionError::Invalid(format!("Approval grant signature verification failed: {}", e))
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
                TransactionError::Invalid(format!("Approval grant signature verification failed: {}", e))
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

pub(crate) fn validate_registered_approval_grant(
    state: &dyn StateAccess,
    grant: &ioi_types::app::ApprovalGrant,
    now_ms: Option<u64>,
    expected_policy_hash: Option<[u8; 32]>,
) -> Result<(), TransactionError> {
    grant
        .verify()
        .map_err(|e| TransactionError::Invalid(format!("Invalid approval grant: {}", e)))?;
    verify_approval_grant_signature(grant)?;
    let authority = load_registered_approval_authority(state, &grant.authority_id)?.ok_or_else(
        || TransactionError::Invalid("Approval authority is not registered".to_string()),
    )?;
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
    if let Some(now_ms) = now_ms {
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
    }
    if let Some(expected_policy_hash) = expected_policy_hash {
        if grant.policy_hash != expected_policy_hash {
            return Err(TransactionError::Invalid(
                "Approval grant policy hash mismatch".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_resume_review_contract_for_grant_local(
    expected_request_hash: [u8; 32],
    approval_grant: &ioi_types::app::ApprovalGrant,
    review_request: Option<&PiiReviewRequest>,
    now_ms: u64,
) -> Result<(), TransactionError> {
    if approval_grant.request_hash != expected_request_hash {
        return Err(TransactionError::Invalid(
            "Approval grant hash mismatch".to_string(),
        ));
    }
    let Some(request) = review_request else {
        if let Some(action) = approval_grant.pii_action.as_ref() {
            if !matches!(action, PiiApprovalAction::Deny) {
                return Err(TransactionError::Invalid(
                    "PII action provided but no review request exists".to_string(),
                ));
            }
        }
        return Ok(());
    };
    if request.decision_hash != expected_request_hash
        || approval_grant.review_request_hash != Some(request.decision_hash)
    {
        return Err(TransactionError::Invalid(
            "PII review request hash mismatch".to_string(),
        ));
    }
    if now_ms > request.deadline_ms {
        return Err(TransactionError::Invalid(
            "PII review approval deadline exceeded".to_string(),
        ));
    }
    if approval_grant.pii_action.is_none() {
        return Err(TransactionError::Invalid(
            "PII review request requires explicit pii_action".to_string(),
        ));
    }
    Ok(())
}

pub(super) async fn validate_and_apply(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    _agent_state: &mut AgentState,
    session_id: [u8; 32],
    tool: &AgentTool,
    expected_request_hash: [u8; 32],
    pii_request: Option<&PiiReviewRequest>,
    block_timestamp_ms: u64,
    block_timestamp_secs: u64,
    rules: &mut ActionRules,
    verification_checks: &mut Vec<String>,
) -> Result<ApprovalResult, TransactionError> {
    let mut scoped_exception_override_hash: Option<[u8; 32]> = None;
    let mut explicit_pii_deny = false;
    let approval_grant = load_pending_approval_grant(state, &session_id)?;

    // Validate approval grant before executing anything.
    // Runtime secret retries for package__install are allowed without approval grant.
    if let Some(grant) = approval_grant.as_ref() {
        validate_registered_approval_grant(state, grant, Some(block_timestamp_ms), None)?;
        validate_resume_review_contract_for_grant_local(
            expected_request_hash,
            grant,
            pii_request,
            block_timestamp_ms,
        )
        .map_err(|e| TransactionError::Invalid(e.to_string()))?;

        if matches!(grant.pii_action, Some(PiiApprovalAction::ApproveTransform)) {
            rules.pii_controls.safe_transform_enabled = true;
            verification_checks.push("pii_action=approve_transform".to_string());
        }

        if matches!(
            grant.pii_action,
            Some(PiiApprovalAction::GrantScopedException)
        ) {
            let mut probe_tool = tool.clone();
            let mut verified = false;
            for spec in probe_tool.pii_egress_specs() {
                let Some(text) = probe_tool.pii_egress_field_mut(spec.field) else {
                    continue;
                };
                let (_scrubbed, _map, _report, routed, evidence) = service
                    .scrubber
                    .inspect_route_transform_for_egress_field(
                        text,
                        spec.field,
                        &spec.target,
                        to_shared_risk_surface(spec.risk_surface),
                        &rules.pii_controls,
                        spec.supports_transform,
                    )
                    .await
                    .map_err(|e| {
                        TransactionError::Invalid(format!(
                            "PII verification failed while consuming scoped exception: {}",
                            e
                        ))
                    })?;

                if routed.decision_hash != expected_request_hash {
                    continue;
                }

                let scoped_exception = if let Some(existing) = grant.scoped_exception.as_ref() {
                    existing.clone()
                } else {
                    mint_default_scoped_exception(
                        &evidence,
                        &spec.target,
                        to_shared_risk_surface(spec.risk_surface),
                        expected_request_hash,
                        block_timestamp_secs,
                        "deterministic-default",
                    )
                    .map_err(|e| {
                        TransactionError::Invalid(format!(
                            "Failed to mint deterministic scoped exception: {}",
                            e
                        ))
                    })?
                };

                let usage_key = pii::review::exception_usage(&scoped_exception.exception_id);
                let raw_usage = state.get(&usage_key)?;
                let uses_consumed = decode_exception_usage_state(raw_usage.as_deref())
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                verify_scoped_exception_for_decision(
                    &scoped_exception,
                    &evidence,
                    &spec.target,
                    to_shared_risk_surface(spec.risk_surface),
                    expected_request_hash,
                    &rules.pii_controls,
                    block_timestamp_secs,
                    uses_consumed,
                )
                .map_err(|e| {
                    let reason = match e {
                        ScopedExceptionVerifyError::PolicyDisabled => {
                            "Scoped exception policy disabled"
                        }
                        ScopedExceptionVerifyError::MissingAllowedClasses => {
                            "Scoped exception missing allowed classes"
                        }
                        ScopedExceptionVerifyError::DestinationMismatch => {
                            "Scoped exception destination mismatch"
                        }
                        ScopedExceptionVerifyError::ActionMismatch => {
                            "Scoped exception action mismatch"
                        }
                        ScopedExceptionVerifyError::Expired => "Scoped exception expired",
                        ScopedExceptionVerifyError::Overused => "Scoped exception overused",
                        ScopedExceptionVerifyError::IneligibleEvidence => {
                            "Scoped exception not eligible for this evidence"
                        }
                        ScopedExceptionVerifyError::ClassMismatch => {
                            "Scoped exception class mismatch"
                        }
                        ScopedExceptionVerifyError::InvalidMaxUses => {
                            "Scoped exception max_uses invalid"
                        }
                    };
                    TransactionError::Invalid(reason.to_string())
                })?;

                let next_uses = check_exception_usage_increment_ok(uses_consumed)
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                state.insert(&usage_key, &codec::to_bytes_canonical(&next_uses)?)?;
                scoped_exception_override_hash = Some(expected_request_hash);
                verified = true;
                break;
            }

            if !verified {
                return Err(TransactionError::Invalid(
                    "Scoped exception does not match the pending PII decision".into(),
                ));
            }
            verification_checks.push("pii_action=grant_scoped_exception".to_string());
        }

        if matches!(grant.pii_action, Some(PiiApprovalAction::Deny)) {
            explicit_pii_deny = true;
            verification_checks.push("pii_action=deny".to_string());
        } else {
            mark_gate_approved(state, session_id)?;
        }
    } else if pii_request.is_some() {
        return Err(TransactionError::Invalid(
            "Missing approval authority for review request".into(),
        ));
    } else if !matches!(tool, AgentTool::SysInstallPackage { .. }) {
        return Err(TransactionError::Invalid("Missing approval authority".into()));
    } else {
        verification_checks.push("resume_without_approval_runtime_secret=true".to_string());
    }

    Ok(ApprovalResult {
        scoped_exception_override_hash,
        explicit_pii_deny,
    })
}
