// Path: crates/validator/src/firewall/mod.rs

//! The Agency Firewall: Pre-execution policy enforcement and validation.

/// The inference engine interface for classification.
pub mod inference;
// REMOVED: pub mod policy;
// REMOVED: pub mod rules;
/// Policy Synthesizer for Ghost Mode.
pub mod synthesizer;

// [FIX] Import PolicyEngine and Verdict from ioi-services
use ioi_pii::{
    build_decision_material, build_review_summary, check_exception_usage_increment_ok,
    decode_exception_usage_state, inspect_and_route_with_for_target, mint_default_scoped_exception,
    resolve_expected_request_hash, validate_review_request_v3_cim,
    verify_scoped_exception_for_decision, RiskSurface, ScopedExceptionVerifyError,
};
use ioi_services::agentic::policy::PolicyEngine;
use ioi_services::agentic::rules::{ActionRules, Verdict};
// [NEW] Imports for state lookup
use ioi_services::agentic::runtime::kernel::approval::{
    ApprovalScopeContext, AuthorityScopeMatcher,
};
use ioi_services::agentic::runtime::keys::{
    get_approval_authority_key, get_approval_grant_key, get_incident_key, get_state_key, pii,
};
use ioi_services::agentic::runtime::service::recovery::incident::IncidentState;
use ioi_services::agentic::runtime::{AgentState, ResumeAgentParams, StepAgentParams};

use ioi_api::crypto::{SerializableKey, VerifyingKey};
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::{LocalSafetyModel, PiiRiskSurface};

use ioi_api::state::namespaced::{NamespacedStateAccess, ReadOnlyNamespacedStateAccess};
use ioi_api::state::{service_namespace_prefix, StateAccess, StateOverlay};
use ioi_api::transaction::context::TxContext;
use ioi_crypto::algorithms::hash::sha256;
use ioi_crypto::sign::dilithium::{MldsaPublicKey, MldsaSignature};
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
use ioi_tx::system::{nonce, validation};
use ioi_types::app::action::PiiApprovalAction;
use ioi_types::app::agentic::{AgentTool, PiiEgressRiskSurface, PiiTarget};
use ioi_types::app::{action::ApprovalGrant, ChainTransaction, KernelEvent, SystemPayload};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::ActiveServiceMeta;
use std::sync::Arc;

fn to_shared_risk_surface(risk_surface: PiiRiskSurface) -> RiskSurface {
    match risk_surface {
        PiiRiskSurface::LocalProcessing => RiskSurface::LocalProcessing,
        PiiRiskSurface::Egress => RiskSurface::Egress,
    }
}

fn to_shared_risk_surface_from_egress(risk_surface: PiiEgressRiskSurface) -> RiskSurface {
    match risk_surface {
        PiiEgressRiskSurface::Egress => RiskSurface::Egress,
    }
}

fn parse_hash_hex(input: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(input).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn validate_resume_review_contract_for_grant_local(
    expected_request_hash: [u8; 32],
    approval_grant: &ApprovalGrant,
    review_request: Option<&ioi_types::app::agentic::PiiReviewRequest>,
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

fn compute_policy_hash(rules: &ActionRules) -> Result<[u8; 32], TransactionError> {
    let canonical =
        serde_jcs::to_vec(rules).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = sha256(&canonical).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Policy hash failed: {}",
            e
        ))
    })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
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

fn validate_registered_approval_grant(
    overlay: &StateOverlay<'_>,
    grant: &ApprovalGrant,
    now_ms: u64,
    expected_policy_hash: [u8; 32],
    scope_context: Option<&ApprovalScopeContext>,
) -> Result<(), TransactionError> {
    grant
        .verify()
        .map_err(|e| TransactionError::Invalid(format!("Invalid approval grant: {}", e)))?;
    verify_approval_grant_signature(grant)?;
    if grant.policy_hash != expected_policy_hash {
        return Err(TransactionError::Invalid(
            "Approval grant policy hash mismatch".to_string(),
        ));
    }
    if now_ms > grant.expires_at {
        return Err(TransactionError::Invalid(
            "Approval grant has expired".to_string(),
        ));
    }
    let authority_key = [
        service_namespace_prefix("desktop_agent").as_slice(),
        get_approval_authority_key(&grant.authority_id).as_slice(),
    ]
    .concat();
    let authority: ioi_types::app::ApprovalAuthority = overlay
        .get(&authority_key)?
        .and_then(|bytes| codec::from_bytes_canonical(&bytes).ok())
        .ok_or_else(|| {
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
    if now_ms > authority.expires_at {
        return Err(TransactionError::Invalid(
            "Approval authority has expired".to_string(),
        ));
    }
    if authority.signature_suite != grant.approver_suite
        || authority.public_key != grant.approver_public_key
    {
        return Err(TransactionError::Invalid(
            "Approval authority does not match approval grant signer".to_string(),
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

fn policy_request_params(method: &str, params: &[u8]) -> Vec<u8> {
    if serde_json::from_slice::<serde_json::Value>(params).is_ok() {
        return params.to_vec();
    }

    serde_json::to_vec(&serde_json::json!({
        "__ioi_policy_non_json_params": {
            "method": method,
            "encoding": "hex",
            "value": hex::encode(params),
        }
    }))
    .unwrap_or_else(|_| b"{\"__ioi_policy_non_json_params\":null}".to_vec())
}

/// Firewall policy must bind to committed, chain-visible desktop state.
/// Runtime checkpoints are convenience mirrors and are intentionally not
/// consulted here.
fn load_committed_desktop_agent_state(
    overlay: &StateOverlay<'_>,
    session_id: &[u8; 32],
) -> Option<AgentState> {
    let ns_prefix = service_namespace_prefix("desktop_agent");
    let state_key = get_state_key(session_id);
    let full_key = [ns_prefix.as_slice(), state_key.as_slice()].concat();
    let bytes = overlay.get(&full_key).ok()??;
    codec::from_bytes_canonical::<AgentState>(&bytes).ok()
}

fn load_committed_incident_state(
    overlay: &StateOverlay<'_>,
    session_id: &[u8; 32],
) -> Option<IncidentState> {
    let ns_prefix = service_namespace_prefix("desktop_agent");
    let incident_key = get_incident_key(session_id);
    let full_key = [ns_prefix.as_slice(), incident_key.as_slice()].concat();
    let bytes = overlay.get(&full_key).ok()??;
    codec::from_bytes_canonical::<IncidentState>(&bytes).ok()
}

/// The main firewall entry point.
pub async fn enforce_firewall(
    state: &mut dyn StateAccess,
    services: &ioi_api::services::access::ServiceDirectory,
    tx: &ChainTransaction,
    chain_id: ioi_types::app::ChainId,
    next_block_height: u64,
    expected_timestamp_secs: u64,
    skip_stateless_checks: bool,
    is_simulation: bool,
    safety_model: Arc<dyn LocalSafetyModel>,
    os_driver: Arc<dyn OsDriver>,
    // [NEW] Added event_broadcaster to emit UI events (gates, blocks)
    event_broadcaster: &Option<tokio::sync::broadcast::Sender<KernelEvent>>,
) -> Result<(), TransactionError> {
    let mut overlay = StateOverlay::new(state);

    // 1. Identify Signer
    let (signer_account_id, _session_auth) = match tx {
        ChainTransaction::System(s) => (s.header.account_id, s.header.session_auth.as_ref()),
        ChainTransaction::Settlement(s) => (s.header.account_id, s.header.session_auth.as_ref()),
        ChainTransaction::Application(a) => match a {
            ioi_types::app::ApplicationTransaction::DeployContract { header, .. }
            | ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                (header.account_id, header.session_auth.as_ref())
            }
        },
        ChainTransaction::Semantic { header, .. } => {
            (header.account_id, header.session_auth.as_ref())
        }
    };

    // 2. Context
    let next_timestamp_ns = (expected_timestamp_secs as u128).saturating_mul(1_000_000_000u128);
    // [FIX] Use raw u64
    let next_timestamp = next_timestamp_ns
        .try_into()
        .map_err(|_| TransactionError::Invalid("Timestamp overflow".to_string()))?;

    let tx_ctx = TxContext {
        block_height: next_block_height,
        block_timestamp: next_timestamp,
        chain_id,
        signer_account_id,
        services,
        simulation: is_simulation,
        is_internal: false,
    };

    // --- LAYER 1: CRYPTOGRAPHIC HARDENING ---
    if !skip_stateless_checks {
        validation::verify_stateless_signature(tx)?;
    }
    validation::verify_stateful_authorization(&overlay, services, tx, &tx_ctx)?;

    // --- LAYER 2: REPLAY PROTECTION ---
    if is_simulation {
        nonce::assert_nonce_at_least(&overlay, tx)?;
    } else {
        nonce::assert_next_nonce(&overlay, tx)?;
    }

    // --- LAYER 3: POLICY ENGINE & SEMANTIC SCRUBBING ---
    if let ChainTransaction::System(sys) = tx {
        let SystemPayload::CallService {
            service_id,
            method,
            params,
        } = &sys.payload;

        PolicyEngine::check_service_call(&overlay, service_id, method, false)?;

        if service_id == "agentic"
            || service_id == "desktop_agent"
            || service_id == "compute_market"
        {
            let allow_approval_bypass_for_message =
                service_id == "desktop_agent" && method == "post_message@v1";
            if allow_approval_bypass_for_message {
                tracing::info!(
                    target: "firewall",
                    "Approval-gate bypass enabled for desktop_agent post_message@v1"
                );
            }

            // [NEW] Attempt to extract session_id and approval token from state
            let mut session_id_opt = None;
            let mut approval_grant: Option<ApprovalGrant> = None;
            let mut agent_state_opt: Option<AgentState> = None;
            let mut pending_gate_hash_opt: Option<[u8; 32]> = None;
            let mut expected_request_hash_opt: Option<[u8; 32]> = None;
            if service_id == "desktop_agent" && method == "step@v1" {
                if let Ok(p) = codec::from_bytes_canonical::<StepAgentParams>(params) {
                    session_id_opt = Some(p.session_id);

                    if let Some(agent_state) =
                        load_committed_desktop_agent_state(&overlay, &p.session_id)
                    {
                        agent_state_opt = Some(agent_state);
                    }
                    let grant_key = [
                        service_namespace_prefix("desktop_agent").as_slice(),
                        get_approval_grant_key(&p.session_id).as_slice(),
                    ]
                    .concat();
                    approval_grant = overlay
                        .get(&grant_key)?
                        .and_then(|bytes| codec::from_bytes_canonical(&bytes).ok());
                }
            } else if service_id == "desktop_agent" && method == "resume@v1" {
                if let Ok(p) = codec::from_bytes_canonical::<ResumeAgentParams>(params) {
                    session_id_opt = Some(p.session_id);
                    approval_grant = p.approval_grant.clone();

                    if let Some(agent_state) =
                        load_committed_desktop_agent_state(&overlay, &p.session_id)
                    {
                        agent_state_opt = Some(agent_state);
                    }
                    if approval_grant.is_none() {
                        let grant_key = [
                            service_namespace_prefix("desktop_agent").as_slice(),
                            get_approval_grant_key(&p.session_id).as_slice(),
                        ]
                        .concat();
                        approval_grant = overlay
                            .get(&grant_key)?
                            .and_then(|bytes| codec::from_bytes_canonical(&bytes).ok());
                    }

                    pending_gate_hash_opt = load_committed_incident_state(&overlay, &p.session_id)
                        .and_then(|incident_state| {
                            incident_state
                                .pending_gate
                                .as_ref()
                                .and_then(|pending| parse_hash_hex(&pending.request_hash))
                        });
                }
            }

            // [FIX] Load active policy from state (Global Fallback)
            // We use the global policy key (zero session ID) defined in `ioi-local.rs`.
            // Canonical prefix: b"agent::policy::"
            // The namespaced prefix is not applied here because we are reading raw state in the firewall,
            // but the policy was inserted in ioi-local via raw insert which might or might not be namespaced.
            // Wait, ioi-local.rs uses `workload_container.state_tree().write()` which is raw access.
            // But `ioi-local.rs` inserts keys `agent::policy::{session_id}`.

            // NOTE: The `ioi-local` setup writes to raw state.
            // The policy prefix is `b"agent::policy::"`.
            // The global policy uses a zeroed session ID.

            let policy_prefix = b"agent::policy::";

            let rules = if let Some(sid) = session_id_opt {
                // Try session specific policy first
                let session_policy_key = [policy_prefix, sid.as_slice()].concat();
                if let Ok(Some(bytes)) = overlay.get(&session_policy_key) {
                    codec::from_bytes_canonical::<ActionRules>(&bytes).unwrap_or_default()
                } else {
                    // Fallback to global
                    let global_key = [policy_prefix, [0u8; 32].as_slice()].concat();
                    if let Ok(Some(bytes)) = overlay.get(&global_key) {
                        codec::from_bytes_canonical::<ActionRules>(&bytes).unwrap_or_default()
                    } else {
                        ActionRules::default()
                    }
                }
            } else {
                // Global fallback
                let global_key = [policy_prefix, [0u8; 32].as_slice()].concat();
                if let Ok(Some(bytes)) = overlay.get(&global_key) {
                    codec::from_bytes_canonical::<ActionRules>(&bytes).unwrap_or_default()
                } else {
                    ActionRules::default()
                }
            };

            if service_id == "desktop_agent" && method == "resume@v1" {
                let agent_state = agent_state_opt.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "Missing desktop agent state for resume review verification".to_string(),
                    )
                })?;
                let pending_tool_hash = agent_state.pending_tool_hash.ok_or_else(|| {
                    TransactionError::Invalid(
                        "Missing pending tool hash for resume review verification".to_string(),
                    )
                })?;
                let expected_request_hash =
                    resolve_expected_request_hash(pending_gate_hash_opt, pending_tool_hash);
                expected_request_hash_opt = Some(expected_request_hash);

                let request_key_local = pii::review::request(&expected_request_hash);
                let request_key = [
                    service_namespace_prefix("desktop_agent").as_slice(),
                    request_key_local.as_slice(),
                ]
                .concat();
                let pii_request_opt = overlay
                    .get(&request_key)?
                    .and_then(|bytes| codec::from_bytes_canonical(&bytes).ok());
                if let Some(request) = pii_request_opt.as_ref() {
                    validate_review_request_v3_cim(request)
                        .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                }

                if pii_request_opt.is_some() && approval_grant.is_none() {
                    return Err(TransactionError::Invalid(
                        "Missing approval authority for review request".to_string(),
                    ));
                }

                if let Some(grant) = approval_grant.as_ref() {
                    let expected_policy_hash = compute_policy_hash(&rules)?;
                    let approval_scope = ApprovalScopeContext::new("desktop_agent.resume");
                    validate_registered_approval_grant(
                        &overlay,
                        grant,
                        expected_timestamp_secs.saturating_mul(1000),
                        expected_policy_hash,
                        Some(&approval_scope),
                    )?;
                    validate_resume_review_contract_for_grant_local(
                        expected_request_hash,
                        grant,
                        pii_request_opt.as_ref(),
                        expected_timestamp_secs.saturating_mul(1000),
                    )
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                }
            }

            // Scoped exception grants must verify deterministically before execution.
            if service_id == "desktop_agent" && method == "resume@v1" {
                if let Some(grant) = approval_grant.as_ref().filter(|grant| {
                    matches!(
                        grant.pii_action,
                        Some(PiiApprovalAction::GrantScopedException)
                    )
                }) {
                    let agent_state = agent_state_opt.as_ref().ok_or_else(|| {
                        TransactionError::Invalid(
                            "Missing desktop agent state for scoped exception verification"
                                .to_string(),
                        )
                    })?;

                    let pending_tool_jcs =
                        agent_state.pending_tool_jcs.as_ref().ok_or_else(|| {
                            TransactionError::Invalid(
                                "Missing pending tool for scoped exception verification"
                                    .to_string(),
                            )
                        })?;

                    let mut tool: AgentTool =
                        serde_json::from_slice(pending_tool_jcs).map_err(|e| {
                            TransactionError::Invalid(format!(
                            "Failed to decode pending tool for scoped exception verification: {}",
                            e
                        ))
                        })?;

                    let expected_request_hash = expected_request_hash_opt.ok_or_else(|| {
                        TransactionError::Invalid(
                            "Missing expected request hash for scoped exception verification"
                                .to_string(),
                        )
                    })?;

                    let block_timestamp_secs = expected_timestamp_secs;
                    let mut verified = false;
                    for spec in tool.pii_egress_specs() {
                        let Some(text) = tool.pii_egress_field_mut(spec.field) else {
                            continue;
                        };

                        let risk_surface = to_shared_risk_surface_from_egress(spec.risk_surface);
                        let safety_model = Arc::clone(&safety_model);
                        let (evidence, routed) = inspect_and_route_with_for_target(
                            |input, shared_risk_surface| {
                                let safety_model = safety_model.clone();
                                Box::pin(async move {
                                    let api_risk_surface = match shared_risk_surface {
                                        RiskSurface::LocalProcessing => {
                                            PiiRiskSurface::LocalProcessing
                                        }
                                        RiskSurface::Egress => PiiRiskSurface::Egress,
                                    };
                                    let inspection =
                                        safety_model.inspect_pii(input, api_risk_surface).await?;
                                    Ok(inspection.evidence)
                                })
                            },
                            text,
                            &spec.target,
                            risk_surface,
                            &rules.pii_controls,
                            spec.supports_transform,
                        )
                        .await
                        .map_err(|e| {
                            TransactionError::Invalid(format!(
                                "Scoped exception PII verification failed: {}",
                                e
                            ))
                        })?;

                        if routed.decision_hash != expected_request_hash {
                            continue;
                        }

                        let scoped_exception =
                            if let Some(existing) = grant.scoped_exception.as_ref() {
                                existing.clone()
                            } else {
                                mint_default_scoped_exception(
                                    &evidence,
                                    &spec.target,
                                    risk_surface,
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

                        let usage_key_local =
                            pii::review::exception_usage(&scoped_exception.exception_id);
                        let usage_key = [
                            service_namespace_prefix("desktop_agent").as_slice(),
                            usage_key_local.as_slice(),
                        ]
                        .concat();
                        let raw_usage = overlay.get(&usage_key)?;
                        let uses_consumed = decode_exception_usage_state(raw_usage.as_deref())
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                        verify_scoped_exception_for_decision(
                            &scoped_exception,
                            &evidence,
                            &spec.target,
                            risk_surface,
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

                        check_exception_usage_increment_ok(uses_consumed)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                        verified = true;
                        break;
                    }

                    if !verified {
                        return Err(TransactionError::Invalid(
                            "Scoped exception does not match pending PII decision".to_string(),
                        ));
                    }
                }
            }

            let dummy_request = ioi_types::app::ActionRequest {
                target: ioi_types::app::ActionTarget::Custom(method.clone()),
                params: policy_request_params(method, params),
                context: ioi_types::app::ActionContext {
                    agent_id: "unknown".into(),
                    session_id: session_id_opt,
                    window_id: None,
                },
                nonce: 0,
            };

            let verdict =
                PolicyEngine::evaluate(&rules, &dummy_request, &safety_model, &os_driver).await;

            match verdict {
                Verdict::Allow => {
                    // Proceed
                }
                Verdict::Block => {
                    // [NEW] Emit Block Event
                    if let Some(tx) = event_broadcaster {
                        let _ = tx.send(KernelEvent::FirewallInterception {
                            verdict: "BLOCK".to_string(),
                            target: method.clone(),
                            request_hash: dummy_request.hash(),
                            session_id: session_id_opt,
                        });
                    }
                    return Err(TransactionError::Invalid("Blocked by Policy".into()));
                }
                Verdict::RequireApproval => {
                    if allow_approval_bypass_for_message {
                        tracing::info!(
                            target: "firewall",
                            "Downgrading REQUIRE_APPROVAL to ALLOW for desktop_agent post_message@v1"
                        );
                    } else {
                        let req_hash_bytes = dummy_request.hash();
                        let req_hash_hex = hex::encode(req_hash_bytes);

                        // [NEW] Attempt to extract visual hash from params for the event
                        // This allows the UI to display the screenshot the agent saw when requesting the action.
                        let mut _visual_hash_opt: Option<[u8; 32]> = None;
                        if let Ok(json) =
                            serde_json::from_slice::<serde_json::Value>(&dummy_request.params)
                        {
                            if let Some(hex_hash) =
                                json.get("expected_visual_hash").and_then(|s| s.as_str())
                            {
                                if let Ok(bytes) = hex::decode(hex_hash) {
                                    if bytes.len() == 32 {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&bytes);
                                        _visual_hash_opt = Some(arr);
                                    }
                                }
                            }
                        }

                        // [NEW] Emit RequireApproval Event (Triggers Gate UI)
                        if let Some(tx) = event_broadcaster {
                            let _ = tx.send(KernelEvent::FirewallInterception {
                                verdict: "REQUIRE_APPROVAL".to_string(),
                                target: method.clone(),
                                request_hash: req_hash_bytes,
                                session_id: session_id_opt,
                                // KernelEvent currently doesn't have a visual_hash field in FirewallInterception.
                                // The UI must fetch the StepTrace or reconstruct it.
                                // For now, we rely on the `request_hash` matching the pending tool call in state.
                            });
                        }

                        tracing::info!(target: "firewall", "Gating action {} (Hash: {})", method, req_hash_hex);
                        return Err(TransactionError::PendingApproval(req_hash_hex));
                    }
                }
            }

            let input_str = match std::str::from_utf8(params) {
                Ok(s) => Some(s),
                Err(_) if service_id == "desktop_agent" => None,
                Err(_) => {
                    return Err(TransactionError::Invalid(
                        "PII firewall requires UTF-8 payload for egress evaluation.".to_string(),
                    ))
                }
            };

            if let Some(input_str) = input_str {
                let pii_target = PiiTarget::ServiceCall {
                    service_id: service_id.clone(),
                    method: method.clone(),
                };
                let pii_target_label = pii_target.canonical_label();
                let safety_model = Arc::clone(&safety_model);
                let (evidence, routed) = inspect_and_route_with_for_target(
                    |input, shared_risk_surface| {
                        let safety_model = safety_model.clone();
                        Box::pin(async move {
                            let api_risk_surface = match shared_risk_surface {
                                RiskSurface::LocalProcessing => PiiRiskSurface::LocalProcessing,
                                RiskSurface::Egress => PiiRiskSurface::Egress,
                            };
                            let inspection =
                                safety_model.inspect_pii(input, api_risk_surface).await?;
                            Ok(inspection.evidence)
                        })
                    },
                    input_str,
                    &pii_target,
                    to_shared_risk_surface(PiiRiskSurface::Egress),
                    &rules.pii_controls,
                    false, // Firewall cannot mutate arbitrary service payloads.
                )
                .await
                .map_err(|e| {
                    TransactionError::Invalid(format!("PII inspection failed (fail-closed): {}", e))
                })?;

                if let Some(tx) = event_broadcaster {
                    let _ = tx.send(KernelEvent::PiiDecisionReceipt(
                        ioi_types::app::PiiDecisionReceiptEvent {
                            session_id: session_id_opt,
                            target: pii_target_label.clone(),
                            target_id: Some(pii_target.clone()),
                            risk_surface: "egress".to_string(),
                            decision_hash: routed.decision_hash,
                            decision: routed.decision.clone(),
                            transform_plan_id: routed
                                .transform_plan
                                .as_ref()
                                .map(|p| p.plan_id.clone()),
                            span_count: evidence.spans.len() as u32,
                            ambiguous: evidence.ambiguous,
                            stage2_kind: routed.stage2_decision.as_ref().map(|d| {
                                match d {
                                    ioi_types::app::agentic::Stage2Decision::ApproveTransformPlan {
                                        ..
                                    } => "approve_transform_plan",
                                    ioi_types::app::agentic::Stage2Decision::Deny { .. } => "deny",
                                    ioi_types::app::agentic::Stage2Decision::RequestMoreInfo {
                                        ..
                                    } => "request_more_info",
                                    ioi_types::app::agentic::Stage2Decision::GrantScopedException {
                                        ..
                                    } => "grant_scoped_exception",
                                }
                                .to_string()
                            }),
                            assist_invoked: routed.assist.assist_invoked,
                            assist_applied: routed.assist.assist_applied,
                            assist_kind: routed.assist.assist_kind.clone(),
                            assist_version: routed.assist.assist_version.clone(),
                            assist_identity_hash: routed.assist.assist_identity_hash,
                            assist_input_graph_hash: routed.assist.assist_input_graph_hash,
                            assist_output_graph_hash: routed.assist.assist_output_graph_hash,
                        },
                    ));
                }

                match routed.decision {
                    ioi_types::app::agentic::FirewallDecision::Allow
                    | ioi_types::app::agentic::FirewallDecision::AllowLocalOnly => {}
                    ioi_types::app::agentic::FirewallDecision::RedactThenAllow
                    | ioi_types::app::agentic::FirewallDecision::TokenizeThenAllow
                    | ioi_types::app::agentic::FirewallDecision::Quarantine
                    | ioi_types::app::agentic::FirewallDecision::RequireUserReview => {
                        tracing::warn!(
                            target: "firewall",
                            "PII router gated transaction (decision={:?}, stage2={:?}, spans={}, ambiguous={}).",
                            routed.decision,
                            routed.stage2_decision,
                            evidence.spans.len(),
                            evidence.ambiguous
                        );

                        let material = build_decision_material(
                            &evidence,
                            &routed.decision,
                            routed.transform_plan.as_ref(),
                            routed.stage2_decision.as_ref(),
                            to_shared_risk_surface(PiiRiskSurface::Egress),
                            &pii_target,
                            false,
                            &routed.assist,
                        );
                        let summary = build_review_summary(
                            &evidence,
                            &pii_target,
                            routed.stage2_decision.as_ref(),
                        );
                        let created_at_ms = expected_timestamp_secs.saturating_mul(1000);
                        let deadline_ms = created_at_ms
                            .saturating_add(rules.pii_controls.stage2_timeout_ms as u64);

                        if let Some(tx) = event_broadcaster {
                            let _ = tx.send(KernelEvent::PiiReviewRequested {
                                decision_hash: routed.decision_hash,
                                material,
                                summary,
                                deadline_ms,
                                session_id: session_id_opt,
                            });
                            let _ = tx.send(KernelEvent::FirewallInterception {
                                verdict: "REQUIRE_APPROVAL".to_string(),
                                target: pii_target_label,
                                request_hash: routed.decision_hash,
                                session_id: session_id_opt,
                            });
                        }

                        return Err(TransactionError::PendingApproval(hex::encode(
                            routed.decision_hash,
                        )));
                    }
                    ioi_types::app::agentic::FirewallDecision::Deny => {
                        tracing::warn!(
                            target: "firewall",
                            "PII router denied transaction (stage2={:?}).",
                            routed.stage2_decision
                        );
                        return Err(TransactionError::Invalid(
                            "PII firewall denied raw egress payload.".to_string(),
                        ));
                    }
                }
            }
        }
    }

    // --- LAYER 4: SERVICE DECORATORS ---
    let decorators: Vec<(&str, &dyn ioi_api::transaction::decorator::TxDecorator)> = services
        .services_in_deterministic_order()
        .filter_map(|s| s.as_tx_decorator().map(|d| (s.id(), d)))
        .collect();

    for (id, decorator) in &decorators {
        let meta_key = active_service_key(id);
        let meta_bytes = overlay.get(&meta_key)?.ok_or_else(|| {
            TransactionError::Unsupported(format!("Service '{}' is not active", id))
        })?;
        let meta: ActiveServiceMeta = ioi_types::codec::from_bytes_canonical(&meta_bytes)?;
        let prefix = service_namespace_prefix(id);
        let namespaced_view = ReadOnlyNamespacedStateAccess::new(&overlay, prefix, &meta);

        decorator
            .validate_ante(&namespaced_view, tx, &tx_ctx)
            .await?;
    }

    // --- LAYER 5: STATE MUTATION ---
    if !is_simulation {
        for (id, decorator) in decorators {
            let meta_key = active_service_key(id);
            let meta_bytes = overlay.get(&meta_key)?.unwrap();
            let meta: ActiveServiceMeta = ioi_types::codec::from_bytes_canonical(&meta_bytes)?;
            let prefix = service_namespace_prefix(id);
            let mut namespaced_write = NamespacedStateAccess::new(&mut overlay, prefix, &meta);

            decorator
                .write_ante(&mut namespaced_write, tx, &tx_ctx)
                .await?;
        }
        nonce::bump_nonce(&mut overlay, tx)?;
    }

    Ok(())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
