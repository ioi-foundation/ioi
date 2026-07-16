//! Shared authenticated governed-decision boundary.
//!
//! This is a mechanical extraction of the production wallet.network resolution, frozen
//! authority-snapshot verification, approval-grant binding, and exact-coordinate replay logic
//! first proven by the room-participation plane (#74). Policy stays with each caller through an
//! explicit contract: scope prefix, hash domains, governance labels, and wire-code prefix are
//! caller-owned. The wallet.network resolver semantics are not widened here.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::Json;
use ioi_services::agentic::runtime::kernel::approval::{
    verify_wallet_approval_grant_binding, ApprovalScopeContext, AuthorityScopeMatcher,
};
use ioi_types::app::{
    ApprovalGrant, PrincipalAuthorityBindingCoordinates, PrincipalAuthorityBindingProofV1,
    PrincipalAuthorityKind, PrincipalAuthorityResolutionReceipt, PrincipalAuthorityResolutionV1,
    ResolvePrincipalAuthorityParams,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::outcome_room_routes::record_output_hash;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Governance {
    Host,
    Participant,
}

#[derive(Clone, Copy)]
pub(crate) struct AuthorityContract {
    pub(crate) scope_prefix: &'static str,
    pub(crate) policy_domain: &'static str,
    pub(crate) request_domain: &'static str,
    pub(crate) resolution_domain: &'static str,
    pub(crate) code_prefix: &'static str,
    pub(crate) host_label: &'static str,
    pub(crate) participant_label: &'static str,
}

impl AuthorityContract {
    pub(crate) fn governance_label(self, governance: Governance) -> &'static str {
        match governance {
            Governance::Host => self.host_label,
            Governance::Participant => self.participant_label,
        }
    }

    pub(crate) fn operation_scope(self, op: &str) -> String {
        format!("{}.{op}", self.scope_prefix)
    }

    fn code(self, suffix: &str) -> String {
        format!("{}_{}", self.code_prefix, suffix)
    }
}

/// Byte-stable authority evidence retained by governed receipts and intents.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DecisionEvidence {
    pub(crate) acting_authority_id: Value,
    pub(crate) grant_ref: String,
    pub(crate) policy_hash: String,
    pub(crate) request_hash: String,
    pub(crate) effect_hash: String,
    pub(crate) authorized_effect: Value,
    pub(crate) wallet_approval_grant: Value,
    pub(crate) authority_binding: Value,
}

/// One online authorization also returns wallet.network's authenticated committed time. Callers
/// may use it as a lease clock; it is not added to legacy #74 evidence or hash domains.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AuthorizedDecision {
    pub(crate) evidence: DecisionEvidence,
    pub(crate) resolved_at_ms: u64,
}

pub(crate) struct VerifiedAuthorityResolution {
    pub(crate) resolution: PrincipalAuthorityResolutionV1,
    pub(crate) authority_binding: Value,
}

fn local_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn nonce_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

pub(crate) fn decision_policy_hash(
    contract: AuthorityContract,
    governance: Governance,
    room_ref: &str,
    required_authority: &str,
    op: &str,
) -> String {
    record_output_hash(
        &json!({
            "domain": contract.policy_domain,
            "governance": contract.governance_label(governance),
            "outcome_room_ref": room_ref,
            "required_authority_ref": required_authority,
            "required_scope": contract.operation_scope(op),
        }),
        &[],
    )
}

pub(crate) fn decision_request_hash(
    contract: AuthorityContract,
    governance: Governance,
    subject_ref: &str,
    op: &str,
    revision: u64,
    required_authority: &str,
    effect_hash: &str,
) -> String {
    record_output_hash(
        &json!({
            "domain": contract.request_domain,
            "governance": contract.governance_label(governance),
            "subject_ref": subject_ref,
            "op": op,
            "revision": revision,
            "required_authority_ref": required_authority,
            "required_scope": contract.operation_scope(op),
            "effect_hash": effect_hash,
        }),
        &[],
    )
}

pub(crate) fn decision_effect_hash(contract: AuthorityContract, effect: &Value) -> String {
    record_output_hash(
        &json!({
            "domain": format!("{}.effect.v1", contract.request_domain),
            "effect": effect,
        }),
        &[],
    )
}

pub(crate) fn resolution_request_id(
    contract: AuthorityContract,
    required_authority_ref: &str,
    required_scope: &str,
    expected: Option<&PrincipalAuthorityBindingCoordinates>,
) -> [u8; 32] {
    let material = json!({
        "domain": contract.resolution_domain,
        "principal_ref": required_authority_ref,
        "required_scope": required_scope,
        "expected_coordinates": expected,
        "nonce": nonce_nanos(),
    });
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(
        serde_json::to_vec(&material).unwrap_or_default(),
    ));
    if out == [0u8; 32] {
        out[31] = 1;
    }
    out
}

pub(crate) fn stable_authority_binding(
    resolution: &PrincipalAuthorityResolutionV1,
    binding_proof: &PrincipalAuthorityBindingProofV1,
) -> Value {
    json!({
        "schema_version": resolution.schema_version,
        "principal_ref": resolution.principal_ref,
        "authority_kind": resolution.authority_kind,
        "coordinates": resolution.coordinates,
        "required_scope": resolution.required_scope,
        "matched_scope": resolution.matched_scope,
        "approval_authority": resolution.approval_authority,
        "approval_authority_snapshot_hash": resolution.approval_authority_snapshot_hash,
        "binding_proof": binding_proof,
    })
}

pub(crate) fn validate_authority_resolution(
    request: &ResolvePrincipalAuthorityParams,
    receipt: PrincipalAuthorityResolutionReceipt,
    binding_proof: PrincipalAuthorityBindingProofV1,
) -> Result<VerifiedAuthorityResolution, String> {
    if receipt.request_id != request.request_id {
        return Err("wallet resolver returned a receipt for a different request_id".into());
    }
    let resolution = receipt.resolution;
    if resolution.schema_version != 1
        || receipt.resolved_at_ms != resolution.resolved_at_ms
        || resolution.principal_ref != request.principal_ref
        || resolution.authority_kind != PrincipalAuthorityKind::Approval
        || resolution.required_scope != request.required_scope
    {
        return Err(
            "wallet resolver returned a foreign principal, kind, scope, or timestamp".into(),
        );
    }
    if request
        .expected_coordinates
        .as_ref()
        .is_some_and(|expected| expected != &resolution.coordinates)
    {
        return Err("wallet resolver returned coordinates different from the replay pin".into());
    }
    if resolution.coordinates.binding_version == 0
        || resolution.coordinates.binding_hash == [0u8; 32]
        || resolution.coordinates.binding_ref
            != format!(
                "wallet.network://principal-authority-binding/{}",
                hex::encode(resolution.coordinates.binding_hash)
            )
    {
        return Err("wallet resolver returned noncanonical immutable coordinates".into());
    }
    let authority = &resolution.approval_authority;
    authority.verify().map_err(|error| {
        format!("wallet resolver returned an invalid authority snapshot: {error}")
    })?;
    if resolution.approval_authority_snapshot_hash == [0u8; 32]
        || resolution.mutation_audit_event_id == [0u8; 32]
        || resolution.mutation_audit_event_hash == [0u8; 32]
        || authority
            .artifact_hash()
            .map_err(|error| error.to_string())?
            != resolution.approval_authority_snapshot_hash
        || authority.authority_id != resolution.authority_id
        || authority.public_key != resolution.authority_public_key
        || authority.signature_suite != resolution.authority_signature_suite
    {
        return Err("wallet resolver authority snapshot/hash/signer tuple mismatch".into());
    }
    // Preserved #74 semantics: local time is used only to reject an already-expired authority
    // snapshot/grant. Work-claim issue/expiry calculations use `resolution.resolved_at_ms`.
    let now_ms = local_now_ms();
    if authority.revoked
        || authority.expires_at < resolution.resolved_at_ms
        || authority.expires_at < now_ms
    {
        return Err("wallet resolver returned a revoked or expired authority snapshot".into());
    }
    let decision = AuthorityScopeMatcher::evaluate(
        authority,
        &ApprovalScopeContext::new(request.required_scope.clone()),
    );
    if !decision.allowed
        || decision.matched_scope.as_deref() != Some(resolution.matched_scope.as_str())
    {
        return Err(
            "wallet resolver matched_scope is not the canonical snapshot scope match".into(),
        );
    }
    let authority_binding = stable_authority_binding(&resolution, &binding_proof);
    Ok(VerifiedAuthorityResolution {
        resolution,
        authority_binding,
    })
}

pub(crate) async fn resolve_required_authority(
    contract: AuthorityContract,
    required_authority_ref: &str,
    required_scope: &str,
    expected_coordinates: Option<PrincipalAuthorityBindingCoordinates>,
) -> Result<VerifiedAuthorityResolution, (StatusCode, String, String)> {
    let request = ResolvePrincipalAuthorityParams {
        request_id: resolution_request_id(
            contract,
            required_authority_ref,
            required_scope,
            expected_coordinates.as_ref(),
        ),
        principal_ref: required_authority_ref.to_string(),
        authority_kind: PrincipalAuthorityKind::Approval,
        required_scope: required_scope.to_string(),
        expected_coordinates,
    };
    let authenticated =
        super::wallet_network_capability_client::resolve_principal_authority(request.clone())
            .await
            .map_err(|error| {
                use super::wallet_network_capability_client::ResolveError;
                match error {
                    ResolveError::NotConfigured(message) => (
                        StatusCode::NOT_IMPLEMENTED,
                        contract.code("authority_binding_unavailable"),
                        message,
                    ),
                    ResolveError::Unavailable(message) => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        contract.code("authority_resolver_unavailable"),
                        message,
                    ),
                    ResolveError::Refused(message) => (
                        StatusCode::FORBIDDEN,
                        contract.code("authority_resolution_refused"),
                        message,
                    ),
                    ResolveError::Invalid(message) => (
                        StatusCode::BAD_GATEWAY,
                        contract.code("authority_resolution_invalid"),
                        message,
                    ),
                }
            })?;
    validate_authority_resolution(&request, authenticated.receipt, authenticated.binding_proof)
        .map_err(|message| {
            (
                StatusCode::BAD_GATEWAY,
                contract.code("authority_resolution_invalid"),
                message,
            )
        })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn authorize_decision_for_resolution(
    contract: AuthorityContract,
    body: &Value,
    governance: Governance,
    room_ref: &str,
    required_authority: &str,
    verified_resolution: &VerifiedAuthorityResolution,
    subject_ref: &str,
    op: &str,
    revision: u64,
    effect: &Value,
) -> Result<AuthorizedDecision, (StatusCode, Json<Value>)> {
    let resolution = &verified_resolution.resolution;
    let policy_hash = decision_policy_hash(contract, governance, room_ref, required_authority, op);
    let effect_hash = decision_effect_hash(contract, effect);
    let request_hash = decision_request_hash(
        contract,
        governance,
        subject_ref,
        op,
        revision,
        required_authority,
        &effect_hash,
    );
    let grant = body
        .get("wallet_approval_grant")
        .cloned()
        .unwrap_or(Value::Null);
    let binding = if grant.is_null() {
        Err("a wallet_approval_grant is required".to_string())
    } else {
        verify_wallet_approval_grant_binding(
            &grant,
            Some(local_now_ms()),
            Some(&policy_hash),
            Some(&request_hash),
        )
        .and_then(|binding| {
            let parsed: ApprovalGrant = serde_json::from_value(grant.clone())
                .map_err(|error| format!("approval grant is not canonical: {error}"))?;
            let authority = &resolution.approval_authority;
            if parsed.authority_id != authority.authority_id
                || parsed.approver_public_key != authority.public_key
                || parsed.approver_suite != authority.signature_suite
            {
                return Err(format!(
                    "approval grant signer tuple does not match the frozen authority snapshot bound to '{required_authority}'"
                ));
            }
            Ok(binding)
        })
    };
    match binding {
        Ok(binding) => Ok(AuthorizedDecision {
            evidence: DecisionEvidence {
                acting_authority_id: grant.get("authority_id").cloned().unwrap_or(Value::Null),
                grant_ref: binding.grant_ref,
                policy_hash,
                request_hash,
                effect_hash,
                authorized_effect: effect.clone(),
                wallet_approval_grant: grant,
                authority_binding: verified_resolution.authority_binding.clone(),
            },
            resolved_at_ms: resolution.resolved_at_ms,
        }),
        Err(reason) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": {
                    "code": match governance {
                        Governance::Host => contract.code("host_authority_required"),
                        Governance::Participant => contract.code("participant_authority_required"),
                    },
                    "message": format!("'{op}' on '{subject_ref}' is a governed {} decision ({reason}). Bind a wallet approval grant from the authority resolved for '{required_authority}' to policy_hash + request_hash.", contract.governance_label(governance)),
                    "governance": contract.governance_label(governance),
                    "required_authority_ref": required_authority,
                    "required_scope": contract.operation_scope(op),
                    "approval": { "policy_hash": policy_hash, "request_hash": request_hash, "effect_hash": effect_hash },
                    "runtimeTruthSource": "daemon-runtime"
                }
            })),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_decision(
    contract: AuthorityContract,
    body: &Value,
    governance: Governance,
    room_ref: &str,
    required_authority: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
    effect: &Value,
) -> Result<AuthorizedDecision, (StatusCode, Json<Value>)> {
    let policy_hash = decision_policy_hash(contract, governance, room_ref, required_authority, op);
    let effect_hash = decision_effect_hash(contract, effect);
    let request_hash = decision_request_hash(
        contract,
        governance,
        subject_ref,
        op,
        revision,
        required_authority,
        &effect_hash,
    );
    let required_scope = contract.operation_scope(op);
    let resolution = match resolve_required_authority(
        contract,
        required_authority,
        &required_scope,
        None,
    )
    .await
    {
        Ok(resolution) => resolution,
        Err((status, code, reason)) => {
            return Err((
                status,
                Json(json!({
                    "error": {
                        "code": code,
                        "message": format!("'{op}' on '{subject_ref}' is unavailable: {reason}. Signature + request/policy/effect hash verification cannot establish who may act for a domain or participant."),
                        "governance": contract.governance_label(governance),
                        "required_authority_ref": required_authority,
                        "required_scope": required_scope,
                        "approval": { "policy_hash": policy_hash, "request_hash": request_hash, "effect_hash": effect_hash },
                        "runtimeTruthSource": "daemon-runtime"
                    }
                })),
            ));
        }
    };
    authorize_decision_for_resolution(
        contract,
        body,
        governance,
        room_ref,
        required_authority,
        &resolution,
        subject_ref,
        op,
        revision,
        effect,
    )
}

pub(crate) fn sealed_evidence(receipt: &Value) -> DecisionEvidence {
    DecisionEvidence {
        acting_authority_id: receipt.get("actor_id").cloned().unwrap_or(Value::Null),
        grant_ref: receipt
            .get("authority_grant_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        policy_hash: receipt
            .get("policy_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        request_hash: receipt
            .get("input_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        effect_hash: receipt
            .get("effect_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        authorized_effect: receipt
            .get("authorized_effect")
            .cloned()
            .unwrap_or(Value::Null),
        wallet_approval_grant: receipt
            .get("wallet_approval_grant")
            .cloned()
            .unwrap_or(Value::Null),
        authority_binding: receipt
            .get("principal_authority_binding")
            .cloned()
            .unwrap_or(Value::Null),
    }
}

pub(crate) fn append_evidence(receipt: &mut Value, authorized: &AuthorizedDecision) {
    let evidence = &authorized.evidence;
    if let Some(object) = receipt.as_object_mut() {
        object.insert("actor_id".into(), evidence.acting_authority_id.clone());
        object.insert("authority_grant_id".into(), json!(evidence.grant_ref));
        object.insert("policy_hash".into(), json!(evidence.policy_hash));
        object.insert("input_hash".into(), json!(evidence.request_hash));
        object.insert("effect_hash".into(), json!(evidence.effect_hash));
        object.insert(
            "authorized_effect".into(),
            evidence.authorized_effect.clone(),
        );
        object.insert(
            "wallet_approval_grant".into(),
            evidence.wallet_approval_grant.clone(),
        );
        object.insert(
            "principal_authority_binding".into(),
            evidence.authority_binding.clone(),
        );
        object.insert(
            "authority_resolved_at_ms".into(),
            json!(authorized.resolved_at_ms),
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn reauthorize_sealed_receipt(
    contract: AuthorityContract,
    receipt: &Value,
    governance: Governance,
    room_ref: &str,
    required_authority: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
    effect: &Value,
) -> Result<u64, String> {
    let sealed = sealed_evidence(receipt);
    if sealed.wallet_approval_grant.is_null() || !sealed.authority_binding.is_object() {
        return Err("the governed intent does not retain its complete signed grant and authority binding tuple".into());
    }
    validate_sealed_effect(contract, receipt, effect)?;
    let required_scope = contract.operation_scope(op);
    if sealed
        .authority_binding
        .get("principal_ref")
        .and_then(Value::as_str)
        != Some(required_authority)
        || sealed
            .authority_binding
            .get("required_scope")
            .and_then(Value::as_str)
            != Some(required_scope.as_str())
    {
        return Err(
            "the governed intent authority tuple names a foreign principal or operation scope"
                .into(),
        );
    }
    let coordinates: PrincipalAuthorityBindingCoordinates = serde_json::from_value(
        sealed
            .authority_binding
            .get("coordinates")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .map_err(|error| format!("the governed intent binding coordinates are malformed: {error}"))?;
    let resolution = resolve_required_authority(
        contract,
        required_authority,
        &required_scope,
        Some(coordinates),
    )
    .await
    .map_err(|(_, code, message)| format!("{code}: {message}"))?;
    if resolution.authority_binding != sealed.authority_binding {
        return Err("wallet.network no longer resolves the exact snapshot, scope, and immutable coordinates pinned by the governed intent".into());
    }
    let body = json!({ "wallet_approval_grant": sealed.wallet_approval_grant });
    let live = authorize_decision_for_resolution(
        contract,
        &body,
        governance,
        room_ref,
        required_authority,
        &resolution,
        subject_ref,
        op,
        revision,
        effect,
    )
    .map_err(|(_, Json(payload))| {
        payload
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("the retained approval grant no longer verifies")
            .to_string()
    })?;
    if live.evidence != sealed {
        return Err("the reverified grant and resolution do not reconstruct the exact sealed authority tuple".into());
    }
    Ok(live.resolved_at_ms)
}

pub(crate) fn validate_sealed_effect(
    contract: AuthorityContract,
    receipt: &Value,
    expected_effect: &Value,
) -> Result<(), String> {
    #[cfg(test)]
    if receipt.get("wallet_approval_grant") == Some(&Value::Null)
        && receipt.get("principal_authority_binding") == Some(&Value::Null)
    {
        // Lower-seam transaction tests use a deliberately non-authorizing tuple so they can
        // exercise storage reconstruction in isolation. Such a tuple cannot reach production
        // replay: reauthorization rejects it before any successor can be committed.
        return Ok(());
    }
    let sealed_effect = receipt
        .get("authorized_effect")
        .ok_or_else(|| "governed receipt lacks authorized_effect".to_string())?;
    let sealed_hash = receipt
        .get("effect_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "governed receipt lacks effect_hash".to_string())?;
    let expected_hash = decision_effect_hash(contract, expected_effect);
    if sealed_effect != expected_effect || sealed_hash != expected_hash {
        return Err(
            "governed receipt effect/hash does not match the deterministic mutation effect".into(),
        );
    }
    Ok(())
}

pub(crate) fn decision_authority_posture(contract: AuthorityContract) -> Value {
    let configured = super::wallet_network_capability_client::configured();
    json!({
        "status": if configured { "configured" } else { "not_configured" },
        "code": if configured { contract.code("authority_binding_configured") } else { contract.code("authority_binding_not_configured") },
        "reachability": "not_probed",
        "resolver": "wallet.network principal-authority binding v1 via pinned TLS and a signed CallService capability transaction",
        "effect": "governed decisions attempt authenticated wallet.network resolution and fail closed before mutation when wallet.network is unavailable or refuses resolution",
        "pending_governed_intents": if configured { "bounded post-readiness replay attempts authenticated re-resolution against exact immutable coordinates; failures retain intents unchanged" } else { "retained fail-closed until wallet.network is configured" },
        "runtimeTruthSource": "daemon-runtime",
    })
}
