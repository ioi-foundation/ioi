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
use ioi_services::wallet_network::{
    ApprovalGrantConsumptionReceipt, ConsumeApprovalGrantForEffectV2Params,
    ExpectedPrincipalAuthorityBinding,
};
use ioi_types::app::{
    ApprovalAuthority, ApprovalGrant, PrincipalAuthorityBindingCoordinates,
    PrincipalAuthorityBindingProofV1, PrincipalAuthorityKind, PrincipalAuthorityResolutionReceipt,
    PrincipalAuthorityResolutionV1, ResolvePrincipalAuthorityParams,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::outcome_room_routes::record_output_hash;

const AUTHORITY_ADMISSION_INTENT_FAMILY: &str = "authority-admission-intents";
static AUTHORITY_ADMISSION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Governance {
    Host,
    Participant,
}

/// Scope prefix of the source-control publication family. Disjoint from every
/// other family in `operation_scope`: no lifecycle, environment, membership,
/// writer, node, or enrollment scope shares this root.
pub(crate) const SCM_PUBLICATION_SCOPE_PREFIX: &str = "scope:scm.publication";
/// The one scope that authorizes advancing a remote target ref.
pub(crate) const SCM_PUBLICATION_ADVANCE_TARGET_REF_SCOPE: &str =
    "scope:scm.publication.advance-target-ref";
/// The one scope that authorizes opening a review request on the remote.
pub(crate) const SCM_PUBLICATION_OPEN_REVIEW_REQUEST_SCOPE: &str =
    "scope:scm.publication.open-review-request";
/// The source-control publication authority contract.
pub(crate) const SCM_PUBLICATION_AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: SCM_PUBLICATION_SCOPE_PREFIX,
    policy_domain: "hypervisor.scm.publication.policy.v1",
    request_domain: "hypervisor.scm.publication.request.v1",
    resolution_domain: "hypervisor.scm.publication.resolution.v1",
    code_prefix: "scm_publication",
    host_label: "estate",
    participant_label: "delegate",
};

/// Source-neutral live-route authority contract used while legacy route families migrate onto
/// the same wallet-owned resolution and consumption transaction as qualified owner paths.
pub(crate) const LIVE_ROUTE_AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "scope:hypervisor.live-route",
    policy_domain: "hypervisor.live-route.policy.v1",
    request_domain: "hypervisor.live-route.request.v1",
    resolution_domain: "hypervisor.live-route.resolution.v1",
    code_prefix: "live_route",
    host_label: "deployment",
    participant_label: "holder",
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorityPolicyContext<'a> {
    OutcomeRoom {
        outcome_room_ref: &'a str,
    },
    SystemGenesis {
        system_id: &'a str,
        genesis_id: &'a str,
    },
    HypervisorOsNode {
        estate_namespace: &'a str,
        node_id: &'a str,
    },
    HypervisorEnvironment {
        estate_namespace: &'a str,
        subject_ref: &'a str,
    },
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
        // Source-control publication owns a scope family disjoint from every
        // local plane: advancing a REMOTE target ref and opening a review
        // request on someone else's host are two distinct authorities, and
        // neither is any lifecycle, environment, membership, or writer scope.
        if self.scope_prefix == SCM_PUBLICATION_SCOPE_PREFIX {
            return match op {
                "advance_target_ref" => SCM_PUBLICATION_ADVANCE_TARGET_REF_SCOPE.to_owned(),
                "open_review_request" => SCM_PUBLICATION_OPEN_REVIEW_REQUEST_SCOPE.to_owned(),
                _ => format!("{SCM_PUBLICATION_SCOPE_PREFIX}.{op}"),
            };
        }
        // Named M1.5d continuity and local-enrollment operations have owner
        // scopes deliberately disjoint from the generic lifecycle family.
        // Keep the mapping here because this function owns every policy,
        // request, live-resolution, and sealed-replay scope coordinate.
        if self.scope_prefix != "scope:autonomous_system.lifecycle" {
            return format!("{}.{op}", self.scope_prefix);
        }
        match op {
            "initiate_succession"
            | "complete_succession"
            | "migrate"
            | "initiate_dissolution"
            | "open_dissolution_disposition"
            | "record_dissolution_domain_outcome"
            | "complete_dissolution" => {
                format!("scope:autonomous_system.continuity.{op}")
            }
            "acknowledge_migration_destination" => {
                "scope:autonomous_system.continuity.migration_destination_acknowledge".to_owned()
            }
            "admit_node"
            | "attest_readiness"
            | "advance_catchup"
            | "promote_role"
            | "drain_node"
            | "remove_node"
            | "declare_desired_topology" => {
                format!("scope:autonomous_system.membership.{op}")
            }
            "admit_node_identity"
            | "submit_boot_receipt"
            | "mark_node_ready"
            | "declare_boot_profile"
            | "declare_temporal_profile" => {
                format!("scope:hypervisoros.node.{op}")
            }
            "genesis"
            | "same_node_restore"
            | "replacement_restore"
            | "promotion"
            | "declare_failover_profile"
            | "resolve_lost_suffix" => {
                format!("scope:autonomous_system.writer.{op}")
            }
            "declare_route_binding"
            | "record_backup"
            | "declare_change_plan"
            | "advance_change_plan_stage"
            | "open_cleanup_obligation"
            | "satisfy_cleanup_obligation"
            | "escalate_cleanup_obligation" => {
                format!("scope:hypervisor_environment.{op}")
            }
            "enroll_local" => "scope:autonomous_system.network_enrollment.local.enroll".to_owned(),
            "exit_local_enrollment" => {
                "scope:autonomous_system.network_enrollment.local.exit".to_owned()
            }
            _ => format!("{}.{op}", self.scope_prefix),
        }
    }

    fn code(self, suffix: &str) -> String {
        format!("{}_{}", self.code_prefix, suffix)
    }
}

/// Byte-stable authority evidence retained by governed receipts and intents.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct AuthorizedDecision {
    pub(crate) evidence: DecisionEvidence,
    pub(crate) resolved_at_ms: u64,
}

pub(crate) struct AdmittedDeploymentGrant {
    pub(crate) authorized: AuthorizedDecision,
    pub(crate) admission_intent_ref: String,
}

/// Durable final-invocation disposition carried on the admission-intent record.
///
/// `admitted` is what a successful consumption leaves behind: authority is spent and no invoker
/// has claimed it. `claimed` is written durably BEFORE the final invoker is entered, so a daemon
/// that dies mid-dispatch leaves proof that an external effect MAY already have happened.
/// `invoked` and `refused` are terminal. `reconciliation_required` is the honest Unknown: a claim
/// belonging to a previous process was found, so the operation is never automatically re-invoked
/// and its spent usage is never automatically refunded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinalInvocationDisposition {
    Admitted,
    Claimed,
    Invoked,
    Refused,
    ReconciliationRequired,
}

impl FinalInvocationDisposition {
    fn parse(value: Option<&str>) -> Option<Self> {
        Some(match value? {
            "admitted" => Self::Admitted,
            "claimed" => Self::Claimed,
            "invoked" => Self::Invoked,
            "refused" => Self::Refused,
            "reconciliation_required" => Self::ReconciliationRequired,
            _ => return None,
        })
    }

    fn label(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Claimed => "claimed",
            Self::Invoked => "invoked",
            Self::Refused => "refused",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }
}

/// A single-use right to enter one final invoker for one admitted effect. Holding this value is
/// the only proof that the durable `claimed` transition was written before dispatch.
pub(crate) struct FinalInvocationClaim {
    reference: String,
    claim_id: String,
    effect_hash: String,
    invoker_label: String,
}

impl FinalInvocationClaim {
    pub(crate) fn claim_id(&self) -> &str {
        &self.claim_id
    }

    pub(crate) fn reference(&self) -> &str {
        &self.reference
    }

    pub(crate) fn effect_hash(&self) -> &str {
        &self.effect_hash
    }
}

/// Identifies this daemon process. A `claimed` record carrying THIS id belongs to a request that
/// is still in flight here; one carrying any other id belongs to a process that died mid-dispatch.
fn process_incarnation_id() -> &'static str {
    static INCARNATION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    INCARNATION.get_or_init(|| format!("inc_{:032x}", nonce_nanos()))
}

pub(crate) struct VerifiedAuthorityResolution {
    pub(crate) resolution: PrincipalAuthorityResolutionV1,
    pub(crate) authority_binding: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StableAuthorityBindingV1 {
    schema_version: u16,
    principal_ref: String,
    authority_kind: PrincipalAuthorityKind,
    coordinates: PrincipalAuthorityBindingCoordinates,
    required_scope: String,
    matched_scope: String,
    approval_authority: ApprovalAuthority,
    approval_authority_snapshot_hash: [u8; 32],
    binding_proof: PrincipalAuthorityBindingProofV1,
}

const APPROVAL_GRANT_FIELDS: &[&str] = &[
    "schema_version",
    "authority_id",
    "request_hash",
    "policy_hash",
    "audience",
    "nonce",
    "counter",
    "expires_at",
    "max_usages",
    "window_id",
    "pii_action",
    "scoped_exception",
    "review_request_hash",
    "approver_public_key",
    "approver_sig",
    "approver_suite",
];

/// Parse the accepted ApprovalGrant JSON ABI, reject undeclared fields, and return the one
/// canonical typed projection retained by new evidence. Explicit null and omission remain
/// equivalent for optional legacy fields.
pub(crate) fn canonicalize_approval_grant(value: &Value) -> Result<(ApprovalGrant, Value), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "approval grant must be one JSON object".to_string())?;
    if let Some(field) = object
        .keys()
        .find(|field| !APPROVAL_GRANT_FIELDS.contains(&field.as_str()))
    {
        return Err(format!(
            "approval grant contains undeclared field '{field}'"
        ));
    }
    let parsed: ApprovalGrant = serde_json::from_value(value.clone())
        .map_err(|error| format!("approval grant is not canonical: {error}"))?;
    let canonical = serde_json::to_value(&parsed)
        .map_err(|error| format!("approval grant cannot be serialized canonically: {error}"))?;
    let mut normalized = value.clone();
    let normalized_object = normalized
        .as_object_mut()
        .expect("approval grant object was checked above");
    for field in [
        "window_id",
        "pii_action",
        "scoped_exception",
        "review_request_hash",
    ] {
        if normalized_object.get(field).is_some_and(Value::is_null) {
            normalized_object.remove(field);
        }
    }
    if canonical != normalized {
        return Err(
            "approval grant differs from its closed canonical typed projection".to_string(),
        );
    }
    Ok((parsed, canonical))
}

/// Validate the complete retained wallet.network binding without treating its untrusted JSON
/// envelope as evidence. Reauthorization callers additionally resolve and byte-compare this
/// projection against wallet.network's authenticated current resolution.
pub(crate) fn canonicalize_authority_binding(
    value: &Value,
    resolved_at_ms: u64,
) -> Result<Value, String> {
    let binding: StableAuthorityBindingV1 = serde_json::from_value(value.clone())
        .map_err(|error| format!("principal-authority binding is not closed and typed: {error}"))?;
    let canonical = serde_json::to_value(&binding).map_err(|error| {
        format!("principal-authority binding cannot be serialized canonically: {error}")
    })?;
    if canonical != *value {
        return Err(
            "principal-authority binding differs from its closed canonical typed projection"
                .to_string(),
        );
    }
    if binding.schema_version != 1 || binding.authority_kind != PrincipalAuthorityKind::Approval {
        return Err("principal-authority binding has an unsupported version or kind".to_string());
    }
    binding
        .binding_proof
        .verify_active_at(resolved_at_ms)
        .map_err(|error| format!("principal-authority binding proof is not active: {error}"))?;
    binding
        .binding_proof
        .verify_authority_snapshot(&binding.approval_authority)
        .map_err(|error| {
            format!(
                "principal-authority binding proof does not bind its authority snapshot: {error}"
            )
        })?;
    let statement = &binding.binding_proof.statement;
    if binding.coordinates != binding.binding_proof.coordinates()
        || binding.principal_ref != statement.principal_ref
        || binding.authority_kind != statement.authority_kind
        || binding.approval_authority_snapshot_hash != statement.approval_authority_snapshot_hash
    {
        return Err(
            "principal-authority binding does not match its immutable proof coordinates and statement"
                .to_string(),
        );
    }
    let decision = AuthorityScopeMatcher::evaluate(
        &binding.approval_authority,
        &ApprovalScopeContext::new(binding.required_scope.clone()),
    );
    if !decision.allowed
        || decision.matched_scope.as_deref() != Some(binding.matched_scope.as_str())
    {
        return Err(
            "principal-authority binding matched_scope is not the canonical authority scope match"
                .to_string(),
        );
    }
    Ok(canonical)
}

pub(crate) fn verify_retained_authority_binding_root(value: &Value) -> Result<(), String> {
    let binding: StableAuthorityBindingV1 = serde_json::from_value(value.clone())
        .map_err(|error| format!("principal-authority binding is not closed and typed: {error}"))?;
    super::wallet_network_capability_client::verify_retained_principal_authority_binding_proof(
        &binding.binding_proof,
    )
    .map_err(|error| format!("{error:?}"))
}

/// Revalidate a retained governed-decision tuple without rewriting history or requiring the
/// authority grant to remain unexpired today. The signed grant and authority binding must both
/// have been valid at the authenticated resolution time captured by the original decision.
pub(crate) fn verify_retained_decision_evidence(
    evidence: &DecisionEvidence,
    resolved_at_ms: u64,
    required_authority: &str,
    required_scope: &str,
) -> Result<(), String> {
    let (grant, canonical_grant) = canonicalize_approval_grant(&evidence.wallet_approval_grant)?;
    if canonical_grant != evidence.wallet_approval_grant {
        return Err("retained approval grant is not its canonical typed projection".into());
    }
    let binding_value =
        canonicalize_authority_binding(&evidence.authority_binding, resolved_at_ms)?;
    if binding_value != evidence.authority_binding {
        return Err("retained authority binding is not its canonical typed projection".into());
    }
    verify_retained_authority_binding_root(&binding_value)?;
    let binding: StableAuthorityBindingV1 = serde_json::from_value(binding_value)
        .map_err(|error| format!("retained authority binding is malformed: {error}"))?;
    if binding.principal_ref != required_authority || binding.required_scope != required_scope {
        return Err("retained authority binding names a foreign principal or scope".into());
    }
    if grant.authority_id != binding.approval_authority.authority_id
        || grant.approver_public_key != binding.approval_authority.public_key
        || grant.approver_suite != binding.approval_authority.signature_suite
    {
        return Err(
            "retained approval signer tuple differs from the bound authority snapshot".into(),
        );
    }
    let verified = verify_wallet_approval_grant_binding(
        &canonical_grant,
        Some(resolved_at_ms),
        Some(&evidence.policy_hash),
        Some(&evidence.request_hash),
    )?;
    if verified.grant_ref != evidence.grant_ref
        || canonical_grant.get("authority_id") != Some(&evidence.acting_authority_id)
    {
        return Err("retained approval identity or grant reference does not recompute".into());
    }
    Ok(())
}

fn local_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn sha256_ref_bytes(value: &str, field: &str) -> Result<[u8; 32], String> {
    let raw = value
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("{field} is not a canonical sha256 ref"))?;
    if raw.len() != 64 || raw != raw.to_ascii_lowercase() {
        return Err(format!(
            "{field} must contain exactly 32 lowercase hexadecimal bytes"
        ));
    }
    let decoded = hex::decode(raw).map_err(|_| format!("{field} is not hexadecimal"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    if out == [0u8; 32] {
        return Err(format!("{field} must not be all zeroes"));
    }
    Ok(out)
}

fn authority_consumption_challenge(
    contract: AuthorityContract,
    status: StatusCode,
    suffix: &str,
    message: String,
) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({
            "error": {
                "code": contract.code(suffix),
                "message": message,
                "runtimeTruthSource": "daemon-runtime"
            }
        })),
    )
}

/// Persist the exact daemon-derived effect intent before asking wallet.network to consume one
/// use, then retain the immutable wallet receipt in that same durable slot. The wallet method is
/// idempotent for the deterministic consumption id, so a crash after wallet commit but before the
/// second daemon write recovers the original receipt and never decrements usage twice.
async fn consume_authorized_decision(
    data_dir: &str,
    contract: AuthorityContract,
    required_scope: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
    authorized: &AuthorizedDecision,
    recovery_reuses_consumed_receipt: bool,
) -> Result<String, (StatusCode, Json<Value>)> {
    let (grant, _) = canonicalize_approval_grant(&authorized.evidence.wallet_approval_grant)
        .map_err(|message| {
            authority_consumption_challenge(
                contract,
                StatusCode::FORBIDDEN,
                "authority_consumption_invalid",
                message,
            )
        })?;
    let request_hash = sha256_ref_bytes(&authorized.evidence.request_hash, "request_hash")
        .map_err(|message| {
            authority_consumption_challenge(
                contract,
                StatusCode::FORBIDDEN,
                "authority_consumption_invalid",
                message,
            )
        })?;
    let grant_hash = grant.artifact_hash().map_err(|error| {
        authority_consumption_challenge(
            contract,
            StatusCode::FORBIDDEN,
            "authority_consumption_invalid",
            format!("approval grant cannot be hashed: {error}"),
        )
    })?;
    let expected_max_usages = grant.max_usages.unwrap_or(1);
    if expected_max_usages == 0 {
        return Err(authority_consumption_challenge(
            contract,
            StatusCode::FORBIDDEN,
            "authority_consumption_invalid",
            "approval grant max_usages must be positive".to_string(),
        ));
    }
    let expected_principal_authority: ExpectedPrincipalAuthorityBinding =
        serde_json::from_value(authorized.evidence.authority_binding.clone()).map_err(|error| {
            authority_consumption_challenge(
                contract,
                StatusCode::BAD_GATEWAY,
                "authority_consumption_invalid",
                format!("resolved principal authority cannot authorize wallet use: {error}"),
            )
        })?;
    let expected_target_label = required_scope.to_string();
    let commitment = json!({
        "domain": "ioi.hypervisor.governed-authority-consumption.v1",
        "subject_ref": subject_ref,
        "operation": op,
        "revision": revision,
        "required_scope": expected_target_label,
        "policy_hash": authorized.evidence.policy_hash,
        "request_hash": authorized.evidence.request_hash,
        "effect_hash": authorized.evidence.effect_hash,
        "grant_hash": format!("sha256:{}", hex::encode(grant_hash)),
        "principal_authority": expected_principal_authority,
    });
    let encoded = serde_jcs::to_vec(&commitment).map_err(|error| {
        authority_consumption_challenge(
            contract,
            StatusCode::INTERNAL_SERVER_ERROR,
            "authority_consumption_intent_invalid",
            format!("authority consumption intent cannot be canonicalized: {error}"),
        )
    })?;
    let mut consumption_id = [0u8; 32];
    consumption_id.copy_from_slice(&Sha256::digest(encoded));
    let tail = format!("aai_{}", hex::encode(consumption_id));
    let params = ConsumeApprovalGrantForEffectV2Params {
        request_hash,
        grant_hash,
        consumption_id,
        expected_principal_authority,
        expected_target_label,
        expected_max_usages,
    };

    let _guard = AUTHORITY_ADMISSION_LOCK.lock().await;
    let existing =
        super::durable_fs::read_record_durable(data_dir, AUTHORITY_ADMISSION_INTENT_FAMILY, &tail)
            .map_err(|message| {
                authority_consumption_challenge(
                    contract,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "authority_consumption_intent_unreadable",
                    message,
                )
            })?;
    if existing
        .as_ref()
        .is_some_and(|record| record.get("commitment") != Some(&commitment))
    {
        return Err(authority_consumption_challenge(
            contract,
            StatusCode::CONFLICT,
            "authority_consumption_intent_conflict",
            "the deterministic authority-consumption slot contains a different commitment"
                .to_string(),
        ));
    }
    if existing
        .as_ref()
        .is_some_and(|record| record.get("status").and_then(Value::as_str) == Some("consumed"))
    {
        let reference = format!("{AUTHORITY_ADMISSION_INTENT_FAMILY}/{tail}");
        if recovery_reuses_consumed_receipt {
            revalidate_admission_reference(data_dir, &reference, &authorized.evidence.effect_hash)
                .map_err(|message| {
                    authority_consumption_challenge(
                        contract,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "authority_consumption_receipt_unavailable",
                        message,
                    )
                })?;
            return Ok(reference);
        }
        return Err(authority_consumption_challenge(
            contract,
            StatusCode::CONFLICT,
            "authority_operation_already_admitted",
            "this deterministic authority operation is already consumed; direct replay cannot invoke it again and recovery must reuse its retained receipt"
                .to_string(),
        ));
    }
    if existing.is_none() {
        let prepared = json!({
            "schema_version": "ioi.hypervisor.authority-admission-intent.v1",
            "intent_id": tail,
            "status": "prepared",
            "commitment": commitment,
            "consumption_id": hex::encode(consumption_id),
            "wallet_consumption_receipt": Value::Null,
            "final_invoker_status": "pending",
        });
        super::durable_fs::persist_record_durable(
            data_dir,
            AUTHORITY_ADMISSION_INTENT_FAMILY,
            &tail,
            &prepared,
        )
        .map_err(|error| {
            authority_consumption_challenge(
                contract,
                StatusCode::INTERNAL_SERVER_ERROR,
                "authority_consumption_intent_not_durable",
                format!("authority intent was not durably prepared: {error:?}"),
            )
        })?;
    }

    super::wallet_network_capability_client::preflight_approval_grant_for_effect_v2(&params)
        .await
        .map_err(|error| map_consumption_error(contract, error))?;
    let receipt = super::wallet_network_capability_client::consume_approval_grant_for_effect_v2(
        params.clone(),
    )
    .await
    .map_err(|error| map_consumption_error(contract, error))?;
    retain_consumption_receipt(data_dir, contract, &tail, &commitment, &receipt)?;
    Ok(format!("{AUTHORITY_ADMISSION_INTENT_FAMILY}/{tail}"))
}

/// Final-invoker fence: accept only the durable, consumed receipt for the exact authorized effect,
/// then recover the immutable wallet-owned receipt by its deterministic consumption identity.
/// A daemon-local projection is evidence, not the owner head.
pub(crate) async fn revalidate_admission_receipt(
    data_dir: &str,
    admitted: &AdmittedDeploymentGrant,
) -> Result<(), String> {
    revalidate_authoritative_admission(
        data_dir,
        &admitted.admission_intent_ref,
        &admitted.authorized,
    )
    .await
}

async fn revalidate_authoritative_admission(
    data_dir: &str,
    reference: &str,
    authorized: &AuthorizedDecision,
) -> Result<(), String> {
    revalidate_admission_reference(data_dir, reference, &authorized.evidence.effect_hash)?;
    let tail = reference
        .strip_prefix(&format!("{AUTHORITY_ADMISSION_INTENT_FAMILY}/"))
        .ok_or_else(|| {
            "authority admission receipt reference is outside its owner family".to_string()
        })?;
    let record =
        super::durable_fs::read_record_durable(data_dir, AUTHORITY_ADMISSION_INTENT_FAMILY, tail)?
            .ok_or_else(|| "authority admission receipt is absent".to_string())?;
    let local_receipt: ApprovalGrantConsumptionReceipt = serde_json::from_value(
        record
            .get("wallet_consumption_receipt")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .map_err(|error| format!("authority admission receipt is malformed: {error}"))?;
    verify_consumption_receipt_hash(&local_receipt)?;

    let (grant, _) = canonicalize_approval_grant(&authorized.evidence.wallet_approval_grant)?;
    let request_hash = sha256_ref_bytes(&authorized.evidence.request_hash, "request_hash")?;
    let grant_hash = grant
        .artifact_hash()
        .map_err(|error| format!("approval grant cannot be hashed: {error}"))?;
    let consumption_id = decode_hex_32(
        record
            .get("consumption_id")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "consumption_id",
    )?;
    let expected_principal_authority: ExpectedPrincipalAuthorityBinding =
        serde_json::from_value(authorized.evidence.authority_binding.clone()).map_err(|error| {
            format!("authority binding cannot revalidate wallet consumption: {error}")
        })?;
    let expected_target_label = record
        .pointer("/commitment/required_scope")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "authority admission receipt lacks its exact target head".to_string())?
        .to_string();
    let expected_max_usages = grant.max_usages.unwrap_or(1);
    let params = ConsumeApprovalGrantForEffectV2Params {
        request_hash,
        grant_hash,
        consumption_id,
        expected_principal_authority,
        expected_target_label,
        expected_max_usages,
    };
    let owner_receipt =
        super::wallet_network_capability_client::recover_approval_grant_consumption_for_effect_v2(
            &params,
        )
        .await
        .map_err(|error| {
            format!("wallet-owned authority receipt could not be revalidated: {error:?}")
        })?
        .ok_or_else(|| "wallet-owned authority receipt is absent".to_string())?;
    verify_consumption_receipt_hash(&owner_receipt)?;
    if owner_receipt != local_receipt {
        return Err(
            "daemon admission projection differs from the wallet-owned immutable consumption receipt"
                .to_string(),
        );
    }
    Ok(())
}

/// What a claim attempt is allowed to do, given the durable disposition it found.
#[derive(Debug, PartialEq, Eq)]
enum ClaimTransition {
    /// No invoker has held this effect: the claim may be written and the invoker entered.
    Grant,
    /// Terminal, in-flight, or already-reconciling: no invoker may run.
    Refuse(String),
    /// A claim from a process that is gone. Persist the Unknown, then refuse.
    ReconcileOrphanedClaim,
}

/// The claim decision, isolated from durability and wallet I/O so the crash-window semantics are
/// directly provable. The one subtle case is `Claimed`: a claim stamped with THIS process's
/// incarnation belongs to a request still running here and must not disturb it, while a claim
/// stamped with any other incarnation belongs to a process that died mid-dispatch and makes the
/// external effect indeterminate.
fn evaluate_claim_transition(
    disposition: FinalInvocationDisposition,
    record: &Value,
    incarnation_id: &str,
) -> ClaimTransition {
    match disposition {
        FinalInvocationDisposition::Admitted => ClaimTransition::Grant,
        FinalInvocationDisposition::Claimed => {
            let owner = record
                .pointer("/final_invoker_claim/incarnation_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if owner == incarnation_id {
                ClaimTransition::Refuse(
                    "this admitted effect is already claimed by an in-flight final invocation"
                        .to_string(),
                )
            } else {
                ClaimTransition::ReconcileOrphanedClaim
            }
        }
        FinalInvocationDisposition::Invoked => ClaimTransition::Refuse(
            "this admitted effect already reached its final invoker exactly once".to_string(),
        ),
        FinalInvocationDisposition::Refused => ClaimTransition::Refuse(
            "this admitted effect was already refused before invocation".to_string(),
        ),
        FinalInvocationDisposition::ReconciliationRequired => ClaimTransition::Refuse(
            "this admitted effect is awaiting reconciliation and cannot be re-invoked".to_string(),
        ),
    }
}

/// Claim the one final invocation this admitted effect is entitled to.
///
/// Order is the whole point: the wallet-owned receipt is revalidated, the `claimed` transition is
/// persisted durably, and only then may the caller enter its final invoker. A crash between the
/// claim and the completion therefore always leaves durable evidence that the external effect is
/// of unknown disposition. Re-entry after such a crash fails closed into `reconciliation_required`
/// rather than re-invoking, because a second `advance`, `spawn`, or outbound send is not
/// recoverable by retrying it.
pub(crate) async fn claim_final_invocation(
    data_dir: &str,
    admitted: &AdmittedDeploymentGrant,
    invoker_label: &str,
) -> Result<FinalInvocationClaim, String> {
    if invoker_label.trim().is_empty() {
        return Err("a final invocation claim names its invoker".to_string());
    }
    revalidate_authoritative_admission(
        data_dir,
        &admitted.admission_intent_ref,
        &admitted.authorized,
    )
    .await?;

    let _guard = AUTHORITY_ADMISSION_LOCK.lock().await;
    let tail = admission_intent_tail(&admitted.admission_intent_ref)?;
    let mut record =
        super::durable_fs::read_record_durable(data_dir, AUTHORITY_ADMISSION_INTENT_FAMILY, tail)?
            .ok_or_else(|| "authority admission receipt is absent".to_string())?;
    let disposition = FinalInvocationDisposition::parse(
        record.get("final_invoker_status").and_then(Value::as_str),
    )
    .ok_or_else(|| {
        "authority admission receipt carries no final-invoker disposition".to_string()
    })?;

    match evaluate_claim_transition(disposition, &record, process_incarnation_id()) {
        ClaimTransition::Grant => {}
        ClaimTransition::Refuse(reason) => return Err(reason),
        ClaimTransition::ReconcileOrphanedClaim => {
            // The claiming process did not survive its dispatch window. Make the Unknown durable.
            record["final_invoker_status"] =
                json!(FinalInvocationDisposition::ReconciliationRequired.label());
            record["final_invoker_reconciliation"] = json!({
                "reason": "claim_owner_process_did_not_complete",
                "orphaned_claim": record.get("final_invoker_claim").cloned().unwrap_or(Value::Null),
                "observed_at_ms": local_now_ms(),
                "usage_disposition": "spent_not_refunded",
            });
            super::durable_fs::persist_record_durable(
                data_dir,
                AUTHORITY_ADMISSION_INTENT_FAMILY,
                tail,
                &record,
            )
            .map_err(|error| format!("reconciliation state was not durably recorded: {error:?}"))?;
            return Err(
                "a previous process claimed this final invocation and did not complete it; the effect is of unknown disposition and requires reconciliation"
                    .to_string(),
            );
        }
    }

    let claim_id = format!("fic_{:032x}", nonce_nanos());
    record["final_invoker_status"] = json!(FinalInvocationDisposition::Claimed.label());
    record["final_invoker_claim"] = json!({
        "claim_id": claim_id,
        "invoker_label": invoker_label,
        "incarnation_id": process_incarnation_id(),
        "effect_hash": admitted.authorized.evidence.effect_hash,
        "claimed_at_ms": local_now_ms(),
    });
    super::durable_fs::persist_record_durable(
        data_dir,
        AUTHORITY_ADMISSION_INTENT_FAMILY,
        tail,
        &record,
    )
    .map_err(|error| {
        format!("final-invocation claim was not durable, so no invoker may run: {error:?}")
    })?;
    // Live fault verifiers SIGKILL exactly here: claimed on disk, invoker not yet entered.
    super::durable_fs::test_crash_pause_if_selected(
        "IOI_TEST_CRASH_AT",
        "final_invocation_claimed",
        "IOI_TEST_CRASH_MARKER_PATH",
        &claim_id,
    )
    .map_err(|error| format!("test crash coordination failed: {error}"))?;

    Ok(FinalInvocationClaim {
        reference: admitted.admission_intent_ref.clone(),
        claim_id,
        effect_hash: admitted.authorized.evidence.effect_hash.clone(),
        invoker_label: invoker_label.to_string(),
    })
}

/// Record that the claimed final invoker ran to a known disposition.
pub(crate) async fn complete_final_invocation(
    data_dir: &str,
    claim: &FinalInvocationClaim,
    outcome: &str,
) -> Result<(), String> {
    settle_final_invocation(
        data_dir,
        claim,
        FinalInvocationDisposition::Invoked,
        outcome,
    )
    .await
}

/// Record that the claimed invoker refused BEFORE producing any external effect. Usage stays
/// spent: the authority was consumed to reach the decision point.
pub(crate) async fn refuse_final_invocation(
    data_dir: &str,
    claim: &FinalInvocationClaim,
    reason: &str,
) -> Result<(), String> {
    settle_final_invocation(data_dir, claim, FinalInvocationDisposition::Refused, reason).await
}

async fn settle_final_invocation(
    data_dir: &str,
    claim: &FinalInvocationClaim,
    disposition: FinalInvocationDisposition,
    detail: &str,
) -> Result<(), String> {
    let _guard = AUTHORITY_ADMISSION_LOCK.lock().await;
    let tail = admission_intent_tail(&claim.reference)?;
    let mut record =
        super::durable_fs::read_record_durable(data_dir, AUTHORITY_ADMISSION_INTENT_FAMILY, tail)?
            .ok_or_else(|| "authority admission receipt is absent".to_string())?;
    if record.get("final_invoker_status").and_then(Value::as_str)
        != Some(FinalInvocationDisposition::Claimed.label())
    {
        return Err("a final invocation can only settle from its own durable claim".to_string());
    }
    if record
        .pointer("/final_invoker_claim/claim_id")
        .and_then(Value::as_str)
        != Some(claim.claim_id.as_str())
    {
        return Err("this claim does not own the recorded final invocation".to_string());
    }
    record["final_invoker_status"] = json!(disposition.label());
    record["final_invoker_settlement"] = json!({
        "claim_id": claim.claim_id,
        "invoker_label": claim.invoker_label,
        "effect_hash": claim.effect_hash,
        "outcome": detail,
        "settled_at_ms": local_now_ms(),
    });
    super::durable_fs::persist_record_durable(
        data_dir,
        AUTHORITY_ADMISSION_INTENT_FAMILY,
        tail,
        &record,
    )
    .map_err(|error| format!("final-invocation settlement was not durable: {error:?}"))
}

/// Read-only disposition lookup used by recovery and background completion loops.
pub(crate) fn final_invocation_disposition(
    data_dir: &str,
    reference: &str,
) -> Result<FinalInvocationDisposition, String> {
    let tail = admission_intent_tail(reference)?;
    let record =
        super::durable_fs::read_record_durable(data_dir, AUTHORITY_ADMISSION_INTENT_FAMILY, tail)?
            .ok_or_else(|| "authority admission receipt is absent".to_string())?;
    FinalInvocationDisposition::parse(record.get("final_invoker_status").and_then(Value::as_str))
        .ok_or_else(|| {
            "authority admission receipt carries no final-invoker disposition".to_string()
        })
}

fn admission_intent_tail(reference: &str) -> Result<&str, String> {
    reference
        .strip_prefix(&format!("{AUTHORITY_ADMISSION_INTENT_FAMILY}/"))
        .ok_or_else(|| {
            "authority admission receipt reference is outside its owner family".to_string()
        })
}

fn decode_hex_32(value: &str, field: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || value != value.to_ascii_lowercase() {
        return Err(format!(
            "{field} must contain exactly 32 lowercase hexadecimal bytes"
        ));
    }
    let decoded = hex::decode(value).map_err(|_| format!("{field} is not hexadecimal"))?;
    let mut output = [0u8; 32];
    output.copy_from_slice(&decoded);
    if output == [0u8; 32] {
        return Err(format!("{field} must not be all zeroes"));
    }
    Ok(output)
}

fn verify_consumption_receipt_hash(
    receipt: &ApprovalGrantConsumptionReceipt,
) -> Result<(), String> {
    if receipt.schema_version != 1 || receipt.receipt_hash == [0u8; 32] {
        return Err(
            "authority consumption receipt has an unsupported version or empty hash".into(),
        );
    }
    let mut material = serde_json::to_value(receipt)
        .map_err(|error| format!("authority consumption receipt cannot be serialized: {error}"))?;
    material["receipt_hash"] = json!(vec![0u8; 32]);
    let encoded = serde_jcs::to_vec(&material).map_err(|error| {
        format!("authority consumption receipt cannot be canonicalized: {error}")
    })?;
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&Sha256::digest(encoded));
    if receipt.receipt_hash != expected {
        return Err("authority consumption receipt hash does not match its content".into());
    }
    Ok(())
}

fn revalidate_admission_reference(
    data_dir: &str,
    reference: &str,
    expected_effect_hash: &str,
) -> Result<(), String> {
    let tail = reference
        .strip_prefix(&format!("{AUTHORITY_ADMISSION_INTENT_FAMILY}/"))
        .ok_or_else(|| {
            "authority admission receipt reference is outside its owner family".to_string()
        })?;
    let record =
        super::durable_fs::read_record_durable(data_dir, AUTHORITY_ADMISSION_INTENT_FAMILY, tail)?
            .ok_or_else(|| "authority admission receipt is absent".to_string())?;
    if record.get("status").and_then(Value::as_str) != Some("consumed")
        || record
            .get("wallet_consumption_receipt")
            .is_none_or(Value::is_null)
        || record
            .pointer("/commitment/effect_hash")
            .and_then(Value::as_str)
            != Some(expected_effect_hash)
    {
        return Err(
            "authority admission receipt is not a consumed receipt for the exact effect"
                .to_string(),
        );
    }
    Ok(())
}

fn retain_consumption_receipt(
    data_dir: &str,
    contract: AuthorityContract,
    tail: &str,
    commitment: &Value,
    receipt: &ApprovalGrantConsumptionReceipt,
) -> Result<(), (StatusCode, Json<Value>)> {
    let consumed = json!({
        "schema_version": "ioi.hypervisor.authority-admission-intent.v1",
        "intent_id": tail,
        "status": "consumed",
        "commitment": commitment,
        "consumption_id": hex::encode(receipt.consumption_id),
        "wallet_consumption_receipt": receipt,
        "final_invoker_status": "admitted",
    });
    super::durable_fs::persist_record_durable(
        data_dir,
        AUTHORITY_ADMISSION_INTENT_FAMILY,
        tail,
        &consumed,
    )
    .map_err(|error| {
        authority_consumption_challenge(
            contract,
            StatusCode::INTERNAL_SERVER_ERROR,
            "authority_consumption_receipt_not_durable",
            format!(
                "wallet consumption committed but its daemon admission receipt is not durably projected; retry recovers the same consumption id: {error:?}"
            ),
        )
    })
}

fn map_consumption_error(
    contract: AuthorityContract,
    error: super::wallet_network_capability_client::ResolveError,
) -> (StatusCode, Json<Value>) {
    use super::wallet_network_capability_client::ResolveError;
    match error {
        ResolveError::NotConfigured(message) => authority_consumption_challenge(
            contract,
            StatusCode::NOT_IMPLEMENTED,
            "authority_consumption_not_configured",
            message,
        ),
        ResolveError::Unavailable(message) => authority_consumption_challenge(
            contract,
            StatusCode::SERVICE_UNAVAILABLE,
            "authority_consumption_unavailable",
            message,
        ),
        ResolveError::Refused(message) => authority_consumption_challenge(
            contract,
            StatusCode::FORBIDDEN,
            "authority_consumption_refused",
            message,
        ),
        ResolveError::Invalid(message) => authority_consumption_challenge(
            contract,
            StatusCode::BAD_GATEWAY,
            "authority_consumption_invalid",
            message,
        ),
    }
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
    decision_policy_hash_for_context(
        contract,
        governance,
        AuthorityPolicyContext::OutcomeRoom {
            outcome_room_ref: room_ref,
        },
        required_authority,
        op,
    )
}

/// Context-neutral policy commitment for governed planes that are not room-owned.
///
/// Existing room planes stay on `decision_policy_hash`, which delegates here with the original
/// `outcome_room_ref` key and therefore preserves their policy hashes byte-for-byte.
pub(crate) fn decision_policy_hash_for_context(
    contract: AuthorityContract,
    governance: Governance,
    context: AuthorityPolicyContext<'_>,
    required_authority: &str,
    op: &str,
) -> String {
    let mut material = serde_json::Map::new();
    material.insert("domain".into(), json!(contract.policy_domain));
    material.insert(
        "governance".into(),
        json!(contract.governance_label(governance)),
    );
    match context {
        AuthorityPolicyContext::OutcomeRoom { outcome_room_ref } => {
            material.insert("outcome_room_ref".into(), json!(outcome_room_ref));
        }
        AuthorityPolicyContext::SystemGenesis {
            system_id,
            genesis_id,
        } => {
            material.insert("genesis_id".into(), json!(genesis_id));
            material.insert("system_id".into(), json!(system_id));
        }
        AuthorityPolicyContext::HypervisorOsNode {
            estate_namespace,
            node_id,
        } => {
            material.insert("estate_namespace".into(), json!(estate_namespace));
            material.insert("node_id".into(), json!(node_id));
        }
        AuthorityPolicyContext::HypervisorEnvironment {
            estate_namespace,
            subject_ref,
        } => {
            material.insert("estate_namespace".into(), json!(estate_namespace));
            material.insert("environment_subject_ref".into(), json!(subject_ref));
        }
    }
    material.insert("required_authority_ref".into(), json!(required_authority));
    material.insert("required_scope".into(), json!(contract.operation_scope(op)));
    record_output_hash(&Value::Object(material), &[])
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

fn live_effect_hash(effect: &Value) -> Result<String, String> {
    let material = json!({
        "domain": "ioi.hypervisor.live-authority-effect.v1",
        "effect": effect,
    });
    let encoded = serde_jcs::to_vec(&material)
        .map_err(|error| format!("live effect cannot be canonicalized: {error}"))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(encoded))))
}

/// Resolve the deployment-owned principal independently of request evidence, verify the submitted
/// grant against that current issuer and the daemon-derived exact commitments, durably prepare an
/// admission intent, and atomically consume one wallet-owned usage. Callers pass the complete
/// effect material and invoke nothing unless this function returns its admitted decision.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_deployment_grant(
    data_dir: &str,
    grant_value: &Value,
    required_scope: &str,
    policy_hash: &str,
    request_hash: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
    effect: &Value,
) -> Result<AdmittedDeploymentGrant, (StatusCode, Json<Value>)> {
    let required_authority = std::env::var("IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            authority_consumption_challenge(
                LIVE_ROUTE_AUTHORITY,
                StatusCode::NOT_IMPLEMENTED,
                "authority_principal_not_configured",
                "IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF is required; request-carried issuer fields never select deployment authority".to_string(),
            )
        })?;
    let resolution = resolve_required_authority(
        LIVE_ROUTE_AUTHORITY,
        &required_authority,
        required_scope,
        None,
    )
    .await
    .map_err(|(status, code, message)| {
        (
            status,
            Json(json!({
                "error": {
                    "code": code,
                    "message": message,
                    "required_authority_ref": required_authority,
                    "required_scope": required_scope,
                    "runtimeTruthSource": "daemon-runtime"
                }
            })),
        )
    })?;
    let (grant, canonical_grant) = canonicalize_approval_grant(grant_value).map_err(|message| {
        authority_consumption_challenge(
            LIVE_ROUTE_AUTHORITY,
            StatusCode::FORBIDDEN,
            "authority_grant_invalid",
            message,
        )
    })?;
    let binding = verify_wallet_approval_grant_binding(
        &canonical_grant,
        Some(local_now_ms()),
        Some(policy_hash),
        Some(request_hash),
    )
    .map_err(|message| {
        authority_consumption_challenge(
            LIVE_ROUTE_AUTHORITY,
            StatusCode::FORBIDDEN,
            "authority_grant_invalid",
            message,
        )
    })?;
    let authority = &resolution.resolution.approval_authority;
    if grant.authority_id != authority.authority_id
        || grant.approver_public_key != authority.public_key
        || grant.approver_suite != authority.signature_suite
    {
        return Err(authority_consumption_challenge(
            LIVE_ROUTE_AUTHORITY,
            StatusCode::FORBIDDEN,
            "authority_issuer_mismatch",
            "approval grant signer tuple does not match the independently resolved current deployment authority".to_string(),
        ));
    }
    let effect_hash = live_effect_hash(effect).map_err(|message| {
        authority_consumption_challenge(
            LIVE_ROUTE_AUTHORITY,
            StatusCode::INTERNAL_SERVER_ERROR,
            "authority_effect_invalid",
            message,
        )
    })?;
    let authorized = AuthorizedDecision {
        evidence: DecisionEvidence {
            acting_authority_id: canonical_grant
                .get("authority_id")
                .cloned()
                .unwrap_or(Value::Null),
            grant_ref: binding.grant_ref,
            policy_hash: policy_hash.to_string(),
            request_hash: request_hash.to_string(),
            effect_hash,
            authorized_effect: effect.clone(),
            wallet_approval_grant: canonical_grant,
            authority_binding: resolution.authority_binding,
        },
        resolved_at_ms: resolution.resolution.resolved_at_ms,
    };
    let admission_intent_ref = consume_authorized_decision(
        data_dir,
        LIVE_ROUTE_AUTHORITY,
        required_scope,
        subject_ref,
        op,
        revision,
        &authorized,
        false,
    )
    .await?;
    Ok(AdmittedDeploymentGrant {
        authorized,
        admission_intent_ref,
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
    authorize_decision_for_resolution_with_context(
        contract,
        body,
        governance,
        AuthorityPolicyContext::OutcomeRoom {
            outcome_room_ref: room_ref,
        },
        required_authority,
        verified_resolution,
        subject_ref,
        op,
        revision,
        effect,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn authorize_decision_for_resolution_with_context(
    contract: AuthorityContract,
    body: &Value,
    governance: Governance,
    context: AuthorityPolicyContext<'_>,
    required_authority: &str,
    verified_resolution: &VerifiedAuthorityResolution,
    subject_ref: &str,
    op: &str,
    revision: u64,
    effect: &Value,
) -> Result<AuthorizedDecision, (StatusCode, Json<Value>)> {
    let resolution = &verified_resolution.resolution;
    let policy_hash =
        decision_policy_hash_for_context(contract, governance, context, required_authority, op);
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
    let verified_grant = if grant.is_null() {
        Err("a wallet_approval_grant is required".to_string())
    } else {
        (|| {
            let (parsed, canonical) = canonicalize_approval_grant(&grant)?;
            let binding = verify_wallet_approval_grant_binding(
                &canonical,
                Some(local_now_ms()),
                Some(&policy_hash),
                Some(&request_hash),
            )?;
            let authority = &resolution.approval_authority;
            if parsed.authority_id != authority.authority_id
                || parsed.approver_public_key != authority.public_key
                || parsed.approver_suite != authority.signature_suite
            {
                return Err(format!(
                    "approval grant signer tuple does not match the frozen authority snapshot bound to '{required_authority}'"
                ));
            }
            Ok((binding, canonical))
        })()
    };
    match verified_grant {
        Ok((binding, canonical_grant)) => Ok(AuthorizedDecision {
            evidence: DecisionEvidence {
                acting_authority_id: canonical_grant
                    .get("authority_id")
                    .cloned()
                    .unwrap_or(Value::Null),
                grant_ref: binding.grant_ref,
                policy_hash,
                request_hash,
                effect_hash,
                authorized_effect: effect.clone(),
                wallet_approval_grant: canonical_grant,
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
    data_dir: &str,
    body: &Value,
    governance: Governance,
    room_ref: &str,
    required_authority: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
    effect: &Value,
) -> Result<AuthorizedDecision, (StatusCode, Json<Value>)> {
    let authorized = authorize_decision_with_context(
        contract,
        body,
        governance,
        AuthorityPolicyContext::OutcomeRoom {
            outcome_room_ref: room_ref,
        },
        required_authority,
        subject_ref,
        op,
        revision,
        effect,
    )
    .await?;
    let required_scope = contract.operation_scope(op);
    let admission_intent_ref = consume_authorized_decision(
        data_dir,
        contract,
        &required_scope,
        subject_ref,
        op,
        revision,
        &authorized,
        false,
    )
    .await?;
    revalidate_authoritative_admission(data_dir, &admission_intent_ref, &authorized)
        .await
        .map_err(|message| {
            authority_consumption_challenge(
                contract,
                StatusCode::SERVICE_UNAVAILABLE,
                "authority_consumption_receipt_unavailable",
                message,
            )
        })?;
    Ok(authorized)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_decision_with_context(
    contract: AuthorityContract,
    body: &Value,
    governance: Governance,
    context: AuthorityPolicyContext<'_>,
    required_authority: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
    effect: &Value,
) -> Result<AuthorizedDecision, (StatusCode, Json<Value>)> {
    let policy_hash =
        decision_policy_hash_for_context(contract, governance, context, required_authority, op);
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
    authorize_decision_for_resolution_with_context(
        contract,
        body,
        governance,
        context,
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
    data_dir: &str,
    receipt: &Value,
    governance: Governance,
    room_ref: &str,
    required_authority: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
    effect: &Value,
) -> Result<u64, String> {
    reauthorize_sealed_receipt_with_context(
        contract,
        data_dir,
        receipt,
        governance,
        AuthorityPolicyContext::OutcomeRoom {
            outcome_room_ref: room_ref,
        },
        required_authority,
        subject_ref,
        op,
        revision,
        effect,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn reauthorize_sealed_receipt_with_context(
    contract: AuthorityContract,
    data_dir: &str,
    receipt: &Value,
    governance: Governance,
    context: AuthorityPolicyContext<'_>,
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
    let (_, canonical_grant) = canonicalize_approval_grant(&sealed.wallet_approval_grant)?;
    let canonical_binding = canonicalize_authority_binding(
        &sealed.authority_binding,
        receipt
            .get("authority_resolved_at_ms")
            .and_then(Value::as_u64)
            .ok_or_else(|| "the governed intent lacks authority_resolved_at_ms".to_string())?,
    )?;
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
    if resolution.authority_binding != canonical_binding {
        return Err("wallet.network no longer resolves the exact snapshot, scope, and immutable coordinates pinned by the governed intent".into());
    }
    let body = json!({ "wallet_approval_grant": canonical_grant });
    let live = authorize_decision_for_resolution_with_context(
        contract,
        &body,
        governance,
        context,
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
    let mut normalized_sealed = sealed;
    normalized_sealed.wallet_approval_grant = body["wallet_approval_grant"].clone();
    normalized_sealed.authority_binding = canonical_binding;
    if live.evidence != normalized_sealed {
        return Err("the reverified grant and resolution do not reconstruct the exact sealed authority tuple".into());
    }
    let admission_intent_ref = consume_authorized_decision(
        data_dir,
        contract,
        &required_scope,
        subject_ref,
        op,
        revision,
        &live,
        true,
    )
    .await
    .map_err(|(_, Json(payload))| {
        payload
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("the original authority consumption receipt could not be recovered")
            .to_string()
    })?;
    revalidate_authoritative_admission(data_dir, &admission_intent_ref, &live).await?;
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

#[cfg(test)]
mod scm_publication_scope_tests {
    use super::*;

    /// Every other family's `AuthorityContract` scope prefix that ships today.
    /// The publication family must be disjoint from all of them, so a grant
    /// minted for any local plane can never authorize a remote crossing.
    const EXISTING_SCOPE_PREFIXES: &[&str] = &[
        "scope:autonomous_system.lifecycle",
        "scope:autonomous_system.continuity",
        "scope:autonomous_system.membership",
        "scope:autonomous_system.writer",
        "scope:autonomous_system.network_enrollment",
        "scope:hypervisoros.node",
        "scope:hypervisor_environment",
        "scope:outcome_room",
    ];

    #[test]
    fn publication_scopes_are_disjoint_from_every_other_family() {
        for prefix in EXISTING_SCOPE_PREFIXES {
            assert!(
                !SCM_PUBLICATION_SCOPE_PREFIX.starts_with(prefix),
                "the publication family must not sit under '{prefix}'"
            );
            assert!(
                !prefix.starts_with(SCM_PUBLICATION_SCOPE_PREFIX),
                "'{prefix}' must not sit under the publication family"
            );
        }
        for scope in [
            SCM_PUBLICATION_ADVANCE_TARGET_REF_SCOPE,
            SCM_PUBLICATION_OPEN_REVIEW_REQUEST_SCOPE,
        ] {
            assert!(scope.starts_with(SCM_PUBLICATION_SCOPE_PREFIX));
            for prefix in EXISTING_SCOPE_PREFIXES {
                assert!(!scope.starts_with(prefix), "{scope} leaked into {prefix}");
            }
        }
        assert_ne!(
            SCM_PUBLICATION_ADVANCE_TARGET_REF_SCOPE, SCM_PUBLICATION_OPEN_REVIEW_REQUEST_SCOPE,
            "advancing a remote ref and opening a review are two authorities"
        );
    }

    #[test]
    fn publication_operations_resolve_their_exact_named_scopes() {
        assert_eq!(
            SCM_PUBLICATION_AUTHORITY.operation_scope("advance_target_ref"),
            SCM_PUBLICATION_ADVANCE_TARGET_REF_SCOPE
        );
        assert_eq!(
            SCM_PUBLICATION_AUTHORITY.operation_scope("open_review_request"),
            SCM_PUBLICATION_OPEN_REVIEW_REQUEST_SCOPE
        );
        // The lifecycle family is untouched by the new arm.
        let lifecycle = AuthorityContract {
            scope_prefix: "scope:autonomous_system.lifecycle",
            ..SCM_PUBLICATION_AUTHORITY
        };
        assert_eq!(
            lifecycle.operation_scope("declare_route_binding"),
            "scope:hypervisor_environment.declare_route_binding"
        );
        assert_eq!(
            lifecycle.operation_scope("initialize"),
            "scope:autonomous_system.lifecycle.initialize"
        );
    }
}

#[cfg(test)]
mod final_invocation_claim_tests {
    use super::*;

    fn claimed_by(incarnation: &str) -> Value {
        json!({
            "final_invoker_status": "claimed",
            "final_invoker_claim": {
                "claim_id": "fic_0001",
                "invoker_label": "scm.publication.advance-target-ref",
                "incarnation_id": incarnation,
            },
        })
    }

    #[test]
    fn an_unclaimed_admission_grants_exactly_one_claim() {
        assert_eq!(
            evaluate_claim_transition(
                FinalInvocationDisposition::Admitted,
                &json!({ "final_invoker_status": "admitted" }),
                "inc_current",
            ),
            ClaimTransition::Grant
        );
    }

    #[test]
    fn a_second_claim_in_this_process_never_reaches_a_second_invocation() {
        let transition = evaluate_claim_transition(
            FinalInvocationDisposition::Claimed,
            &claimed_by("inc_current"),
            "inc_current",
        );
        assert!(
            matches!(transition, ClaimTransition::Refuse(_)),
            "an in-flight claim is refused, not reconciled: {transition:?}"
        );
        assert_ne!(
            transition,
            ClaimTransition::ReconcileOrphanedClaim,
            "a live sibling request must not have its operation flipped to reconciliation"
        );
    }

    #[test]
    fn a_claim_from_a_dead_process_becomes_reconciliation_and_is_never_reinvoked() {
        assert_eq!(
            evaluate_claim_transition(
                FinalInvocationDisposition::Claimed,
                &claimed_by("inc_previous_boot"),
                "inc_current",
            ),
            ClaimTransition::ReconcileOrphanedClaim,
            "a crash inside the dispatch window is Unknown, not retryable"
        );
    }

    #[test]
    fn every_terminal_and_reconciling_disposition_refuses_a_new_invocation() {
        for disposition in [
            FinalInvocationDisposition::Invoked,
            FinalInvocationDisposition::Refused,
            FinalInvocationDisposition::ReconciliationRequired,
        ] {
            let transition = evaluate_claim_transition(
                disposition,
                &json!({ "final_invoker_status": disposition.label() }),
                "inc_current",
            );
            assert!(
                matches!(transition, ClaimTransition::Refuse(_)),
                "{disposition:?} must refuse a further final invocation, got {transition:?}"
            );
        }
    }

    #[test]
    fn dispositions_round_trip_through_their_durable_labels() {
        for disposition in [
            FinalInvocationDisposition::Admitted,
            FinalInvocationDisposition::Claimed,
            FinalInvocationDisposition::Invoked,
            FinalInvocationDisposition::Refused,
            FinalInvocationDisposition::ReconciliationRequired,
        ] {
            assert_eq!(
                FinalInvocationDisposition::parse(Some(disposition.label())),
                Some(disposition)
            );
        }
        assert_eq!(FinalInvocationDisposition::parse(Some("invented")), None);
        assert_eq!(
            FinalInvocationDisposition::parse(None),
            None,
            "a record with no disposition is never treated as claimable"
        );
    }

    #[test]
    fn a_consumed_admission_starts_admitted_so_it_is_claimable_exactly_once() {
        // This is the shape retain_consumption_receipt writes; the claim state machine depends on
        // it starting at `admitted` rather than at `pending`, which nothing advanced.
        let consumed = json!({
            "status": "consumed",
            "final_invoker_status": "admitted",
        });
        assert_eq!(
            FinalInvocationDisposition::parse(
                consumed.get("final_invoker_status").and_then(Value::as_str)
            ),
            Some(FinalInvocationDisposition::Admitted)
        );
    }
}
