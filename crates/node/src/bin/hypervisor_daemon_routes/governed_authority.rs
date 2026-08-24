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
    ConsumePortableAuthorityGrantV3ForEffectParams, ConsumeStandingApprovalGrantForEffectParams,
    ExpectedPrincipalAuthorityBinding, PortableAuthorityEffectAdmissionContextV1,
    PortableAuthorityEffectAdmissionReceiptV2Record, PortableAuthorityGrantV3ConsumptionReceipt,
    PortableAuthorityTemporalPostureV1, StandingApprovalGrantConsumptionReceipt,
};
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use ioi_types::app::hypervisoros_node_attestation::temporal_profile_root;
use ioi_types::app::{
    ApprovalAuthority, ApprovalGrant, PrincipalAuthorityBindingCoordinates,
    PrincipalAuthorityBindingProofV1, PrincipalAuthorityKind, PrincipalAuthorityResolutionReceipt,
    PrincipalAuthorityResolutionV1, ResolvePrincipalAuthorityParams, StandingApprovalGrant,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::outcome_room_routes::record_output_hash;

const AUTHORITY_ADMISSION_INTENT_FAMILY: &str = "authority-admission-intents";
const AUTHORITY_EFFECT_ADMISSION_V2_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/authority-effect-admission-receipt/v2";
const PORTABLE_ADMISSION_EVIDENCE_HASH_EXCLUSIONS: &[&str] = &[
    "output_hash",
    "final_invoker_status",
    "final_invoker_claim",
    "final_invoker_settlement",
    "final_invoker_reconciliation",
];
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

/// One standing-envelope draw admitted by the same durable intent-before-effect discipline.
pub(crate) struct AdmittedStandingGrant {
    pub(crate) admission_intent_ref: String,
    pub(crate) effect_hash: String,
    pub(crate) grant_ref: String,
    pub(crate) receipt: StandingApprovalGrantConsumptionReceipt,
}

/// One portable v3 exact-effect admission whose authority and registered v2 receipt remain
/// wallet-owned. The daemon retains the exact paired projection and re-resolves it before claim.
pub(crate) struct AdmittedPortableAuthorityGrant {
    pub(crate) admission_intent_ref: String,
    pub(crate) effect_hash: String,
    pub(crate) params: ConsumePortableAuthorityGrantV3ForEffectParams,
    pub(crate) consumption_receipt: PortableAuthorityGrantV3ConsumptionReceipt,
    pub(crate) admission_receipt: PortableAuthorityEffectAdmissionReceiptV2Record,
}

/// Inputs the PEP must derive from trusted route and owner state before portable consumption.
/// A request may present signed grant material, but it never supplies these resolved bindings.
#[derive(Clone, Debug)]
pub(crate) struct PortableAuthorityPepContext {
    pub(crate) grant_hash: [u8; 32],
    pub(crate) expected_audience: String,
    pub(crate) expected_holder_id: String,
    pub(crate) expected_holder_key_id: String,
    pub(crate) actual_effect_ref: String,
    pub(crate) admission: PortableAuthorityEffectAdmissionContextV1,
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

const STANDING_APPROVAL_GRANT_FIELDS: &[&str] = &[
    "schema_version",
    "authority_id",
    "standing_envelope_hash",
    "policy_hash",
    "audience",
    "nonce",
    "counter",
    "issued_at_ms",
    "expires_at_ms",
    "max_usages",
    "max_cumulative_deposit_microusd",
    "max_cumulative_spend_microusd",
    "review_receipt_hash",
    "approval_ceremony_context_hash",
    "auth_factor_receipt_hash",
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

/// Parse the separate standing-grant signature domain without weakening the C7 grant ABI.
pub(crate) fn canonicalize_standing_approval_grant(
    value: &Value,
) -> Result<(StandingApprovalGrant, Value), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "standing approval grant must be one JSON object".to_string())?;
    if let Some(field) = object
        .keys()
        .find(|field| !STANDING_APPROVAL_GRANT_FIELDS.contains(&field.as_str()))
    {
        return Err(format!(
            "standing approval grant contains undeclared field '{field}'"
        ));
    }
    let parsed: StandingApprovalGrant = serde_json::from_value(value.clone())
        .map_err(|error| format!("standing approval grant is not canonical: {error}"))?;
    parsed
        .verify()
        .map_err(|error| format!("standing approval grant is structurally invalid: {error}"))?;
    let canonical = serde_json::to_value(&parsed).map_err(|error| {
        format!("standing approval grant cannot be serialized canonically: {error}")
    })?;
    if canonical != *value {
        return Err(
            "standing approval grant differs from its closed canonical typed projection".into(),
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

fn portable_consumption_slot_material(commitment: &Value) -> Result<Value, String> {
    let mut material = commitment.clone();
    material
        .as_object_mut()
        .ok_or_else(|| "portable authority commitment is not an object".to_string())?
        .remove("admission")
        .ok_or_else(|| "portable authority commitment lacks admission context".to_string())?;
    Ok(material)
}

fn portable_consumption_id(commitment: &Value) -> Result<[u8; 32], String> {
    let encoded = serde_jcs::to_vec(&portable_consumption_slot_material(commitment)?)
        .map_err(|error| format!("portable authority slot cannot be canonicalized: {error}"))?;
    let mut consumption_id = [0u8; 32];
    consumption_id.copy_from_slice(&Sha256::digest(encoded));
    Ok(consumption_id)
}

fn portable_params_with_retained_admission(
    current: &ConsumePortableAuthorityGrantV3ForEffectParams,
    record: &Value,
) -> Result<ConsumePortableAuthorityGrantV3ForEffectParams, String> {
    let admission = serde_json::from_value(
        record
            .pointer("/commitment/admission")
            .cloned()
            .ok_or_else(|| "prepared portable intent lacks its admission context".to_string())?,
    )
    .map_err(|error| format!("prepared portable admission context is malformed: {error}"))?;
    let mut retained = current.clone();
    retained.admission = admission;
    Ok(retained)
}

fn portable_prepared_record(tail: &str, commitment: &Value, consumption_id: [u8; 32]) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.authority-admission-intent.v1",
        "intent_id": tail,
        "status": "prepared",
        "authority_mode": "portable_v3",
        "commitment": commitment,
        "consumption_id": hex::encode(consumption_id),
        "wallet_consumption_receipt": Value::Null,
        "wallet_admission_receipt_v2": Value::Null,
        "final_invoker_status": "pending",
    })
}

/// Admit one daemon-derived exact effect through an already registered portable v3 grant.
///
/// The deterministic slot is prepared before wallet I/O. wallet.network then verifies the sealed
/// grant, meters the use, and constructs the registered v2 admission receipt in one transaction.
/// A retry after wallet commit recovers the same pair and can never decrement a second use.
pub(crate) async fn authorize_portable_authority_effect(
    data_dir: &str,
    contract: AuthorityContract,
    required_scope: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
    effect: &Value,
    pep: PortableAuthorityPepContext,
    recovery_reuses_consumed_receipt: bool,
) -> Result<AdmittedPortableAuthorityGrant, (StatusCode, Json<Value>)> {
    let effect_hash = live_effect_hash(effect).map_err(|message| {
        authority_consumption_challenge(
            contract,
            StatusCode::INTERNAL_SERVER_ERROR,
            "portable_authority_effect_invalid",
            message,
        )
    })?;
    let actual_effect_hash = sha256_ref_bytes(&effect_hash, "effect_hash").map_err(|message| {
        authority_consumption_challenge(
            contract,
            StatusCode::INTERNAL_SERVER_ERROR,
            "portable_authority_effect_invalid",
            message,
        )
    })?;
    let commitment = json!({
        "domain": "ioi.hypervisor.portable-authority-consumption.v1",
        "authority_mode": "portable_v3",
        "subject_ref": subject_ref,
        "operation": op,
        "revision": revision,
        "required_scope": required_scope,
        "effect_ref": pep.actual_effect_ref,
        "effect_hash": effect_hash,
        "grant_hash": format!("sha256:{}", hex::encode(pep.grant_hash)),
        "expected_audience": pep.expected_audience,
        "expected_holder_id": pep.expected_holder_id,
        "expected_holder_key_id": pep.expected_holder_key_id,
        "admission": pep.admission,
    });
    let consumption_id = portable_consumption_id(&commitment).map_err(|message| {
        authority_consumption_challenge(
            contract,
            StatusCode::INTERNAL_SERVER_ERROR,
            "portable_authority_intent_invalid",
            message,
        )
    })?;
    let tail = format!("pai_{}", hex::encode(consumption_id));
    let params = ConsumePortableAuthorityGrantV3ForEffectParams {
        grant_hash: pep.grant_hash,
        consumption_id,
        expected_audience: pep.expected_audience,
        expected_holder_id: pep.expected_holder_id,
        expected_holder_key_id: pep.expected_holder_key_id,
        actual_effect_ref: pep.actual_effect_ref,
        actual_effect_hash,
        admission: pep.admission,
    };

    let _guard = AUTHORITY_ADMISSION_LOCK.lock().await;
    let existing =
        super::durable_fs::read_record_durable(data_dir, AUTHORITY_ADMISSION_INTENT_FAMILY, &tail)
            .map_err(|message| {
                authority_consumption_challenge(
                    contract,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "portable_authority_intent_unreadable",
                    message,
                )
            })?;
    if let Some(record) = existing.as_ref() {
        let retained_commitment = record.get("commitment").ok_or_else(|| {
            authority_consumption_challenge(
                contract,
                StatusCode::CONFLICT,
                "portable_authority_intent_conflict",
                "the deterministic portable-authority slot lacks its commitment".into(),
            )
        })?;
        let retained_slot =
            portable_consumption_slot_material(retained_commitment).map_err(|message| {
                authority_consumption_challenge(
                    contract,
                    StatusCode::CONFLICT,
                    "portable_authority_intent_conflict",
                    message,
                )
            })?;
        let current_slot = portable_consumption_slot_material(&commitment).map_err(|message| {
            authority_consumption_challenge(
                contract,
                StatusCode::INTERNAL_SERVER_ERROR,
                "portable_authority_intent_invalid",
                message,
            )
        })?;
        if retained_slot != current_slot {
            return Err(authority_consumption_challenge(
                contract,
                StatusCode::CONFLICT,
                "portable_authority_intent_conflict",
                "the deterministic portable-authority slot contains a different exact operation"
                    .into(),
            ));
        }
        let retained_params =
            portable_params_with_retained_admission(&params, record).map_err(|message| {
                authority_consumption_challenge(
                    contract,
                    StatusCode::CONFLICT,
                    "portable_authority_intent_conflict",
                    message,
                )
            })?;
        match record.get("status").and_then(Value::as_str) {
            Some("consumed") => {
                // A durable use with no final-invoker claim is the crash window between admission
                // and dispatch. Reusing that exact immutable pair is recovery, not replay; the
                // common claim lock still grants exactly one invoker. Once any claim/disposition
                // exists, ordinary direct entry refuses and only an explicitly idempotent owner
                // recovery path may inspect the retained admission.
                let unclaimed =
                    record.get("final_invoker_status").and_then(Value::as_str) == Some("admitted");
                if !recovery_reuses_consumed_receipt && !unclaimed {
                    return Err(authority_consumption_challenge(
                        contract,
                        StatusCode::CONFLICT,
                        "portable_authority_operation_already_admitted",
                        "this exact portable-authority operation already has a final-invoker disposition and cannot invoke twice".into(),
                    ));
                }
                let admitted = portable_admission_from_record(
                    &format!("{AUTHORITY_ADMISSION_INTENT_FAMILY}/{tail}"),
                    &effect_hash,
                    &retained_params,
                    record,
                )
                .map_err(|message| {
                    authority_consumption_challenge(
                        contract,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "portable_authority_receipt_unavailable",
                        message,
                    )
                })?;
                revalidate_portable_authority_admission(data_dir, &admitted)
                    .await
                    .map_err(|message| {
                        authority_consumption_challenge(
                            contract,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "portable_authority_receipt_unavailable",
                            message,
                        )
                    })?;
                return Ok(admitted);
            }
            Some("prepared") => {
                let recovered = super::wallet_network_capability_client::recover_portable_authority_grant_v3_consumption_for_effect(&retained_params)
                    .await
                    .map_err(|error| map_consumption_error(contract, error))?;
                if let Some(owner) = recovered {
                    let consumed = portable_consumed_record(&tail, retained_commitment, &owner);
                    super::durable_fs::persist_record_durable(
                        data_dir,
                        AUTHORITY_ADMISSION_INTENT_FAMILY,
                        &tail,
                        &consumed,
                    )
                    .map_err(|error| {
                        authority_consumption_challenge(
                            contract,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "portable_authority_receipt_not_durable",
                            format!(
                                "recovered wallet evidence could not be durably projected: {error:?}"
                            ),
                        )
                    })?;
                    let admitted = portable_admission_from_record(
                        &format!("{AUTHORITY_ADMISSION_INTENT_FAMILY}/{tail}"),
                        &effect_hash,
                        &retained_params,
                        &consumed,
                    )
                    .map_err(|message| {
                        authority_consumption_challenge(
                            contract,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "portable_authority_receipt_unavailable",
                            message,
                        )
                    })?;
                    revalidate_portable_authority_admission(data_dir, &admitted)
                        .await
                        .map_err(|message| {
                            authority_consumption_challenge(
                                contract,
                                StatusCode::SERVICE_UNAVAILABLE,
                                "portable_authority_receipt_unavailable",
                                message,
                            )
                        })?;
                    return Ok(admitted);
                }
                // The owner proves the old slot never committed. It is now safe to refresh only
                // the mutable admission context while preserving the stable consumption id.
                if retained_commitment != &commitment {
                    let prepared = portable_prepared_record(&tail, &commitment, consumption_id);
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
                            "portable_authority_intent_not_durable",
                            format!(
                                "refreshed portable authority intent was not durable: {error:?}"
                            ),
                        )
                    })?;
                }
            }
            _ => {
                return Err(authority_consumption_challenge(
                    contract,
                    StatusCode::CONFLICT,
                    "portable_authority_intent_conflict",
                    "the deterministic portable-authority slot has an invalid lifecycle state"
                        .into(),
                ))
            }
        }
    }
    if existing.is_none() {
        let prepared = portable_prepared_record(&tail, &commitment, consumption_id);
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
                "portable_authority_intent_not_durable",
                format!("portable authority intent was not durably prepared: {error:?}"),
            )
        })?;
    }

    super::wallet_network_capability_client::preflight_portable_authority_grant_v3_for_effect(
        &params,
    )
    .await
    .map_err(|error| map_consumption_error(contract, error))?;
    let owner =
        super::wallet_network_capability_client::consume_portable_authority_grant_v3_for_effect(
            params.clone(),
        )
        .await
        .map_err(|error| map_consumption_error(contract, error))?;
    let consumed = portable_consumed_record(&tail, &commitment, &owner);
    super::durable_fs::persist_record_durable(
        data_dir,
        AUTHORITY_ADMISSION_INTENT_FAMILY,
        &tail,
        &consumed,
    )
    .map_err(|error| {
        authority_consumption_challenge(
            contract,
            StatusCode::INTERNAL_SERVER_ERROR,
            "portable_authority_receipt_not_durable",
            format!(
                "wallet committed the portable use but its paired daemon projection did not persist; retry recovers the same consumption id: {error:?}"
            ),
        )
    })?;
    Ok(AdmittedPortableAuthorityGrant {
        admission_intent_ref: format!("{AUTHORITY_ADMISSION_INTENT_FAMILY}/{tail}"),
        effect_hash,
        params,
        consumption_receipt: owner.consumption_receipt,
        admission_receipt: owner.admission_receipt,
    })
}

fn portable_consumed_record(
    tail: &str,
    commitment: &Value,
    owner: &super::wallet_network_capability_client::PortableAuthorityConsumptionAdmission,
) -> Value {
    let mut consumed = json!({
        "schema_version": "ioi.hypervisor.authority-admission-intent.v1",
        "intent_id": tail,
        "status": "consumed",
        "authority_mode": "portable_v3",
        "commitment": commitment,
        "consumption_id": hex::encode(owner.consumption_receipt.consumption_id),
        "wallet_consumption_receipt": owner.consumption_receipt,
        "wallet_admission_receipt_v2": owner.admission_receipt,
        "final_invoker_status": "admitted",
    });
    consumed["output_hash"] = json!(record_output_hash(
        &consumed,
        PORTABLE_ADMISSION_EVIDENCE_HASH_EXCLUSIONS,
    ));
    consumed
}

fn portable_admission_from_record(
    reference: &str,
    effect_hash: &str,
    params: &ConsumePortableAuthorityGrantV3ForEffectParams,
    record: &Value,
) -> Result<AdmittedPortableAuthorityGrant, String> {
    revalidate_admission_record(record, effect_hash)?;
    let consumption_receipt = serde_json::from_value(
        record
            .get("wallet_consumption_receipt")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .map_err(|error| format!("portable consumption receipt is malformed: {error}"))?;
    let admission_receipt = serde_json::from_value(
        record
            .get("wallet_admission_receipt_v2")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .map_err(|error| format!("portable admission receipt is malformed: {error}"))?;
    Ok(AdmittedPortableAuthorityGrant {
        admission_intent_ref: reference.to_string(),
        effect_hash: effect_hash.to_string(),
        params: params.clone(),
        consumption_receipt,
        admission_receipt,
    })
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

/// Recover and byte-compare the wallet-owned standing draw before a caller may reach its invoker.
pub(crate) async fn revalidate_standing_admission_receipt(
    data_dir: &str,
    admitted: &AdmittedStandingGrant,
) -> Result<(), String> {
    let tail = admitted
        .admission_intent_ref
        .strip_prefix(&format!("{AUTHORITY_ADMISSION_INTENT_FAMILY}/"))
        .ok_or_else(|| {
            "standing authority intent reference is outside its owner family".to_string()
        })?;
    let record =
        super::durable_fs::read_record_durable(data_dir, AUTHORITY_ADMISSION_INTENT_FAMILY, tail)?
            .ok_or_else(|| "standing authority intent receipt is absent".to_string())?;
    if record.get("status").and_then(Value::as_str) != Some("consumed")
        || record
            .pointer("/commitment/effect_hash")
            .and_then(Value::as_str)
            != Some(admitted.effect_hash.as_str())
    {
        return Err("standing authority intent is not the consumed exact effect".to_string());
    }
    let local_receipt: StandingApprovalGrantConsumptionReceipt = serde_json::from_value(
        record
            .get("wallet_consumption_receipt")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .map_err(|error| format!("standing authority receipt is malformed: {error}"))?;
    if local_receipt != admitted.receipt {
        return Err("standing authority receipt changed after admission".to_string());
    }
    let params = ConsumeStandingApprovalGrantForEffectParams {
        grant_hash: local_receipt.grant_hash,
        standing_envelope_hash: local_receipt.standing_envelope_hash,
        policy_hash: local_receipt.policy_hash,
        request_hash: local_receipt.request_hash,
        consumption_id: local_receipt.consumption_id,
        estimated_deposit_microusd: local_receipt.estimated_deposit_microusd,
        estimated_spend_microusd: local_receipt.estimated_spend_microusd,
        expected_principal_authority: local_receipt.expected_principal_authority.clone(),
        expected_target_label: local_receipt.target_label.clone(),
    };
    let wallet_receipt = super::wallet_network_capability_client::recover_standing_approval_grant_consumption_for_effect(&params)
        .await
        .map_err(|error| format!("standing wallet receipt recovery failed: {error:?}"))?
        .ok_or_else(|| "wallet.network no longer resolves the standing draw receipt".to_string())?;
    if wallet_receipt != local_receipt {
        return Err("standing wallet receipt differs from durable daemon evidence".to_string());
    }
    Ok(())
}

/// Recover and byte-compare both wallet-owned portable records before final invocation.
pub(crate) async fn revalidate_portable_authority_admission(
    data_dir: &str,
    admitted: &AdmittedPortableAuthorityGrant,
) -> Result<(), String> {
    let tail = admitted
        .admission_intent_ref
        .strip_prefix(&format!("{AUTHORITY_ADMISSION_INTENT_FAMILY}/"))
        .ok_or_else(|| {
            "portable authority intent reference is outside its owner family".to_string()
        })?;
    let record =
        super::durable_fs::read_record_durable(data_dir, AUTHORITY_ADMISSION_INTENT_FAMILY, tail)?
            .ok_or_else(|| "portable authority intent receipt is absent".to_string())?;
    revalidate_admission_record(&record, &admitted.effect_hash)?;
    if record.get("authority_mode").and_then(Value::as_str) != Some("portable_v3") {
        return Err("portable authority intent has a foreign authority mode".to_string());
    }
    let expected_output_hash =
        record_output_hash(&record, PORTABLE_ADMISSION_EVIDENCE_HASH_EXCLUSIONS);
    if record.get("output_hash").and_then(Value::as_str) != Some(expected_output_hash.as_str()) {
        return Err("portable authority intent output hash does not recompute".to_string());
    }
    let local_consumption: PortableAuthorityGrantV3ConsumptionReceipt = serde_json::from_value(
        record
            .get("wallet_consumption_receipt")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .map_err(|error| format!("portable consumption receipt is malformed: {error}"))?;
    let local_admission: PortableAuthorityEffectAdmissionReceiptV2Record = serde_json::from_value(
        record
            .get("wallet_admission_receipt_v2")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .map_err(|error| format!("portable admission receipt is malformed: {error}"))?;
    if local_consumption != admitted.consumption_receipt
        || local_admission != admitted.admission_receipt
    {
        return Err("portable authority evidence changed after admission".to_string());
    }

    // Admission is not a temporal lease that may be replayed indefinitely. Re-census the
    // owner plane immediately before the final-invoker claim and require the exact context the
    // wallet sealed to still be current. Profile succession, evaluation replacement, evidence
    // expiry, or loss of required continuity evidence therefore fails closed before any effect.
    let policy_hash = format!(
        "sha256:{}",
        hex::encode(admitted.params.admission.policy_hash)
    );
    let current_admission = resolve_portable_temporal_context(
        data_dir,
        &admitted.params.admission.decision_profile_ref,
        &policy_hash,
        &admitted.params.actual_effect_ref,
        &admitted.effect_hash,
    )?;
    if current_admission != admitted.params.admission {
        return Err("portable authority temporal context changed after admission".to_string());
    }

    // Idempotent wallet replay is authoritative here: it returns the same immutable pair but
    // first re-verifies the current capability client, issuer authority, revocation evidence,
    // signed grant/issuance chain, and exact effect. A recovery or key rotation after consumption
    // therefore cannot carry old authority across the final-invoker boundary.
    let owner =
        super::wallet_network_capability_client::consume_portable_authority_grant_v3_for_effect(
            admitted.params.clone(),
        )
        .await
        .map_err(|error| format!("portable wallet evidence revalidation failed: {error:?}"))?;
    if owner.consumption_receipt != local_consumption || owner.admission_receipt != local_admission
    {
        return Err(
            "daemon portable projection differs from wallet-owned immutable evidence".to_string(),
        );
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PortableAdmissionEvidence {
    pub(crate) admission_intent_ref: String,
    pub(crate) receipt_ref: String,
    pub(crate) receipt_hash: String,
    pub(crate) effect_ref: String,
    pub(crate) effect_hash: String,
    pub(crate) final_invoker_status: String,
}

fn portable_admission_evidence_from_record(
    admission_intent_ref: &str,
    record: &Value,
    expected_effect_ref: &str,
    expected_effect_hash: &str,
    expected_grant_hash: &str,
) -> Result<PortableAdmissionEvidence, String> {
    revalidate_admission_record(record, expected_effect_hash)?;
    if record.get("authority_mode").and_then(Value::as_str) != Some("portable_v3")
        || record
            .pointer("/commitment/effect_ref")
            .and_then(Value::as_str)
            != Some(expected_effect_ref)
        || record
            .pointer("/commitment/grant_hash")
            .and_then(Value::as_str)
            != Some(expected_grant_hash)
    {
        return Err(
            "authority admission evidence does not bind the exact portable grant and effect".into(),
        );
    }
    let output_hash = record_output_hash(record, PORTABLE_ADMISSION_EVIDENCE_HASH_EXCLUSIONS);
    if record.get("output_hash").and_then(Value::as_str) != Some(output_hash.as_str()) {
        return Err("portable authority admission output hash does not recompute".into());
    }
    let paired_receipt: PortableAuthorityEffectAdmissionReceiptV2Record = serde_json::from_value(
        record
            .get("wallet_admission_receipt_v2")
            .cloned()
            .ok_or_else(|| {
                "portable authority admission lacks its registered v2 receipt".to_string()
            })?,
    )
    .map_err(|reason| format!("portable authority admission pair is malformed: {reason}"))?;
    let receipt: Value =
        serde_json::from_slice(&paired_receipt.receipt_json).map_err(|reason| {
            format!("portable authority admission receipt JSON is malformed: {reason}")
        })?;
    validate_architecture_contract(AUTHORITY_EFFECT_ADMISSION_V2_CONTRACT, &receipt).map_err(
        |reason| format!("portable authority admission v2 receipt is invalid: {reason}"),
    )?;
    if receipt
        .pointer("/body/actual_effect_ref")
        .and_then(Value::as_str)
        != Some(expected_effect_ref)
        || receipt
            .pointer("/body/actual_effect_hash")
            .and_then(Value::as_str)
            != Some(expected_effect_hash)
        || receipt
            .pointer("/body/authority_grant_hash")
            .and_then(Value::as_str)
            != Some(expected_grant_hash)
        || receipt.pointer("/body/decision").and_then(Value::as_str) != Some("admitted")
        || receipt
            .pointer("/body/invoker_called")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("portable authority admission v2 receipt differs from durable intent".into());
    }
    let receipt_ref = receipt
        .pointer("/receipt_envelope/receipt_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "portable authority admission v2 receipt has no receipt id".to_string())?;
    let receipt_hash = receipt
        .get("receipt_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "portable authority admission v2 receipt has no receipt hash".to_string())?;
    if sha256_ref_bytes(receipt_hash, "receipt_hash")? != paired_receipt.receipt_hash
        || sha256_ref_bytes(expected_grant_hash, "authority_grant_hash")?
            != paired_receipt.grant_hash
    {
        return Err("portable authority admission pair differs from its registered receipt".into());
    }
    let final_invoker_status = record
        .get("final_invoker_status")
        .and_then(Value::as_str)
        .ok_or_else(|| "portable authority admission has no final-invoker status".to_string())?;
    Ok(PortableAdmissionEvidence {
        admission_intent_ref: admission_intent_ref.to_string(),
        receipt_ref: receipt_ref.to_string(),
        receipt_hash: receipt_hash.to_string(),
        effect_ref: expected_effect_ref.to_string(),
        effect_hash: expected_effect_hash.to_string(),
        final_invoker_status: final_invoker_status.to_string(),
    })
}

/// Resolve the wallet-owned registered v2 admission receipt behind the native
/// route's daemon-local locator. When a response was lost before that locator
/// reached the gateway, exact grant/effect coordinates recover a unique
/// durable slot; ambiguity refuses rather than selecting by directory order.
pub(crate) fn resolve_portable_admission_evidence(
    data_dir: &str,
    admission_receipt_locator: Option<&str>,
    expected_effect_ref: &str,
    expected_effect_hash: &str,
    expected_grant_hash: &str,
) -> Result<PortableAdmissionEvidence, String> {
    if let Some(locator) = admission_receipt_locator {
        let reference = locator.strip_prefix("receipt://").unwrap_or(locator);
        let tail = admission_intent_tail(reference)?;
        let record = super::durable_fs::read_record_durable(
            data_dir,
            AUTHORITY_ADMISSION_INTENT_FAMILY,
            tail,
        )?
        .ok_or_else(|| "portable authority admission locator is absent".to_string())?;
        return portable_admission_evidence_from_record(
            reference,
            &record,
            expected_effect_ref,
            expected_effect_hash,
            expected_grant_hash,
        );
    }

    find_portable_admission_evidence(
        data_dir,
        expected_effect_ref,
        expected_effect_hash,
        expected_grant_hash,
    )?
    .ok_or_else(|| {
        "exact grant/effect coordinates resolve no portable authority admission slot".to_string()
    })
}

/// Find an already-consumed portable admission without treating its absence as
/// an error. Native routes use this before a replayed authorization attempt so
/// they can close a claim that is provably earlier than their own durable
/// Prepared boundary. More than one exact slot is always corrupt/ambiguous.
pub(crate) fn find_portable_admission_evidence(
    data_dir: &str,
    expected_effect_ref: &str,
    expected_effect_hash: &str,
    expected_grant_hash: &str,
) -> Result<Option<PortableAdmissionEvidence>, String> {
    let records = super::system_activation_routes::enumerate_family(
        data_dir,
        AUTHORITY_ADMISSION_INTENT_FAMILY,
    )
    .map_err(|error| format!("portable authority admission census failed: {error:?}"))?;
    let mut matches = Vec::new();
    for (tail, record) in records {
        if record.get("authority_mode").and_then(Value::as_str) == Some("portable_v3")
            && record
                .pointer("/commitment/effect_ref")
                .and_then(Value::as_str)
                == Some(expected_effect_ref)
            && record
                .pointer("/commitment/effect_hash")
                .and_then(Value::as_str)
                == Some(expected_effect_hash)
            && record
                .pointer("/commitment/grant_hash")
                .and_then(Value::as_str)
                == Some(expected_grant_hash)
        {
            matches.push((tail, record));
        }
    }
    if matches.len() > 1 {
        return Err(format!(
            "exact grant/effect coordinates resolve {} portable authority admission slots",
            matches.len()
        ));
    }
    let Some((tail, record)) = matches.pop() else {
        return Ok(None);
    };
    portable_admission_evidence_from_record(
        &format!("{AUTHORITY_ADMISSION_INTENT_FAMILY}/{tail}"),
        &record,
        expected_effect_ref,
        expected_effect_hash,
        expected_grant_hash,
    )
    .map(Some)
}

const PRE_NATIVE_PREPARED_ABSENT_OUTCOME: &str =
    "claim_owner_process_did_not_enter_native_prepared";

/// Close the only recoverable claim-before-dispatch crash window.
///
/// The caller MUST already hold its native operation lock and prove that no
/// native Prepared or terminal record exists for the exact operation. Under
/// that ordering proof, a claim owned by a previous daemon incarnation cannot
/// have entered the native invoker and may be settled as an explicit refusal.
/// A live claim, an invoked claim, or Unknown is never rewritten.
pub(crate) async fn refuse_orphaned_claim_before_native_prepared(
    data_dir: &str,
    evidence: &PortableAdmissionEvidence,
    invoker_label: &str,
) -> Result<bool, String> {
    let _guard = AUTHORITY_ADMISSION_LOCK.lock().await;
    let tail = admission_intent_tail(&evidence.admission_intent_ref)?;
    let mut record =
        super::durable_fs::read_record_durable(data_dir, AUTHORITY_ADMISSION_INTENT_FAMILY, tail)?
            .ok_or_else(|| "authority admission receipt is absent".to_string())?;
    revalidate_admission_record(&record, &evidence.effect_hash)?;
    if record
        .pointer("/commitment/effect_ref")
        .and_then(Value::as_str)
        != Some(evidence.effect_ref.as_str())
    {
        return Err("portable authority admission changed effect identity".to_string());
    }
    let current = FinalInvocationDisposition::parse(
        record.get("final_invoker_status").and_then(Value::as_str),
    )
    .ok_or_else(|| {
        "authority admission receipt carries no final-invoker disposition".to_string()
    })?;
    if current == FinalInvocationDisposition::Admitted {
        return Ok(false);
    }
    if current == FinalInvocationDisposition::Refused {
        if record
            .pointer("/final_invoker_settlement/outcome")
            .and_then(Value::as_str)
            == Some(PRE_NATIVE_PREPARED_ABSENT_OUTCOME)
        {
            return Ok(true);
        }
        return Err("the exact portable admission was refused for a different reason".to_string());
    }
    if current != FinalInvocationDisposition::Claimed {
        return Err(format!(
            "a {} portable admission cannot be recovered as pre-native refusal",
            current.label()
        ));
    }
    let claim = record
        .get("final_invoker_claim")
        .cloned()
        .ok_or_else(|| "claimed portable admission has no claim coordinates".to_string())?;
    if claim.get("effect_hash").and_then(Value::as_str) != Some(evidence.effect_hash.as_str())
        || claim.get("invoker_label").and_then(Value::as_str) != Some(invoker_label)
    {
        return Err("claimed portable admission differs from the exact native invoker".to_string());
    }
    let owner_incarnation = claim
        .get("incarnation_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "claimed portable admission has no process incarnation".to_string())?;
    if owner_incarnation == process_incarnation_id() {
        return Err(
            "the exact native invocation is still claimed by this daemon process".to_string(),
        );
    }
    let claim_id = claim
        .get("claim_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "claimed portable admission has no claim id".to_string())?;
    record["final_invoker_status"] = json!(FinalInvocationDisposition::Refused.label());
    record["final_invoker_settlement"] = json!({
        "claim_id": claim_id,
        "invoker_label": invoker_label,
        "effect_hash": evidence.effect_hash,
        "outcome": PRE_NATIVE_PREPARED_ABSENT_OUTCOME,
        "settled_at_ms": local_now_ms(),
        "reconciled_from_absent_native_prepared": true,
    });
    super::durable_fs::persist_record_durable(
        data_dir,
        AUTHORITY_ADMISSION_INTENT_FAMILY,
        tail,
        &record,
    )
    .map_err(|error| format!("pre-native refusal was not durably recorded: {error:?}"))?;
    let readback =
        super::durable_fs::read_record_durable(data_dir, AUTHORITY_ADMISSION_INTENT_FAMILY, tail)?
            .ok_or_else(|| "pre-native refusal disappeared after durable write".to_string())?;
    if readback.get("final_invoker_status").and_then(Value::as_str) != Some("refused")
        || readback
            .pointer("/final_invoker_settlement/outcome")
            .and_then(Value::as_str)
            != Some(PRE_NATIVE_PREPARED_ABSENT_OUTCOME)
    {
        return Err("pre-native refusal failed durable read-back verification".to_string());
    }
    Ok(true)
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
    revalidate_authoritative_admission(
        data_dir,
        &admitted.admission_intent_ref,
        &admitted.authorized,
    )
    .await?;
    claim_final_invocation_reference(
        data_dir,
        &admitted.admission_intent_ref,
        &admitted.authorized.evidence.effect_hash,
        invoker_label,
    )
    .await
}

/// Portable-v3 variant of the same final-invoker fence. The paired wallet records are
/// revalidated before the common durable claim transition is allowed.
pub(crate) async fn claim_portable_final_invocation(
    data_dir: &str,
    admitted: &AdmittedPortableAuthorityGrant,
    invoker_label: &str,
) -> Result<FinalInvocationClaim, String> {
    revalidate_portable_authority_admission(data_dir, admitted).await?;
    claim_final_invocation_reference(
        data_dir,
        &admitted.admission_intent_ref,
        &admitted.effect_hash,
        invoker_label,
    )
    .await
}

async fn claim_final_invocation_reference(
    data_dir: &str,
    admission_intent_ref: &str,
    effect_hash: &str,
    invoker_label: &str,
) -> Result<FinalInvocationClaim, String> {
    if invoker_label.trim().is_empty() {
        return Err("a final invocation claim names its invoker".to_string());
    }

    let _guard = AUTHORITY_ADMISSION_LOCK.lock().await;
    let tail = admission_intent_tail(admission_intent_ref)?;
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
        "effect_hash": effect_hash,
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
        reference: admission_intent_ref.to_string(),
        claim_id,
        effect_hash: effect_hash.to_string(),
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

/// Settle an orphaned final-invocation claim from independently observed remote truth. Recovery
/// callers do not get to manufacture a new claim: every coordinate must match the durable claim
/// byte-for-byte, and only `claimed`/`reconciliation_required` may advance to `invoked`.
pub(crate) async fn reconcile_final_invocation_as_invoked(
    data_dir: &str,
    reference: &str,
    claim_id: &str,
    effect_hash: &str,
    invoker_label: &str,
    outcome: &str,
) -> Result<(), String> {
    reconcile_final_invocation(
        data_dir,
        reference,
        claim_id,
        effect_hash,
        invoker_label,
        FinalInvocationDisposition::Invoked,
        outcome,
    )
    .await
}

/// Settle a claimed final invoker as a proven pre-effect refusal after its terminal publication
/// record was committed but the ordinary settlement response was lost.
pub(crate) async fn reconcile_final_invocation_as_refused(
    data_dir: &str,
    reference: &str,
    claim_id: &str,
    effect_hash: &str,
    invoker_label: &str,
    reason: &str,
) -> Result<(), String> {
    reconcile_final_invocation(
        data_dir,
        reference,
        claim_id,
        effect_hash,
        invoker_label,
        FinalInvocationDisposition::Refused,
        reason,
    )
    .await
}

/// Preserve spent authority as Unknown when a Prepared dispatch cannot be proven either absent or
/// converged. This is a durable terminal authority disposition, never a refund or a second claim.
pub(crate) async fn mark_final_invocation_reconciliation_required(
    data_dir: &str,
    reference: &str,
    claim_id: &str,
    effect_hash: &str,
    invoker_label: &str,
    reason: &str,
) -> Result<(), String> {
    reconcile_final_invocation(
        data_dir,
        reference,
        claim_id,
        effect_hash,
        invoker_label,
        FinalInvocationDisposition::ReconciliationRequired,
        reason,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_final_invocation(
    data_dir: &str,
    reference: &str,
    claim_id: &str,
    effect_hash: &str,
    invoker_label: &str,
    disposition: FinalInvocationDisposition,
    detail: &str,
) -> Result<(), String> {
    if claim_id.is_empty() || effect_hash.is_empty() || invoker_label.is_empty() {
        return Err("reconciliation requires the exact durable claim coordinates".to_string());
    }
    if !matches!(
        disposition,
        FinalInvocationDisposition::Invoked
            | FinalInvocationDisposition::Refused
            | FinalInvocationDisposition::ReconciliationRequired
    ) {
        return Err(
            "reconciliation may only prove invocation/refusal or preserve Unknown".to_string(),
        );
    }
    let _guard = AUTHORITY_ADMISSION_LOCK.lock().await;
    let tail = admission_intent_tail(reference)?;
    let mut record =
        super::durable_fs::read_record_durable(data_dir, AUTHORITY_ADMISSION_INTENT_FAMILY, tail)?
            .ok_or_else(|| "authority admission receipt is absent".to_string())?;
    let recorded_claim = record.get("final_invoker_claim").ok_or_else(|| {
        "authority admission receipt carries no final-invocation claim".to_string()
    })?;
    for (field, expected) in [
        ("claim_id", claim_id),
        ("effect_hash", effect_hash),
        ("invoker_label", invoker_label),
    ] {
        if recorded_claim.get(field).and_then(Value::as_str) != Some(expected) {
            return Err(format!(
                "reconciliation coordinate '{field}' does not match the durable claim"
            ));
        }
    }
    let current = FinalInvocationDisposition::parse(
        record.get("final_invoker_status").and_then(Value::as_str),
    )
    .ok_or_else(|| {
        "authority admission receipt carries no final-invoker disposition".to_string()
    })?;
    if current == disposition
        && matches!(
            disposition,
            FinalInvocationDisposition::Invoked | FinalInvocationDisposition::Refused
        )
        && record
            .pointer("/final_invoker_settlement/claim_id")
            .and_then(Value::as_str)
            == Some(claim_id)
    {
        return Ok(());
    }
    if !matches!(
        current,
        FinalInvocationDisposition::Claimed | FinalInvocationDisposition::ReconciliationRequired
    ) {
        return Err(format!(
            "a {} final invocation cannot be reconciled to {}",
            current.label(),
            disposition.label()
        ));
    }
    record["final_invoker_status"] = json!(disposition.label());
    if matches!(
        disposition,
        FinalInvocationDisposition::Invoked | FinalInvocationDisposition::Refused
    ) {
        record["final_invoker_settlement"] = json!({
            "claim_id": claim_id,
            "invoker_label": invoker_label,
            "effect_hash": effect_hash,
            "outcome": detail,
            "settled_at_ms": local_now_ms(),
            "reconciled_from_remote_truth": true,
        });
    } else {
        record["final_invoker_reconciliation"] = json!({
            "reason": detail,
            "claim_id": claim_id,
            "invoker_label": invoker_label,
            "effect_hash": effect_hash,
            "observed_at_ms": local_now_ms(),
            "usage_disposition": "spent_not_refunded",
        });
    }
    super::durable_fs::persist_record_durable(
        data_dir,
        AUTHORITY_ADMISSION_INTENT_FAMILY,
        tail,
        &record,
    )
    .map_err(|error| format!("reconciled final-invocation disposition was not durable: {error:?}"))
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
    revalidate_admission_record(&record, expected_effect_hash)
}

fn revalidate_admission_record(record: &Value, expected_effect_hash: &str) -> Result<(), String> {
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

pub(crate) fn live_effect_hash(effect: &Value) -> Result<String, String> {
    let material = json!({
        "domain": "ioi.hypervisor.live-authority-effect.v1",
        "effect": effect,
    });
    let encoded = serde_jcs::to_vec(&material)
        .map_err(|error| format!("live effect cannot be canonicalized: {error}"))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(encoded))))
}

pub(crate) fn portable_effect_ref(effect_hash: &str) -> Result<String, String> {
    let bytes = sha256_ref_bytes(effect_hash, "effect_hash")?;
    Ok(format!(
        "effect://hypervisor/live-route/{}",
        hex::encode(bytes)
    ))
}

const TEMPORAL_PROFILE_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/temporal-verification-profile/v1";
const TEMPORAL_EVALUATION_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/temporal-validity-evaluation/v1";
const TEMPORAL_PROFILE_FAMILY: &str = "hypervisoros-temporal-profiles";
const TEMPORAL_EVIDENCE_FAMILY: &str = "hypervisoros-node-evidence";

fn enumerate_censused_authority_family(data_dir: &str, family: &str) -> Result<Vec<Value>, String> {
    let local = super::system_activation_routes::enumerate_family(data_dir, family)
        .map_err(|error| format!("local census for '{family}' failed: {error:?}"))?;
    let mut local_values: Vec<Value> = local.into_iter().map(|(_, value)| value).collect();
    let mut substrate = super::substrate_store::read_required_all(data_dir, family)
        .map_err(|error| format!("Agentgres census for '{family}' failed: {error}"))?;
    let sort_key = |value: &Value| serde_json::to_string(value).unwrap_or_default();
    local_values.sort_by_key(sort_key);
    substrate.sort_by_key(sort_key);
    if local_values != substrate {
        return Err(format!(
            "local and Agentgres censuses for '{family}' differ"
        ));
    }
    Ok(local_values)
}

fn parse_temporal_bound_ms(value: &Value, pointer: &str) -> Result<u64, String> {
    let text = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("temporal evaluation requires '{pointer}'"))?;
    let parsed = OffsetDateTime::parse(text, &Rfc3339)
        .map_err(|error| format!("temporal bound '{pointer}' is invalid: {error}"))?;
    u64::try_from(parsed.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| format!("temporal bound '{pointer}' predates the supported epoch"))
}

fn resolve_portable_temporal_context_from_records(
    profiles: &[Value],
    evaluations: &[Value],
    decision_profile_ref: &str,
    policy_hash: &str,
    effect_ref: &str,
    effect_hash: &str,
    now_ms: u64,
) -> Result<PortableAuthorityEffectAdmissionContextV1, String> {
    let mut rooted = Vec::with_capacity(profiles.len());
    for profile in profiles {
        validate_architecture_contract(TEMPORAL_PROFILE_CONTRACT, profile)
            .map_err(|error| format!("temporal profile is not registered-valid: {error}"))?;
        rooted.push((profile, temporal_profile_root(profile)?));
    }
    let cited: Vec<&str> = rooted
        .iter()
        .filter_map(|(profile, _)| {
            profile
                .get("predecessor_profile_root")
                .and_then(Value::as_str)
        })
        .collect();
    let mut current: Vec<&Value> = rooted
        .iter()
        .filter(|(profile, root)| {
            profile.get("status").and_then(Value::as_str) == Some("declared")
                && !cited.contains(&root.as_str())
        })
        .map(|(profile, _)| *profile)
        .collect();
    let profile = match current.len() {
        1 => current.pop().expect("one current profile"),
        0 => return Err("no current declared temporal profile exists".to_string()),
        _ => return Err("multiple temporal profiles claim current owner state".to_string()),
    };
    if !profile
        .pointer("/declaration/applicable_operation_classes")
        .and_then(Value::as_array)
        .is_some_and(|classes| classes.iter().any(|value| value == "external_effect"))
    {
        return Err("the current temporal profile does not admit external effects".to_string());
    }
    if profile
        .pointer("/declaration/required_effect_fence_profile_ref")
        .is_some_and(|value| !value.is_null())
    {
        return Err(
            "the current temporal profile requires an effect-fence profile that this admission does not prove"
                .to_string(),
        );
    }
    let profile_ref = profile
        .get("profile_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "the current temporal profile lacks profile_ref".to_string())?;
    let profile_hash = profile
        .get("profile_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "the current temporal profile lacks profile_hash".to_string())?;
    let required_claims: Vec<&str> = profile
        .pointer("/declaration/required_claims")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let minimum_domains = profile
        .pointer(
            "/declaration/evidence_policy/required_failure_domain_separation/minimum_distinct_source_domains",
        )
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    let maximum_uncertainty_ms = profile
        .pointer("/declaration/evidence_policy/maximum_uncertainty_ms")
        .and_then(Value::as_u64);
    let maximum_evidence_age_ms = profile
        .pointer("/declaration/evidence_policy/maximum_evidence_age_ms")
        .and_then(Value::as_u64);
    let protected_floor_kinds: Vec<&str> = profile
        .pointer("/declaration/continuity_policy/protected_namespace_floor_kinds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();

    let mut matching = Vec::new();
    for evaluation in evaluations {
        if evaluation.get("schema_version").and_then(Value::as_str)
            != Some("ioi.components.daemon-runtime.temporal-validity-evaluation.v1")
        {
            continue;
        }
        validate_architecture_contract(TEMPORAL_EVALUATION_CONTRACT, evaluation)
            .map_err(|error| format!("temporal evaluation is not registered-valid: {error}"))?;
        if evaluation.get("profile_ref").and_then(Value::as_str) == Some(profile_ref)
            && evaluation.get("profile_hash").and_then(Value::as_str) == Some(profile_hash)
            && evaluation.get("subject_ref").and_then(Value::as_str) == Some(effect_ref)
            && evaluation.get("subject_hash").and_then(Value::as_str) == Some(effect_hash)
            && evaluation.get("operation_class").and_then(Value::as_str) == Some("external_effect")
        {
            matching.push(evaluation);
        }
    }
    let evaluation = match matching.len() {
        1 => matching.pop().expect("one exact temporal evaluation"),
        0 => {
            return Err(
                "no durable temporal evaluation binds the current profile and exact effect"
                    .to_string(),
            )
        }
        _ => return Err("multiple temporal evaluations bind the same exact effect".to_string()),
    };
    let claims = evaluation
        .get("claims")
        .and_then(Value::as_array)
        .ok_or_else(|| "temporal evaluation lacks claims".to_string())?;
    for required in &required_claims {
        if !claims.iter().any(|claim| {
            claim.get("kind").and_then(Value::as_str) == Some(*required)
                && claim.get("status").and_then(Value::as_str) == Some("established")
        }) {
            return Err(format!(
                "temporal evaluation does not establish required claim '{required}'"
            ));
        }
    }
    for claim in claims
        .iter()
        .filter(|claim| claim.get("status").and_then(Value::as_str) == Some("established"))
    {
        if maximum_uncertainty_ms.is_some_and(|maximum| {
            claim
                .get("uncertainty_ms")
                .and_then(Value::as_u64)
                .is_some_and(|actual| actual > maximum)
        }) {
            return Err("temporal claim exceeds the profile uncertainty bound".to_string());
        }
        if maximum_evidence_age_ms.is_some_and(|maximum| {
            claim
                .get("maximum_age_ms")
                .and_then(Value::as_u64)
                .is_some_and(|actual| actual > maximum)
        }) {
            return Err("temporal claim exceeds the profile evidence-age bound".to_string());
        }
    }
    for floor_kind in &protected_floor_kinds {
        if !claims.iter().any(|claim| {
            claim.get("kind").and_then(Value::as_str) == Some("continuity_floor")
                && claim.get("status").and_then(Value::as_str) == Some("established")
                && claim.get("floor_kind").and_then(Value::as_str) == Some(*floor_kind)
                && claim
                    .get("outside_rollback_domain_evidence_refs")
                    .and_then(Value::as_array)
                    .is_some_and(|refs| !refs.is_empty())
        }) {
            return Err(format!(
                "temporal evaluation does not establish protected continuity floor '{floor_kind}'"
            ));
        }
    }
    let domain_count = evaluation
        .get("source_failure_domain_refs")
        .and_then(Value::as_array)
        .map(|values| values.len() as u64)
        .unwrap_or_default();
    if domain_count < minimum_domains {
        return Err("temporal evaluation lacks the required failure-domain separation".to_string());
    }
    let valid_from = parse_temporal_bound_ms(evaluation, "/evidence_horizon/valid_from")?;
    let valid_until = parse_temporal_bound_ms(evaluation, "/evidence_horizon/valid_until")?;
    if valid_until < valid_from
        || maximum_evidence_age_ms
            .is_some_and(|maximum| valid_until.saturating_sub(valid_from) > maximum)
    {
        return Err("temporal evaluation exceeds the profile evidence horizon".to_string());
    }
    if now_ms < valid_from || now_ms > valid_until {
        return Err("temporal evaluation is outside its evidence horizon".to_string());
    }
    if evaluation
        .get("obligations")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty())
    {
        return Err("temporal evaluation has unresolved pre-effect obligations".to_string());
    }
    let evidence_horizon_ms = valid_until.saturating_sub(valid_from);
    let temporal_posture = match evaluation.get("temporal_posture").and_then(Value::as_str) {
        Some("online_fresh") => PortableAuthorityTemporalPostureV1::OnlineFresh,
        Some("bounded_offline")
            if profile
                .pointer("/declaration/disconnected_policy/allowed_operation_classes")
                .and_then(Value::as_array)
                .is_some_and(|classes| classes.iter().any(|value| value == "external_effect")) =>
        {
            let maximum_holdover_ms = profile
                .pointer("/declaration/disconnected_policy/maximum_holdover_ms")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    "offline external effects require an explicit maximum holdover".to_string()
                })?;
            let maximum_revocation_exposure_ms = profile
                .pointer("/declaration/disconnected_policy/maximum_revocation_exposure_ms")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    "offline external effects require an explicit maximum revocation exposure"
                        .to_string()
                })?;
            if evidence_horizon_ms > maximum_holdover_ms
                || evidence_horizon_ms > maximum_revocation_exposure_ms
            {
                return Err(
                    "offline temporal evaluation exceeds its holdover or revocation-exposure bound"
                        .to_string(),
                );
            }
            PortableAuthorityTemporalPostureV1::BoundedOffline
        }
        Some("bounded_offline") => {
            return Err("the temporal profile forbids offline external effects".to_string())
        }
        _ => return Err("temporal evaluation posture cannot admit an effect".to_string()),
    };
    let mut continuity_floor_evidence_refs: Vec<String> = claims
        .iter()
        .filter(|claim| {
            claim.get("kind").and_then(Value::as_str) == Some("continuity_floor")
                && claim.get("status").and_then(Value::as_str) == Some("established")
        })
        .flat_map(|claim| {
            claim
                .get("outside_rollback_domain_evidence_refs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    continuity_floor_evidence_refs.sort();
    continuity_floor_evidence_refs.dedup();
    if required_claims.contains(&"continuity_floor") && continuity_floor_evidence_refs.is_empty() {
        return Err(
            "established continuity-floor claim carries no outside-domain evidence".to_string(),
        );
    }
    Ok(PortableAuthorityEffectAdmissionContextV1 {
        decision_profile_ref: decision_profile_ref.to_string(),
        policy_hash: sha256_ref_bytes(policy_hash, "policy_hash")?,
        temporal_verification_profile_ref: profile_ref.to_string(),
        temporal_verification_profile_hash: sha256_ref_bytes(profile_hash, "profile_hash")?,
        temporal_validity_evaluation_ref: evaluation
            .get("evaluation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "temporal evaluation lacks evaluation_id".to_string())?
            .to_string(),
        temporal_validity_evaluation_hash: sha256_ref_bytes(
            evaluation
                .get("evaluation_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| "temporal evaluation lacks evaluation_hash".to_string())?,
            "evaluation_hash",
        )?,
        temporal_posture,
        continuity_floor_evidence_refs,
        principal_authority_revalidation_receipt_ref: None,
        principal_authority_revalidation_receipt_hash: None,
    })
}

pub(crate) fn resolve_portable_temporal_context(
    data_dir: &str,
    decision_profile_ref: &str,
    policy_hash: &str,
    effect_ref: &str,
    effect_hash: &str,
) -> Result<PortableAuthorityEffectAdmissionContextV1, String> {
    let profiles = enumerate_censused_authority_family(data_dir, TEMPORAL_PROFILE_FAMILY)?;
    let evaluations = enumerate_censused_authority_family(data_dir, TEMPORAL_EVIDENCE_FAMILY)?;
    resolve_portable_temporal_context_from_records(
        &profiles,
        &evaluations,
        decision_profile_ref,
        policy_hash,
        effect_ref,
        effect_hash,
        local_now_ms(),
    )
}

/// Resolve every non-request binding needed to turn a grant-hash locator into an admission.
/// Signed audience/holder coordinates come from wallet state, and temporal claims come from the
/// current censused owner plane. The locator alone never authorizes or supplies policy facts.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_portable_authority_locator(
    data_dir: &str,
    contract: AuthorityContract,
    grant_hash: [u8; 32],
    required_scope: &str,
    decision_profile_ref: &str,
    policy_hash: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
    effect: &Value,
    recovery_reuses_consumed_receipt: bool,
) -> Result<AdmittedPortableAuthorityGrant, (StatusCode, Json<Value>)> {
    let effect_hash = live_effect_hash(effect).map_err(|message| {
        authority_consumption_challenge(
            contract,
            StatusCode::INTERNAL_SERVER_ERROR,
            "portable_authority_effect_invalid",
            message,
        )
    })?;
    let effect_ref = portable_effect_ref(&effect_hash).map_err(|message| {
        authority_consumption_challenge(
            contract,
            StatusCode::INTERNAL_SERVER_ERROR,
            "portable_authority_effect_invalid",
            message,
        )
    })?;
    let effect_hash_bytes = sha256_ref_bytes(&effect_hash, "effect_hash").map_err(|message| {
        authority_consumption_challenge(
            contract,
            StatusCode::INTERNAL_SERVER_ERROR,
            "portable_authority_effect_invalid",
            message,
        )
    })?;
    let binding =
        super::wallet_network_capability_client::resolve_portable_authority_grant_v3_for_effect(
            grant_hash,
            &effect_ref,
            effect_hash_bytes,
        )
        .await
        .map_err(|error| map_consumption_error(contract, error))?;
    let admission = resolve_portable_temporal_context(
        data_dir,
        decision_profile_ref,
        policy_hash,
        &effect_ref,
        &effect_hash,
    )
    .map_err(|message| {
        authority_consumption_challenge(
            contract,
            StatusCode::PRECONDITION_REQUIRED,
            "portable_authority_temporal_evidence_required",
            message,
        )
    })?;
    authorize_portable_authority_effect(
        data_dir,
        contract,
        required_scope,
        subject_ref,
        op,
        revision,
        effect,
        PortableAuthorityPepContext {
            grant_hash,
            expected_audience: binding.audience,
            expected_holder_id: binding.holder_id,
            expected_holder_key_id: binding.holder_key_id,
            actual_effect_ref: effect_ref,
            admission,
        },
        recovery_reuses_consumed_receipt,
    )
    .await
}

/// Resolve the deployment-owned principal independently of request evidence, verify the submitted
/// grant against that current issuer and the daemon-derived exact commitments, durably prepare an
/// admission intent, and atomically consume one wallet-owned usage. Callers pass the complete
/// effect material and invoke nothing unless this function returns its admitted decision.
#[allow(clippy::too_many_arguments)]
async fn authorize_deployment_grant_with_recovery(
    data_dir: &str,
    grant_value: &Value,
    required_scope: &str,
    policy_hash: &str,
    request_hash: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
    effect: &Value,
    recovery_reuses_consumed_receipt: bool,
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
        recovery_reuses_consumed_receipt,
    )
    .await?;
    Ok(AdmittedDeploymentGrant {
        authorized,
        admission_intent_ref,
    })
}

/// Resolve and consume deployment authority for a non-replayable operation. A previously
/// consumed deterministic admission is a typed conflict rather than reusable authority.
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
    authorize_deployment_grant_with_recovery(
        data_dir,
        grant_value,
        required_scope,
        policy_hash,
        request_hash,
        subject_ref,
        op,
        revision,
        effect,
        false,
    )
    .await
}

/// Resolve current deployment authority, bind one exact effect to a registered standing
/// envelope, durably prepare it, and atomically reserve usage/deposit/spend in wallet.network.
/// The C7 exact-request path above remains a separate signing and consumption domain.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_standing_deployment_grant(
    data_dir: &str,
    grant_value: &Value,
    standing_envelope_hash: [u8; 32],
    policy_hash: [u8; 32],
    required_scope: &str,
    request_hash_ref: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
    effect: &Value,
    estimated_deposit_microusd: u64,
    estimated_spend_microusd: u64,
    max_usages: u32,
    max_cumulative_deposit_microusd: u64,
    max_cumulative_spend_microusd: u64,
) -> Result<AdmittedStandingGrant, (StatusCode, Json<Value>)> {
    let required_authority = std::env::var("IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            authority_consumption_challenge(
                LIVE_ROUTE_AUTHORITY,
                StatusCode::NOT_IMPLEMENTED,
                "authority_principal_not_configured",
                "IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF is required; a standing grant never selects its own deployment authority".to_string(),
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
            Json(json!({"error": {
                "code": code,
                "message": message,
                "required_authority_ref": required_authority,
                "required_scope": required_scope,
                "runtimeTruthSource": "daemon-runtime"
            }})),
        )
    })?;
    let (grant, canonical_grant) =
        canonicalize_standing_approval_grant(grant_value).map_err(|message| {
            authority_consumption_challenge(
                LIVE_ROUTE_AUTHORITY,
                StatusCode::FORBIDDEN,
                "standing_authority_grant_invalid",
                message,
            )
        })?;
    let now_ms = local_now_ms();
    if grant.standing_envelope_hash != standing_envelope_hash
        || grant.policy_hash != policy_hash
        || grant.max_usages > max_usages
        || grant.max_cumulative_deposit_microusd > max_cumulative_deposit_microusd
        || grant.max_cumulative_spend_microusd > max_cumulative_spend_microusd
        || now_ms < grant.issued_at_ms
        || now_ms > grant.expires_at_ms
    {
        return Err(authority_consumption_challenge(
            LIVE_ROUTE_AUTHORITY,
            StatusCode::FORBIDDEN,
            "standing_authority_grant_invalid",
            "standing grant does not bind the exact envelope/policy or current validity window"
                .to_string(),
        ));
    }
    let authority = &resolution.resolution.approval_authority;
    if grant.authority_id != authority.authority_id
        || grant.approver_public_key != authority.public_key
        || grant.approver_suite != authority.signature_suite
    {
        return Err(authority_consumption_challenge(
            LIVE_ROUTE_AUTHORITY,
            StatusCode::FORBIDDEN,
            "standing_authority_issuer_mismatch",
            "standing grant signer tuple does not match the independently resolved current deployment authority".to_string(),
        ));
    }
    let request_hash = sha256_ref_bytes(request_hash_ref, "request_hash").map_err(|message| {
        authority_consumption_challenge(
            LIVE_ROUTE_AUTHORITY,
            StatusCode::FORBIDDEN,
            "standing_authority_consumption_invalid",
            message,
        )
    })?;
    let grant_hash = grant.artifact_hash().map_err(|error| {
        authority_consumption_challenge(
            LIVE_ROUTE_AUTHORITY,
            StatusCode::FORBIDDEN,
            "standing_authority_consumption_invalid",
            format!("standing approval grant cannot be hashed: {error}"),
        )
    })?;
    let expected_principal_authority: ExpectedPrincipalAuthorityBinding =
        serde_json::from_value(resolution.authority_binding.clone()).map_err(|error| {
            authority_consumption_challenge(
                LIVE_ROUTE_AUTHORITY,
                StatusCode::BAD_GATEWAY,
                "standing_authority_consumption_invalid",
                format!("resolved principal authority cannot authorize standing use: {error}"),
            )
        })?;
    let effect_hash = live_effect_hash(effect).map_err(|message| {
        authority_consumption_challenge(
            LIVE_ROUTE_AUTHORITY,
            StatusCode::INTERNAL_SERVER_ERROR,
            "standing_authority_effect_invalid",
            message,
        )
    })?;
    let commitment = json!({
        "domain": "ioi.hypervisor.standing-authority-consumption.v1",
        "approval_mode": "silent_within_standing_envelope",
        "subject_ref": subject_ref,
        "operation": op,
        "revision": revision,
        "required_scope": required_scope,
        "standing_envelope_hash": format!("sha256:{}", hex::encode(standing_envelope_hash)),
        "policy_hash": format!("sha256:{}", hex::encode(policy_hash)),
        "request_hash": request_hash_ref,
        "effect_hash": effect_hash,
        "grant_hash": format!("sha256:{}", hex::encode(grant_hash)),
        "estimated_deposit_microusd": estimated_deposit_microusd,
        "estimated_spend_microusd": estimated_spend_microusd,
        "principal_authority": expected_principal_authority,
        "standing_approval_grant": canonical_grant,
    });
    let encoded = serde_jcs::to_vec(&commitment).map_err(|error| {
        authority_consumption_challenge(
            LIVE_ROUTE_AUTHORITY,
            StatusCode::INTERNAL_SERVER_ERROR,
            "standing_authority_intent_invalid",
            format!("standing authority intent cannot be canonicalized: {error}"),
        )
    })?;
    let mut consumption_id = [0u8; 32];
    consumption_id.copy_from_slice(&Sha256::digest(encoded));
    let tail = format!("sai_{}", hex::encode(consumption_id));
    let params = ConsumeStandingApprovalGrantForEffectParams {
        grant_hash,
        standing_envelope_hash,
        policy_hash,
        request_hash,
        consumption_id,
        estimated_deposit_microusd,
        estimated_spend_microusd,
        expected_principal_authority,
        expected_target_label: required_scope.to_string(),
    };

    let _guard = AUTHORITY_ADMISSION_LOCK.lock().await;
    let existing =
        super::durable_fs::read_record_durable(data_dir, AUTHORITY_ADMISSION_INTENT_FAMILY, &tail)
            .map_err(|message| {
                authority_consumption_challenge(
                    LIVE_ROUTE_AUTHORITY,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "standing_authority_intent_unreadable",
                    message,
                )
            })?;
    if existing
        .as_ref()
        .is_some_and(|record| record.get("commitment") != Some(&commitment))
    {
        return Err(authority_consumption_challenge(
            LIVE_ROUTE_AUTHORITY,
            StatusCode::CONFLICT,
            "standing_authority_intent_conflict",
            "the deterministic standing-authority slot contains a different commitment".into(),
        ));
    }
    if existing
        .as_ref()
        .is_some_and(|record| record.get("status").and_then(Value::as_str) == Some("consumed"))
    {
        return Err(authority_consumption_challenge(
            LIVE_ROUTE_AUTHORITY,
            StatusCode::CONFLICT,
            "standing_authority_operation_already_admitted",
            "this exact standing-authority operation is already consumed and cannot invoke twice"
                .into(),
        ));
    }
    if existing.is_none() {
        super::durable_fs::persist_record_durable(
            data_dir,
            AUTHORITY_ADMISSION_INTENT_FAMILY,
            &tail,
            &json!({
                "schema_version": "ioi.hypervisor.authority-admission-intent.v1",
                "intent_id": tail,
                "status": "prepared",
                "authority_mode": "standing_envelope",
                "commitment": commitment,
                "consumption_id": hex::encode(consumption_id),
                "wallet_consumption_receipt": Value::Null,
                "final_invoker_status": "pending",
            }),
        )
        .map_err(|error| {
            authority_consumption_challenge(
                LIVE_ROUTE_AUTHORITY,
                StatusCode::INTERNAL_SERVER_ERROR,
                "standing_authority_intent_not_durable",
                format!("standing authority intent was not durably prepared: {error:?}"),
            )
        })?;
    }
    let receipt =
        super::wallet_network_capability_client::consume_standing_approval_grant_for_effect(params)
            .await
            .map_err(|error| map_consumption_error(LIVE_ROUTE_AUTHORITY, error))?;
    let mut consumed = json!({
        "schema_version": "ioi.hypervisor.authority-admission-intent.v1",
        "intent_id": tail,
        "status": "consumed",
        "authority_mode": "standing_envelope",
        "commitment": commitment,
        "consumption_id": hex::encode(consumption_id),
        "wallet_consumption_receipt": receipt,
        "final_invoker_status": "admitted",
    });
    consumed["output_hash"] = json!(record_output_hash(&consumed, &["output_hash"]));
    super::durable_fs::persist_record_durable(
        data_dir,
        AUTHORITY_ADMISSION_INTENT_FAMILY,
        &tail,
        &consumed,
    )
    .map_err(|error| {
        authority_consumption_challenge(
            LIVE_ROUTE_AUTHORITY,
            StatusCode::INTERNAL_SERVER_ERROR,
            "standing_authority_receipt_not_durable",
            format!("wallet committed the draw but its daemon receipt did not persist: {error:?}"),
        )
    })?;
    Ok(AdmittedStandingGrant {
        admission_intent_ref: format!("{AUTHORITY_ADMISSION_INTENT_FAMILY}/{tail}"),
        effect_hash,
        grant_ref: format!("standing-grant://sha256:{}", hex::encode(grant_hash)),
        receipt,
    })
}

/// Resolve deployment authority for an operation whose owner route is byte-idempotent and whose
/// durable partial state proves that retrying can only converge the same effect. A consumed exact
/// admission receipt is revalidated against wallet truth; it is never re-consumed or widened.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_deployment_grant_for_idempotent_recovery(
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
    authorize_deployment_grant_with_recovery(
        data_dir,
        grant_value,
        required_scope,
        policy_hash,
        request_hash,
        subject_ref,
        op,
        revision,
        effect,
        true,
    )
    .await
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

#[cfg(test)]
mod portable_authority_intent_tests {
    use super::*;

    fn owner_pair(
    ) -> super::super::wallet_network_capability_client::PortableAuthorityConsumptionAdmission {
        super::super::wallet_network_capability_client::PortableAuthorityConsumptionAdmission {
            consumption_receipt: PortableAuthorityGrantV3ConsumptionReceipt {
                schema_version: 1,
                receipt_hash: [0x11; 32],
                grant_hash: [0x22; 32],
                consumption_id: [0x33; 32],
                authority_grant_ref: "authority-grant://tests/portable/1".to_string(),
                actual_effect_ref: "effect://tests/portable/1".to_string(),
                actual_effect_hash: [0x44; 32],
                audience: "daemon://tests/pep".to_string(),
                holder_id: "worker://tests/holder".to_string(),
                holder_key_id: "key://tests/holder/1".to_string(),
                admission_receipt_hash: [0x55; 32],
                consumed_at_ms: 1_787_587_300_000,
                usage_ordinal: 1,
                remaining_calls: 0,
            },
            admission_receipt: PortableAuthorityEffectAdmissionReceiptV2Record {
                schema_version: 1,
                grant_hash: [0x22; 32],
                consumption_id: [0x33; 32],
                receipt_hash: [0x55; 32],
                receipt_json: br#"{"schema_version":"tests"}"#.to_vec(),
            },
        }
    }

    fn fixture(name: &str) -> Value {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        serde_json::from_slice(&std::fs::read(root.join(name)).expect("fixture bytes"))
            .expect("fixture JSON")
    }

    fn hash_material(material: Value) -> String {
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                serde_jcs::to_vec(&material).expect("canonical test material")
            ))
        )
    }

    fn temporal_records() -> (Value, Value, String, String, u64) {
        let mut profile = fixture(
            "docs/architecture/_meta/schemas/fixtures/temporal-verification-profile-v1/positive-declared.json",
        );
        profile["declaration"]["applicable_operation_classes"] = json!(["external_effect"]);
        refresh_profile_hash(&mut profile);

        let effect_ref = "effect://hypervisor/tests/portable".to_string();
        let effect_hash = format!("sha256:{}", hex::encode([0x44; 32]));
        let mut evaluation = fixture(
            "docs/architecture/_meta/schemas/fixtures/temporal-validity-evaluation-v1/positive-online-fresh.json",
        );
        evaluation["profile_hash"] = profile["profile_hash"].clone();
        evaluation["subject_ref"] = json!(effect_ref);
        evaluation["subject_hash"] = json!(effect_hash);
        evaluation["operation_class"] = json!("external_effect");
        evaluation["evidence_horizon"] = json!({
            "valid_from": "2026-08-24T12:00:00Z",
            "valid_until": "2026-08-24T12:10:00Z",
        });
        evaluation["obligations"] = json!([]);
        refresh_evaluation_hash(&mut evaluation);
        let now_ms = parse_temporal_bound_ms(&json!({"at":"2026-08-24T12:05:00Z"}), "/at")
            .expect("test time");
        (profile, evaluation, effect_ref, effect_hash, now_ms)
    }

    fn refresh_profile_hash(profile: &mut Value) {
        profile["profile_hash"] = json!(hash_material(json!({
            "domain": "ioi.temporal-verification-profile-hash-jcs-sha256.v1",
            "profile_ref": profile["profile_ref"],
            "profile_version": profile["profile_version"],
            "declaration": profile["declaration"],
        })));
    }

    fn refresh_evaluation_hash(evaluation: &mut Value) {
        evaluation["evaluation_hash"] = json!(hash_material(json!({
            "domain": "ioi.temporal-validity-evaluation-hash-jcs-sha256.v1",
            "evaluation_id": evaluation["evaluation_id"],
            "profile_ref": evaluation["profile_ref"],
            "profile_hash": evaluation["profile_hash"],
            "subject_ref": evaluation["subject_ref"],
            "subject_hash": evaluation["subject_hash"],
            "operation_class": evaluation["operation_class"],
            "evidence_refs": evaluation["evidence_refs"],
            "source_failure_domain_refs": evaluation["source_failure_domain_refs"],
            "claims": evaluation["claims"],
            "temporal_posture": evaluation["temporal_posture"],
            "evidence_horizon": evaluation["evidence_horizon"],
            "invalidation_triggers": evaluation["invalidation_triggers"],
            "obligations": evaluation["obligations"],
        })));
    }

    #[test]
    fn portable_projection_retains_the_atomic_pair_and_starts_claimable() {
        let effect_hash = format!("sha256:{}", hex::encode([0x44; 32]));
        let commitment = json!({
            "domain": "ioi.hypervisor.portable-authority-consumption.v1",
            "effect_hash": effect_hash,
        });
        let record = portable_consumed_record("pai_tests", &commitment, &owner_pair());

        assert_eq!(record["authority_mode"], "portable_v3");
        assert_eq!(record["final_invoker_status"], "admitted");
        assert_eq!(
            record["wallet_consumption_receipt"]["admission_receipt_hash"],
            record["wallet_admission_receipt_v2"]["receipt_hash"]
        );
        assert_eq!(
            record["output_hash"],
            record_output_hash(&record, PORTABLE_ADMISSION_EVIDENCE_HASH_EXCLUSIONS)
        );
        revalidate_admission_record(&record, &effect_hash)
            .expect("the exact portable effect is retained");
        let mut claimed = record.clone();
        claimed["final_invoker_status"] = json!("claimed");
        claimed["final_invoker_claim"] = json!({"claim_id":"fic_tests"});
        assert_eq!(
            claimed["output_hash"],
            record_output_hash(&claimed, PORTABLE_ADMISSION_EVIDENCE_HASH_EXCLUSIONS),
            "legitimate finalizer state must not invalidate immutable authority evidence"
        );
    }

    #[test]
    fn portable_projection_rejects_effect_substitution_and_hash_tampering() {
        let effect_hash = format!("sha256:{}", hex::encode([0x44; 32]));
        let commitment = json!({
            "domain": "ioi.hypervisor.portable-authority-consumption.v1",
            "effect_hash": effect_hash,
        });
        let mut record = portable_consumed_record("pai_tests", &commitment, &owner_pair());
        assert!(revalidate_admission_record(
            &record,
            &format!("sha256:{}", hex::encode([0x45; 32]))
        )
        .is_err());

        record["wallet_admission_receipt_v2"]["receipt_hash"] = json!(vec![0; 32]);
        assert_ne!(
            record["output_hash"],
            record_output_hash(&record, PORTABLE_ADMISSION_EVIDENCE_HASH_EXCLUSIONS),
            "editing either half of the wallet pair invalidates the daemon projection"
        );
    }

    #[test]
    fn gateway_resolves_the_registered_v2_receipt_from_the_sealed_portable_pair() {
        let receipt = fixture(
            "docs/architecture/_meta/schemas/fixtures/authority-effect-admission-receipt-v2/positive-exact-effect.json",
        );
        let effect_ref = receipt["body"]["actual_effect_ref"]
            .as_str()
            .expect("effect ref");
        let effect_hash = receipt["body"]["actual_effect_hash"]
            .as_str()
            .expect("effect hash");
        let grant_hash = receipt["body"]["authority_grant_hash"]
            .as_str()
            .expect("grant hash");
        let mut pair = owner_pair();
        pair.admission_receipt = PortableAuthorityEffectAdmissionReceiptV2Record {
            schema_version: 1,
            grant_hash: sha256_ref_bytes(grant_hash, "grant_hash").unwrap(),
            consumption_id: [0x33; 32],
            receipt_hash: sha256_ref_bytes(
                receipt["receipt_hash"].as_str().expect("receipt hash"),
                "receipt_hash",
            )
            .unwrap(),
            receipt_json: serde_jcs::to_vec(&receipt).unwrap(),
        };
        let commitment = json!({
            "domain":"ioi.hypervisor.portable-authority-consumption.v1",
            "effect_ref":effect_ref,
            "effect_hash":effect_hash,
            "grant_hash":grant_hash,
        });
        let mut record = portable_consumed_record("pai_gateway", &commitment, &pair);
        record["final_invoker_status"] = json!("invoked");
        let resolved = portable_admission_evidence_from_record(
            "authority-admission-intents/pai_gateway",
            &record,
            effect_ref,
            effect_hash,
            grant_hash,
        )
        .expect("registered admission evidence");
        assert_eq!(
            resolved.receipt_ref,
            receipt["receipt_envelope"]["receipt_id"]
        );
        assert_eq!(resolved.receipt_hash, receipt["receipt_hash"]);
        assert_eq!(resolved.final_invoker_status, "invoked");

        assert!(portable_admission_evidence_from_record(
            "authority-admission-intents/pai_gateway",
            &record,
            effect_ref,
            &format!("sha256:{}", hex::encode([0x99; 32])),
            grant_hash,
        )
        .is_err());
    }

    #[tokio::test]
    async fn absent_native_prepared_settles_only_a_dead_process_claim_as_refused() {
        let data_dir = std::env::temp_dir().join(format!(
            "ioi-portable-pre-native-refusal-{:032x}",
            nonce_nanos()
        ));
        let data_dir_text = data_dir.to_string_lossy().to_string();
        let effect_ref = "effect://hypervisor/tests/pre-native";
        let effect_hash = format!("sha256:{}", hex::encode([0x44; 32]));
        let grant_hash = format!("sha256:{}", hex::encode([0x22; 32]));
        let commitment = json!({
            "domain":"ioi.hypervisor.portable-authority-consumption.v1",
            "effect_ref":effect_ref,
            "effect_hash":effect_hash,
            "grant_hash":grant_hash,
        });
        let mut record = portable_consumed_record("pai_pre_native", &commitment, &owner_pair());
        record["final_invoker_status"] = json!("claimed");
        record["final_invoker_claim"] = json!({
            "claim_id":"fic_previous",
            "invoker_label":"scm.publication.advance-target-ref",
            "incarnation_id":"inc_previous_boot",
            "effect_hash":effect_hash,
        });
        super::super::durable_fs::persist_record_durable(
            &data_dir_text,
            AUTHORITY_ADMISSION_INTENT_FAMILY,
            "pai_pre_native",
            &record,
        )
        .expect("claimed admission persisted");
        let evidence = PortableAdmissionEvidence {
            admission_intent_ref: "authority-admission-intents/pai_pre_native".to_string(),
            receipt_ref: "receipt://tests/admission".to_string(),
            receipt_hash: format!("sha256:{}", hex::encode([0x55; 32])),
            effect_ref: effect_ref.to_string(),
            effect_hash: effect_hash.clone(),
            final_invoker_status: "claimed".to_string(),
        };

        assert!(refuse_orphaned_claim_before_native_prepared(
            &data_dir_text,
            &evidence,
            "scm.publication.advance-target-ref",
        )
        .await
        .expect("dead claim is proven pre-native"));
        assert!(refuse_orphaned_claim_before_native_prepared(
            &data_dir_text,
            &evidence,
            "scm.publication.advance-target-ref",
        )
        .await
        .expect("retry converges on the same refusal"));
        let settled = super::super::durable_fs::read_record_durable(
            &data_dir_text,
            AUTHORITY_ADMISSION_INTENT_FAMILY,
            "pai_pre_native",
        )
        .expect("readback")
        .expect("settled record");
        assert_eq!(settled["final_invoker_status"], "refused");
        assert_eq!(
            settled["final_invoker_settlement"]["outcome"],
            PRE_NATIVE_PREPARED_ABSENT_OUTCOME
        );
        std::fs::remove_dir_all(&data_dir).expect("test cleanup");
    }

    #[tokio::test]
    async fn absent_native_prepared_never_settles_a_live_process_claim() {
        let data_dir =
            std::env::temp_dir().join(format!("ioi-portable-live-claim-{:032x}", nonce_nanos()));
        let data_dir_text = data_dir.to_string_lossy().to_string();
        let effect_ref = "effect://hypervisor/tests/live-claim";
        let effect_hash = format!("sha256:{}", hex::encode([0x44; 32]));
        let commitment = json!({
            "domain":"ioi.hypervisor.portable-authority-consumption.v1",
            "effect_ref":effect_ref,
            "effect_hash":effect_hash,
            "grant_hash":format!("sha256:{}", hex::encode([0x22; 32])),
        });
        let mut record = portable_consumed_record("pai_live_claim", &commitment, &owner_pair());
        record["final_invoker_status"] = json!("claimed");
        record["final_invoker_claim"] = json!({
            "claim_id":"fic_live",
            "invoker_label":"scm.publication.advance-target-ref",
            "incarnation_id":process_incarnation_id(),
            "effect_hash":effect_hash,
        });
        super::super::durable_fs::persist_record_durable(
            &data_dir_text,
            AUTHORITY_ADMISSION_INTENT_FAMILY,
            "pai_live_claim",
            &record,
        )
        .expect("claimed admission persisted");
        let evidence = PortableAdmissionEvidence {
            admission_intent_ref: "authority-admission-intents/pai_live_claim".to_string(),
            receipt_ref: "receipt://tests/admission".to_string(),
            receipt_hash: format!("sha256:{}", hex::encode([0x55; 32])),
            effect_ref: effect_ref.to_string(),
            effect_hash,
            final_invoker_status: "claimed".to_string(),
        };

        assert!(refuse_orphaned_claim_before_native_prepared(
            &data_dir_text,
            &evidence,
            "scm.publication.advance-target-ref",
        )
        .await
        .is_err());
        let unchanged = super::super::durable_fs::read_record_durable(
            &data_dir_text,
            AUTHORITY_ADMISSION_INTENT_FAMILY,
            "pai_live_claim",
        )
        .expect("readback")
        .expect("claimed record");
        assert_eq!(unchanged["final_invoker_status"], "claimed");
        std::fs::remove_dir_all(&data_dir).expect("test cleanup");
    }

    #[test]
    fn portable_slot_identity_is_stable_across_temporal_refresh_but_not_effect_change() {
        let mut commitment = json!({
            "domain": "ioi.hypervisor.portable-authority-consumption.v1",
            "authority_mode": "portable_v3",
            "subject_ref": "environment://tests/portable",
            "operation": "scm.publish",
            "revision": 1,
            "required_scope": "scope:scm.publication.advance-target-ref",
            "effect_ref": "effect://hypervisor/tests/portable",
            "effect_hash": format!("sha256:{}", hex::encode([0x44; 32])),
            "grant_hash": format!("sha256:{}", hex::encode([0x22; 32])),
            "expected_audience": "daemon://tests/pep",
            "expected_holder_id": "worker://tests/holder",
            "expected_holder_key_id": "key://tests/holder/1",
            "admission": {"temporal_validity_evaluation_ref":"evaluation://tests/1"},
        });
        let first = portable_consumption_id(&commitment).expect("first slot");
        commitment["admission"]["temporal_validity_evaluation_ref"] = json!("evaluation://tests/2");
        assert_eq!(
            portable_consumption_id(&commitment).expect("refreshed slot"),
            first,
            "mutable currentness evidence must not mint a second exact-operation slot"
        );
        commitment["effect_hash"] = json!(format!("sha256:{}", hex::encode([0x45; 32])));
        assert_ne!(
            portable_consumption_id(&commitment).expect("changed effect slot"),
            first,
            "a different exact effect must never share the consumption slot"
        );
    }

    #[test]
    fn portable_pep_resolves_only_current_exact_established_temporal_evidence() {
        let (profile, evaluation, effect_ref, effect_hash, now_ms) = temporal_records();
        let context = resolve_portable_temporal_context_from_records(
            &[profile],
            &[evaluation.clone()],
            "policy://hypervisor/tests/portable",
            &format!("sha256:{}", hex::encode([0x66; 32])),
            &effect_ref,
            &effect_hash,
            now_ms,
        )
        .expect("exact temporal evidence admits");
        assert_eq!(
            context.temporal_validity_evaluation_ref,
            evaluation["evaluation_id"]
        );
        assert_eq!(
            context.continuity_floor_evidence_refs,
            vec!["evidence://acme/estate-1/anchor/operator/9"]
        );
    }

    #[test]
    fn portable_pep_refuses_foreign_or_expired_temporal_evidence() {
        let (profile, mut evaluation, effect_ref, effect_hash, now_ms) = temporal_records();
        assert!(resolve_portable_temporal_context_from_records(
            std::slice::from_ref(&profile),
            std::slice::from_ref(&evaluation),
            "policy://hypervisor/tests/portable",
            &format!("sha256:{}", hex::encode([0x66; 32])),
            "effect://hypervisor/tests/foreign",
            &effect_hash,
            now_ms,
        )
        .is_err());

        evaluation["evidence_horizon"]["valid_until"] = json!("2026-08-24T12:04:00Z");
        refresh_evaluation_hash(&mut evaluation);
        assert!(resolve_portable_temporal_context_from_records(
            &[profile],
            &[evaluation],
            "policy://hypervisor/tests/portable",
            &format!("sha256:{}", hex::encode([0x66; 32])),
            &effect_ref,
            &effect_hash,
            now_ms,
        )
        .is_err());

        let (profile, mut evaluation, effect_ref, effect_hash, now_ms) = temporal_records();
        evaluation["evidence_horizon"]["valid_until"] = json!("2026-08-24T12:11:00Z");
        refresh_evaluation_hash(&mut evaluation);
        assert!(resolve_portable_temporal_context_from_records(
            std::slice::from_ref(&profile),
            std::slice::from_ref(&evaluation),
            "policy://hypervisor/tests/portable",
            &format!("sha256:{}", hex::encode([0x66; 32])),
            &effect_ref,
            &effect_hash,
            now_ms,
        )
        .is_err());

        let (mut fenced, mut evaluation, effect_ref, effect_hash, now_ms) = temporal_records();
        fenced["declaration"]["required_effect_fence_profile_ref"] =
            json!("policy://hypervisor/tests/effect-fence");
        refresh_profile_hash(&mut fenced);
        evaluation["profile_hash"] = fenced["profile_hash"].clone();
        refresh_evaluation_hash(&mut evaluation);
        assert!(resolve_portable_temporal_context_from_records(
            &[fenced],
            &[evaluation],
            "policy://hypervisor/tests/portable",
            &format!("sha256:{}", hex::encode([0x66; 32])),
            &effect_ref,
            &effect_hash,
            now_ms,
        )
        .is_err());
    }

    #[test]
    fn portable_pep_enforces_bounded_offline_holdover_and_revocation_exposure() {
        let (mut profile, mut evaluation, effect_ref, effect_hash, now_ms) = temporal_records();
        profile["declaration"]["disconnected_policy"]["allowed_operation_classes"] =
            json!(["external_effect"]);
        evaluation["temporal_posture"] = json!("bounded_offline");

        profile["declaration"]["disconnected_policy"]["maximum_holdover_ms"] = json!(600_000);
        profile["declaration"]["disconnected_policy"]["maximum_revocation_exposure_ms"] =
            Value::Null;
        refresh_profile_hash(&mut profile);
        evaluation["profile_hash"] = profile["profile_hash"].clone();
        refresh_evaluation_hash(&mut evaluation);
        assert!(resolve_portable_temporal_context_from_records(
            std::slice::from_ref(&profile),
            std::slice::from_ref(&evaluation),
            "policy://hypervisor/tests/portable",
            &format!("sha256:{}", hex::encode([0x66; 32])),
            &effect_ref,
            &effect_hash,
            now_ms,
        )
        .is_err());

        profile["declaration"]["disconnected_policy"]["maximum_revocation_exposure_ms"] =
            json!(599_999);
        refresh_profile_hash(&mut profile);
        evaluation["profile_hash"] = profile["profile_hash"].clone();
        refresh_evaluation_hash(&mut evaluation);
        assert!(resolve_portable_temporal_context_from_records(
            std::slice::from_ref(&profile),
            std::slice::from_ref(&evaluation),
            "policy://hypervisor/tests/portable",
            &format!("sha256:{}", hex::encode([0x66; 32])),
            &effect_ref,
            &effect_hash,
            now_ms,
        )
        .is_err());

        profile["declaration"]["disconnected_policy"]["maximum_revocation_exposure_ms"] =
            json!(600_000);
        refresh_profile_hash(&mut profile);
        evaluation["profile_hash"] = profile["profile_hash"].clone();
        refresh_evaluation_hash(&mut evaluation);
        assert_eq!(
            resolve_portable_temporal_context_from_records(
                &[profile],
                &[evaluation],
                "policy://hypervisor/tests/portable",
                &format!("sha256:{}", hex::encode([0x66; 32])),
                &effect_ref,
                &effect_hash,
                now_ms,
            )
            .expect("exactly bounded offline evidence admits")
            .temporal_posture,
            PortableAuthorityTemporalPostureV1::BoundedOffline
        );
    }
}
