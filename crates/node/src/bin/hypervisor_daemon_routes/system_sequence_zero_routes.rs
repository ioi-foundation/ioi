//! Governed M1.4 sequence-zero materialization over one converged M1.3 admission.
//!
//! This plane freezes activation candidates and daemon-derived roots. It never mutates the
//! M1.3 aggregate and does not initialize, activate, enroll, or create a live System chain.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    Json,
};
use ioi_services::wallet_network::{
    ApprovalGrantConsumptionReceipt, ConsumeApprovalGrantForEffectV2Params,
    ExpectedPrincipalAuthorityBinding,
};
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use ioi_types::app::{
    compile_system_sequence_zero_plan, compute_system_genesis_admission_receipt_root,
    compute_system_genesis_admission_record_root, finalize_system_sequence_zero_materialization,
    validate_principal_authority_ref, ApprovalGrant, CompiledSystemSequenceZeroPlan,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::governed_authority::{
    self as governed, AuthorityContract, AuthorityPolicyContext, AuthorizedDecision,
    DecisionEvidence, Governance,
};
use super::DaemonState;

type VErr = (String, String);

const RECORD_DIR: &str = "autonomous-system-sequence-zero-materializations";
const RECEIPT_DIR: &str = "autonomous-system-sequence-zero-materialization-receipts";
const COMPONENT_DIR: &str = "autonomous-system-sequence-zero-component-registries";
const CONSUMPTION_DIR: &str = "autonomous-system-sequence-zero-authority-consumptions";
pub(crate) const INTENT_DIR: &str = "autonomous-system-sequence-zero-materialization-intents";
const LEGACY_RECEIPT_SCHEMA: &str =
    "ioi.autonomous-system-sequence-zero-materialization-receipt.v1";
const LEGACY_RECEIPT_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v1";
const CURRENT_RECEIPT_SCHEMA: &str =
    "ioi.autonomous-system-sequence-zero-materialization-receipt.v2";
const CURRENT_RECEIPT_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2";
const RECEIPT_TYPE: &str = "autonomous_system_sequence_zero_materialization";
const INTENT_SCHEMA: &str =
    "ioi.hypervisor.autonomous-system-sequence-zero-materialization-intent.v1";
const OP: &str = "genesis_materialize";
const MAX_REQUEST_BYTES: usize = 512 * 1024;

const AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "scope:autonomous_system",
    policy_domain: "hypervisor.system-sequence-zero.decision.policy.v1",
    request_domain: "hypervisor.system-sequence-zero.decision.request.v1",
    resolution_domain: "hypervisor.system-sequence-zero.authority-resolution.v1",
    code_prefix: "system_sequence_zero",
    host_label: "system_owner",
    participant_label: "not_applicable",
};

static SYSTEM_SEQUENCE_ZERO_LOCK: Mutex<()> = Mutex::new(());
static SYSTEM_SEQUENCE_ZERO_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static SYSTEM_SEQUENCE_ZERO_REPLAY_CURSOR: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
struct SourcePlan {
    source_record_tail: String,
    source_record: Value,
    source_receipt: Value,
    source_record_root: String,
    source_receipt_root: String,
    system_id: String,
    genesis_ref: String,
    governing_authority_ref: String,
    plan: CompiledSystemSequenceZeroPlan,
}

struct ReconstructedIntent {
    source: SourcePlan,
    materialization: Value,
    materialization_tail: String,
    receipt: Value,
    receipt_tail: String,
    receipt_version: ReceiptVersion,
    component_registry: Value,
    component_tail: String,
    wallet_consumption: ConsumeApprovalGrantForEffectV2Params,
    wallet_consumption_ref: String,
    wallet_consumption_tail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptVersion {
    /// Frozen PR #91 predecessor bytes, retained for read compatibility only.
    LegacyV1,
    /// Current contract identity and exact retained signed-grant binding.
    CurrentV2,
}

impl ReceiptVersion {
    fn schema(self) -> &'static str {
        match self {
            Self::LegacyV1 => LEGACY_RECEIPT_SCHEMA,
            Self::CurrentV2 => CURRENT_RECEIPT_SCHEMA,
        }
    }

    fn contract(self) -> &'static str {
        match self {
            Self::LegacyV1 => LEGACY_RECEIPT_CONTRACT,
            Self::CurrentV2 => CURRENT_RECEIPT_CONTRACT,
        }
    }
}

fn verr(code: &str, message: impl Into<String>) -> VErr {
    (code.to_owned(), message.into())
}

fn classify((code, message): VErr) -> (StatusCode, Json<Value>) {
    let status = if code.ends_with("_not_found") {
        StatusCode::NOT_FOUND
    } else if code.contains("wallet_consumption_refused") {
        StatusCode::FORBIDDEN
    } else if code.contains("wallet_consumption_unavailable") {
        StatusCode::SERVICE_UNAVAILABLE
    } else if code.contains("wallet_consumption_invalid") {
        StatusCode::BAD_GATEWAY
    } else if code.contains("already_materialized")
        || code.contains("conflict")
        || code.contains("in_flight")
    {
        StatusCode::CONFLICT
    } else if code.contains("unavailable") {
        StatusCode::NOT_IMPLEMENTED
    } else if code.contains("unreadable")
        || code.contains("persist_failed")
        || code.contains("pending_convergence")
        || code.contains("durability")
        || code.contains("swapped")
        || code.contains("agentgres")
        || code.contains("authority_root_invalid")
        || code.contains("materialization_invalid")
        || code.contains("evidence_mismatch")
        || code.contains("evidence_missing")
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (
        status,
        Json(json!({
            "error": {
                "code": code,
                "message": message,
                "runtimeTruthSource": "daemon-runtime"
            }
        })),
    )
}

fn s(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn canonical_tail(tail: &str, prefix: &str) -> bool {
    tail.strip_prefix(prefix).is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn canonical_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn hash_bytes_from_ref(value: &str, field: &str) -> Result<[u8; 32], VErr> {
    let raw = value.strip_prefix("sha256:").ok_or_else(|| {
        verr(
            "system_sequence_zero_authority_evidence_invalid",
            format!("{field} is not a canonical sha256 ref"),
        )
    })?;
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(verr(
            "system_sequence_zero_authority_evidence_invalid",
            format!("{field} must contain exactly 32 lowercase hexadecimal bytes"),
        ));
    }
    let decoded = hex::decode(raw).map_err(|_| {
        verr(
            "system_sequence_zero_authority_evidence_invalid",
            format!("{field} is not lowercase hexadecimal"),
        )
    })?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

fn ms_to_rfc3339(ms: u64) -> Result<String, VErr> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms).saturating_mul(1_000_000))
        .map_err(|_| {
            verr(
                "system_sequence_zero_wallet_time_invalid",
                "wallet time is not representable",
            )
        })?
        .format(&Rfc3339)
        .map_err(|error| {
            verr(
                "system_sequence_zero_wallet_time_invalid",
                error.to_string(),
            )
        })
}

fn without(value: &Value, field: &str) -> Value {
    let mut clone = value.clone();
    if let Some(object) = clone.as_object_mut() {
        object.remove(field);
    }
    clone
}

fn reject_sensitive_keys(value: &Value, path: &str) -> Result<(), VErr> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized = key
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                if [
                    "password",
                    "secret",
                    "credential",
                    "authorization",
                    "privatekey",
                    "apikey",
                    "token",
                ]
                .iter()
                .any(|fragment| normalized.contains(fragment))
                {
                    return Err(verr(
                        "system_sequence_zero_sensitive_field_rejected",
                        format!("sensitive field '{path}.{key}' is forbidden"),
                    ));
                }
                reject_sensitive_keys(child, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_sensitive_keys(child, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_request(body: &Value) -> Result<(String, String), VErr> {
    if serde_json::to_vec(body).map_or(MAX_REQUEST_BYTES + 1, |bytes| bytes.len())
        > MAX_REQUEST_BYTES
    {
        return Err(verr(
            "system_sequence_zero_request_too_large",
            "sequence-zero materialization request exceeds its bounded size",
        ));
    }
    reject_sensitive_keys(body, "$")?;
    let object = body.as_object().ok_or_else(|| {
        verr(
            "system_sequence_zero_request_invalid",
            "request must be one closed JSON object",
        )
    })?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "expected_genesis_admission_record_root"
                | "expected_genesis_admission_receipt_root"
                | "wallet_approval_grant"
        ) {
            return Err(verr(
                "system_sequence_zero_request_field_unknown",
                format!("undeclared request field '{key}' is forbidden"),
            ));
        }
    }
    let record_root = object
        .get("expected_genesis_admission_record_root")
        .and_then(Value::as_str)
        .filter(|value| canonical_hash(value))
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_expected_record_root_invalid",
                "expected_genesis_admission_record_root must be one canonical sha256 ref",
            )
        })?;
    let receipt_root = object
        .get("expected_genesis_admission_receipt_root")
        .and_then(Value::as_str)
        .filter(|value| canonical_hash(value))
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_expected_receipt_root_invalid",
                "expected_genesis_admission_receipt_root must be one canonical sha256 ref",
            )
        })?;
    Ok((record_root.to_owned(), receipt_root.to_owned()))
}

fn source_plan_locked(data_dir: &str, source_record_tail: &str) -> Result<SourcePlan, VErr> {
    let source =
        super::system_genesis_routes::load_verified_admission_by_key(data_dir, source_record_tail)?
            .ok_or_else(|| {
                verr(
                    "system_sequence_zero_source_not_found",
                    format!("no converged M1.3 admission exists at key '{source_record_tail}'"),
                )
            })?;
    let source_record_root =
        compute_system_genesis_admission_record_root(&source.record).map_err(|error| {
            verr(
                "system_sequence_zero_source_evidence_invalid",
                format!("M1.3 admission record cannot be hashed ({error})"),
            )
        })?;
    let source_receipt_root = compute_system_genesis_admission_receipt_root(&source.receipt)
        .map_err(|error| {
            verr(
                "system_sequence_zero_source_evidence_invalid",
                format!("M1.3 admission receipt cannot be hashed ({error})"),
            )
        })?;
    let source_receipt_ref = source
        .receipt
        .get("receipt_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_source_evidence_invalid",
                "M1.3 admission receipt lacks its identity",
            )
        })?;
    let authorized_genesis = source
        .record
        .get("authorized_genesis")
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_source_evidence_invalid",
                "M1.3 aggregate lacks authorized_genesis",
            )
        })?;
    let initial_profile_bundle = source
        .record
        .get("initial_profile_bundle")
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_source_evidence_invalid",
                "M1.3 aggregate lacks initial_profile_bundle",
            )
        })?;
    let plan = compile_system_sequence_zero_plan(
        authorized_genesis,
        initial_profile_bundle,
        &source_record_root,
        source_receipt_ref,
        &source_receipt_root,
    )
    .map_err(|error| {
        verr(
            "system_sequence_zero_source_evidence_invalid",
            format!("converged M1.3 evidence cannot produce M1.4 ({error})"),
        )
    })?;
    let system_id = s(&source.record, "system_id");
    let genesis_ref = s(&source.record, "genesis_ref");
    let governing_authority_ref = s(&source.record, "governing_authority_ref");
    validate_principal_authority_ref(&governing_authority_ref).map_err(|error| {
        verr(
            "system_sequence_zero_governing_authority_invalid",
            format!("M1.3 governing authority is not portable ({error})"),
        )
    })?;
    Ok(SourcePlan {
        source_record_tail: source.record_tail,
        source_record: source.record,
        source_receipt: source.receipt,
        source_record_root,
        source_receipt_root,
        system_id,
        genesis_ref,
        governing_authority_ref,
        plan,
    })
}

fn materialization_tail(plan: &CompiledSystemSequenceZeroPlan) -> Result<String, VErr> {
    let root = plan
        .materialization_body
        .get("genesis_admission_record_root")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("sha256:"))
        .filter(|value| value.len() == 64)
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_identity_invalid",
                "materialization plan lacks its canonical M1.3 root",
            )
        })?;
    Ok(format!("aszm_{root}"))
}

fn receipt_tail(plan: &CompiledSystemSequenceZeroPlan) -> Result<String, VErr> {
    plan.materialization_body
        .get("materialization_receipt_ref")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("receipt://"))
        .filter(|value| canonical_tail(value, "aszmr_"))
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_receipt_identity_invalid",
                "materialization plan lacks its canonical receipt identity",
            )
        })
}

fn component_tail(plan: &CompiledSystemSequenceZeroPlan) -> Result<String, VErr> {
    plan.component_registry_root
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64)
        .map(|value| format!("aszcr_{value}"))
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_component_identity_invalid",
                "component registry root is not canonical",
            )
        })
}

fn wallet_consumption_coordinates(
    authorized: &AuthorizedDecision,
    source: &SourcePlan,
) -> Result<(ConsumeApprovalGrantForEffectV2Params, String), VErr> {
    let request_hash =
        hash_bytes_from_ref(&authorized.evidence.request_hash, "authority request_hash")?;
    let grant: ApprovalGrant = serde_json::from_value(
        authorized.evidence.wallet_approval_grant.clone(),
    )
    .map_err(|error| {
        verr(
            "system_sequence_zero_authority_evidence_invalid",
            format!("wallet approval grant is malformed ({error})"),
        )
    })?;
    let grant_hash = grant.artifact_hash().map_err(|error| {
        verr(
            "system_sequence_zero_authority_evidence_invalid",
            format!("wallet approval grant cannot be hashed ({error})"),
        )
    })?;
    if grant.max_usages != Some(1) {
        return Err(verr(
            "system_sequence_zero_authority_evidence_invalid",
            "sequence-zero materialization requires a separately consumed single-use grant",
        ));
    }
    let expected_principal_authority: ExpectedPrincipalAuthorityBinding =
        serde_json::from_value(authorized.evidence.authority_binding.clone()).map_err(|error| {
            verr(
                "system_sequence_zero_authority_evidence_invalid",
                format!(
                "principal authority binding cannot be projected into wallet consumption ({error})"
            ),
            )
        })?;
    let material = json!({
        "domain": "ioi.hypervisor.system-sequence-zero.authority-use.v1",
        "system_id": source.system_id,
        "genesis_ref": source.genesis_ref,
        "genesis_admission_record_root": source.source_record_root,
        "genesis_admission_receipt_root": source.source_receipt_root,
        "operation_commitment": source.plan.operation_commitment,
        "transition_commitment_ref": source.plan.transition_commitment_ref,
        "policy_hash": authorized.evidence.policy_hash,
        "request_hash": authorized.evidence.request_hash,
        "effect_hash": authorized.evidence.effect_hash,
        "grant_hash": format!("sha256:{}", hex::encode(grant_hash)),
        "principal_authority": expected_principal_authority
    });
    let consumption_hash = super::outcome_room_routes::record_output_hash(&material, &[]);
    let consumption_id = hash_bytes_from_ref(&consumption_hash, "wallet consumption id")?;
    let consumption_ref = format!(
        "wallet.network://approval-effect-consumption/{}/{}",
        hex::encode(request_hash),
        hex::encode(consumption_id)
    );
    Ok((
        ConsumeApprovalGrantForEffectV2Params {
            request_hash,
            grant_hash,
            consumption_id,
            expected_principal_authority,
            expected_target_label: AUTHORITY.operation_scope(OP),
            expected_max_usages: 1,
        },
        consumption_ref,
    ))
}

fn legacy_canonical_grant_ref(wallet_grant_ref: &str) -> String {
    format!(
        "grant://wallet.network/approval/sha256:{:x}",
        Sha256::digest(wallet_grant_ref.as_bytes())
    )
}

fn canonical_grant_ref(grant: &ApprovalGrant) -> Result<String, VErr> {
    let artifact_hash = grant.artifact_hash().map_err(|error| {
        verr(
            "system_sequence_zero_receipt_evidence_mismatch",
            format!("retained wallet approval grant cannot be hashed ({error})"),
        )
    })?;
    Ok(format!(
        "grant://wallet.network/approval/sha256:{}",
        hex::encode(artifact_hash)
    ))
}

fn reconstruct_sealed_authority_context(
    receipt: &Value,
    system_id: &str,
    genesis_ref: &str,
    governing_authority_ref: &str,
    subject_ref: &str,
    authority_effect: &Value,
) -> Result<(String, String, String), VErr> {
    let policy_hash = governed::decision_policy_hash_for_context(
        AUTHORITY,
        Governance::Host,
        AuthorityPolicyContext::SystemGenesis {
            system_id,
            genesis_id: genesis_ref,
        },
        governing_authority_ref,
        OP,
    );
    let effect_hash = governed::decision_effect_hash(AUTHORITY, authority_effect);
    let request_hash = governed::decision_request_hash(
        AUTHORITY,
        Governance::Host,
        subject_ref,
        OP,
        0,
        governing_authority_ref,
        &effect_hash,
    );
    if receipt.get("policy_hash").and_then(Value::as_str) != Some(policy_hash.as_str())
        || receipt.get("input_hash").and_then(Value::as_str) != Some(request_hash.as_str())
        || receipt.get("effect_hash").and_then(Value::as_str) != Some(effect_hash.as_str())
        || receipt.get("authorized_effect") != Some(authority_effect)
        || receipt.get("subject_ref").and_then(Value::as_str) != Some(subject_ref)
    {
        return Err(verr(
            "system_sequence_zero_receipt_evidence_mismatch",
            "sealed policy, request, effect, or subject does not reconstruct from the exact M1.3 source and M1.4 plan",
        ));
    }
    Ok((policy_hash, request_hash, effect_hash))
}

fn sealed_sequence_zero_authorized_decision(
    receipt: &Value,
    source: &SourcePlan,
    resolved_at_ms: u64,
    receipt_version: ReceiptVersion,
) -> Result<AuthorizedDecision, VErr> {
    let wallet_approval_grant = receipt
        .get("wallet_approval_grant")
        .cloned()
        .unwrap_or(Value::Null);
    let (grant, canonical_grant) = governed::canonicalize_approval_grant(&wallet_approval_grant)
        .map_err(|error| {
            verr(
                "system_sequence_zero_receipt_evidence_mismatch",
                format!("sealed wallet approval grant is malformed ({error})"),
            )
        })?;
    let subject_ref = s(&source.plan.materialization_body, "materialization_id");
    let (policy_hash, request_hash, effect_hash) = reconstruct_sealed_authority_context(
        receipt,
        &source.system_id,
        &source.genesis_ref,
        &source.governing_authority_ref,
        &subject_ref,
        &source.plan.authority_effect,
    )?;
    let binding =
        ioi_services::agentic::runtime::kernel::approval::verify_wallet_approval_grant_binding(
            &canonical_grant,
            Some(resolved_at_ms),
            Some(&policy_hash),
            Some(&request_hash),
        )
        .map_err(|error| {
            verr(
                "system_sequence_zero_receipt_evidence_mismatch",
                format!("sealed wallet approval grant does not verify ({error})"),
            )
        })?;
    let exact_grant_ref = canonical_grant_ref(&grant)?;
    let legacy_grant_ref = legacy_canonical_grant_ref(&binding.grant_ref);
    let expected_grant_ref = match receipt_version {
        ReceiptVersion::LegacyV1 => legacy_grant_ref,
        ReceiptVersion::CurrentV2 => exact_grant_ref,
    };
    if receipt.get("authority_grant_id").and_then(Value::as_str)
        != Some(expected_grant_ref.as_str())
    {
        return Err(verr(
            "system_sequence_zero_receipt_evidence_mismatch",
            format!(
                "{} authority_grant_id does not match its versioned retained-grant identity",
                receipt_version.schema()
            ),
        ));
    }
    let authority_binding = governed::canonicalize_authority_binding(
        receipt
            .get("principal_authority_binding")
            .unwrap_or(&Value::Null),
        resolved_at_ms,
    )
    .map_err(|error| {
        verr(
            "system_sequence_zero_receipt_evidence_mismatch",
            format!("sealed principal-authority binding is invalid ({error})"),
        )
    })?;
    let expected_principal_authority: ExpectedPrincipalAuthorityBinding =
        serde_json::from_value(authority_binding.clone()).map_err(|error| {
            verr(
                "system_sequence_zero_receipt_evidence_mismatch",
                format!("sealed principal-authority binding cannot authorize wallet use ({error})"),
            )
        })?;
    if expected_principal_authority.principal_ref != source.governing_authority_ref
        || expected_principal_authority.required_scope != AUTHORITY.operation_scope(OP)
        || grant.authority_id != expected_principal_authority.approval_authority.authority_id
        || grant.approver_public_key != expected_principal_authority.approval_authority.public_key
        || grant.approver_suite
            != expected_principal_authority
                .approval_authority
                .signature_suite
    {
        return Err(verr(
            "system_sequence_zero_receipt_evidence_mismatch",
            "sealed grant signer or principal-authority binding does not match the M1.3 governing authority and M1.4 scope",
        ));
    }
    let acting_authority_id = serde_json::to_value(grant.authority_id).map_err(|error| {
        verr(
            "system_sequence_zero_receipt_evidence_mismatch",
            format!("sealed authority id cannot be projected ({error})"),
        )
    })?;
    Ok(AuthorizedDecision {
        evidence: DecisionEvidence {
            acting_authority_id,
            grant_ref: binding.grant_ref,
            policy_hash,
            request_hash,
            effect_hash,
            authorized_effect: source.plan.authority_effect.clone(),
            wallet_approval_grant: canonical_grant,
            authority_binding,
        },
        resolved_at_ms,
    })
}

fn profile_boundary_refs(materialization: &Value) -> Vec<Value> {
    let mut refs = vec![
        materialization
            .get("system_id")
            .cloned()
            .unwrap_or(Value::Null),
        materialization
            .get("genesis_ref")
            .cloned()
            .unwrap_or(Value::Null),
        materialization
            .get("manifest_ref")
            .cloned()
            .unwrap_or(Value::Null),
        materialization
            .get("constitution_ref")
            .cloned()
            .unwrap_or(Value::Null),
        materialization
            .get("component_registry_ref")
            .cloned()
            .unwrap_or(Value::Null),
    ];
    if let Some(profiles) = materialization.get("profile_refs") {
        for field in [
            "deployment_profile_ref",
            "ordering_admission_finality_profile_ref",
            "lifecycle_continuity_profile_ref",
            "network_enrollment_ref",
        ] {
            if let Some(value) = profiles.get(field).filter(|value| !value.is_null()) {
                refs.push(value.clone());
            }
        }
        refs.extend(
            profiles
                .get("oracle_evidence_profile_refs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .cloned(),
        );
    }
    refs
}

fn build_receipt_for_version(
    receipt_tail: &str,
    materialization: &Value,
    source: &SourcePlan,
    authorized: &AuthorizedDecision,
    wallet_consumption_ref: &str,
    wallet_consumption_tail: &str,
    created_at: &str,
    receipt_version: ReceiptVersion,
) -> Result<Value, VErr> {
    let receipt_ref = format!("receipt://{receipt_tail}");
    let materialization_output_hash =
        super::outcome_room_routes::record_output_hash(materialization, &[]);
    let retained_grant: ApprovalGrant = serde_json::from_value(
        authorized.evidence.wallet_approval_grant.clone(),
    )
    .map_err(|error| {
        verr(
            "system_sequence_zero_receipt_evidence_mismatch",
            format!("retained wallet approval grant is malformed ({error})"),
        )
    })?;
    let portable_grant_ref = match receipt_version {
        ReceiptVersion::LegacyV1 => legacy_canonical_grant_ref(&authorized.evidence.grant_ref),
        ReceiptVersion::CurrentV2 => canonical_grant_ref(&retained_grant)?,
    };
    let mut boundary_refs = profile_boundary_refs(materialization);
    match receipt_version {
        ReceiptVersion::LegacyV1 => boundary_refs.push(json!(format!(
            "system-genesis-admission://{}",
            source.source_record_tail
        ))),
        ReceiptVersion::CurrentV2 => boundary_refs.push(json!(source.source_record_root)),
    }
    boundary_refs.push(
        source
            .source_record
            .get("admission_receipt_ref")
            .cloned()
            .unwrap_or(Value::Null),
    );
    boundary_refs.push(json!(source.governing_authority_ref));
    boundary_refs.push(json!(portable_grant_ref.clone()));
    if receipt_version == ReceiptVersion::CurrentV2 {
        boundary_refs.push(json!(wallet_consumption_ref));
    }
    boundary_refs.push(json!(format!(
        "system-sequence-zero-authority-consumption://{wallet_consumption_tail}"
    )));
    let mut receipt = json!({
        "schema_version": receipt_version.schema(),
        "receipt_id": receipt_ref,
        "receipt_ref": receipt_ref,
        "receipt_type": RECEIPT_TYPE,
        "receipt_profile_ref": receipt_version.contract(),
        "actor_id": "runtime://hypervisor-runtime",
        "subject_ref": materialization.get("materialization_id"),
        "op": "materialized",
        "attested_boundary_fact_refs": boundary_refs,
        "bound_facts": {
            "materialization_id": materialization.get("materialization_id"),
            "materialization_output_hash": materialization_output_hash,
            "governing_authority_ref": source.governing_authority_ref,
            "authority_effect_hash": authorized.evidence.effect_hash,
            "system_id": materialization.get("system_id"),
            "genesis_ref": materialization.get("genesis_ref"),
            "genesis_admission_record_root": materialization.get("genesis_admission_record_root"),
            "genesis_admission_receipt_ref": materialization.get("genesis_admission_receipt_ref"),
            "genesis_admission_receipt_root": materialization.get("genesis_admission_receipt_root"),
            "proposed_initial_state_root": materialization.get("proposed_initial_state_root"),
            "proposed_initial_receipt_root": materialization.get("proposed_initial_receipt_root"),
            "package_id": materialization.get("package_id"),
            "manifest_ref": materialization.get("manifest_ref"),
            "admitted_manifest_root": materialization.get("admitted_manifest_root"),
            "constitution_ref": materialization.get("constitution_ref"),
            "constitution_root": materialization.get("constitution_root"),
            "profile_bundle_root": materialization.get("profile_bundle_root"),
            "profile_materialization_root": materialization.get("profile_materialization_root"),
            "deployment_profile_root": materialization.get("deployment_profile_root"),
            "profile_refs": materialization.get("profile_refs"),
            "component_registry_ref": materialization.get("component_registry_ref"),
            "component_registry_root": materialization.get("component_registry_root"),
            "component_binding_count": materialization.get("component_binding_count"),
            "sequence": 0,
            "predecessor_transition_commitment_ref": Value::Null,
            "operation_commitment": materialization.get("operation_commitment"),
            "transition_commitment_ref": materialization.get("transition_commitment_ref"),
            "initial_state_root": materialization.get("initial_state_root"),
            "initial_receipt_root": materialization.get("initial_receipt_root"),
            "wallet_grant_consumption_ref": wallet_consumption_ref,
            "wallet_grant_consumption_evidence_ref": format!(
                "system-sequence-zero-authority-consumption://{wallet_consumption_tail}"
            ),
            "materialized_pending_activation": true,
            "active_profile_admission": false,
            "initialize_admitted": false,
            "activation_admitted": false,
            "live_chain_created": false,
            "node_membership_created": false,
            "network_effect_admitted": false,
            "runtime_effect_admitted": false
        },
        "output_hash": materialization_output_hash,
        "hash_scope_excludes": [],
        "assurance_posture": "sequence_zero_materialized_not_activated",
        "assurance_note": "governed materialization of immutable activation candidates and sequence-zero roots; active-profile admission, initialize, activation, live-chain, membership, network, and runtime effects remain unadmitted",
        "verification_ref": Value::Null,
        "acceptance_ref": Value::Null,
        "claim_scope_ref": Value::Null,
        "run_id": Value::Null,
        "task_id": Value::Null,
        "input_hash": Value::Null,
        "policy_hash": Value::Null,
        "authority_grant_id": Value::Null,
        "primitive_capabilities": [],
        "authority_scopes": [AUTHORITY.operation_scope(OP)],
        "artifact_refs": [],
        "evidence_bundle_refs": [],
        "adjudication_ref": Value::Null,
        "settlement_ref": Value::Null,
        "signature": Value::Null,
        "public_commitment_ref": Value::Null,
        "timestamp": created_at,
        "outcome": "ok",
        "at": created_at
    });
    governed::append_evidence(&mut receipt, authorized);
    receipt["actor_id"] = json!("runtime://hypervisor-runtime");
    receipt["authority_grant_id"] = json!(portable_grant_ref);
    validate_architecture_contract(receipt_version.contract(), &receipt).map_err(|error| {
        verr(
            "system_sequence_zero_receipt_evidence_mismatch",
            format!(
                "{} materialization receipt contract invalid ({error})",
                receipt_version.schema()
            ),
        )
    })?;
    Ok(receipt)
}

fn build_receipt(
    receipt_tail: &str,
    materialization: &Value,
    source: &SourcePlan,
    authorized: &AuthorizedDecision,
    wallet_consumption_ref: &str,
    wallet_consumption_tail: &str,
    created_at: &str,
) -> Result<Value, VErr> {
    build_receipt_for_version(
        receipt_tail,
        materialization,
        source,
        authorized,
        wallet_consumption_ref,
        wallet_consumption_tail,
        created_at,
        ReceiptVersion::CurrentV2,
    )
}

fn map_commit_failure(failure: super::durable_fs::CommitFailure) -> VErr {
    use super::durable_fs::CommitFailure;
    match failure {
        CommitFailure::KeyInvalid(message) => {
            verr("system_sequence_zero_evidence_key_invalid", message)
        }
        CommitFailure::NotCommitted(message) => {
            verr("system_sequence_zero_persist_failed", message)
        }
        CommitFailure::SlotUnreadable(message) => {
            verr("system_sequence_zero_registry_unreadable", message)
        }
        CommitFailure::Conflict(message) => verr("system_sequence_zero_conflict", message),
        CommitFailure::DurabilityUnconfirmed(message) => {
            verr("system_sequence_zero_pending_convergence", message)
        }
        CommitFailure::Swapped(message) => verr("system_sequence_zero_evidence_swapped", message),
    }
}

fn persist_immutable(data_dir: &str, family: &str, tail: &str, value: &Value) -> Result<(), VErr> {
    super::durable_fs::persist_receipt_no_clobber(data_dir, family, tail, value)
        .map_err(map_commit_failure)?;
    super::substrate_store::admit_required(data_dir, family, tail, value).map_err(|error| {
        verr(
            "system_sequence_zero_agentgres_admission_failed",
            format!(
                "Agentgres refused required admission for '{family}/{tail}' ({error}); the durable intent remains for replay"
            ),
        )
    })
}

fn persist_intent(
    data_dir: &str,
    tail: &str,
    intent: &Value,
    cleanup_request_created_family: bool,
) -> Result<(), VErr> {
    let failure =
        match super::durable_fs::persist_receipt_no_clobber(data_dir, INTENT_DIR, tail, intent) {
            Ok(()) => return Ok(()),
            Err(failure) => failure,
        };
    let intent_is_provably_absent = matches!(
        &failure,
        super::durable_fs::CommitFailure::KeyInvalid(_)
            | super::durable_fs::CommitFailure::NotCommitted(_)
            | super::durable_fs::CommitFailure::Conflict(_)
    );
    if intent_is_provably_absent && cleanup_request_created_family {
        remove_request_created_family_if_empty(data_dir)?;
    }
    Err(map_commit_failure(failure))
}

fn load_value(data_dir: &str, family: &str, tail: &str) -> Result<Option<Value>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("family '{family}' cannot be pinned ({error})")),
    };
    let name = format!("{tail}.json");
    let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
        Ok(None) => return Ok(None),
        Ok(Some((_file, bytes))) => bytes,
        Err(error) => return Err(format!("slot '{family}/{name}' is unreadable ({error})")),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("slot '{family}/{name}' is malformed ({error})"))
}

fn persist_wallet_consumption(
    data_dir: &str,
    tail: &str,
    receipt: &ApprovalGrantConsumptionReceipt,
) -> Result<(), VErr> {
    if !canonical_tail(tail, "aszmc_") {
        return Err(verr(
            "system_sequence_zero_wallet_consumption_invalid",
            "wallet consumption evidence key is noncanonical",
        ));
    }
    let value = serde_json::to_value(receipt).map_err(|error| {
        verr(
            "system_sequence_zero_wallet_consumption_invalid",
            format!("wallet consumption receipt cannot be projected ({error})"),
        )
    })?;
    persist_immutable(data_dir, CONSUMPTION_DIR, tail, &value)
}

fn test_pause_after_durable_wallet_consumption_evidence() -> Result<(), VErr> {
    super::durable_fs::test_crash_pause_if_selected(
        "IOI_TEST_PAUSE_SYSTEM_SEQUENCE_ZERO_AFTER_WALLET_CONSUMPTION_EVIDENCE",
        "1",
        "IOI_TEST_SYSTEM_SEQUENCE_ZERO_WALLET_EVIDENCE_MARKER_PATH",
        "system sequence-zero wallet consumption and intent evidence durable before finalization",
    )
    .map_err(|error| {
        verr(
            "system_sequence_zero_pending_convergence",
            format!("test crash-pause marker could not be signaled ({error})"),
        )
    })
}

fn load_wallet_consumption(
    data_dir: &str,
    tail: &str,
) -> Result<Option<ApprovalGrantConsumptionReceipt>, String> {
    if !canonical_tail(tail, "aszmc_") {
        return Err(format!(
            "noncanonical sequence-zero wallet consumption key '{tail}'"
        ));
    }
    load_value(data_dir, CONSUMPTION_DIR, tail)?
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| {
            format!("wallet consumption evidence '{CONSUMPTION_DIR}/{tail}' is malformed ({error})")
        })
}

fn consume_intent(
    data_dir: &str,
    tail: &str,
    remove_request_created_family: bool,
) -> Result<(), VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, INTENT_DIR) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(verr(
                "system_sequence_zero_intent_unreadable",
                error.to_string(),
            ))
        }
    };
    match super::durable_fs::unlink_durable_at(&directory, &format!("{tail}.json"), INTENT_DIR) {
        Ok(super::durable_fs::UnlinkOutcome::Absent)
        | Ok(super::durable_fs::UnlinkOutcome::Durable) => {}
        Ok(super::durable_fs::UnlinkOutcome::ReplayAnchorRestoredAfterUnconfirmedRemoval(
            error,
        )) => {
            return Err(verr(
                "system_sequence_zero_pending_convergence",
                format!(
                    "intent removal durability was unconfirmed; the byte-exact replay anchor was restored ({error})"
                ),
            ))
        }
        Ok(super::durable_fs::UnlinkOutcome::RemovedDurabilityUnconfirmed(error)) => {
            eprintln!(
                "SystemSequenceZero intent '{tail}' is absent from the live namespace but its directory durability is unconfirmed ({error}); terminal evidence remains authoritative and replay is idempotent"
            );
        }
        Err(error) => {
            return Err(verr(
                "system_sequence_zero_pending_convergence",
                format!("intent unlink failed ({error})"),
            ))
        }
    }
    drop(directory);
    if remove_request_created_family {
        remove_request_created_family_if_empty(data_dir)?;
    }
    Ok(())
}

fn remove_request_created_family_if_empty(data_dir: &str) -> Result<(), VErr> {
    match super::durable_fs::remove_empty_family_durable(data_dir, INTENT_DIR) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::ENOTEMPTY) => {
            // Another governed intent now shares the family. The transitive cleanup marker on
            // that intent carries the obligation until the last owner converges.
            Ok(())
        }
        Err(error) => Err(verr(
            "system_sequence_zero_pending_convergence",
            format!("request-created empty intent family cleanup failed ({error})"),
        )),
    }
}

fn intent_created_family(intent: &Value) -> Result<bool, VErr> {
    match intent.get("intent_family_created_by_request") {
        None => Ok(false),
        Some(value) => value.as_bool().ok_or_else(|| {
            verr(
                "system_sequence_zero_intent_unreadable",
                "intent has malformed request-created-family provenance",
            )
        }),
    }
}

fn inherited_family_cleanup_obligation(
    family_preexisted: bool,
    existing_intents: &[(String, Value)],
) -> Result<bool, VErr> {
    if !family_preexisted {
        return Ok(true);
    }
    existing_intents
        .iter()
        .try_fold(false, |required, (_, intent)| {
            Ok(required || intent_created_family(intent)?)
        })
}

fn touched_refs(
    source: &SourcePlan,
    materialization_id: &str,
    receipt_ref: &str,
    component_registry_ref: &str,
    wallet_consumption_ref: &str,
) -> Vec<String> {
    BTreeSet::from([
        source.system_id.clone(),
        source.genesis_ref.clone(),
        format!("system-genesis-admission://{}", source.source_record_tail),
        source.source_record_root.clone(),
        source.source_receipt_root.clone(),
        materialization_id.to_owned(),
        receipt_ref.to_owned(),
        component_registry_ref.to_owned(),
        source.plan.operation_commitment.clone(),
        source.plan.transition_commitment_ref.clone(),
        wallet_consumption_ref.to_owned(),
    ])
    .into_iter()
    .filter(|reference| !reference.is_empty())
    .collect()
}

fn seal_intent(mut intent: Value, tail: &str, source: &SourcePlan) -> Value {
    let materialization_id = s(&intent, "materialization_id");
    let receipt_ref = s(&intent, "materialization_receipt_ref");
    let component_registry_ref = s(&intent, "component_registry_ref");
    let wallet_consumption_ref = s(&intent, "wallet_grant_consumption_ref");
    let object = intent.as_object_mut().expect("intent object");
    object.insert("schema_version".into(), json!(INTENT_SCHEMA));
    object.insert(
        "intent_id".into(),
        json!(format!(
            "system-sequence-zero-materialization-intent://{tail}"
        )),
    );
    object.insert(
        "touched_refs".into(),
        json!(touched_refs(
            source,
            &materialization_id,
            &receipt_ref,
            &component_registry_ref,
            &wallet_consumption_ref,
        )),
    );
    let hash = super::outcome_room_routes::record_output_hash(&intent, &[]);
    intent
        .as_object_mut()
        .expect("intent object")
        .insert("intent_hash".into(), json!(hash));
    intent
}

fn validate_intent_seal(intent: &Value, tail: &str) -> Result<(), String> {
    if !canonical_tail(tail, "aszmi_")
        || intent.get("schema_version").and_then(Value::as_str) != Some(INTENT_SCHEMA)
        || intent.get("intent_id").and_then(Value::as_str)
            != Some(format!("system-sequence-zero-materialization-intent://{tail}").as_str())
        || intent.get("intent_hash").and_then(Value::as_str)
            != Some(
                super::outcome_room_routes::record_output_hash(
                    &without(intent, "intent_hash"),
                    &[],
                )
                .as_str(),
            )
    {
        return Err("intent storage-key/hash binding failed".to_owned());
    }
    if intent
        .get("intent_family_created_by_request")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err("intent has malformed request-created-family provenance".to_owned());
    }
    Ok(())
}

fn scan_intents(data_dir: &str) -> Result<Vec<(String, Value)>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, INTENT_DIR) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("intent family cannot be pinned ({error})")),
    };
    let names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|error| format!("intent family cannot be enumerated ({error})"))?;
    let mut intents = Vec::new();
    for name in names {
        let tail = name.strip_suffix(".json").ok_or_else(|| {
            format!("unexpected non-JSON entry '{name}' exists in the intent family")
        })?;
        if !canonical_tail(tail, "aszmi_") {
            return Err(format!(
                "unexpected noncanonical JSON entry '{name}' exists in the intent family"
            ));
        }
        let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
            Ok(Some((_file, bytes))) => bytes,
            Ok(None) => return Err(format!("canonical intent '{name}' vanished")),
            Err(error) => return Err(format!("canonical intent '{name}' is unreadable ({error})")),
        };
        let intent: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("canonical intent '{name}' is malformed ({error})"))?;
        validate_intent_seal(&intent, tail)?;
        intents.push((tail.to_owned(), intent));
    }
    Ok(intents)
}

fn fair_replay_window(
    mut intents: Vec<(String, Value)>,
    max_intents: usize,
    cursor: &AtomicUsize,
) -> Vec<(String, Value)> {
    if intents.is_empty() || max_intents == 0 {
        return Vec::new();
    }
    intents.sort_by(|left, right| left.0.cmp(&right.0));
    let count = max_intents.min(intents.len());
    let start = cursor.fetch_add(1, Ordering::Relaxed) % intents.len();
    (0..count)
        .map(|offset| intents[(start + offset) % intents.len()].clone())
        .collect()
}

fn load_intent(data_dir: &str, tail: &str) -> Result<Option<Value>, String> {
    if !canonical_tail(tail, "aszmi_") {
        return Err(format!(
            "noncanonical sequence-zero materialization intent key '{tail}'"
        ));
    }
    let intent = load_value(data_dir, INTENT_DIR, tail)?;
    if let Some(intent) = &intent {
        validate_intent_seal(intent, tail)?;
    }
    Ok(intent)
}

fn refuse_pending_overlap(
    data_dir: &str,
    refs: &[String],
    ignored: Option<&str>,
) -> Result<(), VErr> {
    let wanted = refs.iter().map(String::as_str).collect::<BTreeSet<_>>();
    for (tail, intent) in scan_intents(data_dir)
        .map_err(|error| verr("system_sequence_zero_intent_unreadable", error))?
    {
        if ignored == Some(tail.as_str()) {
            continue;
        }
        if intent
            .get("touched_refs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|reference| wanted.contains(reference))
        {
            return Err(verr(
                "system_sequence_zero_mutation_in_flight",
                format!("a durable sequence-zero intent '{tail}' owns these coordinates"),
            ));
        }
    }
    Ok(())
}

fn validate_materialization_identity(tail: &str, value: &Value) -> Result<(), String> {
    let source_root = value
        .get("genesis_admission_record_root")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("sha256:"))
        .unwrap_or("");
    if !canonical_tail(tail, "aszm_")
        || tail.strip_prefix("aszm_") != Some(source_root)
        || value.get("materialization_id").and_then(Value::as_str)
            != Some(format!("system-materialization://sequence-zero/sha256:{source_root}").as_str())
        || value.get("status").and_then(Value::as_str) != Some("materialized_pending_activation")
        || value.get("activation_receipt_ref") != Some(&Value::Null)
    {
        return Err("materialization storage-key/status binding failed".to_owned());
    }
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        "schema://ioi/foundations/autonomous-system-sequence-zero-materialization/v1",
        value,
    )
    .map_err(|error| format!("materialization contract invalid ({error})"))
}

fn validate_component_identity(tail: &str, value: &Value) -> Result<(), String> {
    let root = value
        .get("component_registry_root")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("sha256:"))
        .unwrap_or("");
    if !canonical_tail(tail, "aszcr_")
        || tail.strip_prefix("aszcr_") != Some(root)
        || value.get("component_registry_ref").and_then(Value::as_str)
            != Some(
                format!("agentgres://object-set/autonomous-system-components/sha256:{root}")
                    .as_str(),
            )
        || value.get("status").and_then(Value::as_str) != Some("frozen_pending_activation")
    {
        return Err("component-registry storage-key/status binding failed".to_owned());
    }
    Ok(())
}

fn validate_receipt_identity(tail: &str, value: &Value) -> Result<ReceiptVersion, String> {
    if !canonical_tail(tail, "aszmr_")
        || value.get("receipt_ref").and_then(Value::as_str)
            != Some(format!("receipt://{tail}").as_str())
        || value.get("receipt_id") != value.get("receipt_ref")
        || value.get("receipt_type").and_then(Value::as_str) != Some(RECEIPT_TYPE)
    {
        return Err("materialization receipt storage-key identity failed".to_owned());
    }
    let identity = (
        value.get("schema_version").and_then(Value::as_str),
        value.get("receipt_profile_ref").and_then(Value::as_str),
    );
    let receipt_version = match identity {
        (Some(LEGACY_RECEIPT_SCHEMA), Some(LEGACY_RECEIPT_CONTRACT)) => ReceiptVersion::LegacyV1,
        (Some(CURRENT_RECEIPT_SCHEMA), Some(CURRENT_RECEIPT_CONTRACT)) => ReceiptVersion::CurrentV2,
        _ => {
            return Err(
                "materialization receipt has an unknown or mixed versioned contract identity"
                    .to_owned(),
            )
        }
    };
    validate_architecture_contract(receipt_version.contract(), value).map_err(|error| {
        format!(
            "{} materialization receipt contract invalid ({error})",
            receipt_version.schema()
        )
    })?;
    Ok(receipt_version)
}

fn validate_wallet_consumption_receipt(
    materialization_receipt: &Value,
    wallet_consumption: &ConsumeApprovalGrantForEffectV2Params,
    wallet_consumption_ref: &str,
    wallet_receipt: &ApprovalGrantConsumptionReceipt,
) -> Result<(), VErr> {
    let grant: ApprovalGrant = serde_json::from_value(
        materialization_receipt
            .get("wallet_approval_grant")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .map_err(|error| {
        verr(
            "system_sequence_zero_wallet_consumption_invalid",
            format!("sealed wallet approval grant is malformed ({error})"),
        )
    })?;
    let grant_hash = grant.artifact_hash().map_err(|error| {
        verr(
            "system_sequence_zero_wallet_consumption_invalid",
            format!("sealed wallet approval grant cannot be hashed ({error})"),
        )
    })?;
    let mut receipt_hash_material = serde_json::to_value(wallet_receipt).map_err(|error| {
        verr(
            "system_sequence_zero_wallet_consumption_invalid",
            format!("wallet consumption receipt cannot be serialized ({error})"),
        )
    })?;
    receipt_hash_material["receipt_hash"] = json!(vec![0u8; 32]);
    let canonical_receipt = serde_jcs::to_vec(&receipt_hash_material).map_err(|error| {
        verr(
            "system_sequence_zero_wallet_consumption_invalid",
            format!("wallet consumption receipt cannot be canonicalized ({error})"),
        )
    })?;
    let expected_receipt_hash: [u8; 32] = Sha256::digest(&canonical_receipt).into();
    let expected_scope = AUTHORITY.operation_scope(OP);
    let expected_ref = format!(
        "wallet.network://approval-effect-consumption/{}/{}",
        hex::encode(wallet_consumption.request_hash),
        hex::encode(wallet_consumption.consumption_id)
    );
    if wallet_consumption_ref != expected_ref
        || wallet_receipt.schema_version != 1
        || wallet_receipt.request_hash != wallet_consumption.request_hash
        || wallet_receipt.grant_hash != wallet_consumption.grant_hash
        || wallet_receipt.consumption_id != wallet_consumption.consumption_id
        || wallet_receipt.principal_authority != wallet_consumption.expected_principal_authority
        || wallet_receipt.receipt_hash != expected_receipt_hash
        || wallet_receipt.policy_hash != grant.policy_hash
        || wallet_receipt.authority_id != grant.authority_id
        || wallet_receipt.target.canonical_label() != expected_scope
        || wallet_receipt.session_id.is_some()
        || wallet_receipt.audience != grant.audience
        || wallet_receipt.grant_nonce != grant.nonce
        || wallet_receipt.grant_counter != grant.counter
        || wallet_receipt.grant_hash != grant_hash
        || wallet_receipt.consumed_at_ms > grant.expires_at
        || grant.max_usages != Some(1)
        || wallet_receipt.usage_ordinal != 1
        || wallet_receipt.remaining_usages != 0
    {
        return Err(verr(
            "system_sequence_zero_wallet_consumption_invalid",
            "wallet.network consumption receipt does not bind the exact retained grant, canonical scope, and durable intent",
        ));
    }
    Ok(())
}

fn reconstruct_artifacts(source: SourcePlan, receipt: Value) -> Result<ReconstructedIntent, VErr> {
    let receipt_tail = receipt_tail(&source.plan)?;
    let receipt_version = validate_receipt_identity(&receipt_tail, &receipt)
        .map_err(|message| verr("system_sequence_zero_receipt_evidence_mismatch", message))?;
    let resolved_at_ms = receipt
        .get("authority_resolved_at_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_receipt_evidence_mismatch",
                "materialization receipt lacks wallet authority time",
            )
        })?;
    let created_at = ms_to_rfc3339(resolved_at_ms)?;
    let authorized = sealed_sequence_zero_authorized_decision(
        &receipt,
        &source,
        resolved_at_ms,
        receipt_version,
    )?;
    governed::validate_sealed_effect(AUTHORITY, &receipt, &source.plan.authority_effect)
        .map_err(|message| verr("system_sequence_zero_receipt_evidence_mismatch", message))?;
    let finalized = finalize_system_sequence_zero_materialization(&source.plan, &created_at)
        .map_err(|error| {
            verr(
                "system_sequence_zero_materialization_invalid",
                format!("M1.4 artifact cannot be finalized ({error})"),
            )
        })?;
    let materialization = serde_json::to_value(finalized.materialization).map_err(|error| {
        verr(
            "system_sequence_zero_materialization_invalid",
            format!("M1.4 projection cannot be serialized ({error})"),
        )
    })?;
    let reconstructed_canonical = serde_jcs::to_vec(&materialization).map_err(|error| {
        verr(
            "system_sequence_zero_materialization_invalid",
            format!("M1.4 projection cannot be canonicalized ({error})"),
        )
    })?;
    if finalized.canonical_json != reconstructed_canonical {
        return Err(verr(
            "system_sequence_zero_materialization_invalid",
            "M1.4 projection differs from its canonical compiler bytes",
        ));
    }
    let materialization_tail = materialization_tail(&source.plan)?;
    let component_tail = component_tail(&source.plan)?;
    let component_registry = source.plan.component_registry_snapshot.clone();
    validate_materialization_identity(&materialization_tail, &materialization)
        .map_err(|message| verr("system_sequence_zero_materialization_invalid", message))?;
    validate_component_identity(&component_tail, &component_registry)
        .map_err(|message| verr("system_sequence_zero_component_evidence_mismatch", message))?;
    let (wallet_consumption, wallet_consumption_ref) =
        wallet_consumption_coordinates(&authorized, &source)?;
    let wallet_consumption_tail =
        format!("aszmc_{}", hex::encode(wallet_consumption.consumption_id));
    let expected_receipt = build_receipt_for_version(
        &receipt_tail,
        &materialization,
        &source,
        &authorized,
        &wallet_consumption_ref,
        &wallet_consumption_tail,
        &created_at,
        receipt_version,
    )?;
    if receipt != expected_receipt {
        return Err(verr(
            "system_sequence_zero_receipt_evidence_mismatch",
            "materialization receipt does not reconstruct byte-exactly from M1.3, M1.4, and sealed authority evidence",
        ));
    }
    Ok(ReconstructedIntent {
        source,
        materialization,
        materialization_tail,
        receipt,
        receipt_tail,
        receipt_version,
        component_registry,
        component_tail,
        wallet_consumption,
        wallet_consumption_ref,
        wallet_consumption_tail,
    })
}

fn verify_converged_receipt_authority_root_with<F>(receipt: &Value, verify: F) -> Result<(), VErr>
where
    F: FnOnce(&Value) -> Result<(), String>,
{
    verify(
        receipt
            .get("principal_authority_binding")
            .unwrap_or(&Value::Null),
    )
    .map_err(|message| {
        verr(
            "system_sequence_zero_receipt_authority_root_invalid",
            format!(
                "retained principal-authority binding is not signed by the configured pinned wallet root ({message})"
            ),
        )
    })
}

fn validate_reconstructed_intent(
    intent: &Value,
    tail: &str,
    reconstructed: &ReconstructedIntent,
) -> Result<(), VErr> {
    validate_intent_seal(intent, tail)
        .map_err(|message| verr("system_sequence_zero_intent_unreadable", message))?;
    let expected_touched = touched_refs(
        &reconstructed.source,
        &s(&reconstructed.materialization, "materialization_id"),
        &format!("receipt://{}", reconstructed.receipt_tail),
        &s(&reconstructed.component_registry, "component_registry_ref"),
        &reconstructed.wallet_consumption_ref,
    );
    if intent.get("kind").and_then(Value::as_str) != Some("materialize_sequence_zero")
        || intent.get("op").and_then(Value::as_str) != Some(OP)
        || intent.get("phase").and_then(Value::as_str) != Some("prepared_for_authority_consumption")
        || intent.get("source_record_tail").and_then(Value::as_str)
            != Some(reconstructed.source.source_record_tail.as_str())
        || intent
            .get("genesis_admission_record_root")
            .and_then(Value::as_str)
            != Some(reconstructed.source.source_record_root.as_str())
        || intent
            .get("genesis_admission_receipt_root")
            .and_then(Value::as_str)
            != Some(reconstructed.source.source_receipt_root.as_str())
        || intent.get("required_authority_ref").and_then(Value::as_str)
            != Some(reconstructed.source.governing_authority_ref.as_str())
        || intent.get("materialization_tail").and_then(Value::as_str)
            != Some(reconstructed.materialization_tail.as_str())
        || intent.get("receipt_tail").and_then(Value::as_str)
            != Some(reconstructed.receipt_tail.as_str())
        || intent.get("component_tail").and_then(Value::as_str)
            != Some(reconstructed.component_tail.as_str())
        || intent
            .get("wallet_consumption_tail")
            .and_then(Value::as_str)
            != Some(reconstructed.wallet_consumption_tail.as_str())
        || intent
            .get("wallet_consumption_request_hash")
            .and_then(Value::as_str)
            != Some(
                format!(
                    "sha256:{}",
                    hex::encode(reconstructed.wallet_consumption.request_hash)
                )
                .as_str(),
            )
        || intent.get("wallet_consumption_id").and_then(Value::as_str)
            != Some(hex::encode(reconstructed.wallet_consumption.consumption_id).as_str())
        || intent
            .get("wallet_consumption_grant_hash")
            .and_then(Value::as_str)
            != Some(
                format!(
                    "sha256:{}",
                    hex::encode(reconstructed.wallet_consumption.grant_hash)
                )
                .as_str(),
            )
        || intent
            .get("wallet_grant_consumption_ref")
            .and_then(Value::as_str)
            != Some(reconstructed.wallet_consumption_ref.as_str())
        || intent.get("materialization") != Some(&reconstructed.materialization)
        || intent.get("receipt") != Some(&reconstructed.receipt)
        || intent.get("component_registry") != Some(&reconstructed.component_registry)
        || intent.get("touched_refs") != Some(&json!(expected_touched))
    {
        return Err(verr(
            "system_sequence_zero_intent_unreadable",
            "intent does not reconstruct byte-exactly from M1.3, M1.4, and sealed authority evidence",
        ));
    }
    Ok(())
}

fn reconstruct_intent_locked(
    data_dir: &str,
    tail: &str,
    intent: &Value,
) -> Result<ReconstructedIntent, VErr> {
    validate_intent_seal(intent, tail)
        .map_err(|message| verr("system_sequence_zero_intent_unreadable", message))?;
    let source_tail = intent
        .get("source_record_tail")
        .and_then(Value::as_str)
        .filter(|value| canonical_tail(value, "asg_"))
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_intent_unreadable",
                "intent lacks a canonical M1.3 source key",
            )
        })?;
    let source = source_plan_locked(data_dir, source_tail)?;
    let receipt = intent
        .get("receipt")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_intent_unreadable",
                "intent lacks its immutable materialization receipt",
            )
        })?;
    let reconstructed = reconstruct_artifacts(source, receipt)?;
    verify_converged_receipt_authority_root_with(&reconstructed.receipt, |binding| {
        governed::verify_retained_authority_binding_root(binding)
    })?;
    validate_reconstructed_intent(intent, tail, &reconstructed)?;
    Ok(reconstructed)
}

fn preflight_locked(data_dir: &str, source: &SourcePlan) -> Result<(), VErr> {
    let materialization_tail = materialization_tail(&source.plan)?;
    let receipt_tail = receipt_tail(&source.plan)?;
    let component_tail = component_tail(&source.plan)?;
    let materialization_id = s(&source.plan.materialization_body, "materialization_id");
    let receipt_ref = format!("receipt://{receipt_tail}");
    let component_registry_ref = s(
        &source.plan.component_registry_snapshot,
        "component_registry_ref",
    );
    let refs = touched_refs(
        source,
        &materialization_id,
        &receipt_ref,
        &component_registry_ref,
        "",
    );
    refuse_pending_overlap(data_dir, &refs, None)?;
    for (family, tail, label) in [
        (RECORD_DIR, materialization_tail.as_str(), "materialization"),
        (
            RECEIPT_DIR,
            receipt_tail.as_str(),
            "materialization receipt",
        ),
        (COMPONENT_DIR, component_tail.as_str(), "component registry"),
    ] {
        match load_value(data_dir, family, tail) {
            Ok(None) => {}
            Ok(Some(_)) if family == RECORD_DIR => {
                return match load_converged_materialization_locked(
                    data_dir,
                    &source.source_record_tail,
                ) {
                    Ok(Some(_)) => Err(verr(
                        "system_sequence_zero_already_materialized",
                        format!(
                            "M1.3 admission '{}' already has sequence-zero materialization",
                            source.source_record_tail
                        ),
                    )),
                    Ok(None) => Err(verr(
                        "system_sequence_zero_evidence_mismatch",
                        "the deterministic materialization slot changed while proving convergence",
                    )),
                    Err(error) => Err(error),
                };
            }
            Ok(Some(_)) => {
                return Err(verr(
                    "system_sequence_zero_evidence_mismatch",
                    format!(
                        "{label} '{family}/{tail}' exists without its converged materialization"
                    ),
                ))
            }
            Err(message) => return Err(verr("system_sequence_zero_registry_unreadable", message)),
        }
        match super::substrate_store::read_required_exact(data_dir, family, tail) {
            Ok(None) => {}
            Ok(Some(_)) => {
                return Err(verr(
                    "system_sequence_zero_agentgres_evidence_mismatch",
                    format!(
                        "Agentgres contains '{family}/{tail}' while the required local {label} is absent"
                    ),
                ))
            }
            Err(error) => {
                return Err(verr(
                    "system_sequence_zero_agentgres_evidence_unreadable",
                    format!("Agentgres cannot prove absence for '{family}/{tail}' ({error})"),
                ))
            }
        }
    }
    Ok(())
}

fn require_legacy_receipt_preexisting(
    data_dir: &str,
    receipt_version: ReceiptVersion,
    receipt_tail: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    if receipt_version == ReceiptVersion::CurrentV2 {
        return Ok(());
    }
    let local = load_value(data_dir, RECEIPT_DIR, receipt_tail)
        .map_err(|message| verr("system_sequence_zero_registry_unreadable", message))?;
    let required_matches =
        super::substrate_store::verify_required_exact(data_dir, RECEIPT_DIR, receipt_tail, receipt)
            .is_ok();
    if local.as_ref() == Some(receipt) && required_matches {
        return Ok(());
    }
    Err(verr(
        "system_sequence_zero_legacy_receipt_write_unavailable",
        "the current daemon reads frozen v1 receipts but never creates or backfills them; converge this interrupted historical intent with its pinned historical writer",
    ))
}

fn complete_intent_locked(
    data_dir: &str,
    tail: &str,
    intent: &Value,
) -> Result<ReconstructedIntent, VErr> {
    let reconstructed = reconstruct_intent_locked(data_dir, tail, intent)?;
    require_legacy_receipt_preexisting(
        data_dir,
        reconstructed.receipt_version,
        &reconstructed.receipt_tail,
        &reconstructed.receipt,
    )?;
    let wallet_receipt = load_wallet_consumption(data_dir, &reconstructed.wallet_consumption_tail)
        .map_err(|message| verr("system_sequence_zero_wallet_consumption_invalid", message))?
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_pending_convergence",
                "durable wallet consumption evidence is absent",
            )
        })?;
    validate_wallet_consumption_receipt(
        &reconstructed.receipt,
        &reconstructed.wallet_consumption,
        &reconstructed.wallet_consumption_ref,
        &wallet_receipt,
    )?;
    persist_immutable(
        data_dir,
        COMPONENT_DIR,
        &reconstructed.component_tail,
        &reconstructed.component_registry,
    )?;
    if std::env::var("IOI_TEST_FORCE_SYSTEM_SEQUENCE_ZERO_AFTER_COMPONENT")
        .ok()
        .as_deref()
        == Some("1")
    {
        return Err(verr(
            "system_sequence_zero_pending_convergence",
            "test-forced interruption after component-registry admission",
        ));
    }
    persist_immutable(
        data_dir,
        RECEIPT_DIR,
        &reconstructed.receipt_tail,
        &reconstructed.receipt,
    )?;
    if std::env::var("IOI_TEST_FORCE_SYSTEM_SEQUENCE_ZERO_AFTER_RECEIPT")
        .ok()
        .as_deref()
        == Some("1")
    {
        return Err(verr(
            "system_sequence_zero_pending_convergence",
            "test-forced interruption after materialization-receipt admission",
        ));
    }
    persist_immutable(
        data_dir,
        RECORD_DIR,
        &reconstructed.materialization_tail,
        &reconstructed.materialization,
    )?;
    if std::env::var("IOI_TEST_FORCE_SYSTEM_SEQUENCE_ZERO_AFTER_MATERIALIZATION")
        .ok()
        .as_deref()
        == Some("1")
    {
        return Err(verr(
            "system_sequence_zero_pending_convergence",
            "test-forced interruption after materialization admission",
        ));
    }
    consume_intent(data_dir, tail, intent_created_family(intent)?)?;
    Ok(reconstructed)
}

async fn consume_wallet_grant(
    reconstructed: &ReconstructedIntent,
) -> Result<ApprovalGrantConsumptionReceipt, VErr> {
    let wallet_receipt =
        super::wallet_network_capability_client::consume_approval_grant_for_effect_v2(
            reconstructed.wallet_consumption.clone(),
        )
        .await
        .map_err(|error| {
            use super::wallet_network_capability_client::ResolveError;
            match error {
                ResolveError::NotConfigured(message) | ResolveError::Unavailable(message) => verr(
                    "system_sequence_zero_wallet_consumption_unavailable",
                    message,
                ),
                ResolveError::Refused(message)
                    if message.contains("approval_effect_expected_target_mismatch")
                        || message.contains("approval_effect_expected_max_usages_mismatch") =>
                {
                    verr(
                        "system_sequence_zero_wallet_consumption_precondition_refused",
                        message,
                    )
                }
                ResolveError::Refused(message) => {
                    verr("system_sequence_zero_wallet_consumption_refused", message)
                }
                ResolveError::Invalid(message) => {
                    verr("system_sequence_zero_wallet_consumption_invalid", message)
                }
            }
        })?;
    validate_wallet_consumption_receipt(
        &reconstructed.receipt,
        &reconstructed.wallet_consumption,
        &reconstructed.wallet_consumption_ref,
        &wallet_receipt,
    )?;
    Ok(wallet_receipt)
}

fn consume_unspent_precondition_intent_locked(
    data_dir: &str,
    tail: &str,
    expected_intent: &Value,
    wallet_consumption_tail: &str,
) -> Result<(), VErr> {
    let stored = load_intent(data_dir, tail)
        .map_err(|message| verr("system_sequence_zero_intent_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_pending_convergence",
                "precondition-refused materialization intent vanished before cleanup",
            )
        })?;
    if &stored != expected_intent {
        return Err(verr(
            "system_sequence_zero_intent_unreadable",
            "precondition-refused materialization intent changed before cleanup",
        ));
    }
    if load_wallet_consumption(data_dir, wallet_consumption_tail)
        .map_err(|message| verr("system_sequence_zero_wallet_consumption_invalid", message))?
        .is_some()
    {
        return Err(verr(
            "system_sequence_zero_pending_convergence",
            "wallet-consumption evidence exists for a precondition-refused intent",
        ));
    }
    match super::substrate_store::read_required_exact(
        data_dir,
        CONSUMPTION_DIR,
        wallet_consumption_tail,
    ) {
        Ok(None) => consume_intent(data_dir, tail, intent_created_family(&stored)?),
        Ok(Some(_)) => Err(verr(
            "system_sequence_zero_pending_convergence",
            "Agentgres wallet-consumption evidence exists for a precondition-refused intent",
        )),
        Err(error) => Err(verr(
            "system_sequence_zero_agentgres_evidence_unreadable",
            format!(
                "Agentgres cannot prove wallet-consumption absence before intent cleanup ({error})"
            ),
        )),
    }
}

fn with_plane_locks<T>(operation: impl FnOnce() -> T) -> T {
    // Fixed order: immutable M1.3 source plane, then its M1.4 successor plane.
    let _source = super::system_genesis_routes::SYSTEM_GENESIS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _sequence_zero = SYSTEM_SEQUENCE_ZERO_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    operation()
}

fn compare_expected_source(
    source: &SourcePlan,
    expected_record_root: &str,
    expected_receipt_root: &str,
) -> Result<(), VErr> {
    if source.source_record_root != expected_record_root
        || source.source_receipt_root != expected_receipt_root
    {
        return Err(verr(
            "system_sequence_zero_source_conflict",
            "the exact M1.3 admission record or receipt root differs from the caller's expected source",
        ));
    }
    Ok(())
}

fn build_online_artifacts(
    source: SourcePlan,
    authorized: &AuthorizedDecision,
) -> Result<ReconstructedIntent, VErr> {
    let created_at = ms_to_rfc3339(authorized.resolved_at_ms)?;
    let finalized = finalize_system_sequence_zero_materialization(&source.plan, &created_at)
        .map_err(|error| {
            verr(
                "system_sequence_zero_materialization_invalid",
                format!("M1.4 artifact cannot be finalized ({error})"),
            )
        })?;
    let materialization = serde_json::to_value(finalized.materialization).map_err(|error| {
        verr(
            "system_sequence_zero_materialization_invalid",
            format!("M1.4 projection cannot be serialized ({error})"),
        )
    })?;
    let receipt_tail = receipt_tail(&source.plan)?;
    let (wallet_consumption, wallet_consumption_ref) =
        wallet_consumption_coordinates(authorized, &source)?;
    let wallet_consumption_tail =
        format!("aszmc_{}", hex::encode(wallet_consumption.consumption_id));
    let receipt = build_receipt(
        &receipt_tail,
        &materialization,
        &source,
        authorized,
        &wallet_consumption_ref,
        &wallet_consumption_tail,
        &created_at,
    )?;
    reconstruct_artifacts(source, receipt)
}

pub(crate) async fn handle_materialize(
    AxumPath(source_record_tail): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !canonical_tail(&source_record_tail, "asg_") {
        return classify(verr(
            "system_sequence_zero_source_key_invalid",
            "the source key must be 'asg_' plus 64 lowercase hex characters",
        ));
    }
    let (expected_record_root, expected_receipt_root) = match validate_request(&body) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let _gate = SYSTEM_SEQUENCE_ZERO_GATE.lock().await;
    let source = match with_plane_locks(|| {
        let source = source_plan_locked(&state.data_dir, &source_record_tail)?;
        compare_expected_source(&source, &expected_record_root, &expected_receipt_root)?;
        preflight_locked(&state.data_dir, &source)?;
        Ok::<_, VErr>(source)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let authorized = match governed::authorize_decision_with_context(
        AUTHORITY,
        &body,
        Governance::Host,
        AuthorityPolicyContext::SystemGenesis {
            system_id: &source.system_id,
            genesis_id: &source.genesis_ref,
        },
        &source.governing_authority_ref,
        &s(&source.plan.materialization_body, "materialization_id"),
        OP,
        0,
        &source.plan.authority_effect,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let reconstructed = match build_online_artifacts(source.clone(), &authorized) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent_tail = format!(
        "aszmi_{}",
        hex::encode(reconstructed.wallet_consumption.request_hash)
    );
    let intent_body = json!({
            "kind": "materialize_sequence_zero",
            "op": OP,
            "phase": "prepared_for_authority_consumption",
            "source_record_tail": reconstructed.source.source_record_tail,
            "system_id": reconstructed.source.system_id,
            "genesis_ref": reconstructed.source.genesis_ref,
            "genesis_admission_record_root": reconstructed.source.source_record_root,
            "genesis_admission_receipt_root": reconstructed.source.source_receipt_root,
            "required_authority_ref": reconstructed.source.governing_authority_ref,
            "materialization_id": reconstructed.materialization.get("materialization_id"),
            "materialization_tail": reconstructed.materialization_tail,
            "materialization_receipt_ref": reconstructed.receipt.get("receipt_ref"),
            "receipt_tail": reconstructed.receipt_tail,
            "component_registry_ref": reconstructed.component_registry.get("component_registry_ref"),
            "component_tail": reconstructed.component_tail,
            "wallet_consumption_tail": reconstructed.wallet_consumption_tail,
            "wallet_consumption_request_hash": format!(
                "sha256:{}",
                hex::encode(reconstructed.wallet_consumption.request_hash)
            ),
            "wallet_consumption_grant_hash": format!(
                "sha256:{}",
                hex::encode(reconstructed.wallet_consumption.grant_hash)
            ),
            "wallet_consumption_id": hex::encode(reconstructed.wallet_consumption.consumption_id),
            "wallet_grant_consumption_ref": reconstructed.wallet_consumption_ref,
            "materialization": reconstructed.materialization,
            "receipt": reconstructed.receipt,
            "component_registry": reconstructed.component_registry
    });
    let intent = match with_plane_locks(|| {
        let current = source_plan_locked(&state.data_dir, &source_record_tail)?;
        compare_expected_source(&current, &expected_record_root, &expected_receipt_root)?;
        if current.source_record != source.source_record
            || current.source_receipt != source.source_receipt
            || current.plan != source.plan
        {
            return Err(verr(
                "system_sequence_zero_source_conflict",
                "the converged M1.3 source changed during authorization",
            ));
        }
        preflight_locked(&state.data_dir, &current)?;
        let family_preexisted =
            match super::durable_fs::open_family_dir_pinned(&state.data_dir, INTENT_DIR) {
                Ok(directory) => {
                    drop(directory);
                    true
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => {
                    return Err(verr(
                        "system_sequence_zero_intent_unreadable",
                        format!("intent family preflight failed ({error})"),
                    ))
                }
            };
        let existing_intents = if family_preexisted {
            scan_intents(&state.data_dir)
                .map_err(|message| verr("system_sequence_zero_intent_unreadable", message))?
        } else {
            Vec::new()
        };
        let cleanup_required =
            inherited_family_cleanup_obligation(family_preexisted, &existing_intents)?;
        let mut intent_body = intent_body;
        // Propagate the cleanup obligation across concurrent intents. The last surviving intent
        // must still restore an originally absent family after the first creator has converged.
        intent_body["intent_family_created_by_request"] = json!(cleanup_required);
        let intent = seal_intent(intent_body, &intent_tail, &reconstructed.source);
        persist_intent(&state.data_dir, &intent_tail, &intent, cleanup_required)?;
        Ok(intent)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if std::env::var("IOI_TEST_FORCE_SYSTEM_SEQUENCE_ZERO_AFTER_PREPARE")
        .ok()
        .as_deref()
        == Some("1")
    {
        return classify(verr(
            "system_sequence_zero_pending_convergence",
            "test-forced interruption after durable authority-consumption preparation",
        ));
    }
    let reconstructed = match with_plane_locks(|| {
        let stored = load_intent(&state.data_dir, &intent_tail)
            .map_err(|message| verr("system_sequence_zero_intent_unreadable", message))?
            .ok_or_else(|| {
                verr(
                    "system_sequence_zero_pending_convergence",
                    "durable materialization intent vanished before wallet consumption",
                )
            })?;
        if stored != intent {
            return Err(verr(
                "system_sequence_zero_intent_unreadable",
                "durable materialization intent differs from the authorized request",
            ));
        }
        reconstruct_intent_locked(&state.data_dir, &intent_tail, &stored)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let wallet_receipt = match consume_wallet_grant(&reconstructed).await {
        Ok(value) => value,
        Err(error) if error.0 == "system_sequence_zero_wallet_consumption_precondition_refused" => {
            if let Err(cleanup_error) = with_plane_locks(|| {
                consume_unspent_precondition_intent_locked(
                    &state.data_dir,
                    &intent_tail,
                    &intent,
                    &reconstructed.wallet_consumption_tail,
                )
            }) {
                return classify(cleanup_error);
            }
            return classify(error);
        }
        Err(error) => return classify(error),
    };
    if std::env::var("IOI_TEST_FORCE_SYSTEM_SEQUENCE_ZERO_AFTER_WALLET_CONSUME")
        .ok()
        .as_deref()
        == Some("1")
    {
        return classify(verr(
            "system_sequence_zero_pending_convergence",
            "test-forced interruption after wallet authority consumption",
        ));
    }
    let completed = with_plane_locks(|| {
        let stored = load_intent(&state.data_dir, &intent_tail)
            .map_err(|message| verr("system_sequence_zero_intent_unreadable", message))?
            .ok_or_else(|| {
                verr(
                    "system_sequence_zero_pending_convergence",
                    "durable materialization intent vanished before completion",
                )
            })?;
        if stored != intent {
            return Err(verr(
                "system_sequence_zero_intent_unreadable",
                "durable materialization intent differs from the authorized request",
            ));
        }
        persist_wallet_consumption(
            &state.data_dir,
            &reconstructed.wallet_consumption_tail,
            &wallet_receipt,
        )?;
        test_pause_after_durable_wallet_consumption_evidence()?;
        complete_intent_locked(&state.data_dir, &intent_tail, &stored)
    });
    match completed {
        Ok(value) => (
            StatusCode::CREATED,
            Json(json!({
                "autonomous_system_sequence_zero_materialization": value.materialization,
                "autonomous_system_sequence_zero_materialization_receipt": value.receipt,
                "component_registry_snapshot": value.component_registry,
                "wallet_grant_consumption_receipt": wallet_receipt,
                "nonclaims": {
                    "active_profile_admission": false,
                    "initialize": false,
                    "activation": false,
                    "live_chain": false,
                    "node_membership": false,
                    "network_effect": false,
                    "runtime_effect": false,
                    "systems_product_surface": false
                }
            })),
        ),
        Err(error) => classify(error),
    }
}

fn load_converged_materialization_locked(
    data_dir: &str,
    source_record_tail: &str,
) -> Result<Option<(ReconstructedIntent, ApprovalGrantConsumptionReceipt)>, VErr> {
    let source = source_plan_locked(data_dir, source_record_tail)?;
    let materialization_tail = materialization_tail(&source.plan)?;
    let pending = scan_intents(data_dir)
        .map_err(|message| verr("system_sequence_zero_intent_unreadable", message))?
        .iter()
        .any(|(_, intent)| {
            intent.get("source_record_tail").and_then(Value::as_str) == Some(source_record_tail)
        });
    if pending {
        return Err(verr(
            "system_sequence_zero_pending_convergence",
            format!(
                "sequence-zero materialization for '{source_record_tail}' has not crossed every durable boundary"
            ),
        ));
    }
    let Some(materialization) = load_value(data_dir, RECORD_DIR, &materialization_tail)
        .map_err(|message| verr("system_sequence_zero_registry_unreadable", message))?
    else {
        return match super::substrate_store::read_required_exact(
            data_dir,
            RECORD_DIR,
            &materialization_tail,
        ) {
            Ok(None) => Ok(None),
            Ok(Some(_)) => Err(verr(
                "system_sequence_zero_agentgres_evidence_mismatch",
                "Agentgres contains the materialization while its required local projection is absent",
            )),
            Err(error) => Err(verr(
                "system_sequence_zero_agentgres_evidence_unreadable",
                format!("Agentgres cannot prove materialization absence ({error})"),
            )),
        };
    };
    validate_materialization_identity(&materialization_tail, &materialization)
        .map_err(|message| verr("system_sequence_zero_materialization_invalid", message))?;
    let receipt_tail = receipt_tail(&source.plan)?;
    let receipt = load_value(data_dir, RECEIPT_DIR, &receipt_tail)
        .map_err(|message| verr("system_sequence_zero_registry_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_receipt_evidence_missing",
                "materialization receipt is absent",
            )
        })?;
    let reconstructed = reconstruct_artifacts(source, receipt)?;
    verify_converged_receipt_authority_root_with(&reconstructed.receipt, |binding| {
        governed::verify_retained_authority_binding_root(binding)
    })?;
    if reconstructed.materialization != materialization {
        return Err(verr(
            "system_sequence_zero_materialization_evidence_mismatch",
            "stored materialization does not reconstruct from its M1.3 source and receipt",
        ));
    }
    let component = load_value(data_dir, COMPONENT_DIR, &reconstructed.component_tail)
        .map_err(|message| verr("system_sequence_zero_registry_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_component_evidence_missing",
                "component-registry snapshot is absent",
            )
        })?;
    if component != reconstructed.component_registry {
        return Err(verr(
            "system_sequence_zero_component_evidence_mismatch",
            "stored component registry does not reconstruct from its M1.3 source",
        ));
    }
    let wallet_receipt = load_wallet_consumption(data_dir, &reconstructed.wallet_consumption_tail)
        .map_err(|message| verr("system_sequence_zero_wallet_consumption_invalid", message))?
        .ok_or_else(|| {
            verr(
                "system_sequence_zero_wallet_consumption_evidence_missing",
                "wallet consumption evidence is absent",
            )
        })?;
    validate_wallet_consumption_receipt(
        &reconstructed.receipt,
        &reconstructed.wallet_consumption,
        &reconstructed.wallet_consumption_ref,
        &wallet_receipt,
    )?;
    for (family, tail, value) in [
        (
            RECORD_DIR,
            reconstructed.materialization_tail.as_str(),
            &reconstructed.materialization,
        ),
        (
            RECEIPT_DIR,
            reconstructed.receipt_tail.as_str(),
            &reconstructed.receipt,
        ),
        (
            COMPONENT_DIR,
            reconstructed.component_tail.as_str(),
            &reconstructed.component_registry,
        ),
    ] {
        super::substrate_store::verify_required_exact(data_dir, family, tail, value).map_err(
            |error| {
                verr(
                    "system_sequence_zero_agentgres_evidence_mismatch",
                    format!("Agentgres exact proof for '{family}/{tail}' failed ({error})"),
                )
            },
        )?;
    }
    let wallet_value = serde_json::to_value(&wallet_receipt).map_err(|error| {
        verr(
            "system_sequence_zero_wallet_consumption_invalid",
            format!("wallet consumption receipt cannot be projected ({error})"),
        )
    })?;
    super::substrate_store::verify_required_exact(
        data_dir,
        CONSUMPTION_DIR,
        &reconstructed.wallet_consumption_tail,
        &wallet_value,
    )
    .map_err(|error| {
        verr(
            "system_sequence_zero_agentgres_evidence_mismatch",
            format!("Agentgres wallet-consumption proof failed ({error})"),
        )
    })?;
    Ok(Some((reconstructed, wallet_receipt)))
}

pub(crate) async fn handle_get(
    AxumPath(source_record_tail): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    if !canonical_tail(&source_record_tail, "asg_") {
        return classify(verr(
            "system_sequence_zero_source_key_invalid",
            "the source key must be 'asg_' plus 64 lowercase hex characters",
        ));
    }
    match with_plane_locks(|| {
        load_converged_materialization_locked(&state.data_dir, &source_record_tail)
    }) {
        Ok(Some((value, wallet_receipt))) => (
            StatusCode::OK,
            Json(json!({
                "autonomous_system_sequence_zero_materialization": value.materialization,
                "autonomous_system_sequence_zero_materialization_receipt": value.receipt,
                "component_registry_snapshot": value.component_registry,
                "wallet_grant_consumption_receipt": wallet_receipt,
                "authority": governed::decision_authority_posture(AUTHORITY),
                "nonclaims": {
                    "active_profile_admission": false,
                    "initialize": false,
                    "activation": false,
                    "live_chain": false,
                    "node_membership": false,
                    "network_effect": false,
                    "runtime_effect": false,
                    "systems_product_surface": false
                }
            })),
        ),
        Ok(None) => classify(verr(
            "system_sequence_zero_not_found",
            format!("no converged sequence-zero materialization exists for '{source_record_tail}'"),
        )),
        Err(error) => classify(error),
    }
}

pub(crate) async fn complete_governed_system_sequence_zero_intents(
    data_dir: &str,
    max_intents: usize,
) {
    let _gate = SYSTEM_SEQUENCE_ZERO_GATE.lock().await;
    let intents = match with_plane_locks(|| scan_intents(data_dir)) {
        Ok(value) => fair_replay_window(value, max_intents, &SYSTEM_SEQUENCE_ZERO_REPLAY_CURSOR),
        Err(message) => {
            eprintln!("SystemSequenceZero completer: scan failed ({message})");
            return;
        }
    };
    for (tail, intent) in intents.into_iter().take(max_intents) {
        let reconstructed = match with_plane_locks(|| {
            reconstruct_intent_locked(data_dir, &tail, &intent)
        }) {
            Ok(value) => value,
            Err((_, message)) => {
                eprintln!("SystemSequenceZero completer: '{tail}' invalid ({message}); retained");
                continue;
            }
        };
        let existing_wallet_receipt = match with_plane_locks(|| {
            load_wallet_consumption(data_dir, &reconstructed.wallet_consumption_tail)
        }) {
            Ok(value) => value,
            Err(message) => {
                eprintln!(
                    "SystemSequenceZero completer: '{tail}' wallet evidence unreadable ({message}); retained"
                );
                continue;
            }
        };
        if let Err(message) = governed::verify_retained_authority_binding_root(
            &reconstructed
                .receipt
                .get("principal_authority_binding")
                .cloned()
                .unwrap_or(Value::Null),
        ) {
            eprintln!(
                "SystemSequenceZero completer: '{tail}' retained binding proof invalid ({message}); retained"
            );
            continue;
        }
        // Wallet consumption is the replay oracle: an existing exact receipt is idempotent even
        // after revocation, while a first consumption validates the current binding before spend.
        let wallet_receipt = match existing_wallet_receipt {
            Some(value) => value,
            None => match consume_wallet_grant(&reconstructed).await {
                Ok(value) => value,
                Err((code, message))
                    if code == "system_sequence_zero_wallet_consumption_precondition_refused" =>
                {
                    match with_plane_locks(|| {
                        consume_unspent_precondition_intent_locked(
                            data_dir,
                            &tail,
                            &intent,
                            &reconstructed.wallet_consumption_tail,
                        )
                    }) {
                        Ok(()) => eprintln!(
                            "SystemSequenceZero completer: '{tail}' discarded after wallet precondition refusal ({message})"
                        ),
                        Err((_, cleanup_message)) => eprintln!(
                            "SystemSequenceZero completer: '{tail}' precondition cleanup failed ({cleanup_message}); retained"
                        ),
                    }
                    continue;
                }
                Err((_, message)) => {
                    eprintln!(
                        "SystemSequenceZero completer: '{tail}' wallet consumption unavailable ({message}); retained"
                    );
                    continue;
                }
            },
        };
        let result = with_plane_locks(|| {
            let stored = load_intent(data_dir, &tail)
                .map_err(|message| verr("system_sequence_zero_intent_unreadable", message))?
                .ok_or_else(|| {
                    verr(
                        "system_sequence_zero_pending_convergence",
                        "materialization intent vanished during startup convergence",
                    )
                })?;
            if stored != intent {
                return Err(verr(
                    "system_sequence_zero_intent_unreadable",
                    "materialization intent changed during startup convergence",
                ));
            }
            persist_wallet_consumption(
                data_dir,
                &reconstructed.wallet_consumption_tail,
                &wallet_receipt,
            )?;
            test_pause_after_durable_wallet_consumption_evidence()?;
            complete_intent_locked(data_dir, &tail, &stored)
        });
        if let Err((_, message)) = result {
            eprintln!("SystemSequenceZero completer: '{tail}' incomplete ({message}); retained");
        }
    }
}

#[cfg(test)]
mod system_sequence_zero_tests {
    use super::*;
    use ioi_types::app::{
        account_id_from_key_material, PrincipalAuthorityBindingProofV1, SignatureSuite,
        WalletControlPlaneRootRecord,
    };
    use std::collections::BTreeMap;

    const ZERO_HASH: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn receipt_fixture_source(materialization: &Value, receipt: &Value) -> SourcePlan {
        let source_record_root = s(materialization, "genesis_admission_record_root");
        let source_record_tail = format!(
            "asg_{}",
            source_record_root
                .strip_prefix("sha256:")
                .expect("fixture genesis record root")
        );
        SourcePlan {
            source_record_tail,
            source_record: json!({
                "admission_receipt_ref": materialization["genesis_admission_receipt_ref"]
            }),
            source_receipt: Value::Null,
            source_record_root,
            source_receipt_root: s(materialization, "genesis_admission_receipt_root"),
            system_id: s(materialization, "system_id"),
            genesis_ref: s(materialization, "genesis_ref"),
            governing_authority_ref: s(&receipt["bound_facts"], "governing_authority_ref"),
            plan: CompiledSystemSequenceZeroPlan {
                component_registry_snapshot: Value::Null,
                materialization_body: materialization.clone(),
                authority_effect: receipt["authorized_effect"].clone(),
                component_registry_root: String::new(),
                profile_materialization_root: String::new(),
                operation_commitment: String::new(),
                initial_state_root: String::new(),
                initial_receipt_root: String::new(),
                transition_commitment_ref: String::new(),
            },
        }
    }

    fn receipt_fixture_coordinates(receipt: &Value) -> (&str, &str, &str, &str) {
        (
            receipt["receipt_ref"]
                .as_str()
                .and_then(|value| value.strip_prefix("receipt://"))
                .expect("fixture receipt tail"),
            receipt["bound_facts"]["wallet_grant_consumption_ref"]
                .as_str()
                .expect("fixture wallet consumption ref"),
            receipt["bound_facts"]["wallet_grant_consumption_evidence_ref"]
                .as_str()
                .and_then(|value| {
                    value.strip_prefix("system-sequence-zero-authority-consumption://")
                })
                .expect("fixture wallet consumption tail"),
            receipt["timestamp"].as_str().expect("fixture timestamp"),
        )
    }

    #[test]
    fn bounded_replay_window_rotates_past_a_retained_prefix() {
        let cursor = AtomicUsize::new(0);
        let intents = vec![
            ("aszmi_a".to_string(), json!({"slot": "a"})),
            ("aszmi_b".to_string(), json!({"slot": "b"})),
        ];
        assert_eq!(
            fair_replay_window(intents.clone(), 1, &cursor)[0].0,
            "aszmi_a"
        );
        assert_eq!(
            fair_replay_window(intents, 1, &cursor)[0].0,
            "aszmi_b",
            "a retained first intent cannot starve the next consumed intent"
        );
    }

    #[test]
    fn default_ceiling_still_rotates_the_first_replayed_intent() {
        let cursor = AtomicUsize::new(0);
        let intents = vec![
            ("aszmi_a".to_string(), json!({"slot": "a"})),
            ("aszmi_b".to_string(), json!({"slot": "b"})),
            ("aszmi_c".to_string(), json!({"slot": "c"})),
        ];
        let starts = (0..3)
            .map(|_| {
                fair_replay_window(intents.clone(), 32, &cursor)[0]
                    .0
                    .clone()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            starts,
            vec!["aszmi_a", "aszmi_b", "aszmi_c"],
            "a slow first intent cannot monopolize the first wall-clock slot when len <= ceiling"
        );
    }

    #[test]
    fn request_created_family_cleanup_obligation_follows_the_last_concurrent_intent() {
        let inherited = vec![(
            "aszmi_a".to_string(),
            json!({"intent_family_created_by_request": true}),
        )];
        assert!(inherited_family_cleanup_obligation(true, &inherited).unwrap());
        assert!(inherited_family_cleanup_obligation(false, &[]).unwrap());
        assert!(!inherited_family_cleanup_obligation(true, &[]).unwrap());
    }

    #[test]
    fn legacy_pending_intent_without_family_provenance_remains_readable() {
        let tail = format!("aszmi_{}", "a".repeat(64));
        let mut intent = json!({
            "schema_version": INTENT_SCHEMA,
            "intent_id": format!(
                "system-sequence-zero-materialization-intent://{tail}"
            )
        });
        let hash = crate::outcome_room_routes::record_output_hash(&intent, &[]);
        intent["intent_hash"] = json!(hash);

        validate_intent_seal(&intent, &tail).expect("legacy sealed bytes remain readable");
        assert!(!intent_created_family(&intent).unwrap());
    }

    #[test]
    fn request_shape_is_closed_bounded_and_secret_free() {
        let valid = json!({
            "expected_genesis_admission_record_root": ZERO_HASH,
            "expected_genesis_admission_receipt_root": ZERO_HASH
        });
        assert_eq!(
            validate_request(&valid).expect("closed request"),
            (ZERO_HASH.to_owned(), ZERO_HASH.to_owned())
        );

        let unknown = json!({
            "expected_genesis_admission_record_root": ZERO_HASH,
            "expected_genesis_admission_receipt_root": ZERO_HASH,
            "initial_state_root": ZERO_HASH
        });
        assert_eq!(
            validate_request(&unknown).unwrap_err().0,
            "system_sequence_zero_request_field_unknown"
        );

        let secret = json!({
            "expected_genesis_admission_record_root": ZERO_HASH,
            "expected_genesis_admission_receipt_root": ZERO_HASH,
            "metadata": { "api_token": "must-never-persist" }
        });
        let error = validate_request(&secret).unwrap_err();
        assert_eq!(error.0, "system_sequence_zero_sensitive_field_rejected");
        assert!(!error.1.contains("must-never-persist"));
    }

    #[test]
    fn retained_authority_evidence_accepts_legacy_nulls_but_rejects_unknown_fields() {
        let receipt: Value = serde_json::from_str(include_str!(
            "../../../../../docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v1/positive-materialized-pending-activation.json"
        ))
        .expect("registered positive receipt fixture");

        let mut legacy_grant = receipt["wallet_approval_grant"].clone();
        for field in [
            "window_id",
            "pii_action",
            "scoped_exception",
            "review_request_hash",
        ] {
            legacy_grant[field] = Value::Null;
        }
        let (_, canonical_grant) =
            governed::canonicalize_approval_grant(&legacy_grant).expect("legacy null ABI");
        assert!(canonical_grant.is_object());

        legacy_grant["forged_context"] = json!("claim inflation");
        assert!(governed::canonicalize_approval_grant(&legacy_grant).is_err());

        let mut nested_grant = receipt["wallet_approval_grant"].clone();
        nested_grant["pii_action"] = json!("grant_scoped_exception");
        nested_grant["scoped_exception"] = json!({
            "exception_id": "exception-1",
            "allowed_classes": ["email"],
            "destination_hash": vec![7; 32],
            "action_hash": vec![8; 32],
            "expires_at": 1,
            "max_uses": 1,
            "justification_hash": vec![9; 32]
        });
        governed::canonicalize_approval_grant(&nested_grant)
            .expect("closed nested grant projection");
        nested_grant["scoped_exception"]["forged_context"] = json!("claim inflation");
        assert!(governed::canonicalize_approval_grant(&nested_grant).is_err());

        let mut authority_binding = receipt["principal_authority_binding"].clone();
        authority_binding["forged_context"] = json!("claim inflation");
        assert!(governed::canonicalize_authority_binding(
            &authority_binding,
            receipt["authority_resolved_at_ms"]
                .as_u64()
                .expect("fixture authority time"),
        )
        .is_err());
    }

    #[test]
    fn portable_grant_ref_binds_the_exact_retained_signed_artifact() {
        let receipt: Value = serde_json::from_str(include_str!(
            "../../../../../docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json"
        ))
        .expect("registered positive receipt fixture");
        let grant: ApprovalGrant = serde_json::from_value(receipt["wallet_approval_grant"].clone())
            .expect("fixture grant projection");
        let expected = format!(
            "grant://wallet.network/approval/sha256:{}",
            hex::encode(grant.artifact_hash().expect("grant artifact hash"))
        );
        assert_eq!(canonical_grant_ref(&grant).unwrap(), expected);

        let mut altered = grant;
        altered.counter += 1;
        assert_ne!(
            canonical_grant_ref(&altered).unwrap(),
            expected,
            "changing retained signed grant material must change its portable identity"
        );
    }

    #[test]
    fn converged_get_gate_rejects_coherent_evidence_from_a_foreign_wallet_root() {
        let receipt: Value = serde_json::from_str(include_str!(
            "../../../../../docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json"
        ))
        .expect("registered current receipt fixture");
        let proof: PrincipalAuthorityBindingProofV1 =
            serde_json::from_value(receipt["principal_authority_binding"]["binding_proof"].clone())
                .expect("retained binding proof");
        let issuer_root = WalletControlPlaneRootRecord {
            account_id: proof.statement.issuer_root_account_id,
            signature_suite: proof.issuer_signature_proof.suite,
            public_key: proof.issuer_signature_proof.public_key.clone(),
            registered_at_ms: 0,
            updated_at_ms: 0,
            metadata: BTreeMap::new(),
        };
        let foreign_public_key = receipt["wallet_approval_grant"]["approver_public_key"]
            .as_array()
            .expect("foreign public key")
            .iter()
            .map(|value| value.as_u64().expect("public-key byte") as u8)
            .collect::<Vec<_>>();
        let foreign_root = WalletControlPlaneRootRecord {
            account_id: account_id_from_key_material(SignatureSuite::ED25519, &foreign_public_key)
                .expect("foreign root id"),
            signature_suite: SignatureSuite::ED25519,
            public_key: foreign_public_key,
            registered_at_ms: 0,
            updated_at_ms: 0,
            metadata: BTreeMap::new(),
        };

        verify_converged_receipt_authority_root_with(&receipt, |_| {
            super::super::wallet_network_capability_client::verify_retained_principal_authority_binding_proof_with_root(
                &proof,
                &issuer_root,
            )
            .map_err(|error| format!("{error:?}"))
        })
        .expect("coherent issuer-root evidence");
        let error = verify_converged_receipt_authority_root_with(&receipt, |_| {
            super::super::wallet_network_capability_client::verify_retained_principal_authority_binding_proof_with_root(
                &proof,
                &foreign_root,
            )
            .map_err(|error| format!("{error:?}"))
        })
        .expect_err("foreign-root evidence must fail the converged GET gate");
        assert_eq!(
            error.0,
            "system_sequence_zero_receipt_authority_root_invalid"
        );
    }

    #[test]
    fn receipt_reader_pins_current_v2_and_frozen_legacy_v1_bytes() {
        let registered_fixture: Value = serde_json::from_str(include_str!(
            "../../../../../docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json"
        ))
        .expect("registered current receipt fixture");
        let materialization = registered_fixture["authorized_effect"]["materialization"].clone();
        let source = receipt_fixture_source(&materialization, &registered_fixture);
        let resolved_at_ms = registered_fixture["authority_resolved_at_ms"]
            .as_u64()
            .expect("fixture authority time");
        let (receipt_tail, wallet_ref, wallet_tail, created_at) =
            receipt_fixture_coordinates(&registered_fixture);
        let authorized = sealed_sequence_zero_authorized_decision(
            &registered_fixture,
            &source,
            resolved_at_ms,
            ReceiptVersion::CurrentV2,
        )
        .expect("fixture retained authority evidence");
        let current = build_receipt_for_version(
            receipt_tail,
            &materialization,
            &source,
            &authorized,
            wallet_ref,
            wallet_tail,
            created_at,
            ReceiptVersion::CurrentV2,
        )
        .expect("build current receipt");
        assert_eq!(
            validate_receipt_identity(receipt_tail, &current),
            Ok(ReceiptVersion::CurrentV2)
        );
        let current_authorized = sealed_sequence_zero_authorized_decision(
            &current,
            &source,
            resolved_at_ms,
            ReceiptVersion::CurrentV2,
        )
        .expect("current retained authority evidence");
        let rebuilt_current = build_receipt_for_version(
            receipt_tail,
            &materialization,
            &source,
            &current_authorized,
            wallet_ref,
            wallet_tail,
            created_at,
            ReceiptVersion::CurrentV2,
        )
        .expect("rebuild current receipt");
        assert_eq!(rebuilt_current, current);
        assert_eq!(
            hex::encode(Sha256::digest(
                serde_jcs::to_vec(&rebuilt_current).expect("current JCS")
            )),
            "378c8636bcac1807828ff4b49e576a0b87716efa76e1c8ba42028acd96afa166",
            "current v2 bytes are pinned"
        );

        let historical = build_receipt_for_version(
            receipt_tail,
            &materialization,
            &source,
            &authorized,
            wallet_ref,
            wallet_tail,
            created_at,
            ReceiptVersion::LegacyV1,
        )
        .expect("build historical receipt");
        let mut mixed_identity = historical.clone();
        mixed_identity["receipt_profile_ref"] = json!(CURRENT_RECEIPT_CONTRACT);
        assert!(
            validate_receipt_identity(receipt_tail, &mixed_identity).is_err(),
            "legacy bytes cannot claim the current contract identity"
        );
        assert_eq!(
            validate_receipt_identity(receipt_tail, &historical),
            Ok(ReceiptVersion::LegacyV1)
        );
        let historical_authorized = sealed_sequence_zero_authorized_decision(
            &historical,
            &source,
            resolved_at_ms,
            ReceiptVersion::LegacyV1,
        )
        .expect("historical retained authority evidence");
        assert_eq!(historical_authorized, authorized);
        let rebuilt_historical = build_receipt_for_version(
            receipt_tail,
            &materialization,
            &source,
            &historical_authorized,
            wallet_ref,
            wallet_tail,
            created_at,
            ReceiptVersion::LegacyV1,
        )
        .expect("rebuild historical receipt");
        assert_eq!(rebuilt_historical, historical);
        let data_dir = tempfile::tempdir().expect("legacy replay test data dir");
        let data_dir = data_dir.path().to_str().expect("utf8 data dir");
        let missing = require_legacy_receipt_preexisting(
            data_dir,
            ReceiptVersion::LegacyV1,
            receipt_tail,
            &historical,
        )
        .expect_err("current replay must not author a missing historical receipt");
        assert_eq!(
            missing.0,
            "system_sequence_zero_legacy_receipt_write_unavailable"
        );
        persist_immutable(data_dir, RECEIPT_DIR, receipt_tail, &historical)
            .expect("pinned historical writer fixture persists its own receipt");
        require_legacy_receipt_preexisting(
            data_dir,
            ReceiptVersion::LegacyV1,
            receipt_tail,
            &historical,
        )
        .expect("current replay may consume an already-durable historical receipt");
        assert_ne!(historical, current);
        assert_eq!(
            hex::encode(Sha256::digest(
                serde_jcs::to_vec(&rebuilt_historical).expect("historical JCS")
            )),
            "1d80772f57195d90f9b14f0fcee171fa050acd092c03cecd7dc40f9bd1cbe063",
            "historical v1 bytes are pinned"
        );
    }

    #[test]
    fn sealed_authority_context_cannot_move_between_system_genesis_pairs() {
        let authority_effect = json!({
            "operation": "materialize_sequence_zero",
            "materialization": {
                "materialization_id": "system-materialization://sequence-zero/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "activation_admitted": false,
            "runtime_effect_admitted": false
        });
        let subject_ref =
            "system-materialization://sequence-zero/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let policy_hash = governed::decision_policy_hash_for_context(
            AUTHORITY,
            Governance::Host,
            AuthorityPolicyContext::SystemGenesis {
                system_id: "system://acme/system-a",
                genesis_id: "genesis://acme/system-a/zero",
            },
            "org://acme/research",
            OP,
        );
        let effect_hash = governed::decision_effect_hash(AUTHORITY, &authority_effect);
        let request_hash = governed::decision_request_hash(
            AUTHORITY,
            Governance::Host,
            subject_ref,
            OP,
            0,
            "org://acme/research",
            &effect_hash,
        );
        let receipt = json!({
            "policy_hash": policy_hash,
            "input_hash": request_hash,
            "effect_hash": effect_hash,
            "authorized_effect": authority_effect,
            "subject_ref": subject_ref,
        });

        reconstruct_sealed_authority_context(
            &receipt,
            "system://acme/system-a",
            "genesis://acme/system-a/zero",
            "org://acme/research",
            subject_ref,
            &receipt["authorized_effect"],
        )
        .expect("matching context");
        assert_eq!(
            reconstruct_sealed_authority_context(
                &receipt,
                "system://acme/system-b",
                "genesis://acme/system-b/zero",
                "org://acme/research",
                subject_ref,
                &receipt["authorized_effect"],
            )
            .unwrap_err()
            .0,
            "system_sequence_zero_receipt_evidence_mismatch"
        );
    }

    #[test]
    fn materialization_storage_identity_is_exact_and_pre_activation() {
        let mut materialization: Value = serde_json::from_str(include_str!(
            "../../../../../docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-v1/positive-materialized-pending-activation.json"
        ))
        .expect("registered positive fixture");
        materialization["genesis_admission_record_root"] = json!(ZERO_HASH);
        materialization["materialization_id"] = json!(format!(
            "system-materialization://sequence-zero/{ZERO_HASH}"
        ));
        let tail = format!("aszm_{}", ZERO_HASH.trim_start_matches("sha256:"));
        validate_materialization_identity(&tail, &materialization)
            .expect("canonical pre-activation identity");

        materialization["status"] = json!("active");
        assert!(validate_materialization_identity(&tail, &materialization).is_err());
        materialization["status"] = json!("materialized_pending_activation");
        assert!(validate_materialization_identity(
            &format!("aszm_{}", "f".repeat(64)),
            &materialization
        )
        .is_err());
    }

    #[test]
    fn storage_tails_reject_aliases_and_path_components() {
        assert!(canonical_tail(&format!("aszm_{}", "a".repeat(64)), "aszm_"));
        assert!(!canonical_tail(
            &format!("ASZM_{}", "a".repeat(64)),
            "aszm_"
        ));
        assert!(!canonical_tail(
            &format!("aszm_{}/escape", "a".repeat(64)),
            "aszm_"
        ));
        assert!(!canonical_tail(
            &format!("aszm_{}", "A".repeat(64)),
            "aszm_"
        ));
    }
}
