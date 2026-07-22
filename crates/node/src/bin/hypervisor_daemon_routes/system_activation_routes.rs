//! Governed M1.5a System initialization and activation owner.
//!
//! These are deliberately two operations with separate scopes, gates, intent families, and replay
//! cursors. The pure compiler is used only for deterministic plan/effect derivation; this module is
//! the authority and transaction boundary.

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
use ioi_types::app::{
    compile_system_activate_plan, compile_system_initialize_plan, ApprovalGrant,
    CompiledSystemLifecyclePlan, SystemLifecycleOperation, UnverifiedCommittedSystemLifecycleStep,
    SYSTEM_ACTIVATION_RECEIPT_CONTRACT, SYSTEM_ACTIVE_PROFILE_SET_CONTRACT, SYSTEM_CHAIN_CONTRACT,
    SYSTEM_DEPLOYMENT_PROFILE_REVISION_CONTRACT, SYSTEM_HOME_DOMAIN_BINDING_CONTRACT,
    SYSTEM_LIFECYCLE_AUTHORITY_DECISION_CONTRACT, SYSTEM_LIFECYCLE_PROPOSAL_CONTRACT,
    SYSTEM_LIFECYCLE_STATE_CONTRACT, SYSTEM_LIFECYCLE_TRANSITION_RECEIPT_CONTRACT,
    SYSTEM_OPERATION_LOG_CONTRACT,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::governed_authority::{
    self as governed, AuthorityContract, AuthorityPolicyContext, AuthorizedDecision, Governance,
};
use super::DaemonState;

type VErr = (String, String);

pub(crate) const INITIALIZE_INTENT_DIR: &str = "autonomous-system-initialize-intents";
pub(crate) const ACTIVATE_INTENT_DIR: &str = "autonomous-system-activate-intents";
pub(crate) const STATE_DIR: &str = "autonomous-system-activation-states";
const DEPLOYMENT_DIR: &str = "autonomous-system-deployment-profile-revisions";
pub(crate) const AUTHORITY_EVIDENCE_DIR: &str = "autonomous-system-lifecycle-authority-evidence";
pub(crate) const AUTHORITY_CONSUMPTION_DIR: &str = "autonomous-system-lifecycle-authority-consumptions";
pub(crate) const PROPOSAL_DIR: &str = "autonomous-system-lifecycle-proposals";
pub(crate) const DECISION_DIR: &str = "autonomous-system-lifecycle-authority-decisions";
pub(crate) const TRANSITION_DIR: &str = "autonomous-system-lifecycle-transitions";
const INITIALIZE_RECEIPT_DIR: &str = "autonomous-system-initialize-transition-receipts";
pub(crate) const ACTIVATION_RECEIPT_DIR: &str = "autonomous-system-activation-receipts";
const ACTIVE_SET_DIR: &str = "autonomous-system-active-profile-sets";
const HOME_BINDING_DIR: &str = "autonomous-system-home-bindings";
pub(crate) const OPERATION_LOG_DIR: &str = "autonomous-system-operation-log-revisions";
pub(crate) const CHAIN_DIR: &str = "autonomous-system-chain-revisions";
pub(crate) const MAX_REQUEST_BYTES: usize = 512 * 1024;

const LIFECYCLE_TRANSITION_CONTRACT: &str = "schema://ioi/foundations/lifecycle-transition/v1";
const LIFECYCLE_PROPOSAL_HASH_PROFILE: &str =
    "ioi.autonomous-system-activation-proposal-jcs-sha256.v1";
const LIFECYCLE_DECISION_HASH_PROFILE: &str =
    "ioi.autonomous-system-activation-authority-decision-jcs-sha256.v1";
const LIFECYCLE_TRANSITION_HASH_PROFILE: &str =
    "ioi.autonomous-system-lifecycle-transition-jcs-sha256.v1";
const LIFECYCLE_RECEIPT_HASH_PROFILE: &str =
    "ioi.lifecycle-transition-receipt-artifact-jcs-sha256.v1";
const ACTIVATION_RECEIPT_HASH_PROFILE: &str =
    "ioi.autonomous-system-activation-receipt-artifact-jcs-sha256.v1";
const DETERMINISTIC_REF_HASH_PROFILE: &str =
    "ioi.autonomous-system-lifecycle-evidence-ref-jcs-sha256.v1";

#[derive(Clone)]
pub(crate) struct NodeAdmissionEvidence {
    authorized: AuthorizedDecision,
    authority_evidence: Value,
    authority_evidence_ref: String,
    authority_evidence_root: String,
    wallet_params: ConsumeApprovalGrantForEffectV2Params,
    wallet_consumption_ref: String,
    wallet_consumption_tail: String,
    wallet_consumption_root: String,
    wallet_consumption_evidence_ref: String,
}

#[derive(Clone)]
struct AdmittedGraph {
    plan: CompiledSystemLifecyclePlan,
    step: UnverifiedCommittedSystemLifecycleStep,
    deployment: Value,
    authority_evidence: Value,
    wallet_consumption: Value,
    active_set: Option<Value>,
    home_binding: Option<Value>,
    operation_log: Option<Value>,
    chain: Option<Value>,
}

pub(crate) static SYSTEM_ACTIVATION_LOCK: Mutex<()> = Mutex::new(());
static SYSTEM_ACTIVATION_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static INITIALIZE_REPLAY_CURSOR: AtomicUsize = AtomicUsize::new(0);
static ACTIVATE_REPLAY_CURSOR: AtomicUsize = AtomicUsize::new(0);

pub(crate) const AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "scope:autonomous_system.lifecycle",
    policy_domain: "hypervisor.system-lifecycle.decision.policy.v1",
    request_domain: "hypervisor.system-lifecycle.decision.request.v1",
    resolution_domain: "hypervisor.system-lifecycle.authority-resolution.v1",
    code_prefix: "system_lifecycle",
    host_label: "system_owner",
    participant_label: "not_applicable",
};

pub(crate) fn verr(code: &str, message: impl Into<String>) -> VErr {
    (code.to_owned(), message.into())
}

pub(crate) fn classify((code, message): VErr) -> (StatusCode, Json<Value>) {
    let status = if code.ends_with("_not_found") {
        StatusCode::NOT_FOUND
    } else if code.contains("authority_required") || code.contains("wallet_consumption_refused") {
        StatusCode::FORBIDDEN
    } else if code.contains("wallet_consumption_unavailable") {
        StatusCode::SERVICE_UNAVAILABLE
    } else if code.contains("conflict") {
        StatusCode::CONFLICT
    } else if code.contains("pending")
        || code.contains("unreadable")
        || code.contains("persist_failed")
        || code.contains("admission_failed")
        || code.contains("evidence_mismatch")
        || code.contains("artifact_mismatch")
        || code.contains("artifact_swapped")
        || matches!(
            code.as_str(),
            "system_lifecycle_artifact_invalid"
                | "system_activate_artifact_invalid"
                | "system_lifecycle_intent_invalid"
                | "system_lifecycle_key_invalid"
                | "system_lifecycle_time_invalid"
                | "system_lifecycle_wallet_consumption_invalid"
        )
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (
        status,
        Json(
            json!({"error":{"code":code,"message":message,"runtimeTruthSource":"daemon-runtime"}}),
        ),
    )
}

pub(crate) fn canonical_system_key(value: &str) -> bool {
    value.strip_prefix("asg_").is_some_and(|tail| {
        tail.len() == 64
            && tail
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    })
}

fn canonical_hash(value: &Value) -> bool {
    value
        .as_str()
        .and_then(|v| v.strip_prefix("sha256:"))
        .is_some_and(|tail| {
            tail.len() == 64
                && tail
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        })
}

pub(crate) fn canonical_hash_str(value: &str) -> bool {
    canonical_hash(&Value::String(value.to_owned()))
}

pub(crate) fn jcs_hash(value: &Value) -> Result<String, VErr> {
    let bytes = serde_jcs::to_vec(value)
        .map_err(|error| verr("system_lifecycle_artifact_invalid", error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn artifact_root(domain: &str, value: &Value) -> Result<String, VErr> {
    jcs_hash(&json!({"domain": domain, "artifact": value}))
}

pub(crate) fn required_string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, VErr> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_invalid",
                format!("missing canonical string at {pointer}"),
            )
        })
}

fn namespace(system_id: &str) -> Result<&str, VErr> {
    system_id
        .strip_prefix("system://")
        .filter(|tail| {
            !tail.is_empty()
                && tail.len() <= 224
                && !tail.chars().any(|character| {
                    character.is_whitespace() || matches!(character, '?' | '#' | '\\')
                })
        })
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_invalid",
                "system_id is not canonical",
            )
        })
}

pub(crate) fn validate_contract(contract: &str, value: &Value, label: &str) -> Result<(), VErr> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        contract, value,
    )
    .map_err(|error| {
        verr(
            "system_lifecycle_artifact_invalid",
            format!("{label} violates {contract} ({error})"),
        )
    })
}

fn hash_bytes(value: &str, label: &str) -> Result<[u8; 32], VErr> {
    let tail = value
        .strip_prefix("sha256:")
        .filter(|tail| {
            tail.len() == 64
                && tail
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        .ok_or_else(|| {
            verr(
                "system_lifecycle_authority_invalid",
                format!("{label} is not a canonical sha256 ref"),
            )
        })?;
    let decoded = hex::decode(tail).map_err(|error| {
        verr(
            "system_lifecycle_authority_invalid",
            format!("{label} cannot be decoded ({error})"),
        )
    })?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

pub(crate) fn ms_to_timestamp(milliseconds: u64) -> Result<String, VErr> {
    let nanos = i128::from(milliseconds) * 1_000_000;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|error| verr("system_lifecycle_time_invalid", error.to_string()))?
        .format(&Rfc3339)
        .map_err(|error| verr("system_lifecycle_time_invalid", error.to_string()))
}

fn deterministic_receipt_ref(
    system_id: &str,
    operation: SystemLifecycleOperation,
) -> Result<String, VErr> {
    let root = jcs_hash(&json!({
        "domain": DETERMINISTIC_REF_HASH_PROFILE,
        "system_id": system_id,
        "sequence": operation.sequence(),
        "kind": if operation == SystemLifecycleOperation::Initialize {
            "lifecycle_transition_receipt"
        } else {
            "autonomous_system_activation_receipt"
        },
    }))?;
    let prefix = if operation == SystemLifecycleOperation::Initialize {
        "ltr_"
    } else {
        "asar_"
    };
    Ok(format!("receipt://{prefix}{}", &root[7..]))
}

fn contains_sensitive_key(value: &Value) -> bool {
    const SENSITIVE: &[&str] = &[
        "secret",
        "password",
        "privatekey",
        "apikey",
        "token",
        "credential",
        "authorization",
        "mnemonic",
        "seed",
    ];
    match value {
        Value::Object(map) => map.iter().any(|(key, child)| {
            let normalized = key
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .flat_map(char::to_lowercase)
                .collect::<String>();
            SENSITIVE.iter().any(|needle| normalized.contains(needle))
                || contains_sensitive_key(child)
        }),
        Value::Array(values) => values.iter().any(contains_sensitive_key),
        _ => false,
    }
}

fn validate_request(operation: SystemLifecycleOperation, body: &Value) -> Result<(), VErr> {
    let encoded = serde_json::to_vec(body)
        .map_err(|e| verr("system_lifecycle_request_invalid", e.to_string()))?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(verr(
            "system_lifecycle_request_oversize",
            "request exceeds the 512 KiB closed-input limit",
        ));
    }
    if contains_sensitive_key(body) {
        return Err(verr(
            "system_lifecycle_sensitive_field_rejected",
            "secret-bearing keys are forbidden recursively",
        ));
    }
    let object = body.as_object().ok_or_else(|| {
        verr(
            "system_lifecycle_request_invalid",
            "request must be one JSON object",
        )
    })?;
    let allowed: &[&str] = match operation {
        SystemLifecycleOperation::Initialize => &[
            "expected_sequence_zero_materialization_root",
            "expected_sequence_zero_materialization_receipt_root",
            "deployment_profile_revision",
            "wallet_approval_grant",
        ],
        SystemLifecycleOperation::Activate => &[
            "expected_initialize_proposal_root",
            "expected_initialize_decision_root",
            "expected_initialize_state_root",
            "expected_initialize_transition_root",
            "expected_initialize_receipt_root",
            "wallet_approval_grant",
        ],
    };
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(verr(
            "system_lifecycle_request_field_unknown",
            format!("undeclared request field '{key}' is forbidden"),
        ));
    }
    let required: &[&str] = match operation {
        SystemLifecycleOperation::Initialize => &[
            "expected_sequence_zero_materialization_root",
            "expected_sequence_zero_materialization_receipt_root",
        ],
        SystemLifecycleOperation::Activate => &[
            "expected_initialize_proposal_root",
            "expected_initialize_decision_root",
            "expected_initialize_state_root",
            "expected_initialize_transition_root",
            "expected_initialize_receipt_root",
        ],
    };
    for field in required {
        if !object.get(*field).is_some_and(canonical_hash) {
            return Err(verr(
                "system_lifecycle_expected_root_invalid",
                format!("{field} must be one canonical sha256 ref"),
            ));
        }
    }
    if operation == SystemLifecycleOperation::Initialize
        && !object
            .get("deployment_profile_revision")
            .is_some_and(Value::is_object)
    {
        return Err(verr(
            "system_lifecycle_deployment_revision_invalid",
            "deployment_profile_revision must be one object",
        ));
    }
    Ok(())
}

fn canonical_grant(authorized: &AuthorizedDecision) -> Result<(ApprovalGrant, String), VErr> {
    let (grant, canonical) = governed::canonicalize_approval_grant(
        &authorized.evidence.wallet_approval_grant,
    )
    .map_err(|error| {
        verr(
            "system_lifecycle_authority_invalid",
            format!("wallet approval grant is malformed ({error})"),
        )
    })?;
    if canonical != authorized.evidence.wallet_approval_grant {
        return Err(verr(
            "system_lifecycle_authority_invalid",
            "wallet approval grant is not its exact canonical typed projection",
        ));
    }
    grant.verify().map_err(|error| {
        verr(
            "system_lifecycle_authority_invalid",
            format!("wallet approval grant signature is invalid ({error})"),
        )
    })?;
    let hash = grant.artifact_hash().map_err(|error| {
        verr(
            "system_lifecycle_authority_invalid",
            format!("wallet approval grant cannot be hashed ({error})"),
        )
    })?;
    Ok((
        grant,
        format!(
            "grant://wallet.network/approval/sha256:{}",
            hex::encode(hash)
        ),
    ))
}

pub(crate) fn prepare_node_evidence(
    plan: &CompiledSystemLifecyclePlan,
    authorized: AuthorizedDecision,
) -> Result<NodeAdmissionEvidence, VErr> {
    if authorized.evidence.authorized_effect != plan.authority_effect {
        return Err(verr(
            "system_lifecycle_authority_invalid",
            "governed authority decision detached the compiled effect",
        ));
    }
    let effect_hash = governed::decision_effect_hash(AUTHORITY, &plan.authority_effect);
    if authorized.evidence.effect_hash != effect_hash {
        return Err(verr(
            "system_lifecycle_authority_invalid",
            "governed authority effect hash differs from the node compiler hash",
        ));
    }
    let canonical_binding = governed::canonicalize_authority_binding(
        &authorized.evidence.authority_binding,
        authorized.resolved_at_ms,
    )
    .map_err(|error| {
        verr(
            "system_lifecycle_authority_invalid",
            format!("principal authority binding is invalid ({error})"),
        )
    })?;
    if canonical_binding != authorized.evidence.authority_binding {
        return Err(verr(
            "system_lifecycle_authority_invalid",
            "principal authority binding is not its exact canonical typed projection",
        ));
    }
    governed::verify_retained_authority_binding_root(&canonical_binding).map_err(|error| {
        verr(
            "system_lifecycle_authority_invalid",
            format!("principal authority binding is not retained-root valid ({error})"),
        )
    })?;
    let (grant, grant_ref) = canonical_grant(&authorized)?;
    let wallet_grant_ref = format!(
        "wallet.network://grant/approval/{}",
        grant_ref
            .strip_prefix("grant://wallet.network/approval/sha256:")
            .ok_or_else(|| {
                verr(
                    "system_lifecycle_authority_invalid",
                    "portable grant identity has an invalid wallet hash coordinate",
                )
            })?
    );
    let system_id = required_string(&plan.authority_effect, "/system_id")?;
    let genesis_ref = required_string(&plan.authority_effect, "/genesis_ref")?;
    let expected_policy_hash = governed::decision_policy_hash_for_context(
        AUTHORITY,
        Governance::Host,
        AuthorityPolicyContext::SystemGenesis {
            system_id,
            genesis_id: genesis_ref,
        },
        &plan.source.source_governing_authority_ref,
        plan.operation.as_str(),
    );
    let expected_request_hash = governed::decision_request_hash(
        AUTHORITY,
        Governance::Host,
        system_id,
        plan.operation.as_str(),
        plan.operation.sequence(),
        &plan.source.source_governing_authority_ref,
        &effect_hash,
    );
    if authorized.evidence.grant_ref != wallet_grant_ref
        || authorized.evidence.policy_hash != expected_policy_hash
        || authorized.evidence.request_hash != expected_request_hash
        || grant.policy_hash != hash_bytes(&expected_policy_hash, "policy_hash")?
        || grant.request_hash != hash_bytes(&expected_request_hash, "request_hash")?
    {
        return Err(verr(
            "system_lifecycle_authority_invalid",
            "grant identity or policy/request commitment differs from the compiled governed decision",
        ));
    }
    if grant.max_usages != Some(1) {
        return Err(verr(
            "system_lifecycle_authority_invalid",
            "lifecycle operations require a distinct single-use wallet grant",
        ));
    }
    let expected_principal_authority: ExpectedPrincipalAuthorityBinding =
        serde_json::from_value(authorized.evidence.authority_binding.clone()).map_err(|error| {
            verr(
                "system_lifecycle_authority_invalid",
                format!("authority binding cannot authorize wallet use ({error})"),
            )
        })?;
    if expected_principal_authority.principal_ref != plan.source.source_governing_authority_ref
        || expected_principal_authority.required_scope != plan.operation.required_scope()
        || expected_principal_authority.approval_authority.authority_id != grant.authority_id
        || expected_principal_authority.approval_authority.public_key != grant.approver_public_key
        || expected_principal_authority
            .approval_authority
            .signature_suite
            != grant.approver_suite
    {
        return Err(verr(
            "system_lifecycle_authority_invalid",
            "grant signer, principal, or exact operation scope differs from the compiled authority",
        ));
    }
    let mut authority_evidence = json!({
        "schema_version": "ioi.hypervisor.system-lifecycle-authority-evidence.v1",
        "authority_evidence_ref": Value::Null,
        "authority_evidence_root": Value::Null,
        "system_id": plan.authority_effect["system_id"],
        "operation": plan.operation.as_str(),
        "sequence": plan.operation.sequence(),
        "required_scope": plan.operation.required_scope(),
        "source_governing_authority_ref": plan.source.source_governing_authority_ref,
        "acting_authority_id": authorized.evidence.acting_authority_id,
        "authority_grant_ref": grant_ref,
        "wallet_authority_grant_ref": wallet_grant_ref,
        "policy_hash": authorized.evidence.policy_hash,
        "request_hash": authorized.evidence.request_hash,
        "effect_hash": authorized.evidence.effect_hash,
        "authorized_effect": authorized.evidence.authorized_effect,
        "wallet_approval_grant": authorized.evidence.wallet_approval_grant,
        "principal_authority_binding": authorized.evidence.authority_binding,
        "authority_resolved_at_ms": authorized.resolved_at_ms,
    });
    let authority_evidence_root = jcs_hash(&json!({
        "domain": "ioi.hypervisor.system-lifecycle-authority-evidence-jcs-sha256.v1",
        "evidence": authority_evidence,
    }))?;
    let authority_evidence_ref = format!(
        "system-lifecycle-authority-evidence://aslae_{}",
        &authority_evidence_root[7..]
    );
    authority_evidence["authority_evidence_ref"] = json!(authority_evidence_ref);
    authority_evidence["authority_evidence_root"] = json!(authority_evidence_root);

    let request_hash = hash_bytes(&authorized.evidence.request_hash, "request_hash")?;
    let grant_hash = grant.artifact_hash().map_err(|error| {
        verr(
            "system_lifecycle_authority_invalid",
            format!("wallet grant cannot be hashed ({error})"),
        )
    })?;
    let consumption_material = json!({
        "domain": "ioi.hypervisor.system-lifecycle.authority-use.v1",
        "system_id": plan.authority_effect["system_id"],
        "operation": plan.operation.as_str(),
        "sequence": plan.operation.sequence(),
        "operation_commitment": plan.authority_effect["operation_commitment"],
        "predecessor_state_root": plan.authority_effect["predecessor_state_root"],
        "resulting_state_root": plan.resulting_state_root,
        "policy_hash": authorized.evidence.policy_hash,
        "request_hash": authorized.evidence.request_hash,
        "effect_hash": authorized.evidence.effect_hash,
        "grant_hash": format!("sha256:{}", hex::encode(grant_hash)),
        "principal_authority": expected_principal_authority,
    });
    let consumption_hash =
        super::outcome_room_routes::record_output_hash(&consumption_material, &[]);
    let consumption_id = hash_bytes(&consumption_hash, "consumption_id")?;
    let wallet_consumption_ref = format!(
        "wallet.network://approval-effect-consumption/{}/{}",
        hex::encode(request_hash),
        hex::encode(consumption_id)
    );
    let wallet_consumption_tail = format!("aslac_{}", hex::encode(consumption_id));
    let wallet_consumption_evidence_ref =
        format!("system-lifecycle-authority-consumption://{wallet_consumption_tail}");
    Ok(NodeAdmissionEvidence {
        authorized,
        authority_evidence,
        authority_evidence_ref,
        authority_evidence_root,
        wallet_params: ConsumeApprovalGrantForEffectV2Params {
            request_hash,
            grant_hash,
            consumption_id,
            expected_principal_authority,
            expected_target_label: plan.operation.required_scope().to_owned(),
            expected_max_usages: 1,
        },
        wallet_consumption_ref,
        wallet_consumption_tail,
        wallet_consumption_root: String::new(),
        wallet_consumption_evidence_ref,
    })
}

pub(crate) fn validate_wallet_receipt(
    evidence: &mut NodeAdmissionEvidence,
    receipt: &ApprovalGrantConsumptionReceipt,
) -> Result<Value, VErr> {
    let (grant, _) = canonical_grant(&evidence.authorized)?;
    let mut receipt_material = serde_json::to_value(receipt).map_err(|error| {
        verr(
            "system_lifecycle_wallet_consumption_invalid",
            error.to_string(),
        )
    })?;
    receipt_material["receipt_hash"] = json!(vec![0u8; 32]);
    let expected_receipt_hash: [u8; 32] =
        Sha256::digest(serde_jcs::to_vec(&receipt_material).map_err(|error| {
            verr(
                "system_lifecycle_wallet_consumption_invalid",
                error.to_string(),
            )
        })?)
        .into();
    if receipt.schema_version != 1
        || receipt.request_hash != evidence.wallet_params.request_hash
        || receipt.grant_hash != evidence.wallet_params.grant_hash
        || receipt.consumption_id != evidence.wallet_params.consumption_id
        || receipt.principal_authority != evidence.wallet_params.expected_principal_authority
        || receipt.receipt_hash != expected_receipt_hash
        || receipt.policy_hash != grant.policy_hash
        || receipt.authority_id != grant.authority_id
        || receipt.target.canonical_label() != evidence.wallet_params.expected_target_label
        || receipt.session_id.is_some()
        || receipt.audience != grant.audience
        || receipt.grant_nonce != grant.nonce
        || receipt.grant_counter != grant.counter
        || receipt.consumed_at_ms > grant.expires_at
        || grant.max_usages != Some(1)
        || receipt.usage_ordinal != 1
        || receipt.remaining_usages != 0
    {
        return Err(verr(
            "system_lifecycle_wallet_consumption_invalid",
            "wallet receipt does not bind the exact grant, principal, scope, one-use ceiling, and durable intent",
        ));
    }
    let value = serde_json::to_value(receipt).map_err(|error| {
        verr(
            "system_lifecycle_wallet_consumption_invalid",
            error.to_string(),
        )
    })?;
    evidence.wallet_consumption_root = artifact_root(
        "ioi.hypervisor.system-lifecycle-authority-consumption-jcs-sha256.v1",
        &value,
    )?;
    Ok(value)
}

pub(crate) fn with_source_locks<T>(f: impl FnOnce() -> T) -> T {
    let _genesis = super::system_genesis_routes::SYSTEM_GENESIS_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _sequence_zero = super::system_sequence_zero_routes::SYSTEM_SEQUENCE_ZERO_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _activation = SYSTEM_ACTIVATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    f()
}

fn map_commit_failure(error: super::durable_fs::CommitFailure) -> VErr {
    use super::durable_fs::CommitFailure;
    match error {
        CommitFailure::KeyInvalid(message) => verr("system_lifecycle_key_invalid", message),
        CommitFailure::NotCommitted(message) => verr("system_lifecycle_persist_failed", message),
        CommitFailure::SlotUnreadable(message) => {
            verr("system_lifecycle_artifact_unreadable", message)
        }
        CommitFailure::Conflict(message) => verr("system_lifecycle_conflict", message),
        CommitFailure::DurabilityUnconfirmed(message) => {
            verr("system_lifecycle_pending_convergence", message)
        }
        CommitFailure::Swapped(message) => verr("system_lifecycle_artifact_swapped", message),
    }
}

pub(crate) fn persist_local(data_dir: &str, family: &str, tail: &str, value: &Value) -> Result<(), VErr> {
    super::durable_fs::persist_receipt_no_clobber(data_dir, family, tail, value)
        .map_err(map_commit_failure)
}

pub(crate) fn forced_fault(variable: &str, value: &str) -> bool {
    std::env::var(variable).ok().as_deref() == Some(value)
}

pub(crate) fn load_local(data_dir: &str, family: &str, tail: &str) -> Result<Option<Value>, VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(verr(
                "system_lifecycle_artifact_unreadable",
                format!("family '{family}' cannot be pinned ({error})"),
            ))
        }
    };
    let name = format!("{tail}.json");
    let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
        Ok(None) => return Ok(None),
        Ok(Some((_file, bytes))) => bytes,
        Err(error) => {
            return Err(verr(
                "system_lifecycle_artifact_unreadable",
                format!("slot '{family}/{name}' cannot be read ({error})"),
            ))
        }
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        verr(
            "system_lifecycle_artifact_unreadable",
            format!("slot '{family}/{name}' is malformed ({error})"),
        )
    })
}

pub(crate) fn load_required_exact(data_dir: &str, family: &str, tail: &str) -> Result<Option<Value>, VErr> {
    let local = load_local(data_dir, family, tail)?;
    match local {
        Some(value) => {
            super::substrate_store::verify_required_exact(data_dir, family, tail, &value).map_err(
                |error| {
                    verr(
                        "system_lifecycle_agentgres_evidence_mismatch",
                        format!("exact proof for '{family}/{tail}' failed ({error})"),
                    )
                },
            )?;
            Ok(Some(value))
        }
        None => match super::substrate_store::read_required_exact(data_dir, family, tail) {
            Ok(None) => Ok(None),
            Ok(Some(_)) => Err(verr(
                "system_lifecycle_agentgres_evidence_mismatch",
                format!("Agentgres contains '{family}/{tail}' while local evidence is absent"),
            )),
            Err(error) => Err(verr(
                "system_lifecycle_agentgres_evidence_mismatch",
                format!("absence proof for '{family}/{tail}' failed ({error})"),
            )),
        },
    }
}

pub(crate) fn recover_wallet_consumption(data_dir: &str, tail: &str) -> Result<Option<Value>, VErr> {
    let local = load_local(data_dir, AUTHORITY_CONSUMPTION_DIR, tail)?;
    let agentgres =
        super::substrate_store::read_required_exact(data_dir, AUTHORITY_CONSUMPTION_DIR, tail)
            .map_err(|error| {
                verr(
                    "system_lifecycle_agentgres_evidence_mismatch",
                    format!("wallet consumption projection failed ({error})"),
                )
            })?;
    resolve_wallet_consumption_evidence(tail, local, agentgres)
}

fn resolve_wallet_consumption_evidence(
    tail: &str,
    local: Option<Value>,
    agentgres: Option<agentgres::mux::ExactProjection>,
) -> Result<Option<Value>, VErr> {
    match (local, agentgres) {
        (None, None) => Ok(None),
        (Some(value), None) => Ok(Some(value)),
        (None, Some(exact)) => validate_remote_wallet_consumption(tail, exact).map(Some),
        (Some(value), Some(exact)) => {
            let remote = validate_remote_wallet_consumption(tail, exact)?;
            if remote != value {
                return Err(verr(
                    "system_lifecycle_agentgres_evidence_mismatch",
                    "wallet consumption local and Agentgres evidence disagree",
                ));
            }
            Ok(Some(value))
        }
    }
}

fn validate_remote_wallet_consumption(
    tail: &str,
    exact: agentgres::mux::ExactProjection,
) -> Result<Value, VErr> {
    let value = super::substrate_store::validate_required_exact_projection(
        AUTHORITY_CONSUMPTION_DIR,
        tail,
        exact,
    )
    .map_err(|error| {
        verr(
            "system_lifecycle_agentgres_evidence_mismatch",
            format!("wallet consumption recovery proof failed ({error})"),
        )
    })?;
    Ok(value)
}

pub(crate) fn tail(prefix: &str, root: &str) -> Result<String, VErr> {
    if !canonical_hash_str(root) {
        return Err(verr(
            "system_lifecycle_artifact_invalid",
            "artifact root is not canonical",
        ));
    }
    Ok(format!("{prefix}{}", &root[7..]))
}

fn intent_family(operation: SystemLifecycleOperation) -> &'static str {
    match operation {
        SystemLifecycleOperation::Initialize => INITIALIZE_INTENT_DIR,
        SystemLifecycleOperation::Activate => ACTIVATE_INTENT_DIR,
    }
}

fn intent_tail(operation: SystemLifecycleOperation, request_hash: &str) -> Result<String, VErr> {
    let prefix = if operation == SystemLifecycleOperation::Initialize {
        "asini_"
    } else {
        "asaci_"
    };
    tail(prefix, request_hash)
}

fn intent_seal(mut intent: Value) -> Result<Value, VErr> {
    intent["intent_hash"] = Value::Null;
    let hash = jcs_hash(&json!({
        "domain": "ioi.hypervisor.system-lifecycle-intent-jcs-sha256.v1",
        "intent": intent,
    }))?;
    intent["intent_hash"] = json!(hash);
    Ok(intent)
}

pub(crate) fn verify_intent_seal(intent: &Value) -> Result<(), VErr> {
    let mut material = intent.clone();
    let stored = material["intent_hash"].clone();
    material["intent_hash"] = Value::Null;
    let expected = jcs_hash(&json!({
        "domain": "ioi.hypervisor.system-lifecycle-intent-jcs-sha256.v1",
        "intent": material,
    }))?;
    if stored != json!(expected) {
        return Err(verr(
            "system_lifecycle_intent_unreadable",
            "intent seal does not match its exact bytes",
        ));
    }
    Ok(())
}

pub(crate) fn verify_intent_coordinates(
    operation: SystemLifecycleOperation,
    stored_tail: &str,
    intent: &Value,
) -> Result<(), VErr> {
    let expected_kind = format!("system_{}", operation.as_str());
    let request_hash = intent
        .pointer("/governed_authority/request_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "system_lifecycle_intent_unreadable",
                "intent lacks its governed request hash",
            )
        })?;
    let expected_tail = intent_tail(operation, request_hash).map_err(|(_, message)| {
        verr(
            "system_lifecycle_intent_unreadable",
            format!("intent request hash cannot derive its storage key ({message})"),
        )
    })?;
    if intent.get("kind").and_then(Value::as_str) != Some(expected_kind.as_str())
        || intent.get("operation").and_then(Value::as_str) != Some(operation.as_str())
        || intent.get("sequence").and_then(Value::as_u64) != Some(operation.sequence())
        || stored_tail != expected_tail
    {
        return Err(verr(
            "system_lifecycle_intent_unreadable",
            "intent kind, operation, sequence, request hash, or storage key is detached",
        ));
    }
    Ok(())
}

pub(crate) fn remove_intent(data_dir: &str, family: &str, tail: &str) -> Result<(), VErr> {
    let directory =
        super::durable_fs::open_family_dir_pinned(data_dir, family).map_err(|error| {
            verr(
                "system_lifecycle_pending_convergence",
                format!("intent family cannot be pinned ({error})"),
            )
        })?;
    match super::durable_fs::unlink_durable_at(&directory, &format!("{tail}.json"), family) {
        Ok(
            super::durable_fs::UnlinkOutcome::Absent | super::durable_fs::UnlinkOutcome::Durable,
        ) => Ok(()),
        Ok(super::durable_fs::UnlinkOutcome::ReplayAnchorRestoredAfterUnconfirmedRemoval(
            error,
        ))
        | Ok(super::durable_fs::UnlinkOutcome::RemovedDurabilityUnconfirmed(error)) => Err(verr(
            "system_lifecycle_pending_convergence",
            format!("intent removal durability is unconfirmed ({error})"),
        )),
        Err(error) => Err(verr(
            "system_lifecycle_pending_convergence",
            format!("intent removal failed ({error})"),
        )),
    }
}

fn compile_initialize(
    data_dir: &str,
    key: &str,
    body: &Value,
) -> Result<CompiledSystemLifecyclePlan, VErr> {
    with_source_locks(|| {
        let source = super::system_sequence_zero_routes::load_current_v2_activation_source_locked(
            data_dir, key,
        )?
        .ok_or_else(|| {
            verr(
                "system_initialize_source_not_found",
                "no current-v2 converged M1.4 source exists",
            )
        })?;
        ensure_no_pending_intent(data_dir, key)?;
        refuse_existing_sequence(
            data_dir,
            required_string(&source.materialization, "/system_id")?,
            1,
        )?;
        let materialization_root = artifact_root(
            "ioi.autonomous-system-sequence-zero-materialization-artifact-jcs-sha256.v1",
            &source.materialization,
        )?;
        let materialization_receipt_root = artifact_root(
            "ioi.autonomous-system-sequence-zero-materialization-receipt-artifact-jcs-sha256.v1",
            &source.materialization_receipt,
        )?;
        if body.get("expected_sequence_zero_materialization_root")
            != Some(&json!(materialization_root))
            || body.get("expected_sequence_zero_materialization_receipt_root")
                != Some(&json!(materialization_receipt_root))
        {
            return Err(verr(
                "system_initialize_source_conflict",
                "expected M1.4 roots do not match the verified source",
            ));
        }
        compile_system_initialize_plan(&source, &body["deployment_profile_revision"])
            .map_err(|e| verr("system_initialize_plan_invalid", e))
    })
}

fn load_initialized_step(
    data_dir: &str,
    body: &Value,
) -> Result<(UnverifiedCommittedSystemLifecycleStep, Value), VErr> {
    let proposal_root = required_string(body, "/expected_initialize_proposal_root")?.to_owned();
    let decision_root = required_string(body, "/expected_initialize_decision_root")?.to_owned();
    let state_root = required_string(body, "/expected_initialize_state_root")?.to_owned();
    let transition_root = required_string(body, "/expected_initialize_transition_root")?.to_owned();
    let receipt_root = required_string(body, "/expected_initialize_receipt_root")?.to_owned();
    let proposal = load_required_exact(data_dir, PROPOSAL_DIR, &tail("aslp_", &proposal_root)?)?
        .ok_or_else(|| {
            verr(
                "system_activate_initialize_not_found",
                "initialized proposal is absent",
            )
        })?;
    let decision = load_required_exact(data_dir, DECISION_DIR, &tail("aslad_", &decision_root)?)?
        .ok_or_else(|| {
        verr(
            "system_activate_initialize_not_found",
            "initialized decision is absent",
        )
    })?;
    let state = load_required_exact(data_dir, STATE_DIR, &tail("asls_", &state_root)?)?
        .ok_or_else(|| {
            verr(
                "system_activate_initialize_not_found",
                "initialized state is absent",
            )
        })?;
    let transition =
        load_required_exact(data_dir, TRANSITION_DIR, &tail("aslt_", &transition_root)?)?
            .ok_or_else(|| {
                verr(
                    "system_activate_initialize_not_found",
                    "initialized transition is absent",
                )
            })?;
    let receipt = load_required_exact(
        data_dir,
        INITIALIZE_RECEIPT_DIR,
        &tail("asltr_", &receipt_root)?,
    )?
    .ok_or_else(|| {
        verr(
            "system_activate_initialize_not_found",
            "initialized receipt is absent",
        )
    })?;
    for (contract, value, label) in [
        (SYSTEM_LIFECYCLE_PROPOSAL_CONTRACT, &proposal, "proposal"),
        (
            SYSTEM_LIFECYCLE_AUTHORITY_DECISION_CONTRACT,
            &decision,
            "decision",
        ),
        (SYSTEM_LIFECYCLE_STATE_CONTRACT, &state, "state"),
        (LIFECYCLE_TRANSITION_CONTRACT, &transition, "transition"),
        (
            SYSTEM_LIFECYCLE_TRANSITION_RECEIPT_CONTRACT,
            &receipt,
            "receipt",
        ),
    ] {
        validate_contract(contract, value, label)?;
    }
    if proposal.get("proposal_root") != Some(&json!(proposal_root))
        || decision.get("decision_root") != Some(&json!(decision_root))
        || state.get("activation_state_root") != Some(&json!(state_root))
        || artifact_root(LIFECYCLE_TRANSITION_HASH_PROFILE, &transition)? != transition_root
        || artifact_root(LIFECYCLE_RECEIPT_HASH_PROFILE, &receipt)? != receipt_root
    {
        return Err(verr(
            "system_activate_initialize_detached",
            "initialized tuple has a detached embedded identity or artifact root",
        ));
    }
    let deployment_root = required_string(&receipt, "/bound_facts/deployment_profile_root")?;
    let deployment =
        load_required_exact(data_dir, DEPLOYMENT_DIR, &tail("asdpr_", deployment_root)?)?
            .ok_or_else(|| {
                verr(
                    "system_activate_initialize_not_found",
                    "initialized deployment revision is absent",
                )
            })?;
    validate_contract(
        SYSTEM_DEPLOYMENT_PROFILE_REVISION_CONTRACT,
        &deployment,
        "deployment revision",
    )?;
    if deployment.get("deployment_profile_root") != Some(&json!(deployment_root)) {
        return Err(verr(
            "system_activate_initialize_detached",
            "persisted deployment revision root is detached",
        ));
    }
    Ok((
        UnverifiedCommittedSystemLifecycleStep {
            proposal,
            decision,
            state,
            transition,
            receipt,
            state_root,
            proposal_root,
            decision_root,
            transition_root,
            receipt_root,
        },
        deployment,
    ))
}

fn compile_activate(
    data_dir: &str,
    key: &str,
    body: &Value,
) -> Result<CompiledSystemLifecyclePlan, VErr> {
    with_source_locks(|| {
        let source = super::system_sequence_zero_routes::load_current_v2_activation_source_locked(
            data_dir, key,
        )?
        .ok_or_else(|| {
            verr(
                "system_activate_source_not_found",
                "no current-v2 converged M1.4 source exists",
            )
        })?;
        ensure_no_pending_intent(data_dir, key)?;
        refuse_existing_sequence(
            data_dir,
            required_string(&source.materialization, "/system_id")?,
            2,
        )?;
        let (initialized, deployment) = load_initialized_step(data_dir, body)?;
        if initialized.state.get("system_id") != source.materialization.get("system_id") {
            return Err(verr(
                "system_activate_initialize_detached",
                "initialized tuple belongs to another System",
            ));
        }
        compile_system_activate_plan(&source, &deployment, &initialized)
            .map_err(|error| verr("system_activate_plan_invalid", error))
    })
}

fn revalidate_and_persist_intent(
    data_dir: &str,
    key: &str,
    body: &Value,
    plan: &CompiledSystemLifecyclePlan,
    evidence: &NodeAdmissionEvidence,
    intent_tail: &str,
) -> Result<Value, VErr> {
    with_source_locks(|| {
        let source = super::system_sequence_zero_routes::load_current_v2_activation_source_locked(
            data_dir, key,
        )?
        .ok_or_else(|| {
            verr(
                "system_lifecycle_source_not_found",
                "M1.4 source vanished before intent sealing",
            )
        })?;
        let rebuilt = match plan.operation {
            SystemLifecycleOperation::Initialize => {
                let materialization_root = artifact_root(
                    "ioi.autonomous-system-sequence-zero-materialization-artifact-jcs-sha256.v1",
                    &source.materialization,
                )?;
                let receipt_root = artifact_root(
                    "ioi.autonomous-system-sequence-zero-materialization-receipt-artifact-jcs-sha256.v1",
                    &source.materialization_receipt,
                )?;
                if body.get("expected_sequence_zero_materialization_root")
                    != Some(&json!(materialization_root))
                    || body.get("expected_sequence_zero_materialization_receipt_root")
                        != Some(&json!(receipt_root))
                {
                    return Err(verr(
                        "system_initialize_source_conflict",
                        "M1.4 roots changed before intent sealing",
                    ));
                }
                compile_system_initialize_plan(&source, &body["deployment_profile_revision"])
            }
            SystemLifecycleOperation::Activate => {
                let (initialized, deployment) = load_initialized_step(data_dir, body)?;
                compile_system_activate_plan(&source, &deployment, &initialized)
            }
        }
        .map_err(|error| verr("system_lifecycle_plan_invalid", error))?;
        if rebuilt != *plan {
            return Err(verr(
                "system_lifecycle_source_conflict",
                "source bytes or compiled plan changed before intent sealing",
            ));
        }
        let intent = build_intent(key, plan.operation, body, plan, evidence)?;
        persist_local(
            data_dir,
            intent_family(plan.operation),
            intent_tail,
            &intent,
        )?;
        Ok(intent)
    })
}

fn build_admitted_step(
    plan: &CompiledSystemLifecyclePlan,
    evidence: &NodeAdmissionEvidence,
    wallet_consumption: Value,
    timestamp: &str,
) -> Result<AdmittedGraph, VErr> {
    let reconstructed = match plan.operation {
        SystemLifecycleOperation::Initialize => {
            compile_system_initialize_plan(&plan.source, &plan.deployment_profile_revision)
        }
        SystemLifecycleOperation::Activate => compile_system_activate_plan(
            &plan.source,
            &plan.deployment_profile_revision,
            plan.previous_step.as_ref().ok_or_else(|| {
                verr(
                    "system_activate_initialize_not_found",
                    "activation plan lacks the initialized predecessor",
                )
            })?,
        ),
    }
    .map_err(|error| verr("system_lifecycle_plan_invalid", error))?;
    if reconstructed != *plan {
        return Err(verr(
            "system_lifecycle_plan_invalid",
            "compiled plan changed between preflight and admitted construction",
        ));
    }
    let effect = &plan.authority_effect;
    let system_id = required_string(effect, "/system_id")?;
    let genesis_ref = required_string(effect, "/genesis_ref")?;
    let operation_commitment = required_string(effect, "/operation_commitment")?;
    let grant_ref = required_string(&evidence.authority_evidence, "/authority_grant_ref")?;
    let proposal_ref = format!(
        "proposal://{}/lifecycle/sequence/{}",
        namespace(system_id)?,
        plan.operation.sequence()
    );
    let proposal_material = json!({
        "domain": LIFECYCLE_PROPOSAL_HASH_PROFILE,
        "proposal_ref": proposal_ref,
        "system_id": system_id,
        "genesis_ref": genesis_ref,
        "operation": plan.operation.as_str(),
        "sequence": plan.operation.sequence(),
        "required_scope": plan.operation.required_scope(),
        "operation_commitment": operation_commitment,
        "authority_effect": effect,
        "authority_effect_hash": evidence.authorized.evidence.effect_hash,
        "status": "proposed",
        "created_at": timestamp,
    });
    let proposal_root = jcs_hash(&proposal_material)?;
    let mut proposal = proposal_material;
    proposal.as_object_mut().expect("object").remove("domain");
    proposal["schema_version"] = json!("ioi.autonomous-system-activation-proposal.v1");
    proposal["proposal_root"] = json!(proposal_root);
    validate_contract(
        SYSTEM_LIFECYCLE_PROPOSAL_CONTRACT,
        &proposal,
        "lifecycle proposal",
    )?;

    let decision_ref = format!(
        "decision://{}/lifecycle/sequence/{}",
        namespace(system_id)?,
        plan.operation.sequence()
    );
    let decision_material = json!({
        "domain": LIFECYCLE_DECISION_HASH_PROFILE,
        "decision_ref": decision_ref,
        "proposal_ref": proposal_ref,
        "proposal_root": proposal_root,
        "system_id": system_id,
        "genesis_ref": genesis_ref,
        "operation": plan.operation.as_str(),
        "sequence": plan.operation.sequence(),
        "required_scope": plan.operation.required_scope(),
        "operation_commitment": operation_commitment,
        "input_hash": evidence.authorized.evidence.request_hash,
        "policy_hash": evidence.authorized.evidence.policy_hash,
        "effect_hash": evidence.authorized.evidence.effect_hash,
        "authority_grant_ref": grant_ref,
        "authority_evidence_ref": evidence.authority_evidence_ref,
        "authority_evidence_root": evidence.authority_evidence_root,
        "wallet_grant_consumption_ref": evidence.wallet_consumption_ref,
        "wallet_grant_consumption_root": evidence.wallet_consumption_root,
        "wallet_grant_consumption_evidence_ref": evidence.wallet_consumption_evidence_ref,
        "outcome": "admitted",
        "decided_at": timestamp,
    });
    let decision_root = jcs_hash(&decision_material)?;
    let mut decision = decision_material;
    decision.as_object_mut().expect("object").remove("domain");
    decision["schema_version"] = json!("ioi.autonomous-system-activation-authority-decision.v1");
    decision["decision_root"] = json!(decision_root);
    validate_contract(
        SYSTEM_LIFECYCLE_AUTHORITY_DECISION_CONTRACT,
        &decision,
        "lifecycle authority decision",
    )?;

    let receipt_ref = deterministic_receipt_ref(system_id, plan.operation)?;
    let transition_ref = format!(
        "lifecycle-transition://{}/sequence/{}",
        namespace(system_id)?,
        plan.operation.sequence()
    );
    let previous_state = if plan.operation == SystemLifecycleOperation::Initialize {
        "draft"
    } else {
        "initialized"
    };
    let proposed_state = if plan.operation == SystemLifecycleOperation::Initialize {
        "initialized"
    } else {
        "active"
    };
    let mut triggers = vec![effect["sequence_zero_receipt_ref"].clone()];
    if let Some(previous) = &plan.previous_step {
        triggers.push(previous.receipt["receipt_ref"].clone());
    }
    let transition = json!({
        "schema_version": "ioi.lifecycle-transition.v1",
        "lifecycle_transition_id": transition_ref,
        "system_id": system_id,
        "resulting_or_related_system_id": Value::Null,
        "lifecycle_profile_ref": effect["lifecycle_profile_ref"],
        "transition_kind": plan.operation.as_str(),
        "genesis_ref": genesis_ref,
        "manifest_ref": effect["manifest_ref"],
        "admitted_manifest_root": effect["admitted_manifest_root"],
        "previous_state": previous_state,
        "proposed_state": proposed_state,
        "trigger_evidence_refs": triggers,
        "oracle_evidence_profile_refs": plan.source.genesis_admission_record.pointer("/authorized_genesis/initial_profile_refs/oracle_evidence_profile_refs").cloned().unwrap_or_else(|| json!([])),
        "proposal_ref": proposal_ref,
        "decision_ref": decision_ref,
        "authority_grant_refs": [grant_ref],
        "challenge_opened_at": Value::Null,
        "challenge_closes_at": Value::Null,
        "predecessor_state_root": effect["predecessor_state_root"],
        "resulting_state_root": plan.resulting_state_root,
        "operation_commitment": operation_commitment,
        "state_transition_commitment_ref": Value::Null,
        "lineage_ref": Value::Null,
        "identity_continuity_decision_ref": Value::Null,
        "disposition_receipt_refs": [],
        "receipt_refs": [receipt_ref],
        "public_commitment_ref": Value::Null,
        "status": "committed",
    });
    validate_contract(
        LIFECYCLE_TRANSITION_CONTRACT,
        &transition,
        "lifecycle transition",
    )?;
    let transition_root = artifact_root(LIFECYCLE_TRANSITION_HASH_PROFILE, &transition)?;

    let mut boundary = vec![
        system_id.to_owned(),
        genesis_ref.to_owned(),
        required_string(effect, "/genesis_admission_receipt_ref")?.to_owned(),
        required_string(effect, "/sequence_zero_materialization_id")?.to_owned(),
        required_string(effect, "/sequence_zero_receipt_ref")?.to_owned(),
        required_string(effect, "/component_registry_ref")?.to_owned(),
        required_string(effect, "/deployment_profile_ref")?.to_owned(),
        required_string(effect, "/materialization_wallet_consumption_ref")?.to_owned(),
        required_string(effect, "/home_domain_ref")?.to_owned(),
        required_string(effect, "/source_governing_authority_ref")?.to_owned(),
        required_string(effect, "/upgrade_policy_ref")?.to_owned(),
        proposal_ref.clone(),
        decision_ref.clone(),
        transition_ref.clone(),
        required_string(effect, "/resulting_state_ref")?.to_owned(),
        evidence.authority_evidence_ref.clone(),
        evidence.wallet_consumption_ref.clone(),
        evidence.wallet_consumption_evidence_ref.clone(),
        grant_ref.to_owned(),
    ];
    for field in [
        "active_profile_set_ref",
        "chain_ref",
        "home_domain_binding_ref",
    ] {
        if let Some(value) = effect.get(field).and_then(Value::as_str) {
            boundary.push(value.to_owned());
        }
    }
    boundary.sort();
    boundary.dedup();
    let bound_facts = json!({
        "system_id": system_id,
        "operation": plan.operation.as_str(),
        "sequence": plan.operation.sequence(),
        "required_scope": plan.operation.required_scope(),
        "authority_effect_hash": evidence.authorized.evidence.effect_hash,
        "genesis_ref": genesis_ref,
        "genesis_admission_record_root": effect["genesis_admission_record_root"],
        "genesis_admission_receipt_ref": effect["genesis_admission_receipt_ref"],
        "genesis_admission_receipt_root": effect["genesis_admission_receipt_root"],
        "sequence_zero_materialization_id": effect["sequence_zero_materialization_id"],
        "sequence_zero_materialization_root": effect["sequence_zero_materialization_root"],
        "sequence_zero_receipt_ref": effect["sequence_zero_receipt_ref"],
        "sequence_zero_receipt_root": effect["sequence_zero_receipt_root"],
        "sequence_zero_receipt_artifact_root": effect["sequence_zero_receipt_artifact_root"],
        "source_governing_authority_ref": effect["source_governing_authority_ref"],
        "home_domain_ref": effect["home_domain_ref"],
        "home_domain_commitment": effect["home_domain_commitment"],
        "home_domain_binding_ref": effect["home_domain_binding_ref"],
        "home_domain_binding_root": effect["home_domain_binding_root"],
        "component_registry_ref": effect["component_registry_ref"],
        "component_registry_root": effect["component_registry_root"],
        "materialization_wallet_consumption_ref": effect["materialization_wallet_consumption_ref"],
        "materialization_wallet_consumption_root": effect["materialization_wallet_consumption_root"],
        "deployment_profile_ref": effect["deployment_profile_ref"],
        "deployment_profile_root": effect["deployment_profile_root"],
        "profile_bundle_root": effect["profile_bundle_root"],
        "policy_root": effect["policy_root"],
        "module_registry_root": effect["module_registry_root"],
        "upgrade_policy_ref": effect["upgrade_policy_ref"],
        "operation_commitment": operation_commitment,
        "proposal_ref": proposal_ref,
        "proposal_root": proposal_root,
        "decision_ref": decision_ref,
        "decision_root": decision_root,
        "transition_ref": transition_ref,
        "transition_root": transition_root,
        "predecessor_state_root": effect["predecessor_state_root"],
        "resulting_state_ref": effect["resulting_state_ref"],
        "resulting_state_root": effect["resulting_state_root"],
        "active_profile_set_ref": effect["active_profile_set_ref"],
        "active_profile_set_root": effect["active_profile_set_root"],
        "chain_ref": effect["chain_ref"],
        "live_chain_created": plan.operation == SystemLifecycleOperation::Activate,
    });
    let is_initialize = plan.operation == SystemLifecycleOperation::Initialize;
    let receipt = json!({
        "schema_version": if is_initialize { "ioi.lifecycle-transition-receipt.v1" } else { "ioi.autonomous-system-activation-receipt.v1" },
        "receipt_id": receipt_ref,
        "receipt_ref": receipt_ref,
        "receipt_type": if is_initialize { "lifecycle_transition" } else { "autonomous_system_activation" },
        "receipt_profile_ref": if is_initialize { SYSTEM_LIFECYCLE_TRANSITION_RECEIPT_CONTRACT } else { SYSTEM_ACTIVATION_RECEIPT_CONTRACT },
        "actor_id": "runtime://hypervisor-runtime",
        "subject_ref": transition_ref,
        "op": plan.operation.as_str(),
        "sequence": plan.operation.sequence(),
        "attested_boundary_fact_refs": boundary,
        "bound_facts": bound_facts,
        "input_hash": evidence.authorized.evidence.request_hash,
        "output_hash": plan.resulting_state_root,
        "policy_hash": evidence.authorized.evidence.policy_hash,
        "effect_hash": evidence.authorized.evidence.effect_hash,
        "authority_grant_id": grant_ref,
        "required_scope": plan.operation.required_scope(),
        "authority_scopes": [plan.operation.required_scope()],
        "authority_evidence_ref": evidence.authority_evidence_ref,
        "authority_evidence_root": evidence.authority_evidence_root,
        "wallet_grant_consumption_ref": evidence.wallet_consumption_ref,
        "wallet_grant_consumption_root": evidence.wallet_consumption_root,
        "wallet_grant_consumption_evidence_ref": evidence.wallet_consumption_evidence_ref,
        "primitive_capabilities": [], "artifact_refs": [], "evidence_bundle_refs": [],
        "verification_ref": Value::Null, "acceptance_ref": Value::Null,
        "claim_scope_ref": Value::Null, "run_id": Value::Null, "task_id": Value::Null,
        "adjudication_ref": Value::Null, "settlement_ref": Value::Null,
        "signature": Value::Null, "public_commitment_ref": Value::Null,
        "assurance_posture": if is_initialize { "initialized_not_active" } else { "active_chain_created" },
        "assurance_note": if is_initialize { "sequence one initialized; no live chain, membership, runtime, or network effect exists" } else { "sequence two admitted constitutional and logical continuity; no membership, runtime, or network effect exists" },
        "timestamp": timestamp, "outcome": "ok", "at": timestamp,
    });
    let receipt_contract = if is_initialize {
        SYSTEM_LIFECYCLE_TRANSITION_RECEIPT_CONTRACT
    } else {
        SYSTEM_ACTIVATION_RECEIPT_CONTRACT
    };
    validate_contract(receipt_contract, &receipt, "lifecycle receipt")?;
    let receipt_root = artifact_root(
        if is_initialize {
            LIFECYCLE_RECEIPT_HASH_PROFILE
        } else {
            ACTIVATION_RECEIPT_HASH_PROFILE
        },
        &receipt,
    )?;
    let mut state = plan.semantic_state.clone();
    state["transition_ref"] = json!(transition_ref);
    state["transition_root"] = json!(transition_root);
    state["transition_receipt_ref"] = json!(receipt_ref);
    state["transition_receipt_root"] = json!(receipt_root);
    state["created_at"] = json!(timestamp);
    validate_contract(SYSTEM_LIFECYCLE_STATE_CONTRACT, &state, "lifecycle state")?;
    let step = UnverifiedCommittedSystemLifecycleStep {
        proposal,
        decision,
        state,
        transition,
        receipt,
        state_root: plan.resulting_state_root.clone(),
        proposal_root,
        decision_root,
        transition_root,
        receipt_root,
    };
    let active_set = plan.semantic_active_profile_set.clone().map(|mut value| {
        value["activation_transition_ref"] = step.transition["lifecycle_transition_id"].clone();
        value["activation_receipt_ref"] = step.receipt["receipt_ref"].clone();
        value["created_at"] = json!(timestamp);
        value
    });
    if let Some(value) = &active_set {
        validate_contract(
            SYSTEM_ACTIVE_PROFILE_SET_CONTRACT,
            value,
            "active profile set",
        )?;
    }
    let home_binding = plan.semantic_home_domain_binding.clone().map(|mut value| {
        value["created_at"] = json!(timestamp);
        value
    });
    if let Some(value) = &home_binding {
        validate_contract(SYSTEM_HOME_DOMAIN_BINDING_CONTRACT, value, "home binding")?;
    }
    Ok(AdmittedGraph {
        plan: plan.clone(),
        step,
        deployment: plan.deployment_profile_revision.clone(),
        authority_evidence: evidence.authority_evidence.clone(),
        wallet_consumption,
        active_set,
        home_binding,
        operation_log: None,
        chain: None,
    })
}

fn lifecycle_log_entry(
    plan: &CompiledSystemLifecyclePlan,
    step: &UnverifiedCommittedSystemLifecycleStep,
    committed_at: &str,
) -> Result<Value, VErr> {
    let effect = &plan.authority_effect;
    let active = plan.operation == SystemLifecycleOperation::Activate;
    Ok(json!({
        "sequence": plan.operation.sequence(),
        "entry_kind": if active { "system_activation" } else { "system_initialization" },
        "operation_name": plan.operation.as_str(),
        "operation_owner_profile_ref": LIFECYCLE_TRANSITION_CONTRACT,
        "operation_owner_ref": step.transition["lifecycle_transition_id"],
        "operation_owner_root": step.transition_root,
        "required_scope": plan.operation.required_scope(),
        "materialization_ref": Value::Null, "materialization_root": Value::Null,
        "deployment_profile_ref": effect["deployment_profile_ref"],
        "deployment_profile_root": effect["deployment_profile_root"],
        "operation_commitment": effect["operation_commitment"],
        "proposal_ref": step.proposal["proposal_ref"], "proposal_root": step.proposal_root,
        "decision_ref": step.decision["decision_ref"], "decision_root": step.decision_root,
        "transition_ref": step.transition["lifecycle_transition_id"], "transition_root": step.transition_root,
        "state_transition_commitment_ref": Value::Null,
        "state_ref": step.state["activation_state_ref"], "state_root": step.state_root,
        "predecessor_state_root": step.transition["predecessor_state_root"],
        "receipt_profile_ref": if active { SYSTEM_ACTIVATION_RECEIPT_CONTRACT } else { SYSTEM_LIFECYCLE_TRANSITION_RECEIPT_CONTRACT },
        "receipt_ref": step.receipt["receipt_ref"], "receipt_root": step.receipt_root,
        "receipt_artifact_root": step.receipt_root,
        "component_registry_ref": effect["component_registry_ref"],
        "component_registry_root": effect["component_registry_root"],
        "active_profile_set_ref": if active { effect["active_profile_set_ref"].clone() } else { Value::Null },
        "active_profile_set_root": if active { effect["active_profile_set_root"].clone() } else { Value::Null },
        "chain_ref": if active { effect["chain_ref"].clone() } else { Value::Null },
        "authority_evidence_ref": step.decision["authority_evidence_ref"],
        "authority_evidence_root": step.decision["authority_evidence_root"],
        "wallet_consumption_ref": step.decision["wallet_grant_consumption_ref"],
        "wallet_consumption_root": step.decision["wallet_grant_consumption_root"],
        "live_chain_created": active, "committed_at": committed_at,
    }))
}

fn complete_live_graph(graph: &mut AdmittedGraph, timestamp: &str) -> Result<(), VErr> {
    if graph.plan.operation == SystemLifecycleOperation::Initialize {
        return Ok(());
    }
    let effect = &graph.plan.authority_effect;
    let previous = graph.plan.previous_step.as_ref().ok_or_else(|| {
        verr(
            "system_activate_initialize_not_found",
            "activation lacks initialized predecessor",
        )
    })?;
    let active_set = graph.active_set.as_ref().ok_or_else(|| {
        verr(
            "system_activate_artifact_invalid",
            "activation lacks active profile set",
        )
    })?;
    let binding = graph.home_binding.as_ref().ok_or_else(|| {
        verr(
            "system_activate_artifact_invalid",
            "activation lacks home binding",
        )
    })?;
    let sequence_zero = json!({
        "sequence": 0, "entry_kind": "sequence_zero_materialization",
        "operation_name": "materialize_sequence_zero",
        "operation_owner_profile_ref": "schema://ioi/foundations/autonomous-system-sequence-zero-materialization/v1",
        "operation_owner_ref": effect["sequence_zero_materialization_id"],
        "operation_owner_root": effect["sequence_zero_materialization_root"],
        "required_scope": "scope:autonomous_system.genesis_materialize",
        "materialization_ref": effect["sequence_zero_materialization_id"],
        "materialization_root": effect["sequence_zero_materialization_root"],
        "deployment_profile_ref": effect["deployment_profile_ref"], "deployment_profile_root": effect["deployment_profile_root"],
        "operation_commitment": graph.plan.source.materialization["operation_commitment"],
        "proposal_ref": Value::Null, "proposal_root": Value::Null,
        "decision_ref": Value::Null, "decision_root": Value::Null,
        "transition_ref": Value::Null, "transition_root": Value::Null,
        "state_transition_commitment_ref": Value::Null, "state_ref": Value::Null,
        "state_root": graph.plan.source.materialization["initial_state_root"],
        "predecessor_state_root": Value::Null,
        "receipt_profile_ref": "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
        "receipt_ref": effect["sequence_zero_receipt_ref"], "receipt_root": effect["sequence_zero_receipt_root"],
        "receipt_artifact_root": effect["sequence_zero_receipt_artifact_root"],
        "component_registry_ref": effect["component_registry_ref"], "component_registry_root": effect["component_registry_root"],
        "active_profile_set_ref": Value::Null, "active_profile_set_root": Value::Null,
        "chain_ref": Value::Null, "authority_evidence_ref": Value::Null, "authority_evidence_root": Value::Null,
        "wallet_consumption_ref": effect["materialization_wallet_consumption_ref"],
        "wallet_consumption_root": effect["materialization_wallet_consumption_root"],
        "live_chain_created": false,
        "committed_at": graph.plan.source.materialization["created_at"],
    });
    let initialize_plan = compile_system_initialize_plan(&graph.plan.source, &graph.deployment)
        .map_err(|error| verr("system_activate_plan_invalid", error))?;
    let sequence_one = lifecycle_log_entry(
        &initialize_plan,
        previous,
        required_string(&previous.decision, "/decided_at")?,
    )?;
    let sequence_two = lifecycle_log_entry(&graph.plan, &graph.step, timestamp)?;
    let mut log = json!({
        "schema_version": "ioi.autonomous-system-operation-log.v1",
        "operation_log_ref": Value::Null, "operation_log_root": Value::Null,
        "predecessor_operation_log_ref": Value::Null, "predecessor_operation_log_root": Value::Null,
        "snapshot_kind": "activation_prefix", "system_id": effect["system_id"], "genesis_ref": effect["genesis_ref"],
        "home_domain_ref": effect["home_domain_ref"], "home_domain_commitment": effect["home_domain_commitment"],
        "home_domain_binding_ref": binding["home_domain_binding_ref"], "home_domain_binding_root": binding["home_domain_binding_root"],
        "policy_root": effect["policy_root"], "module_registry_root": effect["module_registry_root"], "upgrade_policy_ref": effect["upgrade_policy_ref"],
        "activation_prefix": {"sequence_zero": sequence_zero, "sequence_one": sequence_one, "sequence_two": sequence_two},
        "entries": [sequence_zero, sequence_one, sequence_two], "head_entry": sequence_two,
        "latest_sequence": 2, "latest_operation_commitment": effect["operation_commitment"],
        "latest_transition_commitment_ref": Value::Null,
        "latest_transition_ref": graph.step.transition["lifecycle_transition_id"], "latest_transition_root": graph.step.transition_root,
        "latest_receipt_ref": graph.step.receipt["receipt_ref"], "latest_receipt_root": graph.step.receipt_root,
        "latest_state_ref": graph.step.state["activation_state_ref"], "latest_state_root": graph.step.state_root,
        "status": "committed", "created_at": timestamp,
    });
    let mut log_material = log.as_object().cloned().expect("object");
    log_material.remove("schema_version");
    log_material.remove("operation_log_ref");
    log_material.remove("operation_log_root");
    log_material.insert(
        "domain".to_owned(),
        json!("ioi.autonomous-system-operation-log-jcs-sha256.v1"),
    );
    let log_root = jcs_hash(&Value::Object(log_material))?;
    log["operation_log_ref"] = json!(format!(
        "agentgres://operation-log/autonomous-system/{}/revision/{log_root}",
        namespace(required_string(effect, "/system_id")?)?
    ));
    log["operation_log_root"] = json!(log_root);
    validate_contract(SYSTEM_OPERATION_LOG_CONTRACT, &log, "operation log")?;

    let active = |pointer: &str| required_string(active_set, pointer);
    let oracle_refs = active_set
        .get("oracle_evidence_profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "system_activate_artifact_invalid",
                "oracle profiles are not an array",
            )
        })?
        .iter()
        .map(|value| required_string(value, "/candidate_profile_ref").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let network_ref = active_set
        .get("network_enrollment")
        .filter(|value| !value.is_null())
        .map(|value| required_string(value, "/candidate_profile_ref").map(str::to_owned))
        .transpose()?;
    let membership_root = jcs_hash(
        &json!({"domain":"ioi.autonomous-system-node-membership-root-jcs-sha256.v1","node_membership_refs":[]}),
    )?;
    let proposal_queue_root = jcs_hash(
        &json!({"domain":"ioi.autonomous-system-proposal-queue-root-jcs-sha256.v1","pending_proposal_refs":[]}),
    )?;
    let mut chain = json!({
        "schema_version":"ioi.autonomous-system-chain.v1", "chain_ref":effect["chain_ref"], "chain_root":Value::Null,
        "system_id":effect["system_id"], "home_domain_ref":effect["home_domain_ref"],
        "home_domain_binding_ref":binding["home_domain_binding_ref"], "home_domain_binding_root":binding["home_domain_binding_root"],
        "governance_owner_refs":graph.plan.source.genesis_admission_record.pointer("/initial_profile_bundle/constitution/governance/governance_owner_refs").cloned().unwrap_or_else(|| json!([])),
        "genesis_ref":effect["genesis_ref"], "genesis_admission_record_root":effect["genesis_admission_record_root"],
        "package_id":effect["package_id"], "manifest_ref":effect["manifest_ref"], "admitted_manifest_root":effect["admitted_manifest_root"],
        "constitution_ref":active("/constitution/candidate_profile_ref")?, "constitution_root":active("/constitution/candidate_profile_root")?,
        "deployment_profile_ref":active("/deployment/candidate_profile_ref")?, "deployment_profile_root":active("/deployment/candidate_profile_root")?,
        "ordering_admission_finality_profile_ref":active("/ordering_admission_finality/candidate_profile_ref")?,
        "oracle_evidence_profile_refs":oracle_refs, "lifecycle_continuity_profile_ref":active("/lifecycle_continuity/candidate_profile_ref")?,
        "network_enrollment_ref":network_ref, "active_profile_set_ref":active("/active_profile_set_ref")?, "active_profile_set_root":active("/active_profile_set_root")?,
        "node_membership_refs":[], "node_membership_root":membership_root, "active_writer_epoch":Value::Null,
        "latest_sequence":2, "latest_operation_commitment":effect["operation_commitment"], "latest_transition_commitment_ref":Value::Null,
        "latest_transition_id":graph.step.transition["lifecycle_transition_id"], "latest_transition_root":graph.step.transition_root,
        "latest_receipt_ref":graph.step.receipt["receipt_ref"], "latest_receipt_root":graph.step.receipt_root,
        "latest_state_ref":graph.step.state["activation_state_ref"], "latest_state_root":graph.step.state_root,
        "worker_instance_refs":[], "workflow_refs":[], "active_component_registry_ref":effect["component_registry_ref"], "active_component_registry_root":effect["component_registry_root"],
        "policy_root":effect["policy_root"], "module_registry_root":effect["module_registry_root"], "pending_proposal_refs":[], "proposal_queue_root":proposal_queue_root,
        "operation_log_ref":log["operation_log_ref"], "operation_log_root":log["operation_log_root"], "upgrade_policy_ref":effect["upgrade_policy_ref"],
        "settlement_policy_ref":Value::Null, "default_settlement_mode":Value::Null, "allowed_settlement_modes":[], "settlement_profile_refs":[], "public_commitment_policy_ref":Value::Null,
        "status":"active", "created_at":timestamp,
    });
    let mut chain_material = chain.as_object().cloned().expect("object");
    chain_material.remove("schema_version");
    chain_material.remove("chain_root");
    chain_material.remove("created_at");
    chain_material.insert(
        "domain".to_owned(),
        json!("ioi.autonomous-system-chain-jcs-sha256.v1"),
    );
    chain["chain_root"] = json!(jcs_hash(&Value::Object(chain_material))?);
    validate_contract(SYSTEM_CHAIN_CONTRACT, &chain, "chain")?;
    graph.operation_log = Some(log);
    graph.chain = Some(chain);
    Ok(())
}

fn evidence_intent_value(evidence: &NodeAdmissionEvidence) -> Value {
    json!({
        "acting_authority_id": evidence.authorized.evidence.acting_authority_id,
        "grant_ref": evidence.authorized.evidence.grant_ref,
        "policy_hash": evidence.authorized.evidence.policy_hash,
        "request_hash": evidence.authorized.evidence.request_hash,
        "effect_hash": evidence.authorized.evidence.effect_hash,
        "authorized_effect": evidence.authorized.evidence.authorized_effect,
        "wallet_approval_grant": evidence.authorized.evidence.wallet_approval_grant,
        "authority_binding": evidence.authorized.evidence.authority_binding,
        "resolved_at_ms": evidence.authorized.resolved_at_ms,
        "authority_evidence": evidence.authority_evidence,
        "authority_evidence_ref": evidence.authority_evidence_ref,
        "authority_evidence_root": evidence.authority_evidence_root,
        "wallet_params": evidence.wallet_params,
        "wallet_consumption_ref": evidence.wallet_consumption_ref,
        "wallet_consumption_tail": evidence.wallet_consumption_tail,
        "wallet_consumption_evidence_ref": evidence.wallet_consumption_evidence_ref,
    })
}

pub(crate) fn evidence_from_intent(value: &Value) -> Result<NodeAdmissionEvidence, VErr> {
    let authorized = AuthorizedDecision {
        evidence: governed::DecisionEvidence {
            acting_authority_id: value["acting_authority_id"].clone(),
            grant_ref: required_string(value, "/grant_ref")?.to_owned(),
            policy_hash: required_string(value, "/policy_hash")?.to_owned(),
            request_hash: required_string(value, "/request_hash")?.to_owned(),
            effect_hash: required_string(value, "/effect_hash")?.to_owned(),
            authorized_effect: value["authorized_effect"].clone(),
            wallet_approval_grant: value["wallet_approval_grant"].clone(),
            authority_binding: value["authority_binding"].clone(),
        },
        resolved_at_ms: value["resolved_at_ms"].as_u64().ok_or_else(|| {
            verr(
                "system_lifecycle_intent_unreadable",
                "intent lacks authority resolution time",
            )
        })?,
    };
    Ok(NodeAdmissionEvidence {
        authorized,
        authority_evidence: value["authority_evidence"].clone(),
        authority_evidence_ref: required_string(value, "/authority_evidence_ref")?.to_owned(),
        authority_evidence_root: required_string(value, "/authority_evidence_root")?.to_owned(),
        wallet_params: serde_json::from_value(value["wallet_params"].clone()).map_err(|error| {
            verr(
                "system_lifecycle_intent_unreadable",
                format!("wallet coordinates are malformed ({error})"),
            )
        })?,
        wallet_consumption_ref: required_string(value, "/wallet_consumption_ref")?.to_owned(),
        wallet_consumption_tail: required_string(value, "/wallet_consumption_tail")?.to_owned(),
        wallet_consumption_root: String::new(),
        wallet_consumption_evidence_ref: required_string(
            value,
            "/wallet_consumption_evidence_ref",
        )?
        .to_owned(),
    })
}

fn build_intent(
    key: &str,
    operation: SystemLifecycleOperation,
    request: &Value,
    plan: &CompiledSystemLifecyclePlan,
    evidence: &NodeAdmissionEvidence,
) -> Result<Value, VErr> {
    let plan_value = serde_json::to_value(plan).map_err(|error| {
        verr(
            "system_lifecycle_intent_invalid",
            format!("compiled plan cannot be sealed ({error})"),
        )
    })?;
    let touched_refs = vec![
        plan.authority_effect["system_id"].clone(),
        plan.authority_effect["sequence_zero_materialization_id"].clone(),
        plan.authority_effect["sequence_zero_receipt_ref"].clone(),
        plan.authority_effect["deployment_profile_ref"].clone(),
        plan.authority_effect["resulting_state_ref"].clone(),
        json!(evidence.authority_evidence_ref),
        json!(evidence.wallet_consumption_ref),
    ];
    intent_seal(json!({
        "schema_version": "ioi.hypervisor.system-lifecycle-intent.v1",
        "kind": format!("system_{}", operation.as_str()),
        "operation": operation.as_str(),
        "sequence": operation.sequence(),
        "source_record_tail": key,
        "phase": "prepared_for_authority_consumption",
        "request_roots": request.as_object().expect("validated object").iter().filter(|(key, _)| key.as_str() != "wallet_approval_grant").map(|(key, value)| (key.clone(), value.clone())).collect::<serde_json::Map<_, _>>(),
        "compiled_plan": plan_value,
        "compiled_authority_effect": plan.authority_effect,
        "governed_authority": evidence_intent_value(evidence),
        "wallet_consumption_ref": evidence.wallet_consumption_ref,
        "wallet_consumption_tail": evidence.wallet_consumption_tail,
        "touched_refs": touched_refs,
        "intent_family_created_by_request": false,
        "created_family_provenance": {"family": intent_family(operation), "precreated_by_daemon": true},
        "intent_hash": Value::Null,
    }))
}

fn graph_records(graph: &AdmittedGraph) -> Result<Vec<(&'static str, String, &Value)>, VErr> {
    let mut records = vec![(
        AUTHORITY_CONSUMPTION_DIR,
        format!(
            "aslac_{}",
            hex::encode(
                serde_json::from_value::<ApprovalGrantConsumptionReceipt>(
                    graph.wallet_consumption.clone()
                )
                .map_err(|error| verr(
                    "system_lifecycle_wallet_consumption_invalid",
                    error.to_string()
                ))?
                .consumption_id
            )
        ),
        &graph.wallet_consumption,
    )];
    if graph.plan.operation == SystemLifecycleOperation::Initialize {
        records.push((
            DEPLOYMENT_DIR,
            tail(
                "asdpr_",
                required_string(&graph.deployment, "/deployment_profile_root")?,
            )?,
            &graph.deployment,
        ));
    }
    records.extend([
        (
            AUTHORITY_EVIDENCE_DIR,
            tail(
                "aslae_",
                required_string(&graph.authority_evidence, "/authority_evidence_root")?,
            )?,
            &graph.authority_evidence,
        ),
        (
            PROPOSAL_DIR,
            tail("aslp_", &graph.step.proposal_root)?,
            &graph.step.proposal,
        ),
        (
            DECISION_DIR,
            tail("aslad_", &graph.step.decision_root)?,
            &graph.step.decision,
        ),
        (
            TRANSITION_DIR,
            tail("aslt_", &graph.step.transition_root)?,
            &graph.step.transition,
        ),
        (
            if graph.plan.operation == SystemLifecycleOperation::Initialize {
                INITIALIZE_RECEIPT_DIR
            } else {
                ACTIVATION_RECEIPT_DIR
            },
            tail(
                if graph.plan.operation == SystemLifecycleOperation::Initialize {
                    "asltr_"
                } else {
                    "asar_"
                },
                &graph.step.receipt_root,
            )?,
            &graph.step.receipt,
        ),
        (
            STATE_DIR,
            tail("asls_", &graph.step.state_root)?,
            &graph.step.state,
        ),
    ]);
    if let Some(value) = &graph.active_set {
        records.push((
            ACTIVE_SET_DIR,
            tail(
                "asaps_",
                required_string(value, "/active_profile_set_root")?,
            )?,
            value,
        ));
    }
    if let Some(value) = &graph.home_binding {
        records.push((
            HOME_BINDING_DIR,
            tail(
                "ashdb_",
                required_string(value, "/home_domain_binding_root")?,
            )?,
            value,
        ));
    }
    if let Some(value) = &graph.operation_log {
        records.push((
            OPERATION_LOG_DIR,
            tail("asol_", required_string(value, "/operation_log_root")?)?,
            value,
        ));
    }
    if let Some(value) = &graph.chain {
        records.push((
            CHAIN_DIR,
            tail("asc_", required_string(value, "/chain_root")?)?,
            value,
        ));
    }
    Ok(records)
}

fn persist_graph(data_dir: &str, graph: &AdmittedGraph) -> Result<(), VErr> {
    validate_contract(
        SYSTEM_DEPLOYMENT_PROFILE_REVISION_CONTRACT,
        &graph.deployment,
        "deployment revision",
    )?;
    for (family, tail, value) in graph_records(graph)? {
        persist_local(data_dir, family, &tail, value)?;
        if forced_fault(
            "IOI_TEST_FORCE_SYSTEM_LIFECYCLE_AFTER_LOCAL_PERSIST",
            family,
        ) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                format!("test-forced interruption after local '{family}/{tail}'"),
            ));
        }
        super::substrate_store::admit_required(data_dir, family, &tail, value).map_err(
            |error| {
                verr(
                    "system_lifecycle_agentgres_admission_failed",
                    format!("required admission for '{family}/{tail}' failed ({error})"),
                )
            },
        )?;
        if forced_fault(
            "IOI_TEST_FORCE_SYSTEM_LIFECYCLE_AFTER_AGENTGRES_ADMIT",
            family,
        ) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                format!("test-forced interruption after Agentgres '{family}/{tail}'"),
            ));
        }
    }
    for (family, tail, value) in graph_records(graph)? {
        let loaded = load_required_exact(data_dir, family, &tail)?.ok_or_else(|| {
            verr(
                "system_lifecycle_pending_convergence",
                format!("'{family}/{tail}' vanished after admission"),
            )
        })?;
        if loaded != *value {
            return Err(verr(
                "system_lifecycle_artifact_mismatch",
                format!("'{family}/{tail}' differs after admission"),
            ));
        }
    }
    Ok(())
}

fn scan_intents(
    data_dir: &str,
    operation: SystemLifecycleOperation,
) -> Result<Vec<(String, Result<Value, VErr>)>, VErr> {
    let family = intent_family(operation);
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                format!("intent family cannot be pinned ({error})"),
            ))
        }
    };
    let mut names = super::durable_fs::enumerate_pinned(&directory).map_err(|error| {
        verr(
            "system_lifecycle_intent_unreadable",
            format!("intent family cannot be enumerated ({error})"),
        )
    })?;
    names.sort();
    Ok(names
        .into_iter()
        .map(|name| {
            let json_suffix = name.strip_suffix(".json");
            let tail = json_suffix.unwrap_or(&name).to_owned();
            let value = (|| {
                if json_suffix.is_none() {
                    return Err(verr(
                        "system_lifecycle_intent_unreadable",
                        format!("unexpected intent entry '{name}'"),
                    ));
                }
                let expected_prefix = if operation == SystemLifecycleOperation::Initialize {
                    "asini_"
                } else {
                    "asaci_"
                };
                if !tail.starts_with(expected_prefix) || tail.len() != expected_prefix.len() + 64 {
                    return Err(verr(
                        "system_lifecycle_intent_unreadable",
                        format!("unexpected intent entry '{name}'"),
                    ));
                }
                let bytes = super::durable_fs::read_slot_strict(&directory, &name)
                    .map_err(|error| {
                        verr(
                            "system_lifecycle_intent_unreadable",
                            format!("intent '{name}' is unreadable ({error})"),
                        )
                    })?
                    .ok_or_else(|| {
                        verr(
                            "system_lifecycle_intent_unreadable",
                            format!("intent '{name}' vanished"),
                        )
                    })?
                    .1;
                let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
                    verr(
                        "system_lifecycle_intent_unreadable",
                        format!("intent '{name}' is malformed ({error})"),
                    )
                })?;
                verify_intent_seal(&value)?;
                verify_intent_coordinates(operation, &tail, &value)?;
                Ok(value)
            })();
            (tail, value)
        })
        .collect())
}

fn fair_window(
    entries: Vec<(String, Result<Value, VErr>)>,
    max: usize,
    cursor: &AtomicUsize,
) -> Vec<(String, Result<Value, VErr>)> {
    if entries.is_empty() || max == 0 {
        return Vec::new();
    }
    let count = max.min(entries.len());
    let start = cursor.fetch_add(1, Ordering::Relaxed) % entries.len();
    (0..count)
        .map(|offset| {
            let index = (start + offset) % entries.len();
            let (tail, value) = &entries[index];
            (
                tail.clone(),
                value
                    .as_ref()
                    .map(Clone::clone)
                    .map_err(|error| error.clone()),
            )
        })
        .collect()
}

fn reconstruct_intent_plan(
    data_dir: &str,
    intent: &Value,
    operation: SystemLifecycleOperation,
) -> Result<CompiledSystemLifecyclePlan, VErr> {
    let stored: CompiledSystemLifecyclePlan =
        serde_json::from_value(intent["compiled_plan"].clone()).map_err(|error| {
            verr(
                "system_lifecycle_intent_unreadable",
                format!("compiled plan is malformed ({error})"),
            )
        })?;
    if stored.operation != operation
        || intent.get("compiled_authority_effect") != Some(&stored.authority_effect)
    {
        return Err(verr(
            "system_lifecycle_intent_unreadable",
            "intent operation or effect detaches its compiled plan",
        ));
    }
    with_source_locks(|| {
        let key = required_string(intent, "/source_record_tail")?;
        let source = super::system_sequence_zero_routes::load_current_v2_activation_source_locked(
            data_dir, key,
        )?
        .ok_or_else(|| {
            verr(
                "system_lifecycle_source_not_found",
                "replay source is absent",
            )
        })?;
        if source != stored.source {
            return Err(verr(
                "system_lifecycle_source_conflict",
                "replay M1.3/M1.4 bytes differ from the sealed source",
            ));
        }
        let rebuilt = match operation {
            SystemLifecycleOperation::Initialize => {
                compile_system_initialize_plan(&source, &stored.deployment_profile_revision)
            }
            SystemLifecycleOperation::Activate => compile_system_activate_plan(
                &source,
                &stored.deployment_profile_revision,
                stored.previous_step.as_ref().ok_or_else(|| {
                    verr(
                        "system_activate_initialize_not_found",
                        "replay plan lacks initialized predecessor",
                    )
                })?,
            ),
        }
        .map_err(|error| verr("system_lifecycle_plan_invalid", error))?;
        if rebuilt != stored {
            return Err(verr(
                "system_lifecycle_source_conflict",
                "replay plan does not reconstruct byte-exactly",
            ));
        }
        Ok(stored)
    })
}

async fn replay_one(
    data_dir: &str,
    operation: SystemLifecycleOperation,
    tail: &str,
    intent: &Value,
) -> Result<(), VErr> {
    verify_intent_coordinates(operation, tail, intent)?;
    let plan = reconstruct_intent_plan(data_dir, intent, operation)?;
    let mut evidence = evidence_from_intent(&intent["governed_authority"])?;
    let rebuilt = prepare_node_evidence(&plan, evidence.authorized.clone())?;
    if rebuilt.authority_evidence != evidence.authority_evidence
        || rebuilt.wallet_params.request_hash != evidence.wallet_params.request_hash
        || rebuilt.wallet_params.consumption_id != evidence.wallet_params.consumption_id
        || rebuilt.wallet_consumption_ref != evidence.wallet_consumption_ref
    {
        return Err(verr(
            "system_lifecycle_intent_unreadable",
            "sealed authority or wallet coordinates do not reconstruct",
        ));
    }
    let existing = recover_wallet_consumption(data_dir, &evidence.wallet_consumption_tail)?;
    let wallet_receipt: ApprovalGrantConsumptionReceipt = match existing {
        Some(value) => serde_json::from_value(value).map_err(|error| {
            verr(
                "system_lifecycle_wallet_consumption_invalid",
                error.to_string(),
            )
        })?,
        None => {
            match super::wallet_network_capability_client::consume_approval_grant_for_effect_v2(
                evidence.wallet_params.clone(),
            )
            .await
            {
                Ok(value) => value,
                Err(super::wallet_network_capability_client::ResolveError::Refused(message)) => {
                    if load_required_exact(
                        data_dir,
                        AUTHORITY_CONSUMPTION_DIR,
                        &evidence.wallet_consumption_tail,
                    )?
                    .is_none()
                    {
                        remove_intent(data_dir, intent_family(operation), tail)?;
                    }
                    return Err(verr("system_lifecycle_wallet_consumption_refused", message));
                }
                Err(
                    super::wallet_network_capability_client::ResolveError::NotConfigured(message)
                    | super::wallet_network_capability_client::ResolveError::Unavailable(message),
                ) => {
                    return Err(verr(
                        "system_lifecycle_wallet_consumption_unavailable",
                        message,
                    ))
                }
                Err(super::wallet_network_capability_client::ResolveError::Invalid(message)) => {
                    return Err(verr("system_lifecycle_wallet_consumption_invalid", message))
                }
            }
        }
    };
    let wallet_value = validate_wallet_receipt(&mut evidence, &wallet_receipt)?;
    let timestamp = ms_to_timestamp(wallet_receipt.consumed_at_ms)?;
    let mut graph = build_admitted_step(&plan, &evidence, wallet_value, &timestamp)?;
    complete_live_graph(&mut graph, &timestamp)?;
    with_source_locks(|| {
        let current = load_local(data_dir, intent_family(operation), tail)?.ok_or_else(|| {
            verr(
                "system_lifecycle_pending_convergence",
                "replay intent vanished",
            )
        })?;
        if current != *intent {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                "replay intent changed",
            ));
        }
        persist_graph(data_dir, &graph)?;
        remove_intent(data_dir, intent_family(operation), tail)
    })
}

async fn post(
    operation: SystemLifecycleOperation,
    key: String,
    state: Arc<DaemonState>,
    body: Value,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_lifecycle_source_key_invalid",
            "id must be 'asg_' plus 64 lowercase hexadecimal characters",
        ));
    }
    if let Err(error) = validate_request(operation, &body) {
        return classify(error);
    }
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let plan = match operation {
        SystemLifecycleOperation::Initialize => {
            match compile_initialize(&state.data_dir, &key, &body) {
                Ok(v) => v,
                Err(e) => return classify(e),
            }
        }
        SystemLifecycleOperation::Activate => {
            match compile_activate(&state.data_dir, &key, &body) {
                Ok(value) => value,
                Err(error) => return classify(error),
            }
        }
    };
    let system_id = plan
        .authority_effect
        .get("system_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let genesis_ref = plan
        .authority_effect
        .get("genesis_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    let authority = plan.source.source_governing_authority_ref.clone();
    let authorized = match governed::authorize_decision_with_context(
        AUTHORITY,
        &body,
        Governance::Host,
        AuthorityPolicyContext::SystemGenesis {
            system_id,
            genesis_id: genesis_ref,
        },
        &authority,
        system_id,
        operation.as_str(),
        operation.sequence(),
        &plan.authority_effect,
    )
    .await
    {
        Err(response) => return response,
        Ok(value) => value,
    };
    let mut evidence = match prepare_node_evidence(&plan, authorized) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent_tail = match intent_tail(operation, &evidence.authorized.evidence.request_hash) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if let Err(error) =
        revalidate_and_persist_intent(&state.data_dir, &key, &body, &plan, &evidence, &intent_tail)
    {
        return classify(error);
    }
    if forced_fault(
        "IOI_TEST_FORCE_SYSTEM_LIFECYCLE_AFTER_INTENT",
        operation.as_str(),
    ) {
        return classify(verr(
            "system_lifecycle_pending_convergence",
            "test-forced interruption after durable intent",
        ));
    }
    let wallet_receipt =
        match super::wallet_network_capability_client::consume_approval_grant_for_effect_v2(
            evidence.wallet_params.clone(),
        )
        .await
        {
            Ok(value) => value,
            Err(
                super::wallet_network_capability_client::ResolveError::NotConfigured(message)
                | super::wallet_network_capability_client::ResolveError::Unavailable(message),
            ) => {
                return classify(verr(
                    "system_lifecycle_wallet_consumption_unavailable",
                    message,
                ))
            }
            Err(super::wallet_network_capability_client::ResolveError::Refused(message)) => {
                let cleanup = with_source_locks(|| {
                    if load_required_exact(
                        &state.data_dir,
                        AUTHORITY_CONSUMPTION_DIR,
                        &evidence.wallet_consumption_tail,
                    )?
                    .is_some()
                    {
                        return Err(verr(
                            "system_lifecycle_pending_convergence",
                            "wallet refusal conflicts with existing consumption evidence",
                        ));
                    }
                    remove_intent(&state.data_dir, intent_family(operation), &intent_tail)
                });
                if let Err(error) = cleanup {
                    return classify(error);
                }
                return classify(verr("system_lifecycle_wallet_consumption_refused", message));
            }
            Err(super::wallet_network_capability_client::ResolveError::Invalid(message)) => {
                return classify(verr("system_lifecycle_wallet_consumption_invalid", message))
            }
        };
    let wallet_value = match validate_wallet_receipt(&mut evidence, &wallet_receipt) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if forced_fault(
        "IOI_TEST_FORCE_SYSTEM_LIFECYCLE_AFTER_WALLET_CONSUMPTION",
        operation.as_str(),
    ) {
        return classify(verr(
            "system_lifecycle_pending_convergence",
            "test-forced interruption after exact wallet consumption",
        ));
    }
    let timestamp = match ms_to_timestamp(wallet_receipt.consumed_at_ms) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let mut graph = match build_admitted_step(&plan, &evidence, wallet_value, &timestamp) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if let Err(error) = complete_live_graph(&mut graph, &timestamp) {
        return classify(error);
    }
    let result =
        with_source_locks(|| {
            let stored = load_local(&state.data_dir, intent_family(operation), &intent_tail)?
                .ok_or_else(|| {
                    verr(
                        "system_lifecycle_pending_convergence",
                        "durable intent vanished after wallet consumption",
                    )
                })?;
            verify_intent_seal(&stored)?;
            if stored.get("compiled_plan")
                != Some(&serde_json::to_value(&plan).map_err(|error| {
                    verr("system_lifecycle_intent_unreadable", error.to_string())
                })?)
            {
                return Err(verr(
                    "system_lifecycle_intent_unreadable",
                    "durable intent does not bind the authorized plan",
                ));
            }
            persist_graph(&state.data_dir, &graph)?;
            if forced_fault(
                "IOI_TEST_FORCE_SYSTEM_LIFECYCLE_BEFORE_TERMINAL_VISIBILITY",
                operation.as_str(),
            ) {
                return Err(verr(
                    "system_lifecycle_pending_convergence",
                    "test-forced interruption before terminal intent removal",
                ));
            }
            remove_intent(&state.data_dir, intent_family(operation), &intent_tail)
        });
    if let Err(error) = result {
        return classify(error);
    }
    (
        StatusCode::OK,
        Json(json!({
            "operation": operation.as_str(),
            "autonomous_system_activation_state": graph.step.state,
            "lifecycle_transition": graph.step.transition,
            "lifecycle_receipt": graph.step.receipt,
            "active_profile_set": graph.active_set,
            "home_domain_binding": graph.home_binding,
            "operation_log": graph.operation_log,
            "autonomous_system_chain": graph.chain,
            "nonclaims": {"runtime_effect":false,"network_effect":false,"membership":false,"writer":false,"settlement":false,"m2_state_transition_commitment":false}
        })),
    )
}

pub(crate) async fn handle_initialize(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    post(SystemLifecycleOperation::Initialize, key, state, body).await
}
pub(crate) async fn handle_activate(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    post(SystemLifecycleOperation::Activate, key, state, body).await
}

pub(crate) async fn handle_get_initialize(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    get_state(&key, &state.data_dir, 1)
}
pub(crate) async fn handle_get_activate(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    get_state(&key, &state.data_dir, 2)
}

fn get_state(key: &str, data_dir: &str, sequence: u64) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(key) {
        return classify(verr(
            "system_lifecycle_source_key_invalid",
            "id must be canonical",
        ));
    }
    match with_source_locks(|| load_visible_graph(data_dir, key, sequence)) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

pub(crate) fn enumerate_family(data_dir: &str, family: &str) -> Result<Vec<(String, Value)>, VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(verr(
                "system_lifecycle_artifact_unreadable",
                format!("family '{family}' cannot be pinned ({error})"),
            ))
        }
    };
    let names = super::durable_fs::enumerate_pinned(&directory).map_err(|error| {
        verr(
            "system_lifecycle_artifact_unreadable",
            format!("family '{family}' cannot be enumerated ({error})"),
        )
    })?;
    let mut values = Vec::new();
    for name in names {
        let tail = name.strip_suffix(".json").ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_unreadable",
                format!("unexpected entry '{family}/{name}'"),
            )
        })?;
        let value = load_required_exact(data_dir, family, tail)?.ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_unreadable",
                format!("'{family}/{name}' vanished"),
            )
        })?;
        values.push((tail.to_owned(), value));
    }
    Ok(values)
}

fn ensure_no_pending_intent(data_dir: &str, key: &str) -> Result<(), VErr> {
    for operation in [
        SystemLifecycleOperation::Initialize,
        SystemLifecycleOperation::Activate,
    ] {
        for (_tail, intent) in scan_intents(data_dir, operation)? {
            let intent = intent?;
            if intent.get("source_record_tail").and_then(Value::as_str) == Some(key) {
                return Err(verr(
                    "system_lifecycle_pending_convergence",
                    format!("{} intent is still pending", operation.as_str()),
                ));
            }
        }
    }
    Ok(())
}

fn refuse_existing_sequence(data_dir: &str, system_id: &str, sequence: u64) -> Result<(), VErr> {
    if enumerate_family(data_dir, STATE_DIR)?
        .into_iter()
        .any(|(_, state)| {
            state.get("system_id").and_then(Value::as_str) == Some(system_id)
                && state.get("sequence").and_then(Value::as_u64) == Some(sequence)
        })
    {
        return Err(verr(
            "system_lifecycle_sequence_conflict",
            format!("lifecycle sequence {sequence} is already durably admitted"),
        ));
    }
    Ok(())
}

fn unique_system_record(
    data_dir: &str,
    family: &str,
    system_id: &str,
    sequence: Option<u64>,
) -> Result<Value, VErr> {
    let mut matches = enumerate_family(data_dir, family)?
        .into_iter()
        .filter_map(|(_, value)| {
            (value.get("system_id").and_then(Value::as_str) == Some(system_id)
                && sequence.is_none_or(|sequence| {
                    value.get("sequence").and_then(Value::as_u64) == Some(sequence)
                }))
            .then_some(value)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(verr(
            if matches.is_empty() {
                "system_lifecycle_not_found"
            } else {
                "system_lifecycle_artifact_mismatch"
            },
            format!(
                "expected exactly one converged '{family}' record, found {}",
                matches.len()
            ),
        ));
    }
    Ok(matches.remove(0))
}

fn authorized_from_authority_artifact(authority: &Value) -> Result<AuthorizedDecision, VErr> {
    Ok(AuthorizedDecision {
        evidence: governed::DecisionEvidence {
            acting_authority_id: authority.get("acting_authority_id").cloned().ok_or_else(
                || {
                    verr(
                        "system_lifecycle_artifact_mismatch",
                        "authority evidence omits acting authority",
                    )
                },
            )?,
            grant_ref: required_string(authority, "/wallet_authority_grant_ref")?.to_owned(),
            policy_hash: required_string(authority, "/policy_hash")?.to_owned(),
            request_hash: required_string(authority, "/request_hash")?.to_owned(),
            effect_hash: required_string(authority, "/effect_hash")?.to_owned(),
            authorized_effect: authority.get("authorized_effect").cloned().ok_or_else(|| {
                verr(
                    "system_lifecycle_artifact_mismatch",
                    "authority evidence omits its authorized effect",
                )
            })?,
            wallet_approval_grant: authority.get("wallet_approval_grant").cloned().ok_or_else(
                || {
                    verr(
                        "system_lifecycle_artifact_mismatch",
                        "authority evidence omits its wallet grant",
                    )
                },
            )?,
            authority_binding: authority
                .get("principal_authority_binding")
                .cloned()
                .ok_or_else(|| {
                    verr(
                        "system_lifecycle_artifact_mismatch",
                        "authority evidence omits its principal binding",
                    )
                })?,
        },
        resolved_at_ms: authority
            .get("authority_resolved_at_ms")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                verr(
                    "system_lifecycle_artifact_mismatch",
                    "authority evidence omits its resolution time",
                )
            })?,
    })
}

fn committed_step_from_visible(
    response: &Value,
) -> Result<UnverifiedCommittedSystemLifecycleStep, VErr> {
    let proposal = response["lifecycle_proposal"].clone();
    let decision = response["lifecycle_authority_decision"].clone();
    let state = response["autonomous_system_activation_state"].clone();
    let transition = response["lifecycle_transition"].clone();
    let receipt = response["lifecycle_receipt"].clone();
    Ok(UnverifiedCommittedSystemLifecycleStep {
        state_root: required_string(&state, "/activation_state_root")?.to_owned(),
        proposal_root: required_string(&proposal, "/proposal_root")?.to_owned(),
        decision_root: required_string(&decision, "/decision_root")?.to_owned(),
        transition_root: required_string(&state, "/transition_root")?.to_owned(),
        receipt_root: required_string(&state, "/transition_receipt_root")?.to_owned(),
        proposal,
        decision,
        state,
        transition,
        receipt,
    })
}

fn load_visible_graph(data_dir: &str, key: &str, sequence: u64) -> Result<Value, VErr> {
    ensure_no_pending_intent(data_dir, key)?;
    let source = super::system_sequence_zero_routes::load_current_v2_activation_source_locked(
        data_dir, key,
    )?
    .ok_or_else(|| {
        verr(
            "system_lifecycle_not_found",
            "verified M1.4 source is absent",
        )
    })?;
    let system_id = required_string(&source.materialization, "/system_id")?;
    let state = unique_system_record(data_dir, STATE_DIR, system_id, Some(sequence))?;
    validate_contract(SYSTEM_LIFECYCLE_STATE_CONTRACT, &state, "state")?;
    let state_root = required_string(&state, "/activation_state_root")?;
    if load_required_exact(data_dir, STATE_DIR, &tail("asls_", state_root)?)? != Some(state.clone())
    {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "state key/root binding failed",
        ));
    }
    let transition_root = required_string(&state, "/transition_root")?;
    let receipt_root = required_string(&state, "/transition_receipt_root")?;
    let transition =
        load_required_exact(data_dir, TRANSITION_DIR, &tail("aslt_", transition_root)?)?
            .ok_or_else(|| verr("system_lifecycle_artifact_mismatch", "transition is absent"))?;
    if artifact_root(LIFECYCLE_TRANSITION_HASH_PROFILE, &transition)? != transition_root {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "transition root differs from exact bytes",
        ));
    }
    let receipt_family = if sequence == 1 {
        INITIALIZE_RECEIPT_DIR
    } else {
        ACTIVATION_RECEIPT_DIR
    };
    let receipt = load_required_exact(
        data_dir,
        receipt_family,
        &tail(if sequence == 1 { "asltr_" } else { "asar_" }, receipt_root)?,
    )?
    .ok_or_else(|| verr("system_lifecycle_artifact_mismatch", "receipt is absent"))?;
    let receipt_domain = if sequence == 1 {
        LIFECYCLE_RECEIPT_HASH_PROFILE
    } else {
        ACTIVATION_RECEIPT_HASH_PROFILE
    };
    if artifact_root(receipt_domain, &receipt)? != receipt_root
        || receipt.get("subject_ref") != transition.get("lifecycle_transition_id")
        || receipt.pointer("/bound_facts/resulting_state_root") != Some(&json!(state_root))
    {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "receipt/transition/state graph is detached",
        ));
    }
    let proposal_root = required_string(&receipt, "/bound_facts/proposal_root")?;
    let decision_root = required_string(&receipt, "/bound_facts/decision_root")?;
    let proposal = load_required_exact(data_dir, PROPOSAL_DIR, &tail("aslp_", proposal_root)?)?
        .ok_or_else(|| verr("system_lifecycle_artifact_mismatch", "proposal is absent"))?;
    let decision = load_required_exact(data_dir, DECISION_DIR, &tail("aslad_", decision_root)?)?
        .ok_or_else(|| verr("system_lifecycle_artifact_mismatch", "decision is absent"))?;
    if proposal.get("proposal_root") != Some(&json!(proposal_root))
        || decision.get("decision_root") != Some(&json!(decision_root))
        || decision.get("proposal_root") != Some(&json!(proposal_root))
        || receipt.get("effect_hash") != proposal.get("authority_effect_hash")
        || receipt.get("effect_hash") != decision.get("effect_hash")
    {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "proposal/decision authority graph is detached",
        ));
    }
    let deployment_root = required_string(&receipt, "/bound_facts/deployment_profile_root")?;
    let deployment =
        load_required_exact(data_dir, DEPLOYMENT_DIR, &tail("asdpr_", deployment_root)?)?
            .ok_or_else(|| verr("system_lifecycle_artifact_mismatch", "deployment is absent"))?;
    let authority_root = required_string(&receipt, "/authority_evidence_root")?;
    let authority = load_required_exact(
        data_dir,
        AUTHORITY_EVIDENCE_DIR,
        &tail("aslae_", authority_root)?,
    )?
    .ok_or_else(|| {
        verr(
            "system_lifecycle_artifact_mismatch",
            "authority evidence is absent",
        )
    })?;
    governed::verify_retained_authority_binding_root(&authority["principal_authority_binding"])
        .map_err(|error| verr("system_lifecycle_artifact_mismatch", error))?;
    let consumption_tail = required_string(&receipt, "/wallet_grant_consumption_evidence_ref")?
        .rsplit_once("//")
        .map(|(_, tail)| tail)
        .unwrap_or("");
    let wallet = load_required_exact(data_dir, AUTHORITY_CONSUMPTION_DIR, consumption_tail)?
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_mismatch",
                "wallet consumption is absent",
            )
        })?;
    let plan = if sequence == 1 {
        compile_system_initialize_plan(&source, &deployment)
            .map_err(|error| verr("system_lifecycle_artifact_mismatch", error))?
    } else {
        let initialized_response = load_visible_graph(data_dir, key, 1)?;
        if initialized_response.get("deployment_profile_revision") != Some(&deployment) {
            return Err(verr(
                "system_lifecycle_artifact_mismatch",
                "activation does not reuse the exact initialized deployment revision",
            ));
        }
        let initialized = committed_step_from_visible(&initialized_response)?;
        compile_system_activate_plan(&source, &deployment, &initialized)
            .map_err(|error| verr("system_lifecycle_artifact_mismatch", error))?
    };
    let authorized = authorized_from_authority_artifact(&authority)?;
    let mut evidence = prepare_node_evidence(&plan, authorized)?;
    if evidence.authority_evidence != authority {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "authority evidence does not reconstruct byte-exactly from the compiled plan",
        ));
    }
    let wallet_receipt: ApprovalGrantConsumptionReceipt = serde_json::from_value(wallet.clone())
        .map_err(|error| {
            verr(
                "system_lifecycle_artifact_mismatch",
                format!("wallet receipt is malformed ({error})"),
            )
        })?;
    let wallet_value = validate_wallet_receipt(&mut evidence, &wallet_receipt)?;
    if wallet_value != wallet {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "wallet receipt does not round-trip byte-exactly",
        ));
    }
    let timestamp = ms_to_timestamp(wallet_receipt.consumed_at_ms)?;
    let mut expected_graph = build_admitted_step(&plan, &evidence, wallet.clone(), &timestamp)?;
    complete_live_graph(&mut expected_graph, &timestamp)?;
    if expected_graph.step.state != state
        || expected_graph.step.transition != transition
        || expected_graph.step.receipt != receipt
        || expected_graph.step.proposal != proposal
        || expected_graph.step.decision != decision
        || expected_graph.deployment != deployment
    {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "served lifecycle graph does not reconstruct byte-exactly from its verified source, authority, and wallet receipt",
        ));
    }
    let mut response = json!({
        "autonomous_system_activation_state": state,
        "deployment_profile_revision": deployment,
        "lifecycle_authority_evidence": authority,
        "lifecycle_proposal": proposal,
        "lifecycle_authority_decision": decision,
        "lifecycle_transition": transition,
        "lifecycle_receipt": receipt,
        "wallet_grant_consumption_receipt": wallet,
        "active_profile_set": Value::Null,
        "home_domain_binding": Value::Null,
        "operation_log": Value::Null,
        "autonomous_system_chain": Value::Null,
    });
    if sequence == 1 {
        if response.pointer("/autonomous_system_activation_state/status")
            != Some(&json!("initialized"))
            || response.pointer("/autonomous_system_activation_state/active_profile_set_ref")
                != Some(&Value::Null)
            || response.pointer("/autonomous_system_activation_state/chain_ref")
                != Some(&Value::Null)
        {
            return Err(verr(
                "system_lifecycle_artifact_mismatch",
                "sequence one claims active state",
            ));
        }
    } else {
        let active_root = required_string(
            &response,
            "/lifecycle_receipt/bound_facts/active_profile_set_root",
        )?;
        let binding_root = required_string(
            &response,
            "/lifecycle_receipt/bound_facts/home_domain_binding_root",
        )?;
        let active = load_required_exact(data_dir, ACTIVE_SET_DIR, &tail("asaps_", active_root)?)?
            .ok_or_else(|| verr("system_lifecycle_artifact_mismatch", "active set is absent"))?;
        let binding =
            load_required_exact(data_dir, HOME_BINDING_DIR, &tail("ashdb_", binding_root)?)?
                .ok_or_else(|| {
                    verr(
                        "system_lifecycle_artifact_mismatch",
                        "home binding is absent",
                    )
                })?;
        let chain = unique_system_record(data_dir, CHAIN_DIR, system_id, None)?;
        let log_root = required_string(&chain, "/operation_log_root")?;
        let log = load_required_exact(data_dir, OPERATION_LOG_DIR, &tail("asol_", log_root)?)?
            .ok_or_else(|| {
                verr(
                    "system_lifecycle_artifact_mismatch",
                    "operation log is absent",
                )
            })?;
        if expected_graph.active_set.as_ref() != Some(&active)
            || expected_graph.home_binding.as_ref() != Some(&binding)
            || expected_graph.operation_log.as_ref() != Some(&log)
            || expected_graph.chain.as_ref() != Some(&chain)
        {
            return Err(verr(
                "system_lifecycle_artifact_mismatch",
                "served activation terminal artifacts do not reconstruct byte-exactly",
            ));
        }
        let entries = log
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                verr(
                    "system_lifecycle_artifact_mismatch",
                    "operation log entries are absent",
                )
            })?;
        if entries.len() != 3
            || entries[0]["sequence"] != json!(0)
            || entries[1]["sequence"] != json!(1)
            || entries[2]["sequence"] != json!(2)
            || chain.get("latest_state_root")
                != response.pointer("/autonomous_system_activation_state/activation_state_root")
            || chain.get("operation_log_root") != log.get("operation_log_root")
            || !chain
                .get("node_membership_refs")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            || !chain
                .get("worker_instance_refs")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            || !chain
                .get("workflow_refs")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            || !chain
                .get("pending_proposal_refs")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            || chain.get("active_writer_epoch") != Some(&Value::Null)
            || chain.get("latest_transition_commitment_ref") != Some(&Value::Null)
        {
            return Err(verr(
                "system_lifecycle_artifact_mismatch",
                "activation terminal graph or exact 0/1/2 log is detached",
            ));
        }
        response["active_profile_set"] = active;
        response["home_domain_binding"] = binding;
        response["operation_log"] = log;
        response["autonomous_system_chain"] = chain;
    }
    response["nonclaims"] = json!({"runtime_effect":false,"network_effect":false,"membership":false,"writer":false,"settlement":false,"m2_state_transition_commitment":false});
    Ok(response)
}

async fn complete_intents(data_dir: &str, operation: SystemLifecycleOperation, max: usize) {
    let entries = match scan_intents(data_dir, operation) {
        Ok(entries) => entries,
        Err((_, message)) => {
            eprintln!(
                "SystemLifecycle {} replay scan failed ({message})",
                operation.as_str()
            );
            return;
        }
    };
    let cursor = if operation == SystemLifecycleOperation::Initialize {
        &INITIALIZE_REPLAY_CURSOR
    } else {
        &ACTIVATE_REPLAY_CURSOR
    };
    for (tail, result) in fair_window(entries, max, cursor) {
        let intent = match result {
            Ok(intent) => intent,
            Err((_, message)) => {
                eprintln!(
                    "SystemLifecycle {} poisoned intent '{tail}' retained ({message})",
                    operation.as_str()
                );
                continue;
            }
        };
        if let Err((_, message)) = replay_one(data_dir, operation, &tail, &intent).await {
            eprintln!(
                "SystemLifecycle {} intent '{tail}' retained/incomplete ({message})",
                operation.as_str()
            );
        }
    }
}

pub(crate) async fn complete_initialize_intents(data_dir: &str, max: usize) {
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    complete_intents(data_dir, SystemLifecycleOperation::Initialize, max).await;
}
pub(crate) async fn complete_activate_intents(data_dir: &str, max: usize) {
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    complete_intents(data_dir, SystemLifecycleOperation::Activate, max).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{
        compile_system_genesis_proposal, compile_system_sequence_zero_plan,
        compute_system_component_set_hash, compute_system_genesis_admission_receipt_root,
        compute_system_genesis_admission_record_root, compute_system_release_root,
        finalize_system_sequence_zero_materialization, ActionTarget,
        UnverifiedSystemSequenceZeroActivationSource,
    };
    const H: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn fixture(path: &str) -> Value {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        serde_json::from_slice(&std::fs::read(root.join(path)).unwrap()).unwrap()
    }

    fn hash_array(hash: &str) -> Value {
        Value::Array(
            hash.trim_start_matches("sha256:")
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    Value::from(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                })
                .collect(),
        )
    }

    fn deployment_revision(
        system_id: &str,
        constitution_ref: &str,
        manifest_ref: &str,
        ordering_ref: &str,
    ) -> Value {
        let mut revision = fixture("docs/architecture/_meta/schemas/fixtures/autonomous-system-deployment-profile-revision-v1/positive-candidate.json");
        revision["profile"]["system_id"] = json!(system_id);
        revision["profile"]["constitution_ref"] = json!(constitution_ref);
        revision["profile"]["manifest_ref"] = json!(manifest_ref);
        revision["profile"]["ordering_admission_finality_profile_ref"] = json!(ordering_ref);
        let root = jcs_hash(&json!({"domain":"ioi.autonomous-system-deployment-profile-revision-jcs-sha256.v1","profile":revision["profile"]})).unwrap();
        let identity = revision
            .pointer("/profile/deployment_profile_id")
            .and_then(Value::as_str)
            .unwrap();
        revision["deployment_profile_ref"] = json!(format!("{identity}/revision/{root}"));
        revision["deployment_profile_root"] = json!(root);
        revision
    }

    fn structural_m14_receipt(materialization: &Value, authority: &str) -> Value {
        let mut receipt = fixture("docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json");
        let mut body = materialization.clone();
        body.as_object_mut().unwrap().remove("created_at");
        let effect = json!({"operation":"materialize_sequence_zero","materialization":body,"activation_admitted":false,"runtime_effect_admitted":false});
        let effect_hash = jcs_hash(&json!({"domain":"hypervisor.system-sequence-zero.decision.request.v1.effect.v1","effect":effect})).unwrap();
        let policy_hash = jcs_hash(&json!({"domain":"hypervisor.system-sequence-zero.decision.policy.v1","governance":"system_owner","genesis_id":materialization["genesis_ref"],"system_id":materialization["system_id"],"required_authority_ref":authority,"required_scope":"scope:autonomous_system.genesis_materialize"})).unwrap();
        let request_hash = jcs_hash(&json!({"domain":"hypervisor.system-sequence-zero.decision.request.v1","governance":"system_owner","subject_ref":materialization["materialization_id"],"op":"genesis_materialize","revision":0,"required_authority_ref":authority,"required_scope":"scope:autonomous_system.genesis_materialize","effect_hash":effect_hash})).unwrap();
        receipt["wallet_approval_grant"]["request_hash"] = hash_array(&request_hash);
        receipt["wallet_approval_grant"]["policy_hash"] = hash_array(&policy_hash);
        let grant_hash = jcs_hash(&receipt["wallet_approval_grant"]).unwrap();
        let grant_ref = format!(
            "grant://wallet.network/approval/sha256:{}",
            &grant_hash[7..]
        );
        let consumption_tail = "20".repeat(32);
        let consumption_ref = format!(
            "wallet.network://approval-effect-consumption/{}/{consumption_tail}",
            &request_hash[7..]
        );
        let consumption_evidence_ref =
            format!("system-sequence-zero-authority-consumption://aszmc_{consumption_tail}");
        receipt["receipt_id"] = materialization["materialization_receipt_ref"].clone();
        receipt["receipt_ref"] = materialization["materialization_receipt_ref"].clone();
        receipt["subject_ref"] = materialization["materialization_id"].clone();
        receipt["authorized_effect"] = effect;
        receipt["input_hash"] = json!(request_hash);
        receipt["policy_hash"] = json!(policy_hash);
        receipt["effect_hash"] = json!(effect_hash);
        receipt["authority_grant_id"] = json!(grant_ref);
        receipt["timestamp"] = materialization["created_at"].clone();
        receipt["at"] = materialization["created_at"].clone();
        receipt["bound_facts"]["governing_authority_ref"] = json!(authority);
        receipt["bound_facts"]["authority_effect_hash"] = json!(effect_hash);
        receipt["bound_facts"]["wallet_grant_consumption_ref"] = json!(consumption_ref);
        receipt["bound_facts"]["wallet_grant_consumption_evidence_ref"] =
            json!(consumption_evidence_ref);
        receipt["principal_authority_binding"]["principal_ref"] = json!(authority);
        receipt["principal_authority_binding"]["binding_proof"]["statement"]["principal_ref"] =
            json!(authority);
        let statement_hash = jcs_hash(&json!({"domain":"ioi.wallet-network.principal-authority-binding.v1","statement":receipt["principal_authority_binding"]["binding_proof"]["statement"]})).unwrap();
        receipt["principal_authority_binding"]["binding_proof"]["statement_hash"] =
            hash_array(&statement_hash);
        let binding_hash = jcs_hash(&json!({"domain":"ioi.wallet-network.principal-authority-binding-proof.v1","schema_version":receipt["principal_authority_binding"]["binding_proof"]["schema_version"],"statement":receipt["principal_authority_binding"]["binding_proof"]["statement"],"statement_hash":receipt["principal_authority_binding"]["binding_proof"]["statement_hash"],"issuer_signature_proof":receipt["principal_authority_binding"]["binding_proof"]["issuer_signature_proof"]})).unwrap();
        let binding_ref = format!(
            "wallet.network://principal-authority-binding/{}",
            &binding_hash[7..]
        );
        receipt["principal_authority_binding"]["binding_proof"]["binding_hash"] =
            hash_array(&binding_hash);
        receipt["principal_authority_binding"]["binding_proof"]["binding_ref"] = json!(binding_ref);
        receipt["principal_authority_binding"]["coordinates"]["binding_hash"] =
            hash_array(&binding_hash);
        receipt["principal_authority_binding"]["coordinates"]["binding_ref"] = json!(binding_ref);
        for field in [
            "materialization_id",
            "system_id",
            "genesis_ref",
            "genesis_admission_receipt_ref",
            "genesis_admission_record_root",
            "genesis_admission_receipt_root",
            "proposed_initial_state_root",
            "proposed_initial_receipt_root",
            "package_id",
            "manifest_ref",
            "admitted_manifest_root",
            "constitution_ref",
            "constitution_root",
            "profile_bundle_root",
            "profile_materialization_root",
            "deployment_profile_root",
            "profile_refs",
            "component_registry_ref",
            "component_registry_root",
            "component_binding_count",
            "sequence",
            "predecessor_transition_commitment_ref",
            "operation_commitment",
            "transition_commitment_ref",
            "initial_state_root",
            "initial_receipt_root",
        ] {
            receipt["bound_facts"][field] = materialization[field].clone();
        }
        let mut boundary = vec![
            materialization["system_id"].clone(),
            materialization["genesis_ref"].clone(),
            materialization["manifest_ref"].clone(),
            materialization["constitution_ref"].clone(),
            materialization["component_registry_ref"].clone(),
            materialization["profile_refs"]["deployment_profile_ref"].clone(),
            materialization["profile_refs"]["ordering_admission_finality_profile_ref"].clone(),
            materialization["profile_refs"]["lifecycle_continuity_profile_ref"].clone(),
            materialization["genesis_admission_record_root"].clone(),
            materialization["genesis_admission_receipt_ref"].clone(),
            json!(authority),
            json!(grant_ref),
            json!(consumption_ref),
            json!(consumption_evidence_ref),
        ];
        boundary.extend(
            materialization["profile_refs"]["oracle_evidence_profile_refs"]
                .as_array()
                .unwrap()
                .iter()
                .cloned(),
        );
        boundary.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        boundary.dedup();
        receipt["attested_boundary_fact_refs"] = Value::Array(boundary);
        receipt
    }

    fn compiled_initialize_fixture() -> CompiledSystemLifecyclePlan {
        let mut release = fixture("docs/architecture/_meta/schemas/fixtures/autonomous-system-manifest-v1/positive-reusable-release.json");
        release["typed_components"]["component_set_hash"] =
            json!(compute_system_component_set_hash(&release).unwrap());
        release["release_root"] = json!(compute_system_release_root(&release).unwrap());
        let candidate = fixture("docs/architecture/_meta/schemas/fixtures/autonomous-system-genesis-v1/positive-proposed.json");
        let revision = deployment_revision(
            candidate["system_id"].as_str().unwrap(),
            candidate["constitution_ref"].as_str().unwrap(),
            candidate["manifest_ref"].as_str().unwrap(),
            candidate
                .pointer("/initial_profile_refs/ordering_admission_finality_profile_ref")
                .and_then(Value::as_str)
                .unwrap(),
        );
        let mut proposal_candidate = candidate.clone();
        proposal_candidate
            .as_object_mut()
            .unwrap()
            .remove("admitted_manifest_root");
        proposal_candidate
            .as_object_mut()
            .unwrap()
            .remove("initial_profile_bundle_root");
        proposal_candidate["cryptographic_origin"]
            .as_object_mut()
            .unwrap()
            .remove("genesis_operation_commitment");
        proposal_candidate["cryptographic_origin"]
            .as_object_mut()
            .unwrap()
            .remove("genesis_transition_commitment_ref");
        proposal_candidate["initial_component_bindings"]["admitted_component_set_hash"] =
            release["typed_components"]["component_set_hash"].clone();
        proposal_candidate["initial_profile_refs"]["deployment_profile_ref"] =
            revision["deployment_profile_ref"].clone();
        let input = json!({"schema_version":"ioi.autonomous-system-genesis-proposal-input.v1","candidate":proposal_candidate,"template_bindings":{"constitution_template_ref":release["constitution_template_ref"],"deployment_template_ref":release["required_profile_templates"]["deployment_template_ref"],"ordering_admission_finality_template_ref":release["required_profile_templates"]["ordering_admission_finality_template_ref"],"oracle_evidence_template_refs":release["required_profile_templates"]["oracle_evidence_template_refs"],"lifecycle_continuity_template_ref":release["required_profile_templates"]["lifecycle_continuity_template_ref"],"network_enrollment_constraint_ref":release["required_profile_templates"]["network_enrollment_constraint_ref"]},"constitution":fixture("docs/architecture/_meta/schemas/fixtures/autonomous-system-constitution-v1/positive-draft.json"),"ordering_profile":fixture("docs/architecture/_meta/schemas/fixtures/ordering-admission-finality-profile-v1/positive-single-authority.json"),"oracle_profiles":[fixture("docs/architecture/_meta/schemas/fixtures/oracle-evidence-profile-v1/positive-fail-closed.json")],"lifecycle_profile":fixture("docs/architecture/_meta/schemas/fixtures/lifecycle-continuity-profile-v1/positive-successor-governed.json"),"network_enrollment":Value::Null});
        let proposal = compile_system_genesis_proposal(&release, &input)
            .proposal
            .unwrap();
        let mut genesis = serde_json::to_value(&proposal.genesis).unwrap();
        let bundle = serde_json::to_value(&proposal.initial_profile_bundle.bundle).unwrap();
        let receipt_ref = format!("receipt://asgr_{}", "7".repeat(64));
        genesis["status"] = json!("authorized");
        genesis["instantiation"]["authority_grant_refs"] = json!([format!(
            "grant://wallet.network/approval/sha256:{}",
            "8".repeat(64)
        )]);
        genesis["cryptographic_origin"]["admission_proof_ref"] = json!(receipt_ref);
        genesis["status_source_receipt_refs"] = json!([receipt_ref]);
        let authority = "org://acme/research";
        let record = json!({"schema_version":"ioi.hypervisor.autonomous-system-genesis-admission.v1","authorized_genesis":genesis,"initial_profile_bundle":bundle,"admission_receipt_ref":receipt_ref,"governing_authority_ref":authority});
        let receipt = json!({"schema_version":"ioi.hypervisor.autonomous-system-genesis-receipt.v1","receipt_ref":receipt_ref,"subject":genesis["genesis_id"]});
        let record_root = compute_system_genesis_admission_record_root(&record).unwrap();
        let receipt_root = compute_system_genesis_admission_receipt_root(&receipt).unwrap();
        let sequence = compile_system_sequence_zero_plan(
            &genesis,
            &record["initial_profile_bundle"],
            &record_root,
            &receipt_ref,
            &receipt_root,
        )
        .unwrap();
        let materialization = serde_json::to_value(
            finalize_system_sequence_zero_materialization(&sequence, "2026-07-21T11:00:00Z")
                .unwrap()
                .materialization,
        )
        .unwrap();
        let m14_receipt = structural_m14_receipt(&materialization, authority);
        let source = UnverifiedSystemSequenceZeroActivationSource {
            source_governing_authority_ref: authority.to_owned(),
            genesis_admission_record: record,
            genesis_admission_receipt: receipt,
            materialization,
            materialization_receipt: m14_receipt.clone(),
            component_registry: sequence.component_registry_snapshot,
            materialization_wallet_consumption: json!({"schema_version":"ioi.test-wallet-consumption.v1","consumption_ref":m14_receipt["bound_facts"]["wallet_grant_consumption_ref"]}),
        };
        compile_system_initialize_plan(&source, &revision).unwrap()
    }

    fn dummy_evidence(plan: &CompiledSystemLifecyclePlan, marker: u8) -> NodeAdmissionEvidence {
        use ioi_api::crypto::{SerializableKey, SigningKeyPair};
        use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
        use ioi_types::app::{account_id_from_key_material, SignatureSuite};

        let hash = |byte: u8| format!("sha256:{}", format!("{byte:02x}").repeat(32));
        let binding: ExpectedPrincipalAuthorityBinding = serde_json::from_value(
            plan.source.materialization_receipt["principal_authority_binding"].clone(),
        )
        .unwrap();
        let effect_hash = governed::decision_effect_hash(AUTHORITY, &plan.authority_effect);
        let grant_ref = format!(
            "grant://wallet.network/approval/sha256:{}",
            format!("{marker:02x}").repeat(32)
        );
        let consumption_id = [marker.wrapping_add(2); 32];
        let consumption_tail = format!("aslac_{}", hex::encode(consumption_id));
        let private_key = Ed25519PrivateKey::from_bytes(&[marker; 32]).unwrap();
        let keypair = Ed25519KeyPair::from_private_key(&private_key).unwrap();
        let public_key = keypair.public_key().to_bytes();
        let mut grant = ApprovalGrant {
            schema_version: 1,
            authority_id: account_id_from_key_material(SignatureSuite::ED25519, &public_key)
                .unwrap(),
            request_hash: [marker.wrapping_add(4); 32],
            policy_hash: [marker.wrapping_add(3); 32],
            audience: [0x77; 32],
            nonce: [0x78; 32],
            counter: 1,
            expires_at: 1_850_000_000_000,
            max_usages: Some(1),
            window_id: None,
            pii_action: None,
            scoped_exception: None,
            review_request_hash: None,
            approver_public_key: public_key,
            approver_sig: Vec::new(),
            approver_suite: SignatureSuite::ED25519,
        };
        grant.approver_sig = keypair
            .sign(&grant.signing_bytes().unwrap())
            .unwrap()
            .to_bytes()
            .to_vec();
        let grant_value = serde_json::to_value(grant).unwrap();
        let mut authority_evidence = json!({
            "schema_version":"ioi.hypervisor.system-lifecycle-authority-evidence.v1",
            "authority_evidence_ref":Value::Null,
            "authority_evidence_root":Value::Null,
            "authority_grant_ref":grant_ref,
            "principal_authority_binding":plan.source.materialization_receipt["principal_authority_binding"],
        });
        let authority_root = jcs_hash(&json!({
            "domain":"ioi.hypervisor.system-lifecycle-authority-evidence-jcs-sha256.v1",
            "evidence":authority_evidence,
        }))
        .unwrap();
        let authority_ref = format!(
            "system-lifecycle-authority-evidence://aslae_{}",
            &authority_root[7..]
        );
        authority_evidence["authority_evidence_ref"] = json!(authority_ref);
        authority_evidence["authority_evidence_root"] = json!(authority_root);
        NodeAdmissionEvidence {
            authorized: AuthorizedDecision {
                evidence: governed::DecisionEvidence {
                    acting_authority_id: json!(vec![0u8; 32]),
                    grant_ref: grant_ref.clone(),
                    policy_hash: hash(marker.wrapping_add(3)),
                    request_hash: hash(marker.wrapping_add(4)),
                    effect_hash,
                    authorized_effect: plan.authority_effect.clone(),
                    wallet_approval_grant: grant_value,
                    authority_binding: plan.source.materialization_receipt
                        ["principal_authority_binding"]
                        .clone(),
                },
                resolved_at_ms: 1_753_096_800_000,
            },
            authority_evidence,
            authority_evidence_ref: authority_ref,
            authority_evidence_root: authority_root,
            wallet_params: ConsumeApprovalGrantForEffectV2Params {
                request_hash: [marker.wrapping_add(4); 32],
                grant_hash: [marker.wrapping_add(5); 32],
                consumption_id,
                expected_principal_authority: binding,
                expected_target_label: plan.operation.required_scope().to_owned(),
                expected_max_usages: 1,
            },
            wallet_consumption_ref: format!(
                "wallet.network://approval-effect-consumption/{}/{}",
                format!("{:02x}", marker.wrapping_add(4)).repeat(32),
                hex::encode(consumption_id)
            ),
            wallet_consumption_tail: consumption_tail.clone(),
            wallet_consumption_root: hash(marker.wrapping_add(6)),
            wallet_consumption_evidence_ref: format!(
                "system-lifecycle-authority-consumption://{consumption_tail}"
            ),
        }
    }

    fn wallet_receipt_fixture(evidence: &NodeAdmissionEvidence) -> ApprovalGrantConsumptionReceipt {
        let grant: ApprovalGrant =
            serde_json::from_value(evidence.authorized.evidence.wallet_approval_grant.clone())
                .unwrap();
        let mut receipt = ApprovalGrantConsumptionReceipt {
            schema_version: 1,
            receipt_hash: [0; 32],
            request_hash: evidence.wallet_params.request_hash,
            grant_hash: evidence.wallet_params.grant_hash,
            consumption_id: evidence.wallet_params.consumption_id,
            principal_authority: evidence.wallet_params.expected_principal_authority.clone(),
            policy_hash: grant.policy_hash,
            authority_id: grant.authority_id,
            target: ActionTarget::Custom(evidence.wallet_params.expected_target_label.clone()),
            session_id: None,
            audience: grant.audience,
            issued_revocation_epoch: 0,
            grant_nonce: grant.nonce,
            grant_counter: grant.counter,
            consumed_at_ms: evidence.authorized.resolved_at_ms,
            usage_ordinal: 1,
            remaining_usages: 0,
        };
        let mut material = serde_json::to_value(&receipt).unwrap();
        material["receipt_hash"] = json!(vec![0u8; 32]);
        receipt.receipt_hash = Sha256::digest(serde_jcs::to_vec(&material).unwrap()).into();
        receipt
    }
    #[test]
    fn initialize_input_is_closed_and_sensitive_recursive() {
        let good = json!({"expected_sequence_zero_materialization_root":H,"expected_sequence_zero_materialization_receipt_root":H,"deployment_profile_revision":{}});
        assert!(validate_request(SystemLifecycleOperation::Initialize, &good).is_ok());
        let mut unknown = good.clone();
        unknown["extra"] = json!(true);
        assert_eq!(
            validate_request(SystemLifecycleOperation::Initialize, &unknown)
                .unwrap_err()
                .0,
            "system_lifecycle_request_field_unknown"
        );
        let mut secret = good;
        secret["deployment_profile_revision"]["nested"] = json!({"api-key":"x"});
        assert_eq!(
            validate_request(SystemLifecycleOperation::Initialize, &secret)
                .unwrap_err()
                .0,
            "system_lifecycle_sensitive_field_rejected"
        );
        let mut embedded = json!({"expected_sequence_zero_materialization_root":H,"expected_sequence_zero_materialization_receipt_root":H,"deployment_profile_revision":{}});
        embedded["deployment_profile_revision"]["operatorPasswordHint"] = json!("never-store");
        assert_eq!(
            validate_request(SystemLifecycleOperation::Initialize, &embedded)
                .unwrap_err()
                .0,
            "system_lifecycle_sensitive_field_rejected"
        );
    }

    #[test]
    fn internal_storage_failures_never_masquerade_as_client_input() {
        for code in [
            "system_lifecycle_persist_failed",
            "system_lifecycle_agentgres_admission_failed",
            "system_lifecycle_agentgres_evidence_mismatch",
            "system_lifecycle_artifact_invalid",
            "system_lifecycle_artifact_mismatch",
            "system_lifecycle_artifact_swapped",
            "system_lifecycle_intent_invalid",
            "system_lifecycle_key_invalid",
            "system_lifecycle_time_invalid",
            "system_lifecycle_wallet_consumption_invalid",
            "system_activate_artifact_invalid",
        ] {
            assert_eq!(
                classify(verr(code, "injected")).0,
                StatusCode::INTERNAL_SERVER_ERROR
            );
        }
        assert_eq!(
            classify(verr("system_lifecycle_source_conflict", "stale")).0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            classify(verr("system_lifecycle_source_key_invalid", "caller input")).0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            classify(verr("system_initialize_plan_invalid", "caller input")).0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    #[test]
    fn operations_have_distinct_scopes_and_replay_lanes() {
        assert_ne!(
            SystemLifecycleOperation::Initialize.required_scope(),
            SystemLifecycleOperation::Activate.required_scope()
        );
        assert_ne!(INITIALIZE_INTENT_DIR, ACTIVATE_INTENT_DIR);
    }
    #[test]
    fn activation_input_is_closed_and_oversize_refuses() {
        let good = json!({
            "expected_initialize_proposal_root": H,
            "expected_initialize_decision_root": H,
            "expected_initialize_state_root": H,
            "expected_initialize_transition_root": H,
            "expected_initialize_receipt_root": H,
        });
        assert!(validate_request(SystemLifecycleOperation::Activate, &good).is_ok());
        let mut wrong = good.clone();
        wrong["deployment_profile_revision"] = json!({});
        assert_eq!(
            validate_request(SystemLifecycleOperation::Activate, &wrong)
                .unwrap_err()
                .0,
            "system_lifecycle_request_field_unknown"
        );
        let mut oversize = good;
        oversize["wallet_approval_grant"] = json!({"padding":"x".repeat(MAX_REQUEST_BYTES)});
        assert_eq!(
            validate_request(SystemLifecycleOperation::Activate, &oversize)
                .unwrap_err()
                .0,
            "system_lifecycle_request_oversize"
        );
    }

    #[test]
    fn intent_seal_and_poison_fairness_are_exact() {
        let sealed = intent_seal(json!({"intent_hash":Value::Null,"value":1})).unwrap();
        verify_intent_seal(&sealed).unwrap();
        let mut tampered = sealed;
        tampered["value"] = json!(2);
        assert_eq!(
            verify_intent_seal(&tampered).unwrap_err().0,
            "system_lifecycle_intent_unreadable"
        );
        let cursor = AtomicUsize::new(0);
        let entries = vec![
            ("a".to_owned(), Err(verr("poison", "bad"))),
            ("b".to_owned(), Ok(json!(2))),
            ("c".to_owned(), Ok(json!(3))),
        ];
        let first = fair_window(entries.clone(), 1, &cursor);
        let second = fair_window(entries, 1, &cursor);
        assert!(first[0].1.is_err());
        assert_eq!(second[0].0, "b");
    }
    #[test]
    fn intent_storage_key_is_bound_to_its_sealed_operation_and_request() {
        let request_hash = format!("sha256:{}", "12".repeat(32));
        let operation = SystemLifecycleOperation::Initialize;
        let stored_tail = intent_tail(operation, &request_hash).unwrap();
        let intent = json!({
            "kind": "system_initialize",
            "operation": "initialize",
            "sequence": 1,
            "governed_authority": {"request_hash": request_hash},
        });
        verify_intent_coordinates(operation, &stored_tail, &intent).unwrap();
        assert_eq!(
            verify_intent_coordinates(operation, &format!("asini_{}", "34".repeat(32)), &intent,)
                .unwrap_err()
                .0,
            "system_lifecycle_intent_unreadable"
        );
        assert_eq!(
            verify_intent_coordinates(SystemLifecycleOperation::Activate, &stored_tail, &intent)
                .unwrap_err()
                .0,
            "system_lifecycle_intent_unreadable"
        );
    }
    #[test]
    fn intent_storage_slot_requires_the_canonical_json_filename() {
        let data_dir = tempfile::tempdir().unwrap();
        let data_dir = data_dir.path().to_str().unwrap();
        let family = intent_family(SystemLifecycleOperation::Initialize);
        std::fs::create_dir_all(std::path::Path::new(data_dir).join(family)).unwrap();
        std::fs::write(
            std::path::Path::new(data_dir)
                .join(family)
                .join(format!("asini_{}", "12".repeat(32))),
            b"{}",
        )
        .unwrap();
        let scanned = scan_intents(data_dir, SystemLifecycleOperation::Initialize).unwrap();
        assert_eq!(scanned.len(), 1);
        assert_eq!(
            scanned[0].1.as_ref().unwrap_err().0,
            "system_lifecycle_intent_unreadable"
        );
    }
    #[test]
    fn compiler_effect_hash_matches_governed_helper() {
        let plan = compiled_initialize_fixture();
        let governed_hash = governed::decision_effect_hash(AUTHORITY, &plan.authority_effect);
        let compiler_domain_hash = jcs_hash(&json!({
            "domain":"hypervisor.system-lifecycle.decision.request.v1.effect.v1",
            "effect":plan.authority_effect,
        }))
        .unwrap();
        assert_eq!(governed_hash, compiler_domain_hash);
        assert_eq!(plan.operation, SystemLifecycleOperation::Initialize);
        assert_eq!(
            plan.authority_effect["required_scope"],
            json!("scope:autonomous_system.lifecycle.initialize")
        );
        let initialized = build_admitted_step(
            &plan,
            &dummy_evidence(&plan, 0x21),
            json!({}),
            "2026-07-21T11:30:00Z",
        )
        .unwrap()
        .step;
        let activate = compile_system_activate_plan(
            &plan.source,
            &plan.deployment_profile_revision,
            &initialized,
        )
        .unwrap();
        assert_eq!(
            governed::decision_effect_hash(AUTHORITY, &activate.authority_effect),
            jcs_hash(&json!({
                "domain":"hypervisor.system-lifecycle.decision.request.v1.effect.v1",
                "effect":activate.authority_effect,
            }))
            .unwrap()
        );
    }

    #[test]
    fn node_constructor_builds_registered_initialize_and_activate_graphs() {
        let initialize_plan = compiled_initialize_fixture();
        let source_bytes = serde_jcs::to_vec(&initialize_plan.source).unwrap();
        let mut initialize_evidence = dummy_evidence(&initialize_plan, 0x31);
        let initialize_wallet = wallet_receipt_fixture(&initialize_evidence);
        let initialize_wallet =
            validate_wallet_receipt(&mut initialize_evidence, &initialize_wallet).unwrap();
        let initialize = build_admitted_step(
            &initialize_plan,
            &initialize_evidence,
            initialize_wallet,
            "2026-07-21T12:00:00Z",
        )
        .unwrap();
        assert_eq!(initialize.step.state["status"], json!("initialized"));
        assert!(initialize.active_set.is_none());
        assert!(initialize.chain.is_none());
        assert_eq!(
            graph_records(&initialize)
                .unwrap()
                .iter()
                .map(|record| record.0)
                .collect::<Vec<_>>(),
            vec![
                AUTHORITY_CONSUMPTION_DIR,
                DEPLOYMENT_DIR,
                AUTHORITY_EVIDENCE_DIR,
                PROPOSAL_DIR,
                DECISION_DIR,
                TRANSITION_DIR,
                INITIALIZE_RECEIPT_DIR,
                STATE_DIR,
            ]
        );
        for (family, record_id, value) in graph_records(&initialize).unwrap() {
            super::super::substrate_store::validate_required_identity_for_test(
                family, &record_id, value,
            )
            .unwrap();
        }
        let activate_plan = compile_system_activate_plan(
            &initialize_plan.source,
            &initialize_plan.deployment_profile_revision,
            &initialize.step,
        )
        .unwrap();
        let mut activate_evidence = dummy_evidence(&activate_plan, 0x41);
        let activate_wallet = wallet_receipt_fixture(&activate_evidence);
        let activate_wallet =
            validate_wallet_receipt(&mut activate_evidence, &activate_wallet).unwrap();
        let mut activated = build_admitted_step(
            &activate_plan,
            &activate_evidence,
            activate_wallet,
            "2026-07-21T12:01:00Z",
        )
        .unwrap();
        complete_live_graph(&mut activated, "2026-07-21T12:01:00Z").unwrap();
        assert_eq!(activated.step.state["status"], json!("active"));
        assert_eq!(
            activated.operation_log.as_ref().unwrap()["entries"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert!(activated.chain.is_some());
        assert_eq!(
            graph_records(&activated)
                .unwrap()
                .iter()
                .map(|record| record.0)
                .collect::<Vec<_>>(),
            vec![
                AUTHORITY_CONSUMPTION_DIR,
                AUTHORITY_EVIDENCE_DIR,
                PROPOSAL_DIR,
                DECISION_DIR,
                TRANSITION_DIR,
                ACTIVATION_RECEIPT_DIR,
                STATE_DIR,
                ACTIVE_SET_DIR,
                HOME_BINDING_DIR,
                OPERATION_LOG_DIR,
                CHAIN_DIR,
            ]
        );
        for (family, record_id, value) in graph_records(&activated).unwrap() {
            super::super::substrate_store::validate_required_identity_for_test(
                family, &record_id, value,
            )
            .unwrap();
        }
        assert_eq!(
            serde_jcs::to_vec(&initialize_plan.source).unwrap(),
            source_bytes
        );
    }

    #[test]
    fn wallet_receipt_must_be_complete_and_exact() {
        let plan = compiled_initialize_fixture();
        let evidence = dummy_evidence(&plan, 0x51);
        let receipt = wallet_receipt_fixture(&evidence);
        let mut accepted = evidence.clone();
        validate_wallet_receipt(&mut accepted, &receipt).unwrap();
        for mutation in [
            "request",
            "grant",
            "consumption",
            "principal",
            "scope",
            "usage",
        ] {
            let mut rejected = receipt.clone();
            match mutation {
                "request" => rejected.request_hash[0] ^= 1,
                "grant" => rejected.grant_hash[0] ^= 1,
                "consumption" => rejected.consumption_id[0] ^= 1,
                "principal" => rejected.principal_authority.approval_authority.authority_id[0] ^= 1,
                "scope" => rejected.target = ActionTarget::Custom("scope:foreign".to_owned()),
                "usage" => rejected.remaining_usages = 1,
                _ => unreachable!(),
            }
            let mut evidence = evidence.clone();
            assert_eq!(
                validate_wallet_receipt(&mut evidence, &rejected)
                    .unwrap_err()
                    .0,
                "system_lifecycle_wallet_consumption_invalid"
            );
        }
    }

    #[test]
    fn activation_refuses_detached_initialized_tuple() {
        let initialize_plan = compiled_initialize_fixture();
        let mut initialized = build_admitted_step(
            &initialize_plan,
            &dummy_evidence(&initialize_plan, 0x61),
            json!({}),
            "2026-07-21T12:00:00Z",
        )
        .unwrap()
        .step;
        initialized.state_root = format!("sha256:{}", "ff".repeat(32));
        assert!(compile_system_activate_plan(
            &initialize_plan.source,
            &initialize_plan.deployment_profile_revision,
            &initialized,
        )
        .is_err());
    }

    #[test]
    fn lifecycle_slots_are_strict_and_no_clobber() {
        let data_dir = tempfile::tempdir().unwrap();
        let data_dir = data_dir.path().to_str().unwrap();
        let tail = format!("asini_{}", "11".repeat(32));
        let value = json!({"value": 1});
        persist_local(data_dir, INITIALIZE_INTENT_DIR, &tail, &value).unwrap();
        persist_local(data_dir, INITIALIZE_INTENT_DIR, &tail, &value).unwrap();
        assert_eq!(
            persist_local(data_dir, INITIALIZE_INTENT_DIR, &tail, &json!({"value": 2}))
                .unwrap_err()
                .0,
            "system_lifecycle_conflict"
        );

        let family = std::path::Path::new(data_dir).join(ACTIVATE_INTENT_DIR);
        std::fs::create_dir_all(&family).unwrap();
        let symlink_tail = format!("asaci_{}", "22".repeat(32));
        std::os::unix::fs::symlink(
            family.join(format!("{tail}.json")),
            family.join(format!("{symlink_tail}.json")),
        )
        .unwrap();
        assert_eq!(
            persist_local(data_dir, ACTIVATE_INTENT_DIR, &symlink_tail, &value)
                .unwrap_err()
                .0,
            "system_lifecycle_artifact_unreadable"
        );
        let directory_tail = format!("asaci_{}", "33".repeat(32));
        std::fs::create_dir(family.join(format!("{directory_tail}.json"))).unwrap();
        assert_eq!(
            persist_local(data_dir, ACTIVATE_INTENT_DIR, &directory_tail, &value)
                .unwrap_err()
                .0,
            "system_lifecycle_artifact_unreadable"
        );
    }

    #[test]
    fn wallet_recovery_never_replicates_unvalidated_single_side_evidence() {
        let plan = compiled_initialize_fixture();
        let evidence = dummy_evidence(&plan, 0x77);
        let mut malformed = serde_json::to_value(wallet_receipt_fixture(&evidence)).unwrap();
        malformed["remaining_usages"] = json!(1);
        let tail = evidence.wallet_consumption_tail.clone();

        let remote = agentgres::mux::ExactProjection {
            operation: agentgres::Operation {
                domain: AUTHORITY_CONSUMPTION_DIR.to_string(),
                object_ref: format!("agentgres://{AUTHORITY_CONSUMPTION_DIR}/{tail}"),
                op_kind: format!("{AUTHORITY_CONSUMPTION_DIR}.persist"),
                expected_head: None,
                expected_absent: true,
                payload: malformed.clone(),
                recorded_at_ms: 0,
                idem_key: tail.clone(),
            },
            seq: 7,
            head: "sha256:head".to_string(),
            admission_batch_seq: 3,
            admission_root: "sha256:admission-root".to_string(),
            terminal_root: "sha256:terminal-root".to_string(),
        };
        let recovered = resolve_wallet_consumption_evidence(&tail, None, Some(remote))
            .unwrap()
            .unwrap();
        let mut remote_evidence = evidence.clone();
        let remote_receipt: ApprovalGrantConsumptionReceipt =
            serde_json::from_value(recovered).unwrap();
        assert_eq!(
            validate_wallet_receipt(&mut remote_evidence, &remote_receipt)
                .unwrap_err()
                .0,
            "system_lifecycle_wallet_consumption_invalid"
        );

        let local_evidence = dummy_evidence(&plan, 0x78);
        let mut local_malformed =
            serde_json::to_value(wallet_receipt_fixture(&local_evidence)).unwrap();
        local_malformed["remaining_usages"] = json!(1);
        let local_tail = local_evidence.wallet_consumption_tail;
        assert_eq!(
            resolve_wallet_consumption_evidence(&local_tail, Some(local_malformed.clone()), None,)
                .unwrap()
                .unwrap(),
            local_malformed
        );
    }
}
