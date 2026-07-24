//! Protected constitutional amendment execution (M1.5 m1-5c) — runtime.
//!
//! This module CONTINUES the proven protected-transition runtime at sequence
//! three or later for exactly one operation: `amend_constitution`. The same
//! durable families carry proposals, decisions, transitions, and authority
//! evidence; the amendment mints its own declaration, successor constitution,
//! successor active-profile-set (v2), and receipt families; the chain
//! revision swaps `constitution_ref`/`constitution_root` to the successor —
//! that swap is THE amendment moment. Operational status never changes here.
//!
//! Nothing in this module mints a parallel authority or persistence path:
//! wallet consumption rides `prepare_node_evidence_for` with the exact
//! `scope:autonomous_system.lifecycle.amend_constitution` scope, sealed intents ride
//! the same crash-convergent replay discipline, and every family crosses the
//! required Agentgres admission boundary.

use ioi_types::app::system_activation::UnverifiedCommittedSystemLifecycleStep;
use ioi_types::app::system_amendment_execution::{
    compile_amendment_execution_plan, CompiledAmendmentExecutionPlan, AMENDMENT_OP,
    AMENDMENT_REQUIRED_SCOPE,
};
use ioi_types::app::system_lifecycle_transitions::ProtectedLifecycleStatus;
use ioi_types::app::ApprovalGrant;
use serde_json::{json, Value};

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use ioi_services::wallet_network::{
    ApprovalGrantConsumptionReceipt, ConsumeApprovalGrantForEffectV2Params,
    ExpectedPrincipalAuthorityBinding,
};
use sha2::{Digest, Sha256};

use super::governed_authority::{
    self as governed, AuthorityContract, AuthorityPolicyContext, AuthorizedDecision, Governance,
};
use super::system_activation_routes::{
    canonical_grant, canonical_hash_str, canonical_system_key, classify, contains_sensitive_key,
    enumerate_family, evidence_from_intent, evidence_intent_value, forced_fault, hash_bytes,
    intent_seal, jcs_hash, load_local, load_required_exact, ms_to_timestamp, persist_local,
    prepare_node_evidence_for, remove_intent, required_string, tail, validate_contract,
    validate_wallet_receipt, verify_intent_seal, verr, with_source_locks, NodeAdmissionEvidence,
    ACTIVE_SET_DIR, AUTHORITY, AUTHORITY_CONSUMPTION_DIR, AUTHORITY_EVIDENCE_DIR, CHAIN_DIR,
    DECISION_DIR, MAX_REQUEST_BYTES, OPERATION_LOG_DIR, PROPOSAL_DIR, SYSTEM_ACTIVATION_GATE,
    TRANSITION_DIR,
};
use super::system_protected_transition_routes::{
    claim_chain_successor, continue_log_with_entry, ensure_no_pending_protected_intent,
    load_activation_effect, load_chain_head, load_log_for_chain, load_previous_step,
    preflight_chain_writer_grant, record_by_root, reserve_chain_writer, system_id_for_key,
    DecisionAuthorityTuple, LIFECYCLE_STATE_DIR,
};
use super::DaemonState;

const CHAIN_ROOT_DOMAIN: &str = "ioi.autonomous-system-chain-jcs-sha256.v1";
const AMENDMENT_PROPOSAL_HASH_DOMAIN: &str =
    "ioi.autonomous-system-amendment-execution-proposal-jcs-sha256.v1";
const AMENDMENT_DECISION_HASH_DOMAIN: &str =
    "ioi.autonomous-system-amendment-execution-decision-jcs-sha256.v1";
const AMENDMENT_TRANSITION_HASH_DOMAIN: &str =
    "ioi.autonomous-system-amendment-transition-jcs-sha256.v1";
const AMENDMENT_RECEIPT_HASH_DOMAIN: &str =
    "ioi.autonomous-system-amendment-receipt-artifact-jcs-sha256.v1";
const AMENDMENT_PROPOSAL_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-amendment-execution-proposal/v1";
const AMENDMENT_DECISION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-amendment-execution-decision/v1";
const AMENDMENT_DECLARATION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-constitution-amendment/v1";
const AMENDMENT_APPROVAL_DECISION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-constitution-amendment-approval-decision/v1";
const CONSTITUTION_CONTRACT: &str = "schema://ioi/foundations/autonomous-system-constitution/v1";
const ACTIVE_PROFILE_SET_V2_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-active-profile-set/v2";
const LIFECYCLE_STATE_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-lifecycle-state/v1";
const AMENDMENT_TRANSITION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-amendment-transition/v1";
const AMENDMENT_RECEIPT_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-amendment-receipt/v1";
const SYSTEM_CHAIN_CONTRACT: &str = "schema://ioi/foundations/autonomous-system-chain/v1";
const AMENDMENT_APPROVAL_OP: &str = "approve_constitution_amendment";
/// External governance approves the immutable declaration, not whichever
/// lifecycle sequence later executes it. The unique amendment subject and
/// exact effect hash carry the declaration identity; this fixed coordinate
/// keeps that one-use approval reusable when unrelated lifecycle operations
/// advance the chain before execution authorization completes.
const AMENDMENT_APPROVAL_REVISION: u64 = 0;
const AMENDMENT_APPROVAL_SCOPE: &str =
    "scope:autonomous_system.governance.approve_constitution_amendment";
const AMENDMENT_GOVERNANCE_AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "scope:autonomous_system.governance",
    policy_domain: "hypervisor.system-governance.decision.policy.v1",
    request_domain: "hypervisor.system-governance.decision.request.v1",
    resolution_domain: "hypervisor.system-governance.authority-resolution.v1",
    code_prefix: "system_governance",
    host_label: "external_governance",
    participant_label: "not_applicable",
};

/// Sealed amendment intents (`asamx_` prefix).
pub(crate) const AMENDMENT_INTENT_DIR: &str = "autonomous-system-amendment-intents";
/// Sealed pre-consumption intents for the declaration's governance approval.
pub(crate) const AMENDMENT_APPROVAL_INTENT_DIR: &str =
    "autonomous-system-amendment-governance-approval-intents";
/// Durable retirement records for pre-hardening execution intents. These
/// intents never execute under the new governance model; the record makes
/// their idempotent upgrade migration explicit before the blocker is removed.
const LEGACY_AMENDMENT_INTENT_RESOLUTION_DIR: &str =
    "autonomous-system-legacy-amendment-intent-resolutions";
/// Typed amendment receipts (`asamr_` prefix).
pub(crate) const AMENDMENT_RECEIPT_DIR: &str = "autonomous-system-amendment-receipts";
/// Retained constitution-amendment declarations (`asca_` prefix).
pub(crate) const AMENDMENT_DECLARATION_DIR: &str = "autonomous-system-constitution-amendments";
/// External-governance decisions approving declarations (`ascaad_` prefix).
pub(crate) const AMENDMENT_APPROVAL_DECISION_DIR: &str =
    "autonomous-system-constitution-amendment-approval-decisions";
/// Authenticated authority evidence for one external-governance approval.
pub(crate) const AMENDMENT_APPROVAL_AUTHORITY_EVIDENCE_DIR: &str =
    "autonomous-system-constitution-amendment-approval-authority-evidence";
/// Minted (successor) constitution bodies (`ascn_` prefix).
pub(crate) const CONSTITUTION_DIR: &str = "autonomous-system-constitutions";

type VErr = (String, String);

fn required(value: &Value, pointer: &str) -> Result<String, VErr> {
    required_string(value, pointer).map(str::to_owned)
}

fn ns(system_id: &str) -> Result<&str, VErr> {
    system_id.strip_prefix("system://").ok_or_else(|| {
        verr(
            "system_lifecycle_artifact_invalid",
            "system_id is not canonical",
        )
    })
}

fn artifact_root_with(domain: &str, artifact: &Value) -> Result<String, VErr> {
    jcs_hash(&json!({"domain": domain, "artifact": artifact}))
}

/// The exact durable truth one amendment compiles against — never the caller.
pub(crate) struct AmendmentSource {
    /// Committed sequence-two activation effect (identity carrier).
    pub activation_effect: Value,
    /// Predecessor step artifacts at chain-head sequence.
    pub previous_step: UnverifiedCommittedSystemLifecycleStep,
    /// The current chain head revision (highest `latest_sequence`).
    pub chain_head: Value,
    /// The current operation log revision matching the chain head.
    pub operation_log: Value,
    /// The chain's ACTIVE constitution body (genesis bundle or minted).
    pub predecessor_constitution: Value,
    /// The predecessor state's exact active profile set (v1 or v2).
    pub predecessor_profile_set: Value,
}

/// Load the chain's active constitution body for `constitution_root`:
/// a minted successor persists content-addressed in its own family; the
/// genesis constitution lives verbatim in the admitted initial profile
/// bundle, bound by its declared root.
fn load_constitution_body(
    data_dir: &str,
    genesis_record: &Value,
    constitution_root: &str,
) -> Result<Value, VErr> {
    if !canonical_hash_str(constitution_root) {
        return Err(verr(
            "system_lifecycle_artifact_invalid",
            "chain head carries a non-canonical constitution_root",
        ));
    }
    if let Some(minted) = load_required_exact(
        data_dir,
        CONSTITUTION_DIR,
        &tail("ascn_", constitution_root)?,
    )? {
        return Ok(minted);
    }
    let bundle = genesis_record
        .pointer("/initial_profile_bundle/constitution")
        .cloned()
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_mismatch",
                "admitted genesis lacks its initial profile bundle constitution",
            )
        })?;
    // The chain names a constitution by its authoritative profile-candidate
    // root, not by the body's declared self-root field.
    let bundle_root =
        ioi_types::app::system_amendment_execution::constitution_candidate_root(&bundle)
            .map_err(|error| verr("system_lifecycle_artifact_invalid", error))?;
    if bundle_root != constitution_root {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "no durable constitution body recomputes to the chain's constitution_root",
        ));
    }
    Ok(bundle)
}

/// Reconstruct the complete durable truth an amendment compiles against,
/// cross-checking chain head, operation log, and predecessor step exactly
/// like the protected loader before any compile happens.
pub(crate) fn load_amendment_source(
    data_dir: &str,
    key: &str,
) -> Result<(String, AmendmentSource), VErr> {
    let admission = super::system_genesis_routes::load_verified_admission_by_key(data_dir, key)?
        .ok_or_else(|| {
            verr(
                "system_lifecycle_not_found",
                "no admitted genesis exists for this id",
            )
        })?;
    let system_id = required(&admission.record, "/authorized_genesis/system_id")
        .or_else(|_| required(&admission.record, "/system_id"))?;
    let chain_head = load_chain_head(data_dir, &system_id)?;
    let operation_log = load_log_for_chain(data_dir, &chain_head)?;
    let previous_step = load_previous_step(data_dir, &operation_log)?;
    for (pointer, label) in [
        ("/latest_state_root", "state"),
        ("/latest_transition_root", "transition"),
        ("/latest_receipt_root", "receipt"),
    ] {
        let chain_value = required(&chain_head, pointer)?;
        let log_value = required(&operation_log, pointer)?;
        if chain_value != log_value {
            return Err(verr(
                "system_lifecycle_artifact_mismatch",
                format!("chain head and operation log disagree on the latest {label} root"),
            ));
        }
    }
    if required(&chain_head, "/latest_state_root")? != previous_step.state_root {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "reconstructed predecessor step detaches from the chain head",
        ));
    }
    let activation_effect = load_activation_effect(data_dir, &system_id)?;
    let constitution_root = required(&chain_head, "/constitution_root")?;
    let constitution_ref = required(&chain_head, "/constitution_ref")?;
    let predecessor_constitution =
        load_constitution_body(data_dir, &admission.record, &constitution_root)?;
    if predecessor_constitution
        .get("constitution_id")
        .and_then(Value::as_str)
        != Some(constitution_ref.as_str())
    {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "durable constitution body does not carry the chain's constitution_ref identity",
        ));
    }
    let set_root = required(&previous_step.state, "/active_profile_set_root")?;
    let set_ref = required(&previous_step.state, "/active_profile_set_ref")?;
    let predecessor_profile_set =
        load_required_exact(data_dir, ACTIVE_SET_DIR, &tail("asaps_", &set_root)?)?.ok_or_else(
            || {
                verr(
                    "system_lifecycle_artifact_mismatch",
                    "the predecessor state's active profile set is not durably admitted",
                )
            },
        )?;
    if predecessor_profile_set
        .get("active_profile_set_ref")
        .and_then(Value::as_str)
        != Some(set_ref.as_str())
    {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "durable active profile set does not carry the predecessor state's set ref",
        ));
    }
    Ok((
        system_id,
        AmendmentSource {
            activation_effect,
            previous_step,
            chain_head,
            operation_log,
            predecessor_constitution,
            predecessor_profile_set,
        },
    ))
}

/// Compile one amendment from durable truth plus the proposed declaration
/// and successor body. Both proposed objects are contract-validated before
/// the semantic compiler sees them.
pub(crate) fn compile_amendment_from_source(
    source: &AmendmentSource,
    amendment: &Value,
    approval_decision: &Value,
    approval_authority_evidence_root: &str,
    successor_constitution: &Value,
) -> Result<CompiledAmendmentExecutionPlan, VErr> {
    // These two bodies are CALLER-supplied: a contract violation here is a
    // bad request, not a server fault, so it must not classify as a 500 the
    // way a server-built artifact legitimately does.
    fn caller_input((_, message): VErr) -> VErr {
        verr("system_lifecycle_request_invalid", message)
    }
    validate_contract(
        AMENDMENT_DECLARATION_CONTRACT,
        amendment,
        "amendment declaration",
    )
    .map_err(caller_input)?;
    validate_contract(
        AMENDMENT_APPROVAL_DECISION_CONTRACT,
        approval_decision,
        "amendment approval decision",
    )
    .map_err(caller_input)?;
    validate_contract(
        CONSTITUTION_CONTRACT,
        successor_constitution,
        "successor constitution",
    )
    .map_err(caller_input)?;
    let chain_head_root = required(&source.chain_head, "/chain_root")?;
    let chain_constitution_root = required(&source.chain_head, "/constitution_root")?;
    let activation_receipt_ref = source
        .operation_log
        .get("entries")
        .and_then(Value::as_array)
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry.get("sequence").and_then(Value::as_u64) == Some(2))
        })
        .and_then(|entry| entry.get("receipt_ref"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_mismatch",
                "operation log lacks its committed sequence-two activation receipt",
            )
        })?;
    compile_amendment_execution_plan(
        &source.activation_effect,
        &source.previous_step,
        &chain_head_root,
        &chain_constitution_root,
        activation_receipt_ref,
        amendment,
        approval_decision,
        approval_authority_evidence_root,
        &source.predecessor_constitution,
        successor_constitution,
        &source.predecessor_profile_set,
    )
    .map_err(|error| verr("system_lifecycle_plan_invalid", error))
}

fn approval_governance_authority(source: &AmendmentSource) -> Result<String, VErr> {
    let accountable = source
        .predecessor_constitution
        .pointer("/governance/governance_owner_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "system_governance_profile_invalid",
                "active constitution lacks external governance owners",
            )
        })?;
    if accountable.len() != 1 {
        return Err(verr(
            "system_governance_profile_unavailable",
            "the selected M1 profile requires exactly one external governance owner",
        ));
    }
    let authority = accountable[0]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            verr(
                "system_governance_profile_invalid",
                "external governance owner is not canonical",
            )
        })?;
    if authority.starts_with("system://") || authority.starts_with("agent://") {
        return Err(verr(
            "system_governance_profile_invalid",
            "an agent or System principal cannot issue amendment approval",
        ));
    }
    Ok(authority.to_owned())
}

fn amendment_approval_effect(
    source: &AmendmentSource,
    plan: &CompiledAmendmentExecutionPlan,
) -> Result<Value, VErr> {
    Ok(json!({
        "schema_version": "ioi.hypervisor.constitution-amendment-governance-approval-effect.v1",
        "operation": AMENDMENT_APPROVAL_OP,
        "required_scope": AMENDMENT_APPROVAL_SCOPE,
        "system_id": required(&source.activation_effect, "/system_id")?,
        "genesis_ref": required(&source.activation_effect, "/genesis_ref")?,
        "governing_decision_profile_ref": required(
            &source.predecessor_constitution,
            "/governance/amendment_decision_profile_ref",
        )?,
        "deciding_authority_ref": approval_governance_authority(source)?,
        "amendment_ref": required(&plan.amendment, "/amendment_id")?,
        "amendment_root": plan.amendment_root,
        "approval_decision_ref": required(&plan.approval_decision, "/decision_ref")?,
        "approval_decision_root": plan.approval_decision_root,
        "predecessor_constitution_root": required(&source.chain_head, "/constitution_root")?,
        "successor_constitution_root": plan.successor_constitution_root,
        "changed_field_paths_commitment": plan.changed_field_paths_commitment,
        "evidence_refs": plan.amendment["evidence_refs"],
        "authority_requirement_refs": plan.amendment["authority_requirement_refs"],
        "proposed_by_ref": plan.amendment["proposed_by_ref"],
        "outcome": "approved",
    }))
}

fn governance_approval_request_hash(
    source: &AmendmentSource,
    plan: &CompiledAmendmentExecutionPlan,
    effect_hash: &str,
) -> Result<String, VErr> {
    Ok(governed::decision_request_hash(
        AMENDMENT_GOVERNANCE_AUTHORITY,
        Governance::Host,
        &required(&plan.amendment, "/amendment_id")?,
        AMENDMENT_APPROVAL_OP,
        AMENDMENT_APPROVAL_REVISION,
        &approval_governance_authority(source)?,
        effect_hash,
    ))
}

struct GovernanceApprovalWalletUse {
    grant: ApprovalGrant,
    params: ConsumeApprovalGrantForEffectV2Params,
    consumption_ref: String,
}

struct GovernanceApprovalConsumptionFailure {
    error: VErr,
    definitively_unconsumed: bool,
}

fn governance_approval_wallet_use(
    source: &AmendmentSource,
    plan: &CompiledAmendmentExecutionPlan,
    effect: &Value,
    authorized: &AuthorizedDecision,
) -> Result<GovernanceApprovalWalletUse, VErr> {
    if authorized.evidence.authorized_effect != *effect {
        return Err(verr(
            "system_governance_approval_invalid",
            "governance authority detached the exact approval effect",
        ));
    }
    let required_authority = approval_governance_authority(source)?;
    let system_id = required(&source.activation_effect, "/system_id")?;
    let genesis_ref = required(&source.activation_effect, "/genesis_ref")?;
    let expected_policy_hash = governed::decision_policy_hash_for_context(
        AMENDMENT_GOVERNANCE_AUTHORITY,
        Governance::Host,
        AuthorityPolicyContext::SystemGenesis {
            system_id: &system_id,
            genesis_id: &genesis_ref,
        },
        &required_authority,
        AMENDMENT_APPROVAL_OP,
    );
    let expected_effect_hash =
        governed::decision_effect_hash(AMENDMENT_GOVERNANCE_AUTHORITY, effect);
    let expected_request_hash =
        governance_approval_request_hash(source, plan, &expected_effect_hash)?;
    let (grant, portable_grant_ref) = canonical_grant(authorized).map_err(|(_, message)| {
        verr(
            "system_governance_approval_invalid",
            format!("governance approval grant is invalid ({message})"),
        )
    })?;
    let wallet_grant_ref = format!(
        "wallet.network://grant/approval/{}",
        portable_grant_ref
            .strip_prefix("grant://wallet.network/approval/sha256:")
            .ok_or_else(|| {
                verr(
                    "system_governance_approval_invalid",
                    "governance approval grant identity is not canonical",
                )
            })?
    );
    if authorized.evidence.grant_ref != wallet_grant_ref
        || authorized.evidence.policy_hash != expected_policy_hash
        || authorized.evidence.effect_hash != expected_effect_hash
        || authorized.evidence.request_hash != expected_request_hash
        || grant.policy_hash != hash_bytes(&expected_policy_hash, "policy_hash")?
        || grant.request_hash != hash_bytes(&expected_request_hash, "request_hash")?
        || grant.max_usages != Some(1)
    {
        return Err(verr(
            "system_governance_approval_invalid",
            "governance approval grant does not bind the exact one-use decision",
        ));
    }
    let expected_principal_authority: ExpectedPrincipalAuthorityBinding =
        serde_json::from_value(authorized.evidence.authority_binding.clone()).map_err(|error| {
            verr(
                "system_governance_approval_invalid",
                format!("governance authority binding is invalid ({error})"),
            )
        })?;
    if expected_principal_authority.principal_ref != required_authority
        || expected_principal_authority.required_scope != AMENDMENT_APPROVAL_SCOPE
        || expected_principal_authority.approval_authority.authority_id != grant.authority_id
        || expected_principal_authority.approval_authority.public_key != grant.approver_public_key
        || expected_principal_authority
            .approval_authority
            .signature_suite
            != grant.approver_suite
    {
        return Err(verr(
            "system_governance_approval_invalid",
            "governance grant signer, principal, or scope differs from committed governance",
        ));
    }
    let request_hash = hash_bytes(&expected_request_hash, "request_hash")?;
    let grant_hash = grant.artifact_hash().map_err(|error| {
        verr(
            "system_governance_approval_invalid",
            format!("governance approval grant cannot be hashed ({error})"),
        )
    })?;
    let consumption_hash = jcs_hash(&json!({
        "domain": "ioi.hypervisor.constitution-amendment-governance-approval-authority-use.v1",
        "system_id": system_id,
        "amendment_root": plan.amendment_root,
        "approval_decision_root": plan.approval_decision_root,
        "effect_hash": expected_effect_hash,
        "grant_hash": format!("sha256:{}", hex::encode(grant_hash)),
        "principal_authority": required_authority,
    }))?;
    let consumption_id = hash_bytes(&consumption_hash, "consumption_id")?;
    Ok(GovernanceApprovalWalletUse {
        grant,
        params: ConsumeApprovalGrantForEffectV2Params {
            request_hash,
            grant_hash,
            consumption_id,
            expected_principal_authority,
            expected_target_label: AMENDMENT_APPROVAL_SCOPE.to_owned(),
            expected_max_usages: 1,
        },
        consumption_ref: format!(
            "wallet.network://approval-effect-consumption/{}/{}",
            hex::encode(request_hash),
            hex::encode(consumption_id),
        ),
    })
}

fn validate_governance_approval_wallet_receipt(
    use_: &GovernanceApprovalWalletUse,
    receipt: &ApprovalGrantConsumptionReceipt,
) -> Result<(Value, String), VErr> {
    let mut receipt_material = serde_json::to_value(receipt)
        .map_err(|error| verr("system_governance_approval_invalid", error.to_string()))?;
    receipt_material["receipt_hash"] = json!(vec![0u8; 32]);
    let expected_receipt_hash: [u8; 32] = Sha256::digest(
        serde_jcs::to_vec(&receipt_material)
            .map_err(|error| verr("system_governance_approval_invalid", error.to_string()))?,
    )
    .into();
    let grant = &use_.grant;
    if receipt.schema_version != 1
        || receipt.request_hash != use_.params.request_hash
        || receipt.grant_hash != use_.params.grant_hash
        || receipt.consumption_id != use_.params.consumption_id
        || receipt.principal_authority != use_.params.expected_principal_authority
        || receipt.receipt_hash != expected_receipt_hash
        || receipt.policy_hash != grant.policy_hash
        || receipt.authority_id != grant.authority_id
        || receipt.target.canonical_label() != AMENDMENT_APPROVAL_SCOPE
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
            "system_governance_approval_invalid",
            "wallet receipt does not bind the current exact one-use governance approval grant",
        ));
    }
    let value = serde_json::to_value(receipt)
        .map_err(|error| verr("system_governance_approval_invalid", error.to_string()))?;
    let root = artifact_root_with(
        "ioi.hypervisor.constitution-amendment-governance-approval-consumption-jcs-sha256.v1",
        &value,
    )?;
    Ok((value, root))
}

fn approval_authority_evidence(
    source: &AmendmentSource,
    plan: &CompiledAmendmentExecutionPlan,
    effect: &Value,
    authorized: AuthorizedDecision,
    wallet_receipt: ApprovalGrantConsumptionReceipt,
) -> Result<Value, VErr> {
    let wallet_use = governance_approval_wallet_use(source, plan, effect, &authorized)?;
    let (wallet_consumption, wallet_consumption_root) =
        validate_governance_approval_wallet_receipt(&wallet_use, &wallet_receipt)?;
    let decision_hex = plan
        .approval_decision_root
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64)
        .ok_or_else(|| {
            verr(
                "system_governance_approval_invalid",
                "approval decision root is not canonical",
            )
        })?;
    let mut evidence = json!({
        "schema_version": "ioi.hypervisor.constitution-amendment-governance-approval-evidence.v1",
        "approval_authority_evidence_ref": format!(
            "system-governance-approval-evidence://ascaae_{decision_hex}"
        ),
        "approval_authority_evidence_root": Value::Null,
        "approval_decision_root": plan.approval_decision_root,
        "amendment_root": plan.amendment_root,
        "required_scope": AMENDMENT_APPROVAL_SCOPE,
        "acting_authority_id": authorized.evidence.acting_authority_id,
        "authority_grant_ref": authorized.evidence.grant_ref,
        "policy_hash": authorized.evidence.policy_hash,
        "request_hash": authorized.evidence.request_hash,
        "effect_hash": authorized.evidence.effect_hash,
        "authorized_effect": authorized.evidence.authorized_effect,
        "wallet_approval_grant": authorized.evidence.wallet_approval_grant,
        "principal_authority_binding": authorized.evidence.authority_binding,
        "authority_resolved_at_ms": authorized.resolved_at_ms,
        "wallet_grant_consumption_ref": wallet_use.consumption_ref,
        "wallet_grant_consumption_root": wallet_consumption_root,
        "wallet_grant_consumption": wallet_consumption,
    });
    if evidence["authorized_effect"] != *effect {
        return Err(verr(
            "system_governance_approval_invalid",
            "governance authority detached the exact approval effect",
        ));
    }
    let root = jcs_hash(&json!({
        "domain": "ioi.hypervisor.constitution-amendment-governance-approval-evidence-jcs-sha256.v1",
        "evidence": evidence,
    }))?;
    evidence["approval_authority_evidence_root"] = json!(root);
    Ok(evidence)
}

fn validate_approval_authority_evidence(
    source: &AmendmentSource,
    plan: &CompiledAmendmentExecutionPlan,
    evidence: &Value,
) -> Result<String, VErr> {
    let expected_effect = amendment_approval_effect(source, plan)?;
    if evidence.get("schema_version").and_then(Value::as_str)
        != Some("ioi.hypervisor.constitution-amendment-governance-approval-evidence.v1")
        || evidence.get("approval_decision_root") != Some(&json!(plan.approval_decision_root))
        || evidence.get("amendment_root") != Some(&json!(plan.amendment_root))
        || evidence.get("required_scope").and_then(Value::as_str) != Some(AMENDMENT_APPROVAL_SCOPE)
        || evidence.get("authorized_effect") != Some(&expected_effect)
    {
        return Err(verr(
            "system_governance_approval_invalid",
            "durable governance approval evidence does not bind the exact decision",
        ));
    }
    let retained = governed::DecisionEvidence {
        acting_authority_id: evidence
            .get("acting_authority_id")
            .cloned()
            .unwrap_or(Value::Null),
        grant_ref: evidence
            .get("authority_grant_ref")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        policy_hash: evidence
            .get("policy_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        request_hash: evidence
            .get("request_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        effect_hash: evidence
            .get("effect_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        authorized_effect: evidence
            .get("authorized_effect")
            .cloned()
            .unwrap_or(Value::Null),
        wallet_approval_grant: evidence
            .get("wallet_approval_grant")
            .cloned()
            .unwrap_or(Value::Null),
        authority_binding: evidence
            .get("principal_authority_binding")
            .cloned()
            .unwrap_or(Value::Null),
    };
    let required_authority = approval_governance_authority(source)?;
    let expected_policy_hash = governed::decision_policy_hash_for_context(
        AMENDMENT_GOVERNANCE_AUTHORITY,
        Governance::Host,
        AuthorityPolicyContext::SystemGenesis {
            system_id: &required(&source.activation_effect, "/system_id")?,
            genesis_id: &required(&source.activation_effect, "/genesis_ref")?,
        },
        &required_authority,
        AMENDMENT_APPROVAL_OP,
    );
    let expected_effect_hash =
        governed::decision_effect_hash(AMENDMENT_GOVERNANCE_AUTHORITY, &expected_effect);
    let expected_request_hash =
        governance_approval_request_hash(source, plan, &expected_effect_hash)?;
    if retained.policy_hash != expected_policy_hash
        || retained.effect_hash != expected_effect_hash
        || retained.request_hash != expected_request_hash
    {
        return Err(verr(
            "system_governance_approval_invalid",
            "durable governance approval hashes detach from the exact authority context and effect",
        ));
    }
    let authority_resolved_at_ms = evidence
        .get("authority_resolved_at_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            verr(
                "system_governance_approval_invalid",
                "durable governance approval lacks its authenticated resolution time",
            )
        })?;
    governed::verify_retained_decision_evidence(
        &retained,
        authority_resolved_at_ms,
        &required_authority,
        AMENDMENT_APPROVAL_SCOPE,
    )
    .map_err(|error| {
        verr(
            "system_governance_approval_invalid",
            format!("durable governance approval signature does not reverify ({error})"),
        )
    })?;
    let retained_authorized = AuthorizedDecision {
        evidence: retained,
        resolved_at_ms: authority_resolved_at_ms,
    };
    let wallet_use =
        governance_approval_wallet_use(source, plan, &expected_effect, &retained_authorized)?;
    let wallet_receipt: ApprovalGrantConsumptionReceipt = serde_json::from_value(
        evidence
            .get("wallet_grant_consumption")
            .cloned()
            .ok_or_else(|| {
                verr(
                    "system_governance_approval_invalid",
                    "durable governance approval lacks wallet consumption evidence",
                )
            })?,
    )
    .map_err(|error| {
        verr(
            "system_governance_approval_invalid",
            format!("wallet consumption evidence is malformed ({error})"),
        )
    })?;
    let (_, wallet_consumption_root) =
        validate_governance_approval_wallet_receipt(&wallet_use, &wallet_receipt)?;
    if evidence
        .get("wallet_grant_consumption_ref")
        .and_then(Value::as_str)
        != Some(wallet_use.consumption_ref.as_str())
        || evidence
            .get("wallet_grant_consumption_root")
            .and_then(Value::as_str)
            != Some(wallet_consumption_root.as_str())
    {
        return Err(verr(
            "system_governance_approval_invalid",
            "durable governance approval names a foreign wallet consumption",
        ));
    }
    let mut material = evidence.clone();
    material["approval_authority_evidence_root"] = Value::Null;
    let root = jcs_hash(&json!({
        "domain": "ioi.hypervisor.constitution-amendment-governance-approval-evidence-jcs-sha256.v1",
        "evidence": material,
    }))?;
    if evidence
        .get("approval_authority_evidence_root")
        .and_then(Value::as_str)
        != Some(root.as_str())
    {
        return Err(verr(
            "system_governance_approval_invalid",
            "durable governance approval evidence root does not recompute",
        ));
    }
    Ok(root)
}

fn approval_evidence_tail(decision_root: &str) -> Result<String, VErr> {
    tail("ascaae_", decision_root)
}

fn approval_intent_tail(params: &ConsumeApprovalGrantForEffectV2Params) -> String {
    format!("asagai_{}", hex::encode(params.consumption_id))
}

fn seal_approval_intent(
    key: &str,
    body: &Value,
    plan: &CompiledAmendmentExecutionPlan,
    effect: &Value,
    authorized: &AuthorizedDecision,
    wallet_use: &GovernanceApprovalWalletUse,
) -> Result<(String, Value), VErr> {
    let record_tail = approval_intent_tail(&wallet_use.params);
    let value = intent_seal(json!({
        "schema_version": "ioi.hypervisor.constitution-amendment-governance-approval-intent.v1",
        "source_record_tail": key,
        "op": AMENDMENT_APPROVAL_OP,
        "request_body": body,
        "compiled_plan": plan_to_value(plan)?,
        "approval_effect": effect,
        "authorized_approval": serde_json::to_value(authorized)
            .map_err(|error| verr("system_lifecycle_intent_invalid", error.to_string()))?,
        "wallet_params": serde_json::to_value(&wallet_use.params)
            .map_err(|error| verr("system_lifecycle_intent_invalid", error.to_string()))?,
        "intent_hash": Value::Null,
    }))?;
    Ok((record_tail, value))
}

fn verify_approval_intent_coordinates(record_tail: &str, intent: &Value) -> Result<(), VErr> {
    if intent.get("schema_version").and_then(Value::as_str)
        != Some("ioi.hypervisor.constitution-amendment-governance-approval-intent.v1")
        || intent.get("op").and_then(Value::as_str) != Some(AMENDMENT_APPROVAL_OP)
    {
        return Err(verr(
            "system_lifecycle_intent_invalid",
            "intent is not a constitution-amendment governance-approval intent",
        ));
    }
    let params: ConsumeApprovalGrantForEffectV2Params =
        serde_json::from_value(intent.get("wallet_params").cloned().ok_or_else(|| {
            verr(
                "system_lifecycle_intent_invalid",
                "intent lacks wallet_params",
            )
        })?)
        .map_err(|error| verr("system_lifecycle_intent_invalid", error.to_string()))?;
    if approval_intent_tail(&params) != record_tail {
        return Err(verr(
            "system_lifecycle_intent_invalid",
            "governance approval intent tail does not bind its consumption id",
        ));
    }
    Ok(())
}

async fn recover_or_consume_governance_approval(
    wallet_use: &GovernanceApprovalWalletUse,
) -> Result<ApprovalGrantConsumptionReceipt, GovernanceApprovalConsumptionFailure> {
    use super::wallet_network_capability_client::ResolveError;

    let failure = |error: ResolveError, definitively_unconsumed| {
        let error = match error {
            ResolveError::NotConfigured(message) | ResolveError::Unavailable(message) => {
                verr("system_governance_wallet_consumption_unavailable", message)
            }
            ResolveError::Refused(message) => {
                verr("system_governance_wallet_consumption_refused", message)
            }
            ResolveError::Invalid(message) => {
                verr("system_governance_wallet_consumption_invalid", message)
            }
        };
        GovernanceApprovalConsumptionFailure {
            error,
            definitively_unconsumed,
        }
    };

    match super::wallet_network_capability_client::recover_approval_grant_consumption_for_effect_v2(
        &wallet_use.params,
    )
    .await
    {
        Ok(Some(value)) => Ok(value),
        Ok(None) => {
            match super::wallet_network_capability_client::consume_approval_grant_for_effect_v2(
                wallet_use.params.clone(),
            )
            .await
            {
                Ok(value) => Ok(value),
                Err(error @ ResolveError::Refused(_)) => {
                    // A refusal is definitive only after a second recovery proves
                    // that a racing consumer did not commit the receipt between
                    // the first recovery and this consume attempt.
                    match super::wallet_network_capability_client::
                    recover_approval_grant_consumption_for_effect_v2(&wallet_use.params)
                    .await
                {
                    Ok(Some(value)) => Ok(value),
                    Ok(None) => Err(failure(error, true)),
                    Err(recovery_error) => Err(failure(recovery_error, false)),
                }
                }
                Err(error) => Err(failure(error, false)),
            }
        }
        Err(error) => Err(failure(error, false)),
    }
}

fn remove_matching_approval_intent(
    data_dir: &str,
    tail_value: &str,
    expected: &Value,
) -> Result<(), VErr> {
    with_source_locks(
        || match load_local(data_dir, AMENDMENT_APPROVAL_INTENT_DIR, tail_value)? {
            Some(current) if current == *expected => {
                remove_intent(data_dir, AMENDMENT_APPROVAL_INTENT_DIR, tail_value)
            }
            Some(_) => Err(verr(
                "system_lifecycle_intent_unreadable",
                "governance approval intent changed before refusal cleanup",
            )),
            None => Ok(()),
        },
    )
}

fn load_approval_authority_evidence(
    data_dir: &str,
    source: &AmendmentSource,
    plan: &CompiledAmendmentExecutionPlan,
) -> Result<Option<(Value, String)>, VErr> {
    let record_tail = approval_evidence_tail(&plan.approval_decision_root)?;
    let local = super::system_activation_routes::load_local(
        data_dir,
        AMENDMENT_APPROVAL_AUTHORITY_EVIDENCE_DIR,
        &record_tail,
    )?;
    let remote = super::substrate_store::read_required_exact(
        data_dir,
        AMENDMENT_APPROVAL_AUTHORITY_EVIDENCE_DIR,
        &record_tail,
    )
    .map_err(|error| {
        verr(
            "system_lifecycle_agentgres_evidence_mismatch",
            format!("governance approval recovery proof failed ({error})"),
        )
    })?;
    let remote_value = remote
        .map(|exact| {
            super::substrate_store::validate_required_exact_projection(
                AMENDMENT_APPROVAL_AUTHORITY_EVIDENCE_DIR,
                &record_tail,
                exact,
            )
            .map_err(|error| {
                verr(
                    "system_lifecycle_agentgres_evidence_mismatch",
                    format!("governance approval recovery proof failed ({error})"),
                )
            })
        })
        .transpose()?;
    let evidence = match (&local, &remote_value) {
        (None, None) => return Ok(None),
        (Some(local), Some(remote)) if local != remote => {
            return Err(verr(
                "system_lifecycle_agentgres_evidence_mismatch",
                "governance approval local and Agentgres evidence disagree",
            ));
        }
        (Some(local), _) => local.clone(),
        (None, Some(remote)) => remote.clone(),
    };
    let root = validate_approval_authority_evidence(source, plan, &evidence)?;

    // A governance approval consumes a one-use wallet grant before this
    // projection is made durable. Repair either half of an interrupted
    // dual-write from its independently validated peer so a crash cannot
    // strand the consumed approval. Validation always precedes replication.
    match (local.is_some(), remote_value.is_some()) {
        (true, false) => super::substrate_store::admit_required(
            data_dir,
            AMENDMENT_APPROVAL_AUTHORITY_EVIDENCE_DIR,
            &record_tail,
            &evidence,
        )
        .map_err(|error| {
            verr(
                "system_governance_approval_admission_failed",
                format!("governance approval recovery admission failed ({error})"),
            )
        })?,
        (false, true) => persist_local(
            data_dir,
            AMENDMENT_APPROVAL_AUTHORITY_EVIDENCE_DIR,
            &record_tail,
            &evidence,
        )?,
        _ => {}
    }
    super::substrate_store::verify_required_exact(
        data_dir,
        AMENDMENT_APPROVAL_AUTHORITY_EVIDENCE_DIR,
        &record_tail,
        &evidence,
    )
    .map_err(|error| {
        verr(
            "system_lifecycle_agentgres_evidence_mismatch",
            format!("governance approval exact proof failed after recovery ({error})"),
        )
    })?;
    Ok(Some((evidence, root)))
}

fn persist_governance_approval(
    data_dir: &str,
    source: &AmendmentSource,
    plan: &CompiledAmendmentExecutionPlan,
    evidence: &Value,
) -> Result<String, VErr> {
    let root = validate_approval_authority_evidence(source, plan, evidence)?;
    let records = [
        (
            AMENDMENT_DECLARATION_DIR,
            tail("asca_", &plan.amendment_root)?,
            &plan.amendment,
        ),
        (
            AMENDMENT_APPROVAL_DECISION_DIR,
            tail("ascaad_", &plan.approval_decision_root)?,
            &plan.approval_decision,
        ),
        (
            AMENDMENT_APPROVAL_AUTHORITY_EVIDENCE_DIR,
            approval_evidence_tail(&plan.approval_decision_root)?,
            evidence,
        ),
    ];
    for (family, record_tail, value) in records {
        persist_local(data_dir, family, &record_tail, value)?;
        if forced_fault(
            "IOI_TEST_FORCE_SYSTEM_AMENDMENT_AFTER_LOCAL_PERSIST",
            family,
        ) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                format!("test-forced interruption after local '{family}/{record_tail}'"),
            ));
        }
        super::substrate_store::admit_required(data_dir, family, &record_tail, value).map_err(
            |error| {
                verr(
                    "system_governance_approval_admission_failed",
                    format!("durable governance approval admission failed ({error})"),
                )
            },
        )?;
        if forced_fault(
            "IOI_TEST_FORCE_SYSTEM_AMENDMENT_AFTER_AGENTGRES_ADMIT",
            family,
        ) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                format!("test-forced interruption after Agentgres '{family}/{record_tail}'"),
            ));
        }
    }
    Ok(root)
}

/// Canonical sealed projection of a compiled amendment plan. The plan type
/// deliberately stays outside serde; this projection is the byte-exact
/// rebinding subject for sealed intents and replay.
pub(crate) fn plan_to_value(plan: &CompiledAmendmentExecutionPlan) -> Result<Value, VErr> {
    Ok(json!({
        "sequence": plan.sequence,
        "status": plan.status.as_str(),
        "previous_step": serde_json::to_value(&plan.previous_step)
            .map_err(|error| verr("system_lifecycle_intent_invalid", error.to_string()))?,
        "amendment": plan.amendment,
        "amendment_root": plan.amendment_root,
        "approval_decision": plan.approval_decision,
        "approval_decision_root": plan.approval_decision_root,
        "successor_constitution": plan.successor_constitution,
        "successor_constitution_root": plan.successor_constitution_root,
        "changed_field_paths": plan.changed_field_paths,
        "changed_field_paths_commitment": plan.changed_field_paths_commitment,
        "successor_profile_set": plan.successor_profile_set,
        "successor_profile_set_root": plan.successor_profile_set_root,
        "semantic_state": plan.semantic_state,
        "resulting_state_root": plan.resulting_state_root,
        "authority_effect": plan.authority_effect,
    }))
}

/// One fully built amendment step: the lifecycle tuple plus the retained
/// declaration, the minted successor constitution, the successor profile
/// set (admitted_by slots filled), the continued log, and the chain
/// revision that swaps the constitution.
#[derive(Debug)]
pub(crate) struct AmendmentStepArtifacts {
    pub step: UnverifiedCommittedSystemLifecycleStep,
    pub declaration: Value,
    pub declaration_root: String,
    pub approval_decision: Value,
    pub approval_decision_root: String,
    pub successor_constitution: Value,
    pub successor_profile_set: Value,
    pub operation_log: Value,
    pub chain: Value,
}

/// Build and validate the complete typed amendment step.
pub(crate) fn build_amendment_artifacts(
    plan: &CompiledAmendmentExecutionPlan,
    source: &AmendmentSource,
    authority: &DecisionAuthorityTuple,
    timestamp: &str,
) -> Result<AmendmentStepArtifacts, VErr> {
    let effect = &plan.authority_effect;
    let system_id = required(effect, "/system_id")?;
    let genesis_ref = required(effect, "/genesis_ref")?;
    let operation_commitment = required(effect, "/operation_commitment")?;
    let sequence = plan.sequence;
    let amendment_ref = required(&plan.amendment, "/amendment_id")?;
    let predecessor_constitution_ref = required(&plan.amendment, "/predecessor_constitution_ref")?;
    let predecessor_constitution_root = required(effect, "/predecessor_constitution_root")?;
    let successor_constitution_ref = required(&plan.successor_constitution, "/constitution_id")?;
    // The proposal's authority_effect_hash is contract-pinned as the plain
    // canonical JCS hash of the embedded effect (NOT the governed
    // domain-separated decision hash).
    let authority_effect_hash = jcs_hash(effect)?;

    validate_contract(
        AMENDMENT_DECLARATION_CONTRACT,
        &plan.amendment,
        "amendment declaration",
    )?;
    validate_contract(
        AMENDMENT_APPROVAL_DECISION_CONTRACT,
        &plan.approval_decision,
        "amendment approval decision",
    )?;
    validate_contract(
        CONSTITUTION_CONTRACT,
        &plan.successor_constitution,
        "successor constitution",
    )?;

    let proposal_ref = format!(
        "proposal://{}/amend-constitution/{sequence}",
        ns(&system_id)?
    );
    let proposal_material = json!({
        "domain": AMENDMENT_PROPOSAL_HASH_DOMAIN,
        "proposal_ref": proposal_ref,
        "system_id": system_id,
        "genesis_ref": genesis_ref,
        "op": AMENDMENT_OP,
        "sequence": sequence,
        "amendment_ref": amendment_ref,
        "amendment_root": plan.amendment_root,
        "approval_decision_root": plan.approval_decision_root,
        "predecessor_constitution_ref": predecessor_constitution_ref,
        "predecessor_constitution_root": predecessor_constitution_root,
        "successor_constitution_ref": successor_constitution_ref,
        "successor_constitution_root": plan.successor_constitution_root,
        "changed_field_paths_commitment": plan.changed_field_paths_commitment,
        "predecessor_status": plan.status.as_str(),
        "predecessor_state_root": plan.previous_step.state_root,
        "predecessor_chain_head_root": effect["predecessor_chain_head_root"],
        "irreversibility": "one_way",
        "required_scope": AMENDMENT_REQUIRED_SCOPE,
        "operation_commitment": operation_commitment,
        "authority_effect": effect,
        "authority_effect_hash": authority_effect_hash,
        "status": "proposed",
        "created_at": timestamp,
    });
    let proposal_root = jcs_hash(&proposal_material)?;
    let mut proposal = proposal_material;
    proposal.as_object_mut().expect("object").remove("domain");
    proposal["schema_version"] = json!("ioi.autonomous-system-amendment-execution-proposal.v1");
    proposal["proposal_root"] = json!(proposal_root);
    validate_contract(AMENDMENT_PROPOSAL_CONTRACT, &proposal, "amendment proposal")?;

    let decision_ref = format!(
        "decision://{}/amend-constitution/{sequence}",
        ns(&system_id)?
    );
    let decision_material = json!({
        "domain": AMENDMENT_DECISION_HASH_DOMAIN,
        "decision_ref": decision_ref,
        "proposal_ref": proposal_ref,
        "proposal_root": proposal_root,
        "system_id": system_id,
        "op": AMENDMENT_OP,
        "sequence": sequence,
        "amendment_ref": amendment_ref,
        "amendment_root": plan.amendment_root,
        "approval_decision_root": plan.approval_decision_root,
        "irreversibility": "one_way",
        "required_scope": AMENDMENT_REQUIRED_SCOPE,
        "operation_commitment": operation_commitment,
        "input_hash": authority.input_hash,
        "policy_hash": authority.policy_hash,
        // Contract discipline: the decision restates the hash that
        // recomputes from the exact proposal effect.
        "effect_hash": authority_effect_hash,
        "authority_grant_ref": authority.authority_grant_ref,
        "authority_evidence_ref": authority.authority_evidence_ref,
        "authority_evidence_root": authority.authority_evidence_root,
        "wallet_grant_consumption_ref": authority.wallet_grant_consumption_ref,
        "wallet_grant_consumption_evidence_ref": authority.wallet_grant_consumption_evidence_ref,
        "outcome": "admitted",
        "decided_at": timestamp,
    });
    let decision_root = jcs_hash(&decision_material)?;
    let mut decision = decision_material;
    decision.as_object_mut().expect("object").remove("domain");
    decision["schema_version"] = json!("ioi.autonomous-system-amendment-execution-decision.v1");
    decision["decision_root"] = json!(decision_root);
    validate_contract(AMENDMENT_DECISION_CONTRACT, &decision, "amendment decision")?;

    let transition_ref = format!(
        "lifecycle-transition://{}/sequence/{sequence}",
        ns(&system_id)?
    );
    let receipt_root_seed = jcs_hash(&json!({
        "domain": "ioi.autonomous-system-lifecycle-evidence-ref-jcs-sha256.v1",
        "system_id": system_id,
        "sequence": sequence,
        "kind": "constitution_amendment_receipt",
    }))?;
    let receipt_ref = format!(
        "receipt://ltr_{}",
        receipt_root_seed
            .strip_prefix("sha256:")
            .expect("hash prefix")
    );

    let mut state = plan.semantic_state.clone();
    state["transition_ref"] = json!(transition_ref);
    state["transition_receipt_ref"] = json!(receipt_ref);
    state["created_at"] = json!(timestamp);

    let transition = json!({
        "schema_version": "ioi.autonomous-system-amendment-transition.v1",
        "lifecycle_transition_id": transition_ref,
        "system_id": system_id,
        "resulting_or_related_system_id": Value::Null,
        "lifecycle_profile_ref": source.chain_head["lifecycle_continuity_profile_ref"],
        "transition_kind": AMENDMENT_OP,
        "genesis_ref": Value::Null,
        "manifest_ref": Value::Null,
        "admitted_manifest_root": Value::Null,
        "previous_state": plan.status.as_str(),
        "proposed_state": plan.status.as_str(),
        "trigger_evidence_refs": [plan.previous_step.receipt["receipt_ref"].clone()],
        "oracle_evidence_profile_refs": source.chain_head["oracle_evidence_profile_refs"],
        "proposal_ref": proposal_ref,
        "decision_ref": decision_ref,
        "authority_grant_refs": [authority.authority_grant_ref],
        "challenge_opened_at": Value::Null,
        "challenge_closes_at": Value::Null,
        "predecessor_state_root": plan.previous_step.state_root,
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
        AMENDMENT_TRANSITION_CONTRACT,
        &transition,
        "amendment transition",
    )?;
    let transition_root = artifact_root_with(AMENDMENT_TRANSITION_HASH_DOMAIN, &transition)?;

    state["transition_root"] = json!(transition_root);
    validate_contract(LIFECYCLE_STATE_CONTRACT, &state, "lifecycle state")?;

    let bound_facts = json!({
        "system_id": system_id,
        "operation": AMENDMENT_OP,
        "sequence": sequence,
        "required_scope": AMENDMENT_REQUIRED_SCOPE,
        "authority_effect_hash": authority.effect_hash,
        "genesis_ref": Value::Null,
        "genesis_admission_record_root": Value::Null,
        "genesis_admission_receipt_ref": Value::Null,
        "genesis_admission_receipt_root": Value::Null,
        "sequence_zero_materialization_id": Value::Null,
        "sequence_zero_materialization_root": Value::Null,
        "sequence_zero_receipt_ref": Value::Null,
        "sequence_zero_receipt_root": Value::Null,
        "sequence_zero_receipt_artifact_root": Value::Null,
        "source_governing_authority_ref": Value::Null,
        "home_domain_ref": Value::Null,
        "home_domain_commitment": Value::Null,
        "home_domain_binding_ref": Value::Null,
        "home_domain_binding_root": Value::Null,
        "component_registry_ref": Value::Null,
        "component_registry_root": Value::Null,
        "materialization_wallet_consumption_ref": Value::Null,
        "materialization_wallet_consumption_root": Value::Null,
        "deployment_profile_ref": Value::Null,
        "deployment_profile_root": Value::Null,
        "profile_bundle_root": Value::Null,
        "policy_root": Value::Null,
        "module_registry_root": Value::Null,
        "upgrade_policy_ref": Value::Null,
        "operation_commitment": operation_commitment,
        "amendment_ref": amendment_ref,
        "amendment_root": plan.amendment_root,
        "approval_decision_root": plan.approval_decision_root,
        "predecessor_constitution_ref": predecessor_constitution_ref,
        "predecessor_constitution_root": predecessor_constitution_root,
        "successor_constitution_ref": successor_constitution_ref,
        "successor_constitution_root": plan.successor_constitution_root,
        "changed_field_paths_commitment": plan.changed_field_paths_commitment,
        "proposal_ref": proposal_ref,
        "proposal_root": proposal_root,
        "decision_ref": decision_ref,
        "decision_root": decision_root,
        "transition_ref": transition_ref,
        "transition_root": transition_root,
        "predecessor_state_root": plan.previous_step.state_root,
        "resulting_state_ref": effect["resulting_state_ref"],
        "resulting_state_root": plan.resulting_state_root,
        "predecessor_chain_head_root": effect["predecessor_chain_head_root"],
        "active_profile_set_ref": effect["active_profile_set_ref"],
        "active_profile_set_root": effect["active_profile_set_root"],
        "chain_ref": effect["chain_ref"],
        "live_chain_created": false,
    });
    // Boundary = exactly the non-null ref-valued bound facts plus the four
    // authority coordinates, mirroring the protected receipt's exact-
    // coverage discipline extended by the amendment facts.
    let mut boundary = vec![
        system_id.clone(),
        proposal_ref.clone(),
        decision_ref.clone(),
        transition_ref.clone(),
        amendment_ref.clone(),
        predecessor_constitution_ref.clone(),
        successor_constitution_ref.clone(),
        required(effect, "/resulting_state_ref")?,
        required(effect, "/active_profile_set_ref")?,
        required(effect, "/chain_ref")?,
        authority.authority_grant_ref.clone(),
        authority.authority_evidence_ref.clone(),
        authority.wallet_grant_consumption_ref.clone(),
        authority.wallet_grant_consumption_evidence_ref.clone(),
    ];
    boundary.sort();
    boundary.dedup();
    let receipt = json!({
        "schema_version": "ioi.autonomous-system-amendment-receipt.v1",
        "receipt_id": receipt_ref,
        "receipt_ref": receipt_ref,
        "receipt_type": "lifecycle_transition",
        "receipt_profile_ref": AMENDMENT_RECEIPT_CONTRACT,
        "actor_id": "runtime://hypervisor-runtime",
        "subject_ref": transition_ref,
        "op": AMENDMENT_OP,
        "sequence": sequence,
        "attested_boundary_fact_refs": boundary,
        "bound_facts": bound_facts,
        "input_hash": authority.input_hash,
        "output_hash": plan.resulting_state_root,
        "policy_hash": authority.policy_hash,
        "effect_hash": authority.effect_hash,
        "authority_grant_id": authority.authority_grant_ref,
        "required_scope": AMENDMENT_REQUIRED_SCOPE,
        "authority_scopes": [AMENDMENT_REQUIRED_SCOPE],
        "authority_evidence_ref": authority.authority_evidence_ref,
        "authority_evidence_root": authority.authority_evidence_root,
        "wallet_grant_consumption_ref": authority.wallet_grant_consumption_ref,
        "wallet_grant_consumption_root": authority.wallet_grant_consumption_root,
        "wallet_grant_consumption_evidence_ref":
            authority.wallet_grant_consumption_evidence_ref,
        "primitive_capabilities": [], "artifact_refs": [], "evidence_bundle_refs": [],
        "verification_ref": Value::Null, "acceptance_ref": Value::Null,
        "claim_scope_ref": Value::Null, "run_id": Value::Null, "task_id": Value::Null,
        "adjudication_ref": Value::Null, "settlement_ref": Value::Null,
        "signature": Value::Null, "public_commitment_ref": Value::Null,
        "assurance_posture": "constitutional_amendment_committed",
        "assurance_note": "protected constitutional amendment committed over the live chain; the constitution and active profile set swap to the successor revision; operational status is unchanged and no membership, runtime, network, or settlement effect exists",
        "timestamp": timestamp, "outcome": "ok", "at": timestamp,
    });
    validate_contract(AMENDMENT_RECEIPT_CONTRACT, &receipt, "amendment receipt")?;
    let receipt_root = artifact_root_with(AMENDMENT_RECEIPT_HASH_DOMAIN, &receipt)?;

    // Successor profile set: the plan minted it with empty admitted_by
    // slots; fill them with the minted transition/receipt refs. The v2 root
    // recipe excludes those slots, so the committed root stays the plan's.
    let mut successor_profile_set = plan.successor_profile_set.clone();
    successor_profile_set["admitted_by_transition_ref"] = json!(transition_ref);
    successor_profile_set["admitted_by_receipt_ref"] = json!(receipt_ref);
    successor_profile_set["created_at"] = json!(timestamp);
    let recomputed_set_root =
        ioi_types::app::system_amendment_execution::active_profile_set_v2_root(
            &successor_profile_set,
        )
        .map_err(|error| verr("system_lifecycle_artifact_invalid", error))?;
    if recomputed_set_root != plan.successor_profile_set_root {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "successor profile set root moved when its admitted_by slots were filled",
        ));
    }
    validate_contract(
        ACTIVE_PROFILE_SET_V2_CONTRACT,
        &successor_profile_set,
        "successor active profile set",
    )?;

    let state_root = plan.resulting_state_root.clone();
    let step = UnverifiedCommittedSystemLifecycleStep {
        proposal,
        decision,
        state: state.clone(),
        transition: transition.clone(),
        receipt: receipt.clone(),
        state_root: state_root.clone(),
        proposal_root: proposal_root.clone(),
        decision_root: decision_root.clone(),
        transition_root: transition_root.clone(),
        receipt_root: receipt_root.clone(),
    };

    let operation_log = continue_amendment_operation_log(plan, &step, source, timestamp)?;
    let chain = continue_amendment_chain(plan, &step, source, &operation_log, timestamp)?;
    Ok(AmendmentStepArtifacts {
        step,
        declaration: plan.amendment.clone(),
        declaration_root: plan.amendment_root.clone(),
        approval_decision: plan.approval_decision.clone(),
        approval_decision_root: plan.approval_decision_root.clone(),
        successor_constitution: plan.successor_constitution.clone(),
        successor_profile_set,
        operation_log,
        chain,
    })
}

fn amendment_log_entry(
    plan: &CompiledAmendmentExecutionPlan,
    step: &UnverifiedCommittedSystemLifecycleStep,
    timestamp: &str,
) -> Value {
    let effect = &plan.authority_effect;
    json!({
        "sequence": plan.sequence,
        "entry_kind": "constitution_amendment",
        "operation_name": AMENDMENT_OP,
        "operation_owner_profile_ref": AMENDMENT_PROPOSAL_CONTRACT,
        "operation_owner_ref": step.proposal["proposal_ref"],
        "operation_owner_root": step.proposal_root,
        "required_scope": AMENDMENT_REQUIRED_SCOPE,
        "materialization_ref": Value::Null,
        "materialization_root": Value::Null,
        "deployment_profile_ref": effect["deployment_profile_ref"],
        "deployment_profile_root": effect["deployment_profile_root"],
        "operation_commitment": effect["operation_commitment"],
        "proposal_ref": step.proposal["proposal_ref"],
        "proposal_root": step.proposal_root,
        "decision_ref": step.decision["decision_ref"],
        "decision_root": step.decision_root,
        "transition_ref": step.transition["lifecycle_transition_id"],
        "transition_root": step.transition_root,
        "state_transition_commitment_ref": Value::Null,
        "state_ref": step.state["lifecycle_state_ref"],
        "state_root": step.state_root,
        "predecessor_state_root": plan.previous_step.state_root,
        "receipt_profile_ref": AMENDMENT_RECEIPT_CONTRACT,
        "receipt_ref": step.receipt["receipt_ref"],
        "receipt_root": step.receipt_root,
        "receipt_artifact_root": step.receipt_root,
        "active_profile_set_ref": effect["active_profile_set_ref"],
        "active_profile_set_root": effect["active_profile_set_root"],
        "chain_ref": effect["chain_ref"],
        "authority_evidence_ref": Value::Null,
        "authority_evidence_root": Value::Null,
        "wallet_consumption_ref": Value::Null,
        "wallet_consumption_root": Value::Null,
        "component_registry_ref": Value::Null,
        "component_registry_root": Value::Null,
        "live_chain_created": false,
        "committed_at": timestamp,
    })
}

/// Continue the operation log with a `constitution_amendment` entry through
/// the shared v1-to-v2 continuation helper.
pub(crate) fn continue_amendment_operation_log(
    plan: &CompiledAmendmentExecutionPlan,
    step: &UnverifiedCommittedSystemLifecycleStep,
    source: &AmendmentSource,
    timestamp: &str,
) -> Result<Value, VErr> {
    let system_id = required(&plan.authority_effect, "/system_id")?;
    let entry = amendment_log_entry(plan, step, timestamp);
    continue_log_with_entry(
        &source.operation_log,
        &entry,
        plan.sequence,
        &plan.previous_step.state_root,
        &system_id,
        timestamp,
    )
}

/// Continue the chain with the amendment head: the head coordinates update
/// and `constitution_ref`/`constitution_root` swap to the successor. Every
/// other chain field is carried verbatim (the protected continuation
/// carries constitution refs verbatim; this one swaps them — THE amendment
/// moment).
pub(crate) fn continue_amendment_chain(
    plan: &CompiledAmendmentExecutionPlan,
    step: &UnverifiedCommittedSystemLifecycleStep,
    source: &AmendmentSource,
    operation_log: &Value,
    timestamp: &str,
) -> Result<Value, VErr> {
    let mut chain = source.chain_head.clone();
    chain["latest_sequence"] = json!(plan.sequence);
    chain["latest_operation_commitment"] = plan.authority_effect["operation_commitment"].clone();
    chain["latest_transition_id"] = step.transition["lifecycle_transition_id"].clone();
    chain["latest_transition_root"] = json!(step.transition_root);
    chain["latest_receipt_ref"] = step.receipt["receipt_ref"].clone();
    chain["latest_receipt_root"] = json!(step.receipt_root);
    chain["latest_state_ref"] = step.state["lifecycle_state_ref"].clone();
    chain["latest_state_root"] = json!(step.state_root);
    chain["operation_log_ref"] = operation_log["operation_log_ref"].clone();
    chain["operation_log_root"] = operation_log["operation_log_root"].clone();
    chain["constitution_ref"] = plan.successor_constitution["constitution_id"].clone();
    chain["constitution_root"] = json!(plan.successor_constitution_root);
    chain["status"] = json!(plan.status.as_str());
    chain["created_at"] = json!(timestamp);
    let mut material = chain.as_object().cloned().expect("object");
    material.remove("schema_version");
    material.remove("chain_root");
    material.remove("created_at");
    material.insert("domain".to_owned(), json!(CHAIN_ROOT_DOMAIN));
    chain["chain_root"] = json!(jcs_hash(&Value::Object(material))?);
    validate_contract(SYSTEM_CHAIN_CONTRACT, &chain, "chain revision")?;
    Ok(chain)
}

fn validate_amendment_request(body: &Value) -> Result<(), VErr> {
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
    const ALLOWED: &[&str] = &[
        "amendment",
        "amendment_approval_decision",
        "successor_constitution",
        "expected_chain_head_root",
        "expected_predecessor_state_root",
        "amendment_governance_approval_grant",
        "wallet_approval_grant",
    ];
    if let Some(key) = object.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(verr(
            "system_lifecycle_request_field_unknown",
            format!("undeclared request field '{key}' is forbidden"),
        ));
    }
    for key in [
        "amendment",
        "amendment_approval_decision",
        "successor_constitution",
    ] {
        if !object.get(key).is_some_and(Value::is_object) {
            return Err(verr(
                "system_lifecycle_request_invalid",
                format!("'{key}' must be one JSON object"),
            ));
        }
    }
    for key in [
        "expected_chain_head_root",
        "expected_predecessor_state_root",
    ] {
        let value = object.get(key).and_then(Value::as_str).unwrap_or("");
        if !canonical_hash_str(value) {
            return Err(verr(
                "system_lifecycle_request_invalid",
                format!("'{key}' must be a canonical sha256 commitment"),
            ));
        }
    }
    Ok(())
}

fn check_expected_roots(body: &Value, source: &AmendmentSource) -> Result<(), VErr> {
    let chain_root = source
        .chain_head
        .get("chain_root")
        .and_then(Value::as_str)
        .unwrap_or("");
    if body.get("expected_chain_head_root") != Some(&json!(chain_root)) {
        return Err(verr(
            "system_lifecycle_head_conflict",
            "the live chain head moved past the caller's expected root",
        ));
    }
    if body.get("expected_predecessor_state_root") != Some(&json!(source.previous_step.state_root))
    {
        return Err(verr(
            "system_lifecycle_head_conflict",
            "the predecessor state moved past the caller's expected root",
        ));
    }
    Ok(())
}

fn decision_tuple(evidence: &NodeAdmissionEvidence) -> Result<DecisionAuthorityTuple, VErr> {
    Ok(DecisionAuthorityTuple {
        input_hash: evidence.authorized.evidence.request_hash.clone(),
        policy_hash: evidence.authorized.evidence.policy_hash.clone(),
        effect_hash: evidence.authorized.evidence.effect_hash.clone(),
        authority_grant_ref: required(&evidence.authority_evidence, "/authority_grant_ref")?,
        authority_evidence_ref: evidence.authority_evidence_ref.clone(),
        authority_evidence_root: evidence.authority_evidence_root.clone(),
        wallet_grant_consumption_ref: evidence.wallet_consumption_ref.clone(),
        wallet_grant_consumption_root: evidence.wallet_consumption_root.clone(),
        wallet_grant_consumption_evidence_ref: evidence.wallet_consumption_evidence_ref.clone(),
    })
}

fn persist_amendment_graph(
    data_dir: &str,
    artifacts: &AmendmentStepArtifacts,
    evidence: &NodeAdmissionEvidence,
    wallet_consumption: &Value,
) -> Result<(), VErr> {
    let consumption_receipt: ApprovalGrantConsumptionReceipt =
        serde_json::from_value(wallet_consumption.clone()).map_err(|error| {
            verr(
                "system_lifecycle_wallet_consumption_invalid",
                error.to_string(),
            )
        })?;
    let set_root = required(&artifacts.successor_profile_set, "/active_profile_set_root")?;
    // The persisted key is the AUTHORITATIVE candidate root, never the body's
    // declared self-root field (which is carried verbatim from the
    // predecessor and is not a content binding).
    let constitution_root =
        ioi_types::app::system_amendment_execution::constitution_candidate_root(
            &artifacts.successor_constitution,
        )
        .map_err(|error| verr("system_lifecycle_artifact_invalid", error))?;
    claim_chain_successor(
        data_dir,
        required_string(&artifacts.chain, "/system_id")?,
        artifacts
            .chain
            .get("latest_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                verr(
                    "system_lifecycle_artifact_invalid",
                    "successor chain lacks latest_sequence",
                )
            })?,
        required_string(
            &artifacts.step.receipt,
            "/bound_facts/predecessor_chain_head_root",
        )?,
        required_string(&artifacts.chain, "/chain_root")?,
        required_string(&artifacts.step.proposal, "/proposal_ref")?,
        &artifacts.step.proposal_root,
        AMENDMENT_OP,
        required_string(&artifacts.step.receipt, "/timestamp")?,
    )?;
    let records: Vec<(&str, String, &Value)> = vec![
        (
            AUTHORITY_CONSUMPTION_DIR,
            format!("aslac_{}", hex::encode(consumption_receipt.consumption_id)),
            wallet_consumption,
        ),
        (
            AUTHORITY_EVIDENCE_DIR,
            tail("aslae_", &evidence.authority_evidence_root)?,
            &evidence.authority_evidence,
        ),
        (
            AMENDMENT_DECLARATION_DIR,
            tail("asca_", &artifacts.declaration_root)?,
            &artifacts.declaration,
        ),
        (
            AMENDMENT_APPROVAL_DECISION_DIR,
            tail("ascaad_", &artifacts.approval_decision_root)?,
            &artifacts.approval_decision,
        ),
        (
            CONSTITUTION_DIR,
            tail("ascn_", &constitution_root)?,
            &artifacts.successor_constitution,
        ),
        (
            PROPOSAL_DIR,
            tail("aslp_", &artifacts.step.proposal_root)?,
            &artifacts.step.proposal,
        ),
        (
            DECISION_DIR,
            tail("aslad_", &artifacts.step.decision_root)?,
            &artifacts.step.decision,
        ),
        (
            TRANSITION_DIR,
            tail("aslt_", &artifacts.step.transition_root)?,
            &artifacts.step.transition,
        ),
        (
            AMENDMENT_RECEIPT_DIR,
            tail("asamr_", &artifacts.step.receipt_root)?,
            &artifacts.step.receipt,
        ),
        (
            ACTIVE_SET_DIR,
            tail("asaps_", &set_root)?,
            &artifacts.successor_profile_set,
        ),
        (
            LIFECYCLE_STATE_DIR,
            tail("asls_", &artifacts.step.state_root)?,
            &artifacts.step.state,
        ),
        (
            OPERATION_LOG_DIR,
            tail(
                "asol_",
                required_string(&artifacts.operation_log, "/operation_log_root")?,
            )?,
            &artifacts.operation_log,
        ),
        (
            CHAIN_DIR,
            tail("asc_", required_string(&artifacts.chain, "/chain_root")?)?,
            &artifacts.chain,
        ),
    ];
    for (family, record_tail, value) in &records {
        persist_local(data_dir, family, record_tail, value)?;
        if forced_fault(
            "IOI_TEST_FORCE_SYSTEM_AMENDMENT_AFTER_LOCAL_PERSIST",
            family,
        ) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                format!("test-forced interruption after local '{family}/{record_tail}'"),
            ));
        }
        super::substrate_store::admit_required(data_dir, family, record_tail, value).map_err(
            |error| {
                verr(
                    "system_lifecycle_agentgres_admission_failed",
                    format!("required admission for '{family}/{record_tail}' failed ({error})"),
                )
            },
        )?;
        if forced_fault(
            "IOI_TEST_FORCE_SYSTEM_AMENDMENT_AFTER_AGENTGRES_ADMIT",
            family,
        ) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                format!("test-forced interruption after Agentgres '{family}/{record_tail}'"),
            ));
        }
    }
    for (family, record_tail, value) in &records {
        let loaded = load_required_exact(data_dir, family, record_tail)?.ok_or_else(|| {
            verr(
                "system_lifecycle_persist_failed",
                format!("'{family}/{record_tail}' did not converge"),
            )
        })?;
        if &loaded != *value {
            return Err(verr(
                "system_lifecycle_persist_failed",
                format!("'{family}/{record_tail}' diverged after admission"),
            ));
        }
    }
    Ok(())
}

/// POST /v1/hypervisor/autonomous-systems/:id/amendments
pub(crate) async fn handle_amendment(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_lifecycle_source_key_invalid",
            "id must be 'asg_' plus 64 lowercase hexadecimal characters",
        ));
    }
    if let Err(error) = validate_amendment_request(&body) {
        return classify(error);
    }
    let amendment = body["amendment"].clone();
    let approval_decision = body["amendment_approval_decision"].clone();
    let successor_constitution = body["successor_constitution"].clone();
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let placeholder_approval_evidence_root = format!("sha256:{}", "00".repeat(32));
    let (system_id, source, provisional_plan, existing_approval) = match with_source_locks(|| {
        super::system_activation_routes::ensure_no_pending_intent(&state.data_dir, &key)?;
        ensure_no_pending_protected_intent(&state.data_dir, &key)?;
        ensure_no_pending_amendment_intent(&state.data_dir, &key)?;
        let (system_id, source) = load_amendment_source(&state.data_dir, &key)?;
        check_expected_roots(&body, &source)?;
        let plan = compile_amendment_from_source(
            &source,
            &amendment,
            &approval_decision,
            &placeholder_approval_evidence_root,
            &successor_constitution,
        )?;
        let existing = load_approval_authority_evidence(&state.data_dir, &source, &plan)?;
        Ok::<_, VErr>((system_id, source, plan, existing))
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let genesis_ref = match required(&source.activation_effect, "/genesis_ref") {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let governing = match required(&source.activation_effect, "/source_governing_authority_ref") {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let approval_authority_evidence_root = match existing_approval {
        Some((_evidence, root)) => root,
        None => {
            let approval_authority = match approval_governance_authority(&source) {
                Ok(value) => value,
                Err(error) => return classify(error),
            };
            let approval_effect = match amendment_approval_effect(&source, &provisional_plan) {
                Ok(value) => value,
                Err(error) => return classify(error),
            };
            let approval_body = json!({
                "wallet_approval_grant": body.get("amendment_governance_approval_grant")
                    .cloned().unwrap_or(Value::Null),
            });
            let approval_subject = match required(&provisional_plan.amendment, "/amendment_id") {
                Ok(value) => value,
                Err(error) => return classify(error),
            };
            let authorized_approval = match governed::authorize_decision_with_context(
                AMENDMENT_GOVERNANCE_AUTHORITY,
                &approval_body,
                Governance::Host,
                AuthorityPolicyContext::SystemGenesis {
                    system_id: &system_id,
                    genesis_id: &genesis_ref,
                },
                &approval_authority,
                &approval_subject,
                AMENDMENT_APPROVAL_OP,
                AMENDMENT_APPROVAL_REVISION,
                &approval_effect,
            )
            .await
            {
                Err(response) => return response,
                Ok(value) => value,
            };
            let approval_wallet_use = match governance_approval_wallet_use(
                &source,
                &provisional_plan,
                &approval_effect,
                &authorized_approval,
            ) {
                Ok(value) => value,
                Err(error) => return classify(error),
            };
            let (approval_intent_tail, approval_intent) = match seal_approval_intent(
                &key,
                &body,
                &provisional_plan,
                &approval_effect,
                &authorized_approval,
                &approval_wallet_use,
            ) {
                Ok(value) => value,
                Err(error) => return classify(error),
            };
            if let Err(error) = with_source_locks(|| {
                let (_, fresh) = load_amendment_source(&state.data_dir, &key)?;
                check_expected_roots(&body, &fresh)?;
                let recompiled = compile_amendment_from_source(
                    &fresh,
                    &amendment,
                    &approval_decision,
                    &placeholder_approval_evidence_root,
                    &successor_constitution,
                )?;
                if plan_to_value(&recompiled)? != plan_to_value(&provisional_plan)? {
                    return Err(verr(
                        "system_lifecycle_head_conflict",
                        "durable truth changed before governance approval intent sealing",
                    ));
                }
                persist_local(
                    &state.data_dir,
                    AMENDMENT_APPROVAL_INTENT_DIR,
                    &approval_intent_tail,
                    &approval_intent,
                )
            }) {
                return classify(error);
            }
            let approval_wallet_receipt =
                match recover_or_consume_governance_approval(&approval_wallet_use).await {
                    Ok(value) => value,
                    Err(failure) => {
                        if failure.definitively_unconsumed {
                            if let Err(error) = remove_matching_approval_intent(
                                &state.data_dir,
                                &approval_intent_tail,
                                &approval_intent,
                            ) {
                                return classify(error);
                            }
                        }
                        return classify(failure.error);
                    }
                };
            if forced_fault(
                "IOI_TEST_FORCE_SYSTEM_AMENDMENT_AFTER_GOVERNANCE_APPROVAL_WALLET_CONSUMPTION",
                AMENDMENT_APPROVAL_OP,
            ) {
                return classify(verr(
                    "system_lifecycle_pending_convergence",
                    "test-forced interruption after governance approval wallet consumption",
                ));
            }
            let approval_evidence = match approval_authority_evidence(
                &source,
                &provisional_plan,
                &approval_effect,
                authorized_approval,
                approval_wallet_receipt,
            ) {
                Ok(value) => value,
                Err(error) => return classify(error),
            };
            match with_source_locks(|| {
                let (_, fresh) = load_amendment_source(&state.data_dir, &key)?;
                check_expected_roots(&body, &fresh)?;
                let recompiled = compile_amendment_from_source(
                    &fresh,
                    &amendment,
                    &approval_decision,
                    &placeholder_approval_evidence_root,
                    &successor_constitution,
                )?;
                if plan_to_value(&recompiled)? != plan_to_value(&provisional_plan)? {
                    return Err(verr(
                        "system_lifecycle_head_conflict",
                        "durable truth changed during governance approval",
                    ));
                }
                let root = persist_governance_approval(
                    &state.data_dir,
                    &fresh,
                    &recompiled,
                    &approval_evidence,
                )?;
                remove_intent(
                    &state.data_dir,
                    AMENDMENT_APPROVAL_INTENT_DIR,
                    &approval_intent_tail,
                )?;
                Ok(root)
            }) {
                Ok(root) => root,
                Err(error) => return classify(error),
            }
        }
    };
    let plan = match compile_amendment_from_source(
        &source,
        &amendment,
        &approval_decision,
        &approval_authority_evidence_root,
        &successor_constitution,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let authorized = match governed::authorize_decision_with_context(
        AUTHORITY,
        &body,
        Governance::Host,
        AuthorityPolicyContext::SystemGenesis {
            system_id: &system_id,
            genesis_id: &genesis_ref,
        },
        &governing,
        &system_id,
        AMENDMENT_OP,
        plan.sequence,
        &plan.authority_effect,
    )
    .await
    {
        Err(response) => return response,
        Ok(value) => value,
    };
    let mut evidence = match prepare_node_evidence_for(
        &plan.authority_effect,
        AMENDMENT_OP,
        plan.sequence,
        AMENDMENT_REQUIRED_SCOPE,
        &governing,
        &plan.resulting_state_root,
        authorized,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if let Err(error) = preflight_chain_writer_grant(&evidence.wallet_params).await {
        return classify(error);
    }
    let intent_tail_value = match tail("asamx_", &evidence.authorized.evidence.request_hash) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let plan_value = match plan_to_value(&plan) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let sealed = match intent_seal(json!({
        "schema_version": "ioi.hypervisor.constitution-amendment-intent.v1",
        "source_record_tail": &key,
        "op": AMENDMENT_OP,
        "request_body": &body,
        "compiled_plan": &plan_value,
        "governed_authority": evidence_intent_value(&evidence),
        "intent_hash": Value::Null,
    })) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if let Err(error) = with_source_locks(|| {
        persist_local(
            &state.data_dir,
            AMENDMENT_INTENT_DIR,
            &intent_tail_value,
            &sealed,
        )
    }) {
        return classify(error);
    }
    let reservation = reserve_chain_writer(
        &state.data_dir,
        &system_id,
        plan.sequence,
        plan.authority_effect["predecessor_chain_head_root"]
            .as_str()
            .unwrap_or(""),
        plan.authority_effect["operation_commitment"]
            .as_str()
            .unwrap_or(""),
        &format!(
            "proposal://{}/amend-constitution/{}",
            match ns(&system_id) {
                Ok(value) => value,
                Err(error) => return classify(error),
            },
            plan.sequence,
        ),
        plan.authority_effect["operation_commitment"]
            .as_str()
            .unwrap_or(""),
        AMENDMENT_OP,
    );
    if let Err(error) = reservation {
        if error.0 == "system_lifecycle_head_conflict" {
            if let Err(cleanup_error) =
                remove_intent(&state.data_dir, AMENDMENT_INTENT_DIR, &intent_tail_value)
            {
                // A failed loser cleanup leaves a sealed intent that blocks
                // every later lifecycle operation. Report pending convergence
                // instead of hiding that durable interlock behind the race
                // winner's head-conflict response.
                return classify(cleanup_error);
            }
        }
        return classify(error);
    }
    let revalidated = with_source_locks(|| {
        // The shared expected-absent reservation is the cross-process gate.
        // Its winner still revalidates the complete source before wallet
        // consumption; a loser returns conflict above without consulting a
        // stale process-local Agentgres projection after the winner commits.
        let (_, fresh) = load_amendment_source(&state.data_dir, &key)?;
        check_expected_roots(&body, &fresh)?;
        let recompiled = compile_amendment_from_source(
            &fresh,
            &amendment,
            &approval_decision,
            &approval_authority_evidence_root,
            &successor_constitution,
        )?;
        if plan_to_value(&recompiled)? != plan_value {
            return Err(verr(
                "system_lifecycle_head_conflict",
                "durable truth changed between authorization and writer reservation",
            ));
        }
        Ok::<_, VErr>(())
    });
    if let Err(error) = revalidated {
        if error.0 == "system_lifecycle_head_conflict" {
            let _ = remove_intent(&state.data_dir, AMENDMENT_INTENT_DIR, &intent_tail_value);
        }
        return classify(error);
    }
    if forced_fault("IOI_TEST_FORCE_SYSTEM_AMENDMENT_AFTER_INTENT", AMENDMENT_OP) {
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
                    remove_intent(&state.data_dir, AMENDMENT_INTENT_DIR, &intent_tail_value)
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
        "IOI_TEST_FORCE_SYSTEM_AMENDMENT_AFTER_WALLET_CONSUMPTION",
        AMENDMENT_OP,
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
    let tuple = match decision_tuple(&evidence) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let artifacts = match build_amendment_artifacts(&plan, &source, &tuple, &timestamp) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let result = with_source_locks(|| {
        let stored = load_local(&state.data_dir, AMENDMENT_INTENT_DIR, &intent_tail_value)?
            .ok_or_else(|| {
                verr(
                    "system_lifecycle_pending_convergence",
                    "durable intent vanished after wallet consumption",
                )
            })?;
        verify_intent_seal(&stored)?;
        if stored.get("compiled_plan") != Some(&plan_value) {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                "durable intent does not bind the authorized plan",
            ));
        }
        persist_amendment_graph(&state.data_dir, &artifacts, &evidence, &wallet_value)?;
        if forced_fault(
            "IOI_TEST_FORCE_SYSTEM_AMENDMENT_BEFORE_TERMINAL_VISIBILITY",
            AMENDMENT_OP,
        ) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                "test-forced interruption before terminal intent removal",
            ));
        }
        remove_intent(&state.data_dir, AMENDMENT_INTENT_DIR, &intent_tail_value)
    });
    if let Err(error) = result {
        return classify(error);
    }
    (
        StatusCode::OK,
        Json(json!({
            "op": AMENDMENT_OP,
            "sequence": plan.sequence,
            "amendment": artifacts.declaration,
            "amendment_root": artifacts.declaration_root,
            "successor_constitution": artifacts.successor_constitution,
            "active_profile_set": artifacts.successor_profile_set,
            "lifecycle_state": artifacts.step.state,
            "lifecycle_transition": artifacts.step.transition,
            "lifecycle_receipt": artifacts.step.receipt,
            "operation_log": artifacts.operation_log,
            "autonomous_system_chain": artifacts.chain,
            "claims": {"constitution_changed": true, "profile_set_changed": true},
            "nonclaims": {"runtime_effect":false,"network_effect":false,"membership":false,"writer":false,"settlement":false,"status_change":false}
        })),
    )
}

/// GET /v1/hypervisor/autonomous-systems/:id/amendments — eligibility plus
/// retained amendment evidence for the System.
pub(crate) async fn handle_get_amendment(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_lifecycle_source_key_invalid",
            "id must be canonical",
        ));
    }
    match with_source_locks(|| {
        let system_id = system_id_for_key(&state.data_dir, &key)?;
        let chain_head = load_chain_head(&state.data_dir, &system_id)?;
        let operation_log = load_log_for_chain(&state.data_dir, &chain_head)?;
        let previous_step = load_previous_step(&state.data_dir, &operation_log)?;
        let committed: Vec<Value> = operation_log
            .get("entries")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|entry| {
                        entry.get("entry_kind").and_then(Value::as_str)
                            == Some("constitution_amendment")
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let retained: Vec<Value> = enumerate_family(&state.data_dir, AMENDMENT_DECLARATION_DIR)?
            .into_iter()
            .filter_map(|(_, declaration)| {
                (declaration.get("system_id").and_then(Value::as_str) == Some(system_id.as_str()))
                    .then_some(declaration)
            })
            .collect();
        let admits = chain_head
            .get("status")
            .and_then(Value::as_str)
            .and_then(ProtectedLifecycleStatus::parse)
            .map(|status| {
                matches!(
                    status,
                    ProtectedLifecycleStatus::Active | ProtectedLifecycleStatus::Paused
                )
            })
            .unwrap_or(false);
        Ok::<_, VErr>(json!({
            "op": AMENDMENT_OP,
            "required_scope": AMENDMENT_REQUIRED_SCOPE,
            "eligible_now": {
                "predecessor_status": chain_head
                    .get("status")
                    .cloned()
                    .unwrap_or(Value::Null),
                "admits": admits,
            },
            "current_constitution": {
                "constitution_ref": chain_head.get("constitution_ref").cloned().unwrap_or(Value::Null),
                "constitution_root": chain_head.get("constitution_root").cloned().unwrap_or(Value::Null),
            },
            "current_active_profile_set": {
                "active_profile_set_ref": previous_step.state.get("active_profile_set_ref").cloned().unwrap_or(Value::Null),
                "active_profile_set_root": previous_step.state.get("active_profile_set_root").cloned().unwrap_or(Value::Null),
            },
            "chain_head": chain_head,
            "operation_log_head": operation_log["head_entry"],
            "committed_amendments": committed,
            "retained_declarations": retained,
        }))
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

static AMENDMENT_REPLAY_CURSOR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AmendmentIntentGeneration {
    LegacyUnboundGovernance,
    CurrentBoundGovernance,
}

fn amendment_intent_generation(intent: &Value) -> Result<AmendmentIntentGeneration, VErr> {
    let bindings = [
        intent
            .pointer("/request_body/amendment_approval_decision")
            .is_some_and(Value::is_object),
        intent
            .pointer("/compiled_plan/approval_decision")
            .is_some_and(Value::is_object),
        intent
            .pointer("/compiled_plan/approval_decision_root")
            .is_some_and(Value::is_string),
        intent
            .pointer("/compiled_plan/authority_effect/approval_decision_root")
            .is_some_and(Value::is_string),
        intent
            .pointer("/compiled_plan/authority_effect/approval_authority_evidence_root")
            .is_some_and(Value::is_string),
    ];
    if bindings.iter().all(|bound| *bound) {
        return Ok(AmendmentIntentGeneration::CurrentBoundGovernance);
    }
    if bindings.iter().all(|bound| !*bound) {
        return Ok(AmendmentIntentGeneration::LegacyUnboundGovernance);
    }
    Err(verr(
        "system_lifecycle_intent_invalid",
        "amendment intent mixes legacy and governance-bound coordinates",
    ))
}

fn verify_amendment_intent_coordinates(tail_value: &str, intent: &Value) -> Result<(), VErr> {
    if intent.get("schema_version").and_then(Value::as_str)
        != Some("ioi.hypervisor.constitution-amendment-intent.v1")
    {
        return Err(verr(
            "system_lifecycle_intent_invalid",
            "intent schema is not the constitution-amendment intent",
        ));
    }
    if intent.get("op").and_then(Value::as_str) != Some(AMENDMENT_OP) {
        return Err(verr(
            "system_lifecycle_intent_invalid",
            "intent op is not amend_constitution",
        ));
    }
    let request_hash = required(intent, "/governed_authority/request_hash")?;
    if tail_value != tail("asamx_", &request_hash)? {
        return Err(verr(
            "system_lifecycle_intent_invalid",
            "intent tail does not bind its sealed request hash",
        ));
    }
    Ok(())
}

/// Reconstruct the durable truth exactly as the sealed plan compiled it:
/// the predecessor chain revision by its committed root, the log and step
/// that revision binds, and the at-plan constitution and profile set —
/// append-only content addressing makes this possible after the head moves.
fn source_at_plan(data_dir: &str, key: &str, sealed_plan: &Value) -> Result<AmendmentSource, VErr> {
    let chain_root = required(sealed_plan, "/authority_effect/predecessor_chain_head_root")?;
    let chain_head = record_by_root(
        data_dir,
        CHAIN_DIR,
        "asc_",
        &chain_root,
        "predecessor chain revision",
    )?;
    let operation_log = load_log_for_chain(data_dir, &chain_head)?;
    let previous_step = load_previous_step(data_dir, &operation_log)?;
    let admission = super::system_genesis_routes::load_verified_admission_by_key(data_dir, key)?
        .ok_or_else(|| {
            verr(
                "system_lifecycle_not_found",
                "no admitted genesis exists for this id",
            )
        })?;
    let system_id = required(sealed_plan, "/authority_effect/system_id")?;
    let activation_effect = load_activation_effect(data_dir, &system_id)?;
    let constitution_root = required(&chain_head, "/constitution_root")?;
    let predecessor_constitution =
        load_constitution_body(data_dir, &admission.record, &constitution_root)?;
    let set_root = required(&previous_step.state, "/active_profile_set_root")?;
    let predecessor_profile_set =
        load_required_exact(data_dir, ACTIVE_SET_DIR, &tail("asaps_", &set_root)?)?.ok_or_else(
            || {
                verr(
                    "system_lifecycle_artifact_mismatch",
                    "the at-plan active profile set is not durably admitted",
                )
            },
        )?;
    Ok(AmendmentSource {
        activation_effect,
        previous_step,
        chain_head,
        operation_log,
        predecessor_constitution,
        predecessor_profile_set,
    })
}

/// Validate the frozen pre-hardening intent boundary without re-authorizing or
/// executing it. Those intents approved a bare lifecycle effect and therefore
/// cannot be upgraded into the governance-bound amendment operation. Upgrade
/// migration may only retain any already-committed wallet receipt and retire
/// the local blocker; a fresh governance approval is required to amend again.
fn validate_legacy_amendment_intent(
    data_dir: &str,
    intent: &Value,
) -> Result<(NodeAdmissionEvidence, String), VErr> {
    let key = required(intent, "/source_record_tail")?;
    let sealed_plan = intent.get("compiled_plan").cloned().ok_or_else(|| {
        verr(
            "system_lifecycle_intent_invalid",
            "legacy intent lacks its compiled plan",
        )
    })?;
    let amendment = intent
        .pointer("/request_body/amendment")
        .cloned()
        .ok_or_else(|| {
            verr(
                "system_lifecycle_intent_invalid",
                "legacy intent lacks its amendment declaration",
            )
        })?;
    let successor_constitution = intent
        .pointer("/request_body/successor_constitution")
        .cloned()
        .ok_or_else(|| {
            verr(
                "system_lifecycle_intent_invalid",
                "legacy intent lacks its successor constitution",
            )
        })?;
    if sealed_plan.get("amendment") != Some(&amendment)
        || sealed_plan.get("successor_constitution") != Some(&successor_constitution)
    {
        return Err(verr(
            "system_lifecycle_intent_unreadable",
            "legacy request body detaches from its sealed plan",
        ));
    }
    let amendment_root =
        ioi_types::app::system_amendment_execution::amendment_declaration_root(&amendment)
            .map_err(|error| verr("system_lifecycle_intent_invalid", error))?;
    let successor_root = ioi_types::app::system_amendment_execution::constitution_candidate_root(
        &successor_constitution,
    )
    .map_err(|error| verr("system_lifecycle_intent_invalid", error))?;
    if sealed_plan.get("amendment_root").and_then(Value::as_str) != Some(amendment_root.as_str())
        || sealed_plan
            .get("successor_constitution_root")
            .and_then(Value::as_str)
            != Some(successor_root.as_str())
    {
        return Err(verr(
            "system_lifecycle_intent_unreadable",
            "legacy plan content roots do not recompute",
        ));
    }

    let source = source_at_plan(data_dir, &key, &sealed_plan)?;
    let source_previous = serde_json::to_value(&source.previous_step)
        .map_err(|error| verr("system_lifecycle_intent_invalid", error.to_string()))?;
    if sealed_plan.get("previous_step") != Some(&source_previous) {
        return Err(verr(
            "system_lifecycle_source_conflict",
            "legacy intent predecessor step does not reconstruct",
        ));
    }
    let effect = sealed_plan
        .get("authority_effect")
        .cloned()
        .ok_or_else(|| {
            verr(
                "system_lifecycle_intent_invalid",
                "legacy intent lacks its authority effect",
            )
        })?;
    let resulting_state_root = required(&sealed_plan, "/resulting_state_root")?;
    if required(&effect, "/resulting_state_root")? != resulting_state_root
        || required(&effect, "/amendment_root")? != amendment_root
        || required(&effect, "/successor_constitution_root")? != successor_root
    {
        return Err(verr(
            "system_lifecycle_intent_unreadable",
            "legacy authority effect detaches from its sealed result",
        ));
    }

    let mut evidence = evidence_from_intent(&intent["governed_authority"])?;
    let governing = required(&source.activation_effect, "/source_governing_authority_ref")?;
    let sequence = sealed_plan
        .get("sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            verr(
                "system_lifecycle_intent_invalid",
                "legacy intent lacks its sequence",
            )
        })?;
    let rebuilt = prepare_node_evidence_for(
        &effect,
        AMENDMENT_OP,
        sequence,
        AMENDMENT_REQUIRED_SCOPE,
        &governing,
        &resulting_state_root,
        evidence.authorized.clone(),
    )?;
    if rebuilt.authority_evidence != evidence.authority_evidence
        || rebuilt.wallet_params.request_hash != evidence.wallet_params.request_hash
        || rebuilt.wallet_params.consumption_id != evidence.wallet_params.consumption_id
        || rebuilt.wallet_consumption_ref != evidence.wallet_consumption_ref
    {
        return Err(verr(
            "system_lifecycle_intent_unreadable",
            "legacy authority or wallet coordinates do not reconstruct",
        ));
    }
    evidence.wallet_consumption_root.clear();
    Ok((evidence, key))
}

fn persist_legacy_amendment_resolution(
    data_dir: &str,
    tail_value: &str,
    intent: &Value,
    key: &str,
    evidence: &NodeAdmissionEvidence,
    wallet_value: Option<&Value>,
) -> Result<(), VErr> {
    if let Some(wallet_value) = wallet_value {
        let authority_tail = tail("aslae_", &evidence.authority_evidence_root)?;
        for (family, record_tail, value) in [
            (
                AUTHORITY_CONSUMPTION_DIR,
                evidence.wallet_consumption_tail.as_str(),
                wallet_value,
            ),
            (
                AUTHORITY_EVIDENCE_DIR,
                authority_tail.as_str(),
                &evidence.authority_evidence,
            ),
        ] {
            persist_local(data_dir, family, record_tail, value)?;
            super::substrate_store::admit_required(data_dir, family, record_tail, value).map_err(
                |error| {
                    verr(
                        "system_lifecycle_agentgres_admission_failed",
                        format!(
                            "legacy migration admission for '{family}/{record_tail}' failed ({error})"
                        ),
                    )
                },
            )?;
        }
    }
    let intent_hash = required(intent, "/intent_hash")?;
    let resolution = json!({
        "schema_version": "ioi.hypervisor.legacy-constitution-amendment-intent-resolution.v1",
        "source_record_tail": key,
        "op": AMENDMENT_OP,
        "legacy_intent_hash": intent_hash,
        "legacy_request_hash": required(intent, "/governed_authority/request_hash")?,
        "migration_action": "retire_without_reexecution",
        "reason": "legacy execution authority did not bind the external-governance approval decision; a fresh governance-bound amendment is required",
    });
    persist_local(
        data_dir,
        LEGACY_AMENDMENT_INTENT_RESOLUTION_DIR,
        &tail("asamli_", &intent_hash)?,
        &resolution,
    )?;
    remove_intent(data_dir, AMENDMENT_INTENT_DIR, tail_value)
}

async fn migrate_legacy_amendment_intent(
    data_dir: &str,
    tail_value: &str,
    intent: &Value,
) -> Result<(), VErr> {
    let (mut evidence, key) = validate_legacy_amendment_intent(data_dir, intent)?;
    let existing = super::system_activation_routes::recover_wallet_consumption(
        data_dir,
        &evidence.wallet_consumption_tail,
    )?;
    let receipt = match existing {
        Some(value) => Some(serde_json::from_value(value).map_err(|error| {
            verr(
                "system_lifecycle_wallet_consumption_invalid",
                error.to_string(),
            )
        })?),
        None => match super::wallet_network_capability_client::
            recover_approval_grant_consumption_for_effect_v2(&evidence.wallet_params)
            .await
        {
            Ok(value) => value,
            Err(super::wallet_network_capability_client::ResolveError::Refused(message)) => {
                return Err(verr("system_lifecycle_wallet_consumption_refused", message))
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
        },
    };
    let wallet_value = match receipt {
        Some(receipt) => Some(validate_wallet_receipt(&mut evidence, &receipt)?),
        None => None,
    };
    with_source_locks(|| {
        let current = load_local(data_dir, AMENDMENT_INTENT_DIR, tail_value)?.ok_or_else(|| {
            verr(
                "system_lifecycle_pending_convergence",
                "legacy migration intent vanished",
            )
        })?;
        if current != *intent {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                "legacy migration intent changed",
            ));
        }
        persist_legacy_amendment_resolution(
            data_dir,
            tail_value,
            intent,
            &key,
            &evidence,
            wallet_value.as_ref(),
        )
    })
}

async fn replay_one_amendment(
    data_dir: &str,
    tail_value: &str,
    intent: &Value,
) -> Result<(), VErr> {
    verify_intent_seal(intent)?;
    verify_amendment_intent_coordinates(tail_value, intent)?;
    if amendment_intent_generation(intent)? == AmendmentIntentGeneration::LegacyUnboundGovernance {
        return migrate_legacy_amendment_intent(data_dir, tail_value, intent).await;
    }
    let key = required(intent, "/source_record_tail")?;
    let sealed_plan = intent.get("compiled_plan").cloned().ok_or_else(|| {
        verr(
            "system_lifecycle_intent_invalid",
            "intent lacks its compiled plan",
        )
    })?;
    let amendment = intent
        .pointer("/request_body/amendment")
        .cloned()
        .ok_or_else(|| {
            verr(
                "system_lifecycle_intent_invalid",
                "intent lacks its sealed amendment declaration",
            )
        })?;
    let approval_decision = intent
        .pointer("/request_body/amendment_approval_decision")
        .cloned()
        .ok_or_else(|| {
            verr(
                "system_lifecycle_intent_invalid",
                "intent lacks its amendment approval decision",
            )
        })?;
    let successor_constitution = intent
        .pointer("/request_body/successor_constitution")
        .cloned()
        .ok_or_else(|| {
            verr(
                "system_lifecycle_intent_invalid",
                "intent lacks its sealed successor constitution",
            )
        })?;
    let source = source_at_plan(data_dir, &key, &sealed_plan)?;
    let approval_authority_evidence_root = required(
        &sealed_plan,
        "/authority_effect/approval_authority_evidence_root",
    )?;
    let plan = compile_amendment_from_source(
        &source,
        &amendment,
        &approval_decision,
        &approval_authority_evidence_root,
        &successor_constitution,
    )?;
    let (_, durable_approval_root) = load_approval_authority_evidence(data_dir, &source, &plan)?
        .ok_or_else(|| {
            verr(
                "system_governance_approval_missing",
                "sealed amendment intent lacks durable governance approval evidence",
            )
        })?;
    if durable_approval_root != approval_authority_evidence_root {
        return Err(verr(
            "system_governance_approval_invalid",
            "sealed amendment intent names different governance approval evidence",
        ));
    }
    if plan_to_value(&plan)? != sealed_plan {
        return Err(verr(
            "system_lifecycle_source_conflict",
            "replay plan does not reconstruct byte-exactly",
        ));
    }
    let mut evidence = evidence_from_intent(&intent["governed_authority"])?;
    let governing = required(&source.activation_effect, "/source_governing_authority_ref")?;
    let rebuilt = prepare_node_evidence_for(
        &plan.authority_effect,
        AMENDMENT_OP,
        plan.sequence,
        AMENDMENT_REQUIRED_SCOPE,
        &governing,
        &plan.resulting_state_root,
        evidence.authorized.clone(),
    )?;
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
    let system_id = required(&plan.authority_effect, "/system_id")?;
    let reservation = reserve_chain_writer(
        data_dir,
        &system_id,
        plan.sequence,
        required(&plan.authority_effect, "/predecessor_chain_head_root")?.as_str(),
        required(&plan.authority_effect, "/operation_commitment")?.as_str(),
        &format!(
            "proposal://{}/amend-constitution/{}",
            ns(&system_id)?,
            plan.sequence,
        ),
        required(&plan.authority_effect, "/operation_commitment")?.as_str(),
        AMENDMENT_OP,
    );
    if let Err(error) = reservation {
        if error.0 == "system_lifecycle_head_conflict" {
            remove_intent(data_dir, AMENDMENT_INTENT_DIR, tail_value)?;
        }
        return Err(error);
    }
    let existing = super::system_activation_routes::recover_wallet_consumption(
        data_dir,
        &evidence.wallet_consumption_tail,
    )?;
    let wallet_receipt: ApprovalGrantConsumptionReceipt = match existing {
        Some(value) => serde_json::from_value(value).map_err(|error| {
            verr(
                "system_lifecycle_wallet_consumption_invalid",
                error.to_string(),
            )
        })?,
        None => {
            let recovered = super::wallet_network_capability_client::
                recover_approval_grant_consumption_for_effect_v2(&evidence.wallet_params)
                .await;
            match recovered {
                Ok(Some(value)) => value,
                Ok(None) => match super::wallet_network_capability_client::
                    consume_approval_grant_for_effect_v2(evidence.wallet_params.clone())
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
                            remove_intent(data_dir, AMENDMENT_INTENT_DIR, tail_value)?;
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
                },
                Err(super::wallet_network_capability_client::ResolveError::Refused(message)) => {
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
    let tuple = decision_tuple(&evidence)?;
    let artifacts = build_amendment_artifacts(&plan, &source, &tuple, &timestamp)?;
    with_source_locks(|| {
        let current = load_local(data_dir, AMENDMENT_INTENT_DIR, tail_value)?.ok_or_else(|| {
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
        persist_amendment_graph(data_dir, &artifacts, &evidence, &wallet_value)?;
        remove_intent(data_dir, AMENDMENT_INTENT_DIR, tail_value)
    })
}

async fn replay_one_approval_intent(
    data_dir: &str,
    tail_value: &str,
    intent: &Value,
) -> Result<(), VErr> {
    verify_intent_seal(intent)?;
    verify_approval_intent_coordinates(tail_value, intent)?;
    let key = required(intent, "/source_record_tail")?;
    let body = intent.get("request_body").cloned().ok_or_else(|| {
        verr(
            "system_lifecycle_intent_invalid",
            "governance approval intent lacks its request body",
        )
    })?;
    let sealed_plan = intent.get("compiled_plan").cloned().ok_or_else(|| {
        verr(
            "system_lifecycle_intent_invalid",
            "governance approval intent lacks its compiled plan",
        )
    })?;
    let amendment = body.get("amendment").cloned().ok_or_else(|| {
        verr(
            "system_lifecycle_intent_invalid",
            "governance approval intent lacks its amendment",
        )
    })?;
    let approval_decision = body
        .get("amendment_approval_decision")
        .cloned()
        .ok_or_else(|| {
            verr(
                "system_lifecycle_intent_invalid",
                "governance approval intent lacks its approval decision",
            )
        })?;
    let successor_constitution = body.get("successor_constitution").cloned().ok_or_else(|| {
        verr(
            "system_lifecycle_intent_invalid",
            "governance approval intent lacks its successor constitution",
        )
    })?;
    let source = source_at_plan(data_dir, &key, &sealed_plan)?;
    check_expected_roots(&body, &source)?;
    let placeholder_root = format!("sha256:{}", "00".repeat(32));
    let plan = compile_amendment_from_source(
        &source,
        &amendment,
        &approval_decision,
        &placeholder_root,
        &successor_constitution,
    )?;
    if plan_to_value(&plan)? != sealed_plan {
        return Err(verr(
            "system_lifecycle_source_conflict",
            "governance approval replay plan does not reconstruct byte-exactly",
        ));
    }
    let effect = amendment_approval_effect(&source, &plan)?;
    if intent.get("approval_effect") != Some(&effect) {
        return Err(verr(
            "system_lifecycle_intent_unreadable",
            "governance approval intent detaches from its recomputed effect",
        ));
    }
    let authorized: AuthorizedDecision =
        serde_json::from_value(intent.get("authorized_approval").cloned().ok_or_else(|| {
            verr(
                "system_lifecycle_intent_invalid",
                "governance approval intent lacks authority evidence",
            )
        })?)
        .map_err(|error| verr("system_lifecycle_intent_invalid", error.to_string()))?;
    let required_authority = approval_governance_authority(&source)?;
    governed::verify_retained_decision_evidence(
        &authorized.evidence,
        authorized.resolved_at_ms,
        &required_authority,
        AMENDMENT_APPROVAL_SCOPE,
    )
    .map_err(|message| verr("system_governance_approval_invalid", message))?;
    let wallet_use = governance_approval_wallet_use(&source, &plan, &effect, &authorized)?;
    if intent.get("wallet_params")
        != Some(
            &serde_json::to_value(&wallet_use.params)
                .map_err(|error| verr("system_lifecycle_intent_invalid", error.to_string()))?,
        )
    {
        return Err(verr(
            "system_lifecycle_intent_unreadable",
            "governance approval wallet coordinates do not reconstruct",
        ));
    }
    let wallet_receipt = match recover_or_consume_governance_approval(&wallet_use).await {
        Ok(value) => value,
        Err(failure) => {
            if failure.definitively_unconsumed {
                remove_matching_approval_intent(data_dir, tail_value, intent)?;
            }
            return Err(failure.error);
        }
    };
    let evidence =
        approval_authority_evidence(&source, &plan, &effect, authorized, wallet_receipt)?;
    with_source_locks(|| {
        let current =
            load_local(data_dir, AMENDMENT_APPROVAL_INTENT_DIR, tail_value)?.ok_or_else(|| {
                verr(
                    "system_lifecycle_pending_convergence",
                    "governance approval replay intent vanished",
                )
            })?;
        if current != *intent {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                "governance approval replay intent changed",
            ));
        }
        let fresh = source_at_plan(data_dir, &key, &sealed_plan)?;
        let recompiled = compile_amendment_from_source(
            &fresh,
            &amendment,
            &approval_decision,
            &placeholder_root,
            &successor_constitution,
        )?;
        if plan_to_value(&recompiled)? != sealed_plan {
            return Err(verr(
                "system_lifecycle_source_conflict",
                "governance approval replay truth changed before persistence",
            ));
        }
        persist_governance_approval(data_dir, &fresh, &recompiled, &evidence)?;
        remove_intent(data_dir, AMENDMENT_APPROVAL_INTENT_DIR, tail_value)
    })
}

fn scan_approval_intents(data_dir: &str) -> Result<Vec<(String, Result<Value, VErr>)>, VErr> {
    let directory =
        match super::durable_fs::open_family_dir_pinned(data_dir, AMENDMENT_APPROVAL_INTENT_DIR) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(verr(
                    "system_lifecycle_intent_unreadable",
                    format!("approval intent family cannot be pinned ({error})"),
                ))
            }
        };
    let mut names = super::durable_fs::enumerate_pinned(&directory).map_err(|error| {
        verr(
            "system_lifecycle_intent_unreadable",
            format!("approval intent family cannot be enumerated ({error})"),
        )
    })?;
    names.sort();
    Ok(names
        .into_iter()
        .map(|name| {
            let tail_value = name.strip_suffix(".json").unwrap_or(&name).to_owned();
            let checked = (|| {
                if !name.ends_with(".json") {
                    return Err(verr(
                        "system_lifecycle_intent_unreadable",
                        format!("unexpected approval intent entry '{name}'"),
                    ));
                }
                let bytes = super::durable_fs::read_slot_strict(&directory, &name)
                    .map_err(|error| {
                        verr(
                            "system_lifecycle_intent_unreadable",
                            format!("approval intent '{name}' is unreadable ({error})"),
                        )
                    })?
                    .ok_or_else(|| {
                        verr(
                            "system_lifecycle_intent_unreadable",
                            format!("approval intent '{name}' vanished"),
                        )
                    })?
                    .1;
                let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
                    verr(
                        "system_lifecycle_intent_unreadable",
                        format!("approval intent '{name}' is malformed ({error})"),
                    )
                })?;
                verify_intent_seal(&value)?;
                verify_approval_intent_coordinates(&tail_value, &value)?;
                Ok(value)
            })();
            (tail_value, checked)
        })
        .collect())
}

fn scan_amendment_intents(data_dir: &str) -> Result<Vec<(String, Result<Value, VErr>)>, VErr> {
    // Intents are local-durable pre-admission records: read them through the
    // raw pinned reader, never through the Agentgres exact-proof loader.
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, AMENDMENT_INTENT_DIR)
    {
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
            let tail_value = name.strip_suffix(".json").unwrap_or(&name).to_owned();
            let checked = (|| {
                if !name.ends_with(".json") {
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
                verify_amendment_intent_coordinates(&tail_value, &value)?;
                Ok(value)
            })();
            (tail_value, checked)
        })
        .collect())
}

fn refuse_pending_for_key(
    entries: Vec<(String, Result<Value, VErr>)>,
    key: &str,
    message: &str,
) -> Result<(), VErr> {
    for (_tail, intent) in entries {
        let intent = intent?;
        if intent.get("source_record_tail").and_then(Value::as_str) == Some(key) {
            return Err(verr("system_lifecycle_pending_convergence", message));
        }
    }
    Ok(())
}

/// Refuse a new lifecycle mutation for `key` while either the declaration's
/// one-use governance approval or the amendment execution itself is pending;
/// bootstrap and protected pendency are checked by the callers through their
/// own choke points.
pub(crate) fn ensure_no_pending_amendment_intent(data_dir: &str, key: &str) -> Result<(), VErr> {
    refuse_pending_for_key(
        scan_approval_intents(data_dir)?,
        key,
        "a constitutional amendment governance approval intent is still pending",
    )?;
    refuse_pending_for_key(
        scan_amendment_intents(data_dir)?,
        key,
        "a constitutional amendment intent is still pending",
    )
}

/// Boot/periodic replay driver: converge pending amendment intents, keeping
/// poisoned ones retained with their reasons.
pub(crate) async fn complete_amendment_intents(data_dir: &str, max: usize) {
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let approval_entries = match scan_approval_intents(data_dir) {
        Ok(entries) => entries,
        Err((_, message)) => {
            eprintln!("ConstitutionAmendment approval replay scan failed ({message})");
            return;
        }
    };
    let approval_start = AMENDMENT_REPLAY_CURSOR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    for (offset, _) in approval_entries.iter().enumerate().take(max) {
        let index = (approval_start + offset) % approval_entries.len().max(1);
        let (tail_value, result) = &approval_entries[index];
        let intent = match result {
            Ok(intent) => intent,
            Err((_, message)) => {
                eprintln!(
                    "ConstitutionAmendment poisoned approval intent '{tail_value}' retained ({message})"
                );
                continue;
            }
        };
        if let Err((_, message)) = replay_one_approval_intent(data_dir, tail_value, intent).await {
            eprintln!(
                "ConstitutionAmendment approval intent '{tail_value}' retained/incomplete ({message})"
            );
        }
    }
    let entries = match scan_amendment_intents(data_dir) {
        Ok(entries) => entries,
        Err((_, message)) => {
            eprintln!("ConstitutionAmendment replay scan failed ({message})");
            return;
        }
    };
    let start = AMENDMENT_REPLAY_CURSOR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    for (offset, _) in entries.iter().enumerate().take(max) {
        let index = (start + offset) % entries.len().max(1);
        let (tail_value, result) = &entries[index];
        let intent = match result {
            Ok(intent) => intent,
            Err((_, message)) => {
                eprintln!(
                    "ConstitutionAmendment poisoned intent '{tail_value}' retained ({message})"
                );
                continue;
            }
        };
        if let Err((_, message)) = replay_one_amendment(data_dir, tail_value, intent).await {
            eprintln!(
                "ConstitutionAmendment intent '{tail_value}' retained/incomplete ({message})"
            );
        }
    }
}

#[cfg(test)]
mod builder_tests {
    use super::*;
    use ioi_types::app::system_amendment_execution::{
        amendment_approval_decision_root, changed_paths_commitment, constitution_candidate_root,
    };

    fn fixture(path: &str) -> Value {
        let root = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/"
        );
        serde_json::from_str(&std::fs::read_to_string(format!("{root}{path}")).expect(path))
            .expect(path)
    }

    fn h(marker: u8) -> String {
        format!("sha256:{}", format!("{marker:02x}").repeat(32))
    }

    #[test]
    fn pending_governance_approval_entry_interlocks_the_target_system() {
        let target = "asg_target";
        let error = refuse_pending_for_key(
            vec![(
                "asagai_pending".to_owned(),
                Ok(json!({ "source_record_tail": target })),
            )],
            target,
            "approval pending",
        )
        .expect_err("the target system must remain interlocked");
        assert_eq!(error.0, "system_lifecycle_pending_convergence");

        refuse_pending_for_key(
            vec![(
                "asagai_foreign".to_owned(),
                Ok(json!({ "source_record_tail": "asg_foreign" })),
            )],
            target,
            "approval pending",
        )
        .expect("a foreign system's approval intent must not interlock this system");
    }

    #[test]
    fn amendment_intent_generation_is_closed_and_never_partially_migrated() {
        let legacy = json!({
            "request_body": {},
            "compiled_plan": {"authority_effect": {}},
        });
        assert_eq!(
            amendment_intent_generation(&legacy).expect("legacy generation"),
            AmendmentIntentGeneration::LegacyUnboundGovernance,
        );

        let current = json!({
            "request_body": {"amendment_approval_decision": {}},
            "compiled_plan": {
                "approval_decision": {},
                "approval_decision_root": h(1),
                "authority_effect": {
                    "approval_decision_root": h(1),
                    "approval_authority_evidence_root": h(2),
                },
            },
        });
        assert_eq!(
            amendment_intent_generation(&current).expect("current generation"),
            AmendmentIntentGeneration::CurrentBoundGovernance,
        );

        let mixed = json!({
            "request_body": {"amendment_approval_decision": {}},
            "compiled_plan": {"authority_effect": {}},
        });
        assert_eq!(
            amendment_intent_generation(&mixed)
                .expect_err("mixed generations must fail closed")
                .0,
            "system_lifecycle_intent_invalid",
        );
    }

    #[test]
    fn definitive_refusal_cleanup_removes_the_matching_approval_intent() {
        let data_dir = tempfile::tempdir().expect("data dir");
        let data_dir = data_dir.path().to_str().expect("utf8 path");
        let tail_value = format!("asagai_{}", "ab".repeat(32));
        let intent = json!({
            "schema_version": "ioi.hypervisor.constitution-amendment-governance-approval-intent.v1",
            "source_record_tail": "asg_target",
        });
        persist_local(
            data_dir,
            AMENDMENT_APPROVAL_INTENT_DIR,
            &tail_value,
            &intent,
        )
        .expect("persist intent");

        remove_matching_approval_intent(data_dir, &tail_value, &intent)
            .expect("remove matching intent");
        assert!(
            load_local(data_dir, AMENDMENT_APPROVAL_INTENT_DIR, &tail_value)
                .expect("read intent")
                .is_none()
        );
    }

    /// A full contract-valid constitution body. The predecessor keeps the
    /// chain-declared root (genesis-inherited binding); the successor's
    /// root is recomputed by the minted recipe.
    fn constitution(
        id: &str,
        version: &str,
        root: &str,
        predecessor_ref: &str,
        system_id: &str,
    ) -> Value {
        // Full contract-valid body (the constitution.v1 positive fixture),
        // parameterized on the lineage fields. Both predecessor and successor
        // persist as `active`.
        json!({
            "schema_version": "ioi.autonomous-system-constitution.v1",
            "constitution_id": id,
            "system_id": system_id,
            "version": version,
            "predecessor_constitution_ref": predecessor_ref,
            "declared_purpose": {
                "statement": "Pursue bounded research outcomes for accountable project stakeholders.",
                "ontology_refs": ["ontology://acme/research/v1"],
                "beneficiary_or_stakeholder_refs": ["org://acme/research"],
                "acceptance_policy_refs": ["policy://acme/acceptance/research"]
            },
            "normative_constraints": {
                "invariant_refs": ["invariant://acme/no-unreceipted-effects/v1"],
                "permitted_objective_policy_refs": ["policy://acme/objectives/permitted"],
                "prohibited_objective_policy_refs": ["policy://acme/objectives/prohibited"],
                "permitted_ontology_action_contract_refs": [],
                "prohibited_effect_policy_refs": ["policy://acme/effects/prohibited"]
            },
            "agency_boundary": {
                "authority_ceiling_scope_refs": ["scope:network.read"],
                "delegable_scope_refs": [],
                "non_delegable_scope_refs": ["scope:governance.amend"],
                "resource_and_budget_ceiling_policy_refs": ["policy://acme/budget/ceiling"],
                "time_and_duration_ceiling_policy_refs": ["policy://acme/time/ceiling"],
                "data_and_privacy_ceiling_policy_refs": ["policy://acme/privacy/default"],
                "effect_and_externality_ceiling_policy_refs": ["policy://acme/effects/ceiling"],
                "egress_policy_ref": "policy://acme/egress/default",
                "node_expansion": "governed_membership_only",
                "code_propagation": "admitted_deployment_only",
                "self_authority_widening": "forbidden"
            },
            "governance": {
                "governance_owner_refs": ["org://acme/research"],
                "accountable_principal_refs": ["wallet://acme/governance"],
                "affected_party_policy_ref": "policy://acme/governance/affected-parties",
                "ordinary_upgrade_policy_ref": "policy://acme/governance/upgrades",
                "amendment_mode": "external_governance_only",
                "amendment_decision_profile_ref": "policy://acme/governance/amendments",
                "protected_clause_refs": ["constitution-clause://acme/purpose"],
                "protected_field_paths": ["/declared_purpose"],
                "agent_may_propose_amendment": true,
                "agent_may_commit_amendment": false,
                "emergency_pause_authority_refs": ["wallet://acme/governance"],
                "revocation_authority_refs": ["wallet://acme/governance"]
            },
            "protected_profile_governance": {
                "improvement_governance_profile_ref": Value::Null,
                "improvement_governance_profile_change_decision_profile_ref": Value::Null,
                "deployment_constraint_ref": "policy://acme/deployment/constraint",
                "deployment_change_decision_profile_ref": "policy://acme/deployment/change",
                "ordering_admission_finality_constraint_ref": "policy://acme/ordering/constraint",
                "ordering_profile_change_decision_profile_ref": "policy://acme/ordering/change",
                "oracle_evidence_constraint_ref": "policy://acme/oracle/constraint",
                "oracle_profile_change_decision_profile_ref": "policy://acme/oracle/change",
                "lifecycle_continuity_constraint_ref": "policy://acme/lifecycle/constraint",
                "lifecycle_profile_change_decision_profile_ref": "policy://acme/lifecycle/change",
                "network_enrollment_constraint_ref": "policy://acme/network/local-only",
                "network_enrollment_change_decision_profile_ref": "policy://acme/network/change"
            },
            "shutdown": {
                "kill_switch_ref": "policy://acme/shutdown/kill-switch",
                "decommission_policy_ref": "policy://acme/shutdown/decommission",
                "minimum_archive_policy_ref": "policy://acme/archive/minimum"
            },
            // Structural (diff-excluded): the constitution lineage was
            // activated once at System activation; amendment revisions inherit
            // that activation receipt rather than re-activating.
            "activation_receipt_ref": "receipt://acme/system-alpha/activation",
            "public_commitment_ref": Value::Null,
            "status": "active",
            "constitution_root": root,
        })
    }

    /// A coherent durable prior assembled from the REAL registered fixtures
    /// (v1 activation-prefix log + sequence-two chain revision) extended
    /// with the amendment inputs: the chain's constitution body, the
    /// predecessor state's profile set, and a contract-valid declaration.
    fn amendment_fixture() -> (AmendmentSource, Value, Value, Value) {
        let log = fixture("autonomous-system-operation-log-v1/positive-activation-prefix.json");
        let mut chain = fixture("autonomous-system-chain-v1/positive-active-sequence-two.json");
        assert_eq!(log["operation_log_root"], chain["operation_log_root"]);
        assert_eq!(log["latest_state_root"], chain["latest_state_root"]);
        let system_id = log["system_id"].as_str().unwrap().to_owned();
        let head = &log["head_entry"];
        let previous_step = UnverifiedCommittedSystemLifecycleStep {
            proposal: json!({"proposal_ref": head["proposal_ref"]}),
            decision: json!({"decision_ref": head["decision_ref"]}),
            state: json!({
                "activation_state_ref": head["state_ref"],
                "system_id": system_id,
                "sequence": 2,
                "status": "active",
                "active_profile_set_ref": chain["active_profile_set_ref"],
                "active_profile_set_root": chain["active_profile_set_root"],
            }),
            transition: json!({"lifecycle_transition_id": head["transition_ref"]}),
            receipt: json!({"receipt_ref": head["receipt_ref"]}),
            state_root: log["latest_state_root"].as_str().unwrap().to_owned(),
            proposal_root: head["proposal_root"].as_str().unwrap().to_owned(),
            decision_root: head["decision_root"].as_str().unwrap().to_owned(),
            transition_root: head["transition_root"].as_str().unwrap().to_owned(),
            receipt_root: head["receipt_root"].as_str().unwrap().to_owned(),
        };
        let activation_effect = json!({
            "schema_version": "ioi.autonomous-system-lifecycle-authority-effect.v1",
            "operation": "activate",
            "sequence": 2,
            "system_id": system_id,
            "genesis_ref": chain["genesis_ref"],
            "genesis_admission_record_root": chain["genesis_admission_record_root"],
            "genesis_admission_receipt_ref": format!("receipt://asgar_{}", "61".repeat(32)),
            "genesis_admission_receipt_root": h(0x71),
            "sequence_zero_materialization_id": log["entries"][0]["materialization_ref"],
            "sequence_zero_materialization_root": log["entries"][0]["materialization_root"],
            "sequence_zero_receipt_ref": log["entries"][0]["receipt_ref"],
            "sequence_zero_receipt_root": log["entries"][0]["receipt_root"],
            "sequence_zero_receipt_artifact_root": log["entries"][0]["receipt_artifact_root"],
            "component_registry_ref": log["entries"][0]["component_registry_ref"],
            "component_registry_root": log["entries"][0]["component_registry_root"],
            "materialization_wallet_consumption_ref": log["entries"][0]["wallet_consumption_ref"],
            "materialization_wallet_consumption_root":
                log["entries"][0]["wallet_consumption_root"],
            "profile_bundle_root": h(0x72),
            "source_governing_authority_ref": "wallet://acme/governance",
            "home_domain_ref": log["home_domain_ref"],
            "home_domain_commitment": log["home_domain_commitment"],
            "home_domain_binding_ref": log["home_domain_binding_ref"],
            "home_domain_binding_root": log["home_domain_binding_root"],
            "policy_root": log["policy_root"],
            "module_registry_root": log["module_registry_root"],
            "upgrade_policy_ref": log["upgrade_policy_ref"],
            "deployment_profile_ref": chain["deployment_profile_ref"],
            "deployment_profile_root": chain["deployment_profile_root"],
            "active_profile_set_ref": chain["active_profile_set_ref"],
            "active_profile_set_root": chain["active_profile_set_root"],
            "chain_ref": chain["chain_ref"],
            "live_chain_created": true,
            "node_membership_created": false,
            "runtime_effect_admitted": false,
            "network_effect_admitted": false,
        });
        let predecessor_constitution = constitution(
            chain["constitution_ref"].as_str().unwrap(),
            "1.0.0",
            chain["constitution_root"].as_str().unwrap(),
            "constitution://acme/system-alpha/root-lineage",
            &system_id,
        );
        let predecessor_root = constitution_candidate_root(&predecessor_constitution).unwrap();
        chain["constitution_root"] = json!(predecessor_root);
        let mut successor_constitution = constitution(
            "constitution://acme/system-alpha/v2",
            "1.1.0",
            "",
            chain["constitution_ref"].as_str().unwrap(),
            &system_id,
        );
        successor_constitution["normative_constraints"]
            ["permitted_ontology_action_contract_refs"] =
            json!(["ontology-action://acme/added/v1"]);
        successor_constitution["constitution_root"] =
            predecessor_constitution["constitution_root"].clone();
        successor_constitution["activation_receipt_ref"] = head["receipt_ref"].clone();
        let successor_root = constitution_candidate_root(&successor_constitution).unwrap();
        let amendment = json!({
            "schema_version": "ioi.autonomous-system-constitution-amendment.v1",
            "amendment_id": "constitution-amendment://acme/system-alpha/2",
            "system_id": system_id,
            "predecessor_constitution_ref": chain["constitution_ref"],
            "predecessor_constitution_root": chain["constitution_root"],
            "proposed_successor_constitution_ref":
                successor_constitution["constitution_id"],
            "proposed_successor_constitution_root": successor_root,
            "changed_field_paths": ["/normative_constraints/permitted_ontology_action_contract_refs"],
            "protected_field_paths": ["/declared_purpose"],
            "governing_decision_profile_ref": "policy://acme/governance/amendments",
            "proposal_ref": "proposal://acme/constitution-amendment/2",
            "evidence_refs": ["evidence://acme/amendment/2"],
            "authority_requirement_refs": ["authority-requirement://acme/governance/amend"],
            "proposed_by_ref": system_id,
            "decision_ref": "decision://acme/constitution-amendment/2",
            "status": "approved",
        });
        let paths =
            vec!["/normative_constraints/permitted_ontology_action_contract_refs".to_owned()];
        let mut approval_decision = json!({
            "schema_version": "ioi.autonomous-system-constitution-amendment-approval-decision.v1",
            "decision_ref": amendment["decision_ref"],
            "decision_root": Value::Null,
            "amendment_ref": amendment["amendment_id"],
            "amendment_root": ioi_types::app::system_amendment_execution::amendment_declaration_root(&amendment).unwrap(),
            "proposal_ref": amendment["proposal_ref"],
            "system_id": system_id,
            "governing_decision_profile_ref": amendment["governing_decision_profile_ref"],
            "predecessor_constitution_root": amendment["predecessor_constitution_root"],
            "successor_constitution_root": amendment["proposed_successor_constitution_root"],
            "changed_field_paths_commitment": changed_paths_commitment(&paths).unwrap(),
            "evidence_refs": amendment["evidence_refs"],
            "authority_requirement_refs": amendment["authority_requirement_refs"],
            "outcome": "approved",
            "decided_at": "2026-07-23T12:00:00Z",
        });
        approval_decision["decision_root"] =
            json!(amendment_approval_decision_root(&approval_decision).unwrap());
        let predecessor_profile_set = json!({
            "schema_version": "ioi.autonomous-system-active-profile-set.v1",
            "active_profile_set_ref": chain["active_profile_set_ref"],
            "active_profile_set_root": chain["active_profile_set_root"],
            "system_id": system_id,
            "genesis_ref": chain["genesis_ref"],
            "profile_bundle_root": h(0x72),
            "constitution": {
                "candidate_profile_ref": chain["constitution_ref"],
                "candidate_profile_root": chain["constitution_root"],
                "admitted_posture": "active",
            },
            "deployment": {
                "candidate_profile_ref": chain["deployment_profile_ref"],
                "candidate_profile_root": chain["deployment_profile_root"],
                "admitted_posture": "active",
            },
            "ordering_admission_finality": {
                "candidate_profile_ref": chain["ordering_admission_finality_profile_ref"],
                "candidate_profile_root": h(0x43),
                "admitted_posture": "active",
            },
            "oracle_evidence_profiles": [],
            "lifecycle_continuity": {
                "candidate_profile_ref": chain["lifecycle_continuity_profile_ref"],
                "candidate_profile_root": h(0x44),
                "admitted_posture": "active",
            },
            "network_enrollment": Value::Null,
            "status": "active",
        });
        (
            AmendmentSource {
                activation_effect,
                previous_step,
                chain_head: chain,
                operation_log: log,
                predecessor_constitution,
                predecessor_profile_set,
            },
            amendment,
            approval_decision,
            successor_constitution,
        )
    }

    fn authority_tuple() -> DecisionAuthorityTuple {
        DecisionAuthorityTuple {
            input_hash: h(0x51),
            policy_hash: h(0x52),
            effect_hash: h(0x53),
            authority_grant_ref: format!("grant://wallet.network/approval/{}", h(0x54)),
            authority_evidence_ref: format!(
                "system-lifecycle-authority-evidence://aslae_{}",
                "55".repeat(32)
            ),
            authority_evidence_root: h(0x55),
            wallet_grant_consumption_ref: format!(
                "wallet.network://approval-effect-consumption/{}/{}",
                "56".repeat(32),
                "58".repeat(32)
            ),
            wallet_grant_consumption_root: h(0x56),
            wallet_grant_consumption_evidence_ref: format!(
                "system-lifecycle-authority-consumption://aslac_{}",
                "57".repeat(32)
            ),
        }
    }

    const TS: &str = "2026-07-22T12:00:00.000Z";

    fn built() -> (
        CompiledAmendmentExecutionPlan,
        AmendmentSource,
        AmendmentStepArtifacts,
    ) {
        let (source, amendment, approval_decision, successor) = amendment_fixture();
        let plan = compile_amendment_from_source(
            &source,
            &amendment,
            &approval_decision,
            &h(0x59),
            &successor,
        )
        .expect("plan");
        let artifacts =
            build_amendment_artifacts(&plan, &source, &authority_tuple(), TS).expect("artifacts");
        (plan, source, artifacts)
    }

    #[test]
    fn governance_approval_request_is_stable_across_execution_sequence_changes() {
        let (mut plan, source, _) = built();
        let effect = amendment_approval_effect(&source, &plan).expect("approval effect");
        let effect_hash = governed::decision_effect_hash(AMENDMENT_GOVERNANCE_AUTHORITY, &effect);
        let approved_at_sequence = plan.sequence;
        let request_hash = governance_approval_request_hash(&source, &plan, &effect_hash)
            .expect("governance request hash");

        // Pause/resume or another unrelated lifecycle operation may advance
        // the chain before execution authorization. Governance approved the
        // immutable declaration and must not need to consume a second grant.
        plan.sequence += 2;
        assert_ne!(plan.sequence, approved_at_sequence);
        assert_eq!(
            governance_approval_request_hash(&source, &plan, &effect_hash)
                .expect("stable governance request hash"),
            request_hash,
        );
    }

    #[test]
    fn proposal_root_recomputes_per_the_invariant_material() {
        let (_, _, artifacts) = built();
        let proposal = &artifacts.step.proposal;
        let mut material = proposal.as_object().cloned().expect("object");
        material.remove("schema_version");
        material.remove("proposal_root");
        material.insert("domain".to_owned(), json!(AMENDMENT_PROPOSAL_HASH_DOMAIN));
        let recomputed = jcs_hash(&Value::Object(material)).expect("hash");
        assert_eq!(proposal["proposal_root"], json!(recomputed));
        assert_eq!(proposal["op"], json!("amend_constitution"));
        assert_eq!(proposal["status"], json!("proposed"));
        // The contract-pinned effect hash is the plain JCS hash of the
        // embedded effect.
        assert_eq!(
            proposal["authority_effect_hash"],
            json!(jcs_hash(&proposal["authority_effect"]).expect("hash")),
        );
    }

    #[test]
    fn decision_binds_the_proposal_effect_hash_and_recomputes() {
        let (_, _, artifacts) = built();
        let decision = &artifacts.step.decision;
        assert_eq!(
            decision["effect_hash"],
            artifacts.step.proposal["authority_effect_hash"],
        );
        assert_eq!(
            decision["proposal_root"],
            json!(artifacts.step.proposal_root)
        );
        assert_eq!(decision["outcome"], json!("admitted"));
        let mut material = decision.as_object().cloned().expect("object");
        material.remove("schema_version");
        material.remove("decision_root");
        material.insert("domain".to_owned(), json!(AMENDMENT_DECISION_HASH_DOMAIN));
        let recomputed = jcs_hash(&Value::Object(material)).expect("hash");
        assert_eq!(decision["decision_root"], json!(recomputed));
    }

    #[test]
    fn receipt_boundary_is_exactly_the_nonnull_refs_plus_authority_coordinates() {
        let (plan, _, artifacts) = built();
        let receipt = &artifacts.step.receipt;
        let authority = authority_tuple();
        let mut expected = vec![
            plan.authority_effect["system_id"]
                .as_str()
                .unwrap()
                .to_owned(),
            artifacts.step.proposal["proposal_ref"]
                .as_str()
                .unwrap()
                .to_owned(),
            artifacts.step.decision["decision_ref"]
                .as_str()
                .unwrap()
                .to_owned(),
            artifacts.step.transition["lifecycle_transition_id"]
                .as_str()
                .unwrap()
                .to_owned(),
            plan.amendment["amendment_id"].as_str().unwrap().to_owned(),
            plan.amendment["predecessor_constitution_ref"]
                .as_str()
                .unwrap()
                .to_owned(),
            plan.successor_constitution["constitution_id"]
                .as_str()
                .unwrap()
                .to_owned(),
            plan.authority_effect["resulting_state_ref"]
                .as_str()
                .unwrap()
                .to_owned(),
            plan.authority_effect["active_profile_set_ref"]
                .as_str()
                .unwrap()
                .to_owned(),
            plan.authority_effect["chain_ref"]
                .as_str()
                .unwrap()
                .to_owned(),
            authority.authority_grant_ref,
            authority.authority_evidence_ref,
            authority.wallet_grant_consumption_ref,
            authority.wallet_grant_consumption_evidence_ref,
        ];
        expected.sort();
        expected.dedup();
        assert_eq!(receipt["attested_boundary_fact_refs"], json!(expected));
        assert_eq!(receipt["op"], json!("amend_constitution"));
        assert_eq!(
            receipt["required_scope"],
            json!("scope:autonomous_system.lifecycle.amend_constitution"),
        );
        assert_eq!(
            receipt["bound_facts"]["successor_constitution_root"],
            json!(plan.successor_constitution_root),
        );
        assert_eq!(
            receipt["bound_facts"]["changed_field_paths_commitment"],
            json!(plan.changed_field_paths_commitment),
        );
        assert_eq!(
            receipt["bound_facts"]["predecessor_chain_head_root"],
            plan.authority_effect["predecessor_chain_head_root"],
        );
        assert_eq!(
            receipt["bound_facts"]["approval_decision_root"],
            json!(plan.approval_decision_root),
        );
        assert_eq!(receipt["wallet_grant_consumption_root"], json!(h(0x56)));
        assert_ne!(
            receipt["wallet_grant_consumption_root"],
            receipt["effect_hash"],
        );
        assert_eq!(
            receipt["assurance_posture"],
            json!("constitutional_amendment_committed"),
        );
    }

    #[test]
    fn log_appends_a_constitution_amendment_entry_with_continuity() {
        let (plan, source, artifacts) = built();
        assert_eq!(plan.sequence, 3);
        let log = &artifacts.operation_log;
        assert_eq!(
            log["schema_version"],
            json!("ioi.autonomous-system-operation-log.v2")
        );
        assert_eq!(log["latest_sequence"], 3);
        assert_eq!(log["entries"].as_array().unwrap().len(), 4);
        let entry = &log["head_entry"];
        assert_eq!(entry["entry_kind"], json!("constitution_amendment"));
        assert_eq!(entry["operation_name"], json!("amend_constitution"));
        assert_eq!(
            entry["required_scope"],
            json!("scope:autonomous_system.lifecycle.amend_constitution"),
        );
        assert_eq!(
            entry["predecessor_state_root"],
            source.operation_log["latest_state_root"],
        );
        assert_eq!(
            entry["active_profile_set_root"],
            json!(plan.successor_profile_set_root),
        );
    }

    #[test]
    fn chain_swaps_only_the_constitution_and_head_coordinates() {
        let (plan, source, artifacts) = built();
        let prior = source.chain_head.as_object().unwrap();
        let next = artifacts.chain.as_object().unwrap();
        assert_eq!(
            prior.keys().collect::<Vec<_>>(),
            next.keys().collect::<Vec<_>>()
        );
        let moved: &[&str] = &[
            "constitution_ref",
            "constitution_root",
            "latest_sequence",
            "latest_operation_commitment",
            "latest_transition_id",
            "latest_transition_root",
            "latest_receipt_ref",
            "latest_receipt_root",
            "latest_state_ref",
            "latest_state_root",
            "operation_log_ref",
            "operation_log_root",
            "chain_root",
            "created_at",
        ];
        for (key, prior_value) in prior {
            if moved.contains(&key.as_str()) {
                continue;
            }
            assert_eq!(
                prior_value, &next[key],
                "chain field '{key}' must carry verbatim through an amendment",
            );
        }
        assert_eq!(
            next["constitution_ref"],
            plan.successor_constitution["constitution_id"],
        );
        assert_eq!(
            next["constitution_root"],
            json!(plan.successor_constitution_root),
        );
        assert_eq!(next["latest_sequence"], 3);
        // Amendment never alters operational status.
        assert_eq!(next["status"], prior["status"]);
        assert_eq!(
            next["latest_state_root"].as_str().unwrap(),
            plan.resulting_state_root,
        );
    }

    #[test]
    fn profile_set_admitted_by_slots_fill_without_moving_the_root() {
        let (plan, _, artifacts) = built();
        let set = &artifacts.successor_profile_set;
        assert_eq!(
            set["admitted_by_transition_ref"],
            artifacts.step.transition["lifecycle_transition_id"],
        );
        assert_eq!(
            set["admitted_by_receipt_ref"],
            artifacts.step.receipt["receipt_ref"],
        );
        assert_eq!(set["created_at"], json!(TS));
        assert_eq!(
            set["active_profile_set_root"],
            json!(plan.successor_profile_set_root),
        );
        assert_eq!(
            set["schema_version"],
            json!("ioi.autonomous-system-active-profile-set.v2"),
        );
        assert_eq!(
            set["constitution"]["candidate_profile_root"],
            json!(plan.successor_constitution_root),
        );
    }

    #[test]
    fn state_slots_fill_and_status_stays_unchanged() {
        let (plan, _, artifacts) = built();
        let state = &artifacts.step.state;
        assert_eq!(state["sequence"], 3);
        assert_eq!(state["status"], json!("active"));
        assert_eq!(
            state["transition_ref"],
            artifacts.step.transition["lifecycle_transition_id"],
        );
        assert_eq!(
            state["transition_root"],
            json!(artifacts.step.transition_root),
        );
        assert_eq!(
            state["transition_receipt_ref"],
            artifacts.step.receipt["receipt_ref"],
        );
        assert_eq!(state["created_at"], json!(TS));
        assert_eq!(
            state["lifecycle_state_root"].as_str().unwrap(),
            plan.resulting_state_root,
        );
        assert_eq!(
            state["active_profile_set_root"],
            json!(plan.successor_profile_set_root),
        );
        // The declaration and successor constitution ride verbatim.
        assert_eq!(artifacts.declaration, plan.amendment);
        assert_eq!(
            artifacts.successor_constitution,
            plan.successor_constitution
        );
    }
}
