//! Named succession, migration, dissolution, and local-enrollment transitions.
//!
//! This is a distinct owner layer over the shared live-chain writer. It does
//! not reuse the generic protected proposal family or any of its wallet scopes.

use ioi_types::app::system_activation::UnverifiedCommittedSystemLifecycleStep;
use ioi_types::app::system_continuity_transitions::{
    compile_continuity_transition_plan, CompiledContinuityTransitionPlan,
    ContinuityTransitionDeclaration, ContinuityTransitionOp,
};
use serde_json::{json, Value};
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use ioi_services::agentic::runtime::kernel::approval::{
    ApprovalScopeContext, AuthorityScopeMatcher,
};
use ioi_services::wallet_network::{
    ApprovalGrantConsumptionReceipt, ConsumeApprovalGrantForEffectV2Params,
};

use super::governed_authority::{self as governed, AuthorityPolicyContext, Governance};
use super::system_activation_routes::{
    canonical_system_key, classify, contains_sensitive_key, evidence_from_intent,
    evidence_intent_value, forced_fault, intent_seal, jcs_hash, load_local, load_required_exact,
    ms_to_timestamp, persist_local, prepare_node_evidence_for, remove_intent, required_string,
    tail, validate_contract, validate_wallet_receipt, verify_intent_seal, verr, with_source_locks,
    AUTHORITY, AUTHORITY_CONSUMPTION_DIR, AUTHORITY_EVIDENCE_DIR, CHAIN_DIR, DECISION_DIR,
    MAX_REQUEST_BYTES, OPERATION_LOG_DIR, PROPOSAL_DIR, SYSTEM_ACTIVATION_GATE, TRANSITION_DIR,
};
use super::system_protected_transition_routes::{
    claim_chain_successor, continue_log_with_entry, current_governing_authority, decision_tuple,
    load_activation_effect, load_log_for_chain, load_previous_step, preflight_chain_writer_grant,
    record_by_root, reserve_chain_writer, DecisionAuthorityTuple, ProtectedStepArtifacts,
    ProtectedTransitionSource, LIFECYCLE_STATE_DIR,
};
use super::DaemonState;

type VErr = (String, String);

pub(crate) const CONTINUITY_RECEIPT_DIR: &str = "autonomous-system-continuity-transition-receipts";
pub(crate) const NETWORK_ENROLLMENT_DIR: &str = "autonomous-system-network-enrollments";
pub(crate) const CONTINUITY_INTENT_DIR: &str = "autonomous-system-continuity-transition-intents";
pub(crate) const MIGRATION_ACK_DIR: &str =
    "autonomous-system-migration-destination-acknowledgements";
pub(crate) const MIGRATION_ACK_INTENT_DIR: &str =
    "autonomous-system-migration-destination-acknowledgement-intents";
pub(crate) const MIGRATION_ACK_RESERVATION_DIR: &str =
    "autonomous-system-migration-destination-acknowledgement-reservations";
pub(crate) const MIGRATION_ACK_RECEIPT_DIR: &str =
    "autonomous-system-migration-destination-acknowledgement-receipts";
pub(crate) const DISSOLUTION_DISPOSITION_DIR: &str = "autonomous-system-dissolution-dispositions";
pub(crate) const DISSOLUTION_RECEIPT_DIR: &str = "autonomous-system-dissolution-receipts";

const LIFECYCLE_TRANSITION_CONTRACT: &str = "schema://ioi/foundations/lifecycle-transition/v1";
const CONTINUITY_STATE_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-continuity-state/v1";
const NETWORK_ENROLLMENT_TRANSITION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-network-enrollment-transition/v1";
const NETWORK_ENROLLMENT_CONTRACT: &str = "schema://ioi/foundations/ioi-network-enrollment/v1";
const RECEIPT_CONTRACT: &str = "schema://ioi/foundations/receipt-envelope/v1";
const OPERATION_LOG_CONTRACT: &str = "schema://ioi/foundations/autonomous-system-operation-log/v2";
const SYSTEM_CHAIN_CONTRACT: &str = "schema://ioi/foundations/autonomous-system-chain/v1";
const MIGRATION_ACK_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-migration-destination-acknowledgement/v1";
const DISSOLUTION_DISPOSITION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-dissolution-disposition/v1";
const DISSOLUTION_DISPOSITION_TRANSITION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-dissolution-disposition-transition/v1";
const DISSOLUTION_RECEIPT_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-dissolution-receipt/v1";
const DISSOLUTION_DISPOSITION_ARTIFACT_DOMAIN: &str =
    "ioi.autonomous-system-dissolution-disposition-artifact-jcs-sha256.v1";
const MIGRATION_ACK_OP: &str = "acknowledge_migration_destination";
const MIGRATION_ACK_SCOPE: &str =
    "scope:autonomous_system.continuity.migration_destination_acknowledge";
const SUCCESSOR_GOVERNANCE_SCOPES: &[&str] = &[
    "scope:autonomous_system.lifecycle.pause",
    "scope:autonomous_system.lifecycle.resume",
    "scope:autonomous_system.lifecycle.suspend",
    "scope:autonomous_system.lifecycle.reinstate",
    "scope:autonomous_system.lifecycle.enter_dormancy",
    "scope:autonomous_system.lifecycle.wake",
    "scope:autonomous_system.lifecycle.begin_recovery",
    "scope:autonomous_system.lifecycle.complete_recovery",
    "scope:autonomous_system.lifecycle.quarantine",
    "scope:autonomous_system.lifecycle.release_quarantine",
    "scope:autonomous_system.lifecycle.retire",
    "scope:autonomous_system.lifecycle.archive",
    "scope:autonomous_system.lifecycle.revoke",
    "scope:autonomous_system.lifecycle.decommission",
    "scope:autonomous_system.lifecycle.amend_constitution",
    "scope:autonomous_system.continuity.initiate_succession",
    "scope:autonomous_system.continuity.complete_succession",
    "scope:autonomous_system.continuity.migrate",
    MIGRATION_ACK_SCOPE,
    "scope:autonomous_system.continuity.initiate_dissolution",
    "scope:autonomous_system.continuity.open_dissolution_disposition",
    "scope:autonomous_system.continuity.record_dissolution_domain_outcome",
    "scope:autonomous_system.continuity.complete_dissolution",
    "scope:autonomous_system.network_enrollment.local.enroll",
    "scope:autonomous_system.network_enrollment.local.exit",
];

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

fn artifact_root(domain: &str, artifact: &Value) -> Result<String, VErr> {
    jcs_hash(&json!({"domain":domain,"artifact":artifact}))
}

/// Durable live-chain inputs plus the active M1 lifecycle policy body.
pub(crate) struct ContinuitySource {
    pub base: ProtectedTransitionSource,
    pub lifecycle_profile: Value,
    pub constitution_ref: String,
    pub current_enrollment: Option<Value>,
    pub current_dissolution_disposition: Option<Value>,
}

/// Load the live dissolution-disposition record the latest chain step binds.
/// A record exists exactly while the System is `dissolving`; the previous
/// step's transition envelope pins its content root, so a swapped or edited
/// durable record fails closed rather than loading.
fn load_current_dissolution_disposition(
    data_dir: &str,
    previous_state: &Value,
    previous_transition: &Value,
) -> Result<Option<Value>, VErr> {
    if previous_state.get("status").and_then(Value::as_str) != Some("dissolving") {
        return Ok(None);
    }
    let root = previous_transition
        .get("resulting_disposition_root")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_mismatch",
                "dissolving chain step lacks its exact disposition record root",
            )
        })?;
    let record_tail = tail("asddr_", root)?;
    let record = load_required_exact(data_dir, DISSOLUTION_DISPOSITION_DIR, &record_tail)?
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_mismatch",
                "dissolving chain lacks its exact local and Agentgres disposition record",
            )
        })?;
    if artifact_root(DISSOLUTION_DISPOSITION_ARTIFACT_DOMAIN, &record)? != root {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "current disposition record content root does not bind the committed step",
        ));
    }
    Ok(Some(record))
}

fn load_current_enrollment(
    data_dir: &str,
    chain: &Value,
    previous_state: &Value,
) -> Result<Option<Value>, VErr> {
    let Some(enrollment_ref) = chain.get("network_enrollment_ref").and_then(Value::as_str) else {
        if previous_state
            .get("network_enrollment_root")
            .is_some_and(|value| !value.is_null())
        {
            return Err(verr(
                "system_lifecycle_artifact_mismatch",
                "state retains an enrollment root while the chain is unenrolled",
            ));
        }
        return Ok(None);
    };
    let root = previous_state
        .get("network_enrollment_root")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_mismatch",
                "enrolled chain lacks its exact enrollment artifact root",
            )
        })?;
    let record_tail = tail("asne_", root)?;
    let enrollment = load_required_exact(data_dir, NETWORK_ENROLLMENT_DIR, &record_tail)?
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_mismatch",
                "enrolled chain lacks its exact local and Agentgres artifact",
            )
        })?;
    if enrollment
        .get("network_enrollment_id")
        .and_then(Value::as_str)
        != Some(enrollment_ref)
        || artifact_root(
            "ioi.autonomous-system-network-enrollment-artifact-jcs-sha256.v1",
            &enrollment,
        )? != root
    {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "current enrollment reference and content root do not bind one artifact",
        ));
    }
    Ok(Some(enrollment))
}

/// Load and cross-check the active lifecycle profile from the admitted genesis
/// bundle. Amendments preserve this profile body in the M1 selected profile.
pub(crate) fn load_continuity_source(data_dir: &str, key: &str) -> Result<ContinuitySource, VErr> {
    let admission = super::system_genesis_routes::load_verified_admission_by_key(data_dir, key)?
        .ok_or_else(|| verr("system_lifecycle_not_found", "no admitted genesis exists"))?;
    let (_system_id, exact) = super::system_amendment_routes::load_amendment_source(data_dir, key)?;
    let base = ProtectedTransitionSource {
        activation_effect: exact.activation_effect,
        previous_step: exact.previous_step,
        chain_head: exact.chain_head,
        operation_log: exact.operation_log,
    };
    let lifecycle_profile = admission
        .record
        .pointer("/initial_profile_bundle/lifecycle_profile")
        .cloned()
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_mismatch",
                "admitted genesis lacks its lifecycle profile body",
            )
        })?;
    if lifecycle_profile
        .get("lifecycle_profile_id")
        .and_then(Value::as_str)
        != base
            .chain_head
            .get("lifecycle_continuity_profile_ref")
            .and_then(Value::as_str)
    {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "active chain and admitted lifecycle profile disagree",
        ));
    }
    let candidate_root = jcs_hash(&json!({
        "domain":"ioi.autonomous-system-profile-candidate-jcs-sha256.v1",
        "kind":"lifecycle_continuity",
        "candidate":lifecycle_profile,
    }))?;
    if exact
        .predecessor_profile_set
        .pointer("/lifecycle_continuity/candidate_profile_root")
        .and_then(Value::as_str)
        != Some(candidate_root.as_str())
    {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "active profile set does not bind the admitted lifecycle policy body",
        ));
    }
    let constitution_ref = required(&base.chain_head, "/constitution_ref")?;
    let current_enrollment =
        load_current_enrollment(data_dir, &base.chain_head, &base.previous_step.state)?;
    let current_dissolution_disposition = load_current_dissolution_disposition(
        data_dir,
        &base.previous_step.state,
        &base.previous_step.transition,
    )?;
    Ok(ContinuitySource {
        base,
        lifecycle_profile,
        constitution_ref,
        current_enrollment,
        current_dissolution_disposition,
    })
}

pub(crate) fn compile_from_source(
    op: ContinuityTransitionOp,
    source: &ContinuitySource,
    declaration: &ContinuityTransitionDeclaration,
    trusted_successor_authority_binding: Option<&Value>,
    trusted_migration_destination_ack: Option<&Value>,
) -> Result<CompiledContinuityTransitionPlan, VErr> {
    compile_continuity_transition_plan(
        op,
        &source.base.activation_effect,
        &source.base.previous_step,
        &source.base.chain_head,
        &source.constitution_ref,
        &source.lifecycle_profile,
        source.current_enrollment.as_ref(),
        declaration,
        trusted_successor_authority_binding,
        trusted_migration_destination_ack,
        source.current_dissolution_disposition.as_ref(),
    )
    .map_err(|error| verr("system_continuity_plan_invalid", error))
}

fn load_migration_destination_ack(
    data_dir: &str,
    op: ContinuityTransitionOp,
    declaration: &ContinuityTransitionDeclaration,
) -> Result<Option<Value>, VErr> {
    if op != ContinuityTransitionOp::Migrate {
        return Ok(None);
    }
    let root = declaration
        .migration_destination_ack_root
        .as_deref()
        .ok_or_else(|| {
            verr(
                "system_continuity_migration_ack_required",
                "migration requires a durable destination acknowledgement root",
            )
        })?;
    let acknowledgement = load_required_exact(data_dir, MIGRATION_ACK_DIR, &tail("asmda_", root)?)?
        .ok_or_else(|| {
            verr(
                "system_continuity_migration_ack_not_found",
                "migration destination acknowledgement is absent from local and Agentgres truth",
            )
        })?;
    Ok(Some(acknowledgement))
}

async fn verified_successor_authority_binding(
    op: ContinuityTransitionOp,
    declaration: &ContinuityTransitionDeclaration,
) -> Result<Option<Value>, (StatusCode, Json<Value>)> {
    if op != ContinuityTransitionOp::CompleteSuccession {
        return Ok(None);
    }
    let principal = declaration
        .successor_authority_ref
        .as_deref()
        .ok_or_else(|| {
            classify(verr(
                "system_continuity_plan_invalid",
                "completed succession lacks its successor authority",
            ))
        })?;
    let probe_scope = SUCCESSOR_GOVERNANCE_SCOPES[0];
    let verified = governed::resolve_required_authority(AUTHORITY, principal, probe_scope, None)
        .await
        .map_err(|(status, code, reason)| {
            (
                status,
                Json(json!({"error":{"code":code,"message":format!("successor authority '{principal}' cannot be installed: {reason}"),"required_authority_ref":principal,"required_scope":probe_scope,"runtimeTruthSource":"daemon-runtime"}})),
            )
        })?;
    for required_scope in SUCCESSOR_GOVERNANCE_SCOPES {
        let decision = AuthorityScopeMatcher::evaluate(
            &verified.resolution.approval_authority,
            &ApprovalScopeContext::new((*required_scope).to_owned()),
        );
        if !decision.allowed {
            return Err(classify(verr(
                "system_continuity_successor_authority_incomplete",
                format!(
                    "successor authority '{principal}' lacks required governance scope '{required_scope}'"
                ),
            )));
        }
    }
    Ok(Some(verified.authority_binding))
}

fn require_distinct_successor_signer(
    current_binding: &Value,
    successor_binding: &Value,
) -> Result<(), VErr> {
    let current = current_binding
        .get("approval_authority")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            verr(
                "system_continuity_authority_binding_invalid",
                "current governing authority binding lacks its signer tuple",
            )
        })?;
    let successor = successor_binding
        .get("approval_authority")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            verr(
                "system_continuity_successor_authority_incomplete",
                "successor governing authority binding lacks its signer tuple",
            )
        })?;
    for field in ["authority_id", "public_key", "signature_suite"] {
        if !current.contains_key(field) || !successor.contains_key(field) {
            return Err(verr(
                "system_continuity_authority_binding_invalid",
                format!("governing authority signer tuple lacks '{field}'"),
            ));
        }
    }
    if current.get("authority_id") == successor.get("authority_id")
        || (current.get("public_key") == successor.get("public_key")
            && current.get("signature_suite") == successor.get("signature_suite"))
    {
        return Err(verr(
            "system_continuity_successor_authority_not_reissued",
            "successor principal aliases the current governing signer",
        ));
    }
    Ok(())
}

fn decision_receipt(
    plan: &CompiledContinuityTransitionPlan,
    proposal_ref: &str,
    proposal_root: &str,
    authority: &DecisionAuthorityTuple,
    timestamp: &str,
) -> Result<(Value, String, String), VErr> {
    let system_id = required(&plan.authority_effect, "/system_id")?;
    let decision_ref = format!(
        "decision://{}/continuity/sequence/{}",
        ns(&system_id)?,
        plan.sequence
    );
    let receipt = json!({
        "receipt_id": format!("receipt://{}/continuity-decision/sequence/{}",ns(&system_id)?,plan.sequence),
        "receipt_type":"continuity_authority_decision",
        "receipt_profile_ref":RECEIPT_CONTRACT,
        "attested_boundary_fact_refs":[proposal_ref,authority.authority_evidence_ref],
        "claim_scope_ref":"policy://autonomous-system/continuity",
        "run_id":Value::Null,"task_id":Value::Null,"actor_id":"runtime://hypervisor-runtime",
        "authority_grant_id":authority.authority_grant_ref,
        "primitive_capabilities":[],"authority_scopes":[plan.op.required_scope()],
        "artifact_refs":[format!("artifact://continuity-proposal/{proposal_root}")],
        "evidence_bundle_refs":[],"verification_ref":Value::Null,"acceptance_ref":Value::Null,
        "adjudication_ref":Value::Null,"settlement_ref":Value::Null,"timestamp":timestamp,
        "signature":Value::Null,"public_commitment_ref":Value::Null,
        "input_hash":authority.input_hash,"output_hash":plan.resulting_state_root,"policy_hash":authority.policy_hash,
    });
    validate_contract(
        RECEIPT_CONTRACT,
        &receipt,
        "continuity authority decision receipt",
    )?;
    let mut decision = json!({
        "schema_version":"ioi.autonomous-system-continuity-decision.v1",
        "decision_ref":decision_ref,
        "decision_root":Value::Null,
        "system_id":system_id,
        "op":plan.op.as_str(),
        "sequence":plan.sequence,
        "operation_commitment":plan.authority_effect["operation_commitment"],
        "authority_effect":plan.authority_effect,
        "decision_receipt":receipt,
    });
    let root = jcs_hash(&json!({
        "domain":"ioi.autonomous-system-continuity-decision-jcs-sha256.v1",
        "decision_ref":decision["decision_ref"],
        "system_id":decision["system_id"],
        "op":decision["op"],
        "sequence":decision["sequence"],
        "operation_commitment":decision["operation_commitment"],
        "authority_effect":decision["authority_effect"],
        "decision_receipt":decision["decision_receipt"],
    }))?;
    decision["decision_root"] = json!(root);
    Ok((decision, decision_ref, root))
}

fn proposal(
    plan: &CompiledContinuityTransitionPlan,
    source: &ContinuitySource,
    timestamp: &str,
) -> Result<(Value, String, String), VErr> {
    let system_id = required(&plan.authority_effect, "/system_id")?;
    let proposal_ref = format!(
        "proposal://{}/continuity/sequence/{}",
        ns(&system_id)?,
        plan.sequence
    );
    let body = if let Some(enrollment) = plan.network_enrollment.clone() {
        enrollment
    } else if matches!(
        plan.op,
        ContinuityTransitionOp::OpenDissolutionDisposition
            | ContinuityTransitionOp::RecordDissolutionDomainOutcome
    ) {
        plan.dissolution_disposition.clone().ok_or_else(|| {
            verr(
                "system_continuity_plan_invalid",
                "disposition step compiled without its record",
            )
        })?
    } else {
        json!({
            "schema_version":"ioi.lifecycle-transition.v1",
            "lifecycle_transition_id":format!("lifecycle-transition://{}/continuity/sequence/{}/proposal",ns(&system_id)?,plan.sequence),
            "system_id":system_id,"resulting_or_related_system_id":if plan.op==ContinuityTransitionOp::Migrate {json!(system_id)} else {Value::Null},
            "lifecycle_profile_ref":source.lifecycle_profile["lifecycle_profile_id"],
            "transition_kind":plan.op.transition_kind(),"genesis_ref":Value::Null,"manifest_ref":Value::Null,
            "admitted_manifest_root":Value::Null,"previous_state":plan.predecessor_status,"proposed_state":plan.resulting_status,
            "trigger_evidence_refs":plan.authority_effect["trigger_evidence_refs"],
            "oracle_evidence_profile_refs":source.base.chain_head["oracle_evidence_profile_refs"],
            "proposal_ref":proposal_ref,"decision_ref":Value::Null,"authority_grant_refs":[],
            "challenge_opened_at":Value::Null,"challenge_closes_at":Value::Null,
            "predecessor_state_root":plan.previous_step.state_root,"resulting_state_root":Value::Null,
            "operation_commitment":Value::Null,"state_transition_commitment_ref":Value::Null,
            "lineage_ref":Value::Null,
            "identity_continuity_decision_ref":Value::Null,"disposition_receipt_refs":[],"receipt_refs":[],
            "public_commitment_ref":Value::Null,"status":"proposed"
        })
    };
    let contract = if plan.network_enrollment.is_some() {
        NETWORK_ENROLLMENT_CONTRACT
    } else if matches!(
        plan.op,
        ContinuityTransitionOp::OpenDissolutionDisposition
            | ContinuityTransitionOp::RecordDissolutionDomainOutcome
    ) {
        DISSOLUTION_DISPOSITION_CONTRACT
    } else {
        LIFECYCLE_TRANSITION_CONTRACT
    };
    validate_contract(contract, &body, "continuity proposal body")?;
    let mut value = json!({
        "schema_version":"ioi.autonomous-system-continuity-proposal.v1",
        "proposal_ref":proposal_ref,
        "proposal_root":Value::Null,
        "system_id":system_id,
        "op":plan.op.as_str(),
        "sequence":plan.sequence,
        "operation_commitment":plan.authority_effect["operation_commitment"],
        "authority_effect":plan.authority_effect,
        "proposal_body":body,
        "created_at":timestamp,
    });
    let root = jcs_hash(&json!({
        "domain":"ioi.autonomous-system-continuity-proposal-jcs-sha256.v1",
        "proposal_ref":value["proposal_ref"],
        "system_id":value["system_id"],
        "op":value["op"],
        "sequence":value["sequence"],
        "operation_commitment":value["operation_commitment"],
        "authority_effect":value["authority_effect"],
        "proposal_body":value["proposal_body"],
        "created_at":value["created_at"],
    }))?;
    value["proposal_root"] = json!(root);
    Ok((value, proposal_ref, root))
}

/// Build the committed graph without performing I/O.
pub(crate) fn build_continuity_artifacts(
    plan: &CompiledContinuityTransitionPlan,
    source: &ContinuitySource,
    authority: &DecisionAuthorityTuple,
    timestamp: &str,
) -> Result<ProtectedStepArtifacts, VErr> {
    let system_id = required(&plan.authority_effect, "/system_id")?;
    let (proposal, proposal_ref, proposal_root) = proposal(plan, source, timestamp)?;
    let (decision, decision_ref, decision_root) =
        decision_receipt(plan, &proposal_ref, &proposal_root, authority, timestamp)?;
    let transition_ref = format!(
        "lifecycle-transition://{}/continuity/sequence/{}",
        ns(&system_id)?,
        plan.sequence
    );
    let receipt_ref = format!(
        "receipt://{}/continuity/sequence/{}",
        ns(&system_id)?,
        plan.sequence
    );
    let mut authority_effect_material = plan.authority_effect.clone();
    authority_effect_material["operation_commitment"] = Value::Null;
    let transition = if matches!(
        plan.op,
        ContinuityTransitionOp::OpenDissolutionDisposition
            | ContinuityTransitionOp::RecordDissolutionDomainOutcome
    ) {
        json!({
            "schema_version":"ioi.autonomous-system-dissolution-disposition-transition.v1",
            "lifecycle_transition_id":transition_ref,"system_id":system_id,"op":plan.op.as_str(),"sequence":plan.sequence,
            "proposal_ref":proposal_ref,"proposal_root":proposal_root,"decision_ref":decision_ref,"decision_root":decision_root,
            "predecessor_state_root":plan.previous_step.state_root,"resulting_state_root":plan.resulting_state_root,
            "dissolution_disposition_ref":plan.authority_effect["dissolution_disposition_ref"],
            "predecessor_disposition_root":plan.authority_effect["predecessor_disposition_root"],
            "resulting_disposition_root":plan.authority_effect["resulting_disposition_root"],
            "recorded_domain":plan.authority_effect["recorded_dissolution_domain"],
            "operation_commitment":plan.authority_effect["operation_commitment"],
            "authority_effect_material":authority_effect_material,
            "authority_grant_refs":[authority.authority_grant_ref],"receipt_refs":[receipt_ref],"status":"committed"
        })
    } else if plan.network_enrollment.is_some() {
        json!({
            "schema_version":"ioi.autonomous-system-network-enrollment-transition.v1",
            "lifecycle_transition_id":transition_ref,"system_id":system_id,"op":plan.op.as_str(),"sequence":plan.sequence,
            "proposal_ref":proposal_ref,"proposal_root":proposal_root,"decision_ref":decision_ref,"decision_root":decision_root,
            "predecessor_state_root":plan.previous_step.state_root,"resulting_state_root":plan.resulting_state_root,
            "predecessor_enrollment_ref":plan.authority_effect["current_network_enrollment_ref"],
            "predecessor_enrollment_root":plan.authority_effect["current_network_enrollment_root"],
            "resulting_enrollment_ref":plan.authority_effect["resulting_network_enrollment_ref"],
            "resulting_enrollment_root":plan.authority_effect["resulting_network_enrollment_root"],
            "operation_commitment":plan.authority_effect["operation_commitment"],
            "authority_effect_material":authority_effect_material,
            "authority_grant_refs":[authority.authority_grant_ref],"receipt_refs":[receipt_ref],"status":"committed"
        })
    } else {
        json!({
            "schema_version":"ioi.lifecycle-transition.v1","lifecycle_transition_id":transition_ref,
            "system_id":system_id,"resulting_or_related_system_id":if plan.op==ContinuityTransitionOp::Migrate {json!(system_id)} else {Value::Null},
            "lifecycle_profile_ref":source.lifecycle_profile["lifecycle_profile_id"],"transition_kind":plan.op.transition_kind(),
            "genesis_ref":Value::Null,"manifest_ref":Value::Null,"admitted_manifest_root":Value::Null,
            "previous_state":plan.predecessor_status,"proposed_state":plan.resulting_status,
            "trigger_evidence_refs":plan.authority_effect["trigger_evidence_refs"],
            "oracle_evidence_profile_refs":source.base.chain_head["oracle_evidence_profile_refs"],
            "proposal_ref":proposal_ref,"decision_ref":decision_ref,"authority_grant_refs":[authority.authority_grant_ref],
            "challenge_opened_at":Value::Null,"challenge_closes_at":Value::Null,
            "predecessor_state_root":plan.previous_step.state_root,"resulting_state_root":plan.resulting_state_root,
            "operation_commitment":plan.authority_effect["operation_commitment"],"state_transition_commitment_ref":Value::Null,
            "lineage_ref":Value::Null,
            "identity_continuity_decision_ref":if plan.op==ContinuityTransitionOp::CompleteSuccession {Some(decision_ref.clone())} else {None},
            "disposition_receipt_refs":if plan.op==ContinuityTransitionOp::CompleteDissolution {plan.authority_effect["disposition_receipt_refs"].clone()} else {json!([])},
            "receipt_refs":[receipt_ref],"public_commitment_ref":Value::Null,"status":"committed"
        })
    };
    validate_contract(
        if matches!(
            plan.op,
            ContinuityTransitionOp::OpenDissolutionDisposition
                | ContinuityTransitionOp::RecordDissolutionDomainOutcome
        ) {
            DISSOLUTION_DISPOSITION_TRANSITION_CONTRACT
        } else if plan.network_enrollment.is_some() {
            NETWORK_ENROLLMENT_TRANSITION_CONTRACT
        } else {
            LIFECYCLE_TRANSITION_CONTRACT
        },
        &transition,
        "continuity transition",
    )?;
    let transition_root = artifact_root(
        "ioi.autonomous-system-continuity-transition-jcs-sha256.v1",
        &transition,
    )?;
    let mut state = plan.semantic_state.clone();
    state["transition_ref"] = json!(transition_ref);
    state["transition_root"] = json!(transition_root);
    state["transition_receipt_ref"] = json!(receipt_ref);
    state["created_at"] = json!(timestamp);
    let receipt = json!({
        "receipt_id":receipt_ref,"receipt_type":"continuity_transition","receipt_profile_ref":RECEIPT_CONTRACT,
        "attested_boundary_fact_refs":[system_id,proposal_ref,decision_ref,transition_ref,authority.authority_evidence_ref],
        "claim_scope_ref":"policy://autonomous-system/continuity","run_id":Value::Null,"task_id":Value::Null,"actor_id":"runtime://hypervisor-runtime",
        "authority_grant_id":authority.authority_grant_ref,"primitive_capabilities":[],"authority_scopes":[plan.op.required_scope()],
        "artifact_refs":[format!("artifact://continuity-transition/{transition_root}"),format!("artifact://continuity-state/{}",plan.resulting_state_root)],
        "evidence_bundle_refs":[],
        "verification_ref":Value::Null,"acceptance_ref":Value::Null,"adjudication_ref":Value::Null,
        "settlement_ref":Value::Null,"timestamp":timestamp,"signature":Value::Null,"public_commitment_ref":Value::Null,
        "input_hash":authority.input_hash,"output_hash":plan.resulting_state_root,"policy_hash":authority.policy_hash,
    });
    validate_contract(RECEIPT_CONTRACT, &receipt, "continuity receipt")?;
    let receipt_root = artifact_root(
        "ioi.autonomous-system-continuity-receipt-jcs-sha256.v1",
        &receipt,
    )?;
    state["transition_receipt_root"] = json!(receipt_root);
    validate_contract(CONTINUITY_STATE_CONTRACT, &state, "continuity state")?;
    let step = UnverifiedCommittedSystemLifecycleStep {
        proposal,
        decision,
        state,
        transition,
        receipt,
        state_root: plan.resulting_state_root.clone(),
        proposal_root: proposal_root.clone(),
        decision_root: decision_root.clone(),
        transition_root: transition_root.clone(),
        receipt_root: receipt_root.clone(),
    };
    let owner_contract = if matches!(
        plan.op,
        ContinuityTransitionOp::OpenDissolutionDisposition
            | ContinuityTransitionOp::RecordDissolutionDomainOutcome
    ) {
        DISSOLUTION_DISPOSITION_CONTRACT
    } else if plan.network_enrollment.is_some() {
        NETWORK_ENROLLMENT_CONTRACT
    } else {
        LIFECYCLE_TRANSITION_CONTRACT
    };
    let entry = json!({
        "sequence":plan.sequence,"entry_kind":"protected_transition","operation_name":plan.op.as_str(),
        "operation_owner_profile_ref":owner_contract,"operation_owner_ref":proposal_ref,"operation_owner_root":proposal_root,
        "required_scope":plan.op.required_scope(),"materialization_ref":Value::Null,"materialization_root":Value::Null,
        "deployment_profile_ref":source.base.chain_head["deployment_profile_ref"],"deployment_profile_root":source.base.chain_head["deployment_profile_root"],
        "operation_commitment":plan.authority_effect["operation_commitment"],"proposal_ref":proposal_ref,"proposal_root":proposal_root,
        "decision_ref":decision_ref,"decision_root":decision_root,"transition_ref":transition_ref,"transition_root":transition_root,
        "state_transition_commitment_ref":Value::Null,"state_ref":step.state["lifecycle_state_ref"],"state_root":plan.resulting_state_root,
        "predecessor_state_root":plan.previous_step.state_root,"receipt_profile_ref":RECEIPT_CONTRACT,
        "receipt_ref":receipt_ref,"receipt_root":receipt_root,"receipt_artifact_root":receipt_root,
        "component_registry_ref":Value::Null,"component_registry_root":Value::Null,
        "active_profile_set_ref":plan.authority_effect["active_profile_set_ref"],"active_profile_set_root":plan.authority_effect["active_profile_set_root"],
        "chain_ref":plan.authority_effect["chain_ref"],"authority_evidence_ref":authority.authority_evidence_ref,
        "authority_evidence_root":authority.authority_evidence_root,"wallet_consumption_ref":authority.wallet_grant_consumption_ref,
        "wallet_consumption_root":authority.wallet_grant_consumption_root,"live_chain_created":false,"committed_at":timestamp
    });
    let operation_log = continue_log_with_entry(
        &source.base.operation_log,
        &entry,
        plan.sequence,
        &plan.previous_step.state_root,
        &system_id,
        timestamp,
    )?;
    validate_contract(
        OPERATION_LOG_CONTRACT,
        &operation_log,
        "continuity operation log",
    )?;
    let mut chain = source.base.chain_head.clone();
    chain["latest_sequence"] = json!(plan.sequence);
    chain["latest_operation_commitment"] = plan.authority_effect["operation_commitment"].clone();
    chain["latest_transition_id"] = json!(transition_ref);
    chain["latest_transition_root"] = json!(transition_root);
    chain["latest_receipt_ref"] = json!(receipt_ref);
    chain["latest_receipt_root"] = json!(receipt_root);
    chain["latest_state_ref"] = step.state["lifecycle_state_ref"].clone();
    chain["latest_state_root"] = json!(plan.resulting_state_root);
    chain["operation_log_ref"] = operation_log["operation_log_ref"].clone();
    chain["operation_log_root"] = operation_log["operation_log_root"].clone();
    chain["network_enrollment_ref"] =
        plan.authority_effect["resulting_network_enrollment_ref"].clone();
    if plan.op == ContinuityTransitionOp::CompleteSuccession {
        chain["governance_owner_refs"] =
            json!([plan.authority_effect["resulting_governing_authority_ref"]]);
    }
    chain["status"] = json!(plan.resulting_status);
    chain["created_at"] = json!(timestamp);
    let mut material = chain.as_object().cloned().expect("chain object");
    material.remove("schema_version");
    material.remove("chain_root");
    material.remove("created_at");
    material.insert(
        "domain".into(),
        json!("ioi.autonomous-system-chain-jcs-sha256.v1"),
    );
    chain["chain_root"] = json!(jcs_hash(&Value::Object(material))?);
    validate_contract(SYSTEM_CHAIN_CONTRACT, &chain, "continuity chain")?;
    Ok(ProtectedStepArtifacts {
        step,
        operation_log,
        chain,
    })
}

fn declaration_from_body(body: &Value) -> Result<ContinuityTransitionDeclaration, VErr> {
    let mut value = serde_json::Map::new();
    for key in [
        "trigger_evidence_refs",
        "successor_candidate_ref",
        "successor_authority_ref",
        "migration_destination_ack_ref",
        "migration_destination_ack_root",
        "residual_disposition_receipt_refs",
        "live_effect_refs",
        "network_enrollment",
        "dissolution_disposition",
        "dissolution_domain_outcome",
    ] {
        if let Some(field) = body.get(key) {
            value.insert(key.to_owned(), field.clone());
        }
    }
    serde_json::from_value(Value::Object(value))
        .map_err(|error| verr("system_continuity_request_invalid", error.to_string()))
}

fn validate_request(body: &Value) -> Result<(), VErr> {
    let encoded = serde_json::to_vec(body)
        .map_err(|error| verr("system_continuity_request_invalid", error.to_string()))?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(verr(
            "system_continuity_request_oversize",
            "request exceeds 512 KiB",
        ));
    }
    if contains_sensitive_key(body) {
        return Err(verr(
            "system_continuity_sensitive_field_rejected",
            "secret-bearing keys are forbidden recursively",
        ));
    }
    let object = body.as_object().ok_or_else(|| {
        verr(
            "system_continuity_request_invalid",
            "request must be an object",
        )
    })?;
    const ALLOWED: &[&str] = &[
        "expected_chain_head_root",
        "expected_predecessor_state_root",
        "wallet_approval_grant",
        "trigger_evidence_refs",
        "successor_candidate_ref",
        "successor_authority_ref",
        "migration_destination_ack_ref",
        "migration_destination_ack_root",
        "residual_disposition_receipt_refs",
        "live_effect_refs",
        "network_enrollment",
        "dissolution_disposition",
        "dissolution_domain_outcome",
    ];
    if let Some(key) = object.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(verr(
            "system_continuity_request_field_unknown",
            format!("undeclared request field '{key}' is forbidden"),
        ));
    }
    Ok(())
}

fn check_expected(body: &Value, source: &ContinuitySource) -> Result<(), VErr> {
    if body.get("expected_chain_head_root") != source.base.chain_head.get("chain_root")
        || body.get("expected_predecessor_state_root")
            != Some(&json!(source.base.previous_step.state_root))
    {
        return Err(verr(
            "system_lifecycle_head_conflict",
            "continuity request is stale against the live chain head",
        ));
    }
    Ok(())
}

fn ensure_no_pending(data_dir: &str, key: &str) -> Result<(), VErr> {
    for (_tail, intent) in scan_continuity_intents(data_dir)? {
        let intent = intent?;
        if intent.get("source_record_tail").and_then(Value::as_str) == Some(key) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                "a continuity transition is pending convergence",
            ));
        }
    }
    Ok(())
}

/// Mint the named dissolution receipt, exactly once, at completion. Every
/// bound fact is resolved from the compiled plan and committed artifacts,
/// never from the caller (INV-37).
fn build_dissolution_receipt(
    plan: &CompiledContinuityTransitionPlan,
    artifacts: &ProtectedStepArtifacts,
) -> Result<(Value, String), VErr> {
    let record = plan.dissolution_disposition.as_ref().ok_or_else(|| {
        verr(
            "system_continuity_plan_invalid",
            "completion compiled without its finalized disposition record",
        )
    })?;
    let system_id = required(&plan.authority_effect, "/system_id")?;
    let mut domain_commitments = serde_json::Map::new();
    for domain in ioi_types::app::system_continuity_transitions::DISSOLUTION_OUTCOME_DOMAINS {
        let outcome = record
            .pointer(&format!("/outcome_domains/{domain}"))
            .cloned()
            .ok_or_else(|| {
                verr(
                    "system_continuity_plan_invalid",
                    format!("finalized record lacks the {domain} domain"),
                )
            })?;
        let state = required(&outcome, "/state")?;
        let commitment = jcs_hash(&json!({
            "domain":"ioi.autonomous-system-dissolution-domain-outcome-jcs-sha256.v1",
            "system_id":system_id,
            "dissolution_domain":domain,
            "outcome":outcome,
        }))?;
        domain_commitments.insert(
            domain.to_owned(),
            json!({"state":state,"outcome_commitment":commitment}),
        );
    }
    let tombstone_commitment = jcs_hash(&json!({
        "domain":"ioi.autonomous-system-dissolution-tombstone-jcs-sha256.v1",
        "system_id":system_id,
        "tombstone_outcome":record.pointer("/outcome_domains/tombstone"),
        "resulting_state_root":plan.resulting_state_root,
    }))?;
    let receipt = json!({
        "schema_version":"ioi.autonomous-system-dissolution-receipt.v1",
        "dissolution_receipt_id":format!("dissolution-receipt://{}/sequence/{}",ns(&system_id)?,plan.sequence),
        "system_id":system_id,
        "op":"complete_dissolution",
        "sequence":plan.sequence,
        "required_scope":"scope:autonomous_system.continuity.complete_dissolution",
        "assurance_posture":"dissolution_committed",
        "lifecycle_profile_ref":record["lifecycle_profile_ref"],
        "lifecycle_profile_root":record["lifecycle_profile_root"],
        "dissolution_disposition_ref":plan.authority_effect["dissolution_disposition_ref"],
        "dissolution_disposition_root":plan.authority_effect["resulting_disposition_root"],
        "domain_outcome_commitments":Value::Object(domain_commitments),
        "initiate_transition_ref":record["initiate_transition_ref"],
        "initiate_transition_root":record["initiate_transition_root"],
        "complete_transition_ref":record["complete_transition_ref"],
        "complete_transition_root":artifacts.step.transition_root,
        "predecessor_state_root":plan.previous_step.state_root,
        "resulting_state_root":plan.resulting_state_root,
        "tombstone_commitment":tombstone_commitment,
        "predecessor_chain_root":plan.authority_effect["predecessor_chain_head_root"],
        "transition_receipt_ref":artifacts.step.receipt["receipt_id"],
        "created_at":artifacts.step.state["created_at"],
    });
    validate_contract(
        DISSOLUTION_RECEIPT_CONTRACT,
        &receipt,
        "dissolution receipt",
    )?;
    let receipt_root = artifact_root(
        "ioi.autonomous-system-dissolution-receipt-artifact-jcs-sha256.v1",
        &receipt,
    )?;
    Ok((receipt, tail("asdr_", &receipt_root)?))
}

fn persist_graph(
    data_dir: &str,
    plan: &CompiledContinuityTransitionPlan,
    artifacts: &ProtectedStepArtifacts,
    evidence: &super::system_activation_routes::NodeAdmissionEvidence,
    wallet_consumption: &Value,
    enrollment: Option<&Value>,
) -> Result<(), VErr> {
    let consumption: ApprovalGrantConsumptionReceipt =
        serde_json::from_value(wallet_consumption.clone()).map_err(|error| {
            verr(
                "system_lifecycle_wallet_consumption_invalid",
                error.to_string(),
            )
        })?;
    let system_id = required(&artifacts.chain, "/system_id")?;
    let predecessor_chain_root = required(&plan.authority_effect, "/predecessor_chain_head_root")?;
    let successor_chain_root = required(&artifacts.chain, "/chain_root")?;
    let operation_ref = required(&artifacts.operation_log, "/head_entry/operation_owner_ref")?;
    let operation = required(&artifacts.operation_log, "/head_entry/operation_name")?;
    let committed_at = required(&artifacts.operation_log, "/head_entry/committed_at")?;
    claim_chain_successor(
        data_dir,
        &system_id,
        artifacts.chain["latest_sequence"]
            .as_u64()
            .ok_or_else(|| verr("system_lifecycle_artifact_invalid", "chain lacks sequence"))?,
        &predecessor_chain_root,
        &successor_chain_root,
        &operation_ref,
        &artifacts.step.proposal_root,
        &operation,
        &committed_at,
    )?;
    let mut records: Vec<(&str, String, &Value)> = vec![
        (
            AUTHORITY_CONSUMPTION_DIR,
            format!("aslac_{}", hex::encode(consumption.consumption_id)),
            wallet_consumption,
        ),
        (
            AUTHORITY_EVIDENCE_DIR,
            tail("aslae_", &evidence.authority_evidence_root)?,
            &evidence.authority_evidence,
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
            CONTINUITY_RECEIPT_DIR,
            tail("asctr_", &artifacts.step.receipt_root)?,
            &artifacts.step.receipt,
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
    if let Some(enrollment) = enrollment {
        let enrollment_root = artifact_root(
            "ioi.autonomous-system-network-enrollment-artifact-jcs-sha256.v1",
            enrollment,
        )?;
        records.insert(
            7,
            (
                NETWORK_ENROLLMENT_DIR,
                tail("asne_", &enrollment_root)?,
                enrollment,
            ),
        );
    }
    if let Some(record) = plan.dissolution_disposition.as_ref() {
        let record_root = artifact_root(DISSOLUTION_DISPOSITION_ARTIFACT_DOMAIN, record)?;
        records.push((
            DISSOLUTION_DISPOSITION_DIR,
            tail("asddr_", &record_root)?,
            record,
        ));
    }
    let dissolution_receipt = if plan.op == ContinuityTransitionOp::CompleteDissolution {
        Some(build_dissolution_receipt(plan, artifacts)?)
    } else {
        None
    };
    if let Some((receipt, receipt_tail)) = dissolution_receipt.as_ref() {
        records.push((DISSOLUTION_RECEIPT_DIR, receipt_tail.clone(), receipt));
    }
    for (family, record_tail, value) in records {
        persist_local(data_dir, family, &record_tail, value)?;
        super::substrate_store::admit_required(data_dir, family, &record_tail, value).map_err(
            |error| {
                verr(
                    "system_lifecycle_agentgres_admission_failed",
                    format!("required admission for '{family}/{record_tail}' failed ({error})"),
                )
            },
        )?;
        let loaded = load_required_exact(data_dir, family, &record_tail)?.ok_or_else(|| {
            verr(
                "system_lifecycle_persist_failed",
                "continuity artifact did not converge",
            )
        })?;
        if loaded != *value {
            return Err(verr(
                "system_lifecycle_persist_failed",
                "continuity artifact diverged",
            ));
        }
    }
    Ok(())
}

fn validate_migration_ack_request(body: &Value) -> Result<(), VErr> {
    let encoded = serde_json::to_vec(body).map_err(|error| {
        verr(
            "system_continuity_migration_ack_request_invalid",
            error.to_string(),
        )
    })?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(verr(
            "system_continuity_migration_ack_request_oversize",
            "request exceeds 512 KiB",
        ));
    }
    if contains_sensitive_key(body) {
        return Err(verr(
            "system_continuity_sensitive_field_rejected",
            "secret-bearing keys are forbidden recursively",
        ));
    }
    let object = body.as_object().ok_or_else(|| {
        verr(
            "system_continuity_migration_ack_request_invalid",
            "request must be one object",
        )
    })?;
    const ALLOWED: &[&str] = &[
        "expected_chain_head_root",
        "expected_predecessor_state_root",
        "destination_ref",
        "acknowledged_state_root",
        "wallet_approval_grant",
    ];
    if let Some(key) = object.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(verr(
            "system_continuity_migration_ack_request_field_unknown",
            format!("undeclared request field '{key}' is forbidden"),
        ));
    }
    for field in [
        "expected_chain_head_root",
        "expected_predecessor_state_root",
        "acknowledged_state_root",
    ] {
        let value = object.get(field).and_then(Value::as_str).unwrap_or("");
        if tail("hash_", value).is_err() {
            return Err(verr(
                "system_continuity_migration_ack_request_invalid",
                format!("{field} must be one canonical sha256 root"),
            ));
        }
    }
    let destination = object
        .get("destination_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !destination.starts_with("deployment-profile://")
        || destination.len() > 256
        || destination.chars().any(char::is_whitespace)
    {
        return Err(verr(
            "system_continuity_migration_ack_destination_invalid",
            "destination_ref must be one canonical deployment-profile ref",
        ));
    }
    Ok(())
}

fn build_migration_ack_plan(source: &ContinuitySource, body: &Value) -> Result<Value, VErr> {
    check_expected(body, source)?;
    let status = required(&source.base.chain_head, "/status")?;
    if !matches!(status.as_str(), "active" | "successor_governed") {
        return Err(verr(
            "system_continuity_migration_ack_status_invalid",
            "migration destination acknowledgement requires an active or successor-governed System",
        ));
    }
    let system_id = required(&source.base.chain_head, "/system_id")?;
    let genesis_ref = required(&source.base.chain_head, "/genesis_ref")?;
    let predecessor_state_ref = source
        .base
        .previous_step
        .state
        .get("lifecycle_state_ref")
        .or_else(|| source.base.previous_step.state.get("activation_state_ref"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "system_continuity_migration_ack_source_invalid",
                "live predecessor lacks a canonical state ref",
            )
        })?;
    let predecessor_state_root = source.base.previous_step.state_root.as_str();
    if body.get("acknowledged_state_root").and_then(Value::as_str) != Some(predecessor_state_root) {
        return Err(verr(
            "system_continuity_migration_ack_state_mismatch",
            "destination acknowledgement must bind the byte-exact live predecessor state",
        ));
    }
    let predecessor_chain_head_root = required(&source.base.chain_head, "/chain_root")?;
    let source_deployment_profile_ref =
        required(&source.base.chain_head, "/deployment_profile_ref")?;
    let destination_ref = required(body, "/destination_ref")?;
    if destination_ref == source_deployment_profile_ref {
        return Err(verr(
            "system_continuity_migration_ack_destination_unchanged",
            "migration destination must differ from the current deployment profile",
        ));
    }
    let governing =
        current_governing_authority(&source.base.previous_step, &source.base.chain_head)?;
    let sequence = source
        .base
        .chain_head
        .get("latest_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            verr(
                "system_continuity_migration_ack_source_invalid",
                "live chain lacks its latest sequence",
            )
        })?;
    let mut effect = json!({
        "schema_version":"ioi.autonomous-system-migration-destination-acknowledgement-effect.v1",
        "op":MIGRATION_ACK_OP,
        "required_scope":MIGRATION_ACK_SCOPE,
        "sequence":sequence,
        "system_id":system_id,
        "genesis_ref":genesis_ref,
        "source_governing_authority_ref":governing,
        "predecessor_state_ref":predecessor_state_ref,
        "predecessor_state_root":predecessor_state_root,
        "predecessor_chain_head_root":predecessor_chain_head_root,
        "source_deployment_profile_ref":source_deployment_profile_ref,
        "destination_ref":destination_ref,
        "acknowledged_state_root":predecessor_state_root,
        "identity_preserved":true,
        "operation_commitment":Value::Null,
    });
    let operation_commitment = jcs_hash(&json!({
        "domain":"ioi.autonomous-system-migration-destination-acknowledgement-operation-jcs-sha256.v1",
        "effect":effect,
    }))?;
    effect["operation_commitment"] = json!(operation_commitment);
    let acknowledgement_ref = format!(
        "migration-destination-acknowledgement://{}/sequence/{}/asmda_{}",
        ns(&system_id)?,
        sequence,
        &operation_commitment["sha256:".len()..]
    );
    let acknowledgement_root = jcs_hash(&json!({
        "domain":"ioi.autonomous-system-migration-destination-acknowledgement-jcs-sha256.v1",
        "acknowledgement_ref":acknowledgement_ref,
        "system_id":system_id,
        "predecessor_state_ref":predecessor_state_ref,
        "predecessor_state_root":predecessor_state_root,
        "predecessor_chain_head_root":predecessor_chain_head_root,
        "source_deployment_profile_ref":source_deployment_profile_ref,
        "destination_ref":destination_ref,
        "acknowledged_state_root":predecessor_state_root,
        "required_scope":MIGRATION_ACK_SCOPE,
        "operation_commitment":operation_commitment,
    }))?;
    Ok(json!({
        "acknowledgement_ref":acknowledgement_ref,
        "acknowledgement_root":acknowledgement_root,
        "authority_effect_material":effect,
    }))
}

fn build_migration_ack_artifacts(
    plan: &Value,
    evidence: &super::system_activation_routes::NodeAdmissionEvidence,
    timestamp: &str,
) -> Result<(Value, Value, String), VErr> {
    let effect = &plan["authority_effect_material"];
    let acknowledgement_ref = required(plan, "/acknowledgement_ref")?;
    let acknowledgement_root = required(plan, "/acknowledgement_root")?;
    let system_id = required(effect, "/system_id")?;
    let sequence = effect
        .get("sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            verr(
                "system_continuity_migration_ack_invalid",
                "acknowledgement effect lacks sequence",
            )
        })?;
    let receipt_ref = format!(
        "receipt://{}/migration-destination-acknowledgement/sequence/{}/{}",
        ns(&system_id)?,
        sequence,
        &acknowledgement_root["sha256:".len()..]
    );
    let authority_grant_ref = required(&evidence.authority_evidence, "/authority_grant_ref")?;
    let receipt = json!({
        "receipt_id":receipt_ref,
        "receipt_type":"migration_destination_acknowledgement",
        "receipt_profile_ref":RECEIPT_CONTRACT,
        "attested_boundary_fact_refs":[acknowledgement_ref,evidence.authority_evidence_ref],
        "claim_scope_ref":"policy://autonomous-system/continuity/migration-destination-acknowledgement",
        "run_id":Value::Null,"task_id":Value::Null,"actor_id":"runtime://hypervisor-runtime",
        "authority_grant_id":authority_grant_ref,
        "primitive_capabilities":[],"authority_scopes":[MIGRATION_ACK_SCOPE],
        // The acknowledgement is a typed boundary fact, not an artifact://
        // envelope member. It is already bound above; keep the generic
        // artifact lane empty, as the other System lifecycle receipts do.
        "artifact_refs":[],"evidence_bundle_refs":[],
        "verification_ref":Value::Null,"acceptance_ref":Value::Null,
        "adjudication_ref":Value::Null,"settlement_ref":Value::Null,
        "timestamp":timestamp,"signature":Value::Null,"public_commitment_ref":Value::Null,
        "input_hash":evidence.authorized.evidence.request_hash,
        "output_hash":acknowledgement_root,
        "policy_hash":evidence.authorized.evidence.policy_hash,
    });
    validate_contract(
        RECEIPT_CONTRACT,
        &receipt,
        "migration destination acknowledgement receipt",
    )?;
    let receipt_root = artifact_root(
        "ioi.autonomous-system-continuity-receipt-jcs-sha256.v1",
        &receipt,
    )?;
    let mut retained_effect = effect.clone();
    retained_effect["operation_commitment"] = Value::Null;
    let acknowledgement = json!({
        "schema_version":"ioi.autonomous-system-migration-destination-acknowledgement.v1",
        "acknowledgement_ref":acknowledgement_ref,
        "acknowledgement_root":acknowledgement_root,
        "system_id":effect["system_id"],
        "predecessor_state_ref":effect["predecessor_state_ref"],
        "predecessor_state_root":effect["predecessor_state_root"],
        "predecessor_chain_head_root":effect["predecessor_chain_head_root"],
        "source_deployment_profile_ref":effect["source_deployment_profile_ref"],
        "destination_ref":effect["destination_ref"],
        "acknowledged_state_root":effect["acknowledged_state_root"],
        "required_scope":MIGRATION_ACK_SCOPE,
        "operation_commitment":effect["operation_commitment"],
        "authority_effect_material":retained_effect,
        "authority_grant_refs":[authority_grant_ref],
        "authority_evidence_ref":evidence.authority_evidence_ref,
        "authority_evidence_root":evidence.authority_evidence_root,
        "wallet_consumption_ref":evidence.wallet_consumption_ref,
        "wallet_consumption_root":evidence.wallet_consumption_root,
        "receipt_ref":receipt_ref,
        "receipt_root":receipt_root,
        "status":"committed",
        "created_at":timestamp,
    });
    validate_contract(
        MIGRATION_ACK_CONTRACT,
        &acknowledgement,
        "migration destination acknowledgement",
    )?;
    Ok((acknowledgement, receipt, receipt_root))
}

fn persist_migration_ack(
    data_dir: &str,
    acknowledgement: &Value,
    receipt: &Value,
    receipt_root: &str,
    evidence: &super::system_activation_routes::NodeAdmissionEvidence,
    wallet_consumption: &Value,
) -> Result<(), VErr> {
    let records = [
        (
            AUTHORITY_CONSUMPTION_DIR,
            evidence.wallet_consumption_tail.clone(),
            wallet_consumption,
        ),
        (
            AUTHORITY_EVIDENCE_DIR,
            tail("aslae_", &evidence.authority_evidence_root)?,
            &evidence.authority_evidence,
        ),
        (
            MIGRATION_ACK_RECEIPT_DIR,
            tail("asmdar_", receipt_root)?,
            receipt,
        ),
        (
            MIGRATION_ACK_DIR,
            tail(
                "asmda_",
                required_string(acknowledgement, "/acknowledgement_root")?,
            )?,
            acknowledgement,
        ),
    ];
    for (family, record_tail, value) in records {
        persist_local(data_dir, family, &record_tail, value)?;
        super::substrate_store::admit_required(data_dir, family, &record_tail, value).map_err(
            |error| {
                verr(
                    "system_lifecycle_agentgres_admission_failed",
                    format!("required admission for '{family}/{record_tail}' failed ({error})"),
                )
            },
        )?;
        if load_required_exact(data_dir, family, &record_tail)?.as_ref() != Some(value) {
            return Err(verr(
                "system_continuity_migration_ack_persist_failed",
                "migration acknowledgement graph did not converge byte-exactly",
            ));
        }
    }
    Ok(())
}

#[derive(Debug)]
struct MigrationAckConsumptionFailure {
    error: VErr,
    definitively_unconsumed: bool,
}

async fn recover_or_consume_migration_ack(
    params: &ConsumeApprovalGrantForEffectV2Params,
) -> Result<ApprovalGrantConsumptionReceipt, MigrationAckConsumptionFailure> {
    use super::wallet_network_capability_client::ResolveError;
    let failure = |error: ResolveError, definitively_unconsumed| {
        let error = match error {
            ResolveError::NotConfigured(message) | ResolveError::Unavailable(message) => {
                verr("system_lifecycle_wallet_consumption_unavailable", message)
            }
            ResolveError::Refused(message) => {
                verr("system_lifecycle_wallet_consumption_refused", message)
            }
            ResolveError::Invalid(message) => {
                verr("system_lifecycle_wallet_consumption_invalid", message)
            }
        };
        MigrationAckConsumptionFailure {
            error,
            definitively_unconsumed,
        }
    };
    match super::wallet_network_capability_client::recover_approval_grant_consumption_for_effect_v2(
        params,
    )
    .await
    {
        Ok(Some(value)) => Ok(value),
        Ok(None) => {
            match super::wallet_network_capability_client::consume_approval_grant_for_effect_v2(
                params.clone(),
            )
            .await
            {
                Ok(value) => Ok(value),
                Err(error @ ResolveError::Refused(_)) => {
                    match super::wallet_network_capability_client::recover_approval_grant_consumption_for_effect_v2(
                        params,
                    )
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

fn migration_ack_reservation(
    plan: &Value,
    evidence: &super::system_activation_routes::NodeAdmissionEvidence,
) -> Result<(String, Value), VErr> {
    let effect = &plan["authority_effect_material"];
    let predecessor_chain_root = required(effect, "/predecessor_chain_head_root")?;
    let record_tail = tail("asmdarv_", &predecessor_chain_root)?;
    Ok((
        record_tail,
        json!({
            "schema_version":"ioi.hypervisor.migration-destination-acknowledgement-reservation.v1",
            "predecessor_chain_head_root":predecessor_chain_root,
            "acknowledgement_ref":plan["acknowledgement_ref"],
            "acknowledgement_root":plan["acknowledgement_root"],
            "request_hash":evidence.authorized.evidence.request_hash,
            "wallet_consumption_tail":evidence.wallet_consumption_tail,
        }),
    ))
}

fn verified_migration_ack_evidence_from_intent(
    plan: &Value,
    sealed_authority: &Value,
) -> Result<super::system_activation_routes::NodeAdmissionEvidence, VErr> {
    let evidence = evidence_from_intent(sealed_authority)?;
    let effect = &plan["authority_effect_material"];
    let sequence = effect
        .get("sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            verr(
                "system_lifecycle_intent_invalid",
                "migration acknowledgement plan lacks sequence",
            )
        })?;
    let governing = required(effect, "/source_governing_authority_ref")?;
    let rebuilt = prepare_node_evidence_for(
        effect,
        MIGRATION_ACK_OP,
        sequence,
        MIGRATION_ACK_SCOPE,
        &governing,
        &required(plan, "/acknowledgement_root")?,
        evidence.authorized.clone(),
    )?;
    if evidence_intent_value(&rebuilt) != *sealed_authority {
        return Err(verr(
            "system_lifecycle_intent_unreadable",
            "sealed migration acknowledgement authority coordinates do not reconstruct",
        ));
    }
    Ok(evidence)
}

fn verify_migration_ack_intent_coordinates(record_tail: &str, intent: &Value) -> Result<(), VErr> {
    if intent.get("schema_version").and_then(Value::as_str)
        != Some("ioi.hypervisor.migration-destination-acknowledgement-intent.v1")
    {
        return Err(verr(
            "system_lifecycle_intent_invalid",
            "intent is not a migration destination acknowledgement intent",
        ));
    }
    let request_hash = required(intent, "/governed_authority/request_hash")?;
    if tail("asmdai_", &request_hash)? != record_tail {
        return Err(verr(
            "system_lifecycle_intent_invalid",
            "migration acknowledgement intent tail does not bind its request hash",
        ));
    }
    Ok(())
}

fn scan_sealed_intent_family(
    data_dir: &str,
    family: &str,
    label: &str,
) -> Result<Vec<(String, Result<Value, VErr>)>, VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                format!("{label} intent family cannot be pinned ({error})"),
            ))
        }
    };
    let mut names = super::durable_fs::enumerate_pinned(&directory).map_err(|error| {
        verr(
            "system_lifecycle_intent_unreadable",
            format!("{label} intent family cannot be enumerated ({error})"),
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
                        format!("unexpected {label} intent entry '{name}'"),
                    ));
                }
                let bytes = super::durable_fs::read_slot_strict(&directory, &name)
                    .map_err(|error| {
                        verr(
                            "system_lifecycle_intent_unreadable",
                            format!("{label} intent '{name}' is unreadable ({error})"),
                        )
                    })?
                    .ok_or_else(|| {
                        verr(
                            "system_lifecycle_intent_unreadable",
                            format!("{label} intent '{name}' vanished"),
                        )
                    })?
                    .1;
                let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
                    verr(
                        "system_lifecycle_intent_unreadable",
                        format!("{label} intent '{name}' is malformed ({error})"),
                    )
                })?;
                verify_intent_seal(&value)?;
                Ok(value)
            })();
            (tail_value, checked)
        })
        .collect())
}

fn scan_migration_ack_intents(data_dir: &str) -> Result<Vec<(String, Result<Value, VErr>)>, VErr> {
    Ok(scan_sealed_intent_family(
        data_dir,
        MIGRATION_ACK_INTENT_DIR,
        "migration destination acknowledgement",
    )?
    .into_iter()
    .map(|(record_tail, checked)| {
        let checked = checked.and_then(|value| {
            verify_migration_ack_intent_coordinates(&record_tail, &value)?;
            Ok(value)
        });
        (record_tail, checked)
    })
    .collect())
}

pub(crate) fn ensure_no_pending_migration_ack(data_dir: &str, key: &str) -> Result<(), VErr> {
    for (_tail, intent) in scan_migration_ack_intents(data_dir)? {
        let intent = intent?;
        if intent.get("source_record_tail").and_then(Value::as_str) == Some(key) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                "a migration destination acknowledgement is pending convergence",
            ));
        }
    }
    Ok(())
}

fn ensure_migration_ack_request_admitted(
    data_dir: &str,
    key: &str,
    body: &Value,
) -> Result<Option<Value>, VErr> {
    let mut exact_pending = None;
    for (_tail, intent) in scan_migration_ack_intents(data_dir)? {
        let intent = intent?;
        if intent.get("source_record_tail").and_then(Value::as_str) != Some(key) {
            continue;
        }
        if intent.get("request_body") == Some(body) {
            // A second daemon may continue the same sealed request. Its
            // compiled plan, reservation, and wallet coordinates must still
            // compare equal below. Resume the sealed authority evidence: a
            // fresh authority resolution has a new resolved_at_ms and is not
            // byte-identical to the durable intent even though it authorizes
            // the same request.
            exact_pending = Some(intent);
            continue;
        }
        return Err(verr(
            "system_lifecycle_head_conflict",
            "a different migration destination acknowledgement already reserves this live head",
        ));
    }
    Ok(exact_pending)
}

/// POST /v1/hypervisor/autonomous-systems/:id/continuity/migration-destination-acknowledgements
pub(crate) async fn handle_migration_destination_acknowledgement(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_lifecycle_source_key_invalid",
            "id is not canonical",
        ));
    }
    if let Err(error) = validate_migration_ack_request(&body) {
        return classify(error);
    }
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let (source, exact_continuation) = match with_source_locks(|| {
        super::system_activation_routes::ensure_no_pending_intent(&state.data_dir, &key)?;
        super::system_protected_transition_routes::ensure_no_pending_protected_intent(
            &state.data_dir,
            &key,
        )?;
        super::system_amendment_routes::ensure_no_pending_amendment_intent(&state.data_dir, &key)?;
        ensure_no_pending(&state.data_dir, &key)?;
        let exact_continuation =
            ensure_migration_ack_request_admitted(&state.data_dir, &key, &body)?;
        Ok::<_, VErr>((
            load_continuity_source(&state.data_dir, &key)?,
            exact_continuation,
        ))
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let plan = match build_migration_ack_plan(&source, &body) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let effect = &plan["authority_effect_material"];
    let system_id = required(effect, "/system_id").unwrap_or_default();
    let genesis_ref = required(effect, "/genesis_ref").unwrap_or_default();
    let governing = required(effect, "/source_governing_authority_ref").unwrap_or_default();
    let sequence = effect
        .get("sequence")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let mut evidence = if let Some(intent) = &exact_continuation {
        if intent.get("compiled_plan") != Some(&plan) {
            return classify(verr(
                "system_lifecycle_source_conflict",
                "sealed migration acknowledgement continuation does not match the live compiled plan",
            ));
        }
        match verified_migration_ack_evidence_from_intent(&plan, &intent["governed_authority"]) {
            Ok(value) => value,
            Err(error) => return classify(error),
        }
    } else {
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
            MIGRATION_ACK_OP,
            sequence,
            effect,
        )
        .await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
        match prepare_node_evidence_for(
            effect,
            MIGRATION_ACK_OP,
            sequence,
            MIGRATION_ACK_SCOPE,
            &governing,
            required_string(&plan, "/acknowledgement_root").unwrap_or(""),
            authorized,
        ) {
            Ok(value) => value,
            Err(error) => return classify(error),
        }
    };
    if exact_continuation.is_none() {
        if let Err(error) = preflight_chain_writer_grant(&evidence.wallet_params).await {
            return classify(error);
        }
    }
    let intent_tail = match tail("asmdai_", &evidence.authorized.evidence.request_hash) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let (reservation_tail, reservation) = match migration_ack_reservation(&plan, &evidence) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent = match with_source_locks(|| {
        let fresh = load_continuity_source(&state.data_dir, &key)?;
        if build_migration_ack_plan(&fresh, &body)? != plan {
            return Err(verr(
                "system_lifecycle_head_conflict",
                "durable truth changed before acknowledgement intent sealing",
            ));
        }
        let intent = intent_seal(json!({
            "schema_version":"ioi.hypervisor.migration-destination-acknowledgement-intent.v1",
            "source_record_tail":key,
            "request_body":body,
            "compiled_plan":plan,
            "governed_authority":evidence_intent_value(&evidence),
            "intent_hash":Value::Null,
        }))?;
        persist_local(
            &state.data_dir,
            MIGRATION_ACK_INTENT_DIR,
            &intent_tail,
            &intent,
        )?;
        if let Err(error) = persist_local(
            &state.data_dir,
            MIGRATION_ACK_RESERVATION_DIR,
            &reservation_tail,
            &reservation,
        ) {
            if load_local(&state.data_dir, MIGRATION_ACK_INTENT_DIR, &intent_tail)?.as_ref()
                == Some(&intent)
            {
                remove_intent(&state.data_dir, MIGRATION_ACK_INTENT_DIR, &intent_tail)?;
            }
            return Err(error);
        }
        Ok::<_, VErr>(intent)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if forced_fault(
        "IOI_TEST_FORCE_SYSTEM_MIGRATION_ACK_AFTER_INTENT",
        MIGRATION_ACK_OP,
    ) {
        return classify(verr(
            "system_lifecycle_pending_convergence",
            "test-forced interruption after durable migration acknowledgement intent",
        ));
    }
    let wallet_receipt = match recover_or_consume_migration_ack(&evidence.wallet_params).await {
        Ok(value) => value,
        Err(failure) => {
            if failure.definitively_unconsumed {
                if let Err(error) = with_source_locks(|| {
                    match load_local(&state.data_dir, MIGRATION_ACK_INTENT_DIR, &intent_tail)? {
                        Some(current) if current == intent => {
                            remove_intent(&state.data_dir, MIGRATION_ACK_INTENT_DIR, &intent_tail)?;
                        }
                        Some(_) => {
                            return Err(verr(
                                "system_lifecycle_intent_unreadable",
                                "migration acknowledgement intent changed before refusal cleanup",
                            ));
                        }
                        None => {}
                    }
                    match load_local(
                        &state.data_dir,
                        MIGRATION_ACK_RESERVATION_DIR,
                        &reservation_tail,
                    )? {
                        Some(current) if current == reservation => remove_intent(
                            &state.data_dir,
                            MIGRATION_ACK_RESERVATION_DIR,
                            &reservation_tail,
                        ),
                        Some(_) => Err(verr(
                            "system_lifecycle_intent_unreadable",
                            "migration acknowledgement reservation changed before refusal cleanup",
                        )),
                        None => Ok(()),
                    }
                }) {
                    return classify(error);
                }
            }
            return classify(failure.error);
        }
    };
    let wallet_value = match validate_wallet_receipt(&mut evidence, &wallet_receipt) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if forced_fault(
        "IOI_TEST_FORCE_SYSTEM_MIGRATION_ACK_AFTER_WALLET_CONSUMPTION",
        MIGRATION_ACK_OP,
    ) {
        return classify(verr(
            "system_lifecycle_pending_convergence",
            "test-forced interruption after exact migration acknowledgement wallet consumption",
        ));
    }
    let timestamp = match ms_to_timestamp(wallet_receipt.consumed_at_ms) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let (acknowledgement, receipt, receipt_root) =
        match build_migration_ack_artifacts(&plan, &evidence, &timestamp) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    if let Err(error) = with_source_locks(|| {
        let Some(stored) = load_local(&state.data_dir, MIGRATION_ACK_INTENT_DIR, &intent_tail)?
        else {
            let ack_tail = tail(
                "asmda_",
                required_string(&acknowledgement, "/acknowledgement_root")?,
            )?;
            if load_required_exact(&state.data_dir, MIGRATION_ACK_DIR, &ack_tail)?.as_ref()
                == Some(&acknowledgement)
            {
                return Ok(());
            }
            return Err(verr(
                "system_lifecycle_pending_convergence",
                "migration acknowledgement intent vanished before its exact graph became visible",
            ));
        };
        verify_intent_seal(&stored)?;
        if stored != intent {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                "durable migration acknowledgement intent changed",
            ));
        }
        persist_migration_ack(
            &state.data_dir,
            &acknowledgement,
            &receipt,
            &receipt_root,
            &evidence,
            &wallet_value,
        )?;
        remove_intent(&state.data_dir, MIGRATION_ACK_INTENT_DIR, &intent_tail)
    }) {
        return classify(error);
    }
    (
        StatusCode::OK,
        Json(json!({
            "migration_destination_acknowledgement":acknowledgement,
            "receipt":receipt,
            "nonclaims":{"migration_executed":false,"network_assurance":false,"membership":false,"writer":false,"settlement":false}
        })),
    )
}

/// POST /v1/hypervisor/autonomous-systems/:id/continuity/:op
pub(crate) async fn handle_transition(
    AxumPath((key, op_name)): AxumPath<(String, String)>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_lifecycle_source_key_invalid",
            "id is not canonical",
        ));
    }
    let Some(op) = ContinuityTransitionOp::parse(&op_name) else {
        return classify(verr(
            "system_lifecycle_operation_not_found",
            "unknown continuity op",
        ));
    };
    if let Err(error) = validate_request(&body) {
        return classify(error);
    }
    let declaration = match declaration_from_body(&body) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let source = match with_source_locks(|| {
        super::system_activation_routes::ensure_no_pending_intent(&state.data_dir, &key)?;
        super::system_protected_transition_routes::ensure_no_pending_protected_intent(
            &state.data_dir,
            &key,
        )?;
        super::system_amendment_routes::ensure_no_pending_amendment_intent(&state.data_dir, &key)?;
        ensure_no_pending(&state.data_dir, &key)?;
        ensure_no_pending_migration_ack(&state.data_dir, &key)?;
        let source = load_continuity_source(&state.data_dir, &key)?;
        check_expected(&body, &source)?;
        Ok::<_, VErr>(source)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let successor_binding = match verified_successor_authority_binding(op, &declaration).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let migration_ack = match load_migration_destination_ack(&state.data_dir, op, &declaration) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let plan = match compile_from_source(
        op,
        &source,
        &declaration,
        successor_binding.as_ref(),
        migration_ack.as_ref(),
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let system_id = required(&plan.authority_effect, "/system_id").unwrap_or_default();
    let genesis_ref = required(&source.base.activation_effect, "/genesis_ref").unwrap_or_default();
    let governing =
        required(&plan.authority_effect, "/source_governing_authority_ref").unwrap_or_default();
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
        op.as_str(),
        plan.sequence,
        &plan.authority_effect,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    if op == ContinuityTransitionOp::CompleteSuccession {
        let Some(successor_binding) = successor_binding.as_ref() else {
            return classify(verr(
                "system_continuity_successor_authority_incomplete",
                "completed succession lacks its verified successor binding",
            ));
        };
        if let Err(error) = require_distinct_successor_signer(
            &authorized.evidence.authority_binding,
            successor_binding,
        ) {
            return classify(error);
        }
    }
    let mut evidence = match prepare_node_evidence_for(
        &plan.authority_effect,
        op.as_str(),
        plan.sequence,
        op.required_scope(),
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
    let intent_tail = match tail("asctx_", &evidence.authorized.evidence.request_hash) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent = match with_source_locks(|| {
        let fresh = load_continuity_source(&state.data_dir, &key)?;
        check_expected(&body, &fresh)?;
        let recompiled = compile_from_source(
            op,
            &fresh,
            &declaration,
            successor_binding.as_ref(),
            migration_ack.as_ref(),
        )?;
        if recompiled != plan {
            return Err(verr(
                "system_lifecycle_head_conflict",
                "durable truth changed between authorization and intent sealing",
            ));
        }
        let intent = intent_seal(json!({
            "schema_version":"ioi.hypervisor.continuity-transition-intent.v1","source_record_tail":key,
            "op":op.as_str(),"request_body":body,"compiled_plan":plan,"governed_authority":evidence_intent_value(&evidence),
            "intent_hash":Value::Null
        }))?;
        persist_local(
            &state.data_dir,
            CONTINUITY_INTENT_DIR,
            &intent_tail,
            &intent,
        )?;
        Ok::<_, VErr>(intent)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if let Err(error) = reserve_chain_writer(
        &state.data_dir,
        &system_id,
        plan.sequence,
        required_string(&plan.authority_effect, "/predecessor_chain_head_root").unwrap_or(""),
        required_string(&plan.authority_effect, "/operation_commitment").unwrap_or(""),
        &format!(
            "proposal://{}/continuity/sequence/{}",
            ns(&system_id).unwrap_or("invalid"),
            plan.sequence
        ),
        required_string(&plan.authority_effect, "/operation_commitment").unwrap_or(""),
        op.as_str(),
    ) {
        let _ = remove_intent(&state.data_dir, CONTINUITY_INTENT_DIR, &intent_tail);
        return classify(error);
    }
    if forced_fault("IOI_TEST_FORCE_SYSTEM_CONTINUITY_AFTER_INTENT", op.as_str()) {
        return classify(verr(
            "system_lifecycle_pending_convergence",
            "test-forced interruption after durable continuity intent",
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
                    remove_intent(&state.data_dir, CONTINUITY_INTENT_DIR, &intent_tail)
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
        "IOI_TEST_FORCE_SYSTEM_CONTINUITY_AFTER_WALLET_CONSUMPTION",
        op.as_str(),
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
    let artifacts = match build_continuity_artifacts(&plan, &source, &tuple, &timestamp) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let result = with_source_locks(|| {
        let stored =
            load_local(&state.data_dir, CONTINUITY_INTENT_DIR, &intent_tail)?.ok_or_else(|| {
                verr(
                    "system_lifecycle_pending_convergence",
                    "continuity intent vanished",
                )
            })?;
        verify_intent_seal(&stored)?;
        if stored != intent {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                "durable continuity intent changed",
            ));
        }
        persist_graph(
            &state.data_dir,
            &plan,
            &artifacts,
            &evidence,
            &wallet_value,
            plan.network_enrollment.as_ref(),
        )?;
        if forced_fault(
            "IOI_TEST_FORCE_SYSTEM_CONTINUITY_BEFORE_TERMINAL_VISIBILITY",
            op.as_str(),
        ) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                "test-forced interruption before terminal intent removal",
            ));
        }
        remove_intent(&state.data_dir, CONTINUITY_INTENT_DIR, &intent_tail)
    });
    if let Err(error) = result {
        return classify(error);
    }
    (
        StatusCode::OK,
        Json(
            json!({"op":op.as_str(),"sequence":plan.sequence,"lifecycle_state":artifacts.step.state,
        "transition":artifacts.step.transition,"receipt":artifacts.step.receipt,"operation_log":artifacts.operation_log,
        "autonomous_system_chain":artifacts.chain,"network_enrollment":plan.network_enrollment,
        "nonclaims":{"network_assurance":false,"runtime_effect":false,"membership":false,"writer":false,"settlement":false}}),
        ),
    )
}

/// Read-only named-continuity projection. This never fabricates eligibility:
/// it reports the predecessor-status gate separately from declaration evidence
/// and wallet authority that a future POST must still supply.
pub(crate) async fn handle_get_transition(
    AxumPath((key, op_name)): AxumPath<(String, String)>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_lifecycle_source_key_invalid",
            "id is not canonical",
        ));
    }
    let Some(op) = ContinuityTransitionOp::parse(&op_name) else {
        return classify(verr(
            "system_lifecycle_operation_not_found",
            "unknown continuity op",
        ));
    };
    match with_source_locks(|| {
        ensure_no_pending(&state.data_dir, &key)?;
        let source = load_continuity_source(&state.data_dir, &key)?;
        let status = required(&source.base.chain_head, "/status")?;
        let status_admitted = match op {
            ContinuityTransitionOp::InitiateSuccession
            | ContinuityTransitionOp::InitiateDissolution => {
                matches!(
                    status.as_str(),
                    "active" | "paused" | "suspended" | "successor_governed"
                )
            }
            ContinuityTransitionOp::CompleteSuccession => status == "succession_pending",
            ContinuityTransitionOp::Migrate
            | ContinuityTransitionOp::EnrollLocal
            | ContinuityTransitionOp::ExitLocalEnrollment => {
                matches!(status.as_str(), "active" | "successor_governed")
            }
            ContinuityTransitionOp::OpenDissolutionDisposition => status == "dissolution_pending",
            ContinuityTransitionOp::RecordDissolutionDomainOutcome
            | ContinuityTransitionOp::CompleteDissolution => status == "dissolving",
        };
        let mut blockers = Vec::new();
        if !status_admitted {
            blockers.push(json!({"code":"predecessor_status_not_admitted","status":status}));
        }
        if op == ContinuityTransitionOp::ExitLocalEnrollment && source.current_enrollment.is_none()
        {
            blockers.push(json!({"code":"no_current_local_enrollment"}));
        }
        let committed: Vec<Value> = source
            .base
            .operation_log
            .get("entries")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|entry| {
                        entry.get("operation_name").and_then(Value::as_str) == Some(op.as_str())
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Ok::<_, VErr>(json!({
            "op":op.as_str(),
            "required_scope":op.required_scope(),
            "eligible_now":{"status_admitted":status_admitted,"blockers":blockers},
            "required_declaration_evidence":{
                "trigger_evidence":true,
                "successor_candidate":matches!(op,ContinuityTransitionOp::InitiateSuccession|ContinuityTransitionOp::CompleteSuccession),
                "reissued_authority":op==ContinuityTransitionOp::CompleteSuccession,
                "verified_migration_root":op==ContinuityTransitionOp::Migrate,
                "residual_disposition":matches!(op,ContinuityTransitionOp::CompleteDissolution|ContinuityTransitionOp::ExitLocalEnrollment),
                "local_enrollment_body":matches!(op,ContinuityTransitionOp::EnrollLocal|ContinuityTransitionOp::ExitLocalEnrollment),
                "dissolution_disposition_record":op==ContinuityTransitionOp::OpenDissolutionDisposition,
                "dissolution_domain_outcome":op==ContinuityTransitionOp::RecordDissolutionDomainOutcome
            },
            "chain_head":source.base.chain_head,
            "operation_log_head":source.base.operation_log["head_entry"],
            "current_network_enrollment_ref":source.current_enrollment.as_ref().and_then(|value| value.get("network_enrollment_id")),
            "committed_entries":committed,
            "nonclaims":{"wallet_authorized":false,"network_assurance":false,"membership":false,"writer":false,"settlement":false}
        }))
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

static MIGRATION_ACK_REPLAY_CURSOR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn migration_ack_source_at_plan(
    data_dir: &str,
    intent: &Value,
    plan: &Value,
) -> Result<ContinuitySource, VErr> {
    let effect = &plan["authority_effect_material"];
    let chain_root = required(effect, "/predecessor_chain_head_root")?;
    let chain_head = record_by_root(
        data_dir,
        CHAIN_DIR,
        "asc_",
        &chain_root,
        "migration acknowledgement predecessor chain revision",
    )?;
    let operation_log = load_log_for_chain(data_dir, &chain_head)?;
    let previous_step = load_previous_step(data_dir, &operation_log)?;
    let system_id = required(effect, "/system_id")?;
    let activation_effect = load_activation_effect(data_dir, &system_id)?;
    let source_tail = required(intent, "/source_record_tail")?;
    let admission =
        super::system_genesis_routes::load_verified_admission_by_key(data_dir, &source_tail)?
            .ok_or_else(|| verr("system_lifecycle_not_found", "admitted genesis vanished"))?;
    let lifecycle_profile = admission
        .record
        .pointer("/initial_profile_bundle/lifecycle_profile")
        .cloned()
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_mismatch",
                "admitted genesis lacks its lifecycle profile body",
            )
        })?;
    let current_enrollment = load_current_enrollment(data_dir, &chain_head, &previous_step.state)?;
    let current_dissolution_disposition = load_current_dissolution_disposition(
        data_dir,
        &previous_step.state,
        &previous_step.transition,
    )?;
    Ok(ContinuitySource {
        base: ProtectedTransitionSource {
            activation_effect,
            previous_step,
            chain_head: chain_head.clone(),
            operation_log,
        },
        lifecycle_profile,
        constitution_ref: required(&chain_head, "/constitution_ref")?,
        current_enrollment,
        current_dissolution_disposition,
    })
}

async fn replay_one_migration_ack(
    data_dir: &str,
    record_tail: &str,
    intent: &Value,
) -> Result<(), VErr> {
    verify_intent_seal(intent)?;
    verify_migration_ack_intent_coordinates(record_tail, intent)?;
    let plan = intent.get("compiled_plan").cloned().ok_or_else(|| {
        verr(
            "system_lifecycle_intent_invalid",
            "intent lacks compiled plan",
        )
    })?;
    let body = intent.get("request_body").cloned().ok_or_else(|| {
        verr(
            "system_lifecycle_intent_invalid",
            "intent lacks request body",
        )
    })?;
    validate_migration_ack_request(&body)?;
    let source = migration_ack_source_at_plan(data_dir, intent, &plan)?;
    if build_migration_ack_plan(&source, &body)? != plan {
        return Err(verr(
            "system_lifecycle_source_conflict",
            "migration acknowledgement replay plan does not reconstruct byte-exactly",
        ));
    }
    let mut evidence =
        verified_migration_ack_evidence_from_intent(&plan, &intent["governed_authority"])?;
    let (reservation_tail, reservation) = migration_ack_reservation(&plan, &evidence)?;
    let stored_reservation =
        match load_local(data_dir, MIGRATION_ACK_RESERVATION_DIR, &reservation_tail)? {
            Some(value) => value,
            None => {
                // The replayable intent is fsynced before this CAS reservation.
                // A crash in that narrow window therefore recreates the exact
                // reservation instead of leaving an unowned permanent fence.
                persist_local(
                    data_dir,
                    MIGRATION_ACK_RESERVATION_DIR,
                    &reservation_tail,
                    &reservation,
                )?;
                load_local(data_dir, MIGRATION_ACK_RESERVATION_DIR, &reservation_tail)?.ok_or_else(
                    || {
                        verr(
                            "system_lifecycle_intent_unreadable",
                            "migration acknowledgement reservation did not become durable",
                        )
                    },
                )?
            }
        };
    if stored_reservation != reservation {
        // This request lost the predecessor-head CAS before the wallet
        // boundary. Confirm wallet.network has no receipt for its exact
        // coordinates, then remove only the losing replayable intent so it
        // cannot permanently interlock the winning acknowledgement.
        return match super::wallet_network_capability_client::
            recover_approval_grant_consumption_for_effect_v2(&evidence.wallet_params)
            .await
        {
            Ok(None) => remove_intent(data_dir, MIGRATION_ACK_INTENT_DIR, record_tail),
            Ok(Some(_)) => Err(verr(
                "system_lifecycle_intent_unreadable",
                "losing migration acknowledgement unexpectedly has wallet consumption evidence",
            )),
            Err(super::wallet_network_capability_client::ResolveError::NotConfigured(message)
                | super::wallet_network_capability_client::ResolveError::Unavailable(message)) => {
                Err(verr("system_lifecycle_wallet_consumption_unavailable", message))
            }
            Err(super::wallet_network_capability_client::ResolveError::Refused(message)) => {
                Err(verr("system_lifecycle_wallet_consumption_refused", message))
            }
            Err(super::wallet_network_capability_client::ResolveError::Invalid(message)) => {
                Err(verr("system_lifecycle_wallet_consumption_invalid", message))
            }
        };
    }
    let ack_tail = tail("asmda_", &required(&plan, "/acknowledgement_root")?)?;
    if load_required_exact(data_dir, MIGRATION_ACK_DIR, &ack_tail)?.is_some() {
        return remove_intent(data_dir, MIGRATION_ACK_INTENT_DIR, record_tail);
    }
    let wallet_receipt = match recover_or_consume_migration_ack(&evidence.wallet_params).await {
        Ok(value) => value,
        Err(failure) => {
            if failure.definitively_unconsumed {
                with_source_locks(|| {
                    remove_intent(data_dir, MIGRATION_ACK_INTENT_DIR, record_tail)?;
                    remove_intent(data_dir, MIGRATION_ACK_RESERVATION_DIR, &reservation_tail)
                })?;
            }
            return Err(failure.error);
        }
    };
    let wallet_value = validate_wallet_receipt(&mut evidence, &wallet_receipt)?;
    let timestamp = ms_to_timestamp(wallet_receipt.consumed_at_ms)?;
    let (acknowledgement, receipt, receipt_root) =
        build_migration_ack_artifacts(&plan, &evidence, &timestamp)?;
    with_source_locks(|| {
        let current =
            load_local(data_dir, MIGRATION_ACK_INTENT_DIR, record_tail)?.ok_or_else(|| {
                verr(
                    "system_lifecycle_pending_convergence",
                    "migration acknowledgement replay intent vanished",
                )
            })?;
        if current != *intent {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                "migration acknowledgement replay intent changed",
            ));
        }
        persist_migration_ack(
            data_dir,
            &acknowledgement,
            &receipt,
            &receipt_root,
            &evidence,
            &wallet_value,
        )?;
        remove_intent(data_dir, MIGRATION_ACK_INTENT_DIR, record_tail)
    })
}

pub(crate) async fn complete_migration_destination_acknowledgement_intents(
    data_dir: &str,
    max: usize,
) {
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let entries = match scan_migration_ack_intents(data_dir) {
        Ok(entries) => entries,
        Err((_, message)) => {
            eprintln!("MigrationDestinationAcknowledgement replay scan failed ({message})");
            return;
        }
    };
    let start = MIGRATION_ACK_REPLAY_CURSOR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    for offset in 0..entries.len().min(max) {
        let (record_tail, result) = &entries[(start + offset) % entries.len().max(1)];
        let intent = match result {
            Ok(value) => value,
            Err((_, message)) => {
                eprintln!("MigrationDestinationAcknowledgement poisoned intent '{record_tail}' retained ({message})");
                continue;
            }
        };
        if let Err((_, message)) = replay_one_migration_ack(data_dir, record_tail, intent).await {
            eprintln!("MigrationDestinationAcknowledgement intent '{record_tail}' retained/incomplete ({message})");
        }
    }
}

static CONTINUITY_REPLAY_CURSOR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn verify_intent_coordinates(tail_value: &str, intent: &Value) -> Result<(), VErr> {
    if intent.get("schema_version").and_then(Value::as_str)
        != Some("ioi.hypervisor.continuity-transition-intent.v1")
    {
        return Err(verr(
            "system_lifecycle_intent_invalid",
            "intent schema is not the continuity-transition intent",
        ));
    }
    if ContinuityTransitionOp::parse(&required(intent, "/op")?).is_none() {
        return Err(verr(
            "system_lifecycle_intent_invalid",
            "intent op is outside the named continuity family",
        ));
    }
    let request_hash = required(intent, "/governed_authority/request_hash")?;
    if tail_value != tail("asctx_", &request_hash)? {
        return Err(verr(
            "system_lifecycle_intent_invalid",
            "intent tail does not bind its sealed request hash",
        ));
    }
    Ok(())
}

fn source_at_plan(
    data_dir: &str,
    intent: &Value,
    plan: &CompiledContinuityTransitionPlan,
) -> Result<ContinuitySource, VErr> {
    let chain_root = required(&plan.authority_effect, "/predecessor_chain_head_root")?;
    let chain_head = record_by_root(
        data_dir,
        CHAIN_DIR,
        "asc_",
        &chain_root,
        "predecessor continuity chain revision",
    )?;
    let operation_log = load_log_for_chain(data_dir, &chain_head)?;
    let previous_step = load_previous_step(data_dir, &operation_log)?;
    let system_id = required(&plan.authority_effect, "/system_id")?;
    let activation_effect = load_activation_effect(data_dir, &system_id)?;
    let source_tail = required(intent, "/source_record_tail")?;
    let admission =
        super::system_genesis_routes::load_verified_admission_by_key(data_dir, &source_tail)?
            .ok_or_else(|| verr("system_lifecycle_not_found", "admitted genesis vanished"))?;
    let lifecycle_profile = admission
        .record
        .pointer("/initial_profile_bundle/lifecycle_profile")
        .cloned()
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_mismatch",
                "admitted genesis lacks its lifecycle profile body",
            )
        })?;
    let current_enrollment = load_current_enrollment(data_dir, &chain_head, &previous_step.state)?;
    let current_dissolution_disposition = load_current_dissolution_disposition(
        data_dir,
        &previous_step.state,
        &previous_step.transition,
    )?;
    Ok(ContinuitySource {
        base: ProtectedTransitionSource {
            activation_effect,
            previous_step,
            chain_head,
            operation_log,
        },
        lifecycle_profile,
        constitution_ref: required(&plan.authority_effect, "/constitution_ref")?,
        current_enrollment,
        current_dissolution_disposition,
    })
}

async fn replay_one(data_dir: &str, tail_value: &str, intent: &Value) -> Result<(), VErr> {
    verify_intent_seal(intent)?;
    verify_intent_coordinates(tail_value, intent)?;
    let plan: CompiledContinuityTransitionPlan =
        serde_json::from_value(intent["compiled_plan"].clone())
            .map_err(|error| verr("system_lifecycle_intent_invalid", error.to_string()))?;
    let op = plan.op;
    let declaration = declaration_from_body(&intent["request_body"])?;
    let source = source_at_plan(data_dir, intent, &plan)?;
    let successor_binding = plan
        .authority_effect
        .get("successor_authority_binding")
        .filter(|value| !value.is_null());
    let migration_ack = load_migration_destination_ack(data_dir, op, &declaration)?;
    if compile_from_source(
        op,
        &source,
        &declaration,
        successor_binding,
        migration_ack.as_ref(),
    )? != plan
    {
        return Err(verr(
            "system_lifecycle_source_conflict",
            "continuity replay plan does not reconstruct byte-exactly",
        ));
    }
    let mut evidence = evidence_from_intent(&intent["governed_authority"])?;
    if op == ContinuityTransitionOp::CompleteSuccession {
        let successor_binding = successor_binding.ok_or_else(|| {
            verr(
                "system_continuity_successor_authority_incomplete",
                "sealed succession replay lacks its successor authority binding",
            )
        })?;
        require_distinct_successor_signer(
            &evidence.authorized.evidence.authority_binding,
            successor_binding,
        )?;
    }
    let governing = required(&plan.authority_effect, "/source_governing_authority_ref")?;
    let rebuilt = prepare_node_evidence_for(
        &plan.authority_effect,
        op.as_str(),
        plan.sequence,
        op.required_scope(),
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
            "sealed continuity authority coordinates do not reconstruct",
        ));
    }
    let system_id = required(&plan.authority_effect, "/system_id")?;
    let reservation = reserve_chain_writer(
        data_dir,
        &system_id,
        plan.sequence,
        &required(&plan.authority_effect, "/predecessor_chain_head_root")?,
        &required(&plan.authority_effect, "/operation_commitment")?,
        &format!(
            "proposal://{}/continuity/sequence/{}",
            ns(&system_id)?,
            plan.sequence
        ),
        &required(&plan.authority_effect, "/operation_commitment")?,
        op.as_str(),
    );
    if let Err(error) = reservation {
        if error.0 == "system_lifecycle_head_conflict" {
            remove_intent(data_dir, CONTINUITY_INTENT_DIR, tail_value)?;
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
            // A crash may land after wallet.network committed the one-use
            // consumption but before the Hypervisor persisted its local
            // evidence graph. Recover that exact wallet-owned receipt before
            // attempting another consume, which must otherwise refuse the
            // already-spent grant.
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
                            remove_intent(data_dir, CONTINUITY_INTENT_DIR, tail_value)?;
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
    let artifacts = build_continuity_artifacts(&plan, &source, &tuple, &timestamp)?;
    with_source_locks(|| {
        let current =
            load_local(data_dir, CONTINUITY_INTENT_DIR, tail_value)?.ok_or_else(|| {
                verr(
                    "system_lifecycle_pending_convergence",
                    "continuity replay intent vanished",
                )
            })?;
        if current != *intent {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                "continuity replay intent changed",
            ));
        }
        persist_graph(
            data_dir,
            &plan,
            &artifacts,
            &evidence,
            &wallet_value,
            plan.network_enrollment.as_ref(),
        )?;
        remove_intent(data_dir, CONTINUITY_INTENT_DIR, tail_value)
    })
}

fn scan_continuity_intents(data_dir: &str) -> Result<Vec<(String, Result<Value, VErr>)>, VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, CONTINUITY_INTENT_DIR)
    {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                format!("continuity intent family cannot be pinned ({error})"),
            ))
        }
    };
    let mut names = super::durable_fs::enumerate_pinned(&directory).map_err(|error| {
        verr(
            "system_lifecycle_intent_unreadable",
            format!("continuity intent family cannot be enumerated ({error})"),
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
                        format!("unexpected continuity intent entry '{name}'"),
                    ));
                }
                let bytes = super::durable_fs::read_slot_strict(&directory, &name)
                    .map_err(|error| {
                        verr(
                            "system_lifecycle_intent_unreadable",
                            format!("continuity intent '{name}' is unreadable ({error})"),
                        )
                    })?
                    .ok_or_else(|| {
                        verr(
                            "system_lifecycle_intent_unreadable",
                            format!("continuity intent '{name}' vanished"),
                        )
                    })?
                    .1;
                let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
                    verr(
                        "system_lifecycle_intent_unreadable",
                        format!("continuity intent '{name}' is malformed ({error})"),
                    )
                })?;
                verify_intent_seal(&value)?;
                verify_intent_coordinates(&tail_value, &value)?;
                Ok(value)
            })();
            (tail_value, checked)
        })
        .collect())
}

pub(crate) async fn complete_continuity_transition_intents(data_dir: &str, max: usize) {
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let entries = match scan_continuity_intents(data_dir) {
        Ok(entries) => entries,
        Err((_, message)) => {
            eprintln!("ContinuityTransition replay scan failed ({message})");
            return;
        }
    };
    let start = CONTINUITY_REPLAY_CURSOR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    for offset in 0..entries.len().min(max) {
        let (tail_value, result) = &entries[(start + offset) % entries.len().max(1)];
        let intent = match result {
            Ok(intent) => intent,
            Err((_, message)) => {
                eprintln!(
                    "ContinuityTransition poisoned intent '{tail_value}' retained ({message})"
                );
                continue;
            }
        };
        if let Err((_, message)) = replay_one(data_dir, tail_value, intent).await {
            eprintln!("ContinuityTransition intent '{tail_value}' retained/incomplete ({message})");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(path: &str) -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/../../docs/architecture/_meta/schemas/fixtures/{path}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .expect(path),
        )
        .expect(path)
    }

    fn h(marker: u8) -> String {
        format!("sha256:{}", format!("{marker:02x}").repeat(32))
    }

    fn source() -> ContinuitySource {
        let log = fixture("autonomous-system-operation-log-v1/positive-activation-prefix.json");
        let chain = fixture("autonomous-system-chain-v1/positive-active-sequence-two.json");
        let head = &log["head_entry"];
        let previous_step = UnverifiedCommittedSystemLifecycleStep {
            proposal: json!({"proposal_ref":head["proposal_ref"]}),
            decision: json!({"decision_ref":head["decision_ref"]}),
            state: json!({"activation_state_ref":head["state_ref"],"system_id":log["system_id"],
                "sequence":2,"status":"active","active_profile_set_ref":chain["active_profile_set_ref"],
                "active_profile_set_root":chain["active_profile_set_root"]}),
            transition: json!({"lifecycle_transition_id":head["transition_ref"]}),
            receipt: json!({"receipt_ref":head["receipt_ref"]}),
            state_root: required_string(&log, "/latest_state_root").unwrap().into(),
            proposal_root: required_string(head, "/proposal_root").unwrap().into(),
            decision_root: required_string(head, "/decision_root").unwrap().into(),
            transition_root: required_string(head, "/transition_root").unwrap().into(),
            receipt_root: required_string(head, "/receipt_root").unwrap().into(),
        };
        let activation_effect = json!({
            "schema_version":"ioi.autonomous-system-lifecycle-authority-effect.v1","operation":"activate","sequence":2,
            "system_id":log["system_id"],"genesis_ref":chain["genesis_ref"],"source_governing_authority_ref":"wallet://acme/governing",
            "home_domain_ref":log["home_domain_ref"],"home_domain_commitment":log["home_domain_commitment"],
            "home_domain_binding_ref":log["home_domain_binding_ref"],"home_domain_binding_root":log["home_domain_binding_root"],
            "policy_root":log["policy_root"],"module_registry_root":log["module_registry_root"],"upgrade_policy_ref":log["upgrade_policy_ref"],
            "deployment_profile_ref":chain["deployment_profile_ref"],"deployment_profile_root":chain["deployment_profile_root"],
            "active_profile_set_ref":chain["active_profile_set_ref"],"active_profile_set_root":chain["active_profile_set_root"],
            "chain_ref":chain["chain_ref"],"live_chain_created":true,"node_membership_created":false,
            "runtime_effect_admitted":false,"network_effect_admitted":false
        });
        let mut lifecycle_profile =
            fixture("lifecycle-continuity-profile-v1/positive-successor-governed.json");
        lifecycle_profile["lifecycle_profile_id"] =
            chain["lifecycle_continuity_profile_ref"].clone();
        ContinuitySource {
            constitution_ref: required_string(&chain, "/constitution_ref").unwrap().into(),
            current_enrollment: None,
            current_dissolution_disposition: None,
            lifecycle_profile,
            base: ProtectedTransitionSource {
                activation_effect,
                previous_step,
                chain_head: chain,
                operation_log: log,
            },
        }
    }

    fn authority() -> DecisionAuthorityTuple {
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

    #[test]
    fn named_ops_never_parse_as_generic_protected_ops() {
        for op in ContinuityTransitionOp::ALL {
            assert!(
                ioi_types::app::system_lifecycle_transitions::ProtectedTransitionOp::parse(
                    op.as_str()
                )
                .is_none()
            );
            assert_eq!(AUTHORITY.operation_scope(op.as_str()), op.required_scope());
        }
        assert_eq!(
            AUTHORITY.operation_scope(MIGRATION_ACK_OP),
            MIGRATION_ACK_SCOPE
        );
    }

    #[test]
    fn dissolution_ladder_artifacts_validate_every_registered_envelope() {
        // The full disposition ladder at unit speed: every committed-graph
        // artifact (proposal body, transition envelope, receipt, state,
        // operation log, chain, dissolution receipt) is validated inside
        // build_continuity_artifacts against the registered contracts, so
        // any schema-versus-implementation drift fails HERE in milliseconds
        // instead of an hour into the live journey.
        let mut source = source();
        let system_id = required(&source.base.chain_head, "/system_id").expect("system id");
        let auth = authority();
        let timestamp = "2026-07-26T00:00:00Z";

        let step = |source: &ContinuitySource,
                    op: ContinuityTransitionOp,
                    declaration: &ContinuityTransitionDeclaration,
                    record: Option<&Value>|
         -> ProtectedStepArtifacts {
            let plan = compile_from_source(op, source, declaration, None, None)
                .unwrap_or_else(|error| panic!("{} plan: {error:?}", op.as_str()));
            // The trusted record rides the source; re-inject for ops that
            // consume it since compile_from_source reads the source copy.
            let _ = record;
            let artifacts = build_continuity_artifacts(&plan, source, &auth, timestamp)
                .unwrap_or_else(|error| panic!("{} artifacts: {error:?}", op.as_str()));
            artifacts
        };
        let advance = |source: &mut ContinuitySource, artifacts: &ProtectedStepArtifacts| {
            source.base.previous_step = artifacts.step.clone();
            source.base.operation_log = artifacts.operation_log.clone();
            source.base.chain_head = artifacts.chain.clone();
        };

        let mut declaration = ContinuityTransitionDeclaration {
            trigger_evidence_refs: vec!["evidence://acme/dissolution/trigger".into()],
            successor_candidate_ref: None,
            successor_authority_ref: None,
            migration_destination_ack_ref: None,
            migration_destination_ack_root: None,
            residual_disposition_receipt_refs: vec![],
            live_effect_refs: vec![],
            network_enrollment: None,
            dissolution_disposition: None,
            dissolution_domain_outcome: None,
        };
        let initiate = step(
            &source,
            ContinuityTransitionOp::InitiateDissolution,
            &declaration,
            None,
        );
        advance(&mut source, &initiate);

        // The record binds the exact initiate transition and the active
        // profile; the fixture profile declares no asset contracts, so the
        // assets domain waives against the profile null declaration.
        let profile_root = jcs_hash(&json!({
            "domain": "ioi.lifecycle-continuity-profile-artifact-jcs-sha256.v1",
            "artifact": source.lifecycle_profile,
        }))
        .expect("profile root");
        let initiate_ref = required(&initiate.step.state, "/transition_ref").expect("initiate ref");
        let initiate_root = initiate.step.transition_root.clone();
        let root_tail = initiate_root.strip_prefix("sha256:").expect("root tail");
        let domain_entry = |policy: &str| json!({"policy_ref": policy, "state": "pending", "evidence_refs": [], "receipt_refs": []});
        let policies = [
            ("active_work", "policy://acme/lifecycle/work-disposition"),
            (
                "outstanding_obligations",
                "policy://acme/lifecycle/obligations",
            ),
            (
                "authority_revocation",
                "policy://acme/lifecycle/revoke-authority",
            ),
            (
                "worker_and_node_shutdown",
                "policy://acme/lifecycle/shutdown",
            ),
            (
                "data_export_retention_and_erasure",
                "policy://acme/lifecycle/data-disposition",
            ),
            ("network_exit", "policy://acme/lifecycle/network-exit"),
            ("tombstone", "policy://acme/lifecycle/tombstone"),
        ];
        let mut outcome_domains = serde_json::Map::new();
        for (domain, policy) in policies {
            outcome_domains.insert(domain.to_owned(), domain_entry(policy));
        }
        outcome_domains.insert(
            "assets".to_owned(),
            json!({"policy_ref": "policy://profile-null-declaration",
                "state": "waived_under_policy", "evidence_refs": [], "receipt_refs": []}),
        );
        let namespace_tail = system_id.strip_prefix("system://").expect("namespace");
        let record = json!({
            "schema_version": "ioi.autonomous-system-dissolution-disposition.v1",
            "dissolution_disposition_id":
                format!("dissolution-disposition://{namespace_tail}/initiate/{root_tail}"),
            "system_id": system_id,
            "lifecycle_profile_ref": source.lifecycle_profile["lifecycle_profile_id"],
            "lifecycle_profile_root": profile_root,
            "initiate_transition_ref": initiate_ref,
            "initiate_transition_root": initiate_root,
            "outcome_domains": Value::Object(outcome_domains),
            "escalation_decision_refs": [],
            "complete_transition_ref": Value::Null,
            "status": "open",
            "created_at": "2026-07-26T00:00:00Z",
        });
        declaration.trigger_evidence_refs = vec![];
        declaration.dissolution_disposition = Some(record);
        let opened = step(
            &source,
            ContinuityTransitionOp::OpenDissolutionDisposition,
            &declaration,
            None,
        );
        advance(&mut source, &opened);
        declaration.dissolution_disposition = None;
        // The opened record is the proposal body of the committed open step.
        source.current_dissolution_disposition = Some(
            opened
                .step
                .proposal
                .get("proposal_body")
                .cloned()
                .expect("opened record body"),
        );

        for (domain, policy) in policies {
            let mut d = declaration.clone();
            d.dissolution_domain_outcome = Some(json!({
                "domain": domain,
                "state": "completed",
                "policy_ref": policy,
                "evidence_refs": [format!("evidence://dissolution/{domain}")],
                "receipt_refs": [format!("receipt://dissolution/{domain}")],
            }));
            let recorded = step(
                &source,
                ContinuityTransitionOp::RecordDissolutionDomainOutcome,
                &d,
                None,
            );
            let updated = compile_from_source(
                ContinuityTransitionOp::RecordDissolutionDomainOutcome,
                &source,
                &d,
                None,
                None,
            )
            .expect("record plan")
            .dissolution_disposition
            .expect("updated record");
            advance(&mut source, &recorded);
            source.current_dissolution_disposition = Some(updated);
        }
        assert_eq!(
            source
                .current_dissolution_disposition
                .as_ref()
                .and_then(|record| record.get("status"))
                .and_then(Value::as_str),
            Some("terminal_complete"),
        );

        let complete_plan = compile_from_source(
            ContinuityTransitionOp::CompleteDissolution,
            &source,
            &declaration,
            None,
            None,
        )
        .expect("complete plan");
        let completed = build_continuity_artifacts(&complete_plan, &source, &auth, timestamp)
            .expect("complete artifacts");
        assert_eq!(
            completed
                .step
                .transition
                .get("disposition_receipt_refs")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(7),
        );
        let (dissolution_receipt, _tail) =
            build_dissolution_receipt(&complete_plan, &completed).expect("dissolution receipt");
        assert_eq!(
            dissolution_receipt
                .get("assurance_posture")
                .and_then(Value::as_str),
            Some("dissolution_committed"),
        );
    }

    #[test]
    fn migration_ack_plan_binds_exact_head_and_rejects_a_noop_destination() {
        let source = source();
        let body = json!({
            "expected_chain_head_root":source.base.chain_head["chain_root"],
            "expected_predecessor_state_root":source.base.previous_step.state_root,
            "destination_ref":"deployment-profile://acme/system-alpha/migrated",
            "acknowledged_state_root":source.base.previous_step.state_root,
        });
        let plan = build_migration_ack_plan(&source, &body).expect("ack plan");
        assert_eq!(
            plan["authority_effect_material"]["predecessor_chain_head_root"],
            source.base.chain_head["chain_root"]
        );
        assert_eq!(
            plan["authority_effect_material"]["source_governing_authority_ref"],
            "org://acme/research"
        );
        let mut no_op = body;
        no_op["destination_ref"] = source.base.chain_head["deployment_profile_ref"].clone();
        assert!(build_migration_ack_plan(&source, &no_op)
            .unwrap_err()
            .1
            .contains("must differ"));
    }

    #[test]
    fn relocated_migration_ack_intent_refuses_its_filename_coordinate() {
        let request_hash = h(0x61);
        let intent = intent_seal(json!({
            "schema_version":"ioi.hypervisor.migration-destination-acknowledgement-intent.v1",
            "governed_authority":{"request_hash":request_hash},
            "intent_hash":Value::Null,
        }))
        .expect("seal");
        let exact_tail = tail("asmdai_", &request_hash).expect("tail");
        assert!(verify_migration_ack_intent_coordinates(&exact_tail, &intent).is_ok());
        assert!(verify_migration_ack_intent_coordinates(
            &tail("asmdai_", &h(0x62)).expect("relocated tail"),
            &intent,
        )
        .is_err());
    }

    #[test]
    fn succession_refuses_a_new_principal_aliasing_the_current_signer() {
        let current = json!({
            "approval_authority": {
                "authority_id": [1, 2, 3],
                "public_key": [4, 5, 6],
                "signature_suite": -8
            }
        });
        let aliased = json!({
            "approval_authority": {
                "authority_id": [1, 2, 3],
                "public_key": [4, 5, 6],
                "signature_suite": -8
            }
        });
        let reissued = json!({
            "approval_authority": {
                "authority_id": [7, 8, 9],
                "public_key": [10, 11, 12],
                "signature_suite": -8
            }
        });
        assert!(require_distinct_successor_signer(&current, &aliased).is_err());
        assert!(require_distinct_successor_signer(&current, &reissued).is_ok());
    }

    #[test]
    fn succession_builds_a_contract_valid_live_chain_successor() {
        let source = source();
        let declaration = ContinuityTransitionDeclaration {
            trigger_evidence_refs: vec!["evidence://succession/trigger".into()],
            successor_candidate_ref: Some("org://acme/successor".into()),
            successor_authority_ref: None,
            migration_destination_ack_ref: None,
            migration_destination_ack_root: None,
            residual_disposition_receipt_refs: vec![],
            live_effect_refs: vec![],
            network_enrollment: None,
            dissolution_disposition: None,
            dissolution_domain_outcome: None,
        };
        let plan = compile_from_source(
            ContinuityTransitionOp::InitiateSuccession,
            &source,
            &declaration,
            None,
            None,
        )
        .expect("compile");
        let artifacts =
            build_continuity_artifacts(&plan, &source, &authority(), "2026-07-24T12:00:00Z")
                .expect("build");
        assert_eq!(artifacts.chain["status"], "succession_pending");
        assert_eq!(artifacts.chain["latest_sequence"], 3);
        assert_eq!(
            artifacts.operation_log["entries"].as_array().unwrap().len(),
            4
        );

        let mut successor_source = ContinuitySource {
            base: ProtectedTransitionSource {
                activation_effect: source.base.activation_effect.clone(),
                previous_step: artifacts.step.clone(),
                chain_head: artifacts.chain.clone(),
                operation_log: artifacts.operation_log.clone(),
            },
            lifecycle_profile: source.lifecycle_profile.clone(),
            constitution_ref: source.constitution_ref.clone(),
            current_enrollment: None,
            current_dissolution_disposition: None,
        };
        successor_source.lifecycle_profile["succession"]["successor_candidate_refs"]
            .as_array_mut()
            .unwrap()
            .push(json!("org://acme/other-successor"));
        let substituted = ContinuityTransitionDeclaration {
            trigger_evidence_refs: vec!["evidence://succession/selected".into()],
            successor_candidate_ref: Some("org://acme/other-successor".into()),
            successor_authority_ref: Some("org://acme/successor-authority".into()),
            migration_destination_ack_ref: None,
            migration_destination_ack_root: None,
            residual_disposition_receipt_refs: vec![],
            live_effect_refs: vec![],
            network_enrollment: None,
            dissolution_disposition: None,
            dissolution_domain_outcome: None,
        };
        assert!(compile_from_source(
            ContinuityTransitionOp::CompleteSuccession,
            &successor_source,
            &substituted,
            None,
            None,
        )
        .unwrap_err()
        .1
        .contains("differs from the initiated candidate"));
        let complete = ContinuityTransitionDeclaration {
            successor_candidate_ref: Some("org://acme/successor".into()),
            ..substituted
        };
        let successor_binding = json!({
            "principal_ref":"org://acme/successor-authority",
            "approval_authority":{"revoked":false,"scope_allowlist":["scope:autonomous_system.lifecycle.*"]}
        });
        let complete_plan = compile_from_source(
            ContinuityTransitionOp::CompleteSuccession,
            &successor_source,
            &complete,
            Some(&successor_binding),
            None,
        )
        .expect("complete succession");
        let completed = build_continuity_artifacts(
            &complete_plan,
            &successor_source,
            &authority(),
            "2026-07-24T12:01:00Z",
        )
        .expect("build completion");
        assert_eq!(
            completed.chain["governance_owner_refs"],
            json!(["org://acme/successor-authority"])
        );
        assert_eq!(
            completed.step.state["governing_authority_ref"],
            "org://acme/successor-authority"
        );
    }
}
