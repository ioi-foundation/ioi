//! Generic protected operational lifecycle transitions (M1.5 m1-5b) —
//! helper layer.
//!
//! This module CONTINUES the proven activation runtime at sequence three or
//! later: the same durable families for proposals, decisions, transitions,
//! and authority evidence; a new lifecycle-state family for the
//! post-activation states; operation-log continuation under the v2 general
//! contract; and chain revisions over the already-general chain contract.
//! Nothing here mints a parallel authority or persistence path.
//!
//! 4b-1 scope: discovery/loaders and pure artifact builders with unit tests.
//! The route handlers, sealed intents, and daemon registration land in 4b-2.

use ioi_types::app::system_activation::UnverifiedCommittedSystemLifecycleStep;
use ioi_types::app::system_lifecycle_transitions::{
    compile_protected_transition_plan, CompiledProtectedTransitionPlan, ProtectedTransitionOp,
};
use serde_json::Value;

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use ioi_services::wallet_network::ApprovalGrantConsumptionReceipt;
use serde_json::json;

use super::governed_authority::{self as governed, AuthorityPolicyContext, Governance};
use super::DaemonState;
use super::system_activation_routes::{
    canonical_hash_str, canonical_system_key, classify, contains_sensitive_key,
    enumerate_family, evidence_from_intent, evidence_intent_value, forced_fault, intent_seal,
    jcs_hash, load_local, load_required_exact, ms_to_timestamp, persist_local,
    prepare_node_evidence_for, remove_intent, required_string, tail, validate_contract,
    validate_wallet_receipt, verify_intent_seal, verr, with_source_locks,
    NodeAdmissionEvidence, ACTIVATION_RECEIPT_DIR, AUTHORITY, AUTHORITY_CONSUMPTION_DIR,
    AUTHORITY_EVIDENCE_DIR, CHAIN_DIR, DECISION_DIR, MAX_REQUEST_BYTES, OPERATION_LOG_DIR,
    PROPOSAL_DIR, STATE_DIR, SYSTEM_ACTIVATION_GATE, TRANSITION_DIR,
};

const OPERATION_LOG_V2_ROOT_DOMAIN: &str = "ioi.autonomous-system-operation-log-jcs-sha256.v2";
const CHAIN_ROOT_DOMAIN: &str = "ioi.autonomous-system-chain-jcs-sha256.v1";
const PROTECTED_PROPOSAL_HASH_DOMAIN: &str =
    "ioi.autonomous-system-protected-transition-proposal-jcs-sha256.v1";
const PROTECTED_DECISION_HASH_DOMAIN: &str =
    "ioi.autonomous-system-protected-transition-decision-jcs-sha256.v1";
const LIFECYCLE_TRANSITION_HASH_DOMAIN: &str =
    "ioi.autonomous-system-lifecycle-transition-jcs-sha256.v1";
const LIFECYCLE_RECEIPT_HASH_DOMAIN: &str =
    "ioi.lifecycle-transition-receipt-artifact-jcs-sha256.v1";
const PROTECTED_PROPOSAL_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-protected-transition-proposal/v1";
const PROTECTED_DECISION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-protected-transition-decision/v1";
const LIFECYCLE_STATE_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-lifecycle-state/v1";
const LIFECYCLE_TRANSITION_CONTRACT: &str = "schema://ioi/foundations/lifecycle-transition/v1";
const LIFECYCLE_RECEIPT_CONTRACT: &str =
    "schema://ioi/foundations/lifecycle-transition-receipt/v1";
const OPERATION_LOG_V2_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-operation-log/v2";
const SYSTEM_CHAIN_CONTRACT: &str = "schema://ioi/foundations/autonomous-system-chain/v1";

/// The wallet/authority tuple a decision commits. 4b-2 fills this from
/// NodeAdmissionEvidence; tests fill synthetic canonical values.
pub(crate) struct DecisionAuthorityTuple {
    pub input_hash: String,
    pub policy_hash: String,
    pub effect_hash: String,
    pub authority_grant_ref: String,
    pub authority_evidence_ref: String,
    pub authority_evidence_root: String,
    pub wallet_grant_consumption_ref: String,
    pub wallet_grant_consumption_evidence_ref: String,
}

/// One fully built protected step, every artifact contract-validated.
#[derive(Debug)]
pub(crate) struct ProtectedStepArtifacts {
    pub step: UnverifiedCommittedSystemLifecycleStep,
    pub operation_log: Value,
    pub chain: Value,
}

type VErr = (String, String);

/// Post-activation lifecycle states (`ioi.autonomous-system-lifecycle-state.v1`).
pub(crate) const LIFECYCLE_STATE_DIR: &str = "autonomous-system-lifecycle-states";
/// Protected-transition receipts (LifecycleTransitionReceipt family, sequence >= 3).
pub(crate) const PROTECTED_RECEIPT_DIR: &str = "autonomous-system-protected-transition-receipts";
/// Sealed protected-transition intents (single family; the op rides the tail).
pub(crate) const PROTECTED_INTENT_DIR: &str = "autonomous-system-protected-transition-intents";

/// The exact truth a protected transition compiles against, reconstructed
/// from durable records only — never from the caller.
pub(crate) struct ProtectedTransitionSource {
    /// Committed sequence-two activation effect (identity carrier).
    pub activation_effect: Value,
    /// Predecessor step artifacts at chain-head sequence.
    pub previous_step: UnverifiedCommittedSystemLifecycleStep,
    /// The current chain head revision (highest `latest_sequence`).
    pub chain_head: Value,
    /// The current operation log revision matching the chain head.
    pub operation_log: Value,
}

fn required(value: &Value, pointer: &str) -> Result<String, VErr> {
    required_string(value, pointer).map(str::to_owned)
}

/// Load the current chain head revision for `system_id`: the unique chain
/// record carrying the highest `latest_sequence`. Duplicate heads at the
/// same sequence are corruption and refuse.
pub(crate) fn load_chain_head(data_dir: &str, system_id: &str) -> Result<Value, VErr> {
    select_chain_head(enumerate_family(data_dir, CHAIN_DIR)?, system_id)
}

/// Pure head selection over enumerated chain revisions: the head is the
/// unique revision with the highest `latest_sequence` for the System;
/// duplicate heads at that sequence are corruption and refuse.
fn select_chain_head(
    records: Vec<(String, Value)>,
    system_id: &str,
) -> Result<Value, VErr> {
    let mut best: Option<(u64, Value)> = None;
    let mut duplicate_at: Option<u64> = None;
    for (_tail, value) in records {
        if value.get("system_id").and_then(Value::as_str) != Some(system_id) {
            continue;
        }
        let sequence = value
            .get("latest_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                verr(
                    "system_lifecycle_artifact_invalid",
                    "chain revision lacks latest_sequence",
                )
            })?;
        match &best {
            Some((current, _)) if *current == sequence => duplicate_at = Some(sequence),
            Some((current, _)) if *current > sequence => {}
            _ => {
                best = Some((sequence, value));
                if duplicate_at == Some(sequence) {
                    duplicate_at = None;
                }
            }
        }
    }
    if let Some(sequence) = duplicate_at {
        if best.as_ref().is_some_and(|(head, _)| *head == sequence) {
            return Err(verr(
                "system_lifecycle_artifact_mismatch",
                format!("two chain revisions both claim head sequence {sequence}"),
            ));
        }
    }
    best.map(|(_, value)| value).ok_or_else(|| {
        verr(
            "system_lifecycle_not_found",
            "no live chain revision exists for this System",
        )
    })
}

/// Load the operation-log revision bound by the chain head.
pub(crate) fn load_log_for_chain(data_dir: &str, chain: &Value) -> Result<Value, VErr> {
    let log_root = required(chain, "/operation_log_root")?;
    let tail = format!(
        "asol_{}",
        log_root
            .strip_prefix("sha256:")
            .filter(|tail| tail.len() == 64)
            .ok_or_else(|| {
                verr(
                    "system_lifecycle_artifact_invalid",
                    "chain head carries a non-canonical operation_log_root",
                )
            })?
    );
    load_required_exact(data_dir, OPERATION_LOG_DIR, &tail)?.ok_or_else(|| {
        verr(
            "system_lifecycle_artifact_mismatch",
            "chain head binds an operation log that is not durably admitted",
        )
    })
}

pub(crate) fn record_by_root(
    data_dir: &str,
    family: &str,
    prefix: &str,
    root: &str,
    label: &str,
) -> Result<Value, VErr> {
    if !canonical_hash_str(root) {
        return Err(verr(
            "system_lifecycle_artifact_invalid",
            format!("{label} root is not canonical"),
        ));
    }
    let tail = format!("{prefix}{}", &root[7..]);
    load_required_exact(data_dir, family, &tail)?.ok_or_else(|| {
        verr(
            "system_lifecycle_artifact_mismatch",
            format!("{label} bound by the head is not durably admitted"),
        )
    })
}

/// Reconstruct the predecessor step exactly as the operation-log head binds
/// it: proposal/decision/transition/receipt/state, each loaded content-
/// addressed by the roots the head entry committed.
pub(crate) fn load_previous_step(
    data_dir: &str,
    log: &Value,
) -> Result<UnverifiedCommittedSystemLifecycleStep, VErr> {
    let head = log.get("head_entry").ok_or_else(|| {
        verr(
            "system_lifecycle_artifact_invalid",
            "operation log lacks a head entry",
        )
    })?;
    let sequence = head.get("sequence").and_then(Value::as_u64).ok_or_else(|| {
        verr(
            "system_lifecycle_artifact_invalid",
            "operation-log head lacks a sequence",
        )
    })?;
    let proposal_root = required(head, "/proposal_root")?;
    let decision_root = required(head, "/decision_root")?;
    let transition_root = required(head, "/transition_root")?;
    let receipt_root = required(head, "/receipt_root")?;
    let state_root = required(head, "/state_root")?;
    let state_family = if sequence == 2 { STATE_DIR } else { LIFECYCLE_STATE_DIR };
    let receipt = if sequence == 2 {
        record_by_root(
            data_dir,
            ACTIVATION_RECEIPT_DIR,
            "asar_",
            &receipt_root,
            "activation receipt",
        )?
    } else {
        // Sequence >= 3 heads are either generic protected transitions or
        // constitutional amendments; both are content-addressed by the same
        // committed receipt root, so dispatch on which family holds it.
        if !canonical_hash_str(&receipt_root) {
            return Err(verr(
                "system_lifecycle_artifact_invalid",
                "protected receipt root is not canonical",
            ));
        }
        match load_required_exact(
            data_dir,
            PROTECTED_RECEIPT_DIR,
            &format!("asptr_{}", &receipt_root[7..]),
        )? {
            Some(value) => value,
            None => record_by_root(
                data_dir,
                super::system_amendment_routes::AMENDMENT_RECEIPT_DIR,
                "asamr_",
                &receipt_root,
                "amendment receipt",
            )?,
        }
    };
    Ok(UnverifiedCommittedSystemLifecycleStep {
        proposal: record_by_root(data_dir, PROPOSAL_DIR, "aslp_", &proposal_root, "proposal")?,
        decision: record_by_root(data_dir, DECISION_DIR, "aslad_", &decision_root, "decision")?,
        state: record_by_root(data_dir, state_family, "asls_", &state_root, "state")?,
        transition: record_by_root(
            data_dir,
            TRANSITION_DIR,
            "aslt_",
            &transition_root,
            "transition",
        )?,
        receipt,
        state_root,
        proposal_root,
        decision_root,
        transition_root,
        receipt_root,
    })
}

/// Load the committed sequence-two activation effect (the identity carrier)
/// from the durably admitted authority evidence.
pub(crate) fn load_activation_effect(data_dir: &str, system_id: &str) -> Result<Value, VErr> {
    let mut matches = Vec::new();
    for (_tail, value) in enumerate_family(data_dir, AUTHORITY_EVIDENCE_DIR)? {
        if value.get("system_id").and_then(Value::as_str) == Some(system_id)
            && value.get("sequence").and_then(Value::as_u64) == Some(2)
            && value.get("operation").and_then(Value::as_str) == Some("activate")
        {
            matches.push(value);
        }
    }
    if matches.len() != 1 {
        return Err(verr(
            if matches.is_empty() {
                "system_lifecycle_not_found"
            } else {
                "system_lifecycle_artifact_mismatch"
            },
            format!(
                "expected exactly one converged activation authority evidence, found {}",
                matches.len()
            ),
        ));
    }
    matches
        .remove(0)
        .get("authorized_effect")
        .cloned()
        .filter(|effect| !effect.is_null())
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_invalid",
                "activation authority evidence lacks the committed effect",
            )
        })
}

/// Reconstruct the complete durable truth a protected transition compiles
/// against, and cross-check that chain head, operation log, and predecessor
/// step agree before any compile happens.
pub(crate) fn load_protected_source(
    data_dir: &str,
    system_id: &str,
) -> Result<ProtectedTransitionSource, VErr> {
    let chain_head = load_chain_head(data_dir, system_id)?;
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
    let activation_effect = load_activation_effect(data_dir, system_id)?;
    Ok(ProtectedTransitionSource {
        activation_effect,
        previous_step,
        chain_head,
        operation_log,
    })
}

/// Compile a protected transition from durable truth only.
pub(crate) fn compile_from_source(
    op: ProtectedTransitionOp,
    source: &ProtectedTransitionSource,
) -> Result<CompiledProtectedTransitionPlan, VErr> {
    let chain_head_root = required(&source.chain_head, "/chain_root")?;
    compile_protected_transition_plan(
        op,
        &source.activation_effect,
        &source.previous_step,
        &chain_head_root,
    )
    .map_err(|error| verr("system_lifecycle_plan_invalid", error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn revision(system: &str, sequence: u64, marker: &str) -> (String, Value) {
        (
            format!("asc_{marker}"),
            json!({"system_id": system, "latest_sequence": sequence, "marker": marker}),
        )
    }

    #[test]
    fn head_selection_takes_the_highest_sequence_for_the_system() {
        let head = select_chain_head(
            vec![
                revision("system://a", 2, "two"),
                revision("system://a", 4, "four"),
                revision("system://b", 9, "foreign"),
                revision("system://a", 3, "three"),
            ],
            "system://a",
        )
        .expect("head");
        assert_eq!(head["marker"], "four");
    }

    #[test]
    fn duplicate_heads_at_the_top_sequence_refuse() {
        let error = select_chain_head(
            vec![
                revision("system://a", 3, "left"),
                revision("system://a", 3, "right"),
                revision("system://a", 2, "old"),
            ],
            "system://a",
        )
        .expect_err("duplicate heads");
        assert_eq!(error.0, "system_lifecycle_artifact_mismatch");
    }

    #[test]
    fn superseded_duplicates_below_the_head_do_not_refuse() {
        let head = select_chain_head(
            vec![
                revision("system://a", 3, "left"),
                revision("system://a", 3, "right"),
                revision("system://a", 5, "head"),
            ],
            "system://a",
        )
        .expect("head above duplicates");
        assert_eq!(head["marker"], "head");
    }

    #[test]
    fn missing_system_refuses_not_found() {
        let error = select_chain_head(vec![revision("system://b", 2, "b")], "system://a")
            .expect_err("no chain");
        assert_eq!(error.0, "system_lifecycle_not_found");
    }
}

fn artifact_root_with(domain: &str, artifact: &Value) -> Result<String, VErr> {
    jcs_hash(&json!({"domain": domain, "artifact": artifact}))
}

fn ns(system_id: &str) -> Result<&str, VErr> {
    system_id.strip_prefix("system://").ok_or_else(|| {
        verr(
            "system_lifecycle_artifact_invalid",
            "system_id is not canonical",
        )
    })
}

/// Build the complete protected step (proposal, decision, state, transition,
/// receipt) plus the continued operation log and chain revision, validating
/// every artifact against its registered contract. Pure over its inputs.
pub(crate) fn build_protected_artifacts(
    plan: &CompiledProtectedTransitionPlan,
    source: &ProtectedTransitionSource,
    authority: &DecisionAuthorityTuple,
    timestamp: &str,
) -> Result<ProtectedStepArtifacts, VErr> {
    let effect = &plan.authority_effect;
    let system_id = required(effect, "/system_id")?;
    let genesis_ref = required(effect, "/genesis_ref")?;
    let operation_commitment = required(effect, "/operation_commitment")?;
    let sequence = plan.sequence;
    let op = plan.op.as_str();
    let scope = plan.op.required_scope();
    let irreversibility = plan.op.irreversibility().as_str();

    let proposal_ref = format!("proposal://{}/lifecycle/sequence/{sequence}", ns(&system_id)?);
    let proposal_material = json!({
        "domain": PROTECTED_PROPOSAL_HASH_DOMAIN,
        "proposal_ref": proposal_ref,
        "system_id": system_id,
        "genesis_ref": genesis_ref,
        "op": op,
        "sequence": sequence,
        "predecessor_status": plan.predecessor_status.as_str(),
        "predecessor_state_root": plan.previous_step.state_root,
        "predecessor_chain_head_root": effect["predecessor_chain_head_root"],
        "irreversibility": irreversibility,
        "required_scope": scope,
        "operation_commitment": operation_commitment,
        "authority_effect": effect,
        "authority_effect_hash": authority.effect_hash,
        "status": "proposed",
        "created_at": timestamp,
    });
    let proposal_root = jcs_hash(&proposal_material)?;
    let mut proposal = proposal_material;
    proposal.as_object_mut().expect("object").remove("domain");
    proposal["schema_version"] = json!("ioi.autonomous-system-protected-transition-proposal.v1");
    proposal["proposal_root"] = json!(proposal_root);
    validate_contract(PROTECTED_PROPOSAL_CONTRACT, &proposal, "protected proposal")?;

    let decision_ref = format!("decision://{}/lifecycle/sequence/{sequence}", ns(&system_id)?);
    let decision_material = json!({
        "domain": PROTECTED_DECISION_HASH_DOMAIN,
        "decision_ref": decision_ref,
        "proposal_ref": proposal_ref,
        "proposal_root": proposal_root,
        "system_id": system_id,
        "op": op,
        "sequence": sequence,
        "irreversibility": irreversibility,
        "required_scope": scope,
        "operation_commitment": operation_commitment,
        "input_hash": authority.input_hash,
        "policy_hash": authority.policy_hash,
        "effect_hash": authority.effect_hash,
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
    decision["schema_version"] =
        json!("ioi.autonomous-system-protected-transition-decision.v1");
    decision["decision_root"] = json!(decision_root);
    validate_contract(PROTECTED_DECISION_CONTRACT, &decision, "protected decision")?;

    let transition_ref = format!(
        "lifecycle-transition://{}/sequence/{sequence}",
        ns(&system_id)?
    );
    let receipt_root_seed = jcs_hash(&json!({
        "domain": "ioi.autonomous-system-lifecycle-evidence-ref-jcs-sha256.v1",
        "system_id": system_id,
        "sequence": sequence,
        "kind": "lifecycle_transition_receipt",
    }))?;
    let receipt_ref = format!(
        "receipt://ltr_{}",
        receipt_root_seed.strip_prefix("sha256:").expect("hash prefix")
    );

    let mut state = plan.semantic_state.clone();
    state["transition_ref"] = json!(transition_ref);
    state["transition_receipt_ref"] = json!(receipt_ref);
    state["created_at"] = json!(timestamp);

    let transition = json!({
        "schema_version": "ioi.lifecycle-transition.v1",
        "lifecycle_transition_id": transition_ref,
        "system_id": system_id,
        "resulting_or_related_system_id": Value::Null,
        "lifecycle_profile_ref": source.chain_head["lifecycle_continuity_profile_ref"],
        "transition_kind": op,
        "genesis_ref": Value::Null,
        "manifest_ref": Value::Null,
        "admitted_manifest_root": Value::Null,
        "previous_state": plan.predecessor_status.as_str(),
        "proposed_state": plan.op.resulting_status().as_str(),
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
    validate_contract(LIFECYCLE_TRANSITION_CONTRACT, &transition, "protected transition")?;
    let transition_root = artifact_root_with(LIFECYCLE_TRANSITION_HASH_DOMAIN, &transition)?;

    state["transition_root"] = json!(transition_root);
    validate_contract(LIFECYCLE_STATE_CONTRACT, &state, "lifecycle state")?;

    let bound_facts = json!({
        "system_id": system_id,
        "operation": op,
        "sequence": sequence,
        "required_scope": scope,
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
        "proposal_ref": proposal_ref,
        "proposal_root": proposal_root,
        "decision_ref": decision_ref,
        "decision_root": decision_root,
        "transition_ref": transition_ref,
        "transition_root": transition_root,
        "predecessor_state_root": plan.previous_step.state_root,
        "resulting_state_ref": effect["resulting_state_ref"],
        "resulting_state_root": plan.resulting_state_root,
        "active_profile_set_ref": Value::Null,
        "active_profile_set_root": Value::Null,
        "chain_ref": effect["chain_ref"],
        "live_chain_created": false,
    });
    // Boundary = exactly the non-null ref-valued bound facts plus the four
    // authority coordinates, per the receipt's exact-coverage invariant.
    // Identity re-attestation is deliberately absent: the chain binds it.
    let mut boundary = vec![
        system_id.clone(),
        proposal_ref.clone(),
        decision_ref.clone(),
        transition_ref.clone(),
        required(effect, "/resulting_state_ref")?,
        required(effect, "/chain_ref")?,
        authority.authority_grant_ref.clone(),
        authority.authority_evidence_ref.clone(),
        authority.wallet_grant_consumption_ref.clone(),
        authority.wallet_grant_consumption_evidence_ref.clone(),
    ];
    boundary.sort();
    boundary.dedup();
    let receipt = json!({
        "schema_version": "ioi.lifecycle-transition-receipt.v1",
        "receipt_id": receipt_ref,
        "receipt_ref": receipt_ref,
        "receipt_type": "lifecycle_transition",
        "receipt_profile_ref": LIFECYCLE_RECEIPT_CONTRACT,
        "actor_id": "runtime://hypervisor-runtime",
        "subject_ref": transition_ref,
        "op": op,
        "sequence": sequence,
        "attested_boundary_fact_refs": boundary,
        "bound_facts": bound_facts,
        "input_hash": authority.input_hash,
        "output_hash": plan.resulting_state_root,
        "policy_hash": authority.policy_hash,
        "effect_hash": authority.effect_hash,
        "authority_grant_id": authority.authority_grant_ref,
        "required_scope": scope,
        "authority_scopes": [scope],
        "authority_evidence_ref": authority.authority_evidence_ref,
        "authority_evidence_root": authority.authority_evidence_root,
        "wallet_grant_consumption_ref": authority.wallet_grant_consumption_ref,
        "wallet_grant_consumption_root": authority.effect_hash,
        "wallet_grant_consumption_evidence_ref":
            authority.wallet_grant_consumption_evidence_ref,
        "primitive_capabilities": [], "artifact_refs": [], "evidence_bundle_refs": [],
        "verification_ref": Value::Null, "acceptance_ref": Value::Null,
        "claim_scope_ref": Value::Null, "run_id": Value::Null, "task_id": Value::Null,
        "adjudication_ref": Value::Null, "settlement_ref": Value::Null,
        "signature": Value::Null, "public_commitment_ref": Value::Null,
        "assurance_posture": "protected_lifecycle_committed",
        "assurance_note": "generic protected operational transition committed over the live chain; no membership, runtime, network, constitution, or profile-set effect exists",
        "timestamp": timestamp, "outcome": "ok", "at": timestamp,
    });
    validate_contract(LIFECYCLE_RECEIPT_CONTRACT, &receipt, "protected receipt")?;
    let receipt_root = artifact_root_with(LIFECYCLE_RECEIPT_HASH_DOMAIN, &receipt)?;

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

    let operation_log = continue_operation_log(plan, &step, source, timestamp)?;
    let chain = continue_chain(plan, &step, source, &operation_log, timestamp)?;
    Ok(ProtectedStepArtifacts {
        step,
        operation_log,
        chain,
    })
}

fn log_entry_for_step(
    plan: &CompiledProtectedTransitionPlan,
    step: &UnverifiedCommittedSystemLifecycleStep,
    timestamp: &str,
) -> Result<Value, VErr> {
    let effect = &plan.authority_effect;
    Ok(json!({
        "sequence": plan.sequence,
        "entry_kind": "protected_transition",
        "operation_name": plan.op.as_str(),
        "operation_owner_profile_ref": PROTECTED_PROPOSAL_CONTRACT,
        "operation_owner_ref": step.proposal["proposal_ref"],
        "operation_owner_root": step.proposal_root,
        "required_scope": plan.op.required_scope(),
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
        "receipt_profile_ref": LIFECYCLE_RECEIPT_CONTRACT,
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
    }))
}

/// Continue the operation log under the v2 general contract: a v1
/// activation-prefix log migrates by carrying its closed prefix verbatim; a
/// v2 log appends. Entry-to-entry continuity is enforced here (daemon-owned)
/// because portable index-fixed rules cannot express it generally.
pub(crate) fn continue_operation_log(
    plan: &CompiledProtectedTransitionPlan,
    step: &UnverifiedCommittedSystemLifecycleStep,
    source: &ProtectedTransitionSource,
    timestamp: &str,
) -> Result<Value, VErr> {
    let entry = log_entry_for_step(plan, step, timestamp)?;
    let system_id = required(&plan.authority_effect, "/system_id")?;
    continue_log_with_entry(
        &source.operation_log,
        &entry,
        plan.sequence,
        &plan.previous_step.state_root,
        &system_id,
        timestamp,
    )
}

/// Shared v1-to-v2 operation-log continuation: a v1 activation-prefix log
/// migrates by carrying its closed prefix verbatim; a v2 log appends. The
/// protected-transition and constitution-amendment continuations both
/// converge here so one implementation owns the head/root discipline.
pub(crate) fn continue_log_with_entry(
    prior: &Value,
    entry: &Value,
    sequence: u64,
    predecessor_state_root: &str,
    system_id: &str,
    timestamp: &str,
) -> Result<Value, VErr> {
    let prior_entries = prior
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_invalid",
                "prior operation log lacks entries",
            )
        })?;
    let prior_head_state_root = required(prior, "/latest_state_root")?;
    if prior_head_state_root != predecessor_state_root {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "operation-log continuation detaches from the predecessor state",
        ));
    }
    let mut entries = prior_entries;
    entries.push(entry.clone());
    let mut log = prior.clone();
    log["schema_version"] = json!("ioi.autonomous-system-operation-log.v2");
    log["snapshot_kind"] = json!("lifecycle_log");
    log["entries"] = json!(entries);
    log["head_entry"] = entry.clone();
    log["latest_sequence"] = json!(sequence);
    log["latest_operation_commitment"] = entry["operation_commitment"].clone();
    log["latest_transition_commitment_ref"] = Value::Null;
    log["latest_transition_ref"] = entry["transition_ref"].clone();
    log["latest_transition_root"] = entry["transition_root"].clone();
    log["latest_receipt_ref"] = entry["receipt_ref"].clone();
    log["latest_receipt_root"] = entry["receipt_root"].clone();
    log["latest_state_ref"] = entry["state_ref"].clone();
    log["latest_state_root"] = entry["state_root"].clone();
    log["status"] = json!("committed");
    log["created_at"] = json!(timestamp);
    let mut material = log.as_object().cloned().expect("object");
    material.remove("schema_version");
    material.remove("operation_log_ref");
    material.remove("operation_log_root");
    material.insert("domain".to_owned(), json!(OPERATION_LOG_V2_ROOT_DOMAIN));
    let root = jcs_hash(&Value::Object(material))?;
    log["operation_log_ref"] = json!(format!(
        "agentgres://operation-log/autonomous-system/{}/revision/{root}",
        ns(system_id)?
    ));
    log["operation_log_root"] = json!(root);
    validate_contract(OPERATION_LOG_V2_CONTRACT, &log, "operation log v2")?;
    Ok(log)
}

/// Continue the chain with a new revision at the protected head.
pub(crate) fn continue_chain(
    plan: &CompiledProtectedTransitionPlan,
    step: &UnverifiedCommittedSystemLifecycleStep,
    source: &ProtectedTransitionSource,
    operation_log: &Value,
    timestamp: &str,
) -> Result<Value, VErr> {
    let mut chain = source.chain_head.clone();
    chain["latest_sequence"] = json!(plan.sequence);
    chain["latest_operation_commitment"] =
        plan.authority_effect["operation_commitment"].clone();
    chain["latest_transition_id"] = step.transition["lifecycle_transition_id"].clone();
    chain["latest_transition_root"] = json!(step.transition_root);
    chain["latest_receipt_ref"] = step.receipt["receipt_ref"].clone();
    chain["latest_receipt_root"] = json!(step.receipt_root);
    chain["latest_state_ref"] = step.state["lifecycle_state_ref"].clone();
    chain["latest_state_root"] = json!(step.state_root);
    chain["operation_log_ref"] = operation_log["operation_log_ref"].clone();
    chain["operation_log_root"] = operation_log["operation_log_root"].clone();
    chain["status"] = json!(plan.op.resulting_status().as_str());
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

#[cfg(test)]
mod builder_tests {
    use super::*;
    use ioi_types::app::system_lifecycle_transitions::compile_protected_transition_plan;
    use serde_json::json;

    fn fixture(path: &str) -> Value {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/architecture/_meta/schemas/fixtures/");
        serde_json::from_str(
            &std::fs::read_to_string(format!("{root}{path}")).expect(path),
        )
        .expect(path)
    }

    fn h(marker: u8) -> String {
        format!("sha256:{}", format!("{marker:02x}").repeat(32))
    }

    /// A coherent durable prior assembled from the REAL registered fixtures:
    /// the v1 activation-prefix log and the sequence-two chain revision that
    /// binds it (same log root, same latest state root, same System).
    fn real_prior_source() -> ProtectedTransitionSource {
        let log = fixture("autonomous-system-operation-log-v1/positive-activation-prefix.json");
        let chain = fixture("autonomous-system-chain-v1/positive-active-sequence-two.json");
        assert_eq!(log["operation_log_root"], chain["operation_log_root"]);
        assert_eq!(log["latest_state_root"], chain["latest_state_root"]);
        let head = &log["head_entry"];
        let previous_step = UnverifiedCommittedSystemLifecycleStep {
            proposal: json!({"proposal_ref": head["proposal_ref"]}),
            decision: json!({"decision_ref": head["decision_ref"], "decided_at": "2026-07-21T00:00:00.000Z"}),
            state: json!({
                "activation_state_ref": head["state_ref"],
                "system_id": log["system_id"],
                "sequence": 2,
                "status": "active",
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
            "system_id": log["system_id"],
            "genesis_ref": chain["genesis_ref"],
            "genesis_admission_record_root": chain["genesis_admission_record_root"],
            "genesis_admission_receipt_ref": format!(
                "receipt://asgar_{}", "61".repeat(32)
            ),
            "genesis_admission_receipt_root": h(0x71),
            "sequence_zero_materialization_id":
                log["entries"][0]["materialization_ref"],
            "sequence_zero_materialization_root":
                log["entries"][0]["materialization_root"],
            "sequence_zero_receipt_ref": log["entries"][0]["receipt_ref"],
            "sequence_zero_receipt_root": log["entries"][0]["receipt_root"],
            "sequence_zero_receipt_artifact_root":
                log["entries"][0]["receipt_artifact_root"],
            "component_registry_ref": log["entries"][0]["component_registry_ref"],
            "component_registry_root": log["entries"][0]["component_registry_root"],
            "materialization_wallet_consumption_ref":
                log["entries"][0]["wallet_consumption_ref"],
            "materialization_wallet_consumption_root":
                log["entries"][0]["wallet_consumption_root"],
            "profile_bundle_root": h(0x72),
            "source_governing_authority_ref": "wallet://acme/governing",
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
        ProtectedTransitionSource {
            activation_effect,
            previous_step,
            chain_head: chain,
            operation_log: log,
        }
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
            wallet_grant_consumption_evidence_ref: format!(
                "system-lifecycle-authority-consumption://aslac_{}",
                "57".repeat(32)
            ),
        }
    }

    #[test]
    fn full_protected_step_builds_and_every_artifact_validates() {
        let source = real_prior_source();
        let plan = compile_from_source(ProtectedTransitionOp::Pause, &source).expect("plan");
        assert_eq!(plan.sequence, 3);
        let artifacts = build_protected_artifacts(
            &plan,
            &source,
            &authority_tuple(),
            "2026-07-22T12:00:00.000Z",
        )
        .expect("artifacts");
        assert_eq!(artifacts.operation_log["latest_sequence"], 3);
        assert_eq!(
            artifacts.operation_log["entries"].as_array().unwrap().len(),
            4
        );
        assert_eq!(
            artifacts.operation_log["schema_version"],
            "ioi.autonomous-system-operation-log.v2"
        );
        assert_eq!(artifacts.chain["latest_sequence"], 3);
        assert_eq!(artifacts.chain["status"], "paused");
        assert_eq!(
            artifacts.chain["latest_state_root"].as_str().unwrap(),
            plan.resulting_state_root,
        );
        // continuity: the appended entry binds the prior head state root.
        let entry = &artifacts.operation_log["head_entry"];
        assert_eq!(
            entry["predecessor_state_root"],
            source.operation_log["latest_state_root"],
        );
        assert_eq!(artifacts.step.receipt["op"], "pause");
    }

    #[test]
    fn continuation_refuses_a_detached_predecessor() {
        let source = real_prior_source();
        let plan = compile_from_source(ProtectedTransitionOp::Pause, &source).expect("plan");
        let mut detached = real_prior_source();
        detached.operation_log["latest_state_root"] = json!(h(0x99));
        let artifacts = build_protected_artifacts(
            &plan,
            &detached,
            &authority_tuple(),
            "2026-07-22T12:00:00.000Z",
        );
        let error = artifacts.expect_err("detached continuation");
        assert_eq!(error.0, "system_lifecycle_artifact_mismatch");
    }

    #[test]
    fn one_way_and_terminal_arcs_build_over_the_real_prior() {
        let source = real_prior_source();
        for (op, expected_status) in [
            (ProtectedTransitionOp::Retire, "retired"),
            (ProtectedTransitionOp::Quarantine, "quarantined"),
            (ProtectedTransitionOp::Revoke, "revoked"),
        ] {
            let plan = compile_from_source(op, &source).expect(op.as_str());
            let artifacts = build_protected_artifacts(
                &plan,
                &source,
                &authority_tuple(),
                "2026-07-22T12:00:00.000Z",
            )
            .expect(op.as_str());
            assert_eq!(artifacts.chain["status"], expected_status, "{}", op.as_str());
        }
    }
}

fn validate_protected_request(body: &Value) -> Result<(), VErr> {
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
        "expected_chain_head_root",
        "expected_predecessor_state_root",
        "wallet_approval_grant",
    ];
    if let Some(key) = object.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(verr(
            "system_lifecycle_request_field_unknown",
            format!("undeclared request field '{key}' is forbidden"),
        ));
    }
    for key in ["expected_chain_head_root", "expected_predecessor_state_root"] {
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

fn check_expected_roots(body: &Value, source: &ProtectedTransitionSource) -> Result<(), VErr> {
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
    if body.get("expected_predecessor_state_root")
        != Some(&json!(source.previous_step.state_root))
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
        wallet_grant_consumption_evidence_ref: evidence
            .wallet_consumption_evidence_ref
            .clone(),
    })
}

fn persist_protected_graph(
    data_dir: &str,
    artifacts: &ProtectedStepArtifacts,
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
            PROTECTED_RECEIPT_DIR,
            tail("asptr_", &artifacts.step.receipt_root)?,
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
    for (family, record_tail, value) in &records {
        persist_local(data_dir, family, record_tail, value)?;
        if forced_fault("IOI_TEST_FORCE_SYSTEM_LIFECYCLE_AFTER_LOCAL_PERSIST", family) {
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
        if forced_fault("IOI_TEST_FORCE_SYSTEM_LIFECYCLE_AFTER_AGENTGRES_ADMIT", family) {
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

/// POST /v1/hypervisor/autonomous-systems/:id/transitions/:op
pub(crate) async fn handle_transition(
    AxumPath((key, op_name)): AxumPath<(String, String)>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_lifecycle_source_key_invalid",
            "id must be 'asg_' plus 64 lowercase hexadecimal characters",
        ));
    }
    let Some(op) = ProtectedTransitionOp::parse(&op_name) else {
        return classify(verr(
            "system_lifecycle_operation_not_found",
            format!("'{op_name}' is not a generic protected transition"),
        ));
    };
    if let Err(error) = validate_protected_request(&body) {
        return classify(error);
    }
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let (source, plan) = match with_source_locks(|| {
        super::system_activation_routes::ensure_no_pending_intent(&state.data_dir, &key)?;
        ensure_no_pending_protected_intent(&state.data_dir, &key)?;
        super::system_amendment_routes::ensure_no_pending_amendment_intent(
            &state.data_dir,
            &key,
        )?;
        let source = load_protected_source(&state.data_dir, &system_id_for_key(&state.data_dir, &key)?)?;
        check_expected_roots(&body, &source)?;
        let plan = compile_from_source(op, &source)?;
        Ok::<_, VErr>((source, plan))
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let system_id = match required(&plan.authority_effect, "/system_id") {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let genesis_ref = match required(&source.activation_effect, "/genesis_ref") {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let governing = match required(&source.activation_effect, "/source_governing_authority_ref")
    {
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
        op.as_str(),
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
    let intent_tail_value =
        match tail("asptx_", &evidence.authorized.evidence.request_hash) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    let sealed = match with_source_locks(|| {
        // Revalidate the entire durable truth under the lock, then seal.
        let fresh = load_protected_source(&state.data_dir, &system_id)?;
        check_expected_roots(&body, &fresh)?;
        let recompiled = compile_from_source(op, &fresh)?;
        if recompiled != plan {
            return Err(verr(
                "system_lifecycle_head_conflict",
                "durable truth changed between authorization and intent sealing",
            ));
        }
        let intent = intent_seal(json!({
            "schema_version": "ioi.hypervisor.protected-transition-intent.v1",
            "source_record_tail": key,
            "op": op.as_str(),
            "request_body": body,
            "compiled_plan": serde_json::to_value(&plan)
                .map_err(|e| verr("system_lifecycle_intent_invalid", e.to_string()))?,
            "governed_authority": evidence_intent_value(&evidence),
            "intent_hash": Value::Null,
        }))?;
        persist_local(
            &state.data_dir,
            PROTECTED_INTENT_DIR,
            &intent_tail_value,
            &intent,
        )?;
        Ok::<_, VErr>(intent)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    drop(sealed);
    if forced_fault("IOI_TEST_FORCE_SYSTEM_LIFECYCLE_AFTER_INTENT", op.as_str()) {
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
                    remove_intent(&state.data_dir, PROTECTED_INTENT_DIR, &intent_tail_value)
                });
                if let Err(error) = cleanup {
                    return classify(error);
                }
                return classify(verr(
                    "system_lifecycle_wallet_consumption_refused",
                    message,
                ));
            }
            Err(super::wallet_network_capability_client::ResolveError::Invalid(message)) => {
                return classify(verr(
                    "system_lifecycle_wallet_consumption_invalid",
                    message,
                ))
            }
        };
    let wallet_value = match validate_wallet_receipt(&mut evidence, &wallet_receipt) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if forced_fault(
        "IOI_TEST_FORCE_SYSTEM_LIFECYCLE_AFTER_WALLET_CONSUMPTION",
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
    let artifacts = match build_protected_artifacts(&plan, &source, &tuple, &timestamp) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let result = with_source_locks(|| {
        let stored = load_local(&state.data_dir, PROTECTED_INTENT_DIR, &intent_tail_value)?
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
        persist_protected_graph(&state.data_dir, &artifacts, &evidence, &wallet_value)?;
        if forced_fault(
            "IOI_TEST_FORCE_SYSTEM_LIFECYCLE_BEFORE_TERMINAL_VISIBILITY",
            op.as_str(),
        ) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                "test-forced interruption before terminal intent removal",
            ));
        }
        remove_intent(&state.data_dir, PROTECTED_INTENT_DIR, &intent_tail_value)
    });
    if let Err(error) = result {
        return classify(error);
    }
    (
        StatusCode::OK,
        Json(json!({
            "op": op.as_str(),
            "sequence": plan.sequence,
            "lifecycle_state": artifacts.step.state,
            "lifecycle_transition": artifacts.step.transition,
            "lifecycle_receipt": artifacts.step.receipt,
            "operation_log": artifacts.operation_log,
            "autonomous_system_chain": artifacts.chain,
            "nonclaims": {"runtime_effect":false,"network_effect":false,"membership":false,"writer":false,"settlement":false,"constitution_change":false,"profile_set_change":false}
        })),
    )
}

/// GET /v1/hypervisor/autonomous-systems/:id/transitions/:op
pub(crate) async fn handle_get_transition(
    AxumPath((key, op_name)): AxumPath<(String, String)>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_lifecycle_source_key_invalid",
            "id must be canonical",
        ));
    }
    let Some(op) = ProtectedTransitionOp::parse(&op_name) else {
        return classify(verr(
            "system_lifecycle_operation_not_found",
            format!("'{op_name}' is not a generic protected transition"),
        ));
    };
    match with_source_locks(|| {
        let system_id = system_id_for_key(&state.data_dir, &key)?;
        let source = load_protected_source(&state.data_dir, &system_id)?;
        let committed: Vec<Value> = source
            .operation_log
            .get("entries")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|entry| {
                        entry.get("operation_name").and_then(Value::as_str)
                            == Some(op.as_str())
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Ok::<_, VErr>(json!({
            "op": op.as_str(),
            "eligible_now": {
                "predecessor_status": source
                    .chain_head
                    .get("status")
                    .cloned()
                    .unwrap_or(Value::Null),
                "admits": source
                    .chain_head
                    .get("status")
                    .and_then(Value::as_str)
                    .and_then(
                        ioi_types::app::system_lifecycle_transitions::ProtectedLifecycleStatus::parse,
                    )
                    .map(|status| op.admits_predecessor(status))
                    .unwrap_or(false),
            },
            "chain_head": source.chain_head,
            "operation_log_head": source.operation_log["head_entry"],
            "committed_entries": committed,
        }))
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

/// Resolve the durable system_id for a caller-facing `asg_` key through the
/// genesis module's verified admission loader (the family's owning accessor).
pub(crate) fn system_id_for_key(data_dir: &str, key: &str) -> Result<String, VErr> {
    let admission = super::system_genesis_routes::load_verified_admission_by_key(data_dir, key)?
        .ok_or_else(|| {
            verr(
                "system_lifecycle_not_found",
                "no admitted genesis exists for this id",
            )
        })?;
    required(&admission.record, "/authorized_genesis/system_id")
        .or_else(|_| required(&admission.record, "/system_id"))
}

static PROTECTED_REPLAY_CURSOR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn verify_protected_intent_coordinates(tail_value: &str, intent: &Value) -> Result<(), VErr> {
    if intent.get("schema_version").and_then(Value::as_str)
        != Some("ioi.hypervisor.protected-transition-intent.v1")
    {
        return Err(verr(
            "system_lifecycle_intent_invalid",
            "intent schema is not the protected-transition intent",
        ));
    }
    let op_name = required(intent, "/op")?;
    if ProtectedTransitionOp::parse(&op_name).is_none() {
        return Err(verr(
            "system_lifecycle_intent_invalid",
            "intent op is outside the generic protected family",
        ));
    }
    let request_hash = required(intent, "/governed_authority/request_hash")?;
    if tail_value != tail("asptx_", &request_hash)? {
        return Err(verr(
            "system_lifecycle_intent_invalid",
            "intent tail does not bind its sealed request hash",
        ));
    }
    Ok(())
}

/// Load the exact chain revision a plan compiled against, by root.
fn load_chain_by_root(data_dir: &str, chain_root: &str) -> Result<Value, VErr> {
    record_by_root(data_dir, CHAIN_DIR, "asc_", chain_root, "predecessor chain revision")
}

/// Reconstruct the durable truth exactly as the sealed plan compiled it:
/// the predecessor chain revision by its committed root, the log that
/// revision binds, and the predecessor step that log binds. Append-only
/// content addressing makes this reconstruction possible even after the
/// head has moved past this transition.
fn source_at_plan(
    data_dir: &str,
    plan: &CompiledProtectedTransitionPlan,
) -> Result<ProtectedTransitionSource, VErr> {
    let chain_root = required(&plan.authority_effect, "/predecessor_chain_head_root")?;
    let chain_head = load_chain_by_root(data_dir, &chain_root)?;
    let operation_log = load_log_for_chain(data_dir, &chain_head)?;
    let previous_step = load_previous_step(data_dir, &operation_log)?;
    let system_id = required(&plan.authority_effect, "/system_id")?;
    let activation_effect = load_activation_effect(data_dir, &system_id)?;
    Ok(ProtectedTransitionSource {
        activation_effect,
        previous_step,
        chain_head,
        operation_log,
    })
}

async fn replay_one_protected(data_dir: &str, tail_value: &str, intent: &Value) -> Result<(), VErr> {
    verify_intent_seal(intent)?;
    verify_protected_intent_coordinates(tail_value, intent)?;
    let plan: CompiledProtectedTransitionPlan =
        serde_json::from_value(intent["compiled_plan"].clone()).map_err(|error| {
            verr("system_lifecycle_intent_invalid", error.to_string())
        })?;
    let op = plan.op;
    let source = source_at_plan(data_dir, &plan)?;
    let recompiled = compile_from_source(op, &source)?;
    if recompiled != plan {
        return Err(verr(
            "system_lifecycle_source_conflict",
            "replay plan does not reconstruct byte-exactly",
        ));
    }
    let mut evidence = evidence_from_intent(&intent["governed_authority"])?;
    let governing = required(&source.activation_effect, "/source_governing_authority_ref")?;
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
            "sealed authority or wallet coordinates do not reconstruct",
        ));
    }
    let existing =
        super::system_activation_routes::recover_wallet_consumption(
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
                        remove_intent(data_dir, PROTECTED_INTENT_DIR, tail_value)?;
                    }
                    return Err(verr(
                        "system_lifecycle_wallet_consumption_refused",
                        message,
                    ));
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
                    return Err(verr(
                        "system_lifecycle_wallet_consumption_invalid",
                        message,
                    ))
                }
            }
        }
    };
    let wallet_value = validate_wallet_receipt(&mut evidence, &wallet_receipt)?;
    let timestamp = ms_to_timestamp(wallet_receipt.consumed_at_ms)?;
    let tuple = decision_tuple(&evidence)?;
    let artifacts = build_protected_artifacts(&plan, &source, &tuple, &timestamp)?;
    with_source_locks(|| {
        let current = load_local(data_dir, PROTECTED_INTENT_DIR, tail_value)?.ok_or_else(|| {
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
        persist_protected_graph(data_dir, &artifacts, &evidence, &wallet_value)?;
        remove_intent(data_dir, PROTECTED_INTENT_DIR, tail_value)
    })
}

fn scan_protected_intents(data_dir: &str) -> Result<Vec<(String, Result<Value, VErr>)>, VErr> {
    // Intents are local-durable pre-admission records: read them through the
    // raw pinned reader, never through the Agentgres exact-proof loader.
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, PROTECTED_INTENT_DIR)
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
                verify_protected_intent_coordinates(&tail_value, &value)?;
                Ok(value)
            })();
            (tail_value, checked)
        })
        .collect())
}

/// Refuse a new lifecycle mutation for `key` while any protected intent for
/// it is still pending; bootstrap pendency is checked by the caller through
/// the activation module's own choke point.
pub(crate) fn ensure_no_pending_protected_intent(
    data_dir: &str,
    key: &str,
) -> Result<(), VErr> {
    for (_tail, intent) in scan_protected_intents(data_dir)? {
        let intent = intent?;
        if intent.get("source_record_tail").and_then(Value::as_str) == Some(key) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                "a protected transition intent is still pending",
            ));
        }
    }
    Ok(())
}

/// Boot/periodic replay driver: converge pending protected intents, keeping
/// poisoned ones retained with their reasons.
pub(crate) async fn complete_protected_transition_intents(data_dir: &str, max: usize) {
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let entries = match scan_protected_intents(data_dir) {
        Ok(entries) => entries,
        Err((_, message)) => {
            eprintln!("ProtectedTransition replay scan failed ({message})");
            return;
        }
    };
    let start = PROTECTED_REPLAY_CURSOR
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    for (offset, (tail_value, result)) in entries.iter().enumerate().take(max) {
        let _ = offset;
        let index = (start + offset) % entries.len().max(1);
        let (tail_value, result) = &entries[index];
        let intent = match result {
            Ok(intent) => intent,
            Err((_, message)) => {
                eprintln!(
                    "ProtectedTransition poisoned intent '{tail_value}' retained ({message})"
                );
                continue;
            }
        };
        if let Err((_, message)) = replay_one_protected(data_dir, tail_value, intent).await {
            eprintln!(
                "ProtectedTransition intent '{tail_value}' retained/incomplete ({message})"
            );
        }
        let _ = tail_value;
    }
}
