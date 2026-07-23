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
use serde_json::{json, Value};

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use ioi_services::wallet_network::ApprovalGrantConsumptionReceipt;

use super::governed_authority::{self as governed, AuthorityPolicyContext, Governance};
use super::system_activation_routes::{
    canonical_hash_str, canonical_system_key, classify, contains_sensitive_key, enumerate_family,
    evidence_from_intent, evidence_intent_value, forced_fault, intent_seal, jcs_hash, load_local,
    load_required_exact, ms_to_timestamp, persist_local, prepare_node_evidence_for, remove_intent,
    required_string, tail, validate_contract, validate_wallet_receipt, verify_intent_seal, verr,
    with_source_locks, NodeAdmissionEvidence, ACTIVE_SET_DIR, AUTHORITY,
    AUTHORITY_CONSUMPTION_DIR, AUTHORITY_EVIDENCE_DIR, CHAIN_DIR, DECISION_DIR,
    MAX_REQUEST_BYTES, OPERATION_LOG_DIR, PROPOSAL_DIR, SYSTEM_ACTIVATION_GATE, TRANSITION_DIR,
};
use super::system_protected_transition_routes::{
    continue_log_with_entry, ensure_no_pending_protected_intent, load_activation_effect,
    load_chain_head, load_log_for_chain, load_previous_step, record_by_root, system_id_for_key,
    DecisionAuthorityTuple, LIFECYCLE_STATE_DIR,
};
use super::DaemonState;

const CHAIN_ROOT_DOMAIN: &str = "ioi.autonomous-system-chain-jcs-sha256.v1";
const AMENDMENT_PROPOSAL_HASH_DOMAIN: &str =
    "ioi.autonomous-system-amendment-execution-proposal-jcs-sha256.v1";
const AMENDMENT_DECISION_HASH_DOMAIN: &str =
    "ioi.autonomous-system-amendment-execution-decision-jcs-sha256.v1";
const LIFECYCLE_TRANSITION_HASH_DOMAIN: &str =
    "ioi.autonomous-system-lifecycle-transition-jcs-sha256.v1";
const LIFECYCLE_RECEIPT_HASH_DOMAIN: &str =
    "ioi.lifecycle-transition-receipt-artifact-jcs-sha256.v1";
const AMENDMENT_PROPOSAL_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-amendment-execution-proposal/v1";
const AMENDMENT_DECISION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-amendment-execution-decision/v1";
const AMENDMENT_DECLARATION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-constitution-amendment/v1";
const CONSTITUTION_CONTRACT: &str = "schema://ioi/foundations/autonomous-system-constitution/v1";
const ACTIVE_PROFILE_SET_V2_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-active-profile-set/v2";
const LIFECYCLE_STATE_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-lifecycle-state/v1";
const LIFECYCLE_RECEIPT_CONTRACT: &str =
    "schema://ioi/foundations/lifecycle-transition-receipt/v1";
const SYSTEM_CHAIN_CONTRACT: &str = "schema://ioi/foundations/autonomous-system-chain/v1";

/// Sealed amendment intents (`asamx_` prefix).
pub(crate) const AMENDMENT_INTENT_DIR: &str = "autonomous-system-amendment-intents";
/// Amendment receipts (LifecycleTransitionReceipt family, `asamr_` prefix).
pub(crate) const AMENDMENT_RECEIPT_DIR: &str = "autonomous-system-amendment-receipts";
/// Retained constitution-amendment declarations (`asca_` prefix).
pub(crate) const AMENDMENT_DECLARATION_DIR: &str = "autonomous-system-constitution-amendments";
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
    if let Some(minted) =
        load_required_exact(data_dir, CONSTITUTION_DIR, &tail("ascn_", constitution_root)?)?
    {
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
    let bundle_root = ioi_types::app::system_amendment_execution::constitution_candidate_root(
        &bundle,
    )
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
    successor_constitution: &Value,
) -> Result<CompiledAmendmentExecutionPlan, VErr> {
    // These two bodies are CALLER-supplied: a contract violation here is a
    // bad request, not a server fault, so it must not classify as a 500 the
    // way a server-built artifact legitimately does.
    fn caller_input((_, message): VErr) -> VErr {
        verr("system_lifecycle_request_invalid", message)
    }
    validate_contract(AMENDMENT_DECLARATION_CONTRACT, amendment, "amendment declaration")
        .map_err(caller_input)?;
    validate_contract(
        CONSTITUTION_CONTRACT,
        successor_constitution,
        "successor constitution",
    )
    .map_err(caller_input)?;
    let chain_head_root = required(&source.chain_head, "/chain_root")?;
    let chain_constitution_root = required(&source.chain_head, "/constitution_root")?;
    compile_amendment_execution_plan(
        &source.activation_effect,
        &source.previous_step,
        &chain_head_root,
        &chain_constitution_root,
        amendment,
        &source.predecessor_constitution,
        successor_constitution,
        &source.predecessor_profile_set,
    )
    .map_err(|error| verr("system_lifecycle_plan_invalid", error))
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
    pub successor_constitution: Value,
    pub successor_profile_set: Value,
    pub operation_log: Value,
    pub chain: Value,
}

/// Build the complete amendment step, validating every artifact whose
/// registered contract can express it. The lifecycle-transition.v1 and
/// lifecycle-transition-receipt.v1 registered enums do not yet admit the
/// `amend_constitution` op (registry evolution pending); those two
/// artifacts mirror the protected shapes truthfully and are bound by their
/// content-addressed roots instead of contract validation.
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
    let predecessor_constitution_ref =
        required(&plan.amendment, "/predecessor_constitution_ref")?;
    let predecessor_constitution_root = required(effect, "/predecessor_constitution_root")?;
    let successor_constitution_ref =
        required(&plan.successor_constitution, "/constitution_id")?;
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
        receipt_root_seed.strip_prefix("sha256:").expect("hash prefix")
    );

    let mut state = plan.semantic_state.clone();
    state["transition_ref"] = json!(transition_ref);
    state["transition_receipt_ref"] = json!(receipt_ref);
    state["created_at"] = json!(timestamp);

    // TRUTHFUL transition shape mirroring the protected builder; the
    // registered lifecycle-transition.v1 transition_kind enum does not yet
    // carry `amend_constitution`, so this artifact is bound by its
    // content-addressed root (registry evolution note, not a fork).
    let transition = json!({
        "schema_version": "ioi.lifecycle-transition.v1",
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
    let transition_root = artifact_root_with(LIFECYCLE_TRANSITION_HASH_DOMAIN, &transition)?;

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
    // TRUTHFUL receipt mirroring the protected lean receipt; the registered
    // lifecycle-transition-receipt.v1 op enum and lifecycle-scope pattern do
    // not yet admit `amend_constitution`, so the artifact is bound by its
    // content-addressed root. `assurance_posture` keeps the registered
    // protected value — the enum offers no amendment-specific member.
    let receipt = json!({
        "schema_version": "ioi.lifecycle-transition-receipt.v1",
        "receipt_id": receipt_ref,
        "receipt_ref": receipt_ref,
        "receipt_type": "lifecycle_transition",
        "receipt_profile_ref": LIFECYCLE_RECEIPT_CONTRACT,
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
        "wallet_grant_consumption_root": authority.effect_hash,
        "wallet_grant_consumption_evidence_ref":
            authority.wallet_grant_consumption_evidence_ref,
        "primitive_capabilities": [], "artifact_refs": [], "evidence_bundle_refs": [],
        "verification_ref": Value::Null, "acceptance_ref": Value::Null,
        "claim_scope_ref": Value::Null, "run_id": Value::Null, "task_id": Value::Null,
        "adjudication_ref": Value::Null, "settlement_ref": Value::Null,
        "signature": Value::Null, "public_commitment_ref": Value::Null,
        "assurance_posture": "protected_lifecycle_committed",
        "assurance_note": "protected constitutional amendment committed over the live chain; the constitution and active profile set swap to the successor revision; operational status is unchanged and no membership, runtime, network, or settlement effect exists",
        "timestamp": timestamp, "outcome": "ok", "at": timestamp,
    });
    let receipt_root = artifact_root_with(LIFECYCLE_RECEIPT_HASH_DOMAIN, &receipt)?;

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
        "successor_constitution",
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
    for key in ["amendment", "successor_constitution"] {
        if !object.get(key).is_some_and(Value::is_object) {
            return Err(verr(
                "system_lifecycle_request_invalid",
                format!("'{key}' must be one JSON object"),
            ));
        }
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
    let constitution_root = ioi_types::app::system_amendment_execution::constitution_candidate_root(
        &artifacts.successor_constitution,
    )
    .map_err(|error| verr("system_lifecycle_artifact_invalid", error))?;
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
        if forced_fault("IOI_TEST_FORCE_SYSTEM_AMENDMENT_AFTER_LOCAL_PERSIST", family) {
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
        if forced_fault("IOI_TEST_FORCE_SYSTEM_AMENDMENT_AFTER_AGENTGRES_ADMIT", family) {
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
    let successor_constitution = body["successor_constitution"].clone();
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let (system_id, source, plan) = match with_source_locks(|| {
        super::system_activation_routes::ensure_no_pending_intent(&state.data_dir, &key)?;
        ensure_no_pending_protected_intent(&state.data_dir, &key)?;
        ensure_no_pending_amendment_intent(&state.data_dir, &key)?;
        let (system_id, source) = load_amendment_source(&state.data_dir, &key)?;
        check_expected_roots(&body, &source)?;
        let plan = compile_amendment_from_source(&source, &amendment, &successor_constitution)?;
        Ok::<_, VErr>((system_id, source, plan))
    }) {
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
    let intent_tail_value = match tail("asamx_", &evidence.authorized.evidence.request_hash) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let plan_value = match plan_to_value(&plan) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let sealed = match with_source_locks(|| {
        // Revalidate the entire durable truth under the lock, then seal.
        let (_, fresh) = load_amendment_source(&state.data_dir, &key)?;
        check_expected_roots(&body, &fresh)?;
        let recompiled =
            compile_amendment_from_source(&fresh, &amendment, &successor_constitution)?;
        if plan_to_value(&recompiled)? != plan_value {
            return Err(verr(
                "system_lifecycle_head_conflict",
                "durable truth changed between authorization and intent sealing",
            ));
        }
        let intent = intent_seal(json!({
            "schema_version": "ioi.hypervisor.constitution-amendment-intent.v1",
            "source_record_tail": key,
            "op": AMENDMENT_OP,
            "request_body": body,
            "compiled_plan": plan_value,
            "governed_authority": evidence_intent_value(&evidence),
            "intent_hash": Value::Null,
        }))?;
        persist_local(
            &state.data_dir,
            AMENDMENT_INTENT_DIR,
            &intent_tail_value,
            &intent,
        )?;
        Ok::<_, VErr>(intent)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    drop(sealed);
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
        let retained: Vec<Value> =
            enumerate_family(&state.data_dir, AMENDMENT_DECLARATION_DIR)?
                .into_iter()
                .filter_map(|(_, declaration)| {
                    (declaration.get("system_id").and_then(Value::as_str)
                        == Some(system_id.as_str()))
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
fn source_at_plan(
    data_dir: &str,
    key: &str,
    sealed_plan: &Value,
) -> Result<AmendmentSource, VErr> {
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

async fn replay_one_amendment(data_dir: &str, tail_value: &str, intent: &Value) -> Result<(), VErr> {
    verify_intent_seal(intent)?;
    verify_amendment_intent_coordinates(tail_value, intent)?;
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
    let plan = compile_amendment_from_source(&source, &amendment, &successor_constitution)?;
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
                        remove_intent(data_dir, AMENDMENT_INTENT_DIR, tail_value)?;
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

/// Refuse a new lifecycle mutation for `key` while any amendment intent for
/// it is still pending; bootstrap and protected pendency are checked by the
/// callers through their own choke points.
pub(crate) fn ensure_no_pending_amendment_intent(data_dir: &str, key: &str) -> Result<(), VErr> {
    for (_tail, intent) in scan_amendment_intents(data_dir)? {
        let intent = intent?;
        if intent.get("source_record_tail").and_then(Value::as_str) == Some(key) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                "a constitutional amendment intent is still pending",
            ));
        }
    }
    Ok(())
}

/// Boot/periodic replay driver: converge pending amendment intents, keeping
/// poisoned ones retained with their reasons.
pub(crate) async fn complete_amendment_intents(data_dir: &str, max: usize) {
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
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
    use ioi_types::app::system_amendment_execution::constitution_candidate_root;

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
    fn amendment_fixture() -> (AmendmentSource, Value, Value) {
        let log = fixture("autonomous-system-operation-log-v1/positive-activation-prefix.json");
        let chain = fixture("autonomous-system-chain-v1/positive-active-sequence-two.json");
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
        let predecessor_constitution = constitution(
            chain["constitution_ref"].as_str().unwrap(),
            "1.0.0",
            chain["constitution_root"].as_str().unwrap(),
            "constitution://acme/system-alpha/root-lineage",
            &system_id,
        );
        let mut successor_constitution = constitution(
            "constitution://acme/system-alpha/v2",
            "1.1.0",
            "",
            chain["constitution_ref"].as_str().unwrap(),
            &system_id,
        );
        successor_constitution["normative_constraints"]["permitted_ontology_action_contract_refs"] =
            json!(["ontology-action://acme/added/v1"]);
        let successor_root = constitution_candidate_root(&successor_constitution).unwrap();
        successor_constitution["constitution_root"] = json!(successor_root);
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
            "decision_ref": Value::Null,
            "status": "proposed",
        });
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
            wallet_grant_consumption_evidence_ref: format!(
                "system-lifecycle-authority-consumption://aslac_{}",
                "57".repeat(32)
            ),
        }
    }

    const TS: &str = "2026-07-22T12:00:00.000Z";

    fn built() -> (CompiledAmendmentExecutionPlan, AmendmentSource, AmendmentStepArtifacts) {
        let (source, amendment, successor) = amendment_fixture();
        let plan = compile_amendment_from_source(&source, &amendment, &successor).expect("plan");
        let artifacts =
            build_amendment_artifacts(&plan, &source, &authority_tuple(), TS).expect("artifacts");
        (plan, source, artifacts)
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
        assert_eq!(decision["proposal_root"], json!(artifacts.step.proposal_root));
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
            plan.authority_effect["system_id"].as_str().unwrap().to_owned(),
            artifacts.step.proposal["proposal_ref"].as_str().unwrap().to_owned(),
            artifacts.step.decision["decision_ref"].as_str().unwrap().to_owned(),
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
            plan.authority_effect["chain_ref"].as_str().unwrap().to_owned(),
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
            receipt["assurance_posture"],
            json!("protected_lifecycle_committed"),
        );
    }

    #[test]
    fn log_appends_a_constitution_amendment_entry_with_continuity() {
        let (plan, source, artifacts) = built();
        assert_eq!(plan.sequence, 3);
        let log = &artifacts.operation_log;
        assert_eq!(log["schema_version"], json!("ioi.autonomous-system-operation-log.v2"));
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
        assert_eq!(prior.keys().collect::<Vec<_>>(), next.keys().collect::<Vec<_>>());
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
        assert_eq!(artifacts.successor_constitution, plan.successor_constitution);
    }
}
