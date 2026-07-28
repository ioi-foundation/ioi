//! M2 membership/readiness plane: the root child of stage M2.
//!
//! Desired topology, observed node membership, and the strict compare-and-swap
//! membership transition log are distinct durable owners over the shared
//! governed authority flow. The desired record never fabricates observed
//! admission, readiness, role, root, watermark, or catch-up truth; the
//! observed side is rebuilt from durable membership transitions and record
//! revisions only, so a restart loses no projection it cannot reconstruct
//! byte-exactly. Every admission input is resolved from durable server truth,
//! never asserted by the caller (INV-37).

use ioi_types::app::system_membership_transitions::{
    compile_membership_transition_plan, desired_topology_root, membership_record_root,
    membership_set_root, CompiledMembershipTransitionPlan, MembershipIdentityBinding,
    MembershipLogHead, MembershipTransitionDeclaration, MembershipTransitionOp,
    MEMBERSHIP_TRANSITION_CONTRACT, NODE_MEMBERSHIP_CONTRACT,
};
use serde_json::{json, Value};
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;

use super::governed_authority::{self as governed, AuthorityPolicyContext, Governance};
use super::system_activation_routes::{
    canonical_system_key, classify, contains_sensitive_key, evidence_intent_value, forced_fault,
    intent_seal, jcs_hash, load_local, load_required_exact, ms_to_timestamp, persist_local,
    prepare_node_evidence_for, remove_intent, required_string, tail, validate_contract,
    validate_wallet_receipt, verify_intent_seal, verr, with_source_locks, AUTHORITY,
    AUTHORITY_CONSUMPTION_DIR, AUTHORITY_EVIDENCE_DIR, MAX_REQUEST_BYTES, SYSTEM_ACTIVATION_GATE,
};
use super::system_protected_transition_routes::{
    current_governing_authority, decision_tuple, preflight_chain_writer_grant,
    DecisionAuthorityTuple,
};
use super::DaemonState;

type VErr = (String, String);

/// Owner-declared desired topology records (content-addressed, CAS lineage).
pub(crate) const DESIRED_TOPOLOGY_DIR: &str = "autonomous-system-desired-topologies";
/// Observed node membership record revisions (timeless content roots).
pub(crate) const MEMBERSHIP_RECORD_DIR: &str = "autonomous-system-node-memberships";
/// Committed membership compare-and-swap transitions.
pub(crate) const MEMBERSHIP_TRANSITION_DIR: &str = "autonomous-system-membership-transitions";
/// Membership transition receipts.
pub(crate) const MEMBERSHIP_RECEIPT_DIR: &str = "autonomous-system-membership-receipts";
/// One-successor-per-predecessor membership CAS claims.
pub(crate) const MEMBERSHIP_CLAIM_DIR: &str = "autonomous-system-membership-successor-claims";
/// Sealed membership transition intents (local replay registry).
pub(crate) const MEMBERSHIP_INTENT_DIR: &str = "autonomous-system-membership-transition-intents";
/// Daemon-resolved node evidence (readiness attestations, catch-up receipts).
/// The loader is live; the runtime producer is a later M2 leg.
pub(crate) const NODE_EVIDENCE_DIR: &str = "autonomous-system-node-evidence";

const RECEIPT_CONTRACT: &str = "schema://ioi/foundations/receipt-envelope/v1";
const DESIRED_TOPOLOGY_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-desired-topology/v1";
const TRANSITION_ARTIFACT_DOMAIN: &str =
    "ioi.autonomous-system-membership-transition-jcs-sha256.v1";
const RECEIPT_ARTIFACT_DOMAIN: &str = "ioi.autonomous-system-membership-receipt-jcs-sha256.v1";
const DECLARE_DESIRED_TOPOLOGY_OP: &str = "declare_desired_topology";
const DECLARE_DESIRED_TOPOLOGY_SCOPE: &str =
    "scope:autonomous_system.membership.declare_desired_topology";

fn required(value: &Value, pointer: &str) -> Result<String, VErr> {
    required_string(value, pointer).map(str::to_owned)
}

fn ns(system_id: &str) -> Result<&str, VErr> {
    system_id.strip_prefix("system://").ok_or_else(|| {
        verr(
            "system_membership_artifact_invalid",
            "system_id is not canonical",
        )
    })
}

fn artifact_root(domain: &str, artifact: &Value) -> Result<String, VErr> {
    jcs_hash(&json!({"domain":domain,"artifact":artifact}))
}

fn plan_err(error: String) -> VErr {
    verr("system_membership_plan_invalid", error)
}

/// Enumerate one local-only family without requiring Agentgres admission.
fn scan_local_family(data_dir: &str, family: &str) -> Result<Vec<(String, Value)>, VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(verr(
                "system_membership_artifact_unreadable",
                format!("family '{family}' cannot be pinned ({error})"),
            ))
        }
    };
    let mut names = super::durable_fs::enumerate_pinned(&directory).map_err(|error| {
        verr(
            "system_membership_artifact_unreadable",
            format!("family '{family}' cannot be enumerated ({error})"),
        )
    })?;
    names.sort();
    let mut values = Vec::new();
    for name in names {
        let record_tail = name
            .strip_suffix(".json")
            .ok_or_else(|| {
                verr(
                    "system_membership_artifact_unreadable",
                    format!("unexpected entry '{family}/{name}'"),
                )
            })?
            .to_owned();
        let value = load_local(data_dir, family, &record_tail)?.ok_or_else(|| {
            verr(
                "system_membership_artifact_unreadable",
                format!("'{family}/{name}' vanished"),
            )
        })?;
        values.push((record_tail, value));
    }
    Ok(values)
}

/// Enumerate one required-admission family with the local-versus-Agentgres
/// census equality proof. A census mismatch is source incompleteness and the
/// read fails closed instead of projecting partial truth.
fn enumerate_required_censused(data_dir: &str, family: &str) -> Result<Vec<Value>, VErr> {
    let local = super::system_activation_routes::enumerate_family(data_dir, family)?;
    let mut local_values: Vec<Value> = local.into_iter().map(|(_, value)| value).collect();
    let mut substrate =
        super::substrate_store::read_required_all(data_dir, family).map_err(|error| {
            verr(
                "system_membership_source_incomplete",
                format!("Agentgres census for '{family}' failed ({error})"),
            )
        })?;
    let sort_key = |value: &Value| serde_json::to_string(value).unwrap_or_default();
    local_values.sort_by_key(sort_key);
    substrate.sort_by_key(sort_key);
    if local_values != substrate {
        return Err(verr(
            "system_membership_source_incomplete",
            format!("local and Agentgres censuses for '{family}' differ"),
        ));
    }
    Ok(local_values)
}

/// The exact durable truth one membership operation compiles against.
pub(crate) struct MembershipSource {
    pub binding: MembershipIdentityBinding,
    pub desired_topology: Option<Value>,
    pub desired_topology_root: Option<String>,
    pub transitions: Vec<Value>,
    pub records: Vec<Value>,
    pub head: MembershipLogHead,
    pub consumed_role_lease_refs: Vec<String>,
}

/// Pure membership replay over committed transitions and a record loader.
/// This is the restart path: no rebuildable head or projection record is
/// consulted, only immutable durable truth.
pub(crate) fn replay_membership_transitions(
    system_id: &str,
    transitions: &[Value],
    load_record: &dyn Fn(&str) -> Result<Option<Value>, VErr>,
) -> Result<(Vec<Value>, MembershipLogHead, Vec<String>), VErr> {
    let mut ordered: Vec<&Value> = transitions
        .iter()
        .filter(|value| value.get("system_id").and_then(Value::as_str) == Some(system_id))
        .collect();
    ordered.sort_by_key(|value| value.get("sequence").and_then(Value::as_u64).unwrap_or(0));
    let empty_root = membership_set_root(system_id, &[]).map_err(plan_err)?;
    let mut expected_predecessor = empty_root.clone();
    let mut live: Vec<Value> = Vec::new();
    let mut consumed: Vec<String> = Vec::new();
    let mut sequence = 0u64;
    for transition in ordered {
        validate_contract(
            MEMBERSHIP_TRANSITION_CONTRACT,
            transition,
            "committed membership transition",
        )?;
        let this_sequence = transition
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                verr(
                    "system_membership_artifact_invalid",
                    "committed transition lacks its sequence",
                )
            })?;
        if this_sequence != sequence + 1 {
            return Err(verr(
                "system_membership_artifact_mismatch",
                "membership log is not contiguous",
            ));
        }
        if transition
            .get("predecessor_membership_root")
            .and_then(Value::as_str)
            != Some(expected_predecessor.as_str())
        {
            return Err(verr(
                "system_membership_artifact_mismatch",
                "membership log breaks its compare-and-swap chain",
            ));
        }
        let node_id = required(transition, "/node_id")?;
        let record_root = required(transition, "/resulting_record_root")?;
        let record = load_record(&record_root)?.ok_or_else(|| {
            verr(
                "system_membership_artifact_mismatch",
                "committed transition lacks its durable record revision",
            )
        })?;
        if membership_record_root(&record).map_err(plan_err)? != record_root
            || record.get("node_id").and_then(Value::as_str) != Some(node_id.as_str())
        {
            return Err(verr(
                "system_membership_artifact_mismatch",
                "durable record revision does not match its committed transition",
            ));
        }
        live.retain(|held| held.get("node_id").and_then(Value::as_str) != Some(node_id.as_str()));
        if transition.get("op").and_then(Value::as_str) != Some("remove_node") {
            live.push(record);
        }
        let derived = membership_set_root(system_id, &live).map_err(plan_err)?;
        let resulting = required(transition, "/resulting_membership_root")?;
        if derived != resulting {
            return Err(verr(
                "system_membership_artifact_mismatch",
                "replayed membership set does not recompute the committed root",
            ));
        }
        if let Some(lease) = transition
            .pointer("/authority_effect_material/role_lease_ref")
            .and_then(Value::as_str)
        {
            consumed.push(lease.to_owned());
        }
        expected_predecessor = resulting;
        sequence = this_sequence;
    }
    Ok((
        live,
        MembershipLogHead {
            sequence,
            membership_root: expected_predecessor,
        },
        consumed,
    ))
}

/// The one current declared desired topology: the declared record that no
/// successor cites as its predecessor. Two uncited declared records are a
/// fork and fail closed.
fn current_desired_topology(
    records: &[Value],
    system_id: &str,
) -> Result<Option<(Value, String)>, VErr> {
    let mut mine: Vec<(Value, String)> = Vec::new();
    for record in records {
        if record.get("system_id").and_then(Value::as_str) != Some(system_id) {
            continue;
        }
        let root = desired_topology_root(record).map_err(plan_err)?;
        mine.push((record.clone(), root));
    }
    let cited: Vec<String> = mine
        .iter()
        .filter_map(|(record, _)| {
            record
                .get("predecessor_desired_topology_root")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let mut current: Vec<(Value, String)> = mine
        .into_iter()
        .filter(|(record, root)| {
            record.get("status").and_then(Value::as_str) == Some("declared")
                && !cited.contains(root)
        })
        .collect();
    match current.len() {
        0 => Ok(None),
        1 => Ok(current.pop()),
        _ => Err(verr(
            "system_membership_artifact_mismatch",
            "two declared desired topologies both claim currency",
        )),
    }
}

pub(crate) fn load_membership_source(data_dir: &str, key: &str) -> Result<MembershipSource, VErr> {
    let continuity = super::system_continuity_routes::load_continuity_source(data_dir, key)?;
    let chain = &continuity.base.chain_head;
    let status = required(chain, "/status")?;
    if !matches!(
        status.as_str(),
        "active" | "degraded" | "successor_governed"
    ) {
        return Err(verr(
            "system_membership_status_invalid",
            "membership operations require a live System",
        ));
    }
    let system_id = required(chain, "/system_id")?;
    let binding = MembershipIdentityBinding {
        system_id: system_id.clone(),
        genesis_ref: required(chain, "/genesis_ref")?,
        source_governing_authority_ref: current_governing_authority(
            &continuity.base.previous_step,
            chain,
        )?,
        deployment_profile_ref: required(chain, "/deployment_profile_ref")?,
        deployment_profile_root: required(chain, "/deployment_profile_root")?,
        admitted_constitution_root: required(chain, "/constitution_root")?,
        admitted_manifest_root: required(chain, "/admitted_manifest_root")?,
    };
    let desired_records = enumerate_required_censused(data_dir, DESIRED_TOPOLOGY_DIR)?;
    let desired = current_desired_topology(&desired_records, &system_id)?;
    let transitions = enumerate_required_censused(data_dir, MEMBERSHIP_TRANSITION_DIR)?;
    let loader = |record_root: &str| -> Result<Option<Value>, VErr> {
        load_required_exact(
            data_dir,
            MEMBERSHIP_RECORD_DIR,
            &tail("asnm_", record_root)?,
        )
    };
    let (records, head, consumed_role_lease_refs) =
        replay_membership_transitions(&system_id, &transitions, &loader)?;
    let (desired_topology, desired_root) = match desired {
        Some((record, root)) => (Some(record), Some(root)),
        None => (None, None),
    };
    Ok(MembershipSource {
        binding,
        desired_topology,
        desired_topology_root: desired_root,
        transitions,
        records,
        head,
        consumed_role_lease_refs,
    })
}

/// Resolve one node-evidence record by its declared ref from durable daemon
/// truth. The caller only ever names the ref; the body is resolved here.
fn load_node_evidence(data_dir: &str, ref_field: &str, reference: &str) -> Result<Value, VErr> {
    let mut matches: Vec<Value> = scan_local_family(data_dir, NODE_EVIDENCE_DIR)?
        .into_iter()
        .filter_map(|(_, value)| {
            (value.get(ref_field).and_then(Value::as_str) == Some(reference)).then_some(value)
        })
        .collect();
    match matches.len() {
        0 => Err(verr(
            "system_membership_evidence_not_found",
            format!("'{reference}' is not resolvable from durable node evidence"),
        )),
        1 => Ok(matches.pop().expect("one evidence record")),
        _ => Err(verr(
            "system_membership_artifact_mismatch",
            format!("'{reference}' resolves to more than one durable evidence record"),
        )),
    }
}

pub(crate) fn compile_from_source(
    op: MembershipTransitionOp,
    source: &MembershipSource,
    declaration: &MembershipTransitionDeclaration,
    trusted_readiness_attestation: Option<&Value>,
    trusted_catchup_receipt: Option<&Value>,
) -> Result<CompiledMembershipTransitionPlan, VErr> {
    let desired = source.desired_topology.as_ref().ok_or_else(|| {
        verr(
            "system_membership_desired_topology_required",
            "no declared desired topology admits membership operations",
        )
    })?;
    compile_membership_transition_plan(
        op,
        &source.binding,
        desired,
        &source.records,
        &source.head,
        &source.consumed_role_lease_refs,
        declaration,
        trusted_readiness_attestation,
        trusted_catchup_receipt,
    )
    .map_err(plan_err)
}

/// One fully built membership step, every artifact contract-validated inside
/// the build itself.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MembershipStepArtifacts {
    pub record: Value,
    pub transition: Value,
    pub transition_root: String,
    pub receipt: Value,
    pub receipt_root: String,
    pub claim: Value,
    pub claim_tail: String,
}

/// Build the committed membership graph without performing I/O. The stamped
/// record revision keeps the exact timeless content root the compiler derived.
pub(crate) fn build_membership_artifacts(
    plan: &CompiledMembershipTransitionPlan,
    source: &MembershipSource,
    authority: &DecisionAuthorityTuple,
    timestamp: &str,
    observation_expires_at: &str,
) -> Result<MembershipStepArtifacts, VErr> {
    let system_id = required(&plan.authority_effect, "/system_id")?;
    let namespace = ns(&system_id)?;
    let mut record = plan.resulting_record.clone();
    if let Some(assignments) = record
        .get_mut("role_assignments")
        .and_then(Value::as_array_mut)
    {
        for assignment in assignments {
            if assignment.get("valid_from") == Some(&Value::Null) {
                assignment["valid_from"] = json!(timestamp);
            }
        }
    }
    if plan.op == MembershipTransitionOp::AdvanceCatchup {
        record["synchronization"]["verified_at"] = json!(timestamp);
    }
    record["observation"]["last_observed_at"] = json!(timestamp);
    record["observation"]["observation_expires_at"] = json!(observation_expires_at);
    if membership_record_root(&record).map_err(plan_err)? != plan.resulting_record_root {
        return Err(verr(
            "system_membership_artifact_mismatch",
            "stamped record revision does not keep its timeless content root",
        ));
    }
    validate_contract(NODE_MEMBERSHIP_CONTRACT, &record, "membership record")?;

    let transition_ref = format!(
        "membership-transition://{namespace}/sequence/{}",
        plan.sequence
    );
    let receipt_ref = format!(
        "receipt://{namespace}/membership/sequence/{}",
        plan.sequence
    );
    let mut authority_effect_material = plan.authority_effect.clone();
    authority_effect_material["operation_commitment"] = Value::Null;
    let transition = json!({
        "schema_version": "ioi.autonomous-system-membership-transition.v1",
        "membership_transition_id": transition_ref,
        "system_id": system_id,
        "op": plan.op.as_str(),
        "sequence": plan.sequence,
        "node_membership_ref": plan.node_membership_ref,
        "node_id": plan.node_id,
        "predecessor_membership_root": plan.predecessor_membership_root,
        "resulting_membership_root": plan.resulting_membership_root,
        "predecessor_record_root": plan.predecessor_record_root,
        "resulting_record_root": plan.resulting_record_root,
        "operation_commitment": plan.authority_effect["operation_commitment"],
        "authority_effect_material": authority_effect_material,
        "evidence_refs": plan.authority_effect["evidence_refs"],
        "authority_grant_refs": [authority.authority_grant_ref],
        "receipt_refs": [receipt_ref],
        "status": "committed",
    });
    validate_contract(
        MEMBERSHIP_TRANSITION_CONTRACT,
        &transition,
        "membership transition",
    )?;
    let transition_root = artifact_root(TRANSITION_ARTIFACT_DOMAIN, &transition)?;

    let receipt = json!({
        "receipt_id": receipt_ref,
        "receipt_type": "membership_transition",
        "receipt_profile_ref": RECEIPT_CONTRACT,
        "attested_boundary_fact_refs": [
            system_id,
            plan.node_membership_ref,
            transition_ref,
            authority.authority_evidence_ref,
        ],
        "claim_scope_ref": "policy://autonomous-system/membership",
        "run_id": Value::Null,
        "task_id": Value::Null,
        "actor_id": "runtime://hypervisor-runtime",
        "authority_grant_id": authority.authority_grant_ref,
        "primitive_capabilities": [],
        "authority_scopes": [plan.op.required_scope()],
        "artifact_refs": [
            format!("artifact://membership-transition/{transition_root}"),
            format!("artifact://node-membership/{}", plan.resulting_record_root),
        ],
        "evidence_bundle_refs": [],
        "verification_ref": Value::Null,
        "acceptance_ref": Value::Null,
        "adjudication_ref": Value::Null,
        "settlement_ref": Value::Null,
        "timestamp": timestamp,
        "signature": Value::Null,
        "public_commitment_ref": Value::Null,
        "input_hash": authority.input_hash,
        "output_hash": plan.resulting_membership_root,
        "policy_hash": authority.policy_hash,
    });
    validate_contract(RECEIPT_CONTRACT, &receipt, "membership receipt")?;
    let receipt_root = artifact_root(RECEIPT_ARTIFACT_DOMAIN, &receipt)?;

    let claim_tail = tail("asmsc_", &plan.predecessor_membership_root)?;
    let claim = json!({
        "schema_version": "ioi.hypervisor.membership-successor-claim.v1",
        "claim_ref": format!(
            "membership-successor-claim://{}",
            plan.predecessor_membership_root
        ),
        "system_id": system_id,
        "sequence": plan.sequence,
        "predecessor_membership_root": plan.predecessor_membership_root,
        "resulting_membership_root": plan.resulting_membership_root,
        "transition_ref": transition_ref,
        "op": plan.op.as_str(),
        "committed_at": timestamp,
    });
    let _ = source; // the source is bound by the compile step; retained for parity
    Ok(MembershipStepArtifacts {
        record,
        transition,
        transition_root,
        receipt,
        receipt_root,
        claim,
        claim_tail,
    })
}

fn persist_membership_graph(
    data_dir: &str,
    plan: &CompiledMembershipTransitionPlan,
    artifacts: &MembershipStepArtifacts,
    evidence: &super::system_activation_routes::NodeAdmissionEvidence,
    wallet_consumption: &Value,
) -> Result<(), VErr> {
    // One successor per predecessor membership root: the expected-absent
    // Agentgres admission is the cross-process CAS boundary.
    persist_local(
        data_dir,
        MEMBERSHIP_CLAIM_DIR,
        &artifacts.claim_tail,
        &artifacts.claim,
    )
    .map_err(|(code, message)| {
        if code == "system_lifecycle_conflict" {
            verr("system_membership_head_conflict", message)
        } else {
            (code, message)
        }
    })?;
    super::substrate_store::admit_required(
        data_dir,
        MEMBERSHIP_CLAIM_DIR,
        &artifacts.claim_tail,
        &artifacts.claim,
    )
    .map_err(|error| {
        let code = if error.kind() == std::io::ErrorKind::AlreadyExists {
            "system_membership_head_conflict"
        } else {
            "system_membership_agentgres_admission_failed"
        };
        verr(code, format!("durable membership claim failed ({error})"))
    })?;
    if load_required_exact(data_dir, MEMBERSHIP_CLAIM_DIR, &artifacts.claim_tail)?.as_ref()
        != Some(&artifacts.claim)
    {
        return Err(verr(
            "system_membership_head_conflict",
            "durable membership predecessor claim belongs to a different successor",
        ));
    }
    let consumption: ioi_services::wallet_network::ApprovalGrantConsumptionReceipt =
        serde_json::from_value(wallet_consumption.clone()).map_err(|error| {
            verr(
                "system_lifecycle_wallet_consumption_invalid",
                error.to_string(),
            )
        })?;
    let records: Vec<(&str, String, &Value)> = vec![
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
            MEMBERSHIP_RECORD_DIR,
            tail("asnm_", &plan.resulting_record_root)?,
            &artifacts.record,
        ),
        (
            MEMBERSHIP_TRANSITION_DIR,
            tail("asmt_", &artifacts.transition_root)?,
            &artifacts.transition,
        ),
        (
            MEMBERSHIP_RECEIPT_DIR,
            tail("asmr_", &artifacts.receipt_root)?,
            &artifacts.receipt,
        ),
    ];
    for (family, record_tail, value) in records {
        persist_local(data_dir, family, &record_tail, value)?;
        super::substrate_store::admit_required(data_dir, family, &record_tail, value).map_err(
            |error| {
                verr(
                    "system_membership_agentgres_admission_failed",
                    format!("required admission for '{family}/{record_tail}' failed ({error})"),
                )
            },
        )?;
        let loaded = load_required_exact(data_dir, family, &record_tail)?.ok_or_else(|| {
            verr(
                "system_membership_persist_failed",
                "membership artifact did not converge",
            )
        })?;
        if loaded != *value {
            return Err(verr(
                "system_membership_persist_failed",
                "membership artifact diverged",
            ));
        }
    }
    Ok(())
}

fn declaration_from_body(body: &Value) -> Result<MembershipTransitionDeclaration, VErr> {
    let mut value = serde_json::Map::new();
    for key in DECLARATION_FIELDS {
        if let Some(field) = body.get(*key) {
            value.insert((*key).to_owned(), field.clone());
        }
    }
    serde_json::from_value(Value::Object(value))
        .map_err(|error| verr("system_membership_request_invalid", error.to_string()))
}

const DECLARATION_FIELDS: &[&str] = &[
    "node_id",
    "expected_membership_root",
    "evidence_refs",
    "node_owner_ref",
    "roles",
    "membership_lease_ref",
    "node_attestation_refs",
    "declared_readiness",
    "readiness_attestation_ref",
    "catchup_operation_offset",
    "catchup_receipt_ref",
    "target_role",
    "role_lease_ref",
];

fn validate_request(body: &Value) -> Result<(), VErr> {
    let encoded = serde_json::to_vec(body)
        .map_err(|error| verr("system_membership_request_invalid", error.to_string()))?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(verr(
            "system_membership_request_oversize",
            "request exceeds 512 KiB",
        ));
    }
    if contains_sensitive_key(body) {
        return Err(verr(
            "system_membership_sensitive_field_rejected",
            "secret-bearing keys are forbidden recursively",
        ));
    }
    let object = body.as_object().ok_or_else(|| {
        verr(
            "system_membership_request_invalid",
            "request must be an object",
        )
    })?;
    if let Some(key) = object.keys().find(|key| {
        !DECLARATION_FIELDS.contains(&key.as_str()) && key.as_str() != "wallet_approval_grant"
    }) {
        return Err(verr(
            "system_membership_request_field_unknown",
            format!("undeclared request field '{key}' is forbidden"),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_no_pending_membership_intent(data_dir: &str, key: &str) -> Result<(), VErr> {
    for (_tail, intent) in scan_local_family(data_dir, MEMBERSHIP_INTENT_DIR)? {
        verify_intent_seal(&intent)?;
        if intent.get("source_record_tail").and_then(Value::as_str) == Some(key) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                "a membership transition is pending convergence",
            ));
        }
    }
    Ok(())
}

fn ensure_no_cross_plane_pending(data_dir: &str, key: &str) -> Result<(), VErr> {
    super::system_activation_routes::ensure_no_pending_intent(data_dir, key)?;
    super::system_protected_transition_routes::ensure_no_pending_protected_intent(data_dir, key)?;
    super::system_amendment_routes::ensure_no_pending_amendment_intent(data_dir, key)?;
    super::system_continuity_routes::ensure_no_pending_migration_ack(data_dir, key)?;
    ensure_no_pending_membership_intent(data_dir, key)
}

fn observation_expiry(
    source: &MembershipSource,
    consumed_at_ms: u64,
) -> Result<(String, String), VErr> {
    let ttl = source
        .desired_topology
        .as_ref()
        .and_then(|value| value.get("observation_ttl_ms"))
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            verr(
                "system_membership_desired_topology_required",
                "declared desired topology lacks its observation ttl",
            )
        })?;
    let timestamp = ms_to_timestamp(consumed_at_ms)?;
    let expires = ms_to_timestamp(consumed_at_ms.checked_add(ttl).ok_or_else(|| {
        verr(
            "system_membership_request_invalid",
            "observation ttl overflow",
        )
    })?)?;
    Ok((timestamp, expires))
}

fn resolve_trusted_inputs(
    data_dir: &str,
    op: MembershipTransitionOp,
    declaration: &MembershipTransitionDeclaration,
) -> Result<(Option<Value>, Option<Value>), VErr> {
    let attestation = match (op, declaration.readiness_attestation_ref.as_deref()) {
        (MembershipTransitionOp::AttestReadiness, Some(reference)) => {
            Some(load_node_evidence(data_dir, "attestation_ref", reference)?)
        }
        _ => None,
    };
    let receipt = match (op, declaration.catchup_receipt_ref.as_deref()) {
        (MembershipTransitionOp::AdvanceCatchup, Some(reference)) => {
            Some(load_node_evidence(data_dir, "receipt_ref", reference)?)
        }
        _ => None,
    };
    Ok((attestation, receipt))
}

/// POST /v1/hypervisor/autonomous-systems/:id/membership/:op
pub(crate) async fn handle_transition(
    AxumPath((key, op_name)): AxumPath<(String, String)>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_membership_source_key_invalid",
            "id is not canonical",
        ));
    }
    let Some(op) = MembershipTransitionOp::parse(&op_name) else {
        return classify(verr(
            "system_membership_operation_not_found",
            "unknown membership op",
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
        ensure_no_cross_plane_pending(&state.data_dir, &key)?;
        load_membership_source(&state.data_dir, &key)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let (attestation, catchup_receipt) =
        match resolve_trusted_inputs(&state.data_dir, op, &declaration) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    let plan = match compile_from_source(
        op,
        &source,
        &declaration,
        attestation.as_ref(),
        catchup_receipt.as_ref(),
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let system_id = required(&plan.authority_effect, "/system_id").unwrap_or_default();
    let genesis_ref = required(&plan.authority_effect, "/genesis_ref").unwrap_or_default();
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
    let mut evidence = match prepare_node_evidence_for(
        &plan.authority_effect,
        op.as_str(),
        plan.sequence,
        op.required_scope(),
        &governing,
        &plan.resulting_membership_root,
        authorized,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if let Err(error) = preflight_chain_writer_grant(&evidence.wallet_params).await {
        return classify(error);
    }
    let intent_tail = match tail("asmti_", &evidence.authorized.evidence.request_hash) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent = match with_source_locks(|| {
        let fresh = load_membership_source(&state.data_dir, &key)?;
        let recompiled = compile_from_source(
            op,
            &fresh,
            &declaration,
            attestation.as_ref(),
            catchup_receipt.as_ref(),
        )?;
        if recompiled != plan {
            return Err(verr(
                "system_membership_head_conflict",
                "durable truth changed between authorization and intent sealing",
            ));
        }
        let intent = intent_seal(json!({
            "schema_version": "ioi.hypervisor.membership-transition-intent.v1",
            "source_record_tail": key,
            "op": op.as_str(),
            "request_body": body,
            "compiled_plan": plan,
            "governed_authority": evidence_intent_value(&evidence),
            "intent_hash": Value::Null,
        }))?;
        persist_local(
            &state.data_dir,
            MEMBERSHIP_INTENT_DIR,
            &intent_tail,
            &intent,
        )?;
        Ok::<_, VErr>(intent)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if forced_fault("IOI_TEST_FORCE_SYSTEM_MEMBERSHIP_AFTER_INTENT", op.as_str()) {
        return classify(verr(
            "system_lifecycle_pending_convergence",
            "test-forced interruption after durable membership intent",
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
                    remove_intent(&state.data_dir, MEMBERSHIP_INTENT_DIR, &intent_tail)
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
        "IOI_TEST_FORCE_SYSTEM_MEMBERSHIP_AFTER_WALLET_CONSUMPTION",
        op.as_str(),
    ) {
        return classify(verr(
            "system_lifecycle_pending_convergence",
            "test-forced interruption after exact wallet consumption",
        ));
    }
    let (timestamp, observation_expires_at) =
        match observation_expiry(&source, wallet_receipt.consumed_at_ms) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    let tuple = match decision_tuple(&evidence) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let artifacts = match build_membership_artifacts(
        &plan,
        &source,
        &tuple,
        &timestamp,
        &observation_expires_at,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let result = with_source_locks(|| {
        let stored =
            load_local(&state.data_dir, MEMBERSHIP_INTENT_DIR, &intent_tail)?.ok_or_else(|| {
                verr(
                    "system_lifecycle_pending_convergence",
                    "membership intent vanished",
                )
            })?;
        verify_intent_seal(&stored)?;
        if stored != intent {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                "durable membership intent changed",
            ));
        }
        persist_membership_graph(&state.data_dir, &plan, &artifacts, &evidence, &wallet_value)?;
        remove_intent(&state.data_dir, MEMBERSHIP_INTENT_DIR, &intent_tail)
    });
    if let Err(error) = result {
        return classify(error);
    }
    (
        StatusCode::OK,
        Json(json!({
            "op": op.as_str(),
            "sequence": plan.sequence,
            "node_membership": artifacts.record,
            "membership_transition": artifacts.transition,
            "receipt": artifacts.receipt,
            "membership_root": plan.resulting_membership_root,
            "nonclaims": {
                "writer": false,
                "availability": false,
                "quorum": false,
                "consensus": false,
                "network_assurance": false,
                "desired_topology_observed": false
            }
        })),
    )
}

/// Read-only membership eligibility projection. This never fabricates
/// eligibility: the status gate is reported separately from declaration
/// evidence and wallet authority a future POST must still supply.
pub(crate) async fn handle_get_transition(
    AxumPath((key, op_name)): AxumPath<(String, String)>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_membership_source_key_invalid",
            "id is not canonical",
        ));
    }
    let Some(op) = MembershipTransitionOp::parse(&op_name) else {
        return classify(verr(
            "system_membership_operation_not_found",
            "unknown membership op",
        ));
    };
    match with_source_locks(|| {
        ensure_no_pending_membership_intent(&state.data_dir, &key)?;
        let source = load_membership_source(&state.data_dir, &key)?;
        let mut blockers = Vec::new();
        if source.desired_topology.is_none() {
            blockers.push(json!({"code":"desired_topology_undeclared"}));
        }
        let committed: Vec<Value> = source
            .transitions
            .iter()
            .filter(|value| value.get("op").and_then(Value::as_str) == Some(op.as_str()))
            .cloned()
            .collect();
        Ok::<_, VErr>(json!({
            "op": op.as_str(),
            "required_scope": op.required_scope(),
            "eligible_now": {"blockers": blockers},
            "required_declaration_evidence": {
                "expected_membership_root": true,
                "node_identity_in_system_namespace": true,
                "admission_bundle": op == MembershipTransitionOp::AdmitNode,
                "resolved_readiness_attestation": op == MembershipTransitionOp::AttestReadiness,
                "resolved_catchup_receipt": op == MembershipTransitionOp::AdvanceCatchup,
                "fresh_role_lease": op == MembershipTransitionOp::PromoteRole,
            },
            "membership_head": {
                "sequence": source.head.sequence,
                "membership_root": source.head.membership_root,
            },
            "live_members": source.records.iter().map(|record| json!({
                "node_id": record["node_id"],
                "status": record["status"],
                "readiness": record["observation"]["readiness"],
            })).collect::<Vec<_>>(),
            "committed_entries": committed.len(),
            "nonclaims": {"wallet_authorized": false, "writer": false, "availability": false}
        }))
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

/// Pure desired-versus-observed projection over durable truth only. Divergence
/// is labeled, never reconciled; absence is honest, never fabricated.
pub(crate) fn build_membership_projection(
    system_id: &str,
    desired: Option<(&Value, &str)>,
    records: &[Value],
    head: &MembershipLogHead,
) -> Result<Value, VErr> {
    let mut members: Vec<&Value> = records.iter().collect();
    members.sort_by_key(|record| {
        record
            .get("node_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    });
    let observed_members: Vec<Value> = members
        .iter()
        .map(|record| {
            Ok(json!({
                "node_id": record["node_id"],
                "node_membership_id": record["node_membership_id"],
                "status": record["status"],
                "readiness": record["observation"]["readiness"],
                "operation_offset": record["synchronization"]["operation_offset"],
                "verified_state_root": record["synchronization"]["verified_state_root"],
                "roles": record.get("role_assignments").and_then(Value::as_array).map(|assignments| {
                    assignments.iter().map(|assignment| assignment["role"].clone()).collect::<Vec<_>>()
                }).unwrap_or_default(),
                "record_root": membership_record_root(record).map_err(plan_err)?,
            }))
        })
        .collect::<Result<Vec<_>, VErr>>()?;
    let divergence = match desired {
        None => Value::Null,
        Some((topology, _root)) => {
            let mut rows = Vec::new();
            let targets = topology
                .get("role_targets")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for target in &targets {
                let role = target.get("role").and_then(Value::as_str).unwrap_or("");
                let holders = |predicate: &dyn Fn(&Value) -> bool| {
                    members
                        .iter()
                        .filter(|record| {
                            record
                                .get("role_assignments")
                                .and_then(Value::as_array)
                                .is_some_and(|assignments| {
                                    assignments.iter().any(|assignment| {
                                        assignment.get("role").and_then(Value::as_str) == Some(role)
                                    })
                                })
                                && predicate(record)
                        })
                        .count() as u64
                };
                let observed_ready = holders(&|record: &Value| {
                    record
                        .pointer("/observation/readiness")
                        .and_then(Value::as_str)
                        == Some("ready")
                        && record.get("status").and_then(Value::as_str) == Some("active")
                });
                let observed_live = holders(&|_record: &Value| true);
                let minimum = target
                    .get("minimum_ready_nodes")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                rows.push(json!({
                    "role": role,
                    "minimum_ready_nodes": minimum,
                    "observed_ready_nodes": observed_ready,
                    "observed_live_nodes": observed_live,
                    "deficit": minimum.saturating_sub(observed_ready),
                    "satisfied": observed_ready >= minimum,
                }));
            }
            let declared_roles: Vec<&str> = targets
                .iter()
                .filter_map(|target| target.get("role").and_then(Value::as_str))
                .collect();
            for record in &members {
                if let Some(assignments) = record.get("role_assignments").and_then(Value::as_array)
                {
                    for assignment in assignments {
                        let role = assignment.get("role").and_then(Value::as_str).unwrap_or("");
                        if !declared_roles.contains(&role) {
                            rows.push(json!({
                                "role": role,
                                "kind": "undeclared_role",
                                "node_id": record["node_id"],
                                "satisfied": false,
                            }));
                        }
                    }
                }
            }
            Value::Array(rows)
        }
    };
    Ok(json!({
        "schema_version": "ioi.hypervisor.autonomous-system-membership-projection.v1",
        "system_id": system_id,
        "state": if records.is_empty() && desired.is_none() { "honest_empty" } else { "ready" },
        "desired": match desired {
            None => Value::Null,
            Some((topology, root)) => json!({
                "desired_topology": topology,
                "desired_topology_root": root,
            }),
        },
        "desired_undeclared": desired.is_none(),
        "observed": {
            "membership_root": head.membership_root,
            "sequence": head.sequence,
            "members": observed_members,
        },
        "divergence": divergence,
        "projection_source": "durable_owner_reconstruction",
        "nonclaims": {
            "desired_asserts_observed": false,
            "observed_asserts_desired": false,
            "availability": false,
            "writer": false,
            "quorum": false,
            "consensus": false
        }
    }))
}

/// GET /v1/hypervisor/autonomous-systems/:id/membership/projection
pub(crate) async fn handle_get_projection(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_membership_source_key_invalid",
            "id is not canonical",
        ));
    }
    match with_source_locks(|| {
        let source = load_membership_source(&state.data_dir, &key)?;
        build_membership_projection(
            &source.binding.system_id,
            source
                .desired_topology
                .as_ref()
                .zip(source.desired_topology_root.as_deref()),
            &source.records,
            &source.head,
        )
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

fn validate_desired_topology_request(body: &Value) -> Result<(), VErr> {
    let encoded = serde_json::to_vec(body)
        .map_err(|error| verr("system_membership_request_invalid", error.to_string()))?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(verr(
            "system_membership_request_oversize",
            "request exceeds 512 KiB",
        ));
    }
    if contains_sensitive_key(body) {
        return Err(verr(
            "system_membership_sensitive_field_rejected",
            "secret-bearing keys are forbidden recursively",
        ));
    }
    let object = body.as_object().ok_or_else(|| {
        verr(
            "system_membership_request_invalid",
            "request must be an object",
        )
    })?;
    const ALLOWED: &[&str] = &["desired_topology", "wallet_approval_grant"];
    if let Some(key) = object.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(verr(
            "system_membership_request_field_unknown",
            format!("undeclared request field '{key}' is forbidden"),
        ));
    }
    Ok(())
}

fn build_desired_topology_plan(source: &MembershipSource, body: &Value) -> Result<Value, VErr> {
    let topology = body.get("desired_topology").cloned().ok_or_else(|| {
        verr(
            "system_membership_request_invalid",
            "request lacks its desired_topology body",
        )
    })?;
    validate_contract(DESIRED_TOPOLOGY_CONTRACT, &topology, "desired topology")?;
    if topology.get("system_id").and_then(Value::as_str) != Some(source.binding.system_id.as_str())
    {
        return Err(verr(
            "system_membership_plan_invalid",
            "desired topology does not belong to this System",
        ));
    }
    if topology.get("status").and_then(Value::as_str) != Some("declared") {
        return Err(verr(
            "system_membership_plan_invalid",
            "a declaration must carry status 'declared'",
        ));
    }
    if topology
        .get("deployment_profile_ref")
        .and_then(Value::as_str)
        != Some(source.binding.deployment_profile_ref.as_str())
        || topology
            .get("deployment_profile_root")
            .and_then(Value::as_str)
            != Some(source.binding.deployment_profile_root.as_str())
    {
        return Err(verr(
            "system_membership_plan_invalid",
            "desired topology is not bound to the live deployment profile revision",
        ));
    }
    let current_root = source.desired_topology_root.as_deref();
    if topology
        .get("predecessor_desired_topology_root")
        .and_then(Value::as_str)
        != current_root
    {
        return Err(verr(
            "system_membership_head_conflict",
            "desired topology declaration does not compare-and-swap the current record",
        ));
    }
    let root = desired_topology_root(&topology).map_err(plan_err)?;
    let sequence = source
        .head
        .sequence
        .checked_add(1)
        .ok_or_else(|| verr("system_membership_plan_invalid", "sequence overflow"))?;
    let mut effect = json!({
        "schema_version": "ioi.autonomous-system-desired-topology-authority-effect.v1",
        "op": DECLARE_DESIRED_TOPOLOGY_OP,
        "required_scope": DECLARE_DESIRED_TOPOLOGY_SCOPE,
        "sequence": sequence,
        "system_id": source.binding.system_id,
        "genesis_ref": source.binding.genesis_ref,
        "source_governing_authority_ref": source.binding.source_governing_authority_ref,
        "deployment_profile_ref": source.binding.deployment_profile_ref,
        "deployment_profile_root": source.binding.deployment_profile_root,
        "desired_topology_ref": topology["desired_topology_id"],
        "desired_topology_root": root,
        "predecessor_desired_topology_root": current_root,
        "asserts_observed_truth": false,
        "operation_commitment": Value::Null,
    });
    let operation_commitment = jcs_hash(&json!({
        "domain": "ioi.autonomous-system-desired-topology-operation-commitment-jcs-sha256.v1",
        "effect": effect,
    }))?;
    effect["operation_commitment"] = json!(operation_commitment);
    Ok(json!({
        "desired_topology": topology,
        "desired_topology_root": root,
        "authority_effect": effect,
    }))
}

/// POST /v1/hypervisor/autonomous-systems/:id/membership/desired-topology
///
/// Declares the desired side as an owner-authorized durable record. The
/// declaration is compare-and-swap over the current declared record and can
/// never carry an observed claim: the contract pins
/// `asserts_observed_truth: false` structurally.
pub(crate) async fn handle_declare_desired_topology(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_membership_source_key_invalid",
            "id is not canonical",
        ));
    }
    if let Err(error) = validate_desired_topology_request(&body) {
        return classify(error);
    }
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let (source, plan) = match with_source_locks(|| {
        ensure_no_cross_plane_pending(&state.data_dir, &key)?;
        let source = load_membership_source(&state.data_dir, &key)?;
        let plan = build_desired_topology_plan(&source, &body)?;
        Ok::<_, VErr>((source, plan))
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let effect = plan["authority_effect"].clone();
    let system_id = source.binding.system_id.clone();
    let genesis_ref = source.binding.genesis_ref.clone();
    let governing = source.binding.source_governing_authority_ref.clone();
    let sequence = effect.get("sequence").and_then(Value::as_u64).unwrap_or(1);
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
        DECLARE_DESIRED_TOPOLOGY_OP,
        sequence,
        &effect,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut evidence = match prepare_node_evidence_for(
        &effect,
        DECLARE_DESIRED_TOPOLOGY_OP,
        sequence,
        DECLARE_DESIRED_TOPOLOGY_SCOPE,
        &governing,
        required_string(&plan, "/desired_topology_root").unwrap_or(""),
        authorized,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if let Err(error) = preflight_chain_writer_grant(&evidence.wallet_params).await {
        return classify(error);
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
                return classify(verr("system_lifecycle_wallet_consumption_refused", message))
            }
            Err(super::wallet_network_capability_client::ResolveError::Invalid(message)) => {
                return classify(verr("system_lifecycle_wallet_consumption_invalid", message))
            }
        };
    let wallet_value = match validate_wallet_receipt(&mut evidence, &wallet_receipt) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let topology = plan["desired_topology"].clone();
    let topology_root = required(&plan, "/desired_topology_root").unwrap_or_default();
    let result = with_source_locks(|| {
        // Recheck the CAS under the lock: the declaration must still swap the
        // exact current record.
        let fresh = load_membership_source(&state.data_dir, &key)?;
        if build_desired_topology_plan(&fresh, &body)? != plan {
            return Err(verr(
                "system_membership_head_conflict",
                "durable desired topology changed before commitment",
            ));
        }
        let consumption: ioi_services::wallet_network::ApprovalGrantConsumptionReceipt =
            serde_json::from_value(wallet_value.clone()).map_err(|error| {
                verr(
                    "system_lifecycle_wallet_consumption_invalid",
                    error.to_string(),
                )
            })?;
        let records: Vec<(&str, String, &Value)> = vec![
            (
                AUTHORITY_CONSUMPTION_DIR,
                format!("aslac_{}", hex::encode(consumption.consumption_id)),
                &wallet_value,
            ),
            (
                AUTHORITY_EVIDENCE_DIR,
                tail("aslae_", &evidence.authority_evidence_root)?,
                &evidence.authority_evidence,
            ),
            (
                DESIRED_TOPOLOGY_DIR,
                tail("asdt_", &topology_root)?,
                &topology,
            ),
        ];
        for (family, record_tail, value) in records {
            persist_local(&state.data_dir, family, &record_tail, value)?;
            super::substrate_store::admit_required(&state.data_dir, family, &record_tail, value)
                .map_err(|error| {
                    verr(
                        "system_membership_agentgres_admission_failed",
                        format!("required admission for '{family}/{record_tail}' failed ({error})"),
                    )
                })?;
            if load_required_exact(&state.data_dir, family, &record_tail)?.as_ref() != Some(value) {
                return Err(verr(
                    "system_membership_persist_failed",
                    "desired topology graph did not converge byte-exactly",
                ));
            }
        }
        Ok(())
    });
    if let Err(error) = result {
        return classify(error);
    }
    (
        StatusCode::OK,
        Json(json!({
            "op": DECLARE_DESIRED_TOPOLOGY_OP,
            "desired_topology": topology,
            "desired_topology_root": topology_root,
            "nonclaims": {
                "observed_membership": false,
                "readiness": false,
                "writer": false,
                "availability": false
            }
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn h(marker: u8) -> String {
        format!("sha256:{}", format!("{marker:02x}").repeat(32))
    }

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

    fn binding() -> MembershipIdentityBinding {
        MembershipIdentityBinding {
            system_id: "system://acme/system-alpha".into(),
            genesis_ref: "genesis://acme/system-alpha".into(),
            source_governing_authority_ref: "org://acme/research".into(),
            deployment_profile_ref: format!(
                "deployment-profile://acme/system-alpha/revision/sha256:{}",
                "a".repeat(64)
            ),
            deployment_profile_root: format!("sha256:{}", "d".repeat(64)),
            admitted_constitution_root: h(0x0b),
            admitted_manifest_root: h(0x0c),
        }
    }

    fn source_with(
        records: Vec<Value>,
        head: MembershipLogHead,
        consumed: Vec<String>,
    ) -> MembershipSource {
        let desired = fixture("autonomous-system-desired-topology-v1/positive-declared.json");
        let root = desired_topology_root(&desired).expect("desired root");
        MembershipSource {
            binding: binding(),
            desired_topology: Some(desired),
            desired_topology_root: Some(root),
            transitions: Vec::new(),
            records,
            head,
            consumed_role_lease_refs: consumed,
        }
    }

    fn head_for(records: &[Value], sequence: u64) -> MembershipLogHead {
        MembershipLogHead {
            sequence,
            membership_root: membership_set_root("system://acme/system-alpha", records)
                .expect("set root"),
        }
    }

    fn declaration_for(node_id: &str, records: &[Value]) -> MembershipTransitionDeclaration {
        MembershipTransitionDeclaration {
            node_id: node_id.into(),
            expected_membership_root: membership_set_root("system://acme/system-alpha", records)
                .expect("set root"),
            evidence_refs: vec![],
            node_owner_ref: None,
            roles: vec![],
            membership_lease_ref: None,
            node_attestation_refs: vec![],
            declared_readiness: None,
            readiness_attestation_ref: None,
            catchup_operation_offset: None,
            catchup_receipt_ref: None,
            target_role: None,
            role_lease_ref: None,
        }
    }

    struct LadderState {
        records: Vec<Value>,
        transitions: Vec<Value>,
        record_bytes: HashMap<String, String>,
        head: MembershipLogHead,
        consumed: Vec<String>,
    }

    fn apply_step(
        state: &mut LadderState,
        op: MembershipTransitionOp,
        declaration: &MembershipTransitionDeclaration,
        attestation: Option<&Value>,
        receipt: Option<&Value>,
    ) -> MembershipStepArtifacts {
        let source = source_with(
            state.records.clone(),
            state.head.clone(),
            state.consumed.clone(),
        );
        let plan = compile_from_source(op, &source, declaration, attestation, receipt)
            .unwrap_or_else(|(code, message)| panic!("{}: {code} {message}", op.as_str()));
        assert_eq!(plan.predecessor_membership_root, state.head.membership_root);
        let artifacts = build_membership_artifacts(
            &plan,
            &source,
            &authority(),
            "2026-07-27T12:00:00Z",
            "2026-07-27T12:05:00Z",
        )
        .unwrap_or_else(|(code, message)| panic!("{}: {code} {message}", op.as_str()));
        // Every registered envelope validates: the record, the transition,
        // and the receipt (the desired topology validated during compile).
        validate_contract(NODE_MEMBERSHIP_CONTRACT, &artifacts.record, "ladder record")
            .expect("record envelope");
        validate_contract(
            MEMBERSHIP_TRANSITION_CONTRACT,
            &artifacts.transition,
            "ladder transition",
        )
        .expect("transition envelope");
        validate_contract(RECEIPT_CONTRACT, &artifacts.receipt, "ladder receipt")
            .expect("receipt envelope");
        state
            .records
            .retain(|record| record["node_id"] != plan.node_id.as_str());
        if op != MembershipTransitionOp::RemoveNode {
            state.records.push(artifacts.record.clone());
        }
        state.transitions.push(artifacts.transition.clone());
        state.record_bytes.insert(
            plan.resulting_record_root.clone(),
            serde_json::to_string(&artifacts.record).expect("record bytes"),
        );
        state.head = MembershipLogHead {
            sequence: plan.sequence,
            membership_root: plan.resulting_membership_root.clone(),
        };
        if let Some(lease) = plan
            .authority_effect
            .get("role_lease_ref")
            .and_then(Value::as_str)
        {
            state.consumed.push(lease.to_owned());
        }
        artifacts
    }

    const NODE: &str = "node://acme/system-alpha/alpha-node-1";

    /// admit -> advance -> attest -> promote, returning the live state.
    fn ladder_to_promotion() -> LadderState {
        let mut state = LadderState {
            records: Vec::new(),
            transitions: Vec::new(),
            record_bytes: HashMap::new(),
            head: head_for(&[], 0),
            consumed: Vec::new(),
        };
        let mut admit = declaration_for(NODE, &state.records);
        admit.node_owner_ref = Some("wallet://acme/node-owner".into());
        admit.roles = vec!["state_replica".into()];
        admit.membership_lease_ref =
            Some("lease://acme/system-alpha/membership/alpha-node-1".into());
        admit.node_attestation_refs = vec!["attestation://acme/alpha-node-1/boot".into()];
        admit.evidence_refs =
            vec!["evidence://acme/system-alpha/membership/admit/alpha-node-1".into()];
        apply_step(
            &mut state,
            MembershipTransitionOp::AdmitNode,
            &admit,
            None,
            None,
        );

        let mut advance = declaration_for(NODE, &state.records);
        advance.catchup_operation_offset = Some(7);
        advance.catchup_receipt_ref =
            Some("receipt://acme/system-alpha/catchup/alpha-node-1/7".into());
        let receipt = json!({
            "receipt_ref": "receipt://acme/system-alpha/catchup/alpha-node-1/7",
            "node_id": NODE,
            "operation_offset": 7,
            "verified_state_root": h(0x0e),
        });
        apply_step(
            &mut state,
            MembershipTransitionOp::AdvanceCatchup,
            &advance,
            None,
            Some(&receipt),
        );

        let mut attest = declaration_for(NODE, &state.records);
        attest.declared_readiness = Some("ready".into());
        attest.readiness_attestation_ref =
            Some("attestation://acme/alpha-node-1/readiness/7".into());
        let attestation = json!({
            "attestation_ref": "attestation://acme/alpha-node-1/readiness/7",
            "node_id": NODE,
            "membership_epoch": state.records[0]["membership_epoch"],
            "verified_state_root": state.records[0]["synchronization"]["verified_state_root"],
            "readiness": "ready",
        });
        apply_step(
            &mut state,
            MembershipTransitionOp::AttestReadiness,
            &attest,
            Some(&attestation),
            None,
        );

        let mut promote = declaration_for(NODE, &state.records);
        promote.target_role = Some("hot_standby".into());
        promote.role_lease_ref = Some("lease://acme/system-alpha/role/standby-1".into());
        apply_step(
            &mut state,
            MembershipTransitionOp::PromoteRole,
            &promote,
            None,
            None,
        );
        state
    }

    #[test]
    fn membership_ladder_artifacts_validate_every_registered_envelope() {
        let mut state = ladder_to_promotion();
        assert_eq!(state.head.sequence, 4);
        assert_eq!(state.records.len(), 1);
        assert_eq!(state.records[0]["status"], "active");
        assert_eq!(state.records[0]["observation"]["readiness"], "ready");

        let drain = declaration_for(NODE, &state.records);
        let drained = apply_step(
            &mut state,
            MembershipTransitionOp::DrainNode,
            &drain,
            None,
            None,
        );
        assert_eq!(drained.record["status"], "draining");

        let remove = declaration_for(NODE, &state.records);
        let removed = apply_step(
            &mut state,
            MembershipTransitionOp::RemoveNode,
            &remove,
            None,
            None,
        );
        // The final record revision survives as evidence while the resulting
        // membership set excludes the node.
        assert_eq!(removed.record["status"], "left");
        assert!(state.records.is_empty());
        assert_eq!(
            state.head.membership_root,
            membership_set_root("system://acme/system-alpha", &[]).expect("empty root")
        );
        assert_eq!(state.transitions.len(), 6);

        // The committed log replays cleanly from durable truth alone.
        let record_bytes = state.record_bytes.clone();
        let loader = move |record_root: &str| -> Result<Option<Value>, VErr> {
            Ok(record_bytes
                .get(record_root)
                .map(|bytes| serde_json::from_str(bytes).expect("stored record")))
        };
        let (live, head, consumed) = replay_membership_transitions(
            "system://acme/system-alpha",
            &state.transitions,
            &loader,
        )
        .expect("replay");
        assert!(live.is_empty());
        assert_eq!(head, state.head);
        assert_eq!(consumed, vec!["lease://acme/system-alpha/role/standby-1"]);
    }

    #[test]
    fn restart_projection_loss_rebuilds_the_projection_from_durable_records_only() {
        let state = ladder_to_promotion();
        let desired = fixture("autonomous-system-desired-topology-v1/positive-declared.json");
        let desired_root = desired_topology_root(&desired).expect("desired root");
        let before = build_membership_projection(
            "system://acme/system-alpha",
            Some((&desired, desired_root.as_str())),
            &state.records,
            &state.head,
        )
        .expect("projection before restart");

        // Restart: every in-memory structure is gone; only durable transition
        // and record bytes remain. The rebuilt projection is byte-exact.
        let transition_bytes: Vec<String> = state
            .transitions
            .iter()
            .map(|value| serde_json::to_string(value).expect("transition bytes"))
            .collect();
        let record_bytes = state.record_bytes.clone();
        drop(state);
        let transitions: Vec<Value> = transition_bytes
            .iter()
            .map(|bytes| serde_json::from_str(bytes).expect("stored transition"))
            .collect();
        let loader = move |record_root: &str| -> Result<Option<Value>, VErr> {
            Ok(record_bytes
                .get(record_root)
                .map(|bytes| serde_json::from_str(bytes).expect("stored record")))
        };
        let (live, head, _consumed) =
            replay_membership_transitions("system://acme/system-alpha", &transitions, &loader)
                .expect("replay after restart");
        let after = build_membership_projection(
            "system://acme/system-alpha",
            Some((&desired, desired_root.as_str())),
            &live,
            &head,
        )
        .expect("projection after restart");
        assert_eq!(before, after);
        assert_eq!(
            serde_json::to_string(&before).expect("bytes"),
            serde_json::to_string(&after).expect("bytes")
        );

        // The divergence rows label desired-versus-observed without
        // reconciling: the declared state_replica target is satisfied and the
        // promoted hot_standby role is labeled undeclared.
        let rows = after["divergence"].as_array().expect("divergence rows");
        assert!(rows.iter().any(|row| row["role"] == "state_replica"
            && row["satisfied"] == true
            && row["observed_ready_nodes"] == 1));
        assert!(rows
            .iter()
            .any(|row| row["role"] == "hot_standby" && row["kind"] == "undeclared_role"));
        assert_eq!(after["nonclaims"]["desired_asserts_observed"], false);
    }

    #[test]
    fn membership_ops_have_owner_scopes_and_never_parse_as_other_families() {
        for op in MembershipTransitionOp::ALL {
            assert_eq!(AUTHORITY.operation_scope(op.as_str()), op.required_scope());
            assert!(
                ioi_types::app::system_lifecycle_transitions::ProtectedTransitionOp::parse(
                    op.as_str()
                )
                .is_none()
            );
            assert!(
                ioi_types::app::system_continuity_transitions::ContinuityTransitionOp::parse(
                    op.as_str()
                )
                .is_none()
            );
        }
        assert_eq!(
            AUTHORITY.operation_scope(DECLARE_DESIRED_TOPOLOGY_OP),
            DECLARE_DESIRED_TOPOLOGY_SCOPE
        );
    }

    #[test]
    fn projection_without_a_declared_desired_topology_is_honest() {
        let projection =
            build_membership_projection("system://acme/system-alpha", None, &[], &head_for(&[], 0))
                .expect("empty projection");
        assert_eq!(projection["state"], "honest_empty");
        assert_eq!(projection["desired"], Value::Null);
        assert_eq!(projection["desired_undeclared"], true);
        assert_eq!(projection["divergence"], Value::Null);
    }
}
