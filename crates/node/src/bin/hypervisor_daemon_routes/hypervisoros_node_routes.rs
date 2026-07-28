//! HypervisorOS node-attestation plane (M2): governed routes over the
//! node-side trust ladder — declared boot posture, declared temporal
//! freshness policy, admitted node identities, verified measured-boot
//! receipts, and derivable readiness.
//!
//! Desired records (boot profile, temporal profile) and observed records
//! (node records, boot receipts) are distinct durable owners over the shared
//! governed authority flow. The observed side is rebuilt from durable
//! node-attestation transitions and record revisions only, so a restart
//! loses no projection it cannot reconstruct byte-exactly. Every admission
//! input is resolved from durable server truth, never asserted by the caller
//! (`INV-37`). Sealed node-identity material lives only behind the
//! wallet.network secret store: requests and artifacts carry the public
//! binding and the vault alias reference, never key material.

use ioi_types::app::hypervisoros_node_attestation::{
    boot_profile_root, boot_receipt_root, compile_node_attestation_plan, node_record_root,
    node_set_root, temporal_profile_root, CompiledNodeAttestationPlan, NodeAttestationDeclaration,
    NodeAttestationLogHead, NodeAttestationOp, NodeEstateBinding, BOOT_PROFILE_CONTRACT,
    BOOT_RECEIPT_CONTRACT, HYPERVISOROS_NODE_CONTRACT, TEMPORAL_PROFILE_CONTRACT,
};
use serde_json::{json, Value};
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;

use super::governed_authority::{self as governed, AuthorityPolicyContext, Governance};
use super::system_activation_routes::{
    classify, contains_sensitive_key, evidence_intent_value, forced_fault, intent_seal, jcs_hash,
    load_local, load_required_exact, ms_to_timestamp, persist_local, prepare_node_evidence_for,
    remove_intent, required_string, tail, validate_contract, validate_wallet_receipt,
    verify_intent_seal, verr, with_source_locks, AUTHORITY, AUTHORITY_CONSUMPTION_DIR,
    AUTHORITY_EVIDENCE_DIR, MAX_REQUEST_BYTES, SYSTEM_ACTIVATION_GATE,
};
use super::system_protected_transition_routes::{
    decision_tuple, preflight_chain_writer_grant, DecisionAuthorityTuple,
};
use super::DaemonState;

type VErr = (String, String);

/// Owner-declared boot profiles (content-addressed, CAS lineage).
pub(crate) const BOOT_PROFILE_DIR: &str = "hypervisoros-boot-profiles";
/// Owner-declared temporal-verification-profile records.
pub(crate) const TEMPORAL_PROFILE_DIR: &str = "hypervisoros-temporal-profiles";
/// Observed node record revisions (timeless content roots).
pub(crate) const NODE_RECORD_DIR: &str = "hypervisoros-node-records";
/// Committed verified boot receipts (timeless content roots).
pub(crate) const BOOT_RECEIPT_DIR: &str = "hypervisoros-boot-receipts";
/// Committed node-attestation compare-and-swap transitions.
pub(crate) const NODE_TRANSITION_DIR: &str = "hypervisoros-node-transitions";
/// Node-attestation plane receipts.
pub(crate) const NODE_PLANE_RECEIPT_DIR: &str = "hypervisoros-node-attestation-receipts";
/// One-successor-per-predecessor node set CAS claims.
pub(crate) const NODE_CLAIM_DIR: &str = "hypervisoros-node-successor-claims";
/// Sealed node-attestation transition intents (local replay registry).
pub(crate) const NODE_INTENT_DIR: &str = "hypervisoros-node-transition-intents";
/// Daemon-resolved node evidence (observed boot receipts, temporal validity
/// evaluations, enforcement coverage declarations). The loader is live; the
/// measured-boot runtime producer is a later M2 leg.
pub(crate) const NODE_EVIDENCE_DIR: &str = "hypervisoros-node-evidence";

const RECEIPT_CONTRACT: &str = "schema://ioi/foundations/receipt-envelope/v1";
const TRANSITION_ARTIFACT_DOMAIN: &str = "ioi.hypervisoros-node-transition-jcs-sha256.v1";
const RECEIPT_ARTIFACT_DOMAIN: &str = "ioi.hypervisoros-node-attestation-receipt-jcs-sha256.v1";
const ENFORCEMENT_COVERAGE_SCHEMA_VERSION: &str =
    "ioi.components.daemon-runtime.enforcement-coverage-declaration.v1";
const DECLARE_BOOT_PROFILE_OP: &str = "declare_boot_profile";
const DECLARE_BOOT_PROFILE_SCOPE: &str = "scope:hypervisoros.node.declare_boot_profile";
const DECLARE_TEMPORAL_PROFILE_OP: &str = "declare_temporal_profile";
const DECLARE_TEMPORAL_PROFILE_SCOPE: &str = "scope:hypervisoros.node.declare_temporal_profile";

fn required(value: &Value, pointer: &str) -> Result<String, VErr> {
    required_string(value, pointer).map(str::to_owned)
}

fn artifact_root(domain: &str, artifact: &Value) -> Result<String, VErr> {
    jcs_hash(&json!({"domain":domain,"artifact":artifact}))
}

fn plan_err(error: String) -> VErr {
    verr("hypervisoros_node_plan_invalid", error)
}

/// The one local estate this daemon is node root for. The node plane is
/// estate-scoped, not System-scoped: a node may later hold memberships in
/// many Systems, and boot integrity never grants any of them authority.
pub(crate) fn local_estate_binding() -> NodeEstateBinding {
    NodeEstateBinding {
        estate_namespace: "local".into(),
        daemon_ref: "runtime://local/daemon".into(),
        agentgres_domain_ref: "agentgres://domain/hypervisor/local".into(),
    }
}

/// Real Ed25519 verifier bound into the pure compiler.
pub(crate) fn ed25519_verifier(
    suite: &str,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    use ioi_api::crypto::{SerializableKey, VerifyingKey};
    use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
    if suite != "ed25519" {
        return Err(format!("unsupported signature suite '{suite}'"));
    }
    let public_key = Ed25519PublicKey::from_bytes(public_key).map_err(|error| error.to_string())?;
    let signature = Ed25519Signature::from_bytes(signature).map_err(|error| error.to_string())?;
    public_key
        .verify(message, &signature)
        .map_err(|error| error.to_string())
}

/// Enumerate one local-only family without requiring Agentgres admission.
fn scan_local_family(data_dir: &str, family: &str) -> Result<Vec<(String, Value)>, VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(verr(
                "hypervisoros_node_artifact_unreadable",
                format!("family '{family}' cannot be pinned ({error})"),
            ))
        }
    };
    let mut names = super::durable_fs::enumerate_pinned(&directory).map_err(|error| {
        verr(
            "hypervisoros_node_artifact_unreadable",
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
                    "hypervisoros_node_artifact_unreadable",
                    format!("unexpected entry '{family}/{name}'"),
                )
            })?
            .to_owned();
        let value = load_local(data_dir, family, &record_tail)?.ok_or_else(|| {
            verr(
                "hypervisoros_node_artifact_unreadable",
                format!("'{family}/{name}' vanished"),
            )
        })?;
        values.push((record_tail, value));
    }
    Ok(values)
}

/// Enumerate one required-admission family with the local-versus-Agentgres
/// census equality proof; a mismatch is source incompleteness and the read
/// fails closed instead of projecting partial truth.
fn enumerate_required_censused(data_dir: &str, family: &str) -> Result<Vec<Value>, VErr> {
    let local = super::system_activation_routes::enumerate_family(data_dir, family)?;
    let mut local_values: Vec<Value> = local.into_iter().map(|(_, value)| value).collect();
    let mut substrate =
        super::substrate_store::read_required_all(data_dir, family).map_err(|error| {
            verr(
                "hypervisoros_node_source_incomplete",
                format!("Agentgres census for '{family}' failed ({error})"),
            )
        })?;
    let sort_key = |value: &Value| serde_json::to_string(value).unwrap_or_default();
    local_values.sort_by_key(sort_key);
    substrate.sort_by_key(sort_key);
    if local_values != substrate {
        return Err(verr(
            "hypervisoros_node_source_incomplete",
            format!("local and Agentgres censuses for '{family}' differ"),
        ));
    }
    Ok(local_values)
}

/// The exact durable truth one node-attestation operation compiles against.
pub(crate) struct NodeAttestationSource {
    pub binding: NodeEstateBinding,
    pub boot_profile: Option<Value>,
    pub boot_profile_root: Option<String>,
    pub temporal_profile: Option<Value>,
    pub temporal_profile_root: Option<String>,
    pub transitions: Vec<Value>,
    pub records: Vec<Value>,
    pub head: NodeAttestationLogHead,
}

/// Pure node-attestation replay over committed transitions and a record
/// loader. This is the restart path: no rebuildable head or projection
/// record is consulted, only immutable durable truth.
pub(crate) fn replay_node_attestation_transitions(
    estate_namespace: &str,
    transitions: &[Value],
    load_record: &dyn Fn(&str) -> Result<Option<Value>, VErr>,
) -> Result<(Vec<Value>, NodeAttestationLogHead), VErr> {
    let mut ordered: Vec<&Value> = transitions
        .iter()
        .filter(|value| {
            value.get("estate_namespace").and_then(Value::as_str) == Some(estate_namespace)
        })
        .collect();
    ordered.sort_by_key(|value| value.get("sequence").and_then(Value::as_u64).unwrap_or(0));
    let empty_root = node_set_root(estate_namespace, &[]).map_err(plan_err)?;
    let mut expected_predecessor = empty_root.clone();
    let mut live: Vec<Value> = Vec::new();
    let mut sequence = 0u64;
    for transition in ordered {
        let this_sequence = transition
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                verr(
                    "hypervisoros_node_artifact_invalid",
                    "committed transition lacks its sequence",
                )
            })?;
        if this_sequence != sequence + 1 {
            return Err(verr(
                "hypervisoros_node_artifact_mismatch",
                "node-attestation log is not contiguous",
            ));
        }
        if transition
            .get("predecessor_node_set_root")
            .and_then(Value::as_str)
            != Some(expected_predecessor.as_str())
        {
            return Err(verr(
                "hypervisoros_node_artifact_mismatch",
                "node-attestation log breaks its compare-and-swap chain",
            ));
        }
        let node_id = required(transition, "/node_id")?;
        let record_root = required(transition, "/resulting_record_root")?;
        let record = load_record(&record_root)?.ok_or_else(|| {
            verr(
                "hypervisoros_node_artifact_mismatch",
                "committed transition lacks its durable record revision",
            )
        })?;
        if node_record_root(&record).map_err(plan_err)? != record_root
            || record.get("node_id").and_then(Value::as_str) != Some(node_id.as_str())
        {
            return Err(verr(
                "hypervisoros_node_artifact_mismatch",
                "durable record revision does not match its committed transition",
            ));
        }
        live.retain(|held| held.get("node_id").and_then(Value::as_str) != Some(node_id.as_str()));
        live.push(record);
        let derived = node_set_root(estate_namespace, &live).map_err(plan_err)?;
        let resulting = required(transition, "/resulting_node_set_root")?;
        if derived != resulting {
            return Err(verr(
                "hypervisoros_node_artifact_mismatch",
                "replayed node set does not recompute the committed root",
            ));
        }
        expected_predecessor = resulting;
        sequence = this_sequence;
    }
    Ok((
        live,
        NodeAttestationLogHead {
            sequence,
            node_set_root: expected_predecessor,
        },
    ))
}

/// The one current declared record of a profile family: the declared record
/// no successor cites as its predecessor. Two uncited declared records are a
/// fork and fail closed.
fn current_declared_profile(
    records: &[Value],
    predecessor_field: &str,
    root: &dyn Fn(&Value) -> Result<String, String>,
) -> Result<Option<(Value, String)>, VErr> {
    let mut mine: Vec<(Value, String)> = Vec::new();
    for record in records {
        mine.push((record.clone(), root(record).map_err(plan_err)?));
    }
    let cited: Vec<String> = mine
        .iter()
        .filter_map(|(record, _)| {
            record
                .get(predecessor_field)
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let mut current: Vec<(Value, String)> = mine
        .into_iter()
        .filter(|(record, record_root)| {
            record.get("status").and_then(Value::as_str) == Some("declared")
                && !cited.contains(record_root)
        })
        .collect();
    match current.len() {
        0 => Ok(None),
        1 => Ok(current.pop()),
        _ => Err(verr(
            "hypervisoros_node_artifact_mismatch",
            "two declared profiles both claim currency",
        )),
    }
}

pub(crate) fn load_node_attestation_source(data_dir: &str) -> Result<NodeAttestationSource, VErr> {
    let binding = local_estate_binding();
    let boot_profiles = enumerate_required_censused(data_dir, BOOT_PROFILE_DIR)?;
    let boot =
        current_declared_profile(&boot_profiles, "predecessor_boot_profile_root", &|value| {
            boot_profile_root(value)
        })?;
    let temporal_profiles = enumerate_required_censused(data_dir, TEMPORAL_PROFILE_DIR)?;
    let temporal =
        current_declared_profile(&temporal_profiles, "predecessor_profile_root", &|value| {
            temporal_profile_root(value)
        })?;
    let transitions = enumerate_required_censused(data_dir, NODE_TRANSITION_DIR)?;
    let loader = |record_root: &str| -> Result<Option<Value>, VErr> {
        load_required_exact(data_dir, NODE_RECORD_DIR, &tail("hvnr_", record_root)?)
    };
    let (records, head) =
        replay_node_attestation_transitions(&binding.estate_namespace, &transitions, &loader)?;
    let (boot_profile, boot_root) = match boot {
        Some((record, root)) => (Some(record), Some(root)),
        None => (None, None),
    };
    let (temporal_profile, temporal_root) = match temporal {
        Some((record, root)) => (Some(record), Some(root)),
        None => (None, None),
    };
    Ok(NodeAttestationSource {
        binding,
        boot_profile,
        boot_profile_root: boot_root,
        temporal_profile,
        temporal_profile_root: temporal_root,
        transitions,
        records,
        head,
    })
}

/// Resolve one node-evidence record by a declared ref from durable daemon
/// truth. The caller only ever names the ref; the body is resolved here.
fn load_node_evidence(data_dir: &str, ref_pointer: &str, reference: &str) -> Result<Value, VErr> {
    let mut matches: Vec<Value> = scan_local_family(data_dir, NODE_EVIDENCE_DIR)?
        .into_iter()
        .filter_map(|(_, value)| {
            (value.pointer(ref_pointer).and_then(Value::as_str) == Some(reference)).then_some(value)
        })
        .collect();
    match matches.len() {
        0 => Err(verr(
            "hypervisoros_node_evidence_not_found",
            format!("'{reference}' is not resolvable from durable node evidence"),
        )),
        1 => Ok(matches.pop().expect("one evidence record")),
        _ => Err(verr(
            "hypervisoros_node_artifact_mismatch",
            format!("'{reference}' resolves to more than one durable evidence record"),
        )),
    }
}

/// Resolve every durable enforcement-coverage declaration bound to the
/// declared enforcement profile (`INV-37`: refs derive from resolved
/// declarations, never the caller).
fn load_enforcement_declarations(
    data_dir: &str,
    node_enforcement_profile_ref: Option<&str>,
) -> Result<Vec<Value>, VErr> {
    let Some(profile_ref) = node_enforcement_profile_ref else {
        return Ok(Vec::new());
    };
    Ok(scan_local_family(data_dir, NODE_EVIDENCE_DIR)?
        .into_iter()
        .filter_map(|(_, value)| {
            (value.get("schema_version").and_then(Value::as_str)
                == Some(ENFORCEMENT_COVERAGE_SCHEMA_VERSION)
                && value
                    .pointer("/subject/profile_or_adapter_ref")
                    .and_then(Value::as_str)
                    == Some(profile_ref))
            .then_some(value)
        })
        .collect())
}

pub(crate) fn compile_from_source(
    op: NodeAttestationOp,
    source: &NodeAttestationSource,
    declaration: &NodeAttestationDeclaration,
    trusted_boot_receipt: Option<&Value>,
    trusted_temporal_evaluation: Option<&Value>,
    trusted_enforcement_declarations: &[Value],
) -> Result<CompiledNodeAttestationPlan, VErr> {
    let boot_profile = source.boot_profile.as_ref().ok_or_else(|| {
        verr(
            "hypervisoros_node_desired_profile_required",
            "no declared boot profile admits node-attestation operations",
        )
    })?;
    let temporal_profile = source.temporal_profile.as_ref().ok_or_else(|| {
        verr(
            "hypervisoros_node_desired_profile_required",
            "no declared temporal profile admits node-attestation operations",
        )
    })?;
    compile_node_attestation_plan(
        op,
        &source.binding,
        boot_profile,
        temporal_profile,
        &source.records,
        &source.head,
        declaration,
        trusted_boot_receipt,
        trusted_temporal_evaluation,
        trusted_enforcement_declarations,
        &ed25519_verifier,
    )
    .map_err(plan_err)
}

/// One fully built node-attestation step, every registered artifact
/// contract-validated inside the build itself.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NodeAttestationStepArtifacts {
    pub record: Value,
    pub committed_boot_receipt: Option<Value>,
    pub transition: Value,
    pub transition_root: String,
    pub receipt: Value,
    pub receipt_root: String,
    pub claim: Value,
    pub claim_tail: String,
}

/// Build the committed node-attestation graph without performing I/O. The
/// stamped revisions keep the exact timeless content roots the compiler
/// derived.
pub(crate) fn build_node_attestation_artifacts(
    plan: &CompiledNodeAttestationPlan,
    source: &NodeAttestationSource,
    authority: &DecisionAuthorityTuple,
    timestamp: &str,
) -> Result<NodeAttestationStepArtifacts, VErr> {
    let ns = required(&plan.authority_effect, "/estate_namespace")?;
    let mut record = plan.resulting_record.clone();
    record["last_transition_at"] = json!(timestamp);
    if plan.op == NodeAttestationOp::SubmitBootReceipt {
        record["attestation"]["verified_at"] = json!(timestamp);
    }
    if node_record_root(&record).map_err(plan_err)? != plan.resulting_record_root {
        return Err(verr(
            "hypervisoros_node_artifact_mismatch",
            "stamped record revision does not keep its timeless content root",
        ));
    }
    validate_contract(HYPERVISOROS_NODE_CONTRACT, &record, "node record")?;

    let committed_boot_receipt = match &plan.committed_boot_receipt {
        None => None,
        Some(receipt) => {
            let mut stamped = receipt.clone();
            stamped["verification"]["verified_at"] = json!(timestamp);
            let expected = plan.committed_boot_receipt_root.as_deref().ok_or_else(|| {
                verr(
                    "hypervisoros_node_artifact_mismatch",
                    "committed receipt root is absent from the plan",
                )
            })?;
            if boot_receipt_root(&stamped).map_err(plan_err)? != expected {
                return Err(verr(
                    "hypervisoros_node_artifact_mismatch",
                    "stamped boot receipt does not keep its timeless content root",
                ));
            }
            validate_contract(BOOT_RECEIPT_CONTRACT, &stamped, "committed boot receipt")?;
            Some(stamped)
        }
    };

    let transition_ref = format!(
        "hypervisoros-node-transition://{ns}/sequence/{}",
        plan.sequence
    );
    let receipt_ref = format!(
        "receipt://{ns}/hypervisoros/node-attestation/sequence/{}",
        plan.sequence
    );
    let mut authority_effect_material = plan.authority_effect.clone();
    authority_effect_material["operation_commitment"] = Value::Null;
    let transition = json!({
        "schema_version": "ioi.hypervisoros-node-transition.v1",
        "node_transition_id": transition_ref,
        "estate_namespace": ns,
        "op": plan.op.as_str(),
        "sequence": plan.sequence,
        "node_record_ref": plan.node_record_ref,
        "node_id": plan.node_id,
        "predecessor_node_set_root": plan.predecessor_node_set_root,
        "resulting_node_set_root": plan.resulting_node_set_root,
        "predecessor_record_root": plan.predecessor_record_root,
        "resulting_record_root": plan.resulting_record_root,
        "committed_boot_receipt_root": plan.committed_boot_receipt_root,
        "operation_commitment": plan.authority_effect["operation_commitment"],
        "authority_effect_material": authority_effect_material,
        "evidence_refs": plan.authority_effect["evidence_refs"],
        "authority_grant_refs": [authority.authority_grant_ref],
        "receipt_refs": [receipt_ref],
        "status": "committed",
    });
    let transition_root = artifact_root(TRANSITION_ARTIFACT_DOMAIN, &transition)?;

    let mut artifact_refs = vec![
        json!(format!(
            "artifact://hypervisoros-node-transition/{transition_root}"
        )),
        json!(format!(
            "artifact://hypervisoros-node-record/{}",
            plan.resulting_record_root
        )),
    ];
    if let Some(root) = plan.committed_boot_receipt_root.as_deref() {
        artifact_refs.push(json!(format!(
            "artifact://hypervisoros-boot-receipt/{root}"
        )));
    }
    let receipt = json!({
        "receipt_id": receipt_ref,
        "receipt_type": "hypervisoros_node_attestation",
        "receipt_profile_ref": RECEIPT_CONTRACT,
        "attested_boundary_fact_refs": [
            plan.node_record_ref,
            plan.node_id,
            transition_ref,
            authority.authority_evidence_ref,
        ],
        "claim_scope_ref": "policy://hypervisoros/node-attestation",
        "run_id": Value::Null,
        "task_id": Value::Null,
        "actor_id": "runtime://hypervisor-runtime",
        "authority_grant_id": authority.authority_grant_ref,
        "primitive_capabilities": [],
        "authority_scopes": [plan.op.required_scope()],
        "artifact_refs": artifact_refs,
        "evidence_bundle_refs": [],
        "verification_ref": Value::Null,
        "acceptance_ref": Value::Null,
        "adjudication_ref": Value::Null,
        "settlement_ref": Value::Null,
        "timestamp": timestamp,
        "signature": Value::Null,
        "public_commitment_ref": Value::Null,
        "input_hash": authority.input_hash,
        "output_hash": plan.resulting_node_set_root,
        "policy_hash": authority.policy_hash,
    });
    validate_contract(RECEIPT_CONTRACT, &receipt, "node-attestation receipt")?;
    let receipt_root = artifact_root(RECEIPT_ARTIFACT_DOMAIN, &receipt)?;

    let claim_tail = tail("hvnsc_", &plan.predecessor_node_set_root)?;
    let claim = json!({
        "schema_version": "ioi.hypervisor.hypervisoros-node-successor-claim.v1",
        "claim_ref": format!(
            "hypervisoros-node-successor-claim://{}",
            plan.predecessor_node_set_root
        ),
        "estate_namespace": ns,
        "sequence": plan.sequence,
        "predecessor_node_set_root": plan.predecessor_node_set_root,
        "resulting_node_set_root": plan.resulting_node_set_root,
        "transition_ref": transition_ref,
        "op": plan.op.as_str(),
        "committed_at": timestamp,
    });
    let _ = source; // bound by the compile step; retained for parity
    Ok(NodeAttestationStepArtifacts {
        record,
        committed_boot_receipt,
        transition,
        transition_root,
        receipt,
        receipt_root,
        claim,
        claim_tail,
    })
}

fn persist_node_attestation_graph(
    data_dir: &str,
    plan: &CompiledNodeAttestationPlan,
    artifacts: &NodeAttestationStepArtifacts,
    evidence: &super::system_activation_routes::NodeAdmissionEvidence,
    wallet_consumption: &Value,
) -> Result<(), VErr> {
    // One successor per predecessor node set root: the expected-absent
    // Agentgres admission is the cross-process CAS boundary.
    persist_local(
        data_dir,
        NODE_CLAIM_DIR,
        &artifacts.claim_tail,
        &artifacts.claim,
    )
    .map_err(|(code, message)| {
        if code == "system_lifecycle_conflict" {
            verr("hypervisoros_node_head_conflict", message)
        } else {
            (code, message)
        }
    })?;
    super::substrate_store::admit_required(
        data_dir,
        NODE_CLAIM_DIR,
        &artifacts.claim_tail,
        &artifacts.claim,
    )
    .map_err(|error| {
        let code = if error.kind() == std::io::ErrorKind::AlreadyExists {
            "hypervisoros_node_head_conflict"
        } else {
            "hypervisoros_node_agentgres_admission_failed"
        };
        verr(code, format!("durable node claim failed ({error})"))
    })?;
    if load_required_exact(data_dir, NODE_CLAIM_DIR, &artifacts.claim_tail)?.as_ref()
        != Some(&artifacts.claim)
    {
        return Err(verr(
            "hypervisoros_node_head_conflict",
            "durable node predecessor claim belongs to a different successor",
        ));
    }
    let consumption: ioi_services::wallet_network::ApprovalGrantConsumptionReceipt =
        serde_json::from_value(wallet_consumption.clone()).map_err(|error| {
            verr(
                "system_lifecycle_wallet_consumption_invalid",
                error.to_string(),
            )
        })?;
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
            NODE_RECORD_DIR,
            tail("hvnr_", &plan.resulting_record_root)?,
            &artifacts.record,
        ),
        (
            NODE_TRANSITION_DIR,
            tail("hvnt_", &artifacts.transition_root)?,
            &artifacts.transition,
        ),
        (
            NODE_PLANE_RECEIPT_DIR,
            tail("hvnar_", &artifacts.receipt_root)?,
            &artifacts.receipt,
        ),
    ];
    if let (Some(receipt), Some(root)) = (
        artifacts.committed_boot_receipt.as_ref(),
        plan.committed_boot_receipt_root.as_deref(),
    ) {
        records.push((BOOT_RECEIPT_DIR, tail("hvbr_", root)?, receipt));
    }
    for (family, record_tail, value) in records {
        persist_local(data_dir, family, &record_tail, value)?;
        super::substrate_store::admit_required(data_dir, family, &record_tail, value).map_err(
            |error| {
                verr(
                    "hypervisoros_node_agentgres_admission_failed",
                    format!("required admission for '{family}/{record_tail}' failed ({error})"),
                )
            },
        )?;
        let loaded = load_required_exact(data_dir, family, &record_tail)?.ok_or_else(|| {
            verr(
                "hypervisoros_node_persist_failed",
                "node-attestation artifact did not converge",
            )
        })?;
        if loaded != *value {
            return Err(verr(
                "hypervisoros_node_persist_failed",
                "node-attestation artifact diverged",
            ));
        }
    }
    Ok(())
}

const DECLARATION_FIELDS: &[&str] = &[
    "node_id",
    "expected_node_set_root",
    "evidence_refs",
    "node_owner_ref",
    "sealed_identity",
    "node_enforcement_profile_ref",
    "measurement_policy_ref",
    "ctee_policy_ref",
    "supported_worker_substrates",
    "supported_mount_profiles",
    "boot_receipt_ref",
    "temporal_validity_evaluation_ref",
];

fn declaration_from_body(body: &Value) -> Result<NodeAttestationDeclaration, VErr> {
    let mut value = serde_json::Map::new();
    for key in DECLARATION_FIELDS {
        if let Some(field) = body.get(*key) {
            value.insert((*key).to_owned(), field.clone());
        }
    }
    serde_json::from_value(Value::Object(value))
        .map_err(|error| verr("hypervisoros_node_request_invalid", error.to_string()))
}

fn validate_request(body: &Value, allowed: &[&str]) -> Result<(), VErr> {
    let encoded = serde_json::to_vec(body)
        .map_err(|error| verr("hypervisoros_node_request_invalid", error.to_string()))?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(verr(
            "hypervisoros_node_request_oversize",
            "request exceeds 512 KiB",
        ));
    }
    if contains_sensitive_key(body) {
        return Err(verr(
            "hypervisoros_node_sensitive_field_rejected",
            "secret-bearing keys are forbidden recursively",
        ));
    }
    let object = body.as_object().ok_or_else(|| {
        verr(
            "hypervisoros_node_request_invalid",
            "request must be an object",
        )
    })?;
    if let Some(key) = object
        .keys()
        .find(|key| !allowed.contains(&key.as_str()) && key.as_str() != "wallet_approval_grant")
    {
        return Err(verr(
            "hypervisoros_node_request_field_unknown",
            format!("undeclared request field '{key}' is forbidden"),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_no_pending_node_attestation_intent(data_dir: &str) -> Result<(), VErr> {
    for (_tail, intent) in scan_local_family(data_dir, NODE_INTENT_DIR)? {
        verify_intent_seal(&intent)?;
        return Err(verr(
            "system_lifecycle_pending_convergence",
            "a node-attestation transition is pending convergence",
        ));
    }
    Ok(())
}

fn resolve_trusted_inputs(
    data_dir: &str,
    op: NodeAttestationOp,
    declaration: &NodeAttestationDeclaration,
) -> Result<(Option<Value>, Option<Value>, Vec<Value>), VErr> {
    let receipt = match (op, declaration.boot_receipt_ref.as_deref()) {
        (NodeAttestationOp::SubmitBootReceipt, Some(reference)) => {
            Some(load_node_evidence(data_dir, "/receipt_id", reference)?)
        }
        _ => None,
    };
    let evaluation = match (op, declaration.temporal_validity_evaluation_ref.as_deref()) {
        (
            NodeAttestationOp::SubmitBootReceipt | NodeAttestationOp::MarkNodeReady,
            Some(reference),
        ) => Some(load_node_evidence(data_dir, "/evaluation_id", reference)?),
        _ => None,
    };
    let enforcement = match op {
        NodeAttestationOp::AdmitNodeIdentity => load_enforcement_declarations(
            data_dir,
            declaration.node_enforcement_profile_ref.as_deref(),
        )?,
        _ => Vec::new(),
    };
    Ok((receipt, evaluation, enforcement))
}

/// For MarkNodeReady the bound verified receipt itself is durable truth.
fn resolve_bound_receipt(
    data_dir: &str,
    source: &NodeAttestationSource,
    declaration: &NodeAttestationDeclaration,
) -> Result<Option<Value>, VErr> {
    let Some(record) = source.records.iter().find(|record| {
        record.get("node_id").and_then(Value::as_str) == Some(declaration.node_id.as_str())
    }) else {
        return Ok(None);
    };
    let Some(root) = record
        .pointer("/attestation/boot_receipt_root")
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    load_required_exact(data_dir, BOOT_RECEIPT_DIR, &tail("hvbr_", root)?)
}

/// POST /v1/hypervisor/hypervisoros/nodes/transitions/:op
pub(crate) async fn handle_node_transition(
    AxumPath(op_name): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(op) = NodeAttestationOp::parse(&op_name) else {
        return classify(verr(
            "hypervisoros_node_operation_not_found",
            "unknown node-attestation op",
        ));
    };
    if let Err(error) = validate_request(&body, DECLARATION_FIELDS) {
        return classify(error);
    }
    let declaration = match declaration_from_body(&body) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let source = match with_source_locks(|| {
        ensure_no_pending_node_attestation_intent(&state.data_dir)?;
        load_node_attestation_source(&state.data_dir)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let (mut receipt_input, evaluation, enforcement) =
        match resolve_trusted_inputs(&state.data_dir, op, &declaration) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    if op == NodeAttestationOp::MarkNodeReady {
        receipt_input = match resolve_bound_receipt(&state.data_dir, &source, &declaration) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    }
    let plan = match compile_from_source(
        op,
        &source,
        &declaration,
        receipt_input.as_ref(),
        evaluation.as_ref(),
        &enforcement,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    // The governed authority is the node owner: for admission the declared
    // owner (whose control wallet.network resolution itself proves); for
    // later steps the owner already durable on the admitted record.
    let governing = match required(&plan.authority_effect, "/node_owner_ref") {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let estate_namespace = source.binding.estate_namespace.clone();
    let authorized = match governed::authorize_decision_with_context(
        AUTHORITY,
        &body,
        Governance::Host,
        AuthorityPolicyContext::HypervisorOsNode {
            estate_namespace: &estate_namespace,
            node_id: &plan.node_id,
        },
        &governing,
        &plan.node_record_ref,
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
        &plan.resulting_node_set_root,
        authorized,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if let Err(error) = preflight_chain_writer_grant(&evidence.wallet_params).await {
        return classify(error);
    }
    let intent_tail = match tail("hvnti_", &evidence.authorized.evidence.request_hash) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent = match with_source_locks(|| {
        let fresh = load_node_attestation_source(&state.data_dir)?;
        let recompiled = compile_from_source(
            op,
            &fresh,
            &declaration,
            receipt_input.as_ref(),
            evaluation.as_ref(),
            &enforcement,
        )?;
        if recompiled != plan {
            return Err(verr(
                "hypervisoros_node_head_conflict",
                "durable truth changed between authorization and intent sealing",
            ));
        }
        let intent = intent_seal(json!({
            "schema_version": "ioi.hypervisor.hypervisoros-node-transition-intent.v1",
            "source_record_tail": "local",
            "op": op.as_str(),
            "request_body": body,
            "compiled_plan": plan,
            "governed_authority": evidence_intent_value(&evidence),
            "intent_hash": Value::Null,
        }))?;
        persist_local(&state.data_dir, NODE_INTENT_DIR, &intent_tail, &intent)?;
        Ok::<_, VErr>(intent)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if forced_fault("IOI_TEST_FORCE_HYPERVISOROS_NODE_AFTER_INTENT", op.as_str()) {
        return classify(verr(
            "system_lifecycle_pending_convergence",
            "test-forced interruption after durable node-attestation intent",
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
                    remove_intent(&state.data_dir, NODE_INTENT_DIR, &intent_tail)
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
        "IOI_TEST_FORCE_HYPERVISOROS_NODE_AFTER_WALLET_CONSUMPTION",
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
    let artifacts = match build_node_attestation_artifacts(&plan, &source, &tuple, &timestamp) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let result = with_source_locks(|| {
        let stored =
            load_local(&state.data_dir, NODE_INTENT_DIR, &intent_tail)?.ok_or_else(|| {
                verr(
                    "system_lifecycle_pending_convergence",
                    "node-attestation intent vanished",
                )
            })?;
        verify_intent_seal(&stored)?;
        if stored != intent {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                "durable node-attestation intent changed",
            ));
        }
        persist_node_attestation_graph(
            &state.data_dir,
            &plan,
            &artifacts,
            &evidence,
            &wallet_value,
        )?;
        remove_intent(&state.data_dir, NODE_INTENT_DIR, &intent_tail)
    });
    if let Err(error) = result {
        return classify(error);
    }
    (
        StatusCode::OK,
        Json(json!({
            "op": op.as_str(),
            "sequence": plan.sequence,
            "node_record": artifacts.record,
            "node_transition": artifacts.transition,
            "receipt": artifacts.receipt,
            "committed_boot_receipt": artifacts.committed_boot_receipt,
            "node_set_root": plan.resulting_node_set_root,
            "nonclaims": {
                "system_authority": false,
                "membership": false,
                "plaintext_privacy": false,
                "ready_before_proof": false,
                "writer": false
            }
        })),
    )
}

/// Read-only node-attestation eligibility projection. This never fabricates
/// eligibility: the profile gate is reported separately from declaration
/// evidence and wallet authority a future POST must still supply.
pub(crate) async fn handle_get_node_transition(
    AxumPath(op_name): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    let Some(op) = NodeAttestationOp::parse(&op_name) else {
        return classify(verr(
            "hypervisoros_node_operation_not_found",
            "unknown node-attestation op",
        ));
    };
    match with_source_locks(|| {
        ensure_no_pending_node_attestation_intent(&state.data_dir)?;
        let source = load_node_attestation_source(&state.data_dir)?;
        let mut blockers = Vec::new();
        if source.boot_profile.is_none() {
            blockers.push(json!({"code":"boot_profile_undeclared"}));
        }
        if source.temporal_profile.is_none() {
            blockers.push(json!({"code":"temporal_profile_undeclared"}));
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
                "expected_node_set_root": true,
                "node_identity_in_estate_namespace": true,
                "public_sealed_identity_binding": op == NodeAttestationOp::AdmitNodeIdentity,
                "resolved_boot_receipt_observation": op == NodeAttestationOp::SubmitBootReceipt,
                "resolved_temporal_evaluation": matches!(
                    op,
                    NodeAttestationOp::SubmitBootReceipt | NodeAttestationOp::MarkNodeReady
                ),
            },
            "attestation_head": {
                "sequence": source.head.sequence,
                "node_set_root": source.head.node_set_root,
            },
            "live_nodes": source.records.iter().map(|record| json!({
                "node_id": record["node_id"],
                "status": record["status"],
            })).collect::<Vec<_>>(),
            "committed_entries": committed.len(),
            "nonclaims": {"wallet_authorized": false, "system_authority": false, "readiness": false}
        }))
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

/// Pure desired-versus-observed projection over durable truth only.
/// Divergence is labeled, never reconciled; absence is honest, never
/// fabricated; readiness is derived, never asserted.
pub(crate) fn build_node_attestation_projection(
    estate_namespace: &str,
    boot_profile: Option<(&Value, &str)>,
    temporal_profile: Option<(&Value, &str)>,
    records: &[Value],
    head: &NodeAttestationLogHead,
    load_receipt: &dyn Fn(&str) -> Result<Option<Value>, VErr>,
) -> Result<Value, VErr> {
    let mut members: Vec<&Value> = records.iter().collect();
    members.sort_by_key(|record| {
        record
            .get("node_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    });
    let current_profile_root = boot_profile.map(|(_, root)| root.to_owned());
    let mut observed_nodes = Vec::new();
    for record in &members {
        let bound_root = record
            .get("boot_profile_root")
            .and_then(Value::as_str)
            .unwrap_or("");
        let receipt = match record
            .pointer("/attestation/boot_receipt_root")
            .and_then(Value::as_str)
        {
            None => None,
            Some(root) => load_receipt(root)?,
        };
        let readiness = ioi_types::app::hypervisoros_node_attestation::derive_node_readiness(
            record,
            receipt.as_ref(),
        );
        observed_nodes.push(json!({
            "node_id": record["node_id"],
            "node_record_id": record["node_record_id"],
            "status": record["status"],
            "boot_profile_root": bound_root,
            "profile_binding_current": current_profile_root.as_deref() == Some(bound_root),
            "verified_boot_epoch": record["attestation"]["verified_boot_epoch"],
            "verified_rollback_counter": record["attestation"]["verified_rollback_counter"],
            "readiness_derivable": readiness.is_ok(),
            "readiness_blocker": match readiness {
                Ok(_) => Value::Null,
                Err(reason) => json!(reason),
            },
            "record_root": node_record_root(record).map_err(plan_err)?,
        }));
    }
    let divergence = match &current_profile_root {
        None => Value::Null,
        Some(root) => {
            let mut rows = Vec::new();
            for node in &observed_nodes {
                if node["profile_binding_current"] != json!(true) {
                    rows.push(json!({
                        "kind": "superseded_profile_binding",
                        "node_id": node["node_id"],
                        "bound_profile_root": node["boot_profile_root"],
                        "current_profile_root": root,
                        "satisfied": false,
                    }));
                }
            }
            Value::Array(rows)
        }
    };
    Ok(json!({
        "schema_version": "ioi.hypervisor.hypervisoros-node-attestation-projection.v1",
        "estate_namespace": estate_namespace,
        "state": if records.is_empty() && boot_profile.is_none() { "honest_empty" } else { "ready" },
        "desired": {
            "boot_profile": boot_profile.map(|(profile, root)| json!({
                "boot_profile": profile,
                "boot_profile_root": root,
            })).unwrap_or(Value::Null),
            "temporal_profile": temporal_profile.map(|(profile, root)| json!({
                "temporal_profile": profile,
                "temporal_profile_record_root": root,
            })).unwrap_or(Value::Null),
        },
        "boot_profile_undeclared": boot_profile.is_none(),
        "temporal_profile_undeclared": temporal_profile.is_none(),
        "observed": {
            "node_set_root": head.node_set_root,
            "sequence": head.sequence,
            "nodes": observed_nodes,
        },
        "divergence": divergence,
        "projection_source": "durable_owner_reconstruction",
        "nonclaims": {
            "desired_asserts_observed": false,
            "observed_asserts_desired": false,
            "system_authority": false,
            "membership": false,
            "plaintext_privacy": false,
            "ready_before_proof": false
        }
    }))
}

/// GET /v1/hypervisor/hypervisoros/nodes/projection
pub(crate) async fn handle_get_node_projection(
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    match with_source_locks(|| {
        let source = load_node_attestation_source(&state.data_dir)?;
        let loader = |root: &str| -> Result<Option<Value>, VErr> {
            load_required_exact(&state.data_dir, BOOT_RECEIPT_DIR, &tail("hvbr_", root)?)
        };
        build_node_attestation_projection(
            &source.binding.estate_namespace,
            source
                .boot_profile
                .as_ref()
                .zip(source.boot_profile_root.as_deref()),
            source
                .temporal_profile
                .as_ref()
                .zip(source.temporal_profile_root.as_deref()),
            &source.records,
            &source.head,
            &loader,
        )
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

/// Build the CAS declaration plan for one desired profile family.
fn build_profile_declaration_plan(
    source: &NodeAttestationSource,
    body: &Value,
    family: ProfileFamily,
) -> Result<Value, VErr> {
    let (field, contract, predecessor_field, current_root, op, scope) = match family {
        ProfileFamily::Boot => (
            "boot_profile",
            BOOT_PROFILE_CONTRACT,
            "predecessor_boot_profile_root",
            source.boot_profile_root.as_deref(),
            DECLARE_BOOT_PROFILE_OP,
            DECLARE_BOOT_PROFILE_SCOPE,
        ),
        ProfileFamily::Temporal => (
            "temporal_profile",
            TEMPORAL_PROFILE_CONTRACT,
            "predecessor_profile_root",
            source.temporal_profile_root.as_deref(),
            DECLARE_TEMPORAL_PROFILE_OP,
            DECLARE_TEMPORAL_PROFILE_SCOPE,
        ),
    };
    let profile = body.get(field).cloned().ok_or_else(|| {
        verr(
            "hypervisoros_node_request_invalid",
            format!("request lacks its {field} body"),
        )
    })?;
    validate_contract(contract, &profile, field)?;
    if profile.get("status").and_then(Value::as_str) != Some("declared") {
        return Err(verr(
            "hypervisoros_node_plan_invalid",
            "a declaration must carry status 'declared'",
        ));
    }
    if profile.get(predecessor_field).and_then(Value::as_str) != current_root {
        return Err(verr(
            "hypervisoros_node_head_conflict",
            "profile declaration does not compare-and-swap the current record",
        ));
    }
    let root = match family {
        ProfileFamily::Boot => boot_profile_root(&profile).map_err(plan_err)?,
        ProfileFamily::Temporal => temporal_profile_root(&profile).map_err(plan_err)?,
    };
    match family {
        ProfileFamily::Boot => {
            // The boot profile binds the exact declared temporal profile.
            let temporal = source.temporal_profile.as_ref().ok_or_else(|| {
                verr(
                    "hypervisoros_node_desired_profile_required",
                    "a boot profile requires the declared temporal profile it binds",
                )
            })?;
            if profile
                .get("temporal_verification_profile_ref")
                .and_then(Value::as_str)
                != temporal.get("profile_ref").and_then(Value::as_str)
                || profile
                    .get("temporal_verification_profile_hash")
                    .and_then(Value::as_str)
                    != temporal.get("profile_hash").and_then(Value::as_str)
            {
                return Err(verr(
                    "hypervisoros_node_plan_invalid",
                    "boot profile is not bound to the declared temporal profile",
                ));
            }
            // Rollback floor never decreases across declarations.
            if let Some(previous) = source.boot_profile.as_ref() {
                let previous_floor = previous
                    .pointer("/update_policy/rollback_floor/minimum_version_counter")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let next_floor = profile
                    .pointer("/update_policy/rollback_floor/minimum_version_counter")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if next_floor < previous_floor {
                    return Err(verr(
                        "hypervisoros_node_plan_invalid",
                        "the rollback floor never decreases across boot profile declarations",
                    ));
                }
            }
        }
        ProfileFamily::Temporal => {}
    }
    let owner = match family {
        ProfileFamily::Boot => required(&profile, "/owner_ref")?,
        // The temporal profile carries no owner field; the estate daemon
        // owner governs its declaration.
        ProfileFamily::Temporal => "wallet://hypervisor/local-estate-owner".to_owned(),
    };
    let sequence = source
        .head
        .sequence
        .checked_add(1)
        .ok_or_else(|| verr("hypervisoros_node_plan_invalid", "sequence overflow"))?;
    let mut effect = json!({
        "schema_version": "ioi.hypervisoros-node-profile-declaration-effect.v1",
        "op": op,
        "required_scope": scope,
        "sequence": sequence,
        "estate_namespace": source.binding.estate_namespace,
        "daemon_ref": source.binding.daemon_ref,
        "profile_kind": field,
        "profile_root": root,
        "predecessor_profile_root": current_root,
        "owner_ref": owner,
        "asserts_observed_measurement": false,
        "operation_commitment": Value::Null,
    });
    let operation_commitment = jcs_hash(&json!({
        "domain": "ioi.hypervisoros-node-profile-declaration-commitment-jcs-sha256.v1",
        "effect": effect,
    }))?;
    effect["operation_commitment"] = json!(operation_commitment);
    Ok(json!({
        "profile": profile,
        "profile_root": root,
        "owner_ref": owner,
        "authority_effect": effect,
    }))
}

#[derive(Clone, Copy, PartialEq)]
enum ProfileFamily {
    Boot,
    Temporal,
}

async fn handle_declare_profile(
    state: Arc<DaemonState>,
    body: Value,
    family: ProfileFamily,
) -> (StatusCode, Json<Value>) {
    let (field, family_dir, prefix, op, scope) = match family {
        ProfileFamily::Boot => (
            "boot_profile",
            BOOT_PROFILE_DIR,
            "hvbp_",
            DECLARE_BOOT_PROFILE_OP,
            DECLARE_BOOT_PROFILE_SCOPE,
        ),
        ProfileFamily::Temporal => (
            "temporal_profile",
            TEMPORAL_PROFILE_DIR,
            "hvtp_",
            DECLARE_TEMPORAL_PROFILE_OP,
            DECLARE_TEMPORAL_PROFILE_SCOPE,
        ),
    };
    if let Err(error) = validate_request(&body, &[field]) {
        return classify(error);
    }
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let (source, plan) = match with_source_locks(|| {
        ensure_no_pending_node_attestation_intent(&state.data_dir)?;
        let source = load_node_attestation_source(&state.data_dir)?;
        let plan = build_profile_declaration_plan(&source, &body, family)?;
        Ok::<_, VErr>((source, plan))
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let effect = plan["authority_effect"].clone();
    let governing = required(&plan, "/owner_ref").unwrap_or_default();
    let profile_root = required(&plan, "/profile_root").unwrap_or_default();
    let sequence = effect.get("sequence").and_then(Value::as_u64).unwrap_or(1);
    let estate_namespace = source.binding.estate_namespace.clone();
    let authorized = match governed::authorize_decision_with_context(
        AUTHORITY,
        &body,
        Governance::Host,
        AuthorityPolicyContext::HypervisorOsNode {
            estate_namespace: &estate_namespace,
            node_id: &profile_root,
        },
        &governing,
        &profile_root,
        op,
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
        op,
        sequence,
        scope,
        &governing,
        &profile_root,
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
    let profile = plan["profile"].clone();
    let result = with_source_locks(|| {
        // Recheck the CAS under the lock: the declaration must still swap
        // the exact current record.
        let fresh = load_node_attestation_source(&state.data_dir)?;
        if build_profile_declaration_plan(&fresh, &body, family)? != plan {
            return Err(verr(
                "hypervisoros_node_head_conflict",
                "durable declared profile changed before commitment",
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
            (family_dir, tail(prefix, &profile_root)?, &profile),
        ];
        for (family_name, record_tail, value) in records {
            persist_local(&state.data_dir, family_name, &record_tail, value)?;
            super::substrate_store::admit_required(
                &state.data_dir,
                family_name,
                &record_tail,
                value,
            )
            .map_err(|error| {
                verr(
                    "hypervisoros_node_agentgres_admission_failed",
                    format!(
                        "required admission for '{family_name}/{record_tail}' failed ({error})"
                    ),
                )
            })?;
            if load_required_exact(&state.data_dir, family_name, &record_tail)?.as_ref()
                != Some(value)
            {
                return Err(verr(
                    "hypervisoros_node_persist_failed",
                    "declared profile graph did not converge byte-exactly",
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
            "op": op,
            field: profile,
            "profile_root": profile_root,
            "nonclaims": {
                "observed_measurement": false,
                "node_admission": false,
                "readiness": false,
                "system_authority": false
            }
        })),
    )
}

/// POST /v1/hypervisor/hypervisoros/nodes/boot-profile
pub(crate) async fn handle_declare_boot_profile(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    handle_declare_profile(state, body, ProfileFamily::Boot).await
}

/// POST /v1/hypervisor/hypervisoros/nodes/temporal-profile
pub(crate) async fn handle_declare_temporal_profile(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    handle_declare_profile(state, body, ProfileFamily::Temporal).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::crypto::{SerializableKey, SigningKeyPair};
    use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
    use ioi_types::app::hypervisoros_node_attestation::{
        derive_node_readiness, identity_key_commitment,
    };
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

    fn keypair(seed: u8) -> Ed25519KeyPair {
        let private_key = Ed25519PrivateKey::from_bytes(&[seed; 32]).expect("private key");
        Ed25519KeyPair::from_private_key(&private_key).expect("keypair")
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

    fn binding() -> NodeEstateBinding {
        NodeEstateBinding {
            estate_namespace: "acme/estate-1".into(),
            daemon_ref: "runtime://acme/estate-1/daemon".into(),
            agentgres_domain_ref: "agentgres://domain/acme/estate-1".into(),
        }
    }

    fn boot_profile() -> Value {
        fixture("hypervisoros-boot-profile-v1/positive-declared.json")
    }

    fn temporal_profile() -> Value {
        fixture("temporal-verification-profile-v1/positive-declared.json")
    }

    fn source_with(records: Vec<Value>, head: NodeAttestationLogHead) -> NodeAttestationSource {
        let boot = boot_profile();
        let boot_root = boot_profile_root(&boot).expect("boot root");
        let temporal = temporal_profile();
        let temporal_root = temporal_profile_root(&temporal).expect("temporal root");
        NodeAttestationSource {
            binding: binding(),
            boot_profile: Some(boot),
            boot_profile_root: Some(boot_root),
            temporal_profile: Some(temporal),
            temporal_profile_root: Some(temporal_root),
            transitions: Vec::new(),
            records,
            head,
        }
    }

    fn head_for(records: &[Value], sequence: u64) -> NodeAttestationLogHead {
        NodeAttestationLogHead {
            sequence,
            node_set_root: node_set_root("acme/estate-1", records).expect("set root"),
        }
    }

    const NODE: &str = "runtime://acme/estate-1/alpha-node-1";

    fn base_declaration(records: &[Value]) -> NodeAttestationDeclaration {
        NodeAttestationDeclaration {
            node_id: NODE.into(),
            expected_node_set_root: node_set_root("acme/estate-1", records).expect("set root"),
            evidence_refs: vec![],
            node_owner_ref: None,
            sealed_identity: None,
            node_enforcement_profile_ref: None,
            measurement_policy_ref: None,
            ctee_policy_ref: None,
            supported_worker_substrates: vec![],
            supported_mount_profiles: vec![],
            boot_receipt_ref: None,
            temporal_validity_evaluation_ref: None,
        }
    }

    fn admit_declaration(pair: &Ed25519KeyPair, records: &[Value]) -> NodeAttestationDeclaration {
        let public_key = hex_encode(&pair.public_key().to_bytes());
        NodeAttestationDeclaration {
            node_owner_ref: Some("wallet://acme/node-owner".into()),
            sealed_identity: Some(json!({
                "key_suite": "ed25519",
                "identity_public_key": public_key,
                "identity_key_commitment": identity_key_commitment("ed25519", &public_key)
                    .expect("commitment"),
                "sealed_identity_alias": "vault://acme/node-identity/alpha-node-1",
                "sealing_receipt_ref": "receipt://acme/vault/seal/alpha-node-1",
            })),
            node_enforcement_profile_ref: Some("node-enforcement://acme/estate-1/default".into()),
            measurement_policy_ref: Some("measurement-policy://acme/estate-1/default".into()),
            ctee_policy_ref: Some("policy://acme/estate-1/ctee".into()),
            supported_worker_substrates: vec!["microvm".into(), "container".into()],
            supported_mount_profiles: vec![
                "public_mount".into(),
                "plaintext_free_model_mount".into(),
            ],
            evidence_refs: vec!["evidence://acme/estate-1/admit/alpha-node-1".into()],
            ..base_declaration(records)
        }
    }

    fn verified_ecd() -> Value {
        let mut declaration =
            fixture("enforcement-coverage-declaration-v1/positive-active-enforcement.json");
        declaration["subject"]["profile_or_adapter_ref"] =
            json!("node-enforcement://acme/estate-1/default");
        declaration
    }

    fn observed_receipt(pair: &Ed25519KeyPair, boot_epoch: u64, counter: u64) -> Value {
        let profile = boot_profile();
        let profile_root = boot_profile_root(&profile).expect("profile root");
        let temporal = temporal_profile();
        let mut receipt = json!({
            "schema_version": "ioi.components.daemon-runtime.hypervisoros-boot-receipt.v1",
            "receipt_id": format!("receipt://acme/estate-1/boot/alpha-node-1/{boot_epoch}"),
            "node_id": NODE,
            "node_record_ref": "hypervisoros-node://acme/estate-1/node/alpha-node-1",
            "observation": {
                "boot_epoch": boot_epoch,
                "boot_profile_ref": profile["boot_profile_id"],
                "boot_profile_root": profile_root,
                "workload_identity": "workload://acme/estate-1/alpha-node-1/daemon",
                "image_hash": profile["image_hash"],
                "daemon_binary_hash": profile["daemon_binary_hash"],
                "policy_build_hash": h(0x2b),
                "package_manifest_hash": profile["package_manifest_hash"],
                "driver_manifest_hash": profile["driver_manifest_hash"],
                "measurement_method": "tpm_quote",
                "privacy_claim": "none",
                "quote_evidence_refs": [
                    format!("attestation://acme/estate-1/alpha-node-1/quote/{boot_epoch}")
                ],
                "attestation_assurance": {
                    "attester_ref": NODE,
                    "verifier_ref": "verifier://acme/estate-1/appraiser-service",
                    "appraiser_ref": "appraiser://acme/estate-1/appraiser-service",
                    "relying_party_ref": "runtime://acme/estate-1/daemon",
                    "nonce": "9f2c4d6e8a0b1c2d3e4f5a6b",
                    "nonce_single_use_status": "consumed_for_this_appraisal",
                    "nonce_consumption_receipt_ref": "receipt://acme/estate-1/nonce/42",
                    "endorsement_refs": ["endorsement://acme/tpm-vendor/root"],
                    "reference_value_refs": ["reference://acme/estate-1/pcr-baseline"],
                    "appraisal_policy_ref": "policy://acme/estate-1/appraisal",
                    "appraisal_result_ref": format!("appraisal://acme/estate-1/alpha-node-1/{boot_epoch}"),
                    "appraisal_status": "pass",
                    "appraised_at": "2026-07-27T12:00:00Z",
                    "appraisal_expires_at": "2026-07-27T12:10:00Z",
                    "effective_posture": "measured_boot",
                    "hardware_or_measured_attested": true,
                    "lease_ref": Value::Null,
                    "lease_expires_at": Value::Null,
                    "revocation_epoch": 12,
                    "revocation_status": "current",
                    "revocation_check_receipt_ref": "receipt://acme/estate-1/revocation/12",
                    "reattest_by": "2026-07-28T12:00:00Z",
                },
                "rollback_state": {
                    "observed_version_counter": counter,
                    "observed_image_head_hash": profile["image_hash"],
                },
                "temporal_state": {
                    "temporal_verification_profile_ref": temporal["profile_ref"],
                    "temporal_verification_profile_hash": temporal["profile_hash"],
                    "rollback_domain_ref": "failure-domain://acme/estate-1/node-local",
                    "continuity_floor_evidence_refs": [
                        "evidence://acme/estate-1/anchor/operator/9"
                    ],
                },
            },
            "verification": {
                "verdict": "unverified",
                "verified_against_boot_profile_root": profile_root,
                "temporal_validity_evaluation_ref": Value::Null,
                "temporal_validity_evaluation_hash": Value::Null,
                "evaluated_temporal_posture": Value::Null,
                "refusal_codes": [],
                "verified_at": Value::Null,
            },
            "signature": {
                "key_suite": "ed25519",
                "signer_public_key": hex_encode(&pair.public_key().to_bytes()),
                "signed_material_hash": Value::Null,
                "signature": "00".repeat(64),
            },
            "note": "Boot measurement is an integrity receipt, not a consumer-GPU plaintext privacy guarantee.",
        });
        let material =
            ioi_types::app::hypervisoros_node_attestation::boot_receipt_signed_material_hash(
                &receipt,
            )
            .expect("signed material");
        let signature = pair.sign(material.as_bytes()).expect("sign").to_bytes();
        receipt["signature"]["signed_material_hash"] = json!(material);
        receipt["signature"]["signature"] = json!(hex_encode(&signature));
        receipt
    }

    fn fresh_evaluation(receipt: &Value) -> Value {
        let temporal = temporal_profile();
        let mut evaluation = json!({
            "schema_version": "ioi.components.daemon-runtime.temporal-validity-evaluation.v1",
            "evaluation_id": "temporal-evaluation://acme/estate-1/boot/42",
            "profile_ref": temporal["profile_ref"],
            "profile_hash": temporal["profile_hash"],
            "subject_ref": receipt["receipt_id"],
            "subject_hash": receipt["signature"]["signed_material_hash"],
            "operation_class": "boot_verification",
            "evidence_refs": [
                "evidence://acme/estate-1/time/authenticated-ntp/42",
                "evidence://acme/estate-1/anchor/operator/9"
            ],
            "source_failure_domain_refs": [
                "failure-domain://acme/estate-1/ntp",
                "failure-domain://acme/operator"
            ],
            "claims": [
                {
                    "kind": "challenge_freshness",
                    "status": "established",
                    "challenge_ref": "challenge://acme/estate-1/boot/42",
                    "maximum_age_ms": 5000,
                    "reason_codes": [],
                },
                {
                    "kind": "status_as_of",
                    "status": "established",
                    "status_subject_ref": receipt["receipt_id"],
                    "status_kind": "appraisal_result",
                    "status_value_hash": h(0x2a),
                    "as_of": "2026-07-27T12:00:00Z",
                    "maximum_age_ms": 600000,
                    "reason_codes": [],
                },
                {
                    "kind": "continuity_floor",
                    "status": "established",
                    "namespace_ref": "boot-profile://acme/estate-1/baseline",
                    "floor_kind": "signed_update_version_and_image_head",
                    "accepted_version_or_epoch": 9,
                    "accepted_head_hash": h(0x1a),
                    "outside_rollback_domain_evidence_refs": [
                        "evidence://acme/estate-1/anchor/operator/9"
                    ],
                    "reason_codes": [],
                }
            ],
            "temporal_posture": "online_fresh",
            "evidence_horizon": {
                "valid_from": "2026-07-27T12:00:00Z",
                "valid_until": "2026-07-27T12:10:00Z",
            },
            "invalidation_triggers": ["reboot", "restore", "profile_superseded"],
            "obligations": ["reattest_by_interval"],
            "evaluation_hash": h(0x00),
        });
        let hash = jcs_hash(&json!({
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
        }))
        .expect("evaluation hash");
        evaluation["evaluation_hash"] = json!(hash);
        evaluation
    }

    struct LadderState {
        records: Vec<Value>,
        transitions: Vec<Value>,
        record_bytes: HashMap<String, String>,
        receipt_bytes: HashMap<String, String>,
        head: NodeAttestationLogHead,
        artifacts: Vec<Value>,
    }

    fn apply_step(
        state: &mut LadderState,
        op: NodeAttestationOp,
        declaration: &NodeAttestationDeclaration,
        receipt: Option<&Value>,
        evaluation: Option<&Value>,
        enforcement: &[Value],
    ) -> NodeAttestationStepArtifacts {
        let source = source_with(state.records.clone(), state.head.clone());
        let plan = compile_from_source(op, &source, declaration, receipt, evaluation, enforcement)
            .unwrap_or_else(|(code, message)| panic!("{}: {code} {message}", op.as_str()));
        assert_eq!(plan.predecessor_node_set_root, state.head.node_set_root);
        let artifacts =
            build_node_attestation_artifacts(&plan, &source, &authority(), "2026-07-27T12:00:00Z")
                .unwrap_or_else(|(code, message)| panic!("{}: {code} {message}", op.as_str()));
        // Every registered envelope validates: the record revision, the
        // committed boot receipt when present, and the plane receipt.
        validate_contract(
            HYPERVISOROS_NODE_CONTRACT,
            &artifacts.record,
            "ladder record",
        )
        .expect("record envelope");
        if let Some(receipt) = artifacts.committed_boot_receipt.as_ref() {
            validate_contract(BOOT_RECEIPT_CONTRACT, receipt, "ladder boot receipt")
                .expect("boot receipt envelope");
            state.receipt_bytes.insert(
                plan.committed_boot_receipt_root.clone().expect("root"),
                serde_json::to_string(receipt).expect("receipt bytes"),
            );
            state.artifacts.push(receipt.clone());
        }
        validate_contract(RECEIPT_CONTRACT, &artifacts.receipt, "ladder plane receipt")
            .expect("plane receipt envelope");
        state
            .records
            .retain(|record| record["node_id"] != plan.node_id.as_str());
        state.records.push(artifacts.record.clone());
        state.transitions.push(artifacts.transition.clone());
        state.record_bytes.insert(
            plan.resulting_record_root.clone(),
            serde_json::to_string(&artifacts.record).expect("record bytes"),
        );
        state.head = NodeAttestationLogHead {
            sequence: plan.sequence,
            node_set_root: plan.resulting_node_set_root.clone(),
        };
        state.artifacts.push(artifacts.record.clone());
        state.artifacts.push(artifacts.transition.clone());
        state.artifacts.push(artifacts.receipt.clone());
        state.artifacts.push(artifacts.claim.clone());
        artifacts
    }

    /// admit -> submit(verified) -> ready over the full artifact builder.
    fn ladder(pair: &Ed25519KeyPair) -> (LadderState, Value) {
        let mut state = LadderState {
            records: Vec::new(),
            transitions: Vec::new(),
            record_bytes: HashMap::new(),
            receipt_bytes: HashMap::new(),
            head: head_for(&[], 0),
            artifacts: Vec::new(),
        };
        let admit = admit_declaration(pair, &state.records);
        apply_step(
            &mut state,
            NodeAttestationOp::AdmitNodeIdentity,
            &admit,
            None,
            None,
            &[verified_ecd()],
        );

        let receipt = observed_receipt(pair, 3, 9);
        let evaluation = fresh_evaluation(&receipt);
        let mut submit = base_declaration(&state.records);
        submit.boot_receipt_ref = Some("receipt://acme/estate-1/boot/alpha-node-1/3".into());
        submit.temporal_validity_evaluation_ref =
            Some("temporal-evaluation://acme/estate-1/boot/42".into());
        let submitted = apply_step(
            &mut state,
            NodeAttestationOp::SubmitBootReceipt,
            &submit,
            Some(&receipt),
            Some(&evaluation),
            &[],
        );
        let committed = submitted
            .committed_boot_receipt
            .clone()
            .expect("committed receipt");

        let mut ready = base_declaration(&state.records);
        ready.temporal_validity_evaluation_ref =
            Some("temporal-evaluation://acme/estate-1/boot/42".into());
        apply_step(
            &mut state,
            NodeAttestationOp::MarkNodeReady,
            &ready,
            Some(&committed),
            Some(&evaluation),
            &[],
        );
        (state, committed)
    }

    #[test]
    fn node_attestation_ladder_artifacts_validate_every_registered_envelope() {
        let pair = keypair(7);
        let (state, committed) = ladder(&pair);
        assert_eq!(state.head.sequence, 3);
        assert_eq!(state.records.len(), 1);
        assert_eq!(state.records[0]["status"], "ready");
        assert_eq!(state.transitions.len(), 3);
        assert_eq!(
            derive_node_readiness(&state.records[0], Some(&committed)).expect("derivable"),
            "ready_derivable"
        );

        // The committed log replays cleanly from durable truth alone.
        let record_bytes = state.record_bytes.clone();
        let loader = move |record_root: &str| -> Result<Option<Value>, VErr> {
            Ok(record_bytes
                .get(record_root)
                .map(|bytes| serde_json::from_str(bytes).expect("stored record")))
        };
        let (live, head) =
            replay_node_attestation_transitions("acme/estate-1", &state.transitions, &loader)
                .expect("replay");
        assert_eq!(live.len(), 1);
        assert_eq!(head, state.head);
    }

    #[test]
    fn restart_rebuilds_the_projection_from_durable_records_only() {
        let pair = keypair(7);
        let (state, _committed) = ladder(&pair);
        let boot = boot_profile();
        let boot_root = boot_profile_root(&boot).expect("boot root");
        let temporal = temporal_profile();
        let temporal_root = temporal_profile_root(&temporal).expect("temporal root");
        let receipt_bytes = state.receipt_bytes.clone();
        let receipt_loader = move |root: &str| -> Result<Option<Value>, VErr> {
            Ok(receipt_bytes
                .get(root)
                .map(|bytes| serde_json::from_str(bytes).expect("stored receipt")))
        };
        let before = build_node_attestation_projection(
            "acme/estate-1",
            Some((&boot, boot_root.as_str())),
            Some((&temporal, temporal_root.as_str())),
            &state.records,
            &state.head,
            &receipt_loader,
        )
        .expect("projection before restart");

        // Restart: only durable transition, record, and receipt bytes remain.
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
        let (live, head) =
            replay_node_attestation_transitions("acme/estate-1", &transitions, &loader)
                .expect("replay after restart");
        let after = build_node_attestation_projection(
            "acme/estate-1",
            Some((&boot, boot_root.as_str())),
            Some((&temporal, temporal_root.as_str())),
            &live,
            &head,
            &receipt_loader,
        )
        .expect("projection after restart");
        assert_eq!(before, after);
        assert_eq!(
            serde_json::to_string(&before).expect("bytes"),
            serde_json::to_string(&after).expect("bytes")
        );
        let nodes = after["observed"]["nodes"].as_array().expect("nodes");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["readiness_derivable"], true);
        assert_eq!(nodes[0]["profile_binding_current"], true);
        assert_eq!(after["divergence"], json!([]));
        assert_eq!(after["nonclaims"]["ready_before_proof"], false);
    }

    #[test]
    fn node_ops_have_owner_scopes_and_never_parse_as_other_families() {
        for op in NodeAttestationOp::ALL {
            assert_eq!(AUTHORITY.operation_scope(op.as_str()), op.required_scope());
            assert!(
                ioi_types::app::system_membership_transitions::MembershipTransitionOp::parse(
                    op.as_str()
                )
                .is_none()
            );
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
            AUTHORITY.operation_scope(DECLARE_BOOT_PROFILE_OP),
            DECLARE_BOOT_PROFILE_SCOPE
        );
        assert_eq!(
            AUTHORITY.operation_scope(DECLARE_TEMPORAL_PROFILE_OP),
            DECLARE_TEMPORAL_PROFILE_SCOPE
        );
    }

    // Sealed-secret absence: every artifact this plane persists carries no
    // secret-bearing key names and none of the node's private key material.
    #[test]
    fn persisted_artifacts_never_carry_sealed_identity_material() {
        let pair = keypair(7);
        let (state, committed) = ladder(&pair);
        let private_hex = hex_encode(&[7u8; 32]);
        let mut serialized = String::new();
        for artifact in state.artifacts.iter().chain(std::iter::once(&committed)) {
            assert!(
                !contains_sensitive_key(artifact),
                "artifact carries a secret-bearing key name: {artifact}"
            );
            serialized.push_str(&serde_json::to_string(artifact).expect("artifact bytes"));
        }
        assert!(!serialized.contains(&private_hex));
        for needle in ["private_key", "privatekey", "mnemonic"] {
            assert!(
                !serialized.to_lowercase().contains(needle),
                "artifact stream leaked '{needle}'"
            );
        }
        // The public binding and the vault alias reference are the only
        // identity material any artifact may carry.
        assert!(serialized.contains("vault://acme/node-identity/alpha-node-1"));
        assert!(serialized.contains(&hex_encode(&pair.public_key().to_bytes())));
    }

    // The declared rollback floor never decreases across boot profile
    // declarations, and a boot profile must bind the declared temporal
    // profile.
    #[test]
    fn boot_profile_declarations_enforce_floor_monotonicity_and_temporal_binding() {
        let source = source_with(Vec::new(), head_for(&[], 0));
        let current_root = source.boot_profile_root.clone().expect("current root");

        // Lowering the floor is refused.
        let mut lowered = boot_profile();
        lowered["predecessor_boot_profile_root"] = json!(current_root);
        lowered["update_policy"]["rollback_floor"]["minimum_version_counter"] = json!(3);
        let body = json!({"boot_profile": lowered});
        let (_code, message) = build_profile_declaration_plan(&source, &body, ProfileFamily::Boot)
            .expect_err("lowered floor must be refused");
        assert!(message.contains("never decreases"));

        // A raised floor with the exact predecessor root compiles.
        let mut raised = boot_profile();
        raised["predecessor_boot_profile_root"] = json!(current_root);
        raised["update_policy"]["rollback_floor"]["minimum_version_counter"] = json!(9);
        let body = json!({"boot_profile": raised});
        build_profile_declaration_plan(&source, &body, ProfileFamily::Boot)
            .expect("raised floor declares");

        // A stale predecessor root is a head conflict.
        let mut stale = boot_profile();
        stale["predecessor_boot_profile_root"] = json!(h(0x77));
        let body = json!({"boot_profile": stale});
        let (code, _message) = build_profile_declaration_plan(&source, &body, ProfileFamily::Boot)
            .expect_err("stale predecessor must be refused");
        assert_eq!(code, "hypervisoros_node_head_conflict");

        // A boot profile bound to a foreign temporal profile is refused.
        let mut foreign = boot_profile();
        foreign["predecessor_boot_profile_root"] = json!(current_root);
        foreign["temporal_verification_profile_hash"] = json!(h(0x66));
        let body = json!({"boot_profile": foreign});
        let (_code, message) = build_profile_declaration_plan(&source, &body, ProfileFamily::Boot)
            .expect_err("foreign temporal binding must be refused");
        assert!(message.contains("declared temporal profile"));
    }

    #[test]
    fn projection_without_declared_profiles_is_honest() {
        let loader = |_root: &str| -> Result<Option<Value>, VErr> { Ok(None) };
        let projection = build_node_attestation_projection(
            "acme/estate-1",
            None,
            None,
            &[],
            &head_for(&[], 0),
            &loader,
        )
        .expect("empty projection");
        assert_eq!(projection["state"], "honest_empty");
        assert_eq!(projection["desired"]["boot_profile"], Value::Null);
        assert_eq!(projection["boot_profile_undeclared"], true);
        assert_eq!(projection["divergence"], Value::Null);
    }
}
