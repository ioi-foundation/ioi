//! M2 writer-fence plane routes: active-writer epoch transitions, the
//! current-fence projection, and lost-suffix custody resolution.
//!
//! The writer-epoch transition log is the durable truth; the active-fence
//! projection is rebuilt from committed transitions only, so a restart loses
//! nothing it cannot reconstruct byte-exactly. Writer authority is admissible
//! ONLY here: the membership plane structurally refuses `admission_writer`
//! and defers to this family. Every admission input is resolved from durable
//! server truth, never asserted by the caller (INV-37); the one-successor-
//! per-predecessor claim family is the cross-process compare-and-swap
//! boundary, so a double claim settles to exactly one writer (INV-24).

use ioi_types::app::system_writer_fence::{
    build_writer_transition_envelope, compile_writer_epoch_transition_plan, failover_profile_root,
    lost_suffix_record_root, replay_writer_epoch_transitions, resolve_lost_suffix_record,
    validate_failover_profile, CompiledWriterTransitionPlan, DisplacedWriterObservation,
    LostSuffixEntryResolution, PriorWriterLogObservation, WriterEpochTransitionKind,
    WriterFenceHead, WriterIdentityBinding, WriterTransitionArtifacts, WriterTransitionDeclaration,
    DECLARE_FAILOVER_PROFILE_OP, DECLARE_FAILOVER_PROFILE_SCOPE, LOST_SUFFIX_CONTRACT,
    RESOLVE_LOST_SUFFIX_OP, RESOLVE_LOST_SUFFIX_SCOPE,
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
use super::system_membership_routes::{load_membership_source, MembershipSource};
use super::system_protected_transition_routes::{decision_tuple, preflight_chain_writer_grant};
use super::DaemonState;

type VErr = (String, String);

/// Owner-declared failover profile records (content-addressed, CAS lineage).
pub(crate) const FAILOVER_PROFILE_DIR: &str = "autonomous-system-failover-profiles";
/// Committed immutable writer-epoch transitions (the durable fence truth).
pub(crate) const WRITER_TRANSITION_DIR: &str = "autonomous-system-writer-epoch-transitions";
/// Writer transition and lost-suffix resolution receipts.
pub(crate) const WRITER_RECEIPT_DIR: &str = "autonomous-system-writer-receipts";
/// One-successor-per-predecessor writer CAS claims.
pub(crate) const WRITER_CLAIM_DIR: &str = "autonomous-system-writer-successor-claims";
/// Lost-suffix custody record revisions (timeless content roots).
pub(crate) const LOST_SUFFIX_DIR: &str = "autonomous-system-lost-suffix-records";
/// Sealed writer transition intents (local replay registry).
pub(crate) const WRITER_INTENT_DIR: &str = "autonomous-system-writer-transition-intents";
/// Daemon-resolved writer evidence (revocation observations, displaced-writer
/// observations, prior-writer log observations). The loader is live; the
/// runtime producer is a later M2 leg.
pub(crate) const WRITER_EVIDENCE_DIR: &str = "autonomous-system-writer-evidence";
/// Membership-plane node evidence (catch-up receipts) — integrated, not
/// duplicated: the writer plane reads the same durable evidence family.
const NODE_EVIDENCE_DIR: &str = "autonomous-system-node-evidence";
/// HypervisorOS-plane node evidence (temporal validity evaluations).
const HV_NODE_EVIDENCE_DIR: &str = "hypervisoros-node-evidence";
/// HypervisorOS-plane declared temporal profiles.
const HV_TEMPORAL_PROFILE_DIR: &str = "hypervisoros-temporal-profiles";
/// HypervisorOS-plane admitted node record revisions.
const HV_NODE_RECORD_DIR: &str = "hypervisoros-node-records";

const RECEIPT_CONTRACT: &str = "schema://ioi/foundations/receipt-envelope/v1";
const TRANSITION_ARTIFACT_DOMAIN: &str =
    "ioi.autonomous-system-writer-epoch-transition-artifact-jcs-sha256.v1";
const RECEIPT_ARTIFACT_DOMAIN: &str = "ioi.autonomous-system-writer-receipt-jcs-sha256.v1";
const GENESIS_CLAIM_DOMAIN: &str = "ioi.autonomous-system-writer-genesis-claim-jcs-sha256.v1";

fn required(value: &Value, pointer: &str) -> Result<String, VErr> {
    required_string(value, pointer).map(str::to_owned)
}

fn ns(system_id: &str) -> Result<&str, VErr> {
    system_id.strip_prefix("system://").ok_or_else(|| {
        verr(
            "system_writer_artifact_invalid",
            "system_id is not canonical",
        )
    })
}

fn plan_err(error: String) -> VErr {
    verr("system_writer_plan_invalid", error)
}

fn artifact_root(domain: &str, artifact: &Value) -> Result<String, VErr> {
    jcs_hash(&json!({"domain":domain,"artifact":artifact}))
}

/// Enumerate one local-only family without requiring Agentgres admission.
fn scan_local_family(data_dir: &str, family: &str) -> Result<Vec<Value>, VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(verr(
                "system_writer_artifact_unreadable",
                format!("family '{family}' cannot be pinned ({error})"),
            ))
        }
    };
    let mut names = super::durable_fs::enumerate_pinned(&directory).map_err(|error| {
        verr(
            "system_writer_artifact_unreadable",
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
                    "system_writer_artifact_unreadable",
                    format!("unexpected entry '{family}/{name}'"),
                )
            })?
            .to_owned();
        let value = load_local(data_dir, family, &record_tail)?.ok_or_else(|| {
            verr(
                "system_writer_artifact_unreadable",
                format!("'{family}/{name}' vanished"),
            )
        })?;
        values.push(value);
    }
    Ok(values)
}

/// Enumerate one required-admission family with the local-versus-Agentgres
/// census equality proof; a census mismatch fails closed.
fn enumerate_required_censused(data_dir: &str, family: &str) -> Result<Vec<Value>, VErr> {
    let local = super::system_activation_routes::enumerate_family(data_dir, family)?;
    let mut local_values: Vec<Value> = local.into_iter().map(|(_, value)| value).collect();
    let mut substrate =
        super::substrate_store::read_required_all(data_dir, family).map_err(|error| {
            verr(
                "system_writer_source_incomplete",
                format!("Agentgres census for '{family}' failed ({error})"),
            )
        })?;
    let sort_key = |value: &Value| serde_json::to_string(value).unwrap_or_default();
    local_values.sort_by_key(sort_key);
    substrate.sort_by_key(sort_key);
    if local_values != substrate {
        return Err(verr(
            "system_writer_source_incomplete",
            format!("local and Agentgres censuses for '{family}' differ"),
        ));
    }
    Ok(local_values)
}

fn resolve_one<'a>(
    records: &'a [Value],
    field: &str,
    reference: &str,
    label: &str,
) -> Result<&'a Value, VErr> {
    let matches: Vec<&Value> = records
        .iter()
        .filter(|value| value.get(field).and_then(Value::as_str) == Some(reference))
        .collect();
    match matches.len() {
        0 => Err(verr(
            "system_writer_evidence_not_found",
            format!("'{reference}' is not resolvable from durable {label}"),
        )),
        1 => Ok(matches[0]),
        _ => Err(verr(
            "system_writer_artifact_mismatch",
            format!("'{reference}' resolves to more than one durable {label} record"),
        )),
    }
}

/// The one current declared record of a content-addressed CAS lineage: the
/// record no successor cites as its predecessor. Two uncited candidates fork
/// and fail closed.
fn current_by_lineage(
    records: &[Value],
    status_field: &str,
    live_status: &str,
    predecessor_field: &str,
    root: &dyn Fn(&Value) -> Result<String, String>,
) -> Result<Option<(Value, String)>, VErr> {
    let mut rooted: Vec<(Value, String)> = Vec::new();
    for record in records {
        rooted.push((record.clone(), root(record).map_err(plan_err)?));
    }
    let cited: Vec<String> = rooted
        .iter()
        .filter_map(|(record, _)| {
            record
                .get(predecessor_field)
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let mut current: Vec<(Value, String)> = rooted
        .into_iter()
        .filter(|(record, record_root)| {
            record.get(status_field).and_then(Value::as_str) == Some(live_status)
                && !cited.contains(record_root)
        })
        .collect();
    match current.len() {
        0 => Ok(None),
        1 => Ok(current.pop()),
        _ => Err(verr(
            "system_writer_artifact_mismatch",
            "two declared records both claim currency",
        )),
    }
}

/// The exact durable truth one writer operation compiles against.
pub(crate) struct WriterSource {
    pub membership: MembershipSource,
    pub binding: WriterIdentityBinding,
    pub failover_profile: Option<Value>,
    pub failover_profile_root: Option<String>,
    pub transitions: Vec<Value>,
    pub fence_head: WriterFenceHead,
    pub lost_suffix_revisions: Vec<Value>,
}

/// Server-resolved trusted inputs for one transition compile (INV-37).
pub(crate) struct WriterTrustedInputs {
    pub attested_node: Value,
    pub catchup_receipt: Value,
    pub temporal_profile: Value,
    pub temporal_evaluation: Value,
    pub displaced: Option<DisplacedWriterObservation>,
    pub prior_log: Option<PriorWriterLogObservation>,
}

pub(crate) fn load_writer_source(data_dir: &str, key: &str) -> Result<WriterSource, VErr> {
    let membership = load_membership_source(data_dir, key)?;
    let continuity = super::system_continuity_routes::load_continuity_source(data_dir, key)?;
    let chain = &continuity.base.chain_head;
    let active_set = load_required_exact(
        data_dir,
        super::system_activation_routes::ACTIVE_SET_DIR,
        &tail("asaps_", &required(chain, "/active_profile_set_root")?)?,
    )?
    .ok_or_else(|| {
        verr(
            "system_writer_source_incomplete",
            "the active profile set is not resolvable from durable truth",
        )
    })?;
    let revocation = resolve_authority_revocation(data_dir, &membership.binding.system_id)?;
    let binding = WriterIdentityBinding {
        system_id: membership.binding.system_id.clone(),
        genesis_ref: membership.binding.genesis_ref.clone(),
        source_governing_authority_ref: membership.binding.source_governing_authority_ref.clone(),
        deployment_profile_ref: membership.binding.deployment_profile_ref.clone(),
        deployment_profile_root: membership.binding.deployment_profile_root.clone(),
        ordering_profile_ref: required(
            &active_set,
            "/ordering_admission_finality/candidate_profile_ref",
        )?,
        ordering_profile_root: required(
            &active_set,
            "/ordering_admission_finality/candidate_profile_root",
        )?,
        authority_revocation_snapshot_ref: revocation.0,
        authority_revocation_epoch: revocation.1,
    };
    let failover_records = enumerate_required_censused(data_dir, FAILOVER_PROFILE_DIR)?;
    let mine: Vec<Value> = failover_records
        .into_iter()
        .filter(|record| {
            record.get("system_id").and_then(Value::as_str) == Some(binding.system_id.as_str())
        })
        .collect();
    let failover = current_by_lineage(
        &mine,
        "status",
        "active",
        "predecessor_failover_profile_root",
        &failover_profile_root,
    )?;
    let transitions = enumerate_required_censused(data_dir, WRITER_TRANSITION_DIR)?;
    let fence_head =
        replay_writer_epoch_transitions(&binding.system_id, &transitions).map_err(plan_err)?;
    let lost_suffix_revisions = enumerate_required_censused(data_dir, LOST_SUFFIX_DIR)?
        .into_iter()
        .filter(|record| {
            record.get("system_id").and_then(Value::as_str) == Some(binding.system_id.as_str())
        })
        .collect();
    let (failover_profile, failover_root) = match failover {
        Some((record, root)) => (Some(record), Some(root)),
        None => (None, None),
    };
    Ok(WriterSource {
        membership,
        binding,
        failover_profile,
        failover_profile_root: failover_root,
        transitions,
        fence_head,
        lost_suffix_revisions,
    })
}

/// Resolve the current authority revocation posture from durable writer
/// evidence. The producer is a later M2 leg; an unresolvable posture fails
/// closed rather than defaulting.
fn resolve_authority_revocation(data_dir: &str, system_id: &str) -> Result<(String, u64), VErr> {
    let records = scan_local_family(data_dir, WRITER_EVIDENCE_DIR)?;
    let mut matches: Vec<&Value> = records
        .iter()
        .filter(|value| {
            value.get("kind").and_then(Value::as_str) == Some("authority_revocation_observation")
                && value.get("system_id").and_then(Value::as_str) == Some(system_id)
        })
        .collect();
    matches.sort_by_key(|value| value.get("revocation_epoch").and_then(Value::as_u64));
    let Some(latest) = matches.last() else {
        return Err(verr(
            "system_writer_evidence_not_found",
            "no authority revocation observation is resolvable from durable writer evidence",
        ));
    };
    Ok((
        required(latest, "/snapshot_ref")?,
        latest
            .get("revocation_epoch")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                verr(
                    "system_writer_artifact_invalid",
                    "revocation observation lacks its epoch",
                )
            })?,
    ))
}

fn resolve_trusted_inputs(
    data_dir: &str,
    kind: WriterEpochTransitionKind,
    declaration: &WriterTransitionDeclaration,
) -> Result<WriterTrustedInputs, VErr> {
    // Attested node: the current ready revision from the attestation plane.
    let node_records = enumerate_required_censused(data_dir, HV_NODE_RECORD_DIR)?;
    let ready: Vec<&Value> = node_records
        .iter()
        .filter(|record| {
            record.get("node_record_id").and_then(Value::as_str)
                == Some(declaration.attested_node_ref.as_str())
                && record.get("status").and_then(Value::as_str) == Some("ready")
        })
        .collect();
    let attested_node = ready.last().copied().cloned().ok_or_else(|| {
        verr(
            "system_writer_evidence_not_found",
            "no verified-ready node attestation record resolves the declared ref",
        )
    })?;
    let node_evidence = scan_local_family(data_dir, NODE_EVIDENCE_DIR)?;
    let catchup_receipt = resolve_one(
        &node_evidence,
        "receipt_ref",
        &declaration.catchup_receipt_ref,
        "node evidence",
    )?
    .clone();
    let temporal_profiles = enumerate_required_censused(data_dir, HV_TEMPORAL_PROFILE_DIR)?;
    let temporal_profile = current_by_lineage(
        &temporal_profiles,
        "status",
        "declared",
        "predecessor_profile_root",
        &|profile: &Value| {
            jcs_hash(&json!({
                "domain": "ioi.temporal-verification-profile-record-jcs-sha256.v1",
                "profile": profile,
            }))
            .map_err(|(_, message)| message)
        },
    )?
    .map(|(record, _)| record)
    .ok_or_else(|| {
        verr(
            "system_writer_evidence_not_found",
            "no declared temporal verification profile admits writer operations",
        )
    })?;
    let hv_evidence = scan_local_family(data_dir, HV_NODE_EVIDENCE_DIR)?;
    let temporal_evaluation = resolve_one(
        &hv_evidence,
        "evaluation_id",
        &declaration.temporal_validity_evaluation_ref,
        "temporal evidence",
    )?
    .clone();
    let writer_evidence = scan_local_family(data_dir, WRITER_EVIDENCE_DIR)?;
    let displaced = match kind {
        WriterEpochTransitionKind::Genesis => None,
        _ => {
            let observation = writer_evidence
                .iter()
                .find(|value| {
                    value.get("kind").and_then(Value::as_str)
                        == Some("displaced_writer_observation")
                })
                .ok_or_else(|| {
                    verr(
                        "system_writer_evidence_not_found",
                        "no displaced-writer observation is resolvable from durable evidence",
                    )
                })?;
            Some(
                serde_json::from_value::<DisplacedWriterObservation>(
                    observation
                        .get("observation")
                        .cloned()
                        .unwrap_or(Value::Null),
                )
                .map_err(|error| verr("system_writer_artifact_invalid", error.to_string()))?,
            )
        }
    };
    let prior_log = writer_evidence
        .iter()
        .find(|value| {
            value.get("kind").and_then(Value::as_str) == Some("prior_writer_log_observation")
        })
        .map(|observation| {
            serde_json::from_value::<PriorWriterLogObservation>(
                observation
                    .get("observation")
                    .cloned()
                    .unwrap_or(Value::Null),
            )
            .map_err(|error| verr("system_writer_artifact_invalid", error.to_string()))
        })
        .transpose()?;
    Ok(WriterTrustedInputs {
        attested_node,
        catchup_receipt,
        temporal_profile,
        temporal_evaluation,
        displaced,
        prior_log,
    })
}

pub(crate) fn compile_from_source(
    kind: WriterEpochTransitionKind,
    source: &WriterSource,
    declaration: &WriterTransitionDeclaration,
    trusted: &WriterTrustedInputs,
) -> Result<CompiledWriterTransitionPlan, VErr> {
    let failover = source.failover_profile.as_ref().ok_or_else(|| {
        verr(
            "system_writer_failover_profile_required",
            "no active failover profile admits writer-epoch transitions",
        )
    })?;
    compile_writer_epoch_transition_plan(
        kind,
        &source.binding,
        failover,
        &source.membership.records,
        &source.membership.head.membership_root,
        &source.fence_head,
        declaration,
        &trusted.attested_node,
        &trusted.catchup_receipt,
        &trusted.temporal_profile,
        &trusted.temporal_evaluation,
        trusted.displaced.as_ref(),
        trusted.prior_log.as_ref(),
    )
    .map_err(plan_err)
}

/// One fully built writer step, every artifact contract-validated inside the
/// build itself.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WriterStepArtifacts {
    pub transition: Value,
    pub transition_hash: String,
    pub transition_root: String,
    pub receipt: Value,
    pub receipt_root: String,
    pub claim: Value,
    pub claim_tail: String,
    pub lost_suffix: Option<(Value, String)>,
}

/// Predecessor claim key: the exact active transition hash, or the genesis
/// sentinel root for the first claim. One successor per predecessor is the
/// cross-process CAS boundary.
fn claim_root_for(system_id: &str, predecessor_hash: Option<&str>) -> Result<String, VErr> {
    match predecessor_hash {
        Some(hash) => Ok(hash.to_owned()),
        None => jcs_hash(&json!({
            "domain": GENESIS_CLAIM_DOMAIN,
            "system_id": system_id,
        })),
    }
}

pub(crate) fn build_writer_step_artifacts(
    plan: &CompiledWriterTransitionPlan,
    authority: &super::system_protected_transition_routes::DecisionAuthorityTuple,
    timestamp: &str,
) -> Result<WriterStepArtifacts, VErr> {
    let WriterTransitionArtifacts {
        transition,
        transition_hash,
        lost_suffix,
    } = build_writer_transition_envelope(plan, &authority.authority_grant_ref, timestamp)
        .map_err(plan_err)?;
    let system_id = required(&transition, "/system_id")?;
    let namespace = ns(&system_id)?;
    let transition_root = artifact_root(TRANSITION_ARTIFACT_DOMAIN, &transition)?;

    let receipt_ref = format!("receipt://{namespace}/writer/epoch/{}", plan.writer_epoch);
    let mut artifact_refs = vec![json!(format!(
        "artifact://writer-epoch-transition/{transition_hash}"
    ))];
    if let Some((_, suffix_root)) = &lost_suffix {
        artifact_refs.push(json!(format!(
            "artifact://lost-suffix-record/{suffix_root}"
        )));
    }
    let receipt = json!({
        "receipt_id": receipt_ref,
        "receipt_type": "writer_epoch_transition",
        "receipt_profile_ref": RECEIPT_CONTRACT,
        "attested_boundary_fact_refs": [
            system_id,
            plan.writer_epoch_transition_ref,
            plan.successor_node_id,
            authority.authority_evidence_ref,
        ],
        "claim_scope_ref": "policy://autonomous-system/writer",
        "run_id": Value::Null,
        "task_id": Value::Null,
        "actor_id": "runtime://hypervisor-runtime",
        "authority_grant_id": authority.authority_grant_ref,
        "primitive_capabilities": [],
        "authority_scopes": [plan.kind.required_scope()],
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
        "output_hash": transition_hash,
        "policy_hash": authority.policy_hash,
    });
    validate_contract(RECEIPT_CONTRACT, &receipt, "writer receipt")?;
    let receipt_root = artifact_root(RECEIPT_ARTIFACT_DOMAIN, &receipt)?;

    let claim_root = claim_root_for(&system_id, plan.predecessor_transition_hash.as_deref())?;
    let claim_tail = tail("aswsc_", &claim_root)?;
    let claim = json!({
        "schema_version": "ioi.hypervisor.writer-successor-claim.v1",
        "claim_ref": format!("writer-successor-claim://{claim_root}"),
        "system_id": system_id,
        "writer_epoch": plan.writer_epoch,
        "predecessor_claim_root": claim_root,
        "predecessor_transition_hash": plan.predecessor_transition_hash,
        "resulting_transition_hash": transition_hash,
        "transition_ref": plan.writer_epoch_transition_ref,
        "transition_kind": plan.kind.as_str(),
        "committed_at": timestamp,
    });
    Ok(WriterStepArtifacts {
        transition,
        transition_hash,
        transition_root,
        receipt,
        receipt_root,
        claim,
        claim_tail,
        lost_suffix,
    })
}

fn persist_writer_graph(
    data_dir: &str,
    plan: &CompiledWriterTransitionPlan,
    artifacts: &WriterStepArtifacts,
    evidence: &super::system_activation_routes::NodeAdmissionEvidence,
    wallet_consumption: &Value,
) -> Result<(), VErr> {
    // One successor per predecessor transition: the expected-absent Agentgres
    // admission is the cross-process CAS boundary settling double claims.
    persist_local(
        data_dir,
        WRITER_CLAIM_DIR,
        &artifacts.claim_tail,
        &artifacts.claim,
    )
    .map_err(|(code, message)| {
        if code == "system_lifecycle_conflict" {
            verr("system_writer_head_conflict", message)
        } else {
            (code, message)
        }
    })?;
    super::substrate_store::admit_required(
        data_dir,
        WRITER_CLAIM_DIR,
        &artifacts.claim_tail,
        &artifacts.claim,
    )
    .map_err(|error| {
        let code = if error.kind() == std::io::ErrorKind::AlreadyExists {
            "system_writer_head_conflict"
        } else {
            "system_writer_agentgres_admission_failed"
        };
        verr(code, format!("durable writer claim failed ({error})"))
    })?;
    if load_required_exact(data_dir, WRITER_CLAIM_DIR, &artifacts.claim_tail)?.as_ref()
        != Some(&artifacts.claim)
    {
        return Err(verr(
            "system_writer_head_conflict",
            "the durable predecessor claim belongs to a different successor writer",
        ));
    }
    let consumption: ioi_services::wallet_network::ApprovalGrantConsumptionReceipt =
        serde_json::from_value(wallet_consumption.clone()).map_err(|error| {
            verr(
                "system_lifecycle_wallet_consumption_invalid",
                error.to_string(),
            )
        })?;
    let consumption_tail = format!("aslac_{}", hex::encode(consumption.consumption_id));
    let evidence_tail = tail("aslae_", &evidence.authority_evidence_root)?;
    let transition_tail = tail("aswt_", &artifacts.transition_root)?;
    let receipt_tail = tail("aswr_", &artifacts.receipt_root)?;
    let mut records: Vec<(&str, String, &Value)> = vec![
        (
            AUTHORITY_CONSUMPTION_DIR,
            consumption_tail,
            wallet_consumption,
        ),
        (
            AUTHORITY_EVIDENCE_DIR,
            evidence_tail,
            &evidence.authority_evidence,
        ),
        (
            WRITER_TRANSITION_DIR,
            transition_tail,
            &artifacts.transition,
        ),
        (WRITER_RECEIPT_DIR, receipt_tail, &artifacts.receipt),
    ];
    let suffix_pair = artifacts
        .lost_suffix
        .as_ref()
        .map(|(record, root)| Ok::<_, VErr>((tail("aslsr_", root)?, record)))
        .transpose()?;
    if let Some((suffix_tail, record)) = &suffix_pair {
        records.push((LOST_SUFFIX_DIR, suffix_tail.clone(), record));
    }
    for (family, record_tail, value) in records {
        persist_local(data_dir, family, &record_tail, value)?;
        super::substrate_store::admit_required(data_dir, family, &record_tail, value).map_err(
            |error| {
                verr(
                    "system_writer_agentgres_admission_failed",
                    format!("required admission for '{family}/{record_tail}' failed ({error})"),
                )
            },
        )?;
        let loaded = load_required_exact(data_dir, family, &record_tail)?.ok_or_else(|| {
            verr(
                "system_writer_persist_failed",
                "writer artifact did not converge",
            )
        })?;
        if loaded != *value {
            return Err(verr(
                "system_writer_persist_failed",
                "writer artifact diverged",
            ));
        }
    }
    let _ = plan;
    Ok(())
}

const DECLARATION_FIELDS: &[&str] = &[
    "candidate_node_id",
    "expected_predecessor_transition_hash",
    "expected_membership_root",
    "writer_lease_ref",
    "catchup_receipt_ref",
    "state_root_verification_ref",
    "attested_node_ref",
    "temporal_validity_evaluation_ref",
    "resource_fences",
    "evidence_refs",
];

fn validate_request(body: &Value, allowed: &[&str]) -> Result<(), VErr> {
    let encoded = serde_json::to_vec(body)
        .map_err(|error| verr("system_writer_request_invalid", error.to_string()))?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(verr(
            "system_writer_request_oversize",
            "request exceeds 512 KiB",
        ));
    }
    if contains_sensitive_key(body) {
        return Err(verr(
            "system_writer_sensitive_field_rejected",
            "secret-bearing keys are forbidden recursively",
        ));
    }
    let object = body
        .as_object()
        .ok_or_else(|| verr("system_writer_request_invalid", "request must be an object"))?;
    if let Some(key) = object
        .keys()
        .find(|key| !allowed.contains(&key.as_str()) && key.as_str() != "wallet_approval_grant")
    {
        return Err(verr(
            "system_writer_request_field_unknown",
            format!("undeclared request field '{key}' is forbidden"),
        ));
    }
    Ok(())
}

fn declaration_from_body(body: &Value) -> Result<WriterTransitionDeclaration, VErr> {
    let mut value = serde_json::Map::new();
    for key in DECLARATION_FIELDS {
        if let Some(field) = body.get(*key) {
            value.insert((*key).to_owned(), field.clone());
        }
    }
    serde_json::from_value(Value::Object(value))
        .map_err(|error| verr("system_writer_request_invalid", error.to_string()))
}

fn ensure_no_cross_plane_pending(data_dir: &str, key: &str) -> Result<(), VErr> {
    super::system_activation_routes::ensure_no_pending_intent(data_dir, key)?;
    super::system_protected_transition_routes::ensure_no_pending_protected_intent(data_dir, key)?;
    super::system_amendment_routes::ensure_no_pending_amendment_intent(data_dir, key)?;
    super::system_continuity_routes::ensure_no_pending_migration_ack(data_dir, key)?;
    super::system_membership_routes::ensure_no_pending_membership_intent(data_dir, key)?;
    ensure_no_pending_writer_intent(data_dir, key)
}

pub(crate) fn ensure_no_pending_writer_intent(data_dir: &str, key: &str) -> Result<(), VErr> {
    for intent in scan_local_family(data_dir, WRITER_INTENT_DIR)? {
        verify_intent_seal(&intent)?;
        if intent.get("source_record_tail").and_then(Value::as_str) == Some(key) {
            return Err(verr(
                "system_lifecycle_pending_convergence",
                "a writer transition is pending convergence",
            ));
        }
    }
    Ok(())
}

/// POST /v1/hypervisor/autonomous-systems/:id/writer/transitions/:kind
pub(crate) async fn handle_transition(
    AxumPath((key, kind_name)): AxumPath<(String, String)>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_writer_source_key_invalid",
            "id is not canonical",
        ));
    }
    let Some(kind) = WriterEpochTransitionKind::parse(&kind_name) else {
        return classify(verr(
            "system_writer_operation_not_found",
            "unknown writer transition kind",
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
    let (source, trusted) = match with_source_locks(|| {
        ensure_no_cross_plane_pending(&state.data_dir, &key)?;
        let source = load_writer_source(&state.data_dir, &key)?;
        let trusted = resolve_trusted_inputs(&state.data_dir, kind, &declaration)?;
        Ok::<_, VErr>((source, trusted))
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let plan = match compile_from_source(kind, &source, &declaration, &trusted) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let system_id = source.binding.system_id.clone();
    let genesis_ref = source.binding.genesis_ref.clone();
    let governing = source.binding.source_governing_authority_ref.clone();
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
        kind.as_str(),
        plan.writer_epoch,
        &plan.authority_effect,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let operation_commitment =
        required(&plan.authority_effect, "/operation_commitment").unwrap_or_default();
    let mut evidence = match prepare_node_evidence_for(
        &plan.authority_effect,
        kind.as_str(),
        plan.writer_epoch,
        kind.required_scope(),
        &governing,
        &operation_commitment,
        authorized,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if let Err(error) = preflight_chain_writer_grant(&evidence.wallet_params).await {
        return classify(error);
    }
    let intent_tail = match tail("aswti_", &evidence.authorized.evidence.request_hash) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent = match with_source_locks(|| {
        let fresh = load_writer_source(&state.data_dir, &key)?;
        let recompiled = compile_from_source(kind, &fresh, &declaration, &trusted)?;
        if recompiled != plan {
            return Err(verr(
                "system_writer_head_conflict",
                "durable truth changed between authorization and intent sealing",
            ));
        }
        let intent = intent_seal(json!({
            "schema_version": "ioi.hypervisor.writer-transition-intent.v1",
            "source_record_tail": key,
            "op": kind.as_str(),
            "request_body": body,
            "compiled_plan": plan,
            "governed_authority": evidence_intent_value(&evidence),
            "intent_hash": Value::Null,
        }))?;
        persist_local(&state.data_dir, WRITER_INTENT_DIR, &intent_tail, &intent)?;
        Ok::<_, VErr>(intent)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if forced_fault("IOI_TEST_FORCE_SYSTEM_WRITER_AFTER_INTENT", kind.as_str()) {
        return classify(verr(
            "system_lifecycle_pending_convergence",
            "test-forced interruption after durable writer intent",
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
                    remove_intent(&state.data_dir, WRITER_INTENT_DIR, &intent_tail)
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
        "IOI_TEST_FORCE_SYSTEM_WRITER_AFTER_WALLET_CONSUMPTION",
        kind.as_str(),
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
    let artifacts = match build_writer_step_artifacts(&plan, &tuple, &timestamp) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let result = with_source_locks(|| {
        let stored =
            load_local(&state.data_dir, WRITER_INTENT_DIR, &intent_tail)?.ok_or_else(|| {
                verr(
                    "system_lifecycle_pending_convergence",
                    "writer intent vanished",
                )
            })?;
        verify_intent_seal(&stored)?;
        if stored != intent {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                "durable writer intent changed",
            ));
        }
        persist_writer_graph(&state.data_dir, &plan, &artifacts, &evidence, &wallet_value)?;
        remove_intent(&state.data_dir, WRITER_INTENT_DIR, &intent_tail)
    });
    if let Err(error) = result {
        return classify(error);
    }
    (
        StatusCode::OK,
        Json(json!({
            "op": kind.as_str(),
            "writer_epoch": plan.writer_epoch,
            "writer_epoch_transition": artifacts.transition,
            "writer_epoch_transition_hash": artifacts.transition_hash,
            "lost_suffix_record": artifacts.lost_suffix.as_ref().map(|(record, _)| record.clone()),
            "receipt": artifacts.receipt,
            "nonclaims": {
                "availability": false,
                "quorum": false,
                "consensus": false,
                "public_finality": false,
                "effects_admissible_immediately": false
            }
        })),
    )
}

/// Read-only writer eligibility projection: the status gate is reported
/// separately from declaration evidence and wallet authority a future POST
/// must still supply.
pub(crate) async fn handle_get_transition(
    AxumPath((key, kind_name)): AxumPath<(String, String)>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_writer_source_key_invalid",
            "id is not canonical",
        ));
    }
    let Some(kind) = WriterEpochTransitionKind::parse(&kind_name) else {
        return classify(verr(
            "system_writer_operation_not_found",
            "unknown writer transition kind",
        ));
    };
    match with_source_locks(|| {
        ensure_no_pending_writer_intent(&state.data_dir, &key)?;
        let source = load_writer_source(&state.data_dir, &key)?;
        let mut blockers = Vec::new();
        if source.failover_profile.is_none() {
            blockers.push(json!({"code":"failover_profile_undeclared"}));
        }
        if kind == WriterEpochTransitionKind::Genesis && source.fence_head.active_epoch > 0 {
            blockers.push(json!({"code":"genesis_spent"}));
        }
        if kind != WriterEpochTransitionKind::Genesis && source.fence_head.active_epoch == 0 {
            blockers.push(json!({"code":"no_active_writer"}));
        }
        Ok::<_, VErr>(json!({
            "op": kind.as_str(),
            "required_scope": kind.required_scope(),
            "eligible_now": {"blockers": blockers},
            "required_declaration_evidence": {
                "expected_membership_root": true,
                "expected_predecessor_transition_hash": kind != WriterEpochTransitionKind::Genesis,
                "fresh_writer_lease": true,
                "resolved_catchup_receipt": true,
                "verified_ready_node_attestation": true,
                "online_fresh_temporal_evaluation": true,
                "displaced_writer_fencing_or_waitout": kind != WriterEpochTransitionKind::Genesis,
            },
            "fence_head": {
                "active_epoch": source.fence_head.active_epoch,
                "active_transition_hash": source.fence_head.active_transition.as_ref()
                    .and_then(|transition| transition.get("writer_epoch_transition_hash").cloned()),
            },
            "nonclaims": {"wallet_authorized": false, "writer_effects_admissible": false}
        }))
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

/// The current lost-suffix revision per record identity: the revision no
/// successor cites as its predecessor.
pub(crate) fn current_lost_suffix_revisions(revisions: &[Value]) -> Result<Vec<Value>, VErr> {
    let mut rooted: Vec<(String, String)> = Vec::new();
    for revision in revisions {
        validate_contract(LOST_SUFFIX_CONTRACT, revision, "lost-suffix revision")?;
        rooted.push((
            required(revision, "/lost_suffix_record_id")?,
            lost_suffix_record_root(revision).map_err(plan_err)?,
        ));
    }
    let cited: Vec<String> = revisions
        .iter()
        .filter_map(|revision| {
            revision
                .get("predecessor_record_root")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let mut current = Vec::new();
    let mut seen_ids = Vec::new();
    for (index, revision) in revisions.iter().enumerate() {
        let (id, root) = &rooted[index];
        if cited.contains(root) {
            continue;
        }
        if seen_ids.contains(id) {
            return Err(verr(
                "system_writer_artifact_mismatch",
                "two lost-suffix revisions both claim currency for one record",
            ));
        }
        seen_ids.push(id.clone());
        current.push(revision.clone());
    }
    Ok(current)
}

/// Pure writer-fence projection over durable truth only: absence is honest,
/// never fabricated, and nothing here asserts availability or finality.
pub(crate) fn build_writer_projection(
    system_id: &str,
    fence_head: &WriterFenceHead,
    lost_suffix_revisions: &[Value],
) -> Result<Value, VErr> {
    let current = current_lost_suffix_revisions(lost_suffix_revisions)?;
    let suffixes: Vec<Value> = current
        .iter()
        .map(|record| {
            json!({
                "lost_suffix_record_id": record["lost_suffix_record_id"],
                "status": record["status"],
                "classification": record["classification"],
                "prior_writer_epoch": record["prior_writer_epoch"],
                "successor_writer_epoch": record["successor_writer_epoch"],
                "operation_count": record["excluded_suffix"]["operation_count"],
                "retained_ambiguous_entries": record["excluded_suffix"]["entries"]
                    .as_array()
                    .map(|entries| entries.iter().filter(|entry| {
                        entry.get("custody_status").and_then(Value::as_str)
                            == Some("retained_ambiguous")
                    }).count())
                    .unwrap_or(0),
            })
        })
        .collect();
    Ok(json!({
        "schema_version": "ioi.hypervisor.autonomous-system-writer-projection.v1",
        "system_id": system_id,
        "state": if fence_head.active_transition.is_none() && suffixes.is_empty() {
            "honest_empty"
        } else {
            "ready"
        },
        "active": match &fence_head.active_transition {
            None => Value::Null,
            Some(transition) => json!({
                "writer_epoch": fence_head.active_epoch,
                "node_id": transition.pointer("/successor_writer/node_id"),
                "writer_epoch_transition_ref": transition.get("writer_epoch_transition_id"),
                "writer_epoch_transition_hash": transition.get("writer_epoch_transition_hash"),
                "effects_admissible_not_before":
                    transition.pointer("/displaced_writer_fencing/effects_admissible_not_before"),
                "transition": transition,
            }),
        },
        "lost_suffixes": suffixes,
        "projection_source": "durable_owner_reconstruction",
        "nonclaims": {
            "availability": false,
            "quorum": false,
            "consensus": false,
            "public_finality": false,
            "desired_asserts_observed": false
        }
    }))
}

/// GET /v1/hypervisor/autonomous-systems/:id/writer/epoch
pub(crate) async fn handle_get_epoch(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_writer_source_key_invalid",
            "id is not canonical",
        ));
    }
    match with_source_locks(|| {
        let source = load_writer_source(&state.data_dir, &key)?;
        build_writer_projection(
            &source.binding.system_id,
            &source.fence_head,
            &source.lost_suffix_revisions,
        )
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

/// GET /v1/hypervisor/autonomous-systems/:id/writer/lost-suffixes
pub(crate) async fn handle_get_lost_suffixes(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_writer_source_key_invalid",
            "id is not canonical",
        ));
    }
    match with_source_locks(|| {
        let source = load_writer_source(&state.data_dir, &key)?;
        let current = current_lost_suffix_revisions(&source.lost_suffix_revisions)?;
        Ok::<_, VErr>(json!({
            "system_id": source.binding.system_id,
            "lost_suffix_records": current,
            "nonclaims": {"reconciliation_complete": false}
        }))
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

const RESOLUTION_FIELDS: &[&str] = &["lost_suffix_record_id", "resolutions", "resulting_status"];

/// Build the successor lost-suffix revision plus its closed governed effect.
pub(crate) fn build_lost_suffix_resolution_plan(
    source: &WriterSource,
    body: &Value,
) -> Result<Value, VErr> {
    let record_id = required(body, "/lost_suffix_record_id")?;
    let resulting_status = required(body, "/resulting_status")?;
    let resolutions: Vec<LostSuffixEntryResolution> =
        serde_json::from_value(body.get("resolutions").cloned().unwrap_or(Value::Null))
            .map_err(|error| verr("system_writer_request_invalid", error.to_string()))?;
    let current = current_lost_suffix_revisions(&source.lost_suffix_revisions)?
        .into_iter()
        .find(|record| {
            record.get("lost_suffix_record_id").and_then(Value::as_str) == Some(record_id.as_str())
        })
        .ok_or_else(|| {
            verr(
                "system_writer_evidence_not_found",
                "the named lost-suffix record has no current durable revision",
            )
        })?;
    let namespace = ns(&source.binding.system_id)?.to_owned();
    let predecessor_root = lost_suffix_record_root(&current).map_err(plan_err)?;
    let receipt_ref = format!(
        "receipt://{namespace}/writer/lost-suffix-resolution/{}",
        predecessor_root.trim_start_matches("sha256:")
    );
    let revision =
        resolve_lost_suffix_record(&current, &resolutions, &resulting_status, &receipt_ref)
            .map_err(plan_err)?;
    let mut effect = json!({
        "schema_version": "ioi.autonomous-system-lost-suffix-resolution-effect.v1",
        "op": RESOLVE_LOST_SUFFIX_OP,
        "required_scope": RESOLVE_LOST_SUFFIX_SCOPE,
        "system_id": source.binding.system_id,
        "genesis_ref": source.binding.genesis_ref,
        "source_governing_authority_ref": source.binding.source_governing_authority_ref,
        "lost_suffix_record_id": record_id,
        "predecessor_record_root": predecessor_root,
        "resulting_status": resulting_status,
        "resolutions": body["resolutions"],
        "disposition_receipt_ref": receipt_ref,
        "entries_silently_dropped": false,
        "entries_silently_replayed": false,
        "operation_commitment": Value::Null,
    });
    let operation_commitment = jcs_hash(&json!({
        "domain": "ioi.autonomous-system-lost-suffix-resolution-commitment-jcs-sha256.v1",
        "effect": effect,
    }))?;
    effect["operation_commitment"] = json!(operation_commitment);
    Ok(json!({
        "revision": revision,
        "predecessor_record_root": predecessor_root,
        "disposition_receipt_ref": receipt_ref,
        "authority_effect": effect,
    }))
}

/// Stamp the resolution receipt and compute persistence roots.
pub(crate) fn build_lost_suffix_resolution_artifacts(
    plan: &Value,
    authority: &super::system_protected_transition_routes::DecisionAuthorityTuple,
    timestamp: &str,
) -> Result<(Value, String, Value, String), VErr> {
    let revision = plan["revision"].clone();
    validate_contract(LOST_SUFFIX_CONTRACT, &revision, "lost-suffix revision")?;
    let revision_root = lost_suffix_record_root(&revision).map_err(plan_err)?;
    let receipt_ref = required(plan, "/disposition_receipt_ref")?;
    let receipt = json!({
        "receipt_id": receipt_ref,
        "receipt_type": "lost_suffix_resolution",
        "receipt_profile_ref": RECEIPT_CONTRACT,
        "attested_boundary_fact_refs": [
            required(&revision, "/system_id")?,
            required(&revision, "/lost_suffix_record_id")?,
            required(plan, "/predecessor_record_root")?,
            authority.authority_evidence_ref,
        ],
        "claim_scope_ref": "policy://autonomous-system/writer",
        "run_id": Value::Null,
        "task_id": Value::Null,
        "actor_id": "runtime://hypervisor-runtime",
        "authority_grant_id": authority.authority_grant_ref,
        "primitive_capabilities": [],
        "authority_scopes": [RESOLVE_LOST_SUFFIX_SCOPE],
        "artifact_refs": [format!("artifact://lost-suffix-record/{revision_root}")],
        "evidence_bundle_refs": [],
        "verification_ref": Value::Null,
        "acceptance_ref": Value::Null,
        "adjudication_ref": Value::Null,
        "settlement_ref": Value::Null,
        "timestamp": timestamp,
        "signature": Value::Null,
        "public_commitment_ref": Value::Null,
        "input_hash": authority.input_hash,
        "output_hash": revision_root,
        "policy_hash": authority.policy_hash,
    });
    validate_contract(RECEIPT_CONTRACT, &receipt, "lost-suffix resolution receipt")?;
    let receipt_root = artifact_root(RECEIPT_ARTIFACT_DOMAIN, &receipt)?;
    Ok((revision, revision_root, receipt, receipt_root))
}

/// POST /v1/hypervisor/autonomous-systems/:id/writer/lost-suffixes/resolution
pub(crate) async fn handle_lost_suffix_resolution(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_writer_source_key_invalid",
            "id is not canonical",
        ));
    }
    if let Err(error) = validate_request(&body, RESOLUTION_FIELDS) {
        return classify(error);
    }
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let (source, plan) = match with_source_locks(|| {
        ensure_no_cross_plane_pending(&state.data_dir, &key)?;
        let source = load_writer_source(&state.data_dir, &key)?;
        let plan = build_lost_suffix_resolution_plan(&source, &body)?;
        Ok::<_, VErr>((source, plan))
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let effect = plan["authority_effect"].clone();
    let system_id = source.binding.system_id.clone();
    let genesis_ref = source.binding.genesis_ref.clone();
    let governing = source.binding.source_governing_authority_ref.clone();
    let sequence = source.fence_head.active_epoch.max(1);
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
        RESOLVE_LOST_SUFFIX_OP,
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
        RESOLVE_LOST_SUFFIX_OP,
        sequence,
        RESOLVE_LOST_SUFFIX_SCOPE,
        &governing,
        required_string(&effect, "/operation_commitment").unwrap_or(""),
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
    let timestamp = match ms_to_timestamp(wallet_receipt.consumed_at_ms) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let tuple = match decision_tuple(&evidence) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let (revision, revision_root, receipt, receipt_root) =
        match build_lost_suffix_resolution_artifacts(&plan, &tuple, &timestamp) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    let result = with_source_locks(|| {
        // Recheck the CAS under the lock: the resolution must still swap the
        // exact current revision.
        let fresh = load_writer_source(&state.data_dir, &key)?;
        if build_lost_suffix_resolution_plan(&fresh, &body)? != plan {
            return Err(verr(
                "system_writer_head_conflict",
                "durable lost-suffix truth changed before commitment",
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
            (LOST_SUFFIX_DIR, tail("aslsr_", &revision_root)?, &revision),
            (WRITER_RECEIPT_DIR, tail("aswr_", &receipt_root)?, &receipt),
        ];
        for (family, record_tail, value) in records {
            persist_local(&state.data_dir, family, &record_tail, value)?;
            super::substrate_store::admit_required(&state.data_dir, family, &record_tail, value)
                .map_err(|error| {
                    verr(
                        "system_writer_agentgres_admission_failed",
                        format!("required admission for '{family}/{record_tail}' failed ({error})"),
                    )
                })?;
            if load_required_exact(&state.data_dir, family, &record_tail)?.as_ref() != Some(value) {
                return Err(verr(
                    "system_writer_persist_failed",
                    "lost-suffix resolution did not converge byte-exactly",
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
            "op": RESOLVE_LOST_SUFFIX_OP,
            "lost_suffix_record": revision,
            "receipt": receipt,
            "nonclaims": {"suffix_replayed": false, "effects_reconciled": false}
        })),
    )
}

const FAILOVER_FIELDS: &[&str] = &["failover_profile"];

/// POST /v1/hypervisor/autonomous-systems/:id/writer/failover-profile
///
/// Declares the DESIRED failover posture as an owner-authorized durable
/// record. The declaration is compare-and-swap over the current active record
/// and can never assert an observed writer, health, or fencing fact.
pub(crate) async fn handle_declare_failover_profile(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_writer_source_key_invalid",
            "id is not canonical",
        ));
    }
    if let Err(error) = validate_request(&body, FAILOVER_FIELDS) {
        return classify(error);
    }
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let (source, plan) = match with_source_locks(|| {
        ensure_no_cross_plane_pending(&state.data_dir, &key)?;
        let source = load_writer_source(&state.data_dir, &key)?;
        let plan = build_failover_profile_plan(&source, &body)?;
        Ok::<_, VErr>((source, plan))
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let effect = plan["authority_effect"].clone();
    let system_id = source.binding.system_id.clone();
    let genesis_ref = source.binding.genesis_ref.clone();
    let governing = source.binding.source_governing_authority_ref.clone();
    let sequence = source.fence_head.active_epoch.max(1);
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
        DECLARE_FAILOVER_PROFILE_OP,
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
        DECLARE_FAILOVER_PROFILE_OP,
        sequence,
        DECLARE_FAILOVER_PROFILE_SCOPE,
        &governing,
        required_string(&plan, "/failover_profile_root").unwrap_or(""),
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
    let profile = plan["failover_profile"].clone();
    let profile_root = required(&plan, "/failover_profile_root").unwrap_or_default();
    let result = with_source_locks(|| {
        let fresh = load_writer_source(&state.data_dir, &key)?;
        if build_failover_profile_plan(&fresh, &body)? != plan {
            return Err(verr(
                "system_writer_head_conflict",
                "durable failover truth changed before commitment",
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
                FAILOVER_PROFILE_DIR,
                tail("aswfp_", &profile_root)?,
                &profile,
            ),
        ];
        for (family, record_tail, value) in records {
            persist_local(&state.data_dir, family, &record_tail, value)?;
            super::substrate_store::admit_required(&state.data_dir, family, &record_tail, value)
                .map_err(|error| {
                    verr(
                        "system_writer_agentgres_admission_failed",
                        format!("required admission for '{family}/{record_tail}' failed ({error})"),
                    )
                })?;
            if load_required_exact(&state.data_dir, family, &record_tail)?.as_ref() != Some(value) {
                return Err(verr(
                    "system_writer_persist_failed",
                    "failover declaration did not converge byte-exactly",
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
            "op": DECLARE_FAILOVER_PROFILE_OP,
            "failover_profile": profile,
            "failover_profile_root": profile_root,
            "nonclaims": {
                "observed_writer": false,
                "observed_health": false,
                "fencing_performed": false
            }
        })),
    )
}

/// Validate one declared failover profile against durable truth and produce
/// its closed governed effect. The declared record must cite the exact
/// current active record root (null for the first declaration).
pub(crate) fn build_failover_profile_plan(
    source: &WriterSource,
    body: &Value,
) -> Result<Value, VErr> {
    let profile = body.get("failover_profile").cloned().ok_or_else(|| {
        verr(
            "system_writer_request_invalid",
            "request lacks its failover_profile body",
        )
    })?;
    let root = validate_failover_profile(&profile, &source.binding).map_err(plan_err)?;
    let current_root = source.failover_profile_root.as_deref();
    if profile
        .get("predecessor_failover_profile_root")
        .and_then(Value::as_str)
        != current_root
    {
        return Err(verr(
            "system_writer_head_conflict",
            "failover declaration does not compare-and-swap the current active record",
        ));
    }
    let mut effect = json!({
        "schema_version": "ioi.autonomous-system-failover-profile-effect.v1",
        "op": DECLARE_FAILOVER_PROFILE_OP,
        "required_scope": DECLARE_FAILOVER_PROFILE_SCOPE,
        "system_id": source.binding.system_id,
        "genesis_ref": source.binding.genesis_ref,
        "source_governing_authority_ref": source.binding.source_governing_authority_ref,
        "failover_profile_ref": profile["failover_profile_id"],
        "failover_profile_root": root,
        "predecessor_failover_profile_root": current_root,
        "asserts_observed_truth": false,
        "operation_commitment": Value::Null,
    });
    let operation_commitment = jcs_hash(&json!({
        "domain": "ioi.autonomous-system-failover-profile-commitment-jcs-sha256.v1",
        "effect": effect,
    }))?;
    effect["operation_commitment"] = json!(operation_commitment);
    Ok(json!({
        "failover_profile": profile,
        "failover_profile_root": root,
        "authority_effect": effect,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::system_protected_transition_routes::DecisionAuthorityTuple;
    use super::*;
    use ioi_types::app::system_membership_transitions::{
        membership_record_root, membership_set_root,
    };
    use ioi_types::app::system_membership_transitions::{
        MembershipIdentityBinding, MembershipLogHead,
    };
    use ioi_types::app::system_writer_fence::{
        build_fence_context, evaluate_consequential_effect_fence, FenceContextOrigin,
        FenceServerTruth, ResourceFenceDeclaration, SuffixAcknowledgementCertainty,
        WRITER_TRANSITION_CONTRACT,
    };

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

    const SYSTEM: &str = "system://acme/system-alpha";
    const NODE_A: &str = "node://acme/system-alpha/alpha-node-1";
    const NODE_B: &str = "node://acme/system-alpha/beta-node-2";

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

    fn membership_binding() -> MembershipIdentityBinding {
        MembershipIdentityBinding {
            system_id: SYSTEM.into(),
            genesis_ref: "genesis://acme/system-alpha".into(),
            source_governing_authority_ref: "org://acme/research".into(),
            deployment_profile_ref: format!(
                "deployment-profile://acme/system-alpha/revision/sha256:{}",
                "a".repeat(64)
            ),
            deployment_profile_root: format!("sha256:{}", "d".repeat(64)),
            admitted_constitution_root: h(0x0B),
            admitted_manifest_root: h(0x0C),
        }
    }

    fn writer_binding() -> WriterIdentityBinding {
        WriterIdentityBinding {
            system_id: SYSTEM.into(),
            genesis_ref: "genesis://acme/system-alpha".into(),
            source_governing_authority_ref: "org://acme/research".into(),
            deployment_profile_ref: membership_binding().deployment_profile_ref,
            deployment_profile_root: membership_binding().deployment_profile_root,
            ordering_profile_ref: "ordering-profile://acme/system-alpha/single-writer-v1".into(),
            ordering_profile_root: h(0x2F),
            authority_revocation_snapshot_ref: "snapshot://acme/authority-revocation/12".into(),
            authority_revocation_epoch: 12,
        }
    }

    fn member(node_id: &str, node_tail: &str, epoch: u64, roles: &[&str]) -> Value {
        let assignments: Vec<Value> = roles
            .iter()
            .map(|role| {
                json!({
                    "role": role,
                    "role_scope_refs": [],
                    "authority_grant_refs": [],
                    "role_lease_ref": Value::Null,
                    "admitted_epoch": epoch,
                    "valid_from": Value::Null,
                    "expires_at": Value::Null,
                })
            })
            .collect();
        json!({
            "schema_version": "ioi.autonomous-system-node-membership.v1",
            "node_membership_id": format!("node-membership://acme/system-alpha/node/{node_tail}"),
            "system_id": SYSTEM,
            "deployment_profile_ref": membership_binding().deployment_profile_ref,
            "node_id": node_id,
            "node_owner_ref": "wallet://acme/node-owner",
            "membership_epoch": epoch,
            "membership_lease_ref": format!("lease://acme/system-alpha/membership/{node_tail}"),
            "role_assignments": assignments,
            "failure_domain_refs": [],
            "failure_independence_evidence_refs": [],
            "node_attestation_refs": [format!("attestation://acme/{node_tail}/boot")],
            "conformance_profile_refs": [],
            "admission": {
                "proposal_ref": format!("proposal://acme/system-alpha/membership/{node_tail}"),
                "decision_ref": format!("decision://acme/system-alpha/membership/{node_tail}"),
                "admitted_constitution_root": h(0x0B),
                "admitted_manifest_root": h(0x0C),
                "admitted_deployment_profile_root": membership_binding().deployment_profile_root,
            },
            "synchronization": {
                "checkpoint_ref": Value::Null,
                "operation_offset": 7,
                "verified_state_root": h(0x0E),
                "catchup_receipt_ref": format!("receipt://acme/system-alpha/catchup/{node_tail}/7"),
                "verified_at": Value::Null,
            },
            "writer_fencing": {
                "writer_epoch": Value::Null,
                "writer_epoch_transition_ref": Value::Null,
                "writer_epoch_transition_hash": Value::Null,
                "writer_lease_ref": Value::Null,
                "promotion_receipt_ref": Value::Null,
            },
            "observation": {
                "readiness": "ready",
                "health_observation_ref": Value::Null,
                "heartbeat_ref": Value::Null,
                "readiness_evidence_refs": [format!("attestation://acme/{node_tail}/readiness/7")],
                "last_heartbeat_at": Value::Null,
                "last_observed_at": "2026-07-28T11:59:00Z",
                "observation_expires_at": "2026-07-28T13:59:00Z",
            },
            "status": "active",
        })
    }

    fn failover_profile(mechanism: &str) -> Value {
        let mut profile = json!({
            "schema_version": "ioi.autonomous-system-failover-profile.v1",
            "failover_profile_id": "failover-profile://acme/system-alpha/primary",
            "system_id": SYSTEM,
            "version": "1.0.0",
            "response_authorization_mode": "manual_governance",
            "recovery_mechanism": mechanism,
            "ambiguous_partition_response": "fail_closed",
            "deployment_timing_assumptions": {
                "evidence_mode": "bounded_clock_partial_synchrony",
                "temporal_verification_profile_ref": "policy://acme/temporal/writer-v1",
                "maximum_clock_skew_or_uncertainty_ms": 250,
                "heartbeat_interval_ms": 1000,
                "heartbeat_evidence_expires_after_ms": 3000,
                "writer_lease_ttl_ms": 10000,
                "writer_lease_renewal_margin_ms": 2500,
                "maximum_effect_lease_ttl_ms": 5000,
                "maximum_revocation_propagation_ms": 1000,
                "promotion_waitout_policy_ref": "policy://acme/writer/waitout-v1",
            },
            "durable_continuity_cas": {
                "mechanism": "wallet_epoch_authority",
                "substrate_ref": "wallet://wallet.network/acme",
                "head_namespace": "acme/system-alpha/writer",
                "cas_proof_schema_ref": WRITER_TRANSITION_CONTRACT,
                "minimum_independent_witnesses": 0,
                "unavailable_or_ambiguous_response": "fail_closed",
            },
            "single_writer_restore": Value::Null,
            "single_writer_promotion": Value::Null,
            "ordering_profile_recovery": Value::Null,
            "predecessor_failover_profile_root": Value::Null,
            "status": "active",
        });
        if mechanism == "single_writer_promotion" {
            profile["single_writer_promotion"] = json!({
                "candidate_role": "hot_standby",
                "minimum_durability": "device_flush",
                "require_latest_verified_state_root": true,
                "require_catchup_receipt": true,
                "require_writer_epoch_increment": true,
                "require_old_writer_fencing": true,
                "promotion_policy_ref": "policy://acme/writer/promotion-v1",
            });
        }
        profile
    }

    fn source_with(
        failover: Option<Value>,
        transitions: Vec<Value>,
        lost_suffix_revisions: Vec<Value>,
    ) -> WriterSource {
        let records = vec![
            member(NODE_A, "alpha-node-1", 3, &["state_replica"]),
            member(NODE_B, "beta-node-2", 5, &["hot_standby"]),
        ];
        let membership_root = membership_set_root(SYSTEM, &records).expect("set root");
        let fence_head = replay_writer_epoch_transitions(SYSTEM, &transitions).expect("replay");
        let failover_root = failover
            .as_ref()
            .map(|profile| failover_profile_root(profile).expect("failover root"));
        WriterSource {
            membership: MembershipSource {
                binding: membership_binding(),
                desired_topology: None,
                desired_topology_root: None,
                transitions: Vec::new(),
                records,
                head: MembershipLogHead {
                    sequence: 4,
                    membership_root,
                },
                consumed_role_lease_refs: Vec::new(),
            },
            binding: writer_binding(),
            failover_profile: failover,
            failover_profile_root: failover_root,
            transitions,
            fence_head,
            lost_suffix_revisions,
        }
    }

    fn evaluation_hash_for(evaluation: &Value) -> String {
        jcs_hash(&json!({
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
        .expect("evaluation hash")
    }

    fn trusted_for(
        source: &WriterSource,
        node_id: &str,
        node_tail: &str,
        promotion: bool,
    ) -> WriterTrustedInputs {
        let record = source
            .membership
            .records
            .iter()
            .find(|record| record.get("node_id").and_then(Value::as_str) == Some(node_id))
            .expect("candidate record");
        let record_root = membership_record_root(record).expect("record root");
        let profile = fixture("temporal-verification-profile-v1/positive-declared.json");
        let mut evaluation = fixture("temporal-validity-evaluation-v1/positive-online-fresh.json");
        evaluation["evaluation_id"] = json!(format!(
            "temporal-evaluation://acme/system-alpha/writer/{node_tail}"
        ));
        evaluation["profile_ref"] = profile["profile_ref"].clone();
        evaluation["profile_hash"] = profile["profile_hash"].clone();
        evaluation["subject_ref"] = json!(node_id);
        evaluation["subject_hash"] = json!(record_root);
        evaluation["evidence_horizon"] = json!({
            "valid_from": "2026-07-28T12:00:00Z",
            "valid_until": "2026-07-28T12:30:00Z",
        });
        evaluation["evaluation_hash"] = json!(evaluation_hash_for(&evaluation));
        WriterTrustedInputs {
            attested_node: fixture("hypervisoros-node-v1/positive-ready.json"),
            catchup_receipt: json!({
                "receipt_ref": format!("receipt://acme/system-alpha/catchup/{node_tail}/7"),
                "node_id": node_id,
                "operation_offset": 7,
                "verified_state_root": h(0x0E),
                "checkpoint_ref": Value::Null,
            }),
            temporal_profile: profile,
            temporal_evaluation: evaluation,
            displaced: promotion.then(|| DisplacedWriterObservation {
                writer_fence_receipt_refs: vec![
                    "receipt://acme/system-alpha/writer/fence/epoch-1".into()
                ],
                effect_lease_fence_receipt_refs: vec![
                    "receipt://acme/system-alpha/writer/effect-fence/epoch-1".into(),
                ],
                displaced_writer_leases_expire_at: "2026-07-28T12:00:20Z".into(),
                revocation_propagation_complete_at: "2026-07-28T12:00:10Z".into(),
                maximum_clock_skew_or_uncertainty_ms: 250,
                witness_evidence_refs: vec![],
            }),
            prior_log: promotion.then(|| PriorWriterLogObservation {
                last_common_offset: 7,
                last_common_state_root: h(0x0E),
                acknowledged_offset: 9,
                authoritative_head_offset: 7,
                authoritative_head_state_root: h(0x0E),
                entry_commitment_refs: vec![
                    (8, "commitment://acme/system-alpha/op/8".into()),
                    (9, "commitment://acme/system-alpha/op/9".into()),
                ],
                custody_artifact_refs: vec![
                    "artifact://acme/system-alpha/lost-suffix/epoch-2/bytes".into(),
                ],
                acknowledgement_certainty: SuffixAcknowledgementCertainty::Ambiguous,
                reconciliation_policy_ref: "policy://acme/lost-suffix/reconciliation-v1".into(),
            }),
        }
    }

    fn declaration(
        node_id: &str,
        node_tail: &str,
        source: &WriterSource,
        predecessor: Option<String>,
    ) -> WriterTransitionDeclaration {
        WriterTransitionDeclaration {
            candidate_node_id: node_id.into(),
            expected_predecessor_transition_hash: predecessor,
            expected_membership_root: source.membership.head.membership_root.clone(),
            writer_lease_ref: format!("lease://acme/system-alpha/writer/{node_tail}"),
            catchup_receipt_ref: format!("receipt://acme/system-alpha/catchup/{node_tail}/7"),
            state_root_verification_ref: format!(
                "verification://acme/system-alpha/state-root/7-{node_tail}"
            ),
            attested_node_ref: "hypervisoros-node://acme/estate-1/node/alpha-node-1".into(),
            temporal_validity_evaluation_ref: format!(
                "temporal-evaluation://acme/system-alpha/writer/{node_tail}"
            ),
            resource_fences: vec![ResourceFenceDeclaration {
                resource_id: "wallet.network/effects".into(),
                allowed_effect_kinds: vec!["external_effect".into()],
                minimum_read_consistency: "state_root_consistent".into(),
                read_watermark: "operation-offset:7".into(),
            }],
            evidence_refs: vec![],
        }
    }

    /// The full plane ladder: declare the failover posture, claim the genesis
    /// epoch, prove the fence admits exactly the active writer, hand over to
    /// the standby with the excluded suffix retained, prove the old epoch
    /// reaches zero selected final invokers, then resolve custody per entry —
    /// with every registered envelope validated inside the builds.
    #[test]
    fn writer_ladder_artifacts_validate_every_registered_envelope() {
        // Step 0 — declared failover posture (structural validation + CAS).
        let empty = source_with(None, Vec::new(), Vec::new());
        let declare = build_failover_profile_plan(
            &empty,
            &json!({"failover_profile": failover_profile("unavailable_fail_closed")}),
        )
        .expect("failover declaration plan");
        assert_eq!(declare["authority_effect"]["asserts_observed_truth"], false);

        // Step 1 — genesis claim.
        let source = source_with(
            Some(failover_profile("unavailable_fail_closed")),
            Vec::new(),
            Vec::new(),
        );
        let genesis_declaration = declaration(NODE_A, "alpha-node-1", &source, None);
        let trusted = trusted_for(&source, NODE_A, "alpha-node-1", false);
        let plan = compile_from_source(
            WriterEpochTransitionKind::Genesis,
            &source,
            &genesis_declaration,
            &trusted,
        )
        .unwrap_or_else(|(code, message)| panic!("genesis: {code} {message}"));
        assert_eq!(plan.writer_epoch, 1);
        assert_eq!(plan.authority_effect["writer_authority_admitted"], true);
        let genesis = build_writer_step_artifacts(&plan, &authority(), "2026-07-28T12:00:05Z")
            .unwrap_or_else(|(code, message)| panic!("genesis build: {code} {message}"));
        assert!(genesis.lost_suffix.is_none());

        // Step 2 — the fence admits exactly the active writer.
        let transitions = vec![genesis.transition.clone()];
        let source = source_with(
            Some(failover_profile("single_writer_promotion")),
            transitions,
            Vec::new(),
        );
        assert_eq!(source.fence_head.active_epoch, 1);
        let active = source.fence_head.active_transition.clone().expect("active");
        let membership_root = source.membership.head.membership_root.clone();
        let payload_hash = h(0x61);
        let truth = FenceServerTruth {
            system_id: SYSTEM,
            executing_node_id: NODE_A,
            active_transition: Some(&active),
            node_membership_root: &membership_root,
            deployment_profile_root:
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            authority_revocation_epoch: 12,
            read_state_root:
                "sha256:0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e",
            read_watermark: "operation-offset:7",
            expected_payload_hash: &payload_hash,
            now: "2026-07-28T12:00:06Z",
        };
        let context = build_fence_context(
            &truth,
            "wallet.network/effects",
            "external_effect",
            "effect-1",
            "2026-07-28T12:03:00Z",
            "2026-07-28T12:00:36Z",
            "temporal-evaluation://acme/system-alpha/effect/1",
            &h(0x4E),
        )
        .expect("PEP context");
        let verdict =
            evaluate_consequential_effect_fence(&truth, &context, FenceContextOrigin::PepGenerated);
        assert!(verdict.admitted, "{:?}", verdict.refusal_reason);
        assert_eq!(verdict.selected_final_invokers, 1);

        // Step 3 — handover: the standby is promoted, the old writer fenced,
        // the acknowledged-but-not-finalized suffix retained.
        let handover_declaration = declaration(
            NODE_B,
            "beta-node-2",
            &source,
            Some(genesis.transition_hash.clone()),
        );
        let trusted = trusted_for(&source, NODE_B, "beta-node-2", true);
        let plan = compile_from_source(
            WriterEpochTransitionKind::Promotion,
            &source,
            &handover_declaration,
            &trusted,
        )
        .unwrap_or_else(|(code, message)| panic!("promotion: {code} {message}"));
        assert_eq!(plan.writer_epoch, 2);
        let handover = build_writer_step_artifacts(&plan, &authority(), "2026-07-28T12:00:07Z")
            .unwrap_or_else(|(code, message)| panic!("promotion build: {code} {message}"));
        let (suffix, suffix_root) = handover.lost_suffix.clone().expect("suffix retained");
        assert_eq!(suffix["prior_writer_epoch"], 1);
        assert_eq!(suffix["successor_writer_epoch"], 2);

        // Step 4 — the old epoch is fenced to zero selected final invokers.
        let transitions = vec![genesis.transition.clone(), handover.transition.clone()];
        let source = source_with(
            Some(failover_profile("single_writer_promotion")),
            transitions.clone(),
            vec![suffix.clone()],
        );
        assert_eq!(source.fence_head.active_epoch, 2);
        let active = source.fence_head.active_transition.clone().expect("active");
        let mut old_truth = truth.clone();
        old_truth.active_transition = Some(&active);
        old_truth.now = "2026-07-28T12:00:21Z";
        let verdict = evaluate_consequential_effect_fence(
            &old_truth,
            &context,
            FenceContextOrigin::PepGenerated,
        );
        assert!(!verdict.admitted);
        assert_eq!(verdict.selected_final_invokers, 0);
        assert_eq!(verdict.refusal_dimension, Some("stale"));

        // Step 5 — per-entry custody resolution through the governed build.
        let resolution_body = json!({
            "lost_suffix_record_id": suffix["lost_suffix_record_id"],
            "resulting_status": "reconciled",
            "resolutions": [
                {
                    "operation_offset": 8,
                    "custody_status": "resolved",
                    "resolution_receipt_ref":
                        "receipt://acme/system-alpha/lost-suffix/epoch-2/op-8",
                    "resolution_evidence_refs": []
                },
                {
                    "operation_offset": 9,
                    "custody_status": "refused",
                    "resolution_receipt_ref":
                        "receipt://acme/system-alpha/lost-suffix/epoch-2/op-9",
                    "resolution_evidence_refs": []
                }
            ]
        });
        let resolution_plan = build_lost_suffix_resolution_plan(&source, &resolution_body)
            .unwrap_or_else(|(code, message)| panic!("resolution: {code} {message}"));
        assert_eq!(
            resolution_plan["authority_effect"]["entries_silently_dropped"],
            false
        );
        let (revision, revision_root, resolution_receipt, _receipt_root) =
            build_lost_suffix_resolution_artifacts(
                &resolution_plan,
                &authority(),
                "2026-07-28T12:05:00Z",
            )
            .unwrap_or_else(|(code, message)| panic!("resolution build: {code} {message}"));
        assert_eq!(revision["status"], "reconciled");
        assert_eq!(revision["predecessor_record_root"], json!(suffix_root));
        assert_ne!(revision_root, suffix_root);
        assert_eq!(resolution_receipt["receipt_type"], "lost_suffix_resolution");

        // Step 6 — restart: the projection rebuilds byte-exactly from the
        // durable transition log and lost-suffix revisions alone.
        let before = build_writer_projection(
            SYSTEM,
            &source.fence_head,
            &[suffix.clone(), revision.clone()],
        )
        .expect("projection");
        let stored: Vec<Value> = transitions
            .iter()
            .map(|value| {
                serde_json::from_str(&serde_json::to_string(value).expect("bytes"))
                    .expect("transition")
            })
            .collect();
        let head_after = replay_writer_epoch_transitions(SYSTEM, &stored).expect("replay");
        let after = build_writer_projection(SYSTEM, &head_after, &[suffix, revision])
            .expect("projection after restart");
        assert_eq!(
            serde_json::to_string(&before).expect("bytes"),
            serde_json::to_string(&after).expect("bytes")
        );
        // The current revision is the reconciled one; the superseded open
        // revision is lineage, not currency.
        assert_eq!(after["lost_suffixes"].as_array().expect("rows").len(), 1);
        assert_eq!(after["lost_suffixes"][0]["status"], "reconciled");
        assert_eq!(after["lost_suffixes"][0]["retained_ambiguous_entries"], 0);
    }

    #[test]
    fn writer_ops_have_owner_scopes_and_never_parse_as_other_families() {
        for kind in WriterEpochTransitionKind::ALL {
            assert_eq!(
                AUTHORITY.operation_scope(kind.as_str()),
                kind.required_scope()
            );
            assert!(
                ioi_types::app::system_membership_transitions::MembershipTransitionOp::parse(
                    kind.as_str()
                )
                .is_none()
            );
            assert!(
                ioi_types::app::system_lifecycle_transitions::ProtectedTransitionOp::parse(
                    kind.as_str()
                )
                .is_none()
            );
            assert!(
                ioi_types::app::system_continuity_transitions::ContinuityTransitionOp::parse(
                    kind.as_str()
                )
                .is_none()
            );
        }
        assert_eq!(
            AUTHORITY.operation_scope(DECLARE_FAILOVER_PROFILE_OP),
            DECLARE_FAILOVER_PROFILE_SCOPE
        );
        assert_eq!(
            AUTHORITY.operation_scope(RESOLVE_LOST_SUFFIX_OP),
            RESOLVE_LOST_SUFFIX_SCOPE
        );
    }

    #[test]
    fn projection_without_any_writer_truth_is_honest() {
        let projection = build_writer_projection(
            "system://acme/system-alpha",
            &WriterFenceHead {
                active_epoch: 0,
                active_transition: None,
            },
            &[],
        )
        .expect("empty projection");
        assert_eq!(projection["state"], "honest_empty");
        assert_eq!(projection["active"], Value::Null);
        assert_eq!(projection["nonclaims"]["public_finality"], false);
    }

    #[test]
    fn registered_transition_fixture_replays_into_the_projection() {
        let genesis = fixture("autonomous-system-writer-epoch-transition-v1/positive-genesis.json");
        let head =
            replay_writer_epoch_transitions("system://acme/system-alpha", &[genesis.clone()])
                .expect("replay");
        assert_eq!(head.active_epoch, 1);
        let suffix = fixture("lost-suffix-record-v1/positive-open-retained.json");
        let projection =
            build_writer_projection("system://acme/system-alpha", &head, &[suffix.clone()])
                .expect("projection");
        assert_eq!(projection["state"], "ready");
        assert_eq!(projection["active"]["writer_epoch"], 1);
        assert_eq!(
            projection["lost_suffixes"][0]["retained_ambiguous_entries"],
            2
        );

        // Restart: the projection rebuilds byte-exactly from durable bytes.
        let bytes = serde_json::to_string(&genesis).expect("bytes");
        let reloaded: Vec<Value> = vec![serde_json::from_str(&bytes).expect("transition")];
        let head_after = replay_writer_epoch_transitions("system://acme/system-alpha", &reloaded)
            .expect("replay after restart");
        let after = build_writer_projection("system://acme/system-alpha", &head_after, &[suffix])
            .expect("projection after restart");
        assert_eq!(
            serde_json::to_string(&projection).expect("bytes"),
            serde_json::to_string(&after).expect("bytes")
        );
    }
}
