//! Profile-native ordering/finality recovery and operational transition commitments.
//!
//! Single-writer systems are deliberately excluded: they recover through the
//! writer-epoch/fencing plane. Threshold, BFT, membership-reconfiguration, and
//! external-finality recoveries collect authenticated, profile-eligible votes
//! over one immutable candidate. Only the threshold-crossing request emits the
//! committed recovery and its complete non-economic StateTransitionCommitment.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::system_activation_routes::{
    canonical_system_key, classify, contains_sensitive_key, enumerate_family, jcs_hash,
    load_required_exact, persist_local, required_string, tail, validate_contract, verr,
};
use super::DaemonState;

pub(crate) const RECOVERY_VOTE_DIR: &str = "autonomous-system-ordering-recovery-votes";
pub(crate) const RECOVERY_RECEIPT_DIR: &str = "autonomous-system-ordering-recovery-receipts";
pub(crate) const RECOVERY_DIR: &str = "autonomous-system-ordering-recoveries";
pub(crate) const COMMITMENT_DIR: &str = "autonomous-system-state-transition-commitments";

const RECOVERY_CONTRACT: &str = "schema://ioi/foundations/ordering-finality-recovery/v1";
const COMMITMENT_CONTRACT: &str = "schema://ioi/foundations/state-transition-commitment/v1";
const RECEIPT_CONTRACT: &str = "schema://ioi/foundations/receipt-envelope/v1";
const RECOVERY_SCOPE: &str = "scope:autonomous_system.ordering.recover";

type VErr = (String, String);

static ORDERING_RECOVERY_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug)]
struct RecoveryPlan {
    proposed: Value,
    candidate_hash: String,
    system_id: String,
    profile: Value,
    profile_hash: String,
    principal_ref: String,
    principal_proof_ref: String,
    hypervisor_node_id: String,
    acting_node_membership_ref: String,
    operation_or_batch_commitment: String,
    resulting_state_root: String,
    finality_proof_ref: String,
    external_settlement_ref: Option<String>,
    expected_transition_commitment_ref: String,
    required_votes: usize,
    eligible_principals: BTreeSet<String>,
    bootstrap_head: BootstrapHead,
}

#[derive(Clone, Debug)]
struct BootstrapHead {
    sequence: u64,
    transition_commitment_ref: String,
    state_root: String,
}

fn required(value: &Value, pointer: &str) -> Result<String, VErr> {
    required_string(value, pointer).map(str::to_owned)
}

fn strings(value: &Value, pointer: &str) -> Result<Vec<String>, VErr> {
    let values = value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "system_ordering_recovery_request_invalid",
                format!("{pointer} must be an array"),
            )
        })?;
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        out.push(
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    verr(
                        "system_ordering_recovery_request_invalid",
                        format!("{pointer} contains a non-string or empty value"),
                    )
                })?
                .to_owned(),
        );
    }
    if out.iter().collect::<BTreeSet<_>>().len() != out.len() {
        return Err(verr(
            "system_ordering_recovery_request_invalid",
            format!("{pointer} contains duplicates"),
        ));
    }
    Ok(out)
}

fn nullable(value: &Value, pointer: &str) -> Result<Option<String>, VErr> {
    match value.pointer(pointer) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        _ => Err(verr(
            "system_ordering_recovery_request_invalid",
            format!("{pointer} must be null or a nonempty string"),
        )),
    }
}

fn exact_keys(value: &Value, expected: &[&str], label: &str) -> Result<(), VErr> {
    let object = value.as_object().ok_or_else(|| {
        verr(
            "system_ordering_recovery_request_invalid",
            format!("{label} must be an object"),
        )
    })?;
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    if actual != expected {
        return Err(verr(
            "system_ordering_recovery_request_invalid",
            format!("{label} has an open, missing, or server-owned field"),
        ));
    }
    Ok(())
}

fn recovery_class_allowed(profile: &str, class: &str) -> bool {
    matches!(
        (profile, class),
        ("threshold_authority", "threshold_view_or_round")
            | ("threshold_authority", "membership_reconfiguration")
            | ("bft_consensus", "bft_view_or_round")
            | ("bft_consensus", "membership_reconfiguration")
            | ("external_chain_finality", "external_finality_rebind")
    )
}

fn bootstrap_head(chain: &Value) -> Result<BootstrapHead, VErr> {
    let sequence = chain
        .get("latest_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            verr(
                "system_ordering_recovery_source_incomplete",
                "live System chain lacks its latest sequence",
            )
        })?;
    let state_root = required(chain, "/latest_state_root")?;
    let transition_commitment_ref = match chain.get("latest_transition_commitment_ref") {
        Some(Value::String(reference)) if !reference.is_empty() => reference.clone(),
        Some(Value::Null) => {
            let operation = required(chain, "/latest_operation_commitment")?;
            format!("commitment://system-operation/{operation}")
        }
        _ => {
            return Err(verr(
                "system_ordering_recovery_source_incomplete",
                "live System chain has a malformed transition-commitment head",
            ))
        }
    };
    Ok(BootstrapHead {
        sequence,
        transition_commitment_ref,
        state_root,
    })
}

fn evaluate_submission(
    policies: &super::system_policy_routes::ActiveSystemPolicies,
    membership: &super::system_membership_routes::MembershipSource,
    bootstrap_head: &BootstrapHead,
    principal_ref: &str,
    body: &Value,
) -> Result<RecoveryPlan, VErr> {
    exact_keys(
        body,
        &[
            "acting_node_membership_ref",
            "expected_transition_commitment_ref",
            "external_settlement_ref",
            "finality_proof_ref",
            "hypervisor_node_id",
            "operation_or_batch_commitment",
            "principal_proof_ref",
            "recovery",
            "resulting_state_root",
        ],
        "ordering recovery submission",
    )?;
    if contains_sensitive_key(body) {
        return Err(verr(
            "system_ordering_recovery_request_invalid",
            "ordering recovery submission contains secret-bearing material",
        ));
    }
    let proposed = body.get("recovery").cloned().ok_or_else(|| {
        verr(
            "system_ordering_recovery_request_invalid",
            "ordering recovery submission lacks its recovery candidate",
        )
    })?;
    validate_contract(RECOVERY_CONTRACT, &proposed, "ordering recovery candidate")
        .map_err(|(_, message)| verr("system_ordering_recovery_request_invalid", message))?;
    if proposed.get("status").and_then(Value::as_str) != Some("proposed")
        || proposed.get("result") != Some(&Value::Null)
        || !strings(&proposed, "/authority_grant_refs")?.is_empty()
    {
        return Err(verr(
            "system_ordering_recovery_request_invalid",
            "caller recovery must be proposed, carry no result, and claim no authority grants",
        ));
    }
    let system_id = required(&proposed, "/system_id")?;
    if system_id != policies.system_id || system_id != membership.binding.system_id {
        return Err(verr(
            "system_ordering_recovery_profile_refused",
            "recovery candidate does not belong to the active System",
        ));
    }
    let profile = &policies.ordering_profile;
    let profile_kind = required(profile, "/profile")?;
    if matches!(
        profile_kind.as_str(),
        "single_authority" | "replicated_single_authority"
    ) {
        return Err(verr(
            "system_ordering_recovery_profile_refused",
            "single-writer recovery belongs to the writer-epoch and fencing plane",
        ));
    }
    let class = required(&proposed, "/recovery_class")?;
    if !recovery_class_allowed(&profile_kind, &class) {
        return Err(verr(
            "system_ordering_recovery_profile_refused",
            "recovery class is not native to the active ordering/finality profile",
        ));
    }
    if required(&proposed, "/ordering_admission_finality_profile_ref")?
        != required(profile, "/ordering_profile_id")?
    {
        return Err(verr(
            "system_ordering_recovery_profile_refused",
            "recovery candidate does not bind the active ordering/finality profile",
        ));
    }
    let desired_topology = membership.desired_topology.as_ref().ok_or_else(|| {
        verr(
            "system_ordering_recovery_profile_refused",
            "profile-native recovery requires an active desired-topology declaration",
        )
    })?;
    if required(&proposed, "/failover_profile_ref")?
        != required(desired_topology, "/failover_profile_ref")?
    {
        return Err(verr(
            "system_ordering_recovery_profile_refused",
            "recovery candidate does not bind the active desired-topology failover profile",
        ));
    }
    let eligible = strings(profile, "/authority_distribution/principal_refs")?;
    if eligible.is_empty() || !eligible.iter().any(|value| value == principal_ref) {
        return Err(verr(
            "system_ordering_recovery_authority_required",
            "authenticated principal is not eligible under the active profile",
        ));
    }
    let required_votes = profile
        .pointer("/admission/threshold/required")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0 && *value <= eligible.len())
        .ok_or_else(|| {
            verr(
                "system_ordering_recovery_profile_refused",
                "active profile declares an impossible authority threshold",
            )
        })?;
    if profile
        .pointer("/admission/threshold/eligible")
        .and_then(Value::as_u64)
        != u64::try_from(eligible.len()).ok()
    {
        return Err(verr(
            "system_ordering_recovery_profile_refused",
            "active profile threshold eligibility does not equal its distinct principal set",
        ));
    }
    let expected_membership = required(&proposed, "/transition/expected_membership_root")?;
    if expected_membership != membership.head.membership_root {
        return Err(verr(
            "system_ordering_recovery_membership_conflict",
            "recovery expected membership root is not current",
        ));
    }
    let resulting_membership = required(&proposed, "/transition/resulting_membership_root")?;
    if class != "membership_reconfiguration" && resulting_membership != expected_membership {
        return Err(verr(
            "system_ordering_recovery_membership_conflict",
            "non-membership recovery cannot change the membership root",
        ));
    }
    if class == "membership_reconfiguration" {
        let transition_ref = nullable(&proposed, "/transition/membership_transition_ref")?
            .ok_or_else(|| {
                verr(
                    "system_ordering_recovery_evidence_refused",
                    "membership recovery lacks its exact membership transition",
                )
            })?;
        let resolved = membership.transitions.iter().any(|value| {
            value
                .get("membership_transition_id")
                .and_then(Value::as_str)
                == Some(transition_ref.as_str())
                && value
                    .get("resulting_membership_root")
                    .and_then(Value::as_str)
                    == Some(resulting_membership.as_str())
        });
        if !resolved {
            return Err(verr(
                "system_ordering_recovery_evidence_refused",
                "membership transition is not resolvable from current durable membership truth",
            ));
        }
    }
    let principal_proof_ref = required(body, "/principal_proof_ref")?;
    let proofs = strings(&proposed, "/transition/threshold_or_consensus_proof_refs")?;
    if matches!(
        class.as_str(),
        "threshold_view_or_round" | "bft_view_or_round"
    ) && !proofs.iter().any(|value| value == &principal_proof_ref)
    {
        return Err(verr(
            "system_ordering_recovery_evidence_refused",
            "authenticated principal proof is outside the candidate proof set",
        ));
    }
    if class == "external_finality_rebind"
        && nullable(&proposed, "/transition/external_finality_recovery_ref")?.as_deref()
            != Some(principal_proof_ref.as_str())
    {
        return Err(verr(
            "system_ordering_recovery_evidence_refused",
            "external-finality principal proof does not equal the declared recovery proof",
        ));
    }
    if strings(&proposed, "/trigger_evidence_refs")?.is_empty()
        || required(&proposed, "/transition/recovery_proof_ref")?.is_empty()
        || nullable(&proposed, "/governing_decision_ref")?.is_none()
    {
        return Err(verr(
            "system_ordering_recovery_evidence_refused",
            "recovery requires trigger evidence, a recovery proof, and a governing decision",
        ));
    }
    let acting_ref = required(body, "/acting_node_membership_ref")?;
    let hypervisor_node_id = required(body, "/hypervisor_node_id")?;
    if !strings(profile, "/ordering/member_node_membership_refs")?
        .iter()
        .any(|reference| reference == &acting_ref)
    {
        return Err(verr(
            "system_ordering_recovery_membership_refused",
            "acting membership is outside the active ordering member set",
        ));
    }
    let acting = membership
        .records
        .iter()
        .find(|value| {
            value.get("node_membership_id").and_then(Value::as_str) == Some(acting_ref.as_str())
        })
        .ok_or_else(|| {
            verr(
                "system_ordering_recovery_membership_refused",
                "acting membership is not present in current durable membership truth",
            )
        })?;
    if acting.get("node_id").and_then(Value::as_str) != Some(hypervisor_node_id.as_str())
        || !matches!(
            acting.get("status").and_then(Value::as_str),
            Some("active" | "admitted")
        )
    {
        return Err(verr(
            "system_ordering_recovery_membership_refused",
            "acting node and current membership do not form an admitted exact pair",
        ));
    }
    let expected_transition_commitment_ref = required(body, "/expected_transition_commitment_ref")?;
    if required(&proposed, "/predecessor/transition_commitment_ref")?
        != expected_transition_commitment_ref
    {
        return Err(verr(
            "system_ordering_recovery_commitment_conflict",
            "request and recovery candidate disagree on the predecessor commitment",
        ));
    }
    let finality_proof_ref = required(body, "/finality_proof_ref")?;
    let candidate_hash = jcs_hash(&json!({
        "domain":"ioi.ordering-finality-recovery-candidate-jcs-sha256.v1",
        "recovery":proposed,
        "hypervisor_node_id":hypervisor_node_id,
        "acting_node_membership_ref":acting_ref,
        "operation_or_batch_commitment":required(body, "/operation_or_batch_commitment")?,
        "resulting_state_root":required(body, "/resulting_state_root")?,
        "finality_proof_ref":finality_proof_ref,
        "external_settlement_ref":nullable(body, "/external_settlement_ref")?,
    }))?;
    Ok(RecoveryPlan {
        proposed,
        candidate_hash,
        system_id,
        profile_hash: jcs_hash(profile)?,
        profile: profile.clone(),
        principal_ref: principal_ref.to_owned(),
        principal_proof_ref,
        hypervisor_node_id,
        acting_node_membership_ref: acting_ref,
        operation_or_batch_commitment: required(body, "/operation_or_batch_commitment")?,
        resulting_state_root: required(body, "/resulting_state_root")?,
        finality_proof_ref,
        external_settlement_ref: nullable(body, "/external_settlement_ref")?,
        expected_transition_commitment_ref,
        required_votes,
        eligible_principals: eligible.into_iter().collect(),
        bootstrap_head: bootstrap_head.clone(),
    })
}

fn persist_exact(
    data_dir: &str,
    family: &str,
    record_tail: &str,
    value: &Value,
) -> Result<(), VErr> {
    persist_local(data_dir, family, record_tail, value)?;
    super::substrate_store::admit_required(data_dir, family, record_tail, value).map_err(
        |error| {
            verr(
                "system_ordering_recovery_admission_failed",
                format!("required admission for '{family}/{record_tail}' failed ({error})"),
            )
        },
    )?;
    if load_required_exact(data_dir, family, record_tail)? != Some(value.clone()) {
        return Err(verr(
            "system_ordering_recovery_evidence_mismatch",
            format!("'{family}/{record_tail}' did not converge byte-exact"),
        ));
    }
    Ok(())
}

fn exact_records(data_dir: &str, family: &str, contract: &str) -> Result<Vec<Value>, VErr> {
    let mut out = Vec::new();
    for (record_tail, value) in enumerate_family(data_dir, family)? {
        validate_contract(contract, &value, family)?;
        super::substrate_store::admit_required(data_dir, family, &record_tail, &value).map_err(
            |error| {
                verr(
                    "system_ordering_recovery_admission_failed",
                    format!("required admission for '{family}/{record_tail}' failed ({error})"),
                )
            },
        )?;
        if load_required_exact(data_dir, family, &record_tail)? != Some(value.clone()) {
            return Err(verr(
                "system_ordering_recovery_evidence_mismatch",
                format!("'{family}/{record_tail}' diverges across durable truth"),
            ));
        }
        out.push(value);
    }
    Ok(out)
}

fn current_commitment(data_dir: &str, system_id: &str) -> Result<Option<Value>, VErr> {
    let records: Vec<Value> = exact_records(data_dir, COMMITMENT_DIR, COMMITMENT_CONTRACT)?
        .into_iter()
        .filter(|value| value.get("system_id").and_then(Value::as_str) == Some(system_id))
        .collect();
    let cited: BTreeSet<String> = records
        .iter()
        .filter_map(|value| {
            value
                .get("expected_predecessor_commitment_ref")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let mut heads: Vec<Value> = records
        .into_iter()
        .filter(|value| {
            value
                .get("resulting_transition_commitment_ref")
                .and_then(Value::as_str)
                .is_some_and(|reference| !cited.contains(reference))
        })
        .collect();
    match heads.len() {
        0 => Ok(None),
        1 => Ok(heads.pop()),
        _ => Err(verr(
            "system_ordering_recovery_evidence_mismatch",
            "state-transition commitment history has forked heads",
        )),
    }
}

fn validate_head(plan: &RecoveryPlan, current: Option<&Value>) -> Result<(), VErr> {
    let predecessor_sequence = plan
        .proposed
        .pointer("/predecessor/sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            verr(
                "system_ordering_recovery_request_invalid",
                "predecessor sequence is absent",
            )
        })?;
    match current {
        None => {
            if predecessor_sequence != plan.bootstrap_head.sequence
                || plan.expected_transition_commitment_ref
                    != plan.bootstrap_head.transition_commitment_ref
                || plan
                    .proposed
                    .pointer("/predecessor/state_root")
                    .and_then(Value::as_str)
                    != Some(plan.bootstrap_head.state_root.as_str())
            {
                return Err(verr(
                    "system_ordering_recovery_commitment_conflict",
                    "first transition commitment is detached from the live System chain head",
                ));
            }
        }
        Some(current) => {
            if current
                .get("resulting_transition_commitment_ref")
                .and_then(Value::as_str)
                != Some(plan.expected_transition_commitment_ref.as_str())
                || current.get("sequence").and_then(Value::as_u64) != Some(predecessor_sequence)
                || current.get("resulting_state_root")
                    != plan.proposed.pointer("/predecessor/state_root")
            {
                return Err(verr(
                    "system_ordering_recovery_commitment_conflict",
                    "recovery predecessor is stale or detached from the current commitment head",
                ));
            }
        }
    }
    Ok(())
}

fn vote_receipt(plan: &RecoveryPlan, timestamp: &str) -> Result<Value, VErr> {
    let vote_hash = jcs_hash(&json!({
        "domain":"ioi.ordering-finality-recovery-vote-jcs-sha256.v1",
        "candidate_hash":plan.candidate_hash,
        "principal_ref":plan.principal_ref,
        "principal_proof_ref":plan.principal_proof_ref,
    }))?;
    let digest = vote_hash.trim_start_matches("sha256:");
    let receipt = json!({
        "receipt_id":format!("receipt://ordering-recovery-vote/sha256:{digest}"),
        "receipt_type":"ordering_finality_recovery.vote",
        "receipt_profile_ref":RECEIPT_CONTRACT,
        "attested_boundary_fact_refs":[plan.proposed["ordering_recovery_id"],plan.principal_proof_ref],
        "claim_scope_ref":plan.profile["admission"]["authority_rule_ref"],
        "run_id":Value::Null,
        "task_id":Value::Null,
        "actor_id":plan.principal_ref,
        "input_hash":plan.candidate_hash,
        "output_hash":vote_hash,
        "policy_hash":plan.profile_hash,
        "authority_grant_id":format!("grant://ordering-recovery-vote/sha256:{digest}"),
        "primitive_capabilities":[],
        "authority_scopes":[RECOVERY_SCOPE],
        "artifact_refs":[],
        "evidence_bundle_refs":[plan.principal_proof_ref],
        "verification_ref":Value::Null,
        "acceptance_ref":Value::Null,
        "adjudication_ref":plan.proposed["governing_decision_ref"],
        "settlement_ref":Value::Null,
        "timestamp":timestamp,
        "signature":Value::Null,
        "public_commitment_ref":format!("commitment://ordering-recovery-candidate/{digest}")
    });
    validate_contract(RECEIPT_CONTRACT, &receipt, "ordering recovery vote")?;
    Ok(receipt)
}

fn vote_record_root(vote: &Value) -> Result<String, VErr> {
    jcs_hash(&json!({
        "domain":"ioi.ordering-recovery-vote-record-jcs-sha256.v1",
        "record":vote,
    }))
}

fn receipt_record_root(receipt: &Value) -> Result<String, VErr> {
    jcs_hash(&json!({
        "domain":"ioi.ordering-recovery-receipt-record-jcs-sha256.v1",
        "record":receipt,
    }))
}

fn recovery_record_root(recovery: &Value) -> Result<String, VErr> {
    jcs_hash(&json!({
        "domain":"ioi.ordering-finality-recovery-record-jcs-sha256.v1",
        "recovery":recovery,
    }))
}

fn validate_existing_vote(plan: &RecoveryPlan, vote: &Value) -> Result<(), VErr> {
    let actor = required(vote, "/actor_id")?;
    if !plan.eligible_principals.contains(&actor) {
        return Err(verr(
            "system_ordering_recovery_evidence_mismatch",
            "stored recovery vote actor is outside the active profile",
        ));
    }
    let proof = strings(vote, "/evidence_bundle_refs")?
        .into_iter()
        .next()
        .ok_or_else(|| {
            verr(
                "system_ordering_recovery_evidence_mismatch",
                "stored recovery vote lacks its principal proof",
            )
        })?;
    let class = required(&plan.proposed, "/recovery_class")?;
    let proof_is_bound = if class == "external_finality_rebind" {
        nullable(&plan.proposed, "/transition/external_finality_recovery_ref")?.as_deref()
            == Some(proof.as_str())
    } else {
        strings(
            &plan.proposed,
            "/transition/threshold_or_consensus_proof_refs",
        )?
        .iter()
        .any(|candidate| candidate == &proof)
    };
    if !proof_is_bound {
        return Err(verr(
            "system_ordering_recovery_evidence_mismatch",
            "stored recovery vote proof is outside the immutable candidate",
        ));
    }
    let timestamp = required(vote, "/timestamp")?;
    let mut expected_plan = plan.clone();
    expected_plan.principal_ref = actor;
    expected_plan.principal_proof_ref = proof;
    if vote_receipt(&expected_plan, &timestamp)? != *vote {
        return Err(verr(
            "system_ordering_recovery_evidence_mismatch",
            "stored recovery vote does not recompute from the active candidate and profile",
        ));
    }
    Ok(())
}

fn proposed_form(committed: &Value) -> Value {
    let mut proposed = committed.clone();
    proposed["status"] = json!("proposed");
    proposed["authority_grant_refs"] = json!([]);
    proposed["result"] = Value::Null;
    proposed
}

fn aggregate_receipt(plan: &RecoveryPlan, votes: &[Value]) -> Result<Value, VErr> {
    let vote_refs: Vec<Value> = votes
        .iter()
        .map(|value| value["receipt_id"].clone())
        .collect();
    let grant_refs: Vec<Value> = votes
        .iter()
        .map(|value| value["authority_grant_id"].clone())
        .collect();
    let timestamp = votes
        .iter()
        .filter_map(|value| value.get("timestamp").and_then(Value::as_str))
        .max()
        .ok_or_else(|| {
            verr(
                "system_ordering_recovery_evidence_mismatch",
                "vote set has no timestamp",
            )
        })?;
    let root = jcs_hash(&json!({
        "domain":"ioi.ordering-finality-recovery-vote-set-jcs-sha256.v1",
        "candidate_hash":plan.candidate_hash,
        "vote_receipt_refs":vote_refs,
        "authority_grant_refs":grant_refs,
    }))?;
    let digest = root.trim_start_matches("sha256:");
    let evidence_refs: Vec<Value> = votes
        .iter()
        .map(|value| value["evidence_bundle_refs"][0].clone())
        .collect();
    let receipt = json!({
        "receipt_id":format!("receipt://ordering-finality-recovery/sha256:{digest}"),
        "receipt_type":"ordering_finality_recovery.admitted",
        "receipt_profile_ref":RECEIPT_CONTRACT,
        "attested_boundary_fact_refs":vote_refs,
        "claim_scope_ref":plan.profile["admission"]["authority_rule_ref"],
        "run_id":Value::Null,
        "task_id":Value::Null,
        "actor_id":plan.system_id,
        "input_hash":plan.candidate_hash,
        "output_hash":root,
        "policy_hash":plan.profile_hash,
        "authority_grant_id":Value::Null,
        "primitive_capabilities":[],
        "authority_scopes":[RECOVERY_SCOPE],
        "artifact_refs":[],
        "evidence_bundle_refs":evidence_refs,
        "verification_ref":Value::Null,
        "acceptance_ref":Value::Null,
        "adjudication_ref":plan.proposed["governing_decision_ref"],
        "settlement_ref":plan.external_settlement_ref,
        "timestamp":timestamp,
        "signature":Value::Null,
        "public_commitment_ref":format!("commitment://ordering-recovery-candidate/{digest}")
    });
    validate_contract(RECEIPT_CONTRACT, &receipt, "ordering recovery receipt")?;
    Ok(receipt)
}

fn build_commitment(plan: &RecoveryPlan, receipt: &Value) -> Result<Value, VErr> {
    let sequence = plan
        .proposed
        .pointer("/predecessor/sequence")
        .and_then(Value::as_u64)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            verr(
                "system_ordering_recovery_request_invalid",
                "sequence cannot advance",
            )
        })?;
    let receipt_root = jcs_hash(receipt)?;
    let operation_ref = format!(
        "agentgres://operation/ordering-recovery-{}",
        plan.candidate_hash.trim_start_matches("sha256:")
    );
    let material = json!({
        "domain":"ioi.state-transition-commitment-jcs-sha256.v1",
        "system_id":plan.system_id,
        "hypervisor_node_id":plan.hypervisor_node_id,
        "acting_node_membership_ref":plan.acting_node_membership_ref,
        "ordering_admission_finality_profile_ref":plan.profile["ordering_profile_id"],
        "authority_mode":"ordering_or_finality_proof",
        "writer_epoch":Value::Null,
        "ordering_or_finality_proof_ref":plan.finality_proof_ref,
        "sequence":sequence,
        "expected_predecessor_commitment_ref":plan.expected_transition_commitment_ref,
        "operation_or_batch_commitment":plan.operation_or_batch_commitment,
        "admission_proof_ref":receipt["receipt_id"],
        "transition_kind":"ordering_finality_recovery",
        "operation_ref":operation_ref,
        "predecessor_state_root":plan.proposed["predecessor"]["state_root"],
        "resulting_state_root":plan.resulting_state_root,
        "receipt_root":receipt_root,
        "ordering_recovery_ref":plan.proposed["ordering_recovery_id"],
        "external_settlement_ref":plan.external_settlement_ref,
    });
    let commitment_hash = jcs_hash(&material)?;
    let digest = commitment_hash.trim_start_matches("sha256:");
    let mut commitment = material.as_object().cloned().expect("material object");
    commitment.remove("domain");
    commitment.insert(
        "schema_version".into(),
        json!("ioi.state-transition-commitment.v1"),
    );
    commitment.insert(
        "state_transition_commitment_id".into(),
        json!(format!("transition://state-transition/sha256:{digest}")),
    );
    commitment.insert(
        "resulting_transition_commitment_ref".into(),
        json!(format!("commitment://state-transition/sha256:{digest}")),
    );
    commitment.insert("status".into(), json!("committed"));
    let commitment = Value::Object(commitment);
    validate_contract(
        COMMITMENT_CONTRACT,
        &commitment,
        "state transition commitment",
    )?;
    Ok(commitment)
}

fn committed_recovery(
    plan: &RecoveryPlan,
    votes: &[Value],
    receipt: &Value,
    commitment: &Value,
) -> Result<Value, VErr> {
    let mut recovery = plan.proposed.clone();
    recovery["authority_grant_refs"] = Value::Array(
        votes
            .iter()
            .map(|value| value["authority_grant_id"].clone())
            .collect(),
    );
    recovery["result"] = json!({
        "sequence":commitment["sequence"],
        "transition_commitment_ref":commitment["resulting_transition_commitment_ref"],
        "state_root":commitment["resulting_state_root"],
        "finality_proof_ref":plan.finality_proof_ref,
        "receipt_ref":receipt["receipt_id"],
    });
    recovery["status"] = json!("committed");
    validate_contract(RECOVERY_CONTRACT, &recovery, "committed ordering recovery")?;
    Ok(recovery)
}

fn persist_committed(
    data_dir: &str,
    receipt: &Value,
    recovery: &Value,
    commitment: &Value,
) -> Result<(), VErr> {
    persist_exact(
        data_dir,
        RECOVERY_RECEIPT_DIR,
        &tail("asorr_", &receipt_record_root(receipt)?)?,
        receipt,
    )?;
    persist_exact(
        data_dir,
        RECOVERY_DIR,
        &tail("asor_", &recovery_record_root(recovery)?)?,
        recovery,
    )?;
    let commitment_ref = required(commitment, "/resulting_transition_commitment_ref")?;
    let commitment_hash = format!(
        "sha256:{}",
        commitment_ref
            .strip_prefix("commitment://state-transition/sha256:")
            .ok_or_else(|| {
                verr(
                    "system_ordering_recovery_evidence_mismatch",
                    "commitment identity is malformed",
                )
            })?
    );
    persist_exact(
        data_dir,
        COMMITMENT_DIR,
        &tail("astc_", &commitment_hash)?,
        commitment,
    )
}

fn candidate_votes(plan: &RecoveryPlan, votes: Vec<Value>) -> Result<Vec<Value>, VErr> {
    let mut matching = Vec::new();
    for vote in votes {
        if vote.get("input_hash").and_then(Value::as_str) == Some(plan.candidate_hash.as_str()) {
            validate_existing_vote(plan, &vote)?;
            matching.push(vote);
        }
    }
    matching.sort_by_key(|value| {
        value
            .get("actor_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    });
    matching.dedup_by(|left, right| left.get("actor_id") == right.get("actor_id"));
    Ok(matching)
}

fn commit_submission(
    data_dir: &str,
    plan: &RecoveryPlan,
) -> Result<(Value, Option<Value>, Option<Value>, bool), VErr> {
    let recovery_id = required(&plan.proposed, "/ordering_recovery_id")?;
    let existing_votes = exact_records(data_dir, RECOVERY_VOTE_DIR, RECEIPT_CONTRACT)?;
    for vote in &existing_votes {
        if vote
            .get("attested_boundary_fact_refs")
            .and_then(Value::as_array)
            .is_some_and(|refs| {
                refs.iter()
                    .any(|value| value.as_str() == Some(recovery_id.as_str()))
            })
            && vote.get("input_hash").and_then(Value::as_str) != Some(plan.candidate_hash.as_str())
        {
            return Err(verr(
                "system_ordering_recovery_identity_conflict",
                "ordering recovery identity is already bound to another candidate",
            ));
        }
    }
    let mut votes = candidate_votes(plan, existing_votes.clone())?;
    let existing_recoveries = exact_records(data_dir, RECOVERY_DIR, RECOVERY_CONTRACT)?;
    if let Some(existing) = existing_recoveries.iter().find(|value| {
        value.get("ordering_recovery_id").and_then(Value::as_str) == Some(recovery_id.as_str())
    }) {
        if proposed_form(existing) != plan.proposed {
            return Err(verr(
                "system_ordering_recovery_identity_conflict",
                "ordering recovery identity is already committed to another candidate",
            ));
        }
        if votes.len() < plan.required_votes {
            return Err(verr(
                "system_ordering_recovery_evidence_mismatch",
                "committed recovery lacks its exact threshold vote set",
            ));
        }
        votes.truncate(plan.required_votes);
        let receipt = aggregate_receipt(plan, &votes)?;
        let commitment = build_commitment(plan, &receipt)?;
        let expected = committed_recovery(plan, &votes, &receipt, &commitment)?;
        if expected != *existing {
            return Err(verr(
                "system_ordering_recovery_evidence_mismatch",
                "committed recovery does not recompute from its threshold vote set",
            ));
        }
        persist_committed(data_dir, &receipt, existing, &commitment)?;
        return Ok((
            Value::Null,
            Some(existing.clone()),
            Some(json!({"receipt":receipt,"commitment":commitment})),
            true,
        ));
    }
    let current = current_commitment(data_dir, &plan.system_id)?;
    validate_head(plan, current.as_ref())?;
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| {
            verr(
                "system_ordering_recovery_admission_failed",
                error.to_string(),
            )
        })?;
    let proposed_vote = vote_receipt(plan, &timestamp)?;
    let existing_vote = existing_votes.iter().find(|value| {
        value.get("input_hash").and_then(Value::as_str) == Some(plan.candidate_hash.as_str())
            && value.get("actor_id").and_then(Value::as_str) == Some(plan.principal_ref.as_str())
    });
    let vote = match existing_vote {
        Some(existing) => {
            if existing.get("evidence_bundle_refs") != proposed_vote.get("evidence_bundle_refs") {
                return Err(verr(
                    "system_ordering_recovery_vote_conflict",
                    "principal already voted with different proof evidence",
                ));
            }
            existing.clone()
        }
        None => {
            let root = vote_record_root(&proposed_vote)?;
            persist_exact(
                data_dir,
                RECOVERY_VOTE_DIR,
                &tail("asorv_", &root)?,
                &proposed_vote,
            )?;
            proposed_vote
        }
    };
    if !votes.iter().any(|value| value == &vote) {
        votes.push(vote.clone());
    }
    votes.sort_by_key(|value| {
        value
            .get("actor_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    });
    votes.dedup_by(|left, right| left.get("actor_id") == right.get("actor_id"));
    if votes.len() < plan.required_votes {
        return Ok((vote, None, None, false));
    }
    votes.truncate(plan.required_votes);
    let receipt = aggregate_receipt(plan, &votes)?;
    let commitment = build_commitment(plan, &receipt)?;
    let recovery = committed_recovery(plan, &votes, &receipt, &commitment)?;
    persist_committed(data_dir, &receipt, &recovery, &commitment)?;
    Ok((
        vote,
        Some(recovery),
        Some(json!({"receipt":receipt,"commitment":commitment})),
        false,
    ))
}

/// POST /v1/hypervisor/autonomous-systems/:id/ordering/recoveries
pub(crate) async fn handle_recovery(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !canonical_system_key(&key) {
        return classify(verr(
            "system_ordering_recovery_source_key_invalid",
            "id must be 'asg_' plus 64 lowercase hexadecimal characters",
        ));
    }
    let identity = match super::substrate_store::resolve_request_identity(&state.data_dir, &headers)
    {
        Ok(identity) => identity,
        Err(refusal) => {
            let status = match refusal {
                super::substrate_store::RequestScopeRefusal::AuthenticationRequired => {
                    StatusCode::UNAUTHORIZED
                }
                super::substrate_store::RequestScopeRefusal::SubstrateUnavailable(_) => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                _ => StatusCode::FORBIDDEN,
            };
            return (
                status,
                Json(
                    json!({"error":{"code":refusal.code(),"message":refusal.message(),"runtimeTruthSource":"daemon-runtime"}}),
                ),
            );
        }
    };
    let _guard = ORDERING_RECOVERY_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let policies =
        match super::system_policy_routes::load_active_system_policies(&state.data_dir, &key) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    let membership =
        match super::system_membership_routes::load_membership_source(&state.data_dir, &key) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    let continuity =
        match super::system_continuity_routes::load_continuity_source(&state.data_dir, &key) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    let bootstrap = match bootstrap_head(&continuity.base.chain_head) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let plan = match evaluate_submission(
        &policies,
        &membership,
        &bootstrap,
        &identity.principal_ref,
        &body,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    match commit_submission(&state.data_dir, &plan) {
        Ok((vote, Some(recovery), Some(output), replayed)) => (
            if replayed {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            Json(json!({
                "ok":true,
                "state":"committed",
                "replayed":replayed,
                "vote_receipt":vote,
                "ordering_finality_recovery":recovery,
                "recovery_receipt":output["receipt"],
                "state_transition_commitment":output["commitment"],
                "runtimeTruthSource":"daemon-runtime"
            })),
        ),
        Ok((vote, None, None, false)) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "ok":true,
                "state":"evidence_pending",
                "replayed":false,
                "vote_receipt":vote,
                "votes_required":plan.required_votes,
                "runtimeTruthSource":"daemon-runtime"
            })),
        ),
        Ok(_) => classify(verr(
            "system_ordering_recovery_evidence_mismatch",
            "impossible recovery result shape",
        )),
        Err(error) => classify(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::system_membership_transitions::{
        MembershipIdentityBinding, MembershipLogHead,
    };

    fn fixture(path: &str) -> Value {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        serde_json::from_slice(&std::fs::read(root.join(path)).unwrap()).unwrap()
    }

    fn profile(kind: &str, required_votes: u64) -> Value {
        let mut value = fixture(
            "docs/architecture/_meta/schemas/fixtures/ordering-admission-finality-profile-v1/positive-single-authority.json",
        );
        value["ordering_profile_id"] = json!("ordering-profile://acme/system-beta/bft-v1");
        value["system_id"] = json!("system://acme/system-beta");
        value["profile"] = json!(kind);
        value["authority_distribution"] = json!({
            "posture":"declared_multi_principal",
            "principal_refs":["user://one","user://two","user://three"],
            "independence_evidence_refs":["evidence://acme/independence"]
        });
        value["ordering"]["writer_epoch_required"] = json!(false);
        value["ordering"]["fencing_required"] = json!(false);
        value["ordering"]["member_node_membership_refs"] =
            json!(["node-membership://acme/system-beta/bft-1"]);
        value["admission"]["threshold"] = json!({"required":required_votes,"eligible":3});
        value
    }

    fn membership() -> super::super::system_membership_routes::MembershipSource {
        let record = json!({
            "node_membership_id":"node-membership://acme/system-beta/bft-1",
            "node_id":"node://acme/bft-1",
            "status":"active"
        });
        let root = format!("sha256:{}", "43".repeat(32));
        super::super::system_membership_routes::MembershipSource {
            binding: MembershipIdentityBinding {
                system_id: "system://acme/system-beta".into(),
                genesis_ref: "genesis://acme/system-beta".into(),
                source_governing_authority_ref: "org://acme/research".into(),
                deployment_profile_ref: "deployment-profile://acme/system-beta/revision/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                deployment_profile_root: format!("sha256:{}", "a".repeat(64)),
                admitted_constitution_root: format!("sha256:{}", "b".repeat(64)),
                admitted_manifest_root: format!("sha256:{}", "c".repeat(64)),
            },
            desired_topology: Some(json!({
                "failover_profile_ref":"failover-profile://acme/system-beta/bft"
            })),
            desired_topology_root: Some(format!("sha256:{}", "d".repeat(64))),
            transitions: vec![],
            records: vec![record],
            head: MembershipLogHead { sequence: 1, membership_root: root },
            consumed_role_lease_refs: vec![],
        }
    }

    fn bootstrap() -> BootstrapHead {
        BootstrapHead {
            sequence: 42,
            transition_commitment_ref: "commitment://acme/system-beta/transition/42".into(),
            state_root: format!("sha256:{}", "42".repeat(32)),
        }
    }

    fn policies(profile: Value) -> super::super::system_policy_routes::ActiveSystemPolicies {
        super::super::system_policy_routes::ActiveSystemPolicies {
            system_id: "system://acme/system-beta".into(),
            constitution: json!({}),
            ordering_profile: profile,
            oracle_profiles: vec![],
            lifecycle_profile: json!({}),
            active_profile_set: json!({}),
        }
    }

    fn body(membership_root: &str, proof: &str) -> Value {
        let mut recovery = fixture(
            "docs/architecture/_meta/schemas/fixtures/ordering-finality-recovery-v1/positive-committed-bft.json",
        );
        recovery["status"] = json!("proposed");
        recovery["authority_grant_refs"] = json!([]);
        recovery["result"] = Value::Null;
        recovery["transition"]["expected_membership_root"] = json!(membership_root);
        recovery["transition"]["resulting_membership_root"] = json!(membership_root);
        recovery["transition"]["threshold_or_consensus_proof_refs"] =
            json!(["evidence://acme/vote/one", "evidence://acme/vote/two"]);
        json!({
            "recovery":recovery,
            "principal_proof_ref":proof,
            "hypervisor_node_id":"node://acme/bft-1",
            "acting_node_membership_ref":"node-membership://acme/system-beta/bft-1",
            "operation_or_batch_commitment":format!("sha256:{}", "4".repeat(64)),
            "resulting_state_root":format!("sha256:{}", "5".repeat(64)),
            "finality_proof_ref":"evidence://acme/finality/43",
            "external_settlement_ref":null,
            "expected_transition_commitment_ref":"commitment://acme/system-beta/transition/42"
        })
    }

    fn plan(principal: &str, proof: &str) -> RecoveryPlan {
        let membership = membership();
        evaluate_submission(
            &policies(profile("bft_consensus", 2)),
            &membership,
            &bootstrap(),
            principal,
            &body(&membership.head.membership_root, proof),
        )
        .unwrap()
    }

    #[test]
    fn single_writer_profiles_cannot_borrow_profile_native_recovery() {
        let membership = membership();
        let body = body(&membership.head.membership_root, "evidence://acme/vote/one");
        assert_eq!(
            evaluate_submission(
                &policies(profile("single_authority", 1)),
                &membership,
                &bootstrap(),
                "user://one",
                &body,
            )
            .unwrap_err()
            .0,
            "system_ordering_recovery_profile_refused"
        );
    }

    #[test]
    fn profile_threshold_and_authenticated_principal_are_exact() {
        let membership = membership();
        let body = body(&membership.head.membership_root, "evidence://acme/vote/one");
        let plan = evaluate_submission(
            &policies(profile("bft_consensus", 2)),
            &membership,
            &bootstrap(),
            "user://one",
            &body,
        )
        .unwrap();
        assert_eq!(plan.required_votes, 2);
        assert_eq!(
            evaluate_submission(
                &policies(profile("bft_consensus", 2)),
                &membership,
                &bootstrap(),
                "user://attacker",
                &body,
            )
            .unwrap_err()
            .0,
            "system_ordering_recovery_authority_required"
        );
    }

    #[test]
    fn commitment_is_profile_native_non_economic_and_exactly_bound() {
        let membership = membership();
        let body = body(&membership.head.membership_root, "evidence://acme/vote/one");
        let plan = evaluate_submission(
            &policies(profile("bft_consensus", 2)),
            &membership,
            &bootstrap(),
            "user://one",
            &body,
        )
        .unwrap();
        let vote_one = vote_receipt(&plan, "2026-08-25T00:00:00Z").unwrap();
        let mut second = plan.clone();
        second.principal_ref = "user://two".into();
        second.principal_proof_ref = "evidence://acme/vote/two".into();
        let vote_two = vote_receipt(&second, "2026-08-25T00:00:01Z").unwrap();
        let receipt = aggregate_receipt(&plan, &[vote_one, vote_two]).unwrap();
        let commitment = build_commitment(&plan, &receipt).unwrap();
        assert_eq!(commitment["authority_mode"], "ordering_or_finality_proof");
        assert!(commitment["writer_epoch"].is_null());
        assert!(commitment["external_settlement_ref"].is_null());
        let mut substituted = commitment.clone();
        substituted["resulting_state_root"] = json!(format!("sha256:{}", "6".repeat(64)));
        assert!(validate_contract(COMMITMENT_CONTRACT, &substituted, "substituted").is_err());
    }

    #[test]
    fn durable_threshold_replays_restarts_and_heals_partial_commit() {
        super::super::substrate_store::reset_handle_for_test();
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        let first = plan("user://one", "evidence://acme/vote/one");
        let second = plan("user://two", "evidence://acme/vote/two");

        let pending = commit_submission(data_dir, &first).unwrap();
        assert!(pending.1.is_none());
        let committed = commit_submission(data_dir, &second).unwrap();
        assert!(committed.1.is_some());
        assert!(!committed.3);
        assert_eq!(
            enumerate_family(data_dir, RECOVERY_VOTE_DIR).unwrap().len(),
            2
        );
        assert_eq!(enumerate_family(data_dir, RECOVERY_DIR).unwrap().len(), 1);
        assert_eq!(enumerate_family(data_dir, COMMITMENT_DIR).unwrap().len(), 1);

        let replay = commit_submission(data_dir, &second).unwrap();
        assert!(replay.3);
        assert_eq!(replay.1, committed.1);
        assert_eq!(replay.2, committed.2);
        super::super::substrate_store::reset_handle_for_test();
        assert_eq!(
            current_commitment(data_dir, "system://acme/system-beta")
                .unwrap()
                .unwrap(),
            committed.2.as_ref().unwrap()["commitment"]
        );
        super::super::substrate_store::reset_handle_for_test();

        let partial_directory = tempfile::tempdir().unwrap();
        let partial_data_dir = partial_directory.path().to_str().unwrap();
        let vote_one = vote_receipt(&first, "2026-08-25T00:00:00Z").unwrap();
        let vote_two = vote_receipt(&second, "2026-08-25T00:00:01Z").unwrap();
        for vote in [&vote_one, &vote_two] {
            persist_exact(
                partial_data_dir,
                RECOVERY_VOTE_DIR,
                &tail("asorv_", &vote_record_root(vote).unwrap()).unwrap(),
                vote,
            )
            .unwrap();
        }
        let receipt = aggregate_receipt(&first, &[vote_one, vote_two]).unwrap();
        let commitment = build_commitment(&first, &receipt).unwrap();
        let recovery = committed_recovery(
            &first,
            &candidate_votes(
                &first,
                exact_records(partial_data_dir, RECOVERY_VOTE_DIR, RECEIPT_CONTRACT).unwrap(),
            )
            .unwrap(),
            &receipt,
            &commitment,
        )
        .unwrap();
        persist_exact(
            partial_data_dir,
            RECOVERY_RECEIPT_DIR,
            &tail("asorr_", &receipt_record_root(&receipt).unwrap()).unwrap(),
            &receipt,
        )
        .unwrap();
        persist_exact(
            partial_data_dir,
            RECOVERY_DIR,
            &tail("asor_", &recovery_record_root(&recovery).unwrap()).unwrap(),
            &recovery,
        )
        .unwrap();
        assert!(enumerate_family(partial_data_dir, COMMITMENT_DIR)
            .unwrap()
            .is_empty());
        let healed = commit_submission(partial_data_dir, &first).unwrap();
        assert!(healed.3);
        assert_eq!(healed.2.unwrap()["commitment"], commitment);
        assert_eq!(
            enumerate_family(partial_data_dir, COMMITMENT_DIR)
                .unwrap()
                .len(),
            1
        );
        super::super::substrate_store::reset_handle_for_test();
    }

    #[test]
    fn required_agentgres_keys_bind_exact_recovery_and_commitment_bytes() {
        let first = plan("user://one", "evidence://acme/vote/one");
        let second = plan("user://two", "evidence://acme/vote/two");
        let vote_one = vote_receipt(&first, "2026-08-25T00:00:00Z").unwrap();
        let vote_two = vote_receipt(&second, "2026-08-25T00:00:01Z").unwrap();
        let votes = vec![vote_one.clone(), vote_two];
        let receipt = aggregate_receipt(&first, &votes).unwrap();
        let commitment = build_commitment(&first, &receipt).unwrap();
        let recovery = committed_recovery(&first, &votes, &receipt, &commitment).unwrap();
        for (family, record_tail, record) in [
            (
                RECOVERY_VOTE_DIR,
                tail("asorv_", &vote_record_root(&vote_one).unwrap()).unwrap(),
                vote_one,
            ),
            (
                RECOVERY_RECEIPT_DIR,
                tail("asorr_", &receipt_record_root(&receipt).unwrap()).unwrap(),
                receipt,
            ),
            (
                RECOVERY_DIR,
                tail("asor_", &recovery_record_root(&recovery).unwrap()).unwrap(),
                recovery,
            ),
        ] {
            super::super::substrate_store::validate_required_identity_for_test(
                family,
                &record_tail,
                &record,
            )
            .unwrap();
            let mut substituted = record;
            substituted["status"] = json!("substituted");
            assert!(
                super::super::substrate_store::validate_required_identity_for_test(
                    family,
                    &record_tail,
                    &substituted,
                )
                .is_err()
            );
        }
        let commitment_ref = required(&commitment, "/resulting_transition_commitment_ref").unwrap();
        let commitment_tail = format!(
            "astc_{}",
            commitment_ref
                .strip_prefix("commitment://state-transition/sha256:")
                .unwrap()
        );
        super::super::substrate_store::validate_required_identity_for_test(
            COMMITMENT_DIR,
            &commitment_tail,
            &commitment,
        )
        .unwrap();
        let mut substituted = commitment;
        substituted["resulting_state_root"] = json!(format!("sha256:{}", "9".repeat(64)));
        assert!(
            super::super::substrate_store::validate_required_identity_for_test(
                COMMITMENT_DIR,
                &commitment_tail,
                &substituted,
            )
            .is_err()
        );
    }
}
