//! M4 bounded-System OutcomeRoom admission.
//!
//! This is the current-contract path. The older `outcome_room_routes` module retains
//! predecessor storage/recovery helpers only; canonical v1 reads and writes are retired. A v2
//! room is admitted only after the daemon reconstructs an active sequence-two System
//! from its owner planes. Every room or room-child commit crosses a declared
//! Agentgres required-admission domain before the local aggregate projection
//! becomes visible.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, DaemonState};

const ROOM_SCHEMA: &str = "ioi.foundations.outcome-room.v2";
const ROOM_CONTRACT: &str = "schema://ioi/foundations/outcome-room/v2";
const BASE_SCHEMA: &str = "ioi.foundations.room-admitted-object-base.v2";
const OUTCOME_PACKAGE: &str = "package://ioi/outcome-room";

const ROOM_DIR: &str = super::outcome_room_routes::ROOM_DIR;
const INTENT_DIR: &str = "outcome-room-system-admission-intents";
const CHILD_INTENT_DIR: &str = "outcome-room-child-admission-intents";
const MEMBERSHIP_INTENT_DIR: &str = "outcome-room-membership-admission-intents";
const RECEIPT_DIR: &str = "outcome-room-system-receipts";
const OBJECT_DIR: &str = "outcome-room-admitted-object-projections";

const ADMISSION_OPERATION_DOMAIN: &str = "outcome-room-admission-operations";
const TRANSITION_OPERATION_DOMAIN: &str = "outcome-room-transition-operations";
const RECEIPT_DOMAIN: &str = "outcome-room-admission-receipts";
const OBJECT_DOMAIN: &str = "outcome-room-admitted-objects";

const GRAPH_SCHEMA: &str = "ioi.foundations.collaborative-work-graph.v1";
const GRAPH_CONTRACT: &str = "schema://ioi/foundations/collaborative-work-graph/v1";
const DISCUSSION_SCHEMA: &str = "ioi.foundations.outcome-room-discussion-projection.v1";
const DISCUSSION_CONTRACT: &str = "schema://ioi/foundations/outcome-room-discussion-projection/v1";

pub(crate) const M4_ROOM_REF_SET_MAX: usize = 64;
pub(crate) const M4_HOSTED_ROOM_MAX: usize = 50;
pub(crate) const M4_SERIALIZED_BODY_MAX: usize = 1024 * 1024;
const M4_REPLAY_ENTRY_MAX: usize = 128;
const M4_TRANSITION_ENTRY_MAX: usize = 127;
const M4_DISCUSSION_SUBJECT_MAX: usize = 67;
const M4_REQUIRED_DOMAIN_MAX: usize = M4_HOSTED_ROOM_MAX * M4_REPLAY_ENTRY_MAX;

pub(crate) type VErr = (String, String);

fn verr(code: &str, message: impl Into<String>) -> VErr {
    (code.to_owned(), message.into())
}

pub(crate) fn classify((code, message): VErr) -> (StatusCode, Json<Value>) {
    let status = if code == "outcome_room_v1_read_retired" {
        StatusCode::GONE
    } else if code == "outcome_room_host_domain_owner_mismatch" {
        // This is a selected-profile contract-coordinate refusal, not an authenticated
        // principal/room-owner authorization failure. Keep the durable error vocabulary exact
        // without allowing the generic `owner_mismatch` branch to misclassify it as 403.
        StatusCode::UNPROCESSABLE_ENTITY
    } else if code.contains("authentication_required")
        || code.contains("authenticated_principal_required")
    {
        StatusCode::UNAUTHORIZED
    } else if code.contains("owner_mismatch") || code.contains("access_forbidden") {
        StatusCode::FORBIDDEN
    } else if code.ends_with("_not_found") {
        StatusCode::NOT_FOUND
    } else if code.contains("conflict") || code.contains("stale") {
        StatusCode::CONFLICT
    } else if code == "outcome_room_projection_response_too_large"
        || code == "outcome_room_projection_source_unavailable"
        || code.contains("pending")
        || code.contains("unreadable")
        || code.contains("unresolved")
        || code.contains("persist")
        || code.contains("unconfirmed")
        || code.contains("agentgres")
        || code.contains("recovery")
    {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (
        status,
        Json(json!({"error":{"code":code,"message":message}})),
    )
}

fn refuse_predecessor_projection(room: &Value) -> Option<(StatusCode, Json<Value>)> {
    match super::outcome_room_routes::outcome_room_generation(room) {
        Ok(super::outcome_room_routes::OutcomeRoomGeneration::CurrentV2) => None,
        Ok(super::outcome_room_routes::OutcomeRoomGeneration::PredecessorV1) => Some(classify(
            verr(
                "outcome_room_v1_read_retired",
                "the canonical OutcomeRoom projection routes read only bounded-System v2 rooms; predecessor v1 reads are retired",
            ),
        )),
        Err(error) => Some(classify(error)),
    }
}

pub(crate) fn ensure_serialized_body_bound(value: &Value, code: &str) -> Result<(), VErr> {
    let size = serde_json::to_vec(value)
        .map_err(|error| verr(code, format!("response cannot be serialized ({error})")))?
        .len();
    if size > M4_SERIALIZED_BODY_MAX {
        return Err(verr(
            code,
            format!(
                "serialized body is {size} bytes; hosted M4 permits at most {M4_SERIALIZED_BODY_MAX} bytes"
            ),
        ));
    }
    Ok(())
}

pub(crate) fn validate_current_room_contract(room: &Value) -> Result<(), VErr> {
    canonical_contract(ROOM_CONTRACT, room)?;
    ensure_serialized_body_bound(room, "outcome_room_record_too_large")
}

/// Resolve the caller posture at the v2 room boundary. A loopback, unenforced daemon retains its
/// explicit local-development operator lane; an exposed request never inherits that identity.
pub(crate) fn request_principal(data_dir: &str, headers: &HeaderMap) -> Result<String, VErr> {
    let posture = super::lifecycle_routes::deployment_auth_posture(data_dir, headers);
    if posture == "exposed_untrusted" {
        return Err(verr(
            "outcome_room_authenticated_principal_required",
            "an exposed OutcomeRoom endpoint requires enforced identity",
        ));
    }
    if let Some(principal) = super::lifecycle_routes::resolve_principal(data_dir, headers) {
        let id = principal
            .get("principal_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                verr(
                    "outcome_room_authentication_required",
                    "the authenticated session did not resolve a principal identity",
                )
            })?;
        return Ok(format!("user://{id}"));
    }
    if super::lifecycle_routes::auth_enforced(data_dir, headers) {
        return Err(verr(
            "outcome_room_authentication_required",
            "authentication is required before OutcomeRoom state may be accessed",
        ));
    }
    Ok("user://local-operator".to_owned())
}

fn authorize_declared_owner(
    data_dir: &str,
    headers: &HeaderMap,
    owner_ref: &str,
) -> Result<(), VErr> {
    let principal_ref = request_principal(data_dir, headers)?;
    if principal_ref != owner_ref {
        return Err(verr(
            "outcome_room_owner_mismatch",
            "the authenticated principal does not own the requested OutcomeRoom",
        ));
    }
    Ok(())
}

pub(crate) fn authorize_resolved_room_principal(
    principal_ref: &str,
    room: &Value,
) -> Result<(), VErr> {
    let owner = exact_string(
        room,
        "/owner_or_sponsor_ref",
        "outcome_room_owner_unresolved",
    )?;
    if principal_ref != owner {
        return Err(verr(
            "outcome_room_owner_mismatch",
            "the authenticated principal does not own the requested OutcomeRoom",
        ));
    }
    Ok(())
}

pub(crate) fn authorize_room_access(
    data_dir: &str,
    headers: &HeaderMap,
    room: &Value,
) -> Result<(), VErr> {
    let principal_ref = request_principal(data_dir, headers)?;
    authorize_resolved_room_principal(&principal_ref, room)
}

pub(crate) fn managed_missing_room_refusal(
    data_dir: &str,
    headers: &HeaderMap,
) -> Option<(StatusCode, Json<Value>)> {
    if super::lifecycle_routes::deployment_auth_posture(data_dir, headers) == "local_development" {
        return None;
    }
    Some(classify(verr(
        "outcome_room_owner_mismatch",
        "the authenticated principal does not own the requested OutcomeRoom",
    )))
}

pub(crate) fn room_source_refusal(
    data_dir: &str,
    headers: &HeaderMap,
    error: VErr,
) -> (StatusCode, Json<Value>) {
    if super::lifecycle_routes::deployment_auth_posture(data_dir, headers) != "local_development" {
        eprintln!(
            "managed OutcomeRoom source refusal: {} ({})",
            error.0, error.1
        );
        return classify(verr(
            "outcome_room_owner_projection_unresolved",
            "OutcomeRoom ownership truth cannot be resolved from the complete strict source census.",
        ));
    }
    classify(error)
}

pub(crate) fn authorize_generation_dispatch_if_managed(
    data_dir: &str,
    headers: &HeaderMap,
    principal_ref: &str,
    room: &Value,
) -> Result<(), VErr> {
    if super::lifecycle_routes::deployment_auth_posture(data_dir, headers) == "local_development" {
        return Ok(());
    }
    authorize_resolved_room_principal(principal_ref, room)
}

fn jcs_root(domain: &str, value: &Value) -> Result<String, VErr> {
    super::system_activation_routes::jcs_hash(&json!({
        "domain": domain,
        "value": value,
    }))
    .map_err(|(_, message)| verr("outcome_room_hash_failed", message))
}

fn create_request_root(body: &Value) -> Result<String, VErr> {
    jcs_root("ioi.outcome-room-create-request-jcs-sha256.v1", body)
}

fn rooted_record(
    family: &str,
    prefix: &str,
    root_field: &str,
    mut record: Value,
) -> Result<(String, Value), VErr> {
    let Some(object) = record.as_object_mut() else {
        return Err(verr(
            "outcome_room_record_invalid",
            "record is not an object",
        ));
    };
    object.insert(root_field.to_owned(), Value::Null);
    let root = super::system_activation_routes::jcs_hash(&json!({
        "domain":"ioi.outcome-room-required-admission-record-jcs-sha256.v1",
        "record_family":family,
        "record":record,
    }))
    .map_err(|(_, message)| verr("outcome_room_hash_failed", message))?;
    record[root_field] = json!(root);
    let key = format!(
        "{prefix}{}",
        root.strip_prefix("sha256:").unwrap_or_default()
    );
    Ok((key, record))
}

fn state_root(room: &Value) -> Result<String, VErr> {
    let mut material = room.clone();
    material["room_state_root"] = Value::Null;
    material["room_receipt_root"] = Value::Null;
    jcs_root("ioi.outcome-room-state-jcs-sha256.v2", &material)
}

fn canonical_contract(contract_id: &str, value: &Value) -> Result<(), VErr> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        contract_id,
        value,
    )
    .map_err(|message| {
        verr(
            "outcome_room_contract_invalid",
            format!("{contract_id} rejected the value ({message})"),
        )
    })
}

fn exact_string<'a>(value: &'a Value, pointer: &str, code: &str) -> Result<&'a str, VErr> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty() && text.len() <= 500)
        .ok_or_else(|| verr(code, format!("'{pointer}' is required")))
}

fn require_no_caller_system_claims(body: &Value) -> Result<(), VErr> {
    for field in [
        "genesis_ref",
        "package_id",
        "manifest_ref",
        "constitution_ref",
        "active_profile_refs",
        "autonomous_system_state_ref",
        "latest_sequence",
        "latest_transition_commitment_ref",
        "room_state_root",
        "room_receipt_root",
        "status",
    ] {
        if body.get(field).is_some_and(|value| !value.is_null()) {
            return Err(verr(
                "outcome_room_system_binding_plane_owned",
                format!("'{field}' is derived from verified bounded-System and admission truth"),
            ));
        }
    }
    Ok(())
}

/// Freeze the executable M4 admission profile without narrowing the durable v2 contract. Later
/// stages may add independently proven federated, open-participation, multi-party, discovery, or
/// settlement owners; this route must refuse those coordinates until those owners exist.
fn require_selected_m4_profile(room: &Value) -> Result<(), VErr> {
    if room.get("coordination_topology").and_then(Value::as_str) != Some("hosted_admission") {
        return Err(verr(
            "outcome_room_federated_admission_unavailable",
            "the selected M4 runtime profile admits hosted OutcomeRooms only; federated admission requires its later owner and proof",
        ));
    }
    if !matches!(
        room.get("room_mode").and_then(Value::as_str),
        Some("private_goal" | "permissioned_team")
    ) {
        return Err(verr(
            "outcome_room_external_participation_unavailable",
            "the selected M4 runtime profile admits private or permissioned hosted rooms only; cross-organization and open-challenge participation require their later owner and proof",
        ));
    }
    if !room
        .get("discovery_and_external_admission_policy_refs")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return Err(verr(
            "outcome_room_external_discovery_unavailable",
            "the selected M4 runtime profile admits no external-discovery or AIIP admission policy",
        ));
    }
    if !room
        .get("multi_party_collaboration_ref")
        .is_some_and(Value::is_null)
    {
        return Err(verr(
            "outcome_room_multi_party_collaboration_unavailable",
            "the selected M4 runtime profile admits no multi-party collaboration binding",
        ));
    }
    if !room
        .get("settlement_policy_ref")
        .is_some_and(Value::is_null)
    {
        return Err(verr(
            "outcome_room_settlement_unavailable",
            "the selected M4 runtime profile admits no settlement policy",
        ));
    }
    Ok(())
}

/// The selected hosted proof has no independent domain-owner registry. Bind its admission owner
/// to the exact active bounded System instead of accepting an unresolved caller-named domain.
fn require_selected_m4_host(room: &Value, system_chain: &Value) -> Result<(), VErr> {
    let system_id = exact_string(
        system_chain,
        "/system_id",
        "outcome_room_system_binding_invalid",
    )?;
    if room.get("host_domain_ref").and_then(Value::as_str) != Some(system_id) {
        return Err(verr(
            "outcome_room_host_domain_owner_mismatch",
            "the selected M4 hosted profile requires host_domain_ref to name the exact resolved active System; general domain-owner resolution is not implemented",
        ));
    }
    Ok(())
}

fn active_system_binding(data_dir: &str, system_id: &str) -> Result<Value, VErr> {
    let graph = super::system_activation_routes::load_active_system_graph(data_dir, system_id)
        .map_err(|(code, message)| {
            verr(
                "outcome_room_active_system_required",
                format!("{code}: {message}"),
            )
        })?;
    let chain = graph.get("autonomous_system_chain").ok_or_else(|| {
        verr(
            "outcome_room_system_binding_invalid",
            "active System lacks its chain",
        )
    })?;
    if chain.get("package_id").and_then(Value::as_str) != Some(OUTCOME_PACKAGE) {
        return Err(verr(
            "outcome_room_package_substitution_refused",
            format!("the active System package must be '{OUTCOME_PACKAGE}'"),
        ));
    }
    let active = graph.get("active_profile_set").ok_or_else(|| {
        verr(
            "outcome_room_system_binding_invalid",
            "active System lacks its profile set",
        )
    })?;
    for (chain_field, active_pointer) in [
        ("constitution_ref", "/constitution/candidate_profile_ref"),
        (
            "deployment_profile_ref",
            "/deployment/candidate_profile_ref",
        ),
        (
            "ordering_admission_finality_profile_ref",
            "/ordering_admission_finality/candidate_profile_ref",
        ),
        (
            "lifecycle_continuity_profile_ref",
            "/lifecycle_continuity/candidate_profile_ref",
        ),
    ] {
        if chain.get(chain_field) != active.pointer(active_pointer) {
            return Err(verr(
                "outcome_room_system_binding_invalid",
                format!("active profile set is detached at '{chain_field}'"),
            ));
        }
    }
    Ok(graph)
}

fn room_tail_for_system(system_id: &str) -> Result<String, VErr> {
    let root = jcs_root(
        "ioi.outcome-room-system-identity-jcs-sha256.v1",
        &json!({"system_id":system_id}),
    )?;
    Ok(format!(
        "or_{}",
        root.strip_prefix("sha256:").unwrap_or_default()
    ))
}

fn collective_goal_run_for_room(
    data_dir: &str,
    goal_ref: &str,
    system_id: &str,
    system_graph: &Value,
) -> Result<Value, VErr> {
    let matches = strict_goal_run_census(data_dir)?
        .into_iter()
        .filter(|record| record.get("goal_ref").and_then(Value::as_str) == Some(goal_ref))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(verr(
            "outcome_room_collective_goal_run_unresolved",
            "objective_ref must resolve one exact durable GoalRun",
        ));
    }
    let goal_run = &matches[0];
    let decision = goal_run.get("admission_path_decision").ok_or_else(|| {
        verr(
            "outcome_room_collective_path_required",
            "room objective GoalRun has no admitted path decision",
        )
    })?;
    let facts = decision.get("runtime_facts").ok_or_else(|| {
        verr(
            "outcome_room_collective_path_required",
            "room objective GoalRun omits runtime path facts",
        )
    })?;
    let collective_fact = [
        "requires_outcome_room",
        "requires_shared_frontier",
        "requires_collective_scheduling",
    ]
    .iter()
    .any(|field| facts.get(field).and_then(Value::as_bool) == Some(true));
    let reasons = decision
        .get("reason_codes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let collective_reason = [
        "outcome_room_required",
        "shared_frontier_required",
        "collective_scheduling_required",
    ]
    .iter()
    .any(|reason| reasons.iter().any(|value| value.as_str() == Some(*reason)));
    if decision.get("decision").and_then(Value::as_str) != Some("system_bound_required")
        || facts.get("system_path_available").and_then(Value::as_bool) != Some(true)
        || !collective_fact
        || !collective_reason
    {
        return Err(verr(
            "outcome_room_collective_path_required",
            "room materialization requires a system_bound_required GoalRun whose admitted facts and reason codes require room, shared frontier, or collective scheduling",
        ));
    }
    if goal_run.get("target_system_id").and_then(Value::as_str) != Some(system_id) {
        return Err(verr(
            "outcome_room_collective_target_system_mismatch",
            "room System must equal the GoalRun's exact daemon-resolved target_system_id",
        ));
    }
    super::goalrun_routes::verify_collective_admission_fact_resolution(goal_run, system_graph)
        .map_err(|message| verr("outcome_room_collective_fact_evidence_invalid", message))?;
    Ok(goal_run.clone())
}

fn build_room_admission(
    data_dir: &str,
    body: &Value,
    room_tail: &str,
    at: &str,
) -> Result<(Value, Value, Value), VErr> {
    if body.get("schema_version").and_then(Value::as_str) != Some(ROOM_SCHEMA) {
        return Err(verr(
            "outcome_room_schema_version_invalid",
            format!("current bounded-System admission requires '{ROOM_SCHEMA}'"),
        ));
    }
    require_no_caller_system_claims(body)?;
    let system_id = exact_string(body, "/system_id", "outcome_room_system_id_required")?;
    let graph = active_system_binding(data_dir, system_id)?;
    let chain = &graph["autonomous_system_chain"];
    let active = &graph["active_profile_set"];
    let operation_log = &graph["operation_log"];
    let common = super::outcome_room_routes::validate_room_create(body)?;
    require_selected_m4_profile(&common)?;
    require_selected_m4_host(&common, chain)?;
    let objective_ref = exact_string(
        &common,
        "/objective_ref",
        "outcome_room_collective_goal_run_required",
    )?;
    let collective_goal_run =
        collective_goal_run_for_room(data_dir, objective_ref, system_id, &graph)?;
    if collective_goal_run.get("owner_ref") != common.get("owner_or_sponsor_ref") {
        return Err(verr(
            "outcome_room_collective_goal_run_owner_mismatch",
            "room owner must equal the durable collective GoalRun owner",
        ));
    }
    let surplus = super::outcome_room_routes::required_ref(
        body,
        "cooperation_surplus_policy_ref",
        &["policy"],
        "outcome_room_policy_required",
    )?;
    let terms = super::outcome_room_routes::list_ref(body, "collaboration_terms_refs", &["terms"])?;
    let oracle_refs = active
        .get("oracle_evidence_profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "outcome_room_system_binding_invalid",
                "oracle profile set is absent",
            )
        })?
        .iter()
        .map(|entry| {
            entry
                .get("candidate_profile_ref")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    verr(
                        "outcome_room_system_binding_invalid",
                        "oracle profile ref is absent",
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let network = active
        .get("network_enrollment")
        .filter(|value| !value.is_null())
        .and_then(|value| value.get("candidate_profile_ref"))
        .cloned()
        .unwrap_or(Value::Null);
    let room_id = format!("outcome-room://{room_tail}");
    let mut room = json!({
        "schema_version": ROOM_SCHEMA,
        "outcome_room_id": room_id,
        "system_id": chain["system_id"],
        "genesis_ref": chain["genesis_ref"],
        "package_id": chain["package_id"],
        "manifest_ref": chain["manifest_ref"],
        "constitution_ref": chain["constitution_ref"],
        "active_profile_refs": {
            "deployment_profile_ref": active["deployment"]["candidate_profile_ref"],
            "ordering_admission_finality_profile_ref": active["ordering_admission_finality"]["candidate_profile_ref"],
            "oracle_evidence_profile_refs": oracle_refs,
            "lifecycle_continuity_profile_ref": active["lifecycle_continuity"]["candidate_profile_ref"],
            "network_enrollment_ref": network,
        },
        "autonomous_system_state_ref": operation_log["operation_log_ref"],
        "owner_or_sponsor_ref": common["owner_or_sponsor_ref"],
        "objective_ref": common["objective_ref"],
        "objective": common["objective"],
        "constraint_refs": common["constraint_refs"],
        "acceptance_criteria_refs": common["acceptance_criteria_refs"],
        "stop_policy_ref": common["stop_policy_ref"],
        "room_mode": common["room_mode"],
        "visibility_policy_ref": common["visibility_policy_ref"],
        "participation_policy_ref": common["participation_policy_ref"],
        "privacy_policy_ref": common["privacy_policy_ref"],
        "contribution_policy_ref": common["contribution_policy_ref"],
        "cooperation_surplus_policy_ref": surplus,
        "collaboration_terms_refs": terms,
        "discovery_and_external_admission_policy_refs": common["discovery_and_external_admission_policy_refs"],
        "artifact_license_rights_retention_and_export_policy_refs": common["artifact_license_rights_retention_and_export_policy_refs"],
        "coordination_topology": common["coordination_topology"],
        "coordination_policy_ref": common["coordination_policy_ref"],
        "host_domain_ref": common["host_domain_ref"],
        "ordering_and_merge_policy_ref": common["ordering_and_merge_policy_ref"],
        "conflict_and_failover_policy_ref": common["conflict_and_failover_policy_ref"],
        "multi_party_collaboration_ref": common["multi_party_collaboration_ref"],
        "ontology_profile_refs": common["ontology_profile_refs"],
        "scorecard_and_guardrail_refs": common["scorecard_and_guardrail_refs"],
        "verifier_path_refs": common["verifier_path_refs"],
        "resource_and_budget_refs": common["resource_and_budget_refs"],
        "settlement_policy_ref": common["settlement_policy_ref"],
        "participant_lease_refs": [],
        "member_goal_run_refs": [],
        "participation_request_refs": [],
        "resource_offer_refs": [],
        "capability_offer_refs": [],
        "frontier_item_refs": [],
        "attempt_refs": [],
        "finding_refs": [],
        "verifier_challenge_refs": [],
        "discussion_projection_refs": [],
        "admission_and_replay_refs": [],
        "contribution_refs": [],
        "participant_state_bundle_refs": [],
        "latest_sequence": 0,
        "latest_transition_commitment_ref": Value::Null,
        "room_state_root": Value::Null,
        "room_receipt_root": Value::Null,
        "status": "open",
    });
    let transition_root = jcs_root(
        "ioi.outcome-room-genesis-transition-jcs-sha256.v2",
        &json!({
            "system_chain_root":chain["chain_root"],
            "system_state_root":chain["latest_state_root"],
            "room":room,
        }),
    )?;
    let transition_ref = format!(
        "commitment://ioi/outcome-room/{room_tail}/sequence/0/{}",
        transition_root.strip_prefix("sha256:").unwrap_or_default()
    );
    room["latest_transition_commitment_ref"] = json!(transition_ref);
    room["room_state_root"] = json!(state_root(&room)?);
    let receipt_ref = format!("receipt://outcome-room/{room_tail}/sequence/0");
    room["admission_and_replay_refs"] = json!([receipt_ref]);
    room["room_state_root"] = json!(state_root(&room)?);
    let receipt = json!({
        "schema_version":"ioi.outcome-room-admission-receipt.v2",
        "receipt_ref":receipt_ref,
        "receipt_root":Value::Null,
        "receipt_type":"outcome_room_admission",
        "system_id":room["system_id"],
        "outcome_room_ref":room["outcome_room_id"],
        "package_id":room["package_id"],
        "manifest_ref":room["manifest_ref"],
        "genesis_ref":room["genesis_ref"],
        "constitution_ref":room["constitution_ref"],
        "expected_room_revision":Value::Null,
        "resulting_room_revision":0,
        "sequence":0,
        "expected_predecessor_commitment_ref":Value::Null,
        "resulting_transition_commitment_ref":room["latest_transition_commitment_ref"],
        "resulting_room_state_root":room["room_state_root"],
        "status":"admitted",
        "at":at,
    });
    let (_, receipt) = rooted_record(RECEIPT_DOMAIN, "orrc_", "receipt_root", receipt)?;
    room["room_receipt_root"] = receipt["receipt_root"].clone();
    validate_current_room_contract(&room)?;
    let operation = json!({
        "schema_version":"ioi.outcome-room-admission-operation.v2",
        "operation_root":Value::Null,
        "operation_kind":"room_genesis_admitted",
        "outcome_room_ref":room["outcome_room_id"],
        "system_id":room["system_id"],
        "sequence":0,
        "expected_predecessor_commitment_ref":Value::Null,
        "resulting_transition_commitment_ref":room["latest_transition_commitment_ref"],
        "resulting_room_state_root":room["room_state_root"],
        "resulting_room":room,
        "receipt_ref":receipt["receipt_ref"],
        "receipt_root":receipt["receipt_root"],
        "system_chain_root":chain["chain_root"],
        "system_state_root":chain["latest_state_root"],
        "collective_goal_run_ref":collective_goal_run["goal_ref"],
        "collective_path_decision_ref":collective_goal_run["admission_path_decision"]["decision_ref"],
        "request_root":create_request_root(body)?,
        "at":at,
    });
    let (_, operation) = rooted_record(
        ADMISSION_OPERATION_DOMAIN,
        "orao_",
        "operation_root",
        operation,
    )?;
    Ok((operation["resulting_room"].clone(), receipt, operation))
}

fn key_for(record: &Value, field: &str, prefix: &str) -> Result<String, VErr> {
    let root = exact_string(
        record,
        &format!("/{field}"),
        "outcome_room_record_root_missing",
    )?;
    Ok(format!(
        "{prefix}{}",
        root.strip_prefix("sha256:").unwrap_or_default()
    ))
}

fn persist_local(family: &str, data_dir: &str, key: &str, value: &Value) -> Result<(), VErr> {
    super::durable_fs::persist_record_durable(data_dir, family, key, value).map_err(|failure| {
        verr(
            "outcome_room_projection_persist_failed",
            format!("{family}/{key}: {}", failure.detail()),
        )
    })
}

fn admit_required(family: &str, data_dir: &str, key: &str, value: &Value) -> Result<(), VErr> {
    super::substrate_store::admit_required(data_dir, family, key, value).map_err(|error| {
        verr(
            "outcome_room_agentgres_admission_failed",
            format!("{family}/{key}: {error}"),
        )
    })
}

fn strict_intent_family(data_dir: &str, family: &str) -> Result<Vec<(String, Value)>, VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(verr(
                "outcome_room_pending_intent_unreadable",
                format!("intent family '{family}' cannot be pinned ({error})"),
            ))
        }
    };
    let names = super::durable_fs::enumerate_pinned(&directory).map_err(|error| {
        verr(
            "outcome_room_pending_intent_unreadable",
            format!("intent family '{family}' cannot be enumerated ({error})"),
        )
    })?;
    let mut records = Vec::new();
    for name in names {
        let Some(key) = name.strip_suffix(".json") else {
            return Err(verr(
                "outcome_room_pending_intent_unreadable",
                format!("intent family '{family}' contains unexpected slot '{name}'"),
            ));
        };
        if key.is_empty()
            || key.len() > 180
            || !key.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
        {
            return Err(verr(
                "outcome_room_pending_intent_unreadable",
                format!("intent slot '{family}/{name}' has a non-canonical name"),
            ));
        }
        let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
            Ok(Some((_file, bytes))) => bytes,
            Ok(None) => {
                return Err(verr(
                    "outcome_room_pending_intent_unreadable",
                    format!("intent slot '{family}/{name}' vanished during census"),
                ))
            }
            Err(error) => {
                return Err(verr(
                    "outcome_room_pending_intent_unreadable",
                    format!("intent slot '{family}/{name}' is unreadable ({error})"),
                ))
            }
        };
        let record: Value = serde_json::from_slice(&bytes).map_err(|error| {
            verr(
                "outcome_room_pending_intent_unreadable",
                format!("intent slot '{family}/{name}' is malformed ({error})"),
            )
        })?;
        if !record.is_object() {
            return Err(verr(
                "outcome_room_pending_intent_unreadable",
                format!("intent slot '{family}/{name}' is not an object"),
            ));
        }
        records.push((key.to_owned(), record));
    }
    Ok(records)
}

fn pending_intent_census(data_dir: &str) -> Result<Vec<(String, String, Value)>, VErr> {
    let mut records = Vec::new();
    for family in [INTENT_DIR, CHILD_INTENT_DIR, MEMBERSHIP_INTENT_DIR] {
        records.extend(
            strict_intent_family(data_dir, family)?
                .into_iter()
                .map(|(key, record)| (family.to_owned(), key, record)),
        );
    }
    Ok(records)
}

pub(crate) fn refuse_while_any_intent_pending(data_dir: &str) -> Result<(), VErr> {
    let pending = pending_intent_census(data_dir)?;
    if pending.is_empty() {
        return Ok(());
    }
    Err(verr(
        "outcome_room_mutation_pending_recovery",
        format!(
            "{} durable OutcomeRoom transaction(s) require recovery before another mutation",
            pending.len()
        ),
    ))
}

fn confirm_room_read_stable(data_dir: &str, room_ref: &str, observed: &Value) -> Result<(), VErr> {
    refuse_while_any_intent_pending(data_dir)?;
    let current = super::outcome_room_routes::resolve_room_strict(data_dir, room_ref)
        .map_err(|error| verr("outcome_room_source_unreadable", error))?
        .ok_or_else(|| {
            verr(
                "outcome_room_projection_source_stale",
                "room vanished during read",
            )
        })?;
    if current != *observed {
        return Err(verr(
            "outcome_room_projection_source_stale",
            "room head changed while its projection was being read",
        ));
    }
    Ok(())
}

fn reservation_slot_root(room_ref: &str, predecessor: Option<&str>) -> Result<String, VErr> {
    jcs_root(
        "ioi.outcome-room-head-reservation-slot-jcs-sha256.v1",
        &json!({
            "outcome_room_ref": room_ref,
            "expected_predecessor_commitment_ref": predecessor,
        }),
    )
}

fn reserve_exact_room_successor(data_dir: &str, operation: &Value) -> Result<(), VErr> {
    let room_ref = exact_string(
        operation,
        "/outcome_room_ref",
        "outcome_room_reservation_invalid",
    )?;
    let predecessor = operation
        .get("expected_predecessor_commitment_ref")
        .and_then(Value::as_str);
    let slot_root = reservation_slot_root(room_ref, predecessor)?;
    let key = format!(
        "orhr_{}",
        slot_root.strip_prefix("sha256:").unwrap_or_default()
    );
    let reservation = json!({
        "schema_version":"ioi.outcome-room-head-reservation.v1",
        "reservation_slot_root":slot_root,
        "outcome_room_ref":room_ref,
        "sequence":operation["sequence"],
        "expected_predecessor_commitment_ref":operation["expected_predecessor_commitment_ref"],
        "resulting_transition_commitment_ref":operation["resulting_transition_commitment_ref"],
        "resulting_room_state_root":operation["resulting_room_state_root"],
        "operation_root":operation["operation_root"],
        "at":operation["at"],
    });
    super::substrate_store::admit_outcome_room_head_reservation(data_dir, &key, &reservation)
        .map_err(|error| {
            let code = if error.kind() == std::io::ErrorKind::AlreadyExists
                || error.to_string().contains("different immutable")
            {
                "outcome_room_head_conflict"
            } else {
                "outcome_room_head_reservation_agentgres_failed"
            };
            verr(code, error.to_string())
        })
}

fn remove_intent(data_dir: &str, family: &str, key: &str) -> Result<(), VErr> {
    let path = std::path::Path::new(data_dir)
        .join(family)
        .join(format!("{key}.json"));
    match std::fs::remove_file(&path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| {
                        verr("outcome_room_intent_cleanup_failed", error.to_string())
                    })?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(verr(
            "outcome_room_intent_cleanup_failed",
            error.to_string(),
        )),
    }
}

fn finalize_room(
    data_dir: &str,
    room_tail: &str,
    body: &Value,
    room: &Value,
    receipt: &Value,
    operation: &Value,
    cleanup_definitive_live_conflict: bool,
) -> Result<(), VErr> {
    let operation_key = key_for(operation, "operation_root", "orao_")?;
    let intent = json!({
        "schema_version":"ioi.outcome-room-system-admission-intent.v1",
        "room_tail":room_tail,
        "request":body,
        "room":room,
        "receipt":receipt,
        "operation":operation,
        "at":operation["at"],
    });
    // The operation-root key prevents two distinct concurrent genesis candidates from replacing
    // each other's recovery intent before the fixed room-head reservation adjudicates them.
    persist_local(INTENT_DIR, data_dir, &operation_key, &intent)?;
    if let Err(error) = reserve_exact_room_successor(data_dir, operation) {
        if cleanup_definitive_live_conflict && error.0 == "outcome_room_head_conflict" {
            remove_intent(data_dir, INTENT_DIR, &operation_key)?;
        }
        return Err(error);
    }
    let receipt_key = key_for(receipt, "receipt_root", "orrc_")?;
    admit_required(
        ADMISSION_OPERATION_DOMAIN,
        data_dir,
        &operation_key,
        operation,
    )?;
    admit_required(RECEIPT_DOMAIN, data_dir, &receipt_key, receipt)?;
    persist_local(RECEIPT_DIR, data_dir, &receipt_key, receipt)?;
    if std::env::var("IOI_TEST_FORCE_OUTCOME_ROOM_AFTER_AGENTGRES")
        .ok()
        .as_deref()
        == Some("1")
    {
        return Err(verr(
            "outcome_room_admission_pending_recovery",
            "test-forced interruption after Agentgres admission and before projection visibility",
        ));
    }
    persist_local(ROOM_DIR, data_dir, room_tail, room)?;
    remove_intent(data_dir, INTENT_DIR, &operation_key)
}

pub(crate) async fn handle_create(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let system_id = match exact_string(&body, "/system_id", "outcome_room_system_id_required") {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let room_tail = match room_tail_for_system(system_id) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let room_ref = format!("outcome-room://{room_tail}");
    let owner = match exact_string(
        &body,
        "/owner_or_sponsor_ref",
        "outcome_room_owner_required",
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if let Err(error) = authorize_declared_owner(&state.data_dir, &headers, owner) {
        return classify(error);
    }
    let _guard = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(error) = refuse_while_any_intent_pending(&state.data_dir) {
        return room_source_refusal(&state.data_dir, &headers, error);
    }
    let current_rooms =
        match super::outcome_room_routes::list_current_rooms_canonical_strict(&state.data_dir) {
            Ok(rooms) => rooms,
            Err(error) => return room_source_refusal(&state.data_dir, &headers, error),
        };
    let existing = match super::outcome_room_routes::resolve_room_strict(&state.data_dir, &room_ref)
    {
        Ok(value) => value,
        Err(message) => {
            return room_source_refusal(
                &state.data_dir,
                &headers,
                verr("outcome_room_source_unreadable", message),
            )
        }
    };
    if let Some(existing) = existing {
        if existing.get("system_id").and_then(Value::as_str) == Some(system_id)
            && existing.get("schema_version").and_then(Value::as_str) == Some(ROOM_SCHEMA)
        {
            if let Err(error) = authorize_room_access(&state.data_dir, &headers, &existing) {
                return classify(error);
            }
            let request_root = match create_request_root(&body) {
                Ok(value) => value,
                Err(error) => return classify(error),
            };
            let admitted = match required_projection_records(
                &state.data_dir,
                ADMISSION_OPERATION_DOMAIN,
                &room_ref,
                1,
            ) {
                Ok(values) => values,
                Err(error) => return classify(error),
            };
            if admitted.len() == 1
                && admitted[0].get("request_root").and_then(Value::as_str)
                    == Some(request_root.as_str())
            {
                let response = json!({"outcome_room":existing,"replayed":true});
                if let Err(error) =
                    ensure_serialized_body_bound(&response, "outcome_room_response_too_large")
                {
                    return classify(error);
                }
                return (StatusCode::OK, Json(response));
            }
            return classify(verr(
                "outcome_room_create_body_conflict",
                "the deterministic room identity exists, but its exact admitted create body differs",
            ));
        }
        return classify(verr(
            "outcome_room_system_identity_conflict",
            "the deterministic room identity is already occupied by different bytes",
        ));
    }
    if current_rooms.len() >= M4_HOSTED_ROOM_MAX {
        return classify(verr(
            "outcome_room_capacity_exceeded",
            format!(
                "hosted M4 already contains the selected maximum of {M4_HOSTED_ROOM_MAX} rooms"
            ),
        ));
    }
    let at = iso_now();
    let (room, receipt, operation) =
        match build_room_admission(&state.data_dir, &body, &room_tail, &at) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    let response = json!({
        "outcome_room":room.clone(),
        "outcome_room_receipt":receipt.clone(),
        "agentgres_operation":operation.clone(),
        "replayed":false,
    });
    if let Err(error) = ensure_serialized_body_bound(&response, "outcome_room_response_too_large") {
        return classify(error);
    }
    if let Err(error) = finalize_room(
        &state.data_dir,
        &room_tail,
        &body,
        &room,
        &receipt,
        &operation,
        true,
    ) {
        return classify(error);
    }
    (StatusCode::CREATED, Json(response))
}

struct ChildContract {
    schema: &'static str,
    id_field: &'static str,
    list_field: Option<&'static str>,
}

fn child_contract(contract_id: &str) -> Option<ChildContract> {
    Some(match contract_id {
        "schema://ioi/foundations/work-frontier-item/v2" => ChildContract {
            schema: "ioi.foundations.work-frontier-item.v2",
            id_field: "frontier_item_id",
            list_field: Some("frontier_item_refs"),
        },
        "schema://ioi/foundations/work-claim-lease/v2" => ChildContract {
            schema: "ioi.foundations.work-claim-lease.v2",
            id_field: "work_claim_id",
            list_field: None,
        },
        "schema://ioi/foundations/attempt/v2" => ChildContract {
            schema: "ioi.foundations.attempt.v2",
            id_field: "attempt_id",
            list_field: Some("attempt_refs"),
        },
        "schema://ioi/foundations/finding/v2" => ChildContract {
            schema: "ioi.foundations.finding.v2",
            id_field: "finding_id",
            list_field: Some("finding_refs"),
        },
        "schema://ioi/foundations/verifier-challenge/v2" => ChildContract {
            schema: "ioi.foundations.verifier-challenge.v2",
            id_field: "verifier_challenge_id",
            list_field: Some("verifier_challenge_refs"),
        },
        "schema://ioi/foundations/participant-state-bundle/v2" => ChildContract {
            schema: "ioi.foundations.participant-state-bundle.v2",
            id_field: "participant_state_bundle_id",
            list_field: Some("participant_state_bundle_refs"),
        },
        "schema://ioi/foundations/work-result/v2" => ChildContract {
            schema: "ioi.foundations.work-result.v2",
            id_field: "work_result_id",
            list_field: None,
        },
        "schema://ioi/foundations/outcome-delta/v2" => ChildContract {
            schema: "ioi.foundations.outcome-delta.v2",
            id_field: "outcome_delta_id",
            list_field: None,
        },
        _ => return None,
    })
}

fn expected_proposed_base<'a>(
    object: &'a Value,
    room: &Value,
    object_ref: &str,
) -> Result<&'a Value, VErr> {
    let base = object.get("room_admission").ok_or_else(|| {
        verr(
            "outcome_room_admission_base_required",
            "room_admission is required",
        )
    })?;
    let sequence = room
        .get("latest_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| verr("outcome_room_state_invalid", "room sequence is absent"))?;
    for (field, expected) in [
        ("schema_version", json!(BASE_SCHEMA)),
        ("room_system_id", room["system_id"].clone()),
        ("outcome_room_ref", room["outcome_room_id"].clone()),
        ("proposed_or_issued_by_ref", room["system_id"].clone()),
        ("expected_room_revision", json!(sequence)),
        (
            "expected_predecessor_commitment_ref",
            room["latest_transition_commitment_ref"].clone(),
        ),
        (
            "admission_policy_ref",
            room["coordination_policy_ref"].clone(),
        ),
        ("admission_status", json!("proposed")),
    ] {
        if base.get(field) != Some(&expected) {
            return Err(verr(
                if field == "room_system_id" || field == "outcome_room_ref" {
                    "outcome_room_wrong_system_child_refused"
                } else if field.starts_with("expected_") {
                    "outcome_room_stale_child_refused"
                } else {
                    "outcome_room_admission_base_invalid"
                },
                format!("child '{object_ref}' has a detached '{field}'"),
            ));
        }
    }
    for field in [
        "admission_decision_ref",
        "admission_receipt_ref",
        "admitted_sequence",
        "resulting_room_revision",
        "resulting_transition_commitment_ref",
        "resulting_room_state_root",
        "resulting_receipt_root",
        "updated_at",
    ] {
        if base.get(field) != Some(&Value::Null) {
            return Err(verr(
                "outcome_room_stale_verdict_refused",
                format!("proposed child carries plane-owned terminal field '{field}'"),
            ));
        }
    }
    let mut payload = object.clone();
    payload
        .as_object_mut()
        .ok_or_else(|| verr("outcome_room_child_invalid", "child is not an object"))?
        .remove("room_admission");
    let expected_payload = jcs_root("ioi.outcome-room-child-payload-jcs-sha256.v1", &payload)?;
    if base.get("payload_root").and_then(Value::as_str) != Some(expected_payload.as_str()) {
        return Err(verr(
            "outcome_room_child_payload_root_mismatch",
            "payload_root does not bind the exact object-specific payload",
        ));
    }
    Ok(base)
}

fn append_unique(room: &mut Value, field: &str, value: Value) -> Result<(), VErr> {
    let array = room
        .get_mut(field)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            verr(
                "outcome_room_state_invalid",
                format!("room lacks '{field}'"),
            )
        })?;
    if !array.contains(&value) {
        array.push(value);
    }
    Ok(())
}

fn next_room_sequence(room: &Value) -> Result<u64, VErr> {
    let prior_sequence = room["latest_sequence"]
        .as_u64()
        .ok_or_else(|| verr("outcome_room_state_invalid", "room sequence is absent"))?;
    if prior_sequence >= M4_TRANSITION_ENTRY_MAX as u64 {
        return Err(verr(
            "outcome_room_transition_capacity_exceeded",
            format!(
                "hosted M4 permits room transitions only through sequence {M4_TRANSITION_ENTRY_MAX}"
            ),
        ));
    }
    Ok(prior_sequence + 1)
}

fn build_child_admission(
    room: &Value,
    contract_id: &str,
    object: &Value,
    at: &str,
) -> Result<(Value, Value, Value, Value), VErr> {
    let contract = child_contract(contract_id).ok_or_else(|| {
        verr(
            "outcome_room_child_contract_unavailable",
            "only the registered M4 room-child v2 families are admitted",
        )
    })?;
    if object.get("schema_version").and_then(Value::as_str) != Some(contract.schema) {
        return Err(verr(
            "outcome_room_child_contract_substitution",
            "object schema_version does not match object_contract_id",
        ));
    }
    let sequence = next_room_sequence(room)?;
    let object_ref = object
        .get(contract.id_field)
        .and_then(Value::as_str)
        .ok_or_else(|| verr("outcome_room_child_identity_required", contract.id_field))?;
    let base = expected_proposed_base(object, room, object_ref)?;
    canonical_contract(contract_id, object)?;
    let prior_sequence = sequence - 1;
    let transition_hash = jcs_root(
        "ioi.outcome-room-child-transition-jcs-sha256.v2",
        &json!({
            "outcome_room_ref":room["outcome_room_id"],
            "system_id":room["system_id"],
            "sequence":sequence,
            "predecessor":room["latest_transition_commitment_ref"],
            "object_contract_id":contract_id,
            "object_ref":object_ref,
            "payload_root":base["payload_root"],
        }),
    )?;
    let room_tail = room["outcome_room_id"]
        .as_str()
        .and_then(|value| value.strip_prefix("outcome-room://"))
        .ok_or_else(|| verr("outcome_room_state_invalid", "room identity is invalid"))?;
    let transition_ref = format!(
        "commitment://ioi/outcome-room/{room_tail}/sequence/{sequence}/{}",
        transition_hash.strip_prefix("sha256:").unwrap_or_default()
    );
    let receipt_ref = format!("receipt://outcome-room/{room_tail}/sequence/{sequence}");
    let mut updated_room = room.clone();
    updated_room["latest_sequence"] = json!(sequence);
    updated_room["latest_transition_commitment_ref"] = json!(transition_ref);
    append_unique(
        &mut updated_room,
        "admission_and_replay_refs",
        json!(receipt_ref),
    )?;
    if let Some(field) = contract.list_field {
        append_unique(&mut updated_room, field, json!(object_ref))?;
    }
    updated_room["room_state_root"] = json!(state_root(&updated_room)?);
    let receipt = json!({
        "schema_version":"ioi.outcome-room-admission-receipt.v2",
        "receipt_ref":receipt_ref,
        "receipt_root":Value::Null,
        "receipt_type":"room_child_admission",
        "system_id":room["system_id"],
        "outcome_room_ref":room["outcome_room_id"],
        "subject_refs":[object_ref],
        "object_contract_id":contract_id,
        "expected_room_revision":prior_sequence,
        "resulting_room_revision":sequence,
        "sequence":sequence,
        "expected_predecessor_commitment_ref":room["latest_transition_commitment_ref"],
        "resulting_transition_commitment_ref":updated_room["latest_transition_commitment_ref"],
        "resulting_room_state_root":updated_room["room_state_root"],
        "status":"admitted",
        "at":at,
    });
    let (_, receipt) = rooted_record(RECEIPT_DOMAIN, "orrc_", "receipt_root", receipt)?;
    updated_room["room_receipt_root"] = receipt["receipt_root"].clone();
    validate_current_room_contract(&updated_room)?;

    let mut admitted = object.clone();
    admitted["room_admission"] = json!({
        "schema_version":BASE_SCHEMA,
        "room_system_id":room["system_id"],
        "outcome_room_ref":room["outcome_room_id"],
        "proposed_or_issued_by_ref":room["system_id"],
        "expected_room_revision":prior_sequence,
        "expected_predecessor_commitment_ref":room["latest_transition_commitment_ref"],
        "payload_root":base["payload_root"],
        "admission_policy_ref":room["coordination_policy_ref"],
        "admission_decision_ref":format!("decision://outcome-room/{room_tail}/sequence/{sequence}"),
        "admission_receipt_ref":receipt["receipt_ref"],
        "admitted_sequence":sequence,
        "resulting_room_revision":sequence,
        "resulting_transition_commitment_ref":updated_room["latest_transition_commitment_ref"],
        "resulting_room_state_root":updated_room["room_state_root"],
        "resulting_receipt_root":receipt["receipt_root"],
        "created_at":base["created_at"],
        "updated_at":at,
        "admission_status":"admitted",
    });
    canonical_contract(contract_id, &admitted)?;
    let object_record = json!({
        "schema_version":"ioi.outcome-room-admitted-object.v2",
        "object_root":Value::Null,
        "object_contract_id":contract_id,
        "object_ref":object_ref,
        "outcome_room_ref":room["outcome_room_id"],
        "system_id":room["system_id"],
        "admitted_object":admitted,
        "at":at,
    });
    let (_, object_record) = rooted_record(OBJECT_DOMAIN, "orobj_", "object_root", object_record)?;
    let operation = json!({
        "schema_version":"ioi.outcome-room-transition-operation.v2",
        "operation_root":Value::Null,
        "operation_kind":"room_child_admitted",
        "outcome_room_ref":room["outcome_room_id"],
        "system_id":room["system_id"],
        "sequence":sequence,
        "expected_predecessor_commitment_ref":room["latest_transition_commitment_ref"],
        "resulting_transition_commitment_ref":updated_room["latest_transition_commitment_ref"],
        "resulting_room_state_root":updated_room["room_state_root"],
        "resulting_room":updated_room,
        "object_contract_id":contract_id,
        "object_ref":object_ref,
        "object_root":object_record["object_root"],
        "receipt_ref":receipt["receipt_ref"],
        "receipt_root":receipt["receipt_root"],
        "at":at,
    });
    let (_, operation) = rooted_record(
        TRANSITION_OPERATION_DOMAIN,
        "orto_",
        "operation_root",
        operation,
    )?;
    Ok((
        operation["resulting_room"].clone(),
        receipt,
        object_record,
        operation,
    ))
}

fn finalize_child(
    data_dir: &str,
    room_tail: &str,
    prior_room: &Value,
    room: &Value,
    receipt: &Value,
    object: &Value,
    operation: &Value,
    runtime_dependencies: Option<&Value>,
) -> Result<(), VErr> {
    let operation_key = key_for(operation, "operation_root", "orto_")?;
    let receipt_key = key_for(receipt, "receipt_root", "orrc_")?;
    let object_key = key_for(object, "object_root", "orobj_")?;
    let admitted_object = object.get("admitted_object").ok_or_else(|| {
        verr(
            "outcome_room_owner_record_invalid",
            "admitted-object projection omits its owner record",
        )
    })?;
    let (owner_family, owner_identity_field) = match admitted_object
        .get("schema_version")
        .and_then(Value::as_str)
    {
        Some("ioi.foundations.work-result.v2") => {
            (super::work_result_routes::RESULT_DIR, "work_result_id")
        }
        Some("ioi.foundations.outcome-delta.v2") => {
            (super::work_result_routes::DELTA_DIR, "outcome_delta_id")
        }
        _ => {
            return Err(verr(
                "outcome_room_owner_record_contract_unavailable",
                "child finalization accepts only WorkResult or OutcomeDelta",
            ))
        }
    };
    let owner_identity = exact_string(
        admitted_object,
        &format!("/{owner_identity_field}"),
        "outcome_room_owner_record_identity_required",
    )?;
    let owner_key = safe_owner_key(owner_identity);
    let intent = json!({
        "schema_version":"ioi.outcome-room-child-admission-intent.v1",
        "room_tail":room_tail,
        "prior_room_state_root":prior_room["room_state_root"],
        "prior_room":prior_room,
        "room":room,
        "receipt":receipt,
        "object":object,
        "owner_publication_family":owner_family,
        "owner_publication_key":owner_key,
        "owner_publication_record":admitted_object,
        "runtime_dependencies":runtime_dependencies.cloned().unwrap_or(Value::Null),
        "operation":operation,
        "at":operation["at"],
    });
    persist_local(CHILD_INTENT_DIR, data_dir, &operation_key, &intent)?;
    if std::env::var("IOI_TEST_FORCE_OUTCOME_ROOM_CHILD_AFTER_INTENT")
        .ok()
        .as_deref()
        == Some("1")
    {
        return Err(verr(
            "outcome_room_child_pending_recovery",
            "test-forced interruption after child intent persistence and before any child admission side effect",
        ));
    }
    if let Some(dependencies) = runtime_dependencies {
        super::goalrun_routes::converge_room_owner_runtime_dependencies(
            data_dir,
            room,
            admitted_object,
            dependencies,
        )
        .map_err(|(code, message)| verr(&code, message))?;
    }
    if std::env::var("IOI_TEST_FORCE_OUTCOME_ROOM_CHILD_AFTER_RUNTIME_DEPENDENCIES")
        .ok()
        .as_deref()
        == Some("1")
    {
        return Err(verr(
            "outcome_room_child_pending_recovery",
            "test-forced interruption after intent-covered runtime dependencies and before room succession",
        ));
    }
    if let Err(error) = reserve_exact_room_successor(data_dir, operation) {
        if error.0 == "outcome_room_head_conflict"
            && child_head_conflict_may_remove_intent(runtime_dependencies)
        {
            remove_intent(data_dir, CHILD_INTENT_DIR, &operation_key)?;
        }
        return Err(error);
    }
    admit_required(
        TRANSITION_OPERATION_DOMAIN,
        data_dir,
        &operation_key,
        operation,
    )?;
    admit_required(RECEIPT_DOMAIN, data_dir, &receipt_key, receipt)?;
    admit_required(OBJECT_DOMAIN, data_dir, &object_key, object)?;
    persist_local(RECEIPT_DIR, data_dir, &receipt_key, receipt)?;
    persist_local(OBJECT_DIR, data_dir, &object_key, object)?;
    if std::env::var("IOI_TEST_FORCE_OUTCOME_ROOM_CHILD_AFTER_AGENTGRES")
        .ok()
        .as_deref()
        == Some("1")
    {
        return Err(verr(
            "outcome_room_child_pending_recovery",
            "test-forced interruption after Agentgres admission and before projection visibility",
        ));
    }
    persist_local(ROOM_DIR, data_dir, room_tail, room)?;
    if std::env::var("IOI_TEST_FORCE_OUTCOME_ROOM_CHILD_AFTER_ROOM")
        .ok()
        .as_deref()
        == Some("1")
    {
        return Err(verr(
            "outcome_room_child_pending_recovery",
            "test-forced interruption after room projection and before owner publication",
        ));
    }
    let room_receipt_ref = exact_string(
        receipt,
        "/receipt_ref",
        "outcome_room_owner_receipt_ref_invalid",
    )?;
    super::goalrun_routes::converge_room_owner_backlinks(
        data_dir,
        admitted_object,
        room_receipt_ref,
    )
    .map_err(|(code, message)| verr(&code, message))?;
    remove_intent(data_dir, CHILD_INTENT_DIR, &operation_key)?;
    Ok(())
}

fn owner_convergence_summary(
    resulting_room: &Value,
    object_record: &Value,
    receipt: &Value,
) -> Result<Value, VErr> {
    let admitted_object = object_record.get("admitted_object").ok_or_else(|| {
        verr(
            "outcome_room_owner_record_invalid",
            "admitted-object projection omits its owner record",
        )
    })?;
    let contract_id = exact_string(
        object_record,
        "/object_contract_id",
        "outcome_room_owner_record_contract_unavailable",
    )?;
    let owner_record_ref = exact_string(
        object_record,
        "/object_ref",
        "outcome_room_owner_record_identity_required",
    )?;
    let goal_run_ref = admitted_object
        .get("goal_run_ref")
        .filter(|value| !value.is_null())
        .cloned()
        .or_else(|| {
            admitted_object
                .get("work_subject_ref")
                .filter(|value| {
                    value
                        .as_str()
                        .is_some_and(|reference| reference.starts_with("goal://"))
                })
                .cloned()
        })
        .unwrap_or(Value::Null);
    let invocation_or_run_ref = admitted_object
        .get("invocation_or_run_ref")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or(Value::Null);
    let parent_work_result_ref = if contract_id.ends_with("outcome-delta/v2") {
        admitted_object
            .get("proposed_by_ref")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    Ok(json!({
        "owner_record_contract_id":contract_id,
        "owner_record_ref":owner_record_ref,
        "admitted_object_projection_root":object_record["object_root"],
        "outcome_room_ref":resulting_room["outcome_room_id"],
        "resulting_room_revision":resulting_room["latest_sequence"],
        "resulting_transition_commitment_ref":resulting_room["latest_transition_commitment_ref"],
        "resulting_room_state_root":resulting_room["room_state_root"],
        "room_admission_receipt_ref":receipt["receipt_ref"],
        "room_admission_receipt_root":receipt["receipt_root"],
        "goal_run_ref":goal_run_ref,
        "invocation_or_run_ref":invocation_or_run_ref,
        "parent_work_result_ref":parent_work_result_ref,
    }))
}

fn owner_admission_http_response(contract_id: &str, admission: Value) -> Value {
    if contract_id.ends_with("work-result/v2") {
        json!({"ok":true,"admission":admission})
    } else {
        json!({
            "ok":true,
            "admission":admission,
            "effect_executed":false,
            "acceptance_granted":false,
        })
    }
}

fn child_head_conflict_may_remove_intent(runtime_dependencies: Option<&Value>) -> bool {
    // A WorkResult's dependency bundle may already have converged before an
    // out-of-process writer advances the room head.  Its child intent is then
    // the durable recovery and inspection owner for those partial writes.
    // OutcomeDelta has no dependency bundle, so a definitive live conflict can
    // discard its write-free intent.
    runtime_dependencies.is_none()
}

fn safe_owner_key(reference: &str) -> String {
    super::goalrun_routes::room_owner_record_key(reference)
}

fn owner_publication_slot(
    data_dir: &str,
    owner_record: &Value,
) -> Result<(&'static str, String), VErr> {
    let (family, identity_field, records) =
        match owner_record.get("schema_version").and_then(Value::as_str) {
            Some("ioi.foundations.work-result.v2") => (
                super::work_result_routes::RESULT_DIR,
                "work_result_id",
                super::work_result_routes::list_work_results_strict(data_dir),
            ),
            Some("ioi.foundations.outcome-delta.v2") => (
                super::work_result_routes::DELTA_DIR,
                "outcome_delta_id",
                super::work_result_routes::list_outcome_deltas_strict(data_dir),
            ),
            _ => return Err(verr(
                "outcome_room_owner_record_contract_unavailable",
                "M4 admits only owner-plane WorkResult and OutcomeDelta records into room truth",
            )),
        };
    let identity = exact_string(
        owner_record,
        &format!("/{identity_field}"),
        "outcome_room_owner_record_identity_required",
    )?;
    let matches = records
        .map_err(|message| {
            verr(
                "outcome_room_owner_publication_registry_unreadable",
                format!(
                    "versioned owner registry refuses publication preflight for '{identity}' ({message})"
                ),
            )
        })?
        .into_iter()
        .filter(|record| record.get(identity_field).and_then(Value::as_str) == Some(identity))
        .collect::<Vec<_>>();
    if !matches.is_empty() {
        return Err(verr(
            "outcome_room_owner_record_prematurely_visible",
            format!(
                "owner record '{identity}' is already public before its room transaction commits"
            ),
        ));
    }
    Ok((family, safe_owner_key(identity)))
}

fn outcome_delta_semantic_request(record: &Value) -> Value {
    let sorted_ref_set = |field: &str| {
        let mut refs = record
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        refs.sort();
        Value::Array(refs.into_iter().map(Value::String).collect())
    };
    // OutcomeDelta has no canonical idempotency key. This projection therefore compares only
    // the complete caller-visible semantics, treating the registered unique ref arrays as sets;
    // plane-minted identity, admission coordinates/verdict, and lifecycle status are excluded.
    json!({
        "schema_version":record["schema_version"],
        "work_subject_ref":record["work_subject_ref"],
        "outcome_room_ref":record["outcome_room_ref"],
        "proposed_by_ref":record["proposed_by_ref"],
        "target_ref":record["target_ref"],
        "delta_kind":record["delta_kind"],
        "payload_ref":record["payload_ref"],
        "precondition_and_invariant_refs":sorted_ref_set("precondition_and_invariant_refs"),
        "expected_effect_ref":record["expected_effect_ref"],
        "verifier_and_acceptance_refs":sorted_ref_set("verifier_and_acceptance_refs"),
        "information_flow_label_refs":sorted_ref_set("information_flow_label_refs"),
    })
}

fn refuse_terminal_outcome_delta_retry(
    data_dir: &str,
    admitted_candidate: &Value,
) -> Result<(), VErr> {
    if admitted_candidate
        .get("schema_version")
        .and_then(Value::as_str)
        != Some("ioi.foundations.outcome-delta.v2")
    {
        return Ok(());
    }
    let candidate_semantics = outcome_delta_semantic_request(admitted_candidate);
    let existing =
        super::work_result_routes::list_outcome_deltas_strict(data_dir).map_err(|message| {
            verr(
                "outcome_room_owner_publication_registry_unreadable",
                format!(
                    "versioned OutcomeDelta registry refuses semantic retry preflight ({message})"
                ),
            )
        })?;
    for record in existing.into_iter().filter(|record| {
        record.get("schema_version").and_then(Value::as_str)
            == Some("ioi.foundations.outcome-delta.v2")
    }) {
        canonical_contract("schema://ioi/foundations/outcome-delta/v2", &record).map_err(|_| {
            verr(
                "outcome_room_owner_publication_registry_unreadable",
                "versioned OutcomeDelta registry contains a non-canonical v2 owner record",
            )
        })?;
        if outcome_delta_semantic_request(&record) == candidate_semantics {
            return Err(verr(
                "outcome_room_delta_post_terminal_retry_refused",
                "an OutcomeDelta with the same complete request semantics is already admitted; the current contract has no canonical idempotency identity, so the post-terminal retry is refused without mutation",
            ));
        }
    }
    Ok(())
}

/// Read-only owner-registry preflight for callers that would otherwise admit runtime dependency
/// evidence before entering the room transaction. The transaction repeats this census under the
/// room mutation lock, so the early check prevents side effects on already-dark registry truth
/// without weakening the commit-time TOCTOU guard.
pub(crate) fn preflight_owner_publication(
    data_dir: &str,
    owner_record: &Value,
) -> Result<(), VErr> {
    owner_publication_slot(data_dir, owner_record).map(|_| ())
}

fn prepare_owner_record_for_room(
    data_dir: &str,
    room: &Value,
    owner_record: &Value,
    at: &str,
    runtime_dependencies: Option<&Value>,
) -> Result<(String, Value), VErr> {
    let _ = owner_publication_slot(data_dir, owner_record)?;
    if let Some(base) = owner_record
        .get("room_admission")
        .filter(|value| !value.is_null())
    {
        if base.get("room_system_id") != room.get("system_id")
            || base.get("outcome_room_ref") != room.get("outcome_room_id")
        {
            return Err(verr(
                "outcome_room_wrong_system_child_refused",
                "caller-carried room base names the wrong System or room",
            ));
        }
        if base.get("expected_room_revision") != room.get("latest_sequence")
            || base.get("expected_predecessor_commitment_ref")
                != room.get("latest_transition_commitment_ref")
        {
            return Err(verr(
                "outcome_room_stale_child_refused",
                "caller-carried room base is stale",
            ));
        }
        if base.get("admission_status").and_then(Value::as_str) != Some("proposed")
            || [
                "admission_decision_ref",
                "admission_receipt_ref",
                "admitted_sequence",
                "resulting_room_revision",
                "resulting_transition_commitment_ref",
                "resulting_room_state_root",
                "resulting_receipt_root",
                "updated_at",
            ]
            .iter()
            .any(|field| base.get(*field).is_some_and(|value| !value.is_null()))
        {
            return Err(verr(
                "outcome_room_stale_verdict_refused",
                "caller-carried room base includes a terminal admission verdict",
            ));
        }
        return Err(verr(
            "outcome_room_admission_base_plane_owned",
            "room_admission is derived by the daemon from the current owner and room heads",
        ));
    }
    if owner_record
        .get("outcome_room_ref")
        .is_some_and(|value| !value.is_null())
    {
        return Err(verr(
            "outcome_room_owner_record_room_fields_plane_owned",
            "owner-plane outcome_room_ref is server-derived by the room seam",
        ));
    }
    let (contract_id, identity_field) =
        match owner_record.get("schema_version").and_then(Value::as_str) {
            Some("ioi.foundations.work-result.v2") => {
                ("schema://ioi/foundations/work-result/v2", "work_result_id")
            }
            Some("ioi.foundations.outcome-delta.v2") => (
                "schema://ioi/foundations/outcome-delta/v2",
                "outcome_delta_id",
            ),
            _ => unreachable!("validated above"),
        };
    let _object_ref = exact_string(
        owner_record,
        &format!("/{identity_field}"),
        "outcome_room_owner_record_identity_required",
    )?;
    let room_ref = exact_string(room, "/outcome_room_id", "outcome_room_state_invalid")?;
    if !owner_record
        .get("information_flow_label_refs")
        .and_then(Value::as_array)
        .is_some_and(|labels| !labels.is_empty())
    {
        return Err(verr(
            "outcome_room_projection_labels_required",
            "room-admitted WorkResult and OutcomeDelta records require a non-empty label projection",
        ));
    }
    if contract_id.ends_with("work-result/v2") {
        let dependencies = runtime_dependencies.ok_or_else(|| {
            verr(
                "outcome_room_work_result_runtime_dependency_intent_required",
                "room WorkResult admission requires one complete retained runtime-dependency intent",
            )
        })?;
        super::goalrun_routes::validate_room_owner_runtime_dependency_intent(
            data_dir,
            room,
            owner_record,
            dependencies,
        )
        .map_err(|(code, message)| verr(&code, message))?;
        let goal_run_ref = exact_string(
            owner_record,
            "/goal_run_ref",
            "outcome_room_work_result_goal_run_required",
        )?;
        if !room
            .get("member_goal_run_refs")
            .and_then(Value::as_array)
            .is_some_and(|refs| {
                refs.iter()
                    .any(|value| value.as_str() == Some(goal_run_ref))
            })
        {
            return Err(verr(
                "outcome_room_work_result_goal_run_unbound",
                "WorkResult GoalRun is not a reciprocal member of this room",
            ));
        }
        if owner_record
            .get("invocation_or_run_ref")
            .is_none_or(Value::is_null)
        {
            return Err(verr(
                "outcome_room_work_result_execution_unresolved",
                "room WorkResult must resolve the real invocation or run that produced it",
            ));
        }
    } else {
        if runtime_dependencies.is_some() {
            return Err(verr(
                "outcome_room_delta_runtime_dependency_intent_refused",
                "OutcomeDelta does not own a WorkResult runtime-dependency bundle",
            ));
        }
        super::goalrun_routes::validate_room_owner_runtime_dependencies(
            data_dir,
            room,
            owner_record,
        )
        .map_err(|(code, message)| verr(&code, message))?;
        let proposed_by = exact_string(
            owner_record,
            "/proposed_by_ref",
            "outcome_room_delta_proposer_required",
        )?;
        let admitted_results =
            required_projection_records(data_dir, OBJECT_DOMAIN, room_ref, M4_REPLAY_ENTRY_MAX)?;
        let proposed_result = admitted_results.iter().find(|record| {
            record.get("object_contract_id").and_then(Value::as_str)
                == Some("schema://ioi/foundations/work-result/v2")
                && record.get("object_ref").and_then(Value::as_str) == Some(proposed_by)
        });
        let Some(proposed_result) = proposed_result else {
            return Err(verr(
                "outcome_room_delta_work_result_unbound",
                "OutcomeDelta proposer is not an admitted WorkResult in this exact room",
            ));
        };
        let admitted_work_result = proposed_result.get("admitted_object").ok_or_else(|| {
            verr(
                "outcome_room_delta_work_result_unresolved",
                "OutcomeDelta proposer projection omits its admitted WorkResult",
            )
        })?;
        super::goalrun_routes::validate_room_owner_runtime_dependencies(
            data_dir,
            room,
            admitted_work_result,
        )
        .map_err(|(code, message)| verr(&code, message))?;
        if admitted_work_result.get("work_subject_ref") != owner_record.get("work_subject_ref") {
            return Err(verr(
                "outcome_room_delta_work_subject_conflict",
                "OutcomeDelta work subject differs from its admitted WorkResult",
            ));
        }
        let parent_labels = admitted_work_result
            .get("information_flow_label_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                verr(
                    "outcome_room_delta_label_inheritance_unresolved",
                    "the admitted parent WorkResult has no label set",
                )
            })?;
        let delta_labels = owner_record
            .get("information_flow_label_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                verr(
                    "outcome_room_delta_label_inheritance_unresolved",
                    "OutcomeDelta omits its complete label set",
                )
            })?;
        let parent_set = parent_labels
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        let delta_set = delta_labels
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        if parent_set.len() != parent_labels.len()
            || delta_set.len() != delta_labels.len()
            || !parent_set.is_subset(&delta_set)
        {
            return Err(verr(
                "outcome_room_delta_label_inheritance_substituted",
                "OutcomeDelta's complete information-flow label set must contain every exact parent WorkResult label; it may add resolved labels but cannot drop, replace, or duplicate a parent label",
            ));
        }
    }
    let sequence = room
        .get("latest_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| verr("outcome_room_state_invalid", "room sequence is absent"))?;
    let predecessor = exact_string(
        room,
        "/latest_transition_commitment_ref",
        "outcome_room_state_invalid",
    )?;
    let mut prepared = owner_record.clone();
    prepared["outcome_room_ref"] = json!(room_ref);
    prepared["room_admission"] = Value::Null;
    let mut payload = prepared.clone();
    payload
        .as_object_mut()
        .expect("validated owner record object")
        .remove("room_admission");
    let payload_root = jcs_root("ioi.outcome-room-child-payload-jcs-sha256.v1", &payload)?;
    prepared["room_admission"] = json!({
        "schema_version":BASE_SCHEMA,
        "room_system_id":room["system_id"],
        "outcome_room_ref":room_ref,
        "proposed_or_issued_by_ref":room["system_id"],
        "expected_room_revision":sequence,
        "expected_predecessor_commitment_ref":predecessor,
        "payload_root":payload_root,
        "admission_policy_ref":room["coordination_policy_ref"],
        "admission_decision_ref":Value::Null,
        "admission_receipt_ref":Value::Null,
        "admitted_sequence":Value::Null,
        "resulting_room_revision":Value::Null,
        "resulting_transition_commitment_ref":Value::Null,
        "resulting_room_state_root":Value::Null,
        "resulting_receipt_root":Value::Null,
        "created_at":at,
        "updated_at":Value::Null,
        "admission_status":"proposed",
    });
    Ok((contract_id.to_owned(), prepared))
}

/// Daemon-private M4 seam. The owner-plane constructor supplies a byte-exact candidate that has not
/// yet been published in the global owner registry; this transaction derives every room coordinate,
/// admits only WorkResult/OutcomeDelta, then publishes the owner record and backlinks atomically
/// before removing its durable intent. It is intentionally not routed directly, but it constructs
/// and bounds the exact envelope returned by its two owner HTTP callers before any durable effect.
pub(crate) fn admit_persisted_owner_record(
    data_dir: &str,
    room_ref: &str,
    owner_record: &Value,
    runtime_dependencies: Option<&Value>,
) -> Result<Value, VErr> {
    let _guard = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    refuse_while_any_intent_pending(data_dir)?;
    let _ = super::outcome_room_routes::list_current_rooms_canonical_strict(data_dir)?;
    let fresh = super::outcome_room_routes::resolve_room_strict(data_dir, room_ref)
        .map_err(|error| verr("outcome_room_source_unreadable", error))?
        .ok_or_else(|| {
            verr(
                "outcome_room_stale_child_refused",
                "room is absent before owner-record admission",
            )
        })?;
    if fresh.get("schema_version").and_then(Value::as_str) != Some(ROOM_SCHEMA)
        || fresh.get("status").and_then(Value::as_str) != Some("open")
    {
        return Err(verr(
            "outcome_room_admission_contract_unavailable",
            "owner-record admission requires an open v2 bounded-System room",
        ));
    }
    active_system_binding(
        data_dir,
        fresh
            .get("system_id")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let at = iso_now();
    let (contract_id, prepared) =
        prepare_owner_record_for_room(data_dir, &fresh, owner_record, &at, runtime_dependencies)?;
    let (updated, receipt, object_record, operation) =
        build_child_admission(&fresh, &contract_id, &prepared, &at)?;
    // ORA-8: this check is deliberately after canonical candidate construction but still inside
    // ROOM_MUTATION_LOCK and before `finalize_child` performs its first durable write. Two
    // concurrent exact retries serialize here; a genuinely distinct semantic delta remains free
    // to receive its own plane-minted identity and room successor.
    refuse_terminal_outcome_delta_retry(data_dir, &object_record["admitted_object"])?;
    let owner_convergence = owner_convergence_summary(&updated, &object_record, &receipt)?;
    let admission = json!({
        "outcome_room":updated,
        "admitted_object":object_record["admitted_object"],
        "admission_receipt":receipt,
        "agentgres_operation":operation,
        "owner_convergence":owner_convergence,
    });
    let response = owner_admission_http_response(&contract_id, admission);
    ensure_serialized_body_bound(&response, "outcome_room_response_too_large")?;
    let room_tail = room_ref
        .strip_prefix("outcome-room://")
        .ok_or_else(|| verr("outcome_room_ref_invalid", "room ref is not canonical"))?;
    finalize_child(
        data_dir,
        room_tail,
        &fresh,
        &updated,
        &receipt,
        &object_record,
        &operation,
        runtime_dependencies,
    )?;
    Ok(response)
}

fn goal_run_record_root(record: &Value) -> Result<String, VErr> {
    jcs_root(
        "ioi.goal-run-room-membership-predecessor-jcs-sha256.v1",
        record,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MembershipTransition {
    Attach,
    Detach,
}

impl MembershipTransition {
    fn operation_kind(self) -> &'static str {
        match self {
            Self::Attach => "goal_run_membership_admitted",
            Self::Detach => "goal_run_membership_detached",
        }
    }

    fn receipt_type(self) -> &'static str {
        match self {
            Self::Attach => "goal_run_membership_admission",
            Self::Detach => "goal_run_membership_detachment",
        }
    }

    fn transition_label(self) -> &'static str {
        match self {
            Self::Attach => "attach",
            Self::Detach => "detach",
        }
    }

    fn from_operation(operation: &Value) -> Result<Self, VErr> {
        match operation.get("operation_kind").and_then(Value::as_str) {
            Some("goal_run_membership_admitted") => Ok(Self::Attach),
            Some("goal_run_membership_detached") => Ok(Self::Detach),
            _ => Err(verr(
                "outcome_room_recovery_invalid",
                "membership operation kind is neither attach nor detach",
            )),
        }
    }
}

fn validate_membership_relation(
    room: &Value,
    goal_run: &Value,
    room_ref: &str,
    goal_run_ref: &str,
    transition: MembershipTransition,
) -> Result<(), VErr> {
    let members = room
        .get("member_goal_run_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "outcome_room_membership_state_invalid",
                "room member_goal_run_refs is absent",
            )
        })?;
    let room_memberships = members
        .iter()
        .filter(|value| value.as_str() == Some(goal_run_ref))
        .count();
    let backlink = goal_run
        .get("outcome_room_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    match transition {
        MembershipTransition::Attach => {
            if room_memberships != 0 || backlink.is_some() {
                return Err(verr(
                    "outcome_room_goal_run_already_member",
                    backlink.map_or_else(
                        || "GoalRun is already present in this room member set".to_owned(),
                        |existing| format!("GoalRun already belongs to '{existing}'"),
                    ),
                ));
            }
        }
        MembershipTransition::Detach => {
            if backlink.is_some_and(|existing| existing != room_ref) {
                return Err(verr(
                    "outcome_room_goal_run_wrong_room",
                    format!(
                        "GoalRun backlink names '{}', not the requested room '{room_ref}'",
                        backlink.unwrap_or_default()
                    ),
                ));
            }
            if room_memberships != 1 || backlink != Some(room_ref) {
                return Err(verr(
                    "outcome_room_goal_run_not_member",
                    "detach requires one exact reciprocal room/GoalRun membership",
                ));
            }
        }
    }
    Ok(())
}

fn refuse_detach_with_admitted_goal_children(
    data_dir: &str,
    room: &Value,
    goal_run_ref: &str,
    transition: MembershipTransition,
) -> Result<(), VErr> {
    if transition != MembershipTransition::Detach {
        return Ok(());
    }
    let room_ref = exact_string(room, "/outcome_room_id", "outcome_room_state_invalid")?;
    // Missing required-object truth is uncertainty, not evidence that no dependent child exists.
    // Reconstruct the exact operation/receipt/object/runtime closure before dropping membership.
    let _ = load_projection_snapshot(data_dir, room_ref)?;
    let admitted =
        required_projection_records(data_dir, OBJECT_DOMAIN, room_ref, M4_REPLAY_ENTRY_MAX)?;
    let mut dependent = false;
    for projection in admitted {
        let contract_id = exact_string(
            &projection,
            "/object_contract_id",
            "outcome_room_projection_object_source_unresolved",
        )?;
        if !matches!(
            contract_id,
            "schema://ioi/foundations/work-result/v2" | "schema://ioi/foundations/outcome-delta/v2"
        ) {
            continue;
        }
        let owner_record = projection.get("admitted_object").ok_or_else(|| {
            verr(
                "outcome_room_projection_object_source_unresolved",
                "admitted room child omits its owner record",
            )
        })?;
        canonical_contract(contract_id, owner_record)?;
        super::goalrun_routes::validate_room_owner_runtime_dependencies(
            data_dir,
            room,
            owner_record,
        )
        .map_err(|(code, message)| verr(&code, message))?;
        dependent |= owner_record.get("goal_run_ref").and_then(Value::as_str) == Some(goal_run_ref)
            || owner_record.get("work_subject_ref").and_then(Value::as_str) == Some(goal_run_ref);
    }
    if dependent {
        return Err(verr(
            "outcome_room_goal_run_detach_has_admitted_children",
            "GoalRun membership cannot detach while admitted room WorkResult or OutcomeDelta truth depends on that reciprocal edge.",
        ));
    }
    Ok(())
}

fn refuse_attach_with_preexisting_goal_truth(
    data_dir: &str,
    goal_run_ref: &str,
    transition: MembershipTransition,
) -> Result<(), VErr> {
    if transition != MembershipTransition::Attach {
        return Ok(());
    }
    let results = super::work_result_routes::list_work_results_strict(data_dir).map_err(|_| {
        verr(
            "outcome_room_membership_work_truth_unreadable",
            "GoalRun membership cannot resolve the complete WorkResult registry.",
        )
    })?;
    let result_refs = results
        .iter()
        .filter(|result| {
            // The generic v1 route materializes `goal_run_ref: null` beside its required
            // `goal_ref`.  A present JSON null is not an owner identity and must not shadow the
            // canonical generic goal ref when membership checks for pre-existing roomless truth.
            result
                .get("goal_run_ref")
                .and_then(Value::as_str)
                .or_else(|| result.get("goal_ref").and_then(Value::as_str))
                == Some(goal_run_ref)
        })
        .filter_map(|result| result.get("work_result_id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let deltas = super::work_result_routes::list_outcome_deltas_strict(data_dir).map_err(|_| {
        verr(
            "outcome_room_membership_work_truth_unreadable",
            "GoalRun membership cannot resolve the complete OutcomeDelta registry.",
        )
    })?;
    let delta_exists = deltas.iter().any(|delta| {
        delta.get("work_subject_ref").and_then(Value::as_str) == Some(goal_run_ref)
            || delta
                .get("proposed_by_ref")
                .and_then(Value::as_str)
                .is_some_and(|reference| result_refs.contains(reference))
    });
    if !result_refs.is_empty() || delta_exists {
        return Err(verr(
            "outcome_room_goal_run_attach_preexisting_work_truth",
            "GoalRun membership cannot attach after roomless WorkResult or OutcomeDelta truth exists; no parallel result history may enter the bounded aggregate.",
        ));
    }
    Ok(())
}

fn build_membership_transition(
    room: &Value,
    goal_run: &Value,
    at: &str,
    transition: MembershipTransition,
) -> Result<(Value, Value, Value), VErr> {
    let sequence = next_room_sequence(room)?;
    let goal_run_ref = exact_string(
        goal_run,
        "/goal_ref",
        "outcome_room_goal_run_identity_conflict",
    )?;
    let expected_goal_run_root = goal_run_record_root(goal_run)?;
    let mut resulting_goal_run = goal_run.clone();
    resulting_goal_run["outcome_room_ref"] = match transition {
        MembershipTransition::Attach => room["outcome_room_id"].clone(),
        MembershipTransition::Detach => Value::Null,
    };
    resulting_goal_run["updated_at"] = json!(at);
    let resulting_goal_run_root = goal_run_record_root(&resulting_goal_run)?;
    let prior_sequence = sequence - 1;
    let transition_hash = jcs_root(
        "ioi.outcome-room-goal-run-membership-transition-jcs-sha256.v2",
        &json!({
            "outcome_room_ref":room["outcome_room_id"],
            "system_id":room["system_id"],
            "sequence":sequence,
            "predecessor":room["latest_transition_commitment_ref"],
            "membership_transition":transition.transition_label(),
            "goal_run_ref":goal_run_ref,
            "expected_goal_run_record_root":expected_goal_run_root,
            "resulting_goal_run_record_root":resulting_goal_run_root,
        }),
    )?;
    let room_tail = room["outcome_room_id"]
        .as_str()
        .and_then(|value| value.strip_prefix("outcome-room://"))
        .ok_or_else(|| verr("outcome_room_state_invalid", "room identity is invalid"))?;
    let transition_ref = format!(
        "commitment://ioi/outcome-room/{room_tail}/sequence/{sequence}/{}",
        transition_hash.strip_prefix("sha256:").unwrap_or_default()
    );
    let receipt_ref = format!("receipt://outcome-room/{room_tail}/sequence/{sequence}");
    let mut updated = room.clone();
    updated["latest_sequence"] = json!(sequence);
    updated["latest_transition_commitment_ref"] = json!(transition_ref);
    match transition {
        MembershipTransition::Attach => {
            append_unique(&mut updated, "member_goal_run_refs", json!(goal_run_ref))?;
        }
        MembershipTransition::Detach => {
            let members = updated
                .get_mut("member_goal_run_refs")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| {
                    verr(
                        "outcome_room_membership_state_invalid",
                        "room member_goal_run_refs is absent",
                    )
                })?;
            let before = members.len();
            members.retain(|value| value.as_str() != Some(goal_run_ref));
            if before.saturating_sub(members.len()) != 1 {
                return Err(verr(
                    "outcome_room_goal_run_not_member",
                    "detach requires one exact room-side membership",
                ));
            }
        }
    }
    append_unique(
        &mut updated,
        "admission_and_replay_refs",
        json!(receipt_ref),
    )?;
    updated["room_state_root"] = json!(state_root(&updated)?);
    let receipt = json!({
        "schema_version":"ioi.outcome-room-admission-receipt.v2",
        "receipt_ref":receipt_ref,
        "receipt_root":Value::Null,
        "receipt_type":transition.receipt_type(),
        "system_id":room["system_id"],
        "outcome_room_ref":room["outcome_room_id"],
        "subject_refs":[goal_run_ref],
        "expected_room_revision":prior_sequence,
        "resulting_room_revision":sequence,
        "sequence":sequence,
        "expected_predecessor_commitment_ref":room["latest_transition_commitment_ref"],
        "resulting_transition_commitment_ref":updated["latest_transition_commitment_ref"],
        "resulting_room_state_root":updated["room_state_root"],
        "expected_goal_run_record_root":expected_goal_run_root,
        "resulting_goal_run_record_root":resulting_goal_run_root,
        "status":"admitted",
        "at":at,
    });
    let (_, receipt) = rooted_record(RECEIPT_DOMAIN, "orrc_", "receipt_root", receipt)?;
    updated["room_receipt_root"] = receipt["receipt_root"].clone();
    validate_current_room_contract(&updated)?;
    let operation = json!({
        "schema_version":"ioi.outcome-room-transition-operation.v2",
        "operation_root":Value::Null,
        "operation_kind":transition.operation_kind(),
        "outcome_room_ref":room["outcome_room_id"],
        "system_id":room["system_id"],
        "sequence":sequence,
        "expected_predecessor_commitment_ref":room["latest_transition_commitment_ref"],
        "resulting_transition_commitment_ref":updated["latest_transition_commitment_ref"],
        "resulting_room_state_root":updated["room_state_root"],
        "resulting_room":updated,
        "expected_goal_run_record_root":expected_goal_run_root,
        "resulting_goal_run_record_root":resulting_goal_run_root,
        "resulting_goal_run":resulting_goal_run,
        "object_contract_id":Value::Null,
        "object_ref":goal_run_ref,
        "object_root":Value::Null,
        "receipt_ref":receipt["receipt_ref"],
        "receipt_root":receipt["receipt_root"],
        "at":at,
    });
    let (_, operation) = rooted_record(
        TRANSITION_OPERATION_DOMAIN,
        "orto_",
        "operation_root",
        operation,
    )?;
    Ok((operation["resulting_room"].clone(), receipt, operation))
}

fn stamp_goal_run_membership(
    data_dir: &str,
    goal_run_id: &str,
    goal_run_ref: &str,
    room_ref: &str,
    expected_root: &str,
    resulting_root: &str,
    at: &str,
    transition: MembershipTransition,
) -> Result<(), VErr> {
    let result = super::goalrun_routes::update_goal_run_guarded(
        data_dir,
        goal_run_id,
        |fresh| {
            if fresh.get("goal_ref").and_then(Value::as_str) != Some(goal_run_ref) {
                return Err((
                    "outcome_room_goal_run_identity_conflict".to_owned(),
                    "GoalRun file identity is detached from goal_ref".to_owned(),
                ));
            }
            let backlink = fresh
                .get("outcome_room_ref")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty());
            match transition {
                MembershipTransition::Attach => match backlink {
                    Some(existing) if existing == room_ref => {
                        let actual = goal_run_record_root(fresh)
                            .map_err(|(code, message)| (code, message))?;
                        if actual != resulting_root {
                            return Err((
                                "outcome_room_goal_run_resulting_head_conflict".to_owned(),
                                "GoalRun carries the room ref but not the sealed resulting root"
                                    .to_owned(),
                            ));
                        }
                        return Ok(());
                    }
                    Some(existing) => {
                        return Err((
                            "outcome_room_goal_run_already_member".to_owned(),
                            format!("GoalRun already belongs to '{existing}'"),
                        ))
                    }
                    None => {}
                },
                MembershipTransition::Detach => match backlink {
                    None => {
                        let actual = goal_run_record_root(fresh)
                            .map_err(|(code, message)| (code, message))?;
                        if actual != resulting_root {
                            return Err((
                                "outcome_room_goal_run_resulting_head_conflict".to_owned(),
                                "GoalRun cleared its room ref but not at the sealed resulting root"
                                    .to_owned(),
                            ));
                        }
                        return Ok(());
                    }
                    Some(existing) if existing == room_ref => {}
                    Some(existing) => {
                        return Err((
                            "outcome_room_goal_run_wrong_room".to_owned(),
                            format!(
                                "GoalRun backlink names '{existing}', not the detaching room '{room_ref}'"
                            ),
                        ))
                    }
                },
            }
            let actual = goal_run_record_root(fresh).map_err(|(code, message)| (code, message))?;
            if actual != expected_root {
                return Err((
                    "outcome_room_goal_run_head_conflict".to_owned(),
                    "GoalRun changed after the caller reviewed its reciprocal attachment"
                        .to_owned(),
                ));
            }
            Ok(())
        },
        |object| {
            object.insert(
                "outcome_room_ref".to_owned(),
                match transition {
                    MembershipTransition::Attach => json!(room_ref),
                    MembershipTransition::Detach => Value::Null,
                },
            );
            object.insert("updated_at".to_owned(), json!(at));
        },
    )
    .map_err(|(code, message)| verr(&code, message))?;
    let result = super::goalrun_routes::require_durable_mutation(
        result,
        "outcome_room_goal_membership_durability_unconfirmed",
        "The reciprocal GoalRun room membership",
    )
    .map_err(|(code, message)| verr(&code, message))?;
    match transition {
        MembershipTransition::Attach
            if result.get("outcome_room_ref").and_then(Value::as_str) != Some(room_ref) =>
        {
            return Err(verr(
                "outcome_room_goal_run_stamp_failed",
                "GoalRun mutation returned without the reciprocal room ref",
            ));
        }
        MembershipTransition::Detach
            if result
                .get("outcome_room_ref")
                .is_some_and(|value| !value.is_null()) =>
        {
            return Err(verr(
                "outcome_room_goal_run_detach_failed",
                "GoalRun mutation returned with a residual room ref",
            ));
        }
        _ => {}
    }
    let actual = goal_run_record_root(&result).map_err(|(code, message)| verr(&code, message))?;
    if actual != resulting_root {
        return Err(verr(
            "outcome_room_goal_run_resulting_head_conflict",
            "GoalRun mutation did not produce the sealed resulting root",
        ));
    }
    Ok(())
}

fn finalize_membership(
    data_dir: &str,
    room_tail: &str,
    prior_room: &Value,
    prior_goal_run: &Value,
    room: &Value,
    receipt: &Value,
    operation: &Value,
    goal_run_id: &str,
    goal_run_ref: &str,
    expected_goal_run_root: &str,
    resulting_goal_run_root: &str,
) -> Result<(), VErr> {
    let operation_key = key_for(operation, "operation_root", "orto_")?;
    let receipt_key = key_for(receipt, "receipt_root", "orrc_")?;
    let intent = json!({
        "schema_version":"ioi.outcome-room-membership-admission-intent.v1",
        "room_tail":room_tail,
        "prior_room_state_root":prior_room["room_state_root"],
        "prior_room":prior_room,
        "prior_goal_run":prior_goal_run,
        "room":room,
        "receipt":receipt,
        "operation":operation,
        "goal_run_id":goal_run_id,
        "goal_run_ref":goal_run_ref,
        "expected_goal_run_record_root":expected_goal_run_root,
        "resulting_goal_run_record_root":resulting_goal_run_root,
        "at":operation["at"],
    });
    persist_local(MEMBERSHIP_INTENT_DIR, data_dir, &operation_key, &intent)?;
    if std::env::var("IOI_TEST_FORCE_OUTCOME_ROOM_MEMBERSHIP_AFTER_INTENT")
        .ok()
        .as_deref()
        == Some("1")
    {
        return Err(verr(
            "outcome_room_membership_pending_recovery",
            "test-forced interruption after membership intent persistence and before any membership admission side effect",
        ));
    }
    if let Err(error) = reserve_exact_room_successor(data_dir, operation) {
        if error.0 == "outcome_room_head_conflict" {
            remove_intent(data_dir, MEMBERSHIP_INTENT_DIR, &operation_key)?;
        }
        return Err(error);
    }
    admit_required(
        TRANSITION_OPERATION_DOMAIN,
        data_dir,
        &operation_key,
        operation,
    )?;
    admit_required(RECEIPT_DOMAIN, data_dir, &receipt_key, receipt)?;
    persist_local(RECEIPT_DIR, data_dir, &receipt_key, receipt)?;
    let transition = MembershipTransition::from_operation(operation)?;
    stamp_goal_run_membership(
        data_dir,
        goal_run_id,
        goal_run_ref,
        room["outcome_room_id"].as_str().unwrap_or_default(),
        expected_goal_run_root,
        resulting_goal_run_root,
        operation["at"].as_str().unwrap_or_default(),
        transition,
    )?;
    if std::env::var("IOI_TEST_FORCE_OUTCOME_ROOM_MEMBERSHIP_AFTER_GOAL_RUN")
        .ok()
        .as_deref()
        == Some("1")
    {
        return Err(verr(
            "outcome_room_membership_pending_recovery",
            "test-forced interruption after reciprocal GoalRun stamp and before room projection",
        ));
    }
    persist_local(ROOM_DIR, data_dir, room_tail, room)?;
    remove_intent(data_dir, MEMBERSHIP_INTENT_DIR, &operation_key)
}

async fn handle_goal_run_membership(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
    transition: MembershipTransition,
) -> (StatusCode, Json<Value>) {
    // Resolve authentication before touching the room registry, pending-intent families, or
    // GoalRun owner truth. Existing, missing, malformed, and recovery-pending rooms must be
    // indistinguishable to an anonymous or otherwise unauthenticated exposed caller.
    let principal_ref = match request_principal(&state.data_dir, &headers) {
        Ok(principal_ref) => principal_ref,
        Err(error) => return classify(error),
    };
    let room_ref = format!("outcome-room://{id}");
    let observed_room =
        match super::outcome_room_routes::resolve_room_strict(&state.data_dir, &room_ref) {
            Ok(Some(room)) if room.get("status").and_then(Value::as_str) == Some("open") => room,
            Ok(_) => {
                if let Some(response) = managed_missing_room_refusal(&state.data_dir, &headers) {
                    return response;
                }
                return classify(verr("outcome_room_not_found", "open room is absent"));
            }
            Err(message) => {
                return room_source_refusal(
                    &state.data_dir,
                    &headers,
                    verr("outcome_room_source_unreadable", message),
                )
            }
        };
    if observed_room.get("schema_version").and_then(Value::as_str) != Some(ROOM_SCHEMA) {
        return classify(verr(
            "outcome_room_membership_contract_unavailable",
            format!(
                "current reciprocal {} requires a v2 bounded-System room",
                transition.transition_label()
            ),
        ));
    }
    if let Err(error) = validate_current_room_contract(&observed_room) {
        return classify(error);
    }
    if let Err(error) = authorize_resolved_room_principal(&principal_ref, &observed_room) {
        return classify(error);
    }
    let goal_run_ref = match exact_string(&body, "/goal_run_ref", "outcome_room_goal_run_required")
    {
        Ok(value) if super::outcome_room_routes::ref_scheme_ok(value, &["goal"]) => value,
        Ok(_) => {
            return classify(verr(
                "outcome_room_goal_run_ref_invalid",
                "goal_run_ref must be goal://...",
            ))
        }
        Err(error) => return classify(error),
    };
    let goal_run_id = goal_run_ref.strip_prefix("goal://").unwrap_or_default();
    let expected_goal_root = match exact_string(
        &body,
        "/expected_goal_run_record_root",
        "outcome_room_goal_run_head_required",
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let expected_room_revision = body.get("expected_revision").and_then(Value::as_u64);
    if expected_room_revision != observed_room.get("latest_sequence").and_then(Value::as_u64) {
        return classify(verr(
            "outcome_room_revision_conflict",
            "expected_revision does not match the room's exact Agentgres-backed head",
        ));
    }
    let _guard = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(error) = refuse_while_any_intent_pending(&state.data_dir) {
        return room_source_refusal(&state.data_dir, &headers, error);
    }
    if let Err(error) =
        super::outcome_room_routes::list_current_rooms_canonical_strict(&state.data_dir)
    {
        return classify(error);
    }
    let fresh_room =
        match super::outcome_room_routes::resolve_room_strict(&state.data_dir, &room_ref) {
            Ok(Some(room)) if room.get("status").and_then(Value::as_str) == Some("open") => room,
            Ok(_) => {
                return classify(verr(
                    "outcome_room_stale_membership_refused",
                    "room became unavailable",
                ))
            }
            Err(message) => {
                return room_source_refusal(
                    &state.data_dir,
                    &headers,
                    verr("outcome_room_source_unreadable", message),
                )
            }
        };
    if fresh_room.get("room_state_root") != observed_room.get("room_state_root") {
        return classify(verr(
            "outcome_room_stale_membership_refused",
            "room head changed",
        ));
    }
    // The room's durable objective is the only GoalRun this M4 lane may inspect.  Reject an
    // arbitrary requested ref before enumerating GoalRun truth so an authorized room owner
    // cannot use membership as a missing-versus-existing GoalRun oracle.  Dependency loss for
    // the room's exact objective remains inspectable to that owner below.
    if goal_run_ref
        != fresh_room
            .get("objective_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
    {
        return classify(verr(
            "outcome_room_collective_goal_run_required",
            "M4 membership admits only the room's exact owner-bound collective objective GoalRun",
        ));
    }
    let goal_runs = match strict_goal_run_census(&state.data_dir) {
        Ok(records) => records,
        Err(error) => return classify(error),
    };
    let Some(goal_run) = goal_runs
        .into_iter()
        .find(|record| record.get("goal_run_id").and_then(Value::as_str) == Some(goal_run_id))
    else {
        return classify(verr("outcome_room_goal_run_not_found", "GoalRun is absent"));
    };
    if goal_run.get("owner_ref") != fresh_room.get("owner_or_sponsor_ref") {
        return classify(verr(
            "outcome_room_collective_goal_run_required",
            "M4 membership admits only the room's exact owner-bound collective objective GoalRun",
        ));
    }
    let system_id = fresh_room
        .get("system_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let system_graph = match active_system_binding(&state.data_dir, system_id) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let collective =
        match collective_goal_run_for_room(&state.data_dir, goal_run_ref, system_id, &system_graph)
        {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    if collective != goal_run {
        return classify(verr(
            "outcome_room_collective_goal_run_head_conflict",
            "collective GoalRun changed during membership resolution",
        ));
    }
    if let Err(error) =
        validate_membership_relation(&fresh_room, &goal_run, &room_ref, goal_run_ref, transition)
    {
        return classify(error);
    }
    if let Err(error) =
        refuse_attach_with_preexisting_goal_truth(&state.data_dir, goal_run_ref, transition)
    {
        return classify(error);
    }
    if let Err(error) = refuse_detach_with_admitted_goal_children(
        &state.data_dir,
        &fresh_room,
        goal_run_ref,
        transition,
    ) {
        return classify(error);
    }
    let actual_goal_root = match goal_run_record_root(&goal_run) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if actual_goal_root != expected_goal_root {
        return classify(verr(
            "outcome_room_goal_run_head_conflict",
            "expected GoalRun root does not match current durable truth",
        ));
    }
    let at = iso_now();
    let (updated, receipt, operation) =
        match build_membership_transition(&fresh_room, &goal_run, &at, transition) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    let resulting_goal_root = match exact_string(
        &operation,
        "/resulting_goal_run_record_root",
        "outcome_room_goal_run_resulting_head_required",
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let response = json!({
        "outcome_room":updated.clone(),
        "outcome_room_receipt":receipt.clone(),
        "agentgres_operation":operation.clone(),
        "goal_run":operation["resulting_goal_run"].clone(),
        "membership_transition":transition.transition_label(),
        "goal_run_stamped":{
            "goal_run_ref":goal_run_ref,
            "outcome_room_ref":operation["resulting_goal_run"]["outcome_room_ref"].clone(),
        },
    });
    if let Err(error) = ensure_serialized_body_bound(&response, "outcome_room_response_too_large") {
        return classify(error);
    }
    if let Err(error) = finalize_membership(
        &state.data_dir,
        &id,
        &fresh_room,
        &goal_run,
        &updated,
        &receipt,
        &operation,
        goal_run_id,
        goal_run_ref,
        expected_goal_root,
        resulting_goal_root,
    ) {
        return classify(error);
    }
    (StatusCode::OK, Json(response))
}

pub(crate) async fn handle_attach_goal_run(
    state: State<Arc<DaemonState>>,
    headers: HeaderMap,
    id: AxumPath<String>,
    body: Json<Value>,
) -> (StatusCode, Json<Value>) {
    handle_goal_run_membership(state, headers, id, body, MembershipTransition::Attach).await
}

pub(crate) async fn handle_detach_goal_run(
    state: State<Arc<DaemonState>>,
    headers: HeaderMap,
    id: AxumPath<String>,
    body: Json<Value>,
) -> (StatusCode, Json<Value>) {
    handle_goal_run_membership(state, headers, id, body, MembershipTransition::Detach).await
}

fn safe_replay_operation(operation: &Value) -> Value {
    let mut safe = json!({
        "operation_root":operation["operation_root"],
        "operation_kind":operation["operation_kind"],
        "outcome_room_ref":operation["outcome_room_ref"],
        "system_id":operation["system_id"],
        "sequence":operation["sequence"],
        "expected_predecessor_commitment_ref":operation["expected_predecessor_commitment_ref"],
        "resulting_transition_commitment_ref":operation["resulting_transition_commitment_ref"],
        "resulting_room_state_root":operation["resulting_room_state_root"],
        "object_contract_id":operation.get("object_contract_id").cloned().unwrap_or(Value::Null),
        "object_ref":operation.get("object_ref").cloned().unwrap_or(Value::Null),
        "object_root":operation.get("object_root").cloned().unwrap_or(Value::Null),
        "receipt_ref":operation["receipt_ref"],
        "receipt_root":operation["receipt_root"],
        "at":operation["at"],
    });
    for field in [
        "system_chain_root",
        "system_state_root",
        "collective_goal_run_ref",
        "collective_path_decision_ref",
        "request_root",
    ] {
        if let Some(value) = operation.get(field) {
            safe[field] = value.clone();
        }
    }
    safe
}

pub(crate) async fn handle_replay(
    AxumPath(id): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    // Authentication precedes every room-store read. Missing, malformed, pending, and existing
    // room state must be indistinguishable to an exposed anonymous caller.
    let principal_ref = match request_principal(&state.data_dir, &headers) {
        Ok(principal_ref) => principal_ref,
        Err(error) => return classify(error),
    };
    let _guard = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let room_ref = format!("outcome-room://{id}");
    let room = match super::outcome_room_routes::resolve_room_strict(&state.data_dir, &room_ref) {
        Ok(Some(room)) => room,
        Ok(None) => {
            if let Some(response) = managed_missing_room_refusal(&state.data_dir, &headers) {
                return response;
            }
            return classify(verr("outcome_room_not_found", "room is absent"));
        }
        Err(error) => {
            return room_source_refusal(
                &state.data_dir,
                &headers,
                verr("outcome_room_source_unreadable", error),
            )
        }
    };
    if let Err(error) =
        authorize_generation_dispatch_if_managed(&state.data_dir, &headers, &principal_ref, &room)
    {
        return classify(error);
    }
    if let Some(response) = refuse_predecessor_projection(&room) {
        return response;
    }
    if let Err(error) = authorize_resolved_room_principal(&principal_ref, &room) {
        return classify(error);
    }
    if let Err(error) = refuse_while_any_intent_pending(&state.data_dir) {
        return room_source_refusal(&state.data_dir, &headers, error);
    }
    // Replay is an owner projection of the current bounded aggregate, not permission to expose
    // an operation-only history after an admitted child has lost its exact runtime dependencies.
    // Re-run the same object/admission/byte/label census used by graph, discussion, and product
    // reads before returning even the payload-free replay projection.
    if let Err(error) = load_projection_snapshot(&state.data_dir, &room_ref) {
        return classify(error);
    }
    let mut operations = match required_projection_records(
        &state.data_dir,
        ADMISSION_OPERATION_DOMAIN,
        &room_ref,
        1,
    ) {
        Ok(values) => values,
        Err(error) => return classify(error),
    };
    let transitions = match required_projection_records(
        &state.data_dir,
        TRANSITION_OPERATION_DOMAIN,
        &room_ref,
        M4_TRANSITION_ENTRY_MAX,
    ) {
        Ok(values) => values,
        Err(error) => return classify(error),
    };
    operations.extend(transitions);
    if operations.len() > M4_REPLAY_ENTRY_MAX {
        return classify(verr(
            "outcome_room_projection_source_unavailable",
            format!(
                "room replay contains {} operations; hosted M4 permits at most {M4_REPLAY_ENTRY_MAX}",
                operations.len()
            ),
        ));
    }
    operations.sort_by_key(|value| {
        value
            .get("sequence")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX)
    });
    let latest = room["latest_sequence"].as_u64().unwrap_or(u64::MAX);
    if operations.len() != latest.saturating_add(1) as usize
        || operations.iter().enumerate().any(|(index, value)| {
            value.get("sequence").and_then(Value::as_u64) != Some(index as u64)
        })
    {
        return classify(verr(
            "outcome_room_replay_discontinuous",
            "Agentgres operation sequence does not reconstruct the visible room head",
        ));
    }
    for pair in operations.windows(2) {
        if pair[1].get("expected_predecessor_commitment_ref")
            != pair[0].get("resulting_transition_commitment_ref")
        {
            return classify(verr(
                "outcome_room_replay_discontinuous",
                "operation predecessor commitment does not match the prior head",
            ));
        }
    }
    if operations
        .last()
        .and_then(|value| value.get("resulting_room_state_root"))
        != room.get("room_state_root")
        || operations
            .last()
            .and_then(|value| value.get("resulting_transition_commitment_ref"))
            != room.get("latest_transition_commitment_ref")
    {
        return classify(verr(
            "outcome_room_replay_head_mismatch",
            "reconstructed Agentgres head differs from the room projection",
        ));
    }
    let response = json!({
        "schema_version":"ioi.outcome-room-replay-projection.v2",
        "outcome_room_ref":room_ref,
        "system_id":room["system_id"],
        "latest_sequence":latest,
        "latest_transition_commitment_ref":room["latest_transition_commitment_ref"],
        "room_state_root":room["room_state_root"],
        "room_receipt_root":room["room_receipt_root"],
        "operations":operations.iter().map(safe_replay_operation).collect::<Vec<_>>(),
        "payload_bytes_exported":false,
        "runtimeTruthSource":"agentgres-required-admission-projection",
    });
    if let Err(error) =
        ensure_serialized_body_bound(&response, "outcome_room_projection_response_too_large")
    {
        return classify(error);
    }
    if let Err(error) = confirm_room_read_stable(&state.data_dir, &room_ref, &room) {
        return classify(error);
    }
    (StatusCode::OK, Json(response))
}

#[derive(Default)]
struct ProjectionRefs {
    participant_refs: BTreeSet<String>,
    frontier_item_refs: BTreeSet<String>,
    work_claim_refs: BTreeSet<String>,
    attempt_refs: BTreeSet<String>,
    finding_refs: BTreeSet<String>,
    verifier_challenge_refs: BTreeSet<String>,
    work_result_refs: BTreeSet<String>,
    outcome_delta_refs: BTreeSet<String>,
    information_flow_label_refs: BTreeSet<String>,
    work_result_summaries: Vec<Value>,
    outcome_delta_summaries: Vec<Value>,
}

struct ProjectionSnapshot {
    room: Value,
    member_goal_run_refs: BTreeSet<String>,
    refs: ProjectionRefs,
    source_admission_receipt_refs: Vec<String>,
    permitted_subject_refs: BTreeSet<String>,
}

fn bounded_ref_set(value: &Value, field: &str, code: &str) -> Result<BTreeSet<String>, VErr> {
    let entries = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| verr(code, format!("'{field}' must be a ref array")))?;
    if entries.len() > M4_ROOM_REF_SET_MAX {
        return Err(verr(
            code,
            format!(
                "'{field}' contains {} refs; hosted M4 permits at most {M4_ROOM_REF_SET_MAX}",
                entries.len()
            ),
        ));
    }
    let mut refs = BTreeSet::new();
    for entry in entries {
        let reference = entry.as_str().filter(|reference| {
            !reference.is_empty()
                && reference.len() <= 500
                && reference.contains("://")
                && !reference.chars().any(char::is_whitespace)
        });
        let Some(reference) = reference else {
            return Err(verr(code, format!("'{field}' contains an invalid ref")));
        };
        if !refs.insert(reference.to_owned()) {
            return Err(verr(code, format!("'{field}' contains a duplicate ref")));
        }
    }
    Ok(refs)
}

fn ensure_projection_cardinality(
    actual: usize,
    maximum: usize,
    collection: &str,
) -> Result<(), VErr> {
    if actual > maximum {
        return Err(verr(
            "outcome_room_projection_source_unavailable",
            format!("{collection} contains {actual} entries; hosted M4 permits at most {maximum}"),
        ));
    }
    Ok(())
}

fn strict_goal_run_census(data_dir: &str) -> Result<Vec<Value>, VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, "goal-runs") {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(verr(
                "outcome_room_projection_goal_runs_unreadable",
                format!("GoalRun registry cannot be pinned ({error})"),
            ))
        }
    };
    let names = super::durable_fs::enumerate_pinned(&directory).map_err(|error| {
        verr(
            "outcome_room_projection_goal_runs_unreadable",
            format!("GoalRun registry cannot be enumerated ({error})"),
        )
    })?;
    ensure_projection_cardinality(names.len(), M4_REQUIRED_DOMAIN_MAX, "GoalRun source census")?;
    let mut records = Vec::new();
    for name in names {
        let Some(tail) = name.strip_suffix(".json") else {
            return Err(verr(
                "outcome_room_projection_goal_runs_unreadable",
                format!(
                    "GoalRun registry contains non-record entry '{name}'; partial truth is refused"
                ),
            ));
        };
        if tail.is_empty()
            || tail.len() > 160
            || !tail.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
        {
            return Err(verr(
                "outcome_room_projection_goal_runs_unreadable",
                format!("GoalRun slot '{name}' has a non-canonical name"),
            ));
        }
        let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
            Ok(Some((_file, bytes))) => bytes,
            Ok(None) => {
                return Err(verr(
                    "outcome_room_projection_goal_runs_unreadable",
                    format!("GoalRun slot '{name}' vanished during projection"),
                ))
            }
            Err(error) => {
                return Err(verr(
                    "outcome_room_projection_goal_runs_unreadable",
                    format!("GoalRun slot '{name}' is unreadable ({error})"),
                ))
            }
        };
        let record: Value = serde_json::from_slice(&bytes).map_err(|error| {
            verr(
                "outcome_room_projection_goal_runs_unreadable",
                format!("GoalRun slot '{name}' is malformed ({error})"),
            )
        })?;
        if record.get("goal_run_id").and_then(Value::as_str) != Some(tail)
            || record.get("goal_ref").and_then(Value::as_str)
                != Some(format!("goal://{tail}").as_str())
        {
            return Err(verr(
                "outcome_room_projection_goal_runs_unreadable",
                format!("GoalRun slot '{name}' fails identity binding"),
            ));
        }
        records.push(record);
    }
    Ok(records)
}

fn required_projection_records(
    data_dir: &str,
    family: &str,
    room_ref: &str,
    per_room_max: usize,
) -> Result<Vec<Value>, VErr> {
    let records = super::substrate_store::read_required_all(data_dir, family).map_err(|error| {
        verr(
            "outcome_room_projection_source_unreadable",
            format!("Agentgres family '{family}' cannot be projected ({error})"),
        )
    })?;
    if records.len() > M4_REQUIRED_DOMAIN_MAX {
        return Err(verr(
            "outcome_room_projection_source_unavailable",
            format!(
                "Agentgres family '{family}' contains {} records; hosted M4 permits at most {M4_REQUIRED_DOMAIN_MAX}",
                records.len()
            ),
        ));
    }
    let projected = records
        .into_iter()
        .filter(|record| record.get("outcome_room_ref").and_then(Value::as_str) == Some(room_ref))
        .collect::<Vec<_>>();
    if projected.len() > per_room_max {
        return Err(verr(
            "outcome_room_projection_source_unavailable",
            format!(
                "Agentgres family '{family}' contains {} records for '{room_ref}'; hosted M4 permits at most {per_room_max}",
                projected.len()
            ),
        ));
    }
    Ok(projected)
}

fn verify_projection_operation_chain(
    room: &Value,
    mut operations: Vec<(&'static str, Value)>,
) -> Result<Vec<Value>, VErr> {
    let room_ref = exact_string(
        room,
        "/outcome_room_id",
        "outcome_room_projection_source_unresolved",
    )?;
    let system_id = exact_string(
        room,
        "/system_id",
        "outcome_room_projection_source_unresolved",
    )?;
    let latest = room
        .get("latest_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            verr(
                "outcome_room_projection_source_unresolved",
                "room latest_sequence is absent",
            )
        })?;
    if operations.len() > M4_REPLAY_ENTRY_MAX {
        return Err(verr(
            "outcome_room_projection_source_unavailable",
            format!(
                "room operation census contains {} records; hosted M4 permits at most {M4_REPLAY_ENTRY_MAX}",
                operations.len()
            ),
        ));
    }
    operations.sort_by_key(|(_, operation)| {
        operation
            .get("sequence")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX)
    });
    if operations.len() != latest.saturating_add(1) as usize {
        return Err(verr(
            "outcome_room_projection_source_unresolved",
            "Agentgres operation census does not exactly cover the visible room revision",
        ));
    }
    let mut verified: Vec<Value> = Vec::with_capacity(operations.len());
    for (index, (family, operation)) in operations.into_iter().enumerate() {
        verify_rooted_record(family, "operation_root", &operation).map_err(|_| {
            verr(
                "outcome_room_projection_source_unresolved",
                format!("Agentgres operation {index} has an invalid root"),
            )
        })?;
        if operation.get("sequence").and_then(Value::as_u64) != Some(index as u64)
            || operation.get("outcome_room_ref").and_then(Value::as_str) != Some(room_ref)
            || operation.get("system_id").and_then(Value::as_str) != Some(system_id)
        {
            return Err(verr(
                "outcome_room_projection_source_unresolved",
                format!("Agentgres operation {index} is detached from the room"),
            ));
        }
        if index > 0
            && operation.get("expected_predecessor_commitment_ref")
                != verified[index - 1].get("resulting_transition_commitment_ref")
        {
            return Err(verr(
                "outcome_room_projection_source_unresolved",
                format!("Agentgres operation {index} does not extend the prior head"),
            ));
        }
        let resulting_room = operation.get("resulting_room").ok_or_else(|| {
            verr(
                "outcome_room_projection_source_unresolved",
                format!("Agentgres operation {index} omits its resulting room"),
            )
        })?;
        validate_current_room_contract(resulting_room).map_err(|_| {
            verr(
                "outcome_room_projection_source_unresolved",
                format!("Agentgres operation {index} carries an invalid room"),
            )
        })?;
        let recomputed = state_root(resulting_room)?;
        if resulting_room
            .get("latest_sequence")
            .and_then(Value::as_u64)
            != Some(index as u64)
            || resulting_room
                .get("room_state_root")
                .and_then(Value::as_str)
                != Some(recomputed.as_str())
            || operation.get("resulting_room_state_root") != resulting_room.get("room_state_root")
            || operation.get("resulting_transition_commitment_ref")
                != resulting_room.get("latest_transition_commitment_ref")
        {
            return Err(verr(
                "outcome_room_projection_source_unresolved",
                format!("Agentgres operation {index} does not bind its resulting room root"),
            ));
        }
        verified.push(operation);
    }
    if verified
        .last()
        .and_then(|operation| operation.get("resulting_room"))
        != Some(room)
    {
        return Err(verr(
            "outcome_room_projection_source_stale",
            "local room projection is not the exact current Agentgres head",
        ));
    }
    Ok(verified)
}

fn verify_projection_receipts(
    room: &Value,
    operations: &[Value],
    receipts: Vec<Value>,
) -> Result<Vec<String>, VErr> {
    let room_ref = room["outcome_room_id"].as_str().unwrap_or_default();
    let system_id = room["system_id"].as_str().unwrap_or_default();
    let latest = room["latest_sequence"].as_u64().unwrap_or(u64::MAX);
    if receipts.len() > M4_REPLAY_ENTRY_MAX {
        return Err(verr(
            "outcome_room_projection_source_unavailable",
            format!(
                "room receipt census contains {} records; hosted M4 permits at most {M4_REPLAY_ENTRY_MAX}",
                receipts.len()
            ),
        ));
    }
    let mut by_sequence = BTreeMap::new();
    for receipt in receipts {
        verify_rooted_record(RECEIPT_DOMAIN, "receipt_root", &receipt).map_err(|_| {
            verr(
                "outcome_room_projection_receipt_source_unresolved",
                "an Agentgres room receipt has an invalid root",
            )
        })?;
        let sequence = receipt
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                verr(
                    "outcome_room_projection_receipt_source_unresolved",
                    "an Agentgres room receipt omits its sequence",
                )
            })?;
        if receipt.get("outcome_room_ref").and_then(Value::as_str) != Some(room_ref)
            || receipt.get("system_id").and_then(Value::as_str) != Some(system_id)
            || receipt.get("status").and_then(Value::as_str) != Some("admitted")
            || by_sequence.insert(sequence, receipt).is_some()
        {
            return Err(verr(
                "outcome_room_projection_receipt_source_unresolved",
                "room receipt census contains a detached or duplicate receipt",
            ));
        }
    }
    if by_sequence.len() != latest.saturating_add(1) as usize {
        return Err(verr(
            "outcome_room_projection_receipt_source_unresolved",
            "Agentgres receipt census does not exactly cover the room revision",
        ));
    }
    let mut refs = Vec::with_capacity(by_sequence.len());
    for (index, operation) in operations.iter().enumerate() {
        let receipt = by_sequence.get(&(index as u64)).ok_or_else(|| {
            verr(
                "outcome_room_projection_receipt_source_unresolved",
                format!("room receipt {index} is absent"),
            )
        })?;
        if operation.get("receipt_ref") != receipt.get("receipt_ref")
            || operation.get("receipt_root") != receipt.get("receipt_root")
            || operation.get("resulting_room_state_root")
                != receipt.get("resulting_room_state_root")
            || operation.get("resulting_transition_commitment_ref")
                != receipt.get("resulting_transition_commitment_ref")
        {
            return Err(verr(
                "outcome_room_projection_receipt_source_unresolved",
                format!("room receipt {index} is detached from its operation"),
            ));
        }
        refs.push(
            receipt
                .get("receipt_ref")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        );
    }
    let declared = room
        .get("admission_and_replay_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if declared
        != refs
            .iter()
            .map(|reference| json!(reference))
            .collect::<Vec<_>>()
        || room.get("room_receipt_root")
            != by_sequence
                .get(&latest)
                .and_then(|receipt| receipt.get("receipt_root"))
    {
        return Err(verr(
            "outcome_room_projection_receipt_source_stale",
            "room receipt refs or terminal receipt root differ from Agentgres truth",
        ));
    }
    Ok(refs)
}

fn verify_reciprocal_goal_runs(
    room: &Value,
    goal_runs: &[Value],
) -> Result<BTreeSet<String>, VErr> {
    let room_ref = room["outcome_room_id"].as_str().unwrap_or_default();
    let declared = bounded_ref_set(
        room,
        "member_goal_run_refs",
        "outcome_room_projection_membership_unresolved",
    )?;
    let mut reciprocal = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for run in goal_runs {
        let goal_ref = run.get("goal_ref").and_then(Value::as_str).ok_or_else(|| {
            verr(
                "outcome_room_projection_membership_unresolved",
                "GoalRun record omits goal_ref",
            )
        })?;
        if !seen.insert(goal_ref.to_owned()) {
            return Err(verr(
                "outcome_room_projection_membership_unresolved",
                format!("GoalRun '{goal_ref}' resolves more than once"),
            ));
        }
        if run.get("outcome_room_ref").and_then(Value::as_str) == Some(room_ref) {
            reciprocal.insert(goal_ref.to_owned());
        }
    }
    if reciprocal != declared {
        return Err(verr(
            "outcome_room_projection_membership_unresolved",
            "room membership and GoalRun backlinks are not the same exact set",
        ));
    }
    Ok(declared)
}

fn projection_ref_bucket<'a>(
    refs: &'a mut ProjectionRefs,
    contract_id: &str,
) -> Option<&'a mut BTreeSet<String>> {
    match contract_id {
        "schema://ioi/foundations/work-frontier-item/v2" => Some(&mut refs.frontier_item_refs),
        "schema://ioi/foundations/work-claim-lease/v2" => Some(&mut refs.work_claim_refs),
        "schema://ioi/foundations/attempt/v2" => Some(&mut refs.attempt_refs),
        "schema://ioi/foundations/finding/v2" => Some(&mut refs.finding_refs),
        "schema://ioi/foundations/verifier-challenge/v2" => Some(&mut refs.verifier_challenge_refs),
        "schema://ioi/foundations/participant-state-bundle/v2" => Some(&mut refs.participant_refs),
        "schema://ioi/foundations/work-result/v2" => Some(&mut refs.work_result_refs),
        "schema://ioi/foundations/outcome-delta/v2" => Some(&mut refs.outcome_delta_refs),
        _ => None,
    }
}

fn require_projection_labels(
    refs: &ProjectionRefs,
    label_bearing_object_count: usize,
) -> Result<(), VErr> {
    if label_bearing_object_count > 0 && refs.information_flow_label_refs.is_empty() {
        return Err(verr(
            "outcome_room_projection_labels_unresolved",
            "an admitted label-bearing room object does not supply the projection label set",
        ));
    }
    Ok(())
}

fn safe_room_object_summary(contract_id: &str, admitted: &Value) -> Option<Value> {
    let admission_receipt_ref = admitted
        .pointer("/room_admission/admission_receipt_ref")
        .cloned()
        .unwrap_or(Value::Null);
    match contract_id {
        "schema://ioi/foundations/work-result/v2" => Some(json!({
            "work_result_id":admitted["work_result_id"],
            "goal_run_ref":admitted["goal_run_ref"],
            "work_subject_ref":admitted["work_subject_ref"],
            "outcome_class":admitted["outcome_class"],
            "status":admitted["status"],
            "uncertainty":admitted["uncertainty"],
            "admission_receipt_ref":admission_receipt_ref,
            "evidence_refs_exported":false,
            "artifact_refs_exported":false,
        })),
        "schema://ioi/foundations/outcome-delta/v2" => Some(json!({
            "outcome_delta_id":admitted["outcome_delta_id"],
            "work_subject_ref":admitted["work_subject_ref"],
            "proposed_by_ref":admitted["proposed_by_ref"],
            "delta_kind":admitted["delta_kind"],
            "status":admitted["status"],
            "admission_receipt_ref":admission_receipt_ref,
            "verifier_and_acceptance_refs_exported":false,
        })),
        _ => None,
    }
}

fn verify_owner_projection_backlinks(
    data_dir: &str,
    room_ref: &str,
    contract_id: &str,
    object_ref: &str,
    admitted: &Value,
    room_receipt_ref: &str,
) -> Result<(), VErr> {
    let public = match contract_id {
        "schema://ioi/foundations/work-result/v2" => {
            super::work_result_routes::load_work_result_strict(data_dir, object_ref)
        }
        "schema://ioi/foundations/outcome-delta/v2" => {
            super::work_result_routes::load_outcome_delta_strict(data_dir, object_ref)
        }
        _ => return Ok(()),
    }
    .map_err(|message| {
        verr(
            "outcome_room_projection_owner_source_unreadable",
            format!(
                "versioned owner registry cannot resolve '{object_ref}' without partial truth ({message})"
            ),
        )
    })?
    .ok_or_else(|| {
        verr(
            "outcome_room_projection_owner_source_unresolved",
            format!("owner registry has no admitted '{object_ref}'"),
        )
    })?;
    let public_matches = if contract_id.ends_with("work-result/v2") {
        let admitted_refs = admitted
            .get("outcome_delta_refs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let public_refs = public
            .get("outcome_delta_refs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut normalized = public.clone();
        normalized["outcome_delta_refs"] = Value::Array(admitted_refs.clone());
        admitted_refs.iter().all(|item| public_refs.contains(item)) && normalized == *admitted
    } else {
        public == *admitted
    };
    if !public_matches {
        return Err(verr(
            "outcome_room_projection_owner_source_stale",
            format!("owner registry bytes for '{object_ref}' diverge from room admission"),
        ));
    }
    let (goal_ref, parent_result) = if contract_id.ends_with("work-result/v2") {
        (
            admitted
                .get("goal_run_ref")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            None,
        )
    } else {
        let proposer = admitted
            .get("proposed_by_ref")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let parent = super::work_result_routes::load_work_result_strict(data_dir, proposer)
            .map_err(|message| {
                verr(
                    "outcome_room_projection_owner_backlink_unreadable",
                    format!(
                        "versioned WorkResult registry cannot resolve OutcomeDelta parent '{proposer}' without partial truth ({message})"
                    ),
                )
            })?
            .ok_or_else(|| {
                verr(
                    "outcome_room_projection_owner_backlink_unresolved",
                    format!("OutcomeDelta parent WorkResult '{proposer}' is absent"),
                )
            })?;
        if parent.get("outcome_room_ref").and_then(Value::as_str) != Some(room_ref)
            || !parent
                .get("outcome_delta_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| refs.iter().any(|value| value.as_str() == Some(object_ref)))
        {
            return Err(verr(
                "outcome_room_projection_owner_backlink_unresolved",
                "OutcomeDelta owner backlink is not exact",
            ));
        }
        (
            parent
                .get("goal_run_ref")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            Some(proposer.to_owned()),
        )
    };
    let goal_runs = strict_goal_run_census(data_dir)?
        .into_iter()
        .filter(|record| record.get("goal_ref").and_then(Value::as_str) == Some(goal_ref.as_str()))
        .collect::<Vec<_>>();
    if goal_runs.len() != 1
        || goal_runs[0].get("outcome_room_ref").and_then(Value::as_str) != Some(room_ref)
        || !goal_runs[0]
            .get("receipt_refs")
            .and_then(Value::as_array)
            .is_some_and(|refs| {
                refs.iter()
                    .any(|value| value.as_str() == Some(room_receipt_ref))
            })
        || (parent_result.is_none()
            && !goal_runs[0]
                .get("work_result_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| refs.iter().any(|value| value.as_str() == Some(object_ref))))
    {
        return Err(verr(
            "outcome_room_projection_owner_backlink_unresolved",
            format!("GoalRun owner backlinks for '{object_ref}' are incomplete"),
        ));
    }
    Ok(())
}

fn sort_projection_objects_by_admission_order(objects: &mut [Value]) {
    // Agentgres projects this family by content-derived object key. Content hashes are not a
    // semantic order: run-derived WorkResult/OutcomeDelta bytes can therefore swap enumeration
    // order across otherwise equivalent fresh executions. Validate owner/backlink truth in the
    // room's admitted sequence instead, with stable identity/root tie-breaks. Missing, duplicate,
    // or detached coordinates remain invalid and are rejected by the exact checks below; this
    // ordering helper never turns an invalid coordinate into accepted truth.
    objects.sort_by_cached_key(|record| {
        (
            record
                .pointer("/admitted_object/room_admission/admitted_sequence")
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX),
            record
                .get("object_ref")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            record
                .get("object_root")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        )
    });
}

fn verify_projection_objects(
    data_dir: &str,
    room: &Value,
    operations: &[Value],
    mut objects: Vec<Value>,
) -> Result<ProjectionRefs, VErr> {
    ensure_projection_cardinality(
        objects.len(),
        M4_REPLAY_ENTRY_MAX,
        "room admitted-object census",
    )?;
    let room_ref = room["outcome_room_id"].as_str().unwrap_or_default();
    let system_id = room["system_id"].as_str().unwrap_or_default();
    let mut refs = ProjectionRefs::default();
    let mut object_sequences = BTreeSet::new();
    let mut label_bearing_object_count = 0usize;
    sort_projection_objects_by_admission_order(&mut objects);
    for object_record in objects {
        verify_rooted_record(OBJECT_DOMAIN, "object_root", &object_record).map_err(|_| {
            verr(
                "outcome_room_projection_object_source_unresolved",
                "an Agentgres admitted-object record has an invalid root",
            )
        })?;
        let contract_id = exact_string(
            &object_record,
            "/object_contract_id",
            "outcome_room_projection_object_source_unresolved",
        )?;
        let contract = child_contract(contract_id).ok_or_else(|| {
            verr(
                "outcome_room_projection_object_source_unresolved",
                format!("admitted object uses unknown room contract '{contract_id}'"),
            )
        })?;
        let object_ref = exact_string(
            &object_record,
            "/object_ref",
            "outcome_room_projection_object_source_unresolved",
        )?;
        let admitted = object_record.get("admitted_object").ok_or_else(|| {
            verr(
                "outcome_room_projection_object_source_unresolved",
                format!("admitted object '{object_ref}' omits its value"),
            )
        })?;
        if object_record
            .get("outcome_room_ref")
            .and_then(Value::as_str)
            != Some(room_ref)
            || object_record.get("system_id").and_then(Value::as_str) != Some(system_id)
            || admitted.get(contract.id_field).and_then(Value::as_str) != Some(object_ref)
        {
            return Err(verr(
                "outcome_room_projection_object_source_unresolved",
                format!("admitted object '{object_ref}' is detached from its room or identity"),
            ));
        }
        canonical_contract(contract_id, admitted).map_err(|_| {
            verr(
                "outcome_room_projection_object_source_unresolved",
                format!("admitted object '{object_ref}' fails its registered contract"),
            )
        })?;
        super::goalrun_routes::validate_room_owner_runtime_dependencies(
            data_dir,
            room,
            admitted,
        )
        .map_err(|(code, _message)| {
            verr(
                "outcome_room_projection_runtime_dependency_unresolved",
                format!(
                    "admitted object '{object_ref}' cannot project because one exact runtime dependency is unavailable ({code})"
                ),
            )
        })?;
        let admission = admitted.get("room_admission").ok_or_else(|| {
            verr(
                "outcome_room_projection_object_source_unresolved",
                format!("admitted object '{object_ref}' omits room admission"),
            )
        })?;
        let sequence = admission
            .get("admitted_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                verr(
                    "outcome_room_projection_object_source_unresolved",
                    format!("admitted object '{object_ref}' omits its sequence"),
                )
            })?;
        if sequence == 0
            || sequence as usize >= operations.len()
            || !object_sequences.insert(sequence)
            || admission.get("admission_status").and_then(Value::as_str) != Some("admitted")
            || admission.get("outcome_room_ref").and_then(Value::as_str) != Some(room_ref)
            || admission.get("room_system_id").and_then(Value::as_str) != Some(system_id)
        {
            return Err(verr(
                "outcome_room_projection_object_source_unresolved",
                format!("admitted object '{object_ref}' has a detached admission coordinate"),
            ));
        }
        let operation = &operations[sequence as usize];
        let label_bearing = matches!(
            contract_id,
            "schema://ioi/foundations/work-result/v2" | "schema://ioi/foundations/outcome-delta/v2"
        );
        if label_bearing {
            label_bearing_object_count += 1;
        }
        let detached = operation.get("operation_kind").and_then(Value::as_str)
            != Some("room_child_admitted")
            || operation.get("object_contract_id").and_then(Value::as_str) != Some(contract_id)
            || operation.get("object_ref").and_then(Value::as_str) != Some(object_ref)
            || operation.get("object_root") != object_record.get("object_root")
            || operation.get("receipt_ref") != admission.get("admission_receipt_ref")
            || operation.get("receipt_root") != admission.get("resulting_receipt_root")
            || operation.get("resulting_room_state_root")
                != admission.get("resulting_room_state_root")
            || operation.get("resulting_transition_commitment_ref")
                != admission.get("resulting_transition_commitment_ref");
        if detached {
            return Err(verr(
                if label_bearing {
                    "outcome_room_projection_label_source_stale"
                } else {
                    "outcome_room_projection_object_source_stale"
                },
                format!("admitted object '{object_ref}' is detached from its Agentgres operation"),
            ));
        }
        let room_receipt_ref = admission
            .get("admission_receipt_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                verr(
                    "outcome_room_projection_owner_backlink_unresolved",
                    "admitted object omits its room receipt ref",
                )
            })?;
        verify_owner_projection_backlinks(
            data_dir,
            room_ref,
            contract_id,
            object_ref,
            admitted,
            room_receipt_ref,
        )?;
        let mut payload = admitted.clone();
        payload
            .as_object_mut()
            .ok_or_else(|| {
                verr(
                    "outcome_room_projection_object_source_unresolved",
                    format!("admitted object '{object_ref}' is not an object"),
                )
            })?
            .remove("room_admission");
        let payload_root = jcs_root("ioi.outcome-room-child-payload-jcs-sha256.v1", &payload)?;
        if admission.get("payload_root").and_then(Value::as_str) != Some(payload_root.as_str()) {
            return Err(verr(
                if label_bearing {
                    "outcome_room_projection_label_source_stale"
                } else {
                    "outcome_room_projection_object_source_stale"
                },
                format!("admitted object '{object_ref}' payload no longer matches its root"),
            ));
        }
        let bucket_size = {
            let bucket = projection_ref_bucket(&mut refs, contract_id).ok_or_else(|| {
                verr(
                    "outcome_room_projection_object_source_unresolved",
                    format!("admitted object '{object_ref}' has no graph projection family"),
                )
            })?;
            if !bucket.insert(object_ref.to_owned()) {
                return Err(verr(
                    "outcome_room_projection_object_source_unresolved",
                    format!("admitted object ref '{object_ref}' occurs more than once"),
                ));
            }
            bucket.len()
        };
        ensure_projection_cardinality(
            bucket_size,
            M4_ROOM_REF_SET_MAX,
            "one room-child projection family",
        )?;
        if let Some(labels) = admitted.get("information_flow_label_refs") {
            let labels = labels.as_array().ok_or_else(|| {
                verr(
                    "outcome_room_projection_labels_unresolved",
                    format!("admitted object '{object_ref}' has a malformed label set"),
                )
            })?;
            if label_bearing && labels.is_empty() {
                return Err(verr(
                    "outcome_room_projection_labels_unresolved",
                    format!("admitted object '{object_ref}' has no information-flow label"),
                ));
            }
            for label in labels {
                let Some(label) = label.as_str().filter(|label| {
                    label.starts_with("ifc-label://")
                        && label.len() <= 500
                        && !label.chars().any(char::is_whitespace)
                }) else {
                    return Err(verr(
                        "outcome_room_projection_labels_unresolved",
                        format!("admitted object '{object_ref}' has an invalid label ref"),
                    ));
                };
                refs.information_flow_label_refs.insert(label.to_owned());
                ensure_projection_cardinality(
                    refs.information_flow_label_refs.len(),
                    M4_ROOM_REF_SET_MAX,
                    "room information-flow-label projection",
                )?;
            }
        } else if label_bearing {
            return Err(verr(
                "outcome_room_projection_labels_unresolved",
                format!("admitted object '{object_ref}' omits its information-flow labels"),
            ));
        }
        if let Some(summary) = safe_room_object_summary(contract_id, admitted) {
            if contract_id == "schema://ioi/foundations/work-result/v2" {
                refs.work_result_summaries.push(summary);
                ensure_projection_cardinality(
                    refs.work_result_summaries.len(),
                    M4_ROOM_REF_SET_MAX,
                    "room WorkResult summary projection",
                )?;
            } else {
                refs.outcome_delta_summaries.push(summary);
                ensure_projection_cardinality(
                    refs.outcome_delta_summaries.len(),
                    M4_ROOM_REF_SET_MAX,
                    "room OutcomeDelta summary projection",
                )?;
            }
        }
    }
    let child_operation_sequences = operations
        .iter()
        .filter(|operation| {
            operation.get("operation_kind").and_then(Value::as_str) == Some("room_child_admitted")
        })
        .filter_map(|operation| operation.get("sequence").and_then(Value::as_u64))
        .collect::<BTreeSet<_>>();
    if child_operation_sequences != object_sequences {
        return Err(verr(
            "outcome_room_projection_object_source_unresolved",
            "Agentgres child operations and admitted-object records are not the same exact set",
        ));
    }
    for (room_field, derived) in [
        ("frontier_item_refs", &refs.frontier_item_refs),
        ("attempt_refs", &refs.attempt_refs),
        ("finding_refs", &refs.finding_refs),
        ("verifier_challenge_refs", &refs.verifier_challenge_refs),
        ("participant_state_bundle_refs", &refs.participant_refs),
    ] {
        if bounded_ref_set(
            room,
            room_field,
            "outcome_room_projection_object_source_unresolved",
        )? != *derived
        {
            return Err(verr(
                "outcome_room_projection_object_source_stale",
                format!("room '{room_field}' is not the exact admitted-object set"),
            ));
        }
    }
    // Genesis and membership-only rooms honestly project an empty label set. Once even one
    // label-bearing owner child exists, its exact non-empty labels remain mandatory and are
    // checked above before the projection can be returned.
    require_projection_labels(&refs, label_bearing_object_count)?;
    Ok(refs)
}

fn projection_values(
    snapshot: &ProjectionSnapshot,
    generated_at: &str,
) -> Result<(Value, Value), VErr> {
    let room_ref = snapshot.room["outcome_room_id"]
        .as_str()
        .unwrap_or_default();
    let room_tail = room_ref.strip_prefix("outcome-room://").unwrap_or_default();
    let revision = snapshot.room["latest_sequence"]
        .as_u64()
        .unwrap_or_default();
    let state_root = snapshot.room["room_state_root"]
        .as_str()
        .unwrap_or_default();
    let root_tail = state_root.strip_prefix("sha256:").unwrap_or_default();
    let strings = |values: &BTreeSet<String>| {
        values
            .iter()
            .cloned()
            .map(Value::String)
            .collect::<Vec<_>>()
    };
    let graph = json!({
        "schema_version":GRAPH_SCHEMA,
        "projection_id":format!("projection://ioi/outcome-room/{room_tail}/collaborative-work-graph/revision/{revision}/{root_tail}"),
        "outcome_room_ref":room_ref,
        "source_room_revision":revision,
        "source_room_state_root":state_root,
        "member_goal_run_refs":strings(&snapshot.member_goal_run_refs),
        "participant_refs":strings(&snapshot.refs.participant_refs),
        "frontier_item_refs":strings(&snapshot.refs.frontier_item_refs),
        "work_claim_refs":strings(&snapshot.refs.work_claim_refs),
        "attempt_refs":strings(&snapshot.refs.attempt_refs),
        "finding_refs":strings(&snapshot.refs.finding_refs),
        "verifier_challenge_refs":strings(&snapshot.refs.verifier_challenge_refs),
        "work_result_refs":strings(&snapshot.refs.work_result_refs),
        "outcome_delta_refs":strings(&snapshot.refs.outcome_delta_refs),
        "source_admission_receipt_refs":snapshot.source_admission_receipt_refs,
        "information_flow_label_refs":strings(&snapshot.refs.information_flow_label_refs),
        "generated_at":generated_at,
        "authoritative":false,
        "client_writable":false,
    });
    canonical_contract(GRAPH_CONTRACT, &graph)?;
    let discussion = json!({
        "schema_version":DISCUSSION_SCHEMA,
        "projection_id":format!("projection://ioi/outcome-room/{room_tail}/discussion/revision/{revision}/{root_tail}"),
        "outcome_room_ref":room_ref,
        "source_room_revision":revision,
        "source_room_state_root":state_root,
        "source_admission_receipt_refs":snapshot.source_admission_receipt_refs,
        "visibility_policy_ref":snapshot.room["visibility_policy_ref"],
        "information_flow_label_refs":strings(&snapshot.refs.information_flow_label_refs),
        "permitted_subject_refs":strings(&snapshot.permitted_subject_refs),
        "message_refs":[],
        "redaction_summary_refs":[],
        "replay_cursor":format!("{room_ref}@{revision}:{state_root}"),
        "generated_at":generated_at,
        "authoritative":false,
        "client_writable":false,
    });
    canonical_contract(DISCUSSION_CONTRACT, &discussion)?;
    Ok((graph, discussion))
}

fn validate_projection_system_binding(
    data_dir: &str,
    room: &Value,
    genesis_operation: &Value,
) -> Result<(), VErr> {
    let system_id = exact_string(
        room,
        "/system_id",
        "outcome_room_projection_system_unresolved",
    )?;
    let graph = active_system_binding(data_dir, system_id).map_err(|_| {
        verr(
            "outcome_room_projection_system_unresolved",
            "the room's exact active bounded-System source cannot be resolved",
        )
    })?;
    let chain = graph.get("autonomous_system_chain").ok_or_else(|| {
        verr(
            "outcome_room_projection_system_unresolved",
            "the active bounded System omits its chain",
        )
    })?;
    let active = graph.get("active_profile_set").ok_or_else(|| {
        verr(
            "outcome_room_projection_system_unresolved",
            "the active bounded System omits its selected profiles",
        )
    })?;
    let operation_log = graph.get("operation_log").ok_or_else(|| {
        verr(
            "outcome_room_projection_system_unresolved",
            "the active bounded System omits its operation log",
        )
    })?;
    let oracle_refs = active
        .get("oracle_evidence_profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "outcome_room_projection_system_unresolved",
                "the active bounded System omits its oracle profiles",
            )
        })?
        .iter()
        .map(|entry| {
            entry.get("candidate_profile_ref").cloned().ok_or_else(|| {
                verr(
                    "outcome_room_projection_system_unresolved",
                    "an active oracle profile omits its canonical ref",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_profiles = json!({
        "deployment_profile_ref":active["deployment"]["candidate_profile_ref"],
        "ordering_admission_finality_profile_ref":active["ordering_admission_finality"]["candidate_profile_ref"],
        "oracle_evidence_profile_refs":oracle_refs,
        "lifecycle_continuity_profile_ref":active["lifecycle_continuity"]["candidate_profile_ref"],
        "network_enrollment_ref":active
            .get("network_enrollment")
            .filter(|value| !value.is_null())
            .and_then(|value| value.get("candidate_profile_ref"))
            .cloned()
            .unwrap_or(Value::Null),
    });
    if room.get("system_id") != chain.get("system_id")
        || room.get("genesis_ref") != chain.get("genesis_ref")
        || room.get("package_id") != chain.get("package_id")
        || room.get("manifest_ref") != chain.get("manifest_ref")
        || room.get("constitution_ref") != chain.get("constitution_ref")
        || room.get("active_profile_refs") != Some(&expected_profiles)
        || room.get("autonomous_system_state_ref") != operation_log.get("operation_log_ref")
        || genesis_operation.get("system_chain_root") != chain.get("chain_root")
        || genesis_operation.get("system_state_root") != chain.get("latest_state_root")
        || genesis_operation.get("collective_goal_run_ref") != room.get("objective_ref")
    {
        return Err(verr(
            "outcome_room_projection_system_unresolved",
            "room genesis is detached from its exact active package, constitution, profiles, System chain, or state root",
        ));
    }
    let collective = collective_goal_run_for_room(
        data_dir,
        room.get("objective_ref")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        system_id,
        &graph,
    )?;
    if genesis_operation.get("collective_path_decision_ref")
        != collective.pointer("/admission_path_decision/decision_ref")
    {
        return Err(verr(
            "outcome_room_projection_system_unresolved",
            "room genesis is detached from the collective GoalRun's admitted path decision",
        ));
    }
    let mut pre_genesis_room = genesis_operation
        .get("resulting_room")
        .cloned()
        .ok_or_else(|| {
            verr(
                "outcome_room_projection_system_unresolved",
                "room genesis operation omits its resulting room",
            )
        })?;
    pre_genesis_room["latest_transition_commitment_ref"] = Value::Null;
    pre_genesis_room["room_state_root"] = Value::Null;
    pre_genesis_room["room_receipt_root"] = Value::Null;
    pre_genesis_room["admission_and_replay_refs"] = json!([]);
    let transition_hash = jcs_root(
        "ioi.outcome-room-genesis-transition-jcs-sha256.v2",
        &json!({
            "system_chain_root":chain["chain_root"],
            "system_state_root":chain["latest_state_root"],
            "room":pre_genesis_room,
        }),
    )?;
    let room_tail = room
        .get("outcome_room_id")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("outcome-room://"))
        .ok_or_else(|| {
            verr(
                "outcome_room_projection_system_unresolved",
                "room identity is non-canonical",
            )
        })?;
    let expected_transition = format!(
        "commitment://ioi/outcome-room/{room_tail}/sequence/0/{}",
        transition_hash.strip_prefix("sha256:").unwrap_or_default()
    );
    if genesis_operation
        .get("resulting_transition_commitment_ref")
        .and_then(Value::as_str)
        != Some(expected_transition.as_str())
    {
        return Err(verr(
            "outcome_room_projection_system_unresolved",
            "room genesis transition does not reproduce from the exact active System roots",
        ));
    }
    Ok(())
}

fn load_projection_snapshot(data_dir: &str, room_ref: &str) -> Result<ProjectionSnapshot, VErr> {
    let _ = super::outcome_room_routes::list_current_rooms_canonical_strict(data_dir)?;
    let room = super::outcome_room_routes::resolve_room_strict(data_dir, room_ref)
        .map_err(|error| verr("outcome_room_projection_source_unreadable", error))?
        .ok_or_else(|| verr("outcome_room_not_found", "room is absent"))?;
    if room.get("schema_version").and_then(Value::as_str) != Some(ROOM_SCHEMA) {
        return Err(verr(
            "outcome_room_projection_contract_unavailable",
            "graph and discussion projections require a v2 bounded-System room",
        ));
    }
    validate_current_room_contract(&room).map_err(|_| {
        verr(
            "outcome_room_projection_source_unresolved",
            "local room fails its registered contract",
        )
    })?;
    let expected_state_root = state_root(&room)?;
    if room.get("room_state_root").and_then(Value::as_str) != Some(expected_state_root.as_str()) {
        return Err(verr(
            "outcome_room_projection_source_stale",
            "local room state root does not recompute",
        ));
    }
    let mut operations =
        required_projection_records(data_dir, ADMISSION_OPERATION_DOMAIN, room_ref, 1)?
            .into_iter()
            .map(|operation| (ADMISSION_OPERATION_DOMAIN, operation))
            .collect::<Vec<_>>();
    operations.extend(
        required_projection_records(
            data_dir,
            TRANSITION_OPERATION_DOMAIN,
            room_ref,
            M4_TRANSITION_ENTRY_MAX,
        )?
        .into_iter()
        .map(|operation| (TRANSITION_OPERATION_DOMAIN, operation)),
    );
    let operations = verify_projection_operation_chain(&room, operations)?;
    let genesis_operation = operations.first().ok_or_else(|| {
        verr(
            "outcome_room_projection_system_unresolved",
            "room replay omits its genesis operation",
        )
    })?;
    validate_projection_system_binding(data_dir, &room, genesis_operation)?;
    let source_admission_receipt_refs = verify_projection_receipts(
        &room,
        &operations,
        required_projection_records(data_dir, RECEIPT_DOMAIN, room_ref, M4_REPLAY_ENTRY_MAX)?,
    )?;
    let member_goal_run_refs =
        verify_reciprocal_goal_runs(&room, &strict_goal_run_census(data_dir)?)?;
    let mut refs = verify_projection_objects(
        data_dir,
        &room,
        &operations,
        required_projection_records(data_dir, OBJECT_DOMAIN, room_ref, M4_REPLAY_ENTRY_MAX)?,
    )?;
    let participant_lease_refs = bounded_ref_set(
        &room,
        "participant_lease_refs",
        "outcome_room_projection_participants_unresolved",
    )?;
    for lease_ref in &participant_lease_refs {
        let lease =
            super::room_participation_routes::resolve_participant_lease_strict(data_dir, lease_ref)
                .map_err(|error| verr("outcome_room_projection_participants_unresolved", error))?
                .ok_or_else(|| {
                    verr(
                        "outcome_room_projection_participants_unresolved",
                        format!("participant lease '{lease_ref}' is absent"),
                    )
                })?;
        if lease.get("outcome_room_ref").and_then(Value::as_str) != Some(room_ref) {
            return Err(verr(
                "outcome_room_projection_participants_unresolved",
                format!("participant lease '{lease_ref}' belongs to another room"),
            ));
        }
    }
    refs.participant_refs
        .extend(participant_lease_refs.iter().cloned());
    ensure_projection_cardinality(
        refs.participant_refs.len(),
        M4_ROOM_REF_SET_MAX,
        "room participant projection",
    )?;
    if !bounded_ref_set(
        &room,
        "discussion_projection_refs",
        "outcome_room_projection_discussion_source_unresolved",
    )?
    .is_empty()
    {
        return Err(verr(
            "outcome_room_projection_discussion_source_unresolved",
            "room declares discussion refs that have no admitted message/projection source in M4",
        ));
    }
    let mut permitted_subject_refs = BTreeSet::new();
    for field in ["system_id", "owner_or_sponsor_ref", "host_domain_ref"] {
        let subject = exact_string(
            &room,
            &format!("/{field}"),
            "outcome_room_projection_visibility_policy_unresolved",
        )?;
        permitted_subject_refs.insert(subject.to_owned());
    }
    permitted_subject_refs.extend(participant_lease_refs);
    ensure_projection_cardinality(
        permitted_subject_refs.len(),
        M4_DISCUSSION_SUBJECT_MAX,
        "discussion permitted-subject projection",
    )?;
    exact_string(
        &room,
        "/visibility_policy_ref",
        "outcome_room_projection_visibility_policy_unresolved",
    )?;
    Ok(ProjectionSnapshot {
        room,
        member_goal_run_refs,
        refs,
        source_admission_receipt_refs,
        permitted_subject_refs,
    })
}

fn projection_response(data_dir: &str, room_tail: &str, graph: bool) -> Result<Value, VErr> {
    let room_ref = format!("outcome-room://{room_tail}");
    let snapshot = load_projection_snapshot(data_dir, &room_ref)?;
    let (graph_projection, discussion_projection) = projection_values(&snapshot, &iso_now())?;
    let response = if graph {
        json!({
            "collaborative_work_graph":graph_projection,
            "runtimeTruthSource":"agentgres-required-admission-projection",
        })
    } else {
        json!({
            "discussion_projection":discussion_projection,
            "runtimeTruthSource":"agentgres-required-admission-projection",
        })
    };
    ensure_serialized_body_bound(&response, "outcome_room_projection_response_too_large")?;
    Ok(response)
}

pub(crate) async fn handle_collaborative_work_graph(
    AxumPath(id): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let principal_ref = match request_principal(&state.data_dir, &headers) {
        Ok(principal_ref) => principal_ref,
        Err(error) => return classify(error),
    };
    let _guard = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let room_ref = format!("outcome-room://{id}");
    let room = match super::outcome_room_routes::resolve_room_strict(&state.data_dir, &room_ref) {
        Ok(Some(room)) => room,
        Ok(None) => {
            if let Some(response) = managed_missing_room_refusal(&state.data_dir, &headers) {
                return response;
            }
            return classify(verr("outcome_room_not_found", "room is absent"));
        }
        Err(error) => {
            return room_source_refusal(
                &state.data_dir,
                &headers,
                verr("outcome_room_source_unreadable", error),
            )
        }
    };
    if let Err(error) =
        authorize_generation_dispatch_if_managed(&state.data_dir, &headers, &principal_ref, &room)
    {
        return classify(error);
    }
    if let Some(response) = refuse_predecessor_projection(&room) {
        return response;
    }
    if let Err(error) = authorize_resolved_room_principal(&principal_ref, &room) {
        return classify(error);
    }
    if let Err(error) = refuse_while_any_intent_pending(&state.data_dir) {
        return room_source_refusal(&state.data_dir, &headers, error);
    }
    let response = match projection_response(&state.data_dir, &id, true) {
        Ok(response) => response,
        Err(error) => return classify(error),
    };
    if let Err(error) = confirm_room_read_stable(&state.data_dir, &room_ref, &room) {
        return classify(error);
    }
    (StatusCode::OK, Json(response))
}

pub(crate) async fn handle_discussion_projection(
    AxumPath(id): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let principal_ref = match request_principal(&state.data_dir, &headers) {
        Ok(principal_ref) => principal_ref,
        Err(error) => return classify(error),
    };
    let _guard = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let room_ref = format!("outcome-room://{id}");
    let room = match super::outcome_room_routes::resolve_room_strict(&state.data_dir, &room_ref) {
        Ok(Some(room)) => room,
        Ok(None) => {
            if let Some(response) = managed_missing_room_refusal(&state.data_dir, &headers) {
                return response;
            }
            return classify(verr("outcome_room_not_found", "room is absent"));
        }
        Err(error) => {
            return room_source_refusal(
                &state.data_dir,
                &headers,
                verr("outcome_room_source_unreadable", error),
            )
        }
    };
    if let Err(error) =
        authorize_generation_dispatch_if_managed(&state.data_dir, &headers, &principal_ref, &room)
    {
        return classify(error);
    }
    if let Some(response) = refuse_predecessor_projection(&room) {
        return response;
    }
    if let Err(error) = authorize_resolved_room_principal(&principal_ref, &room) {
        return classify(error);
    }
    if let Err(error) = refuse_while_any_intent_pending(&state.data_dir) {
        return room_source_refusal(&state.data_dir, &headers, error);
    }
    let response = match projection_response(&state.data_dir, &id, false) {
        Ok(response) => response,
        Err(error) => return classify(error),
    };
    if let Err(error) = confirm_room_read_stable(&state.data_dir, &room_ref, &room) {
        return classify(error);
    }
    (StatusCode::OK, Json(response))
}

fn selected_product_projection(
    data_dir: &str,
    snapshot: &ProjectionSnapshot,
) -> Result<Value, VErr> {
    let member_goal_runs = strict_goal_run_census(data_dir)?
        .into_iter()
        .filter_map(|run| {
            let goal_ref = run.get("goal_ref").and_then(Value::as_str)?;
            if !snapshot.member_goal_run_refs.contains(goal_ref) {
                return None;
            }
            Some(json!({
                "goal_run_ref":goal_ref,
                "status":run.get("status").cloned().unwrap_or(Value::Null),
                "admission_path":run.pointer("/admission_path_decision/decision").cloned().unwrap_or(Value::Null),
            }))
        })
        .collect::<Vec<_>>();
    let projection = json!({
        "schema_version":"ioi.hypervisor.outcome-room-product-projection.v1",
        "outcome_room":{
            "outcome_room_ref":snapshot.room["outcome_room_id"],
            "system_id":snapshot.room["system_id"],
            "package_id":snapshot.room["package_id"],
            "genesis_ref":snapshot.room["genesis_ref"],
            "manifest_ref":snapshot.room["manifest_ref"],
            "constitution_ref":snapshot.room["constitution_ref"],
            "active_profile_refs":snapshot.room["active_profile_refs"],
            "owner_or_sponsor_ref":snapshot.room["owner_or_sponsor_ref"],
            "objective_ref":snapshot.room["objective_ref"],
            "status":snapshot.room["status"],
            "latest_sequence":snapshot.room["latest_sequence"],
            "latest_transition_commitment_ref":snapshot.room["latest_transition_commitment_ref"],
            "room_state_root":snapshot.room["room_state_root"],
            "room_receipt_root":snapshot.room["room_receipt_root"],
        },
        "member_goal_runs":member_goal_runs,
        "work_result_refs":snapshot.refs.work_result_refs.iter().cloned().collect::<Vec<_>>(),
        "outcome_delta_refs":snapshot.refs.outcome_delta_refs.iter().cloned().collect::<Vec<_>>(),
        "work_results":snapshot.refs.work_result_summaries.clone(),
        "outcome_deltas":snapshot.refs.outcome_delta_summaries.clone(),
        "source_admission_receipt_refs":snapshot.source_admission_receipt_refs,
        "payload_refs_exported":false,
        "payload_bytes_exported":false,
        "runtimeTruthSource":"agentgres-required-admission-projection",
    });
    ensure_serialized_body_bound(&projection, "outcome_room_projection_response_too_large")?;
    Ok(projection)
}

/// Principal-filtered, room-selected product state. It exposes refs and safe lifecycle state only;
/// payload refs and bytes remain on their owner planes.
pub(crate) async fn handle_product_projection(
    AxumPath(id): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let principal_ref = match request_principal(&state.data_dir, &headers) {
        Ok(principal_ref) => principal_ref,
        Err(error) => return classify(error),
    };
    let _guard = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let room_ref = format!("outcome-room://{id}");
    let room = match super::outcome_room_routes::resolve_room_strict(&state.data_dir, &room_ref) {
        Ok(Some(room)) => room,
        Ok(None) => {
            if let Some(response) = managed_missing_room_refusal(&state.data_dir, &headers) {
                return response;
            }
            return classify(verr("outcome_room_not_found", "room is absent"));
        }
        Err(error) => {
            return room_source_refusal(
                &state.data_dir,
                &headers,
                verr("outcome_room_source_unreadable", error),
            )
        }
    };
    if let Err(error) =
        authorize_generation_dispatch_if_managed(&state.data_dir, &headers, &principal_ref, &room)
    {
        return classify(error);
    }
    if let Some(response) = refuse_predecessor_projection(&room) {
        return response;
    }
    if let Err(error) = authorize_resolved_room_principal(&principal_ref, &room) {
        return classify(error);
    }
    if let Err(error) = refuse_while_any_intent_pending(&state.data_dir) {
        return room_source_refusal(&state.data_dir, &headers, error);
    }
    let snapshot = match load_projection_snapshot(&state.data_dir, &room_ref) {
        Ok(snapshot) => snapshot,
        Err(error) => return classify(error),
    };
    let projection = match selected_product_projection(&state.data_dir, &snapshot) {
        Ok(projection) => projection,
        Err(error) => return classify(error),
    };
    if let Err(error) = confirm_room_read_stable(&state.data_dir, &room_ref, &room) {
        return classify(error);
    }
    (StatusCode::OK, Json(projection))
}

fn verify_rooted_record(family: &str, root_field: &str, value: &Value) -> Result<(), VErr> {
    let expected = exact_string(
        value,
        &format!("/{root_field}"),
        "outcome_room_recovery_invalid",
    )?;
    let mut material = value.clone();
    material[root_field] = Value::Null;
    let actual = super::system_activation_routes::jcs_hash(&json!({
        "domain":"ioi.outcome-room-required-admission-record-jcs-sha256.v1",
        "record_family":family,
        "record":material,
    }))
    .map_err(|(_, message)| verr("outcome_room_hash_failed", message))?;
    if actual != expected {
        return Err(verr(
            "outcome_room_recovery_invalid",
            format!("'{root_field}' does not recompute"),
        ));
    }
    Ok(())
}

fn validate_recovery_room_head(
    data_dir: &str,
    room_tail: &str,
    prior_root: Option<&str>,
    resulting_room: &Value,
) -> Result<(), VErr> {
    let room_ref = format!("outcome-room://{room_tail}");
    let current = super::outcome_room_routes::resolve_room_strict(data_dir, &room_ref)
        .map_err(|error| verr("outcome_room_recovery_unreadable", error))?;
    let resulting_root = exact_string(
        resulting_room,
        "/room_state_root",
        "outcome_room_recovery_invalid",
    )?;
    match (prior_root, current) {
        (None, None) => Ok(()),
        (None, Some(current)) if current == *resulting_room => Ok(()),
        (None, Some(_)) => Err(verr(
            "outcome_room_recovery_head_conflict",
            "genesis recovery refuses to replace an occupied room slot",
        )),
        (Some(_), None) => Err(verr(
            "outcome_room_recovery_head_conflict",
            "transition recovery cannot reconstruct an absent predecessor room",
        )),
        (Some(prior), Some(current)) => {
            let current_root = exact_string(
                &current,
                "/room_state_root",
                "outcome_room_recovery_head_conflict",
            )?;
            if current_root == prior || current_root == resulting_root {
                Ok(())
            } else {
                Err(verr(
                    "outcome_room_recovery_head_conflict",
                    "recovery refuses to overwrite a newer or divergent room head",
                ))
            }
        }
    }
}

/// Complete every v2 room transaction before readiness. Any malformed, unreadable, or divergent
/// intent is a startup error; recovery never skips dark state and never overwrites a newer head.
pub(crate) fn preflight_pending_owner_registry_census(data_dir: &str) -> Result<(), VErr> {
    for (_intent_key, intent) in strict_intent_family(data_dir, CHILD_INTENT_DIR)? {
        let owner_family = exact_string(
            &intent,
            "/owner_publication_family",
            "outcome_room_recovery_invalid",
        )?;
        let census = match owner_family {
            super::work_result_routes::RESULT_DIR => {
                super::work_result_routes::list_work_results_strict(data_dir)
            }
            super::work_result_routes::DELTA_DIR => {
                super::work_result_routes::list_outcome_deltas_strict(data_dir)
            }
            _ => {
                return Err(verr(
                    "outcome_room_recovery_invalid",
                    format!(
                        "pending child intent names unsupported owner registry '{owner_family}'"
                    ),
                ))
            }
        };
        census.map_err(|message| {
            verr(
                "outcome_room_recovery_owner_registry_unreadable",
                format!(
                    "pending OutcomeRoom child recovery requires one complete versioned owner registry ({message})"
                ),
            )
        })?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_child_recovery_intent(
    data_dir: &str,
    intent_key: &str,
    intent: &Value,
    room_tail: &str,
    prior_room: &Value,
    room: &Value,
    receipt: &Value,
    object: &Value,
    operation: &Value,
    owner_family: &str,
    owner_key: &str,
    owner_record: &Value,
    runtime_dependencies: &Value,
) -> Result<(), VErr> {
    if intent.get("schema_version").and_then(Value::as_str)
        != Some("ioi.outcome-room-child-admission-intent.v1")
    {
        return Err(verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' has an unsupported envelope"),
        ));
    }
    let contract_id = exact_string(
        object,
        "/object_contract_id",
        "outcome_room_recovery_invalid",
    )?;
    let (expected_family, expected_schema, identity_field) = match contract_id {
        "schema://ioi/foundations/work-result/v2" => (
            super::work_result_routes::RESULT_DIR,
            "ioi.foundations.work-result.v2",
            "work_result_id",
        ),
        "schema://ioi/foundations/outcome-delta/v2" => (
            super::work_result_routes::DELTA_DIR,
            "ioi.foundations.outcome-delta.v2",
            "outcome_delta_id",
        ),
        _ => {
            return Err(verr(
                "outcome_room_recovery_invalid",
                format!("child intent '{intent_key}' names a non-published contract family"),
            ))
        }
    };
    if owner_family != expected_family
        || owner_record.get("schema_version").and_then(Value::as_str) != Some(expected_schema)
    {
        return Err(verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' substitutes its owner family or contract"),
        ));
    }
    canonical_contract(contract_id, owner_record).map_err(|_| {
        verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' carries a non-canonical owner record"),
        )
    })?;

    let object_ref = exact_string(
        owner_record,
        &format!("/{identity_field}"),
        "outcome_room_recovery_invalid",
    )?;
    if safe_owner_key(object_ref) != owner_key {
        return Err(verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' detaches its owner key"),
        ));
    }
    let room_ref = exact_string(room, "/outcome_room_id", "outcome_room_recovery_invalid")?;
    if room_ref != format!("outcome-room://{room_tail}") {
        return Err(verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' detaches its room slot"),
        ));
    }
    validate_current_room_contract(room)?;
    let system_id = exact_string(room, "/system_id", "outcome_room_recovery_invalid")?;
    let sequence = room
        .get("latest_sequence")
        .and_then(Value::as_u64)
        .filter(|sequence| *sequence > 0)
        .ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                format!("child intent '{intent_key}' has no child sequence"),
            )
        })?;
    let resulting_transition = exact_string(
        room,
        "/latest_transition_commitment_ref",
        "outcome_room_recovery_invalid",
    )?;
    let resulting_room_root =
        exact_string(room, "/room_state_root", "outcome_room_recovery_invalid")?;
    if state_root(room)? != resulting_room_root {
        return Err(verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' carries a detached room state root"),
        ));
    }
    let prior_transition = exact_string(
        operation,
        "/expected_predecessor_commitment_ref",
        "outcome_room_recovery_invalid",
    )?;
    if prior_transition == resulting_transition {
        return Err(verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' does not advance the room head"),
        ));
    }
    let at = exact_string(operation, "/at", "outcome_room_recovery_invalid")?;

    let mut payload = owner_record.clone();
    payload
        .as_object_mut()
        .ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                "owner record is not an object",
            )
        })?
        .remove("room_admission");
    let payload_root = jcs_root("ioi.outcome-room-child-payload-jcs-sha256.v1", &payload)?;
    let prior_root = exact_string(
        intent,
        "/prior_room_state_root",
        "outcome_room_recovery_invalid",
    )?;
    validate_current_room_contract(prior_room)?;
    if prior_room.get("outcome_room_id").and_then(Value::as_str) != Some(room_ref)
        || prior_room.get("system_id").and_then(Value::as_str) != Some(system_id)
        || prior_room.get("latest_sequence").and_then(Value::as_u64) != Some(sequence - 1)
        || prior_room
            .get("latest_transition_commitment_ref")
            .and_then(Value::as_str)
            != Some(prior_transition)
        || prior_room.get("room_state_root").and_then(Value::as_str) != Some(prior_root)
        || state_root(prior_room)? != prior_root
    {
        return Err(verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' detaches its exact predecessor room"),
        ));
    }
    let proposed_admission = json!({
        "schema_version":BASE_SCHEMA,
        "room_system_id":system_id,
        "outcome_room_ref":room_ref,
        "proposed_or_issued_by_ref":system_id,
        "expected_room_revision":sequence - 1,
        "expected_predecessor_commitment_ref":prior_transition,
        "payload_root":payload_root,
        "admission_policy_ref":prior_room["coordination_policy_ref"],
        "admission_decision_ref":Value::Null,
        "admission_receipt_ref":Value::Null,
        "admitted_sequence":Value::Null,
        "resulting_room_revision":Value::Null,
        "resulting_transition_commitment_ref":Value::Null,
        "resulting_room_state_root":Value::Null,
        "resulting_receipt_root":Value::Null,
        "created_at":at,
        "updated_at":Value::Null,
        "admission_status":"proposed",
    });
    let mut proposed_owner_record = owner_record.clone();
    proposed_owner_record["room_admission"] = proposed_admission;
    let (constructor_room, constructor_receipt, constructor_object, constructor_operation) =
        build_child_admission(prior_room, contract_id, &proposed_owner_record, at)?;
    if constructor_room != *room
        || constructor_receipt != *receipt
        || constructor_object != *object
        || constructor_operation != *operation
    {
        return Err(verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' is not constructor-exact from its predecessor"),
        ));
    }
    let transition_hash = jcs_root(
        "ioi.outcome-room-child-transition-jcs-sha256.v2",
        &json!({
            "outcome_room_ref":room_ref,
            "system_id":system_id,
            "sequence":sequence,
            "predecessor":prior_transition,
            "object_contract_id":contract_id,
            "object_ref":object_ref,
            "payload_root":payload_root,
        }),
    )?;
    let expected_transition_ref = format!(
        "commitment://ioi/outcome-room/{room_tail}/sequence/{sequence}/{}",
        transition_hash.strip_prefix("sha256:").unwrap_or_default()
    );
    if resulting_transition != expected_transition_ref {
        return Err(verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' carries a substituted transition commitment"),
        ));
    }
    let expected_receipt_ref = format!("receipt://outcome-room/{room_tail}/sequence/{sequence}");
    let expected_decision_ref = format!("decision://outcome-room/{room_tail}/sequence/{sequence}");
    let admission = owner_record.get("room_admission").ok_or_else(|| {
        verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' omits its terminal admission"),
        )
    })?;
    let expected_admission = json!({
        "schema_version":BASE_SCHEMA,
        "room_system_id":system_id,
        "outcome_room_ref":room_ref,
        "proposed_or_issued_by_ref":system_id,
        "expected_room_revision":sequence - 1,
        "expected_predecessor_commitment_ref":prior_transition,
        "payload_root":payload_root,
        "admission_policy_ref":room["coordination_policy_ref"],
        "admission_decision_ref":expected_decision_ref,
        "admission_receipt_ref":expected_receipt_ref,
        "admitted_sequence":sequence,
        "resulting_room_revision":sequence,
        "resulting_transition_commitment_ref":resulting_transition,
        "resulting_room_state_root":resulting_room_root,
        "resulting_receipt_root":receipt["receipt_root"],
        "created_at":at,
        "updated_at":at,
        "admission_status":"admitted",
    });
    if admission != &expected_admission {
        return Err(verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' carries a detached admission verdict"),
        ));
    }

    let expected_receipt = json!({
        "schema_version":"ioi.outcome-room-admission-receipt.v2",
        "receipt_ref":expected_receipt_ref,
        "receipt_root":Value::Null,
        "receipt_type":"room_child_admission",
        "system_id":system_id,
        "outcome_room_ref":room_ref,
        "subject_refs":[object_ref],
        "object_contract_id":contract_id,
        "expected_room_revision":sequence - 1,
        "resulting_room_revision":sequence,
        "sequence":sequence,
        "expected_predecessor_commitment_ref":prior_transition,
        "resulting_transition_commitment_ref":resulting_transition,
        "resulting_room_state_root":resulting_room_root,
        "status":"admitted",
        "at":at,
    });
    let (_, expected_receipt) =
        rooted_record(RECEIPT_DOMAIN, "orrc_", "receipt_root", expected_receipt)?;
    let expected_object = json!({
        "schema_version":"ioi.outcome-room-admitted-object.v2",
        "object_root":Value::Null,
        "object_contract_id":contract_id,
        "object_ref":object_ref,
        "outcome_room_ref":room_ref,
        "system_id":system_id,
        "admitted_object":owner_record,
        "at":at,
    });
    let (_, expected_object) =
        rooted_record(OBJECT_DOMAIN, "orobj_", "object_root", expected_object)?;
    let expected_operation = json!({
        "schema_version":"ioi.outcome-room-transition-operation.v2",
        "operation_root":Value::Null,
        "operation_kind":"room_child_admitted",
        "outcome_room_ref":room_ref,
        "system_id":system_id,
        "sequence":sequence,
        "expected_predecessor_commitment_ref":prior_transition,
        "resulting_transition_commitment_ref":resulting_transition,
        "resulting_room_state_root":resulting_room_root,
        "resulting_room":room,
        "object_contract_id":contract_id,
        "object_ref":object_ref,
        "object_root":expected_object["object_root"],
        "receipt_ref":expected_receipt["receipt_ref"],
        "receipt_root":expected_receipt["receipt_root"],
        "at":at,
    });
    let (expected_operation_key, expected_operation) = rooted_record(
        TRANSITION_OPERATION_DOMAIN,
        "orto_",
        "operation_root",
        expected_operation,
    )?;
    if receipt != &expected_receipt
        || object != &expected_object
        || operation != &expected_operation
        || expected_operation_key != intent_key
        || intent.get("at").and_then(Value::as_str) != Some(at)
        || room.get("room_receipt_root") != expected_receipt.get("receipt_root")
        || !room
            .get("admission_and_replay_refs")
            .and_then(Value::as_array)
            .is_some_and(|refs| {
                refs.iter()
                    .filter(|value| value.as_str() == Some(expected_receipt_ref.as_str()))
                    .count()
                    == 1
            })
    {
        return Err(verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' has detached transaction coordinates"),
        ));
    }

    if !owner_record
        .get("information_flow_label_refs")
        .and_then(Value::as_array)
        .is_some_and(|labels| !labels.is_empty())
    {
        return Err(verr(
            "outcome_room_recovery_invalid",
            format!("child intent '{intent_key}' omits its label closure"),
        ));
    }
    if owner_family == super::work_result_routes::RESULT_DIR {
        let goal_run_ref = exact_string(
            owner_record,
            "/goal_run_ref",
            "outcome_room_recovery_invalid",
        )?;
        if runtime_dependencies.is_null()
            || !prior_room
                .get("member_goal_run_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter()
                        .any(|value| value.as_str() == Some(goal_run_ref))
                })
            || owner_record
                .get("invocation_or_run_ref")
                .is_none_or(Value::is_null)
        {
            return Err(verr(
                "outcome_room_recovery_invalid",
                format!("child intent '{intent_key}' detaches its WorkResult runtime owner"),
            ));
        }
        super::goalrun_routes::validate_room_owner_runtime_dependency_intent(
            data_dir,
            prior_room,
            owner_record,
            runtime_dependencies,
        )
        .map_err(|(code, message)| verr(&code, message))?;
    } else {
        if !runtime_dependencies.is_null() {
            return Err(verr(
                "outcome_room_recovery_invalid",
                "OutcomeDelta child intent carries a WorkResult runtime-dependency bundle",
            ));
        }
        super::goalrun_routes::validate_room_owner_runtime_dependencies(
            data_dir,
            prior_room,
            owner_record,
        )
        .map_err(|(code, message)| verr(&code, message))?;
        let proposed_by = exact_string(
            owner_record,
            "/proposed_by_ref",
            "outcome_room_recovery_invalid",
        )?;
        let parent =
            required_projection_records(data_dir, OBJECT_DOMAIN, room_ref, M4_REPLAY_ENTRY_MAX)?
                .into_iter()
                .find(|record| {
                    record.get("object_contract_id").and_then(Value::as_str)
                        == Some("schema://ioi/foundations/work-result/v2")
                        && record.get("object_ref").and_then(Value::as_str) == Some(proposed_by)
                        && record.get("outcome_room_ref").and_then(Value::as_str) == Some(room_ref)
                        && record.get("system_id").and_then(Value::as_str) == Some(system_id)
                })
                .and_then(|record| record.get("admitted_object").cloned())
                .ok_or_else(|| {
                    verr(
                        "outcome_room_recovery_invalid",
                        format!(
                            "child intent '{intent_key}' detaches its admitted WorkResult parent"
                        ),
                    )
                })?;
        canonical_contract("schema://ioi/foundations/work-result/v2", &parent).map_err(|_| {
            verr(
                "outcome_room_recovery_invalid",
                format!("child intent '{intent_key}' resolves a non-canonical parent"),
            )
        })?;
        super::goalrun_routes::validate_room_owner_runtime_dependencies(
            data_dir, prior_room, &parent,
        )
        .map_err(|(code, message)| verr(&code, message))?;
        let parent_labels = parent
            .get("information_flow_label_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| verr("outcome_room_recovery_invalid", "parent labels are absent"))?;
        let delta_labels = owner_record
            .get("information_flow_label_refs")
            .and_then(Value::as_array)
            .expect("validated label array");
        let parent_set = parent_labels
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        let delta_set = delta_labels
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        if parent.get("work_subject_ref") != owner_record.get("work_subject_ref")
            || parent_set.len() != parent_labels.len()
            || delta_set.len() != delta_labels.len()
            || !parent_set.is_subset(&delta_set)
        {
            return Err(verr(
                "outcome_room_recovery_invalid",
                format!("child intent '{intent_key}' substitutes its parent binding or labels"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn complete_pending(data_dir: &str) -> Result<(), VErr> {
    for (intent_key, intent) in strict_intent_family(data_dir, INTENT_DIR)? {
        let room_tail = exact_string(&intent, "/room_tail", "outcome_room_recovery_invalid")?;
        let body = intent.get("request").ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                "create intent omits request",
            )
        })?;
        let at = exact_string(&intent, "/at", "outcome_room_recovery_invalid")?;
        let (room, receipt, operation) = build_room_admission(data_dir, body, room_tail, at)?;
        if intent.get("room") != Some(&room)
            || intent.get("receipt") != Some(&receipt)
            || intent.get("operation") != Some(&operation)
            || key_for(&operation, "operation_root", "orao_")? != intent_key
        {
            return Err(verr(
                "outcome_room_recovery_invalid",
                format!("create intent '{intent_key}' is not canonical"),
            ));
        }
        validate_recovery_room_head(data_dir, room_tail, None, &room)?;
        finalize_room(
            data_dir, room_tail, body, &room, &receipt, &operation, false,
        )?;
    }

    for (intent_key, intent) in strict_intent_family(data_dir, CHILD_INTENT_DIR)? {
        let room_tail = exact_string(&intent, "/room_tail", "outcome_room_recovery_invalid")?;
        let prior_root = exact_string(
            &intent,
            "/prior_room_state_root",
            "outcome_room_recovery_invalid",
        )?;
        let prior_room = intent.get("prior_room").ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                "child intent omits its exact predecessor room",
            )
        })?;
        let room = intent
            .get("room")
            .ok_or_else(|| verr("outcome_room_recovery_invalid", "child intent omits room"))?;
        let receipt = intent.get("receipt").ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                "child intent omits receipt",
            )
        })?;
        let object = intent
            .get("object")
            .ok_or_else(|| verr("outcome_room_recovery_invalid", "child intent omits object"))?;
        let operation = intent.get("operation").ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                "child intent omits operation",
            )
        })?;
        let owner_family = exact_string(
            &intent,
            "/owner_publication_family",
            "outcome_room_recovery_invalid",
        )?;
        let owner_key = exact_string(
            &intent,
            "/owner_publication_key",
            "outcome_room_recovery_invalid",
        )?;
        let owner_record = intent.get("owner_publication_record").ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                "child intent omits owner publication record",
            )
        })?;
        let runtime_dependencies = intent.get("runtime_dependencies").ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                "child intent omits its runtime-dependency disposition",
            )
        })?;
        validate_child_recovery_intent(
            data_dir,
            &intent_key,
            &intent,
            room_tail,
            prior_room,
            room,
            receipt,
            object,
            operation,
            owner_family,
            owner_key,
            owner_record,
            runtime_dependencies,
        )?;
        verify_rooted_record(TRANSITION_OPERATION_DOMAIN, "operation_root", operation)?;
        verify_rooted_record(RECEIPT_DOMAIN, "receipt_root", receipt)?;
        verify_rooted_record(OBJECT_DOMAIN, "object_root", object)?;
        validate_current_room_contract(room)?;
        let operation_key = key_for(operation, "operation_root", "orto_")?;
        if operation_key != intent_key
            || operation.get("resulting_room") != Some(room)
            || object.get("admitted_object") != Some(owner_record)
            || !matches!(
                owner_family,
                super::work_result_routes::RESULT_DIR | super::work_result_routes::DELTA_DIR
            )
            || operation.get("expected_predecessor_commitment_ref")
                == operation.get("resulting_transition_commitment_ref")
        {
            return Err(verr(
                "outcome_room_recovery_invalid",
                format!("child intent '{intent_key}' is detached"),
            ));
        }
        let (owner_identity_field, existing_owner) = if owner_family
            == super::work_result_routes::RESULT_DIR
        {
            let identity = exact_string(
                owner_record,
                "/work_result_id",
                "outcome_room_recovery_invalid",
            )?;
            (
                "work_result_id",
                super::work_result_routes::load_work_result_strict(data_dir, identity).map_err(
                    |message| {
                        verr(
                            "outcome_room_recovery_owner_registry_unreadable",
                            format!(
                                "versioned WorkResult registry is not complete enough to recover '{identity}' ({message})"
                            ),
                        )
                    },
                )?,
            )
        } else {
            let identity = exact_string(
                owner_record,
                "/outcome_delta_id",
                "outcome_room_recovery_invalid",
            )?;
            (
                "outcome_delta_id",
                super::work_result_routes::load_outcome_delta_strict(data_dir, identity).map_err(
                    |message| {
                        verr(
                            "outcome_room_recovery_owner_registry_unreadable",
                            format!(
                                "versioned OutcomeDelta registry is not complete enough to recover '{identity}' ({message})"
                            ),
                        )
                    },
                )?,
            )
        };
        if existing_owner
            .as_ref()
            .is_some_and(|record| record != owner_record)
        {
            return Err(verr(
                "outcome_room_recovery_head_conflict",
                "owner publication slot contains divergent bytes",
            ));
        }
        let expected_owner_key = owner_record
            .get(owner_identity_field)
            .and_then(Value::as_str)
            .map(safe_owner_key)
            .ok_or_else(|| {
                verr(
                    "outcome_room_recovery_invalid",
                    "owner publication identity is absent",
                )
            })?;
        if expected_owner_key != owner_key {
            return Err(verr(
                "outcome_room_recovery_invalid",
                "owner publication key is detached from its record identity",
            ));
        }
        validate_recovery_room_head(data_dir, room_tail, Some(prior_root), room)?;
        if owner_family == super::work_result_routes::RESULT_DIR {
            if runtime_dependencies.is_null() {
                return Err(verr(
                    "outcome_room_recovery_invalid",
                    "WorkResult child intent omits its recoverable runtime dependencies",
                ));
            }
            super::goalrun_routes::converge_room_owner_runtime_dependencies(
                data_dir,
                room,
                owner_record,
                runtime_dependencies,
            )
            .map_err(|(code, message)| verr(&code, message))?;
        } else if !runtime_dependencies.is_null() {
            return Err(verr(
                "outcome_room_recovery_invalid",
                "OutcomeDelta child intent carries a WorkResult runtime-dependency bundle",
            ));
        }
        let receipt_key = key_for(receipt, "receipt_root", "orrc_")?;
        let object_key = key_for(object, "object_root", "orobj_")?;
        reserve_exact_room_successor(data_dir, operation)?;
        admit_required(
            TRANSITION_OPERATION_DOMAIN,
            data_dir,
            &operation_key,
            operation,
        )?;
        admit_required(RECEIPT_DOMAIN, data_dir, &receipt_key, receipt)?;
        admit_required(OBJECT_DOMAIN, data_dir, &object_key, object)?;
        persist_local(RECEIPT_DIR, data_dir, &receipt_key, receipt)?;
        persist_local(OBJECT_DIR, data_dir, &object_key, object)?;
        persist_local(ROOM_DIR, data_dir, room_tail, room)?;
        let room_receipt_ref =
            exact_string(receipt, "/receipt_ref", "outcome_room_recovery_invalid")?;
        super::goalrun_routes::converge_room_owner_backlinks(
            data_dir,
            owner_record,
            room_receipt_ref,
        )
        .map_err(|(code, message)| verr(&code, message))?;
        remove_intent(data_dir, CHILD_INTENT_DIR, &operation_key)?;
    }

    for (intent_key, intent) in strict_intent_family(data_dir, MEMBERSHIP_INTENT_DIR)? {
        let room_tail = exact_string(&intent, "/room_tail", "outcome_room_recovery_invalid")?;
        let prior_root = exact_string(
            &intent,
            "/prior_room_state_root",
            "outcome_room_recovery_invalid",
        )?;
        let prior_room = intent.get("prior_room").ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                "membership intent omits its exact predecessor room",
            )
        })?;
        let prior_goal_run = intent.get("prior_goal_run").ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                "membership intent omits its exact predecessor GoalRun",
            )
        })?;
        let room = intent.get("room").ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                "membership intent omits room",
            )
        })?;
        let receipt = intent.get("receipt").ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                "membership intent omits receipt",
            )
        })?;
        let operation = intent.get("operation").ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                "membership intent omits operation",
            )
        })?;
        let goal_run_id = exact_string(&intent, "/goal_run_id", "outcome_room_recovery_invalid")?;
        let goal_run_ref = exact_string(&intent, "/goal_run_ref", "outcome_room_recovery_invalid")?;
        let expected_goal_root = exact_string(
            &intent,
            "/expected_goal_run_record_root",
            "outcome_room_recovery_invalid",
        )?;
        let resulting_goal_root = exact_string(
            &intent,
            "/resulting_goal_run_record_root",
            "outcome_room_recovery_invalid",
        )?;
        if intent.get("schema_version").and_then(Value::as_str)
            != Some("ioi.outcome-room-membership-admission-intent.v1")
            || prior_room.get("room_state_root").and_then(Value::as_str) != Some(prior_root)
            || state_root(prior_room)? != prior_root
            || prior_room.get("outcome_room_id").and_then(Value::as_str)
                != Some(format!("outcome-room://{room_tail}").as_str())
            || prior_goal_run.get("goal_run_id").and_then(Value::as_str) != Some(goal_run_id)
            || prior_goal_run.get("goal_ref").and_then(Value::as_str) != Some(goal_run_ref)
            || goal_run_record_root(prior_goal_run)? != expected_goal_root
        {
            return Err(verr(
                "outcome_room_recovery_invalid",
                format!("membership intent '{intent_key}' detaches its exact predecessors"),
            ));
        }
        validate_current_room_contract(prior_room)?;
        verify_rooted_record(TRANSITION_OPERATION_DOMAIN, "operation_root", operation)?;
        verify_rooted_record(RECEIPT_DOMAIN, "receipt_root", receipt)?;
        validate_current_room_contract(room)?;
        let transition = MembershipTransition::from_operation(operation)?;
        validate_membership_relation(
            prior_room,
            prior_goal_run,
            prior_room["outcome_room_id"].as_str().unwrap_or_default(),
            goal_run_ref,
            transition,
        )?;
        let at = exact_string(operation, "/at", "outcome_room_recovery_invalid")?;
        let (constructor_room, constructor_receipt, constructor_operation) =
            build_membership_transition(prior_room, prior_goal_run, at, transition)?;
        if constructor_room != *room
            || constructor_receipt != *receipt
            || constructor_operation != *operation
            || intent.get("at").and_then(Value::as_str) != Some(at)
        {
            return Err(verr(
                "outcome_room_recovery_invalid",
                format!(
                    "membership intent '{intent_key}' is not constructor-exact from its predecessors"
                ),
            ));
        }
        let resulting_goal_run = operation.get("resulting_goal_run").ok_or_else(|| {
            verr(
                "outcome_room_recovery_invalid",
                "membership operation omits resulting GoalRun",
            )
        })?;
        let recomputed_resulting_goal_root = goal_run_record_root(resulting_goal_run)?;
        let resulting_backlink = resulting_goal_run
            .get("outcome_room_ref")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        let expected_resulting_backlink = match transition {
            MembershipTransition::Attach => room.get("outcome_room_id").and_then(Value::as_str),
            MembershipTransition::Detach => None,
        };
        let operation_key = key_for(operation, "operation_root", "orto_")?;
        if operation_key != intent_key
            || operation.get("resulting_room") != Some(room)
            || receipt.get("receipt_type").and_then(Value::as_str)
                != Some(transition.receipt_type())
            || resulting_goal_run.get("goal_ref").and_then(Value::as_str) != Some(goal_run_ref)
            || resulting_backlink != expected_resulting_backlink
            || recomputed_resulting_goal_root != resulting_goal_root
            || operation
                .get("expected_goal_run_record_root")
                .and_then(Value::as_str)
                != Some(expected_goal_root)
            || operation
                .get("resulting_goal_run_record_root")
                .and_then(Value::as_str)
                != Some(resulting_goal_root)
        {
            return Err(verr(
                "outcome_room_recovery_invalid",
                format!("membership intent '{intent_key}' is detached"),
            ));
        }
        validate_recovery_room_head(data_dir, room_tail, Some(prior_root), room)?;
        let current_goal_run = strict_goal_run_census(data_dir)?
            .into_iter()
            .find(|record| record.get("goal_run_id").and_then(Value::as_str) == Some(goal_run_id))
            .ok_or_else(|| {
                verr(
                    "outcome_room_recovery_head_conflict",
                    "membership GoalRun disappeared before recovery",
                )
            })?;
        let current_goal_root = goal_run_record_root(&current_goal_run)?;
        if current_goal_root != expected_goal_root && current_goal_root != resulting_goal_root {
            return Err(verr(
                "outcome_room_recovery_head_conflict",
                "membership recovery refuses a divergent GoalRun head",
            ));
        }
        let receipt_key = key_for(receipt, "receipt_root", "orrc_")?;
        reserve_exact_room_successor(data_dir, operation)?;
        admit_required(
            TRANSITION_OPERATION_DOMAIN,
            data_dir,
            &operation_key,
            operation,
        )?;
        admit_required(RECEIPT_DOMAIN, data_dir, &receipt_key, receipt)?;
        persist_local(RECEIPT_DIR, data_dir, &receipt_key, receipt)?;
        stamp_goal_run_membership(
            data_dir,
            goal_run_id,
            goal_run_ref,
            room["outcome_room_id"].as_str().unwrap_or_default(),
            expected_goal_root,
            resulting_goal_root,
            operation["at"].as_str().unwrap_or_default(),
            transition,
        )?;
        persist_local(ROOM_DIR, data_dir, room_tail, room)?;
        remove_intent(data_dir, MEMBERSHIP_INTENT_DIR, &operation_key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORK_RESULT_V2_CONTRACT: &str = "schema://ioi/foundations/work-result/v2";
    const WORK_RESULT_V2_POSITIVE_FIXTURE_PATH: &str =
        "docs/architecture/_meta/schemas/fixtures/work-result-v2/positive-hosted-admitted.json";
    const WORK_RESULT_V2_POSITIVE_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/_meta/schemas/fixtures/work-result-v2/positive-hosted-admitted.json"
    ));
    const OUTCOME_ROOM_V2_POSITIVE_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/_meta/schemas/fixtures/outcome-room-v2/positive-hosted-active.json"
    ));
    const OUTCOME_DELTA_V2_POSITIVE_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/_meta/schemas/fixtures/outcome-delta-v2/positive-hosted-admitted.json"
    ));

    fn owner_child_guard_dir(tag: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!(
            "ioi-outcome-room-owner-child-{tag}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&data_dir).unwrap();
        data_dir
    }

    fn positive_outcome_room_v2() -> Value {
        let room: Value = serde_json::from_str(OUTCOME_ROOM_V2_POSITIVE_FIXTURE)
            .expect("the registered OutcomeRoom v2 positive fixture contains JSON");
        canonical_contract(ROOM_CONTRACT, &room)
            .expect("the registered OutcomeRoom v2 positive fixture validates canonically");
        room
    }

    #[test]
    fn owner_mismatch_refusal_does_not_disclose_principal_or_owner_coordinates() {
        let principal = "user://authenticated-outsider";
        let owner = "user://private-room-owner";
        let room = json!({"owner_or_sponsor_ref": owner});
        let error = authorize_resolved_room_principal(principal, &room)
            .expect_err("a distinct principal must not read owner OutcomeRoom truth");
        assert_eq!(error.0, "outcome_room_owner_mismatch");
        assert!(!error.1.contains(principal));
        assert!(!error.1.contains(owner));
        assert_eq!(
            error.1,
            "the authenticated principal does not own the requested OutcomeRoom"
        );
    }

    fn registered_positive_work_result_v2() -> Value {
        let registration =
            ioi_types::app::generated::architecture_contracts::ARCHITECTURE_CONTRACT_FIXTURES
                .iter()
                .find(|fixture| {
                    fixture.contract_id == WORK_RESULT_V2_CONTRACT
                        && fixture.path == WORK_RESULT_V2_POSITIVE_FIXTURE_PATH
                })
                .expect("the WorkResult v2 positive fixture is registered");
        assert!(registration.expected_schema_accept);
        assert!(registration.expected_accept);
        assert_eq!(registration.expected_failure, None);
        assert_eq!(registration.expected_rule_id, None);

        let record: Value = serde_json::from_str(WORK_RESULT_V2_POSITIVE_FIXTURE)
            .expect("the registered WorkResult v2 positive fixture contains JSON");
        canonical_contract(WORK_RESULT_V2_CONTRACT, &record)
            .expect("the registered WorkResult v2 positive fixture validates canonically");
        record
    }

    fn owner_child_guard_room(record: &Value) -> Value {
        let admission = record
            .get("room_admission")
            .and_then(Value::as_object)
            .expect("the registered positive fixture carries room admission coordinates");
        json!({
            "system_id":admission["room_system_id"],
            "outcome_room_id":admission["outcome_room_ref"],
            "latest_sequence":admission["expected_room_revision"],
            "latest_transition_commitment_ref":admission["expected_predecessor_commitment_ref"],
            "coordination_policy_ref":admission["admission_policy_ref"],
        })
    }

    fn alter_one_canonical_admission_field(
        original: &Value,
        field: &str,
        replacement: Value,
    ) -> Value {
        let pointer = format!("/room_admission/{field}");
        let prior = original
            .pointer(&pointer)
            .cloned()
            .expect("the targeted room-admission field exists");
        assert_ne!(prior, replacement, "the mutation must change its one field");

        let mut altered = original.clone();
        *altered
            .pointer_mut(&pointer)
            .expect("the targeted room-admission field remains addressable") = replacement;
        canonical_contract(WORK_RESULT_V2_CONTRACT, &altered)
            .expect("the one-field admission mutation remains schema and invariant valid");

        let mut reconstructed = altered.clone();
        *reconstructed
            .pointer_mut(&pointer)
            .expect("the targeted room-admission field remains addressable") = prior;
        assert_eq!(
            reconstructed, *original,
            "only the named room-admission field may differ from the registered fixture"
        );
        altered
    }

    fn owner_plane_work_result_candidate(fixture: &Value) -> Value {
        let mut candidate = fixture.clone();
        // The private owner constructor is deliberately pre-admission: these two coordinates
        // become canonical only after `prepare_owner_record_for_room` derives them from the
        // current room head. The registered admitted fixture itself was validated before this
        // conversion; do not mislabel the transitional candidate as a canonical wire record.
        candidate["outcome_room_ref"] = Value::Null;
        candidate["room_admission"] = Value::Null;
        candidate
    }

    fn assert_owner_child_guard_precedes_publication(data_dir: &std::path::Path) {
        for family in [
            super::super::work_result_routes::RESULT_DIR,
            CHILD_INTENT_DIR,
            RECEIPT_DIR,
            OBJECT_DIR,
        ] {
            assert!(
                !data_dir.join(family).exists(),
                "refused owner child unexpectedly published '{family}'"
            );
        }
    }

    #[test]
    fn delta_projection_parent_refuses_partial_versioned_work_result_truth_without_mutation() {
        let data_dir = owner_child_guard_dir("delta-parent-versioned-census");
        let room_ref = "outcome-room://m4/strict-projection-parent";
        let result_ref = "work-result://m4/strict-projection-parent";
        let delta_ref = "outcome-delta://m4/strict-projection-parent";
        let delta = json!({
            "schema_version":"ioi.foundations.outcome-delta.v2",
            "outcome_delta_id":delta_ref,
            "proposed_by_ref":result_ref,
        });
        let delta_dir = data_dir.join(super::super::work_result_routes::DELTA_DIR);
        let result_dir = data_dir.join(super::super::work_result_routes::RESULT_DIR);
        std::fs::create_dir_all(&delta_dir).unwrap();
        std::fs::create_dir_all(&result_dir).unwrap();
        let delta_path = delta_dir.join(format!(
            "{}.json",
            super::super::goalrun_routes::room_owner_record_key(delta_ref)
        ));
        let result_path = result_dir.join(format!(
            "{}.json",
            super::super::goalrun_routes::room_owner_record_key(result_ref)
        ));
        let delta_bytes = serde_json::to_vec(&delta).unwrap();
        let malformed_result_bytes = b"{not-json";
        std::fs::write(&delta_path, &delta_bytes).unwrap();
        std::fs::write(&result_path, malformed_result_bytes).unwrap();

        let error = verify_owner_projection_backlinks(
            data_dir.to_str().unwrap(),
            room_ref,
            "schema://ioi/foundations/outcome-delta/v2",
            delta_ref,
            &delta,
            "receipt://outcome-room/m4/strict-projection-parent",
        )
        .unwrap_err();
        assert_eq!(error.0, "outcome_room_projection_owner_backlink_unreadable");
        assert_eq!(std::fs::read(&delta_path).unwrap(), delta_bytes);
        assert_eq!(std::fs::read(&result_path).unwrap(), malformed_result_bytes);
        assert_eq!(std::fs::read_dir(&delta_dir).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(&result_dir).unwrap().count(), 1);
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn projection_object_validation_order_is_admission_order_not_agentgres_content_order() {
        let object = |object_ref: &str, object_root: &str, admitted_sequence: Option<u64>| {
            json!({
                "object_ref":object_ref,
                "object_root":object_root,
                "admitted_object":{
                    "room_admission":{
                        "admitted_sequence":admitted_sequence,
                    },
                },
            })
        };
        let result = object(
            "work-result://m4/admission-order",
            &format!("sha256:{}", "f".repeat(64)),
            Some(4),
        );
        let delta = object(
            "outcome-delta://m4/admission-order",
            &format!("sha256:{}", "0".repeat(64)),
            Some(5),
        );
        let invalid = object(
            "work-result://m4/missing-admission-order",
            &format!("sha256:{}", "1".repeat(64)),
            None,
        );

        let mut content_hash_order = vec![delta.clone(), invalid.clone(), result.clone()];
        let mut reversed_order = content_hash_order.iter().cloned().rev().collect::<Vec<_>>();
        sort_projection_objects_by_admission_order(&mut content_hash_order);
        sort_projection_objects_by_admission_order(&mut reversed_order);

        let refs = |records: &[Value]| {
            records
                .iter()
                .map(|record| record["object_ref"].as_str().unwrap_or_default().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(refs(&content_hash_order), refs(&reversed_order));
        assert_eq!(
            refs(&content_hash_order),
            vec![
                "work-result://m4/admission-order".to_owned(),
                "outcome-delta://m4/admission-order".to_owned(),
                "work-result://m4/missing-admission-order".to_owned(),
            ]
        );
    }

    #[test]
    fn owner_publication_preflight_refuses_malformed_and_relocated_registry_without_mutation() {
        let data_dir = owner_child_guard_dir("owner-publication-strict-census");
        let result_dir = data_dir.join(super::super::work_result_routes::RESULT_DIR);
        std::fs::create_dir_all(&result_dir).unwrap();
        let candidate = json!({
            "schema_version":"ioi.foundations.work-result.v2",
            "work_result_id":"work-result://m4/strict-preflight-candidate",
        });

        let malformed_path = result_dir.join("malformed.json");
        let malformed_bytes = b"{not-json";
        std::fs::write(&malformed_path, malformed_bytes).unwrap();
        let malformed_error = owner_publication_slot(data_dir.to_str().unwrap(), &candidate)
            .expect_err("partial registry truth must fail before publication");
        assert_eq!(
            malformed_error.0,
            "outcome_room_owner_publication_registry_unreadable"
        );
        assert_eq!(std::fs::read(&malformed_path).unwrap(), malformed_bytes);
        std::fs::remove_file(&malformed_path).unwrap();

        let relocated_path = result_dir.join("relocated.json");
        let relocated = json!({
            "schema_version":"ioi.foundations.work-result.v2",
            "work_result_id":"work-result://m4/relocated-existing",
        });
        let relocated_bytes = serde_json::to_vec(&relocated).unwrap();
        std::fs::write(&relocated_path, &relocated_bytes).unwrap();
        let relocated_error = owner_publication_slot(data_dir.to_str().unwrap(), &candidate)
            .expect_err("a relocated record must fail before publication");
        assert_eq!(
            relocated_error.0,
            "outcome_room_owner_publication_registry_unreadable"
        );
        assert_eq!(std::fs::read(&relocated_path).unwrap(), relocated_bytes);
        assert_eq!(std::fs::read_dir(&result_dir).unwrap().count(), 1);
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn terminal_outcome_delta_retry_is_semantic_write_free_and_allows_distinct_future_delta() {
        let data_dir = owner_child_guard_dir("terminal-delta-semantic-retry");
        let delta_dir = data_dir.join(super::super::work_result_routes::DELTA_DIR);
        std::fs::create_dir_all(&delta_dir).unwrap();
        let mut existing: Value = serde_json::from_str(OUTCOME_DELTA_V2_POSITIVE_FIXTURE)
            .expect("the registered OutcomeDelta v2 fixture contains JSON");
        existing["precondition_and_invariant_refs"] =
            json!(["policy://alpha/retain", "state://alpha/revision/7"]);
        existing["verifier_and_acceptance_refs"] =
            json!(["gate://alpha/accept", "verifier-path://alpha/one"]);
        existing["information_flow_label_refs"] =
            json!(["ifc-label://alpha/private", "ifc-label://alpha/public"]);
        canonical_contract("schema://ioi/foundations/outcome-delta/v2", &existing)
            .expect("the expanded existing OutcomeDelta remains canonical");
        let existing_ref = existing["outcome_delta_id"].as_str().unwrap();
        let existing_path = delta_dir.join(format!(
            "{}.json",
            super::super::goalrun_routes::room_owner_record_key(existing_ref)
        ));
        let existing_bytes = serde_json::to_vec(&existing).unwrap();
        std::fs::write(&existing_path, &existing_bytes).unwrap();

        let mut exact_retry = existing.clone();
        exact_retry["outcome_delta_id"] = json!("outcome-delta://alpha/retry");
        exact_retry["status"] = json!("proposed");
        exact_retry["precondition_and_invariant_refs"] =
            json!(["state://alpha/revision/7", "policy://alpha/retain"]);
        exact_retry["verifier_and_acceptance_refs"] =
            json!(["verifier-path://alpha/one", "gate://alpha/accept"]);
        exact_retry["information_flow_label_refs"] =
            json!(["ifc-label://alpha/public", "ifc-label://alpha/private"]);
        exact_retry["room_admission"]["admission_decision_ref"] = json!("decision://alpha/retry");
        exact_retry["room_admission"]["admission_receipt_ref"] = json!("receipt://alpha/retry");
        let refusal = refuse_terminal_outcome_delta_retry(data_dir.to_str().unwrap(), &exact_retry)
            .expect_err("the complete semantic retry must be refused");
        assert_eq!(refusal.0, "outcome_room_delta_post_terminal_retry_refused");
        assert_eq!(std::fs::read(&existing_path).unwrap(), existing_bytes);
        assert_eq!(std::fs::read_dir(&delta_dir).unwrap().count(), 1);

        let mut distinct = exact_retry;
        distinct["payload_ref"] = json!("state-delta://alpha/two");
        refuse_terminal_outcome_delta_retry(data_dir.to_str().unwrap(), &distinct)
            .expect("a semantically distinct future OutcomeDelta remains admissible");

        let source = include_str!("outcome_room_system_routes.rs");
        let admission = source
            .find("pub(crate) fn admit_persisted_owner_record")
            .expect("owner admission seam exists");
        let admission = &source[admission..];
        let lock = admission
            .find("ROOM_MUTATION_LOCK")
            .expect("owner admission takes the room mutation lock");
        let semantic_fence = admission
            .find("refuse_terminal_outcome_delta_retry")
            .expect("owner admission applies the semantic retry fence");
        let durable_finalize = admission
            .find("finalize_child(")
            .expect("owner admission retains its durable finalizer");
        assert!(
            lock < semantic_fence && semantic_fence < durable_finalize,
            "the semantic retry fence must run under the room lock and before every child write"
        );
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn pending_child_owner_registry_census_wins_before_migration_and_preserves_intent() {
        let data_dir = owner_child_guard_dir("pending-owner-registry-preflight");
        let intent_dir = data_dir.join(CHILD_INTENT_DIR);
        let result_dir = data_dir.join(super::super::work_result_routes::RESULT_DIR);
        std::fs::create_dir_all(&intent_dir).unwrap();
        std::fs::create_dir_all(&result_dir).unwrap();
        let owner_record = registered_positive_work_result_v2();
        let intent_path = intent_dir.join("pending-owner.json");
        let intent_bytes = serde_json::to_vec(&json!({
            "owner_publication_family":super::super::work_result_routes::RESULT_DIR,
            "owner_publication_record":owner_record,
        }))
        .unwrap();
        std::fs::write(&intent_path, &intent_bytes).unwrap();

        let malformed_path = result_dir.join("malformed-pending-owner.json");
        let malformed_bytes = b"{not-json";
        std::fs::write(&malformed_path, malformed_bytes).unwrap();
        let malformed = preflight_pending_owner_registry_census(data_dir.to_str().unwrap())
            .expect_err("pending recovery must own the malformed-registry refusal");
        assert_eq!(
            malformed.0,
            "outcome_room_recovery_owner_registry_unreadable"
        );
        assert_eq!(std::fs::read(&malformed_path).unwrap(), malformed_bytes);
        assert_eq!(std::fs::read(&intent_path).unwrap(), intent_bytes);
        assert_eq!(std::fs::read_dir(&intent_dir).unwrap().count(), 1);
        std::fs::remove_file(&malformed_path).unwrap();

        let relocated_path = result_dir.join("relocated-pending-owner.json");
        let relocated_bytes = serde_json::to_vec(&json!({
            "schema_version":"ioi.foundations.work-result.v2",
            "work_result_id":"work-result://m4/relocated-pending-owner",
        }))
        .unwrap();
        std::fs::write(&relocated_path, &relocated_bytes).unwrap();
        let relocated = preflight_pending_owner_registry_census(data_dir.to_str().unwrap())
            .expect_err("pending recovery must own the relocated-registry refusal");
        assert_eq!(
            relocated.0,
            "outcome_room_recovery_owner_registry_unreadable"
        );
        assert_eq!(std::fs::read(&relocated_path).unwrap(), relocated_bytes);
        assert_eq!(std::fs::read(&intent_path).unwrap(), intent_bytes);
        assert_eq!(std::fs::read_dir(&intent_dir).unwrap().count(), 1);

        let startup = include_str!("../hypervisor-daemon.rs");
        let recovery_preflight = startup
            .find("outcome_room_system_routes::preflight_pending_owner_registry_census")
            .expect("startup invokes the pending-child owner-registry preflight");
        let compatibility_migration = startup
            .find("goalrun_routes::migrate_legacy_goal_run_work_results")
            .expect("startup retains the predecessor compatibility migration");
        assert!(
            recovery_preflight < compatibility_migration,
            "pending OutcomeRoom recovery must own its typed owner-registry refusal before generic migration"
        );

        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn goal_run_projection_census_refuses_non_record_entries_without_mutation() {
        let data_dir = owner_child_guard_dir("goal-run-census-non-record");
        let goal_run_dir = data_dir.join("goal-runs");
        std::fs::create_dir_all(&goal_run_dir).unwrap();
        let non_record_path = goal_run_dir.join("projection-shadow");
        let non_record_bytes = b"shadow bytes";
        std::fs::write(&non_record_path, non_record_bytes).unwrap();

        let error = strict_goal_run_census(data_dir.to_str().unwrap())
            .expect_err("non-record registry entries must prevent partial projection truth");
        assert_eq!(error.0, "outcome_room_projection_goal_runs_unreadable");
        assert_eq!(std::fs::read(&non_record_path).unwrap(), non_record_bytes);
        assert_eq!(std::fs::read_dir(&goal_run_dir).unwrap().count(), 1);
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn owner_child_admission_refuses_wrong_system_guard_before_publication() {
        let data_dir = owner_child_guard_dir("wrong-system");
        let fixture = registered_positive_work_result_v2();
        let room = owner_child_guard_room(&fixture);
        let record = alter_one_canonical_admission_field(
            &fixture,
            "room_system_id",
            json!("system://ioi/outcome-room/wrong"),
        );

        let error = prepare_owner_record_for_room(
            data_dir.to_str().unwrap(),
            &room,
            &record,
            "2026-07-30T00:00:00Z",
            None,
        )
        .unwrap_err();
        assert_eq!(error.0, "outcome_room_wrong_system_child_refused");
        assert_owner_child_guard_precedes_publication(&data_dir);
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn owner_child_admission_refuses_stale_child_guard_before_publication() {
        let data_dir = owner_child_guard_dir("stale-child");
        let fixture = registered_positive_work_result_v2();
        let room = owner_child_guard_room(&fixture);
        let record = alter_one_canonical_admission_field(
            &fixture,
            "expected_room_revision",
            json!(room["latest_sequence"].as_u64().unwrap() - 1),
        );

        let error = prepare_owner_record_for_room(
            data_dir.to_str().unwrap(),
            &room,
            &record,
            "2026-07-30T00:00:00Z",
            None,
        )
        .unwrap_err();
        assert_eq!(error.0, "outcome_room_stale_child_refused");
        assert_owner_child_guard_precedes_publication(&data_dir);
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn owner_child_admission_refuses_stale_verdict_guard_before_publication() {
        let data_dir = owner_child_guard_dir("stale-verdict");
        let fixture = registered_positive_work_result_v2();
        let room = owner_child_guard_room(&fixture);
        let mut record = fixture.clone();
        record["room_admission"]["admission_status"] = json!("proposed");
        for field in [
            "admitted_sequence",
            "resulting_room_revision",
            "resulting_transition_commitment_ref",
            "resulting_room_state_root",
            "resulting_receipt_root",
        ] {
            record["room_admission"][field] = Value::Null;
        }
        canonical_contract(WORK_RESULT_V2_CONTRACT, &record)
            .expect("the proposed probe is canonical before the stale terminal refs are refused");
        assert!(
            record["room_admission"]["admission_decision_ref"].is_string(),
            "the canonical proposed probe deliberately retains one terminal verdict ref"
        );

        let error = prepare_owner_record_for_room(
            data_dir.to_str().unwrap(),
            &room,
            &record,
            "2026-07-30T00:00:00Z",
            None,
        )
        .unwrap_err();
        assert_eq!(error.0, "outcome_room_stale_verdict_refused");
        assert_owner_child_guard_precedes_publication(&data_dir);
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn owner_child_admission_refuses_missing_or_empty_projection_labels_guard_before_publication() {
        let data_dir = owner_child_guard_dir("projection-labels");
        let fixture = registered_positive_work_result_v2();
        let room = owner_child_guard_room(&fixture);

        let mut empty_admitted = fixture.clone();
        empty_admitted["information_flow_label_refs"] = json!([]);
        canonical_contract(WORK_RESULT_V2_CONTRACT, &empty_admitted)
            .expect("an empty label array remains schema-valid before the room guard refuses it");
        let empty = owner_plane_work_result_candidate(&empty_admitted);

        let mut missing_admitted = fixture.clone();
        missing_admitted
            .as_object_mut()
            .expect("the registered admitted fixture is an object")
            .remove("information_flow_label_refs")
            .expect("the required label field existed before the missing-field probe");
        assert!(
            canonical_contract(WORK_RESULT_V2_CONTRACT, &missing_admitted).is_err(),
            "the registered schema must continue to reject a missing required label field"
        );
        let missing = owner_plane_work_result_candidate(&missing_admitted);

        for record in [&empty, &missing] {
            let error = prepare_owner_record_for_room(
                data_dir.to_str().unwrap(),
                &room,
                record,
                "2026-07-30T00:00:00Z",
                None,
            )
            .unwrap_err();
            assert_eq!(error.0, "outcome_room_projection_labels_required");
            assert_owner_child_guard_precedes_publication(&data_dir);
        }
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn deterministic_room_identity_is_system_bound() {
        let first = room_tail_for_system("system://example/one").unwrap();
        let again = room_tail_for_system("system://example/one").unwrap();
        let other = room_tail_for_system("system://example/two").unwrap();
        assert_eq!(first, again);
        assert_ne!(first, other);
        assert_eq!(first.len(), 67);
    }

    #[test]
    fn selected_m4_profile_refuses_later_stage_coordinates() {
        let selected = positive_outcome_room_v2();
        require_selected_m4_profile(&selected).expect("the hosted M4 fixture is selected");

        for (field, replacement, expected_code) in [
            (
                "coordination_topology",
                json!("federated_admission"),
                "outcome_room_federated_admission_unavailable",
            ),
            (
                "room_mode",
                json!("cross_org"),
                "outcome_room_external_participation_unavailable",
            ),
            (
                "room_mode",
                json!("open_challenge"),
                "outcome_room_external_participation_unavailable",
            ),
            (
                "discovery_and_external_admission_policy_refs",
                json!(["aiip://channel/later-stage"]),
                "outcome_room_external_discovery_unavailable",
            ),
            (
                "multi_party_collaboration_ref",
                json!("collaboration://later-stage"),
                "outcome_room_multi_party_collaboration_unavailable",
            ),
            (
                "settlement_policy_ref",
                json!("policy://later-stage/settlement"),
                "outcome_room_settlement_unavailable",
            ),
        ] {
            let mut candidate = selected.clone();
            candidate[field] = replacement;
            let error = require_selected_m4_profile(&candidate)
                .expect_err("a later-stage coordinate must not enter the selected M4 runtime");
            assert_eq!(error.0, expected_code, "unexpected refusal for {field}");
        }
    }

    #[test]
    fn selected_m4_host_resolves_to_the_active_system() {
        let system = json!({"system_id":"system://ioi/m4/host"});
        let selected = json!({"host_domain_ref":"system://ioi/m4/host"});
        require_selected_m4_host(&selected, &system)
            .expect("the selected M4 host resolves to the exact active System");

        let substituted = json!({"host_domain_ref":"domain://ioi/substituted-host"});
        let error = require_selected_m4_host(&substituted, &system)
            .expect_err("an unresolved caller-named domain must not pose as the hosted owner");
        assert_eq!(error.0, "outcome_room_host_domain_owner_mismatch");
        let (status, _) = classify(error);
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn membership_detach_transition_is_dual_head_rooted() {
        let room = positive_outcome_room_v2();
        let goal_run = json!({
            "goal_run_id":"demo/1",
            "goal_ref":"goal://demo/1",
            "outcome_room_ref":"outcome-room://demo",
            "updated_at":"2026-07-30T11:59:00Z",
        });
        validate_membership_relation(
            &room,
            &goal_run,
            "outcome-room://demo",
            "goal://demo/1",
            MembershipTransition::Detach,
        )
        .unwrap();
        let expected_goal_root = goal_run_record_root(&goal_run).unwrap();
        let (detached_room, receipt, operation) = build_membership_transition(
            &room,
            &goal_run,
            "2026-07-30T12:00:00Z",
            MembershipTransition::Detach,
        )
        .unwrap();

        assert_eq!(detached_room["latest_sequence"], json!(2));
        assert_eq!(detached_room["member_goal_run_refs"], json!([]));
        assert_eq!(
            receipt["receipt_type"],
            json!("goal_run_membership_detachment")
        );
        assert_eq!(
            operation["operation_kind"],
            json!("goal_run_membership_detached")
        );
        assert_eq!(
            operation["expected_goal_run_record_root"],
            json!(expected_goal_root)
        );
        assert_eq!(
            operation["resulting_goal_run"]["outcome_room_ref"],
            Value::Null
        );
        assert_eq!(
            operation["resulting_goal_run_record_root"],
            json!(goal_run_record_root(&operation["resulting_goal_run"]).unwrap())
        );
        assert_eq!(
            detached_room["room_receipt_root"], receipt["receipt_root"],
            "the detached room head must seal the same rooted receipt"
        );
        verify_rooted_record(TRANSITION_OPERATION_DOMAIN, "operation_root", &operation).unwrap();
        verify_rooted_record(RECEIPT_DOMAIN, "receipt_root", &receipt).unwrap();
        canonical_contract(ROOM_CONTRACT, &detached_room).unwrap();
    }

    #[test]
    fn membership_attach_refuses_generic_result_when_nullable_alias_is_null() {
        let data_dir = owner_child_guard_dir("attach-after-generic-result");
        persist_local(
            super::super::work_result_routes::RESULT_DIR,
            data_dir.to_str().unwrap(),
            "wr_preexisting",
            &json!({
                "schema_version":"ioi.hypervisor.work-result.v1",
                "work_result_id":"work-result://wr_preexisting",
                "goal_ref":"goal://demo/1",
                "goal_run_ref":Value::Null,
            }),
        )
        .unwrap();

        let error = refuse_attach_with_preexisting_goal_truth(
            data_dir.to_str().unwrap(),
            "goal://demo/1",
            MembershipTransition::Attach,
        )
        .expect_err("roomless generic result truth must fence later room attachment");
        assert_eq!(
            error.0,
            "outcome_room_goal_run_attach_preexisting_work_truth"
        );
        assert!(
            refuse_attach_with_preexisting_goal_truth(
                data_dir.to_str().unwrap(),
                "goal://unrelated",
                MembershipTransition::Attach,
            )
            .is_ok(),
            "the guard must remain scoped to the exact GoalRun"
        );
        assert!(
            refuse_attach_with_preexisting_goal_truth(
                data_dir.to_str().unwrap(),
                "goal://demo/1",
                MembershipTransition::Detach,
            )
            .is_ok(),
            "pre-existing generic truth constrains attachment, not detachment"
        );
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn membership_detach_guards_wrong_room_and_missing_reciprocity() {
        let data_dir = owner_child_guard_dir("membership-detach-refusal");
        let assert_no_publication = || {
            assert_eq!(
                std::fs::read_dir(&data_dir).unwrap().count(),
                0,
                "a reciprocal-detach guard must refuse before any durable publication"
            );
        };
        let room = positive_outcome_room_v2();
        let foreign = json!({
            "goal_ref":"goal://demo/1",
            "outcome_room_ref":"outcome-room://foreign",
        });
        assert_eq!(
            validate_membership_relation(
                &room,
                &foreign,
                "outcome-room://demo",
                "goal://demo/1",
                MembershipTransition::Detach,
            )
            .unwrap_err()
            .0,
            "outcome_room_goal_run_wrong_room"
        );
        assert_no_publication();

        let missing_backlink = json!({
            "goal_ref":"goal://demo/1",
            "outcome_room_ref":Value::Null,
        });
        assert_eq!(
            validate_membership_relation(
                &room,
                &missing_backlink,
                "outcome-room://demo",
                "goal://demo/1",
                MembershipTransition::Detach,
            )
            .unwrap_err()
            .0,
            "outcome_room_goal_run_not_member"
        );
        assert_no_publication();

        let mut missing_room_edge = room;
        missing_room_edge["member_goal_run_refs"] = json!([]);
        let goal_run = json!({
            "goal_ref":"goal://demo/1",
            "outcome_room_ref":"outcome-room://demo",
        });
        assert_eq!(
            validate_membership_relation(
                &missing_room_edge,
                &goal_run,
                "outcome-room://demo",
                "goal://demo/1",
                MembershipTransition::Detach,
            )
            .unwrap_err()
            .0,
            "outcome_room_goal_run_not_member"
        );
        assert_no_publication();
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn replay_projection_never_exports_child_bytes() {
        let operation = json!({
            "operation_root":"sha256:a",
            "operation_kind":"room_child_admitted",
            "outcome_room_ref":"outcome-room://or_a",
            "system_id":"system://a",
            "sequence":1,
            "expected_predecessor_commitment_ref":"commitment://zero",
            "resulting_transition_commitment_ref":"commitment://one",
            "resulting_room_state_root":"sha256:b",
            "object_contract_id":"schema://object",
            "object_ref":"finding://one",
            "object_root":"sha256:c",
            "receipt_ref":"receipt://one",
            "receipt_root":"sha256:d",
            "at":"2026-07-30T00:00:00Z",
            "admitted_object":{"sensitive":"must-not-export"},
        });
        let projection = safe_replay_operation(&operation);
        assert!(projection.get("admitted_object").is_none());
        assert!(!serde_json::to_string(&projection)
            .unwrap()
            .contains("must-not-export"));
    }

    #[test]
    fn graph_and_discussion_projections_are_registered_non_writable_ref_views() {
        let mut refs = ProjectionRefs::default();
        refs.participant_refs
            .insert("participant-state://room/one".to_owned());
        refs.frontier_item_refs
            .insert("frontier://room/one".to_owned());
        refs.work_claim_refs
            .insert("work-claim://room/one".to_owned());
        refs.attempt_refs.insert("attempt://room/one".to_owned());
        refs.finding_refs.insert("finding://room/one".to_owned());
        refs.verifier_challenge_refs
            .insert("verifier-challenge://room/one".to_owned());
        refs.work_result_refs
            .insert("work-result://room/one".to_owned());
        refs.outcome_delta_refs
            .insert("outcome-delta://room/one".to_owned());
        refs.information_flow_label_refs
            .insert("ifc-label://room/public".to_owned());
        let snapshot = ProjectionSnapshot {
            room: json!({
                "outcome_room_id":"outcome-room://or_projection_test",
                "latest_sequence":9,
                "room_state_root":format!("sha256:{}", "a".repeat(64)),
                "visibility_policy_ref":"policy://room/visibility",
            }),
            member_goal_run_refs: BTreeSet::from(["goal://room/one".to_owned()]),
            refs,
            source_admission_receipt_refs: vec!["receipt://room/sequence/9".to_owned()],
            permitted_subject_refs: BTreeSet::from(["system://room/host".to_owned()]),
        };
        let (graph, discussion) = projection_values(&snapshot, "2026-07-30T12:00:00Z").unwrap();
        assert_eq!(graph["authoritative"], json!(false));
        assert_eq!(graph["client_writable"], json!(false));
        assert_eq!(graph["work_result_refs"], json!(["work-result://room/one"]));
        assert_eq!(
            graph["outcome_delta_refs"],
            json!(["outcome-delta://room/one"])
        );
        assert_eq!(discussion["authoritative"], json!(false));
        assert_eq!(discussion["client_writable"], json!(false));
        assert_eq!(discussion["message_refs"], json!([]));
        assert_eq!(discussion["redaction_summary_refs"], json!([]));
        assert_eq!(
            discussion["information_flow_label_refs"],
            json!(["ifc-label://room/public"])
        );
    }

    #[test]
    fn projection_ref_sources_fail_closed_and_honest_empty_labels_are_allowed() {
        let duplicate = json!({"refs":["goal://one","goal://one"]});
        assert_eq!(
            bounded_ref_set(&duplicate, "refs", "projection_refs_invalid")
                .unwrap_err()
                .0,
            "projection_refs_invalid"
        );
        let refs = ProjectionRefs::default();
        require_projection_labels(&refs, 0)
            .expect("a room with no label-bearing children honestly projects an empty label set");
        assert_eq!(
            require_projection_labels(&refs, 1).unwrap_err().0,
            "outcome_room_projection_labels_unresolved"
        );
        let mut labeled = ProjectionRefs::default();
        labeled
            .information_flow_label_refs
            .insert("ifc-label://room/public".to_owned());
        require_projection_labels(&labeled, 1)
            .expect("one label-bearing child with one retained label projects");
    }

    #[test]
    fn selected_room_contract_refuses_each_finite_bound() {
        let mut over_refs = positive_outcome_room_v2();
        over_refs["constraint_refs"] = Value::Array(
            (0..=M4_ROOM_REF_SET_MAX)
                .map(|index| json!(format!("constraint://m4/{index}")))
                .collect(),
        );
        assert!(validate_current_room_contract(&over_refs).is_err());

        let mut over_objective = positive_outcome_room_v2();
        over_objective["objective"] = json!("x".repeat(4097));
        assert!(validate_current_room_contract(&over_objective).is_err());

        let mut over_sequence = positive_outcome_room_v2();
        over_sequence["latest_sequence"] = json!(128);
        assert!(validate_current_room_contract(&over_sequence).is_err());
    }

    #[test]
    fn terminal_room_sequence_refuses_membership_and_child_builds_before_effects() {
        let mut room = positive_outcome_room_v2();
        room["latest_sequence"] = json!(M4_TRANSITION_ENTRY_MAX);
        let goal_run = json!({
            "goal_run_id":"demo/terminal",
            "goal_ref":"goal://demo/terminal",
            "outcome_room_ref":room["outcome_room_id"],
            "updated_at":"2026-07-30T11:59:00Z",
        });
        for transition in [MembershipTransition::Attach, MembershipTransition::Detach] {
            let error =
                build_membership_transition(&room, &goal_run, "2026-07-30T12:00:00Z", transition)
                    .expect_err("sequence 128 must never be constructed");
            assert_eq!(error.0, "outcome_room_transition_capacity_exceeded");
        }

        let proposed_child = json!({"schema_version":"ioi.foundations.work-result.v2"});
        let error = build_child_admission(
            &room,
            WORK_RESULT_V2_CONTRACT,
            &proposed_child,
            "2026-07-30T12:00:00Z",
        )
        .expect_err("a child must not be admitted beyond the terminal room sequence");
        assert_eq!(error.0, "outcome_room_transition_capacity_exceeded");
    }

    #[test]
    fn projection_cardinality_and_http_envelope_bounds_fail_typed() {
        let room = positive_outcome_room_v2();
        let operations = (0..=M4_REPLAY_ENTRY_MAX)
            .map(|_| (ADMISSION_OPERATION_DOMAIN, json!({})))
            .collect::<Vec<_>>();
        assert_eq!(
            verify_projection_operation_chain(&room, operations)
                .unwrap_err()
                .0,
            "outcome_room_projection_source_unavailable"
        );
        assert_eq!(
            verify_projection_receipts(
                &room,
                &[],
                (0..=M4_REPLAY_ENTRY_MAX).map(|_| json!({})).collect(),
            )
            .unwrap_err()
            .0,
            "outcome_room_projection_source_unavailable"
        );
        let object_error = match verify_projection_objects(
            "unused",
            &room,
            &[],
            (0..=M4_REPLAY_ENTRY_MAX).map(|_| json!({})).collect(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("an over-bound admitted-object census must fail closed"),
        };
        assert_eq!(object_error.0, "outcome_room_projection_source_unavailable");
        assert_eq!(
            classify(verr(
                "outcome_room_projection_response_too_large",
                "read envelope is over bound",
            ))
            .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            classify(verr(
                "outcome_room_projection_source_unavailable",
                "projection source is over bound",
            ))
            .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            classify(verr(
                "outcome_room_response_too_large",
                "mutation envelope is over bound",
            ))
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[test]
    fn runtime_ref_and_serialized_body_guards_refuse_overflow() {
        let over_refs = json!({
            "refs": (0..=M4_ROOM_REF_SET_MAX)
                .map(|index| format!("goal://m4/{index}"))
                .collect::<Vec<_>>()
        });
        assert_eq!(
            bounded_ref_set(&over_refs, "refs", "projection_refs_invalid")
                .unwrap_err()
                .0,
            "projection_refs_invalid"
        );

        let over_body = json!({"body":"x".repeat(M4_SERIALIZED_BODY_MAX)});
        assert_eq!(
            ensure_serialized_body_bound(&over_body, "outcome_room_response_too_large")
                .unwrap_err()
                .0,
            "outcome_room_response_too_large"
        );
    }

    #[test]
    fn owner_convergence_summary_contains_refs_and_heads_not_duplicate_bodies() {
        let room = json!({
            "outcome_room_id":"outcome-room://or_a",
            "latest_sequence":7,
            "latest_transition_commitment_ref":"commitment://room/7",
            "room_state_root":format!("sha256:{}", "a".repeat(64)),
        });
        let object = json!({
            "object_contract_id":"schema://ioi/foundations/work-result/v2",
            "object_ref":"work-result://m4/result",
            "object_root":format!("sha256:{}", "b".repeat(64)),
            "admitted_object":{
                "goal_run_ref":"goal://m4/run",
                "invocation_or_run_ref":"harness-invocation://m4/run",
            },
        });
        let receipt = json!({
            "receipt_ref":"receipt://outcome-room/or_a/sequence/7",
            "receipt_root":format!("sha256:{}", "c".repeat(64)),
        });
        let summary = owner_convergence_summary(&room, &object, &receipt).unwrap();
        assert_eq!(summary["goal_run_ref"], json!("goal://m4/run"));
        assert_eq!(
            summary["invocation_or_run_ref"],
            json!("harness-invocation://m4/run")
        );
        assert_eq!(summary["resulting_room_revision"], json!(7));
        for duplicated_body in ["goal_run", "harness_invocation", "work_result"] {
            assert!(summary.get(duplicated_body).is_none());
        }
        ensure_serialized_body_bound(&summary, "outcome_room_response_too_large").unwrap();

        let mut delta_object = object;
        delta_object["object_contract_id"] = json!("schema://ioi/foundations/outcome-delta/v2");
        delta_object["object_ref"] = json!("outcome-delta://m4/delta");
        delta_object["admitted_object"] = json!({
            "work_subject_ref":"goal://m4/run",
            "proposed_by_ref":"work-result://m4/result",
        });
        let delta_summary = owner_convergence_summary(&room, &delta_object, &receipt).unwrap();
        assert_eq!(delta_summary["goal_run_ref"], json!("goal://m4/run"));
        assert_eq!(
            delta_summary["parent_work_result_ref"],
            json!("work-result://m4/result")
        );

        let work_result_response = owner_admission_http_response(
            "schema://ioi/foundations/work-result/v2",
            json!({"summary":summary}),
        );
        assert_eq!(
            work_result_response
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["admission", "ok"])
        );
        let delta_response = owner_admission_http_response(
            "schema://ioi/foundations/outcome-delta/v2",
            json!({"summary":delta_summary}),
        );
        assert_eq!(
            delta_response
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["acceptance_granted", "admission", "effect_executed", "ok",])
        );
        assert_eq!(delta_response["effect_executed"], json!(false));
        assert_eq!(delta_response["acceptance_granted"], json!(false));
    }

    #[test]
    fn hosted_room_census_refuses_a_fifty_first_current_room() {
        let data_dir = owner_child_guard_dir("room-capacity");
        let room_dir = data_dir.join(ROOM_DIR);
        std::fs::create_dir_all(&room_dir).unwrap();
        for index in 0..=M4_HOSTED_ROOM_MAX {
            let tail = format!("or_{index:x}");
            let mut room = positive_outcome_room_v2();
            room["outcome_room_id"] = json!(format!("outcome-room://{tail}"));
            std::fs::write(
                room_dir.join(format!("{tail}.json")),
                serde_json::to_vec(&room).unwrap(),
            )
            .unwrap();
        }
        let error = super::super::outcome_room_routes::list_current_rooms_canonical_strict(
            data_dir.to_str().unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.0, "outcome_room_projection_source_unavailable");
        assert_eq!(classify(error).0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            classify(verr(
                "outcome_room_capacity_exceeded",
                "a fresh fifty-first room is refused before mutation",
            ))
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn product_summaries_do_not_export_payload_refs_or_bytes() {
        let work_result = json!({
            "work_result_id":"work-result://room/one",
            "goal_run_ref":"goal://room/one",
            "work_subject_ref":"work-subject://room/one",
            "outcome_class":"completed",
            "status":"completed",
            "uncertainty":{"kind":"bounded"},
            "supporting_evidence_refs":["evidence://safe"],
            "contradicting_evidence_refs":[],
            "artifact_receipt_and_trace_refs":["receipt://artifact/safe"],
            "result_payload_ref":"artifact://secret-result-payload",
            "result_payload_bytes":"secret-result-bytes",
            "room_admission":{"admission_receipt_ref":"receipt://room/one"},
        });
        let outcome_delta = json!({
            "outcome_delta_id":"outcome-delta://room/one",
            "work_subject_ref":"work-subject://room/one",
            "proposed_by_ref":"work-result://room/one",
            "delta_kind":"refinement",
            "status":"proposed",
            "verifier_and_acceptance_refs":["verifier-path://safe"],
            "payload_ref":"artifact://secret-delta-payload",
            "payload_bytes":"secret-delta-bytes",
            "room_admission":{"admission_receipt_ref":"receipt://room/two"},
        });

        let work_summary =
            safe_room_object_summary("schema://ioi/foundations/work-result/v2", &work_result)
                .unwrap();
        let delta_summary =
            safe_room_object_summary("schema://ioi/foundations/outcome-delta/v2", &outcome_delta)
                .unwrap();
        let exported = serde_json::to_string(&json!([work_summary, delta_summary])).unwrap();
        for forbidden in [
            "result_payload_ref",
            "result_payload_bytes",
            "payload_ref",
            "payload_bytes",
            "secret-result-payload",
            "secret-result-bytes",
            "secret-delta-payload",
            "secret-delta-bytes",
        ] {
            assert!(!exported.contains(forbidden), "exported '{forbidden}'");
        }
    }

    #[test]
    fn changed_create_body_has_a_distinct_replay_identity() {
        let first = json!({
            "schema_version":ROOM_SCHEMA,
            "system_id":"system://room/one",
            "owner_or_sponsor_ref":"user://local-operator",
            "objective_ref":"goal://room/one",
            "objective":"first objective",
        });
        let mut changed = first.clone();
        changed["objective"] = json!("changed objective");

        assert_eq!(
            create_request_root(&first).unwrap(),
            create_request_root(&first).unwrap()
        );
        assert_ne!(
            create_request_root(&first).unwrap(),
            create_request_root(&changed).unwrap()
        );
    }

    #[test]
    fn recovery_refuses_to_overwrite_a_newer_room_head() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!(
            "ioi-outcome-room-recovery-head-{}-{nonce}",
            std::process::id()
        ));
        let room_tail = format!("or_{}", "ab".repeat(32));
        let room_ref = format!("outcome-room://{room_tail}");
        let prior_root = format!("sha256:{}", "11".repeat(32));
        let resulting_root = format!("sha256:{}", "22".repeat(32));
        let newer_root = format!("sha256:{}", "33".repeat(32));
        let prior = json!({
            "outcome_room_id":room_ref,
            "room_state_root":prior_root,
        });
        let resulting = json!({
            "outcome_room_id":format!("outcome-room://{room_tail}"),
            "room_state_root":resulting_root,
        });
        persist_local(ROOM_DIR, data_dir.to_str().unwrap(), &room_tail, &prior).unwrap();
        validate_recovery_room_head(
            data_dir.to_str().unwrap(),
            &room_tail,
            prior.get("room_state_root").and_then(Value::as_str),
            &resulting,
        )
        .unwrap();

        let newer = json!({
            "outcome_room_id":format!("outcome-room://{room_tail}"),
            "room_state_root":newer_root,
        });
        persist_local(ROOM_DIR, data_dir.to_str().unwrap(), &room_tail, &newer).unwrap();
        let error = validate_recovery_room_head(
            data_dir.to_str().unwrap(),
            &room_tail,
            prior.get("room_state_root").and_then(Value::as_str),
            &resulting,
        )
        .unwrap_err();
        assert_eq!(error.0, "outcome_room_recovery_head_conflict");
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn work_result_head_conflict_retains_the_dependency_recovery_intent() {
        let dependencies = json!({
            "schema_version":"ioi.outcome-room-work-result-runtime-dependencies.v1"
        });
        assert!(!child_head_conflict_may_remove_intent(Some(&dependencies)));
        assert!(child_head_conflict_may_remove_intent(None));
    }

    #[test]
    fn room_owner_record_keys_do_not_alias_punctuation() {
        let slash = safe_owner_key("work-result://room/a/b");
        let underscore = safe_owner_key("work-result://room/a_b");
        assert_ne!(slash, underscore);
        assert!(slash.starts_with("room_owner_"));
        assert_eq!(slash.len(), "room_owner_".len() + 64);
    }

    #[test]
    fn malformed_or_orphaned_intent_slots_block_the_census() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!(
            "ioi-outcome-room-intent-census-{}-{nonce}",
            std::process::id()
        ));
        let family = data_dir.join(CHILD_INTENT_DIR);
        std::fs::create_dir_all(&family).unwrap();
        std::fs::write(family.join("orphan.pending"), b"{}\n").unwrap();

        let error = pending_intent_census(data_dir.to_str().unwrap()).unwrap_err();
        assert_eq!(error.0, "outcome_room_pending_intent_unreadable");
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[test]
    fn membership_auth_preflight_precedes_room_registry_and_pending_state_reads() {
        let membership_source = include_str!("outcome_room_system_routes.rs");
        let membership = membership_source
            .split("async fn handle_goal_run_membership(")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub(crate) async fn handle_attach_goal_run(")
                    .next()
            })
            .expect("membership handler remains source-addressable");
        let principal = membership
            .find("request_principal(&state.data_dir, &headers)")
            .expect("membership handler resolves its principal");
        let room_read = membership
            .find("resolve_room_strict(&state.data_dir, &room_ref)")
            .expect("membership handler resolves room truth");
        let pending_read = membership
            .find("refuse_while_any_intent_pending(&state.data_dir)")
            .expect("membership handler fences pending recovery");
        let collective_ref_guard = membership
            .find("The room's durable objective is the only GoalRun this M4 lane may inspect")
            .expect("membership handler fences arbitrary GoalRun refs");
        let goal_run_census = membership
            .find("strict_goal_run_census(&state.data_dir)")
            .expect("membership handler resolves the exact collective GoalRun");
        assert!(principal < room_read && principal < pending_read);
        assert!(collective_ref_guard < goal_run_census);

        let wrapper_source = include_str!("outcome_room_routes.rs");
        for (start, end) in [
            (
                "pub(crate) async fn handle_outcome_room_transition(",
                "async fn handle_legacy_outcome_room_transition(",
            ),
            (
                "pub(crate) async fn handle_outcome_room_attach_goal_run(",
                "pub(crate) async fn handle_outcome_room_detach_goal_run(",
            ),
            (
                "pub(crate) async fn handle_outcome_room_detach_goal_run(",
                "async fn handle_legacy_outcome_room_attach_goal_run(",
            ),
        ] {
            let wrapper = wrapper_source
                .split(start)
                .nth(1)
                .and_then(|tail| tail.split(end).next())
                .unwrap_or_else(|| panic!("wrapper '{start}' remains source-addressable"));
            let principal = wrapper
                .find("request_principal(&st.data_dir, &headers)")
                .unwrap_or_else(|| panic!("wrapper '{start}' resolves its principal"));
            let room_read = wrapper
                .find("resolve_room_strict(&st.data_dir, &room_id)")
                .unwrap_or_else(|| panic!("wrapper '{start}' resolves room truth"));
            assert!(
                principal < room_read,
                "wrapper '{start}' must authenticate before generation/existence dispatch"
            );
        }
    }

    #[test]
    fn membership_and_reconcile_share_room_then_goal_lock_order() {
        // Bind the regression to the actual reconcile handler, not merely to this test's use of
        // the same mutexes. The room fence must enclose its first GoalRun reservation CAS and be
        // released explicitly before any awaited effect boundary.
        let goal_run_source = include_str!("goalrun_routes.rs");
        let reconcile = goal_run_source
            .split("pub(crate) async fn handle_goal_run_reconcile(")
            .nth(1)
            .and_then(|tail| tail.split("// lifecycle-recovery").next())
            .expect("reconcile handler remains source-addressable");
        let room_lock = reconcile
            .find("ROOM_MUTATION_LOCK")
            .expect("reconcile acquires the shared room fence");
        let reservation = reconcile
            .find("let run = match update_goal_run_guarded(")
            .expect("reconcile reserves through the GoalRun CAS seam");
        let drop_guard = reconcile
            .find("drop(room_guard);")
            .expect("reconcile explicitly releases the room fence");
        let first_await_after_reservation = reconcile[reservation..]
            .find(".await")
            .map(|offset| reservation + offset)
            .expect("reconcile retains an awaited authority/effect boundary");
        assert!(room_lock < reservation);
        assert!(reservation < drop_guard);
        assert!(drop_guard < first_await_after_reservation);

        // Exercise the shared protocol deterministically: membership owns ROOM then GOAL and
        // seals its reciprocal backlink first; a reconcile reservation queued on ROOM follows
        // and merges only its lifecycle fields. The final GoalRun must retain both updates.
        let data_dir = owner_child_guard_dir("membership-reconcile-race");
        let goal_run_id = "m4_membership_reconcile_race";
        let goal_run_ref = format!("goal://{goal_run_id}");
        let room_ref = "outcome-room://m4-membership-reconcile-race";
        let prior = json!({
            "goal_run_id":goal_run_id,
            "goal_ref":goal_run_ref,
            "owner_ref":"user://local-operator",
            "status":"active",
            "outcome_room_ref":Value::Null,
            "updated_at":"2026-07-30T12:00:00Z",
        });
        persist_local("goal-runs", data_dir.to_str().unwrap(), goal_run_id, &prior).unwrap();
        let expected_root = goal_run_record_root(&prior).unwrap();
        let mut attached = prior.clone();
        attached["outcome_room_ref"] = json!(room_ref);
        attached["updated_at"] = json!("2026-07-30T12:00:01Z");
        let resulting_root = goal_run_record_root(&attached).unwrap();

        let (membership_holds_room_tx, membership_holds_room_rx) = std::sync::mpsc::channel();
        let reconcile_attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reconcile_attempted_for_membership = reconcile_attempted.clone();
        let membership_data = data_dir.clone();
        let membership_goal_ref = goal_run_ref.clone();
        let membership_thread = std::thread::spawn(move || {
            let _room_guard = super::super::outcome_room_routes::ROOM_MUTATION_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            membership_holds_room_tx.send(()).unwrap();
            while !reconcile_attempted_for_membership.load(std::sync::atomic::Ordering::Acquire) {
                std::thread::yield_now();
            }
            stamp_goal_run_membership(
                membership_data.to_str().unwrap(),
                goal_run_id,
                &membership_goal_ref,
                room_ref,
                &expected_root,
                &resulting_root,
                "2026-07-30T12:00:01Z",
                MembershipTransition::Attach,
            )
            .unwrap();
        });

        membership_holds_room_rx.recv().unwrap();
        let reconcile_data = data_dir.clone();
        let reconcile_attempted_for_thread = reconcile_attempted.clone();
        let reconcile_thread = std::thread::spawn(move || {
            reconcile_attempted_for_thread.store(true, std::sync::atomic::Ordering::Release);
            let _room_guard = super::super::outcome_room_routes::ROOM_MUTATION_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            super::super::goalrun_routes::update_goal_run_guarded(
                reconcile_data.to_str().unwrap(),
                goal_run_id,
                |fresh| {
                    if fresh.get("outcome_room_ref").and_then(Value::as_str) != Some(room_ref) {
                        return Err((
                            "test_membership_missing".to_owned(),
                            "membership did not linearize before reconcile".to_owned(),
                        ));
                    }
                    Ok(())
                },
                |record| {
                    record.insert("status".to_owned(), json!("reconciling"));
                    record.insert(
                        "lifecycle_op".to_owned(),
                        json!({"op":"reconcile","token":"lop_m4_membership_race"}),
                    );
                },
            )
            .unwrap();
        });
        membership_thread.join().unwrap();
        reconcile_thread.join().unwrap();

        let final_goal_run = strict_goal_run_census(data_dir.to_str().unwrap())
            .unwrap()
            .into_iter()
            .find(|record| record.get("goal_run_id").and_then(Value::as_str) == Some(goal_run_id))
            .expect("the raced GoalRun remains durable");
        assert_eq!(final_goal_run["outcome_room_ref"], json!(room_ref));
        assert_eq!(final_goal_run["status"], json!("reconciling"));
        assert_eq!(
            final_goal_run.pointer("/lifecycle_op/token"),
            Some(&json!("lop_m4_membership_race"))
        );
        assert!(!data_dir.join(MEMBERSHIP_INTENT_DIR).exists());
        std::fs::remove_dir_all(data_dir).unwrap();
    }
}
