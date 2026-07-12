//! OutcomeRoom plane — build step 2 of the contract-first sequence: the HOSTED room aggregate
//! above bounded GoalRuns (canonical owner: docs/architecture/domains/ioi-ai/
//! collaborative-outcome-pattern.md; envelope: common-objects-and-envelopes.md
//! §OutcomeRoomEnvelope). A room is the shared collaborative-pursuit profile — it declares its
//! objective, policies, mode, and admission topology, and EVERY shared-state transition is
//! admitted and receipted. It is not a runtime and not a global database.
//!
//! Step-2 contract (honest scope):
//! - HOSTED admission only: `coordination_topology: hosted_admission`. `federated_admission` is
//!   a named gap until the AIIP leg (build steps 7-8) — declared, never faked.
//! - Lifecycle transitions pause | resume | close | archive are admitted, receipted,
//!   optimistically concurrent (`expected_revision` REQUIRED; mismatch = typed conflict, zero
//!   mutation). The richer statuses (active/blocked/verifying/accepted/disputed/settled/revoked)
//!   need participant/verification/settlement authority — named-gap transitions (build steps 3+).
//! - GoalRun membership: attach-goal-run binds an EXISTING goal-run record into the room's
//!   membership projection (`member_goal_run_refs`), receipted. The reciprocal
//!   `GoalRun.outcome_room_ref` stamp arrives with participant leases (build step 3) — the
//!   goal-runs family is not mutated from this plane.
//! - Step-3 object lists (participant leases, participation requests, frontier, attempts,
//!   findings, challenges, state bundles, discussion projections, contributions) are PLANE-OWNED
//!   or named gaps: caller-supplied values refuse per-field; the room carries consistent empties.
//! - Every discipline from the #71 review rounds applies from the start: recursive sensitive-key
//!   rejection; per-field canonical refs; a plane mutation lock (one daemon writer per data dir);
//!   ATOMIC file replacement with temp cleanup on both failure paths; record-first/
//!   receipt-second with EXACT-PRIOR restore (byte-for-byte, `updated_at` included) on receipt
//!   failure; receipts on the complete portable ReceiptEnvelope base with bound facts and a
//!   recomputable output hash.
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const ROOM_SCHEMA: &str = "ioi.hypervisor.outcome-room.v1";
const ADMISSION_RECEIPT_SCHEMA: &str = "ioi.hypervisor.outcome-room-admission-receipt.v1";
const TRANSITION_RECEIPT_SCHEMA: &str = "ioi.hypervisor.outcome-room-transition-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.outcome-rooms-overview.v1";
pub(crate) const ROOM_DIR: &str = "outcome-room-registry";
const ROOM_RECEIPT_DIR: &str = "outcome-room-registry-receipts";
const GOAL_RUN_DIR: &str = "goal-runs";

/// Canonical vocabularies (OutcomeRoomEnvelope, verbatim).
const ROOM_MODES: &[&str] = &["private_goal", "permissioned_team", "cross_org", "open_challenge"];
const ROOM_STATUSES: &[&str] = &[
    "proposed", "open", "active", "paused", "blocked", "verifying",
    "accepted", "disputed", "settled", "closed", "revoked", "archived",
];
const TOPOLOGIES: &[&str] = &["hosted_admission", "federated_admission"];
/// Step-2 lifecycle transitions: name → (allowed from-statuses, to-status).
const TRANSITIONS: &[(&str, &[&str], &str)] = &[
    ("pause", &["open"], "paused"),
    ("resume", &["paused"], "open"),
    ("close", &["open", "paused"], "closed"),
    ("archive", &["closed"], "archived"),
];
/// Canon-named transitions whose authority arrives with later build steps — refused typed.
const UNAVAILABLE_TRANSITIONS: &[(&str, &str)] = &[
    ("activate", "participant/claim authority (build step 3)"),
    ("block", "frontier/blocker authority (build step 3)"),
    ("verify", "verifier authority (build step 3)"),
    ("accept", "acceptance authority (build step 3)"),
    ("dispute", "challenge/adjudication authority (build step 3)"),
    ("settle", "settlement authority (build step 5+)"),
    ("revoke", "governance revocation authority (build step 3)"),
];
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "password", "secret", "credential", "authorization", "privatekey", "apikey", "token",
];

/// Serializes every room mutation's read→validate→persist→receipt critical section (one daemon
/// writer per data directory, per the runtime model). No .await executes under this lock.
static ROOM_MUTATION_LOCK: Mutex<()> = Mutex::new(());

const REF_MAX: usize = 300;
const LIST_MAX: usize = 64;
const OBJECTIVE_MAX: usize = 2000;
const HISTORY_MAX: usize = 100;

fn nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}

type VErr = (String, String);
fn verr(code: &str, msg: impl Into<String>) -> VErr {
    (code.into(), msg.into())
}

fn reject_sensitive_keys(v: &Value, path: &str) -> Result<(), VErr> {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                let normalized: String = k.to_lowercase().chars().filter(|c| !matches!(c, '_' | '-' | ' ' | '.')).collect();
                if SENSITIVE_KEY_FRAGMENTS.iter().any(|f| normalized.contains(f)) && !child.is_null() {
                    return Err(verr("outcome_room_plaintext_secret_rejected", format!("sensitive key `{path}{k}` is never accepted anywhere in the body — rooms carry canonical refs; secrets stay in the daemon credential planes")));
                }
                reject_sensitive_keys(child, &format!("{path}{k}."))?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for (i, it) in items.iter().enumerate() {
                reject_sensitive_keys(it, &format!("{path}{i}."))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn str_opt_bounded(body: &Value, key: &str, max: usize) -> Result<Option<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) => {
            if raw.chars().count() > max {
                return Err(verr("outcome_room_field_too_long", format!("`{key}` exceeds the bounded length ({max} chars)")));
            }
            let trimmed = raw.trim();
            if trimmed.is_empty() { return Ok(None); }
            Ok(Some(trimmed.to_string()))
        }
        Some(_) => Err(verr("outcome_room_field_type_invalid", format!("`{key}` must be a string when present — a non-string value is never defaulted"))),
    }
}

fn ref_scheme_ok(v: &str, schemes: &[&str]) -> bool {
    match v.split_once("://") {
        Some((scheme, tail)) if !tail.is_empty() => schemes.contains(&scheme),
        _ => false,
    }
}

fn scheme_err(key: &str, schemes: &[&str]) -> VErr {
    verr("outcome_room_ref_scheme_invalid", format!("`{key}` must be a canonical ref [{}] — a raw string is never a ref", schemes.iter().map(|s| format!("{s}://")).collect::<Vec<_>>().join("|")))
}

fn scalar_ref(body: &Value, key: &str, schemes: &[&str]) -> Result<Option<String>, VErr> {
    match str_opt_bounded(body, key, REF_MAX)? {
        None => Ok(None),
        Some(v) if ref_scheme_ok(&v, schemes) => Ok(Some(v)),
        Some(_) => Err(scheme_err(key, schemes)),
    }
}

/// A REQUIRED canonical scalar ref (rooms are governed: their core policy refs must be declared).
fn required_ref(body: &Value, key: &str, schemes: &[&str], req_code: &str) -> Result<String, VErr> {
    match scalar_ref(body, key, schemes)? {
        Some(v) => Ok(v),
        None => Err(verr(req_code, format!("`{key}` is required — a room without it is ungoverned (declare a canonical [{}] ref)", schemes.join("|")))),
    }
}

fn list_ref(body: &Value, key: &str, schemes: &[&str]) -> Result<Vec<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => {
            if items.len() > LIST_MAX {
                return Err(verr("outcome_room_field_too_long", format!("`{key}` exceeds the bounded list length ({LIST_MAX})")));
            }
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                match it {
                    Value::String(raw) => {
                        let t = raw.trim();
                        if t.is_empty() { continue; }
                        if t.chars().count() > REF_MAX {
                            return Err(verr("outcome_room_field_too_long", format!("a `{key}` member exceeds the bounded length ({REF_MAX} chars)")));
                        }
                        if !ref_scheme_ok(t, schemes) {
                            return Err(scheme_err(key, schemes));
                        }
                        out.push(t.to_string());
                    }
                    _ => return Err(verr("outcome_room_field_type_invalid", format!("`{key}` members must be strings"))),
                }
            }
            Ok(out)
        }
        Some(_) => Err(verr("outcome_room_field_type_invalid", format!("`{key}` must be an array of refs when present"))),
    }
}

fn vocab_required(body: &Value, key: &str, vocab: &[&str], code: &str) -> Result<String, VErr> {
    match str_opt_bounded(body, key, 80)? {
        Some(v) if vocab.contains(&v.as_str()) => Ok(v),
        Some(v) => Err(verr(code, format!("`{key}` value '{v}' is not a member of the canonical vocabulary [{}]", vocab.join("|")))),
        None => Err(verr(code, format!("`{key}` is required and must be a member of [{}]", vocab.join("|")))),
    }
}

/// Step-3 object planes: caller-supplied values refuse per-field until the plane exists.
fn plane_owned_list(body: &Value, key: &str, code: &str, why: &str) -> Result<(), VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Array(items)) => {
            if items.iter().any(|it| !matches!(it, Value::String(s) if s.trim().is_empty())) {
                Err(verr(code, format!("`{key}` is not caller-authored — {why}")))
            } else {
                Ok(())
            }
        }
        Some(_) => Err(verr("outcome_room_field_type_invalid", format!("`{key}` must be an array when present"))),
    }
}

fn record_output_hash(record: &Value, excludes: &[&str]) -> String {
    let mut clone = record.clone();
    if let Some(obj) = clone.as_object_mut() {
        for k in excludes { obj.remove(*k); }
    }
    format!("sha256:{:x}", Sha256::digest(serde_json::to_vec(&clone).unwrap_or_default()))
}

/// Plane-owned mutable fields excluded from the admission-time hash: later receipted transitions
/// and membership appends never invalidate the admission receipt.
const ROOM_HASH_EXCLUDES: &[&str] = &[
    "admission_receipt_ref", "updated_at", "revision", "status", "status_history",
    "member_goal_run_refs", "admission_and_replay_refs",
];

/// PURE receipt on the complete portable ReceiptEnvelope base (the exact key set pinned by the
/// work-result plane's tests is preserved here, plus this plane's own bound facts).
fn build_room_receipt(
    schema: &str,
    receipt_type: &str,
    prefix: &str,
    subject_ref: &str,
    op: &str,
    bound_facts: Value,
    boundary_refs: Vec<Value>,
    output_hash: String,
    posture: &str,
    note: &str,
    now: &str,
) -> (String, Value) {
    let id_tail = format!("{prefix}_{:x}", nanos());
    let receipt_id = format!("receipt://{id_tail}");
    let rec = json!({
        "schema_version": schema,
        "receipt_id": receipt_id,
        "receipt_ref": receipt_id,
        "receipt_type": receipt_type,
        "receipt_profile_ref": format!("schema://{schema}"),
        "actor_id": "daemon://hypervisor-runtime",
        "subject_ref": subject_ref,
        "op": op,
        "attested_boundary_fact_refs": boundary_refs,
        "bound_facts": bound_facts,
        "output_hash": output_hash,
        "hash_scope_excludes": ROOM_HASH_EXCLUDES,
        "assurance_posture": posture,
        "assurance_note": note,
        "verification_ref": Value::Null,
        "acceptance_ref": Value::Null,
        "claim_scope_ref": Value::Null,
        "run_id": Value::Null,
        "task_id": Value::Null,
        "input_hash": Value::Null,
        "policy_hash": Value::Null,
        "authority_grant_id": Value::Null,
        "primitive_capabilities": [],
        "authority_scopes": [],
        "artifact_refs": [],
        "evidence_bundle_refs": [],
        "adjudication_ref": Value::Null,
        "settlement_ref": Value::Null,
        "signature": Value::Null,
        "l1_commitment": Value::Null,
        "timestamp": now,
        "outcome": "ok",
        "at": now
    });
    (id_tail, rec)
}

/// ATOMIC file replacement for the MUTABLE room record: tmp sibling (no .json extension —
/// invisible to read_record_dir) + rename; BOTH failure paths clean the temp file.
fn persist_room_atomic(data_dir: &str, record_id: &str, record: &Value) -> std::io::Result<()> {
    let dir = std::path::Path::new(data_dir).join(ROOM_DIR);
    std::fs::create_dir_all(&dir)?;
    let safe: String = record_id.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_");
    let tmp = dir.join(format!(".{safe}.tmp-{:x}", nanos()));
    if let Err(e) = std::fs::write(&tmp, serde_json::to_vec_pretty(record).unwrap_or_default()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, dir.join(format!("{safe}.json"))) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

fn load_room(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, ROOM_DIR)
        .into_iter()
        .find(|r| r.get("outcome_room_id").and_then(|v| v.as_str()) == Some(id))
}

pub(crate) fn resolve_open_room(data_dir: &str, room_ref: &str) -> Option<Value> {
    load_room(data_dir, room_ref)
}

/// CREATION finalize: room record first, receipt second, receipt failure removes the created
/// record with a CHECKED rollback; distinct typed lanes.
fn finalize_room_create(
    data_dir: &str,
    room_tail: &str,
    record: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    if let Err(e) = persist_room_atomic(data_dir, room_tail, record) {
        return Err(verr("outcome_room_record_persist_failed", format!("room record persist failed ({e}) — nothing changed")));
    }
    match persist_record(data_dir, ROOM_RECEIPT_DIR, receipt_id, receipt) {
        Ok(()) => Ok(()),
        Err(e) => {
            if remove_record(data_dir, ROOM_DIR, room_tail) {
                Err(verr("outcome_room_receipt_persist_failed", format!("admission receipt persist failed ({e}); the created room was rolled back — nothing changed")))
            } else {
                Err(verr("outcome_room_rollback_failed", format!("admission receipt persist failed ({e}) AND the created room rollback failed — manual repair required for '{room_tail}'")))
            }
        }
    }
}

/// MUTATION finalize: updated room first (atomic replacement), receipt second, receipt failure
/// restores the EXACT prior record — byte for byte, `updated_at` and `revision` included. Safe
/// because callers hold ROOM_MUTATION_LOCK across read → validate → finalize.
fn finalize_room_mutation(
    data_dir: &str,
    room_tail: &str,
    prior: &Value,
    updated: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    if let Err(e) = persist_room_atomic(data_dir, room_tail, updated) {
        return Err(verr("outcome_room_record_persist_failed", format!("room mutation persist failed ({e}) — nothing changed")));
    }
    match persist_record(data_dir, ROOM_RECEIPT_DIR, receipt_id, receipt) {
        Ok(()) => Ok(()),
        Err(e) => {
            if persist_room_atomic(data_dir, room_tail, prior).is_ok() {
                Err(verr("outcome_room_receipt_persist_failed", format!("transition receipt persist failed ({e}); the room was restored EXACTLY (status, revision, membership, updated_at) — nothing changed")))
            } else {
                Err(verr("outcome_room_rollback_failed", format!("transition receipt persist failed ({e}) AND the prior-room restore failed — manual repair required for '{room_tail}'")))
            }
        }
    }
}

/// Optimistic concurrency (#63 discipline, REQUIRED on this new plane — no legacy callers):
/// `expected_revision` must be an integer exactly matching the persisted revision.
fn check_expected_revision(body: &Value, current: u64) -> Result<(), VErr> {
    match body.get("expected_revision") {
        None | Some(Value::Null) => Err(verr("outcome_room_expected_revision_invalid", "`expected_revision` is required on every room mutation (optimistic concurrency; read the room first)")),
        Some(v) => match v.as_u64() {
            None => Err(verr("outcome_room_expected_revision_invalid", "`expected_revision` must be an integer")),
            Some(er) if er != current => Err(verr("outcome_room_revision_conflict", format!("expected_revision {er} does not match the persisted revision {current} — reload and re-apply (zero mutation)"))),
            Some(_) => Ok(()),
        },
    }
}

/// Validate a room creation body into its durable record (PURE — no I/O, no ids/times).
fn validate_room_create(body: &Value) -> Result<Value, VErr> {
    reject_sensitive_keys(body, "")?;
    // Plane-owned scalars refuse typed.
    if body.get("status").map(|v| !v.is_null()).unwrap_or(false) {
        return Err(verr("outcome_room_status_plane_owned", "`status` is plane-owned: a hosted room admits as `open`; lifecycle changes go through receipted transitions"));
    }
    if body.get("revision").map(|v| !v.is_null()).unwrap_or(false) || body.get("admission_receipt_ref").map(|v| !v.is_null()).unwrap_or(false) {
        return Err(verr("outcome_room_field_plane_owned", "`revision` and `admission_receipt_ref` are minted by this plane"));
    }
    // Step-3 object lists refuse per-field.
    for (key, code, why) in [
        ("participant_lease_refs", "outcome_room_participants_unavailable", "RoomParticipantLease is build step 3"),
        ("participation_request_refs", "outcome_room_participation_unavailable", "RoomParticipationRequest is build step 3"),
        ("frontier_item_refs", "outcome_room_frontier_unavailable", "WorkFrontierItem is build step 3"),
        ("attempt_refs", "outcome_room_attempts_unavailable", "the Attempt plane is build step 3"),
        ("finding_refs", "outcome_room_findings_unavailable", "the Finding plane is build step 3"),
        ("verifier_challenge_refs", "outcome_room_challenges_unavailable", "the VerifierChallenge plane is build step 3"),
        ("participant_state_bundle_refs", "outcome_room_state_bundles_unavailable", "ParticipantStateBundle is build step 7"),
        ("discussion_projection_refs", "outcome_room_discussion_unavailable", "discussion projections arrive with the Missions surface (build step 4)"),
        ("contribution_refs", "outcome_room_contributions_unavailable", "contribution lineage arrives with participant leases (build step 3)"),
        ("admission_and_replay_refs", "outcome_room_replay_plane_owned", "the receipt trail is appended by this plane's own admitted transitions"),
        ("member_goal_run_refs", "outcome_room_membership_plane_owned", "membership registers through the receipted attach-goal-run transition"),
    ] {
        plane_owned_list(body, key, code, why)?;
    }
    let owner = required_ref(body, "owner_or_sponsor_ref", &["user", "org", "project", "domain", "service"], "outcome_room_owner_required")?;
    let objective_ref = required_ref(body, "objective_ref", &["goal", "task", "service"], "outcome_room_objective_ref_required")?;
    let objective = match str_opt_bounded(body, "objective", OBJECTIVE_MAX)? {
        Some(o) => o,
        None => return Err(verr("outcome_room_objective_required", "A room declares its shared `objective` (bounded plain statement).")),
    };
    let room_mode = vocab_required(body, "room_mode", ROOM_MODES, "outcome_room_mode_invalid")?;
    let topology = vocab_required(body, "coordination_topology", TOPOLOGIES, "outcome_room_topology_invalid")?;
    if topology == "federated_admission" {
        return Err(verr("outcome_room_federated_unavailable", "`federated_admission` needs the AIIP leg (build steps 7-8: discovery, typed participation, portable exit, federated shared-state ordering) — hosted_admission is the step-2 contract"));
    }
    let record = json!({
        "schema_version": ROOM_SCHEMA,
        "owner_or_sponsor_ref": owner,
        "objective_ref": objective_ref,
        "objective": objective,
        "constraint_refs": list_ref(body, "constraint_refs", &["constraint", "policy", "budget"])?,
        "acceptance_criteria_refs": list_ref(body, "acceptance_criteria_refs", &["rubric", "gate", "policy"])?,
        "stop_policy_ref": required_ref(body, "stop_policy_ref", &["policy"], "outcome_room_policy_required")?,
        "room_mode": room_mode,
        "visibility_policy_ref": required_ref(body, "visibility_policy_ref", &["policy"], "outcome_room_policy_required")?,
        "participation_policy_ref": required_ref(body, "participation_policy_ref", &["policy"], "outcome_room_policy_required")?,
        "privacy_policy_ref": required_ref(body, "privacy_policy_ref", &["policy"], "outcome_room_policy_required")?,
        "contribution_policy_ref": required_ref(body, "contribution_policy_ref", &["policy"], "outcome_room_policy_required")?,
        "discovery_and_external_admission_policy_refs": list_ref(body, "discovery_and_external_admission_policy_refs", &["policy", "room-discovery", "aiip"])?,
        "artifact_license_rights_retention_and_export_policy_refs": list_ref(body, "artifact_license_rights_retention_and_export_policy_refs", &["policy", "license"])?,
        "coordination_topology": topology,
        "coordination_policy_ref": required_ref(body, "coordination_policy_ref", &["policy"], "outcome_room_policy_required")?,
        "host_domain_ref": scalar_ref(body, "host_domain_ref", &["domain"])?,
        "ordering_and_merge_policy_ref": required_ref(body, "ordering_and_merge_policy_ref", &["policy"], "outcome_room_policy_required")?,
        "conflict_and_failover_policy_ref": required_ref(body, "conflict_and_failover_policy_ref", &["policy"], "outcome_room_policy_required")?,
        "multi_party_collaboration_ref": scalar_ref(body, "multi_party_collaboration_ref", &["collaboration"])?,
        "ontology_profile_refs": list_ref(body, "ontology_profile_refs", &["ontology", "semantic-profile", "ontology-mapping"])?,
        "scorecard_and_guardrail_refs": list_ref(body, "scorecard_and_guardrail_refs", &["benchmark", "rubric", "gate", "policy"])?,
        "verifier_path_refs": list_ref(body, "verifier_path_refs", &["verifier_path"])?,
        "resource_and_budget_refs": list_ref(body, "resource_and_budget_refs", &["resource_pool", "budget", "goal-budget", "order"])?,
        "settlement_policy_ref": scalar_ref(body, "settlement_policy_ref", &["policy"])?,
        "participant_lease_refs": [],
        "participation_request_refs": [],
        "frontier_item_refs": [],
        "attempt_refs": [],
        "finding_refs": [],
        "verifier_challenge_refs": [],
        "discussion_projection_refs": [],
        "admission_and_replay_refs": [],
        "contribution_refs": [],
        "participant_state_bundle_refs": [],
        "member_goal_run_refs": [],
        "status": "open",
        "revision": 1,
        "status_history": [],
        "runtimeTruthSource": "daemon-runtime"
    });
    Ok(record)
}

fn sorted_newest(data_dir: &str) -> Vec<Value> {
    let mut items = read_record_dir(data_dir, ROOM_DIR);
    items.sort_by(|a, b| s(b, "created_at", "").cmp(&s(a, "created_at", "")));
    items
}

// ================================ HANDLERS =======================================================

pub(crate) async fn handle_outcome_rooms_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "schema_version": ROOM_SCHEMA, "outcome_rooms": sorted_newest(&st.data_dir), "runtimeTruthSource": "daemon-runtime" }))
}

pub(crate) async fn handle_outcome_room_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_room(&st.data_dir, &format!("outcome-room://{id}")) {
        Some(r) => (StatusCode::OK, Json(json!({ "outcome_room": r }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": { "code": "not_found", "outcome_room": id } }))),
    }
}

pub(crate) async fn handle_outcome_rooms_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let rooms = read_record_dir(&st.data_dir, ROOM_DIR);
    let by_status = |status: &str| rooms.iter().filter(|r| s(r, "status", "") == status).count();
    Json(json!({
        "schema_version": OVERVIEW_SCHEMA,
        "outcome_rooms": rooms.len(),
        "by_status": ROOM_STATUSES.iter().filter(|st2| by_status(st2) > 0).map(|st2| json!({ "status": st2, "count": by_status(st2) })).collect::<Vec<_>>(),
        "room_modes": ROOM_MODES,
        "room_statuses": ROOM_STATUSES,
        "coordination_topologies": TOPOLOGIES,
        "lifecycle_transitions": TRANSITIONS.iter().map(|(t, from, to)| json!({ "transition": t, "from": from, "to": to })).collect::<Vec<_>>(),
        "governance_gaps": [
            "hosted_admission only — federated_admission needs the AIIP leg (build steps 7-8) and is refused typed at creation, never faked",
            "participant leases, participation requests, frontier items, attempts, findings, challenges, contributions, and state bundles are build-step-3+ planes: their room lists stay plane-owned empties until those planes exist",
            "the reciprocal GoalRun.outcome_room_ref stamp arrives with participant leases (build step 3) — membership is currently the room-side projection, registered only through the receipted attach-goal-run transition",
            "richer lifecycle statuses (active/blocked/verifying/accepted/disputed/settled/revoked) are named-gap transitions requiring later authority; a receipt is not proof of correctness — acceptance and settlement are assurance rungs above admission"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// POST /v1/hypervisor/outcome-rooms — admit a HOSTED room (fail-closed, atomic, receipted).
pub(crate) async fn handle_outcome_room_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let err400 = |(code, msg): VErr| (StatusCode::BAD_REQUEST, Json(json!({ "error": { "code": code, "message": msg } })));
    let mut record = match validate_room_create(&body) {
        Ok(r) => r,
        Err(e) => return err400(e),
    };
    let _guard = ROOM_MUTATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let id_tail = format!("or_{:x}", nanos());
    let room_id = format!("outcome-room://{id_tail}");
    let now = iso_now();
    {
        let obj = record.as_object_mut().expect("record is an object");
        obj.insert("outcome_room_id".into(), json!(room_id));
        obj.insert("created_at".into(), json!(now));
        obj.insert("updated_at".into(), json!(now));
    }
    let (receipt_id, receipt) = build_room_receipt(
        ADMISSION_RECEIPT_SCHEMA, "OutcomeRoomAdmissionReceipt", "orr", &room_id, "admitted",
        json!({
            "room_mode": record["room_mode"],
            "coordination_topology": record["coordination_topology"],
            "owner_or_sponsor_ref": record["owner_or_sponsor_ref"],
            "objective_ref": record["objective_ref"],
            "status_at_admission": "open",
        }),
        vec![json!(room_id), record["owner_or_sponsor_ref"].clone(), record["objective_ref"].clone()],
        record_output_hash(&record, ROOM_HASH_EXCLUDES),
        "admitted_not_verified",
        "admission of a declared hosted room — a receipt is not proof of outcome; every later shared-state change is its own admitted, receipted transition",
        &now,
    );
    {
        let obj = record.as_object_mut().expect("object");
        obj.insert("admission_receipt_ref".into(), receipt["receipt_ref"].clone());
        obj.insert("admission_and_replay_refs".into(), json!([receipt["receipt_ref"]]));
    }
    if let Err((code, msg)) = finalize_room_create(&st.data_dir, &id_tail, &record, &receipt_id, &receipt) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": { "code": code, "message": msg } })));
    }
    (StatusCode::CREATED, Json(json!({ "outcome_room": record, "outcome_room_receipt": receipt })))
}

/// Shared mutation core for transition + attach: revision check, mutate, receipt, finalize.
fn mutate_room(
    data_dir: &str,
    room_tail: &str,
    body: &Value,
    op: &str,
    mutate: impl FnOnce(&mut Value) -> Result<Value, VErr>, // returns bound facts
) -> Result<(Value, Value), VErr> {
    let room_id = format!("outcome-room://{room_tail}");
    let Some(prior) = load_room(data_dir, &room_id) else {
        return Err(verr("outcome_room_not_found", format!("no admitted room '{room_id}'")));
    };
    let current_rev = prior.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
    check_expected_revision(body, current_rev)?;
    let now = iso_now();
    let mut updated = prior.clone();
    let bound_facts = mutate(&mut updated)?;
    {
        let obj = updated.as_object_mut().expect("room is an object");
        obj.insert("revision".into(), json!(current_rev + 1));
        obj.insert("updated_at".into(), json!(now));
    }
    let (receipt_id, receipt) = build_room_receipt(
        TRANSITION_RECEIPT_SCHEMA, "OutcomeRoomTransitionReceipt", "ort", &room_id, op,
        bound_facts,
        vec![json!(room_id)],
        record_output_hash(&updated, ROOM_HASH_EXCLUDES),
        "admitted_not_verified",
        "an admitted shared-state transition on a hosted room — receipted, optimistically concurrent, and honest about being admission (not verification or acceptance)",
        &now,
    );
    {
        let obj = updated.as_object_mut().expect("object");
        let mut trail: Vec<Value> = obj.get("admission_and_replay_refs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        trail.push(receipt["receipt_ref"].clone());
        obj.insert("admission_and_replay_refs".into(), Value::Array(trail));
        let mut history: Vec<Value> = obj.get("status_history").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        history.push(json!({ "op": op, "at": now, "receipt_ref": receipt["receipt_ref"], "revision": current_rev + 1 }));
        if history.len() > HISTORY_MAX { let drop_n = history.len() - HISTORY_MAX; history.drain(0..drop_n); }
        obj.insert("status_history".into(), Value::Array(history));
    }
    finalize_room_mutation(data_dir, room_tail, &prior, &updated, &receipt_id, &receipt)?;
    Ok((updated, receipt))
}

/// POST /v1/hypervisor/outcome-rooms/:id/transition — admitted, receipted lifecycle transition.
pub(crate) async fn handle_outcome_room_transition(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let err = |status: StatusCode, (code, msg): VErr| (status, Json(json!({ "error": { "code": code, "message": msg } })));
    if let Err(e) = reject_sensitive_keys(&body, "") {
        return err(StatusCode::BAD_REQUEST, e);
    }
    let transition = match str_opt_bounded(&body, "transition", 40) {
        Ok(Some(t)) => t,
        Ok(None) => return err(StatusCode::BAD_REQUEST, verr("outcome_room_transition_invalid", format!("`transition` is required — step-2 lifecycle: [{}]", TRANSITIONS.iter().map(|(t, _, _)| *t).collect::<Vec<_>>().join("|")))),
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    if let Some((_, why)) = UNAVAILABLE_TRANSITIONS.iter().find(|(t, _)| *t == transition) {
        return err(StatusCode::BAD_REQUEST, verr("outcome_room_transition_unavailable", format!("transition '{transition}' needs {why} — a named gap, never faked")));
    }
    let Some((_, allowed_from, to_status)) = TRANSITIONS.iter().find(|(t, _, _)| *t == transition) else {
        return err(StatusCode::BAD_REQUEST, verr("outcome_room_transition_invalid", format!("unknown transition '{transition}' — step-2 lifecycle: [{}]", TRANSITIONS.iter().map(|(t, _, _)| *t).collect::<Vec<_>>().join("|"))));
    };
    let _guard = ROOM_MUTATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let result = mutate_room(&st.data_dir, &id, &body, &transition, |room| {
        let from = s(room, "status", "");
        if !allowed_from.contains(&from.as_str()) {
            return Err(verr("outcome_room_transition_invalid", format!("transition '{transition}' is not admitted from status '{from}' (allowed from: [{}])", allowed_from.join("|"))));
        }
        room.as_object_mut().expect("object").insert("status".into(), json!(to_status));
        let rev = room.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(json!({ "transition": transition, "from": from, "to": to_status, "revision_before": rev, "revision_after": rev + 1 }))
    });
    match result {
        Ok((room, receipt)) => (StatusCode::OK, Json(json!({ "outcome_room": room, "outcome_room_receipt": receipt }))),
        Err(e) if e.0 == "outcome_room_not_found" => err(StatusCode::NOT_FOUND, e),
        Err(e) if e.0 == "outcome_room_revision_conflict" => err(StatusCode::CONFLICT, e),
        Err(e) if e.0.ends_with("_persist_failed") || e.0 == "outcome_room_rollback_failed" => err(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

/// POST /v1/hypervisor/outcome-rooms/:id/attach-goal-run — bind an EXISTING bounded GoalRun into
/// the room's membership projection (admitted, receipted, duplicate-safe, open rooms only).
pub(crate) async fn handle_outcome_room_attach_goal_run(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let err = |status: StatusCode, (code, msg): VErr| (status, Json(json!({ "error": { "code": code, "message": msg } })));
    if let Err(e) = reject_sensitive_keys(&body, "") {
        return err(StatusCode::BAD_REQUEST, e);
    }
    let goal_run_id = match str_opt_bounded(&body, "goal_run_ref", REF_MAX) {
        Ok(Some(g)) => g,
        Ok(None) => return err(StatusCode::BAD_REQUEST, verr("outcome_room_goal_run_required", "`goal_run_ref` is required (the goal-run record id, e.g. gr_…)")),
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    // The GoalRun must be an EXISTING bounded run in the daemon's goal-runs family.
    let run_exists = read_record_dir(&st.data_dir, GOAL_RUN_DIR)
        .into_iter()
        .any(|r| r.get("goal_run_id").and_then(|v| v.as_str()) == Some(goal_run_id.as_str()));
    if !run_exists {
        return err(StatusCode::BAD_REQUEST, verr("outcome_room_goal_run_unbound", format!("`goal_run_ref` does not resolve to an admitted GoalRun ('{goal_run_id}') — the aggregate binds only real bounded runs")));
    }
    let _guard = ROOM_MUTATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let result = mutate_room(&st.data_dir, &id, &body, "goal_run_attached", |room| {
        let status = s(room, "status", "");
        if status != "open" {
            return Err(verr("outcome_room_not_open", format!("membership changes are admitted only on an `open` room (status is '{status}')")));
        }
        let members: Vec<String> = room.get("member_goal_run_refs").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        if members.iter().any(|m| m == &goal_run_id) {
            return Err(verr("outcome_room_goal_run_duplicate", format!("GoalRun '{goal_run_id}' is already a member — attachment is idempotent-refusing, never double-registered")));
        }
        let mut arr: Vec<Value> = members.into_iter().map(Value::String).collect();
        arr.push(json!(goal_run_id));
        let count = arr.len();
        room.as_object_mut().expect("object").insert("member_goal_run_refs".into(), Value::Array(arr));
        let rev = room.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(json!({ "goal_run_ref": goal_run_id, "member_count_after": count, "revision_before": rev, "revision_after": rev + 1 }))
    });
    match result {
        Ok((room, receipt)) => (StatusCode::OK, Json(json!({ "outcome_room": room, "outcome_room_receipt": receipt }))),
        Err(e) if e.0 == "outcome_room_not_found" => err(StatusCode::NOT_FOUND, e),
        Err(e) if e.0 == "outcome_room_revision_conflict" => err(StatusCode::CONFLICT, e),
        Err(e) if e.0.ends_with("_persist_failed") || e.0 == "outcome_room_rollback_failed" => err(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

#[cfg(test)]
mod outcome_room_tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ioi-room-{tag}-{:x}", nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn valid_room_body() -> Value {
        json!({
            "owner_or_sponsor_ref": "org://acme",
            "objective_ref": "goal://alloy-program",
            "objective": "Find a fatigue-resistant alloy candidate.",
            "room_mode": "permissioned_team",
            "coordination_topology": "hosted_admission",
            "stop_policy_ref": "policy://stop-on-budget",
            "visibility_policy_ref": "policy://team-visible",
            "participation_policy_ref": "policy://invited-only",
            "privacy_policy_ref": "policy://no-pii",
            "contribution_policy_ref": "policy://contribution-v1",
            "coordination_policy_ref": "policy://coordination-v1",
            "ordering_and_merge_policy_ref": "policy://ordered-admission",
            "conflict_and_failover_policy_ref": "policy://host-failover"
        })
    }

    #[test]
    fn creation_is_fail_closed_typed_and_hosted_only() {
        let rec = validate_room_create(&valid_room_body()).unwrap();
        assert_eq!(rec["status"], json!("open"));
        assert_eq!(rec["revision"], json!(1));
        assert_eq!(rec["member_goal_run_refs"], json!([]));
        assert_eq!(rec["participant_lease_refs"], json!([]));
        let cases: Vec<(&str, Value, &str)> = vec![
            ("coordination_topology", json!("federated_admission"), "outcome_room_federated_unavailable"),
            ("coordination_topology", json!("mesh"), "outcome_room_topology_invalid"),
            ("room_mode", json!("party"), "outcome_room_mode_invalid"),
            ("owner_or_sponsor_ref", json!("not-a-ref"), "outcome_room_ref_scheme_invalid"),
            ("stop_policy_ref", json!(Value::Null), "outcome_room_policy_required"),
            ("status", json!("accepted"), "outcome_room_status_plane_owned"),
            ("revision", json!(7), "outcome_room_field_plane_owned"),
            ("participant_lease_refs", json!(["participant-lease://ghost"]), "outcome_room_participants_unavailable"),
            ("frontier_item_refs", json!(["frontier://ghost"]), "outcome_room_frontier_unavailable"),
            ("admission_and_replay_refs", json!(["receipt://forged"]), "outcome_room_replay_plane_owned"),
            ("member_goal_run_refs", json!(["gr_x"]), "outcome_room_membership_plane_owned"),
        ];
        for (key, val, code) in cases {
            let mut b = valid_room_body();
            b[key] = val;
            assert_eq!(validate_room_create(&b).unwrap_err().0, code, "field: {key}");
        }
        // Recursive secrets refuse.
        let mut b = valid_room_body();
        b["notes"] = json!({ "api_key": "x" });
        assert_eq!(validate_room_create(&b).unwrap_err().0, "outcome_room_plaintext_secret_rejected");
    }

    #[test]
    fn mutation_requires_exact_revision_and_receipts_bind_the_transition() {
        let dir = temp_dir("rev");
        let data_dir = dir.to_str().unwrap();
        let mut room = validate_room_create(&valid_room_body()).unwrap();
        {
            let obj = room.as_object_mut().unwrap();
            obj.insert("outcome_room_id".into(), json!("outcome-room://or_1"));
            obj.insert("created_at".into(), json!("2026-01-01T00:00:00Z"));
            obj.insert("updated_at".into(), json!("2026-01-01T00:00:00Z"));
            obj.insert("admission_receipt_ref".into(), json!("receipt://orr_seed"));
        }
        persist_room_atomic(data_dir, "or_1", &room).unwrap();
        // Missing/stale revision → typed, ZERO mutation (byte-for-byte).
        let before = serde_json::to_vec(&load_room(data_dir, "outcome-room://or_1").unwrap()).unwrap();
        let e = mutate_room(data_dir, "or_1", &json!({}), "pause", |_| Ok(json!({}))).unwrap_err();
        assert_eq!(e.0, "outcome_room_expected_revision_invalid");
        let e = mutate_room(data_dir, "or_1", &json!({ "expected_revision": 9 }), "pause", |_| Ok(json!({}))).unwrap_err();
        assert_eq!(e.0, "outcome_room_revision_conflict");
        assert_eq!(serde_json::to_vec(&load_room(data_dir, "outcome-room://or_1").unwrap()).unwrap(), before, "refused mutations change NOTHING");
        // Exact revision → transition lands with revision+1, receipt in the trail, bound facts.
        let (updated, receipt) = mutate_room(data_dir, "or_1", &json!({ "expected_revision": 1 }), "pause", |room| {
            room.as_object_mut().unwrap().insert("status".into(), json!("paused"));
            Ok(json!({ "transition": "pause", "from": "open", "to": "paused" }))
        }).unwrap();
        assert_eq!(updated["revision"], json!(2));
        assert_eq!(updated["status"], json!("paused"));
        assert!(s(&receipt, "receipt_id", "").starts_with("receipt://ort_"));
        assert_eq!(receipt["receipt_type"], json!("OutcomeRoomTransitionReceipt"));
        assert_eq!(receipt["bound_facts"]["to"], json!("paused"));
        assert_eq!(updated["admission_and_replay_refs"].as_array().unwrap().last().unwrap(), &receipt["receipt_ref"]);
        // The hash recomputes from the persisted record minus the declared excludes.
        let persisted = load_room(data_dir, "outcome-room://or_1").unwrap();
        assert_eq!(s(&receipt, "output_hash", ""), record_output_hash(&persisted, ROOM_HASH_EXCLUDES));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn receipt_failure_restores_the_exact_prior_room() {
        let dir = temp_dir("restore");
        let data_dir = dir.to_str().unwrap();
        let mut room = validate_room_create(&valid_room_body()).unwrap();
        {
            let obj = room.as_object_mut().unwrap();
            obj.insert("outcome_room_id".into(), json!("outcome-room://or_1"));
            obj.insert("created_at".into(), json!("2026-01-01T00:00:00Z"));
            obj.insert("updated_at".into(), json!("2026-01-01T11:11:11Z"));
        }
        persist_room_atomic(data_dir, "or_1", &room).unwrap();
        let before = serde_json::to_vec(&load_room(data_dir, "outcome-room://or_1").unwrap()).unwrap();
        std::fs::write(dir.join(ROOM_RECEIPT_DIR), b"blocker").unwrap();
        let e = mutate_room(data_dir, "or_1", &json!({ "expected_revision": 1 }), "pause", |room| {
            room.as_object_mut().unwrap().insert("status".into(), json!("paused"));
            Ok(json!({}))
        }).unwrap_err();
        assert_eq!(e.0, "outcome_room_receipt_persist_failed");
        let after = serde_json::to_vec(&load_room(data_dir, "outcome-room://or_1").unwrap()).unwrap();
        assert_eq!(after, before, "the room is BYTE-FOR-BYTE the prior record (status, revision, updated_at)");
        // No temp artifact survives.
        let tmp_leaks: Vec<String> = std::fs::read_dir(dir.join(ROOM_DIR)).unwrap()
            .filter_map(|e2| e2.ok())
            .map(|e2| e2.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(tmp_leaks.is_empty(), "no .tmp-* leak: {tmp_leaks:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_replacement_cleans_temp_on_rename_failure() {
        let dir = temp_dir("tmpclean");
        let data_dir = dir.to_str().unwrap();
        let record_dir = dir.join(ROOM_DIR);
        std::fs::create_dir_all(record_dir.join("or_block.json").join("occupied")).unwrap();
        assert!(persist_room_atomic(data_dir, "or_block", &json!({})).is_err());
        let tmp_leaks: Vec<String> = std::fs::read_dir(&record_dir).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(tmp_leaks.is_empty(), "no temporary artifact survives: {tmp_leaks:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_receipt_carries_the_pinned_envelope_base() {
        let (_, receipt) = build_room_receipt(
            ADMISSION_RECEIPT_SCHEMA, "OutcomeRoomAdmissionReceipt", "orr", "outcome-room://or_k", "admitted",
            json!({ "room_mode": "private_goal" }), vec![json!("outcome-room://or_k")],
            "sha256:x".into(), "admitted_not_verified", "n", "2026-01-01T00:00:00Z",
        );
        let expected = [
            "schema_version", "receipt_id", "receipt_ref", "receipt_type", "receipt_profile_ref",
            "actor_id", "subject_ref", "op", "attested_boundary_fact_refs", "bound_facts",
            "output_hash", "hash_scope_excludes", "assurance_posture", "assurance_note",
            "verification_ref", "acceptance_ref", "claim_scope_ref", "run_id", "task_id",
            "input_hash", "policy_hash", "authority_grant_id", "primitive_capabilities",
            "authority_scopes", "artifact_refs", "evidence_bundle_refs", "adjudication_ref",
            "settlement_ref", "signature", "l1_commitment", "timestamp", "outcome", "at",
        ];
        let mut exp: Vec<&str> = expected.to_vec();
        exp.sort_unstable();
        let mut actual: Vec<String> = receipt.as_object().unwrap().keys().cloned().collect();
        actual.sort_unstable();
        assert_eq!(actual, exp.iter().map(|k| k.to_string()).collect::<Vec<_>>(), "room receipt base drifted from the pinned ReceiptEnvelope key set");
    }
}
