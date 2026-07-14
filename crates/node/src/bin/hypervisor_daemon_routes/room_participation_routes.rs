//! Room participation plane — build step 3, first pair (#74): `RoomParticipationRequest` +
//! `RoomParticipantLease` over the hosted OutcomeRoom aggregate (canonical owner:
//! docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md; envelopes:
//! common-objects-and-envelopes.md §RoomParticipationRequestEnvelope /
//! §RoomParticipantLeaseEnvelope). Participation is a LEASE, not ambient membership: a typed
//! admission request carries identity, affiliation, eligibility evidence, and requested scopes;
//! the hosted admission owner admits a bounded lease or rejects without granting context or
//! power. A lease record grants NOTHING by itself — context/authority/budget powers stay
//! declared refs to their own governed planes.
//!
//! Step-3 contract (honest scope):
//! - HOSTED admission only; `federated_admission`, AIIP signatures, and
//!   `room_discovery_ref` are named gaps (build steps 7-8) — declared, never faked.
//! - Request lifecycle: creation admits as `submitted`; `evaluate` → evaluating;
//!   `reject` / `withdraw` are terminal; `admit` (its own endpoint) mints the lease in ONE
//!   crash-convergent finalization. `draft` is client-side; `expired` needs TTL/clock authority
//!   (named gap).
//! - Lease lifecycle: admitted `active`; suspend/resume, sleep/wake, wait/activate,
//!   quarantine/release_quarantine, retire, revoke. `invited`/`joining` (invite flow),
//!   `retiring` (claim-release orchestration, arrives with WorkClaimLease), and `expire`
//!   (TTL/clock) are named gaps. Revocation ends FUTURE participation only: it appends the
//!   revocation receipt, never erases lineage.
//! - OutcomeRoom backlinks (`participation_request_refs`, `participant_lease_refs`) are bound
//!   EXCLUSIVELY through the room-owned seam `outcome_room_routes::bind_room_backlink` — this
//!   plane never writes a room record.
//! - Every admitted mutation is an intent transaction on the shared durable core (#73):
//!   durable intent → append-only no-clobber receipt → terminal record, with a boot completer
//!   that reconstructs the ONLY valid successor (record AND receipt) through the SAME
//!   constructors and requires byte equality before converging — the full #72 discipline.
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::outcome_room_routes::{
    self as rooms, build_room_receipt_at, check_expected_revision, is_canonical_receipt_tail,
    is_rfc3339, list_ref, record_output_hash, reject_sensitive_keys, required_ref, s, scalar_ref,
    str_opt_bounded, verr, vocab_required, VErr,
};
use super::{iso_now, DaemonState};

const REQUEST_SCHEMA: &str = "ioi.hypervisor.room-participation-request.v1";
const LEASE_SCHEMA: &str = "ioi.hypervisor.room-participant-lease.v1";
const REQUEST_RECEIPT_SCHEMA: &str = "ioi.hypervisor.room-participation-request-receipt.v1";
const LEASE_RECEIPT_SCHEMA: &str = "ioi.hypervisor.room-participant-lease-receipt.v1";
pub(crate) const REQUEST_DIR: &str = "room-participation-requests";
pub(crate) const LEASE_DIR: &str = "room-participant-leases";
const RECEIPT_DIR: &str = "room-participation-receipts";
const SUBMIT_INTENT_DIR: &str = "room-participation-submit-intents";

// Receipt assurance notes — shared by finalizers AND replay validators, so a reconstructed
// receipt is byte-identical to the finalized one.
const SUBMIT_NOTE: &str = "admission of a typed participation request — a receipt is not eligibility, admission, or authority; the hosted owner's decision is its own receipted transition";
const REQUEST_TRANSITION_NOTE: &str = "an admitted participation-request transition — receipted, optimistically concurrent, and honest about being admission (not verification)";
const ADMIT_NOTE: &str = "an admitted participation decision — the request's terminal admission and the bounded participant lease land in one crash-convergent finalization; the lease grants nothing beyond its own declared refs";
const LEASE_TRANSITION_NOTE: &str = "an admitted participant-lease transition — receipted, optimistically concurrent; revocation ends FUTURE participation and never erases contribution lineage";

/// Canonical vocabularies (envelopes, verbatim).
const REQUEST_STATUSES: &[&str] = &[
    "draft",
    "submitted",
    "evaluating",
    "admitted",
    "rejected",
    "withdrawn",
    "expired",
];
const LEASE_STATUSES: &[&str] = &[
    "invited",
    "joining",
    "active",
    "sleeping",
    "waiting",
    "suspended",
    "quarantined",
    "retiring",
    "retired",
    "revoked",
];
const ADMITTED_ROLES: &[&str] = &[
    "conductor",
    "implementer",
    "reviewer",
    "verifier",
    "operator",
    "researcher",
    "specialist",
    "synthesizer",
    "resource_provider",
    "integrity_challenger",
    "memory_curator",
];
/// Request lifecycle: name → (allowed from-statuses, to-status). `admit` is NOT here — it mints
/// a lease and runs through its own endpoint + finalization.
const REQUEST_TRANSITIONS: &[(&str, &[&str], &str)] = &[
    ("evaluate", &["submitted"], "evaluating"),
    ("reject", &["submitted", "evaluating"], "rejected"),
    ("withdraw", &["submitted", "evaluating"], "withdrawn"),
];
const UNAVAILABLE_REQUEST_TRANSITIONS: &[(&str, &str)] = &[
    (
        "expire",
        "TTL/clock authority (a later build step) — expiry is never faked by a wall-clock guess",
    ),
    (
        "admit",
        "the admit endpoint (it mints the participant lease in one finalization)",
    ),
];
/// Lease lifecycle: name → (allowed from-statuses, to-status). Terminal: retired, revoked.
const LEASE_TRANSITIONS: &[(&str, &[&str], &str)] = &[
    ("suspend", &["active", "sleeping", "waiting"], "suspended"),
    ("resume", &["suspended"], "active"),
    ("sleep", &["active", "waiting"], "sleeping"),
    ("wake", &["sleeping"], "active"),
    ("wait", &["active"], "waiting"),
    ("activate", &["waiting"], "active"),
    (
        "quarantine",
        &["active", "sleeping", "waiting", "suspended"],
        "quarantined",
    ),
    ("release_quarantine", &["quarantined"], "active"),
    (
        "retire",
        &["active", "sleeping", "waiting", "suspended"],
        "retired",
    ),
    (
        "revoke",
        &["active", "sleeping", "waiting", "suspended", "quarantined"],
        "revoked",
    ),
];
const UNAVAILABLE_LEASE_TRANSITIONS: &[(&str, &str)] = &[
    ("invite", "the invite flow (invited/joining statuses) — a later leg of this plane"),
    ("join", "the invite flow (invited/joining statuses) — a later leg of this plane"),
    ("begin_retirement", "claim-release orchestration (`retiring`) — arrives with WorkClaimLease (build step 3, #76)"),
    ("expire", "TTL/clock authority (a later build step) — expiry is never faked by a wall-clock guess"),
];

/// CREATION hash scope: the admission receipt binds the DECLARED shape — plane-owned mutable
/// fields are excluded so later receipted transitions never invalidate it.
const REQUEST_CREATE_EXCLUDES: &[&str] = &[
    "admission_receipt_ref",
    "updated_at",
    "revision",
    "status",
    "status_history",
    "admission_and_replay_refs",
    "admission_decision_ref",
    "participant_lease_ref",
    "request_hash",
];
const LEASE_CREATE_EXCLUDES: &[&str] = &[
    "admission_receipt_ref",
    "updated_at",
    "revision",
    "status",
    "status_history",
    "admission_and_replay_refs",
    "future_access_revocation_refs",
    "exit_and_claim_release_refs",
];
/// TRANSITION hash scope: the receipt hashes the transition's OUTPUT — only the circular
/// receipt-bearing fields are excluded.
const TRAIL_EXCLUDES: &[&str] = &[
    "admission_receipt_ref",
    "admission_and_replay_refs",
    "status_history",
];

const HISTORY_MAX: usize = 100;
const REF_MAX: usize = 300;

/// Serializes every PARTICIPATION-scope critical section. LOCK ORDERING (fixed, documented):
/// PARTICIPATION_LOCK is acquired BEFORE the room plane's ROOM_MUTATION_LOCK (taken inside
/// `bind_room_backlink`); no path ever takes them in the reverse order, and no .await runs
/// under either lock.
static PARTICIPATION_LOCK: Mutex<()> = Mutex::new(());

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn is_canonical_request_tail(tail: &str) -> bool {
    is_canonical_receipt_tail(tail, "rpr")
}
fn is_canonical_lease_tail(tail: &str) -> bool {
    is_canonical_receipt_tail(tail, "rpl")
}

// ================================ STRICT STORAGE ACCESS ==========================================

/// Persist a MUTABLE plane record through the shared typed durable writer (#73).
fn persist_atomic(
    data_dir: &str,
    family: &str,
    record_id: &str,
    record: &Value,
) -> Result<(), super::durable_fs::PersistFailure> {
    super::durable_fs::persist_record_durable(data_dir, family, record_id, record)
}

/// The shared no-clobber receipt commit mapped onto this plane's wire codes.
fn persist_receipt(data_dir: &str, tail: &str, receipt: &Value) -> Result<(), VErr> {
    use super::durable_fs::CommitFailure;
    super::durable_fs::persist_receipt_no_clobber(data_dir, RECEIPT_DIR, tail, receipt).map_err(
        |f| match f {
            CommitFailure::KeyInvalid(m) => verr("room_participation_receipt_key_invalid", m),
            CommitFailure::NotCommitted(m) => verr("room_participation_receipt_persist_failed", m),
            CommitFailure::SlotUnreadable(m) => {
                verr("room_participation_receipt_slot_unreadable", m)
            }
            CommitFailure::Conflict(m) => verr("room_participation_receipt_conflict", m),
            CommitFailure::DurabilityUnconfirmed(m) => {
                verr("room_participation_receipt_durability_unconfirmed", m)
            }
            CommitFailure::Swapped(m) => verr("room_participation_receipt_swapped", m),
        },
    )
}

/// Strict slot read keyed by a CANONICAL stem (validated BEFORE any filesystem access), through
/// the shared pinned no-follow primitives. Ok(None) = definitively absent; Err = unreadable /
/// non-JSON occupant — write-side callers refuse, read paths map Err to invisible.
fn read_slot_strict(
    data_dir: &str,
    family: &str,
    stem: &str,
    canonical: fn(&str) -> bool,
) -> Result<Option<Value>, String> {
    if !canonical(stem) {
        return Err(format!(
            "non-canonical stem '{stem}' — refused before any filesystem access"
        ));
    }
    let dir = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("family '{family}' unavailable ({e})")),
    };
    match super::durable_fs::read_slot_strict(&dir, &format!("{stem}.json")) {
        Ok(None) => Ok(None),
        Ok(Some((_f, bytes))) => serde_json::from_slice::<Value>(&bytes)
            .map(Some)
            .map_err(|e| format!("slot '{stem}' holds non-JSON content ({e})")),
        Err(e) => Err(format!(
            "slot '{stem}' is occupied but not readable as a regular file ({e})"
        )),
    }
}

/// Scan a plane family as (canonical-stem, value) pairs through the pinned fd (#72 round 21
/// finding 3 discipline): a scan failure is a TYPED error, never a false-empty registry; the
/// file STEM is the trusted storage key and content identity must agree with it.
fn scan_family(
    data_dir: &str,
    family: &str,
    id_field: &str,
    id_prefix: &str,
    canonical: fn(&str) -> bool,
) -> Result<Vec<(String, Value)>, String> {
    let dir = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("family '{family}' directory could not be pinned ({e}) — refusing to report a false-empty registry")),
    };
    let names = super::durable_fs::enumerate_pinned(&dir).map_err(|e| format!("family '{family}' could not be enumerated ({e}) — refusing to report a false-empty registry"))?;
    let mut out = Vec::new();
    for name in names {
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if !canonical(stem) {
            continue;
        }
        match super::durable_fs::read_slot_strict(&dir, &name) {
            Ok(Some((_f, bytes))) => {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    // Content identity must agree with the trusted storage key.
                    if value.get(id_field).and_then(Value::as_str)
                        == Some(format!("{id_prefix}{stem}").as_str())
                    {
                        out.push((stem.to_string(), value));
                    }
                }
            }
            _ => continue,
        }
    }
    Ok(out)
}

fn load_request(data_dir: &str, tail: &str) -> Option<Value> {
    let id = format!("participation-request://{tail}");
    read_slot_strict(data_dir, REQUEST_DIR, tail, is_canonical_request_tail)
        .ok()
        .flatten()
        .filter(|r| r.get("participation_request_id").and_then(Value::as_str) == Some(id.as_str()))
}

fn load_lease(data_dir: &str, tail: &str) -> Option<Value> {
    let id = format!("participant-lease://{tail}");
    read_slot_strict(data_dir, LEASE_DIR, tail, is_canonical_lease_tail)
        .ok()
        .flatten()
        .filter(|r| r.get("participant_lease_id").and_then(Value::as_str) == Some(id.as_str()))
}

/// Which durable intent (if any) is pending on a plane record — EVERY mutator refuses while one
/// is in flight; a restart (boot completer) converges it first.
fn pending_intent(record: &Value) -> Option<(&'static str, &'static str)> {
    if record.get("admit_intent").is_some() {
        return Some(("admit_intent", "room_participation_admit_in_flight"));
    }
    if record.get("transition_intent").is_some() {
        return Some((
            "transition_intent",
            "room_participation_transition_in_flight",
        ));
    }
    None
}

// ================================ DECLARATION VALIDATORS =========================================

/// Validate + canonicalize the participation-request DECLARATION (the caller-owned shape) —
/// used by creation AND by replay reconstruction, so a hollow or drifted envelope can never
/// converge (#72 round 16 discipline). Returns the canonical declaration record.
fn validate_request_create(body: &Value) -> Result<Value, VErr> {
    reject_sensitive_keys(body, "")?;
    // Plane-owned scalars refuse typed.
    for (key, code, why) in [
        ("status", "room_participation_status_plane_owned", "a typed request admits as `submitted`; decisions are receipted transitions"),
        ("participant_lease_ref", "room_participation_field_plane_owned", "the lease ref is minted by an admitted decision"),
        ("admission_decision_ref", "room_participation_field_plane_owned", "the decision ref is minted by an admitted decision"),
        ("request_hash", "room_participation_field_plane_owned", "the request hash is computed by this plane"),
        ("revision", "room_participation_field_plane_owned", "`revision` is minted by this plane"),
        ("admission_receipt_ref", "room_participation_field_plane_owned", "receipts are minted by this plane"),
        ("signature", "room_participation_signature_unavailable", "AIIP-signed requests are the federated/discovery leg (build steps 7-8) — a named gap, never faked"),
        ("room_discovery_ref", "room_participation_discovery_unavailable", "OutcomeRoomDiscoveryEnvelope is the AIIP discovery leg (build step 7) — a named gap, never faked"),
    ] {
        if body.get(key).map(|v| !v.is_null()).unwrap_or(false) {
            return Err(verr(code, why));
        }
    }
    let outcome_room_ref = required_ref(
        body,
        "outcome_room_ref",
        &["outcome-room"],
        "room_participation_room_required",
    )?;
    let requested_by = required_ref(
        body,
        "requested_by_ref",
        &["worker", "service", "org", "domain"],
        "room_participation_requested_by_required",
    )?;
    let topology = vocab_required(
        body,
        "coordination_topology",
        &["hosted_admission", "federated_admission"],
        "room_participation_topology_invalid",
    )?;
    if topology == "federated_admission" {
        return Err(verr("room_participation_federated_unavailable", "`federated_admission` participation needs the AIIP leg (build steps 7-8) — hosted_admission is the step-3 contract"));
    }
    let admission_owner = required_ref(
        body,
        "admission_owner_ref",
        &["domain", "policy"],
        "room_participation_admission_owner_required",
    )?;
    // The canon pins `private_context_included: false` — a request NEVER carries raw context.
    match body.get("private_context_included") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => return Err(verr("room_participation_private_context_rejected", "`private_context_included` must be false — a participation request never carries raw private context")),
        Some(_) => return Err(verr("room_participation_private_context_rejected", "`private_context_included` must be the boolean false")),
    }
    let record = json!({
        "outcome_room_ref": outcome_room_ref,
        "requested_by_ref": requested_by,
        "operator_and_home_domain_refs": list_ref(body, "operator_and_home_domain_refs", &["user", "wallet", "org", "domain", "system"])?,
        "worker_composition_and_dependency_refs": list_ref(body, "worker_composition_and_dependency_refs", &["package", "worker", "model-route", "harness-profile", "runtime", "provider"])?,
        "capability_offer_refs": list_ref(body, "capability_offer_refs", &["capability-offer", "ai", "package"])?,
        "affiliation_and_independent_operation_evidence_refs": list_ref(body, "affiliation_and_independent_operation_evidence_refs", &["evidence", "receipt", "org", "certification-claim"])?,
        "supported_semantic_and_action_profile_refs": list_ref(body, "supported_semantic_and_action_profile_refs", &["ontology", "semantic-profile", "ontology-mapping", "ontology-action", "action-schema"])?,
        "eligibility_evidence_refs": list_ref(body, "eligibility_evidence_refs", &["evidence", "receipt", "benchmark", "conformance-profile", "certification-claim"])?,
        "requested_role_frontier_and_visibility_refs": list_ref(body, "requested_role_frontier_and_visibility_refs", &["frontier", "policy", "restricted-view"])?,
        "privacy_custody_and_context_policy_refs": list_ref(body, "privacy_custody_and_context_policy_refs", &["privacy-posture", "custody", "policy"])?,
        "proposed_quote_and_budget_refs": list_ref(body, "proposed_quote_and_budget_refs", &["quote", "goal-budget", "order"])?,
        "accepted_verifier_settlement_dispute_and_contribution_policy_refs": list_ref(body, "accepted_verifier_settlement_dispute_and_contribution_policy_refs", &["verifier-path", "policy", "settlement-intent", "dispute"])?,
        "requested_participant_state_export_policy_ref": scalar_ref(body, "requested_participant_state_export_policy_ref", &["policy"])?,
        "coordination_topology": topology,
        "admission_owner_ref": admission_owner,
        "private_context_included": false,
        "room_discovery_ref": Value::Null,
        "signature": Value::Null,
    });
    Ok(record)
}

/// Seal a validated declaration into the COMPLETE submitted request — creation and replay
/// reconstruction both call THIS, so a replay byte-compares against the only valid shape.
fn seal_request(declaration: &Value, tail: &str, receipt_ref: &str, now: &str) -> Value {
    let mut record = declaration.clone();
    let obj = record.as_object_mut().expect("declaration is an object");
    obj.insert("schema_version".into(), json!(REQUEST_SCHEMA));
    obj.insert(
        "participation_request_id".into(),
        json!(format!("participation-request://{tail}")),
    );
    obj.insert("status".into(), json!("submitted"));
    obj.insert("revision".into(), json!(1));
    obj.insert("status_history".into(), json!([]));
    obj.insert("created_at".into(), json!(now));
    obj.insert("updated_at".into(), json!(now));
    obj.insert("admission_receipt_ref".into(), json!(receipt_ref));
    obj.insert("admission_and_replay_refs".into(), json!([receipt_ref]));
    obj.insert("admission_decision_ref".into(), Value::Null);
    obj.insert("participant_lease_ref".into(), Value::Null);
    obj.insert("runtimeTruthSource".into(), json!("daemon-runtime"));
    // request_hash binds the DECLARED shape (computed over the sealed record minus plane-owned
    // mutables — the same scope the admission receipt hashes).
    let h = record_output_hash(&record, REQUEST_CREATE_EXCLUDES);
    record
        .as_object_mut()
        .expect("object")
        .insert("request_hash".into(), json!(h));
    record
}

/// Validate + canonicalize the host's ADMIT parameters — used by the admit endpoint AND by
/// replay reconstruction.
fn validate_admit_params(body: &Value) -> Result<Value, VErr> {
    reject_sensitive_keys(body, "")?;
    let admitted_role = vocab_required(
        body,
        "admitted_role",
        ADMITTED_ROLES,
        "participant_lease_role_invalid",
    )?;
    let operator_ref = required_ref(
        body,
        "operator_ref",
        &["user", "org", "wallet", "domain"],
        "participant_lease_operator_required",
    )?;
    let home_domain_ref = required_ref(
        body,
        "home_domain_ref",
        &["domain", "system"],
        "participant_lease_home_domain_required",
    )?;
    let ttl = match body.get("ttl_seconds") {
        None | Some(Value::Null) => Value::Null,
        Some(v) => match v.as_u64() {
            Some(n) if n > 0 => json!(n),
            _ => {
                return Err(verr(
                    "participant_lease_ttl_invalid",
                    "`ttl_seconds` must be a positive integer or null",
                ))
            }
        },
    };
    Ok(json!({
        "admitted_role": admitted_role,
        "operator_ref": operator_ref,
        "home_domain_ref": home_domain_ref,
        "visibility_scope_ref": scalar_ref(body, "visibility_scope_ref", &["policy", "restricted-view"])?,
        "context_and_authority_lease_refs": list_ref(body, "context_and_authority_lease_refs", &["context-lease", "grant", "authority"])?,
        "runtime_resource_and_budget_lease_refs": list_ref(body, "runtime_resource_and_budget_lease_refs", &["lease", "resource-lease", "budget"])?,
        "ttl_seconds": ttl,
    }))
}

/// Build the COMPLETE bounded lease from the (pre-admit) request + validated admit params —
/// the admit finalizer and the replay validator both call THIS.
fn build_lease(
    request: &Value,
    params: &Value,
    lease_tail: &str,
    lease_receipt_ref: &str,
    now: &str,
) -> Value {
    let mut identity_refs: Vec<Value> = request
        .get("affiliation_and_independent_operation_evidence_refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    identity_refs.extend(
        request
            .get("eligibility_evidence_refs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
    );
    let mut record = json!({
        "schema_version": LEASE_SCHEMA,
        "participant_lease_id": format!("participant-lease://{lease_tail}"),
        "outcome_room_ref": request.get("outcome_room_ref").cloned().unwrap_or(Value::Null),
        "participant_ref": request.get("requested_by_ref").cloned().unwrap_or(Value::Null),
        "admitted_role": params.get("admitted_role").cloned().unwrap_or(Value::Null),
        "operator_ref": params.get("operator_ref").cloned().unwrap_or(Value::Null),
        "home_domain_ref": params.get("home_domain_ref").cloned().unwrap_or(Value::Null),
        "worker_and_runtime_refs": request.get("worker_composition_and_dependency_refs").cloned().unwrap_or(json!([])),
        "capability_advertisement_refs": request.get("capability_offer_refs").cloned().unwrap_or(json!([])),
        "tool_connector_and_capability_dependency_refs": [],
        "join_request_ref": request.get("participation_request_id").cloned().unwrap_or(Value::Null),
        "identity_and_eligibility_evidence_refs": identity_refs,
        "admission_decision_ref": lease_receipt_ref,
        "visibility_scope_ref": params.get("visibility_scope_ref").cloned().unwrap_or(Value::Null),
        "context_and_authority_lease_refs": params.get("context_and_authority_lease_refs").cloned().unwrap_or(json!([])),
        "runtime_resource_and_budget_lease_refs": params.get("runtime_resource_and_budget_lease_refs").cloned().unwrap_or(json!([])),
        "current_claim_ref": Value::Null,
        "heartbeat_ref": Value::Null,
        "next_wake_condition_ref": Value::Null,
        "quiet_hours_or_backoff_ref": Value::Null,
        "last_contribution_ref": Value::Null,
        "exit_and_claim_release_refs": [],
        "portable_participant_state_bundle_ref": Value::Null,
        "future_access_revocation_refs": [],
        "ttl_seconds": params.get("ttl_seconds").cloned().unwrap_or(Value::Null),
        "status": "active",
        "revision": 1,
        "status_history": [],
        "created_at": now,
        "updated_at": now,
        "admission_receipt_ref": lease_receipt_ref,
        "admission_and_replay_refs": [lease_receipt_ref],
        "runtimeTruthSource": "daemon-runtime"
    });
    let _ = &mut record;
    record
}

/// Apply a lease transition deterministically — finalizer AND replay validator call THIS.
/// Revocation appends the revocation receipt to `future_access_revocation_refs` (future access
/// ends; lineage is never erased).
fn apply_transition(
    record: &Value,
    intent_field: &str,
    op: &str,
    to_status: &str,
    receipt_ref: &Value,
    now: &Value,
    extra_revocation: bool,
) -> Value {
    let prior_rev = record.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let from = s(record, "status", "");
    let mut updated = record.clone();
    if let Some(obj) = updated.as_object_mut() {
        obj.remove(intent_field);
        obj.insert("status".into(), json!(to_status));
        obj.insert("revision".into(), json!(prior_rev + 1));
        obj.insert("updated_at".into(), now.clone());
        let mut trail: Vec<Value> = obj
            .get("admission_and_replay_refs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        trail.push(receipt_ref.clone());
        obj.insert("admission_and_replay_refs".into(), Value::Array(trail));
        let mut history: Vec<Value> = obj
            .get("status_history")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        history.push(json!({ "op": op, "from": from, "at": now, "receipt_ref": receipt_ref, "revision": prior_rev + 1 }));
        if history.len() > HISTORY_MAX {
            let drop_n = history.len() - HISTORY_MAX;
            history.drain(0..drop_n);
        }
        obj.insert("status_history".into(), Value::Array(history));
        if extra_revocation {
            let mut revs: Vec<Value> = obj
                .get("future_access_revocation_refs")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            revs.push(receipt_ref.clone());
            obj.insert("future_access_revocation_refs".into(), Value::Array(revs));
        }
    }
    updated
}

// ================================ FINALIZERS =====================================================

/// Duplicate-live guard: at most ONE live (non-terminal) request per (room, principal), and at
/// most ONE live lease per (room, participant). Scans are TYPED — an unreadable registry
/// refuses rather than admitting a duplicate over unknown truth.
fn live_request_exists(data_dir: &str, room_ref: &str, principal: &str) -> Result<bool, VErr> {
    let requests = scan_family(
        data_dir,
        REQUEST_DIR,
        "participation_request_id",
        "participation-request://",
        is_canonical_request_tail,
    )
    .map_err(|e| verr("room_participation_registry_unreadable", e))?;
    Ok(requests.iter().any(|(_, r)| {
        s(r, "outcome_room_ref", "") == room_ref
            && s(r, "requested_by_ref", "") == principal
            && matches!(s(r, "status", "").as_str(), "submitted" | "evaluating")
    }))
}

fn live_lease_exists(data_dir: &str, room_ref: &str, participant: &str) -> Result<bool, VErr> {
    let leases = scan_family(
        data_dir,
        LEASE_DIR,
        "participant_lease_id",
        "participant-lease://",
        is_canonical_lease_tail,
    )
    .map_err(|e| verr("participant_lease_registry_unreadable", e))?;
    Ok(leases.iter().any(|(_, l)| {
        s(l, "outcome_room_ref", "") == room_ref
            && s(l, "participant_ref", "") == participant
            && !matches!(s(l, "status", "").as_str(), "retired" | "revoked")
    }))
}

/// SUBMIT finalization: durable internal intent → append-only receipt → room backlink (through
/// the room-owned seam; `already_bound` = converged replay) → terminal request → consume the
/// intent. Any failure after the intent refuses typed with the intent RETAINED — a restart
/// converges this same submission.
fn finalize_submit(
    data_dir: &str,
    tail: &str,
    final_request: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    let intent = json!({
        "kind": "submit",
        "request_tail": tail,
        "request_ref": final_request.get("participation_request_id").cloned().unwrap_or(Value::Null),
        "room_ref": final_request.get("outcome_room_ref").cloned().unwrap_or(Value::Null),
        "final_request": final_request,
        "final_request_hash": record_output_hash(final_request, &[]),
        "receipt_id": receipt_id,
        "receipt": receipt,
        "receipt_hash": record_output_hash(receipt, &[]),
        "at": final_request.get("updated_at").cloned().unwrap_or(Value::Null),
    });
    if let Err(f) = persist_atomic(data_dir, SUBMIT_INTENT_DIR, tail, &intent) {
        if f.visible() {
            return Err(verr("room_participation_submit_pending_convergence", format!("the submit intent is {} — a restart converges this same submission; do not re-submit", f.detail())));
        }
        return Err(verr(
            "room_participation_persist_failed",
            format!(
                "the submit intent did not commit ({}) — nothing was admitted",
                f.detail()
            ),
        ));
    }
    complete_submit(data_dir, tail, final_request, receipt_id, receipt)
}

/// The convergent tail of a submission — called by the finalizer AND (after validation) by the
/// boot completer, so both paths produce the identical durable outcome.
fn complete_submit(
    data_dir: &str,
    tail: &str,
    final_request: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    persist_receipt(data_dir, receipt_id, receipt).map_err(|(code, msg)| {
        let ecode = if code == "room_participation_receipt_conflict" || code == "room_participation_receipt_slot_unreadable" || code == "room_participation_receipt_swapped" { code } else { "room_participation_submit_pending_convergence".to_string() };
        (ecode, format!("the submission receipt is not durably committed ({msg}); the DURABLE intent is retained — a restart converges this same submission"))
    })?;
    let room_ref = s(final_request, "outcome_room_ref", "");
    let request_id = s(final_request, "participation_request_id", "");
    match rooms::bind_room_backlink(
        data_dir,
        &room_ref,
        "participation_request_bound",
        &request_id,
    ) {
        Ok(_) => {}
        // Idempotent replay: the ref landed before a crash — converged, not a conflict.
        Err((code, _)) if code == "outcome_room_backlink_already_bound" => {}
        Err((code, msg)) => {
            return Err(verr(&code, format!("{msg}; the DURABLE submit intent is retained — a restart converges this same submission")));
        }
    }
    if let Err(f) = persist_atomic(data_dir, REQUEST_DIR, tail, final_request) {
        if f.visible() {
            return Err(verr("room_participation_submit_pending_convergence", format!("the terminal request write is {} — the intent is retained; a restart re-verifies and completes", f.detail())));
        }
        return Err(verr("room_participation_submit_pending_convergence", format!("the terminal request write did not commit ({}) — the intent is retained; a restart completes it", f.detail())));
    }
    let _ = std::fs::remove_file(
        std::path::Path::new(data_dir)
            .join(SUBMIT_INTENT_DIR)
            .join(format!("{tail}.json")),
    );
    Ok(())
}

/// Single-record transition finalization (request or lease): seal the intent ON the record →
/// receipt (append-only) → terminal record with the intent consumed. Receipt failure retains
/// the intent (visible/unconfirmed evidence is never rolled back "as absent").
fn finalize_record_transition(
    data_dir: &str,
    family: &str,
    tail: &str,
    prior: &Value,
    updated: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    let mut carrying = prior.clone();
    carrying.as_object_mut().expect("object").insert(
        "transition_intent".into(),
        json!({
            "op": receipt.get("op").cloned().unwrap_or(Value::Null),
            "final_record": updated,
            "final_record_hash": record_output_hash(updated, &[]),
            "receipt_id": receipt_id,
            "receipt": receipt,
            "receipt_hash": record_output_hash(receipt, &[]),
            "at": updated.get("updated_at").cloned().unwrap_or(Value::Null),
        }),
    );
    if let Err(f) = persist_atomic(data_dir, family, tail, &carrying) {
        if f.visible() {
            return Err(verr("room_participation_transition_pending_convergence", format!("the transition intent is {} — a restart converges it; the visible state may already carry the intent", f.detail())));
        }
        return Err(verr(
            "room_participation_persist_failed",
            format!(
                "the transition intent did not commit ({}) — nothing changed",
                f.detail()
            ),
        ));
    }
    match persist_receipt(data_dir, receipt_id, receipt) {
        Ok(()) => {}
        Err((code, msg)) if code == "room_participation_receipt_durability_unconfirmed" => {
            return Err(verr("room_participation_transition_pending_convergence", format!("{msg}; the DURABLE intent is retained with the record still showing its PRIOR state — a restart confirms the receipt and applies the transition")));
        }
        Err((code, msg))
            if code == "room_participation_receipt_conflict"
                || code == "room_participation_receipt_slot_unreadable"
                || code == "room_participation_receipt_swapped" =>
        {
            // Roll the intent back exactly — append-only evidence is never overwritten.
            return match persist_atomic(data_dir, family, tail, prior) {
                Ok(()) => Err(verr(
                    &code,
                    format!("{msg}; the intent was rolled back EXACTLY — nothing changed"),
                )),
                Err(_) => Err(verr(
                    &code,
                    format!(
                        "{msg} AND the intent rollback did not commit — manual repair required"
                    ),
                )),
            };
        }
        Err((_code, msg)) => {
            return match persist_atomic(data_dir, family, tail, prior) {
                Ok(()) => Err(verr("room_participation_receipt_persist_failed", format!("transition receipt persist did not commit ({msg}); the intent was rolled back EXACTLY — nothing changed"))),
                Err(_) => Err(verr("room_participation_transition_pending_convergence", format!("transition receipt persist did not commit ({msg}) AND the intent rollback did not commit — a restart converges the sealed transition"))),
            };
        }
    }
    if let Err(f) = persist_atomic(data_dir, family, tail, updated) {
        return Err(verr("room_participation_transition_pending_convergence", format!("the terminal transition write is {}; the DURABLE intent and receipt are retained — a restart completes the transition", f.detail())));
    }
    Ok(())
}

/// ADMIT finalization: seal the admit intent ON the request → lease receipt → request receipt →
/// room backlink (lease ref) → lease record → terminal request with the intent consumed. Every
/// failure after the durable intent refuses typed with the intent retained.
#[allow(clippy::too_many_arguments)]
fn finalize_admit(
    data_dir: &str,
    request_tail: &str,
    prior_request: &Value,
    admit: &Value,
) -> Result<(), VErr> {
    let mut carrying = prior_request.clone();
    carrying
        .as_object_mut()
        .expect("object")
        .insert("admit_intent".into(), admit.clone());
    if let Err(f) = persist_atomic(data_dir, REQUEST_DIR, request_tail, &carrying) {
        if f.visible() {
            return Err(verr(
                "room_participation_admit_pending_convergence",
                format!(
                    "the admit intent is {} — a restart converges it",
                    f.detail()
                ),
            ));
        }
        return Err(verr(
            "room_participation_persist_failed",
            format!(
                "the admit intent did not commit ({}) — nothing changed",
                f.detail()
            ),
        ));
    }
    complete_admit(data_dir, request_tail, prior_request, admit)
}

/// The convergent tail of an admission — finalizer AND (after validation) boot completer.
fn complete_admit(
    data_dir: &str,
    request_tail: &str,
    prior_request: &Value,
    admit: &Value,
) -> Result<(), VErr> {
    let final_request = admit.get("final_request").cloned().unwrap_or(Value::Null);
    let final_lease = admit.get("final_lease").cloned().unwrap_or(Value::Null);
    let lease_tail = admit
        .get("lease_tail")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let lease_receipt_id = admit
        .get("lease_receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let lease_receipt = admit.get("lease_receipt").cloned().unwrap_or(Value::Null);
    let request_receipt_id = admit
        .get("request_receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let request_receipt = admit.get("request_receipt").cloned().unwrap_or(Value::Null);
    let pend = |msg: String| -> VErr {
        verr("room_participation_admit_pending_convergence", format!("{msg}; the DURABLE admit intent is retained — a restart converges this same admission"))
    };
    persist_receipt(data_dir, &lease_receipt_id, &lease_receipt).map_err(|(code, msg)| {
        if code == "room_participation_receipt_conflict"
            || code == "room_participation_receipt_slot_unreadable"
            || code == "room_participation_receipt_swapped"
        {
            (code, msg)
        } else {
            pend(msg)
        }
    })?;
    persist_receipt(data_dir, &request_receipt_id, &request_receipt).map_err(|(code, msg)| {
        if code == "room_participation_receipt_conflict"
            || code == "room_participation_receipt_slot_unreadable"
            || code == "room_participation_receipt_swapped"
        {
            (code, msg)
        } else {
            pend(msg)
        }
    })?;
    let room_ref = s(&final_lease, "outcome_room_ref", "");
    let lease_id = s(&final_lease, "participant_lease_id", "");
    match rooms::bind_room_backlink(data_dir, &room_ref, "participant_lease_bound", &lease_id) {
        Ok(_) => {}
        Err((code, _)) if code == "outcome_room_backlink_already_bound" => {}
        Err((_code, msg)) => return Err(pend(msg)),
    }
    // The lease slot is append-only in spirit: an existing occupant must BE this sealed lease.
    match read_slot_strict(data_dir, LEASE_DIR, &lease_tail, is_canonical_lease_tail) {
        Ok(Some(existing)) => {
            if serde_json::to_vec(&existing).unwrap_or_default()
                != serde_json::to_vec(&final_lease).unwrap_or_default()
            {
                return Err(verr("participant_lease_conflict", format!("the lease slot '{lease_tail}' already holds DIFFERENT state — refused, never overwritten; the admit intent is retained for manual repair")));
            }
        }
        Ok(None) => {
            if let Err(f) = persist_atomic(data_dir, LEASE_DIR, &lease_tail, &final_lease) {
                return Err(pend(format!("the lease record write is {}", f.detail())));
            }
        }
        Err(e) => {
            return Err(verr(
                "participant_lease_registry_unreadable",
                format!("{e} — the admit intent is retained; never admitted over unknown truth"),
            ))
        }
    }
    if let Err(f) = persist_atomic(data_dir, REQUEST_DIR, request_tail, &final_request) {
        return Err(pend(format!(
            "the terminal request write is {}",
            f.detail()
        )));
    }
    let _ = prior_request;
    Ok(())
}

// ================================ REPLAY VALIDATORS ==============================================

/// Plane-owned + identity fields stripped from a sealed request to recover the ORIGINAL
/// declaration for reconstruction.
const REQUEST_PLANE_OWNED: &[&str] = &[
    "schema_version",
    "participation_request_id",
    "status",
    "revision",
    "status_history",
    "created_at",
    "updated_at",
    "admission_receipt_ref",
    "admission_and_replay_refs",
    "admission_decision_ref",
    "participant_lease_ref",
    "request_hash",
    "runtimeTruthSource",
];

/// Reconstruct the ONLY valid submitted request + EXACT receipt from a sealed submit intent;
/// byte-compare both. The TRUSTED key is the intent's filename stem.
fn validate_submit_intent(
    intent: &Value,
    request_tail: &str,
) -> Result<(Value, String, Value), String> {
    if !is_canonical_request_tail(request_tail) {
        return Err("non-canonical request tail (storage key)".into());
    }
    let final_request = intent.get("final_request").cloned().unwrap_or(Value::Null);
    let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
    let receipt_id = intent
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if intent.get("final_request_hash").and_then(Value::as_str)
        != Some(record_output_hash(&final_request, &[]).as_str())
    {
        return Err("final-request seal".into());
    }
    if intent.get("receipt_hash").and_then(Value::as_str)
        != Some(record_output_hash(&receipt, &[]).as_str())
    {
        return Err("receipt seal".into());
    }
    if !is_canonical_receipt_tail(&receipt_id, "rqr") {
        return Err("non-canonical submission receipt tail".into());
    }
    let request_id = format!("participation-request://{request_tail}");
    if intent.get("request_tail").and_then(Value::as_str) != Some(request_tail)
        || intent.get("request_ref").and_then(Value::as_str) != Some(request_id.as_str())
        || final_request
            .get("participation_request_id")
            .and_then(Value::as_str)
            != Some(request_id.as_str())
        || receipt.get("subject_ref").and_then(Value::as_str) != Some(request_id.as_str())
        || receipt
            .pointer("/attested_boundary_fact_refs/0")
            .and_then(Value::as_str)
            != Some(request_id.as_str())
    {
        return Err("request identity does not bind to the storage key".into());
    }
    let now = final_request
        .get("updated_at")
        .cloned()
        .unwrap_or(Value::Null);
    if !is_rfc3339(&now) || final_request.get("created_at") != final_request.get("updated_at") {
        return Err("submission timestamps invalid".into());
    }
    // Reconstruct THROUGH the declaration validator + sealer.
    let mut declaration = final_request.clone();
    if let Some(obj) = declaration.as_object_mut() {
        for k in REQUEST_PLANE_OWNED {
            obj.remove(*k);
        }
    }
    let validated = validate_request_create(&declaration)
        .map_err(|(_, m)| format!("sealed declaration does not validate: {m}"))?;
    let receipt_ref = format!("receipt://{receipt_id}");
    let expected = seal_request(
        &validated,
        request_tail,
        &receipt_ref,
        now.as_str().unwrap_or(""),
    );
    if serde_json::to_vec(&expected).unwrap_or_default()
        != serde_json::to_vec(&final_request).unwrap_or_default()
    {
        return Err("not the canonical sealed request".into());
    }
    let room_ref = s(&final_request, "outcome_room_ref", "");
    let expected_receipt = build_room_receipt_at(
        &receipt_id,
        REQUEST_RECEIPT_SCHEMA,
        "RoomParticipationRequestReceipt",
        &request_id,
        "submitted",
        json!({ "outcome_room_ref": room_ref, "requested_by_ref": s(&final_request, "requested_by_ref", ""), "status_at_submission": "submitted" }),
        vec![json!(request_id), json!(room_ref)],
        record_output_hash(&expected, REQUEST_CREATE_EXCLUDES),
        REQUEST_CREATE_EXCLUDES,
        "admitted_not_verified",
        SUBMIT_NOTE,
        now.as_str().unwrap_or(""),
    );
    if serde_json::to_vec(&expected_receipt).unwrap_or_default()
        != serde_json::to_vec(&receipt).unwrap_or_default()
    {
        return Err("not the canonical submission receipt".into());
    }
    Ok((final_request, receipt_id, receipt))
}

/// Reconstruct the ONLY valid single-record transition successor + EXACT receipt; byte-compare.
#[allow(clippy::too_many_arguments)]
fn validate_transition_intent(
    intent: &Value,
    prior: &Value,
    tail: &str,
    id_field: &str,
    id_prefix: &str,
    transitions: &[(&str, &[&str], &str)],
    receipt_prefix: &str,
    receipt_schema: &str,
    receipt_type: &str,
    note: &str,
    canonical: fn(&str) -> bool,
) -> Result<(Value, String, Value), String> {
    if !canonical(tail) {
        return Err("non-canonical storage key".into());
    }
    let final_record = intent.get("final_record").cloned().unwrap_or(Value::Null);
    let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
    let receipt_id = intent
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if intent.get("final_record_hash").and_then(Value::as_str)
        != Some(record_output_hash(&final_record, &[]).as_str())
    {
        return Err("final-record seal".into());
    }
    if intent.get("receipt_hash").and_then(Value::as_str)
        != Some(record_output_hash(&receipt, &[]).as_str())
    {
        return Err("receipt seal".into());
    }
    if !is_canonical_receipt_tail(&receipt_id, receipt_prefix) {
        return Err("non-canonical transition receipt tail".into());
    }
    let record_id = format!("{id_prefix}{tail}");
    if prior.get(id_field).and_then(Value::as_str) != Some(record_id.as_str())
        || final_record.get(id_field).and_then(Value::as_str) != Some(record_id.as_str())
        || receipt.get("subject_ref").and_then(Value::as_str) != Some(record_id.as_str())
        || receipt
            .pointer("/attested_boundary_fact_refs/0")
            .and_then(Value::as_str)
            != Some(record_id.as_str())
    {
        return Err("record identity does not bind to the storage key".into());
    }
    let now = final_record
        .get("updated_at")
        .cloned()
        .unwrap_or(Value::Null);
    if !is_rfc3339(&now) {
        return Err("transition updated_at not RFC3339".into());
    }
    let op = receipt.get("op").and_then(Value::as_str).unwrap_or("");
    let Some((_, allowed_from, to_status)) = transitions.iter().find(|(t, _, _)| *t == op) else {
        return Err("unknown transition op".into());
    };
    let from = prior.get("status").and_then(Value::as_str).unwrap_or("");
    if !allowed_from.contains(&from) {
        return Err("transition not admitted from prior status".into());
    }
    let prior_rev = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    if receipt_ref.as_str() != Some(format!("receipt://{receipt_id}").as_str()) {
        return Err("receipt ref vs intent tail".into());
    }
    let expected = apply_transition(
        prior,
        "transition_intent",
        op,
        to_status,
        &receipt_ref,
        &now,
        op == "revoke",
    );
    if serde_json::to_vec(&expected).unwrap_or_default()
        != serde_json::to_vec(&final_record).unwrap_or_default()
    {
        return Err("not the deterministic successor".into());
    }
    let expected_receipt = build_room_receipt_at(
        &receipt_id,
        receipt_schema,
        receipt_type,
        &record_id,
        op,
        json!({ "transition": op, "from": from, "to": to_status, "revision_before": prior_rev, "revision_after": prior_rev + 1 }),
        vec![
            json!(record_id),
            final_record
                .get("outcome_room_ref")
                .cloned()
                .unwrap_or(Value::Null),
        ],
        record_output_hash(&expected, TRAIL_EXCLUDES),
        TRAIL_EXCLUDES,
        "admitted_not_verified",
        note,
        now.as_str().unwrap_or(""),
    );
    if serde_json::to_vec(&expected_receipt).unwrap_or_default()
        != serde_json::to_vec(&receipt).unwrap_or_default()
    {
        return Err("not the canonical transition receipt".into());
    }
    Ok((final_record, receipt_id, receipt))
}

/// Reconstruct the ONLY valid admit outcome (terminal request + lease + BOTH receipts) from a
/// sealed admit intent; byte-compare all four. The TRUSTED key is the request record's stem.
fn validate_admit_intent(
    intent: &Value,
    prior_request: &Value,
    request_tail: &str,
) -> Result<(), String> {
    if !is_canonical_request_tail(request_tail) {
        return Err("non-canonical request tail (storage key)".into());
    }
    let final_request = intent.get("final_request").cloned().unwrap_or(Value::Null);
    let final_lease = intent.get("final_lease").cloned().unwrap_or(Value::Null);
    let params = intent.get("admit_params").cloned().unwrap_or(Value::Null);
    let lease_tail = intent
        .get("lease_tail")
        .and_then(Value::as_str)
        .unwrap_or("");
    let lease_receipt_id = intent
        .get("lease_receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let lease_receipt = intent.get("lease_receipt").cloned().unwrap_or(Value::Null);
    let request_receipt_id = intent
        .get("request_receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let request_receipt = intent
        .get("request_receipt")
        .cloned()
        .unwrap_or(Value::Null);
    for (field, sealed) in [
        ("final_request_hash", &final_request),
        ("final_lease_hash", &final_lease),
        ("lease_receipt_hash", &lease_receipt),
        ("request_receipt_hash", &request_receipt),
    ] {
        if intent.get(field).and_then(Value::as_str)
            != Some(record_output_hash(sealed, &[]).as_str())
        {
            return Err(format!("{field} seal"));
        }
    }
    if !is_canonical_lease_tail(lease_tail) {
        return Err("non-canonical lease tail".into());
    }
    if !is_canonical_receipt_tail(lease_receipt_id, "rlr")
        || !is_canonical_receipt_tail(request_receipt_id, "rqt")
    {
        return Err("non-canonical admit receipt tail".into());
    }
    let request_id = format!("participation-request://{request_tail}");
    let lease_id = format!("participant-lease://{lease_tail}");
    if prior_request
        .get("participation_request_id")
        .and_then(Value::as_str)
        != Some(request_id.as_str())
        || final_request
            .get("participation_request_id")
            .and_then(Value::as_str)
            != Some(request_id.as_str())
        || final_lease
            .get("participant_lease_id")
            .and_then(Value::as_str)
            != Some(lease_id.as_str())
    {
        return Err("identity does not bind to the storage keys".into());
    }
    let from = prior_request
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !matches!(from, "submitted" | "evaluating") {
        return Err("admit not admitted from prior status".into());
    }
    let now = final_request
        .get("updated_at")
        .cloned()
        .unwrap_or(Value::Null);
    if !is_rfc3339(&now)
        || final_lease.get("updated_at") != Some(&now)
        || final_lease.get("created_at") != Some(&now)
    {
        return Err("admit timestamps invalid".into());
    }
    let now_str = now.as_str().unwrap_or("");
    // Reconstruct the lease THROUGH the admit-params validator + lease constructor.
    let validated_params = validate_admit_params(&params)
        .map_err(|(_, m)| format!("sealed admit params do not validate: {m}"))?;
    if serde_json::to_vec(&validated_params).unwrap_or_default()
        != serde_json::to_vec(&params).unwrap_or_default()
    {
        return Err("admit params are not canonical".into());
    }
    let lease_receipt_ref = format!("receipt://{lease_receipt_id}");
    let expected_lease = build_lease(
        prior_request,
        &params,
        lease_tail,
        &lease_receipt_ref,
        now_str,
    );
    if serde_json::to_vec(&expected_lease).unwrap_or_default()
        != serde_json::to_vec(&final_lease).unwrap_or_default()
    {
        return Err("not the canonical lease".into());
    }
    // Reconstruct the terminal request successor.
    let prior_rev = prior_request
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let request_receipt_ref = json!(format!("receipt://{request_receipt_id}"));
    let mut expected_request = apply_transition(
        prior_request,
        "admit_intent",
        "admit",
        "admitted",
        &request_receipt_ref,
        &now,
        false,
    );
    if let Some(obj) = expected_request.as_object_mut() {
        obj.insert("participant_lease_ref".into(), json!(lease_id));
        obj.insert("admission_decision_ref".into(), request_receipt_ref.clone());
    }
    if serde_json::to_vec(&expected_request).unwrap_or_default()
        != serde_json::to_vec(&final_request).unwrap_or_default()
    {
        return Err("not the deterministic admitted request".into());
    }
    // Reconstruct BOTH receipts exactly.
    let room_ref = s(&final_lease, "outcome_room_ref", "");
    let expected_lease_receipt = build_room_receipt_at(
        lease_receipt_id,
        LEASE_RECEIPT_SCHEMA,
        "RoomParticipantLeaseReceipt",
        &lease_id,
        "admitted",
        json!({ "outcome_room_ref": room_ref, "participant_ref": s(&final_lease, "participant_ref", ""), "admitted_role": s(&final_lease, "admitted_role", ""), "join_request_ref": request_id, "status_at_admission": "active" }),
        vec![json!(lease_id), json!(room_ref), json!(request_id)],
        record_output_hash(&expected_lease, LEASE_CREATE_EXCLUDES),
        LEASE_CREATE_EXCLUDES,
        "admitted_not_verified",
        ADMIT_NOTE,
        now_str,
    );
    if serde_json::to_vec(&expected_lease_receipt).unwrap_or_default()
        != serde_json::to_vec(&lease_receipt).unwrap_or_default()
    {
        return Err("not the canonical lease receipt".into());
    }
    let expected_request_receipt = build_room_receipt_at(
        request_receipt_id,
        REQUEST_RECEIPT_SCHEMA,
        "RoomParticipationRequestReceipt",
        &request_id,
        "admit",
        json!({ "transition": "admit", "from": from, "to": "admitted", "participant_lease_ref": lease_id, "revision_before": prior_rev, "revision_after": prior_rev + 1 }),
        vec![json!(request_id), json!(lease_id)],
        record_output_hash(&expected_request, TRAIL_EXCLUDES),
        TRAIL_EXCLUDES,
        "admitted_not_verified",
        ADMIT_NOTE,
        now_str,
    );
    if serde_json::to_vec(&expected_request_receipt).unwrap_or_default()
        != serde_json::to_vec(&request_receipt).unwrap_or_default()
    {
        return Err("not the canonical admit receipt".into());
    }
    Ok(())
}

// ================================ BOOT COMPLETER =================================================

/// BOOT COMPLETER for the participation plane: validate every pending intent by CANONICAL
/// reconstruction (never trusting sealed hashes alone), then converge forward byte-exactly.
/// Anything inconsistent is left in place for manual repair; nothing is manufactured,
/// overwritten, or deleted. Runs AFTER the room-plane completers (its backlink replay requires
/// no pending room intents).
pub(crate) fn complete_participation_intents(data_dir: &str) {
    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // (1) Submit intents — internal family; the file STEM is the trusted request tail.
    let submit_intents = match scan_intent_family(data_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("participation completer: submit-intent scan failed ({e}) — retrying next boot, nothing converged");
            return;
        }
    };
    for (tail, intent) in submit_intents {
        match validate_submit_intent(&intent, &tail) {
            Ok((final_request, receipt_id, receipt)) => {
                // A request already at this identity must BE the sealed one.
                match read_slot_strict(data_dir, REQUEST_DIR, &tail, is_canonical_request_tail) {
                    Ok(Some(existing)) => {
                        // The existing record may have moved PAST submission (later receipted
                        // transitions); the sealed shape must match its admission lineage.
                        if existing.get("admission_receipt_ref")
                            != final_request.get("admission_receipt_ref")
                        {
                            eprintln!("participation completer: request '{tail}' exists with a DIFFERENT admission lineage — intent retained for manual repair");
                            continue;
                        }
                        let _ = std::fs::remove_file(
                            std::path::Path::new(data_dir)
                                .join(SUBMIT_INTENT_DIR)
                                .join(format!("{tail}.json")),
                        );
                    }
                    Ok(None) => {
                        if let Err((code, msg)) =
                            complete_submit(data_dir, &tail, &final_request, &receipt_id, &receipt)
                        {
                            eprintln!("participation completer: submit '{tail}' not converged ({code}: {msg}) — retrying next boot");
                        }
                    }
                    Err(e) => {
                        eprintln!("participation completer: request slot '{tail}' cannot be inspected ({e}) — refused, intent retained");
                    }
                }
            }
            Err(why) => {
                eprintln!("participation completer: submit intent '{tail}' fails canonical validation ({why}) — left in place for manual repair");
            }
        }
    }
    // (2) Request records carrying transition/admit intents.
    let requests = match scan_family(
        data_dir,
        REQUEST_DIR,
        "participation_request_id",
        "participation-request://",
        is_canonical_request_tail,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("participation completer: request scan failed ({e}) — retrying next boot");
            return;
        }
    };
    for (tail, record) in requests {
        if let Some(admit) = record.get("admit_intent").cloned() {
            let mut prior = record.clone();
            prior
                .as_object_mut()
                .expect("object")
                .remove("admit_intent");
            match validate_admit_intent(&admit, &prior, &tail) {
                Ok(()) => {
                    if let Err((code, msg)) = complete_admit(data_dir, &tail, &prior, &admit) {
                        eprintln!("participation completer: admit '{tail}' not converged ({code}: {msg}) — retrying next boot");
                    }
                }
                Err(why) => {
                    eprintln!("participation completer: admit intent on '{tail}' fails canonical validation ({why}) — left in place for manual repair");
                }
            }
        } else if let Some(ti) = record.get("transition_intent").cloned() {
            let mut prior = record.clone();
            prior
                .as_object_mut()
                .expect("object")
                .remove("transition_intent");
            match validate_transition_intent(
                &ti,
                &prior,
                &tail,
                "participation_request_id",
                "participation-request://",
                REQUEST_TRANSITIONS,
                "rqt",
                REQUEST_RECEIPT_SCHEMA,
                "RoomParticipationRequestReceipt",
                REQUEST_TRANSITION_NOTE,
                is_canonical_request_tail,
            ) {
                Ok((final_record, receipt_id, receipt)) => {
                    if persist_receipt(data_dir, &receipt_id, &receipt).is_ok() {
                        if let Err(f) = persist_atomic(data_dir, REQUEST_DIR, &tail, &final_record)
                        {
                            eprintln!("participation completer: request transition '{tail}' terminal write {} — retrying next boot", f.detail());
                        }
                    } else {
                        eprintln!("participation completer: request transition '{tail}' receipt not durable — intent retained");
                    }
                }
                Err(why) => {
                    eprintln!("participation completer: transition intent on request '{tail}' fails canonical validation ({why}) — left for manual repair");
                }
            }
        }
    }
    // (3) Lease records carrying transition intents.
    let leases = match scan_family(
        data_dir,
        LEASE_DIR,
        "participant_lease_id",
        "participant-lease://",
        is_canonical_lease_tail,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("participation completer: lease scan failed ({e}) — retrying next boot");
            return;
        }
    };
    for (tail, record) in leases {
        if let Some(ti) = record.get("transition_intent").cloned() {
            let mut prior = record.clone();
            prior
                .as_object_mut()
                .expect("object")
                .remove("transition_intent");
            match validate_transition_intent(
                &ti,
                &prior,
                &tail,
                "participant_lease_id",
                "participant-lease://",
                LEASE_TRANSITIONS,
                "rlt",
                LEASE_RECEIPT_SCHEMA,
                "RoomParticipantLeaseReceipt",
                LEASE_TRANSITION_NOTE,
                is_canonical_lease_tail,
            ) {
                Ok((final_record, receipt_id, receipt)) => {
                    if persist_receipt(data_dir, &receipt_id, &receipt).is_ok() {
                        if let Err(f) = persist_atomic(data_dir, LEASE_DIR, &tail, &final_record) {
                            eprintln!("participation completer: lease transition '{tail}' terminal write {} — retrying next boot", f.detail());
                        }
                    } else {
                        eprintln!("participation completer: lease transition '{tail}' receipt not durable — intent retained");
                    }
                }
                Err(why) => {
                    eprintln!("participation completer: transition intent on lease '{tail}' fails canonical validation ({why}) — left for manual repair");
                }
            }
        }
    }
}

fn scan_intent_family(data_dir: &str) -> Result<Vec<(String, Value)>, String> {
    let dir = match super::durable_fs::open_family_dir_pinned(data_dir, SUBMIT_INTENT_DIR) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("intent family could not be pinned ({e})")),
    };
    let names = super::durable_fs::enumerate_pinned(&dir)
        .map_err(|e| format!("intent family could not be enumerated ({e})"))?;
    let mut out = Vec::new();
    for name in names {
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if !is_canonical_request_tail(stem) {
            continue;
        }
        if let Ok(Some((_f, bytes))) = super::durable_fs::read_slot_strict(&dir, &name) {
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                out.push((stem.to_string(), value));
            }
        }
    }
    Ok(out)
}

// ================================ HANDLERS =======================================================

fn http_err(status: StatusCode, (code, msg): VErr) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({ "error": { "code": code, "message": msg } })),
    )
}

fn classify(e: VErr) -> (StatusCode, Json<Value>) {
    let status = if e.0.ends_with("_not_found") {
        StatusCode::NOT_FOUND
    } else if e.0.ends_with("_conflict")
        || e.0.ends_with("_in_flight")
        || e.0.ends_with("_already_bound")
        || e.0.ends_with("_duplicate")
    {
        StatusCode::CONFLICT
    } else if e.0.ends_with("_persist_failed")
        || e.0.ends_with("_pending_convergence")
        || e.0.ends_with("_durability_unconfirmed")
        || e.0.ends_with("_unreadable")
        || e.0.ends_with("_swapped")
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    http_err(status, e)
}

/// POST /v1/hypervisor/room-participation-requests — a typed admission request; admits as
/// `submitted` with a receipt, bound into the room through the room-owned seam.
pub(crate) async fn handle_participation_request_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let declaration = match validate_request_create(&body) {
        Ok(d) => d,
        Err(e) => return classify(e),
    };
    let room_ref = s(&declaration, "outcome_room_ref", "");
    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // The room must resolve OPEN and hosted, its host must BE the declared admission owner, and
    // no room intent may be pending (the bind would refuse anyway — refuse early and typed).
    let Some(room) = rooms::resolve_open_room(&st.data_dir, &room_ref) else {
        return classify(verr("room_participation_room_not_found", format!("no admitted OPEN room '{room_ref}' — participation binds only to a live hosted room")));
    };
    if s(&room, "status", "") != "open" {
        return classify(verr(
            "room_participation_room_not_open",
            format!(
                "room '{room_ref}' is '{}' — requests bind only to an OPEN room",
                s(&room, "status", "?")
            ),
        ));
    }
    if s(&room, "host_domain_ref", "") != s(&declaration, "admission_owner_ref", "") {
        return classify(verr("room_participation_admission_owner_mismatch", format!("`admission_owner_ref` must equal the room's host domain '{}' — the hosted owner is not negotiable per request", s(&room, "host_domain_ref", "?"))));
    }
    match live_request_exists(&st.data_dir, &room_ref, &s(&declaration, "requested_by_ref", "")) {
        Ok(true) => return classify(verr("room_participation_request_duplicate", "a live (submitted/evaluating) request by this principal already exists for this room — withdraw it or await the decision")),
        Ok(false) => {}
        Err(e) => return classify(e),
    }
    match live_lease_exists(
        &st.data_dir,
        &room_ref,
        &s(&declaration, "requested_by_ref", ""),
    ) {
        Ok(true) => return classify(verr(
            "room_participation_request_duplicate",
            "this principal already holds a live lease in this room — one participant, one lease",
        )),
        Ok(false) => {}
        Err(e) => return classify(e),
    }
    let now = iso_now();
    let tail = format!("rpr_{:x}", nanos());
    let receipt_id = format!("rqr_{:x}", nanos());
    let receipt_ref = format!("receipt://{receipt_id}");
    let record = seal_request(&declaration, &tail, &receipt_ref, &now);
    let request_id = s(&record, "participation_request_id", "");
    let receipt = build_room_receipt_at(
        &receipt_id,
        REQUEST_RECEIPT_SCHEMA,
        "RoomParticipationRequestReceipt",
        &request_id,
        "submitted",
        json!({ "outcome_room_ref": room_ref, "requested_by_ref": s(&record, "requested_by_ref", ""), "status_at_submission": "submitted" }),
        vec![json!(request_id), json!(room_ref)],
        record_output_hash(&record, REQUEST_CREATE_EXCLUDES),
        REQUEST_CREATE_EXCLUDES,
        "admitted_not_verified",
        SUBMIT_NOTE,
        &now,
    );
    if let Err(e) = finalize_submit(&st.data_dir, &tail, &record, &receipt_id, &receipt) {
        return classify(e);
    }
    (
        StatusCode::CREATED,
        Json(json!({ "participation_request": record, "participation_request_receipt": receipt })),
    )
}

/// GET /v1/hypervisor/room-participation-requests[?room=outcome-room://…]
pub(crate) async fn handle_participation_requests_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    match scan_family(
        &st.data_dir,
        REQUEST_DIR,
        "participation_request_id",
        "participation-request://",
        is_canonical_request_tail,
    ) {
        Ok(items) => {
            let mut rows: Vec<Value> = items
                .into_iter()
                .map(|(_, r)| r)
                .filter(|r| {
                    q.get("room")
                        .map(|room| s(r, "outcome_room_ref", "") == *room)
                        .unwrap_or(true)
                })
                .collect();
            rows.sort_by(|a, b| s(b, "created_at", "").cmp(&s(a, "created_at", "")));
            (
                StatusCode::OK,
                Json(
                    json!({ "schema_version": REQUEST_SCHEMA, "participation_requests": rows, "request_statuses": REQUEST_STATUSES, "request_transitions": REQUEST_TRANSITIONS.iter().map(|(t, from, to)| json!({ "transition": t, "from": from, "to": to })).collect::<Vec<_>>(), "runtimeTruthSource": "daemon-runtime" }),
                ),
            )
        }
        Err(e) => http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            verr("room_participation_registry_unreadable", e),
        ),
    }
}

/// GET /v1/hypervisor/room-participation-requests/:id
pub(crate) async fn handle_participation_request_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_request(&st.data_dir, &id) {
        Some(r) => (StatusCode::OK, Json(json!({ "participation_request": r }))),
        None => http_err(
            StatusCode::NOT_FOUND,
            verr(
                "room_participation_request_not_found",
                format!("no participation request '{id}'"),
            ),
        ),
    }
}

/// POST /v1/hypervisor/room-participation-requests/:id/transition
pub(crate) async fn handle_participation_request_transition(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(e) = reject_sensitive_keys(&body, "") {
        return classify(e);
    }
    let transition = match str_opt_bounded(&body, "transition", 40) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return classify(verr(
                "room_participation_transition_invalid",
                format!(
                    "`transition` is required — request lifecycle: [{}]",
                    REQUEST_TRANSITIONS
                        .iter()
                        .map(|(t, _, _)| *t)
                        .collect::<Vec<_>>()
                        .join("|")
                ),
            ))
        }
        Err(e) => return classify(e),
    };
    if let Some((_, why)) = UNAVAILABLE_REQUEST_TRANSITIONS
        .iter()
        .find(|(t, _)| *t == transition)
    {
        return classify(verr(
            "room_participation_transition_unavailable",
            format!("transition '{transition}' needs {why}"),
        ));
    }
    let Some((_, allowed_from, to_status)) = REQUEST_TRANSITIONS
        .iter()
        .find(|(t, _, _)| *t == transition)
    else {
        return classify(verr(
            "room_participation_transition_invalid",
            format!(
                "unknown transition '{transition}' — request lifecycle: [{}]",
                REQUEST_TRANSITIONS
                    .iter()
                    .map(|(t, _, _)| *t)
                    .collect::<Vec<_>>()
                    .join("|")
            ),
        ));
    };
    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    match transition_record(
        &st.data_dir,
        REQUEST_DIR,
        &id,
        &body,
        transition.as_str(),
        allowed_from,
        to_status,
        "participation-request://",
        "rqt",
        REQUEST_RECEIPT_SCHEMA,
        "RoomParticipationRequestReceipt",
        REQUEST_TRANSITION_NOTE,
        "room_participation",
    ) {
        Ok((record, receipt)) => (
            StatusCode::OK,
            Json(
                json!({ "participation_request": record, "participation_request_receipt": receipt }),
            ),
        ),
        Err(e) => classify(e),
    }
}

/// The shared single-record transition core (request + lease).
#[allow(clippy::too_many_arguments)]
fn transition_record(
    data_dir: &str,
    family: &str,
    tail: &str,
    body: &Value,
    op: &str,
    allowed_from: &[&str],
    to_status: &str,
    id_prefix: &str,
    receipt_prefix: &str,
    receipt_schema: &str,
    receipt_type: &str,
    note: &str,
    code_ns: &str,
) -> Result<(Value, Value), VErr> {
    let (loader, nf_code): (fn(&str, &str) -> Option<Value>, &str) = if family == REQUEST_DIR {
        (load_request, "room_participation_request_not_found")
    } else {
        (load_lease, "participant_lease_not_found")
    };
    let Some(prior) = loader(data_dir, tail) else {
        return Err(verr(nf_code, format!("no record '{tail}'")));
    };
    if let Some((field, code)) = pending_intent(&prior) {
        return Err(verr(code, format!("a durable {field} is pending on this record — a restart converges it before any other mutation is admitted")));
    }
    let from = s(&prior, "status", "");
    if !allowed_from.contains(&from.as_str()) {
        return Err(verr(
            &format!("{code_ns}_transition_invalid"),
            format!(
                "transition '{op}' is not admitted from status '{from}' (allowed from: [{}])",
                allowed_from.join("|")
            ),
        ));
    }
    let current_rev = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    check_expected_revision(body, current_rev)
        .map_err(|(_, m)| verr(&format!("{code_ns}_revision_conflict"), m))?;
    let now = iso_now();
    let receipt_id = format!("{receipt_prefix}_{:x}", nanos());
    let record_id = format!("{id_prefix}{tail}");
    let receipt_ref = json!(format!("receipt://{receipt_id}"));
    let now_v = json!(now);
    let updated = apply_transition(
        &prior,
        "transition_intent",
        op,
        to_status,
        &receipt_ref,
        &now_v,
        op == "revoke",
    );
    let receipt = build_room_receipt_at(
        &receipt_id,
        receipt_schema,
        receipt_type,
        &record_id,
        op,
        json!({ "transition": op, "from": from, "to": to_status, "revision_before": current_rev, "revision_after": current_rev + 1 }),
        vec![
            json!(record_id),
            updated
                .get("outcome_room_ref")
                .cloned()
                .unwrap_or(Value::Null),
        ],
        record_output_hash(&updated, TRAIL_EXCLUDES),
        TRAIL_EXCLUDES,
        "admitted_not_verified",
        note,
        &now,
    );
    finalize_record_transition(
        data_dir,
        family,
        tail,
        &prior,
        &updated,
        &receipt_id,
        &receipt,
    )?;
    Ok((updated, receipt))
}

/// POST /v1/hypervisor/room-participation-requests/:id/admit — the hosted owner's admitted
/// decision: terminal request + bounded ACTIVE lease + room backlink in ONE finalization.
pub(crate) async fn handle_participation_request_admit(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let params = match validate_admit_params(&body) {
        Ok(p) => p,
        Err(e) => return classify(e),
    };
    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let Some(prior) = load_request(&st.data_dir, &id) else {
        return classify(verr(
            "room_participation_request_not_found",
            format!("no participation request '{id}'"),
        ));
    };
    if let Some((field, code)) = pending_intent(&prior) {
        return classify(verr(
            code,
            format!("a durable {field} is pending on this record — a restart converges it first"),
        ));
    }
    let from = s(&prior, "status", "");
    if !matches!(from.as_str(), "submitted" | "evaluating") {
        return classify(verr(
            "room_participation_transition_invalid",
            format!(
                "admit is not admitted from status '{from}' (allowed from: [submitted|evaluating])"
            ),
        ));
    }
    let current_rev = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    if let Err((_, m)) = check_expected_revision(&body, current_rev) {
        return classify(verr("room_participation_revision_conflict", m));
    }
    let room_ref = s(&prior, "outcome_room_ref", "");
    match live_lease_exists(&st.data_dir, &room_ref, &s(&prior, "requested_by_ref", "")) {
        Ok(true) => return classify(verr("participant_lease_duplicate", "this principal already holds a live lease in this room — one participant, one lease; revoke or retire the existing lease first")),
        Ok(false) => {}
        Err(e) => return classify(e),
    }
    // The room must still be OPEN with no pending intent (the bind enforces it; check early).
    let Some(_room) = rooms::resolve_open_room(&st.data_dir, &room_ref) else {
        return classify(verr("room_participation_room_not_found", format!("room '{room_ref}' no longer resolves OPEN — admission refuses rather than leasing into a closed room")));
    };
    let now = iso_now();
    let lease_tail = format!("rpl_{:x}", nanos());
    let lease_receipt_id = format!("rlr_{:x}", nanos());
    let request_receipt_id = format!("rqt_{:x}", nanos());
    let lease_receipt_ref = format!("receipt://{lease_receipt_id}");
    let request_receipt_ref = json!(format!("receipt://{request_receipt_id}"));
    let request_id = s(&prior, "participation_request_id", "");
    let lease_id = format!("participant-lease://{lease_tail}");
    let final_lease = build_lease(&prior, &params, &lease_tail, &lease_receipt_ref, &now);
    let now_v = json!(now);
    let mut final_request = apply_transition(
        &prior,
        "admit_intent",
        "admit",
        "admitted",
        &request_receipt_ref,
        &now_v,
        false,
    );
    if let Some(obj) = final_request.as_object_mut() {
        obj.insert("participant_lease_ref".into(), json!(lease_id));
        obj.insert("admission_decision_ref".into(), request_receipt_ref.clone());
    }
    let lease_receipt = build_room_receipt_at(
        &lease_receipt_id,
        LEASE_RECEIPT_SCHEMA,
        "RoomParticipantLeaseReceipt",
        &lease_id,
        "admitted",
        json!({ "outcome_room_ref": room_ref, "participant_ref": s(&final_lease, "participant_ref", ""), "admitted_role": s(&final_lease, "admitted_role", ""), "join_request_ref": request_id, "status_at_admission": "active" }),
        vec![json!(lease_id), json!(room_ref), json!(request_id)],
        record_output_hash(&final_lease, LEASE_CREATE_EXCLUDES),
        LEASE_CREATE_EXCLUDES,
        "admitted_not_verified",
        ADMIT_NOTE,
        &now,
    );
    let request_receipt = build_room_receipt_at(
        &request_receipt_id,
        REQUEST_RECEIPT_SCHEMA,
        "RoomParticipationRequestReceipt",
        &request_id,
        "admit",
        json!({ "transition": "admit", "from": from, "to": "admitted", "participant_lease_ref": lease_id, "revision_before": current_rev, "revision_after": current_rev + 1 }),
        vec![json!(request_id), json!(lease_id)],
        record_output_hash(&final_request, TRAIL_EXCLUDES),
        TRAIL_EXCLUDES,
        "admitted_not_verified",
        ADMIT_NOTE,
        &now,
    );
    let admit = json!({
        "kind": "admit",
        "lease_tail": lease_tail,
        "admit_params": params,
        "final_request": final_request,
        "final_request_hash": record_output_hash(&final_request, &[]),
        "final_lease": final_lease,
        "final_lease_hash": record_output_hash(&final_lease, &[]),
        "lease_receipt_id": lease_receipt_id,
        "lease_receipt": lease_receipt,
        "lease_receipt_hash": record_output_hash(&lease_receipt, &[]),
        "request_receipt_id": request_receipt_id,
        "request_receipt": request_receipt,
        "request_receipt_hash": record_output_hash(&request_receipt, &[]),
        "at": now,
    });
    if let Err(e) = finalize_admit(&st.data_dir, &id, &prior, &admit) {
        return classify(e);
    }
    (
        StatusCode::OK,
        Json(
            json!({ "participation_request": final_request, "participant_lease": final_lease, "participant_lease_receipt": lease_receipt, "participation_request_receipt": request_receipt }),
        ),
    )
}

/// GET /v1/hypervisor/room-participant-leases[?room=…]
pub(crate) async fn handle_participant_leases_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    match scan_family(
        &st.data_dir,
        LEASE_DIR,
        "participant_lease_id",
        "participant-lease://",
        is_canonical_lease_tail,
    ) {
        Ok(items) => {
            let mut rows: Vec<Value> = items
                .into_iter()
                .map(|(_, r)| r)
                .filter(|r| {
                    q.get("room")
                        .map(|room| s(r, "outcome_room_ref", "") == *room)
                        .unwrap_or(true)
                })
                .collect();
            rows.sort_by(|a, b| s(b, "created_at", "").cmp(&s(a, "created_at", "")));
            (
                StatusCode::OK,
                Json(
                    json!({ "schema_version": LEASE_SCHEMA, "participant_leases": rows, "lease_statuses": LEASE_STATUSES, "lease_transitions": LEASE_TRANSITIONS.iter().map(|(t, from, to)| json!({ "transition": t, "from": from, "to": to })).collect::<Vec<_>>(), "admitted_roles": ADMITTED_ROLES, "runtimeTruthSource": "daemon-runtime" }),
                ),
            )
        }
        Err(e) => http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            verr("participant_lease_registry_unreadable", e),
        ),
    }
}

/// GET /v1/hypervisor/room-participant-leases/:id
pub(crate) async fn handle_participant_lease_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_lease(&st.data_dir, &id) {
        Some(r) => (StatusCode::OK, Json(json!({ "participant_lease": r }))),
        None => http_err(
            StatusCode::NOT_FOUND,
            verr(
                "participant_lease_not_found",
                format!("no participant lease '{id}'"),
            ),
        ),
    }
}

/// POST /v1/hypervisor/room-participant-leases/:id/transition
pub(crate) async fn handle_participant_lease_transition(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(e) = reject_sensitive_keys(&body, "") {
        return classify(e);
    }
    let transition = match str_opt_bounded(&body, "transition", 40) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return classify(verr(
                "participant_lease_transition_invalid",
                format!(
                    "`transition` is required — lease lifecycle: [{}]",
                    LEASE_TRANSITIONS
                        .iter()
                        .map(|(t, _, _)| *t)
                        .collect::<Vec<_>>()
                        .join("|")
                ),
            ))
        }
        Err(e) => return classify(e),
    };
    if let Some((_, why)) = UNAVAILABLE_LEASE_TRANSITIONS
        .iter()
        .find(|(t, _)| *t == transition)
    {
        return classify(verr(
            "participant_lease_transition_unavailable",
            format!("transition '{transition}' needs {why} — a named gap, never faked"),
        ));
    }
    let Some((_, allowed_from, to_status)) =
        LEASE_TRANSITIONS.iter().find(|(t, _, _)| *t == transition)
    else {
        return classify(verr(
            "participant_lease_transition_invalid",
            format!(
                "unknown transition '{transition}' — lease lifecycle: [{}]",
                LEASE_TRANSITIONS
                    .iter()
                    .map(|(t, _, _)| *t)
                    .collect::<Vec<_>>()
                    .join("|")
            ),
        ));
    };
    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    match transition_record(
        &st.data_dir,
        LEASE_DIR,
        &id,
        &body,
        transition.as_str(),
        allowed_from,
        to_status,
        "participant-lease://",
        "rlt",
        LEASE_RECEIPT_SCHEMA,
        "RoomParticipantLeaseReceipt",
        LEASE_TRANSITION_NOTE,
        "participant_lease",
    ) {
        Ok((record, receipt)) => (
            StatusCode::OK,
            Json(json!({ "participant_lease": record, "participant_lease_receipt": receipt })),
        ),
        Err(e) => classify(e),
    }
}

// ====================================== TESTS ====================================================

#[cfg(test)]
mod participation_tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ioi-participation-{tag}-{:x}", nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A minimal OPEN hosted room the seam accepts (content id == stem, open, no intents).
    fn plant_room(data_dir: &str, tail: &str) {
        let room = json!({
            "schema_version": "ioi.hypervisor.outcome-room.v1",
            "outcome_room_id": format!("outcome-room://{tail}"),
            "status": "open", "revision": 1, "host_domain_ref": "domain://acme-host",
            "participation_request_refs": [], "participant_lease_refs": [],
            "member_goal_run_refs": [], "status_history": [],
            "admission_receipt_ref": "receipt://orr_0", "admission_and_replay_refs": ["receipt://orr_0"],
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
        });
        super::super::durable_fs::persist_record_durable(data_dir, rooms::ROOM_DIR, tail, &room)
            .unwrap();
    }

    fn declaration_body(room_tail: &str) -> Value {
        json!({
            "outcome_room_ref": format!("outcome-room://{room_tail}"),
            "requested_by_ref": "worker://independent-alloy-lab",
            "coordination_topology": "hosted_admission",
            "admission_owner_ref": "domain://acme-host",
            "operator_and_home_domain_refs": ["org://alloy-lab", "domain://alloy-lab.example"],
            "capability_offer_refs": ["capability-offer://fatigue-sim"],
            "eligibility_evidence_refs": ["evidence://fatigue-benchmarks"],
            "accepted_verifier_settlement_dispute_and_contribution_policy_refs": ["policy://contribution-v1"]
        })
    }

    /// Drive the SUBMIT flow exactly as the handler does (validate → seal → receipt → finalize).
    fn submit(
        data_dir: &str,
        room_tail: &str,
        req_tail: &str,
        receipt_tail: &str,
        now: &str,
    ) -> (Value, Value) {
        let declaration = validate_request_create(&declaration_body(room_tail)).unwrap();
        let receipt_ref = format!("receipt://{receipt_tail}");
        let record = seal_request(&declaration, req_tail, &receipt_ref, now);
        let request_id = s(&record, "participation_request_id", "");
        let room_ref = s(&record, "outcome_room_ref", "");
        let receipt = build_room_receipt_at(
            receipt_tail,
            REQUEST_RECEIPT_SCHEMA,
            "RoomParticipationRequestReceipt",
            &request_id,
            "submitted",
            json!({ "outcome_room_ref": room_ref, "requested_by_ref": s(&record, "requested_by_ref", ""), "status_at_submission": "submitted" }),
            vec![json!(request_id), json!(room_ref)],
            record_output_hash(&record, REQUEST_CREATE_EXCLUDES),
            REQUEST_CREATE_EXCLUDES,
            "admitted_not_verified",
            SUBMIT_NOTE,
            now,
        );
        finalize_submit(data_dir, req_tail, &record, receipt_tail, &receipt).unwrap();
        (record, receipt)
    }

    #[test]
    fn submit_finalizes_and_binds_the_room_through_the_seam() {
        let dir = temp_dir("submit");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_a1");
        let (record, _receipt) = submit(
            data_dir,
            "or_a1",
            "rpr_a1",
            "rqr_a1",
            "2026-02-01T00:00:00Z",
        );
        let _ = record;
        // Wait: request tail must be canonical rpr_<hex> — a1 is hex. Room bound?
        let stored = load_request(data_dir, "rpr_a1").expect("request stored");
        assert_eq!(stored["status"], json!("submitted"));
        assert_eq!(stored["revision"], json!(1));
        let room = rooms::resolve_open_room(data_dir, "outcome-room://or_a1").unwrap();
        assert_eq!(
            room["participation_request_refs"],
            json!(["participation-request://rpr_a1"]),
            "the room backlink landed through the seam"
        );
        assert_eq!(
            room["revision"],
            json!(2),
            "the backlink was a receipted room transition"
        );
        assert!(
            std::fs::read(dir.join(RECEIPT_DIR).join("rqr_a1.json")).is_ok(),
            "the submission receipt is durable"
        );
        assert!(
            !dir.join(SUBMIT_INTENT_DIR).join("rpr_a1.json").exists(),
            "the submit intent was consumed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn submit_completer_converges_a_crashed_submission_and_refuses_tamper() {
        let dir = temp_dir("submit-replay");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_b2");
        // Seal the intent EXACTLY as finalize_submit would, then "crash" before everything else.
        let declaration = validate_request_create(&declaration_body("or_b2")).unwrap();
        let now = "2026-02-01T00:00:00Z";
        let record = seal_request(&declaration, "rpr_b2", "receipt://rqr_b2", now);
        let request_id = s(&record, "participation_request_id", "");
        let receipt = build_room_receipt_at(
            "rqr_b2",
            REQUEST_RECEIPT_SCHEMA,
            "RoomParticipationRequestReceipt",
            &request_id,
            "submitted",
            json!({ "outcome_room_ref": "outcome-room://or_b2", "requested_by_ref": s(&record, "requested_by_ref", ""), "status_at_submission": "submitted" }),
            vec![json!(request_id), json!("outcome-room://or_b2")],
            record_output_hash(&record, REQUEST_CREATE_EXCLUDES),
            REQUEST_CREATE_EXCLUDES,
            "admitted_not_verified",
            SUBMIT_NOTE,
            now,
        );
        let intent = json!({
            "kind": "submit", "request_tail": "rpr_b2", "request_ref": request_id,
            "room_ref": "outcome-room://or_b2",
            "final_request": record, "final_request_hash": record_output_hash(&record, &[]),
            "receipt_id": "rqr_b2", "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "at": now,
        });
        persist_atomic(data_dir, SUBMIT_INTENT_DIR, "rpr_b2", &intent).unwrap();
        complete_participation_intents(data_dir);
        assert!(
            load_request(data_dir, "rpr_b2").is_some(),
            "the completer converged the crashed submission"
        );
        let room = rooms::resolve_open_room(data_dir, "outcome-room://or_b2").unwrap();
        assert_eq!(
            room["participation_request_refs"],
            json!(["participation-request://rpr_b2"])
        );
        assert!(
            !dir.join(SUBMIT_INTENT_DIR).join("rpr_b2.json").exists(),
            "intent consumed after convergence"
        );
        // Idempotent second boot.
        complete_participation_intents(data_dir);
        // TAMPERED intent: an escalated requested_by inside a re-sealed intent must be refused —
        // reconstruction through the declaration validator + sealer catches it even with hashes fixed.
        let mut forged = record.clone();
        forged
            .as_object_mut()
            .unwrap()
            .insert("requested_by_ref".into(), json!("org://insider"));
        let forged_intent = json!({
            "kind": "submit", "request_tail": "rpr_b3", "request_ref": "participation-request://rpr_b3",
            "room_ref": "outcome-room://or_b2",
            "final_request": forged, "final_request_hash": record_output_hash(&forged, &[]),
            "receipt_id": "rqr_b3", "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "at": now,
        });
        persist_atomic(data_dir, SUBMIT_INTENT_DIR, "rpr_b3", &forged_intent).unwrap();
        complete_participation_intents(data_dir);
        assert!(
            load_request(data_dir, "rpr_b3").is_none(),
            "a tampered submission never converges"
        );
        assert!(
            dir.join(SUBMIT_INTENT_DIR).join("rpr_b3.json").exists(),
            "the tampered intent is retained for manual repair"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admit_mints_the_lease_binds_the_room_and_guards_duplicates() {
        let dir = temp_dir("admit");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_c3");
        let (prior, _r) = submit(
            data_dir,
            "or_c3",
            "rpr_c3",
            "rqr_c3",
            "2026-02-01T00:00:00Z",
        );
        let prior = load_request(data_dir, "rpr_c3").unwrap();
        let _ = prior;
        let prior = load_request(data_dir, "rpr_c3").unwrap();
        let params = validate_admit_params(&json!({
            "admitted_role": "implementer", "operator_ref": "org://alloy-lab", "home_domain_ref": "domain://alloy-lab.example", "ttl_seconds": 86400
        })).unwrap();
        let now = "2026-02-02T00:00:00Z";
        let final_lease = build_lease(&prior, &params, "rpl_c3", "receipt://rlr_c3", now);
        let request_receipt_ref = json!("receipt://rqt_c3");
        let now_v = json!(now);
        let mut final_request = apply_transition(
            &prior,
            "admit_intent",
            "admit",
            "admitted",
            &request_receipt_ref,
            &now_v,
            false,
        );
        final_request.as_object_mut().unwrap().insert(
            "participant_lease_ref".into(),
            json!("participant-lease://rpl_c3"),
        );
        final_request
            .as_object_mut()
            .unwrap()
            .insert("admission_decision_ref".into(), request_receipt_ref.clone());
        let request_id = s(&prior, "participation_request_id", "");
        let room_ref = s(&prior, "outcome_room_ref", "");
        let current_rev = prior["revision"].as_u64().unwrap();
        let lease_receipt = build_room_receipt_at(
            "rlr_c3",
            LEASE_RECEIPT_SCHEMA,
            "RoomParticipantLeaseReceipt",
            "participant-lease://rpl_c3",
            "admitted",
            json!({ "outcome_room_ref": room_ref, "participant_ref": s(&final_lease, "participant_ref", ""), "admitted_role": "implementer", "join_request_ref": request_id, "status_at_admission": "active" }),
            vec![
                json!("participant-lease://rpl_c3"),
                json!(room_ref),
                json!(request_id),
            ],
            record_output_hash(&final_lease, LEASE_CREATE_EXCLUDES),
            LEASE_CREATE_EXCLUDES,
            "admitted_not_verified",
            ADMIT_NOTE,
            now,
        );
        let request_receipt = build_room_receipt_at(
            "rqt_c3",
            REQUEST_RECEIPT_SCHEMA,
            "RoomParticipationRequestReceipt",
            &request_id,
            "admit",
            json!({ "transition": "admit", "from": "submitted", "to": "admitted", "participant_lease_ref": "participant-lease://rpl_c3", "revision_before": current_rev, "revision_after": current_rev + 1 }),
            vec![json!(request_id), json!("participant-lease://rpl_c3")],
            record_output_hash(&final_request, TRAIL_EXCLUDES),
            TRAIL_EXCLUDES,
            "admitted_not_verified",
            ADMIT_NOTE,
            now,
        );
        let admit = json!({
            "kind": "admit", "lease_tail": "rpl_c3", "admit_params": params,
            "final_request": final_request, "final_request_hash": record_output_hash(&final_request, &[]),
            "final_lease": final_lease, "final_lease_hash": record_output_hash(&final_lease, &[]),
            "lease_receipt_id": "rlr_c3", "lease_receipt": lease_receipt, "lease_receipt_hash": record_output_hash(&lease_receipt, &[]),
            "request_receipt_id": "rqt_c3", "request_receipt": request_receipt, "request_receipt_hash": record_output_hash(&request_receipt, &[]),
            "at": now,
        });
        // The sealed admit intent must validate through canonical reconstruction…
        validate_admit_intent(&admit, &prior, "rpr_c3").expect("canonical admit validates");
        finalize_admit(data_dir, "rpr_c3", &prior, &admit).unwrap();
        let lease = load_lease(data_dir, "rpl_c3").expect("lease minted");
        assert_eq!(lease["status"], json!("active"));
        assert_eq!(lease["admitted_role"], json!("implementer"));
        assert_eq!(lease["join_request_ref"], json!(request_id));
        let req = load_request(data_dir, "rpr_c3").unwrap();
        assert_eq!(req["status"], json!("admitted"));
        assert_eq!(
            req["participant_lease_ref"],
            json!("participant-lease://rpl_c3")
        );
        let room = rooms::resolve_open_room(data_dir, "outcome-room://or_c3").unwrap();
        assert_eq!(
            room["participant_lease_refs"],
            json!(["participant-lease://rpl_c3"]),
            "the lease backlink landed through the seam"
        );
        // Duplicate-live guard: the same principal cannot get a second live lease or request.
        assert!(live_lease_exists(
            data_dir,
            "outcome-room://or_c3",
            "worker://independent-alloy-lab"
        )
        .unwrap());
        // …and a ROLE-ESCALATED forged lease inside the sealed intent is refused.
        let mut escalated = admit.clone();
        let mut bad_lease = escalated["final_lease"].clone();
        bad_lease
            .as_object_mut()
            .unwrap()
            .insert("admitted_role".into(), json!("conductor"));
        escalated
            .as_object_mut()
            .unwrap()
            .insert("final_lease".into(), bad_lease.clone());
        escalated.as_object_mut().unwrap().insert(
            "final_lease_hash".into(),
            json!(record_output_hash(&bad_lease, &[])),
        );
        assert!(
            validate_admit_intent(&escalated, &prior, "rpr_c3").is_err(),
            "a role-escalated sealed lease never validates"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lease_transitions_walk_receipted_and_revoke_appends_revocation() {
        let dir = temp_dir("lease-walk");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_d4");
        submit(
            data_dir,
            "or_d4",
            "rpr_d4",
            "rqr_d4",
            "2026-02-01T00:00:00Z",
        );
        let prior = load_request(data_dir, "rpr_d4").unwrap();
        let params = validate_admit_params(&json!({ "admitted_role": "reviewer", "operator_ref": "org://alloy-lab", "home_domain_ref": "domain://alloy-lab.example" })).unwrap();
        let now = "2026-02-02T00:00:00Z";
        let final_lease = build_lease(&prior, &params, "rpl_d4", "receipt://rlr_d4", now);
        persist_atomic(data_dir, LEASE_DIR, "rpl_d4", &final_lease).unwrap();
        // suspend → resume → revoke, each optimistically concurrent and receipted.
        let (l1, r1) = transition_record(
            data_dir,
            LEASE_DIR,
            "rpl_d4",
            &json!({ "expected_revision": 1 }),
            "suspend",
            &["active", "sleeping", "waiting"],
            "suspended",
            "participant-lease://",
            "rlt",
            LEASE_RECEIPT_SCHEMA,
            "RoomParticipantLeaseReceipt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
        )
        .unwrap();
        assert_eq!(l1["status"], json!("suspended"));
        assert_eq!(r1["op"], json!("suspend"));
        // Stale revision: byte-unchanged refusal.
        let stale = transition_record(
            data_dir,
            LEASE_DIR,
            "rpl_d4",
            &json!({ "expected_revision": 1 }),
            "resume",
            &["suspended"],
            "active",
            "participant-lease://",
            "rlt",
            LEASE_RECEIPT_SCHEMA,
            "RoomParticipantLeaseReceipt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
        );
        assert_eq!(stale.unwrap_err().0, "participant_lease_revision_conflict");
        let (l2, _) = transition_record(
            data_dir,
            LEASE_DIR,
            "rpl_d4",
            &json!({ "expected_revision": 2 }),
            "resume",
            &["suspended"],
            "active",
            "participant-lease://",
            "rlt",
            LEASE_RECEIPT_SCHEMA,
            "RoomParticipantLeaseReceipt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
        )
        .unwrap();
        assert_eq!(l2["status"], json!("active"));
        let (l3, r3) = transition_record(
            data_dir,
            LEASE_DIR,
            "rpl_d4",
            &json!({ "expected_revision": 3 }),
            "revoke",
            &["active", "sleeping", "waiting", "suspended", "quarantined"],
            "revoked",
            "participant-lease://",
            "rlt",
            LEASE_RECEIPT_SCHEMA,
            "RoomParticipantLeaseReceipt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
        )
        .unwrap();
        assert_eq!(l3["status"], json!("revoked"));
        assert_eq!(
            l3["future_access_revocation_refs"],
            json!([r3["receipt_ref"]]),
            "revocation appends its receipt — future access ends, lineage stays"
        );
        // Terminal: no further transitions.
        let dead = transition_record(
            data_dir,
            LEASE_DIR,
            "rpl_d4",
            &json!({ "expected_revision": 4 }),
            "resume",
            &["suspended"],
            "active",
            "participant-lease://",
            "rlt",
            LEASE_RECEIPT_SCHEMA,
            "RoomParticipantLeaseReceipt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
        );
        assert_eq!(dead.unwrap_err().0, "participant_lease_transition_invalid");
        // The lease no longer counts as live.
        assert!(!live_lease_exists(
            data_dir,
            "outcome-room://or_d4",
            "worker://independent-alloy-lab"
        )
        .unwrap());
        // Receipts: 3 transition receipts exist (suspend/resume/revoke).
        let receipts = std::fs::read_dir(dir.join(RECEIPT_DIR)).unwrap().count();
        assert!(
            receipts >= 4,
            "submission + three transition receipts are durable (found {receipts})"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lease_transition_intent_replays_byte_exact_and_refuses_forgery() {
        let dir = temp_dir("lease-replay");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_e5");
        submit(
            data_dir,
            "or_e5",
            "rpr_e5",
            "rqr_e5",
            "2026-02-01T00:00:00Z",
        );
        let prior_req = load_request(data_dir, "rpr_e5").unwrap();
        let params = validate_admit_params(&json!({ "admitted_role": "verifier", "operator_ref": "org://alloy-lab", "home_domain_ref": "domain://alloy-lab.example" })).unwrap();
        let lease = build_lease(
            &prior_req,
            &params,
            "rpl_e5",
            "receipt://rlr_e5",
            "2026-02-02T00:00:00Z",
        );
        // Seal a canonical suspend intent ON the lease record, as finalize would, then "crash".
        let now = json!("2026-02-03T00:00:00Z");
        let receipt_ref = json!("receipt://rlt_e5");
        let updated = apply_transition(
            &lease,
            "transition_intent",
            "suspend",
            "suspended",
            &receipt_ref,
            &now,
            false,
        );
        let receipt = build_room_receipt_at(
            "rlt_e5",
            LEASE_RECEIPT_SCHEMA,
            "RoomParticipantLeaseReceipt",
            "participant-lease://rpl_e5",
            "suspend",
            json!({ "transition": "suspend", "from": "active", "to": "suspended", "revision_before": 1, "revision_after": 2 }),
            vec![
                json!("participant-lease://rpl_e5"),
                json!("outcome-room://or_e5"),
            ],
            record_output_hash(&updated, TRAIL_EXCLUDES),
            TRAIL_EXCLUDES,
            "admitted_not_verified",
            LEASE_TRANSITION_NOTE,
            "2026-02-03T00:00:00Z",
        );
        let mut carrying = lease.clone();
        carrying.as_object_mut().unwrap().insert("transition_intent".into(), json!({
            "op": "suspend", "final_record": updated, "final_record_hash": record_output_hash(&updated, &[]),
            "receipt_id": "rlt_e5", "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "at": "2026-02-03T00:00:00Z",
        }));
        persist_atomic(data_dir, LEASE_DIR, "rpl_e5", &carrying).unwrap();
        complete_participation_intents(data_dir);
        let converged = load_lease(data_dir, "rpl_e5").unwrap();
        assert_eq!(
            converged["status"],
            json!("suspended"),
            "the completer applied the sealed transition"
        );
        assert!(
            converged.get("transition_intent").is_none(),
            "intent consumed"
        );
        assert!(
            std::fs::read(dir.join(RECEIPT_DIR).join("rlt_e5.json")).is_ok(),
            "the sealed receipt is durable"
        );
        // FORGERY: a lying final_record (status jumped to revoked) with fixed seals is refused.
        let mut lying = converged.clone();
        let bad_final = {
            let mut b = apply_transition(
                &converged,
                "transition_intent",
                "suspend",
                "suspended",
                &json!("receipt://rlt_e6"),
                &json!("2026-02-04T00:00:00Z"),
                false,
            );
            b.as_object_mut()
                .unwrap()
                .insert("status".into(), json!("revoked"));
            b
        };
        let bad_receipt = build_room_receipt_at(
            "rlt_e6",
            LEASE_RECEIPT_SCHEMA,
            "RoomParticipantLeaseReceipt",
            "participant-lease://rpl_e5",
            "suspend",
            json!({ "transition": "suspend", "from": "suspended", "to": "suspended", "revision_before": 2, "revision_after": 3 }),
            vec![
                json!("participant-lease://rpl_e5"),
                json!("outcome-room://or_e5"),
            ],
            record_output_hash(&bad_final, TRAIL_EXCLUDES),
            TRAIL_EXCLUDES,
            "admitted_not_verified",
            LEASE_TRANSITION_NOTE,
            "2026-02-04T00:00:00Z",
        );
        lying.as_object_mut().unwrap().insert("transition_intent".into(), json!({
            "op": "suspend", "final_record": bad_final, "final_record_hash": record_output_hash(&bad_final, &[]),
            "receipt_id": "rlt_e6", "receipt": bad_receipt, "receipt_hash": record_output_hash(&bad_receipt, &[]),
            "at": "2026-02-04T00:00:00Z",
        }));
        persist_atomic(data_dir, LEASE_DIR, "rpl_e5", &lying).unwrap();
        complete_participation_intents(data_dir);
        let after = load_lease(data_dir, "rpl_e5").unwrap();
        assert!(
            after.get("transition_intent").is_some(),
            "the forged intent is retained for manual repair, never applied"
        );
        assert_eq!(
            s(&after, "status", ""),
            "suspended",
            "the lying successor was refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn creation_declaration_is_fail_closed() {
        // Vocabulary, plane-owned fields, topology, and private-context guards refuse typed.
        let body = declaration_body("or_ff");
        assert!(validate_request_create(&body).is_ok());
        for (mutation, expected_code) in [
            (
                json!({ "status": "admitted" }),
                "room_participation_status_plane_owned",
            ),
            (
                json!({ "participant_lease_ref": "participant-lease://x" }),
                "room_participation_field_plane_owned",
            ),
            (
                json!({ "request_hash": "sha256:forged" }),
                "room_participation_field_plane_owned",
            ),
            (
                json!({ "signature": "sig" }),
                "room_participation_signature_unavailable",
            ),
            (
                json!({ "room_discovery_ref": "room-discovery://x" }),
                "room_participation_discovery_unavailable",
            ),
            (
                json!({ "coordination_topology": "federated_admission" }),
                "room_participation_federated_unavailable",
            ),
            (
                json!({ "coordination_topology": "mesh" }),
                "room_participation_topology_invalid",
            ),
            (
                json!({ "private_context_included": true }),
                "room_participation_private_context_rejected",
            ),
            (
                json!({ "requested_by_ref": "user://someone" }),
                "outcome_room_ref_scheme_invalid",
            ),
            (
                json!({ "capability_offer_refs": ["not-a-ref"] }),
                "outcome_room_ref_scheme_invalid",
            ),
            (
                json!({ "notes": { "api_key": "SENTINEL" } }),
                "outcome_room_plaintext_secret_rejected",
            ),
        ] {
            let mut b = body.clone();
            for (k, v) in mutation.as_object().unwrap() {
                b.as_object_mut().unwrap().insert(k.clone(), v.clone());
            }
            let (code, _) = validate_request_create(&b).unwrap_err();
            assert_eq!(code, expected_code, "mutation {mutation} → wrong code");
        }
        // Admit params: role vocabulary is canonical.
        let (code, _) = validate_admit_params(&json!({ "admitted_role": "root", "operator_ref": "org://x", "home_domain_ref": "domain://x" })).unwrap_err();
        assert_eq!(code, "participant_lease_role_invalid");
        let _ = code;
    }

    #[test]
    fn storage_key_binding_refuses_a_relocated_intent() {
        // An intent whose sealed request claims a DIFFERENT id than its filename stem is refused.
        let dir = temp_dir("rebind");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_f6");
        let declaration = validate_request_create(&declaration_body("or_f6")).unwrap();
        let record = seal_request(
            &declaration,
            "rpr_f6",
            "receipt://rqr_f6",
            "2026-02-01T00:00:00Z",
        );
        let receipt = json!({ "receipt_ref": "receipt://rqr_f6" });
        let intent = json!({
            "kind": "submit", "request_tail": "rpr_f6", "request_ref": "participation-request://rpr_f6",
            "room_ref": "outcome-room://or_f6",
            "final_request": record, "final_request_hash": record_output_hash(&record, &[]),
            "receipt_id": "rqr_f6", "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "at": "2026-02-01T00:00:00Z",
        });
        // Stored under a DIFFERENT stem: refused before any write.
        persist_atomic(data_dir, SUBMIT_INTENT_DIR, "rpr_f7", &intent).unwrap();
        complete_participation_intents(data_dir);
        assert!(
            load_request(data_dir, "rpr_f6").is_none(),
            "nothing admitted at the claimed id"
        );
        assert!(
            load_request(data_dir, "rpr_f7").is_none(),
            "nothing admitted at the stem id"
        );
        assert!(
            dir.join(SUBMIT_INTENT_DIR).join("rpr_f7.json").exists(),
            "intent retained"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
