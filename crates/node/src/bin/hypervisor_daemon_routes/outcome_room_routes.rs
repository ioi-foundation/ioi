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
//! - GoalRun membership (#72 review finding 2): attach-goal-run binds an EXISTING goal-run
//!   record by its CANONICAL `goal://` identity, stamps the reciprocal
//!   `GoalRun.outcome_room_ref` ATOMICALLY in the same finalization (room → run → receipt, full
//!   checked rollback), and refuses a run that already belongs to ANY room — singular room
//!   identity, never contradictory multi-room state.
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

use super::{iso_now, read_record_dir, DaemonState};

const ROOM_SCHEMA: &str = "ioi.hypervisor.outcome-room.v1";
const ADMISSION_RECEIPT_SCHEMA: &str = "ioi.hypervisor.outcome-room-admission-receipt.v1";
const TRANSITION_RECEIPT_SCHEMA: &str = "ioi.hypervisor.outcome-room-transition-receipt.v1";
// Receipt assurance notes — shared by the finalizers AND the replay validators (#72 round 16)
// so a reconstructed receipt is byte-identical to the finalized one (no drift, no trust).
const ADMISSION_NOTE: &str = "admission of a declared hosted room — a receipt is not proof of outcome; every later shared-state change is its own admitted, receipted transition";
const TRANSITION_NOTE: &str = "an admitted shared-state transition on a hosted room — receipted, optimistically concurrent, and honest about being admission (not verification or acceptance)";
const ATTACH_NOTE: &str = "an admitted membership transition — the room's member list and the GoalRun's reciprocal outcome_room_ref stamp land in one atomic finalization";
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

/// Serializes every ROOM-SCOPE critical section (one daemon writer per data directory): room
/// creation/transition/attach here, AND room-scoped WorkResult/OutcomeDelta admission in
/// work_result_routes. LOCK ORDERING (fixed, documented): ROOM_MUTATION_LOCK is always acquired
/// BEFORE DELTA_ADMISSION_LOCK; no .await executes under either lock. This closes the
/// close-vs-admission TOCTOU (#72 review finding 3).
pub(crate) static ROOM_MUTATION_LOCK: Mutex<()> = Mutex::new(());

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

/// ADMISSION hash scope: the admission receipt binds the DECLARED room shape — plane-owned
/// mutable fields are excluded so later receipted transitions never invalidate it.
const ROOM_HASH_EXCLUDES: &[&str] = &[
    "admission_receipt_ref", "updated_at", "revision", "status", "status_history",
    "member_goal_run_refs", "admission_and_replay_refs",
];
/// TRANSITION hash scope (#72 review finding 4): a transition receipt hashes the transition's
/// OUTPUT — resulting status, revision, membership, and updated_at ARE included; only the
/// circular receipt-bearing fields are excluded (the trail and history embed this receipt's own
/// ref, and admission_receipt_ref is the creation receipt). Distinct transitions therefore emit
/// DISTINCT hashes.
const TRANSITION_HASH_EXCLUDES: &[&str] = &[
    "admission_receipt_ref", "admission_and_replay_refs", "status_history",
];

// ================================================================================================
// SEMANTIC REPLAY VALIDATORS (#72 round 15): a boot completer must never trust a sealed intent's
// self-consistent hashes — those are recomputed from the same mutable intent and prove nothing
// about authenticity. Every intent is validated by CANONICAL SEMANTICS before ANY replay write,
// in EVERY state (room present or absent): the receipt's exact profile/identity/scope is pinned,
// the hash scope is the server-side CONSTANT (never receipt-supplied), and the sealed successor
// is reconstructed as the ONLY valid successor of the durable prior state. Any violation refuses
// with room, receipt family, and intent byte-for-byte unchanged.
// ================================================================================================

/// A canonical receipt tail is EXACTLY `{prefix}_{lowercase-hex}` — the only form
/// build_room_receipt mints (#72 round 17 finding 2). Rejecting anything else before
/// reconstruction closes the normalization-collision attack (`ort/collision` → `ort_collision`)
/// at the source: a non-canonical tail can never name an evidence file.
fn is_canonical_receipt_tail(tail: &str, prefix: &str) -> bool {
    tail.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('_'))
        .map(|hex| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
        .unwrap_or(false)
}

/// A canonical room tail is EXACTLY `or_{lowercase-hex}` (creation mints `or_{:x}`).
fn is_canonical_room_tail(tail: &str) -> bool {
    is_canonical_receipt_tail(tail, "or")
}

/// A record id is filesystem-safe iff it survives the persistence normalization unchanged (#72
/// round 17 finding 2): otherwise two distinct ids (e.g. `ort/collision` and `ort_collision`)
/// would silently target the same evidence file.
fn is_normalization_safe(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// RFC3339 timestamp validation (#72 round 17 finding 3): replay must reject any timestamp
/// production could not emit (null, empty, or malformed) rather than coerce it to "".
fn is_rfc3339(v: &Value) -> bool {
    v.as_str()
        .map(|s| time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).is_ok())
        .unwrap_or(false)
}

/// Read a NON-promoted record directory as (file-stem, value) pairs — the file STEM is the
/// trusted storage key (#72 round 17 finding 1), never a content field a forged record controls.
fn read_dir_with_stems(data_dir: &str, family: &str) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let dir = std::path::Path::new(data_dir).join(family);
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()).map(str::to_string) else { continue };
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    out.push((stem, value));
                }
            }
        }
    }
    out
}

/// Load the room stored AT `stem.json` (by filename, not content id) — the trusted key.
fn load_room_file(data_dir: &str, stem: &str) -> Option<Value> {
    let path = std::path::Path::new(data_dir).join(ROOM_DIR).join(format!("{stem}.json"));
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok())
}

/// Plane-owned + identity fields the creation constructor sets itself — stripped from a sealed
/// room to recover the ORIGINAL declaration body for reconstruction (#72 round 16).
const ROOM_PLANE_OWNED_FIELDS: &[&str] = &[
    "schema_version", "runtimeTruthSource", "outcome_room_id", "created_at", "updated_at",
    "status", "revision", "status_history", "admission_receipt_ref", "admission_and_replay_refs",
    "member_goal_run_refs", "participant_lease_refs", "participation_request_refs",
    "frontier_item_refs", "attempt_refs", "finding_refs", "verifier_challenge_refs",
    "discussion_projection_refs", "contribution_refs", "participant_state_bundle_refs",
];

/// Reconstruct the COMPLETE admission room from a sealed one, through the SAME declaration
/// validator/constructor creation uses (#72 round 16 finding 1): a hollow envelope (missing
/// owner/objective/host/mode/topology/policy refs) is REJECTED by `validate_room_create` — it
/// can never pass as "matching facts" the way `None == None` did. The plane-owned identity and
/// timestamps are then reattached from the sealed room; the caller byte-compares the result.
fn reconstruct_admission_room(final_room: &Value, receipt_ref: &Value, trusted_room_id: &str) -> Result<Value, String> {
    let mut body = final_room.clone();
    if let Some(obj) = body.as_object_mut() {
        for k in ROOM_PLANE_OWNED_FIELDS { obj.remove(*k); }
    }
    let mut record = validate_room_create(&body).map_err(|(code, _)| format!("declaration invalid ({code})"))?;
    // Creation stamps ONE `now` into created_at, updated_at, and the receipt timestamp — which
    // must be a real RFC3339 timestamp production could emit (#72 round 17 finding 3).
    let now = final_room.get("updated_at").cloned().unwrap_or(Value::Null);
    if !is_rfc3339(&now) {
        return Err("updated_at is not a valid RFC3339 timestamp".into());
    }
    // The storage key is the TRUSTED id (`trusted_room_id`, the filename stem) — INJECTED here,
    // never copied from the untrusted sealed room (#72 round 17 finding 1).
    if let Some(obj) = record.as_object_mut() {
        obj.insert("outcome_room_id".into(), json!(trusted_room_id));
        obj.insert("created_at".into(), now.clone());
        obj.insert("updated_at".into(), now);
        obj.insert("admission_receipt_ref".into(), receipt_ref.clone());
        obj.insert("admission_and_replay_refs".into(), json!([receipt_ref]));
    }
    Ok(record)
}

/// ADMISSION intent validator (#72 rounds 15-16): reconstruct the COMPLETE room (via the
/// creation declaration validator) AND the EXACT admission receipt, then require byte equality
/// with both sealed artifacts. No sealed field — declaration, plane-owned state, bound facts,
/// boundary refs, posture, actor, portable-base nulls, or timestamps — is ever trusted.
fn validate_admission_intent(intent: &Value, room_id: &str, room_tail: &str) -> Result<(), String> {
    let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
    let final_room = intent.get("final_room").cloned().unwrap_or(Value::Null);
    let intent_receipt_id = intent.get("receipt_id").and_then(Value::as_str).unwrap_or("");
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    // Self-consistency of the intent seals (fast reject).
    if intent.get("receipt_hash").and_then(Value::as_str) != Some(record_output_hash(&receipt, &[]).as_str()) {
        return Err("receipt seal".into());
    }
    if intent.get("final_room_hash").and_then(Value::as_str) != Some(record_output_hash(&final_room, &[]).as_str()) {
        return Err("final-room seal".into());
    }
    // STORAGE-KEY BINDING (#72 round 17 finding 1): the TRUSTED key is the filename stem — every
    // identity field the completer will index or reference must equal it. `room_tail` is the
    // stem; `room_id` is `outcome-room://<stem>`.
    if !is_canonical_room_tail(room_tail) {
        return Err("non-canonical room tail (storage key)".into());
    }
    if intent.get("room_tail").and_then(Value::as_str) != Some(room_tail)
        || intent.get("room_ref").and_then(Value::as_str) != Some(room_id)
        || final_room.get("outcome_room_id").and_then(Value::as_str) != Some(room_id)
        || receipt.get("subject_ref").and_then(Value::as_str) != Some(room_id)
        || receipt.pointer("/attested_boundary_fact_refs/0").and_then(Value::as_str) != Some(room_id)
    {
        return Err("room identity does not bind to the storage key".into());
    }
    // CANONICAL RECEIPT TAIL (#72 round 17 finding 2): the tail names the evidence file; only
    // `orr_<hex>` survives normalization unambiguously.
    if !is_canonical_receipt_tail(intent_receipt_id, "orr") {
        return Err("non-canonical admission receipt tail".into());
    }
    // The receipt ref must be receipt://<intent tail> (the file the completer will persist to).
    if receipt_ref.as_str() != Some(format!("receipt://{intent_receipt_id}").as_str()) {
        return Err("receipt ref vs intent tail".into());
    }
    // Timestamp equalities production always emits (#72 round 17 finding 3).
    let ca = final_room.get("created_at").cloned().unwrap_or(Value::Null);
    let ua = final_room.get("updated_at").cloned().unwrap_or(Value::Null);
    if !is_rfc3339(&ca) || !is_rfc3339(&ua) || ca != ua {
        return Err("admission timestamps not RFC3339-equal".into());
    }
    // RECONSTRUCT the complete room through the creation constructor with the TRUSTED id;
    // byte-compare (a sealed outcome_room_id != the stem now fails here).
    let expected_room = reconstruct_admission_room(&final_room, &receipt_ref, room_id)?;
    if serde_json::to_vec(&expected_room).unwrap_or_default() != serde_json::to_vec(&final_room).unwrap_or_default() {
        return Err("not the canonical admission room".into());
    }
    // RECONSTRUCT the EXACT admission receipt from the validated room; byte-compare.
    let now = expected_room.get("updated_at").and_then(Value::as_str).unwrap_or("");
    let expected_receipt = build_room_receipt_at(
        intent_receipt_id, ADMISSION_RECEIPT_SCHEMA, "OutcomeRoomAdmissionReceipt", room_id, "admitted",
        json!({ "room_mode": expected_room["room_mode"], "coordination_topology": expected_room["coordination_topology"], "owner_or_sponsor_ref": expected_room["owner_or_sponsor_ref"], "objective_ref": expected_room["objective_ref"], "host_domain_ref": expected_room["host_domain_ref"], "status_at_admission": "open" }),
        vec![json!(room_id), expected_room["owner_or_sponsor_ref"].clone(), expected_room["objective_ref"].clone(), expected_room["host_domain_ref"].clone()],
        record_output_hash(&expected_room, ROOM_HASH_EXCLUDES), ROOM_HASH_EXCLUDES, "admitted_not_verified", ADMISSION_NOTE, now,
    );
    if serde_json::to_vec(&expected_receipt).unwrap_or_default() != serde_json::to_vec(&receipt).unwrap_or_default() {
        return Err("not the canonical admission receipt".into());
    }
    Ok(())
}

/// Reconstruct the ONLY valid TRANSITION successor of `prior` for the named op AND the EXACT
/// transition receipt, then require the sealed `final_room` + receipt to equal them byte-for-
/// byte (#72 rounds 15-16 finding 2). `prior` is the durable room with its `transition_intent`
/// stripped — so a forged declaration, status, revision, trail, OR receipt (bound facts,
/// boundary refs, posture, actor, timestamps) can never match the deterministic reconstruction.
fn validate_transition_intent(intent: &Value, prior: &Value, room_id: &str, room_tail: &str) -> Result<(), String> {
    let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
    let final_room = intent.get("final_room").cloned().unwrap_or(Value::Null);
    let intent_receipt_id = intent.get("receipt_id").and_then(Value::as_str).unwrap_or("");
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    if intent.get("receipt_hash").and_then(Value::as_str) != Some(record_output_hash(&receipt, &[]).as_str()) {
        return Err("receipt seal".into());
    }
    if intent.get("final_room_hash").and_then(Value::as_str) != Some(record_output_hash(&final_room, &[]).as_str()) {
        return Err("final-room seal".into());
    }
    // Storage-key + canonical-tail binding (#72 round 17 findings 1-2): the prior room's own id,
    // the successor's id, the receipt subject + first boundary all equal the trusted stem key.
    if !is_canonical_room_tail(room_tail) {
        return Err("non-canonical room tail (storage key)".into());
    }
    if prior.get("outcome_room_id").and_then(Value::as_str) != Some(room_id)
        || final_room.get("outcome_room_id").and_then(Value::as_str) != Some(room_id)
        || receipt.get("subject_ref").and_then(Value::as_str) != Some(room_id)
        || receipt.pointer("/attested_boundary_fact_refs/0").and_then(Value::as_str) != Some(room_id)
    {
        return Err("room identity does not bind to the storage key".into());
    }
    if !is_canonical_receipt_tail(intent_receipt_id, "ort") {
        return Err("non-canonical transition receipt tail".into());
    }
    if !is_rfc3339(&final_room.get("updated_at").cloned().unwrap_or(Value::Null)) {
        return Err("transition updated_at not RFC3339".into());
    }
    if receipt_ref.as_str() != Some(format!("receipt://{intent_receipt_id}").as_str()) {
        return Err("receipt ref vs intent tail".into());
    }
    let op = receipt.get("op").and_then(Value::as_str).unwrap_or("");
    // The op must be a CANONICAL transition admitted from the prior status.
    let Some((_, allowed_from, to_status)) = TRANSITIONS.iter().find(|(t, _, _)| *t == op) else {
        return Err("unknown transition op".into());
    };
    let from = prior.get("status").and_then(Value::as_str).unwrap_or("");
    if !allowed_from.contains(&from) {
        return Err("transition not admitted from prior status".into());
    }
    let prior_rev = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let now = final_room.get("updated_at").cloned().unwrap_or(Value::Null); // excluded/free timestamp
    let now_str = now.as_str().unwrap_or("");
    // Reconstruct the deterministic successor room exactly as mutate_room would.
    let mut expected = prior.clone();
    if let Some(obj) = expected.as_object_mut() {
        obj.remove("transition_intent");
        obj.insert("status".into(), json!(to_status));
        obj.insert("revision".into(), json!(prior_rev + 1));
        obj.insert("updated_at".into(), now.clone());
        let mut trail: Vec<Value> = obj.get("admission_and_replay_refs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        trail.push(receipt_ref.clone());
        obj.insert("admission_and_replay_refs".into(), Value::Array(trail));
        let mut history: Vec<Value> = obj.get("status_history").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        history.push(json!({ "op": op, "at": now, "receipt_ref": receipt_ref, "revision": prior_rev + 1 }));
        if history.len() > HISTORY_MAX { let drop_n = history.len() - HISTORY_MAX; history.drain(0..drop_n); }
        obj.insert("status_history".into(), Value::Array(history));
    }
    if serde_json::to_vec(&expected).unwrap_or_default() != serde_json::to_vec(&final_room).unwrap_or_default() {
        return Err("not the deterministic successor".into());
    }
    // Reconstruct the EXACT transition receipt as mutate_room would; byte-compare.
    let expected_receipt = build_room_receipt_at(
        intent_receipt_id, TRANSITION_RECEIPT_SCHEMA, "OutcomeRoomTransitionReceipt", room_id, op,
        json!({ "transition": op, "from": from, "to": to_status, "revision_before": prior_rev, "revision_after": prior_rev + 1 }),
        vec![json!(room_id)],
        record_output_hash(&expected, TRANSITION_HASH_EXCLUDES), TRANSITION_HASH_EXCLUDES, "admitted_not_verified", TRANSITION_NOTE, now_str,
    );
    if serde_json::to_vec(&expected_receipt).unwrap_or_default() != serde_json::to_vec(&receipt).unwrap_or_default() {
        return Err("not the canonical transition receipt".into());
    }
    Ok(())
}

/// Reconstruct the ONLY valid ATTACH (membership) successor of `prior` for the sealed run AND
/// the EXACT attach receipt, then require the sealed `updated_room` + receipt to equal them
/// byte-for-byte (#72 rounds 15-16 finding 2). `prior` is the durable room with its
/// `attach_intent` stripped.
fn validate_attach_intent(intent: &Value, prior: &Value, room_id: &str, room_tail: &str) -> Result<(), String> {
    let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
    let updated_room = intent.get("updated_room").cloned().unwrap_or(Value::Null);
    let intent_receipt_id = intent.get("receipt_id").and_then(Value::as_str).unwrap_or("");
    let run_file_id = intent.get("run_file_id").and_then(Value::as_str).unwrap_or("");
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    if intent.get("receipt_hash").and_then(Value::as_str) != Some(record_output_hash(&receipt, &[]).as_str()) {
        return Err("receipt seal".into());
    }
    if intent.get("updated_room_hash").and_then(Value::as_str) != Some(record_output_hash(&updated_room, &[]).as_str()) {
        return Err("updated-room seal".into());
    }
    // Storage-key + canonical-tail binding (#72 round 17 findings 1-2).
    if !is_canonical_room_tail(room_tail) {
        return Err("non-canonical room tail (storage key)".into());
    }
    if prior.get("outcome_room_id").and_then(Value::as_str) != Some(room_id)
        || updated_room.get("outcome_room_id").and_then(Value::as_str) != Some(room_id)
        || receipt.get("subject_ref").and_then(Value::as_str) != Some(room_id)
        || receipt.pointer("/attested_boundary_fact_refs/0").and_then(Value::as_str) != Some(room_id)
    {
        return Err("room identity does not bind to the storage key".into());
    }
    if !is_canonical_receipt_tail(intent_receipt_id, "ort") {
        return Err("non-canonical attach receipt tail".into());
    }
    if !is_rfc3339(&updated_room.get("updated_at").cloned().unwrap_or(Value::Null)) {
        return Err("attach updated_at not RFC3339".into());
    }
    if receipt_ref.as_str() != Some(format!("receipt://{intent_receipt_id}").as_str()) {
        return Err("receipt ref vs intent tail".into());
    }
    if run_file_id.is_empty() {
        return Err("missing run".into());
    }
    if prior.get("status").and_then(Value::as_str) != Some("open") {
        return Err("attach not admitted from prior status".into());
    }
    let member = format!("goal://{run_file_id}");
    let members: Vec<String> = prior.get("member_goal_run_refs").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    if members.iter().any(|m| m == &member) {
        return Err("run already a member of the prior room".into());
    }
    let prior_rev = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let now = updated_room.get("updated_at").cloned().unwrap_or(Value::Null);
    let now_str = now.as_str().unwrap_or("");
    let mut expected = prior.clone();
    if let Some(obj) = expected.as_object_mut() {
        obj.remove("attach_intent");
        let mut arr: Vec<Value> = members.iter().cloned().map(Value::String).collect();
        arr.push(json!(member));
        obj.insert("member_goal_run_refs".into(), Value::Array(arr));
        obj.insert("revision".into(), json!(prior_rev + 1));
        obj.insert("updated_at".into(), now.clone());
        let mut trail: Vec<Value> = obj.get("admission_and_replay_refs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        trail.push(receipt_ref.clone());
        obj.insert("admission_and_replay_refs".into(), Value::Array(trail));
        let mut history: Vec<Value> = obj.get("status_history").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        history.push(json!({ "op": "goal_run_attached", "at": now, "receipt_ref": receipt_ref, "revision": prior_rev + 1 }));
        if history.len() > HISTORY_MAX { let drop_n = history.len() - HISTORY_MAX; history.drain(0..drop_n); }
        obj.insert("status_history".into(), Value::Array(history));
    }
    if serde_json::to_vec(&expected).unwrap_or_default() != serde_json::to_vec(&updated_room).unwrap_or_default() {
        return Err("not the deterministic membership successor".into());
    }
    // Reconstruct the EXACT attach receipt as the attach handler would; byte-compare.
    let expected_receipt = build_room_receipt_at(
        intent_receipt_id, TRANSITION_RECEIPT_SCHEMA, "OutcomeRoomTransitionReceipt", room_id, "goal_run_attached",
        json!({ "goal_run_ref": member, "reciprocal_outcome_room_ref_stamped": true, "member_count_after": members.len() + 1, "revision_before": prior_rev, "revision_after": prior_rev + 1 }),
        vec![json!(room_id), json!(member)],
        record_output_hash(&expected, TRANSITION_HASH_EXCLUDES), TRANSITION_HASH_EXCLUDES, "admitted_not_verified", ATTACH_NOTE, now_str,
    );
    if serde_json::to_vec(&expected_receipt).unwrap_or_default() != serde_json::to_vec(&receipt).unwrap_or_default() {
        return Err("not the canonical attach receipt".into());
    }
    Ok(())
}

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
    hash_scope_excludes: &[&str],
    posture: &str,
    note: &str,
    now: &str,
) -> (String, Value) {
    let id_tail = format!("{prefix}_{:x}", nanos());
    let rec = build_room_receipt_at(&id_tail, schema, receipt_type, subject_ref, op, bound_facts, boundary_refs, output_hash, hash_scope_excludes, posture, note, now);
    (id_tail, rec)
}

/// The receipt constructor with an EXPLICIT id tail + timestamp (#72 round 16): both the
/// finalizers (via build_room_receipt) AND the replay validators call THIS, so a replay can
/// reconstruct the EXACT receipt the finalizer would have produced and require byte equality —
/// no sealed receipt field (bound facts, boundary refs, posture, actor, portable-base nulls,
/// timestamps) is ever trusted.
#[allow(clippy::too_many_arguments)]
fn build_room_receipt_at(
    id_tail: &str,
    schema: &str,
    receipt_type: &str,
    subject_ref: &str,
    op: &str,
    bound_facts: Value,
    boundary_refs: Vec<Value>,
    output_hash: String,
    hash_scope_excludes: &[&str],
    posture: &str,
    note: &str,
    now: &str,
) -> Value {
    let receipt_id = format!("receipt://{id_tail}");
    json!({
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
        "hash_scope_excludes": hash_scope_excludes,
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
    })
}

/// ATOMIC file replacement for MUTABLE records (rooms + the reciprocal GoalRun stamp): tmp
/// sibling (no .json extension — invisible to read_record_dir) + rename; BOTH failure paths
/// clean the temp file.
/// The room plane's record writer IS the typed durable writer (#72 round 9 finding 3): tmp +
/// file fsync + rename + checked directory fsync, with the same NotCommitted /
/// RenamedDurabilityUnconfirmed outcome split — room records and receipts carry the same
/// crash-durability contract as goal-run evidence.
fn persist_atomic(data_dir: &str, family: &str, record_id: &str, record: &Value) -> Result<(), super::goalrun_routes::PersistFailure> {
    // Evidence keys must be filesystem-safe AS WRITTEN (#72 round 17 finding 2): the durable
    // writer normalizes unsafe characters, so `ort/collision` and `ort_collision` would silently
    // target the same file. Reject rather than collide — the room plane only ever writes
    // canonical `or_hex` / `orr_hex` / `ort_hex` keys, so this is a no-op for honest callers.
    if !is_normalization_safe(record_id) {
        return Err(super::goalrun_routes::PersistFailure::NotCommitted(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("record id '{record_id}' is not filesystem-safe (would normalize to a different key)"),
        )));
    }
    super::goalrun_routes::persist_record_durable(data_dir, family, record_id, record)
}

fn load_room(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, ROOM_DIR)
        .into_iter()
        .find(|r| r.get("outcome_room_id").and_then(|v| v.as_str()) == Some(id))
}

pub(crate) fn resolve_open_room(data_dir: &str, room_ref: &str) -> Option<Value> {
    load_room(data_dir, room_ref)
}

/// Which durable intent (if any) is pending on a room record — EVERY room mutator refuses
/// while one is in flight (#72 round 10 finding 2): a mutation that raced an intent would be
/// silently erased when the completer replays the sealed final state.
pub(crate) fn pending_intent(room: &Value) -> Option<(&'static str, &'static str)> {
    if room.get("attach_intent").is_some() {
        return Some(("attach_intent", "outcome_room_attach_in_flight"));
    }
    if room.get("transition_intent").is_some() {
        return Some(("transition_intent", "outcome_room_mutation_in_flight"));
    }
    None
}

/// Internal family for pending admissions (#72 round 11 finding 2): a room being admitted
/// lives HERE — never in the public registry — until its receipt is durable, so no
/// noncanonical status ever escapes to consumers and no binding can resolve a pending room.
const ADMISSION_INTENT_DIR: &str = "outcome-room-admission-intents";

/// CREATION as an INTENT TRANSACTION over an INTERNAL family (#72 round 10 finding 1 + round
/// 11 finding 2): the first durable artifact is an admission-intent RECORD in
/// `outcome-room-admission-intents` — the public registry never holds a pending room, so no
/// noncanonical status escapes (`ROOM_STATUSES` stays the enum consumers see) and no binding
/// can resolve a room whose admission is unconfirmed. The receipt must be DURABLE before the
/// terminal registry write; only that terminal write tolerates visible-unconfirmed. The
/// consumed intent is dropped afterwards — an unlink resurrected by a crash merely replays the
/// idempotent, byte-exact convergence.
fn finalize_room_create(
    data_dir: &str,
    room_tail: &str,
    record: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    let intent = json!({
        "room_tail": room_tail,
        "room_ref": record.get("outcome_room_id").cloned().unwrap_or(Value::Null),
        "receipt_id": receipt_id,
        "receipt": receipt,
        "receipt_hash": record_output_hash(receipt, &[]),
        "final_room": record,
        "final_room_hash": record_output_hash(record, &[]),
        "at": iso_now(),
    });
    match persist_atomic(data_dir, ADMISSION_INTENT_DIR, room_tail, &intent) {
        Ok(()) => {}
        Err(f) if f.visible() => {
            return Err(verr("outcome_room_admission_pending_convergence", format!("the admission intent is {}; the room is NOT in the registry — a restart either admits this same room (completer) or it never existed; do not re-create", f.detail())));
        }
        Err(f) => {
            return Err(verr("outcome_room_record_persist_failed", format!("the admission intent persist is {} — nothing changed", f.detail())));
        }
    }
    if let Err(f) = persist_atomic(data_dir, ROOM_RECEIPT_DIR, receipt_id, receipt) {
        return Err(verr("outcome_room_admission_pending_convergence", format!("the admission receipt is {}; the DURABLE intent is retained internally (the room is not yet in the registry) — a restart re-persists the sealed receipt and admits this same room; do not re-create", f.detail())));
    }
    match persist_atomic(data_dir, ROOM_DIR, room_tail, record) {
        Ok(()) => {
            // Consume the intent ONLY after the terminal room write is DURABLE (#72 round 12
            // finding 1): the rename and the unlink live in DIFFERENT directories, so a crash
            // could otherwise preserve the unlink while losing an unconfirmed rename — leaving
            // an admission receipt with neither room nor replay anchor. A lost unlink is the
            // safe direction: the resurrected intent replays an idempotent byte-exact
            // convergence, never a second room.
            let _ = std::fs::remove_file(std::path::Path::new(data_dir).join(ADMISSION_INTENT_DIR).join(format!("{room_tail}.json")));
            Ok(())
        }
        Err(f) if f.visible() => {
            // The room is VISIBLE but its durability is unconfirmed — the intent is RETAINED as
            // the replay anchor; restart confirms or replays the terminal write. Room-or-intent
            // always survives alongside the durable receipt.
            Ok(())
        }
        Err(f) => Err(verr("outcome_room_admission_pending_convergence", format!("the terminal registry write is {}; the DURABLE intent and receipt are retained — a restart admits this same room; do not re-create", f.detail()))),
    }
}

/// MUTATION as an INTENT TRANSACTION (#72 round 10 finding 1): the first durable artifact is
/// the PRIOR room carrying a `transition_intent` sealing the final state + its receipt — the
/// visible status NEVER advances before the receipt is durable (the reviewer's `paused` with
/// zero receipt is structurally impossible). A not-committed receipt rolls the intent back to
/// the exact prior room (durable, nothing changed); a visible-unconfirmed receipt retains the
/// intent for boot replay; only the terminal write tolerates visible-unconfirmed.
fn finalize_room_mutation(
    data_dir: &str,
    room_tail: &str,
    prior: &Value,
    updated: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    let intent = json!({
        "receipt_id": receipt_id,
        "receipt": receipt,
        "receipt_hash": record_output_hash(receipt, &[]),
        "final_room": updated,
        "final_room_hash": record_output_hash(updated, &[]),
        "at": iso_now(),
    });
    let mut pending = prior.clone();
    if let Some(obj) = pending.as_object_mut() {
        obj.insert("transition_intent".into(), intent);
    }
    match persist_atomic(data_dir, ROOM_DIR, room_tail, &pending) {
        Ok(()) => {}
        Err(f) if f.visible() => {
            return Err(verr("outcome_room_mutation_pending_convergence", format!("the transition intent is {}; the visible room still shows the PRIOR state — a restart either applies the sealed transition (completer) or nothing happened", f.detail())));
        }
        Err(f) => {
            return Err(verr("outcome_room_record_persist_failed", format!("the transition intent persist is {} — nothing changed", f.detail())));
        }
    }
    match persist_atomic(data_dir, ROOM_RECEIPT_DIR, receipt_id, receipt) {
        Ok(()) => {}
        Err(f) if f.visible() => {
            return Err(verr("outcome_room_mutation_pending_convergence", format!("the transition receipt is {}; the DURABLE intent is retained with the room still in its PRIOR state — a restart re-persists the sealed receipt and applies the transition", f.detail())));
        }
        Err(f) => {
            let e = f.detail();
            return match persist_atomic(data_dir, ROOM_DIR, room_tail, prior) {
                Ok(()) => Err(verr("outcome_room_receipt_persist_failed", format!("transition receipt persist is {e}; the intent was rolled back EXACTLY (the room never left its prior state) — nothing changed"))),
                Err(_) => Err(verr("outcome_room_mutation_pending_convergence", format!("transition receipt persist is {e} AND the intent rollback did not commit — a restart converges the sealed transition"))),
            };
        }
    }
    match persist_atomic(data_dir, ROOM_DIR, room_tail, updated) {
        Ok(()) => Ok(()),
        Err(f) if f.visible() => Ok(()),
        Err(f) => Err(verr("outcome_room_mutation_pending_convergence", format!("the terminal transition write is {}; the DURABLE intent and receipt are retained — a restart completes the transition", f.detail()))),
    }
}

/// BOOT COMPLETER for admission + transition intents (#72 round 10 finding 1): validate the
/// seals (receipt + final-room hashes, identity bindings), re-persist the sealed receipt
/// (byte-exact when it already exists), then apply the sealed final room. Anything inconsistent
/// is left in place for manual repair; nothing is manufactured, overwritten, or deleted.
pub(crate) fn complete_room_intents(data_dir: &str) {
    let _guard = ROOM_MUTATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // Pending admissions live in the INTERNAL intent family (#72 round 11 finding 2); pending
    // transitions ride on their registry record. Both converge through the same sealed replay.
    // The TRUSTED storage key is the FILENAME STEM (#72 round 17 finding 1), never a content
    // field a forged record controls. Admission intents live in the internal family; transitions
    // ride on their registry record — both keyed by their own file stem.
    let mut work: Vec<(&'static str, Value, String)> = Vec::new();
    for (stem, intent) in read_dir_with_stems(data_dir, ADMISSION_INTENT_DIR) {
        work.push(("admission", intent, stem));
    }
    for (stem, room) in read_dir_with_stems(data_dir, ROOM_DIR) {
        if let Some(i) = room.get("transition_intent") {
            work.push(("transition", i.clone(), stem));
        }
    }
    for (kind, intent, room_tail) in work {
        let room_id = format!("outcome-room://{room_tail}");
        let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
        let receipt_id = intent.get("receipt_id").and_then(Value::as_str).unwrap_or("").to_string();
        let final_room = intent.get("final_room").cloned().unwrap_or(Value::Null);
        if room_tail.is_empty() || receipt.is_null() || receipt_id.is_empty() || final_room.is_null() {
            eprintln!("outcome-room {kind} completer: intent on '{room_tail}' fails schema — left in place for manual repair");
            continue;
        }
        // SEMANTIC VALIDATION FIRST, for EVERY intent, room present or absent (#72 round 15):
        // a sealed intent is only replayed if it is the CANONICAL successor of the durable prior
        // state bound to the TRUSTED storage key — never merely self-consistent. The transition
        // prior is the room record AT THIS STEM with its `transition_intent` stripped.
        let semantic = if kind == "admission" {
            validate_admission_intent(&intent, &room_id, &room_tail)
        } else {
            match load_room_file(data_dir, &room_tail) {
                Some(mut prior) => {
                    if let Some(obj) = prior.as_object_mut() { obj.remove("transition_intent"); }
                    validate_transition_intent(&intent, &prior, &room_id, &room_tail)
                }
                None => Err("transition intent has no durable prior room".into()),
            }
        };
        if let Err(why) = semantic {
            eprintln!("outcome-room {kind} completer: intent on '{room_tail}' is NOT the canonical successor ({why}) — nothing was written (room, receipts, and intent are byte-unchanged); left for manual repair");
            continue;
        }
        // ADMISSION conflict check — before ANY write (#72 round 12 finding 2): a conflict lane
        // leaves room, receipt family, and intent byte-for-byte unchanged. The intent is already
        // proven canonical above; this decides same-vs-foreign for an EXISTING occupant. A room
        // already at this identity is THE SAME admission iff its anchor (the first entry of its
        // admission trail — the sealed admission receipt ref) matches AND its declaration proves
        // the receipt. A different/tampered occupant is refused, never receipted over.
        let mut same_room_already_admitted = false;
        if kind == "admission" {
            if let Some(existing_room) = load_room_file(data_dir, &room_tail) {
                // SAME-ADMISSION PROOF (#72 rounds 12-14): anchor equality alone does not prove
                // identity, and NEITHER does a receipt-self-declared hash scope — a malformed
                // intent could widen `hash_scope_excludes` to exclude `objective`/
                // `owner_or_sponsor_ref` and pass a tampered declaration (#72 round 14). The
                // existing room is the same admission ONLY when
                //   (a) BOTH its `admission_receipt_ref` and its trail anchor equal the sealed
                //       receipt ref, and receipt/intent ids are consistent,
                //   (b) the sealed receipt is a fully-pinned room admission (schema_version,
                //       profile, type, op=="admitted", subject), and its declared
                //       `hash_scope_excludes` EQUALS the canonical `ROOM_HASH_EXCLUDES` exactly
                //       (no widened/duplicate/non-string entries), and
                //   (c) the existing room's IMMUTABLE DECLARATION recomputes to the receipt's
                //       output_hash under the CONSTANT `ROOM_HASH_EXCLUDES` — never the receipt-
                //       provided scope (legitimate transitions only ever touch excluded fields).
                // Any mismatch refuses with room, receipt family, and intent byte-unchanged.
                let sealed_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
                let anchor = |r: &Value| r.pointer("/admission_and_replay_refs/0").cloned().unwrap_or(Value::Null);
                let refs_ok = !sealed_ref.is_null()
                    && anchor(&existing_room) == sealed_ref
                    && existing_room.get("admission_receipt_ref") == Some(&sealed_ref)
                    && receipt.get("receipt_id") == Some(&sealed_ref);
                let identity_ok = receipt.get("schema_version").and_then(Value::as_str) == Some(ADMISSION_RECEIPT_SCHEMA)
                    && receipt.get("receipt_type").and_then(Value::as_str) == Some("OutcomeRoomAdmissionReceipt")
                    && receipt.get("receipt_profile_ref").and_then(Value::as_str) == Some(format!("schema://{ADMISSION_RECEIPT_SCHEMA}").as_str())
                    && receipt.get("op").and_then(Value::as_str) == Some("admitted")
                    && receipt.get("subject_ref").and_then(Value::as_str) == Some(room_id.as_str());
                // The receipt's declared scope must be EXACTLY the canonical list — same length,
                // same entries, same order, all strings (a widened scope is a forged receipt).
                let declared_scope: Vec<&str> = receipt
                    .get("hash_scope_excludes")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().map(|v| v.as_str().unwrap_or("\0non-string")).collect())
                    .unwrap_or_default();
                let scope_ok = declared_scope == ROOM_HASH_EXCLUDES;
                // Recompute under the CONSTANT, never the receipt's field.
                let declaration_ok = receipt.get("output_hash").and_then(Value::as_str)
                    == Some(record_output_hash(&existing_room, ROOM_HASH_EXCLUDES).as_str());
                if !(refs_ok && identity_ok && scope_ok && declaration_ok) {
                    eprintln!("outcome-room admission completer: the room at '{room_id}' does NOT prove this admission (refs_ok={refs_ok} identity_ok={identity_ok} scope_ok={scope_ok} declaration_ok={declaration_ok}) — nothing was written (room, receipts, and intent are byte-unchanged); left for manual repair");
                    continue;
                }
                same_room_already_admitted = true;
            }
        }
        let sealed_receipt_ref = receipt.get("receipt_id").and_then(Value::as_str).unwrap_or("").to_string();
        let existing = read_record_dir(data_dir, ROOM_RECEIPT_DIR)
            .into_iter()
            .find(|r| r.get("receipt_id").and_then(Value::as_str) == Some(sealed_receipt_ref.as_str()));
        if let Some(existing) = existing {
            if serde_json::to_vec(&existing).unwrap_or_default() != serde_json::to_vec(&receipt).unwrap_or_default() {
                eprintln!("outcome-room {kind} completer: a DIFFERENT receipt already exists for '{receipt_id}' — conflicting evidence is never overwritten; left for manual repair");
                continue;
            }
        } else if let Err(f) = persist_atomic(data_dir, ROOM_RECEIPT_DIR, &receipt_id, &receipt) {
            eprintln!("outcome-room {kind} completer: receipt persist for '{room_tail}' is {} — intent retained, retried next boot", f.detail());
            continue;
        }
        if !same_room_already_admitted {
            match persist_atomic(data_dir, ROOM_DIR, &room_tail, &final_room) {
                Ok(()) => {}
                Err(f) if f.visible() && kind == "transition" => {}
                Err(f) if f.visible() => {
                    // ADMISSION terminal visible-unconfirmed (#72 round 12 finding 1): the
                    // intent is the ONLY durable replay anchor in another directory — it must
                    // outlive an unconfirmed rename. Retained; the next boot confirms/replays.
                    eprintln!("outcome-room admission completer: terminal write for '{room_tail}' is {} — intent retained until a boot confirms it", f.detail());
                    continue;
                }
                Err(f) => {
                    eprintln!("outcome-room {kind} completer: terminal write for '{room_tail}' is {} — intent retained, retried next boot", f.detail());
                    continue;
                }
            }
        }
        if kind == "admission" {
            // The room is durably in the registry (or was already) — NOW the intent may go
            // (#72 round 12 finding 1). A crash-lost unlink resurrects only an idempotent
            // byte-exact replay.
            let _ = std::fs::remove_file(std::path::Path::new(data_dir).join(ADMISSION_INTENT_DIR).join(format!("{room_tail}.json")));
        }
        eprintln!("outcome-room {kind} completer: converged the interrupted {kind} on '{room_tail}'");
    }
}

/// ATTACH INTENT TRANSACTION (#72 round 9 finding 3): the attach spans TWO aggregates (room
/// membership + reciprocal GoalRun stamp) plus a receipt, so a durable intent SEALED ON THE
/// ROOM RECORD anchors the whole transaction before any component lands:
///   1. room record + `attach_intent` (durable REQUIRED — seals the updated room, the receipt,
///      and their canonical hashes),
///   2. reciprocal GoalRun stamp through the shared CAS seam (durable REQUIRED),
///   3. receipt (durable REQUIRED),
///   4. TERMINAL: the updated room (membership in, intent consumed) — the only step that
///      tolerates visible-unconfirmed, because a crash-revert restores the intent for replay.
/// Once the intent is durable the attach CONVERGES FORWARD: any later failure refuses typed
/// with the intent retained, and `complete_attach_intents` finishes (or, if the run vanished
/// because its stamp never became durable, rolls the intent back) at boot — no rollback path
/// can ever produce room/stamp/receipt split-brain. Lock ordering holds: callers hold
/// ROOM_MUTATION_LOCK; the seam takes GOAL_RUN_MUTATION_LOCK inside (room → GoalRun, always).
fn finalize_attach(
    data_dir: &str,
    room_tail: &str,
    prior_room: &Value,
    updated_room: &Value,
    run_file_id: &str,
    room_id: &str,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    let intent = json!({
        "run_file_id": run_file_id,
        "room_ref": room_id,
        "receipt_id": receipt_id,
        "receipt": receipt,
        "receipt_hash": record_output_hash(receipt, &[]),
        "updated_room": updated_room,
        "updated_room_hash": record_output_hash(updated_room, &[]),
        "at": iso_now(),
    });
    let mut with_intent = prior_room.clone();
    if let Some(obj) = with_intent.as_object_mut() {
        obj.insert("attach_intent".into(), intent);
    }
    match persist_atomic(data_dir, ROOM_DIR, room_tail, &with_intent) {
        Ok(()) => {}
        Err(f) if f.visible() => {
            return Err(verr("outcome_room_attach_intent_durability_unconfirmed", format!("the attach intent is {} — nothing else was written; a restart either completes the visible intent or nothing happened", f.detail())));
        }
        Err(f) => {
            return Err(verr("outcome_room_record_persist_failed", format!("the attach intent persist is {} — nothing changed", f.detail())));
        }
    }
    // (2) Reciprocal stamp — DURABLE required before the receipt exists.
    let room_ref = room_id.to_string();
    let ref_for_predicate = room_ref.clone();
    let stamped = super::goalrun_routes::update_goal_run_guarded(
        data_dir,
        run_file_id,
        move |fresh| match fresh.get("outcome_room_ref").and_then(Value::as_str) {
            None => Ok(()),
            Some(r) if r.is_empty() || r == ref_for_predicate => Ok(()),
            Some(other) => Err((
                "outcome_room_conflicting_binding".to_string(),
                format!("the run is already bound to '{other}' — singular room identity holds at the write itself, not just at validation"),
            )),
        },
        |obj| {
            obj.insert("outcome_room_ref".into(), json!(room_ref));
        },
    );
    match stamped {
        Ok(super::goalrun_routes::MutationOutcome::Durable(_)) => {}
        Ok(super::goalrun_routes::MutationOutcome::VisibleUnconfirmed(_, note)) => {
            return Err(verr("outcome_room_attach_pending_convergence", format!("the reciprocal stamp is visible but not durably confirmed ({note}); the DURABLE attach intent is retained — a restart converges the attach (reciprocal equality guaranteed either way)")));
        }
        Err((code, msg)) => {
            // The stamp provably did not land. Roll the intent back to the exact prior room; if
            // even that fails, the intent stays and the boot completer resolves it (it restores
            // the prior room when the run cannot be stamped).
            return match persist_atomic(data_dir, ROOM_DIR, room_tail, prior_room) {
                Ok(()) => Err(verr("outcome_room_reciprocal_stamp_failed", format!("the reciprocal GoalRun stamp failed ({code}: {msg}); the room was restored EXACTLY — nothing changed"))),
                Err(_) => Err(verr("outcome_room_attach_pending_convergence", format!("the reciprocal GoalRun stamp failed ({code}: {msg}) AND the intent rollback did not commit — the boot completer resolves the intent at restart"))),
            };
        }
    }
    // (3) Receipt — DURABLE required; any failure keeps the intent for replay (never unstamp,
    // never delete: the completer re-persists the sealed receipt byte-exact and finishes).
    if let Err(f) = persist_atomic(data_dir, ROOM_RECEIPT_DIR, receipt_id, receipt) {
        return Err(verr("outcome_room_attach_pending_convergence", format!("the attach receipt is {}; the DURABLE intent and the stamp are retained — a restart re-persists the sealed receipt and completes the membership", f.detail())));
    }
    // (4) TERMINAL: membership in, intent consumed — visible-unconfirmed tolerated (a
    // crash-revert restores the intent, which replays forward).
    match persist_atomic(data_dir, ROOM_DIR, room_tail, updated_room) {
        Ok(()) => Ok(()),
        Err(f) if f.visible() => Ok(()),
        Err(f) => Err(verr("outcome_room_attach_pending_convergence", format!("the terminal membership write is {}; the DURABLE intent, stamp, and receipt are retained — a restart completes the membership", f.detail()))),
    }
}

/// BOOT COMPLETER for attach intents (#72 round 9 finding 3): a crash between the durable
/// intent and the terminal membership write leaves `attach_intent` on the room. Restart
/// validates the seals (receipt + room hashes, identity bindings), then converges FORWARD —
/// re-stamp (idempotent), re-persist the sealed receipt (byte-exact when it already exists),
/// terminal membership write — or, when the run cannot be stamped (its own record never became
/// durable), rolls the intent back to the prior room. Exact reciprocal convergence either way.
pub(crate) fn complete_attach_intents(data_dir: &str) {
    let _guard = ROOM_MUTATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // The TRUSTED storage key is the FILENAME STEM (#72 round 17 finding 1).
    for (room_tail, room) in read_dir_with_stems(data_dir, ROOM_DIR) {
        let Some(intent) = room.get("attach_intent").cloned() else { continue };
        let room_id = format!("outcome-room://{room_tail}");
        let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
        let receipt_id = intent.get("receipt_id").and_then(Value::as_str).unwrap_or("").to_string();
        let updated_room = intent.get("updated_room").cloned().unwrap_or(Value::Null);
        let run_file_id = intent.get("run_file_id").and_then(Value::as_str).unwrap_or("").to_string();
        let room_ref = intent.get("room_ref").and_then(Value::as_str).unwrap_or("").to_string();
        if room_tail.is_empty() || receipt.is_null() || receipt_id.is_empty() || updated_room.is_null() || run_file_id.is_empty() || room_ref.is_empty() {
            eprintln!("outcome-room attach completer: intent on '{room_tail}' fails schema — left in place for manual repair");
            continue;
        }
        // SEMANTIC VALIDATION FIRST (#72 round 15): the sealed updated_room must be the ONLY
        // valid membership successor of the durable prior room (this room minus its
        // attach_intent) — never merely self-consistent. The receipt's exact
        // profile/identity/op/scope is pinned and the successor is reconstructed deterministically.
        if room_ref != room_id {
            eprintln!("outcome-room attach completer: intent room_ref '{room_ref}' does not match '{room_id}' — left in place for manual repair");
            continue;
        }
        let mut prior = room.clone();
        if let Some(obj) = prior.as_object_mut() { obj.remove("attach_intent"); }
        if let Err(why) = validate_attach_intent(&intent, &prior, &room_id, &room_tail) {
            eprintln!("outcome-room attach completer: intent on '{room_tail}' is NOT the canonical membership successor ({why}) — nothing was written (room, receipts, and intent are byte-unchanged); left for manual repair");
            continue;
        }
        // Re-stamp (idempotent merge of the single owned field), DURABLE required. The CAS
        // predicate is SINGULARITY-SAFE (#72 round 10 finding 3): only an absent/null binding
        // or the SAME room may be stamped — the initiation-time check is stale by replay time,
        // and a run bound elsewhere since must never be overwritten.
        let ref_for_stamp = room_ref.clone();
        let ref_for_predicate = room_ref.clone();
        let stamped = super::goalrun_routes::update_goal_run_guarded(
            data_dir,
            &run_file_id,
            move |fresh| match fresh.get("outcome_room_ref").and_then(Value::as_str) {
                None => Ok(()),
                Some(r) if r.is_empty() || r == ref_for_predicate => Ok(()),
                Some(other) => Err((
                    "outcome_room_conflicting_binding".to_string(),
                    format!("the run is already bound to '{other}' — replay never overwrites another room's reciprocal binding"),
                )),
            },
            |obj| {
                obj.insert("outcome_room_ref".into(), json!(ref_for_stamp));
            },
        );
        match stamped {
            Ok(super::goalrun_routes::MutationOutcome::Durable(_)) => {}
            Ok(super::goalrun_routes::MutationOutcome::VisibleUnconfirmed(_, note)) => {
                eprintln!("outcome-room attach completer: stamp for '{run_file_id}' is visible-unconfirmed ({note}) — intent retained, retried next boot");
                continue;
            }
            Err((code, _)) if code == "goal_run_not_found" => {
                // The run's own record never became durable — converge by ROLLING BACK.
                let mut base = room.clone();
                if let Some(obj) = base.as_object_mut() {
                    obj.remove("attach_intent");
                }
                match persist_atomic(data_dir, ROOM_DIR, &room_tail, &base) {
                    Ok(()) => eprintln!("outcome-room attach completer: run '{run_file_id}' no longer exists — the attach intent on '{room_tail}' was rolled back"),
                    Err(f) if f.visible() => eprintln!("outcome-room attach completer: the intent rollback on '{room_tail}' is visible-unconfirmed — converges next boot"),
                    Err(f) => eprintln!("outcome-room attach completer: the intent rollback on '{room_tail}' is {} — retried next boot", f.detail()),
                }
                continue;
            }
            Err((code, msg)) if code == "outcome_room_conflicting_binding" => {
                eprintln!("outcome-room attach completer: CONFLICT on '{room_tail}' — {msg}; the intent is left untouched for manual repair (never overwritten)");
                continue;
            }
            Err((code, msg)) => {
                eprintln!("outcome-room attach completer: stamp for '{run_file_id}' failed ({code}: {msg}) — intent retained, retried next boot");
                continue;
            }
        }
        // Receipt: byte-exact if it exists; else durable persist. The intent's receipt_id is
        // the FILE tail; the record's receipt_id field carries the receipt:// form.
        let sealed_receipt_ref = receipt.get("receipt_id").and_then(Value::as_str).unwrap_or("").to_string();
        let existing = read_record_dir(data_dir, ROOM_RECEIPT_DIR)
            .into_iter()
            .find(|r| r.get("receipt_id").and_then(Value::as_str) == Some(sealed_receipt_ref.as_str()));
        if let Some(existing) = existing {
            if serde_json::to_vec(&existing).unwrap_or_default() != serde_json::to_vec(&receipt).unwrap_or_default() {
                eprintln!("outcome-room attach completer: a DIFFERENT receipt already exists for '{receipt_id}' — conflicting evidence is never overwritten; left for manual repair");
                continue;
            }
        } else if let Err(f) = persist_atomic(data_dir, ROOM_RECEIPT_DIR, &receipt_id, &receipt) {
            eprintln!("outcome-room attach completer: receipt persist for '{room_tail}' is {} — intent retained, retried next boot", f.detail());
            continue;
        }
        // TERMINAL membership write (tolerates visible-unconfirmed — a revert restores the intent).
        match persist_atomic(data_dir, ROOM_DIR, &room_tail, &updated_room) {
            Ok(()) => {}
            Err(f) if f.visible() => {}
            Err(f) => {
                eprintln!("outcome-room attach completer: terminal membership write for '{room_tail}' is {} — intent retained, retried next boot", f.detail());
                continue;
            }
        }
        eprintln!("outcome-room attach completer: converged the interrupted attach on '{room_tail}' (run '{run_file_id}')");
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
    // hosted_admission BINDS a host authority (#72 review finding 1): one named governed domain
    // owns the room's shared-state admission — a hosted room without a host is ungoverned.
    let host_domain = match scalar_ref(body, "host_domain_ref", &["domain"])? {
        Some(h) => h,
        None => return Err(verr("outcome_room_host_domain_required", "`host_domain_ref` (domain://…) is required for hosted_admission — the host domain is the authority that admits every shared-state transition")),
    };
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
        "host_domain_ref": host_domain,
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
            "membership is singular and reciprocal: attach-goal-run stamps GoalRun.outcome_room_ref atomically with the room-side member list, and a run already belonging to any room refuses typed — one GoalRun, at most one room",
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
            "host_domain_ref": record["host_domain_ref"],
            "status_at_admission": "open",
        }),
        vec![json!(room_id), record["owner_or_sponsor_ref"].clone(), record["objective_ref"].clone(), record["host_domain_ref"].clone()],
        record_output_hash(&record, ROOM_HASH_EXCLUDES),
        ROOM_HASH_EXCLUDES,
        "admitted_not_verified",
        ADMISSION_NOTE,
        &now,
    );
    {
        let obj = record.as_object_mut().expect("object");
        obj.insert("admission_receipt_ref".into(), receipt["receipt_ref"].clone());
        obj.insert("admission_and_replay_refs".into(), json!([receipt["receipt_ref"]]));
    }
    if let Err((code, msg)) = finalize_room_create(&st.data_dir, &id_tail, &record, &receipt_id, &receipt) {
        // The refusal CARRIES the room's identity (#72 round 11 finding 2): a 500 retry must be
        // able to recognize that THIS room may still converge at restart instead of blindly
        // creating a second one.
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": { "code": code, "message": msg },
                "outcome_room_ref": record["outcome_room_id"],
                "admission_intent_ref": format!("outcome-room-admission-intent://{id_tail}"),
            })),
        );
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
    // MUTUAL EXCLUSION (#72 round 10 finding 2): a mutation admitted while an intent is in
    // flight would be silently erased when the completer replays the sealed final state.
    if let Some((field, code)) = pending_intent(&prior) {
        return Err(verr(code, format!("a durable {field} is pending on this room — a restart (boot completer) converges it before any other mutation is admitted")));
    }
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
        record_output_hash(&updated, TRANSITION_HASH_EXCLUDES),
        TRANSITION_HASH_EXCLUDES,
        "admitted_not_verified",
        TRANSITION_NOTE,
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
        Err(e) if e.0 == "outcome_room_revision_conflict" || e.0.ends_with("_in_flight") => err(StatusCode::CONFLICT, e),
        Err(e) if e.0.ends_with("_persist_failed") || e.0.ends_with("_pending_convergence") || e.0.ends_with("_durability_unconfirmed") || e.0 == "outcome_room_rollback_failed" => err(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

/// POST /v1/hypervisor/outcome-rooms/:id/attach-goal-run — bind an EXISTING bounded GoalRun (by
/// its CANONICAL goal:// identity) into the room, stamping the reciprocal
/// `GoalRun.outcome_room_ref` in the SAME atomic finalization. A run already belonging to ANY
/// room refuses typed — singular room identity (#72 review finding 2).
pub(crate) async fn handle_outcome_room_attach_goal_run(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let err = |status: StatusCode, (code, msg): VErr| (status, Json(json!({ "error": { "code": code, "message": msg } })));
    if let Err(e) = reject_sensitive_keys(&body, "") {
        return err(StatusCode::BAD_REQUEST, e);
    }
    // Canonical identity in, canonical identity stored: goal://<goal_run_id>.
    let goal_run_canonical = match str_opt_bounded(&body, "goal_run_ref", REF_MAX) {
        Ok(Some(g)) if ref_scheme_ok(&g, &["goal"]) => g,
        Ok(Some(_)) => return err(StatusCode::BAD_REQUEST, verr("outcome_room_goal_run_ref_invalid", "`goal_run_ref` must be the run's canonical goal:// identity (goal://gr_…) — a raw route id is never a ref")),
        Ok(None) => return err(StatusCode::BAD_REQUEST, verr("outcome_room_goal_run_required", "`goal_run_ref` is required (the run's canonical goal:// identity)")),
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    let run_file_id = goal_run_canonical.strip_prefix("goal://").unwrap_or("").to_string();
    let room_id = format!("outcome-room://{id}");
    // ROOM-SCOPE critical section: resolution through finalization under the one room lock.
    let _guard = ROOM_MUTATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let Some(prior_run) = read_record_dir(&st.data_dir, GOAL_RUN_DIR)
        .into_iter()
        .find(|r| r.get("goal_run_id").and_then(|v| v.as_str()) == Some(run_file_id.as_str())) else {
        return err(StatusCode::BAD_REQUEST, verr("outcome_room_goal_run_unbound", format!("`goal_run_ref` does not resolve to an admitted GoalRun ('{goal_run_canonical}') — the aggregate binds only real bounded runs")));
    };
    // SINGULAR ROOM IDENTITY: a run already in ANY room (this one included) refuses typed.
    if let Some(existing) = prior_run.get("outcome_room_ref").and_then(|v| v.as_str()) {
        if !existing.is_empty() {
            return err(StatusCode::BAD_REQUEST, verr("outcome_room_goal_run_already_member", format!("GoalRun '{goal_run_canonical}' already belongs to '{existing}' — a run has at most ONE room; contradictory multi-room state is never created")));
        }
    }
    let Some(prior_room) = load_room(&st.data_dir, &room_id) else {
        return err(StatusCode::NOT_FOUND, verr("outcome_room_not_found", format!("no admitted room '{room_id}'")));
    };
    if let Some((field, code)) = pending_intent(&prior_room) {
        return err(StatusCode::CONFLICT, verr(code, format!("a durable {field} is pending on this room — a restart (boot completer) converges it before new membership is admitted")));
    }
    let current_rev = prior_room.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
    if let Err(e) = check_expected_revision(&body, current_rev) {
        return if e.0 == "outcome_room_revision_conflict" { err(StatusCode::CONFLICT, e) } else { err(StatusCode::BAD_REQUEST, e) };
    }
    if s(&prior_room, "status", "") != "open" {
        return err(StatusCode::BAD_REQUEST, verr("outcome_room_not_open", format!("membership changes are admitted only on an `open` room (status is '{}')", s(&prior_room, "status", ""))));
    }
    let members: Vec<String> = prior_room.get("member_goal_run_refs").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    if members.iter().any(|m| m == &goal_run_canonical) {
        return err(StatusCode::BAD_REQUEST, verr("outcome_room_goal_run_duplicate", format!("GoalRun '{goal_run_canonical}' is already a member — attachment is idempotent-refusing, never double-registered")));
    }
    let now = iso_now();
    let mut updated_room = prior_room.clone();
    {
        let obj = updated_room.as_object_mut().expect("room is an object");
        let mut arr: Vec<Value> = members.iter().cloned().map(Value::String).collect();
        arr.push(json!(goal_run_canonical));
        obj.insert("member_goal_run_refs".into(), Value::Array(arr));
        obj.insert("revision".into(), json!(current_rev + 1));
        obj.insert("updated_at".into(), json!(now));
    }
    let member_count = members.len() + 1;
    let (receipt_id, receipt) = build_room_receipt(
        TRANSITION_RECEIPT_SCHEMA, "OutcomeRoomTransitionReceipt", "ort", &room_id, "goal_run_attached",
        json!({ "goal_run_ref": goal_run_canonical, "reciprocal_outcome_room_ref_stamped": true, "member_count_after": member_count, "revision_before": current_rev, "revision_after": current_rev + 1 }),
        vec![json!(room_id), json!(goal_run_canonical)],
        record_output_hash(&updated_room, TRANSITION_HASH_EXCLUDES),
        TRANSITION_HASH_EXCLUDES,
        "admitted_not_verified",
        ATTACH_NOTE,
        &now,
    );
    {
        let obj = updated_room.as_object_mut().expect("object");
        let mut trail: Vec<Value> = obj.get("admission_and_replay_refs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        trail.push(receipt["receipt_ref"].clone());
        obj.insert("admission_and_replay_refs".into(), Value::Array(trail));
        let mut history: Vec<Value> = obj.get("status_history").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        history.push(json!({ "op": "goal_run_attached", "at": now, "receipt_ref": receipt["receipt_ref"], "revision": current_rev + 1 }));
        if history.len() > HISTORY_MAX { let drop_n = history.len() - HISTORY_MAX; history.drain(0..drop_n); }
        obj.insert("status_history".into(), Value::Array(history));
    }
    let _ = &prior_run; // resolved above for the already-member check; the seam re-reads fresh
    if let Err((code, msg)) = finalize_attach(&st.data_dir, &id, &prior_room, &updated_room, &run_file_id, &room_id, &receipt_id, &receipt) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": { "code": code, "message": msg } })));
    }
    (StatusCode::OK, Json(json!({ "outcome_room": updated_room, "outcome_room_receipt": receipt, "goal_run_stamped": { "goal_run_ref": goal_run_canonical, "outcome_room_ref": room_id } })))
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
            "conflict_and_failover_policy_ref": "policy://host-failover",
            "host_domain_ref": "domain://acme-host"
        })
    }

    // CANONICAL fixtures built from the PRODUCTION construction paths (#72 round 15): the
    // semantic replay validators now accept ONLY the deterministic successor, so completer
    // fixtures must be byte-identical to what the finalizers seal — never hand-crafted.
    fn canonical_admission(room_tail: &str) -> (Value, Value, String, Value) {
        let room_id = format!("outcome-room://{room_tail}");
        let mut record = validate_room_create(&valid_room_body()).unwrap();
        record["outcome_room_id"] = json!(room_id);
        record["created_at"] = json!("2026-01-01T00:00:00Z");
        record["updated_at"] = json!("2026-01-01T00:00:00Z");
        let (rid, receipt) = build_room_receipt(
            ADMISSION_RECEIPT_SCHEMA, "OutcomeRoomAdmissionReceipt", "orr", &room_id, "admitted",
            json!({ "room_mode": record["room_mode"], "coordination_topology": record["coordination_topology"], "owner_or_sponsor_ref": record["owner_or_sponsor_ref"], "objective_ref": record["objective_ref"], "host_domain_ref": record["host_domain_ref"], "status_at_admission": "open" }),
            vec![json!(room_id), record["owner_or_sponsor_ref"].clone(), record["objective_ref"].clone(), record["host_domain_ref"].clone()],
            record_output_hash(&record, ROOM_HASH_EXCLUDES), ROOM_HASH_EXCLUDES, "admitted_not_verified", ADMISSION_NOTE, "2026-01-01T00:00:00Z",
        );
        record["admission_receipt_ref"] = receipt["receipt_ref"].clone();
        record["admission_and_replay_refs"] = json!([receipt["receipt_ref"]]);
        let intent = json!({
            "room_tail": room_tail, "room_ref": room_id,
            "receipt_id": rid, "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "final_room": record, "final_room_hash": record_output_hash(&record, &[]), "at": "2026-01-01T00:00:00Z",
        });
        (intent, record, rid, receipt)
    }

    // A canonical transition successor built exactly as mutate_room would (op in TRANSITIONS).
    fn canonical_transition(prior: &Value, op: &str) -> (Value, Value, String, Value) {
        let room_id = prior["outcome_room_id"].as_str().unwrap().to_string();
        let to = TRANSITIONS.iter().find(|(t, _, _)| *t == op).unwrap().2;
        let rev = prior["revision"].as_u64().unwrap();
        let now = "2026-06-06T00:00:00Z";
        let mut updated = prior.clone();
        updated.as_object_mut().unwrap().insert("status".into(), json!(to));
        updated.as_object_mut().unwrap().insert("revision".into(), json!(rev + 1));
        updated.as_object_mut().unwrap().insert("updated_at".into(), json!(now));
        let from = prior["status"].as_str().unwrap();
        let (rid, receipt) = build_room_receipt(
            TRANSITION_RECEIPT_SCHEMA, "OutcomeRoomTransitionReceipt", "ort", &room_id, op,
            json!({ "transition": op, "from": from, "to": to, "revision_before": rev, "revision_after": rev + 1 }), vec![json!(room_id)],
            record_output_hash(&updated, TRANSITION_HASH_EXCLUDES), TRANSITION_HASH_EXCLUDES, "admitted_not_verified", TRANSITION_NOTE, now,
        );
        {
            let obj = updated.as_object_mut().unwrap();
            let mut trail: Vec<Value> = obj.get("admission_and_replay_refs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            trail.push(receipt["receipt_ref"].clone());
            obj.insert("admission_and_replay_refs".into(), Value::Array(trail));
            let mut hist: Vec<Value> = obj.get("status_history").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            hist.push(json!({ "op": op, "at": now, "receipt_ref": receipt["receipt_ref"], "revision": rev + 1 }));
            obj.insert("status_history".into(), Value::Array(hist));
        }
        let intent = json!({
            "receipt_id": rid, "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "final_room": updated, "final_room_hash": record_output_hash(&updated, &[]), "at": now,
        });
        (intent, updated, rid, receipt)
    }

    // A canonical membership successor built exactly as the attach handler would.
    fn canonical_attach(prior: &Value, run_file_id: &str) -> (Value, Value, String, Value) {
        let room_id = prior["outcome_room_id"].as_str().unwrap().to_string();
        let rev = prior["revision"].as_u64().unwrap();
        let now = "2026-06-06T00:00:00Z";
        let member = format!("goal://{run_file_id}");
        let mut members: Vec<Value> = prior.get("member_goal_run_refs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        members.push(json!(member));
        let mut updated = prior.clone();
        updated.as_object_mut().unwrap().insert("member_goal_run_refs".into(), Value::Array(members));
        updated.as_object_mut().unwrap().insert("revision".into(), json!(rev + 1));
        updated.as_object_mut().unwrap().insert("updated_at".into(), json!(now));
        let (rid, receipt) = build_room_receipt(
            TRANSITION_RECEIPT_SCHEMA, "OutcomeRoomTransitionReceipt", "ort", &room_id, "goal_run_attached",
            json!({ "goal_run_ref": member, "reciprocal_outcome_room_ref_stamped": true, "member_count_after": prior.get("member_goal_run_refs").and_then(|v| v.as_array()).map(|a| a.len() + 1).unwrap_or(1), "revision_before": rev, "revision_after": rev + 1 }),
            vec![json!(room_id), json!(member)],
            record_output_hash(&updated, TRANSITION_HASH_EXCLUDES), TRANSITION_HASH_EXCLUDES, "admitted_not_verified", ATTACH_NOTE, now,
        );
        {
            let obj = updated.as_object_mut().unwrap();
            let mut trail: Vec<Value> = obj.get("admission_and_replay_refs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            trail.push(receipt["receipt_ref"].clone());
            obj.insert("admission_and_replay_refs".into(), Value::Array(trail));
            let mut hist: Vec<Value> = obj.get("status_history").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            hist.push(json!({ "op": "goal_run_attached", "at": now, "receipt_ref": receipt["receipt_ref"], "revision": rev + 1 }));
            obj.insert("status_history".into(), Value::Array(hist));
        }
        let intent = json!({
            "run_file_id": run_file_id, "room_ref": room_id,
            "receipt_id": rid, "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "updated_room": updated, "updated_room_hash": record_output_hash(&updated, &[]), "at": now,
        });
        (intent, updated, rid, receipt)
    }

    #[test]
    fn creation_is_fail_closed_typed_and_hosted_only() {
        let rec = validate_room_create(&valid_room_body()).unwrap();
        assert_eq!(rec["status"], json!("open"));
        assert_eq!(rec["revision"], json!(1));
        assert_eq!(rec["member_goal_run_refs"], json!([]));
        assert_eq!(rec["participant_lease_refs"], json!([]));
        let cases: Vec<(&str, Value, &str)> = vec![
            ("host_domain_ref", Value::Null, "outcome_room_host_domain_required"),
            ("host_domain_ref", json!("not-a-ref"), "outcome_room_ref_scheme_invalid"),
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
        persist_atomic(data_dir, ROOM_DIR, "or_1", &room).unwrap();
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
        // The hash recomputes from the persisted record minus the receipt's OWN declared
        // excludes — the TRANSITION scope, which includes the resulting status/revision.
        let persisted = load_room(data_dir, "outcome-room://or_1").unwrap();
        assert_eq!(s(&receipt, "output_hash", ""), record_output_hash(&persisted, TRANSITION_HASH_EXCLUDES));
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
        persist_atomic(data_dir, ROOM_DIR, "or_1", &room).unwrap();
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
        assert!(persist_atomic(data_dir, ROOM_DIR, "or_block", &json!({})).is_err());
        let tmp_leaks: Vec<String> = std::fs::read_dir(&record_dir).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(tmp_leaks.is_empty(), "no temporary artifact survives: {tmp_leaks:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_hashes_are_distinct_and_cover_the_output_state() {
        // #72 finding 4: the transition hash INCLUDES status/revision/membership — pause and
        // resume over the same room MUST emit different hashes (and differ from admission's
        // declaration hash scope).
        let base = json!({ "outcome_room_id": "outcome-room://or_h", "status": "open", "revision": 1, "member_goal_run_refs": [], "objective": "x", "updated_at": "2026-01-01T00:00:00Z" });
        let mut paused = base.clone();
        paused["status"] = json!("paused"); paused["revision"] = json!(2);
        let mut resumed = base.clone();
        resumed["status"] = json!("open"); resumed["revision"] = json!(3);
        let h_admit = record_output_hash(&base, ROOM_HASH_EXCLUDES);
        let h_pause = record_output_hash(&paused, TRANSITION_HASH_EXCLUDES);
        let h_resume = record_output_hash(&resumed, TRANSITION_HASH_EXCLUDES);
        assert_ne!(h_pause, h_resume, "distinct output states hash distinctly");
        assert_ne!(h_pause, h_admit, "the transition hash is not the static declaration hash");
        // Membership changes the hash too.
        let mut member = resumed.clone();
        member["member_goal_run_refs"] = json!(["goal://gr_1"]);
        assert_ne!(record_output_hash(&member, TRANSITION_HASH_EXCLUDES), h_resume);
    }

    #[test]
    fn attach_receipt_failure_keeps_the_intent_and_the_boot_completer_converges() {
        // #72 round 9 finding 3: a receipt failure AFTER the durable intent + durable stamp
        // refuses typed with the intent retained — no unstamp, no deletion — and the boot
        // completer converges the attach to exact reciprocal equality.
        let dir = temp_dir("attach");
        let data_dir = dir.to_str().unwrap();
        let (_ai, prior_room, _arid, _arcpt) = canonical_admission("or_1");
        let prior_run = json!({ "goal_run_id": "gr_1", "normalized_goal": "x", "status": "active" });
        persist_atomic(data_dir, ROOM_DIR, "or_1", &prior_room).unwrap();
        persist_atomic(data_dir, GOAL_RUN_DIR, "gr_1", &prior_run).unwrap();
        let (_intent, updated_room, rid, receipt) = canonical_attach(&prior_room, "gr_1");
        std::fs::write(dir.join(ROOM_RECEIPT_DIR), b"blocker").unwrap();
        let (code, _) = finalize_attach(data_dir, "or_1", &prior_room, &updated_room, "gr_1", "outcome-room://or_1", &rid, &receipt).unwrap_err();
        assert_eq!(code, "outcome_room_attach_pending_convergence");
        let room_after = load_room(data_dir, "outcome-room://or_1").unwrap();
        assert!(room_after.get("attach_intent").is_some(), "the DURABLE intent is retained for replay");
        assert_eq!(room_after["member_goal_run_refs"], json!([]), "membership is still pending (terminal write never ran)");
        let run_after = read_record_dir(data_dir, GOAL_RUN_DIR).pop().unwrap();
        assert_eq!(run_after["outcome_room_ref"], json!("outcome-room://or_1"), "the durable stamp STAYS — no unstamp, no split-brain");
        // Restart: the completer re-persists the sealed receipt and finishes the membership.
        std::fs::remove_file(dir.join(ROOM_RECEIPT_DIR)).unwrap();
        complete_attach_intents(data_dir);
        let converged = load_room(data_dir, "outcome-room://or_1").unwrap();
        assert_eq!(converged["member_goal_run_refs"], json!(["goal://gr_1"]), "membership converged");
        assert!(converged.get("attach_intent").is_none(), "the intent was consumed by the terminal write");
        assert_eq!(read_record_dir(data_dir, GOAL_RUN_DIR).pop().unwrap()["outcome_room_ref"], json!("outcome-room://or_1"), "EXACT reciprocal convergence: member ⇔ stamp");
        let persisted_receipt = read_record_dir(data_dir, ROOM_RECEIPT_DIR).into_iter().find(|r| r["receipt_id"] == receipt["receipt_id"]).expect("the sealed receipt was persisted");
        assert_eq!(persisted_receipt["receipt_id"], receipt["receipt_id"]);
        // Idempotent: a second boot pass changes nothing.
        complete_attach_intents(data_dir);
        assert_eq!(load_room(data_dir, "outcome-room://or_1").unwrap()["member_goal_run_refs"], json!(["goal://gr_1"]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_intent_completer_applies_the_sealed_final_state() {
        // #72 round 10 finding 1: a transition interrupted after its durable intent converges
        // at boot — sealed receipt persisted, sealed final room applied, intent consumed.
        let dir = temp_dir("transition-intent");
        let data_dir = dir.to_str().unwrap();
        let (_ai, prior, _arid, _arcpt) = canonical_admission("or_71");
        let (tintent, _final_room, _rid, _rcpt) = canonical_transition(&prior, "pause");
        let mut pending = prior.clone();
        pending["transition_intent"] = tintent;
        persist_atomic(data_dir, ROOM_DIR, "or_71", &pending).unwrap();
        complete_room_intents(data_dir);
        let converged = load_room(data_dir, "outcome-room://or_71").unwrap();
        assert_eq!(converged["status"], json!("paused"), "the sealed transition was applied");
        assert_eq!(converged["revision"], json!(2));
        assert!(converged.get("transition_intent").is_none(), "the intent was consumed");
        assert_eq!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).len(), 1, "the sealed receipt was persisted");
        // Idempotent second boot.
        complete_room_intents(data_dir);
        assert_eq!(load_room(data_dir, "outcome-room://or_71").unwrap()["status"], json!("paused"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_intent_family_converges_without_a_public_pending_status() {
        // #72 round 11 finding 2: a pending admission lives in the INTERNAL intent family — the
        // registry never lists it — and the boot completer admits the sealed room with its
        // receipt; a conflicting existing room is never overwritten.
        let dir = temp_dir("admission-intent");
        let data_dir = dir.to_str().unwrap();
        let (intent, _final_room, _rid, _rcpt) = canonical_admission("or_72");
        persist_atomic(data_dir, ADMISSION_INTENT_DIR, "or_72", &intent).unwrap();
        assert!(load_room(data_dir, "outcome-room://or_72").is_none(), "the registry never lists a pending admission");
        complete_room_intents(data_dir);
        let admitted = load_room(data_dir, "outcome-room://or_72").expect("admitted at boot");
        assert_eq!(admitted["status"], json!("open"), "the sealed CANONICAL status — no pending_admission enum ever existed");
        assert_eq!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).len(), 1, "the sealed receipt was persisted");
        assert!(read_record_dir(data_dir, ADMISSION_INTENT_DIR).is_empty(), "the consumed intent was dropped");
        // CONFLICT-FIRST (#72 round 12 finding 2): a FOREIGN room at the same identity (a
        // DIFFERENT canonical admission, different anchor) refuses BEFORE any write — room,
        // receipt family, and intent stay byte-for-byte unchanged, incl. the intent's receipt.
        let (other, _fr, _rid2, _rcpt2) = canonical_admission("or_72");
        persist_atomic(data_dir, ADMISSION_INTENT_DIR, "or_72", &other).unwrap();
        let receipts_before = read_record_dir(data_dir, ROOM_RECEIPT_DIR).len();
        complete_room_intents(data_dir);
        let still = load_room(data_dir, "outcome-room://or_72").unwrap();
        assert_eq!(still["admission_receipt_ref"], admitted["admission_receipt_ref"], "the ORIGINAL admission stands — the foreign intent did not overwrite it");
        assert_eq!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).len(), receipts_before, "NO receipt was persisted for the room the completer refused to admit (#72 r12 finding 2)");
        assert_eq!(read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(), 1, "the conflicting intent is retained for manual repair");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_completer_recognizes_its_own_later_mutated_room_by_anchor() {
        // #72 round 12 finding 1 corollary: a retained intent whose room already reached the
        // registry — and was then legitimately transitioned — is recognized by its admission
        // ANCHOR (first trail entry) and consumed without overwriting the newer state.
        let dir = temp_dir("admission-anchor");
        let data_dir = dir.to_str().unwrap();
        let (intent, final_room, rid, receipt) = canonical_admission("or_a2");
        persist_atomic(data_dir, ADMISSION_INTENT_DIR, "or_a2", &intent).unwrap();
        // The room already converged AND was later legitimately PAUSED (same anchor, newer
        // content — only hash-excluded fields changed, so the declaration still proves the
        // admission). The pause is a real canonical transition applied to the admitted room.
        let (_ti, mutated, _prid, _prcpt) = canonical_transition(&final_room, "pause");
        persist_atomic(data_dir, ROOM_DIR, "or_a2", &mutated).unwrap();
        persist_atomic(data_dir, ROOM_RECEIPT_DIR, &rid, &receipt).unwrap();
        complete_room_intents(data_dir);
        let room = load_room(data_dir, "outcome-room://or_a2").unwrap();
        assert_eq!(room["status"], json!("paused"), "the newer legitimate state is NOT overwritten by the replay");
        assert!(read_record_dir(data_dir, ADMISSION_INTENT_DIR).is_empty(), "the intent was recognized as consumed and dropped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_replay_binds_the_storage_key_to_the_room_identity() {
        // #72 round 17 finding 1: an intent whose sealed room claims a DIFFERENT outcome_room_id
        // than its filename stem is refused — the storage key is the trusted identity.
        let dir = temp_dir("stem-binding");
        let data_dir = dir.to_str().unwrap();
        let (intent, _room, _rid, _rcpt) = canonical_admission("or_80");
        // The intent is canonical for stem or_80, but we persist it at file or_81.json.
        persist_atomic(data_dir, ADMISSION_INTENT_DIR, "or_81", &intent).unwrap();
        complete_room_intents(data_dir);
        assert!(load_room_file(data_dir, "or_81").is_none(), "the mismatched-stem intent was NOT admitted");
        assert!(load_room_file(data_dir, "or_80").is_none(), "and nothing was written under the content id either");
        assert!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(), "no receipt persisted");
        assert_eq!(read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(), 1, "intent retained for manual repair");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_atomic_rejects_a_normalization_unsafe_key() {
        // #72 round 17 finding 2: `ort/collision` and `ort_collision` would normalize to the same
        // file — the room writer rejects unsafe keys instead of colliding.
        let dir = temp_dir("norm-safe");
        let data_dir = dir.to_str().unwrap();
        persist_atomic(data_dir, ROOM_RECEIPT_DIR, "ort_deadbeef", &json!({ "ok": true })).unwrap();
        let err = persist_atomic(data_dir, ROOM_RECEIPT_DIR, "ort/collision", &json!({ "evil": true })).unwrap_err();
        assert!(matches!(err, super::super::goalrun_routes::PersistFailure::NotCommitted(_)));
        // The canonical file is untouched; no collided file was written.
        assert_eq!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_replay_refuses_non_rfc3339_timestamps() {
        // #72 round 17 finding 3: a room with null/empty timestamps production could never emit
        // is refused (the reconstruction no longer coerces null → "").
        let dir = temp_dir("ts");
        let data_dir = dir.to_str().unwrap();
        let (canonical, _room, _rid, _rcpt) = canonical_admission("or_82");
        let mut final_room = canonical["final_room"].clone();
        final_room["created_at"] = Value::Null;
        final_room["updated_at"] = Value::Null;
        // Reseal so only the timestamp validation stands between the forgery and admission.
        let receipt = canonical["receipt"].clone();
        let forged = json!({
            "room_tail": "or_82", "room_ref": "outcome-room://or_82",
            "receipt_id": canonical["receipt_id"], "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "final_room": final_room, "final_room_hash": record_output_hash(&final_room, &[]), "at": "2026-01-01T00:00:00Z",
        });
        persist_atomic(data_dir, ADMISSION_INTENT_DIR, "or_82", &forged).unwrap();
        complete_room_intents(data_dir);
        assert!(load_room_file(data_dir, "or_82").is_none(), "a null-timestamp room was NOT admitted");
        assert!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(), "no receipt persisted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_replay_refuses_a_hollow_ungoverned_envelope() {
        // #72 round 16 finding 1: a room with NO owner/objective/host/mode/topology/policy refs
        // must be REFUSED — reconstruction through validate_room_create rejects the missing
        // required fields (they can never compare as matching facts via None == None).
        let dir = temp_dir("hollow-admission");
        let data_dir = dir.to_str().unwrap();
        let (canonical, _room, _rid, _rcpt) = canonical_admission("or_73");
        // Strip the governing declaration from the sealed room; reseal the intent hashes so ONLY
        // the semantic reconstruction stands between the hollow envelope and admission.
        let mut final_room = canonical["final_room"].clone();
        for k in ["owner_or_sponsor_ref", "objective_ref", "objective", "host_domain_ref", "room_mode", "coordination_topology", "stop_policy_ref", "visibility_policy_ref", "participation_policy_ref", "privacy_policy_ref", "contribution_policy_ref", "coordination_policy_ref", "ordering_and_merge_policy_ref", "conflict_and_failover_policy_ref"] {
            final_room.as_object_mut().unwrap().remove(k);
        }
        let receipt = canonical["receipt"].clone();
        let hollow = json!({
            "room_tail": "or_73", "room_ref": "outcome-room://or_73",
            "receipt_id": canonical["receipt_id"], "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "final_room": final_room, "final_room_hash": record_output_hash(&final_room, &[]), "at": "2026-01-01T00:00:00Z",
        });
        persist_atomic(data_dir, ADMISSION_INTENT_DIR, "or_73", &hollow).unwrap();
        complete_room_intents(data_dir);
        assert!(load_room(data_dir, "outcome-room://or_73").is_none(), "the hollow envelope was NOT admitted");
        assert!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(), "no receipt persisted for a hollow envelope");
        assert_eq!(read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(), 1, "intent retained for manual repair");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_replay_refuses_a_truthful_successor_with_a_lying_receipt() {
        // #72 round 16 finding 2: the room successor is the CORRECT deterministic pause, but the
        // sealed receipt lies (wrong op/from/to/boundary/posture). The reconstructed receipt
        // must not match — refused byte-unchanged, no durable false evidence.
        let dir = temp_dir("lying-transition");
        let data_dir = dir.to_str().unwrap();
        let (_ai, prior, _arid, _arcpt) = canonical_admission("or_74");
        let (tintent, _final, _rid, _rcpt) = canonical_transition(&prior, "pause");
        // Keep the TRUTHFUL successor room; forge ONLY the receipt's attested facts.
        let mut forged_intent = tintent.clone();
        let mut lying = forged_intent["receipt"].clone();
        lying["bound_facts"] = json!({ "transition": "archive", "from": "accepted", "to": "settled", "revision_before": 900, "revision_after": 901 });
        lying["attested_boundary_fact_refs"] = json!(["outcome-room://some-other-room"]);
        lying["assurance_posture"] = json!("forged_assurance");
        forged_intent["receipt"] = lying.clone();
        forged_intent["receipt_hash"] = json!(record_output_hash(&lying, &[]));
        let mut pending = prior.clone();
        pending["transition_intent"] = forged_intent;
        let pending_bytes = serde_json::to_vec(&pending).unwrap();
        persist_atomic(data_dir, ROOM_DIR, "or_74", &pending).unwrap();
        complete_room_intents(data_dir);
        let after = load_room(data_dir, "outcome-room://or_74").unwrap();
        assert_eq!(serde_json::to_vec(&after).unwrap(), pending_bytes, "room byte-unchanged — the lying receipt never became durable");
        assert_eq!(after["status"], json!("open"), "status never advanced");
        assert!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(), "no false receipt persisted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attach_replay_refuses_a_truthful_membership_with_a_lying_receipt() {
        // #72 round 16 finding 2: the membership successor is correct, but the attach receipt
        // lies about the run and reciprocal-stamp facts. Refused — run never stamped, no receipt.
        let dir = temp_dir("lying-attach");
        let data_dir = dir.to_str().unwrap();
        let (_ai, prior, _arid, _arcpt) = canonical_admission("or_75");
        persist_atomic(data_dir, GOAL_RUN_DIR, "gr_la", &json!({ "goal_run_id": "gr_la", "status": "active" })).unwrap();
        let (aintent, _updated, _rid, _rcpt) = canonical_attach(&prior, "gr_la");
        let mut forged_intent = aintent.clone();
        let mut lying = forged_intent["receipt"].clone();
        lying["bound_facts"] = json!({ "goal_run_ref": "goal://gr_smuggled", "reciprocal_outcome_room_ref_stamped": false, "member_count_after": 99, "revision_before": 5, "revision_after": 6 });
        lying["assurance_posture"] = json!("forged_assurance");
        forged_intent["receipt"] = lying.clone();
        forged_intent["receipt_hash"] = json!(record_output_hash(&lying, &[]));
        let mut with_intent = prior.clone();
        with_intent["attach_intent"] = forged_intent;
        let with_bytes = serde_json::to_vec(&with_intent).unwrap();
        persist_atomic(data_dir, ROOM_DIR, "or_75", &with_intent).unwrap();
        complete_attach_intents(data_dir);
        let after = load_room(data_dir, "outcome-room://or_75").unwrap();
        assert_eq!(serde_json::to_vec(&after).unwrap(), with_bytes, "room byte-unchanged");
        let run = read_record_dir(data_dir, GOAL_RUN_DIR).pop().unwrap();
        assert!(run.get("outcome_room_ref").is_none(), "the run was NEVER stamped for a lying attach receipt");
        assert!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(), "no false receipt persisted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_replay_refuses_a_forged_intent_when_the_room_is_ABSENT() {
        // #72 round 15 finding 1 — the reviewer's exact bypass: in the NORMAL missing-room
        // recovery state (no existing room), a forged intent (wrong schema/op/scope/declaration)
        // must be refused by the FULL semantic validator, not admitted unvalidated.
        let dir = temp_dir("forged-admission-absent");
        let data_dir = dir.to_str().unwrap();
        let (canonical, _room, _rid, _rcpt) = canonical_admission("or_fa");
        // Forge the sealed room + receipt: wrong op, widened scope, forged declaration. Reseal
        // the intent hashes so ONLY the semantic validator (not the self-consistency check)
        // stands between the forgery and admission.
        let mut receipt = canonical["receipt"].clone();
        let mut final_room = canonical["final_room"].clone();
        final_room["objective"] = json!("FORGED");
        final_room["owner_or_sponsor_ref"] = json!("org://attacker");
        receipt["op"] = json!("not-admitted");
        receipt["hash_scope_excludes"] = json!(ROOM_HASH_EXCLUDES.iter().copied().chain(["objective", "owner_or_sponsor_ref"]).collect::<Vec<_>>());
        receipt["output_hash"] = json!(record_output_hash(&final_room, &ROOM_HASH_EXCLUDES.iter().copied().chain(["objective", "owner_or_sponsor_ref"]).collect::<Vec<_>>()));
        let forged = json!({
            "room_tail": "or_fa", "room_ref": "outcome-room://or_fa",
            "receipt_id": canonical["receipt_id"], "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "final_room": final_room, "final_room_hash": record_output_hash(&final_room, &[]), "at": "2026-01-01T00:00:00Z",
        });
        persist_atomic(data_dir, ADMISSION_INTENT_DIR, "or_fa", &forged).unwrap();
        assert!(load_room(data_dir, "outcome-room://or_fa").is_none(), "the room is ABSENT — the normal recovery state");
        complete_room_intents(data_dir);
        assert!(load_room(data_dir, "outcome-room://or_fa").is_none(), "the forged room was NOT admitted");
        assert!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(), "no receipt was persisted for the forgery");
        assert_eq!(read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(), 1, "the intent is retained for manual repair");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_replay_refuses_a_forged_successor() {
        // #72 round 15 finding 2 — a forged transition intent (illegal status, bumped revision,
        // altered declaration) is NOT the deterministic successor of the durable prior; refused.
        let dir = temp_dir("forged-transition");
        let data_dir = dir.to_str().unwrap();
        let (_ai, prior, _arid, _arcpt) = canonical_admission("or_76");
        let (tintent, _updated, _rid, _rcpt) = canonical_transition(&prior, "pause");
        // Forge the sealed final_room: illegal status "accepted", revision 99, altered owner.
        let mut forged_intent = tintent.clone();
        let mut forged_room = forged_intent["final_room"].clone();
        forged_room["status"] = json!("accepted");
        forged_room["revision"] = json!(99);
        forged_room["owner_or_sponsor_ref"] = json!("org://attacker");
        forged_intent["final_room"] = forged_room.clone();
        forged_intent["final_room_hash"] = json!(record_output_hash(&forged_room, &[]));
        let mut pending = prior.clone();
        pending["transition_intent"] = forged_intent;
        let pending_bytes = serde_json::to_vec(&pending).unwrap();
        persist_atomic(data_dir, ROOM_DIR, "or_76", &pending).unwrap();
        complete_room_intents(data_dir);
        let after = load_room(data_dir, "outcome-room://or_76").unwrap();
        assert_eq!(serde_json::to_vec(&after).unwrap(), pending_bytes, "the room (still carrying the forged intent) is byte-for-byte unchanged — the forgery was NOT applied");
        assert_eq!(after["status"], json!("open"), "the visible status never advanced to the forged 'accepted'");
        assert!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(), "no receipt was persisted for the forged transition");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attach_replay_refuses_a_forged_membership_successor() {
        // #72 round 15 finding 2 — a forged attach intent whose updated_room is not the
        // deterministic membership successor (extra members, altered declaration, bumped
        // revision) is refused; the run is never stamped and nothing is written.
        let dir = temp_dir("forged-attach");
        let data_dir = dir.to_str().unwrap();
        let (_ai, prior, _arid, _arcpt) = canonical_admission("or_77");
        persist_atomic(data_dir, GOAL_RUN_DIR, "gr_fm", &json!({ "goal_run_id": "gr_fm", "status": "active" })).unwrap();
        let (aintent, _updated, _rid, _rcpt) = canonical_attach(&prior, "gr_fm");
        let mut forged_intent = aintent.clone();
        let mut forged_room = forged_intent["updated_room"].clone();
        forged_room["member_goal_run_refs"] = json!(["goal://gr_fm", "goal://gr_smuggled"]);
        forged_room["revision"] = json!(42);
        forged_intent["updated_room"] = forged_room.clone();
        forged_intent["updated_room_hash"] = json!(record_output_hash(&forged_room, &[]));
        let mut with_intent = prior.clone();
        with_intent["attach_intent"] = forged_intent;
        persist_atomic(data_dir, ROOM_DIR, "or_77", &with_intent).unwrap();
        complete_attach_intents(data_dir);
        let after = load_room(data_dir, "outcome-room://or_77").unwrap();
        assert!(after.get("attach_intent").is_some(), "the forged intent is retained (refused, not applied)");
        assert_eq!(after["member_goal_run_refs"], json!([]), "no membership was manufactured");
        let run = read_record_dir(data_dir, GOAL_RUN_DIR).pop().unwrap();
        assert!(run.get("outcome_room_ref").is_none(), "the run was NEVER stamped for a forged successor");
        assert!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(), "no receipt was persisted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_replay_refuses_a_widened_hash_scope_that_hides_tampering() {
        // #72 round 14 — the reviewer's exact bypass: a malformed intent widens the receipt's
        // hash_scope_excludes to also exclude `objective` + `owner_or_sponsor_ref`, then a
        // tampered room recomputes to the receipt's output_hash under THAT widened scope. The
        // completer must recompute under the CONSTANT ROOM_HASH_EXCLUDES and require the
        // receipt's declared scope to equal it exactly — so the forgery refuses byte-unchanged.
        let dir = temp_dir("admission-scope");
        let data_dir = dir.to_str().unwrap();
        // The room the attacker WANTS admitted (tampered declaration).
        let mut tampered = json!({ "outcome_room_id": "outcome-room://or_78", "objective": "TAMPERED", "owner_or_sponsor_ref": "org://attacker", "status": "open", "revision": 1, "member_goal_run_refs": [], "updated_at": "2026-01-01T00:00:00Z" });
        // A WIDENED scope that also excludes the tampered declaration fields.
        let widened: Vec<&str> = ROOM_HASH_EXCLUDES.iter().copied().chain(["objective", "owner_or_sponsor_ref"]).collect();
        // The receipt's output_hash is computed over the tampered room under the WIDENED scope,
        // so declaration_ok would pass if the completer trusted the receipt's own scope.
        let (rid, mut receipt) = build_room_receipt(ADMISSION_RECEIPT_SCHEMA, "OutcomeRoomAdmissionReceipt", "orr", "outcome-room://or_78", "admitted", json!({}), vec![], record_output_hash(&tampered, &widened), ROOM_HASH_EXCLUDES, "admitted_not_verified", "n", "2026-01-01T00:00:00Z");
        receipt["hash_scope_excludes"] = json!(widened);
        tampered["admission_receipt_ref"] = receipt["receipt_ref"].clone();
        tampered["admission_and_replay_refs"] = json!([receipt["receipt_ref"]]);
        let intent = json!({
            "room_tail": "or_78", "room_ref": "outcome-room://or_78",
            "receipt_id": rid, "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "final_room": tampered, "final_room_hash": record_output_hash(&tampered, &[]),
            "at": "2026-01-01T00:00:00Z",
        });
        persist_atomic(data_dir, ADMISSION_INTENT_DIR, "or_78", &intent).unwrap();
        persist_atomic(data_dir, ROOM_DIR, "or_78", &tampered).unwrap();
        let room_bytes = serde_json::to_vec(&load_room(data_dir, "outcome-room://or_78").unwrap()).unwrap();
        complete_room_intents(data_dir);
        let after = load_room(data_dir, "outcome-room://or_78").unwrap();
        assert_eq!(serde_json::to_vec(&after).unwrap(), room_bytes, "the tampered room is byte-for-byte unchanged — the widened scope did not admit it");
        assert!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(), "NO receipt was persisted for the forged admission");
        assert_eq!(read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(), 1, "the intent is retained for manual repair");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_replay_refuses_a_tampered_declaration_behind_the_same_anchor() {
        // #72 round 13 — the reviewer's exact reproduction: same anchor, but `objective` and
        // `owner_or_sponsor_ref` (immutable declaration fields) were altered. The replay must
        // refuse with room, receipt family, and intent byte-for-byte unchanged.
        let dir = temp_dir("admission-tamper");
        let data_dir = dir.to_str().unwrap();
        let mut final_room = json!({ "outcome_room_id": "outcome-room://or_79", "objective": "original objective", "owner_or_sponsor_ref": "org://original", "status": "open", "revision": 1, "member_goal_run_refs": [], "updated_at": "2026-01-01T00:00:00Z" });
        let (rid, receipt) = build_room_receipt(ADMISSION_RECEIPT_SCHEMA, "OutcomeRoomAdmissionReceipt", "orr", "outcome-room://or_79", "admitted", json!({}), vec![], record_output_hash(&final_room, ROOM_HASH_EXCLUDES), ROOM_HASH_EXCLUDES, "admitted_not_verified", "n", "2026-01-01T00:00:00Z");
        final_room["admission_receipt_ref"] = receipt["receipt_ref"].clone();
        final_room["admission_and_replay_refs"] = json!([receipt["receipt_ref"]]);
        let intent = json!({
            "room_tail": "or_79", "room_ref": "outcome-room://or_79",
            "receipt_id": rid, "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "final_room": final_room, "final_room_hash": record_output_hash(&final_room, &[]),
            "at": "2026-01-01T00:00:00Z",
        });
        persist_atomic(data_dir, ADMISSION_INTENT_DIR, "or_79", &intent).unwrap();
        // Tampered occupant: SAME anchor + SAME admission_receipt_ref, altered declaration.
        let mut tampered = final_room.clone();
        tampered["objective"] = json!("TAMPERED objective");
        tampered["owner_or_sponsor_ref"] = json!("org://attacker");
        persist_atomic(data_dir, ROOM_DIR, "or_79", &tampered).unwrap();
        let tampered_bytes = serde_json::to_vec(&load_room(data_dir, "outcome-room://or_79").unwrap()).unwrap();
        complete_room_intents(data_dir);
        let after = load_room(data_dir, "outcome-room://or_79").unwrap();
        assert_eq!(serde_json::to_vec(&after).unwrap(), tampered_bytes, "the room is byte-for-byte unchanged — neither receipted over nor 'repaired'");
        assert!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(), "NO receipt was persisted for an admission the declaration does not prove");
        assert_eq!(read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(), 1, "the intent is retained for manual repair");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attach_completer_never_overwrites_another_rooms_binding() {
        // #72 round 10 finding 3 — the A-intent/B-binding proof: room A's surviving intent must
        // NOT rewrite a run that was bound to room B after A's stamp failed; the intent stays
        // as a typed/manual conflict and B's binding is untouched.
        let dir = temp_dir("attach-conflict");
        let data_dir = dir.to_str().unwrap();
        let (_ai, prior_room, _arid, _arcpt) = canonical_admission("or_7a");
        let (intent, _updated_room, _rid, _rcpt) = canonical_attach(&prior_room, "gr_ab");
        let mut with_intent = prior_room.clone();
        with_intent["attach_intent"] = intent;
        persist_atomic(data_dir, ROOM_DIR, "or_7a", &with_intent).unwrap();
        // The run was bound to room B in the meantime.
        persist_atomic(data_dir, GOAL_RUN_DIR, "gr_ab", &json!({ "goal_run_id": "gr_ab", "status": "active", "outcome_room_ref": "outcome-room://or_7c" })).unwrap();
        complete_attach_intents(data_dir);
        let run = read_record_dir(data_dir, GOAL_RUN_DIR).pop().unwrap();
        assert_eq!(run["outcome_room_ref"], json!("outcome-room://or_7c"), "room B's reciprocal binding is UNTOUCHED");
        let room_a = load_room(data_dir, "outcome-room://or_7a").unwrap();
        assert!(room_a.get("attach_intent").is_some(), "room A's intent is left as a manual conflict, never overwritten");
        assert_eq!(room_a["member_goal_run_refs"], json!([]), "room A gained no membership");
        assert!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(), "no receipt was manufactured");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attach_completer_rolls_back_when_the_run_never_became_durable() {
        // #72 round 9 finding 3: if the crash lost the GoalRun record itself (its stamp never
        // became durable), the completer converges the OTHER direction — the intent rolls back
        // to the exact prior room, and no membership, stamp, or receipt is manufactured.
        let dir = temp_dir("attach-vanish");
        let data_dir = dir.to_str().unwrap();
        let (_ai, prior_room, _arid, _arcpt) = canonical_admission("or_7b");
        let (intent, _updated_room, _rid, _rcpt) = canonical_attach(&prior_room, "gr_ghost");
        let mut with_intent = prior_room.clone();
        with_intent["attach_intent"] = intent;
        persist_atomic(data_dir, ROOM_DIR, "or_7b", &with_intent).unwrap();
        complete_attach_intents(data_dir);
        let room_after = load_room(data_dir, "outcome-room://or_7b").unwrap();
        assert!(room_after.get("attach_intent").is_none(), "the intent was rolled back");
        assert_eq!(room_after["member_goal_run_refs"], json!([]), "no membership was manufactured");
        assert!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(), "no receipt was manufactured");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deterministic_interleaving_reconcile_reads_first_attach_lands_reconcile_persists_last() {
        // #72 round 2, the reviewer's exact interleaving: a lifecycle writer loads a STALE
        // snapshot, the attach stamp lands second, the lifecycle writer persists last — BOTH the
        // reconciliation state and the reciprocal room binding must survive, because every
        // writer merges its OWN fields onto the LATEST record through the shared seam.
        let dir = temp_dir("interleave-run");
        let data_dir = dir.to_str().unwrap();
        persist_atomic(data_dir, GOAL_RUN_DIR, "gr_race", &json!({ "goal_run_id": "gr_race", "status": "active", "normalized_goal": "x" })).unwrap();
        // 1. "reconcile reads first" — the stale snapshot exists (and is deliberately unused for
        //    the persist; the old bug persisted exactly this value wholesale).
        let stale_snapshot = read_record_dir(data_dir, GOAL_RUN_DIR).pop().unwrap();
        assert!(stale_snapshot.get("outcome_room_ref").is_none());
        // 2. "attach lands second" — the stamp goes through the seam.
        super::super::goalrun_routes::update_goal_run_guarded(data_dir, "gr_race", |_| Ok(()), |obj| {
            obj.insert("outcome_room_ref".into(), json!("outcome-room://or_race"));
        })
        .unwrap();
        // 3. "reconcile persists last" — through the seam, merging ONLY its lifecycle fields.
        let merged = super::super::goalrun_routes::update_goal_run_guarded(data_dir, "gr_race", |_| Ok(()), |obj| {
            obj.insert("status".into(), json!("complete"));
            obj.insert("reconciliation_ref".into(), json!("reconciliation_result://rec_1"));
        })
        .unwrap()
        .into_record();
        assert_eq!(merged["status"], json!("complete"), "the reconciliation state survived");
        assert_eq!(merged["outcome_room_ref"], json!("outcome-room://or_race"), "the reciprocal room binding SURVIVED the later lifecycle persist");
        let durable = read_record_dir(data_dir, GOAL_RUN_DIR).pop().unwrap();
        assert_eq!(durable["outcome_room_ref"], json!("outcome-room://or_race"));
        assert_eq!(durable["reconciliation_ref"], json!("reconciliation_result://rec_1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_receipt_carries_the_pinned_envelope_base() {
        let (_, receipt) = build_room_receipt(
            ADMISSION_RECEIPT_SCHEMA, "OutcomeRoomAdmissionReceipt", "orr", "outcome-room://or_k", "admitted",
            json!({ "room_mode": "private_goal" }), vec![json!("outcome-room://or_k")],
            "sha256:x".into(), ROOM_HASH_EXCLUDES, "admitted_not_verified", "n", "2026-01-01T00:00:00Z",
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
