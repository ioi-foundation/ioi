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
const ROOM_MODES: &[&str] = &[
    "private_goal",
    "permissioned_team",
    "cross_org",
    "open_challenge",
];
const ROOM_STATUSES: &[&str] = &[
    "proposed",
    "open",
    "active",
    "paused",
    "blocked",
    "verifying",
    "accepted",
    "disputed",
    "settled",
    "closed",
    "revoked",
    "archived",
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
/// Room-owned BACKLINK transitions (#74): step-3 object planes never write the room record —
/// they call `bind_room_backlink`, and the room appends ONE canonical ref to ONE plane-owned
/// list through the same receipted, intent-transactional machinery as every other transition.
/// op → (list field, required ref scheme).
const BACKLINK_OPS: &[(&str, &str, &str)] = &[
    (
        "participation_request_bound",
        "participation_request_refs",
        "participation-request",
    ),
    (
        "participant_lease_bound",
        "participant_lease_refs",
        "participant-lease",
    ),
    (
        "participant_lease_released",
        "released_participant_lease_refs",
        "participant-lease",
    ),
    ("frontier_item_bound", "frontier_item_refs", "frontier"),
    (
        "resource_offer_bound",
        "resource_offer_refs",
        "resource-offer",
    ),
    (
        "capability_offer_bound",
        "capability_offer_refs",
        "capability-offer",
    ),
    ("attempt_bound", "attempt_refs", "attempt"),
    ("finding_bound", "finding_refs", "finding"),
    (
        "verifier_challenge_bound",
        "verifier_challenge_refs",
        "verifier-challenge",
    ),
];
const BACKLINK_NOTE: &str = "an admitted backlink transition — the room's object list gains one canonical ref; the object record itself is its own plane's truth";

fn backlink_ref_ok(value: &str, scheme: &str) -> bool {
    if scheme == "frontier" {
        return value.strip_prefix("frontier://wfi_").is_some_and(|tail| {
            tail.len() == 64
                && tail
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
        });
    }
    if scheme == "resource-offer" {
        return value
            .strip_prefix("resource-offer://rof_")
            .is_some_and(|tail| {
                tail.len() == 64
                    && tail
                        .chars()
                        .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
            });
    }
    if scheme == "capability-offer" {
        return value
            .strip_prefix("capability-offer://cof_")
            .is_some_and(|tail| {
                tail.len() == 64
                    && tail
                        .chars()
                        .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
            });
    }
    if scheme == "verifier-challenge" {
        return value
            .strip_prefix("verifier-challenge://vc_")
            .is_some_and(|tail| {
                tail.len() == 64
                    && tail
                        .chars()
                        .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
            });
    }
    ref_scheme_ok(value, &[scheme])
}

const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "password",
    "secret",
    "credential",
    "authorization",
    "privatekey",
    "apikey",
    "token",
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
pub(crate) fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}

pub(crate) type VErr = (String, String);
pub(crate) fn verr(code: &str, msg: impl Into<String>) -> VErr {
    (code.into(), msg.into())
}

pub(crate) fn reject_sensitive_keys(v: &Value, path: &str) -> Result<(), VErr> {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                let normalized: String = k
                    .to_lowercase()
                    .chars()
                    .filter(|c| !matches!(c, '_' | '-' | ' ' | '.'))
                    .collect();
                if SENSITIVE_KEY_FRAGMENTS
                    .iter()
                    .any(|f| normalized.contains(f))
                    && !child.is_null()
                {
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

pub(crate) fn str_opt_bounded(body: &Value, key: &str, max: usize) -> Result<Option<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) => {
            if raw.chars().count() > max {
                return Err(verr(
                    "outcome_room_field_too_long",
                    format!("`{key}` exceeds the bounded length ({max} chars)"),
                ));
            }
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            Ok(Some(trimmed.to_string()))
        }
        Some(_) => Err(verr(
            "outcome_room_field_type_invalid",
            format!(
                "`{key}` must be a string when present — a non-string value is never defaulted"
            ),
        )),
    }
}

pub(crate) fn ref_scheme_ok(v: &str, schemes: &[&str]) -> bool {
    match v.split_once("://") {
        Some((scheme, tail)) if !tail.is_empty() => schemes.contains(&scheme),
        _ => false,
    }
}

fn scheme_err(key: &str, schemes: &[&str]) -> VErr {
    verr(
        "outcome_room_ref_scheme_invalid",
        format!(
            "`{key}` must be a canonical ref [{}] — a raw string is never a ref",
            schemes
                .iter()
                .map(|s| format!("{s}://"))
                .collect::<Vec<_>>()
                .join("|")
        ),
    )
}

pub(crate) fn scalar_ref(
    body: &Value,
    key: &str,
    schemes: &[&str],
) -> Result<Option<String>, VErr> {
    match str_opt_bounded(body, key, REF_MAX)? {
        None => Ok(None),
        Some(v) if ref_scheme_ok(&v, schemes) => Ok(Some(v)),
        Some(_) => Err(scheme_err(key, schemes)),
    }
}

/// A REQUIRED canonical scalar ref (rooms are governed: their core policy refs must be declared).
pub(crate) fn required_ref(
    body: &Value,
    key: &str,
    schemes: &[&str],
    req_code: &str,
) -> Result<String, VErr> {
    match scalar_ref(body, key, schemes)? {
        Some(v) => Ok(v),
        None => Err(verr(req_code, format!("`{key}` is required — a room without it is ungoverned (declare a canonical [{}] ref)", schemes.join("|")))),
    }
}

pub(crate) fn list_ref(body: &Value, key: &str, schemes: &[&str]) -> Result<Vec<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => {
            if items.len() > LIST_MAX {
                return Err(verr(
                    "outcome_room_field_too_long",
                    format!("`{key}` exceeds the bounded list length ({LIST_MAX})"),
                ));
            }
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                match it {
                    Value::String(raw) => {
                        let t = raw.trim();
                        if t.is_empty() {
                            continue;
                        }
                        if t.chars().count() > REF_MAX {
                            return Err(verr(
                                "outcome_room_field_too_long",
                                format!(
                                    "a `{key}` member exceeds the bounded length ({REF_MAX} chars)"
                                ),
                            ));
                        }
                        if !ref_scheme_ok(t, schemes) {
                            return Err(scheme_err(key, schemes));
                        }
                        out.push(t.to_string());
                    }
                    _ => {
                        return Err(verr(
                            "outcome_room_field_type_invalid",
                            format!("`{key}` members must be strings"),
                        ))
                    }
                }
            }
            Ok(out)
        }
        Some(_) => Err(verr(
            "outcome_room_field_type_invalid",
            format!("`{key}` must be an array of refs when present"),
        )),
    }
}

pub(crate) fn vocab_required(
    body: &Value,
    key: &str,
    vocab: &[&str],
    code: &str,
) -> Result<String, VErr> {
    match str_opt_bounded(body, key, 80)? {
        Some(v) if vocab.contains(&v.as_str()) => Ok(v),
        Some(v) => Err(verr(
            code,
            format!(
                "`{key}` value '{v}' is not a member of the canonical vocabulary [{}]",
                vocab.join("|")
            ),
        )),
        None => Err(verr(
            code,
            format!(
                "`{key}` is required and must be a member of [{}]",
                vocab.join("|")
            ),
        )),
    }
}

/// Step-3 object planes: caller-supplied values refuse per-field until the plane exists.
fn plane_owned_list(body: &Value, key: &str, code: &str, why: &str) -> Result<(), VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Array(items)) => {
            if items
                .iter()
                .any(|it| !matches!(it, Value::String(s) if s.trim().is_empty()))
            {
                Err(verr(
                    code,
                    format!("`{key}` is not caller-authored — {why}"),
                ))
            } else {
                Ok(())
            }
        }
        Some(_) => Err(verr(
            "outcome_room_field_type_invalid",
            format!("`{key}` must be an array when present"),
        )),
    }
}

pub(crate) fn record_output_hash(record: &Value, excludes: &[&str]) -> String {
    let mut clone = record.clone();
    if let Some(obj) = clone.as_object_mut() {
        for k in excludes {
            obj.remove(*k);
        }
    }
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&clone).unwrap_or_default())
    )
}

/// ADMISSION hash scope: the admission receipt binds the DECLARED room shape — plane-owned
/// mutable fields are excluded so later receipted transitions never invalidate it.
const ROOM_HASH_EXCLUDES: &[&str] = &[
    "admission_receipt_ref",
    "updated_at",
    "revision",
    "status",
    "status_history",
    "member_goal_run_refs",
    "admission_and_replay_refs",
    "released_participant_lease_refs",
];
/// TRANSITION hash scope (#72 review finding 4): a transition receipt hashes the transition's
/// OUTPUT — resulting status, revision, membership, and updated_at ARE included; only the
/// circular receipt-bearing fields are excluded (the trail and history embed this receipt's own
/// ref, and admission_receipt_ref is the creation receipt). Distinct transitions therefore emit
/// DISTINCT hashes.
const TRANSITION_HASH_EXCLUDES: &[&str] = &[
    "admission_receipt_ref",
    "admission_and_replay_refs",
    "status_history",
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
pub(crate) fn is_canonical_receipt_tail(tail: &str, prefix: &str) -> bool {
    tail.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('_'))
        .map(|hex| {
            !hex.is_empty()
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .unwrap_or(false)
}

/// A canonical room tail is EXACTLY `or_{lowercase-hex}` (creation mints `or_{:x}`).
fn is_canonical_room_tail(tail: &str) -> bool {
    is_canonical_receipt_tail(tail, "or")
}

pub(crate) fn is_rfc3339(v: &Value) -> bool {
    v.as_str()
        .map(|s| {
            time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).is_ok()
        })
        .unwrap_or(false)
}

/// Read a NON-promoted room-family directory as (canonical-stem, value) pairs — the file STEM is
/// the trusted storage key (#72 round 17 finding 1). Enumeration is through the PINNED fd
/// (#72 round 21 finding 3), and each name is re-resolved with `openat(O_NOFOLLOW)` RELATIVE to
/// that same fd, so neither a directory-level exchange nor an entry-level regular/symlink swap
/// can redirect a read. A directory-level failure (pin/enumerate) is a TYPED ERROR, never a
/// false-empty list; per-entry non-canonical stems and refused (symlink/non-regular) occupants
/// are skipped as legitimately-invisible.
fn read_dir_with_stems(data_dir: &str, family: &str) -> Result<Vec<(String, Value)>, String> {
    let dir = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(d) => d,
        // A not-yet-created family is genuinely empty; anything else (ELOOP from a swapped
        // directory symlink, EACCES, …) is a real error, NOT an empty registry.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("family '{family}' directory could not be pinned ({e}) — refusing to report a false-empty registry")),
    };
    let names = super::durable_fs::enumerate_pinned(&dir).map_err(|e| format!("family '{family}' could not be enumerated through its pinned fd ({e}) — refusing to report a false-empty registry"))?;
    let mut out = Vec::new();
    for name in names {
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        // Canonicalize the stem BEFORE any open (#72 round 20 finding 2).
        if !is_canonical_room_tail(stem) {
            continue;
        }
        // Re-resolve the name O_NOFOLLOW relative to the pinned fd — a symlink/non-regular
        // occupant (or one swapped in after enumeration) is skipped, never read-through.
        match super::durable_fs::read_slot_strict(&dir, &name) {
            Ok(Some((_f, bytes))) => {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    out.push((stem.to_string(), value));
                }
            }
            _ => continue,
        }
    }
    Ok(out)
}

/// Strict ROOM slot read (#72 round 19 finding 1): the stem is validated CANONICAL before any
/// filesystem access — a URL-derived `../…` stem never reaches a path join — and the read is a
/// pinned no-follow open. Ok(None) = definitively absent; Err = unreadable / symlink /
/// non-regular / non-JSON occupant — WRITE-side callers refuse, read paths map Err to invisible.
fn read_room_slot_strict(data_dir: &str, stem: &str) -> Result<Option<Value>, String> {
    if !is_canonical_room_tail(stem) {
        return Err(format!(
            "non-canonical room stem '{stem}' — refused before any filesystem access"
        ));
    }
    let dir = match super::durable_fs::open_family_dir_pinned(data_dir, ROOM_DIR) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("room directory unavailable ({e})")),
    };
    match super::durable_fs::read_slot_strict(&dir, &format!("{stem}.json")) {
        Ok(None) => Ok(None),
        Ok(Some((_f, bytes))) => serde_json::from_slice::<Value>(&bytes)
            .map(Some)
            .map_err(|e| format!("room slot '{stem}' holds non-JSON content ({e})")),
        Err(e) => Err(format!(
            "room slot '{stem}' is occupied but not readable as a regular file ({e})"
        )),
    }
}

/// Load the room stored AT `stem.json` (by filename, not content id) — the trusted key. Reads
/// are strict (canonical stem, pinned no-follow); anything questionable is simply invisible.
fn load_room_file(data_dir: &str, stem: &str) -> Option<Value> {
    read_room_slot_strict(data_dir, stem).ok().flatten()
}

/// Plane-owned + identity fields the creation constructor sets itself — stripped from a sealed
/// room to recover the ORIGINAL declaration body for reconstruction (#72 round 16).
const ROOM_PLANE_OWNED_FIELDS: &[&str] = &[
    "schema_version",
    "runtimeTruthSource",
    "outcome_room_id",
    "created_at",
    "updated_at",
    "status",
    "revision",
    "status_history",
    "admission_receipt_ref",
    "admission_and_replay_refs",
    "member_goal_run_refs",
    "participant_lease_refs",
    "participation_request_refs",
    "resource_offer_refs",
    "capability_offer_refs",
    "frontier_item_refs",
    "attempt_refs",
    "finding_refs",
    "verifier_challenge_refs",
    "discussion_projection_refs",
    "contribution_refs",
    "participant_state_bundle_refs",
];

/// Reconstruct the COMPLETE admission room from a sealed one, through the SAME declaration
/// validator/constructor creation uses (#72 round 16 finding 1): a hollow envelope (missing
/// owner/objective/host/mode/topology/policy refs) is REJECTED by `validate_room_create` — it
/// can never pass as "matching facts" the way `None == None` did. The plane-owned identity and
/// timestamps are then reattached from the sealed room; the caller byte-compares the result.
fn reconstruct_admission_room(
    final_room: &Value,
    receipt_ref: &Value,
    trusted_room_id: &str,
) -> Result<Value, String> {
    let mut body = final_room.clone();
    if let Some(obj) = body.as_object_mut() {
        for k in ROOM_PLANE_OWNED_FIELDS {
            obj.remove(*k);
        }
    }
    let mut record =
        validate_room_create(&body).map_err(|(code, _)| format!("declaration invalid ({code})"))?;
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
    let intent_receipt_id = intent
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    // Self-consistency of the intent seals (fast reject).
    if intent.get("receipt_hash").and_then(Value::as_str)
        != Some(record_output_hash(&receipt, &[]).as_str())
    {
        return Err("receipt seal".into());
    }
    if intent.get("final_room_hash").and_then(Value::as_str)
        != Some(record_output_hash(&final_room, &[]).as_str())
    {
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
        || receipt
            .pointer("/attested_boundary_fact_refs/0")
            .and_then(Value::as_str)
            != Some(room_id)
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
    if serde_json::to_vec(&expected_room).unwrap_or_default()
        != serde_json::to_vec(&final_room).unwrap_or_default()
    {
        return Err("not the canonical admission room".into());
    }
    // RECONSTRUCT the EXACT admission receipt from the validated room; byte-compare.
    let now = expected_room
        .get("updated_at")
        .and_then(Value::as_str)
        .unwrap_or("");
    let expected_receipt = build_room_receipt_at(
        intent_receipt_id,
        ADMISSION_RECEIPT_SCHEMA,
        "OutcomeRoomAdmissionReceipt",
        room_id,
        "admitted",
        json!({ "room_mode": expected_room["room_mode"], "coordination_topology": expected_room["coordination_topology"], "owner_or_sponsor_ref": expected_room["owner_or_sponsor_ref"], "objective_ref": expected_room["objective_ref"], "host_domain_ref": expected_room["host_domain_ref"], "status_at_admission": "open" }),
        vec![
            json!(room_id),
            expected_room["owner_or_sponsor_ref"].clone(),
            expected_room["objective_ref"].clone(),
            expected_room["host_domain_ref"].clone(),
        ],
        record_output_hash(&expected_room, ROOM_HASH_EXCLUDES),
        ROOM_HASH_EXCLUDES,
        "admitted_not_verified",
        ADMISSION_NOTE,
        now,
    );
    if serde_json::to_vec(&expected_receipt).unwrap_or_default()
        != serde_json::to_vec(&receipt).unwrap_or_default()
    {
        return Err("not the canonical admission receipt".into());
    }
    Ok(())
}

/// Reconstruct the ONLY valid TRANSITION successor of `prior` for the named op AND the EXACT
/// transition receipt, then require the sealed `final_room` + receipt to equal them byte-for-
/// byte (#72 rounds 15-16 finding 2). `prior` is the durable room with its `transition_intent`
/// stripped — so a forged declaration, status, revision, trail, OR receipt (bound facts,
/// boundary refs, posture, actor, timestamps) can never match the deterministic reconstruction.
fn validate_transition_intent(
    intent: &Value,
    prior: &Value,
    room_id: &str,
    room_tail: &str,
) -> Result<(), String> {
    let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
    let final_room = intent.get("final_room").cloned().unwrap_or(Value::Null);
    let intent_receipt_id = intent
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    if intent.get("receipt_hash").and_then(Value::as_str)
        != Some(record_output_hash(&receipt, &[]).as_str())
    {
        return Err("receipt seal".into());
    }
    if intent.get("final_room_hash").and_then(Value::as_str)
        != Some(record_output_hash(&final_room, &[]).as_str())
    {
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
        || receipt
            .pointer("/attested_boundary_fact_refs/0")
            .and_then(Value::as_str)
            != Some(room_id)
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
    // The op must be a CANONICAL lifecycle transition OR a room-owned backlink op (#74).
    if let Some((_, field, scheme)) = BACKLINK_OPS.iter().find(|(o, _, _)| *o == op) {
        return validate_backlink_intent(
            intent,
            prior,
            room_id,
            field,
            scheme,
            &receipt,
            &final_room,
            intent_receipt_id,
        );
    }
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
        history.push(
            json!({ "op": op, "at": now, "receipt_ref": receipt_ref, "revision": prior_rev + 1 }),
        );
        if history.len() > HISTORY_MAX {
            let drop_n = history.len() - HISTORY_MAX;
            history.drain(0..drop_n);
        }
        obj.insert("status_history".into(), Value::Array(history));
    }
    if serde_json::to_vec(&expected).unwrap_or_default()
        != serde_json::to_vec(&final_room).unwrap_or_default()
    {
        return Err("not the deterministic successor".into());
    }
    // Reconstruct the EXACT transition receipt as mutate_room would; byte-compare.
    let expected_receipt = build_room_receipt_at(
        intent_receipt_id,
        TRANSITION_RECEIPT_SCHEMA,
        "OutcomeRoomTransitionReceipt",
        room_id,
        op,
        json!({ "transition": op, "from": from, "to": to_status, "revision_before": prior_rev, "revision_after": prior_rev + 1 }),
        vec![json!(room_id)],
        record_output_hash(&expected, TRANSITION_HASH_EXCLUDES),
        TRANSITION_HASH_EXCLUDES,
        "admitted_not_verified",
        TRANSITION_NOTE,
        now_str,
    );
    if serde_json::to_vec(&expected_receipt).unwrap_or_default()
        != serde_json::to_vec(&receipt).unwrap_or_default()
    {
        return Err("not the canonical transition receipt".into());
    }
    Ok(())
}

/// Reconstruct the ONLY valid BACKLINK successor of `prior` for the sealed op (#74): the named
/// plane-owned list gains EXACTLY the receipt's bound ref (canonical scheme, not already
/// present, room OPEN, status unchanged), revision+1, trail + history appended — then require
/// the sealed `final_room` AND receipt to equal the reconstruction byte-for-byte. Identity,
/// seal, storage-key, tail, and timestamp checks already ran in `validate_transition_intent`.
#[allow(clippy::too_many_arguments)]
fn validate_backlink_intent(
    _intent: &Value,
    prior: &Value,
    room_id: &str,
    field: &str,
    scheme: &str,
    receipt: &Value,
    final_room: &Value,
    intent_receipt_id: &str,
) -> Result<(), String> {
    let op = receipt.get("op").and_then(Value::as_str).unwrap_or("");
    let bound_ref = receipt
        .pointer("/bound_facts/bound_ref")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if !backlink_ref_ok(&bound_ref, scheme) {
        return Err("backlink bound ref is not canonical for the op".into());
    }
    if prior.get("status").and_then(Value::as_str) != Some("open") {
        return Err("backlink not admitted from prior status".into());
    }
    let existing: Vec<String> = prior
        .get(field)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if existing.iter().any(|m| m == &bound_ref) {
        return Err("ref already bound on the prior room".into());
    }
    let prior_rev = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let now = final_room.get("updated_at").cloned().unwrap_or(Value::Null);
    let now_str = now.as_str().unwrap_or("");
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    let mut expected = prior.clone();
    if let Some(obj) = expected.as_object_mut() {
        obj.remove("transition_intent");
        let mut arr: Vec<Value> = existing.iter().cloned().map(Value::String).collect();
        arr.push(json!(bound_ref));
        obj.insert(field.into(), Value::Array(arr));
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
        history.push(
            json!({ "op": op, "at": now, "receipt_ref": receipt_ref, "revision": prior_rev + 1 }),
        );
        if history.len() > HISTORY_MAX {
            let drop_n = history.len() - HISTORY_MAX;
            history.drain(0..drop_n);
        }
        obj.insert("status_history".into(), Value::Array(history));
    }
    if serde_json::to_vec(&expected).unwrap_or_default()
        != serde_json::to_vec(final_room).unwrap_or_default()
    {
        return Err("not the deterministic backlink successor".into());
    }
    let expected_receipt = build_room_receipt_at(
        intent_receipt_id,
        TRANSITION_RECEIPT_SCHEMA,
        "OutcomeRoomTransitionReceipt",
        room_id,
        op,
        json!({ "list_field": field, "bound_ref": bound_ref, "revision_before": prior_rev, "revision_after": prior_rev + 1 }),
        vec![json!(room_id), json!(bound_ref)],
        record_output_hash(&expected, TRANSITION_HASH_EXCLUDES),
        TRANSITION_HASH_EXCLUDES,
        "admitted_not_verified",
        BACKLINK_NOTE,
        now_str,
    );
    if serde_json::to_vec(&expected_receipt).unwrap_or_default()
        != serde_json::to_vec(receipt).unwrap_or_default()
    {
        return Err("not the canonical backlink receipt".into());
    }
    Ok(())
}

/// Reconstruct the ONLY valid ATTACH (membership) successor of `prior` for the sealed run AND
/// the EXACT attach receipt, then require the sealed `updated_room` + receipt to equal them
/// byte-for-byte (#72 rounds 15-16 finding 2). `prior` is the durable room with its
/// `attach_intent` stripped.
fn validate_attach_intent(
    intent: &Value,
    prior: &Value,
    room_id: &str,
    room_tail: &str,
) -> Result<(), String> {
    let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
    let updated_room = intent.get("updated_room").cloned().unwrap_or(Value::Null);
    let intent_receipt_id = intent
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let run_file_id = intent
        .get("run_file_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    if intent.get("receipt_hash").and_then(Value::as_str)
        != Some(record_output_hash(&receipt, &[]).as_str())
    {
        return Err("receipt seal".into());
    }
    if intent.get("updated_room_hash").and_then(Value::as_str)
        != Some(record_output_hash(&updated_room, &[]).as_str())
    {
        return Err("updated-room seal".into());
    }
    // Storage-key + canonical-tail binding (#72 round 17 findings 1-2).
    if !is_canonical_room_tail(room_tail) {
        return Err("non-canonical room tail (storage key)".into());
    }
    if prior.get("outcome_room_id").and_then(Value::as_str) != Some(room_id)
        || updated_room.get("outcome_room_id").and_then(Value::as_str) != Some(room_id)
        || receipt.get("subject_ref").and_then(Value::as_str) != Some(room_id)
        || receipt
            .pointer("/attested_boundary_fact_refs/0")
            .and_then(Value::as_str)
            != Some(room_id)
    {
        return Err("room identity does not bind to the storage key".into());
    }
    if !is_canonical_receipt_tail(intent_receipt_id, "ort") {
        return Err("non-canonical attach receipt tail".into());
    }
    if !is_rfc3339(
        &updated_room
            .get("updated_at")
            .cloned()
            .unwrap_or(Value::Null),
    ) {
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
    let members: Vec<String> = prior
        .get("member_goal_run_refs")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if members.iter().any(|m| m == &member) {
        return Err("run already a member of the prior room".into());
    }
    let prior_rev = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let now = updated_room
        .get("updated_at")
        .cloned()
        .unwrap_or(Value::Null);
    let now_str = now.as_str().unwrap_or("");
    let mut expected = prior.clone();
    if let Some(obj) = expected.as_object_mut() {
        obj.remove("attach_intent");
        let mut arr: Vec<Value> = members.iter().cloned().map(Value::String).collect();
        arr.push(json!(member));
        obj.insert("member_goal_run_refs".into(), Value::Array(arr));
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
        history.push(json!({ "op": "goal_run_attached", "at": now, "receipt_ref": receipt_ref, "revision": prior_rev + 1 }));
        if history.len() > HISTORY_MAX {
            let drop_n = history.len() - HISTORY_MAX;
            history.drain(0..drop_n);
        }
        obj.insert("status_history".into(), Value::Array(history));
    }
    if serde_json::to_vec(&expected).unwrap_or_default()
        != serde_json::to_vec(&updated_room).unwrap_or_default()
    {
        return Err("not the deterministic membership successor".into());
    }
    // Reconstruct the EXACT attach receipt as the attach handler would; byte-compare.
    let expected_receipt = build_room_receipt_at(
        intent_receipt_id,
        TRANSITION_RECEIPT_SCHEMA,
        "OutcomeRoomTransitionReceipt",
        room_id,
        "goal_run_attached",
        json!({ "goal_run_ref": member, "reciprocal_outcome_room_ref_stamped": true, "member_count_after": members.len() + 1, "revision_before": prior_rev, "revision_after": prior_rev + 1 }),
        vec![json!(room_id), json!(member)],
        record_output_hash(&expected, TRANSITION_HASH_EXCLUDES),
        TRANSITION_HASH_EXCLUDES,
        "admitted_not_verified",
        ATTACH_NOTE,
        now_str,
    );
    if serde_json::to_vec(&expected_receipt).unwrap_or_default()
        != serde_json::to_vec(&receipt).unwrap_or_default()
    {
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
    let rec = build_room_receipt_at(
        &id_tail,
        schema,
        receipt_type,
        subject_ref,
        op,
        bound_facts,
        boundary_refs,
        output_hash,
        hash_scope_excludes,
        posture,
        note,
        now,
    );
    (id_tail, rec)
}

/// The receipt constructor with an EXPLICIT id tail + timestamp (#72 round 16): both the
/// finalizers (via build_room_receipt) AND the replay validators call THIS, so a replay can
/// reconstruct the EXACT receipt the finalizer would have produced and require byte equality —
/// no sealed receipt field (bound facts, boundary refs, posture, actor, portable-base nulls,
/// timestamps) is ever trusted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_room_receipt_at(
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
fn persist_atomic(
    data_dir: &str,
    family: &str,
    record_id: &str,
    record: &Value,
) -> Result<(), super::durable_fs::PersistFailure> {
    // Evidence keys must be filesystem-safe AS WRITTEN (#72 round 17 finding 2): the durable
    // writer normalizes unsafe characters, so `ort/collision` and `ort_collision` would silently
    // target the same file. Reject rather than collide — the room plane only ever writes
    // canonical `or_hex` / `orr_hex` / `ort_hex` keys, so this is a no-op for honest callers.
    if !super::durable_fs::is_normalization_safe(record_id) {
        return Err(super::durable_fs::PersistFailure::NotCommitted(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("record id '{record_id}' is not filesystem-safe (would normalize to a different key)"),
        )));
    }
    super::durable_fs::persist_record_durable(data_dir, family, record_id, record)
}

/// APPEND-ONLY, no-clobber, DURABILITY-HONEST receipt writer — the SHARED durable-fs commit
/// (#73; mechanics proven in #72 rounds 18-21: ENOENT-only-empty strict inspection, O_TMPFILE
/// descriptor-bound no-replace linkat, byte-identical re-fsync, unconditional directory+parent
/// durability barrier, post-barrier inode/byte certification), mapped onto THIS plane's wire
/// codes. Every receipt writer — create, transition, attach, and both boot completers — uses
/// THIS; the typed outcomes preserve #72's exact contract: visible-but-unconfirmed is
/// `outcome_room_receipt_durability_unconfirmed`, never Ok — terminal state and intent
/// consumption require a DURABLE receipt.
fn persist_receipt_no_clobber(data_dir: &str, tail: &str, receipt: &Value) -> Result<(), VErr> {
    use super::durable_fs::CommitFailure;
    super::durable_fs::persist_receipt_no_clobber(data_dir, ROOM_RECEIPT_DIR, tail, receipt)
        .map_err(|f| match f {
            CommitFailure::KeyInvalid(m) => verr("outcome_room_receipt_key_invalid", m),
            CommitFailure::NotCommitted(m) => verr("outcome_room_receipt_persist_failed", m),
            CommitFailure::SlotUnreadable(m) => verr("outcome_room_receipt_slot_unreadable", m),
            CommitFailure::Conflict(m) => verr("outcome_room_receipt_conflict", m),
            CommitFailure::DurabilityUnconfirmed(m) => {
                verr("outcome_room_receipt_durability_unconfirmed", m)
            }
            CommitFailure::Swapped(m) => verr("outcome_room_receipt_swapped", m),
        })
}

/// EXACT-PATH room loader (#72 round 18 finding 2): read the file AT the id's stem and require
/// its content `outcome_room_id` to equal the id — the storage key and the claimed identity
/// must agree. A relocated/renamed file (content id != its filename stem) is INVISIBLE to every
/// read path (get/list/overview/resolve/mutate/attach), so one identity can never map to two
/// files. Never scans by embedded id.
fn load_room(data_dir: &str, id: &str) -> Option<Value> {
    let stem = id.strip_prefix("outcome-room://")?;
    let room = load_room_file(data_dir, stem)?;
    if room.get("outcome_room_id").and_then(|v| v.as_str()) == Some(id) {
        Some(room)
    } else {
        None
    }
}

/// List only rooms whose content identity AGREES with their storage key (#72 round 18 finding
/// 2) — a relocated file is excluded, never counted or served. Propagates a scanner error as a
/// TYPED error rather than a false-empty list (#72 round 21 finding 3).
fn list_rooms_exact(data_dir: &str) -> Result<Vec<Value>, String> {
    Ok(read_dir_with_stems(data_dir, ROOM_DIR)?
        .into_iter()
        .filter(|(stem, room)| {
            is_canonical_room_tail(stem)
                && room.get("outcome_room_id").and_then(|v| v.as_str())
                    == Some(format!("outcome-room://{stem}").as_str())
        })
        .map(|(_, room)| room)
        .collect())
}

/// The room's LIVE participant leases (#74 review finding 2): admitted (`participant_lease_refs`)
/// minus released (`released_participant_lease_refs`). A room refuses `close`/`archive` while
/// this is non-empty, and the set only shrinks through the receipted `participant_lease_released`
/// backlink — so the interlock is exact under ROOM_MUTATION_LOCK.
pub(crate) fn live_lease_refs(room: &Value) -> Vec<String> {
    let released: std::collections::HashSet<String> = room
        .get("released_participant_lease_refs")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    room.get("participant_lease_refs")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .filter(|r| !released.contains(r))
                .collect()
        })
        .unwrap_or_default()
}

/// The room's host domain authority — resolved from the room record at ANY status (#74 review
/// finding 1). Host-governed participation decisions bind their grant to THIS principal, so a
/// host decision (evaluate/reject/admit/admin lease transition) can be authorized even on a room
/// that has left `open`.
pub(crate) fn resolve_room_host(data_dir: &str, room_ref: &str) -> Option<String> {
    load_room(data_dir, room_ref).and_then(|r| {
        r.get("host_domain_ref")
            .and_then(Value::as_str)
            .map(String::from)
    })
}

/// Resolve an admitted room at any lifecycle status. Callers that own their own typed
/// status/pending-intent errors use this rather than weakening `resolve_open_room`.
pub(crate) fn resolve_room(data_dir: &str, room_ref: &str) -> Option<Value> {
    load_room(data_dir, room_ref)
}

/// Strict write-side room resolution. Unlike the read projection above, this distinguishes a
/// definitively absent slot from an unreadable/symlinked/non-JSON occupant and treats content-id
/// mismatch as storage uncertainty. Recovery cleanup must never erase an intent on `Err`.
pub(crate) fn resolve_room_strict(data_dir: &str, room_ref: &str) -> Result<Option<Value>, String> {
    let stem = room_ref
        .strip_prefix("outcome-room://")
        .ok_or_else(|| "the room ref must be outcome-room://...".to_string())?;
    match read_room_slot_strict(data_dir, stem)? {
        None => Ok(None),
        Some(room) if room.get("outcome_room_id").and_then(Value::as_str) == Some(room_ref) => {
            Ok(Some(room))
        }
        Some(_) => Err(format!(
            "room slot '{stem}' content identity does not match '{room_ref}'"
        )),
    }
}

/// Resolve only a room that is presently OPEN and carries no durable mutation intent. The name
/// is a contract: a closed room (or the visible prior state of a pending close) never resolves as
/// an admission target.
pub(crate) fn resolve_open_room(data_dir: &str, room_ref: &str) -> Option<Value> {
    load_room(data_dir, room_ref)
        .filter(|room| s(room, "status", "") == "open" && pending_intent(room).is_none())
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
            return Err(verr(
                "outcome_room_record_persist_failed",
                format!(
                    "the admission intent persist is {} — nothing changed",
                    f.detail()
                ),
            ));
        }
    }
    if let Err((code, msg)) = persist_receipt_no_clobber(data_dir, receipt_id, receipt) {
        // Occupied/unreadable slots surface their own code; everything else — including
        // VISIBLE-BUT-UNCONFIRMED (#72 round 19 finding 2) — is pending convergence: the room is
        // NOT committed and the intent is NOT consumed until the receipt is DURABLE.
        let ecode = if code == "outcome_room_receipt_conflict"
            || code == "outcome_room_receipt_slot_unreadable"
            || code == "outcome_room_receipt_swapped"
        {
            code.as_str()
        } else {
            "outcome_room_admission_pending_convergence"
        };
        return Err(verr(ecode, format!("the admission receipt is not durably committed ({code}: {msg}); the DURABLE intent is retained internally and the room is NOT in the registry — a restart converges this same admission; do not re-create")));
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
            return Err(verr(
                "outcome_room_record_persist_failed",
                format!(
                    "the transition intent persist is {} — nothing changed",
                    f.detail()
                ),
            ));
        }
    }
    match persist_receipt_no_clobber(data_dir, receipt_id, receipt) {
        Ok(()) => {}
        Err((code, msg)) if code == "outcome_room_receipt_durability_unconfirmed" => {
            // The receipt is VISIBLE and possibly durable (#72 round 19 finding 2) — rolling
            // the intent back would orphan it; the intent is RETAINED and a restart re-fsyncs
            // the byte-identical receipt, then applies the transition.
            return Err(verr("outcome_room_mutation_pending_convergence", format!("{msg}; the DURABLE intent is retained with the room still showing its PRIOR state — a restart confirms the sealed receipt and applies the transition")));
        }
        Err((code, msg))
            if code == "outcome_room_receipt_conflict"
                || code == "outcome_room_receipt_slot_unreadable"
                || code == "outcome_room_receipt_swapped" =>
        {
            // A foreign/unreadable occupant at the receipt slot — roll the intent back exactly
            // and refuse (append-only; never overwrite, never replace on uncertainty).
            return match persist_atomic(data_dir, ROOM_DIR, room_tail, prior) {
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
            return match persist_atomic(data_dir, ROOM_DIR, room_tail, prior) {
                Ok(()) => Err(verr("outcome_room_receipt_persist_failed", format!("transition receipt persist did not commit ({msg}); the intent was rolled back EXACTLY (the room never left its prior state) — nothing changed"))),
                Err(_) => Err(verr("outcome_room_mutation_pending_convergence", format!("transition receipt persist did not commit ({msg}) AND the intent rollback did not commit — a restart converges the sealed transition"))),
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
    // A scan error is NEVER a false-empty pass (#72 round 21 finding 3): log and retry next boot,
    // rather than silently "converging" an unreadable registry as if it had no pending work.
    let admission_intents = match read_dir_with_stems(data_dir, ADMISSION_INTENT_DIR) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("outcome-room completer: admission-intent scan failed ({e}) — retrying next boot, nothing converged");
            return;
        }
    };
    let rooms = match read_dir_with_stems(data_dir, ROOM_DIR) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("outcome-room completer: registry scan failed ({e}) — retrying next boot, nothing converged");
            return;
        }
    };
    for (stem, intent) in admission_intents {
        work.push(("admission", intent, stem));
    }
    for (stem, room) in rooms {
        if let Some(i) = room.get("transition_intent") {
            work.push(("transition", i.clone(), stem));
        }
    }
    for (kind, intent, room_tail) in work {
        let room_id = format!("outcome-room://{room_tail}");
        let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
        let receipt_id = intent
            .get("receipt_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let final_room = intent.get("final_room").cloned().unwrap_or(Value::Null);
        if room_tail.is_empty()
            || receipt.is_null()
            || receipt_id.is_empty()
            || final_room.is_null()
        {
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
                    if let Some(obj) = prior.as_object_mut() {
                        obj.remove("transition_intent");
                    }
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
            // STRICT slot inspection (#72 round 19 finding 3): an unreadable/symlinked/non-JSON
            // occupant at the room slot is REFUSED — only definitively-absent proceeds to admit.
            let existing_slot = match read_room_slot_strict(data_dir, &room_tail) {
                Ok(v) => v,
                Err(why) => {
                    eprintln!("outcome-room admission completer: the room slot '{room_tail}' cannot be inspected ({why}) — refused, never replaced on uncertainty; intent retained for manual repair");
                    continue;
                }
            };
            if let Some(existing_room) = existing_slot {
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
                let anchor = |r: &Value| {
                    r.pointer("/admission_and_replay_refs/0")
                        .cloned()
                        .unwrap_or(Value::Null)
                };
                let refs_ok = !sealed_ref.is_null()
                    && anchor(&existing_room) == sealed_ref
                    && existing_room.get("admission_receipt_ref") == Some(&sealed_ref)
                    && receipt.get("receipt_id") == Some(&sealed_ref);
                let identity_ok = receipt.get("schema_version").and_then(Value::as_str)
                    == Some(ADMISSION_RECEIPT_SCHEMA)
                    && receipt.get("receipt_type").and_then(Value::as_str)
                        == Some("OutcomeRoomAdmissionReceipt")
                    && receipt.get("receipt_profile_ref").and_then(Value::as_str)
                        == Some(format!("schema://{ADMISSION_RECEIPT_SCHEMA}").as_str())
                    && receipt.get("op").and_then(Value::as_str) == Some("admitted")
                    && receipt.get("subject_ref").and_then(Value::as_str) == Some(room_id.as_str());
                // The receipt's declared scope must be EXACTLY the canonical list — same length,
                // same entries, same order, all strings (a widened scope is a forged receipt).
                let declared_scope: Vec<&str> = receipt
                    .get("hash_scope_excludes")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .map(|v| v.as_str().unwrap_or("\0non-string"))
                            .collect()
                    })
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
        // APPEND-ONLY receipt write keyed by the TARGET SLOT (#72 round 18 finding 1): the
        // no-clobber writer inspects the exact `receipt_id.json` slot — byte-identical existing
        // content is idempotent, a different occupant refuses, an empty slot is written durably.
        if let Err((code, msg)) = persist_receipt_no_clobber(data_dir, &receipt_id, &receipt) {
            eprintln!("outcome-room {kind} completer: receipt write for '{room_tail}' refused ({code}: {msg}) — intent retained, left for manual repair");
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
            let _ = std::fs::remove_file(
                std::path::Path::new(data_dir)
                    .join(ADMISSION_INTENT_DIR)
                    .join(format!("{room_tail}.json")),
            );
        }
        eprintln!(
            "outcome-room {kind} completer: converged the interrupted {kind} on '{room_tail}'"
        );
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
            return Err(verr(
                "outcome_room_record_persist_failed",
                format!(
                    "the attach intent persist is {} — nothing changed",
                    f.detail()
                ),
            ));
        }
    }
    // (2) Reciprocal stamp — DURABLE required before the receipt exists.
    let room_ref = room_id.to_string();
    let ref_for_predicate = room_ref.clone();
    let stamped = super::goalrun_routes::update_goal_run_guarded(
        data_dir,
        run_file_id,
        move |fresh| {
            match fresh.get("outcome_room_ref").and_then(Value::as_str) {
            None => Ok(()),
            Some(r) if r.is_empty() || r == ref_for_predicate => Ok(()),
            Some(other) => Err((
                "outcome_room_conflicting_binding".to_string(),
                format!("the run is already bound to '{other}' — singular room identity holds at the write itself, not just at validation"),
            )),
        }
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
    // (3) Receipt — DURABLE, APPEND-ONLY; any failure — including VISIBLE-BUT-UNCONFIRMED (#72
    // round 19 finding 2) — keeps the intent for replay (never unstamp, never delete, never
    // overwrite existing evidence); membership does not advance until the receipt is DURABLE.
    if let Err((code, msg)) = persist_receipt_no_clobber(data_dir, receipt_id, receipt) {
        let ecode = if code == "outcome_room_receipt_conflict"
            || code == "outcome_room_receipt_slot_unreadable"
            || code == "outcome_room_receipt_swapped"
        {
            code.as_str()
        } else {
            "outcome_room_attach_pending_convergence"
        };
        return Err(verr(ecode, format!("the attach receipt is not durably committed ({code}: {msg}); the DURABLE intent and the stamp are retained — a restart converges the sealed receipt (append-only) and completes the membership")));
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
    // The TRUSTED storage key is the FILENAME STEM (#72 round 17 finding 1). A scan error is
    // NEVER a false-empty pass (#72 round 21 finding 3): log and retry next boot.
    let rooms = match read_dir_with_stems(data_dir, ROOM_DIR) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("outcome-room attach completer: registry scan failed ({e}) — retrying next boot, nothing converged");
            return;
        }
    };
    for (room_tail, room) in rooms {
        let Some(intent) = room.get("attach_intent").cloned() else {
            continue;
        };
        let room_id = format!("outcome-room://{room_tail}");
        let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
        let receipt_id = intent
            .get("receipt_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let updated_room = intent.get("updated_room").cloned().unwrap_or(Value::Null);
        let run_file_id = intent
            .get("run_file_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let room_ref = intent
            .get("room_ref")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if room_tail.is_empty()
            || receipt.is_null()
            || receipt_id.is_empty()
            || updated_room.is_null()
            || run_file_id.is_empty()
            || room_ref.is_empty()
        {
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
        if let Some(obj) = prior.as_object_mut() {
            obj.remove("attach_intent");
        }
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
            move |fresh| {
                match fresh.get("outcome_room_ref").and_then(Value::as_str) {
                None => Ok(()),
                Some(r) if r.is_empty() || r == ref_for_predicate => Ok(()),
                Some(other) => Err((
                    "outcome_room_conflicting_binding".to_string(),
                    format!("the run is already bound to '{other}' — replay never overwrites another room's reciprocal binding"),
                )),
            }
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
        // APPEND-ONLY receipt write keyed by the TARGET SLOT (#72 round 18 finding 1).
        if let Err((code, msg)) = persist_receipt_no_clobber(data_dir, &receipt_id, &receipt) {
            eprintln!("outcome-room attach completer: receipt write for '{room_tail}' refused ({code}: {msg}) — intent retained, left for manual repair");
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
pub(crate) fn check_expected_revision(body: &Value, current: u64) -> Result<(), VErr> {
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
    if body.get("revision").map(|v| !v.is_null()).unwrap_or(false)
        || body
            .get("admission_receipt_ref")
            .map(|v| !v.is_null())
            .unwrap_or(false)
    {
        return Err(verr(
            "outcome_room_field_plane_owned",
            "`revision` and `admission_receipt_ref` are minted by this plane",
        ));
    }
    // Step-3 object lists refuse per-field.
    for (key, code, why) in [
        (
            "participant_lease_refs",
            "outcome_room_participants_unavailable",
            "RoomParticipantLease is build step 3",
        ),
        (
            "participation_request_refs",
            "outcome_room_participation_unavailable",
            "RoomParticipationRequest is build step 3",
        ),
        (
            "frontier_item_refs",
            "outcome_room_frontier_unavailable",
            "WorkFrontierItem is build step 3",
        ),
        (
            "resource_offer_refs",
            "outcome_room_resource_offers_plane_owned",
            "ResourceOffer backlinks are admitted by their owning plane",
        ),
        (
            "capability_offer_refs",
            "outcome_room_capability_offers_plane_owned",
            "CapabilityOffer backlinks are admitted by their owning plane",
        ),
        (
            "attempt_refs",
            "outcome_room_attempts_unavailable",
            "the Attempt plane is build step 3",
        ),
        (
            "finding_refs",
            "outcome_room_findings_unavailable",
            "the Finding plane is build step 3",
        ),
        (
            "verifier_challenge_refs",
            "outcome_room_challenges_unavailable",
            "the VerifierChallenge plane is build step 3",
        ),
        (
            "participant_state_bundle_refs",
            "outcome_room_state_bundles_unavailable",
            "ParticipantStateBundle is build step 7",
        ),
        (
            "discussion_projection_refs",
            "outcome_room_discussion_unavailable",
            "discussion projections arrive with the Missions surface (build step 4)",
        ),
        (
            "contribution_refs",
            "outcome_room_contributions_unavailable",
            "contribution lineage arrives with participant leases (build step 3)",
        ),
        (
            "admission_and_replay_refs",
            "outcome_room_replay_plane_owned",
            "the receipt trail is appended by this plane's own admitted transitions",
        ),
        (
            "member_goal_run_refs",
            "outcome_room_membership_plane_owned",
            "membership registers through the receipted attach-goal-run transition",
        ),
    ] {
        plane_owned_list(body, key, code, why)?;
    }
    let owner = required_ref(
        body,
        "owner_or_sponsor_ref",
        &["user", "org", "project", "domain", "service"],
        "outcome_room_owner_required",
    )?;
    let objective_ref = required_ref(
        body,
        "objective_ref",
        &["goal", "task", "service"],
        "outcome_room_objective_ref_required",
    )?;
    let objective = match str_opt_bounded(body, "objective", OBJECTIVE_MAX)? {
        Some(o) => o,
        None => {
            return Err(verr(
                "outcome_room_objective_required",
                "A room declares its shared `objective` (bounded plain statement).",
            ))
        }
    };
    let room_mode = vocab_required(body, "room_mode", ROOM_MODES, "outcome_room_mode_invalid")?;
    let topology = vocab_required(
        body,
        "coordination_topology",
        TOPOLOGIES,
        "outcome_room_topology_invalid",
    )?;
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
        "released_participant_lease_refs": [],
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
        "member_goal_run_refs": [],
        "status": "open",
        "revision": 1,
        "status_history": [],
        "runtimeTruthSource": "daemon-runtime"
    });
    Ok(record)
}

fn sorted_newest(data_dir: &str) -> Result<Vec<Value>, String> {
    // EXACT-PATH listing (#72 round 18 finding 2): only rooms whose content identity agrees with
    // their storage key — a relocated file is never listed.
    let mut items = list_rooms_exact(data_dir)?;
    items.sort_by(|a, b| s(b, "created_at", "").cmp(&s(a, "created_at", "")));
    Ok(items)
}

// ================================ HANDLERS =======================================================

pub(crate) async fn handle_outcome_rooms_list(
    State(st): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    // A scanner error is a TYPED 5xx, NEVER a false-empty 200 (#72 round 21 finding 3).
    match sorted_newest(&st.data_dir) {
        Ok(rooms) => (
            StatusCode::OK,
            Json(
                json!({ "schema_version": ROOM_SCHEMA, "outcome_rooms": rooms, "runtimeTruthSource": "daemon-runtime" }),
            ),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": "outcome_room_registry_unreadable", "message": e } })),
        ),
    }
}

pub(crate) async fn handle_outcome_room_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_room(&st.data_dir, &format!("outcome-room://{id}")) {
        Some(r) => (StatusCode::OK, Json(json!({ "outcome_room": r }))),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "outcome_room": id } })),
        ),
    }
}

pub(crate) async fn handle_outcome_rooms_overview(
    State(st): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    let rooms = match list_rooms_exact(&st.data_dir) {
        Ok(r) => r,
        // A scanner error is a TYPED 5xx, NEVER a false-empty overview (#72 round 21 finding 3).
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "error": { "code": "outcome_room_registry_unreadable", "message": e } }),
                ),
            )
        }
    };
    let by_status = |status: &str| {
        rooms
            .iter()
            .filter(|r| s(r, "status", "") == status)
            .count()
    };
    (
        StatusCode::OK,
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
        })),
    )
}

/// POST /v1/hypervisor/outcome-rooms — admit a HOSTED room (fail-closed, atomic, receipted).
pub(crate) async fn handle_outcome_room_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let err400 = |(code, msg): VErr| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": code, "message": msg } })),
        )
    };
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
        ADMISSION_RECEIPT_SCHEMA,
        "OutcomeRoomAdmissionReceipt",
        "orr",
        &room_id,
        "admitted",
        json!({
            "room_mode": record["room_mode"],
            "coordination_topology": record["coordination_topology"],
            "owner_or_sponsor_ref": record["owner_or_sponsor_ref"],
            "objective_ref": record["objective_ref"],
            "host_domain_ref": record["host_domain_ref"],
            "status_at_admission": "open",
        }),
        vec![
            json!(room_id),
            record["owner_or_sponsor_ref"].clone(),
            record["objective_ref"].clone(),
            record["host_domain_ref"].clone(),
        ],
        record_output_hash(&record, ROOM_HASH_EXCLUDES),
        ROOM_HASH_EXCLUDES,
        "admitted_not_verified",
        ADMISSION_NOTE,
        &now,
    );
    {
        let obj = record.as_object_mut().expect("object");
        obj.insert(
            "admission_receipt_ref".into(),
            receipt["receipt_ref"].clone(),
        );
        obj.insert(
            "admission_and_replay_refs".into(),
            json!([receipt["receipt_ref"]]),
        );
    }
    if let Err((code, msg)) =
        finalize_room_create(&st.data_dir, &id_tail, &record, &receipt_id, &receipt)
    {
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
    (
        StatusCode::CREATED,
        Json(json!({ "outcome_room": record, "outcome_room_receipt": receipt })),
    )
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
    super::work_frontier_claim_routes::refuse_external_mutation_if_reserved(
        data_dir,
        &room_id,
        "outcome_room_mutation_in_flight",
    )?;
    super::attempt_finding_routes::refuse_external_mutation_if_reserved(
        data_dir,
        &room_id,
        "outcome_room_mutation_in_flight",
    )?;
    super::verifier_challenge_routes::refuse_external_mutation_if_reserved(
        data_dir,
        &room_id,
        "outcome_room_mutation_in_flight",
    )?;
    let Some(prior) = load_room(data_dir, &room_id) else {
        return Err(verr(
            "outcome_room_not_found",
            format!("no admitted room '{room_id}'"),
        ));
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
        TRANSITION_RECEIPT_SCHEMA,
        "OutcomeRoomTransitionReceipt",
        "ort",
        &room_id,
        op,
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
        let mut trail: Vec<Value> = obj
            .get("admission_and_replay_refs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        trail.push(receipt["receipt_ref"].clone());
        obj.insert("admission_and_replay_refs".into(), Value::Array(trail));
        let mut history: Vec<Value> = obj
            .get("status_history")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        history.push(json!({ "op": op, "at": now, "receipt_ref": receipt["receipt_ref"], "revision": current_rev + 1 }));
        if history.len() > HISTORY_MAX {
            let drop_n = history.len() - HISTORY_MAX;
            history.drain(0..drop_n);
        }
        obj.insert("status_history".into(), Value::Array(history));
    }
    finalize_room_mutation(data_dir, room_tail, &prior, &updated, &receipt_id, &receipt)?;
    Ok((updated, receipt))
}

/// THE ROOM-OWNED BACKLINK SEAM (#74): the ONLY path by which a step-3 object plane reaches a
/// room record. Internal (no client expected_revision — ROOM_MUTATION_LOCK serializes writers;
/// the append is order-independent), receipted, and intent-transactional exactly like every
/// other room mutation: OPEN room required, pending-intent exclusion, duplicate ref refused,
/// revision bump, trail + history append, crash-convergent finalization.
/// `already_bound` in the error position distinguishes idempotent replay (the caller's boot
/// completer treats an ALREADY-BOUND ref as converged, never as a fresh conflict).
pub(crate) fn bind_room_backlink(
    data_dir: &str,
    room_ref: &str,
    op: &str,
    bound_ref: &str,
) -> Result<(Value, Value), VErr> {
    let _guard = ROOM_MUTATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    bind_room_backlink_room_locked(data_dir, room_ref, op, bound_ref)
}

/// Room-owned backlink seam for callers that already hold `ROOM_MUTATION_LOCK` across room
/// validation and their whole room-scoped finalization. Keeping the unlocked core private to the
/// crate makes close-vs-admit serialization explicit without recursively locking the mutex.
pub(crate) fn bind_room_backlink_room_locked(
    data_dir: &str,
    room_ref: &str,
    op: &str,
    bound_ref: &str,
) -> Result<(Value, Value), VErr> {
    bind_room_backlink_room_locked_impl(data_dir, room_ref, op, bound_ref, None, None, None, None)
}

/// Work-intent replay reaches the room owner seam while its own room reservation is necessarily
/// still durable. Ignore only that sealed intent; a different overlapping intent still refuses.
pub(crate) fn bind_room_backlink_room_locked_for_work_intent(
    data_dir: &str,
    room_ref: &str,
    op: &str,
    bound_ref: &str,
    intent_tail: &str,
) -> Result<(Value, Value), VErr> {
    bind_room_backlink_room_locked_impl(
        data_dir,
        room_ref,
        op,
        bound_ref,
        Some(intent_tail),
        None,
        None,
        None,
    )
}

/// Offer-intent replay reaches the room owner seam while its own room reservation is durable.
pub(crate) fn bind_room_backlink_room_locked_for_offer_intent(
    data_dir: &str,
    room_ref: &str,
    op: &str,
    bound_ref: &str,
    intent_tail: &str,
) -> Result<(Value, Value), VErr> {
    bind_room_backlink_room_locked_impl(
        data_dir,
        room_ref,
        op,
        bound_ref,
        None,
        Some(intent_tail),
        None,
        None,
    )
}

/// Attempt/Finding replay reaches the room seam while its own room reservation is durable.
pub(crate) fn bind_room_backlink_room_locked_for_attempt_finding_intent(
    data_dir: &str,
    room_ref: &str,
    op: &str,
    bound_ref: &str,
    intent_tail: &str,
) -> Result<(Value, Value), VErr> {
    bind_room_backlink_room_locked_impl(
        data_dir,
        room_ref,
        op,
        bound_ref,
        None,
        None,
        Some(intent_tail),
        None,
    )
}

pub(crate) fn bind_room_backlink_room_locked_for_verifier_challenge_intent(
    data_dir: &str,
    room_ref: &str,
    op: &str,
    bound_ref: &str,
    intent_tail: &str,
) -> Result<(Value, Value), VErr> {
    bind_room_backlink_room_locked_impl(
        data_dir,
        room_ref,
        op,
        bound_ref,
        None,
        None,
        None,
        Some(intent_tail),
    )
}

fn bind_room_backlink_room_locked_impl(
    data_dir: &str,
    room_ref: &str,
    op: &str,
    bound_ref: &str,
    ignored_work_intent_tail: Option<&str>,
    ignored_offer_intent_tail: Option<&str>,
    ignored_attempt_finding_intent_tail: Option<&str>,
    ignored_verifier_challenge_intent_tail: Option<&str>,
) -> Result<(Value, Value), VErr> {
    match (ignored_work_intent_tail, ignored_offer_intent_tail) {
        (Some(intent_tail), _) => {
            super::work_frontier_claim_routes::refuse_external_mutation_if_reserved_except(
                data_dir,
                room_ref,
                "outcome_room_mutation_in_flight",
                intent_tail,
            )?
        }
        (None, Some(_)) => {
            super::work_frontier_claim_routes::refuse_external_mutation_if_work_reserved(
                data_dir,
                room_ref,
                "outcome_room_mutation_in_flight",
            )?
        }
        (None, None) => {
            super::work_frontier_claim_routes::refuse_external_mutation_if_work_reserved(
                data_dir,
                room_ref,
                "outcome_room_mutation_in_flight",
            )?
        }
    }
    match ignored_offer_intent_tail {
        Some(intent_tail) => {
            super::resource_capability_offer_routes::refuse_external_mutation_if_reserved_except(
                data_dir,
                room_ref,
                "outcome_room_mutation_in_flight",
                intent_tail,
            )?
        }
        None => super::resource_capability_offer_routes::refuse_external_mutation_if_reserved(
            data_dir,
            room_ref,
            "outcome_room_mutation_in_flight",
        )?,
    }
    match ignored_attempt_finding_intent_tail {
        Some(intent_tail) => {
            super::attempt_finding_routes::refuse_external_mutation_if_reserved_except(
                data_dir,
                room_ref,
                "outcome_room_mutation_in_flight",
                intent_tail,
            )?
        }
        None => super::attempt_finding_routes::refuse_external_mutation_if_reserved(
            data_dir,
            room_ref,
            "outcome_room_mutation_in_flight",
        )?,
    }
    match ignored_verifier_challenge_intent_tail {
        Some(intent_tail) => {
            super::verifier_challenge_routes::refuse_external_mutation_if_reserved_except(
                data_dir,
                room_ref,
                "outcome_room_mutation_in_flight",
                intent_tail,
            )?
        }
        None => super::verifier_challenge_routes::refuse_external_mutation_if_reserved(
            data_dir,
            room_ref,
            "outcome_room_mutation_in_flight",
        )?,
    }
    let Some((_, field, scheme)) = BACKLINK_OPS.iter().find(|(o, _, _)| *o == op) else {
        return Err(verr(
            "outcome_room_backlink_op_invalid",
            format!("unknown backlink op '{op}'"),
        ));
    };
    if !backlink_ref_ok(bound_ref, scheme) {
        return Err(verr(
            "outcome_room_backlink_ref_invalid",
            format!("backlink ref must be {scheme}://… (got '{bound_ref}')"),
        ));
    }
    let Some(room_tail) = room_ref.strip_prefix("outcome-room://").map(str::to_string) else {
        return Err(verr(
            "outcome_room_ref_scheme_invalid",
            "the room ref must be outcome-room://…",
        ));
    };
    let prior = match resolve_room_strict(data_dir, room_ref) {
        Ok(Some(room)) => room,
        Ok(None) => {
            return Err(verr(
                "outcome_room_not_found",
                format!("no admitted room '{room_ref}'"),
            ))
        }
        Err(message) => {
            return Err(verr(
                "outcome_room_registry_unreadable",
                format!("room '{room_ref}' cannot be resolved strictly ({message})"),
            ))
        }
    };
    if let Some((f, code)) = pending_intent(&prior) {
        return Err(verr(code, format!("a durable {f} is pending on this room — a restart (boot completer) converges it before any other mutation is admitted")));
    }
    // A RELEASE only applies to a lease that was actually bound (#74) — releasing an unbound ref
    // is a caller error, not a no-op.
    if op == "participant_lease_released" {
        let bound: Vec<String> = prior
            .get("participant_lease_refs")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if !bound.iter().any(|m| m == bound_ref) {
            return Err(verr(
                "outcome_room_backlink_ref_invalid",
                format!("'{bound_ref}' was never bound to this room — cannot release it"),
            ));
        }
    }
    let existing: Vec<String> = prior
        .get(*field)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if existing.iter().any(|m| m == bound_ref) {
        return Err(verr("outcome_room_backlink_already_bound", format!("'{bound_ref}' is already bound in {field} — idempotent replay converges, a fresh bind is a conflict")));
    }
    if s(&prior, "status", "") != "open" {
        return Err(verr(
            "outcome_room_not_open",
            format!(
                "backlinks bind only to an OPEN room (status: {})",
                s(&prior, "status", "?")
            ),
        ));
    }
    let current_rev = prior.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
    let now = iso_now();
    let mut updated = prior.clone();
    {
        let obj = updated.as_object_mut().expect("room is an object");
        let mut arr: Vec<Value> = existing.iter().cloned().map(Value::String).collect();
        arr.push(json!(bound_ref));
        obj.insert((*field).into(), Value::Array(arr));
        obj.insert("revision".into(), json!(current_rev + 1));
        obj.insert("updated_at".into(), json!(now));
    }
    let (receipt_id, receipt) = build_room_receipt(
        TRANSITION_RECEIPT_SCHEMA,
        "OutcomeRoomTransitionReceipt",
        "ort",
        room_ref,
        op,
        json!({ "list_field": field, "bound_ref": bound_ref, "revision_before": current_rev, "revision_after": current_rev + 1 }),
        vec![json!(room_ref), json!(bound_ref)],
        record_output_hash(&updated, TRANSITION_HASH_EXCLUDES),
        TRANSITION_HASH_EXCLUDES,
        "admitted_not_verified",
        BACKLINK_NOTE,
        &now,
    );
    {
        let obj = updated.as_object_mut().expect("object");
        let mut trail: Vec<Value> = obj
            .get("admission_and_replay_refs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        trail.push(receipt["receipt_ref"].clone());
        obj.insert("admission_and_replay_refs".into(), Value::Array(trail));
        let mut history: Vec<Value> = obj
            .get("status_history")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        history.push(json!({ "op": op, "at": now, "receipt_ref": receipt["receipt_ref"], "revision": current_rev + 1 }));
        if history.len() > HISTORY_MAX {
            let drop_n = history.len() - HISTORY_MAX;
            history.drain(0..drop_n);
        }
        obj.insert("status_history".into(), Value::Array(history));
    }
    finalize_room_mutation(
        data_dir,
        &room_tail,
        &prior,
        &updated,
        &receipt_id,
        &receipt,
    )?;
    Ok((updated, receipt))
}

/// POST /v1/hypervisor/outcome-rooms/:id/transition — admitted, receipted lifecycle transition.
pub(crate) async fn handle_outcome_room_transition(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let err = |status: StatusCode, (code, msg): VErr| {
        (
            status,
            Json(json!({ "error": { "code": code, "message": msg } })),
        )
    };
    if let Err(e) = reject_sensitive_keys(&body, "") {
        return err(StatusCode::BAD_REQUEST, e);
    }
    let transition = match str_opt_bounded(&body, "transition", 40) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return err(
                StatusCode::BAD_REQUEST,
                verr(
                    "outcome_room_transition_invalid",
                    format!(
                        "`transition` is required — step-2 lifecycle: [{}]",
                        TRANSITIONS
                            .iter()
                            .map(|(t, _, _)| *t)
                            .collect::<Vec<_>>()
                            .join("|")
                    ),
                ),
            )
        }
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    if let Some((_, why)) = UNAVAILABLE_TRANSITIONS
        .iter()
        .find(|(t, _)| *t == transition)
    {
        return err(
            StatusCode::BAD_REQUEST,
            verr(
                "outcome_room_transition_unavailable",
                format!("transition '{transition}' needs {why} — a named gap, never faked"),
            ),
        );
    }
    let Some((_, allowed_from, to_status)) = TRANSITIONS.iter().find(|(t, _, _)| *t == transition)
    else {
        return err(
            StatusCode::BAD_REQUEST,
            verr(
                "outcome_room_transition_invalid",
                format!(
                    "unknown transition '{transition}' — step-2 lifecycle: [{}]",
                    TRANSITIONS
                        .iter()
                        .map(|(t, _, _)| *t)
                        .collect::<Vec<_>>()
                        .join("|")
                ),
            ),
        );
    };
    // Fixed cross-plane order for terminal room lifecycle: frontier/claim -> room. The new plane
    // never writes this room file; this owner route asks its read-only blocker seam while both
    // aggregates are serialized.
    let _offer_guard = if matches!(transition.as_str(), "close" | "archive") {
        Some(
            super::resource_capability_offer_routes::OFFER_MATCH_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    } else {
        None
    };
    let _frontier_guard = if matches!(transition.as_str(), "close" | "archive") {
        Some(
            super::work_frontier_claim_routes::FRONTIER_CLAIM_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    } else {
        None
    };
    let _guard = ROOM_MUTATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    if matches!(transition.as_str(), "close" | "archive") {
        if let Err(error) =
            super::resource_capability_offer_routes::refuse_room_close_if_blocked_locked(
                &st.data_dir,
                &format!("outcome-room://{id}"),
            )
        {
            let status = if error.0.contains("registry_unreadable")
                || error.0.contains("intent_unreadable")
            {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::CONFLICT
            };
            return err(status, error);
        }
        if let Err(error) = super::work_frontier_claim_routes::refuse_room_close_if_blocked_locked(
            &st.data_dir,
            &format!("outcome-room://{id}"),
        ) {
            let status = if error.0.contains("registry_unreadable")
                || error.0.contains("intent_unreadable")
            {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::CONFLICT
            };
            return err(status, error);
        }
        if let Err(error) = super::attempt_finding_routes::refuse_room_close_if_blocked_locked(
            &st.data_dir,
            &format!("outcome-room://{id}"),
        ) {
            let status = if error.0.contains("registry_unreadable")
                || error.0.contains("intent_unreadable")
            {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::CONFLICT
            };
            return err(status, error);
        }
        if let Err(error) = super::verifier_challenge_routes::refuse_room_close_if_blocked_locked(
            &st.data_dir,
            &format!("outcome-room://{id}"),
        ) {
            let status = if error.0.contains("registry_unreadable")
                || error.0.contains("intent_unreadable")
            {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::CONFLICT
            };
            return err(status, error);
        }
    }
    let result = mutate_room(&st.data_dir, &id, &body, &transition, |room| {
        let from = s(room, "status", "");
        if !allowed_from.contains(&from.as_str()) {
            return Err(verr("outcome_room_transition_invalid", format!("transition '{transition}' is not admitted from status '{from}' (allowed from: [{}])", allowed_from.join("|"))));
        }
        // ROOM-CLOSE INTERLOCK (#74 review finding 2): a room may not leave `open` for a terminal
        // state while it still has LIVE participant leases — that would strand active
        // participants and let their leases keep mutating in a closed room. Orchestrated
        // participant retirement/export on close is a NAMED GAP (arrives with WorkClaimLease
        // claim-release, #76); until then, close/archive refuses typed while live leases exist,
        // and every live lease must be revoked or retired first. The check is under
        // ROOM_MUTATION_LOCK against the room's own released-set, so it is exact.
        if matches!(transition.as_str(), "close" | "archive") {
            let live = live_lease_refs(room);
            if !live.is_empty() {
                return Err(verr("outcome_room_close_blocked_live_leases", format!("cannot {transition} — {} live participant lease(s) remain ({}); revoke or retire them first (orchestrated retirement-on-close is a named gap, build step 3 #76)", live.len(), live.join(", "))));
            }
        }
        room.as_object_mut()
            .expect("object")
            .insert("status".into(), json!(to_status));
        let rev = room.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(
            json!({ "transition": transition, "from": from, "to": to_status, "revision_before": rev, "revision_after": rev + 1 }),
        )
    });
    match result {
        Ok((room, receipt)) => (
            StatusCode::OK,
            Json(json!({ "outcome_room": room, "outcome_room_receipt": receipt })),
        ),
        Err(e) if e.0 == "outcome_room_not_found" => err(StatusCode::NOT_FOUND, e),
        Err(e)
            if e.0 == "outcome_room_revision_conflict"
                || e.0.ends_with("_in_flight")
                || e.0 == "outcome_room_close_blocked_frontier_claims"
                || e.0 == "outcome_room_close_blocked_offers"
                || e.0 == "outcome_room_close_blocked_attempts_findings"
                || e.0 == "outcome_room_close_blocked_verifier_challenges" =>
        {
            err(StatusCode::CONFLICT, e)
        }
        Err(e)
            if e.0.ends_with("_persist_failed")
                || e.0.ends_with("_pending_convergence")
                || e.0.ends_with("_durability_unconfirmed")
                || e.0.ends_with("_unreadable")
                || e.0 == "outcome_room_rollback_failed" =>
        {
            err(StatusCode::INTERNAL_SERVER_ERROR, e)
        }
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
    let err = |status: StatusCode, (code, msg): VErr| {
        (
            status,
            Json(json!({ "error": { "code": code, "message": msg } })),
        )
    };
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
    let run_file_id = goal_run_canonical
        .strip_prefix("goal://")
        .unwrap_or("")
        .to_string();
    let room_id = format!("outcome-room://{id}");
    // ROOM-SCOPE critical section: resolution through finalization under the one room lock.
    let _guard = ROOM_MUTATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    if let Err(error) = super::work_frontier_claim_routes::refuse_external_mutation_if_reserved(
        &st.data_dir,
        &room_id,
        "outcome_room_mutation_in_flight",
    ) {
        let status = if error.0.contains("unreadable") {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::CONFLICT
        };
        return err(status, error);
    }
    if let Err(error) = super::attempt_finding_routes::refuse_external_mutation_if_reserved(
        &st.data_dir,
        &room_id,
        "outcome_room_mutation_in_flight",
    ) {
        let status = if error.0.contains("unreadable") {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::CONFLICT
        };
        return err(status, error);
    }
    if let Err(error) = super::verifier_challenge_routes::refuse_external_mutation_if_reserved(
        &st.data_dir,
        &room_id,
        "outcome_room_mutation_in_flight",
    ) {
        let status = if error.0.contains("unreadable") {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::CONFLICT
        };
        return err(status, error);
    }
    let Some(prior_run) = read_record_dir(&st.data_dir, GOAL_RUN_DIR)
        .into_iter()
        .find(|r| r.get("goal_run_id").and_then(|v| v.as_str()) == Some(run_file_id.as_str()))
    else {
        return err(StatusCode::BAD_REQUEST, verr("outcome_room_goal_run_unbound", format!("`goal_run_ref` does not resolve to an admitted GoalRun ('{goal_run_canonical}') — the aggregate binds only real bounded runs")));
    };
    // SINGULAR ROOM IDENTITY: a run already in ANY room (this one included) refuses typed.
    if let Some(existing) = prior_run.get("outcome_room_ref").and_then(|v| v.as_str()) {
        if !existing.is_empty() {
            return err(StatusCode::BAD_REQUEST, verr("outcome_room_goal_run_already_member", format!("GoalRun '{goal_run_canonical}' already belongs to '{existing}' — a run has at most ONE room; contradictory multi-room state is never created")));
        }
    }
    let Some(prior_room) = load_room(&st.data_dir, &room_id) else {
        return err(
            StatusCode::NOT_FOUND,
            verr(
                "outcome_room_not_found",
                format!("no admitted room '{room_id}'"),
            ),
        );
    };
    if let Some((field, code)) = pending_intent(&prior_room) {
        return err(StatusCode::CONFLICT, verr(code, format!("a durable {field} is pending on this room — a restart (boot completer) converges it before new membership is admitted")));
    }
    let current_rev = prior_room
        .get("revision")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if let Err(e) = check_expected_revision(&body, current_rev) {
        return if e.0 == "outcome_room_revision_conflict" {
            err(StatusCode::CONFLICT, e)
        } else {
            err(StatusCode::BAD_REQUEST, e)
        };
    }
    if s(&prior_room, "status", "") != "open" {
        return err(
            StatusCode::BAD_REQUEST,
            verr(
                "outcome_room_not_open",
                format!(
                    "membership changes are admitted only on an `open` room (status is '{}')",
                    s(&prior_room, "status", "")
                ),
            ),
        );
    }
    let members: Vec<String> = prior_room
        .get("member_goal_run_refs")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
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
        TRANSITION_RECEIPT_SCHEMA,
        "OutcomeRoomTransitionReceipt",
        "ort",
        &room_id,
        "goal_run_attached",
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
        let mut trail: Vec<Value> = obj
            .get("admission_and_replay_refs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        trail.push(receipt["receipt_ref"].clone());
        obj.insert("admission_and_replay_refs".into(), Value::Array(trail));
        let mut history: Vec<Value> = obj
            .get("status_history")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        history.push(json!({ "op": "goal_run_attached", "at": now, "receipt_ref": receipt["receipt_ref"], "revision": current_rev + 1 }));
        if history.len() > HISTORY_MAX {
            let drop_n = history.len() - HISTORY_MAX;
            history.drain(0..drop_n);
        }
        obj.insert("status_history".into(), Value::Array(history));
    }
    let _ = &prior_run; // resolved above for the already-member check; the seam re-reads fresh
    if let Err((code, msg)) = finalize_attach(
        &st.data_dir,
        &id,
        &prior_room,
        &updated_room,
        &run_file_id,
        &room_id,
        &receipt_id,
        &receipt,
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": code, "message": msg } })),
        );
    }
    (
        StatusCode::OK,
        Json(
            json!({ "outcome_room": updated_room, "outcome_room_receipt": receipt, "goal_run_stamped": { "goal_run_ref": goal_run_canonical, "outcome_room_ref": room_id } }),
        ),
    )
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
            ADMISSION_RECEIPT_SCHEMA,
            "OutcomeRoomAdmissionReceipt",
            "orr",
            &room_id,
            "admitted",
            json!({ "room_mode": record["room_mode"], "coordination_topology": record["coordination_topology"], "owner_or_sponsor_ref": record["owner_or_sponsor_ref"], "objective_ref": record["objective_ref"], "host_domain_ref": record["host_domain_ref"], "status_at_admission": "open" }),
            vec![
                json!(room_id),
                record["owner_or_sponsor_ref"].clone(),
                record["objective_ref"].clone(),
                record["host_domain_ref"].clone(),
            ],
            record_output_hash(&record, ROOM_HASH_EXCLUDES),
            ROOM_HASH_EXCLUDES,
            "admitted_not_verified",
            ADMISSION_NOTE,
            "2026-01-01T00:00:00Z",
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
        updated
            .as_object_mut()
            .unwrap()
            .insert("status".into(), json!(to));
        updated
            .as_object_mut()
            .unwrap()
            .insert("revision".into(), json!(rev + 1));
        updated
            .as_object_mut()
            .unwrap()
            .insert("updated_at".into(), json!(now));
        let from = prior["status"].as_str().unwrap();
        let (rid, receipt) = build_room_receipt(
            TRANSITION_RECEIPT_SCHEMA,
            "OutcomeRoomTransitionReceipt",
            "ort",
            &room_id,
            op,
            json!({ "transition": op, "from": from, "to": to, "revision_before": rev, "revision_after": rev + 1 }),
            vec![json!(room_id)],
            record_output_hash(&updated, TRANSITION_HASH_EXCLUDES),
            TRANSITION_HASH_EXCLUDES,
            "admitted_not_verified",
            TRANSITION_NOTE,
            now,
        );
        {
            let obj = updated.as_object_mut().unwrap();
            let mut trail: Vec<Value> = obj
                .get("admission_and_replay_refs")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            trail.push(receipt["receipt_ref"].clone());
            obj.insert("admission_and_replay_refs".into(), Value::Array(trail));
            let mut hist: Vec<Value> = obj
                .get("status_history")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
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
        let mut members: Vec<Value> = prior
            .get("member_goal_run_refs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        members.push(json!(member));
        let mut updated = prior.clone();
        updated
            .as_object_mut()
            .unwrap()
            .insert("member_goal_run_refs".into(), Value::Array(members));
        updated
            .as_object_mut()
            .unwrap()
            .insert("revision".into(), json!(rev + 1));
        updated
            .as_object_mut()
            .unwrap()
            .insert("updated_at".into(), json!(now));
        let (rid, receipt) = build_room_receipt(
            TRANSITION_RECEIPT_SCHEMA,
            "OutcomeRoomTransitionReceipt",
            "ort",
            &room_id,
            "goal_run_attached",
            json!({ "goal_run_ref": member, "reciprocal_outcome_room_ref_stamped": true, "member_count_after": prior.get("member_goal_run_refs").and_then(|v| v.as_array()).map(|a| a.len() + 1).unwrap_or(1), "revision_before": rev, "revision_after": rev + 1 }),
            vec![json!(room_id), json!(member)],
            record_output_hash(&updated, TRANSITION_HASH_EXCLUDES),
            TRANSITION_HASH_EXCLUDES,
            "admitted_not_verified",
            ATTACH_NOTE,
            now,
        );
        {
            let obj = updated.as_object_mut().unwrap();
            let mut trail: Vec<Value> = obj
                .get("admission_and_replay_refs")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            trail.push(receipt["receipt_ref"].clone());
            obj.insert("admission_and_replay_refs".into(), Value::Array(trail));
            let mut hist: Vec<Value> = obj
                .get("status_history")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
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
            (
                "host_domain_ref",
                Value::Null,
                "outcome_room_host_domain_required",
            ),
            (
                "host_domain_ref",
                json!("not-a-ref"),
                "outcome_room_ref_scheme_invalid",
            ),
            (
                "coordination_topology",
                json!("federated_admission"),
                "outcome_room_federated_unavailable",
            ),
            (
                "coordination_topology",
                json!("mesh"),
                "outcome_room_topology_invalid",
            ),
            ("room_mode", json!("party"), "outcome_room_mode_invalid"),
            (
                "owner_or_sponsor_ref",
                json!("not-a-ref"),
                "outcome_room_ref_scheme_invalid",
            ),
            (
                "stop_policy_ref",
                json!(Value::Null),
                "outcome_room_policy_required",
            ),
            (
                "status",
                json!("accepted"),
                "outcome_room_status_plane_owned",
            ),
            ("revision", json!(7), "outcome_room_field_plane_owned"),
            (
                "participant_lease_refs",
                json!(["participant-lease://ghost"]),
                "outcome_room_participants_unavailable",
            ),
            (
                "frontier_item_refs",
                json!(["frontier://ghost"]),
                "outcome_room_frontier_unavailable",
            ),
            (
                "admission_and_replay_refs",
                json!(["receipt://forged"]),
                "outcome_room_replay_plane_owned",
            ),
            (
                "member_goal_run_refs",
                json!(["gr_x"]),
                "outcome_room_membership_plane_owned",
            ),
        ];
        for (key, val, code) in cases {
            let mut b = valid_room_body();
            b[key] = val;
            assert_eq!(
                validate_room_create(&b).unwrap_err().0,
                code,
                "field: {key}"
            );
        }
        // Recursive secrets refuse.
        let mut b = valid_room_body();
        b["notes"] = json!({ "api_key": "x" });
        assert_eq!(
            validate_room_create(&b).unwrap_err().0,
            "outcome_room_plaintext_secret_rejected"
        );
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
        let before =
            serde_json::to_vec(&load_room(data_dir, "outcome-room://or_1").unwrap()).unwrap();
        let e = mutate_room(data_dir, "or_1", &json!({}), "pause", |_| Ok(json!({}))).unwrap_err();
        assert_eq!(e.0, "outcome_room_expected_revision_invalid");
        let e = mutate_room(
            data_dir,
            "or_1",
            &json!({ "expected_revision": 9 }),
            "pause",
            |_| Ok(json!({})),
        )
        .unwrap_err();
        assert_eq!(e.0, "outcome_room_revision_conflict");
        assert_eq!(
            serde_json::to_vec(&load_room(data_dir, "outcome-room://or_1").unwrap()).unwrap(),
            before,
            "refused mutations change NOTHING"
        );
        // Exact revision → transition lands with revision+1, receipt in the trail, bound facts.
        let (updated, receipt) = mutate_room(
            data_dir,
            "or_1",
            &json!({ "expected_revision": 1 }),
            "pause",
            |room| {
                room.as_object_mut()
                    .unwrap()
                    .insert("status".into(), json!("paused"));
                Ok(json!({ "transition": "pause", "from": "open", "to": "paused" }))
            },
        )
        .unwrap();
        assert_eq!(updated["revision"], json!(2));
        assert_eq!(updated["status"], json!("paused"));
        assert!(s(&receipt, "receipt_id", "").starts_with("receipt://ort_"));
        assert_eq!(
            receipt["receipt_type"],
            json!("OutcomeRoomTransitionReceipt")
        );
        assert_eq!(receipt["bound_facts"]["to"], json!("paused"));
        assert_eq!(
            updated["admission_and_replay_refs"]
                .as_array()
                .unwrap()
                .last()
                .unwrap(),
            &receipt["receipt_ref"]
        );
        // The hash recomputes from the persisted record minus the receipt's OWN declared
        // excludes — the TRANSITION scope, which includes the resulting status/revision.
        let persisted = load_room(data_dir, "outcome-room://or_1").unwrap();
        assert_eq!(
            s(&receipt, "output_hash", ""),
            record_output_hash(&persisted, TRANSITION_HASH_EXCLUDES)
        );
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
        let before =
            serde_json::to_vec(&load_room(data_dir, "outcome-room://or_1").unwrap()).unwrap();
        std::fs::write(dir.join(ROOM_RECEIPT_DIR), b"blocker").unwrap();
        let e = mutate_room(
            data_dir,
            "or_1",
            &json!({ "expected_revision": 1 }),
            "pause",
            |room| {
                room.as_object_mut()
                    .unwrap()
                    .insert("status".into(), json!("paused"));
                Ok(json!({}))
            },
        )
        .unwrap_err();
        assert_eq!(e.0, "outcome_room_receipt_persist_failed");
        let after =
            serde_json::to_vec(&load_room(data_dir, "outcome-room://or_1").unwrap()).unwrap();
        assert_eq!(
            after, before,
            "the room is BYTE-FOR-BYTE the prior record (status, revision, updated_at)"
        );
        // No temp artifact survives.
        let tmp_leaks: Vec<String> = std::fs::read_dir(dir.join(ROOM_DIR))
            .unwrap()
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
        let tmp_leaks: Vec<String> = std::fs::read_dir(&record_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(
            tmp_leaks.is_empty(),
            "no temporary artifact survives: {tmp_leaks:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_hashes_are_distinct_and_cover_the_output_state() {
        // #72 finding 4: the transition hash INCLUDES status/revision/membership — pause and
        // resume over the same room MUST emit different hashes (and differ from admission's
        // declaration hash scope).
        let base = json!({ "outcome_room_id": "outcome-room://or_h", "status": "open", "revision": 1, "member_goal_run_refs": [], "objective": "x", "updated_at": "2026-01-01T00:00:00Z" });
        let mut paused = base.clone();
        paused["status"] = json!("paused");
        paused["revision"] = json!(2);
        let mut resumed = base.clone();
        resumed["status"] = json!("open");
        resumed["revision"] = json!(3);
        let h_admit = record_output_hash(&base, ROOM_HASH_EXCLUDES);
        let h_pause = record_output_hash(&paused, TRANSITION_HASH_EXCLUDES);
        let h_resume = record_output_hash(&resumed, TRANSITION_HASH_EXCLUDES);
        assert_ne!(h_pause, h_resume, "distinct output states hash distinctly");
        assert_ne!(
            h_pause, h_admit,
            "the transition hash is not the static declaration hash"
        );
        // Membership changes the hash too.
        let mut member = resumed.clone();
        member["member_goal_run_refs"] = json!(["goal://gr_1"]);
        assert_ne!(
            record_output_hash(&member, TRANSITION_HASH_EXCLUDES),
            h_resume
        );
    }

    #[test]
    fn attach_receipt_failure_keeps_the_intent_and_the_boot_completer_converges() {
        // #72 round 9 finding 3: a receipt failure AFTER the durable intent + durable stamp
        // refuses typed with the intent retained — no unstamp, no deletion — and the boot
        // completer converges the attach to exact reciprocal equality.
        let dir = temp_dir("attach");
        let data_dir = dir.to_str().unwrap();
        let (_ai, prior_room, _arid, _arcpt) = canonical_admission("or_1");
        let prior_run =
            json!({ "goal_run_id": "gr_1", "normalized_goal": "x", "status": "active" });
        persist_atomic(data_dir, ROOM_DIR, "or_1", &prior_room).unwrap();
        persist_atomic(data_dir, GOAL_RUN_DIR, "gr_1", &prior_run).unwrap();
        let (_intent, updated_room, rid, receipt) = canonical_attach(&prior_room, "gr_1");
        std::fs::write(dir.join(ROOM_RECEIPT_DIR), b"blocker").unwrap();
        let (code, _) = finalize_attach(
            data_dir,
            "or_1",
            &prior_room,
            &updated_room,
            "gr_1",
            "outcome-room://or_1",
            &rid,
            &receipt,
        )
        .unwrap_err();
        assert_eq!(code, "outcome_room_attach_pending_convergence");
        let room_after = load_room(data_dir, "outcome-room://or_1").unwrap();
        assert!(
            room_after.get("attach_intent").is_some(),
            "the DURABLE intent is retained for replay"
        );
        assert_eq!(
            room_after["member_goal_run_refs"],
            json!([]),
            "membership is still pending (terminal write never ran)"
        );
        let run_after = read_record_dir(data_dir, GOAL_RUN_DIR).pop().unwrap();
        assert_eq!(
            run_after["outcome_room_ref"],
            json!("outcome-room://or_1"),
            "the durable stamp STAYS — no unstamp, no split-brain"
        );
        // Restart: the completer re-persists the sealed receipt and finishes the membership.
        std::fs::remove_file(dir.join(ROOM_RECEIPT_DIR)).unwrap();
        complete_attach_intents(data_dir);
        let converged = load_room(data_dir, "outcome-room://or_1").unwrap();
        assert_eq!(
            converged["member_goal_run_refs"],
            json!(["goal://gr_1"]),
            "membership converged"
        );
        assert!(
            converged.get("attach_intent").is_none(),
            "the intent was consumed by the terminal write"
        );
        assert_eq!(
            read_record_dir(data_dir, GOAL_RUN_DIR).pop().unwrap()["outcome_room_ref"],
            json!("outcome-room://or_1"),
            "EXACT reciprocal convergence: member ⇔ stamp"
        );
        let persisted_receipt = read_record_dir(data_dir, ROOM_RECEIPT_DIR)
            .into_iter()
            .find(|r| r["receipt_id"] == receipt["receipt_id"])
            .expect("the sealed receipt was persisted");
        assert_eq!(persisted_receipt["receipt_id"], receipt["receipt_id"]);
        // Idempotent: a second boot pass changes nothing.
        complete_attach_intents(data_dir);
        assert_eq!(
            load_room(data_dir, "outcome-room://or_1").unwrap()["member_goal_run_refs"],
            json!(["goal://gr_1"])
        );
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
        assert_eq!(
            converged["status"],
            json!("paused"),
            "the sealed transition was applied"
        );
        assert_eq!(converged["revision"], json!(2));
        assert!(
            converged.get("transition_intent").is_none(),
            "the intent was consumed"
        );
        assert_eq!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).len(),
            1,
            "the sealed receipt was persisted"
        );
        // Idempotent second boot.
        complete_room_intents(data_dir);
        assert_eq!(
            load_room(data_dir, "outcome-room://or_71").unwrap()["status"],
            json!("paused")
        );
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
        assert!(
            load_room(data_dir, "outcome-room://or_72").is_none(),
            "the registry never lists a pending admission"
        );
        complete_room_intents(data_dir);
        let admitted = load_room(data_dir, "outcome-room://or_72").expect("admitted at boot");
        assert_eq!(
            admitted["status"],
            json!("open"),
            "the sealed CANONICAL status — no pending_admission enum ever existed"
        );
        assert_eq!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).len(),
            1,
            "the sealed receipt was persisted"
        );
        assert!(
            read_record_dir(data_dir, ADMISSION_INTENT_DIR).is_empty(),
            "the consumed intent was dropped"
        );
        // CONFLICT-FIRST (#72 round 12 finding 2): a FOREIGN room at the same identity (a
        // DIFFERENT canonical admission, different anchor) refuses BEFORE any write — room,
        // receipt family, and intent stay byte-for-byte unchanged, incl. the intent's receipt.
        let (other, _fr, _rid2, _rcpt2) = canonical_admission("or_72");
        persist_atomic(data_dir, ADMISSION_INTENT_DIR, "or_72", &other).unwrap();
        let receipts_before = read_record_dir(data_dir, ROOM_RECEIPT_DIR).len();
        complete_room_intents(data_dir);
        let still = load_room(data_dir, "outcome-room://or_72").unwrap();
        assert_eq!(
            still["admission_receipt_ref"], admitted["admission_receipt_ref"],
            "the ORIGINAL admission stands — the foreign intent did not overwrite it"
        );
        assert_eq!(read_record_dir(data_dir, ROOM_RECEIPT_DIR).len(), receipts_before, "NO receipt was persisted for the room the completer refused to admit (#72 r12 finding 2)");
        assert_eq!(
            read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(),
            1,
            "the conflicting intent is retained for manual repair"
        );
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
        assert_eq!(
            room["status"],
            json!("paused"),
            "the newer legitimate state is NOT overwritten by the replay"
        );
        assert!(
            read_record_dir(data_dir, ADMISSION_INTENT_DIR).is_empty(),
            "the intent was recognized as consumed and dropped"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scanner_returns_typed_error_not_false_empty_when_registry_is_unreadable() {
        // #72 round 21 finding 3: a directory-level exchange (registry replaced by a symlink) or
        // any pin/enumerate failure is a TYPED error, never an empty registry served as truth.
        let dir = temp_dir("false-empty");
        let data_dir = dir.to_str().unwrap();
        let (_i, room, _rid, _rcpt) = canonical_admission("or_d0");
        persist_atomic(data_dir, ROOM_DIR, "or_d0", &room).unwrap();
        // Move the real registry aside and replace it with a SYMLINK to the moved directory.
        std::fs::rename(dir.join(ROOM_DIR), dir.join("registry-moved")).unwrap();
        std::os::unix::fs::symlink(dir.join("registry-moved"), dir.join(ROOM_DIR)).unwrap();
        // The pinned open is O_NOFOLLOW → ELOOP → typed Err, NOT a false-empty Ok(vec![]).
        assert!(
            read_dir_with_stems(data_dir, ROOM_DIR).is_err(),
            "a symlinked registry directory is a typed error"
        );
        assert!(
            sorted_newest(data_dir).is_err(),
            "list surfaces the error, never a false-empty list"
        );
        assert!(list_rooms_exact(data_dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn receipt_commit_from_anonymous_descriptor_leaves_no_residue() {
        // #72 round 20 findings 1+3: the O_TMPFILE commit binds bytes to the DESCRIPTOR (no
        // swappable named source) and leaves NO temp residue — the directory holds exactly the
        // target file with nlink 1, and a byte-identical replay adds nothing.
        use std::os::unix::fs::MetadataExt;
        let dir = temp_dir("tmpfile-commit");
        let data_dir = dir.to_str().unwrap();
        let receipt = json!({ "receipt_id": "receipt://orr_c0", "attested": true });
        persist_receipt_no_clobber(data_dir, "orr_c0", &receipt).unwrap();
        let rdir = dir.join(ROOM_RECEIPT_DIR);
        let names: Vec<String> = std::fs::read_dir(&rdir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names,
            vec!["orr_c0.json".to_string()],
            "exactly the target file — no .nc-* temp residue"
        );
        let meta = std::fs::metadata(rdir.join("orr_c0.json")).unwrap();
        assert_eq!(
            meta.nlink(),
            1,
            "the committed inode has exactly ONE name (no hard-link residue)"
        );
        let on_disk: Value =
            serde_json::from_slice(&std::fs::read(rdir.join("orr_c0.json")).unwrap()).unwrap();
        assert_eq!(
            on_disk, receipt,
            "the committed bytes are exactly ours (descriptor-bound, unswappable)"
        );
        // Idempotent replay: still exactly one file, still nlink 1.
        persist_receipt_no_clobber(data_dir, "orr_c0", &receipt).unwrap();
        let names2: Vec<String> = std::fs::read_dir(&rdir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names2,
            vec!["orr_c0.json".to_string()],
            "replay leaves no residue either"
        );
        assert_eq!(
            std::fs::metadata(rdir.join("orr_c0.json")).unwrap().nlink(),
            1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scanner_skips_symlink_and_noncanonical_entries() {
        // #72 round 20 finding 2: the room scanner re-resolves each name O_NOFOLLOW relative to a
        // pinned fd and canonicalizes the stem first — a symlinked entry (even one named like a
        // canonical room) and a non-canonical stem never enter the trusted set.
        let dir = temp_dir("scanner");
        let data_dir = dir.to_str().unwrap();
        let (_i, room, _rid, _rcpt) = canonical_admission("or_c1");
        persist_atomic(data_dir, ROOM_DIR, "or_c1", &room).unwrap();
        // An external file with forged content, symlinked into the room dir under a canonical name.
        std::fs::write(
            dir.join("EXTERNAL.json"),
            serde_json::to_vec(
                &json!({ "outcome_room_id": "outcome-room://or_c2", "forged": true }),
            )
            .unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            dir.join("EXTERNAL.json"),
            dir.join(ROOM_DIR).join("or_c2.json"),
        )
        .unwrap();
        // A real file under a NON-canonical stem (uppercase / non-hex).
        std::fs::write(
            dir.join(ROOM_DIR).join("or_ZZ.json"),
            serde_json::to_vec(&json!({ "outcome_room_id": "outcome-room://or_ZZ" })).unwrap(),
        )
        .unwrap();
        let stems: Vec<String> = read_dir_with_stems(data_dir, ROOM_DIR)
            .unwrap()
            .into_iter()
            .map(|(s, _)| s)
            .collect();
        assert_eq!(
            stems,
            vec!["or_c1".to_string()],
            "only the genuine canonical regular file is scanned"
        );
        let listed: Vec<String> = sorted_newest(data_dir)
            .unwrap()
            .into_iter()
            .filter_map(|r| r["outcome_room_id"].as_str().map(str::to_string))
            .collect();
        assert_eq!(
            listed,
            vec!["outcome-room://or_c1".to_string()],
            "the symlink's forged content never reaches the public list"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backlink_seam_binds_receipted_refuses_typed_and_replays_byte_exact() {
        // #74: the room-owned backlink seam — the ONLY path an object plane has to a room
        // record — is receipted, duplicate-refusing, open-room-only, and its sealed intent
        // replays byte-exactly through the SAME completer as every other room transition.
        let dir = temp_dir("backlink");
        let data_dir = dir.to_str().unwrap();
        let (_i, room, _rid, _rcpt) = canonical_admission("or_91");
        persist_atomic(data_dir, ROOM_DIR, "or_91", &room).unwrap();
        let (updated, receipt) = bind_room_backlink(
            data_dir,
            "outcome-room://or_91",
            "participation_request_bound",
            "participation-request://rpr_91",
        )
        .unwrap();
        assert_eq!(
            updated["participation_request_refs"],
            json!(["participation-request://rpr_91"])
        );
        assert_eq!(updated["revision"], json!(2));
        assert_eq!(receipt["op"], json!("participation_request_bound"));
        assert_eq!(
            receipt["bound_facts"]["bound_ref"],
            json!("participation-request://rpr_91")
        );
        let (code, _) = bind_room_backlink(
            data_dir,
            "outcome-room://or_91",
            "participation_request_bound",
            "participation-request://rpr_91",
        )
        .unwrap_err();
        assert_eq!(code, "outcome_room_backlink_already_bound");
        let (code, _) = bind_room_backlink(
            data_dir,
            "outcome-room://or_91",
            "frontier_item_bound",
            "frontier://x",
        )
        .unwrap_err();
        assert_eq!(code, "outcome_room_backlink_ref_invalid");
        let frontier_ref = format!("frontier://wfi_{}", "a".repeat(64));
        let (frontier_bound, frontier_receipt) = bind_room_backlink(
            data_dir,
            "outcome-room://or_91",
            "frontier_item_bound",
            &frontier_ref,
        )
        .unwrap();
        assert_eq!(frontier_bound["frontier_item_refs"], json!([frontier_ref]));
        assert_eq!(frontier_receipt["op"], json!("frontier_item_bound"));
        let (code, _) = bind_room_backlink(
            data_dir,
            "outcome-room://or_91",
            "participant_lease_bound",
            "participation-request://wrong-scheme",
        )
        .unwrap_err();
        assert_eq!(code, "outcome_room_backlink_ref_invalid");
        let (_i2, mut closed, _rid2, _rcpt2) = canonical_admission("or_92");
        closed
            .as_object_mut()
            .unwrap()
            .insert("status".into(), json!("closed"));
        persist_atomic(data_dir, ROOM_DIR, "or_92", &closed).unwrap();
        let (code, _) = bind_room_backlink(
            data_dir,
            "outcome-room://or_92",
            "participation_request_bound",
            "participation-request://rpr_92",
        )
        .unwrap_err();
        assert_eq!(code, "outcome_room_not_open");
        // CRASH REPLAY: seal a canonical backlink intent and let the ROOM completer converge it.
        let prior = load_room(data_dir, "outcome-room://or_91").unwrap();
        let now = json!("2026-03-01T00:00:00Z");
        let receipt_ref = json!("receipt://ort_9b");
        let prior_rev = prior["revision"].as_u64().unwrap();
        let mut expected = prior.clone();
        {
            let obj = expected.as_object_mut().unwrap();
            let mut arr: Vec<Value> = obj
                .get("participant_lease_refs")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            arr.push(json!("participant-lease://rpl_91"));
            obj.insert("participant_lease_refs".into(), Value::Array(arr));
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
            history.push(json!({ "op": "participant_lease_bound", "at": now, "receipt_ref": receipt_ref, "revision": prior_rev + 1 }));
            obj.insert("status_history".into(), Value::Array(history));
        }
        let sealed_receipt = build_room_receipt_at(
            "ort_9b",
            TRANSITION_RECEIPT_SCHEMA,
            "OutcomeRoomTransitionReceipt",
            "outcome-room://or_91",
            "participant_lease_bound",
            json!({ "list_field": "participant_lease_refs", "bound_ref": "participant-lease://rpl_91", "revision_before": prior_rev, "revision_after": prior_rev + 1 }),
            vec![
                json!("outcome-room://or_91"),
                json!("participant-lease://rpl_91"),
            ],
            record_output_hash(&expected, TRANSITION_HASH_EXCLUDES),
            TRANSITION_HASH_EXCLUDES,
            "admitted_not_verified",
            BACKLINK_NOTE,
            "2026-03-01T00:00:00Z",
        );
        let mut carrying = prior.clone();
        carrying.as_object_mut().unwrap().insert("transition_intent".into(), json!({
            "op": "participant_lease_bound",
            "final_room": expected, "final_room_hash": record_output_hash(&expected, &[]),
            "receipt_id": "ort_9b", "receipt": sealed_receipt, "receipt_hash": record_output_hash(&sealed_receipt, &[]),
            "at": "2026-03-01T00:00:00Z",
        }));
        persist_atomic(data_dir, ROOM_DIR, "or_91", &carrying).unwrap();
        complete_room_intents(data_dir);
        let converged = load_room(data_dir, "outcome-room://or_91").unwrap();
        assert_eq!(
            converged["participant_lease_refs"],
            json!(["participant-lease://rpl_91"]),
            "the sealed backlink applied byte-exactly"
        );
        assert!(
            converged.get("transition_intent").is_none(),
            "intent consumed"
        );
        // FORGED backlink (ref not in the receipt's reconstruction) never converges.
        let mut lying = converged.clone();
        let mut bad_final = expected.clone();
        bad_final.as_object_mut().unwrap().insert(
            "participant_lease_refs".into(),
            json!(["participant-lease://rpl_FORGED"]),
        );
        lying.as_object_mut().unwrap().insert("transition_intent".into(), json!({
            "op": "participant_lease_bound",
            "final_room": bad_final, "final_room_hash": record_output_hash(&bad_final, &[]),
            "receipt_id": "ort_9c", "receipt": sealed_receipt, "receipt_hash": record_output_hash(&sealed_receipt, &[]),
            "at": "2026-03-01T00:00:00Z",
        }));
        persist_atomic(data_dir, ROOM_DIR, "or_91", &lying).unwrap();
        complete_room_intents(data_dir);
        let after = load_room_file(data_dir, "or_91").unwrap();
        assert!(
            after.get("transition_intent").is_some(),
            "the forged backlink intent is retained, never applied"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn room_reads_refuse_path_traversal_stems() {
        // #72 round 19 finding 1: a URL-derived `../…` stem must never reach a path join — a
        // matching record planted OUTSIDE the room directory is invisible to every read path.
        let dir = temp_dir("traversal");
        let data_dir = dir.to_str().unwrap();
        let planted = json!({ "outcome_room_id": "outcome-room://../goal-runs/gr_esc", "status": "open", "schema_version": ROOM_SCHEMA });
        std::fs::create_dir_all(dir.join("goal-runs")).unwrap();
        std::fs::write(
            dir.join("goal-runs/gr_esc.json"),
            serde_json::to_vec_pretty(&planted).unwrap(),
        )
        .unwrap();
        assert!(
            load_room(data_dir, "outcome-room://../goal-runs/gr_esc").is_none(),
            "traversal id refused BEFORE any filesystem access"
        );
        assert!(
            resolve_open_room(data_dir, "outcome-room://../goal-runs/gr_esc").is_none(),
            "cross-plane binding resolution refuses the traversal id"
        );
        assert!(
            load_room_file(data_dir, "../goal-runs/gr_esc").is_none(),
            "non-canonical stems never reach a path join"
        );
        // A SYMLINKED room slot is equally invisible (pinned no-follow read).
        let (_i, room, _rid, _rcpt) = canonical_admission("or_a0");
        std::fs::create_dir_all(dir.join(ROOM_DIR)).unwrap();
        std::fs::write(
            dir.join(ROOM_DIR).join("real.json"),
            serde_json::to_vec_pretty(&room).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink("real.json", dir.join(ROOM_DIR).join("or_a0.json")).unwrap();
        assert!(
            load_room(data_dir, "outcome-room://or_a0").is_none(),
            "a symlinked room slot is refused (O_NOFOLLOW)"
        );
        assert!(
            sorted_newest(data_dir).unwrap().is_empty(),
            "neither the symlink nor the non-canonical stem is listed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn receipt_writer_refuses_unreadable_and_symlink_occupants() {
        // #72 round 19 finding 3: only ENOENT means empty — an unreadable (mode 000) or
        // symlinked occupant REFUSES; nothing is overwritten. (Runs as non-root: mode 000
        // genuinely blocks the open.)
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("strict-slot");
        let data_dir = dir.to_str().unwrap();
        let foreign = json!({ "foreign": "evidence" });
        persist_atomic(data_dir, ROOM_RECEIPT_DIR, "orr_aa", &foreign).unwrap();
        let slot = dir.join(ROOM_RECEIPT_DIR).join("orr_aa.json");
        std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o000)).unwrap();
        let ours = json!({ "receipt_id": "receipt://orr_aa", "mine": true });
        let (code, _) = persist_receipt_no_clobber(data_dir, "orr_aa", &ours).unwrap_err();
        assert_eq!(
            code, "outcome_room_receipt_slot_unreadable",
            "an unreadable occupant is REFUSED, never treated as empty"
        );
        std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o644)).unwrap();
        let on_disk: Value = serde_json::from_slice(&std::fs::read(&slot).unwrap()).unwrap();
        assert_eq!(
            on_disk, foreign,
            "the unreadable occupant was NOT overwritten"
        );
        // Symlinked occupant: refused at the open (O_NOFOLLOW), the link survives as a link.
        std::os::unix::fs::symlink(
            "orr_aa.json",
            dir.join(ROOM_RECEIPT_DIR).join("orr_ab.json"),
        )
        .unwrap();
        let (code2, _) = persist_receipt_no_clobber(data_dir, "orr_ab", &ours).unwrap_err();
        assert_eq!(code2, "outcome_room_receipt_slot_unreadable");
        assert!(
            std::fs::symlink_metadata(dir.join(ROOM_RECEIPT_DIR).join("orr_ab.json"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink occupant was NOT replaced"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_completer_refuses_an_unreadable_receipt_slot() {
        // #72 round 19 finding 3, end-to-end: a mode-000 occupant at the sealed receipt slot
        // blocks admission at boot — occupant untouched, room absent, intent retained.
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("slot-000");
        let data_dir = dir.to_str().unwrap();
        let (intent, _room, rid, _rcpt) = canonical_admission("or_a1");
        let foreign = json!({ "foreign": "evidence", "sentinel": "KEEP" });
        persist_atomic(data_dir, ROOM_RECEIPT_DIR, &rid, &foreign).unwrap();
        let slot = dir.join(ROOM_RECEIPT_DIR).join(format!("{rid}.json"));
        std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o000)).unwrap();
        persist_atomic(data_dir, ADMISSION_INTENT_DIR, "or_a1", &intent).unwrap();
        complete_room_intents(data_dir);
        assert!(
            load_room_file(data_dir, "or_a1").is_none(),
            "the room was NOT admitted over an unreadable receipt slot"
        );
        assert_eq!(
            read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(),
            1,
            "intent retained for manual repair"
        );
        std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o644)).unwrap();
        let on_disk: Value = serde_json::from_slice(&std::fs::read(&slot).unwrap()).unwrap();
        assert_eq!(
            on_disk, foreign,
            "the unreadable occupant survived byte-for-byte"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn receipt_writer_is_append_only_no_clobber() {
        // #72 round 18 finding 1: a canonical receipt slot already holding DIFFERENT evidence is
        // NEVER overwritten; byte-identical content is idempotent.
        let dir = temp_dir("no-clobber");
        let data_dir = dir.to_str().unwrap();
        let foreign = json!({ "foreign": "evidence", "sentinel": "DO_NOT_ERASE" });
        persist_atomic(data_dir, ROOM_RECEIPT_DIR, "orr_deadbeef", &foreign).unwrap();
        let ours = json!({ "receipt_id": "receipt://orr_deadbeef", "mine": true });
        let (code, _) = persist_receipt_no_clobber(data_dir, "orr_deadbeef", &ours).unwrap_err();
        assert_eq!(
            code, "outcome_room_receipt_conflict",
            "a different occupant is refused"
        );
        let on_disk: Value = serde_json::from_slice(
            &std::fs::read(dir.join(ROOM_RECEIPT_DIR).join("orr_deadbeef.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            on_disk, foreign,
            "the foreign sentinel evidence is UNTOUCHED"
        );
        // Idempotent: writing the SAME bytes that are already there is Ok, no error.
        persist_receipt_no_clobber(data_dir, "orr_cafe", &ours).unwrap();
        persist_receipt_no_clobber(data_dir, "orr_cafe", &ours).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_completer_refuses_when_the_receipt_slot_is_occupied() {
        // #72 round 18 finding 1, end-to-end: a foreign occupant at the sealed receipt tail
        // blocks admission — the room is NOT admitted, the sentinel survives, the intent stays.
        let dir = temp_dir("slot-occupied");
        let data_dir = dir.to_str().unwrap();
        let (intent, _room, rid, _rcpt) = canonical_admission("or_90");
        let foreign = json!({ "foreign": "evidence", "sentinel": "KEEP" });
        persist_atomic(data_dir, ROOM_RECEIPT_DIR, &rid, &foreign).unwrap();
        persist_atomic(data_dir, ADMISSION_INTENT_DIR, "or_90", &intent).unwrap();
        complete_room_intents(data_dir);
        assert!(
            load_room_file(data_dir, "or_90").is_none(),
            "the room was NOT admitted over an occupied receipt slot"
        );
        let on_disk: Value = serde_json::from_slice(
            &std::fs::read(dir.join(ROOM_RECEIPT_DIR).join(format!("{rid}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            on_disk, foreign,
            "the foreign sentinel evidence is UNTOUCHED"
        );
        assert_eq!(
            read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(),
            1,
            "intent retained for manual repair"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relocated_room_file_is_invisible_to_every_read_path() {
        // #72 round 18 finding 2: a valid room moved to a DIFFERENT canonical filename (content
        // id no longer matches its stem) is invisible via get/list/resolve — one identity can
        // never map to two files.
        let dir = temp_dir("relocated");
        let data_dir = dir.to_str().unwrap();
        let (_intent, room, _rid, _rcpt) = canonical_admission("or_91");
        // Store the room (claiming outcome-room://or_91) at a DIFFERENT stem or_92.json.
        persist_atomic(data_dir, ROOM_DIR, "or_92", &room).unwrap();
        // GET by the ORIGINAL id: the file or_91.json does not exist → None.
        assert!(
            load_room(data_dir, "outcome-room://or_91").is_none(),
            "GET original id: no file at that stem"
        );
        // GET by the NEW filename's id: content id (or_91) != stem (or_92) → None.
        assert!(
            load_room(data_dir, "outcome-room://or_92").is_none(),
            "GET new stem: content id != stem, refused"
        );
        // LIST/resolve exclude the relocated file entirely.
        assert!(
            sorted_newest(data_dir).unwrap().is_empty(),
            "the relocated room is not listed"
        );
        assert!(resolve_open_room(data_dir, "outcome-room://or_91").is_none());
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
        assert!(
            load_room_file(data_dir, "or_81").is_none(),
            "the mismatched-stem intent was NOT admitted"
        );
        assert!(
            load_room_file(data_dir, "or_80").is_none(),
            "and nothing was written under the content id either"
        );
        assert!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(),
            "no receipt persisted"
        );
        assert_eq!(
            read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(),
            1,
            "intent retained for manual repair"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_atomic_rejects_a_normalization_unsafe_key() {
        // #72 round 17 finding 2: `ort/collision` and `ort_collision` would normalize to the same
        // file — the room writer rejects unsafe keys instead of colliding.
        let dir = temp_dir("norm-safe");
        let data_dir = dir.to_str().unwrap();
        persist_atomic(
            data_dir,
            ROOM_RECEIPT_DIR,
            "ort_deadbeef",
            &json!({ "ok": true }),
        )
        .unwrap();
        let err = persist_atomic(
            data_dir,
            ROOM_RECEIPT_DIR,
            "ort/collision",
            &json!({ "evil": true }),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            super::super::durable_fs::PersistFailure::NotCommitted(_)
        ));
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
        assert!(
            load_room_file(data_dir, "or_82").is_none(),
            "a null-timestamp room was NOT admitted"
        );
        assert!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(),
            "no receipt persisted"
        );
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
        for k in [
            "owner_or_sponsor_ref",
            "objective_ref",
            "objective",
            "host_domain_ref",
            "room_mode",
            "coordination_topology",
            "stop_policy_ref",
            "visibility_policy_ref",
            "participation_policy_ref",
            "privacy_policy_ref",
            "contribution_policy_ref",
            "coordination_policy_ref",
            "ordering_and_merge_policy_ref",
            "conflict_and_failover_policy_ref",
        ] {
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
        assert!(
            load_room(data_dir, "outcome-room://or_73").is_none(),
            "the hollow envelope was NOT admitted"
        );
        assert!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(),
            "no receipt persisted for a hollow envelope"
        );
        assert_eq!(
            read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(),
            1,
            "intent retained for manual repair"
        );
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
        assert_eq!(
            serde_json::to_vec(&after).unwrap(),
            pending_bytes,
            "room byte-unchanged — the lying receipt never became durable"
        );
        assert_eq!(after["status"], json!("open"), "status never advanced");
        assert!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(),
            "no false receipt persisted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attach_replay_refuses_a_truthful_membership_with_a_lying_receipt() {
        // #72 round 16 finding 2: the membership successor is correct, but the attach receipt
        // lies about the run and reciprocal-stamp facts. Refused — run never stamped, no receipt.
        let dir = temp_dir("lying-attach");
        let data_dir = dir.to_str().unwrap();
        let (_ai, prior, _arid, _arcpt) = canonical_admission("or_75");
        persist_atomic(
            data_dir,
            GOAL_RUN_DIR,
            "gr_la",
            &json!({ "goal_run_id": "gr_la", "status": "active" }),
        )
        .unwrap();
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
        assert_eq!(
            serde_json::to_vec(&after).unwrap(),
            with_bytes,
            "room byte-unchanged"
        );
        let run = read_record_dir(data_dir, GOAL_RUN_DIR).pop().unwrap();
        assert!(
            run.get("outcome_room_ref").is_none(),
            "the run was NEVER stamped for a lying attach receipt"
        );
        assert!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(),
            "no false receipt persisted"
        );
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
        receipt["hash_scope_excludes"] = json!(ROOM_HASH_EXCLUDES
            .iter()
            .copied()
            .chain(["objective", "owner_or_sponsor_ref"])
            .collect::<Vec<_>>());
        receipt["output_hash"] = json!(record_output_hash(
            &final_room,
            &ROOM_HASH_EXCLUDES
                .iter()
                .copied()
                .chain(["objective", "owner_or_sponsor_ref"])
                .collect::<Vec<_>>()
        ));
        let forged = json!({
            "room_tail": "or_fa", "room_ref": "outcome-room://or_fa",
            "receipt_id": canonical["receipt_id"], "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "final_room": final_room, "final_room_hash": record_output_hash(&final_room, &[]), "at": "2026-01-01T00:00:00Z",
        });
        persist_atomic(data_dir, ADMISSION_INTENT_DIR, "or_fa", &forged).unwrap();
        assert!(
            load_room(data_dir, "outcome-room://or_fa").is_none(),
            "the room is ABSENT — the normal recovery state"
        );
        complete_room_intents(data_dir);
        assert!(
            load_room(data_dir, "outcome-room://or_fa").is_none(),
            "the forged room was NOT admitted"
        );
        assert!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(),
            "no receipt was persisted for the forgery"
        );
        assert_eq!(
            read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(),
            1,
            "the intent is retained for manual repair"
        );
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
        assert_eq!(
            after["status"],
            json!("open"),
            "the visible status never advanced to the forged 'accepted'"
        );
        assert!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(),
            "no receipt was persisted for the forged transition"
        );
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
        persist_atomic(
            data_dir,
            GOAL_RUN_DIR,
            "gr_fm",
            &json!({ "goal_run_id": "gr_fm", "status": "active" }),
        )
        .unwrap();
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
        assert!(
            after.get("attach_intent").is_some(),
            "the forged intent is retained (refused, not applied)"
        );
        assert_eq!(
            after["member_goal_run_refs"],
            json!([]),
            "no membership was manufactured"
        );
        let run = read_record_dir(data_dir, GOAL_RUN_DIR).pop().unwrap();
        assert!(
            run.get("outcome_room_ref").is_none(),
            "the run was NEVER stamped for a forged successor"
        );
        assert!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(),
            "no receipt was persisted"
        );
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
        let widened: Vec<&str> = ROOM_HASH_EXCLUDES
            .iter()
            .copied()
            .chain(["objective", "owner_or_sponsor_ref"])
            .collect();
        // The receipt's output_hash is computed over the tampered room under the WIDENED scope,
        // so declaration_ok would pass if the completer trusted the receipt's own scope.
        let (rid, mut receipt) = build_room_receipt(
            ADMISSION_RECEIPT_SCHEMA,
            "OutcomeRoomAdmissionReceipt",
            "orr",
            "outcome-room://or_78",
            "admitted",
            json!({}),
            vec![],
            record_output_hash(&tampered, &widened),
            ROOM_HASH_EXCLUDES,
            "admitted_not_verified",
            "n",
            "2026-01-01T00:00:00Z",
        );
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
        let room_bytes =
            serde_json::to_vec(&load_room(data_dir, "outcome-room://or_78").unwrap()).unwrap();
        complete_room_intents(data_dir);
        let after = load_room(data_dir, "outcome-room://or_78").unwrap();
        assert_eq!(
            serde_json::to_vec(&after).unwrap(),
            room_bytes,
            "the tampered room is byte-for-byte unchanged — the widened scope did not admit it"
        );
        assert!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(),
            "NO receipt was persisted for the forged admission"
        );
        assert_eq!(
            read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(),
            1,
            "the intent is retained for manual repair"
        );
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
        let (rid, receipt) = build_room_receipt(
            ADMISSION_RECEIPT_SCHEMA,
            "OutcomeRoomAdmissionReceipt",
            "orr",
            "outcome-room://or_79",
            "admitted",
            json!({}),
            vec![],
            record_output_hash(&final_room, ROOM_HASH_EXCLUDES),
            ROOM_HASH_EXCLUDES,
            "admitted_not_verified",
            "n",
            "2026-01-01T00:00:00Z",
        );
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
        let tampered_bytes =
            serde_json::to_vec(&load_room(data_dir, "outcome-room://or_79").unwrap()).unwrap();
        complete_room_intents(data_dir);
        let after = load_room(data_dir, "outcome-room://or_79").unwrap();
        assert_eq!(
            serde_json::to_vec(&after).unwrap(),
            tampered_bytes,
            "the room is byte-for-byte unchanged — neither receipted over nor 'repaired'"
        );
        assert!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(),
            "NO receipt was persisted for an admission the declaration does not prove"
        );
        assert_eq!(
            read_record_dir(data_dir, ADMISSION_INTENT_DIR).len(),
            1,
            "the intent is retained for manual repair"
        );
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
        assert_eq!(
            run["outcome_room_ref"],
            json!("outcome-room://or_7c"),
            "room B's reciprocal binding is UNTOUCHED"
        );
        let room_a = load_room(data_dir, "outcome-room://or_7a").unwrap();
        assert!(
            room_a.get("attach_intent").is_some(),
            "room A's intent is left as a manual conflict, never overwritten"
        );
        assert_eq!(
            room_a["member_goal_run_refs"],
            json!([]),
            "room A gained no membership"
        );
        assert!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(),
            "no receipt was manufactured"
        );
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
        assert!(
            room_after.get("attach_intent").is_none(),
            "the intent was rolled back"
        );
        assert_eq!(
            room_after["member_goal_run_refs"],
            json!([]),
            "no membership was manufactured"
        );
        assert!(
            read_record_dir(data_dir, ROOM_RECEIPT_DIR).is_empty(),
            "no receipt was manufactured"
        );
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
        persist_atomic(
            data_dir,
            GOAL_RUN_DIR,
            "gr_race",
            &json!({ "goal_run_id": "gr_race", "status": "active", "normalized_goal": "x" }),
        )
        .unwrap();
        // 1. "reconcile reads first" — the stale snapshot exists (and is deliberately unused for
        //    the persist; the old bug persisted exactly this value wholesale).
        let stale_snapshot = read_record_dir(data_dir, GOAL_RUN_DIR).pop().unwrap();
        assert!(stale_snapshot.get("outcome_room_ref").is_none());
        // 2. "attach lands second" — the stamp goes through the seam.
        super::super::goalrun_routes::update_goal_run_guarded(
            data_dir,
            "gr_race",
            |_| Ok(()),
            |obj| {
                obj.insert("outcome_room_ref".into(), json!("outcome-room://or_race"));
            },
        )
        .unwrap();
        // 3. "reconcile persists last" — through the seam, merging ONLY its lifecycle fields.
        let merged = super::super::goalrun_routes::update_goal_run_guarded(
            data_dir,
            "gr_race",
            |_| Ok(()),
            |obj| {
                obj.insert("status".into(), json!("complete"));
                obj.insert(
                    "reconciliation_ref".into(),
                    json!("reconciliation_result://rec_1"),
                );
            },
        )
        .unwrap()
        .into_record();
        assert_eq!(
            merged["status"],
            json!("complete"),
            "the reconciliation state survived"
        );
        assert_eq!(
            merged["outcome_room_ref"],
            json!("outcome-room://or_race"),
            "the reciprocal room binding SURVIVED the later lifecycle persist"
        );
        let durable = read_record_dir(data_dir, GOAL_RUN_DIR).pop().unwrap();
        assert_eq!(durable["outcome_room_ref"], json!("outcome-room://or_race"));
        assert_eq!(
            durable["reconciliation_ref"],
            json!("reconciliation_result://rec_1")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_receipt_carries_the_pinned_envelope_base() {
        let (_, receipt) = build_room_receipt(
            ADMISSION_RECEIPT_SCHEMA,
            "OutcomeRoomAdmissionReceipt",
            "orr",
            "outcome-room://or_k",
            "admitted",
            json!({ "room_mode": "private_goal" }),
            vec![json!("outcome-room://or_k")],
            "sha256:x".into(),
            ROOM_HASH_EXCLUDES,
            "admitted_not_verified",
            "n",
            "2026-01-01T00:00:00Z",
        );
        let expected = [
            "schema_version",
            "receipt_id",
            "receipt_ref",
            "receipt_type",
            "receipt_profile_ref",
            "actor_id",
            "subject_ref",
            "op",
            "attested_boundary_fact_refs",
            "bound_facts",
            "output_hash",
            "hash_scope_excludes",
            "assurance_posture",
            "assurance_note",
            "verification_ref",
            "acceptance_ref",
            "claim_scope_ref",
            "run_id",
            "task_id",
            "input_hash",
            "policy_hash",
            "authority_grant_id",
            "primitive_capabilities",
            "authority_scopes",
            "artifact_refs",
            "evidence_bundle_refs",
            "adjudication_ref",
            "settlement_ref",
            "signature",
            "l1_commitment",
            "timestamp",
            "outcome",
            "at",
        ];
        let mut exp: Vec<&str> = expected.to_vec();
        exp.sort_unstable();
        let mut actual: Vec<String> = receipt.as_object().unwrap().keys().cloned().collect();
        actual.sort_unstable();
        assert_eq!(
            actual,
            exp.iter().map(|k| k.to_string()).collect::<Vec<_>>(),
            "room receipt base drifted from the pinned ReceiptEnvelope key set"
        );
    }
}
