//! Hosted-room work frontier + bounded claim plane — build step 3, second pair (#76).
//!
//! `WorkFrontierItem` is the room's claimable shared-work graph. `WorkClaimLease` is a bounded,
//! participant-owned lease on one item; it is not ambient authority and it never implies result
//! acceptance. Hosted admission only: wallet.network authenticates each host/participant
//! decision through the exact #74 CallService/TLS/root-proof boundary. Requirement-bearing claims
//! consume exact ResourceOffer/CapabilityOffer eligibility receipts; those receipts confer neither
//! allocation nor execution authority. Federated/AIIP admission, attempts, findings, verifier
//! acceptance, and reassignment remain typed unavailable.
//!
//! Cross-plane ownership is strict. This module never writes OutcomeRoom or RoomParticipantLease
//! files: it calls their owner seams while holding the fixed lock order participation -> resource
//! inventory -> offer/match -> frontier/claim -> room. All wallet awaits happen before synchronous
//! locks.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Map, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::governed_authority::{
    self as governed, AuthorityContract, AuthorizedDecision, Governance,
};
use super::outcome_room_routes::{
    self as rooms, build_room_receipt_at, record_output_hash, s, VErr,
};
use super::room_participation_routes as participation;
use super::DaemonState;

const FRONTIER_SCHEMA: &str = "ioi.hypervisor.work-frontier-item.v1";
const CLAIM_SCHEMA: &str = "ioi.hypervisor.work-claim-lease.v1";
const FRONTIER_RECEIPT_SCHEMA: &str = "ioi.hypervisor.work-frontier-mutation-receipt.v1";
const CLAIM_RECEIPT_SCHEMA: &str = "ioi.hypervisor.work-claim-lease-receipt.v1";
const INTENT_SCHEMA: &str = "ioi.hypervisor.work-frontier-claim-intent.v1";

pub(crate) const FRONTIER_DIR: &str = "work-frontier-items";
pub(crate) const CLAIM_DIR: &str = "work-claim-leases";
const RECEIPT_DIR: &str = "work-frontier-claim-receipts";
const INTENT_DIR: &str = "work-frontier-claim-intents";

const FRONTIER_NOTE: &str = "an admitted hosted-room frontier mutation — admission is not result verification or acceptance";
const CLAIM_NOTE: &str = "an admitted bounded work-claim mutation — the claim grants only declared refs and preserves terminal lineage";

const ITEM_KINDS: &[&str] = &[
    "question",
    "problem",
    "hypothesis",
    "task",
    "review_need",
    "verification_need",
    "resource_need",
    "synthesis_need",
];
const DUPLICATION_POLICIES: &[&str] = &[
    "exclusive",
    "allowed",
    "encouraged",
    "independent_replication_required",
];
const CLAIMABILITIES: &[&str] = &["open", "invited_only", "assigned", "paused", "closed"];
const FRONTIER_STATUSES: &[&str] = &[
    "open",
    "claimed",
    "blocked",
    "replicating",
    "verifying",
    "accepted",
    "rejected",
    "superseded",
    "closed",
];
const CLAIM_DUPLICATION_POLICIES: &[&str] = &[
    "exclusive",
    "allowed",
    "independent_replication",
    "adversarial_replication",
];
const CLAIM_STATUSES: &[&str] = &[
    "proposed",
    "active",
    "waiting",
    "released",
    "expired",
    "reassigned",
    "completed",
    "quarantined",
    "revoked",
];

const FRONTIER_TRANSITIONS: &[(&str, &[&str], &str)] = &[
    ("block", &["open"], "blocked"),
    (
        "reopen",
        &["blocked", "verifying", "rejected", "closed"],
        "open",
    ),
    ("close", &["open", "blocked", "verifying"], "closed"),
    ("reject", &["open", "blocked", "verifying"], "rejected"),
    ("supersede", &["open", "blocked", "verifying"], "superseded"),
];

const CLAIM_TERMINAL: &[&str] = &["released", "expired", "completed", "quarantined", "revoked"];
const CLAIM_TTL_MIN_SECONDS: u64 = 30;
const CLAIM_TTL_MAX_SECONDS: u64 = 86_400;
const CLAIM_RENEWAL_MAX: u64 = 16;
const ROOM_FRONTIER_MAX: usize = 256;
const ITEM_CONCURRENCY_MAX: u64 = 16;
const REF_MAX: usize = 300;
const OBJECTIVE_MAX: usize = 4_000;
const REASON_MAX: usize = 1_000;
const LIST_MAX: usize = 64;
const HISTORY_MAX: usize = 100;

const FRONTIER_AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "work_frontier",
    policy_domain: "hypervisor.work-frontier.decision.policy.v1",
    request_domain: "hypervisor.work-frontier.decision.request.v1",
    resolution_domain: "hypervisor.work-frontier.authority-resolution.v1",
    code_prefix: "work_frontier",
    host_label: "room_host",
    participant_label: "participant_claimant",
};

const CLAIM_AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "work_claim",
    policy_domain: "hypervisor.work-claim.decision.policy.v1",
    request_domain: "hypervisor.work-claim.decision.request.v1",
    resolution_domain: "hypervisor.work-claim.authority-resolution.v1",
    code_prefix: "work_claim",
    host_label: "room_host",
    participant_label: "participant_claimant",
};

/// Fixed lock order: participation -> resource inventory -> offer/match -> frontier/claim -> room.
/// Public for the owner-plane orchestration entrypoints; callers never await while holding it.
pub(crate) static FRONTIER_CLAIM_LOCK: Mutex<()> = Mutex::new(());
static TEST_ACQUIRE_BARRIERS: OnceLock<
    tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Barrier>>>,
> = OnceLock::new();

const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "password",
    "secret",
    "credential",
    "authorization",
    "privatekey",
    "apikey",
    "token",
];

fn verr(code: &str, message: impl Into<String>) -> VErr {
    (code.to_string(), message.into())
}

fn classify(error: VErr) -> (StatusCode, Json<Value>) {
    let (code, message) = error;
    let status = if code.ends_with("_not_found") {
        StatusCode::NOT_FOUND
    } else if code.contains("stale_revision")
        || code.contains("eligibility_stale")
        || code.contains("conflict")
        || code.contains("capacity")
        || code.contains("current_claim")
        || code.contains("not_active")
        || code.contains("in_flight")
        || code.contains("not_open")
        || code.contains("dependencies_unresolved")
    {
        StatusCode::CONFLICT
    } else if code.contains("unavailable") {
        StatusCode::NOT_IMPLEMENTED
    } else if code.contains("pending_convergence")
        || code.contains("unreadable")
        || code.contains("persist_failed")
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (
        status,
        Json(json!({
            "error": { "code": code, "message": message, "runtimeTruthSource": "daemon-runtime" }
        })),
    )
}

fn reject_sensitive_keys(value: &Value, path: &str) -> Result<(), VErr> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let normalized: String = key
                    .to_lowercase()
                    .chars()
                    .filter(|character| !matches!(character, '_' | '-' | ' ' | '.'))
                    .collect();
                if SENSITIVE_KEY_FRAGMENTS
                    .iter()
                    .any(|fragment| normalized.contains(fragment))
                    && !child.is_null()
                {
                    return Err(verr(
                        "work_frontier_claim_plaintext_secret_rejected",
                        format!("sensitive key '{path}{key}' is never admitted; store only governed refs"),
                    ));
                }
                reject_sensitive_keys(child, &format!("{path}{key}."))?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                reject_sensitive_keys(item, &format!("{path}{index}."))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn bounded_string(
    body: &Value,
    key: &str,
    max: usize,
    required: bool,
) -> Result<Option<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) if !required => Ok(None),
        None | Some(Value::Null) => Err(verr(
            "work_frontier_claim_field_required",
            format!("'{key}' is required"),
        )),
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() && required {
                return Err(verr(
                    "work_frontier_claim_field_required",
                    format!("'{key}' must not be empty"),
                ));
            }
            if trimmed.chars().count() > max {
                return Err(verr(
                    "work_frontier_claim_field_too_long",
                    format!("'{key}' exceeds {max} characters"),
                ));
            }
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Some(_) => Err(verr(
            "work_frontier_claim_field_type_invalid",
            format!("'{key}' must be a string"),
        )),
    }
}

fn ref_ok(value: &str, schemes: &[&str]) -> bool {
    if schemes.contains(&"scope") {
        if let Some(tail) = value.strip_prefix("scope:") {
            return !tail.is_empty()
                && !tail.starts_with("//")
                && !tail.chars().any(char::is_whitespace)
                && value.len() <= REF_MAX;
        }
    }
    value.split_once("://").is_some_and(|(scheme, tail)| {
        schemes.contains(&scheme) && !tail.is_empty() && value.len() <= REF_MAX
    })
}

fn canonical_tail(tail: &str, prefix: &str) -> bool {
    tail.strip_prefix(prefix).is_some_and(|hex| {
        hex.len() == 64
            && hex
                .chars()
                .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
    })
}

fn canonical_frontier_tail(tail: &str) -> bool {
    canonical_tail(tail, "wfi_")
}

fn canonical_claim_tail(tail: &str) -> bool {
    canonical_tail(tail, "wcl_")
}

fn canonical_intent_tail(tail: &str) -> bool {
    canonical_tail(tail, "wci_")
}

fn canonical_frontier_ref(value: &str) -> bool {
    value
        .strip_prefix("frontier://")
        .is_some_and(canonical_frontier_tail)
}

fn canonical_claim_ref(value: &str) -> bool {
    value
        .strip_prefix("work-claim://")
        .is_some_and(canonical_claim_tail)
}

fn required_ref(body: &Value, key: &str, schemes: &[&str]) -> Result<String, VErr> {
    let value = bounded_string(body, key, REF_MAX, true)?.expect("required");
    if ref_ok(&value, schemes) {
        Ok(value)
    } else {
        Err(verr(
            "work_frontier_claim_ref_invalid",
            format!("'{key}' must be a canonical [{}] ref", schemes.join("|")),
        ))
    }
}

fn optional_ref(body: &Value, key: &str, schemes: &[&str]) -> Result<Option<String>, VErr> {
    match bounded_string(body, key, REF_MAX, false)? {
        None => Ok(None),
        Some(value) if ref_ok(&value, schemes) => Ok(Some(value)),
        Some(_) => Err(verr(
            "work_frontier_claim_ref_invalid",
            format!("'{key}' must be a canonical [{}] ref", schemes.join("|")),
        )),
    }
}

fn ref_list(body: &Value, key: &str, schemes: &[&str]) -> Result<Vec<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) if items.len() <= LIST_MAX => {
            let mut values = Vec::with_capacity(items.len());
            let mut seen = HashSet::new();
            for item in items {
                let Some(value) = item.as_str() else {
                    return Err(verr(
                        "work_frontier_claim_ref_invalid",
                        format!("'{key}' entries must be strings"),
                    ));
                };
                if !ref_ok(value, schemes) || !seen.insert(value.to_string()) {
                    return Err(verr(
                        "work_frontier_claim_ref_invalid",
                        format!("'{key}' contains a noncanonical or duplicate ref '{value}'"),
                    ));
                }
                values.push(value.to_string());
            }
            Ok(values)
        }
        Some(Value::Array(_)) => Err(verr(
            "work_frontier_claim_field_too_long",
            format!("'{key}' exceeds {LIST_MAX} refs"),
        )),
        Some(_) => Err(verr(
            "work_frontier_claim_field_type_invalid",
            format!("'{key}' must be an array"),
        )),
    }
}

fn vocab(body: &Value, key: &str, allowed: &[&str]) -> Result<String, VErr> {
    let value = bounded_string(body, key, 80, true)?.expect("required");
    if allowed.contains(&value.as_str()) {
        Ok(value)
    } else {
        Err(verr(
            "work_frontier_claim_enum_invalid",
            format!("'{key}' must be [{}]", allowed.join("|")),
        ))
    }
}

fn finite_number(body: &Value, key: &str, min: f64, max: f64) -> Result<Value, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::Number(number)) => {
            let Some(value) = number.as_f64() else {
                return Err(verr(
                    "work_frontier_claim_number_invalid",
                    format!("'{key}' must be finite"),
                ));
            };
            if !value.is_finite() || value < min || value > max {
                return Err(verr(
                    "work_frontier_claim_number_invalid",
                    format!("'{key}' must be between {min} and {max}"),
                ));
            }
            Ok(Value::Number(number.clone()))
        }
        Some(_) => Err(verr(
            "work_frontier_claim_number_invalid",
            format!("'{key}' must be a number or null"),
        )),
    }
}

fn expected_revision(body: &Value, current: u64) -> Result<(), VErr> {
    match body.get("expected_revision").and_then(Value::as_u64) {
        Some(expected) if expected == current => Ok(()),
        Some(expected) => Err(verr(
            "work_frontier_claim_stale_revision",
            format!("expected revision {expected}, current revision is {current}"),
        )),
        None => Err(verr(
            "work_frontier_claim_expected_revision_required",
            "every mutation requires unsigned expected_revision",
        )),
    }
}

fn ms_to_rfc3339(milliseconds: u64) -> Result<String, VErr> {
    let nanos = i128::from(milliseconds)
        .checked_mul(1_000_000)
        .ok_or_else(|| {
            verr(
                "work_frontier_claim_wallet_time_invalid",
                "wallet.network resolved_at_ms exceeds the supported timestamp range",
            )
        })?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| {
            verr(
                "work_frontier_claim_wallet_time_invalid",
                "wallet.network resolved_at_ms is not a representable timestamp",
            )
        })?
        .format(&Rfc3339)
        .map_err(|error| verr("work_frontier_claim_wallet_time_invalid", error.to_string()))
}

fn deterministic_tail(prefix: &str, value: &Value) -> String {
    let hash = record_output_hash(value, &[]);
    format!("{prefix}{}", hash.strip_prefix("sha256:").unwrap_or(&hash))
}

fn new_intent_tail(subject_ref: &str, op: &str, revision: u64, resolved_at_ms: u64) -> String {
    deterministic_tail(
        "wci_",
        &json!({
            "domain": "hypervisor.work-frontier-claim.intent-id.v1",
            "subject_ref": subject_ref,
            "op": op,
            "revision": revision,
            "resolved_at_ms": resolved_at_ms,
            "nonce": uuid::Uuid::new_v4().to_string(),
        }),
    )
}

fn new_receipt_tail(
    prefix: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
    resolved_at_ms: u64,
) -> String {
    deterministic_tail(
        prefix,
        &json!({
            "domain": "hypervisor.work-frontier-claim.receipt-id.v1",
            "subject_ref": subject_ref,
            "op": op,
            "revision": revision,
            "resolved_at_ms": resolved_at_ms,
            "nonce": uuid::Uuid::new_v4().to_string(),
        }),
    )
}

// ================================= STRICT DURABLE STORAGE =======================================

fn persist_record(data_dir: &str, family: &str, tail: &str, record: &Value) -> Result<(), VErr> {
    super::durable_fs::persist_record_durable(data_dir, family, tail, record).map_err(|failure| {
        if failure.visible() {
            verr(
                "work_frontier_claim_pending_convergence",
                format!("{family}/{tail} is {}", failure.detail()),
            )
        } else {
            verr(
                "work_frontier_claim_persist_failed",
                format!("{family}/{tail} is {}", failure.detail()),
            )
        }
    })
}

fn persist_receipt(data_dir: &str, tail: &str, receipt: &Value) -> Result<(), VErr> {
    use super::durable_fs::CommitFailure;
    super::durable_fs::persist_receipt_no_clobber(data_dir, RECEIPT_DIR, tail, receipt).map_err(
        |failure| match failure {
            CommitFailure::KeyInvalid(message) => {
                verr("work_frontier_claim_receipt_key_invalid", message)
            }
            CommitFailure::NotCommitted(message) => {
                verr("work_frontier_claim_receipt_persist_failed", message)
            }
            CommitFailure::SlotUnreadable(message) => {
                verr("work_frontier_claim_receipt_unreadable", message)
            }
            CommitFailure::Conflict(message) => {
                verr("work_frontier_claim_receipt_conflict", message)
            }
            CommitFailure::DurabilityUnconfirmed(message) => {
                verr("work_frontier_claim_pending_convergence", message)
            }
            CommitFailure::Swapped(message) => verr("work_frontier_claim_receipt_swapped", message),
        },
    )
}

fn read_slot(
    data_dir: &str,
    family: &str,
    tail: &str,
    canonical: fn(&str) -> bool,
) -> Result<Option<Value>, String> {
    if !canonical(tail) {
        return Err(format!("noncanonical storage key '{tail}'"));
    }
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("family '{family}' cannot be pinned ({error})")),
    };
    match super::durable_fs::read_slot_strict(&directory, &format!("{tail}.json")) {
        Ok(None) => Ok(None),
        Ok(Some((_file, bytes))) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("slot '{family}/{tail}' is malformed JSON ({error})")),
        Err(error) => Err(format!("slot '{family}/{tail}' is unreadable ({error})")),
    }
}

fn validate_record_identity(family: &str, tail: &str, record: &Value) -> Result<(), String> {
    let (schema, id_field, expected_id, statuses) = if family == FRONTIER_DIR {
        (
            FRONTIER_SCHEMA,
            "frontier_item_id",
            format!("frontier://{tail}"),
            FRONTIER_STATUSES,
        )
    } else if family == CLAIM_DIR {
        (
            CLAIM_SCHEMA,
            "work_claim_id",
            format!("work-claim://{tail}"),
            CLAIM_STATUSES,
        )
    } else {
        return Err(format!("unknown record family '{family}'"));
    };
    if !record.is_object()
        || record.get("schema_version").and_then(Value::as_str) != Some(schema)
        || record.get(id_field).and_then(Value::as_str) != Some(expected_id.as_str())
        || !record
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| statuses.contains(&status))
        || record.get("revision").and_then(Value::as_u64).is_none()
        || !record
            .get("outcome_room_ref")
            .and_then(Value::as_str)
            .is_some_and(|value| ref_ok(value, &["outcome-room"]))
    {
        return Err(format!(
            "slot '{family}/{tail}' has a malformed or identity-mismatched envelope"
        ));
    }
    if family == CLAIM_DIR
        && (!record
            .get("frontier_item_ref")
            .and_then(Value::as_str)
            .is_some_and(canonical_frontier_ref)
            || !record
                .get("claimant_ref")
                .and_then(Value::as_str)
                .is_some_and(|value| ref_ok(value, &["participant-lease"]))
            || record
                .get("eligibility_match_receipt_ref")
                .is_some_and(|value| {
                    !value.is_null()
                        && !value.as_str().is_some_and(|reference| {
                            reference
                                .strip_prefix("receipt://wem_")
                                .is_some_and(|tail| {
                                    tail.len() == 64
                                        && tail.chars().all(|c| {
                                            c.is_ascii_digit() || matches!(c, 'a'..='f')
                                        })
                                })
                        })
                }))
    {
        return Err(format!(
            "slot '{family}/{tail}' has malformed claim coordinates"
        ));
    }
    Ok(())
}

fn load_record(
    data_dir: &str,
    family: &str,
    tail: &str,
    canonical: fn(&str) -> bool,
) -> Result<Option<Value>, String> {
    let record = read_slot(data_dir, family, tail, canonical)?;
    if let Some(record) = record {
        validate_record_identity(family, tail, &record)?;
        Ok(Some(record))
    } else {
        Ok(None)
    }
}

fn scan_records(
    data_dir: &str,
    family: &str,
    canonical: fn(&str) -> bool,
) -> Result<Vec<(String, Value)>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("family '{family}' cannot be pinned ({error})")),
    };
    let names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|error| format!("family '{family}' cannot be enumerated ({error})"))?;
    let mut records = Vec::new();
    for name in names {
        let Some(tail) = name.strip_suffix(".json") else {
            continue;
        };
        if !canonical(tail) {
            continue;
        }
        let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
            Ok(Some((_file, bytes))) => bytes,
            Ok(None) => {
                return Err(format!(
                    "canonical slot '{family}/{name}' vanished after enumeration"
                ))
            }
            Err(error) => {
                return Err(format!(
                    "canonical slot '{family}/{name}' is unreadable ({error})"
                ))
            }
        };
        let record: Value = serde_json::from_slice(&bytes).map_err(|error| {
            format!("canonical slot '{family}/{name}' is malformed JSON ({error})")
        })?;
        validate_record_identity(family, tail, &record)?;
        records.push((tail.to_string(), record));
    }
    Ok(records)
}

fn load_frontier(data_dir: &str, id_or_tail: &str) -> Result<Option<Value>, String> {
    let tail = id_or_tail.strip_prefix("frontier://").unwrap_or(id_or_tail);
    load_record(data_dir, FRONTIER_DIR, tail, canonical_frontier_tail)
}

pub(crate) fn load_frontier_strict(
    data_dir: &str,
    id_or_tail: &str,
) -> Result<Option<Value>, String> {
    load_frontier(data_dir, id_or_tail)
}

fn load_claim(data_dir: &str, id_or_tail: &str) -> Result<Option<Value>, String> {
    let tail = id_or_tail
        .strip_prefix("work-claim://")
        .unwrap_or(id_or_tail);
    load_record(data_dir, CLAIM_DIR, tail, canonical_claim_tail)
}

fn consume_intent(data_dir: &str, tail: &str) -> Result<(), VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, INTENT_DIR) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(verr(
                "work_frontier_claim_intent_unreadable",
                error.to_string(),
            ))
        }
    };
    match super::durable_fs::unlink_at(&directory, &format!("{tail}.json")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(verr(
                "work_frontier_claim_pending_convergence",
                format!("intent unlink failed ({error})"),
            ))
        }
    }
    directory.sync_all().map_err(|error| {
        verr(
            "work_frontier_claim_pending_convergence",
            format!("intent directory sync failed ({error})"),
        )
    })
}

fn scan_intents(data_dir: &str) -> Result<Vec<(String, Value)>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, INTENT_DIR) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("intent family cannot be pinned ({error})")),
    };
    let names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|error| format!("intent family cannot be enumerated ({error})"))?;
    let mut intents = Vec::new();
    for name in names {
        let Some(tail) = name.strip_suffix(".json") else {
            continue;
        };
        if !canonical_intent_tail(tail) {
            continue;
        }
        let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
            Ok(Some((_file, bytes))) => bytes,
            Ok(None) => {
                return Err(format!(
                    "canonical intent '{name}' vanished after enumeration"
                ))
            }
            Err(error) => return Err(format!("canonical intent '{name}' is unreadable ({error})")),
        };
        let intent: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("canonical intent '{name}' is malformed JSON ({error})"))?;
        if intent.get("schema_version").and_then(Value::as_str) != Some(INTENT_SCHEMA)
            || intent.get("intent_id").and_then(Value::as_str)
                != Some(format!("work-frontier-claim-intent://{tail}").as_str())
            || intent.get("intent_hash").and_then(Value::as_str)
                != Some(record_output_hash(&without_field(&intent, "intent_hash"), &[]).as_str())
        {
            return Err(format!(
                "canonical intent '{name}' fails storage-key or hash binding"
            ));
        }
        validate_touched_refs(&intent).map_err(|message| {
            format!("canonical intent '{name}' has an invalid mutation footprint ({message})")
        })?;
        intents.push((tail.to_string(), intent));
    }
    Ok(intents)
}

fn without_field(value: &Value, field: &str) -> Value {
    let mut clone = value.clone();
    if let Some(object) = clone.as_object_mut() {
        object.remove(field);
    }
    clone
}

fn reconstructed_touched_refs(intent: &Value) -> Result<Vec<String>, String> {
    let kind = intent
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks kind while reconstructing touched refs".to_string())?;
    let mut touched = BTreeSet::new();
    if let Some(final_claim) = intent.get("final_claim").filter(|value| !value.is_null()) {
        let claim_ref = final_claim
            .get("work_claim_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "final claim lacks work_claim_id while reconstructing touched refs".to_string()
            })?;
        if !canonical_claim_ref(claim_ref) {
            return Err("final claim contributes a noncanonical touched ref".into());
        }
        touched.insert(claim_ref.to_string());
    }
    if let Some(final_frontier) = intent
        .get("final_frontier")
        .filter(|value| !value.is_null())
    {
        let frontier_ref = final_frontier
            .get("frontier_item_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "final frontier lacks frontier_item_id while reconstructing touched refs"
                    .to_string()
            })?;
        if !canonical_frontier_ref(frontier_ref) {
            return Err("final frontier contributes a noncanonical touched ref".into());
        }
        touched.insert(frontier_ref.to_string());
    }
    if intent
        .get("final_participant")
        .is_some_and(|value| !value.is_null())
    {
        let participant_ref = intent
            .get("participant_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "participant successor lacks participant_ref while reconstructing touched refs"
                    .to_string()
            })?;
        if !participant_ref
            .strip_prefix("participant-lease://rpl_")
            .is_some_and(|tail| {
                !tail.is_empty()
                    && tail.chars().all(|character| {
                        character.is_ascii_digit() || matches!(character, 'a'..='f')
                    })
            })
        {
            return Err("participant successor contributes a noncanonical touched ref".into());
        }
        touched.insert(participant_ref.to_string());
    }
    if kind == "frontier_create"
        || intent
            .get("release_terminal_room_slot")
            .and_then(Value::as_bool)
            == Some(true)
    {
        let room_ref = intent
            .get("room_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "room mutation lacks room_ref while reconstructing touched refs".to_string()
            })?;
        if !ref_ok(room_ref, &["outcome-room"]) {
            return Err("room mutation contributes a noncanonical touched ref".into());
        }
        touched.insert(room_ref.to_string());
    }
    if touched.is_empty() {
        return Err("intent reconstructs an empty touched_refs set".into());
    }
    Ok(touched.into_iter().collect())
}

fn validate_touched_refs(intent: &Value) -> Result<(), String> {
    let sealed = intent
        .get("touched_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| "intent lacks canonical touched_refs".to_string())?;
    let sealed: Option<Vec<String>> = sealed
        .iter()
        .map(|value| value.as_str().map(str::to_string))
        .collect();
    let sealed = sealed.ok_or_else(|| "intent touched_refs contains a non-string".to_string())?;
    let reconstructed = reconstructed_touched_refs(intent)?;
    if sealed != reconstructed {
        return Err(
            "intent touched_refs does not equal its reconstructed mutation footprint".into(),
        );
    }
    Ok(())
}

fn seal_intent(mut intent: Value, tail: &str) -> Value {
    let touched_refs = reconstructed_touched_refs(&intent)
        .expect("frontier/claim intent builder must produce a canonical mutation footprint");
    let object = intent.as_object_mut().expect("intent object");
    object.insert("schema_version".into(), json!(INTENT_SCHEMA));
    object.insert(
        "intent_id".into(),
        json!(format!("work-frontier-claim-intent://{tail}")),
    );
    object.insert("touched_refs".into(), json!(touched_refs));
    let hash = record_output_hash(&intent, &[]);
    intent
        .as_object_mut()
        .expect("intent object")
        .insert("intent_hash".into(), json!(hash));
    intent
}

fn frontier_declaration_from_record(record: &Value) -> Value {
    json!({
        "outcome_room_ref": record.get("outcome_room_ref").cloned().unwrap_or(Value::Null),
        "item_kind": record.get("item_kind").cloned().unwrap_or(Value::Null),
        "objective": record.get("objective").cloned().unwrap_or(Value::Null),
        "dependency_refs": record.get("dependency_refs").cloned().unwrap_or(Value::Null),
        "related_attempt_and_finding_refs": record.get("related_attempt_and_finding_refs").cloned().unwrap_or(Value::Null),
        "required_capability_refs": record.get("required_capability_refs").cloned().unwrap_or(Value::Null),
        "required_context_resource_authority_and_evidence_refs": record.get("required_context_resource_authority_and_evidence_refs").cloned().unwrap_or(Value::Null),
        "expected_value": record.get("expected_value").cloned().unwrap_or(Value::Null),
        "uncertainty": record.get("uncertainty").cloned().unwrap_or(Value::Null),
        "priority": record.get("priority").cloned().unwrap_or(Value::Null),
        "duplication_policy": record.get("duplication_policy").cloned().unwrap_or(Value::Null),
        "claimability": record.get("claimability").cloned().unwrap_or(Value::Null),
        "max_concurrency": record.get("max_concurrency").cloned().unwrap_or(Value::Null),
        "expires_at": record.get("expires_at").cloned().unwrap_or(Value::Null),
        "stop_condition_ref": record.get("stop_condition_ref").cloned().unwrap_or(Value::Null),
        "coordination_topology": record.get("coordination_topology").cloned().unwrap_or(Value::Null),
    })
}

fn claim_declaration_from_record(record: &Value) -> Value {
    json!({
        "outcome_room_ref": record.get("outcome_room_ref").cloned().unwrap_or(Value::Null),
        "frontier_item_ref": record.get("frontier_item_ref").cloned().unwrap_or(Value::Null),
        "claimant_ref": record.get("claimant_ref").cloned().unwrap_or(Value::Null),
        "eligibility_match_receipt_ref": record.get("eligibility_match_receipt_ref").cloned().unwrap_or(Value::Null),
        "bounded_scope_ref": record.get("bounded_scope_ref").cloned().unwrap_or(Value::Null),
        "context_lease_refs": record.get("context_lease_refs").cloned().unwrap_or(Value::Null),
        "authority_resource_compute_data_budget_and_tool_lease_refs": record.get("authority_resource_compute_data_budget_and_tool_lease_refs").cloned().unwrap_or(Value::Null),
        "duplicate_work_policy": record.get("duplicate_work_policy").cloned().unwrap_or(Value::Null),
        "heartbeat_ref": record.get("heartbeat_ref").cloned().unwrap_or(Value::Null),
        "ttl_seconds": record.get("ttl_seconds").cloned().unwrap_or(Value::Null),
        "coordination_topology": record.get("coordination_topology").cloned().unwrap_or(json!("hosted_admission")),
    })
}

// ================================= CANONICAL DECLARATIONS =======================================

fn reject_plane_owned(body: &Value, fields: &[&str]) -> Result<(), VErr> {
    for field in fields {
        if body.get(*field).is_some_and(|value| !value.is_null()) {
            return Err(verr(
                "work_frontier_claim_field_plane_owned",
                format!("'{field}' is minted by the frontier/claim plane"),
            ));
        }
    }
    Ok(())
}

fn reject_unknown_fields(body: &Value, allowed: &[&str]) -> Result<(), VErr> {
    let object = body.as_object().ok_or_else(|| {
        verr(
            "work_frontier_claim_body_invalid",
            "mutation body must be a JSON object",
        )
    })?;
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(verr(
            "work_frontier_claim_field_unknown",
            format!("unknown or non-admitted field '{field}'"),
        ));
    }
    Ok(())
}

fn validate_hosted_topology(body: &Value) -> Result<(), VErr> {
    match body.get("coordination_topology") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(value)) if value == "hosted_admission" => Ok(()),
        Some(Value::String(value)) if value == "federated_admission" => Err(verr(
            "work_frontier_claim_federated_unavailable",
            "federated/AIIP frontier admission is a later typed contract; #76 admits hosted rooms only",
        )),
        _ => Err(verr(
            "work_frontier_claim_topology_invalid",
            "coordination_topology must be hosted_admission when present",
        )),
    }
}

fn parse_concurrency(body: &Value, duplication_policy: &str) -> Result<u64, VErr> {
    let value = match body.get("max_concurrency") {
        None | Some(Value::Null) if duplication_policy == "exclusive" => 1,
        None | Some(Value::Null) => {
            return Err(verr(
                "work_frontier_claim_max_concurrency_required",
                "non-exclusive frontier items require an explicit max_concurrency",
            ))
        }
        Some(value) => value.as_u64().ok_or_else(|| {
            verr(
                "work_frontier_claim_max_concurrency_invalid",
                "max_concurrency must be an unsigned integer",
            )
        })?,
    };
    if value == 0 || value > ITEM_CONCURRENCY_MAX {
        return Err(verr(
            "work_frontier_claim_max_concurrency_invalid",
            format!("max_concurrency must be between 1 and {ITEM_CONCURRENCY_MAX}"),
        ));
    }
    if duplication_policy == "exclusive" && value != 1 {
        return Err(verr(
            "work_frontier_claim_max_concurrency_invalid",
            "exclusive frontier items have max_concurrency exactly 1",
        ));
    }
    Ok(value)
}

fn validate_frontier_create(body: &Value) -> Result<Value, VErr> {
    reject_sensitive_keys(body, "")?;
    reject_plane_owned(
        body,
        &[
            "schema_version",
            "frontier_item_id",
            "status",
            "revision",
            "created_at",
            "created_at_ms",
            "updated_at",
            "updated_at_ms",
            "admission_receipt_ref",
            "admission_and_replay_refs",
            "status_history",
            "claim_refs",
            "active_claim_refs",
            "runtimeTruthSource",
        ],
    )?;
    reject_unknown_fields(
        body,
        &[
            "outcome_room_ref",
            "item_kind",
            "objective",
            "dependency_refs",
            "related_attempt_and_finding_refs",
            "required_capability_refs",
            "required_context_resource_authority_and_evidence_refs",
            "expected_value",
            "uncertainty",
            "priority",
            "duplication_policy",
            "claimability",
            "max_concurrency",
            "expires_at",
            "stop_condition_ref",
            "coordination_topology",
            "expected_revision",
            "wallet_approval_grant",
        ],
    )?;
    validate_hosted_topology(body)?;
    if body.get("expires_at").is_some_and(|value| !value.is_null()) {
        return Err(verr(
            "work_frontier_claim_frontier_expiry_unavailable",
            "frontier expiry is not admitted in #76; omit expires_at instead of storing an unenforced deadline",
        ));
    }
    let duplication_policy = vocab(body, "duplication_policy", DUPLICATION_POLICIES)?;
    let max_concurrency = parse_concurrency(body, &duplication_policy)?;
    let declaration = json!({
        "outcome_room_ref": required_ref(body, "outcome_room_ref", &["outcome-room"] )?,
        "item_kind": vocab(body, "item_kind", ITEM_KINDS)?,
        "objective": bounded_string(body, "objective", OBJECTIVE_MAX, true)?.expect("required"),
        "dependency_refs": ref_list(body, "dependency_refs", &["frontier", "attempt", "finding"] )?,
        "related_attempt_and_finding_refs": ref_list(body, "related_attempt_and_finding_refs", &["attempt", "finding"] )?,
        "required_capability_refs": ref_list(body, "required_capability_refs", &["capability", "worker", "tool"] )?,
        "required_context_resource_authority_and_evidence_refs": ref_list(body, "required_context_resource_authority_and_evidence_refs", &["context-profile", "resource", "scope", "evidence"] )?,
        "expected_value": finite_number(body, "expected_value", -1_000_000.0, 1_000_000.0)?,
        "uncertainty": finite_number(body, "uncertainty", 0.0, 1.0)?,
        "priority": finite_number(body, "priority", -1_000_000.0, 1_000_000.0)?,
        "duplication_policy": duplication_policy,
        "claimability": vocab(body, "claimability", CLAIMABILITIES)?,
        "max_concurrency": max_concurrency,
        "expires_at": Value::Null,
        "stop_condition_ref": optional_ref(body, "stop_condition_ref", &["policy"] )?,
        "coordination_topology": "hosted_admission",
    });
    Ok(declaration)
}

fn seal_frontier(
    declaration: &Value,
    tail: &str,
    receipt_ref: &str,
    resolved_at_ms: u64,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(resolved_at_ms)?;
    let mut record = declaration.clone();
    let object = record.as_object_mut().expect("frontier declaration object");
    object.insert("schema_version".into(), json!(FRONTIER_SCHEMA));
    object.insert(
        "frontier_item_id".into(),
        json!(format!("frontier://{tail}")),
    );
    object.insert("status".into(), json!("open"));
    object.insert("revision".into(), json!(1));
    object.insert("claim_refs".into(), json!([]));
    object.insert("active_claim_refs".into(), json!([]));
    object.insert("created_at".into(), json!(now));
    object.insert("created_at_ms".into(), json!(resolved_at_ms));
    object.insert("updated_at".into(), json!(now));
    object.insert("updated_at_ms".into(), json!(resolved_at_ms));
    object.insert("admission_receipt_ref".into(), json!(receipt_ref));
    object.insert("admission_and_replay_refs".into(), json!([receipt_ref]));
    object.insert("status_history".into(), json!([]));
    object.insert("runtimeTruthSource".into(), json!("daemon-runtime"));
    Ok(record)
}

fn validate_claim_acquire(body: &Value) -> Result<Value, VErr> {
    reject_sensitive_keys(body, "")?;
    reject_plane_owned(
        body,
        &[
            "schema_version",
            "work_claim_id",
            "issued_at",
            "issued_at_ms",
            "expires_at",
            "expires_at_ms",
            "renewal_count",
            "release_or_reassignment_reason",
            "status",
            "revision",
            "created_at",
            "updated_at",
            "admission_receipt_ref",
            "admission_and_replay_refs",
            "status_history",
            "runtimeTruthSource",
        ],
    )?;
    reject_unknown_fields(
        body,
        &[
            "outcome_room_ref",
            "frontier_item_ref",
            "claimant_ref",
            "eligibility_match_receipt_ref",
            "bounded_scope_ref",
            "context_lease_refs",
            "authority_resource_compute_data_budget_and_tool_lease_refs",
            "duplicate_work_policy",
            "heartbeat_ref",
            "ttl_seconds",
            "coordination_topology",
            "expected_revision",
            "wallet_approval_grant",
        ],
    )?;
    validate_hosted_topology(body)?;
    let ttl_seconds = body
        .get("ttl_seconds")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            verr(
                "work_claim_ttl_required",
                "claim acquisition requires unsigned ttl_seconds",
            )
        })?;
    if !(CLAIM_TTL_MIN_SECONDS..=CLAIM_TTL_MAX_SECONDS).contains(&ttl_seconds) {
        return Err(verr(
            "work_claim_ttl_invalid",
            format!(
                "ttl_seconds must be between {CLAIM_TTL_MIN_SECONDS} and {CLAIM_TTL_MAX_SECONDS}"
            ),
        ));
    }
    let declaration = json!({
        "outcome_room_ref": required_ref(body, "outcome_room_ref", &["outcome-room"] )?,
        "frontier_item_ref": required_ref(body, "frontier_item_ref", &["frontier"] )?,
        "claimant_ref": required_ref(body, "claimant_ref", &["participant-lease"] )?,
        "eligibility_match_receipt_ref": optional_ref(body, "eligibility_match_receipt_ref", &["receipt"] )?,
        "bounded_scope_ref": required_ref(body, "bounded_scope_ref", &["task", "task_brief", "policy"] )?,
        "context_lease_refs": ref_list(body, "context_lease_refs", &["context_lease"] )?,
        "authority_resource_compute_data_budget_and_tool_lease_refs": ref_list(body, "authority_resource_compute_data_budget_and_tool_lease_refs", &["grant", "resource-lease", "compute", "view", "budget", "tool-lease"] )?,
        "duplicate_work_policy": vocab(body, "duplicate_work_policy", CLAIM_DUPLICATION_POLICIES)?,
        "heartbeat_ref": optional_ref(body, "heartbeat_ref", &["heartbeat", "receipt"] )?,
        "ttl_seconds": ttl_seconds,
        "coordination_topology": "hosted_admission",
    });
    if !declaration
        .get("frontier_item_ref")
        .and_then(Value::as_str)
        .is_some_and(canonical_frontier_ref)
    {
        return Err(verr(
            "work_frontier_claim_ref_invalid",
            "frontier_item_ref must be frontier://wfi_<64 lowercase hex>",
        ));
    }
    if !declaration
        .get("claimant_ref")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("participant-lease://rpl_"))
        .is_some_and(|tail| {
            !tail.is_empty()
                && tail
                    .chars()
                    .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
        })
    {
        return Err(verr(
            "work_frontier_claim_ref_invalid",
            "#76 claimants must be canonical participant-lease://rpl_<lowercase hex> refs",
        ));
    }
    Ok(declaration)
}

fn compatible_duplication(frontier: &Value, claim: &Value) -> bool {
    match (
        s(frontier, "duplication_policy", ""),
        s(claim, "duplicate_work_policy", ""),
    ) {
        (frontier, claim) if frontier == "exclusive" => claim == "exclusive",
        (frontier, claim) if frontier == "independent_replication_required" => {
            claim == "independent_replication" || claim == "adversarial_replication"
        }
        (frontier, claim) if frontier == "encouraged" => claim != "exclusive",
        (frontier, _) if frontier == "allowed" => true,
        _ => false,
    }
}

fn seal_claim(
    declaration: &Value,
    tail: &str,
    receipt_ref: &str,
    resolved_at_ms: u64,
) -> Result<Value, VErr> {
    let ttl_seconds = declaration
        .get("ttl_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let expires_at_ms = resolved_at_ms
        .checked_add(ttl_seconds.saturating_mul(1_000))
        .ok_or_else(|| verr("work_claim_ttl_invalid", "claim expiry overflows u64"))?;
    let issued_at = ms_to_rfc3339(resolved_at_ms)?;
    let expires_at = ms_to_rfc3339(expires_at_ms)?;
    Ok(json!({
        "schema_version": CLAIM_SCHEMA,
        "work_claim_id": format!("work-claim://{tail}"),
        "outcome_room_ref": declaration.get("outcome_room_ref").cloned().unwrap_or(Value::Null),
        "frontier_item_ref": declaration.get("frontier_item_ref").cloned().unwrap_or(Value::Null),
        "claimant_ref": declaration.get("claimant_ref").cloned().unwrap_or(Value::Null),
        "eligibility_match_receipt_ref": declaration.get("eligibility_match_receipt_ref").cloned().unwrap_or(Value::Null),
        "bounded_scope_ref": declaration.get("bounded_scope_ref").cloned().unwrap_or(Value::Null),
        "context_lease_refs": declaration.get("context_lease_refs").cloned().unwrap_or(json!([])),
        "authority_resource_compute_data_budget_and_tool_lease_refs": declaration.get("authority_resource_compute_data_budget_and_tool_lease_refs").cloned().unwrap_or(json!([])),
        "duplicate_work_policy": declaration.get("duplicate_work_policy").cloned().unwrap_or(Value::Null),
        "issued_at": issued_at,
        "issued_at_ms": resolved_at_ms,
        "expires_at": expires_at,
        "expires_at_ms": expires_at_ms,
        "heartbeat_ref": declaration.get("heartbeat_ref").cloned().unwrap_or(Value::Null),
        "heartbeat_at_ms": Value::Null,
        "ttl_seconds": ttl_seconds,
        "renewal_count": 0,
        "release_or_reassignment_reason": Value::Null,
        "status": "active",
        "revision": 1,
        "status_history": [],
        "created_at": issued_at,
        "updated_at": issued_at,
        "updated_at_ms": resolved_at_ms,
        "admission_receipt_ref": receipt_ref,
        "admission_and_replay_refs": [receipt_ref],
        "runtimeTruthSource": "daemon-runtime",
    }))
}

fn array_strings(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn append_history(
    object: &mut Map<String, Value>,
    op: &str,
    from: &str,
    receipt_ref: &str,
    now: &str,
    revision: u64,
) {
    let mut trail = object
        .get("admission_and_replay_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    trail.push(json!(receipt_ref));
    object.insert("admission_and_replay_refs".into(), Value::Array(trail));
    let mut history = object
        .get("status_history")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    history.push(json!({
        "op": op,
        "from": from,
        "at": now,
        "receipt_ref": receipt_ref,
        "revision": revision,
    }));
    if history.len() > HISTORY_MAX {
        history.drain(0..history.len() - HISTORY_MAX);
    }
    object.insert("status_history".into(), Value::Array(history));
}

fn transition_frontier(
    prior: &Value,
    op: &str,
    to_status: &str,
    receipt_ref: &str,
    resolved_at_ms: u64,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(resolved_at_ms)?;
    let mut final_record = prior.clone();
    let from = s(prior, "status", "");
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0) + 1;
    let object = final_record.as_object_mut().expect("frontier object");
    object.insert("status".into(), json!(to_status));
    object.insert("revision".into(), json!(revision));
    object.insert("updated_at".into(), json!(now));
    object.insert("updated_at_ms".into(), json!(resolved_at_ms));
    append_history(object, op, &from, receipt_ref, &now, revision);
    Ok(final_record)
}

fn derive_frontier_status(active_count: usize, duplication_policy: &str) -> &'static str {
    if active_count == 0 {
        "open"
    } else if active_count == 1 && duplication_policy == "exclusive" {
        "claimed"
    } else if active_count == 1 {
        "claimed"
    } else {
        "replicating"
    }
}

/// Stable claim-admission control fingerprint. Concurrent claims may change only derived status,
/// claim refs, history, revision, and timestamps; host lifecycle/policy/dependency changes alter
/// this hash and make an already-authorized claim stale before mutation.
pub(crate) fn frontier_claim_control_hash(frontier: &Value) -> String {
    let mut control = frontier.clone();
    if let Some(object) = control.as_object_mut() {
        if object
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| matches!(status, "claimed" | "replicating"))
        {
            object.insert("status".into(), json!("open"));
        }
        for field in [
            "revision",
            "claim_refs",
            "active_claim_refs",
            "updated_at",
            "updated_at_ms",
            "admission_and_replay_refs",
            "status_history",
        ] {
            object.remove(field);
        }
    }
    record_output_hash(&control, &[])
}

fn frontier_claim_successor(
    prior: &Value,
    claim_ref: &str,
    receipt_ref: &str,
    resolved_at_ms: u64,
    acquire: bool,
    completing: bool,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(resolved_at_ms)?;
    let mut all_claims = array_strings(prior, "claim_refs");
    let mut active_claims = array_strings(prior, "active_claim_refs");
    if acquire {
        if all_claims.iter().any(|value| value == claim_ref)
            || active_claims.iter().any(|value| value == claim_ref)
        {
            return Err(verr(
                "work_claim_conflict",
                format!("frontier already references claim '{claim_ref}'"),
            ));
        }
        all_claims.push(claim_ref.to_string());
        active_claims.push(claim_ref.to_string());
    } else {
        if !all_claims.iter().any(|value| value == claim_ref)
            || !active_claims.iter().any(|value| value == claim_ref)
        {
            return Err(verr(
                "work_claim_frontier_binding_mismatch",
                format!("claim '{claim_ref}' is not an active claim of the frontier item"),
            ));
        }
        active_claims.retain(|value| value != claim_ref);
    }
    let status = if completing {
        "verifying"
    } else {
        derive_frontier_status(active_claims.len(), &s(prior, "duplication_policy", ""))
    };
    let from = s(prior, "status", "");
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0) + 1;
    let mut final_record = prior.clone();
    let object = final_record.as_object_mut().expect("frontier object");
    object.insert("claim_refs".into(), json!(all_claims));
    object.insert("active_claim_refs".into(), json!(active_claims));
    object.insert("status".into(), json!(status));
    object.insert("revision".into(), json!(revision));
    object.insert("updated_at".into(), json!(now));
    object.insert("updated_at_ms".into(), json!(resolved_at_ms));
    append_history(
        object,
        if acquire {
            "claim_acquired"
        } else if completing {
            "claim_completed"
        } else {
            "claim_released"
        },
        &from,
        receipt_ref,
        &now,
        revision,
    );
    Ok(final_record)
}

fn transition_claim(
    prior: &Value,
    op: &str,
    to_status: &str,
    receipt_ref: &str,
    resolved_at_ms: u64,
    body: &Value,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(resolved_at_ms)?;
    let from = s(prior, "status", "");
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0) + 1;
    let mut final_claim = prior.clone();
    let object = final_claim.as_object_mut().expect("claim object");
    object.insert("status".into(), json!(to_status));
    object.insert("revision".into(), json!(revision));
    object.insert("updated_at".into(), json!(now));
    object.insert("updated_at_ms".into(), json!(resolved_at_ms));
    if op == "heartbeat" {
        object.insert(
            "heartbeat_ref".into(),
            optional_ref(body, "heartbeat_ref", &["heartbeat", "receipt"])?
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        object.insert("heartbeat_at_ms".into(), json!(resolved_at_ms));
    }
    if op == "renew" {
        let ttl_seconds = body
            .get("ttl_seconds")
            .and_then(Value::as_u64)
            .ok_or_else(|| verr("work_claim_ttl_required", "renew requires ttl_seconds"))?;
        if !(CLAIM_TTL_MIN_SECONDS..=CLAIM_TTL_MAX_SECONDS).contains(&ttl_seconds) {
            return Err(verr(
                "work_claim_ttl_invalid",
                "renew ttl_seconds is out of bounds",
            ));
        }
        let renewal_count = prior
            .get("renewal_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if renewal_count >= CLAIM_RENEWAL_MAX {
            return Err(verr(
                "work_claim_renewal_limit",
                format!("claim already reached the {CLAIM_RENEWAL_MAX}-renewal limit"),
            ));
        }
        let expires_at_ms = resolved_at_ms
            .checked_add(ttl_seconds.saturating_mul(1_000))
            .ok_or_else(|| verr("work_claim_ttl_invalid", "renewed expiry overflows u64"))?;
        object.insert("ttl_seconds".into(), json!(ttl_seconds));
        object.insert("expires_at_ms".into(), json!(expires_at_ms));
        object.insert("expires_at".into(), json!(ms_to_rfc3339(expires_at_ms)?));
        object.insert("renewal_count".into(), json!(renewal_count + 1));
    }
    if CLAIM_TERMINAL.contains(&to_status) {
        object.insert(
            "release_or_reassignment_reason".into(),
            bounded_string(body, "reason", REASON_MAX, true)?
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
    }
    append_history(object, op, &from, receipt_ref, &now, revision);
    Ok(final_claim)
}

#[allow(clippy::too_many_arguments)]
fn build_receipt(
    receipt_tail: &str,
    schema: &str,
    receipt_type: &str,
    subject_ref: &str,
    op: &str,
    bound_facts: Value,
    boundary_refs: Vec<Value>,
    final_record: &Value,
    note: &str,
    authorized: &AuthorizedDecision,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(authorized.resolved_at_ms)?;
    let mut receipt = build_room_receipt_at(
        receipt_tail,
        schema,
        receipt_type,
        subject_ref,
        op,
        bound_facts,
        boundary_refs,
        record_output_hash(
            final_record,
            &["admission_and_replay_refs", "status_history"],
        ),
        &["admission_and_replay_refs", "status_history"],
        "admitted_not_verified",
        note,
        &now,
    );
    governed::append_evidence(&mut receipt, authorized);
    Ok(receipt)
}

fn receipt_ref_for_tail(tail: &str) -> Result<String, String> {
    if !(canonical_tail(tail, "wfr_") || canonical_tail(tail, "wcr_")) {
        return Err(format!("receipt tail '{tail}' is noncanonical"));
    }
    Ok(format!("receipt://{tail}"))
}

fn sealed_authorized(receipt: &Value) -> Result<AuthorizedDecision, String> {
    let resolved_at_ms = receipt
        .get("authority_resolved_at_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| "receipt lacks wallet.network authority_resolved_at_ms".to_string())?;
    Ok(AuthorizedDecision {
        evidence: governed::sealed_evidence(receipt),
        resolved_at_ms,
    })
}

fn validate_receipt_exact(
    contract: AuthorityContract,
    expected_effect: &Value,
    receipt_tail: &str,
    schema: &str,
    receipt_type: &str,
    subject_ref: &str,
    op: &str,
    bound_facts: Value,
    boundary_refs: Vec<Value>,
    final_record: &Value,
    note: &str,
    receipt: &Value,
) -> Result<(), String> {
    governed::validate_sealed_effect(contract, receipt, expected_effect)?;
    let authorized = sealed_authorized(receipt)?;
    let expected = build_receipt(
        receipt_tail,
        schema,
        receipt_type,
        subject_ref,
        op,
        bound_facts,
        boundary_refs,
        final_record,
        note,
        &authorized,
    )
    .map_err(|(_, message)| message)?;
    if expected != *receipt {
        return Err("sealed receipt does not reconstruct byte-exactly".into());
    }
    Ok(())
}

fn validate_intent_coordinates(intent: &Value, tail: &str) -> Result<(), String> {
    if !canonical_intent_tail(tail)
        || intent.get("schema_version").and_then(Value::as_str) != Some(INTENT_SCHEMA)
        || intent.get("intent_id").and_then(Value::as_str)
            != Some(format!("work-frontier-claim-intent://{tail}").as_str())
        || intent.get("intent_hash").and_then(Value::as_str)
            != Some(record_output_hash(&without_field(intent, "intent_hash"), &[]).as_str())
    {
        return Err("intent fails canonical storage-key or content-hash binding".into());
    }
    validate_touched_refs(intent)?;
    let room_ref = intent
        .get("room_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks room_ref".to_string())?;
    if !ref_ok(room_ref, &["outcome-room"]) {
        return Err("intent room_ref is malformed".into());
    }
    let receipt_tail = intent
        .get("receipt_tail")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks receipt_tail".to_string())?;
    let receipt = intent
        .get("receipt")
        .ok_or_else(|| "intent lacks receipt".to_string())?;
    let receipt_ref = receipt_ref_for_tail(receipt_tail)?;
    if receipt.get("receipt_id").and_then(Value::as_str) != Some(receipt_ref.as_str())
        || receipt.get("receipt_ref").and_then(Value::as_str) != Some(receipt_ref.as_str())
        || receipt.get("subject_ref") != intent.get("subject_ref")
        || receipt.get("op") != intent.get("op")
    {
        return Err("intent receipt identity is not bound to its storage coordinates".into());
    }
    let resolved_at_ms = receipt
        .get("authority_resolved_at_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| "intent receipt lacks authenticated wallet time".to_string())?;
    ms_to_rfc3339(resolved_at_ms).map_err(|(_, message)| message)?;
    Ok(())
}

/// Reconstruct every successor and its complete ReceiptEnvelope. A boot pass never trusts sealed
/// successor fields merely because their hashes agree with each other.
fn validate_sealed_intent(intent: &Value, tail: &str) -> Result<(), String> {
    validate_intent_coordinates(intent, tail)?;
    let kind = intent
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks kind".to_string())?;
    let op = intent
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks op".to_string())?;
    let room_ref = intent
        .get("room_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks room_ref".to_string())?;
    let subject_ref = intent
        .get("subject_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks subject_ref".to_string())?;
    let revision_before = intent
        .get("revision_before")
        .and_then(Value::as_u64)
        .ok_or_else(|| "intent lacks revision_before".to_string())?;
    let receipt_tail = intent
        .get("receipt_tail")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks receipt_tail".to_string())?;
    let receipt = intent
        .get("receipt")
        .ok_or_else(|| "intent lacks receipt".to_string())?;
    let resolved_at_ms = receipt
        .get("authority_resolved_at_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| "receipt lacks authority_resolved_at_ms".to_string())?;
    let receipt_ref = receipt_ref_for_tail(receipt_tail)?;

    match kind {
        "frontier_create" => {
            if op != "create"
                || !canonical_frontier_ref(subject_ref)
                || intent.get("governance").and_then(Value::as_str) != Some("host")
            {
                return Err("frontier-create intent has invalid operation or subject".into());
            }
            let final_frontier = intent
                .get("final_frontier")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "frontier-create intent lacks successor".to_string())?;
            let declaration =
                validate_frontier_create(&frontier_declaration_from_record(final_frontier))
                    .map_err(|(_, message)| {
                        format!("frontier declaration does not reconstruct: {message}")
                    })?;
            let expected_tail = deterministic_tail("wfi_", &declaration);
            if subject_ref != format!("frontier://{expected_tail}") {
                return Err("frontier identity is not the declaration hash".into());
            }
            let expected =
                seal_frontier(&declaration, &expected_tail, &receipt_ref, resolved_at_ms)
                    .map_err(|(_, message)| message)?;
            if expected != *final_frontier
                || intent
                    .get("prior_frontier")
                    .is_some_and(|value| !value.is_null())
                || intent
                    .get("prior_claim")
                    .is_some_and(|value| !value.is_null())
                || intent
                    .get("final_claim")
                    .is_some_and(|value| !value.is_null())
                || intent
                    .get("prior_participant")
                    .is_some_and(|value| !value.is_null())
                || intent
                    .get("final_participant")
                    .is_some_and(|value| !value.is_null())
            {
                return Err("frontier-create sealed successors do not reconstruct".into());
            }
            validate_receipt_exact(
                FRONTIER_AUTHORITY,
                &frontier_create_effect(&declaration, revision_before),
                receipt_tail,
                FRONTIER_RECEIPT_SCHEMA,
                "WorkFrontierMutationReceipt",
                subject_ref,
                op,
                json!({ "outcome_room_ref": room_ref, "item_kind": s(&declaration, "item_kind", ""), "status": "open" }),
                vec![json!(subject_ref), json!(room_ref)],
                final_frontier,
                FRONTIER_NOTE,
                receipt,
            )?;
        }
        "frontier_transition" => {
            let prior = intent
                .get("prior_frontier")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "frontier transition lacks prior".to_string())?;
            let final_frontier = intent
                .get("final_frontier")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "frontier transition lacks successor".to_string())?;
            let Some((_, allowed_from, to_status)) = FRONTIER_TRANSITIONS
                .iter()
                .find(|(transition, _, _)| *transition == op)
            else {
                return Err("frontier transition operation is not canonical".into());
            };
            if s(prior, "frontier_item_id", "") != subject_ref
                || s(prior, "outcome_room_ref", "") != room_ref
                || prior.get("revision").and_then(Value::as_u64) != Some(revision_before)
                || !allowed_from.contains(&s(prior, "status", "").as_str())
                || intent.get("governance").and_then(Value::as_str) != Some("host")
            {
                return Err("frontier transition prior coordinates are inconsistent".into());
            }
            let expected = transition_frontier(prior, op, to_status, &receipt_ref, resolved_at_ms)
                .map_err(|(_, message)| message)?;
            if expected != *final_frontier {
                return Err("frontier transition successor does not reconstruct".into());
            }
            validate_receipt_exact(
                FRONTIER_AUTHORITY,
                &frontier_transition_effect(op, revision_before),
                receipt_tail,
                FRONTIER_RECEIPT_SCHEMA,
                "WorkFrontierMutationReceipt",
                subject_ref,
                op,
                json!({ "outcome_room_ref": room_ref, "from": s(prior, "status", ""), "to": to_status, "revision_before": revision_before, "revision_after": revision_before + 1 }),
                vec![json!(subject_ref), json!(room_ref)],
                final_frontier,
                FRONTIER_NOTE,
                receipt,
            )?;
        }
        "claim_acquire" => {
            let final_claim = intent
                .get("final_claim")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "claim acquire lacks claim successor".to_string())?;
            let prior_frontier = intent
                .get("prior_frontier")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "claim acquire lacks frontier prior".to_string())?;
            let final_frontier = intent
                .get("final_frontier")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "claim acquire lacks frontier successor".to_string())?;
            let prior_participant = intent
                .get("prior_participant")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "claim acquire lacks participant prior".to_string())?;
            let final_participant = intent
                .get("final_participant")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "claim acquire lacks participant successor".to_string())?;
            let participant_ref = intent
                .get("participant_ref")
                .and_then(Value::as_str)
                .ok_or_else(|| "claim acquire lacks participant_ref".to_string())?;
            let declaration = validate_claim_acquire(&claim_declaration_from_record(final_claim))
                .map_err(|(_, message)| {
                format!("claim declaration does not reconstruct: {message}")
            })?;
            let frontier_revision_at_authorization = intent
                .get("frontier_revision_at_authorization")
                .and_then(Value::as_u64)
                .ok_or_else(|| "claim acquire lacks frontier authorization revision".to_string())?;
            let frontier_control_at_authorization = intent
                .get("frontier_control_hash_at_authorization")
                .and_then(Value::as_str)
                .ok_or_else(|| "claim acquire lacks frontier control hash".to_string())?;
            let expected_tail = deterministic_tail(
                "wcl_",
                &json!({
                    "declaration": declaration,
                    "frontier_revision": frontier_revision_at_authorization,
                    "participant_revision": prior_participant.get("revision").cloned().unwrap_or(Value::Null),
                }),
            );
            if op != "acquire"
                || subject_ref != format!("work-claim://{expected_tail}")
                || revision_before
                    != prior_participant
                        .get("revision")
                        .and_then(Value::as_u64)
                        .unwrap_or(u64::MAX)
                || frontier_revision_at_authorization
                    > prior_frontier
                        .get("revision")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                || frontier_control_at_authorization != frontier_claim_control_hash(prior_frontier)
                || s(prior_frontier, "outcome_room_ref", "") != room_ref
                || s(prior_participant, "outcome_room_ref", "") != room_ref
                || s(final_claim, "claimant_ref", "") != participant_ref
                || intent.get("governance").and_then(Value::as_str) != Some("participant")
            {
                return Err("claim-acquire coordinates are inconsistent".into());
            }
            let expected_claim =
                seal_claim(&declaration, &expected_tail, &receipt_ref, resolved_at_ms)
                    .map_err(|(_, message)| message)?;
            let expected_frontier = frontier_claim_successor(
                prior_frontier,
                subject_ref,
                &receipt_ref,
                resolved_at_ms,
                true,
                false,
            )
            .map_err(|(_, message)| message)?;
            let now = ms_to_rfc3339(resolved_at_ms).map_err(|(_, message)| message)?;
            let expected_participant = participation::participant_current_claim_successor(
                prior_participant,
                subject_ref,
                &receipt_ref,
                &now,
                true,
            )
            .map_err(|(_, message)| message)?;
            if expected_claim != *final_claim
                || expected_frontier != *final_frontier
                || expected_participant != *final_participant
            {
                return Err("claim-acquire successors do not reconstruct byte-exactly".into());
            }
            validate_receipt_exact(
                CLAIM_AUTHORITY,
                &claim_acquire_effect(&declaration, revision_before),
                receipt_tail,
                CLAIM_RECEIPT_SCHEMA,
                "WorkClaimLeaseReceipt",
                subject_ref,
                op,
                json!({
                    "outcome_room_ref": room_ref,
                    "frontier_item_ref": s(final_claim, "frontier_item_ref", ""),
                    "claimant_ref": participant_ref,
                    "issued_at_ms": resolved_at_ms,
                    "expires_at_ms": final_claim.get("expires_at_ms").cloned().unwrap_or(Value::Null),
                    "revision_after": 1,
                }),
                vec![
                    json!(subject_ref),
                    json!(s(final_claim, "frontier_item_ref", "")),
                    json!(participant_ref),
                    json!(room_ref),
                ],
                final_claim,
                CLAIM_NOTE,
                receipt,
            )?;
        }
        "claim_transition" => {
            let prior_claim = intent
                .get("prior_claim")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "claim transition lacks prior claim".to_string())?;
            let final_claim = intent
                .get("final_claim")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "claim transition lacks successor claim".to_string())?;
            let (governance, to_status, releases_binding) =
                claim_transition_contract(op, &s(prior_claim, "status", ""))
                    .map_err(|(_, message)| message)?;
            let expected_governance = if governance == Governance::Host {
                "host"
            } else {
                "participant"
            };
            if intent.get("governance").and_then(Value::as_str) != Some(expected_governance)
                || s(prior_claim, "work_claim_id", "") != subject_ref
                || s(prior_claim, "outcome_room_ref", "") != room_ref
                || prior_claim.get("revision").and_then(Value::as_u64) != Some(revision_before)
            {
                return Err("claim transition coordinates are inconsistent".into());
            }
            let mut transition_body = json!({});
            let transition_fields = transition_body
                .as_object_mut()
                .expect("transition reconstruction body");
            if op == "renew" {
                transition_fields.insert(
                    "ttl_seconds".into(),
                    final_claim
                        .get("ttl_seconds")
                        .cloned()
                        .unwrap_or(Value::Null),
                );
            } else if op == "heartbeat" {
                transition_fields.insert(
                    "heartbeat_ref".into(),
                    final_claim
                        .get("heartbeat_ref")
                        .cloned()
                        .unwrap_or(Value::Null),
                );
            } else if matches!(
                op,
                "release" | "complete" | "expire" | "quarantine" | "revoke"
            ) {
                transition_fields.insert(
                    "reason".into(),
                    final_claim
                        .get("release_or_reassignment_reason")
                        .cloned()
                        .unwrap_or(Value::Null),
                );
            }
            let expected_claim = transition_claim(
                prior_claim,
                op,
                to_status,
                &receipt_ref,
                resolved_at_ms,
                &transition_body,
            )
            .map_err(|(_, message)| message)?;
            if expected_claim != *final_claim {
                return Err("claim transition successor does not reconstruct".into());
            }
            let expected_effect = claim_transition_effect(op, revision_before, &transition_body)
                .map_err(|(_, message)| message)?;
            let participant_ref = s(prior_claim, "claimant_ref", "");
            let frontier_ref = s(prior_claim, "frontier_item_ref", "");
            if releases_binding {
                let prior_frontier = intent
                    .get("prior_frontier")
                    .filter(|value| !value.is_null())
                    .ok_or_else(|| "terminal claim transition lacks frontier prior".to_string())?;
                let final_frontier = intent
                    .get("final_frontier")
                    .filter(|value| !value.is_null())
                    .ok_or_else(|| {
                        "terminal claim transition lacks frontier successor".to_string()
                    })?;
                let prior_participant = intent
                    .get("prior_participant")
                    .filter(|value| !value.is_null())
                    .ok_or_else(|| {
                        "terminal claim transition lacks participant prior".to_string()
                    })?;
                let final_participant = intent
                    .get("final_participant")
                    .filter(|value| !value.is_null())
                    .ok_or_else(|| {
                        "terminal claim transition lacks participant successor".to_string()
                    })?;
                if intent.get("participant_ref").and_then(Value::as_str)
                    != Some(participant_ref.as_str())
                {
                    return Err("terminal claim participant coordinate mismatch".into());
                }
                let expected_frontier = frontier_claim_successor(
                    prior_frontier,
                    subject_ref,
                    &receipt_ref,
                    resolved_at_ms,
                    false,
                    op == "complete",
                )
                .map_err(|(_, message)| message)?;
                let now = ms_to_rfc3339(resolved_at_ms).map_err(|(_, message)| message)?;
                let expected_participant = participation::participant_current_claim_successor(
                    prior_participant,
                    subject_ref,
                    &receipt_ref,
                    &now,
                    false,
                )
                .map_err(|(_, message)| message)?;
                if expected_frontier != *final_frontier
                    || expected_participant != *final_participant
                {
                    return Err("terminal claim cross-plane successors do not reconstruct".into());
                }
                if intent
                    .get("release_terminal_room_slot")
                    .and_then(Value::as_bool)
                    == Some(true)
                    && (!matches!(op, "release" | "revoke")
                        || !matches!(
                            s(prior_participant, "status", "").as_str(),
                            "retired" | "revoked"
                        )
                        || s(final_participant, "status", "") != s(prior_participant, "status", "")
                        || final_participant
                            .get("current_claim_ref")
                            .is_some_and(|value| !value.is_null()))
                {
                    return Err("terminal room release coordinates are not reconstructable".into());
                }
            } else if intent
                .get("prior_frontier")
                .is_some_and(|value| !value.is_null())
                || intent
                    .get("final_frontier")
                    .is_some_and(|value| !value.is_null())
                || intent
                    .get("prior_participant")
                    .is_some_and(|value| !value.is_null())
                || intent
                    .get("final_participant")
                    .is_some_and(|value| !value.is_null())
                || intent
                    .get("participant_ref")
                    .is_some_and(|value| !value.is_null())
            {
                return Err(
                    "non-terminal claim transition carries forbidden cross-plane successors".into(),
                );
            }
            validate_receipt_exact(
                CLAIM_AUTHORITY,
                &expected_effect,
                receipt_tail,
                CLAIM_RECEIPT_SCHEMA,
                "WorkClaimLeaseReceipt",
                subject_ref,
                op,
                json!({
                    "outcome_room_ref": room_ref,
                    "frontier_item_ref": frontier_ref,
                    "claimant_ref": participant_ref,
                    "from": s(prior_claim, "status", ""),
                    "to": to_status,
                    "revision_before": revision_before,
                    "revision_after": revision_before + 1,
                    "wallet_time_ms": resolved_at_ms,
                }),
                vec![
                    json!(subject_ref),
                    json!(frontier_ref),
                    json!(participant_ref),
                    json!(room_ref),
                ],
                final_claim,
                CLAIM_NOTE,
                receipt,
            )?;
        }
        _ => return Err(format!("unknown intent kind '{kind}'")),
    }
    if intent
        .get("release_terminal_room_slot")
        .and_then(Value::as_bool)
        == Some(true)
        && kind != "claim_transition"
    {
        return Err("only a terminal claim transition may release a participant room slot".into());
    }
    Ok(())
}

// ================================= GRAPH + CAPACITY CHECKS ======================================

fn frontier_by_ref<'a>(records: &'a [(String, Value)], reference: &str) -> Option<&'a Value> {
    records
        .iter()
        .find(|(_, record)| s(record, "frontier_item_id", "") == reference)
        .map(|(_, record)| record)
}

fn dependency_cycle(records: &[(String, Value)], candidate: &Value, candidate_ref: &str) -> bool {
    let mut graph: HashMap<String, Vec<String>> = records
        .iter()
        .map(|(_, record)| {
            (
                s(record, "frontier_item_id", ""),
                array_strings(record, "dependency_refs")
                    .into_iter()
                    .filter(|reference| reference.starts_with("frontier://"))
                    .collect(),
            )
        })
        .collect();
    graph.insert(
        candidate_ref.to_string(),
        array_strings(candidate, "dependency_refs")
            .into_iter()
            .filter(|reference| reference.starts_with("frontier://"))
            .collect(),
    );
    fn visits(
        node: &str,
        graph: &HashMap<String, Vec<String>>,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) -> bool {
        if visiting.contains(node) {
            return true;
        }
        if !visited.insert(node.to_string()) {
            return false;
        }
        visiting.insert(node.to_string());
        for dependency in graph.get(node).into_iter().flatten() {
            if visits(dependency, graph, visiting, visited) {
                return true;
            }
        }
        visiting.remove(node);
        false
    }
    visits(
        candidate_ref,
        &graph,
        &mut HashSet::new(),
        &mut HashSet::new(),
    )
}

fn dependencies_ready(records: &[(String, Value)], frontier: &Value) -> Result<(), VErr> {
    let room_ref = s(frontier, "outcome_room_ref", "");
    for dependency in array_strings(frontier, "dependency_refs") {
        if dependency.starts_with("attempt://") || dependency.starts_with("finding://") {
            return Err(verr(
                "work_frontier_claim_dependencies_unresolved",
                format!("dependency '{dependency}' names an object plane not admitted in #76"),
            ));
        }
        let Some(record) = frontier_by_ref(records, &dependency) else {
            return Err(verr(
                "work_frontier_claim_dependencies_unresolved",
                format!("dependency '{dependency}' does not resolve"),
            ));
        };
        if s(record, "outcome_room_ref", "") != room_ref
            || !matches!(s(record, "status", "").as_str(), "closed" | "accepted")
        {
            return Err(verr(
                "work_frontier_claim_dependencies_unresolved",
                format!("dependency '{dependency}' is not a closed same-room predecessor"),
            ));
        }
    }
    Ok(())
}

fn live_claim_status(status: &str) -> bool {
    matches!(status, "active" | "waiting")
}

// ================================= DURABLE INTENT FINALIZATION ==================================

fn persist_successor(
    data_dir: &str,
    family: &str,
    tail: &str,
    canonical: fn(&str) -> bool,
    prior: Option<&Value>,
    final_record: &Value,
) -> Result<(), VErr> {
    match load_record(data_dir, family, tail, canonical)
        .map_err(|message| verr("work_frontier_claim_registry_unreadable", message))?
    {
        Some(existing) if existing == *final_record => Ok(()),
        Some(existing) if prior.is_some_and(|prior| existing == *prior) => {
            persist_record(data_dir, family, tail, final_record)
        }
        Some(_) => Err(verr(
            "work_frontier_claim_successor_conflict",
            format!("'{family}/{tail}' is neither the sealed prior nor successor"),
        )),
        None if prior.is_none() => persist_record(data_dir, family, tail, final_record),
        None => Err(verr(
            "work_frontier_claim_successor_conflict",
            format!("sealed prior '{family}/{tail}' vanished"),
        )),
    }
}

fn intent_value<'a>(intent: &'a Value, field: &str) -> Option<&'a Value> {
    intent.get(field).filter(|value| !value.is_null())
}

fn intent_string<'a>(intent: &'a Value, field: &str) -> Result<&'a str, VErr> {
    intent.get(field).and_then(Value::as_str).ok_or_else(|| {
        verr(
            "work_frontier_claim_intent_unreadable",
            format!("intent lacks '{field}'"),
        )
    })
}

/// Apply a previously sealed successor while all required locks are held. Each write is
/// idempotent and compares exact prior/final bytes; partial application remains hidden behind the
/// durable intent and converges forward on authenticated replay.
fn complete_intent_locked(data_dir: &str, tail: &str, intent: &Value) -> Result<(), VErr> {
    let kind = intent_string(intent, "kind")?;
    let receipt_tail = intent_string(intent, "receipt_tail")?;
    let receipt = intent_value(intent, "receipt").ok_or_else(|| {
        verr(
            "work_frontier_claim_intent_unreadable",
            "intent lacks receipt",
        )
    })?;

    if kind == "frontier_create" {
        let room_ref = intent_string(intent, "room_ref")?;
        let subject_ref = intent_string(intent, "subject_ref")?;
        match rooms::bind_room_backlink_room_locked_for_work_intent(
            data_dir,
            room_ref,
            "frontier_item_bound",
            subject_ref,
            tail,
        ) {
            Ok(_) => {}
            Err((code, _)) if code == "outcome_room_backlink_already_bound" => {}
            Err(error) => return Err(error),
        }
    }

    persist_receipt(data_dir, receipt_tail, receipt)?;

    if let Some(final_claim) = intent_value(intent, "final_claim") {
        let claim_ref = final_claim
            .get("work_claim_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                verr(
                    "work_frontier_claim_intent_unreadable",
                    "final claim lacks id",
                )
            })?;
        let claim_tail = claim_ref.strip_prefix("work-claim://").ok_or_else(|| {
            verr(
                "work_frontier_claim_intent_unreadable",
                "final claim id is noncanonical",
            )
        })?;
        persist_successor(
            data_dir,
            CLAIM_DIR,
            claim_tail,
            canonical_claim_tail,
            intent_value(intent, "prior_claim"),
            final_claim,
        )?;
    }

    if let Some(final_participant) = intent_value(intent, "final_participant") {
        let participant_ref = intent_string(intent, "participant_ref")?;
        let prior_participant = intent_value(intent, "prior_participant").ok_or_else(|| {
            verr(
                "work_frontier_claim_intent_unreadable",
                "participant successor lacks sealed prior",
            )
        })?;
        participation::persist_participant_claim_successor_locked(
            data_dir,
            participant_ref,
            prior_participant,
            final_participant,
        )?;
    }

    if let Some(final_frontier) = intent_value(intent, "final_frontier") {
        let frontier_ref = final_frontier
            .get("frontier_item_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                verr(
                    "work_frontier_claim_intent_unreadable",
                    "final frontier lacks id",
                )
            })?;
        let frontier_tail = frontier_ref.strip_prefix("frontier://").ok_or_else(|| {
            verr(
                "work_frontier_claim_intent_unreadable",
                "final frontier id is noncanonical",
            )
        })?;
        persist_successor(
            data_dir,
            FRONTIER_DIR,
            frontier_tail,
            canonical_frontier_tail,
            intent_value(intent, "prior_frontier"),
            final_frontier,
        )?;
    }

    if intent
        .get("release_terminal_room_slot")
        .and_then(Value::as_bool)
        == Some(true)
    {
        let participant_ref = intent_string(intent, "participant_ref")?;
        let final_participant = intent_value(intent, "final_participant").ok_or_else(|| {
            verr(
                "work_frontier_claim_intent_unreadable",
                "terminal room release lacks participant successor",
            )
        })?;
        if final_participant
            .get("current_claim_ref")
            .is_some_and(|value| !value.is_null())
            || !matches!(
                s(final_participant, "status", "").as_str(),
                "retired" | "revoked"
            )
        {
            return Err(verr(
                "work_frontier_claim_intent_invalid",
                "terminal room release requires a terminal participant with no current claim",
            ));
        }
        match rooms::bind_room_backlink_room_locked_for_work_intent(
            data_dir,
            intent_string(intent, "room_ref")?,
            "participant_lease_released",
            participant_ref,
            tail,
        ) {
            Ok(_) => {}
            Err((code, _)) if code == "outcome_room_backlink_already_bound" => {}
            Err(error) => return Err(error),
        }
    }

    consume_intent(data_dir, tail)
}

fn persist_and_complete_intent_locked(
    data_dir: &str,
    tail: &str,
    intent: &Value,
) -> Result<(), VErr> {
    validate_sealed_intent(intent, tail).map_err(|message| {
        verr(
            "work_frontier_claim_intent_invalid",
            format!("refused to persist a non-reconstructable transaction: {message}"),
        )
    })?;
    if read_slot(data_dir, INTENT_DIR, tail, canonical_intent_tail)
        .map_err(|message| verr("work_frontier_claim_intent_unreadable", message))?
        .is_some()
    {
        return Err(verr(
            "work_frontier_claim_intent_conflict",
            format!("intent slot '{tail}' is already occupied"),
        ));
    }
    persist_record(data_dir, INTENT_DIR, tail, intent)?;
    complete_intent_locked(data_dir, tail, intent).map_err(|(code, message)| {
        if code.contains("pending_convergence") {
            (code, message)
        } else {
            verr(
                "work_frontier_claim_pending_convergence",
                format!("{message}; durable intent '{tail}' is retained"),
            )
        }
    })
}

fn pending_intent_overlap(
    data_dir: &str,
    refs: &[&str],
    ignored_intent_tail: Option<&str>,
) -> Result<Option<(String, String)>, VErr> {
    let refs: HashSet<&str> = refs.iter().copied().collect();
    for (tail, intent) in scan_intents(data_dir)
        .map_err(|message| verr("work_frontier_claim_intent_unreadable", message))?
    {
        if ignored_intent_tail == Some(tail.as_str()) {
            continue;
        }
        let touched = intent
            .get("touched_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                verr(
                    "work_frontier_claim_intent_unreadable",
                    format!("intent '{tail}' lacks reconstructed touched_refs"),
                )
            })?;
        if let Some(overlap) = touched
            .iter()
            .filter_map(Value::as_str)
            .find(|reference| refs.contains(reference))
        {
            return Ok(Some((tail, overlap.to_string())));
        }
    }
    Ok(None)
}

fn refuse_mutations_if_reserved(
    data_dir: &str,
    refs: &[&str],
    code: &str,
    ignored_intent_tail: Option<&str>,
) -> Result<(), VErr> {
    if let Some((tail, overlap)) = pending_intent_overlap(data_dir, refs, ignored_intent_tail)? {
        return Err(verr(
            code,
            format!("record '{overlap}' is reserved by pending frontier/claim intent '{tail}'"),
        ));
    }
    for reference in refs {
        super::resource_capability_offer_routes::refuse_external_mutation_if_reserved(
            data_dir,
            reference,
            code,
        )?;
    }
    Ok(())
}

/// Cross-plane owner seam. Callers hold their owner lock; work-intent creation cannot race the
/// check because it must acquire that owner lock before making its own intent durable.
pub(crate) fn refuse_external_mutation_if_reserved(
    data_dir: &str,
    record_ref: &str,
    code: &str,
) -> Result<(), VErr> {
    refuse_mutations_if_reserved(data_dir, &[record_ref], code, None)
}

/// Room replay for a different plane can ignore that plane's own reservation while still
/// refusing every pending frontier/claim intent. This helper deliberately does not inspect
/// offer intents; the offer owner seam performs its exact self-intent exception separately.
pub(crate) fn refuse_external_mutation_if_work_reserved(
    data_dir: &str,
    record_ref: &str,
    code: &str,
) -> Result<(), VErr> {
    if let Some((tail, overlap)) = pending_intent_overlap(data_dir, &[record_ref], None)? {
        return Err(verr(
            code,
            format!("record '{overlap}' is reserved by pending frontier/claim intent '{tail}'"),
        ));
    }
    Ok(())
}

/// Replay-only variant for an owner seam reached by the intent that reserved the record. Every
/// other pending intent remains a conflict; callers cannot use this to bypass another intent.
pub(crate) fn refuse_external_mutation_if_reserved_except(
    data_dir: &str,
    record_ref: &str,
    code: &str,
    ignored_intent_tail: &str,
) -> Result<(), VErr> {
    refuse_mutations_if_reserved(data_dir, &[record_ref], code, Some(ignored_intent_tail))
}

fn effective_live_claims(
    data_dir: &str,
    frontier_ref: Option<&str>,
    participant_ref: Option<&str>,
) -> Result<Vec<Value>, VErr> {
    let mut by_id: HashMap<String, Value> = HashMap::new();
    for (_, claim) in scan_records(data_dir, CLAIM_DIR, canonical_claim_tail)
        .map_err(|message| verr("work_frontier_claim_registry_unreadable", message))?
    {
        if live_claim_status(&s(&claim, "status", "")) {
            by_id.insert(s(&claim, "work_claim_id", ""), claim);
        }
    }
    for (_, intent) in scan_intents(data_dir)
        .map_err(|message| verr("work_frontier_claim_intent_unreadable", message))?
    {
        if let Some(claim) = intent_value(&intent, "final_claim") {
            let id = s(claim, "work_claim_id", "");
            if live_claim_status(&s(claim, "status", "")) {
                by_id.insert(id, claim.clone());
            } else {
                by_id.remove(&id);
            }
        }
    }
    Ok(by_id
        .into_values()
        .filter(|claim| {
            frontier_ref
                .map(|reference| s(claim, "frontier_item_ref", "") == reference)
                .unwrap_or(true)
                && participant_ref
                    .map(|reference| s(claim, "claimant_ref", "") == reference)
                    .unwrap_or(true)
        })
        .collect())
}

/// Room-close seam. Caller holds FRONTIER_CLAIM_LOCK before ROOM_MUTATION_LOCK. Canonical scan
/// failures are typed blockers; unresolved work, live claims, and pending compound transactions
/// all keep the room open.
pub(crate) fn refuse_room_close_if_blocked_locked(
    data_dir: &str,
    room_ref: &str,
) -> Result<(), VErr> {
    let frontier = scan_records(data_dir, FRONTIER_DIR, canonical_frontier_tail)
        .map_err(|message| verr("outcome_room_frontier_registry_unreadable", message))?;
    let unresolved: Vec<String> = frontier
        .iter()
        .filter(|(_, record)| {
            s(record, "outcome_room_ref", "") == room_ref
                && !matches!(
                    s(record, "status", "").as_str(),
                    "accepted" | "rejected" | "superseded" | "closed"
                )
        })
        .map(|(_, record)| s(record, "frontier_item_id", ""))
        .collect();
    let live: Vec<String> = scan_records(data_dir, CLAIM_DIR, canonical_claim_tail)
        .map_err(|message| verr("outcome_room_claim_registry_unreadable", message))?
        .into_iter()
        .filter(|(_, record)| {
            s(record, "outcome_room_ref", "") == room_ref
                && live_claim_status(&s(record, "status", ""))
        })
        .map(|(_, record)| s(&record, "work_claim_id", ""))
        .collect();
    let pending: Vec<String> = scan_intents(data_dir)
        .map_err(|message| verr("outcome_room_frontier_claim_intent_unreadable", message))?
        .into_iter()
        .filter(|(_, intent)| intent.get("room_ref").and_then(Value::as_str) == Some(room_ref))
        .map(|(_, intent)| s(&intent, "intent_id", ""))
        .collect();
    if !unresolved.is_empty() || !live.is_empty() || !pending.is_empty() {
        return Err(verr(
            "outcome_room_close_blocked_frontier_claims",
            format!(
                "room has {} unresolved frontier item(s), {} live claim(s), and {} pending frontier/claim transaction(s); resolve them before close ({})",
                unresolved.len(),
                live.len(),
                pending.len(),
                unresolved
                    .iter()
                    .chain(live.iter())
                    .chain(pending.iter())
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    Ok(())
}

fn resolve_room_open_strict(data_dir: &str, room_ref: &str) -> Result<Value, VErr> {
    let room = rooms::resolve_room_strict(data_dir, room_ref)
        .map_err(|message| verr("work_frontier_claim_room_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "work_frontier_claim_room_not_found",
                format!("no room '{room_ref}'"),
            )
        })?;
    if rooms::pending_intent(&room).is_some() {
        return Err(verr(
            "work_frontier_claim_room_in_flight",
            format!("room '{room_ref}' has a pending room transaction"),
        ));
    }
    if s(&room, "status", "") != "open" {
        return Err(verr(
            "work_frontier_claim_room_not_open",
            format!("room '{room_ref}' is not open"),
        ));
    }
    Ok(room)
}

fn participant_strict(data_dir: &str, participant_ref: &str) -> Result<Value, VErr> {
    participation::resolve_participant_lease_strict(data_dir, participant_ref)
        .map_err(|message| verr("work_frontier_claim_participant_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "work_frontier_claim_participant_not_found",
                format!("no participant lease '{participant_ref}'"),
            )
        })
}

/// Verifier-only rendezvous after authenticated resolution and before synchronous locks. It lets
/// every storm caller traverse the real serialized capability transport without spending its
/// resolver timeout waiting for other callers, then releases max_concurrency+1 contenders at the
/// same mutation boundary. Production never enables this environment variable.
async fn test_acquire_barrier(frontier_ref: &str, max_concurrency: usize) {
    if std::env::var("IOI_TEST_WORK_CLAIM_ACQUIRE_BARRIER")
        .ok()
        .as_deref()
        != Some("1")
    {
        return;
    }
    let parties = max_concurrency
        .saturating_add(1)
        .clamp(2, ITEM_CONCURRENCY_MAX as usize + 1);
    let barriers = TEST_ACQUIRE_BARRIERS.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
    let barrier = {
        let mut barriers = barriers.lock().await;
        barriers
            .entry(frontier_ref.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Barrier::new(parties)))
            .clone()
    };
    // A verifier contender can fail authenticated resolution before it reaches this point. Never
    // let that test-only failure turn into an unbounded daemon request: after a bounded soak
    // window, continue through the same production lock path and let atomic capacity decide.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(120), barrier.wait()).await;
}

// ================================= FRONTIER HTTP MUTATIONS ======================================

pub(crate) async fn handle_frontier_create(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let declaration = match validate_frontier_create(&body) {
        Ok(declaration) => declaration,
        Err(error) => return classify(error),
    };
    let room_ref = s(&declaration, "outcome_room_ref", "");
    let room = match rooms::resolve_room_strict(&state.data_dir, &room_ref) {
        Ok(Some(room)) => room,
        Ok(None) => {
            return classify(verr(
                "work_frontier_claim_room_not_found",
                format!("no room '{room_ref}'"),
            ))
        }
        Err(message) => return classify(verr("work_frontier_claim_room_unreadable", message)),
    };
    let room_revision = room.get("revision").and_then(Value::as_u64).unwrap_or(0);
    if let Err(error) = expected_revision(&body, room_revision) {
        return classify(error);
    }
    let host_ref = s(&room, "host_domain_ref", "");
    let frontier_tail = deterministic_tail("wfi_", &declaration);
    let frontier_ref = format!("frontier://{frontier_tail}");
    let effect = frontier_create_effect(&declaration, room_revision);
    let authorized = match governed::authorize_decision(
        FRONTIER_AUTHORITY,
        &body,
        Governance::Host,
        &room_ref,
        &host_ref,
        &frontier_ref,
        "create",
        room_revision,
        &effect,
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(challenge) => return challenge,
    };

    let _offer_guard = super::resource_capability_offer_routes::OFFER_MATCH_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _frontier_guard = FRONTIER_CLAIM_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _room_guard = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let current_room = match resolve_room_open_strict(&state.data_dir, &room_ref) {
        Ok(room) => room,
        Err(error) => return classify(error),
    };
    if let Err(error) = expected_revision(
        &body,
        current_room
            .get("revision")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    ) {
        return classify(error);
    }
    let records = match scan_records(&state.data_dir, FRONTIER_DIR, canonical_frontier_tail) {
        Ok(records) => records,
        Err(message) => return classify(verr("work_frontier_claim_registry_unreadable", message)),
    };
    let pending_creates = match scan_intents(&state.data_dir) {
        Ok(intents) => intents
            .iter()
            .filter(|(_, intent)| {
                intent.get("kind").and_then(Value::as_str) == Some("frontier_create")
                    && intent.get("room_ref").and_then(Value::as_str) == Some(room_ref.as_str())
            })
            .count(),
        Err(message) => return classify(verr("work_frontier_claim_intent_unreadable", message)),
    };
    let current_count = records
        .iter()
        .filter(|(_, record)| s(record, "outcome_room_ref", "") == room_ref)
        .count();
    if current_count + pending_creates >= ROOM_FRONTIER_MAX {
        return classify(verr(
            "work_frontier_claim_room_frontier_capacity",
            format!("room frontier is bounded at {ROOM_FRONTIER_MAX} items"),
        ));
    }
    let frontier_occupied = match load_frontier(&state.data_dir, &frontier_tail) {
        Ok(record) => record.is_some(),
        Err(message) => return classify(verr("work_frontier_claim_registry_unreadable", message)),
    };
    if let Err(error) = refuse_mutations_if_reserved(
        &state.data_dir,
        &[&frontier_ref, &room_ref],
        "work_frontier_claim_mutation_in_flight",
        None,
    ) {
        return classify(error);
    }
    if frontier_occupied {
        return classify(verr(
            "work_frontier_claim_conflict",
            format!("frontier declaration already exists as '{frontier_ref}'"),
        ));
    }
    for dependency in array_strings(&declaration, "dependency_refs") {
        if dependency == frontier_ref {
            return classify(verr(
                "work_frontier_claim_dependency_cycle",
                "frontier item cannot depend on itself",
            ));
        }
        if dependency.starts_with("frontier://") {
            let Some(prior) = frontier_by_ref(&records, &dependency) else {
                return classify(verr(
                    "work_frontier_claim_dependencies_unresolved",
                    format!("frontier dependency '{dependency}' does not resolve"),
                ));
            };
            if s(prior, "outcome_room_ref", "") != room_ref {
                return classify(verr(
                    "work_frontier_claim_cross_room_dependency",
                    format!("frontier dependency '{dependency}' belongs to another room"),
                ));
            }
        }
    }
    if dependency_cycle(&records, &declaration, &frontier_ref) {
        return classify(verr(
            "work_frontier_claim_dependency_cycle",
            "frontier dependency graph would contain a cycle",
        ));
    }
    let receipt_tail = new_receipt_tail(
        "wfr_",
        &frontier_ref,
        "create",
        0,
        authorized.resolved_at_ms,
    );
    let receipt_ref = format!("receipt://{receipt_tail}");
    let final_frontier = match seal_frontier(
        &declaration,
        &frontier_tail,
        &receipt_ref,
        authorized.resolved_at_ms,
    ) {
        Ok(record) => record,
        Err(error) => return classify(error),
    };
    let receipt = match build_receipt(
        &receipt_tail,
        FRONTIER_RECEIPT_SCHEMA,
        "WorkFrontierMutationReceipt",
        &frontier_ref,
        "create",
        json!({ "outcome_room_ref": room_ref, "item_kind": s(&declaration, "item_kind", ""), "status": "open" }),
        vec![json!(frontier_ref), json!(room_ref)],
        &final_frontier,
        FRONTIER_NOTE,
        &authorized,
    ) {
        Ok(receipt) => receipt,
        Err(error) => return classify(error),
    };
    let intent_tail = new_intent_tail(&frontier_ref, "create", 0, authorized.resolved_at_ms);
    let intent = seal_intent(
        json!({
            "kind": "frontier_create",
            "op": "create",
            "governance": "host",
            "room_ref": room_ref,
            "required_authority_ref": host_ref,
            "subject_ref": frontier_ref,
            "revision_before": room_revision,
            "receipt_tail": receipt_tail,
            "receipt": receipt,
            "prior_frontier": Value::Null,
            "final_frontier": final_frontier,
            "prior_claim": Value::Null,
            "final_claim": Value::Null,
            "participant_ref": Value::Null,
            "prior_participant": Value::Null,
            "final_participant": Value::Null,
        }),
        &intent_tail,
    );
    match persist_and_complete_intent_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({ "frontier_item": final_frontier, "frontier_receipt": receipt })),
        ),
        Err(error) => classify(error),
    }
}

pub(crate) async fn handle_frontier_transition(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = reject_sensitive_keys(&body, "") {
        return classify(error);
    }
    if let Err(error) = reject_unknown_fields(
        &body,
        &["transition", "expected_revision", "wallet_approval_grant"],
    ) {
        return classify(error);
    }
    let op = match bounded_string(&body, "transition", 40, true) {
        Ok(Some(op)) => op,
        Ok(None) => unreachable!(),
        Err(error) => return classify(error),
    };
    if op == "accept" {
        return classify(verr(
            "work_frontier_acceptance_unavailable",
            "accepted remains unavailable until Attempt/Finding/verifier admission exists",
        ));
    }
    let Some((_, from_statuses, to_status)) = FRONTIER_TRANSITIONS
        .iter()
        .find(|(transition, _, _)| *transition == op)
    else {
        return classify(verr(
            "work_frontier_transition_invalid",
            format!("unknown transition '{op}'"),
        ));
    };
    let prior = match load_frontier(&state.data_dir, &id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return classify(verr(
                "work_frontier_not_found",
                format!("no frontier item '{id}'"),
            ))
        }
        Err(message) => return classify(verr("work_frontier_claim_registry_unreadable", message)),
    };
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    if let Err(error) = expected_revision(&body, revision) {
        return classify(error);
    }
    if !from_statuses.contains(&s(&prior, "status", "").as_str()) {
        return classify(verr(
            "work_frontier_transition_invalid",
            format!("cannot '{op}' from '{}'", s(&prior, "status", "")),
        ));
    }
    let room_ref = s(&prior, "outcome_room_ref", "");
    let host_ref = match rooms::resolve_room_host(&state.data_dir, &room_ref) {
        Some(host) => host,
        None => {
            return classify(verr(
                "work_frontier_claim_room_not_found",
                format!("room '{room_ref}' does not resolve"),
            ))
        }
    };
    let subject_ref = s(&prior, "frontier_item_id", "");
    let effect = frontier_transition_effect(&op, revision);
    let authorized = match governed::authorize_decision(
        FRONTIER_AUTHORITY,
        &body,
        Governance::Host,
        &room_ref,
        &host_ref,
        &subject_ref,
        &op,
        revision,
        &effect,
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(challenge) => return challenge,
    };
    let _offer_guard = super::resource_capability_offer_routes::OFFER_MATCH_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _frontier_guard = FRONTIER_CLAIM_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _room_guard = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(error) = resolve_room_open_strict(&state.data_dir, &room_ref) {
        return classify(error);
    }
    let current = match load_frontier(&state.data_dir, &id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return classify(verr(
                "work_frontier_not_found",
                format!("no frontier item '{id}'"),
            ))
        }
        Err(message) => return classify(verr("work_frontier_claim_registry_unreadable", message)),
    };
    if let Err(error) = expected_revision(
        &body,
        current.get("revision").and_then(Value::as_u64).unwrap_or(0),
    ) {
        return classify(error);
    }
    if let Err(error) = refuse_mutations_if_reserved(
        &state.data_dir,
        &[&subject_ref],
        "work_frontier_claim_mutation_in_flight",
        None,
    ) {
        return classify(error);
    }
    let live = match effective_live_claims(&state.data_dir, Some(&subject_ref), None) {
        Ok(claims) => claims,
        Err(error) => return classify(error),
    };
    if !live.is_empty() {
        return classify(verr(
            "work_frontier_claim_live_claim_conflict",
            format!(
                "frontier transition '{op}' refuses while {} live claim(s) remain",
                live.len()
            ),
        ));
    }
    let receipt_tail = new_receipt_tail(
        "wfr_",
        &subject_ref,
        &op,
        revision,
        authorized.resolved_at_ms,
    );
    let receipt_ref = format!("receipt://{receipt_tail}");
    let final_frontier = match transition_frontier(
        &current,
        &op,
        to_status,
        &receipt_ref,
        authorized.resolved_at_ms,
    ) {
        Ok(record) => record,
        Err(error) => return classify(error),
    };
    let receipt = match build_receipt(
        &receipt_tail,
        FRONTIER_RECEIPT_SCHEMA,
        "WorkFrontierMutationReceipt",
        &subject_ref,
        &op,
        json!({ "outcome_room_ref": room_ref, "from": s(&current, "status", ""), "to": to_status, "revision_before": revision, "revision_after": revision + 1 }),
        vec![json!(subject_ref), json!(room_ref)],
        &final_frontier,
        FRONTIER_NOTE,
        &authorized,
    ) {
        Ok(receipt) => receipt,
        Err(error) => return classify(error),
    };
    let intent_tail = new_intent_tail(&subject_ref, &op, revision, authorized.resolved_at_ms);
    let intent = seal_intent(
        json!({
            "kind": "frontier_transition", "op": op, "governance": "host",
            "room_ref": room_ref, "required_authority_ref": host_ref,
            "subject_ref": subject_ref, "revision_before": revision,
            "receipt_tail": receipt_tail, "receipt": receipt,
            "prior_frontier": current, "final_frontier": final_frontier,
            "prior_claim": Value::Null, "final_claim": Value::Null,
            "participant_ref": Value::Null, "prior_participant": Value::Null,
            "final_participant": Value::Null,
        }),
        &intent_tail,
    );
    match persist_and_complete_intent_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "frontier_item": final_frontier, "frontier_receipt": receipt })),
        ),
        Err(error) => classify(error),
    }
}

// ================================= CLAIM HTTP MUTATIONS =========================================

pub(crate) async fn handle_claim_acquire(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let declaration = match validate_claim_acquire(&body) {
        Ok(declaration) => declaration,
        Err(error) => return classify(error),
    };
    let frontier_ref = s(&declaration, "frontier_item_ref", "");
    let frontier = match load_frontier(&state.data_dir, &frontier_ref) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return classify(verr(
                "work_frontier_not_found",
                format!("no frontier item '{frontier_ref}'"),
            ))
        }
        Err(message) => return classify(verr("work_frontier_claim_registry_unreadable", message)),
    };
    let frontier_revision_at_authorization = frontier
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let frontier_control_at_authorization = frontier_claim_control_hash(&frontier);
    let participant_ref = s(&declaration, "claimant_ref", "");
    let participant = match participant_strict(&state.data_dir, &participant_ref) {
        Ok(record) => record,
        Err(error) => return classify(error),
    };
    let participant_revision = participant
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if let Err(error) = expected_revision(&body, participant_revision) {
        return classify(error);
    }
    let room_ref = s(&declaration, "outcome_room_ref", "");
    if s(&frontier, "outcome_room_ref", "") != room_ref
        || s(&participant, "outcome_room_ref", "") != room_ref
    {
        return classify(verr(
            "work_claim_cross_room",
            "frontier, participant lease, and claim must name the same room",
        ));
    }
    if s(&participant, "status", "") != "active" {
        return classify(verr(
            "work_frontier_claim_participant_not_active",
            "claimant participant lease must be active",
        ));
    }
    if participant
        .get("current_claim_ref")
        .is_some_and(|value| !value.is_null())
    {
        return classify(verr(
            "work_frontier_claim_current_claim_conflict",
            "participant already has a current claim",
        ));
    }
    let eligibility_receipt_ref = declaration
        .get("eligibility_match_receipt_ref")
        .and_then(Value::as_str);
    if let Err(response) = super::resource_capability_offer_routes::reauthorize_eligibility_for_claim(
        &state.data_dir,
        eligibility_receipt_ref,
        &frontier,
        &participant,
        &declaration,
    )
    .await
    {
        return response;
    }
    let participant_authority = s(&participant, "participant_ref", "");
    let claim_material = json!({
        "declaration": declaration,
        "frontier_revision": frontier_revision_at_authorization,
        "participant_revision": participant.get("revision").cloned().unwrap_or(Value::Null),
    });
    let claim_tail = deterministic_tail("wcl_", &claim_material);
    let claim_ref = format!("work-claim://{claim_tail}");
    let effect = claim_acquire_effect(&declaration, participant_revision);
    let authorized = match governed::authorize_decision(
        CLAIM_AUTHORITY,
        &body,
        Governance::Participant,
        &room_ref,
        &participant_authority,
        &claim_ref,
        "acquire",
        participant_revision,
        &effect,
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(challenge) => return challenge,
    };
    test_acquire_barrier(
        &frontier_ref,
        frontier
            .get("max_concurrency")
            .and_then(Value::as_u64)
            .unwrap_or(1) as usize,
    )
    .await;
    let _participant_guard = participation::PARTICIPATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _resource_guard = super::resource_routes::RESOURCE_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _offer_guard = super::resource_capability_offer_routes::OFFER_MATCH_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _frontier_guard = FRONTIER_CLAIM_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _room_guard = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(error) = resolve_room_open_strict(&state.data_dir, &room_ref) {
        return classify(error);
    }
    let current_participant = match participant_strict(&state.data_dir, &participant_ref) {
        Ok(record) => record,
        Err(error) => return classify(error),
    };
    if current_participant != participant {
        return classify(verr(
            "work_frontier_claim_stale_revision",
            "participant lease changed during authorization",
        ));
    }
    if s(&current_participant, "status", "") != "active" {
        return classify(verr(
            "work_frontier_claim_participant_not_active",
            "claimant participant lease must be active",
        ));
    }
    if current_participant
        .get("current_claim_ref")
        .is_some_and(|value| !value.is_null())
    {
        return classify(verr(
            "work_frontier_claim_current_claim_conflict",
            "participant already has a current claim",
        ));
    }
    let current_frontier = match load_frontier(&state.data_dir, &frontier_ref) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return classify(verr(
                "work_frontier_not_found",
                format!("no frontier item '{frontier_ref}'"),
            ))
        }
        Err(message) => return classify(verr("work_frontier_claim_registry_unreadable", message)),
    };
    if frontier_claim_control_hash(&current_frontier) != frontier_control_at_authorization {
        return classify(verr(
            "work_frontier_claim_stale_revision",
            "frontier claimability, policy, or dependency control changed during authorization",
        ));
    }
    if let Err(error) = refuse_mutations_if_reserved(
        &state.data_dir,
        &[&claim_ref, &frontier_ref, &participant_ref],
        "work_frontier_claim_mutation_in_flight",
        None,
    ) {
        return classify(error);
    }
    if let Err(error) = super::resource_capability_offer_routes::validate_eligibility_for_claim_locked(
        &state.data_dir,
        eligibility_receipt_ref,
        &current_frontier,
        &current_participant,
        &declaration,
    ) {
        return classify(error);
    }
    if !matches!(
        s(&current_frontier, "status", "").as_str(),
        "open" | "claimed" | "replicating"
    ) {
        return classify(verr(
            "work_claim_frontier_not_ready",
            format!(
                "frontier status '{}' is not claimable",
                s(&current_frontier, "status", "")
            ),
        ));
    }
    if s(&current_frontier, "claimability", "") != "open" {
        return classify(verr(
            "work_claim_claimability_unavailable",
            "#76 admits direct claims only for claimability=open; invited/assigned receiving-party admission remains unavailable",
        ));
    }
    let records = match scan_records(&state.data_dir, FRONTIER_DIR, canonical_frontier_tail) {
        Ok(records) => records,
        Err(message) => return classify(verr("work_frontier_claim_registry_unreadable", message)),
    };
    if let Err(error) = dependencies_ready(&records, &current_frontier) {
        return classify(error);
    }
    if !compatible_duplication(&current_frontier, &declaration) {
        return classify(verr(
            "work_claim_duplication_policy_conflict",
            "claim duplicate_work_policy is incompatible with the frontier item",
        ));
    }
    let live_for_item = match effective_live_claims(&state.data_dir, Some(&frontier_ref), None) {
        Ok(claims) => claims,
        Err(error) => return classify(error),
    };
    let max_concurrency = current_frontier
        .get("max_concurrency")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    if live_for_item.len() >= max_concurrency {
        return classify(verr(
            "work_claim_capacity_exhausted",
            format!("frontier capacity {max_concurrency} is full"),
        ));
    }
    let live_for_participant =
        match effective_live_claims(&state.data_dir, None, Some(&participant_ref)) {
            Ok(claims) => claims,
            Err(error) => return classify(error),
        };
    if !live_for_participant.is_empty() {
        return classify(verr(
            "work_frontier_claim_current_claim_conflict",
            "participant already has a completed or pending live claim",
        ));
    }
    let claim_occupied = match load_claim(&state.data_dir, &claim_ref) {
        Ok(record) => record.is_some(),
        Err(message) => return classify(verr("work_frontier_claim_registry_unreadable", message)),
    };
    if claim_occupied {
        return classify(verr(
            "work_claim_conflict",
            format!("claim '{claim_ref}' already exists"),
        ));
    }
    let receipt_tail =
        new_receipt_tail("wcr_", &claim_ref, "acquire", 0, authorized.resolved_at_ms);
    let receipt_ref = format!("receipt://{receipt_tail}");
    let final_claim = match seal_claim(
        &declaration,
        &claim_tail,
        &receipt_ref,
        authorized.resolved_at_ms,
    ) {
        Ok(record) => record,
        Err(error) => return classify(error),
    };
    let final_frontier = match frontier_claim_successor(
        &current_frontier,
        &claim_ref,
        &receipt_ref,
        authorized.resolved_at_ms,
        true,
        false,
    ) {
        Ok(record) => record,
        Err(error) => return classify(error),
    };
    let wallet_now = match ms_to_rfc3339(authorized.resolved_at_ms) {
        Ok(now) => now,
        Err(error) => return classify(error),
    };
    let final_participant = match participation::participant_current_claim_successor(
        &current_participant,
        &claim_ref,
        &receipt_ref,
        &wallet_now,
        true,
    ) {
        Ok(record) => record,
        Err(error) => return classify(error),
    };
    let receipt = match build_receipt(
        &receipt_tail,
        CLAIM_RECEIPT_SCHEMA,
        "WorkClaimLeaseReceipt",
        &claim_ref,
        "acquire",
        json!({
            "outcome_room_ref": room_ref, "frontier_item_ref": frontier_ref,
            "claimant_ref": participant_ref, "issued_at_ms": authorized.resolved_at_ms,
            "expires_at_ms": final_claim.get("expires_at_ms").cloned().unwrap_or(Value::Null),
            "revision_after": 1,
        }),
        vec![
            json!(claim_ref),
            json!(frontier_ref),
            json!(participant_ref),
            json!(room_ref),
        ],
        &final_claim,
        CLAIM_NOTE,
        &authorized,
    ) {
        Ok(receipt) => receipt,
        Err(error) => return classify(error),
    };
    let intent_tail = new_intent_tail(&claim_ref, "acquire", 0, authorized.resolved_at_ms);
    let intent = seal_intent(
        json!({
            "kind": "claim_acquire", "op": "acquire", "governance": "participant",
            "room_ref": room_ref, "required_authority_ref": participant_authority,
            "subject_ref": claim_ref, "revision_before": participant_revision,
            "frontier_revision_at_authorization": frontier_revision_at_authorization,
            "frontier_control_hash_at_authorization": frontier_control_at_authorization,
            "receipt_tail": receipt_tail, "receipt": receipt,
            "prior_frontier": current_frontier, "final_frontier": final_frontier,
            "prior_claim": Value::Null, "final_claim": final_claim,
            "participant_ref": participant_ref, "prior_participant": current_participant,
            "final_participant": final_participant,
        }),
        &intent_tail,
    );
    match persist_and_complete_intent_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(
                json!({ "work_claim": final_claim, "frontier_item": final_frontier, "participant_lease": final_participant, "work_claim_receipt": receipt }),
            ),
        ),
        Err(error) => classify(error),
    }
}

fn claim_transition_contract(
    op: &str,
    from: &str,
) -> Result<(Governance, &'static str, bool), VErr> {
    match op {
        "wait" if from == "active" => Ok((Governance::Participant, "waiting", false)),
        "resume" if from == "waiting" => Ok((Governance::Participant, "active", false)),
        "heartbeat" if matches!(from, "active" | "waiting") => Ok((
            Governance::Participant,
            if from == "active" {
                "active"
            } else {
                "waiting"
            },
            false,
        )),
        "renew" if matches!(from, "active" | "waiting") => Ok((
            Governance::Participant,
            if from == "active" {
                "active"
            } else {
                "waiting"
            },
            false,
        )),
        "release" if matches!(from, "active" | "waiting") => {
            Ok((Governance::Participant, "released", true))
        }
        "complete" if matches!(from, "active" | "waiting") => {
            Ok((Governance::Participant, "completed", true))
        }
        "quarantine" if matches!(from, "active" | "waiting") => {
            Ok((Governance::Host, "quarantined", true))
        }
        "revoke" if matches!(from, "active" | "waiting") => Ok((Governance::Host, "revoked", true)),
        "revoke" if from == "quarantined" => Ok((Governance::Host, "revoked", false)),
        "expire" if matches!(from, "active" | "waiting") => Ok((Governance::Host, "expired", true)),
        "reassign" => Err(verr(
            "work_claim_reassignment_unavailable",
            "reassignment remains unavailable until receiving-party admission exists",
        )),
        _ => Err(verr(
            "work_claim_transition_invalid",
            format!("cannot '{op}' from '{from}'"),
        )),
    }
}

fn frontier_create_effect(declaration: &Value, room_revision: u64) -> Value {
    json!({
        "declaration": declaration,
        "expected_revision": room_revision,
    })
}

fn frontier_transition_effect(op: &str, revision: u64) -> Value {
    json!({
        "transition": op,
        "expected_revision": revision,
    })
}

fn claim_acquire_effect(declaration: &Value, participant_revision: u64) -> Value {
    json!({
        "declaration": declaration,
        "expected_revision": participant_revision,
    })
}

fn claim_transition_effect(op: &str, revision: u64, body: &Value) -> Result<Value, VErr> {
    for (field, admitted_op) in [("ttl_seconds", "renew"), ("heartbeat_ref", "heartbeat")] {
        if op != admitted_op && body.get(field).is_some_and(|value| !value.is_null()) {
            return Err(verr(
                "work_claim_field_not_admitted_for_transition",
                format!("'{field}' is admitted only for transition '{admitted_op}'"),
            ));
        }
    }
    let terminal = matches!(
        op,
        "release" | "complete" | "expire" | "quarantine" | "revoke"
    );
    if !terminal && body.get("reason").is_some_and(|value| !value.is_null()) {
        return Err(verr(
            "work_claim_field_not_admitted_for_transition",
            "'reason' is admitted only for a terminal claim transition",
        ));
    }
    let mut effect = json!({
        "transition": op,
        "expected_revision": revision,
    });
    let object = effect.as_object_mut().expect("effect object");
    if op == "renew" {
        let ttl_seconds = body
            .get("ttl_seconds")
            .and_then(Value::as_u64)
            .ok_or_else(|| verr("work_claim_ttl_required", "renew requires ttl_seconds"))?;
        if !(CLAIM_TTL_MIN_SECONDS..=CLAIM_TTL_MAX_SECONDS).contains(&ttl_seconds) {
            return Err(verr(
                "work_claim_ttl_invalid",
                "renew ttl_seconds is out of bounds",
            ));
        }
        object.insert("ttl_seconds".into(), json!(ttl_seconds));
    }
    if op == "heartbeat" {
        object.insert(
            "heartbeat_ref".into(),
            optional_ref(body, "heartbeat_ref", &["heartbeat", "receipt"])?
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
    }
    if matches!(
        op,
        "release" | "complete" | "expire" | "quarantine" | "revoke"
    ) {
        object.insert(
            "reason".into(),
            Value::String(
                bounded_string(body, "reason", REASON_MAX, true)?.ok_or_else(|| {
                    verr(
                        "work_claim_reason_required",
                        "terminal transition requires reason",
                    )
                })?,
            ),
        );
    }
    Ok(effect)
}

fn claim_expired_at(claim: &Value, wallet_time_ms: u64) -> bool {
    claim
        .get("expires_at_ms")
        .and_then(Value::as_u64)
        .is_none_or(|expires_at_ms| wallet_time_ms >= expires_at_ms)
}

pub(crate) struct PreparedParticipantTerminalClaim {
    prior_claim: Value,
    prior_participant: Value,
    participant_ref: String,
    room_ref: String,
    required_authority: String,
    effect_op: &'static str,
    to_status: &'static str,
    governance: Governance,
    authorized: AuthorizedDecision,
}

/// Resolve and authorize the claim half of participant retire/revoke before any synchronous lock
/// is held. The compound endpoint carries a separately signed work-claim grant because the
/// room-participation grant is never widened into claim authority.
pub(crate) async fn prepare_participant_terminal_claim(
    data_dir: &str,
    participant: &Value,
    participant_transition: &str,
    body: &Value,
) -> Result<Option<PreparedParticipantTerminalClaim>, (StatusCode, Json<Value>)> {
    if !matches!(participant_transition, "retire" | "revoke" | "quarantine") {
        return Ok(None);
    }
    let Some(claim_ref) = participant.get("current_claim_ref").and_then(Value::as_str) else {
        return Ok(None);
    };
    if !canonical_claim_ref(claim_ref) {
        return Err(classify(verr(
            "work_claim_participant_binding_mismatch",
            "participant current_claim_ref is noncanonical",
        )));
    }
    let prior_claim = match load_claim(data_dir, claim_ref) {
        Ok(Some(claim)) => claim,
        Ok(None) => {
            return Err(classify(verr(
                "work_claim_not_found",
                format!("participant names missing current claim '{claim_ref}'"),
            )))
        }
        Err(message) => return Err(read_registry_error(message)),
    };
    let participant_ref = s(participant, "participant_lease_id", "");
    let room_ref = s(participant, "outcome_room_ref", "");
    if s(&prior_claim, "claimant_ref", "") != participant_ref
        || s(&prior_claim, "outcome_room_ref", "") != room_ref
        || !live_claim_status(&s(&prior_claim, "status", ""))
    {
        return Err(classify(verr(
            "work_claim_participant_binding_mismatch",
            "participant and current claim coordinates/status do not agree",
        )));
    }
    let claim_revision = prior_claim
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    match body
        .get("work_claim_expected_revision")
        .and_then(Value::as_u64)
    {
        Some(expected) if expected == claim_revision => {}
        Some(expected) => {
            return Err(classify(verr(
                "work_frontier_claim_stale_revision",
                format!(
                    "expected work-claim revision {expected}, current revision is {claim_revision}"
                ),
            )))
        }
        None => {
            return Err(classify(verr(
                "work_frontier_claim_expected_revision_required",
                "participant retire/revoke with a live claim requires work_claim_expected_revision",
            )))
        }
    }
    let (effect_op, to_status, governance, required_authority) =
        if participant_transition == "retire" {
            (
                "release",
                "released",
                Governance::Participant,
                s(participant, "participant_ref", ""),
            )
        } else {
            let Some(host) = rooms::resolve_room_host(data_dir, &room_ref) else {
                return Err(classify(verr(
                    "work_frontier_claim_room_not_found",
                    format!("room host for '{room_ref}' does not resolve"),
                )));
            };
            if participant_transition == "quarantine" {
                ("quarantine", "quarantined", Governance::Host, host)
            } else {
                ("revoke", "revoked", Governance::Host, host)
            }
        };
    let reason = match effect_op {
        "release" => "participant retired; current claim released before room-slot release",
        "quarantine" => "room host quarantined participant; current claim quarantined before future access ended",
        _ => "room host revoked participant; current claim revoked before room-slot release",
    };
    let grant_body = json!({
        "wallet_approval_grant": body.get("work_claim_wallet_approval_grant").cloned().unwrap_or(Value::Null),
    });
    let effect_body = json!({
        "transition": effect_op,
        "expected_revision": claim_revision,
        "reason": reason,
    });
    let effect =
        claim_transition_effect(effect_op, claim_revision, &effect_body).map_err(classify)?;
    let authorized = governed::authorize_decision(
        CLAIM_AUTHORITY,
        &grant_body,
        governance,
        &room_ref,
        &required_authority,
        claim_ref,
        effect_op,
        claim_revision,
        &effect,
    )
    .await?;
    Ok(Some(PreparedParticipantTerminalClaim {
        prior_claim,
        prior_participant: participant.clone(),
        participant_ref,
        room_ref,
        required_authority,
        effect_op,
        to_status,
        governance,
        authorized,
    }))
}

/// Build the separately authorized claim half of participant retirement/revocation while all
/// three owner locks are held. The returned intent is persisted into its own family before the
/// participation record can become terminal; the participation transition intent embeds the
/// exact same bytes so a crash can restore it without inventing authority.
pub(crate) fn build_participant_terminal_claim_intent_locked(
    data_dir: &str,
    prepared: PreparedParticipantTerminalClaim,
    terminal_participant: &Value,
) -> Result<(String, Value), VErr> {
    let claim_ref = s(&prepared.prior_claim, "work_claim_id", "");
    let claim_revision = prepared
        .prior_claim
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let current_claim = load_claim(data_dir, &claim_ref)
        .map_err(|message| verr("work_frontier_claim_registry_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "work_claim_not_found",
                format!("no work claim '{claim_ref}'"),
            )
        })?;
    if current_claim != prepared.prior_claim {
        return Err(verr(
            "work_frontier_claim_stale_revision",
            "current claim changed during participant terminal authorization",
        ));
    }
    let current_participant = participant_strict(data_dir, &prepared.participant_ref)?;
    if current_participant != prepared.prior_participant
        || terminal_participant
            .get("current_claim_ref")
            .and_then(Value::as_str)
            != Some(claim_ref.as_str())
        || s(terminal_participant, "participant_lease_id", "") != prepared.participant_ref
        || !matches!(
            s(terminal_participant, "status", "").as_str(),
            "retired" | "revoked" | "quarantined"
        )
    {
        return Err(verr(
            "work_claim_participant_binding_mismatch",
            "participant prior/terminal successor does not retain the exact current claim coordinate",
        ));
    }
    let frontier_ref = s(&current_claim, "frontier_item_ref", "");
    let mut mutation_refs = vec![
        claim_ref.as_str(),
        frontier_ref.as_str(),
        prepared.participant_ref.as_str(),
    ];
    if matches!(
        s(terminal_participant, "status", "").as_str(),
        "retired" | "revoked"
    ) {
        mutation_refs.push(prepared.room_ref.as_str());
    }
    refuse_mutations_if_reserved(
        data_dir,
        &mutation_refs,
        "work_frontier_claim_mutation_in_flight",
        None,
    )?;
    let current_frontier = load_frontier(data_dir, &frontier_ref)
        .map_err(|message| verr("work_frontier_claim_registry_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "work_frontier_not_found",
                format!("no frontier item '{frontier_ref}'"),
            )
        })?;
    let receipt_tail = new_receipt_tail(
        "wcr_",
        &claim_ref,
        prepared.effect_op,
        claim_revision,
        prepared.authorized.resolved_at_ms,
    );
    let receipt_ref = format!("receipt://{receipt_tail}");
    let reason = match prepared.effect_op {
        "release" => "participant retired; current claim released before room-slot release",
        "quarantine" => "room host quarantined participant; current claim quarantined before future access ended",
        _ => "room host revoked participant; current claim revoked before room-slot release",
    };
    let final_claim = transition_claim(
        &current_claim,
        prepared.effect_op,
        prepared.to_status,
        &receipt_ref,
        prepared.authorized.resolved_at_ms,
        &json!({ "reason": reason }),
    )?;
    let final_frontier = frontier_claim_successor(
        &current_frontier,
        &claim_ref,
        &receipt_ref,
        prepared.authorized.resolved_at_ms,
        false,
        false,
    )?;
    let wallet_now = ms_to_rfc3339(prepared.authorized.resolved_at_ms)?;
    let final_participant = participation::participant_current_claim_successor(
        terminal_participant,
        &claim_ref,
        &receipt_ref,
        &wallet_now,
        false,
    )?;
    let receipt = build_receipt(
        &receipt_tail,
        CLAIM_RECEIPT_SCHEMA,
        "WorkClaimLeaseReceipt",
        &claim_ref,
        prepared.effect_op,
        json!({
            "outcome_room_ref": prepared.room_ref,
            "frontier_item_ref": frontier_ref,
            "claimant_ref": prepared.participant_ref,
            "from": s(&current_claim, "status", ""),
            "to": prepared.to_status,
            "revision_before": claim_revision,
            "revision_after": claim_revision + 1,
            "wallet_time_ms": prepared.authorized.resolved_at_ms,
        }),
        vec![
            json!(claim_ref),
            json!(frontier_ref),
            json!(prepared.participant_ref),
            json!(prepared.room_ref),
        ],
        &final_claim,
        CLAIM_NOTE,
        &prepared.authorized,
    )?;
    let intent_tail = new_intent_tail(
        &claim_ref,
        prepared.effect_op,
        claim_revision,
        prepared.authorized.resolved_at_ms,
    );
    let intent = seal_intent(
        json!({
            "kind": "claim_transition", "op": prepared.effect_op,
            "governance": if prepared.governance == Governance::Host { "host" } else { "participant" },
            "room_ref": prepared.room_ref,
            "required_authority_ref": prepared.required_authority,
            "subject_ref": claim_ref, "revision_before": claim_revision,
            "receipt_tail": receipt_tail, "receipt": receipt,
            "prior_frontier": current_frontier, "final_frontier": final_frontier,
            "prior_claim": current_claim, "final_claim": final_claim,
            "participant_ref": prepared.participant_ref,
            "prior_participant": terminal_participant, "final_participant": final_participant,
            "release_terminal_room_slot": matches!(s(terminal_participant, "status", "").as_str(), "retired" | "revoked"),
        }),
        &intent_tail,
    );
    validate_sealed_intent(&intent, &intent_tail).map_err(|message| {
        verr(
            "work_frontier_claim_intent_invalid",
            format!("refused to seal compound participant/claim transaction: {message}"),
        )
    })?;
    Ok((intent_tail, intent))
}

/// Persist a prevalidated embedded intent without applying it. Exact existing bytes are
/// idempotent; a different occupant is a hard no-clobber conflict.
pub(crate) fn persist_embedded_intent_locked(
    data_dir: &str,
    tail: &str,
    intent: &Value,
) -> Result<(), VErr> {
    validate_sealed_intent(intent, tail).map_err(|message| {
        verr(
            "work_frontier_claim_intent_invalid",
            format!("embedded transaction does not reconstruct: {message}"),
        )
    })?;
    match read_slot(data_dir, INTENT_DIR, tail, canonical_intent_tail)
        .map_err(|message| verr("work_frontier_claim_intent_unreadable", message))?
    {
        Some(existing) if existing == *intent => Ok(()),
        Some(_) => Err(verr(
            "work_frontier_claim_intent_conflict",
            format!("intent slot '{tail}' contains different authenticated bytes"),
        )),
        None => persist_record(data_dir, INTENT_DIR, tail, intent),
    }
}

/// Apply a compound intent that was authorized in the current request and already made durable.
/// Callers hold participation -> frontier/claim -> room in that order.
pub(crate) fn complete_embedded_intent_locked(
    data_dir: &str,
    tail: &str,
    intent: &Value,
) -> Result<(), VErr> {
    complete_intent_locked(data_dir, tail, intent)
}

pub(crate) async fn handle_claim_transition(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = reject_sensitive_keys(&body, "") {
        return classify(error);
    }
    if let Err(error) = reject_unknown_fields(
        &body,
        &[
            "transition",
            "expected_revision",
            "wallet_approval_grant",
            "ttl_seconds",
            "heartbeat_ref",
            "reason",
        ],
    ) {
        return classify(error);
    }
    let op = match bounded_string(&body, "transition", 40, true) {
        Ok(Some(op)) => op,
        Ok(None) => unreachable!(),
        Err(error) => return classify(error),
    };
    let prior_claim = match load_claim(&state.data_dir, &id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return classify(verr(
                "work_claim_not_found",
                format!("no work claim '{id}'"),
            ))
        }
        Err(message) => return classify(verr("work_frontier_claim_registry_unreadable", message)),
    };
    let revision = prior_claim
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if let Err(error) = expected_revision(&body, revision) {
        return classify(error);
    }
    let (governance, to_status, releases_binding) =
        match claim_transition_contract(&op, &s(&prior_claim, "status", "")) {
            Ok(contract) => contract,
            Err(error) => return classify(error),
        };
    let room_ref = s(&prior_claim, "outcome_room_ref", "");
    let participant_ref = s(&prior_claim, "claimant_ref", "");
    let participant = match participant_strict(&state.data_dir, &participant_ref) {
        Ok(record) => record,
        Err(error) => return classify(error),
    };
    if governance == Governance::Participant && s(&participant, "status", "") != "active" {
        return classify(verr(
            "work_frontier_claim_participant_not_active",
            "participant-governed claim mutations require an active participant lease",
        ));
    }
    let required_authority = match governance {
        Governance::Participant => s(&participant, "participant_ref", ""),
        Governance::Host => match rooms::resolve_room_host(&state.data_dir, &room_ref) {
            Some(host) => host,
            None => {
                return classify(verr(
                    "work_frontier_claim_room_not_found",
                    format!("room '{room_ref}' does not resolve"),
                ))
            }
        },
    };
    let claim_ref = s(&prior_claim, "work_claim_id", "");
    let effect = match claim_transition_effect(&op, revision, &body) {
        Ok(effect) => effect,
        Err(error) => return classify(error),
    };
    let authorized = match governed::authorize_decision(
        CLAIM_AUTHORITY,
        &body,
        governance,
        &room_ref,
        &required_authority,
        &claim_ref,
        &op,
        revision,
        &effect,
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(challenge) => return challenge,
    };
    let _participant_guard = participation::PARTICIPATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _offer_guard = super::resource_capability_offer_routes::OFFER_MATCH_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _frontier_guard = FRONTIER_CLAIM_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _room_guard = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if op != "release" && op != "complete" && !releases_binding {
        if let Err(error) = resolve_room_open_strict(&state.data_dir, &room_ref) {
            return classify(error);
        }
    } else {
        match rooms::resolve_room_strict(&state.data_dir, &room_ref) {
            Ok(Some(_)) => {}
            Ok(None) => {
                return classify(verr(
                    "work_frontier_claim_room_not_found",
                    format!("room '{room_ref}' does not resolve"),
                ))
            }
            Err(message) => return classify(verr("work_frontier_claim_room_unreadable", message)),
        }
    }
    let current_claim = match load_claim(&state.data_dir, &id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return classify(verr(
                "work_claim_not_found",
                format!("no work claim '{id}'"),
            ))
        }
        Err(message) => return classify(verr("work_frontier_claim_registry_unreadable", message)),
    };
    if let Err(error) = expected_revision(
        &body,
        current_claim
            .get("revision")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    ) {
        return classify(error);
    }
    let frontier_ref = s(&current_claim, "frontier_item_ref", "");
    let mut mutation_refs = vec![claim_ref.as_str()];
    if releases_binding {
        mutation_refs.push(frontier_ref.as_str());
        mutation_refs.push(participant_ref.as_str());
    }
    if let Err(error) = refuse_mutations_if_reserved(
        &state.data_dir,
        &mutation_refs,
        "work_frontier_claim_mutation_in_flight",
        None,
    ) {
        return classify(error);
    }
    if governance == Governance::Participant
        && op != "release"
        && claim_expired_at(&current_claim, authorized.resolved_at_ms)
    {
        return classify(verr(
            "work_claim_expired",
            "claim is past its wallet.network expiry and must be expired by the room host",
        ));
    }
    if op == "expire" && !claim_expired_at(&current_claim, authorized.resolved_at_ms) {
        return classify(verr(
            "work_claim_not_expired",
            "wallet.network committed time has not reached claim expiry",
        ));
    }
    let current_frontier = match load_frontier(&state.data_dir, &frontier_ref) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return classify(verr(
                "work_frontier_not_found",
                format!("no frontier item '{frontier_ref}'"),
            ))
        }
        Err(message) => return classify(verr("work_frontier_claim_registry_unreadable", message)),
    };
    let current_participant = match participant_strict(&state.data_dir, &participant_ref) {
        Ok(record) => record,
        Err(error) => return classify(error),
    };
    if governance == Governance::Participant && s(&current_participant, "status", "") != "active" {
        return classify(verr(
            "work_frontier_claim_participant_not_active",
            "participant became inactive while claim authority resolved",
        ));
    }
    let receipt_tail =
        new_receipt_tail("wcr_", &claim_ref, &op, revision, authorized.resolved_at_ms);
    let receipt_ref = format!("receipt://{receipt_tail}");
    let final_claim = match transition_claim(
        &current_claim,
        &op,
        to_status,
        &receipt_ref,
        authorized.resolved_at_ms,
        &body,
    ) {
        Ok(record) => record,
        Err(error) => return classify(error),
    };
    let (final_frontier, final_participant) = if releases_binding {
        let frontier = match frontier_claim_successor(
            &current_frontier,
            &claim_ref,
            &receipt_ref,
            authorized.resolved_at_ms,
            false,
            op == "complete",
        ) {
            Ok(record) => record,
            Err(error) => return classify(error),
        };
        let wallet_now = match ms_to_rfc3339(authorized.resolved_at_ms) {
            Ok(now) => now,
            Err(error) => return classify(error),
        };
        let participant = match participation::participant_current_claim_successor(
            &current_participant,
            &claim_ref,
            &receipt_ref,
            &wallet_now,
            false,
        ) {
            Ok(record) => record,
            Err(error) => return classify(error),
        };
        (Some(frontier), Some(participant))
    } else {
        (None, None)
    };
    let receipt = match build_receipt(
        &receipt_tail,
        CLAIM_RECEIPT_SCHEMA,
        "WorkClaimLeaseReceipt",
        &claim_ref,
        &op,
        json!({
            "outcome_room_ref": room_ref, "frontier_item_ref": frontier_ref,
            "claimant_ref": participant_ref, "from": s(&current_claim, "status", ""),
            "to": to_status, "revision_before": revision, "revision_after": revision + 1,
            "wallet_time_ms": authorized.resolved_at_ms,
        }),
        vec![
            json!(claim_ref),
            json!(frontier_ref),
            json!(participant_ref),
            json!(room_ref),
        ],
        &final_claim,
        CLAIM_NOTE,
        &authorized,
    ) {
        Ok(receipt) => receipt,
        Err(error) => return classify(error),
    };
    let intent_tail = new_intent_tail(&claim_ref, &op, revision, authorized.resolved_at_ms);
    let intent = seal_intent(
        json!({
            "kind": "claim_transition", "op": op,
            "governance": if governance == Governance::Host { "host" } else { "participant" },
            "room_ref": room_ref, "required_authority_ref": required_authority,
            "subject_ref": claim_ref, "revision_before": revision,
            "receipt_tail": receipt_tail, "receipt": receipt,
            "prior_frontier": final_frontier.as_ref().map(|_| current_frontier.clone()).unwrap_or(Value::Null),
            "final_frontier": final_frontier.clone().unwrap_or(Value::Null),
            "prior_claim": current_claim, "final_claim": final_claim,
            "participant_ref": if final_participant.is_some() { json!(participant_ref) } else { Value::Null },
            "prior_participant": final_participant.as_ref().map(|_| current_participant.clone()).unwrap_or(Value::Null),
            "final_participant": final_participant.clone().unwrap_or(Value::Null),
        }),
        &intent_tail,
    );
    match persist_and_complete_intent_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "work_claim": final_claim,
                "frontier_item": final_frontier,
                "participant_lease": final_participant,
                "work_claim_receipt": receipt,
            })),
        ),
        Err(error) => classify(error),
    }
}

// ================================= READ SURFACES ================================================

fn read_registry_error(message: String) -> (StatusCode, Json<Value>) {
    classify(verr("work_frontier_claim_registry_unreadable", message))
}

fn ensure_read_converged(data_dir: &str) -> Result<(), VErr> {
    let pending = scan_intents(data_dir)
        .map_err(|message| verr("work_frontier_claim_intent_unreadable", message))?;
    if pending.is_empty() {
        Ok(())
    } else {
        Err(verr(
            "work_frontier_claim_pending_convergence",
            format!(
                "{} durable frontier/claim transaction(s) await authenticated convergence",
                pending.len()
            ),
        ))
    }
}

fn replay_contract(intent: &Value) -> Result<(AuthorityContract, Governance), String> {
    let kind = intent
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks kind".to_string())?;
    let contract = if kind.starts_with("frontier_") {
        FRONTIER_AUTHORITY
    } else if kind.starts_with("claim_") {
        CLAIM_AUTHORITY
    } else {
        return Err(format!("unknown intent kind '{kind}'"));
    };
    let governance = match intent.get("governance").and_then(Value::as_str) {
        Some("host") => Governance::Host,
        Some("participant") => Governance::Participant,
        _ => return Err("intent governance is not host or participant".into()),
    };
    match (kind, governance) {
        ("frontier_create" | "frontier_transition", Governance::Host)
        | ("claim_acquire", Governance::Participant)
        | ("claim_transition", _) => Ok((contract, governance)),
        _ => Err("intent kind/governance pair is inconsistent".into()),
    }
}

fn replay_required_authority(
    data_dir: &str,
    intent: &Value,
    governance: Governance,
) -> Result<String, String> {
    let room_ref = intent
        .get("room_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks room_ref".to_string())?;
    let expected = match governance {
        Governance::Host => rooms::resolve_room_host(data_dir, room_ref)
            .ok_or_else(|| format!("room host for '{room_ref}' does not resolve"))?,
        Governance::Participant => {
            let participant_ref = intent
                .get("final_claim")
                .or_else(|| intent.get("prior_claim"))
                .and_then(|claim| claim.get("claimant_ref"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    "participant-governed intent lacks claimant coordinate".to_string()
                })?;
            let participant =
                participation::resolve_participant_lease_strict(data_dir, participant_ref)?
                    .ok_or_else(|| {
                        format!("participant lease '{participant_ref}' does not resolve")
                    })?;
            if s(&participant, "outcome_room_ref", "") != room_ref {
                return Err("participant lease and intent room coordinates differ".into());
            }
            s(&participant, "participant_ref", "")
        }
    };
    if intent.get("required_authority_ref").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err("intent required_authority_ref no longer matches the plane owner seam".into());
    }
    Ok(expected)
}

/// Bounded post-readiness replay. Each intent is structurally reconstructed first, then its exact
/// authority binding coordinates, signed grant, snapshot/hash, and operation scope are re-resolved
/// through the authenticated wallet.network transport. Any refusal leaves the intent byte-exact.
pub(crate) async fn complete_governed_frontier_claim_intents(data_dir: &str, max_intents: usize) {
    if max_intents == 0 {
        return;
    }
    let intents = match scan_intents(data_dir) {
        Ok(intents) => intents,
        Err(message) => {
            eprintln!("frontier/claim governed completer: intent scan failed ({message})");
            return;
        }
    };
    for (tail, intent) in intents.into_iter().take(max_intents) {
        if let Err(message) = validate_sealed_intent(&intent, &tail) {
            eprintln!(
                "frontier/claim governed completer: '{tail}' is invalid ({message}); retained"
            );
            continue;
        }
        let (contract, governance) = match replay_contract(&intent) {
            Ok(value) => value,
            Err(message) => {
                eprintln!("frontier/claim governed completer: '{tail}' contract invalid ({message}); retained");
                continue;
            }
        };
        let required_authority = match replay_required_authority(data_dir, &intent, governance) {
            Ok(authority) => authority,
            Err(message) => {
                eprintln!("frontier/claim governed completer: '{tail}' owner seam refused ({message}); retained");
                continue;
            }
        };
        let room_ref = intent.get("room_ref").and_then(Value::as_str).unwrap_or("");
        let subject_ref = intent
            .get("subject_ref")
            .and_then(Value::as_str)
            .unwrap_or("");
        let op = intent.get("op").and_then(Value::as_str).unwrap_or("");
        let revision = intent
            .get("revision_before")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let receipt = intent.get("receipt").unwrap_or(&Value::Null);
        if let Err(message) = governed::reauthorize_sealed_receipt(
            contract,
            receipt,
            governance,
            room_ref,
            &required_authority,
            subject_ref,
            op,
            revision,
            receipt.get("authorized_effect").unwrap_or(&Value::Null),
        )
        .await
        {
            eprintln!("frontier/claim governed completer: '{tail}' authority refused ({message}); retained");
            continue;
        }

        let _participant_guard = participation::PARTICIPATION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _offer_guard = super::resource_capability_offer_routes::OFFER_MATCH_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _frontier_guard = FRONTIER_CLAIM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _room_guard = rooms::ROOM_MUTATION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err((_, message)) = complete_intent_locked(data_dir, &tail, &intent) {
            eprintln!("frontier/claim governed completer: '{tail}' convergence failed ({message}); retained");
        }
    }
}

/// GET /v1/hypervisor/work-frontier-items[?room=outcome-room://...&status=open]
pub(crate) async fn handle_frontier_list(
    State(state): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = ensure_read_converged(&state.data_dir) {
        return classify(error);
    }
    let records = match scan_records(&state.data_dir, FRONTIER_DIR, canonical_frontier_tail) {
        Ok(records) => records,
        Err(message) => return read_registry_error(message),
    };
    let mut rows: Vec<Value> = records
        .into_iter()
        .map(|(_, record)| record)
        .filter(|record| {
            query
                .get("room")
                .map(|room| s(record, "outcome_room_ref", "") == *room)
                .unwrap_or(true)
                && query
                    .get("status")
                    .map(|status| s(record, "status", "") == *status)
                    .unwrap_or(true)
        })
        .collect();
    rows.sort_by(|left, right| {
        right
            .get("priority")
            .and_then(Value::as_f64)
            .partial_cmp(&left.get("priority").and_then(Value::as_f64))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| s(left, "created_at", "").cmp(&s(right, "created_at", "")))
    });
    rows.truncate(LIST_MAX);
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": FRONTIER_SCHEMA,
            "frontier_items": rows,
            "item_kinds": ITEM_KINDS,
            "statuses": FRONTIER_STATUSES,
            "claimabilities": CLAIMABILITIES,
            "duplication_policies": DUPLICATION_POLICIES,
            "accepted_available": false,
            "accepted_unavailable_code": "work_frontier_acceptance_unavailable",
            "federated_admission_available": false,
            "authority": governed::decision_authority_posture(FRONTIER_AUTHORITY),
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

/// GET /v1/hypervisor/work-frontier-items/:id
pub(crate) async fn handle_frontier_get(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = ensure_read_converged(&state.data_dir) {
        return classify(error);
    }
    match load_frontier(&state.data_dir, &id) {
        Ok(Some(record)) => (StatusCode::OK, Json(json!({ "frontier_item": record }))),
        Ok(None) => classify(verr(
            "work_frontier_not_found",
            format!("no frontier item '{id}'"),
        )),
        Err(message) => read_registry_error(message),
    }
}

/// GET /v1/hypervisor/work-frontier-items/overview
pub(crate) async fn handle_frontier_overview(
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    let pending = match scan_intents(&state.data_dir) {
        Ok(intents) => intents.len(),
        Err(message) => return read_registry_error(message),
    };
    let records = match scan_records(&state.data_dir, FRONTIER_DIR, canonical_frontier_tail) {
        Ok(records) => records,
        Err(message) => return read_registry_error(message),
    };
    let mut counts: HashMap<String, usize> = FRONTIER_STATUSES
        .iter()
        .map(|status| ((*status).to_string(), 0))
        .collect();
    for (_, record) in &records {
        *counts.entry(s(record, "status", "")).or_default() += 1;
    }
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": FRONTIER_SCHEMA,
            "count": records.len(),
            "status_counts": counts,
            "hard_room_frontier_bound": ROOM_FRONTIER_MAX,
            "hard_item_concurrency_bound": ITEM_CONCURRENCY_MAX,
            "pending_convergence_count": pending,
            "coordination_topology": "hosted_admission",
            "federated_admission": "typed_unavailable",
            "acceptance": "typed_unavailable_until_attempt_finding_verifier_admission",
            "authority": governed::decision_authority_posture(FRONTIER_AUTHORITY),
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

/// GET /v1/hypervisor/work-claim-leases[?room=...&participant=...&frontier=...&status=...]
pub(crate) async fn handle_claim_list(
    State(state): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = ensure_read_converged(&state.data_dir) {
        return classify(error);
    }
    let records = match scan_records(&state.data_dir, CLAIM_DIR, canonical_claim_tail) {
        Ok(records) => records,
        Err(message) => return read_registry_error(message),
    };
    let mut rows: Vec<Value> = records
        .into_iter()
        .map(|(_, record)| record)
        .filter(|record| {
            query
                .get("room")
                .map(|value| s(record, "outcome_room_ref", "") == *value)
                .unwrap_or(true)
                && query
                    .get("participant")
                    .map(|value| s(record, "claimant_ref", "") == *value)
                    .unwrap_or(true)
                && query
                    .get("frontier")
                    .map(|value| s(record, "frontier_item_ref", "") == *value)
                    .unwrap_or(true)
                && query
                    .get("status")
                    .map(|value| s(record, "status", "") == *value)
                    .unwrap_or(true)
        })
        .collect();
    rows.sort_by(|left, right| s(right, "created_at", "").cmp(&s(left, "created_at", "")));
    rows.truncate(LIST_MAX);
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": CLAIM_SCHEMA,
            "work_claims": rows,
            "statuses": CLAIM_STATUSES,
            "duplication_policies": CLAIM_DUPLICATION_POLICIES,
            "ttl_seconds": { "minimum": CLAIM_TTL_MIN_SECONDS, "maximum": CLAIM_TTL_MAX_SECONDS },
            "maximum_renewals": CLAIM_RENEWAL_MAX,
            "reassignment_available": false,
            "reassignment_unavailable_code": "work_claim_reassignment_unavailable",
            "authority": governed::decision_authority_posture(CLAIM_AUTHORITY),
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

/// GET /v1/hypervisor/work-claim-leases/:id
pub(crate) async fn handle_claim_get(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = ensure_read_converged(&state.data_dir) {
        return classify(error);
    }
    match load_claim(&state.data_dir, &id) {
        Ok(Some(record)) => (StatusCode::OK, Json(json!({ "work_claim": record }))),
        Ok(None) => classify(verr(
            "work_claim_not_found",
            format!("no work claim '{id}'"),
        )),
        Err(message) => read_registry_error(message),
    }
}

/// GET /v1/hypervisor/work-claim-leases/overview
pub(crate) async fn handle_claim_overview(
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    let pending = match scan_intents(&state.data_dir) {
        Ok(intents) => intents.len(),
        Err(message) => return read_registry_error(message),
    };
    let records = match scan_records(&state.data_dir, CLAIM_DIR, canonical_claim_tail) {
        Ok(records) => records,
        Err(message) => return read_registry_error(message),
    };
    let mut counts: HashMap<String, usize> = CLAIM_STATUSES
        .iter()
        .map(|status| ((*status).to_string(), 0))
        .collect();
    for (_, record) in &records {
        *counts.entry(s(record, "status", "")).or_default() += 1;
    }
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": CLAIM_SCHEMA,
            "count": records.len(),
            "live_count": records.iter().filter(|(_, record)| live_claim_status(&s(record, "status", ""))).count(),
            "status_counts": counts,
            "pending_convergence_count": pending,
            "lease_clock": "wallet.network PrincipalAuthorityResolutionReceipt.resolved_at_ms",
            "local_system_time_is_authoritative": false,
            "authority": governed::decision_authority_posture(CLAIM_AUTHORITY),
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

#[cfg(test)]
mod frontier_claim_tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let directory =
            std::env::temp_dir().join(format!("ioi-frontier-claim-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn authorized(ms: u64, contract: AuthorityContract, effect: Value) -> AuthorizedDecision {
        let effect_hash = governed::decision_effect_hash(contract, &effect);
        AuthorizedDecision {
            evidence: governed::DecisionEvidence {
                acting_authority_id: json!("wallet://authority_test"),
                grant_ref: "wallet.network://grant/approval/test".into(),
                policy_hash: format!("sha256:{}", "11".repeat(32)),
                request_hash: format!("sha256:{}", "22".repeat(32)),
                effect_hash,
                authorized_effect: effect,
                wallet_approval_grant: json!({ "signed": "test" }),
                authority_binding: json!({
                    "principal_ref": "domain://host",
                    "required_scope": "work_frontier.create",
                    "coordinates": { "binding_version": 1 },
                }),
            },
            resolved_at_ms: ms,
        }
    }

    fn frontier_body(room: &str) -> Value {
        json!({
            "outcome_room_ref": room,
            "item_kind": "task",
            "objective": "Reproduce the bounded claim invariant.",
            "dependency_refs": [],
            "related_attempt_and_finding_refs": [],
            "required_capability_refs": ["capability://rust-review"],
            "required_context_resource_authority_and_evidence_refs": ["scope:repo.read"],
            "expected_value": 1,
            "uncertainty": 0.25,
            "priority": 10,
            "duplication_policy": "exclusive",
            "claimability": "open",
            "max_concurrency": 1,
            "expires_at": null,
            "stop_condition_ref": "policy://done",
            "coordination_topology": "hosted_admission",
        })
    }

    fn participant(room: &str, claim: Value) -> Value {
        json!({
            "schema_version": "ioi.hypervisor.room-participant-lease.v1",
            "participant_lease_id": format!("participant-lease://rpl_{}", "ab".repeat(32)),
            "outcome_room_ref": room,
            "participant_ref": "worker://claimant",
            "status": "active",
            "revision": 1,
            "current_claim_ref": claim,
            "admission_and_replay_refs": [],
            "status_history": [],
            "exit_and_claim_release_refs": [],
            "updated_at": "2026-01-01T00:00:00Z",
        })
    }

    fn sealed_frontier_create(room: &str, ms: u64) -> (String, Value, Value) {
        let declaration = validate_frontier_create(&frontier_body(room)).unwrap();
        let frontier_tail = deterministic_tail("wfi_", &declaration);
        let frontier_ref = format!("frontier://{frontier_tail}");
        let auth = authorized(
            ms,
            FRONTIER_AUTHORITY,
            frontier_create_effect(&declaration, 1),
        );
        let receipt_tail = format!("wfr_{}", "cd".repeat(32));
        let receipt_ref = format!("receipt://{receipt_tail}");
        let final_frontier = seal_frontier(&declaration, &frontier_tail, &receipt_ref, ms).unwrap();
        let receipt = build_receipt(
            &receipt_tail,
            FRONTIER_RECEIPT_SCHEMA,
            "WorkFrontierMutationReceipt",
            &frontier_ref,
            "create",
            json!({ "outcome_room_ref": room, "item_kind": "task", "status": "open" }),
            vec![json!(frontier_ref), json!(room)],
            &final_frontier,
            FRONTIER_NOTE,
            &auth,
        )
        .unwrap();
        let intent_tail = format!("wci_{}", "ef".repeat(32));
        let intent = seal_intent(
            json!({
                "kind": "frontier_create", "op": "create", "governance": "host",
                "room_ref": room, "required_authority_ref": "domain://host",
                "subject_ref": frontier_ref, "revision_before": 1,
                "receipt_tail": receipt_tail, "receipt": receipt,
                "prior_frontier": null, "final_frontier": final_frontier,
                "prior_claim": null, "final_claim": null,
                "participant_ref": null, "prior_participant": null, "final_participant": null,
            }),
            &intent_tail,
        );
        (intent_tail, intent, declaration)
    }

    #[test]
    fn declarations_are_bounded_hosted_and_secret_free() {
        let room = "outcome-room://or_ab";
        let declaration = validate_frontier_create(&frontier_body(room)).unwrap();
        assert_eq!(
            declaration["required_context_resource_authority_and_evidence_refs"],
            json!(["scope:repo.read"])
        );

        let mut secret = frontier_body(room);
        secret["required_capability_refs"] = json!([{ "nested_api_token": "plaintext" }]);
        assert_eq!(
            validate_frontier_create(&secret).unwrap_err().0,
            "work_frontier_claim_plaintext_secret_rejected"
        );

        let mut federated = frontier_body(room);
        federated["coordination_topology"] = json!("federated_admission");
        assert_eq!(
            validate_frontier_create(&federated).unwrap_err().0,
            "work_frontier_claim_federated_unavailable"
        );

        let mut owned = frontier_body(room);
        owned["status"] = json!("claimed");
        assert!(validate_frontier_create(&owned).is_err());

        let mut oversized = frontier_body(room);
        oversized["dependency_refs"] = Value::Array(
            (0..=LIST_MAX)
                .map(|index| json!(format!("attempt://{index}")))
                .collect(),
        );
        assert_eq!(
            validate_frontier_create(&oversized).unwrap_err().0,
            "work_frontier_claim_field_too_long"
        );
    }

    #[test]
    fn frontier_create_intent_reconstructs_and_coupled_tamper_refuses() {
        let (tail, intent, _) = sealed_frontier_create("outcome-room://or_ab", 1_800_000_000_000);
        validate_sealed_intent(&intent, &tail).unwrap();
        assert_eq!(
            intent["touched_refs"],
            json!([
                intent["subject_ref"].as_str().unwrap(),
                "outcome-room://or_ab",
            ])
        );
        let directory = temp_dir("room-reservation");
        let data_dir = directory.to_str().unwrap();
        persist_record(data_dir, INTENT_DIR, &tail, &intent).unwrap();
        assert_eq!(
            refuse_external_mutation_if_reserved(
                data_dir,
                "outcome-room://or_ab",
                "outcome_room_mutation_in_flight",
            )
            .unwrap_err()
            .0,
            "outcome_room_mutation_in_flight"
        );
        refuse_external_mutation_if_reserved_except(
            data_dir,
            "outcome-room://or_ab",
            "outcome_room_mutation_in_flight",
            &tail,
        )
        .unwrap();
        std::fs::remove_dir_all(directory).unwrap();

        let mut tampered = intent.clone();
        tampered["final_frontier"]["objective"] = json!("scope escalated after sealing");
        tampered["intent_hash"] = json!(record_output_hash(
            &without_field(&tampered, "intent_hash"),
            &[]
        ));
        assert!(validate_sealed_intent(&tampered, &tail).is_err());

        let mut footprint_tampered = intent;
        footprint_tampered["touched_refs"] = json!(["outcome-room://or_ab"]);
        footprint_tampered["intent_hash"] = json!(record_output_hash(
            &without_field(&footprint_tampered, "intent_hash"),
            &[]
        ));
        assert!(validate_sealed_intent(&footprint_tampered, &tail).is_err());
    }

    #[test]
    fn graph_cycle_and_unresolved_dependencies_refuse() {
        let room = "outcome-room://or_ab";
        let (_, _, mut candidate) = sealed_frontier_create(room, 1_800_000_000_000);
        let candidate_ref = format!("frontier://wfi_{}", "01".repeat(32));
        let prior_ref = format!("frontier://wfi_{}", "02".repeat(32));
        candidate["dependency_refs"] = json!([prior_ref]);
        let prior = json!({
            "frontier_item_id": prior_ref,
            "outcome_room_ref": room,
            "dependency_refs": [candidate_ref],
            "status": "open",
        });
        assert!(dependency_cycle(
            &[("wfi_prior".into(), prior)],
            &candidate,
            &candidate_ref
        ));
        assert_eq!(
            dependencies_ready(&[], &candidate).unwrap_err().0,
            "work_frontier_claim_dependencies_unresolved"
        );
    }

    #[test]
    fn claim_clock_concurrency_and_completion_are_canonical() {
        let room = "outcome-room://or_ab";
        let ms = 1_800_000_000_000;
        let declaration = validate_frontier_create(&frontier_body(room)).unwrap();
        let frontier_tail = deterministic_tail("wfi_", &declaration);
        let frontier_ref = format!("frontier://{frontier_tail}");
        let frontier = seal_frontier(
            &declaration,
            &frontier_tail,
            &format!("receipt://wfr_{}", "01".repeat(32)),
            ms,
        )
        .unwrap();
        let participant = participant(room, Value::Null);
        let claim_body = json!({
            "outcome_room_ref": room,
            "frontier_item_ref": frontier_ref,
            "claimant_ref": participant["participant_lease_id"],
            "bounded_scope_ref": "task://bounded",
            "context_lease_refs": ["context_lease://ctx"],
            "authority_resource_compute_data_budget_and_tool_lease_refs": ["tool-lease://tool"],
            "duplicate_work_policy": "exclusive",
            "heartbeat_ref": null,
            "ttl_seconds": 60,
            "coordination_topology": "hosted_admission",
        });
        let claim_declaration = validate_claim_acquire(&claim_body).unwrap();
        assert!(compatible_duplication(&frontier, &claim_declaration));
        let claim_tail = deterministic_tail(
            "wcl_",
            &json!({
                "declaration": claim_declaration,
                "frontier_revision": frontier["revision"],
                "participant_revision": participant["revision"],
            }),
        );
        let claim_ref = format!("work-claim://{claim_tail}");
        let receipt_ref = format!("receipt://wcr_{}", "03".repeat(32));
        let claim = seal_claim(&claim_declaration, &claim_tail, &receipt_ref, ms).unwrap();
        assert_eq!(claim["issued_at_ms"], json!(ms));
        assert_eq!(claim["expires_at_ms"], json!(ms + 60_000));
        assert!(!claim_expired_at(&claim, ms + 59_999));
        assert!(claim_expired_at(&claim, ms + 60_000));
        let claimed =
            frontier_claim_successor(&frontier, &claim_ref, &receipt_ref, ms, true, false).unwrap();
        let stamped = participation::participant_current_claim_successor(
            &participant,
            &claim_ref,
            &receipt_ref,
            &ms_to_rfc3339(ms).unwrap(),
            true,
        )
        .unwrap();
        let receipt_tail = receipt_ref.strip_prefix("receipt://").unwrap();
        let claim_receipt = build_receipt(
            receipt_tail,
            CLAIM_RECEIPT_SCHEMA,
            "WorkClaimLeaseReceipt",
            &claim_ref,
            "acquire",
            json!({
                "outcome_room_ref": room,
                "frontier_item_ref": frontier_ref,
                "claimant_ref": participant["participant_lease_id"],
                "issued_at_ms": ms,
                "expires_at_ms": claim["expires_at_ms"],
                "revision_after": 1,
            }),
            vec![
                json!(claim_ref),
                json!(frontier_ref),
                participant["participant_lease_id"].clone(),
                json!(room),
            ],
            &claim,
            CLAIM_NOTE,
            &authorized(
                ms,
                CLAIM_AUTHORITY,
                claim_acquire_effect(
                    &claim_declaration,
                    participant["revision"].as_u64().unwrap(),
                ),
            ),
        )
        .unwrap();
        let intent_tail = format!("wci_{}", "04".repeat(32));
        let acquire_intent = seal_intent(
            json!({
                "kind": "claim_acquire", "op": "acquire", "governance": "participant",
                "room_ref": room, "required_authority_ref": "worker://claimant",
                "subject_ref": claim_ref, "revision_before": participant["revision"],
                "frontier_revision_at_authorization": frontier["revision"],
                "frontier_control_hash_at_authorization": frontier_claim_control_hash(&frontier),
                "receipt_tail": receipt_tail, "receipt": claim_receipt,
                "prior_frontier": frontier.clone(), "final_frontier": claimed.clone(),
                "prior_claim": null, "final_claim": claim.clone(),
                "participant_ref": participant["participant_lease_id"],
                "prior_participant": participant.clone(), "final_participant": stamped,
            }),
            &intent_tail,
        );
        validate_sealed_intent(&acquire_intent, &intent_tail).unwrap();
        assert_eq!(
            acquire_intent["touched_refs"],
            json!([
                frontier_ref,
                participant["participant_lease_id"].as_str().unwrap(),
                claim_ref,
            ])
        );
        let directory = temp_dir("aggregate-reservations");
        let data_dir = directory.to_str().unwrap();
        persist_record(data_dir, INTENT_DIR, &intent_tail, &acquire_intent).unwrap();
        for reserved_ref in acquire_intent["touched_refs"].as_array().unwrap() {
            assert!(
                pending_intent_overlap(data_dir, &[reserved_ref.as_str().unwrap()], None)
                    .unwrap()
                    .is_some()
            );
        }
        assert!(pending_intent_overlap(data_dir, &[room], None)
            .unwrap()
            .is_none());
        assert!(
            pending_intent_overlap(data_dir, &[&claim_ref], Some(&intent_tail))
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir_all(directory).unwrap();
        assert_eq!(claimed["status"], json!("claimed"));
        assert_eq!(claimed["active_claim_refs"].as_array().unwrap().len(), 1);
        let completed =
            frontier_claim_successor(&claimed, &claim_ref, &receipt_ref, ms + 1, false, true)
                .unwrap();
        assert_eq!(completed["status"], json!("verifying"));
        assert!(completed["active_claim_refs"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(completed["claim_refs"], json!([claim_ref]));
    }

    #[test]
    fn room_close_interlock_tracks_unresolved_and_live_lineage() {
        let directory = temp_dir("close");
        let data_dir = directory.to_str().unwrap();
        let room = "outcome-room://or_ab";
        let declaration = validate_frontier_create(&frontier_body(room)).unwrap();
        let tail = deterministic_tail("wfi_", &declaration);
        let mut frontier = seal_frontier(
            &declaration,
            &tail,
            &format!("receipt://wfr_{}", "01".repeat(32)),
            1_800_000_000_000,
        )
        .unwrap();
        persist_record(data_dir, FRONTIER_DIR, &tail, &frontier).unwrap();
        assert_eq!(
            refuse_room_close_if_blocked_locked(data_dir, room)
                .unwrap_err()
                .0,
            "outcome_room_close_blocked_frontier_claims"
        );
        frontier["status"] = json!("closed");
        persist_record(data_dir, FRONTIER_DIR, &tail, &frontier).unwrap();
        refuse_room_close_if_blocked_locked(data_dir, room).unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn every_mutation_requires_exact_revision() {
        assert_eq!(
            expected_revision(&json!({}), 7).unwrap_err().0,
            "work_frontier_claim_expected_revision_required"
        );
        assert_eq!(
            expected_revision(&json!({ "expected_revision": 6 }), 7)
                .unwrap_err()
                .0,
            "work_frontier_claim_stale_revision"
        );
        expected_revision(&json!({ "expected_revision": 7 }), 7).unwrap();
    }

    #[test]
    fn governed_effects_refuse_body_swaps_at_the_same_revision() {
        for (op, requested_body, swapped_body) in [
            (
                "renew",
                json!({ "transition": "renew", "ttl_seconds": 30, "expected_revision": 7 }),
                json!({ "transition": "renew", "ttl_seconds": 86_400, "expected_revision": 7 }),
            ),
            (
                "heartbeat",
                json!({ "transition": "heartbeat", "heartbeat_ref": "heartbeat://requested", "expected_revision": 7 }),
                json!({ "transition": "heartbeat", "heartbeat_ref": "heartbeat://swapped", "expected_revision": 7 }),
            ),
            (
                "release",
                json!({ "transition": "release", "reason": "requested reason", "expected_revision": 7 }),
                json!({ "transition": "release", "reason": "swapped reason", "expected_revision": 7 }),
            ),
        ] {
            let requested = claim_transition_effect(op, 7, &requested_body).unwrap();
            let swapped = claim_transition_effect(op, 7, &swapped_body).unwrap();
            let sealed = json!({
                "effect_hash": governed::decision_effect_hash(CLAIM_AUTHORITY, &requested),
                "authorized_effect": requested,
                "wallet_approval_grant": { "signed": true },
                "principal_authority_binding": { "binding_version": 1 },
            });
            governed::validate_sealed_effect(
                CLAIM_AUTHORITY,
                &sealed,
                sealed.get("authorized_effect").unwrap(),
            )
            .unwrap();
            assert!(governed::validate_sealed_effect(CLAIM_AUTHORITY, &sealed, &swapped).is_err());
        }
    }

    #[test]
    fn claim_declaration_pins_the_eligibility_match_receipt() {
        let body = json!({
            "outcome_room_ref": "outcome-room://or_ab",
            "frontier_item_ref": format!("frontier://wfi_{}", "ab".repeat(32)),
            "claimant_ref": "participant-lease://rpl_ab",
            "eligibility_match_receipt_ref": format!("receipt://wem_{}", "cd".repeat(32)),
            "bounded_scope_ref": "task://bounded",
            "context_lease_refs": [],
            "authority_resource_compute_data_budget_and_tool_lease_refs": [],
            "duplicate_work_policy": "exclusive",
            "heartbeat_ref": null,
            "ttl_seconds": 60,
            "coordination_topology": "hosted_admission"
        });
        let declaration = validate_claim_acquire(&body).unwrap();
        assert_eq!(declaration["eligibility_match_receipt_ref"], body["eligibility_match_receipt_ref"]);
        let record = seal_claim(&declaration, &format!("wcl_{}", "ef".repeat(32)), &format!("receipt://wcr_{}", "01".repeat(32)), 1_800_000_000_000).unwrap();
        assert_eq!(claim_declaration_from_record(&record)["eligibility_match_receipt_ref"], body["eligibility_match_receipt_ref"]);
    }

    #[test]
    fn occupied_unreadable_and_malformed_slots_are_never_absent() {
        let directory = temp_dir("strict-slots");
        let data_dir = directory.to_str().unwrap();
        let frontier_tail = format!("wfi_{}", "31".repeat(32));
        let frontier_slot = directory
            .join(FRONTIER_DIR)
            .join(format!("{frontier_tail}.json"));
        std::fs::create_dir_all(&frontier_slot).unwrap();
        assert!(load_frontier(data_dir, &frontier_tail).is_err());

        let claim_tail = format!("wcl_{}", "32".repeat(32));
        let claim_family = directory.join(CLAIM_DIR);
        std::fs::create_dir_all(&claim_family).unwrap();
        std::fs::write(
            claim_family.join(format!("{claim_tail}.json")),
            b"{not-json",
        )
        .unwrap();
        assert!(load_claim(data_dir, &claim_tail).is_err());
        assert!(names_for_test(data_dir, INTENT_DIR).is_empty());
        assert!(names_for_test(data_dir, RECEIPT_DIR).is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn names_for_test(data_dir: &str, family: &str) -> Vec<String> {
        std::fs::read_dir(std::path::Path::new(data_dir).join(family))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn persistence_failures_are_server_uncertainty() {
        let (status, Json(body)) = classify(verr(
            "work_frontier_claim_persist_failed",
            "initial intent write did not become durable",
        ));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body.pointer("/error/code").and_then(Value::as_str),
            Some("work_frontier_claim_persist_failed")
        );
    }
}
