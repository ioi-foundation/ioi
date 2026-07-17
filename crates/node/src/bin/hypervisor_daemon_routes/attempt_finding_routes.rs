//! Hosted-room Attempt + Finding admission.
//!
//! Attempts freeze the exact room, frontier, live claim, participant lease, and GoalRun
//! coordinates under which work was declared. Findings freeze an admitted Attempt, its bound
//! WorkResult/evidence, uncertainty, and proof refs. This plane admits provenance and shared
//! declarations only: it grants no execution authority and provides no acceptance, verdict,
//! settlement, or verifier authority.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Map, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[cfg(test)]
use super::governed_authority::DecisionEvidence;
use super::governed_authority::{
    self as governed, AuthorityContract, AuthorizedDecision, Governance,
};
use super::outcome_room_routes::{
    self as rooms, build_room_receipt_at, record_output_hash, s, VErr,
};
use super::room_participation_routes as participation;
use super::work_frontier_claim_routes as work;
use super::DaemonState;

const ATTEMPT_SCHEMA: &str = "ioi.hypervisor.attempt-envelope.v1";
const FINDING_SCHEMA: &str = "ioi.hypervisor.finding-envelope.v1";
const ATTEMPT_RECEIPT_SCHEMA: &str = "ioi.hypervisor.attempt-mutation-receipt.v1";
const FINDING_RECEIPT_SCHEMA: &str = "ioi.hypervisor.finding-mutation-receipt.v1";
const INTENT_SCHEMA: &str = "ioi.hypervisor.attempt-finding-intent.v1";

pub(crate) const ATTEMPT_DIR: &str = "attempts";
pub(crate) const FINDING_DIR: &str = "findings";
const RECEIPT_DIR: &str = "attempt-finding-receipts";
const INTENT_DIR: &str = "attempt-finding-intents";

const LIST_MAX: usize = 128;
const REF_LIST_MAX: usize = 64;
const REF_MAX: usize = 300;
const TEXT_MAX: usize = 4_000;
const HISTORY_MAX: usize = 128;

const ATTEMPT_OUTCOMES: &[&str] = &[
    "positive",
    "negative",
    "inconclusive",
    "invalid",
    "exploit_found",
    "superseded",
];
const ATTEMPT_STATUSES: &[&str] = &["draft", "running", "submitted", "admitted", "superseded"];
const FINDING_KINDS: &[&str] = &[
    "hypothesis",
    "observation",
    "claim",
    "negative_result",
    "integrity_incident",
    "mapping_claim",
    "causal_claim",
    "counterexample",
    "synthesis",
];
const FINDING_STATUSES: &[&str] = &["proposed", "admitted", "superseded", "archived"];

const ATTEMPT_AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "attempt",
    policy_domain: "hypervisor.attempt.decision.policy.v1",
    request_domain: "hypervisor.attempt.decision.request.v1",
    resolution_domain: "hypervisor.attempt.authority-resolution.v1",
    code_prefix: "attempt",
    host_label: "room_host",
    participant_label: "participant_claimant",
};
const FINDING_AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "finding",
    policy_domain: "hypervisor.finding.decision.policy.v1",
    request_domain: "hypervisor.finding.decision.request.v1",
    resolution_domain: "hypervisor.finding.authority-resolution.v1",
    code_prefix: "finding",
    host_label: "room_host",
    participant_label: "participant_claimant",
};

/// Lock order for this plane is participation -> frontier/claim -> room -> GoalRun ->
/// WorkResult -> Attempt/Finding. Authority resolution always finishes before these locks.
pub(crate) static ATTEMPT_FINDING_LOCK: Mutex<()> = Mutex::new(());

fn verr(code: &str, message: impl Into<String>) -> VErr {
    (code.to_string(), message.into())
}

fn classify(error: VErr) -> (StatusCode, Json<Value>) {
    let (code, message) = error;
    let status = if code.ends_with("_not_found") {
        StatusCode::NOT_FOUND
    } else if code.contains("stale_revision")
        || code.contains("conflict")
        || code.contains("in_flight")
        || code.contains("not_active")
        || code.contains("not_open")
        || code.contains("unresolved")
        || code.contains("coordinate_changed")
    {
        StatusCode::CONFLICT
    } else if code.contains("unavailable") {
        StatusCode::NOT_IMPLEMENTED
    } else if code.contains("unreadable")
        || code.contains("persist_failed")
        || code.contains("pending_convergence")
        || code.contains("durability")
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (
        status,
        Json(json!({
            "error": {"code": code, "message": message, "runtimeTruthSource": "daemon-runtime"}
        })),
    )
}

fn canonical_tail(tail: &str, prefix: &str) -> bool {
    tail.strip_prefix(prefix).is_some_and(|hex| {
        hex.len() == 64
            && hex
                .chars()
                .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
    })
}
fn canonical_attempt_tail(tail: &str) -> bool {
    canonical_tail(tail, "att_")
}
fn canonical_finding_tail(tail: &str) -> bool {
    canonical_tail(tail, "fnd_")
}
fn canonical_intent_tail(tail: &str) -> bool {
    canonical_tail(tail, "afi_")
}
fn canonical_receipt_tail(tail: &str) -> bool {
    canonical_tail(tail, "amr_") || canonical_tail(tail, "fmr_")
}

fn ref_ok(value: &str, schemes: &[&str]) -> bool {
    value.len() <= REF_MAX
        && !value.chars().any(char::is_whitespace)
        && schemes.iter().any(|scheme| {
            value
                .strip_prefix(&format!("{scheme}://"))
                .is_some_and(|tail| {
                    !tail.is_empty() && !tail.starts_with('/') && !tail.contains("..")
                })
        })
}

fn prefixed_ref_ok(value: &str, prefixes: &[&str]) -> bool {
    value.len() <= REF_MAX
        && !value.chars().any(char::is_whitespace)
        && prefixes.iter().any(|prefix| {
            value.strip_prefix(prefix).is_some_and(|tail| {
                !tail.is_empty() && !tail.starts_with('/') && !tail.contains("..")
            })
        })
}

const SENSITIVE: &[&str] = &[
    "password",
    "secret",
    "credential",
    "authorization",
    "privatekey",
    "apikey",
    "token",
];

fn reject_sensitive(value: &Value, path: &str) -> Result<(), VErr> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized: String = key
                    .to_lowercase()
                    .chars()
                    .filter(|character| !matches!(character, '_' | '-' | ' ' | '.'))
                    .collect();
                if SENSITIVE
                    .iter()
                    .any(|fragment| normalized.contains(fragment))
                    && key != "wallet_approval_grant"
                    && !child.is_null()
                {
                    return Err(verr(
                        "attempt_finding_plaintext_secret_rejected",
                        format!("sensitive key '{path}{key}' is never admitted"),
                    ));
                }
                reject_sensitive(child, &format!("{path}{key}."))?;
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                reject_sensitive(child, &format!("{path}{index}."))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_unknown(body: &Value, allowed: &[&str]) -> Result<(), VErr> {
    let object = body.as_object().ok_or_else(|| {
        verr(
            "attempt_finding_body_invalid",
            "request body must be an object",
        )
    })?;
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(verr(
                "attempt_finding_field_unknown",
                format!("unknown or plane-owned field '{key}'"),
            ));
        }
    }
    Ok(())
}

fn required_ref(body: &Value, field: &str, schemes: &[&str]) -> Result<String, VErr> {
    let value = body.get(field).and_then(Value::as_str).ok_or_else(|| {
        verr(
            "attempt_finding_ref_required",
            format!("'{field}' is required"),
        )
    })?;
    if !ref_ok(value, schemes) {
        return Err(verr(
            "attempt_finding_ref_invalid",
            format!("'{field}' must use one of [{}]", schemes.join(", ")),
        ));
    }
    Ok(value.to_string())
}

fn optional_ref(body: &Value, field: &str, schemes: &[&str]) -> Result<Value, VErr> {
    match body.get(field) {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(value)) if ref_ok(value, schemes) => Ok(json!(value)),
        _ => Err(verr(
            "attempt_finding_ref_invalid",
            format!(
                "'{field}' must be null or use one of [{}]",
                schemes.join(", ")
            ),
        )),
    }
}

fn ref_list(body: &Value, field: &str, schemes: &[&str]) -> Result<Vec<String>, VErr> {
    ref_list_with_prefixes(body, field, schemes, &[])
}

fn ref_list_with_prefixes(
    body: &Value,
    field: &str,
    schemes: &[&str],
    prefixes: &[&str],
) -> Result<Vec<String>, VErr> {
    let items = body.get(field).and_then(Value::as_array).ok_or_else(|| {
        verr(
            "attempt_finding_list_invalid",
            format!("'{field}' must be a list"),
        )
    })?;
    if items.len() > REF_LIST_MAX {
        return Err(verr(
            "attempt_finding_list_invalid",
            format!("'{field}' exceeds {REF_LIST_MAX} entries"),
        ));
    }
    let mut out = Vec::new();
    for item in items {
        let reference = item.as_str().ok_or_else(|| {
            verr(
                "attempt_finding_list_invalid",
                format!("'{field}' entries must be refs"),
            )
        })?;
        if !ref_ok(reference, schemes) && !prefixed_ref_ok(reference, prefixes) {
            return Err(verr(
                "attempt_finding_ref_invalid",
                format!("'{field}' contains invalid ref '{reference}'"),
            ));
        }
        if out.iter().any(|existing| existing == reference) {
            return Err(verr(
                "attempt_finding_list_invalid",
                format!("'{field}' contains duplicate ref '{reference}'"),
            ));
        }
        out.push(reference.to_string());
    }
    Ok(out)
}

fn bounded_text(body: &Value, field: &str, required: bool) -> Result<Value, VErr> {
    match body.get(field) {
        None | Some(Value::Null) if !required => Ok(Value::Null),
        Some(Value::String(value))
            if !value.trim().is_empty() && value.chars().count() <= TEXT_MAX =>
        {
            Ok(json!(value))
        }
        _ => Err(verr(
            "attempt_finding_text_invalid",
            format!("'{field}' must be a nonempty string of at most {TEXT_MAX} characters"),
        )),
    }
}

fn expected_revision(body: &Value, current: u64) -> Result<(), VErr> {
    match body.get("expected_revision").and_then(Value::as_u64) {
        Some(expected) if expected == current => Ok(()),
        Some(expected) => Err(verr(
            "attempt_finding_stale_revision",
            format!("expected revision {expected}, current revision is {current}"),
        )),
        None => Err(verr(
            "attempt_finding_expected_revision_required",
            "every mutation requires unsigned expected_revision",
        )),
    }
}

fn ms_to_rfc3339(ms: u64) -> Result<String, VErr> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms).saturating_mul(1_000_000))
        .map_err(|_| {
            verr(
                "attempt_finding_wallet_time_invalid",
                "wallet time is not representable",
            )
        })?
        .format(&Rfc3339)
        .map_err(|error| verr("attempt_finding_wallet_time_invalid", error.to_string()))
}

fn without_field(value: &Value, field: &str) -> Value {
    let mut out = value.clone();
    if let Some(object) = out.as_object_mut() {
        object.remove(field);
    }
    out
}

fn deterministic_tail(prefix: &str, value: &Value) -> String {
    let hash = record_output_hash(value, &[]);
    format!("{prefix}{}", hash.strip_prefix("sha256:").unwrap_or(&hash))
}

fn fresh_tail(prefix: &str, subject_ref: &str, op: &str, revision: u64, at_ms: u64) -> String {
    deterministic_tail(
        prefix,
        &json!({
            "domain": "hypervisor.attempt-finding.nonce.v1",
            "subject_ref": subject_ref,
            "op": op,
            "revision": revision,
            "resolved_at_ms": at_ms,
            "nonce": uuid::Uuid::new_v4().to_string(),
        }),
    )
}

fn identity_field(family: &str) -> &'static str {
    if family == ATTEMPT_DIR {
        "attempt_id"
    } else {
        "finding_id"
    }
}

fn validate_record_identity(family: &str, tail: &str, record: &Value) -> Result<(), String> {
    let (schema, scheme) = if family == ATTEMPT_DIR {
        (ATTEMPT_SCHEMA, "attempt")
    } else {
        (FINDING_SCHEMA, "finding")
    };
    if record.get("schema_version").and_then(Value::as_str) != Some(schema)
        || record.get(identity_field(family)).and_then(Value::as_str)
            != Some(format!("{scheme}://{tail}").as_str())
        || record.get("revision").and_then(Value::as_u64).is_none()
    {
        return Err(format!(
            "canonical slot '{family}/{tail}.json' fails schema/identity/revision binding"
        ));
    }
    Ok(())
}

fn load_record(
    data_dir: &str,
    family: &str,
    id_or_tail: &str,
    scheme: &str,
    canonical: fn(&str) -> bool,
) -> Result<Option<Value>, String> {
    let tail = id_or_tail
        .strip_prefix(&format!("{scheme}://"))
        .unwrap_or(id_or_tail);
    if !canonical(tail) {
        return Err(format!("noncanonical {scheme} storage key '{tail}'"));
    }
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("family '{family}' cannot be pinned ({error})")),
    };
    let name = format!("{tail}.json");
    let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
        Ok(None) => return Ok(None),
        Ok(Some((_file, bytes))) => bytes,
        Err(error) => return Err(format!("slot '{family}/{name}' is unreadable ({error})")),
    };
    let record: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("slot '{family}/{name}' is malformed JSON ({error})"))?;
    validate_record_identity(family, tail, &record)?;
    Ok(Some(record))
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
            Ok(None) => return Err(format!("canonical slot '{family}/{name}' vanished")),
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

pub(crate) fn load_attempt_strict(
    data_dir: &str,
    id_or_tail: &str,
) -> Result<Option<Value>, String> {
    load_record(
        data_dir,
        ATTEMPT_DIR,
        id_or_tail,
        "attempt",
        canonical_attempt_tail,
    )
}

pub(crate) fn load_finding_strict(
    data_dir: &str,
    id_or_tail: &str,
) -> Result<Option<Value>, String> {
    load_record(
        data_dir,
        FINDING_DIR,
        id_or_tail,
        "finding",
        canonical_finding_tail,
    )
}

fn persist_record(data_dir: &str, family: &str, tail: &str, record: &Value) -> Result<(), VErr> {
    super::durable_fs::persist_record_durable(data_dir, family, tail, record).map_err(|failure| {
        if failure.visible() {
            verr(
                "attempt_finding_pending_convergence",
                format!("{family}/{tail} is {}", failure.detail()),
            )
        } else {
            verr(
                "attempt_finding_persist_failed",
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
                verr("attempt_finding_receipt_key_invalid", message)
            }
            CommitFailure::NotCommitted(message) => verr("attempt_finding_persist_failed", message),
            CommitFailure::SlotUnreadable(message) => {
                verr("attempt_finding_receipt_unreadable", message)
            }
            CommitFailure::Conflict(message) => verr("attempt_finding_receipt_conflict", message),
            CommitFailure::DurabilityUnconfirmed(message) => {
                verr("attempt_finding_pending_convergence", message)
            }
            CommitFailure::Swapped(message) => verr("attempt_finding_receipt_swapped", message),
        },
    )
}

fn consume_intent(data_dir: &str, tail: &str) -> Result<(), VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, INTENT_DIR) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(verr("attempt_finding_intent_unreadable", error.to_string())),
    };
    match super::durable_fs::unlink_at(&directory, &format!("{tail}.json")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(verr(
                "attempt_finding_pending_convergence",
                format!("intent unlink failed ({error})"),
            ))
        }
    }
    directory.sync_all().map_err(|error| {
        verr(
            "attempt_finding_pending_convergence",
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
            Ok(None) => return Err(format!("canonical intent '{name}' vanished")),
            Err(error) => return Err(format!("canonical intent '{name}' is unreadable ({error})")),
        };
        let intent: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("canonical intent '{name}' is malformed ({error})"))?;
        validate_intent_seal(&intent, tail)?;
        intents.push((tail.to_string(), intent));
    }
    Ok(intents)
}

fn validate_touched(intent: &Value) -> Result<Vec<String>, String> {
    let touched = intent
        .get("touched_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| "intent lacks touched_refs".to_string())?;
    let mut values = Vec::new();
    for item in touched {
        let reference = item
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= REF_MAX)
            .ok_or_else(|| "intent touched_refs contains invalid ref".to_string())?;
        values.push(reference.to_string());
    }
    let mut sorted = values.clone();
    sorted.sort();
    sorted.dedup();
    if values != sorted {
        return Err("intent touched_refs is not exact sorted unique data".into());
    }
    let mut reconstructed: BTreeSet<String> = [
        "subject_ref",
        "room_ref",
        "frontier_ref",
        "claim_ref",
        "participant_ref",
        "goal_run_ref",
        "attempt_ref",
        "work_result_ref",
        "supersedes_ref",
    ]
    .iter()
    .filter_map(|field| intent.get(field).and_then(Value::as_str))
    .filter(|value| !value.is_empty())
    .map(ToOwned::to_owned)
    .collect();
    if let Some(delta_refs) = intent.get("outcome_delta_refs").and_then(Value::as_array) {
        reconstructed.extend(
            delta_refs
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
    }
    if values != reconstructed.into_iter().collect::<Vec<_>>() {
        return Err("intent touched_refs differs from reconstructed aggregate set".into());
    }
    Ok(values)
}

fn validate_intent_seal(intent: &Value, tail: &str) -> Result<(), String> {
    if intent.get("schema_version").and_then(Value::as_str) != Some(INTENT_SCHEMA)
        || intent.get("intent_id").and_then(Value::as_str)
            != Some(format!("attempt-finding-intent://{tail}").as_str())
        || intent.get("intent_hash").and_then(Value::as_str)
            != Some(record_output_hash(&without_field(intent, "intent_hash"), &[]).as_str())
    {
        return Err("intent storage-key/hash binding failed".into());
    }
    validate_touched(intent)?;
    Ok(())
}

fn pending_overlap(
    data_dir: &str,
    refs: &[&str],
    ignored: Option<&str>,
) -> Result<Option<(String, String)>, VErr> {
    let wanted: BTreeSet<&str> = refs
        .iter()
        .copied()
        .filter(|value| !value.is_empty())
        .collect();
    for (tail, intent) in scan_intents(data_dir)
        .map_err(|message| verr("attempt_finding_intent_unreadable", message))?
    {
        if ignored == Some(tail.as_str()) {
            continue;
        }
        let touched = validate_touched(&intent)
            .map_err(|message| verr("attempt_finding_intent_unreadable", message))?;
        if let Some(overlap) = touched.iter().find(|value| wanted.contains(value.as_str())) {
            return Ok(Some((tail, overlap.clone())));
        }
    }
    Ok(None)
}

fn refuse_reserved(
    data_dir: &str,
    refs: &[&str],
    code: &str,
    ignored: Option<&str>,
) -> Result<(), VErr> {
    if let Some((tail, overlap)) = pending_overlap(data_dir, refs, ignored)? {
        Err(verr(
            code,
            format!("record '{overlap}' is reserved by pending Attempt/Finding intent '{tail}'"),
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn refuse_external_mutation_if_reserved(
    data_dir: &str,
    record_ref: &str,
    code: &str,
) -> Result<(), VErr> {
    refuse_reserved(data_dir, &[record_ref], code, None)
}

pub(crate) fn refuse_external_mutation_if_reserved_except(
    data_dir: &str,
    record_ref: &str,
    code: &str,
    intent_tail: &str,
) -> Result<(), VErr> {
    refuse_reserved(data_dir, &[record_ref], code, Some(intent_tail))
}

fn resolve_open_room(data_dir: &str, room_ref: &str) -> Result<Value, VErr> {
    rooms::resolve_room_strict(data_dir, room_ref)
        .map_err(|message| verr("attempt_finding_room_registry_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "attempt_finding_room_not_found",
                format!("no room '{room_ref}'"),
            )
        })
        .and_then(|room| {
            if s(&room, "status", "") == "open" {
                Ok(room)
            } else {
                Err(verr(
                    "attempt_finding_room_not_open",
                    "Attempts and Findings admit only in an open hosted room",
                ))
            }
        })
}

fn participant_strict(data_dir: &str, participant_ref: &str) -> Result<Value, VErr> {
    participation::resolve_participant_lease_strict(data_dir, participant_ref)
        .map_err(|message| verr("attempt_finding_participant_registry_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "attempt_finding_participant_not_found",
                format!("no participant lease '{participant_ref}'"),
            )
        })
}

fn frontier_strict(data_dir: &str, frontier_ref: &str) -> Result<Value, VErr> {
    work::load_frontier_strict(data_dir, frontier_ref)
        .map_err(|message| verr("attempt_finding_frontier_registry_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "attempt_finding_frontier_not_found",
                format!("no frontier item '{frontier_ref}'"),
            )
        })
}

fn claim_strict(data_dir: &str, claim_ref: &str) -> Result<Value, VErr> {
    work::load_claim_strict(data_dir, claim_ref)
        .map_err(|message| verr("attempt_finding_claim_registry_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "attempt_finding_claim_not_found",
                format!("no work claim '{claim_ref}'"),
            )
        })
}

fn goal_run_strict(data_dir: &str, goal_run_ref: &str) -> Result<Value, VErr> {
    super::goalrun_routes::load_goal_run_strict(data_dir, goal_run_ref)
        .map_err(|message| verr("attempt_finding_goal_run_registry_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "attempt_finding_goal_run_not_found",
                format!("no GoalRun '{goal_run_ref}'"),
            )
        })
}

fn work_result_strict(data_dir: &str, result_ref: &str) -> Result<Value, VErr> {
    super::work_result_routes::load_work_result_strict(data_dir, result_ref)
        .map_err(|message| verr("attempt_finding_work_result_registry_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "attempt_finding_work_result_not_found",
                format!("no WorkResult '{result_ref}'"),
            )
        })
}

fn coordinate(reference: &str, record: &Value) -> Value {
    json!({
        "record_ref": reference,
        "revision": record.get("revision").cloned().unwrap_or(Value::Null),
        "updated_at": record.get("updated_at").cloned().unwrap_or(Value::Null),
        "record_hash": record_output_hash(record, &[]),
    })
}

fn coordinate_with_identity(reference: &str, record: &Value, identity: &[(&str, String)]) -> Value {
    let mut value = coordinate(reference, record);
    let object = value.as_object_mut().expect("coordinate object");
    for (field, field_value) in identity {
        object.insert((*field).to_string(), json!(field_value));
    }
    value
}

fn room_coordinate(reference: &str, room: &Value) -> Value {
    let mut control = room.clone();
    if let Some(object) = control.as_object_mut() {
        for field in [
            "revision",
            "updated_at",
            "status_history",
            "admission_and_replay_refs",
            "member_goal_run_refs",
            "participant_lease_refs",
            "released_participant_lease_refs",
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
        ] {
            object.remove(field);
        }
    }
    json!({
        "record_ref": reference,
        "host_domain_ref": s(room, "host_domain_ref", ""),
        "control_hash": record_output_hash(&control, &[]),
    })
}

#[derive(Clone)]
struct AttemptDependencies {
    room: Value,
    frontier: Value,
    claim: Value,
    participant: Value,
    goal_run: Value,
}

fn validate_bound_coordinate_identities(attempt: &Value) -> Result<(), VErr> {
    let coordinates = attempt.get("bound_coordinates").ok_or_else(|| {
        verr(
            "attempt_coordinate_invalid",
            "Attempt lacks immutable historical dependency coordinates",
        )
    })?;
    let expected = [
        ("outcome_room", "outcome_room_ref"),
        ("frontier_item", "frontier_item_ref"),
        ("work_claim", "work_claim_ref"),
        ("participant_lease", "participant_ref"),
        ("goal_run", "goal_run_ref"),
    ];
    for (coordinate_name, record_field) in expected {
        if coordinates
            .pointer(&format!("/{coordinate_name}/record_ref"))
            .and_then(Value::as_str)
            != attempt.get(record_field).and_then(Value::as_str)
        {
            return Err(verr(
                "attempt_coordinate_mismatch",
                format!("historical coordinate '{coordinate_name}' differs from '{record_field}'"),
            ));
        }
    }
    Ok(())
}

fn resolve_attempt_dependencies_with_posture(
    data_dir: &str,
    declaration: &Value,
    require_active_current: bool,
    require_open_room: bool,
) -> Result<AttemptDependencies, VErr> {
    validate_bound_coordinate_identities(declaration).or_else(|error| {
        if declaration.get("bound_coordinates").is_none() {
            Ok(())
        } else {
            Err(error)
        }
    })?;
    let room_ref = s(declaration, "outcome_room_ref", "");
    let frontier_ref = s(declaration, "frontier_item_ref", "");
    let claim_ref = s(declaration, "work_claim_ref", "");
    let participant_ref = s(declaration, "participant_ref", "");
    let goal_run_ref = s(declaration, "goal_run_ref", "");
    let room = if require_open_room {
        resolve_open_room(data_dir, &room_ref)?
    } else {
        rooms::resolve_room_strict(data_dir, &room_ref)
            .map_err(|message| verr("attempt_finding_room_registry_unreadable", message))?
            .ok_or_else(|| {
                verr(
                    "attempt_finding_room_not_found",
                    format!("no room '{room_ref}'"),
                )
            })?
    };
    let frontier = frontier_strict(data_dir, &frontier_ref)?;
    let claim = claim_strict(data_dir, &claim_ref)?;
    let participant = participant_strict(data_dir, &participant_ref)?;
    let goal_run = goal_run_strict(data_dir, &goal_run_ref)?;
    if [
        s(&frontier, "outcome_room_ref", ""),
        s(&claim, "outcome_room_ref", ""),
        s(&participant, "outcome_room_ref", ""),
        s(&goal_run, "outcome_room_ref", ""),
    ]
    .iter()
    .any(|bound| bound != &room_ref)
    {
        return Err(verr(
            "attempt_cross_room",
            "room, frontier, claim, participant, and GoalRun must name the exact same room",
        ));
    }
    if s(&claim, "frontier_item_ref", "") != frontier_ref
        || s(&claim, "claimant_ref", "") != participant_ref
    {
        return Err(verr(
            "attempt_coordinate_mismatch",
            "claim identity must bind the exact declared frontier and participant",
        ));
    }
    if require_active_current
        && (participant.get("current_claim_ref").and_then(Value::as_str)
            != Some(claim_ref.as_str())
            || s(&claim, "status", "") != "active"
            || s(&participant, "status", "") != "active")
    {
        return Err(verr(
            "attempt_participant_or_claim_not_active",
            "participant-governed work requires an active participant and its exact active current claim",
        ));
    }
    if let Some(coordinates) = declaration.get("bound_coordinates") {
        let frozen_host = coordinates
            .pointer("/outcome_room/host_domain_ref")
            .and_then(Value::as_str);
        let frozen_frontier_room = coordinates
            .pointer("/frontier_item/outcome_room_ref")
            .and_then(Value::as_str);
        let frozen_claim_room = coordinates
            .pointer("/work_claim/outcome_room_ref")
            .and_then(Value::as_str);
        let frozen_claim_frontier = coordinates
            .pointer("/work_claim/frontier_item_ref")
            .and_then(Value::as_str);
        let frozen_claimant = coordinates
            .pointer("/work_claim/claimant_ref")
            .and_then(Value::as_str);
        let frozen_participant_room = coordinates
            .pointer("/participant_lease/outcome_room_ref")
            .and_then(Value::as_str);
        let frozen_principal = coordinates
            .pointer("/participant_lease/principal_ref")
            .and_then(Value::as_str);
        let frozen_goal_room = coordinates
            .pointer("/goal_run/outcome_room_ref")
            .and_then(Value::as_str);
        if frozen_host != room.get("host_domain_ref").and_then(Value::as_str)
            || frozen_frontier_room != Some(room_ref.as_str())
            || frozen_claim_room != Some(room_ref.as_str())
            || frozen_claim_frontier != Some(frontier_ref.as_str())
            || frozen_claimant != Some(participant_ref.as_str())
            || frozen_participant_room != Some(room_ref.as_str())
            || frozen_principal != participant.get("participant_ref").and_then(Value::as_str)
            || frozen_goal_room != Some(room_ref.as_str())
        {
            return Err(verr(
                "attempt_coordinate_mismatch",
                "immutable historical identity coordinates differ from the declared room, claim, participant, or GoalRun",
            ));
        }
    }
    Ok(AttemptDependencies {
        room,
        frontier,
        claim,
        participant,
        goal_run,
    })
}

fn resolve_attempt_dependencies(
    data_dir: &str,
    declaration: &Value,
) -> Result<AttemptDependencies, VErr> {
    resolve_attempt_dependencies_with_posture(data_dir, declaration, true, true)
}

fn dependency_coordinates(declaration: &Value, dependencies: &AttemptDependencies) -> Value {
    json!({
        "outcome_room": room_coordinate(&s(declaration, "outcome_room_ref", ""), &dependencies.room),
        "frontier_item": coordinate_with_identity(
            &s(declaration, "frontier_item_ref", ""),
            &dependencies.frontier,
            &[("outcome_room_ref", s(&dependencies.frontier, "outcome_room_ref", ""))],
        ),
        "work_claim": coordinate_with_identity(
            &s(declaration, "work_claim_ref", ""),
            &dependencies.claim,
            &[
                ("outcome_room_ref", s(&dependencies.claim, "outcome_room_ref", "")),
                ("frontier_item_ref", s(&dependencies.claim, "frontier_item_ref", "")),
                ("claimant_ref", s(&dependencies.claim, "claimant_ref", "")),
            ],
        ),
        "participant_lease": coordinate_with_identity(
            &s(declaration, "participant_ref", ""),
            &dependencies.participant,
            &[
                ("outcome_room_ref", s(&dependencies.participant, "outcome_room_ref", "")),
                ("principal_ref", s(&dependencies.participant, "participant_ref", "")),
            ],
        ),
        "goal_run": coordinate_with_identity(
            &s(declaration, "goal_run_ref", ""),
            &dependencies.goal_run,
            &[("outcome_room_ref", s(&dependencies.goal_run, "outcome_room_ref", ""))],
        ),
    })
}

fn validate_attempt_create(body: &Value) -> Result<Value, VErr> {
    reject_sensitive(body, "")?;
    reject_unknown(
        body,
        &[
            "outcome_room_ref",
            "frontier_item_ref",
            "work_claim_ref",
            "participant_ref",
            "goal_run_ref",
            "declared_method_and_hypothesis_refs",
            "parent_and_derivation_refs",
            "input_state_and_environment_refs",
            "worker_model_harness_tool_and_runtime_versions",
            "authority_and_policy_refs",
            "resource_and_cost_refs",
            "artifact_license_ip_retention_and_export_refs",
            "contribution_refs",
            "coordination_topology",
            "expected_revision",
            "wallet_approval_grant",
        ],
    )?;
    expected_revision(body, 0)?;
    if body.get("coordination_topology").and_then(Value::as_str) != Some("hosted_admission") {
        return Err(verr(
            "attempt_federated_unavailable",
            "only hosted admission is implemented; federated/AIIP attempt admission is unavailable",
        ));
    }
    Ok(json!({
        "outcome_room_ref": required_ref(body, "outcome_room_ref", &["outcome-room"] )?,
        "frontier_item_ref": required_ref(body, "frontier_item_ref", &["frontier"] )?,
        "work_claim_ref": required_ref(body, "work_claim_ref", &["work-claim"] )?,
        "participant_ref": required_ref(body, "participant_ref", &["participant-lease"] )?,
        "goal_run_ref": required_ref(body, "goal_run_ref", &["goal"] )?,
        "declared_method_and_hypothesis_refs": ref_list(body, "declared_method_and_hypothesis_refs", &["method", "finding", "artifact"] )?,
        "parent_and_derivation_refs": ref_list(body, "parent_and_derivation_refs", &["attempt", "artifact", "finding"] )?,
        "input_state_and_environment_refs": ref_list(body, "input_state_and_environment_refs", &["state", "environment", "worktree", "dataset"] )?,
        "worker_model_harness_tool_and_runtime_versions": ref_list_with_prefixes(body, "worker_model_harness_tool_and_runtime_versions", &["worker", "model_route", "tool", "runtime"], &["harness_profile:"] )?,
        "authority_and_policy_refs": ref_list(body, "authority_and_policy_refs", &["grant", "policy"] )?,
        "resource_and_cost_refs": ref_list(body, "resource_and_cost_refs", &["resource-lease", "spend", "ledger"] )?,
        "artifact_license_ip_retention_and_export_refs": ref_list(body, "artifact_license_ip_retention_and_export_refs", &["license", "policy"] )?,
        "contribution_refs": ref_list_with_prefixes(body, "contribution_refs", &["receipt"], &["contrib_"] )?,
        "coordination_topology": "hosted_admission",
    }))
}

fn seal_attempt(
    declaration: &Value,
    coordinates: &Value,
    tail: &str,
    receipt_ref: &str,
    at_ms: u64,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(at_ms)?;
    let mut record = declaration.clone();
    let object = record.as_object_mut().expect("attempt declaration");
    object.insert("schema_version".into(), json!(ATTEMPT_SCHEMA));
    object.insert("attempt_id".into(), json!(format!("attempt://{tail}")));
    object.insert("bound_coordinates".into(), coordinates.clone());
    object.insert("outcome_class".into(), Value::Null);
    object.insert("work_result_ref".into(), Value::Null);
    object.insert("outcome_delta_refs".into(), json!([]));
    object.insert("artifact_evidence_and_receipt_refs".into(), json!([]));
    object.insert("verifier_refs".into(), json!([]));
    object.insert("reproduction_state".into(), Value::Null);
    object.insert("status".into(), json!("draft"));
    object.insert("revision".into(), json!(1));
    object.insert("created_at".into(), json!(now));
    object.insert("created_at_ms".into(), json!(at_ms));
    object.insert("updated_at".into(), json!(now));
    object.insert("updated_at_ms".into(), json!(at_ms));
    object.insert("admission_receipt_ref".into(), json!(receipt_ref));
    object.insert("admission_and_replay_refs".into(), json!([receipt_ref]));
    object.insert("status_history".into(), json!([]));
    object.insert("runtimeTruthSource".into(), json!("daemon-runtime"));
    Ok(record)
}

fn validate_attempt_transition(body: &Value, op: &str) -> Result<Value, VErr> {
    let allowed: &[&str] = match op {
        "submit" => &[
            "transition",
            "expected_revision",
            "outcome_class",
            "work_result_ref",
            "outcome_delta_refs",
            "artifact_evidence_and_receipt_refs",
            "reproduction_state",
            "wallet_approval_grant",
        ],
        _ => &["transition", "expected_revision", "wallet_approval_grant"],
    };
    reject_sensitive(body, "")?;
    reject_unknown(body, allowed)?;
    if op != "submit" {
        return Ok(json!({"status_only": true}));
    }
    let outcome = body
        .get("outcome_class")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "attempt_outcome_class_required",
                "submit requires outcome_class",
            )
        })?;
    if !ATTEMPT_OUTCOMES.contains(&outcome) || outcome == "superseded" {
        return Err(verr(
            "attempt_outcome_class_invalid",
            "submit outcome_class must be positive, negative, inconclusive, invalid, or exploit_found",
        ));
    }
    let reproduction = body
        .get("reproduction_state")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "attempt_reproduction_state_required",
                "submit requires a bounded reproduction_state",
            )
        })?;
    if ![
        "unreviewed",
        "reproducible",
        "not_reproduced",
        "contradicted",
        "invalidated",
    ]
    .contains(&reproduction)
    {
        return Err(verr(
            "attempt_reproduction_state_invalid",
            "reproduction_state is outside the canonical vocabulary",
        ));
    }
    Ok(json!({
        "outcome_class": outcome,
        "work_result_ref": required_ref(body, "work_result_ref", &["work-result"] )?,
        "outcome_delta_refs": ref_list(body, "outcome_delta_refs", &["outcome-delta"] )?,
        "artifact_evidence_and_receipt_refs": ref_list(body, "artifact_evidence_and_receipt_refs", &["artifact", "evidence", "receipt", "ledger"] )?,
        "reproduction_state": reproduction,
    }))
}

fn append_history(
    object: &mut Map<String, Value>,
    op: &str,
    from: &str,
    to: &str,
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
        "op": op, "from": from, "to": to, "at": now,
        "receipt_ref": receipt_ref, "revision": revision,
    }));
    if history.len() > HISTORY_MAX {
        history.drain(0..history.len() - HISTORY_MAX);
    }
    object.insert("status_history".into(), Value::Array(history));
}

fn transition_attempt(
    prior: &Value,
    op: &str,
    to: &str,
    effect_fields: &Value,
    receipt_ref: &str,
    at_ms: u64,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(at_ms)?;
    let mut final_record = prior.clone();
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0) + 1;
    let from = s(prior, "status", "");
    let object = final_record.as_object_mut().expect("attempt record");
    object.insert("status".into(), json!(to));
    object.insert("revision".into(), json!(revision));
    object.insert("updated_at".into(), json!(now));
    object.insert("updated_at_ms".into(), json!(at_ms));
    if op == "submit" {
        for field in [
            "outcome_class",
            "work_result_ref",
            "outcome_delta_refs",
            "artifact_evidence_and_receipt_refs",
            "reproduction_state",
        ] {
            object.insert(
                field.into(),
                effect_fields.get(field).cloned().unwrap_or(Value::Null),
            );
        }
    }
    append_history(object, op, &from, to, receipt_ref, &now, revision);
    Ok(final_record)
}

fn validate_finding_create(body: &Value) -> Result<Value, VErr> {
    reject_sensitive(body, "")?;
    reject_unknown(
        body,
        &[
            "outcome_room_ref",
            "attempt_ref",
            "work_result_ref",
            "participant_ref",
            "proposition",
            "finding_kind",
            "confidence_or_uncertainty",
            "valid_time",
            "supporting_evidence_refs",
            "contradicting_evidence_refs",
            "proof_refs",
            "applicability_and_counterexample_refs",
            "provenance_ontology_and_mapping_refs",
            "proposed_effect_refs",
            "supersedes_ref",
            "coordination_topology",
            "expected_revision",
            "wallet_approval_grant",
        ],
    )?;
    expected_revision(body, 0)?;
    if body.get("coordination_topology").and_then(Value::as_str) != Some("hosted_admission") {
        return Err(verr(
            "finding_federated_unavailable",
            "only hosted admission is implemented; federated/AIIP finding admission is unavailable",
        ));
    }
    let kind = body
        .get("finding_kind")
        .and_then(Value::as_str)
        .ok_or_else(|| verr("finding_kind_required", "finding kind is required"))?;
    if !FINDING_KINDS.contains(&kind) {
        return Err(verr(
            "finding_kind_invalid",
            "finding kind is outside canon",
        ));
    }
    let uncertainty = match body.get("confidence_or_uncertainty") {
        Some(Value::Number(number)) => {
            let value = number
                .as_f64()
                .filter(|value| value.is_finite())
                .ok_or_else(|| verr("finding_uncertainty_invalid", "uncertainty must be finite"))?;
            if !(0.0..=1.0).contains(&value) {
                return Err(verr(
                    "finding_uncertainty_invalid",
                    "uncertainty must be between 0 and 1",
                ));
            }
            json!(value)
        }
        Some(Value::Null) => Value::Null,
        _ => {
            return Err(verr(
                "finding_uncertainty_required",
                "confidence_or_uncertainty must be an explicit number or null",
            ))
        }
    };
    let valid_time = match body.get("valid_time") {
        None | Some(Value::Null) => Value::Null,
        Some(value @ Value::Object(_)) if value.to_string().len() <= TEXT_MAX => value.clone(),
        _ => {
            return Err(verr(
                "finding_valid_time_invalid",
                "valid_time must be null or a bounded interval object",
            ))
        }
    };
    Ok(json!({
        "outcome_room_ref": required_ref(body, "outcome_room_ref", &["outcome-room"] )?,
        "attempt_ref": required_ref(body, "attempt_ref", &["attempt"] )?,
        "work_result_ref": required_ref(body, "work_result_ref", &["work-result"] )?,
        "participant_ref": required_ref(body, "participant_ref", &["participant-lease"] )?,
        "proposition": bounded_text(body, "proposition", true)?,
        "finding_kind": kind,
        "confidence_or_uncertainty": uncertainty,
        "valid_time": valid_time,
        "supporting_evidence_refs": ref_list(body, "supporting_evidence_refs", &["evidence", "artifact", "receipt"] )?,
        "contradicting_evidence_refs": ref_list(body, "contradicting_evidence_refs", &["evidence", "artifact", "finding"] )?,
        "proof_refs": ref_list(body, "proof_refs", &["evidence", "artifact", "receipt"] )?,
        "source_and_observation_context_refs": [required_ref(body, "attempt_ref", &["attempt"] )?, required_ref(body, "participant_ref", &["participant-lease"] )?],
        "applicability_and_counterexample_refs": ref_list(body, "applicability_and_counterexample_refs", &["policy", "finding", "ontology"] )?,
        "provenance_ontology_and_mapping_refs": ref_list(body, "provenance_ontology_and_mapping_refs", &["provenance", "ontology", "ontology-mapping"] )?,
        "proposed_effect_refs": ref_list(body, "proposed_effect_refs", &["frontier", "routing-prior", "policy", "capability"] )?,
        "supersedes_ref": optional_ref(body, "supersedes_ref", &["finding"] )?,
        "dispute_ref": Value::Null,
        "coordination_topology": "hosted_admission",
    }))
}

fn seal_finding(
    declaration: &Value,
    coordinates: &Value,
    tail: &str,
    receipt_ref: &str,
    at_ms: u64,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(at_ms)?;
    let mut record = declaration.clone();
    let object = record.as_object_mut().expect("finding declaration");
    object.insert("schema_version".into(), json!(FINDING_SCHEMA));
    object.insert("finding_id".into(), json!(format!("finding://{tail}")));
    object.insert("bound_coordinates".into(), coordinates.clone());
    object.insert("transaction_time".into(), json!(now));
    object.insert("status".into(), json!("proposed"));
    object.insert("revision".into(), json!(1));
    object.insert("created_at".into(), json!(now));
    object.insert("created_at_ms".into(), json!(at_ms));
    object.insert("updated_at".into(), json!(now));
    object.insert("updated_at_ms".into(), json!(at_ms));
    object.insert("admission_receipt_ref".into(), json!(receipt_ref));
    object.insert("admission_and_replay_refs".into(), json!([receipt_ref]));
    object.insert("status_history".into(), json!([]));
    object.insert("runtimeTruthSource".into(), json!("daemon-runtime"));
    Ok(record)
}

fn transition_finding(
    prior: &Value,
    op: &str,
    to: &str,
    receipt_ref: &str,
    at_ms: u64,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(at_ms)?;
    let mut final_record = prior.clone();
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0) + 1;
    let from = s(prior, "status", "");
    let object = final_record.as_object_mut().expect("finding record");
    object.insert("status".into(), json!(to));
    object.insert("revision".into(), json!(revision));
    object.insert("updated_at".into(), json!(now));
    object.insert("updated_at_ms".into(), json!(at_ms));
    append_history(object, op, &from, to, receipt_ref, &now, revision);
    Ok(final_record)
}

fn effect(kind: &str, op: &str, revision: u64, payload: &Value, status_after: &str) -> Value {
    json!({
        "object_kind": kind,
        "op": op,
        "revision_before": revision,
        "payload": payload,
        "status_after": status_after,
        "acceptance_created": false,
        "verdict_created": false,
        "execution_authority_granted": false,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_receipt(
    tail: &str,
    schema: &str,
    receipt_type: &str,
    subject_ref: &str,
    op: &str,
    bound_facts: Value,
    boundary_refs: Vec<Value>,
    output: &Value,
    authorized: &AuthorizedDecision,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(authorized.resolved_at_ms)?;
    let mut receipt = build_room_receipt_at(
        tail,
        schema,
        receipt_type,
        subject_ref,
        op,
        bound_facts,
        boundary_refs,
        record_output_hash(output, &["admission_and_replay_refs", "status_history"]),
        &["admission_and_replay_refs", "status_history"],
        "admitted_not_verified",
        "an admitted hosted-room provenance mutation; no acceptance, verdict, settlement, or execution authority is created",
        &now,
    );
    governed::append_evidence(&mut receipt, authorized);
    Ok(receipt)
}

fn seal_intent(mut intent: Value, tail: &str) -> Value {
    let object = intent.as_object_mut().expect("intent object");
    object.insert("schema_version".into(), json!(INTENT_SCHEMA));
    object.insert(
        "intent_id".into(),
        json!(format!("attempt-finding-intent://{tail}")),
    );
    let mut touched: BTreeSet<String> = [
        "subject_ref",
        "room_ref",
        "frontier_ref",
        "claim_ref",
        "participant_ref",
        "goal_run_ref",
        "attempt_ref",
        "work_result_ref",
        "supersedes_ref",
    ]
    .iter()
    .filter_map(|field| object.get(*field).and_then(Value::as_str))
    .filter(|value| !value.is_empty())
    .map(ToOwned::to_owned)
    .collect();
    if let Some(delta_refs) = object.get("outcome_delta_refs").and_then(Value::as_array) {
        touched.extend(
            delta_refs
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
    }
    object.insert("touched_refs".into(), json!(touched));
    let hash = record_output_hash(&intent, &[]);
    intent
        .as_object_mut()
        .unwrap()
        .insert("intent_hash".into(), json!(hash));
    intent
}

fn persist_successor(
    data_dir: &str,
    family: &str,
    tail: &str,
    scheme: &str,
    canonical: fn(&str) -> bool,
    prior: Option<&Value>,
    final_record: &Value,
) -> Result<(), VErr> {
    let current = load_record(data_dir, family, tail, scheme, canonical)
        .map_err(|message| verr("attempt_finding_registry_unreadable", message))?;
    if current.as_ref() == Some(final_record) {
        return Ok(());
    }
    if current.as_ref() != prior {
        return Err(verr(
            "attempt_finding_pending_convergence",
            format!("{family}/{tail} equals neither sealed prior nor successor"),
        ));
    }
    persist_record(data_dir, family, tail, final_record)
}

fn complete_intent_locked(data_dir: &str, tail: &str, intent: &Value) -> Result<(), VErr> {
    validate_intent_seal(intent, tail)
        .map_err(|message| verr("attempt_finding_intent_unreadable", message))?;
    let kind = intent
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| verr("attempt_finding_intent_unreadable", "intent lacks kind"))?;
    let receipt_tail = intent
        .get("receipt_tail")
        .and_then(Value::as_str)
        .filter(|tail| canonical_receipt_tail(tail))
        .ok_or_else(|| {
            verr(
                "attempt_finding_intent_unreadable",
                "intent receipt tail is invalid",
            )
        })?;
    let receipt = intent
        .get("receipt")
        .ok_or_else(|| verr("attempt_finding_intent_unreadable", "intent lacks receipt"))?;
    if matches!(kind, "attempt_create" | "finding_create") {
        let room_ref = s(intent, "room_ref", "");
        let subject_ref = s(intent, "subject_ref", "");
        let op = if kind == "attempt_create" {
            "attempt_bound"
        } else {
            "finding_bound"
        };
        match rooms::bind_room_backlink_room_locked_for_attempt_finding_intent(
            data_dir,
            &room_ref,
            op,
            &subject_ref,
            tail,
        ) {
            Ok(_) => {}
            Err((code, _)) if code == "outcome_room_backlink_already_bound" => {}
            Err(error) => return Err(error),
        }
    }
    persist_receipt(data_dir, receipt_tail, receipt)?;
    let (family, scheme, canonical, final_field, prior_field) = if kind.starts_with("attempt_") {
        (
            ATTEMPT_DIR,
            "attempt",
            canonical_attempt_tail as fn(&str) -> bool,
            "final_attempt",
            "prior_attempt",
        )
    } else {
        (
            FINDING_DIR,
            "finding",
            canonical_finding_tail as fn(&str) -> bool,
            "final_finding",
            "prior_finding",
        )
    };
    let final_record = intent
        .get(final_field)
        .filter(|value| !value.is_null())
        .ok_or_else(|| {
            verr(
                "attempt_finding_intent_unreadable",
                "intent lacks successor",
            )
        })?;
    let id = final_record
        .get(identity_field(family))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "attempt_finding_intent_unreadable",
                "successor lacks identity",
            )
        })?;
    let record_tail = id.strip_prefix(&format!("{scheme}://")).ok_or_else(|| {
        verr(
            "attempt_finding_intent_unreadable",
            "successor identity scheme mismatch",
        )
    })?;
    persist_successor(
        data_dir,
        family,
        record_tail,
        scheme,
        canonical,
        intent.get(prior_field).filter(|value| !value.is_null()),
        final_record,
    )?;
    consume_intent(data_dir, tail)
}

fn persist_and_complete_locked(data_dir: &str, tail: &str, intent: &Value) -> Result<(), VErr> {
    persist_record(data_dir, INTENT_DIR, tail, intent)?;
    complete_intent_locked(data_dir, tail, intent)
}

fn dependency_refs_from_attempt(attempt: &Value) -> [String; 5] {
    [
        s(attempt, "outcome_room_ref", ""),
        s(attempt, "frontier_item_ref", ""),
        s(attempt, "work_claim_ref", ""),
        s(attempt, "participant_ref", ""),
        s(attempt, "goal_run_ref", ""),
    ]
}

fn validate_attempt_coordinates(
    data_dir: &str,
    attempt: &Value,
    require_active_current: bool,
    require_open_room: bool,
) -> Result<AttemptDependencies, VErr> {
    resolve_attempt_dependencies_with_posture(
        data_dir,
        attempt,
        require_active_current,
        require_open_room,
    )
}

fn validate_work_result_for_attempt(result: &Value, attempt: &Value) -> Result<(), VErr> {
    if s(result, "outcome_room_ref", "") != s(attempt, "outcome_room_ref", "")
        || result.get("goal_run_ref").and_then(Value::as_str)
            != Some(s(attempt, "goal_run_ref", "").as_str())
    {
        return Err(verr(
            "attempt_work_result_coordinate_mismatch",
            "WorkResult must bind the Attempt's exact room and GoalRun",
        ));
    }
    Ok(())
}

fn outcome_delta_strict(data_dir: &str, delta_ref: &str) -> Result<Value, VErr> {
    super::work_result_routes::load_outcome_delta_strict(data_dir, delta_ref)
        .map_err(|message| verr("attempt_finding_outcome_delta_registry_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "attempt_outcome_delta_not_found",
                format!("no OutcomeDelta '{delta_ref}'"),
            )
        })
}

fn validate_outcome_deltas_for_attempt(
    data_dir: &str,
    result: &Value,
    attempt: &Value,
    delta_refs: &[String],
) -> Result<Value, VErr> {
    let result_ref = s(result, "work_result_id", "");
    let room_ref = s(attempt, "outcome_room_ref", "");
    let result_goal = s(result, "goal_ref", "");
    let backlinks = result
        .get("outcome_delta_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "attempt_work_result_coordinate_mismatch",
                "WorkResult outcome_delta_refs backlink set is malformed",
            )
        })?;
    let backlink_refs: BTreeSet<&str> = backlinks.iter().filter_map(Value::as_str).collect();
    let mut coordinates = Vec::new();
    for delta_ref in delta_refs {
        if !backlink_refs.contains(delta_ref.as_str()) {
            return Err(verr(
                "attempt_outcome_delta_not_backlinked",
                format!(
                    "OutcomeDelta '{delta_ref}' is not in WorkResult '{result_ref}' plane-owned backlinks"
                ),
            ));
        }
        let delta = outcome_delta_strict(data_dir, delta_ref)?;
        if s(&delta, "proposed_by_ref", "") != result_ref {
            return Err(verr(
                "attempt_outcome_delta_cross_result",
                format!("OutcomeDelta '{delta_ref}' belongs to another WorkResult"),
            ));
        }
        if s(&delta, "outcome_room_ref", "") != room_ref
            || s(&delta, "outcome_room_ref", "") != s(result, "outcome_room_ref", "")
        {
            return Err(verr(
                "attempt_outcome_delta_cross_room",
                format!("OutcomeDelta '{delta_ref}' belongs to another room"),
            ));
        }
        if s(&delta, "goal_ref", "") != result_goal {
            return Err(verr(
                "attempt_outcome_delta_cross_result",
                format!("OutcomeDelta '{delta_ref}' belongs to another result goal"),
            ));
        }
        coordinates.push(coordinate_with_identity(
            delta_ref,
            &delta,
            &[
                ("work_result_ref", result_ref.clone()),
                ("outcome_room_ref", room_ref.clone()),
                ("goal_ref", result_goal.clone()),
            ],
        ));
    }
    Ok(Value::Array(coordinates))
}

fn work_result_coordinate(result_ref: &str, result: &Value) -> Value {
    coordinate_with_identity(
        result_ref,
        result,
        &[
            ("outcome_room_ref", s(result, "outcome_room_ref", "")),
            ("goal_run_ref", s(result, "goal_run_ref", "")),
            ("goal_ref", s(result, "goal_ref", "")),
        ],
    )
}

fn finding_coordinates(
    attempt: &Value,
    result: &Value,
    supersedes: Option<&Value>,
) -> Result<Value, VErr> {
    let participant = attempt
        .pointer("/bound_coordinates/participant_lease")
        .cloned()
        .ok_or_else(|| {
            verr(
                "attempt_coordinate_invalid",
                "Attempt lacks its historical participant coordinate",
            )
        })?;
    let supersedes_coordinate = supersedes.map_or(Value::Null, |finding| {
        coordinate_with_identity(
            &s(finding, "finding_id", ""),
            finding,
            &[("outcome_room_ref", s(finding, "outcome_room_ref", ""))],
        )
    });
    Ok(json!({
        "attempt": coordinate_with_identity(
            &s(attempt, "attempt_id", ""),
            attempt,
            &[
                ("outcome_room_ref", s(attempt, "outcome_room_ref", "")),
                ("participant_ref", s(attempt, "participant_ref", "")),
                ("work_result_ref", s(attempt, "work_result_ref", "")),
            ],
        ),
        "work_result": work_result_coordinate(&s(result, "work_result_id", ""), result),
        "participant_lease": participant,
        "supersedes_finding": supersedes_coordinate,
    }))
}

#[derive(Clone)]
struct FindingDependencies {
    room: Value,
    attempt: Value,
    result: Value,
    participant: Value,
    supersedes: Option<Value>,
}

fn resolve_finding_dependencies(
    data_dir: &str,
    declaration: &Value,
    require_admitted_attempt: bool,
    require_open_room: bool,
    require_active_participant: bool,
) -> Result<FindingDependencies, VErr> {
    let room_ref = s(declaration, "outcome_room_ref", "");
    let attempt_ref = s(declaration, "attempt_ref", "");
    let result_ref = s(declaration, "work_result_ref", "");
    let participant_ref = s(declaration, "participant_ref", "");
    let room = if require_open_room {
        resolve_open_room(data_dir, &room_ref)?
    } else {
        rooms::resolve_room_strict(data_dir, &room_ref)
            .map_err(|message| verr("attempt_finding_room_registry_unreadable", message))?
            .ok_or_else(|| {
                verr(
                    "attempt_finding_room_not_found",
                    format!("no room '{room_ref}'"),
                )
            })?
    };
    let attempt = load_attempt_strict(data_dir, &attempt_ref)
        .map_err(|message| verr("attempt_finding_registry_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "finding_attempt_not_found",
                format!("no Attempt '{attempt_ref}'"),
            )
        })?;
    if require_admitted_attempt && s(&attempt, "status", "") != "admitted" {
        return Err(verr(
            "finding_attempt_not_admitted",
            "Finding requires an admitted Attempt",
        ));
    }
    let attempt_dependencies =
        validate_attempt_coordinates(data_dir, &attempt, false, require_open_room)?;
    if s(&attempt, "outcome_room_ref", "") != room_ref
        || s(&attempt, "participant_ref", "") != participant_ref
        || attempt.get("work_result_ref").and_then(Value::as_str) != Some(result_ref.as_str())
    {
        return Err(verr(
            "finding_coordinate_mismatch",
            "Finding must bind its Attempt's exact room, participant, and WorkResult",
        ));
    }
    let result = work_result_strict(data_dir, &result_ref)?;
    validate_work_result_for_attempt(&result, &attempt)?;
    let participant = participant_strict(data_dir, &participant_ref)?;
    if s(&participant, "outcome_room_ref", "") != room_ref
        || participant.get("participant_ref").and_then(Value::as_str)
            != attempt_dependencies
                .participant
                .get("participant_ref")
                .and_then(Value::as_str)
    {
        return Err(verr(
            "finding_coordinate_mismatch",
            "Finding participant identity differs from the Attempt's historical participant",
        ));
    }
    if require_active_participant && s(&participant, "status", "") != "active" {
        return Err(verr(
            "finding_participant_not_active",
            "fresh Finding admission requires the exact participant lease to be active; no active/current claim is required",
        ));
    }
    let supersedes = match declaration.get("supersedes_ref") {
        None | Some(Value::Null) => None,
        Some(Value::String(reference)) => {
            let prior = load_finding_strict(data_dir, reference)
                .map_err(|message| verr("attempt_finding_registry_unreadable", message))?
                .ok_or_else(|| {
                    verr(
                        "finding_supersedes_not_found",
                        format!("superseded Finding '{reference}' does not resolve"),
                    )
                })?;
            if s(&prior, "outcome_room_ref", "") != room_ref {
                return Err(verr(
                    "finding_supersedes_cross_room",
                    "a Finding can supersede only a Finding in the exact same room",
                ));
            }
            Some(prior)
        }
        _ => {
            return Err(verr(
                "finding_supersedes_ref_invalid",
                "supersedes_ref must be null or a canonical finding:// ref",
            ))
        }
    };
    if let Some(coordinates) = declaration.get("bound_coordinates") {
        let expected_supersedes = declaration.get("supersedes_ref").and_then(Value::as_str);
        if coordinates
            .pointer("/attempt/record_ref")
            .and_then(Value::as_str)
            != Some(attempt_ref.as_str())
            || coordinates
                .pointer("/attempt/outcome_room_ref")
                .and_then(Value::as_str)
                != Some(room_ref.as_str())
            || coordinates
                .pointer("/attempt/participant_ref")
                .and_then(Value::as_str)
                != Some(participant_ref.as_str())
            || coordinates
                .pointer("/attempt/work_result_ref")
                .and_then(Value::as_str)
                != Some(result_ref.as_str())
            || coordinates
                .pointer("/work_result/record_ref")
                .and_then(Value::as_str)
                != Some(result_ref.as_str())
            || coordinates
                .pointer("/work_result/outcome_room_ref")
                .and_then(Value::as_str)
                != Some(room_ref.as_str())
            || coordinates
                .pointer("/participant_lease/record_ref")
                .and_then(Value::as_str)
                != Some(participant_ref.as_str())
            || coordinates
                .pointer("/supersedes_finding/record_ref")
                .and_then(Value::as_str)
                != expected_supersedes
            || (expected_supersedes.is_none()
                && !coordinates
                    .get("supersedes_finding")
                    .is_some_and(Value::is_null))
        {
            return Err(verr(
                "finding_coordinate_mismatch",
                "Finding historical identity coordinates differ from its declared lineage",
            ));
        }
    }
    Ok(FindingDependencies {
        room,
        attempt,
        result,
        participant,
        supersedes,
    })
}

async fn authorize(
    contract: AuthorityContract,
    body: &Value,
    governance: Governance,
    room_ref: &str,
    required_authority: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
    effect: &Value,
) -> Result<AuthorizedDecision, (StatusCode, Json<Value>)> {
    governed::authorize_decision(
        contract,
        body,
        governance,
        room_ref,
        required_authority,
        subject_ref,
        op,
        revision,
        effect,
    )
    .await
}

pub(crate) async fn handle_attempt_create(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let declaration = match validate_attempt_create(&body) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let dependencies = match resolve_attempt_dependencies(&state.data_dir, &declaration) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let coordinates = dependency_coordinates(&declaration, &dependencies);
    let tail = deterministic_tail(
        "att_",
        &json!({"domain":"hypervisor.attempt.identity.v1","declaration":declaration,"bound_coordinates":coordinates}),
    );
    let subject_ref = format!("attempt://{tail}");
    let room_ref = s(&declaration, "outcome_room_ref", "");
    let participant_ref = s(&declaration, "participant_ref", "");
    let authority = s(&dependencies.participant, "participant_ref", "");
    let mutation_effect = effect(
        "attempt",
        "create",
        0,
        &json!({"declaration":declaration,"bound_coordinates":coordinates}),
        "draft",
    );
    let authorized = match authorize(
        ATTEMPT_AUTHORITY,
        &body,
        Governance::Participant,
        &room_ref,
        &authority,
        &subject_ref,
        "create",
        0,
        &mutation_effect,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let _participant = participation::PARTICIPATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _work = work::FRONTIER_CLAIM_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _room = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _goal = super::goalrun_routes::GOAL_RUN_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _result = super::work_result_routes::DELTA_ADMISSION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _plane = ATTEMPT_FINDING_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Err(error) = resolve_attempt_dependencies(&state.data_dir, &declaration) {
        return classify(error);
    }
    let refs = dependency_refs_from_attempt(&declaration);
    let mut reserved: Vec<&str> = refs.iter().map(String::as_str).collect();
    reserved.push(&subject_ref);
    if let Err(error) = refuse_reserved(
        &state.data_dir,
        &reserved,
        "attempt_finding_mutation_in_flight",
        None,
    ) {
        return classify(error);
    }
    match load_attempt_strict(&state.data_dir, &tail) {
        Ok(None) => {}
        Ok(Some(_)) => {
            return classify(verr(
                "attempt_conflict",
                format!("canonical Attempt '{subject_ref}' already exists"),
            ))
        }
        Err(message) => return classify(verr("attempt_finding_registry_unreadable", message)),
    }
    let receipt_tail = fresh_tail("amr_", &subject_ref, "create", 0, authorized.resolved_at_ms);
    let receipt_ref = format!("receipt://{receipt_tail}");
    let final_attempt = match seal_attempt(
        &declaration,
        &coordinates,
        &tail,
        &receipt_ref,
        authorized.resolved_at_ms,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let receipt = match build_receipt(
        &receipt_tail,
        ATTEMPT_RECEIPT_SCHEMA,
        "AttemptMutationReceipt",
        &subject_ref,
        "create",
        json!({"revision_before":0,"revision_after":1,"status_after":"draft","bound_coordinates":coordinates}),
        refs.iter().map(|value| json!(value)).collect(),
        &final_attempt,
        &authorized,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent_tail = fresh_tail("afi_", &subject_ref, "create", 0, authorized.resolved_at_ms);
    let intent = seal_intent(
        json!({
            "kind":"attempt_create","governance":"participant","op":"create",
            "room_ref":room_ref,"frontier_ref":s(&declaration,"frontier_item_ref",""),
            "claim_ref":s(&declaration,"work_claim_ref",""),"participant_ref":participant_ref,
            "goal_run_ref":s(&declaration,"goal_run_ref",""),"attempt_ref":Value::Null,
            "work_result_ref":Value::Null,"outcome_delta_refs":[],"supersedes_ref":Value::Null,
            "required_authority_ref":authority,
            "subject_ref":subject_ref,"revision_before":0,"receipt_tail":receipt_tail,
            "receipt":receipt,"prior_attempt":Value::Null,"final_attempt":final_attempt,
            "prior_finding":Value::Null,"final_finding":Value::Null,
        }),
        &intent_tail,
    );
    match persist_and_complete_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({"attempt":final_attempt,"attempt_receipt":receipt})),
        ),
        Err(error) => classify(error),
    }
}

fn attempt_transition_contract(op: &str, from: &str) -> Result<(Governance, &'static str), VErr> {
    match (op, from) {
        ("start", "draft") => Ok((Governance::Participant, "running")),
        ("submit", "draft" | "running") => Ok((Governance::Participant, "submitted")),
        ("admit", "submitted") => Ok((Governance::Host, "admitted")),
        ("supersede", "draft" | "running" | "submitted" | "admitted") => {
            Ok((Governance::Host, "superseded"))
        }
        ("accept" | "reject" | "challenge", _) => Err(verr(
            "attempt_verdict_unavailable",
            "acceptance, rejection, and challenge remain unavailable until VerifierChallenge",
        )),
        _ => Err(verr(
            "attempt_transition_invalid",
            format!("transition '{op}' is not admitted from '{from}'"),
        )),
    }
}

pub(crate) async fn handle_attempt_transition(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let op = match body.get("transition").and_then(Value::as_str) {
        Some(value) => value.to_string(),
        None => {
            return classify(verr(
                "attempt_transition_required",
                "transition is required",
            ))
        }
    };
    let fields = match validate_attempt_transition(&body, &op) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let prior = match load_attempt_strict(&state.data_dir, &id) {
        Ok(Some(value)) => value,
        Ok(None) => return classify(verr("attempt_not_found", format!("no Attempt '{id}'"))),
        Err(message) => return classify(verr("attempt_finding_registry_unreadable", message)),
    };
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    if let Err(error) = expected_revision(&body, revision) {
        return classify(error);
    }
    let subject_ref = s(&prior, "attempt_id", "");
    if op == "accept" {
        if let Err(error) = super::verifier_challenge_routes::refuse_acceptance_if_unresolved(
            &state.data_dir,
            &subject_ref,
        ) {
            return classify(error);
        }
    }
    let (governance, to) = match attempt_transition_contract(&op, &s(&prior, "status", "")) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let require_active_current = governance == Governance::Participant;
    let require_open_room = op != "supersede";
    let dependencies = match validate_attempt_coordinates(
        &state.data_dir,
        &prior,
        require_active_current,
        require_open_room,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let room_ref = s(&prior, "outcome_room_ref", "");
    let authority = if governance == Governance::Host {
        let value = s(&dependencies.room, "host_domain_ref", "");
        if value.is_empty() {
            return classify(verr(
                "attempt_host_authority_unavailable",
                "room host does not resolve",
            ));
        }
        value
    } else {
        s(&dependencies.participant, "participant_ref", "")
    };
    let mut result_snapshot = Value::Null;
    let mut delta_snapshots = json!([]);
    let delta_refs: Vec<String> = fields
        .get("outcome_delta_refs")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if op == "submit" {
        let result_ref = s(&fields, "work_result_ref", "");
        let result = match work_result_strict(&state.data_dir, &result_ref) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
        if let Err(error) = validate_work_result_for_attempt(&result, &prior) {
            return classify(error);
        }
        result_snapshot = work_result_coordinate(&result_ref, &result);
        delta_snapshots = match validate_outcome_deltas_for_attempt(
            &state.data_dir,
            &result,
            &prior,
            &delta_refs,
        ) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    }
    let mutation_payload = json!({
        "fields":fields,
        "work_result_coordinate":result_snapshot,
        "outcome_delta_coordinates":delta_snapshots,
    });
    let mutation_effect = effect("attempt", &op, revision, &mutation_payload, to);
    let authorized = match authorize(
        ATTEMPT_AUTHORITY,
        &body,
        governance,
        &room_ref,
        &authority,
        &subject_ref,
        &op,
        revision,
        &mutation_effect,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let _participant = participation::PARTICIPATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _work = work::FRONTIER_CLAIM_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _room = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _goal = super::goalrun_routes::GOAL_RUN_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _result = super::work_result_routes::DELTA_ADMISSION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _plane = ATTEMPT_FINDING_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let current = match load_attempt_strict(&state.data_dir, &id) {
        Ok(Some(value)) => value,
        Ok(None) => return classify(verr("attempt_not_found", "Attempt vanished")),
        Err(message) => return classify(verr("attempt_finding_registry_unreadable", message)),
    };
    if current != prior {
        return classify(verr(
            "attempt_finding_stale_revision",
            "Attempt changed during authorization",
        ));
    }
    if let Err(error) = validate_attempt_coordinates(
        &state.data_dir,
        &current,
        require_active_current,
        require_open_room,
    ) {
        return classify(error);
    }
    let refs = dependency_refs_from_attempt(&current);
    let mut reserved: Vec<&str> = refs.iter().map(String::as_str).collect();
    reserved.push(&subject_ref);
    let work_result_ref = s(&fields, "work_result_ref", "");
    if !work_result_ref.is_empty() {
        let result = match work_result_strict(&state.data_dir, &work_result_ref) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
        if let Err(error) = validate_work_result_for_attempt(&result, &current) {
            return classify(error);
        }
        if let Err(error) =
            validate_outcome_deltas_for_attempt(&state.data_dir, &result, &current, &delta_refs)
        {
            return classify(error);
        }
        reserved.push(&work_result_ref);
        reserved.extend(delta_refs.iter().map(String::as_str));
    }
    if let Err(error) = refuse_reserved(
        &state.data_dir,
        &reserved,
        "attempt_finding_mutation_in_flight",
        None,
    ) {
        return classify(error);
    }
    if let Err(error) = super::verifier_challenge_routes::refuse_external_mutation_if_reserved(
        &state.data_dir,
        &subject_ref,
        "attempt_finding_mutation_in_flight",
    ) {
        return classify(error);
    }
    let receipt_tail = fresh_tail(
        "amr_",
        &subject_ref,
        &op,
        revision,
        authorized.resolved_at_ms,
    );
    let receipt_ref = format!("receipt://{receipt_tail}");
    let final_attempt = match transition_attempt(
        &current,
        &op,
        to,
        &fields,
        &receipt_ref,
        authorized.resolved_at_ms,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let receipt = match build_receipt(
        &receipt_tail,
        ATTEMPT_RECEIPT_SCHEMA,
        "AttemptMutationReceipt",
        &subject_ref,
        &op,
        json!({"revision_before":revision,"revision_after":revision+1,"status_before":s(&current,"status",""),"status_after":to,"mutation_payload":mutation_payload}),
        reserved.iter().map(|value| json!(value)).collect(),
        &final_attempt,
        &authorized,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent_tail = fresh_tail(
        "afi_",
        &subject_ref,
        &op,
        revision,
        authorized.resolved_at_ms,
    );
    let intent = seal_intent(
        json!({
            "kind":"attempt_transition","governance":if governance==Governance::Host{"host"}else{"participant"},"op":op,
            "room_ref":refs[0],"frontier_ref":refs[1],"claim_ref":refs[2],"participant_ref":refs[3],
            "goal_run_ref":refs[4],"attempt_ref":Value::Null,"work_result_ref":if work_result_ref.is_empty(){Value::Null}else{json!(work_result_ref)},
            "outcome_delta_refs":delta_refs,"supersedes_ref":Value::Null,
            "required_authority_ref":authority,"subject_ref":subject_ref,"revision_before":revision,
            "receipt_tail":receipt_tail,"receipt":receipt,"prior_attempt":current,"final_attempt":final_attempt,
            "prior_finding":Value::Null,"final_finding":Value::Null,
        }),
        &intent_tail,
    );
    match persist_and_complete_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"attempt":final_attempt,"attempt_receipt":receipt})),
        ),
        Err(error) => classify(error),
    }
}

pub(crate) async fn handle_finding_create(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let declaration = match validate_finding_create(&body) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let room_ref = s(&declaration, "outcome_room_ref", "");
    let attempt_ref = s(&declaration, "attempt_ref", "");
    let result_ref = s(&declaration, "work_result_ref", "");
    let participant_ref = s(&declaration, "participant_ref", "");
    let supersedes_ref = declaration
        .get("supersedes_ref")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let dependencies =
        match resolve_finding_dependencies(&state.data_dir, &declaration, true, true, true) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    let coordinates = match finding_coordinates(
        &dependencies.attempt,
        &dependencies.result,
        dependencies.supersedes.as_ref(),
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let tail = deterministic_tail(
        "fnd_",
        &json!({"domain":"hypervisor.finding.identity.v1","declaration":declaration,"bound_coordinates":coordinates}),
    );
    let subject_ref = format!("finding://{tail}");
    let authority = s(&dependencies.participant, "participant_ref", "");
    let mutation_effect = effect(
        "finding",
        "create",
        0,
        &json!({"declaration":declaration,"bound_coordinates":coordinates}),
        "proposed",
    );
    let authorized = match authorize(
        FINDING_AUTHORITY,
        &body,
        Governance::Participant,
        &room_ref,
        &authority,
        &subject_ref,
        "create",
        0,
        &mutation_effect,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let _participant = participation::PARTICIPATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _work = work::FRONTIER_CLAIM_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _room = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _goal = super::goalrun_routes::GOAL_RUN_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _result = super::work_result_routes::DELTA_ADMISSION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _plane = ATTEMPT_FINDING_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Err(error) =
        resolve_finding_dependencies(&state.data_dir, &declaration, true, true, true)
    {
        return classify(error);
    }
    let mut reserved = vec![
        subject_ref.as_str(),
        room_ref.as_str(),
        attempt_ref.as_str(),
        result_ref.as_str(),
        participant_ref.as_str(),
    ];
    if !supersedes_ref.is_empty() {
        reserved.push(supersedes_ref.as_str());
    }
    if let Err(error) = refuse_reserved(
        &state.data_dir,
        &reserved,
        "attempt_finding_mutation_in_flight",
        None,
    ) {
        return classify(error);
    }
    match load_finding_strict(&state.data_dir, &tail) {
        Ok(None) => {}
        Ok(Some(_)) => {
            return classify(verr(
                "finding_conflict",
                format!("canonical Finding '{subject_ref}' already exists"),
            ))
        }
        Err(message) => return classify(verr("attempt_finding_registry_unreadable", message)),
    }
    let receipt_tail = fresh_tail("fmr_", &subject_ref, "create", 0, authorized.resolved_at_ms);
    let receipt_ref = format!("receipt://{receipt_tail}");
    let final_finding = match seal_finding(
        &declaration,
        &coordinates,
        &tail,
        &receipt_ref,
        authorized.resolved_at_ms,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let receipt = match build_receipt(
        &receipt_tail,
        FINDING_RECEIPT_SCHEMA,
        "FindingMutationReceipt",
        &subject_ref,
        "create",
        json!({"revision_before":0,"revision_after":1,"status_after":"proposed","bound_coordinates":coordinates,"uncertainty":declaration.get("confidence_or_uncertainty")}),
        reserved.iter().map(|value| json!(value)).collect(),
        &final_finding,
        &authorized,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent_tail = fresh_tail("afi_", &subject_ref, "create", 0, authorized.resolved_at_ms);
    let intent = seal_intent(
        json!({
            "kind":"finding_create","governance":"participant","op":"create",
            "room_ref":room_ref,"frontier_ref":Value::Null,"claim_ref":Value::Null,
            "participant_ref":participant_ref,"goal_run_ref":Value::Null,"attempt_ref":attempt_ref,
            "work_result_ref":result_ref,"outcome_delta_refs":[],
            "supersedes_ref":if supersedes_ref.is_empty(){Value::Null}else{json!(supersedes_ref)},
            "required_authority_ref":authority,"subject_ref":subject_ref,
            "revision_before":0,"receipt_tail":receipt_tail,"receipt":receipt,
            "prior_attempt":Value::Null,"final_attempt":Value::Null,
            "prior_finding":Value::Null,"final_finding":final_finding,
        }),
        &intent_tail,
    );
    match persist_and_complete_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({"finding":final_finding,"finding_receipt":receipt})),
        ),
        Err(error) => classify(error),
    }
}

fn finding_transition_contract(op: &str, from: &str) -> Result<&'static str, VErr> {
    match (op, from) {
        ("admit", "proposed") => Ok("admitted"),
        ("supersede", "proposed" | "admitted") => Ok("superseded"),
        ("archive", "admitted" | "superseded") => Ok("archived"),
        ("accept" | "reject" | "contradict" | "dispute", _) => Err(verr(
            "finding_verdict_unavailable",
            "acceptance, contradiction, rejection, and dispute remain unavailable until VerifierChallenge",
        )),
        _ => Err(verr(
            "finding_transition_invalid",
            format!("transition '{op}' is not admitted from '{from}'"),
        )),
    }
}

pub(crate) async fn handle_finding_transition(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = reject_sensitive(&body, "").and_then(|_| {
        reject_unknown(
            &body,
            &["transition", "expected_revision", "wallet_approval_grant"],
        )
    }) {
        return classify(error);
    }
    let op = match body.get("transition").and_then(Value::as_str) {
        Some(value) => value.to_string(),
        None => {
            return classify(verr(
                "finding_transition_required",
                "transition is required",
            ))
        }
    };
    let prior = match load_finding_strict(&state.data_dir, &id) {
        Ok(Some(value)) => value,
        Ok(None) => return classify(verr("finding_not_found", format!("no Finding '{id}'"))),
        Err(message) => return classify(verr("attempt_finding_registry_unreadable", message)),
    };
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    if let Err(error) = expected_revision(&body, revision) {
        return classify(error);
    }
    let subject_ref = s(&prior, "finding_id", "");
    if op == "accept" {
        if let Err(error) = super::verifier_challenge_routes::refuse_acceptance_if_unresolved(
            &state.data_dir,
            &subject_ref,
        ) {
            return classify(error);
        }
    }
    let to = match finding_transition_contract(&op, &s(&prior, "status", "")) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let room_ref = s(&prior, "outcome_room_ref", "");
    let dependencies =
        match resolve_finding_dependencies(&state.data_dir, &prior, false, false, false) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    let host = s(&dependencies.room, "host_domain_ref", "");
    if host.is_empty() {
        return classify(verr(
            "finding_host_authority_unavailable",
            "room host does not resolve",
        ));
    }
    let mutation_effect = effect(
        "finding",
        &op,
        revision,
        &json!({"status_before":s(&prior,"status","")}),
        to,
    );
    let authorized = match authorize(
        FINDING_AUTHORITY,
        &body,
        Governance::Host,
        &room_ref,
        &host,
        &subject_ref,
        &op,
        revision,
        &mutation_effect,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let _participant = participation::PARTICIPATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _work = work::FRONTIER_CLAIM_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _room = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _goal = super::goalrun_routes::GOAL_RUN_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _result = super::work_result_routes::DELTA_ADMISSION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _plane = ATTEMPT_FINDING_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let current = match load_finding_strict(&state.data_dir, &id) {
        Ok(Some(value)) => value,
        Ok(None) => return classify(verr("finding_not_found", "Finding vanished")),
        Err(message) => return classify(verr("attempt_finding_registry_unreadable", message)),
    };
    if current != prior {
        return classify(verr(
            "attempt_finding_stale_revision",
            "Finding changed during authorization",
        ));
    }
    if let Err(error) = resolve_finding_dependencies(&state.data_dir, &current, false, false, false)
    {
        return classify(error);
    }
    let attempt_ref = s(&current, "attempt_ref", "");
    let result_ref = s(&current, "work_result_ref", "");
    let participant_ref = s(&current, "participant_ref", "");
    let supersedes_ref = current
        .get("supersedes_ref")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut reserved = vec![
        subject_ref.as_str(),
        room_ref.as_str(),
        attempt_ref.as_str(),
        result_ref.as_str(),
        participant_ref.as_str(),
    ];
    if !supersedes_ref.is_empty() {
        reserved.push(supersedes_ref.as_str());
    }
    if let Err(error) = refuse_reserved(
        &state.data_dir,
        &reserved,
        "attempt_finding_mutation_in_flight",
        None,
    ) {
        return classify(error);
    }
    if let Err(error) = super::verifier_challenge_routes::refuse_external_mutation_if_reserved(
        &state.data_dir,
        &subject_ref,
        "attempt_finding_mutation_in_flight",
    ) {
        return classify(error);
    }
    let receipt_tail = fresh_tail(
        "fmr_",
        &subject_ref,
        &op,
        revision,
        authorized.resolved_at_ms,
    );
    let receipt_ref = format!("receipt://{receipt_tail}");
    let final_finding =
        match transition_finding(&current, &op, to, &receipt_ref, authorized.resolved_at_ms) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
    let receipt = match build_receipt(
        &receipt_tail,
        FINDING_RECEIPT_SCHEMA,
        "FindingMutationReceipt",
        &subject_ref,
        &op,
        json!({"revision_before":revision,"revision_after":revision+1,"status_before":s(&current,"status",""),"status_after":to,"bound_coordinates":current.get("bound_coordinates")}),
        reserved.iter().map(|value| json!(value)).collect(),
        &final_finding,
        &authorized,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent_tail = fresh_tail(
        "afi_",
        &subject_ref,
        &op,
        revision,
        authorized.resolved_at_ms,
    );
    let intent = seal_intent(
        json!({
            "kind":"finding_transition","governance":"host","op":op,"room_ref":room_ref,
            "frontier_ref":Value::Null,"claim_ref":Value::Null,"participant_ref":participant_ref,
            "goal_run_ref":Value::Null,"attempt_ref":attempt_ref,"work_result_ref":result_ref,
            "outcome_delta_refs":[],
            "supersedes_ref":if supersedes_ref.is_empty(){Value::Null}else{json!(supersedes_ref)},
            "required_authority_ref":host,"subject_ref":subject_ref,"revision_before":revision,
            "receipt_tail":receipt_tail,"receipt":receipt,"prior_attempt":Value::Null,
            "final_attempt":Value::Null,"prior_finding":current,"final_finding":final_finding,
        }),
        &intent_tail,
    );
    match persist_and_complete_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"finding":final_finding,"finding_receipt":receipt})),
        ),
        Err(error) => classify(error),
    }
}

fn ensure_read_converged(data_dir: &str) -> Result<(), VErr> {
    let intents = scan_intents(data_dir)
        .map_err(|message| verr("attempt_finding_intent_unreadable", message))?;
    if intents.is_empty() {
        Ok(())
    } else {
        Err(verr(
            "attempt_finding_pending_convergence",
            format!(
                "{} Attempt/Finding transaction(s) await authenticated convergence",
                intents.len()
            ),
        ))
    }
}

async fn list(
    state: Arc<DaemonState>,
    query: HashMap<String, String>,
    attempts: bool,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = ensure_read_converged(&state.data_dir) {
        return classify(error);
    }
    let (family, canonical) = if attempts {
        (ATTEMPT_DIR, canonical_attempt_tail as fn(&str) -> bool)
    } else {
        (FINDING_DIR, canonical_finding_tail as fn(&str) -> bool)
    };
    let mut records = match scan_records(&state.data_dir, family, canonical) {
        Ok(values) => values
            .into_iter()
            .map(|(_, value)| value)
            .collect::<Vec<_>>(),
        Err(message) => return classify(verr("attempt_finding_registry_unreadable", message)),
    };
    records.retain(|record| {
        query
            .get("room")
            .map(|value| s(record, "outcome_room_ref", "") == *value)
            .unwrap_or(true)
            && query
                .get("status")
                .map(|value| s(record, "status", "") == *value)
                .unwrap_or(true)
            && query
                .get("participant")
                .map(|value| s(record, "participant_ref", "") == *value)
                .unwrap_or(true)
            && query
                .get("attempt")
                .map(|value| s(record, "attempt_ref", "") == *value)
                .unwrap_or(true)
    });
    records.truncate(LIST_MAX);
    (
        StatusCode::OK,
        Json(if attempts {
            json!({"attempts":records,"runtimeTruthSource":"daemon-runtime"})
        } else {
            json!({"findings":records,"runtimeTruthSource":"daemon-runtime"})
        }),
    )
}

pub(crate) async fn handle_attempt_list(
    State(state): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    list(state, query, true).await
}

pub(crate) async fn handle_finding_list(
    State(state): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    list(state, query, false).await
}

pub(crate) async fn handle_attempt_get(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = ensure_read_converged(&state.data_dir) {
        return classify(error);
    }
    match load_attempt_strict(&state.data_dir, &id) {
        Ok(Some(value)) => (StatusCode::OK, Json(json!({"attempt":value}))),
        Ok(None) => classify(verr("attempt_not_found", format!("no Attempt '{id}'"))),
        Err(message) => classify(verr("attempt_finding_registry_unreadable", message)),
    }
}

pub(crate) async fn handle_finding_get(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = ensure_read_converged(&state.data_dir) {
        return classify(error);
    }
    match load_finding_strict(&state.data_dir, &id) {
        Ok(Some(value)) => (StatusCode::OK, Json(json!({"finding":value}))),
        Ok(None) => classify(verr("finding_not_found", format!("no Finding '{id}'"))),
        Err(message) => classify(verr("attempt_finding_registry_unreadable", message)),
    }
}

async fn overview(state: Arc<DaemonState>, attempts: bool) -> (StatusCode, Json<Value>) {
    let (family, canonical) = if attempts {
        (ATTEMPT_DIR, canonical_attempt_tail as fn(&str) -> bool)
    } else {
        (FINDING_DIR, canonical_finding_tail as fn(&str) -> bool)
    };
    let count = match scan_records(&state.data_dir, family, canonical) {
        Ok(values) => values.len(),
        Err(message) => return classify(verr("attempt_finding_registry_unreadable", message)),
    };
    let pending = match scan_intents(&state.data_dir) {
        Ok(values) => values.len(),
        Err(message) => return classify(verr("attempt_finding_intent_unreadable", message)),
    };
    (
        StatusCode::OK,
        Json(if attempts {
            json!({
                "schema_version":ATTEMPT_SCHEMA,"count":count,"pending_convergence_count":pending,
                "statuses":ATTEMPT_STATUSES,"outcome_classes":ATTEMPT_OUTCOMES,
                "coordination_topology":"hosted_admission","federated_admission":"typed_unavailable",
                "execution_authority":"not_provided","acceptance_authority":"not_provided",
                "authority":governed::decision_authority_posture(ATTEMPT_AUTHORITY),"runtimeTruthSource":"daemon-runtime"
            })
        } else {
            json!({
                "schema_version":FINDING_SCHEMA,"count":count,"pending_convergence_count":pending,
                "statuses":FINDING_STATUSES,"kinds":FINDING_KINDS,
                "coordination_topology":"hosted_admission","federated_admission":"typed_unavailable",
                "verdict_authority":"not_provided","acceptance_authority":"not_provided",
                "authority":governed::decision_authority_posture(FINDING_AUTHORITY),"runtimeTruthSource":"daemon-runtime"
            })
        }),
    )
}

pub(crate) async fn handle_attempt_overview(
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    overview(state, true).await
}

pub(crate) async fn handle_finding_overview(
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    overview(state, false).await
}

fn validate_replay_intent(intent: &Value) -> Result<(AuthorityContract, Governance), String> {
    let kind = intent
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks kind".to_string())?;
    let contract = if kind.starts_with("attempt_") {
        ATTEMPT_AUTHORITY
    } else if kind.starts_with("finding_") {
        FINDING_AUTHORITY
    } else {
        return Err(format!("unknown intent kind '{kind}'"));
    };
    let governance = if intent.get("governance").and_then(Value::as_str) == Some("host") {
        Governance::Host
    } else {
        Governance::Participant
    };
    validate_intent_exact(intent, kind, contract)?;
    Ok((contract, governance))
}

fn sealed_authorized(receipt: &Value) -> Result<AuthorizedDecision, String> {
    Ok(AuthorizedDecision {
        evidence: governed::sealed_evidence(receipt),
        resolved_at_ms: receipt
            .get("authority_resolved_at_ms")
            .and_then(Value::as_u64)
            .ok_or_else(|| "receipt lacks authority_resolved_at_ms".to_string())?,
    })
}

fn attempt_declaration(record: &Value) -> Value {
    let mut declaration = record.clone();
    if let Some(object) = declaration.as_object_mut() {
        for field in [
            "schema_version",
            "attempt_id",
            "bound_coordinates",
            "outcome_class",
            "work_result_ref",
            "outcome_delta_refs",
            "artifact_evidence_and_receipt_refs",
            "verifier_refs",
            "reproduction_state",
            "status",
            "revision",
            "created_at",
            "created_at_ms",
            "updated_at",
            "updated_at_ms",
            "admission_receipt_ref",
            "admission_and_replay_refs",
            "status_history",
            "runtimeTruthSource",
        ] {
            object.remove(field);
        }
    }
    declaration
}

fn finding_declaration(record: &Value) -> Value {
    let mut declaration = record.clone();
    if let Some(object) = declaration.as_object_mut() {
        for field in [
            "schema_version",
            "finding_id",
            "bound_coordinates",
            "transaction_time",
            "status",
            "revision",
            "created_at",
            "created_at_ms",
            "updated_at",
            "updated_at_ms",
            "admission_receipt_ref",
            "admission_and_replay_refs",
            "status_history",
            "runtimeTruthSource",
        ] {
            object.remove(field);
        }
    }
    declaration
}

fn require_intent_ref(intent: &Value, field: &str, expected: Option<String>) -> Result<(), String> {
    let actual = intent.get(field).unwrap_or(&Value::Null);
    let matches = match expected {
        Some(reference) => actual.as_str() == Some(reference.as_str()),
        None => actual.is_null(),
    };
    if matches {
        Ok(())
    } else {
        Err(format!(
            "intent field '{field}' differs from its reconstructed aggregate coordinate"
        ))
    }
}

fn require_intent_ref_list(intent: &Value, field: &str, expected: &[String]) -> Result<(), String> {
    let actual: Vec<&str> = intent
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("intent field '{field}' is not a ref list"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| format!("intent field '{field}' contains a non-ref"))
        })
        .collect::<Result<_, _>>()?;
    if actual == expected.iter().map(String::as_str).collect::<Vec<_>>() {
        Ok(())
    } else {
        Err(format!(
            "intent field '{field}' differs from its reconstructed aggregate coordinates"
        ))
    }
}

fn validate_attempt_intent_refs(
    intent: &Value,
    attempt: &Value,
    work_result_ref: Option<&str>,
    outcome_delta_refs: &[String],
) -> Result<(), String> {
    require_intent_ref(intent, "room_ref", Some(s(attempt, "outcome_room_ref", "")))?;
    require_intent_ref(
        intent,
        "frontier_ref",
        Some(s(attempt, "frontier_item_ref", "")),
    )?;
    require_intent_ref(intent, "claim_ref", Some(s(attempt, "work_claim_ref", "")))?;
    require_intent_ref(
        intent,
        "participant_ref",
        Some(s(attempt, "participant_ref", "")),
    )?;
    require_intent_ref(intent, "goal_run_ref", Some(s(attempt, "goal_run_ref", "")))?;
    require_intent_ref(intent, "attempt_ref", None)?;
    require_intent_ref(
        intent,
        "work_result_ref",
        work_result_ref.map(ToOwned::to_owned),
    )?;
    require_intent_ref(intent, "supersedes_ref", None)?;
    require_intent_ref_list(intent, "outcome_delta_refs", outcome_delta_refs)
}

fn validate_finding_intent_refs(intent: &Value, finding: &Value) -> Result<(), String> {
    require_intent_ref(intent, "room_ref", Some(s(finding, "outcome_room_ref", "")))?;
    require_intent_ref(intent, "frontier_ref", None)?;
    require_intent_ref(intent, "claim_ref", None)?;
    require_intent_ref(
        intent,
        "participant_ref",
        Some(s(finding, "participant_ref", "")),
    )?;
    require_intent_ref(intent, "goal_run_ref", None)?;
    require_intent_ref(intent, "attempt_ref", Some(s(finding, "attempt_ref", "")))?;
    require_intent_ref(
        intent,
        "work_result_ref",
        Some(s(finding, "work_result_ref", "")),
    )?;
    require_intent_ref(
        intent,
        "supersedes_ref",
        finding
            .get("supersedes_ref")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    )?;
    require_intent_ref_list(intent, "outcome_delta_refs", &[])
}

fn validate_intent_exact(
    intent: &Value,
    kind: &str,
    contract: AuthorityContract,
) -> Result<(), String> {
    let receipt_tail = intent
        .get("receipt_tail")
        .and_then(Value::as_str)
        .filter(|tail| canonical_receipt_tail(tail))
        .ok_or_else(|| "intent receipt tail is noncanonical".to_string())?;
    let receipt = intent
        .get("receipt")
        .ok_or_else(|| "intent lacks receipt".to_string())?;
    if receipt.get("receipt_ref").and_then(Value::as_str)
        != Some(format!("receipt://{receipt_tail}").as_str())
    {
        return Err("receipt identity differs from its storage key".into());
    }
    let authorized = sealed_authorized(receipt)?;
    let op = intent
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks op".to_string())?;
    let subject_ref = intent
        .get("subject_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks subject_ref".to_string())?;
    let revision = intent
        .get("revision_before")
        .and_then(Value::as_u64)
        .ok_or_else(|| "intent lacks revision_before".to_string())?;
    let room_ref = intent
        .get("room_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks room_ref".to_string())?;
    let receipt_ref = format!("receipt://{receipt_tail}");

    let (expected_effect, expected_receipt) = match kind {
        "attempt_create" => {
            if intent.get("governance").and_then(Value::as_str) != Some("participant")
                || op != "create"
            {
                return Err("Attempt create intent governance/op does not reconstruct".into());
            }
            if revision != 0
                || intent
                    .get("prior_attempt")
                    .is_some_and(|value| !value.is_null())
            {
                return Err("Attempt create intent carries a prior/revision".into());
            }
            let final_attempt = intent
                .get("final_attempt")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "Attempt create intent lacks successor".to_string())?;
            if final_attempt.get("attempt_id").and_then(Value::as_str) != Some(subject_ref) {
                return Err("Attempt successor identity differs from subject_ref".into());
            }
            validate_attempt_intent_refs(intent, final_attempt, None, &[])?;
            let declaration = attempt_declaration(final_attempt);
            let coordinates = final_attempt
                .get("bound_coordinates")
                .cloned()
                .ok_or_else(|| "Attempt successor lacks bound coordinates".to_string())?;
            let expected_tail = deterministic_tail(
                "att_",
                &json!({"domain":"hypervisor.attempt.identity.v1","declaration":declaration,"bound_coordinates":coordinates}),
            );
            if subject_ref != format!("attempt://{expected_tail}") {
                return Err(
                    "Attempt identity does not reconstruct from declaration coordinates".into(),
                );
            }
            let expected_final = seal_attempt(
                &declaration,
                &coordinates,
                &expected_tail,
                &receipt_ref,
                authorized.resolved_at_ms,
            )
            .map_err(|(_, message)| message)?;
            if expected_final != *final_attempt {
                return Err("Attempt create successor does not reconstruct byte-exactly".into());
            }
            let expected_effect = effect(
                "attempt",
                "create",
                0,
                &json!({"declaration":declaration,"bound_coordinates":coordinates}),
                "draft",
            );
            let refs = dependency_refs_from_attempt(final_attempt);
            let expected_receipt = build_receipt(
                receipt_tail,
                ATTEMPT_RECEIPT_SCHEMA,
                "AttemptMutationReceipt",
                subject_ref,
                "create",
                json!({"revision_before":0,"revision_after":1,"status_after":"draft","bound_coordinates":coordinates}),
                refs.iter().map(|value| json!(value)).collect(),
                final_attempt,
                &authorized,
            )
            .map_err(|(_, message)| message)?;
            (expected_effect, expected_receipt)
        }
        "attempt_transition" => {
            let prior = intent
                .get("prior_attempt")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "Attempt transition lacks prior".to_string())?;
            let final_attempt = intent
                .get("final_attempt")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "Attempt transition lacks successor".to_string())?;
            if prior.get("attempt_id").and_then(Value::as_str) != Some(subject_ref)
                || prior.get("revision").and_then(Value::as_u64) != Some(revision)
            {
                return Err("Attempt transition prior coordinates differ".into());
            }
            let (governance, to) = attempt_transition_contract(op, &s(prior, "status", ""))
                .map_err(|(_, message)| message)?;
            let sealed_governance = intent.get("governance").and_then(Value::as_str);
            if sealed_governance
                != Some(if governance == Governance::Host {
                    "host"
                } else {
                    "participant"
                })
            {
                return Err("Attempt transition governance does not reconstruct".into());
            }
            let facts = receipt
                .get("bound_facts")
                .ok_or_else(|| "Attempt transition receipt lacks bound_facts".to_string())?;
            let payload = facts
                .get("mutation_payload")
                .cloned()
                .ok_or_else(|| "Attempt transition receipt lacks mutation payload".to_string())?;
            let fields = payload.get("fields").cloned().unwrap_or(Value::Null);
            let work_result_ref = fields
                .get("work_result_ref")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty());
            let outcome_delta_refs: Vec<String> = fields
                .get("outcome_delta_refs")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            validate_attempt_intent_refs(intent, prior, work_result_ref, &outcome_delta_refs)?;
            let expected_final = transition_attempt(
                prior,
                op,
                to,
                &fields,
                &receipt_ref,
                authorized.resolved_at_ms,
            )
            .map_err(|(_, message)| message)?;
            if expected_final != *final_attempt {
                return Err(
                    "Attempt transition successor does not reconstruct byte-exactly".into(),
                );
            }
            let expected_effect = effect("attempt", op, revision, &payload, to);
            let mut refs: Vec<String> = dependency_refs_from_attempt(prior).into_iter().collect();
            refs.push(subject_ref.to_string());
            if let Some(result_ref) = payload
                .pointer("/fields/work_result_ref")
                .and_then(Value::as_str)
            {
                refs.push(result_ref.to_string());
            }
            refs.extend(outcome_delta_refs);
            let expected_receipt = build_receipt(
                receipt_tail,
                ATTEMPT_RECEIPT_SCHEMA,
                "AttemptMutationReceipt",
                subject_ref,
                op,
                json!({"revision_before":revision,"revision_after":revision+1,"status_before":s(prior,"status",""),"status_after":to,"mutation_payload":payload}),
                refs.iter().map(|value| json!(value)).collect(),
                final_attempt,
                &authorized,
            )
            .map_err(|(_, message)| message)?;
            (expected_effect, expected_receipt)
        }
        "finding_create" => {
            if intent.get("governance").and_then(Value::as_str) != Some("participant")
                || op != "create"
            {
                return Err("Finding create intent governance/op does not reconstruct".into());
            }
            if revision != 0
                || intent
                    .get("prior_finding")
                    .is_some_and(|value| !value.is_null())
            {
                return Err("Finding create intent carries a prior/revision".into());
            }
            let final_finding = intent
                .get("final_finding")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "Finding create intent lacks successor".to_string())?;
            if final_finding.get("finding_id").and_then(Value::as_str) != Some(subject_ref) {
                return Err("Finding successor identity differs from subject_ref".into());
            }
            validate_finding_intent_refs(intent, final_finding)?;
            let declaration = finding_declaration(final_finding);
            let coordinates = final_finding
                .get("bound_coordinates")
                .cloned()
                .ok_or_else(|| "Finding successor lacks bound coordinates".to_string())?;
            let expected_tail = deterministic_tail(
                "fnd_",
                &json!({"domain":"hypervisor.finding.identity.v1","declaration":declaration,"bound_coordinates":coordinates}),
            );
            if subject_ref != format!("finding://{expected_tail}") {
                return Err(
                    "Finding identity does not reconstruct from declaration coordinates".into(),
                );
            }
            let expected_final = seal_finding(
                &declaration,
                &coordinates,
                &expected_tail,
                &receipt_ref,
                authorized.resolved_at_ms,
            )
            .map_err(|(_, message)| message)?;
            if expected_final != *final_finding {
                return Err("Finding create successor does not reconstruct byte-exactly".into());
            }
            let expected_effect = effect(
                "finding",
                "create",
                0,
                &json!({"declaration":declaration,"bound_coordinates":coordinates}),
                "proposed",
            );
            let mut refs = vec![
                subject_ref.to_string(),
                room_ref.to_string(),
                s(final_finding, "attempt_ref", ""),
                s(final_finding, "work_result_ref", ""),
                s(final_finding, "participant_ref", ""),
            ];
            if let Some(supersedes_ref) =
                final_finding.get("supersedes_ref").and_then(Value::as_str)
            {
                refs.push(supersedes_ref.to_string());
            }
            let expected_receipt = build_receipt(
                receipt_tail,
                FINDING_RECEIPT_SCHEMA,
                "FindingMutationReceipt",
                subject_ref,
                "create",
                json!({"revision_before":0,"revision_after":1,"status_after":"proposed","bound_coordinates":coordinates,"uncertainty":declaration.get("confidence_or_uncertainty")}),
                refs.iter().map(|value| json!(value)).collect(),
                final_finding,
                &authorized,
            )
            .map_err(|(_, message)| message)?;
            (expected_effect, expected_receipt)
        }
        "finding_transition" => {
            if intent.get("governance").and_then(Value::as_str) != Some("host") {
                return Err("Finding transition governance does not reconstruct".into());
            }
            let prior = intent
                .get("prior_finding")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "Finding transition lacks prior".to_string())?;
            let final_finding = intent
                .get("final_finding")
                .filter(|value| !value.is_null())
                .ok_or_else(|| "Finding transition lacks successor".to_string())?;
            if prior.get("finding_id").and_then(Value::as_str) != Some(subject_ref)
                || prior.get("revision").and_then(Value::as_u64) != Some(revision)
            {
                return Err("Finding transition prior coordinates differ".into());
            }
            validate_finding_intent_refs(intent, prior)?;
            let to = finding_transition_contract(op, &s(prior, "status", ""))
                .map_err(|(_, message)| message)?;
            let expected_final =
                transition_finding(prior, op, to, &receipt_ref, authorized.resolved_at_ms)
                    .map_err(|(_, message)| message)?;
            if expected_final != *final_finding {
                return Err(
                    "Finding transition successor does not reconstruct byte-exactly".into(),
                );
            }
            let payload = json!({"status_before":s(prior,"status","")});
            let expected_effect = effect("finding", op, revision, &payload, to);
            let mut refs = vec![
                subject_ref.to_string(),
                room_ref.to_string(),
                s(prior, "attempt_ref", ""),
                s(prior, "work_result_ref", ""),
                s(prior, "participant_ref", ""),
            ];
            if let Some(supersedes_ref) = prior.get("supersedes_ref").and_then(Value::as_str) {
                refs.push(supersedes_ref.to_string());
            }
            let expected_receipt = build_receipt(
                receipt_tail,
                FINDING_RECEIPT_SCHEMA,
                "FindingMutationReceipt",
                subject_ref,
                op,
                json!({"revision_before":revision,"revision_after":revision+1,"status_before":s(prior,"status",""),"status_after":to,"bound_coordinates":prior.get("bound_coordinates")}),
                refs.iter().map(|value| json!(value)).collect(),
                final_finding,
                &authorized,
            )
            .map_err(|(_, message)| message)?;
            (expected_effect, expected_receipt)
        }
        _ => return Err(format!("unknown intent kind '{kind}'")),
    };
    governed::validate_sealed_effect(contract, receipt, &expected_effect)?;
    if expected_receipt != *receipt {
        return Err("mutation receipt does not reconstruct byte-exactly".into());
    }
    Ok(())
}

fn validate_replay_coordinates(data_dir: &str, intent: &Value) -> Result<(), VErr> {
    let kind = s(intent, "kind", "");
    if kind.starts_with("attempt_") {
        let attempt = if kind == "attempt_create" {
            intent.get("final_attempt")
        } else {
            intent.get("prior_attempt")
        }
        .filter(|value| !value.is_null())
        .ok_or_else(|| {
            verr(
                "attempt_finding_intent_unreadable",
                "Attempt intent lacks coordinate source",
            )
        })?;
        let participant_governed =
            intent.get("governance").and_then(Value::as_str) == Some("participant");
        let require_active_current = kind == "attempt_create" || participant_governed;
        let require_open_room = s(intent, "op", "") != "supersede";
        validate_attempt_coordinates(data_dir, attempt, require_active_current, require_open_room)?;
        let result_ref = s(intent, "work_result_ref", "");
        if !result_ref.is_empty() {
            let result = work_result_strict(data_dir, &result_ref)?;
            validate_work_result_for_attempt(&result, attempt)?;
            let delta_refs: Vec<String> = intent
                .get("outcome_delta_refs")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            validate_outcome_deltas_for_attempt(data_dir, &result, attempt, &delta_refs)?;
        }
    } else if kind.starts_with("finding_") {
        let finding = if kind == "finding_create" {
            intent.get("final_finding")
        } else {
            intent.get("prior_finding")
        }
        .filter(|value| !value.is_null())
        .ok_or_else(|| {
            verr(
                "attempt_finding_intent_unreadable",
                "Finding intent lacks coordinate source",
            )
        })?;
        resolve_finding_dependencies(
            data_dir,
            finding,
            kind == "finding_create",
            kind == "finding_create",
            kind == "finding_create",
        )?;
    }
    Ok(())
}

pub(crate) async fn complete_governed_attempt_finding_intents(data_dir: &str, max_intents: usize) {
    let intents = match scan_intents(data_dir) {
        Ok(values) => values,
        Err(message) => {
            eprintln!("Attempt/Finding completer: intent scan failed ({message})");
            return;
        }
    };
    for (tail, intent) in intents.into_iter().take(max_intents) {
        let (contract, governance) = match validate_replay_intent(&intent) {
            Ok(value) => value,
            Err(message) => {
                eprintln!("Attempt/Finding completer: '{tail}' invalid ({message}); retained");
                continue;
            }
        };
        let room_ref = s(&intent, "room_ref", "");
        let participant_ref = s(&intent, "participant_ref", "");
        let required_authority = if governance == Governance::Host {
            match rooms::resolve_room_host(data_dir, &room_ref) {
                Some(value) => value,
                None => {
                    eprintln!(
                        "Attempt/Finding completer: '{tail}' host no longer resolves; retained"
                    );
                    continue;
                }
            }
        } else {
            match participant_strict(data_dir, &participant_ref) {
                Ok(value) => s(&value, "participant_ref", ""),
                Err((_, message)) => {
                    eprintln!("Attempt/Finding completer: '{tail}' participant refused ({message}); retained");
                    continue;
                }
            }
        };
        if intent.get("required_authority_ref").and_then(Value::as_str)
            != Some(required_authority.as_str())
        {
            eprintln!("Attempt/Finding completer: '{tail}' authority owner changed; retained");
            continue;
        }
        if let Err((_, message)) = validate_replay_coordinates(data_dir, &intent) {
            eprintln!(
                "Attempt/Finding completer: '{tail}' coordinates refused ({message}); retained"
            );
            continue;
        }
        let receipt = intent.get("receipt").unwrap_or(&Value::Null);
        let op = s(&intent, "op", "");
        let subject_ref = s(&intent, "subject_ref", "");
        let revision = intent
            .get("revision_before")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let effect = receipt.get("authorized_effect").unwrap_or(&Value::Null);
        if let Err(message) = governed::reauthorize_sealed_receipt(
            contract,
            receipt,
            governance,
            &room_ref,
            &required_authority,
            &subject_ref,
            &op,
            revision,
            effect,
        )
        .await
        {
            eprintln!(
                "Attempt/Finding completer: '{tail}' authority refused ({message}); retained"
            );
            continue;
        }
        let _participant = participation::PARTICIPATION_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _work = work::FRONTIER_CLAIM_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _room = rooms::ROOM_MUTATION_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _goal = super::goalrun_routes::GOAL_RUN_MUTATION_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _result = super::work_result_routes::DELTA_ADMISSION_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _plane = ATTEMPT_FINDING_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Err((_, message)) = validate_replay_coordinates(data_dir, &intent) {
            eprintln!("Attempt/Finding completer: '{tail}' coordinates changed during authorization ({message}); retained");
            continue;
        }
        if let Err((_, message)) = complete_intent_locked(data_dir, &tail, &intent) {
            eprintln!(
                "Attempt/Finding completer: '{tail}' convergence failed ({message}); retained"
            );
        }
    }
}

/// Room close refuses while nonterminal Attempts, proposed/admitted Findings, or pending
/// Attempt/Finding intents remain in the room. Superseded/archived provenance remains durable.
pub(crate) fn refuse_room_close_if_blocked_locked(
    data_dir: &str,
    room_ref: &str,
) -> Result<(), VErr> {
    let attempts = scan_records(data_dir, ATTEMPT_DIR, canonical_attempt_tail)
        .map_err(|message| verr("outcome_room_attempt_registry_unreadable", message))?
        .into_iter()
        .filter(|(_, record)| {
            s(record, "outcome_room_ref", "") == room_ref
                && !matches!(s(record, "status", "").as_str(), "admitted" | "superseded")
        })
        .count();
    let findings = scan_records(data_dir, FINDING_DIR, canonical_finding_tail)
        .map_err(|message| verr("outcome_room_finding_registry_unreadable", message))?
        .into_iter()
        .filter(|(_, record)| {
            s(record, "outcome_room_ref", "") == room_ref
                && matches!(s(record, "status", "").as_str(), "proposed" | "admitted")
        })
        .count();
    let pending = scan_intents(data_dir)
        .map_err(|message| verr("outcome_room_attempt_finding_intent_unreadable", message))?
        .into_iter()
        .filter(|(_, intent)| s(intent, "room_ref", "") == room_ref)
        .count();
    if attempts + findings + pending == 0 {
        Ok(())
    } else {
        Err(verr(
            "outcome_room_close_blocked_attempts_findings",
            format!("room has {attempts} unresolved Attempt(s), {findings} live Finding(s), and {pending} pending provenance transaction(s)"),
        ))
    }
}

#[cfg(test)]
mod attempt_finding_tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ioi-attempt-finding-{tag}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn declaration() -> Value {
        json!({
            "outcome_room_ref":"outcome-room://or_ab",
            "frontier_item_ref":format!("frontier://wfi_{}", "1".repeat(64)),
            "work_claim_ref":format!("work-claim://wcl_{}", "2".repeat(64)),
            "participant_ref":"participant-lease://rpl_ab",
            "goal_run_ref":"goal://gr_ab",
            "declared_method_and_hypothesis_refs":[],
            "parent_and_derivation_refs":[],
            "input_state_and_environment_refs":[],
            "worker_model_harness_tool_and_runtime_versions":[],
            "authority_and_policy_refs":[],
            "resource_and_cost_refs":[],
            "artifact_license_ip_retention_and_export_refs":[],
            "contribution_refs":[],
            "coordination_topology":"hosted_admission"
        })
    }

    fn coordinates() -> Value {
        json!({
            "outcome_room":{"record_ref":"outcome-room://or_ab","host_domain_ref":"agentgres://domain/host","control_hash":"sha256:room"},
            "frontier_item":{"record_ref":format!("frontier://wfi_{}", "1".repeat(64)),"outcome_room_ref":"outcome-room://or_ab","revision":1,"updated_at":null,"record_hash":"sha256:frontier"},
            "work_claim":{"record_ref":format!("work-claim://wcl_{}", "2".repeat(64)),"outcome_room_ref":"outcome-room://or_ab","frontier_item_ref":format!("frontier://wfi_{}", "1".repeat(64)),"claimant_ref":"participant-lease://rpl_ab","revision":1,"updated_at":null,"record_hash":"sha256:claim"},
            "participant_lease":{"record_ref":"participant-lease://rpl_ab","outcome_room_ref":"outcome-room://or_ab","principal_ref":"worker://a","revision":1,"updated_at":null,"record_hash":"sha256:participant"},
            "goal_run":{"record_ref":"goal://gr_ab","outcome_room_ref":"outcome-room://or_ab","revision":null,"updated_at":null,"record_hash":"sha256:goal"}
        })
    }

    fn authorized(effect: &Value) -> AuthorizedDecision {
        AuthorizedDecision {
            evidence: DecisionEvidence {
                acting_authority_id: Value::Null,
                grant_ref: "grant://test".into(),
                policy_hash: "sha256:policy".into(),
                request_hash: "sha256:request".into(),
                effect_hash: governed::decision_effect_hash(ATTEMPT_AUTHORITY, effect),
                authorized_effect: effect.clone(),
                wallet_approval_grant: Value::Null,
                authority_binding: Value::Null,
            },
            resolved_at_ms: 1_800_000_000_000,
        }
    }

    #[test]
    fn canonical_ids_are_exact_64_hex() {
        assert!(canonical_attempt_tail(&format!("att_{}", "a".repeat(64))));
        assert!(canonical_finding_tail(&format!("fnd_{}", "0".repeat(64))));
        assert!(!canonical_attempt_tail("att_ab"));
        assert!(!canonical_finding_tail(&format!("fnd_{}", "G".repeat(64))));
    }

    #[test]
    fn canonical_prefix_refs_do_not_accept_uri_substitutions() {
        let body = json!({
            "versions":["harness_profile:codex"],
            "contributions":["contrib_ab", "receipt://r1"]
        });
        assert_eq!(
            ref_list_with_prefixes(&body, "versions", &[], &["harness_profile:"]).unwrap(),
            vec!["harness_profile:codex"]
        );
        assert_eq!(
            ref_list_with_prefixes(&body, "contributions", &["receipt"], &["contrib_"]).unwrap(),
            vec!["contrib_ab", "receipt://r1"]
        );
        let substituted = json!({"versions":["harness_profile://codex"]});
        assert!(
            ref_list_with_prefixes(&substituted, "versions", &[], &["harness_profile:"]).is_err()
        );
    }

    #[test]
    fn recursively_rejects_secret_bearing_payloads() {
        let error = reject_sensitive(&json!({"proof":{"api_token":"leak"}}), "").unwrap_err();
        assert_eq!(error.0, "attempt_finding_plaintext_secret_rejected");
        assert!(reject_sensitive(&json!({"proof_refs":["receipt://ok"]}), "").is_ok());
    }

    #[test]
    fn room_coordinate_ignores_only_owner_backlink_churn() {
        let before = json!({
            "outcome_room_id":"outcome-room://or_ab","status":"open","host_domain_ref":"agentgres://domain/host",
            "revision":3,"updated_at":"2027-01-01T00:00:00Z","attempt_refs":[],"status_history":[]
        });
        let mut after = before.clone();
        after["revision"] = json!(4);
        after["updated_at"] = json!("2027-01-01T00:00:01Z");
        after["attempt_refs"] = json!([format!("attempt://att_{}", "a".repeat(64))]);
        assert_eq!(
            room_coordinate("outcome-room://or_ab", &before),
            room_coordinate("outcome-room://or_ab", &after)
        );
        after["status"] = json!("closed");
        assert_ne!(
            room_coordinate("outcome-room://or_ab", &before),
            room_coordinate("outcome-room://or_ab", &after)
        );
    }

    #[test]
    fn attempt_create_reconstructs_and_effect_swap_refuses() {
        let declaration = declaration();
        let coordinates = coordinates();
        let tail = deterministic_tail(
            "att_",
            &json!({"domain":"hypervisor.attempt.identity.v1","declaration":declaration,"bound_coordinates":coordinates}),
        );
        let subject = format!("attempt://{tail}");
        let effect = effect(
            "attempt",
            "create",
            0,
            &json!({"declaration":declaration,"bound_coordinates":coordinates}),
            "draft",
        );
        let authorized = authorized(&effect);
        let receipt_tail = format!("amr_{}", "b".repeat(64));
        let receipt_ref = format!("receipt://{receipt_tail}");
        let final_attempt = seal_attempt(
            &declaration,
            &coordinates,
            &tail,
            &receipt_ref,
            authorized.resolved_at_ms,
        )
        .unwrap();
        let refs = dependency_refs_from_attempt(&final_attempt);
        let receipt = build_receipt(
            &receipt_tail, ATTEMPT_RECEIPT_SCHEMA, "AttemptMutationReceipt", &subject, "create",
            json!({"revision_before":0,"revision_after":1,"status_after":"draft","bound_coordinates":coordinates}),
            refs.iter().map(|value| json!(value)).collect(), &final_attempt, &authorized,
        ).unwrap();
        let intent = seal_intent(
            json!({
                "kind":"attempt_create","governance":"participant","op":"create","room_ref":refs[0],
                "frontier_ref":refs[1],"claim_ref":refs[2],"participant_ref":refs[3],"goal_run_ref":refs[4],
                "attempt_ref":null,"work_result_ref":null,"outcome_delta_refs":[],"supersedes_ref":null,
                "required_authority_ref":"worker://a","subject_ref":subject,
                "revision_before":0,"receipt_tail":receipt_tail,"receipt":receipt,"prior_attempt":null,
                "final_attempt":final_attempt,"prior_finding":null,"final_finding":null
            }),
            &format!("afi_{}", "c".repeat(64)),
        );
        validate_intent_exact(&intent, "attempt_create", ATTEMPT_AUTHORITY).unwrap();
        let mut swapped = intent.clone();
        swapped["final_attempt"]["resource_and_cost_refs"] = json!(["spend://escalated"]);
        assert!(validate_intent_exact(&swapped, "attempt_create", ATTEMPT_AUTHORITY).is_err());

        let mut reservation_swap = intent.clone();
        reservation_swap["frontier_ref"] = json!(format!("frontier://wfi_{}", "9".repeat(64)));
        reservation_swap["touched_refs"] = json!([
            "attempt://placeholder",
            format!("frontier://wfi_{}", "9".repeat(64))
        ]);
        assert!(
            validate_intent_exact(&reservation_swap, "attempt_create", ATTEMPT_AUTHORITY).is_err()
        );
    }

    #[test]
    fn touched_refs_are_exact_sorted_aggregate_reservations() {
        let intent = seal_intent(
            json!({
                "kind":"finding_create","room_ref":"outcome-room://or_b","subject_ref":format!("finding://fnd_{}", "d".repeat(64)),
                "frontier_ref":null,"claim_ref":null,"participant_ref":"participant-lease://rpl_b",
                "goal_run_ref":null,"attempt_ref":format!("attempt://att_{}", "e".repeat(64)),
                "work_result_ref":"work-result://wr_b","outcome_delta_refs":[],"supersedes_ref":null
            }),
            &format!("afi_{}", "f".repeat(64)),
        );
        let touched = validate_touched(&intent).unwrap();
        let mut expected = touched.clone();
        expected.sort();
        expected.dedup();
        assert_eq!(touched, expected);
        assert_eq!(touched.len(), 5);
    }

    #[test]
    fn pending_intent_reserves_every_touched_aggregate() {
        let dir = temp_dir("reservation");
        let tail = format!("afi_{}", "1".repeat(64));
        let participant = "participant-lease://rpl_reserved";
        let intent = seal_intent(
            json!({
                "kind":"finding_create","room_ref":"outcome-room://or_r","subject_ref":format!("finding://fnd_{}", "2".repeat(64)),
                "frontier_ref":null,"claim_ref":null,"participant_ref":participant,"goal_run_ref":null,
                "attempt_ref":format!("attempt://att_{}", "3".repeat(64)),"work_result_ref":"work-result://wr_r",
                "outcome_delta_refs":[],"supersedes_ref":null
            }),
            &tail,
        );
        persist_record(dir.to_str().unwrap(), INTENT_DIR, &tail, &intent).unwrap();
        let error = refuse_external_mutation_if_reserved(
            dir.to_str().unwrap(),
            participant,
            "participant_lease_mutation_in_flight",
        )
        .unwrap_err();
        assert_eq!(error.0, "participant_lease_mutation_in_flight");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn finding_uncertainty_and_future_verdicts_fail_closed() {
        let base = json!({
            "outcome_room_ref":"outcome-room://or_a","attempt_ref":format!("attempt://att_{}", "a".repeat(64)),
            "work_result_ref":"work-result://wr_a","participant_ref":"participant-lease://rpl_a",
            "proposition":"p","finding_kind":"observation","confidence_or_uncertainty":1.5,"valid_time":null,
            "supporting_evidence_refs":[],"contradicting_evidence_refs":[],"proof_refs":[],
            "applicability_and_counterexample_refs":[],"provenance_ontology_and_mapping_refs":[],
            "proposed_effect_refs":[],"supersedes_ref":null,"coordination_topology":"hosted_admission",
            "expected_revision":0,"wallet_approval_grant":null
        });
        assert_eq!(
            validate_finding_create(&base).unwrap_err().0,
            "finding_uncertainty_invalid"
        );
        assert_eq!(
            finding_transition_contract("reject", "proposed")
                .unwrap_err()
                .0,
            "finding_verdict_unavailable"
        );
        assert_eq!(
            attempt_transition_contract("accept", "submitted")
                .unwrap_err()
                .0,
            "attempt_verdict_unavailable"
        );
    }

    #[test]
    fn strict_loader_distinguishes_absent_from_malformed() {
        let dir = temp_dir("strict");
        let tail = format!("att_{}", "9".repeat(64));
        assert!(load_attempt_strict(dir.to_str().unwrap(), &tail)
            .unwrap()
            .is_none());
        let family = dir.join(ATTEMPT_DIR);
        std::fs::create_dir_all(&family).unwrap();
        std::fs::write(family.join(format!("{tail}.json")), b"{").unwrap();
        assert!(load_attempt_strict(dir.to_str().unwrap(), &tail).is_err());
        std::fs::remove_dir_all(dir).ok();
    }
}
