//! Hosted-room ResourceOffer + CapabilityOffer admission and receipted eligibility matching.
//!
//! Offers are participant-backed profiles over already admitted inventory/capability refs. They
//! do not allocate resources, grant execution authority, or create claims. A host-governed match
//! receipt freezes the exact room, frontier, participant, offer revisions/hashes, and complete
//! requirement coverage. WorkClaim acquisition locally revalidates that tuple before mutation.

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

const RESOURCE_SCHEMA: &str = "ioi.hypervisor.resource-offer.v1";
const CAPABILITY_SCHEMA: &str = "ioi.hypervisor.capability-offer.v1";
const OFFER_RECEIPT_SCHEMA: &str = "ioi.hypervisor.offer-mutation-receipt.v1";
const MATCH_RECEIPT_SCHEMA: &str = "ioi.hypervisor.work-eligibility-match-receipt.v1";
const INTENT_SCHEMA: &str = "ioi.hypervisor.resource-capability-offer-intent.v1";

const RESOURCE_DIR: &str = "resource-offers";
const CAPABILITY_DIR: &str = "capability-offers";
const RECEIPT_DIR: &str = "resource-capability-offer-receipts";
const INTENT_DIR: &str = "resource-capability-offer-intents";

const RESOURCE_STATUSES: &[&str] = &[
    "offered",
    "queued",
    "allocated",
    "exhausted",
    "withdrawn",
    "expired",
    "revoked",
];
const CAPABILITY_STATUSES: &[&str] = &[
    "offered",
    "eligible",
    "allocated",
    "suspended",
    "withdrawn",
    "revoked",
];
const LIVE_RESOURCE: &[&str] = &["offered"];
const LIVE_CAPABILITY: &[&str] = &["offered", "eligible"];
const LIST_MAX: usize = 128;
const REF_LIST_MAX: usize = 64;
const CLASS_LIST_MAX: usize = 64;
const CLASS_MAX: usize = 160;

const RESOURCE_AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "resource_offer",
    policy_domain: "hypervisor.resource-offer.decision.policy.v1",
    request_domain: "hypervisor.resource-offer.decision.request.v1",
    resolution_domain: "hypervisor.resource-offer.authority-resolution.v1",
    code_prefix: "resource_offer",
    host_label: "room_host",
    participant_label: "participant_provider",
};
const CAPABILITY_AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "capability_offer",
    policy_domain: "hypervisor.capability-offer.decision.policy.v1",
    request_domain: "hypervisor.capability-offer.decision.request.v1",
    resolution_domain: "hypervisor.capability-offer.authority-resolution.v1",
    code_prefix: "capability_offer",
    host_label: "room_host",
    participant_label: "participant_provider",
};
const MATCH_AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "work_eligibility",
    policy_domain: "hypervisor.work-eligibility.decision.policy.v1",
    request_domain: "hypervisor.work-eligibility.decision.request.v1",
    resolution_domain: "hypervisor.work-eligibility.authority-resolution.v1",
    code_prefix: "work_eligibility",
    host_label: "room_host",
    participant_label: "participant_candidate",
};

/// Fixed order: participation -> offers/matches -> frontier/claim -> room.
pub(crate) static OFFER_MATCH_LOCK: Mutex<()> = Mutex::new(());

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
        || code.contains("in_flight")
        || code.contains("not_active")
        || code.contains("not_open")
    {
        StatusCode::CONFLICT
    } else if code.contains("unavailable") {
        StatusCode::NOT_IMPLEMENTED
    } else if code.contains("unreadable")
        || code.contains("persist_failed")
        || code.contains("pending_convergence")
        || code.contains("durability")
        || code.contains("swapped")
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (
        status,
        Json(
            json!({"error":{"code":code,"message":message,"runtimeTruthSource":"daemon-runtime"}}),
        ),
    )
}

fn canonical_tail(tail: &str, prefix: &str) -> bool {
    tail.strip_prefix(prefix).is_some_and(|hex| {
        hex.len() == 64
            && hex
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
    })
}
fn canonical_resource_tail(tail: &str) -> bool {
    canonical_tail(tail, "rof_")
}
fn canonical_capability_tail(tail: &str) -> bool {
    canonical_tail(tail, "cof_")
}
fn canonical_receipt_tail(tail: &str) -> bool {
    canonical_tail(tail, "orm_") || canonical_tail(tail, "wem_")
}
fn canonical_intent_tail(tail: &str) -> bool {
    canonical_tail(tail, "oci_")
}
fn canonical_resource_ref(value: &str) -> bool {
    value
        .strip_prefix("resource-offer://")
        .is_some_and(canonical_resource_tail)
}
fn canonical_capability_ref(value: &str) -> bool {
    value
        .strip_prefix("capability-offer://")
        .is_some_and(canonical_capability_tail)
}
fn canonical_match_ref(value: &str) -> bool {
    value
        .strip_prefix("receipt://")
        .is_some_and(|tail| canonical_tail(tail, "wem_"))
}

fn ref_ok(value: &str, schemes: &[&str]) -> bool {
    if value.len() > 300 || value.chars().any(char::is_whitespace) {
        return false;
    }
    schemes.iter().any(|scheme| {
        value
            .strip_prefix(&format!("{scheme}://"))
            .is_some_and(|tail| !tail.is_empty() && !tail.starts_with('/') && !tail.contains(".."))
    }) || (schemes.contains(&"scope")
        && value
            .strip_prefix("scope:")
            .is_some_and(|tail| !tail.is_empty() && !tail.starts_with(':')))
        || (schemes.contains(&"harness_profile")
            && value
                .strip_prefix("harness_profile:")
                .is_some_and(|tail| !tail.is_empty() && !tail.starts_with(':')))
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
        Value::Object(map) => {
            for (key, child) in map {
                let normalized: String = key
                    .to_lowercase()
                    .chars()
                    .filter(|c| !matches!(c, '_' | '-' | ' ' | '.'))
                    .collect();
                if SENSITIVE
                    .iter()
                    .any(|fragment| normalized.contains(fragment))
                    && !child.is_null()
                {
                    return Err(verr(
                        "offer_plaintext_secret_rejected",
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
    let object = body
        .as_object()
        .ok_or_else(|| verr("offer_body_invalid", "request body must be an object"))?;
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(verr(
                "offer_field_unknown",
                format!("unknown field '{key}'"),
            ));
        }
    }
    Ok(())
}

fn required_ref(body: &Value, key: &str, schemes: &[&str]) -> Result<String, VErr> {
    let value = body
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| verr("offer_field_required", format!("'{key}' is required")))?;
    if !ref_ok(value, schemes) {
        return Err(verr(
            "offer_ref_invalid",
            format!("'{key}' has a noncanonical scheme or path"),
        ));
    }
    Ok(value.to_string())
}
fn optional_ref(body: &Value, key: &str, schemes: &[&str]) -> Result<Value, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(value)) if ref_ok(value, schemes) => Ok(json!(value)),
        _ => Err(verr(
            "offer_ref_invalid",
            format!("'{key}' has a noncanonical ref"),
        )),
    }
}
fn ref_list(body: &Value, key: &str, schemes: &[&str]) -> Result<Vec<String>, VErr> {
    let Some(items) = body.get(key).and_then(Value::as_array) else {
        return if body.get(key).is_none() || body.get(key) == Some(&Value::Null) {
            Ok(Vec::new())
        } else {
            Err(verr(
                "offer_list_invalid",
                format!("'{key}' must be a list"),
            ))
        };
    };
    if items.len() > REF_LIST_MAX {
        return Err(verr(
            "offer_list_too_long",
            format!("'{key}' exceeds {REF_LIST_MAX} entries"),
        ));
    }
    let mut out = Vec::new();
    for item in items {
        let value = item.as_str().ok_or_else(|| {
            verr(
                "offer_ref_invalid",
                format!("'{key}' entries must be strings"),
            )
        })?;
        if !ref_ok(value, schemes) {
            return Err(verr(
                "offer_ref_invalid",
                format!("'{value}' is not admitted in '{key}'"),
            ));
        }
        if out.iter().any(|existing| existing == value) {
            return Err(verr(
                "offer_duplicate_ref",
                format!("duplicate '{value}' in '{key}'"),
            ));
        }
        out.push(value.to_string());
    }
    Ok(out)
}
fn string_list(body: &Value, key: &str) -> Result<Vec<String>, VErr> {
    let items = body
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| verr("offer_list_invalid", format!("'{key}' must be a list")))?;
    if items.is_empty() || items.len() > CLASS_LIST_MAX {
        return Err(verr(
            "offer_list_invalid",
            format!("'{key}' must contain 1..={CLASS_LIST_MAX} entries"),
        ));
    }
    let mut out = Vec::new();
    for item in items {
        let value = item
            .as_str()
            .map(str::trim)
            .filter(|v| !v.is_empty() && v.chars().count() <= CLASS_MAX)
            .ok_or_else(|| {
                verr(
                    "offer_class_invalid",
                    format!("'{key}' contains an invalid class"),
                )
            })?;
        if out.iter().any(|existing| existing == value) {
            return Err(verr(
                "offer_class_invalid",
                format!("duplicate class '{value}'"),
            ));
        }
        out.push(value.to_string());
    }
    Ok(out)
}
fn expected_revision(body: &Value, current: u64) -> Result<(), VErr> {
    match body.get("expected_revision").and_then(Value::as_u64) {
        Some(expected) if expected == current => Ok(()),
        Some(expected) => Err(verr(
            "offer_stale_revision",
            format!("expected revision {expected}, current revision is {current}"),
        )),
        None => Err(verr(
            "offer_expected_revision_required",
            "every mutation requires unsigned expected_revision",
        )),
    }
}
fn ms_to_rfc3339(ms: u64) -> Result<String, VErr> {
    OffsetDateTime::from_unix_timestamp_nanos(
        i128::from(ms)
            .checked_mul(1_000_000)
            .ok_or_else(|| verr("offer_wallet_time_invalid", "wallet time overflows"))?,
    )
    .map_err(|_| {
        verr(
            "offer_wallet_time_invalid",
            "wallet time is not representable",
        )
    })?
    .format(&Rfc3339)
    .map_err(|error| verr("offer_wallet_time_invalid", error.to_string()))
}
fn deterministic_tail(prefix: &str, value: &Value) -> String {
    let hash = record_output_hash(value, &[]);
    format!("{prefix}{}", hash.strip_prefix("sha256:").unwrap_or(&hash))
}
fn fresh_tail(
    prefix: &str,
    domain: &str,
    subject: &str,
    op: &str,
    revision: u64,
    resolved_at_ms: u64,
) -> String {
    deterministic_tail(
        prefix,
        &json!({"domain":domain,"subject_ref":subject,"op":op,"revision":revision,"resolved_at_ms":resolved_at_ms,"nonce":uuid::Uuid::new_v4().to_string()}),
    )
}
fn without_field(value: &Value, field: &str) -> Value {
    let mut out = value.clone();
    if let Some(o) = out.as_object_mut() {
        o.remove(field);
    }
    out
}
fn array_strings(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
fn union_fields(value: &Value, fields: &[&str]) -> BTreeSet<String> {
    fields
        .iter()
        .flat_map(|field| array_strings(value, field))
        .collect()
}

// ================================= STRICT DURABLE STORAGE =======================================

fn persist_record(data_dir: &str, family: &str, tail: &str, record: &Value) -> Result<(), VErr> {
    super::durable_fs::persist_record_durable(data_dir, family, tail, record).map_err(|failure| {
        if failure.visible() {
            verr(
                "offer_pending_convergence",
                format!("{family}/{tail} is {}", failure.detail()),
            )
        } else {
            verr(
                "offer_persist_failed",
                format!("{family}/{tail} is {}", failure.detail()),
            )
        }
    })
}
fn persist_receipt(data_dir: &str, tail: &str, receipt: &Value) -> Result<(), VErr> {
    use super::durable_fs::CommitFailure;
    super::durable_fs::persist_receipt_no_clobber(data_dir, RECEIPT_DIR, tail, receipt).map_err(
        |failure| match failure {
            CommitFailure::KeyInvalid(message) => verr("offer_receipt_key_invalid", message),
            CommitFailure::NotCommitted(message) => verr("offer_receipt_persist_failed", message),
            CommitFailure::SlotUnreadable(message) => verr("offer_receipt_unreadable", message),
            CommitFailure::Conflict(message) => verr("offer_receipt_conflict", message),
            CommitFailure::DurabilityUnconfirmed(message) => {
                verr("offer_pending_convergence", message)
            }
            CommitFailure::Swapped(message) => verr("offer_receipt_swapped", message),
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
fn validate_offer_identity(family: &str, tail: &str, record: &Value) -> Result<(), String> {
    let (schema, field, id, statuses) = if family == RESOURCE_DIR {
        (
            RESOURCE_SCHEMA,
            "resource_offer_id",
            format!("resource-offer://{tail}"),
            RESOURCE_STATUSES,
        )
    } else if family == CAPABILITY_DIR {
        (
            CAPABILITY_SCHEMA,
            "capability_offer_id",
            format!("capability-offer://{tail}"),
            CAPABILITY_STATUSES,
        )
    } else {
        return Err(format!("unknown offer family '{family}'"));
    };
    if !record.is_object()
        || record.get("schema_version").and_then(Value::as_str) != Some(schema)
        || record.get(field).and_then(Value::as_str) != Some(id.as_str())
        || !record
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| statuses.contains(&status))
        || record.get("revision").and_then(Value::as_u64).is_none()
        || !record
            .get("outcome_room_ref")
            .and_then(Value::as_str)
            .is_some_and(|value| ref_ok(value, &["outcome-room"]))
        || !record
            .get("provider_participant_lease_ref")
            .and_then(Value::as_str)
            .is_some_and(|value| ref_ok(value, &["participant-lease"]))
    {
        return Err(format!(
            "slot '{family}/{tail}' has a malformed or identity-mismatched envelope"
        ));
    }
    Ok(())
}
fn load_offer(
    data_dir: &str,
    family: &str,
    id_or_tail: &str,
    canonical: fn(&str) -> bool,
    scheme: &str,
) -> Result<Option<Value>, String> {
    let tail = id_or_tail
        .strip_prefix(&format!("{scheme}://"))
        .unwrap_or(id_or_tail);
    let record = read_slot(data_dir, family, tail, canonical)?;
    if let Some(record) = record {
        validate_offer_identity(family, tail, &record)?;
        Ok(Some(record))
    } else {
        Ok(None)
    }
}
fn load_resource(data_dir: &str, id_or_tail: &str) -> Result<Option<Value>, String> {
    load_offer(
        data_dir,
        RESOURCE_DIR,
        id_or_tail,
        canonical_resource_tail,
        "resource-offer",
    )
}
fn load_capability(data_dir: &str, id_or_tail: &str) -> Result<Option<Value>, String> {
    load_offer(
        data_dir,
        CAPABILITY_DIR,
        id_or_tail,
        canonical_capability_tail,
        "capability-offer",
    )
}
fn scan_offers(
    data_dir: &str,
    family: &str,
    canonical: fn(&str) -> bool,
) -> Result<Vec<(String, Value)>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("family '{family}' cannot be pinned ({e})")),
    };
    let names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|e| format!("family '{family}' cannot be enumerated ({e})"))?;
    let mut out = Vec::new();
    for name in names {
        let Some(tail) = name.strip_suffix(".json") else {
            continue;
        };
        if !canonical(tail) {
            continue;
        }
        let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
            Ok(Some((_f, b))) => b,
            Ok(None) => {
                return Err(format!(
                    "canonical slot '{family}/{name}' vanished after enumeration"
                ))
            }
            Err(e) => {
                return Err(format!(
                    "canonical slot '{family}/{name}' is unreadable ({e})"
                ))
            }
        };
        let record: Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("canonical slot '{family}/{name}' is malformed JSON ({e})"))?;
        validate_offer_identity(family, tail, &record)?;
        out.push((tail.to_string(), record));
    }
    Ok(out)
}
fn load_match_receipt(data_dir: &str, reference: &str) -> Result<Option<Value>, String> {
    let tail = reference.strip_prefix("receipt://").unwrap_or(reference);
    if !canonical_tail(tail, "wem_") {
        return Err("eligibility receipt ref must be receipt://wem_<64 lowercase hex>".into());
    }
    let receipt = read_slot(data_dir, RECEIPT_DIR, tail, canonical_receipt_tail)?;
    if let Some(receipt) = receipt {
        if receipt.get("schema_version").and_then(Value::as_str) != Some(MATCH_RECEIPT_SCHEMA)
            || receipt.get("receipt_ref").and_then(Value::as_str)
                != Some(format!("receipt://{tail}").as_str())
            || receipt.get("receipt_type").and_then(Value::as_str)
                != Some("WorkEligibilityMatchReceipt")
        {
            return Err(format!(
                "eligibility receipt '{tail}' is malformed or identity-mismatched"
            ));
        }
        Ok(Some(receipt))
    } else {
        Ok(None)
    }
}
fn scan_match_receipts(data_dir: &str) -> Result<Vec<Value>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, RECEIPT_DIR) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("receipt family cannot be pinned ({e})")),
    };
    let names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|e| format!("receipt family cannot be enumerated ({e})"))?;
    let mut out = Vec::new();
    for name in names {
        let Some(tail) = name.strip_suffix(".json") else {
            continue;
        };
        if !canonical_tail(tail, "wem_") {
            continue;
        }
        let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
            Ok(Some((_f, b))) => b,
            Ok(None) => return Err(format!("canonical receipt '{name}' vanished")),
            Err(e) => return Err(format!("canonical receipt '{name}' is unreadable ({e})")),
        };
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("canonical receipt '{name}' is malformed ({e})"))?;
        if value.get("schema_version").and_then(Value::as_str) != Some(MATCH_RECEIPT_SCHEMA)
            || value.get("receipt_ref").and_then(Value::as_str)
                != Some(format!("receipt://{tail}").as_str())
        {
            return Err(format!("canonical receipt '{name}' is identity-mismatched"));
        }
        out.push(value);
    }
    Ok(out)
}

fn consume_intent(data_dir: &str, tail: &str) -> Result<(), VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, INTENT_DIR) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(verr("offer_intent_unreadable", e.to_string())),
    };
    match super::durable_fs::unlink_at(&directory, &format!("{tail}.json")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(verr(
                "offer_pending_convergence",
                format!("intent unlink failed ({e})"),
            ))
        }
    }
    directory.sync_all().map_err(|e| {
        verr(
            "offer_pending_convergence",
            format!("intent directory sync failed ({e})"),
        )
    })
}
fn validate_touched(intent: &Value) -> Result<BTreeSet<String>, String> {
    let items = intent
        .get("touched_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| "intent lacks touched_refs".to_string())?;
    let refs: Vec<String> = items
        .iter()
        .map(|v| {
            v.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| "touched_refs contains non-string".to_string())
        })
        .collect::<Result<_, _>>()?;
    let mut sorted = refs.clone();
    sorted.sort();
    sorted.dedup();
    if refs != sorted {
        return Err("touched_refs must be exact, sorted, and unique".into());
    }
    let expected: BTreeSet<String> = [
        intent.get("subject_ref"),
        intent.get("participant_ref"),
        intent.get("room_ref"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .filter(|v| !v.is_empty())
    .map(ToOwned::to_owned)
    .collect();
    let got: BTreeSet<String> = refs.into_iter().collect();
    if got != expected {
        return Err("touched_refs does not reconstruct from intent successors".into());
    }
    Ok(got)
}
fn scan_intents(data_dir: &str) -> Result<Vec<(String, Value)>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, INTENT_DIR) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("intent family cannot be pinned ({e})")),
    };
    let names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|e| format!("intent family cannot be enumerated ({e})"))?;
    let mut out = Vec::new();
    for name in names {
        let Some(tail) = name.strip_suffix(".json") else {
            continue;
        };
        if !canonical_intent_tail(tail) {
            continue;
        }
        let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
            Ok(Some((_f, b))) => b,
            Ok(None) => return Err(format!("canonical intent '{name}' vanished")),
            Err(e) => return Err(format!("canonical intent '{name}' unreadable ({e})")),
        };
        let intent: Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("canonical intent '{name}' malformed ({e})"))?;
        if intent.get("schema_version").and_then(Value::as_str) != Some(INTENT_SCHEMA)
            || intent.get("intent_id").and_then(Value::as_str)
                != Some(format!("offer-intent://{tail}").as_str())
            || intent.get("intent_hash").and_then(Value::as_str)
                != Some(record_output_hash(&without_field(&intent, "intent_hash"), &[]).as_str())
        {
            return Err(format!(
                "canonical intent '{name}' fails storage-key/hash binding"
            ));
        }
        validate_touched(&intent)?;
        out.push((tail.to_string(), intent));
    }
    Ok(out)
}
fn pending_overlap(
    data_dir: &str,
    refs: &[&str],
    ignored: Option<&str>,
) -> Result<Option<(String, String)>, VErr> {
    let wanted: BTreeSet<&str> = refs.iter().copied().filter(|v| !v.is_empty()).collect();
    for (tail, intent) in scan_intents(data_dir).map_err(|m| verr("offer_intent_unreadable", m))? {
        if ignored == Some(tail.as_str()) {
            continue;
        }
        let touched = validate_touched(&intent).map_err(|m| verr("offer_intent_unreadable", m))?;
        if let Some(hit) = touched.iter().find(|r| wanted.contains(r.as_str())) {
            return Ok(Some((tail, hit.clone())));
        }
    }
    Ok(None)
}
fn refuse_reserved(
    data_dir: &str,
    record_ref: &str,
    code: &str,
    ignored: Option<&str>,
) -> Result<(), VErr> {
    if let Some((tail, overlap)) = pending_overlap(data_dir, &[record_ref], ignored)? {
        Err(verr(
            code,
            format!("record '{overlap}' is reserved by pending offer intent '{tail}'"),
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
    refuse_reserved(data_dir, record_ref, code, None)
}
pub(crate) fn refuse_external_mutation_if_reserved_except(
    data_dir: &str,
    record_ref: &str,
    code: &str,
    intent_tail: &str,
) -> Result<(), VErr> {
    refuse_reserved(data_dir, record_ref, code, Some(intent_tail))
}

// ================================= OFFER + MATCH CONTRACTS ======================================

fn participant_strict(data_dir: &str, participant_ref: &str) -> Result<Value, VErr> {
    participation::resolve_participant_lease_strict(data_dir, participant_ref)
        .map_err(|m| verr("offer_participant_registry_unreadable", m))?
        .ok_or_else(|| {
            verr(
                "offer_participant_not_found",
                format!("no participant lease '{participant_ref}'"),
            )
        })
}
fn resolve_open_room(data_dir: &str, room_ref: &str) -> Result<Value, VErr> {
    rooms::resolve_room_strict(data_dir, room_ref)
        .map_err(|m| verr("offer_room_registry_unreadable", m))?
        .ok_or_else(|| verr("offer_room_not_found", format!("no room '{room_ref}'")))
        .and_then(|room| {
            if s(&room, "status", "") == "open" {
                Ok(room)
            } else {
                Err(verr(
                    "offer_room_not_open",
                    "offers and matches require an open room",
                ))
            }
        })
}
fn validate_common_create(body: &Value) -> Result<(String, String), VErr> {
    reject_sensitive(body, "")?;
    if body.get("coordination_topology").and_then(Value::as_str) != Some("hosted_admission") {
        return Err(verr(
            "offer_federated_unavailable",
            "only hosted_admission is implemented; federated/AIIP offer admission is unavailable",
        ));
    }
    expected_revision(body, 0)?;
    Ok((
        required_ref(body, "outcome_room_ref", &["outcome-room"])?,
        required_ref(body, "provider_or_participant_ref", &["participant-lease"])?,
    ))
}
fn validate_resource_create(body: &Value) -> Result<Value, VErr> {
    reject_unknown(
        body,
        &[
            "outcome_room_ref",
            "provider_or_participant_ref",
            "resource_profile_ref",
            "capacity_and_availability_ref",
            "locality_and_custody_refs",
            "trust_and_assurance_refs",
            "cost_ref",
            "eligible_work_classes",
            "policy_constraint_refs",
            "allocation_policy_ref",
            "queue_preemption_and_fairness_policy_ref",
            "expires_at",
            "coordination_topology",
            "expected_revision",
            "wallet_approval_grant",
        ],
    )?;
    let (room_ref, participant_ref) = validate_common_create(body)?;
    Ok(json!({
        "outcome_room_ref":room_ref,"provider_participant_lease_ref":participant_ref,
        "provider_or_participant_ref":body.get("provider_or_participant_ref").cloned().unwrap_or(Value::Null),
        "resource_profile_ref":required_ref(body,"resource_profile_ref",&["resource","runtime","node"] )?,
        "capacity_and_availability_ref":required_ref(body,"capacity_and_availability_ref",&["capacity","schedule"] )?,
        "locality_and_custody_refs":ref_list(body,"locality_and_custody_refs",&["region","custody","privacy_posture"] )?,
        "trust_and_assurance_refs":ref_list(body,"trust_and_assurance_refs",&["evidence","certification_claim","receipt"] )?,
        "cost_ref":optional_ref(body,"cost_ref",&["quote","budget"] )?,
        "eligible_work_classes":string_list(body,"eligible_work_classes")?,
        "policy_constraint_refs":ref_list(body,"policy_constraint_refs",&["policy"] )?,
        "allocation_policy_ref":required_ref(body,"allocation_policy_ref",&["policy"] )?,
        "queue_preemption_and_fairness_policy_ref":required_ref(body,"queue_preemption_and_fairness_policy_ref",&["policy"] )?,
        "expires_at":match body.get("expires_at"){None|Some(Value::Null)=>Value::Null,Some(Value::String(v))=>{OffsetDateTime::parse(v,&Rfc3339).map_err(|_|verr("offer_expiry_invalid","expires_at must be RFC3339"))?;json!(v)},_=>return Err(verr("offer_expiry_invalid","expires_at must be RFC3339 or null"))},
        "coordination_topology":"hosted_admission"
    }))
}
fn validate_capability_create(body: &Value) -> Result<Value, VErr> {
    reject_unknown(
        body,
        &[
            "outcome_room_ref",
            "provider_or_participant_ref",
            "participant_ref",
            "capability_descriptor_refs",
            "eligible_frontier_classes",
            "model_harness_tool_and_connector_refs",
            "authority_and_context_requirements",
            "privacy_cost_quality_and_latency_refs",
            "availability_ref",
            "coordination_topology",
            "expected_revision",
            "wallet_approval_grant",
        ],
    )?;
    let (room_ref, participant_ref) = validate_common_create(body)?;
    if body
        .get("participant_ref")
        .is_some_and(|value| value.as_str() != Some(participant_ref.as_str()))
    {
        return Err(verr(
            "offer_participant_mismatch",
            "participant_ref must equal provider_or_participant_ref",
        ));
    }
    Ok(json!({
        "outcome_room_ref":room_ref,"provider_participant_lease_ref":participant_ref,"participant_ref":participant_ref,
        "capability_descriptor_refs":ref_list(body,"capability_descriptor_refs",&["ai","package","capability"] )?,
        "eligible_frontier_classes":string_list(body,"eligible_frontier_classes")?,
        "model_harness_tool_and_connector_refs":ref_list(body,"model_harness_tool_and_connector_refs",&["model_route","harness_profile","tool","connector"] )?,
        "authority_and_context_requirements":ref_list(body,"authority_and_context_requirements",&["scope","policy","context-profile"] )?,
        "privacy_cost_quality_and_latency_refs":ref_list(body,"privacy_cost_quality_and_latency_refs",&["privacy_posture","quote","benchmark","sla"] )?,
        "availability_ref":optional_ref(body,"availability_ref",&["schedule"] )?,"coordination_topology":"hosted_admission"
    }))
}
fn load_resource_pool_strict(data_dir: &str, pool_id: &str) -> Result<Value, VErr> {
    if pool_id.is_empty()
        || pool_id.len() > 120
        || !pool_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(verr(
            "resource_offer_inventory_unavailable",
            "resource pool id is not a safe canonical storage key",
        ));
    }
    let directory =
        super::durable_fs::open_family_dir_pinned(data_dir, "resource-pools").map_err(|error| {
            verr(
                "resource_offer_inventory_unavailable",
                format!("resource pool registry unavailable ({error})"),
            )
        })?;
    let bytes = match super::durable_fs::read_slot_strict(&directory, &format!("{pool_id}.json")) {
        Ok(Some((_file, bytes))) => bytes,
        Ok(None) => {
            return Err(verr(
                "resource_offer_inventory_unavailable",
                format!("resource pool '{pool_id}' does not exist"),
            ))
        }
        Err(error) => {
            return Err(verr(
                "resource_offer_inventory_unavailable",
                format!("resource pool '{pool_id}' is unreadable ({error})"),
            ))
        }
    };
    let pool: Value = serde_json::from_slice(&bytes).map_err(|error| {
        verr(
            "resource_offer_inventory_unavailable",
            format!("resource pool '{pool_id}' is malformed ({error})"),
        )
    })?;
    if pool.get("schema_version").and_then(Value::as_str) != Some("ioi.hypervisor.resource-pool.v1")
        || pool.get("pool_id").and_then(Value::as_str) != Some(pool_id)
        || !pool.get("capacity").is_some_and(Value::is_object)
    {
        return Err(verr(
            "resource_offer_inventory_unavailable",
            format!("resource pool '{pool_id}' fails identity/schema binding"),
        ));
    }
    Ok(pool)
}

fn resolve_resource_backing(
    data_dir: &str,
    participant: &Value,
    declaration: &Value,
) -> Result<Value, VErr> {
    let inventory = union_fields(
        participant,
        &[
            "worker_and_runtime_refs",
            "runtime_resource_and_budget_lease_refs",
        ],
    );
    let profile = s(declaration, "resource_profile_ref", "");
    if let Some(pool_id) = profile.strip_prefix("resource://pool/") {
        if s(declaration, "capacity_and_availability_ref", "")
            != format!("capacity://pool/{pool_id}")
        {
            return Err(verr(
                "resource_offer_inventory_unavailable",
                "resource-pool offers must bind matching resource://pool/<id> and capacity://pool/<id> coordinates",
            ));
        }
        let pool = load_resource_pool_strict(data_dir, pool_id)?;
        if pool.get("provider").and_then(Value::as_str)
            != participant.get("participant_ref").and_then(Value::as_str)
        {
            return Err(verr(
                "resource_offer_inventory_unavailable",
                format!(
                    "resource pool '{pool_id}' is not owned by the admitted participant principal"
                ),
            ));
        }
        return Ok(json!({
            "kind":"resource_pool_snapshot",
            "pool_id":pool_id,
            "snapshot_hash":record_output_hash(&pool,&[])
        }));
    }
    if !inventory.contains(&profile) {
        return Err(verr("resource_offer_inventory_unavailable",format!("resource profile '{profile}' is not bound to the admitted participant lease; offers cannot invent inventory")));
    }
    Ok(json!({
        "kind":"participant_inventory_ref",
        "resource_profile_ref":profile,
        "participant_control_hash":participant_control_hash(participant)
    }))
}

fn validate_resource_backing_snapshot(
    data_dir: &str,
    participant: &Value,
    offer: &Value,
) -> Result<(), VErr> {
    let current = resolve_resource_backing(data_dir, participant, offer)?;
    if offer.get("inventory_backing") != Some(&current) {
        return Err(verr(
            "work_eligibility_offer_inventory_stale",
            "resource offer backing inventory changed after admission",
        ));
    }
    Ok(())
}

fn resource_offer_expired_at(offer: &Value, resolved_at_ms: u64) -> Result<bool, VErr> {
    let Some(value) = offer.get("expires_at") else {
        return Err(verr(
            "work_claim_eligibility_offer_unreadable",
            "resource offer lacks expires_at",
        ));
    };
    let Value::String(expires_at) = value else {
        return if value.is_null() {
            Ok(false)
        } else {
            Err(verr(
                "work_claim_eligibility_offer_unreadable",
                "resource offer expires_at is not RFC3339 or null",
            ))
        };
    };
    let expires = OffsetDateTime::parse(expires_at, &Rfc3339).map_err(|_| {
        verr(
            "work_claim_eligibility_offer_unreadable",
            "resource offer expires_at is malformed",
        )
    })?;
    Ok(expires.unix_timestamp_nanos() / 1_000_000 <= i128::from(resolved_at_ms))
}

fn verify_capability_backing(participant: &Value, declaration: &Value) -> Result<(), VErr> {
    let advertised = union_fields(
        participant,
        &[
            "capability_advertisement_refs",
            "tool_connector_and_capability_dependency_refs",
            "worker_and_runtime_refs",
        ],
    );
    for reference in array_strings(declaration, "capability_descriptor_refs")
        .into_iter()
        .chain(array_strings(
            declaration,
            "model_harness_tool_and_connector_refs",
        ))
    {
        let derived_advertisement_alias = advertised.iter().any(|advertised_ref| {
            advertised_ref
                .split_once("://")
                .is_some_and(|(scheme, tail)| {
                    reference == format!("capability://advertised/{scheme}/{tail}")
                })
        });
        if !advertised.contains(&reference) && !derived_advertisement_alias {
            return Err(verr(
                "capability_offer_inventory_unavailable",
                format!(
                    "capability ref '{reference}' is not bound to the admitted participant lease"
                ),
            ));
        }
    }
    if array_strings(declaration, "capability_descriptor_refs").is_empty() {
        return Err(verr(
            "capability_offer_descriptor_required",
            "at least one participant-backed capability descriptor is required",
        ));
    }
    Ok(())
}
fn seal_offer(
    kind: &str,
    declaration: &Value,
    tail: &str,
    receipt_ref: &str,
    resolved_at_ms: u64,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(resolved_at_ms)?;
    let mut record = declaration.clone();
    let object = record.as_object_mut().expect("offer declaration");
    let (schema, field, scheme) = if kind == "resource" {
        (RESOURCE_SCHEMA, "resource_offer_id", "resource-offer")
    } else {
        (CAPABILITY_SCHEMA, "capability_offer_id", "capability-offer")
    };
    object.insert("schema_version".into(), json!(schema));
    object.insert(field.into(), json!(format!("{scheme}://{tail}")));
    object.insert("status".into(), json!("offered"));
    object.insert("revision".into(), json!(1));
    if kind == "resource" {
        object.insert("allocation_decision_refs".into(), json!([]));
        object.insert("spend_and_contribution_refs".into(), json!([]));
        object.insert("usage_and_consumption_refs".into(), json!([]));
    }
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
fn transition_offer(
    prior: &Value,
    op: &str,
    to: &str,
    receipt_ref: &str,
    resolved_at_ms: u64,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(resolved_at_ms)?;
    let mut final_record = prior.clone();
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0) + 1;
    let from = s(prior, "status", "");
    let object = final_record.as_object_mut().expect("offer record");
    object.insert("status".into(), json!(to));
    object.insert("revision".into(), json!(revision));
    object.insert("updated_at".into(), json!(now));
    object.insert("updated_at_ms".into(), json!(resolved_at_ms));
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
    history.push(
        json!({"op":op,"from":from,"to":to,"at":now,"revision":revision,"receipt_ref":receipt_ref}),
    );
    object.insert("status_history".into(), Value::Array(history));
    Ok(final_record)
}
fn offer_effect(
    kind: &str,
    op: &str,
    revision: u64,
    declaration: Option<&Value>,
    to: Option<&str>,
) -> Value {
    json!({"object_kind":kind,"op":op,"revision_before":revision,"declaration":declaration.cloned().unwrap_or(Value::Null),"status_after":to})
}

fn participant_control_hash(participant: &Value) -> String {
    let mut value = participant.clone();
    if let Some(object) = value.as_object_mut() {
        for field in [
            "revision",
            "updated_at",
            "current_claim_ref",
            "heartbeat_ref",
            "next_wake_condition_ref",
            "quiet_hours_or_backoff_ref",
            "last_contribution_ref",
            "admission_and_replay_refs",
            "status_history",
            "exit_and_claim_release_refs",
        ] {
            object.remove(field);
        }
    }
    record_output_hash(&value, &[])
}
fn offer_control_hash(offer: &Value) -> String {
    record_output_hash(
        offer,
        &[
            "updated_at",
            "updated_at_ms",
            "admission_and_replay_refs",
            "status_history",
        ],
    )
}

fn match_effect(tuple: &Value) -> Value {
    json!({"op":"match","eligibility_tuple":tuple})
}

fn collect_match_coverage(
    frontier: &Value,
    participant: &Value,
    resources: &[Value],
    capabilities: &[Value],
    claim_refs: &[String],
) -> Result<(Vec<Value>, Vec<Value>, Vec<String>), VErr> {
    let mut resource_provided = BTreeSet::new();
    for offer in resources {
        for field in ["resource_profile_ref", "capacity_and_availability_ref"] {
            if let Some(v) = offer.get(field).and_then(Value::as_str) {
                resource_provided.insert(v.to_string());
            }
        }
        for field in ["locality_and_custody_refs", "trust_and_assurance_refs"] {
            resource_provided.extend(array_strings(offer, field));
        }
    }
    let mut capability_provided = BTreeSet::new();
    for offer in capabilities {
        capability_provided.extend(array_strings(offer, "capability_descriptor_refs"));
        capability_provided.extend(array_strings(
            offer,
            "model_harness_tool_and_connector_refs",
        ));
    }
    // The participant lease may directly prove admitted evidence and already-owned bounded
    // leases. It may not stand in for a selected offer: raw capability advertisements and
    // worker/runtime refs are deliberately excluded here and become eligible only through the
    // corresponding admitted CapabilityOffer or ResourceOffer.
    let mut participant_provided = union_fields(
        participant,
        &[
            "identity_and_eligibility_evidence_refs",
            "context_and_authority_lease_refs",
            "runtime_resource_and_budget_lease_refs",
            "tool_connector_and_capability_dependency_refs",
        ],
    );
    participant_provided.extend(claim_refs.iter().cloned());
    let mut coverage = Vec::new();
    let mut unsupported = Vec::new();
    let mut offer_prerequisite_coverage = Vec::new();
    for offer in resources {
        let prerequisites = array_strings(offer, "policy_constraint_refs");
        unsupported.extend(prerequisites.iter().cloned());
        offer_prerequisite_coverage.push(json!({
            "offer_ref": offer.get("resource_offer_id").cloned().unwrap_or(Value::Null),
            "prerequisite_refs": prerequisites,
            "proof_refs": []
        }));
    }
    for offer in capabilities {
        let prerequisites = array_strings(offer, "authority_and_context_requirements");
        unsupported.extend(prerequisites.iter().cloned());
        offer_prerequisite_coverage.push(json!({
            "offer_ref": offer.get("capability_offer_id").cloned().unwrap_or(Value::Null),
            "prerequisite_refs": prerequisites,
            "proof_refs": []
        }));
    }
    if !unsupported.is_empty() {
        return Ok((Vec::new(), offer_prerequisite_coverage, unsupported));
    }
    for requirement in array_strings(frontier, "required_capability_refs") {
        if capability_provided.contains(&requirement) {
            coverage.push(json!({"requirement_ref":requirement,"matched_exactly":true}));
        } else {
            return Err(verr(
                "work_eligibility_requirements_unmatched",
                format!("required capability '{requirement}' is not proven by a selected participant-backed capability offer"),
            ));
        }
    }
    for requirement in array_strings(
        frontier,
        "required_context_resource_authority_and_evidence_refs",
    ) {
        if requirement.starts_with("scope:") || requirement.starts_with("context-profile://") {
            unsupported.push(requirement);
            continue;
        }
        if resource_provided.contains(&requirement)
            || capability_provided.contains(&requirement)
            || participant_provided.contains(&requirement)
        {
            coverage.push(json!({"requirement_ref":requirement,"matched_exactly":true}));
        } else {
            return Err(verr("work_eligibility_requirements_unmatched",format!("required ref '{requirement}' is not proven by the selected participant-backed offers/evidence")));
        }
    }
    Ok((coverage, offer_prerequisite_coverage, unsupported))
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
    note: &str,
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
        note,
        &now,
    );
    governed::append_evidence(&mut receipt, authorized);
    Ok(receipt)
}

fn existing_match_receipt_exact(
    data_dir: &str,
    reference: &str,
    facts: &Value,
) -> Result<Option<Value>, VErr> {
    let Some(receipt) = load_match_receipt(data_dir, reference)
        .map_err(|message| verr("work_eligibility_receipt_unreadable", message))?
    else {
        return Ok(None);
    };
    if receipt.get("bound_facts") != Some(facts) {
        return Err(verr(
            "work_eligibility_receipt_unreadable",
            "eligibility receipt identity is occupied by different facts",
        ));
    }
    let tail = reference.strip_prefix("receipt://").ok_or_else(|| {
        verr(
            "work_eligibility_receipt_unreadable",
            "eligibility receipt has a noncanonical ref",
        )
    })?;
    let expected_effect = match_effect(facts);
    governed::validate_sealed_effect(MATCH_AUTHORITY, &receipt, &expected_effect)
        .map_err(|message| verr("work_eligibility_receipt_unreadable", message))?;
    let authorized = sealed_authorized(&receipt)
        .map_err(|message| verr("work_eligibility_receipt_unreadable", message))?;
    let expected = build_receipt(
        tail,
        MATCH_RECEIPT_SCHEMA,
        "WorkEligibilityMatchReceipt",
        reference,
        "match",
        facts.clone(),
        vec![
            facts
                .get("outcome_room_ref")
                .cloned()
                .unwrap_or(Value::Null),
            facts
                .get("frontier_item_ref")
                .cloned()
                .unwrap_or(Value::Null),
            facts
                .get("participant_ref")
                .cloned()
                .unwrap_or(Value::Null),
        ],
        facts,
        "a host-admitted exact eligibility match; it creates no allocation, execution authority, or claim",
        &authorized,
    )?;
    if expected != receipt {
        return Err(verr(
            "work_eligibility_receipt_unreadable",
            "eligibility receipt does not reconstruct byte-exactly",
        ));
    }
    Ok(Some(receipt))
}

fn seal_intent(mut intent: Value, tail: &str) -> Value {
    let object = intent.as_object_mut().expect("intent object");
    object.insert("schema_version".into(), json!(INTENT_SCHEMA));
    object.insert("intent_id".into(), json!(format!("offer-intent://{tail}")));
    let mut touched: BTreeSet<String> = BTreeSet::new();
    for field in ["subject_ref", "participant_ref", "room_ref"] {
        if let Some(value) = object
            .get(field)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        {
            touched.insert(value.to_string());
        }
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
    canonical: fn(&str) -> bool,
    prior: Option<&Value>,
    final_record: &Value,
) -> Result<(), VErr> {
    let current = read_slot(data_dir, family, tail, canonical)
        .map_err(|m| verr("offer_registry_unreadable", m))?;
    if current.as_ref() == Some(final_record) {
        return Ok(());
    }
    if current.as_ref() != prior {
        return Err(verr(
            "offer_pending_convergence",
            format!("{family}/{tail} equals neither sealed prior nor successor"),
        ));
    }
    persist_record(data_dir, family, tail, final_record)
}
fn complete_intent_locked(data_dir: &str, tail: &str, intent: &Value) -> Result<(), VErr> {
    let kind = intent
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| verr("offer_intent_unreadable", "intent lacks kind"))?;
    let receipt_tail = intent
        .get("receipt_tail")
        .and_then(Value::as_str)
        .ok_or_else(|| verr("offer_intent_unreadable", "intent lacks receipt tail"))?;
    let receipt = intent
        .get("receipt")
        .ok_or_else(|| verr("offer_intent_unreadable", "intent lacks receipt"))?;
    if kind == "resource_create" || kind == "capability_create" {
        let room_ref = intent.get("room_ref").and_then(Value::as_str).unwrap_or("");
        let subject_ref = intent
            .get("subject_ref")
            .and_then(Value::as_str)
            .unwrap_or("");
        let op = if kind == "resource_create" {
            "resource_offer_bound"
        } else {
            "capability_offer_bound"
        };
        match rooms::bind_room_backlink_room_locked_for_offer_intent(
            data_dir,
            room_ref,
            op,
            subject_ref,
            tail,
        ) {
            Ok(_) => {}
            Err((code, _)) if code == "outcome_room_backlink_already_bound" => {}
            Err(error) => return Err(error),
        }
    }
    persist_receipt(data_dir, receipt_tail, receipt)?;
    if let Some(final_record) = intent.get("final_offer").filter(|v| !v.is_null()) {
        let (family, scheme, canonical) = if kind.starts_with("resource_") {
            (
                RESOURCE_DIR,
                "resource-offer://",
                canonical_resource_tail as fn(&str) -> bool,
            )
        } else {
            (
                CAPABILITY_DIR,
                "capability-offer://",
                canonical_capability_tail as fn(&str) -> bool,
            )
        };
        let id_field = if family == RESOURCE_DIR {
            "resource_offer_id"
        } else {
            "capability_offer_id"
        };
        let id = final_record
            .get(id_field)
            .and_then(Value::as_str)
            .ok_or_else(|| verr("offer_intent_unreadable", "successor lacks id"))?;
        let record_tail = id
            .strip_prefix(scheme)
            .ok_or_else(|| verr("offer_intent_unreadable", "successor id scheme mismatch"))?;
        persist_successor(
            data_dir,
            family,
            record_tail,
            canonical,
            intent.get("prior_offer").filter(|v| !v.is_null()),
            final_record,
        )?;
    }
    consume_intent(data_dir, tail)
}
fn persist_and_complete_locked(data_dir: &str, tail: &str, intent: &Value) -> Result<(), VErr> {
    persist_record(data_dir, INTENT_DIR, tail, intent)?;
    complete_intent_locked(data_dir, tail, intent)
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
fn offer_declaration(record: &Value) -> Value {
    let mut value = record.clone();
    if let Some(object) = value.as_object_mut() {
        for field in [
            "schema_version",
            "resource_offer_id",
            "capability_offer_id",
            "status",
            "revision",
            "allocation_decision_refs",
            "spend_and_contribution_refs",
            "usage_and_consumption_refs",
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
    value
}

fn validate_intent_exact(
    intent: &Value,
    kind: &str,
    contract: AuthorityContract,
) -> Result<(), String> {
    let receipt_tail = intent
        .get("receipt_tail")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks receipt tail".to_string())?;
    if !canonical_receipt_tail(receipt_tail) {
        return Err("intent receipt tail is noncanonical".into());
    }
    let receipt = intent
        .get("receipt")
        .ok_or_else(|| "intent lacks receipt".to_string())?;
    let authorized = sealed_authorized(receipt)?;
    let op = intent
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks op".to_string())?;
    let room_ref = intent
        .get("room_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks room".to_string())?;
    let participant_ref = intent
        .get("participant_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks participant".to_string())?;
    let subject_ref = intent
        .get("subject_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks subject".to_string())?;
    let revision = intent
        .get("revision_before")
        .and_then(Value::as_u64)
        .ok_or_else(|| "intent lacks revision".to_string())?;
    if kind == "eligibility_match" {
        let facts = receipt
            .get("bound_facts")
            .cloned()
            .ok_or_else(|| "match receipt lacks facts".to_string())?;
        let expected_effect = match_effect(&facts);
        governed::validate_sealed_effect(contract, receipt, &expected_effect)?;
        let expected_tail = deterministic_tail(
            "wem_",
            &json!({"domain":"hypervisor.work-eligibility-match.identity.v1","tuple":facts}),
        );
        if receipt_tail != expected_tail || subject_ref != format!("receipt://{expected_tail}") {
            return Err("match identity does not reconstruct from exact tuple".into());
        }
        let expected=build_receipt(receipt_tail,MATCH_RECEIPT_SCHEMA,"WorkEligibilityMatchReceipt",subject_ref,"match",facts.clone(),vec![json!(room_ref),facts.get("frontier_item_ref").cloned().unwrap_or(Value::Null),json!(participant_ref)],&facts,"a host-admitted exact eligibility match; it creates no allocation, execution authority, or claim",&authorized).map_err(|(_,m)|m)?;
        if expected != *receipt {
            return Err("match receipt does not reconstruct byte-exactly".into());
        }
        return Ok(());
    }
    let object_kind = if kind.starts_with("resource_") {
        "resource"
    } else {
        "capability"
    };
    let final_offer = intent
        .get("final_offer")
        .filter(|v| !v.is_null())
        .ok_or_else(|| "offer intent lacks successor".to_string())?;
    let receipt_ref = format!("receipt://{receipt_tail}");
    let (receipt_type, id_field) = if object_kind == "resource" {
        ("ResourceOfferMutationReceipt", "resource_offer_id")
    } else {
        ("CapabilityOfferMutationReceipt", "capability_offer_id")
    };
    if final_offer.get(id_field).and_then(Value::as_str) != Some(subject_ref) {
        return Err("offer successor identity differs from intent subject".into());
    }
    let (expected_final, expected_effect, bound_facts) = if op == "create" {
        if revision != 0 || intent.get("prior_offer").is_some_and(|v| !v.is_null()) {
            return Err("offer creation prior/revision is invalid".into());
        }
        let declaration = offer_declaration(final_offer);
        let expected = seal_offer(
            object_kind,
            &declaration,
            subject_ref
                .split_once("://")
                .map(|(_, tail)| tail)
                .unwrap_or(""),
            &receipt_ref,
            authorized.resolved_at_ms,
        )
        .map_err(|(_, m)| m)?;
        (
            expected,
            offer_effect(
                object_kind,
                "create",
                0,
                Some(&declaration),
                Some("offered"),
            ),
            json!({"object_kind":object_kind,"revision_before":0,"revision_after":1,"status_after":"offered","inventory_backing_proven":true,"allocation_created":false,"execution_authority_granted":false}),
        )
    } else {
        let prior = intent
            .get("prior_offer")
            .filter(|v| !v.is_null())
            .ok_or_else(|| "offer transition lacks prior".to_string())?;
        if prior.get("revision").and_then(Value::as_u64) != Some(revision)
            || prior.get(id_field).and_then(Value::as_str) != Some(subject_ref)
        {
            return Err("offer transition prior coordinates differ".into());
        }
        let (_, to) =
            transition_contract(object_kind, op, &s(prior, "status", "")).map_err(|(_, m)| m)?;
        let expected = transition_offer(prior, op, to, &receipt_ref, authorized.resolved_at_ms)
            .map_err(|(_, m)| m)?;
        (
            expected,
            offer_effect(object_kind, op, revision, None, Some(to)),
            json!({"object_kind":object_kind,"revision_before":revision,"revision_after":revision+1,"status_before":s(prior,"status",""),"status_after":to,"allocation_created":false,"execution_authority_granted":false}),
        )
    };
    if expected_final != *final_offer {
        return Err("offer successor does not reconstruct byte-exactly".into());
    }
    governed::validate_sealed_effect(contract, receipt, &expected_effect)?;
    let note = if op == "create" {
        "an admitted participant-backed offer profile; no allocation or execution authority is created"
    } else {
        "a receipted offer lifecycle mutation; historical offer evidence is retained"
    };
    let expected_receipt = build_receipt(
        receipt_tail,
        OFFER_RECEIPT_SCHEMA,
        receipt_type,
        subject_ref,
        op,
        bound_facts,
        vec![json!(room_ref), json!(participant_ref)],
        final_offer,
        note,
        &authorized,
    )
    .map_err(|(_, m)| m)?;
    if expected_receipt != *receipt {
        return Err("offer receipt does not reconstruct byte-exactly".into());
    }
    Ok(())
}

fn validate_intent(intent: &Value, tail: &str) -> Result<(AuthorityContract, Governance), String> {
    if !canonical_intent_tail(tail)
        || intent.get("schema_version").and_then(Value::as_str) != Some(INTENT_SCHEMA)
        || intent.get("intent_id").and_then(Value::as_str)
            != Some(format!("offer-intent://{tail}").as_str())
        || intent.get("intent_hash").and_then(Value::as_str)
            != Some(record_output_hash(&without_field(intent, "intent_hash"), &[]).as_str())
    {
        return Err("intent storage-key/hash binding failed".into());
    }
    validate_touched(intent)?;
    let kind = intent
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks kind".to_string())?;
    let (contract, governance) = match kind {
        "resource_create" => (RESOURCE_AUTHORITY, Governance::Participant),
        "resource_transition" => (
            RESOURCE_AUTHORITY,
            if intent.get("governance").and_then(Value::as_str) == Some("host") {
                Governance::Host
            } else {
                Governance::Participant
            },
        ),
        "capability_create" => (CAPABILITY_AUTHORITY, Governance::Participant),
        "capability_transition" => (
            CAPABILITY_AUTHORITY,
            if intent.get("governance").and_then(Value::as_str) == Some("host") {
                Governance::Host
            } else {
                Governance::Participant
            },
        ),
        "eligibility_match" => (MATCH_AUTHORITY, Governance::Host),
        _ => return Err(format!("unknown intent kind '{kind}'")),
    };
    validate_intent_exact(intent, kind, contract)?;
    Ok((contract, governance))
}
fn replay_required_authority(
    data_dir: &str,
    intent: &Value,
    governance: Governance,
) -> Result<String, String> {
    let room_ref = intent
        .get("room_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "intent lacks room".to_string())?;
    let expected = if governance == Governance::Host {
        rooms::resolve_room_host(data_dir, room_ref)
            .ok_or_else(|| "room host no longer resolves".to_string())?
    } else {
        let participant_ref = intent
            .get("participant_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| "intent lacks participant".to_string())?;
        let participant =
            participation::resolve_participant_lease_strict(data_dir, participant_ref)?
                .ok_or_else(|| "participant no longer resolves".to_string())?;
        s(&participant, "participant_ref", "")
    };
    if intent.get("required_authority_ref").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err("intent required authority differs from owner seam".into());
    }
    Ok(expected)
}
pub(crate) async fn complete_governed_offer_intents(data_dir: &str, max_intents: usize) {
    let intents = match scan_intents(data_dir) {
        Ok(v) => v,
        Err(message) => {
            eprintln!("offer completer: intent scan failed ({message})");
            return;
        }
    };
    for (tail, intent) in intents.into_iter().take(max_intents) {
        let (contract, governance) = match validate_intent(&intent, &tail) {
            Ok(v) => v,
            Err(message) => {
                eprintln!("offer completer: '{tail}' invalid ({message}); retained");
                continue;
            }
        };
        let authority = match replay_required_authority(data_dir, &intent, governance) {
            Ok(v) => v,
            Err(message) => {
                eprintln!("offer completer: '{tail}' owner refused ({message}); retained");
                continue;
            }
        };
        let room = intent.get("room_ref").and_then(Value::as_str).unwrap_or("");
        let subject = intent
            .get("subject_ref")
            .and_then(Value::as_str)
            .unwrap_or("");
        let op = intent.get("op").and_then(Value::as_str).unwrap_or("");
        let revision = intent
            .get("revision_before")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let receipt = intent.get("receipt").unwrap_or(&Value::Null);
        let effect = receipt.get("authorized_effect").unwrap_or(&Value::Null);
        if let Err(message) = governed::reauthorize_sealed_receipt(
            contract, receipt, governance, room, &authority, subject, op, revision, effect,
        )
        .await
        {
            eprintln!("offer completer: '{tail}' authority refused ({message}); retained");
            continue;
        }
        let _participant = participation::PARTICIPATION_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _resource = super::resource_routes::RESOURCE_MUTATION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _offer = OFFER_MATCH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _frontier = work::FRONTIER_CLAIM_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _room = rooms::ROOM_MUTATION_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Err((_, message)) = complete_intent_locked(data_dir, &tail, &intent) {
            eprintln!("offer completer: '{tail}' convergence failed ({message}); retained")
        }
    }
}

fn ensure_read_converged(data_dir: &str) -> Result<(), VErr> {
    let pending = scan_intents(data_dir).map_err(|m| verr("offer_intent_unreadable", m))?;
    if pending.is_empty() {
        Ok(())
    } else {
        Err(verr(
            "offer_pending_convergence",
            format!(
                "{} offer/match transaction(s) await authenticated convergence",
                pending.len()
            ),
        ))
    }
}

// ================================= HTTP MUTATIONS ===============================================

async fn create_offer(
    state: Arc<DaemonState>,
    body: Value,
    kind: &str,
) -> (StatusCode, Json<Value>) {
    let mut declaration = match if kind == "resource" {
        validate_resource_create(&body)
    } else {
        validate_capability_create(&body)
    } {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    let room_ref = s(&declaration, "outcome_room_ref", "");
    let participant_ref = s(&declaration, "provider_participant_lease_ref", "");
    if let Err(e) = resolve_open_room(&state.data_dir, &room_ref) {
        return classify(e);
    }
    let participant = match participant_strict(&state.data_dir, &participant_ref) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    if s(&participant, "outcome_room_ref", "") != room_ref {
        return classify(verr(
            "offer_cross_room",
            "provider participant and offer must name the same room",
        ));
    }
    if s(&participant, "status", "") != "active" {
        return classify(verr(
            "offer_participant_not_active",
            "only an active participant lease may publish an offer",
        ));
    }
    if kind == "resource" {
        let backing = match resolve_resource_backing(&state.data_dir, &participant, &declaration) {
            Ok(value) => value,
            Err(error) => return classify(error),
        };
        declaration
            .as_object_mut()
            .expect("resource declaration")
            .insert("inventory_backing".into(), backing);
    } else {
        if let Err(error) = verify_capability_backing(&participant, &declaration) {
            return classify(error);
        }
    }
    let participant_revision = participant
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let prefix = if kind == "resource" { "rof_" } else { "cof_" };
    let scheme = if kind == "resource" {
        "resource-offer"
    } else {
        "capability-offer"
    };
    let tail = deterministic_tail(
        prefix,
        &json!({"domain":format!("hypervisor.{kind}-offer.identity.v1"),"declaration":declaration,"participant_revision":participant_revision}),
    );
    let subject_ref = format!("{scheme}://{tail}");
    let effect = offer_effect(kind, "create", 0, Some(&declaration), Some("offered"));
    let contract = if kind == "resource" {
        RESOURCE_AUTHORITY
    } else {
        CAPABILITY_AUTHORITY
    };
    let participant_authority = s(&participant, "participant_ref", "");
    let authorized = match governed::authorize_decision(
        contract,
        &body,
        Governance::Participant,
        &room_ref,
        &participant_authority,
        &subject_ref,
        "create",
        0,
        &effect,
    )
    .await
    {
        Ok(v) => v,
        Err(challenge) => return challenge,
    };
    let _participant_guard = participation::PARTICIPATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _resource_guard = super::resource_routes::RESOURCE_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _offer_guard = OFFER_MATCH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _frontier_guard = work::FRONTIER_CLAIM_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _room_guard = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Err(e) = resolve_open_room(&state.data_dir, &room_ref) {
        return classify(e);
    }
    let current = match participant_strict(&state.data_dir, &participant_ref) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    if current != participant || s(&current, "status", "") != "active" {
        return classify(verr(
            "offer_stale_revision",
            "participant changed during authorization",
        ));
    }
    if kind == "resource" {
        if let Err(error) =
            validate_resource_backing_snapshot(&state.data_dir, &current, &declaration)
        {
            return classify(error);
        }
    }
    for reference in [&subject_ref, &participant_ref, &room_ref] {
        if let Err(e) =
            refuse_reserved(&state.data_dir, reference, "offer_mutation_in_flight", None)
        {
            return classify(e);
        }
        if let Err(e) = work::refuse_external_mutation_if_reserved(
            &state.data_dir,
            reference,
            "offer_mutation_in_flight",
        ) {
            return classify(e);
        }
    }
    let occupied = match if kind == "resource" {
        load_resource(&state.data_dir, &tail)
    } else {
        load_capability(&state.data_dir, &tail)
    } {
        Ok(v) => v,
        Err(m) => return classify(verr("offer_registry_unreadable", m)),
    };
    if occupied.is_some() {
        return classify(verr(
            "offer_conflict",
            format!("canonical offer '{subject_ref}' already exists"),
        ));
    }
    let receipt_tail = fresh_tail(
        "orm_",
        "hypervisor.offer.receipt-id.v1",
        &subject_ref,
        "create",
        0,
        authorized.resolved_at_ms,
    );
    let receipt_ref = format!("receipt://{receipt_tail}");
    let final_offer = match seal_offer(
        kind,
        &declaration,
        &tail,
        &receipt_ref,
        authorized.resolved_at_ms,
    ) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    let receipt=match build_receipt(&receipt_tail,OFFER_RECEIPT_SCHEMA,if kind=="resource"{"ResourceOfferMutationReceipt"}else{"CapabilityOfferMutationReceipt"},&subject_ref,"create",json!({"object_kind":kind,"revision_before":0,"revision_after":1,"status_after":"offered","inventory_backing_proven":true,"allocation_created":false,"execution_authority_granted":false}),vec![json!(room_ref),json!(participant_ref)],&final_offer,"an admitted participant-backed offer profile; no allocation or execution authority is created",&authorized){Ok(v)=>v,Err(e)=>return classify(e)};
    let intent_tail = fresh_tail(
        "oci_",
        "hypervisor.offer.intent-id.v1",
        &subject_ref,
        "create",
        0,
        authorized.resolved_at_ms,
    );
    let intent = seal_intent(
        json!({"kind":format!("{kind}_create"),"governance":"participant","op":"create","room_ref":room_ref,"participant_ref":participant_ref,"required_authority_ref":participant_authority,"subject_ref":subject_ref,"revision_before":0,"receipt_tail":receipt_tail,"receipt":receipt,"prior_offer":Value::Null,"final_offer":final_offer}),
        &intent_tail,
    );
    match persist_and_complete_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({"offer":final_offer,"offer_receipt":receipt})),
        ),
        Err(e) => classify(e),
    }
}
pub(crate) async fn handle_resource_create(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    create_offer(state, body, "resource").await
}
pub(crate) async fn handle_capability_create(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    create_offer(state, body, "capability").await
}

fn transition_contract(
    kind: &str,
    op: &str,
    from: &str,
) -> Result<(Governance, &'static str), VErr> {
    match (kind,op,from){("resource","withdraw","offered")=>Ok((Governance::Participant,"withdrawn")),("resource","expire","offered")=>Ok((Governance::Host,"expired")),("resource","revoke","offered")=>Ok((Governance::Host,"revoked")),("capability","withdraw","offered"|"eligible"|"suspended")=>Ok((Governance::Participant,"withdrawn")),("capability","suspend","offered"|"eligible")=>Ok((Governance::Host,"suspended")),("capability","resume","suspended")=>Ok((Governance::Host,"offered")),("capability","revoke","offered"|"eligible"|"suspended")=>Ok((Governance::Host,"revoked")),(_,"allocate"|"queue"|"exhaust",_)=>Err(verr("offer_allocation_unavailable","offer matching does not introduce allocation authority; allocation transitions remain unavailable")),_=>Err(verr("offer_transition_invalid",format!("transition '{op}' is not admitted from '{from}'")))}
}
async fn transition_offer_http(
    state: Arc<DaemonState>,
    id: String,
    body: Value,
    kind: &str,
) -> (StatusCode, Json<Value>) {
    if let Err(e) = reject_sensitive(&body, "") {
        return classify(e);
    }
    if let Err(e) = reject_unknown(
        &body,
        &["transition", "expected_revision", "wallet_approval_grant"],
    ) {
        return classify(e);
    }
    let op = match body.get("transition").and_then(Value::as_str) {
        Some(v) => v,
        None => return classify(verr("offer_transition_required", "transition is required")),
    };
    let prior = match if kind == "resource" {
        load_resource(&state.data_dir, &id)
    } else {
        load_capability(&state.data_dir, &id)
    } {
        Ok(Some(v)) => v,
        Ok(None) => return classify(verr("offer_not_found", format!("no {kind} offer '{id}'"))),
        Err(m) => return classify(verr("offer_registry_unreadable", m)),
    };
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    if let Err(e) = expected_revision(&body, revision) {
        return classify(e);
    }
    let (governance, to) = match transition_contract(kind, op, &s(&prior, "status", "")) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    let room_ref = s(&prior, "outcome_room_ref", "");
    let participant_ref = s(&prior, "provider_participant_lease_ref", "");
    let participant = match participant_strict(&state.data_dir, &participant_ref) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    let authority = if governance == Governance::Host {
        match rooms::resolve_room_host(&state.data_dir, &room_ref) {
            Some(v) => v,
            None => {
                return classify(verr(
                    "offer_host_authority_unavailable",
                    "room host does not resolve",
                ))
            }
        }
    } else {
        s(&participant, "participant_ref", "")
    };
    let id_field = if kind == "resource" {
        "resource_offer_id"
    } else {
        "capability_offer_id"
    };
    let subject_ref = s(&prior, id_field, "");
    let effect = offer_effect(kind, op, revision, None, Some(to));
    let contract = if kind == "resource" {
        RESOURCE_AUTHORITY
    } else {
        CAPABILITY_AUTHORITY
    };
    let authorized = match governed::authorize_decision(
        contract,
        &body,
        governance,
        &room_ref,
        &authority,
        &subject_ref,
        op,
        revision,
        &effect,
    )
    .await
    {
        Ok(v) => v,
        Err(challenge) => return challenge,
    };
    let _participant_guard = participation::PARTICIPATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _resource_guard = super::resource_routes::RESOURCE_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _offer_guard = OFFER_MATCH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _frontier_guard = work::FRONTIER_CLAIM_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _room_guard = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let current = match if kind == "resource" {
        load_resource(&state.data_dir, &id)
    } else {
        load_capability(&state.data_dir, &id)
    } {
        Ok(Some(v)) => v,
        Ok(None) => return classify(verr("offer_not_found", "offer vanished")),
        Err(m) => return classify(verr("offer_registry_unreadable", m)),
    };
    if current != prior {
        return classify(verr(
            "offer_stale_revision",
            "offer changed during authorization",
        ));
    }
    for reference in [&subject_ref, &participant_ref, &room_ref] {
        if let Err(e) =
            refuse_reserved(&state.data_dir, reference, "offer_mutation_in_flight", None)
        {
            return classify(e);
        }
        if let Err(e) = work::refuse_external_mutation_if_reserved(
            &state.data_dir,
            reference,
            "offer_mutation_in_flight",
        ) {
            return classify(e);
        }
    }
    let receipt_tail = fresh_tail(
        "orm_",
        "hypervisor.offer.receipt-id.v1",
        &subject_ref,
        op,
        revision,
        authorized.resolved_at_ms,
    );
    let receipt_ref = format!("receipt://{receipt_tail}");
    let final_offer =
        match transition_offer(&prior, op, to, &receipt_ref, authorized.resolved_at_ms) {
            Ok(v) => v,
            Err(e) => return classify(e),
        };
    let receipt = match build_receipt(
        &receipt_tail,
        OFFER_RECEIPT_SCHEMA,
        if kind == "resource" {
            "ResourceOfferMutationReceipt"
        } else {
            "CapabilityOfferMutationReceipt"
        },
        &subject_ref,
        op,
        json!({"object_kind":kind,"revision_before":revision,"revision_after":revision+1,"status_before":s(&prior,"status",""),"status_after":to,"allocation_created":false,"execution_authority_granted":false}),
        vec![json!(room_ref), json!(participant_ref)],
        &final_offer,
        "a receipted offer lifecycle mutation; historical offer evidence is retained",
        &authorized,
    ) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    let intent_tail = fresh_tail(
        "oci_",
        "hypervisor.offer.intent-id.v1",
        &subject_ref,
        op,
        revision,
        authorized.resolved_at_ms,
    );
    let intent = seal_intent(
        json!({"kind":format!("{kind}_transition"),"governance":if governance==Governance::Host{"host"}else{"participant"},"op":op,"room_ref":room_ref,"participant_ref":participant_ref,"required_authority_ref":authority,"subject_ref":subject_ref,"revision_before":revision,"receipt_tail":receipt_tail,"receipt":receipt,"prior_offer":prior,"final_offer":final_offer}),
        &intent_tail,
    );
    match persist_and_complete_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"offer":final_offer,"offer_receipt":receipt})),
        ),
        Err(e) => classify(e),
    }
}
pub(crate) async fn handle_resource_transition(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    transition_offer_http(state, id, body, "resource").await
}
pub(crate) async fn handle_capability_transition(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    transition_offer_http(state, id, body, "capability").await
}

fn selected_refs(body: &Value, key: &str, resource: bool) -> Result<Vec<String>, VErr> {
    let items = body.get(key).and_then(Value::as_array).ok_or_else(|| {
        verr(
            "work_eligibility_selection_invalid",
            format!("'{key}' must be a list"),
        )
    })?;
    if items.len() > REF_LIST_MAX {
        return Err(verr(
            "work_eligibility_selection_invalid",
            format!("'{key}' exceeds {REF_LIST_MAX} entries"),
        ));
    }
    let mut out = Vec::new();
    for item in items {
        let reference = item.as_str().ok_or_else(|| {
            verr(
                "work_eligibility_selection_invalid",
                format!("'{key}' entries must be refs"),
            )
        })?;
        if !(if resource {
            canonical_resource_ref(reference)
        } else {
            canonical_capability_ref(reference)
        }) {
            return Err(verr(
                "work_eligibility_selection_invalid",
                format!("noncanonical offer ref '{reference}'"),
            ));
        }
        if out.iter().any(|v| v == reference) {
            return Err(verr(
                "work_eligibility_selection_invalid",
                format!("duplicate offer ref '{reference}'"),
            ));
        }
        out.push(reference.to_string())
    }
    Ok(out)
}
fn validate_claim_ref_selection(
    body: &Value,
    participant: &Value,
) -> Result<(Vec<String>, Vec<String>), VErr> {
    let context = ref_list(body, "context_lease_refs", &["context_lease"])?;
    let authority = ref_list(
        body,
        "authority_resource_compute_data_budget_and_tool_lease_refs",
        &[
            "grant",
            "resource-lease",
            "compute",
            "view",
            "budget",
            "tool-lease",
        ],
    )?;
    let admitted = union_fields(
        participant,
        &[
            "context_and_authority_lease_refs",
            "runtime_resource_and_budget_lease_refs",
            "tool_connector_and_capability_dependency_refs",
        ],
    );
    for reference in context.iter().chain(authority.iter()) {
        if !admitted.contains(reference) {
            return Err(verr(
                "work_eligibility_claim_lease_unproven",
                format!("claim lease ref '{reference}' is not bound to the participant lease"),
            ));
        }
    }
    Ok((context, authority))
}
fn load_selected_offers(
    data_dir: &str,
    room_ref: &str,
    participant: &Value,
    resource_refs: &[String],
    capability_refs: &[String],
) -> Result<(Vec<Value>, Vec<Value>), VErr> {
    let participant_ref = s(participant, "participant_lease_id", "");
    let mut resources = Vec::new();
    for reference in resource_refs {
        let offer = load_resource(data_dir, reference)
            .map_err(|m| verr("work_eligibility_offer_registry_unreadable", m))?
            .ok_or_else(|| {
                verr(
                    "work_eligibility_offer_not_found",
                    format!("no resource offer '{reference}'"),
                )
            })?;
        if s(&offer, "outcome_room_ref", "") != room_ref
            || s(&offer, "provider_participant_lease_ref", "") != participant_ref
        {
            return Err(verr(
                "work_eligibility_offer_mismatch",
                format!("resource offer '{reference}' belongs to a foreign room or participant"),
            ));
        }
        if !LIVE_RESOURCE.contains(&s(&offer, "status", "").as_str()) {
            return Err(verr(
                "work_eligibility_offer_not_active",
                format!("resource offer '{reference}' is not offered"),
            ));
        }
        validate_resource_backing_snapshot(data_dir, participant, &offer)?;
        resources.push(offer)
    }
    let mut capabilities = Vec::new();
    for reference in capability_refs {
        let offer = load_capability(data_dir, reference)
            .map_err(|m| verr("work_eligibility_offer_registry_unreadable", m))?
            .ok_or_else(|| {
                verr(
                    "work_eligibility_offer_not_found",
                    format!("no capability offer '{reference}'"),
                )
            })?;
        if s(&offer, "outcome_room_ref", "") != room_ref
            || s(&offer, "provider_participant_lease_ref", "") != participant_ref
        {
            return Err(verr(
                "work_eligibility_offer_mismatch",
                format!("capability offer '{reference}' belongs to a foreign room or participant"),
            ));
        }
        if !LIVE_CAPABILITY.contains(&s(&offer, "status", "").as_str()) {
            return Err(verr(
                "work_eligibility_offer_not_active",
                format!("capability offer '{reference}' is not active"),
            ));
        }
        capabilities.push(offer)
    }
    Ok((resources, capabilities))
}
fn offer_coordinates(offers: &[Value], field: &str) -> Vec<Value> {
    offers.iter().map(|offer|json!({"offer_ref":offer.get(field).cloned().unwrap_or(Value::Null),"revision":offer.get("revision").cloned().unwrap_or(Value::Null),"control_hash":offer_control_hash(offer)})).collect()
}

pub(crate) async fn handle_match_create(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(e) = reject_sensitive(&body, "") {
        return classify(e);
    }
    if let Err(e) = reject_unknown(
        &body,
        &[
            "outcome_room_ref",
            "frontier_item_ref",
            "participant_ref",
            "resource_offer_refs",
            "capability_offer_refs",
            "context_lease_refs",
            "authority_resource_compute_data_budget_and_tool_lease_refs",
            "coordination_topology",
            "expected_revision",
            "wallet_approval_grant",
        ],
    ) {
        return classify(e);
    }
    if body.get("coordination_topology").and_then(Value::as_str) != Some("hosted_admission") {
        return classify(verr(
            "work_eligibility_federated_unavailable",
            "federated/AIIP matching is unavailable",
        ));
    }
    let room_ref = match required_ref(&body, "outcome_room_ref", &["outcome-room"]) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    let frontier_ref = match required_ref(&body, "frontier_item_ref", &["frontier"]) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    let participant_ref = match required_ref(&body, "participant_ref", &["participant-lease"]) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    let resource_refs = match selected_refs(&body, "resource_offer_refs", true) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    let capability_refs = match selected_refs(&body, "capability_offer_refs", false) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    if let Err(e) = resolve_open_room(&state.data_dir, &room_ref) {
        return classify(e);
    }
    let frontier = match work::load_frontier_strict(&state.data_dir, &frontier_ref) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return classify(verr(
                "work_eligibility_frontier_not_found",
                format!("no frontier '{frontier_ref}'"),
            ))
        }
        Err(m) => return classify(verr("work_eligibility_frontier_registry_unreadable", m)),
    };
    if s(&frontier, "outcome_room_ref", "") != room_ref {
        return classify(verr(
            "work_eligibility_cross_room",
            "frontier and match room differ",
        ));
    }
    let revision = frontier
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if let Err(e) = expected_revision(&body, revision) {
        return classify(e);
    }
    let participant = match participant_strict(&state.data_dir, &participant_ref) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    if s(&participant, "outcome_room_ref", "") != room_ref
        || s(&participant, "status", "") != "active"
    {
        return classify(verr(
            "work_eligibility_participant_not_active",
            "matching requires an active same-room participant",
        ));
    }
    let (context_refs, authority_refs) = match validate_claim_ref_selection(&body, &participant) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    let (resources, capabilities) = match load_selected_offers(
        &state.data_dir,
        &room_ref,
        &participant,
        &resource_refs,
        &capability_refs,
    ) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    let item_kind = s(&frontier, "item_kind", "");
    for offer in resources.iter().chain(capabilities.iter()) {
        let classes = if offer.get("resource_offer_id").is_some() {
            array_strings(offer, "eligible_work_classes")
        } else {
            array_strings(offer, "eligible_frontier_classes")
        };
        if !classes
            .iter()
            .any(|class| class == "*" || class == &item_kind)
        {
            return classify(verr(
                "work_eligibility_work_class_mismatch",
                format!("selected offer is not eligible for frontier class '{item_kind}'"),
            ));
        }
    }
    let mut claim_refs = context_refs.clone();
    claim_refs.extend(authority_refs.clone());
    let (coverage, offer_prerequisite_coverage, unsupported) = match collect_match_coverage(
        &frontier,
        &participant,
        &resources,
        &capabilities,
        &claim_refs,
    ) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    if !unsupported.is_empty() {
        return classify(verr(
            "work_eligibility_requirement_proof_unavailable",
            format!(
                "offer/frontier prerequisites [{}] need a resolvable policy/scope/context proof plane; matching refuses caller assertions",
                unsupported.join(", ")
            ),
        ));
    }
    let tuple = json!({"outcome_room_ref":room_ref,"frontier_item_ref":frontier_ref,"frontier_revision":revision,"frontier_control_hash":work::frontier_claim_control_hash(&frontier),"participant_ref":participant_ref,"participant_revision":participant.get("revision").cloned().unwrap_or(Value::Null),"participant_control_hash":participant_control_hash(&participant),"resource_offers":offer_coordinates(&resources,"resource_offer_id"),"capability_offers":offer_coordinates(&capabilities,"capability_offer_id"),"context_lease_refs":context_refs,"authority_resource_compute_data_budget_and_tool_lease_refs":authority_refs,"requirement_coverage":coverage,"offer_prerequisite_coverage":offer_prerequisite_coverage,"allocation_created":false,"execution_authority_granted":false,"claim_created":false});
    let match_tail = deterministic_tail(
        "wem_",
        &json!({"domain":"hypervisor.work-eligibility-match.identity.v1","tuple":tuple}),
    );
    let match_ref = format!("receipt://{match_tail}");
    let effect = match_effect(&tuple);
    let host = match rooms::resolve_room_host(&state.data_dir, &room_ref) {
        Some(v) => v,
        None => {
            return classify(verr(
                "work_eligibility_host_authority_unavailable",
                "room host does not resolve",
            ))
        }
    };
    let authorized = match governed::authorize_decision(
        MATCH_AUTHORITY,
        &body,
        Governance::Host,
        &room_ref,
        &host,
        &match_ref,
        "match",
        revision,
        &effect,
    )
    .await
    {
        Ok(v) => v,
        Err(challenge) => return challenge,
    };
    let _participant_guard = participation::PARTICIPATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _resource_guard = super::resource_routes::RESOURCE_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _offer_guard = OFFER_MATCH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _frontier_guard = work::FRONTIER_CLAIM_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _room_guard = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Err(e) = resolve_open_room(&state.data_dir, &room_ref) {
        return classify(e);
    }
    let current_participant = match participant_strict(&state.data_dir, &participant_ref) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    let current_frontier = match work::load_frontier_strict(&state.data_dir, &frontier_ref) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return classify(verr(
                "work_eligibility_frontier_not_found",
                "frontier vanished",
            ))
        }
        Err(m) => return classify(verr("work_eligibility_frontier_registry_unreadable", m)),
    };
    let (current_resources, current_capabilities) = match load_selected_offers(
        &state.data_dir,
        &room_ref,
        &current_participant,
        &resource_refs,
        &capability_refs,
    ) {
        Ok(v) => v,
        Err(e) => return classify(e),
    };
    if current_participant != participant
        || current_frontier != frontier
        || current_resources != resources
        || current_capabilities != capabilities
    {
        return classify(verr(
            "work_eligibility_stale_revision",
            "frontier, participant, or offer changed during authorization",
        ));
    }
    for reference in std::iter::once(match_ref.as_str())
        .chain(std::iter::once(room_ref.as_str()))
        .chain(std::iter::once(participant_ref.as_str()))
        .chain(std::iter::once(frontier_ref.as_str()))
        .chain(resource_refs.iter().map(String::as_str))
        .chain(capability_refs.iter().map(String::as_str))
    {
        if let Err(e) = refuse_reserved(
            &state.data_dir,
            reference,
            "work_eligibility_mutation_in_flight",
            None,
        ) {
            return classify(e);
        }
        if let Err(e) = work::refuse_external_mutation_if_reserved(
            &state.data_dir,
            reference,
            "work_eligibility_mutation_in_flight",
        ) {
            return classify(e);
        }
    }
    match existing_match_receipt_exact(&state.data_dir, &match_ref, &tuple) {
        Ok(Some(receipt)) => {
            return (
                StatusCode::OK,
                Json(json!({"eligibility_match_receipt":receipt,"idempotent":true})),
            )
        }
        Ok(None) => {}
        Err(error) => return classify(error),
    }
    for offer in &resources {
        match resource_offer_expired_at(offer, authorized.resolved_at_ms) {
            Ok(true) => {
                return classify(verr(
                    "work_eligibility_offer_expired",
                    "a selected resource offer is expired at wallet.network committed time",
                ))
            }
            Ok(false) => {}
            Err((_, message)) => {
                return classify(verr("work_eligibility_offer_registry_unreadable", message))
            }
        }
    }
    let receipt=match build_receipt(&match_tail,MATCH_RECEIPT_SCHEMA,"WorkEligibilityMatchReceipt",&match_ref,"match",tuple.clone(),vec![json!(room_ref),json!(frontier_ref),json!(participant_ref)],&tuple,"a host-admitted exact eligibility match; it creates no allocation, execution authority, or claim",&authorized){Ok(v)=>v,Err(e)=>return classify(e)};
    let intent_tail = fresh_tail(
        "oci_",
        "hypervisor.offer.intent-id.v1",
        &match_ref,
        "match",
        revision,
        authorized.resolved_at_ms,
    );
    let intent = seal_intent(
        json!({"kind":"eligibility_match","governance":"host","op":"match","room_ref":room_ref,"participant_ref":participant_ref,"required_authority_ref":host,"subject_ref":match_ref,"revision_before":revision,"receipt_tail":match_tail,"receipt":receipt,"prior_offer":Value::Null,"final_offer":Value::Null}),
        &intent_tail,
    );
    match persist_and_complete_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({"eligibility_match_receipt":receipt})),
        ),
        Err(e) => classify(e),
    }
}

/// Claim-side proof gate. Caller holds participation -> offers -> frontier locks and passes the
/// exact participant/frontier records it is about to mutate. No network I/O occurs here.
pub(crate) fn validate_eligibility_for_claim_locked(
    data_dir: &str,
    receipt_ref: Option<&str>,
    frontier: &Value,
    participant: &Value,
    claim_declaration: &Value,
    resolved_at_ms: Option<u64>,
) -> Result<(), VErr> {
    let capability = array_strings(frontier, "required_capability_refs");
    let other = array_strings(
        frontier,
        "required_context_resource_authority_and_evidence_refs",
    );
    if capability.is_empty() && other.is_empty() {
        if receipt_ref.is_some() {
            return Err(verr(
                "work_claim_eligibility_receipt_unexpected",
                "requirement-free frontier must not carry an eligibility receipt",
            ));
        }
        return Ok(());
    }
    let reference = receipt_ref.ok_or_else(|| {
        verr(
            "work_claim_eligibility_receipt_required",
            "requirement-bearing frontier requires a receipted eligibility match",
        )
    })?;
    if !canonical_match_ref(reference) {
        return Err(verr(
            "work_claim_eligibility_receipt_invalid",
            "eligibility receipt must be receipt://wem_<64 lowercase hex>",
        ));
    }
    let receipt = load_match_receipt(data_dir, reference)
        .map_err(|m| verr("work_claim_eligibility_receipt_unreadable", m))?
        .ok_or_else(|| {
            verr(
                "work_claim_eligibility_receipt_not_found",
                format!("no eligibility receipt '{reference}'"),
            )
        })?;
    let facts = receipt.get("bound_facts").ok_or_else(|| {
        verr(
            "work_claim_eligibility_receipt_unreadable",
            "eligibility receipt lacks bound facts",
        )
    })?;
    let expected_tail = deterministic_tail(
        "wem_",
        &json!({"domain":"hypervisor.work-eligibility-match.identity.v1","tuple":facts}),
    );
    if reference != format!("receipt://{expected_tail}") {
        return Err(verr(
            "work_claim_eligibility_receipt_invalid",
            "eligibility receipt identity does not derive from its exact tuple",
        ));
    }
    let expected_effect = match_effect(facts);
    governed::validate_sealed_effect(MATCH_AUTHORITY, &receipt, &expected_effect)
        .map_err(|m| verr("work_claim_eligibility_receipt_invalid", m))?;
    let authorized = sealed_authorized(&receipt)
        .map_err(|m| verr("work_claim_eligibility_receipt_invalid", m))?;
    let expected_receipt=build_receipt(&expected_tail,MATCH_RECEIPT_SCHEMA,"WorkEligibilityMatchReceipt",reference,"match",facts.clone(),vec![facts.get("outcome_room_ref").cloned().unwrap_or(Value::Null),facts.get("frontier_item_ref").cloned().unwrap_or(Value::Null),facts.get("participant_ref").cloned().unwrap_or(Value::Null)],facts,"a host-admitted exact eligibility match; it creates no allocation, execution authority, or claim",&authorized)?;
    if expected_receipt != receipt {
        return Err(verr(
            "work_claim_eligibility_receipt_invalid",
            "eligibility receipt does not reconstruct byte-exactly",
        ));
    }
    if receipt.get("subject_ref").and_then(Value::as_str) != Some(reference)
        || facts.get("allocation_created") != Some(&Value::Bool(false))
        || facts.get("execution_authority_granted") != Some(&Value::Bool(false))
        || facts.get("claim_created") != Some(&Value::Bool(false))
    {
        return Err(verr("work_claim_eligibility_receipt_invalid","eligibility receipt claims allocation, execution authority, a claim, or foreign identity"));
    }
    let frontier_ref = s(frontier, "frontier_item_id", "");
    let participant_ref = s(participant, "participant_lease_id", "");
    if facts.get("outcome_room_ref").and_then(Value::as_str)
        != frontier.get("outcome_room_ref").and_then(Value::as_str)
        || facts.get("frontier_item_ref").and_then(Value::as_str) != Some(frontier_ref.as_str())
        || facts.get("frontier_revision") != frontier.get("revision")
        || facts.get("frontier_control_hash").and_then(Value::as_str)
            != Some(work::frontier_claim_control_hash(frontier).as_str())
        || facts.get("participant_ref").and_then(Value::as_str) != Some(participant_ref.as_str())
        || facts.get("participant_revision") != participant.get("revision")
        || facts
            .get("participant_control_hash")
            .and_then(Value::as_str)
            != Some(participant_control_hash(participant).as_str())
    {
        return Err(verr(
            "work_claim_eligibility_stale",
            "eligibility receipt no longer matches exact frontier/participant coordinates",
        ));
    }
    if facts.get("context_lease_refs") != claim_declaration.get("context_lease_refs")
        || facts.get("authority_resource_compute_data_budget_and_tool_lease_refs")
            != claim_declaration.get("authority_resource_compute_data_budget_and_tool_lease_refs")
    {
        return Err(verr(
            "work_claim_eligibility_claim_tuple_mismatch",
            "claim lease refs differ from the matched eligibility tuple",
        ));
    }
    let mut resources = Vec::new();
    let mut capabilities = Vec::new();
    for (field, resource) in [("resource_offers", true), ("capability_offers", false)] {
        let coords = facts.get(field).and_then(Value::as_array).ok_or_else(|| {
            verr(
                "work_claim_eligibility_receipt_unreadable",
                format!("missing {field}"),
            )
        })?;
        for coordinate in coords {
            let reference = coordinate
                .get("offer_ref")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    verr(
                        "work_claim_eligibility_receipt_unreadable",
                        "offer coordinate lacks ref",
                    )
                })?;
            let offer = if resource {
                load_resource(data_dir, reference)
            } else {
                load_capability(data_dir, reference)
            }
            .map_err(|m| verr("work_claim_eligibility_offer_unreadable", m))?
            .ok_or_else(|| {
                verr(
                    "work_claim_eligibility_offer_not_found",
                    format!("matched offer '{reference}' vanished"),
                )
            })?;
            let live = if resource {
                LIVE_RESOURCE.contains(&s(&offer, "status", "").as_str())
            } else {
                LIVE_CAPABILITY.contains(&s(&offer, "status", "").as_str())
            };
            if !live
                || s(&offer, "provider_participant_lease_ref", "") != participant_ref
                || coordinate.get("revision") != offer.get("revision")
                || coordinate.get("control_hash").and_then(Value::as_str)
                    != Some(offer_control_hash(&offer).as_str())
            {
                return Err(verr("work_claim_eligibility_stale",format!("matched offer '{reference}' changed, became inactive, or belongs to another participant")));
            }
            if resource {
                validate_resource_backing_snapshot(data_dir, participant, &offer)?;
                if resolved_at_ms
                    .map(|now| resource_offer_expired_at(&offer, now))
                    .transpose()?
                    .unwrap_or(false)
                {
                    return Err(verr(
                        "work_claim_eligibility_offer_expired",
                        "matched resource offer expired before claim linearization at wallet.network committed time",
                    ));
                }
                resources.push(offer);
            } else {
                capabilities.push(offer);
            }
        }
    }
    let mut claim_refs = array_strings(claim_declaration, "context_lease_refs");
    claim_refs.extend(array_strings(
        claim_declaration,
        "authority_resource_compute_data_budget_and_tool_lease_refs",
    ));
    let (expected_coverage, expected_offer_prerequisite_coverage, unsupported) =
        collect_match_coverage(
            frontier,
            participant,
            &resources,
            &capabilities,
            &claim_refs,
        )?;
    if !unsupported.is_empty() {
        return Err(verr(
            "work_claim_eligibility_requirement_proof_unavailable",
            format!(
                "offer/frontier prerequisites [{}] remain unsupported at claim admission",
                unsupported.join(", ")
            ),
        ));
    }
    if facts.get("requirement_coverage") != Some(&Value::Array(expected_coverage)) {
        return Err(verr(
            "work_claim_eligibility_receipt_invalid",
            "receipt requirement coverage does not recompute exactly",
        ));
    }
    if facts.get("offer_prerequisite_coverage")
        != Some(&Value::Array(expected_offer_prerequisite_coverage))
    {
        return Err(verr(
            "work_claim_eligibility_receipt_invalid",
            "receipt offer-prerequisite coverage does not recompute exactly",
        ));
    }
    Ok(())
}

pub(crate) async fn reauthorize_eligibility_for_claim(
    data_dir: &str,
    receipt_ref: Option<&str>,
    frontier: &Value,
    participant: &Value,
    claim_declaration: &Value,
) -> Result<Option<u64>, (StatusCode, Json<Value>)> {
    if let Err(error) = validate_eligibility_for_claim_locked(
        data_dir,
        receipt_ref,
        frontier,
        participant,
        claim_declaration,
        None,
    ) {
        return Err(classify(error));
    }
    let Some(reference) = receipt_ref else {
        return Ok(None);
    };
    let receipt = match load_match_receipt(data_dir, reference) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return Err(classify(verr(
                "work_claim_eligibility_receipt_not_found",
                format!("no eligibility receipt '{reference}'"),
            )))
        }
        Err(m) => {
            return Err(classify(verr(
                "work_claim_eligibility_receipt_unreadable",
                m,
            )))
        }
    };
    let facts = receipt.get("bound_facts").cloned().unwrap_or(Value::Null);
    let room_ref = facts
        .get("outcome_room_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    let host = match rooms::resolve_room_host(data_dir, room_ref) {
        Some(v) => v,
        None => {
            return Err(classify(verr(
                "work_claim_eligibility_host_authority_unavailable",
                "eligibility receipt room host no longer resolves",
            )))
        }
    };
    let revision = facts
        .get("frontier_revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let effect = match_effect(&facts);
    governed::reauthorize_sealed_receipt(
        MATCH_AUTHORITY,
        &receipt,
        Governance::Host,
        room_ref,
        &host,
        reference,
        "match",
        revision,
        &effect,
    )
    .await
    .map(Some)
    .map_err(|message| {
        classify(verr(
            "work_claim_eligibility_reauthorization_refused",
            message,
        ))
    })
}

// ================================= HTTP READS ===================================================

fn filter_rows(mut rows: Vec<Value>, query: &HashMap<String, String>) -> Vec<Value> {
    rows.retain(|record| {
        query
            .get("room")
            .map(|v| s(record, "outcome_room_ref", "") == *v)
            .unwrap_or(true)
            && query
                .get("participant")
                .map(|v| s(record, "provider_participant_lease_ref", "") == *v)
                .unwrap_or(true)
            && query
                .get("status")
                .map(|v| s(record, "status", "") == *v)
                .unwrap_or(true)
    });
    rows.sort_by(|a, b| s(b, "created_at", "").cmp(&s(a, "created_at", "")));
    rows.truncate(LIST_MAX);
    rows
}
async fn list_offers(
    state: Arc<DaemonState>,
    query: HashMap<String, String>,
    resource: bool,
) -> (StatusCode, Json<Value>) {
    if let Err(e) = ensure_read_converged(&state.data_dir) {
        return classify(e);
    }
    let records = match scan_offers(
        &state.data_dir,
        if resource {
            RESOURCE_DIR
        } else {
            CAPABILITY_DIR
        },
        if resource {
            canonical_resource_tail
        } else {
            canonical_capability_tail
        },
    ) {
        Ok(v) => v.into_iter().map(|(_, v)| v).collect(),
        Err(m) => return classify(verr("offer_registry_unreadable", m)),
    };
    let mut payload = Map::new();
    payload.insert(
        if resource {
            "resource_offers".into()
        } else {
            "capability_offers".into()
        },
        json!(filter_rows(records, &query)),
    );
    payload.insert(
        "authority".into(),
        governed::decision_authority_posture(if resource {
            RESOURCE_AUTHORITY
        } else {
            CAPABILITY_AUTHORITY
        }),
    );
    payload.insert("runtimeTruthSource".into(), json!("daemon-runtime"));
    (StatusCode::OK, Json(Value::Object(payload)))
}
pub(crate) async fn handle_resource_list(
    State(state): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    list_offers(state, query, true).await
}
pub(crate) async fn handle_capability_list(
    State(state): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    list_offers(state, query, false).await
}
async fn get_offer(
    state: Arc<DaemonState>,
    id: String,
    resource: bool,
) -> (StatusCode, Json<Value>) {
    if let Err(e) = ensure_read_converged(&state.data_dir) {
        return classify(e);
    }
    match if resource {
        load_resource(&state.data_dir, &id)
    } else {
        load_capability(&state.data_dir, &id)
    } {
        Ok(Some(v)) => (StatusCode::OK, Json(json!({"offer":v}))),
        Ok(None) => classify(verr("offer_not_found", format!("no offer '{id}'"))),
        Err(m) => classify(verr("offer_registry_unreadable", m)),
    }
}
pub(crate) async fn handle_resource_get(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    get_offer(state, id, true).await
}
pub(crate) async fn handle_capability_get(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    get_offer(state, id, false).await
}
async fn overview(state: Arc<DaemonState>, resource: bool) -> (StatusCode, Json<Value>) {
    let pending = match scan_intents(&state.data_dir) {
        Ok(v) => v.len(),
        Err(m) => return classify(verr("offer_intent_unreadable", m)),
    };
    let records = match scan_offers(
        &state.data_dir,
        if resource {
            RESOURCE_DIR
        } else {
            CAPABILITY_DIR
        },
        if resource {
            canonical_resource_tail
        } else {
            canonical_capability_tail
        },
    ) {
        Ok(v) => v,
        Err(m) => return classify(verr("offer_registry_unreadable", m)),
    };
    (
        StatusCode::OK,
        Json(
            json!({"schema_version":if resource{RESOURCE_SCHEMA}else{CAPABILITY_SCHEMA},"count":records.len(),"pending_convergence_count":pending,"coordination_topology":"hosted_admission","allocation_authority":"not_provided","execution_authority":"not_provided","federated_admission":"typed_unavailable","authority":governed::decision_authority_posture(if resource{RESOURCE_AUTHORITY}else{CAPABILITY_AUTHORITY}),"runtimeTruthSource":"daemon-runtime"}),
        ),
    )
}
pub(crate) async fn handle_resource_overview(
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    overview(state, true).await
}
pub(crate) async fn handle_capability_overview(
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    overview(state, false).await
}
pub(crate) async fn handle_match_list(
    State(state): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if let Err(e) = ensure_read_converged(&state.data_dir) {
        return classify(e);
    }
    let mut receipts = match scan_match_receipts(&state.data_dir) {
        Ok(v) => v,
        Err(m) => return classify(verr("work_eligibility_receipt_unreadable", m)),
    };
    receipts.retain(|receipt| {
        let facts = receipt.get("bound_facts").unwrap_or(&Value::Null);
        query
            .get("room")
            .map(|v| facts.get("outcome_room_ref").and_then(Value::as_str) == Some(v.as_str()))
            .unwrap_or(true)
            && query
                .get("frontier")
                .map(|v| facts.get("frontier_item_ref").and_then(Value::as_str) == Some(v.as_str()))
                .unwrap_or(true)
            && query
                .get("participant")
                .map(|v| facts.get("participant_ref").and_then(Value::as_str) == Some(v.as_str()))
                .unwrap_or(true)
    });
    receipts.truncate(LIST_MAX);
    (
        StatusCode::OK,
        Json(json!({"eligibility_match_receipts":receipts,"runtimeTruthSource":"daemon-runtime"})),
    )
}
pub(crate) async fn handle_match_get(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    if let Err(e) = ensure_read_converged(&state.data_dir) {
        return classify(e);
    }
    match load_match_receipt(&state.data_dir, &id) {
        Ok(Some(v)) => (StatusCode::OK, Json(json!({"eligibility_match_receipt":v}))),
        Ok(None) => classify(verr(
            "work_eligibility_receipt_not_found",
            format!("no eligibility receipt '{id}'"),
        )),
        Err(m) => classify(verr("work_eligibility_receipt_unreadable", m)),
    }
}
pub(crate) async fn handle_match_overview(
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    let receipts = match scan_match_receipts(&state.data_dir) {
        Ok(v) => v,
        Err(m) => return classify(verr("work_eligibility_receipt_unreadable", m)),
    };
    let pending = match scan_intents(&state.data_dir) {
        Ok(v) => v.len(),
        Err(m) => return classify(verr("offer_intent_unreadable", m)),
    };
    (
        StatusCode::OK,
        Json(
            json!({"schema_version":MATCH_RECEIPT_SCHEMA,"count":receipts.len(),"pending_convergence_count":pending,"allocation_created":false,"execution_authority_granted":false,"claim_created_by_matching":false,"authority":governed::decision_authority_posture(MATCH_AUTHORITY),"runtimeTruthSource":"daemon-runtime"}),
        ),
    )
}

/// Room-close seam under OFFER_MATCH_LOCK. Live offers and pending offer/match transactions keep
/// the room open; allocation is deliberately outside this plane.
pub(crate) fn refuse_room_close_if_blocked_locked(
    data_dir: &str,
    room_ref: &str,
) -> Result<(), VErr> {
    let resources = scan_offers(data_dir, RESOURCE_DIR, canonical_resource_tail)
        .map_err(|m| verr("outcome_room_offer_registry_unreadable", m))?
        .into_iter()
        .filter(|(_, v)| {
            s(v, "outcome_room_ref", "") == room_ref
                && LIVE_RESOURCE.contains(&s(v, "status", "").as_str())
        })
        .count();
    let capabilities = scan_offers(data_dir, CAPABILITY_DIR, canonical_capability_tail)
        .map_err(|m| verr("outcome_room_offer_registry_unreadable", m))?
        .into_iter()
        .filter(|(_, v)| {
            s(v, "outcome_room_ref", "") == room_ref
                && LIVE_CAPABILITY.contains(&s(v, "status", "").as_str())
        })
        .count();
    let pending = scan_intents(data_dir)
        .map_err(|m| verr("outcome_room_offer_intent_unreadable", m))?
        .into_iter()
        .filter(|(_, v)| v.get("room_ref").and_then(Value::as_str) == Some(room_ref))
        .count();
    if resources + capabilities + pending > 0 {
        Err(verr("outcome_room_close_blocked_offers",format!("room has {resources} live resource offer(s), {capabilities} live capability offer(s), and {pending} pending offer/match transaction(s)")))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod offer_match_tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("ioi-offer-match-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn participant() -> Value {
        json!({
            "participant_lease_id":"participant-lease://rpl_ab",
            "outcome_room_ref":"outcome-room://or_ab",
            "participant_ref":"worker://worker-ab",
            "status":"active","revision":4,"updated_at":"2027-01-15T08:00:00Z",
            "worker_and_runtime_refs":["runtime://rt-ab"],
            "capability_advertisement_refs":["ai://cap-ab"],
            "tool_connector_and_capability_dependency_refs":[],
            "identity_and_eligibility_evidence_refs":["evidence://ev-ab"],
            "context_and_authority_lease_refs":[],"runtime_resource_and_budget_lease_refs":[],
            "current_claim_ref":null,"admission_and_replay_refs":[],"status_history":[]
        })
    }

    fn frontier() -> Value {
        json!({
            "schema_version":"ioi.hypervisor.work-frontier-item.v1",
            "frontier_item_id":format!("frontier://wfi_{}","11".repeat(32)),
            "outcome_room_ref":"outcome-room://or_ab","item_kind":"task","status":"open","revision":3,
            "required_capability_refs":["ai://cap-ab"],
            "required_context_resource_authority_and_evidence_refs":["evidence://ev-ab"],
            "claim_refs":[],"active_claim_refs":[],"updated_at":"2027-01-15T08:00:00Z"
        })
    }

    fn authorized(effect: &Value) -> AuthorizedDecision {
        AuthorizedDecision {
            evidence: DecisionEvidence {
                acting_authority_id: Value::Null,
                grant_ref: String::new(),
                policy_hash: String::new(),
                request_hash: String::new(),
                effect_hash: governed::decision_effect_hash(MATCH_AUTHORITY, effect),
                authorized_effect: effect.clone(),
                wallet_approval_grant: Value::Null,
                authority_binding: Value::Null,
            },
            resolved_at_ms: 1_800_000_000_000,
        }
    }

    #[test]
    fn validators_bind_inventory_and_refuse_secret_or_unbacked_profiles() {
        let body = json!({
            "outcome_room_ref":"outcome-room://or_ab","provider_or_participant_ref":"participant-lease://rpl_ab",
            "resource_profile_ref":"runtime://rt-ab","capacity_and_availability_ref":"capacity://cap-ab",
            "locality_and_custody_refs":[],"trust_and_assurance_refs":[],"cost_ref":null,
            "eligible_work_classes":["task"],"policy_constraint_refs":[],"allocation_policy_ref":"policy://allocate",
            "queue_preemption_and_fairness_policy_ref":"policy://fair","expires_at":null,
            "coordination_topology":"hosted_admission","expected_revision":0
        });
        let declaration = validate_resource_create(&body).unwrap();
        let backing =
            resolve_resource_backing("/definitely-unused", &participant(), &declaration).unwrap();
        assert_eq!(backing["kind"], "participant_inventory_ref");
        let mut unbacked = declaration.clone();
        unbacked["resource_profile_ref"] = json!("runtime://foreign");
        assert_eq!(
            resolve_resource_backing("/definitely-unused", &participant(), &unbacked)
                .unwrap_err()
                .0,
            "resource_offer_inventory_unavailable"
        );
        let mut secret = body;
        secret["nested"] = json!({"api_token":"plaintext"});
        assert_eq!(
            validate_resource_create(&secret).unwrap_err().0,
            "offer_field_unknown"
        );
        assert_eq!(
            reject_sensitive(&secret, "").unwrap_err().0,
            "offer_plaintext_secret_rejected"
        );
    }

    #[test]
    fn matching_covers_exact_requirements_and_refuses_unprovable_scope() {
        let participant = participant();
        let frontier = frontier();
        let capability = json!({"capability_offer_id":format!("capability-offer://cof_{}","33".repeat(32)),"capability_descriptor_refs":["ai://cap-ab"],"model_harness_tool_and_connector_refs":[],"authority_and_context_requirements":[]});
        let (coverage, offer_prerequisites, unsupported) =
            collect_match_coverage(&frontier, &participant, &[], &[capability.clone()], &[])
                .unwrap();
        assert_eq!(coverage.len(), 2);
        assert_eq!(offer_prerequisites.len(), 1);
        assert_eq!(offer_prerequisites[0]["prerequisite_refs"], json!([]));
        assert!(unsupported.is_empty());
        assert_eq!(
            collect_match_coverage(&frontier, &participant, &[], &[], &[])
                .unwrap_err()
                .0,
            "work_eligibility_requirements_unmatched"
        );
        let mut scoped = frontier;
        scoped["required_context_resource_authority_and_evidence_refs"] = json!(["scope:execute"]);
        let (_, _, unsupported) =
            collect_match_coverage(&scoped, &participant, &[], &[capability], &[]).unwrap();
        assert_eq!(unsupported, vec!["scope:execute"]);
    }

    #[test]
    fn offer_prerequisites_are_constraints_never_proof() {
        let participant = participant();
        let mut frontier = frontier();
        frontier["required_context_resource_authority_and_evidence_refs"] =
            json!(["policy://no-pii"]);
        let resource = json!({
            "resource_offer_id": format!("resource-offer://rof_{}", "55".repeat(32)),
            "resource_profile_ref": "runtime://rt-ab",
            "capacity_and_availability_ref": "capacity://cap-ab",
            "locality_and_custody_refs": [],
            "trust_and_assurance_refs": [],
            "policy_constraint_refs": ["policy://no-pii"]
        });
        let capability = json!({
            "capability_offer_id": format!("capability-offer://cof_{}", "66".repeat(32)),
            "capability_descriptor_refs": ["ai://cap-ab"],
            "model_harness_tool_and_connector_refs": [],
            "authority_and_context_requirements": ["scope:unresolved-capability-authority"]
        });
        let (coverage, offer_prerequisites, unsupported) =
            collect_match_coverage(&frontier, &participant, &[resource], &[capability], &[])
                .unwrap();
        assert!(coverage.is_empty());
        assert_eq!(offer_prerequisites.len(), 2);
        assert_eq!(
            unsupported,
            vec!["policy://no-pii", "scope:unresolved-capability-authority"]
        );
    }

    #[test]
    fn resource_offer_expiry_uses_authenticated_wallet_time() {
        let offer = json!({"expires_at":"1970-01-01T00:00:02.000Z"});
        assert!(!resource_offer_expired_at(&offer, 1_999).unwrap());
        assert!(resource_offer_expired_at(&offer, 2_000).unwrap());
    }

    #[test]
    fn match_effect_binds_claim_leases_and_offer_coordinates() {
        let tuple = json!({"context_lease_refs":["context_lease://one"],"resource_offers":[{"offer_ref":format!("resource-offer://rof_{}","22".repeat(32)),"revision":1}]});
        let mut swapped = tuple.clone();
        swapped["context_lease_refs"] = json!(["context_lease://two"]);
        assert_ne!(
            governed::decision_effect_hash(MATCH_AUTHORITY, &match_effect(&tuple)),
            governed::decision_effect_hash(MATCH_AUTHORITY, &match_effect(&swapped))
        );
    }

    #[test]
    fn eligibility_receipt_revalidates_exact_offer_frontier_participant_and_claim_tuple() {
        let directory = temp_dir("eligibility");
        let data_dir = directory.to_str().unwrap();
        let participant = participant();
        let frontier = frontier();
        let declaration = json!({"outcome_room_ref":"outcome-room://or_ab","provider_participant_lease_ref":"participant-lease://rpl_ab","participant_ref":"participant-lease://rpl_ab","capability_descriptor_refs":["ai://cap-ab"],"eligible_frontier_classes":["task"],"model_harness_tool_and_connector_refs":[],"authority_and_context_requirements":[],"privacy_cost_quality_and_latency_refs":[],"availability_ref":null,"coordination_topology":"hosted_admission"});
        let offer_tail = format!("cof_{}", "33".repeat(32));
        let receipt_ref = format!("receipt://orm_{}", "44".repeat(32));
        let offer = seal_offer(
            "capability",
            &declaration,
            &offer_tail,
            &receipt_ref,
            1_800_000_000_000,
        )
        .unwrap();
        persist_record(data_dir, CAPABILITY_DIR, &offer_tail, &offer).unwrap();
        let coverage = json!([{"requirement_ref":"ai://cap-ab","matched_exactly":true},{"requirement_ref":"evidence://ev-ab","matched_exactly":true}]);
        let facts = json!({"outcome_room_ref":"outcome-room://or_ab","frontier_item_ref":frontier["frontier_item_id"],"frontier_revision":frontier["revision"],"frontier_control_hash":work::frontier_claim_control_hash(&frontier),"participant_ref":participant["participant_lease_id"],"participant_revision":participant["revision"],"participant_control_hash":participant_control_hash(&participant),"resource_offers":[],"capability_offers":offer_coordinates(&[offer.clone()],"capability_offer_id"),"context_lease_refs":[],"authority_resource_compute_data_budget_and_tool_lease_refs":[],"requirement_coverage":coverage,"offer_prerequisite_coverage":[{"offer_ref":offer["capability_offer_id"],"prerequisite_refs":[],"proof_refs":[]}],"allocation_created":false,"execution_authority_granted":false,"claim_created":false});
        let tail = deterministic_tail(
            "wem_",
            &json!({"domain":"hypervisor.work-eligibility-match.identity.v1","tuple":facts}),
        );
        let reference = format!("receipt://{tail}");
        let effect = match_effect(&facts);
        let receipt=build_receipt(&tail,MATCH_RECEIPT_SCHEMA,"WorkEligibilityMatchReceipt",&reference,"match",facts.clone(),vec![json!("outcome-room://or_ab"),frontier["frontier_item_id"].clone(),participant["participant_lease_id"].clone()],&facts,"a host-admitted exact eligibility match; it creates no allocation, execution authority, or claim",&authorized(&effect)).unwrap();
        persist_receipt(data_dir, &tail, &receipt).unwrap();
        assert_eq!(
            existing_match_receipt_exact(data_dir, &reference, &facts).unwrap(),
            Some(receipt.clone())
        );
        let claim = json!({"context_lease_refs":[],"authority_resource_compute_data_budget_and_tool_lease_refs":[]});
        validate_eligibility_for_claim_locked(
            data_dir,
            Some(&reference),
            &frontier,
            &participant,
            &claim,
            Some(1_800_000_000_000),
        )
        .unwrap();
        let mut stale_offer = offer;
        stale_offer["revision"] = json!(2);
        persist_record(data_dir, CAPABILITY_DIR, &offer_tail, &stale_offer).unwrap();
        assert_eq!(
            validate_eligibility_for_claim_locked(
                data_dir,
                Some(&reference),
                &frontier,
                &participant,
                &claim,
                Some(1_800_000_000_000)
            )
            .unwrap_err()
            .0,
            "work_claim_eligibility_stale"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn allocation_transitions_remain_typed_unavailable() {
        assert_eq!(
            transition_contract("resource", "allocate", "offered")
                .unwrap_err()
                .0,
            "offer_allocation_unavailable"
        );
    }

    #[test]
    fn unreadable_canonical_slots_are_uncertainty_not_absence() {
        let directory = temp_dir("strict");
        let data_dir = directory.to_str().unwrap();
        let tail = format!("rof_{}", "55".repeat(32));
        std::fs::create_dir_all(directory.join(RESOURCE_DIR).join(format!("{tail}.json"))).unwrap();
        assert!(load_resource(data_dir, &tail).is_err());
        assert!(scan_offers(data_dir, RESOURCE_DIR, canonical_resource_tail).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
