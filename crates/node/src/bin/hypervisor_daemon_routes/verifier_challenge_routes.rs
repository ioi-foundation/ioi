//! Hosted VerifierChallenge plane.
//!
//! A challenge freezes the exact admitted Attempt/Finding provenance it contests and admits a
//! governed adjudication lifecycle. It never rewrites evidence and never creates acceptance,
//! verdict, settlement, execution, allocation, or federation authority.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::attempt_finding_routes as provenance;
use super::governed_authority::{
    self as governed, AuthorityContract, AuthorizedDecision, Governance,
};
use super::outcome_room_routes::{
    self as rooms, build_room_receipt_at, record_output_hash, s, VErr,
};
use super::room_participation_routes as participation;
use super::work_frontier_claim_routes as work;
use super::DaemonState;

const RECORD_SCHEMA: &str = "ioi.hypervisor.verifier-challenge-envelope.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.verifier-challenge-receipt.v1";
const INTENT_SCHEMA: &str = "ioi.hypervisor.verifier-challenge-intent.v1";
const RECORD_DIR: &str = "verifier-challenges";
const RECEIPT_DIR: &str = "verifier-challenge-receipts";
const INTENT_DIR: &str = "verifier-challenge-intents";
const LIST_MAX: usize = 128;
const REF_MAX: usize = 300;
const REFS_MAX: usize = 64;
const HISTORY_MAX: usize = 128;

const KINDS: &[&str] = &[
    "metric",
    "rule",
    "verifier",
    "evidence",
    "eligibility",
    "result",
    "exploit",
    "independence",
    "collusion",
    "mapping",
];
const STATUSES: &[&str] = &[
    "proposed",
    "admitted",
    "investigating",
    "upheld",
    "rejected",
    "rule_changed",
    "reverifying",
    "resolved",
    "withdrawn",
];
const UNRESOLVED: &[&str] = &[
    "proposed",
    "admitted",
    "investigating",
    "upheld",
    "rule_changed",
    "reverifying",
];
const AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "verifier_challenge",
    policy_domain: "hypervisor.verifier-challenge.decision.policy.v1",
    request_domain: "hypervisor.verifier-challenge.decision.request.v1",
    resolution_domain: "hypervisor.verifier-challenge.authority-resolution.v1",
    code_prefix: "verifier_challenge",
    host_label: "room_host",
    participant_label: "participant_challenger",
};

/// Fixed lock tail: participation -> frontier/claim -> room -> GoalRun -> WorkResult ->
/// Attempt/Finding -> VerifierChallenge. Authority resolution always completes before locks.
pub(crate) static VERIFIER_CHALLENGE_LOCK: Mutex<()> = Mutex::new(());

fn verr(code: &str, message: impl Into<String>) -> VErr {
    (code.into(), message.into())
}

fn classify((code, message): VErr) -> (StatusCode, Json<Value>) {
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
fn canonical_challenge_tail(tail: &str) -> bool {
    canonical_tail(tail, "vc_")
}
fn canonical_intent_tail(tail: &str) -> bool {
    canonical_tail(tail, "vci_")
}
fn canonical_receipt_tail(tail: &str) -> bool {
    canonical_tail(tail, "vcr_")
}

fn ref_ok(value: &str, prefixes: &[&str]) -> bool {
    value.len() <= REF_MAX
        && !value.chars().any(char::is_whitespace)
        && prefixes.iter().any(|prefix| {
            value.strip_prefix(prefix).is_some_and(|tail| {
                !tail.is_empty() && !tail.starts_with('/') && !tail.contains("..")
            })
        })
}

fn reject_sensitive(value: &Value, path: &str) -> Result<(), VErr> {
    const SENSITIVE: &[&str] = &[
        "password",
        "secret",
        "credential",
        "authorization",
        "privatekey",
        "apikey",
        "token",
    ];
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized: String = key
                    .to_lowercase()
                    .chars()
                    .filter(|c| !matches!(c, '_' | '-' | ' ' | '.'))
                    .collect();
                if SENSITIVE
                    .iter()
                    .any(|fragment| normalized.contains(fragment))
                    && key != "wallet_approval_grant"
                    && !child.is_null()
                {
                    return Err(verr(
                        "verifier_challenge_plaintext_secret_rejected",
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
            "verifier_challenge_body_invalid",
            "request body must be an object",
        )
    })?;
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(verr(
                "verifier_challenge_field_unknown",
                format!("unknown or plane-owned field '{key}'"),
            ));
        }
    }
    Ok(())
}

fn required_ref(body: &Value, field: &str, prefixes: &[&str]) -> Result<String, VErr> {
    let value = body.get(field).and_then(Value::as_str).ok_or_else(|| {
        verr(
            "verifier_challenge_ref_required",
            format!("'{field}' is required"),
        )
    })?;
    if !ref_ok(value, prefixes) {
        return Err(verr(
            "verifier_challenge_ref_invalid",
            format!("'{field}' has a noncanonical scheme/path"),
        ));
    }
    Ok(value.to_string())
}

fn optional_ref(body: &Value, field: &str, prefixes: &[&str]) -> Result<Option<String>, VErr> {
    match body.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if ref_ok(value, prefixes) => Ok(Some(value.clone())),
        _ => Err(verr(
            "verifier_challenge_ref_invalid",
            format!("'{field}' has a noncanonical scheme/path"),
        )),
    }
}

fn ref_list(
    body: &Value,
    field: &str,
    prefixes: &[&str],
    nonempty: bool,
) -> Result<Vec<String>, VErr> {
    let values = body.get(field).and_then(Value::as_array).ok_or_else(|| {
        verr(
            "verifier_challenge_ref_list_required",
            format!("'{field}' must be a list"),
        )
    })?;
    if values.len() > REFS_MAX || (nonempty && values.is_empty()) {
        return Err(verr(
            "verifier_challenge_ref_list_invalid",
            format!(
                "'{field}' must contain {}..={REFS_MAX} refs",
                usize::from(nonempty)
            ),
        ));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let reference = value
            .as_str()
            .filter(|v| ref_ok(v, prefixes))
            .ok_or_else(|| {
                verr(
                    "verifier_challenge_ref_invalid",
                    format!("'{field}' contains an invalid ref"),
                )
            })?;
        out.push(reference.to_string());
    }
    let mut exact = out.clone();
    exact.sort();
    exact.dedup();
    if exact != out {
        return Err(verr(
            "verifier_challenge_ref_list_invalid",
            format!("'{field}' must be sorted and unique"),
        ));
    }
    Ok(out)
}

fn expected_revision(body: &Value, current: u64) -> Result<(), VErr> {
    match body.get("expected_revision").and_then(Value::as_u64) {
        Some(value) if value == current => Ok(()),
        Some(value) => Err(verr(
            "verifier_challenge_stale_revision",
            format!("expected revision {value}, current revision is {current}"),
        )),
        None => Err(verr(
            "verifier_challenge_expected_revision_required",
            "every mutation requires expected_revision",
        )),
    }
}

fn without(value: &Value, field: &str) -> Value {
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
fn fresh_tail(prefix: &str, subject: &str, op: &str, revision: u64, at_ms: u64) -> String {
    deterministic_tail(
        prefix,
        &json!({"domain":"hypervisor.verifier-challenge.nonce.v1","subject_ref":subject,
        "op":op,"revision":revision,"resolved_at_ms":at_ms,"nonce":uuid::Uuid::new_v4().to_string()}),
    )
}
fn ms_to_rfc3339(ms: u64) -> Result<String, VErr> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms).saturating_mul(1_000_000))
        .map_err(|_| {
            verr(
                "verifier_challenge_wallet_time_invalid",
                "wallet time is not representable",
            )
        })?
        .format(&Rfc3339)
        .map_err(|error| verr("verifier_challenge_wallet_time_invalid", error.to_string()))
}

fn validate_record_identity(tail: &str, record: &Value) -> Result<(), String> {
    if record.get("schema_version").and_then(Value::as_str) != Some(RECORD_SCHEMA)
        || record.get("verifier_challenge_id").and_then(Value::as_str)
            != Some(format!("verifier-challenge://{tail}").as_str())
        || record.get("revision").and_then(Value::as_u64).is_none()
        || !STATUSES.contains(&s(record, "status", "").as_str())
    {
        return Err(format!("canonical slot '{RECORD_DIR}/{tail}.json' fails schema/identity/revision/status binding"));
    }
    Ok(())
}

fn load_record(data_dir: &str, id_or_tail: &str) -> Result<Option<Value>, String> {
    let tail = id_or_tail
        .strip_prefix("verifier-challenge://")
        .unwrap_or(id_or_tail);
    if !canonical_challenge_tail(tail) {
        return Err(format!("noncanonical VerifierChallenge key '{tail}'"));
    }
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, RECORD_DIR) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("family cannot be pinned ({error})")),
    };
    let name = format!("{tail}.json");
    let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
        Ok(None) => return Ok(None),
        Ok(Some((_file, bytes))) => bytes,
        Err(error) => return Err(format!("slot '{name}' is unreadable ({error})")),
    };
    let record: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("slot '{name}' is malformed JSON ({error})"))?;
    validate_record_identity(tail, &record)?;
    Ok(Some(record))
}

fn scan_records(data_dir: &str) -> Result<Vec<Value>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, RECORD_DIR) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("family cannot be pinned ({error})")),
    };
    let names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|e| format!("family cannot be enumerated ({e})"))?;
    let mut records = Vec::new();
    for name in names {
        let Some(tail) = name.strip_suffix(".json") else {
            continue;
        };
        if !canonical_challenge_tail(tail) {
            continue;
        }
        let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
            Ok(Some((_file, bytes))) => bytes,
            Ok(None) => return Err(format!("canonical slot '{name}' vanished")),
            Err(error) => return Err(format!("canonical slot '{name}' is unreadable ({error})")),
        };
        let record: Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("canonical slot '{name}' is malformed JSON ({e})"))?;
        validate_record_identity(tail, &record)?;
        records.push(record);
    }
    Ok(records)
}

fn persist_record(data_dir: &str, family: &str, tail: &str, record: &Value) -> Result<(), VErr> {
    super::durable_fs::persist_record_durable(data_dir, family, tail, record).map_err(|failure| {
        if failure.visible() {
            verr("verifier_challenge_pending_convergence", failure.detail())
        } else {
            verr("verifier_challenge_persist_failed", failure.detail())
        }
    })
}

fn persist_receipt(data_dir: &str, tail: &str, receipt: &Value) -> Result<(), VErr> {
    use super::durable_fs::CommitFailure;
    super::durable_fs::persist_receipt_no_clobber(data_dir, RECEIPT_DIR, tail, receipt).map_err(
        |failure| match failure {
            CommitFailure::KeyInvalid(message) => {
                verr("verifier_challenge_receipt_key_invalid", message)
            }
            CommitFailure::NotCommitted(message) => {
                verr("verifier_challenge_persist_failed", message)
            }
            CommitFailure::SlotUnreadable(message) => {
                verr("verifier_challenge_receipt_unreadable", message)
            }
            CommitFailure::Conflict(message) => {
                verr("verifier_challenge_receipt_conflict", message)
            }
            CommitFailure::DurabilityUnconfirmed(message) => {
                verr("verifier_challenge_pending_convergence", message)
            }
            CommitFailure::Swapped(message) => verr("verifier_challenge_receipt_swapped", message),
        },
    )
}

fn consume_intent(data_dir: &str, tail: &str) -> Result<(), VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, INTENT_DIR) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(verr(
                "verifier_challenge_intent_unreadable",
                error.to_string(),
            ))
        }
    };
    match super::durable_fs::unlink_at(&directory, &format!("{tail}.json")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(verr(
                "verifier_challenge_pending_convergence",
                format!("intent unlink failed ({error})"),
            ))
        }
    }
    directory.sync_all().map_err(|e| {
        verr(
            "verifier_challenge_pending_convergence",
            format!("intent directory sync failed ({e})"),
        )
    })
}

fn seal_intent(mut intent: Value, tail: &str) -> Value {
    let object = intent.as_object_mut().expect("intent object");
    object.insert("schema_version".into(), json!(INTENT_SCHEMA));
    object.insert(
        "intent_id".into(),
        json!(format!("verifier-challenge-intent://{tail}")),
    );
    let mut touched: BTreeSet<String> = [
        "subject_ref",
        "room_ref",
        "challenged_ref",
        "work_result_ref",
        "challenger_ref",
    ]
    .iter()
    .filter_map(|field| object.get(*field).and_then(Value::as_str))
    .filter(|value| !value.is_empty())
    .map(ToOwned::to_owned)
    .collect();
    if let Some(values) = object
        .get("affected_attempt_refs")
        .and_then(Value::as_array)
    {
        touched.extend(
            values
                .iter()
                .filter_map(Value::as_str)
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

fn validate_touched(intent: &Value) -> Result<Vec<String>, String> {
    let values: Vec<String> = intent
        .get("touched_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| "intent lacks touched_refs".to_string())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|v| !v.is_empty() && v.len() <= REF_MAX)
                .map(ToOwned::to_owned)
                .ok_or_else(|| "intent touched_refs contains invalid ref".to_string())
        })
        .collect::<Result<_, _>>()?;
    let mut exact: BTreeSet<String> = [
        "subject_ref",
        "room_ref",
        "challenged_ref",
        "work_result_ref",
        "challenger_ref",
    ]
    .iter()
    .filter_map(|field| intent.get(*field).and_then(Value::as_str))
    .filter(|value| !value.is_empty())
    .map(ToOwned::to_owned)
    .collect();
    if let Some(items) = intent
        .get("affected_attempt_refs")
        .and_then(Value::as_array)
    {
        exact.extend(
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned),
        );
    }
    if values != exact.into_iter().collect::<Vec<_>>() {
        return Err("intent touched_refs differs from reconstructed exact aggregate set".into());
    }
    Ok(values)
}

fn validate_intent_seal(intent: &Value, tail: &str) -> Result<(), String> {
    if intent.get("schema_version").and_then(Value::as_str) != Some(INTENT_SCHEMA)
        || intent.get("intent_id").and_then(Value::as_str)
            != Some(format!("verifier-challenge-intent://{tail}").as_str())
        || intent.get("intent_hash").and_then(Value::as_str)
            != Some(record_output_hash(&without(intent, "intent_hash"), &[]).as_str())
    {
        return Err("intent storage-key/hash binding failed".into());
    }
    validate_touched(intent)?;
    Ok(())
}

fn scan_intents(data_dir: &str) -> Result<Vec<(String, Value)>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, INTENT_DIR) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("intent family cannot be pinned ({error})")),
    };
    let names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|e| format!("intent family cannot be enumerated ({e})"))?;
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
            .map_err(|e| format!("canonical intent '{name}' is malformed ({e})"))?;
        validate_intent_seal(&intent, tail)?;
        intents.push((tail.to_string(), intent));
    }
    Ok(intents)
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
    for (tail, intent) in
        scan_intents(data_dir).map_err(|e| verr("verifier_challenge_intent_unreadable", e))?
    {
        if ignored == Some(tail.as_str()) {
            continue;
        }
        let touched = validate_touched(&intent)
            .map_err(|e| verr("verifier_challenge_intent_unreadable", e))?;
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
            format!("record '{overlap}' is reserved by pending VerifierChallenge intent '{tail}'"),
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

fn room_strict(data_dir: &str, room_ref: &str, require_open: bool) -> Result<Value, VErr> {
    let room = rooms::resolve_room_strict(data_dir, room_ref)
        .map_err(|e| verr("verifier_challenge_room_registry_unreadable", e))?
        .ok_or_else(|| {
            verr(
                "verifier_challenge_room_not_found",
                format!("no room '{room_ref}'"),
            )
        })?;
    if require_open && s(&room, "status", "") != "open" {
        return Err(verr(
            "verifier_challenge_room_not_open",
            "fresh challenge admission requires an open hosted room",
        ));
    }
    Ok(room)
}
fn participant_strict(
    data_dir: &str,
    participant_ref: &str,
    require_active: bool,
) -> Result<Value, VErr> {
    let participant = participation::resolve_participant_lease_strict(data_dir, participant_ref)
        .map_err(|e| verr("verifier_challenge_participant_registry_unreadable", e))?
        .ok_or_else(|| {
            verr(
                "verifier_challenge_participant_not_found",
                format!("no participant lease '{participant_ref}'"),
            )
        })?;
    if require_active && s(&participant, "status", "") != "active" {
        return Err(verr(
            "verifier_challenge_participant_not_active",
            "fresh challenger-governed mutation requires the exact participant lease to be active",
        ));
    }
    Ok(participant)
}

fn coordinate(reference: &str, record: &Value) -> Value {
    json!({"record_ref":reference,"revision":record.get("revision").cloned().unwrap_or(Value::Null),
        "record_hash":record_output_hash(record, &[])})
}
fn historical_attempt_coordinate(reference: &str, attempt: &Value) -> Value {
    json!({"record_ref":reference,"outcome_room_ref":s(attempt,"outcome_room_ref",""),
        "participant_ref":s(attempt,"participant_ref",""),"work_result_ref":attempt.get("work_result_ref").cloned().unwrap_or(Value::Null),
        "identity_hash":record_output_hash(&json!({"attempt_id":reference,"outcome_room_ref":s(attempt,"outcome_room_ref",""),
            "participant_ref":s(attempt,"participant_ref",""),"work_result_ref":attempt.get("work_result_ref").cloned().unwrap_or(Value::Null),
            "bound_coordinates":attempt.get("bound_coordinates").cloned().unwrap_or(Value::Null)}), &[])})
}

#[derive(Clone)]
struct TargetDependencies {
    room: Value,
    challenger: Value,
    target: Value,
    target_kind: &'static str,
    bound_attempt_ref: String,
    work_result_ref: Option<String>,
    attempts: Vec<(String, Value)>,
    work_result: Option<Value>,
}

fn unsupported_target(reference: &str) -> bool {
    [
        "verifier-path://",
        "benchmark://",
        "rubric://",
        "evidence://",
        "eligibility://",
        "eligibility-match://",
        "work-eligibility://",
        "work-eligibility-match://",
        "decision://",
        "governance-decision://",
        "aiip://",
        "federated://",
    ]
    .iter()
    .any(|prefix| reference.starts_with(prefix))
}

fn resolve_dependencies(
    data_dir: &str,
    declaration: &Value,
    active: bool,
    open: bool,
) -> Result<TargetDependencies, VErr> {
    let room_ref = s(declaration, "outcome_room_ref", "");
    let challenger_ref = s(declaration, "challenger_ref", "");
    let challenged_ref = s(declaration, "challenged_ref", "");
    let room = room_strict(data_dir, &room_ref, open)?;
    let challenger = participant_strict(data_dir, &challenger_ref, active)?;
    if s(&challenger, "outcome_room_ref", "") != room_ref {
        return Err(verr(
            "verifier_challenge_cross_room",
            "challenger participant lease belongs to another room",
        ));
    }
    if unsupported_target(&challenged_ref) {
        return Err(verr(
            "verifier_challenge_target_resolver_unavailable",
            "this challenge target owner resolver is not implemented",
        ));
    }
    let (target, target_kind, bound_attempt_ref, work_result_ref) =
        if challenged_ref.starts_with("attempt://") {
            let target = provenance::load_attempt_strict(data_dir, &challenged_ref)
                .map_err(|e| verr("verifier_challenge_target_unreadable", e))?
                .ok_or_else(|| {
                    verr(
                        "verifier_challenge_target_not_found",
                        format!("no Attempt '{challenged_ref}'"),
                    )
                })?;
            let result = target
                .get("work_result_ref")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            (target, "attempt", challenged_ref.clone(), result)
        } else if challenged_ref.starts_with("finding://") {
            let target = provenance::load_finding_strict(data_dir, &challenged_ref)
                .map_err(|e| verr("verifier_challenge_target_unreadable", e))?
                .ok_or_else(|| {
                    verr(
                        "verifier_challenge_target_not_found",
                        format!("no Finding '{challenged_ref}'"),
                    )
                })?;
            (
                target.clone(),
                "finding",
                s(&target, "attempt_ref", ""),
                Some(s(&target, "work_result_ref", "")),
            )
        } else {
            return Err(verr(
                "verifier_challenge_target_invalid",
                "challenged_ref must be an exact attempt:// or finding:// ref",
            ));
        };
    if s(&target, "outcome_room_ref", "") != room_ref {
        return Err(verr(
            "verifier_challenge_cross_room",
            "challenged target belongs to another room",
        ));
    }
    let affected_refs = declaration
        .get("affected_attempt_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "verifier_challenge_affected_attempts_required",
                "affected_attempt_refs is required",
            )
        })?;
    let mut attempts = Vec::new();
    for item in affected_refs {
        let reference = item.as_str().ok_or_else(|| {
            verr(
                "verifier_challenge_affected_attempt_invalid",
                "affected Attempt ref is not a string",
            )
        })?;
        let attempt = provenance::load_attempt_strict(data_dir, reference)
            .map_err(|e| verr("verifier_challenge_affected_attempt_unreadable", e))?
            .ok_or_else(|| {
                verr(
                    "verifier_challenge_affected_attempt_not_found",
                    format!("no Attempt '{reference}'"),
                )
            })?;
        if s(&attempt, "outcome_room_ref", "") != room_ref {
            return Err(verr(
                "verifier_challenge_cross_room",
                "every affected Attempt must belong to the exact room",
            ));
        }
        attempts.push((reference.to_string(), attempt));
    }
    if !attempts
        .iter()
        .any(|(reference, _)| reference == &bound_attempt_ref)
    {
        return Err(verr(
            "verifier_challenge_bound_attempt_required",
            "the challenged Attempt, or Finding's bound Attempt, must be affected",
        ));
    }
    let work_result = match &work_result_ref {
        Some(reference) if !reference.is_empty() => Some(
            super::work_result_routes::load_work_result_strict(data_dir, reference)
                .map_err(|e| verr("verifier_challenge_work_result_unreadable", e))?
                .ok_or_else(|| {
                    verr(
                        "verifier_challenge_work_result_not_found",
                        format!("no WorkResult '{reference}'"),
                    )
                })?,
        ),
        _ => None,
    };
    if let Some(result) = &work_result {
        if s(result, "outcome_room_ref", "") != room_ref {
            return Err(verr(
                "verifier_challenge_cross_room",
                "bound WorkResult belongs to another room",
            ));
        }
    }
    Ok(TargetDependencies {
        room,
        challenger,
        target,
        target_kind,
        bound_attempt_ref,
        work_result_ref,
        attempts,
        work_result,
    })
}

fn frozen_coordinates(declaration: &Value, dependencies: &TargetDependencies) -> Value {
    let affected: Vec<Value> = dependencies
        .attempts
        .iter()
        .map(|(reference, attempt)| historical_attempt_coordinate(reference, attempt))
        .collect();
    json!({
        "challenged_target":{"kind":dependencies.target_kind,"coordinate":coordinate(&s(declaration,"challenged_ref",""), &dependencies.target)},
        "bound_attempt_ref":dependencies.bound_attempt_ref,
        "affected_attempts":affected,
        "work_result":dependencies.work_result_ref.as_ref().zip(dependencies.work_result.as_ref())
            .map(|(reference, record)| coordinate(reference, record)).unwrap_or(Value::Null),
        "challenger_participant":{"record_ref":s(declaration,"challenger_ref",""),"outcome_room_ref":s(&dependencies.challenger,"outcome_room_ref",""),
            "principal_ref":dependencies.challenger.get("participant_ref").cloned().unwrap_or(Value::Null)},
        "room":{"record_ref":s(declaration,"outcome_room_ref",""),"host_domain_ref":s(&dependencies.room,"host_domain_ref","")},
    })
}

fn validate_create(body: &Value) -> Result<Value, VErr> {
    reject_sensitive(body, "")?;
    reject_unknown(
        body,
        &[
            "outcome_room_ref",
            "challenger_ref",
            "challenged_ref",
            "challenge_kind",
            "challenge_evidence_refs",
            "adjudicator_policy_ref",
            "prior_rule_version_ref",
            "proposed_rule_version_ref",
            "affected_attempt_refs",
            "reverification_required",
            "coordination_topology",
            "expected_revision",
            "wallet_approval_grant",
        ],
    )?;
    expected_revision(body, 0)?;
    if body.get("coordination_topology").and_then(Value::as_str) != Some("hosted_admission") {
        return Err(verr(
            "verifier_challenge_federated_unavailable",
            "only hosted_admission is implemented",
        ));
    }
    let room = required_ref(body, "outcome_room_ref", &["outcome-room://"])?;
    let challenger = required_ref(
        body,
        "challenger_ref",
        &["participant-lease://", "worker://", "org://", "user://"],
    )?;
    if !challenger.starts_with("participant-lease://") {
        return Err(verr(
            "verifier_challenge_challenger_mapping_unavailable",
            "worker, org, and user challengers require a trusted principal-to-authority mapping",
        ));
    }
    let challenged = required_ref(
        body,
        "challenged_ref",
        &[
            "attempt://",
            "finding://",
            "verifier-path://",
            "benchmark://",
            "rubric://",
            "evidence://",
            "eligibility://",
            "eligibility-match://",
            "work-eligibility://",
            "work-eligibility-match://",
            "decision://",
            "governance-decision://",
            "aiip://",
            "federated://",
        ],
    )?;
    if unsupported_target(&challenged) {
        return Err(verr(
            "verifier_challenge_target_resolver_unavailable",
            "this challenge target owner resolver is not implemented",
        ));
    }
    let kind = body
        .get("challenge_kind")
        .and_then(Value::as_str)
        .filter(|value| KINDS.contains(value))
        .ok_or_else(|| {
            verr(
                "verifier_challenge_kind_invalid",
                "challenge_kind is not canonical",
            )
        })?;
    let evidence = ref_list(
        body,
        "challenge_evidence_refs",
        &["evidence://", "artifact://", "receipt://"],
        false,
    )?;
    let adjudicator = required_ref(body, "adjudicator_policy_ref", &["policy://"])?;
    let prior = optional_ref(
        body,
        "prior_rule_version_ref",
        &["rubric://", "verifier-path://"],
    )?;
    let proposed = optional_ref(
        body,
        "proposed_rule_version_ref",
        &["rubric://", "verifier-path://"],
    )?;
    let affected = ref_list(body, "affected_attempt_refs", &["attempt://"], true)?;
    let reverification = body
        .get("reverification_required")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            verr(
                "verifier_challenge_reverification_required",
                "reverification_required must be boolean",
            )
        })?;
    Ok(
        json!({"outcome_room_ref":room,"challenger_ref":challenger,"challenged_ref":challenged,
        "challenge_kind":kind,"challenge_evidence_refs":evidence,"adjudicator_policy_ref":adjudicator,
        "prior_rule_version_ref":prior,"proposed_rule_version_ref":proposed,"affected_attempt_refs":affected,
        "reverification_required":reverification,"adjudication_ref":Value::Null,
        "coordination_topology":"hosted_admission"}),
    )
}

fn validate_transition(body: &Value, op: &str) -> Result<Value, VErr> {
    reject_sensitive(body, "")?;
    let allowed = if op == "rule_changed" {
        vec![
            "transition",
            "expected_revision",
            "prior_rule_version_ref",
            "proposed_rule_version_ref",
            "affected_attempt_refs",
            "reverification_required",
            "wallet_approval_grant",
        ]
    } else {
        vec!["transition", "expected_revision", "wallet_approval_grant"]
    };
    reject_unknown(body, &allowed)?;
    if op == "rule_changed" {
        let prior = required_ref(
            body,
            "prior_rule_version_ref",
            &["rubric://", "verifier-path://"],
        )?;
        let proposed = required_ref(
            body,
            "proposed_rule_version_ref",
            &["rubric://", "verifier-path://"],
        )?;
        let affected = ref_list(body, "affected_attempt_refs", &["attempt://"], true)?;
        if body.get("reverification_required").and_then(Value::as_bool) != Some(true) {
            return Err(verr(
                "verifier_challenge_rule_change_reverification_required",
                "rule_changed requires reverification_required=true",
            ));
        }
        Ok(
            json!({"prior_rule_version_ref":prior,"proposed_rule_version_ref":proposed,
            "affected_attempt_refs":affected,"reverification_required":true}),
        )
    } else {
        Ok(json!({}))
    }
}

fn transition_contract(op: &str, from: &str) -> Result<(Governance, &'static str), VErr> {
    match (op, from) {
        ("admit", "proposed") => Ok((Governance::Host, "admitted")),
        ("investigate", "admitted") => Ok((Governance::Host, "investigating")),
        ("uphold", "admitted" | "investigating") => Ok((Governance::Host, "upheld")),
        ("reject", "admitted" | "investigating") => Ok((Governance::Host, "rejected")),
        ("rule_changed", "upheld") => Ok((Governance::Host, "rule_changed")),
        ("begin_reverification", "upheld" | "rule_changed") => {
            Ok((Governance::Host, "reverifying"))
        }
        ("resolve", "upheld" | "rejected" | "rule_changed" | "reverifying") => {
            Ok((Governance::Host, "resolved"))
        }
        ("withdraw", "proposed") => Ok((Governance::Participant, "withdrawn")),
        _ => Err(verr(
            "verifier_challenge_transition_invalid",
            format!("transition '{op}' is not admitted from '{from}'"),
        )),
    }
}

fn effect(op: &str, revision: u64, payload: &Value, after: &str) -> Value {
    json!({"object_kind":"verifier_challenge","op":op,"revision_before":revision,"payload":payload,
        "status_after":after,"acceptance_created":false,"verdict_created":false,
        "settlement_created":false,"execution_authority_granted":false})
}

fn append_history(
    mut record: Value,
    op: &str,
    status: &str,
    receipt_ref: &str,
    at_ms: u64,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(at_ms)?;
    let revision = record.get("revision").and_then(Value::as_u64).unwrap_or(0) + 1;
    let object = record.as_object_mut().ok_or_else(|| {
        verr(
            "verifier_challenge_record_invalid",
            "record is not an object",
        )
    })?;
    object.insert("status".into(), json!(status));
    object.insert("revision".into(), json!(revision));
    object.insert("updated_at".into(), json!(now));
    object.insert("updated_at_ms".into(), json!(at_ms));
    let trail = object
        .entry("admission_and_replay_refs")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .unwrap();
    trail.push(json!(receipt_ref));
    let history = object
        .entry("status_history")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .unwrap();
    history.push(json!({"op":op,"status":status,"revision":revision,"receipt_ref":receipt_ref,"at":now,"at_ms":at_ms}));
    if history.len() > HISTORY_MAX {
        history.drain(0..history.len() - HISTORY_MAX);
    }
    Ok(record)
}

fn seal_create(
    declaration: &Value,
    coordinates: &Value,
    tail: &str,
    receipt_ref: &str,
    at_ms: u64,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(at_ms)?;
    let mut record = declaration.clone();
    let object = record.as_object_mut().unwrap();
    object.insert("schema_version".into(), json!(RECORD_SCHEMA));
    object.insert(
        "verifier_challenge_id".into(),
        json!(format!("verifier-challenge://{tail}")),
    );
    object.insert("frozen_coordinates".into(), coordinates.clone());
    object.insert("status".into(), json!("proposed"));
    object.insert("revision".into(), json!(1));
    object.insert("created_at".into(), json!(now));
    object.insert("created_at_ms".into(), json!(at_ms));
    object.insert("updated_at".into(), json!(now));
    object.insert("updated_at_ms".into(), json!(at_ms));
    object.insert("admission_receipt_ref".into(), json!(receipt_ref));
    object.insert("admission_and_replay_refs".into(), json!([receipt_ref]));
    object.insert(
        "status_history".into(),
        json!([{"op":"create","status":"proposed","revision":1,
        "receipt_ref":receipt_ref,"at":now,"at_ms":at_ms}]),
    );
    object.insert("runtimeTruthSource".into(), json!("daemon-runtime"));
    Ok(record)
}

fn transition_record(
    prior: &Value,
    op: &str,
    to: &str,
    fields: &Value,
    receipt_ref: &str,
    at_ms: u64,
) -> Result<Value, VErr> {
    let mut next = prior.clone();
    if op == "rule_changed" {
        let object = next.as_object_mut().unwrap();
        for field in [
            "prior_rule_version_ref",
            "proposed_rule_version_ref",
            "affected_attempt_refs",
            "reverification_required",
        ] {
            object.insert(
                field.into(),
                fields.get(field).cloned().unwrap_or(Value::Null),
            );
        }
    }
    append_history(next, op, to, receipt_ref, at_ms)
}

fn build_receipt(
    tail: &str,
    challenge: &Value,
    op: &str,
    prior: Option<&Value>,
    output: &Value,
    effect: &Value,
    authorized: &AuthorizedDecision,
) -> Result<Value, VErr> {
    let now = ms_to_rfc3339(authorized.resolved_at_ms)?;
    let before_revision = prior
        .and_then(|v| v.get("revision"))
        .cloned()
        .unwrap_or(json!(0));
    let before_status = prior
        .and_then(|v| v.get("status"))
        .cloned()
        .unwrap_or(Value::Null);
    let boundary_refs: Vec<Value> = std::iter::once(json!(s(challenge, "outcome_room_ref", "")))
        .chain(std::iter::once(json!(s(challenge, "challenged_ref", ""))))
        .chain(
            challenge
                .get("affected_attempt_refs")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        )
        .collect();
    let mut receipt = build_room_receipt_at(tail, RECEIPT_SCHEMA, "VerifierChallengeReceipt",
        &s(challenge,"verifier_challenge_id",""), op,
        json!({"verifier_challenge_ref":s(challenge,"verifier_challenge_id",""),
            "outcome_room_ref":s(challenge,"outcome_room_ref",""),"challenger_ref":s(challenge,"challenger_ref",""),
            "challenged_ref":s(challenge,"challenged_ref",""),"challenge_kind":s(challenge,"challenge_kind",""),
            "challenge_evidence_refs":challenge.get("challenge_evidence_refs"),"prior_rule_version_ref":challenge.get("prior_rule_version_ref"),
            "proposed_rule_version_ref":challenge.get("proposed_rule_version_ref"),"affected_attempt_refs":challenge.get("affected_attempt_refs"),
            "adjudicator_policy_ref":challenge.get("adjudicator_policy_ref"),"reverification_required":challenge.get("reverification_required"),
            "frozen_coordinates":challenge.get("frozen_coordinates"),"predecessor_status":before_status,
            "resulting_status":output.get("status"),"revision_before":before_revision,"revision_after":output.get("revision"),
            "operation_effect":effect,"operation_effect_hash":record_output_hash(effect,&[])}),
        boundary_refs, record_output_hash(output, &["admission_and_replay_refs","status_history"]),
        &["admission_and_replay_refs","status_history"], "admitted_not_verified",
        "an admitted hosted-room challenge mutation; no acceptance, verdict, settlement, or execution authority is created", &now);
    governed::append_evidence(&mut receipt, authorized);
    Ok(receipt)
}

fn persist_successor(
    data_dir: &str,
    tail: &str,
    prior: Option<&Value>,
    successor: &Value,
) -> Result<(), VErr> {
    let current = load_record(data_dir, tail)
        .map_err(|e| verr("verifier_challenge_registry_unreadable", e))?;
    if current.as_ref() == Some(successor) {
        return Ok(());
    }
    if current.as_ref() != prior {
        return Err(verr(
            "verifier_challenge_pending_convergence",
            "record equals neither sealed prior nor deterministic successor",
        ));
    }
    persist_record(data_dir, RECORD_DIR, tail, successor)
}

fn complete_intent_locked(data_dir: &str, tail: &str, intent: &Value) -> Result<(), VErr> {
    validate_intent_seal(intent, tail)
        .map_err(|e| verr("verifier_challenge_intent_unreadable", e))?;
    let kind = s(intent, "kind", "");
    let receipt_tail = intent
        .get("receipt_tail")
        .and_then(Value::as_str)
        .filter(|value| canonical_receipt_tail(value))
        .ok_or_else(|| {
            verr(
                "verifier_challenge_intent_unreadable",
                "intent receipt tail is invalid",
            )
        })?;
    let receipt = intent.get("receipt").ok_or_else(|| {
        verr(
            "verifier_challenge_intent_unreadable",
            "intent lacks receipt",
        )
    })?;
    let successor = intent
        .get("final_challenge")
        .filter(|value| !value.is_null())
        .ok_or_else(|| {
            verr(
                "verifier_challenge_intent_unreadable",
                "intent lacks successor",
            )
        })?;
    let subject = s(intent, "subject_ref", "");
    let record_tail = subject
        .strip_prefix("verifier-challenge://")
        .filter(|value| canonical_challenge_tail(value))
        .ok_or_else(|| {
            verr(
                "verifier_challenge_intent_unreadable",
                "subject ref is noncanonical",
            )
        })?;
    if successor
        .get("verifier_challenge_id")
        .and_then(Value::as_str)
        != Some(subject.as_str())
    {
        return Err(verr(
            "verifier_challenge_intent_unreadable",
            "successor identity differs from subject",
        ));
    }
    if kind == "create" {
        let room_ref = s(intent, "room_ref", "");
        match rooms::bind_room_backlink_room_locked_for_verifier_challenge_intent(
            data_dir,
            &room_ref,
            "verifier_challenge_bound",
            &subject,
            tail,
        ) {
            Ok(_) => {}
            Err((code, _)) if code == "outcome_room_backlink_already_bound" => {}
            Err(error) => return Err(error),
        }
    }
    persist_receipt(data_dir, receipt_tail, receipt)?;
    persist_successor(
        data_dir,
        record_tail,
        intent
            .get("prior_challenge")
            .filter(|value| !value.is_null()),
        successor,
    )?;
    consume_intent(data_dir, tail)
}

fn persist_and_complete_locked(data_dir: &str, tail: &str, intent: &Value) -> Result<(), VErr> {
    persist_record(data_dir, INTENT_DIR, tail, intent)?;
    complete_intent_locked(data_dir, tail, intent)
}

async fn authorize(
    body: &Value,
    governance: Governance,
    room_ref: &str,
    authority: &str,
    subject: &str,
    op: &str,
    revision: u64,
    effect: &Value,
) -> Result<AuthorizedDecision, (StatusCode, Json<Value>)> {
    governed::authorize_decision(
        AUTHORITY, body, governance, room_ref, authority, subject, op, revision, effect,
    )
    .await
}

fn reservation_refs(declaration: &Value, subject: &str) -> Vec<String> {
    let mut refs = vec![
        subject.to_string(),
        s(declaration, "outcome_room_ref", ""),
        s(declaration, "challenged_ref", ""),
        s(declaration, "challenger_ref", ""),
    ];
    refs.extend(
        declaration
            .get("affected_attempt_refs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned),
    );
    refs.sort();
    refs.dedup();
    refs
}

pub(crate) async fn handle_create(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let declaration = match validate_create(&body) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let dependencies = match resolve_dependencies(&state.data_dir, &declaration, true, true) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let coordinates = frozen_coordinates(&declaration, &dependencies);
    let tail = deterministic_tail(
        "vc_",
        &json!({"domain":"hypervisor.verifier-challenge.identity.v1",
        "declaration":declaration,"frozen_coordinates":coordinates}),
    );
    let subject = format!("verifier-challenge://{tail}");
    let room_ref = s(&declaration, "outcome_room_ref", "");
    let authority = s(&dependencies.challenger, "participant_ref", "");
    if authority.is_empty() {
        return classify(verr(
            "verifier_challenge_participant_authority_unavailable",
            "participant authority does not resolve",
        ));
    }
    let mutation_effect = effect(
        "create",
        0,
        &json!({"declaration":declaration,"frozen_coordinates":coordinates}),
        "proposed",
    );
    let authorized = match authorize(
        &body,
        Governance::Participant,
        &room_ref,
        &authority,
        &subject,
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
    let _provenance = provenance::ATTEMPT_FINDING_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _plane = VERIFIER_CHALLENGE_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let dependencies = match resolve_dependencies(&state.data_dir, &declaration, true, true) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if frozen_coordinates(&declaration, &dependencies) != coordinates {
        return classify(verr(
            "verifier_challenge_coordinate_changed",
            "target coordinates changed during authority resolution",
        ));
    }
    let refs = reservation_refs(&declaration, &subject);
    let ref_views: Vec<&str> = refs.iter().map(String::as_str).collect();
    if let Err(error) = refuse_reserved(
        &state.data_dir,
        &ref_views,
        "verifier_challenge_mutation_in_flight",
        None,
    ) {
        return classify(error);
    }
    match load_record(&state.data_dir, &tail) {
        Ok(None) => {}
        Ok(Some(_)) => {
            return classify(verr(
                "verifier_challenge_conflict",
                "canonical challenge already exists",
            ))
        }
        Err(message) => return classify(verr("verifier_challenge_registry_unreadable", message)),
    }
    let receipt_tail = fresh_tail("vcr_", &subject, "create", 0, authorized.resolved_at_ms);
    let receipt_ref = format!("receipt://{receipt_tail}");
    let final_challenge = match seal_create(
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
        &final_challenge,
        "create",
        None,
        &final_challenge,
        &mutation_effect,
        &authorized,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent_tail = fresh_tail("vci_", &subject, "create", 0, authorized.resolved_at_ms);
    let intent = seal_intent(
        json!({"kind":"create","governance":"participant","op":"create",
        "room_ref":room_ref,"challenged_ref":s(&declaration,"challenged_ref",""),
        "work_result_ref":dependencies.work_result_ref,"challenger_ref":s(&declaration,"challenger_ref",""),
        "affected_attempt_refs":declaration.get("affected_attempt_refs"),"required_authority_ref":authority,
        "subject_ref":subject,"revision_before":0,"receipt_tail":receipt_tail,"receipt":receipt,
        "prior_challenge":Value::Null,"final_challenge":final_challenge}),
        &intent_tail,
    );
    match persist_and_complete_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(
                json!({"verifier_challenge":final_challenge,"verifier_challenge_receipt":receipt}),
            ),
        ),
        Err(error) => classify(error),
    }
}

pub(crate) async fn handle_transition(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let op = match body.get("transition").and_then(Value::as_str) {
        Some(value) => value.to_string(),
        None => {
            return classify(verr(
                "verifier_challenge_transition_required",
                "transition is required",
            ))
        }
    };
    let fields = match validate_transition(&body, &op) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let prior = match load_record(&state.data_dir, &id) {
        Ok(Some(value)) => value,
        Ok(None) => {
            return classify(verr(
                "verifier_challenge_not_found",
                format!("no challenge '{id}'"),
            ))
        }
        Err(message) => return classify(verr("verifier_challenge_registry_unreadable", message)),
    };
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    if let Err(error) = expected_revision(&body, revision) {
        return classify(error);
    }
    let (governance, to) = match transition_contract(&op, &s(&prior, "status", "")) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let declaration = prior.clone();
    let dependencies = match resolve_dependencies(
        &state.data_dir,
        &declaration,
        governance == Governance::Participant,
        false,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if op == "rule_changed"
        && fields.get("affected_attempt_refs") != prior.get("affected_attempt_refs")
    {
        return classify(verr(
            "verifier_challenge_affected_attempt_substitution",
            "rule change must retain the exact frozen affected Attempts",
        ));
    }
    if op == "begin_reverification"
        && prior
            .get("reverification_required")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return classify(verr(
            "verifier_challenge_reverification_not_required",
            "begin_reverification requires a challenge marked for reverification",
        ));
    }
    let room_ref = s(&prior, "outcome_room_ref", "");
    let subject = s(&prior, "verifier_challenge_id", "");
    let authority = if governance == Governance::Host {
        s(&dependencies.room, "host_domain_ref", "")
    } else {
        s(&dependencies.challenger, "participant_ref", "")
    };
    if authority.is_empty() {
        return classify(verr(
            "verifier_challenge_authority_unavailable",
            "governing authority does not resolve",
        ));
    }
    let mutation_effect = effect(
        &op,
        revision,
        &json!({"status_before":s(&prior,"status",""),"fields":fields}),
        to,
    );
    let authorized = match authorize(
        &body,
        governance,
        &room_ref,
        &authority,
        &subject,
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
    let _provenance = provenance::ATTEMPT_FINDING_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _plane = VERIFIER_CHALLENGE_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let current = match load_record(&state.data_dir, &id) {
        Ok(Some(value)) => value,
        Ok(None) => {
            return classify(verr(
                "verifier_challenge_not_found",
                format!("no challenge '{id}'"),
            ))
        }
        Err(message) => return classify(verr("verifier_challenge_registry_unreadable", message)),
    };
    if current != prior {
        return classify(verr(
            "verifier_challenge_stale_revision",
            "challenge changed during authority resolution",
        ));
    }
    if let Err(error) = resolve_dependencies(
        &state.data_dir,
        &declaration,
        governance == Governance::Participant,
        false,
    ) {
        return classify(error);
    }
    let refs = reservation_refs(&declaration, &subject);
    let views: Vec<&str> = refs.iter().map(String::as_str).collect();
    if let Err(error) = refuse_reserved(
        &state.data_dir,
        &views,
        "verifier_challenge_mutation_in_flight",
        None,
    ) {
        return classify(error);
    }
    let receipt_tail = fresh_tail("vcr_", &subject, &op, revision, authorized.resolved_at_ms);
    let receipt_ref = format!("receipt://{receipt_tail}");
    let final_challenge = match transition_record(
        &prior,
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
        &final_challenge,
        &op,
        Some(&prior),
        &final_challenge,
        &mutation_effect,
        &authorized,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent_tail = fresh_tail("vci_", &subject, &op, revision, authorized.resolved_at_ms);
    let intent = seal_intent(
        json!({"kind":"transition","governance":if governance==Governance::Host{"host"}else{"participant"},
        "op":op,"room_ref":room_ref,"challenged_ref":s(&final_challenge,"challenged_ref",""),
        "work_result_ref":dependencies.work_result_ref,"challenger_ref":s(&final_challenge,"challenger_ref",""),
        "affected_attempt_refs":final_challenge.get("affected_attempt_refs"),"required_authority_ref":authority,
        "subject_ref":subject,"revision_before":revision,"receipt_tail":receipt_tail,"receipt":receipt,
        "prior_challenge":prior,"final_challenge":final_challenge}),
        &intent_tail,
    );
    match persist_and_complete_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::OK,
            Json(
                json!({"verifier_challenge":final_challenge,"verifier_challenge_receipt":receipt}),
            ),
        ),
        Err(error) => classify(error),
    }
}

fn ensure_read_converged(data_dir: &str) -> Result<(), VErr> {
    let intents =
        scan_intents(data_dir).map_err(|e| verr("verifier_challenge_intent_unreadable", e))?;
    if intents.is_empty() {
        Ok(())
    } else {
        Err(verr(
            "verifier_challenge_pending_convergence",
            format!(
                "{} challenge transaction(s) await authenticated convergence",
                intents.len()
            ),
        ))
    }
}

pub(crate) async fn handle_list(
    State(state): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = ensure_read_converged(&state.data_dir) {
        return classify(error);
    }
    let mut records = match scan_records(&state.data_dir) {
        Ok(value) => value,
        Err(message) => return classify(verr("verifier_challenge_registry_unreadable", message)),
    };
    records.retain(|record| {
        query
            .get("room")
            .map(|v| s(record, "outcome_room_ref", "") == *v)
            .unwrap_or(true)
            && query
                .get("status")
                .map(|v| s(record, "status", "") == *v)
                .unwrap_or(true)
            && query
                .get("challenged")
                .map(|v| s(record, "challenged_ref", "") == *v)
                .unwrap_or(true)
    });
    records.truncate(LIST_MAX);
    (
        StatusCode::OK,
        Json(json!({"verifier_challenges":records,"runtimeTruthSource":"daemon-runtime"})),
    )
}

pub(crate) async fn handle_get(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = ensure_read_converged(&state.data_dir) {
        return classify(error);
    }
    match load_record(&state.data_dir, &id) {
        Ok(Some(record)) => (StatusCode::OK, Json(json!({"verifier_challenge":record}))),
        Ok(None) => classify(verr(
            "verifier_challenge_not_found",
            format!("no challenge '{id}'"),
        )),
        Err(message) => classify(verr("verifier_challenge_registry_unreadable", message)),
    }
}

pub(crate) async fn handle_overview(
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    let records = match scan_records(&state.data_dir) {
        Ok(value) => value,
        Err(message) => return classify(verr("verifier_challenge_registry_unreadable", message)),
    };
    let pending = match scan_intents(&state.data_dir) {
        Ok(value) => value.len(),
        Err(message) => return classify(verr("verifier_challenge_intent_unreadable", message)),
    };
    let mut blockers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for record in &records {
        if UNRESOLVED.contains(&s(record, "status", "").as_str()) {
            blockers
                .entry(s(record, "challenged_ref", ""))
                .or_default()
                .push(s(record, "verifier_challenge_id", ""));
        }
    }
    (
        StatusCode::OK,
        Json(json!({"schema_version":RECORD_SCHEMA,"count":records.len(),
        "pending_convergence_count":pending,"statuses":STATUSES,"challenge_kinds":KINDS,
        "unresolved_statuses":UNRESOLVED,"unresolved_blockers_by_challenged_ref":blockers,
        "supported_targets":["attempt://","finding://"],"unsupported_targets":"typed_unavailable",
        "coordination_topology":"hosted_admission","federated_admission":"typed_unavailable",
        "acceptance_authority":"not_provided","verdict_authority":"not_provided",
        "settlement_authority":"not_provided","execution_authority":"not_provided",
        "authority":governed::decision_authority_posture(AUTHORITY),"runtimeTruthSource":"daemon-runtime"})),
    )
}

pub(crate) fn refuse_acceptance_if_unresolved(
    data_dir: &str,
    challenged_ref: &str,
) -> Result<(), VErr> {
    let blockers: Vec<String> = scan_records(data_dir)
        .map_err(|e| verr("verifier_challenge_registry_unreadable", e))?
        .into_iter()
        .filter(|record| {
            let directly_challenged = s(record, "challenged_ref", "") == challenged_ref;
            let affected_attempt = challenged_ref.starts_with("attempt://")
                && record
                    .get("affected_attempt_refs")
                    .and_then(Value::as_array)
                    .is_some_and(|items| {
                        items
                            .iter()
                            .any(|item| item.as_str() == Some(challenged_ref))
                    });
            (directly_challenged || affected_attempt)
                && UNRESOLVED.contains(&s(record, "status", "").as_str())
        })
        .map(|record| s(&record, "verifier_challenge_id", ""))
        .collect();
    let pending = scan_intents(data_dir)
        .map_err(|e| verr("verifier_challenge_intent_unreadable", e))?
        .into_iter()
        .any(|(_, intent)| {
            s(&intent, "challenged_ref", "") == challenged_ref
                || (challenged_ref.starts_with("attempt://")
                    && intent
                        .get("affected_attempt_refs")
                        .and_then(Value::as_array)
                        .is_some_and(|items| {
                            items
                                .iter()
                                .any(|item| item.as_str() == Some(challenged_ref))
                        }))
        });
    if pending || !blockers.is_empty() {
        Err(verr(
            "verifier_challenge_acceptance_unresolved",
            format!(
                "acceptance is blocked by unresolved challenge state ({})",
                if pending {
                    "pending intent".to_string()
                } else {
                    blockers.join(", ")
                }
            ),
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn refuse_room_close_if_blocked_locked(
    data_dir: &str,
    room_ref: &str,
) -> Result<(), VErr> {
    let unresolved = scan_records(data_dir)
        .map_err(|e| verr("outcome_room_verifier_challenge_registry_unreadable", e))?
        .into_iter()
        .filter(|record| {
            s(record, "outcome_room_ref", "") == room_ref
                && UNRESOLVED.contains(&s(record, "status", "").as_str())
        })
        .count();
    let pending = scan_intents(data_dir)
        .map_err(|e| verr("outcome_room_verifier_challenge_intent_unreadable", e))?
        .into_iter()
        .filter(|(_, intent)| s(intent, "room_ref", "") == room_ref)
        .count();
    if unresolved + pending > 0 {
        Err(verr("outcome_room_close_blocked_verifier_challenges", format!("room has {unresolved} unresolved challenge(s) and {pending} pending challenge transaction(s)")))
    } else {
        Ok(())
    }
}

fn challenge_declaration(record: &Value) -> Value {
    let mut value = record.clone();
    if let Some(object) = value.as_object_mut() {
        for field in [
            "schema_version",
            "verifier_challenge_id",
            "frozen_coordinates",
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
    value
}

fn reconstruct_intent(intent: &Value) -> Result<(Governance, Value, Value), String> {
    let receipt = intent
        .get("receipt")
        .ok_or_else(|| "intent lacks receipt".to_string())?;
    let op = s(intent, "op", "");
    let revision = intent
        .get("revision_before")
        .and_then(Value::as_u64)
        .ok_or_else(|| "intent lacks revision".to_string())?;
    let prior = intent
        .get("prior_challenge")
        .filter(|value| !value.is_null());
    let final_record = intent
        .get("final_challenge")
        .filter(|value| !value.is_null())
        .ok_or_else(|| "intent lacks successor".to_string())?;
    let governance = if intent.get("governance").and_then(Value::as_str) == Some("host") {
        Governance::Host
    } else {
        Governance::Participant
    };
    let subject = s(intent, "subject_ref", "");
    let record_tail = subject
        .strip_prefix("verifier-challenge://")
        .filter(|value| canonical_challenge_tail(value))
        .ok_or_else(|| "intent subject is noncanonical".to_string())?;
    let receipt_tail = intent
        .get("receipt_tail")
        .and_then(Value::as_str)
        .filter(|value| canonical_receipt_tail(value))
        .ok_or_else(|| "intent lacks canonical receipt tail".to_string())?;
    let receipt_ref = format!("receipt://{receipt_tail}");
    let resolved_at_ms = receipt
        .get("authority_resolved_at_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| "receipt lacks authority time".to_string())?;
    let expected_refs = [
        (
            "room_ref",
            final_record.get("outcome_room_ref").and_then(Value::as_str),
        ),
        (
            "challenged_ref",
            final_record.get("challenged_ref").and_then(Value::as_str),
        ),
        (
            "challenger_ref",
            final_record.get("challenger_ref").and_then(Value::as_str),
        ),
    ];
    for (field, expected) in expected_refs {
        if intent.get(field).and_then(Value::as_str) != expected {
            return Err(format!(
                "intent '{field}' differs from its deterministic successor"
            ));
        }
    }
    if intent.get("affected_attempt_refs") != final_record.get("affected_attempt_refs") {
        return Err("intent affected Attempts differ from its deterministic successor".into());
    }
    let actual_work_result = intent.get("work_result_ref").and_then(Value::as_str);
    let expected_work_result = final_record
        .pointer("/frozen_coordinates/work_result/record_ref")
        .and_then(Value::as_str);
    if actual_work_result != expected_work_result {
        return Err("intent WorkResult differs from its frozen successor coordinate".into());
    }
    let effect = if op == "create" {
        if governance != Governance::Participant || revision != 0 || prior.is_some() {
            return Err("create intent governance/prior/revision does not reconstruct".into());
        }
        let declaration = challenge_declaration(final_record);
        let coordinates = final_record
            .get("frozen_coordinates")
            .cloned()
            .ok_or_else(|| "create successor lacks frozen coordinates".to_string())?;
        let identity_tail = deterministic_tail(
            "vc_",
            &json!({"domain":"hypervisor.verifier-challenge.identity.v1",
            "declaration":declaration,"frozen_coordinates":coordinates}),
        );
        if identity_tail != record_tail {
            return Err("create successor identity does not reconstruct".into());
        }
        let expected_final = seal_create(
            &declaration,
            &coordinates,
            record_tail,
            &receipt_ref,
            resolved_at_ms,
        )
        .map_err(|(_, message)| message)?;
        if &expected_final != final_record {
            return Err("create successor does not reconstruct byte-exactly".into());
        }
        effect(
            "create",
            0,
            &json!({"declaration":challenge_declaration(final_record),
            "frozen_coordinates":final_record.get("frozen_coordinates").cloned().unwrap_or(Value::Null)}),
            "proposed",
        )
    } else {
        let prior = prior.ok_or_else(|| "transition intent lacks prior".to_string())?;
        let (expected_governance, to) =
            transition_contract(&op, &s(prior, "status", "")).map_err(|(_, message)| message)?;
        if governance != expected_governance
            || revision != prior.get("revision").and_then(Value::as_u64).unwrap_or(0)
            || prior.get("verifier_challenge_id").and_then(Value::as_str) != Some(subject.as_str())
        {
            return Err(
                "transition governance, revision, or predecessor identity does not reconstruct"
                    .into(),
            );
        }
        let fields = if op == "rule_changed" {
            json!({"prior_rule_version_ref":final_record.get("prior_rule_version_ref"),
            "proposed_rule_version_ref":final_record.get("proposed_rule_version_ref"),"affected_attempt_refs":final_record.get("affected_attempt_refs"),
            "reverification_required":final_record.get("reverification_required")})
        } else {
            json!({})
        };
        let expected_final =
            transition_record(prior, &op, to, &fields, &receipt_ref, resolved_at_ms)
                .map_err(|(_, message)| message)?;
        if &expected_final != final_record {
            return Err("transition successor does not reconstruct byte-exactly".into());
        }
        effect(
            &op,
            revision,
            &json!({"status_before":s(prior,"status",""),"fields":fields}),
            &s(final_record, "status", ""),
        )
    };
    governed::validate_sealed_effect(AUTHORITY, receipt, &effect)?;
    let authorized = AuthorizedDecision {
        evidence: governed::sealed_evidence(receipt),
        resolved_at_ms,
    };
    let expected = build_receipt(
        receipt_tail,
        final_record,
        &op,
        prior,
        final_record,
        &effect,
        &authorized,
    )
    .map_err(|(_, m)| m)?;
    if &expected != receipt {
        return Err("receipt does not reconstruct byte-exactly".into());
    }
    Ok((governance, effect, final_record.clone()))
}

pub(crate) async fn complete_governed_verifier_challenge_intents(
    data_dir: &str,
    max_intents: usize,
) {
    let intents = match scan_intents(data_dir) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("VerifierChallenge completer: scan failed ({message})");
            return;
        }
    };
    for (tail, intent) in intents.into_iter().take(max_intents) {
        let (governance, effect, source) = match reconstruct_intent(&intent) {
            Ok(value) => value,
            Err(message) => {
                eprintln!("VerifierChallenge completer: '{tail}' invalid ({message}); retained");
                continue;
            }
        };
        let room_ref = s(&intent, "room_ref", "");
        let challenger_ref = s(&intent, "challenger_ref", "");
        let required = if governance == Governance::Host {
            rooms::resolve_room_host(data_dir, &room_ref).unwrap_or_default()
        } else {
            match participant_strict(data_dir, &challenger_ref, true) {
                Ok(value) => s(&value, "participant_ref", ""),
                Err(_) => String::new(),
            }
        };
        if required.is_empty()
            || intent.get("required_authority_ref").and_then(Value::as_str)
                != Some(required.as_str())
        {
            continue;
        }
        if resolve_dependencies(
            data_dir,
            &source,
            governance == Governance::Participant,
            false,
        )
        .is_err()
        {
            continue;
        }
        let receipt = intent.get("receipt").unwrap_or(&Value::Null);
        let op = s(&intent, "op", "");
        let subject = s(&intent, "subject_ref", "");
        let revision = intent
            .get("revision_before")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if let Err(message) = governed::reauthorize_sealed_receipt(
            AUTHORITY, receipt, governance, &room_ref, &required, &subject, &op, revision, &effect,
        )
        .await
        {
            eprintln!(
                "VerifierChallenge completer: '{tail}' authority refused ({message}); retained"
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
        let _provenance = provenance::ATTEMPT_FINDING_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _plane = VERIFIER_CHALLENGE_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if resolve_dependencies(
            data_dir,
            &source,
            governance == Governance::Participant,
            false,
        )
        .is_err()
        {
            continue;
        }
        if let Err((_, message)) = complete_intent_locked(data_dir, &tail, &intent) {
            eprintln!(
                "VerifierChallenge completer: '{tail}' convergence failed ({message}); retained"
            );
        }
    }
}

#[cfg(test)]
mod verifier_challenge_tests {
    use super::super::governed_authority::DecisionEvidence;
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ioi-verifier-challenge-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn body() -> Value {
        json!({
            "outcome_room_ref":"outcome-room://or_a",
            "challenger_ref":"participant-lease://rpl_a",
            "challenged_ref":format!("attempt://att_{}", "a".repeat(64)),
            "challenge_kind":"evidence",
            "challenge_evidence_refs":["evidence://ev_a"],
            "adjudicator_policy_ref":"policy://adjudicator-a",
            "prior_rule_version_ref":null,
            "proposed_rule_version_ref":null,
            "affected_attempt_refs":[format!("attempt://att_{}", "a".repeat(64))],
            "reverification_required":false,
            "coordination_topology":"hosted_admission",
            "expected_revision":0,
            "wallet_approval_grant":null
        })
    }

    #[test]
    fn canonical_identity_is_exact_lower_hex() {
        assert!(canonical_challenge_tail(&format!("vc_{}", "a".repeat(64))));
        assert!(!canonical_challenge_tail(&format!("vc_{}", "A".repeat(64))));
        assert!(!canonical_challenge_tail("vc_short"));
    }

    #[test]
    fn only_attempt_and_finding_targets_are_available() {
        for prefix in [
            "verifier-path://vp_a",
            "benchmark://b_a",
            "rubric://r_a",
            "evidence://e_a",
            "eligibility://m_a",
            "decision://d_a",
            "federated://f_a",
        ] {
            let mut value = body();
            value["challenged_ref"] = json!(prefix);
            assert_eq!(
                validate_create(&value).unwrap_err().0,
                "verifier_challenge_target_resolver_unavailable"
            );
        }
    }

    #[test]
    fn worker_org_and_user_challengers_fail_closed() {
        for reference in ["worker://w_a", "org://o_a", "user://u_a"] {
            let mut value = body();
            value["challenger_ref"] = json!(reference);
            assert_eq!(
                validate_create(&value).unwrap_err().0,
                "verifier_challenge_challenger_mapping_unavailable"
            );
        }
    }

    #[test]
    fn lifecycle_is_exact_and_creates_no_verdict() {
        assert_eq!(
            transition_contract("admit", "proposed").unwrap().1,
            "admitted"
        );
        assert_eq!(
            transition_contract("uphold", "investigating").unwrap().1,
            "upheld"
        );
        assert_eq!(
            transition_contract("resolve", "reverifying").unwrap().1,
            "resolved"
        );
        assert!(transition_contract("resolve", "proposed").is_err());
        let mutation = effect("uphold", 3, &json!({}), "upheld");
        assert_eq!(mutation["verdict_created"], json!(false));
        assert_eq!(mutation["acceptance_created"], json!(false));
        assert_eq!(mutation["execution_authority_granted"], json!(false));
    }

    #[test]
    fn rule_change_requires_exact_versions_attempts_and_reverification() {
        let mut value = json!({"transition":"rule_changed","expected_revision":4,
            "prior_rule_version_ref":"rubric://v1","proposed_rule_version_ref":"rubric://v2",
            "affected_attempt_refs":[format!("attempt://att_{}", "a".repeat(64))],
            "reverification_required":false,"wallet_approval_grant":null});
        assert_eq!(
            validate_transition(&value, "rule_changed").unwrap_err().0,
            "verifier_challenge_rule_change_reverification_required"
        );
        value["reverification_required"] = json!(true);
        assert!(validate_transition(&value, "rule_changed").is_ok());
        value
            .as_object_mut()
            .unwrap()
            .remove("prior_rule_version_ref");
        assert_eq!(
            validate_transition(&value, "rule_changed").unwrap_err().0,
            "verifier_challenge_ref_required"
        );
    }

    #[test]
    fn recursive_secrets_and_plane_owned_fields_refuse() {
        let mut value = body();
        value["nested"] = json!({"api_token":"clear"});
        assert_eq!(
            validate_create(&value).unwrap_err().0,
            "verifier_challenge_plaintext_secret_rejected"
        );
        let mut value = body();
        value["status"] = json!("resolved");
        assert_eq!(
            validate_create(&value).unwrap_err().0,
            "verifier_challenge_field_unknown"
        );
    }

    #[test]
    fn touched_refs_are_exact_sorted_aggregate_reservations() {
        let subject = format!("verifier-challenge://vc_{}", "b".repeat(64));
        let attempt = format!("attempt://att_{}", "a".repeat(64));
        let intent = seal_intent(
            json!({"kind":"create","subject_ref":subject,
            "room_ref":"outcome-room://or_a","challenged_ref":attempt,
            "work_result_ref":"work-result://wr_a","challenger_ref":"participant-lease://rpl_a",
            "affected_attempt_refs":[attempt]}),
            &format!("vci_{}", "c".repeat(64)),
        );
        let touched = validate_touched(&intent).unwrap();
        let mut sorted = touched.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(touched, sorted);
        assert_eq!(touched.len(), 5);
    }

    #[test]
    fn pending_intent_reserves_room_target_attempt_participant_and_result() {
        let dir = temp_dir("reservation");
        let tail = format!("vci_{}", "4".repeat(64));
        let attempt = format!("attempt://att_{}", "a".repeat(64));
        let target = format!("finding://fnd_{}", "b".repeat(64));
        let intent = seal_intent(
            json!({"kind":"create","subject_ref":format!("verifier-challenge://vc_{}", "c".repeat(64)),
                "room_ref":"outcome-room://or_a","challenged_ref":target,
                "work_result_ref":"work-result://wr_a","challenger_ref":"participant-lease://rpl_a",
                "affected_attempt_refs":[attempt]}),
            &tail,
        );
        persist_record(dir.to_str().unwrap(), INTENT_DIR, &tail, &intent).unwrap();
        for reference in [
            "outcome-room://or_a",
            target.as_str(),
            attempt.as_str(),
            "participant-lease://rpl_a",
            "work-result://wr_a",
        ] {
            let error = refuse_external_mutation_if_reserved(
                dir.to_str().unwrap(),
                reference,
                "aggregate_mutation_in_flight",
            )
            .unwrap_err();
            assert_eq!(error.0, "aggregate_mutation_in_flight");
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn strict_loader_distinguishes_absent_malformed_and_relocated() {
        let dir = temp_dir("strict");
        let tail = format!("vc_{}", "9".repeat(64));
        assert!(load_record(dir.to_str().unwrap(), &tail).unwrap().is_none());
        let family = dir.join(RECORD_DIR);
        std::fs::create_dir_all(&family).unwrap();
        std::fs::write(family.join(format!("{tail}.json")), b"{").unwrap();
        assert!(load_record(dir.to_str().unwrap(), &tail).is_err());
        std::fs::write(family.join(format!("{tail}.json")), serde_json::to_vec(&json!({
            "schema_version":RECORD_SCHEMA,"verifier_challenge_id":format!("verifier-challenge://vc_{}", "8".repeat(64)),
            "revision":1,"status":"proposed"})).unwrap()).unwrap();
        assert!(load_record(dir.to_str().unwrap(), &tail).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn transition_intent_reconstructs_its_complete_successor() {
        let subject = format!("verifier-challenge://vc_{}", "3".repeat(64));
        let attempt = format!("attempt://att_{}", "2".repeat(64));
        let prior = json!({"schema_version":RECORD_SCHEMA,"verifier_challenge_id":subject,
            "outcome_room_ref":"outcome-room://or_a","challenger_ref":"participant-lease://rpl_a",
            "challenged_ref":attempt,"challenge_kind":"rule","challenge_evidence_refs":[],
            "adjudicator_policy_ref":"policy://p","prior_rule_version_ref":null,"proposed_rule_version_ref":null,
            "affected_attempt_refs":[attempt],"reverification_required":false,"adjudication_ref":null,
            "coordination_topology":"hosted_admission","frozen_coordinates":{"challenged_target":{"kind":"attempt"},
                "bound_attempt_ref":attempt,"affected_attempts":[],"work_result":null,
                "challenger_participant":{"record_ref":"participant-lease://rpl_a"},"room":{"record_ref":"outcome-room://or_a"}},
            "status":"admitted","revision":2,"created_at":"1970-01-01T00:00:01Z","created_at_ms":1000,
            "updated_at":"1970-01-01T00:00:01Z","updated_at_ms":1000,"admission_receipt_ref":"receipt://vcr_old",
            "admission_and_replay_refs":["receipt://vcr_old"],"status_history":[],"runtimeTruthSource":"daemon-runtime"});
        let at_ms = 2_000;
        let receipt_tail = format!("vcr_{}", "4".repeat(64));
        let receipt_ref = format!("receipt://{receipt_tail}");
        let final_record = transition_record(
            &prior,
            "investigate",
            "investigating",
            &json!({}),
            &receipt_ref,
            at_ms,
        )
        .unwrap();
        let mutation_effect = effect(
            "investigate",
            2,
            &json!({"status_before":"admitted","fields":{}}),
            "investigating",
        );
        let authorized = AuthorizedDecision {
            resolved_at_ms: at_ms,
            evidence: DecisionEvidence {
                acting_authority_id: json!("authority://test"),
                grant_ref: "grant://test".into(),
                policy_hash: "sha256:test".into(),
                request_hash: "sha256:test".into(),
                effect_hash: "sha256:test".into(),
                authorized_effect: mutation_effect.clone(),
                wallet_approval_grant: Value::Null,
                authority_binding: Value::Null,
            },
        };
        let receipt = build_receipt(
            &receipt_tail,
            &final_record,
            "investigate",
            Some(&prior),
            &final_record,
            &mutation_effect,
            &authorized,
        )
        .unwrap();
        let intent = seal_intent(
            json!({"kind":"transition","governance":"host","op":"investigate",
            "room_ref":"outcome-room://or_a","challenged_ref":attempt,"work_result_ref":null,
            "challenger_ref":"participant-lease://rpl_a","affected_attempt_refs":[attempt],
            "required_authority_ref":"domain://host","subject_ref":subject,"revision_before":2,
            "receipt_tail":receipt_tail,"receipt":receipt,"prior_challenge":prior,"final_challenge":final_record}),
            &format!("vci_{}", "5".repeat(64)),
        );
        reconstruct_intent(&intent).unwrap();
    }
}
