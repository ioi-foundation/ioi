//! WorkResult + OutcomeDelta plane — the FIRST contract-first cut of the collaborative-pursuit
//! leg (canon-to-code-delta build step 1). Admits the GENERIC bounded result seam of
//! `WorkResultEnvelope` (canonical owner: docs/architecture/foundations/
//! objects/work-results-and-lifecycle.md) — a result may come from research, ontology mutation,
//! incident resolution, service delivery, physical missions, review, or evaluation, not only
//! software; `ImplementationResultPayload` (the `implementation_result` GoalRun payload) remains
//! the SOFTWARE profile reached through `result_profile: software_implementation` +
//! `result_payload_ref`, and is NOT the general model.
//!
//! Doctrine enforced here (hardened per the #71 review):
//! - RECURSIVE sensitive-key rejection over every persisted subtree: any object key in the body
//!   whose normalized form contains password/secret/credential/authorization/privatekey/apikey/
//!   token refuses typed — a nested `uncertainty.password` can never persist.
//! - CANONICAL-REF validation per field: every scalar and list ref field accepts ONLY the
//!   envelope's declared schemes for that field (including the special non-URI forms
//!   `scope:*`, `harness_profile:*`, `agent_harness_adapter:*`, and `encrypted_ref`); a raw
//!   string is never a ref. `goal_ref` must be a `goal://` identity.
//! - ROOM ownership is fail-closed: the generic POST routes refuse non-null
//!   `outcome_room_ref`, retired `room_admission`/`room_binding`, and `system_binding`; only the
//!   GoalRun-owner/private v3 seam may derive SystemScopedObjectBinding and submit
//!   room-associated truth through Agentgres expected-head admission.
//! - FUTURE-PLANE fields are named gaps, fail-closed: non-empty `work_claim_ref`,
//!   `attempt_ref`, `finding_refs`, `acceptance_ref`, and
//!   `superseded_by_ref` refuse with per-field unavailable codes until their planes exist
//!   (build steps 2-3) — callers cannot forge assurance or relationship state.
//!   `outcome_delta_refs` and `challenge_refs` are PLANE-OWNED: their owner-plane admissions
//!   register backlinks atomically; callers may never supply either list.
//! - BINDING invariants resolve RECORDS, not booleans: an OutcomeDelta binds an EXISTING
//!   WorkResult with the SAME `goal_ref` (cross-goal refuses typed, zero mutation); a
//!   `supersedes_work_result_ref` must resolve to an existing SAME-GOAL result.
//! - RECEIPTS are distinct pure profiles on the canonical `ReceiptEnvelope` base
//!   (`receipt://` identity, receipt_type, profile ref, actor/subject, bound facts, output
//!   hash, timestamp, assurance posture): `WorkResultReceipt` binds the result profile and
//!   outcome class; `OutcomeDeltaAdmissionReceipt` binds proposer, target, kind,
//!   preconditions, expected effect, and verifier/acceptance posture, and states explicitly
//!   that the PROPOSAL record was admitted while `effect_admitted: false`.
//! - ATOMIC persistence (#62/#69 discipline) extended to the delta→result BACKLINK: delta
//!   record first, backlink second, receipt third; every failure lane rolls back all earlier
//!   writes with CHECKED operations and a distinct typed 5xx; no orphan record, no orphan
//!   backlink, no orphan receipt.
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{collections::BTreeMap, io::ErrorKind};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[cfg(test)]
use super::read_record_dir;
use super::{iso_now, persist_record, remove_record, DaemonState};

const RESULT_SCHEMA: &str = "ioi.foundations.work-result.v3";
const RESULT_CONTRACT: &str = "schema://ioi/foundations/work-result/v3";
const RESULT_RECEIPT_SCHEMA: &str = "ioi.hypervisor.work-result-receipt.v1";
const DELTA_SCHEMA: &str = "ioi.foundations.outcome-delta.v3";
const DELTA_CONTRACT: &str = "schema://ioi/foundations/outcome-delta/v3";
const DELTA_RECEIPT_SCHEMA: &str = "ioi.hypervisor.outcome-delta-admission-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.work-results-overview.v1";
const RESULT_REGISTRY_PROJECTION_SCHEMA: &str =
    "ioi.hypervisor.versioned-work-result-registry-projection.v1";
const DELTA_REGISTRY_PROJECTION_SCHEMA: &str =
    "ioi.hypervisor.versioned-outcome-delta-registry-projection.v1";
pub(crate) const RESULT_DIR: &str = "work-result-registry";
const RESULT_RECEIPT_DIR: &str = "work-result-registry-receipts";
pub(crate) const DELTA_DIR: &str = "outcome-delta-registry";
const DELTA_RECEIPT_DIR: &str = "outcome-delta-registry-receipts";

/// The canonical envelope vocabularies
/// (docs/architecture/foundations/objects/work-results-and-lifecycle.md, verbatim).
const RESULT_PROFILES: &[&str] = &[
    "software_implementation",
    "research",
    "ontology_mutation",
    "incident_resolution",
    "service_delivery",
    "physical_mission",
    "review",
    "evaluation",
    "custom",
];
const OUTCOME_CLASSES: &[&str] = &[
    "positive",
    "negative",
    "inconclusive",
    "invalid",
    "exploit_found",
    "superseded",
];
const RESULT_STATUSES: &[&str] = &[
    "completed",
    "failed",
    "blocked",
    "partial",
    "challenged",
    "superseded",
];
const NEXT_ACTIONS: &[&str] = &[
    "none",
    "repair",
    "review",
    "verify",
    "replicate",
    "synthesize",
    "ask_user",
    "escalate",
    "update_work_queue",
];
const REPRODUCTION_STATES: &[&str] = &[
    "unreviewed",
    "reproducible",
    "not_reproduced",
    "contradicted",
    "invalidated",
];
const DELTA_KINDS: &[&str] = &[
    "create",
    "update",
    "supersede",
    "reject",
    "merge",
    "promote",
    "rollback",
    "course_correct",
    "close",
];
/// OutcomeDelta target schemes (the canonical target_ref vocabulary).
const DELTA_TARGET_SCHEMES: &[&str] = &[
    "frontier",
    "finding",
    "ontology",
    "state",
    "capability",
    "policy",
    "routing-prior",
    "service",
];
/// Proposer planes the canon names that are NOT yet admitted (build step 3) — refused typed.
const UNAVAILABLE_PROPOSER_SCHEMES: &[&str] = &["attempt", "finding", "participant-lease"];
/// Normalized sensitive-key fragments: an object key ANYWHERE in the body whose normalized form
/// (lowercased, separators stripped) contains one of these refuses the whole admission.
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "password",
    "secret",
    "credential",
    "authorization",
    "privatekey",
    "apikey",
    "token",
];

/// Serializes every delta admission's read→bind→backlink→receipt critical section (#71 round 2):
/// without it, two concurrent admissions read the same WorkResult snapshot and the second
/// truncating write loses the first's backlink. Held across SYNCHRONOUS file I/O only — no
/// .await ever executes under this lock.
pub(crate) static DELTA_ADMISSION_LOCK: Mutex<()> = Mutex::new(());

const RESULT_RECORD_SCHEMAS: &[&str] = &[RESULT_SCHEMA];
const DELTA_RECORD_SCHEMAS: &[&str] = &[DELTA_SCHEMA];

fn identity_hash_key(prefix: &str, identity: &str) -> String {
    format!(
        "{prefix}{}",
        hex::encode(Sha256::digest(identity.as_bytes()))
    )
}

/// Collision-free live slot for M3's direct GoalRun WorkResult/OutcomeDelta generation. The
/// result and delta families are distinct, so the same generation prefix is unambiguous. Startup
/// migration uses this exact key too: a legacy source and a newly-admitted M3 record cannot create
/// two live aliases for one identity.
pub(crate) fn goal_run_work_truth_record_key(identity: &str) -> String {
    identity_hash_key("m3_goal_run_", identity)
}

fn bounded_work_truth_identity(identity: &str, scheme: &str) -> bool {
    identity.strip_prefix(scheme).is_some_and(|tail| {
        !tail.is_empty()
            && tail.len() <= 500
            && !tail.chars().any(char::is_whitespace)
            && !tail.contains("..")
    })
}

fn expected_current_slots(record: &Value, identity: &str) -> Result<Vec<String>, String> {
    let schema = record
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(schema, RESULT_SCHEMA | DELTA_SCHEMA) {
        return Err(format!("unsupported record schema '{schema}'"));
    }
    let tail = identity
        .split_once("://")
        .map(|(_, tail)| tail)
        .unwrap_or("");
    let keys = if record.get("system_binding").is_some_and(Value::is_object) {
        vec![identity_hash_key("room_owner_", identity)]
    } else if tail.len() <= 120
        && tail
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        vec![tail.to_string()]
    } else {
        vec![goal_run_work_truth_record_key(identity)]
    };
    Ok(keys.into_iter().map(|key| format!("{key}.json")).collect())
}

fn read_versioned_registry_strict(
    data_dir: &str,
    family: &str,
    identity_field: &str,
    identity_scheme: &str,
    accepted_schemas: &[&str],
) -> Result<Vec<Value>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("{family} cannot be pinned ({error})")),
    };
    let names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|error| format!("{family} cannot be enumerated ({error})"))?;
    let mut records = BTreeMap::<String, Value>::new();
    for name in names {
        if !name.ends_with(".json") {
            return Err(format!(
                "{family} contains non-record entry '{name}'; partial registry truth is refused"
            ));
        }
        let Some((_file, bytes)) = super::durable_fs::read_slot_strict(&directory, &name)
            .map_err(|error| format!("{family}/{name} is unreadable ({error})"))?
        else {
            return Err(format!(
                "{family}/{name} disappeared during its pinned registry read"
            ));
        };
        let record: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("{family}/{name} is malformed ({error})"))?;
        let schema = record
            .get("schema_version")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !accepted_schemas.contains(&schema) {
            return Err(format!(
                "{family}/{name} declares unsupported record schema '{schema}'"
            ));
        }
        let contract_id = if identity_field == "work_result_id" {
            RESULT_CONTRACT
        } else {
            DELTA_CONTRACT
        };
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            contract_id,
            &record,
        )
        .map_err(|error| format!("{family}/{name} fails '{contract_id}' ({error})"))?;
        let identity = record
            .get(identity_field)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if !bounded_work_truth_identity(&identity, identity_scheme) {
            return Err(format!(
                "{family}/{name} fails its {identity_field} scheme/shape binding"
            ));
        }
        let expected_slots = expected_current_slots(&record, &identity)?;
        if !expected_slots.contains(&name) {
            return Err(format!(
                "{family}/{name} is relocated from the exact '{schema}' slot for '{identity}'"
            ));
        }
        if records.insert(identity.clone(), record).is_some() {
            return Err(format!(
                "{family} resolves duplicate identity '{identity}'; ambiguous truth is refused"
            ));
        }
    }
    Ok(records.into_values().collect())
}

pub(crate) fn list_work_results_strict(data_dir: &str) -> Result<Vec<Value>, String> {
    read_versioned_registry_strict(
        data_dir,
        RESULT_DIR,
        "work_result_id",
        "work-result://",
        RESULT_RECORD_SCHEMAS,
    )
}

pub(crate) fn list_outcome_deltas_strict(data_dir: &str) -> Result<Vec<Value>, String> {
    read_versioned_registry_strict(
        data_dir,
        DELTA_DIR,
        "outcome_delta_id",
        "outcome-delta://",
        DELTA_RECORD_SCHEMAS,
    )
}

/// Strict WorkResult point loader for later provenance planes. Unlike the legacy list helper,
/// this distinguishes absence from an occupied unreadable/malformed/identity-mismatched slot.
pub(crate) fn load_work_result_strict(
    data_dir: &str,
    result_ref: &str,
) -> Result<Option<Value>, String> {
    if !result_ref.starts_with("work-result://")
        || result_ref.len() <= "work-result://".len()
        || result_ref.len() > 500
        || result_ref.chars().any(char::is_whitespace)
    {
        return Err("WorkResult ref must be one bounded work-result:// identity".into());
    }
    Ok(list_work_results_strict(data_dir)?
        .into_iter()
        .find(|record| record.get("work_result_id").and_then(Value::as_str) == Some(result_ref)))
}

/// Resolve the exact already-occupied storage slot for a live WorkResult. This is used only by
/// owner-plane successor writes: it preserves the admitted generation's path instead of creating
/// a second alias when updating a historical M3 record.
pub(crate) fn resolve_work_result_storage_key_strict(
    data_dir: &str,
    result_ref: &str,
) -> Result<Option<String>, String> {
    let Some(record) = load_work_result_strict(data_dir, result_ref)? else {
        return Ok(None);
    };
    let expected = expected_current_slots(&record, result_ref)?;
    let directory = super::durable_fs::open_family_dir_pinned(data_dir, RESULT_DIR)
        .map_err(|error| format!("WorkResult registry cannot be pinned ({error})"))?;
    let mut occupied = Vec::new();
    for name in expected {
        match super::durable_fs::read_slot_strict(&directory, &name) {
            Ok(Some((_file, bytes))) => {
                let candidate: Value = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("WorkResult slot '{name}' is malformed ({error})"))?;
                if candidate != record {
                    return Err(format!(
                        "WorkResult slot '{name}' changed during exact path resolution"
                    ));
                }
                occupied.push(name.trim_end_matches(".json").to_string());
            }
            Ok(None) => {}
            Err(error) => return Err(format!("WorkResult slot '{name}' is unreadable ({error})")),
        }
    }
    match occupied.as_slice() {
        [] => Err(format!(
            "WorkResult '{result_ref}' has no occupied admitted storage slot"
        )),
        [key] => Ok(Some(key.clone())),
        _ => Err(format!(
            "WorkResult '{result_ref}' occupies multiple admitted storage slots"
        )),
    }
}

// ------------------------------------------------- the WorkResult owner's published subject resolver

/// The domain separator for the WorkResult RECORD commitment (M06.1).
///
/// Deliberately NOT `record_output_hash`/`RESULT_HASH_EXCLUDES`. That digest exists for the
/// ADMISSION RECEIPT and excludes the plane-owned mutable fields on purpose, so a later backlink
/// cannot invalidate a frozen receipt. Reusing it here would be the exact pretense M06.1 is required
/// to refuse: two genuinely different versions of one record — before and after an owner-admitted
/// `outcome_delta_refs` or `review_refs` backlink — would collide under one hash, and a consumer
/// binding "the exact bytes" would be binding a hash that cannot tell them apart. This commitment
/// covers the WHOLE record, so each owner-admitted version is a DISTINCT content hash and the URI
/// alone is never treated as a stable identity.
pub(crate) const WORK_RESULT_COMMITMENT_DOMAIN: &str =
    "ioi.work-result-record-commitment-jcs-sha256.v1";

/// One WorkResult, resolved by its own owner: the exact admitted record, the bytes it currently
/// commits to, and the two verbatim vocabulary members a consumer may never re-derive for itself.
#[derive(Debug)]
pub(crate) struct ResolvedWorkResult {
    pub content_hash: String,
    pub record: Value,
    /// Carried VERBATIM from the WorkResult vocabulary (which has `exploit_found`, and has neither
    /// `disputed` nor `no_fault`). It is NOT the assurance ladder's `outcome_class` and must never
    /// be mapped onto it: two vocabularies that overlap in most members and disagree in three are
    /// exactly where a silent normalisation would hide.
    pub outcome_class: String,
    pub status: String,
}

/// Commit the EXACT record bytes under an explicit domain and version.
fn work_result_record_commitment(record: &Value) -> Result<String, String> {
    let material = json!({
        "domain": WORK_RESULT_COMMITMENT_DOMAIN,
        "record": record,
    });
    serde_jcs::to_vec(&material)
        .map(|bytes| format!("sha256:{:x}", Sha256::digest(&bytes)))
        .map_err(|error| format!("WorkResult record could not be canonicalized ({error})"))
}

/// The WorkResult owner's visibility reader, exposed for neighbouring planes that must resolve a
/// `work-result://` subject WITHOUT widening or narrowing what this owner would show the same
/// caller. It is the same computation `global_truth_reader` performs; both go through here so the
/// two can never drift into two different answers about who may see a result.
pub(crate) fn work_truth_visibility_reader(
    data_dir: &str,
    headers: &HeaderMap,
) -> Result<Option<String>, (StatusCode, Json<Value>)> {
    match super::lifecycle_routes::deployment_auth_posture(data_dir, headers) {
        "local_development" => Ok(None),
        "exposed_untrusted" => Err((
            StatusCode::FORBIDDEN,
            Json(
                json!({"error":{"code":"work_truth_exposed_untrusted_refused","message":"Global WorkResult and OutcomeDelta truth is unavailable on an exposed deployment without enforced identity."}}),
            ),
        )),
        _ => {
            let principal = super::lifecycle_routes::resolve_principal(data_dir, headers)
                .ok_or_else(|| (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error":{"code":"work_truth_authentication_required","message":"Authentication is required before reading global WorkResult or OutcomeDelta truth."}})),
                ))?;
            let principal_id = s(&principal, "principal_id", "");
            if principal_id.is_empty() {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(
                        json!({"error":{"code":"work_truth_principal_unresolved","message":"The authenticated request did not resolve a principal identity."}}),
                    ),
                ));
            }
            Ok(Some(format!("user://{principal_id}")))
        }
    }
}

/// Resolve one `work-result://` subject through THIS owner, or refuse by name.
///
/// THE PREFIX IS NEVER THE PROOF. A well-formed `work-result://` that names nothing admitted is
/// refused as absent, and a record this reader is not entitled to see is refused with the same
/// code and message as one that does not exist — a caller must not be able to use the graph as an
/// oracle for the existence of another owner's results.
///
/// `reader` is this owner's own visibility answer (see `work_truth_visibility_reader`), threaded in
/// rather than recomputed, so a consumer sees exactly what `GET /v1/hypervisor/work-results/:id`
/// would show the same caller.
pub(crate) fn resolve_admitted_work_result(
    data_dir: &str,
    reader: Option<&str>,
    result_ref: &str,
) -> Result<ResolvedWorkResult, (String, String)> {
    let absent = || {
        verr(
            "work_result_subject_not_admitted",
            format!("no admitted WorkResult resolves '{result_ref}' for this reader"),
        )
    };
    let record = load_work_result_strict(data_dir, result_ref)
        .map_err(|message| verr("work_result_subject_unreadable", message))?
        .ok_or_else(absent)?;
    if let Some(owner) = reader {
        // The owner's OWN entitlement check, not a second interpretation of it.
        if !result_owner_matches(data_dir, &record, owner)
            .map_err(|message| verr("work_result_subject_unreadable", message))?
        {
            return Err(absent());
        }
    }
    let content_hash = work_result_record_commitment(&record)
        .map_err(|message| verr("work_result_subject_commitment_failed", message))?;
    let outcome_class = s(&record, "outcome_class", "");
    let status = s(&record, "status", "");
    if outcome_class.is_empty() || status.is_empty() {
        return Err(verr(
            "work_result_subject_vocabulary_absent",
            "the admitted WorkResult carries no outcome_class/status pair to carry verbatim",
        ));
    }
    Ok(ResolvedWorkResult {
        content_hash,
        record,
        outcome_class,
        status,
    })
}

fn canonical_verifier_challenge_ref(reference: &str) -> bool {
    reference
        .strip_prefix("verifier-challenge://vc_")
        .is_some_and(|tail| {
            tail.len() == 64
                && tail
                    .chars()
                    .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
        })
}

/// Pure WorkResult-owned successor planner for a VerifierChallenge backlink. The challenge plane
/// seals both the exact prior and this exact successor in its durable intent; replay never derives
/// a successor from mutable current state.
pub(crate) fn verifier_challenge_backlink_successor(
    prior: &Value,
    result_ref: &str,
    challenge_ref: &str,
) -> Result<Value, (String, String)> {
    if prior.get("schema_version").and_then(Value::as_str) != Some(RESULT_SCHEMA)
        || prior.get("work_result_id").and_then(Value::as_str) != Some(result_ref)
    {
        return Err(verr(
            "work_result_challenge_backlink_identity_mismatch",
            "sealed WorkResult prior does not match its schema and identity",
        ));
    }
    if !canonical_verifier_challenge_ref(challenge_ref) {
        return Err(verr(
            "work_result_challenge_ref_invalid",
            "VerifierChallenge backlink must be verifier-challenge://vc_<64 lowercase hex>",
        ));
    }
    let refs = prior
        .get("review_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "work_result_challenge_backlink_invalid",
                "WorkResult review_refs is not a plane-owned list",
            )
        })?;
    if refs.len() >= 128 {
        return Err(verr(
            "work_result_challenge_backlink_capacity",
            "WorkResult review_refs reached its hard bound",
        ));
    }
    if refs.iter().any(|item| item.as_str() == Some(challenge_ref)) {
        return Err(verr(
            "work_result_challenge_backlink_already_bound",
            "VerifierChallenge is already bound to this WorkResult",
        ));
    }
    let mut next = prior.clone();
    let object = next.as_object_mut().expect("validated WorkResult object");
    let mut next_refs: Vec<String> = refs
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    next_refs.push(challenge_ref.to_string());
    next_refs.sort();
    next_refs.dedup();
    object.insert("review_refs".into(), json!(next_refs));
    Ok(next)
}

/// WorkResult-owned, lock-required backlink seam. The caller holds DELTA_ADMISSION_LOCK and
/// passes the exact intent tail so only that intent's reservation is bypassed. Current bytes must
/// equal the sealed prior or sealed successor; every other state refuses without mutation.
pub(crate) fn bind_verifier_challenge_locked(
    data_dir: &str,
    result_ref: &str,
    challenge_ref: &str,
    prior: &Value,
    successor: &Value,
    intent_tail: &str,
) -> Result<Value, (String, String)> {
    let expected = verifier_challenge_backlink_successor(prior, result_ref, challenge_ref)?;
    if expected != *successor {
        return Err(verr(
            "work_result_challenge_backlink_invalid",
            "sealed WorkResult successor does not reconstruct exactly",
        ));
    }
    let current = load_work_result_strict(data_dir, result_ref)
        .map_err(|message| verr("work_result_challenge_backlink_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "work_result_challenge_backlink_not_found",
                format!("no WorkResult '{result_ref}'"),
            )
        })?;
    if current == *successor {
        return Ok(current);
    }
    if current != *prior {
        return Err(verr(
            "work_result_challenge_backlink_conflict",
            "WorkResult equals neither the sealed prior nor sealed successor",
        ));
    }
    super::verifier_challenge_routes::refuse_external_mutation_if_reserved_except(
        data_dir,
        result_ref,
        "work_result_mutation_in_flight",
        intent_tail,
    )?;
    let storage_key = resolve_work_result_storage_key_strict(data_dir, result_ref)
        .map_err(|message| verr("work_result_challenge_backlink_unreadable", message))?
        .ok_or_else(|| {
            verr(
                "work_result_challenge_backlink_not_found",
                format!("no WorkResult '{result_ref}'"),
            )
        })?;
    persist_result_atomic(data_dir, &storage_key, successor).map_err(|error| {
        verr(
            "work_result_challenge_backlink_persist_failed",
            format!("WorkResult challenge backlink persist failed ({error})"),
        )
    })?;
    Ok(successor.clone())
}

/// Strict OutcomeDelta point loader for provenance consumers. The WorkResult plane remains the
/// storage owner: callers receive absence distinctly from unreadable, malformed, or relocated
/// canonical evidence and never scan this family themselves.
pub(crate) fn load_outcome_delta_strict(
    data_dir: &str,
    delta_ref: &str,
) -> Result<Option<Value>, String> {
    if !delta_ref.starts_with("outcome-delta://")
        || delta_ref.len() <= "outcome-delta://".len()
        || delta_ref.len() > 500
        || delta_ref.chars().any(char::is_whitespace)
    {
        return Err("OutcomeDelta ref must be one bounded outcome-delta:// identity".into());
    }
    Ok(list_outcome_deltas_strict(data_dir)?
        .into_iter()
        .find(|record| record.get("outcome_delta_id").and_then(Value::as_str) == Some(delta_ref)))
}

const REF_MAX: usize = 300;
const LIST_MAX: usize = 64;
const UNCERTAINTY_MAX: usize = 2000;

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}

type VErr = (String, String);
fn verr(code: &str, msg: impl Into<String>) -> VErr {
    (code.into(), msg.into())
}

/// RECURSIVE sensitive-key rejection over every subtree of the body (#71 review finding 1):
/// nothing persisted may carry a key whose normalized form names credential material. Normalized
/// = lowercased with `_`, `-`, spaces, and dots stripped, so `Client-Secret`, `access_token`,
/// `secretAccessKey`, and `private key` all match their fragments.
fn reject_sensitive_keys(v: &Value, path: &str) -> Result<(), VErr> {
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
                    return Err(verr(
                        "work_result_plaintext_secret_rejected",
                        format!("sensitive key `{path}{k}` is never accepted anywhere in the body — results and deltas carry canonical refs; secrets stay in the daemon credential planes"),
                    ));
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

/// Typed, bounded optional-string reader: omitted/null → None; a present non-string refuses
/// typed; oversized refuses typed — never defaulted, never truncated.
fn str_opt_bounded(body: &Value, key: &str, max: usize) -> Result<Option<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) => {
            if raw.chars().count() > max {
                return Err(verr(
                    "work_result_field_too_long",
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
            "work_result_field_type_invalid",
            format!(
                "`{key}` must be a string when present — a non-string value is never defaulted"
            ),
        )),
    }
}

/// Canonical-ref admission for one value: `scheme://tail` with the FIELD's declared schemes; a
/// special non-URI PREFIX form (`scope:`, `harness_profile:`, `agent_harness_adapter:` — tail
/// required); or a special EXACT literal (`encrypted_ref` — the canon's opaque encrypted-payload
/// marker, which matches EXACTLY: `encrypted_ref<anything>` is a raw string, not a ref). A raw
/// string is never a ref.
fn ref_scheme_ok(v: &str, schemes: &[&str], prefixes: &[&str], exacts: &[&str]) -> bool {
    if exacts.contains(&v) {
        return true;
    }
    if prefixes
        .iter()
        .any(|p| v.starts_with(p) && v.len() > p.len())
    {
        return true;
    }
    match v.split_once("://") {
        Some((scheme, tail)) if !tail.is_empty() => schemes.contains(&scheme),
        _ => false,
    }
}

fn scheme_err(key: &str, schemes: &[&str], prefixes: &[&str], exacts: &[&str]) -> VErr {
    let mut allowed: Vec<String> = schemes.iter().map(|s| format!("{s}://")).collect();
    allowed.extend(prefixes.iter().map(|p| format!("{p}*")));
    allowed.extend(exacts.iter().map(|e| format!("{e} (exact)")));
    verr(
        "work_result_ref_scheme_invalid",
        format!(
            "`{key}` must be a canonical ref [{}] — a raw string is never a ref",
            allowed.join("|")
        ),
    )
}

/// Field-specific scalar canonical ref: typed, bounded, scheme-validated.
fn scalar_ref(
    body: &Value,
    key: &str,
    schemes: &[&str],
    prefixes: &[&str],
    exacts: &[&str],
) -> Result<Option<String>, VErr> {
    match str_opt_bounded(body, key, REF_MAX)? {
        None => Ok(None),
        Some(v) if ref_scheme_ok(&v, schemes, prefixes, exacts) => Ok(Some(v)),
        Some(_) => Err(scheme_err(key, schemes, prefixes, exacts)),
    }
}

/// Field-specific ref list: typed, bounded, every member scheme-validated; omitted/null → [].
fn list_ref(
    body: &Value,
    key: &str,
    schemes: &[&str],
    prefixes: &[&str],
    exacts: &[&str],
) -> Result<Vec<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => {
            if items.len() > LIST_MAX {
                return Err(verr(
                    "work_result_field_too_long",
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
                                "work_result_field_too_long",
                                format!(
                                    "a `{key}` member exceeds the bounded length ({REF_MAX} chars)"
                                ),
                            ));
                        }
                        if !ref_scheme_ok(t, schemes, prefixes, exacts) {
                            return Err(scheme_err(key, schemes, prefixes, exacts));
                        }
                        out.push(t.to_string());
                    }
                    _ => {
                        return Err(verr(
                            "work_result_field_type_invalid",
                            format!("`{key}` members must be strings"),
                        ))
                    }
                }
            }
            Ok(out)
        }
        Some(_) => Err(verr(
            "work_result_field_type_invalid",
            format!("`{key}` must be an array of refs when present"),
        )),
    }
}

/// A FUTURE-PLANE field (build steps 2-3): typed/bounded like any field, but any non-empty value
/// refuses with the field's own named unavailable code — assurance and relationship state cannot
/// be caller-authored before the owning plane exists.
fn future_plane_scalar(body: &Value, key: &str, code: &str, why: &str) -> Result<(), VErr> {
    if str_opt_bounded(body, key, REF_MAX)?.is_some() {
        return Err(verr(
            code,
            format!("`{key}` names a plane that is not admitted yet — {why}"),
        ));
    }
    Ok(())
}
fn future_plane_list(body: &Value, key: &str, code: &str, why: &str) -> Result<(), VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Array(items)) => {
            let has_member = items
                .iter()
                .any(|it| !matches!(it, Value::String(s) if s.trim().is_empty()));
            if has_member {
                Err(verr(
                    code,
                    format!("`{key}` names a plane that is not admitted yet — {why}"),
                ))
            } else {
                Ok(())
            }
        }
        Some(_) => Err(verr(
            "work_result_field_type_invalid",
            format!("`{key}` must be an array when present"),
        )),
    }
}

/// A required vocabulary member: present string ∈ vocab, else typed refusal naming the vocabulary.
fn vocab_required(body: &Value, key: &str, vocab: &[&str], code: &str) -> Result<String, VErr> {
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

/// The admission-time output hash: sha256 over the record serialized with serde_json's sorted
/// object keys, EXCLUDING the plane-owned mutable fields listed in the receipt's
/// `hash_scope_excludes` (so a later plane-owned backlink or transition never invalidates the
/// admission receipt). Verifiers recompute this from the persisted record.
fn record_output_hash(record: &Value, excludes: &[&str]) -> String {
    let mut clone = record.clone();
    if let Some(obj) = clone.as_object_mut() {
        for k in excludes {
            obj.remove(*k);
        }
    }
    let bytes = serde_json::to_vec(&clone).unwrap_or_default();
    format!("sha256:{:x}", Sha256::digest(&bytes))
}

const RESULT_HASH_EXCLUDES: &[&str] = &["admission_receipt_ref", "outcome_delta_refs"];
const DELTA_HASH_EXCLUDES: &[&str] = &["admission_receipt_ref", "status"];

/// PURE receipt profile: `WorkResultReceipt` on the canonical ReceiptEnvelope base — binds the
/// generic result profile and outcome class (plus goal identity and status at admission), the
/// admission-time record hash, and the honest assurance posture.
fn build_work_result_receipt(record: &Value, now: &str) -> (String, Value) {
    let id_tail = format!("wrr_{:x}", nanos());
    let receipt_id = format!("receipt://{id_tail}");
    let subject = s(record, "work_result_id", "");
    let rec = json!({
        "schema_version": RESULT_RECEIPT_SCHEMA,
        "receipt_id": receipt_id,
        "receipt_ref": receipt_id,
        "receipt_type": "WorkResultReceipt",
        "receipt_profile_ref": format!("schema://{RESULT_RECEIPT_SCHEMA}"),
        "actor_id": "daemon://hypervisor-runtime",
        "subject_ref": subject,
        "op": "admitted",
        "attested_boundary_fact_refs": [subject, s(record, "work_subject_ref", "")],
        "bound_facts": {
            "work_subject_ref": record["work_subject_ref"],
            "result_profile": record["result_profile"],
            "outcome_class": record["outcome_class"],
            "status_at_admission": record["status"],
        },
        "output_hash": record_output_hash(record, RESULT_HASH_EXCLUDES),
        "hash_scope_excludes": RESULT_HASH_EXCLUDES,
        "assurance_posture": "admitted_not_verified",
        "assurance_note": "admission of a declared result — a receipt is not proof of correctness; verification/acceptance/adjudication/settlement are the ladder rungs above and are NOT implied",
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

/// PURE receipt profile: `OutcomeDeltaAdmissionReceipt` — binds proposer, target, kind,
/// preconditions, expected effect, and verifier/acceptance posture, and states explicitly that
/// the PROPOSAL record was admitted while the declared EFFECT is not (`effect_admitted: false`).
fn build_outcome_delta_receipt(record: &Value, now: &str) -> (String, Value) {
    let id_tail = format!("odr_{:x}", nanos());
    let receipt_id = format!("receipt://{id_tail}");
    let subject = s(record, "outcome_delta_id", "");
    let rec = json!({
        "schema_version": DELTA_RECEIPT_SCHEMA,
        "receipt_id": receipt_id,
        "receipt_ref": receipt_id,
        "receipt_type": "OutcomeDeltaAdmissionReceipt",
        "receipt_profile_ref": format!("schema://{DELTA_RECEIPT_SCHEMA}"),
        "actor_id": "daemon://hypervisor-runtime",
        "subject_ref": subject,
        "op": "proposed",
        "attested_boundary_fact_refs": [subject, s(record, "work_subject_ref", ""), s(record, "proposed_by_ref", ""), s(record, "target_ref", "")],
        "bound_facts": {
            "work_subject_ref": record["work_subject_ref"],
            "proposed_by_ref": record["proposed_by_ref"],
            "target_ref": record["target_ref"],
            "delta_kind": record["delta_kind"],
            "precondition_and_invariant_refs": record["precondition_and_invariant_refs"],
            "expected_effect_ref": record["expected_effect_ref"],
            "verifier_and_acceptance_refs": record["verifier_and_acceptance_refs"],
            "record_status_at_admission": "proposed",
            "effect_admitted": false,
        },
        "effect_admitted": false,
        "output_hash": record_output_hash(record, DELTA_HASH_EXCLUDES),
        "hash_scope_excludes": DELTA_HASH_EXCLUDES,
        "assurance_posture": "proposal_admitted_effect_not_admitted",
        "assurance_note": "the PROPOSAL record was admitted; the declared effect is NOT admitted, evaluated, or applied — evaluation/admission transitions are build-step-2/3 authority",
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

/// ATOMIC FILE REPLACEMENT for the MUTABLE WorkResult record (#71 round 2): a truncating
/// `fs::write` lets a concurrent reader observe an empty/partial file (the review's false
/// `outcome_delta_unbound_result` refusals). Writing to a `.tmp-*` sibling (no `.json`
/// extension — `read_record_dir` only parses `*.json`) and `rename`ing into place is atomic on
/// the same filesystem, so readers always see a complete record. Parity with persist_record
/// (#72 review round 3 finding 4): a promoted family would have exactly one write path (the
/// substrate engine), and a not-yet-promoted family still feeds the opt-in dual-write soak —
/// atomic replacement must not silently drop either cross-cutting hook.
fn persist_result_atomic(data_dir: &str, record_id: &str, record: &Value) -> std::io::Result<()> {
    if super::substrate_store::is_promoted(RESULT_DIR) {
        return super::substrate_store::persist_promoted(data_dir, RESULT_DIR, record_id, record);
    }
    let dir = std::path::Path::new(data_dir).join(RESULT_DIR);
    std::fs::create_dir_all(&dir)?;
    let safe: String = record_id.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    );
    let tmp = dir.join(format!(".{safe}.tmp-{:x}", nanos()));
    // Both failure paths CLEAN UP the temporary sibling (#71 round 3): a leaked .tmp-* is
    // deliberately invisible to read_record_dir, so it would evade every orphan check.
    if let Err(e) = std::fs::write(&tmp, serde_json::to_vec_pretty(record).unwrap_or_default()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, dir.join(format!("{safe}.json"))) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    super::substrate_store::dual_write(data_dir, RESULT_DIR, record_id, record);
    Ok(())
}

/// Atomic-with-rollback finalization for a standalone record + receipt (results).
fn finalize_result_persist(
    data_dir: &str,
    record_id: &str,
    record: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    if let Err(e) = persist_record(data_dir, RESULT_DIR, record_id, record) {
        return Err(verr(
            "work_result_record_persist_failed",
            format!("record persist failed ({e}) — nothing changed"),
        ));
    }
    match persist_record(data_dir, RESULT_RECEIPT_DIR, receipt_id, receipt) {
        Ok(()) => Ok(()),
        Err(e) => {
            if remove_record(data_dir, RESULT_DIR, record_id) {
                Err(verr("work_result_receipt_persist_failed", format!("receipt persist failed ({e}); the created record was rolled back — nothing changed")))
            } else {
                Err(verr("work_result_rollback_failed", format!("receipt persist failed ({e}) AND the created record rollback failed — manual repair required for '{record_id}'")))
            }
        }
    }
}

/// Atomic-with-rollback finalization for a delta + its WorkResult BACKLINK + receipt (#71 review
/// items 8/12; rounds 2-3): delta record FIRST, backlink SECOND (ATOMIC file replacement —
/// readers never observe a torn record), receipt THIRD; every failure lane rolls back all
/// earlier writes with CHECKED operations and distinct typed codes. The receipt-failure rollback
/// restores the EXACT prior record — including every plane-owned backlink, byte for byte — so a
/// "nothing changed" refusal leaves no unreceipted state mutation. That exact restore is safe
/// ONLY because callers hold DELTA_ADMISSION_LOCK across resolution → finalization: `prior` is
/// read inside the lock, so no other admission's success can be captured stale or clobbered.
fn finalize_delta_persist(
    data_dir: &str,
    delta_id: &str,
    delta: &Value,
    result_id: &str,
    prior_result: &Value,
    updated_result: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    if let Err(e) = persist_record(data_dir, DELTA_DIR, delta_id, delta) {
        return Err(verr(
            "outcome_delta_record_persist_failed",
            format!("delta record persist failed ({e}) — nothing changed"),
        ));
    }
    if let Err(e) = persist_result_atomic(data_dir, result_id, updated_result) {
        return if remove_record(data_dir, DELTA_DIR, delta_id) {
            Err(verr("outcome_delta_backlink_persist_failed", format!("work-result backlink persist failed ({e}); the delta record was rolled back — nothing changed")))
        } else {
            Err(verr("outcome_delta_rollback_failed", format!("work-result backlink persist failed ({e}) AND the delta rollback failed — manual repair required for '{delta_id}'")))
        };
    }
    match persist_record(data_dir, DELTA_RECEIPT_DIR, receipt_id, receipt) {
        Ok(()) => Ok(()),
        Err(e) => {
            let restored = persist_result_atomic(data_dir, result_id, prior_result).is_ok();
            let removed = remove_record(data_dir, DELTA_DIR, delta_id);
            if restored && removed {
                Err(verr("outcome_delta_receipt_persist_failed", format!("delta receipt persist failed ({e}); the delta was rolled back and the work-result restored EXACTLY — nothing changed")))
            } else {
                Err(verr("outcome_delta_rollback_failed", format!("delta receipt persist failed ({e}) AND rollback was incomplete (prior restored: {restored}, delta removed: {removed}) — manual repair required for '{delta_id}'")))
            }
        }
    }
}

/// Validate a WorkResult admission body into its durable record (PURE except the supersedes
/// resolver, which returns the resolved result's goal_ref).
fn validate_work_result(
    body: &Value,
    resolve_result: &dyn Fn(&str) -> Option<Value>,
    _resolve_room: &dyn Fn(&str) -> Option<Value>,
) -> Result<Value, VErr> {
    reject_sensitive_keys(body, "")?;
    // goal_ref is a canonical goal:// identity (never a raw string).
    let goal_ref = match str_opt_bounded(body, "goal_ref", REF_MAX)? {
        Some(g) if ref_scheme_ok(&g, &["goal"], &[], &[]) => g,
        Some(_) => {
            return Err(verr(
                "work_result_goal_ref_invalid",
                "`goal_ref` must be a canonical goal:// identity",
            ))
        }
        None => {
            return Err(verr(
                "work_result_goal_ref_required",
                "A WorkResult requires `goal_ref` — every result is goal-shaped work.",
            ))
        }
    };
    if body
        .get("outcome_room_ref")
        .is_some_and(|value| !value.is_null())
        || body
            .get("system_binding")
            .is_some_and(|value| !value.is_null())
    {
        return Err(verr(
            "work_result_system_binding_owner_required",
            "bounded-System scope is admitted only by its application owner; the generic substrate seam never resolves room vocabulary or mints SystemScopedObjectBinding",
        ));
    }
    // FUTURE-PLANE fields (build step 3): non-empty values are per-field named gaps.
    future_plane_scalar(
        body,
        "work_claim_ref",
        "work_result_work_claim_unavailable",
        "WorkClaimLease is build step 3",
    )?;
    future_plane_scalar(
        body,
        "attempt_ref",
        "work_result_attempt_unavailable",
        "the Attempt plane is build step 3",
    )?;
    future_plane_scalar(
        body,
        "acceptance_ref",
        "work_result_acceptance_unavailable",
        "acceptance authority is build step 3; admission never implies acceptance",
    )?;
    future_plane_scalar(body, "superseded_by_ref", "work_result_superseded_by_unavailable", "supersession-by arrives with the later result/delta that supersedes this one — it is never self-declared at admission")?;
    future_plane_list(
        body,
        "finding_refs",
        "work_result_finding_refs_unavailable",
        "the Finding plane is build step 3",
    )?;
    // OutcomeDelta and VerifierChallenge backlinks are plane-owned and land through their owner
    // seams. Even an empty caller-provided list is forbidden: absence, not a caller assertion,
    // selects the canonical empty admission state.
    if body
        .get("outcome_delta_refs")
        .map(|v| !v.is_null())
        .unwrap_or(false)
    {
        return Err(verr("work_result_outcome_delta_refs_plane_owned", "`outcome_delta_refs` is plane-owned — the OutcomeDelta admission registers the backlink atomically; callers never supply it"));
    }
    if body
        .get("review_refs")
        .map(|v| !v.is_null())
        .unwrap_or(false)
    {
        return Err(verr("work_result_review_refs_plane_owned", "`review_refs` is plane-owned — review admission registers the backlink through the WorkResult owner seam; callers never supply it"));
    }
    let result_profile = vocab_required(
        body,
        "result_profile",
        RESULT_PROFILES,
        "work_result_profile_invalid",
    )?;
    let outcome_class = vocab_required(
        body,
        "outcome_class",
        OUTCOME_CLASSES,
        "work_result_outcome_class_invalid",
    )?;
    let status = vocab_required(
        body,
        "status",
        RESULT_STATUSES,
        "work_result_status_invalid",
    )?;
    let next_action = match str_opt_bounded(body, "next_action", 80)? {
        None => "none".to_string(), // canonical default: a result with no follow-up declares none
        Some(v) if NEXT_ACTIONS.contains(&v.as_str()) => v,
        Some(v) => {
            return Err(verr(
                "work_result_next_action_invalid",
                format!(
                    "`next_action` value '{v}' is not a member of [{}]",
                    NEXT_ACTIONS.join("|")
                ),
            ))
        }
    };
    let reproduction_state = match str_opt_bounded(body, "reproduction_state", 80)? {
        None => Value::Null, // canon allows null — an unclaimed reproduction posture stays null
        Some(v) if REPRODUCTION_STATES.contains(&v.as_str()) => Value::String(v),
        Some(v) => {
            return Err(verr(
                "work_result_reproduction_state_invalid",
                format!(
                    "`reproduction_state` value '{v}' is not a member of [{}]",
                    REPRODUCTION_STATES.join("|")
                ),
            ))
        }
    };
    // `uncertainty` is number | string | object | null per canon — bounded by serialized size
    // (its subtree already passed the recursive sensitive-key rejection above).
    let uncertainty = match body.get("uncertainty") {
        None | Some(Value::Null) => Value::Null,
        Some(v @ (Value::Number(_) | Value::String(_) | Value::Object(_))) => {
            if v.to_string().chars().count() > UNCERTAINTY_MAX {
                return Err(verr(
                    "work_result_field_too_long",
                    format!(
                        "`uncertainty` exceeds the bounded serialized length ({UNCERTAINTY_MAX})"
                    ),
                ));
            }
            v.clone()
        }
        Some(_) => {
            return Err(verr(
                "work_result_field_type_invalid",
                "`uncertainty` must be a number, string, or object when present",
            ))
        }
    };
    // supersedes_work_result_ref: only a resolvable SAME-GOAL, SAME-ROOM work-result (#71 item 6;
    // #72 review finding 2 — supersession preserves singular room identity exactly like deltas).
    let supersedes = match scalar_ref(
        body,
        "supersedes_work_result_ref",
        &["work-result"],
        &[],
        &[],
    )? {
        None => Value::Null,
        Some(r) => {
            let tail = r.strip_prefix("work-result://").unwrap_or("");
            match resolve_result(tail) {
                None => return Err(verr("work_result_supersedes_unbound", format!("`supersedes_work_result_ref` does not resolve to an admitted WorkResult ('{r}')"))),
                Some(target) => {
                    let target_goal = s(&target, "work_subject_ref", "");
                    if target_goal != goal_ref {
                        return Err(verr("work_result_supersedes_cross_goal", format!("`supersedes_work_result_ref` resolves under '{target_goal}', not this result's '{goal_ref}' — supersession never crosses goals")));
                    }
                    let target_room = target.get("system_binding").cloned().unwrap_or(Value::Null);
                    if !target_room.is_null() {
                        return Err(verr("work_result_supersedes_cross_system_scope", "a generic WorkResult cannot supersede an application-scoped WorkResult"));
                    }
                    Value::String(r)
                }
            }
        }
    };
    // Field-specific canonical-ref validation (the envelope's declared schemes per field).
    let record = json!({
        "schema_version": RESULT_SCHEMA,
        "work_subject_ref": goal_ref,
        "system_binding": Value::Null,
        "produced_by_ref":"system://ioi/hypervisor/daemon",
        "submitted_by_ref":"system://ioi/hypervisor/daemon",
        "operator_and_affiliation_refs":[],
        "invocation_or_run_ref": scalar_ref(body, "invocation_or_run_ref", &["harness_invocation", "run", "service", "mission"], &[], &[])?,
        "result_profile": result_profile,
        "result_profile_ref": scalar_ref(body, "result_profile_ref", &["schema", "profile"], &[], &[])?,
        "result_payload_ref": scalar_ref(body, "result_payload_ref", &["artifact", "cid"], &[], &["encrypted_ref"])?,
        "producer_component_resolution":{
            "resolved_component_set_snapshot_ref":Value::Null,
            "resolved_component_set_hash":Value::Null,
            "component_resolution_receipt_ref":Value::Null,
            "resolver_kind":"none",
            "resolver_revision_ref":Value::Null,
            "resolver_content_hash":Value::Null,
        },
        "declared_method_and_lineage_refs": list_ref(body, "declared_method_and_lineage_refs", &["method", "attempt", "finding", "work-result", "artifact", "trace"], &[], &[])?,
        "information_flow_label_refs":[],
        "outcome_class": outcome_class,
        "status": status,
        "outcome_delta_refs": [],
        "observation_refs": [],
        "claim_refs": list_ref(body, "claim_refs", &["finding", "ontology-assertion", "evidence"], &[], &[])?,
        "uncertainty": uncertainty,
        "supporting_evidence_refs": list_ref(body, "supporting_evidence_refs", &["artifact", "evidence", "receipt", "ledger"], &[], &[])?,
        "contradicting_evidence_refs": list_ref(body, "contradicting_evidence_refs", &["finding", "ontology-assertion", "evidence", "artifact"], &[], &[])?,
        "artifact_receipt_and_trace_refs": list_ref(body, "artifact_receipt_and_trace_refs", &["artifact", "receipt", "ledger", "trace"], &[], &[])?,
        "resource_and_cost_refs": list_ref(body, "resource_and_cost_refs", &["resource-lease", "cost", "quote", "budget", "ledger", "receipt"], &[], &[])?,
        "authority_and_policy_refs": list_ref(body, "authority_and_policy_refs", &["grant", "policy", "receipt"], &["scope:"], &[])?,
        "blocker_and_decision_request_refs": list_ref(body, "blocker_and_decision_request_refs", &["blocker", "handoff", "proposal"], &[], &[])?,
        "verifier_refs": list_ref(body, "verifier_refs", &["verifier_path", "worker", "gate", "receipt"], &[], &[])?,
        "license_disclosure_retention_and_export_refs": list_ref(body, "license_disclosure_retention_and_export_refs", &["license", "policy", "restricted_view", "receipt"], &[], &[])?,
        "reproduction_state": reproduction_state,
        "reproduction_refs": list_ref(body, "reproduction_refs", &["attempt", "work-result", "evidence", "receipt"], &[], &[])?,
        "acceptance_ref": Value::Null,
        "review_refs": [],
        "supersedes_work_result_ref": supersedes,
        "superseded_by_ref": Value::Null,
        "summary_ref": scalar_ref(body, "summary_ref", &["message", "artifact"], &[], &[])?,
        "next_action": next_action,
    });
    Ok(record)
}

/// Validate an OutcomeDelta admission body. The resolver returns the referenced WorkResult
/// RECORD (not a boolean), so the binding invariants compare goal (and, once rooms exist, room)
/// identity — a cross-goal binding refuses typed with zero mutation.
fn validate_outcome_delta(
    body: &Value,
    resolve_result: &dyn Fn(&str) -> Option<Value>,
    _resolve_room: &dyn Fn(&str) -> Option<Value>,
) -> Result<(Value, Value), VErr> {
    reject_sensitive_keys(body, "")?;
    // Plane-owned fields refuse typed — a caller can never self-admit or self-receipt a delta.
    if body.get("status").map(|v| !v.is_null()).unwrap_or(false) {
        return Err(verr("outcome_delta_status_plane_owned", "`status` is plane-owned: a delta admits as `proposed`; evaluation/admission transitions are a named gap (build steps 2-3 authority)."));
    }
    if body
        .get("admission_receipt_ref")
        .map(|v| !v.is_null())
        .unwrap_or(false)
    {
        return Err(verr("outcome_delta_receipt_plane_owned", "`admission_receipt_ref` is minted by this plane — it is never accepted from the caller."));
    }
    let goal_ref = match str_opt_bounded(body, "goal_ref", REF_MAX)? {
        Some(g) if ref_scheme_ok(&g, &["goal"], &[], &[]) => g,
        Some(_) => {
            return Err(verr(
                "outcome_delta_goal_ref_invalid",
                "`goal_ref` must be a canonical goal:// identity",
            ))
        }
        None => {
            return Err(verr(
                "outcome_delta_goal_ref_required",
                "An OutcomeDelta requires `goal_ref`.",
            ))
        }
    };
    if body
        .get("outcome_room_ref")
        .is_some_and(|value| !value.is_null())
        || body
            .get("system_binding")
            .is_some_and(|value| !value.is_null())
    {
        return Err(verr(
            "outcome_delta_system_binding_owner_required",
            "bounded-System scope is admitted only by its application owner; the generic substrate seam never resolves room vocabulary or mints SystemScopedObjectBinding",
        ));
    }
    let delta_kind = vocab_required(
        body,
        "delta_kind",
        DELTA_KINDS,
        "outcome_delta_kind_invalid",
    )?;
    // THE INVARIANT: the delta binds an EXISTING admitted WorkResult UNDER THE SAME GOAL.
    let proposed_by = match str_opt_bounded(body, "proposed_by_ref", REF_MAX)? {
        Some(p) => p,
        None => return Err(verr("outcome_delta_unbound_result", "`proposed_by_ref` is required: an OutcomeDelta binds an admitted work-result:// at write.")),
    };
    if let Some(scheme) = proposed_by.split("://").next() {
        if UNAVAILABLE_PROPOSER_SCHEMES.contains(&scheme) {
            return Err(verr("outcome_delta_proposer_kind_unavailable", format!("`proposed_by_ref` scheme '{scheme}://' names a plane that is not admitted yet (build step 3) — today a delta binds an admitted work-result://.")));
        }
    }
    let Some(result_id) = proposed_by.strip_prefix("work-result://") else {
        return Err(verr("outcome_delta_unbound_result", "`proposed_by_ref` must be a work-result:// ref — the delta-binds-result invariant is fail-closed."));
    };
    let bound_result = match resolve_result(result_id) {
        Some(r) => r,
        None => return Err(verr("outcome_delta_unbound_result", format!("`proposed_by_ref` does not resolve to an admitted WorkResult ('{result_id}') — nothing was created."))),
    };
    let bound_goal = s(&bound_result, "work_subject_ref", "");
    if bound_goal != goal_ref {
        return Err(verr("outcome_delta_cross_goal", format!("the bound WorkResult belongs to '{bound_goal}', not this delta's '{goal_ref}' — a delta never binds a result from another goal (zero mutation)")));
    }
    let result_room = bound_result
        .get("system_binding")
        .cloned()
        .unwrap_or(Value::Null);
    if !result_room.is_null() {
        return Err(verr(
            "outcome_delta_cross_system_scope",
            "a generic OutcomeDelta cannot bind an application-scoped WorkResult",
        ));
    }
    let target_ref = match str_opt_bounded(body, "target_ref", REF_MAX)? {
        Some(t) => t,
        None => {
            return Err(verr(
                "outcome_delta_target_required",
                format!(
                    "`target_ref` is required and must use a canonical scheme [{}]",
                    DELTA_TARGET_SCHEMES.join("|")
                ),
            ))
        }
    };
    if !ref_scheme_ok(&target_ref, DELTA_TARGET_SCHEMES, &[], &[]) {
        return Err(verr(
            "outcome_delta_target_scheme_invalid",
            format!(
                "`target_ref` scheme must be one of [{}]",
                DELTA_TARGET_SCHEMES.join("|")
            ),
        ));
    }
    let record = json!({
        "schema_version": DELTA_SCHEMA,
        "work_subject_ref": goal_ref,
        "system_binding":Value::Null,
        "proposed_by_ref": proposed_by,
        "target_ref": target_ref,
        "delta_kind": delta_kind,
        "payload_ref": scalar_ref(body, "payload_ref", &["artifact", "patch", "mapping", "state-delta"], &[], &[])?,
        "precondition_and_invariant_refs": list_ref(body, "precondition_and_invariant_refs", &["policy", "gate", "state"], &[], &[])?,
        "expected_effect_ref": scalar_ref(body, "expected_effect_ref", &["effect"], &[], &[])?,
        "verifier_and_acceptance_refs": list_ref(body, "verifier_and_acceptance_refs", &["verifier_path", "rubric", "gate"], &[], &[])?,
        "information_flow_label_refs":bound_result.get("information_flow_label_refs").cloned().unwrap_or_else(|| json!([])),
        "status": "proposed",
    });
    Ok((record, bound_result))
}

fn sorted_newest(mut items: Vec<Value>) -> Vec<Value> {
    items.sort_by(|a, b| s(b, "created_at", "").cmp(&s(a, "created_at", "")));
    items
}

fn record_schema_counts(records: &[Value], accepted: &[&str]) -> Value {
    let mut counts = serde_json::Map::new();
    for schema in accepted {
        counts.insert(
            (*schema).to_string(),
            json!(records
                .iter()
                .filter(
                    |record| record.get("schema_version").and_then(Value::as_str) == Some(*schema)
                )
                .count()),
        );
    }
    Value::Object(counts)
}

fn work_result_collection_projection(results: Vec<Value>) -> Value {
    json!({
        "schema_version": RESULT_REGISTRY_PROJECTION_SCHEMA,
        "accepted_record_schema_versions": RESULT_RECORD_SCHEMAS,
        "record_schema_counts": record_schema_counts(&results, RESULT_RECORD_SCHEMAS),
        "work_results": results,
        "runtimeTruthSource": "daemon-runtime"
    })
}

fn outcome_delta_collection_projection(deltas: Vec<Value>) -> Value {
    json!({
        "schema_version": DELTA_REGISTRY_PROJECTION_SCHEMA,
        "accepted_record_schema_versions": DELTA_RECORD_SCHEMAS,
        "record_schema_counts": record_schema_counts(&deltas, DELTA_RECORD_SCHEMAS),
        "outcome_deltas": deltas,
        "runtimeTruthSource": "daemon-runtime"
    })
}

fn registry_refusal(kind: &str, error: String) -> (StatusCode, Json<Value>) {
    eprintln!("{kind} registry refusal: {error}");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": {
                "code": format!("{kind}_registry_unreadable"),
                "message": format!("The complete versioned {kind} registry cannot be resolved; partial or false-empty truth is refused.")
            }
        })),
    )
}

/// This plane's own reader. It DELEGATES to `work_truth_visibility_reader` rather than repeating
/// the computation, so the answer a neighbouring resolver gets is the same answer these handlers
/// act on — by construction, not by two copies agreeing today.
fn global_truth_reader(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Result<Option<String>, (StatusCode, Json<Value>)> {
    work_truth_visibility_reader(&st.data_dir, headers)
}

fn fence_pending_room_projection(data_dir: &str) -> Result<(), (StatusCode, Json<Value>)> {
    super::outcome_room_system_routes::refuse_while_any_intent_pending(data_dir).map_err(
        |(code, message)| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": { "code": code, "message": message } })),
            )
        },
    )
}

fn authorize_goal_mutation(
    data_dir: &str,
    reader: Option<&str>,
    goal_ref: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    let Some(owner_ref) = reader else {
        return Ok(());
    };
    let goal = super::goalrun_routes::load_goal_run_strict(data_dir, goal_ref)
        .map_err(|_message| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":{"code":"work_truth_goal_owner_unresolved","message":"GoalRun ownership truth cannot be resolved; the mutation is refused."}})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::FORBIDDEN,
                Json(
                    json!({"error":{"code":"work_truth_goal_owner_mismatch","message":"The authenticated principal does not own this GoalRun and cannot mutate its work truth."}}),
                ),
            )
        })?;
    if goal.get("owner_ref").and_then(Value::as_str) != Some(owner_ref) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                json!({"error":{"code":"work_truth_goal_owner_mismatch","message":"The authenticated principal does not own this GoalRun and cannot mutate its work truth."}}),
            ),
        ));
    }
    Ok(())
}

/// The generic v1 routes remain available for non-GoalRun goals and the broader M3 result seam,
/// but they may not manufacture result truth for an explicitly resultless zero-execution GoalRun.
/// Resolve this independently of deployment auth mode: local `reader=None` is not permission to
/// bypass the GoalRun owner's retained execution ceiling.
fn fence_zero_execution_goal_result_lane(
    data_dir: &str,
    goal_ref: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    if !goal_ref
        .strip_prefix("goal://")
        .is_some_and(|tail| !tail.is_empty() && tail.len() <= 160 && !tail.contains(".."))
    {
        // The closed body validator owns the existing typed syntax refusal.
        return Ok(());
    }
    let goal_run = super::goalrun_routes::load_goal_run_strict(data_dir, goal_ref).map_err(
        |_message| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": {
                        "code":"work_truth_goal_owner_unresolved",
                        "message":"GoalRun truth cannot be resolved before generic result admission."
                    }
                })),
            )
        },
    )?;
    if let Some(goal_run) = goal_run {
        if let Some(response) =
            super::goalrun_routes::refuse_result_write_for_zero_execution_goal(&goal_run)
        {
            return Err(response);
        }
    }
    Ok(())
}

/// Once a GoalRun is reciprocally attached to an OutcomeRoom, all result truth for that run must
/// cross the private v3 room-owner Agentgres admission seam. Omitting caller-supplied room fields is not
/// permission to manufacture a parallel roomless v1 result/delta path.
fn fence_room_member_goal_result_lane(
    data_dir: &str,
    goal_ref: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    if !goal_ref
        .strip_prefix("goal://")
        .is_some_and(|tail| !tail.is_empty() && tail.len() <= 160 && !tail.contains(".."))
    {
        return Ok(());
    }
    let goal_run = super::goalrun_routes::load_goal_run_strict(data_dir, goal_ref).map_err(
        |_message| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": {
                        "code":"work_truth_goal_owner_unresolved",
                        "message":"GoalRun truth cannot be resolved before generic result admission."
                    }
                })),
            )
        },
    )?;
    if goal_run.is_some_and(|goal_run| {
        goal_run
            .get("outcome_room_ref")
            .is_some_and(|value| !value.is_null())
    }) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": {
                    "code":"generic_work_truth_room_member_goal_refused",
                    "message":"A room-member GoalRun may publish WorkResult and OutcomeDelta truth only through the private v3 OutcomeRoom Agentgres admission seam."
                }
            })),
        ));
    }
    Ok(())
}

fn refuse_generic_system_binding(
    body: &Value,
    object_kind: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    for field in [
        "outcome_room_ref",
        "room_admission",
        "room_binding",
        "system_binding",
    ] {
        if body.get(field).is_some_and(|value| !value.is_null()) {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": {
                        "code": format!("generic_{object_kind}_room_binding_refused"),
                        "message": format!("`{field}` is owned by the private v3 OutcomeRoom Agentgres admission seam; the generic mutation route cannot create room-associated truth.")
                    }
                })),
            ));
        }
    }
    Ok(())
}

fn result_owner_matches(data_dir: &str, result: &Value, owner_ref: &str) -> Result<bool, String> {
    let goal_ref = result
        .get("work_subject_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some(goal) = super::goalrun_routes::load_goal_run_strict(data_dir, goal_ref)? else {
        // WorkResult is a substrate-generic seam: its work subject need not be a GoalRun that
        // this application can resolve. A managed principal-scoped collection omits such a
        // record rather than turning an unowned generic subject into a registry-wide 503 oracle.
        return Ok(false);
    };
    let Some(resolved_owner) = goal.get("owner_ref").and_then(Value::as_str) else {
        return Ok(false);
    };
    Ok(resolved_owner == owner_ref)
}

fn delta_owner_matches(data_dir: &str, delta: &Value, owner_ref: &str) -> Result<bool, String> {
    let proposer = delta
        .get("proposed_by_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    let result = load_work_result_strict(data_dir, proposer)?
        .ok_or_else(|| format!("OutcomeDelta proposer '{proposer}' does not resolve"))?;
    result_owner_matches(data_dir, &result, owner_ref)
}

fn owner_filtered_results(data_dir: &str, owner_ref: Option<&str>) -> Result<Vec<Value>, String> {
    let mut filtered = Vec::new();
    for result in list_work_results_strict(data_dir)? {
        match owner_ref {
            None => filtered.push(result),
            Some(owner) if result_owner_matches(data_dir, &result, owner)? => filtered.push(result),
            Some(_) => {}
        }
    }
    Ok(sorted_newest(filtered))
}

fn owner_filtered_deltas(data_dir: &str, owner_ref: Option<&str>) -> Result<Vec<Value>, String> {
    let mut filtered = Vec::new();
    for delta in list_outcome_deltas_strict(data_dir)? {
        match owner_ref {
            None => filtered.push(delta),
            Some(owner) if delta_owner_matches(data_dir, &delta, owner)? => filtered.push(delta),
            Some(_) => {}
        }
    }
    Ok(sorted_newest(filtered))
}

// ================================ HANDLERS =======================================================

pub(crate) async fn handle_work_results_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let reader = match global_truth_reader(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let _room_scope = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    let results = match owner_filtered_results(&st.data_dir, reader.as_deref()) {
        Ok(results) => results,
        Err(error) => return registry_refusal("work_result", error),
    };
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    (
        StatusCode::OK,
        Json(work_result_collection_projection(results)),
    )
}

pub(crate) async fn handle_work_result_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let reader = match global_truth_reader(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let _room_scope = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    let result_ref = format!("work-result://{}", id.trim_start_matches('/'));
    let resolved = match load_work_result_strict(&st.data_dir, &result_ref) {
        Ok(value) => value,
        Err(error) => return registry_refusal("work_result", error),
    };
    let response = match resolved {
        Some(result) => match reader.as_deref() {
            Some(owner) => match result_owner_matches(&st.data_dir, &result, owner) {
                Ok(true) => (
                    StatusCode::OK,
                    Json(json!({
                        "schema_version": RESULT_REGISTRY_PROJECTION_SCHEMA,
                        "record_schema_version": result.get("schema_version"),
                        "work_result": result
                    })),
                ),
                Ok(false) => (
                    StatusCode::FORBIDDEN,
                    Json(
                        json!({"error":{"code":"work_result_owner_mismatch","message":"The authenticated principal does not own this WorkResult."}}),
                    ),
                ),
                Err(_) => (
                    StatusCode::FORBIDDEN,
                    Json(
                        json!({"error":{"code":"work_result_owner_mismatch","message":"The authenticated principal does not own this WorkResult."}}),
                    ),
                ),
            },
            None => (
                StatusCode::OK,
                Json(json!({
                    "schema_version": RESULT_REGISTRY_PROJECTION_SCHEMA,
                    "record_schema_version": result.get("schema_version"),
                    "work_result": result
                })),
            ),
        },
        None if reader.is_some() => (
            StatusCode::FORBIDDEN,
            Json(
                json!({"error":{"code":"work_result_owner_mismatch","message":"The authenticated principal does not own this WorkResult."}}),
            ),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "work_result": id } })),
        ),
    };
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    response
}

/// GET /v1/hypervisor/work-results/overview — the DECLARATION VOCABULARY projection (a consuming
/// surface derives its pickers from THIS, never a hardcoded copy) + honest governance gaps.
pub(crate) async fn handle_work_results_overview(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let reader = match global_truth_reader(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let _room_scope = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    let results = match owner_filtered_results(&st.data_dir, reader.as_deref()) {
        Ok(results) => results,
        Err(error) => return registry_refusal("work_result", error),
    };
    let deltas = match owner_filtered_deltas(&st.data_dir, reader.as_deref()) {
        Ok(deltas) => deltas,
        Err(error) => return registry_refusal("outcome_delta", error),
    };
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": OVERVIEW_SCHEMA,
            "work_results": results.len(),
            "outcome_deltas": deltas.len(),
            "work_result_record_schema_counts": record_schema_counts(&results, RESULT_RECORD_SCHEMAS),
            "outcome_delta_record_schema_counts": record_schema_counts(&deltas, DELTA_RECORD_SCHEMAS),
            "result_profiles": RESULT_PROFILES,
            "outcome_classes": OUTCOME_CLASSES,
            "statuses": RESULT_STATUSES,
            "next_actions": NEXT_ACTIONS,
            "reproduction_states": REPRODUCTION_STATES,
            "delta_kinds": DELTA_KINDS,
            "delta_target_schemes": DELTA_TARGET_SCHEMES,
            "governance_gaps": [
                "results and deltas are ADMITTED DECLARATIONS with durable receipts — acceptance, verification, adjudication, and settlement are the assurance-ladder rungs above admission and are NOT implied (a receipt is not proof of correctness)",
                "outcome-delta evaluation/admission/rollback TRANSITIONS are not wired: status is plane-owned at `proposed` until the room/acceptance authority of build steps 2-3 exists",
                "attempt://, finding://, and participant-lease:// proposers are named gaps (build step 3) — today a delta binds an admitted, SAME-GOAL work-result://",
                "generic POST /work-results and /outcome-deltas refuse outcome_room_ref, retired room_admission/room_binding, and system_binding: only the GoalRun-owner/private v3 OutcomeRoom Agentgres seam may create room-associated truth; work_claim_ref, attempt_ref, finding_refs, acceptance_ref, and superseded_by_ref remain unavailable here; outcome_delta_refs and challenge_refs are plane-owned and registered atomically by their owner seams"
            ],
            "runtimeTruthSource": "daemon-runtime"
        })),
    )
}

/// POST /v1/hypervisor/work-results — admit a generic WorkResult (fail-closed, atomic, receipted).
pub(crate) async fn handle_work_result_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let err400 = |(code, msg): VErr| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": code, "message": msg } })),
        )
    };
    let reader = match global_truth_reader(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Err(response) = refuse_generic_system_binding(&body, "work_result") {
        return response;
    }
    if let Err(response) = authorize_goal_mutation(
        &st.data_dir,
        reader.as_deref(),
        body.get("goal_ref").and_then(Value::as_str).unwrap_or(""),
    ) {
        return response;
    }
    if let Err(response) = fence_zero_execution_goal_result_lane(
        &st.data_dir,
        body.get("goal_ref").and_then(Value::as_str).unwrap_or(""),
    ) {
        return response;
    }
    if let Err(response) = fence_room_member_goal_result_lane(
        &st.data_dir,
        body.get("goal_ref").and_then(Value::as_str).unwrap_or(""),
    ) {
        return response;
    }
    let data_dir = st.data_dir.clone();
    // ROOM-SCOPE critical section (#72 review finding 3): room resolution through finalization
    // holds ROOM_MUTATION_LOCK, so a room cannot close between the check and the persist.
    // Lock ordering: ROOM_MUTATION_LOCK before DELTA_ADMISSION_LOCK, always.
    let _room_scope = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Err(response) = fence_room_member_goal_result_lane(
        &st.data_dir,
        body.get("goal_ref").and_then(Value::as_str).unwrap_or(""),
    ) {
        return response;
    }
    let strict_results = match list_work_results_strict(&data_dir) {
        Ok(results) => results,
        Err(error) => return registry_refusal("work_result", error),
    };
    let resolve_result = |tail: &str| {
        let identity = format!("work-result://{tail}");
        strict_results
            .iter()
            .find(|record| {
                record.get("schema_version").and_then(Value::as_str) == Some(RESULT_SCHEMA)
                    && record.get("work_result_id").and_then(Value::as_str)
                        == Some(identity.as_str())
            })
            .cloned()
    };
    // Defense in depth: the generic route already issued the exact typed room-binding refusal;
    // its validator receives no room resolver, so later refactors cannot silently mint an
    // application-owned scope binding.
    let resolve_room = |_room_ref: &str| None;
    let mut record = match validate_work_result(&body, &resolve_result, &resolve_room) {
        Ok(r) => r,
        Err(e) => return err400(e),
    };
    let id_tail = format!("wr_{:x}", nanos());
    let work_result_id = format!("work-result://{id_tail}");
    let now = iso_now();
    {
        let obj = record.as_object_mut().expect("record is an object");
        obj.insert("work_result_id".into(), json!(work_result_id));
    }
    if let Err(error) =
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            RESULT_CONTRACT,
            &record,
        )
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({"error":{"code":"work_result_contract_projection_invalid","message":format!("The daemon-derived WorkResult does not satisfy the current contract ({error}).")}}),
            ),
        );
    }
    // Receipt binds the admission-time record (hash computed BEFORE the receipt ref lands on it).
    let (receipt_id, receipt) = build_work_result_receipt(&record, &now);
    if let Err((code, msg)) =
        finalize_result_persist(&st.data_dir, &id_tail, &record, &receipt_id, &receipt)
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": code, "message": msg } })),
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({ "work_result": record, "work_result_receipt": receipt })),
    )
}

pub(crate) async fn handle_outcome_deltas_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let reader = match global_truth_reader(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let _room_scope = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    let deltas = match owner_filtered_deltas(&st.data_dir, reader.as_deref()) {
        Ok(deltas) => deltas,
        Err(error) => return registry_refusal("outcome_delta", error),
    };
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    (
        StatusCode::OK,
        Json(outcome_delta_collection_projection(deltas)),
    )
}

pub(crate) async fn handle_outcome_delta_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let reader = match global_truth_reader(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let _room_scope = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    let delta_ref = format!("outcome-delta://{}", id.trim_start_matches('/'));
    let resolved = match load_outcome_delta_strict(&st.data_dir, &delta_ref) {
        Ok(value) => value,
        Err(error) => return registry_refusal("outcome_delta", error),
    };
    let response = match resolved {
        Some(delta) => match reader.as_deref() {
            Some(owner) => match delta_owner_matches(&st.data_dir, &delta, owner) {
                Ok(true) => (
                    StatusCode::OK,
                    Json(json!({
                        "schema_version": DELTA_REGISTRY_PROJECTION_SCHEMA,
                        "record_schema_version": delta.get("schema_version"),
                        "outcome_delta": delta
                    })),
                ),
                Ok(false) => (
                    StatusCode::FORBIDDEN,
                    Json(
                        json!({"error":{"code":"outcome_delta_owner_mismatch","message":"The authenticated principal does not own this OutcomeDelta."}}),
                    ),
                ),
                Err(_) => (
                    StatusCode::FORBIDDEN,
                    Json(
                        json!({"error":{"code":"outcome_delta_owner_mismatch","message":"The authenticated principal does not own this OutcomeDelta."}}),
                    ),
                ),
            },
            None => (
                StatusCode::OK,
                Json(json!({
                    "schema_version": DELTA_REGISTRY_PROJECTION_SCHEMA,
                    "record_schema_version": delta.get("schema_version"),
                    "outcome_delta": delta
                })),
            ),
        },
        None if reader.is_some() => (
            StatusCode::FORBIDDEN,
            Json(
                json!({"error":{"code":"outcome_delta_owner_mismatch","message":"The authenticated principal does not own this OutcomeDelta."}}),
            ),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "outcome_delta": id } })),
        ),
    };
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    response
}

/// POST /v1/hypervisor/outcome-deltas — admit a delta bound to an EXISTING SAME-GOAL WorkResult;
/// the result's `outcome_delta_refs` backlink registers in the SAME atomic finalization.
pub(crate) async fn handle_outcome_delta_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let err400 = |(code, msg): VErr| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": code, "message": msg } })),
        )
    };
    let reader = match global_truth_reader(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Err(response) = refuse_generic_system_binding(&body, "outcome_delta") {
        return response;
    }
    if let Err(response) = authorize_goal_mutation(
        &st.data_dir,
        reader.as_deref(),
        body.get("goal_ref").and_then(Value::as_str).unwrap_or(""),
    ) {
        return response;
    }
    if let Err(response) = fence_zero_execution_goal_result_lane(
        &st.data_dir,
        body.get("goal_ref").and_then(Value::as_str).unwrap_or(""),
    ) {
        return response;
    }
    if let Err(response) = fence_room_member_goal_result_lane(
        &st.data_dir,
        body.get("goal_ref").and_then(Value::as_str).unwrap_or(""),
    ) {
        return response;
    }
    let data_dir = st.data_dir.clone();
    // ROOM-SCOPE + ADMISSION critical section (#71 round 2; #72 finding 3): the documented lock
    // ordering is ROOM_MUTATION_LOCK first, DELTA_ADMISSION_LOCK second — room resolution through
    // finalization is serialized against room transitions, and concurrent delta admissions
    // against one WorkResult each see the previous backlink state. No .await under either lock.
    let _room_scope = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _admission = DELTA_ADMISSION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let strict_results = match list_work_results_strict(&data_dir) {
        Ok(results) => results,
        Err(error) => return registry_refusal("work_result", error),
    };
    let resolve = |rid: &str| {
        let identity = format!("work-result://{rid}");
        strict_results
            .iter()
            .find(|record| {
                record.get("schema_version").and_then(Value::as_str) == Some(RESULT_SCHEMA)
                    && record.get("work_result_id").and_then(Value::as_str)
                        == Some(identity.as_str())
            })
            .cloned()
    };
    // Defense in depth: only the application owner seam resolves bounded-System scope.
    let resolve_room = |_room_ref: &str| None;
    let (mut record, prior_result) = match validate_outcome_delta(&body, &resolve, &resolve_room) {
        Ok(r) => r,
        Err(e) => return err400(e),
    };
    if prior_result
        .get("system_binding")
        .is_some_and(|value| !value.is_null())
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                json!({"error":{"code":"generic_outcome_delta_room_binding_refused","message":"A generic OutcomeDelta cannot mutate a room-associated WorkResult; only the private v3 OutcomeRoom Agentgres admission seam owns that truth."}}),
            ),
        );
    }
    if let Err(response) = authorize_goal_mutation(
        &st.data_dir,
        reader.as_deref(),
        prior_result
            .get("work_subject_ref")
            .and_then(Value::as_str)
            .unwrap_or(""),
    ) {
        return response;
    }
    if let Err(response) = fence_zero_execution_goal_result_lane(
        &st.data_dir,
        prior_result
            .get("work_subject_ref")
            .and_then(Value::as_str)
            .unwrap_or(""),
    ) {
        return response;
    }
    if let Err(response) = fence_room_member_goal_result_lane(
        &st.data_dir,
        prior_result
            .get("work_subject_ref")
            .and_then(Value::as_str)
            .unwrap_or(""),
    ) {
        return response;
    }
    let bound_result_ref = s(&prior_result, "work_result_id", "");
    if let Err((code, message)) =
        super::attempt_finding_routes::refuse_external_mutation_if_reserved(
            &st.data_dir,
            &bound_result_ref,
            "work_result_mutation_in_flight",
        )
    {
        let status = if code.contains("unreadable") {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::CONFLICT
        };
        return (
            status,
            Json(json!({"error":{"code":code,"message":message}})),
        );
    }
    if let Err((code, message)) =
        super::verifier_challenge_routes::refuse_external_mutation_if_reserved(
            &st.data_dir,
            &bound_result_ref,
            "work_result_mutation_in_flight",
        )
    {
        let status = if code.contains("unreadable") {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::CONFLICT
        };
        return (
            status,
            Json(json!({"error":{"code":code,"message":message}})),
        );
    }
    let id_tail = format!("od_{:x}", nanos());
    let outcome_delta_id = format!("outcome-delta://{id_tail}");
    let now = iso_now();
    {
        let obj = record.as_object_mut().expect("record is an object");
        obj.insert("outcome_delta_id".into(), json!(outcome_delta_id));
    }
    if let Err(error) =
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            DELTA_CONTRACT,
            &record,
        )
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({"error":{"code":"outcome_delta_contract_projection_invalid","message":format!("The daemon-derived OutcomeDelta does not satisfy the current contract ({error}).")}}),
            ),
        );
    }
    let (receipt_id, receipt) = build_outcome_delta_receipt(&record, &now);
    // The plane-owned backlink: prior result + the new delta id, updated in the same atomic seam.
    let bound_result_ref = s(&prior_result, "work_result_id", "");
    let result_storage_key =
        match resolve_work_result_storage_key_strict(&st.data_dir, &bound_result_ref) {
            Ok(Some(key)) => key,
            Ok(None) => {
                return registry_refusal(
                    "work_result",
                    format!("WorkResult '{bound_result_ref}' has no admitted storage slot"),
                )
            }
            Err(error) => return registry_refusal("work_result", error),
        };
    let mut updated_result = prior_result.clone();
    {
        let obj = updated_result.as_object_mut().expect("result is an object");
        let mut refs: Vec<Value> = obj
            .get("outcome_delta_refs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        refs.push(json!(outcome_delta_id));
        obj.insert("outcome_delta_refs".into(), Value::Array(refs));
    }
    if let Err((code, msg)) = finalize_delta_persist(
        &st.data_dir,
        &id_tail,
        &record,
        &result_storage_key,
        &prior_result,
        &updated_result,
        &receipt_id,
        &receipt,
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": { "code": code, "message": msg } })),
        );
    }
    (
        StatusCode::CREATED,
        Json(
            json!({ "outcome_delta": record, "outcome_delta_receipt": receipt, "work_result_backlink": { "work_result_id": s(&prior_result, "work_result_id", ""), "outcome_delta_refs_appended": outcome_delta_id } }),
        ),
    )
}

#[cfg(test)]
mod work_result_tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ioi-wr-{tag}-{:x}", nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn no_resolve(_: &str) -> Option<Value> {
        None
    }
    fn no_room(_: &str) -> Option<Value> {
        None
    }
    fn open_room(r: &str) -> Option<Value> {
        (r == "outcome-room://or_open")
            .then(|| json!({ "outcome_room_id": r, "status": "open" }))
            .or_else(|| {
                (r == "outcome-room://or_closed")
                    .then(|| json!({ "outcome_room_id": r, "status": "closed" }))
            })
    }
    fn valid_result_body() -> Value {
        json!({
            "goal_ref": "goal://g-research-1",
            "result_profile": "research",
            "outcome_class": "positive",
            "status": "completed",
            "claim_refs": ["evidence://lab-observation-1"],
            "supporting_evidence_refs": ["artifact://a1", "receipt://r1"]
        })
    }

    fn exact_family_bytes(data_dir: &str, family: &str) -> BTreeMap<String, Vec<u8>> {
        let path = std::path::Path::new(data_dir).join(family);
        let mut bytes = BTreeMap::new();
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
                    bytes.insert(
                        entry.file_name().to_string_lossy().into_owned(),
                        std::fs::read(entry.path()).unwrap(),
                    );
                }
            }
        }
        bytes
    }

    #[test]
    fn generic_profiles_admit_beyond_software() {
        for p in RESULT_PROFILES {
            let mut b = valid_result_body();
            b["result_profile"] = json!(p);
            let rec = validate_work_result(&b, &no_resolve, &no_room).unwrap();
            assert_eq!(rec["result_profile"], json!(*p));
            assert_eq!(rec["next_action"], json!("none"));
            assert_eq!(rec["reproduction_state"], Value::Null);
            // Future-plane + plane-owned fields persist as consistent empties, never caller values.
            assert_eq!(rec["outcome_delta_refs"], json!([]));
            assert_eq!(rec["acceptance_ref"], Value::Null);
        }
    }

    #[test]
    fn research_result_and_mapping_delta_prove_the_non_software_seam() {
        let mut body = valid_result_body();
        body["result_payload_ref"] = json!("artifact://research/observation-set/1");
        let mut result = validate_work_result(&body, &no_resolve, &no_room)
            .expect("compile a non-software result");
        result["work_result_id"] = json!("work-result://research/observation-set/1");
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            RESULT_CONTRACT,
            &result,
        )
        .expect("non-software result satisfies the universal contract");
        assert_eq!(result["result_profile"], "research");
        assert!(result.get("changed_files").is_none());
        assert!(result.get("patches").is_none());
        assert!(result.get("tests").is_none());

        let resolver = |tail: &str| (tail == "research/observation-set/1").then(|| result.clone());
        let delta_body = json!({
            "goal_ref":"goal://g-research-1",
            "delta_kind":"update",
            "target_ref":"ontology://research/corpus/1",
            "proposed_by_ref":"work-result://research/observation-set/1",
            "payload_ref":"mapping://research/corpus/observation-set/1"
        });
        let (mut delta, bound_result) = validate_outcome_delta(&delta_body, &resolver, &no_room)
            .expect("compile a non-patch outcome delta");
        delta["outcome_delta_id"] = json!("outcome-delta://research/corpus/revision/1");
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            DELTA_CONTRACT,
            &delta,
        )
        .expect("non-patch delta satisfies the universal contract");
        assert_eq!(bound_result["result_profile"], "research");
        assert_eq!(
            delta["payload_ref"],
            "mapping://research/corpus/observation-set/1"
        );
        assert_eq!(delta["status"], "proposed");
    }

    #[test]
    fn sensitive_keys_are_rejected_recursively() {
        // Top level, nested object, nested-in-array, and normalized-variant keys all refuse.
        let cases = vec![
            json!({ "password": "hunter2" }),
            json!({ "uncertainty": { "password": "SENTINEL_NESTED_SECRET" } }),
            json!({ "uncertainty": { "detail": { "Client-Secret": "x" } } }),
            json!({ "uncertainty": { "list": [{ "access_token": "x" }] } }),
            json!({ "uncertainty": { "secretAccessKey": "x" } }),
            json!({ "uncertainty": { "private key": "x" } }),
            json!({ "uncertainty": { "AUTHORIZATION": "Bearer x" } }),
        ];
        for extra in cases {
            let mut b = valid_result_body();
            for (k, v) in extra.as_object().unwrap() {
                b[k] = v.clone();
            }
            assert_eq!(
                validate_work_result(&b, &no_resolve, &no_room)
                    .unwrap_err()
                    .0,
                "work_result_plaintext_secret_rejected",
                "case: {extra}"
            );
        }
    }

    #[test]
    fn refs_are_canonical_per_field_and_raw_strings_never_pass() {
        // goal_ref must be a goal:// identity.
        let mut b = valid_result_body();
        b["goal_ref"] = json!("not-a-ref");
        assert_eq!(
            validate_work_result(&b, &no_resolve, &no_room)
                .unwrap_err()
                .0,
            "work_result_goal_ref_invalid"
        );
        // Scalar refs: raw strings and wrong schemes refuse per field.
        let mut b = valid_result_body();
        b["result_payload_ref"] = json!("fixture-secret-raw-value");
        assert_eq!(
            validate_work_result(&b, &no_resolve, &no_room)
                .unwrap_err()
                .0,
            "work_result_ref_scheme_invalid"
        );
        let mut b = valid_result_body();
        b["summary_ref"] = json!("goal://not-a-summary-scheme");
        assert_eq!(
            validate_work_result(&b, &no_resolve, &no_room)
                .unwrap_err()
                .0,
            "work_result_ref_scheme_invalid"
        );
        // List refs: every member scheme-checked.
        let mut b = valid_result_body();
        b["supporting_evidence_refs"] = json!(["artifact://ok", "raw-string"]);
        assert_eq!(
            validate_work_result(&b, &no_resolve, &no_room)
                .unwrap_err()
                .0,
            "work_result_ref_scheme_invalid"
        );
        // Special non-URI forms admit where the envelope declares them.
        let mut b = valid_result_body();
        b["authority_and_policy_refs"] = json!(["scope:gmail.send", "grant://g1"]);
        b["worker_harness_model_runtime_version_refs"] = json!([
            "harness_profile:codex-local",
            "agent_harness_adapter:claude-code",
            "model://m1"
        ]);
        b["result_payload_ref"] = json!("encrypted_ref");
        let rec = validate_work_result(&b, &no_resolve, &no_room).unwrap();
        assert_eq!(
            rec["authority_and_policy_refs"][0],
            json!("scope:gmail.send")
        );
        assert_eq!(rec["result_payload_ref"], json!("encrypted_ref"));
        // encrypted_ref matches EXACTLY — any suffix is a raw-value smuggling form (#71 round 2).
        for smuggle in [
            "encrypted_refSENTINEL_RAW_MATERIAL",
            "encrypted_ref:vault-42",
            "encrypted_ref-x",
            "xencrypted_ref",
        ] {
            let mut b = valid_result_body();
            b["result_payload_ref"] = json!(smuggle);
            assert_eq!(
                validate_work_result(&b, &no_resolve, &no_room)
                    .unwrap_err()
                    .0,
                "work_result_ref_scheme_invalid",
                "smuggle form: {smuggle:?}"
            );
        }
        // Whitespace-padded input TRIMS to the exact literal (normalization, not smuggling).
        let mut b = valid_result_body();
        b["result_payload_ref"] = json!("encrypted_ref ");
        assert_eq!(
            validate_work_result(&b, &no_resolve, &no_room).unwrap()["result_payload_ref"],
            json!("encrypted_ref")
        );
        // But a bare special prefix with no tail refuses.
        let mut b = valid_result_body();
        b["authority_and_policy_refs"] = json!(["scope:"]);
        assert_eq!(
            validate_work_result(&b, &no_resolve, &no_room)
                .unwrap_err()
                .0,
            "work_result_ref_scheme_invalid"
        );
    }

    #[test]
    fn future_plane_fields_refuse_with_named_codes() {
        let cases = vec![
            (
                "work_claim_ref",
                json!("work-claim://c1"),
                "work_result_work_claim_unavailable",
            ),
            (
                "attempt_ref",
                json!("attempt://a1"),
                "work_result_attempt_unavailable",
            ),
            (
                "acceptance_ref",
                json!("acceptance://ghost"),
                "work_result_acceptance_unavailable",
            ),
            (
                "superseded_by_ref",
                json!("work-result://future"),
                "work_result_superseded_by_unavailable",
            ),
            (
                "finding_refs",
                json!(["finding://ghost"]),
                "work_result_finding_refs_unavailable",
            ),
            (
                "review_refs",
                json!(["verifier-challenge://ghost"]),
                "work_result_review_refs_plane_owned",
            ),
            (
                "outcome_delta_refs",
                json!(["outcome-delta://ghost"]),
                "work_result_outcome_delta_refs_plane_owned",
            ),
        ];
        for (key, val, code) in cases {
            let mut b = valid_result_body();
            b[key] = val;
            assert_eq!(
                validate_work_result(&b, &no_resolve, &no_room)
                    .unwrap_err()
                    .0,
                code,
                "field: {key}"
            );
        }
    }

    #[test]
    fn verifier_challenge_backlink_is_plane_owned_and_exact() {
        let mut caller = valid_result_body();
        caller["review_refs"] = json!([]);
        assert_eq!(
            validate_work_result(&caller, &no_resolve, &no_room)
                .unwrap_err()
                .0,
            "work_result_review_refs_plane_owned"
        );

        let dir = temp_dir("challenge-backlink");
        let data_dir = dir.to_str().unwrap();
        let result_ref = "work-result://wr_challenge";
        let challenge_ref = format!("verifier-challenge://vc_{}", "a".repeat(64));
        let mut prior = validate_work_result(&valid_result_body(), &no_resolve, &no_room).unwrap();
        prior["work_result_id"] = json!(result_ref);
        persist_record(data_dir, RESULT_DIR, "wr_challenge", &prior).unwrap();
        let successor =
            verifier_challenge_backlink_successor(&prior, result_ref, &challenge_ref).unwrap();
        let applied = bind_verifier_challenge_locked(
            data_dir,
            result_ref,
            &challenge_ref,
            &prior,
            &successor,
            "vci_test",
        )
        .unwrap();
        assert_eq!(applied, successor);
        assert_eq!(
            load_work_result_strict(data_dir, result_ref)
                .unwrap()
                .unwrap()["review_refs"],
            json!([challenge_ref])
        );
        assert_eq!(
            bind_verifier_challenge_locked(
                data_dir,
                result_ref,
                &format!("verifier-challenge://vc_{}", "a".repeat(64)),
                &prior,
                &successor,
                "vci_test",
            )
            .unwrap(),
            successor
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn generic_seam_never_resolves_application_scope_or_mints_system_binding() {
        let mut b = valid_result_body();
        b["outcome_room_ref"] = json!("outcome-room://or_ghost");
        assert_eq!(
            validate_work_result(&b, &no_resolve, &open_room)
                .unwrap_err()
                .0,
            "work_result_system_binding_owner_required"
        );
        let mut b = valid_result_body();
        b["system_binding"] = json!({"system_id":"system://forged"});
        assert_eq!(
            validate_work_result(&b, &no_resolve, &open_room)
                .unwrap_err()
                .0,
            "work_result_system_binding_owner_required"
        );
        let roomed = json!({ "work_result_id": "work-result://wr_r", "work_subject_ref": "goal://alpha", "system_binding": {"parent_scope_ref":"outcome-room://or_open"}, "outcome_delta_refs": [] });
        let resolver = |rid: &str| (rid == "wr_r").then(|| roomed.clone());
        let base = json!({ "goal_ref": "goal://alpha", "delta_kind": "update", "target_ref": "frontier://f1", "proposed_by_ref": "work-result://wr_r" });
        assert_eq!(
            validate_outcome_delta(&base, &resolver, &open_room)
                .unwrap_err()
                .0,
            "outcome_delta_cross_system_scope"
        );
    }

    #[test]
    fn principal_scoped_collection_omits_a_generic_subject_without_goalrun_ownership() {
        let dir = temp_dir("generic-subject-owner-filter");
        let result = json!({
            "work_result_id":"work-result://generic/unowned",
            "work_subject_ref":"goal://generic-substrate-subject",
        });
        assert!(!result_owner_matches(
            dir.to_str().unwrap(),
            &result,
            "user://authenticated-reader",
        )
        .expect("an absent application owner is an unowned generic subject, not registry damage"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn supersedes_requires_resolvable_same_goal_same_room_result() {
        let resolver = |tail: &str| match tail {
            "wr_same" => Some(
                json!({ "work_result_id": "work-result://wr_same", "work_subject_ref": "goal://g-research-1", "system_binding": null }),
            ),
            "wr_other" => Some(
                json!({ "work_result_id": "work-result://wr_other", "work_subject_ref": "goal://g-other", "system_binding": null }),
            ),
            "wr_roomed" => Some(
                json!({ "work_result_id": "work-result://wr_roomed", "work_subject_ref": "goal://g-research-1", "system_binding": {"parent_scope_ref":"outcome-room://or_open"} }),
            ),
            _ => None,
        };
        let mut b = valid_result_body();
        b["supersedes_work_result_ref"] = json!("work-result://wr_ghost");
        assert_eq!(
            validate_work_result(&b, &resolver, &no_room).unwrap_err().0,
            "work_result_supersedes_unbound"
        );
        let mut b = valid_result_body();
        b["supersedes_work_result_ref"] = json!("work-result://wr_other");
        assert_eq!(
            validate_work_result(&b, &resolver, &no_room).unwrap_err().0,
            "work_result_supersedes_cross_goal"
        );
        let mut b = valid_result_body();
        b["supersedes_work_result_ref"] = json!("work-result://wr_same");
        assert_eq!(
            validate_work_result(&b, &resolver, &no_room).unwrap()["supersedes_work_result_ref"],
            json!("work-result://wr_same")
        );
        // #72 finding 2: supersession preserves room identity EXACTLY, like deltas.
        // Roomless result superseding a roomed result → cross-room.
        let mut b = valid_result_body();
        b["supersedes_work_result_ref"] = json!("work-result://wr_roomed");
        assert_eq!(
            validate_work_result(&b, &resolver, &open_room)
                .unwrap_err()
                .0,
            "work_result_supersedes_cross_system_scope"
        );
        // Caller-supplied application scope is refused before supersession can be evaluated.
        let mut b = valid_result_body();
        b["supersedes_work_result_ref"] = json!("work-result://wr_same");
        b["outcome_room_ref"] = json!("outcome-room://or_open");
        assert_eq!(
            validate_work_result(&b, &resolver, &open_room)
                .unwrap_err()
                .0,
            "work_result_system_binding_owner_required"
        );
    }

    #[test]
    fn delta_binds_same_goal_result_and_receipts_bind_facts() {
        let bound = json!({ "work_result_id": "work-result://wr_real", "work_subject_ref": "goal://alpha", "system_binding": null, "outcome_delta_refs": [] });
        let resolver = |rid: &str| {
            if rid == "wr_real" {
                Some(bound.clone())
            } else {
                None
            }
        };
        let base = json!({ "goal_ref": "goal://alpha", "delta_kind": "update", "target_ref": "frontier://f1", "proposed_by_ref": "work-result://wr_real" });
        // Cross-goal binding refuses typed (finding 2).
        let mut b = base.clone();
        b["goal_ref"] = json!("goal://beta");
        assert_eq!(
            validate_outcome_delta(&b, &resolver, &open_room)
                .unwrap_err()
                .0,
            "outcome_delta_cross_goal"
        );
        // Rooms are LIVE (step 2): unresolvable / closed / cross-room bindings refuse typed.
        let mut b = base.clone();
        b["outcome_room_ref"] = json!("outcome-room://or_ghost");
        assert_eq!(
            validate_outcome_delta(&b, &resolver, &open_room)
                .unwrap_err()
                .0,
            "outcome_delta_system_binding_owner_required"
        );
        let mut b = base.clone();
        b["outcome_room_ref"] = json!("outcome-room://or_closed");
        assert_eq!(
            validate_outcome_delta(&b, &resolver, &open_room)
                .unwrap_err()
                .0,
            "outcome_delta_system_binding_owner_required"
        );
        // The bound result has NO room — a roomed delta is a cross-room binding.
        let mut b = base.clone();
        b["outcome_room_ref"] = json!("outcome-room://or_open");
        assert_eq!(
            validate_outcome_delta(&b, &resolver, &open_room)
                .unwrap_err()
                .0,
            "outcome_delta_system_binding_owner_required"
        );
        // Ghost / foreign / future proposers refuse.
        let mut b = base.clone();
        b["proposed_by_ref"] = json!("work-result://wr_ghost");
        assert_eq!(
            validate_outcome_delta(&b, &resolver, &open_room)
                .unwrap_err()
                .0,
            "outcome_delta_unbound_result"
        );
        for scheme in UNAVAILABLE_PROPOSER_SCHEMES {
            let mut b = base.clone();
            b["proposed_by_ref"] = json!(format!("{scheme}://x1"));
            assert_eq!(
                validate_outcome_delta(&b, &resolver, &open_room)
                    .unwrap_err()
                    .0,
                "outcome_delta_proposer_kind_unavailable"
            );
        }
        // Happy: same-goal binding returns the BOUND RECORD for the atomic backlink.
        let (rec, prior) = validate_outcome_delta(&base, &resolver, &open_room).unwrap();
        assert_eq!(rec["status"], json!("proposed"));
        assert_eq!(s(&prior, "work_result_id", ""), "work-result://wr_real");
        // Receipt profiles: canonical receipt:// identity + bound facts + hash + honest posture.
        let mut full = rec.clone();
        full["outcome_delta_id"] = json!("outcome-delta://od_t");
        let (_, receipt) = build_outcome_delta_receipt(&full, "2026-01-01T00:00:00Z");
        assert!(s(&receipt, "receipt_id", "").starts_with("receipt://odr_"));
        assert_eq!(
            receipt["receipt_type"],
            json!("OutcomeDeltaAdmissionReceipt")
        );
        assert_eq!(
            receipt["bound_facts"]["proposed_by_ref"],
            json!("work-result://wr_real")
        );
        assert_eq!(receipt["bound_facts"]["delta_kind"], json!("update"));
        assert_eq!(receipt["bound_facts"]["effect_admitted"], json!(false));
        assert_eq!(receipt["effect_admitted"], json!(false));
        assert!(s(&receipt, "output_hash", "").starts_with("sha256:"));
        // The hash matches a recompute over the record minus the declared excludes.
        assert_eq!(
            s(&receipt, "output_hash", ""),
            record_output_hash(&full, DELTA_HASH_EXCLUDES)
        );
        let (_, wr_receipt) = build_work_result_receipt(
            &json!({ "work_result_id": "work-result://wr_real", "work_subject_ref": "goal://alpha", "result_profile": "research", "outcome_class": "negative", "status": "completed" }),
            "2026-01-01T00:00:00Z",
        );
        assert!(s(&wr_receipt, "receipt_id", "").starts_with("receipt://wrr_"));
        assert_eq!(wr_receipt["receipt_type"], json!("WorkResultReceipt"));
        assert_eq!(
            wr_receipt["bound_facts"]["result_profile"],
            json!("research")
        );
        assert_eq!(
            wr_receipt["bound_facts"]["outcome_class"],
            json!("negative")
        );
        assert_eq!(
            wr_receipt["assurance_posture"],
            json!("admitted_not_verified")
        );
    }

    #[test]
    fn delta_finalize_is_atomic_across_record_backlink_and_receipt() {
        let dir = temp_dir("delta-atomic");
        let data_dir = dir.to_str().unwrap();
        let now = "2026-01-01T00:00:00Z";
        let prior = json!({ "work_result_id": "work-result://wr_1", "goal_ref": "goal://a", "outcome_delta_refs": [] });
        persist_record(data_dir, RESULT_DIR, "wr_1", &prior).unwrap();
        let delta = json!({ "outcome_delta_id": "outcome-delta://od_1", "goal_ref": "goal://a", "proposed_by_ref": "work-result://wr_1", "status": "proposed" });
        let mut updated = prior.clone();
        updated["outcome_delta_refs"] = json!(["outcome-delta://od_1"]);
        let (rid, receipt) = build_outcome_delta_receipt(&delta, now);
        // Receipt dir blocked → delta removed AND the WorkResult restored BYTE-FOR-BYTE.
        std::fs::write(dir.join(DELTA_RECEIPT_DIR), b"blocker").unwrap();
        let (code, msg) = finalize_delta_persist(
            data_dir, "od_1", &delta, "wr_1", &prior, &updated, &rid, &receipt,
        )
        .unwrap_err();
        assert_eq!(code, "outcome_delta_receipt_persist_failed");
        assert!(msg.contains("rolled back"), "{msg}");
        assert!(
            read_record_dir(data_dir, DELTA_DIR).is_empty(),
            "no unproven delta survives"
        );
        let restored = read_record_dir(data_dir, RESULT_DIR).pop().unwrap();
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            serde_json::to_vec(&prior).unwrap(),
            "the WorkResult is byte-for-byte the prior record (refs AND updated_at)"
        );
        std::fs::remove_file(dir.join(DELTA_RECEIPT_DIR)).unwrap();
        // Happy path: delta + backlink + receipt all persist.
        finalize_delta_persist(
            data_dir, "od_1", &delta, "wr_1", &prior, &updated, &rid, &receipt,
        )
        .unwrap();
        assert_eq!(read_record_dir(data_dir, DELTA_DIR).len(), 1);
        assert_eq!(read_record_dir(data_dir, DELTA_RECEIPT_DIR).len(), 1);
        let linked = read_record_dir(data_dir, RESULT_DIR).pop().unwrap();
        assert_eq!(
            linked["outcome_delta_refs"],
            json!(["outcome-delta://od_1"]),
            "the backlink landed atomically"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn receipt_failure_restores_the_exact_prior_record_including_interleaving() {
        // INTERLEAVING LANE (#71 rounds 2-3): delta A already landed ([A] on the result, with A's
        // updated_at). Delta B's receipt fails. B's rollback must restore the prior record
        // BYTE-FOR-BYTE — [A] survives AND updated_at is A's, not B's (no unreceipted mutation).
        // `prior` is captured under DELTA_ADMISSION_LOCK in the handler, so it is never stale.
        let dir = temp_dir("interleave");
        let data_dir = dir.to_str().unwrap();
        let now_b = "2026-01-02T00:00:00Z";
        let with_a = json!({ "work_result_id": "work-result://wr_1", "goal_ref": "goal://a", "outcome_delta_refs": ["outcome-delta://od_A"], "updated_at": "2026-01-01T11:11:11Z" });
        persist_record(data_dir, RESULT_DIR, "wr_1", &with_a).unwrap();
        let delta_b = json!({ "outcome_delta_id": "outcome-delta://od_B", "goal_ref": "goal://a", "proposed_by_ref": "work-result://wr_1", "status": "proposed" });
        let mut updated = with_a.clone();
        updated["outcome_delta_refs"] = json!(["outcome-delta://od_A", "outcome-delta://od_B"]);
        updated["updated_at"] = json!(now_b);
        let (rid, receipt) = build_outcome_delta_receipt(&delta_b, now_b);
        std::fs::write(dir.join(DELTA_RECEIPT_DIR), b"blocker").unwrap();
        let (code, _) = finalize_delta_persist(
            data_dir, "od_B", &delta_b, "wr_1", &with_a, &updated, &rid, &receipt,
        )
        .unwrap_err();
        assert_eq!(code, "outcome_delta_receipt_persist_failed");
        let after = read_record_dir(data_dir, RESULT_DIR).pop().unwrap();
        assert_eq!(
            serde_json::to_vec(&after).unwrap(),
            serde_json::to_vec(&with_a).unwrap(),
            "byte-for-byte prior: [A] survives and updated_at is untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_replacement_cleans_its_temp_file_on_rename_failure() {
        // #71 round 3: a failed write/rename must leave NO .tmp-* sibling (tmp files are
        // invisible to read_record_dir, so a leak would evade every orphan sweep).
        let dir = temp_dir("tmpclean");
        let data_dir = dir.to_str().unwrap();
        let record_dir = dir.join(RESULT_DIR);
        std::fs::create_dir_all(&record_dir).unwrap();
        // Force RENAME failure: the destination path is a NON-EMPTY DIRECTORY.
        let dest = record_dir.join("wr_block.json");
        std::fs::create_dir_all(dest.join("occupied")).unwrap();
        let err = persist_result_atomic(
            data_dir,
            "wr_block",
            &json!({ "work_result_id": "work-result://wr_block" }),
        );
        assert!(err.is_err(), "rename onto a non-empty directory must fail");
        let tmp_leaks: Vec<String> = std::fs::read_dir(&record_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(
            tmp_leaks.is_empty(),
            "no temporary artifact survives a failed replacement: {tmp_leaks:?}"
        );
        // And through the FULL finalize path: the backlink rename fails → delta rolled back,
        // no tmp, no delta record, no receipt.
        let delta = json!({ "outcome_delta_id": "outcome-delta://od_t", "goal_ref": "goal://a", "proposed_by_ref": "work-result://wr_block", "status": "proposed" });
        let prior = json!({ "work_result_id": "work-result://wr_block", "outcome_delta_refs": [] });
        let (rid, receipt) = build_outcome_delta_receipt(&delta, "2026-01-01T00:00:00Z");
        let (code, _) = finalize_delta_persist(
            data_dir, "od_t", &delta, "wr_block", &prior, &prior, &rid, &receipt,
        )
        .unwrap_err();
        assert_eq!(code, "outcome_delta_backlink_persist_failed");
        let tmp_leaks2: Vec<String> = std::fs::read_dir(&record_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(
            tmp_leaks2.is_empty(),
            "no temporary artifact survives the finalize backlink failure: {tmp_leaks2:?}"
        );
        assert!(
            read_record_dir(data_dir, DELTA_DIR).is_empty(),
            "delta rolled back"
        );
        assert!(
            read_record_dir(data_dir, DELTA_RECEIPT_DIR).is_empty(),
            "no receipt"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn receipts_carry_the_exact_portable_envelope_key_set() {
        // Pin the COMPLETE ReceiptEnvelope base (#71 round 2): every canonical base field is
        // explicitly present (null/[] when unbound) and no key drifts in or out silently.
        let expected_base = [
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
        let (_, wr) = build_work_result_receipt(
            &json!({ "work_result_id": "work-result://wr_k", "goal_ref": "goal://g", "result_profile": "research", "outcome_class": "positive", "status": "completed" }),
            "2026-01-01T00:00:00Z",
        );
        let (_, od) = build_outcome_delta_receipt(
            &json!({ "outcome_delta_id": "outcome-delta://od_k", "goal_ref": "goal://g", "proposed_by_ref": "work-result://wr_k", "target_ref": "frontier://f", "delta_kind": "update" }),
            "2026-01-01T00:00:00Z",
        );
        for (name, rcpt, extra) in [
            ("WorkResultReceipt", &wr, vec![]),
            ("OutcomeDeltaAdmissionReceipt", &od, vec!["effect_admitted"]),
        ] {
            let mut expected: Vec<&str> = expected_base.to_vec();
            expected.extend(extra);
            expected.sort_unstable();
            let mut actual: Vec<String> = rcpt.as_object().unwrap().keys().cloned().collect();
            actual.sort_unstable();
            assert_eq!(
                actual,
                expected.iter().map(|k| k.to_string()).collect::<Vec<_>>(),
                "{name} key set drifted"
            );
            assert_eq!(rcpt["claim_scope_ref"], Value::Null);
            assert_eq!(rcpt["primitive_capabilities"], json!([]));
            assert_eq!(rcpt["authority_scopes"], json!([]));
            assert_eq!(rcpt["artifact_refs"], json!([]));
            assert_eq!(rcpt["evidence_bundle_refs"], json!([]));
            assert_eq!(rcpt["adjudication_ref"], Value::Null);
            assert_eq!(rcpt["settlement_ref"], Value::Null);
        }
    }

    #[test]
    fn result_finalize_atomicity_no_orphan_record_no_orphan_receipt() {
        let dir = temp_dir("atomic");
        let data_dir = dir.to_str().unwrap();
        let now = "2026-01-01T00:00:00Z";
        let record = json!({ "work_result_id": "work-result://wr_x", "goal_ref": "goal://g", "result_profile": "research", "outcome_class": "positive", "status": "completed" });
        let (rid, receipt) = build_work_result_receipt(&record, now);
        std::fs::write(dir.join(RESULT_RECEIPT_DIR), b"blocker").unwrap();
        let (code, msg) =
            finalize_result_persist(data_dir, "wr_x", &record, &rid, &receipt).unwrap_err();
        assert_eq!(code, "work_result_receipt_persist_failed");
        assert!(msg.contains("rolled back"), "{msg}");
        assert!(
            read_record_dir(data_dir, RESULT_DIR).is_empty(),
            "no unproven admission survives"
        );
        std::fs::remove_file(dir.join(RESULT_RECEIPT_DIR)).unwrap();
        std::fs::remove_dir_all(dir.join(RESULT_DIR)).unwrap();
        std::fs::write(dir.join(RESULT_DIR), b"blocker").unwrap();
        let (code2, _) =
            finalize_result_persist(data_dir, "wr_x", &record, &rid, &receipt).unwrap_err();
        assert_eq!(code2, "work_result_record_persist_failed");
        assert!(
            read_record_dir(data_dir, RESULT_RECEIPT_DIR).is_empty(),
            "no receipt without its record"
        );
        std::fs::remove_file(dir.join(RESULT_DIR)).unwrap();
        finalize_result_persist(data_dir, "wr_x", &record, &rid, &receipt).unwrap();
        assert_eq!(read_record_dir(data_dir, RESULT_DIR).len(), 1);
        assert_eq!(read_record_dir(data_dir, RESULT_RECEIPT_DIR).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn finalize_reports_rollback_failure_as_its_own_typed_lane() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("rbfail");
        let data_dir = dir.to_str().unwrap();
        let now = "2026-01-01T00:00:00Z";
        let record = json!({ "work_result_id": "work-result://wr_z", "goal_ref": "goal://g", "result_profile": "research", "outcome_class": "positive", "status": "completed" });
        let (rid, receipt) = build_work_result_receipt(&record, now);
        persist_record(data_dir, RESULT_DIR, "wr_z", &record).unwrap();
        std::fs::write(dir.join(RESULT_RECEIPT_DIR), b"blocker").unwrap();
        let record_dir = dir.join(RESULT_DIR);
        std::fs::set_permissions(&record_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let out = finalize_result_persist(data_dir, "wr_z", &record, &rid, &receipt);
        std::fs::set_permissions(&record_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (code, msg) = out.unwrap_err();
        if code == "work_result_rollback_failed" {
            assert!(msg.contains("manual repair required"), "{msg}");
        } else {
            assert_eq!(code, "work_result_receipt_persist_failed"); // root bypasses dir perms in some CI
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ------------------------------------------------ M06.1: the published WorkResult subject seam

    #[test]
    fn work_result_subject_resolver_refuses_a_prefix_that_names_nothing() {
        let dir = temp_dir("m061-absent");
        let data_dir = dir.to_str().unwrap();
        // A perfectly well-formed identity for a record that was never admitted. THE POINT: the
        // resolver must not treat the spelling as evidence the subject exists.
        let (code, _message) =
            resolve_admitted_work_result(data_dir, None, "work-result://wr_never_admitted")
                .expect_err("an unadmitted subject must refuse");
        assert_eq!(code, "work_result_subject_not_admitted");

        // And a malformed identity is refused by the owner's own reader rather than probed.
        let (code, _message) = resolve_admitted_work_result(data_dir, None, "goal://not-a-result")
            .expect_err("a foreign scheme must refuse");
        assert_eq!(code, "work_result_subject_unreadable");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn work_result_commitment_distinguishes_owner_admitted_backlink_versions() {
        // THE CONSTRAINT THIS EXISTS FOR. A WorkResult is not immutable: its owner admits
        // `review_refs` and `outcome_delta_refs` backlinks in place. If the subject commitment
        // excluded those fields — as the ADMISSION RECEIPT's hash deliberately does — then version 1
        // and version 2 of one record would share a hash, and a transition sealed over the first
        // would silently read as attesting the second. Binding "the exact record bytes" has to mean
        // exactly that, or the URI is being passed off as a stable identity.
        let dir = temp_dir("m061-versions");
        let data_dir = dir.to_str().unwrap();
        let result_ref = "work-result://wr_versions";
        let challenge_ref = format!("verifier-challenge://vc_{}", "b".repeat(64));
        let mut prior = validate_work_result(&valid_result_body(), &no_resolve, &no_room).unwrap();
        prior["work_result_id"] = json!(result_ref);
        persist_record(data_dir, RESULT_DIR, "wr_versions", &prior).unwrap();

        let v1 = resolve_admitted_work_result(data_dir, None, result_ref).expect("v1 resolves");
        assert!(v1.content_hash.starts_with("sha256:"));
        assert_eq!(
            v1.record, prior,
            "the resolver carries the exact admitted record"
        );
        assert_eq!(v1.outcome_class, "positive");
        assert_eq!(v1.status, "completed");

        // The owner admits a backlink, in place, through its own seam.
        let successor =
            verifier_challenge_backlink_successor(&prior, result_ref, &challenge_ref).unwrap();
        bind_verifier_challenge_locked(
            data_dir,
            result_ref,
            &challenge_ref,
            &prior,
            &successor,
            "vci_m061",
        )
        .unwrap();

        let v2 = resolve_admitted_work_result(data_dir, None, result_ref).expect("v2 resolves");
        assert_ne!(
            v1.content_hash, v2.content_hash,
            "an owner-admitted backlink must produce a DISTINCT content-hash version"
        );
        // AND THE CASE WHERE THE TWO DIGESTS GENUINELY DIVERGE. `RESULT_HASH_EXCLUDES` omits
        // `outcome_delta_refs` (but NOT `review_refs`), so an admitted OutcomeDelta backlink leaves
        // the admission-receipt digest byte-identical while changing the record. That is correct for
        // a receipt — it must not be invalidated by a later plane-owned backlink — and it is exactly
        // why the subject commitment could not reuse it: under the receipt's digest these two
        // versions are indistinguishable, and a transition sealed over the first would silently read
        // as attesting the second.
        let mut with_delta = successor.clone();
        with_delta["outcome_delta_refs"] = json!(["outcome-delta://od_m061"]);
        assert_eq!(
            record_output_hash(&successor, RESULT_HASH_EXCLUDES),
            record_output_hash(&with_delta, RESULT_HASH_EXCLUDES),
            "the admission-receipt digest is deliberately blind to an OutcomeDelta backlink",
        );
        assert_ne!(
            work_result_record_commitment(&successor).unwrap(),
            work_result_record_commitment(&with_delta).unwrap(),
            "the subject commitment must SEE the version the receipt digest is blind to",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn work_result_commitment_binds_its_domain_and_the_whole_record() {
        // The commitment is recomputable by a relying party from the declared domain plus the exact
        // bytes, and nothing else. A domain that drifted would silently change every subject hash.
        let record = json!({
            "work_result_id": "work-result://wr_domain",
            "outcome_class": "negative",
            "status": "completed",
        });
        let expected = {
            let material = json!({
                "domain": "ioi.work-result-record-commitment-jcs-sha256.v1",
                "record": record,
            });
            format!(
                "sha256:{:x}",
                Sha256::digest(&serde_jcs::to_vec(&material).unwrap())
            )
        };
        assert_eq!(work_result_record_commitment(&record).unwrap(), expected);
        assert_eq!(
            WORK_RESULT_COMMITMENT_DOMAIN,
            "ioi.work-result-record-commitment-jcs-sha256.v1"
        );

        // A single changed byte anywhere in the record moves the hash.
        let mut altered = record.clone();
        altered["status"] = json!("failed");
        assert_ne!(
            work_result_record_commitment(&record).unwrap(),
            work_result_record_commitment(&altered).unwrap()
        );
    }

    #[test]
    fn work_result_subject_resolver_answers_absence_and_non_entitlement_identically() {
        // A graph over a result the caller may not see must not become an existence oracle for
        // another owner's work. Absence and not-entitled therefore share one code and one message.
        let dir = temp_dir("m061-scope");
        let data_dir = dir.to_str().unwrap();
        let result_ref = "work-result://wr_scoped";
        let mut record = validate_work_result(&valid_result_body(), &no_resolve, &no_room).unwrap();
        record["work_result_id"] = json!(result_ref);
        persist_record(data_dir, RESULT_DIR, "wr_scoped", &record).unwrap();

        // With no reader the owner's global posture applies and the record resolves.
        assert!(resolve_admitted_work_result(data_dir, None, result_ref).is_ok());

        // With a reader that does not own the backing goal, the SAME refusal an absent record gets.
        let (scoped_code, scoped_message) =
            resolve_admitted_work_result(data_dir, Some("user://someone_else"), result_ref)
                .expect_err("a non-entitled reader must refuse");
        let (absent_code, absent_message) = resolve_admitted_work_result(
            data_dir,
            Some("user://someone_else"),
            "work-result://wr_absent",
        )
        .expect_err("an absent record must refuse");
        assert_eq!(scoped_code, absent_code);
        assert_eq!(scoped_code, "work_result_subject_not_admitted");
        // The messages differ only by the ref the caller itself supplied, never by what exists.
        assert!(scoped_message.contains(result_ref));
        assert!(absent_message.contains("work-result://wr_absent"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
