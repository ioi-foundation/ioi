//! WorkResult + OutcomeDelta plane — the FIRST contract-first cut of the collaborative-pursuit
//! leg (canon-to-code-delta build step 1). Admits the GENERIC bounded result seam of
//! `WorkResultEnvelope` (canonical owner: docs/architecture/foundations/
//! common-objects-and-envelopes.md) — a result may come from research, ontology mutation,
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
//! - FUTURE-PLANE fields are named gaps, fail-closed: non-empty `outcome_room_ref`,
//!   `work_claim_ref`, `attempt_ref`, `finding_refs`, `acceptance_ref`, and
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

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const RESULT_SCHEMA: &str = "ioi.hypervisor.work-result.v1";
const RESULT_RECEIPT_SCHEMA: &str = "ioi.hypervisor.work-result-receipt.v1";
const DELTA_SCHEMA: &str = "ioi.hypervisor.outcome-delta.v1";
const DELTA_RECEIPT_SCHEMA: &str = "ioi.hypervisor.outcome-delta-admission-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.work-results-overview.v1";
pub(crate) const RESULT_DIR: &str = "work-result-registry";
const RESULT_RECEIPT_DIR: &str = "work-result-registry-receipts";
pub(crate) const DELTA_DIR: &str = "outcome-delta-registry";
const DELTA_RECEIPT_DIR: &str = "outcome-delta-registry-receipts";

/// The canonical envelope vocabularies (common-objects-and-envelopes.md, verbatim).
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
    "update_frontier",
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

/// Strict WorkResult point loader for later provenance planes. Unlike the legacy list helper,
/// this distinguishes absence from an occupied unreadable/malformed/identity-mismatched slot.
pub(crate) fn load_work_result_strict(
    data_dir: &str,
    result_ref: &str,
) -> Result<Option<Value>, String> {
    let tail = result_ref
        .strip_prefix("work-result://")
        .ok_or_else(|| "WorkResult ref must be work-result://...".to_string())?;
    if tail.is_empty()
        || tail.len() > 120
        || !tail
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err("WorkResult ref has a noncanonical storage key".into());
    }
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, RESULT_DIR) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("WorkResult registry cannot be pinned ({error})")),
    };
    let bytes = match super::durable_fs::read_slot_strict(&directory, &format!("{tail}.json")) {
        Ok(None) => return Ok(None),
        Ok(Some((_file, bytes))) => bytes,
        Err(error) => return Err(format!("WorkResult slot '{tail}' is unreadable ({error})")),
    };
    let record: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("WorkResult slot '{tail}' is malformed ({error})"))?;
    if record.get("schema_version").and_then(Value::as_str) != Some(RESULT_SCHEMA)
        || record.get("work_result_id").and_then(Value::as_str) != Some(result_ref)
    {
        return Err(format!(
            "WorkResult slot '{tail}' fails storage-key/schema identity binding"
        ));
    }
    Ok(Some(record))
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
    updated_at: &str,
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
        .get("challenge_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "work_result_challenge_backlink_invalid",
                "WorkResult challenge_refs is not a plane-owned list",
            )
        })?;
    if refs.len() >= 128 {
        return Err(verr(
            "work_result_challenge_backlink_capacity",
            "WorkResult challenge_refs reached its hard bound",
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
    object.insert("challenge_refs".into(), json!(next_refs));
    object.insert("updated_at".into(), json!(updated_at));
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
    let updated_at = successor
        .get("updated_at")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "work_result_challenge_backlink_invalid",
                "sealed WorkResult successor lacks updated_at",
            )
        })?;
    let expected =
        verifier_challenge_backlink_successor(prior, result_ref, challenge_ref, updated_at)?;
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
    let tail = result_ref.strip_prefix("work-result://").ok_or_else(|| {
        verr(
            "work_result_challenge_backlink_identity_mismatch",
            "WorkResult ref has the wrong scheme",
        )
    })?;
    persist_result_atomic(data_dir, tail, successor).map_err(|error| {
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
    let tail = delta_ref
        .strip_prefix("outcome-delta://")
        .ok_or_else(|| "OutcomeDelta ref must be outcome-delta://...".to_string())?;
    if tail.is_empty()
        || tail.len() > 120
        || !tail
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err("OutcomeDelta ref has a noncanonical storage key".into());
    }
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, DELTA_DIR) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("OutcomeDelta registry cannot be pinned ({error})")),
    };
    let bytes = match super::durable_fs::read_slot_strict(&directory, &format!("{tail}.json")) {
        Ok(None) => return Ok(None),
        Ok(Some((_file, bytes))) => bytes,
        Err(error) => {
            return Err(format!(
                "OutcomeDelta slot '{tail}' is unreadable ({error})"
            ))
        }
    };
    let record: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("OutcomeDelta slot '{tail}' is malformed ({error})"))?;
    if record.get("schema_version").and_then(Value::as_str) != Some(DELTA_SCHEMA)
        || record.get("outcome_delta_id").and_then(Value::as_str) != Some(delta_ref)
    {
        return Err(format!(
            "OutcomeDelta slot '{tail}' fails storage-key/schema identity binding"
        ));
    }
    Ok(Some(record))
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

const RESULT_HASH_EXCLUDES: &[&str] =
    &["admission_receipt_ref", "outcome_delta_refs", "updated_at"];
const DELTA_HASH_EXCLUDES: &[&str] = &["admission_receipt_ref", "status", "updated_at"];

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
        "attested_boundary_fact_refs": [subject, s(record, "goal_ref", "")],
        "bound_facts": {
            "goal_ref": record["goal_ref"],
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
        "attested_boundary_fact_refs": [subject, s(record, "goal_ref", ""), s(record, "proposed_by_ref", ""), s(record, "target_ref", "")],
        "bound_facts": {
            "goal_ref": record["goal_ref"],
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
/// restores the EXACT prior record — outcome_delta_refs AND updated_at, byte for byte — so a
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
                Err(verr("outcome_delta_receipt_persist_failed", format!("delta receipt persist failed ({e}); the delta was rolled back and the work-result restored EXACTLY (refs + updated_at) — nothing changed")))
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
    resolve_room: &dyn Fn(&str) -> Option<Value>,
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
    // Room binding (build step 2, LIVE): a declared room must RESOLVE to an OPEN hosted room.
    let outcome_room = match scalar_ref(body, "outcome_room_ref", &["outcome-room"], &[], &[])? {
        None => Value::Null,
        Some(r) => {
            match resolve_room(&r) {
                None => {
                    return Err(verr(
                        "work_result_room_unbound",
                        format!(
                        "`outcome_room_ref` does not resolve to an admitted OutcomeRoom ('{r}')"
                    ),
                    ))
                }
                // ADMISSION BOUNDARY IS INTENT-AWARE (#72 round 10 review, finding 1): a room whose
                // transition/attach intent is durably sealed may already be ORDERED closed — its
                // visible prior status must not admit new results while convergence is pending.
                Some(room) if super::outcome_room_routes::pending_intent(&room).is_some() => {
                    return Err(verr("work_result_room_intent_pending", format!("room '{r}' has a durable mutation intent pending convergence — results refuse until the sealed transition applies (a restart converges it)")));
                }
                Some(room) if room.get("status").and_then(|v| v.as_str()) != Some("open") => {
                    return Err(verr(
                        "work_result_room_not_open",
                        format!(
                            "room '{r}' is '{}' — results admit only into an open room",
                            room.get("status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                        ),
                    ));
                }
                Some(_) => Value::String(r),
            }
        }
    };
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
        .get("challenge_refs")
        .map(|v| !v.is_null())
        .unwrap_or(false)
    {
        return Err(verr("work_result_challenge_refs_plane_owned", "`challenge_refs` is plane-owned — VerifierChallenge admission registers the backlink through the WorkResult owner seam; callers never supply it"));
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
                    let target_goal = s(&target, "goal_ref", "");
                    if target_goal != goal_ref {
                        return Err(verr("work_result_supersedes_cross_goal", format!("`supersedes_work_result_ref` resolves under '{target_goal}', not this result's '{goal_ref}' — supersession never crosses goals")));
                    }
                    let target_room = target.get("outcome_room_ref").cloned().unwrap_or(Value::Null);
                    if target_room != outcome_room {
                        return Err(verr("work_result_supersedes_cross_room", format!("the superseded result's room ({}) must exactly equal this result's room ({}) — supersession never crosses room scope", if target_room.is_null() { "null".into() } else { target_room.to_string() }, if outcome_room.is_null() { "null".into() } else { outcome_room.to_string() })));
                    }
                    Value::String(r)
                }
            }
        }
    };
    // Field-specific canonical-ref validation (the envelope's declared schemes per field).
    let record = json!({
        "schema_version": RESULT_SCHEMA,
        "goal_ref": goal_ref,
        "goal_run_ref": scalar_ref(body, "goal_run_ref", &["goal"], &[], &[])?,
        "outcome_room_ref": outcome_room,
        "work_claim_ref": Value::Null,
        "attempt_ref": Value::Null,
        "invocation_or_run_ref": scalar_ref(body, "invocation_or_run_ref", &["harness_invocation", "run", "service", "mission"], &[], &[])?,
        "result_profile": result_profile,
        "result_profile_ref": scalar_ref(body, "result_profile_ref", &["schema", "profile"], &[], &[])?,
        "result_payload_ref": scalar_ref(body, "result_payload_ref", &["artifact", "cid"], &[], &["encrypted_ref"])?,
        "worker_harness_model_runtime_version_refs": list_ref(body, "worker_harness_model_runtime_version_refs", &["worker", "model", "model_route", "runtime", "registry_version"], &["harness_profile:", "agent_harness_adapter:"], &[])?,
        "declared_method_and_lineage_refs": list_ref(body, "declared_method_and_lineage_refs", &["method", "attempt", "finding", "work-result", "artifact", "trace"], &[], &[])?,
        "outcome_class": outcome_class,
        "status": status,
        "outcome_delta_refs": [],
        "finding_refs": [],
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
        "challenge_refs": [],
        "supersedes_work_result_ref": supersedes,
        "superseded_by_ref": Value::Null,
        "summary_ref": scalar_ref(body, "summary_ref", &["message", "artifact"], &[], &[])?,
        "next_action": next_action,
        "runtimeTruthSource": "daemon-runtime"
    });
    Ok(record)
}

fn load_by(data_dir: &str, dir: &str, id_key: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, dir)
        .into_iter()
        .find(|r| r.get(id_key).and_then(|v| v.as_str()) == Some(id))
}

/// Validate an OutcomeDelta admission body. The resolver returns the referenced WorkResult
/// RECORD (not a boolean), so the binding invariants compare goal (and, once rooms exist, room)
/// identity — a cross-goal binding refuses typed with zero mutation.
fn validate_outcome_delta(
    body: &Value,
    resolve_result: &dyn Fn(&str) -> Option<Value>,
    resolve_room: &dyn Fn(&str) -> Option<Value>,
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
    // Room binding (build step 2, LIVE): a declared room must resolve to an OPEN hosted room,
    // and must EXACTLY equal the bound result's room (checked after the result resolves below).
    let delta_room = match scalar_ref(body, "outcome_room_ref", &["outcome-room"], &[], &[])? {
        None => Value::Null,
        Some(r) => {
            match resolve_room(&r) {
                None => {
                    return Err(verr(
                        "outcome_delta_room_unbound",
                        format!(
                        "`outcome_room_ref` does not resolve to an admitted OutcomeRoom ('{r}')"
                    ),
                    ))
                }
                // Intent-aware admission boundary (#72 round 10 review, finding 1) — same rule as
                // results: a durably ordered transition outranks the visible prior status.
                Some(room) if super::outcome_room_routes::pending_intent(&room).is_some() => {
                    return Err(verr("outcome_delta_room_intent_pending", format!("room '{r}' has a durable mutation intent pending convergence — deltas refuse until the sealed transition applies (a restart converges it)")));
                }
                Some(room) if room.get("status").and_then(|v| v.as_str()) != Some("open") => {
                    return Err(verr(
                        "outcome_delta_room_not_open",
                        format!(
                            "room '{r}' is '{}' — deltas admit only into an open room",
                            room.get("status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                        ),
                    ));
                }
                Some(_) => Value::String(r),
            }
        }
    };
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
    let bound_goal = s(&bound_result, "goal_ref", "");
    if bound_goal != goal_ref {
        return Err(verr("outcome_delta_cross_goal", format!("the bound WorkResult belongs to '{bound_goal}', not this delta's '{goal_ref}' — a delta never binds a result from another goal (zero mutation)")));
    }
    // EXACT room equality with the bound result (#71 round-1 directive, live since step 2):
    // both null, or the same outcome-room:// ref — anything else is a cross-room binding.
    let result_room = bound_result
        .get("outcome_room_ref")
        .cloned()
        .unwrap_or(Value::Null);
    if delta_room != result_room {
        return Err(verr("outcome_delta_cross_room", format!("the delta's room ({}) must exactly equal the bound result's room ({}) — a delta never crosses room scope (zero mutation)", if delta_room.is_null() { "null".into() } else { delta_room.to_string() }, if result_room.is_null() { "null".into() } else { result_room.to_string() })));
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
        "goal_ref": goal_ref,
        "outcome_room_ref": delta_room,
        "proposed_by_ref": proposed_by,
        "target_ref": target_ref,
        "delta_kind": delta_kind,
        "payload_ref": scalar_ref(body, "payload_ref", &["artifact", "patch", "mapping", "state-delta"], &[], &[])?,
        "precondition_and_invariant_refs": list_ref(body, "precondition_and_invariant_refs", &["policy", "gate", "state"], &[], &[])?,
        "expected_effect_ref": scalar_ref(body, "expected_effect_ref", &["effect"], &[], &[])?,
        "verifier_and_acceptance_refs": list_ref(body, "verifier_and_acceptance_refs", &["verifier_path", "rubric", "gate"], &[], &[])?,
        "status": "proposed",
        "runtimeTruthSource": "daemon-runtime"
    });
    Ok((record, bound_result))
}

fn sorted_newest(data_dir: &str, dir: &str) -> Vec<Value> {
    let mut items = read_record_dir(data_dir, dir);
    items.sort_by(|a, b| s(b, "created_at", "").cmp(&s(a, "created_at", "")));
    items
}

// ================================ HANDLERS =======================================================

pub(crate) async fn handle_work_results_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(
        json!({ "schema_version": RESULT_SCHEMA, "work_results": sorted_newest(&st.data_dir, RESULT_DIR), "runtimeTruthSource": "daemon-runtime" }),
    )
}

pub(crate) async fn handle_work_result_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_by(
        &st.data_dir,
        RESULT_DIR,
        "work_result_id",
        &format!("work-result://{id}"),
    ) {
        Some(r) => (StatusCode::OK, Json(json!({ "work_result": r }))),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "work_result": id } })),
        ),
    }
}

/// GET /v1/hypervisor/work-results/overview — the DECLARATION VOCABULARY projection (a consuming
/// surface derives its pickers from THIS, never a hardcoded copy) + honest governance gaps.
pub(crate) async fn handle_work_results_overview(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    let results = read_record_dir(&st.data_dir, RESULT_DIR);
    let deltas = read_record_dir(&st.data_dir, DELTA_DIR);
    Json(json!({
        "schema_version": OVERVIEW_SCHEMA,
        "work_results": results.len(),
        "outcome_deltas": deltas.len(),
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
            "outcome_room_ref is LIVE (build step 2): it must resolve to an OPEN hosted room, and a delta's room must exactly equal its bound result's room; the remaining future-plane fields (work_claim_ref, attempt_ref, finding_refs, acceptance_ref, superseded_by_ref) refuse non-empty values with per-field unavailable codes until their owners land; outcome_delta_refs and challenge_refs are plane-owned and registered atomically by their owner seams"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// POST /v1/hypervisor/work-results — admit a generic WorkResult (fail-closed, atomic, receipted).
pub(crate) async fn handle_work_result_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let err400 = |(code, msg): VErr| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": code, "message": msg } })),
        )
    };
    let data_dir = st.data_dir.clone();
    // ROOM-SCOPE critical section (#72 review finding 3): room resolution through finalization
    // holds ROOM_MUTATION_LOCK, so a room cannot close between the check and the persist.
    // Lock ordering: ROOM_MUTATION_LOCK before DELTA_ADMISSION_LOCK, always.
    let _room_scope = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let resolve_result = |tail: &str| {
        load_by(
            &data_dir,
            RESULT_DIR,
            "work_result_id",
            &format!("work-result://{tail}"),
        )
    };
    // The validator owns the typed distinction between missing, pending, and non-open rooms.
    let resolve_room =
        |room_ref: &str| super::outcome_room_routes::resolve_room(&data_dir, room_ref);
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
        obj.insert("created_at".into(), json!(now));
        obj.insert("updated_at".into(), json!(now));
    }
    // Receipt binds the admission-time record (hash computed BEFORE the receipt ref lands on it).
    let (receipt_id, receipt) = build_work_result_receipt(&record, &now);
    record.as_object_mut().expect("object").insert(
        "admission_receipt_ref".into(),
        receipt["receipt_ref"].clone(),
    );
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

pub(crate) async fn handle_outcome_deltas_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(
        json!({ "schema_version": DELTA_SCHEMA, "outcome_deltas": sorted_newest(&st.data_dir, DELTA_DIR), "runtimeTruthSource": "daemon-runtime" }),
    )
}

pub(crate) async fn handle_outcome_delta_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_by(
        &st.data_dir,
        DELTA_DIR,
        "outcome_delta_id",
        &format!("outcome-delta://{id}"),
    ) {
        Some(r) => (StatusCode::OK, Json(json!({ "outcome_delta": r }))),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "outcome_delta": id } })),
        ),
    }
}

/// POST /v1/hypervisor/outcome-deltas — admit a delta bound to an EXISTING SAME-GOAL WorkResult;
/// the result's `outcome_delta_refs` backlink registers in the SAME atomic finalization.
pub(crate) async fn handle_outcome_delta_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let err400 = |(code, msg): VErr| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": code, "message": msg } })),
        )
    };
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
    let resolve = |rid: &str| {
        load_by(
            &data_dir,
            RESULT_DIR,
            "work_result_id",
            &format!("work-result://{rid}"),
        )
    };
    // The validator owns the typed distinction between missing, pending, and non-open rooms.
    let resolve_room =
        |room_ref: &str| super::outcome_room_routes::resolve_room(&data_dir, room_ref);
    let (mut record, prior_result) = match validate_outcome_delta(&body, &resolve, &resolve_room) {
        Ok(r) => r,
        Err(e) => return err400(e),
    };
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
        obj.insert("created_at".into(), json!(now));
        obj.insert("updated_at".into(), json!(now));
    }
    let (receipt_id, receipt) = build_outcome_delta_receipt(&record, &now);
    record.as_object_mut().expect("object").insert(
        "admission_receipt_ref".into(),
        receipt["receipt_ref"].clone(),
    );
    // The plane-owned backlink: prior result + the new delta id, updated in the same atomic seam.
    let result_id_tail = s(&prior_result, "work_result_id", "").replace("work-result://", "");
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
        obj.insert("updated_at".into(), json!(now));
    }
    if let Err((code, msg)) = finalize_delta_persist(
        &st.data_dir,
        &id_tail,
        &record,
        &result_id_tail,
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
                "challenge_refs",
                json!(["verifier-challenge://ghost"]),
                "work_result_challenge_refs_plane_owned",
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
        caller["challenge_refs"] = json!([]);
        assert_eq!(
            validate_work_result(&caller, &no_resolve, &no_room)
                .unwrap_err()
                .0,
            "work_result_challenge_refs_plane_owned"
        );

        let dir = temp_dir("challenge-backlink");
        let data_dir = dir.to_str().unwrap();
        let result_ref = "work-result://wr_challenge";
        let challenge_ref = format!("verifier-challenge://vc_{}", "a".repeat(64));
        let prior = json!({
            "schema_version":RESULT_SCHEMA,
            "work_result_id":result_ref,
            "challenge_refs":[],
            "updated_at":"2026-01-01T00:00:00Z"
        });
        persist_record(data_dir, RESULT_DIR, "wr_challenge", &prior).unwrap();
        let successor = verifier_challenge_backlink_successor(
            &prior,
            result_ref,
            &challenge_ref,
            "2026-01-02T00:00:00Z",
        )
        .unwrap();
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
                .unwrap()["challenge_refs"],
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
    fn room_binding_resolves_open_rooms_and_deltas_never_cross_rooms() {
        // Result side: unresolvable and non-open rooms refuse; an open room binds.
        let mut b = valid_result_body();
        b["outcome_room_ref"] = json!("outcome-room://or_ghost");
        assert_eq!(
            validate_work_result(&b, &no_resolve, &open_room)
                .unwrap_err()
                .0,
            "work_result_room_unbound"
        );
        let mut b = valid_result_body();
        b["outcome_room_ref"] = json!("outcome-room://or_closed");
        assert_eq!(
            validate_work_result(&b, &no_resolve, &open_room)
                .unwrap_err()
                .0,
            "work_result_room_not_open"
        );
        let mut b = valid_result_body();
        b["outcome_room_ref"] = json!("outcome-room://or_open");
        assert_eq!(
            validate_work_result(&b, &no_resolve, &open_room).unwrap()["outcome_room_ref"],
            json!("outcome-room://or_open")
        );
        // Delta side: room EQUALITY with the bound result — same room admits; both-null admits.
        let roomed = json!({ "work_result_id": "work-result://wr_r", "goal_ref": "goal://alpha", "outcome_room_ref": "outcome-room://or_open", "outcome_delta_refs": [] });
        let resolver = |rid: &str| (rid == "wr_r").then(|| roomed.clone());
        let base = json!({ "goal_ref": "goal://alpha", "delta_kind": "update", "target_ref": "frontier://f1", "proposed_by_ref": "work-result://wr_r", "outcome_room_ref": "outcome-room://or_open" });
        let (rec, _) = validate_outcome_delta(&base, &resolver, &open_room).unwrap();
        assert_eq!(rec["outcome_room_ref"], json!("outcome-room://or_open"));
        // A room-less delta against a roomed result is cross-room too.
        let mut b = base.clone();
        b.as_object_mut().unwrap().remove("outcome_room_ref");
        assert_eq!(
            validate_outcome_delta(&b, &resolver, &open_room)
                .unwrap_err()
                .0,
            "outcome_delta_cross_room"
        );
    }

    #[test]
    fn supersedes_requires_resolvable_same_goal_same_room_result() {
        let resolver = |tail: &str| match tail {
            "wr_same" => Some(
                json!({ "work_result_id": "work-result://wr_same", "goal_ref": "goal://g-research-1" }),
            ),
            "wr_other" => Some(
                json!({ "work_result_id": "work-result://wr_other", "goal_ref": "goal://g-other" }),
            ),
            "wr_roomed" => Some(
                json!({ "work_result_id": "work-result://wr_roomed", "goal_ref": "goal://g-research-1", "outcome_room_ref": "outcome-room://or_open" }),
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
            "work_result_supersedes_cross_room"
        );
        // Same-room supersession admits.
        let mut b = valid_result_body();
        b["supersedes_work_result_ref"] = json!("work-result://wr_roomed");
        b["outcome_room_ref"] = json!("outcome-room://or_open");
        assert_eq!(
            validate_work_result(&b, &resolver, &open_room).unwrap()["supersedes_work_result_ref"],
            json!("work-result://wr_roomed")
        );
        // Roomed result superseding a room-less result → cross-room too.
        let mut b = valid_result_body();
        b["supersedes_work_result_ref"] = json!("work-result://wr_same");
        b["outcome_room_ref"] = json!("outcome-room://or_open");
        assert_eq!(
            validate_work_result(&b, &resolver, &open_room)
                .unwrap_err()
                .0,
            "work_result_supersedes_cross_room"
        );
    }

    #[test]
    fn delta_binds_same_goal_result_and_receipts_bind_facts() {
        let bound = json!({ "work_result_id": "work-result://wr_real", "goal_ref": "goal://alpha", "outcome_delta_refs": [] });
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
            "outcome_delta_room_unbound"
        );
        let mut b = base.clone();
        b["outcome_room_ref"] = json!("outcome-room://or_closed");
        assert_eq!(
            validate_outcome_delta(&b, &resolver, &open_room)
                .unwrap_err()
                .0,
            "outcome_delta_room_not_open"
        );
        // The bound result has NO room — a roomed delta is a cross-room binding.
        let mut b = base.clone();
        b["outcome_room_ref"] = json!("outcome-room://or_open");
        assert_eq!(
            validate_outcome_delta(&b, &resolver, &open_room)
                .unwrap_err()
                .0,
            "outcome_delta_cross_room"
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
        full["created_at"] = json!("2026-01-01T00:00:00Z");
        full["updated_at"] = json!("2026-01-01T00:00:00Z");
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
            &json!({ "work_result_id": "work-result://wr_real", "goal_ref": "goal://alpha", "result_profile": "research", "outcome_class": "negative", "status": "completed" }),
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
}
