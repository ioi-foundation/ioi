//! PolicyBoundDataView — the SECOND inert authority-crossing rung. Given a validated ConnectorMapping
//! (#13), a view declares the AUTHORITY ENVELOPE for the would-be ontology-shaped data: which
//! operations are allowed, for which subjects/actors, for what purpose, over which property scope,
//! under which retention/export/training/evaluation/publish postures, and with which receipt
//! obligations. It is a CAPABILITY over semantic data — not a thin ACL table — so a future
//! TransformationRun has a real gate to satisfy instead of inventing authorization at execution time.
//!
//! Declarative/inert like the mapping it binds: a view never executes a run, never reads the source,
//! never mints object rows, and never implies approval. `object_instances` stays 0;
//! `authority.crossed` stays false. Declaring a view authorizes NOTHING to run — it declares what a
//! run would have to prove.
//!
//! Fail-closed at write: known + READY mapping; operations from the enum only; non-empty subject set;
//! wildcard-all authority only on an explicit draft (and then never `ready`); property scope must be
//! a subset of what the mapping actually maps; postures from their enums, and never contradicting an
//! allowed operation; high-risk operations (export/publish/train/evaluate) require named receipt
//! obligations; no credential material.
//!
//! MUTATION DURABILITY (MEF-GAP-008). All three mutations here DISCARDED their writes. Create
//! returned `201` for a record no later read could find. A NARROWING patch returned `ok:true`
//! while every consumer — `materializing_run_routes::check_plan_against_truth` among them — kept
//! resolving the OLD WIDER `allowed_operations` / `property_scope`. The receipt helper minted a
//! `receipt_ref`, embedded it in the record, and then discarded its own write, so a view could
//! cite evidence that resolved to nothing. The legacy writer was `std::fs::write` — open +
//! truncate + write, no temp file, no rename, no fsync — so a failure PART-WAY THROUGH destroyed
//! the prior record instead of leaving it intact, and the shared reader then skipped the torn
//! bytes as if the view had never existed.
//!
//! Records now commit through `durable_fs::persist_record_durable` (temp sibling → file fsync →
//! rename → directory fsync) and revocations through `durable_fs::unlink_durable_at` (unlink →
//! parent-directory fsync). That is the exact crash guarantee obtained and no more: an individual
//! record replacement is atomic and, on `Ok`, durable; a rename that landed but could not be
//! confirmed is reported as VISIBLE-but-unconfirmed rather than as either outcome. It is NOT a
//! transaction — see the read-modify-write nonclaim on `redeclare_policy_view`.
//!
//! ACKNOWLEDGEMENT IS PROJECTED FROM A RELOAD, never from the in-memory candidate, and the reload
//! goes through `load_view` — the same `read_record_dir` path every downstream consumer uses — so
//! what is acknowledged is what the enforcement-time readers will actually resolve. A commit whose
//! reload is absent or disagrees with the candidate is 503, never a success. Checking only that
//! SOME record with this id exists would be insufficient for patch, whose whole point is that the
//! narrowed fields changed.
//!
//! AUDIT ORDERING is record commit → reload → receipt: a receipt may describe only a fact already
//! observed. COMPATIBILITY EFFECT of that ordering, recorded rather than hidden: the new receipt
//! ref is NOT embedded in the durable record, because embedding it would need either a receipt
//! minted before the record is durable (evidence for an unobserved fact) or a SECOND fallible
//! record write (inventing atomicity). So `receipt_refs` no longer grows on create/patch and the
//! new history entry carries no `receipt_ref`; prior `receipt_refs`/`history` data is preserved
//! verbatim. The receipt is returned in the response and stays discoverable through the existing
//! history join — `GET /:id/history` retains receipts on `policy_view_ref`.
//!
//! NOT CLOSED HERE, and never to be read as closed. No handler resolves a principal, so authority
//! over create/patch/delete is an implementation gap, not permission. Ids stay `nanos()`-derived:
//! there is no idempotency key and a retry still mints a second view. There is no expected-absent
//! genesis and no compare-and-swap. `odk-policy-bound-data-views` is in neither `PROMOTED_DOMAINS`
//! nor `REQUIRED_ADMISSION_DOMAINS`, and the `agentgres://` prefix on a receipt ref is a string
//! literal naming no admitted object. A MALFORMED view record is still indistinguishable from an
//! absent one at the read surface, because the shared reader that skips it is not writable here.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::durable_fs::{
    persist_receipt_no_clobber, persist_record_durable, unlink_durable_at, CommitFailure,
    PersistFailure, UnlinkOutcome,
};
use super::{iso_now, read_record_dir, DaemonState};

const VIEW_SCHEMA: &str = "ioi.hypervisor.odk.policy-bound-data-view.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.odk.policy-bound-data-view-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.odk.policy-bound-data-views-overview.v1";
pub(crate) const RECORD_DIR: &str = "odk-policy-bound-data-views";
const RECEIPT_DIR: &str = "odk-policy-bound-data-view-receipts";
/// Why the durable record carries no receipt ref of its own — see the module header.
const RECEIPT_BINDING_NOTE: &str = "unembedded — a receipt is minted only AFTER this record is durable and has reloaded, so it is never embedded here; join odk-policy-bound-data-view-receipts on policy_view_ref (GET /:id/history) to find it";

/// The operations an autonomous system could be authorized to perform over the mapped data.
const ALLOWED_OPERATIONS: &[&str] = &[
    "read",
    "transform",
    "distill",
    "train",
    "evaluate",
    "export",
    "publish",
    "route",
];
/// Operations whose authorization ALWAYS requires a named receipt obligation.
const HIGH_RISK_OPERATIONS: &[&str] = &["export", "publish", "train", "evaluate"];
/// Wildcard subject spellings — authority-for-everyone is only ever a draft, never ready.
const WILDCARD_SUBJECTS: &[&str] = &["*", "all", "everyone", "any"];
/// Posture enums. A posture that contradicts an allowed operation is a fail-closed conflict.
const RETENTION_POSTURES: &[&str] = &["ephemeral", "bounded", "durable"];
const EXPORT_POSTURES: &[&str] = &["no_export", "receipted_export_only"];
const TRAINING_POSTURES: &[&str] = &["no_training", "receipted_training_only"];
const EVALUATION_POSTURES: &[&str] = &["no_evaluation", "receipted_evaluation_only"];
const PUBLISH_ROUTE_POSTURES: &[&str] = &["no_publish_route", "receipted_publish_route_only"];
/// The contracts still missing downstream of this rung.
const MISSING_CONTRACTS: &[&str] = &["TransformationRun", "OntologyProjection"];
/// Body keys that would be a plaintext secret — rejected outright.
const PLAINTEXT_SECRET_KEYS: &[&str] = &[
    "secret",
    "password",
    "api_key",
    "apikey",
    "token",
    "credential",
];

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}
fn opt_s(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
}
fn str_list(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
type VErr = (String, String);
fn verr(code: &str, msg: String) -> VErr {
    (code.to_string(), msg)
}

fn is_wildcard(subject: &str) -> bool {
    WILDCARD_SUBJECTS.contains(&subject.to_lowercase().as_str())
}
/// Which posture field (and its enum + "forbidden" value) governs an operation, if any.
fn posture_for_operation(
    op: &str,
) -> Option<(&'static str, &'static [&'static str], &'static str)> {
    match op {
        "export" => Some(("export_posture", EXPORT_POSTURES, "no_export")),
        "train" => Some(("training_posture", TRAINING_POSTURES, "no_training")),
        "evaluate" => Some(("evaluation_posture", EVALUATION_POSTURES, "no_evaluation")),
        "publish" | "route" => Some((
            "publish_route_posture",
            PUBLISH_ROUTE_POSTURES,
            "no_publish_route",
        )),
        _ => None,
    }
}

fn load_mapping(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, crate::connector_mapping_routes::RECORD_DIR)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
}
/// Every property the mapping actually maps (key + title + fields) — the widest scope a view may claim.
fn mapped_property_ids(mapping: &Value) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for k in ["key_mapping", "title_mapping"] {
        if let Some(pid) = mapping
            .get(k)
            .and_then(|m| m.get("property_id"))
            .and_then(|v| v.as_str())
        {
            ids.push(pid.to_string());
        }
    }
    if let Some(fs) = mapping.get("field_mappings").and_then(|v| v.as_array()) {
        for f in fs {
            if let Some(pid) = f.get("property_id").and_then(|v| v.as_str()) {
                ids.push(pid.to_string());
            }
        }
    }
    ids
}

/// Validate a view body fail-closed and project the declared record fields + honest health.
/// INERT: nothing is authorized to run; this only validates the declared envelope.
fn validate_and_project(data_dir: &str, body: &Value) -> Result<Value, VErr> {
    if let Some(obj) = body.as_object() {
        if PLAINTEXT_SECRET_KEYS
            .iter()
            .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
        {
            return Err(verr(
                "policy_view_plaintext_secret_rejected",
                "A policy-bound data view never carries credentials.".into(),
            ));
        }
    }
    if opt_s(body, "name").is_none() {
        return Err(verr(
            "policy_view_name_required",
            "A policy-bound data view requires a name.".into(),
        ));
    }
    // Known + READY mapping — a view binds validated shape, never a half-declared one.
    let mapping_id = opt_s(body, "connector_mapping_id").unwrap_or_default();
    let mapping = load_mapping(data_dir, &mapping_id).ok_or_else(|| {
        verr(
            "policy_view_mapping_unknown",
            format!("connector_mapping_id '{mapping_id}' does not resolve to a declared mapping"),
        )
    })?;
    let mapping_health = mapping
        .pointer("/health/status")
        .and_then(|v| v.as_str())
        .unwrap_or("incomplete");
    if mapping_health != "ready" {
        return Err(verr(
            "policy_view_mapping_not_ready",
            format!("mapping '{mapping_id}' health is '{mapping_health}' — a view binds only a ready mapping"),
        ));
    }

    // Allowed operations: enum only, at least one.
    let operations = str_list(body, "allowed_operations");
    if operations.is_empty() {
        return Err(verr(
            "policy_view_operations_required",
            "At least one allowed operation is required.".into(),
        ));
    }
    for op in &operations {
        if !ALLOWED_OPERATIONS.contains(&op.as_str()) {
            return Err(verr(
                "policy_view_operation_invalid",
                format!("operation '{op}' is not a known operation"),
            ));
        }
    }

    // Authority subjects: non-empty; wildcard-all only on an explicit draft.
    let subjects = str_list(body, "authority_subjects");
    if subjects.is_empty() {
        return Err(verr(
            "policy_view_subjects_required",
            "A non-empty authority subject set is required.".into(),
        ));
    }
    let is_draft = body.get("draft").and_then(|v| v.as_bool()).unwrap_or(false);
    let has_wildcard = subjects.iter().any(|x| is_wildcard(x));
    if has_wildcard && !is_draft {
        return Err(verr(
            "policy_view_wildcard_authority_rejected",
            "Wildcard-all authority is never granted implicitly — mark the view draft:true to hold it as an incomplete draft.".into(),
        ));
    }

    // Property scope must be a subset of what the mapping actually maps.
    let mapped = mapped_property_ids(&mapping);
    let property_scope = str_list(body, "property_scope");
    for pid in &property_scope {
        if !mapped.iter().any(|m| m == pid) {
            return Err(verr(
                "policy_view_property_unscoped",
                format!("property '{pid}' is not mapped by the bound connector mapping — a view cannot authorize unmapped data"),
            ));
        }
    }

    // Postures: enum-valid, and never contradicting an allowed operation.
    let posture = |key: &str, allowed: &[&str], default: &str| -> Result<String, VErr> {
        let val = opt_s(body, key).unwrap_or_else(|| default.to_string());
        if !allowed.contains(&val.as_str()) {
            return Err(verr(
                "policy_view_posture_invalid",
                format!("{key} '{val}' must be one of {allowed:?}"),
            ));
        }
        Ok(val)
    };
    let retention_posture = opt_s(body, "retention_posture");
    if let Some(rp) = &retention_posture {
        if !RETENTION_POSTURES.contains(&rp.as_str()) {
            return Err(verr(
                "policy_view_posture_invalid",
                format!("retention_posture '{rp}' must be one of {RETENTION_POSTURES:?}"),
            ));
        }
    }
    let export_posture = posture("export_posture", EXPORT_POSTURES, "no_export")?;
    let training_posture = posture("training_posture", TRAINING_POSTURES, "no_training")?;
    let evaluation_posture = posture("evaluation_posture", EVALUATION_POSTURES, "no_evaluation")?;
    let publish_route_posture = posture(
        "publish_route_posture",
        PUBLISH_ROUTE_POSTURES,
        "no_publish_route",
    )?;
    let posture_value = |key: &str| -> &str {
        match key {
            "export_posture" => &export_posture,
            "training_posture" => &training_posture,
            "evaluation_posture" => &evaluation_posture,
            _ => &publish_route_posture,
        }
    };
    for op in &operations {
        if let Some((key, _, forbidden)) = posture_for_operation(op) {
            if posture_value(key) == forbidden {
                return Err(verr(
                    "policy_view_posture_conflict",
                    format!("operation '{op}' is allowed but {key} declares '{forbidden}' — the capability contradicts its own posture"),
                ));
            }
        }
    }

    // High-risk operations require a NAMED receipt obligation (an obligation string naming the op).
    let receipt_obligations = str_list(body, "receipt_obligations");
    for op in &operations {
        if HIGH_RISK_OPERATIONS.contains(&op.as_str())
            && !receipt_obligations
                .iter()
                .any(|o| o.to_lowercase().contains(op.as_str()))
        {
            return Err(verr(
                "policy_view_receipt_obligation_required",
                format!("operation '{op}' is high-risk and requires a named receipt obligation (e.g. \"{op}: receipt per batch\")"),
            ));
        }
    }

    // Honest readiness — ready ONLY when the envelope is complete: purpose, retention, scoped
    // properties, no wildcard. (Subjects/operations/obligations were enforced at write.)
    let purpose = s(body, "purpose", "");
    let mut gaps: Vec<String> = Vec::new();
    if purpose.trim().is_empty() {
        gaps.push("no purpose declared — a capability without a purpose is not grantable".into());
    }
    if retention_posture.is_none() {
        gaps.push("no retention posture declared".into());
    }
    if property_scope.is_empty() {
        gaps.push("no property scope declared — scope the view to mapped properties".into());
    }
    if has_wildcard {
        gaps.push(
            "wildcard-all authority — narrow the subject set before this view can be ready".into(),
        );
    }
    let status = if gaps.is_empty() {
        "ready"
    } else {
        "incomplete"
    };
    let (n_subjects, n_operations, n_scope) =
        (subjects.len(), operations.len(), property_scope.len());

    Ok(json!({
        "connector_mapping_id": mapping_id,
        "connector_mapping_ref": mapping.get("ref").cloned().unwrap_or(Value::Null),
        "ontology_ref": mapping.get("ontology_ref").cloned().unwrap_or(Value::Null),
        "object_type_id": mapping.get("object_type_id").cloned().unwrap_or(Value::Null),
        "allowed_operations": operations,
        "authority_subjects": subjects,
        "purpose": purpose,
        "property_scope": property_scope,
        "object_scope": body.get("object_scope").cloned().unwrap_or(Value::Null),
        "retention_posture": retention_posture,
        "export_posture": export_posture,
        "training_posture": training_posture,
        "evaluation_posture": evaluation_posture,
        "publish_route_posture": publish_route_posture,
        "receipt_obligations": receipt_obligations,
        "health": {
            "status": status,
            "gaps": gaps,
            "authorized_subjects": n_subjects,
            "allowed_operations": n_operations,
            "scoped_properties": n_scope,
            "object_instances": 0,
            "missing_contracts": MISSING_CONTRACTS,
            "note": "declarative gate only — nothing is authorized to RUN; a future TransformationRun must satisfy this view before any execution"
        },
        "authority": { "crossed": false, "note": "declaring a view implies no approval and executes nothing" }
    }))
}

fn load_view(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, RECORD_DIR)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
}
fn bad(err: VErr) -> (StatusCode, Value) {
    (
        StatusCode::BAD_REQUEST,
        json!({ "ok": false, "error": { "code": err.0, "message": err.1 } }),
    )
}

// ══════════════════════════ MUTATION DURABILITY PROTOCOL ═════════════════════════════════════
//
// Extracted OUT of the Axum adapters so every lane below is reachable from a deterministic,
// process-local fault without an HTTP client or a daemon. `DaemonState` never appears here.

/// Stable refusal codes. None collides with the twelve shipped `policy_view_*` validation codes.
const PERSISTENCE_FAILED: &str = "policy_view_persistence_failed";
const DURABILITY_UNCONFIRMED: &str = "policy_view_durability_unconfirmed";
const STATE_AMBIGUOUS: &str = "policy_view_state_ambiguous";
const REVOCATION_UNCONFIRMED: &str = "policy_view_revocation_unconfirmed";
/// Carried on a SUCCESS body only: the mutation is durable, its audit record is not.
const AUDIT_RECEIPT_NOT_DURABLE: &str = "policy_view_audit_receipt_not_durable";

/// What a refusal may truthfully say about the state it leaves behind. The consequence sentence is
/// GENERATED per lane rather than spliced onto a fixed tail, so a create refusal can never inherit
/// a "the prior view stands" clause and a patch refusal can never inherit "nothing was declared".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Continuity {
    /// Create: no view existed under this id before the request, and none exists now.
    NothingDeclared,
    /// Patch: the prior declaration is still exactly what every reader resolves.
    PriorViewStands,
}

/// What a record commit PLUS its reload established about DURABLE truth.
///
/// `Committed` is the only variant that licenses a success response, and it requires the reloaded
/// projection to equal the candidate — not merely to exist under the same id, which a patch that
/// silently kept the wider scope would also satisfy.
#[derive(Debug, PartialEq, Eq)]
enum Acknowledgement {
    Committed,
    /// Nothing committed, AND the durable state is provably still what this request read.
    NotCommitted(String),
    /// The rename landed and the record is VISIBLE; only its durability is unconfirmed.
    DurabilityUnconfirmed(String),
    /// The durable state matches neither the candidate nor what this request read.
    Ambiguous(String),
}

/// PURE classification — no filesystem access — so the lanes with no uid-independent injection on
/// this unpromoted daemon-file family are asserted from constructed variants instead of reviewed.
///
/// `NotCommitted` from the writer proves only that THIS candidate did not commit; it does not
/// prove continuity. Continuity is proven separately, by re-reading and comparing against `prior`
/// (`None` for a genesis create, which expects the id to resolve to nothing). Without that check
/// the 500's "the prior view stands" clause would be a guess.
fn classify_commit(
    outcome: Result<(), PersistFailure>,
    prior: Option<&Value>,
    candidate: &Value,
    reloaded: Option<&Value>,
) -> Acknowledgement {
    match outcome {
        Ok(()) if reloaded == Some(candidate) => Acknowledgement::Committed,
        Ok(()) => Acknowledgement::Ambiguous(match reloaded {
            None => "the record commit reported success but the view does not read back at all"
                .to_string(),
            Some(_) => "the record commit reported success but the durable record disagrees with the candidate this request would have acknowledged".to_string(),
        }),
        Err(failure @ PersistFailure::RenamedDurabilityUnconfirmed(_)) => {
            Acknowledgement::DurabilityUnconfirmed(failure.detail())
        }
        Err(failure) if reloaded == prior => Acknowledgement::NotCommitted(failure.detail()),
        Err(failure) => Acknowledgement::Ambiguous(format!(
            "{} — and the durable state no longer matches what this request read, so continuity cannot be claimed either",
            failure.detail()
        )),
    }
}

fn refusal(status: StatusCode, code: &str, message: String) -> (StatusCode, Value) {
    (
        status,
        json!({ "ok": false, "error": { "code": code, "message": message } }),
    )
}

/// Map an acknowledgement onto the wire. `None` means the mutation may proceed to its audit.
fn commit_refusal(
    ack: &Acknowledgement,
    continuity: Continuity,
    id: &str,
) -> Option<(StatusCode, Value)> {
    let stands = match continuity {
        Continuity::NothingDeclared => format!(
            "No policy-bound data view was declared: '{id}' resolves to nothing and no receipt was minted."
        ),
        Continuity::PriorViewStands => format!(
            "Nothing was applied: the prior declaration of '{id}' is still exactly what every reader resolves, so any narrowing in this request is NOT in effect."
        ),
    };
    match ack {
        Acknowledgement::Committed => None,
        Acknowledgement::NotCommitted(detail) => Some(refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            PERSISTENCE_FAILED,
            format!("The record could not be committed ({detail}). {stands} Retry the request."),
        )),
        Acknowledgement::DurabilityUnconfirmed(detail) => Some(refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            DURABILITY_UNCONFIRMED,
            format!("{detail}. This request therefore claims NEITHER that the change was applied NOR that '{id}' is unchanged. Re-read '{id}' and reconcile before retrying."),
        )),
        Acknowledgement::Ambiguous(detail) => Some(refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            STATE_AMBIGUOUS,
            format!("{detail}. The in-memory candidate is NOT returned as active. Re-read '{id}' and reconcile before retrying."),
        )),
    }
}

/// The audit receipt's own durability — a fact ABOUT the receipt, never authority of any kind.
#[derive(Debug)]
enum AuditOutcome {
    /// The receipt is durably committed; this ref resolves.
    Durable(String),
    /// No receipt landed. NO ref is produced, so none can be returned or persisted.
    Gap(String),
}

fn commit_failure_detail(failure: &CommitFailure) -> String {
    match failure {
        CommitFailure::KeyInvalid(detail)
        | CommitFailure::NotCommitted(detail)
        | CommitFailure::SlotUnreadable(detail)
        | CommitFailure::Conflict(detail)
        | CommitFailure::DurabilityUnconfirmed(detail)
        | CommitFailure::Swapped(detail) => detail.clone(),
    }
}

/// Mint and DURABLY commit one audit receipt. Called only AFTER the fact it describes has been
/// observed in a reload, so `outcome: "ok"` is never written over an unobserved mutation.
///
/// `persist_receipt_no_clobber` is the append-only committer: an occupied slot holding different
/// evidence refuses rather than overwriting, and a visible-but-unconfirmed commit is a gap, not a
/// success. The `agentgres://` prefix is a NAMING CONVENTION carried forward verbatim from the
/// shipped record; it names no admitted object and this packet does not make it one.
fn commit_view_receipt(data_dir: &str, view_ref: &str, op: &str, summary: &str) -> AuditOutcome {
    let id = format!("pbdvr_{:x}", nanos());
    let receipt_ref = format!("agentgres://policy-bound-data-view-receipt/{id}");
    let rec = json!({
        "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
        "policy_view_ref": view_ref, "op": op, "outcome": "ok", "summary": summary, "at": iso_now()
    });
    match persist_receipt_no_clobber(data_dir, RECEIPT_DIR, &id, &rec) {
        Ok(()) => AuditOutcome::Durable(receipt_ref),
        Err(failure) => AuditOutcome::Gap(commit_failure_detail(&failure)),
    }
}

/// Attach the audit posture to a SUCCESS body. A gap never downgrades the mutation to a failure —
/// the mutation is already durable and cannot be un-done — and never yields a `receipt_ref` key.
fn with_audit(mut body: Value, audit: AuditOutcome) -> Value {
    match audit {
        AuditOutcome::Durable(receipt_ref) => {
            body["audit_durable"] = json!(true);
            body["receipt_ref"] = json!(receipt_ref);
        }
        AuditOutcome::Gap(detail) => {
            body["audit_durable"] = json!(false);
            body["audit_gap"] = json!({
                "code": AUDIT_RECEIPT_NOT_DURABLE,
                "message": format!("This mutation IS in effect and is durable. Its audit receipt did NOT commit ({detail}), so no receipt reference is returned or persisted and this act is unevidenced in the receipt store.")
            });
        }
    }
    body
}

/// Open the record family as a walk root, FOLLOWING a symlinked family directory exactly as the
/// production readers do. `durable_fs::open_family_dir_pinned` adds `O_NOFOLLOW`, which would deny
/// every deletion in any deployment that relocates a record family behind a symlink while
/// `read_record_dir` and `load_view` followed it happily. Containment where it matters is retained:
/// `unlink_durable_at` is `unlinkat(dirfd, name, 0)`, which removes the entry itself and never
/// follows it to a target, and the acknowledgement is decided by the reloaded absence regardless.
fn open_record_family(data_dir: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(std::path::Path::new(data_dir).join(RECORD_DIR))
}

/// The typed disposition of the record-slot unlink. `RemovedDurable` and `AlreadyAbsent` are kept
/// DISTINCT because only the first is causal: folding them is how a response comes to claim a
/// revocation this request did not perform.
#[derive(Debug, PartialEq, Eq)]
enum SlotUnlink {
    RemovedDurable,
    AlreadyAbsent,
    DurabilityUnconfirmed(String),
    NotPerformed(String),
}

fn classify_unlink(outcome: std::io::Result<UnlinkOutcome>) -> SlotUnlink {
    match outcome {
        Ok(UnlinkOutcome::Durable) => SlotUnlink::RemovedDurable,
        Ok(UnlinkOutcome::Absent) => SlotUnlink::AlreadyAbsent,
        Ok(UnlinkOutcome::RemovedDurabilityUnconfirmed(error)) => SlotUnlink::DurabilityUnconfirmed(
            format!("the record slot is absent from the live namespace but the directory fsync did not confirm it ({error})"),
        ),
        Ok(UnlinkOutcome::ReplayAnchorRestoredAfterUnconfirmedRemoval(error)) => {
            SlotUnlink::DurabilityUnconfirmed(format!(
                "the removal was unconfirmed and a byte-exact record was durably restored in its place ({error})"
            ))
        }
        Err(error) => SlotUnlink::NotPerformed(format!("the record slot was not unlinked ({error})")),
    }
}

/// GET /v1/hypervisor/odk/policy-bound-data-views — declared views (newest first).
pub(crate) async fn handle_policy_views_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, RECORD_DIR);
    items.sort_by(|a, b| s(b, "updated_at", "").cmp(&s(a, "updated_at", "")));
    Json(
        json!({ "ok": true, "schema_version": VIEW_SCHEMA, "policy_bound_data_views": items, "runtimeTruthSource": "daemon-runtime" }),
    )
}

/// GET /v1/hypervisor/odk/policy-bound-data-views/overview — vocab + counts + honest gaps.
pub(crate) async fn handle_policy_views_overview(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    let items = read_record_dir(&st.data_dir, RECORD_DIR);
    let by_status = |status: &str| {
        items
            .iter()
            .filter(|r| r.pointer("/health/status").and_then(|v| v.as_str()) == Some(status))
            .count()
    };
    Json(json!({
        "ok": true,
        "schema_version": OVERVIEW_SCHEMA,
        "policy_bound_data_views": items.len(),
        "health": { "ready": by_status("ready"), "incomplete": by_status("incomplete") },
        "allowed_operations": ALLOWED_OPERATIONS,
        "high_risk_operations": HIGH_RISK_OPERATIONS,
        "postures": {
            "retention": RETENTION_POSTURES,
            "export": EXPORT_POSTURES,
            "training": TRAINING_POSTURES,
            "evaluation": EVALUATION_POSTURES,
            "publish_route": PUBLISH_ROUTE_POSTURES
        },
        "missing_contracts": MISSING_CONTRACTS,
        "governance_gaps": [
            "DECLARATIVE gate only — a view authorizes nothing to run; it declares what a run would have to prove",
            "execution is a NAMED GAP: a future TransformationRun must satisfy a ready view before anything executes",
            "no object plane exists — object_instances is 0 until an OntologyProjection is built",
            "wildcard-all authority is never granted implicitly; high-risk operations always carry named receipt obligations"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// GET /v1/hypervisor/odk/policy-bound-data-views/:id.
pub(crate) async fn handle_policy_view_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_view(&st.data_dir, &id) {
        Some(r) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "policy_bound_data_view": r })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "policy-bound data view not found" })),
        ),
    }
}

/// GET /v1/hypervisor/odk/policy-bound-data-views/:id/health.
pub(crate) async fn handle_policy_view_health(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_view(&st.data_dir, &id) {
        Some(r) => (
            StatusCode::OK,
            Json(
                json!({ "ok": true, "policy_view_ref": r.get("ref"), "revision": r.get("revision"), "health": r.get("health") }),
            ),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "policy-bound data view not found" })),
        ),
    }
}

/// GET /v1/hypervisor/odk/policy-bound-data-views/:id/history — embedded history + receipts.
pub(crate) async fn handle_policy_view_history(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(r) = load_view(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "policy-bound data view not found" })),
        );
    };
    let vref = r
        .get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut receipts = read_record_dir(&st.data_dir, RECEIPT_DIR);
    receipts.retain(|x| x.get("policy_view_ref").and_then(|v| v.as_str()) == Some(vref.as_str()));
    receipts.sort_by(|a, b| s(b, "at", "").cmp(&s(a, "at", "")));
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "policy_view_ref": vref, "revision": r.get("revision"), "history": r.get("history").cloned().unwrap_or(json!([])), "receipts": receipts }),
        ),
    )
}

/// Declare a view: validate fail-closed, commit the record DURABLY, acknowledge from the reloaded
/// projection, and only then mint the audit receipt.
///
/// The identity stays `nanos()`-derived, unchanged and deliberately not fixed here: there is no
/// idempotency key on this plane, so an identical retry still mints a SECOND view. That is a named
/// residual, not something this packet closes.
pub(crate) fn declare_policy_view(data_dir: &str, body: &Value) -> (StatusCode, Value) {
    let projected = match validate_and_project(data_dir, body) {
        Ok(p) => p,
        Err(e) => return bad(e),
    };
    let id = format!("pbdv_{:x}", nanos());
    let now = iso_now();
    let vref = format!("policy-bound-data-view://{id}");
    let is_draft = body.get("draft").and_then(|v| v.as_bool()).unwrap_or(false);
    // `receipt_refs` starts EMPTY and the history entry carries no `receipt_ref`: the receipt for
    // this act cannot exist yet, and embedding a ref before its receipt is durable is exactly the
    // dangling-evidence defect this packet removes. See the module header for the join that
    // replaces it.
    let mut record = json!({
        "schema_version": VIEW_SCHEMA,
        "object": "ioi.hypervisor.odk.policy_bound_data_view",
        "id": id,
        "ref": vref,
        "name": s(body, "name", "policy-bound-data-view"),
        "description": s(body, "description", ""),
        "status": if is_draft { "draft" } else { "declared" },
        "revision": 1,
        "receipt_refs": [],
        "receipt_binding": RECEIPT_BINDING_NOTE,
        "history": [ { "revision": 1, "op": "created", "at": now.clone(), "summary": "PolicyBoundDataView declared" } ],
        "created_at": now.clone(),
        "updated_at": now
    });
    if let (Some(obj), Some(proj)) = (record.as_object_mut(), projected.as_object()) {
        for (k, v) in proj {
            obj.insert(k.clone(), v.clone());
        }
    }
    let outcome = persist_record_durable(data_dir, RECORD_DIR, &id, &record);
    let reloaded = load_view(data_dir, &id);
    let ack = classify_commit(outcome, None, &record, reloaded.as_ref());
    if let Some(response) = commit_refusal(&ack, Continuity::NothingDeclared, &id) {
        return response;
    }
    let durable = reloaded.expect("a committed acknowledgement carries its reloaded projection");
    let audit = commit_view_receipt(data_dir, &vref, "created", "PolicyBoundDataView declared");
    (
        StatusCode::CREATED,
        with_audit(
            json!({ "ok": true, "policy_bound_data_view": durable }),
            audit,
        ),
    )
}

/// POST /v1/hypervisor/odk/policy-bound-data-views — declare a view (fail-closed, receipted, INERT).
pub(crate) async fn handle_policy_view_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let (status, payload) = declare_policy_view(&st.data_dir, &body);
    (status, Json(payload))
}

/// Re-declare a view: re-validate the merged envelope, commit DURABLY, and acknowledge only what
/// reloads. A narrowing that does not commit must never be reported applied — every consumer
/// re-reads this record at the moment it acts, so a lost narrowing keeps the OLD WIDER scope
/// authorizing work the operator believes is no longer authorized.
///
/// NOT A TRANSACTION. This is still a read-modify-write with no compare-and-swap: two concurrent
/// patches both derive `revision` from their own stale read and one update is silently lost.
/// `persist_record_durable` makes each individual write atomic and durable; it does not serialize
/// them. Named residual, unchanged by this packet.
pub(crate) fn redeclare_policy_view(
    data_dir: &str,
    id: &str,
    patch: &Value,
) -> (StatusCode, Value) {
    let Some(existing) = load_view(data_dir, id) else {
        // PRESERVED VERBATIM, body and status. This packet changes the durability contract, not
        // the not-found contract; the extracted signature had to name a status, and naming OK
        // keeps the shipped wire response byte-for-byte rather than silently broadening it to 404.
        return (
            StatusCode::OK,
            json!({ "ok": false, "reason": "policy-bound data view not found" }),
        );
    };
    let mut merged = json!({});
    let mo = merged.as_object_mut().unwrap();
    for k in [
        "name",
        "description",
        "connector_mapping_id",
        "allowed_operations",
        "authority_subjects",
        "purpose",
        "property_scope",
        "object_scope",
        "retention_posture",
        "export_posture",
        "training_posture",
        "evaluation_posture",
        "publish_route_posture",
        "receipt_obligations",
        "draft",
    ] {
        if let Some(v) = patch.get(k).or_else(|| existing.get(k)) {
            mo.insert(k.to_string(), v.clone());
        }
    }
    // `draft` is not persisted verbatim on the record — reconstruct it from status when not patched.
    if patch.get("draft").is_none()
        && existing.get("status").and_then(|v| v.as_str()) == Some("draft")
    {
        mo.insert("draft".into(), json!(true));
    }
    let projected = match validate_and_project(data_dir, &merged) {
        Ok(p) => p,
        // PRESERVED VERBATIM, body and status: a malformed patch still answers 200 with the shipped
        // nested error envelope and changes nothing. Broadening it to 400 is a wire change this
        // durability packet has no mandate to make.
        Err(e) => {
            return (
                StatusCode::OK,
                json!({ "ok": false, "error": { "code": e.0, "message": e.1 } }),
            )
        }
    };
    let mut record = existing.clone();
    if let Some(v) = patch.get("name") {
        record["name"] = v.clone();
    }
    if let Some(v) = patch.get("description") {
        record["description"] = v.clone();
    }
    if let Some(v) = patch.get("draft").and_then(|v| v.as_bool()) {
        record["status"] = json!(if v { "draft" } else { "declared" });
    }
    if let (Some(obj), Some(proj)) = (record.as_object_mut(), projected.as_object()) {
        for (k, v) in proj {
            obj.insert(k.clone(), v.clone());
        }
    }
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1) + 1;
    record["revision"] = json!(rev);
    let now = iso_now();
    record["updated_at"] = json!(now.clone());
    let vref = record
        .get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut hist = record
        .get("history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    // No `receipt_ref` on the new entry, and PRIOR `receipt_refs` / `history` are carried through
    // untouched: the receipt for THIS act cannot be minted until this record is durable.
    hist.push(json!({ "revision": rev, "op": "patched", "at": now, "summary": "PolicyBoundDataView re-declared" }));
    let len = hist.len();
    if len > 20 {
        hist = hist[len - 20..].to_vec();
    }
    record["history"] = json!(hist);
    record["receipt_binding"] = json!(RECEIPT_BINDING_NOTE);
    let outcome = persist_record_durable(data_dir, RECORD_DIR, id, &record);
    let reloaded = load_view(data_dir, id);
    let ack = classify_commit(outcome, Some(&existing), &record, reloaded.as_ref());
    if let Some(response) = commit_refusal(&ack, Continuity::PriorViewStands, id) {
        return response;
    }
    let durable = reloaded.expect("a committed acknowledgement carries its reloaded projection");
    let audit = commit_view_receipt(
        data_dir,
        &vref,
        "patched",
        "PolicyBoundDataView re-declared",
    );
    (
        StatusCode::OK,
        with_audit(
            json!({ "ok": true, "policy_bound_data_view": durable }),
            audit,
        ),
    )
}

/// PATCH — re-validate the merged view; a malformed patch changes nothing (no revision bump).
pub(crate) async fn handle_policy_view_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(patch): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let (status, payload) = redeclare_policy_view(&st.data_dir, &id, &patch);
    (status, Json(payload))
}

/// Destroy a view: durable unlink (slot AND containing directory), verified absence through the
/// reader every consumer uses, and only then the audit receipt.
///
/// The shipped path called `remove_record`, which is `fs::remove_file(..).is_ok()` with no parent
/// fsync. "The name is gone from the live namespace" and "the removal is on disk" are different
/// facts, and a REVOCATION acknowledgement may only be made on the second: an unsynced unlink can
/// be undone by a crash, resurrecting a declared capability the operator revoked.
pub(crate) fn destroy_policy_view(data_dir: &str, id: &str) -> (StatusCode, Value) {
    let Some(existing) = load_view(data_dir, id) else {
        // PRESERVED VERBATIM — the shipped absent-view body, byte for byte.
        return (
            StatusCode::OK,
            json!({ "ok": false, "removed": false, "id": id }),
        );
    };
    let vref = existing
        .get("ref")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("policy-bound-data-view://{id}"));
    // The SAME name the durable writer commits to. `persist_record_durable` REFUSES an id outside
    // [A-Za-z0-9_-] rather than normalizing it, so writer and deleter agree on exactly one file; a
    // record that is loadable but does not live at that name is never unlinked on a guess — it is
    // caught by the reloaded-presence gate below and refused.
    let target = format!("{id}.json");
    let disposition = match open_record_family(data_dir) {
        Ok(family) => classify_unlink(unlink_durable_at(&family, &target, RECORD_DIR)),
        // ONLY ENOENT is absence: no family directory means no record slot to unlink. The gate
        // below still has to prove the view no longer resolves before anything is acknowledged.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => SlotUnlink::AlreadyAbsent,
        Err(error) => SlotUnlink::NotPerformed(format!(
            "the record family could not be opened as a directory ({error})"
        )),
    };
    let caused_here = match &disposition {
        SlotUnlink::RemovedDurable => true,
        SlotUnlink::AlreadyAbsent => false,
        SlotUnlink::DurabilityUnconfirmed(detail) | SlotUnlink::NotPerformed(detail) => {
            return refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                REVOCATION_UNCONFIRMED,
                format!("The revocation of '{id}' is NOT acknowledged: {detail}. No deletion is claimed and no receipt was minted. Re-read '{id}' and retry."),
            )
        }
    };
    // Acknowledge from the RELOADED absence, never from the unlink outcome.
    if load_view(data_dir, id).is_some() {
        return refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            REVOCATION_UNCONFIRMED,
            format!("The removal reported done, but '{id}' STILL resolves as a policy-bound data view — the revocation is NOT acknowledged and no receipt was minted. This happens when the record does not live at the filename the durable writer commits to. Retry, or repair the record's slot out of band."),
        );
    }
    let audit = commit_view_receipt(
        data_dir,
        &vref,
        "deleted",
        "PolicyBoundDataView removed (declared capability revoked)",
    );
    (
        StatusCode::OK,
        with_audit(
            json!({
                "ok": true,
                "removed": caused_here,
                "id": id,
                // Distinct on purpose: only `removed_durable` supports the claim that THIS request
                // revoked the capability. `already_absent` means the slot was gone when this
                // request attempted its unlink, so the absence is confirmed but not caused here.
                "record_slot": if caused_here { "removed_durable" } else { "already_absent" },
            }),
            audit,
        ),
    )
}

/// DELETE — receipted removal (revoking a declared capability is itself an auditable act).
pub(crate) async fn handle_policy_view_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let (status, payload) = destroy_policy_view(&st.data_dir, &id);
    (status, Json(payload))
}

#[cfg(test)]
mod policy_bound_data_view_tests {
    use super::*;

    #[test]
    fn operation_enum_and_high_risk_are_named() {
        assert!(ALLOWED_OPERATIONS.contains(&"distill"));
        assert!(ALLOWED_OPERATIONS.contains(&"route"));
        assert!(!ALLOWED_OPERATIONS.contains(&"delete"));
        assert_eq!(
            HIGH_RISK_OPERATIONS,
            &["export", "publish", "train", "evaluate"]
        );
        assert_eq!(
            MISSING_CONTRACTS,
            &["TransformationRun", "OntologyProjection"]
        );
    }

    #[test]
    fn wildcard_subjects_are_detected_case_insensitively() {
        assert!(is_wildcard("*"));
        assert!(is_wildcard("ALL"));
        assert!(is_wildcard("Everyone"));
        assert!(!is_wildcard("agent://planner"));
    }

    #[test]
    fn posture_governs_the_right_operations() {
        assert_eq!(posture_for_operation("export").unwrap().0, "export_posture");
        assert_eq!(
            posture_for_operation("train").unwrap().0,
            "training_posture"
        );
        assert_eq!(
            posture_for_operation("publish").unwrap().0,
            "publish_route_posture"
        );
        assert_eq!(
            posture_for_operation("route").unwrap().0,
            "publish_route_posture"
        );
        assert!(posture_for_operation("read").is_none());
        assert!(posture_for_operation("transform").is_none());
    }

    #[test]
    fn mapped_property_ids_cover_key_title_and_fields() {
        let mapping = json!({
            "key_mapping": { "property_id": "loan_id" },
            "title_mapping": { "property_id": "title" },
            "field_mappings": [{ "property_id": "amount" }]
        });
        assert_eq!(
            mapped_property_ids(&mapping),
            vec!["loan_id", "title", "amount"]
        );
    }
}

/// The DURABILITY contract for POST / PATCH / DELETE on `/v1/hypervisor/odk/policy-bound-data-views`.
///
/// Every fault below is DETERMINISTIC, UID-INDEPENDENT and PROCESS-LOCAL. chmod is deliberately NOT
/// used: root bypasses mode-bit denial, so a permission-based fault would pass vacuously whenever
/// the suite runs as root. No env var and no cwd change is used either — which also rules out
/// `durable_fs`'s process-global `IOI_TEST_FORCE_*` seams, since those would race the rest of the
/// suite. Every fault is a PATH SHADOW, a re-homed record, or a CONSTRUCTED typed variant fed to a
/// pure classifier, and every postcondition is judged through the PRODUCTION readers — including
/// `materializing_run_routes::check_plan_against_truth`, the execution-time consumer — rather than
/// through the response body.
///
/// No test depends on a wall-clock id: ids are read back from the response, never predicted.
///
/// `odk-policy-bound-data-views` is in neither `PROMOTED_DOMAINS` nor `REQUIRED_ADMISSION_DOMAINS`,
/// so it takes the daemon-file path; a promoted family would route through the substrate engine and
/// its failure points would differ (see the promotion guard at the bottom).
#[cfg(test)]
mod policy_bound_data_view_durability_tests {
    use super::*;

    const MAPPING: &str = "cmap_loans";
    const SUBJECT: &str = "agent://planner";
    const PURPOSE: &str = "loan servicing analytics";

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    fn family(root: &std::path::Path) -> std::path::PathBuf {
        root.join(RECORD_DIR)
    }

    /// A READY mapping over three properties — the widest scope a view here may claim.
    fn seed_mapping(data_dir: &str) {
        persist_record_durable(
            data_dir,
            crate::connector_mapping_routes::RECORD_DIR,
            MAPPING,
            &json!({
                "id": MAPPING,
                "ref": format!("connector-mapping://{MAPPING}"),
                "ontology_ref": "ontology://ont_loans",
                "object_type_id": "loan",
                "key_mapping": { "property_id": "loan_id" },
                "title_mapping": { "property_id": "title" },
                "field_mappings": [{ "property_id": "amount" }],
                "health": { "status": "ready" }
            }),
        )
        .expect("mapping seeded");
    }

    /// The WIDE declaration: three operations-worth of scope over all three mapped properties.
    fn wide_body() -> Value {
        json!({
            "name": "loan servicing view",
            "connector_mapping_id": MAPPING,
            "allowed_operations": ["read", "transform"],
            "authority_subjects": [SUBJECT, "agent://reviewer"],
            "purpose": PURPOSE,
            "property_scope": ["loan_id", "title", "amount"],
            "retention_posture": "bounded"
        })
    }

    /// The NARROWING patch: one operation, one property. This is the mutation whose loss is the
    /// authority defect — a narrowing reported applied while the wider scope keeps authorizing.
    fn narrowing_patch() -> Value {
        json!({
            "allowed_operations": ["read"],
            "property_scope": ["loan_id"]
        })
    }

    /// Declare a wide view through the production path and return (id, record).
    fn declare_wide(data_dir: &str) -> (String, Value) {
        let (status, body) = declare_policy_view(data_dir, &wide_body());
        assert_eq!(status, StatusCode::CREATED, "body: {body}");
        let record = body["policy_bound_data_view"].clone();
        let id = record["id"].as_str().expect("id").to_string();
        (id, record)
    }

    /// The other four rungs `check_plan_against_truth` re-reads, plus the plan that cites them.
    /// The plan asks for BOTH operations and ALL THREE properties, so it is authorized by the wide
    /// view and refused by the narrowed one.
    fn seed_gate_inputs(data_dir: &str, view_id: &str) -> Value {
        persist_record_durable(
            data_dir,
            crate::data_source_routes::RECORD_DIR,
            "dsrc_loans",
            &json!({ "source_id": "dsrc_loans", "credential_posture": "wallet_credential_lease" }),
        )
        .expect("data source seeded");
        persist_record_durable(
            data_dir,
            crate::transformation_run_routes::RECORD_DIR,
            "trun_loans",
            &json!({ "id": "trun_loans", "status": "dry_run_ready" }),
        )
        .expect("transformation run seeded");
        persist_record_durable(
            data_dir,
            crate::ontology_projection_routes::RECORD_DIR,
            "proj_loans",
            &json!({
                "id": "proj_loans", "status": "ready",
                "visible_properties": ["loan_id", "title", "amount"]
            }),
        )
        .expect("projection seeded");
        json!({
            "data_source_id": "dsrc_loans",
            "connector_mapping_id": MAPPING,
            "policy_view_id": view_id,
            "transformation_run_id": "trun_loans",
            "ontology_projection_id": "proj_loans",
            "subject": SUBJECT,
            "purpose": PURPOSE,
            "requested_operations": ["read", "transform"],
            "requested_properties": ["loan_id", "title", "amount"]
        })
    }

    fn receipts(data_dir: &str) -> Vec<Value> {
        read_record_dir(data_dir, RECEIPT_DIR)
    }

    fn receipts_for_op(data_dir: &str, op: &str) -> Vec<Value> {
        receipts(data_dir)
            .into_iter()
            .filter(|r| r.get("op").and_then(|v| v.as_str()) == Some(op))
            .collect()
    }

    // ── Genesis: the record cannot commit ────────────────────────────────────────────────────

    #[test]
    fn genesis_refuses_when_the_family_dir_is_shadowed_by_a_file() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        seed_mapping(data_dir);
        // A REGULAR FILE where the record family belongs: create_dir_all refuses, so no temp
        // sibling is ever staged and nothing is visible. Not a chmod — root cannot bypass this.
        std::fs::write(family(directory.path()), b"not a directory").expect("family shadow");

        let (status, body) = declare_policy_view(data_dir, &wide_body());

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
        assert_eq!(body["ok"], json!(false));
        assert_eq!(body["error"]["code"], json!(PERSISTENCE_FAILED));
        assert!(
            body["error"]["message"]
                .as_str()
                .expect("message")
                .contains("resolves to nothing"),
            "a genesis refusal states that nothing was declared, got: {}",
            body["error"]["message"]
        );
        // No view was acknowledged, in the response or on disk...
        assert!(body.get("policy_bound_data_view").is_none());
        assert!(read_record_dir(data_dir, RECORD_DIR).is_empty());
        // ...and NO success receipt was minted: the receipt cannot precede the record.
        assert!(
            receipts(data_dir).is_empty(),
            "a refused declaration must mint no receipt"
        );
    }

    // ── Successor: a NARROWING that does not commit ──────────────────────────────────────────

    /// THE AUTHORITY TEST. The assertion is the ENFORCEMENT CONSEQUENCE, not the status code: after
    /// a narrowing whose write failed, `check_plan_against_truth` — the execution-time consumer —
    /// must still resolve the OLD WIDER `allowed_operations` / `property_scope`, and the caller must
    /// have been told so. The companion assertion proves the narrowing is enforcement-relevant at
    /// all: applied durably in a clean tree, the very same patch makes that gate refuse.
    #[test]
    fn a_narrowing_that_cannot_commit_refuses_and_the_gate_still_resolves_the_wider_scope() {
        let directory = temp();
        let root = directory.path();
        let data_dir = root.to_str().expect("utf8");
        seed_mapping(data_dir);
        let (id, wide) = declare_wide(data_dir);
        let plan = seed_gate_inputs(data_dir, &id);
        assert!(
            crate::materializing_run_routes::check_plan_against_truth(data_dir, &plan).is_ok(),
            "the wide view authorizes the plan before anything is narrowed"
        );

        // Re-home the record under a name the durable writer would never choose. `load_view`
        // matches on the `id` FIELD, so the view still resolves through every production reader,
        // while the write target is now free to be shadowed by a DIRECTORY — a rename onto which
        // fails after the temp sibling is staged and fsynced.
        persist_record_durable(data_dir, RECORD_DIR, "seed", &wide).expect("record re-homed");
        std::fs::remove_file(family(root).join(format!("{id}.json"))).expect("slot vacated");
        std::fs::create_dir_all(family(root).join(format!("{id}.json"))).expect("successor shadow");
        let receipts_before = receipts_for_op(data_dir, "patched").len();

        let (status, body) = redeclare_policy_view(data_dir, &id, &narrowing_patch());

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
        assert_eq!(body["error"]["code"], json!(PERSISTENCE_FAILED));
        assert!(
            body["error"]["message"]
                .as_str()
                .expect("message")
                .contains("NOT in effect"),
            "the refusal must say the narrowing is not in effect, got: {}",
            body["error"]["message"]
        );
        assert!(body.get("policy_bound_data_view").is_none());
        assert_eq!(
            receipts_for_op(data_dir, "patched").len(),
            receipts_before,
            "a refused narrowing must mint no receipt"
        );

        // THE CONSEQUENCE. The reader every consumer uses still resolves the WIDER envelope...
        let live = load_view(data_dir, &id).expect("the prior view survives");
        assert_eq!(live["allowed_operations"], json!(["read", "transform"]));
        assert_eq!(
            live["property_scope"],
            json!(["loan_id", "title", "amount"])
        );
        assert_eq!(live["revision"], json!(1), "no revision was consumed");
        // ...and the execution-time gate keeps authorizing exactly what the operator tried to revoke.
        assert!(
            crate::materializing_run_routes::check_plan_against_truth(data_dir, &plan).is_ok(),
            "the failed narrowing must not be reported applied while the gate still admits the plan"
        );

        // The same patch, applied durably in a clean tree, DOES make that gate refuse — so the
        // assertion above is about a real authority change and not about an inert field.
        let clean = temp();
        let clean_dir = clean.path().to_str().expect("utf8");
        seed_mapping(clean_dir);
        let (clean_id, _) = declare_wide(clean_dir);
        let clean_plan = seed_gate_inputs(clean_dir, &clean_id);
        let (clean_status, clean_body) =
            redeclare_policy_view(clean_dir, &clean_id, &narrowing_patch());
        assert_eq!(clean_status, StatusCode::OK, "body: {clean_body}");
        let refusal =
            crate::materializing_run_routes::check_plan_against_truth(clean_dir, &clean_plan)
                .expect_err("a durable narrowing must make the execution-time gate refuse");
        assert!(
            refusal.contains("transform") || refusal.contains("no longer within policy scope"),
            "the gate must refuse on the narrowed operation or property, got: {refusal}"
        );
    }

    // ── Acknowledgement is projected from the reload ─────────────────────────────────────────

    #[test]
    fn a_durable_declaration_is_acknowledged_from_the_reloaded_projection() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        seed_mapping(data_dir);

        let (status, body) = declare_policy_view(data_dir, &wide_body());

        assert_eq!(status, StatusCode::CREATED, "body: {body}");
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["audit_durable"], json!(true));
        let acknowledged = body["policy_bound_data_view"].clone();
        let id = acknowledged["id"].as_str().expect("id");
        // The acknowledgement is BYTE-DERIVED from the reload: it equals what the production reader
        // resolves, field for field, not merely "a record with this id exists".
        let durable = load_view(data_dir, id).expect("the view is durable");
        assert_eq!(acknowledged, durable);
        assert_eq!(acknowledged["revision"], json!(1));
        assert_eq!(
            acknowledged["allowed_operations"],
            json!(["read", "transform"])
        );
        assert_eq!(acknowledged["health"]["status"], json!("ready"));
        // The receipt is REAL and resolves through the shipped history join, and no ref was
        // embedded in the durable record.
        let receipt_ref = body["receipt_ref"].as_str().expect("a real receipt ref");
        assert_eq!(acknowledged["receipt_refs"], json!([]));
        let minted = receipts(data_dir);
        assert_eq!(minted.len(), 1);
        assert_eq!(minted[0]["receipt_ref"], json!(receipt_ref));
        assert_eq!(minted[0]["policy_view_ref"], acknowledged["ref"]);
    }

    #[test]
    fn a_durable_narrowing_is_acknowledged_from_the_reload_with_its_exact_identity_and_revision() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        seed_mapping(data_dir);
        let (id, _) = declare_wide(data_dir);

        let (status, body) = redeclare_policy_view(data_dir, &id, &narrowing_patch());

        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["audit_durable"], json!(true));
        let acknowledged = body["policy_bound_data_view"].clone();
        let durable = load_view(data_dir, &id).expect("the view is durable");
        assert_eq!(acknowledged, durable);
        assert_eq!(acknowledged["id"], json!(id));
        assert_eq!(acknowledged["revision"], json!(2));
        assert_eq!(acknowledged["allowed_operations"], json!(["read"]));
        assert_eq!(acknowledged["property_scope"], json!(["loan_id"]));
        assert_eq!(
            acknowledged["history"].as_array().expect("history").len(),
            2
        );
    }

    // ── Record durable, audit receipt not ────────────────────────────────────────────────────

    #[test]
    fn a_view_whose_receipt_did_not_persist_is_active_and_names_its_audit_gap() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        seed_mapping(data_dir);
        // A REGULAR FILE where the RECEIPT family belongs. The record family is untouched, so the
        // record commits and reloads and only the audit write fails.
        std::fs::write(directory.path().join(RECEIPT_DIR), b"not a directory")
            .expect("receipt family shadow");

        let (status, body) = declare_policy_view(data_dir, &wide_body());

        // The mutation IS active and is reported active — never as a failure.
        assert_eq!(status, StatusCode::CREATED, "body: {body}");
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["audit_durable"], json!(false));
        assert_eq!(body["audit_gap"]["code"], json!(AUDIT_RECEIPT_NOT_DURABLE));
        let message = body["audit_gap"]["message"].as_str().expect("message");
        assert!(
            message.contains("IS in effect"),
            "the audit gap must not read as a failed mutation, got: {message}"
        );
        // NO fabricated receipt ref is returned...
        assert!(
            body.get("receipt_ref").is_none(),
            "no receipt ref may be returned over a failed audit write"
        );
        let acknowledged = body["policy_bound_data_view"].clone();
        let id = acknowledged["id"].as_str().expect("id");
        // ...nor persisted in the durable record.
        let durable = load_view(data_dir, id).expect("the view is active");
        assert_eq!(acknowledged, durable);
        assert_eq!(durable["receipt_refs"], json!([]));
        assert!(
            !durable.to_string().contains("agentgres://"),
            "the durable record must carry no receipt reference at all"
        );
    }

    // ── Constructed lanes: no uid-independent injection exists for these ─────────────────────

    /// A renamed-but-unconfirmed commit is the one outcome that is neither applied nor unchanged.
    /// Its only injection point is a process-global env var owned by `durable_fs`, which this suite
    /// refuses to use, so the typed variant is fed to the pure classifier directly.
    #[test]
    fn a_renamed_but_unconfirmed_commit_claims_neither_applied_nor_unchanged() {
        let candidate = json!({ "id": "pbdv_x", "revision": 2 });
        let prior = json!({ "id": "pbdv_x", "revision": 1 });

        let ack = classify_commit(
            Err(PersistFailure::RenamedDurabilityUnconfirmed(
                std::io::Error::other("directory fsync failed"),
            )),
            Some(&prior),
            &candidate,
            Some(&prior),
        );

        assert!(matches!(ack, Acknowledgement::DurabilityUnconfirmed(_)));
        let (status, body) =
            commit_refusal(&ack, Continuity::PriorViewStands, "pbdv_x").expect("a refusal");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], json!(DURABILITY_UNCONFIRMED));
        let message = body["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("VISIBLE and may already be durable"),
            "the caller must be told the record is visible, got: {message}"
        );
        assert!(
            message.contains("NEITHER") && message.contains("NOR"),
            "the refusal must claim neither applied nor unchanged, got: {message}"
        );
        // And it must NOT be spoken of as the prior view standing — that clause belongs to the
        // 500 lane, where nothing committed.
        assert!(!message.contains("still exactly what every reader resolves"));
    }

    /// THE RELOAD COMPARISON IS LOAD-BEARING. If acknowledgement were relaxed to "a record with
    /// this id exists", the case below — a commit reporting success while the durable projection is
    /// still the UNCHANGED PRIOR RECORD — would be acknowledged as an applied narrowing. It must
    /// classify Ambiguous, and the refusal must refuse to return the candidate as active.
    #[test]
    fn a_reload_that_is_still_the_prior_record_is_never_acknowledged_as_applied() {
        let prior =
            json!({ "id": "pbdv_x", "revision": 1, "allowed_operations": ["read", "transform"] });
        let candidate = json!({ "id": "pbdv_x", "revision": 2, "allowed_operations": ["read"] });

        // Same id, same "a record exists" answer — and yet nothing was applied.
        let ack = classify_commit(Ok(()), Some(&prior), &candidate, Some(&prior));
        assert!(
            matches!(ack, Acknowledgement::Ambiguous(_)),
            "an unchanged prior record must never satisfy the acknowledgement, got: {ack:?}"
        );
        let (status, body) =
            commit_refusal(&ack, Continuity::PriorViewStands, "pbdv_x").expect("a refusal");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], json!(STATE_AMBIGUOUS));
        assert!(body["error"]["message"]
            .as_str()
            .expect("message")
            .contains("candidate is NOT returned as active"));

        // The exact-match case is the ONLY one that is acknowledged...
        assert_eq!(
            classify_commit(Ok(()), Some(&prior), &candidate, Some(&candidate)),
            Acknowledgement::Committed
        );
        // ...and a commit that reports success while nothing reads back is ambiguous too.
        assert!(matches!(
            classify_commit(Ok(()), Some(&prior), &candidate, None),
            Acknowledgement::Ambiguous(_)
        ));
        // A failure whose reload no longer matches what the request read cannot claim continuity.
        assert!(matches!(
            classify_commit(
                Err(PersistFailure::NotCommitted(std::io::Error::other("io"))),
                Some(&prior),
                &candidate,
                None
            ),
            Acknowledgement::Ambiguous(_)
        ));
    }

    #[test]
    fn unlink_dispositions_map_exactly_and_only_durable_is_causal() {
        assert_eq!(
            classify_unlink(Ok(UnlinkOutcome::Durable)),
            SlotUnlink::RemovedDurable
        );
        assert_eq!(
            classify_unlink(Ok(UnlinkOutcome::Absent)),
            SlotUnlink::AlreadyAbsent
        );
        assert!(matches!(
            classify_unlink(Ok(UnlinkOutcome::RemovedDurabilityUnconfirmed(
                std::io::Error::other("dir fsync failed")
            ))),
            SlotUnlink::DurabilityUnconfirmed(_)
        ));
        assert!(matches!(
            classify_unlink(Ok(
                UnlinkOutcome::ReplayAnchorRestoredAfterUnconfirmedRemoval(std::io::Error::other(
                    "restored"
                ))
            )),
            SlotUnlink::DurabilityUnconfirmed(_)
        ));
        assert!(matches!(
            classify_unlink(Err(std::io::Error::other("unlink failed"))),
            SlotUnlink::NotPerformed(_)
        ));
    }

    // ── Revocation ───────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_revocation_is_acknowledged_only_from_reloaded_absence() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        seed_mapping(data_dir);
        let (id, wide) = declare_wide(data_dir);
        let plan = seed_gate_inputs(data_dir, &id);
        assert!(crate::materializing_run_routes::check_plan_against_truth(data_dir, &plan).is_ok());

        let (status, body) = destroy_policy_view(data_dir, &id);

        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["removed"], json!(true));
        assert_eq!(body["id"], json!(id));
        assert_eq!(body["record_slot"], json!("removed_durable"));
        assert_eq!(body["audit_durable"], json!(true));
        // Judged through the production readers, not the response.
        assert!(load_view(data_dir, &id).is_none());
        assert!(!family(directory.path()).join(format!("{id}.json")).exists());
        assert!(
            crate::materializing_run_routes::check_plan_against_truth(data_dir, &plan).is_err(),
            "a revoked capability must stop authorizing"
        );
        // The revocation receipt is real and joins to the view by ref.
        let deleted = receipts_for_op(data_dir, "deleted");
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0]["policy_view_ref"], wide["ref"]);
        assert_eq!(body["receipt_ref"], deleted[0]["receipt_ref"]);
    }

    #[test]
    fn a_record_slot_shadowed_by_a_directory_refuses_without_claiming_revocation() {
        let directory = temp();
        let root = directory.path();
        let data_dir = root.to_str().expect("utf8");
        seed_mapping(data_dir);
        let (id, wide) = declare_wide(data_dir);
        let plan = seed_gate_inputs(data_dir, &id);
        // The record still resolves through `load_view` (id-in-field) from a re-homed slot, while
        // the name the deleter must unlink is occupied by a DIRECTORY: `unlinkat(.., 0)` returns
        // EISDIR, which is neither a removal nor an absence.
        persist_record_durable(data_dir, RECORD_DIR, "seed", &wide).expect("record re-homed");
        std::fs::remove_file(family(root).join(format!("{id}.json"))).expect("slot vacated");
        std::fs::create_dir_all(family(root).join(format!("{id}.json"))).expect("slot shadow");

        let (status, body) = destroy_policy_view(data_dir, &id);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
        assert_eq!(body["ok"], json!(false));
        assert_eq!(body["error"]["code"], json!(REVOCATION_UNCONFIRMED));
        assert!(body["error"]["message"]
            .as_str()
            .expect("message")
            .contains("No deletion is claimed"));
        assert!(body.get("removed").is_none());
        assert!(
            receipts_for_op(data_dir, "deleted").is_empty(),
            "an unclassifiable unlink must mint no revocation receipt"
        );
        // The capability is still declared and still authorizes — which is what the caller was told.
        assert!(load_view(data_dir, &id).is_some());
        assert!(crate::materializing_run_routes::check_plan_against_truth(data_dir, &plan).is_ok());
    }

    #[test]
    fn a_record_that_does_not_live_at_the_writers_filename_refuses_rather_than_claiming_revocation()
    {
        let directory = temp();
        let root = directory.path();
        let data_dir = root.to_str().expect("utf8");
        seed_mapping(data_dir);
        let (id, wide) = declare_wide(data_dir);
        // Re-homed with NO shadow: the unlink target simply is not there, so the unlink returns
        // ENOENT (Absent) — and the view still resolves. Absence of the NAME is not absence of the
        // VIEW, and only the reload can tell them apart.
        persist_record_durable(data_dir, RECORD_DIR, "seed", &wide).expect("record re-homed");
        std::fs::remove_file(family(root).join(format!("{id}.json"))).expect("slot vacated");

        let (status, body) = destroy_policy_view(data_dir, &id);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
        assert_eq!(body["error"]["code"], json!(REVOCATION_UNCONFIRMED));
        assert!(body["error"]["message"]
            .as_str()
            .expect("message")
            .contains("STILL resolves"));
        assert!(receipts_for_op(data_dir, "deleted").is_empty());
        assert!(load_view(data_dir, &id).is_some());
    }

    #[test]
    fn a_deletion_whose_receipt_did_not_persist_is_effective_and_names_its_audit_gap() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        seed_mapping(data_dir);
        let (id, _) = declare_wide(data_dir);
        // Replace the receipt family with a regular file AFTER the declaration receipt landed, so
        // only the revocation's audit write fails.
        std::fs::remove_dir_all(directory.path().join(RECEIPT_DIR))
            .expect("receipt family removed");
        std::fs::write(directory.path().join(RECEIPT_DIR), b"not a directory")
            .expect("receipt family shadow");

        let (status, body) = destroy_policy_view(data_dir, &id);

        // The deletion REMAINS EFFECTIVE and is reported so.
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["removed"], json!(true));
        assert_eq!(body["audit_durable"], json!(false));
        assert_eq!(body["audit_gap"]["code"], json!(AUDIT_RECEIPT_NOT_DURABLE));
        assert!(
            body.get("receipt_ref").is_none(),
            "no receipt ref may be returned over a failed audit write"
        );
        assert!(load_view(data_dir, &id).is_none());
    }

    // ── Preserved shipped wire responses ─────────────────────────────────────────────────────

    #[test]
    fn an_absent_view_preserves_the_shipped_delete_response() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");

        let (status, body) = destroy_policy_view(data_dir, "pbdv_never_existed");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({ "ok": false, "removed": false, "id": "pbdv_never_existed" })
        );
        assert!(receipts(data_dir).is_empty());
    }

    #[test]
    fn an_absent_view_preserves_the_shipped_patch_response() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");

        let (status, body) = redeclare_policy_view(data_dir, "pbdv_never_existed", &json!({}));

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({ "ok": false, "reason": "policy-bound data view not found" })
        );
    }

    #[test]
    fn a_malformed_declaration_still_refuses_before_any_write() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");

        let (status, body) = declare_policy_view(data_dir, &wide_body());

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        assert_eq!(body["error"]["code"], json!("policy_view_mapping_unknown"));
        assert!(read_record_dir(data_dir, RECORD_DIR).is_empty());
        assert!(receipts(data_dir).is_empty());

        // The patch lane keeps its shipped 200-with-ok:false convention for the same class.
        seed_mapping(data_dir);
        let (id, _) = declare_wide(data_dir);
        std::fs::remove_file(
            directory
                .path()
                .join(crate::connector_mapping_routes::RECORD_DIR)
                .join(format!("{MAPPING}.json")),
        )
        .expect("mapping removed");
        let (patch_status, patch_body) = redeclare_policy_view(data_dir, &id, &json!({}));
        assert_eq!(patch_status, StatusCode::OK);
        assert_eq!(
            patch_body["error"]["code"],
            json!("policy_view_mapping_unknown")
        );
        assert_eq!(
            load_view(data_dir, &id).expect("view")["revision"],
            json!(1),
            "a malformed patch bumps no revision"
        );
    }

    // ── Source-shape pins for the claims no injectable fault can catch ───────────────────────

    fn production_fn<'a>(source: &'a str, signature: &str) -> &'a str {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("the production function `{signature}` is gone"));
        let rest = &source[start..];
        let end = rest.find("\n}\n").map(|i| i + 3).unwrap_or(rest.len());
        &rest[..end]
    }

    fn production_source(source: &str) -> &str {
        &source[..source.find("\n#[cfg(test)]").expect("the test boundary")]
    }

    /// Production CODE only — doc comments and inline commentary stripped. The prose below
    /// deliberately NAMES the legacy writers it replaced (`persist_record`, `remove_record`,
    /// `fs::remove_file`), so a scraper that reads comments would report the defect it is
    /// describing.
    fn production_code(source: &str) -> String {
        production_source(source)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Every mutation must use the durable primitives, and in COMMIT → RELOAD → RECEIPT order. A
    /// receipt minted before the fact it describes has been observed is evidence for an unobserved
    /// mutation, and no path shadow can catch that reordering — it is pinned here instead.
    #[test]
    fn the_mutations_use_the_durable_primitives_in_commit_reload_receipt_order() {
        let source = include_str!("policy_bound_data_view_routes.rs");
        let production = production_code(source);
        assert!(
            !production.contains("persist_record(")
                && !production.contains("remove_record(")
                && !production.contains("remove_file"),
            "no mutation here may go through the non-durable legacy writers"
        );

        for signature in [
            "pub(crate) fn declare_policy_view",
            "pub(crate) fn redeclare_policy_view",
        ] {
            let body = production_fn(source, signature);
            let commit = body
                .find("persist_record_durable(")
                .unwrap_or_else(|| panic!("{signature} no longer commits durably"));
            let reload = body
                .find("let reloaded = load_view(")
                .unwrap_or_else(|| panic!("{signature} no longer reloads"));
            let ack = body
                .find("classify_commit(")
                .unwrap_or_else(|| panic!("{signature} no longer compares the reload"));
            let receipt = body
                .find("commit_view_receipt(")
                .unwrap_or_else(|| panic!("{signature} no longer audits"));
            assert!(
                commit < reload && reload < ack && ack < receipt,
                "{signature} must commit, then reload and compare, and only then mint a receipt"
            );
        }

        let destroy = production_fn(source, "pub(crate) fn destroy_policy_view");
        let unlink = destroy
            .find("unlink_durable_at(")
            .expect("the revocation must go through the durability-honest unlink");
        let gate = destroy
            .find("load_view(data_dir, id).is_some()")
            .expect("the revocation must be gated on reloaded absence");
        let receipt = destroy
            .find("commit_view_receipt(")
            .expect("the revocation must be audited");
        assert!(
            unlink < gate && gate < receipt,
            "delete must unlink durably, prove absence by reload, and only then mint a receipt"
        );
    }

    /// The record family is NOT substrate-owned today. If it is ever promoted, `read_record_dir`
    /// and `persist_record_durable` route through the Agentgres engine instead and the daemon-file
    /// faults this suite injects stop describing the real write path — so this fails loudly first.
    #[test]
    fn the_record_family_is_not_promoted_to_the_substrate_today() {
        assert!(!super::super::substrate_store::is_promoted(RECORD_DIR));
        assert!(!super::super::substrate_store::is_promoted(RECEIPT_DIR));
    }

    /// Every stable `policy_view_*` code the production surface can emit is behaviourally covered,
    /// asserted from a constructed variant, or ENUMERATED as noncoverage with its reason. A new
    /// code in none of the three lists fails this test, so noncoverage cannot accrue silently.
    #[test]
    fn every_policy_view_code_is_covered_or_explicitly_enumerated_as_noncoverage() {
        // Reached by a deterministic path shadow, a re-homed record, or real data state here.
        const BEHAVIOURAL: &[&str] = &[
            "policy_view_persistence_failed",
            "policy_view_revocation_unconfirmed",
            "policy_view_audit_receipt_not_durable",
            "policy_view_mapping_unknown",
        ];
        // Asserted from constructed typed variants against the pure classifier and refusal builder.
        //  * durability_unconfirmed — a post-rename directory-fsync failure has no uid-independent
        //    injection; `durable_fs`'s only seam for it is a process-global env var this suite
        //    refuses to use.
        //  * state_ambiguous — a commit that succeeds and then reads back differently needs a
        //    concurrent writer; in one process a committed rename is immediately readable.
        const CONSTRUCTED: &[&str] = &[
            "policy_view_durability_unconfirmed",
            "policy_view_state_ambiguous",
        ];
        // The shipped fail-closed VALIDATION codes. Unchanged by this durability packet, and
        // exercised by apps/hypervisor/scripts/verify-hypervisor-policy-bound-data-view.mjs against
        // a live daemon rather than by this suite. `policy_view_mapping_unknown` is covered above
        // as the representative of the class, to pin that both lanes keep their shipped shape.
        const ENUMERATED_NONCOVERAGE: &[&str] = &[
            "policy_view_plaintext_secret_rejected",
            "policy_view_name_required",
            "policy_view_mapping_not_ready",
            "policy_view_operations_required",
            "policy_view_operation_invalid",
            "policy_view_subjects_required",
            "policy_view_wildcard_authority_rejected",
            "policy_view_property_unscoped",
            "policy_view_posture_invalid",
            "policy_view_posture_conflict",
            "policy_view_receipt_obligation_required",
        ];

        // `policy_view_ref` is the receipt's JOIN FIELD name, not a wire code. It is excluded by
        // name so the scraper stays dumb and TOTAL — every other `"policy_view_*"` literal in the
        // production surface must be classified — rather than clever and lossy.
        const NOT_A_CODE: &[&str] = &["policy_view_ref"];

        let source = include_str!("policy_bound_data_view_routes.rs");
        let mut emitted: Vec<String> = Vec::new();
        for chunk in production_source(source).split("\"policy_view_").skip(1) {
            let code = format!(
                "policy_view_{}",
                &chunk[..chunk.find('"').expect("closing quote")]
            );
            if !emitted.contains(&code) && !NOT_A_CODE.contains(&code.as_str()) {
                emitted.push(code);
            }
        }
        assert!(!emitted.is_empty(), "no codes found — the scraper broke");
        for code in &emitted {
            let code = code.as_str();
            assert!(
                BEHAVIOURAL.contains(&code)
                    || CONSTRUCTED.contains(&code)
                    || ENUMERATED_NONCOVERAGE.contains(&code),
                "code `{code}` is in none of the three coverage lists — cover it or enumerate it \
                 as noncoverage with a reason"
            );
        }
        for code in BEHAVIOURAL
            .iter()
            .chain(CONSTRUCTED)
            .chain(ENUMERATED_NONCOVERAGE)
        {
            assert!(
                emitted.iter().any(|e| e == code),
                "coverage list names `{code}`, which this module no longer emits — prune the list"
            );
        }
    }
}
