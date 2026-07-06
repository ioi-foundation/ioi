//! Feedback & Annotations object plane — FOUNDATION cut (daemon-first, queue-only).
//!
//! A FeedbackEntry is durable operator feedback or an annotation over a REAL subject (run,
//! session, surface object, domain app — local-looking refs must resolve, named refs are
//! allowed). Every entry carries an EVIDENCE-ELIGIBILITY consent posture from day one
//! (never_train | synthetic_only | redacted_opt_in | full_private_opt_in | org_policy) because
//! the whole point of the queue is safe conversion into eval/training candidates later.
//!
//! Deliberately inert — the queue records and gates, it does not act:
//!   * conversion emits a NAMED candidate ref only; no eval or training executes here;
//!   * converting an entry whose consent is `never_train` fails closed with a named code —
//!     consent is a gate, not a label;
//!   * no notification fan-out, no automatic triage, no model calls.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::governance_routes::resolve_governance_ref;
use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const KIND_FEEDBACK: &str = "feedback-entries";
const ENTRY_KINDS: &[&str] = &["feedback", "annotation"];
/// Evidence-eligibility ladder (guide cross-cutting rule): classify BEFORE any train/eval use.
const CONSENT_LADDER: &[&str] = &[
    "never_train",
    "synthetic_only",
    "redacted_opt_in",
    "full_private_opt_in",
    "org_policy",
];

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn bad(code: &str, msg: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": code, "message": msg } })),
    )
}
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn load(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, KIND_FEEDBACK)
        .into_iter()
        .find(|r| r.get("id").and_then(Value::as_str) == Some(id))
}

/// Status machine: open → triaged → converted; open/triaged → dismissed.
fn next_feedback_status(cur: &str, transition: &str) -> Result<&'static str, String> {
    match (cur, transition) {
        ("open", "triage") => Ok("triaged"),
        ("open", "dismiss") | ("triaged", "dismiss") => Ok("dismissed"),
        ("open", "convert") | ("triaged", "convert") => Ok("converted"),
        _ => Err(format!("cannot {transition} from {cur}")),
    }
}
/// Consent gate for conversion: `never_train` forbids any eval/training candidacy — fail closed.
fn convert_allowed(consent: &str) -> bool {
    !consent.is_empty() && consent != "never_train" && CONSENT_LADDER.contains(&consent)
}

pub(crate) async fn handle_feedback_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let items = read_record_dir(&st.data_dir, KIND_FEEDBACK);
    let mut by_status: HashMap<String, i64> = HashMap::new();
    let mut by_kind: HashMap<String, i64> = HashMap::new();
    let mut by_consent: HashMap<String, i64> = HashMap::new();
    for e in &items {
        *by_status.entry(text(e, "status").to_string()).or_insert(0) += 1;
        *by_kind.entry(text(e, "entry_kind").to_string()).or_insert(0) += 1;
        *by_consent.entry(text(e, "consent").to_string()).or_insert(0) += 1;
    }
    Json(json!({
        "ok": true,
        "total": items.len(),
        "by_status": serde_json::to_value(&by_status).unwrap_or_else(|_| json!({})),
        "by_kind": serde_json::to_value(&by_kind).unwrap_or_else(|_| json!({})),
        "by_consent": serde_json::to_value(&by_consent).unwrap_or_else(|_| json!({})),
        "consent_ladder": CONSENT_LADDER,
        "status_note": "Queue truth only: conversion emits a NAMED candidate ref; no eval or training executes here, and never_train entries can never convert."
    }))
}

pub(crate) async fn handle_feedback_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_FEEDBACK);
    if let Some(s) = q.get("status").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        items.retain(|e| text(e, "status") == s);
    }
    items.sort_by(|a, b| text(b, "updated_at").cmp(text(a, "updated_at")));
    Json(json!({ "ok": true, "feedback_entries": items }))
}

pub(crate) async fn handle_feedback_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let subject_ref = text(&body, "subject_ref");
    if subject_ref.is_empty() {
        return bad("feedback_subject_required", "a subject ref is required");
    }
    if let Err((c, m)) = resolve_governance_ref(&st.data_dir, subject_ref) {
        return bad(&c, &m);
    }
    let entry_kind = {
        let k = text(&body, "entry_kind");
        if k.is_empty() { "feedback" } else { k }
    };
    if !ENTRY_KINDS.contains(&entry_kind) {
        return bad("feedback_kind_invalid", "entry_kind must be feedback | annotation");
    }
    let fb_body = text(&body, "body");
    if fb_body.trim().is_empty() {
        return bad("feedback_body_required", "an empty entry records nothing — body is required");
    }
    let consent = {
        let c = text(&body, "consent");
        if c.is_empty() { "never_train" } else { c }
    };
    if !CONSENT_LADDER.contains(&consent) {
        return bad(
            "feedback_consent_invalid",
            "consent must be never_train | synthetic_only | redacted_opt_in | full_private_opt_in | org_policy",
        );
    }
    let id = format!("fb_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.feedback-entry.v1",
        "object": "ioi.hypervisor.feedback_entry",
        "id": id, "ref": format!("feedback://{id}"),
        "subject_ref": subject_ref,
        "entry_kind": entry_kind,
        "body": fb_body,
        "author_ref": text(&body, "author_ref"),
        "consent": consent,
        "status": "open",
        "converted_to_ref": Value::Null,
        "created_at": now, "updated_at": now
    });
    let _ = persist_record(&st.data_dir, KIND_FEEDBACK, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "feedback_entry": record })))
}

pub(crate) async fn handle_feedback_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, &id) {
        Some(e) => Json(json!({ "ok": true, "feedback_entry": e })),
        None => Json(json!({ "ok": false, "reason": "feedback_entry not found" })),
    }
}

pub(crate) async fn handle_feedback_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut e) = load(&st.data_dir, &id) else {
        return bad("feedback_not_found", "feedback_entry not found");
    };
    if let Some(t) = body.get("transition").and_then(Value::as_str) {
        let cur = text(&e, "status").to_string();
        match next_feedback_status(&cur, t) {
            Ok(next) => {
                if next == "converted" {
                    let consent = text(&e, "consent").to_string();
                    if !convert_allowed(&consent) {
                        return bad(
                            "feedback_consent_forbids_training",
                            "consent is never_train — this entry can never become an eval/training candidate; raise consent first (a recorded change), then convert",
                        );
                    }
                    let target = text(&body, "converted_to_ref");
                    if target.trim().is_empty() {
                        return bad("feedback_convert_ref_required", "convert requires converted_to_ref (the named eval/training candidate)");
                    }
                    e["converted_to_ref"] = json!(target);
                }
                e["status"] = json!(next);
            }
            Err(m) => return bad("feedback_transition_invalid", &m),
        }
    }
    // Editable while not terminal: body, consent (a recorded consent change), author_ref.
    let terminal = matches!(text(&e, "status"), "converted" | "dismissed");
    for key in ["body", "consent", "author_ref"] {
        if let Some(v) = body.get(key) {
            if terminal && body.get("transition").is_none() {
                return bad("feedback_terminal_immutable", "converted/dismissed entries are receipts — create a new entry instead");
            }
            if key == "consent" {
                let c = v.as_str().unwrap_or("");
                if !CONSENT_LADDER.contains(&c) {
                    return bad("feedback_consent_invalid", "unknown consent value");
                }
            }
            e[key] = v.clone();
        }
    }
    e["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_FEEDBACK, &id, &e);
    (StatusCode::OK, Json(json!({ "ok": true, "feedback_entry": e })))
}

pub(crate) async fn handle_feedback_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let removed = remove_record(&st.data_dir, KIND_FEEDBACK, &id);
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feedback_status_machine() {
        assert_eq!(next_feedback_status("open", "triage").unwrap(), "triaged");
        assert_eq!(next_feedback_status("open", "dismiss").unwrap(), "dismissed");
        assert_eq!(next_feedback_status("triaged", "convert").unwrap(), "converted");
        assert!(next_feedback_status("converted", "triage").is_err());
        assert!(next_feedback_status("dismissed", "convert").is_err());
        assert!(next_feedback_status("open", "bogus").is_err());
    }

    #[test]
    fn consent_gates_conversion() {
        assert!(!convert_allowed("never_train")); // the whole point: fail closed
        assert!(!convert_allowed("")); // absent consent is never permission
        assert!(!convert_allowed("made_up_value"));
        assert!(convert_allowed("synthetic_only"));
        assert!(convert_allowed("redacted_opt_in"));
        assert!(convert_allowed("full_private_opt_in"));
        assert!(convert_allowed("org_policy"));
    }
}
