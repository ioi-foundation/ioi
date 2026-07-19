//! Eval-suite library object plane — FOUNDATION cut (daemon-first, declaration-only).
//!
//! A HypervisorEvalSuite is a DECLARED, INERT assessment suite: a named grouping that says WHAT
//! would be evaluated and UNDER WHAT ADMISSIBILITY — never how it scores. It carries:
//!   * subject_scope        — which kinds of real subject the suite assesses (mission runs, failed
//!                            runs, goal runs, feedback entries, sessions, …);
//!   * rubric_refs          — named rubric refs (declared criteria; not executed here);
//!   * evidence_requirements— what evidence a subject must carry to be admissible (proof/timeline/…);
//!   * consent_requirements — which evidence-eligibility rungs a candidate must hold to enter the
//!                            suite (a GATE, mirroring the feedback plane's consent ladder);
//!   * candidate_refs       — named eval/feedback/training-candidate handoffs the suite would draw on.
//!
//! Deliberately inert — the library declares and gates, it does NOT act:
//!   * there is NO run/execute endpoint — no EvalRun, no scoring, no verdict, no model judge here;
//!   * a suite whose consent_requirements would admit only `never_train` fails closed (nothing could
//!     ever be assessed) — consent is a gate, not a label;
//!   * candidate_refs are recorded as NAMED handoffs only; attaching one runs nothing.
//! Health is a declared-completeness signal (empty | declared), never a score.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const KIND_EVAL_SUITE: &str = "eval-suites";
/// Subject kinds a suite may declare it assesses (real estate objects, named — nothing is executed).
const SUBJECT_KINDS: &[&str] = &[
    "mission_run",
    "failed_run",
    "goal_run",
    "goal_run_blocker",
    "feedback_entry",
    "session",
    "domain_app",
    "surface_object",
];
/// Evidence a subject may be required to carry to be admissible (declared requirement, not enforced
/// execution — the suite records what it WOULD need).
const EVIDENCE_KINDS: &[&str] = &[
    "proof_ref",
    "timeline_ref",
    "receipt_ref",
    "source_hash",
    "state_root",
    "transcript_ref",
];
/// Evidence-eligibility ladder — shared with the feedback plane (classify BEFORE any train/eval use).
const CONSENT_LADDER: &[&str] = &[
    "never_train",
    "synthetic_only",
    "redacted_opt_in",
    "full_private_opt_in",
    "org_policy",
];
/// Candidate handoffs are LOCAL evidence refs, never arbitrary external URLs — allowlist the schemes
/// the feedback/eval plane actually mints (a suite references candidates; it does not fetch them).
const CANDIDATE_SCHEMES: &[&str] = &["eval://", "feedback://", "training-candidate://"];

/// A candidate ref must use an allowlisted local scheme and carry a body after it.
fn candidate_ref_ok(cr: &str) -> bool {
    CANDIDATE_SCHEMES
        .iter()
        .any(|s| cr.starts_with(s) && cr.len() > s.len())
}

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
    read_record_dir(data_dir, KIND_EVAL_SUITE)
        .into_iter()
        .find(|r| r.get("id").and_then(Value::as_str) == Some(id))
}

/// Parse a JSON array of strings; returns None if a non-string element is present.
fn str_array(v: Option<&Value>) -> Option<Vec<String>> {
    match v {
        None | Some(Value::Null) => Some(vec![]),
        Some(Value::Array(a)) => {
            let mut out = Vec::with_capacity(a.len());
            for e in a {
                let s = e.as_str()?;
                out.push(s.to_string());
            }
            Some(out)
        }
        _ => None,
    }
}

/// Consent gate: a suite must be able to admit SOME trainable/assessable evidence. A requirement set
/// that is empty, invalid, or admits only `never_train` can never assess anything — fail closed.
fn consent_requirements_usable(reqs: &[String]) -> Result<(), (&'static str, String)> {
    if reqs.is_empty() {
        return Err((
            "eval_suite_consent_required",
            "consent_requirements is required — declare which evidence-eligibility rungs a candidate must hold".into(),
        ));
    }
    for r in reqs {
        if !CONSENT_LADDER.contains(&r.as_str()) {
            return Err((
                "eval_suite_consent_invalid",
                format!("unknown consent rung `{r}` — must be one of {CONSENT_LADDER:?}"),
            ));
        }
    }
    if reqs.iter().all(|r| r == "never_train") {
        return Err((
            "eval_suite_consent_requirement_unusable",
            "a suite requiring only never_train evidence can never assess anything — include at least one admissible rung".into(),
        ));
    }
    Ok(())
}

/// Declared-completeness — NOT a score. `declared` once real candidates are attached; else `empty`.
fn health_of(candidate_count: usize) -> &'static str {
    if candidate_count == 0 {
        "empty"
    } else {
        "declared"
    }
}

pub(crate) async fn handle_eval_suite_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let items = read_record_dir(&st.data_dir, KIND_EVAL_SUITE);
    let mut by_status: HashMap<String, i64> = HashMap::new();
    let mut by_health: HashMap<String, i64> = HashMap::new();
    for e in &items {
        *by_status.entry(text(e, "status").to_string()).or_insert(0) += 1;
        *by_health.entry(text(e, "health").to_string()).or_insert(0) += 1;
    }
    Json(json!({
        "ok": true,
        "total": items.len(),
        "by_status": serde_json::to_value(&by_status).unwrap_or_else(|_| json!({})),
        "by_health": serde_json::to_value(&by_health).unwrap_or_else(|_| json!({})),
        "subject_kinds": SUBJECT_KINDS,
        "evidence_kinds": EVIDENCE_KINDS,
        "consent_ladder": CONSENT_LADDER,
        "status_note": "Declaration truth only: a suite declares what it WOULD assess and under what admissibility. There is no run/scoring/judge here — EvalRun execution, verdicts, and scorecards are named gaps."
    }))
}

pub(crate) async fn handle_eval_suite_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_EVAL_SUITE);
    if let Some(s) = q.get("status").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        items.retain(|e| text(e, "status") == s);
    }
    items.sort_by(|a, b| text(b, "updated_at").cmp(text(a, "updated_at")));
    Json(json!({ "ok": true, "eval_suites": items }))
}

pub(crate) async fn handle_eval_suite_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let name = text(&body, "name").trim().to_string();
    if name.is_empty() {
        return bad("eval_suite_name_required", "a suite name is required");
    }

    // subject_scope — required, non-empty, every kind known.
    let Some(subject_scope) = str_array(body.get("subject_scope")) else {
        return bad(
            "eval_suite_subject_scope_invalid",
            "subject_scope must be an array of strings",
        );
    };
    if subject_scope.is_empty() {
        return bad(
            "eval_suite_subject_scope_required",
            "declare at least one subject kind the suite assesses",
        );
    }
    for s in &subject_scope {
        if !SUBJECT_KINDS.contains(&s.as_str()) {
            return bad(
                "eval_suite_subject_scope_invalid",
                &format!("unknown subject kind `{s}` — must be one of {SUBJECT_KINDS:?}"),
            );
        }
    }

    // evidence_requirements — optional, but every kind known when present.
    let Some(evidence_requirements) = str_array(body.get("evidence_requirements")) else {
        return bad(
            "eval_suite_evidence_invalid",
            "evidence_requirements must be an array of strings",
        );
    };
    for ev in &evidence_requirements {
        if !EVIDENCE_KINDS.contains(&ev.as_str()) {
            return bad(
                "eval_suite_evidence_invalid",
                &format!("unknown evidence kind `{ev}` — must be one of {EVIDENCE_KINDS:?}"),
            );
        }
    }

    // consent_requirements — required, valid rungs, must admit something (gate).
    let Some(consent_requirements) = str_array(body.get("consent_requirements")) else {
        return bad(
            "eval_suite_consent_invalid",
            "consent_requirements must be an array of strings",
        );
    };
    if let Err((c, m)) = consent_requirements_usable(&consent_requirements) {
        return bad(c, &m);
    }

    // rubric_refs / candidate_refs — optional named refs; candidates must look like refs (`scheme://`).
    let Some(rubric_refs) = str_array(body.get("rubric_refs")) else {
        return bad(
            "eval_suite_rubric_invalid",
            "rubric_refs must be an array of strings",
        );
    };
    let Some(candidate_refs) = str_array(body.get("candidate_refs")) else {
        return bad(
            "eval_suite_candidate_invalid",
            "candidate_refs must be an array of strings",
        );
    };
    for cr in &candidate_refs {
        if !candidate_ref_ok(cr) {
            return bad(
                "eval_suite_candidate_ref_invalid",
                &format!("candidate `{cr}` is not a local handoff ref — expected an allowlisted scheme ({CANDIDATE_SCHEMES:?}), not an external URL"),
            );
        }
    }

    let id = format!("es_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.eval-suite.v1",
        "object": "ioi.hypervisor.eval_suite",
        "id": id, "ref": format!("eval-suite://{id}"),
        "name": name,
        "description": text(&body, "description"),
        "subject_scope": subject_scope,
        "rubric_refs": rubric_refs,
        "evidence_requirements": evidence_requirements,
        "consent_requirements": consent_requirements,
        "candidate_refs": candidate_refs.clone(),
        // Inert: a suite is always a draft declaration. It does not execute.
        "status": "draft",
        "health": health_of(candidate_refs.len()),
        "authority_note": "inert declaration — no EvalRun/scoring/judge; candidate_refs are named handoffs only",
        "created_at": now, "updated_at": now
    });
    let _ = persist_record(&st.data_dir, KIND_EVAL_SUITE, &id, &record);
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "eval_suite": record })),
    )
}

pub(crate) async fn handle_eval_suite_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, &id) {
        Some(e) => Json(json!({ "ok": true, "eval_suite": e })),
        None => Json(json!({ "ok": false, "reason": "eval_suite not found" })),
    }
}

pub(crate) async fn handle_eval_suite_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut e) = load(&st.data_dir, &id) else {
        return bad("eval_suite_not_found", "eval_suite not found");
    };

    // A draft's declaration is editable; consent/subject/evidence stay validated on every change.
    if let Some(v) = body.get("name") {
        let n = v.as_str().unwrap_or("").trim();
        if n.is_empty() {
            return bad("eval_suite_name_required", "name cannot be blank");
        }
        e["name"] = json!(n);
    }
    if body.get("description").is_some() {
        e["description"] = json!(text(&body, "description"));
    }
    if let Some(raw) = body.get("subject_scope") {
        let Some(scope) = str_array(Some(raw)) else {
            return bad(
                "eval_suite_subject_scope_invalid",
                "subject_scope must be an array of strings",
            );
        };
        if scope.is_empty() {
            return bad(
                "eval_suite_subject_scope_required",
                "at least one subject kind is required",
            );
        }
        for s in &scope {
            if !SUBJECT_KINDS.contains(&s.as_str()) {
                return bad(
                    "eval_suite_subject_scope_invalid",
                    &format!("unknown subject kind `{s}`"),
                );
            }
        }
        e["subject_scope"] = json!(scope);
    }
    if let Some(raw) = body.get("evidence_requirements") {
        let Some(ev) = str_array(Some(raw)) else {
            return bad(
                "eval_suite_evidence_invalid",
                "evidence_requirements must be an array of strings",
            );
        };
        for x in &ev {
            if !EVIDENCE_KINDS.contains(&x.as_str()) {
                return bad(
                    "eval_suite_evidence_invalid",
                    &format!("unknown evidence kind `{x}`"),
                );
            }
        }
        e["evidence_requirements"] = json!(ev);
    }
    if let Some(raw) = body.get("consent_requirements") {
        let Some(reqs) = str_array(Some(raw)) else {
            return bad(
                "eval_suite_consent_invalid",
                "consent_requirements must be an array of strings",
            );
        };
        if let Err((c, m)) = consent_requirements_usable(&reqs) {
            return bad(c, &m);
        }
        e["consent_requirements"] = json!(reqs);
    }
    if let Some(raw) = body.get("rubric_refs") {
        let Some(rr) = str_array(Some(raw)) else {
            return bad(
                "eval_suite_rubric_invalid",
                "rubric_refs must be an array of strings",
            );
        };
        e["rubric_refs"] = json!(rr);
    }
    if let Some(raw) = body.get("candidate_refs") {
        let Some(cr) = str_array(Some(raw)) else {
            return bad(
                "eval_suite_candidate_invalid",
                "candidate_refs must be an array of strings",
            );
        };
        for c in &cr {
            if !candidate_ref_ok(c) {
                return bad("eval_suite_candidate_ref_invalid", &format!("candidate `{c}` is not a local handoff ref (allowed schemes: {CANDIDATE_SCHEMES:?})"));
            }
        }
        e["health"] = json!(health_of(cr.len()));
        e["candidate_refs"] = json!(cr);
    }
    e["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_EVAL_SUITE, &id, &e);
    (StatusCode::OK, Json(json!({ "ok": true, "eval_suite": e })))
}

pub(crate) async fn handle_eval_suite_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let removed = remove_record(&st.data_dir, KIND_EVAL_SUITE, &id);
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_requirements_gate_fails_closed() {
        // absent / empty → nothing declared, fail closed
        assert!(consent_requirements_usable(&[]).is_err());
        // only never_train → could never assess anything, fail closed
        assert!(consent_requirements_usable(&["never_train".into()]).is_err());
        // unknown rung → fail closed
        assert!(consent_requirements_usable(&["made_up".into()]).is_err());
        // a real admissible rung (even alongside never_train) → usable
        assert!(
            consent_requirements_usable(&["never_train".into(), "synthetic_only".into()]).is_ok()
        );
        assert!(consent_requirements_usable(&["org_policy".into()]).is_ok());
    }

    #[test]
    fn health_is_declared_completeness_not_a_score() {
        assert_eq!(health_of(0), "empty");
        assert_eq!(health_of(3), "declared");
    }

    #[test]
    fn candidate_refs_are_local_handoffs_only() {
        assert!(candidate_ref_ok("eval://c1"));
        assert!(candidate_ref_ok("feedback://fb_123"));
        assert!(candidate_ref_ok("training-candidate://t9"));
        assert!(!candidate_ref_ok("https://external.example/x")); // no external URLs
        assert!(!candidate_ref_ok("eval://")); // scheme with no body
        assert!(!candidate_ref_ok("mission-run://m1")); // scheme not on the allowlist
        assert!(!candidate_ref_ok("just-a-string"));
    }

    #[test]
    fn str_array_rejects_non_strings() {
        assert!(str_array(Some(&json!(["a", "b"]))).is_some());
        assert!(str_array(Some(&json!([]))).is_some());
        assert!(str_array(None).is_some()); // absent = empty, ok
        assert!(str_array(Some(&json!(["a", 3]))).is_none()); // a non-string element is rejected
        assert!(str_array(Some(&json!("scalar"))).is_none());
    }
}
