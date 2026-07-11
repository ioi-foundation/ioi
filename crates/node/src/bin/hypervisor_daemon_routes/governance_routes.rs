//! Governance object plane — FOUNDATION cut (daemon-first, READ PROJECTION only).
//!
//! Governance is a horizontal control lens, not a parallel policy store. This cut builds a single
//! read projection (`overview`) that AGGREGATES real governance substrate the daemon already owns —
//! authority posture/providers/grants/receipts, capability leases, auth policy + principal posture,
//! connector/SCM policy posture, and the authority/policy refs carried by automations, Foundry
//! drafts, ODK manifests and Domain App candidates.
//!
//! Hard boundaries (honesty):
//!   * NO ApprovalRequest / ReleaseControl / KillSwitch tables — none are persisted, so none are
//!     invented; where a control is missing it is named plainly in `governance_gaps`.
//!   * NO release/kill-switch/approval CRUD (no real mutation path exists yet).
//!   * NO Marketplace coupling, NO Domain App runtime mount.
//! It may name gaps, but must never fabricate a control that does not exist.

use std::sync::Arc;

use axum::extract::State;
use axum::extract::{Path as AxumPath, Query};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use super::{iso_now, persist_record, read_record_dir, remove_record, sha256_hex_str, DaemonState};

async fn gj(base: &str, path: &str) -> Value {
    match reqwest::Client::new().get(format!("{base}{path}")).send().await {
        Ok(r) => match r.text().await {
            Ok(t) => serde_json::from_str(&t).unwrap_or(Value::Null),
            Err(_) => Value::Null,
        },
        Err(_) => Value::Null,
    }
}
/// Extract `v[key]` as a Vec of values (empty if absent / not an array).
fn arr(v: &Value, key: &str) -> Vec<Value> {
    v.get(key)
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
}
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
fn histogram(items: &[Value], key: &str) -> HashMap<String, i64> {
    let mut h = HashMap::new();
    for it in items {
        let k = it
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        *h.entry(k).or_insert(0) += 1;
    }
    h
}
/// (total, granted, revoked, active) for authority grants at `now` (unix seconds).
fn grant_stats(grants: &[Value], now: i64) -> (usize, usize, usize, usize) {
    let (mut granted, mut revoked, mut active) = (0usize, 0usize, 0usize);
    for g in grants {
        let dec = g.get("decision").and_then(|v| v.as_str()).unwrap_or("");
        let is_revoked = g.get("revoked").and_then(|v| v.as_bool()).unwrap_or(false);
        if dec == "granted" {
            granted += 1;
        }
        if is_revoked {
            revoked += 1;
        }
        let exp = g.get("expires_at_unix").and_then(|v| v.as_i64()).unwrap_or(0);
        let not_expired = exp == 0 || exp > now;
        if dec == "granted" && !is_revoked && not_expired {
            active += 1;
        }
    }
    (grants.len(), granted, revoked, active)
}
/// (total, active, revoked, receipt_required) for capability leases at `now_ms` (unix millis).
fn lease_stats(leases: &[Value], now_ms: i64) -> (usize, usize, usize, usize) {
    let (mut active, mut revoked, mut receipt_req) = (0usize, 0usize, 0usize);
    for l in leases {
        let is_revoked = l
            .get("revocation_ref")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if is_revoked {
            revoked += 1;
        }
        if l.get("receipt_required").and_then(|v| v.as_bool()).unwrap_or(false) {
            receipt_req += 1;
        }
        let exp = l.get("expires_at").and_then(|v| v.as_i64()).unwrap_or(0);
        let not_expired = exp == 0 || exp > now_ms;
        if !is_revoked && not_expired {
            active += 1;
        }
    }
    (leases.len(), active, revoked, receipt_req)
}
/// Count records (in a kind dir) that declare a non-null value under any of `keys`.
fn count_with_refs(records: &[Value], keys: &[&str]) -> usize {
    records
        .iter()
        .filter(|r| {
            keys.iter().any(|k| {
                r.get(*k).map(|v| {
                    !v.is_null()
                        && v.as_str() != Some("")
                        && v.as_array().map(|a| !a.is_empty()).unwrap_or(true)
                }).unwrap_or(false)
            })
        })
        .count()
}

/// GET /v1/hypervisor/governance/overview — the aggregated governance control lens (read-only).
pub(crate) async fn handle_governance_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let base = st.base_url.clone();
    // Computed governance endpoints (loopback — same truth the rest of the platform serves).
    let posture = gj(&base, "/v1/hypervisor/authority/posture").await;
    let providers = gj(&base, "/v1/hypervisor/authority/providers").await;
    let grants_env = gj(&base, "/v1/hypervisor/authority/grants").await;
    let receipts_env = gj(&base, "/v1/hypervisor/authority/receipts").await;
    let leases_env = gj(&base, "/v1/hypervisor/capability-leases").await;
    let authpol = gj(&base, "/v1/hypervisor/auth/policy").await;
    let whoami = gj(&base, "/v1/hypervisor/auth/whoami").await;
    let connectors = arr(&gj(&base, "/v1/hypervisor/connectors").await, "connectors");
    let scm = arr(&gj(&base, "/v1/hypervisor/scm-connectors").await, "connectors");

    // Durable object kinds (direct read — carry authority/policy refs governance projects over).
    let automations = read_record_dir(&st.data_dir, "automations");
    let foundry_specs = read_record_dir(&st.data_dir, "foundry-specs");
    let foundry_run_plans = read_record_dir(&st.data_dir, "foundry-run-plans");
    let odk_manifests = read_record_dir(&st.data_dir, "odk-manifests");
    let domain_apps = read_record_dir(&st.data_dir, "domain-apps");

    let now = now_unix();
    let grants = arr(&grants_env, "grants");
    let receipts = arr(&receipts_env, "receipts");
    let leases = arr(&leases_env, "leases");
    let crossings = arr(&posture, "wallet_required_crossings");

    let (g_total, g_granted, g_revoked, g_active) = grant_stats(&grants, now);
    let (l_total, l_active, l_revoked, l_receipt) = lease_stats(&leases, now * 1000);
    let receipt_hist = histogram(&receipts, "event");
    let lease_by_provider = histogram(&leases, "backing_provider");
    let spec_by_kind = histogram(&foundry_specs, "kind");
    let connectors_requiring_credential = connectors
        .iter()
        .filter(|c| c.get("requires_credential").and_then(|v| v.as_bool()).unwrap_or(false))
        .count();

    // Policy/authority refs carried by durable objects — what already declares a governance ref
    // (so a future policy plane knows its coverage vs the gaps).
    let policy_ref_coverage = json!({
        "automations_total": automations.len(),
        "automations_with_authority_or_runtime_policy": count_with_refs(&automations, &["authority_policy_ref", "default_runtime_policy_ref"]),
        "foundry_specs_total": foundry_specs.len(),
        "foundry_specs_with_authority_policy": count_with_refs(&foundry_specs, &["authority_policy_ref"]),
        "domain_apps_total": domain_apps.len(),
        "domain_apps_with_authority_requirements": count_with_refs(&domain_apps, &["authority_requirement_refs"]),
        "odk_manifests_total": odk_manifests.len(),
        "odk_manifests_with_operator_contracts": count_with_refs(&odk_manifests, &["mcp_operator_contracts"])
    });

    // ---- Section 1: authority posture.
    let authority_posture = json!({
        "mode": posture.get("mode").cloned().unwrap_or(Value::Null),
        "provider": posture.get("provider").cloned().unwrap_or(Value::Null),
        "active_mode": providers.get("active_mode").cloned().unwrap_or(Value::Null),
        "wallet_network_live": posture.get("wallet_network_live").cloned().unwrap_or(Value::Null),
        "wallet_required_crossings": crossings,
        "standing_grants": arr(&posture, "grants"),
        "providers": arr(&providers, "providers"),
        "grants": { "total": g_total, "granted": g_granted, "revoked": g_revoked, "active": g_active }
    });

    // ---- Section 2: identity posture.
    let identity_posture = json!({
        "deployment_auth_posture": authpol.get("deployment_auth_posture").cloned().unwrap_or(Value::Null),
        "rollout_trust": authpol.get("rollout_trust").cloned().unwrap_or(Value::Null),
        "effective_enforced": authpol.get("effective_enforced").cloned().unwrap_or(Value::Null),
        "exposed": authpol.get("exposed").cloned().unwrap_or(Value::Null),
        "login_possible": authpol.get("login_possible").cloned().unwrap_or(Value::Null),
        "policy": authpol.get("policy").cloned().unwrap_or(Value::Null),
        "current_principal": {
            "authenticated": whoami.get("authenticated").cloned().unwrap_or(Value::Null),
            "role": whoami.get("principal").and_then(|p| p.get("role")).cloned().unwrap_or(Value::Null),
            "status": whoami.get("principal").and_then(|p| p.get("status")).cloned().unwrap_or(Value::Null)
        }
    });

    // ---- Section 3: lease posture.
    let lease_posture = json!({
        "total": l_total,
        "active": l_active,
        "revoked": l_revoked,
        "receipt_required": l_receipt,
        "by_backing_provider": serde_json::to_value(&lease_by_provider).unwrap_or_else(|_| json!({}))
    });

    // ---- Section 4: approval & admission posture. Approvals are represented AS authority grants +
    // wallet-gated crossings; there is no standalone ApprovalRequest object (named in gaps).
    let approval_and_admission_posture = json!({
        "admission_gated_crossings": arr(&posture, "wallet_required_crossings"),
        "admission_gated_crossings_count": crossings.len(),
        "authority_decisions": serde_json::to_value(&receipt_hist).unwrap_or_else(|_| json!({})),
        "connectors_requiring_credential": connectors_requiring_credential,
        "note": "Approvals are represented as authority grants/receipts over wallet-gated crossings; no standalone persisted ApprovalRequest object exists (see governance_gaps)."
    });

    // ---- Section 5: release-control CANDIDATES (things a release gate WOULD govern; none mutated).
    let release_control_candidates = json!({
        "foundry_run_plans": foundry_run_plans.len(),
        "domain_app_candidates": domain_apps.len(),
        "scm_publish_connectors": scm.len(),
        "note": "Promotion (Foundry) and Domain App mount are preview/draft only; SCM publication is a wallet-gated crossing. No ReleaseControl object mutates these yet (see governance_gaps)."
    });

    // ---- Section 6: revocation targets — REAL revocation paths exist for these.
    let revocation_targets = json!({
        "active_authority_grants": g_active,
        "active_capability_leases": l_active,
        "connectors": connectors.len(),
        "scm_connectors": scm.len(),
        "note": "These have real revocation paths (authority revoke / lease revoke / connector disconnect)."
    });

    // ---- Section 7: improvement-gate candidates — bounded-improvement work that a gate WOULD bound.
    let improvement_gate_candidates = json!({
        "foundry_specs_by_kind": serde_json::to_value(&spec_by_kind).unwrap_or_else(|_| json!({})),
        "foundry_run_plans": foundry_run_plans.len(),
        "note": "Foundry tune/eval specs + run plans are bounded-improvement candidates; no formal improvement-gate object exists yet (see governance_gaps)."
    });

    // ---- Section 8: governance gaps — named plainly. has_substrate = the underlying capability
    // exists but is not governed/exposed here; else the control object itself is missing.
    let enforced = authpol.get("effective_enforced").and_then(|v| v.as_bool()).unwrap_or(false);
    let wallet_live = posture.get("wallet_network_live").and_then(|v| v.as_bool()).unwrap_or(false);

    // ---- Control objects (Option A: durable governance truth; record-only, enforcement deferred).
    let approvals = read_record_dir(&st.data_dir, KIND_APPROVAL);
    let releases = read_record_dir(&st.data_dir, KIND_RELEASE);
    let killswitches = read_record_dir(&st.data_dir, KIND_KILL);
    let gates = read_record_dir(&st.data_dir, KIND_GATE);
    let control_objects = json!({
        "approval_requests": { "total": approvals.len(), "by_status": serde_json::to_value(histogram(&approvals, "status")).unwrap_or_else(|_| json!({})) },
        "release_controls": { "total": releases.len(), "by_state": serde_json::to_value(histogram(&releases, "state")).unwrap_or_else(|_| json!({})) },
        "kill_switches": { "total": killswitches.len(), "by_state": serde_json::to_value(histogram(&killswitches, "state")).unwrap_or_else(|_| json!({})) },
        "improvement_gates": { "total": gates.len(), "by_state": serde_json::to_value(histogram(&gates, "state")).unwrap_or_else(|_| json!({})) }
    });
    // The four control-object gaps FLIP from missing-control to present/control-empty now that the
    // plane exists; enforcement is still deferred (record-only). The genuinely-open gaps that remain
    // are the substrate-inactive ones (auth enforcement, wallet network). summary.governance_gaps
    // counts only the still-open gaps, so downstream blocked_reasons stays honest.
    let present = |n: usize| if n > 0 { "present" } else { "control_empty" };
    let pending_approvals = approvals.iter().filter(|a| a.get("status").and_then(|v| v.as_str()) == Some("pending")).count();
    let tripped = killswitches.iter().filter(|k| k.get("state").and_then(|v| v.as_str()) == Some("tripped")).count();
    let governance_gaps = json!([
        { "id": "approval_request_object", "title": "ApprovalRequest control present", "status": present(approvals.len()), "count": approvals.len(), "detail": format!("{} approval request(s) recorded ({} pending). Records only — approval does not execute the action.", approvals.len(), pending_approvals), "has_substrate": true },
        { "id": "release_control_object", "title": "ReleaseControl present", "status": present(releases.len()), "count": releases.len(), "detail": format!("{} release control(s) recorded. Records only — opening a gate does not perform a release.", releases.len()), "has_substrate": true },
        { "id": "kill_switch_object", "title": "KillSwitch present", "status": present(killswitches.len()), "count": killswitches.len(), "detail": format!("{} kill switch(es) recorded ({} tripped). Records only — tripping does not revoke/kill yet.", killswitches.len(), tripped), "has_substrate": true },
        { "id": "improvement_gate_object", "title": "ImprovementGate present", "status": present(gates.len()), "count": gates.len(), "detail": format!("{} improvement gate(s) recorded. Records only — bounds are captured, not enforced.", gates.len()), "has_substrate": true },
        { "id": "auth_enforcement_inactive", "title": "Identity enforcement present but not active", "status": "open", "detail": format!("The IdP/enforcement ring exists but effective_enforced={enforced} in this deployment."), "has_substrate": true },
        { "id": "wallet_network_offline", "title": "Wallet authority network not live", "status": "open", "detail": format!("local_operator mode; wallet_network_live={wallet_live} — portable/delegated authority is not live."), "has_substrate": true }
    ]);
    let open_gaps = governance_gaps.as_array().map(|a| a.iter().filter(|g| g.get("status").and_then(|v| v.as_str()) == Some("open")).count()).unwrap_or(0);

    Json(json!({
        "ok": true,
        "schema_version": "ioi.hypervisor.governance-overview.v1",
        "status_note": "Governance foundation: a read projection over real authority/identity/lease/admission substrate. It surfaces posture, revocation targets, release/improvement candidates, and names missing controls plainly. It creates and mutates nothing.",
        "summary": {
            "authority_grants_active": g_active,
            "authority_grants_total": g_total,
            "capability_leases_active": l_active,
            "capability_leases_total": l_total,
            "wallet_required_crossings": crossings.len(),
            "auth_enforced": enforced,
            "connectors": connectors.len() + scm.len(),
            "automations": automations.len(),
            "odk_manifests": odk_manifests.len(),
            "governance_gaps": open_gaps,
            "control_objects_total": approvals.len() + releases.len() + killswitches.len() + gates.len()
        },
        "authority_posture": authority_posture,
        "identity_posture": identity_posture,
        "lease_posture": lease_posture,
        "approval_and_admission_posture": approval_and_admission_posture,
        "policy_ref_coverage": policy_ref_coverage,
        "release_control_candidates": release_control_candidates,
        "revocation_targets": revocation_targets,
        "improvement_gate_candidates": improvement_gate_candidates,
        "control_objects": control_objects,
        "governance_gaps": governance_gaps
    }))
}

// ============================ CONTROL OBJECTS (Option A: record-only) ===========================
//
// Durable governance control objects. State transitions record governance TRUTH only — they never
// call authority/revoke, lease revoke, connector disconnect, release/apply, publish, mount, rollback,
// or kill endpoints. Each object may carry enforcement_preview / would_call / required_authority_refs
// naming what a later authority-gated crossing WOULD do, but this plane executes none of it.

const KIND_APPROVAL: &str = "governance-approval-requests";
const KIND_APPROVAL_RECEIPT: &str = "governance-approval-transition-receipts";
const KIND_RELEASE: &str = "governance-release-controls";
const KIND_KILL: &str = "governance-kill-switches";
const KIND_GATE: &str = "governance-improvement-gates";
pub(crate) const KIND_COHORT: &str = "governance-cohorts";

fn safe(seg: &str) -> String {
    seg.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_")
}
fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn load(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(
        &std::fs::read(Path::new(data_dir).join(kind).join(format!("{}.json", safe(id)))).ok()?,
    )
    .ok()
}
fn bad(code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}
fn split_ref(r: &str) -> Option<(&str, &str)> {
    r.split_once("://").filter(|(s, rest)| !s.is_empty() && !rest.is_empty())
}
fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key).and_then(|v| v.as_str()).map(str::trim).unwrap_or("")
}
fn str_refs(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string).collect())
        .unwrap_or_default()
}
/// A control target ref is REQUIRED (non-empty). If it LOOKS local (a foundry id or a known local
/// scheme) it must resolve to a real record; otherwise it is an allowed named ref (authority action,
/// connector id, lease id, model route, external target, …).
pub(crate) fn resolve_governance_ref(data_dir: &str, r: &str) -> Result<(), (String, String)> {
    if r.is_empty() {
        return Err(("governance_ref_required".into(), "a target ref is required".into()));
    }
    let unresolved = |scheme: &str| Err(("governance_ref_unresolved".into(), format!("local ref '{r}' does not resolve to a {scheme} record")));
    if r.starts_with("fspec_") {
        return if load(data_dir, "foundry-specs", r).is_some() { Ok(()) } else { unresolved("foundry-spec") };
    }
    if r.starts_with("frun_") {
        return if load(data_dir, "foundry-run-plans", r).is_some() { Ok(()) } else { unresolved("foundry-run-plan") };
    }
    if let Some((scheme, id)) = split_ref(r) {
        let kind = match scheme {
            "marketplace-publish" => Some("marketplace-publish-candidates"),
            "marketplace-listing" => Some("marketplace-listings"),
            "marketplace-admission" => Some("marketplace-admission-reviews"),
            "managed-instance-offer" => Some("marketplace-instance-offers"),
            "domain-app" => Some("domain-apps"),
            "surface-descriptor" => Some("odk-surface-descriptors"),
            "odk" => Some("odk-manifests"),
            "recipe" => Some("odk-data-recipes"),
            "ontology" => Some("odk-domain-ontologies"),
            "approval-request" => Some(KIND_APPROVAL),
            "release-control" => Some(KIND_RELEASE),
            "kill-switch" => Some(KIND_KILL),
            "improvement-gate" => Some(KIND_GATE),
            "cohort" => Some(KIND_COHORT),
            "improvement-proposal" => Some("improvement-proposals"),
            "simulation-report" => Some("simulation-reports"),
            _ => None, // authority-action:// / connector:// / lease:// / route:// / http:// → named
        };
        if let Some(k) = kind {
            if load(data_dir, k, id).is_none() {
                return unresolved(scheme);
            }
        }
    }
    Ok(())
}

// ---- pure state machines (record-only; unit-tested) --------------------------------------------
fn next_approval_status(cur: &str, t: &str) -> Result<&'static str, String> {
    match (cur, t) {
        ("pending", "approve") => Ok("approved"),
        ("pending", "reject") => Ok("rejected"),
        ("approved", "revoke") => Ok("revoked"),
        _ => Err(format!("invalid transition '{t}' from '{cur}' (pending->approve|reject, approved->revoke)")),
    }
}
fn next_kill_state(cur: &str, t: &str) -> Result<&'static str, String> {
    match (cur, t) {
        ("armed", "trip") => Ok("tripped"),
        ("tripped", "rearm") => Ok("armed"),
        _ => Err(format!("invalid transition '{t}' from '{cur}' (armed->trip, tripped->rearm)")),
    }
}
fn next_gate_state(cur: &str, t: &str) -> Result<&'static str, String> {
    match (cur, t) {
        ("open", "bound") => Ok("bounded"),
        ("bounded", "close") => Ok("closed"),
        ("bounded", "reopen") | ("closed", "reopen") => Ok("open"),
        _ => Err(format!("invalid transition '{t}' from '{cur}' (open->bound, bounded->close, ->reopen)")),
    }
}
/// Release transitions: open/close change state; request_rollback/request_recall set a flag (Ok(None)).
fn next_release_state(cur: &str, t: &str) -> Result<Option<&'static str>, String> {
    match (cur, t) {
        ("closed", "open") => Ok(Some("open")),
        ("open", "close") => Ok(Some("closed")),
        (_, "request_rollback") | (_, "request_recall") => Ok(None),
        _ => Err(format!("invalid transition '{t}' from '{cur}' (closed->open, open->close, request_rollback|request_recall)")),
    }
}

fn g_list(data_dir: &str, kind: &str, key: &str) -> Json<Value> {
    let mut items = read_record_dir(data_dir, kind);
    items.sort_by(|a, b| b.get("updated_at").and_then(|v| v.as_str()).unwrap_or("").cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or("")));
    Json(json!({ "ok": true, key: items }))
}
fn g_get(data_dir: &str, kind: &str, key: &str, id: &str) -> Json<Value> {
    match load(data_dir, kind, id) {
        Some(r) => Json(json!({ "ok": true, key: r })),
        None => Json(json!({ "ok": false, "reason": format!("{key} not found") })),
    }
}
fn g_del(data_dir: &str, kind: &str, id: &str) -> Json<Value> {
    let removed = remove_record(data_dir, kind, id);
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}
/// Common optional control fields (enforcement is NAMED, never executed).
fn control_common(body: &Value) -> Value {
    json!({
        "enforcement_preview": body.get("enforcement_preview").cloned().unwrap_or(Value::Null),
        "would_call": body.get("would_call").cloned().unwrap_or_else(|| json!([])),
        "required_authority_refs": str_refs(body, "required_authority_refs")
    })
}

// ---- ApprovalRequest ---------------------------------------------------------------------------
pub(crate) async fn handle_approval_list(State(st): State<Arc<DaemonState>>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_APPROVAL);
    if let Some(s) = q.get("status").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        items.retain(|a| a.get("status").and_then(|v| v.as_str()) == Some(s));
    }
    items.sort_by(|a, b| b.get("updated_at").and_then(|v| v.as_str()).unwrap_or("").cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or("")));
    Json(json!({ "ok": true, "approval_requests": items }))
}
pub(crate) async fn handle_approval_create(State(st): State<Arc<DaemonState>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let subject_ref = str_field(&body, "subject_ref");
    if let Err((c, m)) = resolve_governance_ref(&st.data_dir, subject_ref) {
        return bad(&c, &m);
    }
    let id = format!("appr_{:x}", nanos());
    let now = iso_now();
    let mut record = json!({
        "schema_version": "ioi.hypervisor.governance.approval-request.v1",
        "object": "ioi.hypervisor.governance.approval_request",
        "id": id, "ref": format!("approval-request://{id}"),
        "subject_ref": subject_ref,
        "request_kind": body.get("request_kind").and_then(|v| v.as_str()).unwrap_or(""),
        "reason": body.get("reason").and_then(|v| v.as_str()).unwrap_or(""),
        "status": "pending",
        "reviewer_ref": Value::Null,
        "decided_at": Value::Null,
        "created_at": now, "updated_at": now
    });
    record.as_object_mut().unwrap().extend(control_common(&body).as_object().unwrap().clone());
    let _ = persist_record(&st.data_dir, KIND_APPROVAL, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "approval_request": record })))
}
pub(crate) async fn handle_approval_get(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    g_get(&st.data_dir, KIND_APPROVAL, "approval_request", &id)
}
/// Apply an approval transition to `prev`, producing (updated record, transition receipt).
/// PURE (no I/O): validation happens BEFORE any mutation and a rejected transition returns Err
/// touching nothing. Legacy records without revision/history/receipt_refs migrate lazily here
/// (implicit revision 1, empty history) and stay readable. The receipt carries ONLY record-derived
/// fields + the transition — never request headers, cookies, tokens, or arbitrary form data.
fn apply_approval_transition(
    prev: &Value,
    transition: &str,
    reviewer_ref: Option<&Value>,
    now: &str,
    receipt_id: &str,
) -> Result<(Value, Value), (String, String)> {
    let cur = prev.get("status").and_then(|v| v.as_str()).unwrap_or("pending");
    let next = next_approval_status(cur, transition)
        .map_err(|e| ("governance_transition_invalid".to_string(), e))?;
    let prev_revision = prev.get("revision").and_then(Value::as_u64).unwrap_or(1);
    let revision = prev_revision + 1;
    let receipt_ref = format!("agentgres://governance-approval-transition-receipt/{receipt_id}");
    let receipt = json!({
        "schema_version": "ioi.hypervisor.governance.approval-transition-receipt.v1",
        "object": "ioi.hypervisor.governance.approval_transition_receipt",
        "receipt_id": receipt_id,
        "receipt_ref": receipt_ref.clone(),
        "approval_request_id": prev.get("id").cloned().unwrap_or(Value::Null),
        "approval_request_ref": prev.get("ref").cloned().unwrap_or(Value::Null),
        "subject_ref": prev.get("subject_ref").cloned().unwrap_or(Value::Null),
        "transition": transition,
        "previous_status": cur,
        "resulting_status": next,
        "reviewer_ref": reviewer_ref.cloned().unwrap_or(Value::Null),
        "required_authority_refs": prev.get("required_authority_refs").cloned().unwrap_or_else(|| json!([])),
        "outcome": "ok",
        "at": now,
    });
    let mut a = prev.clone();
    a["status"] = json!(next);
    a["decided_at"] = json!(now);
    if let Some(rv) = reviewer_ref {
        a["reviewer_ref"] = rv.clone();
    }
    a["revision"] = json!(revision);
    let mut hist = a.get("history").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    hist.push(json!({ "revision": revision, "op": transition, "at": now, "summary": format!("{cur} -> {next}"), "receipt_ref": receipt_ref.clone() }));
    if hist.len() > 50 {
        // Bounded history: keep the newest 50 entries (receipts stay durable on disk regardless).
        let cut = hist.len() - 50;
        hist.drain(0..cut);
    }
    a["history"] = Value::Array(hist);
    let mut refs = a.get("receipt_refs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    refs.push(json!(receipt_ref));
    a["receipt_refs"] = Value::Array(refs);
    a["updated_at"] = json!(now);
    Ok((a, receipt))
}

/// Atomic-with-restore finalization. The RECORD persists first (a receipt must never describe a
/// transition that did not persist); the receipt follows; if the receipt write fails, the prior
/// record state is RESTORED with a checked write so a persisted transition never lacks its
/// receipt. Every failure reports — no success claim survives a partial write.
fn finalize_approval_transition(
    data_dir: &str,
    id: &str,
    prev: &Value,
    updated: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), String> {
    persist_record(data_dir, KIND_APPROVAL, id, updated)
        .map_err(|e| format!("approval record persist failed ({e}) — nothing changed"))?;
    match persist_record(data_dir, KIND_APPROVAL_RECEIPT, receipt_id, receipt) {
        Ok(()) => Ok(()),
        Err(e) => match persist_record(data_dir, KIND_APPROVAL, id, prev) {
            Ok(()) => Err(format!("transition receipt persist failed ({e}); the prior record state was restored — nothing changed")),
            Err(e2) => Err(format!("transition receipt persist failed ({e}) AND the record restore failed ({e2}) — manual repair required for approval '{id}'")),
        },
    }
}

pub(crate) async fn handle_approval_patch(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>, Json(body): Json<Value>) -> Json<Value> {
    let Some(mut a) = load(&st.data_dir, KIND_APPROVAL, &id) else {
        return Json(json!({ "ok": false, "reason": "approval_request not found", "error": { "code": "approval_not_found", "message": "approval_request not found" } }));
    };
    // TRANSITION lane (receipted): validate → build record+receipt → finalize atomically-with-
    // restore. A transition request patches NOTHING else in the same call, so the receipt is the
    // whole truth of what changed. A refused transition alters no status/revision/history/refs.
    if let Some(t) = body.get("transition").and_then(|v| v.as_str()) {
        let now = iso_now();
        let receipt_id = format!("atr_{:x}", nanos());
        return match apply_approval_transition(&a, t, body.get("reviewer_ref"), &now, &receipt_id) {
            Ok((updated, receipt)) => match finalize_approval_transition(&st.data_dir, &id, &a, &updated, &receipt_id, &receipt) {
                Ok(()) => Json(json!({ "ok": true, "approval_request": updated, "transition_receipt": receipt })),
                Err(m) => Json(json!({ "ok": false, "error": { "code": "governance_transition_persist_failed", "message": m } })),
            },
            Err((code, message)) => Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
        };
    }
    // Non-transition metadata patch (legacy lane, semantics unchanged: no receipt, no revision bump).
    for key in ["request_kind", "reason", "reviewer_ref", "enforcement_preview", "would_call", "required_authority_refs"] {
        if let Some(v) = body.get(key) { a[key] = v.clone(); }
    }
    a["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_APPROVAL, &id, &a);
    Json(json!({ "ok": true, "approval_request": a }))
}
pub(crate) async fn handle_approval_delete(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    g_del(&st.data_dir, KIND_APPROVAL, &id)
}

// ---- ReleaseControl ----------------------------------------------------------------------------
pub(crate) async fn handle_release_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    g_list(&st.data_dir, KIND_RELEASE, "release_controls")
}
pub(crate) async fn handle_release_create(State(st): State<Arc<DaemonState>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let target = str_field(&body, "release_target_ref");
    if let Err((c, m)) = resolve_governance_ref(&st.data_dir, target) {
        return bad(&c, &m);
    }
    let rollout_mode = { let m = str_field(&body, "rollout_mode"); if m.is_empty() { "full" } else { m } };
    if !["canary", "cohort", "full"].contains(&rollout_mode) {
        return bad("governance_rollout_mode_invalid", "rollout_mode must be canary | cohort | full");
    }
    let canary_percent = body.get("canary_percent").and_then(Value::as_u64).map(|v| v.min(100));
    if rollout_mode == "canary" && canary_percent.is_none() {
        return bad("governance_canary_percent_required", "canary rollout needs canary_percent (0-100)");
    }
    if rollout_mode == "cohort" && str_refs(&body, "cohort_refs").is_empty() {
        return bad("governance_cohort_refs_required", "cohort rollout needs cohort_refs");
    }
    let (cohort_refs, deprecated_raw) = match partition_cohort_refs(&st.data_dir, &str_refs(&body, "cohort_refs")) {
        Ok(parts) => parts,
        Err((code, message)) => return bad(&code, &message),
    };
    let id = format!("rel_{:x}", nanos());
    let now = iso_now();
    let mut record = json!({
        "schema_version": "ioi.hypervisor.governance.release-control.v1",
        "object": "ioi.hypervisor.governance.release_control",
        "id": id, "ref": format!("release-control://{id}"),
        "release_target_ref": target,
        "state": "closed",
        "rollout_mode": rollout_mode,
        "canary_percent": canary_percent.map(|v| json!(v)).unwrap_or(Value::Null),
        "cohort_refs": cohort_refs,
        "deprecated_raw_cohort_refs": deprecated_raw.clone(),
        "cohort_refs_deprecation": if deprecated_raw.is_empty() { Value::Null } else { json!("raw member refs in cohort_refs are DEPRECATED — create a cohort:// object and reference it") },
        "starts_at": body.get("starts_at").cloned().unwrap_or(Value::Null),
        "ends_at": body.get("ends_at").cloned().unwrap_or(Value::Null),
        "rollback_state": Value::Null,
        "promoted_at": Value::Null,
        "rolled_back_at": Value::Null,
        "rollback_requested": false,
        "recall_requested": false,
        "canary": body.get("canary").cloned().unwrap_or(Value::Null),
        "cohort": body.get("cohort").cloned().unwrap_or(Value::Null),
        "created_at": now, "updated_at": now
    });
    record.as_object_mut().unwrap().extend(control_common(&body).as_object().unwrap().clone());
    let _ = persist_record(&st.data_dir, KIND_RELEASE, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "release_control": record })))
}
pub(crate) async fn handle_release_get(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    g_get(&st.data_dir, KIND_RELEASE, "release_control", &id)
}
pub(crate) async fn handle_release_patch(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>, Json(body): Json<Value>) -> Json<Value> {
    let Some(mut r) = load(&st.data_dir, KIND_RELEASE, &id) else {
        return Json(json!({ "ok": false, "reason": "release_control not found" }));
    };
    if let Some(t) = body.get("transition").and_then(|v| v.as_str()) {
        let cur = r.get("state").and_then(|v| v.as_str()).unwrap_or("closed");
        match next_release_state(cur, t) {
            Ok(Some(next)) => r["state"] = json!(next),
            Ok(None) => { if t == "request_rollback" { r["rollback_requested"] = json!(true); } else { r["recall_requested"] = json!(true); } }
            Err(e) => return Json(json!({ "ok": false, "error": { "code": "governance_transition_invalid", "message": e } })),
        }
    }
    if body.get("cohort_refs").is_some() {
        match partition_cohort_refs(&st.data_dir, &str_refs(&body, "cohort_refs")) {
            Ok((cohort_refs, deprecated_raw)) => {
                r["cohort_refs"] = json!(cohort_refs);
                r["deprecated_raw_cohort_refs"] = json!(deprecated_raw.clone());
                r["cohort_refs_deprecation"] = if deprecated_raw.is_empty() { Value::Null } else { json!("raw member refs in cohort_refs are DEPRECATED — create a cohort:// object and reference it") };
            }
            Err((code, message)) => return Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
        }
    }
    for key in ["canary", "cohort", "rollout_mode", "canary_percent", "starts_at", "ends_at", "enforcement_preview", "would_call", "required_authority_refs"] {
        if let Some(v) = body.get(key) { r[key] = v.clone(); }
    }
    r["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_RELEASE, &id, &r);
    Json(json!({ "ok": true, "release_control": r }))
}
pub(crate) async fn handle_release_delete(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    g_del(&st.data_dir, KIND_RELEASE, &id)
}

// ---- Cohorts -----------------------------------------------------------------------------------
//
// Durable rollout audiences. A cohort names WHO a canary/cohort ReleaseControl applies to via
// resolvable member refs (principal:// project:// org:// environment:// ioi-agent-policy://).
// Eligibility is evaluated against DAEMON-DERIVED context, never trusted caller text.

const COHORT_MEMBER_SCHEMES: &[&str] = &["principal", "project", "org", "environment", "ioi-agent-policy"];

/// Split ReleaseControl cohort_refs into (all refs kept as given, deprecated raw member refs).
/// cohort:// entries must resolve; anything else is a DEPRECATED raw member ref (still honored).
fn partition_cohort_refs(data_dir: &str, entries: &[String]) -> Result<(Vec<String>, Vec<String>), (String, String)> {
    let mut deprecated: Vec<String> = Vec::new();
    for entry in entries {
        if let Some(id) = entry.strip_prefix("cohort://") {
            if load(data_dir, KIND_COHORT, id).is_none() {
                return Err(("governance_cohort_unresolved".into(), format!("'{entry}' does not resolve to a recorded cohort")));
            }
        } else {
            deprecated.push(entry.clone());
        }
    }
    Ok((entries.to_vec(), deprecated))
}

fn validate_cohort_members(entries: &[String]) -> Result<(), (String, String)> {
    for entry in entries {
        let scheme = split_ref(entry).map(|(s, _)| s).unwrap_or("");
        if !COHORT_MEMBER_SCHEMES.contains(&scheme) {
            return Err(("governance_cohort_member_ref_invalid".into(), format!("'{entry}' — member refs must use principal:// project:// org:// environment:// ioi-agent-policy://")));
        }
    }
    Ok(())
}

pub(crate) async fn handle_cohort_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    g_list(&st.data_dir, KIND_COHORT, "cohorts")
}
pub(crate) async fn handle_cohort_create(State(st): State<Arc<DaemonState>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let display_name = str_field(&body, "display_name");
    if display_name.is_empty() {
        return bad("governance_cohort_name_required", "a cohort needs a display_name");
    }
    let scope = { let s = str_field(&body, "scope"); if s.is_empty() { "project" } else { s } };
    if !["personal", "project", "org"].contains(&scope) {
        return bad("governance_cohort_scope_invalid", "scope must be personal | project | org");
    }
    let members = str_refs(&body, "member_refs");
    if let Err((code, message)) = validate_cohort_members(&members) {
        return bad(&code, &message);
    }
    let id = format!("coh_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.governance.cohort.v1",
        "object": "ioi.hypervisor.governance.cohort",
        "id": id, "ref": format!("cohort://{id}"),
        "display_name": display_name,
        "description": str_field(&body, "description"),
        "scope": scope,
        "member_refs": members,
        "status": "active",
        "evidence_refs": str_refs(&body, "evidence_refs"),
        "created_at": now, "updated_at": now
    });
    let _ = persist_record(&st.data_dir, KIND_COHORT, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "cohort": record })))
}
pub(crate) async fn handle_cohort_get(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    g_get(&st.data_dir, KIND_COHORT, "cohort", &id)
}
pub(crate) async fn handle_cohort_patch(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>, Json(body): Json<Value>) -> Json<Value> {
    let Some(mut c) = load(&st.data_dir, KIND_COHORT, &id) else {
        return Json(json!({ "ok": false, "reason": "cohort not found" }));
    };
    if let Some(t) = body.get("transition").and_then(Value::as_str) {
        match t {
            "enable" => c["status"] = json!("active"),
            "disable" => c["status"] = json!("disabled"),
            other => return Json(json!({ "ok": false, "error": { "code": "governance_transition_invalid", "message": format!("invalid cohort transition '{other}' (enable | disable)") } })),
        }
    }
    if let Some(status) = body.get("status").and_then(Value::as_str) {
        if !["active", "disabled"].contains(&status) {
            return Json(json!({ "ok": false, "error": { "code": "governance_cohort_status_invalid", "message": "status must be active | disabled" } }));
        }
        c["status"] = json!(status);
    }
    if body.get("member_refs").is_some() {
        let members = str_refs(&body, "member_refs");
        if let Err((code, message)) = validate_cohort_members(&members) {
            return Json(json!({ "ok": false, "error": { "code": code, "message": message } }));
        }
        c["member_refs"] = json!(members);
    }
    for key in ["display_name", "description", "evidence_refs"] {
        if let Some(v) = body.get(key) { c[key] = v.clone(); }
    }
    c["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_COHORT, &id, &c);
    Json(json!({ "ok": true, "cohort": c }))
}
pub(crate) async fn handle_cohort_delete(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    g_del(&st.data_dir, KIND_COHORT, &id)
}

// ---- KillSwitch --------------------------------------------------------------------------------
pub(crate) async fn handle_kill_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    g_list(&st.data_dir, KIND_KILL, "kill_switches")
}
pub(crate) async fn handle_kill_create(State(st): State<Arc<DaemonState>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let subject_ref = str_field(&body, "subject_ref");
    if let Err((c, m)) = resolve_governance_ref(&st.data_dir, subject_ref) {
        return bad(&c, &m);
    }
    let id = format!("kill_{:x}", nanos());
    let now = iso_now();
    let mut record = json!({
        "schema_version": "ioi.hypervisor.governance.kill-switch.v1",
        "object": "ioi.hypervisor.governance.kill_switch",
        "id": id, "ref": format!("kill-switch://{id}"),
        "subject_ref": subject_ref,
        // The revoke/disable path this switch WOULD call at enforcement time (named, not called).
        "revoke_path": body.get("revoke_path").and_then(|v| v.as_str()).unwrap_or(""),
        "state": "armed",
        "trip_reason": Value::Null,
        "tripped_at": Value::Null,
        "created_at": now, "updated_at": now
    });
    record.as_object_mut().unwrap().extend(control_common(&body).as_object().unwrap().clone());
    let _ = persist_record(&st.data_dir, KIND_KILL, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "kill_switch": record })))
}
pub(crate) async fn handle_kill_get(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    g_get(&st.data_dir, KIND_KILL, "kill_switch", &id)
}
pub(crate) async fn handle_kill_patch(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>, Json(body): Json<Value>) -> Json<Value> {
    let Some(mut k) = load(&st.data_dir, KIND_KILL, &id) else {
        return Json(json!({ "ok": false, "reason": "kill_switch not found" }));
    };
    if let Some(t) = body.get("transition").and_then(|v| v.as_str()) {
        let cur = k.get("state").and_then(|v| v.as_str()).unwrap_or("armed");
        match next_kill_state(cur, t) {
            Ok(next) => {
                k["state"] = json!(next);
                if next == "tripped" {
                    k["tripped_at"] = json!(iso_now());
                    k["trip_reason"] = json!(body.get("trip_reason").and_then(|v| v.as_str()).unwrap_or(""));
                } else {
                    k["tripped_at"] = Value::Null;
                    k["trip_reason"] = Value::Null;
                }
            }
            Err(e) => return Json(json!({ "ok": false, "error": { "code": "governance_transition_invalid", "message": e } })),
        }
    }
    for key in ["subject_ref", "revoke_path", "enforcement_preview", "would_call", "required_authority_refs"] {
        if let Some(v) = body.get(key) { k[key] = v.clone(); }
    }
    k["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_KILL, &id, &k);
    Json(json!({ "ok": true, "kill_switch": k }))
}
pub(crate) async fn handle_kill_delete(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    g_del(&st.data_dir, KIND_KILL, &id)
}

const KIND_KILL_ENFORCE_RECEIPT: &str = "governance-kill-enforcement-receipts";

/// POST /v1/hypervisor/governance/kill-switches/:id/enforce — effectful enforcement (AFTER trip).
/// This cut enforces ONLY domain-app runtime targets: it stops serving + unmounts the matching
/// runtime(s) via the shared runtime logic (consistent receipts/state), records the outcome on the
/// KillSwitch, and emits an enforcement receipt even for a no-op. It does NOT revoke wallet grants,
/// leases, connectors, environments, workers, or anything outside the Domain-App runtime target.
pub(crate) async fn handle_kill_enforce(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut k) = load(&st.data_dir, KIND_KILL, &id) else {
        return bad("kill_switch_not_found", "kill switch not found");
    };
    if k.get("state").and_then(|v| v.as_str()) != Some("tripped") {
        return bad("kill_switch_not_tripped", "KillSwitch must be tripped before it can be enforced");
    }
    let subject = k.get("subject_ref").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let supported = subject.starts_with("domain-app-runtime://") || subject.starts_with("domain-app://");
    if !supported {
        return bad(
            "kill_target_unsupported",
            "this enforcement cut supports only 'domain-app-runtime://' or 'domain-app://' targets",
        );
    }
    let runtimes = super::domain_apps_routes::runtimes_for_kill_target(&st.data_dir, &subject);
    let now = iso_now();
    let mut affected: Vec<String> = Vec::new();
    let mut receipt_refs: Vec<String> = Vec::new();
    for rt in &runtimes {
        if let Some(r) = rt.get("ref").and_then(|v| v.as_str()) {
            affected.push(r.to_string());
        }
        receipt_refs.extend(super::domain_apps_routes::kill_enforce_runtime(&st.data_dir, rt));
    }
    let enforcement_state = if runtimes.is_empty() { "noop" } else { "enforced" };
    // Emit a governance enforcement receipt even for a no-op (proof, never silent).
    let erid = format!("kille_{:x}", nanos());
    let state_root = sha256_hex_str(&format!("kill_enforce|{}|{subject}|{}|{now}", k.get("ref").and_then(|v| v.as_str()).unwrap_or(""), affected.join(",")));
    let ereceipt = json!({
        "schema_version": "ioi.hypervisor.governance.kill-enforcement-receipt.v1",
        "object": "ioi.hypervisor.governance.kill_enforcement_receipt",
        "id": erid, "ref": format!("kill-enforcement-receipt://{erid}"),
        "kill_switch_ref": k.get("ref").cloned().unwrap_or(Value::Null),
        "subject_ref": subject,
        "enforcement_state": enforcement_state,
        "affected_runtime_refs": affected.clone(),
        "state_root": format!("sha256:{state_root}"),
        "at": now
    });
    let _ = persist_record(&st.data_dir, KIND_KILL_ENFORCE_RECEIPT, &erid, &ereceipt);
    receipt_refs.push(format!("kill-enforcement-receipt://{erid}"));
    let result = if enforcement_state == "enforced" {
        format!("stopped/unmounted {} runtime(s)", runtimes.len())
    } else {
        "no active runtime for target".to_string()
    };
    k["enforced_at"] = json!(now);
    k["enforcement_state"] = json!(enforcement_state);
    k["enforcement_result"] = json!(result);
    k["affected_runtime_refs"] = json!(affected);
    k["enforcement_receipt_refs"] = json!(receipt_refs);
    k["last_enforcement_error"] = Value::Null;
    k["updated_at"] = json!(now);
    let _ = persist_record(&st.data_dir, KIND_KILL, &id, &k);
    (StatusCode::CREATED, Json(json!({ "ok": true, "kill_switch": k, "enforcement_receipt": ereceipt })))
}

// ---- ImprovementGate ---------------------------------------------------------------------------
pub(crate) async fn handle_gate_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    g_list(&st.data_dir, KIND_GATE, "improvement_gates")
}
pub(crate) async fn handle_gate_create(State(st): State<Arc<DaemonState>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let subject_ref = str_field(&body, "subject_ref");
    if let Err((c, m)) = resolve_governance_ref(&st.data_dir, subject_ref) {
        return bad(&c, &m);
    }
    let id = format!("impg_{:x}", nanos());
    let now = iso_now();
    let bounds = body.get("bounds").cloned().unwrap_or_else(|| {
        json!({
            "max_iterations": body.get("max_iterations").cloned().unwrap_or(Value::Null),
            "eval_threshold": body.get("eval_threshold").cloned().unwrap_or(Value::Null),
            "privacy_posture": body.get("privacy_posture").cloned().unwrap_or(Value::Null),
            "rollback_ref": body.get("rollback_ref").cloned().unwrap_or(Value::Null),
            "promotion_policy_ref": body.get("promotion_policy_ref").cloned().unwrap_or(Value::Null)
        })
    });
    let mut record = json!({
        "schema_version": "ioi.hypervisor.governance.improvement-gate.v1",
        "object": "ioi.hypervisor.governance.improvement_gate",
        "id": id, "ref": format!("improvement-gate://{id}"),
        "subject_ref": subject_ref,
        "state": "open",
        "bounds": bounds,
        "created_at": now, "updated_at": now
    });
    record.as_object_mut().unwrap().extend(control_common(&body).as_object().unwrap().clone());
    let _ = persist_record(&st.data_dir, KIND_GATE, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "improvement_gate": record })))
}
pub(crate) async fn handle_gate_get(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    g_get(&st.data_dir, KIND_GATE, "improvement_gate", &id)
}
pub(crate) async fn handle_gate_patch(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>, Json(body): Json<Value>) -> Json<Value> {
    let Some(mut g) = load(&st.data_dir, KIND_GATE, &id) else {
        return Json(json!({ "ok": false, "reason": "improvement_gate not found" }));
    };
    if let Some(t) = body.get("transition").and_then(|v| v.as_str()) {
        let cur = g.get("state").and_then(|v| v.as_str()).unwrap_or("open");
        match next_gate_state(cur, t) {
            Ok(next) => g["state"] = json!(next),
            Err(e) => return Json(json!({ "ok": false, "error": { "code": "governance_transition_invalid", "message": e } })),
        }
    }
    for key in ["bounds", "enforcement_preview", "would_call", "required_authority_refs"] {
        if let Some(v) = body.get(key) { g[key] = v.clone(); }
    }
    g["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, KIND_GATE, &id, &g);
    Json(json!({ "ok": true, "improvement_gate": g }))
}
pub(crate) async fn handle_gate_delete(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    g_del(&st.data_dir, KIND_GATE, &id)
}

#[cfg(test)]
mod governance_tests {
    use super::*;

    #[test]
    fn approval_transitions_valid_and_invalid() {
        assert_eq!(next_approval_status("pending", "approve").unwrap(), "approved");
        assert_eq!(next_approval_status("pending", "reject").unwrap(), "rejected");
        assert_eq!(next_approval_status("approved", "revoke").unwrap(), "revoked");
        assert!(next_approval_status("approved", "approve").is_err());
        assert!(next_approval_status("rejected", "revoke").is_err());
        assert!(next_approval_status("pending", "publish").is_err());
    }

    fn legacy_pending() -> Value {
        // A pre-#62 record: no revision / history / receipt_refs fields (lazy-migration input).
        json!({
            "id": "appr_t1", "ref": "approval-request://appr_t1",
            "subject_ref": "automation://a1", "request_kind": "test", "reason": "r",
            "status": "pending", "reviewer_ref": Value::Null, "decided_at": Value::Null,
            "required_authority_refs": ["authority://x"],
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
        })
    }

    #[test]
    fn approval_transition_accepted_builds_record_and_receipt() {
        let prev = legacy_pending();
        let (a, r) = apply_approval_transition(&prev, "approve", Some(&json!("agent://rev")), "2026-02-01T00:00:00Z", "atr_test1").unwrap();
        // Record: status, decided, reviewer, revision bumped EXACTLY once (legacy 1 -> 2),
        // one history entry, one receipt ref — all pointing at the same receipt.
        assert_eq!(a["status"], json!("approved"));
        assert_eq!(a["revision"], json!(2));
        assert_eq!(a["reviewer_ref"], json!("agent://rev"));
        let hist = a["history"].as_array().unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0]["op"], json!("approve"));
        assert_eq!(hist[0]["revision"], json!(2));
        let refs = a["receipt_refs"].as_array().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], r["receipt_ref"]);
        assert_eq!(hist[0]["receipt_ref"], r["receipt_ref"]);
        // Receipt: full transition truth, nothing else.
        assert_eq!(r["approval_request_id"], json!("appr_t1"));
        assert_eq!(r["subject_ref"], json!("automation://a1"));
        assert_eq!(r["transition"], json!("approve"));
        assert_eq!(r["previous_status"], json!("pending"));
        assert_eq!(r["resulting_status"], json!("approved"));
        assert_eq!(r["outcome"], json!("ok"));
        // EXACT key set — request headers/cookies/tokens/arbitrary form data can never leak in.
        let mut keys: Vec<&str> = r.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["approval_request_id", "approval_request_ref", "at", "object", "outcome", "previous_status", "receipt_id", "receipt_ref", "required_authority_refs", "resulting_status", "reviewer_ref", "schema_version", "subject_ref", "transition"]);
    }

    #[test]
    fn approval_transition_refused_touches_nothing_and_duplicates_refuse() {
        let prev = legacy_pending();
        let (approved, _r1) = apply_approval_transition(&prev, "approve", None, "2026-02-01T00:00:00Z", "atr_a").unwrap();
        // Duplicate approve on the already-approved record: typed refusal, zero mutation.
        let err = apply_approval_transition(&approved, "approve", None, "2026-02-02T00:00:00Z", "atr_b").unwrap_err();
        assert_eq!(err.0, "governance_transition_invalid");
        // Pure fn: the input record is untouched by a refusal (revision/history/refs intact).
        assert_eq!(approved["revision"], json!(2));
        assert_eq!(approved["history"].as_array().unwrap().len(), 1);
        assert_eq!(approved["receipt_refs"].as_array().unwrap().len(), 1);
        // Unknown vocabulary refuses too.
        assert!(apply_approval_transition(&prev, "escalate", None, "t", "atr_c").is_err());
    }

    #[test]
    fn approval_history_is_bounded() {
        let mut rec = legacy_pending();
        let mut hist = Vec::new();
        for i in 0..60 {
            hist.push(json!({ "revision": i, "op": "seed", "at": "t", "summary": "s", "receipt_ref": format!("agentgres://x/{i}") }));
        }
        rec["history"] = Value::Array(hist);
        let (a, _r) = apply_approval_transition(&rec, "approve", None, "t2", "atr_bound").unwrap();
        let h = a["history"].as_array().unwrap();
        assert_eq!(h.len(), 50, "history is bounded to the newest 50 entries");
        assert_eq!(h.last().unwrap()["op"], json!("approve"), "the newest entry is the accepted transition");
    }

    #[test]
    fn approval_finalize_restores_prior_state_when_receipt_persist_fails() {
        // Real tempdir; the receipt KIND path is pre-created as a FILE so create_dir_all fails —
        // the injected persistence failure. The record must be RESTORED to its prior bytes.
        let dir = std::env::temp_dir().join(format!("ioi-appr-final-{:x}", nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let data_dir = dir.to_str().unwrap();
        let prev = legacy_pending();
        persist_record(data_dir, KIND_APPROVAL, "appr_t1", &prev).unwrap();
        let (updated, receipt) = apply_approval_transition(&prev, "approve", None, "t", "atr_fail").unwrap();
        // Block the receipts dir: a plain file where the directory must go.
        std::fs::write(dir.join(KIND_APPROVAL_RECEIPT), b"blocker").unwrap();
        let err = finalize_approval_transition(data_dir, "appr_t1", &prev, &updated, "atr_fail", &receipt).unwrap_err();
        assert!(err.contains("restored"), "failure names the restore: {err}");
        let on_disk = load(data_dir, KIND_APPROVAL, "appr_t1").unwrap();
        assert_eq!(on_disk["status"], json!("pending"), "the transition did not survive the receipt failure");
        assert!(on_disk.get("revision").is_none(), "no revision bump survived");
        // And the happy path works once the blocker is gone: record + receipt both persist.
        std::fs::remove_file(dir.join(KIND_APPROVAL_RECEIPT)).unwrap();
        finalize_approval_transition(data_dir, "appr_t1", &prev, &updated, "atr_fail", &receipt).unwrap();
        assert_eq!(load(data_dir, KIND_APPROVAL, "appr_t1").unwrap()["status"], json!("approved"));
        assert_eq!(load(data_dir, KIND_APPROVAL_RECEIPT, "atr_fail").unwrap()["transition"], json!("approve"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kill_and_gate_and_release_transitions() {
        assert_eq!(next_kill_state("armed", "trip").unwrap(), "tripped");
        assert_eq!(next_kill_state("tripped", "rearm").unwrap(), "armed");
        assert!(next_kill_state("armed", "rearm").is_err());
        assert_eq!(next_gate_state("open", "bound").unwrap(), "bounded");
        assert_eq!(next_gate_state("bounded", "close").unwrap(), "closed");
        assert_eq!(next_gate_state("closed", "reopen").unwrap(), "open");
        assert!(next_gate_state("open", "close").is_err());
        assert_eq!(next_release_state("closed", "open").unwrap(), Some("open"));
        assert_eq!(next_release_state("open", "close").unwrap(), Some("closed"));
        assert_eq!(next_release_state("open", "request_rollback").unwrap(), None); // flag, no state change
        assert!(next_release_state("closed", "close").is_err());
    }

    #[test]
    fn resolve_governance_ref_named_vs_local() {
        // named refs (no scheme / unknown scheme) are allowed without resolution
        assert!(resolve_governance_ref("/nonexistent", "authority-action://spend").is_ok());
        assert!(resolve_governance_ref("/nonexistent", "connector:conn_123").is_ok());
        assert!(resolve_governance_ref("/nonexistent", "lease_abc").is_ok());
        // required (empty) rejected
        assert_eq!(resolve_governance_ref("/nonexistent", "").unwrap_err().0, "governance_ref_required");
        // local-looking (foundry id / known scheme) must resolve -> unresolved in an empty dir
        assert_eq!(resolve_governance_ref("/nonexistent", "frun_x").unwrap_err().0, "governance_ref_unresolved");
        assert_eq!(resolve_governance_ref("/nonexistent", "domain-app://dapp_x").unwrap_err().0, "governance_ref_unresolved");
        assert_eq!(resolve_governance_ref("/nonexistent", "marketplace-publish://mpub_x").unwrap_err().0, "governance_ref_unresolved");
    }

    #[test]
    fn grant_stats_counts_granted_revoked_active() {
        let now = 1_000_000i64;
        let grants = vec![
            json!({ "decision": "granted", "revoked": false, "expires_at_unix": now + 1000 }), // active
            json!({ "decision": "granted", "revoked": true, "expires_at_unix": now + 1000 }),  // revoked
            json!({ "decision": "granted", "revoked": false, "expires_at_unix": now - 1000 }), // expired
            json!({ "decision": "granted", "revoked": false, "expires_at_unix": 0 }),          // active (no expiry)
            json!({ "decision": "denied", "revoked": false }),                                  // not granted
        ];
        let (total, granted, revoked, active) = grant_stats(&grants, now);
        assert_eq!(total, 5);
        assert_eq!(granted, 4);
        assert_eq!(revoked, 1);
        assert_eq!(active, 2); // rows 1 and 4
    }

    #[test]
    fn lease_stats_counts_active_revoked_receipt() {
        let now_ms = 1_000_000i64;
        let leases = vec![
            json!({ "expires_at": now_ms + 5000, "receipt_required": true }),                    // active + receipt
            json!({ "expires_at": now_ms + 5000, "revocation_ref": "rev_1" }),                    // revoked
            json!({ "expires_at": now_ms - 5000 }),                                               // expired
            json!({ "expires_at": 0, "receipt_required": false }),                                // active (no expiry)
        ];
        let (total, active, revoked, receipt) = lease_stats(&leases, now_ms);
        assert_eq!(total, 4);
        assert_eq!(active, 2); // rows 0 and 3
        assert_eq!(revoked, 1);
        assert_eq!(receipt, 1);
    }

    #[test]
    fn histogram_groups_by_key() {
        let items = vec![
            json!({ "event": "granted" }),
            json!({ "event": "granted" }),
            json!({ "event": "revoked" }),
            json!({}),
        ];
        let h = histogram(&items, "event");
        assert_eq!(h.get("granted"), Some(&2));
        assert_eq!(h.get("revoked"), Some(&1));
        assert_eq!(h.get("unknown"), Some(&1));
    }

    #[test]
    fn count_with_refs_detects_declared_refs() {
        let recs = vec![
            json!({ "authority_policy_ref": "policy.a" }),
            json!({ "authority_policy_ref": Value::Null }),
            json!({ "authority_policy_ref": "" }),
            json!({ "other": 1 }),
        ];
        assert_eq!(count_with_refs(&recs, &["authority_policy_ref"]), 1);
    }
}
