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
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use super::{iso_now, persist_record, read_record_dir, remove_record, sha256_hex_str, DaemonState};

/// Posture- and principal-bearing headers. `handle_auth_policy_get` computes
/// `deployment_auth_posture` FROM the inbound headers, so a header-less loopback
/// made the Governance overview report `local_development` (and
/// `explicit_override_allowed: true`) on an exposed instance. That is a
/// truth-reporting defect: the lens that exists to show the authority posture was
/// showing the loopback's posture instead of the deployment's.
const FORWARDED_AUTH_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "x-forwarded-host",
    "x-forwarded-for",
    "x-ioi-forwarded",
];

async fn gj(base: &str, path: &str, inbound: &axum::http::HeaderMap) -> Value {
    let mut req = reqwest::Client::new().get(format!("{base}{path}"));
    for name in FORWARDED_AUTH_HEADERS {
        if let Some(value) = inbound.get(*name).and_then(|v| v.to_str().ok()) {
            req = req.header(*name, value);
        }
    }
    match req.send().await {
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
        let exp = g
            .get("expires_at_unix")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
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
        if l.get("receipt_required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
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
                r.get(*k)
                    .map(|v| {
                        !v.is_null()
                            && v.as_str() != Some("")
                            && v.as_array().map(|a| !a.is_empty()).unwrap_or(true)
                    })
                    .unwrap_or(false)
            })
        })
        .count()
}

/// GET /v1/hypervisor/governance/overview — the aggregated governance control lens (read-only).
pub(crate) async fn handle_governance_overview(
    State(st): State<Arc<DaemonState>>,
    inbound: axum::http::HeaderMap,
) -> Json<Value> {
    let base = st.base_url.clone();
    // Computed governance endpoints (loopback — same truth the rest of the platform serves).
    let posture = gj(&base, "/v1/hypervisor/authority/posture", &inbound).await;
    let providers = gj(&base, "/v1/hypervisor/authority/providers", &inbound).await;
    let grants_env = gj(&base, "/v1/hypervisor/authority/grants", &inbound).await;
    let receipts_env = gj(&base, "/v1/hypervisor/authority/receipts", &inbound).await;
    let leases_env = gj(&base, "/v1/hypervisor/capability-leases", &inbound).await;
    let authpol = gj(&base, "/v1/hypervisor/auth/policy", &inbound).await;
    let whoami = gj(&base, "/v1/hypervisor/auth/whoami", &inbound).await;
    let connectors = arr(
        &gj(&base, "/v1/hypervisor/connectors", &inbound).await,
        "connectors",
    );
    let scm = arr(
        &gj(&base, "/v1/hypervisor/scm-connectors", &inbound).await,
        "connectors",
    );

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
        .filter(|c| {
            c.get("requires_credential")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
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
    let enforced = authpol
        .get("effective_enforced")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let wallet_live = posture
        .get("wallet_network_live")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

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
    let pending_approvals = approvals
        .iter()
        .filter(|a| a.get("status").and_then(|v| v.as_str()) == Some("pending"))
        .count();
    let tripped = killswitches
        .iter()
        .filter(|k| k.get("state").and_then(|v| v.as_str()) == Some("tripped"))
        .count();
    let governance_gaps = json!([
        { "id": "approval_request_object", "title": "ApprovalRequest control present", "status": present(approvals.len()), "count": approvals.len(), "detail": format!("{} approval request(s) recorded ({} pending). Records only — approval does not execute the action.", approvals.len(), pending_approvals), "has_substrate": true },
        { "id": "release_control_object", "title": "ReleaseControl present", "status": present(releases.len()), "count": releases.len(), "detail": format!("{} release control(s) recorded. Records only — opening a gate does not perform a release.", releases.len()), "has_substrate": true },
        { "id": "kill_switch_object", "title": "KillSwitch present", "status": present(killswitches.len()), "count": killswitches.len(), "detail": format!("{} kill switch(es) recorded ({} tripped). Records only — tripping does not revoke/kill yet.", killswitches.len(), tripped), "has_substrate": true },
        { "id": "improvement_gate_object", "title": "ImprovementGate present", "status": present(gates.len()), "count": gates.len(), "detail": format!("{} improvement gate(s) recorded. Records only — bounds are captured, not enforced.", gates.len()), "has_substrate": true },
        { "id": "auth_enforcement_inactive", "title": "Identity enforcement present but not active", "status": "open", "detail": format!("The IdP/enforcement ring exists but effective_enforced={enforced} in this deployment."), "has_substrate": true },
        { "id": "wallet_network_offline", "title": "Wallet authority network not live", "status": "open", "detail": format!("local_operator mode; wallet_network_live={wallet_live} — portable/delegated authority is not live."), "has_substrate": true }
    ]);
    let open_gaps = governance_gaps
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|g| g.get("status").and_then(|v| v.as_str()) == Some("open"))
                .count()
        })
        .unwrap_or(0);

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
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}
fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn load(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(
        &std::fs::read(
            Path::new(data_dir)
                .join(kind)
                .join(format!("{}.json", safe(id))),
        )
        .ok()?,
    )
    .ok()
}
fn bad(code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}
/// A governance control write that did not durably land, for the handlers that carry status codes.
///
/// These records are read back as authority. `handle_kill_enforce` reloads the KillSwitch and
/// refuses unless `state == "tripped"`, so a trip returned over a discarded write reported the
/// switch tripped while the record stayed `armed` — and enforcement would then refuse it with
/// `kill_switch_not_tripped`. A control that reports engaged and cannot be enforced is worse than
/// one that reports its failure.
fn governance_persist_failed(control: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "ok": false, "error": {
            "code": "governance_persistence_failed",
            "message": format!("the {control} could not be durably recorded and is NOT in force")
        }})),
    )
}
/// Same, for the patch handlers, whose whole failure convention is a 200-shaped `ok:false`.
fn governance_persist_failed_json(control: &str) -> Json<Value> {
    Json(json!({ "ok": false, "error": {
        "code": "governance_persistence_failed",
        "message": format!("the {control} change could not be durably recorded and is NOT in force")
    }}))
}
fn split_ref(r: &str) -> Option<(&str, &str)> {
    r.split_once("://")
        .filter(|(s, rest)| !s.is_empty() && !rest.is_empty())
}
fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("")
}
fn str_refs(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
/// A control target ref is REQUIRED (non-empty). If it LOOKS local (a foundry id or a known local
/// scheme) it must resolve to a real record; otherwise it is an allowed named ref (authority action,
/// connector id, lease id, model route, external target, …).
pub(crate) fn resolve_governance_ref(data_dir: &str, r: &str) -> Result<(), (String, String)> {
    if r.is_empty() {
        return Err((
            "governance_ref_required".into(),
            "a target ref is required".into(),
        ));
    }
    let unresolved = |scheme: &str| {
        Err((
            "governance_ref_unresolved".into(),
            format!("local ref '{r}' does not resolve to a {scheme} record"),
        ))
    };
    if r.starts_with("fspec_") {
        return if load(data_dir, "foundry-specs", r).is_some() {
            Ok(())
        } else {
            unresolved("foundry-spec")
        };
    }
    if r.starts_with("frun_") {
        return if load(data_dir, "foundry-run-plans", r).is_some() {
            Ok(())
        } else {
            unresolved("foundry-run-plan")
        };
    }
    if let Some((scheme, id)) = split_ref(r) {
        let kind = match scheme {
            "marketplace-publish" => Some("marketplace-publish-candidates"),
            "marketplace-listing" => Some("marketplace-listings"),
            "marketplace-admission" => Some("marketplace-admission-reviews"),
            "managed-instance-offer" => Some("marketplace-instance-offers"),
            "domain-app" => Some("domain-apps"),
            // Studio blueprint promotion (OQ-11): `blueprint://` LOOKS local and IS local, so it
            // must resolve to a stored blueprint — without this arm it would fall through as an
            // unvalidated named ref and an approval could be minted for a blueprint that does not
            // exist.
            "blueprint" => Some(super::studio_routes::KIND_BLUEPRINT),
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
        _ => Err(format!(
            "invalid transition '{t}' from '{cur}' (pending->approve|reject, approved->revoke)"
        )),
    }
}
fn next_kill_state(cur: &str, t: &str) -> Result<&'static str, String> {
    match (cur, t) {
        ("armed", "trip") => Ok("tripped"),
        ("tripped", "rearm") => Ok("armed"),
        _ => Err(format!(
            "invalid transition '{t}' from '{cur}' (armed->trip, tripped->rearm)"
        )),
    }
}
fn next_gate_state(cur: &str, t: &str) -> Result<&'static str, String> {
    match (cur, t) {
        ("open", "bound") => Ok("bounded"),
        ("bounded", "close") => Ok("closed"),
        ("bounded", "reopen") | ("closed", "reopen") => Ok("open"),
        _ => Err(format!(
            "invalid transition '{t}' from '{cur}' (open->bound, bounded->close, ->reopen)"
        )),
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
    items.sort_by(|a, b| {
        b.get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
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
pub(crate) async fn handle_approval_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_APPROVAL);
    if let Some(s) = q.get("status").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        items.retain(|a| a.get("status").and_then(|v| v.as_str()) == Some(s));
    }
    items.sort_by(|a, b| {
        b.get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(json!({ "ok": true, "approval_requests": items }))
}
pub(crate) async fn handle_approval_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
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
    record
        .as_object_mut()
        .unwrap()
        .extend(control_common(&body).as_object().unwrap().clone());
    if persist_record(&st.data_dir, KIND_APPROVAL, &id, &record).is_err() {
        return governance_persist_failed("approval");
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "approval_request": record })),
    )
}
pub(crate) async fn handle_approval_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    g_get(&st.data_dir, KIND_APPROVAL, "approval_request", &id)
}
// ---- reviewer attribution (GOV-ATTR-1) ---------------------------------------------------------
//
// A governance decision's reviewer is WHO DECIDED. Attribution a client can choose is not
// attribution at all: the transition receipt is read back as durable proof of who approved, so a
// request-carried `reviewer_ref` let any caller sign a decision as anyone. Canon
// (`identity-access-and-metering.md`) rules that a request body never selects the acting
// principal — the server-resolved authenticated principal is the only admissible reviewer.
//
// Three rules, all fail-closed:
//   1. A request-carried identity field is REFUSED, never ignored. Silently dropping one would let
//      a caller believe it had attributed the decision while the record said otherwise, and the
//      surfaces that send one today would go on lying instead of being fixed.
//   2. The reviewer is resolved server-side through the canonical request-identity seam. That
//      holds even where the deployment's broad auth posture is permissive: `resolve_principal`
//      mints nothing for an unauthenticated request, so no posture can produce an anonymous
//      governance reviewer.
//   3. Authorization is settled BEFORE the target record is read. Loading first would make this
//      route an unauthenticated record-existence oracle: a missing id answers "not found" while a
//      real one answers 401, so an anonymous caller could enumerate which approval ids exist by
//      reading the difference. Whether a governance record exists is itself privileged.

/// A typed refusal as DATA (status + stable code + message) rather than a rendered response, so
/// the gates below stay pure and unit-testable without constructing an axum request.
type GovernanceRefusal = (StatusCode, String, String);

fn refused(r: GovernanceRefusal) -> (StatusCode, Json<Value>) {
    let (status, code, message) = r;
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}

/// Identity/attribution fields the SERVER owns. A request that carries any of them is trying to
/// name who acted, which canon forbids outright: "Request bodies never select the acting principal,
/// owner, role, or authority." Every name here is a real attribution field in this estate's code or
/// canon — `reviewer_ref` is what this record and its receipt carry, `principal_ref` is what the
/// identity seam resolves, `acting_principal_ref`/`is_impersonated` are what `resolve_principal`
/// sets on an impersonated request, `changed_by_principal_ref` is canon's named actor field on
/// transition receipts, and `actor_ref` is the estate's generic actor name. This is deliberately
/// NOT a guess-list: an invented name would refuse a field nothing writes, and `required_authority_refs`
/// is excluded on purpose — it names WHAT authority a crossing needs, never WHO is acting, and it
/// stays a legitimately patchable metadata field.
const CLIENT_PROHIBITED_IDENTITY_FIELDS: &[&str] = &[
    "reviewer_ref",
    "principal_ref",
    "acting_principal_ref",
    "changed_by_principal_ref",
    "actor_ref",
    "is_impersonated",
];

/// PURE request gate: a client may never name who acted. Refuses on the KEY BEING PRESENT, not on
/// its value, so `null`, `""`, and a value that happens to match the caller are refused alike.
/// "Accept it when it matches" would make the check depend on the very identity the request is
/// trying to assert, and would leave forged attribution one impersonation away from working.
/// Runs before identity resolution AND before the record load, so a forged patch reaches no
/// identity substrate, no record, and no transition builder.
fn reject_client_supplied_identity(body: &Value) -> Result<(), GovernanceRefusal> {
    let Some(field) = CLIENT_PROHIBITED_IDENTITY_FIELDS
        .iter()
        .find(|field| body.get(**field).is_some())
    else {
        return Ok(());
    };
    Err((
        StatusCode::BAD_REQUEST,
        "governance_reviewer_ref_not_client_settable".to_string(),
        format!(
            "'{field}' is derived from the authenticated caller and cannot be supplied by the \
             request; remove it and re-send"
        ),
    ))
}

/// PURE: carry the identity seam's own refusal out under its own code, choosing the status that
/// keeps the failure modes distinguishable. A missing/unresolvable principal is 401 ("authenticate"),
/// substrate trouble is 503 ("ask again"). Collapsing 503 into 401 would tell an already-authenticated
/// operator to log in again while identity storage was simply down — and collapsing 401 into 503
/// would invite a retry loop around a request that can never succeed as sent.
fn reviewer_identity_refusal(
    refusal: super::substrate_store::RequestScopeRefusal,
) -> GovernanceRefusal {
    use super::substrate_store::RequestScopeRefusal;
    let status = match &refusal {
        RequestScopeRefusal::AuthenticationRequired
        | RequestScopeRefusal::PrincipalIdentityInvalid => StatusCode::UNAUTHORIZED,
        RequestScopeRefusal::TenantAuthorityRequired
        | RequestScopeRefusal::ResourceScopeRequired
        | RequestScopeRefusal::ResourceOwnerMismatch => StatusCode::FORBIDDEN,
        RequestScopeRefusal::SubstrateUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status, refusal.code().to_string(), refusal.message())
}

/// Resolve the acting reviewer through THE canonical request-identity seam — no second resolver
/// and no client-settable identity header. Returns the principal ref ONLY; the headers that proved
/// it (cookies, bearer tokens) stay here and never reach a record or a receipt.
fn resolve_governance_reviewer(
    data_dir: &str,
    headers: &HeaderMap,
) -> Result<String, GovernanceRefusal> {
    super::substrate_store::resolve_request_identity(data_dir, headers)
        .map(|identity| identity.principal_ref)
        .map_err(reviewer_identity_refusal)
}

/// The transition this patch requests, if any. ONE definition of "is this a mutation?", shared by
/// the authorization decision and the lane the handler actually takes, so the two can never
/// disagree about which request needed a reviewer.
fn requested_transition(body: &Value) -> Option<&str> {
    body.get("transition").and_then(|v| v.as_str())
}

/// Settle EVERYTHING the request alone decides — prohibited fields, then which lane, then the
/// caller's identity — before the handler is allowed to touch the target record. Returns the
/// server-derived reviewer for a transition, or `None` for a metadata-only patch (which keeps its
/// existing authorization posture: this cut narrows attribution, it does not newly gate metadata).
///
/// Taking `data_dir` for the identity seam but never reading a governance record is the point: a
/// refusal from here cannot depend on whether the id exists, so the 401 an anonymous caller gets
/// is identical for a real approval and an invented one. Ordering within it is load-bearing —
/// a prohibited field is a pure statement about the request's shape and is refused first (400),
/// so a forged body is rejected the same way whether or not the caller could authenticate.
fn prepare_approval_patch_identity(
    data_dir: &str,
    headers: &HeaderMap,
    body: &Value,
) -> Result<Option<String>, GovernanceRefusal> {
    reject_client_supplied_identity(body)?;
    if requested_transition(body).is_none() {
        return Ok(None);
    }
    resolve_governance_reviewer(data_dir, headers).map(Some)
}

/// Apply an approval transition to `prev`, producing (updated record, transition receipt).
/// PURE (no I/O): validation happens BEFORE any mutation and a rejected transition returns Err
/// touching nothing. Legacy records without revision/history/receipt_refs migrate lazily here
/// (implicit revision 1, empty history) and stay readable. The receipt carries ONLY record-derived
/// fields + the transition — never request headers, cookies, tokens, or arbitrary form data.
///
/// `reviewer_ref` is the SERVER-DERIVED principal ref of the authenticated caller, taken as `&str`
/// rather than an optional request `Value` so a client-chosen reviewer is not merely rejected by
/// the handler but unrepresentable here: there is no argument shape a request body can occupy, and
/// no branch that leaves the decided record's reviewer null.
fn apply_approval_transition(
    prev: &Value,
    transition: &str,
    reviewer_ref: &str,
    now: &str,
    receipt_id: &str,
) -> Result<(Value, Value), (String, String)> {
    let cur = prev
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("pending");
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
        "reviewer_ref": reviewer_ref,
        "required_authority_refs": prev.get("required_authority_refs").cloned().unwrap_or_else(|| json!([])),
        "outcome": "ok",
        "at": now,
    });
    let mut a = prev.clone();
    a["status"] = json!(next);
    a["decided_at"] = json!(now);
    // Unconditional: a decided record always names its server-derived reviewer. The old
    // `if let Some(..)` left `reviewer_ref` null whenever the caller omitted it, so the record
    // and its receipt disagreed about whether anyone was accountable for the decision.
    a["reviewer_ref"] = json!(reviewer_ref);
    a["revision"] = json!(revision);
    let mut hist = a
        .get("history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    hist.push(json!({ "revision": revision, "op": transition, "at": now, "summary": format!("{cur} -> {next}"), "receipt_ref": receipt_ref.clone() }));
    if hist.len() > 50 {
        // Bounded history: keep the newest 50 entries (receipts stay durable on disk regardless).
        let cut = hist.len() - 50;
        hist.drain(0..cut);
    }
    a["history"] = Value::Array(hist);
    let mut refs = a
        .get("receipt_refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
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

/// `HeaderMap` is extracted BEFORE `Json` because the body extractor consumes the request; the
/// headers are read only by the canonical identity seam and never copied into a record or receipt.
///
/// ORDER IS THE CONTRACT: prohibited fields → lane → authorization → *then* the record. Nothing
/// above the load may depend on the record existing, or the refusal itself leaks whether it does.
///
/// Refusal statuses: the GOV-ATTR-1 gates carry real HTTP statuses (400 client-supplied identity,
/// 401 unauthenticated, 503 identity substrate down). The pre-existing lanes keep this handler's
/// 200-shaped `ok:false` convention verbatim — re-statusing not-found / invalid-transition /
/// persist-failed is a separate contract change and is not smuggled in here.
pub(crate) async fn handle_approval_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Everything the request alone decides, settled before a single record byte is read.
    let authorized_reviewer = match prepare_approval_patch_identity(&st.data_dir, &headers, &body) {
        Ok(authorized_reviewer) => authorized_reviewer,
        Err(r) => return refused(r),
    };
    let Some(mut a) = load(&st.data_dir, KIND_APPROVAL, &id) else {
        return (
            StatusCode::OK,
            Json(
                json!({ "ok": false, "reason": "approval_request not found", "error": { "code": "approval_not_found", "message": "approval_request not found" } }),
            ),
        );
    };
    // TRANSITION lane (receipted): validate → build record+receipt → finalize atomically-with-
    // restore. A transition request patches NOTHING else in the same call, so the receipt is the
    // whole truth of what changed. A refused transition alters no status/revision/history/refs.
    //
    // `authorized_reviewer` is `Some` exactly when a transition was requested and its caller
    // authenticated — both read through `requested_transition`, so the two agree by construction.
    // The `unwrap_or_default()` below cannot fire; if it ever did, `""` is not a valid transition
    // and `next_approval_status` refuses it, so even the impossible state fails closed rather than
    // silently degrading a transition into an unreceipted metadata patch.
    if let Some(reviewer_ref) = authorized_reviewer {
        let t = requested_transition(&body).unwrap_or_default();
        let now = iso_now();
        let receipt_id = format!("atr_{:x}", nanos());
        return match apply_approval_transition(&a, t, &reviewer_ref, &now, &receipt_id) {
            Ok((updated, receipt)) => match finalize_approval_transition(
                &st.data_dir,
                &id,
                &a,
                &updated,
                &receipt_id,
                &receipt,
            ) {
                Ok(()) => (
                    StatusCode::OK,
                    Json(
                        json!({ "ok": true, "approval_request": updated, "transition_receipt": receipt }),
                    ),
                ),
                Err(m) => (
                    StatusCode::OK,
                    Json(
                        json!({ "ok": false, "error": { "code": "governance_transition_persist_failed", "message": m } }),
                    ),
                ),
            },
            Err((code, message)) => (
                StatusCode::OK,
                Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
            ),
        };
    }
    // Non-transition metadata patch (legacy lane, semantics and authorization posture otherwise
    // unchanged: no receipt, no revision bump, no new auth requirement). `reviewer_ref` is GONE
    // from the patchable set — the identity gate already refuses a body carrying it, and leaving
    // it listed would restore the forgery the moment that gate moved.
    for key in [
        "request_kind",
        "reason",
        "enforcement_preview",
        "would_call",
        "required_authority_refs",
    ] {
        if let Some(v) = body.get(key) {
            a[key] = v.clone();
        }
    }
    a["updated_at"] = json!(iso_now());
    if persist_record(&st.data_dir, KIND_APPROVAL, &id, &a).is_err() {
        return (StatusCode::OK, governance_persist_failed_json("approval"));
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "approval_request": a })),
    )
}
pub(crate) async fn handle_approval_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    g_del(&st.data_dir, KIND_APPROVAL, &id)
}

// ---- Unified approvals inbox (W0.6) ------------------------------------------------------------

/// GET /v1/hypervisor/governance/approvals-inbox — ONE read projection over every
/// decision plane the daemon persists, so Governance / Approvals reads a single queue
/// instead of four disjoint ones. Folds, with a typed source ref per row:
///   1. governance approval-requests            (status == "pending")
///   2. thread/tool-exec approvals              (kernel approval-queue, pending-only)
///   3. improvement proposals                   (state == "pending")
///   4. memory-mutation proposals               (review_state == "proposed")
/// plus the two decision-shaped planes, as named rows — never silent absorption:
///   5. marketplace admission-reviews           (decision == "pending")
///   6. the POST-only `*-admissions` planners   (synchronous; nothing queues — the
///      plane is named with pending 0 and its routes, mechanically derived)
/// Read-only: every row points `decide` at the plane's EXISTING mutation route; this
/// projection mints no new authority and performs no transitions.
pub(crate) async fn handle_approvals_inbox(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items: Vec<Value> = Vec::new();
    let mut planes: Vec<Value> = Vec::new();

    // 1. Governance approval-requests (record-only transitions, receipted on decide).
    let approvals = read_record_dir(&st.data_dir, KIND_APPROVAL);
    let mut governance_pending = 0usize;
    for record in &approvals {
        if record.get("status").and_then(Value::as_str) != Some("pending") {
            continue;
        }
        governance_pending += 1;
        let id = record.get("id").and_then(Value::as_str).unwrap_or("");
        items.push(json!({
            "source_plane": "governance_approval_request",
            "item_ref": record.get("ref"),
            "subject_ref": record.get("subject_ref"),
            "title": record.get("request_kind"),
            "reason": record.get("reason"),
            "status": "pending",
            "created_at": record.get("created_at"),
            "updated_at": record.get("updated_at"),
            "decide": {
                "route": format!("/v1/hypervisor/governance/approval-requests/{id}"),
                "method": "PATCH",
                "transitions": ["approve", "reject", "revoke"]
            }
        }));
    }
    planes.push(json!({
        "plane": "governance_approval_request",
        "read_route": "/v1/hypervisor/governance/approval-requests",
        "pending": governance_pending,
        "total": approvals.len()
    }));

    // 2. Thread/tool-exec approvals (embedded on agent/run records; kernel projection).
    let (thread_pending, thread_errors) = super::lifecycle_routes::pending_thread_approvals(&st);
    let thread_pending_len = thread_pending.len();
    for entry in thread_pending {
        let thread_id = entry.get("thread_id").and_then(Value::as_str).unwrap_or("");
        let approval_id = entry
            .get("approval_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        items.push(json!({
            "source_plane": "thread_approval",
            "item_ref": Value::Null,
            "thread_id": thread_id,
            "approval_id": approval_id,
            "run_id": entry.get("run_id"),
            // The typed source identity of this plane IS the (thread_id, approval_id)
            // pair; the subject is the run when one is bound, else the thread. No new
            // ref scheme is minted here.
            "subject_ref": entry.get("run_id").and_then(Value::as_str).filter(|value| !value.is_empty()).map(str::to_string).unwrap_or_else(|| thread_id.to_string()),
            "reason": entry.get("reason"),
            "status": "pending",
            "lease_status": entry.get("lease_status"),
            "receipt_refs": entry.get("receipt_refs"),
            "decide": {
                "route": format!("/v1/threads/{thread_id}/approvals/{approval_id}/decision"),
                "method": "POST",
                "transitions": ["approve", "reject", "revoke"]
            }
        }));
    }
    planes.push(json!({
        "plane": "thread_approval",
        "read_route": "(embedded on agent/run records; no standalone list route)",
        "pending": thread_pending_len,
        "projection_errors": thread_errors
    }));

    // 3. Improvement proposals (owner: Intelligence/Improvement; the inbox projects).
    let improvements = read_record_dir(&st.data_dir, "improvement-proposals");
    let mut improvement_pending = 0usize;
    for record in &improvements {
        if record.get("state").and_then(Value::as_str) != Some("pending") {
            continue;
        }
        improvement_pending += 1;
        let id = record
            .get("improvement_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        items.push(json!({
            "source_plane": "improvement_proposal",
            "item_ref": record.get("proposal_ref"),
            "subject_ref": record.get("target_ref"),
            "title": record.get("proposal_kind"),
            "reason": record.get("reason"),
            "status": "pending",
            "created_at": record.get("created_at"),
            "decide": {
                "route": format!("/v1/hypervisor/intelligence/improvement-proposals/{id}"),
                "method": "POST",
                "transitions": ["approve", "reject", "apply"]
            }
        }));
    }
    planes.push(json!({
        "plane": "improvement_proposal",
        "read_route": "/v1/hypervisor/intelligence/improvement-proposals",
        "pending": improvement_pending,
        "total": improvements.len()
    }));

    // 4. Memory-mutation proposals (owner: Intelligence memory plane).
    let mutations = read_record_dir(&st.data_dir, "memory-mutation-proposals");
    let mut mutation_pending = 0usize;
    for record in &mutations {
        if record.get("review_state").and_then(Value::as_str) != Some("proposed") {
            continue;
        }
        mutation_pending += 1;
        let id = record
            .get("mutation_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        items.push(json!({
            "source_plane": "memory_mutation_proposal",
            "item_ref": record.get("proposal_ref"),
            "subject_ref": record.get("target_ref"),
            "title": record.get("operation"),
            "reason": record.get("reason"),
            "status": "proposed",
            "created_at": record.get("created_at"),
            "decide": {
                "route": format!("/v1/hypervisor/memory-mutation-proposals/{id}"),
                "method": "POST",
                "transitions": ["approve", "reject"]
            }
        }));
    }
    planes.push(json!({
        "plane": "memory_mutation_proposal",
        "read_route": "/v1/hypervisor/memory-mutation-proposals",
        "pending": mutation_pending,
        "total": mutations.len()
    }));

    // 5. Marketplace admission-reviews (decision-shaped: a review whose decision is
    // still "pending" is an open decision; `admitted` != `published`).
    let reviews = read_record_dir(&st.data_dir, "marketplace-admission-reviews");
    let mut review_pending = 0usize;
    for record in &reviews {
        if record.get("decision").and_then(Value::as_str) != Some("pending") {
            continue;
        }
        review_pending += 1;
        let id = record.get("id").and_then(Value::as_str).unwrap_or("");
        items.push(json!({
            "source_plane": "marketplace_admission_review",
            "item_ref": record.get("ref"),
            "subject_ref": record.get("candidate_ref"),
            "title": "marketplace admission review",
            "status": "pending",
            "created_at": record.get("created_at"),
            "updated_at": record.get("updated_at"),
            "decide": {
                "route": format!("/v1/hypervisor/marketplace/admission-reviews/{id}"),
                "method": "PATCH",
                "transitions": ["needs_changes", "admitted", "rejected"]
            }
        }));
    }
    planes.push(json!({
        "plane": "marketplace_admission_review",
        "read_route": "/v1/hypervisor/marketplace/admission-reviews",
        "pending": review_pending,
        "total": reviews.len()
    }));

    // 6. The POST-only `*-admissions` planner family: pure synchronous kernel
    // planners — the decision returns to the caller at POST time and nothing
    // queues. Named here (routes mechanically derived from the router source, so
    // this row cannot silently drift) rather than silently absorbed.
    let admission_planner_routes: Vec<String> = super::operability_routes::parsed_router_routes()
        .iter()
        .filter(|route| {
            route.path.ends_with("-admissions") && route.methods == vec!["POST".to_string()]
        })
        .map(|route| route.path.clone())
        .collect();
    planes.push(json!({
        "plane": "admission_planners",
        "routes": admission_planner_routes,
        "pending": 0,
        "note": "synchronous planners: POST returns the admission decision to the caller; no pending queue exists"
    }));

    // Newest first across planes (ISO timestamps compare lexicographically).
    items.sort_by(|a, b| {
        let ca = a.get("created_at").and_then(Value::as_str).unwrap_or("");
        let cb = b.get("created_at").and_then(Value::as_str).unwrap_or("");
        cb.cmp(ca)
    });
    let pending_total = items.len();
    Json(json!({
        "ok": true,
        "schema_version": "ioi.hypervisor.governance.approvals-inbox.v1",
        "pending_total": pending_total,
        "items": items,
        "planes": planes,
        "read_only": true,
        "note": "read projection only — every decision executes on the source plane's existing route; this inbox mints no new mutation authority",
        "generated_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime"
    }))
}

// ---- ReleaseControl ----------------------------------------------------------------------------
pub(crate) async fn handle_release_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    g_list(&st.data_dir, KIND_RELEASE, "release_controls")
}
pub(crate) async fn handle_release_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let target = str_field(&body, "release_target_ref");
    if let Err((c, m)) = resolve_governance_ref(&st.data_dir, target) {
        return bad(&c, &m);
    }
    let rollout_mode = {
        let m = str_field(&body, "rollout_mode");
        if m.is_empty() {
            "full"
        } else {
            m
        }
    };
    if !["canary", "cohort", "full"].contains(&rollout_mode) {
        return bad(
            "governance_rollout_mode_invalid",
            "rollout_mode must be canary | cohort | full",
        );
    }
    let canary_percent = body
        .get("canary_percent")
        .and_then(Value::as_u64)
        .map(|v| v.min(100));
    if rollout_mode == "canary" && canary_percent.is_none() {
        return bad(
            "governance_canary_percent_required",
            "canary rollout needs canary_percent (0-100)",
        );
    }
    if rollout_mode == "cohort" && str_refs(&body, "cohort_refs").is_empty() {
        return bad(
            "governance_cohort_refs_required",
            "cohort rollout needs cohort_refs",
        );
    }
    let (cohort_refs, deprecated_raw) =
        match partition_cohort_refs(&st.data_dir, &str_refs(&body, "cohort_refs")) {
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
    record
        .as_object_mut()
        .unwrap()
        .extend(control_common(&body).as_object().unwrap().clone());
    if persist_record(&st.data_dir, KIND_RELEASE, &id, &record).is_err() {
        return governance_persist_failed("release");
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "release_control": record })),
    )
}
pub(crate) async fn handle_release_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    g_get(&st.data_dir, KIND_RELEASE, "release_control", &id)
}
pub(crate) async fn handle_release_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut r) = load(&st.data_dir, KIND_RELEASE, &id) else {
        return Json(json!({ "ok": false, "reason": "release_control not found" }));
    };
    if let Some(t) = body.get("transition").and_then(|v| v.as_str()) {
        let cur = r.get("state").and_then(|v| v.as_str()).unwrap_or("closed");
        match next_release_state(cur, t) {
            Ok(Some(next)) => r["state"] = json!(next),
            Ok(None) => {
                if t == "request_rollback" {
                    r["rollback_requested"] = json!(true);
                } else {
                    r["recall_requested"] = json!(true);
                }
            }
            Err(e) => {
                return Json(
                    json!({ "ok": false, "error": { "code": "governance_transition_invalid", "message": e } }),
                )
            }
        }
    }
    if body.get("cohort_refs").is_some() {
        match partition_cohort_refs(&st.data_dir, &str_refs(&body, "cohort_refs")) {
            Ok((cohort_refs, deprecated_raw)) => {
                r["cohort_refs"] = json!(cohort_refs);
                r["deprecated_raw_cohort_refs"] = json!(deprecated_raw.clone());
                r["cohort_refs_deprecation"] = if deprecated_raw.is_empty() {
                    Value::Null
                } else {
                    json!("raw member refs in cohort_refs are DEPRECATED — create a cohort:// object and reference it")
                };
            }
            Err((code, message)) => {
                return Json(json!({ "ok": false, "error": { "code": code, "message": message } }))
            }
        }
    }
    for key in [
        "canary",
        "cohort",
        "rollout_mode",
        "canary_percent",
        "starts_at",
        "ends_at",
        "enforcement_preview",
        "would_call",
        "required_authority_refs",
    ] {
        if let Some(v) = body.get(key) {
            r[key] = v.clone();
        }
    }
    r["updated_at"] = json!(iso_now());
    if persist_record(&st.data_dir, KIND_RELEASE, &id, &r).is_err() {
        return governance_persist_failed_json("release");
    }
    Json(json!({ "ok": true, "release_control": r }))
}
pub(crate) async fn handle_release_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    g_del(&st.data_dir, KIND_RELEASE, &id)
}

// ---- Cohorts -----------------------------------------------------------------------------------
//
// Durable rollout audiences. A cohort names WHO a canary/cohort ReleaseControl applies to via
// resolvable member refs (principal:// project:// org:// environment:// ioi-agent-policy://).
// Eligibility is evaluated against DAEMON-DERIVED context, never trusted caller text.

const COHORT_MEMBER_SCHEMES: &[&str] = &[
    "principal",
    "project",
    "org",
    "environment",
    "ioi-agent-policy",
];

/// Split ReleaseControl cohort_refs into (all refs kept as given, deprecated raw member refs).
/// cohort:// entries must resolve; anything else is a DEPRECATED raw member ref (still honored).
fn partition_cohort_refs(
    data_dir: &str,
    entries: &[String],
) -> Result<(Vec<String>, Vec<String>), (String, String)> {
    let mut deprecated: Vec<String> = Vec::new();
    for entry in entries {
        if let Some(id) = entry.strip_prefix("cohort://") {
            if load(data_dir, KIND_COHORT, id).is_none() {
                return Err((
                    "governance_cohort_unresolved".into(),
                    format!("'{entry}' does not resolve to a recorded cohort"),
                ));
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
pub(crate) async fn handle_cohort_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let display_name = str_field(&body, "display_name");
    if display_name.is_empty() {
        return bad(
            "governance_cohort_name_required",
            "a cohort needs a display_name",
        );
    }
    let scope = {
        let s = str_field(&body, "scope");
        if s.is_empty() {
            "project"
        } else {
            s
        }
    };
    if !["personal", "project", "org"].contains(&scope) {
        return bad(
            "governance_cohort_scope_invalid",
            "scope must be personal | project | org",
        );
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
    if persist_record(&st.data_dir, KIND_COHORT, &id, &record).is_err() {
        return governance_persist_failed("cohort");
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "cohort": record })),
    )
}
pub(crate) async fn handle_cohort_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    g_get(&st.data_dir, KIND_COHORT, "cohort", &id)
}
pub(crate) async fn handle_cohort_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut c) = load(&st.data_dir, KIND_COHORT, &id) else {
        return Json(json!({ "ok": false, "reason": "cohort not found" }));
    };
    if let Some(t) = body.get("transition").and_then(Value::as_str) {
        match t {
            "enable" => c["status"] = json!("active"),
            "disable" => c["status"] = json!("disabled"),
            other => {
                return Json(
                    json!({ "ok": false, "error": { "code": "governance_transition_invalid", "message": format!("invalid cohort transition '{other}' (enable | disable)") } }),
                )
            }
        }
    }
    if let Some(status) = body.get("status").and_then(Value::as_str) {
        if !["active", "disabled"].contains(&status) {
            return Json(
                json!({ "ok": false, "error": { "code": "governance_cohort_status_invalid", "message": "status must be active | disabled" } }),
            );
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
        if let Some(v) = body.get(key) {
            c[key] = v.clone();
        }
    }
    c["updated_at"] = json!(iso_now());
    if persist_record(&st.data_dir, KIND_COHORT, &id, &c).is_err() {
        return governance_persist_failed_json("cohort");
    }
    Json(json!({ "ok": true, "cohort": c }))
}
pub(crate) async fn handle_cohort_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    g_del(&st.data_dir, KIND_COHORT, &id)
}

// ---- KillSwitch --------------------------------------------------------------------------------
pub(crate) async fn handle_kill_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    g_list(&st.data_dir, KIND_KILL, "kill_switches")
}
pub(crate) async fn handle_kill_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
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
    record
        .as_object_mut()
        .unwrap()
        .extend(control_common(&body).as_object().unwrap().clone());
    if persist_record(&st.data_dir, KIND_KILL, &id, &record).is_err() {
        return governance_persist_failed("kill switch");
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "kill_switch": record })),
    )
}
pub(crate) async fn handle_kill_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    g_get(&st.data_dir, KIND_KILL, "kill_switch", &id)
}
pub(crate) async fn handle_kill_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
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
                    k["trip_reason"] = json!(body
                        .get("trip_reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""));
                } else {
                    k["tripped_at"] = Value::Null;
                    k["trip_reason"] = Value::Null;
                }
            }
            Err(e) => {
                return Json(
                    json!({ "ok": false, "error": { "code": "governance_transition_invalid", "message": e } }),
                )
            }
        }
    }
    for key in [
        "subject_ref",
        "revoke_path",
        "enforcement_preview",
        "would_call",
        "required_authority_refs",
    ] {
        if let Some(v) = body.get(key) {
            k[key] = v.clone();
        }
    }
    k["updated_at"] = json!(iso_now());
    if persist_record(&st.data_dir, KIND_KILL, &id, &k).is_err() {
        return governance_persist_failed_json("kill switch");
    }
    Json(json!({ "ok": true, "kill_switch": k }))
}
pub(crate) async fn handle_kill_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
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
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Enforcement stops running software. It was reachable unauthenticated: anyone who could reach
    // the port could unmount every runtime a tripped switch named.
    let caller =
        match super::mutation_event_foundation::require_write_caller(&st.data_dir, &headers, &body)
        {
            Ok(caller) => caller,
            Err(response) => return response,
        };
    let Some(mut k) = load(&st.data_dir, KIND_KILL, &id) else {
        return bad("kill_switch_not_found", "kill switch not found");
    };
    if k.get("state").and_then(|v| v.as_str()) != Some("tripped") {
        return bad(
            "kill_switch_not_tripped",
            "KillSwitch must be tripped before it can be enforced",
        );
    }
    let subject = k
        .get("subject_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let supported =
        subject.starts_with("domain-app-runtime://") || subject.starts_with("domain-app://");
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
    let targets: Vec<String> = runtimes
        .iter()
        .filter_map(|rt| rt.get("ref").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    // Admit the WHOLE fan-out as one transition before stopping anything. Previously this loop
    // enforced runtime-by-runtime and returned on the first failure: with five targets, a failure
    // at the third left two runtimes killed, three running, and the KillSwitch never updated — a
    // half-enforced kill that no record described and no restart could finish. The admitted
    // transition names every target, so recovery can complete the set instead of guessing it.
    let enforcement_plan = json!({
        "kill_switch_ref": k.get("ref").cloned().unwrap_or(Value::Null),
        "subject_ref": subject,
        "target_runtime_refs": targets
    });
    let plan_commit = match super::mutation_event_foundation::admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        "hypervisor-governance",
        KIND_KILL,
        k.get("ref").and_then(|v| v.as_str()).unwrap_or(&id),
        "governance.kill_enforce.planned",
        k.get("admitted_head").and_then(|v| v.as_str()),
        &enforcement_plan,
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    for rt in &runtimes {
        if let Some(r) = rt.get("ref").and_then(|v| v.as_str()) {
            affected.push(r.to_string());
        }
        match super::domain_apps_routes::kill_enforce_runtime(&st.data_dir, &caller, rt) {
            Ok(refs) => receipt_refs.extend(refs),
            // Report the admitted plan so the caller — and a restart — can finish the remaining
            // targets. Returning a bare error here is what made partial enforcement invisible.
            Err((status, Json(mut payload))) => {
                payload["admitted_enforcement_head"] = json!(plan_commit.projection.head);
                payload["planned_target_runtime_refs"] =
                    json!(enforcement_plan["target_runtime_refs"]);
                payload["enforced_before_failure"] = json!(affected);
                return (status, Json(payload));
            }
        }
    }
    let enforcement_state = if runtimes.is_empty() {
        "noop"
    } else {
        "enforced"
    };
    // Emit a governance enforcement receipt even for a no-op (proof, never silent).
    let erid = format!("kille_{:x}", nanos());
    let state_root = sha256_hex_str(&format!(
        "kill_enforce|{}|{subject}|{}|{now}",
        k.get("ref").and_then(|v| v.as_str()).unwrap_or(""),
        affected.join(",")
    ));
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
    if persist_record(&st.data_dir, KIND_KILL_ENFORCE_RECEIPT, &erid, &ereceipt).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "kill_enforcement_receipt_persistence_failed",
                    "message": "runtime enforcement completed but its governance receipt could not be committed; reconcile before retry",
                    "effects_committed": true,
                    "recovery_required": true
                }
            })),
        );
    }
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
    if persist_record(&st.data_dir, KIND_KILL, &id, &k).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "kill_enforcement_projection_persistence_failed",
                    "message": "runtime enforcement and its receipt committed, but the KillSwitch projection did not; reconcile from the receipt before retry",
                    "effects_committed": true,
                    "recovery_required": true,
                    "enforcement_receipt_ref": format!("kill-enforcement-receipt://{erid}")
                }
            })),
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "kill_switch": k, "enforcement_receipt": ereceipt })),
    )
}

// ---- ImprovementGate ---------------------------------------------------------------------------
pub(crate) async fn handle_gate_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    g_list(&st.data_dir, KIND_GATE, "improvement_gates")
}
pub(crate) async fn handle_gate_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
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
    record
        .as_object_mut()
        .unwrap()
        .extend(control_common(&body).as_object().unwrap().clone());
    if persist_record(&st.data_dir, KIND_GATE, &id, &record).is_err() {
        return governance_persist_failed("gate");
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "improvement_gate": record })),
    )
}
pub(crate) async fn handle_gate_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    g_get(&st.data_dir, KIND_GATE, "improvement_gate", &id)
}
pub(crate) async fn handle_gate_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut g) = load(&st.data_dir, KIND_GATE, &id) else {
        return Json(json!({ "ok": false, "reason": "improvement_gate not found" }));
    };
    if let Some(t) = body.get("transition").and_then(|v| v.as_str()) {
        let cur = g.get("state").and_then(|v| v.as_str()).unwrap_or("open");
        match next_gate_state(cur, t) {
            Ok(next) => g["state"] = json!(next),
            Err(e) => {
                return Json(
                    json!({ "ok": false, "error": { "code": "governance_transition_invalid", "message": e } }),
                )
            }
        }
    }
    for key in [
        "bounds",
        "enforcement_preview",
        "would_call",
        "required_authority_refs",
    ] {
        if let Some(v) = body.get(key) {
            g[key] = v.clone();
        }
    }
    g["updated_at"] = json!(iso_now());
    if persist_record(&st.data_dir, KIND_GATE, &id, &g).is_err() {
        return governance_persist_failed_json("gate");
    }
    Json(json!({ "ok": true, "improvement_gate": g }))
}
pub(crate) async fn handle_gate_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    g_del(&st.data_dir, KIND_GATE, &id)
}

#[cfg(test)]
mod governance_tests {
    use super::*;

    #[test]
    fn approval_transitions_valid_and_invalid() {
        assert_eq!(
            next_approval_status("pending", "approve").unwrap(),
            "approved"
        );
        assert_eq!(
            next_approval_status("pending", "reject").unwrap(),
            "rejected"
        );
        assert_eq!(
            next_approval_status("approved", "revoke").unwrap(),
            "revoked"
        );
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

    /// The server-derived principal ref the identity seam would return; the ONLY admissible
    /// reviewer identity. Shaped like `resolve_request_identity`'s output (`user://<principal_id>`).
    const SERVER_PRINCIPAL: &str = "user://principal-real";

    #[test]
    fn approval_transition_accepted_builds_record_and_receipt() {
        let prev = legacy_pending();
        let (a, r) = apply_approval_transition(
            &prev,
            "approve",
            SERVER_PRINCIPAL,
            "2026-02-01T00:00:00Z",
            "atr_test1",
        )
        .unwrap();
        // Record: status, decided, reviewer, revision bumped EXACTLY once (legacy 1 -> 2),
        // one history entry, one receipt ref — all pointing at the same receipt.
        assert_eq!(a["status"], json!("approved"));
        assert_eq!(a["revision"], json!(2));
        assert_eq!(a["reviewer_ref"], json!(SERVER_PRINCIPAL));
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
        assert_eq!(
            keys,
            vec![
                "approval_request_id",
                "approval_request_ref",
                "at",
                "object",
                "outcome",
                "previous_status",
                "receipt_id",
                "receipt_ref",
                "required_authority_refs",
                "resulting_status",
                "reviewer_ref",
                "schema_version",
                "subject_ref",
                "transition"
            ]
        );
    }

    #[test]
    fn approval_transition_refused_touches_nothing_and_duplicates_refuse() {
        let prev = legacy_pending();
        let (approved, _r1) = apply_approval_transition(
            &prev,
            "approve",
            SERVER_PRINCIPAL,
            "2026-02-01T00:00:00Z",
            "atr_a",
        )
        .unwrap();
        // Duplicate approve on the already-approved record: typed refusal, zero mutation.
        let err = apply_approval_transition(
            &approved,
            "approve",
            SERVER_PRINCIPAL,
            "2026-02-02T00:00:00Z",
            "atr_b",
        )
        .unwrap_err();
        assert_eq!(err.0, "governance_transition_invalid");
        // Pure fn: the input record is untouched by a refusal (revision/history/refs intact).
        assert_eq!(approved["revision"], json!(2));
        assert_eq!(approved["history"].as_array().unwrap().len(), 1);
        assert_eq!(approved["receipt_refs"].as_array().unwrap().len(), 1);
        // Unknown vocabulary refuses too.
        assert!(
            apply_approval_transition(&prev, "escalate", SERVER_PRINCIPAL, "t", "atr_c").is_err()
        );
    }

    #[test]
    fn approval_history_is_bounded() {
        let mut rec = legacy_pending();
        let mut hist = Vec::new();
        for i in 0..60 {
            hist.push(json!({ "revision": i, "op": "seed", "at": "t", "summary": "s", "receipt_ref": format!("agentgres://x/{i}") }));
        }
        rec["history"] = Value::Array(hist);
        let (a, _r) =
            apply_approval_transition(&rec, "approve", SERVER_PRINCIPAL, "t2", "atr_bound")
                .unwrap();
        let h = a["history"].as_array().unwrap();
        assert_eq!(h.len(), 50, "history is bounded to the newest 50 entries");
        assert_eq!(
            h.last().unwrap()["op"],
            json!("approve"),
            "the newest entry is the accepted transition"
        );
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
        let (updated, receipt) =
            apply_approval_transition(&prev, "approve", SERVER_PRINCIPAL, "t", "atr_fail").unwrap();
        // Block the receipts dir: a plain file where the directory must go.
        std::fs::write(dir.join(KIND_APPROVAL_RECEIPT), b"blocker").unwrap();
        let err = finalize_approval_transition(
            data_dir, "appr_t1", &prev, &updated, "atr_fail", &receipt,
        )
        .unwrap_err();
        assert!(err.contains("restored"), "failure names the restore: {err}");
        let on_disk = load(data_dir, KIND_APPROVAL, "appr_t1").unwrap();
        assert_eq!(
            on_disk["status"],
            json!("pending"),
            "the transition did not survive the receipt failure"
        );
        assert!(
            on_disk.get("revision").is_none(),
            "no revision bump survived"
        );
        assert!(
            on_disk["reviewer_ref"].is_null(),
            "no reviewer attribution survived a transition that did not land"
        );
        // And the happy path works once the blocker is gone: record + receipt both persist.
        std::fs::remove_file(dir.join(KIND_APPROVAL_RECEIPT)).unwrap();
        finalize_approval_transition(data_dir, "appr_t1", &prev, &updated, "atr_fail", &receipt)
            .unwrap();
        assert_eq!(
            load(data_dir, KIND_APPROVAL, "appr_t1").unwrap()["status"],
            json!("approved")
        );
        assert_eq!(
            load(data_dir, KIND_APPROVAL_RECEIPT, "atr_fail").unwrap()["transition"],
            json!("approve")
        );
        // GOV-ATTR-1 at the DURABLE layer: what a later read treats as proof of who decided is
        // the server-derived principal, in the record and in the receipt alike.
        assert_eq!(
            load(data_dir, KIND_APPROVAL, "appr_t1").unwrap()["reviewer_ref"],
            json!(SERVER_PRINCIPAL),
            "the persisted record names the server-derived reviewer"
        );
        assert_eq!(
            load(data_dir, KIND_APPROVAL_RECEIPT, "atr_fail").unwrap()["reviewer_ref"],
            json!(SERVER_PRINCIPAL),
            "and so does the durable receipt"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- GOV-ATTR-1: the reviewer is the authenticated caller, resolved server-side -------------

    /// A reviewer identity a request might try to assert. Never admissible.
    const FORGED_PRINCIPAL: &str = "user://attacker-chosen";

    #[test]
    fn request_carried_reviewer_ref_is_refused_in_every_form() {
        // The KEY BEING PRESENT is the whole test — value-insensitive, so no shape slips through.
        // `null`, `""`, and a value matching the real caller are all refused: accepting a match
        // would make the gate depend on the identity the request is trying to assert.
        for forged in [
            json!({ "transition": "approve", "reviewer_ref": FORGED_PRINCIPAL }),
            json!({ "transition": "approve", "reviewer_ref": SERVER_PRINCIPAL }),
            json!({ "transition": "approve", "reviewer_ref": Value::Null }),
            json!({ "transition": "approve", "reviewer_ref": "" }),
            json!({ "transition": "approve", "reviewer_ref": { "id": "x" } }),
            json!({ "transition": "reject", "reviewer_ref": FORGED_PRINCIPAL }),
            json!({ "transition": "revoke", "reviewer_ref": FORGED_PRINCIPAL }),
            // Metadata-only lane (no `transition`): equally refused, so the field cannot be
            // planted by one call and left standing for a later decision to inherit.
            json!({ "reviewer_ref": FORGED_PRINCIPAL }),
            json!({ "reason": "r", "reviewer_ref": FORGED_PRINCIPAL }),
        ] {
            let (status, code, message) = reject_client_supplied_identity(&forged).expect_err(
                &format!("a body carrying reviewer_ref must be refused: {forged}"),
            );
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "refusal is a 400-class error"
            );
            assert_eq!(code, "governance_reviewer_ref_not_client_settable");
            assert!(
                message.contains("authenticated caller"),
                "the refusal says WHY, so a caller can fix the request: {message}"
            );
        }
    }

    #[test]
    fn a_body_that_names_no_reviewer_passes_the_gate() {
        // The gate refuses forgery ONLY; it must not break either patch lane.
        for admissible in [
            json!({ "transition": "approve" }),
            json!({ "transition": "revoke" }),
            json!({ "reason": "r", "request_kind": "k" }),
            json!({ "required_authority_refs": ["authority://x"] }),
            json!({}),
            // A near-miss key is a different field and must not be refused as if it were this one.
            json!({ "reviewer_refs": ["user://a"] }),
        ] {
            assert!(
                reject_client_supplied_identity(&admissible).is_ok(),
                "must pass the gate: {admissible}"
            );
        }
    }

    #[test]
    fn every_server_owned_identity_field_is_refused_from_the_body() {
        // Not just `reviewer_ref`: a body may not name WHO ACTED under any of the estate's
        // attribution field names, or the forgery just moves to the next spelling. Each is refused
        // under the same stable code, and the message names the offending field so a caller can
        // fix the request rather than guess which key was the problem.
        for field in CLIENT_PROHIBITED_IDENTITY_FIELDS {
            let mut body = json!({ "transition": "approve" });
            body[*field] = json!(FORGED_PRINCIPAL);
            let (status, code, message) = reject_client_supplied_identity(&body)
                .expect_err(&format!("'{field}' must be refused from the body"));
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(code, "governance_reviewer_ref_not_client_settable");
            assert!(
                message.contains(field),
                "the refusal names the offending field: {message}"
            );
        }
        // `required_authority_refs` names WHAT authority a crossing needs, never WHO is acting, so
        // it stays patchable — refusing it would break the metadata lane this cut preserves.
        assert!(reject_client_supplied_identity(
            &json!({ "required_authority_refs": ["authority://x"] })
        )
        .is_ok());
    }

    #[test]
    fn transition_authorization_is_settled_before_any_record_is_read() {
        // The oracle this closes: loading the record first made a missing id answer "not found"
        // and a real id answer 401, so an anonymous caller could enumerate which approval ids
        // exist by reading the difference. Whether a governance record exists is itself
        // privileged. Proven BEHAVIOURALLY — by what the pre-load path returns — rather than by
        // asserting anything about source order.
        let dir = std::env::temp_dir().join(format!("ioi-appr-preload-{:x}", nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let data_dir = dir.to_str().unwrap();
        let transition = json!({ "transition": "approve" });

        // (a) Empty data dir — NO approval record exists at all. An unauthenticated transition
        // still answers 401, never "not found", so the absence is never confirmed to the caller.
        let absent =
            prepare_approval_patch_identity(data_dir, &HeaderMap::new(), &transition).unwrap_err();
        assert_eq!(absent.0, StatusCode::UNAUTHORIZED);
        assert_eq!(absent.1, "request_principal_required");

        // (b) Now a REAL approval record sits in that same data dir. The identity seam reads this
        // directory too, so this is a real assertion rather than a tautology: its refusal must be
        // invariant to which governance records are present. Same status, code, and message.
        persist_record(data_dir, KIND_APPROVAL, "appr_real", &legacy_pending()).unwrap();
        let present =
            prepare_approval_patch_identity(data_dir, &HeaderMap::new(), &transition).unwrap_err();
        assert_eq!(
            present, absent,
            "an existing record and an absent one must be indistinguishable to an unauthenticated \
             caller — any difference here IS the enumeration oracle"
        );

        // (c) A prohibited identity field is refused BEFORE authentication: with no credentials at
        // all the answer is still 400, not 401, so that ordering is visible in the response itself.
        let forged = prepare_approval_patch_identity(
            data_dir,
            &HeaderMap::new(),
            &json!({ "transition": "approve", "reviewer_ref": FORGED_PRINCIPAL }),
        )
        .unwrap_err();
        assert_eq!(forged.0, StatusCode::BAD_REQUEST);
        assert_eq!(forged.1, "governance_reviewer_ref_not_client_settable");

        // (d) A metadata-only patch keeps its existing posture: no identity demanded, so the
        // handler proceeds to the record exactly as it did before this cut.
        assert_eq!(
            prepare_approval_patch_identity(data_dir, &HeaderMap::new(), &json!({ "reason": "r" }))
                .unwrap(),
            None,
            "this cut narrows attribution; it does not newly gate metadata patches"
        );
        // (e) ...but a metadata-only patch carrying a prohibited field is still refused with no
        // record read, so the field cannot be planted for a later decision to inherit.
        assert_eq!(
            prepare_approval_patch_identity(
                data_dir,
                &HeaderMap::new(),
                &json!({ "reason": "r", "reviewer_ref": FORGED_PRINCIPAL })
            )
            .unwrap_err()
            .1,
            "governance_reviewer_ref_not_client_settable"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transition_attributes_only_the_server_derived_principal() {
        // The builder takes `&str`, so a request `Value` cannot even be passed to it. What is left
        // to prove is the OUTPUT: both the record and the durable receipt name the caller, and a
        // stale/forged reviewer already sitting in the stored record is OVERWRITTEN, not inherited.
        // A pre-gate record could carry anything; the decision landing now was made by the
        // authenticated caller, whatever the old bytes claimed.
        let mut poisoned = legacy_pending();
        poisoned["reviewer_ref"] = json!(FORGED_PRINCIPAL);
        let (record, receipt) = apply_approval_transition(
            &poisoned,
            "approve",
            SERVER_PRINCIPAL,
            "2026-02-01T00:00:00Z",
            "atr_attr",
        )
        .unwrap();
        assert_eq!(record["reviewer_ref"], json!(SERVER_PRINCIPAL));
        assert_eq!(receipt["reviewer_ref"], json!(SERVER_PRINCIPAL));
        assert!(
            !record["reviewer_ref"].is_null() && !receipt["reviewer_ref"].is_null(),
            "a decided record and its receipt always name who decided"
        );
        for (label, doc) in [("record", &record), ("receipt", &receipt)] {
            assert!(
                !serde_json::to_string(doc)
                    .unwrap()
                    .contains(FORGED_PRINCIPAL),
                "{label} still carries the pre-existing forged reviewer"
            );
        }
    }

    #[test]
    fn unauthenticated_transition_gets_no_anonymous_reviewer() {
        // Through the REAL canonical seam: an empty data dir (no sessions, no API tokens) reached
        // with no auth headers is the most permissive posture there is, and it must still refuse.
        // Canon: "an unenforced local auth gate is never an implicit administrator credential"
        // (identity-access-and-metering.md). A permissive posture minting `user://anonymous` here
        // would put an unaccountable name on durable proof of a governance decision.
        let dir = std::env::temp_dir().join(format!("ioi-appr-anon-{:x}", nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let data_dir = dir.to_str().unwrap();
        for headers in [
            HeaderMap::new(),
            // A bearer that resolves to nobody mints nobody — the token is not the principal.
            HeaderMap::from_iter([(
                axum::http::header::AUTHORIZATION,
                "Bearer not-a-real-token".parse().unwrap(),
            )]),
            // Nor does a cookie that names no live session.
            HeaderMap::from_iter([(
                axum::http::header::COOKIE,
                "ioi_session=not-a-real-session".parse().unwrap(),
            )]),
        ] {
            let (status, code, _message) =
                resolve_governance_reviewer(data_dir, &headers).unwrap_err();
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(code, "request_principal_required");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_refusals_stay_fail_closed_and_distinguishable() {
        use super::super::substrate_store::RequestScopeRefusal;
        // Every seam refusal keeps ITS OWN code, and a substrate outage stays a 503 rather than
        // being flattened into "log in again" — an authenticated operator told to re-authenticate
        // while identity storage is merely down cannot act on that, and would keep retrying.
        let cases = [
            (
                RequestScopeRefusal::AuthenticationRequired,
                StatusCode::UNAUTHORIZED,
                "request_principal_required",
            ),
            (
                RequestScopeRefusal::PrincipalIdentityInvalid,
                StatusCode::UNAUTHORIZED,
                "request_principal_invalid",
            ),
            (
                RequestScopeRefusal::TenantAuthorityRequired,
                StatusCode::FORBIDDEN,
                "request_tenant_authority_required",
            ),
            (
                RequestScopeRefusal::ResourceScopeRequired,
                StatusCode::FORBIDDEN,
                "request_resource_scope_required",
            ),
            (
                RequestScopeRefusal::ResourceOwnerMismatch,
                StatusCode::FORBIDDEN,
                "request_resource_owner_mismatch",
            ),
            (
                RequestScopeRefusal::SubstrateUnavailable("identity store unreadable".into()),
                StatusCode::SERVICE_UNAVAILABLE,
                "request_scope_substrate_unavailable",
            ),
        ];
        for (refusal, want_status, want_code) in cases {
            let (status, code, message) = reviewer_identity_refusal(refusal);
            assert_eq!(status, want_status, "status for {want_code}");
            assert_eq!(code, want_code);
            assert!(
                !status.is_success(),
                "{want_code} must never render as success"
            );
            assert!(
                !message.is_empty(),
                "{want_code} carries an operator-readable message"
            );
        }
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
        assert_eq!(
            next_release_state("open", "request_rollback").unwrap(),
            None
        ); // flag, no state change
        assert!(next_release_state("closed", "close").is_err());
    }

    #[test]
    fn resolve_governance_ref_named_vs_local() {
        // named refs (no scheme / unknown scheme) are allowed without resolution
        assert!(resolve_governance_ref("/nonexistent", "authority-action://spend").is_ok());
        assert!(resolve_governance_ref("/nonexistent", "connector:conn_123").is_ok());
        assert!(resolve_governance_ref("/nonexistent", "lease_abc").is_ok());
        // required (empty) rejected
        assert_eq!(
            resolve_governance_ref("/nonexistent", "").unwrap_err().0,
            "governance_ref_required"
        );
        // local-looking (foundry id / known scheme) must resolve -> unresolved in an empty dir
        assert_eq!(
            resolve_governance_ref("/nonexistent", "frun_x")
                .unwrap_err()
                .0,
            "governance_ref_unresolved"
        );
        assert_eq!(
            resolve_governance_ref("/nonexistent", "domain-app://dapp_x")
                .unwrap_err()
                .0,
            "governance_ref_unresolved"
        );
        assert_eq!(
            resolve_governance_ref("/nonexistent", "marketplace-publish://mpub_x")
                .unwrap_err()
                .0,
            "governance_ref_unresolved"
        );
        // blueprint:// is local (OQ-11 studio plane): an approval subject must name a REAL
        // stored blueprint, never fall through as an unvalidated named ref.
        assert_eq!(
            resolve_governance_ref("/nonexistent", "blueprint://bp_x")
                .unwrap_err()
                .0,
            "governance_ref_unresolved"
        );
    }

    #[test]
    fn grant_stats_counts_granted_revoked_active() {
        let now = 1_000_000i64;
        let grants = vec![
            json!({ "decision": "granted", "revoked": false, "expires_at_unix": now + 1000 }), // active
            json!({ "decision": "granted", "revoked": true, "expires_at_unix": now + 1000 }), // revoked
            json!({ "decision": "granted", "revoked": false, "expires_at_unix": now - 1000 }), // expired
            json!({ "decision": "granted", "revoked": false, "expires_at_unix": 0 }), // active (no expiry)
            json!({ "decision": "denied", "revoked": false }),                        // not granted
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
            json!({ "expires_at": now_ms + 5000, "receipt_required": true }), // active + receipt
            json!({ "expires_at": now_ms + 5000, "revocation_ref": "rev_1" }), // revoked
            json!({ "expires_at": now_ms - 5000 }),                           // expired
            json!({ "expires_at": 0, "receipt_required": false }),            // active (no expiry)
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
