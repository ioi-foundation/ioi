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
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{read_record_dir, DaemonState};

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
    let governance_gaps = json!([
        { "id": "approval_request_object", "title": "No persisted ApprovalRequest object", "detail": "Approvals live implicitly as authority grants/receipts; there is no standalone approval-request record to list, route, or resolve.", "has_substrate": false },
        { "id": "release_control_object", "title": "No ReleaseControl object or release-gate mutation", "detail": "Foundry promotion and Domain App mount are preview/draft only; nothing gates or performs a release.", "has_substrate": false },
        { "id": "kill_switch_object", "title": "No KillSwitch object or kill-switch mutation path", "detail": "There is no persisted kill-switch control or mutation endpoint.", "has_substrate": false },
        { "id": "improvement_gate_object", "title": "No formal bounded-improvement gate object", "detail": "Foundry tune/eval work exists but no improvement-gate record bounds/approves it.", "has_substrate": false },
        { "id": "auth_enforcement_inactive", "title": "Identity enforcement present but not active", "detail": format!("The IdP/enforcement ring exists but effective_enforced={enforced} in this deployment."), "has_substrate": true },
        { "id": "wallet_network_offline", "title": "Wallet authority network not live", "detail": format!("local_operator mode; wallet_network_live={wallet_live} — portable/delegated authority is not live."), "has_substrate": true }
    ]);

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
            "governance_gaps": 6
        },
        "authority_posture": authority_posture,
        "identity_posture": identity_posture,
        "lease_posture": lease_posture,
        "approval_and_admission_posture": approval_and_admission_posture,
        "policy_ref_coverage": policy_ref_coverage,
        "release_control_candidates": release_control_candidates,
        "revocation_targets": revocation_targets,
        "improvement_gate_candidates": improvement_gate_candidates,
        "governance_gaps": governance_gaps
    }))
}

#[cfg(test)]
mod governance_tests {
    use super::*;

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
