//! Cross-provider placement decisions and failover orchestration.
//!
//! This is where `hypervisor_choose` moves from advisory to an explicit,
//! challengeable PLACEMENT DECISION, and where Hypervisor proves it can
//! move work ACROSS venues: intent → candidates → decision → governed
//! provider create → snapshot/archive custody → named failure → failover
//! → state_root-validated restore on a DIFFERENT provider class.
//!
//! Boundaries (canon):
//! - A decision is NEVER authority: provider mutation still crosses the
//!   wallet gate. This file performs mutations ONLY by calling the
//!   existing `handle_provider_op` / `handle_storage_archive_op` handlers
//!   IN-PROCESS, so every budget / quote / wallet / custody gate is reused
//!   verbatim — no second mutation lane, no flattened provider semantics.
//! - No fee objects are minted in this cut. `routing_fee_eligibility:
//!   eligible_future` is recorded only when the decision actually compared
//!   two or more real candidates. The decision receipt is explicitly NOT a
//!   RoutingDecisionReceipt: no fee minted, no charge today.
//! - Restore truth stays the daemon-admitted sha256 `state_root` on
//!   `provider-materials`; failover REFUSES (fail closed, receipted) when
//!   no valid restore material exists, and falls back to the storage
//!   archive ladder (fetch → hash → decrypt → state_root) when daemon
//!   custody bytes are damaged.
//! - Old and new provider-native ids remain EVIDENCE ONLY on the run.
//! - Orchestration is RESUMABLE: a wallet 403 parks the run in
//!   `awaiting_authority_*` with the exact challenge echoed; the caller
//!   mints the grant and reposts with the phase grant to advance.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::decentralized_cloud_routes as dcr;
use super::DaemonState;

pub(crate) const DECISION_KIND: &str = "placement-decisions";
pub(crate) const DECISION_RECEIPT_KIND: &str = "placement-decision-receipts";
pub(crate) const FAILOVER_PLAN_KIND: &str = "failover-plans";
pub(crate) const FAILOVER_RUN_KIND: &str = "failover-runs";

pub(crate) const FAILURE_CONDITIONS: &[&str] = &[
    "provider_outage",
    "host_unreachable",
    "capacity_eviction",
    "credential_revoked",
    "storage_unavailable",
    "archive_invalid",
    "snapshot_invalid",
    "ingress_unavailable",
];

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}

fn text(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn load_account_by_ref(data_dir: &str, account_ref: &str) -> Option<Value> {
    super::read_record_dir(data_dir, "provider-accounts")
        .into_iter()
        .find(|a| text(a, "account_ref") == account_ref || text(a, "account_id") == account_ref)
}

// ---------------------------------------------------------------------------
// Deterministic candidate ranking — the SAME rule the advisory uses
// (+20 full_lifecycle, +10 conformance_reference, −5 prior failed ops,
// tie-break candidate_ref ascending), plus failover-specific filters.
// Ineligible candidates become `rejected[]` rows with named reason codes —
// the decision must cite what it did NOT pick and why.
// ---------------------------------------------------------------------------

struct Ranked {
    eligible: Vec<Value>,
    rejected: Vec<Value>,
}

fn rank_candidates(
    data_dir: &str,
    intent_ref: &str,
    exclude_provider_kind: Option<&str>,
    require_full_lifecycle: bool,
) -> Ranked {
    let mut eligible: Vec<(i64, String, Value)> = Vec::new();
    let mut rejected: Vec<Value> = Vec::new();
    for c in dcr::candidates_for(data_dir, intent_ref) {
        let c = dcr::with_read_status(c);
        let cref = text(&c, "candidate_ref");
        let kind = text(&c, "provider_kind");
        let status = text(&c, "status");
        let labels: Vec<String> = c
            .get("eligibility_labels")
            .and_then(|l| l.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let reject = |reason: &str, detail: String| {
            json!({
                "candidate_ref": cref,
                "provider_kind": kind,
                "reason_code": reason,
                "detail": detail,
            })
        };
        if status == "expired" {
            rejected.push(reject("expired_requires_requote", "candidate expired; requote via refresh".into()));
            continue;
        }
        if status == "superseded" {
            rejected.push(reject("superseded_by_newer_batch", "superseded candidate retained as evidence".into()));
            continue;
        }
        let sim_harness = labels.iter().any(|l| l == "simulated_control_plane");
        let eligible_flag = match c.get("placement_eligible") {
            Some(Value::Bool(true)) => true,
            // Simulator-mode candidates are honestly labeled advisory_only +
            // simulated_control_plane; the quote gate admits them when the
            // account mode matches, so the decision lane does too — with the
            // posture recorded on the decision, never laundered into "live".
            Some(Value::String(s)) if s == "advisory_only" && sim_harness => true,
            _ => false,
        };
        if !eligible_flag {
            rejected.push(reject(
                "not_placement_eligible",
                format!("eligibility_labels: {}", labels.join(",")),
            ));
            continue;
        }
        if let Some(ex) = exclude_provider_kind {
            if kind == ex {
                rejected.push(reject(
                    "same_class_as_failed_provider",
                    format!("failover requires a different provider class than '{ex}'"),
                ));
                continue;
            }
        }
        if require_full_lifecycle
            && !labels.iter().any(|l| l == "full_lifecycle" || l == "lifecycle_harness_only")
        {
            rejected.push(reject(
                "lifecycle_unproven_for_failover_target",
                "failover replacement requires a full_lifecycle candidate".into(),
            ));
            continue;
        }
        let mut score: i64 = 0;
        if labels.iter().any(|l| l == "full_lifecycle" || l == "lifecycle_harness_only") {
            score += 20;
        }
        if labels.iter().any(|l| l == "conformance_reference") {
            score += 10;
        }
        if c.get("reliability")
            .and_then(|r| r.get("ops_failed"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0)
            > 0
        {
            score -= 5;
        }
        eligible.push((score, cref, c));
    }
    eligible.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    Ranked { eligible: eligible.into_iter().map(|(_, _, c)| c).collect(), rejected }
}

// ---------------------------------------------------------------------------
// Placement decisions
// ---------------------------------------------------------------------------

fn mint_decision(
    data_dir: &str,
    intent: &Value,
    ranked: &Ranked,
    decision_mode: &str,
    failover_run_ref: Option<&str>,
    failover_policy: Value,
) -> (Value, Value) {
    let selected = &ranked.eligible[0];
    let alternatives: Vec<Value> = ranked.eligible[1..]
        .iter()
        .map(|c| {
            json!({
                "candidate_ref": text(c, "candidate_ref"),
                "provider_kind": text(c, "provider_kind"),
                "reason_code": "ranked_lower_deterministically",
            })
        })
        .collect();
    let fee_eligibility = if ranked.eligible.len() >= 2 { "eligible_future" } else { "not_applicable" };
    let id = format!("pld_{:x}", nanos());
    let decision_ref = format!("placement-decision://{id}");
    let mut decision = json!({
        "schema_version": "ioi.hypervisor.placement-decision.v1",
        "decision_id": id,
        "decision_ref": decision_ref,
        "decision_mode": decision_mode,
        "intent_ref": text(intent, "intent_ref"),
        "selected_candidate_ref": text(selected, "candidate_ref"),
        "selected": {
            "provider_kind": text(selected, "provider_kind"),
            "provider_account_ref": text(selected, "provider_account_ref"),
            "display_name": text(selected, "display_name"),
            "source": text(selected, "source"),
            "adapter_ref": text(selected, "adapter_ref"),
            "quote_ref": selected.get("quote_ref").cloned().unwrap_or(Value::Null),
            "spend_estimate": selected.get("spend_estimate").cloned().unwrap_or(Value::Null),
            "execution_posture": selected
                .get("eligibility_labels")
                .and_then(|l| l.as_array())
                .map(|a| a.iter().any(|x| x.as_str() == Some("simulated_control_plane")))
                .unwrap_or(false)
                .then_some("simulated_control_plane — labeled harness lane, never live supply")
                .unwrap_or("live_or_byo"),
        },
        "alternatives_considered": alternatives,
        "rejected_candidates": ranked.rejected,
        "custody_posture": text(intent, "custody_posture"),
        "spend_posture": {
            "cost_owner": "customer",
            "fee_object_minted": false,
            "routing_fee_eligibility": fee_eligibility,
            "note": "no fee minted in this cut; provider spend is customer-borne and quote-gated at mutation time",
        },
        "support_boundary": intent.get("support_boundary").cloned().unwrap_or(Value::Null),
        "failover_policy": failover_policy,
        "decided_at": super::iso_now(),
        "authority": "none — a placement decision is evidence, not authority; provider mutation still requires a wallet capability grant",
    });
    if let Some(fr) = failover_run_ref {
        decision["failover_run_ref"] = json!(fr);
    }
    let receipt_root = sha256_hex(&serde_json::to_vec(&decision).unwrap_or_default());
    decision["receipt_root"] = json!(receipt_root);
    let rid = format!("pdr_{:x}", nanos());
    let receipt = json!({
        "schema_version": "ioi.hypervisor.placement-decision-receipt.v1",
        "receipt_id": rid,
        "receipt_ref": format!("placement-decision-receipt://{rid}"),
        "decision_ref": decision["decision_ref"],
        "intent_ref": decision["intent_ref"],
        "selected_candidate_ref": decision["selected_candidate_ref"],
        "alternatives_count": ranked.eligible.len() - 1,
        "rejected_count": decision["rejected_candidates"].as_array().map(|a| a.len()).unwrap_or(0),
        "receipt_root": receipt_root,
        "no_fee": true,
        "fee_object_minted": false,
        "note": "NOT a RoutingDecisionReceipt — no fee minted, no charge today; this receipt exists so the placement choice is challengeable evidence",
        "at": super::iso_now(),
    });
    decision["receipt_ref"] = receipt["receipt_ref"].clone();
    let _ = super::persist_record(data_dir, DECISION_KIND, &id, &decision);
    let _ = super::persist_record(data_dir, DECISION_RECEIPT_KIND, &rid, &receipt);
    (decision, receipt)
}

/// POST /v1/hypervisor/placement/decisions — explicit optimized-placement
/// decision over live candidates (no mutation, no fee).
pub(crate) async fn handle_placement_decide(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let data_dir = st.data_dir.clone();
    let intent = body
        .get("intent_ref")
        .and_then(|v| v.as_str())
        .and_then(|r| dcr::load_intent(&data_dir, r))
        .unwrap_or_else(|| dcr::ensure_default_intent(&data_dir));
    // Refresh-through-advisory keeps decision inputs fresh + persisted.
    let advisory = dcr::advisory_for(&st, &intent, false).await;
    let ranked = rank_candidates(&data_dir, &text(&intent, "intent_ref"), None, false);
    if ranked.eligible.is_empty() {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "reason": "no_eligible_candidate",
                "detail": "no placement-eligible candidate exists; effective venue stays run_local (advisory mode)",
                "advisory": advisory,
                "rejected_candidates": ranked.rejected,
            })),
        );
    }
    let policy = body
        .get("failover_policy")
        .cloned()
        .unwrap_or(json!({ "mode": "manual", "replacement_rule": "different_provider_class_with_full_lifecycle" }));
    let (decision, receipt) = mint_decision(&data_dir, &intent, &ranked, "decision", None, policy);
    (StatusCode::OK, Json(json!({ "ok": true, "decision": decision, "receipt": receipt })))
}

pub(crate) async fn handle_placement_decisions_list(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    let mut items = super::read_record_dir(&st.data_dir, DECISION_KIND);
    items.sort_by_key(|d| std::cmp::Reverse(text(d, "decided_at")));
    Json(json!({
        "schema_version": "ioi.hypervisor.placement-decisions.v1",
        "decisions": items,
        "receipts": super::read_record_dir(&st.data_dir, DECISION_RECEIPT_KIND),
    }))
}

pub(crate) async fn handle_placement_decision_get(
    State(st): State<Arc<DaemonState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    match super::read_record_dir(&st.data_dir, DECISION_KIND)
        .into_iter()
        .find(|d| text(d, "decision_id") == id || text(d, "decision_ref").ends_with(&id))
    {
        Some(d) => (StatusCode::OK, Json(d)),
        None => (StatusCode::NOT_FOUND, Json(json!({"reason": "placement_decision_unknown"}))),
    }
}

// ---------------------------------------------------------------------------
// Failover plans
// ---------------------------------------------------------------------------

fn latest_admitted_material(data_dir: &str, env_ref: &str) -> Option<Value> {
    let mut mats: Vec<Value> = super::read_record_dir(data_dir, "provider-materials")
        .into_iter()
        .filter(|m| text(m, "environment_ref") == env_ref && !text(m, "state_root").is_empty())
        .collect();
    mats.sort_by_key(|m| std::cmp::Reverse(text(m, "material_ref")));
    mats.into_iter().next()
}

fn archives_for_material(data_dir: &str, material_ref: &str) -> Vec<Value> {
    super::read_record_dir(data_dir, "storage-archive-objects")
        .into_iter()
        .filter(|a| text(a, "material_ref") == material_ref)
        .collect()
}

/// Custody validation: the admitted state_root vs the bytes on disk.
fn validate_custody(material: &Value) -> Result<String, String> {
    let root = text(material, "state_root");
    let path = text(material, "path");
    if root.is_empty() || path.is_empty() {
        return Err("material record missing state_root/path".into());
    }
    match std::fs::read(&path) {
        Ok(bytes) if sha256_hex(&bytes) == root => Ok(root),
        Ok(_) => Err("custody_hash_mismatch".into()),
        Err(e) => Err(format!("custody_bytes_unreadable: {e}")),
    }
}

/// POST /v1/hypervisor/failover/plans
pub(crate) async fn handle_failover_plan_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let data_dir = st.data_dir.clone();
    let env_ref = text(&body, "environment_ref");
    if env_ref.is_empty() {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"reason": "environment_ref_required"})));
    }
    let source_account_ref = text(&body, "source_account_ref");
    let material = latest_admitted_material(&data_dir, &env_ref);
    let (material_ref, state_root, archives) = match &material {
        Some(m) => {
            let mref = text(m, "material_ref");
            let archives: Vec<String> = archives_for_material(&data_dir, &mref)
                .iter()
                .map(|a| text(a, "archive_ref"))
                .collect();
            (mref, text(m, "state_root"), archives)
        }
        None => (String::new(), String::new(), Vec::new()),
    };
    let id = format!("fpl_{:x}", nanos());
    let intent_ref = body
        .get("intent_ref")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| text(&dcr::ensure_default_intent(&data_dir), "intent_ref"));
    let plan = json!({
        "schema_version": "ioi.hypervisor.failover-plan.v1",
        "plan_id": id,
        "plan_ref": format!("failover-plan://{id}"),
        "environment_ref": env_ref,
        "intent_ref": intent_ref,
        "source_account_ref": source_account_ref,
        "restore_material_ref": material_ref,
        "state_root": state_root,
        "archive_refs": archives,
        "readiness": if material.is_some() { "ready_daemon_custody" } else { "no_restore_material" },
        "armed_conditions": body.get("armed_conditions").cloned().unwrap_or(json!(FAILURE_CONDITIONS)),
        "failover_policy": body.get("failover_policy").cloned().unwrap_or(json!({
            "mode": "manual",
            "replacement_rule": "different_provider_class_with_full_lifecycle",
        })),
        "created_at": super::iso_now(),
        "authority": "none — a failover plan is preparation evidence; every mutation it leads to is wallet-gated at execution time",
    });
    let _ = super::persist_record(&data_dir, FAILOVER_PLAN_KIND, &id, &plan);
    (StatusCode::OK, Json(json!({"ok": true, "plan": plan})))
}

pub(crate) async fn handle_failover_plans_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({
        "schema_version": "ioi.hypervisor.failover-plans.v1",
        "plans": super::read_record_dir(&st.data_dir, FAILOVER_PLAN_KIND),
    }))
}

// ---------------------------------------------------------------------------
// Failover runs — resumable orchestration
// ---------------------------------------------------------------------------

fn push_event(run: &mut Value, phase: &str, status: &str, detail: Value) {
    let ev = json!({
        "schema_version": "ioi.hypervisor.failover-event.v1",
        "phase": phase,
        "status": status,
        "detail": detail,
        "at": super::iso_now(),
    });
    if let Some(events) = run.get_mut("events").and_then(|e| e.as_array_mut()) {
        events.push(ev);
    }
}

fn persist_run(data_dir: &str, run: &Value) {
    let _ = super::persist_record(data_dir, FAILOVER_RUN_KIND, &text(run, "run_id"), run);
}

fn phase_done(run: &Value, phase: &str) -> bool {
    run.get("events")
        .and_then(|e| e.as_array())
        .map(|evs| evs.iter().any(|ev| text(ev, "phase") == phase && text(ev, "status") == "ok"))
        .unwrap_or(false)
}

fn awaiting(run: &mut Value, data_dir: &str, gate: &str, challenge: &Value) -> (StatusCode, Json<Value>) {
    run["status"] = json!(format!("awaiting_authority_{gate}"));
    run["next_required"] = json!({
        "gate": gate,
        "grant_body_key": format!("wallet_approval_grant_{gate}"),
        "approval": challenge.get("approval").cloned().unwrap_or(Value::Null),
        "challenge": challenge,
        "note": "mint the grant against approval.policy_hash/request_hash and repost /v1/hypervisor/failover/run with run_ref + the grant key above",
    });
    persist_run(data_dir, run);
    (StatusCode::OK, Json(json!({"ok": true, "run": run.clone()})))
}

fn refuse(run: &mut Value, data_dir: &str, reason: &str, detail: String) -> (StatusCode, Json<Value>) {
    run["status"] = json!("refused");
    run["refusal"] = json!({ "reason": reason, "detail": detail, "at": super::iso_now() });
    push_event(run, "refused", reason, json!({ "detail": detail }));
    persist_run(data_dir, run);
    (StatusCode::CONFLICT, Json(json!({"ok": false, "reason": reason, "run": run.clone()})))
}

async fn provider_op(st: &Arc<DaemonState>, body: Value) -> (StatusCode, Value) {
    let (code, Json(resp)) = super::provider_routes::handle_provider_op(State(st.clone()), Json(body)).await;
    (code, resp)
}

/// POST /v1/hypervisor/failover/run — create or resume a failover run.
pub(crate) async fn handle_failover_run(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let data_dir = st.data_dir.clone();

    // ---- load or create the run --------------------------------------
    let mut run = if let Some(rref) = body.get("run_ref").and_then(|v| v.as_str()) {
        match super::read_record_dir(&data_dir, FAILOVER_RUN_KIND)
            .into_iter()
            .find(|r| text(r, "run_ref") == rref || text(r, "run_id") == rref)
        {
            Some(r) => r,
            None => return (StatusCode::NOT_FOUND, Json(json!({"reason": "failover_run_unknown"}))),
        }
    } else {
        let condition = text(&body, "failure_condition");
        if !FAILURE_CONDITIONS.contains(&condition.as_str()) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "reason": "failover_condition_unknown",
                    "supported": FAILURE_CONDITIONS,
                })),
            );
        }
        let plan = body
            .get("plan_ref")
            .and_then(|v| v.as_str())
            .and_then(|pr| {
                super::read_record_dir(&data_dir, FAILOVER_PLAN_KIND)
                    .into_iter()
                    .find(|p| text(p, "plan_ref") == pr || text(p, "plan_id") == pr)
            })
            .or_else(|| {
                let env = text(&body, "environment_ref");
                let mut plans: Vec<Value> = super::read_record_dir(&data_dir, FAILOVER_PLAN_KIND)
                    .into_iter()
                    .filter(|p| text(p, "environment_ref") == env)
                    .collect();
                plans.sort_by_key(|p| std::cmp::Reverse(text(p, "created_at")));
                plans.into_iter().next()
            });
        let Some(plan) = plan else {
            return (StatusCode::CONFLICT, Json(json!({"reason": "failover_plan_required"})));
        };
        let old_account = load_account_by_ref(&data_dir, &text(&plan, "source_account_ref"));
        let old_kind = old_account.as_ref().map(|a| text(a, "kind")).unwrap_or_default();
        let id = format!("for_{:x}", nanos());
        let env_ref = text(&plan, "environment_ref");
        let mut r = json!({
            "schema_version": "ioi.hypervisor.failover-run.v1",
            "run_id": id,
            "run_ref": format!("failover-run://{id}"),
            "plan_ref": text(&plan, "plan_ref"),
            "intent_ref": text(&plan, "intent_ref"),
            "environment_ref": env_ref,
            "replacement_environment_ref": format!("{env_ref}-fo-{}", &id[4..id.len().min(12)]),
            "failure_condition": condition,
            "old_provider": {
                "account_ref": text(&plan, "source_account_ref"),
                "provider_kind": old_kind,
                "native_ids": "evidence_only — never restore truth",
            },
            "restore_material_ref": text(&plan, "restore_material_ref"),
            "state_root": text(&plan, "state_root"),
            "archive_refs": plan.get("archive_refs").cloned().unwrap_or(json!([])),
            "max_hourly_usd": body.get("max_hourly_usd").cloned().unwrap_or(Value::Null),
            "teardown_policy": body.get("teardown_policy").cloned().unwrap_or(json!("always")),
            "events": [],
            "receipt_refs": [],
            "status": "running",
            "started_at": super::iso_now(),
        });
        push_event(&mut r, "detected", "ok", json!({
            "failure_condition": condition,
            "mode": "accepted_named_condition",
            "note": "failure conditions may be detected or accepted by name; injection is only supported where safe (ssh/loopback/akash simulator)",
        }));
        persist_run(&data_dir, &r);
        r
    };

    if text(&run, "status") == "refused" {
        return (StatusCode::CONFLICT, Json(json!({"ok": false, "reason": "failover_run_already_refused", "run": run})));
    }
    run["next_required"] = Value::Null;

    // ---- phase: material_secured --------------------------------------
    if !phase_done(&run, "material_secured") {
        let mref = text(&run, "restore_material_ref");
        if mref.is_empty() {
            return refuse(&mut run, &data_dir, "failover_refused_no_restore_material",
                "no daemon-admitted provider material exists for this environment; fail closed — availability is not restore truth".into());
        }
        let material = super::read_record_dir(&data_dir, "provider-materials")
            .into_iter()
            .find(|m| text(m, "material_ref") == mref);
        let Some(material) = material else {
            return refuse(&mut run, &data_dir, "failover_refused_no_restore_material",
                format!("material record {mref} absent — fail closed"));
        };
        match validate_custody(&material) {
            Ok(root) => {
                push_event(&mut run, "material_secured", "ok", json!({
                    "restore_material_ref": mref, "state_root": root, "via": "daemon_custody",
                }));
            }
            Err(custody_err) => {
                // Daemon custody damaged → storage archive ladder (or refuse).
                let condition = text(&run, "failure_condition");
                let archives = run.get("archive_refs").and_then(|a| a.as_array()).cloned().unwrap_or_default();
                if condition == "storage_unavailable" || archives.is_empty() {
                    return refuse(&mut run, &data_dir, "snapshot_invalid",
                        format!("daemon custody invalid ({custody_err}) and no storage archive available — fail closed"));
                }
                let archive_ref = archives[0].as_str().unwrap_or("").to_string();
                let sbody = json!({
                    "op": "restore",
                    "archive_ref": archive_ref,
                    "material_ref": mref,
                    "wallet_approval_grant": body.get("wallet_approval_grant_archive_restore").cloned().unwrap_or(Value::Null),
                });
                let (code, Json(resp)) = super::storage_backend_routes::handle_storage_archive_op(
                    State(st.clone()), Json(sbody)).await;
                if code == StatusCode::FORBIDDEN {
                    return awaiting(&mut run, &data_dir, "archive_restore", &resp);
                }
                if code != StatusCode::OK {
                    return refuse(&mut run, &data_dir, "archive_invalid",
                        format!("storage archive restore failed ({}): {}", code, text(&resp, "reason")));
                }
                match validate_custody(&material) {
                    Ok(root) => {
                        if let Some(rr) = resp.get("receipt_ref") {
                            if let Some(arr) = run.get_mut("receipt_refs").and_then(|a| a.as_array_mut()) { arr.push(rr.clone()); }
                        }
                        push_event(&mut run, "material_secured", "ok", json!({
                            "restore_material_ref": mref, "state_root": root,
                            "via": "storage_archive_5_gate_ladder", "archive_ref": archive_ref,
                        }));
                    }
                    Err(e) => {
                        return refuse(&mut run, &data_dir, "archive_invalid",
                            format!("custody still invalid after archive restore ({e}) — fail closed"));
                    }
                }
            }
        }
        persist_run(&data_dir, &run);
    }

    // ---- phase: replacement_selected -----------------------------------
    if !phase_done(&run, "replacement_selected") {
        let intent = {
            let iref = text(&run, "intent_ref");
            if iref.is_empty() { None } else { dcr::load_intent(&data_dir, &iref) }
        }
        .unwrap_or_else(|| dcr::ensure_default_intent(&data_dir));
        let old_kind = run.get("old_provider").map(|o| text(o, "provider_kind")).unwrap_or_default();
        let ranked = rank_candidates(&data_dir, &text(&intent, "intent_ref"),
            if old_kind.is_empty() { None } else { Some(old_kind.as_str()) }, true);
        if ranked.eligible.is_empty() {
            return refuse(&mut run, &data_dir, "failover_no_replacement_candidate",
                format!("no placement-eligible full_lifecycle candidate outside class '{old_kind}' ({} rejected with reasons)", ranked.rejected.len()));
        }
        let policy = json!({ "mode": "failover", "replacement_rule": "different_provider_class_with_full_lifecycle", "excluded_class": old_kind });
        let (decision, receipt) = mint_decision(&data_dir, &intent, &ranked, "failover_replacement",
            Some(&text(&run, "run_ref")), policy);
        run["decision_ref"] = decision["decision_ref"].clone();
        run["replacement"] = json!({
            "candidate_ref": decision["selected_candidate_ref"],
            "provider_account_ref": decision["selected"]["provider_account_ref"],
            "provider_kind": decision["selected"]["provider_kind"],
            "native_ids": "evidence_only — never restore truth",
        });
        if let Some(arr) = run.get_mut("receipt_refs").and_then(|a| a.as_array_mut()) {
            arr.push(receipt["receipt_ref"].clone());
        }
        push_event(&mut run, "replacement_selected", "ok", json!({
            "decision_ref": decision["decision_ref"],
            "candidate_ref": decision["selected_candidate_ref"],
            "provider_kind": decision["selected"]["provider_kind"],
            "alternatives_considered": decision["alternatives_considered"].as_array().map(|a| a.len()).unwrap_or(0),
            "rejected": decision["rejected_candidates"].as_array().map(|a| a.len()).unwrap_or(0),
        }));
        persist_run(&data_dir, &run);
    }

    // ---- phase: replacement_created -------------------------------------
    if !phase_done(&run, "replacement_created") {
        let repl = run["replacement"].clone();
        let op_body = json!({
            "provider_id": text(&repl, "provider_account_ref"),
            "op": "create",
            "environment_ref": text(&run, "replacement_environment_ref"),
            "candidate_ref": text(&repl, "candidate_ref"),
            "max_hourly_usd": run.get("max_hourly_usd").cloned().unwrap_or(Value::Null),
            "teardown_policy": run.get("teardown_policy").cloned().unwrap_or(json!("always")),
            "plan": { "failover_run_ref": text(&run, "run_ref"), "decision_ref": run.get("decision_ref").cloned().unwrap_or(Value::Null) },
            "wallet_approval_grant": body.get("wallet_approval_grant_create").cloned().unwrap_or(Value::Null),
        });
        let (code, resp) = provider_op(&st, op_body).await;
        if code == StatusCode::FORBIDDEN {
            return awaiting(&mut run, &data_dir, "create", &resp);
        }
        if code != StatusCode::OK {
            return refuse(&mut run, &data_dir, "failover_replacement_create_failed",
                format!("{}: {}", code, text(&resp, "reason")));
        }
        if let Some(rr) = resp.get("receipt_ref") {
            if let Some(arr) = run.get_mut("receipt_refs").and_then(|a| a.as_array_mut()) { arr.push(rr.clone()); }
        }
        push_event(&mut run, "replacement_created", "ok", json!({
            "receipt_ref": resp.get("receipt_ref").cloned().unwrap_or(Value::Null),
            "provider_native_evidence": resp.get("evidence").cloned().unwrap_or(Value::Null),
        }));
        persist_run(&data_dir, &run);
    }

    // ---- phase: started (endpoints proven, never assumed) ------------------
    if !phase_done(&run, "started") {
        let repl = run["replacement"].clone();
        let op_body = json!({
            "provider_id": text(&repl, "provider_account_ref"),
            "op": "start",
            "environment_ref": text(&run, "replacement_environment_ref"),
            "plan": { "failover_run_ref": text(&run, "run_ref") },
            "wallet_approval_grant": body.get("wallet_approval_grant_start").cloned().unwrap_or(Value::Null),
        });
        let (code, resp) = provider_op(&st, op_body).await;
        if code == StatusCode::FORBIDDEN {
            return awaiting(&mut run, &data_dir, "start", &resp);
        }
        if code != StatusCode::OK {
            return refuse(&mut run, &data_dir, "failover_replacement_start_failed",
                format!("{}: {}", code, text(&resp, "reason")));
        }
        if let Some(rr) = resp.get("receipt_ref") {
            if let Some(arr) = run.get_mut("receipt_refs").and_then(|a| a.as_array_mut()) { arr.push(rr.clone()); }
        }
        push_event(&mut run, "started", "ok", json!({
            "endpoint_evidence": resp.get("evidence").and_then(|e| e.get("endpoint")).cloned().unwrap_or(Value::Null),
        }));
        persist_run(&data_dir, &run);
    }

    // ---- phase: restored --------------------------------------------------
    if !phase_done(&run, "restored") {
        let repl = run["replacement"].clone();
        let archive_ref = run
            .get("archive_refs")
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or(Value::Null);
        let op_body = json!({
            "provider_id": text(&repl, "provider_account_ref"),
            "op": "restore",
            "environment_ref": text(&run, "replacement_environment_ref"),
            "material_ref": text(&run, "restore_material_ref"),
            "restore_material_ref": text(&run, "restore_material_ref"),
            "archive_ref": archive_ref,
            "plan": { "failover_run_ref": text(&run, "run_ref") },
            "wallet_approval_grant": body.get("wallet_approval_grant_restore").cloned().unwrap_or(Value::Null),
        });
        let (code, resp) = provider_op(&st, op_body).await;
        if code == StatusCode::FORBIDDEN {
            return awaiting(&mut run, &data_dir, "restore", &resp);
        }
        if code != StatusCode::OK || text(&resp, "outcome") == "restore_refused" {
            return refuse(&mut run, &data_dir, "restore_refused",
                format!("state_root validation is mandatory; provider restore refused: {}", text(&resp, "reason")));
        }
        if let Some(rr) = resp.get("receipt_ref") {
            if let Some(arr) = run.get_mut("receipt_refs").and_then(|a| a.as_array_mut()) { arr.push(rr.clone()); }
        }
        let root = text(&run, "state_root");
        push_event(&mut run, "restored", "ok", json!({
            "state_root": root,
            "receipt_ref": resp.get("receipt_ref").cloned().unwrap_or(Value::Null),
        }));
        persist_run(&data_dir, &run);
    }

    // ---- phase: old_closed -------------------------------------------------
    if !phase_done(&run, "old_closed") {
        let condition = text(&run, "failure_condition");
        let old_ref = run.get("old_provider").map(|o| text(o, "account_ref")).unwrap_or_default();
        if condition == "credential_revoked" || old_ref.is_empty() {
            run["old_teardown"] = json!({ "state": "closed_with_warning",
                "warning": format!("teardown impossible ({condition}) — any open spend exposure stays visible with a standing warning") });
            push_event(&mut run, "old_closed", "ok", json!({ "state": "closed_with_warning", "condition": condition }));
        } else {
            let op_body = json!({
                "provider_id": old_ref,
                "op": "delete",
                "environment_ref": text(&run, "environment_ref"),
                "plan": { "failover_run_ref": text(&run, "run_ref") },
                "wallet_approval_grant": body.get("wallet_approval_grant_teardown").cloned().unwrap_or(Value::Null),
            });
            let (code, resp) = provider_op(&st, op_body).await;
            if code == StatusCode::FORBIDDEN {
                return awaiting(&mut run, &data_dir, "teardown", &resp);
            }
            if let Some(rr) = resp.get("receipt_ref") {
                if let Some(arr) = run.get_mut("receipt_refs").and_then(|a| a.as_array_mut()) { arr.push(rr.clone()); }
            }
            if code == StatusCode::OK {
                run["old_teardown"] = json!({ "state": "closed", "receipt_ref": resp.get("receipt_ref").cloned().unwrap_or(Value::Null) });
                push_event(&mut run, "old_closed", "ok", json!({ "state": "closed" }));
            } else {
                run["old_teardown"] = json!({ "state": "closed_with_warning",
                    "warning": format!("old provider teardown failed ({}): {} — spend exposure remains visible", code, text(&resp, "reason")) });
                push_event(&mut run, "old_closed", "ok", json!({ "state": "closed_with_warning" }));
            }
        }
        persist_run(&data_dir, &run);
    }

    let warned = run.get("old_teardown").map(|t| text(t, "state") == "closed_with_warning").unwrap_or(false);
    run["status"] = json!(if warned { "restored_with_warning" } else { "restored" });
    run["completed_at"] = json!(super::iso_now());
    persist_run(&data_dir, &run);
    (StatusCode::OK, Json(json!({"ok": true, "run": run})))
}

pub(crate) async fn handle_failover_runs_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut runs = super::read_record_dir(&st.data_dir, FAILOVER_RUN_KIND);
    runs.sort_by_key(|r| std::cmp::Reverse(text(r, "started_at")));
    Json(json!({
        "schema_version": "ioi.hypervisor.failover-runs.v1",
        "runs": runs,
        "supported_failure_conditions": FAILURE_CONDITIONS,
    }))
}

pub(crate) async fn handle_failover_run_get(
    State(st): State<Arc<DaemonState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    match super::read_record_dir(&st.data_dir, FAILOVER_RUN_KIND)
        .into_iter()
        .find(|r| text(r, "run_id") == id || text(r, "run_ref").ends_with(&id))
    {
        Some(r) => (StatusCode::OK, Json(r)),
        None => (StatusCode::NOT_FOUND, Json(json!({"reason": "failover_run_unknown"}))),
    }
}
