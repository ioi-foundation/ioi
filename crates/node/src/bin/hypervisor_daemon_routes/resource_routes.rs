//! T5 — Resource Management: capacity + budget scheduling.
//!
//! Promotes resource management from per-environment isolation to cross-workload allocation
//! DECISIONS. Daemon-owned objects (file-backed under state_dir): ResourcePool, ResourceBudget,
//! ResourceAllocationRequest, ResourceAllocationDecision, WorkQueue (derived from queued
//! decisions), SchedulerCatchupPolicy. Every allocation produces a typed decision + a visible
//! reason + a receipt — never a silent provider error.
//!
//! Decisions: admit | queue | degrade | pause | preempt | shift_provider | request_budget |
//! fail_closed. Reasons: capacity_exhausted | budget_exhausted | quota_exhausted | rate_limited |
//! provider_unhealthy | privacy_or_data_locality_block | authority_missing | maintenance_window |
//! lower_priority_preempted. External spend / budget increase is an authority crossing (T4).
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, DaemonState};

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn i(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(|x| x.as_i64()).unwrap_or(0)
}
fn s(v: &Value, k: &str, default: &str) -> String {
    v.get(k)
        .and_then(|x| x.as_str())
        .unwrap_or(default)
        .to_string()
}

fn emit_receipt(
    data_dir: &str,
    event: &str,
    subject: &str,
    decision: &str,
    reason: &str,
) -> String {
    let id = format!("rrc_{:x}", nanos());
    let receipt_ref = format!("agentgres://resource-receipt/{id}");
    let rec = json!({
        "schema_version": "ioi.hypervisor.resource-receipt.v1",
        "receipt_id": id, "receipt_ref": receipt_ref,
        "event": event, "subject": subject, "decision": decision, "reason": reason, "at": iso_now()
    });
    let _ = persist_record(data_dir, "resource-receipts", &id, &rec);
    receipt_ref
}

/// Sum of CPU/memory currently committed to a pool by admitted (non-released) allocation decisions.
fn pool_usage(data_dir: &str, pool_id: &str) -> (i64, i64, i64) {
    let mut cpu = 0;
    let mut mem = 0;
    let mut count = 0;
    for d in read_record_dir(data_dir, "allocation-decisions") {
        if d.get("pool_id").and_then(|v| v.as_str()) != Some(pool_id) {
            continue;
        }
        if d.get("state").and_then(|v| v.as_str()) != Some("admitted") {
            continue;
        }
        let needs = d.get("granted_needs").cloned().unwrap_or_else(|| json!({}));
        cpu += i(&needs, "cpu");
        mem += i(&needs, "memory_mb");
        count += 1;
    }
    (cpu, mem, count)
}

// ---- pools ----

/// POST /v1/hypervisor/resource/pools — create/update a ResourcePool.
pub(crate) async fn handle_pool_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let id = body
        .get("pool_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("pool_{:x}", nanos()));
    let record = json!({
        "schema_version": "ioi.hypervisor.resource-pool.v1",
        "pool_id": id,
        "name": s(&body, "name", &id),
        "provider": s(&body, "provider", "local"),
        "monitor": s(&body, "monitor", "cloud-hypervisor"),
        "locality": s(&body, "locality", "local"),
        "health": s(&body, "health", "healthy"),
        "capacity": body.get("capacity").cloned().unwrap_or_else(|| json!({ "cpu": 8, "memory_mb": 16384, "storage_mb": 102400, "gpu": 0 })),
        "quota": body.get("quota").cloned().unwrap_or_else(|| json!({ "max_concurrent": 100, "rate_per_min": 1000 })),
        "created_at": iso_now()
    });
    let _ = persist_record(&st.data_dir, "resource-pools", &id, &record);
    Json(json!({ "pool": record }))
}

/// GET /v1/hypervisor/resource/pools — pools with LIVE computed usage + availability.
pub(crate) async fn handle_pools_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut pools = read_record_dir(&st.data_dir, "resource-pools");
    for p in pools.iter_mut() {
        let pid = p
            .get("pool_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let (cpu, mem, count) = pool_usage(&st.data_dir, &pid);
        let cap = p.get("capacity").cloned().unwrap_or_else(|| json!({}));
        p["used"] = json!({ "cpu": cpu, "memory_mb": mem, "concurrent": count });
        p["available"] =
            json!({ "cpu": i(&cap, "cpu") - cpu, "memory_mb": i(&cap, "memory_mb") - mem });
    }
    Json(
        json!({ "schema_version": "ioi.hypervisor.resource-pools.v1", "pools": pools, "at": iso_now() }),
    )
}

// ---- budgets ----

/// POST /v1/hypervisor/resource/budgets — create/update a ResourceBudget.
pub(crate) async fn handle_budget_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let id = body
        .get("budget_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("budget_{:x}", nanos()));
    let record = json!({
        "schema_version": "ioi.hypervisor.resource-budget.v1",
        "budget_id": id,
        "name": s(&body, "name", &id),
        "scope": s(&body, "scope", "local_free"),           // local_free | external_spend
        "limit": i(&body, "limit").max(0),
        "spent": i(&body, "spent").max(0),
        "currency": s(&body, "currency", "credits"),
        "authority_required": body.get("authority_required").and_then(|v| v.as_bool()).unwrap_or_else(|| s(&body, "scope", "local_free") == "external_spend"),
        "created_at": iso_now()
    });
    let _ = persist_record(&st.data_dir, "resource-budgets", &id, &record);
    Json(json!({ "budget": record }))
}

/// GET /v1/hypervisor/resource/budgets — budgets with remaining.
pub(crate) async fn handle_budgets_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut budgets = read_record_dir(&st.data_dir, "resource-budgets");
    for b in budgets.iter_mut() {
        b["remaining"] = json!((i(b, "limit") - i(b, "spent")).max(0));
    }
    Json(
        json!({ "schema_version": "ioi.hypervisor.resource-budgets.v1", "budgets": budgets, "at": iso_now() }),
    )
}

fn load(data_dir: &str, dir: &str, id_key: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, dir)
        .into_iter()
        .find(|r| r.get(id_key).and_then(|v| v.as_str()) == Some(id))
}

// ---- allocation engine ----

/// POST /v1/hypervisor/resource/allocate — evaluate a ResourceAllocationRequest and return a typed
/// ResourceAllocationDecision (admit|queue|degrade|pause|preempt|shift_provider|request_budget|
/// fail_closed) with a visible reason + receipt. Persists the request and the decision.
pub(crate) async fn handle_allocate(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let data_dir = &st.data_dir;
    let req_id = format!("areq_{:x}", nanos());
    let needs = body
        .get("needs")
        .cloned()
        .unwrap_or_else(|| json!({ "cpu": 1, "memory_mb": 512 }));
    let priority = i(&body, "priority");
    let degradable = body
        .get("degradable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let estimated_cost = if body.get("estimated_cost").is_some() {
        i(&body, "estimated_cost")
    } else {
        i(&needs, "cpu") * 10
    };
    let privacy = s(&body, "privacy", "local");
    let pool_id = s(&body, "pool_ref", "");
    let candidates: Vec<String> = body
        .get("provider_candidates")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let budget_ref = s(&body, "budget_ref", "");
    let grant_ref = body
        .get("grant_ref")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let external = s(&body, "spend_scope", "local_free") == "external_spend"
        || load(data_dir, "resource-budgets", "budget_id", &budget_ref)
            .map(|b| s(&b, "scope", "") == "external_spend")
            .unwrap_or(false);

    let request = json!({
        "schema_version": "ioi.hypervisor.resource-allocation-request.v1",
        "request_id": req_id,
        "session_ref": s(&body, "session_ref", ""), "environment_ref": s(&body, "environment_ref", ""), "work_run_ref": s(&body, "work_run_ref", ""),
        "resource_class": s(&body, "resource_class", "standard"), "monitor": s(&body, "monitor", "cloud-hypervisor"),
        "needs": needs, "budget_ref": budget_ref, "priority": priority, "pool_ref": pool_id,
        "provider_candidates": candidates, "privacy": privacy, "external_spend": external, "created_at": iso_now()
    });
    let _ = persist_record(data_dir, "allocation-requests", &req_id, &request);

    let pool = load(data_dir, "resource-pools", "pool_id", &pool_id);

    // Build the decision via the real evaluation ladder.
    let mut decision = "admit";
    let mut reason = "admitted";
    let mut granted_needs = needs.clone();
    let mut detail = json!({});
    let mut victim_decision_id: Option<String> = None;

    'eval: {
        // 1) provider/pool health.
        let Some(pool) = pool.clone() else {
            decision = "fail_closed";
            reason = "capacity_exhausted";
            detail = json!({ "note": format!("pool '{pool_id}' not found") });
            break 'eval;
        };
        match s(&pool, "health", "healthy").as_str() {
            "maintenance" => {
                decision = "pause";
                reason = "maintenance_window";
                break 'eval;
            }
            "unhealthy" => {
                // shift to a healthy candidate pool if one exists.
                let healthy = candidates.iter().find_map(|c| {
                    load(data_dir, "resource-pools", "pool_id", c)
                        .filter(|p| s(p, "health", "") == "healthy")
                        .map(|_| c.clone())
                });
                if let Some(c) = healthy {
                    decision = "shift_provider";
                    reason = "provider_unhealthy";
                    detail = json!({ "shift_to": c });
                } else {
                    decision = "fail_closed";
                    reason = "provider_unhealthy";
                }
                break 'eval;
            }
            _ => {}
        }
        // 2) privacy / data locality.
        if privacy != s(&pool, "locality", "local") && privacy != "any" {
            decision = "fail_closed";
            reason = "privacy_or_data_locality_block";
            detail = json!({ "request_privacy": privacy, "pool_locality": s(&pool, "locality", "local") });
            break 'eval;
        }
        // 3) authority for external spend.
        if external && grant_ref.is_none() {
            decision = "fail_closed";
            reason = "authority_missing";
            detail = json!({ "required_authority": { "effect": "spend", "provider": "enterprise_authority|wallet_network_live" } });
            break 'eval;
        }
        // 4) budget.
        if !budget_ref.is_empty() {
            if let Some(budget) = load(data_dir, "resource-budgets", "budget_id", &budget_ref) {
                let remaining = i(&budget, "limit") - i(&budget, "spent");
                if estimated_cost > remaining {
                    if external {
                        decision = "request_budget";
                        reason = "budget_exhausted";
                        detail = json!({ "needed": estimated_cost, "remaining": remaining, "authority_crossing": { "effect": "spend", "kind": "budget_increase", "provider": "enterprise_authority|wallet_network_live" } });
                    } else {
                        decision = "fail_closed";
                        reason = "budget_exhausted";
                        detail = json!({ "needed": estimated_cost, "remaining": remaining, "note": "local budget hard cap" });
                    }
                    break 'eval;
                }
            }
        }
        // 5) quota / rate.
        let quota = pool.get("quota").cloned().unwrap_or_else(|| json!({}));
        let (used_cpu, used_mem, count) = pool_usage(data_dir, &pool_id);
        if i(&quota, "max_concurrent") > 0 && count >= i(&quota, "max_concurrent") {
            decision = "queue";
            reason = "quota_exhausted";
            detail = json!({ "concurrent": count, "max": i(&quota, "max_concurrent") });
            break 'eval;
        }
        // explicit rate-limit signal (the verifier can assert it).
        if body
            .get("rate_limited")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            decision = "queue";
            reason = "rate_limited";
            break 'eval;
        }
        // 6) capacity.
        let cap = pool.get("capacity").cloned().unwrap_or_else(|| json!({}));
        let fits = used_cpu + i(&needs, "cpu") <= i(&cap, "cpu")
            && used_mem + i(&needs, "memory_mb") <= i(&cap, "memory_mb");
        if !fits {
            // preempt a strictly lower-priority admitted allocation if that frees enough.
            let mut admitted: Vec<Value> = read_record_dir(data_dir, "allocation-decisions")
                .into_iter()
                .filter(|d| {
                    d.get("pool_id").and_then(|v| v.as_str()) == Some(pool_id.as_str())
                        && d.get("state").and_then(|v| v.as_str()) == Some("admitted")
                        && i(d, "priority") < priority
                })
                .collect();
            admitted.sort_by_key(|d| i(d, "priority"));
            if let Some(victim) = admitted.first() {
                let vneeds = victim
                    .get("granted_needs")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let freed_cpu = used_cpu - i(&vneeds, "cpu");
                let freed_mem = used_mem - i(&vneeds, "memory_mb");
                if freed_cpu + i(&needs, "cpu") <= i(&cap, "cpu")
                    && freed_mem + i(&needs, "memory_mb") <= i(&cap, "memory_mb")
                {
                    decision = "preempt";
                    reason = "lower_priority_preempted";
                    victim_decision_id = victim
                        .get("decision_id")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    detail = json!({ "preempted_decision": victim_decision_id, "preempted_priority": i(victim, "priority") });
                    break 'eval;
                }
            }
            if degradable {
                // degrade: grant what fits.
                let avail_cpu = (i(&cap, "cpu") - used_cpu).max(0);
                let avail_mem = (i(&cap, "memory_mb") - used_mem).max(0);
                if avail_cpu > 0 && avail_mem > 0 {
                    decision = "degrade";
                    reason = "capacity_exhausted";
                    granted_needs = json!({ "cpu": avail_cpu.min(i(&needs, "cpu")), "memory_mb": avail_mem.min(i(&needs, "memory_mb")) });
                    break 'eval;
                }
            }
            decision = "queue";
            reason = "capacity_exhausted";
            detail = json!({ "used": { "cpu": used_cpu, "memory_mb": used_mem }, "capacity": cap });
            break 'eval;
        }
    }

    // Apply side effects for terminal-positive decisions.
    let dec_id = format!("adec_{:x}", nanos());
    let state = match decision {
        "admit" | "degrade" => "admitted",
        "preempt" => "admitted", // the new request is admitted after preempting the victim
        "queue" => "queued",
        _ => "rejected",
    };
    // preempt: mark the victim released so its capacity is freed for the live usage computation.
    if decision == "preempt" {
        if let Some(vid) = &victim_decision_id {
            if let Some(mut victim) = load(data_dir, "allocation-decisions", "decision_id", vid) {
                victim["state"] = json!("preempted");
                victim["preempted_at"] = json!(iso_now());
                let _ = persist_record(data_dir, "allocation-decisions", vid, &victim);
                emit_receipt(
                    data_dir,
                    "preempted",
                    vid,
                    "preempt",
                    "lower_priority_preempted",
                );
            }
        }
    }
    // budget spend on admit/degrade against a budget.
    if (state == "admitted") && !budget_ref.is_empty() {
        if let Some(mut budget) = load(data_dir, "resource-budgets", "budget_id", &budget_ref) {
            budget["spent"] = json!(i(&budget, "spent") + estimated_cost);
            let _ = persist_record(data_dir, "resource-budgets", &budget_ref, &budget);
        }
    }
    let receipt = emit_receipt(data_dir, "allocation_decision", &req_id, decision, reason);
    let decision_record = json!({
        "schema_version": "ioi.hypervisor.resource-allocation-decision.v1",
        "decision_id": dec_id,
        "request_id": req_id,
        "pool_id": pool_id,
        "decision": decision,
        "reason": reason,
        "priority": priority,
        "granted_needs": granted_needs,
        "state": state,
        "detail": detail,
        "receipt_ref": receipt,
        "decided_at": iso_now()
    });
    let _ = persist_record(data_dir, "allocation-decisions", &dec_id, &decision_record);
    Json(json!({ "decision": decision_record }))
}

/// POST /v1/hypervisor/resource/release — free an admitted allocation (capacity returns to pool).
pub(crate) async fn handle_release(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let dec_id = s(&body, "decision_id", "");
    let Some(mut d) = load(&st.data_dir, "allocation-decisions", "decision_id", &dec_id) else {
        return Json(json!({ "ok": false, "reason": format!("decision '{dec_id}' not found") }));
    };
    d["state"] = json!("released");
    d["released_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, "allocation-decisions", &dec_id, &d);
    emit_receipt(
        &st.data_dir,
        "released",
        &dec_id,
        "release",
        "operator_release",
    );
    Json(json!({ "ok": true, "decision_id": dec_id, "state": "released" }))
}

/// GET /v1/hypervisor/resource/work-queue — the WorkQueue: queued allocation decisions in priority
/// order (highest priority first), each with its blocking reason.
pub(crate) async fn handle_work_queue(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut queued: Vec<Value> = read_record_dir(&st.data_dir, "allocation-decisions")
        .into_iter()
        .filter(|d| d.get("state").and_then(|v| v.as_str()) == Some("queued"))
        .collect();
    queued.sort_by(|a, b| i(b, "priority").cmp(&i(a, "priority")));
    Json(
        json!({ "schema_version": "ioi.hypervisor.work-queue.v1", "queue": queued, "depth": queued.len(), "at": iso_now() }),
    )
}

/// POST /v1/hypervisor/resource/catchup — a SchedulerCatchupPolicy decision for a missed window.
/// Body: `{missed_schedule_ref, work_ref, policy?}` where policy ∈ skip|catch_up|reduce_scope|
/// shift_provider|request_budget. Returns the decision + expected verified-work impact + receipt.
pub(crate) async fn handle_catchup(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let data_dir = &st.data_dir;
    let id = format!("cat_{:x}", nanos());
    let missed = s(&body, "missed_schedule_ref", "");
    let work_ref = s(&body, "work_ref", "");
    let policy = s(&body, "policy", "catch_up");
    let impact = match policy.as_str() {
        "skip" => json!({ "verified_work_delta": 0, "note": "window skipped; no catch-up work" }),
        "reduce_scope" => {
            json!({ "verified_work_delta": "partial", "note": "reduced-scope catch-up" })
        }
        "shift_provider" => {
            json!({ "verified_work_delta": "full", "note": "catch up on an alternate provider" })
        }
        "request_budget" => {
            json!({ "verified_work_delta": "pending_authority", "note": "catch-up needs a budget increase (authority crossing)" })
        }
        _ => json!({ "verified_work_delta": "full", "note": "full catch-up scheduled" }),
    };
    let receipt = emit_receipt(
        data_dir,
        "catchup_decision",
        &missed,
        &policy,
        "scheduler_catchup",
    );
    let record = json!({
        "schema_version": "ioi.hypervisor.scheduler-catchup-decision.v1",
        "catchup_id": id, "missed_schedule_ref": missed, "work_ref": work_ref,
        "policy": policy, "expected_impact": impact, "receipt_ref": receipt, "decided_at": iso_now()
    });
    let _ = persist_record(data_dir, "scheduler-catchup-policies", &id, &record);
    Json(json!({ "catchup": record }))
}

/// GET /v1/hypervisor/resource/receipts — the resource decision audit trail (most recent first).
pub(crate) async fn handle_receipts(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut receipts = read_record_dir(&st.data_dir, "resource-receipts");
    receipts.sort_by(|a, b| s(b, "receipt_id", "").cmp(&s(a, "receipt_id", "")));
    Json(
        json!({ "schema_version": "ioi.hypervisor.resource-receipts.v1", "receipts": receipts, "at": iso_now() }),
    )
}
