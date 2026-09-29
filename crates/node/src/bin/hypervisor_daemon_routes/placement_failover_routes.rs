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
//! - A run ACTS AS ITS STARTER (R-240, failover teardown identity): the
//!   principal whose authenticated request created it (or armed the plan
//!   that triggered it) and the one owner that request named, recorded as
//!   `started_by`. Every provider op the run makes crosses as that
//!   principal, re-resolved against their current membership; only the
//!   starter may resume the run; and an old-provider teardown that does not
//!   complete leaves the run `restored_old_exposure_open`, never a quiet
//!   warning.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::cloud_candidate_routes as dcr;
use super::substrate_store::RequestIdentity;
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
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
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
            rejected.push(reject(
                "expired_requires_requote",
                "candidate expired; requote via refresh".into(),
            ));
            continue;
        }
        if status == "superseded" {
            rejected.push(reject(
                "superseded_by_newer_batch",
                "superseded candidate retained as evidence".into(),
            ));
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
            && !labels
                .iter()
                .any(|l| l == "full_lifecycle" || l == "lifecycle_harness_only")
        {
            rejected.push(reject(
                "lifecycle_unproven_for_failover_target",
                "failover replacement requires a full_lifecycle candidate".into(),
            ));
            continue;
        }
        let mut score: i64 = 0;
        if labels
            .iter()
            .any(|l| l == "full_lifecycle" || l == "lifecycle_harness_only")
        {
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
    Ranked {
        eligible: eligible.into_iter().map(|(_, _, c)| c).collect(),
        rejected,
    }
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
) -> Result<(Value, Value), (String, String)> {
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
    let fee_eligibility = if ranked.eligible.len() >= 2 {
        "eligible_future"
    } else {
        "not_applicable"
    };
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
    // W1.2 / MEF-GAP-008 — decision-then-receipt order; both must commit. The receipt-failure error
    // names the persisted decision_ref so the caller can point at the now-unevidenced decision.
    if super::persist_record(data_dir, DECISION_KIND, &id, &decision).is_err() {
        return Err((
            "placement_decision_persistence_failed".to_string(),
            format!("the placement decision {decision_ref} did not commit — no decision or receipt was recorded"),
        ));
    }
    if super::persist_record(data_dir, DECISION_RECEIPT_KIND, &rid, &receipt).is_err() {
        return Err((
            "placement_decision_receipt_persistence_failed".to_string(),
            format!("placement decision {decision_ref} committed but its challengeable receipt did not — the decision is not honestly evidenced"),
        ));
    }
    Ok((decision, receipt))
}

/// POST /v1/hypervisor/placement/decisions — explicit optimized-placement
/// decision over live candidates (no mutation, no fee).
pub(crate) async fn handle_placement_decide(
    State(st): State<Arc<DaemonState>>,
    inbound: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let data_dir = st.data_dir.clone();
    let intent = body
        .get("intent_ref")
        .and_then(|v| v.as_str())
        .and_then(|r| dcr::load_intent(&data_dir, r))
        .unwrap_or_else(|| dcr::ensure_default_intent(&data_dir));
    // Refresh-through-advisory keeps decision inputs fresh + persisted.
    let advisory = match dcr::advisory_for(&st, &intent, false, &inbound).await {
        Ok(a) => a,
        Err((code, message)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "code": code, "message": message })),
            )
        }
    };
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
    let (decision, receipt) =
        match mint_decision(&data_dir, &intent, &ranked, "decision", None, policy) {
            Ok(v) => v,
            Err((code, message)) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "ok": false, "code": code, "message": message })),
                )
            }
        };
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "decision": decision, "receipt": receipt })),
    )
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
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"reason": "placement_decision_unknown"})),
        ),
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
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"reason": "environment_ref_required"})),
        );
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
    // W1.2 / MEF-GAP-008 — load_plan / run_core / evaluate_all all read this plan back; a discarded
    // write hands back a plan_ref that resolves to nothing. Fail closed.
    if super::persist_record(&data_dir, FAILOVER_PLAN_KIND, &id, &plan).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "failover_plan_persistence_failed",
            "message": "the failover plan did not commit — no plan was created" }),
            ),
        );
    }
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

fn persist_run(data_dir: &str, run: &Value) -> std::io::Result<()> {
    super::persist_record(data_dir, FAILOVER_RUN_KIND, &text(run, "run_id"), run)
}

fn phase_done(run: &Value, phase: &str) -> bool {
    run.get("events")
        .and_then(|e| e.as_array())
        .map(|evs| {
            evs.iter()
                .any(|ev| text(ev, "phase") == phase && text(ev, "status") == "ok")
        })
        .unwrap_or(false)
}

fn awaiting(run: &mut Value, data_dir: &str, gate: &str, challenge: &Value) -> (StatusCode, Value) {
    run["status"] = json!(format!("awaiting_authority_{gate}"));
    run["next_required"] = json!({
        "gate": gate,
        "grant_body_key": format!("wallet_approval_grant_{gate}"),
        "approval": challenge.get("approval").cloned().unwrap_or(Value::Null),
        "challenge": challenge,
        "note": "mint the grant against approval.policy_hash/request_hash and repost /v1/hypervisor/failover/run with run_ref + the grant key above",
    });
    // W1.2 / MEF-GAP-008 — a non-durable authority park lets the wallet-gated provider op replay on
    // the next post; if the park does not commit, fail closed (500) rather than returning it.
    if persist_run(data_dir, run).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "code": "failover_run_persistence_failed",
            "message": format!("the awaiting-authority park for gate '{gate}' did not commit — refusing rather than leaving a non-durable park a wallet-gated provider op could replay"),
            "run_ref": text(run, "run_ref"),
            "receipt_refs": run.get("receipt_refs").cloned().unwrap_or(json!([])) }),
        );
    }
    (StatusCode::OK, json!({"ok": true, "run": run.clone()}))
}

fn refuse(run: &mut Value, data_dir: &str, reason: &str, detail: String) -> (StatusCode, Value) {
    run["status"] = json!("refused");
    run["refusal"] = json!({ "reason": reason, "detail": detail, "at": super::iso_now() });
    push_event(run, "refused", reason, json!({ "detail": detail }));
    // W1.2 / MEF-GAP-008 — a non-durable refusal could be replayed as a fresh run; commit it or 500.
    if persist_run(data_dir, run).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "code": "failover_run_persistence_failed",
            "message": format!("the refusal '{reason}' did not commit — refusing durably rather than leaving a non-durable park"),
            "run_ref": text(run, "run_ref"),
            "receipt_refs": run.get("receipt_refs").cloned().unwrap_or(json!([])) }),
        );
    }
    (
        StatusCode::CONFLICT,
        json!({"ok": false, "reason": reason, "run": run.clone()}),
    )
}

// ---------------------------------------------------------------------------
// Who a failover run acts as (R-240, failover teardown identity)
// ---------------------------------------------------------------------------

/// The principal a failover run's provider ops cross as, and the one owner they are owned by.
///
/// Recorded on the run as `started_by` from the authenticated request that created it — or, for an
/// auto-triggered run, from the authenticated request that ARMED the plan — and never read from a
/// later body. Every op re-resolves this principal's current membership narrowed to the owner
/// (`provider_routes::invoke_failover_run_provider_operation`), so nothing a failover does is
/// anonymous or done as the daemon: the old provider's teardown crosses as the starter, exactly as
/// the starter's own teardown of that environment would.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FailoverStarter {
    pub(crate) principal_ref: String,
    pub(crate) owner_ref: String,
}

impl FailoverStarter {
    /// The binding a record carries, or None when it names no principal or owner — a run started, or
    /// a plan armed, before starters were recorded. That absence is refused by name and never filled
    /// in afterwards: a starter inferred after the fact is a starter nobody authenticated.
    fn from_record(binding: Option<&Value>, principal_key: &str) -> Option<Self> {
        let binding = binding?;
        let principal_ref = text(binding, principal_key);
        let owner_ref = text(binding, "owner_ref");
        let principal_ok =
            principal_ref.starts_with("user://") && principal_ref.len() > "user://".len();
        let owner_ok = matches!(owner_ref.split_once("://"), Some(("org" | "project", tail)) if !tail.is_empty());
        (principal_ok && owner_ok).then_some(Self {
            principal_ref,
            owner_ref,
        })
    }
}

/// The caller driving ONE post of a failover run: an authenticated request, or — for an auto-trigger
/// — the plan's arming principal re-resolved against current membership. A create also names the
/// run's owner and its idempotency key (one owner, one key: one run).
pub(crate) struct FailoverActor {
    identity: RequestIdentity,
    create: Option<(String, String)>,
    via: &'static str,
}

/// The actor of an HTTP post. Identity is the FIRST gate: a create is an owned write
/// (`require_write_caller` — authenticated, `owner_ref` the caller holds, `idempotency_key`); a resume
/// needs an authenticated principal, and the run's own `started_by` then says whether it may drive it.
fn failover_request_actor(
    data_dir: &str,
    headers: &HeaderMap,
    body: &Value,
) -> Result<FailoverActor, (StatusCode, Value)> {
    if body.get("run_ref").and_then(Value::as_str).is_some() {
        let identity = super::substrate_store::resolve_request_identity(data_dir, headers)
            .map_err(|refusal| {
                let (status, Json(reply)) =
                    super::mutation_event_foundation::scope_refusal_reply(refusal);
                (status, reply)
            })?;
        return Ok(FailoverActor {
            identity,
            create: None,
            via: "request",
        });
    }
    let caller = super::mutation_event_foundation::require_write_caller(data_dir, headers, body)
        .map_err(|(status, Json(reply))| (status, reply))?;
    Ok(FailoverActor {
        identity: caller.identity,
        create: Some((caller.owner_ref, caller.idempotency_key)),
        via: "request",
    })
}

/// The create fields a retried create must repeat under its idempotency key.
fn failover_create_fingerprint(body: &Value) -> String {
    let fields = json!({
        "plan_ref": body.get("plan_ref").cloned().unwrap_or(Value::Null),
        "environment_ref": body.get("environment_ref").cloned().unwrap_or(Value::Null),
        "failure_condition": body.get("failure_condition").cloned().unwrap_or(Value::Null),
        "max_hourly_usd": body.get("max_hourly_usd").cloned().unwrap_or(Value::Null),
        "teardown_policy": body.get("teardown_policy").cloned().unwrap_or(Value::Null),
    });
    sha256_hex(&serde_jcs::to_vec(&fields).unwrap_or_default())
}

/// One op of the run, one key: the parked call and the retry that names its approval are the same
/// request, so the key is derived from the run and the phase, never from the post.
fn failover_op_idempotency_key(run: &Value, phase: &str) -> String {
    format!("{}.{phase}", text(run, "run_id"))
}

/// A provider op of this run, crossing as its starter. There is no other way for the run core to
/// reach the provider route: an anonymous internal op is not expressible here.
async fn provider_op(
    st: &Arc<DaemonState>,
    starter: &FailoverStarter,
    run: &Value,
    phase: &str,
    mut body: Value,
) -> (StatusCode, Value) {
    let idempotency_key = failover_op_idempotency_key(run, phase);
    body["owner_ref"] = json!(starter.owner_ref);
    body["idempotency_key"] = json!(idempotency_key);
    let (code, Json(resp)) = super::provider_routes::invoke_failover_run_provider_operation(
        st.clone(),
        body,
        &starter.principal_ref,
        &starter.owner_ref,
        &idempotency_key,
        &text(run, "run_ref"),
    )
    .await;
    (code, resp)
}

/// A 403 that is an authority ASK — the gate published the exact coordinates to approve. Any other
/// refusal is not a gate a run can park at.
fn is_authority_ask(code: StatusCode, resp: &Value) -> bool {
    code == StatusCode::FORBIDDEN && resp.get("approval").is_some_and(Value::is_object)
}

/// The starter could not cross as themselves (their membership no longer names the run's owner, or
/// the substrate could not say). Nothing crossed, so the run neither advances nor is refused: the
/// post is refused by name, and a later post by the starter resumes the run where it stands.
fn starter_could_not_cross(code: StatusCode, resp: &Value) -> bool {
    code == StatusCode::UNAUTHORIZED
        || code == StatusCode::SERVICE_UNAVAILABLE
        || (code == StatusCode::FORBIDDEN && !is_authority_ask(code, resp))
}

fn starter_refusal(
    run: &Value,
    phase: &str,
    code: StatusCode,
    resp: &Value,
) -> (StatusCode, Value) {
    (
        code,
        json!({
            "ok": false,
            "code": "failover_starter_could_not_cross",
            "reason": "failover_starter_could_not_cross",
            "message": format!("the {phase} op could not cross as the run's starter — nothing crossed and the run did not advance; the starter resumes it once their membership names the run's owner"),
            "phase": phase,
            "refusal": resp,
            "run_ref": text(run, "run_ref"),
            "started_by": run.get("started_by").cloned().unwrap_or(Value::Null),
        }),
    )
}

/// Whether a teardown the provider route answered ok actually took the old environment down. A
/// provider with a native destroy (the marketplaces and clouds) says so in `native_teardown.destroyed`
/// — the same verdict that closes its spend exposure; a provider with none (a customer's own ssh
/// host, the loopback runner) holds no exposure, and its `cleanup_verified` says whether the
/// environment is gone. Absent both, nothing confirmed it.
fn teardown_confirmed(resp: &Value) -> bool {
    match resp
        .pointer("/evidence/native_teardown/destroyed")
        .and_then(Value::as_bool)
    {
        Some(destroyed) => destroyed,
        None => {
            resp.pointer("/evidence/cleanup_verified")
                .and_then(Value::as_bool)
                == Some(true)
        }
    }
}

/// POST /v1/hypervisor/failover/run — create or resume a failover run.
pub(crate) async fn handle_failover_run(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let actor = match failover_request_actor(&st.data_dir, &headers, &body) {
        Ok(actor) => actor,
        Err((code, reply)) => return (code, Json(reply)),
    };
    let (code, v) = failover_run_core(&st, body, &actor).await;
    (code, Json(v))
}

/// Shared run core: the HTTP handler and the auto-trigger evaluator both
/// use this one path — an automatically triggered run crosses EXACTLY the
/// same wallet gates as an operator-initiated one (INV-1: the trigger is
/// detection + preparation, never authority).
pub(crate) async fn failover_run_core(
    st: &Arc<DaemonState>,
    body: Value,
    actor: &FailoverActor,
) -> (StatusCode, Value) {
    let data_dir = st.data_dir.clone();

    // ---- load or create the run --------------------------------------
    let find_run = |needle: &str| {
        super::read_record_dir(&data_dir, FAILOVER_RUN_KIND)
            .into_iter()
            .find(|r| text(r, "run_ref") == needle || text(r, "run_id") == needle)
    };
    let replayed_create = match (&actor.create, body.get("run_ref")) {
        (Some((owner_ref, create_key)), None) => {
            let id =
                super::mutation_event_foundation::replay_stable_id("for", owner_ref, create_key);
            find_run(&id)
        }
        _ => None,
    };
    let mut run = if let Some(rref) = body.get("run_ref").and_then(|v| v.as_str()) {
        match find_run(rref) {
            Some(r) => r,
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    json!({"reason": "failover_run_unknown"}),
                )
            }
        }
    } else if let Some(existing) = replayed_create {
        // A retried create — one owner, one key — resumes the run it created; a different create
        // under the same key is refused rather than answered with someone else's run.
        if text(&existing, "create_fingerprint") != failover_create_fingerprint(&body) {
            return (
                StatusCode::CONFLICT,
                json!({
                    "ok": false,
                    "code": "failover_run_idempotency_key_reused",
                    "message": "this idempotency key already created a failover run with different create fields — a key names one run",
                    "run_ref": text(&existing, "run_ref"),
                }),
            );
        }
        existing
    } else {
        let Some((owner_ref, create_key)) = actor.create.clone() else {
            return (
                StatusCode::BAD_REQUEST,
                json!({
                    "ok": false,
                    "code": "mutation_owner_ref_required",
                    "message": "a failover run is created by an owned write: owner_ref and idempotency_key are required",
                }),
            );
        };
        let condition = text(&body, "failure_condition");
        if !FAILURE_CONDITIONS.contains(&condition.as_str()) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({
                    "reason": "failover_condition_unknown",
                    "supported": FAILURE_CONDITIONS,
                }),
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
            return (
                StatusCode::CONFLICT,
                json!({"reason": "failover_plan_required"}),
            );
        };
        let old_account = load_account_by_ref(&data_dir, &text(&plan, "source_account_ref"));
        let old_kind = old_account
            .as_ref()
            .map(|a| text(a, "kind"))
            .unwrap_or_default();
        // One owner, one key: one run (a retried create above resumes it rather than minting a twin).
        let id = super::mutation_event_foundation::replay_stable_id("for", &owner_ref, &create_key);
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
            // WHO THIS RUN ACTS AS: every provider op below crosses as this principal under this
            // owner, and only this principal may resume the run (R-240, failover teardown identity).
            "started_by": {
                "principal_ref": actor.identity.principal_ref,
                "owner_ref": owner_ref,
                "via": actor.via,
                "idempotency_key": create_key,
            },
            "create_fingerprint": failover_create_fingerprint(&body),
        });
        if let Some(tb) = body.get("triggered_by") {
            r["triggered_by"] = tb.clone();
        }
        push_event(
            &mut r,
            "detected",
            "ok",
            json!({
                "failure_condition": condition,
                "mode": if body.get("triggered_by").is_some() { "auto_policy_evidence" } else { "accepted_named_condition" },
                "note": "failure conditions may be detected or accepted by name; injection is only supported where safe (ssh/loopback/akash simulator)",
            }),
        );
        // W1.2 / MEF-GAP-008 — a non-durable run cannot be resumed or reconciled; fail closed.
        if persist_run(&data_dir, &r).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "ok": false, "code": "failover_run_persistence_failed",
                "message": "the failover run did not commit at creation — nothing was started",
                "run_ref": text(&r, "run_ref") }),
            );
        }
        r
    };

    // ---- who this run acts as ------------------------------------------
    let Some(starter) = FailoverStarter::from_record(run.get("started_by"), "principal_ref") else {
        return (
            StatusCode::CONFLICT,
            json!({
                "ok": false,
                "code": "failover_run_starter_unrecorded",
                "reason": "failover_run_starter_unrecorded",
                "message": "this failover run does not record who started it, so there is no one its provider ops could cross as — it is never resumed anonymously or as the daemon; start a new failover run",
                "run_ref": text(&run, "run_ref"),
            }),
        );
    };
    if starter.principal_ref != actor.identity.principal_ref {
        return (
            StatusCode::FORBIDDEN,
            json!({
                "ok": false,
                "code": "failover_run_starter_mismatch",
                "reason": "failover_run_starter_mismatch",
                "message": "a failover run's provider ops cross as the principal who started it, so only that principal may drive it",
                "run_ref": text(&run, "run_ref"),
            }),
        );
    }
    if !actor.identity.authorizes_tenant(&starter.owner_ref) {
        let (status, Json(reply)) = super::mutation_event_foundation::scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::TenantAuthorityRequired,
        );
        return (status, reply);
    }

    if text(&run, "status") == "refused" {
        return (
            StatusCode::CONFLICT,
            json!({"ok": false, "reason": "failover_run_already_refused", "run": run}),
        );
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
            return refuse(
                &mut run,
                &data_dir,
                "failover_refused_no_restore_material",
                format!("material record {mref} absent — fail closed"),
            );
        };
        match validate_custody(&material) {
            Ok(root) => {
                push_event(
                    &mut run,
                    "material_secured",
                    "ok",
                    json!({
                        "restore_material_ref": mref, "state_root": root, "via": "daemon_custody",
                    }),
                );
            }
            Err(custody_err) => {
                // Daemon custody damaged → storage archive ladder (or refuse).
                let condition = text(&run, "failure_condition");
                let archives = run
                    .get("archive_refs")
                    .and_then(|a| a.as_array())
                    .cloned()
                    .unwrap_or_default();
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
                let (code, Json(resp)) =
                    super::storage_backend_routes::dispatch_storage_archive_op(st, sbody).await;
                if code == StatusCode::FORBIDDEN {
                    return awaiting(&mut run, &data_dir, "archive_restore", &resp);
                }
                if code != StatusCode::OK {
                    return refuse(
                        &mut run,
                        &data_dir,
                        "archive_invalid",
                        format!(
                            "storage archive restore failed ({}): {}",
                            code,
                            text(&resp, "reason")
                        ),
                    );
                }
                match validate_custody(&material) {
                    Ok(root) => {
                        if let Some(rr) = resp.get("receipt_ref") {
                            if let Some(arr) =
                                run.get_mut("receipt_refs").and_then(|a| a.as_array_mut())
                            {
                                arr.push(rr.clone());
                            }
                        }
                        push_event(
                            &mut run,
                            "material_secured",
                            "ok",
                            json!({
                                "restore_material_ref": mref, "state_root": root,
                                "via": "storage_archive_5_gate_ladder", "archive_ref": archive_ref,
                            }),
                        );
                    }
                    Err(e) => {
                        return refuse(
                            &mut run,
                            &data_dir,
                            "archive_invalid",
                            format!(
                                "custody still invalid after archive restore ({e}) — fail closed"
                            ),
                        );
                    }
                }
            }
        }
        // W1.2 / MEF-GAP-008 — a discarded phase write leaves the run not durably advanced; phases
        // are idempotent (phase_done gates each), so a retried post resumes safely. Fail closed and
        // carry the provider receipt_refs minted so far so nothing is lost silently.
        if persist_run(&data_dir, &run).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "ok": false, "code": "failover_run_persistence_failed",
                "message": "a failover run phase did not commit — the run is not durably advanced; retry the post to resume",
                "run_ref": text(&run, "run_ref"),
                "receipt_refs": run.get("receipt_refs").cloned().unwrap_or(json!([])) }),
            );
        }
    }

    // ---- phase: replacement_selected -----------------------------------
    if !phase_done(&run, "replacement_selected") {
        let intent = {
            let iref = text(&run, "intent_ref");
            if iref.is_empty() {
                None
            } else {
                dcr::load_intent(&data_dir, &iref)
            }
        }
        .unwrap_or_else(|| dcr::ensure_default_intent(&data_dir));
        let old_kind = run
            .get("old_provider")
            .map(|o| text(o, "provider_kind"))
            .unwrap_or_default();
        let ranked = rank_candidates(
            &data_dir,
            &text(&intent, "intent_ref"),
            if old_kind.is_empty() {
                None
            } else {
                Some(old_kind.as_str())
            },
            true,
        );
        if ranked.eligible.is_empty() {
            return refuse(&mut run, &data_dir, "failover_no_replacement_candidate",
                format!("no placement-eligible full_lifecycle candidate outside class '{old_kind}' ({} rejected with reasons)", ranked.rejected.len()));
        }
        let policy = json!({ "mode": "failover", "replacement_rule": "different_provider_class_with_full_lifecycle", "excluded_class": old_kind });
        let (decision, receipt) = match mint_decision(
            &data_dir,
            &intent,
            &ranked,
            "failover_replacement",
            Some(&text(&run, "run_ref")),
            policy,
        ) {
            Ok(v) => v,
            Err((code, message)) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({ "ok": false, "code": code, "message": message,
                    "run_ref": text(&run, "run_ref"),
                    "receipt_refs": run.get("receipt_refs").cloned().unwrap_or(json!([])) }),
                )
            }
        };
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
        push_event(
            &mut run,
            "replacement_selected",
            "ok",
            json!({
                "decision_ref": decision["decision_ref"],
                "candidate_ref": decision["selected_candidate_ref"],
                "provider_kind": decision["selected"]["provider_kind"],
                "alternatives_considered": decision["alternatives_considered"].as_array().map(|a| a.len()).unwrap_or(0),
                "rejected": decision["rejected_candidates"].as_array().map(|a| a.len()).unwrap_or(0),
            }),
        );
        // W1.2 / MEF-GAP-008 — a discarded phase write leaves the run not durably advanced; phases
        // are idempotent (phase_done gates each), so a retried post resumes safely. Fail closed and
        // carry the provider receipt_refs minted so far so nothing is lost silently.
        if persist_run(&data_dir, &run).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "ok": false, "code": "failover_run_persistence_failed",
                "message": "a failover run phase did not commit — the run is not durably advanced; retry the post to resume",
                "run_ref": text(&run, "run_ref"),
                "receipt_refs": run.get("receipt_refs").cloned().unwrap_or(json!([])) }),
            );
        }
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
        let (code, resp) = provider_op(&st, &starter, &run, "create", op_body).await;
        if is_authority_ask(code, &resp) {
            return awaiting(&mut run, &data_dir, "create", &resp);
        }
        if starter_could_not_cross(code, &resp) {
            return starter_refusal(&run, "create", code, &resp);
        }
        if code != StatusCode::OK {
            return refuse(
                &mut run,
                &data_dir,
                "failover_replacement_create_failed",
                format!("{}: {}", code, text(&resp, "reason")),
            );
        }
        if let Some(rr) = resp.get("receipt_ref") {
            if let Some(arr) = run.get_mut("receipt_refs").and_then(|a| a.as_array_mut()) {
                arr.push(rr.clone());
            }
        }
        push_event(
            &mut run,
            "replacement_created",
            "ok",
            json!({
                "receipt_ref": resp.get("receipt_ref").cloned().unwrap_or(Value::Null),
                "provider_native_evidence": resp.get("evidence").cloned().unwrap_or(Value::Null),
            }),
        );
        // W1.2 / MEF-GAP-008 — a discarded phase write leaves the run not durably advanced; phases
        // are idempotent (phase_done gates each), so a retried post resumes safely. Fail closed and
        // carry the provider receipt_refs minted so far so nothing is lost silently.
        if persist_run(&data_dir, &run).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "ok": false, "code": "failover_run_persistence_failed",
                "message": "a failover run phase did not commit — the run is not durably advanced; retry the post to resume",
                "run_ref": text(&run, "run_ref"),
                "receipt_refs": run.get("receipt_refs").cloned().unwrap_or(json!([])) }),
            );
        }
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
        let (code, resp) = provider_op(&st, &starter, &run, "start", op_body).await;
        if is_authority_ask(code, &resp) {
            return awaiting(&mut run, &data_dir, "start", &resp);
        }
        if starter_could_not_cross(code, &resp) {
            return starter_refusal(&run, "start", code, &resp);
        }
        if code != StatusCode::OK {
            return refuse(
                &mut run,
                &data_dir,
                "failover_replacement_start_failed",
                format!("{}: {}", code, text(&resp, "reason")),
            );
        }
        if let Some(rr) = resp.get("receipt_ref") {
            if let Some(arr) = run.get_mut("receipt_refs").and_then(|a| a.as_array_mut()) {
                arr.push(rr.clone());
            }
        }
        push_event(
            &mut run,
            "started",
            "ok",
            json!({
                "endpoint_evidence": resp.get("evidence").and_then(|e| e.get("endpoint")).cloned().unwrap_or(Value::Null),
            }),
        );
        // W1.2 / MEF-GAP-008 — a discarded phase write leaves the run not durably advanced; phases
        // are idempotent (phase_done gates each), so a retried post resumes safely. Fail closed and
        // carry the provider receipt_refs minted so far so nothing is lost silently.
        if persist_run(&data_dir, &run).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "ok": false, "code": "failover_run_persistence_failed",
                "message": "a failover run phase did not commit — the run is not durably advanced; retry the post to resume",
                "run_ref": text(&run, "run_ref"),
                "receipt_refs": run.get("receipt_refs").cloned().unwrap_or(json!([])) }),
            );
        }
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
        let (code, resp) = provider_op(&st, &starter, &run, "restore", op_body).await;
        if is_authority_ask(code, &resp) {
            return awaiting(&mut run, &data_dir, "restore", &resp);
        }
        if starter_could_not_cross(code, &resp) {
            return starter_refusal(&run, "restore", code, &resp);
        }
        if code != StatusCode::OK || text(&resp, "outcome") == "restore_refused" {
            return refuse(
                &mut run,
                &data_dir,
                "restore_refused",
                format!(
                    "state_root validation is mandatory; provider restore refused: {}",
                    text(&resp, "reason")
                ),
            );
        }
        if let Some(rr) = resp.get("receipt_ref") {
            if let Some(arr) = run.get_mut("receipt_refs").and_then(|a| a.as_array_mut()) {
                arr.push(rr.clone());
            }
        }
        let root = text(&run, "state_root");
        push_event(
            &mut run,
            "restored",
            "ok",
            json!({
                "state_root": root,
                "receipt_ref": resp.get("receipt_ref").cloned().unwrap_or(Value::Null),
            }),
        );
        // W1.2 / MEF-GAP-008 — a discarded phase write leaves the run not durably advanced; phases
        // are idempotent (phase_done gates each), so a retried post resumes safely. Fail closed and
        // carry the provider receipt_refs minted so far so nothing is lost silently.
        if persist_run(&data_dir, &run).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "ok": false, "code": "failover_run_persistence_failed",
                "message": "a failover run phase did not commit — the run is not durably advanced; retry the post to resume",
                "run_ref": text(&run, "run_ref"),
                "receipt_refs": run.get("receipt_refs").cloned().unwrap_or(json!([])) }),
            );
        }
    }

    // ---- phase: old_closed -------------------------------------------------
    // The old provider's teardown crosses as the starter, like every op of this run (it used to go
    // out anonymous, answer 401, and close the run `restored_with_warning` with the old exposure
    // still open). A teardown is an owner-scoped write that needs no fresh spend authority — provider
    // cleanup never does — so it parks only if its gate ever asks. CLOSED means the provider route
    // answered ok AND the provider-native destroy confirmed. Anything else — refused, failed,
    // unconfirmed or impossible — leaves the old environment and its exposure OPEN: named on the run,
    // the phase left undone so the next post by the starter retries it, and the run
    // `restored_old_exposure_open` (R-240, failover teardown identity).
    if !phase_done(&run, "old_closed") {
        let condition = text(&run, "failure_condition");
        let env_ref = text(&run, "environment_ref");
        let old_ref = run
            .get("old_provider")
            .map(|o| text(o, "account_ref"))
            .unwrap_or_default();
        let acting = json!({
            "principal_ref": starter.principal_ref,
            "owner_ref": starter.owner_ref,
            "idempotency_key": failover_op_idempotency_key(&run, "teardown"),
        });
        let attempts = run
            .pointer("/old_teardown/attempts")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            + 1;
        let still_open: Option<(&str, String, Value, Value)> = if old_ref.is_empty() {
            Some((
                "old_provider_unknown",
                "the plan names no source provider account, so this run cannot tear the old environment down".into(),
                Value::Null,
                Value::Null,
            ))
        } else if condition == "credential_revoked" {
            Some((
                "teardown_impossible_credential_revoked",
                "the old provider's credential is revoked, so its environment cannot be torn down from here".into(),
                Value::Null,
                Value::Null,
            ))
        } else {
            let op_body = json!({
                "provider_id": old_ref,
                "op": "delete",
                "environment_ref": env_ref,
                "plan": { "failover_run_ref": text(&run, "run_ref") },
                "wallet_approval_grant": body.get("wallet_approval_grant_teardown").cloned().unwrap_or(Value::Null),
            });
            let (code, resp) = provider_op(&st, &starter, &run, "teardown", op_body).await;
            if is_authority_ask(code, &resp) {
                return awaiting(&mut run, &data_dir, "teardown", &resp);
            }
            let receipt = resp.get("receipt_ref").cloned().unwrap_or(Value::Null);
            if !receipt.is_null() {
                if let Some(arr) = run.get_mut("receipt_refs").and_then(|a| a.as_array_mut()) {
                    arr.push(receipt.clone());
                }
            }
            let routed_ok = code == StatusCode::OK && resp.get("ok") == Some(&json!(true));
            let destroyed = teardown_confirmed(&resp);
            let teardown_state = resp
                .pointer("/evidence/teardown_state")
                .cloned()
                .unwrap_or(Value::Null);
            if routed_ok && destroyed {
                run["old_teardown"] = json!({
                    "state": "closed",
                    "receipt_ref": receipt,
                    "teardown_state": teardown_state,
                    "acting": acting,
                    "attempts": attempts,
                    "closed_at": super::iso_now(),
                });
                push_event(
                    &mut run,
                    "old_closed",
                    "ok",
                    json!({ "state": "closed", "acting_principal_ref": starter.principal_ref }),
                );
                None
            } else if routed_ok {
                Some((
                    "teardown_unconfirmed",
                    format!("the provider route ran the teardown but the provider-native destroy did not confirm (teardown_state {teardown_state})"),
                    json!(code.as_u16()),
                    receipt,
                ))
            } else {
                let why = [
                    text(&resp, "code"),
                    text(&resp, "reason"),
                    text(&resp, "message"),
                ]
                .into_iter()
                .find(|s| !s.is_empty())
                .unwrap_or_else(|| "no reason given".into());
                Some((
                    if code == StatusCode::OK {
                        "teardown_failed"
                    } else {
                        "teardown_refused"
                    },
                    format!("{code}: {why}"),
                    json!(code.as_u16()),
                    receipt,
                ))
            }
        };
        if let Some((reason, detail, http_status, receipt)) = still_open {
            let old_exposure = super::read_record_dir(&data_dir, "provider-spend-exposures")
                .into_iter()
                .filter(|e| {
                    text(e, "account_ref") == old_ref && text(e, "environment_ref") == env_ref
                })
                .max_by_key(|e| text(e, "opened_at"));
            run["old_teardown"] = json!({
                "state": "open",
                "reason": reason,
                "detail": detail,
                "http_status": http_status,
                "receipt_ref": receipt,
                "old_exposure_ref": old_exposure.as_ref().map(|e| json!(text(e, "exposure_ref"))).unwrap_or(Value::Null),
                "old_exposure_status": old_exposure.as_ref().map(|e| json!(text(e, "status"))).unwrap_or(Value::Null),
                "acting": acting,
                "attempts": attempts,
                "last_attempt_at": super::iso_now(),
                "warning": "the old environment was NOT torn down: it and any spend exposure it holds stay open and may still accrue on the customer's account — repost this run to retry the teardown, or tear the environment down directly",
            });
            push_event(
                &mut run,
                "old_closed",
                "open",
                json!({ "state": "open", "reason": reason, "detail": detail }),
            );
        }
        // W1.2 / MEF-GAP-008 — a discarded phase write leaves the run not durably advanced; phases
        // are idempotent (phase_done gates each), so a retried post resumes safely. Fail closed and
        // carry the provider receipt_refs minted so far so nothing is lost silently.
        if persist_run(&data_dir, &run).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "ok": false, "code": "failover_run_persistence_failed",
                "message": "a failover run phase did not commit — the run is not durably advanced; retry the post to resume",
                "run_ref": text(&run, "run_ref"),
                "receipt_refs": run.get("receipt_refs").cloned().unwrap_or(json!([])) }),
            );
        }
    }

    if phase_done(&run, "old_closed") {
        run["status"] = json!("restored");
        run["completed_at"] = json!(super::iso_now());
    } else {
        // Restored on the replacement, and the old side is still open: the status says so, and so
        // does what the run needs next — never a quiet `restored_with_warning`.
        run["status"] = json!("restored_old_exposure_open");
        run["next_required"] = json!({
            "gate": "teardown",
            "old_exposure_ref": run.pointer("/old_teardown/old_exposure_ref").cloned().unwrap_or(Value::Null),
            "reason": run.pointer("/old_teardown/reason").cloned().unwrap_or(Value::Null),
            "note": "the old environment's teardown did not complete and its exposure stays open — repost /v1/hypervisor/failover/run with run_ref (as the run's starter) to retry it",
        });
    }
    // W1.2 / MEF-GAP-008 — the terminal status is the run's completion truth; if it does not commit,
    // the run stays mid-phase durably. Fail closed rather than report a false completion.
    if persist_run(&data_dir, &run).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "code": "failover_run_persistence_failed",
            "message": "the failover run's terminal status did not commit — the run is not durably marked restored",
            "run_ref": text(&run, "run_ref"),
            "receipt_refs": run.get("receipt_refs").cloned().unwrap_or(json!([])) }),
        );
    }
    (StatusCode::OK, json!({"ok": true, "run": run}))
}

// ---------------------------------------------------------------------------
// Auto-failover policy trigger — operators DECLARE when a plan may trigger
// automatically from provider evidence. "Automatic" means detection,
// preparation, and loud surfacing: a triggered run advances through the
// unattended phases and PARKS at the wallet gate exactly where an
// operator-initiated run would. Same gates, no fee object, no standing
// authority (INV-1). Detection is evidence-mapped, never guessed — every
// trigger cites the daemon records it read.
// ---------------------------------------------------------------------------

/// Conditions the detector can currently map from real daemon records.
/// Declared conditions outside this set still work for operator-initiated
/// runs; arming warns when a condition has no detector coverage.
pub(crate) const DETECTOR_COVERAGE: &[&str] = &[
    "credential_revoked",
    "capacity_eviction",
    "host_unreachable",
    "storage_unavailable",
];

fn load_plan(data_dir: &str, id_or_ref: &str) -> Option<Value> {
    super::read_record_dir(data_dir, FAILOVER_PLAN_KIND)
        .into_iter()
        .find(|p| {
            text(p, "plan_id") == id_or_ref
                || text(p, "plan_ref") == id_or_ref
                || text(p, "plan_ref").ends_with(id_or_ref)
        })
}

fn persist_plan(data_dir: &str, plan: &Value) -> std::io::Result<()> {
    super::persist_record(data_dir, FAILOVER_PLAN_KIND, &text(plan, "plan_id"), plan)
}

/// Evidence detector: map real daemon records to a named failure condition.
/// Only evidence NEWER than `since` (RFC3339 lexicographic compare) counts,
/// so stale history can never re-trigger an armed plan.
fn detect_failure_evidence(
    data_dir: &str,
    plan: &Value,
    conditions: &[String],
    since: &str,
) -> Option<(String, Vec<String>, String)> {
    let env_ref = text(plan, "environment_ref");
    let source_ref = text(plan, "source_account_ref");
    let wants = |c: &str| conditions.iter().any(|x| x == c);

    // credential_revoked — the source account's credential is gone/revoked.
    if wants("credential_revoked") {
        if let Some(acct) = load_account_by_ref(data_dir, &source_ref) {
            if text(&acct, "status") == "revoked" {
                return Some((
                    "credential_revoked".into(),
                    vec![text(&acct, "account_ref")],
                    "source provider account status is revoked".into(),
                ));
            }
        }
    }
    // capacity_eviction — provider-side lease loss (akash: lease_lost /
    // closed_by_provider records minted by the simulated revocation lane).
    if wants("capacity_eviction") {
        for d in super::read_record_dir(data_dir, "akash-deployments") {
            let ts = text(&d, "updated_at");
            if text(&d, "environment_ref") == env_ref
                && text(&d, "status") == "lease_lost"
                // stateful record: a missing timestamp still counts — the
                // single-shot armed→triggered ladder prevents re-trigger loops
                && (ts.is_empty() || ts.as_str() > since)
            {
                let mut refs = vec![text(&d, "deployment_ref")];
                if !text(&d, "lease_ref").is_empty() {
                    refs.push(text(&d, "lease_ref"));
                }
                return Some((
                    "capacity_eviction".into(),
                    refs,
                    "provider-side lease loss recorded on the deployment".into(),
                ));
            }
        }
    }
    // host_unreachable — error receipts on this environment naming
    // connectivity failure.
    if wants("host_unreachable") {
        for r in super::read_record_dir(data_dir, "provider-receipts") {
            let detail = format!(
                "{} {}",
                text(&r, "reason"),
                r.get("evidence").map(|e| e.to_string()).unwrap_or_default()
            )
            .to_lowercase();
            if text(&r, "environment_ref") == env_ref
                && text(&r, "outcome") == "error"
                && text(&r, "at").as_str() > since
                && (detail.contains("unreachable")
                    || detail.contains("connect")
                    || detail.contains("ssh"))
            {
                return Some((
                    "host_unreachable".into(),
                    vec![text(&r, "receipt_ref")],
                    "connectivity-failure receipt on the environment".into(),
                ));
            }
        }
    }
    // storage_unavailable — an OPEN availability incident on one of the
    // plan's archives.
    if wants("storage_unavailable") {
        let archives: Vec<String> = plan
            .get("archive_refs")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        for i in super::read_record_dir(data_dir, "artifact-availability-incidents") {
            if text(&i, "status") == "open"
                && archives.contains(&text(&i, "archive_ref"))
                && text(&i, "opened_at").as_str() > since
            {
                return Some((
                    "storage_unavailable".into(),
                    vec![text(&i, "incident_ref")],
                    "open availability incident on a plan archive".into(),
                ));
            }
        }
    }
    None
}

/// POST /v1/hypervisor/failover/plans/:id/arm
pub(crate) async fn handle_failover_plan_arm(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let data_dir = st.data_dir.clone();
    // Identity first (R-240, failover teardown identity): a triggered run's provider ops cross as the
    // principal who armed the plan, under the owner they named here — so arming is an owned write.
    // It confers no authority: every mutation of a triggered run still parks at its gate.
    let caller =
        match super::mutation_event_foundation::require_write_caller(&data_dir, &headers, &body) {
            Ok(caller) => caller,
            Err(reply) => return reply,
        };
    let Some(mut plan) = load_plan(&data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"reason": "failover_plan_unknown"})),
        );
    };
    if text(&plan, "readiness") == "no_restore_material" {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "reason": "failover_plan_not_ready",
                "detail": "arming requires a valid restore material — a trigger without restore truth could only fail closed",
            })),
        );
    }
    let conditions: Vec<String> = body
        .get("conditions")
        .and_then(|c| c.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if conditions.is_empty()
        || conditions
            .iter()
            .any(|c| !FAILURE_CONDITIONS.contains(&c.as_str()))
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"reason": "failover_condition_unknown", "supported": FAILURE_CONDITIONS})),
        );
    }
    let uncovered: Vec<&String> = conditions
        .iter()
        .filter(|c| !DETECTOR_COVERAGE.contains(&c.as_str()))
        .collect();
    plan["auto_trigger"] = json!({
        "enabled": true,
        "conditions": conditions,
        "detector_coverage": DETECTOR_COVERAGE,
        "uncovered_conditions_note": if uncovered.is_empty() { Value::Null } else {
            json!(format!("conditions {:?} have no detector coverage yet — they remain operator-declared only", uncovered))
        },
        "cooldown_note": "after a trigger the plan moves to `triggered`; re-arming is an explicit operator action — a trigger loop is structurally impossible",
        "max_hourly_usd": body.get("max_hourly_usd").cloned().unwrap_or(Value::Null),
        "armed_by": body.get("armed_by").cloned().unwrap_or(json!("operator")),
        // who a triggered run acts as, from the authenticated arming request — never a body label
        "armed_by_principal_ref": caller.identity.principal_ref,
        "owner_ref": caller.owner_ref,
        "arm_idempotency_key": caller.idempotency_key,
        "armed_at": super::iso_now(),
        "authority_note": "arming is detection + preparation authority only; every provider mutation of a triggered run still crosses the wallet gate",
    });
    plan["trigger_state"] = json!("armed");
    if persist_plan(&data_dir, &plan).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "failover_plan_persistence_failed",
            "message": "arming did not commit — the plan is not durably armed" }),
            ),
        );
    }
    (StatusCode::OK, Json(json!({"ok": true, "plan": plan})))
}

/// POST /v1/hypervisor/failover/plans/:id/disarm
pub(crate) async fn handle_failover_plan_disarm(
    State(st): State<Arc<DaemonState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    let data_dir = st.data_dir.clone();
    let Some(mut plan) = load_plan(&data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"reason": "failover_plan_unknown"})),
        );
    };
    plan["trigger_state"] = json!("disarmed");
    if let Some(t) = plan.get_mut("auto_trigger") {
        t["enabled"] = json!(false);
        t["disarmed_at"] = json!(super::iso_now());
    }
    // W1.2 / MEF-GAP-008 — CRITICAL fail-closed: a discarded disarm leaves the auto-trigger LIVE
    // while reporting disarmed. Refuse rather than silently keep an armed plan.
    if persist_plan(&data_dir, &plan).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "failover_plan_persistence_failed",
            "message": "disarm did not commit — the auto-trigger may still be live; treat the plan as ARMED" }),
            ),
        );
    }
    (StatusCode::OK, Json(json!({"ok": true, "plan": plan})))
}

async fn evaluate_plan(st: &Arc<DaemonState>, plan: &Value) -> Value {
    let data_dir = st.data_dir.clone();
    let plan_ref = text(plan, "plan_ref");
    let state = text(plan, "trigger_state");
    if state != "armed" {
        return json!({ "plan_ref": plan_ref, "outcome": if state.is_empty() { "disarmed" } else { state.as_str() } });
    }
    // one active run per plan — a second trigger can never stack
    let active = super::read_record_dir(&data_dir, FAILOVER_RUN_KIND)
        .into_iter()
        .any(|r| {
            text(&r, "plan_ref") == plan_ref
                && (text(&r, "status") == "running"
                    || text(&r, "status").starts_with("awaiting_authority"))
        });
    if active {
        return json!({ "plan_ref": plan_ref, "outcome": "active_run_exists" });
    }
    let trigger = plan.get("auto_trigger").cloned().unwrap_or(json!({}));
    let conditions: Vec<String> = trigger
        .get("conditions")
        .and_then(|c| c.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let since = text(&trigger, "armed_at");
    let Some((condition, evidence_refs, detail)) =
        detect_failure_evidence(&data_dir, plan, &conditions, &since)
    else {
        let mut p = plan.clone();
        p["last_evaluated_at"] = json!(super::iso_now());
        // CLASSIFIED — best-effort telemetry: last_evaluated_at is advisory bookkeeping; no decision reads it.
        let _ = persist_plan(&data_dir, &p);
        return json!({ "plan_ref": plan_ref, "outcome": "no_qualifying_evidence", "conditions": conditions });
    };
    // TRIGGER: same run core, same wallet gates; run parks at the first
    // authority gate. The trigger cites its evidence.
    let triggered_by = json!({
        "mode": "auto_policy",
        "plan_ref": plan_ref,
        "condition": condition,
        "evidence_refs": evidence_refs,
        "detail": detail,
        "armed_by": trigger.get("armed_by").cloned().unwrap_or(Value::Null),
        "at": super::iso_now(),
    });
    // WHO THE TRIGGERED RUN ACTS AS (R-240, failover teardown identity): the principal who armed this
    // plan, under the owner they named, re-resolved against their CURRENT membership — never the
    // daemon, never anonymous. A plan armed before arming recorded its principal, or whose armer can
    // no longer act for that owner, does not trigger: the refusal is named on the plan, and the plan
    // leaves `armed` so it cannot refuse in a loop (re-arming is the operator's explicit act).
    let actor = match FailoverStarter::from_record(Some(&trigger), "armed_by_principal_ref") {
        None => Err((
            "failover_plan_armed_without_principal",
            "this plan was armed before arming recorded who armed it, so a triggered run would have no one to act as — re-arm the plan".to_string(),
        )),
        Some(armer) => super::substrate_store::resolve_workload_broker_identity(
            &data_dir,
            &armer.principal_ref,
            &armer.owner_ref,
            &plan_ref,
        )
        .map(|identity| FailoverActor {
            identity,
            // one trigger per arming: the run's key is the arming's, so a replayed trigger resumes it
            create: Some((
                armer.owner_ref.clone(),
                format!("{}.auto-trigger.{}", text(plan, "plan_id"), since),
            )),
            via: "auto_trigger",
        })
        .map_err(|refusal| {
            (
                refusal.code(),
                format!(
                    "the principal who armed this plan cannot act for {} now: {}",
                    armer.owner_ref,
                    refusal.message()
                ),
            )
        }),
    };
    let actor = match actor {
        Ok(actor) => actor,
        Err((code, message)) => {
            let mut p = plan.clone();
            p["trigger_state"] = json!("trigger_refused");
            p["last_evaluated_at"] = json!(super::iso_now());
            p["last_trigger"] = triggered_by.clone();
            p["last_trigger"]["refusal"] = json!({ "code": code, "message": message });
            let committed = persist_plan(&data_dir, &p).is_ok();
            return json!({
                "plan_ref": plan_ref,
                "outcome": "trigger_refused",
                "code": code,
                "message": message,
                "condition": condition,
                "evidence_refs": evidence_refs,
                "plan_state_committed": committed,
                "note": "evidence qualified but nobody the daemon could name may act on it — no run was started",
            });
        }
    };
    let body = json!({
        "plan_ref": plan_ref,
        "failure_condition": condition,
        "max_hourly_usd": trigger.get("max_hourly_usd").cloned().unwrap_or(Value::Null),
        "teardown_policy": "always_teardown_required",
        "triggered_by": triggered_by,
    });
    let (_code, resp) = failover_run_core(st, body, &actor).await;
    let run_ref = resp
        .get("run")
        .map(|r| text(r, "run_ref"))
        .unwrap_or_default();
    let run_status = resp
        .get("run")
        .map(|r| text(r, "status"))
        .unwrap_or_default();
    let mut p = plan.clone();
    p["trigger_state"] = json!("triggered");
    p["last_evaluated_at"] = json!(super::iso_now());
    p["last_trigger"] = triggered_by.clone();
    if !run_ref.is_empty() {
        p["last_trigger"]["run_ref"] = json!(run_ref);
    }
    // W1.2 / MEF-GAP-008 — the trigger_state flip to `triggered` is cooldown truth: if it does not
    // commit, the plan still reads `armed` and could re-trigger. There is no HTTP response to gate
    // here (evaluate_plan returns a Value), so surface the failure honestly in the evaluation result.
    if persist_plan(&data_dir, &p).is_err() {
        return json!({
            "plan_ref": plan_ref,
            "outcome": "triggered_but_plan_state_uncommitted",
            "code": "failover_plan_persistence_failed",
            "condition": condition,
            "evidence_refs": evidence_refs,
            "run_ref": run_ref,
            "run_status": run_status,
            "warning": "the run was triggered but the plan's trigger_state flip to `triggered` did not commit — the plan still reads `armed`; the active-run guard blocks a duplicate while this run is live, but re-arm/cooldown truth is at risk",
        });
    }
    json!({
        "plan_ref": plan_ref,
        "outcome": "triggered",
        "condition": condition,
        "evidence_refs": evidence_refs,
        "run_ref": run_ref,
        "run_status": run_status,
        "note": "triggered run is parked at the wallet gate — automatic detection never becomes automatic authority",
    })
}

/// POST /v1/hypervisor/failover/evaluate — evaluate one plan or all armed
/// plans against current provider evidence. Also driven by the opt-in
/// background evaluator and schedulable via Automations.
pub(crate) async fn handle_failover_evaluate(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    Json(evaluate_all(&st, body.get("plan_ref").and_then(|v| v.as_str())).await)
}

pub(crate) async fn evaluate_all(st: &Arc<DaemonState>, only_plan: Option<&str>) -> Value {
    let plans: Vec<Value> = super::read_record_dir(&st.data_dir, FAILOVER_PLAN_KIND)
        .into_iter()
        .filter(|p| match only_plan {
            Some(pr) => text(p, "plan_ref") == pr || text(p, "plan_id") == pr,
            None => text(p, "trigger_state") == "armed",
        })
        .collect();
    let mut evaluations = Vec::new();
    for plan in &plans {
        evaluations.push(evaluate_plan(st, plan).await);
    }
    json!({
        "schema_version": "ioi.hypervisor.failover-evaluations.v1",
        "evaluated": plans.len(),
        "evaluations": evaluations,
        "at": super::iso_now(),
    })
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
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"reason": "failover_run_unknown"})),
        ),
    }
}

#[cfg(test)]
mod failover_teardown_identity_tests {
    //! R-240, failover teardown identity: a failover run's provider ops cross as the principal who
    //! started it, only that principal drives it, and a teardown that does not complete leaves the
    //! old exposure recorded open.
    use super::*;

    const OWNER: &str = "org://one";
    const OLD: &str = "pacc_old";
    const OLD_REF: &str = "provider-account://pacc_old";
    const ENV: &str = "env-old";
    const RUN_ID: &str = "for_teardown";

    /// A signed-in principal holding active membership in `tenants` (its token derives from its id).
    fn session(d: &str, id: &str, tenants: &[&str]) -> HeaderMap {
        super::super::persist_record(
            d,
            "principals",
            id,
            &json!({ "schema_version": "ioi.hypervisor.principal.v1", "principal_id": id,
                     "email": format!("{id}@example.test"), "name": id, "role": "member",
                     "status": "active", "source": "test",
                     "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z" }),
        )
        .unwrap();
        for tenant in tenants {
            member(d, &format!("user://{id}"), tenant, "active", 0);
        }
        let token = format!("token-{id}");
        super::super::persist_record(
            d,
            "sessions",
            &format!("session-{id}"),
            &json!({ "session_id": format!("session-{id}"), "token_hash": super::super::sha256_hex_str(&token),
                     "principal_id": id, "source": "test",
                     "created_at": "2026-01-01T00:00:00Z", "expires_at": "9999-12-31T23:59:59Z" }),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }

    fn member(d: &str, principal_ref: &str, tenant: &str, status: &str, revision: u64) {
        super::super::lifecycle_routes::apply_membership_transition(
            d,
            principal_ref,
            principal_ref,
            tenant,
            "organization",
            status,
            revision,
            &format!("test-{principal_ref}-{tenant}-{status}"),
            "test membership",
            "deployment_bootstrap",
        )
        .unwrap();
    }

    /// The old side: a verified simulator vast account, (optionally) the instance it holds for ENV,
    /// and the open spend exposure that instance accrues.
    fn seed_old_side(d: &str, with_instance: bool) {
        super::super::persist_record(
            d,
            "provider-accounts",
            OLD,
            &json!({ "account_id": OLD, "account_ref": OLD_REF, "kind": "vast", "status": "verified",
                     "display_name": "old side", "endpoint": { "mode": "simulator" } }),
        )
        .unwrap();
        if with_instance {
            seed_instance(d);
        }
        super::super::persist_record(
            d,
            "provider-spend-exposures",
            "pse_old",
            &json!({ "exposure_id": "pse_old", "exposure_ref": "provider-spend-exposure://pse_old",
                     "account_ref": OLD_REF, "provider": "vast", "environment_ref": ENV,
                     "status": "open", "teardown_state": "live_or_pending", "receipt_refs": [],
                     "opened_at": "2026-09-29T00:00:00Z" }),
        )
        .unwrap();
    }

    fn seed_instance(d: &str) {
        super::super::persist_record(
            d,
            "vast-instances",
            "vi_old",
            &json!({ "record_id": "vi_old", "account_id": OLD, "environment_ref": ENV,
                     "instance_id": "vast-sim-1", "status": "running", "execution_mode": "simulator" }),
        )
        .unwrap();
    }

    /// A run restored on its replacement, standing at the old side's teardown.
    fn seed_run_at_teardown(d: &str, started_by: Option<Value>, condition: &str) -> String {
        let run_ref = format!("failover-run://{RUN_ID}");
        let ok = |phase: &str| json!({ "phase": phase, "status": "ok", "detail": {}, "at": "2026-09-29T00:00:00Z" });
        let mut run = json!({
            "schema_version": "ioi.hypervisor.failover-run.v1",
            "run_id": RUN_ID, "run_ref": run_ref, "plan_ref": "failover-plan://fpl_one",
            "environment_ref": ENV, "replacement_environment_ref": format!("{ENV}-fo-teardown"),
            "failure_condition": condition,
            "old_provider": { "account_ref": OLD_REF, "provider_kind": "vast", "native_ids": "evidence_only — never restore truth" },
            "replacement": { "provider_account_ref": "provider-account://pacc_new", "provider_kind": "akash", "native_ids": "evidence_only — never restore truth" },
            "events": [ok("detected"), ok("material_secured"), ok("replacement_selected"), ok("replacement_created"), ok("started"), ok("restored")],
            "receipt_refs": [], "status": "awaiting_authority_restore", "started_at": "2026-09-29T00:00:00Z",
        });
        if let Some(binding) = started_by {
            run["started_by"] = binding;
        }
        super::super::persist_record(d, FAILOVER_RUN_KIND, RUN_ID, &run).unwrap();
        run_ref
    }

    fn alice_started() -> Option<Value> {
        Some(
            json!({ "principal_ref": "user://alice", "owner_ref": OWNER, "via": "request", "idempotency_key": "k" }),
        )
    }

    async fn post_run(
        st: &Arc<DaemonState>,
        headers: HeaderMap,
        body: Value,
    ) -> (StatusCode, Value) {
        let (code, Json(reply)) = handle_failover_run(State(st.clone()), headers, Json(body)).await;
        (code, reply)
    }

    fn run_record(d: &str) -> Value {
        super::super::read_record_dir(d, FAILOVER_RUN_KIND)
            .into_iter()
            .find(|r| text(r, "run_id") == RUN_ID)
            .expect("the run record")
    }

    fn deletes(d: &str) -> usize {
        super::super::read_record_dir(d, "provider-operations")
            .iter()
            .filter(|o| text(o, "op") == "delete" && text(o, "environment_ref") == ENV)
            .count()
    }

    fn exposure_status(d: &str) -> String {
        super::super::read_record_dir(d, "provider-spend-exposures")
            .into_iter()
            .find(|e| text(e, "exposure_id") == "pse_old")
            .map(|e| text(&e, "status"))
            .unwrap_or_default()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failover_teardown_crosses_as_the_starter_and_closes_the_old_exposure() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let st = crate::test_daemon_state(d);
        let alice = session(d, "alice", &[OWNER]);
        seed_old_side(d, true);
        let run_ref = seed_run_at_teardown(d, alice_started(), "host_unreachable");

        let (code, reply) = post_run(&st, alice, json!({ "run_ref": run_ref })).await;
        assert_eq!(code, StatusCode::OK, "{reply}");
        let run = &reply["run"];
        assert_eq!(run["status"], json!("restored"), "{run}");
        assert_eq!(run["old_teardown"]["state"], json!("closed"), "{run}");
        assert_eq!(
            run["old_teardown"]["acting"],
            json!({ "principal_ref": "user://alice", "owner_ref": OWNER, "idempotency_key": "for_teardown.teardown" }),
            "the teardown crossed as the run's starter, under its owner, with the op's own key"
        );
        assert!(run["next_required"].is_null(), "{run}");
        assert_eq!(
            deletes(d),
            1,
            "the old side's delete ran through the provider route"
        );
        assert_eq!(exposure_status(d), "closed", "the old exposure closed");
        assert_eq!(
            run_record(d)["status"],
            json!("restored"),
            "and the record says so"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_anonymous_failover_op_is_impossible() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let st = crate::test_daemon_state(d);
        let alice = session(d, "alice", &[OWNER]);
        let bob = session(d, "bob", &[OWNER]);
        seed_old_side(d, true);
        let run_ref = seed_run_at_teardown(d, alice_started(), "host_unreachable");
        let before = run_record(d);

        // no caller at all
        let (code, reply) = post_run(&st, HeaderMap::new(), json!({ "run_ref": run_ref })).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED, "{reply}");
        // a caller who did not start the run, in the same organization
        let (code, reply) = post_run(&st, bob, json!({ "run_ref": run_ref })).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "{reply}");
        assert_eq!(
            reply["code"],
            json!("failover_run_starter_mismatch"),
            "{reply}"
        );
        assert_eq!(run_record(d), before, "a refused post changes nothing");
        assert_eq!(deletes(d), 0, "and crosses nothing");
        assert_eq!(exposure_status(d), "open");

        // a run that never recorded its starter is never resumed as anyone
        seed_run_at_teardown(d, None, "host_unreachable");
        let (code, reply) = post_run(&st, alice.clone(), json!({ "run_ref": run_ref })).await;
        assert_eq!(code, StatusCode::CONFLICT, "{reply}");
        assert_eq!(
            reply["code"],
            json!("failover_run_starter_unrecorded"),
            "{reply}"
        );
        assert_eq!(deletes(d), 0);

        // a create is an owned write: an authenticated caller who names no owner creates nothing
        let (code, reply) = post_run(
            &st,
            alice,
            json!({ "plan_ref": "failover-plan://fpl_one", "failure_condition": "host_unreachable" }),
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{reply}");
        assert_eq!(
            reply["code"],
            json!("mutation_owner_ref_required"),
            "{reply}"
        );
        assert_eq!(super::super::read_record_dir(d, FAILOVER_RUN_KIND).len(), 1);

        // a plan armed before arming recorded its principal triggers nothing, by name
        super::super::persist_record(
            d,
            "provider-accounts",
            "pacc_revoked",
            &json!({ "account_id": "pacc_revoked", "account_ref": "provider-account://pacc_revoked",
                     "kind": "vast", "status": "revoked" }),
        )
        .unwrap();
        super::super::persist_record(
            d,
            FAILOVER_PLAN_KIND,
            "fpl_legacy",
            &json!({ "plan_id": "fpl_legacy", "plan_ref": "failover-plan://fpl_legacy",
                     "environment_ref": "env-legacy", "source_account_ref": "provider-account://pacc_revoked",
                     "readiness": "ready_daemon_custody", "trigger_state": "armed",
                     "auto_trigger": { "enabled": true, "conditions": ["credential_revoked"],
                                       "armed_by": "operator", "armed_at": "2026-01-01T00:00:00Z" } }),
        )
        .unwrap();
        let evaluated = evaluate_all(&st, Some("failover-plan://fpl_legacy")).await;
        let outcome = &evaluated["evaluations"][0];
        assert_eq!(outcome["outcome"], json!("trigger_refused"), "{evaluated}");
        assert_eq!(
            outcome["code"],
            json!("failover_plan_armed_without_principal")
        );
        assert_eq!(
            super::super::read_record_dir(d, FAILOVER_RUN_KIND).len(),
            1,
            "no run was started for nobody"
        );
        assert_eq!(
            load_plan(d, "fpl_legacy").unwrap()["trigger_state"],
            json!("trigger_refused")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_teardown_leaves_the_old_exposure_recorded_open() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let st = crate::test_daemon_state(d);
        let alice = session(d, "alice", &[OWNER]);
        // the provider route cannot find the old instance: the delete answers ok:false
        seed_old_side(d, false);
        let run_ref = seed_run_at_teardown(d, alice_started(), "host_unreachable");

        let (code, reply) = post_run(&st, alice.clone(), json!({ "run_ref": run_ref })).await;
        assert_eq!(code, StatusCode::OK, "{reply}");
        let run = &reply["run"];
        assert_eq!(run["status"], json!("restored_old_exposure_open"), "{run}");
        assert_eq!(run["old_teardown"]["state"], json!("open"), "{run}");
        assert_eq!(
            run["old_teardown"]["reason"],
            json!("teardown_failed"),
            "{run}"
        );
        assert_eq!(
            run["old_teardown"]["old_exposure_ref"],
            json!("provider-spend-exposure://pse_old")
        );
        assert_eq!(run["old_teardown"]["old_exposure_status"], json!("open"));
        assert_eq!(run["next_required"]["gate"], json!("teardown"), "{run}");
        assert!(
            !phase_done(run, "old_closed"),
            "the phase stays undone, so a later post retries it"
        );
        assert_eq!(exposure_status(d), "open");
        assert_eq!(run_record(d)["status"], json!("restored_old_exposure_open"));

        // the starter retries once the old side can be torn down: it closes, as the starter
        seed_instance(d);
        let (code, reply) = post_run(&st, alice.clone(), json!({ "run_ref": run_ref })).await;
        assert_eq!(code, StatusCode::OK, "{reply}");
        assert_eq!(reply["run"]["status"], json!("restored"), "{reply}");
        assert_eq!(reply["run"]["old_teardown"]["attempts"], json!(2));
        assert_eq!(exposure_status(d), "closed");

        // a refused teardown (the provider route cannot resolve the old account) is open too
        let dir2 = tempfile::tempdir().unwrap();
        let d2 = dir2.path().to_str().unwrap();
        let st2 = crate::test_daemon_state(d2);
        let alice2 = session(d2, "alice", &[OWNER]);
        let run_ref2 = seed_run_at_teardown(d2, alice_started(), "host_unreachable");
        let (code, reply) = post_run(&st2, alice2.clone(), json!({ "run_ref": run_ref2 })).await;
        assert_eq!(code, StatusCode::OK, "{reply}");
        assert_eq!(
            reply["run"]["status"],
            json!("restored_old_exposure_open"),
            "{reply}"
        );
        assert_eq!(
            reply["run"]["old_teardown"]["reason"],
            json!("teardown_refused")
        );
        assert_eq!(reply["run"]["old_teardown"]["http_status"], json!(428));

        // an impossible teardown (revoked credential) is open too, and crosses nothing
        let dir3 = tempfile::tempdir().unwrap();
        let d3 = dir3.path().to_str().unwrap();
        let st3 = crate::test_daemon_state(d3);
        let alice3 = session(d3, "alice", &[OWNER]);
        seed_old_side(d3, true);
        let run_ref3 = seed_run_at_teardown(d3, alice_started(), "credential_revoked");
        let (code, reply) = post_run(&st3, alice3, json!({ "run_ref": run_ref3 })).await;
        assert_eq!(code, StatusCode::OK, "{reply}");
        assert_eq!(
            reply["run"]["status"],
            json!("restored_old_exposure_open"),
            "{reply}"
        );
        assert_eq!(
            reply["run"]["old_teardown"]["reason"],
            json!("teardown_impossible_credential_revoked")
        );
        assert_eq!(deletes(d3), 0);
        assert_eq!(exposure_status(d3), "open");
    }

    #[test]
    fn a_teardown_is_confirmed_by_the_native_destroy_or_by_verified_cleanup_where_there_is_none() {
        let ok = |evidence: Value| json!({ "ok": true, "evidence": evidence });
        assert!(teardown_confirmed(&ok(
            json!({ "native_teardown": { "destroyed": true } })
        )));
        assert!(
            !teardown_confirmed(&ok(
                json!({ "native_teardown": { "destroyed": false }, "cleanup_verified": true })
            )),
            "a native destroy that did not confirm is not overridden by a workspace cleanup"
        );
        assert!(
            teardown_confirmed(&ok(json!({ "cleanup_verified": true }))),
            "an ssh host's teardown"
        );
        assert!(!teardown_confirmed(&ok(
            json!({ "cleanup_verified": false })
        )));
        assert!(!teardown_confirmed(&ok(json!({}))), "nothing confirmed it");
    }

    /// A triggered run acts as the principal who armed the plan, re-resolved at trigger time; a
    /// revoked armer triggers nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_auto_triggered_run_acts_as_the_principal_who_armed_the_plan() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let st = crate::test_daemon_state(d);
        let alice = session(d, "alice", &[OWNER]);
        // restore truth the trigger can secure: admitted material whose bytes hash to its root
        let custody = dir.path().join("material.bin");
        std::fs::write(&custody, b"custody-bytes").unwrap();
        super::super::persist_record(
            d,
            "provider-materials",
            "pm_one",
            &json!({ "material_ref": "provider-material://pm_one", "environment_ref": ENV,
                     "state_root": sha256_hex(b"custody-bytes"), "path": custody.to_str().unwrap() }),
        )
        .unwrap();
        super::super::persist_record(
            d,
            "provider-accounts",
            OLD,
            &json!({ "account_id": OLD, "account_ref": OLD_REF, "kind": "vast", "status": "revoked" }),
        )
        .unwrap();
        super::super::persist_record(
            d,
            FAILOVER_PLAN_KIND,
            "fpl_one",
            &json!({ "plan_id": "fpl_one", "plan_ref": "failover-plan://fpl_one", "environment_ref": ENV,
                     "source_account_ref": OLD_REF, "restore_material_ref": "provider-material://pm_one",
                     "state_root": sha256_hex(b"custody-bytes"), "archive_refs": [],
                     "readiness": "ready_daemon_custody" }),
        )
        .unwrap();

        // arming is an owned write: nobody arms anonymously
        let arm = |headers: HeaderMap, body: Value| {
            let st = st.clone();
            async move {
                let (code, Json(reply)) = handle_failover_plan_arm(
                    State(st),
                    headers,
                    Path("fpl_one".to_string()),
                    Json(body),
                )
                .await;
                (code, reply)
            }
        };
        let (code, _) = arm(
            HeaderMap::new(),
            json!({ "conditions": ["credential_revoked"] }),
        )
        .await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        let (code, reply) = arm(
            alice,
            json!({ "conditions": ["credential_revoked"], "owner_ref": OWNER, "idempotency_key": "arm-1" }),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{reply}");
        assert_eq!(
            reply["plan"]["auto_trigger"]["armed_by_principal_ref"],
            json!("user://alice")
        );

        let evaluated = evaluate_all(&st, Some("failover-plan://fpl_one")).await;
        assert_eq!(
            evaluated["evaluations"][0]["outcome"],
            json!("triggered"),
            "{evaluated}"
        );
        let runs = super::super::read_record_dir(d, FAILOVER_RUN_KIND);
        assert_eq!(runs.len(), 1, "{runs:?}");
        assert_eq!(
            runs[0]["started_by"]["principal_ref"],
            json!("user://alice"),
            "the triggered run acts as the principal who armed the plan"
        );
        assert_eq!(runs[0]["started_by"]["owner_ref"], json!(OWNER));
        assert_eq!(runs[0]["started_by"]["via"], json!("auto_trigger"));

        // re-armed, then the armer loses the owner: the next trigger is refused by name
        let bob = session(d, "bob", &[OWNER]);
        let (code, reply) = arm(
            bob,
            json!({ "conditions": ["credential_revoked"], "owner_ref": OWNER, "idempotency_key": "arm-2" }),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{reply}");
        member(d, "user://bob", OWNER, "revoked", 1);
        // (the earlier run is refused — no candidates — so it is not an active run)
        let evaluated = evaluate_all(&st, Some("failover-plan://fpl_one")).await;
        let outcome = &evaluated["evaluations"][0];
        assert_eq!(outcome["outcome"], json!("trigger_refused"), "{evaluated}");
        assert_eq!(
            outcome["code"],
            json!("request_tenant_authority_required"),
            "{evaluated}"
        );
        assert_eq!(super::super::read_record_dir(d, FAILOVER_RUN_KIND).len(), 1);
    }
}
