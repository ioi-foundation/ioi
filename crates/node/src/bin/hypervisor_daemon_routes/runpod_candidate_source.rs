//! RunPod CANDIDATE SOURCE — the second external GPU supply adapter, proving the provider
//! ladder is not Vast-specific. RunPod is a GPU RUNTIME CLOUD (`direct_provider` source, not a
//! DePIN marketplace): quotes are per-GPU-type rates with secure-cloud (on-demand) and
//! community-cloud (interruptible) pricing — semantics preserved, never flattened into a fake
//! generic cloud.
//!
//! Same hard boundaries as the Vast source: sealed bearer resolves only in-daemon; no fake
//! quotes on API failure (degraded WITH evidence); fixture/simulator unmistakably labelled and
//! never claimed live; unpriced GPU types are SKIPPED, never estimated; custody is Standard —
//! `cloud_gpu_runtime_NOT_private` without custody proof.
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::lifecycle_routes::open_scm_token;
use super::{iso_now, persist_record, read_record_dir, DaemonState};

const HEALTH_KIND: &str = "runpod-source-health";
const DEFAULT_ENDPOINT: &str = "https://rest.runpod.io/v1";

fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

fn engaged_account(data_dir: &str) -> Option<(Value, Option<String>)> {
    let account = read_record_dir(data_dir, "provider-accounts")
        .into_iter()
        .find(|a| a["kind"] == "runpod" && a["status"] == "verified")?;
    let cred = read_record_dir(data_dir, "provider-credentials")
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(text(&account, "account_id")))?;
    let bearer = cred["sealed_token"].as_str().and_then(open_scm_token);
    bearer.as_ref()?;
    Some((account, bearer))
}

fn persist_health(data_dir: &str, health: &Value) {
    let _ = persist_record(data_dir, HEALTH_KIND, "current", health);
}
fn load_health(data_dir: &str) -> Option<Value> {
    read_record_dir(data_dir, HEALTH_KIND)
        .into_iter()
        .find(|r| r["health_id"].as_str() == Some("current"))
}

/// Source posture for GET /candidate-sources — static credential posture + last fetch health,
/// scoped to the currently engaged account.
pub(crate) fn source_state(data_dir: &str) -> Value {
    let accounts = read_record_dir(data_dir, "provider-accounts");
    let runpod_accounts: Vec<&Value> = accounts.iter().filter(|a| a["kind"] == "runpod").collect();
    if runpod_accounts.is_empty() {
        return json!({ "source": "runpod", "state": "candidate_source_unavailable",
            "reason": "runpod_credential_absent — no runpod ProviderAccount exists; create one, bind a bearer api_key, and preflight it",
            "evidence": { "runpod_accounts": 0, "basis": "provider-accounts records" } });
    }
    let Some((engaged, _)) = engaged_account(data_dir) else {
        return json!({ "source": "runpod", "state": "candidate_source_unavailable",
            "reason": "runpod_credential_absent — a runpod ProviderAccount exists but no verified account with a resolvable sealed bearer credential",
            "evidence": { "runpod_accounts": runpod_accounts.len(),
                          "verified": runpod_accounts.iter().filter(|a| a["status"] == "verified").count(),
                          "basis": "provider-accounts + sealed-credential resolution (daemon-side only)" } });
    };
    match load_health(data_dir).filter(|h| h["account_ref"] == engaged["account_ref"]) {
        Some(h) => {
            let state = text(&h, "state").to_string();
            json!({ "source": "runpod", "state": state,
                "mode": h.get("mode").cloned().unwrap_or(Value::Null),
                "evidence": h.get("evidence").cloned().unwrap_or(Value::Null),
                "at": h.get("at").cloned().unwrap_or(Value::Null) })
        }
        None => json!({ "source": "runpod", "state": "credential_verified_unprobed",
            "reason": "credential verified — no GPU-type fetch has run yet (refresh candidates to probe)",
            "evidence": { "basis": "sealed bearer resolvable; no fetch attempted" } }),
    }
}

fn health_record(outcome: &Value) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.runpod-source-health.v1",
        "health_id": "current",
        "state": outcome["state"],
        "mode": outcome["mode"],
        "account_ref": outcome["account_ref"],
        "evidence": outcome["evidence"],
        "at": outcome["at"],
    })
}

/// Fetch the GPU-type catalog. fixture|simulator read a local file (unmistakably labelled);
/// live performs the real REST fetch — failure is degraded WITH evidence, never fake supply.
pub(crate) async fn fetch_offers(st: &Arc<DaemonState>) -> Value {
    let Some((account, bearer)) = engaged_account(&st.data_dir) else {
        return json!({ "engaged": false });
    };
    let account_ref = text(&account, "account_ref").to_string();
    let ep = account.get("endpoint").cloned().unwrap_or_else(|| json!({}));
    let fetched_at = iso_now();
    if text(&ep, "mode") == "fixture" || text(&ep, "mode") == "simulator" {
        let simulator = text(&ep, "mode") == "simulator";
        let (mode_label, state_label): (&str, &str) = if simulator {
            ("simulator_evidence", "simulator_quote_source")
        } else {
            ("fixture_evidence", "fixture_quote_source")
        };
        let path = text(&ep, "fixture_file");
        let outcome = match std::fs::read_to_string(path).map_err(|e| e.to_string())
            .and_then(|raw| serde_json::from_str::<Value>(&raw).map_err(|e| e.to_string()))
        {
            Ok(doc) => {
                let offers = doc.get("gpu_types").and_then(Value::as_array).cloned().unwrap_or_default();
                json!({ "engaged": true, "mode": mode_label, "account_ref": account_ref,
                    "state": state_label, "offers": offers,
                    "evidence": { "mode": mode_label, "fixture_file": path,
                                  "gpu_types_seen": doc.get("gpu_types").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
                                  "warning": if simulator { "local lifecycle SIMULATOR — control plane simulated, ssh/custody lane real; NOT live supply" } else { "deterministic local fixture — NOT live supply; validates normalization/expiry/invariants only" } },
                    "at": fetched_at })
            }
            Err(e) => json!({ "engaged": true, "mode": mode_label, "account_ref": account_ref,
                "state": "degraded_unreachable", "offers": [],
                "evidence": { "mode": mode_label, "fixture_file": path, "error": format!("fixture unreadable/unparseable: {e}") },
                "at": fetched_at }),
        };
        persist_health(&st.data_dir, &health_record(&outcome));
        return outcome;
    }
    // ── live: the real RunPod REST GPU-type catalog. Read-only; bearer in-daemon only. ──
    let base = {
        let configured = text(&ep, "endpoint");
        if configured.is_empty() { DEFAULT_ENDPOINT.to_string() } else { configured.trim_end_matches('/').to_string() }
    };
    let resp = reqwest::Client::new()
        .get(format!("{base}/gpus"))
        .bearer_auth(bearer.unwrap_or_default())
        .timeout(Duration::from_secs(12))
        .send()
        .await;
    let outcome = match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            match r.json::<Value>().await {
                Ok(doc) if (200..300).contains(&status) => {
                    let offers = doc.as_array().cloned()
                        .or_else(|| doc.get("gpus").and_then(Value::as_array).cloned())
                        .or_else(|| doc.get("data").and_then(Value::as_array).cloned())
                        .unwrap_or_default();
                    json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                        "state": "live_quote_source", "offers": offers,
                        "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status, "gpu_types_seen": offers.len() },
                        "at": fetched_at })
                }
                Ok(doc) => json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                    "state": "degraded_unreachable", "offers": [],
                    "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status,
                                  "error": format!("runpod API rejected the request (body keys: {:?})", doc.as_object().map(|o| o.keys().take(4).cloned().collect::<Vec<_>>()).unwrap_or_default()),
                                  "note": "no fake quotes on failure" },
                    "at": fetched_at }),
                Err(e) => json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                    "state": "degraded_unreachable", "offers": [],
                    "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status, "error": format!("non-JSON response: {e}") },
                    "at": fetched_at }),
            }
        }
        Err(e) => json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
            "state": "degraded_unreachable", "offers": [],
            "evidence": { "mode": "live_evidence", "endpoint": base, "error": format!("fetch failed: {e}"), "note": "no fake quotes on failure" },
            "at": fetched_at }),
    };
    persist_health(&st.data_dir, &health_record(&outcome));
    outcome
}

/// Normalize RunPod GPU-type quotes into CloudResourceCandidates. RunPod semantics preserved:
/// secure-cloud (on-demand) pricing preferred; community-cloud pricing carries an explicit
/// interruption risk label; GPU types WITHOUT any real price are SKIPPED, never estimated.
/// Region is chosen at pod create — quotes are rate cards, and say so.
pub(crate) fn normalize_offers(
    outcome: &Value,
    intent_ref: &str,
    batch: &str,
    observed_at: &str,
    expires_at: &str,
    expires_epoch: u64,
) -> Vec<Value> {
    let mode = text(outcome, "mode");
    let account_ref = text(outcome, "account_ref");
    let fixture = mode == "fixture_evidence";
    let simulator = mode == "simulator_evidence";
    let live = mode == "live_evidence";
    let offers = outcome.get("offers").and_then(Value::as_array).cloned().unwrap_or_default();
    offers.iter().take(24).enumerate().filter_map(|(i, gpu)| {
        let secure = gpu.get("securePrice").and_then(Value::as_f64).filter(|p| *p > 0.0);
        let community = gpu.get("communityPrice").and_then(Value::as_f64).filter(|p| *p > 0.0);
        // No invented quotes: a GPU type without any real price is skipped, not estimated.
        let (dph, cloud_type) = match (secure, community) {
            (Some(p), _) => (p, "secure_cloud_on_demand"),
            (None, Some(p)) => (p, "community_cloud_interruptible"),
            (None, None) => return None,
        };
        let id = format!("crc_{:x}_r{i}", nanos());
        let type_id = gpu.get("id").cloned().unwrap_or(Value::Null);
        let model = text(gpu, "displayName");
        let model = if model.is_empty() { text(gpu, "id") } else { model };
        let vram_gb = gpu.get("memoryInGb").and_then(Value::as_f64);
        let mut risk: Vec<&str> = vec![];
        if cloud_type == "community_cloud_interruptible" { risk.push("community_cloud_interruption"); }
        if fixture { risk.push("fixture_evidence_not_live_supply"); }
        if simulator { risk.push("simulator_evidence_not_live_supply"); }
        let coverage = if fixture { "fixture_quote" } else if simulator { "simulator_quote" } else { "live_quote" };
        let eligibility: Vec<&str> = if live {
            vec!["placement_eligible", "quote_live", "guarded_lifecycle_available", "ssh_bootstrap_known"]
        } else if simulator {
            vec!["advisory_only", "simulated_control_plane", "lifecycle_harness_only"]
        } else {
            vec!["advisory_only", "quote_preflight_only", "lifecycle_adapter_absent"]
        };
        let lifecycle = if live { "guarded_lifecycle (quote-gated, receipted)" }
            else if simulator { "guarded_lifecycle_simulator (control plane simulated; ssh/custody lane real)" }
            else { "quote_preflight_only" };
        let placement_eligible: Value = if live { json!(true) } else { json!("advisory_only") };
        let blocked_reason: Value = if live { Value::Null } else if simulator { json!("simulated_control_plane_not_live_supply") } else { json!("provider_kind_lifecycle_not_implemented") };
        let claims = vec![
            json!(format!("runpod gpu type {type_id}: {model} at ${dph}/hr ({cloud_type}) — verbatim rate-card data, nothing invented")),
            json!("quote + preflight only on this path — provisioning goes through the budget→quote→wallet ladder"),
        ];
        let quote = json!({
            "schema_version": "ioi.hypervisor.provider-quote.v1",
            "quote_ref": format!("provider-quote://{id}"),
            "usd_per_hour": dph,
            "currency": "USD",
            "basis": format!("runpod {cloud_type} rate (verbatim)"),
            "offer_id": type_id,
            "cloud_type": cloud_type,
            "observed_at": observed_at,
            "expires_at": expires_at,
            "evidence_mode": mode,
        });
        let spend_estimate = json!({
            "schema_version": "ioi.hypervisor.spend-estimate.v1",
            "spend_estimate_ref": format!("spend-estimate://{id}"),
            "state": "quoted",
            "usd_per_hour": dph,
            "basis": "real rate-card price only — no derived or padded numbers",
            "cost_owner": "customer",
            "routing_fee_eligibility": "eligible_future — only when optimized placement compares multiple real candidates; no fee exists today",
            "authority": "estimate, not spend authority",
        });
        let custody_plan = json!({
            "schema_version": "ioi.hypervisor.custody-plan.v1",
            "custody_plan_ref": format!("custody-plan://{id}"),
            "supported_postures": ["Standard"],
            "privacy": "cloud_gpu_runtime_NOT_private",
            "detail": "GPU runtime cloud — Standard custody unless proven otherwise; snapshot custody rides the daemon ssh lane",
            "rule": "storage availability does not equal restore validity — daemon-admitted sha256 state roots are restore truth",
        });
        let failover_plan = json!({
            "schema_version": "ioi.hypervisor.failover-plan.v1",
            "failover_plan_ref": format!("failover-plan://{id}"),
            "detail": "re-provision from the rate card + restore from daemon-admitted material; fallback venue run_local",
            "authority_note": "failover requires the same wallet grants as any placement — a plan is not authority",
        });
        let evidence = json!({
            "schema_version": "ioi.hypervisor.candidate-evidence.v1",
            "evidence_ref": format!("candidate-evidence://{id}"),
            "source": "direct_provider",
            "adapter_ref": "adapter:runpod-quote",
            "observed_at": observed_at,
            "expires_at": expires_at,
            "coverage_state": coverage,
            "claims": claims,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "evidence_refs": [json!(account_ref), json!(format!("runpod-gpu-type:{type_id}"))],
            "evidence_mode": mode,
        });
        Some(json!({
            "schema_version": "ioi.hypervisor.cloud-resource-candidate.v1",
            "candidate_id": id,
            "candidate_ref": format!("cloud-resource-candidate://{id}"),
            "intent_ref": intent_ref,
            "batch": batch,
            "source": "direct_provider",
            "adapter_ref": "adapter:runpod-quote",
            "provider_kind": "runpod",
            "provider_account_ref": account_ref,
            "display_name": format!("RunPod · {model}"),
            "resource_classes": ["compute.gpu_runtime", "compute.container"],
            "runtime_class": "compute.gpu_runtime",
            "gpu": { "model": model, "count": 1, "vram_gb": vram_gb },
            "region": Value::Null,
            "region_note": "region/datacenter is selected at pod create — GPU-type quotes are global rate cards",
            "cloud_type": cloud_type,
            "quote": quote,
            "quote_ref": format!("provider-quote://{id}"),
            "quote_state": "quoted_from_rate_card",
            "spend_estimate": spend_estimate,
            "custody_plan": custody_plan,
            "failover_plan": failover_plan,
            "reliability": { "basis": "rate-card quote — per-pod reliability evidence lands with the running pod" },
            "network": { "ports_posture": "proxy ssh / public ip when the pod exposes ports; ingress requires the lifecycle + authority" },
            "storage": { "posture": "container disk + optional network volumes (configured at pod create)" },
            "observed_at": observed_at,
            "expires_at": expires_at,
            "expires_epoch": expires_epoch,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "placement_eligible": placement_eligible,
            "lifecycle": lifecycle,
            "execution_blocked_reason": blocked_reason,
            "coverage_state": coverage,
            "evidence_mode": mode,
            "evidence": evidence,
            "authority": "none — a candidate cannot provision, release credentials, expose ingress, or claim custody/restore truth",
        }))
    }).collect()
}
