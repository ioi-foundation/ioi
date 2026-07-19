//! Lambda-class GPU VM CANDIDATE SOURCE — the third GPU class and the missing member of the
//! first production external-compute trio (canon priority ladder): the BORING, high-trust
//! ordinary Linux GPU VM lane. `direct_provider` source; quotes are per-INSTANCE-TYPE rate
//! cards with per-region capacity — VM semantics preserved (instance type, region, persistent
//! local disk, ssh user ubuntu), never flattened into a generic cloud.
//!
//! Same hard boundaries as the Vast/RunPod sources: sealed bearer in-daemon only; no fake
//! quotes on API failure (degraded WITH evidence); fixture/simulator unmistakably labelled;
//! live claims only after a real fetch; unpriced instance types SKIPPED, never estimated.
//! Prices arrive as cents/hour and are unit-converted verbatim (basis says so). Custody:
//! `cloud_vm_NOT_private`; provider-native snapshots/disks are evidence only — daemon custody
//! state roots remain restore truth.
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::lifecycle_routes::open_scm_token;
use super::{iso_now, persist_record, read_record_dir, DaemonState};

const HEALTH_KIND: &str = "lambda-source-health";
const DEFAULT_ENDPOINT: &str = "https://cloud.lambda.ai/api/v1";

fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn engaged_account(data_dir: &str) -> Option<(Value, Option<String>)> {
    let account = read_record_dir(data_dir, "provider-accounts")
        .into_iter()
        .find(|a| a["kind"] == "lambda_cloud" && a["status"] == "verified")?;
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

pub(crate) fn source_state(data_dir: &str) -> Value {
    let accounts = read_record_dir(data_dir, "provider-accounts");
    let lambda_accounts: Vec<&Value> = accounts
        .iter()
        .filter(|a| a["kind"] == "lambda_cloud")
        .collect();
    if lambda_accounts.is_empty() {
        return json!({ "source": "lambda_cloud", "state": "candidate_source_unavailable",
            "reason": "lambda_cloud_credential_absent — no lambda_cloud ProviderAccount exists; create one, bind a bearer api_key, and preflight it",
            "evidence": { "lambda_cloud_accounts": 0, "basis": "provider-accounts records" } });
    }
    let Some((engaged, _)) = engaged_account(data_dir) else {
        return json!({ "source": "lambda_cloud", "state": "candidate_source_unavailable",
            "reason": "lambda_cloud_credential_absent — a lambda_cloud ProviderAccount exists but no verified account with a resolvable sealed bearer credential",
            "evidence": { "lambda_cloud_accounts": lambda_accounts.len(),
                          "verified": lambda_accounts.iter().filter(|a| a["status"] == "verified").count(),
                          "basis": "provider-accounts + sealed-credential resolution (daemon-side only)" } });
    };
    match load_health(data_dir).filter(|h| h["account_ref"] == engaged["account_ref"]) {
        Some(h) => {
            let state = text(&h, "state").to_string();
            json!({ "source": "lambda_cloud", "state": state,
                "mode": h.get("mode").cloned().unwrap_or(Value::Null),
                "evidence": h.get("evidence").cloned().unwrap_or(Value::Null),
                "at": h.get("at").cloned().unwrap_or(Value::Null) })
        }
        None => json!({ "source": "lambda_cloud", "state": "credential_verified_unprobed",
            "reason": "credential verified — no instance-type fetch has run yet (refresh candidates to probe)",
            "evidence": { "basis": "sealed bearer resolvable; no fetch attempted" } }),
    }
}

fn health_record(outcome: &Value) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.lambda-source-health.v1",
        "health_id": "current",
        "state": outcome["state"],
        "mode": outcome["mode"],
        "account_ref": outcome["account_ref"],
        "evidence": outcome["evidence"],
        "at": outcome["at"],
    })
}

/// Fetch the instance-type catalog. fixture|simulator read a local file (unmistakably
/// labelled); live performs the real fetch — failure degrades WITH evidence, never fake supply.
pub(crate) async fn fetch_offers(st: &Arc<DaemonState>) -> Value {
    let Some((account, bearer)) = engaged_account(&st.data_dir) else {
        return json!({ "engaged": false });
    };
    let account_ref = text(&account, "account_ref").to_string();
    let ep = account
        .get("endpoint")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let fetched_at = iso_now();
    if text(&ep, "mode") == "fixture" || text(&ep, "mode") == "simulator" {
        let simulator = text(&ep, "mode") == "simulator";
        let (mode_label, state_label): (&str, &str) = if simulator {
            ("simulator_evidence", "simulator_quote_source")
        } else {
            ("fixture_evidence", "fixture_quote_source")
        };
        let path = text(&ep, "fixture_file");
        let outcome = match std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|raw| serde_json::from_str::<Value>(&raw).map_err(|e| e.to_string()))
        {
            Ok(doc) => {
                let offers = doc
                    .get("instance_types")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                json!({ "engaged": true, "mode": mode_label, "account_ref": account_ref,
                    "state": state_label, "offers": offers,
                    "evidence": { "mode": mode_label, "fixture_file": path,
                                  "instance_types_seen": doc.get("instance_types").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
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
    // ── live: the real instance-types catalog (Lambda-style GET /instance-types). ──
    let base = {
        let configured = text(&ep, "endpoint");
        if configured.is_empty() {
            DEFAULT_ENDPOINT.to_string()
        } else {
            configured.trim_end_matches('/').to_string()
        }
    };
    let resp = reqwest::Client::new()
        .get(format!("{base}/instance-types"))
        .bearer_auth(bearer.unwrap_or_default())
        .timeout(Duration::from_secs(12))
        .send()
        .await;
    let outcome = match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            match r.json::<Value>().await {
                Ok(doc) if (200..300).contains(&status) => {
                    // Lambda returns { data: { "<type>": { instance_type, regions_with_capacity_available } } }.
                    let offers: Vec<Value> = doc
                        .get("data")
                        .and_then(Value::as_object)
                        .map(|m| {
                            m.values()
                                .map(|entry| {
                                    let it = entry
                                        .get("instance_type")
                                        .cloned()
                                        .unwrap_or_else(|| entry.clone());
                                    let regions = entry
                                        .get("regions_with_capacity_available")
                                        .cloned()
                                        .unwrap_or(json!([]));
                                    json!({ "instance_type": it, "regions": regions })
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                        "state": "live_quote_source", "offers": offers,
                        "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status, "instance_types_seen": offers.len() },
                        "at": fetched_at })
                }
                Ok(doc) => {
                    json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                    "state": "degraded_unreachable", "offers": [],
                    "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status,
                                  "error": format!("lambda API rejected the request (body keys: {:?})", doc.as_object().map(|o| o.keys().take(4).cloned().collect::<Vec<_>>()).unwrap_or_default()),
                                  "note": "no fake quotes on failure" },
                    "at": fetched_at })
                }
                Err(e) => {
                    json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                    "state": "degraded_unreachable", "offers": [],
                    "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status, "error": format!("non-JSON response: {e}") },
                    "at": fetched_at })
                }
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

/// Normalize instance-type quotes into CloudResourceCandidates with VM semantics. Fixture files
/// use { instance_types: [{ name, description, price_cents_per_hour, specs {vcpus, memory_gib,
/// storage_gib, gpus}, gpu_description?, vram_gb?, regions: [..] }] } — the live fetch maps the
/// provider payload into the same shape. Unpriced types are SKIPPED, never estimated.
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
    let offers = outcome
        .get("offers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    offers.iter().take(24).enumerate().filter_map(|(i, entry)| {
        // Live entries are { instance_type, regions }; fixture entries are flat.
        let it = entry.get("instance_type").cloned().unwrap_or_else(|| entry.clone());
        let regions: Vec<String> = entry.get("regions").and_then(Value::as_array)
            .map(|a| a.iter().map(|r| r.get("name").and_then(Value::as_str).unwrap_or(r.as_str().unwrap_or("")).to_string()).filter(|x| !x.is_empty()).collect())
            .unwrap_or_default();
        let cents = it.get("price_cents_per_hour").and_then(Value::as_f64).filter(|p| *p > 0.0)?;
        let dph = cents / 100.0;
        let name = text(&it, "name");
        if name.is_empty() { return None; }
        let id = format!("crc_{:x}_l{i}", nanos());
        let specs = it.get("specs").cloned().unwrap_or(json!({}));
        let gpus = specs.get("gpus").and_then(Value::as_u64).unwrap_or(1);
        let gpu_model = {
            let described = text(&it, "gpu_description");
            if described.is_empty() { text(&it, "description") } else { described }
        };
        let vram_gb = it.get("vram_gb").and_then(Value::as_f64);
        let disk_gb = specs.get("storage_gib").cloned().unwrap_or(Value::Null);
        let mut risk: Vec<&str> = vec![];
        if regions.is_empty() { risk.push("no_region_with_capacity"); }
        if fixture { risk.push("fixture_evidence_not_live_supply"); }
        if simulator { risk.push("simulator_evidence_not_live_supply"); }
        let coverage = if fixture { "fixture_quote" } else if simulator { "simulator_quote" } else { "live_quote" };
        let eligibility: Vec<&str> = if live && !regions.is_empty() {
            vec!["placement_eligible", "quote_live", "guarded_lifecycle_available", "ssh_bootstrap_known"]
        } else if live {
            vec!["advisory_only", "quote_live", "no_region_with_capacity"]
        } else if simulator {
            vec!["advisory_only", "simulated_control_plane", "lifecycle_harness_only"]
        } else {
            vec!["advisory_only", "quote_preflight_only", "lifecycle_adapter_absent"]
        };
        let lifecycle = if live { "guarded_lifecycle (quote-gated, receipted)" }
            else if simulator { "guarded_lifecycle_simulator (control plane simulated; ssh/custody lane real)" }
            else { "quote_preflight_only" };
        let placement_eligible: Value = if live && !regions.is_empty() { json!(true) } else { json!("advisory_only") };
        let blocked_reason: Value = if live && !regions.is_empty() { Value::Null }
            else if live { json!("no_region_with_capacity") }
            else if simulator { json!("simulated_control_plane_not_live_supply") }
            else { json!("provider_kind_lifecycle_not_implemented") };
        let claims = vec![
            json!(format!("lambda-class GPU VM {name}: {gpus}x {gpu_model} at ${dph}/hr — verbatim rate card (price_cents_per_hour/100), nothing invented")),
            json!("ordinary Linux VM + ssh + instance-lifetime persistent disk — the boring high-trust GPU VM lane"),
        ];
        let quote = json!({
            "schema_version": "ioi.hypervisor.provider-quote.v1",
            "quote_ref": format!("provider-quote://{id}"),
            "usd_per_hour": dph,
            "currency": "USD",
            "basis": "lambda instance-type price_cents_per_hour / 100 (verbatim, unit-converted)",
            "offer_id": name,
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
            "privacy": "cloud_vm_NOT_private",
            "detail": "GPU VM cloud — Standard custody unless proven otherwise; provider-native snapshots/disks are EVIDENCE only, daemon custody state roots remain restore truth",
            "rule": "storage availability does not equal restore validity — daemon-admitted sha256 state roots are restore truth",
        });
        let failover_plan = json!({
            "schema_version": "ioi.hypervisor.failover-plan.v1",
            "failover_plan_ref": format!("failover-plan://{id}"),
            "detail": "re-launch the instance type (any region with capacity) + restore from daemon-admitted material; fallback venue run_local",
            "authority_note": "failover requires the same wallet grants as any placement — a plan is not authority",
        });
        let evidence = json!({
            "schema_version": "ioi.hypervisor.candidate-evidence.v1",
            "evidence_ref": format!("candidate-evidence://{id}"),
            "source": "direct_provider",
            "adapter_ref": "adapter:lambda-quote",
            "observed_at": observed_at,
            "expires_at": expires_at,
            "coverage_state": coverage,
            "claims": claims,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "evidence_refs": [json!(account_ref), json!(format!("lambda-instance-type:{name}"))],
            "evidence_mode": mode,
        });
        Some(json!({
            "schema_version": "ioi.hypervisor.cloud-resource-candidate.v1",
            "candidate_id": id,
            "candidate_ref": format!("cloud-resource-candidate://{id}"),
            "intent_ref": intent_ref,
            "batch": batch,
            "source": "direct_provider",
            "adapter_ref": "adapter:lambda-quote",
            "provider_kind": "lambda_cloud",
            "provider_account_ref": account_ref,
            "display_name": format!("Lambda VM · {name}"),
            "resource_classes": ["compute.vm", "compute.gpu_runtime"],
            "runtime_class": "compute.vm",
            "instance_type": name,
            "gpu": { "model": gpu_model, "count": gpus, "vram_gb": vram_gb },
            "regions": regions,
            "region": Value::Null,
            "region_note": "region is chosen at create from regions_with_capacity — the wallet challenge binds it",
            "quote": quote,
            "quote_ref": format!("provider-quote://{id}"),
            "quote_state": "quoted_from_rate_card",
            "spend_estimate": spend_estimate,
            "custody_plan": custody_plan,
            "failover_plan": failover_plan,
            "reliability": { "basis": "rate-card quote — per-instance reliability evidence lands with the running VM" },
            "network": { "ports_posture": "public ip + ssh (port 22, user ubuntu); ingress beyond ssh requires the lifecycle + authority" },
            "storage": { "disk_gb": disk_gb, "posture": "instance-lifetime persistent local NVMe (VM semantics — survives reboots, dies with the VM)" },
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
