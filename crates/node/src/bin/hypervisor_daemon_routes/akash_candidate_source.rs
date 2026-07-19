//! Akash DePIN CANDIDATE SOURCE — the first DePIN compute/GPU lane (canon priority ladder #8).
//! This is NOT a generic VM adapter and NOT another SSH GPU clone: Akash semantics are
//! deployment intent → SDL manifest → provider BIDS → LEASE → lease-assigned endpoints. The
//! `depin_market` source serves BID advisories: per-provider offers with deployment class,
//! resource shape, persistent-storage posture, and lease rates.
//!
//! Same hard boundaries as the Vast/RunPod/Lambda sources: sealed bearer in-daemon only; no
//! fake bids on API failure (degraded WITH evidence); fixture/simulator unmistakably labelled;
//! live claims only after a real fetch. Prices: the native rate is uakt/block (evidence,
//! verbatim); a bid is priced ONLY when the source itself quotes a USD rate — bids without a
//! source-quoted USD rate are SKIPPED, never converted or estimated by the daemon. DePIN
//! honesty: provider variability and bid/lease revocation are named risks; deployment
//! persistent storage is availability posture, NEVER restore truth.
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::lifecycle_routes::open_scm_token;
use super::{iso_now, persist_record, read_record_dir, DaemonState};

const HEALTH_KIND: &str = "akash-source-health";

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
        .find(|a| a["kind"] == "akash" && a["status"] == "verified")?;
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
    let akash_accounts: Vec<&Value> = accounts.iter().filter(|a| a["kind"] == "akash").collect();
    if akash_accounts.is_empty() {
        return json!({ "source": "depin_market", "state": "candidate_source_unavailable",
            "reason": "akash_credential_absent — no akash ProviderAccount exists; create one, bind a bearer api_key, and preflight it",
            "evidence": { "akash_accounts": 0, "basis": "provider-accounts records" } });
    }
    let Some((engaged, _)) = engaged_account(data_dir) else {
        return json!({ "source": "depin_market", "state": "candidate_source_unavailable",
            "reason": "akash_credential_absent — an akash ProviderAccount exists but no verified account with a resolvable sealed bearer credential",
            "evidence": { "akash_accounts": akash_accounts.len(),
                          "verified": akash_accounts.iter().filter(|a| a["status"] == "verified").count(),
                          "basis": "provider-accounts + sealed-credential resolution (daemon-side only)" } });
    };
    match load_health(data_dir).filter(|h| h["account_ref"] == engaged["account_ref"]) {
        Some(h) => {
            let state = text(&h, "state").to_string();
            json!({ "source": "depin_market", "state": state,
                "mode": h.get("mode").cloned().unwrap_or(Value::Null),
                "evidence": h.get("evidence").cloned().unwrap_or(Value::Null),
                "at": h.get("at").cloned().unwrap_or(Value::Null) })
        }
        None => json!({ "source": "depin_market", "state": "credential_verified_unprobed",
            "reason": "credential verified — no bid fetch has run yet (refresh candidates to probe)",
            "evidence": { "basis": "sealed bearer resolvable; no fetch attempted" } }),
    }
}

fn health_record(outcome: &Value) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.akash-source-health.v1",
        "health_id": "current",
        "state": outcome["state"],
        "mode": outcome["mode"],
        "account_ref": outcome["account_ref"],
        "evidence": outcome["evidence"],
        "at": outcome["at"],
    })
}

/// Fetch the bid/offer catalog. fixture|simulator read a local file (unmistakably labelled);
/// live performs the real fetch — failure degrades WITH evidence, never fake supply.
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
                    .get("bids")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                json!({ "engaged": true, "mode": mode_label, "account_ref": account_ref,
                    "state": state_label, "offers": offers,
                    "evidence": { "mode": mode_label, "fixture_file": path,
                                  "bids_seen": doc.get("bids").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
                                  "warning": if simulator { "local lifecycle SIMULATOR — deployment/bid/lease control plane simulated, exec/custody lane real; NOT live supply" } else { "deterministic local fixture — NOT live supply; validates bid normalization/expiry/invariants only" } },
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
    if text(&ep, "mode") != "live" {
        return json!({ "engaged": false });
    }
    // ── live: a configured Akash console/indexer API serving provider/bid/pricing data. ──
    let base = text(&ep, "endpoint").trim_end_matches('/').to_string();
    if base.is_empty() {
        let outcome = json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
            "state": "degraded_unreachable", "offers": [],
            "evidence": { "mode": "live_evidence", "error": "akash_live_config_absent — endpoint.endpoint (console/indexer API base) is required for live bids", "note": "no fake bids on missing config" },
            "at": fetched_at });
        persist_health(&st.data_dir, &health_record(&outcome));
        return outcome;
    }
    let resp = reqwest::Client::new()
        .get(format!("{base}/v1/bids"))
        .bearer_auth(bearer.unwrap_or_default())
        .timeout(Duration::from_secs(12))
        .send()
        .await;
    let outcome = match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            match r.json::<Value>().await {
                Ok(doc) if (200..300).contains(&status) => {
                    let offers = doc
                        .get("bids")
                        .and_then(Value::as_array)
                        .or_else(|| doc.as_array())
                        .cloned()
                        .unwrap_or_default();
                    json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                        "state": "live_quote_source", "offers": offers,
                        "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status, "bids_seen": offers.len() },
                        "at": fetched_at })
                }
                Ok(doc) => {
                    json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                    "state": "degraded_unreachable", "offers": [],
                    "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status,
                                  "error": format!("akash API rejected the request (body keys: {:?})", doc.as_object().map(|o| o.keys().take(4).cloned().collect::<Vec<_>>()).unwrap_or_default()),
                                  "note": "no fake bids on failure" },
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
            "evidence": { "mode": "live_evidence", "endpoint": base, "error": format!("fetch failed: {e}"), "note": "no fake bids on failure" },
            "at": fetched_at }),
    };
    persist_health(&st.data_dir, &health_record(&outcome));
    outcome
}

/// Normalize BID offers into CloudResourceCandidates with DePIN semantics preserved. Fixture
/// files use { bids: [{ provider, region, attributes?, deployment_class?, gpu {model,count,
/// vram_gb}?, cpu_milli, memory_gb, storage_gb, persistent_storage, price { uakt_per_block,
/// usd_per_hour_quoted?, rate_basis? } }] }. A bid without a SOURCE-QUOTED USD rate is SKIPPED
/// — the daemon never invents an AKT/USD conversion.
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
    offers.iter().take(24).enumerate().filter_map(|(i, bid)| {
        let provider = text(bid, "provider");
        if provider.is_empty() { return None; }
        // Priced ONLY when the source quotes USD — uakt/block stays native evidence, never converted here.
        let usd = bid.pointer("/price/usd_per_hour_quoted").and_then(Value::as_f64).filter(|p| *p > 0.0)?;
        let uakt = bid.pointer("/price/uakt_per_block").cloned().unwrap_or(Value::Null);
        let id = format!("crc_{:x}_a{i}", nanos());
        let bid_ref = format!("akash-bid-offer://{id}");
        let deployment_class = {
            let c = text(bid, "deployment_class");
            if c.is_empty() { "compute.container" } else { c }
        };
        let gpu = bid.get("gpu").cloned().unwrap_or(Value::Null);
        let persistent = bid.get("persistent_storage").and_then(Value::as_bool).unwrap_or(false);
        let region = text(bid, "region");
        let mut risk: Vec<&str> = vec!["depin_provider_variability", "bid_lease_revocation", "deployment_storage_not_restore_truth"];
        if fixture { risk.push("fixture_evidence_not_live_supply"); }
        if simulator { risk.push("simulator_evidence_not_live_supply"); }
        let coverage = if fixture { "fixture_quote" } else if simulator { "simulator_quote" } else { "live_quote" };
        let eligibility: Vec<&str> = if live {
            vec!["placement_eligible", "quote_live", "guarded_lifecycle_available"]
        } else if simulator {
            vec!["advisory_only", "simulated_control_plane", "lifecycle_harness_only"]
        } else {
            vec!["advisory_only", "quote_preflight_only"]
        };
        let placement_eligible: Value = if live { json!(true) } else { json!("advisory_only") };
        let blocked_reason: Value = if live { Value::Null }
            else if simulator { json!("simulated_control_plane_not_live_supply") }
            else { json!("fixture_evidence_never_placement_eligible") };
        let claims = vec![
            json!(format!("akash bid from provider {provider}: {deployment_class} at ${usd}/hr — SOURCE-QUOTED USD rate (native uakt/block carried as evidence, never converted by the daemon)")),
            json!("DePIN deployment lease — SDL manifest → bids → lease → lease-assigned endpoints; provider bid/lease semantics preserved, never a fake generic cloud"),
        ];
        let quote = json!({
            "schema_version": "ioi.hypervisor.provider-quote.v1",
            "quote_ref": format!("provider-quote://{id}"),
            "usd_per_hour": usd,
            "currency": "USD",
            "basis": text(bid.get("price").unwrap_or(&Value::Null), "rate_basis").to_string()
                + " — source-quoted USD lease rate (verbatim); native uakt/block rate is evidence only",
            "native_rate": { "uakt_per_block": uakt, "note": "native Akash denomination — evidence, never converted by the daemon" },
            "offer_id": provider,
            "observed_at": observed_at,
            "expires_at": expires_at,
            "evidence_mode": mode,
        });
        let spend_estimate = json!({
            "schema_version": "ioi.hypervisor.spend-estimate.v1",
            "spend_estimate_ref": format!("spend-estimate://{id}"),
            "state": "quoted",
            "usd_per_hour": usd,
            "basis": "source-quoted lease rate only — no derived or padded numbers",
            "cost_owner": "customer",
            "routing_fee_eligibility": "eligible_future — only when optimized placement compares multiple real candidates; no fee exists today",
            "authority": "estimate, not spend authority",
        });
        let custody_plan = json!({
            "schema_version": "ioi.hypervisor.custody-plan.v1",
            "custody_plan_ref": format!("custody-plan://{id}"),
            "supported_postures": ["Standard"],
            "privacy": "depin_host_NOT_private",
            "detail": "DePIN deployment lease — Standard custody unless proven otherwise; deployment persistent storage and provider-native ids are availability EVIDENCE only, daemon custody state roots remain restore truth",
            "rule": "storage availability does not equal restore validity — daemon-admitted sha256 state roots are restore truth",
        });
        let failover_plan = json!({
            "schema_version": "ioi.hypervisor.failover-plan.v1",
            "failover_plan_ref": format!("failover-plan://{id}"),
            "detail": "on lease loss: close, REDEPLOY to a fresh bid (any provider), restore from daemon/storage-archive custody after state_root validation; fallback venue run_local",
            "authority_note": "failover requires the same wallet grants as any placement — a plan is not authority",
        });
        let evidence = json!({
            "schema_version": "ioi.hypervisor.candidate-evidence.v1",
            "evidence_ref": format!("candidate-evidence://{id}"),
            "source": "depin_market",
            "adapter_ref": "adapter:akash-bid",
            "observed_at": observed_at,
            "expires_at": expires_at,
            "coverage_state": coverage,
            "claims": claims,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "evidence_refs": [json!(account_ref), json!(format!("akash-provider:{provider}"))],
            "evidence_mode": mode,
        });
        Some(json!({
            "schema_version": "ioi.hypervisor.cloud-resource-candidate.v1",
            "candidate_id": id,
            "candidate_ref": format!("cloud-resource-candidate://{id}"),
            "intent_ref": intent_ref,
            "batch": batch,
            "source": "depin_market",
            "adapter_ref": "adapter:akash-bid",
            "provider_kind": "akash",
            "provider_account_ref": account_ref,
            "display_name": format!("Akash bid · {provider}"),
            "resource_classes": ["compute.gpu_runtime", "compute.container"],
            "runtime_class": deployment_class,
            "deployment_class": deployment_class,
            "provider_address": provider,
            "bid_ref": bid_ref,
            "provider_attributes": bid.get("attributes").cloned().unwrap_or(Value::Null),
            "gpu": gpu,
            "resources": { "cpu_milli": bid.get("cpu_milli").cloned().unwrap_or(Value::Null),
                           "memory_gb": bid.get("memory_gb").cloned().unwrap_or(Value::Null),
                           "storage_gb": bid.get("storage_gb").cloned().unwrap_or(Value::Null) },
            "region": if region.is_empty() { Value::Null } else { json!(region) },
            "quote": quote,
            "quote_ref": format!("provider-quote://{id}"),
            "quote_state": "quoted_from_bid",
            "spend_estimate": spend_estimate,
            "custody_plan": custody_plan,
            "failover_plan": failover_plan,
            "reliability": { "basis": "bid advisory — per-lease reliability evidence lands with the running deployment" },
            "network": { "ports_posture": "IP/ports are LEASE-ASSIGNED at deployment time and recorded as evidence, not authority; ingress beyond the SDL expose list requires the lifecycle + authority" },
            "storage": { "persistent_storage": persistent,
                         "posture": "deployment-scoped persistent storage (provider posture — survives restarts per SDL, dies with the lease; NEVER restore truth)" },
            "observed_at": observed_at,
            "expires_at": expires_at,
            "expires_epoch": expires_epoch,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "placement_eligible": placement_eligible,
            "lifecycle": if simulator { "guarded_lifecycle_simulator (deployment/bid/lease control plane simulated; exec/custody lane real)" }
                else if live { "guarded_lifecycle (quote-gated, receipted; live chain tx flow lands with the live harness)" }
                else { "quote_preflight_only" },
            "execution_blocked_reason": blocked_reason,
            "coverage_state": coverage,
            "evidence_mode": mode,
            "evidence": evidence,
            "authority": "none — a candidate cannot provision, release credentials, expose ingress, or claim custody/restore truth",
        }))
    }).collect()
}
