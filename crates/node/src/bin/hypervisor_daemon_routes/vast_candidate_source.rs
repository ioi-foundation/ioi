//! Vast.ai CANDIDATE SOURCE — the first live external GPU supply adapter feeding the
//! decentralized.cloud candidate plane. QUOTE + PREFLIGHT + CANDIDATE ENRICHMENT ONLY:
//! no provisioning, no mutation, no spend — the provider lifecycle stays fail-closed
//! (`PROVIDER_KIND_LIFECYCLE_NOT_IMPLEMENTED`) until the guarded lifecycle cut.
//!
//! Hard boundaries (byo-provider-plane.md + decentralized/cloud.md):
//! - No invented quotes: every ProviderQuote/SpendEstimate number comes verbatim from offer
//!   data. Credentials absent → `candidate_source_unavailable` with evidence. Fetch failure →
//!   `degraded_unreachable` with evidence — never fake supply.
//! - Fixture mode is EXPLICIT and unmistakable: offers loaded from a local file are marked
//!   `evidence_mode: fixture_evidence` on the source, every candidate, quote, and evidence
//!   record; `live_quote_source` is claimed only after a real network fetch succeeded.
//! - Privacy: `marketplace_host_NOT_private` — a marketplace host never claims Private/cTEE
//!   custody from marketing labels.
//! - The sealed bearer credential resolves only inside the daemon (existing resolver); it is
//!   never echoed into candidates, evidence, health records, or errors.
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::lifecycle_routes::open_scm_token;
use super::{iso_now, persist_record, read_record_dir, DaemonState};

const HEALTH_KIND: &str = "vast-source-health";
const DEFAULT_ENDPOINT: &str = "https://console.vast.ai/api/v0";

fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

/// The Vast account this source engages: kind == vast, preflight-verified, sealed bearer
/// credential resolvable. Returns (account, bearer) — the bearer never leaves the daemon.
fn engaged_account(data_dir: &str) -> Option<(Value, Option<String>)> {
    let account = read_record_dir(data_dir, "provider-accounts")
        .into_iter()
        .find(|a| a["kind"] == "vast" && a["status"] == "verified")?;
    let cred = read_record_dir(data_dir, "provider-credentials")
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(text(&account, "account_id")))?;
    let bearer = cred["sealed_token"].as_str().and_then(open_scm_token);
    bearer.as_ref()?;
    Some((account, bearer))
}

/// The last fetch outcome, persisted so source health is inspectable without re-probing.
fn persist_health(data_dir: &str, health: &Value) {
    let _ = persist_record(data_dir, HEALTH_KIND, "current", health);
}
pub(crate) fn load_health(data_dir: &str) -> Option<Value> {
    read_record_dir(data_dir, HEALTH_KIND)
        .into_iter()
        .find(|r| r["health_id"].as_str() == Some("current"))
}

/// Source posture for GET /candidate-sources — static credential posture + last fetch health.
pub(crate) fn source_state(data_dir: &str) -> Value {
    let accounts = read_record_dir(data_dir, "provider-accounts");
    let vast_accounts: Vec<&Value> = accounts.iter().filter(|a| a["kind"] == "vast").collect();
    if vast_accounts.is_empty() {
        return json!({ "source": "vast", "state": "candidate_source_unavailable",
            "reason": "vast_credential_absent — no vast ProviderAccount exists; create one, bind a bearer api_key, and preflight it",
            "evidence": { "vast_accounts": 0, "basis": "provider-accounts records" } });
    }
    let Some((engaged, _)) = engaged_account(data_dir) else {
        return json!({ "source": "vast", "state": "candidate_source_unavailable",
            "reason": "vast_credential_absent — a vast ProviderAccount exists but no verified account with a resolvable sealed bearer credential",
            "evidence": { "vast_accounts": vast_accounts.len(),
                          "verified": vast_accounts.iter().filter(|a| a["status"] == "verified").count(),
                          "basis": "provider-accounts + sealed-credential resolution (daemon-side only)" } });
    };
    // Health is evidence about ONE account's last fetch — stale health from a different
    // (e.g. deleted) account says nothing about the currently engaged one.
    match load_health(data_dir).filter(|h| h["account_ref"] == engaged["account_ref"]) {
        Some(h) => {
            let state = text(&h, "state").to_string();
            json!({ "source": "vast", "state": state,
                "mode": h.get("mode").cloned().unwrap_or(Value::Null),
                "evidence": h.get("evidence").cloned().unwrap_or(Value::Null),
                "at": h.get("at").cloned().unwrap_or(Value::Null) })
        }
        None => json!({ "source": "vast", "state": "credential_verified_unprobed",
            "reason": "credential verified — no offer fetch has run yet (refresh candidates to probe)",
            "evidence": { "basis": "sealed bearer resolvable; no fetch attempted" } }),
    }
}

/// Fetch the offer catalog. Fixture mode (endpoint.mode == "fixture") reads a local JSON file
/// and is UNMISTAKABLY marked; live mode performs the real network fetch. Returns the outcome
/// object consumed by candidate derivation (offers normalized separately).
pub(crate) async fn fetch_offers(st: &Arc<DaemonState>) -> Value {
    let Some((account, bearer)) = engaged_account(&st.data_dir) else {
        return json!({ "engaged": false });
    };
    let account_ref = text(&account, "account_ref").to_string();
    let ep = account.get("endpoint").cloned().unwrap_or_else(|| json!({}));
    let fetched_at = iso_now();
    if text(&ep, "mode") == "fixture" {
        let path = text(&ep, "fixture_file");
        let outcome = match std::fs::read_to_string(path) {
            Ok(raw) => match serde_json::from_str::<Value>(&raw) {
                Ok(doc) => {
                    let offers = doc.get("offers").and_then(Value::as_array).cloned().unwrap_or_default();
                    json!({ "engaged": true, "mode": "fixture_evidence", "account_ref": account_ref,
                        "state": "fixture_quote_source", "offers": offers,
                        "evidence": { "mode": "fixture_evidence", "fixture_file": path,
                                      "offers_seen": doc.get("offers").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
                                      "warning": "deterministic local fixture — NOT live supply; validates normalization/expiry/invariants only" },
                        "at": fetched_at })
                }
                Err(e) => json!({ "engaged": true, "mode": "fixture_evidence", "account_ref": account_ref,
                    "state": "degraded_unreachable", "offers": [],
                    "evidence": { "mode": "fixture_evidence", "fixture_file": path, "error": format!("fixture parse failed: {e}") },
                    "at": fetched_at }),
            },
            Err(e) => json!({ "engaged": true, "mode": "fixture_evidence", "account_ref": account_ref,
                "state": "degraded_unreachable", "offers": [],
                "evidence": { "mode": "fixture_evidence", "fixture_file": path, "error": format!("fixture unreadable: {e}") },
                "at": fetched_at }),
        };
        persist_health(&st.data_dir, &health_record(&outcome));
        return outcome;
    }
    // ── live mode: the real Vast offer search. Read-only; the bearer is used in-daemon only. ──
    let base = {
        let configured = text(&ep, "endpoint");
        if configured.is_empty() { DEFAULT_ENDPOINT.to_string() } else { configured.trim_end_matches('/').to_string() }
    };
    let url = format!("{base}/bundles/");
    let client = reqwest::Client::new();
    let query = json!({ "q": { "rentable": { "eq": true }, "order": [["dph_total", "asc"]], "limit": 24 } });
    let resp = client
        .get(&url)
        .bearer_auth(bearer.unwrap_or_default())
        .query(&[("q", query["q"].to_string())])
        .timeout(Duration::from_secs(12))
        .send()
        .await;
    let outcome = match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            match r.json::<Value>().await {
                Ok(doc) if (200..300).contains(&status) => {
                    let offers = doc.get("offers").and_then(Value::as_array).cloned().unwrap_or_default();
                    json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                        "state": "live_quote_source", "offers": offers,
                        "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status,
                                      "offers_seen": doc.get("offers").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0) },
                        "at": fetched_at })
                }
                Ok(doc) => json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                    "state": "degraded_unreachable", "offers": [],
                    "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status,
                                  "error": format!("vast API rejected the request (body keys: {:?})", doc.as_object().map(|o| o.keys().take(4).cloned().collect::<Vec<_>>()).unwrap_or_default()),
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

fn health_record(outcome: &Value) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.vast-source-health.v1",
        "health_id": "current",
        "state": outcome["state"],
        "mode": outcome["mode"],
        "account_ref": outcome["account_ref"],
        "evidence": outcome["evidence"],
        "at": outcome["at"],
    })
}

/// Normalize real Vast offers into CloudResourceCandidates with ProviderQuote + SpendEstimate
/// projections. QUOTE-ONLY posture: `lifecycle: quote_preflight_only`,
/// `placement_eligible: "advisory_only"` (a string, deliberately NOT `true` — the advisory
/// recommendation and eligible-count filters compare against boolean true, so these candidates
/// render as advisory supply without ever becoming recommendable or provisionable).
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
    let offers = outcome.get("offers").and_then(Value::as_array).cloned().unwrap_or_default();
    offers.iter().take(24).enumerate().filter_map(|(i, offer)| {
        // No invented quotes: an offer without a real price is skipped, not estimated.
        let dph = offer.get("dph_total").and_then(Value::as_f64)?;
        let id = format!("crc_{:x}_v{i}", nanos());
        let offer_id = offer.get("id").cloned().unwrap_or(Value::Null);
        let gpu_name = text(offer, "gpu_name");
        let num_gpus = offer.get("num_gpus").and_then(Value::as_u64).unwrap_or(1);
        let vram_gb = offer.get("gpu_ram").and_then(Value::as_f64).map(|mb| (mb / 1024.0 * 10.0).round() / 10.0);
        let region = text(offer, "geolocation");
        let reliability = offer.get("reliability2").and_then(Value::as_f64);
        let verified_host = offer.get("verified").and_then(Value::as_bool).unwrap_or(false);
        let mut risk: Vec<&str> = vec!["marketplace_rental_interruption"];
        if !verified_host { risk.push("unverified_marketplace_host"); }
        if fixture { risk.push("fixture_evidence_not_live_supply"); }
        let claims = vec![
            json!(format!("vast offer {offer_id}: {num_gpus}x {gpu_name} at ${dph}/hr (verbatim offer data — nothing invented)")),
            json!("quote + preflight only — no provisioning, no mutation, no spend on this path"),
        ];
        let coverage = if fixture { "fixture_quote" } else { "live_quote" };
        let eligibility = ["advisory_only", "quote_preflight_only", "lifecycle_adapter_absent"];
        let quote = json!({
            "schema_version": "ioi.hypervisor.provider-quote.v1",
            "quote_ref": format!("provider-quote://{id}"),
            "usd_per_hour": dph,
            "currency": "USD",
            "basis": "vast offer dph_total (verbatim)",
            "offer_id": offer_id,
            "observed_at": observed_at,
            "expires_at": expires_at,
            "evidence_mode": mode,
        });
        let spend_estimate = json!({
            "schema_version": "ioi.hypervisor.spend-estimate.v1",
            "spend_estimate_ref": format!("spend-estimate://{id}"),
            "state": "quoted",
            "usd_per_hour": dph,
            "basis": "real offer price only — no derived or padded numbers",
            "cost_owner": "customer",
            "routing_fee_eligibility": "eligible_future — only when optimized placement compares multiple real candidates; no fee exists today",
            "authority": "estimate, not spend authority",
        });
        let custody_plan = json!({
            "schema_version": "ioi.hypervisor.custody-plan.v1",
            "custody_plan_ref": format!("custody-plan://{id}"),
            "supported_postures": ["Standard"],
            "privacy": "marketplace_host_NOT_private",
            "detail": "marketplace host — never Private/cTEE from marketing labels; snapshot custody lands with the guarded lifecycle cut",
            "rule": "storage availability does not equal restore validity — daemon-admitted sha256 state roots are restore truth",
        });
        let failover_plan = json!({
            "schema_version": "ioi.hypervisor.failover-plan.v1",
            "failover_plan_ref": format!("failover-plan://{id}"),
            "detail": "no failover plan without a live lifecycle adapter; fallback venue run_local",
            "authority_note": "failover requires the same wallet grants as any placement — a plan is not authority",
        });
        let evidence = json!({
            "schema_version": "ioi.hypervisor.candidate-evidence.v1",
            "evidence_ref": format!("candidate-evidence://{id}"),
            "source": "depin_market",
            "adapter_ref": "adapter:vast-quote",
            "observed_at": observed_at,
            "expires_at": expires_at,
            "coverage_state": coverage,
            "claims": claims,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "evidence_refs": [json!(account_ref), json!(format!("vast-offer:{offer_id}"))],
            "evidence_mode": mode,
        });
        Some(json!({
            "schema_version": "ioi.hypervisor.cloud-resource-candidate.v1",
            "candidate_id": id,
            "candidate_ref": format!("cloud-resource-candidate://{id}"),
            "intent_ref": intent_ref,
            "batch": batch,
            "source": "depin_market",
            "adapter_ref": "adapter:vast-quote",
            "provider_kind": "vast",
            "provider_account_ref": account_ref,
            "display_name": format!("Vast · {num_gpus}x {gpu_name}"),
            "resource_classes": ["compute.gpu_runtime", "compute.container"],
            "runtime_class": "compute.gpu_runtime",
            "gpu": { "model": gpu_name, "count": num_gpus, "vram_gb": vram_gb },
            "region": if region.is_empty() { Value::Null } else { json!(region) },
            "quote": quote,
            "quote_ref": format!("provider-quote://{id}"),
            "quote_state": "quoted_from_offer_data",
            "spend_estimate": spend_estimate,
            "custody_plan": custody_plan,
            "failover_plan": failover_plan,
            "reliability": { "host_reliability": reliability, "verified_host": verified_host, "basis": "vast offer fields (verbatim)" },
            "network": { "inet_down_mbps": offer.get("inet_down").cloned().unwrap_or(Value::Null),
                          "inet_up_mbps": offer.get("inet_up").cloned().unwrap_or(Value::Null),
                          "ports_posture": "provider-managed port mapping; ingress exposure requires the lifecycle adapter + authority" },
            "storage": { "disk_gb": offer.get("disk_space").cloned().unwrap_or(Value::Null), "posture": "instance-scoped marketplace disk" },
            "observed_at": observed_at,
            "expires_at": expires_at,
            "expires_epoch": expires_epoch,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "placement_eligible": "advisory_only",
            "lifecycle": "quote_preflight_only",
            "execution_blocked_reason": "provider_kind_lifecycle_not_implemented",
            "coverage_state": coverage,
            "evidence_mode": mode,
            "evidence": evidence,
            "authority": "none — a candidate cannot provision, release credentials, expose ingress, or claim custody/restore truth",
        }))
    }).collect()
}
