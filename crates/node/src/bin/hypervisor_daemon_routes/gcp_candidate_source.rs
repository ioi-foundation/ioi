//! GCP Compute Engine CANDIDATE SOURCE — the second ENTERPRISE hyperscaler lane, sibling to
//! AWS but with GCP SEMANTICS preserved (never EC2 names): service-account/workload-identity
//! authority, PROJECT/region/ZONE, machine types (+ attached accelerators), VPC
//! network/subnetwork/FIREWALL posture, Persistent Disk boot volumes, external-IP-vs-private
//! reachability. `direct_provider` source; quotes are per-machine-type on-demand rate cards.
//!
//! Same hard boundaries as every quote source: the sealed service-account credential resolves
//! only in-daemon; no fake offers on failure (degraded WITH evidence); fixture/simulator
//! unmistakably labelled; live claims only after a real fetch of a configured pricing feed;
//! unpriced shapes SKIPPED, never estimated. Risk labels are GCP-shaped
//! (iam_service_account_scope_dependent, vpc_firewall_ssh_ingress_required,
//! pd_native_snapshots_evidence_only) — never AWS or marketplace labels. Instance/disk/snapshot
//! native ids are evidence only; daemon state roots remain restore truth.
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, DaemonState};

const HEALTH_KIND: &str = "gcp-source-health";

fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn engaged_account(data_dir: &str) -> Option<Value> {
    let account = read_record_dir(data_dir, "provider-accounts")
        .into_iter()
        .find(|a| a["kind"] == "gcp" && a["status"] == "verified")?;
    read_record_dir(data_dir, "provider-credentials")
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(text(&account, "account_id")))?;
    Some(account)
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
    let gcp_accounts: Vec<&Value> = accounts.iter().filter(|a| a["kind"] == "gcp").collect();
    if gcp_accounts.is_empty() {
        return json!({ "source": "gcp", "state": "candidate_source_unavailable",
            "reason": "gcp_credential_absent — no gcp ProviderAccount exists; create one, bind a service-account credential (service_account_key), and preflight it",
            "evidence": { "gcp_accounts": 0, "basis": "provider-accounts records" } });
    }
    let Some(engaged) = engaged_account(data_dir) else {
        return json!({ "source": "gcp", "state": "candidate_source_unavailable",
            "reason": "gcp_credential_absent — a gcp ProviderAccount exists but no verified account with a sealed service-account credential",
            "evidence": { "gcp_accounts": gcp_accounts.len(),
                          "verified": gcp_accounts.iter().filter(|a| a["status"] == "verified").count(),
                          "basis": "provider-accounts + sealed-credential records (daemon-side only)" } });
    };
    match load_health(data_dir).filter(|h| h["account_ref"] == engaged["account_ref"]) {
        Some(h) => {
            let state = text(&h, "state").to_string();
            json!({ "source": "gcp", "state": state,
                "mode": h.get("mode").cloned().unwrap_or(Value::Null),
                "evidence": h.get("evidence").cloned().unwrap_or(Value::Null),
                "at": h.get("at").cloned().unwrap_or(Value::Null) })
        }
        None => json!({ "source": "gcp", "state": "credential_verified_unprobed",
            "reason": "credential verified — no machine-offer fetch has run yet (refresh candidates to probe)",
            "evidence": { "basis": "sealed service-account credential present; no fetch attempted" } }),
    }
}

fn health_record(outcome: &Value) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.gcp-source-health.v1",
        "health_id": "current",
        "state": outcome["state"],
        "mode": outcome["mode"],
        "account_ref": outcome["account_ref"],
        "evidence": outcome["evidence"],
        "at": outcome["at"],
    })
}

/// Fetch the machine-type offer catalog. fixture|simulator read a local file (unmistakably
/// labelled); live fetches a CONFIGURED pricing feed — failure degrades WITH evidence, never
/// fake supply (live lifecycle claims still require the live harness).
pub(crate) async fn fetch_offers(st: &Arc<DaemonState>) -> Value {
    let Some(account) = engaged_account(&st.data_dir) else {
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
                    .get("machine_offers")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                json!({ "engaged": true, "mode": mode_label, "account_ref": account_ref,
                    "state": state_label, "offers": offers,
                    "evidence": { "mode": mode_label, "fixture_file": path,
                                  "machine_offers_seen": doc.get("machine_offers").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
                                  "warning": if simulator { "local lifecycle SIMULATOR — Compute Engine control plane simulated, ssh/custody lane real; NOT live supply" } else { "deterministic local fixture — NOT live supply; validates normalization/expiry/invariants only" } },
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
    let base = text(&ep, "endpoint").trim_end_matches('/').to_string();
    if base.is_empty() {
        let outcome = json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
            "state": "degraded_unreachable", "offers": [],
            "evidence": { "mode": "live_evidence", "error": "gcp_live_config_absent — endpoint.endpoint (a pricing feed serving {machine_offers}) is required for live offers", "note": "no fake offers on missing config" },
            "at": fetched_at });
        persist_health(&st.data_dir, &health_record(&outcome));
        return outcome;
    }
    let resp = reqwest::Client::new()
        .get(format!("{base}/machine-offers"))
        .timeout(Duration::from_secs(12))
        .send()
        .await;
    let outcome = match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            match r.json::<Value>().await {
                Ok(doc) if (200..300).contains(&status) => {
                    let offers = doc
                        .get("machine_offers")
                        .and_then(Value::as_array)
                        .or_else(|| doc.as_array())
                        .cloned()
                        .unwrap_or_default();
                    json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                        "state": "live_quote_source", "offers": offers,
                        "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status, "machine_offers_seen": offers.len() },
                        "at": fetched_at })
                }
                Ok(doc) => {
                    json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                    "state": "degraded_unreachable", "offers": [],
                    "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status,
                                  "error": format!("pricing feed rejected the request (body keys: {:?})", doc.as_object().map(|o| o.keys().take(4).cloned().collect::<Vec<_>>()).unwrap_or_default()),
                                  "note": "no fake offers on failure" },
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
            "evidence": { "mode": "live_evidence", "endpoint": base, "error": format!("fetch failed: {e}"), "note": "no fake offers on failure" },
            "at": fetched_at }),
    };
    persist_health(&st.data_dir, &health_record(&outcome));
    outcome
}

/// Normalize machine-type offers into CloudResourceCandidates with GCP semantics. Fixture files
/// use { machine_offers: [{ project, region, zone, machine_type, vcpu, memory_gb, accelerator
/// {model, count, vram_gb}?, boot_disk {gb, type}, network {network, subnetwork?,
/// external_ip_supported, firewall_ssh_ingress}, usd_per_hour?, pricing_basis? }] }.
/// Unpriced offers are SKIPPED, never estimated.
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
    offers.iter().take(24).enumerate().filter_map(|(i, offer)| {
        let usd = offer.get("usd_per_hour").and_then(Value::as_f64).filter(|p| *p > 0.0)?;
        let machine_type = text(offer, "machine_type");
        let zone = text(offer, "zone");
        if machine_type.is_empty() || zone.is_empty() { return None; }
        let id = format!("crc_{:x}_g{i}", nanos());
        let project = text(offer, "project");
        let accelerator = offer.get("accelerator").cloned().unwrap_or(Value::Null);
        let disk = offer.get("boot_disk").cloned().unwrap_or(json!({}));
        let network = offer.get("network").cloned().unwrap_or(json!({}));
        let external_ip = network.get("external_ip_supported").and_then(Value::as_bool).unwrap_or(true);
        let firewall_ok = network.get("firewall_ssh_ingress").and_then(Value::as_bool).unwrap_or(true);
        let mut risk: Vec<&str> = vec!["iam_service_account_scope_dependent", "vpc_firewall_ssh_ingress_required", "pd_native_snapshots_evidence_only"];
        if !external_ip { risk.push("private_only_posture_unreachable_for_ssh"); }
        if !firewall_ok { risk.push("firewall_ssh_ingress_missing"); }
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
            json!(format!("Compute Engine {machine_type} in {zone} at ${usd}/hr — verbatim on-demand rate card, nothing invented")),
            json!("ENTERPRISE customer-cloud lane — service-account authority, project/zone scoping, VPC firewall posture, Persistent Disk boot volume; runs in YOUR project under YOUR audit logs"),
        ];
        let pricing_basis = {
            let b = text(offer, "pricing_basis");
            if b.is_empty() { "Compute Engine on-demand rate card (verbatim)".to_string() } else { b.to_string() }
        };
        let quote = json!({
            "schema_version": "ioi.hypervisor.provider-quote.v1",
            "quote_ref": format!("provider-quote://{id}"),
            "usd_per_hour": usd,
            "currency": "USD",
            "basis": pricing_basis,
            "offer_id": format!("{zone}/{machine_type}"),
            "observed_at": observed_at,
            "expires_at": expires_at,
            "evidence_mode": mode,
        });
        let spend_estimate = json!({
            "schema_version": "ioi.hypervisor.spend-estimate.v1",
            "spend_estimate_ref": format!("spend-estimate://{id}"),
            "state": "quoted",
            "usd_per_hour": usd,
            "basis": "real rate-card price only — no derived or padded numbers; Persistent Disk billing continues while the instance is stopped (TERMINATED)",
            "cost_owner": "customer",
            "routing_fee_eligibility": "eligible_future — only when optimized placement compares multiple real candidates; no fee exists today",
            "authority": "estimate, not spend authority",
        });
        let custody_plan = json!({
            "schema_version": "ioi.hypervisor.custody-plan.v1",
            "custody_plan_ref": format!("custody-plan://{id}"),
            "supported_postures": ["Standard"],
            "privacy": "customer_cloud_iam_scoped",
            "detail": "your GCP project, your service-account boundary — Standard custody unless proven otherwise; instance/Persistent-Disk/snapshot native ids are EVIDENCE only, daemon custody state roots remain restore truth",
            "rule": "storage availability does not equal restore validity — daemon-admitted sha256 state roots are restore truth",
        });
        let failover_plan = json!({
            "schema_version": "ioi.hypervisor.failover-plan.v1",
            "failover_plan_ref": format!("failover-plan://{id}"),
            "detail": "re-create the machine type (same or another zone) + restore from daemon/storage-archive custody after state_root validation; fallback venue run_local",
            "authority_note": "failover requires the same wallet grants as any placement — a plan is not authority",
        });
        let evidence = json!({
            "schema_version": "ioi.hypervisor.candidate-evidence.v1",
            "evidence_ref": format!("candidate-evidence://{id}"),
            "source": "direct_provider",
            "adapter_ref": "adapter:gcp-compute-quote",
            "observed_at": observed_at,
            "expires_at": expires_at,
            "coverage_state": coverage,
            "claims": claims,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "evidence_refs": [json!(account_ref), json!(format!("gcp-machine-offer:{zone}/{machine_type}"))],
            "evidence_mode": mode,
        });
        Some(json!({
            "schema_version": "ioi.hypervisor.cloud-resource-candidate.v1",
            "candidate_id": id,
            "candidate_ref": format!("cloud-resource-candidate://{id}"),
            "intent_ref": intent_ref,
            "batch": batch,
            "source": "direct_provider",
            "adapter_ref": "adapter:gcp-compute-quote",
            "provider_kind": "gcp",
            "provider_account_ref": account_ref,
            "display_name": format!("GCP Compute · {machine_type} ({zone})"),
            "resource_classes": ["compute.vm", "compute.gpu_runtime"],
            "runtime_class": "compute.vm",
            "machine_type": machine_type,
            "project": if project.is_empty() { Value::Null } else { json!(project) },
            "region": offer.get("region").cloned().unwrap_or(Value::Null),
            "zone": zone,
            "vcpu": offer.get("vcpu").cloned().unwrap_or(Value::Null),
            "memory_gb": offer.get("memory_gb").cloned().unwrap_or(Value::Null),
            "gpu": accelerator,
            "quote": quote,
            "quote_ref": format!("provider-quote://{id}"),
            "quote_state": "quoted_from_rate_card",
            "spend_estimate": spend_estimate,
            "custody_plan": custody_plan,
            "failover_plan": failover_plan,
            "reliability": { "basis": "rate-card quote — per-instance reliability evidence lands with the running instance" },
            "network": {
                "network_posture": network.get("network").cloned().unwrap_or(json!("default")),
                "subnetwork": network.get("subnetwork").cloned().unwrap_or(Value::Null),
                "external_ip_supported": external_ip,
                "firewall_ssh_ingress": firewall_ok,
                "ports_posture": "SSH requires a VPC firewall allow rule + a reachable external IP — private-only or firewall-closed postures fail closed, never fake-ready",
            },
            "storage": { "disk_gb": disk.get("gb").cloned().unwrap_or(Value::Null),
                         "volume_type": disk.get("type").cloned().unwrap_or(Value::Null),
                         "posture": "Persistent Disk boot volume (auto-delete with the instance unless configured otherwise) — native disk/snapshot ids are evidence only, never restore truth" },
            "observed_at": observed_at,
            "expires_at": expires_at,
            "expires_epoch": expires_epoch,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "placement_eligible": placement_eligible,
            "lifecycle": if simulator { "guarded_lifecycle_simulator (Compute Engine control plane simulated; ssh/custody lane real)" }
                else if live { "guarded_lifecycle (quote-gated, receipted; the Compute Engine API flow lands with the live harness)" }
                else { "quote_preflight_only" },
            "execution_blocked_reason": blocked_reason,
            "coverage_state": coverage,
            "evidence_mode": mode,
            "evidence": evidence,
            "authority": "none — a candidate cannot provision, release credentials, expose ingress, or claim custody/restore truth",
        }))
    }).collect()
}
