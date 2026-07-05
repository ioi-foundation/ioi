//! AWS EC2 CANDIDATE SOURCE — the first ENTERPRISE hyperscaler lane (canon priority ladder #5).
//! Not a GPU marketplace and not a generic cloud: AWS semantics preserved — IAM/SigV4
//! authority, region/AZ, VPC/subnet/security-group posture, EC2 instance types, EBS root
//! volume posture, and public-IP-vs-private reachability. `direct_provider` source; quotes are
//! per-instance-type ON-DEMAND rate cards.
//!
//! Same hard boundaries as every quote source: sealed SigV4 credential resolves only in-daemon;
//! no fake offers on failure (degraded WITH evidence); fixture/simulator unmistakably labelled;
//! live claims only after a real fetch of a configured pricing feed; unpriced shapes SKIPPED,
//! never estimated. Risk labels are AWS-shaped (iam_scope_dependent,
//! vpc_ssh_ingress_required, ebs_native_snapshots_evidence_only) — never marketplace or DePIN
//! labels. EC2/EBS native ids are evidence only; daemon state roots remain restore truth.
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, DaemonState};

const HEALTH_KIND: &str = "aws-source-health";

fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

fn engaged_account(data_dir: &str) -> Option<Value> {
    let account = read_record_dir(data_dir, "provider-accounts")
        .into_iter()
        .find(|a| a["kind"] == "aws" && a["status"] == "verified")?;
    // A sealed aws-sigv4 credential must EXIST and resolve daemon-side; it is never exported.
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
    let aws_accounts: Vec<&Value> = accounts.iter().filter(|a| a["kind"] == "aws").collect();
    if aws_accounts.is_empty() {
        return json!({ "source": "aws", "state": "candidate_source_unavailable",
            "reason": "aws_credential_absent — no aws ProviderAccount exists; create one, bind a SigV4 credential (secret_access_key + access_key_id), and preflight it",
            "evidence": { "aws_accounts": 0, "basis": "provider-accounts records" } });
    }
    let Some(engaged) = engaged_account(data_dir) else {
        return json!({ "source": "aws", "state": "candidate_source_unavailable",
            "reason": "aws_credential_absent — an aws ProviderAccount exists but no verified account with a sealed SigV4 credential",
            "evidence": { "aws_accounts": aws_accounts.len(),
                          "verified": aws_accounts.iter().filter(|a| a["status"] == "verified").count(),
                          "basis": "provider-accounts + sealed-credential records (daemon-side only)" } });
    };
    match load_health(data_dir).filter(|h| h["account_ref"] == engaged["account_ref"]) {
        Some(h) => {
            let state = text(&h, "state").to_string();
            json!({ "source": "aws", "state": state,
                "mode": h.get("mode").cloned().unwrap_or(Value::Null),
                "evidence": h.get("evidence").cloned().unwrap_or(Value::Null),
                "at": h.get("at").cloned().unwrap_or(Value::Null) })
        }
        None => json!({ "source": "aws", "state": "credential_verified_unprobed",
            "reason": "credential verified — no instance-offer fetch has run yet (refresh candidates to probe)",
            "evidence": { "basis": "sealed SigV4 credential present; no fetch attempted" } }),
    }
}

fn health_record(outcome: &Value) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.aws-source-health.v1",
        "health_id": "current",
        "state": outcome["state"],
        "mode": outcome["mode"],
        "account_ref": outcome["account_ref"],
        "evidence": outcome["evidence"],
        "at": outcome["at"],
    })
}

/// Fetch the EC2 instance-offer catalog. fixture|simulator read a local file (unmistakably
/// labelled); live fetches a CONFIGURED pricing feed — failure degrades WITH evidence, never
/// fake supply (the full public AWS offers file is impractical inline; a feed endpoint is
/// explicit config, and live lifecycle claims still require the live harness).
pub(crate) async fn fetch_offers(st: &Arc<DaemonState>) -> Value {
    let Some(account) = engaged_account(&st.data_dir) else {
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
                let offers = doc.get("instance_offers").and_then(Value::as_array).cloned().unwrap_or_default();
                json!({ "engaged": true, "mode": mode_label, "account_ref": account_ref,
                    "state": state_label, "offers": offers,
                    "evidence": { "mode": mode_label, "fixture_file": path,
                                  "instance_offers_seen": doc.get("instance_offers").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
                                  "warning": if simulator { "local lifecycle SIMULATOR — EC2 control plane simulated, ssh/custody lane real; NOT live supply" } else { "deterministic local fixture — NOT live supply; validates normalization/expiry/invariants only" } },
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
            "evidence": { "mode": "live_evidence", "error": "aws_live_config_absent — endpoint.endpoint (a pricing feed serving {instance_offers}) is required for live offers", "note": "no fake offers on missing config" },
            "at": fetched_at });
        persist_health(&st.data_dir, &health_record(&outcome));
        return outcome;
    }
    let resp = reqwest::Client::new()
        .get(format!("{base}/instance-offers"))
        .timeout(Duration::from_secs(12))
        .send()
        .await;
    let outcome = match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            match r.json::<Value>().await {
                Ok(doc) if (200..300).contains(&status) => {
                    let offers = doc.get("instance_offers").and_then(Value::as_array)
                        .or_else(|| doc.as_array())
                        .cloned()
                        .unwrap_or_default();
                    json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                        "state": "live_quote_source", "offers": offers,
                        "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status, "instance_offers_seen": offers.len() },
                        "at": fetched_at })
                }
                Ok(doc) => json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                    "state": "degraded_unreachable", "offers": [],
                    "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status,
                                  "error": format!("pricing feed rejected the request (body keys: {:?})", doc.as_object().map(|o| o.keys().take(4).cloned().collect::<Vec<_>>()).unwrap_or_default()),
                                  "note": "no fake offers on failure" },
                    "at": fetched_at }),
                Err(e) => json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                    "state": "degraded_unreachable", "offers": [],
                    "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status, "error": format!("non-JSON response: {e}") },
                    "at": fetched_at }),
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

/// Normalize EC2 instance offers into CloudResourceCandidates with AWS semantics. Fixture files
/// use { instance_offers: [{ region, az?, instance_type, vcpu, memory_gb, gpu?, root_volume
/// {gb, type}, network {vpc_posture, public_ip_supported}, usd_per_hour?, pricing_basis? }] }.
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
    let offers = outcome.get("offers").and_then(Value::as_array).cloned().unwrap_or_default();
    offers.iter().take(24).enumerate().filter_map(|(i, offer)| {
        let usd = offer.get("usd_per_hour").and_then(Value::as_f64).filter(|p| *p > 0.0)?;
        let instance_type = text(offer, "instance_type");
        let region = text(offer, "region");
        if instance_type.is_empty() || region.is_empty() { return None; }
        let id = format!("crc_{:x}_w{i}", nanos());
        let gpu = offer.get("gpu").cloned().unwrap_or(Value::Null);
        let root = offer.get("root_volume").cloned().unwrap_or(json!({}));
        let network = offer.get("network").cloned().unwrap_or(json!({}));
        let public_ip = network.get("public_ip_supported").and_then(Value::as_bool).unwrap_or(true);
        let mut risk: Vec<&str> = vec!["iam_scope_dependent", "vpc_ssh_ingress_required", "ebs_native_snapshots_evidence_only"];
        if !public_ip { risk.push("private_only_posture_unreachable_for_ssh"); }
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
            json!(format!("EC2 {instance_type} in {region} at ${usd}/hr — verbatim on-demand rate card, nothing invented")),
            json!("ENTERPRISE customer-cloud lane — IAM/SigV4 authority, VPC/security-group posture, EBS root volume; runs in YOUR AWS account under YOUR audit trail"),
        ];
        let pricing_basis = {
            let b = text(offer, "pricing_basis");
            if b.is_empty() { "EC2 on-demand rate card (verbatim)".to_string() } else { b.to_string() }
        };
        let quote = json!({
            "schema_version": "ioi.hypervisor.provider-quote.v1",
            "quote_ref": format!("provider-quote://{id}"),
            "usd_per_hour": usd,
            "currency": "USD",
            "basis": pricing_basis,
            "offer_id": format!("{region}/{instance_type}"),
            "observed_at": observed_at,
            "expires_at": expires_at,
            "evidence_mode": mode,
        });
        let spend_estimate = json!({
            "schema_version": "ioi.hypervisor.spend-estimate.v1",
            "spend_estimate_ref": format!("spend-estimate://{id}"),
            "state": "quoted",
            "usd_per_hour": usd,
            "basis": "real rate-card price only — no derived or padded numbers; EBS storage billing continues while the instance is stopped",
            "cost_owner": "customer",
            "routing_fee_eligibility": "eligible_future — only when optimized placement compares multiple real candidates; no fee exists today",
            "authority": "estimate, not spend authority",
        });
        let custody_plan = json!({
            "schema_version": "ioi.hypervisor.custody-plan.v1",
            "custody_plan_ref": format!("custody-plan://{id}"),
            "supported_postures": ["Standard"],
            "privacy": "customer_cloud_iam_scoped",
            "detail": "your AWS account, your IAM boundary — Standard custody unless proven otherwise; EC2/EBS/native-snapshot ids are EVIDENCE only, daemon custody state roots remain restore truth",
            "rule": "storage availability does not equal restore validity — daemon-admitted sha256 state roots are restore truth",
        });
        let failover_plan = json!({
            "schema_version": "ioi.hypervisor.failover-plan.v1",
            "failover_plan_ref": format!("failover-plan://{id}"),
            "detail": "re-launch the instance type (same or another region/AZ) + restore from daemon/storage-archive custody after state_root validation; fallback venue run_local",
            "authority_note": "failover requires the same wallet grants as any placement — a plan is not authority",
        });
        let evidence = json!({
            "schema_version": "ioi.hypervisor.candidate-evidence.v1",
            "evidence_ref": format!("candidate-evidence://{id}"),
            "source": "direct_provider",
            "adapter_ref": "adapter:aws-ec2-quote",
            "observed_at": observed_at,
            "expires_at": expires_at,
            "coverage_state": coverage,
            "claims": claims,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "evidence_refs": [json!(account_ref), json!(format!("aws-instance-offer:{region}/{instance_type}"))],
            "evidence_mode": mode,
        });
        Some(json!({
            "schema_version": "ioi.hypervisor.cloud-resource-candidate.v1",
            "candidate_id": id,
            "candidate_ref": format!("cloud-resource-candidate://{id}"),
            "intent_ref": intent_ref,
            "batch": batch,
            "source": "direct_provider",
            "adapter_ref": "adapter:aws-ec2-quote",
            "provider_kind": "aws",
            "provider_account_ref": account_ref,
            "display_name": format!("AWS EC2 · {instance_type} ({region})"),
            "resource_classes": ["compute.vm", "compute.gpu_runtime"],
            "runtime_class": "compute.vm",
            "instance_type": instance_type,
            "region": region,
            "az": offer.get("az").cloned().unwrap_or(Value::Null),
            "vcpu": offer.get("vcpu").cloned().unwrap_or(Value::Null),
            "memory_gb": offer.get("memory_gb").cloned().unwrap_or(Value::Null),
            "gpu": gpu,
            "quote": quote,
            "quote_ref": format!("provider-quote://{id}"),
            "quote_state": "quoted_from_rate_card",
            "spend_estimate": spend_estimate,
            "custody_plan": custody_plan,
            "failover_plan": failover_plan,
            "reliability": { "basis": "rate-card quote — per-instance reliability evidence lands with the running instance" },
            "network": {
                "vpc_posture": network.get("vpc_posture").cloned().unwrap_or(json!("default_vpc")),
                "public_ip_supported": public_ip,
                "ports_posture": "SSH requires a security-group ingress rule + reachable IP — private-only postures fail closed, never fake-ready",
            },
            "storage": { "disk_gb": root.get("gb").cloned().unwrap_or(Value::Null),
                         "volume_type": root.get("type").cloned().unwrap_or(Value::Null),
                         "posture": "EBS root volume (deleted on termination unless configured otherwise) — native volume/snapshot ids are evidence only, never restore truth" },
            "observed_at": observed_at,
            "expires_at": expires_at,
            "expires_epoch": expires_epoch,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "placement_eligible": placement_eligible,
            "lifecycle": if simulator { "guarded_lifecycle_simulator (EC2 control plane simulated; ssh/custody lane real)" }
                else if live { "guarded_lifecycle (quote-gated, receipted; SigV4 EC2 API flow lands with the live harness)" }
                else { "quote_preflight_only" },
            "execution_blocked_reason": blocked_reason,
            "coverage_state": coverage,
            "evidence_mode": mode,
            "evidence": evidence,
            "authority": "none — a candidate cannot provision, release credentials, expose ingress, or claim custody/restore truth",
        }))
    }).collect()
}
