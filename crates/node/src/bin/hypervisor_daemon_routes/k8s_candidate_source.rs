//! Kubernetes/KubeVirt CLUSTER CANDIDATE SOURCE — the cluster substrate lane (canon priority
//! ladder #7). Clusters are treated as CLUSTERS, never flattened into fake single-VM SSH:
//! candidates are derived from CLUSTER FACTS (cluster/context, authorized namespaces, resource
//! quotas, GPU device-plugin posture, storage classes/PVC support, service/ingress posture,
//! KubeVirt availability) — one candidate per authorized namespace. Customer/operator-owned
//! clusters carry NO direct provider price (spend is customer/operator-borne); nothing is
//! invented.
//!
//! Same hard boundaries as every source: the sealed bearer/kubeconfig resolves only in-daemon;
//! no fake facts on failure (degraded WITH evidence); fixture/simulator unmistakably labelled
//! and never claimed as live cluster access; live claims only after a real API probe. Risk
//! labels are CLUSTER-shaped (quota_exhaustion, cluster_operator_controlled,
//! storage_not_restore_truth, ingress_policy_required). Pod/job/service/PVC/VM names and uids
//! are evidence only; daemon custody state roots remain restore truth.
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::lifecycle_routes::open_scm_token;
use super::{iso_now, persist_record, read_record_dir, DaemonState};

const HEALTH_KIND: &str = "k8s-source-health";

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
        .find(|a| a["kind"] == "k8s" && a["status"] == "verified")?;
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
    let k8s_accounts: Vec<&Value> = accounts.iter().filter(|a| a["kind"] == "k8s").collect();
    if k8s_accounts.is_empty() {
        return json!({ "source": "k8s", "state": "candidate_source_unavailable",
            "reason": "k8s_credential_absent — no k8s ProviderAccount exists; create one, bind a bearer token or kubeconfig, and preflight it",
            "evidence": { "k8s_accounts": 0, "basis": "provider-accounts records" } });
    }
    let Some((engaged, _)) = engaged_account(data_dir) else {
        return json!({ "source": "k8s", "state": "candidate_source_unavailable",
            "reason": "k8s_credential_absent — a k8s ProviderAccount exists but no verified account with a sealed bearer/kubeconfig credential",
            "evidence": { "k8s_accounts": k8s_accounts.len(),
                          "verified": k8s_accounts.iter().filter(|a| a["status"] == "verified").count(),
                          "basis": "provider-accounts + sealed-credential resolution (daemon-side only)" } });
    };
    match load_health(data_dir).filter(|h| h["account_ref"] == engaged["account_ref"]) {
        Some(h) => {
            let state = text(&h, "state").to_string();
            json!({ "source": "k8s", "state": state,
                "mode": h.get("mode").cloned().unwrap_or(Value::Null),
                "evidence": h.get("evidence").cloned().unwrap_or(Value::Null),
                "at": h.get("at").cloned().unwrap_or(Value::Null) })
        }
        None => json!({ "source": "k8s", "state": "credential_verified_unprobed",
            "reason": "credential verified — no cluster-facts probe has run yet (refresh candidates to probe)",
            "evidence": { "basis": "sealed bearer/kubeconfig resolvable; no probe attempted" } }),
    }
}

fn health_record(outcome: &Value) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.k8s-source-health.v1",
        "health_id": "current",
        "state": outcome["state"],
        "mode": outcome["mode"],
        "account_ref": outcome["account_ref"],
        "evidence": outcome["evidence"],
        "at": outcome["at"],
    })
}

/// Fetch the CLUSTER FACTS. fixture|simulator read a local facts file (unmistakably labelled —
/// never claimed as live cluster access); live probes the real API server with the sealed
/// bearer — failure degrades WITH evidence, never fake facts.
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
            ("simulator_evidence", "simulator_facts_source")
        } else {
            ("fixture_evidence", "fixture_facts_source")
        };
        let path = text(&ep, "fixture_file");
        let outcome = match std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|raw| serde_json::from_str::<Value>(&raw).map_err(|e| e.to_string()))
        {
            Ok(doc) => {
                json!({ "engaged": true, "mode": mode_label, "account_ref": account_ref,
                    "state": state_label, "facts": doc,
                    "evidence": { "mode": mode_label, "fixture_file": path,
                                  "namespaces_seen": doc.get("namespaces").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
                                  "warning": if simulator { "local lifecycle SIMULATOR — cluster control plane simulated, exec/custody lane real (local workload fs + real process exec); NOT live cluster access" } else { "deterministic local facts fixture — NOT live cluster access; validates normalization/admission invariants only" } },
                    "at": fetched_at })
            }
            Err(e) => json!({ "engaged": true, "mode": mode_label, "account_ref": account_ref,
                "state": "degraded_unreachable", "facts": Value::Null,
                "evidence": { "mode": mode_label, "fixture_file": path, "error": format!("facts fixture unreadable/unparseable: {e}") },
                "at": fetched_at }),
        };
        persist_health(&st.data_dir, &health_record(&outcome));
        return outcome;
    }
    if text(&ep, "mode") != "live" {
        return json!({ "engaged": false });
    }
    // ── live: a real API-server probe (GET /version with the sealed bearer). Cluster-facts
    // discovery (namespaces/quotas/classes) lands with the live harness; the probe is honest
    // reachability evidence, never fabricated facts. ──
    let base = text(&ep, "endpoint").trim_end_matches('/').to_string();
    if base.is_empty() {
        let outcome = json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
            "state": "degraded_unreachable", "facts": Value::Null,
            "evidence": { "mode": "live_evidence", "error": "k8s_live_config_absent — endpoint.endpoint (the API server base URL) is required for a live probe", "note": "no fake cluster facts on missing config" },
            "at": fetched_at });
        persist_health(&st.data_dir, &health_record(&outcome));
        return outcome;
    }
    let resp = reqwest::Client::builder()
        .danger_accept_invalid_certs(text(&ep, "ca_mode") == "insecure_dev")
        .build()
        .unwrap_or_default()
        .get(format!("{base}/version"))
        .bearer_auth(bearer.unwrap_or_default())
        .timeout(Duration::from_secs(10))
        .send()
        .await;
    let outcome = match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            match r.json::<Value>().await {
                Ok(doc) if (200..300).contains(&status) => {
                    json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                        "state": "degraded_unreachable", "facts": Value::Null,
                        "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status,
                                      "server_version": doc.get("gitVersion").cloned().unwrap_or(Value::Null),
                                      "note": "API server reachable — cluster-facts discovery (namespaces/quotas/classes) lands with the live harness; no candidates are invented from a bare version probe" },
                        "at": fetched_at })
                }
                Ok(doc) => {
                    json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                    "state": "degraded_unreachable", "facts": Value::Null,
                    "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status,
                                  "error": format!("API server rejected the probe (body keys: {:?})", doc.as_object().map(|o| o.keys().take(4).cloned().collect::<Vec<_>>()).unwrap_or_default()),
                                  "note": "no fake cluster facts on failure" },
                    "at": fetched_at })
                }
                Err(e) => {
                    json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
                    "state": "degraded_unreachable", "facts": Value::Null,
                    "evidence": { "mode": "live_evidence", "endpoint": base, "http_status": status, "error": format!("non-JSON response: {e}") },
                    "at": fetched_at })
                }
            }
        }
        Err(e) => json!({ "engaged": true, "mode": "live_evidence", "account_ref": account_ref,
            "state": "degraded_unreachable", "facts": Value::Null,
            "evidence": { "mode": "live_evidence", "endpoint": base, "error": format!("probe failed: {e}"), "note": "no fake cluster facts on failure" },
            "at": fetched_at }),
    };
    persist_health(&st.data_dir, &health_record(&outcome));
    outcome
}

/// Normalize CLUSTER FACTS into CloudResourceCandidates — one per AUTHORIZED namespace, with
/// cluster semantics preserved. Facts files use { cluster {name, context, version},
/// namespaces: [{name, authorized, quota {cpu_milli_available, memory_gb_available,
/// gpu_available}}], runtime_classes, gpu {device_plugin, nodes_with_gpu, models},
/// storage_classes: [{name, pvc_supported}], services {cluster_ip, load_balancer,
/// ingress_class}, kubevirt {installed, crd_version} }. Unauthorized namespaces are rejected
/// with named reasons, never silently skipped.
pub(crate) fn normalize_offers(
    outcome: &Value,
    intent_ref: &str,
    batch: &str,
    observed_at: &str,
    expires_at: &str,
    expires_epoch: u64,
) -> (Vec<Value>, Vec<Value>) {
    let mode = text(outcome, "mode");
    let account_ref = text(outcome, "account_ref");
    let fixture = mode == "fixture_evidence";
    let simulator = mode == "simulator_evidence";
    let facts = outcome.get("facts").cloned().unwrap_or(Value::Null);
    let mut rejected: Vec<Value> = Vec::new();
    if facts.is_null() {
        return (Vec::new(), rejected);
    }
    let cluster = facts.get("cluster").cloned().unwrap_or(json!({}));
    let gpu = facts.get("gpu").cloned().unwrap_or(json!({}));
    let storage_classes = facts
        .get("storage_classes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let services = facts.get("services").cloned().unwrap_or(json!({}));
    let kubevirt = facts.get("kubevirt").cloned().unwrap_or(json!({}));
    let kubevirt_installed = kubevirt
        .get("installed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let namespaces = facts
        .get("namespaces")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let candidates: Vec<Value> = namespaces.iter().enumerate().filter_map(|(i, ns)| {
        let name = text(ns, "name");
        if name.is_empty() { return None; }
        if ns.get("authorized").and_then(Value::as_bool) != Some(true) {
            rejected.push(json!({ "source": "k8s", "adapter_ref": "adapter:k8s-cluster-facts",
                "provider_account_ref": account_ref, "reason_code": "k8s_namespace_unauthorized",
                "detail": format!("namespace '{name}' is not authorized for this service account — RBAC posture, not an error to hide"),
                "evidence_refs": [json!(account_ref)] }));
            return None;
        }
        let id = format!("crc_{:x}_k{i}", nanos());
        let quota = ns.get("quota").cloned().unwrap_or(json!({}));
        let gpu_available = quota.get("gpu_available").and_then(Value::as_u64).unwrap_or(0);
        let mut risk: Vec<&str> = vec!["quota_exhaustion", "cluster_operator_controlled", "storage_not_restore_truth", "ingress_policy_required"];
        if fixture { risk.push("fixture_evidence_not_live_cluster"); }
        if simulator { risk.push("simulator_evidence_not_live_cluster"); }
        let coverage = if fixture { "fixture_facts" } else if simulator { "simulator_facts" } else { "live_facts" };
        let eligibility: Vec<&str> = if simulator {
            vec!["advisory_only", "simulated_control_plane", "lifecycle_harness_only"]
        } else {
            vec!["advisory_only", "facts_preflight_only"]
        };
        let claims = vec![
            json!(format!("cluster '{}' namespace '{name}': cpu {}m / mem {}GB / gpu {} available under quota — CLUSTER posture, never a fake single VM",
                text(&cluster, "name"),
                quota.get("cpu_milli_available").and_then(Value::as_u64).unwrap_or(0),
                quota.get("memory_gb_available").and_then(Value::as_u64).unwrap_or(0),
                gpu_available)),
            json!("customer/operator-owned cluster — no direct provider price; spend is customer/operator-borne (metered posture must be DECLARED to price anything)"),
        ];
        let custody_plan = json!({
            "schema_version": "ioi.hypervisor.custody-plan.v1",
            "custody_plan_ref": format!("custody-plan://{id}"),
            "supported_postures": ["Standard"],
            "privacy": "cluster_operator_controlled",
            "detail": "workload filesystem/PVC snapshots stream to DAEMON custody; PVC/VolumeSnapshot names are availability EVIDENCE only — daemon-admitted sha256 state roots remain restore truth",
            "rule": "storage availability does not equal restore validity — daemon-admitted sha256 state roots are restore truth",
        });
        let evidence = json!({
            "schema_version": "ioi.hypervisor.candidate-evidence.v1",
            "evidence_ref": format!("candidate-evidence://{id}"),
            "source": "k8s",
            "adapter_ref": "adapter:k8s-cluster-facts",
            "observed_at": observed_at,
            "expires_at": expires_at,
            "coverage_state": coverage,
            "claims": claims,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "evidence_refs": [json!(account_ref), json!(format!("k8s-namespace:{}/{name}", text(&cluster, "name")))],
            "evidence_mode": mode,
        });
        Some(json!({
            "schema_version": "ioi.hypervisor.cloud-resource-candidate.v1",
            "candidate_id": id,
            "candidate_ref": format!("cloud-resource-candidate://{id}"),
            "intent_ref": intent_ref,
            "batch": batch,
            "source": "k8s",
            "adapter_ref": "adapter:k8s-cluster-facts",
            "provider_kind": "k8s",
            "provider_account_ref": account_ref,
            "display_name": format!("K8s · {}/{name}", text(&cluster, "name")),
            "resource_classes": ["compute.container", "compute.gpu_runtime"],
            "runtime_class": "compute.container",
            "cluster": cluster,
            "namespace": name,
            "runtime_classes": facts.get("runtime_classes").cloned().unwrap_or(json!([])),
            "quota": quota,
            "gpu": { "device_plugin": gpu.get("device_plugin").cloned().unwrap_or(Value::Null),
                     "nodes_with_gpu": gpu.get("nodes_with_gpu").cloned().unwrap_or(json!(0)),
                     "models": gpu.get("models").cloned().unwrap_or(json!([])),
                     "namespace_gpu_available": gpu_available },
            "storage": { "storage_classes": storage_classes,
                         "posture": "PVCs per storage class — PVC persistence is CLUSTER posture, never restore truth" },
            "network": { "services": services,
                         "ports_posture": "service/ingress exposure is namespace + policy scoped — LoadBalancer/ingress must be supported by the cluster or requests fail closed" },
            "kubevirt": { "installed": kubevirt_installed, "crd_version": kubevirt.get("crd_version").cloned().unwrap_or(Value::Null),
                          "note": if kubevirt_installed { "KubeVirt VMs available — explicitly KubeVirt VMIs, never generic VMs" } else { "KubeVirt CRDs absent — VM workloads fail closed by name" } },
            // Customer/operator cluster: NO quote, NO invented price.
            "quote": Value::Null,
            "quote_ref": Value::Null,
            "quote_state": "unpriced — customer/operator-owned cluster; spend is customer/operator-borne (declare a metered posture to price)",
            "spend_estimate": {
                "schema_version": "ioi.hypervisor.spend-estimate.v1",
                "spend_estimate_ref": format!("spend-estimate://{id}"),
                "state": "customer_operator_borne",
                "basis": "no direct provider price on a customer/operator cluster — nothing is invented; a DECLARED metered posture with a sourced price is required to open exposures",
                "cost_owner": "customer",
                "routing_fee_eligibility": "eligible_future — only when optimized placement compares multiple real candidates; no fee exists today",
                "authority": "estimate, not spend authority",
            },
            "custody_plan": custody_plan,
            "failover_plan": {
                "schema_version": "ioi.hypervisor.failover-plan.v1",
                "failover_plan_ref": format!("failover-plan://{id}"),
                "detail": "re-admit the workload (same or another namespace/cluster) + restore from daemon/storage-archive custody after state_root validation; fallback venue run_local",
                "authority_note": "failover requires the same wallet grants as any placement — a plan is not authority",
            },
            "reliability": { "basis": "cluster facts — per-workload reliability evidence lands with the running workload" },
            "observed_at": observed_at,
            "expires_at": expires_at,
            "expires_epoch": expires_epoch,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "placement_eligible": json!("advisory_only"),
            "lifecycle": if simulator { "guarded_lifecycle_simulator (cluster control plane simulated; exec/custody lane real — local workload fs + real process exec)" }
                else { "facts_preflight_only" },
            "execution_blocked_reason": if simulator { json!("simulated_control_plane_not_live_cluster") } else { json!("fixture_facts_never_live_cluster") },
            "coverage_state": coverage,
            "evidence_mode": mode,
            "evidence": evidence,
            "authority": "none — a candidate cannot admit workloads, release credentials, expose ingress, or claim custody/restore truth",
        }))
    }).collect();
    (candidates, rejected)
}
