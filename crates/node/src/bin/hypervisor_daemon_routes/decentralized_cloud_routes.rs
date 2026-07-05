//! decentralized.cloud CANDIDATE PLANE — first cut.
//!
//! The daemon-owned resource-intelligence projection that fills the "Let Hypervisor choose"
//! advisory path with REAL candidates. Candidate/proposal ONLY (canon:
//! docs/architecture/domains/decentralized/cloud.md):
//!
//!   decentralized.cloud proposes resource candidates.
//!   wallet.network authorizes spend, provider credentials, grants, and revocation.
//!   Hypervisor provisions, executes, snapshots, restores, supervises, and tears down.
//!
//! This cut derives candidates from LOCAL FACTS ONLY: the verified ProviderAccount catalog,
//! environment-class provider eligibility, static adapter capabilities, preflight posture, and
//! provider receipt history. External sources (decentralized.cloud network, DePIN markets,
//! storage networks, managed capacity) return `candidate_source_unavailable` WITH EVIDENCE —
//! never fake prices. Candidates are NOT authority: they cannot provision, release credentials,
//! expose ingress, or claim custody/restore truth; they expire; stale/expired/evidence-less
//! candidates are not placement-eligible. No fee objects, no invented quotes, no
//! RoutingDecisionReceipt.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, DaemonState};

const INTENT_KIND: &str = "cloud-resource-intents";
const CANDIDATE_KIND: &str = "cloud-resource-candidates";
const ADVISORY_KIND: &str = "placement-advisories";
const DEFAULT_TTL_SECS: u64 = 900;

/// Bounded first resource classes (canon cloud.md "Resource Classes" — start bounded).
const RESOURCE_CLASSES: &[&str] = &[
    "compute.vm", "compute.microvm", "compute.container", "compute.gpu_runtime",
    "storage.object", "storage.block", "storage.archive", "storage.cas",
    "network.ip_lease", "network.ingress",
    "runtime.model_server", "runtime.browser", "runtime.workbench",
    "security.tee", "security.ctee",
];
const CUSTODY_POSTURES: &[&str] = &["Standard", "Private"];

fn nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}
fn epoch_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn load_intent(data_dir: &str, id_or_ref: &str) -> Option<Value> {
    let id = id_or_ref.trim_start_matches("cloud-resource-intent://");
    read_record_dir(data_dir, INTENT_KIND)
        .into_iter()
        .find(|r| text(r, "intent_id") == id)
}

/// The standing DEFAULT intent behind venue-policy/UI advisory calls — an ordinary durable
/// intent (workbench runtime, Standard custody, no GPU), created once, visible like any other.
pub(crate) fn ensure_default_intent(data_dir: &str) -> Value {
    if let Some(existing) = load_intent(data_dir, "cri_default") {
        return existing;
    }
    let record = intent_record("cri_default", &json!({
        "requester_ref": "principal://local-operator",
        "user_placement_choice": "let_hypervisor_choose",
        "runtime_class": "runtime.workbench",
        "resource_classes": ["runtime.workbench"],
        "custody_posture": "Standard",
        "note": "standing default intent for the Let-Hypervisor-choose advisory lane",
    }));
    let _ = persist_record(data_dir, INTENT_KIND, "cri_default", &record);
    record
}

fn intent_record(id: &str, body: &Value) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.cloud-resource-intent.v1",
        "intent_id": id,
        "intent_ref": format!("cloud-resource-intent://{id}"),
        "requester_ref": body.get("requester_ref").cloned().unwrap_or(json!("principal://local-operator")),
        "user_placement_choice": body.get("user_placement_choice").cloned().unwrap_or(json!("let_hypervisor_choose")),
        "placement_source": body.get("placement_source").cloned().unwrap_or(json!("optimized")),
        "selection_mode": body.get("selection_mode").cloned().unwrap_or(json!("auto")),
        "runtime_class": body.get("runtime_class").cloned().unwrap_or(json!("runtime.workbench")),
        "resource_classes": body.get("resource_classes").cloned().unwrap_or(json!(["runtime.workbench"])),
        "compute": body.get("compute").cloned().unwrap_or(Value::Null),
        "gpu": body.get("gpu").cloned().unwrap_or(Value::Null),
        "storage": body.get("storage").cloned().unwrap_or(json!([])),
        "network": body.get("network").cloned().unwrap_or(json!([])),
        "custody_posture": body.get("custody_posture").cloned().unwrap_or(json!("Standard")),
        "privacy_requirements": body.get("privacy_requirements").cloned().unwrap_or(json!([])),
        "region_preferences": body.get("region_preferences").cloned().unwrap_or(json!([])),
        "budget_policy_ref": body.get("budget_policy_ref").cloned().unwrap_or(Value::Null),
        "failover_policy_ref": body.get("failover_policy_ref").cloned().unwrap_or(Value::Null),
        "support_boundary": body.get("support_boundary").cloned().unwrap_or(json!("hypervisor_supported: local + verified BYO SSH; cloud kinds credential/preflight only")),
        "evidence_refs": body.get("evidence_refs").cloned().unwrap_or(json!([])),
        "note": body.get("note").cloned().unwrap_or(Value::Null),
        "authority": "none — an intent describes requested capacity; it is not authority",
        "created_at": iso_now(),
    })
}

// ================================= candidate derivation ========================================

/// Per-account reliability evidence from the REAL provider receipt history (local fact).
fn receipt_history(data_dir: &str, account_ref: &str) -> Value {
    let receipts = read_record_dir(data_dir, "provider-receipts");
    let mine: Vec<&Value> = receipts.iter().filter(|r| text(r, "account_ref") == account_ref).collect();
    let ok = mine.iter().filter(|r| text(r, "outcome") == "ok").count();
    let failed = mine.len() - ok;
    let last_at = mine.iter().map(|r| text(r, "at")).max().unwrap_or("");
    json!({
        "ops_ok": ok, "ops_failed": failed,
        "last_at": if last_at.is_empty() { Value::Null } else { json!(last_at) },
        "basis": "provider receipt history (daemon truth)",
    })
}

/// CandidateEvidence — canon-required binding: a candidate without source, adapter, observed
/// timestamp, expiry, coverage state, and evidence refs is not placement-eligible.
#[allow(clippy::too_many_arguments)]
fn candidate_evidence(
    id: &str, source: &str, adapter_ref: &str, observed_at: &str, expires_at: &str,
    coverage: &str, claims: Vec<Value>, risk: &[&str], eligibility: &[&str], refs: Vec<Value>,
) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.candidate-evidence.v1",
        "evidence_ref": format!("candidate-evidence://{id}"),
        "source": source,
        "adapter_ref": adapter_ref,
        "observed_at": observed_at,
        "expires_at": expires_at,
        "coverage_state": coverage,
        "claims": claims,
        "risk_labels": risk,
        "eligibility_labels": eligibility,
        "evidence_refs": refs,
    })
}

/// Derive the candidate set for an intent from LOCAL FACTS ONLY. Returns (candidates, rejected)
/// — rejections carry named reasons + evidence (canon required failure behavior).
fn derive_candidates(
    data_dir: &str,
    intent: &Value,
    classes: &[Value],
    ttl_secs: u64,
    batch: &str,
    vast_outcome: &Value,
    runpod_outcome: &Value,
    lambda_outcome: &Value,
    akash_outcome: &Value,
) -> (Vec<Value>, Vec<Value>) {
    let observed_at = iso_now();
    let expires_epoch = epoch_secs() + ttl_secs;
    let expires_at = chrono_like(expires_epoch);
    let wants_gpu = intent.get("gpu").map(|g| !g.is_null()).unwrap_or(false);
    let wants_private = text(intent, "custody_posture") == "Private";
    let intent_ref = text(intent, "intent_ref").to_string();
    let class_enabled = |id: &str| classes.iter().any(|c| c.get("id").and_then(Value::as_str) == Some(id) && c.get("enabled").and_then(Value::as_bool) == Some(true));

    let mut candidates: Vec<Value> = Vec::new();
    let mut rejected: Vec<Value> = Vec::new();
    let mut push_candidate = |idx: usize, source: &str, adapter_ref: &str, provider_kind: &str,
                              account: Option<&Value>, resource_classes: Vec<&str>, runtime_class: &str,
                              custody_supported: Vec<&str>, coverage: &str, placement_eligible: bool,
                              eligibility: Vec<&str>, risk: Vec<&str>, claims: Vec<Value>,
                              extra_refs: Vec<Value>, spend_state: &str, spend_detail: &str,
                              custody_detail: &str, failover_detail: &str, reliability: Value| {
        let id = format!("crc_{:x}_{idx}", nanos());
        let account_ref = account.map(|a| text(a, "account_ref").to_string());
        let evidence = candidate_evidence(
            &id, source, adapter_ref, &observed_at, &expires_at, coverage,
            claims, &risk, &eligibility, extra_refs,
        );
        candidates.push(json!({
            "schema_version": "ioi.hypervisor.cloud-resource-candidate.v1",
            "candidate_id": id,
            "candidate_ref": format!("cloud-resource-candidate://{id}"),
            "intent_ref": intent_ref,
            "batch": batch,
            "source": source,
            "adapter_ref": adapter_ref,
            "provider_kind": provider_kind,
            "provider_account_ref": account_ref,
            "display_name": account.map(|a| text(a, "display_name").to_string()).unwrap_or_else(|| "Local host".into()),
            "resource_classes": resource_classes,
            "runtime_class": runtime_class,
            // ProviderQuote: NONE exists without a live adapter — never an invented price.
            "quote_ref": Value::Null,
            "quote_state": "no_quote — no live pricing adapter for this source; quotes land with each adapter as provider evidence",
            "spend_estimate": {
                "schema_version": "ioi.hypervisor.spend-estimate.v1",
                "spend_estimate_ref": format!("spend-estimate://{id}"),
                "state": spend_state,
                "detail": spend_detail,
                "cost_owner": "customer",
                "routing_fee_eligibility": "eligible_future — only when optimized placement compares multiple real candidates; no fee exists today",
                "authority": "estimate, not spend authority",
            },
            "custody_plan": {
                "schema_version": "ioi.hypervisor.custody-plan.v1",
                "custody_plan_ref": format!("custody-plan://{id}"),
                "supported_postures": custody_supported,
                "detail": custody_detail,
                "rule": "storage availability does not equal restore validity — daemon-admitted sha256 state roots are restore truth",
            },
            "failover_plan": {
                "schema_version": "ioi.hypervisor.failover-plan.v1",
                "failover_plan_ref": format!("failover-plan://{id}"),
                "detail": failover_detail,
                "authority_note": "failover requires the same wallet grants as any placement — a plan is not authority",
            },
            "reliability": reliability,
            "observed_at": observed_at,
            "expires_at": expires_at,
            "expires_epoch": expires_epoch,
            "risk_labels": risk,
            "eligibility_labels": eligibility,
            "placement_eligible": placement_eligible,
            "coverage_state": coverage,
            "evidence": evidence,
            "authority": "none — a candidate cannot provision, release credentials, expose ingress, or claim custody/restore truth",
        }));
    };

    // ── customer_inventory: the local host (always a real fact; the conformance reference) ──
    if wants_gpu {
        rejected.push(json!({ "source": "customer_inventory", "adapter_ref": "adapter:local-workspace",
            "reason_code": "gpu_requirement_unproven", "detail": "local host GPU capability is host-dependent and not probed — cannot satisfy a GPU requirement without evidence",
            "evidence_refs": ["environment-class://local-workspace-v0"] }));
    } else {
        let mut rc = vec!["runtime.workbench"];
        if class_enabled("microvm") { rc.push("compute.microvm"); }
        push_candidate(0, "customer_inventory", "adapter:local-workspace", "local", None,
            rc, "runtime.workbench",
            vec!["Standard", "Private"], "operational",
            true, vec!["placement_eligible", "conformance_reference"], vec![],
            vec![json!("local daemon host — session/microVM lifecycle + WS-8 snapshots are operational")],
            vec![json!("environment-class://local-workspace-v0")],
            "local_free", "no metered provider spend — your machine",
            "customer-controlled local custody; daemon snapshots with admitted sha256 state roots (real)",
            "n/a — local is itself the fallback venue", json!({ "basis": "conformance reference" }));
    }

    // ── customer_inventory: verified baremetal_ssh accounts (full lifecycle, real evidence) ──
    let accounts = read_record_dir(data_dir, "provider-accounts");
    for (i, account) in accounts.iter().enumerate() {
        let kind = text(account, "kind");
        let account_ref = text(account, "account_ref");
        if kind == "baremetal_ssh" {
            if text(account, "status") != "verified" {
                rejected.push(json!({ "source": "customer_inventory", "adapter_ref": "adapter:baremetal-ssh",
                    "provider_account_ref": account_ref, "reason_code": "provider_account_unverified",
                    "detail": format!("'{}' has not passed preflight — bind a credential and preflight it", text(account, "display_name")),
                    "evidence_refs": [account_ref] }));
                continue;
            }
            if wants_gpu {
                rejected.push(json!({ "source": "customer_inventory", "adapter_ref": "adapter:baremetal-ssh",
                    "provider_account_ref": account_ref, "reason_code": "gpu_requirement_unproven",
                    "detail": "node GPU capability is host-dependent and not probed by preflight yet",
                    "evidence_refs": [account_ref] }));
                continue;
            }
            let reliability = receipt_history(data_dir, account_ref);
            let failed = reliability["ops_failed"].as_u64().unwrap_or(0);
            let risk: Vec<&str> = if failed > 0 { vec!["prior_failed_operations"] } else { vec![] };
            let preflight_at = account.pointer("/preflight/at").and_then(Value::as_str).unwrap_or("");
            push_candidate(i + 1, "customer_inventory", "adapter:baremetal-ssh", "baremetal_ssh", Some(account),
                vec!["compute.vm", "runtime.workbench"], "runtime.workbench",
                vec!["Standard", "Private"], "operational",
                true, vec!["placement_eligible", "full_lifecycle"], risk,
                vec![json!(format!("preflight admitted {preflight_at} (real ssh probe)")),
                     json!("full provider lifecycle over the baremetal_ssh adapter (provider-ops lane)")],
                vec![json!(account_ref), json!(account.pointer("/preflight").cloned().unwrap_or(Value::Null))],
                "local_free", "customer-borne node — no metered provider spend, no provider-spend percentage",
                "customer-controlled node; snapshots stream to DAEMON custody with admitted sha256 state roots (real)",
                "recover from daemon-admitted restore material; fallback venue run_local",
                reliability);
        } else {
            // A vast account with an engaged quote source is represented by its OFFER candidates
            // (normalized below) — skip the generic provider-capable stub for that account.
            let quote_engaged = (kind == "vast"
                && vast_outcome.get("engaged").and_then(Value::as_bool) == Some(true)
                && vast_outcome["account_ref"] == account["account_ref"])
                || (kind == "runpod"
                && runpod_outcome.get("engaged").and_then(Value::as_bool) == Some(true)
                && runpod_outcome["account_ref"] == account["account_ref"])
                || (kind == "lambda_cloud"
                && lambda_outcome.get("engaged").and_then(Value::as_bool) == Some(true)
                && lambda_outcome["account_ref"] == account["account_ref"])
                || (kind == "akash"
                && akash_outcome.get("engaged").and_then(Value::as_bool) == Some(true)
                && akash_outcome["account_ref"] == account["account_ref"]);
            if quote_engaged {
                if wants_private {
                    rejected.push(json!({ "source": "depin_market", "adapter_ref": "adapter:vast-quote",
                        "provider_account_ref": account_ref, "reason_code": "custody_posture_unsupported",
                        "detail": "GPU marketplace/runtime hosts never claim Private custody without custody proof",
                        "evidence_refs": [account_ref] }));
                }
                continue;
            }
            // ── direct_provider: cloud-kind accounts — provider-capable, NOT placement-eligible ──
            if wants_private {
                rejected.push(json!({ "source": "direct_provider", "adapter_ref": format!("adapter:{kind}(absent)"),
                    "provider_account_ref": account_ref, "reason_code": "custody_posture_unsupported",
                    "detail": format!("'{kind}' cannot claim Private custody without matching custody receipts (canon anti-pattern 7)"),
                    "evidence_refs": [account_ref] }));
                continue;
            }
            let verified = text(account, "status") == "verified";
            let eligibility: Vec<&str> = if verified {
                vec!["provider_capable", "credential_preflight_only", "lifecycle_adapter_absent"]
            } else {
                vec!["provider_capable", "credential_unverified", "lifecycle_adapter_absent"]
            };
            push_candidate(i + 1, "direct_provider", &format!("adapter:{kind}(absent)"), kind, Some(account),
                vec!["compute.vm"], "runtime.workbench",
                vec!["Standard"], if verified { "credential_preflight_only" } else { "unverified" },
                false, eligibility, vec!["no_lifecycle_adapter"],
                vec![json!("credential + preflight are real; lifecycle ops fail closed with PROVIDER_KIND_LIFECYCLE_NOT_IMPLEMENTED until this kind's adapter cut")],
                vec![json!(account_ref)],
                "unavailable_no_adapter", "no adapter — no spend estimate is invented; provider spend would be customer-borne on your own account",
                "cloud shared-responsibility custody; Private never claimed without custody receipts",
                "no failover plan without a live adapter",
                receipt_history(data_dir, account_ref));
        }
    }
    // ── storage backends: ARCHIVE/CAS byte-custody candidates from LOCAL FACTS (verified
    // StorageBackendAccounts). Byte availability only — never authority, never restore truth;
    // shown alongside compute options when the intent asks for storage.archive / storage.cas. ──
    let wants_storage = intent.get("resource_classes").and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).any(|c| matches!(c, "storage.archive" | "storage.cas" | "storage.object")))
        .unwrap_or(false);
    if wants_storage {
        for (i, fact) in super::storage_backend_routes::backend_facts(data_dir).iter().enumerate() {
            let account = fact["account"].clone();
            let kind = text(&account, "kind").to_string();
            let account_ref = text(&account, "account_ref").to_string();
            if text(&account, "status") != "verified" {
                rejected.push(json!({ "source": "storage_network", "adapter_ref": "adapter:storage-backend",
                    "provider_account_ref": account_ref, "reason_code": "storage_backend_unverified",
                    "detail": format!("'{}' has not passed preflight — probe the backend before it can hold archive bytes", text(&account, "display_name")),
                    "evidence_refs": [account_ref] }));
                continue;
            }
            let mode = account.pointer("/preflight/evidence/mode").and_then(Value::as_str).unwrap_or("real_local").to_string();
            let fixture = mode == "fixture_evidence";
            let network_kind = matches!(kind.as_str(), "ipfs" | "filecoin");
            let objects = fact["objects"].as_u64().unwrap_or(0);
            let open_incidents = fact["open_incidents"].as_u64().unwrap_or(0);
            let source = if network_kind { "storage_network" } else { "customer_inventory" };
            let mut risk: Vec<&str> = vec![];
            if network_kind { risk.push("public_network_availability_sealed_bytes_only"); }
            if fixture { risk.push("fixture_evidence_not_network_availability"); }
            if open_incidents > 0 { risk.push("open_availability_incidents"); }
            let eligibility: Vec<&str> = if fixture {
                vec!["advisory_only", "fixture_local_cas", "archive_export_available"]
            } else {
                vec!["placement_eligible", "archive_export_available", "custody_probe_verified"]
            };
            let custody_detail = format!(
                "{} — sealed_wallet_secret encryption before every write; provider-native addresses (CID/path/deal) are availability evidence only",
                account.pointer("/capabilities/custody_posture").and_then(Value::as_str).unwrap_or("byte store")
            );
            push_candidate(700 + i, source, "adapter:storage-backend", &kind, Some(&account),
                vec!["storage.archive", "storage.cas"], "storage.archive",
                if kind == "local_disk" { vec!["Standard", "Private"] } else { vec!["Standard"] },
                if fixture { "fixture_evidence" } else { "operational" },
                !fixture, eligibility, risk,
                vec![
                    json!(format!("verified {kind} byte store — {objects} archived object(s), {open_incidents} open incident(s) (daemon records)")),
                    json!("storage availability is NOT restore truth — restore admits only after fetch + commitment hash + decrypt + admitted state_root all verify"),
                ],
                vec![json!(account.get("preflight").cloned().unwrap_or(Value::Null))],
                if network_kind { "unpriced" } else { "local_free" },
                if network_kind { "no cost card fetched — storage cost/retention posture unknown; never invented (deal/pin pricing lands with live evidence)" } else { "no metered spend — local byte store" },
                &custody_detail,
                "replicate the sealed archive to another verified backend; a replacement commitment repairs meaning ONLY via an ArtifactRepairReceipt bound to the same state_root",
                json!({ "objects": objects, "open_incidents": open_incidents, "basis": "daemon archive/incident records — backend self-reports are evidence, not health truth" }));
        }
    }
    // ── depin_market: real Akash BID advisories (deployment/lease semantics preserved). ──
    if akash_outcome.get("engaged").and_then(Value::as_bool) == Some(true) && !wants_private {
        if text(akash_outcome, "state") == "degraded_unreachable" {
            rejected.push(json!({ "source": "depin_market", "adapter_ref": "adapter:akash-bid",
                "provider_account_ref": akash_outcome["account_ref"],
                "reason_code": "candidate_source_degraded",
                "detail": "akash bid fetch failed — no fake bids on failure",
                "evidence_refs": [akash_outcome["evidence"].clone()] }));
        } else {
            candidates.extend(super::akash_candidate_source::normalize_offers(
                akash_outcome, &intent_ref, batch, &observed_at, &expires_at, expires_epoch,
            ));
        }
    }
    // ── direct_provider: real Lambda GPU VM quotes (instance-type rate cards; VM semantics). ──
    if lambda_outcome.get("engaged").and_then(Value::as_bool) == Some(true) && !wants_private {
        if text(lambda_outcome, "state") == "degraded_unreachable" {
            rejected.push(json!({ "source": "direct_provider", "adapter_ref": "adapter:lambda-quote",
                "provider_account_ref": lambda_outcome["account_ref"],
                "reason_code": "candidate_source_degraded",
                "detail": "lambda instance-type fetch failed — no fake quotes on failure",
                "evidence_refs": [lambda_outcome["evidence"].clone()] }));
        } else {
            candidates.extend(super::lambda_candidate_source::normalize_offers(
                lambda_outcome, &intent_ref, batch, &observed_at, &expires_at, expires_epoch,
            ));
        }
    }
    // ── direct_provider: real RunPod GPU-type quotes (rate cards; secure/community pricing). ──
    if runpod_outcome.get("engaged").and_then(Value::as_bool) == Some(true) && !wants_private {
        if text(runpod_outcome, "state") == "degraded_unreachable" {
            rejected.push(json!({ "source": "direct_provider", "adapter_ref": "adapter:runpod-quote",
                "provider_account_ref": runpod_outcome["account_ref"],
                "reason_code": "candidate_source_degraded",
                "detail": "runpod GPU-type fetch failed — no fake quotes on failure",
                "evidence_refs": [runpod_outcome["evidence"].clone()] }));
        } else {
            candidates.extend(super::runpod_candidate_source::normalize_offers(
                runpod_outcome, &intent_ref, batch, &observed_at, &expires_at, expires_epoch,
            ));
        }
    }
    // ── depin_market: real Vast offers (quote-only, advisory supply — never recommendable). ──
    if vast_outcome.get("engaged").and_then(Value::as_bool) == Some(true) && !wants_private {
        if text(vast_outcome, "state") == "degraded_unreachable" {
            rejected.push(json!({ "source": "depin_market", "adapter_ref": "adapter:vast-quote",
                "provider_account_ref": vast_outcome["account_ref"],
                "reason_code": "candidate_source_degraded",
                "detail": "vast offer fetch failed — no fake quotes on failure",
                "evidence_refs": [vast_outcome["evidence"].clone()] }));
        } else {
            candidates.extend(super::vast_candidate_source::normalize_offers(
                vast_outcome, &intent_ref, batch, &observed_at, &expires_at, expires_epoch,
            ));
        }
    }
    (candidates, rejected)
}

/// ISO-8601 from epoch seconds without pulling a date dependency (UTC, whole seconds).
fn chrono_like(epoch: u64) -> String {
    // Days-from-civil algorithm (Howard Hinnant) — exact for the UTC range we care about.
    let days = epoch / 86400;
    let secs = epoch % 86400;
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Read-time candidate status: active | expired (+ superseded batches marked by refresh).
fn with_read_status(mut c: Value) -> Value {
    let expired = c.get("expires_epoch").and_then(Value::as_u64).map(|e| epoch_secs() > e).unwrap_or(true);
    if expired {
        c["status"] = json!("expired");
        c["placement_eligible"] = json!(false);
        let mut labels: Vec<Value> = c.get("eligibility_labels").and_then(Value::as_array).cloned().unwrap_or_default();
        labels.retain(|l| l.as_str() != Some("placement_eligible"));
        labels.push(json!("expired_requires_requote"));
        c["eligibility_labels"] = json!(labels);
    } else if c.get("status").is_none() {
        c["status"] = json!("active");
    }
    c
}

fn candidates_for(data_dir: &str, intent_ref: &str) -> Vec<Value> {
    read_record_dir(data_dir, CANDIDATE_KIND)
        .into_iter()
        .filter(|c| text(c, "intent_ref") == intent_ref)
        .map(with_read_status)
        .collect()
}

async fn live_classes(base: &str) -> Vec<Value> {
    super::orchestration_routes::live_environment_classes(base).await
}

/// Derive + persist a fresh batch for an intent; supersede the prior batch (kept as evidence).
async fn refresh_candidates(st: &Arc<DaemonState>, intent: &Value, ttl_secs: u64) -> (Vec<Value>, Vec<Value>) {
    let classes = live_classes(&st.base_url).await;
    let batch = format!("batch_{:x}", nanos());
    let intent_ref = text(intent, "intent_ref");
    // Supersede prior batch records (they remain on disk as evidence, no longer eligible).
    for mut old in read_record_dir(&st.data_dir, CANDIDATE_KIND) {
        if text(&old, "intent_ref") == intent_ref && old.get("status").and_then(Value::as_str) != Some("superseded") {
            let id = text(&old, "candidate_id").to_string();
            old["status"] = json!("superseded");
            old["placement_eligible"] = json!(false);
            let _ = persist_record(&st.data_dir, CANDIDATE_KIND, &id, &old);
        }
    }
    let vast_outcome = super::vast_candidate_source::fetch_offers(st).await;
    let runpod_outcome = super::runpod_candidate_source::fetch_offers(st).await;
    let lambda_outcome = super::lambda_candidate_source::fetch_offers(st).await;
    let akash_outcome = super::akash_candidate_source::fetch_offers(st).await;
    let (candidates, rejected) = derive_candidates(&st.data_dir, intent, &classes, ttl_secs, &batch, &vast_outcome, &runpod_outcome, &lambda_outcome, &akash_outcome);
    for c in &candidates {
        let _ = persist_record(&st.data_dir, CANDIDATE_KIND, text(c, "candidate_id"), c);
    }
    (candidates, rejected)
}

// ===================================== endpoints ================================================

/// POST /v1/hypervisor/cloud-candidates/intents — create a CloudResourceIntent (not authority)
/// and derive its first candidate batch from local facts.
pub(crate) async fn handle_intent_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Some(classes) = body.get("resource_classes").and_then(Value::as_array) {
        for c in classes {
            if !RESOURCE_CLASSES.contains(&c.as_str().unwrap_or("")) {
                return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "ok": false, "error": {
                    "code": "resource_class_unknown",
                    "message": format!("'{}' is not a bounded first resource class — allowed: {RESOURCE_CLASSES:?}", c.as_str().unwrap_or("?")) } })));
            }
        }
    }
    if let Some(p) = body.get("custody_posture").and_then(Value::as_str) {
        if !CUSTODY_POSTURES.contains(&p) {
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "ok": false, "error": {
                "code": "custody_posture_invalid", "message": "custody_posture must be Standard | Private" } })));
        }
    }
    let id = format!("cri_{:x}", nanos());
    let record = intent_record(&id, &body);
    let _ = persist_record(&st.data_dir, INTENT_KIND, &id, &record);
    let ttl = body.get("ttl_seconds").and_then(Value::as_u64).unwrap_or(DEFAULT_TTL_SECS).clamp(5, 3600);
    let (candidates, rejected) = refresh_candidates(&st, &record, ttl).await;
    (StatusCode::CREATED, Json(json!({ "ok": true, "intent": record,
        "candidates": candidates, "rejected": rejected,
        "candidate_rule": "candidates are proposals with evidence and expiry — never authority" })))
}

/// GET /v1/hypervisor/cloud-candidates/intents/:id
pub(crate) async fn handle_intent_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_intent(&st.data_dir, &id) {
        Some(intent) => (StatusCode::OK, Json(json!({ "ok": true, "intent": intent }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "error": { "code": "cloud_resource_intent_not_found" } }))),
    }
}

/// GET /v1/hypervisor/cloud-candidates/candidates?intent_ref=…
pub(crate) async fn handle_candidates_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let Some(intent_ref) = q.get("intent_ref") else {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "ok": false, "error": { "code": "intent_ref_required" } })));
    };
    let Some(intent) = load_intent(&st.data_dir, intent_ref) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "error": { "code": "cloud_resource_intent_not_found" } })));
    };
    let candidates = candidates_for(&st.data_dir, text(&intent, "intent_ref"));
    (StatusCode::OK, Json(json!({
        "schema_version": "ioi.hypervisor.cloud-resource-candidates.v1",
        "intent_ref": intent["intent_ref"],
        "candidates": candidates,
        "candidate_rule": "candidates are proposals with evidence and expiry — never authority; expired/superseded candidates are not placement-eligible",
        "at": iso_now(),
    })))
}

/// POST /v1/hypervisor/cloud-candidates/candidates/refresh — { intent_ref, ttl_seconds? }.
/// Expired candidates require requote (canon) — refresh IS the requote from local facts.
pub(crate) async fn handle_candidates_refresh(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let intent_ref = text(&body, "intent_ref");
    let Some(intent) = load_intent(&st.data_dir, intent_ref) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "error": { "code": "cloud_resource_intent_not_found" } })));
    };
    let ttl = body.get("ttl_seconds").and_then(Value::as_u64).unwrap_or(DEFAULT_TTL_SECS).clamp(5, 3600);
    let (candidates, rejected) = refresh_candidates(&st, &intent, ttl).await;
    (StatusCode::OK, Json(json!({ "ok": true, "intent_ref": intent["intent_ref"],
        "candidates": candidates, "rejected": rejected, "ttl_seconds": ttl, "at": iso_now() })))
}

/// GET /v1/hypervisor/cloud-candidates/candidate-sources — the source registry with HONEST
/// coverage: local-fact sources are live; external sources are candidate_source_unavailable
/// WITH EVIDENCE (no adapter), never fake prices.
pub(crate) async fn handle_candidate_sources(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let accounts = read_record_dir(&st.data_dir, "provider-accounts");
    let ssh_verified = accounts.iter().filter(|a| a["kind"] == "baremetal_ssh" && a["status"] == "verified").count();
    let cloud_connected = accounts.iter().filter(|a| a["kind"] != "baremetal_ssh").count();
    Json(json!({
        "schema_version": "ioi.hypervisor.cloud-candidate-sources.v1",
        "sources": [
            { "source": "customer_inventory", "state": "available",
              "coverage": "local host + verified baremetal_ssh ProviderAccounts",
              "evidence": { "verified_ssh_accounts": ssh_verified, "basis": "provider-accounts records + preflight posture + receipt history" } },
            { "source": "direct_provider", "state": "credential_preflight_only",
              "coverage": "connected cloud-kind ProviderAccounts (aws/gcp/k8s/vast/akash) — provider-capable, no lifecycle adapter yet",
              "evidence": { "connected_cloud_accounts": cloud_connected, "basis": "provider-accounts records; lifecycle fails closed with named reasons" } },
            { "source": "managed_capacity", "state": "candidate_source_unavailable",
              "reason": "managed_capacity_not_offered — Hypervisor-managed execution (provider-of-record) does not exist yet; nothing honest to propose",
              "evidence": { "basis": "no managed capacity plane in the estate" } },
            { "source": "decentralized.cloud", "state": "candidate_source_unavailable",
              "reason": "network_adapter_absent — the decentralized.cloud network engine is not live; this daemon plane realizes its candidate semantics from local facts only",
              "evidence": { "basis": "no external candidate API is called; no invented prices" } },
            super::vast_candidate_source::source_state(&st.data_dir),
            super::runpod_candidate_source::source_state(&st.data_dir),
            super::lambda_candidate_source::source_state(&st.data_dir),
            super::akash_candidate_source::source_state(&st.data_dir),
            super::storage_backend_routes::source_state(&st.data_dir),
        ],
        "rule": "external providers without live adapters return candidate_source_unavailable with evidence — not fake prices",
        "at": iso_now(),
    }))
}

/// Deterministic, explained advisory over the ACTIVE eligible candidates — recommends among
/// run_local / verified BYO SSH / provider-capable venues. NOT smart routing: rank by
/// (full_lifecycle > conformance local) then stable by ref; every choice carries reason codes.
pub(crate) async fn advisory_for(st: &Arc<DaemonState>, intent: &Value, persist: bool) -> Value {
    let intent_ref = text(intent, "intent_ref").to_string();
    let mut candidates = candidates_for(&st.data_dir, &intent_ref);
    let active_exists = candidates.iter().any(|c| c["status"] == "active");
    // Stale coverage cannot advise silently (canon): requote when nothing is active OR when the
    // provider-account facts changed after the batch was observed (accounts added/verified/
    // revoked must reflect immediately in the advisory).
    let latest_observed = candidates.iter()
        .filter(|c| c["status"] == "active")
        .map(|c| text(c, "observed_at").to_string())
        .max()
        .unwrap_or_default();
    let facts_changed = read_record_dir(&st.data_dir, "provider-accounts")
        .iter()
        .any(|a| text(a, "updated_at") > latest_observed.as_str() || text(a, "created_at") > latest_observed.as_str());
    if !active_exists || facts_changed {
        let (fresh, _) = refresh_candidates(st, intent, DEFAULT_TTL_SECS).await;
        candidates = fresh.into_iter().map(with_read_status).collect();
    }
    let eligible: Vec<&Value> = candidates.iter()
        .filter(|c| c["placement_eligible"] == true && c["status"] == "active")
        .collect();
    let score = |c: &Value| -> i64 {
        let mut s = 0;
        if c.get("eligibility_labels").and_then(Value::as_array).map(|l| l.iter().any(|x| x == "full_lifecycle")).unwrap_or(false) { s += 20; }
        if c.get("eligibility_labels").and_then(Value::as_array).map(|l| l.iter().any(|x| x == "conformance_reference")).unwrap_or(false) { s += 10; }
        if c.get("reliability").and_then(|r| r.get("ops_failed")).and_then(Value::as_u64).unwrap_or(0) > 0 { s -= 5; }
        s
    };
    let mut ranked: Vec<&&Value> = eligible.iter().collect();
    ranked.sort_by(|a, b| score(b).cmp(&score(a)).then(text(a, "candidate_ref").cmp(text(b, "candidate_ref"))));
    let venue_of = |c: &Value| match text(c, "provider_kind") {
        "local" => "run_local",
        "baremetal_ssh" => "use_my_infrastructure",
        _ => "pick_provider",
    };
    let advisory_id = format!("adv_{:x}", nanos());
    let recommendation = ranked.first().map(|c| {
        // Reason codes derive from the winning candidate's LABELS, not the score value — a
        // reliability penalty must not relabel a full-lifecycle node as the local reference.
        let has = |label: &str| c.get("eligibility_labels").and_then(Value::as_array)
            .map(|l| l.iter().any(|x| x == label)).unwrap_or(false);
        let mut reasons: Vec<&str> = Vec::new();
        if has("full_lifecycle") {
            reasons.push("full_lifecycle_over_verified_byo_node");
        } else {
            reasons.push("local_conformance_reference");
        }
        if c.get("reliability").and_then(|r| r.get("ops_failed")).and_then(Value::as_u64).unwrap_or(0) > 0 {
            reasons.push("prior_failed_operations_noted");
        }
        if ranked.len() > 1 {
            reasons.push("ranked_deterministically_among_eligible_candidates");
        }
        json!({
            "venue": venue_of(c),
            "candidate_ref": c["candidate_ref"],
            "provider_account_ref": c["provider_account_ref"],
            "display_name": c["display_name"],
            "reason_codes": reasons,
        })
    });
    let advisory = json!({
        "schema_version": "ioi.hypervisor.placement-advisory.v1",
        "advisory_id": advisory_id,
        "advisory_ref": format!("placement-advisory://{advisory_id}"),
        "intent_ref": intent_ref,
        "considered": candidates.len(),
        "eligible": eligible.len(),
        "candidate_refs": eligible.iter().map(|c| c["candidate_ref"].clone()).collect::<Vec<_>>(),
        "candidates": candidates,
        "recommendation": recommendation.clone().unwrap_or(Value::Null),
        "no_eligible_candidate": if recommendation.is_none() {
            json!("no_eligible_candidate — no active placement-eligible candidate satisfies this intent; effective venue stays run_local")
        } else { Value::Null },
        "effective_venue": recommendation.as_ref().map(|r| r["venue"].clone()).unwrap_or(json!("run_local")),
        // Comparing MULTIPLE real candidates is where a routing fee would become legitimate —
        // declared eligibility only; the fee itself does not exist.
        "routing_fee_basis": if eligible.len() >= 2 { json!("eligible_future") } else { json!("not_applicable") },
        "fee_object_minted": false,
        "authority_note": "an advisory recommends; it cannot provision, spend, or release credentials — placement still requires wallet grants on the execution lane",
        "at": iso_now(),
    });
    if persist {
        let _ = persist_record(&st.data_dir, ADVISORY_KIND, &advisory_id, &advisory);
    }
    advisory
}

/// GET /v1/hypervisor/cloud-candidates/placement-advisory[?intent_ref=…] — intent_ref optional:
/// without it the standing default intent drives the venue-policy/UI lane.
pub(crate) async fn handle_placement_advisory(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let intent = match q.get("intent_ref") {
        Some(r) => match load_intent(&st.data_dir, r) {
            Some(i) => i,
            None => return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "error": { "code": "cloud_resource_intent_not_found" } }))),
        },
        None => ensure_default_intent(&st.data_dir),
    };
    let advisory = advisory_for(&st, &intent, true).await;
    (StatusCode::OK, Json(advisory))
}
