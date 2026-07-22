//! Model-route REGISTRY — daemon-owned truth for which model routes exist, their availability
//! posture, and their session bindings. The resource substrate the model selector / New Session /
//! Agent Studio consume ("the model selection center" — a registry, not a runtime).
//!
//! Doctrine enforced here:
//! - A route is `available` ONLY when a REAL probe succeeded (Ollama `/api/tags` containing the
//!   model tag, or an OpenAI-compatible `/models` catalog with a resolvable credential). Postures
//!   are explicit and honest: `declared` | `available` | `unreachable` | `credentials_missing` |
//!   `model_not_present`. No code path fabricates `available`.
//! - Effectful mutations (enable/disable/select-default/bind-session) COMPOSE the existing pure
//!   kernel planners (model-route-mutation + model-weight-custody admissions) — never a parallel
//!   validation path; planner rejections propagate as the HTTP error body.
//! - Records persist under `model-route-registry` (the pre-existing `model-routes` dir belongs to
//!   the model-mount family and is NOT touched). Every mutation writes a receipt; effectful ops
//!   also post an agent-run-transcript so they carry a state_root in Run Timeline / Work Ledger.
//! - Session-binding consumption (lifecycle_routes::handle_session_execute) stays byte-identical
//!   to the env-var path when no binding exists; only an `available` + `active` ollama-transport
//!   route may bind (the shim refuses other providers — no dropdown lies in either direction).
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use ioi_services::agentic::runtime::RuntimeOwnerServices;

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const ROUTE_SCHEMA: &str = "ioi.hypervisor.model-route.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.model-route-receipt.v1";
const BINDING_SCHEMA: &str = "ioi.hypervisor.model-route-session-binding.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.model-routes-overview.v1";
pub(crate) const RECORD_DIR: &str = "model-route-registry";
const RECEIPT_DIR: &str = "model-route-registry-receipts";
const BINDING_DIR: &str = "model-route-session-bindings";
const SEED_ROUTE_ID: &str = "mrt_local_default";
const PROBE_TIMEOUT_MS: u64 = 1500;
/// A persisted probe older than this is surfaced with `stale: true` in list projections.
const PROBE_FRESH_SECS: u64 = 120;

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}
fn opt_s(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
}

/// Strip a trailing `/v1` (the OpenAI-compat suffix) so the registry stores the provider ROOT;
/// probes derive `/api/tags` or `/models` and the execute hook re-appends `/v1` for the shim.
fn normalize_base_url(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
    trimmed
        .strip_suffix("/v1")
        .unwrap_or(trimmed)
        .trim_end_matches('/')
        .to_string()
}

pub(crate) fn load_route_record(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, RECORD_DIR)
        .into_iter()
        .find(|r| r.get("route_id").and_then(|v| v.as_str()) == Some(id))
}

fn route_receipt(
    data_dir: &str,
    route_ref: &str,
    op: &str,
    outcome: &str,
    admission_id: Option<&str>,
) -> String {
    let id = format!("mrr_{:x}", nanos());
    let receipt_ref = format!("agentgres://model-route-receipt/{id}");
    let _ = persist_record(
        data_dir,
        RECEIPT_DIR,
        &id,
        &json!({
            "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
            "route_ref": route_ref, "op": op, "outcome": outcome,
            "admission_id": admission_id, "at": iso_now()
        }),
    );
    receipt_ref
}

/// Post an agent-run-transcript for an effectful registry op so the transcript plane computes a
/// tamper-evident state_root and the op surfaces in Run Timeline / Work Ledger. Best-effort; the
/// outcome (`transcript_recorded`) is reported honestly on the response.
async fn post_op_transcript(
    base: &str,
    op: &str,
    route_ref: &str,
    detail: &Value,
) -> Option<String> {
    let run_id = format!("mro_{:x}", nanos());
    let at = iso_now();
    let transcript = json!({
        "schema_version": "ioi.hypervisor.agent-run-transcript.v1",
        "run_id": run_id,
        "kind": "model-route-op",
        "op": op,
        "route_ref": route_ref,
        "status": "done",
        "step_results": [ { "step": 0, "kind": op, "status": "done", "output": detail } ],
        "started_at": at,
        "finished_at": at,
    });
    let url = format!("{base}/v1/hypervisor/agent-run-transcripts/{run_id}");
    let ok = reqwest::Client::new()
        .post(&url)
        .json(&transcript)
        .timeout(Duration::from_millis(3000))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    ok.then_some(run_id)
}

// ---------------------------------------------------------------------------
// live model-mount catalog (ref validation against REAL substrate — no duplicate catalogs)
// ---------------------------------------------------------------------------

async fn get_json(base: &str, path: &str) -> Value {
    let url = format!("{base}{path}");
    match reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_millis(3000))
        .send()
        .await
    {
        Ok(r) => match r.text().await {
            Ok(t) => serde_json::from_str(&t).unwrap_or(Value::Null),
            Err(_) => Value::Null,
        },
        Err(_) => Value::Null,
    }
}

fn as_list(v: &Value) -> Vec<Value> {
    if let Some(a) = v.as_array() {
        return a.clone();
    }
    if let Some(obj) = v.as_object() {
        for val in obj.values() {
            if let Some(a) = val.as_array() {
                return a.clone();
            }
        }
    }
    Vec::new()
}

fn collect_ids(list: &[Value], keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for item in list {
        for k in keys {
            if let Some(v) = item.get(*k).and_then(|v| v.as_str()) {
                if !v.is_empty() && !out.iter().any(|x| x == v) {
                    out.push(v.to_string());
                }
            }
        }
    }
    out
}

/// Validate optional provider_ref / endpoint_ref against the LIVE model-mount substrate.
/// Fail-closed with a named code when a declared ref does not resolve.
async fn validate_substrate_refs(
    base: &str,
    provider_ref: Option<&str>,
    endpoint_ref: Option<&str>,
) -> Result<(), (String, String)> {
    if provider_ref.is_none() && endpoint_ref.is_none() {
        return Ok(());
    }
    let providers = collect_ids(
        &as_list(&get_json(base, "/v1/model-mount/providers").await),
        &["id", "provider_ref"],
    );
    let endpoints = collect_ids(
        &as_list(&get_json(base, "/v1/model-mount/endpoints").await),
        &["endpoint_id", "id"],
    );
    if let Some(p) = provider_ref {
        let bare = p.strip_prefix("provider:").unwrap_or(p);
        if !providers.iter().any(|x| x == p || x == bare) {
            return Err((
                "model_route_ref_unresolved".into(),
                format!("provider ref '{p}' does not resolve to real model-mount substrate"),
            ));
        }
    }
    if let Some(e) = endpoint_ref {
        let bare = e.strip_prefix("model-endpoint:").unwrap_or(e);
        if !endpoints.iter().any(|x| x == e || x == bare) {
            return Err((
                "model_route_ref_unresolved".into(),
                format!("endpoint ref '{e}' does not resolve to real model-mount substrate"),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// honest availability probe
// ---------------------------------------------------------------------------

/// A tag `qwen2.5-coder` and its `:latest` resolution are the SAME model to Ollama (native +
/// OpenAI-compat APIs both resolve the untagged name to `:latest`), while `/api/tags` only ever
/// returns fully-qualified names. Match on either form so an untagged declared model_id (including
/// the code-default seed `qwen2.5-coder`) is not falsely reported absent.
fn tag_matches(model_id: &str, tag: &str) -> bool {
    tag == model_id
        || tag == format!("{model_id}:latest")
        || (!model_id.contains(':') && tag.strip_suffix(":latest") == Some(model_id))
}

/// Decide availability from a fetched Ollama tag catalog. Pure — unit tested.
fn ollama_availability(model_id: &str, tags: &[String]) -> (&'static str, Value) {
    if tags.iter().any(|t| tag_matches(model_id, t)) {
        (
            "available",
            json!({ "matched_model": model_id, "catalog_count": tags.len() }),
        )
    } else {
        (
            "model_not_present",
            json!({ "requested_model": model_id, "catalog_count": tags.len() }),
        )
    }
}

/// Run the REAL availability probe for one route record. Never fabricates: connect failures and
/// non-2xx responses are `unreachable`, an unresolvable credential is `credentials_missing`
/// (no network call), a live catalog without the tag is `model_not_present`.
///
/// SECURITY: the probe NEVER resolves a daemon environment secret and sends it to the route's
/// caller-supplied `base_url` — that would turn the registry into a secret-exfiltration primitive
/// (any local caller could name IOI_WALLET_SECRET_PASS as env_key_name and point base_url at a
/// listener). `openai_compatible` routes therefore stay POSTURE-ONLY: `credentials_missing` when
/// the declared env key is absent, `credentials_present` when it resolves — never `available`, and
/// never an authenticated outbound request. Real authenticated catalog probing waits for a future
/// branch that binds the endpoint to admitted/trusted substrate (see overview governance_gaps).
async fn probe_route(route: &Value) -> Value {
    let transport = route
        .pointer("/provider_binding/transport")
        .and_then(|v| v.as_str())
        .unwrap_or("ollama");
    let base_url = route
        .pointer("/provider_binding/base_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim_end_matches('/')
        .to_string();
    let model_id = route
        .pointer("/model/model_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let checked_at = iso_now();
    let client = reqwest::Client::new();

    let (state, kind, evidence) = match transport {
        "ollama" => {
            let url = format!("{base_url}/api/tags");
            match client
                .get(&url)
                .timeout(Duration::from_millis(PROBE_TIMEOUT_MS))
                .send()
                .await
            {
                Ok(resp) if !resp.status().is_success() => (
                    "unreachable",
                    "ollama_tags",
                    json!({ "error": format!("upstream returned HTTP {}", resp.status().as_u16()) }),
                ),
                Ok(resp) => match resp.json::<Value>().await {
                    Ok(body) => {
                        let tags: Vec<String> = body
                            .get("models")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|m| {
                                        m.get("name")
                                            .or_else(|| m.get("model"))
                                            .and_then(|v| v.as_str())
                                            .map(str::to_string)
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        let (state, evidence) = ollama_availability(&model_id, &tags);
                        (state, "ollama_tags", evidence)
                    }
                    Err(e) => (
                        "unreachable",
                        "ollama_tags",
                        json!({ "error": format!("tag catalog unparsable: {e}") }),
                    ),
                },
                Err(e) => (
                    "unreachable",
                    "ollama_tags",
                    json!({ "error": e.to_string() }),
                ),
            }
        }
        "openai_compatible" => {
            // POSTURE-ONLY — never send a secret to the caller-supplied base_url (see fn doc).
            let env_key = route
                .pointer("/credential_binding/env_key_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let needs_key = route
                .get("credential_posture")
                .and_then(|v| v.as_str())
                .map(|p| p != "no_credentials_required")
                .unwrap_or(true);
            let key_present = !env_key.is_empty()
                && std::env::var(env_key)
                    .ok()
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false);
            if needs_key && !key_present {
                (
                    "credentials_missing",
                    "openai_compatible_posture",
                    json!({ "env_key_name": env_key, "note": "declared credential env key absent; no network call made" }),
                )
            } else {
                (
                    "credentials_present",
                    "openai_compatible_posture",
                    json!({ "env_key_name": env_key, "note": "credential env key resolves; authenticated catalog probing is deferred (the daemon never sends a secret to a caller-supplied URL) — not bindable for execution" }),
                )
            }
        }
        other => (
            "declared",
            "none",
            json!({ "note": format!("no probe implemented for transport '{other}'; posture stays declared") }),
        ),
    };
    json!({
        "state": state,
        "probe": { "kind": kind, "checked_at": checked_at, "evidence": evidence }
    })
}

fn probe_is_stale(availability: &Value) -> bool {
    let Some(checked_at) = availability
        .pointer("/probe/checked_at")
        .and_then(|v| v.as_str())
    else {
        return true;
    };
    // iso_now() is RFC3339; a lexicographic comparison against (now - fresh window) is exact.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cutoff = now_secs.saturating_sub(PROBE_FRESH_SECS);
    let cutoff_iso = chrono_free_iso(cutoff);
    checked_at < cutoff_iso.as_str()
}

/// Format unix seconds as a UTC RFC3339 stamp without pulling in chrono (comparison-only use).
fn chrono_free_iso(unix_secs: u64) -> String {
    // Days-from-civil inverse (Howard Hinnant's algorithm) — exact for the comparison window.
    let days = unix_secs / 86_400;
    let secs = unix_secs % 86_400;
    let (h, m, sec) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{sec:02}")
}

// ---------------------------------------------------------------------------
// admission composition (pure kernel planners — never re-implemented)
// ---------------------------------------------------------------------------

/// Compose a model-weight custody admission for a route from its declared custody fields.
fn compose_custody_admission(route: &Value) -> Result<Value, (u16, Value)> {
    let route_ref = s(route, "route_ref", "");
    let model_id = route
        .pointer("/model/model_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let transport = route
        .pointer("/provider_binding/transport")
        .and_then(|v| v.as_str())
        .unwrap_or("ollama");
    let weight_class = route
        .pointer("/custody/weight_class")
        .and_then(|v| v.as_str())
        .unwrap_or(if transport == "ollama" {
            "public_open_weight"
        } else {
            "remote_api_private_weight"
        });
    let (mount_target, posture, controls, scopes): (&str, &str, Vec<&str>, Vec<&str>) =
        if transport == "ollama" {
            (
                "local_device",
                "private_native",
                vec![],
                vec!["scope:model.route.mutate"],
            )
        } else {
            (
                "provider_api",
                "remote_api_provider_trust",
                vec!["wallet_authorized_api_capability"],
                vec!["scope:model.route.mutate", "scope:model.invoke_remote"],
            )
        };
    let request = json!({
        "route_ref": route_ref,
        "model_ref": format!("model:{model_id}"),
        "provider_ref": route.pointer("/provider_binding/provider_ref").cloned()
            .filter(|v| !v.is_null())
            .unwrap_or_else(|| json!(format!("provider:{transport}"))),
        "weight_class": route.pointer("/custody/weight_class").and_then(|v| v.as_str()).unwrap_or(weight_class),
        "mount_target": route.pointer("/custody/mount_target").and_then(|v| v.as_str()).unwrap_or(mount_target),
        "execution_privacy_posture": route.pointer("/custody/execution_privacy_posture").and_then(|v| v.as_str()).unwrap_or(posture),
        "authority_scope_refs": scopes,
        "required_controls": controls,
        "agentgres_operation_refs": [format!("agentgres://operation/model-route/{}/custody", s(route, "route_id", ""))],
    });
    RuntimeOwnerServices::new()
        .admit_model_weight_custody(&request, &iso_now())
        .map_err(|e| {
            (
                e.status,
                json!({ "error": { "code": e.code, "message": e.message, "details": e.details } }),
            )
        })
}

/// Compose a model-route-mutation admission for one mutation kind against the route's own refs.
fn compose_mutation_admission(
    route: &Value,
    mutation_kind: &str,
    session_ref: Option<&str>,
    custody_admission_id: Option<&str>,
) -> Result<Value, (u16, Value)> {
    let route_id = s(route, "route_id", "");
    let route_ref = s(route, "route_ref", "");
    let transport = route
        .pointer("/provider_binding/transport")
        .and_then(|v| v.as_str())
        .unwrap_or("ollama");
    let provider_kind = route
        .pointer("/provider_binding/provider_kind")
        .and_then(|v| v.as_str())
        .unwrap_or("local");
    let credential_posture = route
        .get("credential_posture")
        .and_then(|v| v.as_str())
        .unwrap_or("no_credentials_required");
    let provider_ref = route
        .pointer("/provider_binding/provider_ref")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("provider:{transport}"));
    let endpoint_ref = route
        .pointer("/provider_binding/endpoint_ref")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("model-endpoint:{route_id}"));
    let custody_ref = custody_admission_id
        .map(str::to_string)
        .or_else(|| {
            route
                .pointer("/custody/custody_admission_ref")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    let mut request = json!({
        "mutation_kind": mutation_kind,
        "route_ref": route_ref,
        "project_ref": opt_s(route, "project_ref").unwrap_or_else(|| "project:hypervisor".into()),
        "provider_ref": provider_ref,
        "provider_kind": provider_kind,
        "endpoint_refs": [endpoint_ref],
        "credential_posture": credential_posture,
        "authority_scope_refs": ["scope:model.route.mutate"],
        "agentgres_operation_refs": [format!("agentgres://operation/model-route/{route_id}/{mutation_kind}")],
        "receipt_refs": [format!("receipt://model-route/{route_id}/{mutation_kind}")],
        "state_root_ref": format!("agentgres://state-root/model-route/{route_id}"),
    });
    if !custody_ref.is_empty() {
        request["model_weight_custody_admission_ref"] = json!(custody_ref);
    }
    if mutation_kind != "disable_route" {
        let posture = route
            .pointer("/custody/execution_privacy_posture")
            .and_then(|v| v.as_str())
            .unwrap_or("private_native");
        request["privacy_posture_ref"] = json!(format!("privacy-posture:{posture}"));
    }
    if let Some(sref) = session_ref {
        let normalized = if sref.starts_with("session:") {
            sref.to_string()
        } else {
            format!("session:{sref}")
        };
        request["session_ref"] = json!(normalized);
    }
    if matches!(
        credential_posture,
        "wallet_credential_lease" | "provider_vault_token"
    ) {
        request["credential_scope_refs"] = json!(["scope:secret.use"]);
        if let Some(lease) = route
            .pointer("/credential_binding/provider_credential_lease_ref")
            .and_then(|v| v.as_str())
        {
            request["provider_credential_lease_ref"] = json!(lease);
        }
    }
    RuntimeOwnerServices::new()
        .admit_model_route_mutation(&request, &iso_now())
        .map_err(|e| {
            (
                e.status,
                json!({ "error": { "code": e.code, "message": e.message, "details": e.details } }),
            )
        })
}

/// Record an admission's id + mutation receipt on the route record (admissions are otherwise
/// stateless planner outputs — the registry links them to the object they admitted).
fn stamp_admission(route: &mut Value, admission: &Value) {
    let admission_id = admission
        .get("admission_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let receipt_ref = admission
        .get("mutation_receipt_ref")
        .and_then(|v| v.as_str())
        .or_else(|| admission.get("receipt_ref").and_then(|v| v.as_str()))
        .unwrap_or("");
    route["admission"]["last_admission_id"] = json!(admission_id);
    if !receipt_ref.is_empty() {
        let refs = route["admission"]["mutation_receipt_refs"]
            .as_array_mut()
            .map(|a| {
                if !a.iter().any(|v| v.as_str() == Some(receipt_ref)) {
                    a.push(json!(receipt_ref));
                }
            });
        if refs.is_none() {
            route["admission"]["mutation_receipt_refs"] = json!([receipt_ref]);
        }
    }
}

// ---------------------------------------------------------------------------
// seed — represent the env-var execution reality as a real, admitted registry record
// ---------------------------------------------------------------------------

fn seed_route_record() -> Value {
    let model_id = std::env::var("IOI_HYPERVISOR_MODEL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "qwen2.5-coder".to_string());
    let base_url = normalize_base_url(
        &std::env::var("IOI_HYPERVISOR_MODEL_UPSTREAM")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "http://127.0.0.1:11434".to_string()),
    );
    json!({
        "schema_version": ROUTE_SCHEMA,
        "route_id": SEED_ROUTE_ID,
        "route_ref": format!("model-route:{SEED_ROUTE_ID}"),
        "display_name": "Local default (env)",
        "summary": "The daemon's env-configured local execution route (IOI_HYPERVISOR_MODEL / IOI_HYPERVISOR_MODEL_UPSTREAM), represented as registry truth.",
        "origin": "seeded",
        "project_ref": "project:hypervisor",
        "model": {
            "model_id": model_id,
            "family": Value::Null,
            "modalities": ["text"],
            "capabilities": {
                "tool_calling": Value::Null,
                "structured_outputs": Value::Null,
                "reasoning": { "supported": Value::Null, "effort_levels": [] }
            },
            "context_window": Value::Null,
            "max_output_tokens": Value::Null
        },
        "provider_binding": {
            "provider_kind": "local",
            "transport": "ollama",
            "base_url": base_url,
            "provider_ref": Value::Null,
            "endpoint_ref": Value::Null
        },
        "credential_posture": "no_credentials_required",
        "credential_binding": Value::Null,
        "custody": {
            "weight_class": "public_open_weight",
            "mount_target": "local_device",
            "execution_privacy_posture": "private_native",
            "custody_admission_ref": Value::Null
        },
        "lifecycle": { "status": "declared" },
        "default_route": true,
        "availability": { "state": "declared", "probe": Value::Null },
        "admission": { "last_admission_id": Value::Null, "mutation_receipt_refs": [], "gaps": [] },
        "receipt_refs": [],
        "created_at": iso_now(),
        "updated_at": iso_now()
    })
}

/// Ensure the seeded local-default route exists (and is fully admitted). Idempotent; called from
/// read handlers so the registry never presents an empty world that hides the real env route.
pub(crate) fn ensure_seed(data_dir: &str) {
    if load_route_record(data_dir, SEED_ROUTE_ID).is_some() {
        return;
    }
    let mut record = seed_route_record();
    // Compose the REAL planners for the seed: custody first, then enable. If a planner rejects
    // (should not for the local lane), the seed stays `declared` with the rejection named.
    match compose_custody_admission(&record) {
        Ok(custody) => {
            record["custody"]["custody_admission_ref"] = custody["admission_id"].clone();
            match compose_mutation_admission(
                &record,
                "enable_route",
                None,
                custody.get("admission_id").and_then(|v| v.as_str()),
            ) {
                Ok(admission) => {
                    record["lifecycle"]["status"] = json!("active");
                    stamp_admission(&mut record, &admission);
                }
                Err((_, body)) => {
                    record["admission"]["gaps"] = json!([format!(
                        "seed enable_route admission rejected: {}",
                        body.pointer("/error/code")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                    )]);
                }
            }
        }
        Err((_, body)) => {
            record["admission"]["gaps"] = json!([format!(
                "seed custody admission rejected: {}",
                body.pointer("/error/code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
            )]);
        }
    }
    let receipt = route_receipt(
        data_dir,
        &s(&record, "route_ref", ""),
        "seeded",
        "ok",
        record
            .pointer("/admission/last_admission_id")
            .and_then(|v| v.as_str()),
    );
    record["receipt_refs"] = json!([receipt]);
    let _ = persist_record(data_dir, RECORD_DIR, SEED_ROUTE_ID, &record);
}

fn save_route(data_dir: &str, route: &mut Value) {
    route["updated_at"] = json!(iso_now());
    if let Some(id) = route.get("route_id").and_then(|v| v.as_str()) {
        let id = id.to_string();
        let _ = persist_record(data_dir, RECORD_DIR, &id, route);
    }
}

/// Persist a fresh availability probe onto a route WITHOUT clobbering a concurrent edit: under the
/// registry lock, RE-LOAD the record, set only `availability` (plus an optional receipt ref), save,
/// and return the reloaded+updated record. The lock is held only across the synchronous
/// reload-mutate-save — never across the network probe that produced `availability`. Returns None
/// if the record vanished between probe and persist.
fn persist_availability_locked(
    st: &Arc<DaemonState>,
    id: &str,
    availability: Value,
    receipt: Option<&str>,
) -> Option<Value> {
    let _guard = st
        .model_route_lock
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut route = load_route_record(&st.data_dir, id)?;
    route["availability"] = availability;
    if let Some(r) = receipt {
        if let Some(refs) = route["receipt_refs"].as_array_mut() {
            refs.push(json!(r));
        }
    }
    save_route(&st.data_dir, &mut route);
    Some(route)
}

fn with_staleness(mut route: Value) -> Value {
    let stale = probe_is_stale(&route["availability"]);
    route["availability"]["stale"] = json!(stale);
    route
}

// ---------------------------------------------------------------------------
// route handlers
// ---------------------------------------------------------------------------

/// GET /v1/hypervisor/model-routes — the registry. `?probe=live` re-probes every route serially
/// (bounded by the per-probe timeout) before responding; otherwise persisted probe evidence is
/// returned with an explicit `stale` flag.
pub(crate) async fn handle_model_routes_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    ensure_seed(&st.data_dir);
    let live = q.get("probe").map(|v| v == "live").unwrap_or(false);
    let mut routes = read_record_dir(&st.data_dir, RECORD_DIR);
    routes.sort_by(|a, b| s(a, "route_id", "").cmp(&s(b, "route_id", "")));
    if live {
        let mut refreshed = Vec::with_capacity(routes.len());
        for r in routes {
            let id = s(&r, "route_id", "");
            let availability = probe_route(&r).await;
            // Reload-under-lock so a concurrent PATCH/mutation in the probe window is not clobbered.
            let updated = persist_availability_locked(&st, &id, availability, None).unwrap_or(r);
            refreshed.push(with_staleness(updated));
        }
        routes = refreshed;
    } else {
        routes = routes.into_iter().map(with_staleness).collect();
    }
    let default_route = routes
        .iter()
        .find(|r| r.get("default_route").and_then(|v| v.as_bool()) == Some(true))
        .map(|r| s(r, "route_ref", ""));
    Json(json!({
        "schema_version": ROUTE_SCHEMA,
        "routes": routes,
        "default_route_ref": default_route,
        "probe_mode": if live { "live" } else { "persisted" },
        "at": iso_now()
    }))
}

/// GET /v1/hypervisor/model-routes/overview — read projection: registry counts, the live env
/// execution posture (named plainly as `source: env`), model-mount substrate counts, honest gaps.
pub(crate) async fn handle_model_routes_overview(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    ensure_seed(&st.data_dir);
    let routes = read_record_dir(&st.data_dir, RECORD_DIR);
    let mut by_availability = serde_json::Map::new();
    let mut by_lifecycle = serde_json::Map::new();
    for r in &routes {
        let a = r
            .pointer("/availability/state")
            .and_then(|v| v.as_str())
            .unwrap_or("declared")
            .to_string();
        let l = r
            .pointer("/lifecycle/status")
            .and_then(|v| v.as_str())
            .unwrap_or("declared")
            .to_string();
        *by_availability.entry(a).or_insert(json!(0)) = json!(
            by_availability
                .get(&a)
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                + 1
        );
        let count = by_lifecycle.get(&l).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
        by_lifecycle.insert(l, json!(count));
    }
    let bindings = read_record_dir(&st.data_dir, BINDING_DIR);

    // The env execution posture the session-execute path uses when NO binding exists — named
    // truthfully, source `env`, with a real reachability probe of the configured upstream.
    let env_model = std::env::var("IOI_HYPERVISOR_MODEL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "qwen2.5-coder".to_string());
    let env_upstream = std::env::var("IOI_HYPERVISOR_MODEL_UPSTREAM")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:11434".to_string());
    let env_probe = probe_route(&json!({
        "provider_binding": { "transport": "ollama", "base_url": normalize_base_url(&env_upstream) },
        "model": { "model_id": env_model }
    }))
    .await;

    // Model-mount substrate counts via the live catalog (evidence, not a second truth).
    let mount_providers = as_list(&get_json(&st.base_url, "/v1/model-mount/providers").await).len();
    let mount_routes = as_list(&get_json(&st.base_url, "/v1/model-mount/routes").await).len();

    let mut gaps: Vec<String> = Vec::new();
    if !routes
        .iter()
        .any(|r| r.pointer("/availability/state").and_then(|v| v.as_str()) == Some("available"))
    {
        gaps.push("no registry route has a successful availability probe yet (run POST /v1/hypervisor/model-routes/:id/probe)".into());
    }
    gaps.push("sealed BYOK credential bindings are not implemented; credentialed routes report env-key posture only".into());
    gaps.push("multi-transport execution is not implemented; only ollama-transport routes are bindable for session execution (shim contract)".into());

    Json(json!({
        "schema_version": OVERVIEW_SCHEMA,
        "route_count": routes.len(),
        "by_availability": by_availability,
        "by_lifecycle": by_lifecycle,
        "session_binding_count": bindings.len(),
        "env_execution": {
            "source": "env",
            "model": env_model,
            "upstream": env_upstream,
            "availability": env_probe
        },
        "model_mount_substrate": { "providers": mount_providers, "routes": mount_routes },
        "governance_gaps": gaps,
        "at": iso_now()
    }))
}

/// POST /v1/hypervisor/model-routes — register a DECLARED route. Composes the custody planner and
/// validates optional substrate refs against the live model-mount catalog; nothing persists on a
/// rejection. Credentials are never accepted as plaintext — only an env key NAME (posture).
pub(crate) async fn handle_model_route_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let model_id = s(&body, "model_id", "");
    if model_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "model_route_model_id_required", "message": "model_id is required." } }),
            ),
        );
    }
    let transport = s(&body, "transport", "ollama");
    if !matches!(transport.as_str(), "ollama" | "openai_compatible") {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "model_route_transport_invalid", "message": "transport must be 'ollama' or 'openai_compatible'.", "details": { "transport": transport } } }),
            ),
        );
    }
    let base_url_raw = s(&body, "base_url", "");
    if base_url_raw.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "model_route_base_url_required", "message": "base_url is required." } }),
            ),
        );
    }
    if body
        .get("api_key")
        .or_else(|| body.get("secret"))
        .or_else(|| body.get("token"))
        .is_some()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "model_route_plaintext_secret_rejected", "message": "Plaintext credentials are never accepted. Declare credential posture + env_key_name; the key stays in the daemon's environment." } }),
            ),
        );
    }
    let provider_ref = opt_s(&body, "provider_ref");
    let endpoint_ref = opt_s(&body, "endpoint_ref");
    if let Err((code, message)) = validate_substrate_refs(
        &st.base_url,
        provider_ref.as_deref(),
        endpoint_ref.as_deref(),
    )
    .await
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": { "code": code, "message": message } })),
        );
    }

    let id = format!("mrt_{:x}", nanos());
    let provider_kind = s(
        &body,
        "provider_kind",
        if transport == "ollama" {
            "local"
        } else {
            "hosted_api"
        },
    );
    let credential_posture = s(
        &body,
        "credential_posture",
        if transport == "ollama" {
            "no_credentials_required"
        } else {
            "provider_vault_token"
        },
    );
    let mut record = json!({
        "schema_version": ROUTE_SCHEMA,
        "route_id": id,
        "route_ref": format!("model-route:{id}"),
        "display_name": s(&body, "display_name", &model_id),
        "summary": s(&body, "summary", ""),
        "origin": "registered",
        "project_ref": opt_s(&body, "project_ref").unwrap_or_else(|| "project:hypervisor".into()),
        "model": {
            "model_id": model_id,
            "family": body.get("family").cloned().unwrap_or(Value::Null),
            "modalities": body.get("modalities").cloned().unwrap_or_else(|| json!(["text"])),
            "capabilities": body.get("capabilities").cloned().unwrap_or_else(|| json!({
                "tool_calling": Value::Null,
                "structured_outputs": Value::Null,
                "reasoning": { "supported": Value::Null, "effort_levels": [] }
            })),
            "context_window": body.get("context_window").cloned().unwrap_or(Value::Null),
            "max_output_tokens": body.get("max_output_tokens").cloned().unwrap_or(Value::Null)
        },
        "provider_binding": {
            "provider_kind": provider_kind,
            "transport": transport,
            "base_url": normalize_base_url(&base_url_raw),
            "provider_ref": provider_ref,
            "endpoint_ref": endpoint_ref
        },
        "credential_posture": credential_posture,
        "credential_binding": body.get("env_key_name").and_then(|v| v.as_str()).map(|k| json!({ "kind": "env_key_report", "env_key_name": k })).unwrap_or(Value::Null),
        "custody": {
            "weight_class": body.get("weight_class").cloned().unwrap_or(Value::Null),
            "mount_target": body.get("mount_target").cloned().unwrap_or(Value::Null),
            "execution_privacy_posture": body.get("execution_privacy_posture").cloned().unwrap_or(Value::Null),
            "custody_admission_ref": Value::Null
        },
        "lifecycle": { "status": "declared" },
        "default_route": false,
        "availability": { "state": "declared", "probe": Value::Null },
        "admission": { "last_admission_id": Value::Null, "mutation_receipt_refs": [], "gaps": [] },
        "receipt_refs": [],
        "created_at": iso_now(),
        "updated_at": iso_now()
    });
    // Custody admission at declaration time — the planner is the validator (fail-closed).
    match compose_custody_admission(&record) {
        Ok(custody) => {
            record["custody"]["custody_admission_ref"] = custody["admission_id"].clone();
        }
        Err((status, body)) => {
            return (
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
                Json(body),
            );
        }
    }
    let receipt = route_receipt(
        &st.data_dir,
        &s(&record, "route_ref", ""),
        "registered",
        "ok",
        record
            .pointer("/custody/custody_admission_ref")
            .and_then(|v| v.as_str()),
    );
    record["receipt_refs"] = json!([receipt]);
    let _ = persist_record(
        &st.data_dir,
        RECORD_DIR,
        &s(&record, "route_id", ""),
        &record,
    );
    (StatusCode::CREATED, Json(json!({ "route": record })))
}

/// GET /v1/hypervisor/model-routes/:id — record + persisted probe + bindings + receipts.
pub(crate) async fn handle_model_route_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    let Some(route) = load_route_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    let route_ref = s(&route, "route_ref", "");
    let bindings: Vec<Value> = read_record_dir(&st.data_dir, BINDING_DIR)
        .into_iter()
        .filter(|b| b.get("route_ref").and_then(|v| v.as_str()) == Some(route_ref.as_str()))
        .collect();
    let receipts: Vec<Value> = read_record_dir(&st.data_dir, RECEIPT_DIR)
        .into_iter()
        .filter(|r| r.get("route_ref").and_then(|v| v.as_str()) == Some(route_ref.as_str()))
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "route": with_staleness(route),
            "session_bindings": bindings,
            "receipts": receipts
        })),
    )
}

/// PATCH /v1/hypervisor/model-routes/:id — mutate declared metadata / provider binding /
/// credential posture. A credential-touching change composes `update_provider_credentials`
/// admission; a base_url change resets probe evidence to `declared` (old evidence would lie).
pub(crate) async fn handle_model_route_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut route) = load_route_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    if body
        .get("api_key")
        .or_else(|| body.get("secret"))
        .or_else(|| body.get("token"))
        .is_some()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "model_route_plaintext_secret_rejected", "message": "Plaintext credentials are never accepted." } }),
            ),
        );
    }
    let credential_change =
        body.get("credential_posture").is_some() || body.get("env_key_name").is_some();
    if credential_change {
        if let Some(p) = opt_s(&body, "credential_posture") {
            route["credential_posture"] = json!(p);
        }
        if let Some(k) = opt_s(&body, "env_key_name") {
            route["credential_binding"] = json!({ "kind": "env_key_report", "env_key_name": k });
        }
        match compose_mutation_admission(&route, "update_provider_credentials", None, None) {
            Ok(admission) => stamp_admission(&mut route, &admission),
            Err((status, body)) => {
                return (
                    StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
                    Json(body),
                );
            }
        }
    }
    if let Some(name) = opt_s(&body, "display_name") {
        route["display_name"] = json!(name);
    }
    if let Some(summary) = opt_s(&body, "summary") {
        route["summary"] = json!(summary);
    }
    if let Some(caps) = body.get("capabilities") {
        route["model"]["capabilities"] = caps.clone();
    }
    if let Some(cw) = body.get("context_window") {
        route["model"]["context_window"] = cw.clone();
    }
    if let Some(base) = opt_s(&body, "base_url") {
        let normalized = normalize_base_url(&base);
        if route
            .pointer("/provider_binding/base_url")
            .and_then(|v| v.as_str())
            != Some(normalized.as_str())
        {
            route["provider_binding"]["base_url"] = json!(normalized);
            route["availability"] = json!({ "state": "declared", "probe": Value::Null });
        }
    }
    let receipt = route_receipt(
        &st.data_dir,
        &s(&route, "route_ref", ""),
        "patched",
        "ok",
        None,
    );
    if let Some(refs) = route["receipt_refs"].as_array_mut() {
        refs.push(json!(receipt));
    }
    save_route(&st.data_dir, &mut route);
    (StatusCode::OK, Json(json!({ "route": route })))
}

/// DELETE /v1/hypervisor/model-routes/:id — registered-origin only; fail-closed 409 for the seed,
/// the current default, or a route with session bindings.
pub(crate) async fn handle_model_route_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(route) = load_route_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    let route_ref = s(&route, "route_ref", "");
    if s(&route, "origin", "") == "seeded" {
        return (
            StatusCode::CONFLICT,
            Json(
                json!({ "error": { "code": "model_route_seed_undeletable", "message": "The seeded env-default route represents live execution reality; it cannot be deleted." } }),
            ),
        );
    }
    if route.get("default_route").and_then(|v| v.as_bool()) == Some(true) {
        return (
            StatusCode::CONFLICT,
            Json(
                json!({ "error": { "code": "model_route_default_undeletable", "message": "Select a different default route before deleting this one." } }),
            ),
        );
    }
    let bound = read_record_dir(&st.data_dir, BINDING_DIR)
        .into_iter()
        .any(|b| b.get("route_ref").and_then(|v| v.as_str()) == Some(route_ref.as_str()));
    if bound {
        return (
            StatusCode::CONFLICT,
            Json(
                json!({ "error": { "code": "model_route_has_session_bindings", "message": "Route has session bindings; it cannot be deleted." } }),
            ),
        );
    }
    let removed = remove_record(&st.data_dir, RECORD_DIR, &id);
    let receipt = route_receipt(&st.data_dir, &route_ref, "deleted", "ok", None);
    (
        StatusCode::OK,
        Json(json!({ "ok": removed, "route_ref": route_ref, "receipt_ref": receipt })),
    )
}

/// POST /v1/hypervisor/model-routes/:id/probe — THE honest availability probe (effectful,
/// receipted, transcript-proofed).
pub(crate) async fn handle_model_route_probe(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    let Some(route) = load_route_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    let route_ref = s(&route, "route_ref", "");
    let availability = probe_route(&route).await;
    let state = availability
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("declared");
    let receipt = route_receipt(&st.data_dir, &route_ref, "probed", state, None);
    // Reload-under-lock so a PATCH that landed during the network probe is not clobbered.
    persist_availability_locked(&st, &id, availability.clone(), Some(&receipt));
    let transcript_run = post_op_transcript(&st.base_url, "probe", &route_ref, &availability).await;
    (
        StatusCode::OK,
        Json(json!({
            "route_ref": route_ref,
            "availability": availability,
            "receipt_ref": receipt,
            "transcript_run_id": transcript_run,
            "transcript_recorded": transcript_run.is_some()
        })),
    )
}

async fn lifecycle_flip(
    st: &Arc<DaemonState>,
    id: &str,
    mutation_kind: &str,
    new_status: &str,
) -> (StatusCode, Json<Value>) {
    let Some(route) = load_route_record(&st.data_dir, id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    match compose_mutation_admission(&route, mutation_kind, None, None) {
        Ok(admission) => {
            let route_ref = s(&route, "route_ref", "");
            let receipt = route_receipt(
                &st.data_dir,
                &route_ref,
                mutation_kind,
                "ok",
                admission.get("admission_id").and_then(|v| v.as_str()),
            );
            // Reload-under-lock and apply the flip on fresh state so a concurrent mutation isn't lost.
            let route = {
                let _guard = st
                    .model_route_lock
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let mut fresh = load_route_record(&st.data_dir, id).unwrap_or(route);
                fresh["lifecycle"]["status"] = json!(new_status);
                stamp_admission(&mut fresh, &admission);
                if let Some(refs) = fresh["receipt_refs"].as_array_mut() {
                    refs.push(json!(receipt));
                }
                save_route(&st.data_dir, &mut fresh);
                fresh
            };
            let transcript_run = post_op_transcript(
                &st.base_url,
                mutation_kind,
                &route_ref,
                &json!({ "new_status": new_status }),
            )
            .await;
            (
                StatusCode::OK,
                Json(json!({
                    "route": route,
                    "admission_id": admission.get("admission_id"),
                    "receipt_ref": receipt,
                    "transcript_recorded": transcript_run.is_some()
                })),
            )
        }
        Err((status, body)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(body),
        ),
    }
}

/// POST /v1/hypervisor/model-routes/:id/enable — declared/disabled -> active (admitted). Enabling
/// does NOT assert availability: an active route can still be credentials_missing/unreachable —
/// the two postures stay independently visible.
pub(crate) async fn handle_model_route_enable(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    lifecycle_flip(&st, &id, "enable_route", "active").await
}

/// POST /v1/hypervisor/model-routes/:id/disable — active -> disabled (admitted; relaxed lane).
pub(crate) async fn handle_model_route_disable(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    lifecycle_flip(&st, &id, "disable_route", "disabled").await
}

/// POST /v1/hypervisor/model-routes/:id/select-default — exactly-one default invariant, admitted.
pub(crate) async fn handle_model_route_select_default(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    let Some(route) = load_route_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    match compose_mutation_admission(&route, "select_route", None, None) {
        Ok(admission) => {
            let route_ref = s(&route, "route_ref", "");
            let receipt = route_receipt(
                &st.data_dir,
                &route_ref,
                "select_route",
                "ok",
                admission.get("admission_id").and_then(|v| v.as_str()),
            );
            // Hold the registry lock across clear-others + set-self so two concurrent
            // select-default calls cannot each observe the old default and both win (the
            // exactly-one invariant). No .await inside the guarded region.
            let route = {
                let _guard = st
                    .model_route_lock
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                for mut other in read_record_dir(&st.data_dir, RECORD_DIR) {
                    if other.get("default_route").and_then(|v| v.as_bool()) == Some(true)
                        && s(&other, "route_id", "") != id
                    {
                        other["default_route"] = json!(false);
                        let other_ref = s(&other, "route_ref", "");
                        route_receipt(&st.data_dir, &other_ref, "default_cleared", "ok", None);
                        save_route(&st.data_dir, &mut other);
                    }
                }
                let mut fresh = load_route_record(&st.data_dir, &id).unwrap_or(route);
                fresh["default_route"] = json!(true);
                stamp_admission(&mut fresh, &admission);
                if let Some(refs) = fresh["receipt_refs"].as_array_mut() {
                    refs.push(json!(receipt));
                }
                save_route(&st.data_dir, &mut fresh);
                fresh
            };
            let transcript_run =
                post_op_transcript(&st.base_url, "select_default", &route_ref, &json!({})).await;
            (
                StatusCode::OK,
                Json(json!({
                    "route": route,
                    "receipt_ref": receipt,
                    "transcript_recorded": transcript_run.is_some()
                })),
            )
        }
        Err((status, body)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(body),
        ),
    }
}

/// POST /v1/hypervisor/model-routes/:id/session-bindings — bind a session to a route. FAIL-CLOSED:
/// 412 unless an inline live probe returns `available` AND lifecycle is `active`; 409 for
/// transports the execution shim cannot run (no dropdown lies). Admitted (`bind_session_route`)
/// and receipted; consumed by sessions/:id/execute.
pub(crate) async fn handle_model_route_bind_session(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    let Some(mut route) = load_route_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    let session_ref = s(&body, "session_ref", "");
    if session_ref.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "model_route_session_ref_required", "message": "session_ref is required." } }),
            ),
        );
    }
    let transport = route
        .pointer("/provider_binding/transport")
        .and_then(|v| v.as_str())
        .unwrap_or("ollama")
        .to_string();
    if transport != "ollama" {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": {
                "code": "transport_unsupported_for_execution",
                "message": "Only ollama-transport routes are executable by the session harness today; this route stays declared/available but is not bindable for execution.",
                "details": { "transport": transport }
            } })),
        );
    }
    let lifecycle = route
        .pointer("/lifecycle/status")
        .and_then(|v| v.as_str())
        .unwrap_or("declared")
        .to_string();
    if lifecycle != "active" {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": {
                "code": "model_route_not_active",
                "message": format!("Route lifecycle is '{lifecycle}'; enable it before binding sessions."),
            } })),
        );
    }
    // Inline REAL probe — a binding must never be minted against stale availability.
    let availability = probe_route(&route).await;
    route["availability"] = availability.clone();
    save_route(&st.data_dir, &mut route);
    let state = availability
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("declared");
    if state != "available" {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": {
                "code": "model_route_not_available",
                "message": format!("Live probe returned '{state}'; only an available route may bind a session."),
                "details": availability
            } })),
        );
    }
    match compose_mutation_admission(&route, "bind_session_route", Some(&session_ref), None) {
        Ok(admission) => {
            let binding_id = format!("mrb_{:x}", nanos());
            let route_ref = s(&route, "route_ref", "");
            let receipt = route_receipt(
                &st.data_dir,
                &route_ref,
                "bind_session_route",
                "ok",
                admission.get("admission_id").and_then(|v| v.as_str()),
            );
            let binding = json!({
                "schema_version": BINDING_SCHEMA,
                "binding_id": binding_id,
                "route_ref": route_ref,
                "route_id": s(&route, "route_id", ""),
                "session_ref": session_ref,
                "harness_binding_ref": opt_s(&body, "harness_binding_ref"),
                "admission_id": admission.get("admission_id"),
                "mutation_receipt_ref": admission.get("mutation_receipt_ref"),
                "receipt_ref": receipt,
                "availability_at_bind": availability,
                "model_id": route.pointer("/model/model_id"),
                "base_url": route.pointer("/provider_binding/base_url"),
                "transport": transport,
                "created_at": iso_now()
            });
            let _ = persist_record(&st.data_dir, BINDING_DIR, &binding_id, &binding);
            let transcript_run = post_op_transcript(
                &st.base_url,
                "bind_session_route",
                &route_ref,
                &json!({ "session_ref": binding["session_ref"], "binding_id": binding_id }),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(json!({
                    "binding": binding,
                    "transcript_recorded": transcript_run.is_some()
                })),
            )
        }
        Err((status, body)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(body),
        ),
    }
}

/// GET /v1/hypervisor/model-route-session-bindings?session_ref=&route_ref= — binding projection.
pub(crate) async fn handle_model_route_bindings_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let mut bindings = read_record_dir(&st.data_dir, BINDING_DIR);
    if let Some(sref) = q.get("session_ref") {
        bindings.retain(|b| b.get("session_ref").and_then(|v| v.as_str()) == Some(sref.as_str()));
    }
    if let Some(rref) = q.get("route_ref") {
        bindings.retain(|b| b.get("route_ref").and_then(|v| v.as_str()) == Some(rref.as_str()));
    }
    bindings.sort_by(|a, b| s(b, "binding_id", "").cmp(&s(a, "binding_id", "")));
    Json(json!({
        "schema_version": BINDING_SCHEMA,
        "bindings": bindings,
        "at": iso_now()
    }))
}

/// Resolve the newest execution-consumable binding for a session: route must still be `active`.
/// Returns `(model_id, shim_endpoint, route_ref, binding_id)`; the shim endpoint re-appends the
/// OpenAI-compat `/v1` the stored provider root omits. Used by handle_session_execute — when this
/// returns None the execute path is byte-identical to the env-var default.
pub(crate) fn resolve_session_route_binding(
    data_dir: &str,
    session_id: &str,
) -> Option<(String, String, String, String)> {
    let mut bindings: Vec<Value> = read_record_dir(data_dir, BINDING_DIR)
        .into_iter()
        .filter(|b| {
            let sref = b.get("session_ref").and_then(|v| v.as_str()).unwrap_or("");
            sref == session_id || sref == format!("session:{session_id}")
        })
        .filter(|b| b.get("transport").and_then(|v| v.as_str()) == Some("ollama"))
        .collect();
    bindings.sort_by(|a, b| s(b, "binding_id", "").cmp(&s(a, "binding_id", "")));
    let binding = bindings.into_iter().next()?;
    let route_id = s(&binding, "route_id", "");
    let route = load_route_record(data_dir, &route_id)?;
    if route.pointer("/lifecycle/status").and_then(|v| v.as_str()) != Some("active") {
        return None;
    }
    let model_id = route
        .pointer("/model/model_id")
        .and_then(|v| v.as_str())?
        .to_string();
    let base_url = route
        .pointer("/provider_binding/base_url")
        .and_then(|v| v.as_str())?
        .trim_end_matches('/')
        .to_string();
    Some((
        model_id,
        format!("{base_url}/v1"),
        s(&binding, "route_ref", ""),
        s(&binding, "binding_id", ""),
    ))
}

#[cfg(test)]
mod model_route_tests {
    use super::*;

    #[test]
    fn base_url_normalization_strips_openai_suffix() {
        assert_eq!(
            normalize_base_url("http://127.0.0.1:11434/v1"),
            "http://127.0.0.1:11434"
        );
        assert_eq!(
            normalize_base_url("http://127.0.0.1:11434/"),
            "http://127.0.0.1:11434"
        );
        assert_eq!(
            normalize_base_url("https://openrouter.ai/api/v1"),
            "https://openrouter.ai/api"
        );
    }

    #[test]
    fn ollama_availability_matches_tag_and_latest_forms() {
        let tags = vec![
            "qwen2.5:7b".to_string(),
            "qwen2.5-coder:latest".to_string(),
            "llama3.2:3b".to_string(),
        ];
        // Exact tagged match.
        assert_eq!(ollama_availability("qwen2.5:7b", &tags).0, "available");
        // Untagged declared id resolves to the catalog's `:latest` entry (the seed-default case).
        assert_eq!(ollama_availability("qwen2.5-coder", &tags).0, "available");
        // A genuinely absent tag stays model_not_present with an honest catalog count.
        let (state, evidence) = ollama_availability("qwen2.5:14b", &tags);
        assert_eq!(state, "model_not_present");
        assert_eq!(evidence["catalog_count"], 3);
    }

    #[test]
    fn tag_matches_handles_latest_equivalence_both_directions() {
        assert!(tag_matches("qwen2.5-coder", "qwen2.5-coder:latest"));
        assert!(tag_matches("qwen2.5-coder:latest", "qwen2.5-coder:latest"));
        assert!(tag_matches("qwen2.5:7b", "qwen2.5:7b"));
        // An untagged id must NOT match a different explicit tag.
        assert!(!tag_matches("qwen2.5", "qwen2.5:7b"));
    }

    #[test]
    fn seed_route_composes_real_planner_admissions() {
        let record = seed_route_record();
        let custody = compose_custody_admission(&record).expect("seed custody lane admits");
        assert!(custody["admission_id"]
            .as_str()
            .unwrap()
            .starts_with("model-weight-custody-admission:"));
        let admission = compose_mutation_admission(
            &record,
            "enable_route",
            None,
            custody["admission_id"].as_str(),
        )
        .expect("seed enable_route admits");
        assert_eq!(admission["admission_state"], "admitted_for_model_router");
        assert_eq!(admission["mutation_kind"], "enable_route");
    }

    #[test]
    fn bind_session_admission_normalizes_session_ref() {
        let record = seed_route_record();
        let custody = compose_custody_admission(&record).expect("custody");
        let admission = compose_mutation_admission(
            &record,
            "bind_session_route",
            Some("sess_abc123"),
            custody["admission_id"].as_str(),
        )
        .expect("bind admits");
        assert_eq!(admission["session_ref"], "session:sess_abc123");
    }

    #[test]
    fn credentialed_mutation_without_lease_is_rejected_by_planner() {
        let mut record = seed_route_record();
        record["credential_posture"] = json!("wallet_credential_lease");
        let custody = compose_custody_admission(&record).expect("custody");
        let err = compose_mutation_admission(
            &record,
            "enable_route",
            None,
            custody["admission_id"].as_str(),
        )
        .expect_err("missing lease must fail closed");
        assert_eq!(err.0, 403);
    }

    #[test]
    fn iso_formatter_matches_known_epoch() {
        assert_eq!(chrono_free_iso(0), "1970-01-01T00:00:00");
        assert_eq!(chrono_free_iso(1_782_998_400), "2026-07-02T13:20:00");
    }
}
