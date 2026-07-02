//! Harness-profile REGISTRY — daemon-owned truth for which agent harnesses exist as selectable
//! runtime options, their adapter posture, and their probed runnability. The selection substrate
//! New Session / Agent Studio / session details consume (a registry, not a runtime).
//!
//! Doctrine enforced here:
//! - Runnability is PROBED host truth (binary on PATH / shim file + node / model upstream TCP
//!   reachability) — states `runnable` | `binary_missing` | `shim_missing` |
//!   `model_route_unreachable` | `not_probed`, never fabricated. `runnable` means the adapter's
//!   host requirements resolve; whether the daemon can EXECUTE through it is a separate, explicit
//!   `execution_wiring` axis (`lane_a_host_spawn` | `terminal_pty` | `adapter_slot_unwired`).
//!   An adapter-slot profile is honest selectable metadata — binding it to a session for
//!   execution is rejected fail-closed, in the planner AND here.
//! - Effectful mutations (enable/disable/select-default/bind-session) COMPOSE the pure kernel
//!   harness-profile-mutation planner; rejections propagate as the HTTP error body. Enabling or
//!   selecting a non-local-trust adapter requires an explicit provider-trust acceptance ref.
//! - Session EXECUTION bindings additionally require the model route they execute over to be an
//!   `active` + `available` record in the model-route registry (cross-registry truth, no
//!   free-floating model strings).
//! - The registry is SEEDED from the platform's real adapter set (the former static
//!   agent-runner-profile catalog, plus the deepseek_tui slot); `/v1/hypervisor/agent-runner-
//!   profiles` and the session-composer admission project from these records — one truth.
//! - Every mutation writes a receipt; effectful ops post an agent-run-transcript so they carry a
//!   state_root in Run Timeline / Work Ledger.
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use ioi_services::agentic::runtime::kernel::RuntimeKernelService;

use super::lifecycle_routes::{
    binary_on_path, generic_cli_local_shim_path, model_route_reachable,
};
use super::{iso_now, persist_record, read_record_dir, DaemonState};

const PROFILE_SCHEMA: &str = "ioi.hypervisor.harness-profile.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.harness-profile-receipt.v1";
const BINDING_SCHEMA: &str = "ioi.hypervisor.harness-profile-session-binding.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.harness-profiles-overview.v1";
pub(crate) const RECORD_DIR: &str = "harness-profile-registry";
const RECEIPT_DIR: &str = "harness-profile-registry-receipts";
const BINDING_DIR: &str = "harness-profile-session-bindings";
const DEFAULT_PROFILE_ID: &str = "hp_hypervisor_worker";

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}
fn ps(v: &Value, pointer: &str, d: &str) -> String {
    v.pointer(pointer)
        .and_then(|x| x.as_str())
        .unwrap_or(d)
        .to_string()
}

pub(crate) fn load_profile_record(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, RECORD_DIR)
        .into_iter()
        .find(|r| r.get("profile_id").and_then(|v| v.as_str()) == Some(id))
}

fn profile_receipt(
    data_dir: &str,
    profile_ref: &str,
    op: &str,
    outcome: &str,
    admission_id: Option<&str>,
) -> String {
    let id = format!("hpr_{:x}", nanos());
    let receipt_ref = format!("agentgres://harness-profile-receipt/{id}");
    let _ = persist_record(
        data_dir,
        RECEIPT_DIR,
        &id,
        &json!({
            "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
            "profile_ref": profile_ref, "op": op, "outcome": outcome,
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
    profile_ref: &str,
    detail: &Value,
) -> Option<String> {
    let run_id = format!("hpo_{:x}", nanos());
    let at = iso_now();
    let transcript = json!({
        "schema_version": "ioi.hypervisor.agent-run-transcript.v1",
        "run_id": run_id,
        "kind": "harness-profile-op",
        "op": op,
        "profile_ref": profile_ref,
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
// honest runnability probe — host presence truth, never fabricated
// ---------------------------------------------------------------------------

/// Probe one profile's host requirements. Local IO only (PATH lookups, shim file existence) plus
/// the short TCP reachability check for the native worker's model upstream. Pure host truth: a
/// missing binary is `binary_missing`, a missing shim is `shim_missing`, a dead model upstream is
/// `model_route_unreachable` — `runnable` is only ever derived from resolved evidence.
fn probe_profile(profile: &Value) -> Value {
    let adapter_kind = ps(profile, "/adapter/adapter_kind", "cli_binary");
    let binary = ps(profile, "/adapter/binary", "");
    let (state, evidence): (&str, Value) = match adapter_kind.as_str() {
        "native_worker" => {
            let node = binary_on_path("node");
            let shim = generic_cli_local_shim_path();
            if node.is_none() {
                (
                    "binary_missing",
                    json!({ "required_binary": "node", "note": "the native worker drives the generic-cli-local shim through node" }),
                )
            } else if shim.is_none() {
                (
                    "shim_missing",
                    json!({ "required_shim": "packages/hypervisor-harness-shims/generic-cli-local.mjs" }),
                )
            } else if !model_route_reachable() {
                (
                    "model_route_unreachable",
                    json!({ "note": "node + shim resolve but the configured model upstream did not accept a TCP connection" }),
                )
            } else {
                (
                    "runnable",
                    json!({ "node_path": node, "shim_path": shim, "model_upstream_reachable": true }),
                )
            }
        }
        "terminal_shell" => match binary_on_path(if binary.is_empty() { "bash" } else { &binary }) {
            Some(path) => (
                "runnable",
                json!({ "binary_path": path, "tmux_present": binary_on_path("tmux").is_some() }),
            ),
            None => (
                "binary_missing",
                json!({ "required_binary": if binary.is_empty() { "bash".to_string() } else { binary.clone() } }),
            ),
        },
        _ => match binary_on_path(&binary) {
            Some(path) => ("runnable", json!({ "binary_path": path })),
            None => (
                "binary_missing",
                json!({ "required_binary": binary }),
            ),
        },
    };
    json!({
        "state": state,
        "probe": { "kind": "host_presence", "at": iso_now(), "evidence": evidence }
    })
}

// ---------------------------------------------------------------------------
// planner composition — the pure kernel harness-profile-mutation admission
// ---------------------------------------------------------------------------

fn compose_mutation_admission(
    profile: &Value,
    mutation_kind: &str,
    session_ref: Option<&str>,
    model_route_ref: Option<&str>,
    provider_trust_acceptance_ref: Option<&str>,
) -> Result<Value, (u16, Value)> {
    let profile_id = s(profile, "profile_id", "");
    let profile_ref = s(profile, "profile_ref", "");
    let mut request = json!({
        "mutation_kind": mutation_kind,
        "profile_ref": profile_ref,
        "project_ref": s(profile, "project_ref", "project:hypervisor"),
        "adapter_kind": ps(profile, "/adapter/adapter_kind", "cli_binary"),
        "execution_wiring": ps(profile, "/adapter/execution_wiring", "adapter_slot_unwired"),
        "provider_trust": ps(profile, "/adapter/provider_trust", "local"),
        "runnability_state": ps(profile, "/runnability/state", "not_probed"),
        "authority_scope_refs": ["scope:harness.profile.mutate"],
        "agentgres_operation_refs": [format!("agentgres://operation/harness-profile/{profile_id}/{mutation_kind}")],
        "receipt_refs": [format!("receipt://harness-profile/{profile_id}/{mutation_kind}")],
        "state_root_ref": format!("agentgres://state-root/harness-profile/{profile_id}"),
    });
    if let Some(sref) = session_ref {
        let normalized = if sref.starts_with("session:") {
            sref.to_string()
        } else {
            format!("session:{sref}")
        };
        request["session_ref"] = json!(normalized);
    }
    if let Some(route) = model_route_ref {
        request["model_route_ref"] = json!(route);
    }
    if let Some(acceptance) = provider_trust_acceptance_ref {
        request["provider_trust_acceptance_ref"] = json!(acceptance);
    }
    RuntimeKernelService::new()
        .admit_harness_profile_mutation(&request, &iso_now())
        .map_err(|e| {
            (
                e.status,
                json!({ "error": { "code": e.code, "message": e.message, "details": e.details } }),
            )
        })
}

fn stamp_admission(profile: &mut Value, admission: &Value) {
    let admission_id = admission
        .get("admission_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let receipt_ref = admission
        .get("receipt_refs")
        .and_then(|v| v.as_array())
        .and_then(|a| a.last())
        .and_then(|v| v.as_str())
        .unwrap_or("");
    profile["admission"]["last_admission_id"] = json!(admission_id);
    if !receipt_ref.is_empty() {
        let pushed = profile["admission"]["mutation_receipt_refs"]
            .as_array_mut()
            .map(|a| {
                if !a.iter().any(|v| v.as_str() == Some(receipt_ref)) {
                    a.push(json!(receipt_ref));
                }
            });
        if pushed.is_none() {
            profile["admission"]["mutation_receipt_refs"] = json!([receipt_ref]);
        }
    }
}

// ---------------------------------------------------------------------------
// seeds — the platform's real adapter set as registry records
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn seed_profile(
    profile_id: &str,
    harness: &str,
    display_name: &str,
    summary: &str,
    adapter_kind: &str,
    execution_wiring: &str,
    binary: &str,
    provider_trust: &str,
    models: Value,
    modes: Value,
    reasoning: Value,
    speed: Value,
    service_tier: Value,
    tool_use: bool,
    image_input: bool,
    default_profile: bool,
) -> Value {
    json!({
        "schema_version": PROFILE_SCHEMA,
        "profile_id": profile_id,
        "profile_ref": format!("harness-profile:{profile_id}"),
        "harness": harness,
        "display_name": display_name,
        "summary": summary,
        "origin": "seeded",
        "project_ref": "project:hypervisor",
        "adapter": {
            "adapter_kind": adapter_kind,
            "execution_wiring": execution_wiring,
            "binary": binary,
            "shim_path": if adapter_kind == "native_worker" { json!("packages/hypervisor-harness-shims/generic-cli-local.mjs") } else { Value::Null },
            "provider_trust": provider_trust
        },
        "capabilities": {
            "modes": modes,
            "reasoning": reasoning,
            "speed": speed,
            "service_tier": service_tier,
            "tool_use": tool_use,
            "image_input": image_input
        },
        "model_binding": { "declared_models": models, "model_route_policy": "registry_routes" },
        "lifecycle": { "status": "declared" },
        "default_profile": default_profile,
        "runnability": { "state": "not_probed", "probe": Value::Null },
        "admission": { "last_admission_id": Value::Null, "mutation_receipt_refs": [], "gaps": [] },
        "receipt_refs": [],
        "created_at": iso_now(),
        "updated_at": iso_now()
    })
}

fn seed_profiles() -> Vec<Value> {
    vec![
        seed_profile(
            DEFAULT_PROFILE_ID,
            "hypervisor_worker",
            "Hypervisor Worker (native)",
            "The daemon's native Lane A worker: the generic-cli-local shim spawned over the session workspace, driven against the local model route.",
            "native_worker",
            "lane_a_host_spawn",
            "node",
            "local",
            json!(["hypervisor:native-local"]),
            json!(["agent", "plan", "goal", "spec"]),
            json!(["low", "medium", "high"]),
            json!(["fast", "balanced", "thorough"]),
            json!(["standard"]),
            true,
            false,
            true,
        ),
        seed_profile(
            "hp_shell",
            "shell",
            "Shell / tmux",
            "Direct terminal execution over the session workspace through the daemon's PTY lane.",
            "terminal_shell",
            "terminal_pty",
            "bash",
            "local",
            json!(["hypervisor:native-local"]),
            json!(["agent"]),
            json!(["medium"]),
            json!(["balanced"]),
            json!(["standard"]),
            true,
            false,
            false,
        ),
        seed_profile(
            "hp_opencode",
            "opencode",
            "OpenCode",
            "OpenCode CLI adapter slot — probed for host presence; execution wiring is not yet built.",
            "cli_binary",
            "adapter_slot_unwired",
            "opencode",
            "local",
            json!(["hypervisor:native-local"]),
            json!(["agent"]),
            json!(["medium"]),
            json!(["balanced"]),
            json!(["standard"]),
            true,
            false,
            false,
        ),
        seed_profile(
            "hp_deepseek_tui",
            "deepseek_tui",
            "DeepSeek TUI",
            "DeepSeek terminal UI adapter slot — probed for host presence; execution wiring is not yet built.",
            "cli_binary",
            "adapter_slot_unwired",
            "deepseek",
            "local",
            json!(["deepseek:local"]),
            json!(["agent"]),
            json!(["medium"]),
            json!(["balanced"]),
            json!(["standard"]),
            true,
            false,
            false,
        ),
        seed_profile(
            "hp_claude_code",
            "claude_code",
            "Claude Code",
            "Claude Code CLI adapter slot — remote-attested provider trust; enabling requires an explicit provider-trust acceptance.",
            "cli_binary",
            "adapter_slot_unwired",
            "claude",
            "remote_attested",
            json!(["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5"]),
            json!(["agent", "plan", "goal", "spec"]),
            json!(["low", "medium", "high"]),
            json!(["fast", "balanced", "thorough"]),
            json!(["standard", "priority"]),
            true,
            true,
            false,
        ),
        seed_profile(
            "hp_codex",
            "codex",
            "Codex",
            "Codex CLI adapter slot — remote provider trust; enabling requires an explicit provider-trust acceptance.",
            "cli_binary",
            "adapter_slot_unwired",
            "codex",
            "remote",
            json!(["gpt-5-codex"]),
            json!(["agent", "plan"]),
            json!(["medium", "high"]),
            json!(["balanced", "thorough"]),
            json!(["standard"]),
            true,
            false,
            false,
        ),
    ]
}

/// Ensure the seeded adapter set exists (idempotent, called from read handlers). The default
/// native-worker profile composes a REAL enable admission at seed (local trust — the planner
/// admits without acceptance refs); adapter slots stay `declared` until an admitted enable.
pub(crate) fn ensure_seed(data_dir: &str) {
    for mut record in seed_profiles() {
        let id = s(&record, "profile_id", "");
        if load_profile_record(data_dir, &id).is_some() {
            continue;
        }
        if id == DEFAULT_PROFILE_ID {
            match compose_mutation_admission(&record, "enable_profile", None, None, None) {
                Ok(admission) => {
                    record["lifecycle"]["status"] = json!("active");
                    stamp_admission(&mut record, &admission);
                }
                Err((_, body)) => {
                    record["admission"]["gaps"] = json!([format!(
                        "seed enable_profile admission rejected: {}",
                        body.pointer("/error/code").and_then(|v| v.as_str()).unwrap_or("unknown")
                    )]);
                }
            }
        }
        let receipt = profile_receipt(
            data_dir,
            &s(&record, "profile_ref", ""),
            "seeded",
            "ok",
            record
                .pointer("/admission/last_admission_id")
                .and_then(|v| v.as_str()),
        );
        record["receipt_refs"] = json!([receipt]);
        let _ = persist_record(data_dir, RECORD_DIR, &id, &record);
    }
}

fn save_profile(data_dir: &str, profile: &mut Value) {
    profile["updated_at"] = json!(iso_now());
    if let Some(id) = profile.get("profile_id").and_then(|v| v.as_str()) {
        let id = id.to_string();
        let _ = persist_record(data_dir, RECORD_DIR, &id, profile);
    }
}

/// Persist a fresh runnability probe onto a profile WITHOUT clobbering a concurrent edit:
/// under the registry lock, re-load the record, set only `runnability` (plus an optional receipt
/// ref), save, and return the reloaded+updated record.
fn persist_runnability_locked(
    st: &Arc<DaemonState>,
    id: &str,
    runnability: Value,
    receipt: Option<&str>,
) -> Option<Value> {
    let _guard = st
        .harness_profile_lock
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut profile = load_profile_record(&st.data_dir, id)?;
    profile["runnability"] = runnability;
    if let Some(r) = receipt {
        if let Some(refs) = profile["receipt_refs"].as_array_mut() {
            refs.push(json!(r));
        }
    }
    save_profile(&st.data_dir, &mut profile);
    Some(profile)
}

fn sorted_profiles(data_dir: &str) -> Vec<Value> {
    let mut profiles = read_record_dir(data_dir, RECORD_DIR);
    profiles.sort_by(|a, b| {
        let da = a.get("default_profile").and_then(|v| v.as_bool()) == Some(true);
        let db = b.get("default_profile").and_then(|v| v.as_bool()) == Some(true);
        db.cmp(&da)
            .then(s(a, "profile_id", "").cmp(&s(b, "profile_id", "")))
    });
    profiles
}

/// Legacy-shape runner-profile projection for `/v1/hypervisor/agent-runner-profiles` and the
/// session-composer capability admission — projected FROM the registry so there is one truth.
pub(crate) fn registry_runner_profiles(data_dir: &str) -> Vec<Value> {
    ensure_seed(data_dir);
    sorted_profiles(data_dir)
        .into_iter()
        .map(|p| {
            json!({
                "harness": s(&p, "harness", ""),
                "display_name": s(&p, "display_name", ""),
                "models": p.pointer("/model_binding/declared_models").cloned().unwrap_or(json!([])),
                "modes": p.pointer("/capabilities/modes").cloned().unwrap_or(json!([])),
                "reasoning": p.pointer("/capabilities/reasoning").cloned().unwrap_or(json!([])),
                "speed": p.pointer("/capabilities/speed").cloned().unwrap_or(json!([])),
                "service_tier": p.pointer("/capabilities/service_tier").cloned().unwrap_or(json!([])),
                "tool_use": p.pointer("/capabilities/tool_use").cloned().unwrap_or(json!(false)),
                "image_input": p.pointer("/capabilities/image_input").cloned().unwrap_or(json!(false)),
                "provider_trust": ps(&p, "/adapter/provider_trust", "local"),
                "default": p.get("default_profile").cloned().unwrap_or(json!(false)),
                "profile_ref": s(&p, "profile_ref", ""),
                "lifecycle_status": ps(&p, "/lifecycle/status", "declared"),
                "runnability_state": ps(&p, "/runnability/state", "not_probed"),
                "execution_wiring": ps(&p, "/adapter/execution_wiring", "adapter_slot_unwired"),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

pub(crate) async fn handle_harness_profiles_list(
    State(st): State<Arc<DaemonState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    ensure_seed(&st.data_dir);
    let live = params.get("live").map(|v| v == "1" || v == "true").unwrap_or(false);
    let mut profiles = sorted_profiles(&st.data_dir);
    if live {
        let mut refreshed = Vec::with_capacity(profiles.len());
        for p in profiles {
            let id = s(&p, "profile_id", "");
            let runnability = probe_profile(&p);
            let updated = persist_runnability_locked(&st, &id, runnability, None).unwrap_or(p);
            refreshed.push(updated);
        }
        profiles = refreshed;
    }
    let default_ref = profiles
        .iter()
        .find(|p| p.get("default_profile").and_then(|v| v.as_bool()) == Some(true))
        .map(|p| s(p, "profile_ref", ""));
    Json(json!({
        "schema_version": PROFILE_SCHEMA,
        "profiles": profiles,
        "default_profile_ref": default_ref,
        "runtimeTruthSource": "daemon-runtime"
    }))
}

pub(crate) async fn handle_harness_profiles_overview(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    ensure_seed(&st.data_dir);
    let profiles = sorted_profiles(&st.data_dir);
    let default_ref = profiles
        .iter()
        .find(|p| p.get("default_profile").and_then(|v| v.as_bool()) == Some(true))
        .map(|p| s(p, "profile_ref", ""));
    let lane_a = json!({
        "shim_present": generic_cli_local_shim_path().is_some(),
        "node_present": binary_on_path("node").is_some(),
        "model_upstream_reachable": model_route_reachable(),
    });
    let counts = |state: &str| {
        profiles
            .iter()
            .filter(|p| ps(p, "/runnability/state", "not_probed") == state)
            .count()
    };
    Json(json!({
        "schema_version": OVERVIEW_SCHEMA,
        "profiles": profiles.len(),
        "default_profile_ref": default_ref,
        "wired_execution": {
            "lane_a_host_spawn": lane_a,
            "terminal_pty": { "bash_present": binary_on_path("bash").is_some() },
        },
        "runnability_counts": {
            "runnable": counts("runnable"),
            "binary_missing": counts("binary_missing"),
            "shim_missing": counts("shim_missing"),
            "model_route_unreachable": counts("model_route_unreachable"),
            "not_probed": counts("not_probed"),
        },
        "governance_gaps": [
            "adapter-slot profiles (opencode / deepseek_tui / claude_code / codex) are selectable metadata with probed host presence; the daemon's wired execution lanes are lane_a_host_spawn (generic-cli-local shim) and terminal_pty — binding an unwired profile for session execution is rejected fail-closed",
            "no per-profile credential store exists; remote adapters authenticate through their own CLIs outside daemon custody",
            "provider-trust acceptance for non-local adapters is a declared approval ref admitted by the planner, not yet a wallet.network crossing",
            "capability matrix values (modes/reasoning/speed/service_tier) are declared adapter metadata, not per-binary probed truth"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

pub(crate) async fn handle_harness_profile_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    match load_profile_record(&st.data_dir, &id) {
        Some(profile) => (StatusCode::OK, Json(json!({ "profile": profile }))),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "profile": id } })),
        ),
    }
}

pub(crate) async fn handle_harness_profile_probe(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    let Some(profile) = load_profile_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "profile": id } })),
        );
    };
    let profile_ref = s(&profile, "profile_ref", "");
    let runnability = probe_profile(&profile);
    let state = ps(&runnability, "/state", "not_probed");
    let receipt = profile_receipt(&st.data_dir, &profile_ref, "probed", &state, None);
    persist_runnability_locked(&st, &id, runnability.clone(), Some(&receipt));
    let transcript_run = post_op_transcript(&st.base_url, "probe", &profile_ref, &runnability).await;
    (
        StatusCode::OK,
        Json(json!({
            "profile_ref": profile_ref,
            "runnability": runnability,
            "receipt_ref": receipt,
            "transcript_recorded": transcript_run.is_some(),
            "transcript_run_id": transcript_run,
        })),
    )
}

async fn lifecycle_flip(
    st: &Arc<DaemonState>,
    id: &str,
    body: Option<&Value>,
    mutation_kind: &str,
    new_status: &str,
) -> (StatusCode, Json<Value>) {
    let Some(profile) = load_profile_record(&st.data_dir, id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "profile": id } })),
        );
    };
    let acceptance = body
        .and_then(|b| b.get("provider_trust_acceptance_ref"))
        .and_then(|v| v.as_str());
    match compose_mutation_admission(&profile, mutation_kind, None, None, acceptance) {
        Ok(admission) => {
            let profile_ref = s(&profile, "profile_ref", "");
            let receipt = profile_receipt(
                &st.data_dir,
                &profile_ref,
                mutation_kind,
                "ok",
                admission.get("admission_id").and_then(|v| v.as_str()),
            );
            // Reload-under-lock and apply on fresh state so a concurrent mutation isn't lost.
            let profile = {
                let _guard = st
                    .harness_profile_lock
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let mut fresh = load_profile_record(&st.data_dir, id).unwrap_or(profile);
                fresh["lifecycle"]["status"] = json!(new_status);
                stamp_admission(&mut fresh, &admission);
                if let Some(refs) = fresh["receipt_refs"].as_array_mut() {
                    refs.push(json!(receipt));
                }
                save_profile(&st.data_dir, &mut fresh);
                fresh
            };
            let transcript_run = post_op_transcript(
                &st.base_url,
                mutation_kind,
                &s(&profile, "profile_ref", ""),
                &json!({ "new_status": new_status }),
            )
            .await;
            (
                StatusCode::OK,
                Json(json!({
                    "profile": profile,
                    "admission_id": admission.get("admission_id"),
                    "receipt_ref": receipt,
                    "transcript_recorded": transcript_run.is_some(),
                })),
            )
        }
        Err((status, body)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
            Json(body),
        ),
    }
}

pub(crate) async fn handle_harness_profile_enable(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    lifecycle_flip(&st, &id, body.as_deref(), "enable_profile", "active").await
}

pub(crate) async fn handle_harness_profile_disable(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    lifecycle_flip(&st, &id, body.as_deref(), "disable_profile", "disabled").await
}

pub(crate) async fn handle_harness_profile_select_default(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    let Some(profile) = load_profile_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "profile": id } })),
        );
    };
    let acceptance = body
        .as_deref()
        .and_then(|b| b.get("provider_trust_acceptance_ref"))
        .and_then(|v| v.as_str());
    match compose_mutation_admission(&profile, "select_profile", None, None, acceptance) {
        Ok(admission) => {
            let profile_ref = s(&profile, "profile_ref", "");
            let receipt = profile_receipt(
                &st.data_dir,
                &profile_ref,
                "select_default",
                "ok",
                admission.get("admission_id").and_then(|v| v.as_str()),
            );
            // Hold the registry lock across clear-others + set-self (exactly-one invariant).
            let profile = {
                let _guard = st
                    .harness_profile_lock
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                for mut other in read_record_dir(&st.data_dir, RECORD_DIR) {
                    if other.get("default_profile").and_then(|v| v.as_bool()) == Some(true)
                        && s(&other, "profile_id", "") != id
                    {
                        other["default_profile"] = json!(false);
                        let other_ref = s(&other, "profile_ref", "");
                        profile_receipt(&st.data_dir, &other_ref, "default_cleared", "ok", None);
                        save_profile(&st.data_dir, &mut other);
                    }
                }
                let mut fresh = load_profile_record(&st.data_dir, &id).unwrap_or(profile);
                fresh["default_profile"] = json!(true);
                stamp_admission(&mut fresh, &admission);
                if let Some(refs) = fresh["receipt_refs"].as_array_mut() {
                    refs.push(json!(receipt));
                }
                save_profile(&st.data_dir, &mut fresh);
                fresh
            };
            let transcript_run =
                post_op_transcript(&st.base_url, "select_default", &profile_ref, &json!({})).await;
            (
                StatusCode::OK,
                Json(json!({
                    "profile": profile,
                    "admission_id": admission.get("admission_id"),
                    "receipt_ref": receipt,
                    "transcript_recorded": transcript_run.is_some(),
                })),
            )
        }
        Err((status, body)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
            Json(body),
        ),
    }
}

/// POST /v1/hypervisor/harness-profiles/:id/session-bindings — bind a profile to a session for
/// EXECUTION. Fail-closed, in order: profile active (412), execution lane wired for the execute
/// path — lane A only today (409), LIVE runnability probe passes (412), and the model route it
/// executes over is an active+available registry record (422 unresolved / 412 not available).
/// The planner then composes the admission; the binding record carries the at-bind evidence.
pub(crate) async fn handle_harness_profile_bind_session(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    let Some(profile) = load_profile_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "profile": id } })),
        );
    };
    let Some(session_ref) = body.get("session_ref").and_then(|v| v.as_str()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": "session_ref_required" } })),
        );
    };
    if ps(&profile, "/lifecycle/status", "declared") != "active" {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": {
                "code": "harness_profile_not_active",
                "message": "Only an active (admitted-enabled) harness profile binds to a session.",
                "lifecycle_status": ps(&profile, "/lifecycle/status", "declared")
            } })),
        );
    }
    let wiring = ps(&profile, "/adapter/execution_wiring", "adapter_slot_unwired");
    if wiring != "lane_a_host_spawn" {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": {
                "code": "harness_execution_lane_unsupported",
                "message": "Session execution bindings drive the Lane A host-spawn path today; terminal and adapter-slot profiles are not execution-bindable.",
                "execution_wiring": wiring
            } })),
        );
    }
    // LIVE runnability at bind time — persisted so the registry reflects what the bind saw.
    let runnability = probe_profile(&profile);
    let run_state = ps(&runnability, "/state", "not_probed");
    let mut profile =
        persist_runnability_locked(&st, &id, runnability.clone(), None).unwrap_or(profile);
    if run_state != "runnable" {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": {
                "code": "harness_profile_not_runnable",
                "message": "The live runnability probe did not pass; the profile cannot bind for execution.",
                "runnability": runnability
            } })),
        );
    }
    // Cross-registry truth: the model route must be an active+available registry record.
    let route_ref = body
        .get("model_route_ref")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            super::model_routes::ensure_seed(&st.data_dir);
            read_record_dir(&st.data_dir, super::model_routes::RECORD_DIR)
                .into_iter()
                .find(|r| r.get("default_route").and_then(|v| v.as_bool()) == Some(true))
                .map(|r| s(&r, "route_ref", ""))
                .unwrap_or_default()
        });
    let route_id = route_ref.strip_prefix("model-route:").unwrap_or(&route_ref);
    let Some(route) = super::model_routes::load_route_record(&st.data_dir, route_id) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": { "code": "model_route_ref_unresolved", "model_route_ref": route_ref } })),
        );
    };
    let route_active = ps(&route, "/lifecycle/status", "declared") == "active";
    let route_available = ps(&route, "/availability/state", "declared") == "available";
    if !route_active || !route_available {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": {
                "code": "model_route_not_available",
                "message": "The harness executes over a model route; it must be active and probe-available.",
                "lifecycle_status": ps(&route, "/lifecycle/status", "declared"),
                "availability_state": ps(&route, "/availability/state", "declared")
            } })),
        );
    }
    match compose_mutation_admission(
        &profile,
        "bind_session_profile",
        Some(session_ref),
        Some(&route_ref),
        None,
    ) {
        Ok(admission) => {
            let profile_ref = s(&profile, "profile_ref", "");
            let binding_id = format!("hpb_{:x}", nanos());
            let receipt = profile_receipt(
                &st.data_dir,
                &profile_ref,
                "bind_session",
                "ok",
                admission.get("admission_id").and_then(|v| v.as_str()),
            );
            let normalized_session = if session_ref.starts_with("session:") {
                session_ref.to_string()
            } else {
                format!("session:{session_ref}")
            };
            let binding = json!({
                "schema_version": BINDING_SCHEMA,
                "binding_id": binding_id,
                "profile_ref": profile_ref,
                "harness": s(&profile, "harness", ""),
                "session_ref": normalized_session,
                "model_route_ref": route_ref,
                "execution_wiring": wiring,
                "runnability_at_bind": runnability,
                "model_route_availability_at_bind": route.get("availability").cloned().unwrap_or(Value::Null),
                "admission_id": admission.get("admission_id"),
                "receipt_ref": receipt,
                "created_at": iso_now(),
                "runtimeTruthSource": "daemon-runtime"
            });
            let _ = persist_record(&st.data_dir, BINDING_DIR, &binding_id, &binding);
            {
                let _guard = st
                    .harness_profile_lock
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if let Some(mut fresh) = load_profile_record(&st.data_dir, &id) {
                    stamp_admission(&mut fresh, &admission);
                    if let Some(refs) = fresh["receipt_refs"].as_array_mut() {
                        refs.push(json!(receipt.clone()));
                    }
                    save_profile(&st.data_dir, &mut fresh);
                    profile = fresh;
                }
            }
            let _ = &profile;
            let transcript_run =
                post_op_transcript(&st.base_url, "bind_session", &profile_ref, &binding).await;
            (
                StatusCode::CREATED,
                Json(json!({
                    "binding": binding,
                    "transcript_recorded": transcript_run.is_some(),
                })),
            )
        }
        Err((status, body)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
            Json(body),
        ),
    }
}

pub(crate) async fn handle_harness_profile_bindings_list(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    let Some(profile) = load_profile_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "profile": id } })),
        );
    };
    let profile_ref = s(&profile, "profile_ref", "");
    let session_filter = params.get("session_ref").map(|v| {
        if v.starts_with("session:") {
            v.clone()
        } else {
            format!("session:{v}")
        }
    });
    let mut bindings: Vec<Value> = read_record_dir(&st.data_dir, BINDING_DIR)
        .into_iter()
        .filter(|b| s(b, "profile_ref", "") == profile_ref)
        .filter(|b| {
            session_filter
                .as_ref()
                .map(|f| &s(b, "session_ref", "") == f)
                .unwrap_or(true)
        })
        .collect();
    bindings.sort_by(|a, b| s(b, "created_at", "").cmp(&s(a, "created_at", "")));
    (
        StatusCode::OK,
        Json(json!({ "profile_ref": profile_ref, "bindings": bindings })),
    )
}

#[cfg(test)]
mod harness_profile_tests {
    use super::*;

    #[test]
    fn seed_set_covers_the_goal_adapters_with_one_default() {
        let seeds = seed_profiles();
        let keys: Vec<String> = seeds.iter().map(|p| s(p, "harness", "")).collect();
        for expected in [
            "hypervisor_worker",
            "shell",
            "opencode",
            "deepseek_tui",
            "claude_code",
            "codex",
        ] {
            assert!(keys.contains(&expected.to_string()), "missing {expected}");
        }
        let defaults = seeds
            .iter()
            .filter(|p| p.get("default_profile").and_then(|v| v.as_bool()) == Some(true))
            .count();
        assert_eq!(defaults, 1);
    }

    #[test]
    fn adapter_slots_are_declared_unwired_and_remote_trust_is_explicit() {
        let seeds = seed_profiles();
        for key in ["opencode", "deepseek_tui", "claude_code", "codex"] {
            let p = seeds.iter().find(|p| s(p, "harness", "") == key).unwrap();
            assert_eq!(ps(p, "/adapter/execution_wiring", ""), "adapter_slot_unwired");
            assert_eq!(ps(p, "/lifecycle/status", ""), "declared");
        }
        let claude = seeds
            .iter()
            .find(|p| s(p, "harness", "") == "claude_code")
            .unwrap();
        assert_eq!(ps(claude, "/adapter/provider_trust", ""), "remote_attested");
    }

    #[test]
    fn seed_default_composes_real_enable_admission() {
        let record = seed_profiles().into_iter().next().unwrap();
        let admission = compose_mutation_admission(&record, "enable_profile", None, None, None)
            .expect("local native worker enable admits");
        assert_eq!(admission["decision"], "admitted");
        assert!(admission["admission_id"]
            .as_str()
            .unwrap()
            .starts_with("harness-profile-mutation-admission:"));
    }

    #[test]
    fn remote_trust_enable_without_acceptance_is_planner_rejected() {
        let seeds = seed_profiles();
        let codex = seeds.iter().find(|p| s(p, "harness", "") == "codex").unwrap();
        let err = compose_mutation_admission(codex, "enable_profile", None, None, None)
            .expect_err("remote enable without acceptance rejects");
        assert_eq!(err.0, 403);
        assert_eq!(
            err.1.pointer("/error/code").and_then(|v| v.as_str()),
            Some("harness_profile_mutation_provider_trust_acceptance_required")
        );
    }

    #[test]
    fn unwired_profile_bind_is_planner_rejected() {
        let seeds = seed_profiles();
        let mut opencode = seeds
            .iter()
            .find(|p| s(p, "harness", "") == "opencode")
            .unwrap()
            .clone();
        opencode["runnability"] = json!({ "state": "runnable" });
        let err = compose_mutation_admission(
            &opencode,
            "bind_session_profile",
            Some("session:hyp-x"),
            Some("model-route:mrt_local_default"),
            None,
        )
        .expect_err("unwired bind rejects");
        assert_eq!(
            err.1.pointer("/error/code").and_then(|v| v.as_str()),
            Some("harness_profile_mutation_execution_unwired")
        );
    }
}
