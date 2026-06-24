//! T6 — cloud/remote provider lifecycle.
//!
//! An `EnvironmentProvider` trait + a registry let the SAME Session/Environment/WorkRun object
//! model project local AND remote providers; provider-native IDs are evidence refs only — daemon
//! truth records admitted operations, state roots, restore refs, and receipts.
//!
//! Providers: `local-microvm` (the Phase 1 lane, available), `loopback-runner` (the boring,
//! testable first remote-shaped target: a real separate runner workspace with real fs + exec,
//! proving the full create→ready→WorkRun→stop→archive→restore→recover→delete lifecycle and
//! local/remote equivalence), and `cloud-vpc` (honestly NOT_CONFIGURED until cloud creds are
//! present — never a fake remote; a declared host gap under `--require-remote-provider`).
//!
//! Ops are BODY-dispatched via POST /v1/hypervisor/provider-ops to avoid matchit route collisions.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, DaemonState};

fn nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}
fn safe(seg: &str) -> String {
    seg.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_")
}
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), to)?;
        }
    }
    Ok(())
}

fn provider_receipt(data_dir: &str, provider: &str, env_ref: &str, op: &str, outcome: &str) -> String {
    let id = format!("prc_{:x}", nanos());
    let receipt_ref = format!("agentgres://provider-receipt/{id}");
    let rec = json!({
        "schema_version": "ioi.hypervisor.provider-receipt.v1",
        "receipt_id": id, "receipt_ref": receipt_ref,
        "provider": provider, "environment_ref": env_ref, "op": op, "outcome": outcome, "at": iso_now()
    });
    let _ = persist_record(data_dir, "provider-receipts", &id, &rec);
    receipt_ref
}

/// The EnvironmentProvider adapter trait. Methods return JSON evidence (ProviderOperationRef /
/// ProviderEvidence / RestoreMaterialRef); the daemon — not the provider — owns truth.
trait EnvironmentProvider: Send + Sync {
    fn id(&self) -> &str;
    fn capabilities(&self) -> Value;
    /// (status, reason): "available" | "not_configured".
    fn status(&self) -> (&'static str, String);
    fn preflight(&self, plan: &Value) -> Value;
    fn create(&self, data_dir: &str, env_ref: &str, plan: &Value) -> Result<Value, String>;
    fn start(&self, data_dir: &str, env_ref: &str) -> Result<Value, String>;
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String>;
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String>;
    fn snapshot(&self, data_dir: &str, env_ref: &str) -> Result<Value, String>;
    fn restore(&self, data_dir: &str, env_ref: &str, material_ref: &str) -> Result<Value, String>;
    fn inject_outage(&self, data_dir: &str, env_ref: &str) -> Result<Value, String>;
    fn recover(&self, data_dir: &str, env_ref: &str) -> Result<Value, String>;
    fn delete(&self, data_dir: &str, env_ref: &str) -> Result<Value, String>;
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value;
}

// --- local-microvm: the Phase 1 lane (available; full lifecycle lives in environment_routes). ---
struct LocalMicrovmProvider;
impl EnvironmentProvider for LocalMicrovmProvider {
    fn id(&self) -> &str { "local-microvm" }
    fn capabilities(&self) -> Value {
        json!({ "monitors": ["cloud-hypervisor", "firecracker", "qemu"], "locality": "local", "isolation": "vm_kernel", "restore": true, "remote": false })
    }
    fn status(&self) -> (&'static str, String) { ("available", "local microVM node (Phase 1 lifecycle)".into()) }
    fn preflight(&self, _plan: &Value) -> Value { json!({ "admit": true, "provider": self.id(), "note": "local microVM provider; use the Phase 1 environment routes for the live VM lifecycle" }) }
    fn create(&self, _d: &str, env_ref: &str, _p: &Value) -> Result<Value, String> {
        Ok(json!({ "provider_operation_ref": format!("local-microvm://op/create/{env_ref}"), "delegates_to": "/v1/hypervisor/environments" }))
    }
    fn start(&self, _d: &str, env_ref: &str) -> Result<Value, String> { Ok(json!({ "provider_operation_ref": format!("local-microvm://op/start/{env_ref}") })) }
    fn workrun(&self, _d: &str, env_ref: &str, _c: &str) -> Result<Value, String> { Ok(json!({ "provider_operation_ref": format!("local-microvm://op/workrun/{env_ref}"), "delegates_to": "/v1/hypervisor/environments/:id/workruns/:wr/execute" })) }
    fn stop(&self, _d: &str, env_ref: &str) -> Result<Value, String> { Ok(json!({ "provider_operation_ref": format!("local-microvm://op/stop/{env_ref}") })) }
    fn snapshot(&self, _d: &str, env_ref: &str) -> Result<Value, String> { Ok(json!({ "restore_material_ref": format!("local-microvm://material/{env_ref}") })) }
    fn restore(&self, _d: &str, env_ref: &str, _m: &str) -> Result<Value, String> { Ok(json!({ "provider_operation_ref": format!("local-microvm://op/restore/{env_ref}") })) }
    fn inject_outage(&self, _d: &str, _e: &str) -> Result<Value, String> { Err("local-microvm outage injection is exercised by the Phase 1 verifier (WS-9)".into()) }
    fn recover(&self, _d: &str, env_ref: &str) -> Result<Value, String> { Ok(json!({ "provider_operation_ref": format!("local-microvm://op/recover/{env_ref}") })) }
    fn delete(&self, _d: &str, env_ref: &str) -> Result<Value, String> { Ok(json!({ "provider_operation_ref": format!("local-microvm://op/delete/{env_ref}") })) }
    fn observe(&self, _d: &str, env_ref: &str) -> Value { json!({ "provider": self.id(), "environment_ref": env_ref, "evidence": "see /v1/hypervisor/environments/:id status" }) }
}

// --- loopback-runner: a REAL second provider — a separate runner workspace, real fs + exec. ---
struct LoopbackRunnerProvider;
impl LoopbackRunnerProvider {
    fn root(data_dir: &str, env_ref: &str) -> PathBuf { Path::new(data_dir).join("providers/loopback").join(safe(env_ref)) }
    fn workspace(data_dir: &str, env_ref: &str) -> PathBuf { Self::root(data_dir, env_ref).join("workspace") }
    fn materials(data_dir: &str, env_ref: &str) -> PathBuf { Self::root(data_dir, env_ref).join("materials") }
    fn set_phase(data_dir: &str, env_ref: &str, phase: &str) {
        let root = Self::root(data_dir, env_ref);
        let _ = std::fs::create_dir_all(&root);
        let _ = std::fs::write(root.join("phase"), phase);
    }
    fn phase(data_dir: &str, env_ref: &str) -> String {
        std::fs::read_to_string(Self::root(data_dir, env_ref).join("phase")).unwrap_or_else(|_| "absent".into())
    }
    fn latest_material(data_dir: &str, env_ref: &str) -> Option<PathBuf> {
        let mats = Self::materials(data_dir, env_ref);
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&mats).ok()?.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
        entries.sort();
        entries.pop()
    }
}
impl EnvironmentProvider for LoopbackRunnerProvider {
    fn id(&self) -> &str { "loopback-runner" }
    fn capabilities(&self) -> Value {
        json!({ "monitors": ["runner-exec"], "locality": "local", "isolation": "process_runner", "restore": true, "remote": true, "transport": "loopback", "note": "remote-shaped provider over a local-loopback runner; proves the provider object model + full lifecycle without cloud creds" })
    }
    fn status(&self) -> (&'static str, String) { ("available", "loopback runner (boring, testable first remote-shaped target)".into()) }
    fn preflight(&self, plan: &Value) -> Value {
        json!({ "admit": true, "provider": self.id(), "region": "loopback", "data_locality": "local", "privacy": "local_private", "credentials_required": false, "recipe": plan.get("recipe").cloned().unwrap_or(Value::Null) })
    }
    fn create(&self, data_dir: &str, env_ref: &str, _plan: &Value) -> Result<Value, String> {
        let ws = Self::workspace(data_dir, env_ref);
        std::fs::create_dir_all(&ws).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(Self::materials(data_dir, env_ref)).map_err(|e| e.to_string())?;
        std::fs::write(ws.join("README.runner"), format!("loopback runner workspace for {env_ref}\n")).map_err(|e| e.to_string())?;
        Self::set_phase(data_dir, env_ref, "created");
        Ok(json!({ "provider_operation_ref": format!("loopback-runner://op/create/{}", safe(env_ref)), "workspace_root": ws.to_string_lossy(), "phase": "created" }))
    }
    fn start(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        if !Self::workspace(data_dir, env_ref).exists() { return Err("environment not created on loopback runner".into()); }
        Self::set_phase(data_dir, env_ref, "ready");
        Ok(json!({ "provider_operation_ref": format!("loopback-runner://op/start/{}", safe(env_ref)), "phase": "ready" }))
    }
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String> {
        let ws = Self::workspace(data_dir, env_ref);
        if Self::phase(data_dir, env_ref) != "ready" { return Err("runner not ready for WorkRun".into()); }
        let out = std::process::Command::new("sh").arg("-c").arg(command).current_dir(&ws).output().map_err(|e| e.to_string())?;
        Ok(json!({
            "provider_operation_ref": format!("loopback-runner://op/workrun/{}", safe(env_ref)),
            "exit_code": out.status.code().unwrap_or(-1),
            "stdout": String::from_utf8_lossy(&out.stdout).trim_end().to_string(),
            "stderr": String::from_utf8_lossy(&out.stderr).trim_end().to_string()
        }))
    }
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        Self::set_phase(data_dir, env_ref, "stopped");
        Ok(json!({ "provider_operation_ref": format!("loopback-runner://op/stop/{}", safe(env_ref)), "phase": "stopped" }))
    }
    fn snapshot(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let ws = Self::workspace(data_dir, env_ref);
        if !ws.exists() { return Err("nothing to snapshot".into()); }
        let stamp = format!("{:x}", nanos());
        let mat = Self::materials(data_dir, env_ref).join(&stamp);
        copy_tree(&ws, &mat).map_err(|e| e.to_string())?;
        Ok(json!({ "restore_material_ref": format!("loopback-runner://material/{}/{}", safe(env_ref), stamp), "agentgres_backed": true, "material_path": mat.to_string_lossy() }))
    }
    fn restore(&self, data_dir: &str, env_ref: &str, material_ref: &str) -> Result<Value, String> {
        let stamp = material_ref.rsplit('/').next().unwrap_or("");
        let mat = Self::materials(data_dir, env_ref).join(safe(stamp));
        if !mat.exists() { return Err(format!("restore material '{material_ref}' not found")); }
        let ws = Self::workspace(data_dir, env_ref);
        let _ = std::fs::remove_dir_all(&ws);
        copy_tree(&mat, &ws).map_err(|e| e.to_string())?;
        Self::set_phase(data_dir, env_ref, "ready");
        Ok(json!({ "provider_operation_ref": format!("loopback-runner://op/restore/{}", safe(env_ref)), "phase": "ready", "restored_from": material_ref }))
    }
    fn inject_outage(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        // Simulate a provider outage: the runner workspace is lost but snapshot material survives.
        std::fs::remove_dir_all(Self::workspace(data_dir, env_ref)).map_err(|e| e.to_string())?;
        Self::set_phase(data_dir, env_ref, "outage");
        Ok(json!({ "provider_operation_ref": format!("loopback-runner://op/outage/{}", safe(env_ref)), "phase": "outage", "workspace_lost": true }))
    }
    fn recover(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mat = Self::latest_material(data_dir, env_ref).ok_or("no restore material to recover from")?;
        let ws = Self::workspace(data_dir, env_ref);
        let _ = std::fs::remove_dir_all(&ws);
        copy_tree(&mat, &ws).map_err(|e| e.to_string())?;
        Self::set_phase(data_dir, env_ref, "ready");
        Ok(json!({ "provider_operation_ref": format!("loopback-runner://op/recover/{}", safe(env_ref)), "phase": "ready", "recovered_from": mat.file_name().map(|n| n.to_string_lossy().to_string()) }))
    }
    fn delete(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let root = Self::root(data_dir, env_ref);
        let _ = std::fs::remove_dir_all(&root);
        Ok(json!({ "provider_operation_ref": format!("loopback-runner://op/delete/{}", safe(env_ref)), "cleanup_verified": !root.exists() }))
    }
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value {
        let ws = Self::workspace(data_dir, env_ref);
        let files = std::fs::read_dir(&ws).map(|e| e.flatten().count()).unwrap_or(0);
        json!({ "provider": self.id(), "environment_ref": env_ref, "phase": Self::phase(data_dir, env_ref), "workspace_files": files })
    }
}

// --- cloud-vpc: honestly NOT_CONFIGURED unless cloud creds are present (no fake remote). ---
struct CloudVpcProvider;
impl CloudVpcProvider {
    fn endpoint() -> Option<String> { std::env::var("IOI_REMOTE_PROVIDER_ENDPOINT").ok().filter(|s| !s.trim().is_empty()) }
    fn not_configured() -> String { "REMOTE_PROVIDER_NOT_CONFIGURED — needs a real cloud/VPC endpoint + credentials (set IOI_REMOTE_PROVIDER_ENDPOINT + provider creds, authority-gated). Not faked.".into() }
}
impl EnvironmentProvider for CloudVpcProvider {
    fn id(&self) -> &str { "cloud-vpc" }
    fn capabilities(&self) -> Value { json!({ "locality": "remote", "isolation": "vm_kernel", "restore": true, "remote": true, "credentials_required": true, "authority_gated": true }) }
    fn status(&self) -> (&'static str, String) {
        if Self::endpoint().is_some() { ("available", "cloud/VPC endpoint configured".into()) } else { ("not_configured", Self::not_configured()) }
    }
    fn preflight(&self, _plan: &Value) -> Value {
        match Self::endpoint() { Some(ep) => json!({ "admit": true, "provider": self.id(), "endpoint": ep, "credentials_required": true }), None => json!({ "admit": false, "provider": self.id(), "reason": Self::not_configured() }) }
    }
    fn create(&self, _d: &str, _e: &str, _p: &Value) -> Result<Value, String> { Err(Self::not_configured()) }
    fn start(&self, _d: &str, _e: &str) -> Result<Value, String> { Err(Self::not_configured()) }
    fn workrun(&self, _d: &str, _e: &str, _c: &str) -> Result<Value, String> { Err(Self::not_configured()) }
    fn stop(&self, _d: &str, _e: &str) -> Result<Value, String> { Err(Self::not_configured()) }
    fn snapshot(&self, _d: &str, _e: &str) -> Result<Value, String> { Err(Self::not_configured()) }
    fn restore(&self, _d: &str, _e: &str, _m: &str) -> Result<Value, String> { Err(Self::not_configured()) }
    fn inject_outage(&self, _d: &str, _e: &str) -> Result<Value, String> { Err(Self::not_configured()) }
    fn recover(&self, _d: &str, _e: &str) -> Result<Value, String> { Err(Self::not_configured()) }
    fn delete(&self, _d: &str, _e: &str) -> Result<Value, String> { Err(Self::not_configured()) }
    fn observe(&self, _d: &str, _e: &str) -> Value { json!({ "provider": self.id(), "status": "not_configured", "reason": Self::not_configured() }) }
}

fn registry() -> Vec<Box<dyn EnvironmentProvider>> {
    vec![Box::new(LocalMicrovmProvider), Box::new(LoopbackRunnerProvider), Box::new(CloudVpcProvider)]
}
fn resolve(id: &str) -> Option<Box<dyn EnvironmentProvider>> {
    registry().into_iter().find(|p| p.id() == id)
}

/// GET /v1/hypervisor/providers — the provider registry with capabilities + honest status.
pub(crate) async fn handle_providers_list(State(_st): State<Arc<DaemonState>>) -> Json<Value> {
    let providers: Vec<Value> = registry().iter().map(|p| {
        let (status, reason) = p.status();
        json!({ "provider_ref": p.id(), "capabilities": p.capabilities(), "status": status, "reason": reason })
    }).collect();
    Json(json!({
        "schema_version": "ioi.hypervisor.providers.v1",
        "first_remote_provider_target": "other:loopback-runner",
        "providers": providers,
        "truth_rule": "provider-native IDs are evidence refs only; the daemon owns admitted ops, state roots, restore refs, and receipts",
        "at": iso_now()
    }))
}

/// POST /v1/hypervisor/provider-ops — body-dispatched provider lifecycle op (collision-safe).
/// Body: `{ provider_id, op, environment_ref?, plan?, command?, material_ref?, grant_ref? }`.
/// op ∈ preflight | create | start | workrun | stop | snapshot | restore | inject_outage |
/// recover | delete | observe. Records an admitted-operation record + a provider receipt.
pub(crate) async fn handle_provider_op(State(st): State<Arc<DaemonState>>, Json(body): Json<Value>) -> Json<Value> {
    let data_dir = &st.data_dir;
    let provider_id = body.get("provider_id").and_then(|v| v.as_str()).unwrap_or("");
    let op = body.get("op").and_then(|v| v.as_str()).unwrap_or("");
    let env_ref = body.get("environment_ref").and_then(|v| v.as_str()).unwrap_or("env-default").to_string();
    let Some(provider) = resolve(provider_id) else {
        return Json(json!({ "ok": false, "reason": format!("unknown provider '{provider_id}'") }));
    };

    // Remote/external providers require an authority grant for provider-credential materialization.
    let cap = provider.capabilities();
    let creds_required = cap.get("credentials_required").and_then(|v| v.as_bool()).unwrap_or(false);
    if creds_required && matches!(op, "create" | "start" | "workrun") && body.get("grant_ref").and_then(|v| v.as_str()).is_none() {
        let receipt = provider_receipt(data_dir, provider_id, &env_ref, op, "authority_missing");
        return Json(json!({ "ok": false, "op": op, "provider": provider_id, "reason": "provider credentials are authority-gated; present a grant_ref (effect=provider_credential)", "receipt_ref": receipt }));
    }

    let plan = body.get("plan").cloned().unwrap_or_else(|| json!({}));
    let command = body.get("command").and_then(|v| v.as_str()).unwrap_or("true");
    let material_ref = body.get("material_ref").and_then(|v| v.as_str()).unwrap_or("");
    let result = match op {
        "preflight" => Ok(provider.preflight(&plan)),
        "create" => provider.create(data_dir, &env_ref, &plan),
        "start" => provider.start(data_dir, &env_ref),
        "workrun" => provider.workrun(data_dir, &env_ref, command),
        "stop" => provider.stop(data_dir, &env_ref),
        "snapshot" => provider.snapshot(data_dir, &env_ref),
        "restore" => provider.restore(data_dir, &env_ref, material_ref),
        "inject_outage" => provider.inject_outage(data_dir, &env_ref),
        "recover" => provider.recover(data_dir, &env_ref),
        "delete" => provider.delete(data_dir, &env_ref),
        "observe" => Ok(provider.observe(data_dir, &env_ref)),
        other => Err(format!("unknown op '{other}'")),
    };

    match result {
        Ok(evidence) => {
            let receipt = provider_receipt(data_dir, provider_id, &env_ref, op, "ok");
            // Record the admitted operation as daemon truth (provider IDs inside are evidence only).
            let op_id = format!("pop_{:x}", nanos());
            let record = json!({
                "schema_version": "ioi.hypervisor.provider-operation.v1",
                "operation_id": op_id, "provider": provider_id, "environment_ref": env_ref,
                "op": op, "evidence": evidence, "receipt_ref": receipt, "at": iso_now()
            });
            let _ = persist_record(data_dir, "provider-operations", &op_id, &record);
            Json(json!({ "ok": true, "op": op, "provider": provider_id, "environment_ref": env_ref, "evidence": evidence, "receipt_ref": receipt }))
        }
        Err(reason) => {
            let outcome = if reason.contains("NOT_CONFIGURED") { "not_configured" } else { "error" };
            let receipt = provider_receipt(data_dir, provider_id, &env_ref, op, outcome);
            Json(json!({ "ok": false, "op": op, "provider": provider_id, "environment_ref": env_ref, "reason": reason, "outcome": outcome, "receipt_ref": receipt }))
        }
    }
}

/// GET /v1/hypervisor/provider-operations — the admitted-operation audit trail (daemon truth).
pub(crate) async fn handle_provider_operations(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut ops = super::read_record_dir(&st.data_dir, "provider-operations");
    ops.sort_by(|a, b| b.get("operation_id").and_then(|v| v.as_str()).unwrap_or("").cmp(a.get("operation_id").and_then(|v| v.as_str()).unwrap_or("")));
    Json(json!({ "schema_version": "ioi.hypervisor.provider-operations.v1", "operations": ops, "at": iso_now() }))
}
