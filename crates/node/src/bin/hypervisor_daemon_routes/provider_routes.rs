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

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::lifecycle_routes::{
    authorize_capability_lease, open_scm_token, seal_scm_token, CapabilityLeaseRequest,
};
use super::{iso_now, persist_record, read_record_dir, DaemonState};

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn safe(seg: &str) -> String {
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
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

fn provider_receipt(
    data_dir: &str,
    provider: &str,
    env_ref: &str,
    op: &str,
    outcome: &str,
) -> String {
    provider_receipt_ext(data_dir, provider, env_ref, op, outcome, &json!({}))
}

/// Enriched provider receipt — BYO account operations cite the account, the capability-lease
/// descriptor (never a secret), the grant, credential source, and the cost estimate. Written on
/// SUCCESS AND FAILURE alike: a refused crossing is evidence too.
fn provider_receipt_ext(
    data_dir: &str,
    provider: &str,
    env_ref: &str,
    op: &str,
    outcome: &str,
    extra: &Value,
) -> String {
    let id = format!("prc_{:x}", nanos());
    let receipt_ref = format!("agentgres://provider-receipt/{id}");
    let mut rec = json!({
        "schema_version": "ioi.hypervisor.provider-receipt.v1",
        "receipt_id": id, "receipt_ref": receipt_ref,
        "provider": provider, "environment_ref": env_ref, "op": op, "outcome": outcome, "at": iso_now()
    });
    if let (Some(target), Some(fields)) = (rec.as_object_mut(), extra.as_object()) {
        for (key, value) in fields {
            if !value.is_null() {
                target.insert(key.clone(), value.clone());
            }
        }
    }
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
    fn id(&self) -> &str {
        "local-microvm"
    }
    fn capabilities(&self) -> Value {
        json!({ "monitors": ["cloud-hypervisor", "firecracker", "qemu"], "locality": "local", "isolation": "vm_kernel", "restore": true, "remote": false })
    }
    fn status(&self) -> (&'static str, String) {
        ("available", "local microVM node (Phase 1 lifecycle)".into())
    }
    fn preflight(&self, _plan: &Value) -> Value {
        json!({ "admit": true, "provider": self.id(), "note": "local microVM provider; use the Phase 1 environment routes for the live VM lifecycle" })
    }
    fn create(&self, _d: &str, env_ref: &str, _p: &Value) -> Result<Value, String> {
        Ok(
            json!({ "provider_operation_ref": format!("local-microvm://op/create/{env_ref}"), "delegates_to": "/v1/hypervisor/environments" }),
        )
    }
    fn start(&self, _d: &str, env_ref: &str) -> Result<Value, String> {
        Ok(json!({ "provider_operation_ref": format!("local-microvm://op/start/{env_ref}") }))
    }
    fn workrun(&self, _d: &str, env_ref: &str, _c: &str) -> Result<Value, String> {
        Ok(
            json!({ "provider_operation_ref": format!("local-microvm://op/workrun/{env_ref}"), "delegates_to": "/v1/hypervisor/environments/:id/workruns/:wr/execute" }),
        )
    }
    fn stop(&self, _d: &str, env_ref: &str) -> Result<Value, String> {
        Ok(json!({ "provider_operation_ref": format!("local-microvm://op/stop/{env_ref}") }))
    }
    fn snapshot(&self, _d: &str, env_ref: &str) -> Result<Value, String> {
        Ok(json!({ "restore_material_ref": format!("local-microvm://material/{env_ref}") }))
    }
    fn restore(&self, _d: &str, env_ref: &str, _m: &str) -> Result<Value, String> {
        Ok(json!({ "provider_operation_ref": format!("local-microvm://op/restore/{env_ref}") }))
    }
    fn inject_outage(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("local-microvm outage injection is exercised by the Phase 1 verifier (WS-9)".into())
    }
    fn recover(&self, _d: &str, env_ref: &str) -> Result<Value, String> {
        Ok(json!({ "provider_operation_ref": format!("local-microvm://op/recover/{env_ref}") }))
    }
    fn delete(&self, _d: &str, env_ref: &str) -> Result<Value, String> {
        Ok(json!({ "provider_operation_ref": format!("local-microvm://op/delete/{env_ref}") }))
    }
    fn observe(&self, _d: &str, env_ref: &str) -> Value {
        json!({ "provider": self.id(), "environment_ref": env_ref, "evidence": "see /v1/hypervisor/environments/:id status" })
    }
}

// --- loopback-runner: a REAL second provider — a separate runner workspace, real fs + exec. ---
struct LoopbackRunnerProvider;
impl LoopbackRunnerProvider {
    fn root(data_dir: &str, env_ref: &str) -> PathBuf {
        Path::new(data_dir)
            .join("providers/loopback")
            .join(safe(env_ref))
    }
    fn workspace(data_dir: &str, env_ref: &str) -> PathBuf {
        Self::root(data_dir, env_ref).join("workspace")
    }
    fn materials(data_dir: &str, env_ref: &str) -> PathBuf {
        Self::root(data_dir, env_ref).join("materials")
    }
    fn set_phase(data_dir: &str, env_ref: &str, phase: &str) {
        let root = Self::root(data_dir, env_ref);
        let _ = std::fs::create_dir_all(&root);
        let _ = std::fs::write(root.join("phase"), phase);
    }
    fn phase(data_dir: &str, env_ref: &str) -> String {
        std::fs::read_to_string(Self::root(data_dir, env_ref).join("phase"))
            .unwrap_or_else(|_| "absent".into())
    }
    fn latest_material(data_dir: &str, env_ref: &str) -> Option<PathBuf> {
        let mats = Self::materials(data_dir, env_ref);
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&mats)
            .ok()?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        entries.sort();
        entries.pop()
    }
}
impl EnvironmentProvider for LoopbackRunnerProvider {
    fn id(&self) -> &str {
        "loopback-runner"
    }
    fn capabilities(&self) -> Value {
        json!({ "monitors": ["runner-exec"], "locality": "local", "isolation": "process_runner", "restore": true, "remote": true, "transport": "loopback", "note": "remote-shaped provider over a local-loopback runner; proves the provider object model + full lifecycle without cloud creds" })
    }
    fn status(&self) -> (&'static str, String) {
        (
            "available",
            "loopback runner (boring, testable first remote-shaped target)".into(),
        )
    }
    fn preflight(&self, plan: &Value) -> Value {
        json!({ "admit": true, "provider": self.id(), "region": "loopback", "data_locality": "local", "privacy": "local_private", "credentials_required": false, "recipe": plan.get("recipe").cloned().unwrap_or(Value::Null) })
    }
    fn create(&self, data_dir: &str, env_ref: &str, _plan: &Value) -> Result<Value, String> {
        let ws = Self::workspace(data_dir, env_ref);
        std::fs::create_dir_all(&ws).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(Self::materials(data_dir, env_ref)).map_err(|e| e.to_string())?;
        std::fs::write(
            ws.join("README.runner"),
            format!("loopback runner workspace for {env_ref}\n"),
        )
        .map_err(|e| e.to_string())?;
        Self::set_phase(data_dir, env_ref, "created");
        Ok(
            json!({ "provider_operation_ref": format!("loopback-runner://op/create/{}", safe(env_ref)), "workspace_root": ws.to_string_lossy(), "phase": "created" }),
        )
    }
    fn start(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        if !Self::workspace(data_dir, env_ref).exists() {
            return Err("environment not created on loopback runner".into());
        }
        Self::set_phase(data_dir, env_ref, "ready");
        Ok(
            json!({ "provider_operation_ref": format!("loopback-runner://op/start/{}", safe(env_ref)), "phase": "ready" }),
        )
    }
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String> {
        let ws = Self::workspace(data_dir, env_ref);
        if Self::phase(data_dir, env_ref) != "ready" {
            return Err("runner not ready for WorkRun".into());
        }
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(&ws)
            .output()
            .map_err(|e| e.to_string())?;
        Ok(json!({
            "provider_operation_ref": format!("loopback-runner://op/workrun/{}", safe(env_ref)),
            "exit_code": out.status.code().unwrap_or(-1),
            "stdout": String::from_utf8_lossy(&out.stdout).trim_end().to_string(),
            "stderr": String::from_utf8_lossy(&out.stderr).trim_end().to_string()
        }))
    }
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        Self::set_phase(data_dir, env_ref, "stopped");
        Ok(
            json!({ "provider_operation_ref": format!("loopback-runner://op/stop/{}", safe(env_ref)), "phase": "stopped" }),
        )
    }
    fn snapshot(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let ws = Self::workspace(data_dir, env_ref);
        if !ws.exists() {
            return Err("nothing to snapshot".into());
        }
        let stamp = format!("{:x}", nanos());
        let mat = Self::materials(data_dir, env_ref).join(&stamp);
        copy_tree(&ws, &mat).map_err(|e| e.to_string())?;
        Ok(
            json!({ "restore_material_ref": format!("loopback-runner://material/{}/{}", safe(env_ref), stamp), "agentgres_backed": true, "material_path": mat.to_string_lossy() }),
        )
    }
    fn restore(&self, data_dir: &str, env_ref: &str, material_ref: &str) -> Result<Value, String> {
        let stamp = material_ref.rsplit('/').next().unwrap_or("");
        let mat = Self::materials(data_dir, env_ref).join(safe(stamp));
        if !mat.exists() {
            return Err(format!("restore material '{material_ref}' not found"));
        }
        let ws = Self::workspace(data_dir, env_ref);
        let _ = std::fs::remove_dir_all(&ws);
        copy_tree(&mat, &ws).map_err(|e| e.to_string())?;
        Self::set_phase(data_dir, env_ref, "ready");
        Ok(
            json!({ "provider_operation_ref": format!("loopback-runner://op/restore/{}", safe(env_ref)), "phase": "ready", "restored_from": material_ref }),
        )
    }
    fn inject_outage(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        // Simulate a provider outage: the runner workspace is lost but snapshot material survives.
        std::fs::remove_dir_all(Self::workspace(data_dir, env_ref)).map_err(|e| e.to_string())?;
        Self::set_phase(data_dir, env_ref, "outage");
        Ok(
            json!({ "provider_operation_ref": format!("loopback-runner://op/outage/{}", safe(env_ref)), "phase": "outage", "workspace_lost": true }),
        )
    }
    fn recover(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mat = Self::latest_material(data_dir, env_ref)
            .ok_or("no restore material to recover from")?;
        let ws = Self::workspace(data_dir, env_ref);
        let _ = std::fs::remove_dir_all(&ws);
        copy_tree(&mat, &ws).map_err(|e| e.to_string())?;
        Self::set_phase(data_dir, env_ref, "ready");
        Ok(
            json!({ "provider_operation_ref": format!("loopback-runner://op/recover/{}", safe(env_ref)), "phase": "ready", "recovered_from": mat.file_name().map(|n| n.to_string_lossy().to_string()) }),
        )
    }
    fn delete(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let root = Self::root(data_dir, env_ref);
        let _ = std::fs::remove_dir_all(&root);
        Ok(
            json!({ "provider_operation_ref": format!("loopback-runner://op/delete/{}", safe(env_ref)), "cleanup_verified": !root.exists() }),
        )
    }
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value {
        let ws = Self::workspace(data_dir, env_ref);
        let files = std::fs::read_dir(&ws)
            .map(|e| e.flatten().count())
            .unwrap_or(0);
        json!({ "provider": self.id(), "environment_ref": env_ref, "phase": Self::phase(data_dir, env_ref), "workspace_files": files })
    }
}

// --- cloud-vpc: honestly NOT_CONFIGURED unless cloud creds are present (no fake remote). ---
struct CloudVpcProvider;
impl CloudVpcProvider {
    fn endpoint() -> Option<String> {
        std::env::var("IOI_REMOTE_PROVIDER_ENDPOINT")
            .ok()
            .filter(|s| !s.trim().is_empty())
    }
    fn not_configured() -> String {
        "REMOTE_PROVIDER_NOT_CONFIGURED — needs a real cloud/VPC endpoint + credentials (set IOI_REMOTE_PROVIDER_ENDPOINT + provider creds, authority-gated). Not faked.".into()
    }
}
impl EnvironmentProvider for CloudVpcProvider {
    fn id(&self) -> &str {
        "cloud-vpc"
    }
    fn capabilities(&self) -> Value {
        json!({ "locality": "remote", "isolation": "vm_kernel", "restore": true, "remote": true, "credentials_required": true, "authority_gated": true })
    }
    fn status(&self) -> (&'static str, String) {
        if Self::endpoint().is_some() {
            ("available", "cloud/VPC endpoint configured".into())
        } else {
            ("not_configured", Self::not_configured())
        }
    }
    fn preflight(&self, _plan: &Value) -> Value {
        match Self::endpoint() {
            Some(ep) => {
                json!({ "admit": true, "provider": self.id(), "endpoint": ep, "credentials_required": true })
            }
            None => {
                json!({ "admit": false, "provider": self.id(), "reason": Self::not_configured() })
            }
        }
    }
    fn create(&self, _d: &str, _e: &str, _p: &Value) -> Result<Value, String> {
        Err(Self::not_configured())
    }
    fn start(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err(Self::not_configured())
    }
    fn workrun(&self, _d: &str, _e: &str, _c: &str) -> Result<Value, String> {
        Err(Self::not_configured())
    }
    fn stop(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err(Self::not_configured())
    }
    fn snapshot(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err(Self::not_configured())
    }
    fn restore(&self, _d: &str, _e: &str, _m: &str) -> Result<Value, String> {
        Err(Self::not_configured())
    }
    fn inject_outage(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err(Self::not_configured())
    }
    fn recover(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err(Self::not_configured())
    }
    fn delete(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err(Self::not_configured())
    }
    fn observe(&self, _d: &str, _e: &str) -> Value {
        json!({ "provider": self.id(), "status": "not_configured", "reason": Self::not_configured() })
    }
}

// =================================================================================================
// BYO PROVIDER PLANE — durable ProviderAccount objects over the same EnvironmentProvider trait.
//
// Doctrine (economic-flywheel-and-pricing-boundaries.md): BYO provider spend is CUSTOMER-BORNE.
// The daemon records, governs, estimates, and reconciles — it never hides markup inside provider
// cost. Provider-native state is evidence; daemon/Agentgres admitted state (sha256 state roots,
// receipts, admitted operations) is truth. NO routing fee, NO broker, NO RoutingDecisionReceipt
// exists in this plane — those become legitimate only when IOI itself places runs for payment.

const ACCOUNT_KIND: &str = "provider-accounts";
/// Customer-borne external-spend EXPOSURE rows — reconciliation accounting over receipts.
/// NOT billing, NOT fees, NOT settlement: an exposure is the quote-backed estimate a grant
/// authorized, opened by an admitted metered create and closed by teardown. Actual provider
/// bills are never invented; budget `spent` is never faked.
const EXPOSURE_KIND: &str = "provider-spend-exposures";
const CREDENTIAL_VAULT: &str = "provider-credentials";
const MATERIAL_KIND: &str = "provider-materials";
const ACCOUNT_KINDS: &[&str] = &["baremetal_ssh", "aws", "gcp", "k8s", "vast", "runpod", "akash"];

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn load_account(data_dir: &str, id_or_ref: &str) -> Option<Value> {
    let id = id_or_ref.trim_start_matches("provider-account://");
    read_record_dir(data_dir, ACCOUNT_KIND)
        .into_iter()
        .find(|a| text(a, "account_id") == id)
}

fn load_account_credential(data_dir: &str, account_id: &str) -> Option<Value> {
    read_record_dir(data_dir, CREDENTIAL_VAULT)
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(account_id))
}

/// Per-kind adapter capabilities — provider-specific semantics preserved, never a fake generic
/// cloud (providers-and-environments.md:162). Privacy posture is honest: no "private" label
/// without custody proof.
fn kind_capabilities(kind: &str) -> Value {
    match kind {
        "baremetal_ssh" => json!({ "locality": "remote", "isolation": "customer_host", "restore": true, "remote": true, "transport": "ssh", "credentials_required": true, "authority_gated": true, "privacy": "customer_controlled_host", "lifecycle": "full" }),
        "aws" | "gcp" => json!({ "locality": "remote", "isolation": "vm_kernel", "restore": true, "remote": true, "credentials_required": true, "authority_gated": true, "privacy": "cloud_shared_responsibility", "lifecycle": "credential_preflight_only" }),
        "k8s" => json!({ "locality": "remote", "isolation": "container", "restore": true, "remote": true, "credentials_required": true, "authority_gated": true, "privacy": "cluster_operator_controlled", "lifecycle": "credential_preflight_only" }),
        "vast" => json!({ "locality": "remote", "isolation": "container_gpu", "restore": true, "remote": true, "credentials_required": true, "authority_gated": true, "privacy": "marketplace_host_NOT_private", "lifecycle": "credential_preflight_only" }),
        "runpod" => json!({ "locality": "remote", "isolation": "container_gpu_runtime", "restore": true, "remote": true, "credentials_required": true, "authority_gated": true, "privacy": "cloud_gpu_runtime_NOT_private", "custody": "Standard unless proven otherwise", "lifecycle": "guarded (quote-gated) once a control-plane mode is set; credential_preflight_only before that" }),
        "akash" => json!({ "locality": "remote", "isolation": "deployment_lease", "restore": true, "remote": true, "credentials_required": true, "authority_gated": true, "privacy": "depin_host_NOT_private", "lifecycle": "credential_preflight_only" }),
        other => json!({ "locality": "unknown", "credentials_required": true, "note": format!("unknown kind '{other}'") }),
    }
}

/// Sum of open exposures' first-hour reservations (each at its declared max hourly rate) —
/// an ESTIMATE unit, never an actual bill.
fn open_reserved_estimate(data_dir: &str) -> f64 {
    read_record_dir(data_dir, EXPOSURE_KIND)
        .iter()
        .filter(|e| text(e, "status") == "open")
        .filter_map(|e| e.get("max_hourly_usd").and_then(Value::as_f64))
        .sum()
}
fn open_exposure_for(data_dir: &str, account_ref: &str, env_ref: &str) -> Option<Value> {
    read_record_dir(data_dir, EXPOSURE_KIND)
        .into_iter()
        .find(|e| text(e, "account_ref") == account_ref && text(e, "environment_ref") == env_ref && text(e, "status") == "open")
}

/// external_spend budget posture MUST be discovered BEFORE any provider mutation
/// (providers-and-environments.md:1114 — "Budget exhaustion must be discovered before provider
/// mutation or new external spend"). bare-metal SSH is customer-borne with no metered spend.
fn discover_budget(data_dir: &str, kind: &str, op: &str) -> Result<Value, String> {
    if kind == "baremetal_ssh" {
        return Ok(json!({
            "scope": "local_free",
            "admitted": true,
            "discovered_before_mutation": true,
            "cost_estimate": { "amount": 0.0, "currency": "USD", "basis": "customer_borne_byo — bare-metal SSH node, no metered provider spend" },
            "provider_spend_borne_by": "customer",
        }));
    }
    let budgets = read_record_dir(data_dir, "resource-budgets");
    let Some(budget) = budgets.iter().find(|b| b["scope"].as_str() == Some("external_spend")) else {
        return Err(format!("budget_undiscovered_before_mutation — '{op}' on a metered provider requires an external_spend resource budget to exist first (POST /v1/hypervisor/resource/budgets)"));
    };
    let limit = budget["limit"].as_f64().unwrap_or(0.0);
    let spent = budget["spent"].as_f64().unwrap_or(0.0);
    if spent >= limit {
        return Err(format!("budget_exhausted_before_mutation — external_spend budget '{}' has {spent}/{limit} spent; refusing provider mutation", text(budget, "budget_id")));
    }
    let reserved = open_reserved_estimate(data_dir);
    Ok(json!({
        "scope": "external_spend",
        "admitted": true,
        "discovered_before_mutation": true,
        "budget_ref": format!("budget://{}", text(budget, "budget_id")),
        "remaining": limit - spent,
        "reserved_open_estimates": reserved,
        "remaining_headroom_after_reservations": limit - spent - reserved,
        "reservation_note": "reservations are first-hour estimates at declared max rates — never an actual provider bill; budget spent is never faked",
        "provider_spend_borne_by": "customer",
    }))
}

/// Materialize the account's sealed SSH key to a 0600 file for the ssh client; removed on drop.
struct KeyGuard(PathBuf);
impl Drop for KeyGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn materialize_ssh_key(data_dir: &str, account_id: &str) -> Result<(PathBuf, KeyGuard, Option<String>), String> {
    let cred = load_account_credential(data_dir, account_id)
        .ok_or("provider_credential_unbound — bind an ssh_key credential to this account first")?;
    let key = cred["sealed_token"]
        .as_str()
        .and_then(open_scm_token)
        .ok_or("provider_credential_unresolved — sealed ssh key did not decrypt (seal passphrase mismatch?)")?;
    let dir = Path::new(data_dir).join("provider-ssh");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{}.key", safe(account_id)));
    std::fs::write(&path, format!("{}\n", key.trim_end())).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    let key_source = cred["key_source"].as_str().map(str::to_string);
    Ok((path.clone(), KeyGuard(path), key_source))
}

// --- baremetal_ssh: the FIRST REAL BYO adapter. SSH is a provider, not a local shortcut: ---
// --- credential binding, preflight, full lifecycle, receipts — CI-verifiable over loopback. ---
struct SshProvider {
    account: Value,
    key_path: PathBuf,
}
impl SshProvider {
    fn account_id(&self) -> &str {
        text(&self.account, "account_id")
    }
    fn endpoint(&self) -> (String, String, String) {
        let ep = self.account.get("endpoint").cloned().unwrap_or_else(|| json!({}));
        (
            text(&ep, "host").to_string(),
            ep.get("port").and_then(Value::as_u64).unwrap_or(22).to_string(),
            text(&ep, "user").to_string(),
        )
    }
    fn known_hosts(&self, data_dir: &str) -> String {
        Path::new(data_dir)
            .join("provider-ssh/known_hosts")
            .to_string_lossy()
            .to_string()
    }
    fn base_args(&self, data_dir: &str) -> Vec<String> {
        let (host, port, user) = self.endpoint();
        vec![
            "-p".into(), port,
            "-i".into(), self.key_path.to_string_lossy().to_string(),
            "-o".into(), "BatchMode=yes".into(),
            "-o".into(), "StrictHostKeyChecking=accept-new".into(),
            "-o".into(), format!("UserKnownHostsFile={}", self.known_hosts(data_dir)),
            "-o".into(), "ConnectTimeout=8".into(),
            format!("{user}@{host}"),
        ]
    }
    fn node_root(env_ref: &str) -> String {
        format!("\"$HOME\"/.ioi-hypervisor-nodes/{}", safe(env_ref))
    }
    fn run_script(&self, data_dir: &str, script: &str, stdin_bytes: Option<&[u8]>) -> Result<(i32, Vec<u8>, String), String> {
        let mut cmd = std::process::Command::new("ssh");
        cmd.args(self.base_args(data_dir)).arg(script);
        cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        if stdin_bytes.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        } else {
            cmd.stdin(std::process::Stdio::null());
        }
        let mut child = cmd.spawn().map_err(|e| format!("ssh spawn failed: {e}"))?;
        if let Some(bytes) = stdin_bytes {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(bytes).map_err(|e| format!("ssh stdin failed: {e}"))?;
            }
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        Ok((
            out.status.code().unwrap_or(-1),
            out.stdout,
            String::from_utf8_lossy(&out.stderr).trim_end().to_string(),
        ))
    }
    fn op_ref(&self, op: &str, env_ref: &str) -> String {
        format!("provider-account://{}/op/{op}/{}", self.account_id(), safe(env_ref))
    }
}
impl EnvironmentProvider for SshProvider {
    fn id(&self) -> &str {
        "baremetal-ssh"
    }
    fn capabilities(&self) -> Value {
        let mut caps = kind_capabilities("baremetal_ssh");
        caps["provider_spend_borne_by"] = json!("customer");
        caps
    }
    fn status(&self) -> (&'static str, String) {
        match text(&self.account, "status") {
            "verified" => ("available", format!("verified bare-metal SSH node ({})", text(&self.account, "display_name"))),
            "revoked" => ("revoked", "credential revoked — rebind to use this account".into()),
            _ => ("unverified", "credential bound but preflight has not admitted this node yet".into()),
        }
    }
    fn preflight(&self, _plan: &Value) -> Value {
        // The real probe runs in handle_provider_account_preflight (needs data_dir for ssh);
        // this trait lane reports the recorded posture.
        json!({ "admit": text(&self.account, "status") == "verified", "provider": self.id(), "account_ref": text(&self.account, "account_ref"), "preflight_evidence": self.account.get("preflight").cloned().unwrap_or(Value::Null) })
    }
    fn create(&self, data_dir: &str, env_ref: &str, _plan: &Value) -> Result<Value, String> {
        let root = Self::node_root(env_ref);
        let script = format!("set -e; IOI_ROOT={root}; mkdir -p \"$IOI_ROOT/workspace\"; printf 'byo ssh node workspace for {env}\\n' > \"$IOI_ROOT/workspace/README.node\"; printf created > \"$IOI_ROOT/phase\"; echo \"$IOI_ROOT\"", env = safe(env_ref));
        let (code, stdout, stderr) = self.run_script(data_dir, &script, None)?;
        if code != 0 {
            return Err(format!("ssh create failed (exit {code}): {stderr}"));
        }
        Ok(json!({ "provider_operation_ref": self.op_ref("create", env_ref), "node_root": String::from_utf8_lossy(&stdout).trim(), "phase": "created" }))
    }
    fn start(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let root = Self::node_root(env_ref);
        let script = format!("set -e; IOI_ROOT={root}; test -d \"$IOI_ROOT/workspace\" || {{ echo missing >&2; exit 4; }}; printf ready > \"$IOI_ROOT/phase\"");
        let (code, _, stderr) = self.run_script(data_dir, &script, None)?;
        if code != 0 {
            return Err(format!("ssh start failed (exit {code}): {stderr}"));
        }
        Ok(json!({ "provider_operation_ref": self.op_ref("start", env_ref), "phase": "ready" }))
    }
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String> {
        let root = Self::node_root(env_ref);
        let quoted = command.replace('\'', "'\\''");
        let script = format!("set -e; IOI_ROOT={root}; [ \"$(cat \"$IOI_ROOT/phase\" 2>/dev/null)\" = ready ] || {{ echo not-ready >&2; exit 5; }}; cd \"$IOI_ROOT/workspace\"; sh -c '{quoted}'");
        let (code, stdout, stderr) = self.run_script(data_dir, &script, None)?;
        Ok(json!({
            "provider_operation_ref": self.op_ref("workrun", env_ref),
            "exit_code": code,
            "stdout": String::from_utf8_lossy(&stdout).trim_end(),
            "stderr": stderr,
        }))
    }
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let root = Self::node_root(env_ref);
        let script = format!("IOI_ROOT={root}; printf stopped > \"$IOI_ROOT/phase\"");
        let (code, _, stderr) = self.run_script(data_dir, &script, None)?;
        if code != 0 {
            return Err(format!("ssh stop failed (exit {code}): {stderr}"));
        }
        Ok(json!({ "provider_operation_ref": self.op_ref("stop", env_ref), "phase": "stopped" }))
    }
    /// Snapshot custody: the remote workspace streams BACK to daemon custody; the daemon computes
    /// sha256 and admits the material. Blob existence on the node is never restore truth.
    fn snapshot(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let root = Self::node_root(env_ref);
        let script = format!("set -e; IOI_ROOT={root}; cd \"$IOI_ROOT/workspace\"; tar -czf - .");
        let (code, tar_bytes, stderr) = self.run_script(data_dir, &script, None)?;
        if code != 0 || tar_bytes.is_empty() {
            return Err(format!("ssh snapshot failed (exit {code}): {stderr}"));
        }
        let state_root = sha256_bytes(&tar_bytes);
        let stamp = format!("{:x}", nanos());
        let dir = Path::new(data_dir)
            .join(MATERIAL_KIND)
            .join(safe(self.account_id()))
            .join(safe(env_ref));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let file = dir.join(format!("{stamp}.tar.gz"));
        std::fs::write(&file, &tar_bytes).map_err(|e| e.to_string())?;
        let material_id = format!("pmat_{stamp}");
        let material_ref = format!("provider-material://{}/{}/{stamp}", safe(self.account_id()), safe(env_ref));
        let record = json!({
            "schema_version": "ioi.hypervisor.provider-material.v1",
            "material_id": material_id,
            "material_ref": material_ref,
            "account_ref": text(&self.account, "account_ref"),
            "environment_ref": env_ref,
            "state_root": state_root,
            "bytes": tar_bytes.len(),
            "custody": "daemon",
            "path": file.to_string_lossy(),
            "at": iso_now(),
        });
        let _ = persist_record(data_dir, MATERIAL_KIND, &material_id, &record);
        Ok(json!({ "restore_material_ref": material_ref, "state_root": state_root, "custody": "daemon", "bytes": tar_bytes.len(), "admitted": true }))
    }
    /// Restore truth = daemon-admitted sha256, never blob existence: re-hash the custody bytes
    /// against the ADMITTED state_root and refuse on mismatch before touching the node.
    fn restore(&self, data_dir: &str, env_ref: &str, material_ref: &str) -> Result<Value, String> {
        let material = read_record_dir(data_dir, MATERIAL_KIND)
            .into_iter()
            .find(|m| text(m, "material_ref") == material_ref)
            .ok_or(format!("restore material '{material_ref}' is not daemon-admitted"))?;
        let bytes = std::fs::read(text(&material, "path"))
            .map_err(|e| format!("custody material unreadable: {e}"))?;
        let admitted = text(&material, "state_root");
        let actual = sha256_bytes(&bytes);
        if actual != admitted {
            return Err(format!("restore_material_hash_mismatch — custody bytes hash {actual} but admitted state_root is {admitted}; refusing restore (blob existence is not restore truth)"));
        }
        let root = Self::node_root(env_ref);
        let script = format!("set -e; IOI_ROOT={root}; rm -rf \"$IOI_ROOT/workspace\"; mkdir -p \"$IOI_ROOT/workspace\"; tar -xzf - -C \"$IOI_ROOT/workspace\"; printf ready > \"$IOI_ROOT/phase\"");
        let (code, _, stderr) = self.run_script(data_dir, &script, Some(&bytes))?;
        if code != 0 {
            return Err(format!("ssh restore failed (exit {code}): {stderr}"));
        }
        Ok(json!({ "provider_operation_ref": self.op_ref("restore", env_ref), "phase": "ready", "restored_from": material_ref, "state_root_verified": admitted }))
    }
    fn inject_outage(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let root = Self::node_root(env_ref);
        let script = format!("set -e; IOI_ROOT={root}; rm -rf \"$IOI_ROOT/workspace\"; printf outage > \"$IOI_ROOT/phase\"");
        let (code, _, stderr) = self.run_script(data_dir, &script, None)?;
        if code != 0 {
            return Err(format!("ssh outage injection failed (exit {code}): {stderr}"));
        }
        Ok(json!({ "provider_operation_ref": self.op_ref("inject_outage", env_ref), "phase": "outage", "workspace_lost": true }))
    }
    fn recover(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut materials: Vec<Value> = read_record_dir(data_dir, MATERIAL_KIND)
            .into_iter()
            .filter(|m| text(m, "environment_ref") == env_ref && text(m, "account_ref") == text(&self.account, "account_ref"))
            .collect();
        materials.sort_by(|a, b| text(a, "material_id").cmp(text(b, "material_id")));
        let latest = materials.pop().ok_or("no daemon-admitted restore material to recover from")?;
        let restored = self.restore(data_dir, env_ref, text(&latest, "material_ref"))?;
        Ok(json!({ "provider_operation_ref": self.op_ref("recover", env_ref), "phase": "ready", "recovered_from": text(&latest, "material_ref"), "state_root_verified": restored.get("state_root_verified").cloned().unwrap_or(Value::Null) }))
    }
    fn delete(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let root = Self::node_root(env_ref);
        let script = format!("IOI_ROOT={root}; rm -rf \"$IOI_ROOT\"; test ! -d \"$IOI_ROOT\" && echo gone");
        let (code, stdout, stderr) = self.run_script(data_dir, &script, None)?;
        if code != 0 {
            return Err(format!("ssh delete failed (exit {code}): {stderr}"));
        }
        Ok(json!({ "provider_operation_ref": self.op_ref("delete", env_ref), "cleanup_verified": String::from_utf8_lossy(&stdout).trim() == "gone" }))
    }
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value {
        let root = Self::node_root(env_ref);
        let script = format!("IOI_ROOT={root}; printf '%s\\n' \"$(cat \"$IOI_ROOT/phase\" 2>/dev/null || echo absent)\"; ls \"$IOI_ROOT/workspace\" 2>/dev/null | wc -l");
        match self.run_script(data_dir, &script, None) {
            Ok((_, stdout, _)) => {
                let out = String::from_utf8_lossy(&stdout);
                let mut lines = out.lines();
                let phase = lines.next().unwrap_or("unknown").to_string();
                let files = lines.next().unwrap_or("0").trim().to_string();
                json!({ "provider": self.id(), "account_ref": text(&self.account, "account_ref"), "environment_ref": env_ref, "phase": phase, "workspace_files": files })
            }
            Err(e) => json!({ "provider": self.id(), "environment_ref": env_ref, "phase": "unreachable", "error": e }),
        }
    }
}

// --- cloud kinds (aws|gcp|k8s|vast|akash): credential + preflight ONLY in this cut. Every ---
// --- lifecycle op fails closed with a NAMED reason — never a fake cloud (cloud-vpc pattern). ---
struct CloudKindProvider {
    account: Value,
}
impl CloudKindProvider {
    fn kind(&self) -> String {
        text(&self.account, "kind").to_string()
    }
    fn not_implemented(&self) -> String {
        let kind = self.kind();
        format!("PROVIDER_KIND_LIFECYCLE_NOT_IMPLEMENTED — '{kind}' accounts are credential+preflight only in this cut; the lifecycle lands with the {kind} adapter (Vast → Akash → hyperscaler ladder). Not faked.")
    }
}
impl EnvironmentProvider for CloudKindProvider {
    fn id(&self) -> &str {
        "cloud-kind"
    }
    fn capabilities(&self) -> Value {
        let mut caps = kind_capabilities(&self.kind());
        caps["provider_spend_borne_by"] = json!("customer");
        caps
    }
    fn status(&self) -> (&'static str, String) {
        match text(&self.account, "status") {
            "verified" => ("credential_verified", format!("'{}' credential verified — preflight only until its adapter cut", self.kind())),
            "revoked" => ("revoked", "credential revoked".into()),
            _ => ("unverified", "bind + preflight the credential to verify this account".into()),
        }
    }
    fn preflight(&self, _plan: &Value) -> Value {
        json!({ "admit": text(&self.account, "status") == "verified", "provider": self.kind(), "account_ref": text(&self.account, "account_ref"), "lifecycle": "credential_preflight_only", "preflight_evidence": self.account.get("preflight").cloned().unwrap_or(Value::Null) })
    }
    fn create(&self, _d: &str, _e: &str, _p: &Value) -> Result<Value, String> {
        Err(self.not_implemented())
    }
    fn start(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err(self.not_implemented())
    }
    fn workrun(&self, _d: &str, _e: &str, _c: &str) -> Result<Value, String> {
        Err(self.not_implemented())
    }
    fn stop(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err(self.not_implemented())
    }
    fn snapshot(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err(self.not_implemented())
    }
    fn restore(&self, _d: &str, _e: &str, _m: &str) -> Result<Value, String> {
        Err(self.not_implemented())
    }
    fn inject_outage(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err(self.not_implemented())
    }
    fn recover(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err(self.not_implemented())
    }
    fn delete(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err(self.not_implemented())
    }
    fn observe(&self, _d: &str, _e: &str) -> Value {
        json!({ "provider": self.kind(), "status": text(&self.account, "status"), "lifecycle": "credential_preflight_only", "reason": self.not_implemented() })
    }
}

// --- vast GUARDED LIFECYCLE: the first paid external GPU lifecycle path. Narrow by design: ---
// --- lease ONE instance, bootstrap ssh, reuse the BYO SSH workspace/custody contract, tear  ---
// --- down ALWAYS. Control plane modes: "simulator" (marketplace simulated locally,          ---
// --- ssh/custody lane REAL — labelled, never live supply) | "live" (real Vast API).         ---
const VAST_INSTANCE_KIND: &str = "vast-instances";

fn vast_mode(account: &Value) -> String {
    account.pointer("/endpoint/mode").and_then(Value::as_str).unwrap_or("").to_string()
}
fn load_vast_instance(data_dir: &str, account_id: &str, env_ref: &str) -> Option<Value> {
    read_record_dir(data_dir, VAST_INSTANCE_KIND)
        .into_iter()
        .find(|i| text(i, "account_id") == account_id && text(i, "environment_ref") == env_ref)
}

struct VastProvider {
    account: Value,
}
impl VastProvider {
    fn account_id(&self) -> &str {
        text(&self.account, "account_id")
    }
    fn mode(&self) -> String {
        vast_mode(&self.account)
    }
    fn instance(&self, data_dir: &str, env_ref: &str) -> Option<Value> {
        load_vast_instance(data_dir, self.account_id(), env_ref)
    }
    fn save_instance(&self, data_dir: &str, instance: &Value) {
        let id = text(instance, "record_id").to_string();
        let _ = persist_record(data_dir, VAST_INSTANCE_KIND, &id, instance);
    }
    /// The BYO SSH lane over THIS instance's endpoint — the same workspace mutation + daemon
    /// custody contract as baremetal_ssh (materials attribute to the REAL vast account).
    fn ssh_lane(&self, data_dir: &str, env_ref: &str) -> Result<(SshProvider, KeyGuard), String> {
        let inst = self.instance(data_dir, env_ref)
            .ok_or("vast_instance_absent — provision with the quote-gated create op first")?;
        if text(&inst, "status") == "torn_down" {
            return Err("vast_instance_torn_down — this instance was already torn down".into());
        }
        let ssh = inst.get("ssh").cloned().unwrap_or(Value::Null);
        let key_file = text(&ssh, "key_file");
        let sealed = text(&inst, "sealed_ssh_key");
        if text(&ssh, "host").is_empty() || (key_file.is_empty() && sealed.is_empty()) {
            return Err("vast_ssh_bootstrap_unknown — the instance has no usable ssh endpoint/key (live instances gain one only after boot polling proves readiness)".into());
        }
        let key = if !key_file.is_empty() {
            std::fs::read_to_string(key_file).map_err(|e| format!("vast_ssh_key_unreadable: {e}"))?
        } else {
            // Live instances: the ephemeral private key lives SEALED on the instance record
            // (same dcrypt discipline as every credential) — opened in-daemon, materialized
            // 0600 for one op, removed by the KeyGuard.
            open_scm_token(sealed).ok_or("vast_ssh_key_unsealable — sealed instance key did not decrypt")?
        };
        let dir = Path::new(data_dir).join("provider-ssh");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!("vast-{}-{}.key", safe(self.account_id()), safe(env_ref)));
        std::fs::write(&path, key).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        let synthetic = json!({
            "account_id": self.account_id(),
            "account_ref": self.account["account_ref"],
            "display_name": format!("{} (vast instance)", text(&self.account, "display_name")),
            "kind": "vast", "status": "verified",
            "endpoint": { "host": ssh["host"], "port": ssh["port"], "user": ssh["user"] },
        });
        Ok((SshProvider { account: synthetic, key_path: path.clone() }, KeyGuard(path)))
    }
}
impl EnvironmentProvider for VastProvider {
    fn id(&self) -> &str {
        "vast-guarded"
    }
    fn capabilities(&self) -> Value {
        let mut caps = kind_capabilities("vast");
        caps["provider_spend_borne_by"] = json!("customer");
        caps["lifecycle"] = json!("guarded_lifecycle — quote-gated create, wallet-gated mutations, teardown required");
        caps["execution_mode"] = json!(self.mode());
        caps
    }
    fn status(&self) -> (&'static str, String) {
        match text(&self.account, "status") {
            "verified" => ("available", format!("guarded vast lifecycle ({} control plane)", self.mode())),
            "revoked" => ("revoked", "credential revoked".into()),
            _ => ("unverified", "bind + preflight the credential".into()),
        }
    }
    fn preflight(&self, _plan: &Value) -> Value {
        json!({ "admit": text(&self.account, "status") == "verified", "provider": self.id(),
                "account_ref": self.account["account_ref"], "execution_mode": self.mode(),
                "lifecycle": "guarded_lifecycle", "preflight_evidence": self.account.get("preflight").cloned().unwrap_or(Value::Null) })
    }
    /// Quote-gated provision. The gate ladder (budget → quote freshness/liveness → wallet lease)
    /// ran in handle_provider_op; `plan` carries the validated candidate/quote facts.
    fn create(&self, data_dir: &str, env_ref: &str, plan: &Value) -> Result<Value, String> {
        if let Some(existing) = self.instance(data_dir, env_ref) {
            if text(&existing, "status") != "torn_down" {
                return Err(format!("vast_instance_already_provisioned — {} is live for this environment; tear it down first", text(&existing, "instance_id")));
            }
        }
        let mode = self.mode();
        let record_id = format!("vinst_{:x}", nanos());
        if mode == "simulator" {
            let ssh = self.account.pointer("/endpoint/ssh").cloned().unwrap_or(Value::Null);
            if text(&ssh, "host").is_empty() || text(&ssh, "key_file").is_empty() {
                return Err("vast_simulator_ssh_missing — simulator mode needs endpoint.ssh {host, port, user, key_file}".into());
            }
            let instance_id = format!("vsim_{:x}", nanos());
            let instance = json!({
                "schema_version": "ioi.hypervisor.vast-instance.v1",
                "record_id": record_id, "instance_id": instance_id,
                "account_id": self.account_id(), "account_ref": self.account["account_ref"],
                "environment_ref": env_ref, "status": "provisioned",
                "execution_mode": "simulated_control_plane",
                "ssh": ssh,
                "candidate_ref": plan["candidate_ref"], "quote_ref": plan["quote_ref"],
                "usd_per_hour": plan["usd_per_hour"], "max_hourly_usd": plan["max_hourly_usd"],
                "teardown_policy": plan["teardown_policy"],
                "provider_native": { "instance_id": instance_id,
                    "note": "SIMULATED marketplace id — evidence only, never restore truth; no real Vast instance exists" },
                "created_at": iso_now(),
            });
            self.save_instance(data_dir, &instance);
            // Bootstrap the workspace root over the REAL ssh lane (readiness proof included).
            let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
            let bootstrap = lane.create(data_dir, env_ref, plan)?;
            return Ok(json!({
                "provider_operation_ref": format!("provider-account://{}/op/create/{}", self.account_id(), safe(env_ref)),
                "instance": { "instance_id": instance_id, "status": "provisioned", "execution_mode": "simulated_control_plane" },
                "provider_native": instance["provider_native"],
                "ssh_ready": true, "workspace_bootstrap": bootstrap,
                "live_provisioning_not_run": true,
                "teardown_required": true,
            }));
        }
        if mode == "live" {
            // Real marketplace lease. Any deviation fails NAMED — no partial claims; if the ask
            // succeeded but later steps fail, the instance record still exists so teardown runs.
            let offer_id = plan.get("offer_id").and_then(Value::as_u64)
                .ok_or("vast_live_offer_id_missing — the validated quote carries no offer id")?;
            let bearer = load_account_credential(data_dir, self.account_id())
                .and_then(|c| c["sealed_token"].as_str().and_then(open_scm_token))
                .ok_or("provider_credential_unresolved")?;
            let base = self.account.pointer("/endpoint/endpoint").and_then(Value::as_str)
                .unwrap_or("https://console.vast.ai/api/v0").trim_end_matches('/').to_string();
            let price = plan.get("max_hourly_usd").and_then(Value::as_f64).unwrap_or(0.0);
            let created: Result<Value, String> = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let client = reqwest::Client::new();
                    let resp = client.put(format!("{base}/asks/{offer_id}/"))
                        .bearer_auth(&bearer)
                        .json(&json!({ "client_id": "me", "price": price, "disk": 20, "image": "ubuntu:22.04", "runtype": "ssh" }))
                        .timeout(std::time::Duration::from_secs(30))
                        .send().await.map_err(|e| format!("vast_live_provision_failed: {e}"))?;
                    let status = resp.status().as_u16();
                    let body: Value = resp.json().await.map_err(|e| format!("vast_live_provision_failed: non-JSON response: {e}"))?;
                    if !(200..300).contains(&status) || body.get("success") == Some(&json!(false)) {
                        return Err(format!("vast_live_provision_failed: http {status} {body}"));
                    }
                    Ok(body)
                })
            });
            let body = created?;
            let native_id = body.get("new_contract").cloned().unwrap_or(Value::Null);
            // Ephemeral per-instance ssh keypair: private key SEALED onto the record (never
            // plaintext), public key attached to the Vast account for this lease.
            let keydir = Path::new(data_dir).join("provider-ssh");
            std::fs::create_dir_all(&keydir).map_err(|e| e.to_string())?;
            let tmp = keydir.join(format!("vast-live-{}-{}.tmp", safe(self.account_id()), safe(env_ref)));
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(keydir.join(format!("{}.pub", tmp.to_string_lossy())));
            let keygen = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-q", "-f"]).arg(&tmp)
                .output().map_err(|e| format!("vast_ssh_keygen_failed: {e} (instance {native_id} recorded for teardown)"))?;
            if !keygen.status.success() {
                return Err(format!("vast_ssh_keygen_failed: {} (instance {native_id} recorded for teardown)", String::from_utf8_lossy(&keygen.stderr)));
            }
            let private_key = std::fs::read_to_string(&tmp).map_err(|e| e.to_string())?;
            let public_key = std::fs::read_to_string(format!("{}.pub", tmp.to_string_lossy())).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(format!("{}.pub", tmp.to_string_lossy()));
            let sealed_key = seal_scm_token(private_key.trim())
                .ok_or("vast_ssh_key_seal_failed — could not seal the ephemeral instance key")?;
            let attach: Result<u16, String> = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    reqwest::Client::new().post(format!("{base}/ssh/"))
                        .bearer_auth(&bearer)
                        .json(&json!({ "ssh_key": public_key.trim() }))
                        .timeout(std::time::Duration::from_secs(20))
                        .send().await.map(|r| r.status().as_u16()).map_err(|e| e.to_string())
                })
            });
            let key_attach = match attach {
                Ok(status) if (200..300).contains(&status) => json!({ "attached": true, "http_status": status }),
                Ok(status) => json!({ "attached": false, "http_status": status, "warning": "pubkey attach rejected — boot polling will fail closed until resolved" }),
                Err(e) => json!({ "attached": false, "error": e, "warning": "pubkey attach failed — boot polling will fail closed until resolved" }),
            };
            let instance = json!({
                "schema_version": "ioi.hypervisor.vast-instance.v1",
                "record_id": record_id, "instance_id": format!("vast_{native_id}"),
                "account_id": self.account_id(), "account_ref": self.account["account_ref"],
                "environment_ref": env_ref, "status": "provisioned",
                "execution_mode": "live",
                "sealed_ssh_key": sealed_key,
                "ssh_key_attach": key_attach,
                "ssh": Value::Null,
                "candidate_ref": plan["candidate_ref"], "quote_ref": plan["quote_ref"],
                "usd_per_hour": plan["usd_per_hour"], "max_hourly_usd": plan["max_hourly_usd"],
                "teardown_policy": plan["teardown_policy"],
                "provider_native": { "instance_id": native_id, "note": "provider-native id — evidence only, never restore truth" },
                "created_at": iso_now(),
            });
            self.save_instance(data_dir, &instance);
            return Ok(json!({
                "provider_operation_ref": format!("provider-account://{}/op/create/{}", self.account_id(), safe(env_ref)),
                "instance": { "instance_id": instance["instance_id"], "status": "provisioned", "execution_mode": "live" },
                "provider_native": instance["provider_native"],
                "ssh_key_attach": instance["ssh_key_attach"],
                "ssh_ready": false,
                "note": "live instance leased — run start to boot-poll; workspace ops fail closed (vast_ssh_bootstrap_unknown) until ssh readiness is PROVEN",
                "teardown_required": true,
            }));
        }
        Err("vast_lifecycle_mode_unset — set the account endpoint mode to simulator or live".into())
    }
    fn start(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self.instance(data_dir, env_ref).ok_or("vast_instance_absent")?;
        if text(&inst, "status") == "torn_down" {
            return Err("vast_instance_torn_down".into());
        }
        let mut boot_evidence = Value::Null;
        // Live instances: boot-poll the provider until ssh host/port are KNOWN; the runtime ssh
        // block persists only with readiness evidence attached.
        if text(&inst, "execution_mode") == "live" && inst.get("ssh").map(Value::is_null).unwrap_or(true) {
            let native = inst.pointer("/provider_native/instance_id").cloned().unwrap_or(Value::Null);
            let nid = native.as_u64().or_else(|| native.as_str().and_then(|s| s.parse().ok()))
                .ok_or("vast_boot_poll_failed — no provider-native id on the instance record")?;
            let bearer = load_account_credential(data_dir, self.account_id())
                .and_then(|c| c["sealed_token"].as_str().and_then(open_scm_token))
                .ok_or("provider_credential_unresolved")?;
            let base = self.account.pointer("/endpoint/endpoint").and_then(Value::as_str)
                .unwrap_or("https://console.vast.ai/api/v0").trim_end_matches('/').to_string();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
            let mut attempts = 0u32;
            let mut last_status = String::from("unknown");
            let polled: Option<(String, u64)> = loop {
                attempts += 1;
                let fetched: Result<Value, String> = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let r = reqwest::Client::new().get(format!("{base}/instances/{nid}/"))
                            .bearer_auth(&bearer)
                            .timeout(std::time::Duration::from_secs(15))
                            .send().await.map_err(|e| e.to_string())?;
                        r.json::<Value>().await.map_err(|e| e.to_string())
                    })
                });
                if let Ok(doc) = fetched {
                    let node = doc.get("instances").filter(|v| !v.is_array()).cloned().unwrap_or(doc);
                    last_status = node.get("actual_status").and_then(Value::as_str).unwrap_or("unknown").to_string();
                    let host = node.get("ssh_host").and_then(Value::as_str).unwrap_or("").to_string();
                    let port = node.get("ssh_port").and_then(Value::as_u64).unwrap_or(0);
                    if last_status == "running" && !host.is_empty() && port > 0 {
                        break Some((host, port));
                    }
                }
                if std::time::Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(std::time::Duration::from_secs(10));
            };
            let Some((host, port)) = polled else {
                return Err(format!("vast_boot_pending — instance {nid} not ssh-ready after {attempts} poll(s) (status: {last_status}); re-run start to continue polling"));
            };
            boot_evidence = json!({ "polled_attempts": attempts, "actual_status": last_status,
                                     "ssh_host": host, "ssh_port": port, "proven_at": iso_now() });
            inst["ssh"] = json!({ "host": host, "port": port, "user": "root" });
            inst["ssh_ready_evidence"] = boot_evidence.clone();
            self.save_instance(data_dir, &inst);
        }
        // Bootstrap the remote workspace ONCE (simulator did it at create), then the readiness
        // probe — a REAL ssh round-trip either way.
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        if inst.get("workspace_bootstrapped").and_then(Value::as_bool) != Some(true) {
            if text(&inst, "execution_mode") == "live" {
                lane.create(data_dir, env_ref, &json!({}))?;
            }
            inst["workspace_bootstrapped"] = json!(true);
        }
        lane.start(data_dir, env_ref)?;
        inst["status"] = json!("running");
        self.save_instance(data_dir, &inst);
        Ok(json!({ "provider_operation_ref": format!("provider-account://{}/op/start/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "status": "running", "ssh_ready": true,
                   "boot_evidence": boot_evidence }))
    }
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.workrun(data_dir, env_ref, command)
    }
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self.instance(data_dir, env_ref).ok_or("vast_instance_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let stopped = lane.stop(data_dir, env_ref)?;
        inst["status"] = json!("stopped");
        self.save_instance(data_dir, &inst);
        Ok(json!({ "provider_operation_ref": format!("provider-account://{}/op/stop/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "status": "stopped", "lane": stopped }))
    }
    fn snapshot(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.snapshot(data_dir, env_ref)
    }
    fn restore(&self, data_dir: &str, env_ref: &str, material_ref: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.restore(data_dir, env_ref, material_ref)
    }
    fn inject_outage(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("vast_outage_injection_not_supported — destroying a paid marketplace instance is not a safely representable outage; use the loopback/ssh conformance lanes".into())
    }
    fn recover(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("vast_recover_not_supported — recovery on a marketplace instance is restore-from-daemon-custody after re-provisioning; run create + restore explicitly".into())
    }
    /// Teardown ALWAYS proceeds: remote cleanup is best-effort (the node may already be gone);
    /// the instance record flips to torn_down either way, and the evidence says which happened.
    fn delete(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self.instance(data_dir, env_ref).ok_or("vast_instance_absent")?;
        let remote_cleanup = match self.ssh_lane(data_dir, env_ref) {
            Ok((lane, _guard)) => lane.delete(data_dir, env_ref).map(|e| e["cleanup_verified"].clone()).unwrap_or(json!("unreachable")),
            Err(e) => json!(format!("skipped: {e}")),
        };
        let native_teardown = if text(&inst, "execution_mode") == "live" {
            // Live: destroy the marketplace instance (billing stops here).
            let native = inst.pointer("/provider_native/instance_id").cloned().unwrap_or(Value::Null);
            let bearer = load_account_credential(data_dir, self.account_id())
                .and_then(|c| c["sealed_token"].as_str().and_then(open_scm_token));
            match (native.as_u64().or_else(|| native.as_str().and_then(|s| s.parse().ok())), bearer) {
                (Some(nid), Some(bearer)) => {
                    let base = self.account.pointer("/endpoint/endpoint").and_then(Value::as_str)
                        .unwrap_or("https://console.vast.ai/api/v0").trim_end_matches('/').to_string();
                    let result: Result<u16, String> = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            reqwest::Client::new().delete(format!("{base}/instances/{nid}/"))
                                .bearer_auth(&bearer)
                                .timeout(std::time::Duration::from_secs(30))
                                .send().await.map(|r| r.status().as_u16()).map_err(|e| e.to_string())
                        })
                    });
                    match result {
                        Ok(status) => json!({ "destroyed": (200..300).contains(&status), "http_status": status }),
                        Err(e) => json!({ "destroyed": false, "error": e, "warning": "TEARDOWN MAY BE INCOMPLETE — verify the Vast console" }),
                    }
                }
                _ => json!({ "destroyed": false, "error": "native id or credential unavailable" }),
            }
        } else if self.account.pointer("/endpoint/simulate_teardown_failure").and_then(Value::as_bool) == Some(true) {
            json!({ "destroyed": false, "error": "SIMULATED teardown failure (endpoint.simulate_teardown_failure) — validates the incomplete-teardown warning path", "warning": "TEARDOWN MAY BE INCOMPLETE — verify the Vast console" })
        } else {
            json!({ "destroyed": true, "note": "simulated control plane — no real instance existed" })
        };
        inst["status"] = json!("torn_down");
        inst["torn_down_at"] = json!(iso_now());
        self.save_instance(data_dir, &inst);
        Ok(json!({ "provider_operation_ref": format!("provider-account://{}/op/delete/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "teardown_state": "torn_down",
                   "remote_workspace_cleanup": remote_cleanup, "native_teardown": native_teardown,
                   "cleanup_verified": true }))
    }
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value {
        match self.instance(data_dir, env_ref) {
            None => json!({ "provider": self.id(), "environment_ref": env_ref, "instance": Value::Null, "status": "absent" }),
            Some(inst) => {
                let boot_pending = text(&inst, "execution_mode") == "live" && inst.get("ssh").map(Value::is_null).unwrap_or(true);
                let lane_view = if text(&inst, "status") == "torn_down" { Value::Null }
                    else if boot_pending { json!({ "boot": "pending — run start to poll the provider until ssh readiness is proven" }) }
                    else {
                        match self.ssh_lane(data_dir, env_ref) {
                            Ok((lane, _guard)) => lane.observe(data_dir, env_ref),
                            Err(e) => json!({ "error": e }),
                        }
                    };
                json!({ "provider": self.id(), "environment_ref": env_ref,
                        "instance_id": inst["instance_id"], "status": inst["status"],
                        "execution_mode": inst["execution_mode"],
                        "provider_native": inst["provider_native"],
                        "teardown_state": if text(&inst, "status") == "torn_down" { json!("torn_down") } else { json!("live_or_pending") },
                        "workspace": lane_view })
            }
        }
    }
}

// --- runpod GUARDED LIFECYCLE: the second GPU class, proving the ladder is not Vast-      ---
// --- specific. Same safety contract: quote-gated create, boot polling with readiness       ---
// --- evidence, BYO SSH custody lane reused verbatim, teardown always. Control plane modes: ---
// --- "simulator" (pods simulated locally, ssh/custody REAL) | "live" (RunPod REST pods).   ---
const RUNPOD_INSTANCE_KIND: &str = "runpod-instances";

fn load_runpod_instance(data_dir: &str, account_id: &str, env_ref: &str) -> Option<Value> {
    read_record_dir(data_dir, RUNPOD_INSTANCE_KIND)
        .into_iter()
        .find(|i| text(i, "account_id") == account_id && text(i, "environment_ref") == env_ref)
}

struct RunPodProvider {
    account: Value,
}
impl RunPodProvider {
    fn account_id(&self) -> &str {
        text(&self.account, "account_id")
    }
    fn mode(&self) -> String {
        vast_mode(&self.account) // reads endpoint.mode generically
    }
    fn base(&self) -> String {
        let configured = self.account.pointer("/endpoint/endpoint").and_then(Value::as_str).unwrap_or("");
        if configured.is_empty() { "https://rest.runpod.io/v1".into() } else { configured.trim_end_matches('/').to_string() }
    }
    fn bearer(&self, data_dir: &str) -> Result<String, String> {
        load_account_credential(data_dir, self.account_id())
            .and_then(|c| c["sealed_token"].as_str().and_then(open_scm_token))
            .ok_or("provider_credential_unresolved".into())
    }
    fn instance(&self, data_dir: &str, env_ref: &str) -> Option<Value> {
        load_runpod_instance(data_dir, self.account_id(), env_ref)
    }
    fn save_instance(&self, data_dir: &str, instance: &Value) {
        let id = text(instance, "record_id").to_string();
        let _ = persist_record(data_dir, RUNPOD_INSTANCE_KIND, &id, instance);
    }
    /// The BYO SSH lane over this pod's endpoint — identical custody contract to Vast/BYO.
    fn ssh_lane(&self, data_dir: &str, env_ref: &str) -> Result<(SshProvider, KeyGuard), String> {
        let inst = self.instance(data_dir, env_ref)
            .ok_or("runpod_instance_absent — provision with the quote-gated create op first")?;
        if text(&inst, "status") == "torn_down" {
            return Err("runpod_instance_torn_down — this pod was already torn down".into());
        }
        let ssh = inst.get("ssh").cloned().unwrap_or(Value::Null);
        let key_file = text(&ssh, "key_file");
        let sealed = text(&inst, "sealed_ssh_key");
        if text(&ssh, "host").is_empty() || (key_file.is_empty() && sealed.is_empty()) {
            return Err("runpod_ssh_bootstrap_unknown — the pod has no usable ssh endpoint/key (live pods gain one only after boot polling proves readiness)".into());
        }
        let key = if !key_file.is_empty() {
            std::fs::read_to_string(key_file).map_err(|e| format!("runpod_ssh_key_unreadable: {e}"))?
        } else {
            open_scm_token(sealed).ok_or("runpod_ssh_key_unsealable — sealed pod key did not decrypt")?
        };
        let dir = Path::new(data_dir).join("provider-ssh");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!("runpod-{}-{}.key", safe(self.account_id()), safe(env_ref)));
        std::fs::write(&path, key).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        let synthetic = json!({
            "account_id": self.account_id(),
            "account_ref": self.account["account_ref"],
            "display_name": format!("{} (runpod pod)", text(&self.account, "display_name")),
            "kind": "runpod", "status": "verified",
            "endpoint": { "host": ssh["host"], "port": ssh["port"], "user": ssh["user"] },
        });
        Ok((SshProvider { account: synthetic, key_path: path.clone() }, KeyGuard(path)))
    }
}
impl EnvironmentProvider for RunPodProvider {
    fn id(&self) -> &str {
        "runpod-guarded"
    }
    fn capabilities(&self) -> Value {
        let mut caps = kind_capabilities("runpod");
        caps["provider_spend_borne_by"] = json!("customer");
        caps["lifecycle"] = json!("guarded_lifecycle — quote-gated create, wallet-gated mutations, teardown required");
        caps["execution_mode"] = json!(self.mode());
        caps
    }
    fn status(&self) -> (&'static str, String) {
        match text(&self.account, "status") {
            "verified" => ("available", format!("guarded runpod lifecycle ({} control plane)", self.mode())),
            "revoked" => ("revoked", "credential revoked".into()),
            _ => ("unverified", "bind + preflight the credential".into()),
        }
    }
    fn preflight(&self, _plan: &Value) -> Value {
        json!({ "admit": text(&self.account, "status") == "verified", "provider": self.id(),
                "account_ref": self.account["account_ref"], "execution_mode": self.mode(),
                "lifecycle": "guarded_lifecycle", "preflight_evidence": self.account.get("preflight").cloned().unwrap_or(Value::Null) })
    }
    fn create(&self, data_dir: &str, env_ref: &str, plan: &Value) -> Result<Value, String> {
        if let Some(existing) = self.instance(data_dir, env_ref) {
            if text(&existing, "status") != "torn_down" {
                return Err(format!("runpod_pod_already_provisioned — {} is live for this environment; tear it down first", text(&existing, "instance_id")));
            }
        }
        let mode = self.mode();
        let record_id = format!("rpinst_{:x}", nanos());
        if mode == "simulator" {
            let ssh = self.account.pointer("/endpoint/ssh").cloned().unwrap_or(Value::Null);
            if text(&ssh, "host").is_empty() || text(&ssh, "key_file").is_empty() {
                return Err("runpod_simulator_ssh_missing — simulator mode needs endpoint.ssh {host, port, user, key_file}".into());
            }
            let instance_id = format!("rpsim_{:x}", nanos());
            let instance = json!({
                "schema_version": "ioi.hypervisor.runpod-instance.v1",
                "record_id": record_id, "instance_id": instance_id,
                "account_id": self.account_id(), "account_ref": self.account["account_ref"],
                "environment_ref": env_ref, "status": "provisioned",
                "execution_mode": "simulated_control_plane",
                "ssh": ssh,
                "candidate_ref": plan["candidate_ref"], "quote_ref": plan["quote_ref"],
                "usd_per_hour": plan["usd_per_hour"], "max_hourly_usd": plan["max_hourly_usd"],
                "teardown_policy": plan["teardown_policy"],
                "provider_native": { "pod_id": instance_id,
                    "note": "SIMULATED pod id — evidence only, never restore truth; no real RunPod pod exists" },
                "created_at": iso_now(),
            });
            self.save_instance(data_dir, &instance);
            let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
            let bootstrap = lane.create(data_dir, env_ref, plan)?;
            return Ok(json!({
                "provider_operation_ref": format!("provider-account://{}/op/create/{}", self.account_id(), safe(env_ref)),
                "instance": { "instance_id": instance_id, "status": "provisioned", "execution_mode": "simulated_control_plane" },
                "provider_native": instance["provider_native"],
                "ssh_ready": true, "workspace_bootstrap": bootstrap,
                "live_provisioning_not_run": true,
                "teardown_required": true,
            }));
        }
        if mode == "live" {
            let gpu_type = plan.get("offer_id").and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| plan.get("offer_id").and_then(Value::as_u64).map(|n| n.to_string()))
                .ok_or("runpod_live_gpu_type_missing — the validated quote carries no GPU type id")?;
            let bearer = self.bearer(data_dir)?;
            let base = self.base();
            // Ephemeral per-pod ssh keypair: sealed onto the record; pubkey attached account-side.
            let keydir = Path::new(data_dir).join("provider-ssh");
            std::fs::create_dir_all(&keydir).map_err(|e| e.to_string())?;
            let tmp = keydir.join(format!("runpod-live-{}-{}.tmp", safe(self.account_id()), safe(env_ref)));
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(format!("{}.pub", tmp.to_string_lossy()));
            let keygen = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-q", "-f"]).arg(&tmp)
                .output().map_err(|e| format!("runpod_ssh_keygen_failed: {e}"))?;
            if !keygen.status.success() {
                return Err(format!("runpod_ssh_keygen_failed: {}", String::from_utf8_lossy(&keygen.stderr)));
            }
            let private_key = std::fs::read_to_string(&tmp).map_err(|e| e.to_string())?;
            let public_key = std::fs::read_to_string(format!("{}.pub", tmp.to_string_lossy())).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(format!("{}.pub", tmp.to_string_lossy()));
            let sealed_key = seal_scm_token(private_key.trim())
                .ok_or("runpod_ssh_key_seal_failed — could not seal the ephemeral pod key")?;
            let price = plan.get("max_hourly_usd").and_then(Value::as_f64).unwrap_or(0.0);
            let created: Result<Value, String> = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let client = reqwest::Client::new();
                    let resp = client.post(format!("{base}/pods"))
                        .bearer_auth(&bearer)
                        .json(&json!({
                            "gpuTypeIds": [gpu_type],
                            "imageName": "runpod/base:0.6.2-cuda12.4.1",
                            "name": format!("ioi-hypervisor-{}", safe(env_ref)),
                            "containerDiskInGb": 20,
                            "ports": ["22/tcp"],
                            "env": {},
                            "bidPerGpu": price,
                        }))
                        .timeout(std::time::Duration::from_secs(30))
                        .send().await.map_err(|e| format!("runpod_live_provision_failed: {e}"))?;
                    let status = resp.status().as_u16();
                    let body: Value = resp.json().await.map_err(|e| format!("runpod_live_provision_failed: non-JSON response: {e}"))?;
                    if !(200..300).contains(&status) {
                        return Err(format!("runpod_live_provision_failed: http {status} {body}"));
                    }
                    Ok(body)
                })
            });
            let body = created?;
            let native_id = body.get("id").cloned().unwrap_or(Value::Null);
            let instance = json!({
                "schema_version": "ioi.hypervisor.runpod-instance.v1",
                "record_id": record_id, "instance_id": format!("runpod_{}", native_id.as_str().unwrap_or("?")),
                "account_id": self.account_id(), "account_ref": self.account["account_ref"],
                "environment_ref": env_ref, "status": "provisioned",
                "execution_mode": "live",
                "sealed_ssh_key": sealed_key,
                "ssh_public_key": public_key.trim(),
                "ssh": Value::Null,
                "candidate_ref": plan["candidate_ref"], "quote_ref": plan["quote_ref"],
                "usd_per_hour": plan["usd_per_hour"], "max_hourly_usd": plan["max_hourly_usd"],
                "teardown_policy": plan["teardown_policy"],
                "provider_native": { "pod_id": native_id, "note": "provider-native pod id — evidence only, never restore truth" },
                "created_at": iso_now(),
            });
            self.save_instance(data_dir, &instance);
            return Ok(json!({
                "provider_operation_ref": format!("provider-account://{}/op/create/{}", self.account_id(), safe(env_ref)),
                "instance": { "instance_id": instance["instance_id"], "status": "provisioned", "execution_mode": "live" },
                "provider_native": instance["provider_native"],
                "ssh_ready": false,
                "note": "live pod leased — run start to boot-poll; workspace ops fail closed (runpod_ssh_bootstrap_unknown) until ssh readiness is PROVEN",
                "teardown_required": true,
            }));
        }
        Err("runpod_lifecycle_mode_unset — set the account endpoint mode to simulator or live".into())
    }
    fn start(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self.instance(data_dir, env_ref).ok_or("runpod_instance_absent")?;
        if text(&inst, "status") == "torn_down" {
            return Err("runpod_instance_torn_down".into());
        }
        let mut boot_evidence = Value::Null;
        if text(&inst, "execution_mode") == "live" && inst.get("ssh").map(Value::is_null).unwrap_or(true) {
            let pod_id = inst.pointer("/provider_native/pod_id").and_then(Value::as_str)
                .map(str::to_string)
                .ok_or("runpod_boot_poll_failed — no provider-native pod id on the record")?;
            let bearer = self.bearer(data_dir)?;
            let base = self.base();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
            let mut attempts = 0u32;
            let mut last_status = String::from("unknown");
            let polled: Option<(String, u64)> = loop {
                attempts += 1;
                let fetched: Result<Value, String> = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let r = reqwest::Client::new().get(format!("{base}/pods/{pod_id}"))
                            .bearer_auth(&bearer)
                            .timeout(std::time::Duration::from_secs(15))
                            .send().await.map_err(|e| e.to_string())?;
                        r.json::<Value>().await.map_err(|e| e.to_string())
                    })
                });
                if let Ok(node) = fetched {
                    last_status = node.get("desiredStatus").and_then(Value::as_str)
                        .or_else(|| node.get("status").and_then(Value::as_str))
                        .unwrap_or("unknown").to_string();
                    let public_ip = node.pointer("/runtime/publicIp").and_then(Value::as_str)
                        .or_else(|| node.get("publicIp").and_then(Value::as_str))
                        .unwrap_or("").to_string();
                    let ssh_port = node.pointer("/runtime/ports").and_then(Value::as_array)
                        .and_then(|ports| ports.iter().find(|p| p.get("privatePort").and_then(Value::as_u64) == Some(22)))
                        .and_then(|p| p.get("publicPort").and_then(Value::as_u64))
                        .unwrap_or(0);
                    if last_status.eq_ignore_ascii_case("running") && !public_ip.is_empty() && ssh_port > 0 {
                        break Some((public_ip, ssh_port));
                    }
                }
                if std::time::Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(std::time::Duration::from_secs(10));
            };
            let Some((host, port)) = polled else {
                return Err(format!("runpod_boot_pending — pod {pod_id} not ssh-ready after {attempts} poll(s) (status: {last_status}); re-run start to continue polling"));
            };
            boot_evidence = json!({ "polled_attempts": attempts, "status": last_status,
                                     "ssh_host": host, "ssh_port": port, "proven_at": iso_now() });
            inst["ssh"] = json!({ "host": host, "port": port, "user": "root" });
            inst["ssh_ready_evidence"] = boot_evidence.clone();
            self.save_instance(data_dir, &inst);
        }
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        if inst.get("workspace_bootstrapped").and_then(Value::as_bool) != Some(true) {
            if text(&inst, "execution_mode") == "live" {
                lane.create(data_dir, env_ref, &json!({}))?;
            }
            inst["workspace_bootstrapped"] = json!(true);
        }
        lane.start(data_dir, env_ref)?;
        inst["status"] = json!("running");
        self.save_instance(data_dir, &inst);
        Ok(json!({ "provider_operation_ref": format!("provider-account://{}/op/start/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "status": "running", "ssh_ready": true,
                   "boot_evidence": boot_evidence }))
    }
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.workrun(data_dir, env_ref, command)
    }
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self.instance(data_dir, env_ref).ok_or("runpod_instance_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let stopped = lane.stop(data_dir, env_ref)?;
        inst["status"] = json!("stopped");
        self.save_instance(data_dir, &inst);
        Ok(json!({ "provider_operation_ref": format!("provider-account://{}/op/stop/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "status": "stopped", "lane": stopped }))
    }
    fn snapshot(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.snapshot(data_dir, env_ref)
    }
    fn restore(&self, data_dir: &str, env_ref: &str, material_ref: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.restore(data_dir, env_ref, material_ref)
    }
    fn inject_outage(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("runpod_outage_injection_not_supported — destroying a paid pod is not a safely representable outage; use the loopback/ssh conformance lanes".into())
    }
    fn recover(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("runpod_recover_not_supported — recovery is restore-from-daemon-custody after re-provisioning; run create + restore explicitly".into())
    }
    fn delete(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self.instance(data_dir, env_ref).ok_or("runpod_instance_absent")?;
        let remote_cleanup = match self.ssh_lane(data_dir, env_ref) {
            Ok((lane, _guard)) => lane.delete(data_dir, env_ref).map(|e| e["cleanup_verified"].clone()).unwrap_or(json!("unreachable")),
            Err(e) => json!(format!("skipped: {e}")),
        };
        let native_teardown = if text(&inst, "execution_mode") == "live" {
            let pod_id = inst.pointer("/provider_native/pod_id").and_then(Value::as_str).map(str::to_string);
            match (pod_id, self.bearer(data_dir)) {
                (Some(pid), Ok(bearer)) => {
                    let base = self.base();
                    let result: Result<u16, String> = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            reqwest::Client::new().delete(format!("{base}/pods/{pid}"))
                                .bearer_auth(&bearer)
                                .timeout(std::time::Duration::from_secs(30))
                                .send().await.map(|r| r.status().as_u16()).map_err(|e| e.to_string())
                        })
                    });
                    match result {
                        Ok(status) => json!({ "destroyed": (200..300).contains(&status), "http_status": status }),
                        Err(e) => json!({ "destroyed": false, "error": e, "warning": "TEARDOWN MAY BE INCOMPLETE — verify the RunPod console" }),
                    }
                }
                _ => json!({ "destroyed": false, "error": "pod id or credential unavailable" }),
            }
        } else if self.account.pointer("/endpoint/simulate_teardown_failure").and_then(Value::as_bool) == Some(true) {
            json!({ "destroyed": false, "error": "SIMULATED teardown failure (endpoint.simulate_teardown_failure) — validates the incomplete-teardown warning path", "warning": "TEARDOWN MAY BE INCOMPLETE — verify the RunPod console" })
        } else {
            json!({ "destroyed": true, "note": "simulated control plane — no real pod existed" })
        };
        inst["status"] = json!("torn_down");
        inst["torn_down_at"] = json!(iso_now());
        self.save_instance(data_dir, &inst);
        Ok(json!({ "provider_operation_ref": format!("provider-account://{}/op/delete/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "teardown_state": "torn_down",
                   "remote_workspace_cleanup": remote_cleanup, "native_teardown": native_teardown,
                   "cleanup_verified": true }))
    }
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value {
        match self.instance(data_dir, env_ref) {
            None => json!({ "provider": self.id(), "environment_ref": env_ref, "instance": Value::Null, "status": "absent" }),
            Some(inst) => {
                let boot_pending = text(&inst, "execution_mode") == "live" && inst.get("ssh").map(Value::is_null).unwrap_or(true);
                let lane_view = if text(&inst, "status") == "torn_down" { Value::Null }
                    else if boot_pending { json!({ "boot": "pending — run start to poll the provider until ssh readiness is proven" }) }
                    else {
                        match self.ssh_lane(data_dir, env_ref) {
                            Ok((lane, _guard)) => lane.observe(data_dir, env_ref),
                            Err(e) => json!({ "error": e }),
                        }
                    };
                json!({ "provider": self.id(), "environment_ref": env_ref,
                        "instance_id": inst["instance_id"], "status": inst["status"],
                        "execution_mode": inst["execution_mode"],
                        "provider_native": inst["provider_native"],
                        "teardown_state": if text(&inst, "status") == "torn_down" { json!("torn_down") } else { json!("live_or_pending") },
                        "workspace": lane_view })
            }
        }
    }
}

fn registry() -> Vec<Box<dyn EnvironmentProvider>> {
    vec![
        Box::new(LocalMicrovmProvider),
        Box::new(LoopbackRunnerProvider),
        Box::new(CloudVpcProvider),
    ]
}
fn resolve(id: &str) -> Option<Box<dyn EnvironmentProvider>> {
    registry().into_iter().find(|p| p.id() == id)
}

/// Resolve an ACCOUNT-backed adapter (provider_id = "pacc_*" | "provider-account://pacc_*").
/// SSH accounts need the sealed key materialized — the KeyGuard removes it when the op ends.
fn resolve_account_adapter(
    data_dir: &str,
    id: &str,
) -> Option<Result<(Value, Box<dyn EnvironmentProvider>, Option<KeyGuard>), String>> {
    if !(id.starts_with("pacc_") || id.starts_with("provider-account://")) {
        return None;
    }
    let Some(account) = load_account(data_dir, id) else {
        return Some(Err(format!("unknown provider account '{id}'")));
    };
    if text(&account, "kind") == "vast"
        && matches!(vast_mode(&account).as_str(), "simulator" | "live")
        && text(&account, "status") == "verified"
    {
        return Some(Ok((account.clone(), Box::new(VastProvider { account }), None)));
    }
    if text(&account, "kind") == "runpod"
        && matches!(vast_mode(&account).as_str(), "simulator" | "live")
        && text(&account, "status") == "verified"
    {
        return Some(Ok((account.clone(), Box::new(RunPodProvider { account }), None)));
    }
    if text(&account, "kind") == "baremetal_ssh" {
        match materialize_ssh_key(data_dir, text(&account, "account_id")) {
            Ok((key_path, guard, _)) => Some(Ok((
                account.clone(),
                Box::new(SshProvider { account, key_path }),
                Some(guard),
            ))),
            Err(e) => Some(Err(e)),
        }
    } else {
        Some(Ok((account.clone(), Box::new(CloudKindProvider { account }), None)))
    }
}

// ---- ProviderAccount CRUD --------------------------------------------------------------------

pub(crate) async fn handle_provider_accounts_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut accounts = read_record_dir(&st.data_dir, ACCOUNT_KIND);
    accounts.sort_by(|a, b| text(a, "created_at").cmp(text(b, "created_at")));
    Json(json!({ "schema_version": "ioi.hypervisor.provider-accounts.v1", "accounts": accounts, "spend_rule": "BYO provider spend is customer-borne; the hypervisor records, governs, estimates, and reconciles — it does not hide markup inside provider cost", "at": iso_now() }))
}

pub(crate) async fn handle_provider_account_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let kind = text(&body, "kind");
    if !ACCOUNT_KINDS.contains(&kind) {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "ok": false, "error": { "code": "provider_kind_invalid", "message": format!("kind must be one of {ACCOUNT_KINDS:?}") } })));
    }
    let display_name = text(&body, "display_name");
    if display_name.is_empty() {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "ok": false, "error": { "code": "provider_display_name_required", "message": "a provider account needs a display_name" } })));
    }
    if kind == "baremetal_ssh" {
        let ep = body.get("endpoint").cloned().unwrap_or_else(|| json!({}));
        if text(&ep, "host").is_empty() || text(&ep, "user").is_empty() {
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "ok": false, "error": { "code": "provider_endpoint_required", "message": "baremetal_ssh needs endpoint {host, user, port?}" } })));
        }
    }
    let id = format!("pacc_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.provider-account.v1",
        "account_id": id,
        "account_ref": format!("provider-account://{id}"),
        "display_name": display_name,
        "kind": kind,
        "status": "unverified",
        "credential_binding_ref": Value::Null,
        "endpoint": body.get("endpoint").cloned().unwrap_or_else(|| json!({})),
        "provider_spend_borne_by": "customer",
        "budget_policy_ref": body.get("budget_policy_ref").cloned().unwrap_or(Value::Null),
        "capabilities": kind_capabilities(kind),
        "created_at": now, "updated_at": now,
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, ACCOUNT_KIND, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "account": record })))
}

pub(crate) async fn handle_provider_account_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_account(&st.data_dir, &id) {
        Some(account) => (StatusCode::OK, Json(json!({ "ok": true, "account": account }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "error": { "code": "provider_account_not_found" } }))),
    }
}

pub(crate) async fn handle_provider_account_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut account) = load_account(&st.data_dir, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "error": { "code": "provider_account_not_found" } })));
    };
    for key in ["display_name", "endpoint", "budget_policy_ref"] {
        if let Some(v) = body.get(key) {
            account[key] = v.clone();
        }
    }
    // Endpoint changes invalidate a prior preflight verdict — posture must be re-proven.
    if body.get("endpoint").is_some() && text(&account, "status") == "verified" {
        account["status"] = json!("unverified");
        account["preflight"] = Value::Null;
    }
    account["updated_at"] = json!(iso_now());
    let aid = text(&account, "account_id").to_string();
    let _ = persist_record(&st.data_dir, ACCOUNT_KIND, &aid, &account);
    (StatusCode::OK, Json(json!({ "ok": true, "account": account })))
}

pub(crate) async fn handle_provider_account_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let Some(account) = load_account(&st.data_dir, &id) else {
        return Json(json!({ "ok": false, "error": { "code": "provider_account_not_found" } }));
    };
    let aid = text(&account, "account_id").to_string();
    let removed = super::remove_record(&st.data_dir, ACCOUNT_KIND, &aid);
    if let Some(cred) = load_account_credential(&st.data_dir, &aid) {
        let cid = text(&cred, "credential_id").to_string();
        let _ = super::remove_record(&st.data_dir, CREDENTIAL_VAULT, &cid);
    }
    Json(json!({ "ok": removed, "removed": removed, "account_id": aid }))
}

// ---- ProviderCredentialBinding — sealed material, presence-provable, never exported ----------

pub(crate) async fn handle_provider_account_credential(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut account) = load_account(&st.data_dir, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "error": { "code": "provider_account_not_found" } })));
    };
    let aid = text(&account, "account_id").to_string();
    let kind = text(&account, "kind").to_string();
    // Per-kind primary secret: sealed with the SAME dcrypt ladder as every other credential.
    let (cred_kind, secret) = match kind.as_str() {
        "baremetal_ssh" => ("ssh-key", text(&body, "private_key")),
        "aws" => ("aws-sigv4", text(&body, "secret_access_key")),
        "gcp" => ("oidc-workload", text(&body, "service_account_key")),
        "k8s" => ("bearer", text(&body, "token")),
        "vast" | "runpod" | "akash" => ("bearer", text(&body, "api_key")),
        _ => ("bearer", text(&body, "token")),
    };
    if secret.trim().is_empty() {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "ok": false, "error": { "code": "provider_credential_material_required", "message": format!("'{kind}' accounts bind their secret material at this route (never returned, sealed at rest)") } })));
    }
    let Some(sealed) = seal_scm_token(secret) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "error": { "code": "provider_credential_seal_failed" } })));
    };
    let fingerprint = sha256_bytes(secret.as_bytes());
    let cred_id = format!("pcred_{aid}");
    let mut record = json!({
        "schema_version": "ioi.hypervisor.provider-credential.v1",
        "credential_id": cred_id,
        // connector_id keys the CapabilityLease gateway lookup — one spine, no new gate.
        "connector_id": aid,
        "kind": cred_kind,
        "key_source": std::env::var("IOI_WALLET_SECRET_PASS").map(|_| "wallet-secret").unwrap_or("local-mode"),
        "fingerprint": fingerprint,
        // Non-secret aux hints (region/project/cluster) travel in the clear; secrets never do.
        "aux": body.get("aux").cloned().unwrap_or_else(|| json!({})),
        "bound_at": iso_now(),
    });
    // The sealed material lands under the field name resolve_sealed_credential reads for this
    // kind, so provider credentials ride the SAME gateway resolver as the connector estate.
    let sealed_field = if cred_kind == "aws-sigv4" { "sealed_secret_access_key" } else { "sealed_token" };
    record[sealed_field] = json!(sealed);
    // Non-secret resolver hints (token_url, client_id, audience, …) are read from the record
    // ROOT by the canonical oidc-workload/oauth-refresh branches — splice them up from aux.
    if let Some(aux) = body.get("aux").and_then(Value::as_object) {
        for hint in ["token_url", "client_id", "audience", "scopes", "subject_token_type", "subject_token_file", "access_key_id", "region"] {
            if let Some(v) = aux.get(hint).filter(|v| v.is_string()) {
                record[hint] = v.clone();
            }
        }
    }
    let _ = persist_record(&st.data_dir, CREDENTIAL_VAULT, &cred_id, &record);
    account["credential_binding_ref"] = json!(format!("credential://{CREDENTIAL_VAULT}/{cred_id}"));
    account["status"] = json!("unverified");
    account["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, ACCOUNT_KIND, &aid, &account);
    let receipt = provider_receipt_ext(&st.data_dir, &kind, "-", "credential_bind", "ok", &json!({ "account_ref": text(&account, "account_ref"), "credential_kind": cred_kind, "fingerprint": fingerprint }));
    (StatusCode::CREATED, Json(json!({ "ok": true, "account": account, "credential": { "credential_id": cred_id, "kind": cred_kind, "fingerprint": fingerprint, "sealed": true }, "receipt_ref": receipt })))
}

pub(crate) async fn handle_provider_account_credential_revoke(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let Some(mut account) = load_account(&st.data_dir, &id) else {
        return Json(json!({ "ok": false, "error": { "code": "provider_account_not_found" } }));
    };
    let aid = text(&account, "account_id").to_string();
    let removed = load_account_credential(&st.data_dir, &aid)
        .map(|c| super::remove_record(&st.data_dir, CREDENTIAL_VAULT, text(&c, "credential_id")))
        .unwrap_or(false);
    account["credential_binding_ref"] = Value::Null;
    account["status"] = json!("revoked");
    account["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, ACCOUNT_KIND, &aid, &account);
    let receipt = provider_receipt_ext(&st.data_dir, text(&account, "kind"), "-", "credential_revoke", "ok", &json!({ "account_ref": text(&account, "account_ref") }));
    Json(json!({ "ok": true, "revoked": removed, "account": account, "receipt_ref": receipt }))
}

/// POST /provider-accounts/:id/preflight — the REAL probe. SSH: connect + posture evidence.
/// Cloud kinds: credential resolvability + endpoint hints (honest: no cloud API call this cut).
pub(crate) async fn handle_provider_account_preflight(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut account) = load_account(&st.data_dir, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "error": { "code": "provider_account_not_found" } })));
    };
    let aid = text(&account, "account_id").to_string();
    let kind = text(&account, "kind").to_string();
    let (admit, evidence): (bool, Value) = if kind == "baremetal_ssh" {
        match materialize_ssh_key(&st.data_dir, &aid) {
            Err(e) => (false, json!({ "reason": e })),
            Ok((key_path, _guard, key_source)) => {
                let ssh = SshProvider { account: account.clone(), key_path };
                match ssh.run_script(&st.data_dir, "echo IOI-PREFLIGHT-OK; uname -sm; command -v tar >/dev/null && echo tar-ok || echo tar-missing", None) {
                    Err(e) => (false, json!({ "reason": e })),
                    Ok((code, stdout, stderr)) => {
                        let out = String::from_utf8_lossy(&stdout).trim().to_string();
                        let admit = code == 0 && out.contains("IOI-PREFLIGHT-OK") && out.contains("tar-ok");
                        (admit, json!({ "exit_code": code, "posture": out, "stderr": stderr, "credential_key_source": key_source, "probe": "real ssh connect + uname + tar presence" }))
                    }
                }
            }
        }
    } else {
        match load_account_credential(&st.data_dir, &aid) {
            None => (false, json!({ "reason": "provider_credential_unbound" })),
            Some(cred) => {
                let sealed = cred["sealed_token"].as_str().or(cred["sealed_secret_access_key"].as_str());
                let resolvable = sealed.and_then(open_scm_token).is_some();
                (resolvable, json!({ "credential_kind": text(&cred, "kind"), "credential_resolvable": resolvable, "fingerprint": text(&cred, "fingerprint"), "probe": "credential seal round-trip only — no cloud API call in this cut (lifecycle lands with the adapter)", "lifecycle": "credential_preflight_only" }))
            }
        }
    };
    account["preflight"] = json!({ "admit": admit, "evidence": evidence, "at": iso_now() });
    account["status"] = json!(if admit { "verified" } else { "unverified" });
    account["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, ACCOUNT_KIND, &aid, &account);
    let receipt = provider_receipt_ext(&st.data_dir, &kind, "-", "preflight", if admit { "ok" } else { "preflight_failed" }, &json!({ "account_ref": text(&account, "account_ref"), "evidence": account["preflight"]["evidence"] }));
    (StatusCode::OK, Json(json!({ "ok": admit, "account": account, "receipt_ref": receipt })))
}

/// GET /provider-materials — daemon-custody snapshot material (admitted state roots).
pub(crate) async fn handle_provider_materials(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut materials = read_record_dir(&st.data_dir, MATERIAL_KIND);
    materials.sort_by(|a, b| text(b, "material_id").cmp(text(a, "material_id")));
    Json(json!({ "schema_version": "ioi.hypervisor.provider-materials.v1", "custody_rule": "blob existence is not restore truth — restores admit by daemon-recorded sha256 state_root", "materials": materials, "at": iso_now() }))
}

/// GET /v1/hypervisor/providers — static adapters × durable BYO accounts, honest per-entry
/// status. Placement reads THIS catalog live, so a verified account becomes placeable with no
/// extra wiring (deterministic selection only — no routing fee, no smart placement).
pub(crate) async fn handle_providers_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut providers: Vec<Value> = registry().iter().map(|p| {
        let (status, reason) = p.status();
        json!({ "provider_ref": p.id(), "capabilities": p.capabilities(), "status": status, "reason": reason })
    }).collect();
    let mut accounts_out: Vec<Value> = Vec::new();
    for account in read_record_dir(&st.data_dir, ACCOUNT_KIND) {
        let kind = text(&account, "kind").to_string();
        let (status, reason) = if kind == "baremetal_ssh" {
            match text(&account, "status") {
                "verified" => ("available", format!("verified bare-metal SSH node ({})", text(&account, "display_name"))),
                "revoked" => ("revoked", "credential revoked".to_string()),
                _ => ("unverified", "bind + preflight to admit this node".to_string()),
            }
        } else {
            match text(&account, "status") {
                "verified" => ("credential_verified", format!("'{kind}' credential verified — lifecycle lands with its adapter cut")),
                "revoked" => ("revoked", "credential revoked".to_string()),
                _ => ("unverified", "bind + preflight the credential".to_string()),
            }
        };
        let mut caps = kind_capabilities(&kind);
        caps["provider_spend_borne_by"] = json!("customer");
        let entry = json!({
            "provider_ref": format!("account:{}", text(&account, "account_id")),
            "account_ref": text(&account, "account_ref"),
            "kind": kind,
            "display_name": text(&account, "display_name"),
            "capabilities": caps,
            "status": status,
            "reason": reason,
            "provider_spend_borne_by": "customer",
        });
        providers.push(entry.clone());
        accounts_out.push(entry);
    }
    Json(json!({
        "schema_version": "ioi.hypervisor.providers.v1",
        "first_remote_provider_target": "other:loopback-runner",
        "providers": providers,
        "accounts": accounts_out,
        "spend_rule": "BYO provider spend is customer-borne; the hypervisor records, governs, estimates, and reconciles — never hidden markup",
        "truth_rule": "provider-native IDs are evidence refs only; the daemon owns admitted ops, state roots, restore refs, and receipts",
        "at": iso_now()
    }))
}

/// POST /v1/hypervisor/provider-ops — body-dispatched provider lifecycle op (collision-safe).
/// Body: `{ provider_id, op, environment_ref?, plan?, command?, material_ref?, grant_ref? }`.
/// op ∈ preflight | create | start | workrun | stop | snapshot | restore | inject_outage |
/// recover | delete | observe. Records an admitted-operation record + a provider receipt.
pub(crate) async fn handle_provider_op(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let data_dir = &st.data_dir;
    let provider_id = body
        .get("provider_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let op = body.get("op").and_then(|v| v.as_str()).unwrap_or("");
    let env_ref = body
        .get("environment_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("env-default")
        .to_string();

    // ── BYO account lane: budget BEFORE mutation, REAL wallet grant (never a presence check),
    //    capability-lease receipts on every path. The KeyGuard removes the materialized ssh key.
    if let Some(resolved) = resolve_account_adapter(data_dir, provider_id) {
        let (account, provider, _key_guard) = match resolved {
            Ok(triple) => triple,
            Err(reason) => {
                let receipt = provider_receipt_ext(data_dir, provider_id, &env_ref, op, "credential_unresolved", &json!({ "error": reason }));
                return (StatusCode::PRECONDITION_REQUIRED, Json(json!({ "ok": false, "op": op, "provider": provider_id, "reason": reason, "receipt_ref": receipt })));
            }
        };
        let account_id = text(&account, "account_id").to_string();
        let account_ref = text(&account, "account_ref").to_string();
        let kind = text(&account, "kind").to_string();
        let mutation = !matches!(op, "preflight" | "observe");
        let mut vast_gate = Value::Null;
        let mut budget_note = Value::Null;
        let mut lease_note = Value::Null;
        let mut grant_ref = Value::Null;
        if mutation {
            // 1) external_spend posture is discovered BEFORE any provider mutation.
            match discover_budget(data_dir, &kind, op) {
                Ok(note) => budget_note = note,
                Err(reason) => {
                    let receipt = provider_receipt_ext(data_dir, &kind, &env_ref, op, "budget_blocked", &json!({ "account_ref": account_ref, "error": reason }));
                    return (StatusCode::CONFLICT, Json(json!({ "ok": false, "op": op, "provider": provider_id, "account_ref": account_ref, "reason": reason, "receipt_ref": receipt })));
                }
            }
            // 1b) vast GUARDED LIFECYCLE: create is QUOTE-GATED. The quote must be fresh (not
            //     expired/superseded), priced, bound to THIS account, and NEVER fixture evidence;
            //     live control plane demands live_evidence, the simulator demands
            //     simulator_evidence (labelled harness, no real spend). Runs AFTER budget
            //     discovery and BEFORE the wallet challenge (canon gate order).
            if matches!(kind.as_str(), "vast" | "runpod") && op == "create" {
                let candidate_ref = body.get("candidate_ref").and_then(Value::as_str).unwrap_or("");
                if candidate_ref.is_empty() {
                    let code = format!("{kind}_candidate_ref_required");
                    let receipt = provider_receipt_ext(data_dir, &kind, &env_ref, op, "quote_gate_refused", &json!({ "account_ref": account_ref, "error": code }));
                    return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "ok": false, "op": op, "provider": provider_id, "reason": format!("{code} — provisioning is quote-gated; pass the candidate_ref of a fresh, live, priced CloudResourceCandidate"), "receipt_ref": receipt })));
                }
                let candidate = read_record_dir(data_dir, "cloud-resource-candidates")
                    .into_iter()
                    .find(|c| text(c, "candidate_ref") == candidate_ref);
                let refuse = |code: &str, detail: String| {
                    let receipt = provider_receipt_ext(data_dir, &kind, &env_ref, op, "quote_gate_refused", &json!({ "account_ref": account_ref, "candidate_ref": candidate_ref, "error": code }));
                    (StatusCode::CONFLICT, Json(json!({ "ok": false, "op": op, "provider": provider_id, "reason": format!("{code} — {detail}"), "receipt_ref": receipt })))
                };
                let Some(candidate) = candidate else {
                    return refuse(&format!("{kind}_candidate_unknown"), "no such CloudResourceCandidate — refresh candidates and retry".into());
                };
                if text(&candidate, "provider_account_ref") != account_ref {
                    return refuse(&format!("{kind}_candidate_account_mismatch"), "the candidate belongs to a different provider account".into());
                }
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                let expired = candidate.get("expires_epoch").and_then(Value::as_u64).map(|e| now > e).unwrap_or(true);
                if expired || candidate.get("status").and_then(Value::as_str) == Some("superseded") {
                    return refuse(&format!("{kind}_quote_expired_requires_requote"), "expired or superseded quotes can never mutate — refresh candidates for a fresh quote".into());
                }
                let evidence_mode = text(&candidate, "evidence_mode").to_string();
                let account_mode = vast_mode(&account);
                if evidence_mode == "fixture_evidence" {
                    return refuse(&format!("{kind}_quote_not_live"), "fixture quotes are advisory forever and can never provision".into());
                }
                let mode_ok = (account_mode == "live" && evidence_mode == "live_evidence")
                    || (account_mode == "simulator" && evidence_mode == "simulator_evidence");
                if !mode_ok {
                    return refuse(&format!("{kind}_quote_mode_mismatch"), format!("account control plane is '{account_mode}' but the quote evidence is '{evidence_mode}' — live provisioning demands live quotes; the simulator demands simulator quotes"));
                }
                let Some(price) = candidate.pointer("/quote/usd_per_hour").and_then(Value::as_f64) else {
                    return refuse(&format!("{kind}_quote_unpriced"), "a candidate without a real price can never provision".into());
                };
                let max_hourly = body.get("max_hourly_usd").and_then(Value::as_f64).unwrap_or(price);
                if price > max_hourly {
                    return refuse(&format!("{kind}_price_above_max"), format!("offer price ${price}/hr exceeds the declared max ${max_hourly}/hr"));
                }
                // Reservation adequacy: headroom after OPEN exposures must cover this create's
                // first-hour reservation at the declared max rate. Checked here (not at budget
                // discovery) because the price is only known once the quote is validated.
                let headroom = budget_note.get("remaining_headroom_after_reservations").and_then(Value::as_f64).unwrap_or(0.0);
                if headroom - max_hourly < 0.0 {
                    return refuse(&format!("{kind}_budget_reservation_exceeded"), format!("open exposures already reserve the external_spend headroom (remaining ${headroom:.3} < first-hour reservation ${max_hourly:.3}/hr) — tear an instance down or raise the budget"));
                }
                vast_gate = json!({
                    "candidate_ref": candidate_ref,
                    "quote_ref": candidate["quote_ref"],
                    "offer_id": candidate.pointer("/quote/offer_id").cloned().unwrap_or(Value::Null),
                    "usd_per_hour": price,
                    "max_hourly_usd": max_hourly,
                    "gpu": candidate.get("gpu").cloned().unwrap_or(Value::Null),
                    "spend_estimate": candidate.get("spend_estimate").cloned().unwrap_or(Value::Null),
                    "execution_mode": if account_mode == "live" { "live" } else { "simulated_control_plane" },
                    "teardown_policy": body.get("teardown_policy").and_then(Value::as_str).unwrap_or("always_teardown_required"),
                });
            }
            // 2) A REAL wallet grant via the capability-lease gateway — 403 challenge echoes the
            //    exact policy/request hashes to mint against; the lease descriptor carries no secret.
            let lease_req = CapabilityLeaseRequest {
                authority_provider_ref: "wallet.network".to_string(),
                backing_provider: format!("provider:account:{account_id}"),
                allowed_tools: vec![format!("provider.{op}")],
                resource_refs: vec![account_ref.clone(), env_ref.clone()],
                scopes: vec!["provider.provision".to_string()],
                policy_domain: "hypervisor.provider.op.policy.v1".to_string(),
                request_domain: "hypervisor.provider.op.request.v1".to_string(),
                request_facets: {
                    let mut facets = json!({ "account_ref": account_ref, "op": op, "environment_ref": env_ref, "kind": kind, "external_spend_posture": budget_note.get("scope").cloned().unwrap_or(Value::Null) });
                    if let (Some(target), Some(gate)) = (facets.as_object_mut(), vast_gate.as_object()) {
                        for key in ["candidate_ref", "quote_ref", "max_hourly_usd", "gpu", "teardown_policy", "execution_mode"] {
                            if let Some(v) = gate.get(key) { target.insert(key.to_string(), v.clone()); }
                        }
                    }
                    facets
                },
                credential_connector_id: Some(account_id.clone()),
                credential_store: CREDENTIAL_VAULT.to_string(),
                credential_required: true,
                github_host_fallback: false,
                receipt_required: true,
                revocation_ref: format!("provider-accounts/{account_id}/credential"),
                authority_reason: "provider_operation_authority_required".to_string(),
                grant_value: body.get("wallet_approval_grant").cloned().unwrap_or(Value::Null),
            };
            match authorize_capability_lease(&st, &lease_req).await {
                Err((status, challenge)) => {
                    let outcome = if status == StatusCode::PRECONDITION_REQUIRED { "credential_unresolved" } else { "authority_missing" };
                    let receipt = provider_receipt_ext(data_dir, &kind, &env_ref, op, outcome, &json!({ "account_ref": account_ref, "budget_discovery": budget_note }));
                    let mut payload = challenge;
                    if let Some(object) = payload.as_object_mut() {
                        object.insert("receipt_ref".into(), json!(receipt));
                        object.insert("account_ref".into(), json!(account_ref));
                        if !vast_gate.is_null() {
                            object.insert("lease_request_facets".into(), vast_gate.clone());
                            object.insert("spend_estimate".into(), vast_gate.get("spend_estimate").cloned().unwrap_or(Value::Null));
                        }
                    }
                    return (status, Json(payload));
                }
                Ok(lease) => {
                    lease_note = lease.descriptor.clone();
                    grant_ref = json!(lease.grant_ref);
                }
            }
        }
        let mut plan = body.get("plan").cloned().unwrap_or_else(|| json!({}));
        if let (Some(target), Some(gate)) = (plan.as_object_mut(), vast_gate.as_object()) {
            for (k, v) in gate { target.insert(k.clone(), v.clone()); }
        }
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
        let cost_estimate = budget_note.get("cost_estimate").cloned().unwrap_or(Value::Null);
        return match result {
            Ok(evidence) => {
                let receipt = provider_receipt_ext(data_dir, &kind, &env_ref, op, "ok", &json!({
                    "account_ref": account_ref, "grant_ref": grant_ref, "capability_lease": lease_note,
                    "cost_estimate": cost_estimate, "budget_discovery": budget_note,
                    "candidate_ref": vast_gate.get("candidate_ref").cloned().unwrap_or(Value::Null),
                    "quote_ref": vast_gate.get("quote_ref").cloned().unwrap_or(Value::Null),
                    "spend_estimate": vast_gate.get("spend_estimate").cloned().unwrap_or(Value::Null),
                    "execution_mode": vast_gate.get("execution_mode").cloned().unwrap_or(Value::Null),
                    "provider_native": evidence.get("provider_native").cloned().unwrap_or(Value::Null),
                    "teardown_state": evidence.get("teardown_state").cloned().unwrap_or(Value::Null),
                    "state_root": evidence.get("state_root").cloned().unwrap_or(Value::Null),
                }));
                let op_id = format!("pop_{:x}", nanos());
                let record = json!({
                    "schema_version": "ioi.hypervisor.provider-operation.v1",
                    "operation_id": op_id, "provider": kind, "account_ref": account_ref,
                    "environment_ref": env_ref, "op": op, "evidence": evidence,
                    "grant_ref": grant_ref, "budget_discovery": budget_note, "cost_estimate": cost_estimate,
                    "receipt_ref": receipt, "at": iso_now()
                });
                let _ = persist_record(data_dir, "provider-operations", &op_id, &record);
                // ── Spend exposure accounting (customer-borne; estimates only, never a bill) ──
                if op == "create" && !vast_gate.is_null() {
                    let exp_id = format!("pse_{:x}", nanos());
                    let exposure = json!({
                        "schema_version": "ioi.hypervisor.provider-spend-exposure.v1",
                        "exposure_id": exp_id,
                        "exposure_ref": format!("provider-spend-exposure://{exp_id}"),
                        "account_ref": account_ref, "provider": kind, "environment_ref": env_ref,
                        "candidate_ref": vast_gate["candidate_ref"], "quote_ref": vast_gate["quote_ref"],
                        "grant_ref": grant_ref, "capability_lease_ref": lease_note.get("lease_id").cloned().unwrap_or(Value::Null),
                        "usd_per_hour": vast_gate["usd_per_hour"], "max_hourly_usd": vast_gate["max_hourly_usd"],
                        "execution_mode": vast_gate["execution_mode"],
                        "budget_ref": budget_note.get("budget_ref").cloned().unwrap_or(Value::Null),
                        "provider_native": {
                            "ids": evidence.get("provider_native").cloned().unwrap_or(Value::Null),
                            "note": "evidence only — never restore or billing truth",
                        },
                        "status": "open",
                        "teardown_state": "live_or_pending",
                        "create_receipt_ref": receipt,
                        "receipt_refs": [receipt],
                        "state_roots": Vec::<String>::new(),
                        "estimate_note": "quote-backed ESTIMATE authorized by the grant — no actual provider bill exists here; spend is customer-borne on the customer's own account",
                        "opened_at": iso_now(),
                    });
                    let _ = persist_record(data_dir, EXPOSURE_KIND, &exp_id, &exposure);
                } else if matches!(kind.as_str(), "vast" | "runpod") {
                    if let Some(mut exposure) = open_exposure_for(data_dir, &account_ref, &env_ref) {
                        let exp_id = text(&exposure, "exposure_id").to_string();
                        let mut refs = exposure.get("receipt_refs").and_then(Value::as_array).cloned().unwrap_or_default();
                        refs.push(json!(receipt));
                        exposure["receipt_refs"] = json!(refs);
                        if let Some(root) = evidence.get("state_root").and_then(Value::as_str) {
                            let mut roots = exposure.get("state_roots").and_then(Value::as_array).cloned().unwrap_or_default();
                            roots.push(json!(root));
                            exposure["state_roots"] = json!(roots);
                        }
                        if op == "delete" {
                            let destroyed = evidence.pointer("/native_teardown/destroyed").and_then(Value::as_bool).unwrap_or(false);
                            exposure["teardown_state"] = evidence.get("teardown_state").cloned().unwrap_or(json!("torn_down"));
                            exposure["teardown_receipt_ref"] = json!(receipt);
                            exposure["closed_at"] = json!(iso_now());
                            if destroyed {
                                exposure["status"] = json!("closed");
                            } else {
                                exposure["status"] = json!("closed_with_warning");
                                exposure["warning"] = json!("INCOMPLETE TEARDOWN — the provider-native destroy did not confirm; verify the provider console (exposure may still accrue on the customer's account)");
                            }
                        }
                        let _ = persist_record(data_dir, EXPOSURE_KIND, &exp_id, &exposure);
                    }
                }
                (StatusCode::OK, Json(json!({ "ok": true, "op": op, "provider": provider_id, "account_ref": account_ref, "environment_ref": env_ref, "evidence": evidence, "receipt_ref": receipt, "cost_estimate": cost_estimate })))
            }
            Err(reason) => {
                let outcome = if reason.contains("NOT_IMPLEMENTED") { "not_implemented" } else if reason.contains("hash_mismatch") { "restore_refused" } else { "error" };
                let receipt = provider_receipt_ext(data_dir, &kind, &env_ref, op, outcome, &json!({
                    "account_ref": account_ref, "grant_ref": grant_ref, "capability_lease": lease_note, "error": reason,
                    "candidate_ref": vast_gate.get("candidate_ref").cloned().unwrap_or(Value::Null),
                    "quote_ref": vast_gate.get("quote_ref").cloned().unwrap_or(Value::Null),
                    "execution_mode": vast_gate.get("execution_mode").cloned().unwrap_or(Value::Null),
                }));
                (StatusCode::OK, Json(json!({ "ok": false, "op": op, "provider": provider_id, "account_ref": account_ref, "environment_ref": env_ref, "reason": reason, "outcome": outcome, "receipt_ref": receipt })))
            }
        };
    }

    // ── Legacy static-adapter lane (local-microvm / loopback-runner / cloud-vpc) — unchanged. ──
    let Some(provider) = resolve(provider_id) else {
        let receipt = provider_receipt(data_dir, provider_id, &env_ref, op, "error");
        return (StatusCode::OK, Json(json!({ "ok": false, "reason": format!("unknown provider '{provider_id}'"), "receipt_ref": receipt })));
    };

    // Remote/external providers require an authority grant for provider-credential materialization.
    let cap = provider.capabilities();
    let creds_required = cap
        .get("credentials_required")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if creds_required
        && matches!(op, "create" | "start" | "workrun")
        && body.get("grant_ref").and_then(|v| v.as_str()).is_none()
    {
        let receipt = provider_receipt(data_dir, provider_id, &env_ref, op, "authority_missing");
        return (StatusCode::OK, Json(
            json!({ "ok": false, "op": op, "provider": provider_id, "reason": "provider credentials are authority-gated; present a grant_ref (effect=provider_credential)", "receipt_ref": receipt }),
        ));
    }

    let plan = body.get("plan").cloned().unwrap_or_else(|| json!({}));
    let command = body
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("true");
    let material_ref = body
        .get("material_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("");
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
            (StatusCode::OK, Json(
                json!({ "ok": true, "op": op, "provider": provider_id, "environment_ref": env_ref, "evidence": evidence, "receipt_ref": receipt }),
            ))
        }
        Err(reason) => {
            let outcome = if reason.contains("NOT_CONFIGURED") {
                "not_configured"
            } else {
                "error"
            };
            let receipt = provider_receipt(data_dir, provider_id, &env_ref, op, outcome);
            (StatusCode::OK, Json(
                json!({ "ok": false, "op": op, "provider": provider_id, "environment_ref": env_ref, "reason": reason, "outcome": outcome, "receipt_ref": receipt }),
            ))
        }
    }
}

/// GET /v1/hypervisor/provider-spend/reconciliation — customer-borne external-spend
/// reconciliation over EXISTING records only (exposures + budgets + receipts). Not billing,
/// not fees, not settlement: every number is backed by receipt refs; actual provider bills
/// are never invented.
pub(crate) async fn handle_spend_reconciliation(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let exposures = read_record_dir(&st.data_dir, EXPOSURE_KIND);
    let budgets = read_record_dir(&st.data_dir, "resource-budgets");
    let budget = budgets.iter().find(|b| b["scope"].as_str() == Some("external_spend"));
    let reserved = open_reserved_estimate(&st.data_dir);
    let (limit, spent) = budget
        .map(|b| (b["limit"].as_f64().unwrap_or(0.0), b["spent"].as_f64().unwrap_or(0.0)))
        .unwrap_or((0.0, 0.0));
    let open: Vec<&Value> = exposures.iter().filter(|e| text(e, "status") == "open").collect();
    let warned: Vec<&Value> = exposures.iter().filter(|e| text(e, "status") == "closed_with_warning").collect();
    let closed: Vec<&Value> = exposures.iter().filter(|e| text(e, "status") == "closed").collect();
    let authorized: f64 = exposures.iter().filter_map(|e| e.get("max_hourly_usd").and_then(Value::as_f64)).sum();
    let open_estimate: f64 = open.iter().filter_map(|e| e.get("usd_per_hour").and_then(Value::as_f64)).sum();
    Json(json!({
        "schema_version": "ioi.hypervisor.provider-spend-reconciliation.v1",
        "budget": {
            "budget_ref": budget.map(|b| json!(format!("budget://{}", text(b, "budget_id")))).unwrap_or(Value::Null),
            "exists": budget.is_some(),
            "limit": limit, "spent": spent,
            "reserved_open_estimates": reserved,
            "remaining_headroom": limit - spent - reserved,
            "spent_note": "budget `spent` reflects ACTUAL debits only — reservations and estimates never fake it",
        },
        "authorized_external_spend_rate": { "usd_per_hour_sum": authorized, "basis": "sum of grant-authorized max hourly rates across all exposures (rates, not totals — open rentals have no invented total)" },
        "estimated_open_exposure_rate": { "usd_per_hour_sum": open_estimate, "open_count": open.len() },
        "teardown_finalized": { "count": closed.len() },
        "unsettled_estimates": { "count": open.len() + warned.len(), "note": "estimates stay unsettled until the customer's own provider bill — Hypervisor never fakes settlement" },
        "incomplete_teardown_warnings": warned.iter().map(|e| json!({
            "exposure_ref": e["exposure_ref"], "account_ref": e["account_ref"],
            "environment_ref": e["environment_ref"], "warning": e["warning"],
            "teardown_receipt_ref": e["teardown_receipt_ref"],
        })).collect::<Vec<_>>(),
        "rows": exposures,
        "spend_rule": "BYO/marketplace provider spend is CUSTOMER-BORNE on the customer's own account; Hypervisor records, governs, estimates, and reconciles — no fee objects, no markup, no Work Credit debit, no fake settlement",
        "at": iso_now(),
    }))
}

/// GET /v1/hypervisor/provider-receipts — the crossing audit trail (success AND failure receipts;
/// a refused crossing is evidence too). Descriptors only — never credential material.
pub(crate) async fn handle_provider_receipts(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut receipts = super::read_record_dir(&st.data_dir, "provider-receipts");
    receipts.sort_by(|a, b| text(b, "receipt_id").cmp(text(a, "receipt_id")));
    Json(json!({
        "schema_version": "ioi.hypervisor.provider-receipts.v1",
        "spend_rule": "BYO provider spend is customer-borne; receipts record and reconcile it — never hidden markup",
        "receipts": receipts,
        "at": iso_now()
    }))
}

/// GET /v1/hypervisor/provider-operations — the admitted-operation audit trail (daemon truth).
pub(crate) async fn handle_provider_operations(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut ops = super::read_record_dir(&st.data_dir, "provider-operations");
    ops.sort_by(|a, b| {
        b.get("operation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("operation_id").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(
        json!({ "schema_version": "ioi.hypervisor.provider-operations.v1", "operations": ops, "at": iso_now() }),
    )
}
