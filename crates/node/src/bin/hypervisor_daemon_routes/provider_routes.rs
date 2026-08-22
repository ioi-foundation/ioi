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
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::Json;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::lifecycle_routes::{
    authorize_capability_lease, open_scm_token, seal_scm_token, CapabilityLeaseRequest,
};
use ioi_services::agentic::runtime::kernel::emergency_containment::{
    close_deletion, DeletionOutcome,
};
use ioi_services::wallet_network::SettleStandingApprovalGrantConsumptionParams;

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

fn standing_consumption_for_environment(
    data_dir: &str,
    provider: &str,
    environment_ref: &str,
) -> Option<[u8; 32]> {
    let record = read_record_dir(data_dir, "provider-operations")
        .into_iter()
        .filter(|record| {
            text(record, "provider") == provider
                && text(record, "environment_ref") == environment_ref
                && matches!(text(record, "op"), "create" | "redeploy")
                && record
                    .pointer("/capability_lease/authority_mode")
                    .and_then(Value::as_str)
                    == Some("standing_envelope")
        })
        .max_by(|left, right| text(left, "at").cmp(text(right, "at")))?;
    let encoded = record
        .pointer("/capability_lease/standing_consumption_id")
        .and_then(Value::as_str)?;
    let mut consumption_id = [0u8; 32];
    hex::decode_to_slice(encoded, &mut consumption_id).ok()?;
    Some(consumption_id)
}

fn terminal_spend_microusd(evidence: &Value) -> Option<(u64, &Value)> {
    let settlement = evidence
        .get("settlement")
        .or_else(|| evidence.get("provider_native_settlement"))
        .or_else(|| evidence.pointer("/provider_native/settlement"))?;
    if settlement.get("provider_terminal").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let usd = settlement.get("final_debit_usd")?.as_f64()?;
    if !usd.is_finite() || usd < 0.0 || usd > (u64::MAX as f64 / 1_000_000.0) {
        return None;
    }
    Some(((usd * 1_000_000.0).round() as u64, settlement))
}
/// Derive the EXACT deletion outcome for a provider teardown.
///
/// CARVE-OUT: deletion of an existing provider resource always remains callable — this helper
/// never refuses. It replaces a hardcoded `cleanup_verified: true` that every adapter emitted
/// even when the provider-native destroy explicitly reported `destroyed: false` or when the
/// remote-workspace cleanup was `"unreachable"`.
///
/// Mapping (`unknown` is first-class and never coerced):
/// - `succeeded` — the provider confirmed destruction AND the remote cleanup was not unreachable.
/// - `failed`    — the provider explicitly reported it did not destroy the resource.
/// - `unknown`   — the provider returned no `destroyed` verdict, or the remote half was
///   unreachable, so absence cannot be claimed.
///
/// Returns `(teardown_state, cleanup_verified, deletion_disposition)`.
fn provider_teardown_disposition(
    resource_ref: &str,
    native_teardown: &Value,
    remote_cleanup: &Value,
) -> (&'static str, bool, Value) {
    let destroyed = native_teardown.get("destroyed").and_then(Value::as_bool);
    let remote_unreachable = remote_cleanup.as_str() == Some("unreachable");
    let outcome = match (destroyed, remote_unreachable) {
        (Some(true), false) => DeletionOutcome::Succeeded,
        (Some(false), _) => DeletionOutcome::Failed,
        // No verdict at all, or destroyed-but-remote-half-unreachable: honestly unknown.
        (None, _) | (Some(true), true) => DeletionOutcome::Unknown,
    };
    let disposition = close_deletion(resource_ref, outcome);
    let state = match outcome {
        DeletionOutcome::Succeeded => "torn_down",
        DeletionOutcome::Failed => "teardown_failed",
        DeletionOutcome::Unknown => "torn_down_unverified",
    };
    (
        state,
        outcome == DeletionOutcome::Succeeded,
        disposition.to_json(),
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
) -> Option<String> {
    provider_receipt_ext(data_dir, provider, env_ref, op, outcome, &json!({}))
}

/// Enriched provider receipt — BYO account operations cite the account, the capability-lease
/// descriptor (never a secret), the grant, credential source, and the cost estimate. Written on
/// SUCCESS AND FAILURE alike: a refused crossing is evidence too.
/// A provider-account write that did not durably land. These records carry credential bindings and
/// the verified/unverified posture that a preflight verdict establishes, so returning them as
/// admitted state over a lost write misreports the account's authority posture.
fn provider_account_persist_failed(what: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "ok": false, "error": {
            "code": "provider_account_persistence_failed",
            "message": format!("the provider account {what} could not be durably recorded")
        }})),
    )
}

/// A provider-op durable write that did not land AFTER the external provider effect already
/// executed. The response names the op, the receipt (may be null if it too did not persist), and
/// the provider-native evidence ids, so the caller can reconcile a resource that exists but has no
/// daemon handle — never a silent 2xx over a lost record.
fn provider_op_persist_failed(
    code: &str,
    op: &str,
    provider: &str,
    env_ref: &str,
    receipt: &Option<String>,
    provider_native: Value,
    what_happened: &str,
) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "ok": false, "code": code, "op": op, "provider": provider, "environment_ref": env_ref,
            "receipt_ref": receipt, "provider_native": provider_native,
            "message": format!("{what_happened} — the external provider effect ALREADY happened but this record did not commit, so the resource is not reconcilable through the daemon (receipt {rcpt}). Retry the op or reconcile from the provider console.", rcpt = receipt.as_deref().unwrap_or("<receipt-not-persisted>")),
        })),
    )
}

/// C2 — the external effect happened (or may have) and the pre-effect INTENT is
/// committed, but the outcome/completion root did not finalize. This is
/// `reconciliation_required`: NOT a refusal (the effect is not undone) and NOT
/// "nothing happened" (the intent root proves the attempt). 202 Accepted — the
/// outcome is owed, not failed; the live resource is reconcilable through the
/// committed intent root.
#[allow(clippy::too_many_arguments)]
fn provider_op_reconciliation_required(
    op: &str,
    provider: &str,
    env_ref: &str,
    receipt: &Option<String>,
    provider_native: Value,
    journal_ref: &str,
    intent_state_root: &str,
    what_happened: &str,
) -> (StatusCode, Json<Value>) {
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "ok": false,
            "code": "reconciliation_required",
            "op": op, "provider": provider, "environment_ref": env_ref,
            "receipt_ref": receipt, "provider_native": provider_native,
            "journal_ref": journal_ref,
            "intent_state_root": intent_state_root,
            "message": format!("{what_happened} — the pre-effect INTENT is committed (root {intent_state_root}), so this is reconciliation_required, NOT a refusal and NOT 'nothing happened'. Reconcile the outcome against the committed intent (receipt {rcpt}).", rcpt = receipt.as_deref().unwrap_or("<receipt-not-persisted>")),
        })),
    )
}

fn provider_receipt_ext(
    data_dir: &str,
    provider: &str,
    env_ref: &str,
    op: &str,
    outcome: &str,
    extra: &Value,
) -> Option<String> {
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
    // Returns None when the receipt did not land, so no caller can cite a `receipt_ref` that
    // resolves to nothing — the defect authority_routes was closed for. Callers embedding this in a
    // response serialize None as null, which is honest; callers for whom the receipt IS the
    // evidence of an authority change refuse instead.
    persist_record(data_dir, "provider-receipts", &id, &rec)
        .ok()
        .map(|_| receipt_ref)
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
    /// Provider-native service/control-plane logs (read-only evidence). Default: no log lane.
    fn logs(&self, _data_dir: &str, _env_ref: &str) -> Result<Value, String> {
        Err("logs_not_supported — this provider records no native log lane; workspace exec outputs are receipted in the Work Ledger".into())
    }
    /// Provider-native lifecycle events (read-only evidence). Default: no event lane.
    fn events(&self, _data_dir: &str, _env_ref: &str) -> Result<Value, String> {
        Err("events_not_supported — this provider records no native event lane".into())
    }
    /// Provider-native billing/escrow reconciliation. Read-only at the provider; adapters may
    /// durably advance their local projection only from the fetched counterparty truth.
    fn reconcile(&self, _data_dir: &str, _env_ref: &str) -> Result<Value, String> {
        Err("provider_reconciliation_not_supported".into())
    }
    /// Reboot/restart where the provider supports it (EC2 reboot semantics).
    fn restart(&self, _data_dir: &str, _env_ref: &str) -> Result<Value, String> {
        Err("restart_not_supported — stop and start explicitly on this provider".into())
    }
    /// Re-provision after closure/loss with restore lineage (DePIN redeploy semantics).
    fn redeploy(&self, _data_dir: &str, _env_ref: &str, _plan: &Value) -> Result<Value, String> {
        Err("redeploy_not_supported — close and create explicitly on this provider".into())
    }
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
const ACCOUNT_KINDS: &[&str] = &[
    "baremetal_ssh",
    "aws",
    "gcp",
    "azure",
    "k8s",
    "vast",
    "runpod",
    "lambda_cloud",
    "akash",
];

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
        "baremetal_ssh" => {
            json!({ "locality": "remote", "isolation": "customer_host", "restore": true, "remote": true, "transport": "ssh", "credentials_required": true, "authority_gated": true, "privacy": "customer_controlled_host", "lifecycle": "full" })
        }
        "aws" => json!({ "locality": "remote", "isolation": "vm_kernel",
            "lane": "ENTERPRISE customer-cloud — your AWS account, your IAM boundary, your audit trail",
            "authority_model": "IAM/SigV4 — the sealed credential's IAM scope bounds every action (iam_scope_dependent)",
            "network_posture": "VPC/subnet/security-group posture recorded per instance; SSH requires ingress + a reachable IP — private-only postures fail closed, never fake-ready",
            "instance_lifecycle": "EC2 create → boot → stop/start/restart → terminate (stop halts instance-hours; EBS storage keeps billing until terminate)",
            "volumes": "EBS root volume posture recorded; native volume/snapshot ids are EVIDENCE only — daemon custody state roots remain restore truth",
            "restore": true, "remote": true, "credentials_required": true, "authority_gated": true,
            "privacy": "customer_cloud_iam_scoped",
            "custody": "Standard unless proven otherwise; provider-native EC2/EBS/snapshot ids are evidence only",
            "provider_spend": "customer-borne on-demand spend",
            "lifecycle": "guarded (quote-gated) once a control-plane mode is set; credential_preflight_only before that" }),
        "gcp" => json!({ "locality": "remote", "isolation": "vm_kernel",
            "lane": "ENTERPRISE customer-cloud — your GCP project, your service-account boundary, your audit logs",
            "authority_model": "service-account / workload-identity — the sealed credential's IAM scope bounds every action (iam_service_account_scope_dependent)",
            "scoping": "project / region / ZONE posture recorded per instance",
            "network_posture": "VPC network/subnetwork/FIREWALL posture recorded per instance; SSH requires a firewall allow rule + a reachable external IP — private-only or firewall-closed postures fail closed, never fake-ready",
            "instance_lifecycle": "Compute Engine create → boot → stop/start/reset → delete (stop = TERMINATED: vCPU/RAM billing halts; Persistent Disk keeps billing until delete)",
            "volumes": "Persistent Disk boot volume posture recorded; native disk/snapshot ids are EVIDENCE only — daemon custody state roots remain restore truth",
            "restore": true, "remote": true, "credentials_required": true, "authority_gated": true,
            "privacy": "customer_cloud_iam_scoped",
            "custody": "Standard unless proven otherwise; provider-native instance/disk/snapshot ids are evidence only",
            "provider_spend": "customer-borne on-demand spend",
            "lifecycle": "guarded (quote-gated) once a control-plane mode is set; credential_preflight_only before that" }),
        "azure" => json!({ "locality": "remote", "isolation": "vm_kernel",
            "lane": "ENTERPRISE customer-cloud — your Azure subscription, your service-principal boundary, your Activity Log",
            "authority_model": "service-principal / managed-identity over Azure Resource Manager — the sealed credential's Entra scope bounds every action (entra_service_principal_scope_dependent)",
            "scoping": "subscription / RESOURCE GROUP / location posture recorded per VM",
            "network_posture": "VNet/subnet/NSG posture recorded per VM; SSH requires an NSG allow rule + a reachable public IP — private-only or NSG-denied postures fail closed, never fake-ready",
            "instance_lifecycle": "VM create → boot → stop/DEALLOCATE/start/restart → delete (stopped still bills compute; only DEALLOCATED halts compute billing; managed disks keep billing until delete)",
            "volumes": "managed OS disk posture recorded; native disk/snapshot/resource ids are EVIDENCE only — daemon custody state roots remain restore truth",
            "restore": true, "remote": true, "credentials_required": true, "authority_gated": true,
            "privacy": "customer_cloud_iam_scoped",
            "custody": "Standard unless proven otherwise; provider-native VM/disk/snapshot/resource ids are evidence only",
            "provider_spend": "customer-borne pay-as-you-go spend",
            "lifecycle": "guarded (quote-gated) once a control-plane mode is set; credential_preflight_only before that" }),
        "k8s" => json!({ "locality": "remote", "isolation": "container",
            "lane": "CLUSTER substrate — Kubernetes/KubeVirt/customer clusters treated as CLUSTERS: namespaces, quotas, PVCs, GPU scheduling, services/ingress, admission; never fake single-VM SSH",
            "admission": "namespace-scoped — RBAC, resource quotas/limits, storage-class and service posture all fail closed by name",
            "exec": "Kubernetes exec semantics (logs/exec through the workload) — SSH only if a workload explicitly declares it",
            "storage": "PVC/storage-class posture recorded per workload; PVC persistence is CLUSTER posture — daemon custody state roots remain restore truth",
            "gpu": "device-plugin scheduling posture — GPU requests are admitted against quota + node posture, never assumed",
            "kubevirt": "KubeVirt VMIs when the CRDs are detected — explicitly KubeVirt, never a generic VM; absent CRDs fail closed by name",
            "restore": true, "remote": true, "credentials_required": true, "authority_gated": true,
            "privacy": "cluster_operator_controlled",
            "custody": "Standard unless proven otherwise; pod/job/service/PVC/VM names and uids are evidence only",
            "provider_spend": "customer/operator-borne — no direct provider price; a DECLARED metered posture with a sourced price is required to price anything",
            "lifecycle": "guarded (admission-gated) once a control-plane mode is set; credential_preflight_only before that" }),
        "vast" => {
            json!({ "locality": "remote", "isolation": "container_gpu", "restore": true, "remote": true, "credentials_required": true, "authority_gated": true, "privacy": "marketplace_host_NOT_private", "lifecycle": "credential_preflight_only" })
        }
        "runpod" => {
            json!({ "locality": "remote", "isolation": "container_gpu_runtime", "restore": true, "remote": true, "credentials_required": true, "authority_gated": true, "privacy": "cloud_gpu_runtime_NOT_private", "custody": "Standard unless proven otherwise", "lifecycle": "guarded (quote-gated) once a control-plane mode is set; credential_preflight_only before that" })
        }
        "lambda_cloud" => {
            json!({ "locality": "remote", "isolation": "gpu_vm", "vm_class": "ordinary Linux GPU VM + ssh", "persistent_disk": "instance-lifetime local NVMe (persistent while the VM lives)", "restore": true, "remote": true, "credentials_required": true, "authority_gated": true, "privacy": "cloud_vm_NOT_private", "custody": "Standard unless proven otherwise; provider-native snapshots/disks are evidence only — daemon custody state roots remain restore truth", "lifecycle": "guarded (quote-gated) once a control-plane mode is set; credential_preflight_only before that" })
        }
        "akash" => json!({ "locality": "remote", "isolation": "deployment_lease",
            "deployment_model": "DePIN compute/GPU: deployment intent → SDL manifest → provider bids → lease → lease-assigned endpoints (semantics preserved; never a generic VM)",
            "restore": true, "remote": true, "credentials_required": true, "authority_gated": true,
            "privacy": "depin_host_NOT_private",
            "custody": "Standard unless proven otherwise; deployment persistent storage and provider-native ids (dseq/bid/lease) are availability evidence only — daemon custody state roots remain restore truth",
            "persistent_storage": "deployment-scoped posture per SDL (survives restarts, dies with the lease) — NEVER restore truth",
            "provider_spend": "customer-borne lease spend — bids are priced only when the source itself quotes a USD rate",
            "lifecycle": "guarded (quote-gated) once a control-plane mode is set; credential_preflight_only before that" }),
        other => {
            json!({ "locality": "unknown", "credentials_required": true, "note": format!("unknown kind '{other}'") })
        }
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
        .find(|e| {
            text(e, "account_ref") == account_ref
                && text(e, "environment_ref") == env_ref
                && text(e, "status") == "open"
        })
}

/// external_spend budget posture MUST be discovered BEFORE any provider mutation
/// (providers-and-environments.md:1114 — "Budget exhaustion must be discovered before provider
/// mutation or new external spend"). bare-metal SSH is customer-borne with no metered spend.
fn discover_budget(data_dir: &str, kind: &str, op: &str, account: &Value) -> Result<Value, String> {
    if kind == "baremetal_ssh" {
        return Ok(json!({
            "scope": "local_free",
            "admitted": true,
            "discovered_before_mutation": true,
            "cost_estimate": { "amount": 0.0, "currency": "USD", "basis": "customer_borne_byo — bare-metal SSH node, no metered provider spend" },
            "provider_spend_borne_by": "customer",
        }));
    }
    // Customer/operator-owned clusters have NO direct provider price — budget discovery is
    // metered only when the account DECLARES a metered posture (endpoint.metered).
    if kind == "k8s"
        && account
            .pointer("/endpoint/metered")
            .map(Value::is_null)
            .unwrap_or(true)
    {
        return Ok(json!({
            "scope": "cluster_customer_operated",
            "admitted": true,
            "discovered_before_mutation": true,
            "cost_estimate": { "amount": 0.0, "currency": "USD", "basis": "customer/operator-owned cluster — no direct provider price; declare endpoint.metered to meter" },
            "provider_spend_borne_by": "customer",
        }));
    }
    let budgets = read_record_dir(data_dir, "resource-budgets");
    let Some(budget) = budgets
        .iter()
        .find(|b| b["scope"].as_str() == Some("external_spend"))
    else {
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
fn materialize_ssh_key(
    data_dir: &str,
    account_id: &str,
) -> Result<(PathBuf, KeyGuard, Option<String>), String> {
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
        let ep = self
            .account
            .get("endpoint")
            .cloned()
            .unwrap_or_else(|| json!({}));
        (
            text(&ep, "host").to_string(),
            ep.get("port")
                .and_then(Value::as_u64)
                .unwrap_or(22)
                .to_string(),
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
            "-p".into(),
            port,
            "-i".into(),
            self.key_path.to_string_lossy().to_string(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            format!("UserKnownHostsFile={}", self.known_hosts(data_dir)),
            "-o".into(),
            "ConnectTimeout=8".into(),
            format!("{user}@{host}"),
        ]
    }
    fn node_root(env_ref: &str) -> String {
        format!("\"$HOME\"/.ioi-hypervisor-nodes/{}", safe(env_ref))
    }
    fn run_script(
        &self,
        data_dir: &str,
        script: &str,
        stdin_bytes: Option<&[u8]>,
    ) -> Result<(i32, Vec<u8>, String), String> {
        let mut cmd = std::process::Command::new("ssh");
        cmd.args(self.base_args(data_dir)).arg(script);
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if stdin_bytes.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        } else {
            cmd.stdin(std::process::Stdio::null());
        }
        let mut child = cmd.spawn().map_err(|e| format!("ssh spawn failed: {e}"))?;
        if let Some(bytes) = stdin_bytes {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(bytes)
                    .map_err(|e| format!("ssh stdin failed: {e}"))?;
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
        format!(
            "provider-account://{}/op/{op}/{}",
            self.account_id(),
            safe(env_ref)
        )
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
            "verified" => (
                "available",
                format!(
                    "verified bare-metal SSH node ({})",
                    text(&self.account, "display_name")
                ),
            ),
            "revoked" => (
                "revoked",
                "credential revoked — rebind to use this account".into(),
            ),
            _ => (
                "unverified",
                "credential bound but preflight has not admitted this node yet".into(),
            ),
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
        Ok(
            json!({ "provider_operation_ref": self.op_ref("create", env_ref), "node_root": String::from_utf8_lossy(&stdout).trim(), "phase": "created" }),
        )
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
        let material_ref = format!(
            "provider-material://{}/{}/{stamp}",
            safe(self.account_id()),
            safe(env_ref)
        );
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
        // W1.2 / MEF-GAP-008 — the response claims admitted:true and restore resolves the material by
        // this record; the custody tar was already written to disk, so a lost record orphans those
        // bytes (present but not admitted — restore would refuse them). Refuse and name the file.
        persist_record(data_dir, MATERIAL_KIND, &material_id, &record)
            .map_err(|e| format!("provider_operation_persistence_failed — snapshot material record {material_id} did not commit; custody bytes are written at {} but not daemon-admitted: {e}", file.to_string_lossy()))?;
        Ok(
            json!({ "restore_material_ref": material_ref, "state_root": state_root, "custody": "daemon", "bytes": tar_bytes.len(), "admitted": true }),
        )
    }
    /// Restore truth = daemon-admitted sha256, never blob existence: re-hash the custody bytes
    /// against the ADMITTED state_root and refuse on mismatch before touching the node.
    fn restore(&self, data_dir: &str, env_ref: &str, material_ref: &str) -> Result<Value, String> {
        let material = read_record_dir(data_dir, MATERIAL_KIND)
            .into_iter()
            .find(|m| text(m, "material_ref") == material_ref)
            .ok_or(format!(
                "restore material '{material_ref}' is not daemon-admitted"
            ))?;
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
        Ok(
            json!({ "provider_operation_ref": self.op_ref("restore", env_ref), "phase": "ready", "restored_from": material_ref, "state_root_verified": admitted }),
        )
    }
    fn inject_outage(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let root = Self::node_root(env_ref);
        let script = format!("set -e; IOI_ROOT={root}; rm -rf \"$IOI_ROOT/workspace\"; printf outage > \"$IOI_ROOT/phase\"");
        let (code, _, stderr) = self.run_script(data_dir, &script, None)?;
        if code != 0 {
            return Err(format!(
                "ssh outage injection failed (exit {code}): {stderr}"
            ));
        }
        Ok(
            json!({ "provider_operation_ref": self.op_ref("inject_outage", env_ref), "phase": "outage", "workspace_lost": true }),
        )
    }
    fn recover(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut materials: Vec<Value> = read_record_dir(data_dir, MATERIAL_KIND)
            .into_iter()
            .filter(|m| {
                text(m, "environment_ref") == env_ref
                    && text(m, "account_ref") == text(&self.account, "account_ref")
            })
            .collect();
        materials.sort_by(|a, b| text(a, "material_id").cmp(text(b, "material_id")));
        let latest = materials
            .pop()
            .ok_or("no daemon-admitted restore material to recover from")?;
        let restored = self.restore(data_dir, env_ref, text(&latest, "material_ref"))?;
        Ok(
            json!({ "provider_operation_ref": self.op_ref("recover", env_ref), "phase": "ready", "recovered_from": text(&latest, "material_ref"), "state_root_verified": restored.get("state_root_verified").cloned().unwrap_or(Value::Null) }),
        )
    }
    fn delete(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let root = Self::node_root(env_ref);
        let script =
            format!("IOI_ROOT={root}; rm -rf \"$IOI_ROOT\"; test ! -d \"$IOI_ROOT\" && echo gone");
        let (code, stdout, stderr) = self.run_script(data_dir, &script, None)?;
        if code != 0 {
            return Err(format!("ssh delete failed (exit {code}): {stderr}"));
        }
        Ok(
            json!({ "provider_operation_ref": self.op_ref("delete", env_ref), "cleanup_verified": String::from_utf8_lossy(&stdout).trim() == "gone" }),
        )
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
            Err(e) => {
                json!({ "provider": self.id(), "environment_ref": env_ref, "phase": "unreachable", "error": e })
            }
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
            "verified" => (
                "credential_verified",
                format!(
                    "'{}' credential verified — preflight only until its adapter cut",
                    self.kind()
                ),
            ),
            "revoked" => ("revoked", "credential revoked".into()),
            _ => (
                "unverified",
                "bind + preflight the credential to verify this account".into(),
            ),
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
    account
        .pointer("/endpoint/mode")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
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
    fn save_instance(&self, data_dir: &str, instance: &Value) -> Result<(), String> {
        let id = text(instance, "record_id").to_string();
        // W1.2 / MEF-GAP-008 — this record is the ONLY daemon handle to a JUST-CREATED (paid)
        // provider machine; a lost write orphans it from its own observe/stop/delete lane.
        persist_record(data_dir, VAST_INSTANCE_KIND, &id, instance)
            .map_err(|e| format!("provider_operation_persistence_failed — instance record {id} did not commit; the provider machine may exist with no daemon handle: {e}"))
    }
    /// The BYO SSH lane over THIS instance's endpoint — the same workspace mutation + daemon
    /// custody contract as baremetal_ssh (materials attribute to the REAL vast account).
    fn ssh_lane(&self, data_dir: &str, env_ref: &str) -> Result<(SshProvider, KeyGuard), String> {
        let inst = self
            .instance(data_dir, env_ref)
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
            std::fs::read_to_string(key_file)
                .map_err(|e| format!("vast_ssh_key_unreadable: {e}"))?
        } else {
            // Live instances: the ephemeral private key lives SEALED on the instance record
            // (same dcrypt discipline as every credential) — opened in-daemon, materialized
            // 0600 for one op, removed by the KeyGuard.
            open_scm_token(sealed)
                .ok_or("vast_ssh_key_unsealable — sealed instance key did not decrypt")?
        };
        let dir = Path::new(data_dir).join("provider-ssh");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!(
            "vast-{}-{}.key",
            safe(self.account_id()),
            safe(env_ref)
        ));
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
        Ok((
            SshProvider {
                account: synthetic,
                key_path: path.clone(),
            },
            KeyGuard(path),
        ))
    }
}
impl EnvironmentProvider for VastProvider {
    fn id(&self) -> &str {
        "vast-guarded"
    }
    fn capabilities(&self) -> Value {
        let mut caps = kind_capabilities("vast");
        caps["provider_spend_borne_by"] = json!("customer");
        caps["lifecycle"] = json!(
            "guarded_lifecycle — quote-gated create, wallet-gated mutations, teardown required"
        );
        caps["execution_mode"] = json!(self.mode());
        caps
    }
    fn status(&self) -> (&'static str, String) {
        match text(&self.account, "status") {
            "verified" => (
                "available",
                format!("guarded vast lifecycle ({} control plane)", self.mode()),
            ),
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
            let ssh = self
                .account
                .pointer("/endpoint/ssh")
                .cloned()
                .unwrap_or(Value::Null);
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
            self.save_instance(data_dir, &instance)?;
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
            let offer_id = plan
                .get("offer_id")
                .and_then(Value::as_u64)
                .ok_or("vast_live_offer_id_missing — the validated quote carries no offer id")?;
            let bearer = load_account_credential(data_dir, self.account_id())
                .and_then(|c| c["sealed_token"].as_str().and_then(open_scm_token))
                .ok_or("provider_credential_unresolved")?;
            let base = self
                .account
                .pointer("/endpoint/endpoint")
                .and_then(Value::as_str)
                .unwrap_or("https://console.vast.ai/api/v0")
                .trim_end_matches('/')
                .to_string();
            let price = plan
                .get("max_hourly_usd")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
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

            // CONTAINMENT (cleanup availability): the billable lease now EXISTS. Every step below
            // is fallible, and the full record was previously only persisted at the very end — so
            // a keygen, read, or seal failure returned Err after the GPU was already leased and
            // billing, leaving no record at all. `delete` then failed `vast_instance_absent`
            // forever: a resource the operator could not destroy.
            //
            // Persist a minimal TEARDOWN HANDLE immediately, before anything else can fail. It
            // carries the provider-native id, so deletion stays callable no matter what follows.
            // The full record overwrites this one on the success path.
            let teardown_handle = json!({
                "schema_version": "ioi.hypervisor.vast-instance.v1",
                "record_id": record_id, "instance_id": format!("vast_{native_id}"),
                "account_id": self.account_id(), "account_ref": self.account["account_ref"],
                "environment_ref": env_ref, "status": "provisioning_incomplete",
                "execution_mode": "live",
                "teardown_policy": plan["teardown_policy"],
                "provider_native": { "instance_id": native_id, "note": "provider-native id — evidence only, never restore truth" },
                "created_at": iso_now(),
                "containment_note": "teardown handle persisted immediately after the billable lease; delete stays callable even if provisioning fails below",
            });
            self.save_instance(data_dir, &teardown_handle)?;

            // Ephemeral per-instance ssh keypair: private key SEALED onto the record (never
            // plaintext), public key attached to the Vast account for this lease.
            let keydir = Path::new(data_dir).join("provider-ssh");
            std::fs::create_dir_all(&keydir).map_err(|e| e.to_string())?;
            let tmp = keydir.join(format!(
                "vast-live-{}-{}.tmp",
                safe(self.account_id()),
                safe(env_ref)
            ));
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(keydir.join(format!("{}.pub", tmp.to_string_lossy())));
            let keygen = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-q", "-f"])
                .arg(&tmp)
                .output()
                .map_err(|e| {
                    format!(
                        "vast_ssh_keygen_failed: {e} (instance {native_id} recorded for teardown)"
                    )
                })?;
            if !keygen.status.success() {
                return Err(format!(
                    "vast_ssh_keygen_failed: {} (instance {native_id} recorded for teardown)",
                    String::from_utf8_lossy(&keygen.stderr)
                ));
            }
            let private_key = std::fs::read_to_string(&tmp).map_err(|e| e.to_string())?;
            let public_key = std::fs::read_to_string(format!("{}.pub", tmp.to_string_lossy()))
                .map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(format!("{}.pub", tmp.to_string_lossy()));
            let sealed_key = seal_scm_token(private_key.trim())
                .ok_or("vast_ssh_key_seal_failed — could not seal the ephemeral instance key")?;
            let attach: Result<u16, String> = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    reqwest::Client::new()
                        .post(format!("{base}/ssh/"))
                        .bearer_auth(&bearer)
                        .json(&json!({ "ssh_key": public_key.trim() }))
                        .timeout(std::time::Duration::from_secs(20))
                        .send()
                        .await
                        .map(|r| r.status().as_u16())
                        .map_err(|e| e.to_string())
                })
            });
            let key_attach = match attach {
                Ok(status) if (200..300).contains(&status) => {
                    json!({ "attached": true, "http_status": status })
                }
                Ok(status) => {
                    json!({ "attached": false, "http_status": status, "warning": "pubkey attach rejected — boot polling will fail closed until resolved" })
                }
                Err(e) => {
                    json!({ "attached": false, "error": e, "warning": "pubkey attach failed — boot polling will fail closed until resolved" })
                }
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
            self.save_instance(data_dir, &instance)?;
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
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("vast_instance_absent")?;
        if text(&inst, "status") == "torn_down" {
            return Err("vast_instance_torn_down".into());
        }
        let mut boot_evidence = Value::Null;
        // Live instances: boot-poll the provider until ssh host/port are KNOWN; the runtime ssh
        // block persists only with readiness evidence attached.
        if text(&inst, "execution_mode") == "live"
            && inst.get("ssh").map(Value::is_null).unwrap_or(true)
        {
            let native = inst
                .pointer("/provider_native/instance_id")
                .cloned()
                .unwrap_or(Value::Null);
            let nid = native
                .as_u64()
                .or_else(|| native.as_str().and_then(|s| s.parse().ok()))
                .ok_or("vast_boot_poll_failed — no provider-native id on the instance record")?;
            let bearer = load_account_credential(data_dir, self.account_id())
                .and_then(|c| c["sealed_token"].as_str().and_then(open_scm_token))
                .ok_or("provider_credential_unresolved")?;
            let base = self
                .account
                .pointer("/endpoint/endpoint")
                .and_then(Value::as_str)
                .unwrap_or("https://console.vast.ai/api/v0")
                .trim_end_matches('/')
                .to_string();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
            let mut attempts = 0u32;
            let mut last_status = String::from("unknown");
            let polled: Option<(String, u64)> = loop {
                attempts += 1;
                let fetched: Result<Value, String> = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let r = reqwest::Client::new()
                            .get(format!("{base}/instances/{nid}/"))
                            .bearer_auth(&bearer)
                            .timeout(std::time::Duration::from_secs(15))
                            .send()
                            .await
                            .map_err(|e| e.to_string())?;
                        r.json::<Value>().await.map_err(|e| e.to_string())
                    })
                });
                if let Ok(doc) = fetched {
                    let node = doc
                        .get("instances")
                        .filter(|v| !v.is_array())
                        .cloned()
                        .unwrap_or(doc);
                    last_status = node
                        .get("actual_status")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string();
                    let host = node
                        .get("ssh_host")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
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
            self.save_instance(data_dir, &inst)?;
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
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/start/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "status": "running", "ssh_ready": true,
                   "boot_evidence": boot_evidence }),
        )
    }
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.workrun(data_dir, env_ref, command)
    }
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("vast_instance_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let stopped = lane.stop(data_dir, env_ref)?;
        inst["status"] = json!("stopped");
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/stop/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "status": "stopped", "lane": stopped }),
        )
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
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("vast_instance_absent")?;
        let remote_cleanup = match self.ssh_lane(data_dir, env_ref) {
            Ok((lane, _guard)) => lane
                .delete(data_dir, env_ref)
                .map(|e| e["cleanup_verified"].clone())
                .unwrap_or(json!("unreachable")),
            Err(e) => json!(format!("skipped: {e}")),
        };
        let native_teardown = if text(&inst, "execution_mode") == "live" {
            // Live: destroy the marketplace instance (billing stops here).
            let native = inst
                .pointer("/provider_native/instance_id")
                .cloned()
                .unwrap_or(Value::Null);
            let bearer = load_account_credential(data_dir, self.account_id())
                .and_then(|c| c["sealed_token"].as_str().and_then(open_scm_token));
            match (
                native
                    .as_u64()
                    .or_else(|| native.as_str().and_then(|s| s.parse().ok())),
                bearer,
            ) {
                (Some(nid), Some(bearer)) => {
                    let base = self
                        .account
                        .pointer("/endpoint/endpoint")
                        .and_then(Value::as_str)
                        .unwrap_or("https://console.vast.ai/api/v0")
                        .trim_end_matches('/')
                        .to_string();
                    let result: Result<u16, String> = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            reqwest::Client::new()
                                .delete(format!("{base}/instances/{nid}/"))
                                .bearer_auth(&bearer)
                                .timeout(std::time::Duration::from_secs(30))
                                .send()
                                .await
                                .map(|r| r.status().as_u16())
                                .map_err(|e| e.to_string())
                        })
                    });
                    match result {
                        Ok(status) => {
                            json!({ "destroyed": (200..300).contains(&status), "http_status": status })
                        }
                        Err(e) => {
                            json!({ "destroyed": false, "error": e, "warning": "TEARDOWN MAY BE INCOMPLETE — verify the Vast console" })
                        }
                    }
                }
                _ => json!({ "destroyed": false, "error": "native id or credential unavailable" }),
            }
        } else if self
            .account
            .pointer("/endpoint/simulate_teardown_failure")
            .and_then(Value::as_bool)
            == Some(true)
        {
            json!({ "destroyed": false, "error": "SIMULATED teardown failure (endpoint.simulate_teardown_failure) — validates the incomplete-teardown warning path", "warning": "TEARDOWN MAY BE INCOMPLETE — verify the Vast console" })
        } else {
            json!({ "destroyed": true, "note": "simulated control plane — no real instance existed" })
        };
        // CARVE-OUT: record the EXACT deletion outcome. `teardown_state` was unconditionally
        // "torn_down" and `cleanup_verified` unconditionally true, even when the provider-native
        // destroy reported `destroyed: false`. Non-succeeded outcomes now open a durable obligation.
        let (teardown_state, cleanup_verified, deletion_disposition) =
            provider_teardown_disposition(
                &format!(
                    "provider-account://{}/resource/{}",
                    self.account_id(),
                    safe(env_ref)
                ),
                &native_teardown,
                &remote_cleanup,
            );
        inst["status"] = json!(teardown_state);
        inst["torn_down_at"] = json!(iso_now());
        inst["deletion_disposition"] = deletion_disposition.clone();
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/delete/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "teardown_state": teardown_state,
                   "remote_workspace_cleanup": remote_cleanup, "native_teardown": native_teardown,
                   "cleanup_verified": cleanup_verified, "deletion_disposition": deletion_disposition }),
        )
    }
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value {
        match self.instance(data_dir, env_ref) {
            None => {
                json!({ "provider": self.id(), "environment_ref": env_ref, "instance": Value::Null, "status": "absent" })
            }
            Some(inst) => {
                let boot_pending = text(&inst, "execution_mode") == "live"
                    && inst.get("ssh").map(Value::is_null).unwrap_or(true);
                let lane_view = if text(&inst, "status") == "torn_down" {
                    Value::Null
                } else if boot_pending {
                    json!({ "boot": "pending — run start to poll the provider until ssh readiness is proven" })
                } else {
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
        let configured = self
            .account
            .pointer("/endpoint/endpoint")
            .and_then(Value::as_str)
            .unwrap_or("");
        if configured.is_empty() {
            "https://rest.runpod.io/v1".into()
        } else {
            configured.trim_end_matches('/').to_string()
        }
    }
    fn bearer(&self, data_dir: &str) -> Result<String, String> {
        load_account_credential(data_dir, self.account_id())
            .and_then(|c| c["sealed_token"].as_str().and_then(open_scm_token))
            .ok_or("provider_credential_unresolved".into())
    }
    fn instance(&self, data_dir: &str, env_ref: &str) -> Option<Value> {
        load_runpod_instance(data_dir, self.account_id(), env_ref)
    }
    fn save_instance(&self, data_dir: &str, instance: &Value) -> Result<(), String> {
        let id = text(instance, "record_id").to_string();
        // W1.2 / MEF-GAP-008 — this record is the ONLY daemon handle to a JUST-CREATED (paid)
        // provider machine; a lost write orphans it from its own observe/stop/delete lane.
        persist_record(data_dir, RUNPOD_INSTANCE_KIND, &id, instance)
            .map_err(|e| format!("provider_operation_persistence_failed — instance record {id} did not commit; the provider machine may exist with no daemon handle: {e}"))
    }
    /// The BYO SSH lane over this pod's endpoint — identical custody contract to Vast/BYO.
    fn ssh_lane(&self, data_dir: &str, env_ref: &str) -> Result<(SshProvider, KeyGuard), String> {
        let inst = self
            .instance(data_dir, env_ref)
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
            std::fs::read_to_string(key_file)
                .map_err(|e| format!("runpod_ssh_key_unreadable: {e}"))?
        } else {
            open_scm_token(sealed)
                .ok_or("runpod_ssh_key_unsealable — sealed pod key did not decrypt")?
        };
        let dir = Path::new(data_dir).join("provider-ssh");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!(
            "runpod-{}-{}.key",
            safe(self.account_id()),
            safe(env_ref)
        ));
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
        Ok((
            SshProvider {
                account: synthetic,
                key_path: path.clone(),
            },
            KeyGuard(path),
        ))
    }
}
impl EnvironmentProvider for RunPodProvider {
    fn id(&self) -> &str {
        "runpod-guarded"
    }
    fn capabilities(&self) -> Value {
        let mut caps = kind_capabilities("runpod");
        caps["provider_spend_borne_by"] = json!("customer");
        caps["lifecycle"] = json!(
            "guarded_lifecycle — quote-gated create, wallet-gated mutations, teardown required"
        );
        caps["execution_mode"] = json!(self.mode());
        caps
    }
    fn status(&self) -> (&'static str, String) {
        match text(&self.account, "status") {
            "verified" => (
                "available",
                format!("guarded runpod lifecycle ({} control plane)", self.mode()),
            ),
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
            let ssh = self
                .account
                .pointer("/endpoint/ssh")
                .cloned()
                .unwrap_or(Value::Null);
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
            self.save_instance(data_dir, &instance)?;
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
            let gpu_type = plan
                .get("offer_id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    plan.get("offer_id")
                        .and_then(Value::as_u64)
                        .map(|n| n.to_string())
                })
                .ok_or(
                    "runpod_live_gpu_type_missing — the validated quote carries no GPU type id",
                )?;
            let bearer = self.bearer(data_dir)?;
            let base = self.base();
            // Ephemeral per-pod ssh keypair: sealed onto the record; pubkey attached account-side.
            let keydir = Path::new(data_dir).join("provider-ssh");
            std::fs::create_dir_all(&keydir).map_err(|e| e.to_string())?;
            let tmp = keydir.join(format!(
                "runpod-live-{}-{}.tmp",
                safe(self.account_id()),
                safe(env_ref)
            ));
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(format!("{}.pub", tmp.to_string_lossy()));
            let keygen = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-q", "-f"])
                .arg(&tmp)
                .output()
                .map_err(|e| format!("runpod_ssh_keygen_failed: {e}"))?;
            if !keygen.status.success() {
                return Err(format!(
                    "runpod_ssh_keygen_failed: {}",
                    String::from_utf8_lossy(&keygen.stderr)
                ));
            }
            let private_key = std::fs::read_to_string(&tmp).map_err(|e| e.to_string())?;
            let public_key = std::fs::read_to_string(format!("{}.pub", tmp.to_string_lossy()))
                .map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(format!("{}.pub", tmp.to_string_lossy()));
            let sealed_key = seal_scm_token(private_key.trim())
                .ok_or("runpod_ssh_key_seal_failed — could not seal the ephemeral pod key")?;
            let price = plan
                .get("max_hourly_usd")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let created: Result<Value, String> = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let client = reqwest::Client::new();
                    let resp = client
                        .post(format!("{base}/pods"))
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
                        .send()
                        .await
                        .map_err(|e| format!("runpod_live_provision_failed: {e}"))?;
                    let status = resp.status().as_u16();
                    let body: Value = resp.json().await.map_err(|e| {
                        format!("runpod_live_provision_failed: non-JSON response: {e}")
                    })?;
                    if !(200..300).contains(&status) {
                        return Err(format!(
                            "runpod_live_provision_failed: http {status} {body}"
                        ));
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
            self.save_instance(data_dir, &instance)?;
            return Ok(json!({
                "provider_operation_ref": format!("provider-account://{}/op/create/{}", self.account_id(), safe(env_ref)),
                "instance": { "instance_id": instance["instance_id"], "status": "provisioned", "execution_mode": "live" },
                "provider_native": instance["provider_native"],
                "ssh_ready": false,
                "note": "live pod leased — run start to boot-poll; workspace ops fail closed (runpod_ssh_bootstrap_unknown) until ssh readiness is PROVEN",
                "teardown_required": true,
            }));
        }
        Err(
            "runpod_lifecycle_mode_unset — set the account endpoint mode to simulator or live"
                .into(),
        )
    }
    fn start(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("runpod_instance_absent")?;
        if text(&inst, "status") == "torn_down" {
            return Err("runpod_instance_torn_down".into());
        }
        let mut boot_evidence = Value::Null;
        if text(&inst, "execution_mode") == "live"
            && inst.get("ssh").map(Value::is_null).unwrap_or(true)
        {
            let pod_id = inst
                .pointer("/provider_native/pod_id")
                .and_then(Value::as_str)
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
                        let r = reqwest::Client::new()
                            .get(format!("{base}/pods/{pod_id}"))
                            .bearer_auth(&bearer)
                            .timeout(std::time::Duration::from_secs(15))
                            .send()
                            .await
                            .map_err(|e| e.to_string())?;
                        r.json::<Value>().await.map_err(|e| e.to_string())
                    })
                });
                if let Ok(node) = fetched {
                    last_status = node
                        .get("desiredStatus")
                        .and_then(Value::as_str)
                        .or_else(|| node.get("status").and_then(Value::as_str))
                        .unwrap_or("unknown")
                        .to_string();
                    let public_ip = node
                        .pointer("/runtime/publicIp")
                        .and_then(Value::as_str)
                        .or_else(|| node.get("publicIp").and_then(Value::as_str))
                        .unwrap_or("")
                        .to_string();
                    let ssh_port = node
                        .pointer("/runtime/ports")
                        .and_then(Value::as_array)
                        .and_then(|ports| {
                            ports
                                .iter()
                                .find(|p| p.get("privatePort").and_then(Value::as_u64) == Some(22))
                        })
                        .and_then(|p| p.get("publicPort").and_then(Value::as_u64))
                        .unwrap_or(0);
                    if last_status.eq_ignore_ascii_case("running")
                        && !public_ip.is_empty()
                        && ssh_port > 0
                    {
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
            self.save_instance(data_dir, &inst)?;
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
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/start/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "status": "running", "ssh_ready": true,
                   "boot_evidence": boot_evidence }),
        )
    }
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.workrun(data_dir, env_ref, command)
    }
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("runpod_instance_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let stopped = lane.stop(data_dir, env_ref)?;
        inst["status"] = json!("stopped");
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/stop/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "status": "stopped", "lane": stopped }),
        )
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
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("runpod_instance_absent")?;
        let remote_cleanup = match self.ssh_lane(data_dir, env_ref) {
            Ok((lane, _guard)) => lane
                .delete(data_dir, env_ref)
                .map(|e| e["cleanup_verified"].clone())
                .unwrap_or(json!("unreachable")),
            Err(e) => json!(format!("skipped: {e}")),
        };
        let native_teardown = if text(&inst, "execution_mode") == "live" {
            let pod_id = inst
                .pointer("/provider_native/pod_id")
                .and_then(Value::as_str)
                .map(str::to_string);
            match (pod_id, self.bearer(data_dir)) {
                (Some(pid), Ok(bearer)) => {
                    let base = self.base();
                    let result: Result<u16, String> = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            reqwest::Client::new()
                                .delete(format!("{base}/pods/{pid}"))
                                .bearer_auth(&bearer)
                                .timeout(std::time::Duration::from_secs(30))
                                .send()
                                .await
                                .map(|r| r.status().as_u16())
                                .map_err(|e| e.to_string())
                        })
                    });
                    match result {
                        Ok(status) => {
                            json!({ "destroyed": (200..300).contains(&status), "http_status": status })
                        }
                        Err(e) => {
                            json!({ "destroyed": false, "error": e, "warning": "TEARDOWN MAY BE INCOMPLETE — verify the RunPod console" })
                        }
                    }
                }
                _ => json!({ "destroyed": false, "error": "pod id or credential unavailable" }),
            }
        } else if self
            .account
            .pointer("/endpoint/simulate_teardown_failure")
            .and_then(Value::as_bool)
            == Some(true)
        {
            json!({ "destroyed": false, "error": "SIMULATED teardown failure (endpoint.simulate_teardown_failure) — validates the incomplete-teardown warning path", "warning": "TEARDOWN MAY BE INCOMPLETE — verify the RunPod console" })
        } else {
            json!({ "destroyed": true, "note": "simulated control plane — no real pod existed" })
        };
        // CARVE-OUT: record the EXACT deletion outcome. `teardown_state` was unconditionally
        // "torn_down" and `cleanup_verified` unconditionally true, even when the provider-native
        // destroy reported `destroyed: false`. Non-succeeded outcomes now open a durable obligation.
        let (teardown_state, cleanup_verified, deletion_disposition) =
            provider_teardown_disposition(
                &format!(
                    "provider-account://{}/resource/{}",
                    self.account_id(),
                    safe(env_ref)
                ),
                &native_teardown,
                &remote_cleanup,
            );
        inst["status"] = json!(teardown_state);
        inst["torn_down_at"] = json!(iso_now());
        inst["deletion_disposition"] = deletion_disposition.clone();
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/delete/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "teardown_state": teardown_state,
                   "remote_workspace_cleanup": remote_cleanup, "native_teardown": native_teardown,
                   "cleanup_verified": cleanup_verified, "deletion_disposition": deletion_disposition }),
        )
    }
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value {
        match self.instance(data_dir, env_ref) {
            None => {
                json!({ "provider": self.id(), "environment_ref": env_ref, "instance": Value::Null, "status": "absent" })
            }
            Some(inst) => {
                let boot_pending = text(&inst, "execution_mode") == "live"
                    && inst.get("ssh").map(Value::is_null).unwrap_or(true);
                let lane_view = if text(&inst, "status") == "torn_down" {
                    Value::Null
                } else if boot_pending {
                    json!({ "boot": "pending — run start to poll the provider until ssh readiness is proven" })
                } else {
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

// --- lambda_cloud GUARDED LIFECYCLE: the boring high-trust GPU VM lane (missing member of ---
// --- the first production compute trio). Ordinary Linux VM + ssh (user ubuntu) + persistent  ---
// --- local disk. Same safety contract as Vast/RunPod; VM control-plane semantics (launch /   ---
// --- instances / terminate). Provider-native snapshots/disks are EVIDENCE ONLY.              ---
const LAMBDA_INSTANCE_KIND: &str = "lambda-instances";

fn load_lambda_instance(data_dir: &str, account_id: &str, env_ref: &str) -> Option<Value> {
    read_record_dir(data_dir, LAMBDA_INSTANCE_KIND)
        .into_iter()
        .find(|i| text(i, "account_id") == account_id && text(i, "environment_ref") == env_ref)
}

struct LambdaProvider {
    account: Value,
}
impl LambdaProvider {
    fn account_id(&self) -> &str {
        text(&self.account, "account_id")
    }
    fn mode(&self) -> String {
        vast_mode(&self.account)
    }
    fn base(&self) -> String {
        let configured = self
            .account
            .pointer("/endpoint/endpoint")
            .and_then(Value::as_str)
            .unwrap_or("");
        if configured.is_empty() {
            "https://cloud.lambda.ai/api/v1".into()
        } else {
            configured.trim_end_matches('/').to_string()
        }
    }
    fn bearer(&self, data_dir: &str) -> Result<String, String> {
        load_account_credential(data_dir, self.account_id())
            .and_then(|c| c["sealed_token"].as_str().and_then(open_scm_token))
            .ok_or("provider_credential_unresolved".into())
    }
    fn instance(&self, data_dir: &str, env_ref: &str) -> Option<Value> {
        load_lambda_instance(data_dir, self.account_id(), env_ref)
    }
    fn save_instance(&self, data_dir: &str, instance: &Value) -> Result<(), String> {
        let id = text(instance, "record_id").to_string();
        // W1.2 / MEF-GAP-008 — this record is the ONLY daemon handle to a JUST-CREATED (paid)
        // provider machine; a lost write orphans it from its own observe/stop/delete lane.
        persist_record(data_dir, LAMBDA_INSTANCE_KIND, &id, instance)
            .map_err(|e| format!("provider_operation_persistence_failed — instance record {id} did not commit; the provider machine may exist with no daemon handle: {e}"))
    }
    fn ssh_lane(&self, data_dir: &str, env_ref: &str) -> Result<(SshProvider, KeyGuard), String> {
        let inst = self
            .instance(data_dir, env_ref)
            .ok_or("lambda_instance_absent — provision with the quote-gated create op first")?;
        if text(&inst, "status") == "torn_down" {
            return Err("lambda_instance_torn_down — this VM was already torn down".into());
        }
        let ssh = inst.get("ssh").cloned().unwrap_or(Value::Null);
        let key_file = text(&ssh, "key_file");
        let sealed = text(&inst, "sealed_ssh_key");
        if text(&ssh, "host").is_empty() || (key_file.is_empty() && sealed.is_empty()) {
            return Err("lambda_ssh_bootstrap_unknown — the VM has no usable ssh endpoint/key (it gains one only after boot polling proves readiness)".into());
        }
        let key = if !key_file.is_empty() {
            std::fs::read_to_string(key_file)
                .map_err(|e| format!("lambda_ssh_key_unreadable: {e}"))?
        } else {
            open_scm_token(sealed)
                .ok_or("lambda_ssh_key_unsealable — sealed VM key did not decrypt")?
        };
        let dir = Path::new(data_dir).join("provider-ssh");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!(
            "lambda-{}-{}.key",
            safe(self.account_id()),
            safe(env_ref)
        ));
        std::fs::write(&path, key).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        // Live Lambda VMs use ssh user `ubuntu`; simulator inherits the fixture's endpoint.ssh.
        let user = if text(&ssh, "user").is_empty() {
            "ubuntu"
        } else {
            text(&ssh, "user")
        };
        let synthetic = json!({
            "account_id": self.account_id(),
            "account_ref": self.account["account_ref"],
            "display_name": format!("{} (lambda vm)", text(&self.account, "display_name")),
            "kind": "lambda_cloud", "status": "verified",
            "endpoint": { "host": ssh["host"], "port": ssh.get("port").cloned().unwrap_or(json!(22)), "user": user },
        });
        Ok((
            SshProvider {
                account: synthetic,
                key_path: path.clone(),
            },
            KeyGuard(path),
        ))
    }
    /// Simulator: does this account defer ssh readiness to boot polling (endpoint.simulate_
    /// boot_delay:true)? Proves the ssh-unknown-until-boot contract in CI without a live VM.
    fn sim_boot_delay(&self) -> bool {
        self.account
            .pointer("/endpoint/simulate_boot_delay")
            .and_then(Value::as_bool)
            == Some(true)
    }
}
impl EnvironmentProvider for LambdaProvider {
    fn id(&self) -> &str {
        "lambda-guarded"
    }
    fn capabilities(&self) -> Value {
        let mut caps = kind_capabilities("lambda_cloud");
        caps["provider_spend_borne_by"] = json!("customer");
        caps["lifecycle"] = json!(
            "guarded_lifecycle — quote-gated create, wallet-gated mutations, teardown required"
        );
        caps["execution_mode"] = json!(self.mode());
        caps
    }
    fn status(&self) -> (&'static str, String) {
        match text(&self.account, "status") {
            "verified" => (
                "available",
                format!(
                    "guarded lambda GPU VM lifecycle ({} control plane)",
                    self.mode()
                ),
            ),
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
                return Err(format!("lambda_vm_already_provisioned — {} is live for this environment; tear it down first", text(&existing, "instance_id")));
            }
        }
        let mode = self.mode();
        let record_id = format!("lminst_{:x}", nanos());
        if mode == "simulator" {
            let ssh = self
                .account
                .pointer("/endpoint/ssh")
                .cloned()
                .unwrap_or(Value::Null);
            if text(&ssh, "host").is_empty() || text(&ssh, "key_file").is_empty() {
                return Err("lambda_simulator_ssh_missing — simulator mode needs endpoint.ssh {host, port, user, key_file}".into());
            }
            let instance_id = format!("lmsim_{:x}", nanos());
            // simulate_boot_delay: leave ssh Null so the ssh-unknown-until-boot contract is
            // CI-provable (start "boot polls" and persists readiness); otherwise ssh is ready now.
            let boot_delay = self.sim_boot_delay();
            let instance = json!({
                "schema_version": "ioi.hypervisor.lambda-instance.v1",
                "record_id": record_id, "instance_id": instance_id,
                "account_id": self.account_id(), "account_ref": self.account["account_ref"],
                "environment_ref": env_ref, "status": "provisioned",
                "execution_mode": "simulated_control_plane",
                "sim_ssh": ssh,
                "ssh": if boot_delay { Value::Null } else { ssh.clone() },
                "region": plan["region"], "instance_type": plan["instance_type"],
                "candidate_ref": plan["candidate_ref"], "quote_ref": plan["quote_ref"],
                "usd_per_hour": plan["usd_per_hour"], "max_hourly_usd": plan["max_hourly_usd"],
                "teardown_policy": plan["teardown_policy"],
                "provider_native": { "instance_id": instance_id, "disk_id": format!("{instance_id}-disk"),
                    "note": "SIMULATED VM/disk ids — evidence only, never restore truth; no real Lambda VM exists" },
                "created_at": iso_now(),
            });
            self.save_instance(data_dir, &instance)?;
            let (ssh_ready, bootstrap) = if boot_delay {
                (false, Value::Null) // workspace bootstrap deferred to start (post-boot)
            } else {
                let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
                (true, lane.create(data_dir, env_ref, plan)?)
            };
            return Ok(json!({
                "provider_operation_ref": format!("provider-account://{}/op/create/{}", self.account_id(), safe(env_ref)),
                "instance": { "instance_id": instance_id, "status": "provisioned", "execution_mode": "simulated_control_plane" },
                "provider_native": instance["provider_native"],
                "ssh_ready": ssh_ready, "workspace_bootstrap": bootstrap,
                "live_provisioning_not_run": true,
                "note": if boot_delay { "simulated boot delay — ssh is UNKNOWN until start boot-polls (proves the readiness contract)" } else { "simulator — ssh ready immediately" },
                "teardown_required": true,
            }));
        }
        if mode == "live" {
            let instance_type = plan.get("instance_type").and_then(Value::as_str).ok_or(
                "lambda_live_instance_type_missing — the validated quote carries no instance type",
            )?;
            let region = plan.get("region").and_then(Value::as_str)
                .ok_or("lambda_live_region_missing — provide a region with capacity (the wallet challenge binds it)")?;
            let bearer = self.bearer(data_dir)?;
            let base = self.base();
            let keydir = Path::new(data_dir).join("provider-ssh");
            std::fs::create_dir_all(&keydir).map_err(|e| e.to_string())?;
            let tmp = keydir.join(format!(
                "lambda-live-{}-{}.tmp",
                safe(self.account_id()),
                safe(env_ref)
            ));
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(format!("{}.pub", tmp.to_string_lossy()));
            let keygen = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-q", "-f"])
                .arg(&tmp)
                .output()
                .map_err(|e| format!("lambda_ssh_keygen_failed: {e}"))?;
            if !keygen.status.success() {
                return Err(format!(
                    "lambda_ssh_keygen_failed: {}",
                    String::from_utf8_lossy(&keygen.stderr)
                ));
            }
            let private_key = std::fs::read_to_string(&tmp).map_err(|e| e.to_string())?;
            let public_key = std::fs::read_to_string(format!("{}.pub", tmp.to_string_lossy()))
                .map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(format!("{}.pub", tmp.to_string_lossy()));
            let sealed_key = seal_scm_token(private_key.trim())
                .ok_or("lambda_ssh_key_seal_failed — could not seal the ephemeral VM key")?;
            let key_name = format!("ioi-hypervisor-{}", safe(env_ref));
            let created: Result<Value, String> = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let client = reqwest::Client::new();
                    // Register the ephemeral pubkey, then launch the VM bound to it.
                    let _ = client
                        .post(format!("{base}/ssh-keys"))
                        .bearer_auth(&bearer)
                        .json(&json!({ "name": key_name, "public_key": public_key.trim() }))
                        .timeout(std::time::Duration::from_secs(20))
                        .send()
                        .await;
                    let resp = client
                        .post(format!("{base}/instance-operations/launch"))
                        .bearer_auth(&bearer)
                        .json(
                            &json!({ "region_name": region, "instance_type_name": instance_type,
                                       "ssh_key_names": [key_name], "quantity": 1,
                                       "name": format!("ioi-hypervisor-{}", safe(env_ref)) }),
                        )
                        .timeout(std::time::Duration::from_secs(30))
                        .send()
                        .await
                        .map_err(|e| format!("lambda_live_provision_failed: {e}"))?;
                    let status = resp.status().as_u16();
                    let body: Value = resp.json().await.map_err(|e| {
                        format!("lambda_live_provision_failed: non-JSON response: {e}")
                    })?;
                    if !(200..300).contains(&status) {
                        return Err(format!(
                            "lambda_live_provision_failed: http {status} {body}"
                        ));
                    }
                    Ok(body)
                })
            });
            let body = created?;
            let native_id = body
                .pointer("/data/instance_ids")
                .and_then(Value::as_array)
                .and_then(|a| a.first().cloned())
                .or_else(|| {
                    body.pointer("/instance_ids")
                        .and_then(Value::as_array)
                        .and_then(|a| a.first().cloned())
                })
                .unwrap_or(Value::Null);
            let instance = json!({
                "schema_version": "ioi.hypervisor.lambda-instance.v1",
                "record_id": record_id, "instance_id": format!("lambda_{}", native_id.as_str().unwrap_or("?")),
                "account_id": self.account_id(), "account_ref": self.account["account_ref"],
                "environment_ref": env_ref, "status": "provisioned",
                "execution_mode": "live",
                "sealed_ssh_key": sealed_key, "ssh_key_name": key_name,
                "ssh": Value::Null,
                "region": region, "instance_type": instance_type,
                "candidate_ref": plan["candidate_ref"], "quote_ref": plan["quote_ref"],
                "usd_per_hour": plan["usd_per_hour"], "max_hourly_usd": plan["max_hourly_usd"],
                "teardown_policy": plan["teardown_policy"],
                "provider_native": { "instance_id": native_id, "note": "provider-native VM id — evidence only, never restore truth" },
                "created_at": iso_now(),
            });
            self.save_instance(data_dir, &instance)?;
            return Ok(json!({
                "provider_operation_ref": format!("provider-account://{}/op/create/{}", self.account_id(), safe(env_ref)),
                "instance": { "instance_id": instance["instance_id"], "status": "provisioned", "execution_mode": "live" },
                "provider_native": instance["provider_native"],
                "ssh_ready": false,
                "note": "live VM launched — run start to boot-poll; workspace ops fail closed (lambda_ssh_bootstrap_unknown) until ssh readiness is PROVEN",
                "teardown_required": true,
            }));
        }
        Err(
            "lambda_lifecycle_mode_unset — set the account endpoint mode to simulator or live"
                .into(),
        )
    }
    fn start(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("lambda_instance_absent")?;
        if text(&inst, "status") == "torn_down" {
            return Err("lambda_instance_torn_down".into());
        }
        let mut boot_evidence = Value::Null;
        // Boot polling: live polls the provider; simulator-with-boot-delay resolves from the
        // recorded sim_ssh once (proving the readiness-gated persist without a live VM).
        if inst.get("ssh").map(Value::is_null).unwrap_or(true) {
            if text(&inst, "execution_mode") == "live" {
                let native = inst
                    .pointer("/provider_native/instance_id")
                    .cloned()
                    .unwrap_or(Value::Null);
                let nid = native
                    .as_str()
                    .map(str::to_string)
                    .ok_or("lambda_boot_poll_failed — no provider-native id on the VM record")?;
                let bearer = self.bearer(data_dir)?;
                let base = self.base();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
                let mut attempts = 0u32;
                let mut last_status = String::from("unknown");
                let polled: Option<String> = loop {
                    attempts += 1;
                    let fetched: Result<Value, String> = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            let r = reqwest::Client::new()
                                .get(format!("{base}/instances/{nid}"))
                                .bearer_auth(&bearer)
                                .timeout(std::time::Duration::from_secs(15))
                                .send()
                                .await
                                .map_err(|e| e.to_string())?;
                            r.json::<Value>().await.map_err(|e| e.to_string())
                        })
                    });
                    if let Ok(doc) = fetched {
                        let node = doc.get("data").cloned().unwrap_or(doc);
                        last_status = node
                            .get("status")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                            .to_string();
                        let ip = node
                            .get("ip")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        if last_status.eq_ignore_ascii_case("active") && !ip.is_empty() {
                            break Some(ip);
                        }
                    }
                    if std::time::Instant::now() >= deadline {
                        break None;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(15));
                };
                let Some(ip) = polled else {
                    return Err(format!("lambda_boot_pending — VM {nid} not ssh-ready after {attempts} poll(s) (status: {last_status}); re-run start to continue polling"));
                };
                boot_evidence = json!({ "polled_attempts": attempts, "status": last_status, "ssh_host": ip, "ssh_port": 22, "user": "ubuntu", "proven_at": iso_now() });
                inst["ssh"] = json!({ "host": ip, "port": 22, "user": "ubuntu" });
            } else {
                // simulator boot delay: readiness "proven" from the recorded sim endpoint.
                let sim_ssh = inst.get("sim_ssh").cloned().unwrap_or(Value::Null);
                if text(&sim_ssh, "host").is_empty() {
                    return Err(
                        "lambda_boot_poll_failed — simulator instance has no recorded ssh endpoint"
                            .into(),
                    );
                }
                boot_evidence = json!({ "polled_attempts": 1, "status": "active", "ssh_host": sim_ssh["host"], "ssh_port": sim_ssh.get("port").cloned().unwrap_or(json!(22)), "proven_at": iso_now(), "note": "simulated boot delay resolved" });
                inst["ssh"] = sim_ssh;
            }
            inst["ssh_ready_evidence"] = boot_evidence.clone();
            self.save_instance(data_dir, &inst)?;
        }
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        if inst.get("workspace_bootstrapped").and_then(Value::as_bool) != Some(true) {
            // Bootstrap once for live and for boot-delayed simulator (immediate-sim did it at create).
            if text(&inst, "execution_mode") == "live" || boot_evidence != Value::Null {
                lane.create(data_dir, env_ref, &json!({}))?;
            }
            inst["workspace_bootstrapped"] = json!(true);
        }
        lane.start(data_dir, env_ref)?;
        inst["status"] = json!("running");
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/start/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "status": "running", "ssh_ready": true,
                   "boot_evidence": boot_evidence }),
        )
    }
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.workrun(data_dir, env_ref, command)
    }
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        // Lambda-class VMs have NO native stop — the VM runs (and bills) until terminate.
        // Only the workspace lane halts; saying "stopped" here would fake the spend posture.
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("lambda_instance_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let stopped = lane.stop(data_dir, env_ref)?;
        inst["status"] = json!("workspace_stopped_vm_running");
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/stop/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "status": "workspace_stopped_vm_running",
                   "spend_note": "lambda-class VMs have no native stop — the VM keeps running and accruing customer-borne spend until teardown; only the workspace lane halted",
                   "lane": stopped }),
        )
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
        Err("lambda_outage_injection_not_supported — terminating a paid VM is not a safely representable outage; use the loopback/ssh conformance lanes".into())
    }
    fn recover(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("lambda_recover_not_supported — recovery is restore-from-daemon-custody after re-launching; run create + restore explicitly".into())
    }
    fn delete(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("lambda_instance_absent")?;
        let remote_cleanup = match self.ssh_lane(data_dir, env_ref) {
            Ok((lane, _guard)) => lane
                .delete(data_dir, env_ref)
                .map(|e| e["cleanup_verified"].clone())
                .unwrap_or(json!("unreachable")),
            Err(e) => json!(format!("skipped: {e}")),
        };
        let native_teardown = if text(&inst, "execution_mode") == "live" {
            let native = inst
                .pointer("/provider_native/instance_id")
                .and_then(Value::as_str)
                .map(str::to_string);
            match (native, self.bearer(data_dir)) {
                (Some(nid), Ok(bearer)) => {
                    let base = self.base();
                    let result: Result<u16, String> = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            reqwest::Client::new()
                                .post(format!("{base}/instance-operations/terminate"))
                                .bearer_auth(&bearer)
                                .json(&json!({ "instance_ids": [nid] }))
                                .timeout(std::time::Duration::from_secs(30))
                                .send()
                                .await
                                .map(|r| r.status().as_u16())
                                .map_err(|e| e.to_string())
                        })
                    });
                    match result {
                        Ok(status) => {
                            json!({ "destroyed": (200..300).contains(&status), "http_status": status })
                        }
                        Err(e) => {
                            json!({ "destroyed": false, "error": e, "warning": "TEARDOWN MAY BE INCOMPLETE — verify the Lambda console" })
                        }
                    }
                }
                _ => {
                    json!({ "destroyed": false, "error": "instance id or credential unavailable" })
                }
            }
        } else if self
            .account
            .pointer("/endpoint/simulate_teardown_failure")
            .and_then(Value::as_bool)
            == Some(true)
        {
            json!({ "destroyed": false, "error": "SIMULATED teardown failure (endpoint.simulate_teardown_failure)", "warning": "TEARDOWN MAY BE INCOMPLETE — verify the Lambda console" })
        } else {
            json!({ "destroyed": true, "note": "simulated control plane — no real VM existed" })
        };
        // CARVE-OUT: record the EXACT deletion outcome. `teardown_state` was unconditionally
        // "torn_down" and `cleanup_verified` unconditionally true, even when the provider-native
        // destroy reported `destroyed: false`. Non-succeeded outcomes now open a durable obligation.
        let (teardown_state, cleanup_verified, deletion_disposition) =
            provider_teardown_disposition(
                &format!(
                    "provider-account://{}/resource/{}",
                    self.account_id(),
                    safe(env_ref)
                ),
                &native_teardown,
                &remote_cleanup,
            );
        inst["status"] = json!(teardown_state);
        inst["torn_down_at"] = json!(iso_now());
        inst["deletion_disposition"] = deletion_disposition.clone();
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/delete/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "teardown_state": teardown_state,
                   "remote_workspace_cleanup": remote_cleanup, "native_teardown": native_teardown,
                   "cleanup_verified": cleanup_verified, "deletion_disposition": deletion_disposition }),
        )
    }
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value {
        match self.instance(data_dir, env_ref) {
            None => {
                json!({ "provider": self.id(), "environment_ref": env_ref, "instance": Value::Null, "status": "absent" })
            }
            Some(inst) => {
                let boot_pending = inst.get("ssh").map(Value::is_null).unwrap_or(true)
                    && text(&inst, "status") != "torn_down";
                let lane_view = if text(&inst, "status") == "torn_down" {
                    Value::Null
                } else if boot_pending {
                    json!({ "boot": "pending — run start to poll until ssh readiness is proven" })
                } else {
                    match self.ssh_lane(data_dir, env_ref) {
                        Ok((lane, _guard)) => lane.observe(data_dir, env_ref),
                        Err(e) => json!({ "error": e }),
                    }
                };
                json!({ "provider": self.id(), "environment_ref": env_ref,
                        "instance_id": inst["instance_id"], "status": inst["status"],
                        "execution_mode": inst["execution_mode"], "region": inst["region"], "instance_type": inst["instance_type"],
                        "provider_native": inst["provider_native"],
                        "teardown_state": if text(&inst, "status") == "torn_down" { json!("torn_down") } else { json!("live_or_pending") },
                        "workspace": lane_view })
            }
        }
    }
}

// --- gcp GUARDED LIFECYCLE: the second ENTERPRISE hyperscaler lane — GCP semantics, never   ---
// --- EC2 names: service-account authority, project/zone scoping, VPC network/subnetwork/    ---
// --- FIREWALL posture, Compute Engine stop=TERMINATED billing semantics, reset-in-place,    ---
// --- Persistent Disk boot volumes. Native ids are EVIDENCE ONLY under daemon restore truth. ---
const GCP_INSTANCE_KIND: &str = "gcp-instances";

fn load_gcp_instance(data_dir: &str, account_id: &str, env_ref: &str) -> Option<Value> {
    let mut mine: Vec<Value> = read_record_dir(data_dir, GCP_INSTANCE_KIND)
        .into_iter()
        .filter(|i| text(i, "account_id") == account_id && text(i, "environment_ref") == env_ref)
        .collect();
    mine.sort_by(|a, b| text(a, "record_id").cmp(text(b, "record_id")));
    mine.pop()
}

struct GcpProvider {
    account: Value,
}
impl GcpProvider {
    fn account_id(&self) -> &str {
        text(&self.account, "account_id")
    }
    fn mode(&self) -> String {
        vast_mode(&self.account)
    }
    fn instance(&self, data_dir: &str, env_ref: &str) -> Option<Value> {
        load_gcp_instance(data_dir, self.account_id(), env_ref)
    }
    fn save_instance(&self, data_dir: &str, inst: &Value) -> Result<(), String> {
        let id = text(inst, "record_id").to_string();
        // W1.2 / MEF-GAP-008 — this record is the ONLY daemon handle to a JUST-CREATED (paid)
        // provider machine; a lost write orphans it from its own observe/stop/delete lane.
        persist_record(data_dir, GCP_INSTANCE_KIND, &id, inst)
            .map_err(|e| format!("provider_operation_persistence_failed — instance record {id} did not commit; the provider machine may exist with no daemon handle: {e}"))
    }
    fn push_event(inst: &mut Value, kind: &str, detail: String) {
        let mut events = inst
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        events.push(json!({ "at": iso_now(), "kind": kind, "detail": detail,
                            "execution_mode": inst["execution_mode"] }));
        inst["events"] = json!(events);
    }
    fn ssh_lane(&self, data_dir: &str, env_ref: &str) -> Result<(SshProvider, KeyGuard), String> {
        let inst = self
            .instance(data_dir, env_ref)
            .ok_or("gcp_instance_absent — provision with the quote-gated create op first")?;
        if text(&inst, "status") == "torn_down" {
            return Err("gcp_instance_deleted — this instance was already deleted".into());
        }
        let ssh = inst.get("ssh").cloned().unwrap_or(Value::Null);
        if text(&ssh, "host").is_empty() || text(&ssh, "key_file").is_empty() {
            return Err("gcp_ssh_bootstrap_unknown — the instance has no proven ssh endpoint (it gains one only after boot polling proves readiness through a reachable network/firewall posture; instance state alone is never readiness)".into());
        }
        let key = std::fs::read_to_string(text(&ssh, "key_file"))
            .map_err(|e| format!("gcp_ssh_key_unreadable: {e}"))?;
        let dir = Path::new(data_dir).join("provider-ssh");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!(
            "gcp-{}-{}.key",
            safe(self.account_id()),
            safe(env_ref)
        ));
        std::fs::write(&path, key).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        let synthetic = json!({
            "account_id": self.account_id(),
            "account_ref": self.account["account_ref"],
            "display_name": format!("{} (compute engine instance)", text(&self.account, "display_name")),
            "kind": "gcp", "status": "verified",
            "endpoint": { "host": ssh["host"], "port": ssh.get("port").cloned().unwrap_or(json!(22)), "user": ssh["user"] },
        });
        Ok((
            SshProvider {
                account: synthetic,
                key_path: path.clone(),
            },
            KeyGuard(path),
        ))
    }
    fn network_reachable(inst: &Value) -> Result<(), String> {
        let external_ip = inst
            .pointer("/network_posture/public_ip")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let ingress = inst
            .pointer("/network_posture/ssh_ingress")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if !external_ip {
            return Err("gcp_ssh_ingress_unreachable — private-only network posture (no external IP): SSH readiness cannot be proven; workspace ops fail closed, never fake-ready. Attach an external IP / reachable path (IAP/bastion) or use a BYO node inside the VPC".into());
        }
        if !ingress {
            return Err("gcp_ssh_ingress_unreachable — the VPC FIREWALL posture declares no SSH allow rule: readiness cannot be proven; add a firewall allow rule for the daemon's source or use a reachable path".into());
        }
        Ok(())
    }
}
impl EnvironmentProvider for GcpProvider {
    fn id(&self) -> &str {
        "gcp-guarded"
    }
    fn capabilities(&self) -> Value {
        let mut caps = kind_capabilities("gcp");
        caps["provider_spend_borne_by"] = json!("customer");
        caps["lifecycle"] = json!(
            "guarded_lifecycle — quote-gated create, wallet-gated mutations, delete required"
        );
        caps["execution_mode"] = json!(self.mode());
        caps
    }
    fn status(&self) -> (&'static str, String) {
        match text(&self.account, "status") {
            "verified" => (
                "available",
                format!(
                    "guarded gcp Compute Engine enterprise lifecycle ({} control plane)",
                    self.mode()
                ),
            ),
            "revoked" => ("revoked", "credential revoked".into()),
            _ => (
                "unverified",
                "bind + preflight the service-account credential".into(),
            ),
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
                return Err(format!("gcp_instance_already_provisioned — {} is live for this environment; delete it first", text(&existing, "instance_name")));
            }
        }
        let mode = self.mode();
        if mode == "live" {
            if load_account_credential(data_dir, self.account_id()).is_none() {
                return Err("gcp_live_credentials_absent — live Compute Engine lifecycle needs a bound, resolvable service-account credential; live execution is never claimed unauthenticated".into());
            }
            return Err("gcp_live_api_flow_not_implemented — the Compute Engine instances.insert/get flow lands with the live harness cut; a fake instance is never minted".into());
        }
        if mode != "simulator" {
            return Err(
                "gcp_lifecycle_mode_unset — set the account endpoint mode to simulator or live"
                    .into(),
            );
        }
        let sim_ssh = self
            .account
            .pointer("/endpoint/ssh")
            .cloned()
            .unwrap_or(Value::Null);
        if text(&sim_ssh, "host").is_empty() || text(&sim_ssh, "key_file").is_empty() {
            return Err("gcp_simulator_ssh_missing — simulator mode needs endpoint.ssh {host, port, user, key_file}".into());
        }
        let stamp = nanos();
        let record_id = format!("gcpinst_{stamp:x}");
        let instance_name = format!("sim-instance-{stamp:x}");
        let disk_name = format!("sim-disk-{stamp:x}");
        let project = {
            let p = plan.get("project").and_then(Value::as_str).unwrap_or("");
            if p.is_empty() {
                "sim-project"
            } else {
                p
            }
        };
        let zone = text(plan, "zone").to_string();
        let network = plan.get("network_posture").cloned()
            .unwrap_or_else(|| json!({ "posture_label": "default_network_simulator", "public_ip": true, "ssh_ingress": true }));
        let native_path = format!("projects/{project}/zones/{zone}/instances/{instance_name}");
        let mut inst = json!({
            "schema_version": "ioi.hypervisor.gcp-instance.v1",
            "record_id": record_id, "instance_name": instance_name,
            "account_id": self.account_id(), "account_ref": self.account["account_ref"],
            "environment_ref": env_ref, "status": "PROVISIONING",
            "execution_mode": "simulated_control_plane",
            "project": project, "region": plan["region"], "zone": zone, "machine_type": plan["machine_type"],
            "network_posture": network,
            "boot_disk": { "disk_name": disk_name, "gb": plan["disk_gb"],
                           "auto_delete": true,
                           "note": "SIMULATED Persistent Disk — native disk ids are evidence only, never restore truth" },
            "candidate_ref": plan["candidate_ref"], "quote_ref": plan["quote_ref"],
            "usd_per_hour": plan["usd_per_hour"], "max_hourly_usd": plan["max_hourly_usd"],
            "teardown_policy": plan["teardown_policy"],
            "sim_ssh": sim_ssh,
            "ssh": Value::Null,
            "events": [],
            "provider_native": { "instance_path": native_path, "disk_name": disk_name,
                "note": "SIMULATED Compute Engine/Persistent Disk ids — evidence only, never restore or billing truth; no real GCP instance exists" },
            "created_at": iso_now(),
        });
        let posture_label = inst
            .pointer("/network_posture/posture_label")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string();
        Self::push_event(&mut inst, "instances_insert_accepted", format!("{} in {zone} ({posture_label}) — Cloud Audit Log refs land with the live harness (the audit log is the customer's)", text(plan, "machine_type")));
        self.save_instance(data_dir, &inst)?;
        Ok(json!({
            "provider_operation_ref": format!("provider-account://{}/op/create/{}", self.account_id(), safe(env_ref)),
            "instance": { "instance_name": instance_name, "status": "PROVISIONING", "execution_mode": "simulated_control_plane" },
            "project": project, "zone": zone,
            "network_posture": inst["network_posture"],
            "boot_disk": inst["boot_disk"],
            "provider_native": inst["provider_native"],
            "ssh_ready": false,
            "live_provisioning_not_run": true,
            "note": "instance provisioning — run start to boot-poll; workspace ops fail closed (gcp_ssh_bootstrap_unknown) until ssh readiness is PROVEN through a reachable network/firewall posture (instance state alone is never readiness)",
            "teardown_required": true,
        }))
    }
    fn start(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("gcp_instance_absent")?;
        if text(&inst, "status") == "torn_down" {
            return Err("gcp_instance_deleted".into());
        }
        let mut boot_evidence = Value::Null;
        if inst.get("ssh").map(Value::is_null).unwrap_or(true) {
            if text(&inst, "execution_mode") == "live" {
                return Err(
                    "gcp_live_api_flow_not_implemented — no live instance exists to boot-poll"
                        .into(),
                );
            }
            Self::network_reachable(&inst)?;
            let sim_ssh = inst.get("sim_ssh").cloned().unwrap_or(Value::Null);
            boot_evidence = json!({ "polled_attempts": 1, "instance_state": "RUNNING",
                "external_ip": sim_ssh["host"], "ssh_port": sim_ssh.get("port").cloned().unwrap_or(json!(22)),
                "posture": inst["network_posture"], "proven_at": iso_now(),
                "note": "simulated boot resolved through the declared reachable network/firewall posture — RUNNING state alone was not treated as readiness" });
            inst["ssh"] = sim_ssh;
            inst["ssh_ready_evidence"] = boot_evidence.clone();
            Self::push_event(
                &mut inst,
                "boot_proven",
                "ssh readiness proven through the reachable network/firewall posture".into(),
            );
            self.save_instance(data_dir, &inst)?;
        }
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        if inst.get("workspace_bootstrapped").and_then(Value::as_bool) != Some(true) {
            lane.create(data_dir, env_ref, &json!({}))?;
            inst["workspace_bootstrapped"] = json!(true);
        }
        lane.start(data_dir, env_ref)?;
        let was_stopped = text(&inst, "status") == "TERMINATED";
        inst["status"] = json!("RUNNING");
        Self::push_event(
            &mut inst,
            "instance_started",
            if was_stopped {
                "started from TERMINATED — vCPU/RAM billing resumes; an ephemeral external IP changes across stop/start (a reserved static IP pins it); the simulator retains the fixture endpoint".into()
            } else {
                "workspace running".into()
            },
        );
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/start/{}", self.account_id(), safe(env_ref)),
                   "instance_name": inst["instance_name"], "status": "RUNNING", "ssh_ready": true,
                   "boot_evidence": boot_evidence }),
        )
    }
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.workrun(data_dir, env_ref, command)
    }
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        // REAL Compute Engine stop semantics: a stopped instance reads TERMINATED — vCPU/RAM
        // billing halts; Persistent Disk (and any reserved static IP) keeps billing.
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("gcp_instance_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let stopped = lane.stop(data_dir, env_ref)?;
        inst["status"] = json!("TERMINATED");
        Self::push_event(
            &mut inst,
            "instance_stopped",
            "state TERMINATED — vCPU/RAM billing halts; Persistent Disk keeps billing until delete"
                .into(),
        );
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/stop/{}", self.account_id(), safe(env_ref)),
                   "instance_name": inst["instance_name"], "status": "TERMINATED",
                   "spend_note": "Compute Engine stop reads TERMINATED: vCPU/RAM billing halts; the Persistent Disk boot volume keeps billing until delete — the exposure stays open until teardown",
                   "lane": stopped }),
        )
    }
    fn restart(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        // Compute Engine reset: in-place hard restart, endpoint retained.
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("gcp_instance_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let _ = lane.stop(data_dir, env_ref);
        lane.start(data_dir, env_ref)?;
        inst["status"] = json!("RUNNING");
        Self::push_event(&mut inst, "instance_reset", "in-place reset — endpoint retained (a stop/start cycle, by contrast, changes an ephemeral external IP)".into());
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/restart/{}", self.account_id(), safe(env_ref)),
                   "instance_name": inst["instance_name"], "status": "RUNNING",
                   "note": "Compute Engine reset semantics — endpoint retained; vCPU/RAM billing keeps accruing" }),
        )
    }
    fn snapshot(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("gcp_instance_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let mut evidence = lane.snapshot(data_dir, env_ref)?;
        let native = json!({
            "snapshot_name": format!("sim-snapshot-{:x}", nanos()),
            "disk_name": inst.pointer("/boot_disk/disk_name").cloned().unwrap_or(Value::Null),
            "note": "SIMULATED Persistent Disk snapshot name — evidence only, NEVER restore truth; restores admit by the daemon state_root",
        });
        if let Some(o) = evidence.as_object_mut() {
            o.insert("provider_native_snapshot".into(), native.clone());
        }
        inst["last_native_snapshot"] = native;
        Self::push_event(&mut inst, "snapshot_taken", "daemon-custody snapshot admitted; Persistent-Disk-style native name recorded as evidence".into());
        self.save_instance(data_dir, &inst)?;
        Ok(evidence)
    }
    fn restore(&self, data_dir: &str, env_ref: &str, material_ref: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.restore(data_dir, env_ref, material_ref)
    }
    fn inject_outage(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("gcp_outage_injection_not_supported — deleting a paid instance is not a safely representable outage; use the loopback/ssh conformance lanes".into())
    }
    fn recover(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("gcp_recover_not_supported — recovery is re-create + restore from daemon/storage custody; run create + restore explicitly".into())
    }
    fn delete(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("gcp_instance_absent")?;
        let remote_cleanup = match self.ssh_lane(data_dir, env_ref) {
            Ok((lane, _guard)) => lane
                .delete(data_dir, env_ref)
                .map(|e| e["cleanup_verified"].clone())
                .unwrap_or(json!("unreachable")),
            Err(e) => json!(format!("skipped: {e}")),
        };
        let native_teardown = if text(&inst, "execution_mode") == "live" {
            json!({ "destroyed": false, "error": "gcp_live_api_flow_not_implemented", "warning": "TEARDOWN MAY BE INCOMPLETE — no live instances.delete call exists yet" })
        } else if self
            .account
            .pointer("/endpoint/simulate_teardown_failure")
            .and_then(Value::as_bool)
            == Some(true)
        {
            json!({ "destroyed": false, "error": "SIMULATED delete failure (endpoint.simulate_teardown_failure)", "warning": "TEARDOWN MAY BE INCOMPLETE — verify the Compute Engine console (vCPU/RAM and Persistent Disk may still accrue)" })
        } else {
            json!({ "destroyed": true, "note": "simulated control plane — instance deleted, Persistent Disk auto-deleted with the instance; no real GCP instance existed" })
        };
        // CARVE-OUT: record the EXACT deletion outcome. `teardown_state` was unconditionally
        // "torn_down" and `cleanup_verified` unconditionally true, even when the provider-native
        // destroy reported `destroyed: false`. Non-succeeded outcomes now open a durable obligation.
        let (teardown_state, cleanup_verified, deletion_disposition) =
            provider_teardown_disposition(
                &format!(
                    "provider-account://{}/resource/{}",
                    self.account_id(),
                    safe(env_ref)
                ),
                &native_teardown,
                &remote_cleanup,
            );
        inst["status"] = json!(teardown_state);
        inst["torn_down_at"] = json!(iso_now());
        inst["deletion_disposition"] = deletion_disposition.clone();
        Self::push_event(
            &mut inst,
            "instance_deleted",
            "delete always — boot disk auto-deleted with the instance per posture".into(),
        );
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/delete/{}", self.account_id(), safe(env_ref)),
                   "instance_name": inst["instance_name"], "teardown_state": teardown_state,
                   "remote_workspace_cleanup": remote_cleanup, "native_teardown": native_teardown,
                   "cleanup_verified": cleanup_verified, "deletion_disposition": deletion_disposition }),
        )
    }
    fn events(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let inst = self
            .instance(data_dir, env_ref)
            .ok_or("gcp_instance_absent")?;
        Ok(json!({
            "instance_name": inst["instance_name"],
            "events": inst.get("events").cloned().unwrap_or(json!([])),
            "execution_mode": inst["execution_mode"],
            "basis": "daemon-recorded instance lifecycle events (simulated control plane labelled); Cloud Audit Log refs land with the live harness — the audit log is the customer's",
        }))
    }
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value {
        match self.instance(data_dir, env_ref) {
            None => {
                json!({ "provider": self.id(), "environment_ref": env_ref, "instance": Value::Null, "status": "absent" })
            }
            Some(inst) => {
                let torn = text(&inst, "status") == "torn_down";
                let boot_pending = inst.get("ssh").map(Value::is_null).unwrap_or(true) && !torn;
                let lane_view = if torn {
                    Value::Null
                } else if boot_pending {
                    json!({ "boot": "pending — run start to poll until ssh readiness is proven through a reachable posture" })
                } else {
                    match self.ssh_lane(data_dir, env_ref) {
                        Ok((lane, _guard)) => lane.observe(data_dir, env_ref),
                        Err(e) => json!({ "error": e }),
                    }
                };
                json!({ "provider": self.id(), "environment_ref": env_ref,
                        "instance_name": inst["instance_name"], "status": inst["status"],
                        "execution_mode": inst["execution_mode"],
                        "project": inst["project"], "region": inst["region"], "zone": inst["zone"], "machine_type": inst["machine_type"],
                        "network_posture": inst["network_posture"], "boot_disk": inst["boot_disk"],
                        "events_tail": inst.get("events").and_then(Value::as_array).map(|e| e.iter().rev().take(5).cloned().collect::<Vec<_>>()).unwrap_or_default(),
                        "provider_native": inst["provider_native"],
                        "teardown_state": if torn { json!("torn_down") } else { json!("live_or_pending") },
                        "workspace": lane_view })
            }
        }
    }
}

// --- k8s GUARDED LIFECYCLE: the CLUSTER substrate lane — Kubernetes/KubeVirt/customer       ---
// --- clusters treated as CLUSTERS: namespace-scoped admission (RBAC/quota/PVC/GPU/service), ---
// --- Kubernetes exec semantics (NEVER fake single-VM SSH), KubeVirt VMIs when CRDs exist.   ---
// --- The simulator's control plane is simulated; the exec/custody lane is REAL: a local     ---
// --- workload filesystem with real process execution and daemon-custody snapshots.          ---
const K8S_WORKLOAD_KIND: &str = "k8s-workloads";

fn load_k8s_workload(data_dir: &str, account_id: &str, env_ref: &str) -> Option<Value> {
    let mut mine: Vec<Value> = read_record_dir(data_dir, K8S_WORKLOAD_KIND)
        .into_iter()
        .filter(|w| text(w, "account_id") == account_id && text(w, "environment_ref") == env_ref)
        .collect();
    mine.sort_by(|a, b| text(a, "record_id").cmp(text(b, "record_id")));
    mine.pop()
}

struct K8sProvider {
    account: Value,
}
impl K8sProvider {
    fn account_id(&self) -> &str {
        text(&self.account, "account_id")
    }
    fn mode(&self) -> String {
        vast_mode(&self.account)
    }
    fn facts(&self) -> Result<Value, String> {
        let path = self
            .account
            .pointer("/endpoint/fixture_file")
            .and_then(Value::as_str)
            .unwrap_or("");
        if path.is_empty() {
            return Err("k8s_cluster_facts_missing — simulator mode needs endpoint.fixture_file (the cluster facts document)".into());
        }
        std::fs::read_to_string(path)
            .map_err(|e| format!("k8s_cluster_facts_unreadable: {e}"))
            .and_then(|raw| {
                serde_json::from_str::<Value>(&raw)
                    .map_err(|e| format!("k8s_cluster_facts_unparseable: {e}"))
            })
    }
    fn workload(&self, data_dir: &str, env_ref: &str) -> Option<Value> {
        load_k8s_workload(data_dir, self.account_id(), env_ref)
    }
    fn save_workload(&self, data_dir: &str, w: &Value) -> Result<(), String> {
        let id = text(w, "record_id").to_string();
        // W1.2 / MEF-GAP-008 — this record is the ONLY daemon handle to a JUST-CREATED cluster
        // workload; a lost write orphans it from its own observe/stop/delete lane.
        persist_record(data_dir, K8S_WORKLOAD_KIND, &id, w)
            .map_err(|e| format!("provider_operation_persistence_failed — workload record {id} did not commit; the cluster workload may exist with no daemon handle: {e}"))
    }
    fn push_event(w: &mut Value, kind: &str, detail: String) {
        let mut events = w
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        events.push(json!({ "at": iso_now(), "kind": kind, "detail": detail,
                            "execution_mode": w["execution_mode"] }));
        w["events"] = json!(events);
    }
    /// The REAL exec lane: run a command inside the workload's real local filesystem —
    /// Kubernetes exec semantics (a process in the workload), NEVER an ssh hop.
    fn exec_in_workload(workdir: &str, command: &str) -> Result<(i32, String, String), String> {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(workdir)
            .output()
            .map_err(|e| format!("k8s_exec_failed: {e}"))?;
        Ok((
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).trim_end().to_string(),
            String::from_utf8_lossy(&out.stderr).trim_end().to_string(),
        ))
    }
    fn ready_workload(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let w = self
            .workload(data_dir, env_ref)
            .ok_or("k8s_workload_absent — admit one with the gated create op first")?;
        if text(&w, "status") == "torn_down" {
            return Err("k8s_workload_deleted — this workload was already deleted".into());
        }
        if text(&w, "status") != "Running" {
            return Err(format!("k8s_workload_not_ready — workload is '{}' (run start to reach readiness); pod phase alone is never assumed", text(&w, "status")));
        }
        Ok(w)
    }
}
impl EnvironmentProvider for K8sProvider {
    fn id(&self) -> &str {
        "k8s-guarded"
    }
    fn capabilities(&self) -> Value {
        let mut caps = kind_capabilities("k8s");
        caps["provider_spend_borne_by"] = json!("customer");
        caps["lifecycle"] = json!(
            "guarded_lifecycle — admission-gated create, wallet-gated mutations, delete required"
        );
        caps["execution_mode"] = json!(self.mode());
        caps
    }
    fn status(&self) -> (&'static str, String) {
        match text(&self.account, "status") {
            "verified" => (
                "available",
                format!(
                    "guarded k8s cluster lifecycle ({} control plane)",
                    self.mode()
                ),
            ),
            "revoked" => ("revoked", "credential revoked".into()),
            _ => (
                "unverified",
                "bind + preflight the bearer/kubeconfig credential".into(),
            ),
        }
    }
    fn preflight(&self, _plan: &Value) -> Value {
        json!({ "admit": text(&self.account, "status") == "verified", "provider": self.id(),
                "account_ref": self.account["account_ref"], "execution_mode": self.mode(),
                "lifecycle": "guarded_lifecycle", "preflight_evidence": self.account.get("preflight").cloned().unwrap_or(Value::Null) })
    }
    fn create(&self, data_dir: &str, env_ref: &str, plan: &Value) -> Result<Value, String> {
        if let Some(existing) = self.workload(data_dir, env_ref) {
            if text(&existing, "status") != "torn_down" {
                return Err(format!("k8s_workload_already_admitted — {} is live for this environment; delete it first", text(&existing, "workload_name")));
            }
        }
        let mode = self.mode();
        if mode == "live" {
            if load_account_credential(data_dir, self.account_id()).is_none() {
                return Err("k8s_live_credentials_absent — a live cluster lifecycle needs a bound, resolvable bearer/kubeconfig credential; live execution is never claimed unauthenticated".into());
            }
            return Err("k8s_live_api_flow_not_implemented — the live pod/job/VMI admission flow lands with the live harness cut; a fake workload is never admitted".into());
        }
        if mode != "simulator" {
            return Err(
                "k8s_lifecycle_mode_unset — set the account endpoint mode to simulator or live"
                    .into(),
            );
        }
        // ── ADMISSION: every rung fails closed by NAME against the cluster facts. ──
        let facts = self.facts()?;
        let spec = plan.get("workload_spec").cloned().unwrap_or(json!({}));
        let namespace = text(plan, "namespace").to_string();
        let ns = facts
            .get("namespaces")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().find(|n| text(n, "name") == namespace).cloned());
        let Some(ns) = ns else {
            return Err(format!("k8s_namespace_missing — namespace '{namespace}' does not exist in the cluster facts"));
        };
        if ns.get("authorized").and_then(Value::as_bool) != Some(true) {
            return Err(format!("k8s_namespace_unauthorized — the bound service account has no admission rights in '{namespace}' (RBAC posture)"));
        }
        let quota = ns.get("quota").cloned().unwrap_or(json!({}));
        let req = spec.get("resources").cloned().unwrap_or(json!({}));
        let cpu_req = req.get("cpu_milli").and_then(Value::as_u64).unwrap_or(500);
        let mem_req = req.get("memory_gb").and_then(Value::as_u64).unwrap_or(1);
        let gpu_req = req.get("gpu").and_then(Value::as_u64).unwrap_or(0);
        if cpu_req
            > quota
                .get("cpu_milli_available")
                .and_then(Value::as_u64)
                .unwrap_or(0)
            || mem_req
                > quota
                    .get("memory_gb_available")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
        {
            return Err(format!("k8s_quota_insufficient — requested cpu {cpu_req}m / mem {mem_req}GB exceeds the namespace quota ({quota})"));
        }
        if gpu_req > 0 {
            let plugin = facts
                .pointer("/gpu/device_plugin")
                .and_then(Value::as_str)
                .unwrap_or("");
            let ns_gpu = quota
                .get("gpu_available")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if plugin.is_empty() || gpu_req > ns_gpu {
                return Err(format!("k8s_gpu_unschedulable — requested {gpu_req} GPU(s) but device-plugin/quota posture admits {ns_gpu} (plugin: '{plugin}'); GPU scheduling is never assumed"));
            }
        }
        let pvc = spec.get("pvc").cloned().unwrap_or(Value::Null);
        if !pvc.is_null() {
            let sc = text(&pvc, "storage_class");
            let supported = facts
                .get("storage_classes")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter().any(|c| {
                        text(c, "name") == sc
                            && c.get("pvc_supported").and_then(Value::as_bool) == Some(true)
                    })
                })
                .unwrap_or(false);
            if !supported {
                return Err(format!("k8s_pvc_storage_class_unavailable — storage class '{sc}' does not support PVCs on this cluster"));
            }
        }
        let service = spec.get("service").cloned().unwrap_or(Value::Null);
        if !service.is_null() {
            let svc_type = text(&service, "type");
            if svc_type == "LoadBalancer"
                && facts
                    .pointer("/services/load_balancer")
                    .and_then(Value::as_bool)
                    != Some(true)
            {
                return Err("k8s_service_ingress_unsupported — the cluster declares no LoadBalancer support; use ClusterIP/ingress per the cluster posture".into());
            }
        }
        let kubevirt_req = spec
            .get("kubevirt")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if kubevirt_req
            && facts
                .pointer("/kubevirt/installed")
                .and_then(Value::as_bool)
                != Some(true)
        {
            return Err("k8s_kubevirt_crds_absent — a KubeVirt VMI was requested but the KubeVirt CRDs are not installed on this cluster".into());
        }
        // ── Admitted: mint the workload with a REAL local filesystem (the exec/custody lane). ──
        let stamp = nanos();
        let record_id = format!("k8swl_{stamp:x}");
        let workload_class = if kubevirt_req { "kubevirt_vmi" } else { "pod" };
        let workload_name = if kubevirt_req {
            format!("vmi-sim-{stamp:x}")
        } else {
            format!("pod-sim-{stamp:x}")
        };
        let uid = format!("uid-sim-{stamp:x}");
        let workdir = Path::new(data_dir)
            .join("k8s-workloads-fs")
            .join(safe(self.account_id()))
            .join(safe(env_ref));
        std::fs::create_dir_all(&workdir).map_err(|e| format!("k8s_workload_fs_failed: {e}"))?;
        let pvc_native = if pvc.is_null() {
            Value::Null
        } else {
            json!({ "pvc_name": format!("pvc-sim-{stamp:x}"), "storage_class": pvc["storage_class"], "size_gb": pvc["size_gb"],
                    "note": "SIMULATED PVC name — evidence only; PVC persistence is CLUSTER posture, never restore truth" })
        };
        let service_native = if service.is_null() {
            Value::Null
        } else {
            json!({ "service_name": format!("svc-sim-{stamp:x}"), "type": service["type"], "port": service["port"],
                    "note": "SIMULATED service name — exposure evidence, not authority" })
        };
        let mut w = json!({
            "schema_version": "ioi.hypervisor.k8s-workload.v1",
            "record_id": record_id, "workload_name": workload_name, "workload_class": workload_class,
            "account_id": self.account_id(), "account_ref": self.account["account_ref"],
            "environment_ref": env_ref, "status": "Pending",
            "execution_mode": "simulated_control_plane",
            "cluster": facts.get("cluster").cloned().unwrap_or(Value::Null),
            "namespace": namespace, "workload_spec": spec, "workload_spec_hash": plan["workload_spec_hash"],
            "exec_posture": "kubernetes_exec",
            "candidate_ref": plan["candidate_ref"],
            "teardown_policy": plan["teardown_policy"],
            "workdir": workdir.to_string_lossy(),
            "events": [],
            "provider_native": { "name": workload_name, "uid": uid, "pvc": pvc_native, "service": service_native,
                "note": if kubevirt_req { "SIMULATED KubeVirt VMI name/uid — explicitly KubeVirt, never a generic VM; evidence only, never restore or billing truth; no real cluster workload exists" }
                        else { "SIMULATED pod name/uid — evidence only, never restore or billing truth; no real cluster workload exists" } },
            "created_at": iso_now(),
        });
        Self::push_event(&mut w, "workload_admitted", format!("{workload_class} admitted in namespace '{namespace}' under quota (cpu {cpu_req}m / mem {mem_req}GB / gpu {gpu_req})"));
        self.save_workload(data_dir, &w)?;
        Ok(json!({
            "provider_operation_ref": format!("provider-account://{}/op/create/{}", self.account_id(), safe(env_ref)),
            "workload": { "workload_name": workload_name, "workload_class": workload_class, "namespace": w["namespace"], "status": "Pending", "execution_mode": "simulated_control_plane" },
            "provider_native": w["provider_native"],
            "ready": false,
            "live_provisioning_not_run": true,
            "note": "workload admitted (Pending) — run start to reach readiness; exec fails closed (k8s_workload_not_ready) until then",
            "teardown_required": true,
        }))
    }
    fn start(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut w = self
            .workload(data_dir, env_ref)
            .ok_or("k8s_workload_absent")?;
        if text(&w, "status") == "torn_down" {
            return Err("k8s_workload_deleted".into());
        }
        // Readiness is PROVEN by the real workload fs: a probe file round-trips through the
        // exec lane (pod phase alone is never treated as readiness).
        let workdir = text(&w, "workdir").to_string();
        let (code, out, err) = Self::exec_in_workload(
            &workdir,
            "echo ready > .k8s-readiness-probe && cat .k8s-readiness-probe",
        )?;
        if code != 0 || out != "ready" {
            return Err(format!(
                "k8s_workload_not_ready — readiness probe failed (exit {code}): {err}"
            ));
        }
        let service_evidence = w
            .pointer("/provider_native/service")
            .cloned()
            .unwrap_or(Value::Null);
        w["status"] = json!("Running");
        w["ready_evidence"] = json!({ "probe": "exec round-trip through the workload fs", "proven_at": iso_now(),
                                      "note": "readiness proven by the exec lane — pod phase alone was not treated as readiness" });
        Self::push_event(
            &mut w,
            "workload_ready",
            "readiness probe round-tripped through the exec lane".into(),
        );
        self.save_workload(data_dir, &w)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/start/{}", self.account_id(), safe(env_ref)),
                   "workload_name": w["workload_name"], "status": "Running", "ready": true,
                   "ready_evidence": w["ready_evidence"],
                   "service": service_evidence }),
        )
    }
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String> {
        let mut w = self.ready_workload(data_dir, env_ref)?;
        let workdir = text(&w, "workdir").to_string();
        let (code, stdout, stderr) = Self::exec_in_workload(&workdir, command)?;
        Self::push_event(
            &mut w,
            "exec",
            format!(
                "kubernetes exec: `{}` → exit {code}",
                command.chars().take(60).collect::<String>()
            ),
        );
        self.save_workload(data_dir, &w)?;
        if code != 0 {
            return Err(format!("k8s exec failed (exit {code}): {stderr}"));
        }
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/workrun/{}", self.account_id(), safe(env_ref)),
                   "exec_lane": "kubernetes_exec — a process in the workload (simulated API transport; process execution REAL); never an ssh hop",
                   "exit_code": code, "stdout": stdout, "stderr": stderr }),
        )
    }
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut w = self
            .workload(data_dir, env_ref)
            .ok_or("k8s_workload_absent")?;
        w["status"] = json!("Stopped");
        Self::push_event(&mut w, "workload_stopped", "workload stopped — customer/operator cluster: no metered spend lane by default; PVC persists per its storage class (cluster posture, not restore truth)".into());
        self.save_workload(data_dir, &w)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/stop/{}", self.account_id(), safe(env_ref)),
                   "workload_name": w["workload_name"], "status": "Stopped",
                   "spend_note": "customer/operator-owned cluster — no direct provider price; a DECLARED metered posture would keep any exposure open until delete" }),
        )
    }
    fn snapshot(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let w = self.ready_workload(data_dir, env_ref)?;
        let workdir = text(&w, "workdir").to_string();
        let out = std::process::Command::new("tar")
            .args(["-czf", "-", "-C", &workdir, "."])
            .output()
            .map_err(|e| format!("k8s_snapshot_failed: {e}"))?;
        if !out.status.success() || out.stdout.is_empty() {
            return Err(format!(
                "k8s_snapshot_failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        let tar_bytes = out.stdout;
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
        let material_ref = format!(
            "provider-material://{}/{}/{stamp}",
            safe(self.account_id()),
            safe(env_ref)
        );
        let record = json!({
            "schema_version": "ioi.hypervisor.provider-material.v1",
            "material_id": material_id, "material_ref": material_ref,
            "account_ref": text(&self.account, "account_ref"),
            "environment_ref": env_ref,
            "state_root": state_root, "bytes": tar_bytes.len(),
            "custody": "daemon", "path": file.to_string_lossy(),
            "at": iso_now(),
        });
        // W1.2 / MEF-GAP-008 — admitted:true rests on this record and restore resolves by it; the
        // custody tar is already on disk, so a lost record orphans those bytes. Refuse.
        persist_record(data_dir, MATERIAL_KIND, &material_id, &record)
            .map_err(|e| format!("provider_operation_persistence_failed — snapshot material record {material_id} did not commit; custody bytes are written at {} but not daemon-admitted: {e}", file.to_string_lossy()))?;
        let mut w2 = w.clone();
        Self::push_event(&mut w2, "snapshot_taken", "workload fs streamed to daemon custody; VolumeSnapshot-style native name recorded as evidence".into());
        self.save_workload(data_dir, &w2)?;
        Ok(
            json!({ "restore_material_ref": material_ref, "state_root": state_root, "custody": "daemon",
                   "bytes": tar_bytes.len(), "admitted": true,
                   "provider_native_snapshot": { "volume_snapshot_name": format!("volumesnapshot-sim-{stamp}"),
                       "note": "SIMULATED VolumeSnapshot name — evidence only, NEVER restore truth; restores admit by the daemon state_root" } }),
        )
    }
    fn restore(&self, data_dir: &str, env_ref: &str, material_ref: &str) -> Result<Value, String> {
        let w = self
            .workload(data_dir, env_ref)
            .ok_or("k8s_workload_absent")?;
        if text(&w, "status") == "torn_down" {
            return Err("k8s_workload_deleted".into());
        }
        let material = read_record_dir(data_dir, MATERIAL_KIND)
            .into_iter()
            .find(|m| text(m, "material_ref") == material_ref)
            .ok_or(format!(
                "restore material '{material_ref}' is not daemon-admitted"
            ))?;
        let bytes = std::fs::read(text(&material, "path"))
            .map_err(|e| format!("custody material unreadable: {e}"))?;
        let admitted = text(&material, "state_root");
        let actual = sha256_bytes(&bytes);
        if actual != admitted {
            return Err(format!("restore_material_hash_mismatch — custody bytes hash {actual} but admitted state_root is {admitted}; refusing restore (PVC/blob existence is not restore truth)"));
        }
        let workdir = text(&w, "workdir").to_string();
        let _ = std::fs::remove_dir_all(&workdir);
        std::fs::create_dir_all(&workdir).map_err(|e| e.to_string())?;
        let mut child = std::process::Command::new("tar")
            .args(["-xzf", "-", "-C", &workdir])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("k8s_restore_failed: {e}"))?;
        {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .ok_or("k8s_restore_failed: no stdin")?
                .write_all(&bytes)
                .map_err(|e| e.to_string())?;
        }
        let status = child.wait().map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("k8s_restore_failed: tar extraction failed".into());
        }
        let mut w2 = w.clone();
        Self::push_event(
            &mut w2,
            "restored",
            format!("workload fs restored from daemon custody ({material_ref})"),
        );
        self.save_workload(data_dir, &w2)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/restore/{}", self.account_id(), safe(env_ref)),
                   "restored_from": material_ref, "state_root_verified": admitted }),
        )
    }
    fn logs(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let w = self
            .workload(data_dir, env_ref)
            .ok_or("k8s_workload_absent")?;
        Ok(json!({
            "workload_name": w["workload_name"],
            "control_plane_log": w.get("events").cloned().unwrap_or(json!([])),
            "container_logs": "unavailable_in_simulator — live pod logs land with the live harness; exec outputs are receipted in the Work Ledger",
            "execution_mode": w["execution_mode"],
            "basis": "daemon-recorded workload lifecycle events (simulated control plane labelled)",
        }))
    }
    fn events(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let w = self
            .workload(data_dir, env_ref)
            .ok_or("k8s_workload_absent")?;
        Ok(json!({
            "workload_name": w["workload_name"],
            "events": w.get("events").cloned().unwrap_or(json!([])),
            "execution_mode": w["execution_mode"],
            "basis": "daemon-recorded workload lifecycle events (simulated control plane labelled)",
        }))
    }
    fn inject_outage(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("k8s_outage_injection_not_supported — evicting a customer workload is not a safely representable outage; use the loopback/ssh conformance lanes".into())
    }
    fn recover(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("k8s_recover_not_supported — recovery is re-admit + restore from daemon/storage custody; run create + restore explicitly".into())
    }
    fn delete(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut w = self
            .workload(data_dir, env_ref)
            .ok_or("k8s_workload_absent")?;
        let workdir = text(&w, "workdir").to_string();
        let fs_cleanup = if !workdir.is_empty() && std::fs::remove_dir_all(&workdir).is_ok() {
            json!(true)
        } else {
            json!("already_absent_or_skipped")
        };
        let native_teardown = if self
            .account
            .pointer("/endpoint/simulate_teardown_failure")
            .and_then(Value::as_bool)
            == Some(true)
        {
            json!({ "destroyed": false, "error": "SIMULATED delete failure (endpoint.simulate_teardown_failure)", "warning": "TEARDOWN MAY BE INCOMPLETE — verify the namespace (workload/PVC may persist)" })
        } else {
            json!({ "destroyed": true, "note": "simulated control plane — workload/PVC/service deleted in the namespace; no real cluster workload existed" })
        };
        // CARVE-OUT: record the EXACT deletion outcome. `teardown_state` was unconditionally
        // "torn_down" and `cleanup_verified` unconditionally true, even when the provider-native
        // destroy reported `destroyed: false`. Non-succeeded outcomes now open a durable obligation.
        let (teardown_state, cleanup_verified, deletion_disposition) =
            provider_teardown_disposition(
                &format!(
                    "provider-account://{}/resource/{}",
                    self.account_id(),
                    safe(env_ref)
                ),
                &native_teardown,
                &fs_cleanup,
            );
        w["status"] = json!(teardown_state);
        w["torn_down_at"] = json!(iso_now());
        w["deletion_disposition"] = deletion_disposition.clone();
        Self::push_event(
            &mut w,
            "workload_deleted",
            "delete always — workload, PVC, and service removed per teardown policy".into(),
        );
        self.save_workload(data_dir, &w)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/delete/{}", self.account_id(), safe(env_ref)),
                   "workload_name": w["workload_name"], "teardown_state": teardown_state,
                   "workload_fs_cleanup": fs_cleanup, "native_teardown": native_teardown,
                   "cleanup_verified": cleanup_verified, "deletion_disposition": deletion_disposition }),
        )
    }
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value {
        match self.workload(data_dir, env_ref) {
            None => {
                json!({ "provider": self.id(), "environment_ref": env_ref, "workload": Value::Null, "status": "absent" })
            }
            Some(w) => {
                json!({ "provider": self.id(), "environment_ref": env_ref,
                        "workload_name": w["workload_name"], "workload_class": w["workload_class"],
                        "status": w["status"], "execution_mode": w["execution_mode"],
                        "cluster": w["cluster"], "namespace": w["namespace"],
                        "workload_spec": w["workload_spec"], "exec_posture": w["exec_posture"],
                        "events_tail": w.get("events").and_then(Value::as_array).map(|e| e.iter().rev().take(5).cloned().collect::<Vec<_>>()).unwrap_or_default(),
                        "provider_native": w["provider_native"],
                        "teardown_state": if text(&w, "status") == "torn_down" { json!("torn_down") } else { json!("live_or_pending") } })
            }
        }
    }
}

// --- azure GUARDED LIFECYCLE: the third ENTERPRISE hyperscaler lane and the first fully    ---
// --- NEW account kind — Azure semantics: service-principal authority over ARM,              ---
// --- subscription/resource-group/location scoping, VNet/subnet/NSG posture, stopped-vs-     ---
// --- DEALLOCATED billing honesty, managed OS disks. Native ids EVIDENCE ONLY.               ---
const AZURE_INSTANCE_KIND: &str = "azure-instances";

fn load_azure_instance(data_dir: &str, account_id: &str, env_ref: &str) -> Option<Value> {
    let mut mine: Vec<Value> = read_record_dir(data_dir, AZURE_INSTANCE_KIND)
        .into_iter()
        .filter(|i| text(i, "account_id") == account_id && text(i, "environment_ref") == env_ref)
        .collect();
    mine.sort_by(|a, b| text(a, "record_id").cmp(text(b, "record_id")));
    mine.pop()
}

struct AzureProvider {
    account: Value,
}
impl AzureProvider {
    fn account_id(&self) -> &str {
        text(&self.account, "account_id")
    }
    fn mode(&self) -> String {
        vast_mode(&self.account)
    }
    fn instance(&self, data_dir: &str, env_ref: &str) -> Option<Value> {
        load_azure_instance(data_dir, self.account_id(), env_ref)
    }
    fn save_instance(&self, data_dir: &str, inst: &Value) -> Result<(), String> {
        let id = text(inst, "record_id").to_string();
        // W1.2 / MEF-GAP-008 — this record is the ONLY daemon handle to a JUST-CREATED (paid)
        // provider machine; a lost write orphans it from its own observe/stop/delete lane.
        persist_record(data_dir, AZURE_INSTANCE_KIND, &id, inst)
            .map_err(|e| format!("provider_operation_persistence_failed — instance record {id} did not commit; the provider machine may exist with no daemon handle: {e}"))
    }
    fn push_event(inst: &mut Value, kind: &str, detail: String) {
        let mut events = inst
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        events.push(json!({ "at": iso_now(), "kind": kind, "detail": detail,
                            "execution_mode": inst["execution_mode"] }));
        inst["events"] = json!(events);
    }
    fn ssh_lane(&self, data_dir: &str, env_ref: &str) -> Result<(SshProvider, KeyGuard), String> {
        let inst = self
            .instance(data_dir, env_ref)
            .ok_or("azure_vm_absent — provision with the quote-gated create op first")?;
        if text(&inst, "status") == "torn_down" {
            return Err("azure_vm_deleted — this instance was already deleted".into());
        }
        let ssh = inst.get("ssh").cloned().unwrap_or(Value::Null);
        if text(&ssh, "host").is_empty() || text(&ssh, "key_file").is_empty() {
            return Err("azure_ssh_bootstrap_unknown — the VM has no proven ssh endpoint (it gains one only after boot polling proves readiness through a reachable VNet/NSG posture; VM provisioning state alone is never readiness)".into());
        }
        let key = std::fs::read_to_string(text(&ssh, "key_file"))
            .map_err(|e| format!("azure_ssh_key_unreadable: {e}"))?;
        let dir = Path::new(data_dir).join("provider-ssh");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!(
            "azure-{}-{}.key",
            safe(self.account_id()),
            safe(env_ref)
        ));
        std::fs::write(&path, key).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        let synthetic = json!({
            "account_id": self.account_id(),
            "account_ref": self.account["account_ref"],
            "display_name": format!("{} (azure vm)", text(&self.account, "display_name")),
            "kind": "azure", "status": "verified",
            "endpoint": { "host": ssh["host"], "port": ssh.get("port").cloned().unwrap_or(json!(22)), "user": ssh["user"] },
        });
        Ok((
            SshProvider {
                account: synthetic,
                key_path: path.clone(),
            },
            KeyGuard(path),
        ))
    }
    fn network_reachable(inst: &Value) -> Result<(), String> {
        let external_ip = inst
            .pointer("/network_posture/public_ip")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let ingress = inst
            .pointer("/network_posture/ssh_ingress")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if !external_ip {
            return Err("azure_ssh_ingress_unreachable — private-only network posture (no public IP): SSH readiness cannot be proven; workspace ops fail closed, never fake-ready. Attach a public IP / reachable path (Bastion) or use a BYO node inside the VNet".into());
        }
        if !ingress {
            return Err("azure_ssh_ingress_unreachable — the NSG posture declares no SSH allow rule: readiness cannot be proven; add an NSG allow rule for the daemon's source or use a reachable path".into());
        }
        Ok(())
    }
}
impl EnvironmentProvider for AzureProvider {
    fn id(&self) -> &str {
        "azure-guarded"
    }
    fn capabilities(&self) -> Value {
        let mut caps = kind_capabilities("azure");
        caps["provider_spend_borne_by"] = json!("customer");
        caps["lifecycle"] = json!(
            "guarded_lifecycle — quote-gated create, wallet-gated mutations, delete required"
        );
        caps["execution_mode"] = json!(self.mode());
        caps
    }
    fn status(&self) -> (&'static str, String) {
        match text(&self.account, "status") {
            "verified" => (
                "available",
                format!(
                    "guarded azure VM enterprise lifecycle ({} control plane)",
                    self.mode()
                ),
            ),
            "revoked" => ("revoked", "credential revoked".into()),
            _ => (
                "unverified",
                "bind + preflight the service-principal credential".into(),
            ),
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
                return Err(format!("azure_vm_already_provisioned — {} is live for this environment; delete it first", text(&existing, "vm_name")));
            }
        }
        let mode = self.mode();
        if mode == "live" {
            if load_account_credential(data_dir, self.account_id()).is_none() {
                return Err("azure_live_credentials_absent — live ARM lifecycle needs a bound, resolvable service-principal credential; live execution is never claimed unauthenticated".into());
            }
            return Err("azure_live_api_flow_not_implemented — the ARM virtualMachines create/get flow lands with the live harness cut; a fake VM is never minted".into());
        }
        if mode != "simulator" {
            return Err(
                "azure_lifecycle_mode_unset — set the account endpoint mode to simulator or live"
                    .into(),
            );
        }
        let sim_ssh = self
            .account
            .pointer("/endpoint/ssh")
            .cloned()
            .unwrap_or(Value::Null);
        if text(&sim_ssh, "host").is_empty() || text(&sim_ssh, "key_file").is_empty() {
            return Err("azure_simulator_ssh_missing — simulator mode needs endpoint.ssh {host, port, user, key_file}".into());
        }
        let stamp = nanos();
        let record_id = format!("azinst_{stamp:x}");
        let vm_name = format!("sim-vm-{stamp:x}");
        let disk_name = format!("sim-osdisk-{stamp:x}");
        let subscription = {
            let p = plan
                .get("subscription_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            if p.is_empty() {
                "sim-subscription"
            } else {
                p
            }
        };
        let resource_group = {
            let p = plan
                .get("resource_group")
                .and_then(Value::as_str)
                .unwrap_or("");
            if p.is_empty() {
                "sim-rg"
            } else {
                p
            }
        };
        let location = text(plan, "location").to_string();
        let network = plan.get("network_posture").cloned()
            .unwrap_or_else(|| json!({ "posture_label": "default_vnet_simulator", "public_ip": true, "ssh_ingress": true }));
        let native_path = format!("/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}");
        let mut inst = json!({
            "schema_version": "ioi.hypervisor.azure-instance.v1",
            "record_id": record_id, "vm_name": vm_name,
            "account_id": self.account_id(), "account_ref": self.account["account_ref"],
            "environment_ref": env_ref, "status": "Creating",
            "execution_mode": "simulated_control_plane",
            "subscription_id": subscription, "resource_group": resource_group, "location": location, "vm_size": plan["vm_size"],
            "network_posture": network,
            "os_disk": { "disk_name": disk_name, "gb": plan["disk_gb"],
                         "delete_with_vm": true,
                         "note": "SIMULATED managed OS disk — native disk ids are evidence only, never restore truth" },
            "candidate_ref": plan["candidate_ref"], "quote_ref": plan["quote_ref"],
            "usd_per_hour": plan["usd_per_hour"], "max_hourly_usd": plan["max_hourly_usd"],
            "teardown_policy": plan["teardown_policy"],
            "sim_ssh": sim_ssh,
            "ssh": Value::Null,
            "events": [],
            "provider_native": { "resource_id": native_path, "disk_name": disk_name,
                "note": "SIMULATED ARM resource/managed-disk ids — evidence only, never restore or billing truth; no real Azure VM exists" },
            "created_at": iso_now(),
        });
        let posture_label = inst
            .pointer("/network_posture/posture_label")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string();
        Self::push_event(&mut inst, "vm_create_accepted", format!("{} in {location} ({posture_label}) — Activity Log refs land with the live harness (the Activity Log is the customer's)", text(plan, "vm_size")));
        self.save_instance(data_dir, &inst)?;
        Ok(json!({
            "provider_operation_ref": format!("provider-account://{}/op/create/{}", self.account_id(), safe(env_ref)),
            "instance": { "vm_name": vm_name, "status": "Creating", "execution_mode": "simulated_control_plane" },
            "subscription_id": subscription, "resource_group": resource_group, "location": location,
            "network_posture": inst["network_posture"],
            "os_disk": inst["os_disk"],
            "provider_native": inst["provider_native"],
            "ssh_ready": false,
            "live_provisioning_not_run": true,
            "note": "VM creating — run start to boot-poll; workspace ops fail closed (azure_ssh_bootstrap_unknown) until ssh readiness is PROVEN through a reachable VNet/NSG posture (provisioning state alone is never readiness)",
            "teardown_required": true,
        }))
    }
    fn start(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self.instance(data_dir, env_ref).ok_or("azure_vm_absent")?;
        if text(&inst, "status") == "torn_down" {
            return Err("azure_vm_deleted".into());
        }
        let mut boot_evidence = Value::Null;
        if inst.get("ssh").map(Value::is_null).unwrap_or(true) {
            if text(&inst, "execution_mode") == "live" {
                return Err(
                    "azure_live_api_flow_not_implemented — no live VM exists to boot-poll".into(),
                );
            }
            Self::network_reachable(&inst)?;
            let sim_ssh = inst.get("sim_ssh").cloned().unwrap_or(Value::Null);
            boot_evidence = json!({ "polled_attempts": 1, "vm_state": "VM running",
                "public_ip": sim_ssh["host"], "ssh_port": sim_ssh.get("port").cloned().unwrap_or(json!(22)),
                "posture": inst["network_posture"], "proven_at": iso_now(),
                "note": "simulated boot resolved through the declared reachable VNet/NSG posture — 'VM running' state alone was not treated as readiness" });
            inst["ssh"] = sim_ssh;
            inst["ssh_ready_evidence"] = boot_evidence.clone();
            Self::push_event(
                &mut inst,
                "boot_proven",
                "ssh readiness proven through the reachable VNet/NSG posture".into(),
            );
            self.save_instance(data_dir, &inst)?;
        }
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        if inst.get("workspace_bootstrapped").and_then(Value::as_bool) != Some(true) {
            lane.create(data_dir, env_ref, &json!({}))?;
            inst["workspace_bootstrapped"] = json!(true);
        }
        lane.start(data_dir, env_ref)?;
        let was_stopped = matches!(text(&inst, "status"), "VM deallocated" | "VM stopped");
        inst["status"] = json!("VM running");
        Self::push_event(
            &mut inst,
            "vm_started",
            if was_stopped {
                "started from deallocated — compute billing resumes; a dynamic public IP changes across deallocate/start (a static IP pins it); the simulator retains the fixture endpoint".into()
            } else {
                "workspace running".into()
            },
        );
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/start/{}", self.account_id(), safe(env_ref)),
                   "vm_name": inst["vm_name"], "status": "VM running", "ssh_ready": true,
                   "boot_evidence": boot_evidence }),
        )
    }
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.workrun(data_dir, env_ref, command)
    }
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        // REAL Azure stop semantics, stated exactly: a merely-STOPPED VM (guest shutdown)
        // KEEPS billing compute; only DEALLOCATED releases the hardware and halts compute
        // billing. This op DEALLOCATES (the honest cost-control default) and says so;
        // managed disks (and any static public IP) keep billing until delete either way.
        let mut inst = self.instance(data_dir, env_ref).ok_or("azure_vm_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let stopped = lane.stop(data_dir, env_ref)?;
        inst["status"] = json!("VM deallocated");
        Self::push_event(&mut inst, "vm_deallocated", "DEALLOCATED (not merely stopped) — compute billing halts; a merely-stopped VM would keep billing compute; managed disks keep billing until delete".into());
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/stop/{}", self.account_id(), safe(env_ref)),
                   "vm_name": inst["vm_name"], "status": "VM deallocated",
                   "deallocated": true,
                   "spend_note": "Azure stop-vs-deallocate honesty: this op DEALLOCATES — compute billing halts only because the VM is deallocated (a merely-stopped VM keeps billing compute); managed disks keep billing until delete — the exposure stays open until teardown",
                   "lane": stopped }),
        )
    }
    fn restart(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        // Azure VM restart: in-place restart, endpoint retained (no deallocation).
        let mut inst = self.instance(data_dir, env_ref).ok_or("azure_vm_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let _ = lane.stop(data_dir, env_ref);
        lane.start(data_dir, env_ref)?;
        inst["status"] = json!("VM running");
        Self::push_event(&mut inst, "vm_restarted", "in-place restart — endpoint retained, no deallocation (a deallocate/start cycle, by contrast, changes a dynamic public IP)".into());
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/restart/{}", self.account_id(), safe(env_ref)),
                   "vm_name": inst["vm_name"], "status": "VM running",
                   "note": "Azure restart semantics — endpoint retained; compute billing keeps accruing (no deallocation)" }),
        )
    }
    fn snapshot(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self.instance(data_dir, env_ref).ok_or("azure_vm_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let mut evidence = lane.snapshot(data_dir, env_ref)?;
        let native = json!({
            "snapshot_name": format!("sim-snapshot-{:x}", nanos()),
            "disk_name": inst.pointer("/os_disk/disk_name").cloned().unwrap_or(Value::Null),
            "note": "SIMULATED managed-disk snapshot name — evidence only, NEVER restore truth; restores admit by the daemon state_root",
        });
        if let Some(o) = evidence.as_object_mut() {
            o.insert("provider_native_snapshot".into(), native.clone());
        }
        inst["last_native_snapshot"] = native;
        Self::push_event(
            &mut inst,
            "snapshot_taken",
            "daemon-custody snapshot admitted; managed-disk-style native name recorded as evidence"
                .into(),
        );
        self.save_instance(data_dir, &inst)?;
        Ok(evidence)
    }
    fn restore(&self, data_dir: &str, env_ref: &str, material_ref: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.restore(data_dir, env_ref, material_ref)
    }
    fn inject_outage(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("azure_outage_injection_not_supported — deleting a paid VM is not a safely representable outage; use the loopback/ssh conformance lanes".into())
    }
    fn recover(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("azure_recover_not_supported — recovery is re-create + restore from daemon/storage custody; run create + restore explicitly".into())
    }
    fn delete(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self.instance(data_dir, env_ref).ok_or("azure_vm_absent")?;
        let remote_cleanup = match self.ssh_lane(data_dir, env_ref) {
            Ok((lane, _guard)) => lane
                .delete(data_dir, env_ref)
                .map(|e| e["cleanup_verified"].clone())
                .unwrap_or(json!("unreachable")),
            Err(e) => json!(format!("skipped: {e}")),
        };
        let native_teardown = if text(&inst, "execution_mode") == "live" {
            json!({ "destroyed": false, "error": "azure_live_api_flow_not_implemented", "warning": "TEARDOWN MAY BE INCOMPLETE — no live virtualMachines delete call exists yet" })
        } else if self
            .account
            .pointer("/endpoint/simulate_teardown_failure")
            .and_then(Value::as_bool)
            == Some(true)
        {
            json!({ "destroyed": false, "error": "SIMULATED delete failure (endpoint.simulate_teardown_failure)", "warning": "TEARDOWN MAY BE INCOMPLETE — verify the Azure portal (compute and managed disks may still accrue)" })
        } else {
            json!({ "destroyed": true, "note": "simulated control plane — VM deleted, managed OS disk deleted with the VM per delete option; no real Azure VM existed" })
        };
        // CARVE-OUT: record the EXACT deletion outcome. `teardown_state` was unconditionally
        // "torn_down" and `cleanup_verified` unconditionally true, even when the provider-native
        // destroy reported `destroyed: false`. Non-succeeded outcomes now open a durable obligation.
        let (teardown_state, cleanup_verified, deletion_disposition) =
            provider_teardown_disposition(
                &format!(
                    "provider-account://{}/resource/{}",
                    self.account_id(),
                    safe(env_ref)
                ),
                &native_teardown,
                &remote_cleanup,
            );
        inst["status"] = json!(teardown_state);
        inst["torn_down_at"] = json!(iso_now());
        inst["deletion_disposition"] = deletion_disposition.clone();
        Self::push_event(
            &mut inst,
            "vm_deleted",
            "delete always — managed OS disk deleted with the VM per delete option".into(),
        );
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/delete/{}", self.account_id(), safe(env_ref)),
                   "vm_name": inst["vm_name"], "teardown_state": teardown_state,
                   "remote_workspace_cleanup": remote_cleanup, "native_teardown": native_teardown,
                   "cleanup_verified": cleanup_verified, "deletion_disposition": deletion_disposition }),
        )
    }
    fn events(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let inst = self.instance(data_dir, env_ref).ok_or("azure_vm_absent")?;
        Ok(json!({
            "vm_name": inst["vm_name"],
            "events": inst.get("events").cloned().unwrap_or(json!([])),
            "execution_mode": inst["execution_mode"],
            "basis": "daemon-recorded VM lifecycle events (simulated control plane labelled); Activity Log refs land with the live harness — the Activity Log is the customer's",
        }))
    }
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value {
        match self.instance(data_dir, env_ref) {
            None => {
                json!({ "provider": self.id(), "environment_ref": env_ref, "instance": Value::Null, "status": "absent" })
            }
            Some(inst) => {
                let torn = text(&inst, "status") == "torn_down";
                let boot_pending = inst.get("ssh").map(Value::is_null).unwrap_or(true) && !torn;
                let lane_view = if torn {
                    Value::Null
                } else if boot_pending {
                    json!({ "boot": "pending — run start to poll until ssh readiness is proven through a reachable posture" })
                } else {
                    match self.ssh_lane(data_dir, env_ref) {
                        Ok((lane, _guard)) => lane.observe(data_dir, env_ref),
                        Err(e) => json!({ "error": e }),
                    }
                };
                json!({ "provider": self.id(), "environment_ref": env_ref,
                        "vm_name": inst["vm_name"], "status": inst["status"],
                        "execution_mode": inst["execution_mode"],
                        "subscription_id": inst["subscription_id"], "resource_group": inst["resource_group"], "location": inst["location"], "vm_size": inst["vm_size"],
                        "network_posture": inst["network_posture"], "os_disk": inst["os_disk"],
                        "events_tail": inst.get("events").and_then(Value::as_array).map(|e| e.iter().rev().take(5).cloned().collect::<Vec<_>>()).unwrap_or_default(),
                        "provider_native": inst["provider_native"],
                        "teardown_state": if torn { json!("torn_down") } else { json!("live_or_pending") },
                        "workspace": lane_view })
            }
        }
    }
}

// --- aws GUARDED LIFECYCLE: the first ENTERPRISE hyperscaler lane. Not a marketplace, not a ---
// --- generic VM clone: IAM/SigV4 authority, region/AZ, VPC/security-group posture, EC2      ---
// --- lifecycle with REAL stop/start/restart semantics, EBS root volume posture. Provider-   ---
// --- native EC2/EBS/snapshot ids are EVIDENCE ONLY; daemon state roots are restore truth.   ---
const AWS_INSTANCE_KIND: &str = "aws-instances";

fn load_aws_instance(data_dir: &str, account_id: &str, env_ref: &str) -> Option<Value> {
    let mut mine: Vec<Value> = read_record_dir(data_dir, AWS_INSTANCE_KIND)
        .into_iter()
        .filter(|i| text(i, "account_id") == account_id && text(i, "environment_ref") == env_ref)
        .collect();
    mine.sort_by(|a, b| text(a, "record_id").cmp(text(b, "record_id")));
    mine.pop()
}

struct AwsProvider {
    account: Value,
}
impl AwsProvider {
    fn account_id(&self) -> &str {
        text(&self.account, "account_id")
    }
    fn mode(&self) -> String {
        vast_mode(&self.account)
    }
    fn instance(&self, data_dir: &str, env_ref: &str) -> Option<Value> {
        load_aws_instance(data_dir, self.account_id(), env_ref)
    }
    fn save_instance(&self, data_dir: &str, inst: &Value) -> Result<(), String> {
        let id = text(inst, "record_id").to_string();
        // W1.2 / MEF-GAP-008 — this record is the ONLY daemon handle to a JUST-CREATED (paid)
        // provider machine; a lost write orphans it from its own observe/stop/delete lane.
        persist_record(data_dir, AWS_INSTANCE_KIND, &id, inst)
            .map_err(|e| format!("provider_operation_persistence_failed — instance record {id} did not commit; the provider machine may exist with no daemon handle: {e}"))
    }
    fn push_event(inst: &mut Value, kind: &str, detail: String) {
        let mut events = inst
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        events.push(json!({ "at": iso_now(), "kind": kind, "detail": detail,
                            "execution_mode": inst["execution_mode"] }));
        inst["events"] = json!(events);
    }
    fn ssh_lane(&self, data_dir: &str, env_ref: &str) -> Result<(SshProvider, KeyGuard), String> {
        let inst = self
            .instance(data_dir, env_ref)
            .ok_or("aws_instance_absent — provision with the quote-gated create op first")?;
        if text(&inst, "status") == "torn_down" {
            return Err("aws_instance_terminated — this instance was already terminated".into());
        }
        let ssh = inst.get("ssh").cloned().unwrap_or(Value::Null);
        if text(&ssh, "host").is_empty() || text(&ssh, "key_file").is_empty() {
            return Err("aws_ssh_bootstrap_unknown — the instance has no proven ssh endpoint (it gains one only after boot polling proves readiness through a reachable network posture)".into());
        }
        let key = std::fs::read_to_string(text(&ssh, "key_file"))
            .map_err(|e| format!("aws_ssh_key_unreadable: {e}"))?;
        let dir = Path::new(data_dir).join("provider-ssh");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!(
            "aws-{}-{}.key",
            safe(self.account_id()),
            safe(env_ref)
        ));
        std::fs::write(&path, key).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        let synthetic = json!({
            "account_id": self.account_id(),
            "account_ref": self.account["account_ref"],
            "display_name": format!("{} (ec2 instance)", text(&self.account, "display_name")),
            "kind": "aws", "status": "verified",
            "endpoint": { "host": ssh["host"], "port": ssh.get("port").cloned().unwrap_or(json!(22)), "user": ssh["user"] },
        });
        Ok((
            SshProvider {
                account: synthetic,
                key_path: path.clone(),
            },
            KeyGuard(path),
        ))
    }
    fn network_reachable(inst: &Value) -> Result<(), String> {
        let public_ip = inst
            .pointer("/network_posture/public_ip")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let ingress = inst
            .pointer("/network_posture/ssh_ingress")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if !public_ip {
            return Err("aws_ssh_ingress_unreachable — private-only network posture (no public IP): SSH readiness cannot be proven; workspace ops fail closed, never fake-ready. Configure a public IP / reachable path or use a BYO node inside the VPC".into());
        }
        if !ingress {
            return Err("aws_ssh_ingress_unreachable — the security-group posture declares no SSH ingress: readiness cannot be proven; open ingress for the daemon's source or use a reachable path".into());
        }
        Ok(())
    }
}
impl EnvironmentProvider for AwsProvider {
    fn id(&self) -> &str {
        "aws-guarded"
    }
    fn capabilities(&self) -> Value {
        let mut caps = kind_capabilities("aws");
        caps["provider_spend_borne_by"] = json!("customer");
        caps["lifecycle"] = json!(
            "guarded_lifecycle — quote-gated create, wallet-gated mutations, terminate required"
        );
        caps["execution_mode"] = json!(self.mode());
        caps
    }
    fn status(&self) -> (&'static str, String) {
        match text(&self.account, "status") {
            "verified" => (
                "available",
                format!(
                    "guarded aws EC2 enterprise lifecycle ({} control plane)",
                    self.mode()
                ),
            ),
            "revoked" => ("revoked", "credential revoked".into()),
            _ => ("unverified", "bind + preflight the SigV4 credential".into()),
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
                return Err(format!("aws_instance_already_provisioned — {} is live for this environment; terminate it first", text(&existing, "instance_id")));
            }
        }
        let mode = self.mode();
        if mode == "live" {
            if load_account_credential(data_dir, self.account_id()).is_none() {
                return Err("aws_live_credentials_absent — live EC2 lifecycle needs a bound, resolvable SigV4 credential; live execution is never claimed unauthenticated".into());
            }
            return Err("aws_live_api_flow_not_implemented — the SigV4 EC2 RunInstances/DescribeInstances flow lands with the live harness cut; a fake instance is never minted".into());
        }
        if mode != "simulator" {
            return Err(
                "aws_lifecycle_mode_unset — set the account endpoint mode to simulator or live"
                    .into(),
            );
        }
        let sim_ssh = self
            .account
            .pointer("/endpoint/ssh")
            .cloned()
            .unwrap_or(Value::Null);
        if text(&sim_ssh, "host").is_empty() || text(&sim_ssh, "key_file").is_empty() {
            return Err("aws_simulator_ssh_missing — simulator mode needs endpoint.ssh {host, port, user, key_file}".into());
        }
        let stamp = nanos();
        let record_id = format!("awsinst_{stamp:x}");
        let instance_id = format!("i-sim{stamp:x}");
        let volume_id = format!("vol-sim{stamp:x}");
        let network = plan.get("network_posture").cloned()
            .unwrap_or_else(|| json!({ "posture_label": "default_vpc_simulator", "public_ip": true, "ssh_ingress": true }));
        let mut inst = json!({
            "schema_version": "ioi.hypervisor.aws-instance.v1",
            "record_id": record_id, "instance_id": instance_id,
            "account_id": self.account_id(), "account_ref": self.account["account_ref"],
            "environment_ref": env_ref, "status": "pending",
            "execution_mode": "simulated_control_plane",
            "region": plan["region"], "az": plan["az"], "instance_type": plan["instance_type"],
            "network_posture": network,
            "root_volume": { "volume_id": volume_id, "gb": plan["disk_gb"],
                             "delete_on_termination": true,
                             "note": "SIMULATED EBS root volume — native volume ids are evidence only, never restore truth" },
            "candidate_ref": plan["candidate_ref"], "quote_ref": plan["quote_ref"],
            "usd_per_hour": plan["usd_per_hour"], "max_hourly_usd": plan["max_hourly_usd"],
            "teardown_policy": plan["teardown_policy"],
            "sim_ssh": sim_ssh,
            "ssh": Value::Null,
            "events": [],
            "provider_native": { "instance_id": instance_id, "volume_id": volume_id,
                "note": "SIMULATED EC2/EBS ids — evidence only, never restore or billing truth; no real AWS instance exists" },
            "created_at": iso_now(),
        });
        let posture_label = inst
            .pointer("/network_posture/posture_label")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string();
        Self::push_event(&mut inst, "run_instances_accepted", format!("{} in {} ({posture_label}) — audit refs land with the live harness (CloudTrail is the customer's trail)", text(plan, "instance_type"), text(plan, "region")));
        self.save_instance(data_dir, &inst)?;
        Ok(json!({
            "provider_operation_ref": format!("provider-account://{}/op/create/{}", self.account_id(), safe(env_ref)),
            "instance": { "instance_id": instance_id, "status": "pending", "execution_mode": "simulated_control_plane" },
            "network_posture": inst["network_posture"],
            "root_volume": inst["root_volume"],
            "provider_native": inst["provider_native"],
            "ssh_ready": false,
            "live_provisioning_not_run": true,
            "note": "instance pending — run start to boot-poll; workspace ops fail closed (aws_ssh_bootstrap_unknown) until ssh readiness is PROVEN through a reachable network posture",
            "teardown_required": true,
        }))
    }
    fn start(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("aws_instance_absent")?;
        if text(&inst, "status") == "torn_down" {
            return Err("aws_instance_terminated".into());
        }
        let mut boot_evidence = Value::Null;
        if inst.get("ssh").map(Value::is_null).unwrap_or(true) {
            if text(&inst, "execution_mode") == "live" {
                return Err(
                    "aws_live_api_flow_not_implemented — no live instance exists to boot-poll"
                        .into(),
                );
            }
            // Enterprise network honesty: readiness is provable ONLY through a reachable
            // posture — private-only / no-ingress fails CLOSED, never fake-ready.
            Self::network_reachable(&inst)?;
            let sim_ssh = inst.get("sim_ssh").cloned().unwrap_or(Value::Null);
            boot_evidence = json!({ "polled_attempts": 1, "state": "running",
                "public_ip": sim_ssh["host"], "ssh_port": sim_ssh.get("port").cloned().unwrap_or(json!(22)),
                "posture": inst["network_posture"], "proven_at": iso_now(),
                "note": "simulated boot resolved through the declared reachable posture" });
            inst["ssh"] = sim_ssh;
            inst["ssh_ready_evidence"] = boot_evidence.clone();
            Self::push_event(
                &mut inst,
                "boot_proven",
                "ssh readiness proven through the reachable network posture".into(),
            );
            self.save_instance(data_dir, &inst)?;
        }
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        if inst.get("workspace_bootstrapped").and_then(Value::as_bool) != Some(true) {
            lane.create(data_dir, env_ref, &json!({}))?;
            inst["workspace_bootstrapped"] = json!(true);
        }
        lane.start(data_dir, env_ref)?;
        let was_stopped = text(&inst, "status") == "stopped";
        inst["status"] = json!("running");
        Self::push_event(
            &mut inst,
            "instance_started",
            if was_stopped {
                "started from stopped — instance-hours resume; a stop/start cycle can change the public IP (an EIP pins it); the simulator retains the fixture endpoint".into()
            } else {
                "workspace running".into()
            },
        );
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/start/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "status": "running", "ssh_ready": true,
                   "boot_evidence": boot_evidence }),
        )
    }
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.workrun(data_dir, env_ref, command)
    }
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        // REAL EC2 stop semantics: instance-hours stop accruing; EBS storage does not.
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("aws_instance_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let stopped = lane.stop(data_dir, env_ref)?;
        inst["status"] = json!("stopped");
        Self::push_event(
            &mut inst,
            "instance_stopped",
            "instance-hours stop accruing; EBS root volume storage keeps billing until terminate"
                .into(),
        );
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/stop/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "status": "stopped",
                   "spend_note": "EC2 stop halts instance-hour billing; the EBS root volume keeps billing until terminate — the exposure stays open until teardown",
                   "lane": stopped }),
        )
    }
    fn restart(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        // EC2 reboot: in-place restart, endpoint retained (unlike a stop/start cycle).
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("aws_instance_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let _ = lane.stop(data_dir, env_ref);
        lane.start(data_dir, env_ref)?;
        inst["status"] = json!("running");
        Self::push_event(&mut inst, "instance_rebooted", "in-place reboot — endpoint retained (a stop/start cycle, by contrast, can change the public IP)".into());
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/restart/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "status": "running",
                   "note": "EC2 reboot semantics — endpoint retained; instance-hours keep accruing" }),
        )
    }
    fn snapshot(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("aws_instance_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let mut evidence = lane.snapshot(data_dir, env_ref)?;
        // An EBS-style native snapshot id rides along as EVIDENCE ONLY — the daemon-admitted
        // sha256 state root above is the restore truth.
        let native = json!({
            "snapshot_id": format!("snap-sim{:x}", nanos()),
            "volume_id": inst.pointer("/root_volume/volume_id").cloned().unwrap_or(Value::Null),
            "note": "SIMULATED EBS snapshot id — evidence only, NEVER restore truth; restores admit by the daemon state_root",
        });
        if let Some(o) = evidence.as_object_mut() {
            o.insert("provider_native_snapshot".into(), native.clone());
        }
        inst["last_native_snapshot"] = native;
        Self::push_event(
            &mut inst,
            "snapshot_taken",
            "daemon-custody snapshot admitted; EBS-style native id recorded as evidence".into(),
        );
        self.save_instance(data_dir, &inst)?;
        Ok(evidence)
    }
    fn restore(&self, data_dir: &str, env_ref: &str, material_ref: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.restore(data_dir, env_ref, material_ref)
    }
    fn inject_outage(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("aws_outage_injection_not_supported — terminating a paid instance is not a safely representable outage; use the loopback/ssh conformance lanes".into())
    }
    fn recover(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("aws_recover_not_supported — recovery is re-launch + restore from daemon/storage custody; run create + restore explicitly".into())
    }
    fn delete(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut inst = self
            .instance(data_dir, env_ref)
            .ok_or("aws_instance_absent")?;
        let remote_cleanup = match self.ssh_lane(data_dir, env_ref) {
            Ok((lane, _guard)) => lane
                .delete(data_dir, env_ref)
                .map(|e| e["cleanup_verified"].clone())
                .unwrap_or(json!("unreachable")),
            Err(e) => json!(format!("skipped: {e}")),
        };
        let native_teardown = if text(&inst, "execution_mode") == "live" {
            json!({ "destroyed": false, "error": "aws_live_api_flow_not_implemented", "warning": "TEARDOWN MAY BE INCOMPLETE — no live TerminateInstances call exists yet" })
        } else if self
            .account
            .pointer("/endpoint/simulate_teardown_failure")
            .and_then(Value::as_bool)
            == Some(true)
        {
            json!({ "destroyed": false, "error": "SIMULATED terminate failure (endpoint.simulate_teardown_failure)", "warning": "TEARDOWN MAY BE INCOMPLETE — verify the EC2 console (instance-hours and EBS may still accrue)" })
        } else {
            json!({ "destroyed": true, "note": "simulated control plane — instance terminated, EBS root volume deleted on termination; no real AWS instance existed" })
        };
        // CARVE-OUT: record the EXACT deletion outcome. `teardown_state` was unconditionally
        // "torn_down" and `cleanup_verified` unconditionally true, even when the provider-native
        // destroy reported `destroyed: false`. Non-succeeded outcomes now open a durable obligation.
        let (teardown_state, cleanup_verified, deletion_disposition) =
            provider_teardown_disposition(
                &format!(
                    "provider-account://{}/resource/{}",
                    self.account_id(),
                    safe(env_ref)
                ),
                &native_teardown,
                &remote_cleanup,
            );
        inst["status"] = json!(teardown_state);
        inst["torn_down_at"] = json!(iso_now());
        inst["deletion_disposition"] = deletion_disposition.clone();
        Self::push_event(
            &mut inst,
            "instance_terminated",
            "terminate always — root volume deleted on termination per posture".into(),
        );
        self.save_instance(data_dir, &inst)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/delete/{}", self.account_id(), safe(env_ref)),
                   "instance_id": inst["instance_id"], "teardown_state": teardown_state,
                   "remote_workspace_cleanup": remote_cleanup, "native_teardown": native_teardown,
                   "cleanup_verified": cleanup_verified, "deletion_disposition": deletion_disposition }),
        )
    }
    fn events(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let inst = self
            .instance(data_dir, env_ref)
            .ok_or("aws_instance_absent")?;
        Ok(json!({
            "instance_id": inst["instance_id"],
            "events": inst.get("events").cloned().unwrap_or(json!([])),
            "execution_mode": inst["execution_mode"],
            "basis": "daemon-recorded instance lifecycle events (simulated control plane labelled); CloudTrail-style audit refs land with the live harness — the audit trail is the customer's",
        }))
    }
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value {
        match self.instance(data_dir, env_ref) {
            None => {
                json!({ "provider": self.id(), "environment_ref": env_ref, "instance": Value::Null, "status": "absent" })
            }
            Some(inst) => {
                let torn = text(&inst, "status") == "torn_down";
                let boot_pending = inst.get("ssh").map(Value::is_null).unwrap_or(true) && !torn;
                let lane_view = if torn {
                    Value::Null
                } else if boot_pending {
                    json!({ "boot": "pending — run start to poll until ssh readiness is proven through a reachable posture" })
                } else {
                    match self.ssh_lane(data_dir, env_ref) {
                        Ok((lane, _guard)) => lane.observe(data_dir, env_ref),
                        Err(e) => json!({ "error": e }),
                    }
                };
                json!({ "provider": self.id(), "environment_ref": env_ref,
                        "instance_id": inst["instance_id"], "status": inst["status"],
                        "execution_mode": inst["execution_mode"],
                        "region": inst["region"], "az": inst["az"], "instance_type": inst["instance_type"],
                        "network_posture": inst["network_posture"], "root_volume": inst["root_volume"],
                        "events_tail": inst.get("events").and_then(Value::as_array).map(|e| e.iter().rev().take(5).cloned().collect::<Vec<_>>()).unwrap_or_default(),
                        "provider_native": inst["provider_native"],
                        "teardown_state": if torn { json!("torn_down") } else { json!("live_or_pending") },
                        "workspace": lane_view })
            }
        }
    }
}

// --- akash GUARDED LIFECYCLE: the first DePIN compute/GPU lane. NOT a generic VM adapter —  ---
// --- Akash semantics preserved: deployment intent → SDL manifest → provider BIDS → LEASE →  ---
// --- lease-assigned endpoints → logs/events → close → REDEPLOY. Provider-native ids         ---
// --- (dseq/bid/lease) are EVIDENCE ONLY; daemon custody state roots remain restore truth.   ---
const AKASH_DEPLOYMENT_KIND: &str = "akash-deployments";
const AKASH_BID_KIND: &str = "akash-bids";
const AKASH_LEASE_KIND: &str = "akash-leases";
const AKASH_ENDPOINT_KIND: &str = "akash-endpoints";
const AKASH_REDEPLOY_KIND: &str = "akash-redeploy-plans";
/// Per-deploy deposit ceiling for the managed Console API live path — defense
/// in depth beside the wallet-gated CapabilityLease. A single live create may
/// fund at most this many dollars of escrow; larger deposits are refused.
const AKASH_MAX_DEPLOY_DEPOSIT_USD: f64 = 5.0;

/// Canonical SDL manifest from the validated bid candidate (+ body overrides). The SDL declares
/// an ssh service — exec/custody ride it (canon: SSH only when the deployment explicitly
/// provides it; provider-native lease-shell exec lands with the live harness).
fn akash_build_sdl(candidate: &Value, body: &Value) -> Value {
    let image = body
        .get("image")
        .and_then(Value::as_str)
        .unwrap_or("ubuntu:24.04");
    let resources = candidate.get("resources").cloned().unwrap_or(json!({}));
    let persistent = candidate
        .pointer("/storage/persistent_storage")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    json!({
        "version": "2.0",
        "services": {
            "workspace": {
                "image": image,
                "expose": [ { "port": 22, "as": 22, "proto": "tcp", "service": "ssh", "to": [{ "global": true }] } ],
                "resources": {
                    "cpu_milli": resources.get("cpu_milli").cloned().unwrap_or(Value::Null),
                    "memory_gb": resources.get("memory_gb").cloned().unwrap_or(Value::Null),
                    "storage": { "size_gb": resources.get("storage_gb").cloned().unwrap_or(Value::Null), "persistent": persistent },
                    "gpu": candidate.get("gpu").cloned().unwrap_or(Value::Null),
                },
            }
        },
        "note": "SDL declares an ssh service — exec/custody ride it; persistent storage is deployment posture, NEVER restore truth",
    })
}

fn load_akash_deployment(data_dir: &str, account_id: &str, env_ref: &str) -> Option<Value> {
    let mut mine: Vec<Value> = read_record_dir(data_dir, AKASH_DEPLOYMENT_KIND)
        .into_iter()
        .filter(|d| text(d, "account_id") == account_id && text(d, "environment_ref") == env_ref)
        .collect();
    mine.sort_by(|a, b| text(a, "record_id").cmp(text(b, "record_id")));
    mine.pop()
}

struct AkashProvider {
    account: Value,
}
impl AkashProvider {
    fn account_id(&self) -> &str {
        text(&self.account, "account_id")
    }
    fn mode(&self) -> String {
        vast_mode(&self.account)
    }
    fn deployment(&self, data_dir: &str, env_ref: &str) -> Option<Value> {
        load_akash_deployment(data_dir, self.account_id(), env_ref)
    }
    fn save_deployment(&self, data_dir: &str, dep: &Value) -> Result<(), String> {
        let id = text(dep, "record_id").to_string();
        // W1.2 / MEF-GAP-008 — the deployment record is the ONLY daemon handle to a just-provisioned
        // (customer-borne paid, in live mode) DePIN deployment; a lost write orphans it from its own
        // start/stop/close lane and from spend reconciliation.
        persist_record(data_dir, AKASH_DEPLOYMENT_KIND, &id, dep)
            .map_err(|e| format!("provider_operation_persistence_failed — deployment record {id} did not commit; the deployment/lease may exist with no daemon handle: {e}"))
    }
    fn push_event(dep: &mut Value, kind: &str, detail: String) {
        let mut events = dep
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        events.push(json!({ "at": iso_now(), "kind": kind, "detail": detail,
                            "execution_mode": dep["execution_mode"] }));
        dep["events"] = json!(events);
    }
    fn lease_for(&self, data_dir: &str, deployment_ref: &str) -> Option<Value> {
        read_record_dir(data_dir, AKASH_LEASE_KIND)
            .into_iter()
            .find(|l| text(l, "deployment_ref") == deployment_ref)
    }
    fn save_lease(&self, data_dir: &str, lease: &Value) -> Result<(), String> {
        let id = text(lease, "record_id").to_string();
        // W1.2 / MEF-GAP-008 — the lease record tracks customer-borne spend that accrues until the
        // lease is closed; a lost write hides an accruing lease from spend reconciliation.
        persist_record(data_dir, AKASH_LEASE_KIND, &id, lease)
            .map_err(|e| format!("provider_spend_exposure_persistence_failed — lease record {id} did not commit; an accruing lease may be invisible to spend reconciliation: {e}"))
    }
    fn live_api_key(&self, data_dir: &str) -> Result<String, String> {
        let cred = load_account_credential(data_dir, self.account_id()).ok_or(
            "akash_live_credentials_absent — provider readback needs the bound credential",
        )?;
        cred["sealed_token"]
            .as_str()
            .and_then(open_scm_token)
            .ok_or_else(|| {
                "akash_live_credential_unresolvable — the sealed Console key did not decrypt"
                    .to_string()
            })
    }
    fn console_request(
        request: ioi_drivers::provisioning::akash_console::ConsoleRequest,
    ) -> Result<(u16, Value), String> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                use ioi_drivers::provisioning::akash_console as ac;
                let (header_name, header_value) = request.header();
                let url = format!("{}{}", ac::AKASH_CONSOLE_BASE_URL, request.path);
                let client = reqwest::Client::new();
                let builder = match request.method {
                    ac::ConsoleMethod::Get => client.get(&url),
                    ac::ConsoleMethod::Post => client.post(&url),
                    ac::ConsoleMethod::Put => client.put(&url),
                    ac::ConsoleMethod::Delete => client.delete(&url),
                }
                .header(header_name, header_value)
                .timeout(std::time::Duration::from_secs(60));
                let builder = if let Some(body) = &request.body {
                    builder.json(body)
                } else {
                    builder
                };
                let response = builder
                    .send()
                    .await
                    .map_err(|error| format!("akash_console_http_failed: {error}"))?;
                let status = response.status().as_u16();
                let body = response.json().await.unwrap_or(Value::Null);
                Ok((status, body))
            })
        })
    }
    fn live_detail(&self, data_dir: &str, dseq: &str) -> Result<Value, String> {
        use ioi_drivers::provisioning::akash_console as ac;
        let api_key = self.live_api_key(data_dir)?;
        let (status, detail) = Self::console_request(ac::get_deployment(&api_key, dseq))?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "akash_console_get_deployment_failed: http {status}"
            ));
        }
        Ok(detail)
    }
    fn settle_from_detail(
        &self,
        data_dir: &str,
        dep: &mut Value,
        detail: &Value,
    ) -> Result<Value, String> {
        use ioi_drivers::provisioning::akash_console as ac;
        let deposit_usd = dep
            .get("deposit_usd")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let settlement = ac::parse_settlement_readback(detail, deposit_usd);
        dep["provider_native_settlement"] = settlement.clone();
        dep["settlement_state"] = settlement["settlement_state"].clone();
        dep["provider_readback_hash"] =
            json!(sha256_bytes(&serde_jcs::to_vec(detail).unwrap_or_default()));
        dep["last_reconciled_at"] = json!(iso_now());
        if settlement["provider_terminal"] == json!(true) {
            dep["state"] = settlement["settlement_state"].clone();
            dep["status"] = json!("torn_down");
            dep["teardown_state"] = json!("torn_down");
            Self::push_event(
                dep,
                text(&settlement, "settlement_state"),
                "provider-native deployment, escrow and lease readback reached terminal settlement"
                    .into(),
            );
            for mut lease in read_record_dir(data_dir, AKASH_LEASE_KIND) {
                if lease.get("deployment_ref") == dep.get("deployment_ref")
                    && text(&lease, "state") != "closed"
                {
                    lease["state"] = json!("closed");
                    lease["closed_at"] = json!(iso_now());
                    lease["closure_basis"] = json!(
                        "provider-native terminal deployment, escrow and zero-active-lease readback"
                    );
                    self.save_lease(data_dir, &lease)?;
                }
            }
        } else {
            dep["state"] = json!("reconciliation_required");
            dep["status"] = json!("reconciliation_required");
            Self::push_event(
                dep,
                "reconciliation_required",
                "provider-native close/escrow readback is not terminal".into(),
            );
        }
        self.save_deployment(data_dir, dep)?;

        // A one-call capability lease cannot remain semantically active after its only call was
        // consumed. Reconciliation closes that stale local projection without widening authority.
        for mut lease in read_record_dir(data_dir, "capability-leases") {
            let binds_environment = lease
                .get("resource_refs")
                .and_then(Value::as_array)
                .map(|refs| {
                    refs.iter()
                        .any(|value| value.as_str() == Some(text(dep, "environment_ref")))
                })
                .unwrap_or(false);
            if binds_environment
                && lease.get("remaining_calls").and_then(Value::as_u64) == Some(0)
                && text(&lease, "state") == "active"
            {
                lease["state"] = json!("exhausted");
                lease["exhausted_at"] = json!(iso_now());
                let lease_id = text(&lease, "lease_id").to_string();
                persist_record(data_dir, "capability-leases", &lease_id, &lease).map_err(
                    |error| format!("capability_lease_terminal_state_persistence_failed: {error}"),
                )?;
            }
        }
        Ok(settlement)
    }
    /// Exec/custody lane: available ONLY because the deployment's SDL declares an ssh service
    /// and ONLY after endpoint readiness is proven. Never assumed.
    fn ssh_lane(&self, data_dir: &str, env_ref: &str) -> Result<(SshProvider, KeyGuard), String> {
        let dep = self
            .deployment(data_dir, env_ref)
            .ok_or("akash_deployment_absent — provision with the quote-gated create op first")?;
        if text(&dep, "status") == "torn_down" {
            return Err("akash_deployment_torn_down — this deployment was already closed".into());
        }
        let ssh_declared = dep
            .pointer("/sdl/services/workspace/expose")
            .and_then(Value::as_array)
            .map(|e| {
                e.iter()
                    .any(|x| x.get("service").and_then(Value::as_str) == Some("ssh"))
            })
            .unwrap_or(false);
        if !ssh_declared {
            return Err("akash_exec_lane_unavailable — this deployment's SDL does not expose an ssh service; provider-native lease-shell exec lands with the live harness".into());
        }
        let ssh = dep.get("ssh").cloned().unwrap_or(Value::Null);
        if text(&ssh, "host").is_empty() || text(&ssh, "key_file").is_empty() {
            return Err("akash_endpoint_unready — the lease has no ready endpoint yet; run start to wait for endpoint readiness (endpoints are evidence, never assumed)".into());
        }
        let key = std::fs::read_to_string(text(&ssh, "key_file"))
            .map_err(|e| format!("akash_ssh_key_unreadable: {e}"))?;
        let dir = Path::new(data_dir).join("provider-ssh");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!(
            "akash-{}-{}.key",
            safe(self.account_id()),
            safe(env_ref)
        ));
        std::fs::write(&path, key).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        let synthetic = json!({
            "account_id": self.account_id(),
            "account_ref": self.account["account_ref"],
            "display_name": format!("{} (akash lease)", text(&self.account, "display_name")),
            "kind": "akash", "status": "verified",
            "endpoint": { "host": ssh["host"], "port": ssh.get("port").cloned().unwrap_or(json!(22)), "user": ssh["user"] },
        });
        Ok((
            SshProvider {
                account: synthetic,
                key_path: path.clone(),
            },
            KeyGuard(path),
        ))
    }
    /// Shared provisioning body for create AND redeploy (redeploy passes lineage).
    fn provision(
        &self,
        data_dir: &str,
        env_ref: &str,
        plan: &Value,
        redeployed_from: Option<&Value>,
    ) -> Result<Value, String> {
        let mode = self.mode();
        if mode == "live" {
            // M2b — REAL managed Console API deploy. Reaching here already means
            // the wallet-gated CapabilityLease authorized this op (create is only
            // dispatched after authorize_capability_lease succeeds), so this is an
            // authorized, customer-borne spend. Deposit is additionally capped.
            let Some(cred) = load_account_credential(data_dir, self.account_id()) else {
                return Err("akash_live_credentials_absent — live deployments need a bound, resolvable credential; live execution is never claimed unauthenticated".into());
            };
            let api_key = cred["sealed_token"]
                .as_str()
                .and_then(open_scm_token)
                .ok_or(
                    "akash_live_credential_unresolvable — the sealed Console key did not decrypt",
                )?;

            // C2 and the wallet grant bind the exact SDL template and use-only connector refs.
            // Resolve any sealed registry/result credentials only here, at the provider execution
            // boundary, after intent commitment. The expanded SDL is never journaled or receipted.
            let sdl_template = plan
                .get("sdl_yaml")
                .and_then(Value::as_str)
                .ok_or("akash_live_sdl_required — provide plan.sdl_yaml (the Akash SDL manifest to deploy)")?
                .to_string();
            let sdl_yaml = materialize_akash_sdl(data_dir, plan, &sdl_template)?;
            let deposit = plan
                .get("deposit_usd")
                .and_then(Value::as_f64)
                .unwrap_or(1.0);
            if !(deposit > 0.0 && deposit <= AKASH_MAX_DEPLOY_DEPOSIT_USD) {
                return Err(format!(
                    "akash_deposit_out_of_bounds — deposit ${deposit} must be > 0 and ≤ ${AKASH_MAX_DEPLOY_DEPOSIT_USD} (per-deploy cap)"
                ));
            }

            // C6 provider-pin: the caller may pin the provider address (the one the
            // wallet challenge hashed into the approval). If set, the daemon deploys
            // on THAT provider or refuses — it never falls through to the cheapest.
            let pinned_provider = text(plan, "provider_address").to_string();
            let approved_ceiling = plan
                .get("ceiling_amount")
                .and_then(Value::as_str)
                .and_then(|amount| amount.parse::<f64>().ok())
                .zip(plan.get("ceiling_denom").and_then(Value::as_str));

            // Run the async create→bid→lease→status flow from this sync body,
            // mirroring the live Vast path.
            let live: Value = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    use ioi_drivers::provisioning::akash_console as ac;
                    let client = reqwest::Client::new();
                    let send = |req: ac::ConsoleRequest| {
                        let client = client.clone();
                        async move {
                            let (hn, hv) = req.header();
                            let url = format!("{}{}", ac::AKASH_CONSOLE_BASE_URL, req.path);
                            let rb = match req.method {
                                ac::ConsoleMethod::Get => client.get(&url),
                                ac::ConsoleMethod::Post => client.post(&url),
                                ac::ConsoleMethod::Put => client.put(&url),
                                ac::ConsoleMethod::Delete => client.delete(&url),
                            }
                            .header(hn, hv)
                            .timeout(std::time::Duration::from_secs(60));
                            let rb = if let Some(b) = &req.body {
                                rb.json(b)
                            } else {
                                rb
                            };
                            let resp = rb
                                .send()
                                .await
                                .map_err(|e| format!("akash_console_http_failed: {e}"))?;
                            let code = resp.status().as_u16();
                            let body: Value = resp.json().await.unwrap_or(Value::Null);
                            Ok::<(u16, Value), String>((code, body))
                        }
                    };

                    // 1. create deployment (funds the escrow — the spend point)
                    let (code, cd) =
                        send(ac::create_deployment(&api_key, &sdl_yaml, deposit)).await?;
                    if !(200..300).contains(&code) {
                        return Err(format!("akash_console_create_failed: http {code} {cd}"));
                    }
                    let dseq = ac::parse_created_dseq(&cd)
                        .ok_or("akash_console_create_no_dseq — create response had no data.dseq")?;
                    // The escrow is funded at this point. Persist that fact immediately, before
                    // waiting for bids, so a daemon restart has a provider-native dseq to close
                    // and reconcile. Close acceptance and settlement are later, distinct states.
                    let intent_id = format!("akdep_{}", safe(&dseq));
                    let intent_ref = format!("akash-deployment://{intent_id}");
                    let mut intent = json!({
                        "schema_version": "ioi.hypervisor.akash-deployment.v1",
                        "record_id": intent_id,
                        "deployment_ref": intent_ref,
                        "dseq": dseq,
                        "account_id": self.account_id(),
                        "account_ref": self.account["account_ref"],
                        "environment_ref": env_ref,
                        "status": "deposit_funded",
                        "state": "deposit_funded",
                        "settlement_state": "open",
                        "execution_mode": "live_console_api",
                        "deposit_usd": deposit,
                        "sdl_yaml_bytes": sdl_yaml.len(),
                        "events": [],
                        "created_at": iso_now(),
                    });
                    Self::push_event(
                        &mut intent,
                        "deposit_funded",
                        format!("Console funded deployment escrow for dseq={dseq}"),
                    );
                    persist_record(data_dir, AKASH_DEPLOYMENT_KIND, &intent_id, &intent)
                        .map_err(|error| format!(
                            "akash_deposit_funded_persistence_failed — dseq={dseq} requires immediate provider reconciliation: {error}"
                        ))?;
                    let manifest = ac::parse_created_manifest(&cd).ok_or(
                        "akash_console_create_no_manifest — create response had no data.manifest",
                    )?;

                    // 2. poll bids (up to 10× at 6s). Pinned → select THAT provider's
                    //    bid (refuse if it never bids); unpinned → the cheapest.
                    let mut selected = None;
                    for _ in 0..10 {
                        let (bc, bl) = send(ac::list_bids(&api_key, &dseq)).await?;
                        if (200..300).contains(&bc) {
                            let picked = if pinned_provider.is_empty() {
                                if let Some((ceiling_amount, ceiling_denom)) = approved_ceiling {
                                    ac::parse_cheapest_qualified_bid(
                                        &bl,
                                        ceiling_denom,
                                        ceiling_amount,
                                    )
                                } else {
                                    ac::parse_cheapest_bid(&bl)
                                }
                            } else {
                                approved_ceiling.and_then(|(ceiling_amount, ceiling_denom)| {
                                    ac::parse_pinned_qualified_bid(
                                        &bl,
                                        &pinned_provider,
                                        ceiling_denom,
                                        ceiling_amount,
                                    )
                                })
                            };
                            if let Some(b) = picked {
                                selected = Some(b);
                                break;
                            }
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
                    }
                    let bid = if let Some(bid) = selected {
                        bid
                    } else {
                        let reason = if pinned_provider.is_empty() {
                            "akash_no_qualified_bid — no provider bid within the polling window"
                                .to_string()
                        } else {
                            format!("akash_pinned_provider_no_qualified_bid — the wallet-approved provider '{pinned_provider}' returned no bid in the exact approved denomination and ceiling within the polling window")
                        };
                        let (close_http, close_body) =
                            send(ac::close_deployment(&api_key, &dseq)).await?;
                        intent["close_http"] = json!(close_http);
                        intent["close_response_hash"] = json!(sha256_bytes(
                            &serde_jcs::to_vec(&close_body).unwrap_or_default()
                        ));
                        if !(200..300).contains(&close_http) {
                            intent["state"] = json!("reconciliation_required");
                            intent["status"] = json!("reconciliation_required");
                            intent["settlement_state"] = json!("reconciliation_required");
                            Self::push_event(
                                &mut intent,
                                "reconciliation_required",
                                format!("no-bid compensation close returned HTTP {close_http}"),
                            );
                            persist_record(data_dir, AKASH_DEPLOYMENT_KIND, &intent_id, &intent)
                                .map_err(|error| format!("akash_compensation_persistence_failed: {error}"))?;
                            return Err(format!(
                                "akash_stage_b_reconciliation_required: {reason} | close_http={close_http} dseq={dseq}"
                            ));
                        }
                        intent["state"] = json!("deployment_close_accepted");
                        intent["status"] = json!("deployment_close_accepted");
                        intent["settlement_state"] = json!("refund_pending");
                        intent["close_accepted_at"] = json!(iso_now());
                        Self::push_event(
                            &mut intent,
                            "deployment_close_accepted",
                            "no-bid compensation close accepted; awaiting provider settlement readback"
                                .into(),
                        );
                        persist_record(data_dir, AKASH_DEPLOYMENT_KIND, &intent_id, &intent)
                            .map_err(|error| format!("akash_close_acceptance_persistence_failed: {error}"))?;

                        let (read_http, detail) = send(ac::get_deployment(&api_key, &dseq)).await?;
                        if (200..300).contains(&read_http) {
                            let settlement = ac::parse_settlement_readback(&detail, deposit);
                            intent["provider_native_settlement"] = settlement.clone();
                            intent["provider_readback_hash"] = json!(sha256_bytes(
                                &serde_jcs::to_vec(&detail).unwrap_or_default()
                            ));
                            intent["settlement_state"] = settlement["settlement_state"].clone();
                            intent["state"] = settlement["settlement_state"].clone();
                            if settlement["provider_terminal"] == json!(true) {
                                intent["status"] = json!("torn_down");
                                intent["teardown_state"] = json!("torn_down");
                            } else {
                                intent["status"] = json!("reconciliation_required");
                                intent["state"] = json!("reconciliation_required");
                            }
                        } else {
                            intent["status"] = json!("reconciliation_required");
                            intent["state"] = json!("reconciliation_required");
                            intent["settlement_state"] = json!("reconciliation_required");
                        }
                        let settlement_event = text(&intent, "settlement_state").to_string();
                        Self::push_event(
                            &mut intent,
                            &settlement_event,
                            "no-bid compensation reconciled from provider-native deployment and escrow readback"
                                .into(),
                        );
                        persist_record(data_dir, AKASH_DEPLOYMENT_KIND, &intent_id, &intent)
                            .map_err(|error| format!("akash_settlement_persistence_failed: {error}"))?;
                        return Err(format!(
                            "akash_stage_b_refused ({}): {reason} | close_http={close_http} dseq={dseq}",
                            text(&intent, "settlement_state")
                        ));
                    };
                    // Prove selected == pinned (the pin selector guarantees it; assert the invariant
                    // so a future selector change cannot silently deploy on an unapproved provider).
                    if !pinned_provider.is_empty() && bid.provider != pinned_provider {
                        return Err(format!(
                            "akash_pin_mismatch — selected provider '{}' != wallet-approved '{pinned_provider}'",
                            bid.provider
                        ));
                    }

                    // 3. create the lease against the selected bid
                    let (lc, ll) = send(ac::create_lease(&api_key, &manifest, &dseq, &bid)).await?;
                    if !(200..300).contains(&lc) {
                        return Err(format!("akash_console_lease_failed: http {lc} {ll}"));
                    }

                    // 4. status snapshot
                    let (_sc, sd) = send(ac::get_deployment(&api_key, &dseq)).await?;
                    let dep_state =
                        ac::parse_deployment_state(&sd).unwrap_or_else(|| "unknown".into());

                    Ok::<Value, String>(json!({
                        "dseq": dseq, "provider": bid.provider, "gseq": bid.gseq,
                        "oseq": bid.oseq, "deployment_state": dep_state, "deposit_usd": deposit,
                    }))
                })
            })?;

            // Persist REAL records — same custody discipline as the simulator path,
            // execution_mode = live_console_api, provider-native ids as evidence.
            let stamp = nanos();
            let record_id = format!("akdep_{}", safe(text(&live, "dseq")));
            let deployment_ref = format!("akash-deployment://{record_id}");
            let real_dseq = text(&live, "dseq").to_string();
            let provider_address = text(&live, "provider").to_string();
            let bid_id = format!("akbid_{stamp:x}");
            let bid_rec = json!({
                "schema_version": "ioi.hypervisor.akash-bid.v1",
                "record_id": bid_id, "bid_ref": format!("akash-bid://{bid_id}"),
                "deployment_ref": deployment_ref, "environment_ref": env_ref,
                "account_ref": self.account["account_ref"], "provider_address": provider_address,
                "gseq": live["gseq"], "oseq": live["oseq"], "state": "selected",
                "execution_mode": "live_console_api",
                "note": "REAL managed-Console bid — provider-native ids are evidence, never authority",
                "at": iso_now(),
            });
            persist_record(data_dir, AKASH_BID_KIND, &bid_id, &bid_rec)
                .map_err(|e| format!("provider_operation_persistence_failed — akash bid record {bid_id} did not commit: {e}"))?;
            let lease_id = format!("aklease_{stamp:x}");
            let lease_rec = json!({
                "schema_version": "ioi.hypervisor.akash-lease.v1",
                "record_id": lease_id, "lease_ref": format!("akash-lease://{lease_id}"),
                "deployment_ref": deployment_ref, "bid_ref": bid_rec["bid_ref"],
                "environment_ref": env_ref, "account_ref": self.account["account_ref"],
                "provider_address": provider_address, "state": "open",
                "execution_mode": "live_console_api", "deposit_usd": live["deposit_usd"],
                "spend_note": "REAL customer-borne lease spend accrues (deposit-funded escrow) until the lease closes",
                "opened_at": iso_now(),
            });
            persist_record(data_dir, AKASH_LEASE_KIND, &lease_id, &lease_rec)
                .map_err(|e| format!("provider_spend_exposure_persistence_failed — akash lease record {lease_id} (REAL accruing spend) did not commit: {e}"))?;
            let mut dep = json!({
                "schema_version": "ioi.hypervisor.akash-deployment.v1",
                "record_id": record_id, "deployment_ref": deployment_ref, "dseq": real_dseq,
                "account_id": self.account_id(), "account_ref": self.account["account_ref"],
                "environment_ref": env_ref, "status": "deployment_created",
                "state": "lease_open", "settlement_state": "open",
                "execution_mode": "live_console_api", "sdl_yaml_bytes": sdl_yaml.len(),
                "sdl_template_hash": plan.get("sdl_hash").cloned().unwrap_or(Value::Null),
                "result_credential_ref": plan.get("result_credential_ref").cloned().unwrap_or(Value::Null),
                "result_tls_server_certificate_sha256": plan.get("result_tls_server_certificate_sha256").cloned().unwrap_or(Value::Null),
                "campaign_id": plan.get("campaign_id").cloned().unwrap_or(Value::Null),
                "benchmark_source_commit": plan.get("benchmark_source_commit").cloned().unwrap_or(Value::Null),
                "image_digest": plan.get("image_digest").cloned().unwrap_or(Value::Null),
                "image_build_identity_sha256": plan.get("image_build_identity_sha256").cloned().unwrap_or(Value::Null),
                "provider_preflight_sha256": plan.get("provider_preflight_sha256").cloned().unwrap_or(Value::Null),
                "benchmark_protocol_version": plan.get("benchmark_protocol_version").cloned().unwrap_or(Value::Null),
                "result_schema_version": plan.get("result_schema_version").cloned().unwrap_or(Value::Null),
                "benchmark_warmups": plan.get("benchmark_warmups").cloned().unwrap_or(Value::Null),
                "benchmark_repeats": plan.get("benchmark_repeats").cloned().unwrap_or(Value::Null),
                "endpoint_discovered": false, "endpoint_ready": false,
                "workload_readiness_proven": false, "workload_result_retrieved": false,
                "desired_replicas": 0, "ready_replicas": 0,
                "bid_ref": bid_rec["bid_ref"], "lease_ref": lease_rec["lease_ref"],
                "deposit_usd": live["deposit_usd"], "deployment_state": live["deployment_state"],
                "provider_native": { "dseq": real_dseq, "provider": provider_address, "note": "REAL managed-Console deployment — dseq/provider are provider-native evidence; daemon custody state roots remain restore truth" },
                "redeployed_from": redeployed_from.cloned().unwrap_or(Value::Null),
                "events": [], "created_at": iso_now(),
            });
            Self::push_event(
                &mut dep,
                "deployment_created",
                format!("REAL Console deployment dseq={real_dseq}"),
            );
            Self::push_event(
                &mut dep,
                "bid_selected",
                format!("provider {provider_address} selected"),
            );
            Self::push_event(
                &mut dep,
                "lease_opened",
                format!(
                    "lease open, ${} deposit escrow — customer-borne until close",
                    text(&live, "deposit_usd")
                ),
            );
            if let Some(old) = redeployed_from {
                Self::push_event(
                    &mut dep,
                    "redeployed_from",
                    format!("fresh deployment replacing {}", old.as_str().unwrap_or("?")),
                );
            }
            self.save_deployment(data_dir, &dep)?;
            return Ok(json!({
                "provider_operation_ref": format!("provider-account://{}/op/create/{}", self.account_id(), safe(env_ref)),
                "deployment": { "deployment_ref": deployment_ref, "dseq": real_dseq, "status": text(&live, "deployment_state"), "execution_mode": "live_console_api" },
                "endpoint_discovered": false,
                "workload_readiness_proven": false,
                "workload_result_retrieved": false,
                "bid_ref": bid_rec["bid_ref"], "lease_ref": lease_rec["lease_ref"],
                "provider_native": dep["provider_native"],
                "spend": "REAL — deposit-funded lease accrues until close; run delete/close to stop",
                "teardown_required": true,
            }));
        }
        if mode != "simulator" {
            return Err(
                "akash_lifecycle_mode_unset — set the account endpoint mode to simulator or live"
                    .into(),
            );
        }
        let sim_ssh = self
            .account
            .pointer("/endpoint/ssh")
            .cloned()
            .unwrap_or(Value::Null);
        if text(&sim_ssh, "host").is_empty() || text(&sim_ssh, "key_file").is_empty() {
            return Err("akash_simulator_ssh_missing — simulator mode needs endpoint.ssh {host, port, user, key_file}".into());
        }
        let stamp = nanos();
        let record_id = format!("akdep_{stamp:x}");
        let deployment_ref = format!("akash-deployment://{record_id}");
        let dseq = format!("simdseq_{stamp:x}");
        let provider_address = text(plan, "provider_address").to_string();
        let usd = plan.get("usd_per_hour").cloned().unwrap_or(Value::Null);
        // Bid record — the selected offer, evidence only.
        let bid_id = format!("akbid_{stamp:x}");
        let bid = json!({
            "schema_version": "ioi.hypervisor.akash-bid.v1",
            "record_id": bid_id, "bid_ref": format!("akash-bid://{bid_id}"),
            "deployment_ref": deployment_ref, "environment_ref": env_ref,
            "account_ref": self.account["account_ref"],
            "provider_address": provider_address, "candidate_ref": plan["candidate_ref"],
            "offer_bid_ref": plan["bid_ref"], "usd_per_hour": usd, "native_rate": plan["native_rate"],
            "state": "selected",
            "note": "SIMULATED bid selection — provider-native bid ids are evidence only, never authority",
            "at": iso_now(),
        });
        // W1.2 / MEF-GAP-008 — the deployment record (saved below) cites this bid_ref; a lost bid
        // write leaves the deployment pointing at evidence no reader resolves. Refuse before saving.
        persist_record(data_dir, AKASH_BID_KIND, &bid_id, &bid)
            .map_err(|e| format!("provider_operation_persistence_failed — akash bid record {bid_id} did not commit: {e}"))?;
        // Lease record — open, priced, evidence only.
        let lease_id = format!("aklease_{stamp:x}");
        let lease = json!({
            "schema_version": "ioi.hypervisor.akash-lease.v1",
            "record_id": lease_id, "lease_ref": format!("akash-lease://{lease_id}"),
            "deployment_ref": deployment_ref, "bid_ref": bid["bid_ref"],
            "environment_ref": env_ref, "account_ref": self.account["account_ref"],
            "provider_address": provider_address, "usd_per_hour": usd,
            "state": "open",
            "spend_note": "customer-borne lease spend accrues until the lease closes",
            "note": "SIMULATED lease — provider-native lease ids are evidence only, never authority",
            "opened_at": iso_now(),
        });
        // W1.2 / MEF-GAP-008 — the lease is customer-borne accruing spend and the deployment cites
        // its lease_ref; a lost write hides the lease from spend reconciliation. Refuse before saving.
        persist_record(data_dir, AKASH_LEASE_KIND, &lease_id, &lease)
            .map_err(|e| format!("provider_spend_exposure_persistence_failed — akash lease record {lease_id} (customer-borne accruing spend) did not commit: {e}"))?;
        let mut dep = json!({
            "schema_version": "ioi.hypervisor.akash-deployment.v1",
            "record_id": record_id, "deployment_ref": deployment_ref, "dseq": dseq,
            "account_id": self.account_id(), "account_ref": self.account["account_ref"],
            "environment_ref": env_ref, "status": "deployment_created",
            "execution_mode": "simulated_control_plane",
            "sdl": plan.get("sdl").cloned().unwrap_or_else(|| akash_build_sdl(&json!({}), plan)),
            "sdl_hash": plan["sdl_hash"],
            "bid_ref": bid["bid_ref"], "lease_ref": lease["lease_ref"],
            "candidate_ref": plan["candidate_ref"], "quote_ref": plan["quote_ref"],
            "usd_per_hour": usd, "max_hourly_usd": plan["max_hourly_usd"],
            "teardown_policy": plan["teardown_policy"],
            "sim_ssh": sim_ssh,
            "ssh": Value::Null, "endpoint_ready": false,
            "events": [],
            "redeployed_from": redeployed_from.cloned().unwrap_or(Value::Null),
            "provider_native": { "dseq": dseq, "note": "SIMULATED deployment/bid/lease ids — evidence only, never restore or billing truth; no real Akash deployment exists" },
            "created_at": iso_now(),
        });
        Self::push_event(
            &mut dep,
            "deployment_created",
            format!("SDL accepted (hash {})", text(plan, "sdl_hash")),
        );
        Self::push_event(
            &mut dep,
            "bid_selected",
            format!("bid from provider {provider_address} selected"),
        );
        Self::push_event(
            &mut dep,
            "lease_opened",
            format!("lease open at ${}/hr (customer-borne until closed)", usd),
        );
        if let Some(old) = redeployed_from {
            Self::push_event(
                &mut dep,
                "redeployed_from",
                format!("fresh deployment replacing {}", old.as_str().unwrap_or("?")),
            );
        }
        self.save_deployment(data_dir, &dep)?;
        Ok(json!({
            "provider_operation_ref": format!("provider-account://{}/op/create/{}", self.account_id(), safe(env_ref)),
            "deployment": { "deployment_ref": deployment_ref, "dseq": dseq, "status": "deployment_created", "execution_mode": "simulated_control_plane" },
            "bid_ref": bid["bid_ref"], "lease_ref": lease["lease_ref"],
            "provider_native": dep["provider_native"],
            "endpoint_ready": false,
            "live_provisioning_not_run": true,
            "note": "lease open — run start to wait for endpoint readiness; exec ops fail closed (akash_endpoint_unready) until the endpoint is PROVEN",
            "teardown_required": true,
        }))
    }
}
impl EnvironmentProvider for AkashProvider {
    fn id(&self) -> &str {
        "akash-guarded"
    }
    fn capabilities(&self) -> Value {
        let mut caps = kind_capabilities("akash");
        caps["provider_spend_borne_by"] = json!("customer");
        caps["lifecycle"] = json!("guarded_lifecycle — quote-gated deployment/lease, wallet-gated mutations, close required; redeploy carries restore lineage");
        caps["execution_mode"] = json!(self.mode());
        caps
    }
    fn status(&self) -> (&'static str, String) {
        match text(&self.account, "status") {
            "verified" => (
                "available",
                format!(
                    "guarded akash DePIN deployment lifecycle ({} control plane)",
                    self.mode()
                ),
            ),
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
        if let Some(existing) = self.deployment(data_dir, env_ref) {
            if text(&existing, "status") != "torn_down" {
                return Err(format!("akash_deployment_already_open — {} is live for this environment; close the lease first", text(&existing, "deployment_ref")));
            }
        }
        self.provision(data_dir, env_ref, plan, None)
    }
    fn redeploy(&self, data_dir: &str, env_ref: &str, plan: &Value) -> Result<Value, String> {
        let old = self.deployment(data_dir, env_ref)
            .ok_or("akash_redeploy_requires_closed_deployment — nothing to redeploy; use create for the first deployment")?;
        if text(&old, "status") != "torn_down" {
            return Err("akash_redeploy_requires_closed_deployment — close the open lease first (teardown is never implicit)".into());
        }
        let old_ref = text(&old, "deployment_ref").to_string();
        let mut evidence = self.provision(data_dir, env_ref, plan, Some(&json!(old_ref)))?;
        // AkashRedeployPlan — durable lineage binding old → new + restore refs. Restore itself
        // stays an EXPLICIT op: it admits only by daemon state_root, never by this plan.
        let plan_id = format!("akrdp_{:x}", nanos());
        let record = json!({
            "schema_version": "ioi.hypervisor.akash-redeploy-plan.v1",
            "record_id": plan_id, "plan_ref": format!("akash-redeploy-plan://{plan_id}"),
            "environment_ref": env_ref, "account_ref": self.account["account_ref"],
            "old_deployment_ref": old_ref,
            "new_deployment_ref": evidence.pointer("/deployment/deployment_ref").cloned().unwrap_or(Value::Null),
            "restore_material_ref": plan.get("restore_material_ref").cloned().unwrap_or(Value::Null),
            "archive_ref": plan.get("archive_ref").cloned().unwrap_or(Value::Null),
            "note": "restore admits ONLY by daemon-recorded sha256 state_root — deployment persistent storage and archive bytes alone are never restore truth",
            "at": iso_now(),
        });
        // W1.2 / MEF-GAP-008 — the fresh deployment is already provisioned above; a lost redeploy-plan
        // write drops the old→new lineage/restore binding. Refuse rather than return success without it.
        persist_record(data_dir, AKASH_REDEPLOY_KIND, &plan_id, &record)
            .map_err(|e| format!("provider_operation_persistence_failed — akash redeploy-plan {plan_id} did not commit; the new deployment exists but its restore lineage is unrecorded: {e}"))?;
        if let Some(o) = evidence.as_object_mut() {
            o.insert("redeploy_plan_ref".into(), record["plan_ref"].clone());
            o.insert("redeployed_from".into(), json!(old_ref));
            o.insert("restore_note".into(), json!("run start, then restore with the bound material/archive refs — restore validates the admitted state_root before touching the new deployment"));
        }
        Ok(evidence)
    }
    fn start(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut dep = self
            .deployment(data_dir, env_ref)
            .ok_or("akash_deployment_absent")?;
        if text(&dep, "status") == "torn_down" {
            return Err("akash_deployment_torn_down".into());
        }
        if text(&dep, "execution_mode") == "live_console_api" {
            let dseq = text(&dep, "dseq").to_string();
            let mut discovered = None;
            for _ in 0..10 {
                let detail = self.live_detail(data_dir, &dseq)?;
                if let Some(endpoint) =
                    ioi_drivers::provisioning::akash_console::parse_active_lease_endpoint(&detail)
                {
                    discovered = Some((detail, endpoint));
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(6));
            }
            let (detail, provider_endpoint) = discovered.ok_or(
                "akash_endpoint_undiscovered — no active lease routing endpoint was reported within the bounded polling window",
            )?;
            let workload_readiness_proven = provider_endpoint
                .get("workload_readiness_proven")
                .and_then(Value::as_bool)
                == Some(true);
            let endpoint_id = format!("akep_{:x}", nanos());
            let endpoint = json!({
                "schema_version": "ioi.hypervisor.akash-endpoint.v1",
                "record_id": endpoint_id,
                "endpoint_ref": format!("akash-endpoint://{endpoint_id}"),
                "deployment_ref": dep["deployment_ref"],
                "lease_ref": dep["lease_ref"],
                "environment_ref": env_ref,
                "provider_address": provider_endpoint["provider_address"],
                "lease_id": provider_endpoint["lease_id"],
                "services": provider_endpoint["services"],
                "forwarded_ports": provider_endpoint["forwarded_ports"],
                "ips": provider_endpoint["ips"],
                "endpoint_discovered": true,
                "service_uri_present": provider_endpoint["service_uri_present"],
                "desired_replicas": provider_endpoint["desired_replicas"],
                "ready_replicas": provider_endpoint["ready_replicas"],
                "workload_readiness_proven": workload_readiness_proven,
                "workload_result_retrieved": false,
                "retrieved_live": true,
                "provider_response_hash": sha256_bytes(&serde_jcs::to_vec(&detail).unwrap_or_default()),
                "authority_note": "lease-assigned endpoints are fetched provider evidence, never authority",
                "proven_at": iso_now(),
            });
            persist_record(data_dir, AKASH_ENDPOINT_KIND, &endpoint_id, &endpoint)
                .map_err(|error| format!("provider_operation_persistence_failed — live Akash endpoint evidence did not commit: {error}"))?;
            dep["endpoint_discovered"] = json!(true);
            dep["endpoint_ready"] = json!(workload_readiness_proven);
            dep["workload_readiness_proven"] = json!(workload_readiness_proven);
            dep["workload_result_retrieved"] = json!(false);
            dep["desired_replicas"] = provider_endpoint["desired_replicas"].clone();
            dep["ready_replicas"] = provider_endpoint["ready_replicas"].clone();
            dep["endpoint_ref"] = endpoint["endpoint_ref"].clone();
            dep["status"] = json!(if workload_readiness_proven {
                "workload_ready"
            } else {
                "provider_endpoint_discovered"
            });
            dep["deployment_state"] = json!("active");
            Self::push_event(
                &mut dep,
                "endpoint_discovered",
                format!(
                    "active lease endpoint fetched from managed Console API; workload_readiness_proven={workload_readiness_proven}"
                ),
            );
            self.save_deployment(data_dir, &dep)?;
            return Ok(json!({
                "provider_operation_ref": format!("provider-account://{}/op/start/{}", self.account_id(), safe(env_ref)),
                "deployment_ref": dep["deployment_ref"],
                "dseq": dseq,
                "status": dep["status"],
                "endpoint_discovered": true,
                "endpoint_ready": workload_readiness_proven,
                "workload_readiness_proven": workload_readiness_proven,
                "workload_result_retrieved": false,
                "desired_replicas": provider_endpoint["desired_replicas"],
                "ready_replicas": provider_endpoint["ready_replicas"],
                "endpoint": endpoint,
                "retrieved_live": true,
            }));
        }
        let mut endpoint_evidence = Value::Null;
        if dep.get("endpoint_ready").and_then(Value::as_bool) != Some(true) {
            if text(&dep, "execution_mode") == "live" {
                return Err(
                    "akash_live_deployment_tx_not_implemented — no live deployment exists to await"
                        .into(),
                );
            }
            // Simulator endpoint readiness: resolved from the recorded sim endpoint; the
            // lease-assigned ip/ports are recorded as EVIDENCE, never authority.
            let sim_ssh = dep.get("sim_ssh").cloned().unwrap_or(Value::Null);
            let ep_id = format!("akep_{:x}", nanos());
            let ports: Vec<Value> = dep.pointer("/sdl/services/workspace/expose").and_then(Value::as_array)
                .map(|e| e.iter().map(|x| json!({ "port": x["port"], "as": x["as"], "proto": x["proto"], "service": x["service"] })).collect())
                .unwrap_or_default();
            let endpoint = json!({
                "schema_version": "ioi.hypervisor.akash-endpoint.v1",
                "record_id": ep_id, "endpoint_ref": format!("akash-endpoint://{ep_id}"),
                "deployment_ref": dep["deployment_ref"], "lease_ref": dep["lease_ref"],
                "environment_ref": env_ref,
                "ip": sim_ssh["host"], "ports": ports,
                "authority_note": "lease-assigned IP/ports are EVIDENCE, not authority — ingress beyond the SDL expose list requires the lifecycle + wallet authority",
                "proven_at": iso_now(),
            });
            // W1.2 / MEF-GAP-008 — the deployment (saved below) cites this endpoint_ref; a lost write
            // leaves it pointing at proven-endpoint evidence no reader resolves. Refuse.
            persist_record(data_dir, AKASH_ENDPOINT_KIND, &ep_id, &endpoint)
                .map_err(|e| format!("provider_operation_persistence_failed — akash endpoint record {ep_id} did not commit: {e}"))?;
            endpoint_evidence = endpoint.clone();
            dep["ssh"] = sim_ssh;
            dep["endpoint_ready"] = json!(true);
            dep["endpoint_ref"] = endpoint["endpoint_ref"].clone();
            Self::push_event(
                &mut dep,
                "endpoint_ready",
                format!("lease endpoint proven ({})", text(&endpoint, "ip")),
            );
            self.save_deployment(data_dir, &dep)?;
        }
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        if dep.get("workspace_bootstrapped").and_then(Value::as_bool) != Some(true) {
            lane.create(data_dir, env_ref, &json!({}))?;
            dep["workspace_bootstrapped"] = json!(true);
        }
        lane.start(data_dir, env_ref)?;
        dep["status"] = json!("running");
        Self::push_event(
            &mut dep,
            "workspace_started",
            "workspace lane running over the SDL-declared ssh service".into(),
        );
        self.save_deployment(data_dir, &dep)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/start/{}", self.account_id(), safe(env_ref)),
                   "deployment_ref": dep["deployment_ref"], "status": "running",
                   "endpoint_ready": true, "endpoint": endpoint_evidence }),
        )
    }
    fn workrun(&self, data_dir: &str, env_ref: &str, command: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.workrun(data_dir, env_ref, command)
    }
    fn stop(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        // An Akash lease bills until CLOSED — stopping the workspace never stops the spend.
        let mut dep = self
            .deployment(data_dir, env_ref)
            .ok_or("akash_deployment_absent")?;
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let stopped = lane.stop(data_dir, env_ref)?;
        dep["status"] = json!("workspace_stopped_lease_open");
        Self::push_event(
            &mut dep,
            "workspace_stopped",
            "workspace halted; the lease stays open and accruing".into(),
        );
        self.save_deployment(data_dir, &dep)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/stop/{}", self.account_id(), safe(env_ref)),
                   "deployment_ref": dep["deployment_ref"], "status": "workspace_stopped_lease_open",
                   "spend_note": "akash leases bill until closed — the lease stays open and accruing customer-borne spend; only the workspace lane halted",
                   "lane": stopped }),
        )
    }
    fn snapshot(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.snapshot(data_dir, env_ref)
    }
    fn restore(&self, data_dir: &str, env_ref: &str, material_ref: &str) -> Result<Value, String> {
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        lane.restore(data_dir, env_ref, material_ref)
    }
    fn logs(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut dep = self
            .deployment(data_dir, env_ref)
            .ok_or("akash_deployment_absent")?;
        let mut out = json!({
            "deployment_ref": dep["deployment_ref"], "lease_ref": dep["lease_ref"],
            "control_plane_log": dep.get("events").cloned().unwrap_or(json!([])),
            "execution_mode": dep["execution_mode"],
            "basis": "daemon-recorded control-plane events — provider evidence, not authority",
        });
        if self.mode() == "live" {
            // C6 — real proof retrieval. "Proof of execution" is a FETCHED fact — the
            // lease's on-chain deployment state, read live from the managed Console API
            // (GET /v1/deployments/{dseq}, spend:false) — not a daemon assertion. The
            // managed Console API does NOT expose container service logs (those need the
            // provider's own endpoint), so that is stated honestly, never faked.
            let dseq = text(&dep, "dseq").to_string();
            if dseq.is_empty() {
                return Err(
                    "akash_live_logs_no_dseq — the live deployment record carries no dseq to read"
                        .into(),
                );
            }
            let detail = self.live_detail(data_dir, &dseq)?;
            let state = ioi_drivers::provisioning::akash_console::parse_deployment_state(&detail);
            let leases = detail
                .pointer("/data/leases")
                .or_else(|| detail.get("leases"))
                .cloned()
                .unwrap_or(Value::Null);
            out["lease_state_proof"] = json!({
                "deployment_state": state,
                "retrieved_live": true,
                "source": "managed Console API GET /v1/deployments/{dseq} — the lease's on-chain state, fetched not asserted",
            });
            out["settlement_readback"] = json!({
                "normalized": ioi_drivers::provisioning::akash_console::parse_settlement_readback(
                    &detail,
                    dep.get("deposit_usd").and_then(Value::as_f64).unwrap_or(0.0),
                ),
                "leases": leases,
                "provider_native": detail,
                "provider_response_hash": sha256_bytes(&serde_jcs::to_vec(&detail).unwrap_or_default()),
                "retrieved_live": true,
                "source": "managed Console API GET /v1/deployments/{dseq}",
            });
            out["service_logs"] = json!("not_exposed_by_managed_console_api — container logs require the provider's own endpoint; the retrievable proof is the live lease state above");
            let result_ref = text(&dep, "result_credential_ref").to_string();
            if !result_ref.is_empty() {
                let endpoint_ref = text(&dep, "endpoint_ref");
                let endpoint = read_record_dir(data_dir, AKASH_ENDPOINT_KIND)
                    .into_iter()
                    .find(|record| text(record, "endpoint_ref") == endpoint_ref)
                    .ok_or("akash_result_endpoint_record_absent")?;
                let (host, port) = akash_result_endpoint_target(&endpoint)?;
                let token = resolve_connector_bearer(data_dir, &result_ref)?;
                let base = if port == 443 {
                    format!("https://{host}")
                } else {
                    format!("https://{host}:{port}")
                };
                let certificate_pin = text(&dep, "result_tls_server_certificate_sha256");
                let bundle = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let client = pinned_result_client(&host, port, certificate_pin)?;
                        let mut bundle = serde_json::Map::new();
                        for (name, path) in [
                            ("status", "/status"),
                            ("environment", "/environment"),
                            ("results", "/results"),
                            ("manifest", "/manifest"),
                        ] {
                            let response = client
                                .get(format!("{base}{path}"))
                                .bearer_auth(&token)
                                .send()
                                .await
                                .map_err(|_| "akash_result_endpoint_fetch_failed")?;
                            if !response.status().is_success() {
                                return Err("akash_result_endpoint_refused");
                            }
                            let bytes = response
                                .bytes()
                                .await
                                .map_err(|_| "akash_result_endpoint_body_failed")?;
                            if bytes.len() > 2 * 1024 * 1024 {
                                return Err("akash_result_artifact_too_large");
                            }
                            let value: Value = serde_json::from_slice(&bytes)
                                .map_err(|_| "akash_result_artifact_invalid_json")?;
                            let value = json!({
                                "value": value,
                                "sha256": sha256_bytes(&bytes),
                                "bytes": bytes.len(),
                                "body_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
                            });
                            if name == "status" {
                                validate_akash_result_status(&dep, &value["value"])?;
                            }
                            bundle.insert(name.into(), value);
                        }
                        Ok::<Value, &'static str>(Value::Object(bundle))
                    })
                })
                .map_err(str::to_string)?;
                validate_akash_result_bundle(&dep, &bundle).map_err(str::to_string)?;
                let result_id = format!(
                    "akresult_{}",
                    &sha256_bytes(&serde_jcs::to_vec(&bundle).unwrap_or_default())[7..23]
                );
                let record = json!({
                    "schema_version": "ioi.hypervisor.akash-workload-result.v1",
                    "record_id": result_id,
                    "result_ref": format!("akash-workload-result://{result_id}"),
                    "deployment_ref": dep["deployment_ref"],
                    "environment_ref": env_ref,
                    "provider_address": dep.pointer("/provider_native/provider").cloned().unwrap_or(Value::Null),
                    "credential_ref": result_ref,
                    "bundle": bundle,
                    "retrieved_live": true,
                    "credential_exposed_to_caller": false,
                    "retrieved_at": iso_now(),
                });
                persist_record(data_dir, "akash-workload-results", &result_id, &record)
                    .map_err(|error| format!("akash_result_persistence_failed: {error}"))?;
                dep["workload_result_retrieved"] = json!(true);
                dep["workload_result_ref"] = record["result_ref"].clone();
                Self::push_event(
                    &mut dep,
                    "workload_result_retrieved",
                    "authenticated benchmark result bundle fetched without exposing its bearer token"
                        .into(),
                );
                self.save_deployment(data_dir, &dep)?;
                out["workload_result"] = record;
            }
        } else {
            out["service_logs"] = json!("unavailable_in_simulator — provider-native service logs land with the live lease; workspace exec outputs are receipted in the Work Ledger");
        }
        Ok(out)
    }
    fn events(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let dep = self
            .deployment(data_dir, env_ref)
            .ok_or("akash_deployment_absent")?;
        Ok(json!({
            "deployment_ref": dep["deployment_ref"], "lease_ref": dep["lease_ref"],
            "events": dep.get("events").cloned().unwrap_or(json!([])),
            "execution_mode": dep["execution_mode"],
            "basis": "daemon-recorded deployment lifecycle events (simulated control plane labelled)",
        }))
    }
    fn reconcile(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        if self.mode() != "live" {
            return Err("akash_reconciliation_requires_live_provider_readback".into());
        }
        let mut dep = self
            .deployment(data_dir, env_ref)
            .ok_or("akash_deployment_absent")?;
        let dseq = text(&dep, "dseq").to_string();
        if dseq.is_empty() {
            return Err("akash_reconciliation_dseq_required".into());
        }
        let detail = self.live_detail(data_dir, &dseq)?;
        let settlement = self.settle_from_detail(data_dir, &mut dep, &detail)?;
        Ok(json!({
            "provider_operation_ref": format!("provider-account://{}/op/reconcile/{}", self.account_id(), safe(env_ref)),
            "deployment_ref": dep["deployment_ref"],
            "dseq": dseq,
            "retrieved_live": true,
            "settlement": settlement,
            "provider_native": {
                "response_hash": dep["provider_readback_hash"],
                "deployment": detail.pointer("/data/deployment").cloned().unwrap_or(Value::Null),
                "escrow_account": detail.pointer("/data/escrow_account").cloned().unwrap_or(Value::Null),
                "leases": detail.pointer("/data/leases").cloned().unwrap_or(Value::Null),
            },
            "teardown_state": dep["teardown_state"],
        }))
    }
    fn inject_outage(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        // THE DePIN risk, made testable: simulated provider-side lease revocation. Live leases
        // are never destroyed as an "outage" — this lane exists only on the simulator.
        let mut dep = self
            .deployment(data_dir, env_ref)
            .ok_or("akash_deployment_absent")?;
        if text(&dep, "execution_mode") != "simulated_control_plane" {
            return Err("akash_outage_injection_not_supported_live — revoking a paid lease is not a safely representable outage; use the simulator".into());
        }
        let (lane, _guard) = self.ssh_lane(data_dir, env_ref)?;
        let lost = lane.inject_outage(data_dir, env_ref)?;
        if let Some(mut lease) = self.lease_for(data_dir, text(&dep, "deployment_ref")) {
            lease["state"] = json!("closed_by_provider");
            lease["closed_at"] = json!(iso_now());
            lease["closure_note"] = json!(
                "SIMULATED provider-side revocation — the bid_lease_revocation risk, exercised"
            );
            self.save_lease(data_dir, &lease)?;
        }
        dep["status"] = json!("lease_lost");
        Self::push_event(&mut dep, "lease_revoked_by_provider", "SIMULATED lease revocation — workspace lost; deployment persistent storage is gone with the lease (it was never restore truth)".into());
        self.save_deployment(data_dir, &dep)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/inject_outage/{}", self.account_id(), safe(env_ref)),
                   "deployment_ref": dep["deployment_ref"], "lease_state": "closed_by_provider",
                   "workspace_lost": true, "simulated": true,
                   "recovery_path": "close (teardown accounting) → redeploy to a fresh bid → restore from daemon/storage-archive custody after state_root validation",
                   "lane": lost }),
        )
    }
    fn recover(&self, _d: &str, _e: &str) -> Result<Value, String> {
        Err("akash_recover_not_supported — recovery is REDEPLOY + restore from daemon/storage custody (close the lease, redeploy to a fresh bid, restore explicitly)".into())
    }
    fn delete(&self, data_dir: &str, env_ref: &str) -> Result<Value, String> {
        let mut dep = self
            .deployment(data_dir, env_ref)
            .ok_or("akash_deployment_absent")?;
        if text(&dep, "execution_mode") == "live_console_api" {
            use ioi_drivers::provisioning::akash_console as ac;
            let dseq = text(&dep, "dseq").to_string();
            if dseq.is_empty() {
                return Err("akash_live_close_dseq_required".into());
            }
            let api_key = self.live_api_key(data_dir)?;
            let (close_http, close_body) =
                Self::console_request(ac::close_deployment(&api_key, &dseq))?;
            if !(200..300).contains(&close_http) {
                dep["state"] = json!("reconciliation_required");
                dep["status"] = json!("reconciliation_required");
                dep["close_http"] = json!(close_http);
                dep["close_response_hash"] = json!(sha256_bytes(
                    &serde_jcs::to_vec(&close_body).unwrap_or_default()
                ));
                Self::push_event(
                    &mut dep,
                    "reconciliation_required",
                    format!("Console close did not confirm acceptance (HTTP {close_http})"),
                );
                self.save_deployment(data_dir, &dep)?;
                return Err(format!(
                    "akash_close_reconciliation_required: http {close_http} dseq={dseq}"
                ));
            }
            dep["state"] = json!("deployment_close_accepted");
            dep["status"] = json!("deployment_close_accepted");
            dep["close_http"] = json!(close_http);
            dep["close_response_hash"] = json!(sha256_bytes(
                &serde_jcs::to_vec(&close_body).unwrap_or_default()
            ));
            dep["close_accepted_at"] = json!(iso_now());
            Self::push_event(
                &mut dep,
                "deployment_close_accepted",
                "Console accepted deployment close; settlement still requires provider readback"
                    .into(),
            );
            self.save_deployment(data_dir, &dep)?;

            let detail = self.live_detail(data_dir, &dseq)?;
            let settlement = self.settle_from_detail(data_dir, &mut dep, &detail)?;
            let terminal = settlement["provider_terminal"] == json!(true);
            return Ok(json!({
                "provider_operation_ref": format!("provider-account://{}/op/delete/{}", self.account_id(), safe(env_ref)),
                "deployment_ref": dep["deployment_ref"],
                "dseq": dseq,
                "teardown_state": if terminal { "torn_down" } else { "reconciliation_required" },
                "native_teardown": {
                    "destroyed": terminal,
                    "close_http": close_http,
                    "provider_response_hash": dep["provider_readback_hash"],
                },
                "settlement": settlement,
                "cleanup_verified": terminal,
            }));
        }
        let remote_cleanup = match self.ssh_lane(data_dir, env_ref) {
            Ok((lane, _guard)) => lane
                .delete(data_dir, env_ref)
                .map(|e| e["cleanup_verified"].clone())
                .unwrap_or(json!("unreachable")),
            Err(e) => json!(format!("skipped: {e}")),
        };
        let already_revoked = self
            .lease_for(data_dir, text(&dep, "deployment_ref"))
            .map(|l| text(&l, "state") == "closed_by_provider")
            .unwrap_or(false);
        let native_teardown = if self
            .account
            .pointer("/endpoint/simulate_teardown_failure")
            .and_then(Value::as_bool)
            == Some(true)
        {
            json!({ "destroyed": false, "error": "SIMULATED lease-close failure (endpoint.simulate_teardown_failure)", "warning": "TEARDOWN MAY BE INCOMPLETE — verify the lease on-chain/console (spend may still accrue)" })
        } else if already_revoked {
            json!({ "destroyed": true, "note": "lease was already closed by the provider (simulated revocation) — close confirmed idempotently" })
        } else {
            json!({ "destroyed": true, "note": "simulated control plane — lease closed, no real deployment existed" })
        };
        if let Some(mut lease) = self.lease_for(data_dir, text(&dep, "deployment_ref")) {
            if text(&lease, "state") == "open" {
                lease["state"] = json!("closed");
                lease["closed_at"] = json!(iso_now());
                self.save_lease(data_dir, &lease)?;
            }
        }
        // CARVE-OUT: record the EXACT deletion outcome. `teardown_state` was unconditionally
        // "torn_down" and `cleanup_verified` unconditionally true, even when the provider-native
        // destroy reported `destroyed: false`. Non-succeeded outcomes now open a durable obligation.
        let (teardown_state, cleanup_verified, deletion_disposition) =
            provider_teardown_disposition(
                &format!(
                    "provider-account://{}/resource/{}",
                    self.account_id(),
                    safe(env_ref)
                ),
                &native_teardown,
                &remote_cleanup,
            );
        dep["status"] = json!(teardown_state);
        dep["torn_down_at"] = json!(iso_now());
        dep["deletion_disposition"] = deletion_disposition.clone();
        Self::push_event(
            &mut dep,
            "closed",
            "deployment closed; lease billing ends with closure".into(),
        );
        self.save_deployment(data_dir, &dep)?;
        Ok(
            json!({ "provider_operation_ref": format!("provider-account://{}/op/delete/{}", self.account_id(), safe(env_ref)),
                   "deployment_ref": dep["deployment_ref"], "teardown_state": teardown_state,
                   "remote_workspace_cleanup": remote_cleanup, "native_teardown": native_teardown,
                   "cleanup_verified": cleanup_verified, "deletion_disposition": deletion_disposition }),
        )
    }
    fn observe(&self, data_dir: &str, env_ref: &str) -> Value {
        match self.deployment(data_dir, env_ref) {
            None => {
                json!({ "provider": self.id(), "environment_ref": env_ref, "deployment": Value::Null, "status": "absent" })
            }
            Some(dep) => {
                let torn = text(&dep, "status") == "torn_down";
                let lane_view = if torn {
                    Value::Null
                } else if dep.get("endpoint_ready").and_then(Value::as_bool) != Some(true) {
                    json!({ "endpoint": "pending — run start to wait for lease endpoint readiness" })
                } else {
                    match self.ssh_lane(data_dir, env_ref) {
                        Ok((lane, _guard)) => lane.observe(data_dir, env_ref),
                        Err(e) => json!({ "error": e }),
                    }
                };
                let lease = self.lease_for(data_dir, text(&dep, "deployment_ref"));
                json!({ "provider": self.id(), "environment_ref": env_ref,
                        "deployment_ref": dep["deployment_ref"], "dseq": dep["dseq"], "status": dep["status"],
                        "execution_mode": dep["execution_mode"],
                        "bid_ref": dep["bid_ref"], "lease": lease,
                        "endpoint_ready": dep["endpoint_ready"], "endpoint_ref": dep.get("endpoint_ref").cloned().unwrap_or(Value::Null),
                        "events_tail": dep.get("events").and_then(Value::as_array).map(|e| e.iter().rev().take(5).cloned().collect::<Vec<_>>()).unwrap_or_default(),
                        "provider_native": dep["provider_native"],
                        "teardown_state": if torn { json!("torn_down") } else { json!("live_or_pending") },
                        "workspace": lane_view })
            }
        }
    }
}

/// GET /v1/hypervisor/akash-deployments — the DePIN posture projection: deployments joined to
/// bids/leases/endpoints/redeploy plans (all daemon records; provider-native ids evidence-only).
pub(crate) async fn handle_akash_deployments(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut deployments = read_record_dir(&st.data_dir, AKASH_DEPLOYMENT_KIND);
    deployments.sort_by(|a, b| text(b, "record_id").cmp(text(a, "record_id")));
    Json(json!({
        "schema_version": "ioi.hypervisor.akash-deployments.v1",
        "custody_rule": "provider-native dseq/bid/lease ids and deployment persistent storage are availability EVIDENCE — daemon-admitted sha256 state roots remain restore truth",
        "deployments": deployments,
        "bids": read_record_dir(&st.data_dir, AKASH_BID_KIND),
        "leases": read_record_dir(&st.data_dir, AKASH_LEASE_KIND),
        "endpoints": read_record_dir(&st.data_dir, AKASH_ENDPOINT_KIND),
        "redeploy_plans": read_record_dir(&st.data_dir, AKASH_REDEPLOY_KIND),
        "at": iso_now(),
    }))
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
        return Some(Ok((
            account.clone(),
            Box::new(VastProvider { account }),
            None,
        )));
    }
    if text(&account, "kind") == "runpod"
        && matches!(vast_mode(&account).as_str(), "simulator" | "live")
        && text(&account, "status") == "verified"
    {
        return Some(Ok((
            account.clone(),
            Box::new(RunPodProvider { account }),
            None,
        )));
    }
    if text(&account, "kind") == "lambda_cloud"
        && matches!(vast_mode(&account).as_str(), "simulator" | "live")
        && text(&account, "status") == "verified"
    {
        return Some(Ok((
            account.clone(),
            Box::new(LambdaProvider { account }),
            None,
        )));
    }
    if text(&account, "kind") == "aws"
        && matches!(vast_mode(&account).as_str(), "simulator" | "live")
        && text(&account, "status") == "verified"
    {
        return Some(Ok((
            account.clone(),
            Box::new(AwsProvider { account }),
            None,
        )));
    }
    if text(&account, "kind") == "k8s"
        && matches!(vast_mode(&account).as_str(), "simulator" | "live")
        && text(&account, "status") == "verified"
    {
        return Some(Ok((
            account.clone(),
            Box::new(K8sProvider { account }),
            None,
        )));
    }
    if text(&account, "kind") == "azure"
        && matches!(vast_mode(&account).as_str(), "simulator" | "live")
        && text(&account, "status") == "verified"
    {
        return Some(Ok((
            account.clone(),
            Box::new(AzureProvider { account }),
            None,
        )));
    }
    if text(&account, "kind") == "gcp"
        && matches!(vast_mode(&account).as_str(), "simulator" | "live")
        && text(&account, "status") == "verified"
    {
        return Some(Ok((
            account.clone(),
            Box::new(GcpProvider { account }),
            None,
        )));
    }
    if text(&account, "kind") == "akash"
        && matches!(vast_mode(&account).as_str(), "simulator" | "live")
        && text(&account, "status") == "verified"
    {
        return Some(Ok((
            account.clone(),
            Box::new(AkashProvider { account }),
            None,
        )));
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
        Some(Ok((
            account.clone(),
            Box::new(CloudKindProvider { account }),
            None,
        )))
    }
}

// ---- ProviderAccount CRUD --------------------------------------------------------------------

pub(crate) async fn handle_provider_accounts_list(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    let mut accounts = read_record_dir(&st.data_dir, ACCOUNT_KIND);
    accounts.sort_by(|a, b| text(a, "created_at").cmp(text(b, "created_at")));
    Json(
        json!({ "schema_version": "ioi.hypervisor.provider-accounts.v1", "accounts": accounts, "spend_rule": "BYO provider spend is customer-borne; the hypervisor records, governs, estimates, and reconciles — it does not hide markup inside provider cost", "at": iso_now() }),
    )
}

pub(crate) async fn handle_provider_account_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let kind = text(&body, "kind");
    if !ACCOUNT_KINDS.contains(&kind) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                json!({ "ok": false, "error": { "code": "provider_kind_invalid", "message": format!("kind must be one of {ACCOUNT_KINDS:?}") } }),
            ),
        );
    }
    let display_name = text(&body, "display_name");
    if display_name.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                json!({ "ok": false, "error": { "code": "provider_display_name_required", "message": "a provider account needs a display_name" } }),
            ),
        );
    }
    if kind == "baremetal_ssh" {
        let ep = body.get("endpoint").cloned().unwrap_or_else(|| json!({}));
        if text(&ep, "host").is_empty() || text(&ep, "user").is_empty() {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(
                    json!({ "ok": false, "error": { "code": "provider_endpoint_required", "message": "baremetal_ssh needs endpoint {host, user, port?}" } }),
                ),
            );
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
    if persist_record(&st.data_dir, ACCOUNT_KIND, &id, &record).is_err() {
        return provider_account_persist_failed("could not be created and");
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "account": record })),
    )
}

pub(crate) async fn handle_provider_account_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_account(&st.data_dir, &id) {
        Some(account) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "account": account })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": { "code": "provider_account_not_found" } })),
        ),
    }
}

pub(crate) async fn handle_provider_account_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut account) = load_account(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": { "code": "provider_account_not_found" } })),
        );
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
    // An endpoint change resets a `verified` account to `unverified` so posture must be re-proven.
    // Discarding this write kept the old verified verdict against the new endpoint.
    if persist_record(&st.data_dir, ACCOUNT_KIND, &aid, &account).is_err() {
        return provider_account_persist_failed("patch");
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "account": account })),
    )
}

pub(crate) async fn handle_provider_account_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(account) = load_account(&st.data_dir, &id) else {
        // PRESERVED: OK-with-ok:false keeps the shipped not-found wire response rather than
        // silently broadening it to 404.
        return (
            StatusCode::OK,
            Json(json!({ "ok": false, "error": { "code": "provider_account_not_found" } })),
        );
    };
    let aid = text(&account, "account_id").to_string();
    let account_ref = text(&account, "account_ref").to_string();

    // W1.2 / MEF-GAP-008 — REFUSE while an open spend exposure references this account: the sealed
    // credential is the ONLY key that can tear down a live, customer-borne paid instance, so
    // deleting it would strand accruing spend with no teardown path (closed_with_warning is included
    // — it explicitly flags that the exposure MAY still accrue on the customer's account).
    let open_exposures: Vec<Value> = read_record_dir(&st.data_dir, EXPOSURE_KIND)
        .into_iter()
        .filter(|e| {
            text(e, "account_ref") == account_ref
                && matches!(text(e, "status"), "open" | "closed_with_warning")
        })
        .collect();
    if !open_exposures.is_empty() {
        let refs: Vec<Value> = open_exposures
            .iter()
            .map(|e| e["exposure_ref"].clone())
            .collect();
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "code": "provider_account_delete_open_spend_exposure",
                "message": format!("{} unresolved spend exposure(s) still reference this account — its credential is the only key that can tear down the live paid instance(s); close the deployment(s)/lease(s) first (delete the environment or run the provider delete op), then delete the account. Nothing was deleted.", open_exposures.len()),
                "open_exposure_refs": refs,
                "account_id": aid,
            })),
        );
    }

    // ── EFFECT 1: the live bearer credential FIRST (the b6c19c766 order) ──────────────────────
    // A failed credential removal must NOT be acknowledged as a successful destruction: the sealed
    // live secret would survive on disk, bound by connector_id to an account no listing shows and
    // no delete path can reach again — a credential leak reported as a destruction.
    if let Some(cred) = load_account_credential(&st.data_dir, &aid) {
        let cid = text(&cred, "credential_id").to_string();
        if !super::remove_record(&st.data_dir, CREDENTIAL_VAULT, &cid) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "ok": false,
                    "code": "provider_credential_removal_failed",
                    "message": format!("the sealed credential '{cid}' could not be removed — refusing to delete the account, which would orphan a live, resolvable secret behind an account no listing shows. Nothing was deleted."),
                    "account_id": aid,
                })),
            );
        }
        // Confirm the credential no longer RESOLVES before touching the account record — the ack is
        // from reloaded absence, never from the remove outcome.
        if load_account_credential(&st.data_dir, &aid).is_some() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "ok": false,
                    "code": "provider_credential_removal_unconfirmed",
                    "message": "the credential removal reported done but the credential STILL resolves — refusing to delete the account. Delete again to retry.",
                    "account_id": aid,
                })),
            );
        }
    }

    // ── EFFECT 2: the account record ─────────────────────────────────────────────────────────
    // CLASSIFIED — the remove outcome is intentionally not the gate; acknowledgement below rests on
    // the RELOADED absence, which fails closed (503) if the account still resolves.
    let _ = super::remove_record(&st.data_dir, ACCOUNT_KIND, &aid);

    // ── Acknowledge ONLY from the RELOADED absence, never from the remove outcomes ───────────
    if load_account(&st.data_dir, &aid).is_some() || load_account(&st.data_dir, &id).is_some() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "code": "provider_account_deletion_unconfirmed",
                "message": format!("the account '{aid}' STILL resolves after removal — the deletion is not acknowledged (this happens when the record does not live at the file the writer would give it, e.g. a promoted substrate family). Delete again to retry."),
                "account_id": aid,
            })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "removed": true,
            "account_id": aid,
            "note": "credential removed first (confirmed absent) then the account record — no live bearer is orphaned; provider-operation and spend-exposure records remain as evidence",
        })),
    )
}

// ---- ProviderCredentialBinding — sealed material, presence-provable, never exported ----------

pub(crate) async fn handle_provider_account_credential(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut account) = load_account(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": { "code": "provider_account_not_found" } })),
        );
    };
    let aid = text(&account, "account_id").to_string();
    let kind = text(&account, "kind").to_string();
    // Per-kind primary secret: sealed with the SAME dcrypt ladder as every other credential.
    let (cred_kind, secret) = match kind.as_str() {
        "baremetal_ssh" => ("ssh-key", text(&body, "private_key")),
        "aws" => ("aws-sigv4", text(&body, "secret_access_key")),
        "gcp" => ("gcp-service-account", text(&body, "service_account_key")),
        "azure" => ("azure-service-principal", text(&body, "client_secret")),
        "k8s" => {
            let kubeconfig = text(&body, "kubeconfig");
            if !kubeconfig.is_empty() {
                ("kubeconfig", kubeconfig)
            } else {
                ("bearer", text(&body, "token"))
            }
        }
        "vast" | "runpod" | "lambda_cloud" | "akash" => ("bearer", text(&body, "api_key")),
        _ => ("bearer", text(&body, "token")),
    };
    if secret.trim().is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                json!({ "ok": false, "error": { "code": "provider_credential_material_required", "message": format!("'{kind}' accounts bind their secret material at this route (never returned, sealed at rest)") } }),
            ),
        );
    }
    let Some(sealed) = seal_scm_token(secret) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": { "code": "provider_credential_seal_failed" } })),
        );
    };
    let fingerprint = sha256_bytes(secret.as_bytes());
    let cred_id = format!("pcred_{aid}");
    let mut record = json!({
        "schema_version": "ioi.hypervisor.provider-credential.v1",
        "credential_id": cred_id,
        // connector_id keys the CapabilityLease gateway lookup — one spine, no new gate.
        "connector_id": aid,
        "kind": cred_kind,
        "key_source": super::lifecycle_routes::scm_key_source(),
        "fingerprint": fingerprint,
        // Non-secret aux hints (region/project/cluster) travel in the clear; secrets never do.
        "aux": body.get("aux").cloned().unwrap_or_else(|| json!({})),
        "bound_at": iso_now(),
    });
    // The sealed material lands under the field name resolve_sealed_credential reads for this
    // kind, so provider credentials ride the SAME gateway resolver as the connector estate.
    let sealed_field = if cred_kind == "aws-sigv4" {
        "sealed_secret_access_key"
    } else {
        "sealed_token"
    };
    record[sealed_field] = json!(sealed);
    // Non-secret resolver hints (token_url, client_id, audience, …) are read from the record
    // ROOT by the canonical oidc-workload/oauth-refresh branches — splice them up from aux.
    if let Some(aux) = body.get("aux").and_then(Value::as_object) {
        for hint in [
            "token_url",
            "client_id",
            "audience",
            "scopes",
            "subject_token_type",
            "subject_token_file",
            "access_key_id",
            "region",
            "tenant_id",
            "subscription_id",
            "resource_group",
            "location",
            "namespace",
            "cluster",
            "ca_mode",
        ] {
            if let Some(v) = aux.get(hint).filter(|v| v.is_string()) {
                record[hint] = v.clone();
            }
        }
    }
    // The vault record is what every provider operation resolves at use time; the account fields
    // are the projection of that binding. Neither may be assumed.
    if persist_record(&st.data_dir, CREDENTIAL_VAULT, &cred_id, &record).is_err() {
        return provider_account_persist_failed("credential could not be sealed and");
    }
    account["credential_binding_ref"] = json!(format!("credential://{CREDENTIAL_VAULT}/{cred_id}"));
    account["status"] = json!("unverified");
    account["updated_at"] = json!(iso_now());
    if persist_record(&st.data_dir, ACCOUNT_KIND, &aid, &account).is_err() {
        return provider_account_persist_failed("credential binding");
    }
    let receipt = provider_receipt_ext(
        &st.data_dir,
        &kind,
        "-",
        "credential_bind",
        "ok",
        &json!({ "account_ref": text(&account, "account_ref"), "credential_kind": cred_kind, "fingerprint": fingerprint }),
    );
    (
        StatusCode::CREATED,
        Json(
            json!({ "ok": true, "account": account, "credential": { "credential_id": cred_id, "kind": cred_kind, "fingerprint": fingerprint, "sealed": true }, "receipt_ref": receipt }),
        ),
    )
}

pub(crate) async fn handle_provider_account_credential_revoke(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let Some(mut account) = load_account(&st.data_dir, &id) else {
        return Json(json!({ "ok": false, "error": { "code": "provider_account_not_found" } }));
    };
    let aid = text(&account, "account_id").to_string();
    // Vault removal is the ACTUAL revocation: every provider operation resolves the credential
    // through load_account_credential, not through the account's status. `removed` previously
    // conflated "no credential was bound" with "removal failed" and was returned alongside an
    // unconditional ok:true, so a credential that could not be deleted was reported revoked while
    // remaining fully resolvable.
    let existing = load_account_credential(&st.data_dir, &aid);
    let had_credential = existing.is_some();
    let removed = existing
        .map(|c| super::remove_record(&st.data_dir, CREDENTIAL_VAULT, text(&c, "credential_id")))
        .unwrap_or(false);
    if had_credential && !removed {
        return Json(json!({ "ok": false, "error": {
            "code": "provider_credential_revocation_failed",
            "message": "the sealed credential could not be removed and is still resolvable"
        }}));
    }
    account["credential_binding_ref"] = Value::Null;
    account["status"] = json!("revoked");
    account["updated_at"] = json!(iso_now());
    if persist_record(&st.data_dir, ACCOUNT_KIND, &aid, &account).is_err() {
        return Json(json!({ "ok": false, "error": {
            "code": "provider_account_persistence_failed",
            "message": "the credential was removed but the account still reads as bound; re-run revoke to converge"
        }}));
    }
    let receipt = provider_receipt_ext(
        &st.data_dir,
        text(&account, "kind"),
        "-",
        "credential_revoke",
        "ok",
        &json!({ "account_ref": text(&account, "account_ref") }),
    );
    Json(json!({ "ok": true, "revoked": removed, "account": account, "receipt_ref": receipt }))
}

/// POST /provider-accounts/:id/preflight — the REAL probe. SSH: connect + posture evidence.
/// Cloud kinds: credential resolvability + endpoint hints (honest: no cloud API call this cut).
pub(crate) async fn handle_provider_account_preflight(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut account) = load_account(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": { "code": "provider_account_not_found" } })),
        );
    };
    let aid = text(&account, "account_id").to_string();
    let kind = text(&account, "kind").to_string();
    let (admit, evidence): (bool, Value) = if kind == "baremetal_ssh" {
        match materialize_ssh_key(&st.data_dir, &aid) {
            Err(e) => (false, json!({ "reason": e })),
            Ok((key_path, _guard, key_source)) => {
                let ssh = SshProvider {
                    account: account.clone(),
                    key_path,
                };
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
                let sealed = cred["sealed_token"]
                    .as_str()
                    .or(cred["sealed_secret_access_key"].as_str());
                let token = sealed.and_then(open_scm_token);
                let resolvable = token.is_some();
                if kind == "akash" && vast_mode(&account) == "live" {
                    // M2a — real read-only verification for the managed Akash
                    // Console API. The sealed x-api-key must actually
                    // authenticate: GET /v1/wallet-settings is read-only, moves
                    // no credits and provisions nothing, so `verified` now means
                    // "the key works", not merely "the seal unsealed". Gated on
                    // endpoint.mode==live so offline preflight stays CI-safe.
                    match token {
                        None => (
                            false,
                            json!({ "reason": "provider_credential_unbound", "probe": "akash Console read-only auth: credential did not unseal" }),
                        ),
                        Some(api_key) => {
                            use ioi_drivers::provisioning::akash_console;
                            let req = akash_console::verify_key(&api_key);
                            let (hname, hval) = req.header();
                            let url =
                                format!("{}{}", akash_console::AKASH_CONSOLE_BASE_URL, req.path);
                            let resp = reqwest::Client::new()
                                .get(&url)
                                .header(hname, hval)
                                .timeout(std::time::Duration::from_secs(20))
                                .send()
                                .await;
                            match resp {
                                Ok(r) if (200..300).contains(&r.status().as_u16()) => (
                                    true,
                                    json!({ "credential_kind": text(&cred, "kind"), "fingerprint": text(&cred, "fingerprint"), "probe": "akash managed Console API read-only auth (GET /v1/deployments)", "http_status": r.status().as_u16(), "spend": "none" }),
                                ),
                                Ok(r) => (
                                    false,
                                    json!({ "reason": "akash_console_auth_rejected", "http_status": r.status().as_u16(), "probe": "akash managed Console API read-only auth (GET /v1/deployments)" }),
                                ),
                                Err(e) => (
                                    false,
                                    json!({ "reason": format!("akash_console_verify_failed: {e}"), "probe": "akash managed Console API read-only auth (GET /v1/deployments)" }),
                                ),
                            }
                        }
                    }
                } else {
                    (
                        resolvable,
                        json!({ "credential_kind": text(&cred, "kind"), "credential_resolvable": resolvable, "fingerprint": text(&cred, "fingerprint"), "probe": "credential seal round-trip only — no cloud API call (set endpoint.mode=live to run the real akash Console auth verify)", "lifecycle": "credential_preflight_only" }),
                    )
                }
            }
        }
    };
    account["preflight"] = json!({ "admit": admit, "evidence": evidence, "at": iso_now() });
    account["status"] = json!(if admit { "verified" } else { "unverified" });
    account["updated_at"] = json!(iso_now());
    // Preflight is what MOVES the account to `verified`. Returning that verdict over a discarded
    // write reported a verified account no later read would agree with — and the patch handler
    // relies on the stored `verified` status to know when a posture must be re-proven.
    if persist_record(&st.data_dir, ACCOUNT_KIND, &aid, &account).is_err() {
        return provider_account_persist_failed("preflight verdict");
    }
    let receipt = provider_receipt_ext(
        &st.data_dir,
        &kind,
        "-",
        "preflight",
        if admit { "ok" } else { "preflight_failed" },
        &json!({ "account_ref": text(&account, "account_ref"), "evidence": account["preflight"]["evidence"] }),
    );
    (
        StatusCode::OK,
        Json(json!({ "ok": admit, "account": account, "receipt_ref": receipt })),
    )
}

/// GET /provider-materials — daemon-custody snapshot material (admitted state roots).
pub(crate) async fn handle_provider_materials(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut materials = read_record_dir(&st.data_dir, MATERIAL_KIND);
    materials.sort_by(|a, b| text(b, "material_id").cmp(text(a, "material_id")));
    Json(
        json!({ "schema_version": "ioi.hypervisor.provider-materials.v1", "custody_rule": "blob existence is not restore truth — restores admit by daemon-recorded sha256 state_root", "materials": materials, "at": iso_now() }),
    )
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
                "verified" => (
                    "available",
                    format!(
                        "verified bare-metal SSH node ({})",
                        text(&account, "display_name")
                    ),
                ),
                "revoked" => ("revoked", "credential revoked".to_string()),
                _ => (
                    "unverified",
                    "bind + preflight to admit this node".to_string(),
                ),
            }
        } else {
            match text(&account, "status") {
                "verified" => (
                    "credential_verified",
                    format!("'{kind}' credential verified — lifecycle lands with its adapter cut"),
                ),
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

const PROVIDER_PROPOSAL_NAMESPACE: &str = "hypervisor-provider-operation-proposals";
const PROVIDER_PROPOSAL_KIND: &str = "provider_operation_proposal";
const PROVIDER_PROPOSAL_TTL_SECONDS: u64 = 300;

fn provider_proposal_ref(owner_ref: &str, idempotency_key: &str) -> String {
    format!(
        "provider-operation-proposal://{}",
        super::mutation_event_foundation::replay_stable_id("popp", owner_ref, idempotency_key,)
    )
}

/// Bind a proposal to the exact authenticated transport without retaining a bearer token.
/// The hash is deliberately opaque and is useful only for same-session comparison.
fn provider_proposal_session_binding(
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<Value>)> {
    let material = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .or_else(|| headers.get("cookie").and_then(|value| value.to_str().ok()))
        .or_else(|| headers.get("x-api-key").and_then(|value| value.to_str().ok()))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "ok": false,
                    "code": "provider_operation_proposal_session_required",
                    "message": "proposal issuance and consumption require the same authenticated session"
                })),
            )
        })?;
    Ok(sha256_bytes(material.as_bytes()))
}

fn canonical_provider_proposal_request(body: &Value) -> Result<Value, (StatusCode, Json<Value>)> {
    if body.get("operation_proposal").is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "code": "provider_operation_inline_proposal_forbidden",
                "message": "inline operation_proposal objects are caller assertions and cannot authorize a live provider effect; obtain an opaque proposal_ref from the daemon"
            })),
        ));
    }
    let mut canonical = body.clone();
    let Some(object) = canonical.as_object_mut() else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "code": "provider_operation_proposal_request_invalid" })),
        ));
    };
    object.remove("operation_proposal_ref");
    Ok(canonical)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn random_proposal_nonce() -> String {
    use rand::{distributions::Alphanumeric, Rng};
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn provider_proposal_refusal(code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "ok": false, "code": code, "message": message })),
    )
}

fn issue_provider_operation_proposal(
    data_dir: &str,
    caller: &super::mutation_event_foundation::WriteCaller,
    session_binding: &str,
    request: &Value,
) -> Result<Value, (StatusCode, Json<Value>)> {
    let canonical = canonical_provider_proposal_request(request)?;
    let op = text(&canonical, "op");
    let provider_id = text(&canonical, "provider_id");
    let environment_ref = text(&canonical, "environment_ref");
    if !matches!(op, "create" | "redeploy") || provider_id.is_empty() || environment_ref.is_empty()
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "ok": false,
                "code": "provider_operation_proposal_facets_required",
                "message": "a live proposal requires provider_id, environment_ref and op=create|redeploy"
            })),
        ));
    }
    let proposal_ref = provider_proposal_ref(&caller.owner_ref, &caller.idempotency_key);
    let history = super::mutation_event_foundation::admitted_history_for_caller(
        data_dir,
        caller,
        PROVIDER_PROPOSAL_NAMESPACE,
        PROVIDER_PROPOSAL_KIND,
        &proposal_ref,
    )?;
    let request_hash = sha256_bytes(&serde_jcs::to_vec(&canonical).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "code": "provider_operation_proposal_canonicalization_failed" })),
        )
    })?);
    if let Some(admitted) = history.first() {
        let payload = &admitted.operation.payload;
        if text(payload, "phase") == "admitted"
            && text(payload, "request_hash") == request_hash
            && text(payload, "principal_ref") == caller.identity.principal_ref
            && text(payload, "session_binding") == session_binding
        {
            return Ok(json!({
                "ok": true,
                "proposal_ref": proposal_ref,
                "request_hash": request_hash,
                "expires_at_unix": payload["expires_at_unix"],
                "proposal_admission_receipt_ref": admitted.operation.payload["proposal_admission_receipt_ref"],
                "replayed": true
            }));
        }
        return Err(provider_proposal_refusal(
            "provider_operation_proposal_idempotency_conflict",
            "this proposal idempotency key is already bound to different request or session bytes",
        ));
    }
    let issued_at_unix = unix_now();
    let expires_at_unix = issued_at_unix.saturating_add(PROVIDER_PROPOSAL_TTL_SECONDS);
    let nonce = random_proposal_nonce();
    let admission_receipt_ref = format!(
        "provider-operation-proposal-admission://{}",
        sha256_bytes(format!("{proposal_ref}\0{request_hash}\0{nonce}").as_bytes())
            .trim_start_matches("sha256:")
    );
    let payload = json!({
        "schema_version": "ioi.hypervisor.provider-operation-proposal.v2",
        "phase": "admitted",
        "proposal_ref": proposal_ref,
        "proposal_source": "daemon-issued-durable-proposal",
        "principal_ref": caller.identity.principal_ref,
        "session_binding": session_binding,
        "owner_ref": caller.owner_ref,
        "request_hash": request_hash,
        "provider_id": provider_id,
        "operation_kind": op,
        "environment_ref": environment_ref,
        "resource_refs": [provider_id, environment_ref],
        "one_time_nonce": nonce,
        "issued_at_unix": issued_at_unix,
        "expires_at_unix": expires_at_unix,
        "proposal_admission_receipt_ref": admission_receipt_ref,
    });
    let commit = super::mutation_event_foundation::admit_owner_scoped_write(
        data_dir,
        caller,
        PROVIDER_PROPOSAL_NAMESPACE,
        PROVIDER_PROPOSAL_KIND,
        &proposal_ref,
        "provider_operation_proposal.admitted",
        None,
        &payload,
    )?;
    Ok(json!({
        "ok": true,
        "proposal_ref": proposal_ref,
        "request_hash": request_hash,
        "expires_at_unix": expires_at_unix,
        "proposal_admission_operation_ref": commit.operation_ref,
        "proposal_admission_receipt_ref": admission_receipt_ref,
        "replayed": commit.replayed
    }))
}

fn consume_provider_operation_proposal(
    data_dir: &str,
    caller: &super::mutation_event_foundation::WriteCaller,
    session_binding: &str,
    request: &Value,
) -> Result<Value, (StatusCode, Json<Value>)> {
    let canonical = canonical_provider_proposal_request(request)?;
    let supplied_ref = text(request, "operation_proposal_ref");
    if supplied_ref.is_empty() {
        return Err(provider_proposal_refusal(
            "provider_operation_proposal_ref_required",
            "a live provider effect requires an opaque daemon-issued operation_proposal_ref",
        ));
    }
    let expected_ref = provider_proposal_ref(&caller.owner_ref, &caller.idempotency_key);
    if supplied_ref != expected_ref {
        return Err(provider_proposal_refusal(
            "provider_operation_proposal_ref_substitution",
            "the proposal reference is not the one bound to this owner and idempotency key",
        ));
    }
    let history = super::mutation_event_foundation::admitted_history_for_caller(
        data_dir,
        caller,
        PROVIDER_PROPOSAL_NAMESPACE,
        PROVIDER_PROPOSAL_KIND,
        supplied_ref,
    )?;
    let Some(admitted) = history.first() else {
        return Err(provider_proposal_refusal(
            "provider_operation_proposal_unknown",
            "the proposal reference does not resolve for this authenticated principal",
        ));
    };
    if history.len() != 1 || text(&admitted.operation.payload, "phase") != "admitted" {
        return Err(provider_proposal_refusal(
            "provider_operation_proposal_replayed",
            "the one-time provider proposal was already consumed",
        ));
    }
    let proposal = &admitted.operation.payload;
    if text(proposal, "principal_ref") != caller.identity.principal_ref {
        return Err(provider_proposal_refusal(
            "provider_operation_proposal_principal_mismatch",
            "the proposal belongs to another authenticated principal",
        ));
    }
    if text(proposal, "session_binding") != session_binding {
        return Err(provider_proposal_refusal(
            "provider_operation_proposal_session_mismatch",
            "the proposal belongs to another authenticated session",
        ));
    }
    if proposal
        .get("expires_at_unix")
        .and_then(Value::as_u64)
        .map(|expiry| unix_now() > expiry)
        .unwrap_or(true)
    {
        return Err(provider_proposal_refusal(
            "provider_operation_proposal_expired",
            "the provider proposal expired before consumption",
        ));
    }
    let request_hash = sha256_bytes(&serde_jcs::to_vec(&canonical).map_err(|_| {
        provider_proposal_refusal(
            "provider_operation_proposal_canonicalization_failed",
            "the provider request could not be canonicalized",
        )
    })?);
    if text(proposal, "request_hash") != request_hash
        || text(proposal, "provider_id") != text(&canonical, "provider_id")
        || text(proposal, "operation_kind") != text(&canonical, "op")
        || text(proposal, "environment_ref") != text(&canonical, "environment_ref")
    {
        return Err(provider_proposal_refusal(
            "provider_operation_proposal_request_mismatch",
            "the live provider request or its bound facets changed after proposal issuance",
        ));
    }
    let consumption_receipt_ref = format!(
        "provider-operation-proposal-consumption://{}",
        sha256_bytes(
            format!(
                "{supplied_ref}\0{}\0{request_hash}",
                text(proposal, "one_time_nonce")
            )
            .as_bytes()
        )
        .trim_start_matches("sha256:")
    );
    let consume_caller = super::mutation_event_foundation::WriteCaller {
        identity: caller.identity.clone(),
        owner_ref: caller.owner_ref.clone(),
        idempotency_key: format!("{}.proposal.consume", caller.idempotency_key),
    };
    let payload = json!({
        "schema_version": "ioi.hypervisor.provider-operation-proposal-consumption.v1",
        "phase": "consumed",
        "proposal_ref": supplied_ref,
        "proposal_admission_root": admitted.head,
        "principal_ref": caller.identity.principal_ref,
        "session_binding": session_binding,
        "request_hash": request_hash,
        "one_time_nonce_hash": sha256_bytes(text(proposal, "one_time_nonce").as_bytes()),
        "proposal_consumption_receipt_ref": consumption_receipt_ref,
    });
    let commit = super::mutation_event_foundation::admit_owner_scoped_write(
        data_dir,
        &consume_caller,
        PROVIDER_PROPOSAL_NAMESPACE,
        PROVIDER_PROPOSAL_KIND,
        supplied_ref,
        "provider_operation_proposal.consumed",
        Some(&admitted.head),
        &payload,
    )?;
    if commit.replayed {
        return Err(provider_proposal_refusal(
            "provider_operation_proposal_replayed",
            "the one-time provider proposal was already consumed",
        ));
    }
    Ok(json!({
        "proposal_ref": supplied_ref,
        "principal_ref": caller.identity.principal_ref,
        "proposal_admission_root": admitted.head,
        "proposal_consumption_root": commit.projection.head,
        "proposal_admission_receipt_ref": proposal["proposal_admission_receipt_ref"],
        "proposal_consumption_receipt_ref": consumption_receipt_ref,
        "request_hash": request_hash
    }))
}

/// POST /v1/hypervisor/provider-operation-proposals — authenticate and durably admit one exact
/// live provider request. The response contains only an opaque one-time reference, never a
/// self-authorizing proposal object.
pub(crate) async fn handle_provider_operation_proposal_issue(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let caller =
        match super::mutation_event_foundation::require_write_caller(&st.data_dir, &headers, &body)
        {
            Ok(caller) => caller,
            Err(reply) => return reply,
        };
    let session_binding = match provider_proposal_session_binding(&headers) {
        Ok(binding) => binding,
        Err(reply) => return reply,
    };
    match issue_provider_operation_proposal(&st.data_dir, &caller, &session_binding, &body) {
        Ok(proposal) => (StatusCode::CREATED, Json(proposal)),
        Err(reply) => reply,
    }
}

/// POST /v1/hypervisor/provider-ops — body-dispatched provider lifecycle op (collision-safe).
/// Body: `{ provider_id, op, environment_ref?, plan?, command?, material_ref?, grant_ref? }`.
/// op ∈ preflight | create | start | workrun | stop | snapshot | restore | inject_outage |
/// recover | delete | observe. Records an admitted-operation record + a provider receipt.
/// C2 phase 1 — the INTENT body of a provider-operation journal entry, committed
/// BEFORE the external effect. It carries only what is known pre-effect: the model
/// proposal (by hash), the authority (grant + lease), custody (a fingerprint, never
/// the credential), and the canonical request (by hash). Pure + deterministic (JCS)
/// so a retry replays byte-identically under one idempotency key. This is the
/// pre-effect root: if it does not commit, the op is refused and nothing external
/// has happened.
#[allow(clippy::too_many_arguments)]
fn provider_operation_intent_payload(
    journal_ref: &str,
    kind: &str,
    op: &str,
    account_ref: &str,
    env_ref: &str,
    operation_proposal: &Value,
    grant_ref: &Value,
    lease_note: &Value,
    credential_fingerprint: &str,
    plan: &Value,
) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.provider-operation-journal.v1",
        "phase": "intent",
        "operation_ref": journal_ref,
        "provider": kind,
        "op": op,
        "account_ref": account_ref,
        "environment_ref": env_ref,
        // the model-authored proposal the daemon is about to execute (C4), by hash
        "model_proposal_hash": sha256_bytes(
            &serde_jcs::to_vec(operation_proposal).unwrap_or_default(),
        ),
        // the authority this crossing carries
        "grant_ref": grant_ref,
        "capability_lease_ref": lease_note.get("lease_id").cloned().unwrap_or(Value::Null),
        // custody WITHOUT the credential — the fingerprint, never the secret
        "credential_fingerprint": credential_fingerprint,
        // the canonical request, as a tamper-anchoring hash — never verbatim
        "request_hash": sha256_bytes(&serde_jcs::to_vec(plan).unwrap_or_default()),
    })
}

/// C2 phase 2 — the OUTCOME body, committed AFTER the external effect as a SUCCESSOR
/// of the intent (expected_head = the intent's head). It carries the completion: the
/// outcome label, the provider evidence (by hash), the receipt, and a back-reference
/// to the pre-effect intent root it finalizes. A lost outcome commit after the effect
/// is `reconciliation_required`, never a refusal.
fn provider_operation_outcome_payload(
    journal_ref: &str,
    outcome: &str,
    evidence: &Value,
    receipt: &Value,
    intent_state_root: &str,
) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.provider-operation-journal.v1",
        "phase": "outcome",
        "operation_ref": journal_ref,
        // binds this completion to the exact pre-effect intent it finalizes
        "intent_state_root": intent_state_root,
        "outcome": outcome,
        // redacted provider evidence, as a tamper-anchoring hash — never verbatim
        "evidence_hash": sha256_bytes(&serde_jcs::to_vec(evidence).unwrap_or_default()),
        "receipt_ref": receipt.clone(),
    })
}

/// U1 result binding — append the authenticated workload result as a successor
/// of the create outcome while retaining the original pre-effect intent root.
/// The journal stores only content hashes and opaque refs; result bytes remain
/// in the bounded workload-result record.
fn provider_operation_result_outcome_payload(
    journal_ref: &str,
    intent_state_root: &str,
    predecessor_state_root: &str,
    evidence: &Value,
    receipt: &Option<String>,
) -> Result<Value, &'static str> {
    let workload = evidence
        .get("workload_result")
        .ok_or("akash_result_outcome_evidence_missing")?;
    let bundle = workload
        .get("bundle")
        .ok_or("akash_result_outcome_bundle_missing")?;
    let hash_at = |name: &str| {
        bundle
            .pointer(&format!("/{name}/sha256"))
            .and_then(Value::as_str)
            .filter(|value| {
                value.len() == 71
                    && value.starts_with("sha256:")
                    && value[7..]
                        .chars()
                        .all(|character| character.is_ascii_hexdigit())
            })
            .map(str::to_string)
            .ok_or("akash_result_outcome_hash_missing")
    };
    Ok(json!({
        "schema_version": "ioi.hypervisor.provider-operation-journal.v1",
        "phase": "outcome",
        "operation_ref": journal_ref,
        "intent_state_root": intent_state_root,
        "predecessor_state_root": predecessor_state_root,
        "outcome": "workload_result_retrieved",
        "evidence_hash": sha256_bytes(&serde_jcs::to_vec(evidence).unwrap_or_default()),
        "workload_result_ref": workload.get("result_ref").cloned().unwrap_or(Value::Null),
        "status_hash": hash_at("status")?,
        "environment_hash": hash_at("environment")?,
        "result_hash": hash_at("results")?,
        "manifest_hash": hash_at("manifest")?,
        "receipt_ref": receipt,
    }))
}

/// C2 — the pre-effect state captured by a committed provider-operation INTENT.
/// Carries the caller (to author the successor outcome under the same owner scope),
/// the op's journal stream ref, and the intent root the outcome must chain to.
struct ProviderJournalIntent {
    caller: super::mutation_event_foundation::WriteCaller,
    journal_ref: String,
    intent_state_root: String,
}

fn bind_akash_create_journal_to_deployment(
    data_dir: &str,
    env_ref: &str,
    intent: &ProviderJournalIntent,
    roots: &[String],
) -> Result<(), String> {
    let mut deployment = read_record_dir(data_dir, AKASH_DEPLOYMENT_KIND)
        .into_iter()
        .find(|record| text(record, "environment_ref") == env_ref)
        .ok_or_else(|| "akash_journal_deployment_absent".to_string())?;
    let effect_root = roots
        .last()
        .filter(|root| !root.is_empty())
        .ok_or_else(|| "akash_journal_effect_root_missing".to_string())?;
    deployment["provider_operation_journal_ref"] = json!(intent.journal_ref);
    deployment["provider_operation_journal_owner_ref"] = json!(intent.caller.owner_ref);
    deployment["provider_operation_intent_root"] = json!(intent.intent_state_root);
    deployment["provider_operation_effect_outcome_root"] = json!(effect_root);
    deployment["provider_operation_current_root"] = json!(effect_root);
    let record_id = text(&deployment, "record_id").to_string();
    persist_record(data_dir, AKASH_DEPLOYMENT_KIND, &record_id, &deployment)
        .map_err(|error| format!("akash_journal_deployment_binding_failed: {error}"))
}

fn commit_akash_result_outcome(
    data_dir: &str,
    caller: &super::mutation_event_foundation::WriteCaller,
    env_ref: &str,
    evidence: &Value,
    receipt: &Option<String>,
) -> Result<Vec<String>, (StatusCode, Json<Value>)> {
    let mut deployment = read_record_dir(data_dir, AKASH_DEPLOYMENT_KIND)
        .into_iter()
        .find(|record| text(record, "environment_ref") == env_ref)
        .ok_or_else(|| {
            provider_op_reconciliation_required(
                "logs",
                "akash",
                env_ref,
                receipt,
                Value::Null,
                "",
                "",
                "the authenticated workload result was fetched but its deployment record is absent",
            )
        })?;
    let journal_ref = text(&deployment, "provider_operation_journal_ref").to_string();
    let intent_root = text(&deployment, "provider_operation_intent_root").to_string();
    let predecessor_root = text(&deployment, "provider_operation_current_root").to_string();
    if journal_ref.is_empty() || intent_root.is_empty() || predecessor_root.is_empty() {
        return Err(provider_op_reconciliation_required(
            "logs",
            "akash",
            env_ref,
            receipt,
            deployment
                .get("provider_native")
                .cloned()
                .unwrap_or(Value::Null),
            &journal_ref,
            &intent_root,
            "the authenticated workload result was fetched but the create journal binding is incomplete",
        ));
    }
    if text(&deployment, "provider_operation_journal_owner_ref") != caller.owner_ref {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "code": "akash_result_outcome_owner_mismatch",
                "message": "the result-binding caller does not own the pre-effect journal"
            })),
        ));
    }
    if deployment
        .get("workload_readiness_proven")
        .and_then(Value::as_bool)
        != Some(true)
        || evidence
            .pointer("/workload_result/retrieved_live")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "code": "akash_result_outcome_readiness_unproven",
                "message": "result bytes cannot finalize the journal without positive workload readiness and live authenticated retrieval"
            })),
        ));
    }
    let payload = provider_operation_result_outcome_payload(
        &journal_ref,
        &intent_root,
        &predecessor_root,
        evidence,
        receipt,
    )
    .map_err(|reason| {
        (
            StatusCode::CONFLICT,
            Json(json!({ "ok": false, "code": reason })),
        )
    })?;
    let result_hash = text(&payload, "result_hash").to_string();
    let status_hash = text(&payload, "status_hash").to_string();
    let environment_hash = text(&payload, "environment_hash").to_string();
    let manifest_hash = text(&payload, "manifest_hash").to_string();
    let existing_root = text(&deployment, "provider_operation_result_outcome_root");
    if !existing_root.is_empty() {
        if text(&deployment, "workload_result_hash") == result_hash
            && text(&deployment, "workload_status_hash") == status_hash
            && text(&deployment, "workload_environment_hash") == environment_hash
            && text(&deployment, "workload_manifest_hash") == manifest_hash
        {
            return Ok(vec![
                intent_root,
                predecessor_root,
                existing_root.to_string(),
            ]);
        }
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "code": "akash_result_bundle_changed_after_commit",
                "message": "the completed workload result changed after its outcome root committed"
            })),
        ));
    }
    let outcome_caller = super::mutation_event_foundation::WriteCaller {
        identity: caller.identity.clone(),
        owner_ref: caller.owner_ref.clone(),
        idempotency_key: format!("{}.workload-result-outcome", caller.idempotency_key),
    };
    let commit = super::mutation_event_foundation::admit_owner_scoped_write(
        data_dir,
        &outcome_caller,
        "hypervisor-provider-operations",
        "provider_operation",
        &journal_ref,
        "provider_operation.workload_result_outcome",
        Some(&predecessor_root),
        &payload,
    )
    .map_err(|_| {
        provider_op_reconciliation_required(
            "logs",
            "akash",
            env_ref,
            receipt,
            deployment
                .get("provider_native")
                .cloned()
                .unwrap_or(Value::Null),
            &journal_ref,
            &intent_root,
            "the authenticated workload result was fetched but its successor outcome root did not finalize",
        )
    })?;
    deployment["provider_operation_result_outcome_root"] = json!(commit.projection.head);
    deployment["provider_operation_current_root"] = json!(commit.projection.head);
    deployment["workload_result_hash"] = json!(result_hash);
    deployment["workload_status_hash"] = json!(status_hash);
    deployment["workload_environment_hash"] = json!(environment_hash);
    deployment["workload_manifest_hash"] = json!(manifest_hash);
    let record_id = text(&deployment, "record_id").to_string();
    persist_record(data_dir, AKASH_DEPLOYMENT_KIND, &record_id, &deployment).map_err(|_| {
        provider_op_reconciliation_required(
            "logs",
            "akash",
            env_ref,
            receipt,
            deployment
                .get("provider_native")
                .cloned()
                .unwrap_or(Value::Null),
            &journal_ref,
            &intent_root,
            "the result outcome committed but the deployment projection did not retain its root and hashes",
        )
    })?;
    Ok(vec![intent_root, predecessor_root, commit.projection.head])
}

/// C2 phase 2 — commit the OUTCOME as a successor of the intent (expected_head = the
/// intent root). A distinct idempotency key (`.outcome`) means it is never mistaken
/// for a replay of the intent. On success returns the two-entry chain
/// `[intent_root, outcome_root]`; on a lost commit AFTER the external effect it
/// returns `reconciliation_required` — never a refusal.
#[allow(clippy::too_many_arguments)]
fn commit_provider_operation_outcome(
    data_dir: &str,
    intent: &ProviderJournalIntent,
    op: &str,
    provider: &str,
    env_ref: &str,
    outcome_label: &str,
    evidence: &Value,
    receipt: &Option<String>,
    what_happened_on_reconcile: &str,
) -> Result<Vec<String>, (StatusCode, Json<Value>)> {
    let outcome_caller = super::mutation_event_foundation::WriteCaller {
        identity: intent.caller.identity.clone(),
        owner_ref: intent.caller.owner_ref.clone(),
        idempotency_key: format!("{}.outcome", intent.caller.idempotency_key),
    };
    let payload = provider_operation_outcome_payload(
        &intent.journal_ref,
        outcome_label,
        evidence,
        &json!(receipt),
        &intent.intent_state_root,
    );
    match super::mutation_event_foundation::admit_owner_scoped_write(
        data_dir,
        &outcome_caller,
        "hypervisor-provider-operations",
        "provider_operation",
        &intent.journal_ref,
        "provider_operation.outcome",
        Some(&intent.intent_state_root),
        &payload,
    ) {
        Ok(commit) => Ok(vec![
            intent.intent_state_root.clone(),
            commit.projection.head,
        ]),
        Err(_) => Err(provider_op_reconciliation_required(
            op,
            provider,
            env_ref,
            receipt,
            evidence
                .get("provider_native")
                .cloned()
                .unwrap_or(Value::Null),
            &intent.journal_ref,
            &intent.intent_state_root,
            what_happened_on_reconcile,
        )),
    }
}

/// Resolve the direct live-Akash selection contract. The exact provider lives inside the
/// selector so one canonical object is proposal-, request-, grant-, execution-, and receipt-bound.
/// A shadow `plan.provider_address` is rejected rather than allowed to change execution outside
/// the reviewed selector.
fn direct_akash_provider_pin(plan: &Value) -> Result<Option<String>, &'static str> {
    let selector = plan
        .get("provider_selector")
        .ok_or("provider_selector_missing")?;
    let mode = text(selector, "mode");
    let selection = text(selector, "selection");
    let selector_address = text(selector, "provider_address");
    let shadow_address = text(plan, "provider_address");
    match mode {
        "any_marketplace" => {
            if selection != "lowest_qualified_bid" {
                return Err("marketplace_selection_invalid");
            }
            if !selector_address.is_empty() || !shadow_address.is_empty() {
                return Err("marketplace_selector_cannot_carry_provider_pin");
            }
            Ok(None)
        }
        "exact" => {
            if selection != "only_qualified_bid_from_exact_provider" {
                return Err("exact_selection_invalid");
            }
            if !selector_address.starts_with("akash1")
                || selector_address.len() < 20
                || selector_address.chars().any(char::is_whitespace)
            {
                return Err("exact_provider_address_invalid");
            }
            if !shadow_address.is_empty() && shadow_address != selector_address {
                return Err("provider_selector_address_mismatch");
            }
            Ok(Some(selector_address.to_string()))
        }
        _ => Err("provider_selector_mode_invalid"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StandingProviderDrawBounds {
    envelope_hash: [u8; 32],
    policy_hash: [u8; 32],
    deposit_microusd: u64,
    spend_reservation_microusd: u64,
    max_usages: u32,
    max_cumulative_deposit_microusd: u64,
    max_cumulative_spend_microusd: u64,
}

fn decode_sha256_ref(value: &str, label: &str) -> Result<[u8; 32], String> {
    let hex_value = value
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("{label} is not a sha256 ref"))?;
    if hex_value.len() != 64 || hex_value != hex_value.to_ascii_lowercase() {
        return Err(format!("{label} is not 32 lowercase bytes"));
    }
    let decoded = hex::decode(hex_value).map_err(|_| format!("{label} is not hexadecimal"))?;
    let mut output = [0u8; 32];
    output.copy_from_slice(&decoded);
    if output == [0u8; 32] {
        return Err(format!("{label} must not be zero"));
    }
    Ok(output)
}

/// Validate daemon-derived provider facets as a subset of a registered standing envelope.
/// Host/tool-advertised filters are never read here and therefore cannot widen this decision.
fn validate_standing_provider_facets(
    envelope: &Value,
    provider_id: &str,
    op: &str,
    facets: &Value,
) -> Result<StandingProviderDrawBounds, String> {
    const CONTRACT: &str = "schema://ioi/foundations/standing-authority-envelope/v1";
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        CONTRACT, envelope,
    )
    .map_err(|error| format!("standing envelope is not registered-contract valid: {error}"))?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    if envelope
        .get("not_before_ms")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX)
        > now_ms
        || envelope
            .get("expires_at_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            < now_ms
    {
        return Err("standing_envelope_outside_validity_window".to_string());
    }
    let template = envelope
        .get("facet_template")
        .ok_or_else(|| "standing envelope has no facet template".to_string())?;
    let equals = |pointer: &str, actual: &Value, code: &str| {
        if envelope.pointer(pointer) == Some(actual) {
            Ok(())
        } else {
            Err(code.to_string())
        }
    };
    equals(
        "/facet_template/provider_id",
        &json!(provider_id),
        "standing_provider_id_outside_envelope",
    )?;
    if !template
        .get("operations")
        .and_then(Value::as_array)
        .is_some_and(|operations| operations.iter().any(|operation| operation == op))
    {
        return Err("standing_operation_outside_envelope".to_string());
    }
    equals(
        "/facet_template/provider_selector/mode",
        facets
            .pointer("/provider_selector/mode")
            .unwrap_or(&Value::Null),
        "standing_provider_selector_mode_outside_envelope",
    )?;
    equals(
        "/facet_template/provider_selector/selection",
        facets
            .pointer("/provider_selector/selection")
            .unwrap_or(&Value::Null),
        "standing_provider_selection_outside_envelope",
    )?;
    let provider_address = facets
        .get("provider_address")
        .and_then(Value::as_str)
        .ok_or_else(|| "standing_exact_provider_address_missing".to_string())?;
    if !template
        .pointer("/provider_selector/provider_addresses")
        .and_then(Value::as_array)
        .is_some_and(|addresses| addresses.iter().any(|address| address == provider_address))
    {
        return Err("standing_provider_address_outside_envelope".to_string());
    }
    let deposit_usd = facets
        .get("deposit_usd")
        .and_then(Value::as_f64)
        .ok_or_else(|| "standing_deposit_missing".to_string())?;
    let deposit_scaled = deposit_usd * 1_000_000.0;
    if !deposit_scaled.is_finite()
        || deposit_scaled <= 0.0
        || (deposit_scaled.round() - deposit_scaled).abs() > 0.000_001
    {
        return Err("standing_deposit_not_exact_microusd".to_string());
    }
    let deposit_microusd = deposit_scaled.round() as u64;
    if deposit_microusd
        > template
            .get("per_operation_deposit_microusd")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    {
        return Err("standing_deposit_outside_envelope".to_string());
    }
    equals(
        "/facet_template/pricing_ceiling/denom",
        facets.get("ceiling_denom").unwrap_or(&Value::Null),
        "standing_ceiling_denom_outside_envelope",
    )?;
    let requested_ceiling = facets
        .get("ceiling_amount")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "standing_ceiling_amount_invalid".to_string())?;
    let allowed_ceiling = template
        .pointer("/pricing_ceiling/amount")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "standing_envelope_ceiling_invalid".to_string())?;
    if requested_ceiling > allowed_ceiling {
        return Err("standing_ceiling_outside_envelope".to_string());
    }
    for (facet, set_pointer, code) in [
        ("sdl_hash", "/sdl_hashes", "standing_sdl_outside_envelope"),
        (
            "image_digest",
            "/image_digests",
            "standing_image_outside_envelope",
        ),
        (
            "registry_host",
            "/registry_hosts",
            "standing_registry_outside_envelope",
        ),
        (
            "result_credential_ref",
            "/result_destination_refs",
            "standing_result_destination_outside_envelope",
        ),
        (
            "result_tls_server_certificate_sha256",
            "/result_transport_certificate_hashes",
            "standing_result_transport_outside_envelope",
        ),
    ] {
        let value = facets
            .get(facet)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("standing_{facet}_missing"))?;
        if !template
            .pointer(set_pointer)
            .and_then(Value::as_array)
            .is_some_and(|allowed| allowed.iter().any(|candidate| candidate == value))
        {
            return Err(code.to_string());
        }
    }
    equals(
        "/facet_template/auto_topup",
        facets.get("auto_topup").unwrap_or(&Value::Null),
        "standing_auto_topup_outside_envelope",
    )?;
    equals(
        "/facet_template/teardown_policy",
        facets.get("teardown_policy").unwrap_or(&Value::Null),
        "standing_teardown_outside_envelope",
    )?;
    let duration = facets
        .get("max_duration_seconds")
        .and_then(Value::as_u64)
        .ok_or_else(|| "standing_duration_missing".to_string())?;
    if duration
        > template
            .get("max_duration_seconds")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    {
        return Err("standing_duration_outside_envelope".to_string());
    }
    let aggregate = envelope
        .get("aggregate_bounds")
        .ok_or_else(|| "standing_aggregate_bounds_missing".to_string())?;
    Ok(StandingProviderDrawBounds {
        envelope_hash: decode_sha256_ref(text(envelope, "body_hash"), "standing envelope hash")?,
        policy_hash: decode_sha256_ref(
            text(envelope, "trajectory_policy_hash"),
            "standing trajectory policy hash",
        )?,
        deposit_microusd,
        // Until provider-native settlement arrives, reserve the full deposit as the conservative
        // spend bound. Refund reconciliation may reduce exposure but never creates authority.
        spend_reservation_microusd: deposit_microusd,
        max_usages: aggregate
            .get("max_usages")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| "standing_max_usages_invalid".to_string())?,
        max_cumulative_deposit_microusd: aggregate
            .get("max_cumulative_deposit_microusd")
            .and_then(Value::as_u64)
            .ok_or_else(|| "standing_cumulative_deposit_invalid".to_string())?,
        max_cumulative_spend_microusd: aggregate
            .get("max_cumulative_spend_microusd")
            .and_then(Value::as_u64)
            .ok_or_else(|| "standing_cumulative_spend_invalid".to_string())?,
    })
}

const AKASH_REGISTRY_USERNAME_SENTINEL: &str = "__IOI_REGISTRY_USERNAME__";
const AKASH_REGISTRY_PASSWORD_SENTINEL: &str = "__IOI_REGISTRY_PASSWORD__";
const AKASH_RESULT_TOKEN_SENTINEL: &str = "__IOI_AFT_RESULT_BEARER_TOKEN__";

/// Validate that any secret-bearing SDL template uses daemon-resolved connector references.
/// The references and the unexpanded template are bound into C2 and the wallet challenge; the
/// plaintext values are introduced only inside `provision`, after the pre-effect intent commits.
fn validate_akash_sdl_secret_refs(plan: &Value, sdl: &str) -> Result<(), &'static str> {
    let registry_ref = text(plan, "registry_credential_ref");
    let result_ref = text(plan, "result_credential_ref");
    let valid_ref = |reference: &str| {
        reference
            .strip_prefix("connector://")
            .map(|id| id.starts_with("conn_") && !id.chars().any(char::is_whitespace))
            .unwrap_or(false)
    };
    let registry_sentinels = sdl.contains(AKASH_REGISTRY_USERNAME_SENTINEL)
        || sdl.contains(AKASH_REGISTRY_PASSWORD_SENTINEL);
    let result_sentinel = sdl.contains(AKASH_RESULT_TOKEN_SENTINEL);
    if registry_sentinels != !registry_ref.is_empty()
        || (registry_sentinels && !valid_ref(registry_ref))
    {
        return Err("registry_credential_ref_or_sentinel_invalid");
    }
    if result_sentinel != !result_ref.is_empty() || (result_sentinel && !valid_ref(result_ref)) {
        return Err("result_credential_ref_or_sentinel_invalid");
    }
    if registry_sentinels
        && !(sdl.contains(AKASH_REGISTRY_USERNAME_SENTINEL)
            && sdl.contains(AKASH_REGISTRY_PASSWORD_SENTINEL))
    {
        return Err("registry_credential_template_incomplete");
    }
    Ok(())
}

/// Bind the workload-result identity and measurement shape independently of the
/// SDL hash, then require the reviewed SDL to carry the same values. This makes
/// a stale but internally consistent result bundle distinguishable from the
/// exact campaign authorized by the wallet grant.
fn validate_akash_result_contract(plan: &Value, sdl: &str) -> Result<(), &'static str> {
    let result_ref = text(plan, "result_credential_ref");
    let campaign_id = text(plan, "campaign_id");
    let source_commit = text(plan, "benchmark_source_commit");
    let image_digest = text(plan, "image_digest");
    let image_build_identity_sha256 = text(plan, "image_build_identity_sha256");
    let provider_preflight_sha256 = text(plan, "provider_preflight_sha256");
    let protocol_version = text(plan, "benchmark_protocol_version");
    let result_schema = text(plan, "result_schema_version");
    let warmups = plan.get("benchmark_warmups").and_then(Value::as_u64);
    let repeats = plan.get("benchmark_repeats").and_then(Value::as_u64);
    let tls_server_certificate_sha256 = text(plan, "result_tls_server_certificate_sha256");

    if result_ref.is_empty() {
        if !campaign_id.is_empty()
            || !source_commit.is_empty()
            || !image_digest.is_empty()
            || !image_build_identity_sha256.is_empty()
            || !provider_preflight_sha256.is_empty()
            || !protocol_version.is_empty()
            || !result_schema.is_empty()
            || warmups.is_some()
            || repeats.is_some()
            || !tls_server_certificate_sha256.is_empty()
        {
            return Err("akash_result_contract_without_result_credential");
        }
        return Ok(());
    }
    if !tls_server_certificate_sha256
        .strip_prefix("sha256:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest.chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
        })
    {
        return Err("akash_result_tls_certificate_pin_invalid");
    }
    if campaign_id.is_empty()
        || campaign_id.len() > 128
        || !campaign_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        return Err("akash_result_campaign_id_invalid");
    }
    if source_commit.len() != 40
        || !source_commit
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("akash_result_source_commit_invalid");
    }
    if image_digest.len() != 71
        || !image_digest.starts_with("sha256:")
        || !image_digest[7..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("akash_result_image_digest_invalid");
    }
    if !image_build_identity_sha256
        .strip_prefix("sha256:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest.chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
        })
    {
        return Err("akash_result_image_build_identity_invalid");
    }
    if !provider_preflight_sha256
        .strip_prefix("sha256:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest.chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
        })
    {
        return Err("akash_result_provider_preflight_invalid");
    }
    if protocol_version != "res-p4.3.v2"
        || result_schema != "ioi.aft.benchmark-campaign.v1"
        || warmups != Some(1)
        || repeats != Some(5)
    {
        return Err("akash_result_measurement_protocol_invalid");
    }
    for required in [
        format!("AFT_BENCH_CAMPAIGN_ID={campaign_id}"),
        format!("IOI_BENCH_COMMIT={source_commit}"),
        format!("IOI_BENCH_IMAGE_DIGEST={image_digest}"),
        format!("AFT_BENCH_PROTOCOL_VERSION={protocol_version}"),
        format!("AFT_BENCH_WARMUPS={}", warmups.unwrap_or_default()),
        format!("AFT_BENCH_REPEATS={}", repeats.unwrap_or_default()),
    ] {
        if !sdl.contains(&required) {
            return Err("akash_result_contract_sdl_mismatch");
        }
    }
    if !sdl.contains(&format!("@{image_digest}")) {
        return Err("akash_result_image_digest_sdl_mismatch");
    }
    Ok(())
}

fn validate_akash_result_status(dep: &Value, status: &Value) -> Result<(), &'static str> {
    if status.get("campaign_id").and_then(Value::as_str) != Some(text(dep, "campaign_id")) {
        return Err("akash_result_campaign_identity_mismatch");
    }
    match status.get("state").and_then(Value::as_str) {
        Some("complete") => Ok(()),
        Some("failed") => Err("akash_workload_campaign_failed"),
        Some("starting" | "warmup" | "measuring") => Err("akash_result_endpoint_not_complete"),
        _ => Err("akash_result_status_invalid"),
    }
}

fn validate_akash_result_bundle(dep: &Value, bundle: &Value) -> Result<(), &'static str> {
    let expected_campaign = text(dep, "campaign_id");
    let expected_source_commit = text(dep, "benchmark_source_commit");
    let expected_image_digest = text(dep, "image_digest");
    let expected_protocol = text(dep, "benchmark_protocol_version");
    let expected_result_schema = text(dep, "result_schema_version");
    let expected_warmups = dep.get("benchmark_warmups").and_then(Value::as_u64);
    let expected_repeats = dep.get("benchmark_repeats").and_then(Value::as_u64);
    for name in ["status", "environment", "results", "manifest"] {
        let encoded = bundle
            .pointer(&format!("/{name}/body_base64"))
            .and_then(Value::as_str)
            .ok_or("akash_result_raw_body_missing")?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| "akash_result_raw_body_invalid")?;
        let parsed: Value =
            serde_json::from_slice(&raw).map_err(|_| "akash_result_raw_body_invalid")?;
        let raw_hash = sha256_bytes(&raw);
        if bundle
            .pointer(&format!("/{name}/bytes"))
            .and_then(Value::as_u64)
            != Some(raw.len() as u64)
            || bundle
                .pointer(&format!("/{name}/sha256"))
                .and_then(Value::as_str)
                != Some(raw_hash.as_str())
            || bundle.pointer(&format!("/{name}/value")) != Some(&parsed)
        {
            return Err("akash_result_raw_body_mismatch");
        }
    }
    if expected_campaign.is_empty()
        || bundle
            .pointer("/status/value/state")
            .and_then(Value::as_str)
            != Some("complete")
        || bundle
            .pointer("/results/value/schema_version")
            .and_then(Value::as_str)
            != Some(expected_result_schema)
    {
        return Err("akash_result_campaign_not_complete_or_invalid");
    }
    for path in [
        "/status/value/campaign_id",
        "/environment/value/campaign_id",
        "/results/value/campaign_id",
        "/manifest/value/campaign_id",
    ] {
        if bundle.pointer(path).and_then(Value::as_str) != Some(expected_campaign) {
            return Err("akash_result_campaign_identity_mismatch");
        }
    }
    if bundle
        .pointer("/environment/value/schema_version")
        .and_then(Value::as_str)
        != Some("ioi.aft.environment-manifest.v1")
        || bundle
            .pointer("/manifest/value/schema_version")
            .and_then(Value::as_str)
            != Some("ioi.aft.artifact-manifest.v1")
        || bundle
            .pointer("/environment/value/source_commit")
            .and_then(Value::as_str)
            != Some(expected_source_commit)
        || bundle
            .pointer("/environment/value/image_digest")
            .and_then(Value::as_str)
            != Some(expected_image_digest)
        || bundle
            .pointer("/environment/value/protocol_version")
            .and_then(Value::as_str)
            != Some(expected_protocol)
        || bundle
            .pointer("/environment/value/warmups")
            .and_then(Value::as_u64)
            != expected_warmups
        || bundle
            .pointer("/environment/value/measured_passes")
            .and_then(Value::as_u64)
            != expected_repeats
        || bundle
            .pointer("/results/value/measured_passes")
            .and_then(Value::as_u64)
            != expected_repeats
        || bundle
            .pointer("/results/value/row_count_per_pass")
            .and_then(Value::as_u64)
            != Some(10)
    {
        return Err("akash_result_measurement_contract_mismatch");
    }
    let manifest_artifacts = bundle
        .pointer("/manifest/value/artifacts")
        .and_then(Value::as_array)
        .ok_or("akash_result_manifest_artifacts_missing")?;
    for (artifact_name, bundle_name) in [
        ("environment.json", "environment"),
        ("result.json", "results"),
    ] {
        let artifact = manifest_artifacts
            .iter()
            .find(|item| text(item, "name") == artifact_name)
            .ok_or("akash_result_manifest_required_artifact_missing")?;
        if artifact.get("sha256").and_then(Value::as_str)
            != bundle
                .pointer(&format!("/{bundle_name}/sha256"))
                .and_then(Value::as_str)
            || artifact.get("bytes").and_then(Value::as_u64)
                != bundle
                    .pointer(&format!("/{bundle_name}/bytes"))
                    .and_then(Value::as_u64)
        {
            return Err("akash_result_manifest_hash_mismatch");
        }
    }
    Ok(())
}

fn resolve_connector_bearer(data_dir: &str, reference: &str) -> Result<String, String> {
    let connector_id = reference
        .strip_prefix("connector://")
        .ok_or("connector_credential_ref_invalid")?;
    let credential = read_record_dir(data_dir, "connector-credentials")
        .into_iter()
        .find(|record| text(record, "connector_id") == connector_id)
        .ok_or("connector_credential_not_bound")?;
    if !matches!(text(&credential, "kind"), "bearer" | "service-account") {
        return Err("connector_credential_kind_not_supported_for_sdl_injection".into());
    }
    credential["sealed_token"]
        .as_str()
        .and_then(open_scm_token)
        .ok_or_else(|| "connector_credential_unresolvable".into())
}

fn yaml_single_quoted_fragment(value: &str) -> Result<String, String> {
    if value.contains(['\n', '\r']) {
        return Err("connector_credential_contains_forbidden_line_break".into());
    }
    Ok(value.replace('\'', "''"))
}

fn inject_akash_sdl_secrets(
    template: &str,
    registry_json: Option<&str>,
    result_token: Option<&str>,
) -> Result<String, String> {
    let mut expanded = template.to_string();
    if let Some(registry_json) = registry_json {
        let registry: Value = serde_json::from_str(registry_json)
            .map_err(|_| "registry_credential_payload_invalid_json")?;
        let username = registry
            .get("username")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or("registry_credential_username_missing")?;
        let password = registry
            .get("password")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or("registry_credential_password_missing")?;
        expanded = expanded.replace(
            AKASH_REGISTRY_USERNAME_SENTINEL,
            &yaml_single_quoted_fragment(username)?,
        );
        expanded = expanded.replace(
            AKASH_REGISTRY_PASSWORD_SENTINEL,
            &yaml_single_quoted_fragment(password)?,
        );
    }
    if let Some(result_token) = result_token {
        expanded = expanded.replace(
            AKASH_RESULT_TOKEN_SENTINEL,
            &yaml_single_quoted_fragment(result_token)?,
        );
    }
    if [
        AKASH_REGISTRY_USERNAME_SENTINEL,
        AKASH_REGISTRY_PASSWORD_SENTINEL,
        AKASH_RESULT_TOKEN_SENTINEL,
    ]
    .iter()
    .any(|sentinel| expanded.contains(sentinel))
    {
        return Err("akash_sdl_secret_sentinel_unresolved".into());
    }
    Ok(expanded)
}

fn materialize_akash_sdl(data_dir: &str, plan: &Value, template: &str) -> Result<String, String> {
    validate_akash_sdl_secret_refs(plan, template).map_err(str::to_string)?;
    let registry_ref = text(plan, "registry_credential_ref");
    let result_ref = text(plan, "result_credential_ref");
    let registry = if registry_ref.is_empty() {
        None
    } else {
        Some(resolve_connector_bearer(data_dir, registry_ref)?)
    };
    let result = if result_ref.is_empty() {
        None
    } else {
        Some(resolve_connector_bearer(data_dir, result_ref)?)
    };
    inject_akash_sdl_secrets(template, registry.as_deref(), result.as_deref())
}

/// Build a result client that accepts exactly the owner-reviewed leaf
/// certificate. Some Akash ingress controllers expose a provider-local,
/// self-signed certificate without a DNS SAN. We therefore retrieve the leaf
/// without sending application bytes, verify its DER hash against the
/// authority-bound pin, add only that certificate as a trust root, and disable
/// hostname matching for the subsequent HTTPS request. Chain validation stays
/// enabled, so this is not a global invalid-certificate escape hatch.
fn valid_akash_result_host(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && !host.contains('/')
        && !host.contains(':')
        && !host.eq_ignore_ascii_case("localhost")
        && host.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '.' || character == '-'
        })
}

/// Resolve the only two result transports admitted by the U1 contract:
/// provider-terminated HTTPS on a service URI, or workload-terminated TLS on
/// the provider-assigned raw forwarding for the immutable result port 8080.
/// The latter is required by providers that represent `as: 443` as a random
/// TCP forwarding rather than a Gateway hostname. Ambiguous or plaintext
/// forwards refuse instead of guessing.
fn akash_result_endpoint_target(endpoint: &Value) -> Result<(String, u16), &'static str> {
    if let Some(host) = endpoint
        .get("services")
        .and_then(Value::as_object)
        .and_then(|services| {
            services.values().find_map(|service| {
                service
                    .get("uris")
                    .and_then(Value::as_array)
                    .and_then(|uris| uris.first())
                    .and_then(Value::as_str)
            })
        })
    {
        if !valid_akash_result_host(host) {
            return Err("akash_result_endpoint_uri_invalid");
        }
        return Ok((host.to_string(), 443));
    }

    let forwards = endpoint
        .pointer("/forwarded_ports/aft-bench")
        .and_then(Value::as_array)
        .ok_or("akash_result_endpoint_uri_absent")?;
    let mut matches = forwards.iter().filter_map(|forward| {
        let internal_port = forward.get("port")?.as_u64()?;
        let external_port = forward.get("externalPort")?.as_u64()?;
        let protocol = forward.get("proto")?.as_str()?;
        let host = forward.get("host")?.as_str()?;
        (internal_port == 8080
            && protocol.eq_ignore_ascii_case("tcp")
            && (1..=u16::MAX as u64).contains(&external_port)
            && valid_akash_result_host(host))
        .then(|| (host.to_string(), external_port as u16))
    });
    let target = matches.next().ok_or("akash_result_tls_forward_absent")?;
    if matches.next().is_some() {
        return Err("akash_result_tls_forward_ambiguous");
    }
    Ok(target)
}

fn pinned_result_client(
    host: &str,
    port: u16,
    expected_pin: &str,
) -> Result<reqwest::Client, &'static str> {
    let expected = expected_pin
        .strip_prefix("sha256:")
        .filter(|digest| {
            digest.len() == 64
                && digest.chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
        })
        .ok_or("akash_result_tls_certificate_pin_invalid")?;
    let stream = std::net::TcpStream::connect((host, port))
        .map_err(|_| "akash_result_tls_certificate_probe_failed")?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|_| "akash_result_tls_certificate_probe_failed")?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|_| "akash_result_tls_certificate_probe_failed")?;
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|_| "akash_result_tls_certificate_probe_failed")?;
    let tls = connector
        .connect(host, stream)
        .map_err(|_| "akash_result_tls_certificate_probe_failed")?;
    let certificate = tls
        .peer_certificate()
        .map_err(|_| "akash_result_tls_certificate_probe_failed")?
        .ok_or("akash_result_tls_certificate_absent")?;
    let der = certificate
        .to_der()
        .map_err(|_| "akash_result_tls_certificate_invalid")?;
    if sha256_bytes(&der).strip_prefix("sha256:") != Some(expected) {
        return Err("akash_result_tls_certificate_pin_mismatch");
    }
    let root =
        reqwest::Certificate::from_der(&der).map_err(|_| "akash_result_tls_certificate_invalid")?;
    reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(root)
        .danger_accept_invalid_hostnames(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|_| "akash_result_client_build_failed")
}

/// The single final-invoker implementation for static provider adapters. Both the HTTP route and
/// the workload-bound broker enter here, so the guest lane cannot grow a second provider client
/// or persistence path.
pub(crate) fn invoke_static_provider_operation(
    data_dir: &str,
    body: &Value,
) -> (StatusCode, Json<Value>) {
    let provider_id = text(body, "provider_id");
    let op = text(body, "op");
    let env_ref = body
        .get("environment_ref")
        .and_then(Value::as_str)
        .unwrap_or("env-default");
    let Some(provider) = resolve(provider_id) else {
        let receipt = provider_receipt(data_dir, provider_id, env_ref, op, "error");
        return (
            StatusCode::OK,
            Json(json!({
                "ok": false,
                "reason": format!("unknown provider '{provider_id}'"),
                "receipt_ref": receipt
            })),
        );
    };

    let credentials_required = provider
        .capabilities()
        .get("credentials_required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if credentials_required
        && matches!(op, "create" | "start" | "workrun")
        && body.get("grant_ref").and_then(Value::as_str).is_none()
    {
        let receipt = provider_receipt(data_dir, provider_id, env_ref, op, "authority_missing");
        return (
            StatusCode::OK,
            Json(json!({
                "ok": false,
                "op": op,
                "provider": provider_id,
                "reason": "provider credentials are authority-gated; present a grant_ref (effect=provider_credential)",
                "receipt_ref": receipt
            })),
        );
    }

    let plan = body.get("plan").cloned().unwrap_or_else(|| json!({}));
    let command = body
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or("true");
    let material_ref = body
        .get("material_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    let result = match op {
        "preflight" => Ok(provider.preflight(&plan)),
        "create" => provider.create(data_dir, env_ref, &plan),
        "start" => provider.start(data_dir, env_ref),
        "workrun" => provider.workrun(data_dir, env_ref, command),
        "stop" => provider.stop(data_dir, env_ref),
        "snapshot" => provider.snapshot(data_dir, env_ref),
        "restore" => provider.restore(data_dir, env_ref, material_ref),
        "inject_outage" => provider.inject_outage(data_dir, env_ref),
        "recover" => provider.recover(data_dir, env_ref),
        "delete" => provider.delete(data_dir, env_ref),
        "observe" => Ok(provider.observe(data_dir, env_ref)),
        other => Err(format!("unknown op '{other}'")),
    };

    match result {
        Ok(evidence) => {
            let receipt = provider_receipt(data_dir, provider_id, env_ref, op, "ok");
            let op_id = format!("pop_{:x}", nanos());
            let record = json!({
                "schema_version": "ioi.hypervisor.provider-operation.v1",
                "operation_id": op_id,
                "provider": provider_id,
                "environment_ref": env_ref,
                "op": op,
                "evidence": evidence,
                "receipt_ref": receipt,
                "at": iso_now()
            });
            if persist_record(data_dir, "provider-operations", &op_id, &record).is_err() {
                return provider_op_persist_failed(
                    "provider_operation_persistence_failed",
                    op,
                    provider_id,
                    env_ref,
                    &receipt,
                    evidence
                        .get("provider_native")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "the provider op executed but its admitted-operation record did not commit",
                );
            }
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "op": op,
                    "provider": provider_id,
                    "environment_ref": env_ref,
                    "evidence": evidence,
                    "receipt_ref": receipt
                })),
            )
        }
        Err(reason) => {
            let outcome = if reason.contains("NOT_CONFIGURED") {
                "not_configured"
            } else {
                "error"
            };
            let receipt = provider_receipt(data_dir, provider_id, env_ref, op, outcome);
            (
                StatusCode::OK,
                Json(json!({
                    "ok": false,
                    "op": op,
                    "provider": provider_id,
                    "environment_ref": env_ref,
                    "reason": reason,
                    "outcome": outcome,
                    "receipt_ref": receipt
                })),
            )
        }
    }
}

/// Host-only authenticated context used by the workload effect broker.  It contains no bearer
/// session: the principal's current membership is re-resolved when the context is constructed,
/// and the stored proposal-session binding is only a hash used to consume the already admitted
/// daemon proposal.  HTTP callers can never select this path.
#[derive(Clone)]
pub(crate) struct WorkloadBrokerProviderAuthority {
    caller: super::mutation_event_foundation::WriteCaller,
    proposal_session_binding: String,
}

impl WorkloadBrokerProviderAuthority {
    pub(crate) fn resolve(
        data_dir: &str,
        principal_ref: &str,
        owner_ref: &str,
        idempotency_key: &str,
        proposal_session_binding: &str,
        correlation_ref: &str,
    ) -> Result<Self, (StatusCode, Json<Value>)> {
        if idempotency_key.is_empty()
            || idempotency_key.len() > 256
            || idempotency_key.chars().any(char::is_control)
            || !proposal_session_binding.starts_with("sha256:")
            || proposal_session_binding.len() != 71
        {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "ok": false,
                    "code": "workload_broker_authority_binding_invalid",
                    "message": "the host broker authority binding is malformed"
                })),
            ));
        }
        let identity = super::substrate_store::resolve_workload_broker_identity(
            data_dir,
            principal_ref,
            owner_ref,
            correlation_ref,
        )
        .map_err(super::mutation_event_foundation::scope_refusal_reply)?;
        Ok(Self {
            caller: super::mutation_event_foundation::WriteCaller {
                identity,
                owner_ref: owner_ref.to_owned(),
                idempotency_key: idempotency_key.to_owned(),
            },
            proposal_session_binding: proposal_session_binding.to_owned(),
        })
    }
}

fn provider_write_caller(
    data_dir: &str,
    headers: &HeaderMap,
    body: &Value,
    broker_authority: Option<&WorkloadBrokerProviderAuthority>,
) -> Result<super::mutation_event_foundation::WriteCaller, (StatusCode, Json<Value>)> {
    if let Some(authority) = broker_authority {
        if text(body, "owner_ref") != authority.caller.owner_ref
            || text(body, "idempotency_key") != authority.caller.idempotency_key
        {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "ok": false,
                    "code": "workload_broker_owner_binding_mismatch",
                    "message": "the brokered request changed its authenticated owner or idempotency key"
                })),
            ));
        }
        return Ok(authority.caller.clone());
    }
    super::mutation_event_foundation::require_write_caller(data_dir, headers, body)
}

fn provider_request_session_binding(
    headers: &HeaderMap,
    broker_authority: Option<&WorkloadBrokerProviderAuthority>,
) -> Result<String, (StatusCode, Json<Value>)> {
    broker_authority
        .map(|authority| authority.proposal_session_binding.clone())
        .map(Ok)
        .unwrap_or_else(|| provider_proposal_session_binding(headers))
}

pub(crate) async fn handle_provider_op(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    handle_provider_op_internal(st, headers, body, None).await
}

/// Invoke the exact provider route from the trusted host broker without materializing an operator
/// session. The opaque guest capability is consumed by `workload_effect_boundary`; only that
/// module can assemble this authority context from its host-only durable record.
pub(crate) async fn invoke_workload_brokered_provider_operation(
    st: Arc<DaemonState>,
    body: Value,
    authority: WorkloadBrokerProviderAuthority,
) -> (StatusCode, Json<Value>) {
    handle_provider_op_internal(st, HeaderMap::new(), body, Some(authority)).await
}

async fn handle_provider_op_internal(
    st: Arc<DaemonState>,
    headers: HeaderMap,
    body: Value,
    broker_authority: Option<WorkloadBrokerProviderAuthority>,
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
                let receipt = provider_receipt_ext(
                    data_dir,
                    provider_id,
                    &env_ref,
                    op,
                    "credential_unresolved",
                    &json!({ "error": reason }),
                );
                return (
                    StatusCode::PRECONDITION_REQUIRED,
                    Json(
                        json!({ "ok": false, "op": op, "provider": provider_id, "reason": reason, "receipt_ref": receipt }),
                    ),
                );
            }
        };
        let account_id = text(&account, "account_id").to_string();
        let account_ref = text(&account, "account_ref").to_string();
        let kind = text(&account, "kind").to_string();
        // Provider cleanup and reconciliation never need fresh spend authority, but they are
        // still owner-scoped local writes and are authenticated below.
        let akash_live_readiness =
            op == "start" && kind == "akash" && vast_mode(&account) == "live";
        let akash_live_logs_caller =
            if op == "logs" && kind == "akash" && vast_mode(&account) == "live" {
                match provider_write_caller(data_dir, &headers, &body, broker_authority.as_ref()) {
                    Ok(caller) => Some(caller),
                    Err(reply) => return reply,
                }
            } else {
                None
            };
        let akash_live_result_binding = akash_live_logs_caller.is_some()
            && read_record_dir(data_dir, AKASH_DEPLOYMENT_KIND)
                .into_iter()
                .find(|record| text(record, "environment_ref") == env_ref)
                .map(|record| !text(&record, "result_credential_ref").is_empty())
                .unwrap_or(false);
        let mutation = !matches!(
            op,
            "preflight" | "observe" | "logs" | "events" | "reconcile" | "delete"
        ) && !akash_live_readiness;
        let result_binding_caller = if akash_live_result_binding {
            akash_live_logs_caller
        } else {
            None
        };
        if (matches!(op, "reconcile" | "delete") || akash_live_readiness)
            && result_binding_caller.is_none()
        {
            if let Err(reply) =
                provider_write_caller(data_dir, &headers, &body, broker_authority.as_ref())
            {
                return reply;
            }
        }
        let mut vast_gate = Value::Null;
        let mut budget_note = Value::Null;
        let mut lease_note = Value::Null;
        let mut grant_ref = Value::Null;
        let mut proposal_consumption = Value::Null;
        if mutation {
            // 1) external_spend posture is discovered BEFORE any provider mutation.
            match discover_budget(data_dir, &kind, op, &account) {
                Ok(note) => budget_note = note,
                Err(reason) => {
                    let receipt = provider_receipt_ext(
                        data_dir,
                        &kind,
                        &env_ref,
                        op,
                        "budget_blocked",
                        &json!({ "account_ref": account_ref, "error": reason }),
                    );
                    return (
                        StatusCode::CONFLICT,
                        Json(
                            json!({ "ok": false, "op": op, "provider": provider_id, "account_ref": account_ref, "reason": reason, "receipt_ref": receipt }),
                        ),
                    );
                }
            }
            // 1b) vast GUARDED LIFECYCLE: create is QUOTE-GATED. The quote must be fresh (not
            //     expired/superseded), priced, bound to THIS account, and NEVER fixture evidence;
            //     live control plane demands live_evidence, the simulator demands
            //     simulator_evidence (labelled harness, no real spend). Runs AFTER budget
            //     discovery and BEFORE the wallet challenge (canon gate order).
            // The quote gate guards metered kinds ONCE A CONTROL-PLANE MODE IS SET (fixture/
            // simulator/live) — exactly what the capabilities text promises. Mode-less accounts
            // stay credential_preflight_only: create crosses the wallet and fails closed with
            // the named PROVIDER_KIND_LIFECYCLE_NOT_IMPLEMENTED lane (never a fake).
            if matches!(
                kind.as_str(),
                "vast" | "runpod" | "lambda_cloud" | "akash" | "aws" | "gcp" | "azure" | "k8s"
            ) && matches!(op, "create" | "redeploy")
                && !vast_mode(&account).is_empty()
            {
                let direct_akash_marketplace = kind == "akash"
                    && vast_mode(&account) == "live"
                    && body
                        .pointer("/plan/sdl_yaml")
                        .and_then(Value::as_str)
                        .is_some();
                if direct_akash_marketplace {
                    let sdl_yaml = body
                        .pointer("/plan/sdl_yaml")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let deposit_usd = body
                        .pointer("/plan/deposit_usd")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0);
                    let ceiling_amount = body
                        .pointer("/plan/ceiling_amount")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let ceiling_denom = body
                        .pointer("/plan/ceiling_denom")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let selector = body
                        .pointer("/plan/provider_selector")
                        .cloned()
                        .unwrap_or(Value::Null);
                    let provider_pin =
                        direct_akash_provider_pin(body.pointer("/plan").unwrap_or(&Value::Null));
                    let secret_refs = validate_akash_sdl_secret_refs(
                        body.pointer("/plan").unwrap_or(&Value::Null),
                        sdl_yaml,
                    );
                    let result_contract = validate_akash_result_contract(
                        body.pointer("/plan").unwrap_or(&Value::Null),
                        sdl_yaml,
                    );
                    let ceiling_ok = ceiling_denom == "uact"
                        && ceiling_amount
                            .parse::<f64>()
                            .map(|amount| amount > 0.0)
                            .unwrap_or(false);
                    if sdl_yaml.is_empty()
                        || !(deposit_usd > 0.0 && deposit_usd <= AKASH_MAX_DEPLOY_DEPOSIT_USD)
                        || provider_pin.is_err()
                        || secret_refs.is_err()
                        || result_contract.is_err()
                        || !ceiling_ok
                    {
                        let selector_error = provider_pin.err();
                        return (
                            StatusCode::UNPROCESSABLE_ENTITY,
                            Json(json!({
                                "ok": false,
                                "code": "akash_live_marketplace_facets_required",
                                "message": "direct Akash live deployment requires sdl_yaml, bounded deposit_usd, ceiling_amount in uact, and either any_marketplace/lowest_qualified_bid or an exact/only_qualified_bid_from_exact_provider selector",
                                "selector_error": selector_error,
                                "secret_reference_error": secret_refs.err(),
                                "result_contract_error": result_contract.err()
                            })),
                        );
                    }
                    let provider_pin = provider_pin.ok().flatten();
                    vast_gate = json!({
                        "stage": "deployment_intent",
                        "provider_id": provider_id,
                        "deposit_usd": deposit_usd,
                        "ceiling_amount": ceiling_amount,
                        "ceiling_denom": ceiling_denom,
                        "provider_selector": selector,
                        "auto_topup": false,
                        "sdl_yaml": sdl_yaml,
                        "sdl_hash": sha256_bytes(sdl_yaml.as_bytes()),
                        "registry_credential_ref": body.pointer("/plan/registry_credential_ref").cloned().unwrap_or(Value::Null),
                        "registry_host": body.pointer("/plan/registry_host").cloned().unwrap_or(Value::Null),
                        "result_credential_ref": body.pointer("/plan/result_credential_ref").cloned().unwrap_or(Value::Null),
                        "result_tls_server_certificate_sha256": body.pointer("/plan/result_tls_server_certificate_sha256").cloned().unwrap_or(Value::Null),
                        "campaign_id": body.pointer("/plan/campaign_id").cloned().unwrap_or(Value::Null),
                        "benchmark_source_commit": body.pointer("/plan/benchmark_source_commit").cloned().unwrap_or(Value::Null),
                        "image_digest": body.pointer("/plan/image_digest").cloned().unwrap_or(Value::Null),
                        "image_build_identity_sha256": body.pointer("/plan/image_build_identity_sha256").cloned().unwrap_or(Value::Null),
                        "provider_preflight_sha256": body.pointer("/plan/provider_preflight_sha256").cloned().unwrap_or(Value::Null),
                        "benchmark_protocol_version": body.pointer("/plan/benchmark_protocol_version").cloned().unwrap_or(Value::Null),
                        "result_schema_version": body.pointer("/plan/result_schema_version").cloned().unwrap_or(Value::Null),
                        "benchmark_warmups": body.pointer("/plan/benchmark_warmups").cloned().unwrap_or(Value::Null),
                        "benchmark_repeats": body.pointer("/plan/benchmark_repeats").cloned().unwrap_or(Value::Null),
                        "max_duration_seconds": body.pointer("/plan/max_duration_seconds").cloned().unwrap_or(Value::Null),
                        "execution_mode": "live",
                        "teardown_policy": body
                            .get("teardown_policy")
                            .and_then(Value::as_str)
                            .unwrap_or("always_teardown_required"),
                    });
                    if let (Some(gate), Some(provider_address)) =
                        (vast_gate.as_object_mut(), provider_pin)
                    {
                        gate.insert("provider_address".into(), json!(provider_address));
                    }
                } else {
                    let candidate_ref = body
                        .get("candidate_ref")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if candidate_ref.is_empty() {
                        let code = format!("{kind}_candidate_ref_required");
                        let receipt = provider_receipt_ext(
                            data_dir,
                            &kind,
                            &env_ref,
                            op,
                            "quote_gate_refused",
                            &json!({ "account_ref": account_ref, "error": code }),
                        );
                        return (
                            StatusCode::UNPROCESSABLE_ENTITY,
                            Json(
                                json!({ "ok": false, "op": op, "provider": provider_id, "reason": format!("{code} — provisioning is quote-gated; pass the candidate_ref of a fresh, live, priced CloudResourceCandidate"), "receipt_ref": receipt }),
                            ),
                        );
                    }
                    let candidate = read_record_dir(data_dir, "cloud-resource-candidates")
                        .into_iter()
                        .find(|c| text(c, "candidate_ref") == candidate_ref);
                    let refuse = |code: &str, detail: String| {
                        let receipt = provider_receipt_ext(
                            data_dir,
                            &kind,
                            &env_ref,
                            op,
                            "quote_gate_refused",
                            &json!({ "account_ref": account_ref, "candidate_ref": candidate_ref, "error": code }),
                        );
                        (
                            StatusCode::CONFLICT,
                            Json(
                                json!({ "ok": false, "op": op, "provider": provider_id, "reason": format!("{code} — {detail}"), "receipt_ref": receipt }),
                            ),
                        )
                    };
                    let Some(candidate) = candidate else {
                        return refuse(
                            &format!("{kind}_candidate_unknown"),
                            "no such CloudResourceCandidate — refresh candidates and retry".into(),
                        );
                    };
                    if text(&candidate, "provider_account_ref") != account_ref {
                        return refuse(
                            &format!("{kind}_candidate_account_mismatch"),
                            "the candidate belongs to a different provider account".into(),
                        );
                    }
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let expired = candidate
                        .get("expires_epoch")
                        .and_then(Value::as_u64)
                        .map(|e| now > e)
                        .unwrap_or(true);
                    if expired
                        || candidate.get("status").and_then(Value::as_str) == Some("superseded")
                    {
                        return refuse(&format!("{kind}_quote_expired_requires_requote"), "expired or superseded quotes can never mutate — refresh candidates for a fresh quote".into());
                    }
                    let evidence_mode = text(&candidate, "evidence_mode").to_string();
                    let account_mode = vast_mode(&account);
                    if evidence_mode == "fixture_evidence" {
                        return refuse(
                            &format!("{kind}_quote_not_live"),
                            "fixture quotes are advisory forever and can never provision".into(),
                        );
                    }
                    let mode_ok = (account_mode == "live" && evidence_mode == "live_evidence")
                        || (account_mode == "simulator" && evidence_mode == "simulator_evidence");
                    if !mode_ok {
                        return refuse(&format!("{kind}_quote_mode_mismatch"), format!("account control plane is '{account_mode}' but the quote evidence is '{evidence_mode}' — live provisioning demands live quotes; the simulator demands simulator quotes"));
                    }
                    let k8s_unmetered = kind == "k8s"
                        && account
                            .pointer("/endpoint/metered")
                            .map(Value::is_null)
                            .unwrap_or(true);
                    let (price_v, max_hourly_v): (Value, Value) = if k8s_unmetered {
                        // Customer/operator cluster: NO price exists and none is invented — the
                        // exposure plane opens nothing without a sourced price.
                        (Value::Null, Value::Null)
                    } else {
                        let Some(price) = candidate
                            .pointer("/quote/usd_per_hour")
                            .and_then(Value::as_f64)
                        else {
                            let code = if kind == "k8s" {
                                "k8s_metered_posture_unpriced".to_string()
                            } else {
                                format!("{kind}_quote_unpriced")
                            };
                            return refuse(&code, "a candidate without a real sourced price can never provision on a metered posture".into());
                        };
                        let max_hourly = body
                            .get("max_hourly_usd")
                            .and_then(Value::as_f64)
                            .unwrap_or(price);
                        if price > max_hourly {
                            return refuse(
                                &format!("{kind}_price_above_max"),
                                format!(
                                "offer price ${price}/hr exceeds the declared max ${max_hourly}/hr"
                            ),
                            );
                        }
                        // Reservation adequacy: headroom after OPEN exposures must cover this create's
                        // first-hour reservation at the declared max rate. Checked here (not at budget
                        // discovery) because the price is only known once the quote is validated.
                        let headroom = budget_note
                            .get("remaining_headroom_after_reservations")
                            .and_then(Value::as_f64)
                            .unwrap_or(0.0);
                        if headroom - max_hourly < 0.0 {
                            return refuse(&format!("{kind}_budget_reservation_exceeded"), format!("open exposures already reserve the external_spend headroom (remaining ${headroom:.3} < first-hour reservation ${max_hourly:.3}/hr) — tear an instance down or raise the budget"));
                        }
                        (json!(price), json!(max_hourly))
                    };
                    // k8s: the wallet challenge binds the WORKLOAD SPEC + namespace + PVC/service
                    // posture — a canonical spec is built from the request and its hash rides the
                    // facets (admission is namespace-scoped; nothing generic).
                    let k8s_workload: Value = if kind == "k8s" {
                        let namespace = body
                            .get("namespace")
                            .and_then(Value::as_str)
                            .or_else(|| {
                                account
                                    .pointer("/endpoint/namespace")
                                    .and_then(Value::as_str)
                            })
                            .unwrap_or("default")
                            .to_string();
                        let spec = json!({
                            "image": body.get("image").cloned().unwrap_or(json!("ubuntu:24.04")),
                            "resources": body.get("resources").cloned().unwrap_or(json!({ "cpu_milli": 500, "memory_gb": 1, "gpu": 0 })),
                            "pvc": body.get("pvc").cloned().unwrap_or(Value::Null),
                            "service": body.get("service").cloned().unwrap_or(Value::Null),
                            "kubevirt": body.get("kubevirt").cloned().unwrap_or(json!(false)),
                        });
                        let spec_hash = sha256_bytes(spec.to_string().as_bytes());
                        json!({ "namespace": namespace, "workload_spec": spec, "workload_spec_hash": spec_hash,
                            "exec_posture": "kubernetes_exec" })
                    } else {
                        Value::Null
                    };
                    // akash: the wallet challenge binds the DEPLOYMENT SPEC — a canonical SDL is
                    // built from the validated bid candidate; its hash rides the facets.
                    let akash_sdl: Value = if kind == "akash" {
                        let sdl = akash_build_sdl(&candidate, &body);
                        let sdl_hash = sha256_bytes(sdl.to_string().as_bytes());
                        json!({ "sdl": sdl, "sdl_hash": sdl_hash })
                    } else {
                        Value::Null
                    };
                    // aws|gcp: the wallet challenge binds the ENTERPRISE NETWORK POSTURE — explicit
                    // VPC/subnet(/security-group|firewall) config or the labelled default simulator
                    // posture, with reachability flags (public/external IP + SSH ingress).
                    let aws_network: Value = if matches!(kind.as_str(), "aws" | "gcp" | "azure") {
                        let configured = body
                            .get("network")
                            .cloned()
                            .or_else(|| account.pointer("/endpoint/network").cloned())
                            .filter(|n| !n.is_null());
                        let (explicit_label, default_label) = if kind == "gcp" {
                            ("explicit_network_config", "default_network_simulator")
                        } else if kind == "azure" {
                            ("explicit_vnet_config", "default_vnet_simulator")
                        } else {
                            ("explicit_vpc_config", "default_vpc_simulator")
                        };
                        match configured {
                            Some(n) => {
                                let explicit = n.get("vpc_id").is_some()
                                    || n.get("subnet_id").is_some()
                                    || n.get("security_group_id").is_some()
                                    || n.get("network").is_some()
                                    || n.get("subnetwork").is_some()
                                    || n.get("firewall").is_some()
                                    || n.get("vnet").is_some()
                                    || n.get("subnet").is_some()
                                    || n.get("nsg").is_some();
                                let mut posture = n.clone();
                                if let Some(o) = posture.as_object_mut() {
                                    o.entry("public_ip").or_insert(json!(true));
                                    o.entry("ssh_ingress").or_insert(json!(true));
                                    o.insert(
                                        "posture_label".into(),
                                        json!(if explicit {
                                            explicit_label
                                        } else {
                                            default_label
                                        }),
                                    );
                                }
                                posture
                            }
                            None => {
                                json!({ "posture_label": default_label, "public_ip": true, "ssh_ingress": true })
                            }
                        }
                    } else {
                        Value::Null
                    };
                    vast_gate = json!({
                        "candidate_ref": candidate_ref,
                        "quote_ref": candidate["quote_ref"],
                        "namespace": k8s_workload.get("namespace").cloned().unwrap_or(Value::Null),
                        "workload_spec": k8s_workload.get("workload_spec").cloned().unwrap_or(Value::Null),
                        "workload_spec_hash": k8s_workload.get("workload_spec_hash").cloned().unwrap_or(Value::Null),
                        "exec_posture": k8s_workload.get("exec_posture").cloned().unwrap_or(Value::Null),
                        "az": candidate.get("az").cloned().unwrap_or(Value::Null),
                        "project": candidate.get("project").cloned().unwrap_or(Value::Null),
                        "zone": candidate.get("zone").cloned().unwrap_or(Value::Null),
                        "machine_type": candidate.get("machine_type").cloned().unwrap_or(Value::Null),
                        "subscription_id": candidate.get("subscription_id").cloned().unwrap_or(Value::Null),
                        "resource_group": body.get("resource_group").cloned()
                            .or_else(|| candidate.get("resource_group").cloned())
                            .unwrap_or(Value::Null),
                        "location": candidate.get("location").cloned().unwrap_or(Value::Null),
                        "vm_size": candidate.get("vm_size").cloned().unwrap_or(Value::Null),
                        "network_posture": aws_network,
                        "deployment_class": candidate.get("deployment_class").cloned().unwrap_or(Value::Null),
                        "provider_address": candidate.get("provider_address").cloned().unwrap_or(Value::Null),
                        "bid_ref": candidate.get("bid_ref").cloned().unwrap_or(Value::Null),
                        "persistent_storage": candidate.pointer("/storage/persistent_storage").cloned().unwrap_or(Value::Null),
                        "resources": candidate.get("resources").cloned().unwrap_or(Value::Null),
                        "native_rate": candidate.pointer("/quote/native_rate").cloned().unwrap_or(Value::Null),
                        "sdl": akash_sdl.get("sdl").cloned().unwrap_or(Value::Null),
                        "sdl_hash": akash_sdl.get("sdl_hash").cloned().unwrap_or(Value::Null),
                        "restore_material_ref": body.get("restore_material_ref").cloned().unwrap_or(Value::Null),
                        "archive_ref": body.get("archive_ref").cloned().unwrap_or(Value::Null),
                        "offer_id": candidate.pointer("/quote/offer_id").cloned().unwrap_or(Value::Null),
                        "usd_per_hour": price_v,
                        "max_hourly_usd": max_hourly_v,
                        "gpu": candidate.get("gpu").cloned().unwrap_or(Value::Null),
                        "region": body.get("region").cloned()
                            .or_else(|| candidate.get("region").cloned())
                            .or_else(|| candidate.get("regions").and_then(Value::as_array).and_then(|r| r.first().cloned()))
                            .unwrap_or(Value::Null),
                        "instance_type": candidate.get("instance_type").cloned().unwrap_or(Value::Null),
                        "disk_gb": candidate.pointer("/storage/disk_gb").cloned().unwrap_or(Value::Null),
                        "spend_estimate": candidate.get("spend_estimate").cloned().unwrap_or(Value::Null),
                        "execution_mode": if account_mode == "live" { "live" } else { "simulated_control_plane" },
                        "teardown_policy": body.get("teardown_policy").and_then(Value::as_str).unwrap_or("always_teardown_required"),
                    });
                }
            }
            // C4 — models propose, Hypervisor executes. Once the caller presents a
            // wallet grant for a LIVE Akash cast, resolve and consume the opaque,
            // daemon-issued proposal before consuming that wallet capability. A
            // grant-less request still reaches the spend-free authority challenge.
            if matches!(op, "create" | "redeploy")
                && kind == "akash"
                && vast_mode(&account) == "live"
                && ["wallet_approval_grant", "wallet_standing_approval_grant"]
                    .iter()
                    .any(|field| body.get(*field).is_some_and(|grant| !grant.is_null()))
            {
                let caller = match provider_write_caller(
                    data_dir,
                    &headers,
                    &body,
                    broker_authority.as_ref(),
                ) {
                    Ok(caller) => caller,
                    Err(reply) => return reply,
                };
                let session_binding =
                    match provider_request_session_binding(&headers, broker_authority.as_ref()) {
                        Ok(binding) => binding,
                        Err(reply) => return reply,
                    };
                proposal_consumption = match consume_provider_operation_proposal(
                    data_dir,
                    &caller,
                    &session_binding,
                    &body,
                ) {
                    Ok(consumption) => consumption,
                    Err((status, Json(mut refusal))) => {
                        let receipt = provider_receipt_ext(
                            data_dir,
                            &kind,
                            &env_ref,
                            op,
                            "proposal_not_admitted",
                            &json!({
                                "account_ref": account_ref,
                                "admission_code": refusal.get("code").cloned().unwrap_or(Value::Null)
                            }),
                        );
                        if let Some(object) = refusal.as_object_mut() {
                            object.insert("receipt_ref".into(), json!(receipt));
                        }
                        return (status, Json(refusal));
                    }
                };
            }
            // 2) A REAL wallet grant via the capability-lease gateway — 403 challenge echoes the
            //    exact policy/request hashes to mint against; the lease descriptor carries no secret.
            let mut lease_req = CapabilityLeaseRequest {
                authority_provider_ref: "wallet.network".to_string(),
                backing_provider: format!("provider:account:{account_id}"),
                allowed_tools: vec![format!("provider.{op}")],
                resource_refs: vec![account_ref.clone(), env_ref.clone()],
                scopes: vec!["provider.provision".to_string()],
                policy_domain: "hypervisor.provider.op.policy.v1".to_string(),
                request_domain: "hypervisor.provider.op.request.v1".to_string(),
                request_facets: {
                    let mut facets = json!({ "account_ref": account_ref, "op": op, "environment_ref": env_ref, "kind": kind, "external_spend_posture": budget_note.get("scope").cloned().unwrap_or(Value::Null) });
                    if let (Some(target), Some(gate)) =
                        (facets.as_object_mut(), vast_gate.as_object())
                    {
                        for key in [
                            "candidate_ref",
                            "quote_ref",
                            "max_hourly_usd",
                            "gpu",
                            "region",
                            "az",
                            "instance_type",
                            "disk_gb",
                            "project",
                            "zone",
                            "machine_type",
                            "subscription_id",
                            "resource_group",
                            "location",
                            "vm_size",
                            "namespace",
                            "workload_spec_hash",
                            "exec_posture",
                            "network_posture",
                            "deployment_class",
                            "provider_address",
                            "bid_ref",
                            "persistent_storage",
                            "sdl_hash",
                            "registry_credential_ref",
                            "registry_host",
                            "result_credential_ref",
                            "result_tls_server_certificate_sha256",
                            "campaign_id",
                            "benchmark_source_commit",
                            "image_digest",
                            "image_build_identity_sha256",
                            "provider_preflight_sha256",
                            "benchmark_protocol_version",
                            "result_schema_version",
                            "benchmark_warmups",
                            "benchmark_repeats",
                            "max_duration_seconds",
                            "deposit_usd",
                            "ceiling_amount",
                            "ceiling_denom",
                            "provider_selector",
                            "auto_topup",
                            "stage",
                            "restore_material_ref",
                            "archive_ref",
                            "teardown_policy",
                            "execution_mode",
                        ] {
                            if let Some(v) = gate.get(key) {
                                target.insert(key.to_string(), v.clone());
                            }
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
                grant_value: body
                    .get("wallet_approval_grant")
                    .cloned()
                    .unwrap_or(Value::Null),
                standing_draw: None,
            };
            let standing_grant = body
                .get("wallet_standing_approval_grant")
                .cloned()
                .unwrap_or(Value::Null);
            let standing_envelope = body
                .get("standing_authority_envelope")
                .cloned()
                .unwrap_or(Value::Null);
            if !standing_grant.is_null() || !standing_envelope.is_null() {
                if !lease_req.grant_value.is_null() {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(json!({
                            "ok": false,
                            "code": "provider_authority_mode_ambiguous",
                            "message": "present exactly one of wallet_approval_grant or wallet_standing_approval_grant"
                        })),
                    );
                }
                if standing_grant.is_null() || standing_envelope.is_null() {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(json!({
                            "ok": false,
                            "code": "provider_standing_authority_incomplete",
                            "message": "standing authority requires both its signed grant and registered envelope"
                        })),
                    );
                }
                let bounds = match validate_standing_provider_facets(
                    &standing_envelope,
                    provider_id,
                    op,
                    &lease_req.request_facets,
                ) {
                    Ok(bounds) => bounds,
                    Err(reason) => {
                        return (
                            StatusCode::FORBIDDEN,
                            Json(json!({
                                "ok": false,
                                "code": "provider_standing_authority_facets_refused",
                                "reason": reason,
                                "host_mutation": false
                            })),
                        )
                    }
                };
                lease_req.standing_draw = Some(super::lifecycle_routes::StandingCapabilityDraw {
                    grant_value: standing_grant,
                    envelope_hash: bounds.envelope_hash,
                    policy_hash: bounds.policy_hash,
                    estimated_deposit_microusd: bounds.deposit_microusd,
                    estimated_spend_microusd: bounds.spend_reservation_microusd,
                    max_usages: bounds.max_usages,
                    max_cumulative_deposit_microusd: bounds.max_cumulative_deposit_microusd,
                    max_cumulative_spend_microusd: bounds.max_cumulative_spend_microusd,
                });
            }
            match authorize_capability_lease(&st, &lease_req).await {
                Err((status, challenge)) => {
                    let outcome = if status == StatusCode::PRECONDITION_REQUIRED {
                        "credential_unresolved"
                    } else {
                        "authority_missing"
                    };
                    let receipt = provider_receipt_ext(
                        data_dir,
                        &kind,
                        &env_ref,
                        op,
                        outcome,
                        &json!({ "account_ref": account_ref, "budget_discovery": budget_note }),
                    );
                    let mut payload = challenge;
                    if let Some(object) = payload.as_object_mut() {
                        object.insert("receipt_ref".into(), json!(receipt));
                        object.insert("account_ref".into(), json!(account_ref));
                        if !vast_gate.is_null() {
                            object.insert("lease_request_facets".into(), vast_gate.clone());
                            object.insert(
                                "spend_estimate".into(),
                                vast_gate
                                    .get("spend_estimate")
                                    .cloned()
                                    .unwrap_or(Value::Null),
                            );
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
            for (k, v) in gate {
                target.insert(k.clone(), v.clone());
            }
        }
        let command = body
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("true");
        let material_ref = body
            .get("material_ref")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        // C2 phase 1 — the pre-effect INTENT. For a live provider spend, resolve the
        // authenticated owner-scoped caller and commit the intent + pre-effect root
        // BEFORE the external op. If either fails, refuse: nothing external has
        // happened yet, and a receipt written only after a spend cannot "refuse" it.
        // (INV-37; the journal is the shared substrate engine — no second spine.)
        let provider_journal_intent = if matches!(op, "create" | "redeploy")
            && kind == "akash"
            && vast_mode(&account) == "live"
        {
            let caller =
                match provider_write_caller(data_dir, &headers, &body, broker_authority.as_ref()) {
                    Ok(caller) => caller,
                    Err((status, reply)) => return (status, reply),
                };
            let credential_fingerprint = load_account_credential(data_dir, &account_id)
                .map(|c| text(&c, "fingerprint").to_string())
                .unwrap_or_default();
            let journal_ref = format!(
                "provider-operation://{}",
                super::mutation_event_foundation::replay_stable_id(
                    "pop",
                    &caller.owner_ref,
                    &caller.idempotency_key,
                )
            );
            let intent_caller = super::mutation_event_foundation::WriteCaller {
                identity: caller.identity.clone(),
                owner_ref: caller.owner_ref.clone(),
                idempotency_key: format!("{}.intent", caller.idempotency_key),
            };
            let intent_payload = provider_operation_intent_payload(
                &journal_ref,
                &kind,
                op,
                &account_ref,
                &env_ref,
                &proposal_consumption,
                &grant_ref,
                &lease_note,
                &credential_fingerprint,
                &plan,
            );
            match super::mutation_event_foundation::admit_owner_scoped_write(
                data_dir,
                &intent_caller,
                "hypervisor-provider-operations",
                "provider_operation",
                &journal_ref,
                "provider_operation.intent",
                None,
                &intent_payload,
            ) {
                Ok(commit) => Some(ProviderJournalIntent {
                    caller,
                    journal_ref,
                    intent_state_root: commit.projection.head,
                }),
                // The pre-effect root did not commit → refuse; nothing external happened.
                Err((status, reply)) => return (status, reply),
            }
        } else {
            None
        };
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
            "restart" => provider.restart(data_dir, &env_ref),
            "logs" => provider.logs(data_dir, &env_ref),
            "events" => provider.events(data_dir, &env_ref),
            "reconcile" => provider.reconcile(data_dir, &env_ref),
            "redeploy" => provider.redeploy(data_dir, &env_ref, &plan),
            other => Err(format!("unknown op '{other}'")),
        };
        let cost_estimate = budget_note
            .get("cost_estimate")
            .cloned()
            .unwrap_or(Value::Null);
        return match result {
            Ok(evidence) => {
                let receipt = provider_receipt_ext(
                    data_dir,
                    &kind,
                    &env_ref,
                    op,
                    "ok",
                    &json!({
                        "account_ref": account_ref, "grant_ref": grant_ref, "capability_lease": lease_note,
                        "proposal_consumption": proposal_consumption,
                        "cost_estimate": cost_estimate, "budget_discovery": budget_note,
                        "candidate_ref": vast_gate.get("candidate_ref").cloned().unwrap_or(Value::Null),
                        "quote_ref": vast_gate.get("quote_ref").cloned().unwrap_or(Value::Null),
                        "spend_estimate": vast_gate.get("spend_estimate").cloned().unwrap_or(Value::Null),
                        "execution_mode": vast_gate.get("execution_mode").cloned().unwrap_or(Value::Null),
                        "provider_native": evidence.get("provider_native").cloned().unwrap_or(Value::Null),
                        "teardown_state": evidence.get("teardown_state").cloned().unwrap_or(Value::Null),
                        "state_root": evidence.get("state_root").cloned().unwrap_or(Value::Null),
                    }),
                );
                let op_id = format!("pop_{:x}", nanos());
                let mut record = json!({
                    "schema_version": "ioi.hypervisor.provider-operation.v1",
                    "operation_id": op_id, "provider": kind, "account_ref": account_ref,
                    "environment_ref": env_ref, "op": op, "evidence": evidence,
                    "proposal_consumption": proposal_consumption,
                    "capability_lease": lease_note,
                    "grant_ref": grant_ref, "budget_discovery": budget_note, "cost_estimate": cost_estimate,
                    "receipt_ref": receipt, "at": iso_now()
                });
                // W1.2 / MEF-GAP-008 — the provider op ALREADY executed against the provider; a lost
                // admitted-operation record orphans a live (paid) resource from its own observe/stop/
                // delete lane. Refuse, naming the effect + receipt + provider-native ids.
                if persist_record(data_dir, "provider-operations", &op_id, &record).is_err() {
                    return provider_op_persist_failed(
                        "provider_operation_persistence_failed",
                        op,
                        &kind,
                        &env_ref,
                        &receipt,
                        evidence.get("provider_native").cloned().unwrap_or(Value::Null),
                        "the provider op executed against the provider but its admitted-operation record did not commit",
                    );
                }
                // C2 phase 2 (success) — commit the OUTCOME as a successor of the
                // committed intent (expected_head = the intent root), completing the
                // two-phase journal on the SHARED substrate engine (no second spine).
                // The outcome head is a REAL, recomputable, tamper-evident completion
                // root chained to its pre-effect intent. A lost commit AFTER the
                // external effect is reconciliation_required, never a refusal.
                let mut journal_state_roots: Vec<String> = Vec::new();
                if let Some(intent) = provider_journal_intent.as_ref() {
                    match commit_provider_operation_outcome(
                        data_dir,
                        intent,
                        op,
                        &kind,
                        &env_ref,
                        "ok",
                        &evidence,
                        &receipt,
                        "the provider op executed against the provider but its completion root did not finalize",
                    ) {
                        Ok(roots) => {
                            if let Err(error) = bind_akash_create_journal_to_deployment(
                                data_dir,
                                &env_ref,
                                intent,
                                &roots,
                            ) {
                                return provider_op_reconciliation_required(
                                    op,
                                    &kind,
                                    &env_ref,
                                    &receipt,
                                    evidence
                                        .get("provider_native")
                                        .cloned()
                                        .unwrap_or(Value::Null),
                                    &intent.journal_ref,
                                    &intent.intent_state_root,
                                    &format!(
                                        "the create outcome committed but its deployment journal binding did not persist ({error})"
                                    ),
                                );
                            }
                            journal_state_roots = roots;
                        }
                        Err(reconciliation) => return reconciliation,
                    }
                }
                if let Some(caller) = result_binding_caller.as_ref() {
                    match commit_akash_result_outcome(
                        data_dir, caller, &env_ref, &evidence, &receipt,
                    ) {
                        Ok(roots) => journal_state_roots = roots,
                        Err(reconciliation) => return reconciliation,
                    }
                }
                if !journal_state_roots.is_empty() {
                    record["journal_state_roots"] = json!(journal_state_roots);
                    if persist_record(data_dir, "provider-operations", &op_id, &record).is_err() {
                        return provider_op_reconciliation_required(
                            op,
                            &kind,
                            &env_ref,
                            &receipt,
                            evidence.get("provider_native").cloned().unwrap_or(Value::Null),
                            provider_journal_intent
                                .as_ref()
                                .map(|intent| intent.journal_ref.as_str())
                                .unwrap_or(""),
                            provider_journal_intent
                                .as_ref()
                                .map(|intent| intent.intent_state_root.as_str())
                                .unwrap_or(""),
                            "the outcome committed but its durable provider-operation evidence projection did not record the journal roots",
                        );
                    }
                }
                // A terminal provider readback settles the actual debit for the standing draw
                // that created this environment. The original reservation remains monotonic:
                // refunds are evidence, never newly minted authority.
                if let (Some(consumption_id), Some((actual_spend_microusd, settlement))) = (
                    standing_consumption_for_environment(data_dir, &kind, &env_ref),
                    terminal_spend_microusd(&evidence),
                ) {
                    let terminal_evidence: [u8; 32] =
                        Sha256::digest(serde_jcs::to_vec(settlement).unwrap_or_default()).into();
                    let Some(terminal_evidence_ref) = receipt.clone() else {
                        return provider_op_reconciliation_required(
                            op,
                            &kind,
                            &env_ref,
                            &receipt,
                            evidence.get("provider_native").cloned().unwrap_or(Value::Null),
                            provider_journal_intent.as_ref().map(|intent| intent.journal_ref.as_str()).unwrap_or(""),
                            provider_journal_intent.as_ref().map(|intent| intent.intent_state_root.as_str()).unwrap_or(""),
                            "provider settlement is terminal but its durable evidence receipt is missing",
                        );
                    };
                    let settlement_params = SettleStandingApprovalGrantConsumptionParams {
                        consumption_id,
                        terminal_evidence_hash: terminal_evidence,
                        terminal_evidence_ref,
                        actual_spend_microusd,
                    };
                    let authority_settlement = match super::wallet_network_capability_client::settle_standing_approval_grant_consumption(settlement_params).await {
                        Ok(receipt) => receipt,
                        Err(error) => {
                            return provider_op_reconciliation_required(
                                op,
                                &kind,
                                &env_ref,
                                &receipt,
                                evidence.get("provider_native").cloned().unwrap_or(Value::Null),
                                provider_journal_intent.as_ref().map(|intent| intent.journal_ref.as_str()).unwrap_or(""),
                                provider_journal_intent.as_ref().map(|intent| intent.intent_state_root.as_str()).unwrap_or(""),
                                &format!("provider settlement is terminal but wallet.network standing-authority settlement did not commit ({error:?})"),
                            );
                        }
                    };
                    record["standing_authority_settlement"] =
                        serde_json::to_value(authority_settlement).unwrap_or(Value::Null);
                    if persist_record(data_dir, "provider-operations", &op_id, &record).is_err() {
                        return provider_op_reconciliation_required(
                            op,
                            &kind,
                            &env_ref,
                            &receipt,
                            evidence.get("provider_native").cloned().unwrap_or(Value::Null),
                            provider_journal_intent.as_ref().map(|intent| intent.journal_ref.as_str()).unwrap_or(""),
                            provider_journal_intent.as_ref().map(|intent| intent.intent_state_root.as_str()).unwrap_or(""),
                            "wallet.network settled the standing draw but the provider-operation projection did not persist its settlement receipt",
                        );
                    }
                }
                // ── Spend exposure accounting (customer-borne; estimates only, never a bill) ──
                if matches!(op, "create" | "redeploy")
                    && !vast_gate.is_null()
                    && !vast_gate["usd_per_hour"].is_null()
                {
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
                        // C5(b): the real, chain-committed state root(s) from this op's journal
                        // admission — non-empty for a committed live op, not a driver assertion.
                        "state_roots": journal_state_roots.clone(),
                        "estimate_note": "quote-backed ESTIMATE authorized by the grant — no actual provider bill exists here; spend is customer-borne on the customer's own account",
                        "opened_at": iso_now(),
                    });
                    // W1.2 / MEF-GAP-008 — CRITICAL: a live, customer-borne paid instance was just
                    // provisioned; a lost spend-exposure record makes it INVISIBLE to spend
                    // reconciliation and budget headroom. Refuse, naming the live resource.
                    if persist_record(data_dir, EXPOSURE_KIND, &exp_id, &exposure).is_err() {
                        return provider_op_persist_failed(
                            "provider_spend_exposure_persistence_failed",
                            op,
                            &kind,
                            &env_ref,
                            &receipt,
                            evidence.get("provider_native").cloned().unwrap_or(Value::Null),
                            "a live, customer-borne paid instance was provisioned but its spend-exposure record did not commit — it is now INVISIBLE to spend reconciliation and budget headroom",
                        );
                    }
                } else if matches!(
                    kind.as_str(),
                    "vast" | "runpod" | "lambda_cloud" | "akash" | "aws" | "gcp" | "azure" | "k8s"
                ) {
                    if let Some(mut exposure) = open_exposure_for(data_dir, &account_ref, &env_ref)
                    {
                        let exp_id = text(&exposure, "exposure_id").to_string();
                        let mut refs = exposure
                            .get("receipt_refs")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        refs.push(json!(receipt));
                        exposure["receipt_refs"] = json!(refs);
                        let mut roots = exposure
                            .get("state_roots")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        // C5(b): the real chain-committed head(s) for this op, when journaled.
                        for root in &journal_state_roots {
                            roots.push(json!(root));
                        }
                        // Legacy driver-asserted root, retained for non-journaled simulator ops.
                        if let Some(root) = evidence.get("state_root").and_then(Value::as_str) {
                            roots.push(json!(root));
                        }
                        exposure["state_roots"] = json!(roots);
                        if op == "delete" {
                            let destroyed = evidence
                                .pointer("/native_teardown/destroyed")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            exposure["teardown_state"] = evidence
                                .get("teardown_state")
                                .cloned()
                                .unwrap_or(json!("torn_down"));
                            exposure["teardown_receipt_ref"] = json!(receipt);
                            exposure["closed_at"] = json!(iso_now());
                            if destroyed {
                                exposure["status"] = json!("closed");
                            } else {
                                exposure["status"] = json!("closed_with_warning");
                                exposure["warning"] = json!("INCOMPLETE TEARDOWN — the provider-native destroy did not confirm; verify the provider console (exposure may still accrue on the customer's account)");
                            }
                        }
                        // W1.2 / MEF-GAP-008 — a lost update/close leaves the exposure OPEN forever
                        // (or drops a close_with_warning). Refuse so spend reconciliation is not stale.
                        if persist_record(data_dir, EXPOSURE_KIND, &exp_id, &exposure).is_err() {
                            return provider_op_persist_failed(
                                "provider_spend_exposure_persistence_failed",
                                op,
                                &kind,
                                &env_ref,
                                &receipt,
                                evidence.get("provider_native").cloned().unwrap_or(Value::Null),
                                "the exposure update/close did not commit — a delete may leave the exposure OPEN forever, or a close_with_warning was lost; spend reconciliation is now stale",
                            );
                        }
                    }
                }
                (
                    StatusCode::OK,
                    Json(json!({
                        "ok": true,
                        "op": op,
                        "provider": provider_id,
                        "account_ref": account_ref,
                        "environment_ref": env_ref,
                        "evidence": evidence,
                        "receipt_ref": receipt,
                        "cost_estimate": cost_estimate,
                        "proposal_consumption": proposal_consumption,
                        "capability_lease": lease_note,
                        "journal_state_roots": journal_state_roots,
                    })),
                )
            }
            Err(reason) => {
                let outcome = if reason.contains("NOT_IMPLEMENTED") {
                    "not_implemented"
                } else if reason.contains("hash_mismatch") {
                    "restore_refused"
                } else {
                    "error"
                };
                let receipt = provider_receipt_ext(
                    data_dir,
                    &kind,
                    &env_ref,
                    op,
                    outcome,
                    &json!({
                        "account_ref": account_ref, "grant_ref": grant_ref, "capability_lease": lease_note, "error": reason,
                        "candidate_ref": vast_gate.get("candidate_ref").cloned().unwrap_or(Value::Null),
                        "quote_ref": vast_gate.get("quote_ref").cloned().unwrap_or(Value::Null),
                        "execution_mode": vast_gate.get("execution_mode").cloned().unwrap_or(Value::Null),
                    }),
                );
                // C2 phase 2 (failure) — close the committed intent with a `failed`
                // outcome so no intent dangles. A live op that failed may have had a
                // partial external effect; if even the failure-outcome cannot commit,
                // that is reconciliation_required (verify against the intent root).
                if let Some(intent) = provider_journal_intent.as_ref() {
                    if let Err(reconciliation) = commit_provider_operation_outcome(
                        data_dir,
                        intent,
                        op,
                        &kind,
                        &env_ref,
                        outcome,
                        &json!({ "error": reason.clone() }),
                        &receipt,
                        "the provider op failed and its failure-outcome did not finalize; a partial external effect may exist",
                    ) {
                        return reconciliation;
                    }
                }
                (
                    StatusCode::OK,
                    Json(
                        json!({ "ok": false, "op": op, "provider": provider_id, "account_ref": account_ref, "environment_ref": env_ref, "reason": reason, "outcome": outcome, "receipt_ref": receipt }),
                    ),
                )
            }
        };
    }

    // ── Legacy static-adapter lane (local-microvm / loopback-runner / cloud-vpc). ──
    invoke_static_provider_operation(data_dir, &body)
}

/// GET /v1/hypervisor/provider-spend/reconciliation — customer-borne external-spend
/// reconciliation over EXISTING records only (exposures + budgets + receipts). Not billing,
/// not fees, not settlement: every number is backed by receipt refs; actual provider bills
/// are never invented.
pub(crate) async fn handle_spend_reconciliation(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let exposures = read_record_dir(&st.data_dir, EXPOSURE_KIND);
    let budgets = read_record_dir(&st.data_dir, "resource-budgets");
    let budget = budgets
        .iter()
        .find(|b| b["scope"].as_str() == Some("external_spend"));
    let reserved = open_reserved_estimate(&st.data_dir);
    let (limit, spent) = budget
        .map(|b| {
            (
                b["limit"].as_f64().unwrap_or(0.0),
                b["spent"].as_f64().unwrap_or(0.0),
            )
        })
        .unwrap_or((0.0, 0.0));
    let open: Vec<&Value> = exposures
        .iter()
        .filter(|e| text(e, "status") == "open")
        .collect();
    let warned: Vec<&Value> = exposures
        .iter()
        .filter(|e| text(e, "status") == "closed_with_warning")
        .collect();
    let closed: Vec<&Value> = exposures
        .iter()
        .filter(|e| text(e, "status") == "closed")
        .collect();
    let authorized: f64 = exposures
        .iter()
        .filter_map(|e| e.get("max_hourly_usd").and_then(Value::as_f64))
        .sum();
    let open_estimate: f64 = open
        .iter()
        .filter_map(|e| e.get("usd_per_hour").and_then(Value::as_f64))
        .sum();
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

#[cfg(test)]
mod containment_tests {
    use super::*;

    // ---- MEC C4: daemon-issued, exact-request-bound, one-time proposal provenance ----
    fn provider_proposal_caller(
        principal: &str,
        key: &str,
    ) -> super::super::mutation_event_foundation::WriteCaller {
        super::super::mutation_event_foundation::WriteCaller {
            identity: super::super::substrate_store::request_identity_for_test(
                principal,
                ["org://one".to_string()],
            ),
            owner_ref: "org://one".to_string(),
            idempotency_key: key.to_string(),
        }
    }

    fn provider_proposal_request() -> Value {
        json!({
            "provider_id": "pacc_1",
            "op": "create",
            "environment_ref": "env-one",
            "owner_ref": "org://one",
            "idempotency_key": "proposal-one",
            "candidate_ref": "provider-candidate:akash/1",
            "max_hourly_usd": 0.4,
            "plan": { "deposit_usd": 1.0, "sdl_hash": "sha256:one" },
            "wallet_approval_grant": { "grant_ref": "wallet.network://grant/one" }
        })
    }

    #[test]
    fn direct_akash_selector_binds_exact_provider_and_rejects_shadow_or_fallback() {
        let exact = json!({
            "provider_selector": {
                "mode": "exact",
                "provider_address": "akash15tl6v6gd0nte0syyxnv57zmmspgju4c3xfmdhk",
                "selection": "only_qualified_bid_from_exact_provider"
            }
        });
        assert_eq!(
            direct_akash_provider_pin(&exact),
            Ok(Some(
                "akash15tl6v6gd0nte0syyxnv57zmmspgju4c3xfmdhk".to_string()
            ))
        );

        let mut shadow = exact.clone();
        shadow["provider_address"] = json!("akash1differentprovider000000000000000000000");
        assert_eq!(
            direct_akash_provider_pin(&shadow),
            Err("provider_selector_address_mismatch")
        );

        let mut fallback = exact;
        fallback["provider_selector"]["selection"] = json!("lowest_qualified_bid");
        assert_eq!(
            direct_akash_provider_pin(&fallback),
            Err("exact_selection_invalid")
        );
    }

    #[test]
    fn direct_akash_marketplace_selector_cannot_smuggle_a_provider_pin() {
        let marketplace = json!({
            "provider_selector": {
                "mode": "any_marketplace",
                "selection": "lowest_qualified_bid"
            }
        });
        assert_eq!(direct_akash_provider_pin(&marketplace), Ok(None));

        let mut smuggled = marketplace;
        smuggled["provider_address"] = json!("akash15tl6v6gd0nte0syyxnv57zmmspgju4c3xfmdhk");
        assert_eq!(
            direct_akash_provider_pin(&smuggled),
            Err("marketplace_selector_cannot_carry_provider_pin")
        );
    }

    #[test]
    fn standing_provider_facets_are_closed_over_daemon_derived_values() {
        let envelope: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/standing-authority-envelope-v1/positive-u1.json"
        )))
        .expect("standing envelope fixture");
        let facets = json!({
            "provider_selector": {
                "mode": "exact",
                "provider_address": "akash19zzh7whjt4vfwxd5wtj3tjtyatnpntfhldshd8",
                "selection": "only_qualified_bid_from_exact_provider"
            },
            "provider_address": "akash19zzh7whjt4vfwxd5wtj3tjtyatnpntfhldshd8",
            "deposit_usd": 1.0,
            "ceiling_amount": "1000",
            "ceiling_denom": "uact",
            "sdl_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "image_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "registry_host": "ghcr.io",
            "result_credential_ref": "connector://conn_eee2dfac02809de0",
            "result_tls_server_certificate_sha256": format!("sha256:{}", "a".repeat(64)),
            "auto_topup": false,
            "teardown_policy": "always_teardown_required",
            "max_duration_seconds": 3600
        });
        let bounds = validate_standing_provider_facets(
            &envelope,
            "pacc_18cd245812ad55b9",
            "create",
            &facets,
        )
        .expect("exact subset");
        assert_eq!(bounds.deposit_microusd, 1_000_000);
        assert_eq!(bounds.spend_reservation_microusd, 1_000_000);

        let mut widened = facets.clone();
        widened["result_credential_ref"] = json!("connector://attacker");
        assert_eq!(
            validate_standing_provider_facets(
                &envelope,
                "pacc_18cd245812ad55b9",
                "create",
                &widened,
            )
            .unwrap_err(),
            "standing_result_destination_outside_envelope"
        );
        let mut repinned = facets.clone();
        repinned["result_tls_server_certificate_sha256"] =
            json!(format!("sha256:{}", "b".repeat(64)));
        assert_eq!(
            validate_standing_provider_facets(
                &envelope,
                "pacc_18cd245812ad55b9",
                "create",
                &repinned,
            )
            .unwrap_err(),
            "standing_result_transport_outside_envelope"
        );
        let mut expensive = facets;
        expensive["deposit_usd"] = json!(1.000001);
        assert_eq!(
            validate_standing_provider_facets(
                &envelope,
                "pacc_18cd245812ad55b9",
                "create",
                &expensive,
            )
            .unwrap_err(),
            "standing_deposit_outside_envelope"
        );
    }

    #[test]
    fn akash_sdl_secret_injection_is_execution_boundary_only_and_fail_closed() {
        let template = r#"credentials:
  username: '__IOI_REGISTRY_USERNAME__'
  password: '__IOI_REGISTRY_PASSWORD__'
env:
  - 'AFT_RESULT_BEARER_TOKEN=__IOI_AFT_RESULT_BEARER_TOKEN__'
"#;
        let plan = json!({
            "registry_credential_ref": "connector://conn_registry",
            "result_credential_ref": "connector://conn_results"
        });
        assert_eq!(validate_akash_sdl_secret_refs(&plan, template), Ok(()));
        let expanded = inject_akash_sdl_secrets(
            template,
            Some(r#"{"username":"registry-canary","password":"p'ass-canary"}"#),
            Some("result-canary"),
        )
        .expect("valid sealed values expand at execution");
        assert!(expanded.contains("registry-canary"));
        assert!(expanded.contains("p''ass-canary"));
        assert!(expanded.contains("result-canary"));
        assert!(!expanded.contains("__IOI_"));
        assert!(!plan.to_string().contains("canary"));

        assert!(inject_akash_sdl_secrets(template, None, Some("result-canary")).is_err());
        assert_eq!(
            validate_akash_sdl_secret_refs(&json!({}), template),
            Err("registry_credential_ref_or_sentinel_invalid")
        );
    }

    #[test]
    fn akash_plain_sdl_needs_no_secret_connector_refs() {
        let sdl = "services:\n  web:\n    image: nginx@sha256:abc\n";
        assert_eq!(validate_akash_sdl_secret_refs(&json!({}), sdl), Ok(()));
        assert_eq!(
            validate_akash_sdl_secret_refs(
                &json!({ "result_credential_ref": "connector://conn_results" }),
                sdl,
            ),
            Err("result_credential_ref_or_sentinel_invalid")
        );
    }

    #[test]
    fn akash_result_contract_binds_campaign_source_image_protocol_and_run_count() {
        let commit = "b".repeat(40);
        let digest = format!("sha256:{}", "a".repeat(64));
        let plan = json!({
            "result_credential_ref": "connector://conn_results",
            "result_tls_server_certificate_sha256": format!("sha256:{}", "c".repeat(64)),
            "campaign_id": "u1-campaign-a",
            "benchmark_source_commit": commit,
            "image_digest": digest,
            "image_build_identity_sha256": format!("sha256:{}", "d".repeat(64)),
            "provider_preflight_sha256": format!("sha256:{}", "e".repeat(64)),
            "benchmark_protocol_version": "res-p4.3.v2",
            "result_schema_version": "ioi.aft.benchmark-campaign.v1",
            "benchmark_warmups": 1,
            "benchmark_repeats": 5,
        });
        let sdl = format!(
            r#"services:
  aft:
    image: ghcr.io/ioi/aft@{digest}
    env:
      - 'AFT_BENCH_CAMPAIGN_ID=u1-campaign-a'
      - 'IOI_BENCH_COMMIT={commit}'
      - 'IOI_BENCH_IMAGE_DIGEST={digest}'
      - 'AFT_BENCH_PROTOCOL_VERSION=res-p4.3.v2'
      - 'AFT_BENCH_WARMUPS=1'
      - 'AFT_BENCH_REPEATS=5'
"#
        );
        assert_eq!(validate_akash_result_contract(&plan, &sdl), Ok(()));

        let mut unpinned = plan.clone();
        unpinned["result_tls_server_certificate_sha256"] = Value::Null;
        assert_eq!(
            validate_akash_result_contract(&unpinned, &sdl),
            Err("akash_result_tls_certificate_pin_invalid")
        );

        let mut stale = plan.clone();
        stale["campaign_id"] = json!("u1-campaign-b");
        assert_eq!(
            validate_akash_result_contract(&stale, &sdl),
            Err("akash_result_contract_sdl_mismatch")
        );
        let mut shortened = plan;
        shortened["benchmark_repeats"] = json!(4);
        assert_eq!(
            validate_akash_result_contract(&shortened, &sdl),
            Err("akash_result_measurement_protocol_invalid")
        );
    }

    #[test]
    fn akash_result_bundle_rejects_stale_partial_and_tampered_campaigns() {
        fn response(value: Value) -> Value {
            let raw = serde_json::to_vec(&value).unwrap();
            json!({
                "value": value,
                "sha256": sha256_bytes(&raw),
                "bytes": raw.len(),
                "body_base64": base64::engine::general_purpose::STANDARD.encode(&raw),
            })
        }
        let commit = "b".repeat(40);
        let digest = format!("sha256:{}", "a".repeat(64));
        let dep = json!({
            "campaign_id": "u1-campaign-a",
            "benchmark_source_commit": commit,
            "image_digest": digest,
            "benchmark_protocol_version": "res-p4.3.v2",
            "result_schema_version": "ioi.aft.benchmark-campaign.v1",
            "benchmark_warmups": 1,
            "benchmark_repeats": 5,
        });
        let status = response(json!({
            "campaign_id": "u1-campaign-a", "state": "complete"
        }));
        let environment = response(json!({
            "schema_version": "ioi.aft.environment-manifest.v1",
            "campaign_id": "u1-campaign-a",
            "source_commit": commit,
            "image_digest": digest,
            "protocol_version": "res-p4.3.v2",
            "warmups": 1,
            "measured_passes": 5
        }));
        let results = response(json!({
            "schema_version": "ioi.aft.benchmark-campaign.v1",
            "campaign_id": "u1-campaign-a",
            "measured_passes": 5,
            "row_count_per_pass": 10
        }));
        let manifest = response(json!({
            "schema_version": "ioi.aft.artifact-manifest.v1",
            "campaign_id": "u1-campaign-a",
            "artifacts": [
                { "name": "environment.json", "sha256": environment["sha256"], "bytes": environment["bytes"] },
                { "name": "result.json", "sha256": results["sha256"], "bytes": results["bytes"] }
            ]
        }));
        let bundle = json!({
            "status": status,
            "environment": environment,
            "results": results,
            "manifest": manifest,
        });
        assert_eq!(validate_akash_result_bundle(&dep, &bundle), Ok(()));

        let mut stale = bundle.clone();
        stale["results"]["value"]["campaign_id"] = json!("u1-campaign-b");
        stale["results"] = response(stale["results"]["value"].clone());
        assert_eq!(
            validate_akash_result_bundle(&dep, &stale),
            Err("akash_result_campaign_identity_mismatch")
        );
        let mut partial = bundle.clone();
        partial["results"]["value"]["row_count_per_pass"] = json!(9);
        partial["results"] = response(partial["results"]["value"].clone());
        assert_eq!(
            validate_akash_result_bundle(&dep, &partial),
            Err("akash_result_measurement_contract_mismatch")
        );
        let mut raw_mismatch = bundle.clone();
        raw_mismatch["results"]["value"]["row_count_per_pass"] = json!(9);
        assert_eq!(
            validate_akash_result_bundle(&dep, &raw_mismatch),
            Err("akash_result_raw_body_mismatch")
        );
        let mut tampered = bundle;
        tampered["manifest"]["value"]["artifacts"][1]["sha256"] = json!("sha256:different");
        tampered["manifest"] = response(tampered["manifest"]["value"].clone());
        assert_eq!(
            validate_akash_result_bundle(&dep, &tampered),
            Err("akash_result_manifest_hash_mismatch")
        );
    }

    #[test]
    fn akash_result_status_distinguishes_incomplete_failed_and_complete_campaigns() {
        let dep = json!({"campaign_id": "u1-campaign-a"});
        for state in ["starting", "warmup", "measuring"] {
            assert_eq!(
                validate_akash_result_status(
                    &dep,
                    &json!({"campaign_id": "u1-campaign-a", "state": state}),
                ),
                Err("akash_result_endpoint_not_complete")
            );
        }
        assert_eq!(
            validate_akash_result_status(
                &dep,
                &json!({"campaign_id": "u1-campaign-a", "state": "failed"}),
            ),
            Err("akash_workload_campaign_failed")
        );
        assert_eq!(
            validate_akash_result_status(
                &dep,
                &json!({"campaign_id": "u1-campaign-a", "state": "complete"}),
            ),
            Ok(())
        );
        assert_eq!(
            validate_akash_result_status(
                &dep,
                &json!({"campaign_id": "u1-campaign-b", "state": "complete"}),
            ),
            Err("akash_result_campaign_identity_mismatch")
        );
        assert_eq!(
            validate_akash_result_status(
                &dep,
                &json!({"campaign_id": "u1-campaign-a", "state": "unknown"}),
            ),
            Err("akash_result_status_invalid")
        );
    }

    #[test]
    fn akash_result_target_accepts_only_one_tls_capable_provider_endpoint() {
        let uri = json!({
            "services": {"aft-bench": {"uris": ["result.ingress.provider.example"]}}
        });
        assert_eq!(
            akash_result_endpoint_target(&uri),
            Ok(("result.ingress.provider.example".into(), 443))
        );

        let forwarded = json!({
            "services": {"aft-bench": {"uris": null}},
            "forwarded_ports": {"aft-bench": [{
                "port": 8080,
                "externalPort": 30284,
                "proto": "TCP",
                "host": "provider.example"
            }]}
        });
        assert_eq!(
            akash_result_endpoint_target(&forwarded),
            Ok(("provider.example".into(), 30284))
        );

        let mut plaintext_or_wrong_port = forwarded.clone();
        plaintext_or_wrong_port["forwarded_ports"]["aft-bench"][0]["port"] = json!(80);
        assert_eq!(
            akash_result_endpoint_target(&plaintext_or_wrong_port),
            Err("akash_result_tls_forward_absent")
        );

        let mut ambiguous = forwarded;
        let duplicate = ambiguous["forwarded_ports"]["aft-bench"][0].clone();
        ambiguous["forwarded_ports"]["aft-bench"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert_eq!(
            akash_result_endpoint_target(&ambiguous),
            Err("akash_result_tls_forward_ambiguous")
        );
    }

    #[test]
    fn daemon_issued_proposal_consumes_once_and_replay_refuses() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let caller = provider_proposal_caller("user://proposal-one", "proposal-one");
        let request = provider_proposal_request();
        let issued = issue_provider_operation_proposal(data_dir, &caller, "session:one", &request)
            .expect("daemon issuance admits");
        let mut cast = request;
        cast["operation_proposal_ref"] = issued["proposal_ref"].clone();
        let consumed = consume_provider_operation_proposal(data_dir, &caller, "session:one", &cast)
            .expect("the exact request consumes once");
        assert!(text(&consumed, "proposal_consumption_root").starts_with("sha256:"));
        let (_, Json(replay)) =
            consume_provider_operation_proposal(data_dir, &caller, "session:one", &cast)
                .expect_err("replay must refuse");
        assert_eq!(
            text(&replay, "code"),
            "provider_operation_proposal_replayed"
        );
        super::super::substrate_store::reset_handle_for_test();
    }

    #[test]
    fn inline_literal_tamper_and_session_substitution_all_refuse() {
        assert_eq!(
            text(
                &canonical_provider_proposal_request(&json!({
                    "operation_proposal": { "proposal_source": "daemon-provider-operation-proposal" }
                }))
                .unwrap_err()
                .1
                 .0,
                "code"
            ),
            "provider_operation_inline_proposal_forbidden"
        );

        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let caller = provider_proposal_caller("user://proposal-two", "proposal-one");
        let request = provider_proposal_request();
        let issued = issue_provider_operation_proposal(data_dir, &caller, "session:one", &request)
            .expect("daemon issuance admits");
        let mut cast = request.clone();
        cast["operation_proposal_ref"] = issued["proposal_ref"].clone();
        let (_, Json(session_refusal)) =
            consume_provider_operation_proposal(data_dir, &caller, "session:other", &cast)
                .expect_err("cross-session substitution refuses");
        assert_eq!(
            text(&session_refusal, "code"),
            "provider_operation_proposal_session_mismatch"
        );

        cast["plan"]["deposit_usd"] = json!(2.0);
        let (_, Json(tamper_refusal)) =
            consume_provider_operation_proposal(data_dir, &caller, "session:one", &cast)
                .expect_err("body tamper refuses");
        assert_eq!(
            text(&tamper_refusal, "code"),
            "provider_operation_proposal_request_mismatch"
        );
        super::super::substrate_store::reset_handle_for_test();
    }

    #[test]
    fn terminal_provider_settlement_and_exhausted_authority_survive_restart() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let provider = AkashProvider {
            account: json!({
                "account_id": "pacc_restart",
                "account_ref": "provider-account://pacc_restart",
                "kind": "akash",
                "mode": "live"
            }),
        };
        let mut deployment = json!({
            "record_id": "akdep_restart",
            "deployment_ref": "akash-deployment://akdep_restart",
            "account_id": "pacc_restart",
            "environment_ref": "env-restart",
            "execution_mode": "live",
            "deposit_usd": 1.0,
            "state": "refund_pending",
            "status": "refund_pending",
            "events": []
        });
        provider
            .save_deployment(data_dir, &deployment)
            .expect("pre-terminal deployment persists");
        provider
            .save_lease(
                data_dir,
                &json!({
                    "record_id": "aklease_restart",
                    "lease_ref": "akash-lease://aklease_restart",
                    "deployment_ref": "akash-deployment://akdep_restart",
                    "state": "open"
                }),
            )
            .expect("provider spend projection persists");
        persist_record(
            data_dir,
            "capability-leases",
            "lease_restart",
            &json!({
                "lease_id": "lease_restart",
                "resource_refs": ["provider-account://pacc_restart", "env-restart"],
                "remaining_calls": 0,
                "state": "active"
            }),
        )
        .expect("consumed authority projection persists");
        let detail = json!({ "data": {
            "deployment": { "state": "closed" },
            "escrow_account": { "state": {
                "state": "closed",
                "settled_at": "28269748",
                "funds": [{ "amount": "0.000000000000000000", "denom": "uact" }],
                "transferred": [{ "amount": "0.000000000000000000", "denom": "uact" }]
            }},
            "leases": []
        }});
        provider
            .settle_from_detail(data_dir, &mut deployment, &detail)
            .expect("terminal readback commits");

        // Re-open all durable projections as a fresh daemon would.
        super::super::substrate_store::reset_handle_for_test();
        let restored = provider
            .deployment(data_dir, "env-restart")
            .expect("deployment survives restart");
        assert_eq!(text(&restored, "settlement_state"), "refund_settled");
        assert_eq!(text(&restored, "teardown_state"), "torn_down");
        assert_eq!(
            restored["provider_native_settlement"]["final_debit_usd"],
            0.0
        );
        assert_eq!(restored["provider_native_settlement"]["refund_usd"], 1.0);
        let provider_lease = provider
            .lease_for(data_dir, "akash-deployment://akdep_restart")
            .expect("provider lease projection survives restart");
        assert_eq!(text(&provider_lease, "state"), "closed");
        let lease = read_record_dir(data_dir, "capability-leases")
            .into_iter()
            .find(|record| text(record, "lease_id") == "lease_restart")
            .expect("authority projection survives restart");
        assert_eq!(text(&lease, "state"), "exhausted");
        super::super::substrate_store::reset_handle_for_test();
    }

    #[test]
    fn standing_draw_identity_and_terminal_debit_are_derived_from_durable_provider_truth() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        let consumption_id = [0x5a; 32];
        persist_record(
            data_dir,
            "provider-operations",
            "pop-standing-create",
            &json!({
                "operation_id": "pop-standing-create",
                "provider": "akash",
                "environment_ref": "env-standing",
                "op": "create",
                "at": "2026-08-22T10:00:00Z",
                "capability_lease": {
                    "authority_mode": "standing_envelope",
                    "standing_consumption_id": hex::encode(consumption_id)
                }
            }),
        )
        .expect("persist standing create");
        assert_eq!(
            standing_consumption_for_environment(data_dir, "akash", "env-standing"),
            Some(consumption_id)
        );
        assert_eq!(
            standing_consumption_for_environment(data_dir, "akash", "other-environment"),
            None
        );

        let evidence = json!({
            "settlement": {
                "provider_terminal": true,
                "final_debit_usd": 0.000002,
                "refund_usd": 0.999998,
                "open_unknown_exposure_usd": 0
            }
        });
        let (debit, _) = terminal_spend_microusd(&evidence).expect("terminal debit");
        assert_eq!(debit, 2);
        let mut nonterminal = evidence;
        nonterminal["settlement"]["provider_terminal"] = json!(false);
        assert!(terminal_spend_microusd(&nonterminal).is_none());
    }

    // ---- MEC C2/C5(b): the two-phase provider-operation journal (intent → outcome) ----
    fn journal_caller_for_test(key: &str) -> super::super::mutation_event_foundation::WriteCaller {
        super::super::mutation_event_foundation::WriteCaller {
            identity: super::super::substrate_store::request_identity_for_test(
                "user://mec-c2",
                ["org://one".to_string()],
            ),
            owner_ref: "org://one".to_string(),
            idempotency_key: key.to_string(),
        }
    }

    fn sample_intent_payload(journal_ref: &str) -> Value {
        provider_operation_intent_payload(
            journal_ref,
            "akash",
            "create",
            "provider-account://pacc_1",
            "environment:1",
            &json!({ "proposal_ref": "proposal:provider/1" }),
            &json!("grant://one"),
            &json!({ "lease_id": "lease://one" }),
            "sha256:deadbeefcafe",
            &json!({ "sdl": "manifest", "deposit": { "amount": "500000" } }),
        )
    }

    #[test]
    fn the_two_phase_journal_commits_an_intent_then_an_outcome_that_chains_to_it() {
        // Phase 1 (genesis intent) then phase 2 (successor outcome, expected_head =
        // the intent root). Both roots are real, recomputable sha256 chain heads;
        // the outcome commit only admits BECAUSE it chains to the exact intent root.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let caller = journal_caller_for_test("c2-op-1");
        let journal_ref = "provider-operation://pop_c2_1";

        let intent = super::super::mutation_event_foundation::admit_owner_scoped_write(
            data_dir,
            &super::super::mutation_event_foundation::WriteCaller {
                identity: caller.identity.clone(),
                owner_ref: caller.owner_ref.clone(),
                idempotency_key: format!("{}.intent", caller.idempotency_key),
            },
            "hypervisor-provider-operations",
            "provider_operation",
            journal_ref,
            "provider_operation.intent",
            None,
            &sample_intent_payload(journal_ref),
        )
        .expect("the pre-effect intent admits");
        assert!(intent.projection.head.starts_with("sha256:"));

        let intent_state = ProviderJournalIntent {
            caller,
            journal_ref: journal_ref.to_string(),
            intent_state_root: intent.projection.head.clone(),
        };
        let roots = commit_provider_operation_outcome(
            data_dir,
            &intent_state,
            "create",
            "akash",
            "environment:1",
            "ok",
            &json!({ "provider_native": { "dseq": "123" } }),
            &Some("agentgres://provider-receipt/1".to_string()),
            "unused in this success path",
        )
        .expect("the outcome commits as a successor of the intent");
        // Two-entry chain: [intent_root, outcome_root], distinct, both real.
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0], intent.projection.head);
        assert!(roots[1].starts_with("sha256:"));
        assert_ne!(roots[0], roots[1]);
    }

    #[test]
    fn a_lost_outcome_after_the_effect_is_reconciliation_required_not_a_refusal() {
        // If the outcome cannot chain to the intent (here: a wrong/foreign intent
        // root, standing in for a lost/again-moved head), the op does not "refuse" —
        // the external effect is not undone. It returns 202 reconciliation_required.
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let caller = journal_caller_for_test("c2-op-2");
        let journal_ref = "provider-operation://pop_c2_2";
        super::super::mutation_event_foundation::admit_owner_scoped_write(
            data_dir,
            &super::super::mutation_event_foundation::WriteCaller {
                identity: caller.identity.clone(),
                owner_ref: caller.owner_ref.clone(),
                idempotency_key: format!("{}.intent", caller.idempotency_key),
            },
            "hypervisor-provider-operations",
            "provider_operation",
            journal_ref,
            "provider_operation.intent",
            None,
            &sample_intent_payload(journal_ref),
        )
        .expect("the pre-effect intent admits");
        // A ProviderJournalIntent carrying the WRONG intent root → the successor CAS
        // cannot match → the outcome commit fails → reconciliation_required.
        let wrong = ProviderJournalIntent {
            caller,
            journal_ref: journal_ref.to_string(),
            intent_state_root: "sha256:not-the-real-intent-head".to_string(),
        };
        let (status, _reply) = commit_provider_operation_outcome(
            data_dir,
            &wrong,
            "create",
            "akash",
            "environment:1",
            "ok",
            &json!({ "provider_native": { "dseq": "999" } }),
            &Some("agentgres://provider-receipt/2".to_string()),
            "the provider op executed but its completion root did not finalize",
        )
        .expect_err("a lost/mismatched outcome must not be a plain Ok");
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "reconciliation_required is 202 — the effect happened, the outcome is owed, not refused"
        );
    }

    #[test]
    fn the_intent_payload_anchors_by_hash_and_keeps_custody_a_fingerprint_never_the_secret() {
        // The credential is present only as its fingerprint; the raw secret must NEVER appear.
        // The proposal and request are tamper-anchored by hash, not stored verbatim.
        // (Mutation drill: store the raw plan/secret instead of its hash → RED.)
        let secret = "AKASH-LIVE-SECRET-DO-NOT-LEAK";
        let fingerprint = sha256_bytes(secret.as_bytes());
        let plan =
            json!({ "sdl": "a-real-deployment-manifest", "deposit": { "amount": "500000" } });
        let payload = provider_operation_intent_payload(
            "provider-operation://pop_c2_3",
            "akash",
            "create",
            "provider-account://pacc_1",
            "environment:1",
            &json!({ "proposal_ref": "proposal:provider/3" }),
            &json!("grant://three"),
            &json!({ "lease_id": "lease://three" }),
            &fingerprint,
            &plan,
        );
        let serialized = serde_json::to_string(&payload).unwrap();
        assert_eq!(payload["phase"], "intent");
        assert!(
            !serialized.contains(secret),
            "the raw credential secret leaked into the intent payload"
        );
        assert!(serialized.contains(&fingerprint));
        assert!(payload["model_proposal_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert!(payload["request_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert!(
            !serialized.contains("a-real-deployment-manifest"),
            "the raw request was stored verbatim instead of hashed"
        );
    }

    #[test]
    fn the_outcome_payload_binds_to_its_intent_and_anchors_evidence_by_hash() {
        let evidence = json!({ "provider_native": { "dseq": "424242" }, "raw": "manifest-echo" });
        let payload = provider_operation_outcome_payload(
            "provider-operation://pop_c2_4",
            "ok",
            &evidence,
            &json!("agentgres://provider-receipt/4"),
            "sha256:the-intent-root",
        );
        let serialized = serde_json::to_string(&payload).unwrap();
        assert_eq!(payload["phase"], "outcome");
        // The outcome names the exact pre-effect intent it finalizes.
        assert_eq!(payload["intent_state_root"], "sha256:the-intent-root");
        assert!(payload["evidence_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert!(
            !serialized.contains("manifest-echo"),
            "the raw provider evidence was stored verbatim instead of hashed"
        );
    }

    #[test]
    fn the_workload_result_outcome_names_both_roots_and_binds_each_authenticated_artifact() {
        let evidence = json!({
            "workload_result": {
                "result_ref": "akash-workload-result://akresult_1",
                "retrieved_live": true,
                "bundle": {
                    "status": { "sha256": format!("sha256:{}", "1".repeat(64)) },
                    "environment": { "sha256": format!("sha256:{}", "2".repeat(64)) },
                    "results": { "sha256": format!("sha256:{}", "3".repeat(64)) },
                    "manifest": { "sha256": format!("sha256:{}", "4".repeat(64)) }
                }
            }
        });
        let payload = provider_operation_result_outcome_payload(
            "provider-operation://pop_c2_result",
            "sha256:intent",
            "sha256:create-outcome",
            &evidence,
            &Some("agentgres://provider-receipt/result".to_string()),
        )
        .expect("a complete authenticated bundle is bindable");
        assert_eq!(payload["phase"], "outcome");
        assert_eq!(payload["outcome"], "workload_result_retrieved");
        assert_eq!(payload["intent_state_root"], "sha256:intent");
        assert_eq!(payload["predecessor_state_root"], "sha256:create-outcome");
        assert_eq!(payload["result_hash"], format!("sha256:{}", "3".repeat(64)));
        assert_eq!(
            payload["environment_hash"],
            format!("sha256:{}", "2".repeat(64))
        );
        assert!(payload["evidence_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
    }

    #[test]
    fn a_ready_authenticated_result_extends_the_create_journal_once_and_then_is_immutable() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let create_caller = journal_caller_for_test("c2-result-create");
        let journal_ref = "provider-operation://pop_c2_result_chain";
        let intent = super::super::mutation_event_foundation::admit_owner_scoped_write(
            data_dir,
            &super::super::mutation_event_foundation::WriteCaller {
                identity: create_caller.identity.clone(),
                owner_ref: create_caller.owner_ref.clone(),
                idempotency_key: format!("{}.intent", create_caller.idempotency_key),
            },
            "hypervisor-provider-operations",
            "provider_operation",
            journal_ref,
            "provider_operation.intent",
            None,
            &sample_intent_payload(journal_ref),
        )
        .unwrap();
        let intent_state = ProviderJournalIntent {
            caller: create_caller,
            journal_ref: journal_ref.to_string(),
            intent_state_root: intent.projection.head.clone(),
        };
        let create_roots = commit_provider_operation_outcome(
            data_dir,
            &intent_state,
            "create",
            "akash",
            "environment:result",
            "ok",
            &json!({ "provider_native": { "dseq": "88" } }),
            &Some("agentgres://provider-receipt/create".to_string()),
            "unused",
        )
        .unwrap();
        let deployment = json!({
            "schema_version": "ioi.hypervisor.akash-deployment.v1",
            "record_id": "akdep_result",
            "environment_ref": "environment:result",
            "provider_native": { "dseq": "88" },
            "workload_readiness_proven": true,
            "provider_operation_journal_ref": journal_ref,
            "provider_operation_journal_owner_ref": "org://one",
            "provider_operation_intent_root": intent.projection.head,
            "provider_operation_effect_outcome_root": create_roots[1],
            "provider_operation_current_root": create_roots[1]
        });
        persist_record(data_dir, AKASH_DEPLOYMENT_KIND, "akdep_result", &deployment).unwrap();
        let evidence = json!({
            "workload_result": {
                "result_ref": "akash-workload-result://akresult_88",
                "retrieved_live": true,
                "bundle": {
                    "status": { "sha256": format!("sha256:{}", "1".repeat(64)) },
                    "environment": { "sha256": format!("sha256:{}", "2".repeat(64)) },
                    "results": { "sha256": format!("sha256:{}", "3".repeat(64)) },
                    "manifest": { "sha256": format!("sha256:{}", "4".repeat(64)) }
                }
            }
        });
        let result_caller = journal_caller_for_test("c2-result-logs");
        let roots = commit_akash_result_outcome(
            data_dir,
            &result_caller,
            "environment:result",
            &evidence,
            &Some("agentgres://provider-receipt/result".to_string()),
        )
        .expect("the result successor commits");
        assert_eq!(roots.len(), 3);
        assert_ne!(roots[1], roots[2]);
        let replay = commit_akash_result_outcome(
            data_dir,
            &result_caller,
            "environment:result",
            &evidence,
            &Some("agentgres://provider-receipt/result".to_string()),
        )
        .expect("identical result retrieval reuses the committed root");
        assert_eq!(replay[2], roots[2]);
        let mut changed = evidence;
        changed["workload_result"]["bundle"]["results"]["sha256"] =
            json!(format!("sha256:{}", "9".repeat(64)));
        let (status, body) = commit_akash_result_outcome(
            data_dir,
            &result_caller,
            "environment:result",
            &changed,
            &Some("agentgres://provider-receipt/result".to_string()),
        )
        .expect_err("a changed completed result must not replace the root");
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.0["code"], "akash_result_bundle_changed_after_commit");
        super::super::substrate_store::reset_handle_for_test();
    }

    // ---- CARVE-OUT: provider deletion stays callable and reports exactly ----

    #[test]
    fn a_confirmed_provider_destroy_is_succeeded_and_opens_no_obligation() {
        let (state, verified, disposition) = provider_teardown_disposition(
            "provider-account://acct/resource/env_1",
            &json!({ "destroyed": true }),
            &json!("gone"),
        );
        assert_eq!(state, "torn_down");
        assert!(verified);
        assert_eq!(disposition["outcome"], json!("succeeded"));
        assert!(disposition["cleanup_obligation_ref"].is_null());
    }

    #[test]
    fn an_explicit_destroy_failure_is_failed_and_opens_an_obligation() {
        // This is the case that used to be reported as `cleanup_verified: true`.
        let (state, verified, disposition) = provider_teardown_disposition(
            "provider-account://acct/resource/env_1",
            &json!({ "destroyed": false, "error": "api_error", "warning": "TEARDOWN MAY BE INCOMPLETE" }),
            &json!("gone"),
        );
        assert_eq!(state, "teardown_failed");
        assert!(!verified);
        assert_eq!(disposition["outcome"], json!("failed"));
        assert!(!disposition["cleanup_obligation_ref"].is_null());
    }

    #[test]
    fn an_unimplemented_live_teardown_is_failed_never_verified() {
        let (state, verified, disposition) = provider_teardown_disposition(
            "provider-account://acct/resource/env_1",
            &json!({ "destroyed": false, "error": "aws_live_api_flow_not_implemented" }),
            &json!("gone"),
        );
        assert_eq!(state, "teardown_failed");
        assert!(!verified);
        assert_eq!(disposition["outcome"], json!("failed"));
    }

    #[test]
    fn an_unreachable_remote_half_degrades_to_unknown_not_success() {
        // Provider says destroyed, but the remote workspace cleanup could not be reached:
        // absence is not provable, so the outcome is UNKNOWN and an obligation stays open.
        let (state, verified, disposition) = provider_teardown_disposition(
            "provider-account://acct/resource/env_1",
            &json!({ "destroyed": true }),
            &json!("unreachable"),
        );
        assert_eq!(state, "torn_down_unverified");
        assert!(!verified);
        assert_eq!(disposition["outcome"], json!("unknown"));
        assert!(!disposition["cleanup_obligation_ref"].is_null());
    }

    #[test]
    fn a_missing_destroyed_verdict_is_unknown_never_coerced() {
        let (state, verified, disposition) = provider_teardown_disposition(
            "provider-account://acct/resource/env_1",
            &json!({ "note": "simulated control plane" }),
            &json!("gone"),
        );
        assert_eq!(state, "torn_down_unverified");
        assert!(!verified);
        assert_eq!(disposition["outcome"], json!("unknown"));
    }

    #[test]
    fn provider_deletion_is_total_and_never_refuses() {
        // The carve-out: every combination yields a disposition; none is an error.
        for destroyed in [
            json!({ "destroyed": true }),
            json!({ "destroyed": false }),
            json!({}),
        ] {
            for remote in [json!("gone"), json!("unreachable")] {
                let (state, _, disposition) =
                    provider_teardown_disposition("provider://r", &destroyed, &remote);
                assert!(matches!(
                    state,
                    "torn_down" | "teardown_failed" | "torn_down_unverified"
                ));
                let outcome = disposition["outcome"].as_str().unwrap();
                assert!(matches!(outcome, "succeeded" | "failed" | "unknown"));
                // Non-succeeded ALWAYS opens a durable obligation.
                assert_eq!(
                    disposition["cleanup_obligation_ref"].is_null(),
                    outcome == "succeeded"
                );
            }
        }
    }
}
