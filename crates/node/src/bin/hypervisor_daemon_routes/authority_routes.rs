//! WS-G — local-operator authority (`LocalAuthorityProvider`).
//!
//! Phase 0 authority posture: `local_operator`. wallet.network is NOT live; wallet-required
//! crossings are represented, previewed, and blocked/degraded — never silently allowed. No
//! raw secrets enter daemon/management-plane truth (capability-lease refs only). Canon:
//! `wallet-network/doctrine.md` (which crossings escalate to portable authority).
//!
//! T4 — live authority-provider crossings. Three provider modes per the neutral authority
//! contract: `local_operator` (covers local effects, no grant), `enterprise_authority` (a REAL
//! local enterprise-policy issuer: evaluates a neutral `AuthorityGrantRequest`, issues/denies a
//! portable grant with real expiry + revoke + receipts, all file-backed), and
//! `wallet_network_live` (Option A device signer — DECLARED gap unless a live wallet.network
//! endpoint is configured; never faked). High-risk crossings (`WALLET_REQUIRED`) need a portable
//! grant; the enterprise provider can issue one; the local lane covers only `LOCAL_ALLOWED`.
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, DaemonState};

/// Enterprise policy spend ceiling — a real, enforced denial threshold for portable grants.
const MAX_ENTERPRISE_SPEND: i64 = 100_000;

/// Serializes exact-action grant issue/revoke/consume transitions across the final invoker.
/// The lock is deliberately authority-owned; the workflow-edit adapter never becomes a second
/// grant store or revocation source.
static EXACT_ACTION_GRANT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug)]
pub(crate) struct ExactActionGrantError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl ExactActionGrantError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ExactActionConsumption<T> {
    pub(crate) output: T,
    pub(crate) grant: Value,
    pub(crate) receipt: Value,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Whether a live wallet.network signer endpoint is configured (Option A). Never faked: only true
/// when an operator has wired a real endpoint. Reachability is not asserted here — absence of the
/// var is the declared host gap the verifier reports.
fn wallet_network_endpoint() -> Option<String> {
    std::env::var("IOI_WALLET_NETWORK_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// The configured active authority mode (display/posture). The enterprise issuer is always
/// available regardless; this only records the operator's declared default crossing posture.
fn active_authority_mode() -> String {
    std::env::var("IOI_AUTHORITY_MODE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "local_operator".into())
}

/// Compute a persisted grant's LIVE status from the real clock + revoke flag.
/// `granted` records become `active` | `expired`; non-granted decisions keep their decision.
fn live_grant_status(grant: &Value) -> &'static str {
    if grant.get("decision").and_then(|v| v.as_str()) == Some("denied") {
        return "denied";
    }
    if grant
        .get("revoked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return "revoked";
    }
    match grant
        .get("consumption_state")
        .and_then(Value::as_str)
        .unwrap_or("available")
    {
        "consumed" => return "consumed",
        "prepared" | "failed" => return "prepared",
        _ => {}
    }
    let expires = grant
        .get("expires_at_unix")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    if expires != 0 && now_unix() >= expires {
        return "expired";
    }
    "active"
}

fn load_grant(data_dir: &str, grant_id: &str) -> Option<Value> {
    read_record_dir(data_dir, "authority-grants")
        .into_iter()
        .find(|g| {
            g.get("grant_id").and_then(|v| v.as_str()) == Some(grant_id)
                || g.get("grant_ref").and_then(|v| v.as_str()) == Some(grant_id)
        })
}

#[allow(clippy::too_many_arguments)]
fn retained_exact_action_grant(
    data_dir: &str,
    subject: &str,
    action: &str,
    policy_hash: &str,
    request_hash: &str,
    effect_hash: &str,
    target_ref: &str,
    proposal_ref: &str,
) -> Result<Option<Value>, String> {
    let mut retained = read_record_dir(data_dir, "authority-grants")
        .into_iter()
        .filter(|grant| {
            grant
                .pointer("/resources/proposal_ref")
                .and_then(Value::as_str)
                == Some(proposal_ref)
        })
        .collect::<Vec<_>>();
    if retained.len() > 1 {
        return Err(format!(
            "exact-action proposal '{proposal_ref}' has multiple retained grants; authority repair is required"
        ));
    }
    let Some(grant) = retained.pop() else {
        return Ok(None);
    };
    let exact_fields = [
        ("/schema_version", "ioi.hypervisor.authority-grant.v1"),
        ("/authority_provider_ref", "authority://local-operator"),
        ("/provider", "local_operator"),
        ("/authority_lane", "sovereign_local"),
        ("/subject", subject),
        ("/action", action),
        ("/policy_hash", policy_hash),
        ("/request_hash", request_hash),
        ("/effect_hash", effect_hash),
        ("/resources/proposal_ref", proposal_ref),
        ("/resources/target_ref", target_ref),
        ("/resources/effect_hash", effect_hash),
        ("/resources/request_hash", request_hash),
    ];
    for (pointer, expected) in exact_fields {
        if grant.pointer(pointer).and_then(Value::as_str) != Some(expected) {
            return Err(format!(
                "retained exact-action grant for '{proposal_ref}' does not bind {pointer}; authority repair is required"
            ));
        }
    }
    let grant_id = grant
        .get("grant_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "retained exact-action grant has no canonical grant_id".to_string())?;
    let expected_grant_ref = format!("grant://authority.local/{grant_id}");
    if grant.get("grant_ref").and_then(Value::as_str) != Some(expected_grant_ref.as_str())
        || grant.get("max_usages").and_then(Value::as_u64) != Some(1)
    {
        return Err(format!(
            "retained exact-action grant for '{proposal_ref}' has invalid identity or usage bounds; authority repair is required"
        ));
    }
    Ok(Some(grant))
}

/// Emit + persist an authority receipt (neutral `authority_receipt_refs`). Returns the receipt ref.
fn emit_receipt(
    data_dir: &str,
    event: &str,
    grant_ref: &str,
    subject: &str,
    action: &str,
    detail: &str,
) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let receipt_id = format!("arc_{nanos:x}");
    let receipt_ref = format!("agentgres://authority-receipt/{receipt_id}");
    let record = json!({
        "schema_version": "ioi.hypervisor.authority-receipt.v1",
        "receipt_id": receipt_id,
        "receipt_ref": receipt_ref,
        "event": event,
        "grant_ref": grant_ref,
        "subject": subject,
        "action": action,
        "detail": detail,
        "at": iso_now()
    });
    let _ = persist_record(data_dir, "authority-receipts", &receipt_id, &record);
    receipt_ref
}

/// Issue one daemon-retained sovereign-local AuthorityGrant for one already-reviewed exact
/// action. This is intentionally narrower than the portable wallet.network lane: it is valid
/// only inside this deployment, is one-shot, and binds the exact policy, request, effect, target,
/// proposal, and subject. The review surface supplies no authority fields of its own.
#[allow(clippy::too_many_arguments)]
pub(crate) fn issue_exact_action_grant(
    data_dir: &str,
    subject: &str,
    action: &str,
    policy_hash: &str,
    request_hash: &str,
    effect_hash: &str,
    target_ref: &str,
    proposal_ref: &str,
    expiry_seconds: i64,
) -> Result<Value, String> {
    if [
        subject,
        action,
        policy_hash,
        request_hash,
        effect_hash,
        target_ref,
        proposal_ref,
    ]
    .iter()
    .any(|value| value.trim().is_empty())
    {
        return Err("exact-action grant coordinates must be nonblank".into());
    }
    let _guard = EXACT_ACTION_GRANT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(grant) = retained_exact_action_grant(
        data_dir,
        subject,
        action,
        policy_hash,
        request_hash,
        effect_hash,
        target_ref,
        proposal_ref,
    )? {
        return Ok(grant);
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let grant_id = format!("agr_exact_{nanos:x}");
    let grant_ref = format!("grant://authority.local/{grant_id}");
    let now = now_unix();
    let expires_at_unix = now.saturating_add(expiry_seconds.clamp(1, 86_400));
    let receipt_ref = emit_receipt(
        data_dir,
        "exact_action_granted",
        &grant_ref,
        subject,
        action,
        "sovereign-local exact-action review admitted",
    );
    let record = json!({
        "schema_version": "ioi.hypervisor.authority-grant.v1",
        "grant_id": grant_id,
        "grant_ref": grant_ref,
        "authority_provider_ref": "authority://local-operator",
        "provider": "local_operator",
        "authority_lane": "sovereign_local",
        "subject": subject,
        "action": action,
        "resources": {
            "proposal_ref": proposal_ref,
            "target_ref": target_ref,
            "effect_hash": effect_hash,
            "request_hash": request_hash,
        },
        "policy_hash": policy_hash,
        "request_hash": request_hash,
        "effect_hash": effect_hash,
        "decision": "granted",
        "reason": "operator reviewed and granted this exact local action",
        "revoked": false,
        "revoked_at": Value::Null,
        "issued_at": iso_now(),
        "issued_at_unix": now,
        "expires_at_unix": expires_at_unix,
        "max_usages": 1,
        "uses": 0,
        "consumption_state": "available",
        "pending_consumption_ref": Value::Null,
        "consumed_at": Value::Null,
        "consumption_receipt_ref": Value::Null,
        "authority_receipt_refs": [receipt_ref],
    });
    persist_record(data_dir, "authority-grants", &grant_id, &record)
        .map_err(|error| format!("exact-action grant persist failed: {error}"))?;
    Ok(record)
}

/// Revalidate and consume one exact-action grant while holding the authority mutation lock across
/// the final invoker. A prepared intent is persisted before the effect; if the process fails
/// after preparation, replay remains fail-closed instead of double-executing an uncertain effect.
#[allow(clippy::too_many_arguments)]
pub(crate) fn consume_exact_action_grant<T>(
    data_dir: &str,
    grant_ref: &str,
    subject: &str,
    action: &str,
    policy_hash: &str,
    request_hash: &str,
    effect_hash: &str,
    target_ref: &str,
    final_invoker_ref: &str,
    invoke: impl FnOnce() -> Result<T, String>,
) -> Result<ExactActionConsumption<T>, ExactActionGrantError>
where
    T: serde::Serialize,
{
    let _guard = EXACT_ACTION_GRANT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut grant = load_grant(data_dir, grant_ref).ok_or_else(|| {
        ExactActionGrantError::new(
            "authority_grant_missing",
            format!("exact-action grant '{grant_ref}' is not retained by this authority provider"),
        )
    })?;
    let status = live_grant_status(&grant);
    if status != "active" {
        let code = match status {
            "revoked" => "authority_grant_revoked",
            "expired" => "authority_grant_expired",
            "consumed" | "prepared" => "authority_grant_consumed",
            _ => "authority_grant_inactive",
        };
        return Err(ExactActionGrantError::new(
            code,
            format!("exact-action grant is {status}; final invocation refused"),
        ));
    }
    let expected = [
        ("subject", subject),
        ("action", action),
        ("policy_hash", policy_hash),
        ("request_hash", request_hash),
        ("effect_hash", effect_hash),
    ];
    for (field, value) in expected {
        if grant.get(field).and_then(Value::as_str) != Some(value) {
            return Err(ExactActionGrantError::new(
                "authority_grant_exact_action_mismatch",
                format!("grant {field} does not bind the final invocation"),
            ));
        }
    }
    if grant
        .pointer("/resources/target_ref")
        .and_then(Value::as_str)
        != Some(target_ref)
    {
        return Err(ExactActionGrantError::new(
            "authority_grant_target_mismatch",
            "grant target does not bind the final invocation",
        ));
    }
    if grant.get("max_usages").and_then(Value::as_u64) != Some(1)
        || grant.get("uses").and_then(Value::as_u64).unwrap_or(0) != 0
    {
        return Err(ExactActionGrantError::new(
            "authority_grant_consumed",
            "exact-action grant has no remaining usage",
        ));
    }

    let consumption_id = format!(
        "agc_{}",
        effect_hash
            .strip_prefix("sha256:")
            .unwrap_or(effect_hash)
            .chars()
            .take(32)
            .collect::<String>()
    );
    let consumption_ref = format!("authority-consumption://{consumption_id}");
    grant["consumption_state"] = json!("prepared");
    grant["pending_consumption_ref"] = json!(consumption_ref);
    let grant_id = grant
        .get("grant_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    persist_record(data_dir, "authority-grants", &grant_id, &grant).map_err(|error| {
        ExactActionGrantError::new(
            "authority_consumption_prepare_failed",
            format!("could not persist the one-shot consumption intent: {error}"),
        )
    })?;

    let output = match invoke() {
        Ok(output) => output,
        Err(message) => {
            grant["consumption_state"] = json!("failed");
            grant["consumption_failure"] = json!(message.clone());
            let _ = persist_record(data_dir, "authority-grants", &grant_id, &grant);
            return Err(ExactActionGrantError::new(
                "final_invoker_effect_failed",
                format!("final invoker refused or failed the exact effect: {message}"),
            ));
        }
    };

    let receipt_ref = format!("receipt://hypervisor/authority-grant-consumption/{consumption_id}");
    let receipt = json!({
        "schema_version": "ioi.hypervisor.authority-grant-consumption-receipt.v1",
        "receipt_id": consumption_id,
        "receipt_ref": receipt_ref,
        "authority_grant_ref": grant_ref,
        "authority_lane": "sovereign_local",
        "subject": subject,
        "action": action,
        "policy_hash": policy_hash,
        "request_hash": request_hash,
        "effect_hash": effect_hash,
        "target_ref": target_ref,
        "final_invoker_ref": final_invoker_ref,
        "status": "effect_committed",
        "observed_effect": output,
        "at": iso_now(),
    });
    persist_record(data_dir, "authority-receipts", &consumption_id, &receipt).map_err(|error| {
        ExactActionGrantError::new(
            "authority_consumption_receipt_failed",
            format!("effect occurred but its authority receipt could not be retained: {error}"),
        )
    })?;
    grant["uses"] = json!(1);
    grant["consumption_state"] = json!("consumed");
    grant["consumed_at"] = receipt["at"].clone();
    grant["consumption_receipt_ref"] = receipt["receipt_ref"].clone();
    grant["pending_consumption_ref"] = Value::Null;
    if let Some(receipts) = grant
        .get_mut("authority_receipt_refs")
        .and_then(Value::as_array_mut)
    {
        receipts.push(receipt["receipt_ref"].clone());
    }
    persist_record(data_dir, "authority-grants", &grant_id, &grant).map_err(|error| {
        ExactActionGrantError::new(
            "authority_consumption_commit_failed",
            format!("effect and receipt exist but grant consumption did not converge: {error}"),
        )
    })?;
    Ok(ExactActionConsumption {
        output,
        grant,
        receipt,
    })
}

/// Effects that require portable (wallet.network) authority — blocked/degraded in local mode.
const WALLET_REQUIRED: &[&str] = &[
    "secret_release",
    "provider_credential",
    "spend",
    "payment",
    "decryption",
    "declassification",
    "external_connector_mutation",
    "publication",
    "export",
    "portable_revocation",
    "restore_apply_protected",
    "delegated_lease",
];

/// Effects allowed under `local_operator` authority (no portable authority needed).
const LOCAL_ALLOWED: &[&str] = &[
    "scm_read_public",
    "scm_read_local",
    "local_file_read",
    "local_file_write",
    "local_model_route",
    "workspace_provision",
    "local_exec",
];

/// Mint a capability lease as a real authority grant (the SAME grant/revoke/expiry/receipt
/// machinery — Locked Decision 1: no parallel SessionAccessLease). Returns the grant record; its
/// `grant_ref` IS the `capability_lease_ref`. Used by the editor access-lease surface (effect
/// `environment.editor.open`) so editor access is lease-bound, revocable, expiring, receipt-backed
/// — revocable via POST /v1/hypervisor/authority/revoke and visible in /authority/grants.
pub(crate) fn issue_capability_lease(
    data_dir: &str,
    subject: &str,
    action: &str,
    resources: Value,
    expiry_seconds: i64,
) -> Value {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let grant_id = format!("agr_{nanos:x}");
    let live_wallet = wallet_network_endpoint().is_some();
    let provider = if live_wallet {
        "wallet_network_live"
    } else {
        "enterprise_authority"
    };
    let grant_ref = if live_wallet {
        format!("wallet.network://grant/{grant_id}")
    } else {
        format!("enterprise.authority://grant/{grant_id}")
    };
    let now = now_unix();
    let expires_at_unix = now + expiry_seconds;
    let receipt_ref = emit_receipt(
        data_dir,
        "granted",
        &grant_ref,
        subject,
        action,
        "capability lease (editor access)",
    );
    let record = json!({
        "schema_version": "ioi.hypervisor.authority-grant.v1",
        "grant_id": grant_id, "grant_ref": grant_ref,
        "authority_provider_ref": provider, "provider": provider,
        "subject": subject, "action": action, "resources": resources, "budget": Value::Null,
        "policy_hash": "policy:editor.access", "decision": "granted",
        "reason": format!("capability lease issued for '{action}'"),
        "revoked": false, "revoked_at": Value::Null,
        "issued_at": iso_now(), "issued_at_unix": now,
        "expires_at_unix": expires_at_unix, "expires_at": iso_now(),
        "authority_receipt_refs": [receipt_ref],
        "lease_kind": "capability_lease",
    });
    let _ = persist_record(data_dir, "authority-grants", &grant_id, &record);
    record
}

/// Resolve a capability lease's LIVE admission status (active | expired | revoked | missing) — the
/// SAME enforcement the authority preflight uses. The WS proxy / open-url gate calls this.
pub(crate) fn capability_lease_status(data_dir: &str, lease_ref: &str) -> &'static str {
    match load_grant(data_dir, lease_ref) {
        Some(g) => live_grant_status(&g),
        None => "missing",
    }
}

/// Revoke a capability lease by id/ref — the reusable core of `POST /authority/revoke`, also used
/// by the env port-preview gateway to fail-close a lease on unexpose. Returns true if a granted
/// lease was revoked. (The HTTP handler keeps its richer response; this is the in-process path.)
pub(crate) fn revoke_lease(data_dir: &str, key: &str) -> bool {
    let _guard = EXACT_ACTION_GRANT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(mut grant) = load_grant(data_dir, key) else {
        return false;
    };
    if grant.get("decision").and_then(|v| v.as_str()) != Some("granted") {
        return false;
    }
    let grant_id = grant
        .get("grant_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let grant_ref = grant
        .get("grant_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let subject = grant
        .get("subject")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let action = grant
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    grant["revoked"] = json!(true);
    grant["revoked_at"] = json!(iso_now());
    let receipt_ref = emit_receipt(
        data_dir,
        "revoked",
        &grant_ref,
        &subject,
        &action,
        "port-preview unexpose / operator revoke",
    );
    if let Some(arr) = grant
        .get_mut("authority_receipt_refs")
        .and_then(|v| v.as_array_mut())
    {
        arr.push(json!(receipt_ref));
    }
    let _ = persist_record(data_dir, "authority-grants", &grant_id, &grant);
    true
}

/// GET /v1/hypervisor/authority/posture — the local-operator authority posture.
pub(crate) async fn handle_authority_posture(State(_st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({
        "schema_version": "ioi.hypervisor.authority-posture.v1",
        "mode": "local_operator",
        "provider": "LocalAuthorityProvider",
        "wallet_network_live": false,
        "grants": [
            { "ref": "grant:local_operator/workspace", "scope": "workspace.read_write", "source": "local_operator" },
            { "ref": "grant:local_operator/local_exec", "scope": "local.exec", "source": "local_operator" }
        ],
        "wallet_required_crossings": WALLET_REQUIRED,
        "note": "wallet.network represented; required only at delegated/high-risk crossings",
        "at": iso_now()
    }))
}

/// GET /v1/hypervisor/agent-runner-profiles — the capability matrix the session composer reads so it
/// only offers capabilities the chosen harness actually supports.
pub(crate) async fn handle_agent_runner_profiles(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    // Cut D projection, now REGISTRY-derived: the harness-profile registry is the one truth for
    // the capability matrix; this keeps the legacy response shape for the session composer.
    Json(json!({
        "schema_version": "ioi.hypervisor.agent-runner-profiles.v1",
        "profiles": super::harness_routes::registry_runner_profiles(&st.data_dir)
    }))
}

/// Admit a requested control against the chosen harness's capability matrix. Returns the offending
/// (field, value) on a violation — the basis for fail-closed "no dropdown lies".
fn admit_controls(req: &Value, profiles: &[Value]) -> Result<Value, (String, String)> {
    let harness = req
        .get("harness")
        .and_then(|v| v.as_str())
        .unwrap_or("hypervisor_worker");
    let profile = profiles
        .iter()
        .find(|p| p["harness"].as_str() == Some(harness))
        .ok_or_else(|| ("harness".to_string(), harness.to_string()))?
        .clone();
    let check = |field: &str, default: &str| -> Result<String, (String, String)> {
        let val = req
            .get(field)
            .and_then(|v| v.as_str())
            .unwrap_or(default)
            .to_string();
        let allowed = profile.get(field).and_then(|v| v.as_array());
        match allowed {
            Some(list) if list.iter().any(|x| x.as_str() == Some(val.as_str())) => Ok(val),
            Some(_) => Err((field.to_string(), val)),
            None => Ok(val),
        }
    };
    // model is keyed under "models"; map field name.
    let model = {
        let val = req
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                profile["models"][0]
                    .as_str()
                    .unwrap_or("hypervisor:native-local")
            })
            .to_string();
        match profile["models"].as_array() {
            Some(list) if list.iter().any(|x| x.as_str() == Some(val.as_str())) => val,
            _ => return Err(("model".to_string(), val)),
        }
    };
    Ok(json!({
        "harness": harness, "model": model,
        "mode": check("modes", "agent").map_err(|_| ("mode".to_string(), req.get("mode").and_then(|v| v.as_str()).unwrap_or("").to_string()))?,
        "reasoning": check("reasoning", "medium").map_err(|_| ("reasoning".to_string(), req.get("reasoning").and_then(|v| v.as_str()).unwrap_or("").to_string()))?,
        "speed": check("speed", "balanced").map_err(|_| ("speed".to_string(), req.get("speed").and_then(|v| v.as_str()).unwrap_or("").to_string()))?,
        "service_tier": check("service_tier", "standard").map_err(|_| ("service_tier".to_string(), req.get("service_tier").and_then(|v| v.as_str()).unwrap_or("").to_string()))?,
        "tool_use": profile["tool_use"].clone(), "image_input": profile["image_input"].clone(),
        "provider_trust": profile["provider_trust"].clone()
    }))
}

/// POST /v1/hypervisor/harness-bindings — WS-D: compile a per-session config into an
/// admitted HarnessSessionBinding (Agent/Mode/Model/Reasoning/Speed/Harness/Tools/Memory/
/// Authority/Budget/Privacy). Daemon-owned; persisted under state_dir/harness-bindings.
/// Capability-correct: a control the chosen harness does not support FAILS CLOSED (no dropdown lies).
pub(crate) async fn handle_harness_binding_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    // Admit the requested controls against the REGISTRY-derived harness capability matrix.
    let profiles = super::harness_routes::registry_runner_profiles(&st.data_dir);
    let admitted = match admit_controls(&body, &profiles) {
        Ok(a) => a,
        Err((field, value)) => {
            return Json(json!({ "ok": false, "admitted": false, "fail_closed": true,
                "reason": format!("capability violation: harness '{}' does not support {field} '{value}'", body.get("harness").and_then(|v| v.as_str()).unwrap_or("hypervisor_worker")),
                "violation": { "field": field, "value": value } }));
        }
    };
    let now = iso_now();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let id = format!("hsb_{nanos:x}");
    // capability-gated controls come from `admitted`; non-gated session prefs from the body.
    let a = |k: &str, default: &str| {
        admitted
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or(default)
            .to_string()
    };
    let pick = |k: &str, default: &str| {
        body.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or(default)
            .to_string()
    };
    let record = json!({
        "schema_version": "ioi.hypervisor.harness-session-binding.v1",
        "harness_binding_id": id,
        "agent": pick("agent", "default"),
        "mode": a("mode", "agent"),
        "model": a("model", "hypervisor:native-local"),
        "reasoning": a("reasoning", "medium"),
        "speed": a("speed", "balanced"),
        "service_tier": a("service_tier", "standard"),
        "harness": a("harness", "hypervisor_worker"),
        "tool_use": admitted.get("tool_use").cloned().unwrap_or(json!(true)),
        "image_input": admitted.get("image_input").cloned().unwrap_or(json!(false)),
        "provider_trust": a("provider_trust", "local"),
        "tools": body.get("tools").cloned().unwrap_or_else(|| json!([])),
        "memory": pick("memory", "session_scoped"),
        "authority_posture": "local_operator",
        "budget": body.get("budget").cloned().unwrap_or(Value::Null),
        "privacy": pick("privacy", "local_private"),
        "session_ref": pick("session_ref", ""),
        "admitted": true,
        "evidence_ref": format!("agentgres://harness-binding/{id}"),
        "created_at": now
    });
    let _ = persist_record(&st.data_dir, "harness-bindings", &id, &record);
    Json(json!({ "harnessBinding": record }))
}

/// POST /v1/hypervisor/authority/evaluate — classify a requested effect.
/// `{ "effect": "<name>" }` -> allowed_local | requires_portable_authority | blocked.
pub(crate) async fn handle_authority_evaluate(
    State(_st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let effect = body.get("effect").and_then(|v| v.as_str()).unwrap_or("");
    let wallet_required = WALLET_REQUIRED.contains(&effect);
    let local_allowed = LOCAL_ALLOWED.contains(&effect);
    let (decision, reason) = if wallet_required {
        (
            "requires_portable_authority",
            format!("'{effect}' is a delegated/high-risk crossing; needs wallet.network portable authority (not live in Phase 0 local mode)"),
        )
    } else if local_allowed {
        (
            "allowed_local",
            format!("'{effect}' is within local_operator authority"),
        )
    } else {
        (
            "blocked",
            format!("'{effect}' is not a recognized local effect; blocked fail-closed"),
        )
    };
    Json(json!({
        "schema_version": "ioi.hypervisor.authority-decision.v1",
        "effect": effect,
        "decision": decision,
        "requires_portable_authority": wallet_required,
        "reason": reason,
        "mode": "local_operator",
        "at": iso_now()
    }))
}

// ---------------------------------------------------------------------------
// T4 — live authority providers + portable-grant lifecycle.
// ---------------------------------------------------------------------------

/// GET /v1/hypervisor/authority/providers — the three neutral authority provider modes and their
/// REAL availability. `enterprise_authority` is a live local issuer; `wallet_network_live` is a
/// declared host gap until a live wallet.network signer endpoint is configured (never faked).
pub(crate) async fn handle_authority_providers(State(_st): State<Arc<DaemonState>>) -> Json<Value> {
    let wallet_url = wallet_network_endpoint();
    let wallet_live = wallet_url.is_some();
    Json(json!({
        "schema_version": "ioi.hypervisor.authority-providers.v1",
        "active_mode": active_authority_mode(),
        "providers": [
            {
                "mode": "local_operator",
                "provider_ref": "authority.local://operator",
                "status": "available",
                "live": true,
                "issues_portable_grants": false,
                "note": "covers LOCAL_ALLOWED effects with no portable grant"
            },
            {
                "mode": "enterprise_authority",
                "provider_ref": "enterprise.authority://issuer",
                "status": "available",
                "live": true,
                "issues_portable_grants": true,
                "supports": ["grant", "deny", "revoke", "expiry", "receipts", "audit"],
                "note": "real enterprise-policy issuer; evaluates neutral AuthorityGrantRequest and returns portable authority_grant_refs + authority_receipt_refs"
            },
            {
                "mode": "wallet_network_live",
                "provider_ref": "wallet.network://signer",
                "status": if wallet_live { "available" } else { "not_configured" },
                "live": wallet_live,
                "issues_portable_grants": wallet_live,
                "endpoint": wallet_url,
                "reason": if wallet_live { Value::Null } else { json!("WALLET_NETWORK_ENDPOINT_NOT_CONFIGURED — Option A device signer needs a live wallet.network endpoint (set IOI_WALLET_NETWORK_URL); not faked") }
            }
        ],
        "at": iso_now()
    }))
}

/// POST /v1/hypervisor/authority/grant — neutral AuthorityGrantRequest -> a real enterprise grant
/// or a fail-closed denial. Body: `{subject, action, resources?, budget?, policy_hash?,
/// expiry_seconds?}`. Issues only for recognized portable (`WALLET_REQUIRED`) crossings; local
/// effects need no grant; unknown actions and over-ceiling spend are DENIED. Persists the grant +
/// a receipt. When a live wallet.network endpoint is configured the grant_ref is minted under
/// `wallet.network://`; otherwise under the live enterprise issuer.
pub(crate) async fn handle_authority_grant(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let data_dir = &st.data_dir;
    let subject = body
        .get("subject")
        .and_then(|v| v.as_str())
        .unwrap_or("operator")
        .to_string();
    let action = body
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let resources = body.get("resources").cloned().unwrap_or_else(|| json!([]));
    let policy_hash = body
        .get("policy_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("policy:default")
        .to_string();
    let budget = body.get("budget").cloned().unwrap_or(Value::Null);
    let spend = budget.get("spend").and_then(|v| v.as_i64()).unwrap_or(0);
    let expiry_seconds = body
        .get("expiry_seconds")
        .and_then(|v| v.as_i64())
        .unwrap_or(3600);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let grant_id = format!("agr_{nanos:x}");
    let live_wallet = wallet_network_endpoint().is_some();
    let provider = if live_wallet {
        "wallet_network_live"
    } else {
        "enterprise_authority"
    };
    let grant_ref = if live_wallet {
        format!("wallet.network://grant/{grant_id}")
    } else {
        format!("enterprise.authority://grant/{grant_id}")
    };

    // Enterprise policy evaluation — REAL allow/deny decisions, fail-closed.
    let (decision, reason): (&str, String) = if LOCAL_ALLOWED.contains(&action.as_str()) {
        (
            "no_grant_needed",
            format!("'{action}' is within local_operator authority; no portable grant required"),
        )
    } else if !WALLET_REQUIRED.contains(&action.as_str()) {
        (
            "denied",
            format!("'{action}' is not a recognized portable crossing; denied fail-closed"),
        )
    } else if spend > MAX_ENTERPRISE_SPEND {
        ("denied", format!("requested spend {spend} exceeds enterprise ceiling {MAX_ENTERPRISE_SPEND}; denied by policy"))
    } else {
        (
            "granted",
            format!("enterprise policy admits '{action}' for {subject}"),
        )
    };

    let now = now_unix();
    let expires_at_unix = if decision == "granted" {
        now + expiry_seconds
    } else {
        0
    };
    let receipt_event = if decision == "granted" {
        "granted"
    } else {
        "denied"
    };
    let receipt_ref = emit_receipt(
        data_dir,
        receipt_event,
        &grant_ref,
        &subject,
        &action,
        &reason,
    );

    let record = json!({
        "schema_version": "ioi.hypervisor.authority-grant.v1",
        "grant_id": grant_id,
        "grant_ref": grant_ref,
        "authority_provider_ref": provider,
        "provider": provider,
        "subject": subject,
        "action": action,
        "resources": resources,
        "budget": budget,
        "policy_hash": policy_hash,
        "decision": decision,
        "reason": reason,
        "revoked": false,
        "revoked_at": Value::Null,
        "issued_at": iso_now(),
        "issued_at_unix": now,
        "expires_at_unix": expires_at_unix,
        "expires_at": if expires_at_unix != 0 { json!(iso_now()) } else { Value::Null },
        "authority_receipt_refs": [receipt_ref],
    });
    // Persist every decision (granted | denied | no_grant_needed) for a complete audit trail.
    let _ = persist_record(data_dir, "authority-grants", &grant_id, &record);

    Json(json!({
        "grant": record,
        "status": live_grant_status(&record),
    }))
}

/// POST /v1/hypervisor/authority/revoke — revoke a live grant by `grant_id` or `grant_ref`.
/// Marks the grant revoked (persisted) and emits a revoke receipt; subsequent preflight refuses.
pub(crate) async fn handle_authority_revoke(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let data_dir = &st.data_dir;
    let key = body
        .get("grant_id")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("grant_ref").and_then(|v| v.as_str()))
        .unwrap_or("");
    let _guard = EXACT_ACTION_GRANT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(mut grant) = load_grant(data_dir, key) else {
        return Json(
            json!({ "ok": false, "reason": format!("grant '{key}' not found"), "at": iso_now() }),
        );
    };
    if grant.get("decision").and_then(|v| v.as_str()) != Some("granted") {
        return Json(
            json!({ "ok": false, "reason": "only granted authority can be revoked", "decision": grant.get("decision"), "at": iso_now() }),
        );
    }
    let grant_id = grant
        .get("grant_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let grant_ref = grant
        .get("grant_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let subject = grant
        .get("subject")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let action = grant
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    grant["revoked"] = json!(true);
    grant["revoked_at"] = json!(iso_now());
    let receipt_ref = emit_receipt(
        data_dir,
        "revoked",
        &grant_ref,
        &subject,
        &action,
        "operator/enterprise revoke",
    );
    if let Some(arr) = grant
        .get_mut("authority_receipt_refs")
        .and_then(|v| v.as_array_mut())
    {
        arr.push(json!(receipt_ref));
    }
    let _ = persist_record(data_dir, "authority-grants", &grant_id, &grant);
    Json(
        json!({ "ok": true, "grant_ref": grant_ref, "status": "revoked", "receipt_ref": receipt_ref, "at": iso_now() }),
    )
}

/// GET /v1/hypervisor/authority/grants — list persisted grants with LIVE status (active | expired
/// | revoked | denied | no_grant_needed) computed from the real clock + revoke flag.
pub(crate) async fn handle_authority_grants_list(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    let mut grants = read_record_dir(&st.data_dir, "authority-grants");
    for g in grants.iter_mut() {
        let status = live_grant_status(g);
        g["status"] = json!(status);
    }
    Json(json!({
        "schema_version": "ioi.hypervisor.authority-grants.v1",
        "grants": grants,
        "at": iso_now()
    }))
}

/// POST /v1/hypervisor/authority/preflight — environment-lifecycle crossing admission. Body:
/// `{effect, environment_id?, grant_ref?}`. Local effects admit with local authority; portable
/// crossings require a present, non-revoked, non-expired grant covering the effect — else BLOCK
/// fail-closed with a precise reason (no grant / revoked / expired+re-auth / mismatch). Emits a
/// preflight receipt either way.
pub(crate) async fn handle_authority_preflight(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let data_dir = &st.data_dir;
    let effect = body
        .get("effect")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let environment_id = body
        .get("environment_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let grant_key = body
        .get("grant_ref")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("grant_id").and_then(|v| v.as_str()));

    // Local effects: admitted by local_operator authority, no portable grant.
    if LOCAL_ALLOWED.contains(&effect.as_str()) {
        let receipt = emit_receipt(
            data_dir,
            "preflight_admit",
            "grant:local_operator",
            &environment_id,
            &effect,
            "local authority",
        );
        return Json(json!({
            "schema_version": "ioi.hypervisor.authority-preflight.v1",
            "effect": effect, "environment_id": environment_id,
            "admitted": true, "authority": "local_operator",
            "reason": format!("'{effect}' covered by local_operator authority"),
            "receipt_ref": receipt, "at": iso_now()
        }));
    }
    // Unrecognized effect: fail closed.
    if !WALLET_REQUIRED.contains(&effect.as_str()) {
        let receipt = emit_receipt(
            data_dir,
            "preflight_block",
            "",
            &environment_id,
            &effect,
            "unrecognized effect",
        );
        return Json(json!({
            "schema_version": "ioi.hypervisor.authority-preflight.v1",
            "effect": effect, "environment_id": environment_id,
            "admitted": false, "authority": "fail_closed",
            "reason": format!("'{effect}' is not a recognized crossing; blocked fail-closed"),
            "receipt_ref": receipt, "at": iso_now()
        }));
    }
    // Portable crossing: must present a live grant covering the effect.
    let block = |reason: &str, re_auth: bool, receipt: String| {
        Json(json!({
            "schema_version": "ioi.hypervisor.authority-preflight.v1",
            "effect": effect, "environment_id": environment_id,
            "admitted": false, "authority": "portable", "requires_portable_authority": true,
            "re_auth_required": re_auth, "reason": reason, "receipt_ref": receipt, "at": iso_now()
        }))
    };
    let Some(key) = grant_key else {
        let receipt = emit_receipt(
            data_dir,
            "preflight_block",
            "",
            &environment_id,
            &effect,
            "no grant presented",
        );
        return block(
            &format!("'{effect}' requires a portable authority grant; none presented"),
            true,
            receipt,
        );
    };
    let Some(grant) = load_grant(data_dir, key) else {
        let receipt = emit_receipt(
            data_dir,
            "preflight_block",
            key,
            &environment_id,
            &effect,
            "grant not found",
        );
        return block(&format!("grant '{key}' not found"), true, receipt);
    };
    let grant_ref = grant
        .get("grant_ref")
        .and_then(|v| v.as_str())
        .unwrap_or(key)
        .to_string();
    match live_grant_status(&grant) {
        "revoked" => {
            let receipt = emit_receipt(
                data_dir,
                "preflight_block",
                &grant_ref,
                &environment_id,
                &effect,
                "grant revoked",
            );
            block("grant has been revoked; execution refused", true, receipt)
        }
        "expired" => {
            let receipt = emit_receipt(
                data_dir,
                "preflight_block",
                &grant_ref,
                &environment_id,
                &effect,
                "grant expired",
            );
            block(
                "grant expired; re-authentication required, no execution",
                true,
                receipt,
            )
        }
        "denied" => {
            let receipt = emit_receipt(
                data_dir,
                "preflight_block",
                &grant_ref,
                &environment_id,
                &effect,
                "grant was denied",
            );
            block("authority was denied; fail closed", true, receipt)
        }
        "active" => {
            let covers = grant.get("action").and_then(|v| v.as_str()) == Some(effect.as_str());
            if !covers {
                let receipt = emit_receipt(
                    data_dir,
                    "preflight_block",
                    &grant_ref,
                    &environment_id,
                    &effect,
                    "grant action does not cover effect",
                );
                return block(
                    &format!(
                        "grant covers '{}', not '{effect}'",
                        grant.get("action").and_then(|v| v.as_str()).unwrap_or("")
                    ),
                    false,
                    receipt,
                );
            }
            let receipt = emit_receipt(
                data_dir,
                "preflight_admit",
                &grant_ref,
                &environment_id,
                &effect,
                "valid portable grant",
            );
            Json(json!({
                "schema_version": "ioi.hypervisor.authority-preflight.v1",
                "effect": effect, "environment_id": environment_id,
                "admitted": true, "authority": "portable",
                "grant_ref": grant_ref,
                "provider": grant.get("provider"),
                "reason": format!("valid portable grant admits '{effect}'"),
                "receipt_ref": receipt, "at": iso_now()
            }))
        }
        other => {
            let receipt = emit_receipt(
                data_dir,
                "preflight_block",
                &grant_ref,
                &environment_id,
                &effect,
                other,
            );
            block(
                &format!("grant status '{other}'; fail closed"),
                true,
                receipt,
            )
        }
    }
}

/// GET /v1/hypervisor/authority/receipts — the authority audit trail (granted/denied/revoked/
/// preflight admit/block), most recent first by id.
pub(crate) async fn handle_authority_receipts(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut receipts = read_record_dir(&st.data_dir, "authority-receipts");
    receipts.sort_by(|a, b| {
        b.get("receipt_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("receipt_id").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(json!({
        "schema_version": "ioi.hypervisor.authority-receipts.v1",
        "receipts": receipts,
        "at": iso_now()
    }))
}

#[cfg(test)]
mod exact_action_authority_tests {
    use super::*;

    fn temp_data_dir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ioi-exact-action-authority-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("temporary authority data dir");
        path
    }

    #[test]
    fn retry_reuses_one_retained_exact_action_grant_and_refuses_coordinate_drift() {
        let data_dir = temp_data_dir();
        let data_dir_string = data_dir.to_string_lossy().to_string();
        let issue = |effect_hash: &str| {
            issue_exact_action_grant(
                &data_dir_string,
                "agent://agent-a",
                "workflow.edit.apply",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                effect_hash,
                "state://workspace-target/target-a",
                "proposal://workflow-edit/proposal-a",
                120,
            )
        };
        let effect_hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let first = issue(effect_hash).expect("initial exact-action grant");
        let replay = issue(effect_hash).expect("file-backed issue replay");
        assert_eq!(replay, first);
        assert_eq!(
            read_record_dir(&data_dir_string, "authority-grants")
                .into_iter()
                .filter(|grant| {
                    grant
                        .pointer("/resources/proposal_ref")
                        .and_then(Value::as_str)
                        == Some("proposal://workflow-edit/proposal-a")
                })
                .count(),
            1
        );

        let drift =
            issue("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
                .expect_err("one proposal cannot mint a changed exact-action grant");
        assert!(drift.contains("does not bind /effect_hash"));
        assert_eq!(
            read_record_dir(&data_dir_string, "authority-grants").len(),
            1
        );
        std::fs::remove_dir_all(data_dir).expect("remove temporary authority data dir");
    }
}
