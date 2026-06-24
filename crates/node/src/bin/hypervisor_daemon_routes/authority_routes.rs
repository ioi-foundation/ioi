//! WS-G — local-operator authority (`LocalAuthorityProvider`).
//!
//! Phase 0 authority posture: `local_operator`. wallet.network is NOT live; wallet-required
//! crossings are represented, previewed, and blocked/degraded — never silently allowed. No
//! raw secrets enter daemon/management-plane truth (capability-lease refs only). Canon:
//! `wallet-network/doctrine.md` (which crossings escalate to portable authority).
use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, DaemonState};

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

/// POST /v1/hypervisor/harness-bindings — WS-D: compile a per-session config into an
/// admitted HarnessSessionBinding (Agent/Mode/Model/Reasoning/Speed/Harness/Tools/Memory/
/// Authority/Budget/Privacy). Daemon-owned; persisted under state_dir/harness-bindings.
pub(crate) async fn handle_harness_binding_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let now = iso_now();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let id = format!("hsb_{nanos:x}");
    let pick = |k: &str, default: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or(default).to_string();
    let record = json!({
        "schema_version": "ioi.hypervisor.harness-session-binding.v1",
        "harness_binding_id": id,
        "agent": pick("agent", "default"),
        "mode": pick("mode", "agent"),
        "model": pick("model", "hypervisor:native-local"),
        "reasoning": pick("reasoning", "medium"),
        "speed": pick("speed", "balanced"),
        "harness": pick("harness", "default-harness-profile"),
        "tools": body.get("tools").cloned().unwrap_or_else(|| json!([])),
        "memory": pick("memory", "session_scoped"),
        "authority_posture": "local_operator",
        "budget": body.get("budget").cloned().unwrap_or(Value::Null),
        "privacy": pick("privacy", "local_private"),
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
        ("allowed_local", format!("'{effect}' is within local_operator authority"))
    } else {
        ("blocked", format!("'{effect}' is not a recognized local effect; blocked fail-closed"))
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
