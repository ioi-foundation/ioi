//! Pre-applications WS-3/WS-8 — editor-target registry + host-provisioning plans + editor access
//! services + access leases, all daemon-owned truth.
//!
//! Locked decisions enforced here:
//! - editor access leases are capability leases issued through the EXISTING authority grant
//!   machinery (`authority_routes::issue_capability_lease`) — no parallel SessionAccessLease.
//! - one proven browser target (vscode-browser / oss_openvscode); others stay declared.
//! - the daemon owns truth; provider/runtime IDs are evidence only.
//!
//! Routes are collision-safe: editor services are a TOP-LEVEL resource
//! (`/v1/hypervisor/editor-services`), NOT `/v1/hypervisor/environments/:id/editor-services` —
//! that would collide with the existing `environments/:id/:action` param route and panic matchit.
//!
//! The editor RUNTIME (openvscode-server) is provisioned in WS-2 and the WS proxy in WS-4. Until
//! then, service start fails CLOSED with a precise reason (`editor_runtime_not_provisioned`) — the
//! skeleton is honest, never a fake "ready".
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, Query, State};
use axum::Json;
use serde_json::{json, Value};

use super::authority_routes::{capability_lease_status, issue_capability_lease};
use super::{iso_now, persist_record, read_record_dir, DaemonState};

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}

/// Repo-relative editor-target manifest (daemon cwd = repo root in normal + verifier runs).
fn manifest_path() -> PathBuf {
    std::env::var("IOI_HYPERVISOR_EDITOR_TARGETS_MANIFEST")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::current_dir()
                .unwrap_or_default()
                .join("packages/hypervisor-adapter-targets/editor-targets.manifest.json")
        })
}
fn profiles_dir() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_default()
        .join("packages/hypervisor-adapter-targets/code-editors/profiles")
}
fn read_json(p: &Path) -> Option<Value> {
    std::fs::read(p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

fn editor_receipt(data_dir: &str, subject: &str, event: &str) -> String {
    let id = format!("erc_{:x}", nanos());
    let receipt_ref = format!("agentgres://editor-receipt/{id}");
    let _ = persist_record(
        data_dir,
        "editor-receipts",
        &id,
        &json!({
            "schema_version": "ioi.hypervisor.editor-receipt.v1", "receipt_id": id, "receipt_ref": receipt_ref,
            "subject": subject, "event": event, "at": iso_now()
        }),
    );
    receipt_ref
}

fn load_by(data_dir: &str, dir: &str, key: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, dir)
        .into_iter()
        .find(|r| r.get(key).and_then(|v| v.as_str()) == Some(id))
}

// ---------------------------------------------------------------------------
// editor-targets registry (read the WS-1 manifest + profiles)
// ---------------------------------------------------------------------------

fn load_registry() -> (Value, Vec<Value>) {
    let manifest = read_json(&manifest_path()).unwrap_or_else(|| json!({ "families": [] }));
    let mut profiles = Vec::new();
    for fam in manifest
        .get("families")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default()
    {
        for ed in fam
            .get("editors")
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let id = ed.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let profile = read_json(&profiles_dir().join(format!("{id}.json")));
            profiles.push(json!({
                "target_id": id,
                "family": fam.get("id"),
                "status": ed.get("status").or_else(|| fam.get("status")),
                "profile": profile,
            }));
        }
    }
    (manifest, profiles)
}

/// GET /v1/hypervisor/editor-targets — the editor-target registry (manifest + resolved profiles).
pub(crate) async fn handle_editor_targets_list(State(_st): State<Arc<DaemonState>>) -> Json<Value> {
    let (manifest, profiles) = load_registry();
    let active: Vec<String> = profiles
        .iter()
        .filter(|p| p.get("status").and_then(|v| v.as_str()) == Some("active"))
        .filter_map(|p| {
            p.get("target_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .collect();
    Json(json!({
        "schema_version": "ioi.hypervisor.editor-targets.v1",
        "default_editor": manifest.get("defaultEditorId"),
        "active_targets": active,
        "targets": profiles,
        "locked_decisions": manifest.get("lockedDecisions"),
        "at": iso_now()
    }))
}

/// GET /v1/hypervisor/editor-targets/:id — one resolved editor-target profile.
pub(crate) async fn handle_editor_target_get(
    State(_st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let (_m, profiles) = load_registry();
    match profiles
        .into_iter()
        .find(|p| p.get("target_id").and_then(|v| v.as_str()) == Some(id.as_str()))
    {
        Some(p) => Json(json!({ "target": p })),
        None => Json(json!({ "error": { "code": "not_found", "target": id } })),
    }
}

// ---------------------------------------------------------------------------
// editor-host-provisioning-plans (declared here; executed in WS-2)
// ---------------------------------------------------------------------------

/// POST /v1/hypervisor/editor-host-provisioning-plans — declare a host provisioning plan.
pub(crate) async fn handle_provisioning_plan_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let id = format!("ehp_{:x}", nanos());
    let receipt = editor_receipt(&st.data_dir, &id, "provisioning_plan_declared");
    let record = json!({
        "schema_version": "ioi.hypervisor.editor-host-provisioning-plan.v1",
        "plan_ref": format!("editor_host_plan:{id}"), "plan_id": id,
        "environment_ref": s(&body, "environment_ref", ""),
        "session_ref": s(&body, "session_ref", ""),
        "target_profile_ref": s(&body, "target_profile_ref", "vscode-browser"),
        "runtime_variant": s(&body, "runtime_variant", "oss_openvscode"),
        "server_commit_ref": body.get("server_commit_ref").cloned().unwrap_or(Value::Null),
        "server_binary_ref": body.get("server_binary_ref").cloned().unwrap_or(Value::Null),
        "server_binary_hash": body.get("server_binary_hash").cloned().unwrap_or(Value::Null),
        "extension_bundle_refs": body.get("extension_bundle_refs").cloned().unwrap_or_else(|| json!([])),
        "install_root_ref": body.get("install_root_ref").cloned().unwrap_or(Value::Null),
        "config_refs": body.get("config_refs").cloned().unwrap_or_else(|| json!([])),
        "authority_scope_refs": ["scope:environment.editor.open"],
        "readiness_gate_ref": format!("editor_readiness_gate:{id}"),
        "status": "declared",
        "receipt_refs": [receipt],
        "created_at": iso_now()
    });
    let _ = persist_record(&st.data_dir, "editor-host-provisioning-plans", &id, &record);
    Json(json!({ "plan": record }))
}

/// GET /v1/hypervisor/editor-host-provisioning-plans/:id
pub(crate) async fn handle_provisioning_plan_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load_by(
        &st.data_dir,
        "editor-host-provisioning-plans",
        "plan_id",
        &id,
    ) {
        Some(p) => Json(json!({ "plan": p })),
        None => Json(json!({ "error": { "code": "not_found", "plan": id } })),
    }
}

// ---------------------------------------------------------------------------
// editor access services (a normal environment service; runtime starts in WS-2)
// ---------------------------------------------------------------------------

/// POST /v1/hypervisor/editor-services — create an editor access service for an environment.
pub(crate) async fn handle_editor_service_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let env_id = s(&body, "environment_id", "");
    let target = s(&body, "target_profile", "vscode-browser");
    let id = format!("eds_{:x}", nanos());
    let receipt = editor_receipt(&st.data_dir, &id, "editor_service_created");
    let record = json!({
        "schema_version": "ioi.hypervisor.editor-access-service.v1",
        "service_ref": format!("environment_service:editor_{id}"), "service_id": id,
        "environment_id": env_id, "service_role": "editor_access_service",
        "target_profile": target, "runtime_variant": s(&body, "runtime_variant", "oss_openvscode"),
        "lifecycle": "support",
        "provisioning_plan_ref": body.get("provisioning_plan_ref").cloned().unwrap_or(Value::Null),
        "phase": "created",
        "internal_port": Value::Null, "public_proxy_port": Value::Null,
        "healthcheck": { "kind": "http", "path": "/version" },
        "readiness": { "mode": "blocked", "reason": "editor service created; not started" },
        "log_ref": format!("log://editor-services/{id}"),
        "receipt_refs": [receipt],
        "created_at": iso_now()
    });
    let _ = persist_record(&st.data_dir, "editor-services", &id, &record);
    Json(json!({ "editorService": record }))
}

/// GET /v1/hypervisor/editor-services?environment_id=… — list editor services.
pub(crate) async fn handle_editor_services_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let mut svcs = read_record_dir(&st.data_dir, "editor-services");
    if let Some(env) = q.get("environment_id") {
        svcs.retain(|s| s.get("environment_id").and_then(|v| v.as_str()) == Some(env.as_str()));
    }
    Json(
        json!({ "schema_version": "ioi.hypervisor.editor-services.v1", "editorServices": svcs, "at": iso_now() }),
    )
}

fn save_service(data_dir: &str, svc: &Value) {
    if let Some(id) = svc.get("service_id").and_then(|v| v.as_str()) {
        let _ = persist_record(data_dir, "editor-services", id, svc);
    }
}

/// POST /v1/hypervisor/editor-services/:service_id/start — start the editor runtime (openvscode-
/// server) and wait for real /version readiness. Body may carry `{ session_ref, access_lease_ref }`
/// (WS-6a binding refs injected into the editor host). Until a reproducible OSS runtime is pinned,
/// fails CLOSED with `editor_runtime_not_provisioned` (honest — never a fake ready).
pub(crate) async fn handle_editor_service_start(
    State(st): State<Arc<DaemonState>>,
    AxumPath(service_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut svc) = load_by(&st.data_dir, "editor-services", "service_id", &service_id) else {
        return Json(json!({ "ok": false, "reason": "editor service not found" }));
    };
    // inject binding refs (WS-6a) the editor host will surface in context envelopes.
    if let Some(sr) = body.get("session_ref").and_then(|v| v.as_str()) {
        svc["session_ref"] = json!(sr);
    }
    if let Some(lr) = body.get("access_lease_ref").and_then(|v| v.as_str()) {
        svc["access_lease_ref"] = json!(lr);
    }
    // WS-2 gate: is an OSS browser-IDE runtime provisioned + reachable?
    if !super::editor_host::oss_runtime_present() {
        svc["phase"] = json!("waiting_for_runtime");
        svc["readiness"] = json!({ "mode": "blocked", "reason": "editor_runtime_not_provisioned", "detail": "openvscode-server not pinned/installed yet (WS-2). Run scripts/provision-hypervisor-vscode-browser-host.mjs" });
        save_service(&st.data_dir, &svc);
        return Json(
            json!({ "ok": false, "editorService": svc, "reason": "editor_runtime_not_provisioned" }),
        );
    }
    // WS-2 present: launch + wait for /version.
    match super::editor_host::start_oss_runtime(&st, &service_id, &svc).await {
        Ok(updated) => {
            save_service(&st.data_dir, &updated);
            editor_receipt(&st.data_dir, &service_id, "editor_service_ready");
            Json(json!({ "ok": true, "editorService": updated }))
        }
        Err(reason) => {
            svc["phase"] = json!("failed");
            svc["readiness"] = json!({ "mode": "blocked", "reason": reason });
            save_service(&st.data_dir, &svc);
            Json(json!({ "ok": false, "editorService": svc, "reason": reason }))
        }
    }
}

/// POST /v1/hypervisor/editor-services/:service_id/expose — bind a lease-authenticated WS proxy
/// (WS-4) in front of the ready runtime's internal port. Body: `{ lease_id }`. The public URL is
/// served by the proxy; the raw internal port is never exposed. Fail-closed: requires a ready
/// service + an active capability lease.
pub(crate) async fn handle_editor_service_expose(
    State(st): State<Arc<DaemonState>>,
    AxumPath(service_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut svc) = load_by(&st.data_dir, "editor-services", "service_id", &service_id) else {
        return Json(json!({ "ok": false, "reason": "editor service not found" }));
    };
    if svc.get("phase").and_then(|v| v.as_str()) != Some("ready") {
        return Json(
            json!({ "ok": false, "reason": "editor service not ready (start it first)", "phase": svc.get("phase") }),
        );
    }
    let internal_port = match svc.get("internal_port").and_then(|v| v.as_u64()) {
        Some(p) => p as u16,
        None => return Json(json!({ "ok": false, "reason": "no internal runtime port" })),
    };
    let lease_id = s(&body, "lease_id", "");
    if capability_lease_status(&st.data_dir, &lease_id) != "active" {
        return Json(
            json!({ "ok": false, "reason": format!("capability lease not active ({})", capability_lease_status(&st.data_dir, &lease_id)), "fail_closed": true }),
        );
    }
    // replace any prior proxy for this service.
    {
        let mut proxies = st.editor_proxies.lock().unwrap();
        super::editor_proxy::stop_editor_proxy(&mut proxies, &service_id);
    }
    let (public_port, proxy) = match super::editor_proxy::bind_editor_proxy(
        &st.data_dir,
        &service_id,
        internal_port,
        &lease_id,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return Json(json!({ "ok": false, "reason": format!("proxy bind failed: {e}") })),
    };
    st.editor_proxies
        .lock()
        .unwrap()
        .insert(service_id.clone(), proxy);
    svc["public_proxy_port"] = json!(public_port);
    svc["bound_lease_id"] = json!(lease_id);
    save_service(&st.data_dir, &svc);
    editor_receipt(&st.data_dir, &service_id, "editor_proxy_bound");
    Json(json!({
        "ok": true, "service_id": service_id,
        "public_proxy_port": public_port,
        "open_url": format!("http://127.0.0.1:{public_port}/?lease={lease_id}"),
        "auth_mode": "first_message_session_token", "lease_id": lease_id
    }))
}

/// POST /v1/hypervisor/editor-services/:service_id/stop
pub(crate) async fn handle_editor_service_stop(
    State(st): State<Arc<DaemonState>>,
    AxumPath(service_id): AxumPath<String>,
) -> Json<Value> {
    let Some(mut svc) = load_by(&st.data_dir, "editor-services", "service_id", &service_id) else {
        return Json(json!({ "ok": false, "reason": "editor service not found" }));
    };
    {
        let mut proxies = st.editor_proxies.lock().unwrap();
        super::editor_proxy::stop_editor_proxy(&mut proxies, &service_id);
    }
    super::editor_host::stop_oss_runtime(&st, &service_id);
    svc["phase"] = json!("stopped");
    svc["readiness"] = json!({ "mode": "blocked", "reason": "stopped" });
    svc["internal_port"] = Value::Null;
    svc["public_proxy_port"] = Value::Null;
    save_service(&st.data_dir, &svc);
    editor_receipt(&st.data_dir, &service_id, "editor_service_stopped");
    Json(json!({ "ok": true, "editorService": svc }))
}

/// POST /v1/hypervisor/editor-services/:service_id/rebuild — reconcile/rebuild (recipe-driven).
pub(crate) async fn handle_editor_service_rebuild(
    State(st): State<Arc<DaemonState>>,
    AxumPath(service_id): AxumPath<String>,
) -> Json<Value> {
    let Some(mut svc) = load_by(&st.data_dir, "editor-services", "service_id", &service_id) else {
        return Json(json!({ "ok": false, "reason": "editor service not found" }));
    };
    super::editor_host::stop_oss_runtime(&st, &service_id);
    svc["phase"] = json!("created");
    svc["readiness"] =
        json!({ "mode": "blocked", "reason": "rebuild requested; restart to re-provision" });
    save_service(&st.data_dir, &svc);
    let receipt = editor_receipt(&st.data_dir, &service_id, "editor_service_rebuild");
    Json(json!({ "ok": true, "editorService": svc, "receipt_ref": receipt }))
}

/// GET /v1/hypervisor/editor-services/:service_id/status
pub(crate) async fn handle_editor_service_status(
    State(st): State<Arc<DaemonState>>,
    AxumPath(service_id): AxumPath<String>,
) -> Json<Value> {
    match load_by(&st.data_dir, "editor-services", "service_id", &service_id) {
        Some(svc) => Json(
            json!({ "status": svc.get("readiness"), "phase": svc.get("phase"), "internal_port": svc.get("internal_port"), "public_proxy_port": svc.get("public_proxy_port"), "service": svc }),
        ),
        None => Json(json!({ "error": { "code": "not_found", "service": service_id } })),
    }
}

/// GET /v1/hypervisor/editor-services/:service_id/logs
pub(crate) async fn handle_editor_service_logs(
    State(st): State<Arc<DaemonState>>,
    AxumPath(service_id): AxumPath<String>,
) -> Json<Value> {
    let log = super::editor_host::read_runtime_log(&st.data_dir, &service_id);
    Json(json!({ "service_id": service_id, "log": log, "at": iso_now() }))
}

/// GET /v1/hypervisor/editor-services/:service_id/open-url — the daemon-generated browser URL.
/// Requires a VALID capability lease (the WS proxy enforces it again at connect). Until the
/// service is `ready` (WS-2) this returns a named not-ready reason — never a fabricated URL.
pub(crate) async fn handle_editor_service_open_url(
    State(st): State<Arc<DaemonState>>,
    AxumPath(service_id): AxumPath<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let Some(svc) = load_by(&st.data_dir, "editor-services", "service_id", &service_id) else {
        return Json(json!({ "ok": false, "reason": "editor service not found" }));
    };
    let lease = q.get("lease_ref").cloned().unwrap_or_default();
    let lease_status = if lease.is_empty() {
        "missing"
    } else {
        capability_lease_status(&st.data_dir, &lease)
    };
    if lease_status != "active" {
        return Json(
            json!({ "ok": false, "reason": format!("capability lease not active ({lease_status})"), "fail_closed": true }),
        );
    }
    if svc.get("phase").and_then(|v| v.as_str()) != Some("ready") {
        return Json(
            json!({ "ok": false, "reason": "editor service not ready", "phase": svc.get("phase"), "readiness": svc.get("readiness") }),
        );
    }
    // Ready runtime, but the lease-bound PUBLIC url routes through the WS proxy (WS-4). Until the
    // proxy is bound we do NOT hand out the raw internal port as a durable URL — fail closed honestly.
    let port = svc.get("public_proxy_port").and_then(|v| v.as_u64());
    let Some(p) = port else {
        return Json(
            json!({ "ok": false, "reason": "websocket_proxy_not_ready", "detail": "editor runtime is ready on its internal port; the lease-bound public URL needs the WS proxy (WS-4)", "phase": "ready" }),
        );
    };
    Json(json!({
        "ok": true, "service_id": service_id,
        "open_url": format!("http://127.0.0.1:{p}/?lease={lease}"),
        "lease_ref": lease, "websocket_only": true,
        "note": "route through the browser-IDE shell URL; the raw WS-only target is not a plain preview",
    }))
}

// ---------------------------------------------------------------------------
// editor access leases (capability leases — reuse the authority grant machinery)
// ---------------------------------------------------------------------------

/// POST /v1/hypervisor/editor-access-leases — issue a capability lease for editor access.
/// Body: `{ session_id|session_ref, environment_id, service_id?, expiry_seconds? }`. Reuses the
/// authority grant machinery (Locked Decision 1) — revocable via /authority/revoke, visible in
/// /authority/grants. Returns `capability_lease_ref`.
pub(crate) async fn handle_editor_access_lease_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let subject = body
        .get("session_id")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("session_ref").and_then(|v| v.as_str()))
        .unwrap_or("operator")
        .to_string();
    let env = s(&body, "environment_id", "");
    let service = s(&body, "service_id", "");
    let expiry = body
        .get("expiry_seconds")
        .and_then(|v| v.as_i64())
        .unwrap_or(3600);
    let resources = json!([
        format!("environment:{env}"),
        format!("editor_service:{service}")
    ]);
    let grant = issue_capability_lease(
        &st.data_dir,
        &subject,
        "environment.editor.open",
        resources,
        expiry,
    );
    let lease_ref = grant
        .get("grant_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let lease_id = grant
        .get("grant_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    editor_receipt(&st.data_dir, &service, "editor_access_lease_issued");
    Json(json!({
        "schema_version": "ioi.hypervisor.editor-access-lease.v1",
        "capability_lease_ref": lease_ref,
        "lease_ref": lease_ref,
        "lease_id": lease_id,
        "session_ref": subject, "environment_id": env, "service_id": service,
        "expires_at_unix": grant.get("expires_at_unix"),
        "revoke_route": format!("/v1/hypervisor/editor-access-leases/{lease_id}/revoke"),
        "status": "active", "at": iso_now()
    }))
}

/// POST /v1/hypervisor/editor-access-leases/:lease_id/revoke — revoke via the authority machinery.
/// `:lease_id` is the grant_id (slash-free); revoke marks the underlying capability grant revoked,
/// so /authority/grants and the open-url/proxy gate all see it immediately.
pub(crate) async fn handle_editor_access_lease_revoke(
    State(st): State<Arc<DaemonState>>,
    AxumPath(lease_id): AxumPath<String>,
    Json(_b): Json<Value>,
) -> Json<Value> {
    let status_before = capability_lease_status(&st.data_dir, &lease_id);
    if status_before == "missing" {
        return Json(json!({ "ok": false, "reason": format!("lease '{lease_id}' not found") }));
    }
    let revoke = super::authority_routes::handle_authority_revoke(
        State(st.clone()),
        Json(json!({ "grant_id": lease_id })),
    )
    .await;
    editor_receipt(&st.data_dir, &lease_id, "editor_access_lease_revoked");
    Json(
        json!({ "ok": revoke.0.get("ok").and_then(|v| v.as_bool()).unwrap_or(false), "lease_id": lease_id, "revoke": revoke.0, "status": "revoked" }),
    )
}
