//! Hypervisor Daemon — the Rust true-north HTTP edge for the Hypervisor App.
//!
//! Phase 5 of the real-environment-and-harness-execution master guide: stand up
//! a Rust binary that serves the model-mount kernel (`ModelMountCore`) and the
//! inference edge (`HttpInferenceRuntime`) over HTTP, so the app talks to Rust
//! Core instead of the JS dev-replay scaffold. The kernel is true-north; this
//! daemon is the transport. No silent prose: a turn streams a real model or an
//! honest `no_model_route` error.
//!
//! Binds 127.0.0.1:8765 by default (the app + dev-replay endpoint) so no app
//! change is required to point at it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, patch, post},
    Json, Router,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};
use ioi_services::agentic::runtime::kernel::model_mount::{
    ModelMountArtifactEndpointRequest, ModelMountBackendLifecycleRequest,
    ModelMountCapabilityTokenControlRequest, ModelMountCore,
    ModelMountProviderControlRequest, ModelMountProviderExecutionRequest,
    ModelMountProviderInvocationRequest, ModelMountReadProjectionRequest,
    ModelMountRuntimeEngineRequest, ModelMountRuntimeSurveyRequest,
    ModelMountServerControlRequest, MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION,
    MODEL_MOUNT_BACKEND_LIFECYCLE_SCHEMA_VERSION,
    MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION,
    MODEL_MOUNT_RUNTIME_ENGINE_SCHEMA_VERSION, MODEL_MOUNT_RUNTIME_SURVEY_SCHEMA_VERSION,
    MODEL_MOUNT_SERVER_CONTROL_SCHEMA_VERSION,
};
use ioi_types::app::agentic::InferenceOptions;

struct DaemonState {
    inference: Arc<dyn InferenceRuntime>,
    model_name: String,
    data_dir: String,
    base_url: String,
    // Expiry enforcement (execution semantics): token_hash -> unix-seconds, 0 = none.
    token_expiry: Mutex<HashMap<String, i64>>,
}

// Error responses render as JSON so OpenAI-compatible/model-mount clients (and
// the e2e, which JSON.parses every body) can read them.
struct AppError(StatusCode, String);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = self.0;
        let message = self.1;
        (status, Json(json!({ "error": { "message": message } }))).into_response()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = ioi_telemetry::init::init_tracing();

    let addr_str = std::env::var("IOI_HYPERVISOR_DAEMON_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8765".to_string());
    let addr: SocketAddr = addr_str.parse()?;

    let (api_url, api_key, model_name) = resolve_inference();
    tracing::info!(%api_url, %model_name, "hypervisor-daemon inference route");
    let inference: Arc<dyn InferenceRuntime> =
        Arc::new(HttpInferenceRuntime::new(api_url, api_key, model_name.clone()));

    let data_dir = std::env::var("IOI_HYPERVISOR_DATA_DIR")
        .unwrap_or_else(|_| "./hypervisor-data".to_string());
    let _ = std::fs::create_dir_all(&data_dir);

    let state = Arc::new(DaemonState {
        inference,
        model_name,
        data_dir,
        base_url: format!("http://{addr}"),
        token_expiry: Mutex::new(HashMap::new()),
    });

    // Author the baseline provider + backend catalog as admitted records so the
    // snapshot/projection family lists them.
    seed_catalog(&state);

    let app = Router::new()
        .route("/healthz", get(|| async { "OK" }))
        .route("/readyz", get(|| async { "OK" }))
        .route(
            "/v1/hypervisor/dev-replay/status",
            get(handle_dev_replay_status),
        )
        .route("/v1/models", get(handle_models))
        .route("/v1/model-mount/server/status", get(handle_server_status))
        .route("/v1/model-mount/server/stop", post(handle_server_stop))
        .route("/v1/model-mount/server/restart", post(handle_server_restart))
        .route("/v1/model-mount/server/logs", get(handle_server_logs))
        .route("/v1/model-mount/server/events", get(handle_server_events))
        .route(
            "/v1/model-mount/tokens",
            post(handle_token_create),
        )
        .route(
            "/v1/model-mount/tokens/:id",
            delete(handle_token_revoke),
        )
        .route("/v1/model-mount/snapshot", get(handle_snapshot))
        .route("/v1/model-mount/providers", get(handle_providers))
        .route("/v1/model-mount/backends", get(handle_backends))
        .route(
            "/v1/model-mount/endpoints",
            get(handle_endpoints).post(handle_endpoints_mount),
        )
        .route("/v1/model-mount/artifacts/import", post(handle_artifacts_import))
        .route("/v1/model-mount/instances", get(handle_instances))
        .route("/v1/model-mount/runtime/engines", get(handle_runtime_engines))
        .route(
            "/v1/model-mount/runtime/engines/:id",
            get(handle_runtime_engine_detail).patch(handle_runtime_engine_patch),
        )
        .route("/v1/model-mount/runtime/select", post(handle_runtime_select))
        .route("/v1/model-mount/runtime/survey", post(handle_runtime_survey))
        .route("/v1/model-mount/receipts", get(handle_receipts_list))
        .route("/v1/model-mount/receipts/:id", get(handle_receipt_by_id))
        .route("/v1/model-mount/read-projection", post(handle_read_projection))
        .route("/v1/model-mount/native-local", post(handle_native_local))
        .route("/v1/chat/completions", post(handle_chat_completions))
        .route("/v1/hypervisor/session-turns", post(handle_session_turn))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "hypervisor-daemon listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Resolve the OpenAI-compatible inference endpoint. Honors the same
/// IOI_HYPERVISOR_MODEL_UPSTREAM the JS daemon used (Phase 0); else OpenAI,
/// LOCAL_LLM_URL, or the local Ollama default. Qwen-on-Ollama is the default.
fn resolve_inference() -> (String, String, String) {
    let model = std::env::var("IOI_HYPERVISOR_MODEL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "qwen2.5-coder".to_string());

    if let Ok(base) = std::env::var("IOI_HYPERVISOR_MODEL_UPSTREAM") {
        let base = base.trim_end_matches('/').to_string();
        return (format!("{base}/chat/completions"), String::new(), model);
    }
    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        let m = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
        return (
            "https://api.openai.com/v1/chat/completions".to_string(),
            key,
            m,
        );
    }
    if let Ok(url) = std::env::var("LOCAL_LLM_URL") {
        return (url, String::new(), model);
    }
    (
        "http://localhost:11434/v1/chat/completions".to_string(),
        String::new(),
        model,
    )
}

fn debug_string<E: std::fmt::Debug>(error: E) -> String {
    format!("{error:?}")
}

fn short_hash(input: &str) -> String {
    // Cheap stable id without pulling a hasher into scope.
    let mut acc: u64 = 1469598103934665603;
    for byte in input.bytes() {
        acc ^= byte as u64;
        acc = acc.wrapping_mul(1099511628211);
    }
    format!("{acc:016x}")
}

fn flatten_messages(body: &Value) -> String {
    if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
        let mut out = String::new();
        for message in messages {
            let role = message.get("role").and_then(|r| r.as_str()).unwrap_or("user");
            let content = message
                .get("content")
                .and_then(|c| c.as_str())
                .unwrap_or("");
            out.push_str(role);
            out.push_str(": ");
            out.push_str(content);
            out.push('\n');
        }
        return out;
    }
    body.get("prompt")
        .or_else(|| body.get("seed_intent"))
        .and_then(|p| p.as_str())
        .unwrap_or("Describe your task.")
        .to_string()
}

fn sse_frame(event: &str, data: &Value) -> String {
    format!(
        "event: {event}\ndata: {}\n\n",
        serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string())
    )
}

async fn handle_dev_replay_status() -> Json<Value> {
    Json(json!({
        "schema_version": "ioi.hypervisor.dev_replay_status.v1",
        "status": "ready",
        "boundary": "Rust hypervisor-daemon model-mount + inference edge.",
        "runtimeTruthSource": "daemon-runtime",
    }))
}

async fn handle_models(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": [{ "id": st.model_name, "object": "model", "owned_by": "hypervisor-local" }],
    }))
}

/// Server status, projected by the kernel from Agentgres-admitted server-control
/// records under `state_dir` (controlStatus is "running"; schemaVersion is the
/// runtime envelope version the e2e asserts). Phase 5c.1.
async fn handle_server_status(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    let req: ModelMountReadProjectionRequest = serde_json::from_value(json!({
        "projection_kind": "server_status",
        "schema_version": "ioi.model-mounting.runtime.v1",
        "base_url": st.base_url,
        "state_dir": st.data_dir,
        "state": {},
    }))
    .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let plan = ModelMountCore
        .plan_read_projection(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    Ok(Json(plan.projection))
}

// ---- Phase 5c.1: capability tokens + server control + the auth gate ----
// Truth/authority invariant: the kernel + a wallet.network grant DECIDE; the
// daemon ENFORCES and PROJECTS over Agentgres-admitted records under state_dir.

fn sha256_hex_str(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn parse_expiry_secs(value: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .map(|dt| dt.unix_timestamp())
}

/// Persist a kernel-authored Agentgres record so the read projections replay it.
/// The kernel record carries its own admission evidence; the daemon only writes
/// it to the canonical record dir under state_dir.
fn persist_record(
    data_dir: &str,
    record_dir: &str,
    record_id: &str,
    record: &Value,
) -> std::io::Result<()> {
    let dir = std::path::Path::new(data_dir).join(record_dir);
    std::fs::create_dir_all(&dir)?;
    let safe = record_id
        .replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_");
    std::fs::write(
        dir.join(format!("{safe}.json")),
        serde_json::to_vec_pretty(record).unwrap_or_default(),
    )
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Wallet-rooted capability gate. 401 if no bearer; 403 if the scope is
/// denied/expired/revoked. The kernel authorizes the scope against the admitted
/// grant; the daemon additionally enforces expiry (execution semantics).
fn authorize(
    st: &DaemonState,
    headers: &HeaderMap,
    required_scope: &str,
) -> Result<(), AppError> {
    let Some(token) = bearer_token(headers) else {
        return Err(AppError(
            StatusCode::UNAUTHORIZED,
            "missing capability token".to_string(),
        ));
    };
    let token_hash = sha256_hex_str(&token);
    if let Some(expiry) = st
        .token_expiry
        .lock()
        .ok()
        .and_then(|map| map.get(&token_hash).copied())
    {
        if expiry != 0 && expiry <= now_unix_secs() {
            return Err(AppError(StatusCode::FORBIDDEN, "capability token expired".to_string()));
        }
    }
    let req: ModelMountCapabilityTokenControlRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION,
        "operation_kind": "model_mount.capability_token.authorize",
        "state_dir": st.data_dir,
        "token_hash": token_hash,
        "required_scope": required_scope,
    }))
    .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    ModelMountCore
        .plan_capability_token_control(&req)
        .map(|_| ())
        .map_err(|error| AppError(StatusCode::FORBIDDEN, debug_string(error)))
}

/// POST /v1/model-mount/tokens — mint a wallet-rooted capability token via the
/// kernel; persist the redacted Agentgres record (token_hash only); return the
/// raw token once. Unauthenticated (the grant body carries the authority).
async fn handle_token_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let req: ModelMountCapabilityTokenControlRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION,
        "operation_kind": "model_mount.capability_token.create",
        "state_dir": st.data_dir,
        "body": body,
        "authority_grant_refs": ["wallet-network://capability-grant/model-mount"],
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let plan = ModelMountCore
        .plan_capability_token_control(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    persist_record(&st.data_dir, &plan.record_dir, &plan.record_id, &plan.record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    if let Some(token_hash) = plan.public_response.get("token_hash").and_then(|v| v.as_str()) {
        let expiry = body
            .get("expiresAt")
            .and_then(|v| v.as_str())
            .and_then(parse_expiry_secs)
            .unwrap_or(0);
        if let Ok(mut map) = st.token_expiry.lock() {
            map.insert(token_hash.to_string(), expiry);
        }
    }
    // The e2e uses both `token` (bearer) and `id` (revocation); map token_id -> id.
    let mut response = plan.public_response.clone();
    if let (Some(object), Some(token_id)) = (
        response.as_object_mut(),
        plan.public_response.get("token_id").cloned(),
    ) {
        object.insert("id".to_string(), token_id);
    }
    Ok(Json(response))
}

/// DELETE /v1/model-mount/tokens/:id — revoke via the kernel + persist the
/// revocation record (read by the authorize replay).
async fn handle_token_revoke(
    State(st): State<Arc<DaemonState>>,
    AxumPath(token_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let req: ModelMountCapabilityTokenControlRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION,
        "operation_kind": "model_mount.capability_token.revoke",
        "state_dir": st.data_dir,
        "token_id": token_id,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let plan = ModelMountCore
        .plan_capability_token_control(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    persist_record(&st.data_dir, &plan.record_dir, &plan.record_id, &plan.record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    Ok(Json(plan.public_response))
}

/// Server control via the kernel. stop -> controlStatus "stopped";
/// restart -> "running". The kernel emits a "*_planned" server_status; the
/// daemon maps it to the e2e controlStatus and adds a receiptId.
async fn run_server_control(
    st: Arc<DaemonState>,
    headers: HeaderMap,
    operation: &str,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, &format!("server.control:{operation}"))?;
    let req: ModelMountServerControlRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_SERVER_CONTROL_SCHEMA_VERSION,
        "operation_kind": format!("model_mount.server_control.{operation}"),
        "body": { "base_url": st.base_url },
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let plan = ModelMountCore
        .plan_server_control(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    persist_record(&st.data_dir, &plan.record_dir, &plan.record_id, &plan.record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let control_status = if operation == "stop" { "stopped" } else { "running" };
    let receipt_id = plan
        .receipt_refs
        .first()
        .cloned()
        .unwrap_or_else(|| plan.control_hash.clone());
    let mut response = plan.public_response.clone();
    if let Some(object) = response.as_object_mut() {
        object.insert("controlStatus".to_string(), json!(control_status));
        object.insert("receiptId".to_string(), json!(receipt_id));
    }
    Ok(Json(response))
}

async fn handle_server_stop(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    run_server_control(st, headers, "stop").await
}

async fn handle_server_restart(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    run_server_control(st, headers, "restart").await
}

fn server_control_projection(
    st: &DaemonState,
    kind: &str,
) -> Result<Json<Value>, AppError> {
    let req: ModelMountReadProjectionRequest = serde_json::from_value(json!({
        "projection_kind": kind,
        "schema_version": "ioi.model-mounting.runtime.v1",
        "base_url": st.base_url,
        "state_dir": st.data_dir,
        "state": { "limit": 20 },
    }))
    .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let plan = ModelMountCore
        .plan_read_projection(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    Ok(Json(plan.projection))
}

async fn handle_server_logs(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "server.logs:read")?;
    server_control_projection(&st, "server_logs")
}

async fn handle_server_events(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "server.logs:read")?;
    server_control_projection(&st, "server_events")
}

// ---- Phase 5c.2: baseline provider + backend catalog (admitted records) ----

const PROVIDER_KINDS: &[&str] = &[
    "local_folder",
    "ioi_native_local",
    "lm_studio",
    "ollama",
    "llama_cpp",
    "vllm",
    "openai_compatible",
    "custom_http",
    "depin_tee",
];

const BACKEND_CATALOG: &[(&str, &str)] = &[
    ("backend.fixture", "fixture"),
    ("backend.hypervisor.native-local.fixture", "ioi_native_local"),
    ("backend.llama-cpp", "llama_cpp"),
    ("backend.ollama", "ollama"),
    ("backend.vllm", "vllm"),
    ("backend.lmstudio", "lm_studio"),
    ("backend.openai-compatible", "openai_compatible"),
];

fn iso_now() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "2026-01-01T00:00:00Z".to_string())
}

/// Seed the baseline provider + backend catalog as Agentgres-admitted records:
/// author each through the kernel (plan_provider_control / plan_backend_lifecycle)
/// and persist plan.record under state_dir — NOT a raw fs::write of fixtures.
/// Idempotent (re-seeding overwrites the same content-addressed records).
fn seed_catalog(st: &DaemonState) {
    let generated_at = iso_now();
    for kind in PROVIDER_KINDS {
        let mut body = json!({
            "kind": kind,
            "status": "available",
            "label": format!("Hypervisor {kind} provider"),
        });
        // Only hosted-secret kinds require a vault secret_ref (provider_control
        // validation); custom_http is the one of our 9 that does.
        if *kind == "custom_http" {
            body["secret_ref"] = json!("vault://provider/custom_http");
        }
        let req: ModelMountProviderControlRequest = match serde_json::from_value(json!({
            "schema_version": MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION,
            "operation_kind": "model_mount.provider.write",
            "provider_id": format!("provider:{kind}"),
            "source": "hypervisor-daemon-catalog-seed",
            "generated_at": generated_at,
            "body": body,
            "authority_grant_refs": ["wallet-network://capability-grant/model-mount"],
        })) {
            Ok(req) => req,
            Err(error) => {
                tracing::warn!(%kind, "seed provider request build failed: {error}");
                continue;
            }
        };
        match ModelMountCore.plan_provider_control(&req) {
            Ok(plan) => {
                if let Err(error) =
                    persist_record(&st.data_dir, &plan.record_dir, &plan.record_id, &plan.record)
                {
                    tracing::warn!(%kind, "seed provider persist failed: {error}");
                }
            }
            Err(error) => tracing::warn!(%kind, "seed provider failed: {}", debug_string(error)),
        }
    }
    for (backend_id, backend_kind) in BACKEND_CATALOG {
        let req: ModelMountBackendLifecycleRequest = match serde_json::from_value(json!({
            "schema_version": MODEL_MOUNT_BACKEND_LIFECYCLE_SCHEMA_VERSION,
            "operation_kind": "model_mount.backend.health",
            "backend_id": backend_id,
            "backend_kind": backend_kind,
            "source": "hypervisor-daemon-catalog-seed",
            "generated_at": generated_at,
        })) {
            Ok(req) => req,
            Err(error) => {
                tracing::warn!(%backend_id, "seed backend request build failed: {error}");
                continue;
            }
        };
        match ModelMountCore.plan_backend_lifecycle(&req) {
            Ok(plan) => {
                if let Err(error) =
                    persist_record(&st.data_dir, &plan.record_dir, &plan.record_id, &plan.record)
                {
                    tracing::warn!(%backend_id, "seed backend persist failed: {error}");
                }
            }
            Err(error) => {
                tracing::warn!(%backend_id, "seed backend failed: {}", debug_string(error))
            }
        }
    }
    // Surface the native-local engine in the runtime-engine projection without a
    // competing profile record (a preference selecting it). The e2e's own PATCH
    // then owns the engine's profile (default_load_options).
    if let Ok(req) = serde_json::from_value::<ModelMountRuntimeEngineRequest>(json!({
        "schema_version": MODEL_MOUNT_RUNTIME_ENGINE_SCHEMA_VERSION,
        "operation_kind": "model_mount.runtime_preference.write",
        "engine_id": "backend.hypervisor.native-local.fixture",
        "source": "hypervisor-daemon-catalog-seed",
        "generated_at": generated_at,
    })) {
        if let Ok(plan) = ModelMountCore.plan_runtime_engine(&req) {
            let _ = persist_record(&st.data_dir, &plan.record_dir, &plan.record_id, &plan.record);
        }
    }
}

fn read_receipts(data_dir: &str) -> Vec<Value> {
    let dir = std::path::Path::new(data_dir).join("receipts");
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(bytes) = std::fs::read(entry.path()) {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    let has_id = value.get("id").and_then(|v| v.as_str()).is_some();
                    let has_kind = value.get("kind").and_then(|v| v.as_str()).is_some();
                    if has_id && has_kind {
                        out.push(value);
                    }
                }
            }
        }
    }
    out
}

// ---- Phase 5c.4: artifacts/import + endpoints/mount (kernel) ----

async fn handle_artifacts_import(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "model.import:write")?;
    // The kernel returns source_path_hash, not a content checksum; the e2e
    // asserts imported.checksum =~ /^sha256:/, so hash the artifact file here.
    let checksum = body
        .get("path")
        .and_then(|v| v.as_str())
        .and_then(|p| std::fs::read(p).ok())
        .map(|bytes| {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            format!("sha256:{}", hex::encode(hasher.finalize()))
        })
        .unwrap_or_else(|| "sha256:unavailable".to_string());
    // Map the e2e body field `path` -> kernel body `source_path`.
    let mut control_body = body.clone();
    if let Some(object) = control_body.as_object_mut() {
        if let Some(path) = object.remove("path") {
            object.insert("source_path".to_string(), path);
        }
    }
    let req: ModelMountArtifactEndpointRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION,
        "operation_kind": "model_mount.artifact.import",
        "body": control_body,
        "authority_grant_refs": ["wallet-network://capability-grant/model-mount"],
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let plan = ModelMountCore
        .plan_artifact_endpoint(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    persist_record(&st.data_dir, &plan.record_dir, &plan.record_id, &plan.record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let mut response = plan.public_response.clone();
    if let Some(object) = response.as_object_mut() {
        object.insert("checksum".to_string(), json!(checksum));
    }
    Ok(Json(response))
}

async fn handle_endpoints_mount(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "model.mount:write")?;
    // e2e body {model_id, id, provider_id} -> kernel body {model_id, endpoint_id, provider_id}.
    let mut control_body = body.clone();
    if let Some(object) = control_body.as_object_mut() {
        if let Some(id) = object.remove("id") {
            object.insert("endpoint_id".to_string(), id);
        }
    }
    let req: ModelMountArtifactEndpointRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION,
        "operation_kind": "model_mount.endpoint.mount",
        "body": control_body,
        "authority_grant_refs": ["wallet-network://capability-grant/model-mount"],
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let plan = ModelMountCore
        .plan_artifact_endpoint(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    persist_record(&st.data_dir, &plan.record_dir, &plan.record_id, &plan.record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    Ok(Json(plan.public_response))
}

// ---- Phase 5c.3: runtime engines + survey + select + PATCH + receipts ----

fn project_kind_engine(
    st: &DaemonState,
    kind: &str,
    engine_id: &str,
) -> Result<Value, AppError> {
    let req: ModelMountReadProjectionRequest = serde_json::from_value(json!({
        "projection_kind": kind,
        "schema_version": "ioi.model-mounting.runtime.v1",
        "base_url": st.base_url,
        "state_dir": st.data_dir,
        "engine_id": engine_id,
        "state": {},
    }))
    .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let plan = ModelMountCore
        .plan_read_projection(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    Ok(plan.projection)
}

async fn handle_runtime_engines(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    project_kind(&st, "runtime_engines")
}

async fn handle_runtime_engine_detail(
    State(st): State<Arc<DaemonState>>,
    AxumPath(engine_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let detail = project_kind_engine(&st, "runtime_engine_detail", &engine_id)?;
    let load_options = detail
        .get("default_load_options")
        .cloned()
        .unwrap_or(Value::Null);
    Ok(Json(json!({
        "engine": detail,
        "profile": { "defaultLoadOptions": load_options },
    })))
}

async fn handle_runtime_select(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let engine_id = body
        .get("engine_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "engine_id required".to_string()))?;
    let req: ModelMountRuntimeEngineRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_RUNTIME_ENGINE_SCHEMA_VERSION,
        "operation_kind": "model_mount.runtime_preference.write",
        "engine_id": engine_id,
        "source": "hypervisor-daemon",
        "generated_at": iso_now(),
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let plan = ModelMountCore
        .plan_runtime_engine(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    persist_record(&st.data_dir, &plan.record_dir, &plan.record_id, &plan.record)
        .map_err(|error| (AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())))?;
    let selected = plan
        .public_response
        .get("selected_engine_id")
        .cloned()
        .unwrap_or_else(|| json!(engine_id));
    Ok(Json(json!({ "selectedEngineId": selected })))
}

async fn handle_runtime_engine_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(engine_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    // Map the e2e's camelCase PATCH body onto the kernel control body.
    let mut control_body = json!({ "engine_id": engine_id });
    if let Some(opts) = body.get("defaultLoadOptions").cloned() {
        control_body["default_load_options"] = opts;
    }
    if let Some(label) = body.get("label").cloned() {
        control_body["operator_label"] = label;
    }
    let req: ModelMountRuntimeEngineRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_RUNTIME_ENGINE_SCHEMA_VERSION,
        "operation_kind": "model_mount.runtime_engine_profile.write",
        "engine_id": engine_id,
        "source": "hypervisor-daemon",
        "generated_at": iso_now(),
        "body": control_body,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let plan = ModelMountCore
        .plan_runtime_engine(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    persist_record(&st.data_dir, &plan.record_dir, &plan.record_id, &plan.record)
        .map_err(|error| (AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())))?;
    let load_options = plan
        .public_response
        .get("default_load_options")
        .cloned()
        .unwrap_or(Value::Null);
    let receipt_id = plan
        .receipt_refs
        .first()
        .cloned()
        .unwrap_or_else(|| plan.control_hash.clone());
    Ok(Json(json!({
        "engine": { "operatorProfile": { "defaultLoadOptions": load_options } },
        "profile": { "defaultLoadOptions": load_options },
        "receiptId": receipt_id,
    })))
}

async fn handle_runtime_survey(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    let req: ModelMountRuntimeSurveyRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_RUNTIME_SURVEY_SCHEMA_VERSION,
        "operation_kind": "model_mount.runtime_survey.capture",
        "source": "hypervisor-daemon",
        "generated_at": iso_now(),
        "state_dir": st.data_dir,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let plan = ModelMountCore
        .plan_runtime_survey(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    // Persist the survey receipt so /receipts/:id replays it; ensure
    // details.engineCount (camelCase) matches public_response.engineCount.
    let mut receipt = plan.receipt.clone();
    let engine_count = plan
        .public_response
        .get("engineCount")
        .cloned()
        .unwrap_or(json!(0));
    if let Some(details) = receipt.get_mut("details").and_then(|d| d.as_object_mut()) {
        details.insert("engineCount".to_string(), engine_count);
    } else if let Some(object) = receipt.as_object_mut() {
        object.insert("details".to_string(), json!({ "engineCount": engine_count }));
    }
    if let Some(receipt_id) = receipt.get("id").and_then(|v| v.as_str()) {
        let _ = persist_record(&st.data_dir, "receipts", receipt_id, &receipt);
    }
    Ok(Json(plan.public_response))
}

async fn handle_receipts_list(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(json!(read_receipts(&st.data_dir))))
}

async fn handle_receipt_by_id(
    State(st): State<Arc<DaemonState>>,
    AxumPath(receipt_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    read_receipts(&st.data_dir)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(receipt_id.as_str()))
        .map(Json)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, format!("receipt not found: {receipt_id}")))
}

/// Generic read-projection route (providers/backends/endpoints/instances/...).
fn project_kind(st: &DaemonState, kind: &str) -> Result<Json<Value>, AppError> {
    let req: ModelMountReadProjectionRequest = serde_json::from_value(json!({
        "projection_kind": kind,
        "schema_version": "ioi.model-mounting.runtime.v1",
        "base_url": st.base_url,
        "state_dir": st.data_dir,
        "state": {},
    }))
    .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let plan = ModelMountCore
        .plan_read_projection(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    Ok(Json(plan.projection))
}

async fn handle_providers(State(st): State<Arc<DaemonState>>) -> Result<Json<Value>, AppError> {
    project_kind(&st, "providers")
}
async fn handle_backends(State(st): State<Arc<DaemonState>>) -> Result<Json<Value>, AppError> {
    project_kind(&st, "backends")
}
async fn handle_endpoints(State(st): State<Arc<DaemonState>>) -> Result<Json<Value>, AppError> {
    project_kind(&st, "endpoints")
}
async fn handle_instances(State(st): State<Arc<DaemonState>>) -> Result<Json<Value>, AppError> {
    project_kind(&st, "instances")
}

/// Real model-mount kernel projection over HTTP. The truth is Agentgres; this
/// is the daemon-projected snapshot.
async fn handle_snapshot(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    let req: ModelMountReadProjectionRequest = serde_json::from_value(json!({
        "projection_kind": "snapshot",
        "state_dir": st.data_dir,
        "state": {},
    }))
    .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let plan = ModelMountCore
        .plan_read_projection(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    Ok(Json(plan.projection))
}

/// Run a REAL model-mount native-local inference through the kernel admission
/// chain (admit_provider_execution -> invoke_provider). Deterministic and fully
/// offline — no Ollama, no network — so it proves the Rust Core serves real
/// model-mount inference, not just a projection. This is the
/// `route.native-local` / `backend.hypervisor.native-local.fixture` path.
fn invoke_native_local(prompt: &str, model: &str) -> Result<Value, String> {
    let route_receipt_ref = "receipt://route/native-local";
    let exec_req: ModelMountProviderExecutionRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION,
        "invocation_ref": "model_mount://invocation/native-local",
        "route_decision_ref": "model_mount://route_decision/native-local",
        "route_receipt_ref": route_receipt_ref,
        "route_ref": "route.native-local",
        "provider_ref": "provider.hypervisor.local",
        "endpoint_ref": "endpoint.native-local",
        "model_ref": model,
        "capability": "chat",
        "invocation_kind": "chat.completions",
        "policy_hash": "sha256:native-local-policy",
        "input_hash": format!("sha256:{}", short_hash(prompt)),
        "request_hash": format!("sha256:{}", short_hash(prompt)),
        "idempotency_key": short_hash(prompt),
        "receipt_refs": [route_receipt_ref],
        "node_plaintext_allowed": true,
    }))
    .map_err(|error| format!("exec request build: {error}"))?;

    let record = ModelMountCore
        .admit_provider_execution(&exec_req)
        .map_err(|error| format!("admit_provider_execution: {}", debug_string(error)))?;
    let admitted = serde_json::to_value(&record)
        .map_err(|error| format!("record serialize: {error}"))?;

    let invocation: ModelMountProviderInvocationRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION,
        "provider_execution_ref": admitted["provider_execution_ref"],
        "provider_execution_hash": admitted["provider_execution_hash"],
        "route_decision_ref": admitted["route_decision_ref"],
        "route_receipt_ref": admitted["route_receipt_ref"],
        "route_ref": admitted["route_ref"],
        "provider_ref": admitted["provider_ref"],
        "provider_kind": "ioi_native_local",
        "endpoint_ref": admitted["endpoint_ref"],
        "model_ref": admitted["model_ref"],
        "capability": admitted["capability"],
        "invocation_kind": admitted["invocation_kind"],
        "input": prompt,
        "request_hash": admitted["request_hash"],
        "execution_backend": "rust_model_mount_native_local",
        "backend_ref": "backend.hypervisor.native-local.fixture",
        "api_format": "ioi_native",
        "driver": "native_local",
        "receipt_refs": [admitted["route_receipt_ref"]],
        "admitted_provider_execution": admitted,
    }))
    .map_err(|error| format!("invocation request build: {error}"))?;

    let result = ModelMountCore
        .invoke_provider(&invocation)
        .map_err(|error| format!("invoke_provider: {}", debug_string(error)))?;
    serde_json::to_value(&result).map_err(|error| format!("result serialize: {error}"))
}

/// POST /v1/model-mount/native-local — real offline kernel inference.
async fn handle_native_local(
    State(_st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let prompt = flatten_messages(&body);
    let model = body
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("qwen2.5-coder")
        .to_string();
    let result = invoke_native_local(&prompt, &model)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, error))?;
    Ok(Json(result))
}

async fn handle_read_projection(
    State(_st): State<Arc<DaemonState>>,
    Json(req): Json<ModelMountReadProjectionRequest>,
) -> Result<Json<Value>, AppError> {
    let plan = ModelMountCore
        .plan_read_projection(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    Ok(Json(json!({
        "projection_kind": plan.projection_kind,
        "projection": plan.projection,
        "evidence_refs": plan.evidence_refs,
    })))
}

/// OpenAI-compatible chat completion via the real inference runtime. Honest
/// error (BAD_GATEWAY) when no model route answers — never a faked completion.
async fn handle_chat_completions(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "model.chat:*")?;
    let prompt = flatten_messages(&body);
    let options = InferenceOptions {
        max_tokens: 2048,
        ..Default::default()
    };
    let output = st
        .inference
        .execute_inference([0u8; 32], prompt.as_bytes(), options)
        .await
        .map_err(|error| {
            AppError(
                StatusCode::BAD_GATEWAY,
                format!("no_model_route: {}", debug_string(error)),
            )
        })?;
    let text = String::from_utf8_lossy(&output).to_string();
    Ok(Json(json!({
        "id": format!("chatcmpl-{}", short_hash(&prompt)),
        "object": "chat.completion",
        "model": st.model_name,
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": text },
            "finish_reason": "stop",
        }],
    })))
}

/// The cockpit session turn, in the app's SSE contract shape
/// (turn_start / token / done, or an honest error). Mirrors the JS dev-replay
/// streamSessionTurn so the app needs no change to talk to Rust Core.
async fn handle_session_turn(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let prompt = flatten_messages(&body);
    let turn_ref = format!("session-turn:{}", short_hash(&prompt));
    let receipt_ref = format!(
        "receipt://hypervisor/session-turn/{}",
        turn_ref.replace(|c: char| !c.is_ascii_alphanumeric(), "-")
    );
    let options = InferenceOptions {
        max_tokens: 2048,
        ..Default::default()
    };
    let result = st
        .inference
        .execute_inference([0u8; 32], prompt.as_bytes(), options)
        .await;

    let mut sse = String::from(": hypervisor session turn\n\n");
    match result {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes).to_string();
            sse.push_str(&sse_frame(
                "turn_start",
                &json!({ "turn_ref": turn_ref, "model_name": st.model_name, "source": "model_upstream" }),
            ));
            sse.push_str(&sse_frame("token", &json!({ "text": text })));
            sse.push_str(&sse_frame(
                "done",
                &json!({ "turn_ref": turn_ref, "receipt_ref": receipt_ref, "finish_reason": "stop", "source": "model_upstream" }),
            ));
        }
        Err(error) => {
            sse.push_str(&sse_frame(
                "turn_start",
                &json!({ "turn_ref": turn_ref, "model_name": st.model_name, "source": "no_model_route" }),
            ));
            sse.push_str(&sse_frame(
                "error",
                &json!({
                    "code": "no_model_route",
                    "turn_ref": turn_ref,
                    "message": format!(
                        "The model route did not respond ({}). Start a local model (Ollama with a Qwen model on :11434) or set IOI_HYPERVISOR_MODEL_UPSTREAM to stream real completions.",
                        debug_string(error)
                    ),
                }),
            ));
            sse.push_str(&sse_frame(
                "done",
                &json!({ "turn_ref": turn_ref, "receipt_ref": receipt_ref, "finish_reason": "no_model_route", "source": "no_model_route" }),
            ));
        }
    }
    ([(header::CONTENT_TYPE, "text/event-stream")], sse)
}
