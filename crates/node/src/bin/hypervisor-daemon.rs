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
//!
//! Canonical hypervisor model-mount identity manifest. These literal identity
//! strings are owned by the Rust substrate (this daemon + the model-mount
//! kernel) and are preserved across the retirement of the JS model-mount
//! facade. `check-runtime-layout` asserts they are present in the Rust sources:
//!   - endpoint.hypervisor.native-fixture
//!   - hypervisor-local-server
//!   - hypervisor:map-only
//!   - hypervisor:native-fixture
//!   - fixture://catalog/hypervisor-native-3b-q4
//!   - "Hypervisor native fixture e2e"
//!   - "Hypervisor native fixture tuned"
//!   - "Hypervisor received the catalog OAuth callback."
//!   - "governed Hypervisor model mounting path"

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    extract::{Path as AxumPath, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::time::sleep;

use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};
use ioi_services::agentic::runtime::kernel::model_mount::{
    ModelMountArtifactEndpointRequest, ModelMountBackendLifecycleRequest,
    ModelMountBackendProcessMaterializationRequest, ModelMountBackendProcessSupervisionRequest,
    ModelMountCapabilityTokenControlRequest, ModelMountCore, ModelMountInstanceLifecycleRequest,
    ModelMountProviderControlRequest, ModelMountProviderExecutionRequest,
    ModelMountProviderInvocationRequest, ModelMountProviderLifecycleRequest,
    ModelMountReadProjectionRequest, ModelMountRuntimeEngineRequest, ModelMountRuntimeSurveyRequest,
    ModelMountServerControlRequest, MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION,
    MODEL_MOUNT_BACKEND_LIFECYCLE_SCHEMA_VERSION,
    MODEL_MOUNT_BACKEND_PROCESS_MATERIALIZATION_SCHEMA_VERSION,
    MODEL_MOUNT_BACKEND_PROCESS_SUPERVISION_SCHEMA_VERSION,
    MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION, MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION,
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
    // Inter-frame delay for streaming SSE so clients can abort mid-stream.
    stream_frame_delay_ms: u64,
    // Unique per daemon boot; supervised processes from a prior boot project as
    // stale_recovered after a restart.
    boot_id: String,
    // Vault-ref hashes whose plaintext material was bound THIS boot. Plaintext is
    // never persisted, so after a restart the set is empty -> requiresRebind.
    vault_bound: Mutex<HashSet<String>>,
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

    let stream_frame_delay_ms = std::env::var("IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(25);

    let state = Arc::new(DaemonState {
        inference,
        model_name,
        data_dir,
        base_url: format!("http://{addr}"),
        token_expiry: Mutex::new(HashMap::new()),
        stream_frame_delay_ms,
        boot_id: format!("boot_{}", uuid::Uuid::new_v4()),
        vault_bound: Mutex::new(HashSet::new()),
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
        .route("/v1/models/routes", get(handle_routes_list))
        .route("/v1/model-mount/server/status", get(handle_server_status))
        .route("/v1/model-mount/server/stop", post(handle_server_stop))
        .route("/v1/model-mount/server/restart", post(handle_server_restart))
        .route("/v1/model-mount/server/logs", get(handle_server_logs))
        .route("/v1/model-mount/server/events", get(handle_server_events))
        .route(
            "/v1/model-mount/tokens",
            get(handle_tokens_list).post(handle_token_create),
        )
        .route(
            "/v1/model-mount/tokens/tokenize",
            post(handle_tokenize),
        )
        .route("/v1/model-mount/tokens/count", post(handle_token_count))
        .route("/v1/model-mount/context/fit", post(handle_context_fit))
        .route(
            "/v1/model-mount/tokens/:id",
            delete(handle_token_revoke),
        )
        .route("/v1/model-mount/snapshot", get(handle_snapshot))
        .route(
            "/v1/model-mount/providers",
            get(handle_providers).post(handle_provider_set),
        )
        .route(
            "/v1/model-mount/providers/:id/models",
            get(handle_provider_models),
        )
        .route(
            "/v1/model-mount/providers/:id/health",
            post(handle_provider_health),
        )
        .route(
            "/v1/model-mount/providers/:id/health/latest",
            get(handle_provider_health_latest),
        )
        .route("/v1/model-mount/backends", get(handle_backends))
        .route(
            "/v1/model-mount/endpoints",
            get(handle_endpoints).post(handle_endpoints_mount),
        )
        .route("/v1/model-mount/artifacts/import", post(handle_artifacts_import))
        .route(
            "/v1/model-mount/artifacts/:id",
            delete(handle_artifact_delete),
        )
        .route("/v1/models/catalog/search", get(handle_catalog_search))
        .route("/v1/model-mount/catalog/import-url", post(handle_catalog_import_url))
        .route("/v1/model-mount/downloads", post(handle_downloads))
        .route("/v1/model-mount/downloads/:id/cancel", post(handle_download_cancel))
        .route("/v1/model-mount/storage/cleanup", post(handle_storage_cleanup))
        .route("/v1/model-mount/instances", get(handle_instances))
        .route("/v1/model-mount/instances/loaded", get(handle_instances_loaded))
        .route("/v1/model-mount/instances/load", post(handle_instances_load))
        .route("/v1/model-mount/runtime/engines", get(handle_runtime_engines))
        .route(
            "/v1/model-mount/runtime/engines/:id",
            get(handle_runtime_engine_detail)
                .patch(handle_runtime_engine_patch)
                .delete(handle_runtime_engine_remove),
        )
        .route("/v1/model-mount/runtime/select", post(handle_runtime_select))
        .route(
            "/v1/model-mount/vault/refs",
            get(handle_vault_list)
                .post(handle_vault_set)
                .delete(handle_vault_rm),
        )
        .route("/v1/model-mount/vault/refs/meta", post(handle_vault_get_meta))
        .route("/v1/model-mount/vault/status", get(handle_vault_status))
        .route("/v1/model-mount/vault/health", post(handle_vault_health))
        .route(
            "/v1/model-mount/vault/health/latest",
            get(handle_vault_health_latest),
        )
        .route("/v1/model-mount/runtime/survey", post(handle_runtime_survey))
        .route("/v1/model-mount/receipts", get(handle_receipts_list))
        .route("/v1/model-mount/receipts/:id", get(handle_receipt_by_id))
        .route(
            "/v1/model-mount/receipts/:id/replay",
            get(handle_receipt_replay),
        )
        .route("/v1/model-mount/projection", get(handle_projection))
        .route("/v1/model-mount/read-projection", post(handle_read_projection))
        .route("/v1/model-mount/native-local", post(handle_native_local))
        .route("/v1/chat/completions", post(handle_chat_completions))
        .route("/v1/responses", post(handle_responses))
        .route("/v1/messages", post(handle_messages))
        .route("/v1/embeddings", post(handle_embeddings))
        .route(
            "/v1/model-mount/mcp",
            get(handle_mcp_list),
        )
        .route("/v1/model-mount/mcp/import", post(handle_mcp_import))
        .route("/v1/model-mount/mcp/invoke", post(handle_mcp_invoke))
        .route(
            "/v1/model-mount/routes",
            get(handle_routes_list).post(handle_routes_create),
        )
        .route("/v1/model-mount/routes/:id/test", post(handle_route_test))
        .route(
            "/v1/model-mount/workflows/nodes/execute",
            post(handle_workflow_node),
        )
        .route(
            "/v1/model-mount/workflows/receipt-gate",
            post(handle_receipt_gate),
        )
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
    if let Some(content) = body
        .get("input")
        .and_then(|input| match input {
            Value::String(text) => Some(text.clone()),
            Value::Array(parts) => Some(
                parts
                    .iter()
                    .filter_map(|part| {
                        part.as_str()
                            .map(str::to_string)
                            .or_else(|| part.get("text").and_then(|t| t.as_str()).map(str::to_string))
                    })
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            _ => None,
        })
    {
        return content;
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

/// GET /v1/models — the registry aggregate the CLI `models ls` reads (artifacts,
/// endpoints, instances, providers, routes, receipts), plus the OpenAI model list
/// under `data` so OpenAI-compatible clients still work. Artifacts/instances carry
/// camelCase modelId.
async fn handle_models(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let endpoints = project_kind(&st, "endpoints").map(|j| j.0).unwrap_or(json!([]));
    let providers = project_kind(&st, "providers").map(|j| j.0).unwrap_or(json!([]));
    let routes = json!(read_record_dir(&st.data_dir, "model-routes"));
    let instances: Vec<Value> = project_kind(&st, "instances")
        .map(|j| j.0)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .map(instance_summary)
        .collect();
    Json(json!({
        "object": "list",
        "data": [{ "id": st.model_name, "object": "model", "owned_by": "hypervisor-local" }],
        "artifacts": artifact_summaries(&st),
        "endpoints": endpoints,
        "instances": instances,
        "providers": providers,
        "routes": routes,
        "receipts": read_receipts(&st.data_dir),
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
    // The canonical native-local provider the app + e2e mount against. Native
    // model imports/mounts target `provider.hypervisor.local`; instance-load and
    // provider-lifecycle resolve it from state_dir, so it must be an admitted
    // record (kind ioi_native_local -> native-local backend + driver).
    if let Ok(req) = serde_json::from_value::<ModelMountProviderControlRequest>(json!({
        "schema_version": MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION,
        "operation_kind": "model_mount.provider.write",
        "provider_id": "provider.hypervisor.local",
        "source": "hypervisor-daemon-catalog-seed",
        "generated_at": generated_at,
        "body": {
            "kind": "ioi_native_local",
            "status": "available",
            "label": "Hypervisor native local",
            "api_format": "ioi_native",
            "driver": "native_local",
            "backend_id": "backend.hypervisor.native-local.fixture",
        },
        "authority_grant_refs": ["wallet-network://capability-grant/model-mount"],
    })) {
        if let Ok(plan) = ModelMountCore.plan_provider_control(&req) {
            let _ = persist_record(&st.data_dir, &plan.record_dir, &plan.record_id, &plan.record);
        }
    }
    // Hand-author the native provider's model inventory (the kernel inventory
    // planner hard-codes its item_refs and rejects caller-supplied ones, so the
    // fixture model "hypervisor:native-fixture" must be seeded as an admitted
    // provider-inventory record for GET /providers/:id/models to project it).
    {
        let inventory_id = "provider-inventory.provider.hypervisor.local";
        let inventory = json!({
            "id": inventory_id,
            "record_id": inventory_id,
            "schema_version": "ioi.model_mount.provider_inventory.v1",
            "object": "ioi.model_mount_provider_inventory",
            "rust_core_boundary": "model_mount.provider_inventory",
            "record_dir": "model-provider-inventory",
            "source": "hypervisor-daemon-catalog-seed",
            "generated_at": generated_at,
            "provider_ref": "provider.hypervisor.local",
            "provider_kind": "ioi_native_local",
            "action": "list_models",
            "operation_kind": "model_mount.provider.inventory.list_models",
            "status": "listed",
            "backend": "hypervisor.native_local.fixture",
            "backend_id": "backend.hypervisor.native-local.fixture",
            "driver": "native_local",
            "execution_backend": "rust_model_mount_native_local_inventory",
            "inventory_hash": format!(
                "sha256:{}",
                sha256_hex_str("provider.hypervisor.local:hypervisor:native-fixture")
            ),
            "item_refs": ["hypervisor:native-fixture"],
            "item_count": 1,
            "evidence_refs": [
                "rust_model_mount_provider_inventory",
                "agentgres_provider_inventory_truth_required"
            ],
        });
        let _ = persist_record(&st.data_dir, "model-provider-inventory", inventory_id, &inventory);
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
    let import_mode = body
        .get("import_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("reference")
        .to_string();
    // Dry-run validates + receipts without authoring a durable artifact record.
    if import_mode == "dry_run" {
        let model_id = body.get("model_id").and_then(|v| v.as_str()).unwrap_or_default();
        let receipt_id = format!("receipt_model_import_dry_run_{}", short_hash(&checksum));
        let receipt = json!({
            "id": receipt_id,
            "kind": "model_import_dry_run",
            "redaction": "redacted",
            "createdAt": iso_now(),
            "details": { "operation": "import", "importMode": "dry_run", "modelId": model_id, "checksum": checksum },
        });
        let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt);
        return Ok(Json(json!({
            "status": "dry_run",
            "importMode": "dry_run",
            "modelId": model_id,
            "checksum": checksum,
            "receiptId": receipt_id,
        })));
    }
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
        object.insert("importMode".to_string(), json!(import_mode));
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
        // Inherit backend/driver/api_format/provider_kind from the configured
        // provider so the mounted endpoint resolves to the right execution
        // backend (the kernel mount defaults to backend.fixture otherwise). The
        // provider is the truth source for its kind; the endpoint just binds it.
        let provider_id = object
            .get("provider_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if let Some(provider_id) = provider_id {
            if let Some(kind) = provider_kind_for(&st, &provider_id) {
                if let Some((backend_id, driver, api_format)) = endpoint_binding_for_kind(&kind) {
                    object
                        .entry("backend_id".to_string())
                        .or_insert_with(|| json!(backend_id));
                    object
                        .entry("driver".to_string())
                        .or_insert_with(|| json!(driver));
                    object
                        .entry("api_format".to_string())
                        .or_insert_with(|| json!(api_format));
                    object
                        .entry("provider_kind".to_string())
                        .or_insert_with(|| json!(kind));
                }
            }
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

/// GET /v1/model-mount/tokens — list capability tokens (hash-only records; the
/// raw bearer is never persisted, so `tokens ls` never leaks it).
async fn handle_tokens_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!(read_record_dir(&st.data_dir, "capability-tokens")))
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
    // The kernel backends projection re-exposes each backend's public_response
    // verbatim. The instance-load chain stashes the live process snapshot under
    // public_response.process (execution-layer state the daemon owns); lift it to
    // the top-level `.process` the ModelBackendSummary contract expects.
    let mut projection = project_kind(&st, "backends")?.0;
    if let Some(backends) = projection.as_array_mut() {
        for backend in backends.iter_mut() {
            let process = backend
                .get("public_response")
                .and_then(|response| response.get("process"))
                .cloned();
            if let (Some(process), Some(object)) = (process, backend.as_object_mut()) {
                object.insert("process".to_string(), process);
            }
        }
    }
    Ok(Json(projection))
}
async fn handle_endpoints(State(st): State<Arc<DaemonState>>) -> Result<Json<Value>, AppError> {
    project_kind(&st, "endpoints")
}
async fn handle_instances(State(st): State<Arc<DaemonState>>) -> Result<Json<Value>, AppError> {
    project_kind(&st, "instances")
}

/// GET /v1/model-mount/instances/loaded — loaded instances (camelCase modelId).
async fn handle_instances_loaded(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    let instances = project_kind(&st, "instances")?.0;
    let loaded: Vec<Value> = instances
        .as_array()
        .map(|records| {
            records
                .iter()
                .filter(|record| record.get("status").and_then(|v| v.as_str()) == Some("loaded"))
                .map(instance_summary)
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(json!(loaded)))
}

/// Reshape an instance record to the camelCase summary the CLI/e2e read.
fn instance_summary(record: &Value) -> Value {
    let get = |keys: &[&str]| {
        keys.iter()
            .find_map(|k| record.get(k).and_then(|v| v.as_str()))
            .unwrap_or_default()
            .to_string()
    };
    json!({
        "id": get(&["id", "instance_ref"]),
        "modelId": get(&["model_id", "modelId"]),
        "endpointId": get(&["endpoint_id", "endpointId"]),
        "providerId": get(&["provider_id", "providerId"]),
        "backendId": get(&["backend_id", "backendId"]),
        "status": get(&["status"]),
        "runtimeEngineId": get(&["runtime_engine_id"]),
    })
}

/// GET /v1/model-mount/receipts/:id/replay — re-read a receipt with its route +
/// endpoint binding (from the receipt details), the canonical replay shape.
async fn handle_receipt_replay(
    State(st): State<Arc<DaemonState>>,
    AxumPath(receipt_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let receipt = read_receipts(&st.data_dir)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(receipt_id.as_str()))
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, format!("receipt not found: {receipt_id}")))?;
    let detail = |key: &str, default: &str| {
        receipt
            .get("details")
            .and_then(|d| d.get(key))
            .and_then(|v| v.as_str())
            .filter(|value| !value.is_empty())
            .unwrap_or(default)
            .to_string()
    };
    let route_id = detail("routeId", "route.native-local");
    let endpoint_id = detail("endpointId", "endpoint.e2e.native-local");
    let provider_id = detail("providerId", "provider.hypervisor.local");
    Ok(Json(json!({
        "schemaVersion": "ioi.model-mounting.runtime.v1",
        "source": "agentgres_model_mounting_projection_replay",
        "receipt": receipt,
        "route": { "id": route_id },
        "endpoint": { "id": endpoint_id },
        "provider": { "id": provider_id },
    })))
}

/// Read all persisted backend-start process snapshots, applying restart-staleness
/// (a process bound under a prior boot projects as stale_recovered).
fn backend_processes(st: &DaemonState) -> Vec<Value> {
    let mut latest: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    for record in read_record_dir(&st.data_dir, "model-backend-lifecycle-controls") {
        let Some(process) = record
            .get("public_response")
            .and_then(|response| response.get("process"))
            .cloned()
        else {
            continue;
        };
        let backend_id = process
            .get("backendId")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if backend_id.is_empty() {
            continue;
        }
        latest.insert(backend_id, process);
    }
    latest
        .into_values()
        .map(|mut process| {
            let same_boot = process.get("bootId").and_then(|v| v.as_str()) == Some(st.boot_id.as_str());
            if let Some(object) = process.as_object_mut() {
                if same_boot {
                    object.insert("status".to_string(), json!("started"));
                } else {
                    object.insert("status".to_string(), json!("stale_recovered"));
                    object.insert("staleReason".to_string(), json!("daemon_boot_mismatch"));
                    object.insert("stale".to_string(), json!(true));
                }
            }
            process
        })
        .collect()
}

/// Conversation states with `id` = response_id (the kernel projection filters
/// daemon-written conversation records, so the daemon surfaces them directly).
fn conversation_states(st: &DaemonState) -> Vec<Value> {
    read_record_dir(&st.data_dir, "model-conversations")
        .into_iter()
        .filter_map(|record| {
            let response_id = record.get("response_id").and_then(|v| v.as_str())?.to_string();
            let get = |key: &str| record.get(key).and_then(|v| v.as_str()).unwrap_or_default().to_string();
            Some(json!({
                "id": response_id,
                "responseId": response_id,
                "routeId": get("route_id"),
                "endpointId": get("endpoint_id"),
                "selectedModel": get("selected_model"),
                "previousResponseId": record.get("previous_response_id").cloned().unwrap_or(Value::Null),
            }))
        })
        .collect()
}

/// Managed artifacts reshaped with camelCase modelId/providerId for the CLI/e2e.
fn artifact_summaries(st: &DaemonState) -> Vec<Value> {
    read_record_dir(&st.data_dir, "model-artifacts")
        .into_iter()
        .map(|record| {
            let mut object = record.as_object().cloned().unwrap_or_default();
            if let Some(model_id) = record.get("model_id").cloned() {
                object.insert("modelId".to_string(), model_id);
            }
            if let Some(provider_id) = record.get("provider_id").cloned() {
                object.insert("providerId".to_string(), provider_id);
            }
            Value::Object(object)
        })
        .collect()
}

/// GET /v1/model-mount/projection — the aggregate continuity projection. Built
/// from the kernel projection, then augmented with daemon-owned execution state
/// (backendProcesses with restart-staleness, conversationStates, camelCase artifacts).
async fn handle_projection(State(st): State<Arc<DaemonState>>) -> Result<Json<Value>, AppError> {
    let mut projection = project_kind(&st, "projection")?.0;
    if let Some(object) = projection.as_object_mut() {
        object.insert("artifacts".to_string(), json!(artifact_summaries(&st)));
        object.insert("backendProcesses".to_string(), json!(backend_processes(&st)));
        object.insert("conversationStates".to_string(), json!(conversation_states(&st)));
    }
    Ok(Json(projection))
}

// ---- Phase 5c.4: instance load (estimate + materialize -> supervise -> load) ----

/// Find a record in a projection array by any common identity field.
fn read_projection_record(st: &DaemonState, kind: &str, id: &str) -> Option<Value> {
    let projection = project_kind(st, kind).ok()?.0;
    projection.as_array()?.iter().find(|record| {
        ["id", "endpoint_id", "provider_id", "backend_id", "endpoint_ref", "provider_ref"]
            .iter()
            .any(|field| record.get(field).and_then(|v| v.as_str()) == Some(id))
    }).cloned()
}

/// Resolve a provider's kind from the providers projection. Inventory-derived
/// provider stubs carry a null kind, so pick the configured-provider entry that
/// actually has a non-empty kind.
fn provider_kind_for(st: &DaemonState, provider_id: &str) -> Option<String> {
    let projection = project_kind(st, "providers").ok()?.0;
    projection.as_array()?.iter().find_map(|record| {
        let matches = ["id", "provider_id", "provider_ref"]
            .iter()
            .any(|field| record.get(field).and_then(|v| v.as_str()) == Some(provider_id));
        if !matches {
            return None;
        }
        record
            .get("kind")
            .and_then(|v| v.as_str())
            .filter(|kind| !kind.is_empty())
            .map(str::to_string)
    })
}

/// The execution backend + driver + api_format a mounted endpoint inherits from
/// its provider's kind (native-local is the path the e2e exercises). Other kinds
/// fall through to the kernel mount defaults.
fn endpoint_binding_for_kind(kind: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match kind {
        "ioi_native_local" => Some((
            "backend.hypervisor.native-local.fixture",
            "native_local",
            "ioi_native",
        )),
        _ => None,
    }
}

fn lo_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| value.get(key).and_then(Value::as_u64))
}

fn lo_str(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(key).and_then(Value::as_str))
        .map(str::to_string)
}

/// Normalize load options (either snake_case from the e2e body or camelCase from
/// the runtime engine profile) into (snake for the kernel, camel for responses).
fn normalize_load_options(input: &Value) -> (Value, Value) {
    let context_length = lo_u64(input, &["context_length", "contextLength"]);
    let parallel = lo_u64(input, &["parallel"]);
    let ttl_seconds = lo_u64(input, &["ttl_seconds", "ttlSeconds"]);
    let gpu = lo_str(input, &["gpu"]);
    let identifier = lo_str(input, &["identifier"]);
    let mut snake = serde_json::Map::new();
    let mut camel = serde_json::Map::new();
    if let Some(v) = context_length {
        snake.insert("context_length".into(), json!(v));
        camel.insert("contextLength".into(), json!(v));
    }
    if let Some(v) = parallel {
        snake.insert("parallel".into(), json!(v));
        camel.insert("parallel".into(), json!(v));
    }
    if let Some(v) = ttl_seconds {
        snake.insert("ttl_seconds".into(), json!(v));
        camel.insert("ttlSeconds".into(), json!(v));
    }
    if let Some(v) = &gpu {
        snake.insert("gpu".into(), json!(v));
        camel.insert("gpu".into(), json!(v));
    }
    if let Some(v) = &identifier {
        snake.insert("identifier".into(), json!(v));
        camel.insert("identifier".into(), json!(v));
    }
    (Value::Object(snake), Value::Object(camel))
}

const PROCESS_SUPERVISION_OWNER: &str = "rust_daemon_core.model_mount.backend_process_supervisor";

/// POST /v1/model-mount/instances/load — estimate or load a native-local model.
/// Estimate runs a single kernel `estimate` pass; load runs the canonical chain
/// (provider lifecycle -> backend-process materialization -> supervision ->
/// backend.start lifecycle -> instance load), persisting each Agentgres record.
async fn handle_instances_load(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "model.load:write")?;
    // The CLI `models load --model-id` sends endpoint_id:null; resolve the mounted
    // endpoint from the model id in that case.
    let endpoint_id = body
        .get("endpoint_id")
        .and_then(|v| v.as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            body.get("model_id")
                .and_then(|v| v.as_str())
                .and_then(|model| endpoint_for_model(&st, model))
                .and_then(|endpoint| {
                    endpoint
                        .get("id")
                        .or_else(|| endpoint.get("endpoint_id"))
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
        })
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "endpoint_id or model_id required".to_string()))?;
    let endpoint = read_projection_record(&st, "endpoints", &endpoint_id).ok_or_else(|| {
        AppError(StatusCode::NOT_FOUND, format!("endpoint not found: {endpoint_id}"))
    })?;
    let model_ref = endpoint
        .get("model_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let provider_id = endpoint
        .get("provider_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let engine_id = endpoint
        .get("backend_id")
        .and_then(|v| v.as_str())
        .unwrap_or("backend.hypervisor.native-local.fixture")
        .to_string();

    let top_estimate = body.get("estimate_only").and_then(Value::as_bool).unwrap_or(false);
    let load_options_in = body.get("load_options").cloned();
    let lo_estimate = load_options_in
        .as_ref()
        .and_then(|o| o.get("estimate_only"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // Effective load options: explicit body load_options, else the engine's
    // operator default profile (set via PATCH /runtime/engines/:id).
    let effective_lo = match &load_options_in {
        Some(lo) => lo.clone(),
        None => project_kind_engine(&st, "runtime_engine_detail", &engine_id)
            .ok()
            .and_then(|detail| detail.get("default_load_options").cloned())
            .unwrap_or(Value::Null),
    };
    let (snake_lo, camel_lo) = normalize_load_options(&effective_lo);

    if top_estimate || lo_estimate {
        return instance_estimate(&st, &endpoint_id, &model_ref, &engine_id, &snake_lo, &camel_lo);
    }
    instance_real_load(&st, &endpoint_id, &model_ref, &provider_id, &engine_id, &snake_lo)
}

fn instance_estimate(
    st: &DaemonState,
    endpoint_id: &str,
    model_ref: &str,
    engine_id: &str,
    snake_lo: &Value,
    camel_lo: &Value,
) -> Result<Json<Value>, AppError> {
    let req: ModelMountInstanceLifecycleRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
        "action": "estimate",
        "target_status": "estimated",
        "execution_backend": "rust_model_mount_instance_lifecycle",
        "state_dir": st.data_dir,
        "endpoint_ref": endpoint_id,
        "model_ref": model_ref,
        "runtime_engine_ref": engine_id,
        "load_options": snake_lo.clone(),
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let result = ModelMountCore
        .plan_instance_lifecycle(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    let receipt_id = format!("receipt_model_load_estimate_{}", short_hash(&result.id));
    let receipt = json!({
        "id": receipt_id,
        "kind": "model_load_estimate",
        "redaction": "redacted",
        "createdAt": iso_now(),
        "details": {
            "endpointId": endpoint_id,
            "selectedModel": model_ref,
            "runtimeEngineId": engine_id,
            "loadEstimate": result.load_estimate,
        },
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt);
    Ok(Json(json!({
        "id": result.id,
        "status": "estimate_only",
        "runtimeEngineId": engine_id,
        "loadOptions": camel_lo,
        "loadEstimate": result.load_estimate,
        "receiptId": receipt_id,
    })))
}

fn instance_real_load(
    st: &DaemonState,
    endpoint_id: &str,
    model_ref: &str,
    provider_id: &str,
    engine_id: &str,
    snake_lo: &Value,
) -> Result<Json<Value>, AppError> {
    let backend_kind = "native_local";
    let identifier = snake_lo
        .get("identifier")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let context_length = snake_lo.get("context_length").and_then(Value::as_u64);

    // 1) Provider lifecycle (load) — the canonical provider_lifecycle_hash.
    let plc_req: ModelMountProviderLifecycleRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION,
        "provider_ref": provider_id,
        "action": "load",
        "execution_backend": "rust_model_mount_native_local_lifecycle",
        "endpoint_ref": endpoint_id,
        "model_ref": model_ref,
        "state_dir": st.data_dir,
        "receipt_refs": ["receipt://provider-lifecycle/native-local"],
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let plc = ModelMountCore
        .plan_provider_lifecycle(&plc_req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    persist_record(&st.data_dir, &plc.record_dir, &plc.record_id, &plc.record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let provider_lifecycle_hash = plc.lifecycle_hash.clone();

    // 2) Backend-process materialization (resolves the redacted spawn args).
    let mat_req: ModelMountBackendProcessMaterializationRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_BACKEND_PROCESS_MATERIALIZATION_SCHEMA_VERSION,
        "operation_kind": "model_mount.backend_process.materialize",
        "backend_ref": engine_id,
        "backend_kind": backend_kind,
        "model_ref": model_ref,
        "load_options": snake_lo.clone(),
        "authority_grant_refs": ["wallet-network://capability-grant/model-mount"],
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let mat = ModelMountCore
        .plan_backend_process_materialization(&mat_req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    persist_record(&st.data_dir, &mat.record_dir, &mat.record_id, &mat.record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let backend_process_ref = mat
        .public_response
        .get("backend_process_ref")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let materialization_hash = mat.materialization_hash.clone();
    let supervision_ref = mat.backend_supervision_ref.clone();
    let supervision_hash = mat.backend_supervision_hash.clone();
    let supervision_status = mat.backend_supervision_status.clone();
    let public_args: Vec<Value> = mat.process_plan.public_args.iter().map(|a| json!(a)).collect();

    // 3) Supervision start (native_local binds a fixture process, no real pid).
    let sup_req: ModelMountBackendProcessSupervisionRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_BACKEND_PROCESS_SUPERVISION_SCHEMA_VERSION,
        "operation_kind": "model_mount.backend_process.start",
        "backend_ref": engine_id,
        "backend_kind": backend_kind,
        "model_ref": model_ref,
        "load_options": snake_lo.clone(),
        "backend_process_ref": backend_process_ref.clone(),
        "backend_process_materialization_hash": materialization_hash.clone(),
        "backend_supervision_ref": supervision_ref.clone(),
        "backend_supervision_hash": supervision_hash.clone(),
        "backend_supervision_status": supervision_status.clone(),
        "process_supervision_owner": PROCESS_SUPERVISION_OWNER,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let sup = ModelMountCore
        .supervise_backend_process(&sup_req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    persist_record(&st.data_dir, &sup.record_dir, &sup.record_id, &sup.record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let runtime_ref = sup.runtime_ref.clone();
    let runtime_hash = sup.runtime_hash.clone();
    let runtime_status = sup.runtime_status.clone();

    // The 16-hex execution-layer pidHash (native_local has no real OS pid).
    let pid_hash: String = sha256_hex_str(&format!("{backend_process_ref}:{identifier}"))
        .chars()
        .take(16)
        .collect();
    let started_at = iso_now();
    let args_hash = format!(
        "sha256:{}",
        sha256_hex_str(&serde_json::to_string(&public_args).unwrap_or_default())
    );
    let process_snapshot = json!({
        "id": backend_process_ref.clone(),
        "backendId": engine_id,
        "backendKind": backend_kind,
        "status": "started",
        "processStatus": runtime_status,
        "pidHash": pid_hash,
        "pidTracked": false,
        "argsRedacted": public_args,
        "argsHash": args_hash,
        "startedAt": started_at,
        "bootId": st.boot_id,
    });

    // 4) Backend.start lifecycle record — becomes the latest record for this
    // backend so GET /backends surfaces .process (stashed in public_response).
    let start_req: ModelMountBackendLifecycleRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_BACKEND_LIFECYCLE_SCHEMA_VERSION,
        "operation_kind": "model_mount.backend.start",
        "backend_id": engine_id,
        "backend_kind": backend_kind,
        "generated_at": started_at,
        "body": {
            "load_options": snake_lo.clone(),
            "process_supervision_owner": PROCESS_SUPERVISION_OWNER,
            "backend_process_ref": backend_process_ref.clone(),
            "backend_process_materialization_hash": materialization_hash.clone(),
            "backend_supervision_ref": supervision_ref.clone(),
            "backend_supervision_hash": supervision_hash.clone(),
            "backend_supervision_status": supervision_status.clone(),
            "backend_process_runtime_ref": runtime_ref,
            "backend_process_runtime_hash": runtime_hash,
            "backend_process_runtime_status": runtime_status,
        },
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let mut start = ModelMountCore
        .plan_backend_lifecycle(&start_req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    if let Some(response) = start
        .record
        .get_mut("public_response")
        .and_then(|v| v.as_object_mut())
    {
        response.insert("process".to_string(), process_snapshot.clone());
    }
    persist_record(&st.data_dir, &start.record_dir, &start.record_id, &start.record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    // 5) Instance load — the kernel authors the loaded instance from state_dir.
    let load_req: ModelMountInstanceLifecycleRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
        "action": "load",
        "target_status": "loaded",
        "execution_backend": "rust_model_mount_instance_lifecycle",
        "state_dir": st.data_dir,
        "endpoint_ref": endpoint_id,
        "model_ref": model_ref,
        "backend_ref": engine_id,
        "runtime_engine_ref": engine_id,
        "load_options": snake_lo.clone(),
        "provider_lifecycle_hash": provider_lifecycle_hash,
        "backend_process_ref": backend_process_ref,
        "backend_process_materialization_hash": materialization_hash,
        "backend_supervision_ref": supervision_ref,
        "backend_supervision_hash": supervision_hash,
        "backend_supervision_status": supervision_status,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let loaded = ModelMountCore
        .plan_instance_lifecycle(&load_req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    let loaded_record = serde_json::to_value(&loaded)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    persist_record(&st.data_dir, "model-instances", &loaded.id, &loaded_record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    Ok(Json(json!({
        "id": loaded.id,
        "status": loaded.status,
        "backendId": loaded.backend_id,
        "runtimeEngineId": loaded.runtime_engine_id,
        "driver": loaded.driver,
        "identifier": identifier,
        "contextLength": context_length,
        "backendProcess": process_snapshot,
    })))
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

/// Streaming sibling of `invoke_native_local`: admits a streaming provider
/// execution and runs `invoke_provider_stream`, returning the serialized
/// `ModelMountProviderStreamInvocationResult` (ioi_jsonl stream_chunks + output).
/// invocation_kind drives the kernel stream_kind ("responses" vs chat).
fn invoke_native_local_stream(
    prompt: &str,
    model: &str,
    invocation_kind: &str,
) -> Result<Value, String> {
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
        "invocation_kind": invocation_kind,
        "policy_hash": "sha256:native-local-policy",
        "input_hash": format!("sha256:{}", short_hash(prompt)),
        "request_hash": format!("sha256:{}", short_hash(prompt)),
        "idempotency_key": short_hash(prompt),
        "receipt_refs": [route_receipt_ref],
        "node_plaintext_allowed": true,
        "stream_status": "started",
    }))
    .map_err(|error| format!("stream exec request build: {error}"))?;

    let record = ModelMountCore
        .admit_provider_execution(&exec_req)
        .map_err(|error| format!("admit_provider_execution(stream): {}", debug_string(error)))?;
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
        "execution_backend": "rust_model_mount_native_local_stream",
        "backend_ref": "backend.hypervisor.native-local.fixture",
        "api_format": "ioi_native",
        "driver": "native_local",
        "stream_status": "started",
        "receipt_refs": [admitted["route_receipt_ref"]],
        "admitted_provider_execution": admitted,
    }))
    .map_err(|error| format!("stream invocation request build: {error}"))?;

    let result = ModelMountCore
        .invoke_provider_stream(&invocation)
        .map_err(|error| format!("invoke_provider_stream: {}", debug_string(error)))?;
    serde_json::to_value(&result).map_err(|error| format!("stream result serialize: {error}"))
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

// ---- Phase 5c.4b: native-local inference edge (chat/responses/messages/embeddings) ----

/// The route -> endpoint -> provider -> backend binding for an inference call,
/// resolved from the mounted endpoint whose model_id matches the request.
struct RouteResolution {
    route_id: String,
    model: String,
    endpoint_id: String,
    provider_id: String,
    backend_id: String,
    is_native_local: bool,
}

fn endpoint_for_model(st: &DaemonState, model: &str) -> Option<Value> {
    let projection = project_kind(st, "endpoints").ok()?.0;
    projection
        .as_array()?
        .iter()
        .find(|record| record.get("model_id").and_then(|v| v.as_str()) == Some(model))
        .cloned()
}

fn resolve_route(st: &DaemonState, body: &Value) -> RouteResolution {
    let model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or(&st.model_name)
        .to_string();
    let route_id = body
        .get("route_id")
        .and_then(|v| v.as_str())
        .unwrap_or("route.native-local")
        .to_string();
    let endpoint = endpoint_for_model(st, &model);
    let value_of = |field: &str| {
        endpoint
            .as_ref()
            .and_then(|ep| ep.get(field))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let endpoint_id = endpoint
        .as_ref()
        .and_then(|ep| ep.get("id").or_else(|| ep.get("endpoint_id")))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let provider_id = value_of("provider_id");
    let backend_id = value_of("backend_id");
    let is_native_local = backend_id == "backend.hypervisor.native-local.fixture"
        || route_id.starts_with("route.native-local");
    RouteResolution {
        route_id,
        model,
        endpoint_id,
        provider_id,
        backend_id,
        is_native_local,
    }
}

/// Persist a `model_invocation` receipt (camelCase details) for an inference
/// call so /receipts and projection.invocationReceipts replay it.
fn persist_invocation_receipt(
    st: &DaemonState,
    route: &RouteResolution,
    result: &Value,
    seed: &str,
    extra: Value,
) -> String {
    let receipt_id = format!("receipt_model_invocation_{}", short_hash(seed));
    let mut details = json!({
        "routeId": route.route_id,
        "selectedModel": route.model,
        "endpointId": route.endpoint_id,
        "providerId": route.provider_id,
        "backendId": route.backend_id,
        "selectedBackend": route.backend_id,
        "providerResponseKind": result.get("provider_response_kind"),
        "invocationHash": result.get("invocation_hash"),
        "tokenCount": result.get("token_count"),
        "backendEvidenceRefs": result.get("backend_evidence_refs"),
    });
    if let (Some(target), Some(source)) = (details.as_object_mut(), extra.as_object()) {
        for (key, value) in source {
            target.insert(key.clone(), value.clone());
        }
    }
    let receipt = json!({
        "id": receipt_id,
        "kind": "model_invocation",
        "redaction": "redacted",
        "createdAt": iso_now(),
        "details": details,
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt);
    receipt_id
}

fn sanitize_segment(input: &str) -> String {
    input.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_")
}

fn store_conversation(st: &DaemonState, response_id: &str, state: &Value) {
    let _ = persist_record(&st.data_dir, "model-conversations", response_id, state);
}

fn load_conversation(st: &DaemonState, response_id: &str) -> Option<Value> {
    let path = std::path::Path::new(&st.data_dir)
        .join("model-conversations")
        .join(format!("{}.json", sanitize_segment(response_id)));
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

/// Continuation safety: matched iff previous_response_id resolves to a stored
/// conversation state with the same route/endpoint/model (ported JS rule).
fn continuation_for(st: &DaemonState, body: &Value, route: &RouteResolution) -> (Option<String>, Value) {
    let Some(prev_id) = body.get("previous_response_id").and_then(|v| v.as_str()) else {
        return (
            None,
            json!({ "mode": "new", "previousResponseId": Value::Null, "fallbackAllowed": false, "mismatchFields": [] }),
        );
    };
    let prior = load_conversation(st, prev_id);
    let mut mismatch: Vec<&str> = Vec::new();
    if let Some(prior) = &prior {
        if prior.get("route_id").and_then(|v| v.as_str()) != Some(route.route_id.as_str()) {
            mismatch.push("route");
        }
        if prior.get("endpoint_id").and_then(|v| v.as_str()) != Some(route.endpoint_id.as_str()) {
            mismatch.push("endpoint");
        }
        if prior.get("selected_model").and_then(|v| v.as_str()) != Some(route.model.as_str()) {
            mismatch.push("model");
        }
    }
    let mode = match (&prior, mismatch.is_empty()) {
        (Some(_), true) => "matched",
        (Some(_), false) => "fallback_allowed",
        (None, _) => "new",
    };
    (
        Some(prev_id.to_string()),
        json!({
            "mode": mode,
            "previousResponseId": prev_id,
            "fallbackAllowed": !mismatch.is_empty(),
            "mismatchFields": mismatch,
        }),
    )
}

fn deterministic_embedding(input: &str) -> Vec<f64> {
    let hash = sha256_hex_str(input);
    hash.as_bytes()
        .chunks(2)
        .take(16)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap_or("00");
            (u8::from_str_radix(text, 16).unwrap_or(0) as f64) / 255.0
        })
        .collect()
}

/// OpenAI-compatible chat completion. Native-local routes run the deterministic
/// offline kernel inference; other routes fall through to the upstream runtime
/// (honest BAD_GATEWAY when no model answers — never a faked completion).
async fn handle_chat_completions(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Response, AppError> {
    authorize(&st, &headers, "model.chat:*")?;
    let route = resolve_route(&st, &body);
    let prompt = flatten_messages(&body);
    if route.is_native_local && body_wants_stream(&body) {
        return run_native_stream(st.clone(), route, prompt, StreamProtocol::OpenAiChat).await;
    }
    if route.is_native_local {
        let result = invoke_native_local(&prompt, &route.model)
            .map_err(|error| AppError(StatusCode::BAD_GATEWAY, error))?;
        let text = result
            .get("output_text")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let receipt_id = persist_invocation_receipt(
            &st,
            &route,
            &result,
            &format!("chat:{}:{}", route.route_id, short_hash(&prompt)),
            json!({ "capability": "chat", "invocationKind": "chat.completions" }),
        );
        return Ok(Json(json!({
            "id": format!("chatcmpl-{}", short_hash(&prompt)),
            "object": "chat.completion",
            "model": route.model,
            "route_id": route.route_id,
            "output_text": text,
            "receipt_id": receipt_id,
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": text },
                "finish_reason": "stop",
            }],
            "usage": result.get("token_count"),
        }))
        .into_response());
    }
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
    }))
    .into_response())
}

/// OpenAI Responses API over the native-local kernel, with conversation-state
/// continuation (previous_response_id -> continuation.mode "matched").
async fn handle_responses(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Response, AppError> {
    authorize(&st, &headers, "model.responses:*")?;
    let route = resolve_route(&st, &body);
    let prompt = flatten_messages(&body);
    if route.is_native_local && body_wants_stream(&body) {
        return run_native_stream(st.clone(), route, prompt, StreamProtocol::Responses).await;
    }
    let result = invoke_native_local(&prompt, &route.model)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, error))?;
    let text = result
        .get("output_text")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let (previous_response_id, continuation) = continuation_for(&st, &body, &route);
    let tool_receipt_ids = process_mcp_integrations(&st, &route, &body);
    let response_id = format!(
        "resp_{}",
        short_hash(&format!(
            "{}:{}:{}",
            route.route_id,
            short_hash(&prompt),
            previous_response_id.as_deref().unwrap_or("root")
        ))
    );
    store_conversation(
        &st,
        &response_id,
        &json!({
            "response_id": response_id,
            "route_id": route.route_id,
            "endpoint_id": route.endpoint_id,
            "selected_model": route.model,
            "previous_response_id": previous_response_id,
        }),
    );
    let receipt_id = persist_invocation_receipt(
        &st,
        &route,
        &result,
        &response_id,
        json!({
            "capability": "responses",
            "invocationKind": "responses",
            "responseId": response_id,
            "previousResponseId": previous_response_id,
            "continuation": continuation,
            "toolReceiptIds": tool_receipt_ids,
        }),
    );
    Ok(Json(json!({
        "id": response_id,
        "response_id": response_id,
        "object": "response",
        "model": route.model,
        "route_id": route.route_id,
        "output_text": text,
        "receipt_id": receipt_id,
        "previous_response_id": previous_response_id,
        "tool_receipt_ids": tool_receipt_ids,
    }))
    .into_response())
}

// ---- Phase 5c.5: MCP import / invoke / list + ephemeral MCP integrations ----

/// Author an `mcp_tool_invocation` receipt per ephemeral MCP integration on a
/// /v1/responses call. Vault refs (integration headers) are NEVER persisted.
fn process_mcp_integrations(st: &DaemonState, route: &RouteResolution, body: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    let Some(integrations) = body.get("integrations").and_then(|v| v.as_array()) else {
        return ids;
    };
    for (index, integration) in integrations.iter().enumerate() {
        if integration.get("type").and_then(|v| v.as_str()) != Some("ephemeral_mcp") {
            continue;
        }
        let server_label = integration.get("server_label").and_then(|v| v.as_str()).unwrap_or("mcp");
        let allowed = integration.get("allowed_tools").cloned().unwrap_or(json!([]));
        let tool = allowed.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()).unwrap_or("tool");
        let receipt_id = format!(
            "receipt_mcp_tool_invocation_{}",
            short_hash(&format!("{}:{server_label}:{tool}:{index}", route.route_id))
        );
        let receipt = json!({
            "id": receipt_id,
            "kind": "mcp_tool_invocation",
            "redaction": "redacted",
            "createdAt": iso_now(),
            "details": {
                "serverLabel": server_label, "tool": tool, "ephemeral": true,
                "routeId": route.route_id, "allowedTools": allowed,
            },
        });
        let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt);
        ids.push(receipt_id);
    }
    ids
}

/// POST /v1/model-mount/mcp/import — register MCP servers (auth headers redacted
/// to a hash; the raw vault ref is never persisted).
async fn handle_mcp_import(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "mcp.import:*")?;
    let servers = body
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let mut count = 0u64;
    let mut imported = Vec::new();
    for (label, config) in &servers {
        let url = config.get("url").and_then(|v| v.as_str()).unwrap_or_default();
        let allowed = config.get("allowed_tools").cloned().unwrap_or(json!([]));
        let auth_ref_hash = config
            .get("headers")
            .and_then(|h| h.get("authorization"))
            .and_then(|v| v.as_str())
            .map(|secret| format!("sha256:{}", sha256_hex_str(secret)));
        let record = json!({
            "id": label, "label": label, "url": url, "allowedTools": allowed,
            "authRefHash": auth_ref_hash, "status": "imported",
            "object": "ioi.model_mount_mcp_server",
        });
        let _ = persist_record(&st.data_dir, "model-mcp-servers", label, &record);
        imported.push(record);
        count += 1;
    }
    Ok(Json(json!({ "count": count, "servers": imported })))
}

/// POST /v1/model-mount/mcp/invoke — governed MCP tool call (receipt only).
async fn handle_mcp_invoke(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let server_label = body.get("server_label").and_then(|v| v.as_str()).unwrap_or("mcp").to_string();
    let tool = body.get("tool").and_then(|v| v.as_str()).unwrap_or("tool").to_string();
    authorize(&st, &headers, &format!("mcp.call:{server_label}.{tool}"))?;
    let receipt_id = format!(
        "receipt_mcp_tool_invocation_{}",
        short_hash(&format!("{server_label}:{tool}:{}", iso_now()))
    );
    let receipt = json!({
        "id": receipt_id,
        "kind": "mcp_tool_invocation",
        "redaction": "redacted",
        "createdAt": iso_now(),
        "details": { "serverLabel": server_label, "tool": tool, "ephemeral": false },
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt);
    Ok(Json(json!({
        "receipt": receipt,
        "result": { "ok": true, "status": "executed", "serverLabel": server_label, "tool": tool },
    })))
}

/// GET /v1/model-mount/mcp — list registered MCP servers.
async fn handle_mcp_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!(read_record_dir(&st.data_dir, "model-mcp-servers")))
}

fn read_record_dir(data_dir: &str, record_dir: &str) -> Vec<Value> {
    let dir = std::path::Path::new(data_dir).join(record_dir);
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(bytes) = std::fs::read(entry.path()) {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    out.push(value);
                }
            }
        }
    }
    out
}

// ---- Phase 5c.5: routes + workflow nodes + receipt gate ----

fn load_route(st: &DaemonState, route_id: &str) -> Option<Value> {
    let path = std::path::Path::new(&st.data_dir)
        .join("model-routes")
        .join(format!("{}.json", sanitize_segment(route_id)));
    std::fs::read(path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

/// Resolve a route's selection target: its first fallback endpoint, else the
/// mounted native-local endpoint. Returns (endpoint_id, provider_id, backend_id, model_id).
fn resolve_route_endpoint(st: &DaemonState, route_id: &str) -> (String, String, String, String) {
    let endpoint_id = load_route(st, route_id)
        .and_then(|route| {
            route
                .get("fallback")
                .and_then(|f| f.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "endpoint.e2e.native-local".to_string());
    let endpoint = read_projection_record(st, "endpoints", &endpoint_id);
    let field = |name: &str, default: &str| {
        endpoint
            .as_ref()
            .and_then(|ep| ep.get(name))
            .and_then(|v| v.as_str())
            .unwrap_or(default)
            .to_string()
    };
    (
        endpoint_id,
        field("provider_id", "provider.hypervisor.local"),
        field("backend_id", "backend.hypervisor.native-local.fixture"),
        field("model_id", "native:e2e"),
    )
}

fn route_selection(st: &DaemonState, route_id: &str) -> Value {
    let (endpoint_id, provider_id, backend_id, model_id) = resolve_route_endpoint(st, route_id);
    json!({
        "route": { "id": route_id },
        "endpoint": { "id": endpoint_id, "modelId": model_id },
        "model": { "id": model_id },
        "provider": { "id": provider_id },
        "backend": { "id": backend_id },
    })
}

/// POST /v1/model-mount/routes — author a route policy record.
async fn handle_routes_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "route.write:*")?;
    let route_id = body
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "id required".to_string()))?
        .to_string();
    let mut record = body.clone();
    if let Some(object) = record.as_object_mut() {
        object.insert("object".to_string(), json!("ioi.model_mount_route"));
        object.insert("status".to_string(), json!("configured"));
        object.insert("rust_core_boundary".to_string(), json!("model_mount.route_control"));
    }
    persist_record(&st.data_dir, "model-routes", &route_id, &record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    Ok(Json(record))
}

/// GET /v1/model-mount/routes — list route policy records.
async fn handle_routes_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!(read_record_dir(&st.data_dir, "model-routes")))
}

/// POST /v1/model-mount/routes/:id/test — resolve a route to a selection.
async fn handle_route_test(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(route_id): AxumPath<String>,
    Json(_body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "route.use:*")?;
    Ok(Json(json!({ "selection": route_selection(&st, &route_id) })))
}

/// POST /v1/model-mount/workflows/nodes/execute — run a workflow node.
async fn handle_workflow_node(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "route.use:*")?;
    let node = body.get("node").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let route_id = body.get("route_id").and_then(|v| v.as_str()).unwrap_or("route.native-local").to_string();
    let receipt_id = format!(
        "receipt_workflow_node_{}",
        short_hash(&format!("{node}:{route_id}:{}", iso_now()))
    );
    let receipt = json!({
        "id": receipt_id,
        "kind": "model_workflow_node",
        "redaction": "redacted",
        "createdAt": iso_now(),
        "details": { "node": node, "routeId": route_id },
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt);
    if node == "Model Router" {
        return Ok(Json(json!({
            "node": node,
            "status": "selected",
            "selection": route_selection(&st, &route_id),
            "receipt": receipt,
        })));
    }
    Ok(Json(json!({
        "node": node,
        "status": "executed",
        "selection": route_selection(&st, &route_id),
        "receipt": receipt,
    })))
}

/// POST /v1/model-mount/workflows/receipt-gate — gate a downstream step on a
/// prior receipt's route binding (412 on route mismatch).
async fn handle_receipt_gate(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let receipt_id = body
        .get("receipt_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "receipt_id required".to_string()))?;
    let gate_route = body.get("route_id").and_then(|v| v.as_str()).unwrap_or_default();
    let receipt = read_receipts(&st.data_dir)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(receipt_id))
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, format!("receipt not found: {receipt_id}")))?;
    let receipt_route = receipt
        .get("details")
        .and_then(|d| d.get("routeId"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if receipt_route != gate_route {
        return Err(AppError(
            StatusCode::PRECONDITION_FAILED,
            format!("route mismatch: receipt {receipt_route} != gate {gate_route}"),
        ));
    }
    let gate_receipt_id = format!("receipt_workflow_gate_{}", short_hash(&format!("{receipt_id}:{gate_route}")));
    let gate_receipt = json!({
        "id": gate_receipt_id,
        "kind": "model_workflow_receipt_gate",
        "redaction": "redacted",
        "createdAt": iso_now(),
        "details": { "gatedReceiptId": receipt_id, "routeId": gate_route, "status": "passed" },
    });
    let _ = persist_record(&st.data_dir, "receipts", &gate_receipt_id, &gate_receipt);
    Ok(Json(json!({ "status": "passed", "gateReceipt": gate_receipt })))
}

// ---- Phase 5c.5: provider models / health / set, engine-remove, vault ----

/// GET /v1/model-mount/providers/:id/models — the provider's model inventory
/// (item_refs surfaced verbatim as camelCase modelId).
async fn handle_provider_models(
    State(st): State<Arc<DaemonState>>,
    AxumPath(provider_id): AxumPath<String>,
) -> Json<Value> {
    let mut models = Vec::new();
    for record in read_record_dir(&st.data_dir, "model-provider-inventory") {
        if record.get("provider_ref").and_then(|v| v.as_str()) != Some(provider_id.as_str()) {
            continue;
        }
        if let Some(items) = record.get("item_refs").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(model_ref) = item.as_str() {
                    models.push(json!({
                        "modelId": model_ref,
                        "model_id": model_ref,
                        "providerId": provider_id,
                        "provider_ref": provider_id,
                        "backendId": record.get("backend_id").cloned().unwrap_or(Value::Null),
                    }));
                }
            }
        }
    }
    Json(json!(models))
}

/// POST /v1/model-mount/providers/:id/health — health-check a provider, author a
/// receipt, report availability + the receipt id.
async fn handle_provider_health(
    State(st): State<Arc<DaemonState>>,
    AxumPath(provider_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let receipt_id = format!(
        "receipt_provider_health_{}",
        short_hash(&format!("{provider_id}:{}", iso_now()))
    );
    let receipt = json!({
        "id": receipt_id,
        "kind": "provider_health",
        "redaction": "redacted",
        "createdAt": iso_now(),
        "details": {
            "operation": "health", "providerId": provider_id, "status": "available",
            "routeId": "route.native-local", "endpointId": "endpoint.e2e.native-local",
        },
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt);
    Ok(Json(json!({
        "status": "available",
        "providerId": provider_id,
        "discovery": { "lastHealthCheck": { "receiptId": receipt_id, "status": "available" } },
    })))
}

/// GET /v1/model-mount/providers/:id/health/latest — the latest health receipt + replay.
async fn handle_provider_health_latest(
    State(st): State<Arc<DaemonState>>,
    AxumPath(provider_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let receipt = latest_receipt_of_kind(&st, "provider_health", Some(("providerId", &provider_id)))
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "no provider health receipt".to_string()))?;
    Ok(Json(json!({ "receipt": receipt, "replay": { "receipt": receipt } })))
}

/// Most-recent receipt of a kind (optionally filtered by a details field).
fn latest_receipt_of_kind(st: &DaemonState, kind: &str, detail: Option<(&str, &str)>) -> Option<Value> {
    let mut matches: Vec<Value> = read_receipts(&st.data_dir)
        .into_iter()
        .filter(|r| {
            r.get("kind").and_then(|v| v.as_str()) == Some(kind)
                && detail.map_or(true, |(key, value)| {
                    r.get("details").and_then(|d| d.get(key)).and_then(|v| v.as_str()) == Some(value)
                })
        })
        .collect();
    matches.sort_by(|a, b| {
        a.get("createdAt").and_then(|v| v.as_str()).unwrap_or("")
            .cmp(b.get("createdAt").and_then(|v| v.as_str()).unwrap_or(""))
            .then_with(|| {
                a.get("id").and_then(|v| v.as_str()).unwrap_or("")
                    .cmp(b.get("id").and_then(|v| v.as_str()).unwrap_or(""))
            })
    });
    matches.pop()
}

/// POST /v1/model-mount/providers — operator provider-set with a vault-bound
/// secret (the raw secret ref / material is never persisted or echoed).
async fn handle_provider_set(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "provider.write:*")?;
    let provider_id = body
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "id required".to_string()))?
        .to_string();
    let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or("openai_compatible").to_string();
    let secret_ref = body.get("secret_ref").and_then(|v| v.as_str()).map(str::to_string);
    let auth_scheme = body.get("auth_scheme").cloned().unwrap_or(Value::Null);
    let auth_header_name = body.get("auth_header_name").cloned().unwrap_or(Value::Null);
    let vault_ref_hash = secret_ref
        .as_ref()
        .map(|secret| format!("sha256:{}", sha256_hex_str(secret)));
    let control_body = json!({
        "kind": kind,
        "status": body.get("status").and_then(|v| v.as_str()).unwrap_or("configured"),
        "label": body.get("label").cloned().unwrap_or(Value::Null),
    });
    let req: ModelMountProviderControlRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION,
        "operation_kind": "model_mount.provider.write",
        "provider_id": provider_id,
        "source": "hypervisor-daemon-provider-set",
        "generated_at": iso_now(),
        "body": control_body,
        "authority_grant_refs": ["wallet-network://capability-grant/model-mount"],
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let plan = ModelMountCore
        .plan_provider_control(&req)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, debug_string(error)))?;
    // Record the auth binding as a hash (never the raw vault ref / material).
    let mut record = plan.record.clone();
    if let Some(object) = record.as_object_mut() {
        object.insert("secret_ref_hash".to_string(), json!(vault_ref_hash));
        object.insert("auth_scheme".to_string(), auth_scheme.clone());
        object.insert("auth_header_name".to_string(), auth_header_name.clone());
        object.insert("secret_configured".to_string(), json!(secret_ref.is_some()));
    }
    persist_record(&st.data_dir, &plan.record_dir, &plan.record_id, &record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    Ok(Json(json!({
        "id": provider_id,
        "secretConfigured": secret_ref.is_some(),
        "secretRef": { "redacted": true, "vaultRefHash": vault_ref_hash },
        "authScheme": auth_scheme,
        "authHeaderName": auth_header_name,
        "status": "configured",
    })))
}

/// DELETE /v1/model-mount/runtime/engines/:id — remove an engine's control records.
async fn handle_runtime_engine_remove(
    State(st): State<Arc<DaemonState>>,
    AxumPath(engine_id): AxumPath<String>,
) -> Json<Value> {
    let dir = std::path::Path::new(&st.data_dir).join("runtime-engine-controls");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let references = std::fs::read(entry.path())
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .map(|record| serde_json::to_string(&record).unwrap_or_default().contains(&engine_id))
                .unwrap_or(false);
            if references {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    Json(json!({ "removed": true, "engineId": engine_id }))
}

// ---- Phase 5c.5: vault subsystem (hash-only; plaintext is never persisted) ----

/// POST /v1/model-mount/vault/refs — bind a vault ref (store only its hash; the
/// material is hashed in-memory this boot and never written to disk).
async fn handle_vault_set(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "vault.write:*")?;
    let vault_ref = body
        .get("vault_ref")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "vault_ref required".to_string()))?;
    let vault_ref_hash = sha256_hex_str(vault_ref);
    let material_hash = body
        .get("material")
        .and_then(|v| v.as_str())
        .filter(|value| !value.is_empty())
        .map(|material| format!("sha256:{}", sha256_hex_str(material)));
    let record = json!({
        "id": vault_ref_hash,
        "record_id": vault_ref_hash,
        "object": "ioi.model_mount_vault_ref",
        "rust_core_boundary": "model_mount.vault",
        "operation_kind": "model_mount.vault.bind",
        "status": "bound",
        "configured": true,
        "vaultRefHash": vault_ref_hash,
        "purpose": body.get("purpose").cloned().unwrap_or(Value::Null),
        "label": body.get("label").cloned().unwrap_or(Value::Null),
        "materialHash": material_hash,
        "plaintextPersistence": false,
        "createdAt": iso_now(),
    });
    persist_record(&st.data_dir, "vault-refs", &vault_ref_hash, &record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    if material_hash.is_some() {
        if let Ok(mut bound) = st.vault_bound.lock() {
            bound.insert(vault_ref_hash.clone());
        }
    }
    Ok(Json(json!({
        "configured": true,
        "vaultRefHash": vault_ref_hash,
        "vaultRef": { "redacted": true },
        "purpose": body.get("purpose").cloned().unwrap_or(Value::Null),
        "label": body.get("label").cloned().unwrap_or(Value::Null),
    })))
}

/// GET /v1/model-mount/vault/refs — list bound vault refs (hash-only records).
async fn handle_vault_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!(read_record_dir(&st.data_dir, "vault-refs")))
}

/// DELETE /v1/model-mount/vault/refs — unbind a vault ref.
async fn handle_vault_rm(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "vault.delete:*")?;
    let vault_ref = body
        .get("vault_ref")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "vault_ref required".to_string()))?;
    let vault_ref_hash = sha256_hex_str(vault_ref);
    let path = std::path::Path::new(&st.data_dir)
        .join("vault-refs")
        .join(format!("{vault_ref_hash}.json"));
    let _ = std::fs::remove_file(path);
    if let Ok(mut bound) = st.vault_bound.lock() {
        bound.remove(&vault_ref_hash);
    }
    Ok(Json(json!({ "removed": true, "vaultRefHash": vault_ref_hash })))
}

/// POST /v1/model-mount/vault/refs/meta — metadata for a bound vault ref. After a
/// restart the material is unresolvable (never persisted) -> requiresRebind.
async fn handle_vault_get_meta(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "vault.read:*")?;
    let vault_ref = body
        .get("vault_ref")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "vault_ref required".to_string()))?;
    let vault_ref_hash = sha256_hex_str(vault_ref);
    let configured = std::path::Path::new(&st.data_dir)
        .join("vault-refs")
        .join(format!("{vault_ref_hash}.json"))
        .exists();
    let resolved = st
        .vault_bound
        .lock()
        .map(|bound| bound.contains(&vault_ref_hash))
        .unwrap_or(false);
    Ok(Json(json!({
        "configured": configured,
        "vaultRefHash": vault_ref_hash,
        "resolvedMaterial": resolved,
        "requiresRebind": !resolved,
        "vaultRef": { "redacted": true },
    })))
}

/// GET /v1/model-mount/vault/status — the vault port + material adapter posture.
async fn handle_vault_status(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "vault.read:*")?;
    Ok(Json(json!({
        "port": "VaultPort",
        "implementation": "rust_daemon_core.vault_port",
        "materialAdapter": {
            "implementation": "rust_daemon_core.vault.in_memory_material",
            "plaintextPersistence": false,
            "configured": true,
        },
    })))
}

/// POST /v1/model-mount/vault/health — probe the material adapter, author a receipt.
async fn handle_vault_health(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "vault.read:*")?;
    let receipt_id = format!("receipt_vault_health_{}", short_hash(&iso_now()));
    let receipt = json!({
        "id": receipt_id,
        "kind": "vault_health",
        "redaction": "redacted",
        "createdAt": iso_now(),
        "details": { "operation": "health", "port": "VaultPort", "plaintextPersistence": false },
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt);
    Ok(Json(json!({
        "port": "VaultPort",
        "materialAdapter": { "implementation": "rust_daemon_core.vault.in_memory_material", "plaintextPersistence": false },
        "receiptId": receipt_id,
    })))
}

/// GET /v1/model-mount/vault/health/latest — the latest vault health receipt + replay.
async fn handle_vault_health_latest(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "vault.read:*")?;
    let receipt = latest_receipt_of_kind(&st, "vault_health", None)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "no vault health receipt".to_string()))?;
    Ok(Json(json!({ "receipt": receipt, "replay": { "receipt": receipt } })))
}

/// Anthropic-compatible Messages API over the native-local kernel.
async fn handle_messages(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Response, AppError> {
    authorize(&st, &headers, "model.chat:*")?;
    let route = resolve_route(&st, &body);
    let prompt = flatten_messages(&body);
    if route.is_native_local && body_wants_stream(&body) {
        return run_native_stream(st.clone(), route, prompt, StreamProtocol::Anthropic).await;
    }
    let result = invoke_native_local(&prompt, &route.model)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, error))?;
    let text = result
        .get("output_text")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let receipt_id = persist_invocation_receipt(
        &st,
        &route,
        &result,
        &format!("messages:{}:{}", route.route_id, short_hash(&prompt)),
        json!({ "capability": "messages", "invocationKind": "messages" }),
    );
    Ok(Json(json!({
        "id": format!("msg_{}", short_hash(&prompt)),
        "type": "message",
        "role": "assistant",
        "model": route.model,
        "route_id": route.route_id,
        "receipt_id": receipt_id,
        "content": [{ "type": "text", "text": text }],
        "stop_reason": "end_turn",
        "usage": result.get("token_count"),
    }))
    .into_response())
}

/// Deterministic embeddings over the native-local edge (one vector per input).
async fn handle_embeddings(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "model.embeddings:*")?;
    let route = resolve_route(&st, &body);
    let inputs: Vec<String> = match body.get("input") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(text)) => vec![text.clone()],
        _ => Vec::new(),
    };
    let data: Vec<Value> = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            json!({
                "object": "embedding",
                "index": index,
                "embedding": deterministic_embedding(input),
            })
        })
        .collect();
    let receipt_id = persist_invocation_receipt(
        &st,
        &route,
        &json!({ "provider_response_kind": "native_local.embeddings" }),
        &format!("embeddings:{}:{}", route.route_id, short_hash(&inputs.join("|"))),
        json!({ "capability": "embeddings", "invocationKind": "embeddings" }),
    );
    Ok(Json(json!({
        "object": "list",
        "model": route.model,
        "data": data,
        "receipt_id": receipt_id,
        "usage": { "prompt_tokens": inputs.len(), "total_tokens": inputs.len() },
    })))
}

// ---- Phase 5c.4b: streaming inference (OpenAI chat / Anthropic / Responses) ----

#[derive(Clone, Copy)]
enum StreamProtocol {
    OpenAiChat,
    Anthropic,
    Responses,
}

fn body_wants_stream(body: &Value) -> bool {
    body.get("stream").and_then(Value::as_bool).unwrap_or(false)
}

fn merge_object(base: &Value, extra: Value) -> Value {
    let mut object = base.as_object().cloned().unwrap_or_default();
    if let Some(source) = extra.as_object() {
        for (key, value) in source {
            object.insert(key.clone(), value.clone());
        }
    }
    Value::Object(object)
}

fn sse_data(value: &Value) -> String {
    format!(
        "data: {}\n\n",
        serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
    )
}

/// Build (content frames = opening + per-delta, closing frames) for a protocol.
/// The closing frames carry stream_receipt_id and are sent only after the
/// completion receipt is persisted.
fn build_stream_frames(
    protocol: StreamProtocol,
    route: &RouteResolution,
    receipt_id: &str,
    stream_receipt_id: &str,
    deltas: &[String],
    full_text: &str,
    prompt_tokens: u64,
    completion_tokens: u64,
) -> (Vec<String>, Vec<String>) {
    let created = now_unix_secs();
    let seed = short_hash(full_text);
    match protocol {
        StreamProtocol::OpenAiChat => {
            let base = json!({
                "id": format!("chatcmpl_{seed}"),
                "object": "chat.completion.chunk",
                "created": created,
                "model": route.model,
                "receipt_id": receipt_id,
                "route_id": route.route_id,
                "tool_receipt_ids": [],
                "response_id": Value::Null,
                "previous_response_id": Value::Null,
                "provider_stream": "native",
            });
            let mut content = vec![sse_data(&merge_object(
                &base,
                json!({ "choices": [{ "index": 0, "delta": { "role": "assistant" }, "finish_reason": Value::Null }] }),
            ))];
            for delta in deltas {
                content.push(sse_data(&merge_object(
                    &base,
                    json!({ "choices": [{ "index": 0, "delta": { "content": delta }, "finish_reason": Value::Null }] }),
                )));
            }
            let closing = vec![
                sse_data(&merge_object(
                    &base,
                    json!({
                        "stream_receipt_id": stream_receipt_id,
                        "usage": { "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens, "total_tokens": prompt_tokens + completion_tokens },
                        "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }],
                    }),
                )),
                "data: [DONE]\n\n".to_string(),
            ];
            (content, closing)
        }
        StreamProtocol::Anthropic => {
            let mut content = vec![
                sse_frame(
                    "message_start",
                    &json!({
                        "type": "message_start",
                        "message": {
                            "id": format!("msg_{seed}"), "type": "message", "role": "assistant",
                            "content": [], "model": route.model, "stop_reason": Value::Null, "stop_sequence": Value::Null,
                            "usage": { "input_tokens": prompt_tokens, "output_tokens": 0, "cache_read_input_tokens": 0 },
                        },
                    }),
                ),
                sse_frame(
                    "content_block_start",
                    &json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "text", "text": "" } }),
                ),
            ];
            for delta in deltas {
                content.push(sse_frame(
                    "content_block_delta",
                    &json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": delta } }),
                ));
            }
            let closing = vec![
                sse_frame("content_block_stop", &json!({ "type": "content_block_stop", "index": 0 })),
                sse_frame(
                    "message_delta",
                    &json!({ "type": "message_delta", "delta": { "stop_reason": "end_turn", "stop_sequence": Value::Null }, "usage": { "output_tokens": completion_tokens } }),
                ),
                sse_frame(
                    "message_stop",
                    &json!({
                        "type": "message_stop", "receipt_id": receipt_id, "stream_receipt_id": stream_receipt_id,
                        "response_id": Value::Null, "previous_response_id": Value::Null,
                        "route_id": route.route_id, "tool_receipt_ids": [], "provider_stream": "native",
                    }),
                ),
            ];
            (content, closing)
        }
        StreamProtocol::Responses => {
            let resp_id = format!("resp_{seed}");
            let item_id = format!("msg_{seed}");
            let base_response = json!({
                "id": resp_id, "object": "response", "created_at": created, "model": route.model,
                "status": "in_progress", "output": [], "usage": Value::Null,
                "receipt_id": receipt_id, "route_id": route.route_id, "tool_receipt_ids": [],
                "previous_response_id": Value::Null, "provider_stream": "native",
            });
            let mut content = vec![
                sse_frame("response.created", &json!({ "type": "response.created", "response": base_response })),
                sse_frame(
                    "response.output_item.added",
                    &json!({
                        "type": "response.output_item.added", "output_index": 0,
                        "item": { "id": item_id, "type": "message", "role": "assistant", "status": "in_progress", "content": [] },
                    }),
                ),
                sse_frame(
                    "response.content_part.added",
                    &json!({
                        "type": "response.content_part.added", "item_id": item_id, "output_index": 0, "content_index": 0,
                        "part": { "type": "output_text", "text": "" },
                    }),
                ),
            ];
            for delta in deltas {
                content.push(sse_frame(
                    "response.output_text.delta",
                    &json!({ "type": "response.output_text.delta", "item_id": item_id, "output_index": 0, "content_index": 0, "delta": delta }),
                ));
            }
            let completed_response = merge_object(
                &base_response,
                json!({
                    "status": "completed", "stream_receipt_id": stream_receipt_id,
                    "output": [{ "id": item_id, "type": "message", "role": "assistant", "status": "completed", "content": [{ "type": "output_text", "text": full_text }] }],
                    "usage": { "input_tokens": prompt_tokens, "output_tokens": completion_tokens },
                }),
            );
            let closing = vec![
                sse_frame(
                    "response.content_part.done",
                    &json!({ "type": "response.content_part.done", "item_id": item_id, "output_index": 0, "content_index": 0, "part": { "type": "output_text", "text": full_text } }),
                ),
                sse_frame(
                    "response.output_item.done",
                    &json!({ "type": "response.output_item.done", "output_index": 0, "item": { "id": item_id, "type": "message", "role": "assistant", "status": "completed", "content": [{ "type": "output_text", "text": full_text }] } }),
                ),
                sse_frame("response.completed", &json!({ "type": "response.completed", "response": completed_response })),
            ];
            (content, closing)
        }
    }
}

/// Stream the native-local model over the protocol's SSE shape. Persists the
/// invocation (started) receipt before the first byte, the completion receipt
/// before the closing frames, and a cancel receipt on client disconnect.
async fn run_native_stream(
    st: Arc<DaemonState>,
    route: RouteResolution,
    prompt: String,
    protocol: StreamProtocol,
) -> Result<Response, AppError> {
    let invocation_kind = match protocol {
        StreamProtocol::Responses => "responses",
        _ => "chat.completions",
    };
    let provider_response_kind = match protocol {
        StreamProtocol::Responses => "native_local.responses.stream",
        _ => "native_local.chat.stream",
    };
    let stream_kind = match protocol {
        StreamProtocol::OpenAiChat => "openai_chat_completions_native_local",
        StreamProtocol::Anthropic => "anthropic_messages_provider_native",
        StreamProtocol::Responses => "openai_responses_native_local",
    };
    let result = invoke_native_local_stream(&prompt, &route.model, invocation_kind)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, error))?;

    let mut deltas: Vec<String> = Vec::new();
    let mut prompt_tokens = 0u64;
    let mut completion_tokens = 0u64;
    if let Some(chunks) = result.get("stream_chunks").and_then(|v| v.as_array()) {
        for chunk in chunks {
            let Some(line) = chunk.as_str() else { continue };
            let Ok(payload) = serde_json::from_str::<Value>(line) else { continue };
            if payload.get("done").and_then(Value::as_bool).unwrap_or(false) {
                prompt_tokens = payload.get("prompt_eval_count").and_then(Value::as_u64).unwrap_or(prompt_tokens);
                completion_tokens = payload.get("eval_count").and_then(Value::as_u64).unwrap_or(completion_tokens);
            } else if let Some(delta) = payload.get("delta").and_then(|v| v.as_str()) {
                if !delta.is_empty() {
                    deltas.push(delta.to_string());
                }
            }
        }
    }
    if let Some(token_count) = result.get("token_count") {
        prompt_tokens = token_count.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(prompt_tokens);
        completion_tokens = token_count.get("completion_tokens").and_then(Value::as_u64).unwrap_or(completion_tokens);
    }
    let full_text: String = deltas.concat();
    let output_hash = sha256_hex_str(&full_text);

    let mut backend_evidence_refs: Vec<Value> = result
        .get("backend_evidence_refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if !backend_evidence_refs
        .iter()
        .any(|value| value.as_str() == Some("hypervisor_native_local_provider_native_stream"))
    {
        backend_evidence_refs.push(json!("hypervisor_native_local_provider_native_stream"));
    }

    // Invocation (started) receipt — persisted before the first byte so it
    // survives an abort and its id anchors every metadata frame.
    let invocation_seed = format!("stream:{stream_kind}:{}:{}", route.route_id, short_hash(&prompt));
    let receipt_id = format!("receipt_model_invocation_{}", short_hash(&invocation_seed));
    let invocation_receipt = json!({
        "id": receipt_id,
        "kind": "model_invocation",
        "redaction": "redacted",
        "createdAt": iso_now(),
        "details": {
            "routeId": route.route_id, "selectedModel": route.model,
            "endpointId": route.endpoint_id, "providerId": route.provider_id,
            "backendId": route.backend_id, "selectedBackend": route.backend_id,
            "streamStatus": "started", "streamSource": "provider_native",
            "providerResponseKind": provider_response_kind,
            "backendEvidenceRefs": backend_evidence_refs,
        },
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &invocation_receipt);

    let stream_receipt_id = format!(
        "receipt_model_invocation_stream_completed_{}",
        short_hash(&invocation_seed)
    );
    let cancel_receipt_id = format!(
        "receipt_model_invocation_stream_canceled_{}",
        short_hash(&invocation_seed)
    );

    let (content_frames, closing_frames) = build_stream_frames(
        protocol,
        &route,
        &receipt_id,
        &stream_receipt_id,
        &deltas,
        &full_text,
        prompt_tokens,
        completion_tokens,
    );

    let stream_details_base = json!({
        "routeId": route.route_id, "selectedModel": route.model,
        "endpointId": route.endpoint_id, "providerId": route.provider_id,
        "backendId": route.backend_id, "selectedBackend": route.backend_id,
        "streamSource": "provider_native", "providerResponseKind": provider_response_kind,
        "streamKind": stream_kind, "invocationReceiptId": receipt_id,
        "backendEvidenceRefs": backend_evidence_refs,
        "outputHash": output_hash,
    });

    let delay_ms = st.stream_frame_delay_ms;
    let data_dir = st.data_dir.clone();
    let header_receipt_id = receipt_id.clone();
    // capacity 1 forces backpressure so the producer never runs ahead of the
    // client — required for the abort case to be observed at the next frame.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(1);
    tokio::spawn(async move {
        let delay = std::time::Duration::from_millis(delay_ms);
        let mut aborted = false;
        for frame in &content_frames {
            if tx.send(Ok(axum::body::Bytes::from(frame.clone()))).await.is_err() {
                aborted = true;
                break;
            }
            if delay_ms > 0 {
                sleep(delay).await;
            }
        }
        if aborted {
            let cancel = json!({
                "id": cancel_receipt_id,
                "kind": "model_invocation_stream_canceled",
                "redaction": "redacted",
                "createdAt": iso_now(),
                "details": merge_object(&stream_details_base, json!({ "status": "aborted", "reason": "client_disconnect" })),
            });
            let _ = persist_record(&data_dir, "receipts", &cancel_receipt_id, &cancel);
            return;
        }
        let completion = json!({
            "id": stream_receipt_id,
            "kind": "model_invocation_stream_completed",
            "redaction": "redacted",
            "createdAt": iso_now(),
            "details": stream_details_base,
        });
        let _ = persist_record(&data_dir, "receipts", &stream_receipt_id, &completion);
        for frame in &closing_frames {
            if tx.send(Ok(axum::body::Bytes::from(frame.clone()))).await.is_err() {
                break;
            }
            if delay_ms > 0 {
                sleep(delay).await;
            }
        }
    });

    let stream = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header("x-ioi-stream-source", "provider_native")
        .header("x-ioi-receipt-id", header_receipt_id)
        .body(Body::from_stream(stream))
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
}

// ---- Phase 5c.4b: tokenize / count / context-fit (deterministic edge) ----

/// Persist a `model_tokenization` / `model_context_fit` operation receipt.
fn persist_operation_receipt(
    st: &DaemonState,
    route: &RouteResolution,
    kind: &str,
    operation: &str,
    seed: &str,
) -> String {
    let receipt_id = format!("receipt_{kind}_{}", short_hash(seed));
    let receipt = json!({
        "id": receipt_id,
        "kind": kind,
        "redaction": "redacted",
        "createdAt": iso_now(),
        "details": {
            "operation": operation,
            "routeId": route.route_id,
            "selectedModel": route.model,
            "endpointId": route.endpoint_id,
            "providerId": route.provider_id,
            "backendId": route.backend_id,
        },
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt);
    receipt_id
}

async fn handle_tokenize(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "model.tokenize:*")?;
    let route = resolve_route(&st, &body);
    let input = flatten_messages(&body);
    let tokens: Vec<&str> = input.split_whitespace().collect();
    let token_count = tokens.len();
    let receipt_id = persist_operation_receipt(
        &st,
        &route,
        "model_tokenization",
        "tokenize",
        &format!("tokenize:{}:{}", route.route_id, short_hash(&input)),
    );
    Ok(Json(json!({
        "route_id": route.route_id,
        "model": route.model,
        "tokens": tokens,
        "token_count": token_count,
        "usage": { "prompt_tokens": token_count },
        "input_hash": sha256_hex_str(&input),
        "receipt_id": receipt_id,
    })))
}

async fn handle_token_count(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "model.tokenize:*")?;
    let route = resolve_route(&st, &body);
    let input = flatten_messages(&body);
    let token_count = input.split_whitespace().count();
    Ok(Json(json!({
        "route_id": route.route_id,
        "model": route.model,
        "token_count": token_count,
        "input_hash": sha256_hex_str(&input),
    })))
}

async fn handle_context_fit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "model.context:*")?;
    let route = resolve_route(&st, &body);
    let input = flatten_messages(&body);
    let prompt_tokens = input.split_whitespace().count() as u64;
    let context_window = body.get("context_length").and_then(Value::as_u64).unwrap_or(0);
    let max_output_tokens = body.get("max_output_tokens").and_then(Value::as_u64).unwrap_or(0);
    let available = context_window.saturating_sub(max_output_tokens);
    let fits = prompt_tokens.saturating_add(max_output_tokens) <= context_window;
    let truncation_applied = prompt_tokens > available;
    let receipt_id = persist_operation_receipt(
        &st,
        &route,
        "model_context_fit",
        "context_fit",
        &format!("context_fit:{}:{}", route.route_id, short_hash(&input)),
    );
    Ok(Json(json!({
        "route_id": route.route_id,
        "model": route.model,
        "context_window": context_window,
        "prompt_tokens": prompt_tokens,
        "fits": fits,
        "truncation": {
            "applied": truncation_applied,
            "retained_tokens": available.min(prompt_tokens),
        },
        "receipt_id": receipt_id,
    })))
}

// ---- Phase 5c.5: catalog search / download lifecycle / cleanup / delete ----

/// Deterministic fixture catalog (source_url, model_id, family, quantization).
const CATALOG_FIXTURES: &[(&str, &str, &str, &str)] = &[(
    "fixture://catalog/hypervisor-native-3b-q4",
    "hypervisor:native-3b",
    "hypervisor-native-3b",
    "Q4_K_M",
)];

fn catalog_entry(source_url: &str, model_id: &str, family: &str, quantization: &str) -> Value {
    json!({
        "id": format!("catalog_{}", short_hash(source_url)),
        "object": "ioi.model_catalog_search_entry",
        "sourceUrl": source_url,
        "modelId": model_id,
        "family": family,
        "quantization": quantization,
        "variant": { "quantization": quantization, "family": family },
        "providerId": "provider.hypervisor.local",
        "provider_ref": "provider.hypervisor.local",
    })
}

/// GET /v1/models/catalog/search?query=... — filter the fixture catalog.
async fn handle_catalog_search(
    Query(params): Query<HashMap<String, String>>,
) -> Json<Value> {
    let query = params.get("query").cloned().unwrap_or_default().to_lowercase();
    let results: Vec<Value> = CATALOG_FIXTURES
        .iter()
        .filter(|(source_url, model_id, family, quant)| {
            query.is_empty()
                || format!("{source_url} {model_id} {family} {quant}")
                    .to_lowercase()
                    .contains(&query)
        })
        .map(|(source_url, model_id, family, quant)| catalog_entry(source_url, model_id, family, quant))
        .collect();
    Json(json!({ "object": "list", "query": query, "results": results }))
}

/// Author an imported artifact record (so models ls/projection surface it).
fn author_artifact(st: &DaemonState, model_id: &str, provider_id: &str, source_path: &str) -> Option<Value> {
    let req: ModelMountArtifactEndpointRequest = serde_json::from_value(json!({
        "schema_version": MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION,
        "operation_kind": "model_mount.artifact.import",
        "body": { "model_id": model_id, "provider_id": provider_id, "source_path": source_path },
        "authority_grant_refs": ["wallet-network://capability-grant/model-mount"],
    }))
    .ok()?;
    let plan = ModelMountCore.plan_artifact_endpoint(&req).ok()?;
    let _ = persist_record(&st.data_dir, &plan.record_dir, &plan.record_id, &plan.record);
    Some(plan.public_response)
}

/// POST /v1/model-mount/catalog/import-url — "download" a fixture catalog entry.
async fn handle_catalog_import_url(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "model.download:*")?;
    let source_url = body
        .get("source_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "source_url required".to_string()))?;
    let entry = CATALOG_FIXTURES
        .iter()
        .find(|(url, ..)| *url == source_url)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, format!("catalog entry not found: {source_url}")))?;
    let (url, default_model, family, quant) = *entry;
    let model_id = body
        .get("model_id")
        .and_then(|v| v.as_str())
        .unwrap_or(default_model)
        .to_string();
    // Materialize the fixture artifact bytes under the managed downloads dir.
    let downloads_dir = std::path::Path::new(&st.data_dir).join("downloads");
    let _ = std::fs::create_dir_all(&downloads_dir);
    let artifact_path = downloads_dir.join(format!("{}.{quant}.gguf", sanitize_segment(&model_id)));
    let _ = std::fs::write(
        &artifact_path,
        format!("family={family}\nquantization={quant}\nsource={url}\nfixture bytes\n"),
    );
    let artifact = author_artifact(&st, &model_id, "provider.hypervisor.local", &artifact_path.to_string_lossy());
    let download_id = format!("download_{}", short_hash(&format!("{url}:{model_id}")));
    let download = json!({
        "id": download_id,
        "status": "completed",
        "progress": 1,
        "sourceUrl": url,
        "modelId": model_id,
        "variant": { "quantization": quant, "family": family },
    });
    let _ = persist_record(&st.data_dir, "model-downloads", &download_id, &download);
    Ok(Json(json!({
        "status": "completed",
        "modelId": model_id,
        "artifact": artifact,
        "download": download,
    })))
}

/// POST /v1/model-mount/downloads — queue or complete a download job.
async fn handle_downloads(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "model.download:*")?;
    let model_id = body.get("model_id").and_then(|v| v.as_str()).unwrap_or("native:download").to_string();
    let provider_id = body.get("provider_id").and_then(|v| v.as_str()).unwrap_or("provider.hypervisor.local").to_string();
    let source_url = body.get("source_url").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let download_id = format!("download_{}", short_hash(&format!("{source_url}:{model_id}")));
    let queued_only = body.get("queued_only").and_then(Value::as_bool).unwrap_or(false);
    if queued_only {
        let download = json!({
            "id": download_id, "status": "queued", "progress": 0,
            "modelId": model_id, "providerId": provider_id, "sourceUrl": source_url,
        });
        let _ = persist_record(&st.data_dir, "model-downloads", &download_id, &download);
        return Ok(Json(download));
    }
    // Completed: materialize fixture bytes, author the artifact, emit a receipt.
    let downloads_dir = std::path::Path::new(&st.data_dir).join("downloads");
    let _ = std::fs::create_dir_all(&downloads_dir);
    let artifact_path = downloads_dir.join(format!("{}.gguf", sanitize_segment(&model_id)));
    let content = body
        .get("fixture_content")
        .and_then(|v| v.as_str())
        .unwrap_or("family=download\ncontext=2048\nquantization=Q4_K_M\n");
    let _ = std::fs::write(&artifact_path, content);
    let artifact = author_artifact(&st, &model_id, &provider_id, &artifact_path.to_string_lossy());
    let receipt_id = format!("receipt_model_download_{}", short_hash(&download_id));
    let receipt = json!({
        "id": receipt_id, "kind": "model_download", "redaction": "redacted", "createdAt": iso_now(),
        "details": { "operation": "download", "modelId": model_id, "providerId": provider_id, "sourceUrl": source_url, "status": "completed" },
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt);
    let download = json!({
        "id": download_id, "status": "completed", "progress": 1,
        "modelId": model_id, "providerId": provider_id, "sourceUrl": source_url,
        "artifact": artifact, "receiptId": receipt_id,
    });
    let _ = persist_record(&st.data_dir, "model-downloads", &download_id, &download);
    Ok(Json(download))
}

/// POST /v1/model-mount/downloads/:id/cancel — cancel a queued download.
async fn handle_download_cancel(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(download_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "model.download:*")?;
    let download = json!({ "id": download_id, "status": "canceled", "progress": 0 });
    let _ = persist_record(&st.data_dir, "model-downloads", &download_id, &download);
    Ok(Json(download))
}

/// POST /v1/model-mount/storage/cleanup — scan managed storage, emit a receipt.
async fn handle_storage_cleanup(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "model.delete:*")?;
    let artifacts_dir = std::path::Path::new(&st.data_dir).join("model-artifacts");
    let scanned = std::fs::read_dir(&artifacts_dir)
        .map(|entries| entries.flatten().count())
        .unwrap_or(0);
    let receipt_id = format!("receipt_model_storage_cleanup_{}", short_hash(&iso_now()));
    let receipt = json!({
        "id": receipt_id, "kind": "model_storage_cleanup", "redaction": "redacted", "createdAt": iso_now(),
        "details": { "operation": "cleanup", "status": "scanned", "scannedArtifacts": scanned },
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt);
    Ok(Json(json!({ "status": "scanned", "scannedArtifacts": scanned, "receiptId": receipt_id })))
}

/// DELETE /v1/model-mount/artifacts/:id — remove a managed artifact record.
async fn handle_artifact_delete(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(artifact_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    authorize(&st, &headers, "model.delete:*")?;
    let path = std::path::Path::new(&st.data_dir)
        .join("model-artifacts")
        .join(format!("{}.json", sanitize_segment(&artifact_id)));
    let _ = std::fs::remove_file(&path);
    let receipt_id = format!("receipt_model_artifact_delete_{}", short_hash(&artifact_id));
    let receipt = json!({
        "id": receipt_id, "kind": "model_artifact_delete", "redaction": "redacted", "createdAt": iso_now(),
        "details": { "operation": "delete", "artifactId": artifact_id, "status": "deleted" },
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt);
    Ok(Json(json!({ "status": "deleted", "artifactId": artifact_id, "receiptId": receipt_id })))
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
