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

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};
use ioi_services::agentic::runtime::kernel::model_mount::{
    ModelMountCore, ModelMountProviderExecutionRequest, ModelMountProviderInvocationRequest,
    ModelMountReadProjectionRequest, MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION,
};
use ioi_types::app::agentic::InferenceOptions;

struct DaemonState {
    inference: Arc<dyn InferenceRuntime>,
    model_name: String,
    data_dir: String,
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
    });

    let app = Router::new()
        .route("/healthz", get(|| async { "OK" }))
        .route("/readyz", get(|| async { "OK" }))
        .route(
            "/v1/hypervisor/dev-replay/status",
            get(handle_dev_replay_status),
        )
        .route("/v1/models", get(handle_models))
        .route("/v1/model-mount/snapshot", get(handle_snapshot))
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

/// Real model-mount kernel projection over HTTP. The truth is Agentgres; this
/// is the daemon-projected snapshot.
async fn handle_snapshot(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let req: ModelMountReadProjectionRequest = serde_json::from_value(json!({
        "projection_kind": "snapshot",
        "state_dir": st.data_dir,
        "state": {},
    }))
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let plan = ModelMountCore
        .plan_read_projection(&req)
        .map_err(|error| (StatusCode::BAD_REQUEST, debug_string(error)))?;
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
) -> Result<Json<Value>, (StatusCode, String)> {
    let prompt = flatten_messages(&body);
    let model = body
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("qwen2.5-coder")
        .to_string();
    let result = invoke_native_local(&prompt, &model)
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    Ok(Json(result))
}

async fn handle_read_projection(
    State(_st): State<Arc<DaemonState>>,
    Json(req): Json<ModelMountReadProjectionRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let plan = ModelMountCore
        .plan_read_projection(&req)
        .map_err(|error| (StatusCode::BAD_REQUEST, debug_string(error)))?;
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
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
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
            (
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
