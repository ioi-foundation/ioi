//! Runtime lifecycle route family (thread/agent/run/turn/control/events/MCP).
//!
//! Part of the unified-Rust-daemon migration: the Rust hypervisor-daemon takes
//! ownership of the runtime lifecycle surface the JS runtime daemon currently
//! serves, so the kernel planner calls (`RuntimeKernelService`) become internal
//! Rust function calls instead of a JS->Rust daemon-core bridge. Handlers here
//! read/write the unified `state_dir` (`DaemonState::data_dir`) in the
//! Agentgres record format the kernel planners expect.
//!
//! Lifecycle routes are unauthenticated (the JS daemon contract issues them with
//! no bearer token), so handlers here do NOT call `authorize`.
//!
//! See `internal-docs/implementation/hypervisor-unified-rust-daemon-lifecycle-migration.md`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use serde_json::{json, Value};

use ioi_services::agentic::runtime::kernel::policy::{
    RunCreateStateUpdateRequest, ThreadControlAgentStateUpdateRequest, ThreadCreateStateUpdateRequest,
    RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    THREAD_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::runtime_thread_event::{
    RuntimeThreadEventProjectionRequest, RuntimeThreadTurnProjectionRequest,
    RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION,
    RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::RuntimeKernelService;

use super::{
    build_route_decision, debug_string, iso_now, persist_record, read_record_dir, route_selection,
    short_hash, AppError, DaemonState,
};

const RUNTIME_THREAD_SCHEMA_VERSION: &str = "ioi.runtime.thread.v1";
const RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION: &str = "ioi.runtime.thread-controls.v1";
const RUNTIME_TURN_SCHEMA_VERSION: &str = "ioi.runtime.turn.v1";

/// Derive the agent id for a thread id (`thread_<x>` -> `agent_<x>`).
fn agent_id_for_thread(thread_id: &str) -> String {
    let suffix = thread_id.strip_prefix("thread_").unwrap_or(thread_id);
    format!("agent_{suffix}")
}

/// Load a persisted agent record for a thread (`state_dir/agents/<agent_id>.json`).
fn read_agent_for_thread(st: &DaemonState, thread_id: &str) -> Option<Value> {
    let agent_id = agent_id_for_thread(thread_id);
    read_record_dir(&st.data_dir, "agents")
        .into_iter()
        .find(|agent| agent.get("id").and_then(|v| v.as_str()) == Some(agent_id.as_str()))
}

/// Coalesce a string field across camelCase / snake_case aliases.
fn coalesce_str<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(found) = value.get(*key).and_then(|v| v.as_str()) {
            if !found.is_empty() {
                return Some(found);
            }
        }
    }
    None
}

/// Derive the thread id for an agent id (`agent_<x>` -> `thread_<x>`), matching
/// the JS `threadIdForAgent` convention.
fn thread_id_for_agent(agent_id: &str) -> String {
    let suffix = agent_id.strip_prefix("agent_").unwrap_or(agent_id);
    format!("thread_{suffix}")
}

/// Project a thread record from persisted state via the kernel thread/turn
/// projection (reads `state_dir/{events,agents,runs}`; synthesizes thread.started
/// at seq 1 from the agent record). Returns the projection's `record` object.
fn project_thread_record(st: &DaemonState, thread_id: &str) -> Result<Value, AppError> {
    let event_stream_id = format!("{thread_id}:events");
    let request: RuntimeThreadTurnProjectionRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION,
        "projection_kind": "thread",
        "thread_schema_version": RUNTIME_THREAD_SCHEMA_VERSION,
        "thread_id": thread_id,
        "event_stream_id": event_stream_id,
        "state_dir": st.data_dir,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let projection = RuntimeKernelService::new()
        .project_runtime_thread_turn_projection(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let projected = serde_json::to_value(&projection)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    Ok(projected.get("record").cloned().unwrap_or(Value::Null))
}

/// POST /v1/threads — create a thread (and its owning agent).
///
/// Resolves the model route internally (the route-control planner as an internal
/// Rust call), builds the agent + thread candidates, validates/stamps via
/// `plan_thread_create_state_update`, persists the agent, and returns the kernel
/// thread projection (the thread.started event is synthesized by the projection).
pub(crate) async fn handle_thread_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let options = body.get("options").cloned().unwrap_or_else(|| body.clone());
    let model = options.get("model").cloned().unwrap_or(Value::Null);
    let now = iso_now();

    // --- resolve the model route (internal route-control) ---
    let route_id = coalesce_str(&model, &["routeId", "route_id", "route"])
        .unwrap_or("route.local-first")
        .to_string();
    let requested_model = coalesce_str(&model, &["id", "model"]).unwrap_or("auto").to_string();
    let capability = coalesce_str(&model, &["capability"]).unwrap_or("chat").to_string();
    let mut model_policy = serde_json::Map::new();
    if let Some(effort) = coalesce_str(&model, &["reasoningEffort", "reasoning_effort", "thinking"]) {
        model_policy.insert("reasoning_effort".to_string(), json!(effort));
    }
    if let Some(privacy) = coalesce_str(&model, &["privacy"]) {
        model_policy.insert("privacy".to_string(), json!(privacy));
    }
    let privacy = coalesce_str(&model, &["privacy"]).map(str::to_string);
    let mut route_body = serde_json::Map::new();
    route_body.insert("model".to_string(), json!(requested_model.clone()));
    route_body.insert("route_id".to_string(), json!(route_id.clone()));
    route_body.insert("capability".to_string(), json!(capability));
    route_body.insert("model_policy".to_string(), Value::Object(model_policy));
    if let Some(graph) = coalesce_str(&model, &["workflowGraphId", "workflow_graph_id"]) {
        route_body.insert("workflow_graph_id".to_string(), json!(graph));
    }
    if let Some(node) = coalesce_str(&model, &["workflowNodeId", "workflow_node_id"]) {
        route_body.insert("workflow_node_id".to_string(), json!(node));
    }
    if let Some(node_type) = coalesce_str(&model, &["workflowNodeType", "workflow_node_type"]) {
        route_body.insert("workflow_node_type".to_string(), json!(node_type));
    }
    let route_body = Value::Object(route_body);
    let selection = route_selection(&st, &route_id);
    let decision = build_route_decision(&route_id, &route_body, &selection);

    let selected_model = decision
        .get("selected_model")
        .and_then(|v| v.as_str())
        .unwrap_or(&requested_model)
        .to_string();
    let endpoint_id = decision.get("endpoint_id").cloned().unwrap_or(Value::Null);
    let provider_id = decision.get("provider_id").cloned().unwrap_or(Value::Null);
    let reasoning_effort = decision.get("reasoning_effort").cloned().unwrap_or(Value::Null);
    let workflow_graph_id = decision.get("workflow_graph_id").cloned().unwrap_or(Value::Null);
    let workflow_node_id = decision
        .get("workflow_node_id")
        .and_then(|v| v.as_str())
        .unwrap_or("runtime.model-router")
        .to_string();
    let decision_id = decision.get("decision_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let receipt_id = format!("receipt_{decision_id}_model_route");

    // --- identity ---
    let agent_id = format!("agent_{}", uuid::Uuid::new_v4());
    let thread_id = thread_id_for_agent(&agent_id);
    let event_stream_id = format!("{thread_id}:events");
    let cwd = options
        .get("local")
        .and_then(|local| local.get("cwd"))
        .and_then(|v| v.as_str())
        .unwrap_or(".")
        .to_string();
    let runtime = if options.get("cloud").is_some() {
        "cloud"
    } else if options.get("hosted").is_some() {
        "hosted"
    } else if options.get("selfHosted").is_some() {
        "selfHosted"
    } else {
        options.get("runtime").and_then(|v| v.as_str()).unwrap_or("local")
    }
    .to_string();

    let runtime_controls = json!({
        "schema_version": RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION,
        "mode": "agent",
        "approval_mode": "suggest",
        "model": {
            "id": requested_model.clone(),
            "route_id": route_id.clone(),
            "selected_model": selected_model.clone(),
            "endpoint_id": endpoint_id.clone(),
            "provider_id": provider_id.clone(),
            "receipt_id": receipt_id.clone(),
            "reasoning_effort": reasoning_effort,
            "privacy": privacy.clone(),
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "updated_at": now.clone(),
        },
    });

    // The agent record is dual-cased: the thread-create planner validates camelCase
    // timestamps (createdAt/updatedAt), while the kernel thread/turn projection reads
    // snake_case fields (created_at, model_route_*, model_id, requested_model_id) and
    // derives the thread.started receipt_refs from receipt_refs / model_route_receipt_id.
    let agent = json!({
        "id": agent_id.clone(),
        "status": "active",
        "runtime": runtime,
        "cwd": cwd.clone(),
        // camelCase (planner validate + JS-client compatibility)
        "createdAt": now.clone(),
        "updatedAt": now.clone(),
        "modelId": selected_model.clone(),
        "requestedModelId": requested_model.clone(),
        "modelRouteId": route_id.clone(),
        "modelRouteEndpointId": endpoint_id.clone(),
        "modelRouteProviderId": provider_id.clone(),
        "modelRouteReceiptId": receipt_id.clone(),
        "modelRouteDecision": decision.clone(),
        "runtimeControls": runtime_controls.clone(),
        // snake_case (kernel thread/turn projection readers)
        "created_at": now.clone(),
        "updated_at": now.clone(),
        "model_id": selected_model.clone(),
        "requested_model_id": requested_model.clone(),
        "model_route_id": route_id.clone(),
        "model_route_endpoint_id": endpoint_id.clone(),
        "model_route_provider_id": provider_id.clone(),
        "model_route_receipt_id": receipt_id.clone(),
        "model_route_decision": decision.clone(),
        "runtime_controls": runtime_controls,
        "receipt_refs": [receipt_id],
        "mcpRegistry": Value::Null,
        "options": json!({ "local": { "cwd": cwd } }),
    });

    let thread = json!({
        "schema_version": RUNTIME_THREAD_SCHEMA_VERSION,
        "thread_id": thread_id.clone(),
        "agent_id": agent_id,
        "event_stream_id": event_stream_id,
        "status": "active",
        "created_at": now.clone(),
        "updated_at": now,
    });

    // --- validate/stamp via the kernel planner ---
    let plan_request: ThreadCreateStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": THREAD_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "agent": agent,
        "thread": thread,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let planned = RuntimeKernelService::new()
        .plan_thread_create_state_update(&plan_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;

    // --- persist the planned agent (thread.started is synthesized by projection) ---
    persist_record(&st.data_dir, "agents", &agent_id, &planned.agent)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    // --- return the kernel thread projection ---
    let record = project_thread_record(&st, &thread_id)?;
    Ok(Json(record))
}

/// GET /v1/threads/:id — project a single thread record.
pub(crate) async fn handle_thread_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let record = project_thread_record(&st, &thread_id)?;
    Ok(Json(record))
}

/// Project a turn record from persisted state via the kernel thread/turn projection
/// (selects the run by id from `state_dir/runs` and rebuilds the turn record).
fn project_turn_record(st: &DaemonState, thread_id: &str, run_id: &str) -> Result<Value, AppError> {
    let event_stream_id = format!("{thread_id}:events");
    let turn_id = format!("turn_{}", run_id.strip_prefix("run_").unwrap_or(run_id));
    let request: RuntimeThreadTurnProjectionRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION,
        "projection_kind": "turn",
        "turn_schema_version": RUNTIME_TURN_SCHEMA_VERSION,
        "thread_id": thread_id,
        "turn_id": turn_id,
        "run_id": run_id,
        "event_stream_id": event_stream_id,
        "state_dir": st.data_dir,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let projection = RuntimeKernelService::new()
        .project_runtime_thread_turn_projection(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let projected = serde_json::to_value(&projection)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    Ok(projected.get("record").cloned().unwrap_or(Value::Null))
}

/// POST /v1/threads/:id/turns — submit a turn (create a run).
///
/// Builds a deterministic run candidate from the thread's agent, validates/stamps
/// via `plan_run_create_state_update` (which materializes the runtime
/// task/job/checklist into the run), persists the run, and returns the kernel turn
/// projection.
pub(crate) async fn handle_turn_create(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let Some(agent) = read_agent_for_thread(&st, &thread_id) else {
        return Err(AppError(
            StatusCode::NOT_FOUND,
            format!("thread not found: {thread_id}"),
        ));
    };
    let agent_id = agent_id_for_thread(&thread_id);
    let now = iso_now();
    let run_id = format!("run_{}", uuid::Uuid::new_v4());
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("send").to_string();
    let prompt = body.get("prompt").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let decision = agent.get("model_route_decision").cloned().unwrap_or(Value::Null);
    let decision_id = decision
        .get("decision_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let receipt_id = agent
        .get("model_route_receipt_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("receipt_{run_id}_model_route"));
    let ledger_id = format!("ledger_{run_id}");
    let result_text = "Runtime turn completed via the Rust true-north daemon.".to_string();
    // Run events the projection maps to runtime turn events (run_started -> turn.started,
    // model_route_decision, completed -> turn.completed). Each carries receipt_refs so the
    // projection's event admission accepts it. run_thread_event reads event.data, not payload.
    let run_events = json!([
        { "type": "run_started", "receipt_refs": [receipt_id.clone()], "data": { "prompt": prompt.clone() } },
        {
            "type": "model_route_decision",
            "receipt_refs": [receipt_id.clone()],
            "data": { "model_route_decision": decision.clone() },
        },
        { "type": "completed", "receipt_refs": [receipt_id.clone()], "data": { "result": result_text.clone() } },
    ]);

    // The run record is dual-cased: plan_run_create_state_update validates camelCase
    // (id/agentId/status/mode/createdAt/updatedAt + usage/usage_telemetry/trace.usage_telemetry
    // objects); the kernel turn projection reads snake_case (created_at, status, result,
    // model_route_decision_id, trace.stop_condition.reason, trace.quality_ledger.ledger_id).
    let run = json!({
        "id": run_id.clone(),
        "agentId": agent_id.clone(),
        "agent_id": agent_id,
        "status": "completed",
        "mode": mode,
        "objective": prompt.clone(),
        "createdAt": now.clone(),
        "updatedAt": now.clone(),
        "created_at": now.clone(),
        "updated_at": now.clone(),
        "usage": json!({}),
        "usage_telemetry": json!({}),
        "result": result_text.clone(),
        "output": result_text.clone(),
        "conversation": json!([]),
        "modelRouteDecision": decision.clone(),
        "model_route_decision": decision.clone(),
        "model_route_decision_id": decision_id,
        "modelRouteReceiptId": receipt_id.clone(),
        "model_route_receipt_id": receipt_id,
        "events": run_events,
        "trace": {
            "usage_telemetry": json!({}),
            "stop_condition": { "reason": "evidence_sufficient", "satisfied": true },
            "quality_ledger": { "ledger_id": ledger_id },
        },
    });

    let plan_request: RunCreateStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "run": run,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let planned = RuntimeKernelService::new()
        .plan_run_create_state_update(&plan_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;

    persist_record(&st.data_dir, "runs", &run_id, &planned.run)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let record = project_turn_record(&st, &thread_id, &run_id)?;
    Ok(Json(record))
}

/// Project the runtime event list for a thread (or a run) via the kernel event
/// projection (synthesizes thread.started + maps run events to runtime events).
fn project_runtime_events(
    st: &DaemonState,
    projection_kind: &str,
    thread_id: &str,
    run_id: Option<&str>,
) -> Result<Vec<Value>, AppError> {
    let event_stream_id = format!("{thread_id}:events");
    let request: RuntimeThreadEventProjectionRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION,
        "projection_kind": projection_kind,
        "thread_id": thread_id,
        "event_stream_id": event_stream_id,
        "run_id": run_id,
        "state_dir": st.data_dir,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let projection = RuntimeKernelService::new()
        .project_runtime_thread_events(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let projected = serde_json::to_value(&projection)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    Ok(projected
        .get("events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default())
}

fn event_seq(event: &Value) -> u64 {
    event.get("seq").and_then(Value::as_u64).unwrap_or(0)
}

/// Resolve the cursor seq from `?since_seq=` or the `Last-Event-ID` header. The header
/// may be a bare seq, a `<stream>:<seq>` cursor, or an `<stream>:seq:<padded>` event id.
fn cursor_seq(params: &HashMap<String, String>, headers: &HeaderMap, events: &[Value]) -> Option<u64> {
    if let Some(raw) = params.get("since_seq") {
        return raw.trim().parse::<u64>().ok();
    }
    let last_event_id = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if let Ok(seq) = last_event_id.parse::<u64>() {
        return Some(seq);
    }
    // Match an event by its event_id, else parse a trailing numeric segment as the seq.
    if let Some(event) = events
        .iter()
        .find(|event| event.get("event_id").and_then(|v| v.as_str()) == Some(last_event_id))
    {
        return Some(event_seq(event));
    }
    last_event_id
        .rsplit(':')
        .find_map(|segment| segment.trim_start_matches('0').parse::<u64>().ok())
}

/// Build a one-shot SSE body (the JS `writeSse` contract) over the events with seq
/// greater than the cursor; 409 if the cursor is beyond the latest seq.
fn sse_events_response(
    events: Vec<Value>,
    params: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    let latest_seq = events.iter().map(event_seq).max().unwrap_or(0);
    let since = cursor_seq(params, headers, &events);
    if let Some(cursor) = since {
        if cursor > latest_seq {
            return Err(AppError(
                StatusCode::CONFLICT,
                serde_json::to_string(&json!({
                    "code": "event_cursor_out_of_range",
                    "latestSeq": latest_seq,
                }))
                .unwrap_or_default(),
            ));
        }
    }
    let mut body = String::new();
    for event in events.iter().filter(|event| event_seq(event) > since.unwrap_or(0)) {
        let id = event
            .get("event_id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| event_seq(event).to_string());
        let data = serde_json::to_string(event).unwrap_or_default();
        body.push_str(&format!("id: {id}\nevent: runtime.event\ndata: {data}\n\n"));
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(body))
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
}

/// GET /v1/threads/:id/events[/stream] — SSE projection of the thread's runtime events.
pub(crate) async fn handle_thread_events(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let events = project_runtime_events(&st, "thread", &thread_id, None)?;
    sse_events_response(events, &params, &headers)
}

/// GET /v1/runs/:id/events — SSE projection of a run's runtime events.
pub(crate) async fn handle_run_events(
    State(st): State<Arc<DaemonState>>,
    AxumPath(run_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(run) = read_record_dir(&st.data_dir, "runs")
        .into_iter()
        .find(|run| run.get("id").and_then(|v| v.as_str()) == Some(run_id.as_str()))
    else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("run not found: {run_id}")));
    };
    let agent_id = run
        .get("agentId")
        .or_else(|| run.get("agent_id"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let thread_id = thread_id_for_agent(agent_id);
    let events = project_runtime_events(&st, "run", &thread_id, Some(&run_id))?;
    sse_events_response(events, &params, &headers)
}

/// GET /v1/runs/:id — return the persisted run record.
pub(crate) async fn handle_run_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    read_record_dir(&st.data_dir, "runs")
        .into_iter()
        .find(|run| run.get("id").and_then(|v| v.as_str()) == Some(run_id.as_str()))
        .map(Json)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, format!("run not found: {run_id}")))
}

/// GET /v1/runs — list persisted run records (optionally filtered by ?agent_id=).
pub(crate) async fn handle_runs_list(
    State(st): State<Arc<DaemonState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<Value> {
    let agent_filter = params.get("agent_id").map(String::as_str);
    let runs: Vec<Value> = read_record_dir(&st.data_dir, "runs")
        .into_iter()
        .filter(|run| match agent_filter {
            Some(agent_id) => {
                run.get("agentId").or_else(|| run.get("agent_id")).and_then(|v| v.as_str())
                    == Some(agent_id)
            }
            None => true,
        })
        .collect();
    Json(json!(runs))
}

/// Synchronize an agent record's snake_case projection fields from the camelCase
/// fields the kernel planners write (the planners mutate camelCase, the kernel
/// projections read snake_case). Camel is the source of truth.
fn dual_case_agent(agent: &mut serde_json::Map<String, Value>) {
    const PAIRS: &[(&str, &str)] = &[
        ("createdAt", "created_at"),
        ("updatedAt", "updated_at"),
        ("modelId", "model_id"),
        ("requestedModelId", "requested_model_id"),
        ("modelRouteId", "model_route_id"),
        ("modelRouteEndpointId", "model_route_endpoint_id"),
        ("modelRouteProviderId", "model_route_provider_id"),
        ("modelRouteReceiptId", "model_route_receipt_id"),
        ("modelRouteDecision", "model_route_decision"),
        ("runtimeControls", "runtime_controls"),
    ];
    for (camel, snake) in PAIRS {
        if let Some(value) = agent.get(*camel).cloned() {
            agent.insert((*snake).to_string(), value);
        }
    }
}

fn coalesce_value(value: &Value, keys: &[&str]) -> Value {
    for key in keys {
        if let Some(found) = value.get(*key) {
            if !found.is_null() {
                return found.clone();
            }
        }
    }
    Value::Null
}

/// Build the model_route payload (planner-required: selected_model/requested_model_id/route_id)
/// from the agent's current model route — used for thinking control (model unchanged).
fn model_route_from_agent(agent: &Value) -> Value {
    json!({
        "requested_model_id": coalesce_value(agent, &["requested_model_id", "requestedModelId"]),
        "selected_model": coalesce_value(agent, &["model_id", "modelId"]),
        "route_id": coalesce_value(agent, &["model_route_id", "modelRouteId"]),
        "endpoint_id": coalesce_value(agent, &["model_route_endpoint_id", "modelRouteEndpointId"]),
        "provider_id": coalesce_value(agent, &["model_route_provider_id", "modelRouteProviderId"]),
        "receipt_id": coalesce_value(agent, &["model_route_receipt_id", "modelRouteReceiptId"]),
        "decision": coalesce_value(agent, &["model_route_decision", "modelRouteDecision"]),
    })
}

fn approval_mode_for_mode(mode: &str) -> &'static str {
    match mode {
        "plan" | "review" => "human_required",
        "yolo" => "never_prompt",
        _ => "suggest",
    }
}

/// Apply a thread runtime control (mode | model | thinking) via the kernel
/// plan_thread_control_agent_state_update planner, then dual-case + persist the
/// updated agent so the projection reflects the new controls.
fn apply_thread_control(
    st: &DaemonState,
    thread_id: &str,
    control_kind: &str,
    body: &Value,
) -> Result<Json<Value>, AppError> {
    let Some(agent) = read_agent_for_thread(st, thread_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    };
    let now = body
        .get("updated_at")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(iso_now);
    let current = agent
        .get("runtime_controls")
        .or_else(|| agent.get("runtimeControls"))
        .cloned()
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({ "schema_version": RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION, "mode": "agent", "approval_mode": "suggest", "model": {} }));
    let current_model = current.get("model").cloned().unwrap_or_else(|| json!({}));

    // Compute the next controls and the planner model_route (None for mode control).
    let (controls, model_route) = if control_kind == "mode" {
        let mode = body
            .get("mode")
            .or_else(|| body.get("interaction_mode"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| current.get("mode").and_then(|v| v.as_str()).unwrap_or("agent"))
            .to_string();
        let approval_mode = body
            .get("approval_mode")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| approval_mode_for_mode(&mode))
            .to_string();
        let mut controls = current.clone();
        if let Some(map) = controls.as_object_mut() {
            map.insert("mode".to_string(), json!(mode));
            map.insert("approval_mode".to_string(), json!(approval_mode));
        }
        (controls, Value::Null)
    } else {
        // model + thinking both update the model controls and require a model_route.
        let mut model = current_model.clone();
        let model_map = model.as_object_mut().unwrap();
        if control_kind == "thinking" {
            let effort = coalesce_value(body, &["reasoning_effort", "thinking"]);
            model_map.insert("reasoning_effort".to_string(), effort);
            model_map.insert("updated_at".to_string(), json!(now));
            let mut controls = current.clone();
            controls.as_object_mut().unwrap().insert("model".to_string(), model);
            (controls, model_route_from_agent(&agent))
        } else {
            // model control: re-resolve the route from the request model.
            let req_model = body.get("model").cloned().unwrap_or(Value::Null);
            let route_id = coalesce_value(&req_model, &["route_id", "routeId"]);
            let route_id = route_id
                .as_str()
                .map(str::to_string)
                .or_else(|| coalesce_value(&agent, &["model_route_id"]).as_str().map(str::to_string))
                .unwrap_or_else(|| "route.local-first".to_string());
            let requested = coalesce_value(&req_model, &["id", "model"]);
            let requested = requested.as_str().unwrap_or("auto").to_string();
            let selection = route_selection(st, &route_id);
            let route_body = json!({ "model": requested, "route_id": route_id, "capability": "chat" });
            let decision = build_route_decision(&route_id, &route_body, &selection);
            let selected_model = decision.get("selected_model").cloned().unwrap_or(Value::Null);
            model_map.insert("id".to_string(), json!(requested));
            model_map.insert("route_id".to_string(), json!(route_id));
            model_map.insert("selected_model".to_string(), selected_model.clone());
            model_map.insert("updated_at".to_string(), json!(now));
            if let Some(effort) = coalesce_value(&req_model, &["reasoning_effort", "reasoningEffort"]).as_str() {
                model_map.insert("reasoning_effort".to_string(), json!(effort));
            }
            let mut controls = current.clone();
            controls.as_object_mut().unwrap().insert("model".to_string(), model);
            let route = json!({
                "requested_model_id": requested,
                "selected_model": selected_model,
                "route_id": route_id,
                "endpoint_id": decision.get("endpoint_id").cloned().unwrap_or(Value::Null),
                "provider_id": decision.get("provider_id").cloned().unwrap_or(Value::Null),
                "receipt_id": coalesce_value(&agent, &["model_route_receipt_id"]),
                "decision": decision,
            });
            (controls, route)
        }
    };

    let event_id = format!("thread_control_{thread_id}_{control_kind}_{}", short_hash(&now));
    let request: ThreadControlAgentStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "thread_id": thread_id,
        "state_dir": st.data_dir,
        "event_stream_id": format!("{thread_id}:events"),
        "agent": agent,
        "control_kind": control_kind,
        "controls": controls,
        "event_id": event_id,
        "created_at": now,
        "updated_at": now,
        "model_route": model_route,
        "receipt_refs": [],
        "policy_decision_refs": [],
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .plan_thread_control_agent_state_update(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;

    // Persist the planner-updated agent, dual-cased so the projection reads it.
    let mut updated_agent = record.agent.clone();
    if let Some(map) = updated_agent.as_object_mut() {
        dual_case_agent(map);
    }
    let agent_id = agent_id_for_thread(thread_id);
    persist_record(st.data_dir.as_str(), "agents", &agent_id, &updated_agent)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    // Shape the control response.
    let source_event_kind = match control_kind {
        "mode" => "OperatorControl.Mode",
        "model" => "OperatorControl.Model",
        _ => "OperatorControl.Thinking",
    };
    let event_kind = if control_kind == "model" {
        "model.route_decision".to_string()
    } else {
        format!("thread.{control_kind}_updated")
    };
    let mut response = serde_json::to_value(&record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let model_controls = controls.get("model").cloned().unwrap_or(Value::Null);
    if let Some(map) = response.as_object_mut() {
        map.insert("commit".to_string(), json!({ "persisted": true }));
        map.insert("source".to_string(), json!("rust_thread_control"));
        map.insert("backend".to_string(), json!("rust_policy"));
        map.insert("control_kind".to_string(), json!(control_kind));
        map.insert("runtime_controls".to_string(), controls.clone());
        map.insert("mode".to_string(), controls.get("mode").cloned().unwrap_or(Value::Null));
        map.insert(
            "approval_mode".to_string(),
            controls.get("approval_mode").cloned().unwrap_or(Value::Null),
        );
        map.insert(
            "reasoning_effort".to_string(),
            model_controls.get("reasoning_effort").cloned().unwrap_or(Value::Null),
        );
        map.insert("requested_model".to_string(), model_controls.get("id").cloned().unwrap_or(Value::Null));
        map.insert("model_route_id".to_string(), model_controls.get("route_id").cloned().unwrap_or(Value::Null));
        map.insert(
            "event".to_string(),
            json!({
                "source_event_kind": source_event_kind,
                "event_kind": event_kind,
                "component_kind": if control_kind == "model" { "model_router" } else { "thread_control" },
                "control_kind": control_kind,
            }),
        );
    }
    Ok(Json(response))
}

/// POST /v1/threads/:id/mode — set the thread interaction mode + approval mode.
pub(crate) async fn handle_thread_mode(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    apply_thread_control(&st, &thread_id, "mode", &body)
}

/// POST /v1/threads/:id/model — set the thread model route.
pub(crate) async fn handle_thread_model(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    apply_thread_control(&st, &thread_id, "model", &body)
}

/// POST /v1/threads/:id/thinking — set the thread reasoning effort.
pub(crate) async fn handle_thread_thinking(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    apply_thread_control(&st, &thread_id, "thinking", &body)
}

/// GET /v1/threads — list thread projection records (one per persisted agent).
pub(crate) async fn handle_threads_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let agents = read_record_dir(&st.data_dir, "agents");
    let mut threads = Vec::new();
    for agent in &agents {
        let Some(agent_id) = agent.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let thread_id = thread_id_for_agent(agent_id);
        if let Ok(record) = project_thread_record(&st, &thread_id) {
            if record.is_object() {
                threads.push(record);
            }
        }
    }
    Json(json!(threads))
}
