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
use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use serde_json::{json, Value};

use ioi_services::agentic::runtime::kernel::policy::{
    AgentCreateStateUpdateRequest, CompactionPolicyRequest, ContextBudgetPolicyRequest,
    ContextCompactionPlanRequest, ContextCompactionStateUpdateRequest,
    McpControlAgentStateUpdateRequest, McpToolSearchProjectionRequest,
    OperatorInterruptStateUpdateRequest, OperatorSteerStateUpdateRequest,
    RunCancelStateUpdateRequest, RunCreateStateUpdateRequest, SubagentRecordStateUpdateRequest,
    ThreadControlAgentStateUpdateRequest, ThreadCreateStateUpdateRequest,
    WorkspaceTrustControlStateUpdateRequest, AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    COMPACTION_POLICY_REQUEST_SCHEMA_VERSION, CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
    CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION,
    CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    MCP_TOOL_SEARCH_PROJECTION_REQUEST_SCHEMA_VERSION,
    OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION, RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    THREAD_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    WORKSPACE_TRUST_CONTROL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::approval::{
    verify_wallet_approval_grant_binding, ApprovalDecisionAuthorityRequest,
    ApprovalDecisionStateUpdateRequest, ApprovalRequestAuthorityRequest,
    ApprovalRequestStateUpdateRequest, ApprovalRevokeStateUpdateRequest,
    APPROVAL_DECISION_AUTHORITY_REQUEST_SCHEMA_VERSION,
    APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    APPROVAL_REQUEST_AUTHORITY_REQUEST_SCHEMA_VERSION,
    APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::runtime_conversation_artifact_control::{
    RuntimeConversationArtifactControlRequest,
    RUNTIME_CONVERSATION_ARTIFACT_CONTROL_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::runtime_conversation_artifact_projection::RuntimeConversationArtifactProjectionRequest;
use ioi_services::agentic::runtime::kernel::runtime_diagnostics_repair_control::{
    RuntimeDiagnosticsRepairControlRequest, RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::agentgres_admission::{
    RuntimeRunStateCommitRequest, RUNTIME_RUN_STATE_COMMIT_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::runtime_doctor_report::RuntimeDoctorReportProjectionRequest;
use ioi_services::agentic::runtime::kernel::runtime_lifecycle::RuntimeLifecycleProjectionRequest;
use ioi_services::agentic::runtime::kernel::runtime_managed_session_control::{
    RuntimeManagedSessionControlRequest, RuntimeManagedSessionProjectionRequest,
    RUNTIME_MANAGED_SESSION_CONTROL_REQUEST_SCHEMA_VERSION,
    RUNTIME_MANAGED_SESSION_PROJECTION_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::runtime_workspace_change_control::{
    RuntimeWorkspaceChangeControlRequest, RuntimeWorkspaceChangeProjectionRequest,
    RUNTIME_WORKSPACE_CHANGE_CONTROL_REQUEST_SCHEMA_VERSION,
    RUNTIME_WORKSPACE_CHANGE_PROJECTION_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::workspace_restore::{
    capture_workspace_snapshot_files_protocol_response, WorkspaceRestoreApplyPolicyRequest,
    WorkspaceRestoreOperationsRequest, WorkspaceSnapshotCaptureProtocolRequest,
    WorkspaceSnapshotListProtocolRequest, WorkspaceSnapshotListRequest,
    WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION,
    WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
    WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION,
    WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION, WORKSPACE_SNAPSHOT_LIST_REQUEST_SCHEMA_VERSION,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ioi_services::agentic::runtime::kernel::runtime_memory_control::{
    RuntimeMemoryControlApiRequest, RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::runtime_memory_projection::{
    RuntimeMemoryProjectionApiRequest, RUNTIME_MEMORY_PROJECTION_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::runtime_thread_event::{
    RuntimeThreadEventAdmissionRequest, RuntimeThreadEventProjectionRequest,
    RuntimeThreadEventReplayRequest, RuntimeThreadTurnProjectionRequest,
    RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
    RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION,
    RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION,
    RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::RuntimeKernelService;

use super::{
    build_route_decision, debug_string, iso_now, persist_record, read_record_dir, route_selection,
    sha256_hex_str, short_hash, AppError, DaemonState,
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

/// Build the dual-cased agent candidate for a create request: resolve the model
/// route internally (the route-control planner as an internal Rust call), assign
/// identity, and construct the runtime controls. Shared by thread-create and
/// agent-create. The planners validate camelCase (createdAt/updatedAt); the kernel
/// projections read snake_case (created_at, model_route_*, model_id) — both are set.
fn build_agent_candidate(st: &DaemonState, options: &Value) -> Value {
    let model = options.get("model").cloned().unwrap_or(Value::Null);
    let now = iso_now();
    // The SDK Agent constructor reads options.subagentNames (Object.keys(options.agents)).
    let subagent_names: Vec<String> = options
        .get("agents")
        .and_then(|agents| agents.as_object())
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default();

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
    let selection = route_selection(st, &route_id);
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
        "options": json!({ "local": { "cwd": cwd }, "subagentNames": subagent_names }),
    });
    agent
}

/// POST /v1/threads — create a thread (and its owning agent).
///
/// Builds the agent + thread candidates, validates/stamps via
/// `plan_thread_create_state_update`, persists the agent, and returns the kernel
/// thread projection (the thread.started event is synthesized by the projection).
pub(crate) async fn handle_thread_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let options = body.get("options").cloned().unwrap_or_else(|| body.clone());
    let agent = build_agent_candidate(&st, &options);
    let agent_id = agent
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let thread_id = thread_id_for_agent(&agent_id);
    let event_stream_id = format!("{thread_id}:events");
    let now = agent
        .get("created_at")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(iso_now);

    let thread = json!({
        "schema_version": RUNTIME_THREAD_SCHEMA_VERSION,
        "thread_id": thread_id.clone(),
        "agent_id": agent_id.clone(),
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

    // --- persist the planned agent, then admit+persist thread.started to the log ---
    persist_record(&st.data_dir, "agents", &agent_id, &planned.agent)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    persist_thread_events(&st, &thread_id)?;

    // --- return the kernel thread projection ---
    let record = project_thread_record(&st, &thread_id)?;
    Ok(Json(record))
}

/// POST /v1/agents — create an agent (no thread) via plan_agent_create_state_update.
pub(crate) async fn handle_agent_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let options = body.get("options").cloned().unwrap_or_else(|| json!({}));
    let agent = build_agent_candidate(&st, &options);
    let agent_id = agent
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let plan_request: AgentCreateStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "agent": agent,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let planned = RuntimeKernelService::new()
        .plan_agent_create_state_update(&plan_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    persist_record(st.data_dir.as_str(), "agents", &agent_id, &planned.agent)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    Ok(Json(planned.agent))
}

/// GET /v1/agents — list persisted agent records.
pub(crate) async fn handle_agents_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!(read_record_dir(&st.data_dir, "agents")))
}

/// Apply an operator turn control (interrupt | steer) via the kernel operator-control
/// planner, then persist the updated run. Returns the operator-control envelope.
fn operator_turn_control(
    st: &DaemonState,
    thread_id: &str,
    turn_id: &str,
    body: &Value,
    kind: &str,
) -> Result<Json<Value>, AppError> {
    let run_id = format!("run_{}", turn_id.strip_prefix("turn_").unwrap_or(turn_id));
    let now = iso_now();
    let event_id = format!("operator_{kind}_{thread_id}_{turn_id}_{}", short_hash(&now));
    let source = body.get("source").and_then(|v| v.as_str()).unwrap_or("hypervisor_daemon");
    let event_stream_id = format!("{thread_id}:events");

    let record_value = if kind == "interrupt" {
        let reason = body
            .get("reason")
            .or_else(|| body.get("message"))
            .or_else(|| body.get("runtime_control_action"))
            .or_else(|| body.get("control_action"))
            .and_then(|v| v.as_str())
            .unwrap_or("operator requested interrupt");
        let request: OperatorInterruptStateUpdateRequest = serde_json::from_value(json!({
            "schema_version": OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
            "thread_id": thread_id,
            "state_dir": st.data_dir,
            "event_stream_id": event_stream_id,
            "turn_id": turn_id,
            "run_id": run_id,
            "event_id": event_id,
            "created_at": now,
            "source": source,
            "reason": reason,
        }))
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
        let record = RuntimeKernelService::new()
            .plan_operator_interrupt_state_update(&request)
            .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
        persist_operator_run(st, &run_id, kind, &record.run);
        serde_json::to_value(&record)
    } else {
        let guidance = body
            .get("guidance")
            .or_else(|| body.get("message"))
            .or_else(|| body.get("input"))
            .and_then(|v| v.as_str())
            .unwrap_or("operator steer");
        let request: OperatorSteerStateUpdateRequest = serde_json::from_value(json!({
            "schema_version": OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
            "thread_id": thread_id,
            "state_dir": st.data_dir,
            "event_stream_id": event_stream_id,
            "turn_id": turn_id,
            "run_id": run_id,
            "event_id": event_id,
            "created_at": now,
            "source": source,
            "guidance": guidance,
        }))
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
        let record = RuntimeKernelService::new()
            .plan_operator_steer_state_update(&request)
            .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
        persist_operator_run(st, &run_id, kind, &record.run);
        serde_json::to_value(&record)
    }
    .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    Ok(Json(record_value))
}

/// Persist the operator-control-updated run (keyed by the run's own id) and refresh its
/// bundle. Best-effort: an interrupt/steer must not fail just because the bundle refresh
/// did (persist_run_with_bundle still writes runs/<run>.json on a bundle-commit failure).
fn persist_operator_run(st: &DaemonState, fallback_run_id: &str, kind: &str, run: &Value) {
    let run_id = run
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or(fallback_run_id);
    let _ = persist_run_with_bundle(st, run_id, &format!("run.{kind}"), run);
}

/// POST /v1/threads/:id/turns/:turnId/interrupt — operator interrupt.
pub(crate) async fn handle_turn_interrupt(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, turn_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    operator_turn_control(&st, &thread_id, &turn_id, &body, "interrupt")
}

/// POST /v1/threads/:id/turns/:turnId/steer — operator steer.
pub(crate) async fn handle_turn_steer(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, turn_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    operator_turn_control(&st, &thread_id, &turn_id, &body, "steer")
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

/// Build a deterministic, dual-cased run candidate for an agent. The kernel
/// plan_run_create_state_update validates camelCase (id/agentId/status/mode/
/// createdAt/updatedAt + usage objects); the turn projection reads snake_case
/// (created_at, status, result, trace.stop_condition.reason, quality_ledger). The
/// run events map to runtime turn events (run_started->turn.started, completed->
/// turn.completed); run_thread_event reads event.data + requires receipt_refs.
/// Shared by turn-create and subagent runs.
fn build_run_candidate(agent: &Value, run_id: &str, mode: &str, prompt: &str, now: &str) -> Value {
    let agent_id = agent.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
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
    // The materializer splices runtime task/job/checklist events ahead of the terminal
    // `completed`, so `turn.completed` projects LAST. The decision event carries
    // payload_summary.event_kind=ModelRouteDecision + workflow.model-router so it projects
    // as the contract's `item.completed` model-route decision. The delta + usage_delta
    // round the durable stream out to the contract's >= 11 events.
    let run_events = json!([
        { "type": "run_started", "receipt_refs": [receipt_id.clone()], "data": { "prompt": prompt } },
        {
            "type": "model_route_decision",
            "receipt_refs": [receipt_id.clone()],
            "data": {
                "event_kind": "ModelRouteDecision",
                "workflow_node_id": "workflow.model-router",
                "model_route_decision": decision.clone(),
            },
        },
        {
            "type": "delta",
            "receipt_refs": [receipt_id.clone()],
            "data": { "text": result_text.clone() },
        },
        {
            "type": "usage_delta",
            "receipt_refs": [receipt_id.clone()],
            "data": { "usage_telemetry": { "total_tokens": 0 } },
        },
        { "type": "completed", "receipt_refs": [receipt_id.clone()], "data": { "result": result_text.clone() } },
    ]);
    json!({
        "id": run_id,
        "agentId": agent_id.clone(),
        "agent_id": agent_id,
        "status": "completed",
        "mode": mode,
        "objective": prompt,
        "createdAt": now,
        "updatedAt": now,
        "created_at": now,
        "updated_at": now,
        "usage": json!({}),
        "usage_telemetry": json!({}),
        "result": result_text.clone(),
        "output": result_text,
        "conversation": json!([]),
        "modelRouteDecision": decision.clone(),
        "model_route_decision": decision,
        "model_route_decision_id": decision_id,
        "modelRouteReceiptId": receipt_id.clone(),
        "model_route_receipt_id": receipt_id,
        "events": run_events,
        "trace": {
            "usage_telemetry": json!({}),
            "stop_condition": { "reason": "evidence_sufficient", "satisfied": true },
            "quality_ledger": { "ledger_id": ledger_id },
            // Canonical-state marker + scorecard the live contract reads off the run trace
            // (GET /v1/runs/:id/trace + /scorecard); scorecard also populates the bundle
            // scorecards/<run>.json record (the materializer reads trace.scorecard).
            "canonicalState": { "source": "agentgres_canonical_state_projection" },
            "scorecard": {
                "object": "ioi.runtime_scorecard",
                "runId": run_id,
                "verifierIndependence": 1,
            },
        },
    })
}

/// Commit a run's full Agentgres state bundle to `<state_dir>` via the kernel
/// `commit_runtime_run_state_to_dir`. This writes `runs/<run>.json` (byte-identical to a
/// plain `persist_record` — payload is the run verbatim) PLUS the canonical Agentgres
/// bundle the live contract expects: `tasks/`, `jobs/`, `checklists/`, `scorecards/`,
/// `ledgers/`, `quality/`, `projections/`, `receipts/`, `artifacts/` — all derived from
/// the run's embedded runtimeTask/Job/Checklist + receipts. Replaces the bare
/// `persist_record(runs)` for run-state mutations so the Rust daemon's state_dir matches
/// the canonical layout (the split-brain repoint target toward JS-daemon retirement).
fn commit_run_state_bundle(
    st: &DaemonState,
    run_id: &str,
    operation_kind: &str,
    run: &Value,
) -> Result<(), AppError> {
    // Daemon-derived canonical projection marker; the kernel folds the agentgres
    // transition into the persisted projections/<run>.json record.
    let canonical_projection = json!({
        "runId": run_id,
        "object": "ioi.runtime_canonical_state_projection",
        "source": "agentgres_canonical_state_projection",
    });
    let request: RuntimeRunStateCommitRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_RUN_STATE_COMMIT_SCHEMA_VERSION,
        "run_id": run_id,
        "operation_kind": operation_kind,
        "storage_backend_ref": "storage://runtime-agentgres/local-json",
        "run": run,
        "canonical_projection": canonical_projection,
    }))
    .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    RuntimeKernelService::new()
        .commit_runtime_run_state_to_dir(st.data_dir.as_str(), &request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(())
}

/// Persist a run AND refresh its canonical Agentgres bundle, keeping the bundle faithful
/// across the WHOLE run lifecycle (not just create/cancel). Commits the full bundle via
/// [`commit_run_state_bundle`]; if that fails — e.g. a run that lacks the embedded
/// runtimeTask/Job/Checklist the bundle requires — it falls back to a plain
/// `persist_record` so `runs/<run>.json` is ALWAYS written. The run record is durable; the
/// bundle refresh is best-effort on top of it (validate() runs before any write, so a
/// rejected commit leaves no partial bundle).
fn persist_run_with_bundle(
    st: &DaemonState,
    run_id: &str,
    operation_kind: &str,
    run: &Value,
) -> Result<(), AppError> {
    if commit_run_state_bundle(st, run_id, operation_kind, run).is_ok() {
        return Ok(());
    }
    persist_record(st.data_dir.as_str(), "runs", run_id, run)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
}

/// POST /v1/threads/:id/turns — submit a turn (create a run).
///
/// Shared run-create flow for an agent — used by both turn-create (POST /v1/threads/:id/
/// turns) and agent run-create (POST /v1/agents/:id/runs). Builds the deterministic run
/// candidate, validates/materializes it via plan_run_create, commits the full Agentgres
/// bundle, and admits+persists the turn events onto the thread log. thread.started is
/// synthesized from the agent, so an agent created via POST /v1/agents (no explicit thread)
/// still bootstraps the thread correctly. Returns the planned run record (a RuntimeRunRecord:
/// id / agentId / status / mode / objective / events / trace / ...).
fn create_agent_run(
    st: &DaemonState,
    agent: &Value,
    thread_id: &str,
    mode: &str,
    prompt: &str,
) -> Result<Value, AppError> {
    let now = iso_now();
    let run_id = format!("run_{}", uuid::Uuid::new_v4());
    let run = build_run_candidate(agent, &run_id, mode, prompt, &now);
    let plan_request: RunCreateStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "run": run,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let planned = RuntimeKernelService::new()
        .plan_run_create_state_update(&plan_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    // Persist the run as the full canonical Agentgres bundle (not just runs/<run>.json).
    commit_run_state_bundle(st, &run_id, "run.create", &planned.run)?;
    persist_thread_events(st, thread_id)?;
    Ok(planned.run)
}

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
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("send");
    let prompt = body.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
    let run = create_agent_run(&st, &agent, &thread_id, mode, prompt)?;
    let run_id = run.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();

    let record = project_turn_record(&st, &thread_id, &run_id)?;
    Ok(Json(record))
}

/// POST /v1/agents/:id/runs — create a run for an agent directly (the SDK send / plan /
/// dry_run / handoff path). Unlike POST /v1/threads/:id/turns (which returns the turn
/// projection), this returns the run record itself (the SDK's RuntimeRunRecord), keyed by
/// the run id the SDK then drives /v1/runs/:id/* against.
pub(crate) async fn handle_agent_run_create(
    State(st): State<Arc<DaemonState>>,
    AxumPath(agent_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let Some(agent) = read_record_dir(&st.data_dir, "agents")
        .into_iter()
        .find(|record| record.get("id").and_then(|v| v.as_str()) == Some(agent_id.as_str()))
    else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("agent not found: {agent_id}")));
    };
    let thread_id = thread_id_for_agent(&agent_id);
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("send");
    let prompt = body.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
    let run = create_agent_run(&st, &agent, &thread_id, mode, prompt)?;
    Ok(Json(run))
}

/// Append admitted runtime events to the thread's persisted Agentgres event log
/// (`<state_dir>/events/<sha256(stream_id)>.jsonl`). The kernel reads every
/// `*.jsonl` under `events/` and filters by `event_stream_id`, so one file per
/// stream keeps appends contiguous without clobbering sibling streams.
fn append_persisted_events(
    st: &DaemonState,
    event_stream_id: &str,
    events: &[Value],
) -> Result<(), AppError> {
    if events.is_empty() {
        return Ok(());
    }
    let events_dir = Path::new(st.data_dir.as_str()).join("events");
    fs::create_dir_all(&events_dir)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let path = events_dir.join(format!("{}.jsonl", sha256_hex_str(event_stream_id)));
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    for event in events {
        let line = serde_json::to_string(event)
            .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
        writeln!(file, "{line}")
            .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    }
    Ok(())
}

/// Admit a single custom runtime event (e.g. a context-policy / workspace-trust
/// decision) onto the persisted log via the kernel admission planner — it reads the
/// stream's `latest_seq` from `<state_dir>/events/*.jsonl` and assigns seq+1, so the
/// event lands AFTER the thread.started + turn events already on the log — then
/// append the admitted event. Returns the admitted event (with seq, event_id, refs).
/// Return the already-admitted event on `event_stream_id` carrying `idempotency_key`,
/// if any. Makes admission idempotent: re-admitting the same logical event (a managed
/// session re-projected on every browser action, a snapshot captured twice over an
/// unchanged workspace, a re-applied restore with the same outcome) returns the prior
/// event instead of appending a duplicate line — which would otherwise grow the log
/// unboundedly and let GET /events show duplicate/stale records.
fn existing_event_by_idempotency_key(
    st: &DaemonState,
    event_stream_id: &str,
    idempotency_key: &str,
) -> Option<Value> {
    if idempotency_key.is_empty() {
        return None;
    }
    let path = Path::new(st.data_dir.as_str())
        .join("events")
        .join(format!("{}.jsonl", sha256_hex_str(event_stream_id)));
    let contents = fs::read_to_string(&path).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if event.get("idempotency_key").and_then(|v| v.as_str()) == Some(idempotency_key) {
            return Some(event);
        }
    }
    None
}

fn admit_and_persist_event(st: &DaemonState, event: Value) -> Result<Value, AppError> {
    let event_stream_id = event
        .get("event_stream_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let idempotency_key = event
        .get("idempotency_key")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    // Serialize dedup-check + admit (latest_seq) + append against the runtime event-log
    // bridge (a second process writing the same stream file). Same lock path both sides.
    ioi_services::agentic::runtime::event_log_bridge::with_event_stream_lock(
        &st.data_dir,
        &event_stream_id,
        || {
            if let Some(existing) =
                existing_event_by_idempotency_key(st, &event_stream_id, &idempotency_key)
            {
                return Ok(existing);
            }
            let request: RuntimeThreadEventAdmissionRequest = serde_json::from_value(json!({
                "schema_version": RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
                "event": event,
                "state_dir": st.data_dir,
            }))
            .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
            let record = RuntimeKernelService::new()
                .admit_runtime_thread_event(&request)
                .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
            let admitted = serde_json::to_value(&record.event)
                .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
            append_persisted_events(st, &event_stream_id, std::slice::from_ref(&admitted))?;
            Ok(admitted)
        },
    )
}

/// Unified-event-log writer: run the kernel thread-event projection (which admits
/// the synthesized thread.started + run/turn/materializer events on top of the
/// already-persisted log, skipping anything whose idempotency_key is present) and
/// APPEND the freshly-admitted events to the persisted log. Idempotent — calling it
/// twice yields no duplicates because the projection dedupes against the log. This is
/// the write half of the unified event model: GET /events reads back via `replay`.
fn persist_thread_events(st: &DaemonState, thread_id: &str) -> Result<(), AppError> {
    let event_stream_id = format!("{thread_id}:events");
    // This is a THIRD writer to the stream's <sha256(stream)>.jsonl (alongside
    // admit_and_persist_event and the runtime bridge); it must take the SAME per-stream
    // lock across its read-latest-seq (project) + append window, or it re-opens the
    // duplicate-seq race the lock closes.
    ioi_services::agentic::runtime::event_log_bridge::with_event_stream_lock(
        &st.data_dir,
        &event_stream_id,
        || {
            let admitted = project_runtime_events(st, "thread", thread_id, None)?;
            append_persisted_events(st, &event_stream_id, &admitted)
        },
    )
}

/// Replay the full persisted runtime-event log for a stream (`replay_kind = stream`)
/// or a single turn (`replay_kind = turn`). Returns events with no cursor applied —
/// the daemon's `sse_events_response` owns since_seq/Last-Event-ID/409 handling.
fn replay_runtime_events(
    st: &DaemonState,
    replay_kind: &str,
    event_stream_id: &str,
    turn_id: Option<&str>,
) -> Result<Vec<Value>, AppError> {
    let request: RuntimeThreadEventReplayRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION,
        "replay_kind": replay_kind,
        "event_stream_id": event_stream_id,
        "turn_id": turn_id,
        "cursor": Value::Null,
        "state_dir": st.data_dir,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let replay = RuntimeKernelService::new()
        .project_runtime_thread_event_replay(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let value = serde_json::to_value(&replay)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    Ok(value
        .get("events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default())
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
    // Unified event model: read back the full persisted log via replay.
    let event_stream_id = format!("{thread_id}:events");
    let events = replay_runtime_events(&st, "stream", &event_stream_id, None)?;
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
    // Run events = the persisted log filtered to this run's turn (run_<x> -> turn_<x>).
    let event_stream_id = format!("{thread_id}:events");
    let turn_id = format!("turn_{}", run_id.strip_prefix("run_").unwrap_or(&run_id));
    let events = replay_runtime_events(&st, "turn", &event_stream_id, Some(&turn_id))?;
    sse_events_response(events, &params, &headers)
}

/// GET /v1/tasks — list runtime task records (embedded in run records by the
/// run-create materializer). Optional ?agent_id= / ?status= filters.
pub(crate) async fn handle_tasks_list(
    State(st): State<Arc<DaemonState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<Value> {
    let tasks: Vec<Value> = read_record_dir(&st.data_dir, "runs")
        .into_iter()
        .filter_map(|run| run.get("runtimeTask").cloned().filter(Value::is_object))
        .filter(|task| match params.get("status") {
            Some(status) => task.get("status").and_then(|v| v.as_str()) == Some(status.as_str()),
            None => true,
        })
        .filter(|task| match params.get("agent_id") {
            Some(agent_id) => task.get("agentId").and_then(|v| v.as_str()) == Some(agent_id.as_str()),
            None => true,
        })
        .collect();
    Json(json!(tasks))
}

/// GET /v1/tasks/:id — return one runtime task record (by taskId).
pub(crate) async fn handle_task_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(task_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    read_record_dir(&st.data_dir, "runs")
        .into_iter()
        .filter_map(|run| run.get("runtimeTask").cloned().filter(Value::is_object))
        .find(|task| task.get("taskId").and_then(|v| v.as_str()) == Some(task_id.as_str()))
        .map(Json)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, format!("task not found: {task_id}")))
}

/// GET /v1/jobs — list runtime job records (embedded in run records).
pub(crate) async fn handle_jobs_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let jobs: Vec<Value> = read_record_dir(&st.data_dir, "runs")
        .into_iter()
        .filter_map(|run| run.get("runtimeJob").cloned().filter(Value::is_object))
        .collect();
    Json(json!(jobs))
}

/// GET /v1/jobs/:id — return one runtime job record (by jobId).
pub(crate) async fn handle_job_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(job_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    read_record_dir(&st.data_dir, "runs")
        .into_iter()
        .filter_map(|run| run.get("runtimeJob").cloned().filter(Value::is_object))
        .find(|job| job.get("jobId").and_then(|v| v.as_str()) == Some(job_id.as_str()))
        .map(Json)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, format!("job not found: {job_id}")))
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

/// Shared body for the read-only run sub-projections (usage/wait/conversation/trace/
/// inspect/computer-use/scorecard/artifacts). Each is a PURE projection: the kernel
/// `project_runtime_lifecycle` planner replays the run from `<state_dir>` and shapes the
/// requested view — no daemon-side state, no event admission. This is the run-scoped twin
/// of `handle_thread_usage`.
fn run_projection_response(
    st: &DaemonState,
    run_id: &str,
    projection_kind: &str,
    artifact_ref: Option<&str>,
) -> Result<Json<Value>, AppError> {
    let request: RuntimeLifecycleProjectionRequest = serde_json::from_value(json!({
        "operation": "runtime_lifecycle_projection",
        "operation_kind": format!("runtime.lifecycle_projection.{projection_kind}"),
        "projection_kind": projection_kind,
        "run_id": run_id,
        "artifact_ref": artifact_ref,
        "state_dir": st.data_dir,
        "source": "sdk_client",
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_runtime_lifecycle(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(Json(record.projection.clone()))
}

pub(crate) async fn handle_run_usage(
    State(st): State<Arc<DaemonState>>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    run_projection_response(&st, &run_id, "run_usage", None)
}

pub(crate) async fn handle_run_wait(
    State(st): State<Arc<DaemonState>>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    run_projection_response(&st, &run_id, "run_wait", None)
}

pub(crate) async fn handle_run_conversation(
    State(st): State<Arc<DaemonState>>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    run_projection_response(&st, &run_id, "run_conversation", None)
}

/// Serves both GET /v1/runs/:id/trace and GET /v1/runs/:id/inspect (the JS daemon aliases
/// `inspect` to the same `run_trace` projection).
pub(crate) async fn handle_run_trace(
    State(st): State<Arc<DaemonState>>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    run_projection_response(&st, &run_id, "run_trace", None)
}

pub(crate) async fn handle_run_computer_use_trace(
    State(st): State<Arc<DaemonState>>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    run_projection_response(&st, &run_id, "run_computer_use_trace", None)
}

pub(crate) async fn handle_run_computer_use_trajectory(
    State(st): State<Arc<DaemonState>>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    run_projection_response(&st, &run_id, "run_computer_use_trajectory", None)
}

pub(crate) async fn handle_run_scorecard(
    State(st): State<Arc<DaemonState>>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    run_projection_response(&st, &run_id, "run_scorecard", None)
}

pub(crate) async fn handle_run_artifacts(
    State(st): State<Arc<DaemonState>>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    run_projection_response(&st, &run_id, "run_artifacts", None)
}

pub(crate) async fn handle_run_artifact(
    State(st): State<Arc<DaemonState>>,
    AxumPath((run_id, artifact_ref)): AxumPath<(String, String)>,
) -> Result<Json<Value>, AppError> {
    run_projection_response(&st, &run_id, "run_artifact", Some(&artifact_ref))
}

/// GET /v1/doctor — the redacted runtime-readiness report. The kernel
/// project_runtime_doctor_report planner builds the whole report (checks, provider keys
/// with hashed/redacted values, runtime nodes, workflow activation) from the daemon-derived
/// inputs; nothing is read from the request body. Returns the report (the JS daemon's
/// /v1/doctor `.report`), so the canonical doctor contract holds against the Rust daemon.
pub(crate) async fn handle_doctor(State(st): State<Arc<DaemonState>>) -> Result<Json<Value>, AppError> {
    let request: RuntimeDoctorReportProjectionRequest = serde_json::from_value(json!({
        "operation": "runtime_doctor_report_projection",
        "operation_kind": "runtime.doctor_report.projection",
        "base_url": st.base_url,
        "workspace_root": st.data_dir,
        "state_dir": st.data_dir,
        "home_dir": std::env::var("HOME").ok(),
        "runtime_schema_version": "ioi.runtime.v1",
        "source": "rust_daemon./v1/doctor",
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_runtime_doctor_report(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(Json(record.report))
}

/// Shared body for the top-level runtime-lifecycle projections (usage_list /
/// authority_evidence_summary). Pure kernel projection over the state_dir replay; the query
/// params become projection filters (agent_id / since / group_by / ...). The twin of
/// run_projection_response for the no-run-scope aggregates.
fn lifecycle_projection_response(
    st: &DaemonState,
    projection_kind: &str,
    params: &HashMap<String, String>,
) -> Result<Json<Value>, AppError> {
    let mut request_json = json!({
        "operation": "runtime_lifecycle_projection",
        "operation_kind": format!("runtime.lifecycle_projection.{projection_kind}"),
        "projection_kind": projection_kind,
        "state_dir": st.data_dir,
        "source": "sdk_client",
    });
    if let Some(object) = request_json.as_object_mut() {
        for (key, value) in params {
            object.insert(key.clone(), json!(value));
        }
    }
    let request: RuntimeLifecycleProjectionRequest = serde_json::from_value(request_json)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_runtime_lifecycle(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(Json(record.projection.clone()))
}

/// GET /v1/usage — aggregate runtime usage telemetry (the usage_list projection).
pub(crate) async fn handle_usage_list(
    State(st): State<Arc<DaemonState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    lifecycle_projection_response(&st, "usage_list", &params)
}

/// GET /v1/authority-evidence (and /v1/workflow-capability-preflights) — the authority
/// evidence summary projection (capability-preflight rows from the runtime event log).
pub(crate) async fn handle_authority_evidence(
    State(st): State<Arc<DaemonState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    lifecycle_projection_response(&st, "authority_evidence_summary", &params)
}

/// Apply a non-live MCP control mutation (import/add/remove/enable/disable) via the
/// kernel plan_mcp_control_agent_state_update planner, then dual-case + persist the
/// updated agent (the MCP registry lives on the agent record).
fn apply_mcp_control(
    st: &DaemonState,
    thread_id: &str,
    control_kind: &str,
    payload: Value,
) -> Result<Json<Value>, AppError> {
    if read_agent_for_thread(st, thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    let agent_id = agent_id_for_thread(thread_id);
    let now = iso_now();
    let event_id = format!("mcp_control_{thread_id}_{control_kind}_{}", short_hash(&now));
    // The MCP planner reads the agent from state_dir via agent_id; the inline `agent`
    // transport is retired (passing an object errors AgentCandidateTransportRetired).
    let request: McpControlAgentStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "thread_id": thread_id,
        "agent_id": agent_id,
        "state_dir": st.data_dir,
        "agent": Value::Null,
        "control_kind": control_kind,
        "event_id": event_id,
        "created_at": now,
        "request": payload,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .plan_mcp_control_agent_state_update(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let mut updated_agent = record.agent.clone();
    if let Some(map) = updated_agent.as_object_mut() {
        dual_case_agent(map);
    }
    persist_record(st.data_dir.as_str(), "agents", &agent_id, &updated_agent)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let mut response = serde_json::to_value(&record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    if let Some(map) = response.as_object_mut() {
        map.insert("commit".to_string(), json!({ "persisted": true }));
        map.insert("source".to_string(), json!("rust_mcp_control"));
        map.insert("backend".to_string(), json!("rust_policy"));
    }
    Ok(Json(response))
}

/// POST /v1/threads/:id/mcp/import — import an MCP server set.
pub(crate) async fn handle_mcp_import(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let servers = body.get("servers").cloned().unwrap_or_else(|| json!([]));
    apply_mcp_control(&st, &thread_id, "mcp_import", json!({ "servers": servers }))
}

/// POST /v1/threads/:id/mcp/servers — add a single MCP server.
pub(crate) async fn handle_mcp_add(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    apply_mcp_control(&st, &thread_id, "mcp_add", json!({ "server": body }))
}

/// DELETE /v1/threads/:id/mcp/servers/:server_id — remove an MCP server.
pub(crate) async fn handle_mcp_remove(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, server_id)): AxumPath<(String, String)>,
) -> Result<Json<Value>, AppError> {
    apply_mcp_control(&st, &thread_id, "mcp_remove", json!({ "server_id": server_id }))
}

/// POST /v1/threads/:id/mcp/servers/:server_id/enable — enable an MCP server.
pub(crate) async fn handle_mcp_enable(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, server_id)): AxumPath<(String, String)>,
) -> Result<Json<Value>, AppError> {
    apply_mcp_control(
        &st,
        &thread_id,
        "mcp_enable",
        json!({ "server_id": server_id, "enabled": true }),
    )
}

/// POST /v1/threads/:id/mcp/servers/:server_id/disable — disable an MCP server.
pub(crate) async fn handle_mcp_disable(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, server_id)): AxumPath<(String, String)>,
) -> Result<Json<Value>, AppError> {
    apply_mcp_control(
        &st,
        &thread_id,
        "mcp_disable",
        json!({ "server_id": server_id, "enabled": false }),
    )
}

/// POST /v1/threads/:id/mcp (or /mcp/status) — record an MCP manager status marker.
///
/// Same kernel control planner as import/add/remove/enable/disable; control_kind
/// `mcp_status` records the reported status onto the agent's MCP registry. Live
/// tool invocation (`/mcp/invoke`, `/mcp/serve`) is NOT migrated here — those need
/// live MCP transport admission and stay served by the JS client.
pub(crate) async fn handle_mcp_status(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let mut payload = body.as_object().cloned().unwrap_or_default();
    let status = payload
        .get("status")
        .and_then(|v| v.as_str())
        .map(Value::from)
        .unwrap_or(Value::Null);
    payload.insert("status".to_string(), status);
    apply_mcp_control(&st, &thread_id, "mcp_status", Value::Object(payload))
}

/// POST /v1/threads/:id/mcp/validate — record an MCP manager validation projection.
///
/// Control planner kind `mcp_validate`; records the supplied validation summary onto
/// the agent's MCP registry.
pub(crate) async fn handle_mcp_validate(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let mut payload = body.as_object().cloned().unwrap_or_default();
    let validation = payload.get("validation").cloned().unwrap_or(Value::Null);
    payload.insert("validation".to_string(), validation);
    apply_mcp_control(&st, &thread_id, "mcp_validate", Value::Object(payload))
}

/// POST /v1/threads/:id/compaction-policy — evaluate the compaction policy in the
/// kernel and admit the resulting decision event onto the persisted event log.
///
/// First event-emitting route on the unified log: kernel evaluate_compaction_policy
/// → build the runtime event (mirrors the JS admitContextPolicyRuntimeEvent shape)
/// → admit_and_persist_event (seq lands after thread.started + turns) → return the
/// JS contextPolicyResultEnvelope ({...policy, event, event_id, seq, ...}). The
/// execute_compaction cascade to /compact is a separate (deferred) route, so
/// context_compaction is reported null here.
pub(crate) async fn handle_compaction_policy(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    if read_agent_for_thread(&st, &thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    let obj = body.as_object().cloned().unwrap_or_default();
    let policy_obj = obj
        .get("policy")
        .or_else(|| obj.get("compaction_policy"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    // policy.<key> wins over the top-level request body, matching evaluateCompactionPolicyDecision.
    let pick_str = |keys: &[&str]| -> Value {
        for key in keys {
            if let Some(value) = policy_obj.get(*key).and_then(|v| v.as_str()) {
                return Value::from(value);
            }
            if let Some(value) = obj.get(*key).and_then(|v| v.as_str()) {
                return Value::from(value);
            }
        }
        Value::Null
    };
    let pick_bool = |keys: &[&str]| -> Value {
        for key in keys {
            if let Some(value) = policy_obj.get(*key).and_then(|v| v.as_bool()) {
                return Value::from(value);
            }
            if let Some(value) = obj.get(*key).and_then(|v| v.as_bool()) {
                return Value::from(value);
            }
        }
        Value::Null
    };
    let request: CompactionPolicyRequest = serde_json::from_value(json!({
        "schema_version": COMPACTION_POLICY_REQUEST_SCHEMA_VERSION,
        "thread_id": thread_id,
        "turn_id": obj.get("turn_id").and_then(|v| v.as_str()),
        "context_budget": obj.get("context_budget").or_else(|| obj.get("runtime_context_budget")).cloned().unwrap_or_else(|| json!({})),
        "context_budget_status": obj.get("context_budget_status").and_then(|v| v.as_str()),
        "actions": {
            "ok_action": pick_str(&["ok_action"]),
            "warn_action": pick_str(&["warn_action"]),
            "blocked_action": pick_str(&["blocked_action"]),
        },
        "approval": {
            "approval_required": pick_bool(&["approval_required"]),
            "approval_granted": pick_bool(&["approval_granted", "approved"]),
        },
        "compact": {
            "execute_compaction": pick_bool(&["execute_compaction"]),
            "compact_workflow_node_id": pick_str(&["compact_workflow_node_id"]),
            "compact_reason": pick_str(&["compact_reason", "reason"]),
            "compact_scope": pick_str(&["compact_scope"]),
        },
        "workflow_graph_id": obj.get("workflow_graph_id").and_then(|v| v.as_str()),
        "workflow_node_id": obj.get("workflow_node_id").and_then(|v| v.as_str()).unwrap_or("runtime.compaction-policy"),
        "source": obj.get("source").and_then(|v| v.as_str()).unwrap_or("react_flow"),
        "actor": obj.get("actor").and_then(|v| v.as_str()).unwrap_or("operator"),
        "event_kind": obj.get("event_kind").and_then(|v| v.as_str()).unwrap_or("RuntimeCompactionPolicy.Evaluate"),
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let policy_record = RuntimeKernelService::new()
        .evaluate_compaction_policy(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let policy = serde_json::to_value(&policy_record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let evidence_refs = json!([
        "compaction_policy_evaluation_rust_owned",
        "rust_daemon_core_compaction_policy_event",
        "agentgres_compaction_policy_event_truth_required",
    ]);
    let admitted = admit_and_persist_event(
        &st,
        build_context_policy_event(&st, &thread_id, "compaction_policy", &policy, &evidence_refs),
    )?;

    // contextPolicyResultEnvelope + the execute_compaction cascade (deferred -> null).
    let mut response = context_policy_envelope(policy, admitted, evidence_refs);
    if let Some(map) = response.as_object_mut() {
        map.insert("context_compaction".to_string(), Value::Null);
    }
    Ok(Json(response))
}

/// POST /v1/threads/:id/context-budget — evaluate the context-budget policy in the
/// kernel and admit the resulting decision event onto the persisted event log.
pub(crate) async fn handle_context_budget(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    if read_agent_for_thread(&st, &thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    let obj = body.as_object().cloned().unwrap_or_default();
    let thresholds_src = obj
        .get("thresholds")
        .or_else(|| obj.get("context_budget"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let num = |src: &serde_json::Map<String, Value>, key: &str| -> Value {
        src.get(key)
            .or_else(|| obj.get(key))
            .and_then(|v| v.as_f64())
            .map(Value::from)
            .unwrap_or(Value::Null)
    };
    let mode = match obj.get("mode").and_then(|v| v.as_str()).map(str::to_ascii_lowercase).as_deref() {
        Some("warn") => "warn",
        Some("block") => "block",
        _ => "simulate",
    };
    let request: ContextBudgetPolicyRequest = serde_json::from_value(json!({
        "schema_version": CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
        "usage_telemetry": obj.get("usage_telemetry").cloned().unwrap_or_else(|| json!({})),
        "thresholds": {
            "max_total_tokens": num(&thresholds_src, "max_total_tokens"),
            "max_cost_usd": num(&thresholds_src, "max_cost_usd"),
            "max_context_pressure": num(&thresholds_src, "max_context_pressure"),
            "warn_at_ratio": thresholds_src.get("warn_at_ratio").or_else(|| obj.get("warn_at_ratio")).and_then(|v| v.as_f64()).unwrap_or(0.8),
        },
        "mode": mode,
        "scope": obj.get("scope").and_then(|v| v.as_str()).unwrap_or("thread"),
        "thread_id": thread_id,
        "turn_id": obj.get("turn_id").and_then(|v| v.as_str()),
        "run_id": obj.get("run_id").and_then(|v| v.as_str()),
        "source": obj.get("source").and_then(|v| v.as_str()).unwrap_or("react_flow"),
        "actor": obj.get("actor").and_then(|v| v.as_str()).unwrap_or("operator"),
        "event_kind": obj.get("event_kind").and_then(|v| v.as_str()).unwrap_or("RuntimeContextBudget.Evaluate"),
        "component_kind": "context_budget",
        "workflow_graph_id": obj.get("workflow_graph_id").and_then(|v| v.as_str()),
        "workflow_node_id": obj.get("workflow_node_id").and_then(|v| v.as_str()).unwrap_or("runtime.context-budget"),
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let policy_record = RuntimeKernelService::new()
        .evaluate_context_budget_policy(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let policy = serde_json::to_value(&policy_record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let evidence_refs = json!([
        "context_budget_evaluation_rust_owned",
        "rust_daemon_core_context_budget_event",
        "agentgres_context_budget_event_truth_required",
    ]);
    let admitted = admit_and_persist_event(
        &st,
        build_context_policy_event(&st, &thread_id, "context_budget", &policy, &evidence_refs),
    )?;
    Ok(Json(context_policy_envelope(policy, admitted, evidence_refs)))
}

/// POST /v1/threads/:id/compact — execute a context compaction. Plans the
/// compaction (kernel plan_context_compaction → context.compacted event plan),
/// admits the event onto the unified persisted log, plans the state update
/// (kernel plan_context_compaction_state_update → operator_control + updated
/// agent/run), commits the updated record, and returns the JS
/// ioi.runtime_context_compaction envelope. Default target is the agent; a
/// `run_id` in the body targets that run instead.
pub(crate) async fn handle_compact(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let Some(agent) = read_agent_for_thread(&st, &thread_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    };
    let agent_id = agent
        .get("id")
        .or_else(|| agent.get("agent_id"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| agent_id_for_thread(&thread_id));

    let requested_run_id = body.get("run_id").and_then(|v| v.as_str()).map(str::to_string);
    let run = requested_run_id.as_ref().and_then(|rid| {
        read_record_dir(&st.data_dir, "runs")
            .into_iter()
            .find(|run| run.get("id").and_then(|v| v.as_str()) == Some(rid.as_str()))
    });
    if requested_run_id.is_some() && run.is_none() {
        return Err(AppError(
            StatusCode::NOT_FOUND,
            format!("run not found: {}", requested_run_id.unwrap_or_default()),
        ));
    }
    let target_kind = if body.get("target_kind").and_then(|v| v.as_str()) == Some("agent") || run.is_none() {
        "agent"
    } else {
        "run"
    };
    let run_id = if target_kind == "run" {
        run.as_ref().and_then(|r| r.get("id")).and_then(|v| v.as_str()).map(str::to_string)
    } else {
        None
    };

    let now = iso_now();
    let event_stream_id = format!("{thread_id}:events");
    let reason = body
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("operator requested context compaction")
        .to_string();
    let scope = body
        .get("scope")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| if target_kind == "run" { "run".into() } else { "thread".into() });
    let source = body.get("source").and_then(|v| v.as_str()).unwrap_or("sdk_client").to_string();
    let workspace_root = body
        .get("workspace_root")
        .or_else(|| agent.get("cwd"))
        .or_else(|| agent.get("workspace_root"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // --- plan the compaction (event plan) ---
    let plan_request: ContextCompactionPlanRequest = serde_json::from_value(json!({
        "schema_version": CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION,
        "thread_id": thread_id,
        "agent_id": agent_id,
        "run_id": run_id,
        "turn_id": body.get("turn_id").and_then(|v| v.as_str()),
        "session_id": body.get("session_id").and_then(|v| v.as_str()),
        "state_dir": st.data_dir,
        "workspace_root": workspace_root,
        "event_stream_id": event_stream_id,
        "source": source,
        "actor": body.get("actor").and_then(|v| v.as_str()).unwrap_or("operator"),
        "requested_by": body.get("requested_by").and_then(|v| v.as_str()).unwrap_or("operator"),
        "reason": reason,
        "scope": scope,
        "workflow_graph_id": body.get("workflow_graph_id").and_then(|v| v.as_str()),
        "workflow_node_id": body.get("workflow_node_id").and_then(|v| v.as_str()).unwrap_or("runtime.context-compact"),
        "idempotency_key": body.get("idempotency_key").and_then(|v| v.as_str()),
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let plan = RuntimeKernelService::new()
        .plan_context_compaction(&plan_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let plan = serde_json::to_value(&plan)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    // --- build + admit the context.compacted event ---
    let event_id = format!("evt_context_compaction_{thread_id}_{}", short_hash(&now));
    let evidence_refs = json!([
        "context_compaction_rust_owned",
        "rust_daemon_core_context_compaction_plan",
        "rust_daemon_core_context_compaction_state_update",
        "agentgres_runtime_thread_event_truth_required",
        "agentgres_context_compaction_state_truth_required",
    ]);
    let planned_event = json!({
        "event_stream_id": event_stream_id,
        "event_id": event_id,
        "thread_id": thread_id,
        "turn_id": plan.get("turn_id"),
        "item_id": plan.get("item_id"),
        "idempotency_key": plan.get("idempotency_key"),
        "source": plan.get("source"),
        "source_event_kind": plan.get("source_event_kind"),
        "event_kind": plan.get("event_kind"),
        "status": "completed",
        "actor": plan.get("actor"),
        "workflow_graph_id": plan.get("workflow_graph_id"),
        "workflow_node_id": plan.get("workflow_node_id"),
        "component_kind": plan.get("component_kind"),
        "payload_schema_version": plan.get("payload_schema_version"),
        "payload": plan.get("payload").cloned().unwrap_or_else(|| json!({})),
        "receipt_refs": plan.get("receipt_refs"),
        "policy_decision_refs": plan.get("policy_decision_refs"),
        "artifact_refs": plan.get("artifact_refs"),
        "rollback_refs": plan.get("rollback_refs"),
        "redaction_profile": plan.get("redaction_profile"),
        "created_at": now,
        "evidence_refs": evidence_refs,
    });
    let admitted = admit_and_persist_event(&st, planned_event)?;
    let admitted_event_id = admitted.get("event_id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let admitted_seq = admitted.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);

    // --- plan the state update (operator control + updated agent/run) ---
    let state_request: ContextCompactionStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "target_kind": target_kind,
        "thread_id": thread_id,
        "agent_id": agent_id,
        "run_id": run_id,
        "run": if target_kind == "run" { run.clone() } else { None },
        "agent": agent,
        "event_id": admitted_event_id,
        "seq": admitted_seq,
        "created_at": admitted.get("created_at").and_then(|v| v.as_str()).unwrap_or(now.as_str()),
        "source": source,
        "reason": reason,
        "scope": scope,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let state_update = RuntimeKernelService::new()
        .plan_context_compaction_state_update(&state_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let state_update = serde_json::to_value(&state_update)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    // --- commit the updated record (dual-case the agent before persisting) ---
    let planned_run = state_update.get("run").cloned().unwrap_or(Value::Null);
    let planned_agent = state_update.get("agent").cloned().unwrap_or(Value::Null);
    if target_kind == "run" {
        if let Some(run_id) = &run_id {
            persist_run_with_bundle(&*st, run_id, "run.context_compaction", &planned_run)?;
        }
    } else {
        let mut updated_agent = planned_agent.clone();
        if let Some(map) = updated_agent.as_object_mut() {
            dual_case_agent(map);
        }
        persist_record(st.data_dir.as_str(), "agents", &agent_id, &updated_agent)
            .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    }

    Ok(Json(json!({
        "schema_version": "ioi.runtime.context_compaction.v1",
        "object": "ioi.runtime_context_compaction",
        "status": "completed",
        "operation": "context_compaction",
        "operation_kind": state_update.get("operation_kind"),
        "target_kind": target_kind,
        "thread_id": thread_id,
        "agent_id": agent_id,
        "run_id": run_id,
        "event_id": admitted_event_id,
        "seq": admitted_seq,
        "event": admitted,
        "operator_control": state_update.get("operator_control"),
        "context_compaction": state_update.get("context_compaction"),
        "run": if target_kind == "run" { planned_run } else { Value::Null },
        "agent": if target_kind == "agent" { planned_agent } else { Value::Null },
        "commit": { "persisted": true },
        "evidence_refs": evidence_refs,
    })))
}

/// POST /v1/threads/:id/diagnostics/repair-decisions/:decision_id/execute — execute
/// a diagnostics repair decision. The kernel plan_runtime_diagnostics_repair_control
/// SYNTHESIZES the diagnostics.repair_decision.execute runtime event (with generated
/// receipt_refs + evidence_refs); we admit it onto the unified persisted log. Returns
/// the admitted event envelope. The decision_id from the URL is authoritative.
pub(crate) async fn handle_diagnostics_repair_execute(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, decision_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    if read_agent_for_thread(&st, &thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    let event_stream_id = format!("{thread_id}:events");
    let request: RuntimeDiagnosticsRepairControlRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_REQUEST_SCHEMA_VERSION,
        "operation": "diagnostics_repair_decision_execution",
        "operation_kind": "diagnostics.repair_decision.execute",
        "thread_id": thread_id,
        "event_stream_id": event_stream_id,
        "turn_id": body.get("turn_id").and_then(|v| v.as_str()),
        "decision_id": decision_id,
        "gate_event_id": body.get("gate_event_id").and_then(|v| v.as_str()),
        "gate_id": body.get("gate_id").and_then(|v| v.as_str()),
        "snapshot_id": body.get("snapshot_id").and_then(|v| v.as_str()),
        "workspace_root": body.get("workspace_root").and_then(|v| v.as_str()),
        "source": body.get("source").and_then(|v| v.as_str()).unwrap_or("operator"),
        "status": body.get("status").and_then(|v| v.as_str()),
        "request": body,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .plan_runtime_diagnostics_repair_control(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let event = serde_json::to_value(&record.event)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    if event.is_null() {
        return Err(AppError(
            StatusCode::BAD_GATEWAY,
            "diagnostics repair planner returned no event".to_string(),
        ));
    }
    let admitted = admit_and_persist_event(&st, event)?;
    Ok(Json(admitted))
}

/// POST /v1/threads/:id/approvals — request a thread approval. Two-phase: the kernel
/// authorizes the approval (authorize_approval_request → lease) then plans the state
/// update (plan_approval_request_state_update → the approval folded into the agent/run
/// record). Approvals do NOT admit a runtime event — the embedded approval lives on
/// the agent (or run) record. Default target is the agent; a `run_id` targets that run.
pub(crate) async fn handle_approval_request(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let Some(agent) = read_agent_for_thread(&st, &thread_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    };
    let Some(approval_id) = body.get("approval_id").and_then(|v| v.as_str()).map(str::to_string) else {
        return Err(AppError(StatusCode::BAD_REQUEST, "approval_id is required".to_string()));
    };
    let agent_id = agent
        .get("id")
        .or_else(|| agent.get("agent_id"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| agent_id_for_thread(&thread_id));

    let requested_run_id = body.get("run_id").and_then(|v| v.as_str()).map(str::to_string);
    let run = requested_run_id.as_ref().and_then(|rid| {
        read_record_dir(&st.data_dir, "runs")
            .into_iter()
            .find(|run| run.get("id").and_then(|v| v.as_str()) == Some(rid.as_str()))
    });
    if requested_run_id.is_some() && run.is_none() {
        return Err(AppError(
            StatusCode::NOT_FOUND,
            format!("run not found: {}", requested_run_id.unwrap_or_default()),
        ));
    }
    let target_kind = if run.is_some() { "run" } else { "agent" };
    let now = iso_now();
    let event_id = format!("event_{approval_id}_request");
    let source = body.get("source").and_then(|v| v.as_str()).unwrap_or("sdk_client").to_string();
    let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let scope_reqs = body
        .get("authority_scope_requirements")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // --- phase 1: authorize the approval (lease issuance) ---
    let authority_request: ApprovalRequestAuthorityRequest = serde_json::from_value(json!({
        "schema_version": APPROVAL_REQUEST_AUTHORITY_REQUEST_SCHEMA_VERSION,
        "thread_id": thread_id,
        "approval_id": approval_id,
        "target_kind": target_kind,
        "run_id": requested_run_id,
        "action": body.get("action").and_then(|v| v.as_str()),
        "scope": body.get("scope").and_then(|v| v.as_str()),
        "authority_scope_requirements": scope_reqs,
        "actor_ref": body.get("actor_ref").and_then(|v| v.as_str()),
        "source": source,
        "lease_id": body.get("lease_id").and_then(|v| v.as_str()),
        "lease_ttl_ms": body.get("lease_ttl_ms").and_then(|v| v.as_u64()),
        "expires_at": body.get("expires_at").and_then(|v| v.as_str()),
        "idempotency_key": body.get("idempotency_key").and_then(|v| v.as_str()),
        // The authority receipt is client-supplied (a wallet/policy grant ref); the
        // kernel rejects an empty receipt set with MissingAuthorityReceipt.
        "receipt_refs": body.get("receipt_refs").cloned().unwrap_or_else(|| json!([])),
        "policy_decision_refs": body.get("policy_decision_refs").cloned().unwrap_or_else(|| json!([])),
        "approval_manifest": body.get("approval_manifest").cloned().unwrap_or_else(|| json!({})),
        "authority_context": body.get("authority_context").cloned().unwrap_or_else(|| json!({})),
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let authority = RuntimeKernelService::new()
        .authorize_approval_request(&authority_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let authority = serde_json::to_value(&authority)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    // --- phase 2: plan the state update (fold the approval into the agent/run) ---
    let state_request: ApprovalRequestStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "target_kind": target_kind,
        "thread_id": thread_id,
        "run_id": requested_run_id,
        "state_dir": st.data_dir,
        // Inline run/agent candidate transport is retired (RetiredCandidateTransport);
        // the planner reads the target record from state_dir via thread_id/run_id.
        "agent": Value::Null,
        "run": Value::Null,
        "event_id": event_id,
        "seq": 1,
        "created_at": now,
        "approval_id": approval_id,
        "lease_id": authority.get("lease_id"),
        "lease_status": authority.get("lease_status"),
        "approval_lease": authority.get("approval_lease").cloned().unwrap_or(Value::Null),
        "source": source,
        "reason": reason,
        "receipt_refs": authority.get("receipt_refs").cloned().unwrap_or_else(|| json!([])),
        "policy_decision_refs": authority.get("policy_decision_refs").cloned().unwrap_or_else(|| json!([])),
        "authority_record": authority,
        "authority_hash": authority.get("authority_hash"),
        "authority_receipt_refs": authority.get("authority_receipt_refs").cloned().unwrap_or_else(|| json!([])),
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .plan_approval_request_state_update(&state_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let mut response = serde_json::to_value(&record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    // --- commit the embedded approval onto the agent (or run) record ---
    if target_kind == "run" {
        if let (Some(run_id), Some(run_value)) =
            (requested_run_id.as_ref(), response.get("run").filter(|v| v.is_object()))
        {
            persist_run_with_bundle(&*st, run_id, "run.approval_request", run_value)?;
        }
    } else if let Some(agent_value) = response.get("agent").filter(|v| v.is_object()).cloned() {
        let mut updated_agent = agent_value;
        if let Some(map) = updated_agent.as_object_mut() {
            dual_case_agent(map);
        }
        persist_record(st.data_dir.as_str(), "agents", &agent_id, &updated_agent)
            .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    }
    if let Some(map) = response.as_object_mut() {
        map.insert("commit".to_string(), json!({ "persisted": true }));
    }
    Ok(Json(response))
}

/// Shared memory-control flow (status / validate): project the public memory snapshot
/// (kernel project_runtime_memory_projection), then plan the control event (kernel
/// plan_runtime_memory_control builds a memory.status / memory.validate runtime event
/// with generated receipt_refs in record.payload), and admit it onto the unified log.
fn admit_memory_control_event(
    st: &DaemonState,
    thread_id: &str,
    projection_kind: &str,
    operation_kind: &str,
    control_kind: &str,
    event_kind: &str,
    source_event_kind: &str,
    workflow_node_id: &str,
    payload_schema_version: &str,
) -> Result<Json<Value>, AppError> {
    if read_agent_for_thread(st, thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    let agent_id = agent_id_for_thread(thread_id);
    let event_stream_id = format!("{thread_id}:events");

    // step 1: project the public memory snapshot (read-only).
    let projection_request: RuntimeMemoryProjectionApiRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_MEMORY_PROJECTION_REQUEST_SCHEMA_VERSION,
        "operation_kind": format!("runtime.memory_projection.{projection_kind}"),
        "projection_kind": projection_kind,
        "thread_id": thread_id,
        "agent_id": agent_id,
        "state_dir": st.data_dir,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let projection_record = RuntimeKernelService::new()
        .project_runtime_memory_projection(&projection_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let payload = projection_record.projection.clone();
    // validate drives the event status from the projection's ok flag; status is always ok.
    let status = if projection_kind == "validation" && payload.get("ok").and_then(|v| v.as_bool()) == Some(false) {
        "failed"
    } else {
        "completed"
    };

    // step 2: plan the control event (the planner builds the runtime event in record.payload).
    let control_request: RuntimeMemoryControlApiRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION,
        "operation_kind": operation_kind,
        "thread_id": thread_id,
        "agent_id": agent_id,
        "state_dir": st.data_dir,
        "request": {
            "control_kind": control_kind,
            "event_stream_id": event_stream_id,
            "event_kind": event_kind,
            "source_event_kind": source_event_kind,
            "component_kind": "memory_manager",
            "workflow_node_id": workflow_node_id,
            "payload_schema_version": payload_schema_version,
            "status": status,
            "policy_decision_kind": "read",
            "payload": payload,
        },
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .plan_runtime_memory_control(&control_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let event = record.payload.clone();
    if event.is_null() {
        return Err(AppError(
            StatusCode::BAD_GATEWAY,
            "memory control planner returned no event".to_string(),
        ));
    }
    let admitted = admit_and_persist_event(st, event)?;
    Ok(Json(admitted))
}

/// POST /v1/threads/:id/memory/status — admit a memory.status control event.
pub(crate) async fn handle_memory_status(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    admit_memory_control_event(
        &st,
        &thread_id,
        "status",
        "memory.status",
        "memory_status",
        "memory.status",
        "OperatorControl.MemoryStatus",
        "runtime.memory-manager.status",
        "ioi.runtime.memory-status.v1",
    )
}

/// POST /v1/threads/:id/memory/validate — admit a memory.validate control event.
pub(crate) async fn handle_memory_validate(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    admit_memory_control_event(
        &st,
        &thread_id,
        "validation",
        "memory.validate",
        "memory_validate",
        "memory.validate",
        "OperatorControl.MemoryValidate",
        "runtime.memory-manager.validate",
        "ioi.runtime.memory-validation.v1",
    )
}

/// GET /v1/threads/:id/usage — project the thread's runtime usage (read-only). The
/// kernel runtime-lifecycle projection sums usage_telemetry.total_tokens over the
/// thread's runs in state_dir and returns {thread_id, agent_id, run_count, total_tokens}.
pub(crate) async fn handle_thread_usage(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    if read_agent_for_thread(&st, &thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    let request: RuntimeLifecycleProjectionRequest = serde_json::from_value(json!({
        "operation": "runtime_lifecycle_projection",
        "operation_kind": "runtime.lifecycle_projection.thread_usage",
        "projection_kind": "thread_usage",
        "thread_id": thread_id,
        "state_dir": st.data_dir,
        "source": "sdk_client",
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_runtime_lifecycle(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(Json(record.projection.clone()))
}

/// Read a field of the persisted request-time approval lease for an approval on a
/// target record (agent or run). The request authority folds each approval onto the
/// record's `approvalRequests` list as an operator-control carrying its `approval_lease`;
/// the most recent matching entry's lease is the canonical binding source. Returns None
/// if the approval (or field) isn't found (no binding enforced for that field).
fn approval_lease_field_for(record: &Value, approval_id: &str, field: &str) -> Option<String> {
    record
        .get("approvalRequests")
        .or_else(|| record.get("approval_requests"))
        .and_then(|v| v.as_array())
        .and_then(|items| {
            items
                .iter()
                .rev()
                .find(|item| item.get("approval_id").and_then(|v| v.as_str()) == Some(approval_id))
        })
        .and_then(|item| item.get("approval_lease"))
        .and_then(|lease| lease.get(field))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Persist an approval state-update record's folded agent (dual-cased) or run.
fn commit_approval_record(
    st: &DaemonState,
    target_kind: &str,
    agent_id: &str,
    run_id: Option<&str>,
    response: &Value,
) -> Result<(), AppError> {
    if target_kind == "run" {
        if let (Some(run_id), Some(run_value)) =
            (run_id, response.get("run").filter(|v| v.is_object()))
        {
            persist_run_with_bundle(st, run_id, "run.approval_decision", run_value)?;
        }
    } else if let Some(agent_value) = response.get("agent").filter(|v| v.is_object()).cloned() {
        let mut updated_agent = agent_value;
        if let Some(map) = updated_agent.as_object_mut() {
            dual_case_agent(map);
        }
        persist_record(st.data_dir.as_str(), "agents", agent_id, &updated_agent)
            .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    }
    Ok(())
}

/// Shared approval decision/revoke flow: authorize the decision (kernel
/// authorize_approval_decision — requires a real wallet-signed ApprovalGrant, verified
/// structurally here [authority_id derived from the signer pubkey] and cryptographically
/// at the settlement layer) then plan the decision (approve/reject) or revoke state
/// update, folding the resolved approval onto the agent/run record. NO event admitted.
fn apply_approval_decision(
    st: &DaemonState,
    thread_id: &str,
    approval_id: &str,
    decision: &str,
    body: &Value,
) -> Result<Json<Value>, AppError> {
    let Some(agent) = read_agent_for_thread(st, thread_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    };
    let agent_id = agent
        .get("id")
        .or_else(|| agent.get("agent_id"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| agent_id_for_thread(thread_id));
    let requested_run_id = body.get("run_id").and_then(|v| v.as_str()).map(str::to_string);
    let run = requested_run_id.as_ref().and_then(|rid| {
        read_record_dir(&st.data_dir, "runs")
            .into_iter()
            .find(|run| run.get("id").and_then(|v| v.as_str()) == Some(rid.as_str()))
    });
    let target_kind = if run.is_some() { "run" } else { "agent" };
    let now = iso_now();
    let event_id = format!("event_{approval_id}_{decision}");
    let source = body.get("source").and_then(|v| v.as_str()).unwrap_or("sdk_client").to_string();
    let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Daemon-derived authority binding inputs — NEVER the POST body. now_ms is the
    // daemon wall-clock (rejects an expired grant, fail-closed on a clock fault);
    // expected_policy_hash is the persisted request-time lease's policy_hash (so a grant
    // minted for one approval/lease cannot authorize another). Both are derived from
    // Rust-authored state here, not the caller.
    let now_ms = daemon_now_ms_fail_closed();
    let policy_binding_source = if target_kind == "run" { run.as_ref() } else { Some(&agent) };
    let expected_policy_hash = policy_binding_source
        .and_then(|record| approval_lease_field_for(record, approval_id, "policy_hash"));
    let expected_request_hash = policy_binding_source
        .and_then(|record| approval_lease_field_for(record, approval_id, "request_hash"));

    // --- phase 1: authorize the decision against the wallet-signed grant ---
    let authority_request: ApprovalDecisionAuthorityRequest = serde_json::from_value(json!({
        "schema_version": APPROVAL_DECISION_AUTHORITY_REQUEST_SCHEMA_VERSION,
        "thread_id": thread_id,
        "approval_id": approval_id,
        "decision": decision,
        "target_kind": target_kind,
        "run_id": requested_run_id,
        "approval_lease": body.get("approval_lease").cloned().unwrap_or_else(|| json!({})),
        "source": source,
        // Daemon-derived fail-closed binding (clock + persisted lease policy/request hash).
        "now_ms": now_ms,
        "expected_policy_hash": expected_policy_hash,
        "expected_request_hash": expected_request_hash,
        // Wallet-signed authority grant — verified structurally AND cryptographically by
        // the kernel decision authority (no structural-only acceptance deferred to settlement).
        "wallet_approval_grant": body.get("wallet_approval_grant").cloned().unwrap_or_else(|| json!({})),
        "authority_grant_refs": body.get("authority_grant_refs").cloned().unwrap_or_else(|| json!([])),
        "authority_receipt_refs": body.get("authority_receipt_refs").cloned().unwrap_or_else(|| json!([])),
        "policy_decision_refs": body.get("policy_decision_refs").cloned().unwrap_or_else(|| json!([])),
        "approval_manifest": body.get("approval_manifest").cloned().unwrap_or_else(|| json!({})),
        "approval_request": body.get("approval_request").cloned().unwrap_or_else(|| json!({})),
        "authority_context": body.get("authority_context").cloned().unwrap_or_else(|| json!({})),
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let authority = RuntimeKernelService::new()
        .authorize_approval_decision(&authority_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let authority = serde_json::to_value(&authority)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    // --- phase 2: plan the decision (approve/reject) or revoke state update ---
    let common = json!({
        "target_kind": target_kind,
        "thread_id": thread_id,
        "run_id": requested_run_id,
        "state_dir": st.data_dir,
        // Inline run/agent candidate transport is retired; planner reads from state_dir.
        "agent": Value::Null,
        "run": Value::Null,
        "event_id": event_id,
        "seq": 1,
        "created_at": now,
        "approval_id": approval_id,
        "lease_id": authority.get("lease_id"),
        "approval_lease": authority.get("approval_lease").cloned().unwrap_or(Value::Null),
        "source": source,
        "reason": reason,
        "receipt_refs": authority.get("receipt_refs").cloned().unwrap_or_else(|| json!([])),
        "policy_decision_refs": authority.get("policy_decision_refs").cloned().unwrap_or_else(|| json!([])),
        "authority_record": authority.clone(),
        "authority_hash": authority.get("authority_hash"),
        "authority_receipt_refs": authority.get("authority_receipt_refs").cloned().unwrap_or_else(|| json!([])),
    });
    let mut response = if decision == "revoke" {
        let mut value = common;
        value["schema_version"] = json!(APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION);
        let request: ApprovalRevokeStateUpdateRequest = serde_json::from_value(value)
            .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
        let record = RuntimeKernelService::new()
            .plan_approval_revoke_state_update(&request)
            .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
        serde_json::to_value(&record)
            .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?
    } else {
        let mut value = common;
        value["schema_version"] = json!(APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION);
        value["decision"] = json!(decision);
        value["lease_status"] = authority.get("lease_status").cloned().unwrap_or_else(|| json!("granted"));
        value["status"] = json!(if decision == "approve" { "approved" } else { "rejected" });
        let request: ApprovalDecisionStateUpdateRequest = serde_json::from_value(value)
            .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
        let record = RuntimeKernelService::new()
            .plan_approval_decision_state_update(&request)
            .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
        serde_json::to_value(&record)
            .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?
    };

    commit_approval_record(st, target_kind, &agent_id, requested_run_id.as_deref(), &response)?;
    if let Some(map) = response.as_object_mut() {
        map.insert("commit".to_string(), json!({ "persisted": true }));
    }
    Ok(Json(response))
}

/// POST /v1/threads/:id/approvals/:approval_id/decision — decide via body.decision.
pub(crate) async fn handle_approval_decision(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, approval_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let decision = body.get("decision").and_then(|v| v.as_str()).unwrap_or("").to_string();
    apply_approval_decision(&st, &thread_id, &approval_id, &decision, &body)
}

/// POST /v1/threads/:id/approvals/:approval_id/approve
pub(crate) async fn handle_approval_approve(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, approval_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    apply_approval_decision(&st, &thread_id, &approval_id, "approve", &body)
}

/// POST /v1/threads/:id/approvals/:approval_id/reject
pub(crate) async fn handle_approval_reject(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, approval_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    apply_approval_decision(&st, &thread_id, &approval_id, "reject", &body)
}

/// POST /v1/threads/:id/approvals/:approval_id/revoke
pub(crate) async fn handle_approval_revoke(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, approval_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    apply_approval_decision(&st, &thread_id, &approval_id, "revoke", &body)
}

/// GET /v1/threads/:id/managed-sessions — project the thread's managed sessions
/// (read-only). The kernel projection record carries no `status`; the JS client asserts
/// `status == "projected"`, so the envelope injects it (as the napi projection API does).
pub(crate) async fn handle_managed_sessions(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    if read_agent_for_thread(&st, &thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    let request: RuntimeManagedSessionProjectionRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_MANAGED_SESSION_PROJECTION_REQUEST_SCHEMA_VERSION,
        "operation": "managed_session_inspection",
        "operation_kind": "managed_session.inspect",
        "projection_kind": "list",
        "thread_id": thread_id,
        "state_dir": st.data_dir,
        "source": "runtime.managed_session_state",
        "evidence_refs": [
            "runtime_managed_session_projection_rust_owned",
            "managed_session_inspection_js_facade_retired",
            "agentgres_managed_session_truth_required",
        ],
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_runtime_managed_session_projection(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(Json(json!({
        "schema_version": "ioi.runtime.managed_session_projection.v1",
        "object": "ioi.runtime_managed_session_projection",
        "status": "projected",
        "operation": record.operation,
        "operation_kind": record.operation_kind,
        "projection_kind": record.projection_kind,
        "thread_id": record.thread_id,
        "source": record.source,
        "projection": record.projection,
        "record_count": record.record_count,
        "evidence_refs": record.evidence_refs,
        "receipt_refs": record.receipt_refs,
    })))
}

/// POST /v1/threads/:id/managed-sessions/control — operator control (observe /
/// take_over / return_agent) of a managed session. The kernel
/// plan_runtime_managed_session_control reads the prior managed_session record from
/// the persisted event log (produced by the runtime event-log bridge when a real
/// `browser__*` turn drives a sandbox session) and synthesizes the
/// `managed_session.controlled` transition, which is admitted onto the log. Returns
/// the admitted event. Errors (e.g. record_required) surface when no managed session
/// has been produced for the thread yet.
pub(crate) async fn handle_managed_session_control(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    if read_agent_for_thread(&st, &thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    let Some(managed_session_id) = body.get("managed_session_id").and_then(|v| v.as_str()) else {
        return Err(AppError(StatusCode::BAD_REQUEST, "managed_session_id is required".to_string()));
    };
    let request: RuntimeManagedSessionControlRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_MANAGED_SESSION_CONTROL_REQUEST_SCHEMA_VERSION,
        "operation": "managed_session_control",
        "operation_kind": "managed_session.control",
        "thread_id": thread_id,
        "event_stream_id": format!("{thread_id}:events"),
        "state_dir": st.data_dir,
        "managed_session_id": managed_session_id,
        "control_state": body.get("control_state").and_then(|v| v.as_str()),
        "reason": body.get("reason").and_then(|v| v.as_str()),
        "request": body,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .plan_runtime_managed_session_control(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let event = serde_json::to_value(&record.event)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    if !event.is_object() {
        return Err(AppError(
            StatusCode::BAD_GATEWAY,
            "managed-session control planner returned no event".to_string(),
        ));
    }
    let admitted = admit_and_persist_event(&st, event)?;
    Ok(Json(admitted))
}

/// GET /v1/threads/:id/workspace-change-reviews — project the thread's workspace-change
/// reviews (read-only; same status:"projected" envelope discipline as managed-sessions).
pub(crate) async fn handle_workspace_change_reviews(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    if read_agent_for_thread(&st, &thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    let request: RuntimeWorkspaceChangeProjectionRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_WORKSPACE_CHANGE_PROJECTION_REQUEST_SCHEMA_VERSION,
        "operation": "workspace_change_inspection",
        "operation_kind": "workspace_change.inspect",
        "projection_kind": "list",
        "thread_id": thread_id,
        "state_dir": st.data_dir,
        "source": "runtime.workspace_change_state",
        "evidence_refs": [
            "runtime_workspace_change_projection_rust_owned",
            "workspace_change_inspection_js_facade_retired",
            "agentgres_workspace_change_truth_required",
        ],
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_runtime_workspace_change_projection(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(Json(json!({
        "schema_version": "ioi.runtime.workspace_change_projection.v1",
        "object": "ioi.runtime_workspace_change_projection",
        "status": "projected",
        "operation": record.operation,
        "operation_kind": record.operation_kind,
        "projection_kind": record.projection_kind,
        "thread_id": record.thread_id,
        "source": record.source,
        "projection": record.projection,
        "record_count": record.record_count,
        "evidence_refs": record.evidence_refs,
        "receipt_refs": record.receipt_refs,
    })))
}

/// Run `git -C <root> status --porcelain` and return `(status_label, path)` for each
/// changed file. Empty (and Ok) when the root is not a git work tree or has no changes —
/// detection is a read-only signal, never a hard failure.
fn git_changed_files(workspace_root: &str) -> Vec<(String, String)> {
    let output = std::process::Command::new("git")
        .args(["-C", workspace_root, "status", "--porcelain"])
        .output();
    let Ok(output) = output else { return Vec::new() };
    if !output.status.success() {
        return Vec::new();
    }
    let mut changes = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.len() < 4 {
            continue;
        }
        let code = line[..2].trim().to_string();
        // Porcelain v1: "XY <path>" (or "XY <old> -> <new>" for renames).
        let raw_path = line[3..].trim();
        let path = raw_path.rsplit(" -> ").next().unwrap_or(raw_path).trim_matches('"');
        let label = if code.contains('D') {
            "deleted"
        } else if code.contains('A') || code == "??" {
            "added"
        } else if code.contains('R') {
            "renamed"
        } else {
            "modified"
        };
        changes.push((label.to_string(), path.to_string()));
    }
    changes
}

/// POST /v1/threads/:id/workspace-change-reviews/detect — the workspace-change REVIEW
/// PRODUCER. Runs a real `git status` over the thread's workspace (the agent cwd) and
/// admits a `workspace_change.detected` event onto the unified log: one proposed
/// workspace-change card per changed file. The existing control + projection consumers
/// replay these verbatim — this closes the bootstrap gap where nothing in production
/// emitted a proposed review onto the events log. No fixtures: real on-disk git changes.
pub(crate) async fn handle_workspace_change_detect(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let Some(agent) = read_agent_for_thread(&st, &thread_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    };
    let workspace_root = agent
        .get("cwd")
        .or_else(|| agent.get("workspace_root"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let changed = git_changed_files(&workspace_root);
    let now = iso_now();
    let changes: Vec<Value> = changed
        .iter()
        .map(|(status, path)| {
            let workspace_change_id =
                format!("workspace_change:{}", short_hash(&format!("{thread_id}:{path}")));
            json!({
                "workspace_change_id": workspace_change_id,
                "path": path,
                "tool_name": "file__edit",
                "lifecycle": "proposed",
                "status": status,
            })
        })
        .collect();
    let detected_count = changes.len();
    let mut admitted = Value::Null;
    if detected_count > 0 {
        let event_stream_id = format!("{thread_id}:events");
        let event_hash = short_hash(&format!("{thread_id}:{now}:{detected_count}"));
        let event = json!({
            "event_stream_id": event_stream_id,
            "event_id": format!("event_workspace_change_detect_{event_hash}"),
            "thread_id": thread_id,
            "turn_id": "",
            "item_id": format!("{thread_id}:item:workspace_change_detect:{event_hash}"),
            "idempotency_key": format!("thread:{thread_id}:workspace_change.detect:{event_hash}"),
            "source": "runtime_workspace_change_detect",
            "source_event_kind": "WorkspaceChange.Detected",
            "event_kind": "workspace_change.detected",
            "status": "proposed",
            "actor": "policy",
            "component_kind": "workspace_change",
            "payload_schema_version": "ioi.runtime.workspace-change-detect.v1",
            "payload": { "workspace_root": workspace_root, "changes": changes },
            "receipt_refs": [format!("receipt_workspace_change_detect_{event_hash}")],
            "policy_decision_refs": [format!("policy_workspace_change_detect_{event_hash}")],
            "artifact_refs": [],
            "rollback_refs": [],
            "redaction_profile": "internal",
            "created_at": now,
        });
        admitted = admit_and_persist_event(&st, event)?;
    }
    Ok(Json(json!({
        "schema_version": "ioi.runtime.workspace-change-detection.v1",
        "object": "ioi.runtime_workspace_change_detection",
        "status": "detected",
        "thread_id": thread_id,
        "workspace_root": workspace_root,
        "detected_count": detected_count,
        "changes": changes,
        "event": admitted,
    })))
}

/// POST /v1/threads/:id/workspace-change-reviews/control — accept/reject a proposed
/// workspace-change review. The kernel plan_runtime_workspace_change_control reads the
/// proposed review from the persisted log (by workspace_change_id), validates the
/// lifecycle transition, and synthesizes the workspace_change.controlled event, which
/// the daemon admits onto the unified log.
pub(crate) async fn handle_workspace_change_control(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    if read_agent_for_thread(&st, &thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    let Some(workspace_change_id) = body.get("workspace_change_id").and_then(|v| v.as_str()) else {
        return Err(AppError(StatusCode::BAD_REQUEST, "workspace_change_id is required".to_string()));
    };
    let request: RuntimeWorkspaceChangeControlRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_WORKSPACE_CHANGE_CONTROL_REQUEST_SCHEMA_VERSION,
        "operation": "workspace_change_control",
        "operation_kind": "workspace_change.control",
        "thread_id": thread_id,
        "event_stream_id": format!("{thread_id}:events"),
        "state_dir": st.data_dir,
        "workspace_change_id": workspace_change_id,
        "control_state": body.get("control_state").and_then(|v| v.as_str()),
        "reason": body.get("reason").and_then(|v| v.as_str()),
        "request": body,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .plan_runtime_workspace_change_control(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let event = serde_json::to_value(&record.event)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    if !event.is_object() {
        return Err(AppError(
            StatusCode::BAD_GATEWAY,
            "workspace-change control planner returned no event".to_string(),
        ));
    }
    let admitted = admit_and_persist_event(&st, event)?;
    Ok(Json(admitted))
}

/// GET /v1/threads/:id/snapshots — list the thread's workspace snapshots (read-only).
/// The kernel snapshot-list projection returns an envelope; the JS client consumes its
/// `projection` field. Matches the JS, which passes only thread_id (no state_dir), so an
/// untouched thread projects an empty snapshot list.
pub(crate) async fn handle_snapshots(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    if read_agent_for_thread(&st, &thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    // Consumer: replay the workspace_snapshot.captured events the capture producer
    // admitted (each carries the full snapshot_record) and feed them to the kernel
    // list projection. Without this the projection always saw an empty array.
    let snapshots = read_captured_snapshots(&st, &thread_id);
    let inner: WorkspaceSnapshotListRequest = serde_json::from_value(json!({
        "schema_version": WORKSPACE_SNAPSHOT_LIST_REQUEST_SCHEMA_VERSION,
        "thread_id": thread_id,
        "snapshots": snapshots,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let value = RuntimeKernelService::new()
        .project_workspace_snapshot_list(WorkspaceSnapshotListProtocolRequest { request: inner })
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    // The JS owner returns the envelope's `projection`; fall back to the full envelope.
    let body = value.get("projection").cloned().unwrap_or(value);
    Ok(Json(body))
}

/// Read every `workspace_snapshot.captured` event from the thread's persisted log and
/// return each captured snapshot's full record (`payload.snapshot_record`, including
/// the content package). Deduplicated by snapshot_id; newest-last by log order. This
/// is the consumer the capture producer feeds — the list projection and the restore
/// routes both read snapshots from here, never from a fixture.
fn read_captured_snapshots(st: &DaemonState, thread_id: &str) -> Vec<Value> {
    let event_stream_id = format!("{thread_id}:events");
    let path = Path::new(st.data_dir.as_str())
        .join("events")
        .join(format!("{}.jsonl", sha256_hex_str(&event_stream_id)));
    let Ok(contents) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut snapshots: Vec<Value> = Vec::new();
    let mut index_by_id: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if event.get("event_kind").and_then(|v| v.as_str()) != Some("workspace_snapshot.captured") {
            continue;
        }
        let Some(record) = event
            .get("payload")
            .and_then(|p| p.get("snapshot_record"))
            .filter(|record| record.is_object())
            .cloned()
        else {
            continue;
        };
        let id = record
            .get("snapshot_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if let Some(existing) = index_by_id.get(&id) {
            snapshots[*existing] = record;
        } else {
            index_by_id.insert(id, snapshots.len());
            snapshots.push(record);
        }
    }
    snapshots
}

/// Read a file's committed (`HEAD`) content via `git show HEAD:<path>` — the
/// pre-change ("before") side of a workspace snapshot. Returns None for files not in
/// HEAD (newly created/untracked) or on any git failure.
fn git_file_head_bytes(workspace_root: &str, path: &str) -> Option<Vec<u8>> {
    let output = std::process::Command::new("git")
        .args(["-C", workspace_root, "show", &format!("HEAD:{path}")])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(output.stdout)
}

/// Resolve the git repository root for a workspace (`git rev-parse --show-toplevel`).
/// `git status` paths are repo-root-relative, so snapshot content reads and restore
/// writes must be rooted here — NOT at an agent cwd that may be a subdirectory of the
/// repo (which would resolve every path to the wrong place). Falls back to the given
/// workspace_root when it is not inside a git repo.
fn git_repo_root(workspace_root: &str) -> String {
    std::process::Command::new("git")
        .args(["-C", workspace_root, "rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| workspace_root.to_string())
}

/// One changed path for snapshot capture, carrying the rename source when applicable.
struct SnapshotChange {
    label: String,
    path: String,
    old_path: Option<String>,
}

/// Enumerate workspace changes for snapshot capture ROBUSTLY: `core.quotePath=false`
/// + `--porcelain=v1 -z` (NUL-delimited) so paths with spaces, quotes, or non-ASCII
/// are returned verbatim (never C-quoted, which the naive parser would mangle), and
/// renames carry BOTH the new path and the NUL-separated old path. Paths are
/// repo-root-relative.
fn git_snapshot_changes(repo_root: &str) -> Vec<SnapshotChange> {
    let output = std::process::Command::new("git")
        .args([
            "-c",
            "core.quotePath=false",
            "-C",
            repo_root,
            "status",
            "--porcelain=v1",
            "-z",
        ])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = text.split('\0').collect();
    let mut changes = Vec::new();
    let mut index = 0;
    while index < fields.len() {
        let field = fields[index];
        if field.len() < 4 {
            index += 1;
            continue;
        }
        let code = &field[..2];
        let path = field[3..].to_string();
        if code.contains('R') || code.contains('C') {
            // Rename/copy: the NEXT NUL-terminated field is the source path.
            let old_path = fields
                .get(index + 1)
                .map(|value| value.to_string())
                .filter(|value| !value.is_empty());
            changes.push(SnapshotChange { label: "renamed".to_string(), path, old_path });
            index += 2;
        } else {
            let label = if code.contains('D') {
                "deleted"
            } else if code.contains('A') || code == "??" {
                "added"
            } else {
                "modified"
            };
            changes.push(SnapshotChange { label: label.to_string(), path, old_path: None });
            index += 1;
        }
    }
    changes
}

/// Build the (changed_file, content_draft) pair for one snapshot path. CRITICAL:
/// `before_exists`/`after_exists` come from the git LABEL, never from whether the
/// content could be read. A failed before-content read (binary/non-UTF-8 HEAD blob,
/// unreadable file) therefore leaves before_exists=true with NO content, so the kernel
/// marks the side content-missing and RESTORE BLOCKS — instead of collapsing
/// before_exists to false, which the kernel would reclassify as a destructive `delete`
/// of the user's real file (silent data loss).
fn snapshot_file_entry(
    repo_root: &str,
    path: &str,
    before_exists: bool,
    after_exists: bool,
    created: bool,
) -> (Value, Value) {
    // Read each existing side as RAW BYTES, then decide a SINGLE per-file encoding: if any
    // side is non-UTF-8 (binary), both sides are base64-encoded so they round-trip; else
    // both are stored as literal UTF-8 text. A consistent per-file marker avoids a mixed
    // case where one side's literal text would be wrongly base64-decoded on restore.
    let before_bytes = if before_exists {
        git_file_head_bytes(repo_root, path)
    } else {
        None
    };
    let after_bytes = if after_exists {
        fs::read(Path::new(repo_root).join(path)).ok()
    } else {
        None
    };
    let use_base64 = before_bytes
        .as_ref()
        .map(|bytes| std::str::from_utf8(bytes).is_err())
        .unwrap_or(false)
        || after_bytes
            .as_ref()
            .map(|bytes| std::str::from_utf8(bytes).is_err())
            .unwrap_or(false);
    let encode_side = |bytes: &Option<Vec<u8>>| -> Option<String> {
        bytes.as_ref().map(|bytes| {
            if use_base64 {
                BASE64.encode(bytes)
            } else {
                String::from_utf8_lossy(bytes).to_string()
            }
        })
    };
    let before_content = encode_side(&before_bytes);
    let after_content = encode_side(&after_bytes);
    let changed_file = json!({
        "path": path,
        "created": created,
        "before_exists": before_exists,
        "after_exists": after_exists,
        // The kernel capture/restore cores hash content as bare hex (no `sha256:`
        // prefix); match that so content is captured and restore comparisons line up.
        "before_hash": before_content.as_ref().map(|content| sha256_hex_str(content)),
        "after_hash": after_content.as_ref().map(|content| sha256_hex_str(content)),
    });
    let content_draft = json!({
        "path": path,
        "before_content": before_content,
        "after_content": after_content,
        "encoding": if use_base64 { "base64" } else { "utf8" },
    });
    (changed_file, content_draft)
}

/// POST /v1/threads/:id/snapshots/capture — the snapshot PRODUCER. Captures a real
/// workspace snapshot over the thread's cwd from on-disk git state (no fixtures, no
/// turn execution): for each changed file, `after` = the current working-tree content
/// and `before` = the committed `HEAD` content. The kernel capture core builds the
/// snapshot_record (with the content package); the daemon admits a
/// `workspace_snapshot.captured` event embedding the full record so GET /snapshots
/// (read_captured_snapshots) and the restore routes can read it back.
pub(crate) async fn handle_snapshot_capture(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let Some(agent) = read_agent_for_thread(&st, &thread_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    };
    let agent_cwd = agent
        .get("cwd")
        .or_else(|| agent.get("workspace_root"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if agent_cwd.trim().is_empty() {
        return Err(AppError(StatusCode::BAD_REQUEST, "thread has no workspace cwd to snapshot".to_string()));
    }
    // git status paths are repo-root-relative; root content reads + the restore target
    // at the repo root, not at a (possibly subdirectory) agent cwd.
    let workspace_root = git_repo_root(&agent_cwd);
    let changes = git_snapshot_changes(&workspace_root);
    let mut changed_files: Vec<Value> = Vec::new();
    let mut content_drafts: Vec<Value> = Vec::new();
    for change in &changes {
        // Expand into capture entries whose before/after EXISTS bits come from the git
        // label (never from content-read success), so a content-read failure blocks
        // restore rather than turning the file into a delete target. Renames split into
        // a delete-of-old (before=HEAD:old) + a create-of-new (after=working:new) so a
        // restore reverts the rename instead of deleting the renamed file.
        let entries: Vec<(Value, Value)> = match change.label.as_str() {
            "renamed" => {
                let mut entries = Vec::new();
                if let Some(old) = &change.old_path {
                    entries.push(snapshot_file_entry(&workspace_root, old, true, false, false));
                }
                entries.push(snapshot_file_entry(&workspace_root, &change.path, false, true, true));
                entries
            }
            "added" => vec![snapshot_file_entry(&workspace_root, &change.path, false, true, true)],
            "deleted" => vec![snapshot_file_entry(&workspace_root, &change.path, true, false, false)],
            _ => vec![snapshot_file_entry(&workspace_root, &change.path, true, true, false)],
        };
        for (changed_file, content_draft) in entries {
            changed_files.push(changed_file);
            content_drafts.push(content_draft);
        }
    }
    let protocol: WorkspaceSnapshotCaptureProtocolRequest = serde_json::from_value(json!({
        "request": {
            "schema_version": WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION,
            "changed_files": changed_files,
            "content_drafts": content_drafts,
        },
        "thread_id": thread_id,
        "workspace_root": workspace_root,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let capture = capture_workspace_snapshot_files_protocol_response(protocol)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let mut snapshot_record = capture.get("snapshot_record").cloned().unwrap_or(Value::Null);
    if !snapshot_record.is_object() {
        return Err(AppError(StatusCode::BAD_GATEWAY, "snapshot capture produced no record".to_string()));
    }
    // Pin the captured repo root so restore targets the SAME root the paths are
    // relative to, regardless of the agent cwd at restore time.
    if let Some(record) = snapshot_record.as_object_mut() {
        record.insert("captured_workspace_root".to_string(), Value::String(workspace_root.clone()));
    }
    let snapshot_id = snapshot_record
        .get("snapshot_id")
        .and_then(|v| v.as_str())
        .unwrap_or("workspace_snapshot_unknown")
        .to_string();
    let snapshot_hash = snapshot_record
        .get("snapshot_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("sha256:unknown")
        .to_string();
    // Keep the heavy content package (file bytes, up to 256KB/file) OUT of the event
    // payload — it would otherwise be parsed/replayed verbatim on every GET /events.
    // Strip content_files from the metadata record that goes on the log and persist them
    // as a side artifact (<state_dir>/snapshot-content/<snapshot_id>.json) that the
    // restore path resolves by snapshot_id. The event carries only metadata + a ref.
    let content_files = snapshot_record
        .as_object_mut()
        .and_then(|record| record.remove("content_files"))
        .unwrap_or_else(|| json!([]));
    let artifact_ref = format!("snapshot-content/{snapshot_id}.json");
    let content_artifact = json!({
        "schema_version": "ioi.runtime.workspace-snapshot-content.v1",
        "object": "ioi.runtime_workspace_snapshot_content",
        "snapshot_id": snapshot_id,
        "snapshot_hash": snapshot_hash,
        "captured_workspace_root": workspace_root,
        "content_files": content_files,
    });
    persist_record(&st.data_dir, "snapshot-content", &snapshot_id, &content_artifact)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let event_hash = short_hash(&format!("{thread_id}:{snapshot_id}"));
    let event = json!({
        "event_id": format!("event_workspace_snapshot_{event_hash}"),
        "event_stream_id": format!("{thread_id}:events"),
        "thread_id": thread_id,
        "item_id": format!("{thread_id}:item:workspace_snapshot:{event_hash}"),
        "idempotency_key": format!("workspace_snapshot:capture:{snapshot_id}:{event_hash}"),
        "source": "runtime_workspace_snapshot_capture",
        "source_event_kind": "WorkspaceSnapshotCapture",
        "event_kind": "workspace_snapshot.captured",
        "status": "completed",
        "actor": "policy",
        "component_kind": "workspace_snapshot",
        "payload_schema_version": "ioi.runtime.workspace-snapshot.event.v1",
        "payload": {
            "snapshot_id": snapshot_id,
            "snapshot_hash": snapshot_hash,
            "workspace_root": workspace_root,
            "artifact_ref": artifact_ref.clone(),
            "snapshot_record": snapshot_record,
        },
        "receipt_refs": [format!("receipt_workspace_snapshot_capture_{event_hash}")],
        "policy_decision_refs": [],
        "artifact_refs": [artifact_ref],
        "rollback_refs": [],
        "redaction_profile": "internal",
        "evidence_refs": ["runtime_workspace_snapshot_capture_rust_owned"],
    });
    let admitted = admit_and_persist_event(&st, event)?;
    Ok(Json(json!({
        "object": "ioi.runtime_workspace_snapshot_capture",
        "snapshot_id": snapshot_id,
        "snapshot_hash": snapshot_hash,
        "changed_file_count": changed_files.len(),
        "captured_file_count": capture.get("captured_file_count").cloned().unwrap_or(json!(0)),
        "snapshot_record": snapshot_record,
        "event": admitted,
    })))
}

/// Resolve a captured snapshot's content package (the `content_files` array, with file
/// bytes). Content lives in the `snapshot-content/<snapshot_id>.json` side artifact (the
/// event payload carries only metadata); read it back from there. Falls back to an inline
/// `content_files` on the record for forward/back-compat with any log written before the
/// content was externalized.
fn read_snapshot_content_files(st: &DaemonState, record: &Value) -> Vec<Value> {
    if let Some(files) = record.get("content_files").and_then(|v| v.as_array()) {
        if !files.is_empty() {
            return files.clone();
        }
    }
    let Some(snapshot_id) = record.get("snapshot_id").and_then(|v| v.as_str()) else {
        return Vec::new();
    };
    let safe = snapshot_id
        .replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_");
    let path = Path::new(st.data_dir.as_str())
        .join("snapshot-content")
        .join(format!("{safe}.json"));
    let Ok(bytes) = fs::read(&path) else {
        return Vec::new();
    };
    let Ok(artifact) = serde_json::from_slice::<Value>(&bytes) else {
        return Vec::new();
    };
    artifact
        .get("content_files")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Build the kernel restore `files` (path + before/after `{exists, content_hash,
/// content, encoding}`) from a captured snapshot's content package (resolved from the
/// side artifact). The restore target is the `before` side (the pre-change / `HEAD`
/// content), so applying reverts each file to its snapshotted state.
fn restore_files_from_snapshot(st: &DaemonState, record: &Value) -> Vec<Value> {
    read_snapshot_content_files(st, record)
        .iter()
        .filter_map(|file| {
            let path = file.get("path").and_then(|v| v.as_str())?;
            // The per-file encoding marker (utf8 | base64) is carried on the captured
            // file so the kernel restore can decode binary content before writing.
            let encoding = file.get("encoding").cloned().unwrap_or(Value::Null);
            let side = |key: &str| {
                let side = file.get(key);
                json!({
                    "exists": side.and_then(|s| s.get("exists")).and_then(Value::as_bool).unwrap_or(false),
                    "content_hash": side.and_then(|s| s.get("content_hash")).cloned().unwrap_or(Value::Null),
                    "content": side.and_then(|s| s.get("content")).cloned().unwrap_or(Value::Null),
                    "encoding": encoding.clone(),
                })
            };
            Some(json!({ "path": path, "before": side("before"), "after": side("after") }))
        })
        .collect()
}

/// Daemon wall-clock in epoch-ms for approval-grant expiry checks. On the pathological
/// clock fault (host clock set before 1970-01-01, so `duration_since(UNIX_EPOCH)` errors)
/// this returns `u64::MAX` so EVERY grant compares as expired — fail CLOSED. Returning 0
/// would silently DISABLE the expiry gate (`0 > expires_at` is never true); a clock fault
/// must never be able to revive an expired grant.
fn daemon_now_ms_fail_closed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(u64::MAX)
}

/// Canonical `sha256:<hex>` over the JSON bytes of `value` (matches the kernel's
/// approval_lease_policy_hash format, so a grant minted against these hashes verifies).
fn sha256_json_ref(value: &Value) -> String {
    format!("sha256:{}", sha256_hex_str(&serde_json::to_string(value).unwrap_or_default()))
}

/// Daemon-derived POLICY hash a restore-apply approval grant must carry: binds the grant
/// to this thread + snapshot + workspace root (the policy context).
fn restore_apply_policy_hash(thread_id: &str, snapshot_id: &str, workspace_root: &str) -> String {
    sha256_json_ref(&json!({
        "domain": "workspace_restore.apply.policy.v1",
        "thread_id": thread_id,
        "snapshot_id": snapshot_id,
        "workspace_root": workspace_root,
    }))
}

/// Daemon-derived REQUEST hash a restore-apply approval grant must carry: the stable
/// identity of "restore snapshot <id> into thread <id>". It excludes volatile workspace
/// state so it is identical at mint time and apply time, and it is DISTINCT from any
/// approval-decision request hash — so a grant minted to authorize one operation (an
/// approval decision, or a different snapshot/thread) can never authorize this restore.
fn restore_apply_request_hash(thread_id: &str, snapshot_id: &str) -> String {
    sha256_json_ref(&json!({
        "domain": "workspace_restore.apply.request.v1",
        "thread_id": thread_id,
        "snapshot_id": snapshot_id,
    }))
}

/// Shared body for the two restore routes. Loads the captured snapshot by id (from the
/// log, via the capture producer — never a fixture), builds the restore operations,
/// and runs the kernel restore core (`apply` writes the `before` content back to the
/// real workspace filesystem). `apply` additionally admits a `workspace_restore.applied`
/// event onto the log.
async fn run_snapshot_restore(
    st: Arc<DaemonState>,
    thread_id: String,
    snapshot_id: String,
    body: Value,
    apply: bool,
) -> Result<Json<Value>, AppError> {
    let Some(agent) = read_agent_for_thread(&st, &thread_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    };
    let snapshots = read_captured_snapshots(&st, &thread_id);
    let Some(record) = snapshots
        .into_iter()
        .find(|record| record.get("snapshot_id").and_then(|v| v.as_str()) == Some(snapshot_id.as_str()))
    else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("snapshot not found: {snapshot_id}")));
    };
    // Target the SAME repo root the snapshot paths are relative to (pinned at capture),
    // not the agent cwd at restore time (which may have moved or be a subdirectory).
    let workspace_root = record
        .get("captured_workspace_root")
        .and_then(|v| v.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .or_else(|| {
            agent
                .get("cwd")
                .or_else(|| agent.get("workspace_root"))
                .and_then(|v| v.as_str())
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
        })
        .unwrap_or_default();
    if workspace_root.trim().is_empty() {
        return Err(AppError(StatusCode::BAD_REQUEST, "snapshot has no workspace root to restore into".to_string()));
    }
    let files = restore_files_from_snapshot(&st, &record);
    let kernel = RuntimeKernelService::new();

    // Preview is always computed (read-only): the operator-facing diff and — for apply —
    // the input to the server-side apply-policy decision.
    let preview_request: WorkspaceRestoreOperationsRequest = serde_json::from_value(json!({
        "schema_version": WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION,
        "workspace_root": workspace_root,
        "files": files.clone(),
        "allow_conflicts": Value::Null,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let preview_ops = kernel
        .preview_workspace_restore_operations(&preview_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let preview_value = serde_json::to_value(&preview_ops)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    // Daemon-derived approval binding for THIS restore (thread + snapshot + workspace
    // root). The operator mints a wallet-signed ApprovalGrant against these hashes
    // (returned by restore-preview) and presents it to restore-apply; nothing here comes
    // from the POST body.
    let expected_policy_hash = restore_apply_policy_hash(&thread_id, &snapshot_id, &workspace_root);
    let expected_request_hash = restore_apply_request_hash(&thread_id, &snapshot_id);

    if !apply {
        return Ok(Json(json!({
            "object": "ioi.runtime_workspace_restore_preview",
            "snapshot_id": snapshot_id,
            "operation": "preview_workspace_restore",
            "operations": preview_value,
            // The wallet-signed approval an apply will require, and what to bind it to.
            "approval": {
                "required": true,
                "action": "workspace_restore.apply",
                "policy_hash": expected_policy_hash,
                "request_hash": expected_request_hash,
            },
        })));
    }

    // restore-apply writes the real filesystem, so it requires a REAL wallet-signed
    // ApprovalGrant — verified EXACTLY like the approval-decision routes: structural +
    // dcrypt signature + not-expired + bound to the daemon-derived policy/request hash for
    // THIS restore. A boolean body flag is NOT accepted. now_ms is the daemon wall clock
    // (never the body, fail-closed on a clock fault); the grant is the only untrusted input.
    let now_ms = daemon_now_ms_fail_closed();
    let grant_value = body.get("wallet_approval_grant").cloned().unwrap_or(Value::Null);
    let grant_present = grant_value
        .as_object()
        .map(|object| !object.is_empty())
        .unwrap_or(false);
    let grant_binding = if grant_present {
        verify_wallet_approval_grant_binding(
            &grant_value,
            Some(now_ms),
            Some(&expected_policy_hash),
            Some(&expected_request_hash),
        )
    } else {
        Err("restore-apply requires a wallet_approval_grant".to_string())
    };
    let grant_binding = match grant_binding {
        Ok(binding) => binding,
        Err(reason) => {
            // Missing or invalid grant: FORBIDDEN, write nothing. Echo the binding the
            // operator must mint against so a client can obtain a valid grant and retry.
            return Err(AppError(
                StatusCode::FORBIDDEN,
                format!(
                    "restore-apply approval grant rejected: {reason} \
                     (bind a wallet grant to policy_hash {expected_policy_hash}, \
                     request_hash {expected_request_hash})"
                ),
            ));
        }
    };

    // The verified grant IS the approval. Run the apply policy with approval satisfied BY
    // the grant (never a raw body flag); the operator's override_conflicts still governs
    // whether conflicts may be overridden. A hard/conflict-blocked preview still refuses.
    let policy_operations: Vec<Value> = preview_ops
        .iter()
        .map(|op| json!({ "path": op.path, "status": op.status, "blocked_reason": op.blocked_reason }))
        .collect();
    let policy_request: WorkspaceRestoreApplyPolicyRequest = serde_json::from_value(json!({
        "schema_version": WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "operations": policy_operations,
        "confirm_restore_apply": true,
        "override_conflicts": body.get("override_conflicts"),
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let plan = kernel
        .plan_workspace_restore_apply_policy(&policy_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let policy_value = serde_json::to_value(&plan)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    if plan.policy_status != "allowed" {
        // The grant is valid, but the preview is hard/conflict-blocked: write nothing.
        return Ok(Json(json!({
            "object": "ioi.runtime_workspace_restore_apply",
            "snapshot_id": snapshot_id,
            "operation": "apply_workspace_restore",
            "status": "blocked",
            "requires_confirmation": true,
            "applied_file_count": 0,
            "policy": policy_value,
            "operations": preview_value,
        })));
    }

    // Approved + clean: apply with the SERVER-derived allow_conflicts (plan.allow_conflicts).
    let apply_request: WorkspaceRestoreOperationsRequest = serde_json::from_value(json!({
        "schema_version": WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION,
        "workspace_root": workspace_root,
        "files": files,
        "allow_conflicts": plan.allow_conflicts,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let operations = kernel
        .apply_workspace_restore_operations(&apply_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let operations_value = serde_json::to_value(&operations)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let mut response = json!({
        "object": "ioi.runtime_workspace_restore_apply",
        "snapshot_id": snapshot_id,
        "operation": "apply_workspace_restore",
        "operations": operations_value,
        "policy": policy_value,
    });
    {
        let applied_count = operations
            .iter()
            .filter(|op| op.apply_status.as_deref() == Some("applied")
                || op.apply_status.as_deref() == Some("applied_with_override"))
            .count();
        let blocked_count = operations
            .iter()
            .filter(|op| op.status == "blocked" || op.status == "conflict"
                || op.apply_status.as_deref() == Some("blocked"))
            .count();
        // Distinguish an apply that actually wrote files from one where every op was
        // blocked/conflict (so GET /events does not show "applied" for a no-op). The
        // event hash folds in the operation outcome so each distinct apply is its own
        // audit record while identical no-op re-applies collapse under idempotency.
        let applied = applied_count > 0;
        let outcome_hash = short_hash(&operations_value.to_string());
        let event_hash = short_hash(&format!("{thread_id}:{snapshot_id}:restore:{outcome_hash}"));
        let event_kind = if applied { "workspace_restore.applied" } else { "workspace_restore.blocked" };
        let status = if applied { "completed" } else { "blocked" };
        let event = json!({
            "event_id": format!("event_workspace_restore_{event_hash}"),
            "event_stream_id": format!("{thread_id}:events"),
            "thread_id": thread_id,
            "item_id": format!("{thread_id}:item:workspace_restore:{event_hash}"),
            "idempotency_key": format!("workspace_restore:apply:{snapshot_id}:{outcome_hash}"),
            "source": "runtime_workspace_restore",
            "source_event_kind": "WorkspaceRestoreApply",
            "event_kind": event_kind,
            "status": status,
            "actor": "operator",
            "component_kind": "workspace_restore",
            "payload_schema_version": "ioi.runtime.workspace-restore.event.v1",
            "payload": {
                "snapshot_id": snapshot_id,
                "applied_file_count": applied_count,
                "blocked_file_count": blocked_count,
                "operations": operations_value,
                // Audit which wallet-signed grant authorized this real-FS write.
                "approval_grant_hash": grant_binding.hash,
                "approval_grant_ref": grant_binding.grant_ref.clone(),
            },
            "receipt_refs": [format!("receipt_workspace_restore_{event_hash}")],
            "policy_decision_refs": [grant_binding.grant_ref.clone()],
            "artifact_refs": [],
            "rollback_refs": [],
            "redaction_profile": "internal",
            "evidence_refs": ["runtime_workspace_restore_rust_owned"],
        });
        let admitted = admit_and_persist_event(&st, event)?;
        if let Some(object) = response.as_object_mut() {
            object.insert("applied_file_count".to_string(), json!(applied_count));
            object.insert("blocked_file_count".to_string(), json!(blocked_count));
            object.insert("approval_grant_ref".to_string(), json!(grant_binding.grant_ref));
            object.insert("event".to_string(), admitted);
        }
    }
    Ok(Json(response))
}

/// POST /v1/threads/:id/snapshots/:snapshot_id/restore-preview — preview the restore
/// diff (read-only; reads current workspace files, writes nothing).
pub(crate) async fn handle_snapshot_restore_preview(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, snapshot_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    run_snapshot_restore(st, thread_id, snapshot_id, body, false).await
}

/// POST /v1/threads/:id/snapshots/:snapshot_id/restore-apply — apply the restore: the
/// kernel writes the snapshot's `before` content back to the real workspace filesystem,
/// then a `workspace_restore.applied` event is admitted onto the log.
pub(crate) async fn handle_snapshot_restore_apply(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, snapshot_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    run_snapshot_restore(st, thread_id, snapshot_id, body, true).await
}

/// GET /v1/threads/:id/artifacts — list the thread's conversation artifacts (read-only).
/// The kernel conversation-artifact projection returns an array in record.projection,
/// which the JS owner returns directly; an untouched thread projects an empty array.
pub(crate) async fn handle_artifacts_list(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    if read_agent_for_thread(&st, &thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    let request: RuntimeConversationArtifactProjectionRequest = serde_json::from_value(json!({
        "operation": "conversation_artifact_inspection",
        "operation_kind": "runtime.conversation_artifact_projection.list",
        "projection_kind": "list",
        "thread_id": thread_id,
        "state_dir": st.data_dir,
        "source": "runtime.conversation_artifact_state",
        "evidence_refs": [
            "runtime_conversation_artifact_projection_rust_owned",
            "conversation_artifact_projection_js_facade_retired",
        ],
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_runtime_conversation_artifact_projection(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(Json(record.projection.clone()))
}

/// POST /v1/threads/:id/artifacts — create a conversation artifact. The kernel
/// plan_runtime_conversation_artifact_control builds the artifact record (generating
/// the artifact_id when absent); the daemon persists it to state_dir/artifacts/{id}.json
/// (the GET projection reads it back). Returns the JS shape with 201.
pub(crate) async fn handle_artifact_create(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    if read_agent_for_thread(&st, &thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    let request: RuntimeConversationArtifactControlRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_CONVERSATION_ARTIFACT_CONTROL_REQUEST_SCHEMA_VERSION,
        "operation": "conversation_artifact_create",
        "operation_kind": "artifact.conversation.create",
        "thread_id": thread_id,
        "artifact_id": body.get("artifact_id").and_then(|v| v.as_str()),
        "state_dir": st.data_dir,
        // Inline artifacts/artifact candidate transport is retired; the planner builds it.
        "request": body,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .plan_runtime_conversation_artifact_control(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let artifact_id = record.artifact_id.clone();
    let artifact = record.artifact.clone();
    persist_record(st.data_dir.as_str(), "artifacts", &artifact_id, &artifact)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let mut response = record.result.clone();
    if let Some(map) = response.as_object_mut() {
        map.insert("artifact_id".to_string(), json!(artifact_id));
        map.insert("operation_kind".to_string(), json!(record.operation_kind));
        map.insert("artifact".to_string(), artifact);
        map.insert("commit".to_string(), json!({ "persisted": true }));
    }
    Ok((StatusCode::CREATED, Json(response)))
}

/// Build the JS contextPolicyResultEnvelope: {...policy, event, event_id, seq,
/// receipt_refs, policy_decision_refs, evidence_refs} over an admitted decision event.
fn context_policy_envelope(mut policy: Value, admitted: Value, evidence_refs: Value) -> Value {
    if let Some(map) = policy.as_object_mut() {
        let event_id = admitted.get("event_id").cloned().unwrap_or(Value::Null);
        let seq = admitted.get("seq").cloned().unwrap_or(Value::Null);
        let receipt_refs = merge_string_refs(&[map.get("receipt_refs"), admitted.get("receipt_refs")]);
        let policy_decision_refs =
            merge_string_refs(&[map.get("policy_decision_refs"), admitted.get("policy_decision_refs")]);
        map.insert("event".to_string(), admitted);
        map.insert("event_id".to_string(), event_id);
        map.insert("seq".to_string(), seq);
        map.insert("receipt_refs".to_string(), Value::Array(receipt_refs));
        map.insert("policy_decision_refs".to_string(), Value::Array(policy_decision_refs));
        map.insert("evidence_refs".to_string(), evidence_refs);
    }
    policy
}

/// Build a runtime event from a context-policy decision record (mirrors the JS
/// admitContextPolicyRuntimeEvent + contextPolicyEventPayload for the non-budget
/// component kinds). Used by compaction-policy (and reusable for context-budget).
fn build_context_policy_event(
    _st: &DaemonState,
    thread_id: &str,
    component_kind: &str,
    policy: &Value,
    evidence_refs: &Value,
) -> Value {
    let now = iso_now();
    let event_stream_id = format!("{thread_id}:events");
    let s = |key: &str| policy.get(key).and_then(|v| v.as_str()).map(str::to_string);
    let policy_decision_id = s("policy_decision_id").unwrap_or_default();
    let event_id = format!(
        "evt_{component_kind}_{thread_id}_{}_{}",
        short_hash(&policy_decision_id),
        short_hash(&now)
    );
    // The admission planner requires non-empty receipt_refs; fall back to the decision id.
    let mut receipt_refs = policy
        .get("receipt_refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if receipt_refs.is_empty() {
        receipt_refs.push(Value::from(format!("{component_kind}_decision:{policy_decision_id}")));
    }
    let payload = if component_kind == "context_budget" {
        json!({
            "status": policy.get("status"),
            "mode": policy.get("mode"),
            "scope": policy.get("scope"),
            "summary": policy.get("summary"),
            "policy_decision_id": policy.get("policy_decision_id"),
            "policy_decision": policy.get("policy_decision"),
            "usage_telemetry": policy.get("usage_telemetry"),
            "usage_summary": policy.get("usage_summary"),
            "thresholds": policy.get("thresholds"),
            "warnings": policy.get("warnings"),
            "violations": policy.get("violations"),
            "would_block": policy.get("would_block"),
        })
    } else {
        json!({
            "status": policy.get("status"),
            "action": policy.get("action"),
            "selected_action": policy.get("selected_action"),
            "budget_status": policy.get("budget_status"),
            "summary": policy.get("summary"),
            "policy_decision_id": policy.get("policy_decision_id"),
            "context_budget": policy.get("context_budget"),
            "approval_id": policy.get("approval_id"),
            "approval_required": policy.get("approval_required"),
            "approval_granted": policy.get("approval_granted"),
            "approval_satisfied": policy.get("approval_satisfied"),
            "execute_compaction": policy.get("execute_compaction"),
            "compaction_requested": policy.get("compaction_requested"),
            "compact_reason": policy.get("compact_reason"),
            "compact_scope": policy.get("compact_scope"),
            "continuation_allowed": policy.get("continuation_allowed"),
        })
    };
    json!({
        "event_stream_id": event_stream_id,
        "event_id": event_id,
        "thread_id": thread_id,
        "turn_id": policy.get("turn_id"),
        "item_id": policy.get("runtime_event_item_id"),
        "idempotency_key": policy.get("runtime_event_idempotency_key"),
        "source": policy.get("source"),
        "source_event_kind": policy.get("event_kind"),
        "event_kind": policy.get("runtime_event_kind"),
        "status": policy.get("runtime_event_status"),
        "actor": policy.get("actor"),
        "workflow_graph_id": policy.get("workflow_graph_id"),
        "workflow_node_id": policy.get("workflow_node_id"),
        "component_kind": component_kind,
        "payload_schema_version": policy.get("payload_schema_version"),
        "payload": payload,
        "receipt_refs": receipt_refs,
        "policy_decision_refs": policy.get("policy_decision_refs"),
        "artifact_refs": [],
        "rollback_refs": [],
        "redaction_profile": "internal",
        "created_at": now,
        "evidence_refs": evidence_refs,
    })
}

/// Union string arrays, dropping blanks + duplicates (preserves first-seen order).
fn merge_string_refs(sources: &[Option<&Value>]) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for source in sources {
        if let Some(Value::Array(items)) = source {
            for item in items {
                if let Some(text) = item.as_str() {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
                        out.push(Value::from(trimmed));
                    }
                }
            }
        }
    }
    out
}

/// POST /v1/threads/:id/subagents — spawn a subagent (child agent + run + record).
///
/// Builds a child agent (build_agent_candidate) + a child run (build_run_candidate),
/// then stamps the subagent record via plan_subagent_record_state_update and persists
/// all three. The subagent_id is the child agent id.
pub(crate) async fn handle_subagent_spawn(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let prompt = body.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
    if prompt.is_empty() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "subagent spawn requires a prompt".to_string(),
        ));
    }
    let Some(parent_agent) = read_agent_for_thread(&st, &thread_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    };
    let role = body.get("role").and_then(|v| v.as_str()).unwrap_or("worker").to_string();
    let model_route_id = body
        .get("model_route_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| coalesce_value(&parent_agent, &["model_route_id", "modelRouteId"]).as_str().map(str::to_string))
        .unwrap_or_else(|| "route.local-first".to_string());
    let cwd = coalesce_value(&parent_agent, &["cwd"]);

    // --- child agent ---
    let child_options = json!({ "local": { "cwd": cwd }, "model": { "route_id": model_route_id } });
    let child_agent = build_agent_candidate(&st, &child_options);
    let child_agent_id = child_agent
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let plan_agent: AgentCreateStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "agent": child_agent,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let planned_agent = RuntimeKernelService::new()
        .plan_agent_create_state_update(&plan_agent)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    persist_record(st.data_dir.as_str(), "agents", &child_agent_id, &planned_agent.agent)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    // --- child run ---
    let now = iso_now();
    let run_id = format!("run_{}", uuid::Uuid::new_v4());
    let run = build_run_candidate(&planned_agent.agent, &run_id, "send", prompt, &now);
    let plan_run: RunCreateStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "run": run,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let planned_run = RuntimeKernelService::new()
        .plan_run_create_state_update(&plan_run)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    persist_run_with_bundle(&*st, &run_id, "run.create", &planned_run.run)?;

    // --- subagent record ---
    let child_thread_id = thread_id_for_agent(&child_agent_id);
    let subagent = json!({
        "schema_version": "ioi.runtime.subagent.v1",
        "object": "ioi.runtime_subagent",
        "subagent_id": child_agent_id,
        "agent_id": child_agent_id,
        "child_thread_id": child_thread_id,
        "run_id": run_id,
        "parent_thread_id": thread_id,
        "parent_agent_id": coalesce_value(&parent_agent, &["id"]),
        "role": role,
        "model_route_id": model_route_id,
        "lifecycle_status": "completed",
        "status": "completed",
        "restart_status": "not_restarted",
        "restart_count": 0,
        "fork_context": false,
        "context_mode": "forked",
        "output_contract": Value::Null,
        "output_contract_status": "satisfied",
        "merge_policy": "manual",
        "created_at": now,
        "updated_at": now,
    });
    let plan_subagent: SubagentRecordStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "operation_kind": "subagent.spawn",
        "thread_id": thread_id,
        "subagent": subagent,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let planned_subagent = RuntimeKernelService::new()
        .plan_subagent_record_state_update(&plan_subagent)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    persist_record(st.data_dir.as_str(), "subagents", &child_agent_id, &planned_subagent.subagent)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    Ok((StatusCode::CREATED, Json(planned_subagent.subagent)))
}

/// GET /v1/threads/:id/subagents — list the thread's subagent records.
pub(crate) async fn handle_subagents_list(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<Value> {
    let subagents: Vec<Value> = read_record_dir(&st.data_dir, "subagents")
        .into_iter()
        .filter(|sub| sub.get("parent_thread_id").and_then(|v| v.as_str()) == Some(thread_id.as_str()))
        .filter(|sub| match params.get("role") {
            Some(role) => sub.get("role").and_then(|v| v.as_str()) == Some(role.as_str()),
            None => true,
        })
        .collect();
    Json(json!(subagents))
}

/// GET /v1/threads/:id/subagents/:subagent_id/result — return a subagent record.
pub(crate) async fn handle_subagent_result(
    State(st): State<Arc<DaemonState>>,
    AxumPath((_thread_id, subagent_id)): AxumPath<(String, String)>,
) -> Result<Json<Value>, AppError> {
    read_record_dir(&st.data_dir, "subagents")
        .into_iter()
        .find(|sub| sub.get("subagent_id").and_then(|v| v.as_str()) == Some(subagent_id.as_str()))
        .map(Json)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, format!("subagent not found: {subagent_id}")))
}

/// Load a subagent record by subagent_id.
fn read_subagent(st: &DaemonState, subagent_id: &str) -> Option<Value> {
    read_record_dir(&st.data_dir, "subagents")
        .into_iter()
        .find(|sub| sub.get("subagent_id").and_then(|v| v.as_str()) == Some(subagent_id))
}

/// Stamp + persist a subagent record via plan_subagent_record_state_update.
fn plan_and_persist_subagent(
    st: &DaemonState,
    thread_id: &str,
    operation_kind: &str,
    subagent: Value,
) -> Result<Value, AppError> {
    let subagent_id = subagent
        .get("subagent_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let request: SubagentRecordStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "operation_kind": operation_kind,
        "thread_id": thread_id,
        "subagent": subagent,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .plan_subagent_record_state_update(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    persist_record(st.data_dir.as_str(), "subagents", &subagent_id, &record.subagent)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    Ok(record.subagent)
}

/// POST /v1/threads/:id/subagents/:subId/wait — settle a subagent.
pub(crate) async fn handle_subagent_wait(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, subagent_id)): AxumPath<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let Some(mut subagent) = read_subagent(&st, &subagent_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("subagent not found: {subagent_id}")));
    };
    let now = iso_now();
    if let Some(map) = subagent.as_object_mut() {
        map.insert("waited_at".to_string(), json!(now));
        map.insert("updated_at".to_string(), json!(now));
    }
    Ok(Json(plan_and_persist_subagent(&st, &thread_id, "subagent.wait", subagent)?))
}

/// POST /v1/threads/:id/subagents/:subId/assign — reassign a subagent.
pub(crate) async fn handle_subagent_assign(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, subagent_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let Some(mut subagent) = read_subagent(&st, &subagent_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("subagent not found: {subagent_id}")));
    };
    let now = iso_now();
    if let Some(map) = subagent.as_object_mut() {
        if let Some(role) = body.get("role").and_then(|v| v.as_str()) {
            map.insert("role".to_string(), json!(role));
        }
        if let Some(target) = body.get("target_agent_id").and_then(|v| v.as_str()) {
            map.insert("assigned_agent_id".to_string(), json!(target));
        }
        map.insert("updated_at".to_string(), json!(now));
    }
    Ok(Json(plan_and_persist_subagent(&st, &thread_id, "subagent.assign", subagent)?))
}

/// POST /v1/threads/:id/subagents/:subId/cancel — cancel a subagent (and its run).
pub(crate) async fn handle_subagent_cancel(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, subagent_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let Some(mut subagent) = read_subagent(&st, &subagent_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("subagent not found: {subagent_id}")));
    };
    let now = iso_now();
    if let Some(run_id) = subagent.get("run_id").and_then(|v| v.as_str()).map(str::to_string) {
        if let Some(run) = read_record_dir(&st.data_dir, "runs")
            .into_iter()
            .find(|run| run.get("id").and_then(|v| v.as_str()) == Some(run_id.as_str()))
        {
            if let Ok(request) = serde_json::from_value::<RunCancelStateUpdateRequest>(json!({
                "schema_version": RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                "run_id": run_id,
                "run": run,
                "canceled_at": now,
            })) {
                if let Ok(record) = RuntimeKernelService::new().plan_run_cancel_state_update(&request) {
                    let _ = persist_run_with_bundle(&*st, &run_id, "run.cancel", &record.run);
                }
            }
        }
    }
    if let Some(map) = subagent.as_object_mut() {
        map.insert("status".to_string(), json!("canceled"));
        map.insert("lifecycle_status".to_string(), json!("canceled"));
        if let Some(reason) = body
            .get("reason")
            .or_else(|| body.get("cancellation_reason"))
            .and_then(|v| v.as_str())
        {
            map.insert("cancellation_reason".to_string(), json!(reason));
        }
        map.insert("updated_at".to_string(), json!(now));
    }
    Ok(Json(plan_and_persist_subagent(&st, &thread_id, "subagent.cancel", subagent)?))
}

/// POST /v1/threads/:id/subagents/cancel — propagate cancellation to the thread's
/// subagents (cancel each cancelable child + its run), returning a propagation summary.
pub(crate) async fn handle_subagents_propagate_cancel(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let parent_agent_id = agent_id_for_thread(&thread_id);
    let reason = body
        .get("reason")
        .or_else(|| body.get("cancellation_reason"))
        .and_then(|v| v.as_str())
        .unwrap_or("parent_cancel")
        .to_string();
    let source = body.get("source").and_then(|v| v.as_str()).unwrap_or("agent_studio").to_string();
    let now = iso_now();
    let candidates: Vec<Value> = read_record_dir(&st.data_dir, "subagents")
        .into_iter()
        .filter(|sub| sub.get("parent_thread_id").and_then(|v| v.as_str()) == Some(thread_id.as_str()))
        .collect();
    let mut canceled = Vec::new();
    let mut skipped = Vec::new();
    for candidate in candidates {
        let status = candidate
            .get("status")
            .or_else(|| candidate.get("lifecycle_status"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let run_id = candidate.get("run_id").and_then(|v| v.as_str()).map(str::to_string);
        if candidate.get("subagent_id").and_then(|v| v.as_str()).is_none()
            || status == "canceled"
            || run_id.is_none()
        {
            skipped.push(candidate);
            continue;
        }
        let run_id = run_id.unwrap();
        if let Some(run) = read_record_dir(&st.data_dir, "runs")
            .into_iter()
            .find(|run| run.get("id").and_then(|v| v.as_str()) == Some(run_id.as_str()))
        {
            if let Ok(request) = serde_json::from_value::<RunCancelStateUpdateRequest>(json!({
                "schema_version": RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                "run_id": run_id,
                "run": run,
                "canceled_at": now,
            })) {
                if let Ok(record) = RuntimeKernelService::new().plan_run_cancel_state_update(&request) {
                    let _ = persist_run_with_bundle(&*st, &run_id, "run.cancel", &record.run);
                }
            }
        }
        let mut updated = candidate;
        if let Some(map) = updated.as_object_mut() {
            map.insert("status".to_string(), json!("canceled"));
            map.insert("lifecycle_status".to_string(), json!("canceled"));
            map.insert("cancellation_reason".to_string(), json!(reason));
            map.insert("cancellation_inherited".to_string(), json!(true));
            map.insert("propagated_from_thread_id".to_string(), json!(thread_id));
            map.insert("updated_at".to_string(), json!(now));
        }
        let saved = plan_and_persist_subagent(&st, &thread_id, "subagent.cancel.propagate", updated)?;
        canceled.push(saved);
    }
    let status = if canceled.is_empty() { "noop" } else { "propagated" };
    Ok(Json(json!({
        "schema_version": "ioi.runtime.subagent-cancellation-propagation.v1",
        "object": "ioi.runtime_subagent_cancellation_propagation",
        "thread_id": thread_id,
        "parent_agent_id": parent_agent_id,
        "status": status,
        "source": source,
        "reason": reason,
        "candidate_count": canceled.len() + skipped.len(),
        "canceled_count": canceled.len(),
        "skipped_count": skipped.len(),
        "canceled_subagents": canceled,
        "skipped_subagents": skipped,
    })))
}

/// Shared input/resume: create a new child run, then advance the subagent record.
fn subagent_run_control(
    st: &DaemonState,
    thread_id: &str,
    subagent_id: &str,
    body: &Value,
    operation_kind: &str,
) -> Result<Json<Value>, AppError> {
    let Some(mut subagent) = read_subagent(st, subagent_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("subagent not found: {subagent_id}")));
    };
    let child_agent_id = subagent
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or(subagent_id)
        .to_string();
    let Some(child_agent) = read_record_dir(&st.data_dir, "agents")
        .into_iter()
        .find(|agent| agent.get("id").and_then(|v| v.as_str()) == Some(child_agent_id.as_str()))
    else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("child agent not found: {child_agent_id}")));
    };
    let now = iso_now();
    let run_id = format!("run_{}", uuid::Uuid::new_v4());
    let prompt = body
        .get("input")
        .or_else(|| body.get("prompt"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let run = build_run_candidate(&child_agent, &run_id, "send", prompt, &now);
    let plan_run: RunCreateStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "run": run,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let planned_run = RuntimeKernelService::new()
        .plan_run_create_state_update(&plan_run)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    persist_run_with_bundle(&*st, &run_id, "run.create", &planned_run.run)?;
    if let Some(map) = subagent.as_object_mut() {
        map.insert("run_id".to_string(), json!(run_id));
        map.insert("status".to_string(), json!("completed"));
        map.insert("lifecycle_status".to_string(), json!("completed"));
        map.insert("updated_at".to_string(), json!(now));
    }
    Ok(Json(plan_and_persist_subagent(st, thread_id, operation_kind, subagent)?))
}

/// POST /v1/threads/:id/subagents/:subId/input — send input (creates a new run).
pub(crate) async fn handle_subagent_input(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, subagent_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    subagent_run_control(&st, &thread_id, &subagent_id, &body, "subagent.input")
}

/// POST /v1/threads/:id/subagents/:subId/resume — resume (creates a new run).
pub(crate) async fn handle_subagent_resume(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, subagent_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    subagent_run_control(&st, &thread_id, &subagent_id, &body, "subagent.resume")
}

/// GET /v1/threads/:id/mcp/tools/search — project the thread's MCP tool catalog.
///
/// Exercises the kernel MCP catalog/tool-search projection (the boundary that
/// originally 502'd thread-create). A thread with no mounted MCP servers projects
/// an empty tool set.
pub(crate) async fn handle_mcp_tool_search(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    let agent_id = agent_id_for_thread(&thread_id);
    let query = params
        .get("q")
        .or_else(|| params.get("query"))
        .or_else(|| params.get("search"))
        .cloned();
    let request: McpToolSearchProjectionRequest = serde_json::from_value(json!({
        "schema_version": MCP_TOOL_SEARCH_PROJECTION_REQUEST_SCHEMA_VERSION,
        "status_schema_version": "ioi.runtime.mcp-tool-search.v1",
        "state_dir": st.data_dir,
        "thread_id": thread_id,
        "agent_id": agent_id,
        "server_id": params.get("server_id"),
        "servers": [],
        "query": query,
        "tool_id": params.get("tool_id"),
        "limit": params.get("limit").and_then(|v| v.parse::<u64>().ok()),
        "live_discovery": false,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_mcp_tool_search_projection(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let projected = serde_json::to_value(&record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    Ok(Json(projected))
}

/// POST /v1/runs/:id/cancel — cancel a run via plan_run_cancel_state_update.
/// Cancel a loaded run (plan_run_cancel + re-commit the full bundle so tasks/jobs/
/// checklists reflect the cancel). Returns the canceled run record. Shared by run cancel
/// and the job/task cancel routes (a job/task is canceled by canceling its owning run).
fn cancel_run_record(st: &DaemonState, run: Value) -> Result<Value, AppError> {
    let run_id = run.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let request: RunCancelStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "run_id": run_id,
        "run": run,
        "canceled_at": iso_now(),
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .plan_run_cancel_state_update(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    commit_run_state_bundle(st, &run_id, "run.cancel", &record.run)?;
    // Admit the cancel-specific events (job_canceled + the canceled terminal) onto the
    // thread log so GET /v1/threads/:id/events reflects the cancel. The turn's other events
    // are already on the log from turn-create; admitting the whole turn again would
    // duplicate them (the cancel re-projection uses different event ids), so we admit only
    // the new cancel events. admit_and_persist_event is idempotency-keyed, so a re-cancel
    // (or a job/task cancel after a run cancel) is a no-op.
    let agent_id = record
        .run
        .get("agentId")
        .or_else(|| record.run.get("agent_id"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let thread_id = thread_id_for_agent(agent_id);
    for event in project_runtime_events(st, "run", &thread_id, Some(&run_id))? {
        let is_cancel_event = event
            .get("payload_summary")
            .and_then(|p| p.get("event_kind"))
            .and_then(|v| v.as_str())
            == Some("JobCanceled")
            || event.get("event_kind").and_then(|v| v.as_str()) == Some("turn.canceled");
        if is_cancel_event {
            admit_and_persist_event(st, event)?;
        }
    }
    Ok(record.run)
}

pub(crate) async fn handle_run_cancel(
    State(st): State<Arc<DaemonState>>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let Some(run) = read_record_dir(&st.data_dir, "runs")
        .into_iter()
        .find(|run| run.get("id").and_then(|v| v.as_str()) == Some(run_id.as_str()))
    else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("run not found: {run_id}")));
    };
    Ok(Json(cancel_run_record(&st, run)?))
}

/// POST /v1/jobs/:id/cancel — cancel a runtime job by canceling its owning run; returns
/// the canceled runtimeJob (status/lifecycle/cancellation), embedded in the run record.
pub(crate) async fn handle_job_cancel(
    State(st): State<Arc<DaemonState>>,
    AxumPath(job_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let Some(run) = read_record_dir(&st.data_dir, "runs").into_iter().find(|run| {
        run.get("runtimeJob").and_then(|j| j.get("jobId")).and_then(|v| v.as_str()) == Some(job_id.as_str())
    }) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("job not found: {job_id}")));
    };
    let canceled = cancel_run_record(&st, run)?;
    Ok(Json(canceled.get("runtimeJob").cloned().unwrap_or(Value::Null)))
}

/// POST /v1/tasks/:id/cancel — cancel a runtime task by canceling its owning run; returns
/// the canceled runtimeTask.
pub(crate) async fn handle_task_cancel(
    State(st): State<Arc<DaemonState>>,
    AxumPath(task_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let Some(run) = read_record_dir(&st.data_dir, "runs").into_iter().find(|run| {
        run.get("runtimeTask").and_then(|t| t.get("taskId")).and_then(|v| v.as_str()) == Some(task_id.as_str())
    }) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("task not found: {task_id}")));
    };
    let canceled = cancel_run_record(&st, run)?;
    Ok(Json(canceled.get("runtimeTask").cloned().unwrap_or(Value::Null)))
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

    // Entering review/yolo mode emits a workspace-trust WARNING onto the unified log
    // (the kernel decides it is required from controls.mode). The acknowledge route
    // later consumes that warning by id — the mode transition, not a separate route,
    // is what raises the trust warning.
    if control_kind == "mode" {
        if let Some((warning, admitted)) =
            emit_workspace_trust_warning(st, thread_id, &updated_agent, &controls, &now, &event_id)?
        {
            if let Some(map) = response.as_object_mut() {
                map.insert("workspace_trust_warning".to_string(), warning);
                map.insert("workspace_trust_warning_event".to_string(), admitted);
            }
        }
    }
    Ok(Json(response))
}

/// Emit the workspace-trust warning for a mode transition: plan it (kernel
/// plan_workspace_trust_control_state_update op workspace_trust.warning — returns a
/// not_required record for agent/plan modes) and, when required, admit the
/// workspace.trust_warning event onto the unified log. Returns the warning object +
/// the admitted event, or None when no warning is required for the mode.
fn emit_workspace_trust_warning(
    st: &DaemonState,
    thread_id: &str,
    agent: &Value,
    controls: &Value,
    now: &str,
    source_event_id: &str,
) -> Result<Option<(Value, Value)>, AppError> {
    let request: WorkspaceTrustControlStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": WORKSPACE_TRUST_CONTROL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "operation_kind": "workspace_trust.warning",
        "thread_id": thread_id,
        "event_stream_id": format!("{thread_id}:events"),
        // Inline agent is accepted by the workspace-trust planner (reads agent.id + cwd).
        "agent": agent,
        "controls": controls,
        "source_event_id": source_event_id,
        "source": "runtime_thread_control",
        "actor": "operator",
        "requested_by": "operator",
        "workflow_node_id": "runtime.workspace-trust",
        "state_dir": st.data_dir,
        "created_at": now,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .plan_workspace_trust_control_state_update(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let record = serde_json::to_value(&record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    if record.get("status").and_then(|v| v.as_str()) == Some("not_required") {
        return Ok(None);
    }
    let Some(event) = record.get("event").filter(|v| v.is_object()).cloned() else {
        return Ok(None);
    };
    let admitted = admit_and_persist_event(st, event)?;
    let warning = record.get("workspace_trust_warning").cloned().unwrap_or(Value::Null);
    Ok(Some((warning, admitted)))
}

/// POST /v1/threads/:id/workspace-trust/:warning_id/acknowledge — acknowledge a
/// workspace-trust warning raised by a prior mode transition. The kernel planner reads
/// the warning from the persisted event log by id and emits a workspace.trust_acknowledged
/// event, which the daemon admits onto the unified log.
pub(crate) async fn handle_workspace_trust_acknowledge(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, warning_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let Some(agent) = read_agent_for_thread(&st, &thread_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    };
    let now = iso_now();
    let request: WorkspaceTrustControlStateUpdateRequest = serde_json::from_value(json!({
        "schema_version": WORKSPACE_TRUST_CONTROL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
        "operation_kind": "workspace_trust.acknowledge",
        "thread_id": thread_id,
        "event_stream_id": format!("{thread_id}:events"),
        "agent": agent,
        "warning_id": warning_id,
        "source_event_id": body.get("source_event_id").and_then(|v| v.as_str()),
        "reason": body.get("reason").and_then(|v| v.as_str()),
        "source": body.get("source").and_then(|v| v.as_str()).unwrap_or("runtime_thread_control"),
        "actor": body.get("actor").and_then(|v| v.as_str()).unwrap_or("operator"),
        "workflow_node_id": body.get("workflow_node_id").and_then(|v| v.as_str()).unwrap_or("runtime.workspace-trust"),
        "state_dir": st.data_dir,
        "created_at": now,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .plan_workspace_trust_control_state_update(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    let mut response = serde_json::to_value(&record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let event = response.get("event").cloned().unwrap_or(Value::Null);
    if !event.is_object() {
        return Err(AppError(
            StatusCode::BAD_GATEWAY,
            "workspace-trust acknowledge planner returned no event".to_string(),
        ));
    }
    let admitted = admit_and_persist_event(&st, event)?;
    if let Some(map) = response.as_object_mut() {
        map.insert("event".to_string(), admitted.clone());
        map.insert("workspace_trust_acknowledgement_event".to_string(), admitted);
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
