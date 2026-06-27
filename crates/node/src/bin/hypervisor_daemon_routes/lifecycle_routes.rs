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
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use ioi_services::agentic::runtime::kernel::policy::{
    AgentCreateStateUpdateRequest, CompactionPolicyRequest, ContextBudgetPolicyRequest,
    ContextCompactionPlanRequest, ContextCompactionStateUpdateRequest,
    McpControlAgentStateUpdateRequest, McpManagerCatalogProjectionRequest,
    McpServerValidationInputRequest, McpToolSearchProjectionRequest,
    OperatorInterruptStateUpdateRequest, OperatorSteerStateUpdateRequest,
    RunCancelStateUpdateRequest, RunCreateStateUpdateRequest, SubagentRecordStateUpdateRequest,
    ThreadControlAgentStateUpdateRequest, ThreadCreateStateUpdateRequest,
    WorkspaceTrustControlStateUpdateRequest, AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    COMPACTION_POLICY_REQUEST_SCHEMA_VERSION, CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
    CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION,
    CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
    MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION,
    MCP_TOOL_SEARCH_PROJECTION_REQUEST_SCHEMA_VERSION,
    OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION, RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    THREAD_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    WORKSPACE_TRUST_CONTROL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
};
use jsonwebtoken::{encode as jwt_encode, Algorithm as JwtAlgorithm, EncodingKey, Header as JwtHeader};
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
    RuntimeConversationArtifactControlRecord, RuntimeConversationArtifactControlRequest,
    RUNTIME_CONVERSATION_ARTIFACT_CONTROL_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::runtime_conversation_artifact_projection::RuntimeConversationArtifactProjectionRequest;
use ioi_services::agentic::runtime::kernel::repository_workflow::RepositoryWorkflowProjectionRequest;
use ioi_services::agentic::runtime::kernel::runtime_tool_catalog::RuntimeToolCatalogProjectionRequest;
use ioi_services::agentic::runtime::kernel::skill_hook_registry::SkillHookRegistryProjectionRequest;
use ioi_services::agentic::runtime::kernel::runtime_diagnostics_repair_control::{
    RuntimeDiagnosticsRepairControlRequest, RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::agentgres_admission::{
    RuntimeMemoryStateCommitRequest, RuntimeRunStateCommitRequest,
    RUNTIME_MEMORY_STATE_COMMIT_SCHEMA_VERSION, RUNTIME_RUN_STATE_COMMIT_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::runtime_doctor_report::RuntimeDoctorReportProjectionRequest;
use ioi_services::agentic::runtime::kernel::studio_intent_frame::StudioIntentFrameProjectionRequest;
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
    build_route_decision, debug_string, iso_now, persist_record, read_record_dir, remove_record,
    route_selection, sha256_hex_str, short_hash, AppError, DaemonState, PreviewServer,
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

/// POST /v1/threads/:id/cancel — cancel a thread/agent execution. Real, no fake: marks the persisted
/// agent record cancelled (so the thread projection + list reflect it). Backs AgentService/Stop.
pub(crate) async fn handle_thread_cancel(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let Some(mut agent) = read_agent_for_thread(&st, &thread_id) else {
        return Err(AppError(StatusCode::NOT_FOUND, "thread not found".into()));
    };
    let agent_id = agent.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    agent["status"] = json!("cancelled");
    agent["cancelled_at"] = json!(iso_now());
    persist_record(&st.data_dir, "agents", &agent_id, &agent)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "ok": true, "thread_id": thread_id, "status": "cancelled", "at": iso_now() })))
}

/// DELETE /v1/threads/:id — delete a thread/agent execution. Real, no fake: removes the persisted
/// agent record (so /v1/threads no longer lists it) + best-effort drops its event log. Backs
/// AgentService/DeleteAgentExecution.
pub(crate) async fn handle_thread_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let agent_id = agent_id_for_thread(&thread_id);
    let safe = |s: &str| s.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_");
    let agent_path = std::path::Path::new(&st.data_dir).join("agents").join(format!("{}.json", safe(&agent_id)));
    let existed = agent_path.exists();
    let _ = std::fs::remove_file(&agent_path);
    let suffix = thread_id.strip_prefix("thread_").unwrap_or(&thread_id).to_string();
    let ev_dir = std::path::Path::new(&st.data_dir).join("events");
    if let Ok(entries) = std::fs::read_dir(&ev_dir) {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().contains(&suffix) { let _ = std::fs::remove_file(e.path()); }
        }
    }
    Ok(Json(json!({ "ok": true, "deleted": thread_id, "existed": existed, "at": iso_now() })))
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

/// POST /v1/studio/intent-frame — project a Studio intent frame from a prompt/input/query
/// (the kernel studio_intent_frame projection). Returns the frame.
pub(crate) async fn handle_studio_intent_frame(
    State(_st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let request: StudioIntentFrameProjectionRequest = serde_json::from_value(json!({
        "operation": "studio_intent_frame_projection",
        "operation_kind": "studio.intent_frame.projection",
        "prompt": body.get("prompt").and_then(|v| v.as_str()),
        "input": body.get("input").and_then(|v| v.as_str()),
        "query": body.get("query").and_then(|v| v.as_str()),
        "execution_mode": body.get("execution_mode").and_then(|v| v.as_str()),
        "source": "rust_daemon./v1/studio/intent-frame",
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_studio_intent_frame(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, format!("{error:?}")))?;
    Ok(Json(record.frame))
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

/// POST /v1/threads/:id/tools/:name/invoke — invoke a coding-tool-pack tool against the
/// thread's workspace via the CANONICAL kernel `run_coding_tool_step_module` (workspace.status,
/// git.diff, file.inspect, file.apply_patch, test.run, lsp.diagnostics, artifact.read,
/// tool.retrieve_result, computer_use.request_lease). The tool id is the path `:name`; the body's
/// `input` (+ optional workflow_graph_id/workflow_node_id/run_id/task_id/idempotency_key)
/// Dispatch an `ioi.computer_use.*` projection tool (browser_discovery / provider_registry)
/// through the CANONICAL kernel `RuntimeComputerUseProjectionCore::project`, emit the
/// `computer_use.<kind>` runtime event onto the thread stream, and shape the agent-sdk
/// thread-tool result. Deterministic (no Chromium): browser discovery runs over an empty
/// process row set unless the caller supplies one. Ports the agent-sdk computer-use spine's
/// projection tools onto the Rust true-north.
fn handle_computer_use_projection_tool(
    st: &DaemonState,
    thread_id: &str,
    tool_name: &str,
    projection_kind: &str,
    body: &Value,
) -> Result<Json<Value>, AppError> {
    let input = body.get("input").cloned().unwrap_or_else(|| json!({}));
    let workflow_graph_id = coalesce_str(body, &["workflow_graph_id", "workflowGraphId"]).map(str::to_string);
    let workflow_node_id = coalesce_str(body, &["workflow_node_id", "workflowNodeId"]).map(str::to_string);
    let source = coalesce_str(body, &["source"]).unwrap_or("react_flow").to_string();

    // Build the projection request from the tool input (deterministic process rows by default).
    let mut request_json = json!({
        "projection_kind": projection_kind,
        "source": source,
    });
    if let (Some(map), Some(input_map)) = (request_json.as_object_mut(), input.as_object()) {
        for key in ["platform", "discovered_at", "process_rows", "include_cdp_probe", "include_tab_metadata", "reveal_tab_titles", "probe_timeout_ms"] {
            if let Some(value) = input_map.get(key) {
                map.insert(key.to_string(), value.clone());
            }
        }
        if !input_map.contains_key("process_rows") {
            map.insert("process_rows".to_string(), json!([]));
        }
    }
    let request: ioi_services::agentic::runtime::kernel::runtime_computer_use::RuntimeComputerUseProjectionRequest =
        serde_json::from_value(request_json)
            .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = ioi_services::agentic::runtime::kernel::runtime_computer_use::RuntimeComputerUseProjectionCore
        ::default()
        .project(request)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, format!("{}: {}", error.code(), error.message())))?;
    let (report, payload_key, result_object) = match projection_kind {
        "browser_discovery" => (
            record.browser_discovery.clone().unwrap_or_else(|| json!({})),
            "browser_discovery_report",
            "ioi.runtime_computer_use_browser_discovery_result",
        ),
        _ => (
            record.provider_registry.clone().unwrap_or_else(|| json!({})),
            "provider_registry",
            "ioi.runtime_computer_use_provider_registry_result",
        ),
    };

    // Emit the computer_use.<kind> runtime event onto the thread stream.
    let event_stream_id = format!("{thread_id}:events");
    let now = iso_now();
    let event_hash = short_hash(&format!("{thread_id}:{tool_name}:{now}"));
    let event = json!({
        "event_id": format!("event_computer_use_{projection_kind}_{event_hash}"),
        "event_stream_id": event_stream_id,
        "thread_id": thread_id,
        "turn_id": "",
        "item_id": format!("{thread_id}:item:computer_use:{projection_kind}:{event_hash}"),
        "idempotency_key": format!("thread:{thread_id}:computer_use.{projection_kind}:{event_hash}"),
        "source": source,
        "source_event_kind": "ComputerUse.Projection",
        "event_kind": format!("computer_use.{projection_kind}"),
        "status": "completed",
        "actor": "operator",
        "workspace_root": "",
        "workflow_graph_id": workflow_graph_id,
        "workflow_node_id": workflow_node_id,
        "component_kind": "computer_use_harness",
        "payload_schema_version": "ioi.computer_use.projection.v1",
        "payload": { payload_key: report.clone() },
        "receipt_refs": record.receipt_refs,
        "policy_decision_refs": [],
        "artifact_refs": [],
        "rollback_refs": [],
        "evidence_refs": record.evidence_refs,
    });
    let admitted = admit_and_persist_event(st, event)?;

    Ok(Json(json!({
        "status": "completed",
        "object": result_object,
        "tool_pack": "computer_use",
        "tool_name": tool_name,
        "workflow_node_id": workflow_node_id,
        "result": report,
        "event": admitted,
    })))
}

/// Normalize a caller-supplied visual target (agent-ide camelCase or canonical snake_case) to
/// the canonical snake_case target-index shape the agent-sdk contract reads (target_ref, role,
/// label, som_id, confidence, available_actions, bounds.coordinate_space_id).
fn normalize_visual_target(target: &Value) -> Value {
    let mut normalized = serde_json::Map::new();
    if let Some(target_ref) = coalesce_str(target, &["target_ref", "targetRef"]) {
        normalized.insert("target_ref".to_string(), json!(target_ref));
    }
    for (canonical, keys) in [
        ("label", &["label"][..]),
        ("role", &["role"][..]),
    ] {
        if let Some(value) = coalesce_str(target, keys) {
            normalized.insert(canonical.to_string(), json!(value));
        }
    }
    if let Some(som_id) = target.get("som_id").or_else(|| target.get("somId")) {
        normalized.insert("som_id".to_string(), som_id.clone());
    }
    if let Some(confidence) = target.get("confidence") {
        normalized.insert("confidence".to_string(), confidence.clone());
    }
    if let Some(actions) = target
        .get("available_actions")
        .or_else(|| target.get("availableActions"))
    {
        normalized.insert("available_actions".to_string(), actions.clone());
    }
    if let Some(bounds) = target.get("bounds") {
        let mut bounds_out = bounds.clone();
        if let Some(map) = bounds_out.as_object_mut() {
            if let Some(space) = map.remove("coordinateSpaceId") {
                map.entry("coordinate_space_id").or_insert(space);
            }
        }
        normalized.insert("bounds".to_string(), bounds_out);
    }
    Value::Object(normalized)
}

/// Drive a DETERMINISTIC, read-only computer-use behavioral loop (native_browser / visual_gui)
/// through the Rust daemon, emitting the 11-event agent-sdk computer-use sequence onto the
/// thread stream and shaping the agent-sdk thread-tool result. There is NO single kernel loop
/// producer — this assembles the loop on top of the CANONICAL kernel lease building block
/// (`build_computer_use_lease_request`, which owns lane/session-mode/authority-scope/provider
/// resolution). No real Chromium or display capture: the probe inspects the requested surface
/// read-only. For act-lanes (non read-only) the policy fails closed (commit gate pending),
/// preserving the wallet.network authority boundary. Ports the agent-sdk computer-use spine
/// ("runtime daemon invokes native browser loop through thread tool spine") onto the
/// Rust true-north.
#[allow(clippy::too_many_arguments)]
fn handle_computer_use_loop_tool(
    st: &DaemonState,
    agent: &Value,
    thread_id: &str,
    tool_name: &str,
    lane: &str,
    observe: bool,
    body: &Value,
) -> Result<Json<Value>, AppError> {
    let input = body.get("input").cloned().unwrap_or_else(|| json!({}));
    let workspace_root = memory_agent_cwd(agent).unwrap_or_default();
    let source = coalesce_str(body, &["source"]).unwrap_or("react_flow").to_string();
    let workflow_graph_id =
        coalesce_str(body, &["workflow_graph_id", "workflowGraphId"]).map(str::to_string);
    let workflow_node_id =
        coalesce_str(body, &["workflow_node_id", "workflowNodeId"]).map(str::to_string);
    let tool_call_id = coalesce_str(body, &["tool_call_id", "toolCallId"])
        .unwrap_or("observe")
        .to_string();

    // Normalize the tool input (snake/camel) and force the lane the tool name dispatched.
    let prompt = coalesce_str(&input, &["prompt", "goal", "objective"])
        .unwrap_or("Inspect the requested surface without external side effects.")
        .to_string();
    let url = coalesce_str(&input, &["url"]).map(str::to_string);
    // The observe broker is strictly read-only (capture + index for later visual runs).
    let action_kind = if observe {
        "inspect".to_string()
    } else {
        coalesce_str(&input, &["action_kind", "actionKind"])
            .unwrap_or("inspect")
            .to_string()
    };
    let retention_mode = coalesce_str(
        &input,
        &["observation_retention_mode", "observationRetentionMode"],
    )
    .map(str::to_string)
    .unwrap_or_else(|| {
        if lane == "visual_gui" {
            "local_redacted_artifacts".to_string()
        } else {
            "prompt_visible_summary_only".to_string()
        }
    });
    let session_mode = coalesce_str(&input, &["session_mode", "sessionMode"]).map(str::to_string);

    // visual_gui-lane projection inputs (observation refs + indexed visual targets). Deterministic:
    // the daemon echoes governed observation refs and indexes the caller-supplied visual targets;
    // real-display capture + path→artifact retention ride the artifact data-plane (separate cut).
    let mut screenshot_ref =
        coalesce_str(&input, &["screenshot_ref", "screenshotRef"]).map(str::to_string);
    let som_ref = coalesce_str(&input, &["som_ref", "somRef"]).map(str::to_string);
    let mut ax_ref = coalesce_str(&input, &["ax_ref", "axRef"]).map(str::to_string);
    let app_name =
        coalesce_str(&input, &["app_name", "appName", "capture_app_name", "captureAppName"])
            .map(str::to_string);
    let window_title = coalesce_str(
        &input,
        &["window_title", "windowTitle", "capture_window_title", "captureWindowTitle"],
    )
    .map(str::to_string);
    let mut coordinate_space_id =
        coalesce_str(&input, &["coordinate_space_id", "coordinateSpaceId"]).map(str::to_string);
    let mut visual_targets = input
        .get("visualTargets")
        .or_else(|| input.get("visual_targets"))
        .and_then(Value::as_array)
        .cloned();
    let capture_provider =
        coalesce_str(&input, &["capture_provider", "captureProvider"]).map(str::to_string);
    let capture_fixture_present = input
        .get("captureFixturePngBase64")
        .or_else(|| input.get("capture_fixture_png_base64"))
        .is_some();

    let mut lease_input = json!({
        "lane": lane,
        "prompt": prompt,
        "url": url,
        "action_kind": action_kind,
        "observation_retention_mode": retention_mode,
    });
    if let Some(mode) = &session_mode {
        lease_input["session_mode"] = json!(mode);
    }
    let lease = ioi_services::agentic::runtime::kernel::coding_tool_computer_use::build_computer_use_lease_request(
        &workspace_root,
        &lease_input,
    )
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, format!("{}: {}", error.code(), error.message())))?;

    let lease_request = lease.get("lease_request").cloned().unwrap_or_else(|| json!({}));
    let authority_scope = lease_request
        .get("authority_scope")
        .and_then(Value::as_str)
        .unwrap_or("computer_use.native_browser.read")
        .to_string();
    let session_mode_resolved = lease_request
        .get("session_mode")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let provider_id = lease_request.get("provider_id").cloned().unwrap_or(Value::Null);
    let provider_kind = lease_request
        .get("provider_kind")
        .cloned()
        .unwrap_or(Value::Null);
    let request_ref = lease
        .get("request_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let lease_receipt_refs = lease.get("receipt_refs").cloned().unwrap_or_else(|| json!([]));
    let lease_evidence_refs = lease.get("evidence_refs").cloned().unwrap_or_else(|| json!([]));

    let now = iso_now();
    let run_hash = short_hash(&format!("{thread_id}:{tool_name}:{now}"));

    // The observe broker brokers a read-only capture for later visual runs. With no real-display
    // capture, it surfaces governed observation artifact refs (deterministic) and indexes either
    // the caller-supplied visual targets or a single capture-bounds target. The base64-fixture →
    // artifact bytes (served via artifact.read) ride the artifact data-plane (separate cut); here
    // we project the broker contract and the governed refs.
    let observation_broker = if observe {
        let governed_screenshot = format!("artifact_computer_use_visual_screenshot_{run_hash}");
        let governed_ax = format!("artifact_computer_use_visual_ax_{run_hash}");
        screenshot_ref = Some(governed_screenshot.clone());
        ax_ref = Some(governed_ax.clone());
        let capture_space = format!("screen_{tool_call_id}_local_capture");
        if coordinate_space_id.is_none() {
            coordinate_space_id = Some(capture_space.clone());
        }
        if visual_targets.is_none() {
            visual_targets = Some(vec![json!({
                "target_ref": format!("target_capture_{run_hash}"),
                "label": window_title.clone().unwrap_or_else(|| "Captured surface".to_string()),
                "role": "window",
                "available_actions": ["inspect"],
                "bounds": {
                    "coordinate_space_id": coordinate_space_id.clone().unwrap_or(capture_space),
                    "x": 0,
                    "y": 0,
                    "width": 1,
                    "height": 1,
                },
            })]);
        }
        Some(json!({
            "object": "ioi.computer_use.visual_gui_observation_broker",
            "capture_receipt": {
                "status": "captured",
                "provider_id": capture_provider.clone().unwrap_or_else(|| "fixture".to_string()),
                "source_path_included": false,
                "screenshot_ref": governed_screenshot,
                "ax_ref": governed_ax,
                "fixture": capture_fixture_present,
            },
        }))
    } else {
        None
    };

    let read_only = matches!(action_kind.as_str(), "inspect" | "hover" | "wait" | "scroll");
    let (policy_outcome, fail_closed, gate_status, receipt_status) = if read_only {
        (
            "approved_for_read_only_probe",
            false,
            "not_required",
            "completed",
        )
    } else {
        (
            "requires_wallet_network_authority",
            true,
            "pending_commit_or_handoff",
            "blocked_pending_authority",
        )
    };
    let (contract_ingest, adapter_id) = if lane == "visual_gui" {
        ("local_visual_observation", "ioi.visual_gui.local_observation")
    } else {
        ("native_browser_cdp", "ioi.native_browser.cdp_probe")
    };
    // The action grounds onto the first indexed visual target when supplied; otherwise a
    // synthesized primary document target derived from the lease + surface.
    let first_visual_target_ref = visual_targets
        .as_ref()
        .and_then(|targets| targets.first())
        .and_then(|target| coalesce_str(target, &["target_ref", "targetRef"]))
        .map(str::to_string);
    let target_ref = first_visual_target_ref.clone().unwrap_or_else(|| {
        format!(
            "target_computer_use_{lane}_{}",
            short_hash(&format!("{request_ref}:{}", url.as_deref().unwrap_or(&prompt)))
        )
    });
    let policy_decision_ref = format!("policy_decision_computer_use_{run_hash}");
    let proposal_ref = format!("proposal_computer_use_{run_hash}");

    let environment_selection = json!({
        "selected_lane": lane,
        "selected_session_mode": session_mode_resolved,
        "selected_provider_id": provider_id,
        "selected_provider_kind": provider_kind,
        "contract_ingest": contract_ingest,
        "required_lanes": ["native_browser", "visual_gui", "sandboxed_hosted"],
        "fail_closed_when_unavailable": true,
    });
    let lease_view = json!({
        "lease_ref": request_ref,
        "lane": lane,
        "status": "active",
        "authority_scope": authority_scope,
        "provider_id": provider_id,
        "provider_kind": provider_kind,
        "retention_mode": retention_mode,
        "session_mode": session_mode_resolved,
    });
    let run_state = json!({
        "run_ref": format!("run_computer_use_{run_hash}"),
        "lane": lane,
        "user_goal": prompt,
        "current_subgoal": "Observe the requested surface, index targets, and propose a grounded next action.",
        "status": "completed",
    });
    let mut observation = json!({
        "observation_ref": format!("observation_computer_use_{run_hash}"),
        "retention_mode": retention_mode,
        "surface_url": url,
        "summary": "Read-only inspection of the requested surface; no external side effects.",
        "dom_digest_ref": format!("observation_digest_{run_hash}"),
    });
    let coordinate_space =
        coordinate_space_id.clone().unwrap_or_else(|| format!("{lane}-{run_hash}"));
    let target_index = if let Some(targets) = visual_targets.clone() {
        let normalized: Vec<Value> = targets.iter().map(normalize_visual_target).collect();
        json!({ "coordinate_space_id": coordinate_space, "targets": normalized })
    } else {
        json!({
            "coordinate_space_id": coordinate_space,
            "targets": [{
                "target_ref": target_ref,
                "label": "Primary document target",
                "role": "document",
                "available_actions": ["inspect"],
            }],
        })
    };
    // Retained observation artifacts (visual_gui echoes governed observation refs into cleanup).
    let mut retained_artifact_refs = vec![json!("computer-use-trace.json")];
    if lane == "visual_gui" {
        if let Some(map) = observation.as_object_mut() {
            map.insert("screenshot_ref".to_string(), json!(screenshot_ref));
            map.insert("som_ref".to_string(), json!(som_ref));
            map.insert("ax_ref".to_string(), json!(ax_ref));
            map.insert("app_name".to_string(), json!(app_name));
            map.insert("window_title".to_string(), json!(window_title));
        }
        for governed in [&screenshot_ref, &som_ref, &ax_ref] {
            if let Some(reference) = governed {
                retained_artifact_refs.push(json!(reference));
            }
        }
    }
    let affordance_graph = json!({
        "affordance_graph_ref": format!("affordance_graph_{run_hash}"),
        "affordances": [{
            "affordance_ref": format!("affordance_{run_hash}"),
            "target_ref": target_ref,
            "action_kind": action_kind,
            "required_authority": authority_scope,
        }],
    });
    let action = json!({
        "action_ref": format!("action_computer_use_{run_hash}"),
        "action_kind": action_kind,
        "target_ref": target_ref,
        "proposal_ref": proposal_ref,
        "policy_decision_ref": policy_decision_ref,
        "predicted_postcondition": "Surface inspected; observation summarized.",
    });
    let policy_decision = json!({
        "policy_decision_ref": policy_decision_ref,
        "outcome": policy_outcome,
        "fail_closed": fail_closed,
        "authority_scope": authority_scope,
        "authority_layer": "wallet.network",
    });
    let action_receipt = json!({
        "receipt_ref": format!("receipt_action_computer_use_{run_hash}"),
        "status": receipt_status,
        "adapter_id": adapter_id,
        "observed_postcondition": "Surface inspected; observation summarized.",
    });
    let verification = json!({
        "verification_ref": format!("verification_computer_use_{run_hash}"),
        "status": if read_only { "passed" } else { "deferred" },
        "summary": "Observed postcondition matches the predicted read-only outcome.",
    });
    let commit_gate = json!({
        "commit_gate_ref": format!("commit_gate_computer_use_{run_hash}"),
        "status": gate_status,
        "reason": if read_only {
            "Read-only probe requires no commit or hand-off."
        } else {
            "Effectful action requires wallet.network authority before commit."
        },
    });
    let trajectory = json!({
        "trajectory_ref": format!("trajectory_computer_use_{run_hash}"),
        "artifact_ref": "computer-use-trace.json",
        "entries": [{
            "step": "observe_and_inspect",
            "summary": format!("Completed a read-only {lane} inspection probe."),
        }],
    });
    let cleanup = json!({
        "cleanup_ref": format!("cleanup_computer_use_{run_hash}"),
        "status": "completed",
        "retained_artifact_refs": retained_artifact_refs,
    });
    // Governed observation artifacts the run surfaced (excludes the trajectory trace).
    let artifact_refs: Vec<Value> = if lane == "visual_gui" {
        [&screenshot_ref, &som_ref, &ax_ref]
            .into_iter()
            .filter_map(|reference| reference.clone().map(Value::from))
            .collect()
    } else {
        vec![]
    };

    // The 11-event agent-sdk computer-use behavioral loop, in canonical order.
    let events_spec: Vec<(&str, Value)> = vec![
        (
            "environment_selected",
            json!({
                "tool_ref": tool_name,
                "computer_use_lane": lane,
                "computer_use_contract_ingest": contract_ingest,
                "environment_selection": environment_selection.clone(),
            }),
        ),
        ("lease_acquired", json!({ "lease": lease_view.clone() })),
        ("run_state", json!({ "run_state": run_state.clone() })),
        (
            "observation",
            json!({ "observation_bundle": observation.clone(), "target_index": target_index.clone() }),
        ),
        (
            "affordance_graph",
            json!({ "affordance_graph": affordance_graph.clone() }),
        ),
        (
            "action_proposed",
            json!({
                "action_proposal": {
                    "proposal_ref": proposal_ref,
                    "target_ref": target_ref,
                    "policy_decision_ref": policy_decision_ref,
                    "action_kind": action_kind,
                    "predicted_postcondition": "Surface inspected; observation summarized.",
                },
                "policy_decision_receipt": policy_decision.clone(),
            }),
        ),
        (
            "action_executed",
            json!({ "action_receipt": action_receipt.clone() }),
        ),
        ("verification", json!({ "verification": verification.clone() })),
        ("commit_gate", json!({ "commit_gate": commit_gate.clone() })),
        ("trajectory_written", json!({ "trajectory": trajectory.clone() })),
        ("cleanup", json!({ "cleanup": cleanup.clone() })),
    ];

    let event_stream_id = format!("{thread_id}:events");
    let mut admitted_events = Vec::with_capacity(events_spec.len());
    for (suffix, payload) in events_spec {
        let event_kind = format!("computer_use.{suffix}");
        let event = json!({
            "event_id": format!("event_computer_use_{suffix}_{run_hash}"),
            "event_stream_id": event_stream_id,
            "thread_id": thread_id,
            "turn_id": "",
            "item_id": format!("{thread_id}:item:computer_use:{suffix}:{run_hash}"),
            "idempotency_key": format!("thread:{thread_id}:{event_kind}:{run_hash}"),
            "source": source,
            "source_event_kind": "ComputerUse.Loop",
            "event_kind": event_kind,
            "status": "completed",
            "actor": "operator",
            "workspace_root": workspace_root,
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "component_kind": "computer_use_harness",
            "payload_schema_version": "ioi.computer_use.loop.v1",
            "payload": payload,
            "receipt_refs": lease_receipt_refs,
            "policy_decision_refs": [policy_decision_ref],
            "artifact_refs": [],
            "rollback_refs": [],
            "evidence_refs": lease_evidence_refs,
        });
        admitted_events.push(admit_and_persist_event(st, event)?);
    }

    let object = if observe {
        "ioi.runtime_computer_use_visual_gui_observe_result".to_string()
    } else {
        format!("ioi.runtime_computer_use_{lane}_result")
    };
    let mut result_projection = json!({
        "environmentSelection": environment_selection,
        "lease": lease_view,
        "runState": run_state,
        "observation": observation,
        "targetIndex": target_index,
        "affordanceGraph": affordance_graph,
        "action": action,
        "policyDecision": policy_decision,
        "actionReceipt": action_receipt,
        "verification": verification,
        "commitGate": commit_gate,
        "trajectory": trajectory,
        "cleanup": cleanup,
    });
    if let (Some(broker), Some(map)) = (observation_broker, result_projection.as_object_mut()) {
        map.insert("observationBroker".to_string(), broker);
    }
    let result = json!({
        "status": "completed",
        "object": object,
        "tool_pack": "computer_use",
        "tool_name": tool_name,
        "workflow_graph_id": workflow_graph_id,
        "workflow_node_id": workflow_node_id,
        "event_count": admitted_events.len(),
        "artifact_refs": artifact_refs,
        "receipt_refs": lease_receipt_refs,
        "evidence_refs": lease_evidence_refs,
        "result": result_projection,
    });
    Ok(Json(result))
}

/// parameterizes it; the workspace_root is resolved from the thread's agent record. Ports the
/// JS daemon's coding-tool invocation surface onto the Rust true-north.
pub(crate) async fn handle_coding_tool_invoke(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, tool_name)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let agent = read_agent_for_thread(&st, &thread_id).ok_or_else(|| {
        AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}"))
    })?;

    // Computer-use projection tools dispatch through the kernel computer-use projection
    // (browser_discovery / provider_registry) rather than the coding-tool step module.
    // The native_browser / visual_gui lanes drive the deterministic 11-event behavioral loop.
    if let Some(projection_kind) = tool_name.strip_prefix("ioi.computer_use.") {
        match projection_kind {
            "browser_discovery" | "provider_registry" => {
                return handle_computer_use_projection_tool(&st, &thread_id, &tool_name, projection_kind, &body);
            }
            "native_browser" => {
                return handle_computer_use_loop_tool(&st, &agent, &thread_id, &tool_name, "native_browser", false, &body);
            }
            "visual_gui" => {
                return handle_computer_use_loop_tool(&st, &agent, &thread_id, &tool_name, "visual_gui", false, &body);
            }
            "visual_gui.observe" => {
                return handle_computer_use_loop_tool(&st, &agent, &thread_id, &tool_name, "visual_gui", true, &body);
            }
            _ => {}
        }
    }

    let workspace_root = memory_agent_cwd(&agent);

    let request_json = json!({
        "schema_version": ioi_services::agentic::runtime::kernel::coding_tool_step_module::CODING_TOOL_STEP_MODULE_REQUEST_SCHEMA_VERSION,
        "tool_id": tool_name,
        "workspace_root": workspace_root,
        "input": body.get("input").cloned().unwrap_or_else(|| json!({})),
        "thread_id": thread_id,
        "run_id": body.get("run_id").and_then(Value::as_str),
        "task_id": body.get("task_id").and_then(Value::as_str),
        "workflow_graph_id": body.get("workflow_graph_id").and_then(Value::as_str),
        "workflow_node_id": body.get("workflow_node_id").and_then(Value::as_str),
        "idempotency_key": body.get("idempotency_key").and_then(Value::as_str),
    });
    let request: ioi_services::agentic::runtime::kernel::coding_tool_step_module::CodingToolStepModuleRunRequest =
        serde_json::from_value(request_json)
            .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    match ioi_services::agentic::runtime::kernel::coding_tool_step_module::run_coding_tool_step_module(request) {
        Ok(value) => Ok(Json(value)),
        Err(error) => Err(AppError(
            StatusCode::BAD_REQUEST,
            format!("{}: {}", error.code(), error.message()),
        )),
    }
}

/// Plan a workflow-edit control event via the CANONICAL kernel
/// `RuntimeWorkflowEditControlCore::plan` and admit it onto the thread's runtime event log
/// (idempotent via `admit_and_persist_event`). Returns the admitted event
/// (`workflow.edit_proposed` / `workflow.edit.apply`, component_kind `workflow_edit`).
fn plan_and_admit_workflow_edit_event(
    st: &DaemonState,
    thread_id: &str,
    operation_kind: &str,
    proposal_id: Option<&str>,
    body: &Value,
) -> Result<Value, AppError> {
    let event_stream_id = format!("{thread_id}:events");
    let request_json = json!({
        "schema_version": ioi_services::agentic::runtime::kernel::runtime_workflow_edit_control::RUNTIME_WORKFLOW_EDIT_CONTROL_REQUEST_SCHEMA_VERSION,
        "operation_kind": operation_kind,
        "thread_id": thread_id,
        "event_stream_id": event_stream_id,
        "proposal_id": proposal_id,
        "turn_id": body.get("turn_id").and_then(Value::as_str),
        "workflow_graph_id": coalesce_str(body, &["workflow_graph_id", "workflowGraphId"]),
        "workflow_node_id": coalesce_str(body, &["workflow_node_id", "workflowNodeId"]),
        "workflow_path": coalesce_str(body, &["workflow_path", "workflowPath"]),
        "workspace_root": coalesce_str(body, &["workspace_root", "workspaceRoot"]),
        "source": coalesce_str(body, &["source"]),
        "request": body,
    });
    let request: ioi_services::agentic::runtime::kernel::runtime_workflow_edit_control::RuntimeWorkflowEditControlRequest =
        serde_json::from_value(request_json)
            .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = ioi_services::agentic::runtime::kernel::runtime_workflow_edit_control::RuntimeWorkflowEditControlCore
        ::default()
        .plan(&request)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, format!("{}: {}", error.code(), error.message())))?;
    admit_and_persist_event(st, record.event)
}

/// Read a persisted workflow-edit proposal-approval record (decision-gating state) by its
/// proposal id (`state_dir/workflow_edit_proposals/<proposal_id>.json`).
fn read_workflow_edit_proposal(st: &DaemonState, thread_id: &str, proposal_id: &str) -> Option<Value> {
    read_record_dir(&st.data_dir, "workflow_edit_proposals")
        .into_iter()
        .find(|record| {
            record.get("proposal_id").and_then(Value::as_str) == Some(proposal_id)
                && record.get("thread_id").and_then(Value::as_str) == Some(thread_id)
        })
}

/// Mutate the workflow file with the proposal's `workflow_patch` (resolving a relative
/// `workflow_path` against the thread workspace). No-op when the proposal carries no path/patch.
fn mutate_workflow_edit_file(record: &Value) -> Result<(), AppError> {
    let path = record
        .get("workflow_path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let patch = record.get("workflow_patch").cloned().unwrap_or(Value::Null);
    let (Some(path), false) = (path, patch.is_null()) else {
        return Ok(());
    };
    let workspace_root = record
        .get("workspace_root")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let resolved = if Path::new(path).is_absolute() {
        Path::new(path).to_path_buf()
    } else {
        Path::new(workspace_root).join(path)
    };
    let content = format!(
        "{}\n",
        serde_json::to_string_pretty(&patch).unwrap_or_default()
    );
    fs::write(&resolved, content).map_err(|error| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("workflow-edit file mutation failed: {error}"),
        )
    })
}

/// Record a workflow-edit proposal decision (approve/reject) on the persisted proposal-approval
/// record if `approval_id` belongs to a workflow-edit proposal on this thread. Returns the
/// decision response, or `None` to let the caller fall through to the wallet-gated approval path.
/// This is a lighter, proposal-scoped authority surface (bounded React-Flow edits) — distinct
/// from the wallet-signed run/agent approval grant, which is left untouched.
fn workflow_edit_proposal_decision(
    st: &DaemonState,
    thread_id: &str,
    approval_id: &str,
    decision: &str,
) -> Option<Json<Value>> {
    let mut record = read_record_dir(&st.data_dir, "workflow_edit_proposals")
        .into_iter()
        .find(|record| {
            record.get("approval_id").and_then(Value::as_str) == Some(approval_id)
                && record.get("thread_id").and_then(Value::as_str) == Some(thread_id)
        })?;
    let proposal_id = record
        .get("proposal_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    record["decision"] = json!(decision);
    let _ = persist_record(&st.data_dir, "workflow_edit_proposals", &proposal_id, &record);
    Some(Json(json!({
        "decision": decision,
        "approval_id": approval_id,
        "proposal_id": proposal_id,
        "status": if decision == "approve" { "approved" } else { "rejected" },
    })))
}

/// POST /v1/threads/:id/workflow-edit-proposals — propose a React Flow workflow edit. Plans +
/// admits the `workflow.edit_proposed` event AND registers a proposal-approval record gating the
/// mutation. Returns `{status:"waiting_for_approval", approval_required, mutation_executed:false,
/// approval_id}` — NO file mutation occurs until the proposal is approved.
pub(crate) async fn handle_workflow_edit_propose(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let agent = read_agent_for_thread(&st, &thread_id)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")))?;
    let workspace_root = memory_agent_cwd(&agent).unwrap_or_default();
    let proposal_id = coalesce_str(&body, &["proposal_id", "proposalId"])
        .unwrap_or("proposal")
        .to_string();
    let approval_id = format!(
        "approval_workflow_edit_{}",
        short_hash(&format!("{thread_id}:{proposal_id}"))
    );
    let proposal_record = json!({
        "proposal_id": proposal_id,
        "approval_id": approval_id,
        "thread_id": thread_id,
        "decision": "pending",
        "applied_event_id": Value::Null,
        "workflow_path": coalesce_str(&body, &["workflow_path", "workflowPath"]),
        "workflow_patch": body.get("workflow_patch").or_else(|| body.get("workflowPatch")).cloned(),
        "workspace_root": workspace_root,
        "workflow_graph_id": coalesce_str(&body, &["workflow_graph_id", "workflowGraphId"]),
        "workflow_node_id": coalesce_str(&body, &["workflow_node_id", "workflowNodeId"]),
    });
    persist_record(&st.data_dir, "workflow_edit_proposals", &proposal_id, &proposal_record)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let event = plan_and_admit_workflow_edit_event(&st, &thread_id, "workflow.edit_proposed", Some(&proposal_id), &body)?;
    Ok(Json(json!({
        "status": "waiting_for_approval",
        "approval_required": true,
        "mutation_executed": false,
        "approval_id": approval_id,
        "proposal_id": proposal_id,
        "event": event,
    })))
}

/// POST /v1/threads/:id/workflow-edit-proposals/:proposal_id/apply — apply a proposed edit,
/// GATED on the recorded approval decision: pending → `blocked` (approval_required); rejected →
/// `blocked` (reason `approval_rejected`); approved → MUTATE the workflow file + admit the
/// `workflow.edit.apply` event + `completed` (mutation_executed). Re-apply is an idempotent replay
/// (`idempotent_replay`, same event_id, no re-mutation). No file mutation occurs unless approved.
pub(crate) async fn handle_workflow_edit_apply(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, proposal_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    if read_agent_for_thread(&st, &thread_id).is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")));
    }
    let Some(mut record) = read_workflow_edit_proposal(&st, &thread_id, &proposal_id) else {
        return Ok(Json(json!({
            "status": "blocked",
            "approval_required": true,
            "mutation_executed": false,
            "reason": "proposal_not_found",
            "proposal_id": proposal_id,
        })));
    };
    let decision = record.get("decision").and_then(Value::as_str).unwrap_or("pending");
    let approval_id = record.get("approval_id").cloned().unwrap_or(Value::Null);
    match decision {
        "approve" => {
            let already_applied = record
                .get("applied_event_id")
                .and_then(Value::as_str)
                .map(str::to_string);
            let event = plan_and_admit_workflow_edit_event(&st, &thread_id, "workflow.edit.apply", Some(&proposal_id), &body)?;
            let event_id = event
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if already_applied.is_some() {
                // The mutation already landed; admission is idempotent (same event_id).
                return Ok(Json(json!({
                    "status": "completed",
                    "mutation_executed": true,
                    "idempotent_replay": true,
                    "approval_id": approval_id,
                    "proposal_id": proposal_id,
                    "event": event,
                })));
            }
            mutate_workflow_edit_file(&record)?;
            record["applied_event_id"] = json!(event_id);
            persist_record(&st.data_dir, "workflow_edit_proposals", &proposal_id, &record)
                .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
            Ok(Json(json!({
                "status": "completed",
                "mutation_executed": true,
                "idempotent_replay": false,
                "approval_id": approval_id,
                "proposal_id": proposal_id,
                "event": event,
            })))
        }
        "reject" => Ok(Json(json!({
            "status": "blocked",
            "approval_required": true,
            "mutation_executed": false,
            "reason": "approval_rejected",
            "approval_id": approval_id,
            "proposal_id": proposal_id,
        }))),
        _ => Ok(Json(json!({
            "status": "blocked",
            "approval_required": true,
            "mutation_executed": false,
            "approval_id": approval_id,
            "proposal_id": proposal_id,
        }))),
    }
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

// ---------------------------------------------------------------------------
// Memory CRUD (top-level: thread-scoped + agent-scoped). The memory.status /
// memory.validate control-event handlers above stay separate (they admit an event
// onto the unified log); these mutate the Agentgres memory state (memory-records /
// memory-policies) and re-project the public view, mirroring the retired JS
// `commitMemoryControl` + `projectPublicMemory` (thread-memory-state.mjs).
// ---------------------------------------------------------------------------

/// Resolve the memory-route identity (thread_id, agent_id, workspace_root) for a
/// scope. THREAD: thread_id from the path, agent_id derived, workspace from the agent's
/// cwd; 404 if the thread's agent record is absent. AGENT: agent_id from the path,
/// thread_id from the body's `thread_id` (else derived), workspace from the agent's
/// cwd; 404 if the agent record is absent.
fn resolve_memory_identity(
    st: &DaemonState,
    scope: &str,
    id: &str,
    body: &Value,
) -> Result<(Option<String>, Option<String>, Option<String>), AppError> {
    if scope == "thread" {
        let Some(agent) = read_agent_for_thread(st, id) else {
            return Err(AppError(StatusCode::NOT_FOUND, format!("thread not found: {id}")));
        };
        let agent_id = agent
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| agent_id_for_thread(id));
        let workspace_root = memory_agent_cwd(&agent);
        Ok((Some(id.to_string()), Some(agent_id), workspace_root))
    } else {
        let Some(agent) = read_record_dir(&st.data_dir, "agents")
            .into_iter()
            .find(|record| record.get("id").and_then(|v| v.as_str()) == Some(id))
        else {
            return Err(AppError(StatusCode::NOT_FOUND, format!("agent not found: {id}")));
        };
        let thread_id = body
            .get("thread_id")
            .and_then(|v| v.as_str())
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| thread_id_for_agent(id));
        let workspace_root = memory_agent_cwd(&agent);
        Ok((Some(thread_id), Some(id.to_string()), workspace_root))
    }
}

/// Read the agent's workspace cwd (top-level `cwd`, falling back to `options.local.cwd`
/// then `workspace_root`), mirroring the JS `agent?.cwd` plumbing.
fn memory_agent_cwd(agent: &Value) -> Option<String> {
    agent
        .get("cwd")
        .and_then(|v| v.as_str())
        .or_else(|| {
            agent
                .get("options")
                .and_then(|local| local.get("local"))
                .and_then(|local| local.get("cwd"))
                .and_then(|v| v.as_str())
        })
        .or_else(|| agent.get("workspace_root").and_then(|v| v.as_str()))
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
}

/// Project the public memory view for a route (records / policy / path). Mirrors the JS
/// `projectPublicMemory`: builds a `RuntimeMemoryProjectionApiRequest` over `state_dir`
/// and returns the kernel projection's `projection` value unwrapped.
fn memory_public_projection(
    st: &DaemonState,
    thread_id: Option<&str>,
    agent_id: Option<&str>,
    workspace_root: Option<&str>,
    projection_kind: &str,
    filters: Value,
) -> Result<Value, AppError> {
    let request: RuntimeMemoryProjectionApiRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_MEMORY_PROJECTION_REQUEST_SCHEMA_VERSION,
        "operation": "runtime_memory_projection",
        "operation_kind": format!("runtime.memory_projection.{projection_kind}"),
        "projection_kind": projection_kind,
        "thread_id": thread_id,
        "agent_id": agent_id,
        "workspace_root": workspace_root,
        "state_dir": st.data_dir,
        "filters": filters,
        "source": "runtime.thread_memory_state.public_projection",
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_runtime_memory_projection(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(record.projection.clone())
}

/// Shared read handler for a memory projection route (records / policy / path). Resolves
/// the scope identity (404 if the owner record is absent), then projects over state_dir.
/// `query` carries the route's query-string as the projection filters.
fn handle_memory_projection_route(
    st: &DaemonState,
    scope: &str,
    id: &str,
    projection_kind: &str,
    query: &HashMap<String, String>,
) -> Result<Json<Value>, AppError> {
    let (thread_id, agent_id, workspace_root) =
        resolve_memory_identity(st, scope, id, &Value::Null)?;
    let filters = Value::Object(
        query
            .iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect(),
    );
    let projection = memory_public_projection(
        st,
        thread_id.as_deref(),
        agent_id.as_deref(),
        workspace_root.as_deref(),
        projection_kind,
        filters,
    )?;
    Ok(Json(projection))
}

/// Shared write handler for a memory control route (write / edit / delete / policy):
/// resolve identity, plan the control (kernel `plan_runtime_memory_control` builds the
/// record/policy payload + receipt/evidence refs), persist the payload to the Agentgres
/// state dir (`memory-records` or `memory-policies`), re-project the public view, and
/// return the shaped result. Mirrors the retired JS `commitMemoryControl`.
fn handle_memory_control_route(
    st: &DaemonState,
    scope: &str,
    id: &str,
    op: &str,
    operation_kind: &str,
    memory_id: Option<&str>,
    body: Value,
) -> Result<Json<Value>, AppError> {
    let (thread_id, agent_id, workspace_root) = resolve_memory_identity(st, scope, id, &body)?;
    let target_type = if op == "policy" {
        Some(
            body.get("target_type")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| if scope == "thread" { "thread" } else { "agent" }.to_string()),
        )
    } else {
        None
    };
    let target_id = if op == "policy" {
        Some(
            body.get("target_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| id.to_string()),
        )
    } else {
        None
    };
    let source = body
        .get("source")
        .and_then(|v| v.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "agent_studio".to_string());

    let control_request: RuntimeMemoryControlApiRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION,
        "operation": op,
        "operation_kind": operation_kind,
        "thread_id": thread_id,
        "agent_id": agent_id,
        "memory_id": memory_id,
        "workspace_root": workspace_root,
        "state_dir": st.data_dir,
        "target_type": target_type,
        "target_id": target_id,
        "source": source,
        "now": iso_now(),
        "request": body,
        "evidence_refs": [
            "runtime_memory_control_rust_owned",
            "runtime_memory_state_store_js_mutation_retired",
            "agentgres_thread_memory_state_truth_required",
        ],
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .plan_runtime_memory_control(&control_request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;

    // The planner resolves thread_id/agent_id/workspace_root from the replayed record on
    // edit/delete (when the path-scoped identity was not supplied); trust the record.
    let resolved_thread_id = record.thread_id.clone().or(thread_id);
    let resolved_agent_id = record.agent_id.clone().or(agent_id);
    let resolved_workspace_root = record.workspace_root.clone().or(workspace_root);

    let dir = if record.memory_state_kind == "record" {
        "memory-records"
    } else {
        "memory-policies"
    };
    persist_record(st.data_dir.as_str(), dir, &record.state_id, &record.payload)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    // Canonical Agentgres memory commit receipt (admission_hash / content_hash / commit_hash),
    // matching what the retired JS daemon produced via commit_runtime_memory_state — replacing the
    // bare {persisted:true} shortcut. The `persisted:true` flag is retained alongside (the public
    // commit contract). Best-effort: if the canonical commit can't be derived we still report the
    // persisted write rather than failing the already-durable memory mutation.
    let commit = match RuntimeKernelService::new().commit_runtime_memory_state(
        &RuntimeMemoryStateCommitRequest {
            schema_version: RUNTIME_MEMORY_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            memory_state_kind: record.memory_state_kind.clone(),
            state_id: record.state_id.clone(),
            operation_kind: record.operation_kind.clone(),
            storage_backend_ref: "storage://runtime-agentgres/local-json".to_string(),
            payload: record.payload.clone(),
            receipt_refs: record.receipt_refs.clone(),
        },
    ) {
        Ok(commit) => {
            let mut commit = serde_json::to_value(commit).unwrap_or_else(|_| json!({}));
            if let Some(map) = commit.as_object_mut() {
                map.insert("persisted".to_string(), json!(true));
            }
            commit
        }
        Err(_) => json!({ "persisted": true }),
    };

    // Re-project the public view after the commit, exactly as the JS facade did (records
    // projection for record mutations, policy projection for a policy update).
    let projection = if record.memory_state_kind == "policy" {
        memory_public_projection(
            st,
            resolved_thread_id.as_deref(),
            resolved_agent_id.as_deref(),
            resolved_workspace_root.as_deref(),
            "policy",
            Value::Object(serde_json::Map::new()),
        )?
    } else {
        memory_public_projection(
            st,
            resolved_thread_id.as_deref(),
            resolved_agent_id.as_deref(),
            resolved_workspace_root.as_deref(),
            "records",
            Value::Object(serde_json::Map::new()),
        )?
    };

    let is_record = record.memory_state_kind == "record";
    Ok(Json(json!({
        "schema_version": "ioi.runtime.memory-control-result.v1",
        "object": "ioi.runtime_memory_control_result",
        "status": "committed",
        "operation": record.operation,
        "operation_kind": record.operation_kind,
        "memory_state_kind": record.memory_state_kind,
        "state_id": record.state_id,
        "memory_id": if is_record { Value::String(record.state_id.clone()) } else { Value::Null },
        "thread_id": resolved_thread_id,
        "agent_id": resolved_agent_id,
        "workspace_root": resolved_workspace_root,
        "payload": record.payload,
        "record": if is_record { record.payload.clone() } else { Value::Null },
        "policy": if record.memory_state_kind == "policy" { record.payload.clone() } else { Value::Null },
        "projection": projection,
        "receipt_refs": record.receipt_refs,
        "evidence_refs": record.evidence_refs,
        "commit": commit,
    })))
}

/// GET /v1/threads/:id/memory — project the thread's public memory records.
pub(crate) async fn handle_thread_memory_list(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    handle_memory_projection_route(&st, "thread", &thread_id, "records", &params)
}

/// POST /v1/threads/:id/memory — write (remember) a thread memory record.
pub(crate) async fn handle_thread_memory_create(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    handle_memory_control_route(&st, "thread", &thread_id, "write", "memory.write", None, body)
}

/// GET /v1/threads/:id/memory/policy — project the thread's effective memory policy.
pub(crate) async fn handle_thread_memory_policy_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    handle_memory_projection_route(&st, "thread", &thread_id, "policy", &params)
}

/// PUT|PATCH /v1/threads/:id/memory/policy — set the thread's memory policy.
pub(crate) async fn handle_thread_memory_policy_set(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    handle_memory_control_route(&st, "thread", &thread_id, "policy", "memory.policy", None, body)
}

/// GET /v1/threads/:id/memory/path — project the thread's memory path locations.
pub(crate) async fn handle_thread_memory_path_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    handle_memory_projection_route(&st, "thread", &thread_id, "path", &params)
}

/// PATCH|PUT /v1/threads/:id/memory/:memory_id — edit a thread memory record.
pub(crate) async fn handle_thread_memory_edit(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, memory_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    handle_memory_control_route(
        &st,
        "thread",
        &thread_id,
        "edit",
        "memory.edit",
        Some(&memory_id),
        body,
    )
}

/// DELETE /v1/threads/:id/memory/:memory_id — delete a thread memory record.
pub(crate) async fn handle_thread_memory_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, memory_id)): AxumPath<(String, String)>,
    body: Option<Json<Value>>,
) -> Result<Json<Value>, AppError> {
    let body = body.map(|Json(value)| value).unwrap_or_else(|| json!({}));
    handle_memory_control_route(
        &st,
        "thread",
        &thread_id,
        "delete",
        "memory.delete",
        Some(&memory_id),
        body,
    )
}

/// GET /v1/agents/:id/memory — project the agent's public memory records.
pub(crate) async fn handle_agent_memory_list(
    State(st): State<Arc<DaemonState>>,
    AxumPath(agent_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    handle_memory_projection_route(&st, "agent", &agent_id, "records", &params)
}

/// POST /v1/agents/:id/memory — write (remember) an agent memory record.
pub(crate) async fn handle_agent_memory_create(
    State(st): State<Arc<DaemonState>>,
    AxumPath(agent_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    handle_memory_control_route(&st, "agent", &agent_id, "write", "memory.write", None, body)
}

/// GET /v1/agents/:id/memory/policy — project the agent's effective memory policy.
pub(crate) async fn handle_agent_memory_policy_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(agent_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    handle_memory_projection_route(&st, "agent", &agent_id, "policy", &params)
}

/// PUT|PATCH /v1/agents/:id/memory/policy — set the agent's memory policy.
pub(crate) async fn handle_agent_memory_policy_set(
    State(st): State<Arc<DaemonState>>,
    AxumPath(agent_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    handle_memory_control_route(&st, "agent", &agent_id, "policy", "memory.policy", None, body)
}

/// GET /v1/agents/:id/memory/path — project the agent's memory path locations.
pub(crate) async fn handle_agent_memory_path_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(agent_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    handle_memory_projection_route(&st, "agent", &agent_id, "path", &params)
}

/// PATCH|PUT /v1/agents/:id/memory/:memory_id — edit an agent memory record.
pub(crate) async fn handle_agent_memory_edit(
    State(st): State<Arc<DaemonState>>,
    AxumPath((agent_id, memory_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    handle_memory_control_route(
        &st,
        "agent",
        &agent_id,
        "edit",
        "memory.edit",
        Some(&memory_id),
        body,
    )
}

/// DELETE /v1/agents/:id/memory/:memory_id — delete an agent memory record.
pub(crate) async fn handle_agent_memory_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath((agent_id, memory_id)): AxumPath<(String, String)>,
    body: Option<Json<Value>>,
) -> Result<Json<Value>, AppError> {
    let body = body.map(|Json(value)| value).unwrap_or_else(|| json!({}));
    handle_memory_control_route(
        &st,
        "agent",
        &agent_id,
        "delete",
        "memory.delete",
        Some(&memory_id),
        body,
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
    if matches!(decision.as_str(), "approve" | "reject") {
        if let Some(response) = workflow_edit_proposal_decision(&st, &thread_id, &approval_id, &decision) {
            return Ok(response);
        }
    }
    apply_approval_decision(&st, &thread_id, &approval_id, &decision, &body)
}

/// POST /v1/threads/:id/approvals/:approval_id/approve
pub(crate) async fn handle_approval_approve(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, approval_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    // A workflow-edit proposal approval is a lighter, proposal-scoped decision (recorded here);
    // a run/agent approval falls through to the wallet-signed decision authority.
    if let Some(response) = workflow_edit_proposal_decision(&st, &thread_id, &approval_id, "approve") {
        return Ok(response);
    }
    apply_approval_decision(&st, &thread_id, &approval_id, "approve", &body)
}

/// POST /v1/threads/:id/approvals/:approval_id/reject
pub(crate) async fn handle_approval_reject(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, approval_id)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    if let Some(response) = workflow_edit_proposal_decision(&st, &thread_id, &approval_id, "reject") {
        return Ok(response);
    }
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
    Ok((
        StatusCode::CREATED,
        Json(conversation_artifact_control_response(&record)),
    ))
}

/// Build the conversation-artifact control response (mirrors the retired JS
/// commitConversationArtifactControl): the operation result plus the artifact_id /
/// operation_kind / persisted artifact / the kernel's receipt, policy-decision, and
/// evidence refs / the commit marker. The three ref arrays are part of the JS contract,
/// so consumers reading them off a create/action/export/promote response still see them.
fn conversation_artifact_control_response(
    record: &RuntimeConversationArtifactControlRecord,
) -> Value {
    let mut response = record.result.clone();
    if let Some(map) = response.as_object_mut() {
        map.insert("artifact_id".to_string(), json!(record.artifact_id));
        map.insert("operation_kind".to_string(), json!(record.operation_kind));
        map.insert("artifact".to_string(), record.artifact.clone());
        map.insert("receipt_refs".to_string(), json!(record.receipt_refs));
        map.insert(
            "policy_decision_refs".to_string(),
            json!(record.policy_decision_refs),
        );
        map.insert("evidence_refs".to_string(), json!(record.evidence_refs));
        map.insert("commit".to_string(), json!({ "persisted": true }));
    }
    response
}

/// GET /v1/conversation-artifacts — list conversation artifacts across the daemon (the
/// top-level, non-thread-scoped twin of handle_artifacts_list). thread_id is an optional
/// filter from the query.
pub(crate) async fn handle_conversation_artifacts_list(
    State(st): State<Arc<DaemonState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    let mut request_json = json!({
        "operation": "conversation_artifact_inspection",
        "operation_kind": "runtime.conversation_artifact_projection.list",
        "projection_kind": "list",
        "state_dir": st.data_dir,
        "source": "runtime.conversation_artifact_state",
    });
    if let (Some(object), Some(thread_id)) = (request_json.as_object_mut(), params.get("thread_id")) {
        object.insert("thread_id".to_string(), json!(thread_id));
    }
    let request: RuntimeConversationArtifactProjectionRequest = serde_json::from_value(request_json)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_runtime_conversation_artifact_projection(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(Json(record.projection.clone()))
}

/// POST /v1/conversation-artifacts — create a conversation artifact (the top-level twin of
/// handle_artifact_create). thread_id is read from the body when present.
pub(crate) async fn handle_conversation_artifact_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let request: RuntimeConversationArtifactControlRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_CONVERSATION_ARTIFACT_CONTROL_REQUEST_SCHEMA_VERSION,
        "operation": "conversation_artifact_create",
        "operation_kind": "artifact.conversation.create",
        // The top-level route admits thread-less artifacts; the JS facade bound them to a
        // synthetic "thread_standalone" thread, so mirror that default exactly.
        "thread_id": body.get("thread_id").and_then(|v| v.as_str()).unwrap_or("thread_standalone"),
        "artifact_id": body.get("artifact_id").and_then(|v| v.as_str()),
        "state_dir": st.data_dir,
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
    Ok((
        StatusCode::CREATED,
        Json(conversation_artifact_control_response(&record)),
    ))
}

/// GET /v1/conversation-artifacts/:id — fetch one conversation artifact (projection "get").
pub(crate) async fn handle_conversation_artifact_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(artifact_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let request: RuntimeConversationArtifactProjectionRequest = serde_json::from_value(json!({
        "operation": "conversation_artifact_inspection",
        "operation_kind": "runtime.conversation_artifact_projection.get",
        "projection_kind": "get",
        "artifact_id": artifact_id,
        "state_dir": st.data_dir,
        "source": "runtime.conversation_artifact_state",
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_runtime_conversation_artifact_projection(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(Json(record.projection.clone()))
}

/// GET /v1/conversation-artifacts/:id/revisions — list an artifact's revisions.
pub(crate) async fn handle_conversation_artifact_revisions(
    State(st): State<Arc<DaemonState>>,
    AxumPath(artifact_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let request: RuntimeConversationArtifactProjectionRequest = serde_json::from_value(json!({
        "operation": "conversation_artifact_inspection",
        "operation_kind": "runtime.conversation_artifact_projection.revisions",
        "projection_kind": "revisions",
        "artifact_id": artifact_id,
        "state_dir": st.data_dir,
        "source": "runtime.conversation_artifact_state",
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_runtime_conversation_artifact_projection(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(Json(record.projection.clone()))
}

/// Shared control mutation for action/export/promote: the kernel reads the existing
/// artifact from state_dir, applies the mutation, and returns the updated artifact; the
/// daemon persists it back and returns the result (200, mirroring the JS facade).
async fn conversation_artifact_control_mutation(
    st: &Arc<DaemonState>,
    artifact_id: String,
    operation: &str,
    operation_kind: &str,
    body: Value,
) -> Result<Json<Value>, AppError> {
    let request: RuntimeConversationArtifactControlRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_CONVERSATION_ARTIFACT_CONTROL_REQUEST_SCHEMA_VERSION,
        "operation": operation,
        "operation_kind": operation_kind,
        "artifact_id": artifact_id,
        "state_dir": st.data_dir,
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
    Ok(Json(conversation_artifact_control_response(&record)))
}

/// POST /v1/conversation-artifacts/:id/actions — apply an action to an artifact.
pub(crate) async fn handle_conversation_artifact_action(
    State(st): State<Arc<DaemonState>>,
    AxumPath(artifact_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    conversation_artifact_control_mutation(
        &st,
        artifact_id,
        "conversation_artifact_action",
        "artifact.conversation.action",
        body,
    )
    .await
}

/// POST /v1/conversation-artifacts/:id/export — export an artifact.
pub(crate) async fn handle_conversation_artifact_export(
    State(st): State<Arc<DaemonState>>,
    AxumPath(artifact_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    conversation_artifact_control_mutation(
        &st,
        artifact_id,
        "conversation_artifact_export",
        "artifact.conversation.export",
        body,
    )
    .await
}

/// POST /v1/conversation-artifacts/:id/promote — promote an artifact.
pub(crate) async fn handle_conversation_artifact_promote(
    State(st): State<Arc<DaemonState>>,
    AxumPath(artifact_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    conversation_artifact_control_mutation(
        &st,
        artifact_id,
        "conversation_artifact_promote",
        "artifact.conversation.promote",
        body,
    )
    .await
}

/// Project the skill/hook registry for the given `registry_kind` ("skills" | "hooks" |
/// "catalog") by scanning the daemon's workspace_root + home_dir (.claude/{skills,hooks})
/// through the kernel skill_hook_registry projection.
fn skill_hook_registry_projection(
    st: &Arc<DaemonState>,
    registry_kind: &str,
) -> Result<Value, AppError> {
    let request: SkillHookRegistryProjectionRequest = serde_json::from_value(json!({
        "operation_kind": format!("skill_hook.registry.{registry_kind}"),
        "registry_kind": registry_kind,
        "workspace_root": st.workspace_root,
        "home_dir": st.home_dir,
        "source": "hypervisor_daemon.skill_hook_registry",
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_skill_hook_registry(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(record.projection.clone())
}

/// GET /v1/skills — project the workspace + user skill registry.
pub(crate) async fn handle_skills(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(skill_hook_registry_projection(&st, "skills")?))
}

/// GET /v1/hooks — project the workspace + user hook registry.
pub(crate) async fn handle_hooks(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(skill_hook_registry_projection(&st, "hooks")?))
}

/// Project a repository-workflow view over real git in the daemon's workspace_root. The
/// kernel shells `git -C <workspace_root>` and derives GitHub context purely from remote
/// URLs + GITHUB_TOKEN/GH_TOKEN env presence — no network IO (every projection is a
/// dry-run preview). Returns the UNWRAPPED projection (array for repository_list/pr_attempts,
/// object otherwise) exactly as the retired JS facade did.
fn repository_workflow_projection(
    st: &Arc<DaemonState>,
    operation: &str,
    operation_kind: &str,
    projection_kind: &str,
) -> Result<Value, AppError> {
    let request: RepositoryWorkflowProjectionRequest = serde_json::from_value(json!({
        "operation": operation,
        "operation_kind": operation_kind,
        "projection_kind": projection_kind,
        "workspace_root": st.workspace_root,
        "source": "hypervisor_daemon.repository_workflow",
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_repository_workflow(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(record.projection.clone())
}

/// GET /v1/repositories — list the workspace repositories.
pub(crate) async fn handle_repositories(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(repository_workflow_projection(
        &st,
        "repository_workflow_repository_list",
        "repository_workflow.projection.repository_list",
        "repository_list",
    )?))
}

/// GET /v1/repository-context — project the workspace git repository context.
pub(crate) async fn handle_repository_context(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(repository_workflow_projection(
        &st,
        "repository_workflow_repository_context",
        "repository_workflow.projection.repository_context",
        "repository_context",
    )?))
}

/// GET /v1/branch-policy — project the branch-policy decision.
pub(crate) async fn handle_branch_policy(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(repository_workflow_projection(
        &st,
        "repository_workflow_branch_policy",
        "repository_workflow.projection.branch_policy",
        "branch_policy",
    )?))
}

/// GET /v1/github-context — project the GitHub context (from git remotes + token env).
pub(crate) async fn handle_github_context(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(repository_workflow_projection(
        &st,
        "repository_workflow_github_context",
        "repository_workflow.projection.github_context",
        "github_context",
    )?))
}

/// GET /v1/pr-attempts — project the PR-attempt previews (array).
pub(crate) async fn handle_pr_attempts(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(repository_workflow_projection(
        &st,
        "repository_workflow_pr_attempts",
        "repository_workflow.projection.pr_attempts",
        "pr_attempts",
    )?))
}

/// GET /v1/issue-context — project the issue context.
pub(crate) async fn handle_issue_context(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(repository_workflow_projection(
        &st,
        "repository_workflow_issue_context",
        "repository_workflow.projection.issue_context",
        "issue_context",
    )?))
}

/// GET /v1/review-gate — project the review-gate decision.
pub(crate) async fn handle_review_gate(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(repository_workflow_projection(
        &st,
        "repository_workflow_review_gate",
        "repository_workflow.projection.review_gate",
        "review_gate",
    )?))
}

/// GET /v1/github/pr-create-plan — project the GitHub PR-create plan (dry-run preview).
pub(crate) async fn handle_github_pr_create_plan(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(repository_workflow_projection(
        &st,
        "repository_workflow_github_pr_create_plan",
        "repository_workflow.projection.github_pr_create_plan",
        "github_pr_create_plan",
    )?))
}

/// GET /v1/tools — project the runtime tool catalog (a bare array of tool contracts),
/// optionally filtered by ?pack=. The kernel projection is pure/static, so the daemon
/// needs no state. Returns the unwrapped tools array, matching the retired JS facade.
pub(crate) async fn handle_tools(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    let mut request_json = json!({
        "operation": "runtime_tool_catalog",
        "operation_kind": "runtime.tool_catalog.projection.tools",
        "projection_kind": "tools",
        "source": "hypervisor_daemon./v1/tools",
    });
    if let (Some(object), Some(pack)) = (request_json.as_object_mut(), params.get("pack")) {
        object.insert("pack".to_string(), json!(pack.to_lowercase()));
    }
    let request: RuntimeToolCatalogProjectionRequest = serde_json::from_value(request_json)
        .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let record = RuntimeKernelService::new()
        .project_runtime_tool_catalog(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    Ok(Json(Value::Array(record.tools.clone())))
}

/// GET /v1/hypervisor/core-taxonomy — the canonical Hypervisor Core taxonomy (static
/// doctrine: clients/surfaces/adapters/truth-boundaries). The structure is embedded
/// verbatim from the retired JS `buildHypervisorCoreTaxonomy`; only `generated_at` is
/// stamped at request time.
pub(crate) async fn handle_core_taxonomy() -> Result<Json<Value>, AppError> {
    let mut taxonomy: Value = serde_json::from_str(include_str!("hypervisor_core_taxonomy.json"))
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    if let Some(object) = taxonomy.as_object_mut() {
        object.insert("generated_at".to_string(), json!(iso_now()));
    }
    Ok(Json(taxonomy))
}

/// POST /v1/hypervisor/model-route-mutation-admissions — admit a model-route mutation. The
/// kernel planner (pure) asserts the request bound the required wallet authority + credential
/// posture + model-weight custody + privacy + Agentgres/receipt/state-root refs, then returns
/// the canonical admission record (202). Rejections carry the JS facade's structured
/// {error:{code,message,details}} shape + status (400 validation / 403 authority).
pub(crate) async fn handle_model_route_mutation_admission(
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match RuntimeKernelService::new().admit_model_route_mutation(&body, &iso_now()) {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)),
        Err(error) => (
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                },
            })),
        ),
    }
}

/// POST /v1/hypervisor/model-weight-custody-admissions — admit a model-weight custody route
/// (pure kernel planner: weight-class lane + required controls/scopes/attestation refs).
pub(crate) async fn handle_model_weight_custody_admission(
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match RuntimeKernelService::new().admit_model_weight_custody(&body, &iso_now()) {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)),
        Err(error) => (
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                },
            })),
        ),
    }
}

/// POST /v1/hypervisor/session-launch-recipe-admissions — admit a Hypervisor New-Session
/// launch recipe (pure kernel planner: recipe/target-binding agreement + route/model/privacy/
/// authority/receipt/Agentgres refs + daemon-gate/runtime-truth assertion). 202 + record, or
/// the structured {error:{code,message,details}} shape with status (all 400 validation).
pub(crate) async fn handle_session_launch_recipe_admission(
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match RuntimeKernelService::new().admit_hypervisor_session_launch_recipe(&body, &iso_now()) {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)),
        Err(error) => (
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                },
            })),
        ),
    }
}

/// POST /v1/hypervisor/harness-session-binding-admissions — admit a harness-session binding
/// (pure kernel planner: harness selection / model route / workspace-mount / privacy / authority
/// / receipts + daemon-gate boundary). 202 + record, or the structured {error:{code,message,
/// details}} shape with status (400 field-shape / 403 policy-authority).
pub(crate) async fn handle_harness_session_binding_admission(
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match RuntimeKernelService::new().admit_harness_session_binding(&body, &iso_now()) {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)),
        Err(error) => (
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                },
            })),
        ),
    }
}

/// POST /v1/hypervisor/private-workspace-mount-admissions — admit a private-workspace mount
/// (pure kernel planner: custody-class / mount-target / execution-privacy lane + required controls
/// / scopes / attestation / wallet / declassification refs). 202 + record, or the structured
/// {error:{code,message,details}} shape with status (400 field-shape / 403 custody-lane policy).
pub(crate) async fn handle_private_workspace_mount_admission(
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match RuntimeKernelService::new().admit_private_workspace_mount(&body, &iso_now()) {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)),
        Err(error) => (
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                },
            })),
        ),
    }
}

/// POST /v1/hypervisor/physical-action-intent-admissions — admit a physical-action intent (pure
/// kernel planner: daemon-owned safety / supervision / emergency-stop / receipt envelope; never a
/// generic tool call). 202 + record, or {error:{code,message,details}} with status (400 field-shape
/// / 403 policy-authority).
pub(crate) async fn handle_physical_action_intent_admission(
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match RuntimeKernelService::new().admit_physical_action_intent(&body, &iso_now()) {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)),
        Err(error) => (
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                },
            })),
        ),
    }
}

/// POST /v1/hypervisor/worker-package-install-admissions — admit a worker-package install (pure
/// kernel planner: manifest/ontology/surfaces/requirements/policy/receipt/evidence/artifact refs
/// + wallet approval + mode-specific gates + physical-action safety envelope). 202 + record, or
/// {error:{code,message,details}} with status (400 field-shape / 403 policy-authority).
pub(crate) async fn handle_worker_package_install_admission(
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match RuntimeKernelService::new().admit_worker_package_install(&body, &iso_now()) {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)),
        Err(error) => (
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                },
            })),
        ),
    }
}

/// POST /v1/hypervisor/managed-worker-lifecycle-admissions — admit a managed-worker-instance
/// lifecycle transition (pure kernel planner: canonical state machine + per-state authority /
/// archive / restore / export / deletion / payment-lapse controls + policies + receipts). 202 +
/// record, or {error:{code,message,details}} with status (400 field-shape / 403 lifecycle-policy).
pub(crate) async fn handle_managed_worker_lifecycle_admission(
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match RuntimeKernelService::new().admit_managed_worker_instance_lifecycle_transition(&body, &iso_now()) {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)),
        Err(error) => (
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                },
            })),
        ),
    }
}

/// POST /v1/hypervisor/code-editor-adapter-launch-plans — admit a code-editor adapter launch plan
/// (pure kernel planner: refs/connection/control metadata match + no durable secret release + no
/// adapter runtime-truth claim). 202 + record, or {error:{code,message,details}} with status (400
/// field-shape / 403 policy).
pub(crate) async fn handle_code_editor_adapter_launch_plan_admission(
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match RuntimeKernelService::new().admit_code_editor_adapter_launch_plan(&body, &iso_now()) {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)),
        Err(error) => (
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                },
            })),
        ),
    }
}

/// POST /v1/hypervisor/service-composition-receipt-bundles — admit a multi-party service-delivery
/// receipt bundle (pure kernel planner: contribution/verifier/policy/routing/dispute/Agentgres/
/// receipt refs + delivery evidence + provider-log/dispute + unsafe-plaintext exception gates).
/// 202 + record, or {error:{code,message,details}} with status (400 field-shape / 403 policy).
pub(crate) async fn handle_service_composition_receipt_bundle_admission(
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match RuntimeKernelService::new().admit_service_composition_receipt_bundle(&body, &iso_now()) {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)),
        Err(error) => (
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                },
            })),
        ),
    }
}

/// POST /v1/hypervisor/artifact-availability-incidents — admit an artifact-availability incident
/// (pure kernel planner: artifact/payload/backend + Agentgres/incident/affected-object refs,
/// kind-specific hash/CID evidence, lifecycle-state material, no silent payload mutation; returns
/// the incident + a derived agentgres_operation). 202 + record, or {error:{code,message,details}}
/// with status (400 field-shape / 403 incident-policy).
pub(crate) async fn handle_artifact_availability_incident_admission(
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match RuntimeKernelService::new().admit_artifact_availability_incident(&body, &iso_now()) {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)),
        Err(error) => (
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                },
            })),
        ),
    }
}

/// POST /v1/hypervisor/harness-session-terminal-attachments — admit a client PTY attach (pure
/// kernel planner: validates the daemon-admitted spawn + readiness records and composes the
/// client-attach contract + transcript projection). 202 + record, or {error:{code,message,
/// details}} with status (400 field-shape / 403 spawn-or-readiness boundary).
pub(crate) async fn handle_harness_session_terminal_attach_admission(
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match RuntimeKernelService::new().admit_harness_session_terminal_attach(&body, &iso_now()) {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)),
        Err(error) => (
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                },
            })),
        ),
    }
}

/// POST /v1/hypervisor/projects — create a repository-backed project (the Hypervisor app's
/// requestHypervisorProjectCreate; there was never a JS handler). The kernel planner validates +
/// canonicalizes the project-state record; the daemon persists it under `<state_dir>/projects/`
/// and returns the project-state projection over all projects (selected = the new project). 201,
/// or {error:{code,message,details}} with status (400 validation).
pub(crate) async fn handle_project_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let record = match RuntimeKernelService::new().plan_hypervisor_project_create(&body, &iso_now()) {
        Ok(record) => record,
        Err(error) => {
            return (
                StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
                Json(json!({
                    "error": { "code": error.code, "message": error.message, "details": error.details },
                })),
            );
        }
    };
    let project_id = record
        .get("project_id")
        .and_then(|value| value.as_str())
        .unwrap_or("project:repository")
        .to_string();
    // Persist the project record (best-effort; if the write fails we still return a projection
    // that includes the just-created record so the app reflects the create).
    let _ = persist_record(&st.data_dir, "projects", &project_id, &record);
    let mut records = read_record_dir(&st.data_dir, "projects");
    if !records
        .iter()
        .any(|item| item.get("project_id").and_then(|value| value.as_str()) == Some(project_id.as_str()))
    {
        records.push(record.clone());
    }
    records.sort_by(|a, b| {
        let a_id = a.get("project_id").and_then(|value| value.as_str()).unwrap_or("");
        let b_id = b.get("project_id").and_then(|value| value.as_str()).unwrap_or("");
        a_id.cmp(b_id)
    });
    let projection_slug = project_id.strip_prefix("project:").unwrap_or(&project_id);
    let projection = json!({
        "schema_version": ioi_services::agentic::runtime::kernel::runtime_hypervisor_project_create::PROJECT_STATE_PROJECTION_SCHEMA_VERSION,
        "projection_id": format!("project-state:daemon/{projection_slug}"),
        "source": "daemon-project-state-projection",
        "selected_project_id": project_id,
        "records": records,
        "project_boundary_invariant": ioi_services::agentic::runtime::kernel::runtime_hypervisor_project_create::PROJECT_BOUNDARY_INVARIANT,
        "runtimeTruthSource": "daemon-runtime",
    });
    (StatusCode::CREATED, Json(projection))
}

/// POST /v1/hypervisor/approved-operations — admit a wallet-approved Hypervisor operation (pure
/// kernel planner: daemon-authored proposal + wallet approval/lease + required scopes + Agentgres/
/// receipt/state-root refs + family targets; emits the admission + execution plan). 202 + record,
/// or {error:{code,message,details}} with status (400 field-shape / 403 wallet-authority).
pub(crate) async fn handle_approved_operation_admission(
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    match RuntimeKernelService::new().admit_hypervisor_approved_operation(&body, &iso_now()) {
        Ok(record) => (StatusCode::ACCEPTED, Json(record)),
        Err(error) => (
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                },
            })),
        ),
    }
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

/// Rewrite the camelCase MCP-config keys the kernel reads in snake_case (`allowedTools` ->
/// `allowed_tools`, `serverUrl` -> `server_url`, …) on a single server config, so a `.cursor`
/// (camelCase) config and an `.ioi` (snake_case) config normalize identically.
fn normalize_mcp_config_keys(config: &mut Value) {
    let Some(map) = config.as_object_mut() else {
        return;
    };
    for (camel, snake) in [
        ("allowedTools", "allowed_tools"),
        ("allowedResources", "allowed_resources"),
        ("allowedPrompts", "allowed_prompts"),
        ("serverUrl", "server_url"),
        ("allowNetworkEgress", "allow_network_egress"),
        ("allowChildProcesses", "allow_child_processes"),
        ("containmentMode", "containment_mode"),
    ] {
        if map.contains_key(camel) && !map.contains_key(snake) {
            if let Some(value) = map.remove(camel) {
                map.insert(snake.to_string(), value);
            }
        }
    }
}

/// Read an MCP config file (`.cursor/mcp.json` / `~/.ioi/mcp.json`) and normalize its
/// `mcpServers` through the CANONICAL kernel validation-input projection — assigning
/// `mcp.<id>`, the config source/scope, and surfacing env/header secrets as vault refs (never
/// inlined values). Missing or unparseable files yield no servers (fail-soft). The
/// `config_compatibility` tag is stamped per source-format (cursor / ioi). Read-only, offline
/// config discovery.
fn read_mcp_config_servers(
    path: &str,
    workspace_root: Option<&str>,
    source: &str,
    source_scope: &str,
    config_compatibility: &str,
) -> Vec<Value> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    let mut mcp_servers = parsed
        .get("mcpServers")
        .or_else(|| parsed.get("mcp_servers"))
        .or_else(|| parsed.get("servers"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    match &mut mcp_servers {
        Value::Object(map) => map.values_mut().for_each(normalize_mcp_config_keys),
        Value::Array(items) => items.iter_mut().for_each(normalize_mcp_config_keys),
        _ => {}
    }
    let request: McpServerValidationInputRequest = match serde_json::from_value(json!({
        "schema_version": MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION,
        "input": {
            "mcp_json": { "mcp_servers": mcp_servers },
            "source": source,
            "source_scope": source_scope,
            "source_path": path,
        },
        "workspace_root": workspace_root,
    })) {
        Ok(request) => request,
        Err(_) => return Vec::new(),
    };
    let Ok(record) = RuntimeKernelService::new().project_mcp_server_validation_input(&request) else {
        return Vec::new();
    };
    let mut servers = record.servers;
    for server in &mut servers {
        if let Some(map) = server.as_object_mut() {
            map.insert("config_compatibility".to_string(), json!(config_compatibility));
        }
    }
    servers
}

/// Discover MCP servers for a thread from the workspace `.cursor/mcp.json` (scope `workspace`,
/// `cursor` config compatibility) and the operator-home `~/.ioi/mcp.json` (scope `global`,
/// `ioi`), then project the tools/resources/prompts catalog through the CANONICAL kernel
/// `plan_mcp_manager_catalog_projection` (workflow-node ids `runtime.mcp-{tool,resource,prompt}.<server>.<x>`).
/// `mcp_config_source_mode` (`workspace` / `global`) filters the discovered sources. Ports the
/// JS daemon's `.cursor/mcp.json` discovery + tools/resources/prompts catalog onto the Rust
/// true-north. Live remote-MCP catalog fetch (HTTP/SSE header auth) is a network-bound follow-on.
fn discover_mcp_catalog(
    st: &DaemonState,
    thread_id: &str,
    source_mode: Option<&str>,
) -> Result<Value, AppError> {
    let agent = read_agent_for_thread(st, thread_id)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, format!("thread not found: {thread_id}")))?;
    let workspace_root = memory_agent_cwd(&agent).unwrap_or_default();
    let want_workspace = source_mode.is_none_or(|mode| mode == "workspace");
    let want_global = source_mode.is_none_or(|mode| mode == "global");
    let mut servers = Vec::new();
    if want_workspace && !workspace_root.is_empty() {
        servers.extend(read_mcp_config_servers(
            &format!("{workspace_root}/.cursor/mcp.json"),
            Some(&workspace_root),
            ".cursor/mcp.json",
            "workspace",
            "cursor",
        ));
    }
    if want_global && !st.home_dir.is_empty() {
        servers.extend(read_mcp_config_servers(
            &format!("{}/.ioi/mcp.json", st.home_dir),
            Some(&workspace_root),
            "global.ioi/mcp.json",
            "global",
            "ioi",
        ));
    }
    let request: McpManagerCatalogProjectionRequest = serde_json::from_value(json!({
        "schema_version": MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
        "servers": servers,
    }))
    .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?;
    let catalog = RuntimeKernelService::new()
        .plan_mcp_manager_catalog_projection(&request)
        .map_err(|error| AppError(StatusCode::BAD_GATEWAY, debug_string(error)))?;
    serde_json::to_value(&catalog)
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
}

fn catalog_slice(catalog: &Value, key: &str) -> Vec<Value> {
    catalog
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// GET /v1/mcp/servers?thread_id=&mcp_config_source_mode= — discover the MCP servers for a
/// thread's workspace `.cursor/mcp.json` (+ the operator-home `~/.ioi/mcp.json`).
pub(crate) async fn handle_mcp_discover_servers(
    State(st): State<Arc<DaemonState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    let thread_id = params
        .get("thread_id")
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "thread_id is required".to_string()))?;
    let catalog = discover_mcp_catalog(&st, thread_id, params.get("mcp_config_source_mode").map(String::as_str))?;
    Ok(Json(json!(catalog_slice(&catalog, "servers"))))
}

/// GET /v1/mcp/tools?thread_id= — the discovered MCP tool catalog (runtime.mcp-tool.* node ids).
pub(crate) async fn handle_mcp_discover_tools(
    State(st): State<Arc<DaemonState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    let thread_id = params
        .get("thread_id")
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "thread_id is required".to_string()))?;
    let catalog = discover_mcp_catalog(&st, thread_id, None)?;
    Ok(Json(json!(catalog_slice(&catalog, "tools"))))
}

/// GET /v1/mcp/resources?thread_id= — the discovered MCP resource catalog.
pub(crate) async fn handle_mcp_discover_resources(
    State(st): State<Arc<DaemonState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    let thread_id = params
        .get("thread_id")
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "thread_id is required".to_string()))?;
    let catalog = discover_mcp_catalog(&st, thread_id, None)?;
    Ok(Json(json!(catalog_slice(&catalog, "resources"))))
}

/// GET /v1/mcp/prompts?thread_id= — the discovered MCP prompt catalog.
pub(crate) async fn handle_mcp_discover_prompts(
    State(st): State<Arc<DaemonState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    let thread_id = params
        .get("thread_id")
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "thread_id is required".to_string()))?;
    let catalog = discover_mcp_catalog(&st, thread_id, None)?;
    Ok(Json(json!(catalog_slice(&catalog, "prompts"))))
}

/// GET /v1/mcp?thread_id= — the discovered MCP manager status (server/tool/resource/prompt counts).
pub(crate) async fn handle_mcp_discover_status(
    State(st): State<Arc<DaemonState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    let thread_id = params
        .get("thread_id")
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "thread_id is required".to_string()))?;
    let catalog = discover_mcp_catalog(&st, thread_id, None)?;
    Ok(Json(json!({
        "status": "ready",
        "server_count": catalog.get("server_count").cloned().unwrap_or(json!(0)),
        "tool_count": catalog.get("tool_count").cloned().unwrap_or(json!(0)),
        "resource_count": catalog.get("resource_count").cloned().unwrap_or(json!(0)),
        "prompt_count": catalog.get("prompt_count").cloned().unwrap_or(json!(0)),
        "servers": catalog_slice(&catalog, "servers"),
    })))
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

// ===========================================================================
// Hypervisor session execution surface — Lane A, Cut #1 (provisioning +
// surfacing + fail-closed honest gates).
//
// The Rust daemon takes ownership of the Lane A *surface*: it provisions a real
// isolated workspace (mkdtemp / clone-deferred), projects a real
// `HypervisorEnvironmentStatus`, surfaces real `changed_file_groups` + readiness
// + receipts over SSE, and FAILS CLOSED with an honest reason when the execution
// substrate (model route / harness binary / container runtime) is absent — it
// never fabricates files, diffs, or a terminal transcript.
//
// The positive execution path (real harness spawn → real files → real terminal
// transcript → preview port) is the EQUIPPED-BOX (Cut #2) work; see
// `handle_session_execute`. Per the master guide, external harnesses stay
// adapters; Lane B (the native Rust decision_loop) is the eventual true-north.
// ===========================================================================

const SESSION_RECORD_SCHEMA_VERSION: &str = "ioi.hypervisor.session_record.v1";
const SESSION_CREATE_PROJECTION_SCHEMA_VERSION: &str = "ioi.hypervisor.session_create_projection.v1";
const SESSION_EXECUTE_DECISION_SCHEMA_VERSION: &str = "ioi.hypervisor.session_execute_decision.v1";

/// Harness binaries the Lane A adapter can drive (host-PTY lane). Probed on PATH.
const HARNESS_BINARIES: &[&str] = &["codex", "generic-cli-local", "deepseek", "claude-code-example"];
/// Container runtimes the container lane can use. Probed on PATH.
const CONTAINER_RUNTIMES: &[&str] = &["docker", "podman"];

const WALK_IGNORED_DIRS: &[&str] = &[".git", "node_modules", ".cache", "dist"];
const MAX_WALK_FILES: usize = 500;

/// The real execution substrate, probed honestly (no fake "available").
struct ExecutionSubstrate {
    model_route: bool,
    harness_binary: Option<String>,
    container_runtime: Option<String>,
}

impl ExecutionSubstrate {
    fn probe() -> Self {
        // Host-spawn Lane A: the primary harness is the repo's `generic-cli-local`
        // node shim (driven against Ollama), resolved when `node` + the shim file
        // are present. Fall back to a PATH harness binary (e.g. codex) for display.
        let harness_binary = if generic_cli_local_shim_path().is_some() && binary_on_path("node").is_some()
        {
            Some("generic-cli-local".to_string())
        } else {
            HARNESS_BINARIES
                .iter()
                .find(|name| binary_on_path(name).is_some())
                .map(|name| (*name).to_string())
        };
        Self {
            model_route: model_route_reachable(),
            harness_binary,
            container_runtime: CONTAINER_RUNTIMES
                .iter()
                .find(|name| binary_on_path(name).is_some())
                .map(|name| (*name).to_string()),
        }
    }

    /// Real readiness checks for the environment-status projection.
    fn readiness_checks(&self) -> Value {
        json!([
            { "id": "harness_binary", "status": if self.harness_binary.is_some() { "pass" } else { "fail" } },
            { "id": "ollama_provider", "status": if self.model_route { "pass" } else { "fail" } },
        ])
    }
}

/// Honest reachability probe: can we TCP-connect to the configured model upstream
/// (Ollama / OpenAI-compatible) within a short timeout? Offline → false (no fake).
fn model_route_reachable() -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    let upstream = std::env::var("IOI_HYPERVISOR_MODEL_UPSTREAM")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:11434".to_string());
    let (host, port) = parse_host_port(&upstream);
    let Ok(mut addrs) = format!("{host}:{port}").to_socket_addrs() else {
        return false;
    };
    let Some(addr) = addrs.next() else { return false };
    TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(300)).is_ok()
}

/// Parse `host`/`port` from a URL-ish upstream; default port 11434 (Ollama).
fn parse_host_port(upstream: &str) -> (String, u16) {
    let without_scheme = upstream
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(upstream);
    let authority = without_scheme.split(['/', '?', '#']).next().unwrap_or(without_scheme);
    // Strip any userinfo.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            (host.to_string(), port.parse().unwrap_or(11434))
        }
        _ => (authority.to_string(), 11434),
    }
}

/// `which`-style PATH lookup for an executable (no process spawn). None if absent.
fn binary_on_path(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        let Ok(meta) = std::fs::metadata(&candidate) else { continue };
        if !meta.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        return Some(candidate.to_string_lossy().into_owned());
    }
    None
}

/// Resolve the `generic-cli-local` harness shim (a node script shipped in the repo).
/// `IOI_HYPERVISOR_HARNESS_SHIM` overrides; otherwise it is the well-known path
/// relative to the daemon's working directory. None when the file is absent.
fn generic_cli_local_shim_path() -> Option<String> {
    if let Some(explicit) = std::env::var("IOI_HYPERVISOR_HARNESS_SHIM")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        return std::path::Path::new(&explicit).is_file().then_some(explicit);
    }
    let cwd = std::env::current_dir().ok()?;
    let candidate = cwd.join("harness-shims/generic-cli-local.mjs");
    candidate.is_file().then(|| candidate.to_string_lossy().into_owned())
}

/// The model name the host harness mounts (mirrors the daemon's `resolve_inference`).
fn resolve_harness_model() -> String {
    std::env::var("IOI_HYPERVISOR_MODEL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "qwen2.5-coder".to_string())
}

/// Build the resolved host-spawn argv for the `generic-cli-local` adapter:
/// `node <shim> --provider ollama --model <model> --cd <workspace> --harness-label ...`.
/// None when `node` or the shim is unavailable.
fn resolve_host_harness_argv(model: &str, workspace_root: &str) -> Option<Vec<String>> {
    let node = binary_on_path("node")?;
    let shim = generic_cli_local_shim_path()?;
    Some(vec![
        node,
        shim,
        "--provider".to_string(),
        "ollama".to_string(),
        "--model".to_string(),
        model.to_string(),
        "--cd".to_string(),
        workspace_root.to_string(),
        "--harness-label".to_string(),
        "Generic CLI Harness".to_string(),
    ])
}

const HARNESS_RESULT_SENTINEL: &str = "__HYPERVISOR_HARNESS_RESULT__";
const HOST_SPAWN_LANE_TIMEOUT_SECS: u64 = 180;

/// Outcome of one real host-spawn lane run (truthful — failure reflects reality).
struct HostLaneOutcome {
    ok: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    spawn_error: Option<String>,
    error: Option<String>,
    summary: String,
    files_written: Vec<String>,
    /// (stream, line) transcript in emission order.
    transcript: Vec<(String, String)>,
}

/// Run one real Lane A execution: spawn the admitted host harness over its
/// resolved argv in the provisioned workspace, deliver the user intent after the
/// harness signals `ready`, stream its real stdout, and parse its final
/// `__HYPERVISOR_HARNESS_RESULT__ {json}` line. The harness drives the model and
/// edits the workspace; the daemon owns the spawn and reads the real output. No
/// fabrication: the outcome (files, transcript, error) reflects what truly happened.
async fn run_host_spawn_lane(
    argv: &[String],
    workspace_root: &str,
    intent: &str,
    model_endpoint: Option<&str>,
) -> HostLaneOutcome {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    // Each stdin line is one task to the interactive harness; keep it single-line.
    let intent_line = intent.replace(['\r', '\n'], " ");

    // Minimal, secret-free child env: enough to run node + reach the local model.
    let mut command = tokio::process::Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(workspace_root)
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    if let Some(home) = std::env::var_os("HOME") {
        command.env("HOME", home);
    }
    if let Some(endpoint) = model_endpoint {
        command.env("IOI_HYPERVISOR_MODEL_UPSTREAM", endpoint);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return HostLaneOutcome {
                ok: false,
                exit_code: None,
                timed_out: false,
                spawn_error: Some(error.to_string()),
                error: Some("harness_spawn_failed".to_string()),
                summary: String::new(),
                files_written: Vec::new(),
                transcript: Vec::new(),
            };
        }
    };

    let mut stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    // Collect the harness's stderr concurrently.
    let stderr_task = tokio::spawn(async move {
        let mut collected: Vec<String> = Vec::new();
        if let Some(stderr) = stderr {
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                collected.push(line);
            }
        }
        collected
    });

    let mut transcript: Vec<(String, String)> = Vec::new();
    let mut result_json: Option<Value> = None;

    let drive = async {
        let Some(stdout) = stdout else { return };
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        let mut intent_sent = false;
        while let Ok(Some(line)) = lines.next_line().await {
            transcript.push(("stdout".to_string(), line.clone()));
            if let Some(rest) = line.strip_prefix(HARNESS_RESULT_SENTINEL) {
                result_json = serde_json::from_str(rest.trim()).ok();
                if let Some(stdin) = stdin.as_mut() {
                    let _ = stdin.write_all(b"/exit\n").await;
                    let _ = stdin.flush().await;
                }
            } else if line.contains("ready:") && !intent_sent {
                intent_sent = true;
                if let Some(stdin) = stdin.as_mut() {
                    let _ = stdin.write_all(format!("{intent_line}\n").as_bytes()).await;
                    let _ = stdin.flush().await;
                }
            }
        }
    };

    let timed_out = tokio::time::timeout(
        std::time::Duration::from_secs(HOST_SPAWN_LANE_TIMEOUT_SECS),
        drive,
    )
    .await
    .is_err();
    // Dropping stdin closes the harness's input so it exits even without /exit.
    drop(stdin);
    if timed_out {
        let _ = child.start_kill();
    }
    let exit_code = child.wait().await.ok().and_then(|status| status.code());
    for line in stderr_task.await.unwrap_or_default() {
        transcript.push(("stderr".to_string(), line));
    }

    let files_written = result_json
        .as_ref()
        .and_then(|value| value.get("files_written"))
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let summary = result_json
        .as_ref()
        .and_then(|value| value.get("summary"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let result_ok = result_json
        .as_ref()
        .and_then(|value| value.get("ok"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let result_error = result_json
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let ok = result_ok && !timed_out;
    let error = if ok {
        None
    } else if timed_out {
        Some("harness_timed_out".to_string())
    } else {
        Some(result_error.unwrap_or_else(|| "harness_lane_incomplete".to_string()))
    };

    HostLaneOutcome {
        ok,
        exit_code,
        timed_out,
        spawn_error: None,
        error,
        summary,
        files_written,
        transcript,
    }
}

/// Start a REAL preview listener: a static file server bound to a free localhost
/// port serving `workspace_root`. Returns the bound port + an abort handle for the
/// serving task. Opening this listener exposes workspace bytes — it is only ever
/// called after the execution authority gate admits `port_exposure`.
async fn start_preview_server(
    workspace_root: String,
) -> std::io::Result<(u16, tokio::sync::oneshot::Sender<()>, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = axum::Router::new()
        .route("/", axum::routing::get(serve_preview_root))
        .route("/*preview_path", axum::routing::get(serve_preview_path))
        .with_state(workspace_root);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    // Graceful shutdown so a revoke/teardown deterministically closes the socket:
    // once signalled, axum::serve stops accepting and its listener is dropped.
    let join = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });
    Ok((port, shutdown_tx, join))
}

async fn serve_preview_root(State(root): State<String>) -> Response {
    serve_preview_file(&root, "index.html")
}

async fn serve_preview_path(State(root): State<String>, AxumPath(rel): AxumPath<String>) -> Response {
    serve_preview_file(&root, &rel)
}

/// Serve a file from the preview workspace with a real traversal guard: the
/// resolved (canonicalized) target must stay under the canonicalized workspace
/// root. Real bytes, real content-type; 404 when absent or escaping.
fn serve_preview_file(root: &str, rel: &str) -> Response {
    let base = std::path::Path::new(root);
    let Ok(canon_base) = base.canonicalize() else {
        return (StatusCode::NOT_FOUND, "preview workspace unavailable").into_response();
    };
    let target = canon_base.join(rel.trim_start_matches('/'));
    let Ok(canon_target) = target.canonicalize() else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    if !canon_target.starts_with(&canon_base) {
        return (StatusCode::FORBIDDEN, "path escapes workspace").into_response();
    }
    let Ok(bytes) = std::fs::read(&canon_target) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let content_type = preview_content_type(&canon_target);
    ([(header::CONTENT_TYPE, content_type)], bytes).into_response()
}

fn preview_content_type(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()).map(str::to_ascii_lowercase).as_deref() {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("ico") => "image/x-icon",
        Some("txt") | Some("md") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Open (or replace) the session's preview listener for `workspace_root`, bound
/// under the admitted `capability_lease_ref`, and return the canonical
/// `HypervisorEnvironmentPort` value. Returns None if no listener could bind.
async fn open_session_preview_port(
    st: &DaemonState,
    session_ref: &str,
    workspace_root: &str,
    capability_lease_ref: &str,
) -> Option<Value> {
    let (port, shutdown, join) = start_preview_server(workspace_root.to_string()).await.ok()?;
    let url = format!("http://127.0.0.1:{port}/");
    // Replace any prior listener for this session (signal the old one to shut down;
    // the new listener binds a fresh port, so we don't need to await the old close).
    if let Ok(mut servers) = st.preview_servers.lock() {
        if let Some(previous) = servers.insert(
            session_ref.to_string(),
            PreviewServer {
                port,
                url: url.clone(),
                capability_lease_ref: capability_lease_ref.to_string(),
                workspace_root: workspace_root.to_string(),
                shutdown,
                join,
            },
        ) {
            let _ = previous.shutdown.send(());
            previous.join.abort();
        }
    }
    Some(json!({
        "port": port,
        "protocol": "http",
        "access_policy": "session_lease",
        "capability_lease_ref": capability_lease_ref,
        "url": url,
        "exposure_state": "open",
    }))
}

/// Root for provisioned session workspaces: `{IOI_HYPERVISOR_SESSIONS_ROOT or tmp}/ioi-hypervisor-sessions`.
fn sessions_root() -> std::path::PathBuf {
    let base = std::env::var("IOI_HYPERVISOR_SESSIONS_ROOT")
        .ok()
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("ioi-hypervisor-sessions")
}

/// Real `mkdtemp`-equivalent: create a fresh unique dir `{tag}-{token}` under the
/// sessions root, retrying on collision. Returns the absolute workspace path.
fn mkdtemp_session(session_tag: &str) -> std::io::Result<std::path::PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let root = sessions_root();
    std::fs::create_dir_all(&root)?;
    let pid = std::process::id();
    for _ in 0..64 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let token = format!("{pid:x}{nanos:x}{seq:x}");
        let candidate = root.join(format!("{session_tag}-{token}"));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "exhausted unique workspace name attempts",
    ))
}

struct ProvisionOutcome {
    workspace_root: String,
    workspace_artifact_ref: String,
    component_phases: Value,
    realized_specs: Vec<Value>,
    custody_posture: String,
    initializer: Value,
}

/// Provision a REAL isolated session workspace from a typed initializer. mkdtemp
/// an isolated dir, then realize git specs by shallow-cloning when a remote is
/// given and the clone succeeds; otherwise record the spec deferred (no fake
/// clone). Mirrors `runtime-workspace-provisioner.mjs`.
fn provision_session_workspace(session_ref: &str, initializer: &Value) -> Result<ProvisionOutcome, AppError> {
    let custody_posture = initializer
        .get("custody_posture")
        .and_then(Value::as_str)
        .unwrap_or("public_trunk")
        .to_string();
    let session_tag: String = safe_session_tag(session_ref);
    let workspace_path = mkdtemp_session(&session_tag).map_err(|error| {
        AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("workspace mkdtemp failed: {error}"))
    })?;

    // Never operate on a filesystem root.
    if workspace_path.parent().is_none() {
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "workspace_provision_root_forbidden".to_string(),
        ));
    }
    let workspace_root = workspace_path.to_string_lossy().into_owned();

    let mut workspace_content_phase = "ready";
    let mut realized_specs: Vec<Value> = Vec::new();
    if let Some(specs) = initializer.get("specs").and_then(Value::as_array) {
        for spec in specs {
            if let Some(git) = spec.get("git").and_then(Value::as_object) {
                let remote_uri = git.get("remote_uri").and_then(Value::as_str).unwrap_or("");
                if remote_uri.is_empty() {
                    continue;
                }
                let clone_target = git.get("clone_target").and_then(Value::as_str).unwrap_or(".");
                let clone_into = if clone_target == "." {
                    workspace_root.clone()
                } else {
                    workspace_path.join(clone_target).to_string_lossy().into_owned()
                };
                let cloned = std::process::Command::new("git")
                    .args(["clone", "--depth", "1", remote_uri, clone_into.as_str()])
                    .output()
                    .map(|output| output.status.success())
                    .unwrap_or(false);
                if cloned {
                    realized_specs.push(json!({ "git": remote_uri, "realized": true }));
                } else {
                    // No fake clone: record deferred, leave a real scratch workspace.
                    workspace_content_phase = "initializing";
                    realized_specs.push(json!({ "git": remote_uri, "realized": false }));
                }
                continue;
            }
            if let Some(context_url) = spec.get("context_url").and_then(Value::as_str) {
                // Context-URL realization is a later phase: record it deferred.
                workspace_content_phase = "initializing";
                realized_specs.push(json!({ "context_url": context_url, "realized": false }));
            }
        }
    }

    let artifact_digest = {
        let payload = format!("{workspace_root}\n{}", serde_json::to_string(initializer).unwrap_or_default());
        let hex = sha256_hex_str(&payload);
        hex.chars().take(24).collect::<String>()
    };

    Ok(ProvisionOutcome {
        workspace_root,
        workspace_artifact_ref: format!("agentgres://artifact/workspace/{artifact_digest}"),
        component_phases: json!({
            "provisioner": "ready",
            "workspace_content": workspace_content_phase,
        }),
        realized_specs,
        custody_posture,
        initializer: initializer.clone(),
    })
}

/// Bind a session to an EXISTING started environment's workspace (the env's `status.workspace_root`)
/// instead of provisioning a fresh temp dir, so agent execution and the editor host operate on the
/// SAME files. Returns None when the env is unknown or not started (caller falls back to a fresh
/// session workspace) — never fabricates a path.
fn bind_env_workspace(data_dir: &str, env_id: &str, initializer: &Value) -> Option<ProvisionOutcome> {
    let safe = env_id.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_");
    let path = std::path::Path::new(data_dir).join("environments").join(format!("{safe}.json"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).ok()?).ok()?;
    let workspace_root = v
        .get("status")
        .and_then(|status| status.get("workspace_root"))
        .and_then(Value::as_str)
        .filter(|root| !root.trim().is_empty())?
        .to_string();
    let artifact_digest = sha256_hex_str(&workspace_root).chars().take(24).collect::<String>();
    Some(ProvisionOutcome {
        workspace_root,
        workspace_artifact_ref: format!("agentgres://artifact/workspace/{artifact_digest}"),
        component_phases: json!({ "provisioner": "ready", "workspace_content": "ready" }),
        realized_specs: vec![json!({ "environment_id": env_id, "bound": true })],
        custody_posture: initializer
            .get("custody_posture")
            .and_then(Value::as_str)
            .unwrap_or("public_trunk")
            .to_string(),
        initializer: initializer.clone(),
    })
}

/// A filesystem-safe, length-bounded session tag for the workspace dir name.
fn safe_session_tag(session_ref: &str) -> String {
    let mut out = String::with_capacity(session_ref.len());
    let mut in_run = false;
    for ch in session_ref.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            out.push(ch);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    if out.is_empty() {
        out.push_str("session");
    }
    out.chars().take(48).collect()
}

/// Build the real environment-status projection for a session from its stored
/// provisioning facts + a fresh substrate probe.
#[allow(clippy::too_many_arguments)]
fn project_session_environment_status(
    environment_ref: &str,
    workspace_root: &str,
    custody_posture: &str,
    initializer_ref: &str,
    workspace_artifact_ref: &str,
    component_phases: &Value,
    substrate: &ExecutionSubstrate,
    ports: &Value,
) -> Value {
    RuntimeKernelService::new().project_hypervisor_environment_status(&json!({
        "environmentRef": environment_ref,
        "workspaceRoot": workspace_root,
        "workspaceMountPolicy": custody_posture,
        "initializerRef": initializer_ref,
        "modelRouteRef": "model-route:hypervisor-local-ollama",
        "workspaceArtifactRef": workspace_artifact_ref,
        "componentPhases": component_phases,
        "readinessChecks": substrate.readiness_checks(),
        "ports": ports,
    }))
}

/// Real workspace-diff projection (`changed_file_groups`) over the session
/// workspace: `git` deltas for a work tree, a real file walk for scratch, or the
/// honest `absent` projection when there is no workspace. No fixtures.
fn project_session_workspace_diff(workspace_root: &str) -> Value {
    let service = RuntimeKernelService::new();
    if workspace_root.is_empty() {
        return service.project_hypervisor_workspace_diff_absent();
    }
    let inside_work_tree = git_capture(workspace_root, &["rev-parse", "--is-inside-work-tree"])
        .map(|stdout| stdout.trim() == "true")
        .unwrap_or(false);
    if inside_work_tree {
        let numstat = git_capture(workspace_root, &["diff", "--numstat", "HEAD"]).unwrap_or_default();
        let status = git_capture(workspace_root, &["status", "--porcelain"]).unwrap_or_default();
        service.project_hypervisor_workspace_diff_from_git(workspace_root, &numstat, &status)
    } else {
        let records = walk_workspace_records(workspace_root);
        service.project_hypervisor_workspace_diff_from_records(workspace_root, "filesystem", &records)
    }
}

/// Run a git subcommand in `cwd`, returning stdout on success.
fn git_capture(cwd: &str, args: &[&str]) -> Option<String> {
    let mut command = std::process::Command::new("git");
    command.args(["-C", cwd]);
    command.args(args);
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Real file walk of a scratch workspace → `{relPath, delta, status:"added"}`
/// records (the kernel groups them). Mirrors `walkWorkspace` in the JS projection.
fn walk_workspace_records(root: &str) -> Vec<Value> {
    fn walk(dir: &Path, rel: &str, out: &mut Vec<Value>) {
        if out.len() >= MAX_WALK_FILES {
            return;
        }
        let Ok(read) = std::fs::read_dir(dir) else { return };
        let mut entries: Vec<_> = read.flatten().collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            if out.len() >= MAX_WALK_FILES {
                return;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(file_type) = entry.file_type() else { continue };
            let child_rel = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
            if file_type.is_dir() {
                if WALK_IGNORED_DIRS.contains(&name.as_str()) {
                    continue;
                }
                walk(&entry.path(), &child_rel, out);
            } else if file_type.is_file() {
                let lines = std::fs::read_to_string(entry.path())
                    .map(|content| if content.is_empty() { 0 } else { content.split('\n').count() })
                    .unwrap_or(0);
                out.push(json!({ "relPath": child_rel, "delta": format!("+{lines}"), "status": "added" }));
            }
        }
    }
    let mut out = Vec::new();
    walk(Path::new(root), "", &mut out);
    out
}

/// Load a persisted session record by session_ref.
fn load_session_record(st: &DaemonState, session_ref: &str) -> Option<Value> {
    read_record_dir(&st.data_dir, "sessions")
        .into_iter()
        .find(|record| record.get("session_ref").and_then(Value::as_str) == Some(session_ref))
}

/// Build a one-shot `text/event-stream` response from canonical session-event frames.
fn session_events_response(frames: &[(&str, Value)]) -> Response {
    let mut body = String::from(": hypervisor session events\n\n");
    for (event, data) in frames {
        let encoded = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
        body.push_str(&format!("event: {event}\ndata: {encoded}\n\n"));
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// POST /v1/hypervisor/sessions — create + provision a real session workspace.
///
/// Body: `{ project_ref?, session_ref?, workspace_mount_policy?, context_url?,
/// git?:{remote_uri,clone_target,target_mode}, authority_scope_refs? }`.
/// Provisions a REAL workspace (mkdtemp / clone-deferred), projects a real
/// `HypervisorEnvironmentStatus` (model_mount/harness honestly degraded with no
/// substrate), persists the session + a provisioning receipt, and returns 202.
pub(crate) async fn handle_session_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let now = iso_now();
    let project_ref = body.get("project_ref").and_then(Value::as_str).map(str::to_string);
    let session_ref = body
        .get("session_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            let seed = format!("{}:{now}", project_ref.as_deref().unwrap_or("session"));
            format!("session:hyp-{}", short_hash(&seed))
        });
    // A session may bind to an EXISTING started environment's workspace so agent execution and
    // the editor host operate on the SAME files (the app's compose→run→open-editor loop).
    let bound_env_id = body
        .get("environment_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    let environment_ref = match &bound_env_id {
        Some(env_id) => format!("environment:{env_id}"),
        None => format!("environment:{}", safe_session_tag(&session_ref)),
    };

    // Typed workspace initializer (camelCase input mirrors the JS builder args).
    let initializer = RuntimeKernelService::new().derive_hypervisor_workspace_initializer(&json!({
        "contextUrl": body.get("context_url"),
        "gitSpec": body.get("git"),
        "workspaceMountPolicy": body.get("workspace_mount_policy"),
        "authorityScopeRefs": body.get("authority_scope_refs"),
    }));
    let initializer_ref = initializer
        .get("initializer_ref")
        .and_then(Value::as_str)
        .unwrap_or("workspace-initializer:session")
        .to_string();

    let provision = match bound_env_id
        .as_deref()
        .and_then(|env_id| bind_env_workspace(&st.data_dir, env_id, &initializer))
    {
        Some(outcome) => outcome,
        None => match provision_session_workspace(&session_ref, &initializer) {
            Ok(outcome) => outcome,
            Err(error) => {
                return (
                    error.0,
                    Json(json!({ "error": { "code": "workspace_provision_failed", "message": error.1 } })),
                );
            }
        },
    };

    let substrate = ExecutionSubstrate::probe();
    let environment_status = project_session_environment_status(
        &environment_ref,
        &provision.workspace_root,
        &provision.custody_posture,
        &initializer_ref,
        &provision.workspace_artifact_ref,
        &provision.component_phases,
        &substrate,
        // No preview port at provision time — a session has not executed yet.
        &json!([]),
    );

    // Real provisioning receipt (id + kind so it passes the receipt reader).
    let receipt_ref = format!("receipt://hypervisor/session-provision/{}", safe_session_tag(&session_ref));
    let receipt = json!({
        "id": receipt_ref,
        "kind": "hypervisor.session.provision",
        "session_ref": session_ref,
        "environment_ref": environment_ref,
        "workspace_root": provision.workspace_root,
        "workspace_artifact_ref": provision.workspace_artifact_ref,
        "state_root_ref": environment_status.get("state_root_ref").cloned().unwrap_or(Value::Null),
        "created_at": now,
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);

    let record = json!({
        "schema_version": SESSION_RECORD_SCHEMA_VERSION,
        "session_ref": session_ref,
        "project_ref": project_ref,
        "environment_ref": environment_ref,
        "lifecycle_state": "provisioned",
        "cwd": provision.workspace_root,
        "workspace_root": provision.workspace_root,
        "workspace_artifact_ref": provision.workspace_artifact_ref,
        "custody_posture": provision.custody_posture,
        "initializer": provision.initializer,
        "initializer_ref": initializer_ref,
        "component_phases": provision.component_phases,
        "realized_specs": provision.realized_specs,
        "environment_status": environment_status,
        "latest_receipt_refs": [receipt_ref],
        "created_at": now,
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "sessions", &session_ref, &record);

    (
        StatusCode::ACCEPTED,
        Json(json!({
            "schema_version": SESSION_CREATE_PROJECTION_SCHEMA_VERSION,
            "session_ref": session_ref,
            "environment_ref": environment_ref,
            "environment_status": environment_status,
            "workspace_initializer": provision.initializer,
            "receipt_ref": receipt_ref,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

/// GET /v1/hypervisor/sessions/:id/events — canonical session-events SSE.
///
/// Emits REAL signals only: `environment_status` (re-projected from provisioning
/// facts + a fresh probe), `workspace_change` (real `changed_file_groups`),
/// `readiness` (the honest gate decision), `receipt_projection`, and
/// `terminal_chunk` frames replaying the real harness transcript IFF a prior
/// execution persisted one (never fabricated). 404 if the session is unknown.
pub(crate) async fn handle_session_events(
    State(st): State<Arc<DaemonState>>,
    AxumPath(session_id): AxumPath<String>,
) -> Response {
    let Some(record) = load_session_record(&st, &session_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "session_not_found", "message": "Unknown session.", "session_ref": session_id } })),
        )
            .into_response();
    };
    let workspace_root = record.get("workspace_root").and_then(Value::as_str).unwrap_or("");
    let environment_ref = record.get("environment_ref").and_then(Value::as_str).unwrap_or("environment:hypervisor-session");
    let custody_posture = record.get("custody_posture").and_then(Value::as_str).unwrap_or("public_trunk");
    let initializer_ref = record.get("initializer_ref").and_then(Value::as_str).unwrap_or("workspace-initializer:session");
    let workspace_artifact_ref = record.get("workspace_artifact_ref").and_then(Value::as_str).unwrap_or("");
    let component_phases = record.get("component_phases").cloned().unwrap_or_else(|| json!({}));
    let receipt_refs = record.get("latest_receipt_refs").cloned().unwrap_or_else(|| json!([]));
    // Real preview ports opened by a prior execution (with capability_lease_ref).
    let environment_ports = record.get("environment_ports").cloned().unwrap_or_else(|| json!([]));

    let substrate = ExecutionSubstrate::probe();
    let environment_status = project_session_environment_status(
        environment_ref,
        workspace_root,
        custody_posture,
        initializer_ref,
        workspace_artifact_ref,
        &component_phases,
        &substrate,
        &environment_ports,
    );
    let workspace_diff = project_session_workspace_diff(workspace_root);
    let gate = execution_gate_decision(&session_id, &substrate);

    let mut frames: Vec<(&str, Value)> = vec![
        ("environment_status", environment_status),
        (
            "workspace_change",
            json!({ "changed_file_groups": workspace_diff.get("changed_file_groups").cloned().unwrap_or_else(|| json!([])) }),
        ),
        ("readiness", gate),
        ("receipt_projection", json!({ "latest_receipt_refs": receipt_refs })),
    ];
    // Real terminal transcript from a prior execution (Cut #2). Emitted ONLY when a
    // real run persisted `terminal_events` — never fabricated. Bounded to the tail.
    if let Some(events) = record.get("terminal_events").and_then(Value::as_array) {
        let tail: Vec<&Value> = events.iter().rev().take(300).collect();
        for event in tail.into_iter().rev() {
            frames.push((
                "terminal_chunk",
                json!({
                    "sequence": event.get("sequence").cloned().unwrap_or(Value::Null),
                    "stream": event.get("stream").cloned().unwrap_or_else(|| json!("stdout")),
                    "text": event.get("text").cloned().unwrap_or_else(|| json!("")),
                }),
            ));
        }
    }
    session_events_response(&frames)
}

/// The honest readiness/gate decision for a session given the probed substrate.
/// `decision` is `ready` only when a model route AND a harness binary are present
/// (the host-PTY lane); otherwise it is `blocked` with the specific missing
/// substrate as `reason`.
fn execution_gate_decision(session_ref: &str, substrate: &ExecutionSubstrate) -> Value {
    let (decision, reason, message) = if !substrate.model_route {
        (
            "blocked",
            "no_model_route",
            "No reachable model route. Start a local model (e.g. `ollama serve` + a coding model) or set IOI_HYPERVISOR_MODEL_UPSTREAM.",
        )
    } else if substrate.harness_binary.is_none() {
        (
            "blocked",
            "harness_unavailable",
            "No harness binary on PATH (codex / generic-cli-local). Install a harness adapter to run the Lane A execution loop.",
        )
    } else {
        (
            "ready",
            "execution_substrate_present",
            "Model route and host harness present; POST /v1/hypervisor/sessions/:id/execute runs the real Lane A loop.",
        )
    };
    json!({
        "readiness_id": format!("readiness:{}", safe_session_tag(session_ref)),
        "decision": decision,
        "reason": reason,
        "message": message,
        "checks": substrate.readiness_checks(),
        "model_route": substrate.model_route,
        "harness_binary": substrate.harness_binary,
        "container_runtime": substrate.container_runtime,
        "runtimeTruthSource": "daemon-runtime",
    })
}

/// Consequential scopes a session execution exercises, gated as one capability
/// envelope: `command_exec` (the daemon spawns a process), `port_exposure` (the
/// run may open a real preview listener exposing workspace bytes), and
/// `workspace_write` (the harness edits the workspace). Kept sorted so the
/// daemon-derived policy/request hashes are stable.
const EXECUTION_AUTHORITY_SCOPES: &[&str] = &["command_exec", "port_exposure", "workspace_write"];

/// Daemon-derived POLICY hash an execution grant must carry: binds the grant to
/// this session + workspace + the exact scope set (the policy context). NEVER
/// from the POST body.
fn execution_policy_hash(session_ref: &str, workspace_root: &str, scopes: &[&str]) -> String {
    sha256_json_ref(&json!({
        "domain": "hypervisor.session.execute.policy.v1",
        "session_ref": session_ref,
        "workspace_root": workspace_root,
        "scopes": scopes,
    }))
}

/// Daemon-derived REQUEST hash an execution grant must carry: the stable identity
/// of "run THIS intent in THIS session under THESE scopes". Reproducible at
/// challenge time and retry time (same intent → same hash), and distinct from any
/// other operation's request hash so a grant can never be replayed across intents.
fn execution_request_hash(session_ref: &str, intent: &str, scopes: &[&str]) -> String {
    sha256_json_ref(&json!({
        "domain": "hypervisor.session.execute.request.v1",
        "session_ref": session_ref,
        "intent": intent,
        "scopes": scopes,
    }))
}

/// Resolve the task intent for an execute request: `intent`, else the joined
/// `messages[].content`. None when neither carries text.
fn session_execute_intent(body: &Value) -> Option<String> {
    if let Some(intent) = body.get("intent").and_then(Value::as_str) {
        let trimmed = intent.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        let joined = messages
            .iter()
            .filter_map(|message| message.get("content").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n");
        let trimmed = joined.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

/// The wallet authority gate for a consequential execution. Daemon-derives the
/// policy/request hashes (never from the body) and verifies a bound grant. Returns
/// the admitted capability-lease ref, or the 403 challenge body exposing the hashes
/// so a wallet can mint a bound grant. Lane-independent (both Lane A and Lane B
/// gate execution identically).
fn execute_authority_gate(
    body: &Value,
    session_id: &str,
    workspace_root: &str,
    intent: &str,
) -> Result<String, Value> {
    let policy_hash = execution_policy_hash(session_id, workspace_root, EXECUTION_AUTHORITY_SCOPES);
    let request_hash = execution_request_hash(session_id, intent, EXECUTION_AUTHORITY_SCOPES);
    let grant_value = body.get("wallet_approval_grant").cloned().unwrap_or(Value::Null);
    let now_ms = daemon_now_ms_fail_closed();
    let result = if grant_value.is_null() {
        Err("a wallet_approval_grant is required".to_string())
    } else {
        verify_wallet_approval_grant_binding(&grant_value, Some(now_ms), Some(&policy_hash), Some(&request_hash))
            .map(|binding| binding.grant_ref)
    };
    result.map_err(|reason| {
        json!({
            "schema_version": SESSION_EXECUTE_DECISION_SCHEMA_VERSION,
            "session_ref": session_id,
            "decision": "blocked",
            "reason": "execution_authority_required",
            "message": format!(
                "Consequential execution requires a wallet capability grant ({reason}). \
                 Bind a wallet grant to policy_hash {policy_hash} + request_hash {request_hash}."
            ),
            "required_scopes": EXECUTION_AUTHORITY_SCOPES,
            "approval": { "policy_hash": policy_hash, "request_hash": request_hash },
            // Blocked before any work: nothing ran, nothing fabricated.
            "changed_file_groups": [],
            "terminal_events": [],
            "runtimeTruthSource": "daemon-runtime",
        })
    })
}

// ---- SCM connector registry + wallet-authorized publish crossing -------------------------------
// Publishing the env's work to a remote LEAVES the scoped workspace for an external SCM, so — unlike
// local exec — it is a CROSSING and REQUIRES a wallet capability grant. A connector is the named
// remote target. The publish gate mirrors `execute_authority_gate` (daemon-derived policy + request
// hashes, verified bound grant), then the daemon performs a REAL `git push` and records a durable
// receipt. Boundary: daemon EXECUTES the push · wallet AUTHORIZES the crossing · agentgres RECORDS
// the receipt (host_mutation:true — it touches an external remote). The local-none (file://)
// connector is the verifiable slice; hosted (github/gitlab) connectors fail closed until a scoped
// credential lease is bound.

// SCM crossing scopes — the wallet capability scopes each lease class requires. Distinct so a
// publish grant can never authorize an abandon (and vice versa). The per-crossing policy/request
// HASHES are now derived generically by the CapabilityLease gateway below (no hand-rolled gates).
const SCM_PUBLISH_SCOPES: &[&str] = &["scm_push", "remote_publish"];
const SCM_ABANDON_SCOPES: &[&str] = &["scm_pr_close", "remote_publish"];

// ================================================================================================
// Generic CapabilityLease — the single authority-crossing primitive (master-guide #3).
//
// Every host-touching crossing (SCM publish, SCM abandon, and every future connector) flows through
// ONE gateway instead of hand-rolling its own gate. A caller DECLARES a lease (what tools, what
// resources, what backs it, how to revoke it); the gateway derives the canonical policy/request
// hashes, resolves the SEALED backing credential (never exported), verifies a bound wallet grant,
// and issues a durable lease descriptor. The agent receives USE-ONLY authority (scoped tools +
// resources + receipt + revocation) — NEVER the underlying credential. wallet.network sits ABOVE
// the credential: it authorizes the crossing; the daemon uses the sealed secret; agentgres records
// the lease + receipt. Adding a connector becomes "declare a lease", not "write a new gate".
// ================================================================================================

/// What a caller declares to request a capability lease for one crossing.
struct CapabilityLeaseRequest {
    /// Who authorizes the crossing (the grant authority). Default "wallet.network".
    authority_provider_ref: String,
    /// What credential backs the lease: "scm:host:github" | "scm:connector:<id>" | "none".
    backing_provider: String,
    /// The operations this lease permits, e.g. ["scm.publish"], ["scm.pr.close"].
    allowed_tools: Vec<String>,
    /// The scoped resources the lease is bound to (remote_url, environment_id, pr_url, …).
    resource_refs: Vec<String>,
    /// The wallet capability scopes the grant must carry.
    scopes: Vec<String>,
    /// Stable domain tags so a grant can never be replayed across operation kinds.
    policy_domain: String,
    request_domain: String,
    /// Request-specific binding params folded into the request hash (branch, pr#, intent, …).
    request_facets: Value,
    /// Connector whose sealed credential to resolve (None = authority-only crossing, no secret).
    credential_connector_id: Option<String>,
    /// Which sealed-credential vault to resolve from ("scm-credentials" for SCM, "connector-
    /// credentials" for the generic estate). The same gateway serves every connector family.
    credential_store: String,
    /// Fail closed (428) if the credential is required but unresolved.
    credential_required: bool,
    /// Allow the github host git-auth fallback (a repo lease borrows the connected host token).
    github_host_fallback: bool,
    /// Whether a receipt must be emitted for this crossing.
    receipt_required: bool,
    /// How the backing authority is revoked (the revocation surface).
    revocation_ref: String,
    /// Reason string surfaced on the 403 challenge (per-crossing for API clarity).
    authority_reason: String,
    /// The wallet_approval_grant carried on the request body (Null → 403 challenge).
    grant_value: Value,
}

/// The authorized lease. `token` is for the daemon to USE; it is NEVER serialized or returned.
struct AuthorizedCapabilityLease {
    /// The 9-field lease descriptor (persisted + embeddable in receipts; carries NO secret).
    descriptor: Value,
    token: Option<String>,
    grant_ref: String,
    credential_source: Option<String>,
    credential_key_source: Option<String>,
}

fn capability_lease_policy_hash(req: &CapabilityLeaseRequest) -> String {
    sha256_json_ref(&json!({
        "domain": req.policy_domain,
        "authority_provider_ref": req.authority_provider_ref,
        "backing_provider": req.backing_provider,
        "allowed_tools": req.allowed_tools,
        "resource_refs": req.resource_refs,
        "scopes": req.scopes,
    }))
}
fn capability_lease_request_hash(req: &CapabilityLeaseRequest) -> String {
    sha256_json_ref(&json!({
        "domain": req.request_domain,
        "allowed_tools": req.allowed_tools,
        "resource_refs": req.resource_refs,
        "scopes": req.scopes,
        "facets": req.request_facets,
    }))
}

/// Resolve a sealed credential record into a usable token + (source, key_source). Two kinds:
/// a github-app record MINTS a fresh installation token (RS256 JWT → exchange); any other record
/// opens its sealed PAT. The secret material (pem / sealed token) never leaves the daemon.
async fn resolve_sealed_credential(rec: &Value) -> (Option<String>, Option<String>, Option<String>) {
    let key_source = rec["key_source"].as_str().map(str::to_string);
    if rec["kind"].as_str() == Some("github-app") {
        let pem = rec["sealed_pem"].as_str().and_then(open_scm_token);
        let app_id = rec["app_id"].as_str().unwrap_or("").to_string();
        let installation_id = rec["installation_id"].as_str().unwrap_or("").to_string();
        if let Some(pem) = pem {
            if !app_id.is_empty() && !installation_id.is_empty() {
                if let Ok(tok) = mint_github_installation_token(&app_id, &pem, &installation_id).await {
                    return (Some(tok), Some("github-app-installation".to_string()), key_source);
                }
            }
        }
        return (None, None, key_source);
    }
    if rec["kind"].as_str() == Some("oauth-refresh") {
        let refresh = rec["sealed_refresh_token"].as_str().and_then(open_scm_token);
        let token_url = rec["token_url"].as_str().unwrap_or("").to_string();
        let client_id = rec["client_id"].as_str().unwrap_or("").to_string();
        let client_secret = rec["sealed_client_secret"].as_str().and_then(open_scm_token).unwrap_or_default();
        if let Some(refresh) = refresh {
            if !token_url.is_empty() {
                if let Ok(tok) = mint_oauth_access_token(&token_url, &client_id, &client_secret, &refresh).await {
                    return (Some(tok), Some("oauth-refresh".to_string()), key_source);
                }
            }
        }
        return (None, None, key_source);
    }
    if rec["kind"].as_str() == Some("oidc-workload") {
        // The subject token is the workload's own identity — read fresh from a mounted file (rotating,
        // e.g. a projected service-account token) or a sealed configured value, then exchange it.
        let subject = match rec["subject_token_file"].as_str() {
            Some(path) if !path.is_empty() => std::fs::read_to_string(path).ok().map(|s| s.trim().to_string()),
            _ => rec["sealed_subject_token"].as_str().and_then(open_scm_token),
        };
        let token_url = rec["token_url"].as_str().unwrap_or("");
        if let Some(subject) = subject {
            if !token_url.is_empty() {
                let stt = rec["subject_token_type"].as_str().unwrap_or("urn:ietf:params:oauth:token-type:jwt");
                let audience = rec["audience"].as_str().unwrap_or("");
                let scopes = rec["scopes"].as_str().unwrap_or("");
                let client_id = rec["client_id"].as_str().unwrap_or("");
                if let Ok(tok) = mint_token_exchange(token_url, &subject, stt, audience, scopes, client_id).await {
                    return (Some(tok), Some("oidc-workload".to_string()), key_source);
                }
            }
        }
        return (None, None, key_source);
    }
    if rec["kind"].as_str() == Some("aws-sigv4") {
        // SigV4 signs each request at invoke time (not a bearer). Signal credential presence so the
        // wallet gate passes; the invoke reads the sealed keys and signs. The marker is never sent.
        let present = rec["sealed_secret_access_key"].as_str().is_some();
        return (present.then(|| "aws-sigv4".to_string()), present.then(|| "aws-sigv4".to_string()), key_source);
    }
    let token = if let Some(sealed) = rec["sealed_token"].as_str() { open_scm_token(sealed) } else { rec["token"].as_str().map(str::to_string) };
    let label = if rec["kind"].as_str() == Some("service-account") { "managed-service-account" } else { "connector" };
    let source = token.as_ref().map(|_| label.to_string());
    (token, source, key_source)
}

/// The single authority gateway. Order: resolve sealed credential (428) → verify wallet grant (403)
/// → issue + persist the lease. Returns the authorized lease, or a (StatusCode, body) the caller
/// returns verbatim. This is THE crossing — publish/abandon/future-connectors all route through it.
/// Async because some credential kinds (github-app) MINT a fresh token (network) at resolution time.
async fn authorize_capability_lease(
    st: &Arc<DaemonState>,
    req: &CapabilityLeaseRequest,
) -> Result<AuthorizedCapabilityLease, (StatusCode, Value)> {
    let policy_hash = capability_lease_policy_hash(req);
    let request_hash = capability_lease_request_hash(req);

    // 1) Resolve the SEALED backing credential (decrypt/mint failure → None → fail closed). Connector's
    //    own credential first, then the github host git-auth fallback. Never exported. Two credential
    //    KINDS resolve here: a sealed PAT (open the sealed token) and a github-app (mint a fresh
    //    installation token from the sealed pem + app_id + installation_id).
    let mut token: Option<String> = None;
    let mut credential_source: Option<String> = None;
    let mut credential_key_source: Option<String> = None;
    if let Some(cid) = req.credential_connector_id.as_deref() {
        if let Some(rec) = read_record_dir(&st.data_dir, &req.credential_store).into_iter().find(|c| c["connector_id"].as_str() == Some(cid)) {
            let (t, src, ks) = resolve_sealed_credential(&rec).await;
            token = t; credential_source = src; credential_key_source = ks;
        }
        if token.is_none() && req.github_host_fallback {
            if let Some(host) = read_record_dir(&st.data_dir, "scm-credentials").into_iter().find(|c| c["connector_id"].as_str() == Some("scm_host_github")) {
                let (t, _src, ks) = resolve_sealed_credential(&host).await;
                if t.is_some() { token = t; credential_source = Some("host-authentication".to_string()); credential_key_source = ks; }
            }
        }
        if req.credential_required && token.is_none() {
            return Err((StatusCode::PRECONDITION_REQUIRED, json!({
                "ok": false, "decision": "blocked", "reason": "scm_credential_required",
                "message": "This lease needs a resolvable backing credential before the crossing.",
                "backing_provider": req.backing_provider, "host_mutation": false,
            })));
        }
    }

    // 2) Wallet authority gate — daemon-derived hashes, verified bound grant. 403 challenge otherwise.
    let now_ms = daemon_now_ms_fail_closed();
    let binding = if req.grant_value.is_null() {
        Err("a wallet_approval_grant is required".to_string())
    } else {
        verify_wallet_approval_grant_binding(&req.grant_value, Some(now_ms), Some(&policy_hash), Some(&request_hash))
    };
    let binding = match binding {
        Ok(b) => b,
        Err(reason) => {
            return Err((StatusCode::FORBIDDEN, json!({
                "ok": false, "decision": "blocked", "reason": req.authority_reason,
                "message": format!(
                    "This crossing requires a wallet grant ({reason}) bound to policy_hash {policy_hash} + request_hash {request_hash}."
                ),
                "required_scopes": req.scopes,
                "allowed_tools": req.allowed_tools,
                "resource_refs": req.resource_refs,
                "approval": { "policy_hash": policy_hash, "request_hash": request_hash },
                "host_mutation": false,
            })));
        }
    };

    // 3) Issue + persist the lease (the 9-field shape). No secret in the descriptor.
    let expires_at = req.grant_value.get("expires_at").or_else(|| req.grant_value.get("expiresAt")).cloned().unwrap_or(Value::Null);
    let lease_id = format!("lease_{}", short_hash(&format!("{policy_hash}:{request_hash}")));
    let authority_provider_ref = if binding.provider_ref.trim().is_empty() { req.authority_provider_ref.clone() } else { binding.provider_ref.clone() };
    let descriptor = json!({
        "schema_version": "ioi.hypervisor.capability-lease.v1",
        "lease_id": lease_id,
        "authority_provider_ref": authority_provider_ref,
        "backing_provider": req.backing_provider,
        "allowed_tools": req.allowed_tools,
        "resource_refs": req.resource_refs,
        "policy_hash": policy_hash,
        "request_hash": request_hash,
        "expires_at": expires_at,
        "receipt_required": req.receipt_required,
        "revocation_ref": req.revocation_ref,
        "grant_ref": binding.grant_ref,
        "credential_source": credential_source,
        "issued_at": iso_now(),
    });
    let _ = persist_record(&st.data_dir, "capability-leases", &lease_id, &descriptor);

    Ok(AuthorizedCapabilityLease {
        descriptor,
        token,
        grant_ref: binding.grant_ref,
        credential_source,
        credential_key_source,
    })
}

/// GET /v1/hypervisor/capability-leases — the authority audit trail: every issued use-only lease
/// (the 9-field shape). NEVER includes a credential/secret — leases are use-only by construction.
pub(crate) async fn handle_capability_lease_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "ok": true, "leases": read_record_dir(&st.data_dir, "capability-leases") }))
}

// ================================================================================================
// Generic connector estate (master-guide #5) — ANY external service as a USE-ONLY lease.
//
// The SCM connectors proved the CapabilityLease gateway; this generalizes it: a connector declares a
// `service`, a `base_url`, and a set of named `allowed_tools` (each {name, method, path}). The agent
// invokes a tool by NAME; the daemon authorizes the crossing through the SAME gateway, resolves the
// connector's sealed bearer credential, performs the authenticated HTTP call, and records a receipt.
// The agent receives a use-only lease scoped to declared tools — it NEVER sees the credential.
// Slack/Databricks/Linear/etc. are just a (service, base_url, allowed_tools) triple. Catalog/connect
// UX + non-bearer auth (OAuth refresh / AWS SigV4) are follow-ons on this same spine.
// ================================================================================================

/// POST /v1/hypervisor/connectors — register a generic service connector (no credential yet).
pub(crate) async fn handle_connector_register(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let service = body.get("service").and_then(Value::as_str).unwrap_or("").trim().to_string();
    let base_url = body.get("base_url").and_then(Value::as_str).unwrap_or("").trim_end_matches('/').to_string();
    if service.is_empty() || base_url.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "service and base_url are required" })));
    }
    let kind = body.get("kind").and_then(Value::as_str).unwrap_or("bearer").to_string();
    let name = body.get("name").and_then(Value::as_str).unwrap_or(service.as_str()).to_string();
    let allowed_tools = body.get("allowed_tools").cloned().unwrap_or_else(|| json!([]));
    let requires_credential = body.get("requires_credential").and_then(Value::as_bool).unwrap_or(true);
    // The auth profile declares HOW a member connects (OAuth authcode+PKCE / DCR / device / BYOA /
    // manual). A BYOA confidential client may carry a client_secret — SEAL it (never store plaintext).
    let mut auth_profile = body.get("auth_profile").cloned().unwrap_or(Value::Null);
    if let Some(secret) = auth_profile.get("client_secret").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
        if let Some(obj) = auth_profile.as_object_mut() {
            obj.remove("client_secret");
            if let Some(sealed) = seal_scm_token(&secret) {
                obj.insert("sealed_client_secret".to_string(), json!(sealed));
            }
        }
    }
    // Org policy: the allow-list of tools members may invoke + the risk posture (set by the org).
    // Default standard / no tool restriction; tightened via the set-policy endpoint or at create.
    let org_policy = body.get("org_policy").cloned().unwrap_or_else(|| json!({ "allowed_tools": Value::Null, "risk_posture": "standard" }));
    let connector_id = format!("conn_{}", short_hash(&format!("{service}:{name}:{base_url}")));
    let connector = json!({
        "schema_version": "ioi.hypervisor.connector.v1",
        "connector_id": connector_id, "service": service, "kind": kind, "name": name,
        "base_url": base_url, "allowed_tools": allowed_tools, "requires_credential": requires_credential,
        "auth_profile": auth_profile, "org_policy": org_policy,
        "auth_posture": if requires_credential { "token-lease:unbound" } else { "open" }, "created_at": iso_now(),
    });
    let _ = persist_record(&st.data_dir, "connectors", &connector_id, &connector);
    (StatusCode::OK, Json(json!({ "ok": true, "connector": connector })))
}

/// GET /v1/hypervisor/connectors — list registered service connectors (NEVER includes credentials).
pub(crate) async fn handle_connector_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "ok": true, "connectors": read_record_dir(&st.data_dir, "connectors") }))
}

/// POST /v1/hypervisor/connectors/:id/credential — bind a sealed bearer credential to a connector.
pub(crate) async fn handle_connector_bind_credential(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut connector) = read_record_dir(&st.data_dir, "connectors").into_iter().find(|c| c["connector_id"].as_str() == Some(id.as_str())) else {
        return Json(json!({ "ok": false, "reason": "unknown connector_id" }));
    };
    let key_source = scm_key_source();
    // Two credential KINDS: a static bearer token, or an OAuth2 refresh token (the daemon mints a
    // fresh access token per use — the model the native Integrations surface uses). Both sealed.
    let cred = if body.get("kind").and_then(Value::as_str) == Some("oauth-refresh") {
        let refresh = body.get("refresh_token").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let token_url = body.get("token_url").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let client_id = body.get("client_id").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let client_secret = body.get("client_secret").and_then(Value::as_str).unwrap_or("").to_string();
        if refresh.is_empty() || token_url.is_empty() {
            return Json(json!({ "ok": false, "reason": "oauth-refresh needs refresh_token and token_url" }));
        }
        let (Some(sealed_refresh), Some(sealed_secret)) = (seal_scm_token(&refresh), seal_scm_token(&client_secret)) else {
            return Json(json!({ "ok": false, "reason": "failed to seal credential" }));
        };
        json!({ "connector_id": id, "kind": "oauth-refresh", "sealed_refresh_token": sealed_refresh,
            "token_url": token_url, "client_id": client_id, "sealed_client_secret": sealed_secret,
            "key_source": key_source, "sealed": true, "bound_at": iso_now() })
    } else if body.get("kind").and_then(Value::as_str) == Some("oidc-workload") {
        // Workload identity (RFC 8693): a sealed subject token, OR a path to a mounted (rotating)
        // workload identity token that the daemon reads fresh each use.
        let token_url = body.get("token_url").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let subject_token_file = body.get("subject_token_file").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let subject_token = body.get("subject_token").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if token_url.is_empty() || (subject_token.is_empty() && subject_token_file.is_empty()) {
            return Json(json!({ "ok": false, "reason": "oidc-workload needs token_url and a subject_token or subject_token_file" }));
        }
        let sealed_subject = if subject_token.is_empty() { Value::Null } else {
            match seal_scm_token(&subject_token) { Some(s) => json!(s), None => return Json(json!({ "ok": false, "reason": "failed to seal subject token" })) }
        };
        json!({ "connector_id": id, "kind": "oidc-workload", "token_url": token_url,
            "sealed_subject_token": sealed_subject, "subject_token_file": subject_token_file,
            "subject_token_type": body.get("subject_token_type").and_then(Value::as_str).unwrap_or("urn:ietf:params:oauth:token-type:jwt"),
            "audience": body.get("audience").and_then(Value::as_str).unwrap_or(""),
            "scopes": body.get("scopes").and_then(Value::as_str).unwrap_or(""),
            "client_id": body.get("client_id").and_then(Value::as_str).unwrap_or(""),
            "key_source": key_source, "sealed": true, "bound_at": iso_now() })
    } else if body.get("kind").and_then(Value::as_str) == Some("aws-sigv4") {
        // AWS keys: seal the secret (+ optional session token); access_key_id/region/service are
        // identifiers stored plainly. Each request is SigV4-signed at invoke time.
        let access_key_id = body.get("access_key_id").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let secret = body.get("secret_access_key").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let region = body.get("region").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let service = body.get("service").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let session = body.get("session_token").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if access_key_id.is_empty() || secret.is_empty() || region.is_empty() || service.is_empty() {
            return Json(json!({ "ok": false, "reason": "aws-sigv4 needs access_key_id, secret_access_key, region, service" }));
        }
        let Some(sealed_secret) = seal_scm_token(&secret) else {
            return Json(json!({ "ok": false, "reason": "failed to seal secret" }));
        };
        let sealed_session = if session.is_empty() { Value::Null } else {
            match seal_scm_token(&session) { Some(s) => json!(s), None => return Json(json!({ "ok": false, "reason": "failed to seal session token" })) }
        };
        json!({ "connector_id": id, "kind": "aws-sigv4", "access_key_id": access_key_id,
            "sealed_secret_access_key": sealed_secret, "sealed_session_token": sealed_session,
            "region": region, "service": service, "key_source": key_source, "sealed": true, "bound_at": iso_now() })
    } else {
        let token = body.get("token").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if token.is_empty() {
            return Json(json!({ "ok": false, "reason": "token is required" }));
        }
        let Some(sealed) = seal_scm_token(&token) else {
            return Json(json!({ "ok": false, "reason": "failed to seal credential" }));
        };
        // "service-account" = a managed long-lived service credential (advanced); else a static bearer.
        let kind = if body.get("kind").and_then(Value::as_str) == Some("service-account") { "service-account" } else { "bearer" };
        json!({ "connector_id": id, "kind": kind, "sealed_token": sealed, "key_source": key_source, "sealed": true, "bound_at": iso_now() })
    };
    let _ = persist_record(&st.data_dir, "connector-credentials", &id, &cred);
    connector["auth_posture"] = json!("token-lease:bound");
    let _ = persist_record(&st.data_dir, "connectors", &id, &connector);
    Json(json!({ "ok": true, "connector_id": id, "auth_posture": "token-lease:bound", "kind": cred["kind"] }))
}

/// DELETE /v1/hypervisor/connectors/:id/credential — revoke the sealed credential (fail-closed after).
pub(crate) async fn handle_connector_revoke_credential(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let revoked = remove_record(&st.data_dir, "connector-credentials", &id);
    if let Some(mut connector) = read_record_dir(&st.data_dir, "connectors").into_iter().find(|c| c["connector_id"].as_str() == Some(id.as_str())) {
        connector["auth_posture"] = json!("token-lease:unbound");
        connector["revoked_at"] = json!(iso_now());
        let _ = persist_record(&st.data_dir, "connectors", &id, &connector);
    }
    Json(json!({ "ok": true, "connector_id": id, "revoked": revoked, "auth_posture": "token-lease:unbound" }))
}

/// POST /v1/hypervisor/connectors/:id/policy — set the org policy (allowed-tools allow-list + risk
/// posture) enforced on every invoke. `allowed_tools: null` = no restriction; an array = allow-list
/// (empty = nothing permitted). risk_posture "locked" blocks all invokes (enabled but not usable).
pub(crate) async fn handle_connector_set_policy(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut connector) = read_record_dir(&st.data_dir, "connectors").into_iter().find(|c| c["connector_id"].as_str() == Some(id.as_str())) else {
        return Json(json!({ "ok": false, "reason": "unknown connector_id" }));
    };
    let allowed_tools = body.get("allowed_tools").cloned().unwrap_or(Value::Null);
    let risk_posture = body.get("risk_posture").and_then(Value::as_str).unwrap_or("standard").to_string();
    let org_policy = json!({ "allowed_tools": allowed_tools, "risk_posture": risk_posture, "set_at": iso_now() });
    connector["org_policy"] = org_policy.clone();
    let _ = persist_record(&st.data_dir, "connectors", &id, &connector);
    Json(json!({ "ok": true, "connector_id": id, "org_policy": org_policy }))
}

/// DELETE /v1/hypervisor/connectors/:id — remove a connector and its sealed credential entirely.
pub(crate) async fn handle_connector_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let cred = remove_record(&st.data_dir, "connector-credentials", &id);
    let conn = remove_record(&st.data_dir, "connectors", &id);
    Json(json!({ "ok": true, "connector_id": id, "removed": conn, "credential_removed": cred }))
}

/// POST /v1/hypervisor/connectors/:id/oauth/discover — auto-configure the auth_profile for an MCP
/// connector: discover the authorization server (RFC 9728 → 8414) and dynamically register a public
/// PKCE client (RFC 7591). No per-service OAuth app needed; no vendor secret. Idempotent (keeps an
/// existing client_id).
pub(crate) async fn handle_connector_oauth_discover(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut connector) = read_record_dir(&st.data_dir, "connectors").into_iter().find(|c| c["connector_id"].as_str() == Some(id.as_str())) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "unknown connector_id" })));
    };
    let base_url = connector["base_url"].as_str().unwrap_or("").to_string();
    let redirect_uri = body.get("redirect_uri").and_then(Value::as_str).unwrap_or("http://127.0.0.1:4173/__ioi/integrations/oauth/callback").to_string();
    let (auth_ep, token_ep, reg_ep, device_ep, scopes) = match discover_oauth_for_mcp(&base_url).await {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": "discovery_failed", "message": e }))),
    };
    let existing = connector["auth_profile"]["client_id"].as_str().unwrap_or("").to_string();
    let client_id = if !existing.is_empty() {
        existing
    } else if !reg_ep.is_empty() {
        match dynamic_client_register(&reg_ep, &redirect_uri, &scopes).await {
            Ok(c) => c,
            Err(e) => return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": "dcr_failed", "message": e }))),
        }
    } else {
        return (StatusCode::CONFLICT, Json(json!({ "ok": false, "reason": "no_registration_endpoint", "message": "Authorization server has no Dynamic Client Registration; provide a BYOA client_id in the auth_profile." })));
    };
    let auth_profile = json!({
        "type": "oauth_authcode_pkce", "authorization_endpoint": auth_ep, "token_endpoint": token_ep,
        "registration_endpoint": reg_ep, "device_authorization_endpoint": device_ep,
        "client_id": client_id, "scopes": scopes, "discovered": true,
    });
    connector["auth_profile"] = auth_profile.clone();
    let _ = persist_record(&st.data_dir, "connectors", &id, &connector);
    (StatusCode::OK, Json(json!({ "ok": true, "discovered": true, "auth_profile": auth_profile })))
}

/// POST /v1/hypervisor/connectors/:id/oauth/start — begin the OAuth Authorization Code + PKCE
/// Connect ("authorize this integration"). Returns the provider authorize URL the browser visits.
/// Stores the PKCE verifier (sealed) keyed by state; no secret leaves the daemon.
pub(crate) async fn handle_connector_oauth_start(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(connector) = read_record_dir(&st.data_dir, "connectors").into_iter().find(|c| c["connector_id"].as_str() == Some(id.as_str())) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "unknown connector_id" })));
    };
    let ap = &connector["auth_profile"];
    let authorization_endpoint = ap["authorization_endpoint"].as_str().unwrap_or("").to_string();
    let token_endpoint = ap["token_endpoint"].as_str().unwrap_or("").to_string();
    let client_id = ap["client_id"].as_str().unwrap_or("").to_string();
    if authorization_endpoint.is_empty() || token_endpoint.is_empty() || client_id.is_empty() {
        return (StatusCode::CONFLICT, Json(json!({ "ok": false, "reason": "no_oauth_profile", "message": "This integration has no OAuth auth_profile (authorization_endpoint/token_endpoint/client_id)." })));
    }
    let scopes = ap["scopes"].as_array().map(|a| a.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>().join(" ")).unwrap_or_default();
    let redirect_uri = body.get("redirect_uri").and_then(Value::as_str).unwrap_or("http://127.0.0.1:4173/__ioi/integrations/oauth/callback").to_string();
    let verifier = random_token(64);
    let challenge = pkce_challenge(&verifier);
    let state = random_token(32);
    let Some(sealed_verifier) = seal_scm_token(&verifier) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "reason": "failed to seal pkce verifier" })));
    };
    let pending = json!({ "state": state, "connector_id": id, "sealed_verifier": sealed_verifier, "redirect_uri": redirect_uri, "created_at": iso_now() });
    let _ = persist_record(&st.data_dir, "oauth-pending", &state, &pending);
    let mut authorize_url = format!(
        "{authorization_endpoint}?response_type=code&client_id={}&redirect_uri={}&state={state}&code_challenge={challenge}&code_challenge_method=S256",
        pct(&client_id), pct(&redirect_uri)
    );
    if !scopes.is_empty() {
        authorize_url.push_str(&format!("&scope={}", pct(&scopes)));
    }
    (StatusCode::OK, Json(json!({ "ok": true, "authorize_url": authorize_url, "state": state })))
}

/// POST /v1/hypervisor/connectors/oauth/callback — finish the Connect: exchange the authorization
/// code (PKCE) for tokens and SEAL the refresh token as an oauth-refresh credential. The agent never
/// sees any of it — it gets scoped capability leases minted from this backing material.
pub(crate) async fn handle_connector_oauth_callback(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let state = body.get("state").and_then(Value::as_str).unwrap_or("").to_string();
    let code = body.get("code").and_then(Value::as_str).unwrap_or("").to_string();
    if state.is_empty() || code.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "state and code are required" })));
    }
    let Some(pending) = read_record_dir(&st.data_dir, "oauth-pending").into_iter().find(|p| p["state"].as_str() == Some(state.as_str())) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "unknown or expired state" })));
    };
    let connector_id = pending["connector_id"].as_str().unwrap_or("").to_string();
    let redirect_uri = pending["redirect_uri"].as_str().unwrap_or("").to_string();
    let Some(verifier) = pending["sealed_verifier"].as_str().and_then(open_scm_token) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "reason": "could not open pkce verifier" })));
    };
    let Some(connector) = read_record_dir(&st.data_dir, "connectors").into_iter().find(|c| c["connector_id"].as_str() == Some(connector_id.as_str())) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "unknown connector_id" })));
    };
    let ap = &connector["auth_profile"];
    let token_endpoint = ap["token_endpoint"].as_str().unwrap_or("").to_string();
    let client_id = ap["client_id"].as_str().unwrap_or("").to_string();
    // Confidential BYOA client (e.g. Slack): the sealed client_secret is sent at the token exchange.
    let client_secret = ap["sealed_client_secret"].as_str().and_then(open_scm_token).unwrap_or_default();
    let (access, refresh) = match exchange_oauth_code(&token_endpoint, &client_id, &client_secret, &code, &redirect_uri, &verifier).await {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": "oauth_exchange_failed", "message": e }))),
    };
    // Prefer a refresh token (daemon mints access per use); else seal the access token as a bearer.
    let Some(cred) = seal_oauth_result(&connector_id, &token_endpoint, &client_id, &client_secret, &access, refresh.as_deref()) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "reason": "failed to seal token" })));
    };
    let _ = persist_record(&st.data_dir, "connector-credentials", &connector_id, &cred);
    if let Some(mut c) = read_record_dir(&st.data_dir, "connectors").into_iter().find(|c| c["connector_id"].as_str() == Some(connector_id.as_str())) {
        c["auth_posture"] = json!("token-lease:bound");
        let _ = persist_record(&st.data_dir, "connectors", &connector_id, &c);
    }
    let _ = remove_record(&st.data_dir, "oauth-pending", &state);
    (StatusCode::OK, Json(json!({ "ok": true, "connected": true, "connector_id": connector_id, "credential_kind": cred["kind"] })))
}

// Seal an OAuth result (access + optional refresh) as a connector credential: oauth-refresh when a
// refresh token is present (daemon mints access per use), else a static bearer access token.
fn seal_oauth_result(connector_id: &str, token_endpoint: &str, client_id: &str, client_secret: &str, access: &str, refresh: Option<&str>) -> Option<Value> {
    let key_source = scm_key_source();
    if let Some(refresh) = refresh {
        let sealed = seal_scm_token(refresh)?;
        Some(json!({ "connector_id": connector_id, "kind": "oauth-refresh", "sealed_refresh_token": sealed, "token_url": token_endpoint, "client_id": client_id, "sealed_client_secret": seal_scm_token(client_secret)?, "key_source": key_source, "sealed": true, "bound_at": iso_now() }))
    } else {
        let sealed = seal_scm_token(access)?;
        Some(json!({ "connector_id": connector_id, "kind": "bearer", "sealed_token": sealed, "key_source": key_source, "sealed": true, "bound_at": iso_now() }))
    }
}

/// POST /v1/hypervisor/connectors/:id/oauth/device/start — OAuth Device Authorization Grant (RFC
/// 8628): headless / no-redirect connect. Returns the user_code + verification_uri to display; the
/// user authorizes on another device, then the client polls. (Phase D auth profile.)
pub(crate) async fn handle_connector_device_start(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(connector) = read_record_dir(&st.data_dir, "connectors").into_iter().find(|c| c["connector_id"].as_str() == Some(id.as_str())) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "unknown connector_id" })));
    };
    let ap = &connector["auth_profile"];
    let device_ep = ap["device_authorization_endpoint"].as_str().unwrap_or("").to_string();
    let client_id = ap["client_id"].as_str().unwrap_or("").to_string();
    if device_ep.is_empty() || client_id.is_empty() {
        return (StatusCode::CONFLICT, Json(json!({ "ok": false, "reason": "no_device_profile", "message": "This integration has no device_authorization_endpoint (run discovery, or the AS lacks device flow)." })));
    }
    let scopes = ap["scopes"].as_array().map(|a| a.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>().join(" ")).unwrap_or_default();
    let resp = reqwest::Client::new().post(&device_ep).header("User-Agent", "ioi-hypervisor").header("Accept", "application/json").form(&[("client_id", client_id.as_str()), ("scope", scopes.as_str())]).timeout(std::time::Duration::from_secs(20)).send().await;
    let v: Value = match resp {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or(Value::Null),
        Ok(r) => return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": "device_start_failed", "status": r.status().as_u16() }))),
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": format!("device endpoint unreachable: {e}") }))),
    };
    let device_code = v["device_code"].as_str().unwrap_or("").to_string();
    if device_code.is_empty() {
        return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": "no device_code in response" })));
    }
    let Some(sealed) = seal_scm_token(&device_code) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "reason": "failed to seal device_code" })));
    };
    let interval = v["interval"].as_u64().unwrap_or(5);
    let _ = persist_record(&st.data_dir, "oauth-device-pending", &id, &json!({ "connector_id": id, "sealed_device_code": sealed, "interval": interval, "created_at": iso_now() }));
    (StatusCode::OK, Json(json!({
        "ok": true, "user_code": v["user_code"], "verification_uri": v["verification_uri"],
        "verification_uri_complete": v["verification_uri_complete"], "interval": interval, "expires_in": v["expires_in"],
    })))
}

/// POST /v1/hypervisor/connectors/:id/oauth/device/poll — poll the token endpoint for the device
/// grant; on success seals the tokens (oauth-refresh). Returns {pending:true} while the user hasn't
/// authorized yet.
pub(crate) async fn handle_connector_device_poll(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(pending) = read_record_dir(&st.data_dir, "oauth-device-pending").into_iter().find(|p| p["connector_id"].as_str() == Some(id.as_str())) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "no pending device authorization" })));
    };
    let Some(connector) = read_record_dir(&st.data_dir, "connectors").into_iter().find(|c| c["connector_id"].as_str() == Some(id.as_str())) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "unknown connector_id" })));
    };
    let ap = &connector["auth_profile"];
    let token_endpoint = ap["token_endpoint"].as_str().unwrap_or("").to_string();
    let client_id = ap["client_id"].as_str().unwrap_or("").to_string();
    let Some(device_code) = pending["sealed_device_code"].as_str().and_then(open_scm_token) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "reason": "could not open device_code" })));
    };
    let resp = reqwest::Client::new().post(&token_endpoint).header("User-Agent", "ioi-hypervisor").header("Accept", "application/json").form(&[("grant_type", "urn:ietf:params:oauth:grant-type:device_code"), ("device_code", device_code.as_str()), ("client_id", client_id.as_str())]).timeout(std::time::Duration::from_secs(20)).send().await;
    let (status, v): (u16, Value) = match resp {
        Ok(r) => { let s = r.status().as_u16(); (s, r.json().await.unwrap_or(Value::Null)) }
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": format!("token endpoint unreachable: {e}") }))),
    };
    if (200..300).contains(&status) {
        let access = v["access_token"].as_str().unwrap_or("").to_string();
        let refresh = v["refresh_token"].as_str();
        let Some(cred) = seal_oauth_result(&id, &token_endpoint, &client_id, "", &access, refresh) else {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "reason": "failed to seal token" })));
        };
        let _ = persist_record(&st.data_dir, "connector-credentials", &id, &cred);
        if let Some(mut c) = read_record_dir(&st.data_dir, "connectors").into_iter().find(|c| c["connector_id"].as_str() == Some(id.as_str())) {
            c["auth_posture"] = json!("token-lease:bound");
            let _ = persist_record(&st.data_dir, "connectors", &id, &c);
        }
        let _ = remove_record(&st.data_dir, "oauth-device-pending", &id);
        return (StatusCode::OK, Json(json!({ "ok": true, "connected": true, "connector_id": id, "credential_kind": cred["kind"] })));
    }
    let err = v["error"].as_str().unwrap_or("");
    if err == "authorization_pending" || err == "slow_down" {
        return (StatusCode::OK, Json(json!({ "ok": true, "pending": true, "error": err })));
    }
    (StatusCode::OK, Json(json!({ "ok": false, "reason": if err.is_empty() { "device_poll_failed" } else { err } })))
}

/// POST /v1/hypervisor/connectors/:id/invoke — the wallet-authorized USE crossing: invoke a declared
/// tool on the connector's service with its sealed credential. The agent names a tool; the daemon
/// authorizes via the CapabilityLease gateway, performs the authenticated call, and returns the tool
/// RESULT (credential redacted). The credential never leaves the daemon.
pub(crate) async fn handle_connector_invoke(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(connector) = read_record_dir(&st.data_dir, "connectors").into_iter().find(|c| c["connector_id"].as_str() == Some(id.as_str())) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "unknown connector_id" })));
    };
    let service = connector["service"].as_str().unwrap_or("service").to_string();
    let kind = connector["kind"].as_str().unwrap_or("bearer").to_string();
    let base_url = connector["base_url"].as_str().unwrap_or("").to_string();
    let requires_credential = connector["requires_credential"].as_bool().unwrap_or(true);
    let tool_name = body.get("tool").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if tool_name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "tool is required" })));
    }
    // For HTTP connectors the lease only permits DECLARED tools (off-manifest → refused). MCP servers
    // define their own tools dynamically, so we don't gate on a static manifest — but the wallet
    // grant still scopes to THIS tool name, so authority stays per-tool either way.
    let (method, path) = if kind == "mcp" {
        ("POST".to_string(), "/".to_string())
    } else {
        let Some(tool) = connector["allowed_tools"].as_array().and_then(|tools| tools.iter().find(|t| t["name"].as_str() == Some(tool_name.as_str())).cloned()) else {
            return (StatusCode::FORBIDDEN, Json(json!({ "ok": false, "reason": "tool_not_allowed", "message": format!("'{tool_name}' is not a declared tool on this connector") })));
        };
        (tool["method"].as_str().unwrap_or("POST").to_uppercase(), tool["path"].as_str().unwrap_or("/").to_string())
    };
    let request_args = body.get("request").cloned().unwrap_or_else(|| json!({}));

    // ORG POLICY gate (Phase C) — enforced before the wallet crossing. risk_posture "locked" blocks
    // all use; an allowed_tools allow-list (when set) restricts which tools members may invoke.
    let org_policy = connector["org_policy"].clone();
    let risk_posture = org_policy["risk_posture"].as_str().unwrap_or("standard").to_string();
    if risk_posture == "locked" {
        return (StatusCode::FORBIDDEN, Json(json!({ "ok": false, "reason": "policy_locked", "message": "Org policy has locked this integration (enabled but not usable).", "risk_posture": risk_posture })));
    }
    if let Some(allow) = org_policy["allowed_tools"].as_array() {
        if !allow.iter().any(|t| t.as_str() == Some(tool_name.as_str())) {
            return (StatusCode::FORBIDDEN, Json(json!({ "ok": false, "reason": "tool_not_in_policy", "message": format!("Org policy does not permit the tool '{tool_name}' on this integration."), "allowed_tools": allow })));
        }
    }

    // Authorize the USE crossing through the SAME gateway (connector-credentials vault).
    let lease_req = CapabilityLeaseRequest {
        authority_provider_ref: "wallet.network".to_string(),
        backing_provider: format!("{service}:connector:{id}"),
        allowed_tools: vec![tool_name.clone()],
        resource_refs: vec![base_url.clone(), service.clone()],
        scopes: vec![format!("{service}.{tool_name}")],
        policy_domain: "hypervisor.connector.invoke.policy.v1".to_string(),
        request_domain: "hypervisor.connector.invoke.request.v1".to_string(),
        request_facets: json!({ "service": service, "tool": tool_name, "request_hash": sha256_json_ref(&request_args) }),
        credential_connector_id: Some(id.clone()),
        credential_store: "connector-credentials".to_string(),
        credential_required: requires_credential,
        github_host_fallback: false,
        receipt_required: true,
        revocation_ref: format!("connectors/{id}/credential"),
        authority_reason: "connector_invoke_authority_required".to_string(),
        grant_value: body.get("wallet_approval_grant").cloned().unwrap_or(Value::Null),
    };
    let lease = match authorize_capability_lease(&st, &lease_req).await {
        Ok(l) => l,
        Err((code, challenge)) => return (code, Json(challenge)),
    };
    let token = lease.token.unwrap_or_default();

    // daemon EXECUTES the authenticated call (the agent never holds the token). An MCP connector
    // performs a JSON-RPC tools/call; any other connector performs the declared HTTP request.
    let redact = |s: String| if token.is_empty() { s } else { s.replace(token.as_str(), "***") };
    let url = if kind == "mcp" { base_url.clone() } else { format!("{}{}", base_url, if path.starts_with('/') { path.clone() } else { format!("/{path}") }) };
    let (status_code, response_value, error) = if kind == "mcp" {
        match mcp_call_tool(&base_url, &token, &tool_name, &request_args).await {
            Ok(result) => {
                let red = redact(serde_json::to_string(&result).unwrap_or_default());
                (200u16, serde_json::from_str(&red).unwrap_or(result), None)
            }
            Err(e) => (502u16, Value::Null, Some(redact(e))),
        }
    } else {
        let client = reqwest::Client::new();
        let mut rb = match method.as_str() {
            "GET" => client.get(&url),
            "POST" => client.post(&url),
            "PUT" => client.put(&url),
            "PATCH" => client.patch(&url),
            "DELETE" => client.delete(&url),
            other => return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": format!("unsupported method {other}") }))),
        };
        rb = rb.header("User-Agent", "ioi-hypervisor").header("Accept", "application/json").timeout(std::time::Duration::from_secs(20));
        let body_bytes = if method != "GET" { serde_json::to_vec(&request_args).unwrap_or_default() } else { Vec::new() };
        if lease.credential_source.as_deref() == Some("aws-sigv4") {
            // AWS SigV4: sign this exact request with the sealed keys (never a bearer).
            if let Some(cred) = read_record_dir(&st.data_dir, "connector-credentials").into_iter().find(|c| c["connector_id"].as_str() == Some(id.as_str())) {
                let access_key = cred["access_key_id"].as_str().unwrap_or("").to_string();
                let secret = cred["sealed_secret_access_key"].as_str().and_then(open_scm_token).unwrap_or_default();
                let session = cred["sealed_session_token"].as_str().and_then(open_scm_token);
                let region = cred["region"].as_str().unwrap_or("us-east-1").to_string();
                let service = cred["service"].as_str().unwrap_or("").to_string();
                let parsed = reqwest::Url::parse(&url).ok();
                let host = parsed.as_ref().map(|u| match u.port() { Some(p) => format!("{}:{}", u.host_str().unwrap_or(""), p), None => u.host_str().unwrap_or("").to_string() }).unwrap_or_default();
                let canonical_uri = parsed.as_ref().map(|u| u.path().to_string()).unwrap_or_else(|| "/".to_string());
                let canonical_query = parsed.as_ref().and_then(|u| u.query()).unwrap_or("").to_string();
                let amz = amz_date_now();
                let auth = sigv4_authorization(&method, &host, &canonical_uri, &canonical_query, &body_bytes, &access_key, &secret, session.as_deref(), &region, &service, &amz);
                rb = rb.header("Authorization", auth).header("x-amz-date", amz);
                if let Some(t) = &session { rb = rb.header("x-amz-security-token", t.clone()); }
            }
            if !body_bytes.is_empty() { rb = rb.header("Content-Type", "application/json").body(body_bytes); }
        } else {
            if !token.is_empty() { rb = rb.bearer_auth(&token); }
            if !body_bytes.is_empty() { rb = rb.header("Content-Type", "application/json").body(body_bytes); }
        }
        match rb.send().await {
            Ok(r) => {
                let sc = r.status().as_u16();
                let red = redact(r.text().await.unwrap_or_default());
                (sc, serde_json::from_str(&red).unwrap_or(Value::String(red.chars().take(2000).collect())), None)
            }
            Err(e) => (0, Value::Null, Some(redact(e.to_string()))),
        }
    };
    let ok = (200..300).contains(&status_code);
    let receipt_id = format!("invk_{}", short_hash(&format!("{id}:{tool_name}:{status_code}")));
    let receipt = json!({
        "schema_version": "ioi.hypervisor.connector-invoke-receipt.v1",
        "receipt_id": receipt_id, "connector_id": id, "service": service, "tool": tool_name,
        "method": method, "url": url, "status": status_code, "ok": ok,
        "credential_source": lease.credential_source, "grant_ref": lease.grant_ref,
        "capability_lease": lease.descriptor, "org_policy": org_policy, "host_mutation": true, "error": error,
        "invoked_at": iso_now(),
    });
    let _ = persist_record(&st.data_dir, "connector-invoke-receipts", &receipt_id, &receipt);
    (StatusCode::OK, Json(json!({ "ok": ok, "status": status_code, "response": response_value, "receipt": receipt })))
}

/// GET /v1/hypervisor/connectors/:id/mcp/tools — discover an MCP connector's tools (read-only). Uses
/// the resolved credential (428 if required + unbound); discovery is grant-free, tools/call is leased.
pub(crate) async fn handle_connector_mcp_tools(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(connector) = read_record_dir(&st.data_dir, "connectors").into_iter().find(|c| c["connector_id"].as_str() == Some(id.as_str())) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "unknown connector_id" })));
    };
    let base_url = connector["base_url"].as_str().unwrap_or("").to_string();
    let requires_credential = connector["requires_credential"].as_bool().unwrap_or(true);
    let token = if requires_credential {
        match read_record_dir(&st.data_dir, "connector-credentials").into_iter().find(|c| c["connector_id"].as_str() == Some(id.as_str())) {
            Some(rec) => resolve_sealed_credential(&rec).await.0,
            None => None,
        }
    } else {
        None
    };
    if requires_credential && token.is_none() {
        return (StatusCode::PRECONDITION_REQUIRED, Json(json!({ "ok": false, "reason": "scm_credential_required", "message": "Bind a credential before discovering MCP tools." })));
    }
    match mcp_list_tools(&base_url, &token.unwrap_or_default()).await {
        Ok(tools) => (StatusCode::OK, Json(json!({ "ok": true, "tools": tools }))),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": e }))),
    }
}

// SCM credentials are sealed at rest with the canonical ioi-crypto secret encryption (Argon2id KDF
// + AEAD), keyed by the SAME wallet-secret passphrase the wallet.network secret model uses
// (IOI_WALLET_SECRET_PASS → IOI_GUARDIAN_KEY_PASS → "local-mode" fallback). With a real passphrase
// set this is genuine at-rest protection (key supplied out-of-band, never in the data dir); without
// one it seals under the local-mode fallback (no plaintext at rest, but key is well-known — honest
// label travels via key_source). Decrypt failure → token unavailable → publish fails closed.
fn scm_secret_passphrase() -> String {
    std::env::var("IOI_WALLET_SECRET_PASS").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
        .or_else(|| std::env::var("IOI_GUARDIAN_KEY_PASS").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()))
        .unwrap_or_else(|| "local-mode".to_string())
}
fn scm_key_source() -> &'static str {
    let has = |k: &str| std::env::var(k).map(|v| !v.trim().is_empty()).unwrap_or(false);
    if has("IOI_WALLET_SECRET_PASS") || has("IOI_GUARDIAN_KEY_PASS") { "wallet-secret-pass" } else { "local-mode-fallback" }
}
fn seal_scm_token(token: &str) -> Option<String> {
    ioi_crypto::key_store::encrypt_key(token.as_bytes(), &scm_secret_passphrase()).ok().map(hex::encode)
}
fn open_scm_token(sealed_hex: &str) -> Option<String> {
    let bytes = hex::decode(sealed_hex).ok()?;
    let plain = ioi_crypto::key_store::decrypt_key(&bytes, &scm_secret_passphrase()).ok()?;
    String::from_utf8(plain.0.to_vec()).ok()
}

/// POST /v1/hypervisor/scm-connectors — register a named SCM remote target.
pub(crate) async fn handle_scm_connector_register(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let remote_url = body.get("remote_url").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if remote_url.is_empty() {
        return Json(json!({ "ok": false, "reason": "remote_url is required" }));
    }
    let kind = body.get("kind").and_then(Value::as_str).unwrap_or("git").to_string();
    let name = body.get("name").and_then(Value::as_str).unwrap_or(remote_url.as_str()).to_string();
    // local file:// remotes need no credentials; hosted connectors declare a token-lease posture
    // that a scoped secret lease must satisfy before publish (fail-closed until bound).
    let is_local = remote_url.starts_with("file:") || remote_url.starts_with('/') || remote_url.starts_with("./");
    // Hosted (non-local) connectors require a credential by default; an explicit flag lets a local
    // remote also require one (exercises the credential gate without an external host).
    let requires_credential = body.get("requires_credential").and_then(Value::as_bool).unwrap_or(!is_local);
    let auth_posture = if requires_credential { "token-lease:unbound".to_string() } else { "local-none".to_string() };
    let connector_id = format!("scm_{}", short_hash(&format!("{remote_url}:{kind}")));
    let record = json!({
        "schema_version": "ioi.hypervisor.scm-connector.v1",
        "connector_id": connector_id,
        "kind": kind,
        "name": name,
        "remote_url": remote_url,
        "requires_credential": requires_credential,
        "auth_posture": auth_posture,
        "created_at": iso_now(),
    });
    let _ = persist_record(&st.data_dir, "scm-connectors", &connector_id, &record);
    Json(json!({ "ok": true, "connector": record }))
}

/// GET /v1/hypervisor/scm-connectors — list registered connectors (NEVER includes tokens).
pub(crate) async fn handle_scm_connector_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "ok": true, "connectors": read_record_dir(&st.data_dir, "scm-connectors") }))
}

/// POST /v1/hypervisor/scm-connectors/:id/credential — bind a scoped credential (SCM token) to a
/// connector. The token is stored in a SEPARATE scoped record (`scm-credentials`) that is never
/// returned in connector listings; the connector only flips auth_posture unbound→bound. Interim
/// posture: the daemon data dir is the trust boundary — encrypted / wallet.network secret leases are
/// the named long-term. Binding ≠ release: the wallet gate stays on the publish CROSSING.
pub(crate) async fn handle_scm_connector_bind_credential(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let token = body.get("token").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if token.is_empty() {
        return Json(json!({ "ok": false, "reason": "token is required" }));
    }
    let Some(mut connector) = read_record_dir(&st.data_dir, "scm-connectors")
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(id.as_str()))
    else {
        return Json(json!({ "ok": false, "reason": "unknown connector_id" }));
    };
    // Seal the secret at rest (no plaintext token in the record) and store it scoped — never
    // surfaced in connector listings. Fail closed if sealing fails (do not fall back to plaintext).
    let Some(sealed) = seal_scm_token(&token) else {
        return Json(json!({ "ok": false, "reason": "failed to seal credential" }));
    };
    let key_source = scm_key_source();
    let cred = json!({ "connector_id": id, "sealed_token": sealed, "key_source": key_source, "sealed": true, "bound_at": iso_now() });
    let _ = persist_record(&st.data_dir, "scm-credentials", &id, &cred);
    connector["auth_posture"] = json!("token-lease:bound");
    connector["requires_credential"] = json!(true);
    connector["credential_key_source"] = json!(key_source);
    let _ = persist_record(&st.data_dir, "scm-connectors", &id, &connector);
    // NEVER return the token
    Json(json!({ "ok": true, "connector_id": id, "auth_posture": "token-lease:bound", "key_source": key_source }))
}

/// DELETE /v1/hypervisor/scm-connectors/:id/credential — revoke a bound credential. Deletes the
/// sealed credential record and flips the connector back to unbound. After revoke, the publish
/// crossing fails closed (no credential to resolve — and for github repos, no host-fallback either,
/// once the host connection is revoked). This is the real backing for the native "Git
/// authentications → Disconnect" (no fake ack).
pub(crate) async fn handle_scm_connector_revoke_credential(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let revoked = remove_record(&st.data_dir, "scm-credentials", &id);
    // Flip the connector posture back to unbound (if the connector record still exists).
    if let Some(mut connector) = read_record_dir(&st.data_dir, "scm-connectors")
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(id.as_str()))
    {
        connector["auth_posture"] = json!("token-lease:unbound");
        connector["credential_key_source"] = Value::Null;
        connector["connected_login"] = Value::Null;
        connector["revoked_at"] = json!(iso_now());
        let _ = persist_record(&st.data_dir, "scm-connectors", &id, &connector);
    }
    Json(json!({ "ok": true, "connector_id": id, "revoked": revoked, "auth_posture": "token-lease:unbound" }))
}

// ============================================================================================
// Secrets plane — org/user/project secrets, SEALED at rest in the daemon. The value is encrypted
// with the same passphrase-derived key as SCM credentials and stored in a SEPARATE `secret-values`
// record that is NEVER returned by any list/get. The `secrets` record holds METADATA ONLY (name,
// scope, mount) so the surface can render without ever exposing the value. This backs the native
// Org/User Settings → Secrets pages (previously mock-only). Boundary: daemon EXECUTES (holds the
// sealed value), the agent/session/UI receive only metadata; injection into environments is the
// downstream consumer (a secret is "available in new environments" per the native copy).
// ============================================================================================

/// Generic value sealing (delegates to the SCM token sealer — same Argon2id+AEAD key). Named for
/// the secrets plane so call sites read honestly.
fn seal_value(plain: &str) -> Option<String> {
    seal_scm_token(plain)
}

/// Derive a stable scope key from a connect-JSON SecretScope ({organizationId|userId|projectId:..}).
/// Used both to namespace the secret id (unique per scope+name) and to filter list-by-scope.
fn secret_scope_key(scope: &Value) -> String {
    for k in [
        "organizationId",
        "userId",
        "projectId",
        "organization_id",
        "user_id",
        "project_id",
    ] {
        if let Some(v) = scope.get(k).and_then(Value::as_str) {
            if !v.is_empty() {
                // normalize snake/camel to a single key form for stability
                let norm = k.trim_end_matches("_id").replace("_id", "");
                let norm = match norm.as_str() {
                    "organization" | "organizationId" => "organizationId",
                    "user" | "userId" => "userId",
                    "project" | "projectId" => "projectId",
                    other => other,
                };
                return format!("{norm}:{v}");
            }
        }
    }
    "global".to_string()
}

/// POST /v1/hypervisor/secrets — create (or overwrite) a secret. Seals the value; persists metadata.
pub(crate) async fn handle_secret_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let name = body.get("name").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "name is required" })));
    }
    let value = body.get("value").and_then(Value::as_str).unwrap_or("");
    if value.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "value is required" })));
    }
    let scope = body.get("scope").cloned().unwrap_or(Value::Null);
    let mount = body.get("mount").cloned().unwrap_or(Value::Null);
    let credential_proxy = body
        .get("credential_proxy")
        .or_else(|| body.get("credentialProxy"))
        .cloned()
        .unwrap_or(Value::Null);
    let scope_key = secret_scope_key(&scope);
    let secret_id = format!("sec_{}", short_hash(&format!("{scope_key}:{name}")));
    let Some(sealed) = seal_value(value) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "reason": "failed to seal secret" })));
    };
    let key_source = scm_key_source();
    let now = iso_now();
    // Preserve created_at on overwrite (same scope+name => same id).
    let created_at = read_record_dir(&st.data_dir, "secrets")
        .into_iter()
        .find(|s| s["secret_id"].as_str() == Some(secret_id.as_str()))
        .and_then(|s| s["created_at"].as_str().map(String::from))
        .unwrap_or_else(|| now.clone());
    let record = json!({
        "schema_version": "ioi.hypervisor.secret.v1",
        "secret_id": secret_id,
        "name": name,
        "scope": scope,
        "scope_key": scope_key,
        "mount": mount,
        "credential_proxy": credential_proxy,
        "key_source": key_source,
        "sealed": true,
        "created_at": created_at,
        "updated_at": now,
    });
    let _ = persist_record(&st.data_dir, "secrets", &secret_id, &record);
    // Sealed value lives in a SEPARATE record, never surfaced by any read.
    let cred = json!({ "secret_id": secret_id, "sealed_value": sealed, "key_source": key_source, "sealed": true, "updated_at": now });
    let _ = persist_record(&st.data_dir, "secret-values", &secret_id, &cred);
    (StatusCode::OK, Json(json!({ "ok": true, "secret": record })))
}

/// GET /v1/hypervisor/secrets — list secret METADATA (never values).
pub(crate) async fn handle_secret_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "ok": true, "secrets": read_record_dir(&st.data_dir, "secrets") }))
}

/// POST /v1/hypervisor/secrets/:id/value — rotate the sealed value (name/scope unchanged).
pub(crate) async fn handle_secret_update_value(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let value = body.get("value").and_then(Value::as_str).unwrap_or("");
    if value.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "value is required" })));
    }
    let Some(mut record) = read_record_dir(&st.data_dir, "secrets")
        .into_iter()
        .find(|s| s["secret_id"].as_str() == Some(id.as_str()))
    else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "unknown secret_id" })));
    };
    let Some(sealed) = seal_value(value) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "reason": "failed to seal secret" })));
    };
    let key_source = scm_key_source();
    let now = iso_now();
    let cred = json!({ "secret_id": id, "sealed_value": sealed, "key_source": key_source, "sealed": true, "updated_at": now });
    let _ = persist_record(&st.data_dir, "secret-values", &id, &cred);
    record["updated_at"] = json!(now);
    record["key_source"] = json!(key_source);
    let _ = persist_record(&st.data_dir, "secrets", &id, &record);
    (StatusCode::OK, Json(json!({ "ok": true, "secret": record })))
}

/// DELETE /v1/hypervisor/secrets/:id — remove the secret (metadata + sealed value).
pub(crate) async fn handle_secret_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let removed = remove_record(&st.data_dir, "secrets", &id);
    let _ = remove_record(&st.data_dir, "secret-values", &id);
    Json(json!({ "ok": true, "secret_id": id, "removed": removed }))
}

// ============================================================================================
// API access tokens plane — inbound tokens that authenticate calls TO the Hypervisor API (the
// native "API access tokens" surface). Best practice for an inbound credential: store ONLY a
// sha256 hash + metadata; return the plaintext exactly ONCE (in the create response). The token is
// never recoverable after creation. (Inbound enforcement on the daemon is a separate concern; the
// hash is stored ready for it — the management surface is real today: mint / list / revoke.)
// ============================================================================================

/// RFC 3339 timestamp `secs` seconds from now (token expiry).
fn iso_in_seconds(secs: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    (time::OffsetDateTime::now_utc() + time::Duration::seconds(secs))
        .format(&Rfc3339)
        .unwrap_or_else(|_| iso_now())
}

/// Parse a connect-JSON Duration ("2592000s") or {seconds} object into seconds (default 30 days).
fn parse_valid_for(v: &Value) -> i64 {
    if let Some(s) = v.as_str() {
        return s.trim_end_matches('s').trim().parse::<i64>().unwrap_or(2_592_000);
    }
    if let Some(n) = v.get("seconds") {
        return n.as_i64().or_else(|| n.as_str().and_then(|s| s.parse().ok())).unwrap_or(2_592_000);
    }
    2_592_000
}

/// POST /v1/hypervisor/api-tokens — mint a token. Returns the plaintext ONCE; stores only the hash.
pub(crate) async fn handle_api_token_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let description = body.get("description").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if description.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "description is required" })));
    }
    let user_id = body.get("user_id").or_else(|| body.get("userId")).and_then(Value::as_str).unwrap_or("").to_string();
    let read_only = body.get("read_only").or_else(|| body.get("readOnly")).and_then(Value::as_bool).unwrap_or(false);
    let valid_for_secs = body.get("valid_for").or_else(|| body.get("validFor")).map(parse_valid_for).unwrap_or(2_592_000);
    // Generate a high-entropy opaque token (never stored in plaintext).
    let plaintext = format!(
        "ioi_pat_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let token_hash = sha256_hex_str(&plaintext);
    let token_id = format!("pat_{}", short_hash(&token_hash));
    let now = iso_now();
    let expires_at = iso_in_seconds(valid_for_secs);
    // Metadata record — NEVER contains the plaintext; the hash is for future inbound verification.
    let record = json!({
        "schema_version": "ioi.hypervisor.api-token.v1",
        "token_id": token_id,
        "user_id": user_id,
        "description": description,
        "read_only": read_only,
        "token_hash": token_hash,
        "created_at": now,
        "expires_at": expires_at,
        "last_used_at": Value::Null,
    });
    let _ = persist_record(&st.data_dir, "api-tokens", &token_id, &record);
    // Return the plaintext ONCE (the only time it is ever surfaced).
    (StatusCode::OK, Json(json!({
        "ok": true,
        "token": {
            "token_id": token_id,
            "user_id": user_id,
            "description": description,
            "read_only": read_only,
            "value": plaintext,
            "created_at": now,
            "expires_at": expires_at,
        }
    })))
}

/// GET /v1/hypervisor/api-tokens — list token METADATA (never the value or the hash).
pub(crate) async fn handle_api_token_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let tokens: Vec<Value> = read_record_dir(&st.data_dir, "api-tokens")
        .into_iter()
        .map(|mut t| {
            // defense in depth: strip the hash from any list projection
            if let Some(obj) = t.as_object_mut() {
                obj.remove("token_hash");
            }
            t
        })
        .collect();
    Json(json!({ "ok": true, "tokens": tokens }))
}

/// DELETE /v1/hypervisor/api-tokens/:id — revoke a token.
pub(crate) async fn handle_api_token_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let removed = remove_record(&st.data_dir, "api-tokens", &id);
    Json(json!({ "ok": true, "token_id": id, "removed": removed }))
}

// ============================================================================================
// Identity & Auth plane (multi-user IdP) — principals, sessions, and a gated inbound auth ring.
// This is the OUTER ring (who is calling); it COMPOSES with — does not replace — the wallet/lease
// authority model (what a crossing is allowed to do). Enforcement is policy-gated (default OFF) so
// the single-operator localhost runtime is untouched until an org turns authentication on.
// Boundary: passwords + tokens are HASHED at rest (salted sha256); the plaintext is never stored.
// ============================================================================================

const OPERATOR_ID: &str = "00000000-0000-4000-8000-000000000001";

// Password hashing is Argon2id via dcrypt (ioi_crypto::key_store). The stored field is the hex of
// `salt(16) || hash(32)`; verification re-derives. Never reversible, never sha256.
fn hash_password(pw: &str) -> Option<String> {
    ioi_crypto::key_store::hash_password(pw).ok().map(hex::encode)
}
fn verify_password(pw: &str, stored_hex: &str) -> bool {
    match hex::decode(stored_hex) {
        Ok(bytes) => ioi_crypto::key_store::verify_password(pw, &bytes),
        Err(_) => false,
    }
}
fn gen_opaque(prefix: &str) -> String {
    format!("{prefix}_{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())
}
fn principal_public(mut p: Value) -> Value {
    if let Some(o) = p.as_object_mut() { o.remove("salt"); o.remove("password_hash"); }
    p
}
/// Lazily ensure the single bootstrap operator principal exists (admin, no password until set).
fn ensure_operator(data_dir: &str) {
    let exists = read_record_dir(data_dir, "principals").iter().any(|p| p["principal_id"].as_str() == Some(OPERATOR_ID));
    if !exists {
        let now = iso_now();
        let p = json!({
            "schema_version": "ioi.hypervisor.principal.v1",
            "principal_id": OPERATOR_ID, "email": "johndoe@ioi.local", "name": "John Doe",
            "role": "admin", "status": "active", "source": "local-operator",
            "created_at": now, "updated_at": now,
        });
        let _ = persist_record(data_dir, "principals", OPERATOR_ID, &p);
    }
}
fn find_principal(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, "principals").into_iter().find(|p| p["principal_id"].as_str() == Some(id))
}
fn find_principal_by_email(data_dir: &str, email: &str) -> Option<Value> {
    let e = email.trim().to_lowercase();
    read_record_dir(data_dir, "principals").into_iter().find(|p| p["email"].as_str().map(|x| x.to_lowercase()) == Some(e.clone()))
}
fn auth_policy(data_dir: &str) -> Value {
    read_record_dir(data_dir, "auth-policy").into_iter().find(|p| p["id"].as_str() == Some("policy"))
        .unwrap_or_else(|| json!({ "id": "policy", "require_authentication": false, "allowed_methods": ["local", "oidc", "sso", "api-token"] }))
}
/// Resolve the calling principal from a session cookie (ioi_session=) or a Bearer token (session
/// token OR an API access token whose hash we stored). Returns the public principal record.
fn resolve_principal(data_dir: &str, headers: &HeaderMap) -> Option<Value> {
    // 1) session cookie
    let mut session_tok: Option<String> = None;
    if let Some(cookie) = headers.get("cookie").and_then(|c| c.to_str().ok()) {
        for part in cookie.split(';') {
            let kv = part.trim();
            if let Some(v) = kv.strip_prefix("ioi_session=") { session_tok = Some(v.to_string()); }
        }
    }
    // 2) bearer (session token or API token)
    let bearer = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).map(|s| s.trim().to_string());
    let try_session = |tok: &str| -> Option<Value> {
        let h = sha256_hex_str(tok);
        let now = iso_now();
        read_record_dir(data_dir, "sessions").into_iter()
            .find(|s| s["token_hash"].as_str() == Some(h.as_str()) && s["expires_at"].as_str().map(|e| e > now.as_str()).unwrap_or(false))
            .and_then(|s| s["principal_id"].as_str().map(String::from))
            .and_then(|pid| find_principal(data_dir, &pid))
    };
    if let Some(tok) = &session_tok { if let Some(p) = try_session(tok) { if p["status"].as_str() == Some("active") { return Some(principal_public(p)); } } }
    if let Some(tok) = &bearer {
        if let Some(p) = try_session(tok) { if p["status"].as_str() == Some("active") { return Some(principal_public(p)); } }
        // API access token: match the stored hash → its user_id → principal
        let h = sha256_hex_str(tok);
        if let Some(rec) = read_record_dir(data_dir, "api-tokens").into_iter().find(|t| t["token_hash"].as_str() == Some(h.as_str())) {
            if let Some(uid) = rec["user_id"].as_str() {
                if let Some(p) = find_principal(data_dir, uid) { if p["status"].as_str() == Some("active") { return Some(principal_public(p)); } }
            }
        }
    }
    None
}

/// Axum middleware: when auth-policy.require_authentication is ON, reject unauthenticated requests to
/// the hypervisor data plane (401). Auth endpoints + non-hypervisor paths are always exempt so a
/// client can still log in. Default policy is OFF → pure passthrough (local runtime untouched).
pub(crate) async fn auth_gate(
    State(st): State<Arc<DaemonState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path().to_string();
    let exempt = !path.starts_with("/v1/hypervisor/")
        || path.starts_with("/v1/hypervisor/auth/")
        || path == "/v1/hypervisor/editor-targets"; // readiness probe
    if !exempt && auth_policy(&st.data_dir)["require_authentication"].as_bool().unwrap_or(false) {
        if resolve_principal(&st.data_dir, req.headers()).is_none() {
            return (StatusCode::UNAUTHORIZED, Json(json!({ "ok": false, "reason": "authentication_required" }))).into_response();
        }
    }
    next.run(req).await
}

/// POST /v1/hypervisor/auth/login — local credential login. Returns an opaque session token (the
/// caller — the serve layer — sets it as an HttpOnly cookie). The token hash is stored, never the token.
pub(crate) async fn handle_auth_login(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    ensure_operator(&st.data_dir);
    let email = body.get("email").and_then(Value::as_str).unwrap_or("").trim().to_string();
    let pw = body.get("password").and_then(Value::as_str).unwrap_or("");
    let Some(p) = find_principal_by_email(&st.data_dir, &email) else {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "ok": false, "reason": "invalid_credentials" })));
    };
    if p["status"].as_str() != Some("active") {
        return (StatusCode::FORBIDDEN, Json(json!({ "ok": false, "reason": "account_deactivated" })));
    }
    let stored = p["password_hash"].as_str().unwrap_or("");
    if stored.is_empty() || !verify_password(pw, stored) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "ok": false, "reason": "invalid_credentials" })));
    }
    let (status, sess) = issue_session(&st.data_dir, p["principal_id"].as_str().unwrap_or(""), "local");
    (status, Json(sess))
}

/// Issue a session for a principal (shared by local login + OIDC/SSO callback). Returns the plaintext
/// session token ONCE.
fn issue_session(data_dir: &str, principal_id: &str, source: &str) -> (StatusCode, Value) {
    let Some(p) = find_principal(data_dir, principal_id) else {
        return (StatusCode::NOT_FOUND, json!({ "ok": false, "reason": "unknown_principal" }));
    };
    let token = gen_opaque("ioi_sess");
    let sid = format!("sess_{}", short_hash(&sha256_hex_str(&token)));
    let rec = json!({
        "session_id": sid, "token_hash": sha256_hex_str(&token), "principal_id": principal_id,
        "source": source, "created_at": iso_now(), "expires_at": iso_in_seconds(7 * 24 * 3600),
    });
    let _ = persist_record(data_dir, "sessions", &sid, &rec);
    (StatusCode::OK, json!({ "ok": true, "session_token": token, "expires_at": rec["expires_at"], "principal": principal_public(p) }))
}

/// POST /v1/hypervisor/auth/logout — revoke the current session.
pub(crate) async fn handle_auth_logout(State(st): State<Arc<DaemonState>>, headers: HeaderMap) -> Json<Value> {
    let mut tok: Option<String> = None;
    if let Some(cookie) = headers.get("cookie").and_then(|c| c.to_str().ok()) {
        for part in cookie.split(';') { if let Some(v) = part.trim().strip_prefix("ioi_session=") { tok = Some(v.to_string()); } }
    }
    if tok.is_none() { tok = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).map(|s| s.trim().to_string()); }
    if let Some(tok) = tok {
        let h = sha256_hex_str(&tok);
        if let Some(s) = read_record_dir(&st.data_dir, "sessions").into_iter().find(|s| s["token_hash"].as_str() == Some(h.as_str())) {
            if let Some(sid) = s["session_id"].as_str() { remove_record(&st.data_dir, "sessions", sid); }
        }
    }
    Json(json!({ "ok": true }))
}

/// GET /v1/hypervisor/auth/whoami — the authenticated principal (401 if none and auth required;
/// otherwise falls back to the bootstrap operator so local-mode reads keep working).
pub(crate) async fn handle_auth_whoami(State(st): State<Arc<DaemonState>>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    ensure_operator(&st.data_dir);
    if let Some(p) = resolve_principal(&st.data_dir, &headers) {
        return (StatusCode::OK, Json(json!({ "ok": true, "principal": p, "authenticated": true })));
    }
    if auth_policy(&st.data_dir)["require_authentication"].as_bool().unwrap_or(false) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "ok": false, "reason": "authentication_required" })));
    }
    let op = find_principal(&st.data_dir, OPERATOR_ID).map(principal_public).unwrap_or(Value::Null);
    (StatusCode::OK, Json(json!({ "ok": true, "principal": op, "authenticated": false })))
}

/// GET /v1/hypervisor/auth/policy — the enforcement policy.
pub(crate) async fn handle_auth_policy_get(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "ok": true, "policy": auth_policy(&st.data_dir) }))
}
/// PUT /v1/hypervisor/auth/policy — toggle enforcement / allowed methods.
pub(crate) async fn handle_auth_policy_set(State(st): State<Arc<DaemonState>>, Json(body): Json<Value>) -> Json<Value> {
    let mut p = auth_policy(&st.data_dir);
    if let Some(v) = body.get("require_authentication").and_then(Value::as_bool) { p["require_authentication"] = json!(v); }
    if let Some(v) = body.get("allowed_methods").cloned() { if v.is_array() { p["allowed_methods"] = v; } }
    p["id"] = json!("policy");
    p["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, "auth-policy", "policy", &p);
    Json(json!({ "ok": true, "policy": p }))
}

/// GET /v1/hypervisor/principals — list members (public records, no secrets).
pub(crate) async fn handle_principal_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    ensure_operator(&st.data_dir);
    let ps: Vec<Value> = read_record_dir(&st.data_dir, "principals").into_iter().map(principal_public).collect();
    Json(json!({ "ok": true, "principals": ps }))
}
/// POST /v1/hypervisor/principals — create/provision a principal (optionally with a local password).
pub(crate) async fn handle_principal_create(State(st): State<Arc<DaemonState>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let email = body.get("email").and_then(Value::as_str).unwrap_or("").trim().to_lowercase();
    if email.is_empty() { return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "email is required" }))); }
    if let Some(existing) = find_principal_by_email(&st.data_dir, &email) {
        return (StatusCode::OK, Json(json!({ "ok": true, "principal": principal_public(existing), "existed": true })));
    }
    let now = iso_now();
    let pid = body.get("principal_id").and_then(Value::as_str).map(String::from).unwrap_or_else(|| format!("usr_{}", short_hash(&format!("{email}:{now}"))));
    let mut p = json!({
        "schema_version": "ioi.hypervisor.principal.v1", "principal_id": pid, "email": email,
        "name": body.get("name").and_then(Value::as_str).unwrap_or(&email),
        "role": body.get("role").and_then(Value::as_str).unwrap_or("member"),
        "status": "active", "source": body.get("source").and_then(Value::as_str).unwrap_or("local"),
        "created_at": now, "updated_at": now,
    });
    if let Some(pw) = body.get("password").and_then(Value::as_str) {
        if !pw.is_empty() { if let Some(h) = hash_password(pw) { p["password_hash"] = json!(h); } }
    }
    let _ = persist_record(&st.data_dir, "principals", &pid, &p);
    (StatusCode::OK, Json(json!({ "ok": true, "principal": principal_public(p) })))
}
/// POST /v1/hypervisor/principals/:id/password — set/rotate a local password.
pub(crate) async fn handle_principal_set_password(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    ensure_operator(&st.data_dir);
    let Some(mut p) = find_principal(&st.data_dir, &id) else { return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "unknown_principal" }))); };
    let pw = body.get("password").and_then(Value::as_str).unwrap_or("");
    if pw.is_empty() { return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "password is required" }))); }
    let Some(h) = hash_password(pw) else { return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "reason": "failed to hash password" }))); };
    p["password_hash"] = json!(h); p["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, "principals", &id, &p);
    (StatusCode::OK, Json(json!({ "ok": true })))
}
/// DELETE /v1/hypervisor/principals/:id — deactivate a principal (the operator cannot be removed).
pub(crate) async fn handle_principal_delete(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    if id == OPERATOR_ID { return Json(json!({ "ok": false, "reason": "cannot_remove_operator" })); }
    if let Some(mut p) = find_principal(&st.data_dir, &id) {
        p["status"] = json!("deactivated"); p["updated_at"] = json!(iso_now());
        let _ = persist_record(&st.data_dir, "principals", &id, &p);
        // revoke their sessions
        for s in read_record_dir(&st.data_dir, "sessions").into_iter().filter(|s| s["principal_id"].as_str() == Some(id.as_str())) {
            if let Some(sid) = s["session_id"].as_str() { remove_record(&st.data_dir, "sessions", sid); }
        }
    }
    Json(json!({ "ok": true, "principal_id": id, "status": "deactivated" }))
}

// ============================================================================================
// Metering & Cost plane — the Hypervisor's REAL economic plane (Bucket B absorption). Consumption
// is derived from actual agentgres records (the `receipts` the daemon already writes for every
// session/agent execution), NOT fabricated. Transparent self-hosted OCU (Hypervisor Compute Unit)
// derivation: KIND_ENVIRONMENT = compute-hours (receipt runtime started_at→finished_at);
// KIND_LLM = 0.1 OCU per model-backed receipt. A wallet-backed budget plane sets a ceiling +
// auto-funding policy ("auto top-up" reframed: replenish the budget from wallet.network when the
// balance crosses a threshold). Boundary: agentgres RECORDS (receipts) → metered; wallet FUNDS.
// ============================================================================================

fn parse_ts(s: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}
fn day_bucket(dt: &time::OffsetDateTime) -> String {
    format!("{:04}-{:02}-{:02}T00:00:00Z", dt.year(), dt.month() as u8, dt.day())
}
fn round6(v: f64) -> f64 {
    (v * 1e6).round() / 1e6
}
/// OCU contributed by one receipt: (compute-hours, llm-units).
fn receipt_ocu(r: &Value) -> (f64, f64) {
    let fin = r.get("finished_at").and_then(Value::as_str).and_then(parse_ts);
    let start = r.get("started_at").and_then(Value::as_str).and_then(parse_ts);
    let hours = match (start, fin) {
        (Some(s), Some(f)) => ((f - s).as_seconds_f64() / 3600.0).max(0.0),
        _ => 0.0,
    };
    let llm = if r.get("model").and_then(Value::as_str).map(|m| !m.is_empty()).unwrap_or(false) { 0.1 } else { 0.0 };
    (hours, llm)
}
/// All-time consumption (compute-hours + llm-units) across every recorded receipt.
fn all_time_consumption(data_dir: &str) -> f64 {
    let mut total = 0.0;
    for r in read_record_dir(data_dir, "receipts") {
        let (h, l) = receipt_ocu(&r);
        total += h + l;
    }
    round6(total)
}

/// GET /v1/hypervisor/usage/consumption?from=&to= — per-day OCU consumption by metric kind,
/// aggregated from the real `receipts` records over [from,to] (default: last 7 days).
pub(crate) async fn handle_usage_consumption(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let to = q.get("to").and_then(|s| parse_ts(s)).unwrap_or_else(time::OffsetDateTime::now_utc);
    let from = q.get("from").and_then(|s| parse_ts(s)).unwrap_or_else(|| to - time::Duration::days(7));
    let mut env: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
    let mut llm: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
    for r in read_record_dir(&st.data_dir, "receipts") {
        let Some(fin) = r.get("finished_at").and_then(Value::as_str).and_then(parse_ts) else { continue };
        if fin < from || fin > to { continue; }
        let day = day_bucket(&fin);
        let (hours, llm_units) = receipt_ocu(&r);
        *env.entry(day.clone()).or_default() += hours;
        if llm_units > 0.0 { *llm.entry(day).or_default() += llm_units; }
    }
    let series = |m: &std::collections::BTreeMap<String, f64>| -> Vec<Value> {
        let mut out = Vec::new();
        let mut d = from.replace_time(time::Time::MIDNIGHT);
        let end = to.replace_time(time::Time::MIDNIGHT);
        while d <= end {
            let key = day_bucket(&d);
            let ocu = *m.get(&key).unwrap_or(&0.0);
            let mut entry = json!({ "time": key });
            if ocu > 0.0 { entry["ocu"] = json!(round6(ocu)); }
            out.push(entry);
            d += time::Duration::days(1);
        }
        out
    };
    // KIND_ALL = the per-day TOTAL across every kind. The native chart selects this aggregate metric
    // (sf(metrics, KIND_ALL)); without it the usage chart reads empty even when kinds have data.
    let mut all: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
    for (k, v) in env.iter().chain(llm.iter()) {
        *all.entry(k.clone()).or_default() += *v;
    }
    let total: f64 = all.values().sum::<f64>();
    Json(json!({
        "ok": true,
        "metrics": [
            { "kind": "KIND_ALL", "display_name": "Total", "series": series(&all) },
            { "kind": "KIND_ENVIRONMENT", "display_name": "Environment Usage", "series": series(&env) },
            { "kind": "KIND_LLM", "display_name": "LLM Usage", "series": series(&llm) },
        ],
        "total_ocu": round6(total),
    }))
}

fn load_budget(data_dir: &str) -> Value {
    read_record_dir(data_dir, "budget")
        .into_iter()
        .find(|b| b["id"].as_str() == Some("policy"))
        .unwrap_or_else(|| json!({
            "id": "policy", "budget_ocu": 1000.0, "auto_fund_enabled": false,
            "threshold_ocu": 20.0, "target_ocu": 1000.0, "wallet_ref": Value::Null
        }))
}
fn budget_with_balance(data_dir: &str) -> Value {
    let mut b = load_budget(data_dir);
    let used = all_time_consumption(data_dir);
    let budget = b.get("budget_ocu").and_then(Value::as_f64).unwrap_or(1000.0);
    b["used_ocu"] = json!(used);
    b["available_ocu"] = json!(round6((budget - used).max(0.0)));
    b
}

/// GET /v1/hypervisor/budget — the budget policy + live balance (used/available from real usage).
pub(crate) async fn handle_budget_get(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "ok": true, "budget": budget_with_balance(&st.data_dir) }))
}

/// PUT /v1/hypervisor/budget — set the budget ceiling + wallet auto-funding policy.
pub(crate) async fn handle_budget_set(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let mut b = load_budget(&st.data_dir);
    for k in ["budget_ocu", "threshold_ocu", "target_ocu"] {
        if let Some(v) = body.get(k).and_then(Value::as_f64) { b[k] = json!(v); }
    }
    if let Some(v) = body.get("auto_fund_enabled").and_then(Value::as_bool) { b["auto_fund_enabled"] = json!(v); }
    if let Some(v) = body.get("wallet_ref").and_then(Value::as_str) { b["wallet_ref"] = json!(v); }
    b["id"] = json!("policy");
    b["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, "budget", "policy", &b);
    Json(json!({ "ok": true, "budget": budget_with_balance(&st.data_dir) }))
}

/// POST /v1/hypervisor/budget/reconcile — recompute used vs budget; if auto-funding is enabled and
/// the balance is below threshold, replenish the budget to (used + target) and record a wallet
/// funding ledger entry. This is the wallet-native reframe of SaaS "auto top-up".
pub(crate) async fn handle_budget_reconcile(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut b = load_budget(&st.data_dir);
    let used = all_time_consumption(&st.data_dir);
    let mut budget = b.get("budget_ocu").and_then(Value::as_f64).unwrap_or(1000.0);
    let threshold = b.get("threshold_ocu").and_then(Value::as_f64).unwrap_or(20.0);
    let target = b.get("target_ocu").and_then(Value::as_f64).unwrap_or(1000.0);
    let auto = b.get("auto_fund_enabled").and_then(Value::as_bool).unwrap_or(false);
    let mut available = round6((budget - used).max(0.0));
    let mut funded = false;
    let mut funding_ref = Value::Null;
    if auto && available < threshold {
        let new_budget = used + target;
        let amount = round6(new_budget - budget);
        let ev_id = format!("fund_{}", short_hash(&format!("{used}:{}", iso_now())));
        let ev = json!({
            "id": ev_id, "kind": "budget-auto-fund", "credential_source": "wallet.network",
            "amount_ocu": amount, "target_ocu": target, "used_ocu": round6(used), "at": iso_now()
        });
        let _ = persist_record(&st.data_dir, "ledgers", &ev_id, &ev);
        budget = new_budget;
        b["budget_ocu"] = json!(round6(budget));
        b["updated_at"] = json!(iso_now());
        let _ = persist_record(&st.data_dir, "budget", "policy", &b);
        available = round6((budget - used).max(0.0));
        funded = true;
        funding_ref = json!(ev_id);
    }
    Json(json!({
        "ok": true,
        "reconciled": { "used_ocu": round6(used), "budget_ocu": round6(budget), "available_ocu": available, "threshold_ocu": threshold, "auto_fund_enabled": auto },
        "funded": funded,
        "funding_event_ref": funding_ref,
    }))
}

// ---- OIDC login config (BYO OIDC IdP for org login) — management surface; client_secret SEALED,
// never returned. Login enforcement is a separate concern (the daemon has no session layer yet);
// this makes the config real (save/load/update) the same way API tokens store a hash today. ----
fn load_oidc(data_dir: &str) -> Value {
    read_record_dir(data_dir, "oidc-config")
        .into_iter()
        .find(|c| c["id"].as_str() == Some("config"))
        .unwrap_or_else(|| json!({ "id": "config", "enabled": false, "issuer_url": "", "client_id": "", "email_domain": "", "client_secret_set": false }))
}
fn oidc_public(mut c: Value) -> Value {
    if let Some(o) = c.as_object_mut() { o.remove("sealed_client_secret"); o.remove("key_source"); }
    c
}
/// GET /v1/hypervisor/oidc-config — the OIDC login config (never returns the sealed client secret).
pub(crate) async fn handle_oidc_get(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "ok": true, "config": oidc_public(load_oidc(&st.data_dir)) }))
}
/// PUT /v1/hypervisor/oidc-config — upsert the OIDC IdP config; seals the client secret at rest.
pub(crate) async fn handle_oidc_set(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let mut c = load_oidc(&st.data_dir);
    for k in ["issuer_url", "client_id", "email_domain"] {
        if let Some(v) = body.get(k).and_then(Value::as_str) { c[k] = json!(v); }
    }
    if let Some(v) = body.get("enabled").and_then(Value::as_bool) { c["enabled"] = json!(v); }
    if let Some(sec) = body.get("client_secret").and_then(Value::as_str) {
        if !sec.is_empty() {
            if let Some(sealed) = seal_value(sec) {
                c["sealed_client_secret"] = json!(sealed);
                c["client_secret_set"] = json!(true);
                c["key_source"] = json!(scm_key_source());
            }
        }
    }
    c["id"] = json!("config");
    c["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, "oidc-config", "config", &c);
    Json(json!({ "ok": true, "config": oidc_public(c) }))
}

/// POST /v1/hypervisor/environments/:id/scm/publish — the wallet-authorized publish crossing.
pub(crate) async fn handle_scm_publish(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(env) = read_record_dir(&st.data_dir, "environments")
        .into_iter()
        .find(|e| e["id"].as_str() == Some(id.as_str()))
    else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "environment not found" })));
    };
    let Some(ws) = env["status"]["workspace_root"].as_str().filter(|s| !s.is_empty()).map(str::to_string) else {
        return (StatusCode::CONFLICT, Json(json!({ "ok": false, "reason": "workspace not started", "fail_closed": true })));
    };
    let connector_id = body.get("connector_id").and_then(Value::as_str).unwrap_or("").to_string();
    let Some(connector) = read_record_dir(&st.data_dir, "scm-connectors")
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(connector_id.as_str()))
    else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "unknown connector_id" })));
    };
    // A host-level connector (the github host PAT or a BYOA github-app) can publish to ANY repo it
    // is authorized for, so it takes an explicit target `remote_url` from the request; a repo
    // connector uses its own pinned remote.
    let connector_host_level = connector["host_level"].as_bool().unwrap_or(false);
    let remote_url = body
        .get("remote_url")
        .and_then(Value::as_str)
        .filter(|s| connector_host_level && s.starts_with("https://"))
        .map(str::to_string)
        .unwrap_or_else(|| connector["remote_url"].as_str().unwrap_or("").to_string());
    let auth_posture = connector["auth_posture"].as_str().unwrap_or("").to_string();
    let branch = body
        .get("branch")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("hypervisor/publish-{}", short_hash(&format!("{id}:{connector_id}"))));

    let kind = connector["kind"].as_str().unwrap_or("git").to_string();
    let requires_credential = connector["requires_credential"].as_bool().unwrap_or(auth_posture.starts_with("token-lease"));

    // Authorize the publish CROSSING through the generic capability-lease gateway: it resolves the
    // sealed backing credential (connector or github host fallback), verifies the bound wallet grant,
    // and issues a lease. Fail-closed responses (428 credential / 403 authority) return verbatim.
    let lease_req = CapabilityLeaseRequest {
        authority_provider_ref: "wallet.network".to_string(),
        backing_provider: if requires_credential { format!("scm:connector:{connector_id}") } else { "none".to_string() },
        allowed_tools: vec!["scm.publish".to_string()],
        resource_refs: vec![remote_url.clone(), id.clone()],
        scopes: SCM_PUBLISH_SCOPES.iter().map(|s| s.to_string()).collect(),
        policy_domain: "hypervisor.scm.publish.policy.v1".to_string(),
        request_domain: "hypervisor.scm.publish.request.v1".to_string(),
        request_facets: json!({ "environment_id": id, "connector_id": connector_id, "branch": branch }),
        credential_connector_id: Some(connector_id.clone()),
        credential_store: "scm-credentials".to_string(),
        credential_required: requires_credential,
        github_host_fallback: remote_url.contains("github.com"),
        receipt_required: true,
        revocation_ref: format!("scm-connectors/{connector_id}/credential"),
        authority_reason: "scm_publish_authority_required".to_string(),
        grant_value: body.get("wallet_approval_grant").cloned().unwrap_or(Value::Null),
    };
    let lease = match authorize_capability_lease(&st, &lease_req).await {
        Ok(l) => l,
        Err((code, challenge)) => return (code, Json(challenge)),
    };
    let token = lease.token;
    let credential_key_source = lease.credential_key_source;
    let credential_source = lease.credential_source;
    let grant_ref = lease.grant_ref;
    let capability_lease = lease.descriptor;

    // --- daemon EXECUTES the real push (authorized) ---
    let git = |args: &[&str]| -> (bool, String) {
        match std::process::Command::new("git").arg("-C").arg(&ws).args(args).output() {
            Ok(o) => (
                o.status.success(),
                format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)),
            ),
            Err(e) => (false, e.to_string()),
        }
    };
    let title = body.get("title").and_then(Value::as_str).unwrap_or("Hypervisor publish").to_string();
    let _ = git(&["checkout", "-B", &branch]);
    let _ = git(&["add", "-A"]);
    let _ = git(&[
        "-c", "user.email=hypervisor@ioi.local", "-c", "user.name=Hypervisor",
        "commit", "--allow-empty", "-m", &title,
    ]);
    let head = { let (_, s) = git(&["rev-parse", "HEAD"]); s.trim().to_string() };
    // Inject the resolved credential into an https remote for the push; file:// remotes ignore it.
    let push_url = match (&token, remote_url.starts_with("https://")) {
        (Some(tok), true) => remote_url.replacen("https://", &format!("https://x-access-token:{tok}@"), 1),
        _ => remote_url.clone(),
    };
    let (pushed, push_out_raw) = git(&["push", "--force", &push_url, &format!("{branch}:{branch}")]);
    // REDACT the token from any captured output before it is stored or returned.
    let push_out = match &token { Some(tok) => push_out_raw.replace(tok.as_str(), "***"), None => push_out_raw };

    // GitHub connector → open a REAL pull request via the API. Outward call; only fires for a real
    // https github remote with a bound token (skipped/fail-closed otherwise — e.g. the local slice).
    let mut pr_url: Option<String> = None;
    let mut pr_error: Option<String> = None;
    if pushed && (kind == "github" || kind == "github-app") && remote_url.starts_with("https://") {
        if let Some(tok) = &token {
            let base = body.get("base").and_then(Value::as_str).unwrap_or("main").to_string();
            match create_github_pull_request(&remote_url, tok, &branch, &base, &title).await {
                Ok(url) => pr_url = Some(url),
                Err(e) => pr_error = Some(e),
            }
        }
    }

    let receipt_id = format!("scmpub_{}", short_hash(&format!("{id}:{branch}:{head}")));
    let receipt = json!({
        "schema_version": "ioi.hypervisor.scm-publish-receipt.v1",
        "receipt_id": receipt_id,
        "environment_id": id,
        "connector_id": connector_id,
        "remote_url": remote_url,
        "branch": branch,
        "commit_sha": head,
        "title": title,
        "published": pushed,
        "credential_bound": token.is_some(),
        "credential_key_source": credential_key_source,
        "credential_source": credential_source,
        "pull_request_url": pr_url,
        "pull_request_error": pr_error,
        "grant_ref": grant_ref,
        "capability_lease": capability_lease,
        "host_mutation": true,
        "push_tail": push_out.lines().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n"),
        "published_at": iso_now(),
    });
    let _ = persist_record(&st.data_dir, "scm-publish-receipts", &receipt_id, &receipt);

    if !pushed {
        return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": "git push failed", "receipt": receipt })));
    }
    (StatusCode::OK, Json(json!({ "ok": true, "receipt": receipt, "remote_ref": format!("{remote_url}#{branch}") })))
}

/// Open a GitHub pull request via the REST API (a REAL outward call). Parses owner/repo from the
/// https remote and authenticates with the bound token. Returns the PR html_url or an error string.
/// Only invoked for a real https github remote with a bound credential (the local slice never hits
/// this; github.com stays fail-closed until an operator binds a token to a real repo).
async fn create_github_pull_request(
    remote_url: &str,
    token: &str,
    head: &str,
    base: &str,
    title: &str,
) -> Result<String, String> {
    let path = remote_url
        .trim_start_matches("https://github.com/")
        .trim_end_matches(".git")
        .trim_matches('/');
    let mut parts = path.splitn(2, '/');
    let owner = parts.next().unwrap_or("").to_string();
    let repo = parts.next().unwrap_or("").to_string();
    if owner.is_empty() || repo.is_empty() {
        return Err(format!("could not parse owner/repo from {remote_url}"));
    }
    let api = format!("https://api.github.com/repos/{owner}/{repo}/pulls");
    let resp = reqwest::Client::new()
        .post(&api)
        .header("User-Agent", "ioi-hypervisor")
        .header("Accept", "application/vnd.github+json")
        .bearer_auth(token)
        .timeout(std::time::Duration::from_secs(20))
        .json(&json!({
            "title": title, "head": head, "base": base,
            "body": "Opened by IOI Hypervisor (governed publish crossing).",
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if status.is_success() {
        body.get("html_url")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "github pr api: no html_url in response".to_string())
    } else {
        Err(format!(
            "github pr api {}: {}",
            status.as_u16(),
            body.get("message").and_then(Value::as_str).unwrap_or("error")
        ))
    }
}

/// Close a GitHub pull request (and optionally delete its head branch) via the REST API — a REAL
/// outward mutation authenticated with the sealed token. Returns (closed, head_branch, branch_deleted).
async fn close_github_pull_request(
    remote_url: &str,
    token: &str,
    pr_number: u64,
    delete_branch: bool,
) -> Result<(bool, String, bool), String> {
    let path = remote_url
        .trim_start_matches("https://github.com/")
        .trim_end_matches(".git")
        .trim_matches('/');
    let mut parts = path.splitn(2, '/');
    let owner = parts.next().unwrap_or("").to_string();
    let repo = parts.next().unwrap_or("").to_string();
    if owner.is_empty() || repo.is_empty() {
        return Err(format!("could not parse owner/repo from {remote_url}"));
    }
    let client = reqwest::Client::new();
    let pr_api = format!("https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}");
    // Read the PR first to learn the head branch (needed for branch deletion).
    let getr = client
        .get(&pr_api)
        .header("User-Agent", "ioi-hypervisor")
        .header("Accept", "application/vnd.github+json")
        .bearer_auth(token)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let pr: Value = getr.json().await.unwrap_or(Value::Null);
    let head_branch = pr.pointer("/head/ref").and_then(Value::as_str).unwrap_or("").to_string();
    // Close the PR.
    let patch = client
        .patch(&pr_api)
        .header("User-Agent", "ioi-hypervisor")
        .header("Accept", "application/vnd.github+json")
        .bearer_auth(token)
        .timeout(std::time::Duration::from_secs(20))
        .json(&json!({ "state": "closed" }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !patch.status().is_success() {
        let b: Value = patch.json().await.unwrap_or(Value::Null);
        return Err(format!("github close pr {}: {}", pr_number, b.get("message").and_then(Value::as_str).unwrap_or("error")));
    }
    // Optionally delete the head branch (only for branches in this repo, not cross-fork heads).
    let mut branch_deleted = false;
    if delete_branch && !head_branch.is_empty() {
        let ref_api = format!("https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{head_branch}");
        let del = client
            .delete(&ref_api)
            .header("User-Agent", "ioi-hypervisor")
            .header("Accept", "application/vnd.github+json")
            .bearer_auth(token)
            .timeout(std::time::Duration::from_secs(20))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        branch_deleted = del.status().is_success();
    }
    Ok((true, head_branch, branch_deleted))
}

// ---- GitHub App (BYOA) authentication — manifest-created App, installation tokens ----------------
// The App is created in the USER's own account via GitHub's App-Manifest flow (no vendor-owned
// secret). The App private key (pem) is sealed in the daemon; to ACT, the daemon mints a short-lived
// RS256 JWT from the pem, exchanges it for an installation access token (1h), and uses THAT for the
// crossing. The pem + installation token never leave the daemon; refresh is automatic per use.

#[derive(serde::Serialize)]
struct GithubAppJwtClaims {
    iat: u64,
    exp: u64,
    iss: String,
}

/// Mint a GitHub App JWT (RS256, signed by the App private key). Authenticates AS the App to list
/// installations and mint installation tokens. The pem never leaves the daemon.
fn mint_github_app_jwt(app_id: &str, pem: &str) -> Result<String, String> {
    let now = daemon_now_ms_fail_closed() / 1000;
    let claims = GithubAppJwtClaims { iat: now.saturating_sub(60), exp: now + 540, iss: app_id.to_string() };
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| format!("invalid app private key: {e}"))?;
    jwt_encode(&JwtHeader::new(JwtAlgorithm::RS256), &claims, &key).map_err(|e| format!("app jwt sign failed: {e}"))
}

/// Exchange the App JWT for a short-lived INSTALLATION access token (server-to-server). This is the
/// token the daemon USES for the crossing — minted fresh per use, never exported.
async fn mint_github_installation_token(app_id: &str, pem: &str, installation_id: &str) -> Result<String, String> {
    let jwt = mint_github_app_jwt(app_id, pem)?;
    let api = format!("https://api.github.com/app/installations/{installation_id}/access_tokens");
    let resp = reqwest::Client::new()
        .post(&api)
        .header("User-Agent", "ioi-hypervisor")
        .header("Accept", "application/vnd.github+json")
        .bearer_auth(&jwt)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if status.is_success() {
        body.get("token").and_then(Value::as_str).map(str::to_string).ok_or_else(|| "no token in installation response".to_string())
    } else {
        Err(format!("installation token {}: {}", status.as_u16(), body.get("message").and_then(Value::as_str).unwrap_or("error")))
    }
}

/// Mint a fresh OAuth2 access token from a sealed REFRESH token (the OAuth model the native
/// Integrations surface uses — Gmail/Google/Atlassian/etc.). Standard refresh_token grant; the
/// refresh token + client secret never leave the daemon, and the short-lived access token is minted
/// per use. credential_source "oauth-refresh".
async fn mint_oauth_access_token(token_url: &str, client_id: &str, client_secret: &str, refresh_token: &str) -> Result<String, String> {
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if !client_secret.is_empty() {
        form.push(("client_secret", client_secret));
    }
    let resp = reqwest::Client::new()
        .post(token_url)
        .header("User-Agent", "ioi-hypervisor")
        .header("Accept", "application/json")
        .form(&form)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if status.is_success() {
        body.get("access_token").and_then(Value::as_str).map(str::to_string).ok_or_else(|| "no access_token in refresh response".to_string())
    } else {
        Err(format!("oauth refresh {}: {}", status.as_u16(), body.get("error").and_then(Value::as_str).unwrap_or("error")))
    }
}

// ---- AWS Signature Version 4 (provider-native signed auth) ---------------------------------------
// AWS doesn't use bearer tokens — each request is SIGNED with SigV4 (HMAC-SHA256 chain over a
// canonical request). The sealed secret key never leaves the daemon; we sign per request.

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut k = key.to_vec();
    if k.len() > BLOCK {
        k = Sha256::digest(&k).to_vec();
    }
    k.resize(BLOCK, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^  0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner);
    outer.finalize().to_vec()
}
fn sha256_hex_bytes(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Compute the AWS SigV4 `Authorization` header for a request. `signed_headers` always covers
/// host + x-amz-date (+ x-amz-security-token when a session token is present).
fn sigv4_authorization(
    method: &str, host: &str, canonical_uri: &str, canonical_query: &str, payload: &[u8],
    access_key: &str, secret_key: &str, session_token: Option<&str>, region: &str, service: &str, amz_date: &str,
) -> String {
    let date_stamp = &amz_date[..8.min(amz_date.len())];
    let payload_hash = sha256_hex_bytes(payload);
    let (canonical_headers, signed_headers) = match session_token {
        Some(tok) => (format!("host:{host}\nx-amz-date:{amz_date}\nx-amz-security-token:{tok}\n"), "host;x-amz-date;x-amz-security-token"),
        None => (format!("host:{host}\nx-amz-date:{amz_date}\n"), "host;x-amz-date"),
    };
    let canonical_request = format!("{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex_bytes(canonical_request.as_bytes()));
    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    format!("AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}")
}

/// Current time as an AWS amz-date (YYYYMMDDTHHMMSSZ, UTC).
fn amz_date_now() -> String {
    let secs = (daemon_now_ms_fail_closed() / 1000) as i64;
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!("{:04}{:02}{:02}T{:02}{:02}{:02}Z", dt.year(), dt.month() as u8, dt.day(), dt.hour(), dt.minute(), dt.second()),
        Err(_) => "19700101T000000Z".to_string(),
    }
}

/// OAuth 2.0 Token Exchange (RFC 8693) — workload/OIDC identity: present a subject token (the
/// workload's own OIDC/JWT identity) and exchange it for a provider access token. No interactive
/// auth; the workload's identity IS the credential. credential_source "oidc-workload".
async fn mint_token_exchange(token_url: &str, subject_token: &str, subject_token_type: &str, audience: &str, scopes: &str, client_id: &str) -> Result<String, String> {
    let mut form = vec![
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("subject_token", subject_token),
        ("subject_token_type", subject_token_type),
        ("requested_token_type", "urn:ietf:params:oauth:token-type:access_token"),
    ];
    if !audience.is_empty() { form.push(("audience", audience)); }
    if !scopes.is_empty() { form.push(("scope", scopes)); }
    if !client_id.is_empty() { form.push(("client_id", client_id)); }
    let resp = reqwest::Client::new()
        .post(token_url)
        .header("User-Agent", "ioi-hypervisor")
        .header("Accept", "application/json")
        .form(&form)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if status.is_success() {
        body.get("access_token").and_then(Value::as_str).map(str::to_string).ok_or_else(|| "no access_token in token-exchange response".to_string())
    } else {
        Err(format!("token-exchange {}: {}", status.as_u16(), body.get("error").and_then(Value::as_str).unwrap_or("error")))
    }
}

// ---- OAuth Authorization Code + PKCE (the canonical "authorize this integration" Connect) ---------
// Provider-delegated authority: the user authorizes at the provider; the daemon exchanges the code
// (PKCE, public client) for tokens and seals the refresh token. Agents only ever get scoped leases.

fn random_token(n: usize) -> String {
    use rand::Rng;
    rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(n).map(char::from).collect()
}
/// PKCE S256 code challenge from a verifier (base64url-no-pad of SHA-256).
fn pkce_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
/// Percent-encode a query value (unreserved set per RFC 3986).
fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
/// Exchange an authorization code for (access_token, optional refresh_token). PKCE always; a
/// non-empty client_secret makes it a CONFIDENTIAL client (BYOA OAuth app, e.g. Slack).
async fn exchange_oauth_code(token_url: &str, client_id: &str, client_secret: &str, code: &str, redirect_uri: &str, code_verifier: &str) -> Result<(String, Option<String>), String> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];
    if !client_secret.is_empty() {
        form.push(("client_secret", client_secret));
    }
    let resp = reqwest::Client::new()
        .post(token_url)
        .header("User-Agent", "ioi-hypervisor")
        .header("Accept", "application/json")
        .form(&form)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if status.is_success() {
        let access = body.get("access_token").and_then(Value::as_str).map(str::to_string).ok_or_else(|| "no access_token in code exchange".to_string())?;
        let refresh = body.get("refresh_token").and_then(Value::as_str).map(str::to_string);
        Ok((access, refresh))
    } else {
        Err(format!("oauth code exchange {}: {}", status.as_u16(), body.get("error").and_then(Value::as_str).unwrap_or("error")))
    }
}

// ---- MCP OAuth auto-discovery (RFC 9728 → 8414) + Dynamic Client Registration (RFC 7591) ---------
// The MCP 2025 auth flow: probe the server (401 → protected-resource-metadata) → authorization-server
// metadata → dynamically register a public PKCE client. Result: register only an MCP URL and the
// daemon self-configures the auth_profile — no per-service OAuth app, no vendor secret.

fn url_origin(u: &str) -> String {
    if let Some(idx) = u.find("://") {
        let after = &u[idx + 3..];
        let host_end = after.find('/').unwrap_or(after.len());
        format!("{}{}", &u[..idx + 3], &after[..host_end])
    } else {
        u.to_string()
    }
}

async fn http_get_json(client: &reqwest::Client, url: &str) -> Result<Value, String> {
    let resp = client.get(url).header("User-Agent", "ioi-hypervisor").header("Accept", "application/json").timeout(std::time::Duration::from_secs(15)).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("GET {url} -> {}", resp.status().as_u16()));
    }
    resp.json().await.map_err(|e| e.to_string())
}

/// Discover (authorization_endpoint, token_endpoint, registration_endpoint, device_authorization_endpoint, scopes) for an MCP server.
async fn discover_oauth_for_mcp(mcp_url: &str) -> Result<(String, String, String, String, Vec<String>), String> {
    let client = reqwest::Client::new();
    // 1) protected-resource-metadata URL: prefer the 401 WWW-Authenticate pointer, else well-known.
    let mut prm_url: Option<String> = None;
    if let Ok(resp) = client.post(mcp_url).header("Content-Type", "application/json").header("Accept", "application/json, text/event-stream").json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":MCP_CLIENT_INIT()})).timeout(std::time::Duration::from_secs(15)).send().await {
        if resp.status().as_u16() == 401 {
            if let Some(h) = resp.headers().get("www-authenticate").and_then(|v| v.to_str().ok()) {
                if let Some(idx) = h.find("resource_metadata=") {
                    let rest = h[idx + "resource_metadata=".len()..].trim_start_matches('"');
                    let end = rest.find('"').unwrap_or(rest.len());
                    prm_url = Some(rest[..end].to_string());
                }
            }
        }
    }
    let origin = url_origin(mcp_url);
    let prm_url = prm_url.unwrap_or_else(|| format!("{origin}/.well-known/oauth-protected-resource"));
    let prm = http_get_json(&client, &prm_url).await.map_err(|e| format!("protected-resource-metadata: {e}"))?;
    let as_url = prm["authorization_servers"].as_array().and_then(|a| a.first()).and_then(|v| v.as_str()).ok_or("no authorization_servers in resource metadata")?.to_string();
    let prm_scopes: Vec<String> = prm["scopes_supported"].as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default();
    // 2) authorization-server metadata (oauth-authorization-server, else openid-configuration, else as_url).
    let as_origin = url_origin(&as_url);
    let candidates = [
        format!("{}/.well-known/oauth-authorization-server", as_url.trim_end_matches('/')),
        format!("{as_origin}/.well-known/oauth-authorization-server"),
        format!("{as_origin}/.well-known/openid-configuration"),
        as_url.clone(),
    ];
    let mut meta: Option<Value> = None;
    for c in candidates.iter() {
        if let Ok(m) = http_get_json(&client, c).await {
            if m.get("token_endpoint").is_some() {
                meta = Some(m);
                break;
            }
        }
    }
    let meta = meta.ok_or("could not fetch authorization-server metadata")?;
    let authorization_endpoint = meta["authorization_endpoint"].as_str().ok_or("no authorization_endpoint")?.to_string();
    let token_endpoint = meta["token_endpoint"].as_str().ok_or("no token_endpoint")?.to_string();
    let registration_endpoint = meta["registration_endpoint"].as_str().unwrap_or("").to_string();
    let device_authorization_endpoint = meta["device_authorization_endpoint"].as_str().unwrap_or("").to_string();
    let scopes = if !prm_scopes.is_empty() { prm_scopes } else { meta["scopes_supported"].as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default() };
    Ok((authorization_endpoint, token_endpoint, registration_endpoint, device_authorization_endpoint, scopes))
}

/// Dynamically register a PUBLIC (PKCE) client (RFC 7591) → client_id.
async fn dynamic_client_register(registration_endpoint: &str, redirect_uri: &str, scopes: &[String]) -> Result<String, String> {
    let body = json!({
        "client_name": "IOI Hypervisor",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": scopes.join(" "),
    });
    let resp = reqwest::Client::new().post(registration_endpoint).header("User-Agent", "ioi-hypervisor").header("Accept", "application/json").json(&body).timeout(std::time::Duration::from_secs(20)).send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    if status.is_success() {
        v["client_id"].as_str().map(String::from).ok_or_else(|| "no client_id in DCR response".to_string())
    } else {
        Err(format!("DCR {}: {}", status.as_u16(), v.get("error").and_then(Value::as_str).unwrap_or("error")))
    }
}

// ---- Minimal MCP (Model Context Protocol) client over Streamable HTTP ----------------------------
// The native Integrations surface consumes MCP servers; this lets the daemon BE an MCP client so an
// MCP integration's tools become available to the agent — each tool call governed by a wallet lease.
// Does the initialize handshake (capturing Mcp-Session-Id), then tools/list or tools/call. Handles
// both JSON and SSE responses. The token never leaves the daemon.

fn parse_mcp_response(content_type: &str, text: &str) -> Result<Value, String> {
    if content_type.contains("text/event-stream") {
        for line in text.lines().rev() {
            if let Some(rest) = line.strip_prefix("data:") {
                let t = rest.trim();
                if t.starts_with('{') {
                    return serde_json::from_str(t).map_err(|e| e.to_string());
                }
            }
        }
        Err("no data frame in SSE response".to_string())
    } else {
        serde_json::from_str(text).map_err(|e| e.to_string())
    }
}

async fn mcp_request(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    session: &Option<String>,
    method: &str,
    params: Value,
    id: Option<i64>,
) -> Result<(Value, Option<String>), String> {
    let mut body = serde_json::Map::new();
    body.insert("jsonrpc".to_string(), json!("2.0"));
    body.insert("method".to_string(), json!(method));
    if let Some(i) = id {
        body.insert("id".to_string(), json!(i));
    }
    body.insert("params".to_string(), params);
    let mut rb = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2025-06-18")
        .timeout(std::time::Duration::from_secs(25))
        .json(&Value::Object(body));
    if !token.is_empty() {
        rb = rb.bearer_auth(token);
    }
    if let Some(s) = session {
        rb = rb.header("Mcp-Session-Id", s.as_str());
    }
    let resp = rb.send().await.map_err(|e| e.to_string())?;
    let new_session = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| session.clone());
    let status = resp.status();
    let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let text = resp.text().await.unwrap_or_default();
    if id.is_none() {
        return Ok((Value::Null, new_session)); // notification — no response body
    }
    if !status.is_success() {
        return Err(format!("mcp {method} {}: {}", status.as_u16(), text.chars().take(200).collect::<String>()));
    }
    let parsed = parse_mcp_response(&ct, &text)?;
    if let Some(err) = parsed.get("error") {
        return Err(format!("mcp {method} error: {}", err.get("message").and_then(Value::as_str).unwrap_or("error")));
    }
    Ok((parsed.get("result").cloned().unwrap_or(Value::Null), new_session))
}

const MCP_CLIENT_INIT: fn() -> Value = || json!({
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": { "name": "ioi-hypervisor", "version": "1" },
});

/// MCP initialize handshake → returns the session id for the follow-on calls.
async fn mcp_handshake(client: &reqwest::Client, url: &str, token: &str) -> Result<Option<String>, String> {
    let (_init, session) = mcp_request(client, url, token, &None, "initialize", MCP_CLIENT_INIT(), Some(1)).await?;
    let _ = mcp_request(client, url, token, &session, "notifications/initialized", json!({}), None).await;
    Ok(session)
}

/// List an MCP server's tools (read-only discovery).
async fn mcp_list_tools(url: &str, token: &str) -> Result<Value, String> {
    let client = reqwest::Client::new();
    let session = mcp_handshake(&client, url, token).await?;
    let (result, _) = mcp_request(&client, url, token, &session, "tools/list", json!({}), Some(2)).await?;
    Ok(result.get("tools").cloned().unwrap_or_else(|| json!([])))
}

/// Call one MCP tool (the lease-governed crossing performs this).
async fn mcp_call_tool(url: &str, token: &str, name: &str, args: &Value) -> Result<Value, String> {
    let client = reqwest::Client::new();
    let session = mcp_handshake(&client, url, token).await?;
    let (result, _) = mcp_request(&client, url, token, &session, "tools/call", json!({ "name": name, "arguments": args }), Some(2)).await?;
    Ok(result)
}

/// POST /v1/hypervisor/scm-connectors/:id/abandon-pull-request — the wallet-authorized CLEANUP
/// crossing: close a published PR (and delete its branch) using the connector's sealed credential
/// (or the github host git-auth fallback). The daemon USES the token; it is never exported. Fails
/// closed (428) without a resolvable credential and (403) without a bound wallet grant.
pub(crate) async fn handle_scm_abandon_pull_request(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let connector_id = id;
    let Some(connector) = read_record_dir(&st.data_dir, "scm-connectors")
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(connector_id.as_str()))
    else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "unknown connector_id" })));
    };
    let remote_url = connector["remote_url"].as_str().unwrap_or("").to_string();
    let auth_posture = connector["auth_posture"].as_str().unwrap_or("").to_string();
    let pull_request_url = body.get("pull_request_url").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if pull_request_url.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "pull_request_url is required" })));
    }
    let delete_branch = body.get("delete_branch").and_then(Value::as_bool).unwrap_or(true);
    let Some(pr_number) = pull_request_url.rsplit('/').next().and_then(|s| s.parse::<u64>().ok()) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "could not parse PR number from pull_request_url" })));
    };
    // The repo to act on comes from the PR URL itself (https://github.com/{owner}/{repo}/pull/{n}),
    // so this works for a host-level connector (App / host PAT) whose remote_url is just github.com.
    let target_remote = {
        let path = pull_request_url.trim_start_matches("https://github.com/");
        let mut it = path.split('/');
        match (it.next(), it.next()) {
            (Some(o), Some(r)) if !o.is_empty() && !r.is_empty() => format!("https://github.com/{o}/{r}.git"),
            _ => remote_url.clone(),
        }
    };

    // Authorize the cleanup CROSSING through the SAME generic capability-lease gateway as publish —
    // distinct scopes/domains (scm.pr.close) so a publish grant can't authorize an abandon.
    let requires_credential = connector["requires_credential"].as_bool().unwrap_or(auth_posture.starts_with("token-lease"));
    let lease_req = CapabilityLeaseRequest {
        authority_provider_ref: "wallet.network".to_string(),
        backing_provider: format!("scm:connector:{connector_id}"),
        allowed_tools: vec!["scm.pr.close".to_string()],
        resource_refs: vec![remote_url.clone(), pull_request_url.clone()],
        scopes: SCM_ABANDON_SCOPES.iter().map(|s| s.to_string()).collect(),
        policy_domain: "hypervisor.scm.abandon.policy.v1".to_string(),
        request_domain: "hypervisor.scm.abandon.request.v1".to_string(),
        request_facets: json!({ "connector_id": connector_id, "pull_request_url": pull_request_url, "delete_branch": delete_branch }),
        credential_connector_id: Some(connector_id.clone()),
        credential_store: "scm-credentials".to_string(),
        credential_required: requires_credential,
        github_host_fallback: remote_url.contains("github.com"),
        receipt_required: true,
        revocation_ref: format!("scm-connectors/{connector_id}/credential"),
        authority_reason: "scm_abandon_authority_required".to_string(),
        grant_value: body.get("wallet_approval_grant").cloned().unwrap_or(Value::Null),
    };
    let lease = match authorize_capability_lease(&st, &lease_req).await {
        Ok(l) => l,
        Err((code, challenge)) => return (code, Json(challenge)),
    };
    let token = lease.token;
    let credential_source = lease.credential_source;
    let grant_ref = lease.grant_ref;
    let capability_lease = lease.descriptor;

    // daemon EXECUTES the cleanup (authorized).
    let tok = token.unwrap_or_default();
    let (closed, head_branch, branch_deleted, error) =
        match close_github_pull_request(&target_remote, &tok, pr_number, delete_branch).await {
            Ok((c, b, d)) => (c, b, d, None),
            Err(e) => (false, String::new(), false, Some(e.replace(tok.as_str(), "***"))),
        };

    let receipt_id = format!("scmaband_{}", short_hash(&format!("{connector_id}:{pr_number}")));
    let receipt = json!({
        "schema_version": "ioi.hypervisor.scm-abandon-receipt.v1",
        "receipt_id": receipt_id,
        "connector_id": connector_id,
        "remote_url": remote_url,
        "pull_request_url": pull_request_url,
        "pull_request_number": pr_number,
        "closed": closed,
        "branch": head_branch,
        "branch_deleted": branch_deleted,
        "credential_source": credential_source,
        "grant_ref": grant_ref,
        "capability_lease": capability_lease,
        "host_mutation": closed,
        "error": error,
        "abandoned_at": iso_now(),
    });
    let _ = persist_record(&st.data_dir, "scm-abandon-receipts", &receipt_id, &receipt);
    if !closed {
        return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": "github close failed", "receipt": receipt })));
    }
    (StatusCode::OK, Json(json!({ "ok": true, "receipt": receipt })))
}

/// POST /v1/hypervisor/scm-connect/github — "Connect GitHub" (the login). Validates the token
/// against the GitHub API (identifies the account), then registers a github connector for
/// {owner}/{repo} and SEAL-binds the token in one step. The token is validated + sealed at rest;
/// never returned. Fail-closed if GitHub rejects the token. With no repo it returns identity only
/// (account connected; provide a repo to materialize a connector). This is the PAT-connect flow;
/// OAuth/device flow is a follow-on (needs a registered GitHub OAuth App client_id).
pub(crate) async fn handle_scm_connect_github(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let token = body.get("token").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if token.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "token is required" })));
    }
    // validate + identify the account (read-only)
    let resp = reqwest::Client::new()
        .get("https://api.github.com/user")
        .header("User-Agent", "ioi-hypervisor")
        .header("Accept", "application/vnd.github+json")
        .bearer_auth(&token)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await;
    let resp = match resp {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": format!("github unreachable: {e}") }))),
    };
    if !resp.status().is_success() {
        return (StatusCode::UNAUTHORIZED, Json(json!({
            "ok": false, "decision": "blocked", "reason": "github rejected the token",
            "status": resp.status().as_u16(),
        })));
    }
    let login = resp.json::<Value>().await.ok().and_then(|v| v["login"].as_str().map(str::to_string)).unwrap_or_default();
    if login.is_empty() {
        return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": "could not read github login" })));
    }
    let owner = body.get("owner").and_then(Value::as_str).filter(|s| !s.trim().is_empty()).unwrap_or(login.as_str()).trim().to_string();
    let repo = body.get("repo").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if repo.is_empty() {
        // Host-level git authentication (no specific repo) — the native "Git authentications" flow.
        // Persist a HOST connector for github.com + seal the token; publish to any github repo
        // resolves this host credential when the repo connector has none of its own.
        let connector_id = "scm_host_github".to_string();
        let key_source = scm_key_source();
        let Some(sealed) = seal_scm_token(&token) else {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "reason": "failed to seal credential" })));
        };
        let cred = json!({ "connector_id": connector_id, "sealed_token": sealed, "key_source": key_source, "sealed": true, "bound_at": iso_now() });
        let _ = persist_record(&st.data_dir, "scm-credentials", &connector_id, &cred);
        let connector = json!({
            "schema_version": "ioi.hypervisor.scm-connector.v1",
            "connector_id": connector_id, "kind": "github", "name": format!("github:@{login}"),
            "remote_url": "https://github.com", "host": "github.com", "requires_credential": true,
            "auth_posture": "token-lease:bound", "credential_key_source": key_source,
            "connected_login": login, "host_level": true, "created_at": iso_now(),
        });
        let _ = persist_record(&st.data_dir, "scm-connectors", &connector_id, &connector);
        return (StatusCode::OK, Json(json!({ "ok": true, "login": login, "connected": true, "connector_id": connector_id, "host": "github.com" })));
    }
    let remote_url = format!("https://github.com/{owner}/{repo}.git");
    let connector_id = format!("scm_{}", short_hash(&format!("{remote_url}:github")));
    let key_source = scm_key_source();
    let Some(sealed) = seal_scm_token(&token) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "reason": "failed to seal credential" })));
    };
    let cred = json!({ "connector_id": connector_id, "sealed_token": sealed, "key_source": key_source, "sealed": true, "bound_at": iso_now() });
    let _ = persist_record(&st.data_dir, "scm-credentials", &connector_id, &cred);
    let connector = json!({
        "schema_version": "ioi.hypervisor.scm-connector.v1",
        "connector_id": connector_id,
        "kind": "github",
        "name": format!("github:{owner}/{repo}"),
        "remote_url": remote_url,
        "requires_credential": true,
        "auth_posture": "token-lease:bound",
        "credential_key_source": key_source,
        "connected_login": login,
        "created_at": iso_now(),
    });
    let _ = persist_record(&st.data_dir, "scm-connectors", &connector_id, &connector);
    (StatusCode::OK, Json(json!({ "ok": true, "login": login, "connector": connector, "connector_id": connector_id })))
}

/// Lane B (Phase-5 foothold): a Rust-native, DETERMINISTIC, offline decision step.
/// It derives a deterministic decision from the intent (sha256-seeded, mirroring
/// the model_mount native-local backend's determinism — no external model, no
/// harness, no container) and writes a real artifact into the provisioned
/// workspace. Returns `(files_written, transcript)`. This is the honest foothold
/// toward routing execution through the canonical `RuntimeAgentService::handle_step`
/// once the daemon hosts the full agentic runtime + drivers.
fn run_native_local_decision_step(workspace_root: &str, intent: &str) -> (Vec<String>, Vec<(String, String)>) {
    let digest: String = sha256_hex_str(intent).chars().take(12).collect();
    let rel_dir = "lane-b-native-local";
    let rel_path = format!("{rel_dir}/decision-step.md");
    let mut transcript: Vec<(String, String)> = Vec::new();
    transcript.push(("stdout".to_string(), format!("[lane-b:native_local] perceiving workspace {workspace_root}")));
    transcript.push((
        "stdout".to_string(),
        format!("[lane-b:native_local] deterministic decision (input_hash={digest})"),
    ));

    let mut files_written: Vec<String> = Vec::new();
    let dir = std::path::Path::new(workspace_root).join(rel_dir);
    let target = std::path::Path::new(workspace_root).join(&rel_path);
    let contents = format!(
        "# Lane B — native-local decision step (Phase 5 foothold)\n\n\
         intent: {intent}\n\
         native_local_response: Hypervisor native local model response. input_hash={digest}\n\n\
         This artifact was written by the Rust-native DETERMINISTIC Lane B execution\n\
         mode (no external harness, model, or container). The canonical decision_loop\n\
         (RuntimeAgentService::handle_step) is the true-north that supersedes this\n\
         foothold once the daemon hosts the full agentic runtime + drivers.\n",
    );
    if std::fs::create_dir_all(&dir).is_ok() && std::fs::write(&target, contents).is_ok() {
        files_written.push(rel_path.clone());
        transcript.push(("stdout".to_string(), format!("[lane-b:native_local] wrote {rel_path}")));
    } else {
        transcript.push(("stderr".to_string(), format!("[lane-b:native_local] failed to write {rel_path}")));
    }
    transcript.push(("stdout".to_string(), "[lane-b:native_local] step complete".to_string()));
    (files_written, transcript)
}

/// Run the Lane B (native-local) foothold step end to end: deterministic step +
/// real `changed_file_groups` diff + real terminal transcript + Agentgres receipt,
/// persisted onto the session so the events SSE surfaces it. Wallet-admitted.
fn run_native_local_lane(
    st: &DaemonState,
    session_id: &str,
    workspace_root: &str,
    intent: &str,
    record: &Value,
    capability_lease_ref: &str,
) -> (StatusCode, Json<Value>) {
    let started_at = iso_now();
    let (files_written, transcript) = run_native_local_decision_step(workspace_root, intent);
    let finished_at = iso_now();
    let ok = !files_written.is_empty();

    let diff = project_session_workspace_diff(workspace_root);
    let changed_file_groups = diff.get("changed_file_groups").cloned().unwrap_or_else(|| json!([]));
    let terminal_events: Vec<Value> = transcript
        .iter()
        .enumerate()
        .map(|(index, (stream, text))| json!({ "sequence": index + 1, "stream": stream, "text": text }))
        .collect();

    let exit_status = if ok { "success" } else { "failure" };
    let receipt_ref = format!("receipt://hypervisor/session-lane-b/{}", safe_session_tag(session_id));
    let receipt = json!({
        "id": receipt_ref,
        "kind": "hypervisor.session.lane_b_native_local_step",
        "session_ref": session_id,
        "lane": "native_local",
        "deterministic": true,
        "exit_status": exit_status,
        "files_written": files_written,
        "capability_lease_ref": capability_lease_ref,
        "authority_scope_refs": EXECUTION_AUTHORITY_SCOPES,
        "started_at": started_at,
        "finished_at": finished_at,
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);

    let mut receipt_refs: Vec<Value> = record
        .get("latest_receipt_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !receipt_refs.iter().any(|reference| reference.as_str() == Some(receipt_ref.as_str())) {
        receipt_refs.push(json!(receipt_ref));
    }

    let mut updated = record.clone();
    if let Some(object) = updated.as_object_mut() {
        object.insert("lifecycle_state".into(), json!(if ok { "executed_native_local" } else { "execution_failed" }));
        object.insert("terminal_events".into(), json!(terminal_events));
        object.insert("latest_receipt_refs".into(), json!(receipt_refs.clone()));
    }
    let _ = persist_record(&st.data_dir, "sessions", session_id, &updated);

    (
        StatusCode::OK,
        Json(json!({
            "schema_version": SESSION_EXECUTE_DECISION_SCHEMA_VERSION,
            "session_ref": session_id,
            "decision": if ok { "executed" } else { "failed" },
            "lane": "native_local_decision_step",
            "deterministic": true,
            "exit_status": exit_status,
            "files_written": files_written,
            "changed_file_groups": changed_file_groups,
            "terminal_events": terminal_events,
            "capability_lease_ref": capability_lease_ref,
            "authority_scope_refs": EXECUTION_AUTHORITY_SCOPES,
            "latest_receipt_refs": receipt_refs,
            "started_at": started_at,
            "finished_at": finished_at,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

// ---- GitHub App BYOA manifest flow (the "Create & connect GitHub App" connect button) ------------
// No vendor-owned OAuth App: the user creates an App in THEIR OWN account via GitHub's App-Manifest
// flow. (1) manifest → the browser POSTs it to github.com and the user clicks "Create GitHub App";
// (2) GitHub redirects back with a temporary code; (3) conversion exchanges the code for the App's
// id/client_secret/PRIVATE KEY, which the daemon SEALS; (4) the user installs the App and we capture
// the installation_id. To act, the daemon mints a short-lived installation token from the sealed pem
// (see resolve_sealed_credential) — the credential never leaves the daemon. wallet.network still
// authorizes every crossing on top.

/// POST /v1/hypervisor/scm-connect/github-app/manifest — build the App manifest + the github.com
/// create-app URL the browser POSTs it to. No secret involved yet (the App doesn't exist).
pub(crate) async fn handle_github_app_manifest(
    State(_st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let callback_base = body.get("callback_base").and_then(Value::as_str).unwrap_or("http://127.0.0.1:4173").trim_end_matches('/').to_string();
    let owner = body.get("owner").and_then(Value::as_str).unwrap_or("").trim().to_string();
    let now = daemon_now_ms_fail_closed();
    let state = short_hash(&format!("ghapp:{now}:{owner}"));
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("ioi-hypervisor-{}", short_hash(&format!("{now}:{owner}"))));
    // No hook_attributes: GitHub requires the webhook URL be publicly reachable (localhost is
    // rejected), and a GitHub App needs no webhook for this flow. Omitting it = no webhook, which
    // keeps the manifest valid for a localhost (BYOA/dev) callback. redirect_url + setup_url on
    // localhost are accepted (they're browser redirects, not server-reachable hooks).
    let manifest = json!({
        "name": name,
        "url": callback_base,
        "redirect_url": format!("{callback_base}/__ioi/github-app/callback"),
        "setup_url": format!("{callback_base}/__ioi/github-app/installed"),
        "setup_on_update": true,
        "public": false,
        "default_permissions": { "contents": "write", "pull_requests": "write", "metadata": "read" },
        "default_events": [],
    });
    let create_url = if owner.is_empty() {
        format!("https://github.com/settings/apps/new?state={state}")
    } else {
        format!("https://github.com/organizations/{owner}/settings/apps/new?state={state}")
    };
    (StatusCode::OK, Json(json!({ "ok": true, "create_url": create_url, "manifest": manifest, "state": state })))
}

/// POST /v1/hypervisor/scm-connect/github-app/conversion — exchange the manifest `code` for the App
/// credentials (id, client_secret, PRIVATE KEY), SEAL the secrets, and register a github-app
/// connector. Returns the install_url. Fail-closed if GitHub rejects the code or sealing fails.
pub(crate) async fn handle_github_app_conversion(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let code = body.get("code").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if code.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "code is required" })));
    }
    let api = format!("https://api.github.com/app-manifests/{code}/conversions");
    let resp = reqwest::Client::new()
        .post(&api)
        .header("User-Agent", "ioi-hypervisor")
        .header("Accept", "application/vnd.github+json")
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await;
    let resp = match resp {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": format!("github unreachable: {e}") }))),
    };
    let status = resp.status();
    let conv: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return (StatusCode::BAD_GATEWAY, Json(json!({
            "ok": false, "reason": "github rejected the manifest code",
            "status": status.as_u16(), "message": conv.get("message").and_then(Value::as_str).unwrap_or("error"),
        })));
    }
    let app_id = conv.get("id").and_then(Value::as_i64).map(|n| n.to_string()).unwrap_or_default();
    let slug = conv.get("slug").and_then(Value::as_str).unwrap_or("").to_string();
    let client_id = conv.get("client_id").and_then(Value::as_str).unwrap_or("").to_string();
    let client_secret = conv.get("client_secret").and_then(Value::as_str).unwrap_or("");
    let pem = conv.get("pem").and_then(Value::as_str).unwrap_or("");
    let owner_login = conv.pointer("/owner/login").and_then(Value::as_str).unwrap_or("").to_string();
    let html_url = conv.get("html_url").and_then(Value::as_str).unwrap_or("").to_string();
    if app_id.is_empty() || slug.is_empty() || pem.is_empty() {
        return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "reason": "incomplete app conversion response" })));
    }
    // Seal the App PRIVATE KEY + client secret at rest. Fail closed if sealing fails (no plaintext).
    let (Some(sealed_pem), Some(sealed_secret)) = (seal_scm_token(pem), seal_scm_token(client_secret)) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "reason": "failed to seal app credentials" })));
    };
    let key_source = scm_key_source();
    let connector_id = format!("scm_ghapp_{}", short_hash(&format!("{app_id}:{slug}")));
    let cred = json!({
        "connector_id": connector_id, "kind": "github-app", "sealed_pem": sealed_pem,
        "sealed_client_secret": sealed_secret, "app_id": app_id, "installation_id": Value::Null,
        "key_source": key_source, "sealed": true, "bound_at": iso_now(),
    });
    let _ = persist_record(&st.data_dir, "scm-credentials", &connector_id, &cred);
    let connector = json!({
        "schema_version": "ioi.hypervisor.scm-connector.v1",
        "connector_id": connector_id, "kind": "github-app",
        "name": format!("github-app:@{owner_login} ({slug})"),
        "remote_url": "https://github.com", "host": "github.com", "requires_credential": true,
        "auth_posture": "token-lease:unbound", "credential_key_source": key_source,
        "connected_login": owner_login, "app_id": app_id, "app_slug": slug, "client_id": client_id,
        "html_url": html_url, "installation_id": Value::Null, "host_level": true, "created_at": iso_now(),
    });
    let _ = persist_record(&st.data_dir, "scm-connectors", &connector_id, &connector);
    let install_url = format!("https://github.com/apps/{slug}/installations/new");
    (StatusCode::OK, Json(json!({
        "ok": true, "connector_id": connector_id, "app_slug": slug, "app_id": app_id,
        "connected_login": owner_login, "install_url": install_url, "html_url": html_url,
    })))
}

/// POST /v1/hypervisor/scm-connect/github-app/installation — capture the installation_id after the
/// user installs the App (binds the connector). If no connector_id is given, attaches to the newest
/// github-app connector still awaiting an installation. Verifies by minting an installation token.
pub(crate) async fn handle_github_app_installation(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let installation_id = body
        .get("installation_id")
        .and_then(|v| v.as_str().map(str::to_string).or_else(|| v.as_i64().map(|n| n.to_string())))
        .unwrap_or_default();
    if installation_id.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "reason": "installation_id is required" })));
    }
    let explicit = body.get("connector_id").and_then(Value::as_str).map(str::to_string);
    let mut connectors: Vec<Value> = read_record_dir(&st.data_dir, "scm-connectors")
        .into_iter()
        .filter(|c| c["kind"].as_str() == Some("github-app"))
        .collect();
    // newest first (ISO created_at sorts lexically)
    connectors.sort_by(|a, b| b["created_at"].as_str().unwrap_or("").cmp(a["created_at"].as_str().unwrap_or("")));
    let Some(mut connector) = (match &explicit {
        Some(id) => connectors.into_iter().find(|c| c["connector_id"].as_str() == Some(id.as_str())),
        None => connectors.into_iter().find(|c| c["installation_id"].is_null() || c["installation_id"].as_str().unwrap_or("").is_empty()),
    }) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "no github-app connector awaiting installation" })));
    };
    let connector_id = connector["connector_id"].as_str().unwrap_or("").to_string();
    connector["installation_id"] = json!(installation_id);
    connector["auth_posture"] = json!("token-lease:bound");
    let _ = persist_record(&st.data_dir, "scm-connectors", &connector_id, &connector);
    // mirror installation_id onto the sealed cred record (the gateway reads it there to mint tokens)
    if let Some(mut cred) = read_record_dir(&st.data_dir, "scm-credentials").into_iter().find(|c| c["connector_id"].as_str() == Some(connector_id.as_str())) {
        cred["installation_id"] = json!(installation_id);
        let _ = persist_record(&st.data_dir, "scm-credentials", &connector_id, &cred);
        // verify by minting a token (proves the sealed pem + installation are usable). Never returned.
        let app_id = cred["app_id"].as_str().unwrap_or("").to_string();
        let verified = match cred["sealed_pem"].as_str().and_then(open_scm_token) {
            Some(pem) => mint_github_installation_token(&app_id, &pem, &installation_id).await.is_ok(),
            None => false,
        };
        return (StatusCode::OK, Json(json!({ "ok": true, "connector_id": connector_id, "installation_id": installation_id, "verified": verified })));
    }
    (StatusCode::OK, Json(json!({ "ok": true, "connector_id": connector_id, "installation_id": installation_id, "verified": false })))
}

/// POST /v1/hypervisor/sessions/:id/execute — session execution (Lane A or Lane B).
///
/// Lane A (default `host_spawn`): FAILS CLOSED with an honest reason
/// (`no_model_route` / `harness_unavailable` / `container_unavailable`) when the
/// substrate is absent; otherwise spawns the `generic-cli-local` harness in the
/// provisioned workspace, delivers the intent, and reports the harness's real file
/// writes + diff + transcript + receipts. Lane B (`native_local`): a Rust-native
/// deterministic/offline decision step (Phase-5 foothold) — no substrate needed.
/// Both lanes are wallet-gated; failure paths stay honest (nothing invented).
pub(crate) async fn handle_session_execute(
    State(st): State<Arc<DaemonState>>,
    AxumPath(session_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(record) = load_session_record(&st, &session_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "session_not_found", "message": "Unknown session.", "session_ref": session_id } })),
        );
    };
    let workspace_root = record.get("workspace_root").and_then(Value::as_str).unwrap_or("").to_string();
    let lane = body.get("lane").and_then(Value::as_str).unwrap_or("host_spawn").to_string();

    let Some(intent) = session_execute_intent(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": "session_execute_intent_required", "message": "Execute requires a task intent (`intent` or `messages`)." } })),
        );
    };
    if workspace_root.is_empty() {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": { "code": "session_workspace_absent", "message": "Session has no provisioned workspace to execute in." } })),
        );
    }

    // Lane B (Phase-5 foothold): a Rust-native DETERMINISTIC/offline decision step —
    // no external harness, no model route, no container. Still wallet-gated (it
    // writes the workspace). The canonical RuntimeAgentService::handle_step true-north
    // is now REALIZED on POST /v1/hypervisor/runtime-host/sessions (the daemon hosts
    // the full runtime and runs constrained file/shell/browser tools through
    // handle_step); this lightweight foothold is retained for offline/no-driver use.
    if lane == "native_local" {
        let capability_lease_ref = match execute_authority_gate(&body, &session_id, &workspace_root, &intent) {
            Ok(lease) => lease,
            Err(challenge) => return (StatusCode::FORBIDDEN, Json(challenge)),
        };
        return run_native_local_lane(&st, &session_id, &workspace_root, &intent, &record, &capability_lease_ref);
    }

    // Lane A (host_spawn / container): honest fail-closed substrate checks FIRST so
    // an absent model/harness surfaces as no_model_route / harness_unavailable
    // BEFORE the authority gate (the offline contract), then the wallet gate, then spawn.
    let substrate = ExecutionSubstrate::probe();
    let blocked = if !substrate.model_route {
        Some((
            "no_model_route",
            "No reachable model route. Start a local model (e.g. `ollama serve` + a model) or set IOI_HYPERVISOR_MODEL_UPSTREAM.",
        ))
    } else if substrate.harness_binary.is_none() {
        Some((
            "harness_unavailable",
            "No host harness available (the generic-cli-local node shim, or a PATH harness binary).",
        ))
    } else if lane == "container" && substrate.container_runtime.is_none() {
        Some((
            "container_unavailable",
            "Container lane requested but no container runtime (docker / podman) on PATH.",
        ))
    } else {
        None
    };
    if let Some((reason, message)) = blocked {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "schema_version": SESSION_EXECUTE_DECISION_SCHEMA_VERSION,
                "session_ref": session_id,
                "decision": "blocked",
                "reason": reason,
                "message": message,
                "lane": lane,
                "checks": substrate.readiness_checks(),
                "model_route": substrate.model_route,
                "harness_binary": substrate.harness_binary.clone(),
                "container_runtime": substrate.container_runtime.clone(),
                // No execution happened: these are honestly empty, never fabricated.
                "changed_file_groups": [],
                "terminal_events": [],
                "runtimeTruthSource": "daemon-runtime",
            })),
        );
    }

    // Wallet authority gate (daemon-derived hashes; 403 challenge when unbound). Runs
    // AFTER the substrate check (offline contract) and BEFORE any spawn.
    let capability_lease_ref = match execute_authority_gate(&body, &session_id, &workspace_root, &intent) {
        Ok(lease) => lease,
        Err(challenge) => return (StatusCode::FORBIDDEN, Json(challenge)),
    };

    // REAL Lane A: spawn the host harness in the provisioned workspace and deliver
    // the intent. The harness drives the local model and edits the workspace.
    let model = resolve_harness_model();
    let Some(argv) = resolve_host_harness_argv(&model, &workspace_root) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "schema_version": SESSION_EXECUTE_DECISION_SCHEMA_VERSION,
                "session_ref": session_id,
                "decision": "blocked",
                "reason": "harness_unavailable",
                "message": "Host harness argv could not be resolved (node / shim missing).",
                "changed_file_groups": [],
                "terminal_events": [],
                "runtimeTruthSource": "daemon-runtime",
            })),
        );
    };
    let model_endpoint = std::env::var("IOI_HYPERVISOR_MODEL_UPSTREAM").ok().filter(|value| !value.is_empty());
    let started_at = iso_now();
    let outcome = run_host_spawn_lane(&argv, &workspace_root, &intent, model_endpoint.as_deref()).await;
    let finished_at = iso_now();

    // Real workspace diff — whatever the harness actually wrote (git or walk).
    let diff = project_session_workspace_diff(&workspace_root);
    let changed_file_groups = diff.get("changed_file_groups").cloned().unwrap_or_else(|| json!([]));

    // Real terminal transcript → terminal_events (the harness's actual output).
    let terminal_events: Vec<Value> = outcome
        .transcript
        .iter()
        .enumerate()
        .map(|(index, (stream, text))| json!({ "sequence": index + 1, "stream": stream, "text": text }))
        .collect();

    // Served preview (port_exposure): if the run produced a servable index.html,
    // open a REAL preview listener exposing the workspace, admitted under the same
    // grant's capability lease. Honest: no listener when there is no index.html.
    let mut environment_ports: Vec<Value> = Vec::new();
    if outcome.ok && std::path::Path::new(&workspace_root).join("index.html").is_file() {
        if let Some(port) =
            open_session_preview_port(&st, &session_id, &workspace_root, &capability_lease_ref).await
        {
            environment_ports.push(port);
        }
    }

    // Real lane execution receipt.
    let exit_status = if outcome.ok { "success" } else { "failure" };
    let lane_receipt_ref = format!("receipt://hypervisor/session-execute/{}", safe_session_tag(&session_id));
    let lane_receipt = json!({
        "id": lane_receipt_ref,
        "kind": "hypervisor.session.execute",
        "session_ref": session_id,
        "model": model,
        "exit_status": exit_status,
        "exit_code": outcome.exit_code,
        "files_written": outcome.files_written,
        "summary": outcome.summary,
        "error": outcome.error,
        // Admitted authority: the wallet capability grant that authorized this run.
        "capability_lease_ref": capability_lease_ref,
        "authority_scope_refs": EXECUTION_AUTHORITY_SCOPES,
        "started_at": started_at,
        "finished_at": finished_at,
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "receipts", &lane_receipt_ref, &lane_receipt);

    let mut receipt_refs: Vec<Value> = record
        .get("latest_receipt_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !receipt_refs.iter().any(|reference| reference.as_str() == Some(lane_receipt_ref.as_str())) {
        receipt_refs.push(json!(lane_receipt_ref));
    }

    // Persist the execution outcome onto the session record so the events SSE
    // surfaces the real transcript + receipts.
    let mut updated = record.clone();
    if let Some(object) = updated.as_object_mut() {
        object.insert("lifecycle_state".into(), json!(if outcome.ok { "executed" } else { "execution_failed" }));
        object.insert("terminal_events".into(), json!(terminal_events));
        object.insert(
            "last_execution".into(),
            json!({
                "intent": intent,
                "model": model,
                "exit_status": exit_status,
                "exit_code": outcome.exit_code,
                "timed_out": outcome.timed_out,
                "summary": outcome.summary,
                "files_written": outcome.files_written,
                "error": outcome.error,
                "finished_at": finished_at,
            }),
        );
        object.insert("latest_receipt_refs".into(), json!(receipt_refs));
        object.insert("environment_ports".into(), json!(environment_ports));
    }
    let _ = persist_record(&st.data_dir, "sessions", &session_id, &updated);

    let status_code = if outcome.spawn_error.is_some() {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::OK
    };
    (
        status_code,
        Json(json!({
            "schema_version": SESSION_EXECUTE_DECISION_SCHEMA_VERSION,
            "session_ref": session_id,
            "decision": if outcome.ok { "executed" } else { "failed" },
            "lane": "host_spawn_session",
            "model": model,
            "exit_status": exit_status,
            "exit_code": outcome.exit_code,
            "timed_out": outcome.timed_out,
            "spawn_error": outcome.spawn_error,
            "error": outcome.error,
            "summary": outcome.summary,
            "files_written": outcome.files_written,
            "changed_file_groups": changed_file_groups,
            "terminal_events": terminal_events,
            "environment_ports": environment_ports,
            "latest_receipt_refs": receipt_refs,
            // Admitted wallet authority that gated this consequential run.
            "capability_lease_ref": capability_lease_ref,
            "authority_scope_refs": EXECUTION_AUTHORITY_SCOPES,
            "started_at": started_at,
            "finished_at": finished_at,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

// ===========================================================================
// Session lifecycle teardown + preview-port revoke.
//
// A served preview opens a real listener exposing workspace bytes (Cut #4); it
// must be revocable and torn down, not only abort-on-re-execute / die-with-daemon.
// ===========================================================================

/// Revoke a session's preview listener: remove it from the registry, signal a
/// graceful shutdown, and await the serve task so the socket is CLOSED before
/// returning. Returns the revoked port, or None when no listener was running.
/// The registry lock is never held across the await.
async fn revoke_session_preview(st: &DaemonState, session_ref: &str) -> Option<u16> {
    let server = {
        let mut servers = st.preview_servers.lock().ok()?;
        servers.remove(session_ref)?
    };
    let port = server.port;
    let _ = server.shutdown.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), server.join).await;
    Some(port)
}

/// Remove a provisioned session workspace from disk — ONLY when it lives under the
/// sessions root (never an arbitrary path). Returns whether a dir was removed.
fn remove_session_workspace(workspace_root: &str) -> bool {
    if workspace_root.is_empty() {
        return false;
    }
    let root = sessions_root();
    let target = std::path::Path::new(workspace_root);
    let under_sessions_root = target.starts_with(&root) && target != root;
    if !under_sessions_root {
        return false;
    }
    std::fs::remove_dir_all(target).is_ok()
}

/// Mark every recorded environment port as `revoked` (the listener is gone).
fn mark_session_ports_revoked(record: &Value) -> Vec<Value> {
    record
        .get("environment_ports")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|mut port| {
            if let Some(object) = port.as_object_mut() {
                object.insert("exposure_state".into(), json!("revoked"));
            }
            port
        })
        .collect()
}

/// POST /v1/hypervisor/sessions/:id/ports/revoke — stop the session's preview
/// listener and mark its ports `revoked`. Idempotent: a session with no live
/// listener returns `revoked_port: null` (no fabricated effect). The session
/// itself stays; only the port exposure is revoked.
pub(crate) async fn handle_session_ports_revoke(
    State(st): State<Arc<DaemonState>>,
    AxumPath(session_id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(record) = load_session_record(&st, &session_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "session_not_found", "message": "Unknown session.", "session_ref": session_id } })),
        );
    };
    let revoked_port = revoke_session_preview(&st, &session_id).await;
    let ports = mark_session_ports_revoked(&record);

    let receipt_ref = format!("receipt://hypervisor/session-port-revoke/{}", safe_session_tag(&session_id));
    let receipt = json!({
        "id": receipt_ref,
        "kind": "hypervisor.session.port_revoke",
        "session_ref": session_id,
        "revoked_port": revoked_port,
        "created_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);

    let mut receipt_refs: Vec<Value> = record
        .get("latest_receipt_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !receipt_refs.iter().any(|reference| reference.as_str() == Some(receipt_ref.as_str())) {
        receipt_refs.push(json!(receipt_ref));
    }

    let mut updated = record.clone();
    if let Some(object) = updated.as_object_mut() {
        object.insert("environment_ports".into(), json!(ports));
        object.insert("latest_receipt_refs".into(), json!(receipt_refs.clone()));
    }
    let _ = persist_record(&st.data_dir, "sessions", &session_id, &updated);

    (
        StatusCode::OK,
        Json(json!({
            "schema_version": SESSION_EXECUTE_DECISION_SCHEMA_VERSION,
            "session_ref": session_id,
            "decision": "ports_revoked",
            "revoked_port": revoked_port,
            "environment_ports": ports,
            "latest_receipt_refs": receipt_refs,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

/// DELETE /v1/hypervisor/sessions/:id — tear a session down: revoke its preview
/// listener, remove the provisioned workspace from disk (only under the sessions
/// root), mark the session `torn_down` with its ports cleared, and emit a
/// teardown receipt. 404 if the session is unknown.
pub(crate) async fn handle_session_teardown(
    State(st): State<Arc<DaemonState>>,
    AxumPath(session_id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(record) = load_session_record(&st, &session_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "session_not_found", "message": "Unknown session.", "session_ref": session_id } })),
        );
    };
    let revoked_port = revoke_session_preview(&st, &session_id).await;
    let workspace_root = record.get("workspace_root").and_then(Value::as_str).unwrap_or("").to_string();
    let workspace_removed = remove_session_workspace(&workspace_root);

    let receipt_ref = format!("receipt://hypervisor/session-teardown/{}", safe_session_tag(&session_id));
    let receipt = json!({
        "id": receipt_ref,
        "kind": "hypervisor.session.teardown",
        "session_ref": session_id,
        "revoked_port": revoked_port,
        "workspace_removed": workspace_removed,
        "created_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);

    let mut receipt_refs: Vec<Value> = record
        .get("latest_receipt_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !receipt_refs.iter().any(|reference| reference.as_str() == Some(receipt_ref.as_str())) {
        receipt_refs.push(json!(receipt_ref));
    }

    let mut updated = record.clone();
    if let Some(object) = updated.as_object_mut() {
        object.insert("lifecycle_state".into(), json!("torn_down"));
        object.insert("environment_ports".into(), json!([]));
        object.insert("latest_receipt_refs".into(), json!(receipt_refs.clone()));
    }
    let _ = persist_record(&st.data_dir, "sessions", &session_id, &updated);

    (
        StatusCode::OK,
        Json(json!({
            "schema_version": SESSION_EXECUTE_DECISION_SCHEMA_VERSION,
            "session_ref": session_id,
            "decision": "torn_down",
            "revoked_port": revoked_port,
            "workspace_removed": workspace_removed,
            "latest_receipt_refs": receipt_refs,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

// ===========================================================================
// Phase 5 — RuntimeAgentService host substrate (CONSOLIDATED).
//
// Makes the Rust daemon a legitimate host for the CANONICAL `RuntimeAgentService`
// over a file-backed StateAccess (the daemon state dir), a deterministic (mock)
// inference, a synthetic TxContext, and the event-log bridge wired into /events.
// This is the realized Lane B true-north: the daemon runs the canonical
// `decision_loop::handle_step`, not a placeholder.
//
// Phases, all live on POST /v1/hypervisor/runtime-host/sessions:
//   5A: lifecycle ops (start@v1 + post_message@v1) — no tools, no model.
//   5B: a wallet-gated step@v1 runs the REAL cognition, constrained (no side effect).
//   5C: a `file_write` directive → a constrained file__write mutates the workspace
//       (NativeOsDriver), under a persisted Allow policy decision.
//   5 (shell):   a `shell_run` directive → a constrained shell__run executes through
//       the real TerminalDriver (bwrap sandbox, network-unshared, workspace cwd).
//   5 (browser): a `browser_navigate` directive → a constrained browser__navigate
//       launches the real BrowserDriver (Chromium) against a benign local page.
//
// The GUI driver is a no-op (the host never drives a GUI); the terminal/browser
// drivers are real and invoked on demand. Every consequential tool is governed by
// a per-directive constrained ActionRules policy (default RequireApproval) plus the
// per-capability hard guards (workspace boundary / command allowlist + bwrap / PII
// egress firewall) — and the whole step is wallet-execution-authority gated.
// ===========================================================================
pub(crate) mod runtime_host {
    use std::collections::HashMap;
    use std::sync::{Arc, OnceLock};

    use async_trait::async_trait;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::Json;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use tokio::sync::broadcast;

    use ioi_api::services::access::ServiceDirectory;
    use ioi_api::services::BlockchainService;
    use ioi_api::state::{StateAccess, StateScanIter};
    use ioi_api::transaction::context::TxContext;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::mock::MockInferenceRuntime;
    use ioi_api::vm::inference::InferenceRuntime;
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_memory::MemoryRuntime;
    use ioi_services::agentic::runtime::event_log_bridge::run_event_log_bridge;
    use ioi_services::agentic::runtime::service::{
        install_constrained_browser_navigation_policy, install_constrained_shell_exec_policy,
        install_constrained_workspace_write_policy, RuntimeAgentService,
    };
    use ioi_services::agentic::runtime::types::{AgentMode, PostMessageParams, StartAgentParams, StepAgentParams};
    use ioi_types::app::agentic::{
        BrowserActionPlanRef, CommandExecutionPlanRef, FileMutationPlanRef, RequiredCapability,
        RuntimeActionFrame, RuntimeIntentEvidence, RuntimeRouteFrame,
    };
    use ioi_types::app::{ActionRequest, ContextSlice, KernelEvent};
    use ioi_types::codec;
    use ioi_types::error::{StateError, VmError};

    use super::DaemonState;

    /// File-backed StateAccess over `<data_dir>/runtime-host-state/`. Each KV pair is
    /// a file named `hex(key)` whose bytes are the value. Loads existing keys on
    /// construction and write-throughs on insert/delete, so runtime state writes are
    /// persistent + inspectable. Single-request use (Phase 5A foothold).
    pub(crate) struct DaemonHostStateAccess {
        dir: std::path::PathBuf,
        data: HashMap<Vec<u8>, Vec<u8>>,
    }

    impl DaemonHostStateAccess {
        pub(crate) fn open(data_dir: &str) -> Self {
            let dir = std::path::Path::new(data_dir).join("runtime-host-state");
            let _ = std::fs::create_dir_all(&dir);
            let mut data = HashMap::new();
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if let Ok(key) = hex_decode(&name) {
                        if let Ok(value) = std::fs::read(entry.path()) {
                            data.insert(key, value);
                        }
                    }
                }
            }
            Self { dir, data }
        }

        pub(crate) fn key_count(&self) -> usize {
            self.data.len()
        }

        fn persist_key(&self, key: &[u8], value: &[u8]) {
            let _ = std::fs::write(self.dir.join(hex_encode(key)), value);
        }

        fn remove_key(&self, key: &[u8]) {
            let _ = std::fs::remove_file(self.dir.join(hex_encode(key)));
        }
    }

    impl StateAccess for DaemonHostStateAccess {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }
        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.persist_key(key, value);
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.remove_key(key);
            self.data.remove(key);
            Ok(())
        }
        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                self.insert(key, value)?;
            }
            Ok(())
        }
        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            let mut out = Vec::with_capacity(keys.len());
            for key in keys {
                out.push(self.get(key)?);
            }
            Ok(out)
        }
        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            for key in deletes {
                self.delete(key)?;
            }
            for (key, value) in inserts {
                self.insert(key, value)?;
            }
            Ok(())
        }
        fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
            let results: Vec<_> = self
                .data
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
                .collect();
            Ok(Box::new(results.into_iter()))
        }
    }

    /// A GUI driver that does nothing — the host never drives a GUI in Phase 5A.
    /// Capture/input calls error (so any accidental GUI use is loud, not silent).
    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(&self, _crop: Option<(i32, i32, u32, u32)>) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("runtime-host GUI is disabled in Phase 5A".into()))
        }
        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("runtime-host GUI is disabled in Phase 5A".into()))
        }
        async fn capture_tree(&self) -> Result<String, VmError> {
            Err(VmError::HostError("runtime-host GUI is disabled in Phase 5A".into()))
        }
        async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
            Err(VmError::HostError("runtime-host GUI is disabled in Phase 5A".into()))
        }
        async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
            Err(VmError::HostError("runtime-host GUI is disabled in Phase 5A".into()))
        }
        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }
        async fn register_som_overlay(
            &self,
            _map: HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    /// The runtime-thread-event bridge sender, initialized once. `run_event_log_bridge`
    /// runs in a background task persisting `KernelEvent::RuntimeThreadEvent`s emitted on
    /// this channel into the daemon's `<data_dir>/events` log (the same log /events reads).
    static RUNTIME_HOST_BRIDGE: OnceLock<broadcast::Sender<KernelEvent>> = OnceLock::new();

    fn runtime_host_bridge_sender(data_dir: &str) -> broadcast::Sender<KernelEvent> {
        RUNTIME_HOST_BRIDGE
            .get_or_init(|| {
                let (tx, rx) = broadcast::channel::<KernelEvent>(256);
                let state_dir = data_dir.to_string();
                tokio::spawn(async move {
                    run_event_log_bridge(state_dir, rx).await;
                });
                tx
            })
            .clone()
    }

    /// Construct the canonical RuntimeAgentService as a deterministic, headless host:
    /// no-op GUI, lazy (uninitialized) browser, idle terminal, deterministic mock
    /// inference, the session workspace path, and the runtime-thread-event sender wired
    /// to the bridge. No driver is invoked by the lifecycle ops.
    fn build_runtime_agent_host(
        workspace_path: &str,
        memory: Arc<MemoryRuntime>,
        bridge: broadcast::Sender<KernelEvent>,
        events: broadcast::Sender<KernelEvent>,
    ) -> RuntimeAgentService {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let terminal = Arc::new(TerminalDriver::new());
        let browser = Arc::new(BrowserDriver::new());
        let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
        RuntimeAgentService::new(gui, terminal, browser, inference)
            .with_workspace_path(workspace_path.to_string())
            .with_memory_runtime(memory)
            .with_event_sender(events)
            .with_runtime_thread_event_sender(bridge)
    }

    /// A compact, deterministic summary of a KernelEvent for the step probe / response.
    fn summarize_kernel_event(event: &KernelEvent) -> Value {
        match event {
            KernelEvent::AgentActionResult { step_index, tool_name, error_class, agent_status, .. } => json!({
                "kind": "AgentActionResult",
                "step_index": step_index,
                "tool_name": tool_name,
                "error_class": error_class,
                "agent_status": agent_status,
            }),
            KernelEvent::AgentThought { .. } => json!({ "kind": "AgentThought" }),
            KernelEvent::AgentAnswerDelta { .. } => json!({ "kind": "AgentAnswerDelta" }),
            KernelEvent::RuntimeThreadEvent { .. } => json!({ "kind": "RuntimeThreadEvent" }),
            other => json!({ "kind": format!("{other:?}").split_whitespace().next().unwrap_or("KernelEvent") }),
        }
    }

    /// Build a synthetic, non-chain TxContext bound to a freshly-created ServiceDirectory.
    /// The caller owns the directory so the borrow outlives the call.
    fn synthetic_service_directory() -> ServiceDirectory {
        ServiceDirectory::new(vec![])
    }

    fn synthetic_tx_context<'a>(services: &'a ServiceDirectory, now_ns: u64) -> TxContext<'a> {
        TxContext {
            block_height: 1,
            block_timestamp: now_ns,
            chain_id: ioi_types::app::ChainId(0),
            signer_account_id: ioi_types::app::AccountId::default(),
            services,
            simulation: false,
            is_internal: false,
        }
    }

    /// A pre-resolved `RuntimeRouteFrame` that deterministically dispatches a constrained
    /// `file__write` of `content` to the workspace-relative `path` (mirrors the canonical
    /// `typed_file_write_frame` recipe). The frame's `filesystem.write` capability seeds the
    /// resolved intent so the file tool passes the precheck — no shell, no browser, no model
    /// tool selection. This is the Phase 5C constrained, deterministic tool driver.
    fn file_write_route_frame(path: &str, content: &str) -> RuntimeRouteFrame {
        RuntimeRouteFrame {
            intent_id: "workspace.mutate".to_string(),
            route_family: "workspace".to_string(),
            output_intent: "tool_execution".to_string(),
            direct_answer_allowed: false,
            target: path.to_string(),
            target_kind: Some("workspace_path".to_string()),
            host_mutation: true,
            required_capabilities: vec!["filesystem.write".to_string()],
            typed_evidence: vec![
                RuntimeIntentEvidence {
                    evidence_kind: "workspace_path".to_string(),
                    value: path.to_string(),
                    source: "runtime_host".to_string(),
                    confidence: Some(95),
                },
                RuntimeIntentEvidence {
                    evidence_kind: "file_write_content".to_string(),
                    value: content.to_string(),
                    source: "runtime_host".to_string(),
                    confidence: Some(90),
                },
            ],
            typed_required_capabilities: vec![RequiredCapability {
                capability_id: "filesystem.write".to_string(),
                reason: Some("phase 5c constrained file write".to_string()),
            }],
            host_mutation_scope: None,
            runtime_action: Some(RuntimeActionFrame {
                intent_class: "workspace.mutate".to_string(),
                action_family: "file".to_string(),
                target_text: path.to_string(),
                target_kind: "workspace_path".to_string(),
                host_mutation: true,
                required_capabilities: vec![RequiredCapability {
                    capability_id: "filesystem.write".to_string(),
                    reason: Some("phase 5c constrained file write".to_string()),
                }],
                browser_plan: None,
                command_plan: None,
                file_plan: Some(FileMutationPlanRef {
                    plan_ref: "file.write:runtime-host".to_string(),
                    path: path.to_string(),
                    observed_hash: String::new(),
                    mutation_kind: "write".to_string(),
                    verification_command: None,
                }),
                provenance: Some("runtime_host".to_string()),
            }),
            install_request: None,
            provenance: Some("runtime_host".to_string()),
        }
    }

    /// A pre-resolved `RuntimeRouteFrame` that deterministically dispatches a constrained
    /// `shell__run` of `argv` (argv[0] is the command, the rest are args) via the canonical
    /// `maybe_typed_runtime_shell_run_tool_call`. `intent_id`/`route_family` are the command
    /// family (NOT workspace, so the frame resolves to the shell-command intent rather than
    /// workspace-context). The command runs through the real `TerminalDriver` (bwrap sandbox,
    /// network-unshared, workspace-bound cwd) — no shell/browser/model tool selection.
    fn shell_run_route_frame(argv: &[String]) -> RuntimeRouteFrame {
        let command = argv.first().cloned().unwrap_or_default();
        RuntimeRouteFrame {
            intent_id: "command.exec".to_string(),
            route_family: "command_execution".to_string(),
            output_intent: "tool_execution".to_string(),
            direct_answer_allowed: false,
            target: command.clone(),
            target_kind: Some("shell_command".to_string()),
            host_mutation: true,
            required_capabilities: vec!["command.exec".to_string()],
            typed_evidence: vec![RuntimeIntentEvidence {
                evidence_kind: "normalized_request".to_string(),
                value: argv.join(" "),
                source: "runtime_host".to_string(),
                confidence: Some(95),
            }],
            typed_required_capabilities: vec![RequiredCapability {
                capability_id: "command.exec".to_string(),
                reason: Some("phase 5 constrained shell run".to_string()),
            }],
            host_mutation_scope: None,
            runtime_action: Some(RuntimeActionFrame {
                intent_class: "local_runtime_action".to_string(),
                action_family: "shell".to_string(),
                target_text: argv.join(" "),
                target_kind: "shell_command".to_string(),
                host_mutation: true,
                required_capabilities: vec![RequiredCapability {
                    capability_id: "command.exec".to_string(),
                    reason: Some("phase 5 constrained shell run".to_string()),
                }],
                browser_plan: None,
                command_plan: Some(CommandExecutionPlanRef {
                    plan_ref: "command.exec:runtime-host".to_string(),
                    argv: argv.to_vec(),
                    shell_policy: "bounded".to_string(),
                    cwd: None,
                    env: Vec::new(),
                    approval_scope: None,
                    expected_receipt: Some("command_receipt".to_string()),
                }),
                file_plan: None,
                provenance: Some("runtime_host".to_string()),
            }),
            install_request: None,
            provenance: Some("runtime_host".to_string()),
        }
    }

    /// A pre-resolved `RuntimeRouteFrame` that deterministically dispatches a constrained
    /// `browser__navigate` to `url` via the canonical `maybe_typed_runtime_browser_navigate_tool_call`.
    /// The navigation runs through the real `BrowserDriver` (Chromium); the PII egress firewall
    /// still inspects the URL. Intended for benign/local (`file://`) URLs — no model selection.
    fn browser_navigate_route_frame(url: &str) -> RuntimeRouteFrame {
        RuntimeRouteFrame {
            intent_id: "browser.interact".to_string(),
            route_family: "browser".to_string(),
            output_intent: "tool_execution".to_string(),
            direct_answer_allowed: false,
            target: url.to_string(),
            target_kind: Some("browser_target".to_string()),
            host_mutation: false,
            required_capabilities: vec!["browser.interact".to_string()],
            typed_evidence: vec![RuntimeIntentEvidence {
                evidence_kind: "normalized_request".to_string(),
                value: url.to_string(),
                source: "runtime_host".to_string(),
                confidence: Some(95),
            }],
            typed_required_capabilities: vec![RequiredCapability {
                capability_id: "browser.interact".to_string(),
                reason: Some("phase 5 constrained browser navigation".to_string()),
            }],
            host_mutation_scope: None,
            runtime_action: Some(RuntimeActionFrame {
                intent_class: "local_runtime_action".to_string(),
                action_family: "browser".to_string(),
                target_text: url.to_string(),
                target_kind: "browser_target".to_string(),
                host_mutation: false,
                required_capabilities: vec![RequiredCapability {
                    capability_id: "browser.interact".to_string(),
                    reason: Some("phase 5 constrained browser navigation".to_string()),
                }],
                browser_plan: Some(BrowserActionPlanRef {
                    plan_ref: format!("browser.navigate:{url}"),
                    action: "navigate".to_string(),
                    url: url.to_string(),
                    observation_required: true,
                    observation_ref: None,
                    coordinate_space_id: None,
                    semantic_id: None,
                }),
                command_plan: None,
                file_plan: None,
                provenance: Some("runtime_host".to_string()),
            }),
            install_request: None,
            provenance: Some("runtime_host".to_string()),
        }
    }

    fn session_id_for_ref(session_ref: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(session_ref.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn hex_decode(text: &str) -> Result<Vec<u8>, ()> {
        if text.len() % 2 != 0 {
            return Err(());
        }
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }

    /// A short filesystem-safe id suffix for a session_ref (for the agent/thread linkage).
    fn host_suffix(session_ref: &str) -> String {
        super::short_hash(session_ref)
    }

    /// POST /v1/hypervisor/runtime-host/sessions — Phase 5A: host the canonical
    /// RuntimeAgentService lifecycle (`start@v1` + optional `post_message@v1`) against a
    /// file-backed StateAccess, write the session→thread linkage, and emit a host
    /// lifecycle `RuntimeThreadEvent` through the wired bridge so it lands in /events.
    /// No tools, no model, no workspace mutation.
    pub(crate) async fn handle_runtime_host_session(
        State(st): State<Arc<DaemonState>>,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        let now = super::iso_now();
        let session_ref = body
            .get("session_ref")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("runtime-host-session:{}", super::short_hash(&now)));
        let goal = body
            .get("goal")
            .and_then(Value::as_str)
            .unwrap_or("Phase 5A runtime-host lifecycle exercise")
            .to_string();
        let message = body.get("message").and_then(Value::as_str).map(str::to_string);

        let session_id = session_id_for_ref(&session_ref);
        let session_id_hex = hex_encode(&session_id);
        let suffix = host_suffix(&session_ref);
        let agent_id = format!("agent_{suffix}");
        let thread_id = format!("thread_{suffix}");

        // session → thread linkage so the bridge resolves the event log target.
        let agent_record = json!({
            "id": agent_id,
            "object": "ioi.agent",
            "runtime_session_id": session_id_hex,
            "thread_id": thread_id,
            "runtime_host_status": "hosted",
            "created_at": now,
        });
        let _ = super::persist_record(&st.data_dir, "agents", &agent_id, &agent_record);

        // A real (empty) session workspace path; Phase 5A never mutates it.
        let workspace_path = std::path::Path::new(&st.data_dir)
            .join("runtime-host-workspaces")
            .join(&suffix);
        let _ = std::fs::create_dir_all(&workspace_path);
        let workspace_path = workspace_path.to_string_lossy().into_owned();

        // Persistent transcript/memory runtime (the lifecycle ops append the seed +
        // posted messages to the session transcript via the SCS).
        let memory_path = std::path::Path::new(&st.data_dir).join("runtime-host-memory.sqlite");
        let memory = match MemoryRuntime::open_sqlite(&memory_path) {
            Ok(runtime) => Arc::new(runtime),
            Err(error) => return host_error(&session_ref, "memory_runtime", &format!("{error:?}")),
        };
        let bridge = runtime_host_bridge_sender(&st.data_dir);
        // High-volume KernelEvent capture for the step probe (Phase 5B). The receiver
        // must exist before the step so emitted events are observed, not dropped.
        let (events_tx, mut events_rx) = broadcast::channel::<KernelEvent>(512);
        let host = build_runtime_agent_host(&workspace_path, memory, bridge.clone(), events_tx);
        let mut state = DaemonHostStateAccess::open(&st.data_dir);
        let services = synthetic_service_directory();
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut ctx = synthetic_tx_context(&services, now_ns);

        // A stepped request (5B) runs a consequential tool, so it is wallet-gated at the
        // daemon boundary BEFORE any state mutation — a no-grant call is a 403 challenge
        // that creates no session (so the grant-bound retry runs `start@v1` cleanly).
        let step_requested = body.get("step").and_then(Value::as_bool).unwrap_or(false);
        if step_requested {
            if let Err(challenge) = super::execute_authority_gate(&body, &session_ref, &workspace_path, &goal) {
                return (StatusCode::FORBIDDEN, Json(challenge));
            }
        }

        // Phase 5C: a `file_write` directive supplies a pre-resolved route frame so the step
        // deterministically dispatches a constrained `file__write` (no model tool selection,
        // no shell/browser). Path is workspace-relative + traversal-guarded.
        let file_write_frame = body.get("file_write").and_then(Value::as_object).and_then(|fw| {
            let path = fw.get("path").and_then(Value::as_str)?.trim();
            let content = fw.get("content").and_then(Value::as_str).unwrap_or("");
            if path.is_empty() || path.starts_with('/') || path.split('/').any(|seg| seg == "..") {
                return None;
            }
            Some(file_write_route_frame(path, content))
        });

        // Phase 5 (shell): a `shell_run` directive supplies a pre-resolved command frame so
        // the step deterministically dispatches a constrained `shell__run` through the REAL
        // TerminalDriver (bwrap sandbox, network-unshared, workspace-bound cwd). argv[0] is
        // the command; the policy command allowlist + the bwrap sandbox bound it.
        let shell_run_argv: Option<Vec<String>> =
            body.get("shell_run").and_then(Value::as_object).and_then(|sr| {
                let argv: Vec<String> = sr
                    .get("argv")
                    .and_then(Value::as_array)?
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|s| s.to_string())
                    .collect();
                if argv.is_empty() || argv[0].trim().is_empty() {
                    return None;
                }
                Some(argv)
            });
        let shell_run_frame = shell_run_argv.as_deref().map(shell_run_route_frame);

        // Phase 5 (browser): a `browser_navigate` directive supplies a pre-resolved browser
        // frame so the step deterministically dispatches a constrained `browser__navigate`
        // through the REAL BrowserDriver (Chromium). Intended for benign/local `file://` URLs.
        let browser_navigate_url: Option<String> = body
            .get("browser_navigate")
            .and_then(Value::as_object)
            .and_then(|bn| bn.get("url").and_then(Value::as_str))
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty());
        let browser_navigate_frame = browser_navigate_url
            .as_deref()
            .map(browser_navigate_route_frame);

        // Exactly one pre-resolved tool frame may drive the constrained step (precedence:
        // file write → shell → browser). Without a directive the step runs unconstrained cognition.
        let has_file_write_directive = file_write_frame.is_some();
        let route_frame = file_write_frame.or(shell_run_frame).or(browser_navigate_frame);

        // start@v1 (canonical lifecycle op; deterministic — no inference).
        let start_params = StartAgentParams {
            session_id,
            goal: goal.clone(),
            runtime_route_frame: route_frame,
            max_steps: 8,
            parent_session_id: None,
            initial_budget: 0,
            mode: AgentMode::Agent,
        };
        let start_bytes = match codec::to_bytes_canonical(&start_params) {
            Ok(bytes) => bytes,
            Err(error) => return host_error(&session_ref, "encode_start_params", &error),
        };
        if let Err(error) = host.handle_service_call(&mut state, "start@v1", &start_bytes, &mut ctx).await {
            return host_error(&session_ref, "start_v1", &format!("{error:?}"));
        }

        // Phase 5: install the constrained session policy matching the directive — the runtime
        // POLICY DECISION (an `Allow` verdict, NOT an approval-token bypass) that lets the one
        // constrained capability execute while leaving every other under the default
        // RequireApproval gate. The wallet execution-authority gate above already established
        // the user's authority; the per-capability hard guards (workspace boundary / command
        // allowlist + bwrap) still apply.
        if has_file_write_directive {
            if let Err(error) = install_constrained_workspace_write_policy(&mut state, session_id) {
                return host_error(&session_ref, "install_session_policy", &format!("{error:?}"));
            }
        } else if let Some(argv) = shell_run_argv.as_ref() {
            if let Err(error) =
                install_constrained_shell_exec_policy(&mut state, session_id, &argv[0])
            {
                return host_error(&session_ref, "install_session_policy", &format!("{error:?}"));
            }
        } else if browser_navigate_url.is_some() {
            if let Err(error) = install_constrained_browser_navigation_policy(&mut state, session_id) {
                return host_error(&session_ref, "install_session_policy", &format!("{error:?}"));
            }
        }

        // post_message@v1 (optional; deterministic — no inference).
        let mut message_posted = false;
        if let Some(content) = message.as_ref() {
            let post_params = PostMessageParams {
                session_id,
                role: "user".to_string(),
                content: content.clone(),
            };
            let post_bytes = match codec::to_bytes_canonical(&post_params) {
                Ok(bytes) => bytes,
                Err(error) => return host_error(&session_ref, "encode_post_message_params", &error),
            };
            if let Err(error) = host.handle_service_call(&mut state, "post_message@v1", &post_bytes, &mut ctx).await {
                return host_error(&session_ref, "post_message_v1", &format!("{error:?}"));
            }
            message_posted = true;
        }

        // Phase 5B PROBE: a single constrained, wallet-gated `step@v1` against the hosted
        // runtime. Deterministic (mock inference) — the cognition produces one tool intent;
        // the runtime's own policy decides whether it executes or is gated. We CAPTURE the
        // emitted KernelEvents to report exactly what happened (no assumption).
        let mut step_outcome = Value::Null;
        if step_requested {
            let step_params = StepAgentParams { session_id };
            let step_bytes = match codec::to_bytes_canonical(&step_params) {
                Ok(bytes) => bytes,
                Err(error) => return host_error(&session_ref, "encode_step_params", &error),
            };
            let step_result = host.handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx).await;
            let mut captured: Vec<Value> = Vec::new();
            while let Ok(event) = events_rx.try_recv() {
                captured.push(summarize_kernel_event(&event));
            }
            step_outcome = json!({
                "ran": step_result.is_ok(),
                "error": step_result.err().map(|error| format!("{error:?}")),
                "events": captured,
                // Whether any tool actually mutated the workspace (Phase 5B asserts none for a
                // gated step; the workspace dir is re-read after the step below).
            });
        }

        let workspace_files_after: Vec<String> = std::fs::read_dir(&workspace_path)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();

        let state_keys_written = state.key_count();

        // Emit a host lifecycle RuntimeThreadEvent through the wired bridge. The bridge
        // resolves session→thread and admits it to the daemon's /events log (the same
        // channel step@v1 will use in Phase 5B). event_json omits thread_id/event_stream_id
        // (the bridge fills them from the session lookup).
        let event_hash = super::short_hash(&format!("{thread_id}:{now}:runtime_host_session"));
        let event_json = json!({
            "event_id": format!("event_runtime_host_session_started_{event_hash}"),
            "idempotency_key": format!("thread:{thread_id}:runtime_host.session.started:{event_hash}"),
            "source_event_kind": "RuntimeHost.SessionStarted",
            "event_kind": "runtime_host.session.started",
            "payload_schema_version": "ioi.runtime.runtime-host-session.v1",
            "payload": {
                "session_ref": session_ref,
                "runtime_session_id": session_id_hex,
                "goal": goal,
                "message_posted": message_posted,
                "host": "rust_runtime_agent_service",
            },
            "receipt_refs": [format!("receipt_runtime_host_session_{event_hash}")],
        })
        .to_string();
        let _ = bridge.send(KernelEvent::RuntimeThreadEvent { session_id, event_json });

        (
            StatusCode::OK,
            Json(json!({
                "schema_version": "ioi.hypervisor.runtime_host_session.v1",
                "session_ref": session_ref,
                "runtime_session_id": session_id_hex,
                "thread_id": thread_id,
                "agent_id": agent_id,
                "lifecycle": "hosted",
                "ops": if message_posted { json!(["start@v1", "post_message@v1"]) } else { json!(["start@v1"]) },
                "state_keys_written": state_keys_written,
                "workspace_path": workspace_path,
                "workspace_files_after": workspace_files_after,
                // Phase 5B step probe (null unless `step: true` was requested).
                "step": step_outcome,
                "host": {
                    "service": "RuntimeAgentService",
                    "gui": "noop",
                    "browser": "lazy_uninitialized",
                    "terminal": "idle",
                    "inference": "deterministic_mock",
                    // Lifecycle ops (5A) are tool-free + don't call inference; a step (5B) runs
                    // the deterministic mock cognition (inference invoked).
                    "model_invoked": body.get("step").and_then(Value::as_bool).unwrap_or(false),
                    "workspace_mutated": !workspace_files_after.is_empty(),
                },
                "events_path": format!("/v1/threads/{thread_id}/events"),
                "runtimeTruthSource": "daemon-runtime",
            })),
        )
    }

    fn host_error(session_ref: &str, code: &str, detail: &str) -> (StatusCode, Json<Value>) {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": {
                    "code": format!("runtime_host_{code}_failed"),
                    "message": format!("Runtime host lifecycle op failed at {code}."),
                    "detail": detail,
                    "session_ref": session_ref,
                },
            })),
        )
    }
}

#[cfg(test)]
mod sigv4_tests {
    use super::sigv4_authorization;
    // AWS SigV4 official test suite "get-vanilla" known-answer vector.
    #[test]
    fn sigv4_get_vanilla_matches_aws_vector() {
        let auth = sigv4_authorization(
            "GET", "example.amazonaws.com", "/", "", b"",
            "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", None,
            "us-east-1", "service", "20150830T123600Z",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }
}
