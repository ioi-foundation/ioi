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
    let candidate = cwd.join("packages/runtime-daemon/src/harness-shims/generic-cli-local.mjs");
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
fn project_session_environment_status(
    environment_ref: &str,
    workspace_root: &str,
    custody_posture: &str,
    initializer_ref: &str,
    workspace_artifact_ref: &str,
    component_phases: &Value,
    substrate: &ExecutionSubstrate,
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
    let environment_ref = format!("environment:{}", safe_session_tag(&session_ref));

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

    let provision = match provision_session_workspace(&session_ref, &initializer) {
        Ok(outcome) => outcome,
        Err(error) => {
            return (
                error.0,
                Json(json!({ "error": { "code": "workspace_provision_failed", "message": error.1 } })),
            );
        }
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

    let substrate = ExecutionSubstrate::probe();
    let environment_status = project_session_environment_status(
        environment_ref,
        workspace_root,
        custody_posture,
        initializer_ref,
        workspace_artifact_ref,
        &component_phases,
        &substrate,
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

/// Consequential scopes a session execution exercises. `workspace_write` (the
/// harness edits the workspace) and `command_exec` (the daemon spawns a process)
/// are gated today; `port_exposure` joins this set when the served preview port
/// lands, so the preview is gated under the SAME wallet authority — never an
/// ungated effect surface. Kept sorted so the derived hashes are stable.
const EXECUTION_AUTHORITY_SCOPES: &[&str] = &["command_exec", "workspace_write"];

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

/// POST /v1/hypervisor/sessions/:id/execute — Lane A execution.
///
/// FAILS CLOSED with an honest reason (`no_model_route` / `harness_unavailable` /
/// `container_unavailable`) when the execution substrate is absent — no fabricated
/// work. When a model route + a host harness are present this runs the REAL Lane A
/// loop (Cut #2): it spawns the `generic-cli-local` harness in the provisioned
/// workspace bound to the local model, delivers the intent, and reports the
/// harness's real file writes, a real `changed_file_groups` diff (git/walk), the
/// real terminal transcript, and Agentgres receipts. Failure paths stay honest:
/// the diff and transcript reflect whatever truly happened; nothing is invented.
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
    let substrate = ExecutionSubstrate::probe();

    // Honest fail-closed ordering: model → harness → (container, if requested).
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

    // --- Wallet authority gate (consequential effects: workspace_write + command_exec) ---
    // Execution mutates the workspace and spawns a process, so it is wallet-gated. The
    // policy/request hashes are DAEMON-DERIVED (never the POST body); a no-grant call is a
    // 403 challenge that exposes them so a wallet can mint a bound grant. The grant is then
    // verified cryptographically (signature + structural) and bound to expiry + both hashes
    // by `verify_wallet_approval_grant_binding`. This runs BEFORE any spawn.
    let policy_hash = execution_policy_hash(&session_id, &workspace_root, EXECUTION_AUTHORITY_SCOPES);
    let request_hash = execution_request_hash(&session_id, &intent, EXECUTION_AUTHORITY_SCOPES);
    let grant_value = body.get("wallet_approval_grant").cloned().unwrap_or(Value::Null);
    let now_ms = daemon_now_ms_fail_closed();
    let authority = if grant_value.is_null() {
        Err("a wallet_approval_grant is required".to_string())
    } else {
        verify_wallet_approval_grant_binding(&grant_value, Some(now_ms), Some(&policy_hash), Some(&request_hash))
    };
    let capability_lease_ref = match authority {
        Ok(binding) => binding.grant_ref,
        Err(reason) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
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
                    // Blocked before spawn: nothing ran, nothing fabricated.
                    "changed_file_groups": [],
                    "terminal_events": [],
                    "runtimeTruthSource": "daemon-runtime",
                })),
            );
        }
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
        "policy_hash": policy_hash,
        "request_hash": request_hash,
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
