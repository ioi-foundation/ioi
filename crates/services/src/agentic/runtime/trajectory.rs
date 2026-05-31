use crate::agentic::runtime::substrate::RuntimeSubstrateSnapshot;
use crate::agentic::runtime::types::{AgentState, AgentStatus, ToolCallStatus};
use ioi_types::app::{AgentRuntimeEvent, AgentTurnPhase, EvidenceRef, StopReason};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub const AGENT_TRAJECTORY_STEP_SCHEMA_VERSION: &str = "ioi.agent.trajectory.step.v1";
pub const AGENT_BRAIN_SCHEMA_VERSION: &str = "ioi.agent.brain.v1";

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct AgentTrajectoryStepRecord {
    pub schema_version: String,
    pub session_id: String,
    pub turn_id: String,
    pub step_index: u32,
    pub status: String,
    pub phase: AgentTurnPhase,
    pub objective: String,
    pub parent_session_id: Option<String>,
    pub child_session_ids: Vec<String>,
    pub last_action_type: Option<String>,
    pub pending_tool: Option<String>,
    pub tool_events: Vec<TrajectoryToolEvent>,
    pub workspace_changes: Vec<WorkspaceChangeRecord>,
    pub stop_gate: AgentStopGateRecord,
    pub event_kinds: Vec<String>,
    pub state_ref: String,
    pub substrate_ref: String,
    pub brain_ref: String,
    pub transcript_root: String,
    pub policy_ref: Option<String>,
    pub created_at_ms: u64,
    pub redaction_profile: String,
    pub append_only: bool,
}

impl Default for AgentTrajectoryStepRecord {
    fn default() -> Self {
        Self {
            schema_version: AGENT_TRAJECTORY_STEP_SCHEMA_VERSION.to_string(),
            session_id: String::new(),
            turn_id: String::new(),
            step_index: 0,
            status: String::new(),
            phase: AgentTurnPhase::Accepted,
            objective: String::new(),
            parent_session_id: None,
            child_session_ids: Vec::new(),
            last_action_type: None,
            pending_tool: None,
            tool_events: Vec::new(),
            workspace_changes: Vec::new(),
            stop_gate: AgentStopGateRecord::default(),
            event_kinds: Vec::new(),
            state_ref: String::new(),
            substrate_ref: String::new(),
            brain_ref: String::new(),
            transcript_root: String::new(),
            policy_ref: None,
            created_at_ms: 0,
            redaction_profile: "internal_summary".to_string(),
            append_only: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(default)]
pub struct WorkspaceChangeRecord {
    pub tool_name: String,
    pub path: Option<String>,
    pub lifecycle: String,
    pub edit_count: u32,
    pub authority_ref: Option<String>,
    pub evidence_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct AgentStopGateRecord {
    pub schema_version: String,
    pub session_id: String,
    pub turn_id: String,
    pub step_index: u32,
    pub terminal_state: bool,
    pub reason: StopReason,
    pub evidence_sufficient: bool,
    pub rationale: String,
    pub evidence_refs: Vec<EvidenceRef>,
    pub continuation: String,
    pub replayable: bool,
    pub created_at_ms: u64,
}

impl Default for AgentStopGateRecord {
    fn default() -> Self {
        Self {
            schema_version: "ioi.agent.stop_gate.v1".to_string(),
            session_id: String::new(),
            turn_id: String::new(),
            step_index: 0,
            terminal_state: false,
            reason: StopReason::Unknown,
            evidence_sufficient: false,
            rationale: String::new(),
            evidence_refs: Vec::new(),
            continuation: "continue_model_loop".to_string(),
            replayable: true,
            created_at_ms: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(default)]
pub struct TrajectoryToolEvent {
    pub tool_name: String,
    pub status: String,
    pub evidence_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct AgentBrainRecord {
    pub schema_version: String,
    pub session_id: String,
    pub objective: String,
    pub step_index: u32,
    pub status: String,
    pub implementation_plan_md: String,
    pub task_md: String,
    pub walkthrough_md: String,
    pub scratch_refs: Vec<String>,
    pub evidence_refs: Vec<EvidenceRef>,
    pub updated_at_ms: u64,
    pub read_only: bool,
}

impl Default for AgentBrainRecord {
    fn default() -> Self {
        Self {
            schema_version: AGENT_BRAIN_SCHEMA_VERSION.to_string(),
            session_id: String::new(),
            objective: String::new(),
            step_index: 0,
            status: String::new(),
            implementation_plan_md: String::new(),
            task_md: String::new(),
            walkthrough_md: String::new(),
            scratch_refs: Vec::new(),
            evidence_refs: Vec::new(),
            updated_at_ms: 0,
            read_only: false,
        }
    }
}

pub fn trajectory_step_record_for_state(
    state: &AgentState,
    snapshot: &RuntimeSubstrateSnapshot,
    created_at_ms: u64,
) -> AgentTrajectoryStepRecord {
    let session_id = hex::encode(state.session_id);
    AgentTrajectoryStepRecord {
        session_id: session_id.clone(),
        turn_id: snapshot.turn_state.turn_id.clone(),
        step_index: state.step_count,
        status: status_name(&state.status),
        phase: snapshot.turn_state.phase,
        objective: state.goal.clone(),
        parent_session_id: state.parent_session_id.map(hex::encode),
        child_session_ids: state.child_session_ids.iter().map(hex::encode).collect(),
        last_action_type: state.last_action_type.clone(),
        pending_tool: state.pending_tool_call.clone(),
        tool_events: tool_events_for_state(state),
        workspace_changes: workspace_changes_for_state(state),
        stop_gate: stop_gate_for_state(state, snapshot, created_at_ms),
        event_kinds: event_kinds(&snapshot.events),
        state_ref: format!("agent_state:{session_id}"),
        substrate_ref: format!("agent_runtime_substrate:{session_id}:{}", state.step_count),
        brain_ref: format!("agent_brain:{session_id}"),
        transcript_root: hex::encode(state.transcript_root),
        policy_ref: state
            .resolved_intent
            .as_ref()
            .map(|intent| hex::encode(intent.evidence_requirements_hash)),
        created_at_ms,
        ..AgentTrajectoryStepRecord::default()
    }
}

pub fn brain_record_for_state(
    state: &AgentState,
    snapshot: &RuntimeSubstrateSnapshot,
    updated_at_ms: u64,
) -> AgentBrainRecord {
    let session_id = hex::encode(state.session_id);
    AgentBrainRecord {
        session_id: session_id.clone(),
        objective: state.goal.clone(),
        step_index: state.step_count,
        status: status_name(&state.status),
        implementation_plan_md: implementation_plan_for_state(state, snapshot),
        task_md: task_board_for_state(state, snapshot),
        walkthrough_md: walkthrough_for_state(state, snapshot),
        scratch_refs: vec![format!(
            "agent_scratch:{session_id}:step:{}",
            state.step_count
        )],
        evidence_refs: snapshot.turn_state.evidence_refs.clone(),
        updated_at_ms,
        read_only: matches!(
            state.status,
            AgentStatus::Completed(_) | AgentStatus::Failed(_) | AgentStatus::Terminated
        ),
        ..AgentBrainRecord::default()
    }
}

fn status_name(status: &AgentStatus) -> String {
    match status {
        AgentStatus::Idle => "idle".to_string(),
        AgentStatus::Running => "running".to_string(),
        AgentStatus::Paused(_) => "paused".to_string(),
        AgentStatus::Completed(_) => "completed".to_string(),
        AgentStatus::Failed(_) => "failed".to_string(),
        AgentStatus::Terminated => "terminated".to_string(),
    }
}

fn tool_events_for_state(state: &AgentState) -> Vec<TrajectoryToolEvent> {
    let mut tool_events = state
        .tool_execution_log
        .iter()
        .map(|(tool_name, status)| TrajectoryToolEvent {
            tool_name: tool_name.clone(),
            status: tool_status_name(status),
            evidence_ref: match status {
                ToolCallStatus::Executed(value) | ToolCallStatus::Failed(value) => {
                    Some(value.chars().take(160).collect())
                }
                _ => None,
            },
        })
        .collect::<Vec<_>>();
    tool_events.sort_by(|left, right| left.tool_name.cmp(&right.tool_name));
    tool_events
}

fn workspace_changes_for_state(state: &AgentState) -> Vec<WorkspaceChangeRecord> {
    let mut changes = Vec::new();
    if let Some(pending_change) = pending_workspace_change_for_state(state) {
        changes.push(pending_change);
    }
    changes.extend(applied_workspace_changes_for_state(state));
    changes.extend(failed_workspace_changes_for_state(state));
    changes.sort_by(|left, right| {
        left.lifecycle
            .cmp(&right.lifecycle)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.tool_name.cmp(&right.tool_name))
    });
    changes
}

fn pending_workspace_change_for_state(state: &AgentState) -> Option<WorkspaceChangeRecord> {
    let tool = pending_agent_tool(state)?;
    workspace_change_from_tool(&tool, state.pending_tool_hash).map(|mut change| {
        change.lifecycle = if state.pending_tool_hash.is_some() {
            "awaiting_approval".to_string()
        } else {
            "proposed".to_string()
        };
        change
    })
}

fn pending_agent_tool(state: &AgentState) -> Option<ioi_types::app::agentic::AgentTool> {
    state
        .pending_tool_call
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
}

fn workspace_change_from_tool(
    tool: &ioi_types::app::agentic::AgentTool,
    tool_hash: Option<[u8; 32]>,
) -> Option<WorkspaceChangeRecord> {
    use ioi_types::app::agentic::AgentTool;

    let (tool_name, path, edit_count) = match tool {
        AgentTool::FsWrite { path, .. } => ("file__write", path.as_str(), 1),
        AgentTool::FsPatch { path, .. } => ("file__edit", path.as_str(), 1),
        AgentTool::FsMultiPatch { path, edits } => {
            ("file__multi_edit", path.as_str(), edits.len() as u32)
        }
        AgentTool::FsDelete { path, .. } => ("file__delete", path.as_str(), 1),
        _ => return None,
    };
    Some(WorkspaceChangeRecord {
        tool_name: tool_name.to_string(),
        path: Some(path.to_string()),
        lifecycle: "proposed".to_string(),
        edit_count,
        authority_ref: tool_hash.map(|hash| format!("pending_tool_hash:{}", hex::encode(hash))),
        evidence_ref: None,
    })
}

fn applied_workspace_changes_for_state(state: &AgentState) -> Vec<WorkspaceChangeRecord> {
    state
        .tool_execution_log
        .get("evidence::workspace_edit_applied")
        .and_then(executed_status_value)
        .map(|evidence| {
            let fields = receipt_fields(evidence);
            WorkspaceChangeRecord {
                tool_name: fields
                    .get("tool")
                    .cloned()
                    .unwrap_or_else(|| "file__edit".to_string()),
                path: fields.get("path").cloned(),
                lifecycle: "applied".to_string(),
                edit_count: 1,
                authority_ref: None,
                evidence_ref: Some(evidence.to_string()),
            }
        })
        .into_iter()
        .collect()
}

fn failed_workspace_changes_for_state(state: &AgentState) -> Vec<WorkspaceChangeRecord> {
    state
        .tool_execution_log
        .iter()
        .filter_map(|(tool_name, status)| {
            let evidence = failed_or_executed_status_value(status)?;
            if !evidence.contains("workspace_edit_applied")
                && !evidence.contains("search_block_not_found")
                && !matches!(
                    tool_name.as_str(),
                    "file__write" | "file__edit" | "file__multi_edit" | "file__delete"
                )
            {
                return None;
            }
            let fields = receipt_fields(evidence);
            Some(WorkspaceChangeRecord {
                tool_name: fields
                    .get("tool")
                    .cloned()
                    .unwrap_or_else(|| tool_name.clone()),
                path: fields.get("path").cloned(),
                lifecycle: "failed".to_string(),
                edit_count: 1,
                authority_ref: None,
                evidence_ref: Some(evidence.to_string()),
            })
        })
        .collect()
}

fn executed_status_value(status: &ToolCallStatus) -> Option<&str> {
    match status {
        ToolCallStatus::Executed(value) => Some(value.as_str()),
        _ => None,
    }
}

fn failed_or_executed_status_value(status: &ToolCallStatus) -> Option<&str> {
    match status {
        ToolCallStatus::Executed(value) | ToolCallStatus::Failed(value) => Some(value.as_str()),
        _ => None,
    }
}

fn receipt_fields(value: &str) -> std::collections::BTreeMap<String, String> {
    value
        .split(';')
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() || value.is_empty() {
                return None;
            }
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

fn stop_gate_for_state(
    state: &AgentState,
    snapshot: &RuntimeSubstrateSnapshot,
    created_at_ms: u64,
) -> AgentStopGateRecord {
    let session_id = hex::encode(state.session_id);
    let stop_condition = &snapshot.stop_condition;
    AgentStopGateRecord {
        session_id,
        turn_id: snapshot.turn_state.turn_id.clone(),
        step_index: state.step_count,
        terminal_state: snapshot.turn_state.is_terminal(),
        reason: stop_condition.reason,
        evidence_sufficient: stop_condition.evidence_sufficient,
        rationale: stop_condition.rationale.clone(),
        evidence_refs: stop_condition.evidence_refs.clone(),
        continuation: stop_gate_continuation(state, snapshot),
        created_at_ms,
        ..AgentStopGateRecord::default()
    }
}

fn stop_gate_continuation(state: &AgentState, snapshot: &RuntimeSubstrateSnapshot) -> String {
    match &state.status {
        AgentStatus::Completed(_) if snapshot.stop_condition.evidence_sufficient => {
            "handoff_terminal".to_string()
        }
        AgentStatus::Completed(_) => "verify_before_handoff".to_string(),
        AgentStatus::Failed(_) => "recover_or_surface_failure".to_string(),
        AgentStatus::Paused(_) => "await_operator_or_policy".to_string(),
        AgentStatus::Terminated => "cleanup_terminal".to_string(),
        AgentStatus::Running
            if state.pending_tool_call.is_some() || state.pending_tool_hash.is_some() =>
        {
            "continue_tool_boundary".to_string()
        }
        AgentStatus::Running | AgentStatus::Idle => "continue_model_loop".to_string(),
    }
}

fn tool_status_name(status: &ToolCallStatus) -> String {
    match status {
        ToolCallStatus::Pending => "pending".to_string(),
        ToolCallStatus::Approved => "approved".to_string(),
        ToolCallStatus::Executed(_) => "executed".to_string(),
        ToolCallStatus::Failed(_) => "failed".to_string(),
    }
}

fn event_kinds(events: &[AgentRuntimeEvent]) -> Vec<String> {
    let mut kinds = events
        .iter()
        .map(|event| event.event_kind.clone())
        .collect::<Vec<_>>();
    kinds.sort();
    kinds.dedup();
    kinds
}

fn implementation_plan_for_state(
    state: &AgentState,
    snapshot: &RuntimeSubstrateSnapshot,
) -> String {
    let strategy = snapshot.strategy_decision.selected_strategy.trim();
    let task_family = snapshot.strategy_decision.task_family.trim();
    let mut lines = vec![
        "# Implementation Plan".to_string(),
        String::new(),
        format!("- Objective: {}", state.goal.trim()),
        format!(
            "- Runtime strategy: {}",
            if strategy.is_empty() {
                "unspecified"
            } else {
                strategy
            }
        ),
        format!(
            "- Task family: {}",
            if task_family.is_empty() {
                "unspecified"
            } else {
                task_family
            }
        ),
        format!("- Current step: {}", state.step_count),
    ];
    if !snapshot.stop_condition.rationale.trim().is_empty() {
        lines.push(format!(
            "- Stop condition: {}",
            snapshot.stop_condition.rationale.trim()
        ));
    }
    lines.join("\n")
}

fn task_board_for_state(state: &AgentState, snapshot: &RuntimeSubstrateSnapshot) -> String {
    let mut lines = vec!["# Task Board".to_string(), String::new()];
    lines.push(format!(
        "- [{}] Runtime context prepared",
        checked(snapshot.prompt_assembly.included_section_count() > 0)
    ));
    lines.push(format!(
        "- [{}] Tool/action boundary recorded",
        checked(!state.tool_execution_log.is_empty() || state.pending_tool_call.is_some())
    ));
    lines.push(format!(
        "- [{}] Stop gate recorded",
        checked(!snapshot.stop_condition.rationale.trim().is_empty())
    ));
    lines.push(format!(
        "- [{}] Terminal result available",
        checked(matches!(
            state.status,
            AgentStatus::Completed(_) | AgentStatus::Failed(_) | AgentStatus::Terminated
        ))
    ));
    lines.join("\n")
}

fn walkthrough_for_state(state: &AgentState, snapshot: &RuntimeSubstrateSnapshot) -> String {
    let mut lines = vec![
        "# Walkthrough".to_string(),
        String::new(),
        format!("- Status: {}", status_name(&state.status)),
        format!("- Step: {}", state.step_count),
        format!("- Phase: {:?}", snapshot.turn_state.phase),
        format!("- Recorded runtime events: {}", snapshot.events.len()),
    ];
    if !state.child_session_ids.is_empty() {
        lines.push(format!(
            "- Child sessions: {}",
            state.child_session_ids.len()
        ));
    }
    if state.pending_approval.is_some() {
        lines.push("- Waiting on approval authority.".to_string());
    }
    lines.join("\n")
}

fn checked(value: bool) -> &'static str {
    if value {
        "x"
    } else {
        " "
    }
}
