use crate::agentic::runtime::agent_playbooks::{builtin_agent_playbooks, playbook_decision_record};
use crate::agentic::runtime::keys::{get_managed_session_control_key, get_parent_playbook_run_key};
use crate::agentic::runtime::types::{
    AgentState, AgentStatus, ParentPlaybookRun, ParentPlaybookStepRun, ToolCallStatus,
};
use ioi_api::state::StateAccess;
use ioi_types::app::{
    ComputerUsePerceptionSummary, ComputerUseRecoverySummary, ComputerUseVerificationScorecard,
};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const RUNTIME_MANAGED_SESSION_SCHEMA_VERSION: &str = "ioi.runtime.managed-session.v1";
const RUNS_TRACING_VISIBILITY: &str = "runs_tracing";
const PRODUCT_TEXT_MAX_CHARS: usize = 240;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeManagedSessionSnapshot {
    pub schema_version: String,
    pub session_id: String,
    pub session_count: usize,
    pub sessions: Vec<RuntimeManagedSessionCard>,
    pub replay: RuntimeManagedSessionReplaySnapshot,
    pub product_lane: Vec<RuntimeManagedSessionProductLaneEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeManagedSessionCard {
    pub id: String,
    pub kind: String,
    pub surface_label: String,
    pub status: String,
    pub status_label: String,
    pub control_state: String,
    pub available_control_states: Vec<String>,
    pub waiting_for_user: bool,
    pub waiting_reason: Option<String>,
    pub parent_playbook_id: Option<String>,
    pub parent_playbook_label: Option<String>,
    pub step_id: Option<String>,
    pub step_label: Option<String>,
    pub child_session_id: Option<String>,
    pub page_title: Option<String>,
    pub target: Option<String>,
    pub detail: String,
    pub last_tool: Option<String>,
    pub action_count: u32,
    pub screenshot_persistence: RuntimeScreenshotPersistenceSnapshot,
    pub replay_ready: bool,
    pub trace_visibility: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeScreenshotPersistenceSnapshot {
    pub state: String,
    pub sanitized_preview_ref: Option<String>,
    pub raw_capture_visibility: String,
    pub redaction_required_before_product: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeManagedSessionReplaySnapshot {
    pub replayable_session_ids: Vec<String>,
    pub replay_ready_count: usize,
    pub waiting_session_ids: Vec<String>,
    pub missing_persistence_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeManagedSessionProductLaneEntry {
    pub kind: String,
    pub label: String,
    pub status: String,
    pub session_id: String,
    pub summary: String,
    pub detail_visibility: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct RuntimeManagedSessionControlRecord {
    pub schema_version: String,
    pub parent_session_id: [u8; 32],
    pub managed_session_id: String,
    pub control_state: String,
    pub requested_by: String,
    pub reason: Option<String>,
    pub updated_at_ms: u64,
}

pub fn managed_session_snapshot_for_state(
    state: &dyn StateAccess,
    parent_state: &AgentState,
) -> Result<RuntimeManagedSessionSnapshot, String> {
    let session_id = parent_state.session_id;
    let mut sessions = managed_sessions_from_parent_playbooks(state, parent_state)?;
    sessions.extend(managed_sessions_from_agent_state(state, parent_state)?);
    dedupe_sessions(&mut sessions);

    let replayable_session_ids = sessions
        .iter()
        .filter(|session| session.replay_ready)
        .map(|session| session.id.clone())
        .collect::<Vec<_>>();
    let waiting_session_ids = sessions
        .iter()
        .filter(|session| session.waiting_for_user)
        .map(|session| session.id.clone())
        .collect::<Vec<_>>();
    let missing_persistence_count = sessions
        .iter()
        .filter(|session| {
            session
                .screenshot_persistence
                .redaction_required_before_product
                && session
                    .screenshot_persistence
                    .sanitized_preview_ref
                    .is_none()
        })
        .count();
    let product_lane = sessions
        .iter()
        .map(product_lane_entry_for_session)
        .collect();

    Ok(RuntimeManagedSessionSnapshot {
        schema_version: RUNTIME_MANAGED_SESSION_SCHEMA_VERSION.to_string(),
        session_id: hex::encode(session_id),
        session_count: sessions.len(),
        sessions,
        replay: RuntimeManagedSessionReplaySnapshot {
            replay_ready_count: replayable_session_ids.len(),
            replayable_session_ids,
            waiting_session_ids,
            missing_persistence_count,
        },
        product_lane,
    })
}

pub fn set_managed_session_control_state(
    state: &mut dyn StateAccess,
    parent_session_id: [u8; 32],
    managed_session_id: &str,
    requested_control_state: &str,
    reason: Option<String>,
    updated_at_ms: u64,
) -> Result<RuntimeManagedSessionControlRecord, String> {
    let managed_session_id = managed_session_id.trim();
    if managed_session_id.is_empty() {
        return Err("managed session control requires a non-empty managed_session_id".to_string());
    }
    let control_state = normalize_control_state(requested_control_state).ok_or_else(|| {
        format!("unsupported managed session control state '{requested_control_state}'")
    })?;
    let record = RuntimeManagedSessionControlRecord {
        schema_version: RUNTIME_MANAGED_SESSION_SCHEMA_VERSION.to_string(),
        parent_session_id,
        managed_session_id: managed_session_id.to_string(),
        control_state: control_state.to_string(),
        requested_by: "operator".to_string(),
        reason: reason
            .map(|value| compact_text(&value, PRODUCT_TEXT_MAX_CHARS))
            .filter(|value| !value.is_empty()),
        updated_at_ms,
    };
    let bytes = codec::to_bytes_canonical(&record)
        .map_err(|error| format!("failed to encode managed session control record: {error}"))?;
    state
        .insert(
            &get_managed_session_control_key(&parent_session_id, managed_session_id),
            &bytes,
        )
        .map_err(|error| format!("failed to persist managed session control record: {error}"))?;
    Ok(record)
}

fn managed_sessions_from_parent_playbooks(
    state: &dyn StateAccess,
    parent_state: &AgentState,
) -> Result<Vec<RuntimeManagedSessionCard>, String> {
    let mut sessions = Vec::new();
    for playbook in builtin_agent_playbooks() {
        if playbook_decision_record(&playbook.playbook_id).route_family != "computer_use" {
            continue;
        }
        let Some(run) = load_optional_state::<ParentPlaybookRun>(
            state,
            &get_parent_playbook_run_key(&parent_state.session_id, &playbook.playbook_id),
            "managed session parent playbook",
        )?
        else {
            continue;
        };
        for step in &run.steps {
            if !step_has_computer_use_signal(step) {
                continue;
            }
            let id = managed_session_id_for_step(&run, step);
            let control_state = load_control_state(state, parent_state.session_id, &id)?;
            let kind = session_kind_for_step(step, parent_state);
            let status = session_status_for_step(step);
            let waiting_reason = waiting_reason_for_step(step, parent_state);
            let waiting_for_user = waiting_reason.is_some() || status == "waiting_for_user";
            let detail = detail_for_step(step);
            sessions.push(RuntimeManagedSessionCard {
                id,
                kind: kind.to_string(),
                surface_label: surface_label(kind).to_string(),
                status: if waiting_for_user {
                    "waiting_for_user".to_string()
                } else {
                    status.to_string()
                },
                status_label: status_label(if waiting_for_user {
                    "waiting_for_user"
                } else {
                    status
                })
                .to_string(),
                control_state,
                available_control_states: available_control_states(),
                waiting_for_user,
                waiting_reason,
                parent_playbook_id: Some(run.playbook_id.clone()),
                parent_playbook_label: Some(run.playbook_label.clone()),
                step_id: Some(step.step_id.clone()),
                step_label: Some(step.label.clone()),
                child_session_id: step.child_session_id.map(hex::encode),
                page_title: None,
                target: step
                    .computer_use_perception
                    .as_ref()
                    .and_then(|summary| summary.target.clone())
                    .or_else(|| {
                        step.computer_use_verification
                            .as_ref()
                            .and_then(|scorecard| scorecard.observed_postcondition.clone())
                    })
                    .map(|value| compact_text(&value, PRODUCT_TEXT_MAX_CHARS)),
                detail,
                last_tool: Some("browser__subagent".to_string()),
                action_count: action_count_for_step(step),
                screenshot_persistence: screenshot_persistence_for_step(step),
                replay_ready: step.child_session_id.is_some() || step.completed_at_ms.is_some(),
                trace_visibility: RUNS_TRACING_VISIBILITY.to_string(),
            });
        }
    }
    Ok(sessions)
}

fn managed_sessions_from_agent_state(
    state: &dyn StateAccess,
    parent_state: &AgentState,
) -> Result<Vec<RuntimeManagedSessionCard>, String> {
    let mut sessions = Vec::new();
    let browser_signal = parent_state
        .last_action_type
        .as_deref()
        .filter(|value| value.trim_start().starts_with("browser__"))
        .or_else(|| {
            parent_state
                .pending_tool_call
                .as_deref()
                .filter(|value| value.contains("browser__"))
        });
    let Some(signal) = browser_signal else {
        return Ok(sessions);
    };
    let id = format!(
        "sandbox-browser:{}:{}",
        hex::encode(parent_state.session_id),
        parent_state.step_count
    );
    let control_state = load_control_state(state, parent_state.session_id, &id)?;
    let waiting_reason = waiting_reason_for_parent_state(parent_state);
    let waiting_for_user = waiting_reason.is_some();
    sessions.push(RuntimeManagedSessionCard {
        id,
        kind: "sandbox_browser".to_string(),
        surface_label: "Sandbox browser".to_string(),
        status: if waiting_for_user {
            "waiting_for_user".to_string()
        } else if matches!(parent_state.status, AgentStatus::Running) {
            "browsing".to_string()
        } else {
            "complete".to_string()
        },
        status_label: if waiting_for_user {
            "Waiting for user".to_string()
        } else if matches!(parent_state.status, AgentStatus::Running) {
            "Browsing".to_string()
        } else {
            "Complete".to_string()
        },
        control_state,
        available_control_states: available_control_states(),
        waiting_for_user,
        waiting_reason,
        parent_playbook_id: None,
        parent_playbook_label: None,
        step_id: None,
        step_label: None,
        child_session_id: None,
        page_title: None,
        target: None,
        detail: compact_text(signal, PRODUCT_TEXT_MAX_CHARS),
        last_tool: parent_state.last_action_type.clone(),
        action_count: browser_action_count(parent_state),
        screenshot_persistence: RuntimeScreenshotPersistenceSnapshot {
            state: "quarantined".to_string(),
            sanitized_preview_ref: None,
            raw_capture_visibility: RUNS_TRACING_VISIBILITY.to_string(),
            redaction_required_before_product: true,
        },
        replay_ready: true,
        trace_visibility: RUNS_TRACING_VISIBILITY.to_string(),
    });
    Ok(sessions)
}

fn load_control_state(
    state: &dyn StateAccess,
    parent_session_id: [u8; 32],
    managed_session_id: &str,
) -> Result<String, String> {
    let Some(record) = load_optional_state::<RuntimeManagedSessionControlRecord>(
        state,
        &get_managed_session_control_key(&parent_session_id, managed_session_id),
        "managed session control record",
    )?
    else {
        return Ok("observe".to_string());
    };
    Ok(normalize_control_state(&record.control_state)
        .unwrap_or("observe")
        .to_string())
}

fn normalize_control_state(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "observe" | "expanded_observe" | "watch" => Some("observe"),
        "take_over" | "takeover" | "user_control" => Some("take_over"),
        "return_agent" | "return_to_agent" | "agent_control" => Some("return_agent"),
        _ => None,
    }
}

fn available_control_states() -> Vec<String> {
    ["observe", "take_over", "return_agent"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn step_has_computer_use_signal(step: &ParentPlaybookStepRun) -> bool {
    step.computer_use_perception.is_some()
        || step.computer_use_verification.is_some()
        || step.computer_use_recovery.is_some()
        || contains_computer_use_text(&step.label)
        || contains_computer_use_text(&step.summary)
        || step
            .workflow_id
            .as_deref()
            .map(contains_computer_use_text)
            .unwrap_or(false)
        || step
            .template_id
            .as_deref()
            .map(contains_computer_use_text)
            .unwrap_or(false)
}

fn contains_computer_use_text(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("browser")
        || normalized.contains("gui")
        || normalized.contains("desktop")
        || normalized.contains("computer")
}

fn managed_session_id_for_step(run: &ParentPlaybookRun, step: &ParentPlaybookStepRun) -> String {
    if let Some(child_session_id) = step.child_session_id {
        return format!(
            "managed:{}:{}",
            run.playbook_id,
            hex::encode(child_session_id)
        );
    }
    format!("managed:{}:{}", run.playbook_id, step.step_id)
}

fn session_kind_for_step(step: &ParentPlaybookStepRun, parent_state: &AgentState) -> &'static str {
    let haystack = format!(
        "{} {} {} {}",
        step.label,
        step.summary,
        step.workflow_id.as_deref().unwrap_or_default(),
        parent_state.last_action_type.as_deref().unwrap_or_default()
    )
    .to_ascii_lowercase();
    if haystack.contains("desktop") || haystack.contains("screen__") || haystack.contains("gui") {
        "desktop"
    } else if haystack.contains("local browser") || haystack.contains("host browser") {
        "local_browser"
    } else {
        "sandbox_browser"
    }
}

fn surface_label(kind: &str) -> &'static str {
    match kind {
        "desktop" => "Desktop",
        "local_browser" => "Local browser",
        _ => "Sandbox browser",
    }
}

fn session_status_for_step(step: &ParentPlaybookStepRun) -> &'static str {
    match step.status.as_label() {
        "running" => "browsing",
        "blocked" | "failed" => "needs_user",
        "pending" => "hidden_background",
        _ => "complete",
    }
}

fn status_label(status: &str) -> &'static str {
    match status {
        "browsing" => "Browsing",
        "waiting_for_user" => "Waiting for user",
        "needs_user" => "Needs user",
        "hidden_background" => "Hidden/background",
        _ => "Complete",
    }
}

fn waiting_reason_for_step(
    step: &ParentPlaybookStepRun,
    parent_state: &AgentState,
) -> Option<String> {
    waiting_reason_for_perception(step.computer_use_perception.as_ref())
        .or_else(|| waiting_reason_for_verification(step.computer_use_verification.as_ref()))
        .or_else(|| waiting_reason_for_recovery(step.computer_use_recovery.as_ref()))
        .or_else(|| waiting_reason_for_parent_state(parent_state))
}

fn waiting_reason_for_perception(summary: Option<&ComputerUsePerceptionSummary>) -> Option<String> {
    let summary = summary?;
    let text = [
        summary.approval_risk.as_str(),
        summary.notes.as_deref().unwrap_or_default(),
        summary.next_action.as_deref().unwrap_or_default(),
    ]
    .join(" ");
    manual_wait_reason(&text)
}

fn waiting_reason_for_verification(
    scorecard: Option<&ComputerUseVerificationScorecard>,
) -> Option<String> {
    let scorecard = scorecard?;
    let text = [
        scorecard.approval_state.as_str(),
        scorecard.recovery_status.as_str(),
        scorecard.notes.as_deref().unwrap_or_default(),
        scorecard
            .observed_postcondition
            .as_deref()
            .unwrap_or_default(),
    ]
    .join(" ");
    manual_wait_reason(&text)
}

fn waiting_reason_for_recovery(summary: Option<&ComputerUseRecoverySummary>) -> Option<String> {
    let summary = summary?;
    let text = [
        summary.status.as_str(),
        summary.reason.as_deref().unwrap_or_default(),
        summary.next_step.as_deref().unwrap_or_default(),
    ]
    .join(" ");
    manual_wait_reason(&text)
}

fn waiting_reason_for_parent_state(parent_state: &AgentState) -> Option<String> {
    match parent_state.pause_reason() {
        Some(reason) => manual_wait_reason(&reason.message()),
        None => None,
    }
}

fn manual_wait_reason(value: &str) -> Option<String> {
    let normalized = value.to_ascii_lowercase();
    let reason = if normalized.contains("captcha") {
        "captcha"
    } else if normalized.contains("login") || normalized.contains("sign in") {
        "login"
    } else if normalized.contains("payment") || normalized.contains("checkout") {
        "payment"
    } else if normalized.contains("file picker") || normalized.contains("file chooser") {
        "file_picker"
    } else if normalized.contains("manual")
        || normalized.contains("human")
        || normalized.contains("waiting for user")
        || normalized.contains("approval")
    {
        "manual_action"
    } else {
        return None;
    };
    Some(reason.to_string())
}

fn detail_for_step(step: &ParentPlaybookStepRun) -> String {
    let detail = step
        .computer_use_verification
        .as_ref()
        .and_then(|scorecard| scorecard.observed_postcondition.clone())
        .or_else(|| {
            step.computer_use_perception
                .as_ref()
                .map(|summary| summary.ui_state.clone())
        })
        .or_else(|| step.output_preview.clone())
        .or_else(|| Some(step.summary.clone()))
        .unwrap_or_else(|| "Managed browser session".to_string());
    compact_text(&detail, PRODUCT_TEXT_MAX_CHARS)
}

fn action_count_for_step(step: &ParentPlaybookStepRun) -> u32 {
    let mut count = 0u32;
    if step.computer_use_perception.is_some() {
        count = count.saturating_add(1);
    }
    if step.computer_use_verification.is_some() {
        count = count.saturating_add(1);
    }
    if step.computer_use_recovery.is_some() {
        count = count.saturating_add(1);
    }
    count.max(1)
}

fn browser_action_count(parent_state: &AgentState) -> u32 {
    let count = parent_state
        .recent_actions
        .iter()
        .filter(|action| action.contains("browser__"))
        .count()
        + parent_state
            .tool_execution_log
            .iter()
            .filter(|(key, status)| {
                key.contains("browser__")
                    || matches!(status, ToolCallStatus::Executed(value) if value.contains("browser__"))
            })
            .count();
    count.max(1) as u32
}

fn screenshot_persistence_for_step(
    step: &ParentPlaybookStepRun,
) -> RuntimeScreenshotPersistenceSnapshot {
    let sanitized_preview_ref = step
        .output_preview
        .as_deref()
        .and_then(extract_sanitized_screenshot_ref);
    RuntimeScreenshotPersistenceSnapshot {
        state: if sanitized_preview_ref.is_some() {
            "sanitized_preview_persisted".to_string()
        } else {
            "quarantined".to_string()
        },
        sanitized_preview_ref,
        raw_capture_visibility: RUNS_TRACING_VISIBILITY.to_string(),
        redaction_required_before_product: true,
    }
}

fn extract_sanitized_screenshot_ref(value: &str) -> Option<String> {
    value
        .split_whitespace()
        .find_map(|segment| {
            segment
                .strip_prefix("sanitized_screenshot_ref=")
                .or_else(|| segment.strip_prefix("preview_ref="))
        })
        .map(|value| value.trim_matches(|ch| ch == ',' || ch == ';').to_string())
        .filter(|value| !value.is_empty())
}

fn dedupe_sessions(sessions: &mut Vec<RuntimeManagedSessionCard>) {
    let mut seen = BTreeSet::new();
    sessions.retain(|session| seen.insert(session.id.clone()));
}

fn product_lane_entry_for_session(
    session: &RuntimeManagedSessionCard,
) -> RuntimeManagedSessionProductLaneEntry {
    RuntimeManagedSessionProductLaneEntry {
        kind: "managed_session".to_string(),
        label: session.surface_label.clone(),
        status: session.status.clone(),
        session_id: session.id.clone(),
        summary: session.detail.clone(),
        detail_visibility: RUNS_TRACING_VISIBILITY.to_string(),
    }
}

fn compact_text(value: &str, max_chars: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        return compact;
    }
    let mut trimmed = compact
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    trimmed.push('…');
    trimmed
}

fn load_optional_state<T: Decode>(
    state: &dyn StateAccess,
    key: &[u8],
    label: &str,
) -> Result<Option<T>, String> {
    let Some(bytes) = state
        .get(key)
        .map_err(|error| format!("Failed to read {label}: {error}"))?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical::<T>(&bytes)
        .map(Some)
        .map_err(|error| format!("Failed to decode {label}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::keys::get_parent_playbook_run_key;
    use crate::agentic::runtime::types::{
        AgentMode, ExecutionLedger, ExecutionTier, ParentPlaybookStatus, ParentPlaybookStepStatus,
        PendingSearchCompletion, PlannerState, WorkGraphContext,
    };
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;
    use std::collections::{BTreeMap, VecDeque};

    fn parent_state() -> AgentState {
        AgentState {
            session_id: [0x38; 32],
            goal: "Inspect browser fixture".to_string(),
            runtime_route_frame: None,
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 2,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: Vec::new(),
            budget: 10,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: Vec::new(),
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: Vec::new(),
            pending_search_completion: Option::<PendingSearchCompletion>::None,
            planner_state: Option::<PlannerState>::None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            execution_ledger: ExecutionLedger::default(),
            visual_som_map: None,
            visual_semantic_map: None,
            work_graph_context: Option::<WorkGraphContext>::None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    fn persist_playbook(state: &mut dyn StateAccess, parent: &AgentState, run: &ParentPlaybookRun) {
        let bytes = codec::to_bytes_canonical(run).expect("playbook encodes");
        state
            .insert(
                &get_parent_playbook_run_key(&parent.session_id, &run.playbook_id),
                &bytes,
            )
            .expect("playbook persists");
    }

    #[test]
    fn managed_session_snapshot_reports_waiting_user_state_and_quarantines_screenshot() {
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let parent = parent_state();
        let run = ParentPlaybookRun {
            parent_session_id: parent.session_id,
            playbook_id: "browser_postcondition_gate".to_string(),
            playbook_label: "Browser Postcondition Gate".to_string(),
            topic: "login fixture".to_string(),
            status: ParentPlaybookStatus::Blocked,
            current_step_index: 1,
            active_child_session_id: Some([0x44; 32]),
            started_at_ms: 1,
            updated_at_ms: 2,
            completed_at_ms: None,
            steps: vec![ParentPlaybookStepRun {
                step_id: "execute".to_string(),
                label: "Execute in browser".to_string(),
                summary: "Use grounded browser tools".to_string(),
                status: ParentPlaybookStepStatus::Blocked,
                child_session_id: Some([0x44; 32]),
                template_id: Some("browser_operator".to_string()),
                workflow_id: Some("browser_postcondition_pass".to_string()),
                computer_use_perception: Some(ComputerUsePerceptionSummary {
                    surface_status: "clear".to_string(),
                    ui_state: "Login page is visible".to_string(),
                    target: Some("login form".to_string()),
                    approval_risk: "manual login required".to_string(),
                    next_action: Some("wait for user".to_string()),
                    notes: Some("login is user-only".to_string()),
                }),
                computer_use_verification: Some(ComputerUseVerificationScorecard {
                    verdict: "blocked".to_string(),
                    postcondition_status: "not_met".to_string(),
                    approval_state: "waiting for user".to_string(),
                    recovery_status: "manual login required".to_string(),
                    observed_postcondition: Some("Login gate visible".to_string()),
                    notes: None,
                }),
                output_preview: Some("raw screenshot retained in tracing".to_string()),
                ..Default::default()
            }],
        };
        persist_playbook(&mut state, &parent, &run);

        let snapshot = managed_session_snapshot_for_state(&state, &parent).expect("snapshot");

        assert_eq!(snapshot.session_count, 1);
        let card = &snapshot.sessions[0];
        assert_eq!(card.kind, "sandbox_browser");
        assert_eq!(card.status, "waiting_for_user");
        assert_eq!(card.waiting_reason.as_deref(), Some("login"));
        assert_eq!(card.control_state, "observe");
        assert!(card
            .available_control_states
            .iter()
            .any(|state| state == "take_over"));
        assert_eq!(card.screenshot_persistence.state, "quarantined");
        assert_eq!(
            card.screenshot_persistence.raw_capture_visibility,
            "runs_tracing"
        );
        assert!(snapshot.replay.waiting_session_ids.contains(&card.id));
    }

    #[test]
    fn managed_session_control_state_round_trips_through_snapshot() {
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let parent = parent_state();
        let run = ParentPlaybookRun {
            parent_session_id: parent.session_id,
            playbook_id: "browser_postcondition_gate".to_string(),
            playbook_label: "Browser Postcondition Gate".to_string(),
            topic: "browser fixture".to_string(),
            status: ParentPlaybookStatus::Running,
            current_step_index: 1,
            active_child_session_id: Some([0x45; 32]),
            started_at_ms: 1,
            updated_at_ms: 2,
            completed_at_ms: None,
            steps: vec![ParentPlaybookStepRun {
                step_id: "execute".to_string(),
                label: "Execute in browser".to_string(),
                summary: "Use grounded browser tools".to_string(),
                status: ParentPlaybookStepStatus::Running,
                child_session_id: Some([0x45; 32]),
                template_id: Some("browser_operator".to_string()),
                workflow_id: Some("browser_postcondition_pass".to_string()),
                computer_use_perception: Some(ComputerUsePerceptionSummary {
                    surface_status: "clear".to_string(),
                    ui_state: "Fixture page is visible".to_string(),
                    target: Some("fixture".to_string()),
                    approval_risk: "low".to_string(),
                    next_action: Some("inspect".to_string()),
                    notes: None,
                }),
                output_preview: Some("sanitized_screenshot_ref=preview://fixture".to_string()),
                ..Default::default()
            }],
        };
        let managed_id = managed_session_id_for_step(&run, &run.steps[0]);
        persist_playbook(&mut state, &parent, &run);
        let control = set_managed_session_control_state(
            &mut state,
            parent.session_id,
            &managed_id,
            "take_over",
            Some("operator wants to inspect".to_string()),
            99,
        )
        .expect("control persists");
        assert_eq!(control.control_state, "take_over");

        let snapshot = managed_session_snapshot_for_state(&state, &parent).expect("snapshot");

        let card = &snapshot.sessions[0];
        assert_eq!(card.control_state, "take_over");
        assert_eq!(
            card.screenshot_persistence.sanitized_preview_ref.as_deref(),
            Some("preview://fixture")
        );
        assert!(snapshot.replay.replayable_session_ids.contains(&card.id));
    }

    #[test]
    fn standalone_browser_tool_state_projects_managed_session_without_raw_payloads() {
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent = parent_state();
        parent.last_action_type = Some("browser__inspect".to_string());
        parent.recent_actions = vec!["browser__inspect completed".to_string()];

        let snapshot = managed_session_snapshot_for_state(&state, &parent).expect("snapshot");

        assert_eq!(snapshot.session_count, 1);
        let card = &snapshot.sessions[0];
        assert_eq!(card.kind, "sandbox_browser");
        assert_eq!(card.last_tool.as_deref(), Some("browser__inspect"));
        assert!(!card.detail.contains('{'));
        assert_eq!(card.trace_visibility, "runs_tracing");
        assert_eq!(
            set_managed_session_control_state(
                &mut state,
                parent.session_id,
                &card.id,
                "return_to_agent",
                None,
                101,
            )
            .expect("return control persists")
            .control_state,
            "return_agent"
        );
    }
}
