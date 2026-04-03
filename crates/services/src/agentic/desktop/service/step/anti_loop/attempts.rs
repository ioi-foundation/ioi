use super::model::{
    tier_as_str, AttemptKey, FailureClass, RETRY_GUARD_REPEAT_LIMIT, RETRY_GUARD_WINDOW,
};
use crate::agentic::desktop::types::{AgentState, AgentStatus, ExecutionTier};
use crate::agentic::desktop::utils::load_agent_state_with_runtime_preference;
use ioi_api::state::StateAccess;
use ioi_memory::MemoryRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use std::sync::Arc;

fn normalize_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

pub fn canonical_attempt_window_fingerprint(
    failure_class: FailureClass,
    command_scope: bool,
    window_fingerprint: Option<&str>,
) -> Option<String> {
    if command_scope || matches!(failure_class, FailureClass::NoEffectAfterAction) {
        return None;
    }

    normalize_optional(window_fingerprint)
}

fn lifecycle_attempt_status_label(status: &AgentStatus) -> &'static str {
    match status {
        AgentStatus::Idle => "idle",
        AgentStatus::Running => "running",
        AgentStatus::Paused(_) => "paused",
        AgentStatus::Completed(_) => "completed",
        AgentStatus::Failed(_) => "failed",
        AgentStatus::Terminated => "terminated",
    }
}

pub fn specialized_attempt_target_id(
    state: &dyn StateAccess,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
    tool_name: &str,
    tool_jcs: Option<&[u8]>,
) -> Option<String> {
    if tool_name != "agent__await_result" {
        return None;
    }

    let AgentTool::AgentAwait {
        child_session_id_hex,
    } = serde_json::from_slice::<AgentTool>(tool_jcs?).ok()?
    else {
        return None;
    };

    let child_session_id_hex = child_session_id_hex.trim();
    if child_session_id_hex.is_empty() {
        return None;
    }

    let child_session_id = hex::decode(child_session_id_hex).ok()?;
    if child_session_id.len() != 32 {
        return Some(format!("await_child={child_session_id_hex}"));
    }

    let mut child_session_id_array = [0u8; 32];
    child_session_id_array.copy_from_slice(&child_session_id);
    let child_state = load_agent_state_with_runtime_preference(
        state,
        memory_runtime,
        child_session_id_array,
        child_session_id_hex,
    )
    .ok();

    match child_state {
        Some(child_state) => Some(format!(
            "await_child={child_session_id_hex};step={};status={}",
            child_state.step_count,
            lifecycle_attempt_status_label(&child_state.status)
        )),
        None => Some(format!("await_child={child_session_id_hex}")),
    }
}

pub fn build_attempt_key(
    intent_hash: &str,
    tier: ExecutionTier,
    tool_name: &str,
    target_id: Option<&str>,
    window_fingerprint: Option<&str>,
) -> AttemptKey {
    AttemptKey {
        intent_hash: intent_hash.to_string(),
        tier: tier_as_str(tier).to_string(),
        tool_name: tool_name.to_string(),
        target_id: normalize_optional(target_id),
        window_fingerprint: normalize_optional(window_fingerprint),
    }
}

pub fn attempt_key_hash(attempt_key: &AttemptKey) -> String {
    let canonical_bytes =
        serde_jcs::to_vec(attempt_key).expect("attempt_key_hash: JCS canonicalization failed");
    let digest = sha256(&canonical_bytes).expect("attempt_key_hash: sha256 failed");
    hex::encode(digest)
}

pub fn failure_attempt_fingerprint(failure_class: FailureClass, attempt_key_hash: &str) -> String {
    format!("attempt::{}::{}", failure_class.as_str(), attempt_key_hash)
}

pub fn register_failure_attempt(
    agent_state: &mut AgentState,
    failure_class: FailureClass,
    attempt_key: &AttemptKey,
) -> (usize, String) {
    let attempt_hash = attempt_key_hash(attempt_key);
    let fingerprint = failure_attempt_fingerprint(failure_class, &attempt_hash);
    let repeat_count = register_attempt(agent_state, fingerprint);
    (repeat_count, attempt_hash)
}

fn parse_failure_from_fingerprint(fingerprint: &str) -> Option<FailureClass> {
    let mut parts = fingerprint.split("::");
    let _scope = parts.next()?;
    let class = parts.next()?;
    FailureClass::from_str(class)
}

pub fn latest_failure_class(agent_state: &AgentState) -> Option<FailureClass> {
    agent_state
        .recent_actions
        .last()
        .and_then(|entry| parse_failure_from_fingerprint(entry))
}

pub fn trailing_repetition_count(history: &[String], fingerprint: &str) -> usize {
    history
        .iter()
        .rev()
        .take_while(|entry| entry.as_str() == fingerprint)
        .count()
}

pub fn register_attempt(agent_state: &mut AgentState, fingerprint: String) -> usize {
    agent_state.recent_actions.push(fingerprint.clone());
    if agent_state.recent_actions.len() > RETRY_GUARD_WINDOW {
        let overflow = agent_state.recent_actions.len() - RETRY_GUARD_WINDOW;
        agent_state.recent_actions.drain(0..overflow);
    }
    trailing_repetition_count(&agent_state.recent_actions, &fingerprint)
}

pub fn should_trip_retry_guard(failure_class: FailureClass, repeat_count: usize) -> bool {
    if repeat_count < RETRY_GUARD_REPEAT_LIMIT {
        return false;
    }

    !matches!(
        failure_class,
        FailureClass::PermissionOrApprovalRequired | FailureClass::UserInterventionNeeded
    )
}

pub fn should_block_retry_without_change(failure_class: FailureClass, repeat_count: usize) -> bool {
    if repeat_count <= 1 {
        return false;
    }

    !matches!(
        failure_class,
        FailureClass::PermissionOrApprovalRequired | FailureClass::UserInterventionNeeded
    )
}

pub fn retry_budget_remaining(repeat_count: usize) -> usize {
    RETRY_GUARD_REPEAT_LIMIT.saturating_sub(repeat_count)
}
