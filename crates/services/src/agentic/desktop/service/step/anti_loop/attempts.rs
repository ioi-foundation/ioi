use super::model::{
    tier_as_str, AttemptKey, FailureClass, RETRY_GUARD_REPEAT_LIMIT, RETRY_GUARD_WINDOW,
};
use crate::agentic::desktop::types::{AgentState, ExecutionTier};
use ioi_crypto::algorithms::hash::sha256;

fn normalize_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
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
    let canonical_bytes = serde_jcs::to_vec(attempt_key).unwrap_or_else(|_| {
        format!(
            "{}::{}::{}::{}::{}",
            attempt_key.intent_hash,
            attempt_key.tier,
            attempt_key.tool_name,
            attempt_key.target_id.as_deref().unwrap_or(""),
            attempt_key.window_fingerprint.as_deref().unwrap_or("")
        )
        .into_bytes()
    });
    sha256(&canonical_bytes)
        .map(hex::encode)
        .unwrap_or_else(|_| String::new())
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
