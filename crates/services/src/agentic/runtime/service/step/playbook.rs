use crate::agentic::runtime::agent_playbooks::builtin_agent_playbook;
use crate::agentic::runtime::keys::{get_parent_playbook_run_key, get_state_key};
use crate::agentic::runtime::types::{AgentState, AgentStatus, ParentPlaybookRun};
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::ResolvedIntentState;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::json;

fn instruction_contract_slot_value<'a>(
    resolved: &'a ResolvedIntentState,
    slot_name: &str,
) -> Option<&'a str> {
    resolved
        .instruction_contract
        .as_ref()?
        .slot_bindings
        .iter()
        .find(|binding| binding.slot.trim().eq_ignore_ascii_case(slot_name))
        .and_then(|binding| binding.value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn root_playbook_run_exists(
    state: &dyn StateAccess,
    agent_state: &AgentState,
    resolved: &ResolvedIntentState,
) -> bool {
    let Some(playbook_id) = instruction_contract_slot_value(resolved, "playbook_id") else {
        return false;
    };
    let key = get_parent_playbook_run_key(&agent_state.session_id, playbook_id);
    state.get(&key).ok().flatten().is_some()
}

fn latest_root_playbook_child_session_id(
    state: &dyn StateAccess,
    agent_state: &AgentState,
) -> Option<[u8; 32]> {
    agent_state
        .child_session_ids
        .iter()
        .rev()
        .copied()
        .find(|child_session_id| {
            let key = get_state_key(child_session_id);
            state
                .get(&key)
                .ok()
                .flatten()
                .and_then(|bytes| codec::from_bytes_canonical::<AgentState>(&bytes).ok())
                .map(|child_state| {
                    child_state.parent_session_id == Some(agent_state.session_id)
                        && child_state.status == AgentStatus::Running
                })
                .unwrap_or(false)
        })
}

pub(super) fn queue_root_playbook_delegate_request(
    state: &dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
) -> Result<bool, TransactionError> {
    let Some(resolved) = agent_state.resolved_intent.as_ref() else {
        return Ok(false);
    };
    if resolved
        .intent_id
        .trim()
        .eq_ignore_ascii_case("delegation.task")
        || agent_state.parent_session_id.is_some()
    {
        return Ok(false);
    }

    let Some(playbook_id) = instruction_contract_slot_value(resolved, "playbook_id") else {
        return Ok(false);
    };
    if builtin_agent_playbook(Some(playbook_id)).is_none()
        || root_playbook_run_exists(state, agent_state, resolved)
        || latest_root_playbook_child_session_id(state, agent_state).is_some()
    {
        return Ok(false);
    }

    let params = serde_jcs::to_vec(&json!({
        "goal": agent_state.goal,
        "budget": 0,
        "playbook_id": playbook_id,
        "template_id": instruction_contract_slot_value(resolved, "template_id"),
        "workflow_id": instruction_contract_slot_value(resolved, "workflow_id"),
        "role": serde_json::Value::Null,
        "success_criteria": serde_json::Value::Null,
        "merge_mode": serde_json::Value::Null,
        "expected_output": serde_json::Value::Null,
    }))
    .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target: ActionTarget::Custom("agent__delegate".to_string()),
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1,
    };
    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return Ok(false);
    }

    agent_state.execution_queue.push(request);
    Ok(true)
}

fn active_parent_playbook_child_session_id(
    state: &dyn StateAccess,
    agent_state: &AgentState,
) -> Option<[u8; 32]> {
    let resolved = agent_state.resolved_intent.as_ref()?;
    if resolved
        .intent_id
        .trim()
        .eq_ignore_ascii_case("delegation.task")
    {
        return None;
    }

    let playbook_id = instruction_contract_slot_value(resolved, "playbook_id")?;
    let key = get_parent_playbook_run_key(&agent_state.session_id, playbook_id);
    state
        .get(&key)
        .ok()
        .flatten()
        .and_then(|bytes| codec::from_bytes_canonical::<ParentPlaybookRun>(&bytes).ok())
        .and_then(|run| run.active_child_session_id)
        .or_else(|| latest_root_playbook_child_session_id(state, agent_state))
}

fn child_immediate_progress_await_eligible(
    state: &dyn StateAccess,
    child_session_id: [u8; 32],
) -> bool {
    let key = get_state_key(&child_session_id);
    state
        .get(&key)
        .ok()
        .flatten()
        .and_then(|bytes| codec::from_bytes_canonical::<AgentState>(&bytes).ok())
        .map(|_| true)
        .unwrap_or(false)
}

pub(super) fn queue_parent_playbook_await_request(
    state: &dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
) -> Result<bool, TransactionError> {
    let Some(child_session_id) = active_parent_playbook_child_session_id(state, agent_state) else {
        return Ok(false);
    };
    if !child_immediate_progress_await_eligible(state, child_session_id) {
        return Ok(false);
    }

    let params = serde_jcs::to_vec(&json!({
        "child_session_id_hex": hex::encode(child_session_id),
    }))
    .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target: ActionTarget::Custom("agent__await".to_string()),
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1,
    };
    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return Ok(false);
    }

    agent_state.execution_queue.push(request);
    Ok(true)
}
