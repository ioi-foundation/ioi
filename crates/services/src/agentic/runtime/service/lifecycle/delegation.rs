use crate::agentic::runtime::keys::{
    get_incident_key, get_remediation_key, get_state_key, AGENT_POLICY_PREFIX,
};
use crate::agentic::runtime::service::step::signals::infer_interaction_target;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, SessionSummary, WorkerAssignment,
};
use crate::agentic::runtime::utils::{persist_agent_state, timestamp_ms_now};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::KernelEvent;
use ioi_types::codec;
use ioi_types::error::TransactionError;

mod bootstrap;
mod goal;
mod prep;

use self::bootstrap::{
    delegated_child_preset_resolved_intent, seed_delegated_child_execution_queue,
};
use self::goal::{
    enrich_delegated_child_goal, enrich_delegated_child_goal_with_prep,
    infer_delegated_child_working_directory, resolve_worker_name, resolve_worker_role,
};
use self::prep::build_delegated_child_prep_bundle;
pub(crate) use self::prep::DelegatedChildPrepBundle;

use super::{
    load_worker_assignment, persist_worker_assignment, register_parent_playbook_step_spawn,
    resolve_worker_assignment,
};

#[derive(Debug, Clone)]
pub struct DelegatedChildSpawnOutcome {
    pub child_session_id: [u8; 32],
    pub assignment: WorkerAssignment,
}

pub async fn spawn_delegated_child_session(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    tool_hash: [u8; 32],
    goal: &str,
    budget: u64,
    playbook_id: Option<&str>,
    template_id: Option<&str>,
    workflow_id: Option<&str>,
    requested_role: Option<&str>,
    success_criteria: Option<&str>,
    merge_mode: Option<&str>,
    expected_output: Option<&str>,
    step_index: u32,
    block_height: u64,
) -> Result<DelegatedChildSpawnOutcome, TransactionError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"ioi::agent_delegate_child::v1::");
    payload.extend_from_slice(parent_state.session_id.as_slice());
    payload.extend_from_slice(&step_index.to_le_bytes());
    payload.extend_from_slice(tool_hash.as_slice());

    let child_session_id = sha256(payload)
        .map_err(|e| TransactionError::Invalid(format!("Delegate hash failed: {}", e)))?;

    let child_key = get_state_key(&child_session_id);
    if state.get(&child_key)?.is_some() {
        if parent_state.child_session_ids.contains(&child_session_id) {
            let assignment = load_worker_assignment(state, child_session_id)
                .map_err(TransactionError::Invalid)?
                .ok_or_else(|| {
                    TransactionError::Invalid(format!(
                        "ERROR_CLASS=UnexpectedState Delegated child session {} exists without a worker assignment artifact.",
                        hex::encode(child_session_id)
                    ))
                })?;
            return Ok(DelegatedChildSpawnOutcome {
                child_session_id,
                assignment,
            });
        }

        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=UnexpectedState Delegated child session {} already exists but is not linked to parent session {}.",
            hex::encode(child_session_id),
            hex::encode(parent_state.session_id)
        )));
    }

    let enriched_goal = enrich_delegated_child_goal(&parent_state.goal, goal, workflow_id);
    let mut assignment = resolve_worker_assignment(
        child_session_id,
        step_index,
        budget,
        &enriched_goal,
        playbook_id,
        template_id,
        workflow_id,
        requested_role,
        success_criteria,
        merge_mode,
        expected_output,
    );

    if parent_state.budget < assignment.budget {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=UnexpectedState Insufficient parent budget for delegation (needed {}, have {}).",
            assignment.budget, parent_state.budget
        )));
    }

    let prep_bundle = build_delegated_child_prep_bundle(
        service,
        state,
        parent_state.session_id,
        step_index,
        &assignment,
    )
    .await;
    assignment.goal = enrich_delegated_child_goal_with_prep(
        &parent_state.goal,
        &assignment.goal,
        assignment.workflow_id.as_deref(),
        &prep_bundle,
    );

    let target = infer_interaction_target(&assignment.goal);

    // Initialize transcript before mutating chain state so failures do not burn budget.
    let timestamp_ms = timestamp_ms_now();
    let initial_message = ioi_types::app::agentic::ChatMessage {
        role: "user".to_string(),
        content: assignment.goal.clone(),
        timestamp: timestamp_ms,
        trace_hash: None,
    };
    let transcript_root = service
        .append_chat_to_scs(child_session_id, &initial_message, block_height)
        .await?;

    // Ensure stale remediation/incident metadata cannot leak across deterministic child ids.
    state.delete(&get_remediation_key(&child_session_id))?;
    state.delete(&get_incident_key(&child_session_id))?;

    let child_state = AgentState {
        session_id: child_session_id,
        goal: assignment.goal.clone(),
        transcript_root,
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: parent_state.max_steps,
        last_action_type: None,
        parent_session_id: Some(parent_state.session_id),
        child_session_ids: Vec::new(),
        budget: assignment.budget,
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
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target,
        resolved_intent: delegated_child_preset_resolved_intent(&assignment),
        awaiting_intent_clarification: false,
        working_directory: infer_delegated_child_working_directory(
            &parent_state.working_directory,
            &assignment.goal,
        ),
        command_history: Default::default(),
        active_lens: None,
    };
    let mut child_state = child_state;
    seed_delegated_child_execution_queue(&mut child_state, child_session_id, &assignment)?;

    persist_agent_state(
        state,
        &child_key,
        &child_state,
        service.memory_runtime.as_ref(),
    )?;
    let parent_policy_key = [AGENT_POLICY_PREFIX, parent_state.session_id.as_slice()].concat();
    let child_policy_key = [AGENT_POLICY_PREFIX, child_session_id.as_slice()].concat();
    if let Some(policy_bytes) = state.get(&parent_policy_key)? {
        state.insert(&child_policy_key, &policy_bytes)?;
    }
    persist_worker_assignment(state, child_session_id, &assignment)?;

    // Update session history if present; best-effort to avoid blocking delegation on history corruption.
    let history_key = b"agent::history".to_vec();
    let mut history: Vec<SessionSummary> = state
        .get(&history_key)?
        .and_then(|bytes| codec::from_bytes_canonical(&bytes).ok())
        .unwrap_or_default();

    let title_line = assignment.goal.lines().next().unwrap_or("Agent Task");
    let title = if title_line.len() > 30 {
        format!("{}...", &title_line[..30])
    } else {
        title_line.to_string()
    };
    history.insert(
        0,
        SessionSummary {
            session_id: child_session_id,
            title,
            timestamp: timestamp_ms,
        },
    );
    if history.len() > 50 {
        history.truncate(50);
    }

    if let Ok(bytes) = codec::to_bytes_canonical(&history) {
        if let Err(e) = state.insert(&history_key, &bytes) {
            log::warn!(
                "Failed to update agent::history for delegated child session {}: {}",
                hex::encode(&child_session_id[..4]),
                e
            );
        }
    }

    parent_state.budget -= assignment.budget;
    parent_state.child_session_ids.push(child_session_id);
    register_parent_playbook_step_spawn(
        service,
        state,
        parent_state,
        step_index,
        child_session_id,
        &assignment,
        &prep_bundle,
    )
    .map_err(TransactionError::Invalid)?;

    if let Some(tx) = &service.event_sender {
        let resolved_role = resolve_worker_role(template_id, requested_role);
        let _ = tx.send(KernelEvent::AgentSpawn {
            parent_session_id: parent_state.session_id,
            new_session_id: child_session_id,
            name: resolve_worker_name(&resolved_role, &child_session_id),
            role: resolved_role,
            budget: assignment.budget,
            goal: assignment.goal.clone(),
        });
    }

    Ok(DelegatedChildSpawnOutcome {
        child_session_id,
        assignment,
    })
}

#[cfg(test)]
mod tests;
