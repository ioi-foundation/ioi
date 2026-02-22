use crate::agentic::desktop::keys::{get_incident_key, get_remediation_key, get_state_key};
use crate::agentic::desktop::service::step::signals::infer_interaction_target;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, SessionSummary,
};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::KernelEvent;
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn spawn_delegated_child_session(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    tool_hash: [u8; 32],
    goal: &str,
    budget: u64,
    step_index: u32,
    block_height: u64,
) -> Result<[u8; 32], TransactionError> {
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
            return Ok(child_session_id);
        }

        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=UnexpectedState Delegated child session {} already exists but is not linked to parent session {}.",
            hex::encode(child_session_id),
            hex::encode(parent_state.session_id)
        )));
    }

    if parent_state.budget < budget {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=UnexpectedState Insufficient parent budget for delegation (needed {}, have {}).",
            budget, parent_state.budget
        )));
    }

    let target = infer_interaction_target(goal);

    // Initialize transcript BEFORE mutating chain state so failures do not burn budget.
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let initial_message = ioi_types::app::agentic::ChatMessage {
        role: "user".to_string(),
        content: goal.to_string(),
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
        goal: goal.to_string(),
        transcript_root,
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: parent_state.max_steps,
        last_action_type: None,
        parent_session_id: Some(parent_state.session_id),
        child_session_ids: Vec::new(),
        budget,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_visual_hash: None,
        recent_actions: Vec::new(),
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: Vec::new(),
        pending_search_completion: None,
        active_skill_hash: None,
        tool_execution_log: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
    };

    state.insert(&child_key, &codec::to_bytes_canonical(&child_state)?)?;

    // Update session history if present; best-effort to avoid blocking delegation on history corruption.
    let history_key = b"agent::history".to_vec();
    let mut history: Vec<SessionSummary> = state
        .get(&history_key)?
        .and_then(|bytes| codec::from_bytes_canonical(&bytes).ok())
        .unwrap_or_default();

    let title_line = goal.lines().next().unwrap_or("Agent Task");
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

    parent_state.budget -= budget;
    parent_state.child_session_ids.push(child_session_id);

    if let Some(tx) = &service.event_sender {
        let _ = tx.send(KernelEvent::AgentSpawn {
            parent_session_id: parent_state.session_id,
            new_session_id: child_session_id,
            name: format!("Agent-{}", hex::encode(&child_session_id[0..2])),
            role: "Sub-Worker".to_string(),
            budget,
            goal: goal.to_string(),
        });
    }

    Ok(child_session_id)
}
