// Path: crates/services/src/agentic/desktop/service/lifecycle.rs

use super::DesktopAgentService;
use crate::agentic::desktop::keys::{get_state_key};
// [FIX] Removed unused keys
use crate::agentic::desktop::types::{
    AgentMode, AgentState, AgentStatus, PostMessageParams, ResumeAgentParams, SessionSummary, StartAgentParams,
};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::time::{SystemTime, UNIX_EPOCH};
use hex;

pub async fn handle_start(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    p: StartAgentParams,
) -> Result<(), TransactionError> {
    let key = get_state_key(&p.session_id);
    if state.get(&key)?.is_some() {
        return Err(TransactionError::Invalid("Session already exists".into()));
    }

    if let Some(parent_id) = p.parent_session_id {
        let parent_key = get_state_key(&parent_id);
        if let Some(parent_bytes) = state.get(&parent_key)? {
            let mut parent_state: AgentState = codec::from_bytes_canonical(&parent_bytes)?;
            if parent_state.budget < p.initial_budget {
                return Err(TransactionError::Invalid(
                    "Insufficient parent budget".into(),
                ));
            }
            parent_state.budget -= p.initial_budget;
            parent_state.child_session_ids.push(p.session_id);
            state.insert(&parent_key, &codec::to_bytes_canonical(&parent_state)?)?;
        } else {
            return Err(TransactionError::Invalid("Parent session not found".into()));
        }
    }

    // Initialize with structured User Prompt in SCS
    let initial_message = ioi_types::app::agentic::ChatMessage {
        role: "user".to_string(),
        content: p.goal.clone(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        trace_hash: None,
    };

    // [FIX] Await async call
    let root_hash = service.append_chat_to_scs(
        p.session_id, 
        &initial_message, 
        0 // block height usually not available in handle_start unless passed in
    ).await?;

    let agent_state = AgentState {
        session_id: p.session_id,
        goal: p.goal.clone(),
        // [FIX] Use transcript_root
        transcript_root: root_hash,
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: p.max_steps,
        last_action_type: None,
        parent_session_id: p.parent_session_id,
        child_session_ids: Vec::new(),
        budget: p.initial_budget,
        consecutive_failures: 0,
        tokens_used: 0,
        pending_approval: None,
        pending_tool_call: None,
        recent_actions: Vec::new(),
        mode: p.mode,
        // [FIX] Initialize last_screen_phash
        last_screen_phash: None,
    };
    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    // Update Global History Index
    let history_key = b"agent::history".to_vec();
    let mut history: Vec<SessionSummary> = if let Some(bytes) = state.get(&history_key)? {
        codec::from_bytes_canonical(&bytes).unwrap_or_default()
    } else {
        Vec::new()
    };

    // Prepend new session (newest first)
    history.insert(
        0,
        SessionSummary {
            session_id: p.session_id,
            title: if agent_state.mode == AgentMode::Chat {
                // Truncate long prompts for titles
                let t = p.goal.lines().next().unwrap_or("New Chat");
                if t.len() > 30 {
                    format!("{}...", &t[..30])
                } else {
                    t.to_string()
                }
            } else {
                let t = p.goal.lines().next().unwrap_or("Agent Task");
                if t.len() > 30 {
                    format!("{}...", &t[..30])
                } else {
                    t.to_string()
                }
            },
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        },
    );

    // Keep last 50
    if history.len() > 50 {
        history.truncate(50);
    }

    state.insert(&history_key, &codec::to_bytes_canonical(&history)?)?;

    Ok(())
}

// [NEW] Canonical Input Handler (Inbox Pattern)
pub async fn handle_post_message(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    p: PostMessageParams,
    ctx: &TxContext<'_>,
) -> Result<(), TransactionError> {
    // 1. Write to Kernel SCS (SSOT)
    // We clone here because we might need p values for logic below, although 
    // we can also use the constructed `msg` for checks.
    let msg = ioi_types::app::agentic::ChatMessage {
        role: p.role,
        content: p.content,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        trace_hash: None,
    };
    
    // We persist the message to the verifiable log
    let new_root = service.append_chat_to_scs(p.session_id, &msg, ctx.block_height).await?;
    
    // 2. Wake Up Agent (Set Status to Running)
    let key = get_state_key(&p.session_id);
    if let Some(bytes) = state.get(&key)? {
        let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)?;
        
        // Update root hash pointer
        agent_state.transcript_root = new_root;

        // [FIX] Update Goal AND Reset Counters
        // This ensures the agent treats this as a fresh start for a new sub-task.
        if msg.role == "user" {
            agent_state.goal = msg.content.clone();
            agent_state.step_count = 0;           // <--- CRITICAL FIX
            agent_state.last_action_type = None;  // <--- Clear action bias
        }
        
        // Wake up if dormant
        if agent_state.status != AgentStatus::Running {
            log::info!(
                "Auto-resuming agent session {} due to new message", 
                hex::encode(&p.session_id[..4])
            );
            agent_state.status = AgentStatus::Running;
            agent_state.consecutive_failures = 0; // Reset error backoff
        }
        
        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
    } else {
        return Err(TransactionError::Invalid("Session not found".into()));
    }

    Ok(())
}

pub async fn handle_resume(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    p: ResumeAgentParams,
) -> Result<(), TransactionError> {
    let key = get_state_key(&p.session_id);
    let bytes = state
        .get(&key)?
        .ok_or(TransactionError::Invalid("Session not found".into()))?;
    let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)?;

    if let AgentStatus::Paused(_) = agent_state.status {
        agent_state.status = AgentStatus::Running;

        // Store the Approval Token provided by the UI
        if let Some(token) = p.approval_token {
            log::info!(
                "Resuming session {} with Approval Token for hash {:?}",
                hex::encode(&p.session_id[0..4]),
                hex::encode(&token.request_hash)
            );

            agent_state.pending_approval = Some(token);

            let msg = ioi_types::app::agentic::ChatMessage {
                role: "system".to_string(),
                content: "Authorization GRANTED. You may retry the action immediately.".to_string(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                trace_hash: None,
            };
            
            // [FIX] Await async call
            let new_root = service.append_chat_to_scs(p.session_id, &msg, 0).await?;
            agent_state.transcript_root = new_root;

        } else {
            let msg = ioi_types::app::agentic::ChatMessage {
                role: "system".to_string(),
                content: "Resumed by user/controller without specific approval.".to_string(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                trace_hash: None,
            };
            // [FIX] Await async call
            let new_root = service.append_chat_to_scs(p.session_id, &msg, 0).await?;
            agent_state.transcript_root = new_root;
        }

        // Reset failure counters so the retry doesn't trip the circuit breaker
        agent_state.consecutive_failures = 0;

        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
        Ok(())
    } else {
        Err(TransactionError::Invalid("Agent is not paused".into()))
    }
}

pub async fn handle_delete_session(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    session_id_bytes: &[u8],
) -> Result<(), TransactionError> {
    let session_id: [u8; 32] = session_id_bytes
        .try_into()
        .map_err(|_| TransactionError::Invalid("Invalid session ID".into()))?;

    // 1. Remove from Agent State
    let state_key = get_state_key(&session_id);
    state.delete(&state_key)?;

    // 2. Remove from History Index
    let history_key = b"agent::history".to_vec();
    if let Some(bytes) = state.get(&history_key)? {
        let mut history: Vec<SessionSummary> = codec::from_bytes_canonical(&bytes)?;

        // Remove the target session
        let len_before = history.len();
        history.retain(|s| s.session_id != session_id);

        if history.len() < len_before {
            state.insert(&history_key, &codec::to_bytes_canonical(&history)?)?;
        }
    }

    // 3. Scrub Context Store (SCS)
    // This physically deletes or zeroes the frames associated with the session.
    if let Some(scs_arc) = &service.scs {
        if let Ok(_store) = scs_arc.lock() {
            // Placeholder: store.prune_session(session_id);
            // In a real impl, this would iterate session_index and zero the payloads.
        }
    }

    log::info!("Deleted session {}", hex::encode(session_id));
    Ok(())
}