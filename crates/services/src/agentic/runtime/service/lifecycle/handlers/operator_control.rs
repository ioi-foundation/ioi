use crate::agentic::runtime::keys::{get_approval_grant_key, get_state_key};
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{
    AgentPauseReason, AgentState, AgentStatus, CancelAgentParams, DenyAgentParams, PauseAgentParams,
};
use crate::agentic::runtime::utils::{persist_agent_state, timestamp_ms_now};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::codec;
use ioi_types::error::TransactionError;

fn load_agent_state(
    state: &dyn StateAccess,
    session_id: &[u8; 32],
) -> Result<AgentState, TransactionError> {
    let key = get_state_key(session_id);
    let bytes = state
        .get(&key)?
        .ok_or(TransactionError::Invalid("Session not found".into()))?;
    codec::from_bytes_canonical(&bytes).map_err(|error| {
        TransactionError::Invalid(format!("Failed to decode agent state: {error}"))
    })
}

async fn append_operator_control_message(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    content: String,
    block_height: u64,
) -> Result<[u8; 32], TransactionError> {
    let msg = ioi_types::app::agentic::ChatMessage {
        role: "system".to_string(),
        content,
        timestamp: timestamp_ms_now(),
        trace_hash: None,
    };
    service
        .append_chat_to_scs(session_id, &msg, block_height)
        .await
}

pub async fn handle_pause(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    p: PauseAgentParams,
    ctx: &TxContext<'_>,
) -> Result<(), TransactionError> {
    let mut agent_state = load_agent_state(state, &p.session_id)?;
    let reason = if p.reason.trim().is_empty() {
        "Operator requested pause".to_string()
    } else {
        format!("Operator requested pause: {}", p.reason.trim())
    };
    agent_state.set_pause_reason(AgentPauseReason::Other(reason.clone()));
    agent_state.transcript_root =
        append_operator_control_message(service, p.session_id, reason, ctx.block_height).await?;
    let key = get_state_key(&p.session_id);
    persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())
}

pub async fn handle_cancel(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    p: CancelAgentParams,
    ctx: &TxContext<'_>,
) -> Result<(), TransactionError> {
    let mut agent_state = load_agent_state(state, &p.session_id)?;
    let reason = if p.reason.trim().is_empty() {
        "Operator cancelled session".to_string()
    } else {
        format!("Operator cancelled session: {}", p.reason.trim())
    };
    agent_state.status = AgentStatus::Terminated;
    agent_state.clear_pending_action_state();
    agent_state.transcript_root =
        append_operator_control_message(service, p.session_id, reason, ctx.block_height).await?;
    let key = get_state_key(&p.session_id);
    persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())
}

pub async fn handle_deny(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    p: DenyAgentParams,
    ctx: &TxContext<'_>,
) -> Result<(), TransactionError> {
    let mut agent_state = load_agent_state(state, &p.session_id)?;
    let denied_hash = p
        .request_hash
        .map(hex::encode)
        .unwrap_or_else(|| "current pending action".to_string());
    let reason = if p.reason.trim().is_empty() {
        format!("Operator denied approval for {denied_hash}")
    } else {
        format!(
            "Operator denied approval for {denied_hash}: {}",
            p.reason.trim()
        )
    };
    agent_state.clear_pending_action_state();
    agent_state.set_pause_reason(AgentPauseReason::Other(reason.clone()));
    state.delete(&get_approval_grant_key(&p.session_id))?;
    agent_state.transcript_root =
        append_operator_control_message(service, p.session_id, reason, ctx.block_height).await?;
    let key = get_state_key(&p.session_id);
    persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())
}
