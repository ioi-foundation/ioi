use super::super::runtime_locality::maybe_seed_runtime_locality_context;
use crate::agentic::runtime::keys::{get_incident_key, get_remediation_key, get_state_key};
use crate::agentic::runtime::service::step::signals::infer_interaction_target;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, SessionSummary, StartAgentParams,
    SwarmContext,
};
use crate::agentic::runtime::utils::{persist_agent_state, timestamp_ms_now};
use ioi_api::state::StateAccess;
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::collections::BTreeMap;

pub async fn handle_start(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    p: StartAgentParams,
) -> Result<(), TransactionError> {
    let key = get_state_key(&p.session_id);
    let remediation_key = get_remediation_key(&p.session_id);
    let incident_key = get_incident_key(&p.session_id);
    if state.get(&key)?.is_some() {
        return Err(TransactionError::Invalid("Session already exists".into()));
    }
    state.delete(&remediation_key)?;
    state.delete(&incident_key)?;

    let mut swarm_context = None;
    let mut actual_goal = p.goal.clone();

    if p.goal.starts_with("SWARM:") {
        let parts: Vec<&str> = p.goal.split_whitespace().collect();
        if let Some(hash_hex) = parts.first().and_then(|s| s.strip_prefix("SWARM:")) {
            if let Ok(swarm_hash) = hex::decode(hash_hex) {
                if swarm_hash.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&swarm_hash);

                    if let Some(manifest) = service.fetch_swarm_manifest(state, arr).await {
                        log::info!("Hydrating Swarm '{}' ({})", manifest.name, hash_hex);

                        if let Some((root_role, _root_agent_hash)) = manifest.roster.first() {
                            let delegates: Vec<String> = manifest
                                .delegation_flow
                                .iter()
                                .filter(|(from, _)| from == root_role)
                                .map(|(_, to)| to.clone())
                                .collect();

                            swarm_context = Some(SwarmContext {
                                swarm_id: arr,
                                role: root_role.clone(),
                                allowed_delegates: delegates,
                            });

                            actual_goal = parts[1..].join(" ");
                            if actual_goal.is_empty() {
                                actual_goal =
                                    format!("Execute swarm mission: {}", manifest.description);
                            }
                        }
                    }
                }
            }
        }
    }

    maybe_seed_runtime_locality_context(&actual_goal).await;
    let target = infer_interaction_target(&p.goal);

    if let Some(parent_id) = p.parent_session_id {
        let parent_key = get_state_key(&parent_id);
        if let Some(parent_bytes) = state.get(&parent_key)? {
            let mut parent_state: AgentState = codec::from_bytes_canonical(&parent_bytes)?;

            if parent_state.budget < p.initial_budget {
                return Err(TransactionError::Invalid(
                    "Insufficient parent budget for delegation".into(),
                ));
            }
            parent_state.budget -= p.initial_budget;
            parent_state.child_session_ids.push(p.session_id);

            persist_agent_state(
                state,
                &parent_key,
                &parent_state,
                service.memory_runtime.as_ref(),
            )?;
        } else {
            return Err(TransactionError::Invalid("Parent session not found".into()));
        }
    }

    let initial_message = ioi_types::app::agentic::ChatMessage {
        role: "user".to_string(),
        content: actual_goal.clone(),
        timestamp: timestamp_ms_now(),
        trace_hash: None,
    };

    let root_hash = service
        .append_chat_to_scs(p.session_id, &initial_message, 0)
        .await?;

    let agent_state = AgentState {
        session_id: p.session_id,
        goal: actual_goal,
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
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: Vec::new(),
        mode: p.mode,
        last_screen_phash: None,
        execution_queue: Vec::new(),
        current_tier: ExecutionTier::DomHeadless,
        tool_execution_log: BTreeMap::new(),
        active_skill_hash: None,
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context,
        target,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        active_lens: None,
        pending_search_completion: None,
        planner_state: None,
        command_history: Default::default(),
    };
    persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;

    let history_key = b"agent::history".to_vec();
    let mut history: Vec<SessionSummary> = if let Some(bytes) = state.get(&history_key)? {
        codec::from_bytes_canonical(&bytes).unwrap_or_default()
    } else {
        Vec::new()
    };

    history.insert(
        0,
        SessionSummary {
            session_id: p.session_id,
            title: if agent_state.mode == AgentMode::Chat {
                let t = agent_state.goal.lines().next().unwrap_or("New Chat");
                if t.len() > 30 {
                    format!("{}...", &t[..30])
                } else {
                    t.to_string()
                }
            } else {
                let t = agent_state.goal.lines().next().unwrap_or("Agent Task");
                if t.len() > 30 {
                    format!("{}...", &t[..30])
                } else {
                    t.to_string()
                }
            },
            timestamp: timestamp_ms_now(),
        },
    );

    if history.len() > 50 {
        history.truncate(50);
    }

    state.insert(&history_key, &codec::to_bytes_canonical(&history)?)?;

    Ok(())
}
