use super::compaction::perform_cognitive_compaction;
use super::runtime_locality::maybe_seed_runtime_locality_context;
use super::sudo::{
    incident_waiting_for_sudo_password, is_waiting_for_sudo_password,
    maybe_restore_pending_install_from_incident, status_mentions_sudo_password,
    RUNTIME_SECRET_KIND_SUDO_PASSWORD,
};
use crate::agentic::desktop::keys::{get_incident_key, get_remediation_key, get_state_key};
use crate::agentic::desktop::runtime_secret;
use crate::agentic::desktop::service::step::incident::mark_incident_retry_root;
use crate::agentic::desktop::service::step::signals::infer_interaction_target;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, PostMessageParams, ResumeAgentParams,
    SessionSummary, StartAgentParams, SwarmContext,
};
use crate::agentic::desktop::utils::{delete_agent_state_checkpoint, persist_agent_state};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn reset_for_new_user_goal(agent_state: &mut AgentState, goal: &str) {
    agent_state.goal = goal.to_string();
    agent_state.target = infer_interaction_target(goal);
    agent_state.resolved_intent = None;
    agent_state.awaiting_intent_clarification = false;
    agent_state.step_count = 0;
    agent_state.last_action_type = None;
    agent_state.pending_search_completion = None;
}

pub async fn handle_start(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    p: StartAgentParams,
) -> Result<(), TransactionError> {
    let key = get_state_key(&p.session_id);
    let remediation_key = get_remediation_key(&p.session_id);
    let incident_key = get_incident_key(&p.session_id);
    if state.get(&key)?.is_some() {
        return Err(TransactionError::Invalid("Session already exists".into()));
    }
    // Ensure stale remediation metadata from prior sessions cannot leak.
    state.delete(&remediation_key)?;
    state.delete(&incident_key)?;

    // Swarm hydration logic.
    // If the goal starts with "SWARM:", treat it as a request to instantiate a Swarm Manifest.
    // Format: "SWARM:<swarm_hash_hex>"
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

                        // For MVP, assume first roster agent is the root entry point.
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

    // Seed runtime locality context for locality-sensitive fact lookups when
    // query text omits explicit scope and no trusted session context is present.
    maybe_seed_runtime_locality_context(&actual_goal).await;

    // Derive target surface from ontology-level launch signals.
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

            // Inherit swarm context if parent is in a swarm.
            if let Some(_parent_ctx) = &parent_state.swarm_context {
                // StartAgentParams does not currently encode delegated swarm role.
                // Keep child in ad-hoc mode until explicit role plumbing is added.
            }

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
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
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
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        },
    );

    if history.len() > 50 {
        history.truncate(50);
    }

    state.insert(&history_key, &codec::to_bytes_canonical(&history)?)?;

    Ok(())
}

pub async fn handle_post_message(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    p: PostMessageParams,
    ctx: &TxContext<'_>,
) -> Result<(), TransactionError> {
    let key = get_state_key(&p.session_id);
    if let Some(bytes) = state.get(&key)? {
        let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)?;
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let role = p.role.clone();
        let content = p.content.clone();
        let incident_waiting_for_sudo = incident_waiting_for_sudo_password(state, p.session_id)?;
        let waiting_for_sudo_password =
            is_waiting_for_sudo_password(&agent_state.status) || incident_waiting_for_sudo;
        if role == "user" {
            if waiting_for_sudo_password {
                if content.trim().is_empty() {
                    return Err(TransactionError::Invalid(
                        "Sudo password input cannot be empty".into(),
                    ));
                }
                let session_id_hex = hex::encode(p.session_id);
                runtime_secret::set_secret(
                    &session_id_hex,
                    RUNTIME_SECRET_KIND_SUDO_PASSWORD,
                    content.clone(),
                    true,
                    120,
                )
                .map_err(TransactionError::Invalid)?;
                log::info!(
                    "Captured runtime sudo credential from user message for session {}",
                    hex::encode(&p.session_id[..4])
                );
                // Move incident state out of wait-for-user immediately so UI does not
                // re-surface the sudo prompt card while the retry is already in-flight.
                mark_incident_retry_root(state, p.session_id)?;
                maybe_restore_pending_install_from_incident(state, p.session_id, &mut agent_state)?;
            } else {
                reset_for_new_user_goal(&mut agent_state, &content);
                // Re-seed runtime locality when a new user goal arrives so
                // locality-sensitive public-fact requests can proceed without
                // immediate clarification pauses.
                maybe_seed_runtime_locality_context(&content).await;
                let remediation_key = get_remediation_key(&p.session_id);
                let incident_key = get_incident_key(&p.session_id);
                state.delete(&remediation_key)?;
                state.delete(&incident_key)?;
            }
        }
        let transcript_msg = if role == "user" && waiting_for_sudo_password {
            ioi_types::app::agentic::ChatMessage {
                role: "system".to_string(),
                content: "System: Runtime sudo credential received. Retrying pending install."
                    .to_string(),
                timestamp: timestamp_ms,
                trace_hash: None,
            }
        } else {
            ioi_types::app::agentic::ChatMessage {
                role,
                content,
                timestamp: timestamp_ms,
                trace_hash: None,
            }
        };

        let new_root = service
            .append_chat_to_scs(p.session_id, &transcript_msg, ctx.block_height)
            .await?;
        agent_state.transcript_root = new_root;

        if agent_state.status != AgentStatus::Running {
            log::info!(
                "Auto-resuming agent session {} due to new message",
                hex::encode(&p.session_id[..4])
            );
            agent_state.status = AgentStatus::Running;
            agent_state.consecutive_failures = 0;
        }

        persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;
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
    let session_id_hex = hex::encode(p.session_id);
    let waiting_for_sudo_password_before_resume = is_waiting_for_sudo_password(&agent_state.status);
    let status_hints_sudo_wait = status_mentions_sudo_password(&agent_state.status);
    let incident_waiting_for_sudo = incident_waiting_for_sudo_password(state, p.session_id)?;
    let runtime_secret_ready =
        runtime_secret::has_secret(&session_id_hex, RUNTIME_SECRET_KIND_SUDO_PASSWORD);
    let sudo_retry_resume = p.approval_token.is_none()
        && (waiting_for_sudo_password_before_resume
            || status_hints_sudo_wait
            || incident_waiting_for_sudo
            || runtime_secret_ready);

    // Allow resume even if already running (idempotency).
    if matches!(agent_state.status, AgentStatus::Paused(_))
        || agent_state.status == AgentStatus::Running
        || sudo_retry_resume
    {
        agent_state.status = AgentStatus::Running;
        if sudo_retry_resume {
            maybe_restore_pending_install_from_incident(state, p.session_id, &mut agent_state)?;
        }

        let resuming_pending_install = agent_state
            .pending_tool_jcs
            .as_ref()
            .and_then(|raw| serde_json::from_slice::<ioi_types::app::agentic::AgentTool>(raw).ok())
            .map(|tool| {
                matches!(
                    tool,
                    ioi_types::app::agentic::AgentTool::SysInstallPackage { .. }
                )
            })
            .unwrap_or(false);
        if sudo_retry_resume {
            // Runtime-secret resume should retry canonical pending install directly.
            // Drop stale remediation queue entries that can redirect into system__fail.
            agent_state.execution_queue.clear();
            if !resuming_pending_install {
                log::warn!(
                    "Resume requested for sudo retry, but pending install tool is unavailable for session {}. Keeping session paused.",
                    hex::encode(&p.session_id[..4])
                );
                agent_state.status = AgentStatus::Paused("Waiting for sudo password".to_string());
                persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;
                return Ok(());
            }
        }

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
            let new_root = service.append_chat_to_scs(p.session_id, &msg, 0).await?;
            agent_state.transcript_root = new_root;
        }

        agent_state.consecutive_failures = 0;

        persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;
        Ok(())
    } else {
        Err(TransactionError::Invalid(format!(
            "Agent cannot resume from status: {:?}",
            agent_state.status
        )))
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

    let state_key = get_state_key(&session_id);
    state.delete(&state_key)?;
    if let Err(error) = delete_agent_state_checkpoint(service.memory_runtime.as_ref(), session_id) {
        log::warn!(
            "Failed to delete agent-state checkpoint for session {}: {}",
            hex::encode(&session_id[..4]),
            error
        );
    }
    let remediation_key = get_remediation_key(&session_id);
    state.delete(&remediation_key)?;
    let incident_key = get_incident_key(&session_id);
    state.delete(&incident_key)?;

    let history_key = b"agent::history".to_vec();
    if let Some(bytes) = state.get(&history_key)? {
        let mut history: Vec<SessionSummary> = codec::from_bytes_canonical(&bytes)?;

        let len_before = history.len();
        history.retain(|s| s.session_id != session_id);

        if history.len() < len_before {
            state.insert(&history_key, &codec::to_bytes_canonical(&history)?)?;
        }
    }

    if let Err(e) = perform_cognitive_compaction(service, session_id).await {
        log::warn!("Cognitive Compaction failed during session delete: {}", e);
    }

    log::info!("Deleted/Terminated session {}", hex::encode(session_id));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::reset_for_new_user_goal;
    use crate::agentic::desktop::types::{
        AgentMode, AgentState, AgentStatus, ExecutionTier, PendingSearchCompletion,
    };
    use ioi_types::app::agentic::{
        IntentCandidateScore, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    };
    use std::collections::{BTreeMap, VecDeque};

    fn test_state() -> AgentState {
        AgentState {
            session_id: [0u8; 32],
            goal: "old".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 7,
            max_steps: 16,
            last_action_type: Some("tool".to_string()),
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 10,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: Some(PendingSearchCompletion::default()),
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: Some(ResolvedIntentState {
                intent_id: "conversation.reply".to_string(),
                scope: IntentScopeProfile::Conversation,
                band: IntentConfidenceBand::High,
                score: 1.0,
                top_k: vec![IntentCandidateScore {
                    intent_id: "conversation.reply".to_string(),
                    score: 1.0,
                }],
                required_capabilities: vec![],
                required_receipts: vec![],
                required_postconditions: vec![],
                risk_class: "low".to_string(),
                preferred_tier: "tool_first".to_string(),
                matrix_version: "intent-matrix-v2".to_string(),
                embedding_model_id: "test".to_string(),
                embedding_model_version: "test".to_string(),
                similarity_function_id: "cosine".to_string(),
                intent_set_hash: [0u8; 32],
                tool_registry_hash: [0u8; 32],
                capability_ontology_hash: [0u8; 32],
                query_normalization_version: "v1".to_string(),
                matrix_source_hash: [0u8; 32],
                receipt_hash: [0u8; 32],
                provider_selection: None,
                instruction_contract: None,
                constrained: false,
            }),
            awaiting_intent_clarification: true,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    #[test]
    fn reset_for_new_user_goal_refreshes_target_and_intent_state() {
        let mut state = test_state();
        reset_for_new_user_goal(&mut state, "open calculator");

        assert_eq!(state.goal, "open calculator");
        assert_eq!(
            state
                .target
                .as_ref()
                .and_then(|target| target.app_hint.as_deref()),
            Some("calculator")
        );
        assert!(state.resolved_intent.is_none());
        assert!(!state.awaiting_intent_clarification);
        assert_eq!(state.step_count, 0);
        assert!(state.last_action_type.is_none());
        assert!(state.pending_search_completion.is_none());
    }
}
