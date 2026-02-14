// Path: crates/services/src/agentic/desktop/service/lifecycle.rs

use super::DesktopAgentService;
use crate::agentic::desktop::keys::{get_incident_key, get_remediation_key, get_state_key};
use crate::agentic::desktop::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, InteractionTarget, PostMessageParams,
    ResumeAgentParams, SessionSummary, StartAgentParams, SwarmContext,
};
use hex;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

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

    // [NEW] Swarm Hydration Logic
    // If the goal starts with "SWARM:", we treat it as a request to instantiate a Swarm Manifest.
    // Format: "SWARM:<swarm_hash_hex>"
    let mut swarm_context = None;
    let mut actual_goal = p.goal.clone();

    if p.goal.starts_with("SWARM:") {
        let parts: Vec<&str> = p.goal.split_whitespace().collect();
        if let Some(hash_hex) = parts.get(0).and_then(|s| s.strip_prefix("SWARM:")) {
            if let Ok(swarm_hash) = hex::decode(hash_hex) {
                if swarm_hash.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&swarm_hash);

                    // Fetch Manifest from Market/SCS
                    if let Some(manifest) = service.fetch_swarm_manifest(arr).await {
                        log::info!("Hydrating Swarm '{}' ({})", manifest.name, hash_hex);

                        // 1. Identify Root Agent (First in roster or "Manager")
                        // For MVP, we assume the first agent in roster is the entry point.
                        if let Some((root_role, _root_agent_hash)) = manifest.roster.first() {
                            // This session becomes the Root Agent
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

                            // The goal of the root agent is the rest of the user prompt
                            actual_goal = parts[1..].join(" ");
                            if actual_goal.is_empty() {
                                actual_goal =
                                    format!("Execute swarm mission: {}", manifest.description);
                            }

                            // [TODO] Pre-provision child sessions for other roles?
                            // For now, we let the root agent spawn them lazily via `agent__delegate`.
                        }
                    }
                }
            }
        }
    }

    // [NEW] Heuristic Target Derivation
    // Identify the "Surface of Action" based on the user's prompt.
    // This sets the invariant for the entire session.
    let target = if p.goal.to_lowercase().contains("calculator") {
        Some(InteractionTarget {
            app_hint: Some("calculator".to_string()),
            title_pattern: None,
        })
    } else if p.goal.to_lowercase().contains("code") || p.goal.to_lowercase().contains("vscode") {
        Some(InteractionTarget {
            app_hint: Some("code".to_string()),
            title_pattern: None,
        })
    } else if p.goal.to_lowercase().contains("terminal") {
        Some(InteractionTarget {
            app_hint: Some("terminal".to_string()),
            title_pattern: None,
        })
    } else {
        None // No specific OS target derived; allow general interaction
    };

    // ... [Parent budget check unchanged] ...
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

            // [NEW] Inherit Swarm Context if parent is in a swarm
            if let Some(_parent_ctx) = &parent_state.swarm_context {
                // If this is a delegation, we need to determine the role of the child.
                // The parent likely called `agent__delegate` with a goal.
                // We rely on `agent__delegate` tool logic to pass the role,
                // but `StartAgentParams` doesn't have a role field in the struct yet.
                // For MVP, we assume ad-hoc delegation unless we update StartAgentParams.
                // Let's assume ad-hoc for now or infer from goal if it matches a role name.
            }

            state.insert(&parent_key, &codec::to_bytes_canonical(&parent_state)?)?;
        } else {
            return Err(TransactionError::Invalid("Parent session not found".into()));
        }
    }

    // ... [Chat Init unchanged] ...
    let initial_message = ioi_types::app::agentic::ChatMessage {
        role: "user".to_string(),
        content: actual_goal.clone(), // Use resolved goal
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
        goal: actual_goal, // Use resolved goal
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

        // [FIX] Initialize new fields
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_visual_hash: None,

        recent_actions: Vec::new(),
        mode: p.mode,
        last_screen_phash: None,
        execution_queue: Vec::new(),
        current_tier: ExecutionTier::DomHeadless,
        tool_execution_log: BTreeMap::new(),
        active_skill_hash: None,
        visual_som_map: None,

        // [FIX] Initialize visual_semantic_map to satisfy the new struct definition
        visual_semantic_map: None,

        swarm_context, // [NEW]
        target,        // [NEW] Set the target

        // Default relative working directory for stateful sys tools.
        working_directory: ".".to_string(),

        // [FIX] Initialize active_lens
        active_lens: None,
        pending_search_completion: None,
    };
    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    // ... [History update unchanged] ...
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
    let msg = ioi_types::app::agentic::ChatMessage {
        role: p.role,
        content: p.content,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        trace_hash: None,
    };

    let new_root = service
        .append_chat_to_scs(p.session_id, &msg, ctx.block_height)
        .await?;

    let key = get_state_key(&p.session_id);
    if let Some(bytes) = state.get(&key)? {
        let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)?;

        agent_state.transcript_root = new_root;

        if msg.role == "user" {
            agent_state.goal = msg.content.clone();
            agent_state.step_count = 0;
            agent_state.last_action_type = None;
            agent_state.pending_search_completion = None;
            let remediation_key = get_remediation_key(&p.session_id);
            let incident_key = get_incident_key(&p.session_id);
            state.delete(&remediation_key)?;
            state.delete(&incident_key)?;
        }

        if agent_state.status != AgentStatus::Running {
            log::info!(
                "Auto-resuming agent session {} due to new message",
                hex::encode(&p.session_id[..4])
            );
            agent_state.status = AgentStatus::Running;
            agent_state.consecutive_failures = 0;
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

    // [FIX] Allow resume even if already running (Idempotency)
    // This handles the race where the UI sends resume but the system auto-recovered
    // or received another event that flipped it back to Running.
    if matches!(agent_state.status, AgentStatus::Paused(_))
        || agent_state.status == AgentStatus::Running
    {
        agent_state.status = AgentStatus::Running;

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

        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
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

    // [NEW] Trigger Cognitive Compaction on session delete/close
    // This shreds the raw thoughts but keeps the wisdom in the overlay.
    // Note: This is an async call that locks the SCS, so it might block briefly.
    if let Err(e) = perform_cognitive_compaction(service, session_id).await {
        log::warn!("Cognitive Compaction failed during session delete: {}", e);
    }

    // [NEW] Mark session as Terminated in any remaining state keys if possible,
    // though here we deleted the main state key already.
    // In a full implementation we might move it to an archive key.
    // For now, logging the explicit termination is sufficient.

    log::info!("Deleted/Terminated session {}", hex::encode(session_id));
    Ok(())
}

/// [NEW] Performs the "Refactoring Notes" process:
/// 1. Reads raw thoughts from the current epoch.
/// 2. Summarizes them into an Overlay.
/// 3. Rotates the epoch (Shredding the keys for raw thoughts).
/// 4. Prunes the old epoch key explicitly.
pub async fn perform_cognitive_compaction(
    service: &DesktopAgentService,
    session_id: [u8; 32],
) -> Result<(), TransactionError> {
    // [FIX] Use `service` argument instead of `self.service`
    let scs_mutex = service
        .scs
        .as_ref()
        .ok_or(TransactionError::Invalid("SCS required".into()))?;

    // 1. Retrieve Raw Thoughts (Retention::Epoch)
    // We scan the session index for frames that are both "Thought" type and belong to the current epoch.
    let raw_thoughts: Vec<String> = {
        let store = scs_mutex
            .lock()
            .map_err(|_| TransactionError::Invalid("SCS lock poisoned".into()))?;
        let current_epoch = store.current_epoch;

        if let Some(frame_ids) = store.session_index.get(&session_id) {
            frame_ids
                .iter()
                .filter_map(|&fid| {
                    let frame = store.toc.frames.get(fid as usize)?;
                    // Only collect thoughts from the epoch we are about to shred
                    if frame.frame_type == ioi_scs::FrameType::Thought
                        && frame.epoch_id == current_epoch
                    {
                        // Attempt to read payload (will fail if key is already gone, which is fine)
                        if let Ok(bytes) = store.read_frame_payload(fid) {
                            // Assuming ChatMessage structure
                            if let Ok(msg) = codec::from_bytes_canonical::<
                                ioi_types::app::agentic::ChatMessage,
                            >(&bytes)
                            {
                                return Some(format!("{}: {}", msg.role, msg.content));
                            }
                        }
                    }
                    None
                })
                .collect()
        } else {
            vec![]
        }
    };

    // If no new thoughts to summarize, we might still want to rotate epoch for security,
    // but for now let's just skip to avoid empty overlays.
    if raw_thoughts.is_empty() {
        return Ok(());
    }

    log::info!(
        "Cognitive Compaction: Summarizing {} thoughts...",
        raw_thoughts.len()
    );

    // 2. Synthesize Summary (The Overlay)
    // Use the reasoning model (System 2) to compress the context.
    let prompt = format!(
        "SYSTEM: Summarize the following stream of consciousness into a concise set of facts, decisions, and skills learned.\n\
         Discard transient errors, retries, and verbose logs. Keep only the final working logic and key outcomes.\n\n\
         RAW LOGS:\n{:?}", 
        raw_thoughts
    );

    let options = ioi_types::app::agentic::InferenceOptions {
        temperature: 0.0,
        ..Default::default()
    };

    // Use zero hash for model ID
    let summary_bytes = service
        .reasoning_inference
        .execute_inference([0u8; 32], prompt.as_bytes(), options)
        .await
        .map_err(|e| TransactionError::Invalid(format!("Compaction inference failed: {}", e)))?;

    // 3. Write Overlay Frame (Retention::Archival)
    {
        let mut store = scs_mutex
            .lock()
            .map_err(|_| TransactionError::Invalid("SCS lock poisoned".into()))?;

        // Append frame with Archival retention - this survives key shredding
        // [FIX] Explicitly type the error map
        let _overlay_id = store
            .append_frame(
                ioi_scs::FrameType::Overlay,
                &summary_bytes,
                0,         // Block height (could fetch from context if available, using 0 for now)
                [0u8; 32], // mHNSW root placeholder
                session_id,
                ioi_scs::RetentionClass::Archival, // <--- SAVED FOREVER
            )
            .map_err(|e: anyhow::Error| TransactionError::Invalid(e.to_string()))?;

        // 4. Rotate Epoch (Generates new key, archives Manifest)
        // [FIX] Explicitly type the error map
        let _manifest = store
            .rotate_epoch()
            .map_err(|e: anyhow::Error| TransactionError::Invalid(e.to_string()))?;

        // 5. Explicitly prune the old epoch key to enforce forward secrecy
        // The previous epoch is `current_epoch - 1` after rotation.
        let old_epoch = store.current_epoch.saturating_sub(1);
        store.prune_epoch(old_epoch);
    }

    log::info!(
        "Cognitive Compaction Complete: Epoch rotated, raw thoughts shredded, Overlay preserved."
    );
    Ok(())
}
