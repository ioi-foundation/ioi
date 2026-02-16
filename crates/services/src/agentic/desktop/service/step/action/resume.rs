use super::support::requires_visual_integrity;
use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::service::step::helpers::default_safe_policy;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::AgentTool;
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::time::{SystemTime, UNIX_EPOCH};

// [NEW] Imports for Safe Resume
use crate::agentic::desktop::service::step::visual::hamming_distance;
use crate::agentic::desktop::utils::compute_phash;

pub async fn resume_pending_action(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
) -> Result<(), TransactionError> {
    // 1. Load Canonical Request Bytes
    let tool_jcs = agent_state
        .pending_tool_jcs
        .as_ref()
        .ok_or(TransactionError::Invalid("Missing pending_tool_jcs".into()))?;

    let tool_hash = agent_state
        .pending_tool_hash
        .ok_or(TransactionError::Invalid(
            "Missing pending_tool_hash".into(),
        ))?;

    // 2. Deserialize Tool FIRST
    let tool: AgentTool = serde_json::from_slice(tool_jcs)
        .map_err(|e| TransactionError::Serialization(format!("Corrupt pending tool: {}", e)))?;

    // 3. Visual Guard: Context Drift Check
    let pending_vhash = agent_state
        .pending_visual_hash
        .ok_or(TransactionError::Invalid(
            "Missing pending_visual_hash".into(),
        ))?;

    if requires_visual_integrity(&tool) {
        let current_bytes = service.gui.capture_raw_screen().await.unwrap_or_default();
        let current_phash = compute_phash(&current_bytes).unwrap_or([0u8; 32]);
        let drift = hamming_distance(&pending_vhash, &current_phash);

        if drift > 30 {
            log::warn!("Context Drift Detected (Dist: {}). Aborting Resume.", drift);
            let key = get_state_key(&session_id);
            goto_trace_log(
                agent_state,
                state,
                &key,
                session_id,
                current_phash,
                "[Resumed Action]".to_string(),
                "ABORTED: Visual Context Drifted.".to_string(),
                false,
                Some("Context Drift".to_string()),
                "system::context_drift".to_string(),
                service.event_sender.clone(),
                None,
            )?;

            agent_state.pending_tool_jcs = None;
            agent_state.pending_tool_hash = None;
            agent_state.pending_visual_hash = None;
            agent_state.pending_tool_call = None;
            agent_state.pending_approval = None;
            agent_state.status = AgentStatus::Running;

            state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
            return Ok(());
        }
    } else {
        log::info!(
            "Skipping visual drift check for non-spatial tool (Hash: {}).",
            hex::encode(&tool_hash[0..4])
        );
    }

    service.restore_visual_context(pending_vhash).await?;

    let token = agent_state
        .pending_approval
        .as_ref()
        .ok_or(TransactionError::Invalid("Missing approval token".into()))?;

    if token.request_hash != tool_hash {
        return Err(TransactionError::Invalid(
            "Approval token hash mismatch".into(),
        ));
    }

    agent_state.current_tier = crate::agentic::desktop::types::ExecutionTier::VisualForeground;

    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    let rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);

    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;

    let (success, out, err) = match service
        .handle_action_execution(
            tool.clone(),
            session_id,
            agent_state.step_count,
            pending_vhash,
            &rules,
            &agent_state,
            &os_driver,
            None,
        )
        .await
    {
        Ok(t) => t,
        Err(e) => (false, None, Some(e.to_string())),
    };

    let output_str = out
        .clone()
        .unwrap_or_else(|| err.clone().unwrap_or_default());
    let key = get_state_key(&session_id);

    goto_trace_log(
        agent_state,
        state,
        &key,
        session_id,
        pending_vhash,
        "[Resumed Action]".to_string(),
        output_str.clone(),
        success,
        err.clone(),
        "resumed_action".to_string(),
        service.event_sender.clone(),
        agent_state.active_skill_hash,
    )?;

    if success {
        if let AgentTool::SysChangeDir { .. } = tool {
            if let Some(new_cwd) = out.as_ref() {
                agent_state.working_directory = new_cwd.clone();
            }
        }
    }

    let content = if success {
        out.clone()
            .unwrap_or_else(|| "Action executed successfully.".to_string())
    } else {
        format!(
            "Action Failed: {}",
            err.unwrap_or("Unknown error".to_string())
        )
    };

    let msg = ioi_types::app::agentic::ChatMessage {
        role: "tool".to_string(),
        content,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        trace_hash: None,
    };
    service
        .append_chat_to_scs(session_id, &msg, block_height)
        .await?;

    agent_state.pending_tool_jcs = None;
    agent_state.pending_tool_hash = None;
    agent_state.pending_visual_hash = None;
    agent_state.pending_tool_call = None;
    agent_state.pending_approval = None;
    agent_state.status = AgentStatus::Running;
    agent_state.step_count += 1;

    if success {
        agent_state.consecutive_failures = 0;
    }
    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    Ok(())
}
