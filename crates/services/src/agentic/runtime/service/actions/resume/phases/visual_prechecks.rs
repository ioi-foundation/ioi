use super::super::*;
use crate::agentic::runtime::utils::persist_agent_state;
use ioi_api::vm::drivers::os::OsDriver;
use std::sync::Arc;

pub(crate) struct VisualPrecheckPhaseContext<'a, 's> {
    pub service: &'a RuntimeAgentService,
    pub state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub session_id: [u8; 32],
    pub block_height: u64,
    pub pending_vhash: [u8; 32],
    pub tool: &'a AgentTool,
    pub os_driver: &'a Arc<dyn OsDriver>,
    pub explicit_pii_deny: bool,
    pub pii_request_present: bool,
    pub verification_checks: &'a mut Vec<String>,
}

pub(crate) struct VisualPrecheckPhaseData {
    pub precheck_error: Option<String>,
    pub log_visual_hash: [u8; 32],
}

pub(crate) enum VisualPrecheckPhaseResult {
    Continue(VisualPrecheckPhaseData),
    EarlyReturn,
}

pub(crate) async fn run_visual_prechecks_phase(
    ctx: VisualPrecheckPhaseContext<'_, '_>,
) -> Result<VisualPrecheckPhaseResult, TransactionError> {
    let VisualPrecheckPhaseContext {
        service,
        state,
        agent_state,
        session_id,
        block_height,
        pending_vhash,
        tool,
        os_driver,
        explicit_pii_deny,
        pii_request_present,
        verification_checks,
    } = ctx;

    let (mut precheck_error, mut log_visual_hash) =
        visual::run_visual_prechecks(service, os_driver, tool, pending_vhash, verification_checks)
            .await;

    if explicit_pii_deny {
        mark_gate_denied(state, session_id)?;
        let deny_error = if pii_request_present {
            "PII review denied by approver. Current step stopped before execution; no further changes were made.".to_string()
        } else {
            "Approval denied by approver. Current step stopped before execution; no further changes were made.".to_string()
        };
        let key = get_state_key(&session_id);
        goto_trace_log(
            agent_state,
            state,
            &key,
            session_id,
            pending_vhash,
            "[Resumed Action]".to_string(),
            deny_error.clone(),
            false,
            Some(deny_error.clone()),
            "resumed_action".to_string(),
            service.event_sender.clone(),
            agent_state.active_skill_hash,
            service.memory_runtime.as_ref(),
        )?;

        let deny_msg = ioi_types::app::agentic::ChatMessage {
            role: "system".to_string(),
            content: if pii_request_present {
                "System: PII review denied. Step stopped before execution. Approve and retry to continue.".to_string()
            } else {
                "System: Approval denied. Step stopped before execution. Approve and retry to continue.".to_string()
            },
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_hash: None,
        };
        service
            .append_chat_to_scs(session_id, &deny_msg, block_height)
            .await?;

        clear_pending_resume_state(agent_state);
        agent_state.status = AgentStatus::Running;
        agent_state.step_count = agent_state.step_count.saturating_add(1);
        agent_state.consecutive_failures = agent_state.consecutive_failures.saturating_add(1);
        persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;
        return Ok(VisualPrecheckPhaseResult::EarlyReturn);
    }

    if precheck_error.is_none() && requires_visual_integrity(tool) {
        if let Some(err) = focus::ensure_target_focused_for_resume(os_driver, agent_state).await {
            precheck_error = Some(err);
        }
    }

    if precheck_error.is_none() && log_visual_hash == [0u8; 32] {
        log_visual_hash = pending_vhash;
    }

    Ok(VisualPrecheckPhaseResult::Continue(
        VisualPrecheckPhaseData {
            precheck_error,
            log_visual_hash,
        },
    ))
}
