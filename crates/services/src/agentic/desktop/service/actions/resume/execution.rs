use crate::agentic::desktop::service::lifecycle::spawn_delegated_child_session;
use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::types::AgentState;
use crate::agentic::desktop::utils::await_child_session_status_for_inspection;
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_types::app::agentic::AgentTool;
use std::sync::Arc;

pub(super) struct ExecutionOutcome {
    pub(super) success: bool,
    pub(super) out: Option<String>,
    pub(super) err: Option<String>,
    pub(super) visual_hash: Option<[u8; 32]>,
}

pub(super) async fn execute(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    os_driver: &Arc<dyn OsDriver>,
    tool: &AgentTool,
    rules: &crate::agentic::rules::ActionRules,
    session_id: [u8; 32],
    tool_hash: [u8; 32],
    pending_vhash: [u8; 32],
    scoped_exception_override_hash: Option<[u8; 32]>,
    has_precheck_error: bool,
    precheck_error: Option<String>,
    pre_state_step_index: u32,
    block_height: u64,
    call_context: ServiceCallContext<'_>,
) -> ExecutionOutcome {
    let (mut success, mut out, mut err, visual_hash) = match precheck_error {
        Some(err) => (false, None, Some(err), None),
        None => match service
            .handle_action_execution_with_state(
                state,
                call_context,
                tool.clone(),
                session_id,
                agent_state.step_count,
                pending_vhash,
                rules,
                agent_state,
                os_driver,
                scoped_exception_override_hash,
            )
            .await
        {
            Ok(t) => t,
            Err(e) => (false, None, Some(e.to_string()), None),
        },
    };

    if !has_precheck_error && success {
        match tool {
            AgentTool::AgentDelegate { goal, budget } => {
                match spawn_delegated_child_session(
                    service,
                    state,
                    agent_state,
                    tool_hash,
                    goal,
                    *budget,
                    pre_state_step_index,
                    block_height,
                )
                .await
                {
                    Ok(child_session_id) => {
                        out = Some(format!(
                            "{{\"child_session_id_hex\":\"{}\"}}",
                            hex::encode(child_session_id)
                        ));
                        err = None;
                    }
                    Err(e) => {
                        success = false;
                        out = None;
                        err = Some(e.to_string());
                    }
                }
            }
            AgentTool::AgentAwait {
                child_session_id_hex,
            } => match await_child_session_status_for_inspection(
                state,
                service.memory_runtime.as_ref(),
                child_session_id_hex,
            ) {
                Ok(child_status) => {
                    out = Some(child_status);
                    err = None;
                }
                Err(error) => {
                    success = false;
                    out = None;
                    err = Some(error);
                }
            },
            _ => {}
        }
    }

    ExecutionOutcome {
        success,
        out,
        err,
        visual_hash,
    }
}
