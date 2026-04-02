use crate::agentic::desktop::service::lifecycle::{
    await_child_worker_result, spawn_delegated_child_session,
};
use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::types::AgentState;
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_types::app::agentic::AgentTool;
use serde_json::json;
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
            AgentTool::AgentDelegate {
                goal,
                budget,
                playbook_id,
                template_id,
                workflow_id,
                role,
                success_criteria,
                merge_mode,
                expected_output,
            } => {
                match spawn_delegated_child_session(
                    service,
                    state,
                    agent_state,
                    tool_hash,
                    goal,
                    *budget,
                    playbook_id.as_deref(),
                    template_id.as_deref(),
                    workflow_id.as_deref(),
                    role.as_deref(),
                    success_criteria.as_deref(),
                    merge_mode.as_deref(),
                    expected_output.as_deref(),
                    pre_state_step_index,
                    block_height,
                )
                .await
                {
                    Ok(spawned) => {
                        let assignment = &spawned.assignment;
                        out = Some(
                            json!({
                                "child_session_id_hex": hex::encode(spawned.child_session_id),
                                "budget": assignment.budget,
                                "playbook_id": assignment.playbook_id,
                                "template_id": assignment.template_id,
                                "workflow_id": assignment.workflow_id,
                                "role": assignment.role,
                                "success_criteria": assignment.completion_contract.success_criteria,
                                "merge_mode": assignment.completion_contract.merge_mode.as_label(),
                                "expected_output": assignment.completion_contract.expected_output,
                            })
                            .to_string(),
                        );
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
            } => match await_child_worker_result(
                service,
                state,
                agent_state,
                pre_state_step_index,
                block_height,
                call_context,
                child_session_id_hex,
            )
            .await
            {
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
