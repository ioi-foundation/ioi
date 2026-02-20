use super::hashing::parse_hash_hex;
use crate::agentic::desktop::keys::get_state_key;
use crate::agentic::desktop::service::lifecycle::spawn_delegated_child_session;
use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_types::app::agentic::AgentTool;
use ioi_types::codec;
use std::sync::Arc;

pub(super) struct ExecutionOutcome {
    pub(super) success: bool,
    pub(super) out: Option<String>,
    pub(super) err: Option<String>,
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
    let (mut success, mut out, mut err) = match precheck_error {
        Some(err) => (false, None, Some(err)),
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
            Err(e) => (false, None, Some(e.to_string())),
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
            } => {
                let parsed = parse_hash_hex(child_session_id_hex);
                match parsed {
                    Some(child_session_id) => {
                        let child_key = get_state_key(&child_session_id);
                        let bytes = match state.get(&child_key) {
                            Ok(Some(bytes)) => bytes,
                            Ok(None) => {
                                success = false;
                                out = None;
                                err = Some(format!(
                                    "ERROR_CLASS=UnexpectedState Child session '{}' not found.",
                                    child_session_id_hex
                                ));
                                vec![]
                            }
                            Err(e) => {
                                success = false;
                                out = None;
                                err = Some(format!(
                                    "ERROR_CLASS=UnexpectedState Child state lookup failed: {}",
                                    e
                                ));
                                vec![]
                            }
                        };

                        if success {
                            match codec::from_bytes_canonical::<AgentState>(&bytes) {
                                Ok(child_state) => match child_state.status {
                                    AgentStatus::Running | AgentStatus::Idle => {
                                        out = Some("Running".to_string());
                                        err = None;
                                    }
                                    AgentStatus::Paused(reason) => {
                                        out = Some(format!("Running (paused: {})", reason));
                                        err = None;
                                    }
                                    AgentStatus::Completed(Some(result)) => {
                                        out = Some(result);
                                        err = None;
                                    }
                                    AgentStatus::Completed(None) => {
                                        out = Some("Completed".to_string());
                                        err = None;
                                    }
                                    AgentStatus::Failed(reason) => {
                                        success = false;
                                        out = None;
                                        err = Some(format!(
                                            "ERROR_CLASS=UnexpectedState Child agent failed: {}",
                                            reason
                                        ));
                                    }
                                    AgentStatus::Terminated => {
                                        success = false;
                                        out = None;
                                        err = Some(
                                            "ERROR_CLASS=UnexpectedState Child agent terminated."
                                                .to_string(),
                                        );
                                    }
                                },
                                Err(e) => {
                                    success = false;
                                    out = None;
                                    err = Some(format!(
                                        "ERROR_CLASS=UnexpectedState Failed to decode child session '{}': {}",
                                        child_session_id_hex, e
                                    ));
                                }
                            }
                        }
                    }
                    None => {
                        success = false;
                        out = None;
                        err = Some(format!(
                            "ERROR_CLASS=ToolUnavailable Invalid child_session_id_hex '{}'.",
                            child_session_id_hex
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    ExecutionOutcome { success, out, err }
}
