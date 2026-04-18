use super::super::support::queue_action_request_to_tool;
use super::routing::is_web_research_scope;
use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::service::lifecycle::{
    await_child_worker_result, browser_subagent_request_from_dynamic, run_browser_subagent,
    spawn_delegated_child_session,
};
use crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution;
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::AgentState;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::AgentTool;
use ioi_types::error::TransactionError;
use serde_json::json;
use std::time::Duration;

pub(super) fn browser_queue_action_timeout() -> Duration {
    const DEFAULT_TIMEOUT_SECS: u64 = 12;
    std::env::var("IOI_BROWSER_QUEUE_TOOL_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS))
}

fn web_queue_action_timeout() -> Duration {
    const DEFAULT_TIMEOUT_SECS: u64 = 20;
    std::env::var("IOI_WEB_QUEUE_TOOL_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS))
}

pub(super) fn browser_queue_timeout_for_tool(tool: &AgentTool) -> Duration {
    const WAIT_GRACE_MS: u64 = 5_000;

    let baseline = browser_queue_action_timeout();
    match tool {
        AgentTool::BrowserWait { ms, timeout_ms, .. } => {
            let requested_ms = ms.or(*timeout_ms).unwrap_or(0);
            let requested = Duration::from_millis(requested_ms.saturating_add(WAIT_GRACE_MS));
            requested.max(baseline)
        }
        _ => baseline,
    }
}

fn queue_tool_timeout_policy(
    agent_state: &AgentState,
    tool: &AgentTool,
    tool_name: &str,
) -> Option<(&'static str, Duration)> {
    if is_web_research_scope(agent_state) {
        return Some(("Web", web_queue_action_timeout()));
    }
    if tool_name.starts_with("browser__") {
        return Some(("Browser", browser_queue_timeout_for_tool(tool)));
    }
    None
}

pub(super) fn queue_action_to_tool(
    action_request: &ioi_types::app::ActionRequest,
) -> Result<AgentTool, TransactionError> {
    queue_action_request_to_tool(action_request)
}

pub(super) async fn execute_queue_tool_request(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    call_context: ServiceCallContext<'_>,
    agent_state: &mut AgentState,
    tool_wrapper: AgentTool,
    tool_name: &str,
    rules: &ActionRules,
    session_id: [u8; 32],
    tool_hash: [u8; 32],
) -> Result<(bool, Option<String>, Option<String>, Option<[u8; 32]>), TransactionError> {
    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;

    if !is_tool_allowed_for_resolution(agent_state.resolved_intent.as_ref(), tool_name) {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=PolicyBlocked Tool '{}' blocked by global intent scope.",
            tool_name
        )));
    }

    let mut outcome = if let Some((timeout_scope, timeout)) =
        queue_tool_timeout_policy(agent_state, &tool_wrapper, tool_name)
    {
        match tokio::time::timeout(
            timeout,
            service.handle_action_execution_with_state(
                state,
                call_context,
                tool_wrapper.clone(),
                session_id,
                agent_state.step_count,
                [0u8; 32],
                rules,
                agent_state,
                &os_driver,
                None,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                log::warn!(
                    "{} queue tool execution timed out after {:?} (session={} tool={}).",
                    timeout_scope,
                    timeout,
                    hex::encode(&session_id[..4]),
                    tool_name
                );
                Err(TransactionError::Invalid(format!(
                    "ERROR_CLASS=TimeoutOrHang {} queue tool '{}' timed out after {}ms.",
                    timeout_scope,
                    tool_name,
                    timeout.as_millis()
                )))
            }
        }
    } else {
        service
            .handle_action_execution_with_state(
                state,
                call_context,
                tool_wrapper.clone(),
                session_id,
                agent_state.step_count,
                [0u8; 32],
                rules,
                agent_state,
                &os_driver,
                None,
            )
            .await
    }?;

    if outcome.0 {
        match &tool_wrapper {
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
                    agent_state.step_count,
                    call_context.block_height,
                )
                .await
                {
                    Ok(spawned) => {
                        let assignment = &spawned.assignment;
                        outcome.1 = Some(
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
                        outcome.2 = None;
                    }
                    Err(error) => {
                        outcome.0 = false;
                        outcome.1 = None;
                        outcome.2 = Some(error.to_string());
                    }
                }
            }
            AgentTool::AgentAwait {
                child_session_id_hex,
            } => {
                match await_child_worker_result(
                    service,
                    state,
                    agent_state,
                    agent_state.step_count,
                    call_context.block_height,
                    call_context,
                    child_session_id_hex,
                )
                .await
                {
                    Ok(child_status) => {
                        outcome.1 = Some(child_status);
                        outcome.2 = None;
                    }
                    Err(error) => {
                        outcome.0 = false;
                        outcome.1 = None;
                        outcome.2 = Some(error);
                    }
                }
            }
            AgentTool::Dynamic(value) => {
                match browser_subagent_request_from_dynamic(value).and_then(|request| {
                    request.ok_or_else(|| {
                        "ERROR_CLASS=UnsupportedTool browser__subagent request missing.".to_string()
                    })
                }) {
                    Ok(request) => match run_browser_subagent(
                        service,
                        state,
                        agent_state,
                        tool_hash,
                        agent_state.step_count,
                        call_context.block_height,
                        call_context,
                        &request,
                    )
                    .await
                    {
                        Ok(browser_outcome) => {
                            outcome.1 = Some(
                                json!({
                                    "child_session_id_hex": browser_outcome.child_session_id_hex,
                                    "status": browser_outcome.status,
                                    "task_name": request.task_name,
                                    "recording_name": request.recording_name,
                                    "final_report": browser_outcome.final_report,
                                })
                                .to_string(),
                            );
                            outcome.0 = browser_outcome.success;
                            outcome.2 = if browser_outcome.success {
                                None
                            } else {
                                Some("Browser subagent returned control to the parent.".to_string())
                            };
                        }
                        Err(error) => {
                            outcome.0 = false;
                            outcome.1 = None;
                            outcome.2 = Some(error);
                        }
                    },
                    Err(error)
                        if value
                            .get("name")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|name| name.eq_ignore_ascii_case("browser__subagent")) =>
                    {
                        outcome.0 = false;
                        outcome.1 = None;
                        outcome.2 = Some(error);
                    }
                    Err(_) => {}
                }
            }
            _ => {}
        }
    }

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::{browser_queue_action_timeout, browser_queue_timeout_for_tool};
    use ioi_types::app::agentic::AgentTool;
    use std::time::Duration;

    #[test]
    fn browser_queue_timeout_defaults_for_non_wait_tools() {
        let tool = AgentTool::BrowserSnapshot {};
        assert_eq!(
            browser_queue_timeout_for_tool(&tool),
            browser_queue_action_timeout()
        );
    }

    #[test]
    fn browser_wait_timeout_honors_requested_duration_plus_grace() {
        let tool = AgentTool::BrowserWait {
            ms: Some(15_000),
            condition: None,
            selector: None,
            query: None,
            scope: None,
            timeout_ms: None,
            continue_with: None,
        };

        assert_eq!(
            browser_queue_timeout_for_tool(&tool),
            Duration::from_millis(20_000)
        );
    }
}
