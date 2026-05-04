use super::*;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_types::app::agentic::IntentScopeProfile;
use std::sync::Arc;
use tokio::time::{timeout, Duration};

fn web_tool_execution_timeout() -> Duration {
    const DEFAULT_TIMEOUT_SECS: u64 = 20;
    std::env::var("IOI_WEB_QUEUE_TOOL_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS))
}

fn browser_tool_execution_timeout() -> Duration {
    const DEFAULT_TIMEOUT_SECS: u64 = 30;
    std::env::var("IOI_BROWSER_QUEUE_TOOL_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS))
}

fn browser_tool_timeout_for_action(tool: &AgentTool) -> Duration {
    const WAIT_GRACE_MS: u64 = 5_000;

    let baseline = browser_tool_execution_timeout();
    match tool {
        AgentTool::BrowserWait { ms, timeout_ms, .. } => {
            let requested_ms = ms.or(*timeout_ms).unwrap_or(0);
            let requested = Duration::from_millis(requested_ms.saturating_add(WAIT_GRACE_MS));
            requested.max(baseline)
        }
        _ => baseline,
    }
}

fn tool_execution_timeout_policy(
    agent_state: &AgentState,
    tool: &AgentTool,
    tool_name: &str,
) -> Option<(&'static str, Duration)> {
    if matches!(
        agent_state
            .resolved_intent
            .as_ref()
            .map(|intent| intent.scope),
        Some(IntentScopeProfile::WebResearch)
    ) {
        return Some(("Web", web_tool_execution_timeout()));
    }
    if tool_name.starts_with("browser__") {
        return Some(("Browser", browser_tool_timeout_for_action(tool)));
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn execute_tool_with_optional_timeout(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    call_context: ServiceCallContext<'_>,
    agent_state: &AgentState,
    tool: AgentTool,
    tool_name: &str,
    session_id: [u8; 32],
    final_visual_phash: [u8; 32],
    rules: &ActionRules,
    os_driver: &Arc<dyn OsDriver>,
) -> Result<(bool, Option<String>, Option<String>, Option<[u8; 32]>), TransactionError> {
    if let Some((timeout_scope, timeout_duration)) =
        tool_execution_timeout_policy(agent_state, &tool, tool_name)
    {
        match timeout(
            timeout_duration,
            service.handle_action_execution_with_state(
                state,
                call_context,
                tool.clone(),
                session_id,
                agent_state.step_count,
                final_visual_phash,
                rules,
                agent_state,
                os_driver,
                None,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                log::warn!(
                    "{} action execution timed out after {:?} (session={} tool={}).",
                    timeout_scope,
                    timeout_duration,
                    hex::encode(&session_id[..4]),
                    tool_name
                );
                Err(TransactionError::Invalid(format!(
                    "ERROR_CLASS=TimeoutOrHang {} tool '{}' timed out after {}ms.",
                    timeout_scope,
                    tool_name,
                    timeout_duration.as_millis()
                )))
            }
        }
    } else {
        service
            .handle_action_execution_with_state(
                state,
                call_context,
                tool,
                session_id,
                agent_state.step_count,
                final_visual_phash,
                rules,
                agent_state,
                os_driver,
                None,
            )
            .await
    }
}
