use super::{
    await_child_worker_result, load_child_state, parse_child_session_id_hex,
    spawn_delegated_child_session,
};
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::{AgentState, AgentStatus};
use ioi_api::state::StateAccess;
use serde_json::Value;
use std::time::{Duration, Instant};

const BROWSER_SUBAGENT_MAX_WAIT: Duration = Duration::from_secs(300);
const BROWSER_SUBAGENT_DEFAULT_BUDGET: u64 = 144;

#[derive(Debug, Clone)]
pub(crate) struct BrowserSubagentRequest {
    pub task_name: String,
    pub task_summary: String,
    pub recording_name: String,
    pub task: String,
    pub reused_subagent_id: Option<String>,
    pub media_paths: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct BrowserSubagentOutcome {
    pub success: bool,
    pub child_session_id_hex: String,
    pub status: String,
    pub final_report: String,
}

pub(crate) fn browser_subagent_request_from_dynamic(
    dynamic_tool: &Value,
) -> Result<Option<BrowserSubagentRequest>, String> {
    let Some(name) = dynamic_tool.get("name").and_then(Value::as_str) else {
        return Ok(None);
    };
    if !name.eq_ignore_ascii_case("browser__subagent") {
        return Ok(None);
    }

    let arguments = dynamic_tool
        .get("arguments")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            "ERROR_CLASS=UnexpectedState browser__subagent requires an arguments object."
                .to_string()
        })?;
    let required_string = |key: &str| -> Result<String, String> {
        arguments
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                format!(
                    "ERROR_CLASS=UnexpectedState browser__subagent requires a non-empty '{}' field.",
                    key
                )
            })
    };

    let media_paths = arguments
        .get("media_paths")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(Some(BrowserSubagentRequest {
        task_name: required_string("task_name")?,
        task_summary: required_string("task_summary")?,
        recording_name: required_string("recording_name")?,
        task: required_string("task")?,
        reused_subagent_id: arguments
            .get("reused_subagent_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        media_paths,
    }))
}

fn build_browser_subagent_goal(request: &BrowserSubagentRequest) -> String {
    let mut goal = format!(
        "TaskName: {}\nTaskSummary: {}\nRecordingName: {}\n\nTask:\n{}",
        request.task_name.trim(),
        request.task_summary.trim(),
        request.recording_name.trim(),
        request.task.trim()
    );

    if !request.media_paths.is_empty() {
        goal.push_str("\n\n[MEDIA PATHS]\n");
        for path in &request.media_paths {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                goal.push_str("- ");
                goal.push_str(trimmed);
                goal.push('\n');
            }
        }
    }

    goal.push_str(
        "\n[SUBAGENT CONTRACT]\n\
         - Stay within browser tools only.\n\
         - Do not ask the user directly for follow-up.\n\
         - Return one final semantic report to the parent.\n\
         - If approval, secrets, or a hard blocker prevent completion, explicitly say so in the final report.\n",
    );
    goal
}

pub(crate) async fn run_browser_subagent(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    tool_hash: [u8; 32],
    parent_step_index: u32,
    block_height: u64,
    call_context: ServiceCallContext<'_>,
    request: &BrowserSubagentRequest,
) -> Result<BrowserSubagentOutcome, String> {
    let child_session_id_hex = if let Some(reused) = request
        .reused_subagent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        reused.to_string()
    } else {
        let goal = build_browser_subagent_goal(request);
        let spawned = spawn_delegated_child_session(
            service,
            state,
            parent_state,
            tool_hash,
            &goal,
            BROWSER_SUBAGENT_DEFAULT_BUDGET.min(parent_state.budget.saturating_sub(1).max(1)),
            None,
            Some("browser_specialist"),
            Some("browser_subagent_session"),
            Some("Browser Subagent"),
            Some(
                "Return one final semantic browser report with executed_steps, observed_state, goal_status, blocker_summary, approval_state, and notes.",
            ),
            Some("append_summary_to_parent"),
            Some(
                "Browser specialist report using markdown bullets for executed_steps, observed_state, goal_status, blocker_summary, approval_state, and notes.",
            ),
            parent_step_index,
            block_height,
        )
        .await
        .map_err(|error| error.to_string())?;
        hex::encode(spawned.child_session_id)
    };

    let child_session_id = parse_child_session_id_hex(&child_session_id_hex)?;
    let started = Instant::now();

    loop {
        let merged_output = await_child_worker_result(
            service,
            state,
            parent_state,
            parent_step_index,
            block_height,
            call_context,
            &child_session_id_hex,
        )
        .await?;
        let child_state = load_child_state(
            state,
            service.memory_runtime.as_ref(),
            child_session_id,
            &child_session_id_hex,
        )?;

        match &child_state.status {
            AgentStatus::Completed(_) => {
                return Ok(BrowserSubagentOutcome {
                    success: true,
                    child_session_id_hex,
                    status: "completed".to_string(),
                    final_report: merged_output,
                });
            }
            AgentStatus::Failed(reason) => {
                return Ok(BrowserSubagentOutcome {
                    success: false,
                    child_session_id_hex,
                    status: "failed".to_string(),
                    final_report: format!(
                        "{}\n\nBrowser subagent failed: {}",
                        merged_output,
                        reason.trim()
                    ),
                });
            }
            AgentStatus::Paused(reason) => {
                return Ok(BrowserSubagentOutcome {
                    success: false,
                    child_session_id_hex,
                    status: "paused".to_string(),
                    final_report: format!(
                        "{}\n\nBrowser subagent paused and returned control to the parent: {}",
                        merged_output,
                        reason.trim()
                    ),
                });
            }
            AgentStatus::Terminated => {
                return Ok(BrowserSubagentOutcome {
                    success: false,
                    child_session_id_hex,
                    status: "terminated".to_string(),
                    final_report: format!(
                        "{}\n\nBrowser subagent terminated before producing a final report.",
                        merged_output
                    ),
                });
            }
            AgentStatus::Running | AgentStatus::Idle => {
                if started.elapsed() >= BROWSER_SUBAGENT_MAX_WAIT {
                    return Ok(BrowserSubagentOutcome {
                        success: false,
                        child_session_id_hex,
                        status: "timeout".to_string(),
                        final_report: format!(
                            "{}\n\nBrowser subagent exceeded the synchronous wait budget and returned control to the parent.",
                            merged_output
                        ),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
