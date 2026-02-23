use crate::agentic::desktop::keys::get_state_key;
use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::AgentTool;
use ioi_types::codec;
use ioi_types::error::TransactionError;

#[derive(Debug, Clone)]
pub struct WorkerExecutionResult {
    pub success: bool,
    pub output: Option<String>,
    pub error: Option<String>,
    pub attempts: u8,
}

pub async fn execute_worker_step(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    call_context: ServiceCallContext<'_>,
    rules: &ActionRules,
    worker_session_id: [u8; 32],
    tool: AgentTool,
    max_retries: u8,
) -> Result<WorkerExecutionResult, TransactionError> {
    let key = get_state_key(&worker_session_id);
    let bytes = state.get(&key)?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "Worker session not found: {}",
            hex::encode(worker_session_id)
        ))
    })?;
    let mut worker_state: AgentState = codec::from_bytes_canonical(&bytes)?;
    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;

    let mut output: Option<String> = None;
    let mut error: Option<String> = None;
    let mut success = false;
    let mut attempts: u8 = 0;

    for attempt in 0..=max_retries {
        attempts = attempt.saturating_add(1);
        match service
            .handle_action_execution_with_state(
                state,
                call_context,
                tool.clone(),
                worker_session_id,
                worker_state.step_count,
                worker_state.last_screen_phash.unwrap_or([0u8; 32]),
                rules,
                &worker_state,
                &os_driver,
                None,
            )
            .await
        {
            Ok((step_success, history_entry, step_error)) => {
                output = history_entry;
                error = step_error;
                if step_success {
                    success = true;
                    break;
                }
            }
            Err(err) => {
                error = Some(err.to_string());
            }
        }
        worker_state.consecutive_failures = worker_state.consecutive_failures.saturating_add(1);
    }

    worker_state.step_count = worker_state.step_count.saturating_add(1);
    worker_state.status = if success {
        AgentStatus::Completed(output.clone())
    } else {
        AgentStatus::Failed(
            error
                .clone()
                .unwrap_or_else(|| "worker step failed".to_string()),
        )
    };
    state.insert(&key, &codec::to_bytes_canonical(&worker_state)?)?;

    Ok(WorkerExecutionResult {
        success,
        output,
        error,
        attempts,
    })
}
