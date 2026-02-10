// Path: crates/services/src/agentic/desktop/service/step/queue.rs

use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, StepAgentParams};
use crate::agentic::desktop::execution::ToolExecutor;
use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules; 
use self::super::helpers::default_safe_policy;
use ioi_api::state::StateAccess;
use ioi_drivers::mcp::McpManager;
use ioi_types::app::agentic::AgentTool; 
use ioi_types::error::TransactionError;
use ioi_types::codec;
use serde_json::json;
use std::sync::Arc;

pub async fn process_queue_item(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    p: &StepAgentParams,
) -> Result<(), TransactionError> {
    log::info!(
        "Draining execution queue for session {} (Pending: {})", 
        hex::encode(&p.session_id[..4]), 
        agent_state.execution_queue.len()
    );

    let key = get_state_key(&p.session_id);
    let policy_key = [AGENT_POLICY_PREFIX, p.session_id.as_slice()].concat();
    let rules: ActionRules = state.get(&policy_key)?.and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);

    // Pop the first action
    let action_request = agent_state.execution_queue.remove(0);
    
    // [NEW] Capture the active skill hash for attribution
    let active_skill = agent_state.active_skill_hash;
    
    // [FIX] Removed manual ToolExecutor construction.
    // The service method now handles it internally.
    
    let os_driver = service.os_driver.clone().ok_or(TransactionError::Invalid("OS driver missing".into()))?;

    // Re-construct AgentTool from ActionRequest to reuse execution logic
    let tool_wrapper = match action_request.target {
        ioi_types::app::ActionTarget::Custom(ref name) => {
             let args: serde_json::Value = serde_json::from_slice(&action_request.params).unwrap_or(json!({}));
             let mut wrapper = serde_json::Map::new();
             wrapper.insert("name".to_string(), json!(name));
             wrapper.insert("arguments".to_string(), args);
             AgentTool::Dynamic(serde_json::Value::Object(wrapper))
        },
        _ => {
             // For native targets (e.g. BrowserNavigate), we need to reconstruct the specific enum
             let name = match action_request.target {
                 ioi_types::app::ActionTarget::BrowserNavigate => "browser__navigate",
                 ioi_types::app::ActionTarget::GuiType => "gui__type",
                 ioi_types::app::ActionTarget::GuiClick => "gui__click",
                 ioi_types::app::ActionTarget::SysExec => "sys__exec",
                 _ => return Err(TransactionError::Invalid("Queue execution for this target type pending refactor".into())),
             };

             let args: serde_json::Value = serde_json::from_slice(&action_request.params).unwrap_or(json!({}));
             let mut wrapper = serde_json::Map::new();
             wrapper.insert("name".to_string(), json!(name));
             wrapper.insert("arguments".to_string(), args);
             AgentTool::Dynamic(serde_json::Value::Object(wrapper))
        }
    };

    // Execute
    // [FIX] Updated call: removed executor arg
    let result_tuple = service.handle_action_execution(
        // &executor,  <-- REMOVED
        tool_wrapper, 
        p.session_id, 
        agent_state.step_count, 
        [0u8; 32], 
        &rules, 
        &agent_state, 
        &os_driver
    ).await;

    // [FIX] Explicit type annotation for E0282
    let (success, out, err): (bool, Option<String>, Option<String>) = result_tuple?;
    
    let output_str = out.unwrap_or_default();
    let error_str = err;

    // Log Trace with Provenance
    goto_trace_log(
        agent_state,
        state,
        &key,
        p.session_id,
        [0u8; 32],
        format!("[Macro Step] Executing queued action"),
        output_str,
        success,
        error_str,
        "macro_step".to_string(),
        service.event_sender.clone(),
        active_skill, // [NEW] Pass the skill hash
    )?;

    agent_state.step_count += 1;

    // [NEW] If queue is empty, clear the active skill hash to reset context
    if agent_state.execution_queue.is_empty() {
        agent_state.active_skill_hash = None;
    }

    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    Ok(())
}