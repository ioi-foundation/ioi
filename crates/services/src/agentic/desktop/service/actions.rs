// Path: crates/services/src/agentic/desktop/service/actions.rs

use super::DesktopAgentService;
use crate::agentic::desktop::execution::{ToolExecutionResult, ToolExecutor};
use crate::agentic::policy::PolicyEngine;
use crate::agentic::rules::{ActionRules, Verdict};
use ioi_api::vm::drivers::os::OsDriver;
use ioi_drivers::mcp::McpManager;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, KernelEvent};
use ioi_types::error::TransactionError;
use serde_json::Value;
use std::sync::Arc;

impl DesktopAgentService {
    pub(crate) async fn handle_action_execution(
        &self,
        executor: &ToolExecutor,
        name: &str,
        tool_call: &Value,
        session_id: [u8; 32],
        step_index: u32,
        visual_phash: [u8; 32],
        rules: &ActionRules,
        agent_state: &crate::agentic::desktop::types::AgentState,
        os_driver: &Arc<dyn OsDriver>,
    ) -> Result<(bool, Option<String>, Option<String>), TransactionError> {
        let request_params = serde_json::to_vec(&tool_call["arguments"]).unwrap_or_default();

        let target = if name == "filesystem__write_file" {
            ActionTarget::FsWrite
        } else if name == "filesystem__read_file"
            || name == "filesystem__list_allowed_directories"
        {
            ActionTarget::FsRead
        } else if name == "gui__click" {
            ActionTarget::GuiClick
        } else if name == "gui__type" {
            ActionTarget::GuiType
        } else if name == "browser__navigate" {
            ActionTarget::BrowserNavigate
        } else if name == "sys__exec" {
            ActionTarget::SysExec
        } else {
            ActionTarget::Custom(name.to_string())
        };

        let dummy_request = ActionRequest {
            target,
            params: request_params,
            context: ActionContext {
                agent_id: "desktop_agent".into(),
                session_id: Some(session_id),
                window_id: None,
            },
            nonce: step_index as u64,
        };

        // Pass the stored approval token to the policy engine
        let verdict = PolicyEngine::evaluate(
            rules,
            &dummy_request,
            &self.scrubber.model,
            os_driver,
            agent_state.pending_approval.as_ref(),
        )
        .await;

        match verdict {
            Verdict::Allow => {
                // Proceed
            }
            Verdict::Block => {
                return Err(TransactionError::Invalid("Blocked by Policy".into()));
            }
            Verdict::RequireApproval => {
                let req_hash = hex::encode(dummy_request.hash());
                return Err(TransactionError::PendingApproval(req_hash));
            }
        }

        // Special handling for meta-tools
        if name == "agent__delegate" {
            // [NEW] Logic for Delegation (Swarm Spawning)
            // 1. Parse Args
            let args = &tool_call["arguments"];
            let goal = args["goal"].as_str().unwrap_or("Unknown Goal");
            let budget = args["budget"].as_u64().unwrap_or(0);

            // 2. Create Child Identity
            let mut child_session_id = [0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut child_session_id);

            // 3. Emit Event for UI (SwarmViz)
            if let Some(tx) = &self.event_sender {
                let _ = tx.send(KernelEvent::AgentSpawn {
                    parent_session_id: session_id,
                    new_session_id: child_session_id,
                    name: format!("Agent-{}", hex::encode(&child_session_id[0..2])),
                    role: "Sub-Worker".to_string(), // In real impl, infer from goal
                    budget,
                    goal: goal.to_string(),
                });
            }

            // 4. Return the ID to the LLM so it can track its child
            return Ok((
                true,
                Some(format!(
                    "Delegated to child agent. Session ID: {}",
                    hex::encode(child_session_id)
                )),
                None,
            ));
        } else if name == "agent__await_result" {
            return Ok((true, None, None));
        } else if name == "agent__pause" {
            return Ok((true, None, None));
        } else if name == "agent__complete" {
            return Ok((true, None, None));
        } else if name == "commerce__checkout" {
            return Ok((
                true,
                Some("System: Initiated UCP Checkout (Pending Guardian Approval)".to_string()),
                None,
            ));
        } else {
            // Driver Execution
            let result = executor
                .execute(name, tool_call, session_id, step_index, visual_phash)
                .await;
            return Ok((result.success, result.history_entry, result.error));
        }
    }
}