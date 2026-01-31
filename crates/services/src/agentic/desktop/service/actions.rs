// Path: crates/services/src/agentic/desktop/service/actions.rs

use super::DesktopAgentService;
use crate::agentic::desktop::execution::ToolExecutor;
use crate::agentic::policy::PolicyEngine;
use crate::agentic::rules::{ActionRules, Verdict};
use ioi_api::vm::drivers::os::OsDriver;
use ioi_types::app::agentic::AgentTool; 
use ioi_types::app::{ActionContext, ActionRequest, KernelEvent};
use ioi_types::error::TransactionError;
use std::sync::Arc;
use serde_jcs; // [FIX] Import Canonical JSON serializer

impl DesktopAgentService {

    pub(crate) async fn handle_action_execution(
        &self,
        executor: &ToolExecutor,
        tool: AgentTool, 
        session_id: [u8; 32],
        step_index: u32,
        visual_phash: [u8; 32],
        rules: &ActionRules,
        agent_state: &crate::agentic::desktop::types::AgentState,
        os_driver: &Arc<dyn OsDriver>,
    ) -> Result<(bool, Option<String>, Option<String>), TransactionError> {
        
        // 1. Determine Target from Type-Safe Definition
        let target = tool.target();
        
        // 2. Canonicalize Parameters (Serialize the Enum itself)
        // [FIX] Use Canonical JSON (RFC 8785). This ensures the hash remains stable
        // even if the LLM output keys in a different order upon resume.
        let request_params = serde_jcs::to_vec(&tool)
            .map_err(|e| TransactionError::Serialization(e.to_string()))?;

        let dummy_request = ActionRequest {
            target: target.clone(),
            params: request_params,
            context: ActionContext {
                agent_id: "desktop_agent".into(),
                session_id: Some(session_id),
                window_id: None,
            },
            nonce: step_index as u64,
        };
        
        // Canonicalize the target enum variant name into a string to prevent formatting mismatches
        // [FIX] Handle Custom variant cleanly to match policy rules
        let target_str = match &target {
            ioi_types::app::ActionTarget::Custom(s) => s.clone(),
            _ => serde_json::to_string(&target)
                .unwrap_or_else(|_| "unknown".to_string())
                .trim_matches('"')
                .to_string(),
        };

        // 3. Policy Check
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
                // Emit Block Event to UI
                if let Some(tx) = &self.event_sender {
                    let _ = tx.send(KernelEvent::FirewallInterception {
                        verdict: "BLOCK".to_string(),
                        target: target_str,
                        request_hash: dummy_request.hash(),
                        session_id: Some(session_id),
                    });
                }
                return Err(TransactionError::Invalid("Blocked by Policy".into()));
            }
            Verdict::RequireApproval => {
                let req_hash = hex::encode(dummy_request.hash());
                log::info!("Policy verification failed for target {:?}. Hash: {}", target, req_hash);
                
                // Emit Gate Event to UI
                if let Some(tx) = &self.event_sender {
                    let _ = tx.send(KernelEvent::FirewallInterception {
                        verdict: "REQUIRE_APPROVAL".to_string(),
                        target: target_str,
                        request_hash: dummy_request.hash(),
                        session_id: Some(session_id),
                    });
                }

                return Err(TransactionError::PendingApproval(req_hash));
            }
        }

        // 4. Handle Meta-Tools and Execution
        match tool {
            AgentTool::AgentDelegate { goal, budget } => {
                let mut child_session_id = [0u8; 32];
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut child_session_id);

                if let Some(tx) = &self.event_sender {
                    let _ = tx.send(KernelEvent::AgentSpawn {
                        parent_session_id: session_id,
                        new_session_id: child_session_id,
                        name: format!("Agent-{}", hex::encode(&child_session_id[0..2])),
                        role: "Sub-Worker".to_string(),
                        budget,
                        goal: goal.clone(),
                    });
                }

                Ok((
                    true,
                    Some(format!(
                        "Delegated to child agent. Session ID: {}",
                        hex::encode(child_session_id)
                    )),
                    None,
                ))
            }
            AgentTool::AgentAwait { .. } => Ok((true, None, None)),
            AgentTool::AgentPause { .. } => Ok((true, None, None)),
            AgentTool::AgentComplete { .. } => Ok((true, None, None)),
            AgentTool::CommerceCheckout { .. } => Ok((
                true,
                Some("System: Initiated UCP Checkout (Pending Guardian Approval)".to_string()),
                None,
            )),
            _ => {
                // 5. Native Driver Execution
                let result = executor
                    .execute(tool, session_id, step_index, visual_phash)
                    .await;
                Ok((result.success, result.history_entry, result.error))
            }
        }
    }
}