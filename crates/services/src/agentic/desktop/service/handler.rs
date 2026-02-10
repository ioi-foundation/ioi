// Path: crates/services/src/agentic/desktop/service/handler.rs

use super::DesktopAgentService;
use crate::agentic::desktop::execution::ToolExecutor;
use crate::agentic::desktop::types::AgentState;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_drivers::mcp::McpManager;
use ioi_types::app::agentic::AgentTool;
use ioi_types::error::TransactionError;
use serde_jcs;
use serde_json::json;
use std::sync::Arc;

pub async fn handle_action_execution(
    service: &DesktopAgentService,
    tool: AgentTool,
    session_id: [u8; 32],
    step_index: u32,
    visual_phash: [u8; 32],
    rules: &crate::agentic::rules::ActionRules,
    agent_state: &AgentState,
    os_driver: &Arc<dyn OsDriver>,
) -> Result<(bool, Option<String>, Option<String>), TransactionError> {
    let mcp = service
        .mcp
        .clone()
        .unwrap_or_else(|| Arc::new(McpManager::new()));

    // [VERIFIED] This line ensures the registry propagates to execution
    let lens_registry_arc = service.lens_registry.clone();

    let foreground_window = os_driver.get_active_window_info().await.unwrap_or(None);
    let target_app_hint = agent_state.target.as_ref().and_then(|t| t.app_hint.clone());

    // Construct executor locally with all dependencies
    let executor = ToolExecutor::new(
        service.gui.clone(),
        service.terminal.clone(),
        service.browser.clone(),
        mcp,
        service.event_sender.clone(),
        Some(lens_registry_arc),
        service.reasoning_inference.clone(), // Pass reasoning engine for visual search
    )
    .with_window_context(foreground_window, target_app_hint);

    // 1. Serialization for Policy Check
    let tool_value =
        serde_json::to_value(&tool).map_err(|e| TransactionError::Serialization(e.to_string()))?;

    let args_value = if let Some(args) = tool_value.get("arguments") {
        args.clone()
    } else {
        json!({})
    };

    let request_params = serde_jcs::to_vec(&args_value)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;

    // 2. Compute Canonical Tool Bytes for Hash Stability
    let tool_jcs =
        serde_jcs::to_vec(&tool).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).unwrap();
    let mut tool_hash = [0u8; 32];
    tool_hash.copy_from_slice(tool_hash_bytes.as_ref());

    let target = tool.target();

    let dummy_request = ioi_types::app::ActionRequest {
        target: target.clone(),
        params: request_params,
        context: ioi_types::app::ActionContext {
            agent_id: "desktop_agent".into(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: step_index as u64,
    };

    let target_str = match &target {
        ioi_types::app::ActionTarget::Custom(s) => s.clone(),
        _ => serde_json::to_string(&target)
            .unwrap_or_else(|_| "unknown".to_string())
            .trim_matches('"')
            .to_string(),
    };

    // 3. Policy Check
    let skip_policy = matches!(tool, AgentTool::SystemFail { .. });

    if !skip_policy {
        let is_approved = if let Some(token) = &agent_state.pending_approval {
            token.request_hash == tool_hash
        } else {
            false
        };

        if is_approved {
            log::info!(
                "Policy Gate: Pre-approved via Token for hash {}",
                hex::encode(tool_hash)
            );
        } else {
            // Import PolicyEngine from service level
            use crate::agentic::policy::PolicyEngine;
            use crate::agentic::rules::Verdict;

            let verdict = PolicyEngine::evaluate(
                rules,
                &dummy_request,
                &service.scrubber.model,
                os_driver,
                None,
            )
            .await;

            match verdict {
                Verdict::Allow => {}
                Verdict::Block => {
                    if let Some(tx) = &service.event_sender {
                        let _ = tx.send(ioi_types::app::KernelEvent::FirewallInterception {
                            verdict: "BLOCK".to_string(),
                            target: target_str,
                            request_hash: tool_hash,
                            session_id: Some(session_id),
                        });
                    }
                    return Err(TransactionError::Invalid("Blocked by Policy".into()));
                }
                Verdict::RequireApproval => {
                    log::info!(
                        "Policy Gate: RequireApproval for hash: {}",
                        hex::encode(tool_hash)
                    );

                    if let Some(tx) = &service.event_sender {
                        let _ = tx.send(ioi_types::app::KernelEvent::FirewallInterception {
                            verdict: "REQUIRE_APPROVAL".to_string(),
                            target: target_str,
                            request_hash: tool_hash,
                            session_id: Some(session_id),
                        });
                    }
                    return Err(TransactionError::PendingApproval(hex::encode(tool_hash)));
                }
            }
        }
    }

    // Explicitly acquire lease for browser tools
    if matches!(
        tool,
        AgentTool::BrowserNavigate { .. }
            | AgentTool::BrowserExtract { .. }
            | AgentTool::BrowserClick { .. }
            | AgentTool::BrowserSyntheticClick { .. }
    ) {
        service.browser.set_lease(true);
    }

    // 5. Handle Meta-Tools and Execution
    match tool {
        // ... [Meta Tools Logic] ...
        AgentTool::SystemFail {
            reason,
            missing_capability,
        } => {
            log::warn!(
                "Agent explicit failure: {} (Missing: {:?})",
                reason,
                missing_capability
            );
            let error_msg = if let Some(cap) = missing_capability {
                let reason_lc = reason.to_lowercase();
                let is_true_capability_gap = reason_lc.contains("missing tool")
                    || reason_lc.contains("tool is missing")
                    || reason_lc.contains("not listed in your available tools")
                    || reason_lc.contains("capability missing")
                    || reason_lc.contains("tier restricted")
                    || reason_lc.contains("no typing-capable tool is available")
                    || reason_lc.contains("no clipboard-capable tool is available")
                    || reason_lc.contains("no click-capable tool is available")
                    || (reason_lc.contains("no ") && reason_lc.contains("tool") && reason_lc.contains("available"));

                if is_true_capability_gap {
                    format!(
                        "ESCALATE_REQUEST: Missing capability '{}'. Reason: {}",
                        cap, reason
                    )
                } else {
                    // Treat lookup/runtime failures as action failures, not tier/capability upgrades.
                    format!("Agent Failure: {} (claimed capability: '{}')", reason, cap)
                }
            } else {
                format!("Agent Failure: {}", reason)
            };
            if let Some(tx) = &service.event_sender {
                let _ = tx.send(ioi_types::app::KernelEvent::AgentActionResult {
                    session_id,
                    step_index,
                    tool_name: "system::fail".to_string(),
                    output: error_msg.clone(),
                    // [FIX] Authoritative Status
                    agent_status: "Failed".to_string(),
                });
            }
            Ok((false, None, Some(error_msg)))
        }
        AgentTool::AgentDelegate { goal, budget } => {
            let mut child_session_id = [0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut child_session_id);
            if let Some(tx) = &service.event_sender {
                let _ = tx.send(ioi_types::app::KernelEvent::AgentSpawn {
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
        AgentTool::ChatReply { message } => Ok((true, Some(format!("Replied: {}", message)), None)),
        AgentTool::OsFocusWindow { title } => match os_driver.focus_window(&title).await {
            Ok(true) => {
                // Give the window manager a brief moment to apply focus.
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                let focused = os_driver.get_active_window_info().await.unwrap_or(None);
                let msg = if let Some(win) = focused {
                    format!("Focused '{}' ({})", win.title, win.app_name)
                } else {
                    format!("Focus requested for '{}'", title)
                };
                Ok((true, Some(msg), None))
            }
            Ok(false) => Ok((false, None, Some(format!("No window matched '{}'", title)))),
            Err(e) => Ok((
                false,
                None,
                Some(format!("Window focus failed for '{}': {}", title, e)),
            )),
        },
        AgentTool::OsCopy { content } => match os_driver.set_clipboard(&content).await {
            Ok(()) => Ok((true, Some("Copied to clipboard".to_string()), None)),
            Err(e) => Ok((false, None, Some(format!("Clipboard write failed: {}", e)))),
        },
        AgentTool::OsPaste {} => match os_driver.get_clipboard().await {
            Ok(content) => Ok((true, Some(content), None)),
            Err(e) => Ok((false, None, Some(format!("Clipboard read failed: {}", e)))),
        },

        // Delegate Execution Tools
        _ => {
            let result = executor
                .execute(
                    tool,
                    session_id,
                    step_index,
                    visual_phash,
                    agent_state.visual_som_map.as_ref(),
                    agent_state.visual_semantic_map.as_ref(),
                    agent_state.active_lens.as_deref(),
                )
                .await;
            Ok((result.success, result.history_entry, result.error))
        }
    }
}

pub fn select_runtime(
    service: &DesktopAgentService,
    state: &crate::agentic::desktop::types::AgentState,
) -> std::sync::Arc<dyn ioi_api::vm::inference::InferenceRuntime> {
    if state.consecutive_failures > 0 {
        return service.reasoning_inference.clone();
    }
    if state.step_count == 0 {
        return service.reasoning_inference.clone();
    }
    match state.last_action_type.as_deref() {
        Some("gui__click") | Some("gui__type") => {
            // Prefer fast inference if available for simple UI follow-ups
            service.fast_inference.clone()
        }
        _ => service.reasoning_inference.clone(),
    }
}
