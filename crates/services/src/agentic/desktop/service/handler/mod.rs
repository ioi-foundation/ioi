use super::DesktopAgentService;
use crate::agentic::desktop::execution::ToolExecutor;
use crate::agentic::desktop::service::step::action::{
    is_search_results_url, search_query_from_url,
};
use crate::agentic::desktop::service::step::helpers::is_live_external_research_goal;
use crate::agentic::desktop::service::step::queue::WEB_PIPELINE_SEARCH_LIMIT;
use crate::agentic::desktop::types::{AgentState, RecordedMessage};
use ioi_api::vm::drivers::os::OsDriver;
use ioi_drivers::mcp::McpManager;
use ioi_scs::FrameType;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile, ResolvedIntentState};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::json;
use std::sync::Arc;

mod approvals;
mod focus;
mod pii;

pub(crate) use pii::{
    build_pii_review_request_for_tool, emit_pii_review_requested, persist_pii_review_request,
};

fn normalize_web_research_tool_call(
    tool: &mut AgentTool,
    resolved_intent: Option<&ResolvedIntentState>,
    fallback_query: &str,
) {
    let is_web_research_scope = resolved_intent
        .map(|resolved| resolved.scope == IntentScopeProfile::WebResearch)
        .unwrap_or(false);
    let is_live_external_research = is_live_external_research_goal(fallback_query);
    let is_effective_web_research = is_web_research_scope || is_live_external_research;
    if !is_effective_web_research {
        return;
    }

    match tool {
        AgentTool::BrowserNavigate { url } => {
            if !is_search_results_url(url) {
                return;
            }

            let query = search_query_from_url(url)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| fallback_query.trim().to_string());
            if query.trim().is_empty() {
                return;
            }

            *tool = AgentTool::WebSearch {
                query: query.clone(),
                limit: Some(WEB_PIPELINE_SEARCH_LIMIT),
                url: Some(crate::agentic::web::build_default_search_url(&query)),
            };
        }
        AgentTool::WebSearch { query, limit, url } => {
            let normalized_query = if query.trim().is_empty() {
                fallback_query.trim().to_string()
            } else {
                query.trim().to_string()
            };
            if normalized_query.is_empty() {
                return;
            }
            *query = normalized_query.clone();
            *limit = Some(WEB_PIPELINE_SEARCH_LIMIT);
            if url
                .as_ref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
            {
                *url = Some(crate::agentic::web::build_default_search_url(
                    &normalized_query,
                ));
            }
        }
        AgentTool::MemorySearch { query } => {
            let normalized_query = if query.trim().is_empty() {
                fallback_query.trim().to_string()
            } else {
                query.trim().to_string()
            };
            if normalized_query.is_empty() {
                return;
            }

            // WebResearch is expected to gather fresh external evidence; avoid
            // memory-only retrieval loops by pivoting memory search to web search.
            *tool = AgentTool::WebSearch {
                query: normalized_query.clone(),
                limit: Some(WEB_PIPELINE_SEARCH_LIMIT),
                url: Some(crate::agentic::web::build_default_search_url(
                    &normalized_query,
                )),
            };
        }
        _ => {}
    }
}

pub async fn handle_action_execution(
    service: &DesktopAgentService,
    tool: AgentTool,
    session_id: [u8; 32],
    step_index: u32,
    visual_phash: [u8; 32],
    rules: &crate::agentic::rules::ActionRules,
    agent_state: &AgentState,
    os_driver: &Arc<dyn OsDriver>,
    scoped_exception_hash: Option<[u8; 32]>,
) -> Result<(bool, Option<String>, Option<String>), TransactionError> {
    let mut tool = tool;

    let mcp = service
        .mcp
        .clone()
        .unwrap_or_else(|| Arc::new(McpManager::new()));

    // [VERIFIED] This line ensures the registry propagates to execution
    let lens_registry_arc = service.lens_registry.clone();

    let mut foreground_window = os_driver.get_active_window_info().await.unwrap_or(None);
    let target_app_hint = agent_state.target.as_ref().and_then(|t| t.app_hint.clone());

    // Pre-policy normalization:
    // - Convert search-result browser navigation into governed `web__search` for WebResearch.
    // - Ensure `web__search` carries a computed SERP URL for deterministic policy hashing.
    normalize_web_research_tool_call(
        &mut tool,
        agent_state.resolved_intent.as_ref(),
        &agent_state.goal,
    );

    // `web__search` carries a computed SERP URL for deterministic
    // policy enforcement + hashing (the model should only provide the query).
    if let AgentTool::WebSearch { query, url, .. } = &mut tool {
        if url.as_ref().map(|u| u.trim().is_empty()).unwrap_or(true) {
            *url = Some(crate::agentic::web::build_default_search_url(query));
        }
    }

    // Stage D transform-first enforcement for egress-capable tools.
    pii::apply_pii_transform_first(service, rules, session_id, scoped_exception_hash, &mut tool)
        .await?;

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

    let mut target = tool.target();
    // `FrameType::Observation` inspection can invoke screenshot captioning; gate it via a
    // distinct policy target so default-safe rules can require explicit approval.
    if let AgentTool::MemoryInspect { frame_id } = &tool {
        if let Some(scs_mutex) = service.scs.as_ref() {
            if let Ok(store) = scs_mutex.lock() {
                if let Some(frame) = store.toc.frames.get(*frame_id as usize) {
                    if matches!(frame.frame_type, FrameType::Observation) {
                        target = ioi_types::app::ActionTarget::Custom(
                            "memory::inspect_observation".to_string(),
                        );
                    }
                }
            }
        }
    }

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
        let approved_by_token = agent_state
            .pending_approval
            .as_ref()
            .map(|token| token.request_hash == tool_hash)
            .unwrap_or(false);
        let approved_by_runtime_secret = approvals::is_runtime_secret_install_retry_approved(
            &tool,
            tool_hash,
            session_id,
            agent_state,
        );
        let is_approved = approved_by_token || approved_by_runtime_secret;

        if is_approved {
            if approved_by_token {
                log::info!(
                    "Policy Gate: Pre-approved via Token for hash {}",
                    hex::encode(tool_hash)
                );
            } else {
                log::info!(
                    "Policy Gate: Pre-approved via runtime secret retry for hash {}",
                    hex::encode(tool_hash)
                );
            }
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

    // Pre-execution focus recovery for click-like tools.
    // This reduces FocusMismatch loops by verifying/repairing focus before click dispatch.
    if focus::is_focus_sensitive_tool(&tool) {
        if let Some(hint) = target_app_hint
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
        {
            if !focus::window_matches_hint(foreground_window.as_ref(), hint) {
                match os_driver.focus_window(hint).await {
                    Ok(true) => {
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        foreground_window =
                            os_driver.get_active_window_info().await.unwrap_or(None);
                        if !focus::window_matches_hint(foreground_window.as_ref(), hint) {
                            return Ok((
                                false,
                                None,
                                Some(format!(
                                    "ERROR_CLASS=FocusMismatch Focused window still does not match target '{}'.",
                                    hint
                                )),
                            ));
                        }
                    }
                    Ok(false) => {
                        return Ok((
                            false,
                            None,
                            Some(format!(
                                "ERROR_CLASS=FocusMismatch Unable to focus target window '{}'.",
                                hint
                            )),
                        ));
                    }
                    Err(e) => {
                        let err = e.to_string();
                        if focus::is_missing_focus_dependency_error(&err) {
                            return Ok((
                                false,
                                None,
                                Some(format!(
                                    "ERROR_CLASS=MissingDependency Focus dependency unavailable while focusing '{}': {}",
                                    hint, err
                                )),
                            ));
                        }
                        return Ok((
                            false,
                            None,
                            Some(format!(
                                "ERROR_CLASS=FocusMismatch Focus attempt failed for '{}': {}",
                                hint, err
                            )),
                        ));
                    }
                }
            }
        }
    }

    // Construct executor locally with all dependencies after focus recovery.
    let executor = ToolExecutor::new(
        service.gui.clone(),
        os_driver.clone(),
        service.terminal.clone(),
        service.browser.clone(),
        mcp,
        service.event_sender.clone(),
        Some(lens_registry_arc),
        service.reasoning_inference.clone(), // Pass reasoning engine for visual search
        Some(service.scrubber.clone()),
    )
    .with_window_context(
        foreground_window.clone(),
        target_app_hint.clone(),
        Some(agent_state.current_tier),
    )
    .with_expected_visual_hash(Some(visual_phash))
    .with_working_directory(Some(agent_state.working_directory.clone()));

    // Explicitly acquire lease for browser tools
    if matches!(
        tool,
        AgentTool::BrowserNavigate { .. }
            | AgentTool::BrowserSnapshot { .. }
            | AgentTool::BrowserClick { .. }
            | AgentTool::BrowserClickElement { .. }
            | AgentTool::BrowserSyntheticClick { .. }
            | AgentTool::BrowserScroll { .. }
            | AgentTool::BrowserType { .. }
            | AgentTool::BrowserKey { .. }
    ) {
        service.browser.set_lease(true);
    }

    // 5. Handle Meta-Tools and Execution
    match tool {
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
                    || (reason_lc.contains("no ")
                        && reason_lc.contains("tool")
                        && reason_lc.contains("available"));

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
                    tool_name: "system__fail".to_string(),
                    output: error_msg.clone(),
                    // [FIX] Authoritative Status
                    agent_status: "Failed".to_string(),
                });
            }
            Ok((false, None, Some(error_msg)))
        }
        AgentTool::MemorySearch { query } => {
            if service.scs.is_none() {
                return Ok((
                    false,
                    None,
                    Some(
                        "ERROR_CLASS=ToolUnavailable memory__search requires an SCS-backed memory store."
                            .to_string(),
                    ),
                ));
            }

            let trimmed = query.trim();
            if trimmed.is_empty() {
                return Ok((
                    false,
                    None,
                    Some(
                        "ERROR_CLASS=TargetNotFound memory__search requires a non-empty query."
                            .to_string(),
                    ),
                ));
            }

            let out = service.retrieve_context_hybrid(trimmed, None).await;
            let out = if out.trim().is_empty() {
                "No matching memories found.".to_string()
            } else {
                out
            };
            Ok((true, Some(out), None))
        }
        AgentTool::MemoryInspect { frame_id } => {
            let scs_mutex = match service.scs.as_ref() {
                Some(m) => m,
                None => {
                    return Ok((
                        false,
                        None,
                        Some(
                            "ERROR_CLASS=ToolUnavailable memory__inspect requires an SCS-backed memory store."
                                .to_string(),
                        ),
                    ))
                }
            };

            let frame_type = {
                let store = match scs_mutex.lock() {
                    Ok(store) => store,
                    Err(_) => {
                        return Ok((
                            false,
                            None,
                            Some("ERROR_CLASS=UnexpectedState SCS lock poisoned.".to_string()),
                        ))
                    }
                };

                match store.toc.frames.get(frame_id as usize) {
                    Some(frame) => frame.frame_type,
                    None => {
                        return Ok((
                            false,
                            None,
                            Some(format!(
                                "ERROR_CLASS=TargetNotFound Frame {} not found in memory store.",
                                frame_id
                            )),
                        ))
                    }
                }
            };

            match frame_type {
                FrameType::Observation => match service.inspect_frame(frame_id).await {
                    Ok(desc) => Ok((true, Some(desc), None)),
                    Err(e) => Ok((
                        false,
                        None,
                        Some(format!(
                            "ERROR_CLASS=UnexpectedState memory__inspect failed: {}",
                            e
                        )),
                    )),
                },
                FrameType::Thought | FrameType::Action => {
                    let payload = {
                        let store = match scs_mutex.lock() {
                            Ok(store) => store,
                            Err(_) => {
                                return Ok((
                                    false,
                                    None,
                                    Some("ERROR_CLASS=UnexpectedState SCS lock poisoned."
                                        .to_string()),
                                ))
                            }
                        };

                        match store.read_frame_payload(frame_id) {
                            Ok(payload) => payload,
                            Err(e) => {
                                return Ok((
                                    false,
                                    None,
                                    Some(format!(
                                        "ERROR_CLASS=UnexpectedState Failed to read frame payload: {}",
                                        e
                                    )),
                                ))
                            }
                        }
                    };

                    match codec::from_bytes_canonical::<RecordedMessage>(&payload) {
                        Ok(recorded) => {
                            let content = if recorded.scrubbed_for_model.is_empty() {
                                recorded.scrubbed_for_scs
                            } else {
                                recorded.scrubbed_for_model
                            };
                            let out = serde_json::json!({
                                "frame_id": frame_id,
                                "frame_type": format!("{:?}", frame_type),
                                "role": recorded.role,
                                "timestamp_ms": recorded.timestamp_ms,
                                "content": content,
                            })
                            .to_string();
                            Ok((true, Some(out), None))
                        }
                        Err(_) => Ok((
                            true,
                            Some(format!(
                                "{{\"frame_id\":{},\"frame_type\":\"{:?}\",\"content\":\"<Non-Recorded Payload>\"}}",
                                frame_id, frame_type
                            )),
                            None,
                        )),
                    }
                }
                _ => Ok((
                    true,
                    Some(format!(
                        "{{\"frame_id\":{},\"frame_type\":\"{:?}\",\"content\":\"<Unsupported Frame Type>\"}}",
                        frame_id, frame_type
                    )),
                    None,
                )),
            }
        }
        AgentTool::AgentDelegate { goal, budget } => {
            // Orchestration is stateful; spawning the child session is handled in the step layer
            // so receipts + session state mutations remain atomic and auditable.
            let _ = (goal, budget);
            Ok((true, None, None))
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
            Err(e) => {
                let err = e.to_string();
                if focus::is_missing_focus_dependency_error(&err) {
                    Ok((
                        false,
                        None,
                        Some(format!(
                            "ERROR_CLASS=MissingDependency Focus dependency unavailable for '{}': {}",
                            title, err
                        )),
                    ))
                } else {
                    Ok((
                        false,
                        None,
                        Some(format!("Window focus failed for '{}': {}", title, err)),
                    ))
                }
            }
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

#[cfg(test)]
mod tests {
    use super::approvals::is_runtime_secret_install_retry_approved;
    use super::focus::is_focus_sensitive_tool;
    use super::normalize_web_research_tool_call;
    use crate::agentic::desktop::runtime_secret;
    use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
    use ioi_types::app::agentic::{
        AgentTool, ComputerAction, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    };
    use std::collections::BTreeMap;

    fn test_agent_state() -> AgentState {
        AgentState {
            session_id: [0u8; 32],
            goal: "test".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 1,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,

            awaiting_intent_clarification: false,

            working_directory: ".".to_string(),
            active_lens: None,
            pending_search_completion: None,
            command_history: Default::default(),
        }
    }

    #[test]
    fn right_click_variants_require_focus_recovery() {
        assert!(is_focus_sensitive_tool(&AgentTool::Computer(
            ComputerAction::RightClick {
                coordinate: Some([10, 20]),
            },
        )));
        assert!(is_focus_sensitive_tool(&AgentTool::Computer(
            ComputerAction::RightClickId { id: 12 },
        )));
        assert!(is_focus_sensitive_tool(&AgentTool::Computer(
            ComputerAction::RightClickElement {
                id: "file_row".to_string(),
            },
        )));
    }

    #[test]
    fn browser_click_tools_do_not_require_native_focus_recovery() {
        assert!(!is_focus_sensitive_tool(&AgentTool::BrowserClick {
            selector: "#submit".to_string(),
        }));
        assert!(!is_focus_sensitive_tool(&AgentTool::BrowserClickElement {
            id: "btn_submit".to_string(),
        }));
        assert!(!is_focus_sensitive_tool(
            &AgentTool::BrowserSyntheticClick { x: 20, y: 30 }
        ));
    }

    #[test]
    fn runtime_secret_retry_is_approved_only_for_matching_pending_install() {
        let session_id = [9u8; 32];
        let session_hex = hex::encode(session_id);
        runtime_secret::set_secret(&session_hex, "sudo_password", "pw".to_string(), true, 60)
            .expect("set runtime sudo secret");

        let mut state = test_agent_state();
        let hash = [7u8; 32];
        state.pending_tool_hash = Some(hash);

        let install_tool = AgentTool::SysInstallPackage {
            package: "gnome-calculator".to_string(),
            manager: Some("apt-get".to_string()),
        };
        assert!(is_runtime_secret_install_retry_approved(
            &install_tool,
            hash,
            session_id,
            &state
        ));

        assert!(!is_runtime_secret_install_retry_approved(
            &install_tool,
            [8u8; 32],
            session_id,
            &state
        ));

        let non_install = AgentTool::SysExec {
            command: "echo".to_string(),
            args: vec!["ok".to_string()],
            stdin: None,
            detach: false,
        };
        assert!(!is_runtime_secret_install_retry_approved(
            &non_install,
            hash,
            session_id,
            &state
        ));
    }

    fn resolved(scope: IntentScopeProfile) -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "test".to_string(),
            scope,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            constrained: false,
        }
    }

    #[test]
    fn rewrites_search_navigation_to_web_search_for_web_research_scope() {
        let mut tool = AgentTool::BrowserNavigate {
            url: "https://duckduckgo.com/?q=latest+news".to_string(),
        };
        let intent = resolved(IntentScopeProfile::WebResearch);

        normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback query");

        match tool {
            AgentTool::WebSearch { query, limit, url } => {
                assert_eq!(query, "latest news");
                assert_eq!(limit, Some(super::WEB_PIPELINE_SEARCH_LIMIT));
                let expected = crate::agentic::web::build_default_search_url("latest news");
                assert_eq!(url.as_deref(), Some(expected.as_str()));
            }
            other => panic!("expected WebSearch, got {:?}", other),
        }
    }

    #[test]
    fn does_not_rewrite_non_search_navigation_or_non_web_scope() {
        let mut tool = AgentTool::BrowserNavigate {
            url: "https://example.com/news".to_string(),
        };
        let intent = resolved(IntentScopeProfile::WebResearch);
        normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback query");
        assert!(matches!(tool, AgentTool::BrowserNavigate { .. }));

        let mut scoped_tool = AgentTool::BrowserNavigate {
            url: "https://duckduckgo.com/?q=latest+news".to_string(),
        };
        let non_web_intent = resolved(IntentScopeProfile::Conversation);
        normalize_web_research_tool_call(&mut scoped_tool, Some(&non_web_intent), "fallback");
        assert!(matches!(scoped_tool, AgentTool::BrowserNavigate { .. }));
    }

    #[test]
    fn normalizes_direct_web_search_limit_for_web_research_scope() {
        let mut tool = AgentTool::WebSearch {
            query: "top US breaking news last 6 hours".to_string(),
            limit: Some(3),
            url: None,
        };
        let intent = resolved(IntentScopeProfile::WebResearch);
        normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback");

        match tool {
            AgentTool::WebSearch { query, limit, url } => {
                assert_eq!(query, "top US breaking news last 6 hours");
                assert_eq!(limit, Some(super::WEB_PIPELINE_SEARCH_LIMIT));
                let expected = crate::agentic::web::build_default_search_url(
                    "top US breaking news last 6 hours",
                );
                assert_eq!(url.as_deref(), Some(expected.as_str()));
            }
            other => panic!("expected WebSearch, got {:?}", other),
        }
    }

    #[test]
    fn rewrites_memory_search_to_web_search_for_web_research_scope() {
        let mut tool = AgentTool::MemorySearch {
            query: "active cloud incidents us impact".to_string(),
        };
        let intent = resolved(IntentScopeProfile::WebResearch);
        normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback");

        match tool {
            AgentTool::WebSearch { query, limit, url } => {
                assert_eq!(query, "active cloud incidents us impact");
                assert_eq!(limit, Some(super::WEB_PIPELINE_SEARCH_LIMIT));
                let expected = crate::agentic::web::build_default_search_url(
                    "active cloud incidents us impact",
                );
                assert_eq!(url.as_deref(), Some(expected.as_str()));
            }
            other => panic!("expected WebSearch, got {:?}", other),
        }
    }

    #[test]
    fn rewrites_empty_memory_search_with_fallback_for_web_research_scope() {
        let mut tool = AgentTool::MemorySearch {
            query: "   ".to_string(),
        };
        let intent = resolved(IntentScopeProfile::WebResearch);
        normalize_web_research_tool_call(
            &mut tool,
            Some(&intent),
            "as of now top active us cloud incidents",
        );

        match tool {
            AgentTool::WebSearch { query, limit, url } => {
                assert_eq!(query, "as of now top active us cloud incidents");
                assert_eq!(limit, Some(super::WEB_PIPELINE_SEARCH_LIMIT));
                let expected = crate::agentic::web::build_default_search_url(
                    "as of now top active us cloud incidents",
                );
                assert_eq!(url.as_deref(), Some(expected.as_str()));
            }
            other => panic!("expected WebSearch, got {:?}", other),
        }
    }

    #[test]
    fn rewrites_memory_search_when_live_external_research_goal_overrides_scope() {
        let mut tool = AgentTool::MemorySearch {
            query: "active cloud incidents us impact".to_string(),
        };
        let workspace_intent = resolved(IntentScopeProfile::WorkspaceOps);
        normalize_web_research_tool_call(
            &mut tool,
            Some(&workspace_intent),
            "As of now (UTC), top active cloud incidents with citations",
        );

        match tool {
            AgentTool::WebSearch { query, limit, url } => {
                assert_eq!(query, "active cloud incidents us impact");
                assert_eq!(limit, Some(super::WEB_PIPELINE_SEARCH_LIMIT));
                let expected = crate::agentic::web::build_default_search_url(
                    "active cloud incidents us impact",
                );
                assert_eq!(url.as_deref(), Some(expected.as_str()));
            }
            other => panic!("expected WebSearch, got {:?}", other),
        }
    }

    #[test]
    fn does_not_rewrite_memory_search_for_workspace_local_goal() {
        let mut tool = AgentTool::MemorySearch {
            query: "intent resolver".to_string(),
        };
        let workspace_intent = resolved(IntentScopeProfile::WorkspaceOps);
        normalize_web_research_tool_call(
            &mut tool,
            Some(&workspace_intent),
            "Search the repository for intent resolver code and patch tests",
        );

        assert!(matches!(tool, AgentTool::MemorySearch { .. }));
    }
}
