// Path: crates/services/src/agentic/desktop/service/handler.rs

use super::DesktopAgentService;
use crate::agentic::desktop::execution::ToolExecutor;
use crate::agentic::desktop::runtime_secret;
use crate::agentic::desktop::types::AgentState;
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_drivers::mcp::McpManager;
use ioi_pii::{build_decision_material, build_review_summary, RiskSurface, REVIEW_REQUEST_VERSION};
use ioi_types::app::agentic::{
    AgentTool, ComputerAction, PiiEgressRiskSurface, PiiReviewRequest, PiiTarget,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_jcs;
use serde_json::json;
use std::sync::Arc;

const RUNTIME_SECRET_KIND_SUDO_PASSWORD: &str = "sudo_password";

fn is_focus_sensitive_tool(tool: &AgentTool) -> bool {
    match tool {
        AgentTool::GuiClick { .. }
        | AgentTool::GuiScroll { .. }
        | AgentTool::GuiClickElement { .. } => true,
        AgentTool::Computer(action) => matches!(
            action,
            ComputerAction::LeftClick { .. }
                | ComputerAction::LeftClickId { .. }
                | ComputerAction::LeftClickElement { .. }
                | ComputerAction::RightClick { .. }
                | ComputerAction::DoubleClick { .. }
                | ComputerAction::RightClickId { .. }
                | ComputerAction::RightClickElement { .. }
                | ComputerAction::LeftClickDrag { .. }
                | ComputerAction::DragDrop { .. }
                | ComputerAction::DragDropId { .. }
                | ComputerAction::DragDropElement { .. }
                | ComputerAction::Scroll { .. }
        ),
        _ => false,
    }
}

fn window_matches_hint(window: Option<&WindowInfo>, hint: &str) -> bool {
    let normalized = hint.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return true;
    }

    if let Some(win) = window {
        let title = win.title.to_ascii_lowercase();
        let app = win.app_name.to_ascii_lowercase();
        title.contains(&normalized) || app.contains(&normalized)
    } else {
        false
    }
}

fn is_missing_focus_dependency_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("error_class=missingdependency")
        || (lower.contains("wmctrl")
            && (lower.contains("no such file")
                || lower.contains("not found")
                || lower.contains("missing dependency")))
}

fn is_runtime_secret_install_retry_approved(
    tool: &AgentTool,
    tool_hash: [u8; 32],
    session_id: [u8; 32],
    agent_state: &AgentState,
) -> bool {
    if !matches!(tool, AgentTool::SysInstallPackage { .. }) {
        return false;
    }
    if agent_state.pending_tool_hash != Some(tool_hash) {
        return false;
    }

    let session_id_hex = hex::encode(session_id);
    runtime_secret::has_secret(&session_id_hex, RUNTIME_SECRET_KIND_SUDO_PASSWORD)
}

fn to_shared_risk_surface(risk_surface: PiiEgressRiskSurface) -> RiskSurface {
    match risk_surface {
        PiiEgressRiskSurface::Egress => RiskSurface::Egress,
    }
}

async fn enforce_text_egress_policy(
    service: &DesktopAgentService,
    rules: &crate::agentic::rules::ActionRules,
    session_id: [u8; 32],
    target: &PiiTarget,
    risk_surface: RiskSurface,
    supports_transform: bool,
    scoped_exception_hash: Option<[u8; 32]>,
    text: &mut String,
) -> Result<(), TransactionError> {
    let target_label = target.canonical_label();
    let (scrubbed, _map, report, routed, evidence) = service
        .scrubber
        .inspect_route_transform(
            text,
            target,
            risk_surface,
            &rules.pii_controls,
            supports_transform,
        )
        .await
        .map_err(|e| {
            TransactionError::Invalid(format!(
                "PII inspection failed for target '{}': {}",
                target_label, e
            ))
        })?;

    if let Some(tx) = &service.event_sender {
        let _ = tx.send(ioi_types::app::KernelEvent::PiiDecisionReceipt(
            ioi_types::app::PiiDecisionReceiptEvent {
                session_id: Some(session_id),
                target: target_label.clone(),
                target_id: Some(target.clone()),
                risk_surface: match risk_surface {
                    RiskSurface::LocalProcessing => "local_processing".to_string(),
                    RiskSurface::Egress => "egress".to_string(),
                },
                decision_hash: routed.decision_hash,
                decision: routed.decision.clone(),
                transform_plan_id: routed.transform_plan.as_ref().map(|p| p.plan_id.clone()),
                span_count: evidence.spans.len() as u32,
                ambiguous: evidence.ambiguous,
                stage2_kind: routed.stage2_decision.as_ref().map(|d| {
                    match d {
                        ioi_types::app::agentic::Stage2Decision::ApproveTransformPlan {
                            ..
                        } => "approve_transform_plan",
                        ioi_types::app::agentic::Stage2Decision::Deny { .. } => "deny",
                        ioi_types::app::agentic::Stage2Decision::RequestMoreInfo { .. } => {
                            "request_more_info"
                        }
                        ioi_types::app::agentic::Stage2Decision::GrantScopedException {
                            ..
                        } => "grant_scoped_exception",
                    }
                    .to_string()
                }),
                assist_invoked: routed.assist.assist_invoked,
                assist_applied: routed.assist.assist_applied,
                assist_kind: routed.assist.assist_kind.clone(),
                assist_version: routed.assist.assist_version.clone(),
                assist_identity_hash: routed.assist.assist_identity_hash,
                assist_input_graph_hash: routed.assist.assist_input_graph_hash,
                assist_output_graph_hash: routed.assist.assist_output_graph_hash,
            },
        ));
    }

    let scoped_exception_applies = scoped_exception_hash == Some(routed.decision_hash);

    match routed.decision {
        ioi_types::app::agentic::FirewallDecision::Allow
        | ioi_types::app::agentic::FirewallDecision::AllowLocalOnly => Ok(()),
        ioi_types::app::agentic::FirewallDecision::RedactThenAllow
        | ioi_types::app::agentic::FirewallDecision::TokenizeThenAllow => {
            if !supports_transform {
                if scoped_exception_applies {
                    return Ok(());
                }
                if let Some(tx) = &service.event_sender {
                    let _ = tx.send(ioi_types::app::KernelEvent::FirewallInterception {
                        verdict: "REQUIRE_APPROVAL".to_string(),
                        target: target_label.clone(),
                        request_hash: routed.decision_hash,
                        session_id: Some(session_id),
                    });
                }
                return Err(TransactionError::PendingApproval(hex::encode(
                    routed.decision_hash,
                )));
            }
            if !report.no_raw_substring_leak {
                return Err(TransactionError::Invalid(format!(
                    "PII transform post-check failed for target '{}' (unresolved={}, remaining={}).",
                    target_label, report.unresolved_spans, report.remaining_span_count
                )));
            }
            *text = scrubbed;
            Ok(())
        }
        ioi_types::app::agentic::FirewallDecision::Quarantine
        | ioi_types::app::agentic::FirewallDecision::RequireUserReview => {
            if scoped_exception_applies {
                return Ok(());
            }
            if let Some(tx) = &service.event_sender {
                let _ = tx.send(ioi_types::app::KernelEvent::FirewallInterception {
                    verdict: "REQUIRE_APPROVAL".to_string(),
                    target: target_label,
                    request_hash: routed.decision_hash,
                    session_id: Some(session_id),
                });
            }
            Err(TransactionError::PendingApproval(hex::encode(
                routed.decision_hash,
            )))
        }
        ioi_types::app::agentic::FirewallDecision::Deny => {
            if let Some(tx) = &service.event_sender {
                let _ = tx.send(ioi_types::app::KernelEvent::FirewallInterception {
                    verdict: "BLOCK".to_string(),
                    target: target_label.clone(),
                    request_hash: routed.decision_hash,
                    session_id: Some(session_id),
                });
            }
            Err(TransactionError::Invalid(format!(
                "PII firewall denied raw egress for '{}'.",
                target_label
            )))
        }
    }
}

fn is_pii_review_required(
    decision: &ioi_types::app::agentic::FirewallDecision,
    supports_transform: bool,
) -> bool {
    matches!(
        decision,
        ioi_types::app::agentic::FirewallDecision::Quarantine
            | ioi_types::app::agentic::FirewallDecision::RequireUserReview
    ) || (!supports_transform
        && matches!(
            decision,
            ioi_types::app::agentic::FirewallDecision::RedactThenAllow
                | ioi_types::app::agentic::FirewallDecision::TokenizeThenAllow
        ))
}

pub(crate) async fn build_pii_review_request_for_tool(
    service: &DesktopAgentService,
    rules: &ActionRules,
    session_id: [u8; 32],
    tool: &AgentTool,
    decision_hash: [u8; 32],
    created_at_ms: u64,
) -> Result<Option<PiiReviewRequest>, TransactionError> {
    let mut candidate_tool = tool.clone();
    for spec in candidate_tool.pii_egress_specs() {
        let Some(text) = candidate_tool.pii_egress_field_mut(spec.field) else {
            continue;
        };
        let (_scrubbed, _map, _report, routed, evidence) = service
            .scrubber
            .inspect_route_transform(
                text,
                &spec.target,
                to_shared_risk_surface(spec.risk_surface),
                &rules.pii_controls,
                spec.supports_transform,
            )
            .await
            .map_err(|e| {
                TransactionError::Invalid(format!(
                    "PII inspection failed while building review request: {}",
                    e
                ))
            })?;

        if routed.decision_hash != decision_hash {
            continue;
        }
        if !is_pii_review_required(&routed.decision, spec.supports_transform) {
            continue;
        }

        let material = build_decision_material(
            &evidence,
            &routed.decision,
            routed.transform_plan.as_ref(),
            routed.stage2_decision.as_ref(),
            to_shared_risk_surface(spec.risk_surface),
            &spec.target,
            spec.supports_transform,
            &routed.assist,
        );
        let summary =
            build_review_summary(&evidence, &spec.target, routed.stage2_decision.as_ref());
        let deadline_ms = created_at_ms.saturating_add(rules.pii_controls.stage2_timeout_ms as u64);

        return Ok(Some(PiiReviewRequest {
            request_version: REVIEW_REQUEST_VERSION,
            decision_hash,
            material,
            summary,
            session_id: Some(session_id),
            created_at_ms,
            deadline_ms,
        }));
    }

    Ok(None)
}

pub(crate) fn persist_pii_review_request(
    state: &mut dyn StateAccess,
    request: &PiiReviewRequest,
) -> Result<(), TransactionError> {
    let key = crate::agentic::desktop::keys::pii::review::request(&request.decision_hash);
    let bytes = codec::to_bytes_canonical(request)?;
    state.insert(&key, &bytes)?;
    Ok(())
}

pub(crate) fn emit_pii_review_requested(
    service: &DesktopAgentService,
    request: &PiiReviewRequest,
) {
    if let Some(tx) = &service.event_sender {
        let _ = tx.send(ioi_types::app::KernelEvent::PiiReviewRequested {
            decision_hash: request.decision_hash,
            material: request.material.clone(),
            summary: request.summary.clone(),
            deadline_ms: request.deadline_ms,
            session_id: request.session_id,
        });
    }
}

async fn apply_pii_transform_first(
    service: &DesktopAgentService,
    rules: &crate::agentic::rules::ActionRules,
    session_id: [u8; 32],
    scoped_exception_hash: Option<[u8; 32]>,
    tool: &mut AgentTool,
) -> Result<(), TransactionError> {
    let specs = tool.pii_egress_specs();
    for spec in specs {
        if let Some(text) = tool.pii_egress_field_mut(spec.field) {
            enforce_text_egress_policy(
                service,
                rules,
                session_id,
                &spec.target,
                to_shared_risk_surface(spec.risk_surface),
                spec.supports_transform,
                scoped_exception_hash,
                text,
            )
            .await?;
        }
    }
    Ok(())
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

    // Stage D transform-first enforcement for egress-capable tools.
    apply_pii_transform_first(service, rules, session_id, scoped_exception_hash, &mut tool)
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
        let approved_by_token = agent_state
            .pending_approval
            .as_ref()
            .map(|token| token.request_hash == tool_hash)
            .unwrap_or(false);
        let approved_by_runtime_secret =
            is_runtime_secret_install_retry_approved(&tool, tool_hash, session_id, agent_state);
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
    if is_focus_sensitive_tool(&tool) {
        if let Some(hint) = target_app_hint
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
        {
            if !window_matches_hint(foreground_window.as_ref(), hint) {
                match os_driver.focus_window(hint).await {
                    Ok(true) => {
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        foreground_window =
                            os_driver.get_active_window_info().await.unwrap_or(None);
                        if !window_matches_hint(foreground_window.as_ref(), hint) {
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
                        if is_missing_focus_dependency_error(&err) {
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
            | AgentTool::BrowserExtract { .. }
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
            Err(e) => {
                let err = e.to_string();
                if is_missing_focus_dependency_error(&err) {
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
    use super::{is_focus_sensitive_tool, is_runtime_secret_install_retry_approved};
    use crate::agentic::desktop::runtime_secret;
    use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
    use ioi_types::app::agentic::{AgentTool, ComputerAction};
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
}
