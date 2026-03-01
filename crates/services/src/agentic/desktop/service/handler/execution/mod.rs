use super::super::{DesktopAgentService, ServiceCallContext};
use super::approvals;
use super::focus;
use super::pii;
use super::wallet_mail::try_execute_wallet_mail_dynamic_tool;
use super::web_research::normalize_web_research_tool_call;
use crate::agentic::desktop::execution::ToolExecutor;
use crate::agentic::desktop::types::AgentState;
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_crypto::algorithms::hash::sha256;
use ioi_drivers::mcp::McpManager;
use ioi_scs::{FrameType, RetentionClass};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{
    determinism_commit_state_key, determinism_evidence_state_key, ActionRequest, ActionTarget,
    ApprovalToken, CommittedAction, DeterminismEvidence, ExecutionContractReceiptEvent,
    KernelEvent,
};
use ioi_types::error::TransactionError;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod handlers;

const ACTIVE_WINDOW_QUERY_TIMEOUT: Duration = Duration::from_millis(300);
const CEC_CONTRACT_VERSION: &str = "cec.v0.4";

type ActionExecutionOutcome = (bool, Option<String>, Option<String>, Option<[u8; 32]>);

fn no_visual(
    success: bool,
    history_entry: Option<String>,
    error: Option<String>,
) -> ActionExecutionOutcome {
    (success, history_entry, error, None)
}

fn persist_visual_observation(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    block_height: u64,
    visual_observation: Vec<u8>,
) -> Result<[u8; 32], TransactionError> {
    let scs_mutex = service.scs.as_ref().ok_or_else(|| {
        TransactionError::Invalid(
            "ERROR_CLASS=UnexpectedState Visual evidence store unavailable.".to_string(),
        )
    })?;

    let mut store = scs_mutex
        .lock()
        .map_err(|_| TransactionError::Invalid("Internal: SCS lock poisoned".into()))?;

    let frame_id = store
        .append_frame(
            FrameType::Observation,
            &visual_observation,
            block_height,
            [0u8; 32],
            session_id,
            RetentionClass::Ephemeral,
        )
        .map_err(|e| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=UnexpectedState Failed to persist visual evidence: {}",
                e
            ))
        })?;

    store
        .toc
        .frames
        .get(frame_id as usize)
        .map(|frame| frame.checksum)
        .ok_or_else(|| {
            TransactionError::Invalid(
                "ERROR_CLASS=UnexpectedState Persisted visual evidence frame missing.".to_string(),
            )
        })
}

fn resolved_intent_id(agent_state: &AgentState) -> String {
    agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.intent_id.clone())
        .unwrap_or_else(|| "resolver.unclassified".to_string())
}

fn emit_execution_contract_receipt_event(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    stage: &str,
    key: &str,
    satisfied: bool,
    evidence_material: &str,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };

    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let evidence_payload = format!(
        "intent_id={};stage={};key={};satisfied={};evidence={}",
        intent_id, stage, key, satisfied, evidence_material
    );
    let evidence_commit_hash = sha256(evidence_payload.as_bytes())
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|_| "sha256:unavailable".to_string());

    let _ = tx.send(KernelEvent::ExecutionContractReceipt(
        ExecutionContractReceiptEvent {
            contract_version: CEC_CONTRACT_VERSION.to_string(),
            session_id,
            step_index,
            intent_id: intent_id.to_string(),
            stage: stage.to_string(),
            key: key.to_string(),
            satisfied,
            timestamp_ms,
            evidence_commit_hash,
            verifier_command_commit_hash: None,
            provider_id: None,
            synthesized_payload_hash: None,
        },
    ));
}

fn persist_committed_action(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
    committed_action: &CommittedAction,
) -> Result<(), TransactionError> {
    let key = determinism_commit_state_key(session_id, step_index);
    let bytes = ioi_types::codec::to_bytes_canonical(committed_action)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    state.insert(&key, &bytes)?;
    Ok(())
}

fn persist_determinism_evidence(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
    request: &ActionRequest,
    committed_action: &CommittedAction,
    recovery_retry: bool,
    recovery_reason: Option<String>,
) -> Result<(), TransactionError> {
    let key = determinism_evidence_state_key(session_id, step_index);
    let evidence = DeterminismEvidence {
        schema_version: DeterminismEvidence::schema_version(),
        request: request.clone(),
        committed_action: committed_action.clone(),
        recovery_retry,
        recovery_reason,
    };
    let bytes = ioi_types::codec::to_bytes_canonical(&evidence)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    state.insert(&key, &bytes)?;
    Ok(())
}

async fn query_active_window_with_timeout(
    os_driver: &Arc<dyn OsDriver>,
    session_id: [u8; 32],
    phase: &str,
) -> Option<ioi_api::vm::drivers::os::WindowInfo> {
    match tokio::time::timeout(
        ACTIVE_WINDOW_QUERY_TIMEOUT,
        os_driver.get_active_window_info(),
    )
    .await
    {
        Ok(Ok(window)) => window,
        Ok(Err(err)) => {
            log::warn!(
                "Active-window query failed (session={} phase={}): {}",
                hex::encode(&session_id[..4]),
                phase,
                err
            );
            None
        }
        Err(_) => {
            log::warn!(
                "Active-window query timed out after {:?} (session={} phase={}).",
                ACTIVE_WINDOW_QUERY_TIMEOUT,
                hex::encode(&session_id[..4]),
                phase
            );
            None
        }
    }
}

pub(crate) fn target_requires_window_binding(target: &ActionTarget) -> bool {
    matches!(
        target,
        ActionTarget::UiClick
            | ActionTarget::UiType
            | ActionTarget::GuiMouseMove
            | ActionTarget::GuiClick
            | ActionTarget::GuiType
            | ActionTarget::GuiScreenshot
            | ActionTarget::GuiScroll
            | ActionTarget::GuiSequence
            | ActionTarget::BrowserInteract
            | ActionTarget::BrowserInspect
            | ActionTarget::WindowFocus
            | ActionTarget::GuiInspect
    )
}

fn derive_window_binding(
    window: Option<&ioi_api::vm::drivers::os::WindowInfo>,
) -> Result<Option<u64>, TransactionError> {
    let Some(window) = window else {
        return Ok(None);
    };

    let payload = json!({
        "app_name": window.app_name,
        "title": window.title,
        "x": window.x,
        "y": window.y,
        "width": window.width,
        "height": window.height,
    });

    let canonical =
        serde_jcs::to_vec(&payload).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = ioi_crypto::algorithms::hash::sha256(&canonical).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Window binding hash failed: {}",
            e
        ))
    })?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_ref()[..8]);
    Ok(Some(u64::from_be_bytes(bytes)))
}

pub(crate) async fn resolve_window_binding_for_target(
    os_driver: &Arc<dyn OsDriver>,
    session_id: [u8; 32],
    target: &ActionTarget,
    phase: &str,
) -> Result<Option<u64>, TransactionError> {
    if !target_requires_window_binding(target) {
        return Ok(None);
    }
    let foreground_window = query_active_window_with_timeout(os_driver, session_id, phase).await;
    let derived = derive_window_binding(foreground_window.as_ref())?;
    if derived.is_none() {
        return Err(TransactionError::Invalid(
            "ERROR_CLASS=DeterminismBoundary Missing active-window binding for UI/browsing action."
                .to_string(),
        ));
    }
    Ok(derived)
}

fn compute_policy_hash(rules: &ActionRules) -> Result<[u8; 32], TransactionError> {
    let canonical =
        serde_jcs::to_vec(rules).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = ioi_crypto::algorithms::hash::sha256(&canonical).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Policy hash failed: {}",
            e
        ))
    })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn compute_approval_token_ref(token: &ApprovalToken) -> Result<[u8; 32], TransactionError> {
    let canonical =
        serde_jcs::to_vec(token).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = ioi_crypto::algorithms::hash::sha256(&canonical).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Approval token hash failed: {}",
            e
        ))
    })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

pub async fn handle_action_execution(
    service: &DesktopAgentService,
    tool: AgentTool,
    session_id: [u8; 32],
    step_index: u32,
    visual_phash: [u8; 32],
    rules: &ActionRules,
    agent_state: &AgentState,
    os_driver: &Arc<dyn OsDriver>,
    scoped_exception_hash: Option<[u8; 32]>,
    mut execution_state: Option<&mut dyn StateAccess>,
    execution_call_context: Option<ServiceCallContext<'_>>,
) -> Result<ActionExecutionOutcome, TransactionError> {
    let mut tool = tool;

    let mcp = service
        .mcp
        .clone()
        .unwrap_or_else(|| Arc::new(McpManager::new()));

    // [VERIFIED] This line ensures the registry propagates to execution
    let lens_registry_arc = service.lens_registry.clone();

    let mut foreground_window =
        query_active_window_with_timeout(os_driver, session_id, "pre").await;
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
    let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Tool hash failed: {}",
            e
        ))
    })?;
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

    let window_binding =
        resolve_window_binding_for_target(os_driver, session_id, &target, "pre_determinism_commit")
            .await?;

    let dummy_request = ioi_types::app::ActionRequest {
        target: target.clone(),
        params: request_params,
        context: ioi_types::app::ActionContext {
            agent_id: "desktop_agent".into(),
            session_id: Some(session_id),
            window_id: window_binding,
        },
        nonce: step_index as u64,
    };

    let request_hash = dummy_request.try_hash().map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Invalid committed action request: {}",
            e
        ))
    })?;

    let target_str = match &target {
        ioi_types::app::ActionTarget::Custom(s) => s.clone(),
        _ => serde_json::to_string(&target)
            .unwrap_or_else(|_| "unknown".to_string())
            .trim_matches('"')
            .to_string(),
    };
    let intent_id = resolved_intent_id(agent_state);

    // 3. Policy Check
    let skip_policy = matches!(tool, AgentTool::SystemFail { .. });

    if !skip_policy {
        let policy_hash = compute_policy_hash(rules)?;
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            &intent_id,
            "execution",
            "policy_hash_binding",
            true,
            &format!(
                "policy_hash={};request_hash={};target={}",
                hex::encode(policy_hash),
                hex::encode(request_hash),
                target_str
            ),
        );

        let matched_approval_token = agent_state
            .pending_approval
            .as_ref()
            .filter(|token| token.request_hash == request_hash);
        let approved_by_runtime_secret = approvals::is_runtime_secret_install_retry_approved(
            &tool,
            tool_hash,
            session_id,
            agent_state,
        );
        let is_approved = matched_approval_token.is_some() || approved_by_runtime_secret;

        if is_approved {
            if matched_approval_token.is_some() {
                log::info!(
                    "Policy Gate: Pre-approved via Token for hash {}",
                    hex::encode(request_hash)
                );
            } else {
                log::info!(
                    "Policy Gate: Pre-approved via runtime secret retry for hash {}",
                    hex::encode(request_hash)
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
                    emit_execution_contract_receipt_event(
                        service,
                        session_id,
                        step_index,
                        &intent_id,
                        "execution",
                        "policy_decision",
                        false,
                        &format!(
                            "decision=BLOCK;policy_hash={};request_hash={}",
                            hex::encode(policy_hash),
                            hex::encode(request_hash)
                        ),
                    );
                    if let Some(tx) = &service.event_sender {
                        let _ = tx.send(KernelEvent::FirewallInterception {
                            verdict: "BLOCK".to_string(),
                            target: target_str.clone(),
                            request_hash,
                            session_id: Some(session_id),
                        });
                    }
                    return Err(TransactionError::Invalid("Blocked by Policy".into()));
                }
                Verdict::RequireApproval => {
                    log::info!(
                        "Policy Gate: RequireApproval for hash: {}",
                        hex::encode(request_hash)
                    );
                    emit_execution_contract_receipt_event(
                        service,
                        session_id,
                        step_index,
                        &intent_id,
                        "execution",
                        "policy_decision",
                        false,
                        &format!(
                            "decision=REQUIRE_APPROVAL;policy_hash={};request_hash={}",
                            hex::encode(policy_hash),
                            hex::encode(request_hash)
                        ),
                    );

                    if let Some(tx) = &service.event_sender {
                        let _ = tx.send(KernelEvent::FirewallInterception {
                            verdict: "REQUIRE_APPROVAL".to_string(),
                            target: target_str.clone(),
                            request_hash,
                            session_id: Some(session_id),
                        });
                    }
                    return Err(TransactionError::PendingApproval(hex::encode(request_hash)));
                }
            }
        }

        let approval_ref = matched_approval_token
            .map(compute_approval_token_ref)
            .transpose()?;
        let recovery_retry = agent_state.consecutive_failures > 0;
        let recovery_reason = recovery_retry
            .then(|| format!("consecutive_failures={}", agent_state.consecutive_failures));

        let committed_action = CommittedAction::commit(&dummy_request, policy_hash, approval_ref)
            .map_err(|e| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=DeterminismBoundary Unable to commit action: {}",
                e
            ))
        })?;

        committed_action
            .verify(&dummy_request, policy_hash, approval_ref)
            .map_err(|e| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=DeterminismBoundary Commit verification failed: {}",
                    e
                ))
            })?;

        if let Some(state) = execution_state.as_deref_mut() {
            persist_committed_action(state, session_id, step_index, &committed_action)?;
            persist_determinism_evidence(
                state,
                session_id,
                step_index,
                &dummy_request,
                &committed_action,
                recovery_retry,
                recovery_reason.clone(),
            )?;
        }

        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            &intent_id,
            "execution",
            "determinism_commit",
            true,
            &format!(
                "commitment_hash={};request_hash={};policy_hash={};recovery_retry={}",
                hex::encode(committed_action.commitment_hash),
                hex::encode(committed_action.request_hash),
                hex::encode(committed_action.policy_hash),
                recovery_retry
            ),
        );
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
                            query_active_window_with_timeout(os_driver, session_id, "post_focus")
                                .await;
                        if !focus::window_matches_hint(foreground_window.as_ref(), hint) {
                            return Ok(no_visual(
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
                        return Ok(no_visual(
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
                            return Ok(no_visual(
                                false,
                                None,
                                Some(format!(
                                    "ERROR_CLASS=MissingDependency Focus dependency unavailable while focusing '{}': {}",
                                    hint, err
                                )),
                            ));
                        }
                        return Ok(no_visual(
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

    let finalize_executor_result =
        |result: crate::agentic::desktop::execution::ToolExecutionResult| {
            let visual_hash = if let Some(visual_observation) = result.visual_observation {
                let block_height = execution_call_context
                    .map(|ctx| ctx.block_height)
                    .ok_or_else(|| {
                        TransactionError::Invalid(
                        "ERROR_CLASS=UnexpectedState Missing execution context for visual evidence."
                            .to_string(),
                    )
                    })?;
                Some(persist_visual_observation(
                    service,
                    session_id,
                    block_height,
                    visual_observation,
                )?)
            } else {
                None
            };

            Ok((
                result.success,
                result.history_entry,
                result.error,
                visual_hash,
            ))
        };

    // 5. Handle Meta-Tools and Execution
    match tool {
        AgentTool::SystemFail {
            reason,
            missing_capability,
        } => Ok(handlers::handle_system_fail_tool(
            service,
            session_id,
            step_index,
            reason,
            missing_capability,
        )),
        AgentTool::MemorySearch { query } => {
            Ok(handlers::handle_memory_search_tool(service, &query).await)
        }
        AgentTool::MemoryInspect { frame_id } => {
            Ok(handlers::handle_memory_inspect_tool(service, frame_id).await)
        }
        AgentTool::AgentDelegate { goal, budget } => {
            Ok(handlers::handle_agent_delegate_tool(goal, budget))
        }
        AgentTool::AgentAwait { .. } => Ok(handlers::handle_agent_await_tool()),
        AgentTool::AgentPause { .. } => Ok(handlers::handle_agent_pause_tool()),
        AgentTool::AgentComplete { .. } => Ok(handlers::handle_agent_complete_tool()),
        AgentTool::CommerceCheckout { .. } => Ok(handlers::handle_commerce_checkout_tool()),
        AgentTool::ChatReply { message } => Ok(handlers::handle_chat_reply_tool(message)),
        AgentTool::OsFocusWindow { title } => {
            Ok(handlers::handle_os_focus_window_tool(os_driver, title).await)
        }
        AgentTool::OsCopy { content } => {
            Ok(handlers::handle_os_copy_tool(os_driver, content).await)
        }
        AgentTool::OsPaste {} => Ok(handlers::handle_os_paste_tool(os_driver).await),
        AgentTool::Dynamic(value) => {
            if let (Some(state), Some(call_context)) =
                (execution_state.as_deref_mut(), execution_call_context)
            {
                if let Some(result) = try_execute_wallet_mail_dynamic_tool(
                    state,
                    call_context,
                    &value,
                    session_id,
                    step_index,
                )
                .await?
                {
                    let (success, out, err) = result;
                    return Ok(no_visual(success, out, err));
                }
            }

            let result = executor
                .execute(
                    AgentTool::Dynamic(value),
                    session_id,
                    step_index,
                    visual_phash,
                    agent_state.visual_som_map.as_ref(),
                    agent_state.visual_semantic_map.as_ref(),
                    agent_state.active_lens.as_deref(),
                )
                .await;
            finalize_executor_result(result)
        }

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
            finalize_executor_result(result)
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
mod tests;
