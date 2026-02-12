// Path: crates/services/src/agentic/desktop/service/step/action.rs

use self::super::helpers::default_safe_policy;
use super::anti_loop::{
    build_attempt_key, build_post_state_summary, build_state_summary, choose_routing_tier,
    classify_failure, emit_routing_receipt, escalation_path_for_failure, extract_artifacts,
    lineage_pointer, mutation_receipt_pointer, policy_binding_hash, register_failure_attempt,
    retry_budget_remaining, should_block_retry_without_change, should_trip_retry_guard,
    tier_as_str, to_routing_failure_class, FailureClass, TierRoutingDecision,
};
use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::middleware;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, AgentStatus, ExecutionTier, ToolCallStatus};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{
    ActionContext, ActionRequest, KernelEvent, RoutingReceiptEvent, RoutingStateSummary,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_jcs;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

// [NEW] Imports for Safe Resume
use crate::agentic::desktop::service::step::visual::hamming_distance;
use crate::agentic::desktop::utils::compute_phash;

// Helper to get a string representation of the agent status for event emission.
fn get_status_str(status: &AgentStatus) -> String {
    format!("{:?}", status)
        .split('(')
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

fn mark_system_fail_status(status: &mut AgentStatus, reason: impl Into<String>) {
    *status = AgentStatus::Failed(reason.into());
}

fn enforce_system_fail_terminal_status(
    current_tool_name: &str,
    status: &mut AgentStatus,
    error_msg: Option<&str>,
) -> bool {
    if current_tool_name != "system__fail" {
        return false;
    }

    if !matches!(status, AgentStatus::Failed(_)) {
        let fallback_reason = error_msg.unwrap_or("Agent requested explicit failure");
        mark_system_fail_status(status, fallback_reason.to_string());
    }

    true
}

// Helper to determine if an action relies on precise screen coordinates.
fn requires_visual_integrity(tool: &AgentTool) -> bool {
    match tool {
        AgentTool::Computer(action) => matches!(
            action,
            ioi_types::app::agentic::ComputerAction::LeftClickId { .. }
                | ioi_types::app::agentic::ComputerAction::LeftClick {
                    coordinate: Some(_),
                    ..
                }
                | ioi_types::app::agentic::ComputerAction::LeftClickDrag { .. }
                | ioi_types::app::agentic::ComputerAction::DragDrop { .. }
                | ioi_types::app::agentic::ComputerAction::DragDropId { .. }
                | ioi_types::app::agentic::ComputerAction::DragDropElement { .. }
                | ioi_types::app::agentic::ComputerAction::MouseMove { .. }
                | ioi_types::app::agentic::ComputerAction::Scroll {
                    coordinate: Some(_),
                    ..
                }
        ),
        AgentTool::GuiClick { .. } => true,
        AgentTool::GuiScroll { .. } => true,
        AgentTool::BrowserSyntheticClick { .. } => true,
        AgentTool::BrowserClick { .. } => true,
        AgentTool::BrowserClickElement { .. } => true,
        _ => false,
    }
}

pub fn canonical_tool_identity(tool: &AgentTool) -> (String, serde_json::Value) {
    let serialized = serde_json::to_value(tool).unwrap_or_else(|_| json!({}));
    let dynamic = match tool {
        AgentTool::Dynamic(value) => Some(value),
        _ => None,
    };

    let tool_name = serialized
        .get("name")
        .and_then(|value| value.as_str())
        .or_else(|| dynamic.and_then(|value| value.get("name").and_then(|n| n.as_str())))
        .map(str::to_string)
        .unwrap_or_else(|| format!("{:?}", tool.target()));

    let args = serialized
        .get("arguments")
        .cloned()
        .or_else(|| dynamic.and_then(|value| value.get("arguments").cloned()))
        .unwrap_or_else(|| json!({}));

    (tool_name, args)
}

pub fn canonical_intent_hash(
    tool_name: &str,
    args: &serde_json::Value,
    tier: ExecutionTier,
    step_index: u32,
    tool_version: &str,
) -> String {
    let payload = json!({
        "tool_name": tool_name,
        "args": args,
        "tier": tier_as_str(tier),
        "step_index": step_index,
        "tool_version": tool_version,
    });

    let canonical_bytes = serde_jcs::to_vec(&payload)
        .or_else(|_| serde_json::to_vec(&payload))
        .unwrap_or_default();

    sha256(&canonical_bytes)
        .map(hex::encode)
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn canonical_retry_intent_hash(
    tool_name: &str,
    args: &serde_json::Value,
    tier: ExecutionTier,
    tool_version: &str,
) -> String {
    let payload = json!({
        "tool_name": tool_name,
        "args": args,
        "tier": tier_as_str(tier),
        "tool_version": tool_version,
        "retry_scope": "attempt_dedupe_v1",
    });

    let canonical_bytes = serde_jcs::to_vec(&payload)
        .or_else(|_| serde_json::to_vec(&payload))
        .unwrap_or_default();

    sha256(&canonical_bytes)
        .map(hex::encode)
        .unwrap_or_else(|_| "unknown".to_string())
}

pub async fn resume_pending_action(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
) -> Result<(), TransactionError> {
    // 1. Load Canonical Request Bytes
    let tool_jcs = agent_state
        .pending_tool_jcs
        .as_ref()
        .ok_or(TransactionError::Invalid("Missing pending_tool_jcs".into()))?;

    let tool_hash = agent_state
        .pending_tool_hash
        .ok_or(TransactionError::Invalid(
            "Missing pending_tool_hash".into(),
        ))?;

    // 2. Deserialize Tool FIRST
    let tool: AgentTool = serde_json::from_slice(tool_jcs)
        .map_err(|e| TransactionError::Serialization(format!("Corrupt pending tool: {}", e)))?;

    // 3. Visual Guard: Context Drift Check
    let pending_vhash = agent_state
        .pending_visual_hash
        .ok_or(TransactionError::Invalid(
            "Missing pending_visual_hash".into(),
        ))?;

    if requires_visual_integrity(&tool) {
        let current_bytes = service.gui.capture_raw_screen().await.unwrap_or_default();
        let current_phash = compute_phash(&current_bytes).unwrap_or([0u8; 32]);
        let drift = hamming_distance(&pending_vhash, &current_phash);

        if drift > 30 {
            log::warn!("Context Drift Detected (Dist: {}). Aborting Resume.", drift);
            let key = get_state_key(&session_id);
            goto_trace_log(
                agent_state,
                state,
                &key,
                session_id,
                current_phash,
                "[Resumed Action]".to_string(),
                "ABORTED: Visual Context Drifted.".to_string(),
                false,
                Some("Context Drift".to_string()),
                "system::context_drift".to_string(),
                service.event_sender.clone(),
                None,
            )?;

            agent_state.pending_tool_jcs = None;
            agent_state.pending_tool_hash = None;
            agent_state.pending_visual_hash = None;
            agent_state.pending_tool_call = None;
            agent_state.pending_approval = None;
            agent_state.status = AgentStatus::Running;

            state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
            return Ok(());
        }
    } else {
        log::info!(
            "Skipping visual drift check for non-spatial tool (Hash: {}).",
            hex::encode(&tool_hash[0..4])
        );
    }

    service.restore_visual_context(pending_vhash).await?;

    let token = agent_state
        .pending_approval
        .as_ref()
        .ok_or(TransactionError::Invalid("Missing approval token".into()))?;

    if token.request_hash != tool_hash {
        return Err(TransactionError::Invalid(
            "Approval token hash mismatch".into(),
        ));
    }

    agent_state.current_tier = crate::agentic::desktop::types::ExecutionTier::VisualForeground;

    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    let rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);

    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;

    let (success, out, err) = match service
        .handle_action_execution(
            tool.clone(),
            session_id,
            agent_state.step_count,
            pending_vhash,
            &rules,
            &agent_state,
            &os_driver,
        )
        .await
    {
        Ok(t) => t,
        Err(e) => (false, None, Some(e.to_string())),
    };

    let output_str = out
        .clone()
        .unwrap_or_else(|| err.clone().unwrap_or_default());
    let key = get_state_key(&session_id);

    goto_trace_log(
        agent_state,
        state,
        &key,
        session_id,
        pending_vhash,
        "[Resumed Action]".to_string(),
        output_str.clone(),
        success,
        err.clone(),
        "resumed_action".to_string(),
        service.event_sender.clone(),
        agent_state.active_skill_hash,
    )?;

    if success {
        if let AgentTool::SysChangeDir { .. } = tool {
            if let Some(new_cwd) = out.as_ref() {
                agent_state.working_directory = new_cwd.clone();
            }
        }
    }

    let content = if success {
        out.clone()
            .unwrap_or_else(|| "Action executed successfully.".to_string())
    } else {
        format!(
            "Action Failed: {}",
            err.unwrap_or("Unknown error".to_string())
        )
    };

    let msg = ioi_types::app::agentic::ChatMessage {
        role: "tool".to_string(),
        content,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        trace_hash: None,
    };
    service
        .append_chat_to_scs(session_id, &msg, block_height)
        .await?;

    agent_state.pending_tool_jcs = None;
    agent_state.pending_tool_hash = None;
    agent_state.pending_visual_hash = None;
    agent_state.pending_tool_call = None;
    agent_state.pending_approval = None;
    agent_state.status = AgentStatus::Running;
    agent_state.step_count += 1;

    if success {
        agent_state.consecutive_failures = 0;
    }
    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    Ok(())
}

async fn handle_refusal(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    key: &[u8],
    session_id: [u8; 32],
    visual_phash: [u8; 32],
    reason: &str,
) -> Result<(), TransactionError> {
    log::warn!("Agent Refusal Intercepted: {}", reason);
    goto_trace_log(
        agent_state,
        state,
        key,
        session_id,
        visual_phash,
        "[Refusal Intercepted]".to_string(),
        reason.to_string(),
        true,
        None,
        "system::refusal".to_string(),
        service.event_sender.clone(),
        None,
    )?;
    agent_state.step_count += 1;
    agent_state.status = AgentStatus::Paused(format!("Model Refusal: {}", reason));
    agent_state.consecutive_failures = 0;
    state.insert(key, &codec::to_bytes_canonical(agent_state)?)?;
    Ok(())
}

async fn evaluate_and_crystallize(
    service: &DesktopAgentService,
    agent_state: &AgentState,
    session_id: [u8; 32],
    result: &str,
) {
    if let Some(eval) = &service.evaluator {
        let history = service
            .hydrate_session_history(session_id)
            .unwrap_or_default();
        let reconstructed_trace: Vec<ioi_types::app::agentic::StepTrace> = history
            .iter()
            .enumerate()
            .map(|(i, msg)| ioi_types::app::agentic::StepTrace {
                session_id: session_id,
                step_index: i as u32,
                visual_hash: [0; 32],
                full_prompt: format!("{}: {}", msg.role, msg.content),
                raw_output: msg.content.clone(),
                success: true,
                error: None,
                cost_incurred: 0,
                fitness_score: None,
                skill_hash: None,
                timestamp: msg.timestamp / 1000,
            })
            .collect();

        let contract = ioi_types::app::IntentContract {
            max_price: agent_state.budget + agent_state.tokens_used,
            deadline_epoch: 0,
            min_confidence_score: 80,
            allowed_providers: vec![],
            outcome_type: ioi_types::app::OutcomeType::Result,
            optimize_for: ioi_types::app::OptimizationObjective::Reliability,
        };

        if let Ok(report) = eval.evaluate(&reconstructed_trace, &contract).await {
            if report.score >= 0.8 && report.passed_hard_constraints {
                if let Some(opt) = &service.optimizer {
                    let trace_hash_bytes = ioi_crypto::algorithms::hash::sha256(result.as_bytes())
                        .unwrap_or([0u8; 32]);
                    let mut trace_hash_arr = [0u8; 32];
                    trace_hash_arr.copy_from_slice(trace_hash_bytes.as_ref());
                    let _ = opt
                        .crystallize_skill_internal(session_id, trace_hash_arr, None)
                        .await;
                }
            }
        }
    }
}

/// Applies parity routing for action execution and snapshots pre-state after
/// tier selection so receipt pre-state, intent hash tier, and executor tier stay coherent.
pub fn resolve_action_routing_context(
    agent_state: &mut AgentState,
) -> (TierRoutingDecision, RoutingStateSummary) {
    let routing_decision = choose_routing_tier(agent_state);
    agent_state.current_tier = routing_decision.tier;
    let pre_state_summary = build_state_summary(agent_state);
    (routing_decision, pre_state_summary)
}

pub async fn process_tool_output(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    tool_call_result: String,
    final_visual_phash: [u8; 32],
    strategy_used: String,
    session_id: [u8; 32],
    block_height: u64,
) -> Result<(), TransactionError> {
    let key = get_state_key(&session_id);
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    let rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);
    let (routing_decision, pre_state_summary) = resolve_action_routing_context(agent_state);
    let tool_version = env!("CARGO_PKG_VERSION");
    let mut policy_decision = "allowed".to_string();
    let mut action_payload = json!({
        "raw_tool_output": tool_call_result
    });
    let mut intent_hash = "unknown".to_string();
    let mut retry_intent_hash: Option<String> = None;

    // 1. Raw Refusal Interceptor
    if tool_call_result.contains("\"name\":\"system::refusal\"") {
        let reason = if let Ok(val) = serde_json::from_str::<serde_json::Value>(&tool_call_result) {
            val.get("arguments")
                .and_then(|a| a.get("reason"))
                .and_then(|m| m.as_str())
                .unwrap_or("Refused")
                .to_string()
        } else {
            "Refused".to_string()
        };
        let refusal_tool_name = "system::refusal".to_string();
        let refusal_args = json!({
            "reason": reason
        });
        let refusal_action_payload = json!({
            "name": refusal_tool_name,
            "arguments": refusal_args
        });
        let refusal_intent_hash = canonical_intent_hash(
            &refusal_tool_name,
            &refusal_args,
            routing_decision.tier,
            pre_state_summary.step_index,
            tool_version,
        );
        let refusal_policy_decision = "denied".to_string();
        let refusal_failure_class = FailureClass::UserInterventionNeeded;
        let refusal_stop_condition_hit = true;
        let refusal_escalation_path =
            Some(escalation_path_for_failure(refusal_failure_class).to_string());

        handle_refusal(
            service,
            state,
            agent_state,
            &key,
            session_id,
            final_visual_phash,
            &reason,
        )
        .await?;

        let verification_checks = vec![
            format!("policy_decision={}", refusal_policy_decision),
            "was_refusal=true".to_string(),
            format!("stop_condition_hit={}", refusal_stop_condition_hit),
            format!(
                "routing_tier_selected={}",
                tier_as_str(routing_decision.tier)
            ),
            format!("routing_reason_code={}", routing_decision.reason_code),
            format!(
                "routing_source_failure={}",
                routing_decision
                    .source_failure
                    .map(|class| class.as_str().to_string())
                    .unwrap_or_else(|| "None".to_string())
            ),
            format!(
                "routing_tier_matches_pre_state={}",
                pre_state_summary.tier == tier_as_str(routing_decision.tier)
            ),
            format!("failure_class={}", refusal_failure_class.as_str()),
        ];
        let mut artifacts = extract_artifacts(
            Some("ERROR_CLASS=HumanChallengeRequired"),
            Some(&tool_call_result),
        );
        artifacts.push(format!(
            "trace://agent_step/{}",
            pre_state_summary.step_index
        ));
        artifacts.push(format!("trace://session/{}", hex::encode(&session_id[..4])));
        let post_state = build_post_state_summary(agent_state, false, verification_checks);
        let policy_binding = policy_binding_hash(&refusal_intent_hash, &refusal_policy_decision);
        let receipt = RoutingReceiptEvent {
            session_id,
            step_index: pre_state_summary.step_index,
            intent_hash: refusal_intent_hash,
            policy_decision: refusal_policy_decision,
            tool_name: refusal_tool_name,
            tool_version: tool_version.to_string(),
            pre_state: pre_state_summary,
            action_json: serde_json::to_string(&refusal_action_payload)
                .unwrap_or_else(|_| "{}".to_string()),
            post_state,
            artifacts,
            failure_class: Some(to_routing_failure_class(refusal_failure_class)),
            stop_condition_hit: refusal_stop_condition_hit,
            escalation_path: refusal_escalation_path,
            scs_lineage_ptr: lineage_pointer(agent_state.active_skill_hash),
            mutation_receipt_ptr: mutation_receipt_pointer(state, &session_id),
            policy_binding_hash: policy_binding,
            policy_binding_sig: None,
            policy_binding_signer: None,
        };
        emit_routing_receipt(service.event_sender.as_ref(), receipt);
        return Ok(());
    }

    // 2. Normalize & Expand
    let tool_call = middleware::normalize_tool_call(&tool_call_result);

    // Check for Skill / Macro Match
    if let Ok(AgentTool::Dynamic(ref val)) = tool_call {
        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
            if let Some((macro_def, skill_hash)) = service.fetch_skill_macro(name) {
                let args_map = val
                    .get("arguments")
                    .and_then(|a| a.as_object())
                    .cloned()
                    .unwrap_or_default();
                match service.expand_macro(&macro_def, &args_map) {
                    Ok(steps) => {
                        agent_state.execution_queue.extend(steps);
                        agent_state.active_skill_hash = Some(skill_hash);
                        goto_trace_log(
                            agent_state,
                            state,
                            &key,
                            session_id,
                            final_visual_phash,
                            format!("[Macro Expansion] Loaded skill '{}'", name),
                            format!("Expanded into {} steps", agent_state.execution_queue.len()),
                            true,
                            None,
                            "system::expand_macro".to_string(),
                            service.event_sender.clone(),
                            Some(skill_hash),
                        )?;
                        agent_state.step_count += 1;
                        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                        return Ok(());
                    }
                    Err(_e) => {
                        // ... handle error ...
                        return Ok(());
                    }
                }
            }
        }
    }

    let (_req_hash, req_hash_hex) = if let Ok(ref t) = tool_call {
        let target = t.target();
        let tool_val = serde_json::to_value(t).unwrap_or(json!({}));
        let args_val = tool_val.get("arguments").cloned().unwrap_or(json!({}));
        let params = serde_jcs::to_vec(&args_val).unwrap_or_default();
        let req = ActionRequest {
            target,
            params,
            context: ActionContext {
                agent_id: "desktop_agent".into(),
                session_id: Some(session_id),
                window_id: None,
            },
            nonce: agent_state.step_count as u64,
        };
        let h = req.hash();
        (h, hex::encode(h))
    } else {
        ([0u8; 32], String::new())
    };

    if !req_hash_hex.is_empty() {
        if let Some(status) = agent_state.tool_execution_log.get(&req_hash_hex) {
            if matches!(status, ToolCallStatus::Executed(_)) {
                log::info!("Skipping idempotent step");
                agent_state.step_count += 1;
                agent_state.pending_tool_call = None;
                agent_state.pending_tool_jcs = None;
                agent_state.pending_approval = None;
                agent_state.status = AgentStatus::Running;
                state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                return Ok(());
            }
        }
    }

    // 3. Execution
    let mut success = false;
    let mut error_msg = None;
    let mut is_gated = false;
    let mut is_lifecycle_action = false;
    let mut current_tool_name = "unknown".to_string();
    let mut history_entry: Option<String> = None;
    let mut action_output: Option<String> = None;
    let mut failure_class: Option<FailureClass> = None;
    let mut stop_condition_hit = false;
    let mut escalation_path: Option<String> = None;
    let mut verification_checks = Vec::new();

    match tool_call {
        Ok(tool) => {
            let os_driver = service
                .os_driver
                .clone()
                .ok_or(TransactionError::Invalid("OS driver missing".into()))?;
            action_payload = serde_json::to_value(&tool).unwrap_or_else(|_| json!({}));
            let (tool_name, tool_args) = canonical_tool_identity(&tool);
            current_tool_name = tool_name;
            intent_hash = canonical_intent_hash(
                &current_tool_name,
                &tool_args,
                routing_decision.tier,
                pre_state_summary.step_index,
                tool_version,
            );
            retry_intent_hash = Some(canonical_retry_intent_hash(
                &current_tool_name,
                &tool_args,
                routing_decision.tier,
                tool_version,
            ));

            let target_hash_opt = agent_state
                .pending_approval
                .as_ref()
                .and_then(|t| t.visual_hash)
                .or(agent_state.last_screen_phash);
            if let Some(target_hash) = target_hash_opt {
                let _ = service.restore_visual_context(target_hash).await;
            }

            // [FIX] Pass the required InferenceRuntime (reasoning) to ToolExecutor constructor inside handle_action_execution
            match service
                .handle_action_execution(
                    tool.clone(),
                    session_id,
                    agent_state.step_count,
                    final_visual_phash,
                    &rules,
                    &agent_state,
                    &os_driver,
                )
                .await
            {
                Ok((s, entry, e)) => {
                    success = s;
                    error_msg = e;
                    history_entry = entry.clone();

                    if s && !req_hash_hex.is_empty() {
                        agent_state.tool_execution_log.insert(
                            req_hash_hex.clone(),
                            ToolCallStatus::Executed("success".into()),
                        );
                        agent_state.pending_approval = None;
                        agent_state.pending_tool_jcs = None;
                    }

                    if s {
                        if let Some(entry) = entry.clone() {
                            let tool_msg = ioi_types::app::agentic::ChatMessage {
                                role: "tool".to_string(),
                                content: entry,
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis() as u64,
                                trace_hash: None,
                            };
                            let _ = service
                                .append_chat_to_scs(session_id, &tool_msg, block_height)
                                .await?;
                        }
                    }

                    match &tool {
                        AgentTool::AgentComplete { result } => {
                            agent_state.status = AgentStatus::Completed(Some(result.clone()));
                            is_lifecycle_action = true;
                            action_output = Some(result.clone());
                            evaluate_and_crystallize(service, agent_state, session_id, result)
                                .await;
                        }
                        AgentTool::SysChangeDir { .. } => {
                            if s {
                                if let Some(new_cwd) = history_entry.as_ref() {
                                    agent_state.working_directory = new_cwd.clone();
                                }
                            }
                        }
                        AgentTool::ChatReply { message } => {
                            agent_state.status =
                                AgentStatus::Paused("Waiting for user input".to_string());
                            is_lifecycle_action = true;
                            action_output = Some(message.clone());
                        }
                        AgentTool::SystemFail { reason, .. } => {
                            mark_system_fail_status(&mut agent_state.status, reason.clone());
                            is_lifecycle_action = true;
                            action_output = Some(format!("Agent Failed: {}", reason));
                        }
                        _ => {}
                    }
                }
                Err(TransactionError::PendingApproval(h)) => {
                    policy_decision = "require_approval".to_string();
                    // [NEW] Capture Canonical Context for Resume
                    let tool_jcs = serde_jcs::to_vec(&tool).unwrap();
                    let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).unwrap();
                    let mut hash_arr = [0u8; 32];
                    hash_arr.copy_from_slice(tool_hash_bytes.as_ref());

                    agent_state.pending_tool_jcs = Some(tool_jcs);
                    agent_state.pending_tool_hash = Some(hash_arr);
                    agent_state.pending_visual_hash = Some(final_visual_phash);
                    agent_state.pending_tool_call = Some(tool_call_result.clone());
                    agent_state.last_screen_phash = Some(final_visual_phash);

                    is_gated = true;
                    is_lifecycle_action = true;
                    agent_state.status = AgentStatus::Paused("Waiting for approval".into());

                    let msg = format!("System: Action halted by Agency Firewall (Hash: {}). Requesting authorization.", h);
                    let sys_msg = ioi_types::app::agentic::ChatMessage {
                        role: "system".to_string(),
                        content: msg,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                        trace_hash: None,
                    };
                    let _ = service
                        .append_chat_to_scs(session_id, &sys_msg, block_height)
                        .await?;
                    success = true;
                }
                Err(e) => {
                    success = false;
                    let msg = e.to_string();
                    if msg.to_lowercase().contains("blocked by policy") {
                        policy_decision = "denied".to_string();
                    }
                    error_msg = Some(msg.clone());
                    if !req_hash_hex.is_empty() {
                        agent_state
                            .tool_execution_log
                            .insert(req_hash_hex.clone(), ToolCallStatus::Failed(msg));
                    }
                }
            }
        }
        Err(e) => {
            policy_decision = "denied".to_string();
            current_tool_name = "system::invalid_tool_call".to_string();
            let parse_error = format!("Failed to parse tool call: {}", e);
            let parse_args = json!({
                "raw_tool_output": tool_call_result,
                "parse_error": parse_error,
            });
            intent_hash = canonical_intent_hash(
                &current_tool_name,
                &parse_args,
                routing_decision.tier,
                pre_state_summary.step_index,
                tool_version,
            );
            retry_intent_hash = Some(canonical_retry_intent_hash(
                &current_tool_name,
                &parse_args,
                routing_decision.tier,
                tool_version,
            ));
            action_payload = json!({
                "name": current_tool_name.clone(),
                "arguments": parse_args,
            });
            error_msg = Some(
                action_payload
                    .get("arguments")
                    .and_then(|v| v.get("parse_error"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Failed to parse tool call")
                    .to_string(),
            );
        }
    }

    if success {
        agent_state.recent_actions.clear();
    } else {
        failure_class = classify_failure(error_msg.as_deref(), &policy_decision);
        if let Some(class) = failure_class {
            let target_id = agent_state.target.as_ref().and_then(|target| {
                target
                    .app_hint
                    .as_deref()
                    .filter(|v| !v.trim().is_empty())
                    .or_else(|| {
                        target
                            .title_pattern
                            .as_deref()
                            .filter(|v| !v.trim().is_empty())
                    })
            });
            let window_fingerprint = if final_visual_phash == [0u8; 32] {
                None
            } else {
                Some(hex::encode(final_visual_phash))
            };
            let retry_hash = retry_intent_hash.as_deref().unwrap_or(intent_hash.as_str());
            let attempt_key = build_attempt_key(
                retry_hash,
                routing_decision.tier,
                &current_tool_name,
                target_id,
                window_fingerprint.as_deref(),
            );
            let (repeat_count, attempt_key_hash) =
                register_failure_attempt(agent_state, class, &attempt_key);
            let budget_remaining = retry_budget_remaining(repeat_count);
            let blocked_without_change = should_block_retry_without_change(class, repeat_count);
            verification_checks.push(format!("attempt_repeat_count={}", repeat_count));
            verification_checks.push(format!("attempt_key_hash={}", attempt_key_hash));
            verification_checks.push(format!(
                "attempt_retry_budget_remaining={}",
                budget_remaining
            ));
            verification_checks.push(format!(
                "attempt_retry_blocked_without_change={}",
                blocked_without_change
            ));
            if matches!(class, FailureClass::UserInterventionNeeded) {
                stop_condition_hit = true;
                escalation_path = Some(escalation_path_for_failure(class).to_string());
                is_lifecycle_action = true;
                agent_state.status = AgentStatus::Paused(
                    "Waiting for user intervention: complete the required human verification in Local Browser, then resume.".to_string(),
                );
            } else if blocked_without_change {
                stop_condition_hit = true;
                escalation_path = Some(escalation_path_for_failure(class).to_string());
                is_lifecycle_action = true;
                agent_state.status = AgentStatus::Paused(format!(
                    "Retry blocked: unchanged AttemptKey for {}",
                    class.as_str()
                ));
                if matches!(
                    class,
                    FailureClass::FocusMismatch
                        | FailureClass::TargetNotFound
                        | FailureClass::VisionTargetNotFound
                        | FailureClass::NoEffectAfterAction
                        | FailureClass::TierViolation
                        | FailureClass::MissingDependency
                        | FailureClass::ContextDrift
                        | FailureClass::ToolUnavailable
                        | FailureClass::NonDeterministicUI
                        | FailureClass::TimeoutOrHang
                        | FailureClass::UnexpectedState
                ) {
                    agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
                }
            } else if should_trip_retry_guard(class, repeat_count) {
                stop_condition_hit = true;
                escalation_path = Some(escalation_path_for_failure(class).to_string());
                is_lifecycle_action = true;
                agent_state.status = AgentStatus::Paused(format!(
                    "Retry guard tripped after repeated {} failures",
                    class.as_str()
                ));
                if matches!(
                    class,
                    FailureClass::FocusMismatch
                        | FailureClass::TargetNotFound
                        | FailureClass::VisionTargetNotFound
                        | FailureClass::NoEffectAfterAction
                        | FailureClass::TierViolation
                        | FailureClass::MissingDependency
                        | FailureClass::ContextDrift
                        | FailureClass::ToolUnavailable
                        | FailureClass::NonDeterministicUI
                        | FailureClass::TimeoutOrHang
                        | FailureClass::UnexpectedState
                ) {
                    agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
                }
            }
        }
    }

    if !is_gated {
        if let Some(tx) = &service.event_sender {
            let output_str = action_output
                .or_else(|| if success { history_entry.clone() } else { None })
                .unwrap_or_else(|| {
                    error_msg
                        .clone()
                        .unwrap_or_else(|| "Unknown error".to_string())
                });
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id,
                step_index: agent_state.step_count,
                tool_name: current_tool_name.clone(),
                output: output_str,
                agent_status: get_status_str(&agent_state.status),
            });
        }
    }

    verification_checks.push(format!("policy_decision={}", policy_decision));
    verification_checks.push(format!("was_gated={}", is_gated));
    verification_checks.push(format!("stop_condition_hit={}", stop_condition_hit));
    verification_checks.push(format!(
        "routing_tier_selected={}",
        tier_as_str(routing_decision.tier)
    ));
    verification_checks.push(format!(
        "routing_reason_code={}",
        routing_decision.reason_code
    ));
    verification_checks.push(format!(
        "routing_source_failure={}",
        routing_decision
            .source_failure
            .map(|class| class.as_str().to_string())
            .unwrap_or_else(|| "None".to_string())
    ));
    verification_checks.push(format!(
        "routing_tier_matches_pre_state={}",
        pre_state_summary.tier == tier_as_str(routing_decision.tier)
    ));
    if let Some(class) = failure_class {
        verification_checks.push(format!("failure_class={}", class.as_str()));
    }

    goto_trace_log(
        agent_state,
        state,
        &key,
        session_id,
        final_visual_phash,
        format!("[Strategy: {}]\n{}", strategy_used, tool_call_result),
        tool_call_result,
        success,
        error_msg.clone(),
        current_tool_name.clone(),
        service.event_sender.clone(),
        agent_state.active_skill_hash,
    )?;

    // Failure counter is primarily managed in goto_trace_log.
    // We only override it for explicit escalation or lifecycle transitions.
    if enforce_system_fail_terminal_status(
        &current_tool_name,
        &mut agent_state.status,
        error_msg.as_deref(),
    ) {
        log::info!("SystemFail executed: Forcing IMMEDIATE escalation state (failures=3)");
        agent_state.consecutive_failures = 3;
    } else if !stop_condition_hit && (success || is_lifecycle_action) {
        agent_state.consecutive_failures = 0;
    }

    if !is_gated {
        agent_state.step_count += 1;
        agent_state.pending_tool_call = None;
        agent_state.pending_tool_jcs = None;
        agent_state.pending_approval = None;
    }

    // ... [Max steps check] ...
    if agent_state.step_count >= agent_state.max_steps && agent_state.status == AgentStatus::Running
    {
        agent_state.status = AgentStatus::Completed(None);
    }

    let mut artifacts = extract_artifacts(error_msg.as_deref(), history_entry.as_deref());
    artifacts.push(format!(
        "trace://agent_step/{}",
        pre_state_summary.step_index
    ));
    artifacts.push(format!("trace://session/{}", hex::encode(&session_id[..4])));

    let post_state = build_post_state_summary(agent_state, success, verification_checks);
    let policy_binding = policy_binding_hash(&intent_hash, &policy_decision);

    let receipt = RoutingReceiptEvent {
        session_id,
        step_index: pre_state_summary.step_index,
        intent_hash,
        policy_decision,
        tool_name: current_tool_name,
        tool_version: tool_version.to_string(),
        pre_state: pre_state_summary,
        action_json: serde_json::to_string(&action_payload).unwrap_or_else(|_| "{}".to_string()),
        post_state,
        artifacts,
        failure_class: failure_class.map(to_routing_failure_class),
        stop_condition_hit,
        escalation_path,
        scs_lineage_ptr: lineage_pointer(agent_state.active_skill_hash),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
    };
    emit_routing_receipt(service.event_sender.as_ref(), receipt);

    Ok(())
}
