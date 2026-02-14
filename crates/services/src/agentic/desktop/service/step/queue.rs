// Path: crates/services/src/agentic/desktop/service/step/queue.rs

use self::super::helpers::default_safe_policy;
use super::action::{canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity};
use super::anti_loop::{
    build_attempt_key, build_post_state_summary, build_state_summary, choose_routing_tier,
    classify_failure, emit_routing_receipt, escalation_path_for_failure, extract_artifacts,
    lineage_pointer, mutation_receipt_pointer, policy_binding_hash, register_failure_attempt,
    retry_budget_remaining, should_block_retry_without_change, should_trip_retry_guard,
    tier_as_str, to_routing_failure_class, FailureClass, TierRoutingDecision,
};
use super::incident::{
    advance_incident_after_action_outcome, incident_receipt_fields, load_incident_state,
    register_pending_approval, should_enter_incident_recovery,
    start_or_continue_incident_recovery, ApprovalDirective, IncidentDirective,
};
use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::middleware;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, AgentStatus, StepAgentParams};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{
    ActionRequest, ActionTarget, KernelEvent, RoutingReceiptEvent, RoutingStateSummary,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::json;
use std::path::Path;

/// Applies parity routing for queued actions and snapshots the pre-state after
/// tier selection so receipts and executor context stay coherent.
pub fn resolve_queue_routing_context(
    agent_state: &mut AgentState,
) -> (TierRoutingDecision, RoutingStateSummary) {
    let routing_decision = choose_routing_tier(agent_state);
    agent_state.current_tier = routing_decision.tier;
    let pre_state_summary = build_state_summary(agent_state);
    (routing_decision, pre_state_summary)
}

const MAX_SEARCH_EXTRACT_CHARS: usize = 8_000;

fn fallback_search_summary(query: &str, url: &str) -> String {
    format!(
        "Searched '{}' at {}, but structured extraction failed. Retry refinement if needed.",
        query, url
    )
}

fn strip_markup(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if in_tag => {}
            _ => out.push(ch),
        }
    }
    out
}

fn compact_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_urls(input: &str, limit: usize) -> Vec<String> {
    let mut urls = Vec::new();
    for raw in input.split_whitespace() {
        let trimmed = raw
            .trim_matches(|ch: char| ",.;:!?)]}\"'".contains(ch))
            .trim();
        if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
            continue;
        }
        if urls.iter().any(|existing| existing == trimmed) {
            continue;
        }
        urls.push(trimmed.to_string());
        if urls.len() >= limit {
            break;
        }
    }
    urls
}

fn extract_finding_lines(input: &str, limit: usize) -> Vec<String> {
    let mut findings = Vec::new();
    for line in input.lines() {
        let normalized = compact_whitespace(line).trim().to_string();
        if normalized.len() < 24 || normalized.len() > 200 {
            continue;
        }
        if normalized.starts_with("http://") || normalized.starts_with("https://") {
            continue;
        }
        if normalized.to_ascii_lowercase().contains("cookie")
            || normalized.to_ascii_lowercase().contains("javascript")
        {
            continue;
        }
        if findings.iter().any(|existing| existing == &normalized) {
            continue;
        }
        findings.push(normalized);
        if findings.len() >= limit {
            break;
        }
    }
    findings
}

fn summarize_search_results(query: &str, url: &str, extract_text: &str) -> String {
    let capped = extract_text
        .chars()
        .take(MAX_SEARCH_EXTRACT_CHARS)
        .collect::<String>();
    let stripped = strip_markup(&capped);
    let findings = extract_finding_lines(&stripped, 3);
    let urls = extract_urls(&capped, 2);

    let mut bullets: Vec<String> = Vec::new();
    for finding in findings {
        bullets.push(finding);
        if bullets.len() >= 3 {
            break;
        }
    }
    for link in urls.iter() {
        if bullets.len() >= 3 {
            break;
        }
        bullets.push(format!("Top link: {}", link));
    }

    if bullets.is_empty() {
        let snippet = compact_whitespace(&stripped)
            .chars()
            .take(180)
            .collect::<String>();
        if snippet.is_empty() {
            bullets.push("No high-signal snippets were extracted.".to_string());
        } else {
            bullets.push(format!("Extracted snippet: {}", snippet));
        }
    }

    let refinement_hint = if let Some(link) = urls.first() {
        format!(
            "Open '{}' or refine with more specific keywords (site:, date range, exact phrase).",
            link
        )
    } else {
        "Refine with more specific keywords (site:, date range, exact phrase).".to_string()
    };

    let mut summary = format!("Search summary for '{}':\n", query);
    for bullet in bullets.into_iter().take(3) {
        summary.push_str(&format!("- {}\n", bullet));
    }
    summary.push_str(&format!("- Source URL: {}\n", url));
    summary.push_str(&format!("Next refinement: {}", refinement_hint));
    summary
}

fn infer_sys_tool_name(args: &serde_json::Value) -> &'static str {
    if let Some(obj) = args.as_object() {
        if obj.get("command").is_none() && obj.get("app_name").is_some() {
            return "os__launch_app";
        }
        if obj.get("command").is_none() && obj.get("path").is_some() {
            return "sys__change_directory";
        }
    }
    "sys__exec"
}

fn infer_fs_read_tool_name(args: &serde_json::Value) -> &'static str {
    let Some(obj) = args.as_object() else {
        return "filesystem__read_file";
    };

    // Preserve deterministic filesystem search queued via ActionTarget::FsRead.
    if obj.contains_key("regex") || obj.contains_key("file_pattern") {
        return "filesystem__search";
    }

    if let Some(path) = obj
        .get("path")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if Path::new(path).is_dir() {
            return "filesystem__list_directory";
        }
    }

    "filesystem__read_file"
}

fn infer_fs_write_tool_name(args: &serde_json::Value) -> &'static str {
    let Some(obj) = args.as_object() else {
        return "filesystem__write_file";
    };

    // Preserve deterministic patch requests queued under ActionTarget::FsWrite.
    if obj.contains_key("search") && obj.contains_key("replace") {
        return "filesystem__patch";
    }

    "filesystem__write_file"
}

fn infer_custom_tool_name(name: &str, args: &serde_json::Value) -> String {
    match name {
        // Backward-compatible aliases emitted by ActionTarget::Custom values.
        "browser::click" => {
            if args.get("id").is_some() {
                "browser__click_element".to_string()
            } else {
                "browser__click".to_string()
            }
        }
        "browser::synthetic_click" => "browser__synthetic_click".to_string(),
        "browser::scroll" => "browser__scroll".to_string(),
        "ui::find" => "ui__find".to_string(),
        "os::focus" => "os__focus_window".to_string(),
        "clipboard::write" => "os__copy".to_string(),
        "clipboard::read" => "os__paste".to_string(),
        "fs::read" => infer_fs_read_tool_name(args).to_string(),
        "fs::write" => infer_fs_write_tool_name(args).to_string(),
        "sys::exec" => infer_sys_tool_name(args).to_string(),
        "sys::install_package" => "sys__install_package".to_string(),
        _ => name.to_string(),
    }
}

fn queue_target_to_tool_name_and_args(
    target: &ActionTarget,
    raw_args: serde_json::Value,
) -> Result<(String, serde_json::Value), TransactionError> {
    match target {
        ActionTarget::Custom(name) => Ok((infer_custom_tool_name(name, &raw_args), raw_args)),
        ActionTarget::FsRead => Ok((infer_fs_read_tool_name(&raw_args).to_string(), raw_args)),
        ActionTarget::FsWrite => Ok((infer_fs_write_tool_name(&raw_args).to_string(), raw_args)),
        ActionTarget::BrowserNavigateHermetic => Ok(("browser__navigate".to_string(), raw_args)),
        ActionTarget::BrowserExtract => Ok(("browser__extract".to_string(), raw_args)),
        ActionTarget::GuiType | ActionTarget::UiType => Ok(("gui__type".to_string(), raw_args)),
        ActionTarget::GuiClick | ActionTarget::UiClick => Ok(("gui__click".to_string(), raw_args)),
        ActionTarget::GuiScroll => Ok(("gui__scroll".to_string(), raw_args)),
        ActionTarget::SysExec => Ok((infer_sys_tool_name(&raw_args).to_string(), raw_args)),
        ActionTarget::SysInstallPackage => Ok(("sys__install_package".to_string(), raw_args)),
        ActionTarget::WindowFocus => Ok(("os__focus_window".to_string(), raw_args)),
        ActionTarget::ClipboardWrite => Ok(("os__copy".to_string(), raw_args)),
        ActionTarget::ClipboardRead => Ok(("os__paste".to_string(), raw_args)),
        unsupported => Err(TransactionError::Invalid(format!(
            "Queue execution for target {:?} is not yet mapped to AgentTool",
            unsupported
        ))),
    }
}

pub fn queue_action_request_to_tool(
    action_request: &ActionRequest,
) -> Result<AgentTool, TransactionError> {
    let raw_args: serde_json::Value =
        serde_json::from_slice(&action_request.params).map_err(|e| {
            TransactionError::Serialization(format!("Invalid queued action params JSON: {}", e))
        })?;

    let (tool_name, args) = queue_target_to_tool_name_and_args(&action_request.target, raw_args)?;

    let wrapper = json!({
        "name": tool_name,
        "arguments": args,
    });
    let wrapper_json = serde_json::to_string(&wrapper)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;

    middleware::normalize_tool_call(&wrapper_json)
        .map_err(|e| TransactionError::Invalid(format!("Queue tool normalization failed: {}", e)))
}

pub async fn process_queue_item(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    p: &StepAgentParams,
    block_height: u64,
) -> Result<(), TransactionError> {
    log::info!(
        "Draining execution queue for session {} (Pending: {})",
        hex::encode(&p.session_id[..4]),
        agent_state.execution_queue.len()
    );

    let key = get_state_key(&p.session_id);
    let policy_key = [AGENT_POLICY_PREFIX, p.session_id.as_slice()].concat();
    let rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);
    let (routing_decision, pre_state_summary) = resolve_queue_routing_context(agent_state);
    let mut policy_decision = "allowed".to_string();

    // Pop the first action
    let action_request = agent_state.execution_queue.remove(0);

    // [NEW] Capture the active skill hash for attribution
    let active_skill = agent_state.active_skill_hash;

    // [FIX] Removed manual ToolExecutor construction.
    // The service method now handles it internally.

    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;

    // Re-construct a typed AgentTool from ActionRequest.
    let tool_wrapper = queue_action_request_to_tool(&action_request)?;
    let tool_jcs = serde_jcs::to_vec(&tool_wrapper)
        .or_else(|_| serde_json::to_vec(&tool_wrapper))
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let (tool_name, intent_args) = canonical_tool_identity(&tool_wrapper);
    let action_json = serde_json::to_string(&tool_wrapper).unwrap_or_else(|_| "{}".to_string());
    let intent_hash = canonical_intent_hash(
        &tool_name,
        &intent_args,
        routing_decision.tier,
        pre_state_summary.step_index,
        env!("CARGO_PKG_VERSION"),
    );
    let retry_intent_hash = canonical_retry_intent_hash(
        &tool_name,
        &intent_args,
        routing_decision.tier,
        env!("CARGO_PKG_VERSION"),
    );
    let mut verification_checks = Vec::new();

    // Execute
    // [FIX] Updated call: removed executor arg
    let result_tuple = service
        .handle_action_execution(
            // &executor,  <-- REMOVED
            tool_wrapper.clone(),
            p.session_id,
            agent_state.step_count,
            [0u8; 32],
            &rules,
            &agent_state,
            &os_driver,
        )
        .await;

    let mut is_gated = false;
    let (mut success, mut out, mut err): (bool, Option<String>, Option<String>) = match result_tuple
    {
        Ok(tuple) => tuple,
        Err(TransactionError::PendingApproval(h)) => {
            policy_decision = "require_approval".to_string();
            let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).map_err(|e| {
                TransactionError::Invalid(format!("Failed to hash queued tool JCS: {}", e))
            })?;
            let mut hash_arr = [0u8; 32];
            hash_arr.copy_from_slice(tool_hash_bytes.as_ref());
            let pending_visual_hash = agent_state.last_screen_phash.unwrap_or([0u8; 32]);
            let action_fingerprint = sha256(&tool_jcs)
                .map(hex::encode)
                .unwrap_or_else(|_| String::new());
            let incident_before = load_incident_state(state, &p.session_id)?;
            let incident_stage_before = incident_before
                .as_ref()
                .map(|incident| incident.stage.clone())
                .unwrap_or_else(|| "None".to_string());

            let approval_directive = register_pending_approval(
                state,
                &rules,
                agent_state,
                p.session_id,
                &retry_intent_hash,
                &tool_name,
                &tool_jcs,
                &action_fingerprint,
                &h,
            )?;
            let incident_after = load_incident_state(state, &p.session_id)?;
            let incident_stage_after = incident_after
                .as_ref()
                .map(|incident| incident.stage.clone())
                .unwrap_or_else(|| "None".to_string());
            verification_checks.push(format!(
                "approval_suppressed_single_pending={}",
                matches!(approval_directive, ApprovalDirective::SuppressDuplicatePrompt)
            ));
            verification_checks.push(format!(
                "incident_id_stable={}",
                match (incident_before.as_ref(), incident_after.as_ref()) {
                    (Some(before), Some(after)) => before.incident_id == after.incident_id,
                    _ => true,
                }
            ));
            verification_checks.push(format!(
                "incident_stage_before={}",
                incident_stage_before
            ));
            verification_checks.push(format!("incident_stage_after={}", incident_stage_after));

            agent_state.pending_tool_jcs = Some(tool_jcs.clone());
            agent_state.pending_tool_hash = Some(hash_arr);
            agent_state.pending_visual_hash = Some(pending_visual_hash);
            agent_state.pending_tool_call = Some(action_json.clone());
            agent_state.status = AgentStatus::Paused("Waiting for approval".into());
            is_gated = true;

            if let Some(incident_state) = load_incident_state(state, &p.session_id)? {
                if incident_state.active {
                    log::info!(
                        "incident.approval_intercepted session={} incident_id={} root_tool={} gated_tool={}",
                        hex::encode(&p.session_id[..4]),
                        incident_state.incident_id,
                        incident_state.root_tool_name,
                        tool_name
                    );
                }
            }

            match approval_directive {
                ApprovalDirective::PromptUser => {
                    let msg = format!(
                        "System: Queued action halted by Agency Firewall (Hash: {}). Requesting authorization.",
                        h
                    );
                    let sys_msg = ioi_types::app::agentic::ChatMessage {
                        role: "system".to_string(),
                        content: msg,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                        trace_hash: None,
                    };
                    let _ = service
                        .append_chat_to_scs(p.session_id, &sys_msg, block_height)
                        .await?;
                    (true, None, None)
                }
                ApprovalDirective::SuppressDuplicatePrompt => {
                    let sys_msg = ioi_types::app::agentic::ChatMessage {
                        role: "system".to_string(),
                        content:
                            "System: Approval already pending for this incident/action. Waiting for your decision."
                                .to_string(),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                        trace_hash: None,
                    };
                    let _ = service
                        .append_chat_to_scs(p.session_id, &sys_msg, block_height)
                        .await?;
                    (true, None, None)
                }
                ApprovalDirective::PauseLoop => {
                    policy_decision = "denied".to_string();
                    let loop_msg = format!(
                        "ERROR_CLASS=PermissionOrApprovalRequired Approval loop policy paused this incident for request hash {}.",
                        h
                    );
                    agent_state.status = AgentStatus::Paused(
                        "Approval loop detected for the same incident/action. Automatic retries paused."
                            .to_string(),
                    );
                    let sys_msg = ioi_types::app::agentic::ChatMessage {
                        role: "system".to_string(),
                        content: format!(
                            "System: {} Please approve, deny, or change policy settings.",
                            loop_msg
                        ),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                        trace_hash: None,
                    };
                    let _ = service
                        .append_chat_to_scs(p.session_id, &sys_msg, block_height)
                        .await?;
                    (false, None, Some(loop_msg))
                }
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.to_lowercase().contains("blocked by policy") {
                policy_decision = "denied".to_string();
            }
            (false, None, Some(msg))
        }
    };
    let mut completion_summary: Option<String> = None;

    if !is_gated && tool_name == "browser__extract" {
        if let Some(pending) = agent_state.pending_search_completion.clone() {
            let summary = if success {
                summarize_search_results(&pending.query, &pending.url, out.as_deref().unwrap_or(""))
            } else {
                fallback_search_summary(&pending.query, &pending.url)
            };
            completion_summary = Some(summary.clone());
            success = true;
            out = Some(summary.clone());
            err = None;
            agent_state.status = AgentStatus::Completed(Some(summary));
            agent_state.pending_search_completion = None;
            agent_state.execution_queue.clear();
            agent_state.recent_actions.clear();
            log::info!(
                "Search flow completed after browser__extract for session {}.",
                hex::encode(&p.session_id[..4])
            );
        }
    }

    let output_str = out.clone().unwrap_or_default();
    let error_str = err.clone();

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

    if let Some(summary) = completion_summary.as_ref() {
        if let Some(tx) = &service.event_sender {
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id: p.session_id,
                step_index: agent_state.step_count,
                tool_name: "agent__complete".to_string(),
                output: summary.clone(),
                agent_status: "Completed".to_string(),
            });
        }
    }

    let mut failure_class: Option<FailureClass> = None;
    let mut stop_condition_hit = false;
    let mut escalation_path: Option<String> = None;
    let mut remediation_queued = false;
    if !is_gated {
        let incident_directive = advance_incident_after_action_outcome(
            service,
            state,
            agent_state,
            p.session_id,
            &retry_intent_hash,
            &tool_jcs,
            success,
            block_height,
            err.as_deref(),
            &mut verification_checks,
        )
        .await?;
        if matches!(incident_directive, IncidentDirective::QueueActions) {
            remediation_queued = true;
            stop_condition_hit = false;
            escalation_path = None;
            agent_state.status = AgentStatus::Running;
        }
    }

    if success && !is_gated {
        agent_state.recent_actions.clear();
    } else if !success {
        failure_class = classify_failure(err.as_deref(), &policy_decision);
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
            let window_fingerprint = agent_state
                .last_screen_phash
                .filter(|hash| *hash != [0u8; 32])
                .map(hex::encode);
            let attempt_key = build_attempt_key(
                &retry_intent_hash,
                routing_decision.tier,
                &tool_name,
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
            let incident_state = load_incident_state(state, &p.session_id)?;
            if should_enter_incident_recovery(
                Some(class),
                &policy_decision,
                stop_condition_hit,
                incident_state.as_ref(),
            ) {
                let (resolved_retry_hash, recovery_tool_name, recovery_tool_jcs): (
                    String,
                    String,
                    Vec<u8>,
                ) = if let Some(existing) = incident_state.as_ref().filter(|i| i.active) {
                    (
                        existing.root_retry_hash.clone(),
                        existing.root_tool_name.clone(),
                        existing.root_tool_jcs.clone(),
                    )
                } else {
                    (retry_intent_hash.clone(), tool_name.clone(), tool_jcs.clone())
                };
                remediation_queued = matches!(
                    start_or_continue_incident_recovery(
                        service,
                        state,
                        agent_state,
                        p.session_id,
                        block_height,
                        &rules,
                        &resolved_retry_hash,
                        &recovery_tool_name,
                        &recovery_tool_jcs,
                        class,
                        err.as_deref(),
                        &mut verification_checks,
                    )
                    .await?,
                    IncidentDirective::QueueActions
                );
            }

            if remediation_queued {
                stop_condition_hit = false;
                escalation_path = None;
                agent_state.status = AgentStatus::Running;
            } else if matches!(class, FailureClass::UserInterventionNeeded) {
                stop_condition_hit = true;
                escalation_path = Some(escalation_path_for_failure(class).to_string());
                agent_state.status = AgentStatus::Paused(
                    "Waiting for user intervention: complete the required human verification in your browser/app, then resume.".to_string(),
                );
            } else if blocked_without_change {
                stop_condition_hit = true;
                escalation_path = Some(escalation_path_for_failure(class).to_string());
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

    verification_checks.push(format!("policy_decision={}", policy_decision));
    verification_checks.push(format!("was_gated={}", is_gated));
    verification_checks.push("was_queue=true".to_string());
    verification_checks.push(format!("remediation_queued={}", remediation_queued));
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

    if !is_gated {
        agent_state.step_count += 1;
    }

    if success && !stop_condition_hit && !is_gated {
        agent_state.consecutive_failures = 0;
    }

    let mut artifacts = extract_artifacts(err.as_deref(), out.as_deref());
    artifacts.push(format!(
        "trace://agent_step/{}",
        pre_state_summary.step_index
    ));
    artifacts.push(format!(
        "trace://session/{}",
        hex::encode(&p.session_id[..4])
    ));
    let post_state = build_post_state_summary(agent_state, success, verification_checks);
    let policy_binding = policy_binding_hash(&intent_hash, &policy_decision);
    let incident_fields =
        incident_receipt_fields(load_incident_state(state, &p.session_id)?.as_ref());
    let failure_class_name = failure_class
        .map(|class| class.as_str().to_string())
        .unwrap_or_default();
    let receipt = RoutingReceiptEvent {
        session_id: p.session_id,
        step_index: pre_state_summary.step_index,
        intent_hash,
        policy_decision,
        tool_name,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        pre_state: pre_state_summary,
        action_json,
        post_state,
        artifacts,
        failure_class: failure_class.map(to_routing_failure_class),
        failure_class_name,
        intent_class: incident_fields.intent_class,
        incident_id: incident_fields.incident_id,
        incident_stage: incident_fields.incident_stage,
        strategy_name: incident_fields.strategy_name,
        strategy_node: incident_fields.strategy_node,
        gate_state: incident_fields.gate_state,
        resolution_action: incident_fields.resolution_action,
        stop_condition_hit,
        escalation_path,
        scs_lineage_ptr: lineage_pointer(active_skill),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &p.session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
    };
    emit_routing_receipt(service.event_sender.as_ref(), receipt);

    // [NEW] If queue is empty, clear the active skill hash to reset context
    if agent_state.execution_queue.is_empty() {
        agent_state.active_skill_hash = None;
    }

    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{fallback_search_summary, queue_action_request_to_tool, summarize_search_results};
    use ioi_types::app::agentic::AgentTool;
    use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn build_fs_read_request(args: serde_json::Value) -> ActionRequest {
        ActionRequest {
            target: ActionTarget::FsRead,
            params: serde_json::to_vec(&args).expect("params should serialize"),
            context: ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: None,
                window_id: None,
            },
            nonce: 7,
        }
    }

    fn build_fs_write_request(args: serde_json::Value) -> ActionRequest {
        ActionRequest {
            target: ActionTarget::FsWrite,
            params: serde_json::to_vec(&args).expect("params should serialize"),
            context: ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: None,
                window_id: None,
            },
            nonce: 11,
        }
    }

    fn build_sys_exec_request(args: serde_json::Value) -> ActionRequest {
        ActionRequest {
            target: ActionTarget::SysExec,
            params: serde_json::to_vec(&args).expect("params should serialize"),
            context: ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: None,
                window_id: None,
            },
            nonce: 13,
        }
    }

    #[test]
    fn summary_contains_topic_and_refinement_hint() {
        let summary = summarize_search_results(
            "internet of intelligence",
            "https://duckduckgo.com/?q=internet+of+intelligence",
            "<html><body><a href=\"https://example.com/a\">A</a>\nThe Internet of Intelligence explores decentralized agent coordination.\nOpen protocols enable verifiable execution and policy enforcement.</body></html>",
        );
        assert!(summary.contains("Search summary for 'internet of intelligence'"));
        assert!(summary.contains("Source URL: https://duckduckgo.com/?q=internet+of+intelligence"));
        assert!(summary.contains("Next refinement:"));
    }

    #[test]
    fn fallback_summary_is_deterministic() {
        let msg = fallback_search_summary(
            "internet of intelligence",
            "https://duckduckgo.com/?q=internet+of+intelligence",
        );
        assert_eq!(
            msg,
            "Searched 'internet of intelligence' at https://duckduckgo.com/?q=internet+of+intelligence, but structured extraction failed. Retry refinement if needed."
        );
    }

    #[test]
    fn queue_preserves_filesystem_search_from_fsread_target() {
        let request = build_fs_read_request(serde_json::json!({
            "path": "/tmp/workspace",
            "regex": "TODO",
            "file_pattern": "*.rs"
        }));

        let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
        match tool {
            AgentTool::FsSearch {
                path,
                regex,
                file_pattern,
            } => {
                assert_eq!(path, "/tmp/workspace");
                assert_eq!(regex, "TODO");
                assert_eq!(file_pattern.as_deref(), Some("*.rs"));
            }
            other => panic!("expected FsSearch, got {:?}", other),
        }
    }

    #[test]
    fn queue_infers_list_directory_for_existing_directory_path() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ioi_queue_fs_list_{}", unique));
        fs::create_dir_all(&dir).expect("temp directory should be created");
        let request = build_fs_read_request(serde_json::json!({
            "path": dir.to_string_lossy()
        }));

        let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
        match tool {
            AgentTool::FsList { path } => {
                assert_eq!(path, dir.to_string_lossy());
            }
            other => panic!("expected FsList, got {:?}", other),
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn queue_defaults_to_read_file_when_not_search_or_directory() {
        let request = build_fs_read_request(serde_json::json!({
            "path": "/tmp/not-a-real-file.txt"
        }));

        let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
        match tool {
            AgentTool::FsRead { path } => {
                assert_eq!(path, "/tmp/not-a-real-file.txt");
            }
            other => panic!("expected FsRead, got {:?}", other),
        }
    }

    #[test]
    fn queue_preserves_filesystem_patch_from_fswrite_target() {
        let request = build_fs_write_request(serde_json::json!({
            "path": "/tmp/demo.txt",
            "search": "alpha",
            "replace": "beta"
        }));

        let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
        match tool {
            AgentTool::FsPatch {
                path,
                search,
                replace,
            } => {
                assert_eq!(path, "/tmp/demo.txt");
                assert_eq!(search, "alpha");
                assert_eq!(replace, "beta");
            }
            other => panic!("expected FsPatch, got {:?}", other),
        }
    }

    #[test]
    fn queue_preserves_launch_app_for_sys_exec_target_with_app_name() {
        let request = build_sys_exec_request(serde_json::json!({
            "app_name": "calculator"
        }));

        let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
        match tool {
            AgentTool::OsLaunchApp { app_name } => {
                assert_eq!(app_name, "calculator");
            }
            other => panic!("expected OsLaunchApp, got {:?}", other),
        }
    }
}
