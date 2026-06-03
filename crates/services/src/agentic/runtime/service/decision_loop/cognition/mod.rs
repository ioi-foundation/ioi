mod browser_context;
mod capability;
mod final_reply;
mod history;
mod inference;
mod router;
mod tool_prompting;
mod worker_context;
mod workspace_changes;

use crate::agentic::runtime::agent_playbooks::{
    playbook_decision_record, render_agent_playbook_catalog,
};
use crate::agentic::runtime::service::decision_loop::signals::is_browser_surface;
use crate::agentic::runtime::service::memory::{
    persist_prompt_memory_diagnostics, prepare_prompt_memory_context, MemoryPromptDiagnostics,
    MemoryPromptSectionDiagnostic,
};
use crate::agentic::runtime::service::tool_execution::command_contract::{
    requires_timer_notification_contract, runtime_desktop_directory, runtime_home_directory,
    runtime_host_environment_evidence,
};
use crate::agentic::runtime::service::tool_execution::has_execution_evidence;
use crate::agentic::runtime::service::visual_loop::perception::PerceptionContext;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{
    AgentState, ExecutionTier, WorkerAssignment, MAX_PROMPT_HISTORY,
};
use crate::agentic::runtime::worker_templates::{
    builtin_worker_template, builtin_worker_workflow, render_worker_template_catalog,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use browser_context::{
    browser_observation_has_grounded_geometry_targets,
    browser_observation_has_grounded_shape_targets, browser_prompt_visual_grounding_required,
    goal_prefers_sustained_hover_browser_surface, has_meaningful_visual_context,
    maybe_capture_browser_prompt_screenshot, resolve_browser_observation_context,
    top_edge_jump_name, top_edge_jump_tool_call_with_grounded_selector,
};
#[cfg(test)]
use browser_context::{
    browser_surface_requires_visual_grounding, encode_browser_prompt_screenshot,
    top_edge_jump_tool_call,
};
pub(crate) use browser_context::{
    current_browser_observation_snapshot, reply_safe_browser_semantics_enabled,
};
use capability::{mailbox_connector_instruction, preflight_missing_capability};
use final_reply::{
    contextual_recent_session_events_context, final_reply_evidence_context,
    final_reply_evidence_contract_reason, final_reply_goal_requests_html_document,
    final_reply_html_document_reason, final_reply_html_document_repair_messages,
    final_reply_incomplete_reason, final_reply_market_quote_context_metric_score,
    final_reply_pending_web_evidence_context, final_reply_repair_messages,
    web_context_ready_for_reply,
};
#[cfg(test)]
use final_reply::{
    final_reply_evidence_contradiction_reason, final_reply_market_quote_context_from_pending,
    final_reply_pending_market_quote_ready,
};
pub(crate) use final_reply::{
    final_reply_product_handoff_reason, sanitize_direct_chat_reply_output,
    sanitize_product_handoff_internal_markers,
};
use hex;
use history::{
    build_browser_observation_context_from_snapshot_with_history,
    build_browser_snapshot_success_signal_context, build_recent_browser_observation_context,
    build_recent_command_history_context, build_recent_success_signal_context_with_snapshot,
};
pub(crate) use history::{
    build_browser_snapshot_pending_state_context_with_history,
    build_recent_pending_browser_state_context,
    build_recent_pending_browser_state_context_with_current_snapshot,
    build_recent_pending_browser_state_context_with_snapshot,
    latest_recent_pending_browser_state_context,
};
use image::{codecs::jpeg::JpegEncoder, GenericImageView};
use inference::{
    cognition_inference_timeout_for_reply_mode, inference_error_is_retryable_no_content,
    inference_error_system_fail_reason,
};
use ioi_crypto::algorithms::hash::sha256;
use ioi_drivers::gui::accessibility::serialize_tree_to_xml;
use ioi_drivers::gui::lenses::{auto::AutoLens, AppLens};
use ioi_types::app::agentic::{
    ChatMessage, InferenceOptions, IntentScopeProfile, LlmToolDefinition, ResolvedIntentState,
};
use ioi_types::error::TransactionError;
use router::{determine_attention_mode, AttentionMode};
use serde_json::{json, Value};
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(test)]
use tool_prompting::command_workspace_action_phase_tools;
use tool_prompting::{
    command_execution_action_phase_tools, compact_allowed_tool_list,
    compact_browser_action_prompt_tools, direct_file_read_action_phase_tools,
    direct_file_write_action_phase_tools, format_tool_desc, instruction_contract_slot_value,
    render_selected_parent_playbook_instruction, workspace_context_ready_for_reply,
};
pub(crate) use tool_prompting::{
    filter_cognition_tools, filter_cognition_tools_with_recovery, CognitionToolRecovery,
};
use worker_context::{
    build_strategy_instruction, render_active_worker_instruction,
    render_workspace_scope_instruction, workspace_reference_context,
};
use workspace_changes::{
    render_workspace_change_context, render_workspace_change_lifecycle_instruction,
};

const CURRENT_BROWSER_OBSERVATION_TIMEOUT: Duration = Duration::from_millis(1_500);
const CURRENT_BROWSER_OBSERVATION_CACHE_MAX_AGE: Duration = Duration::from_secs(12);
const BROWSER_PROMPT_SCREENSHOT_MAX_DIM: u32 = 640;
const BROWSER_PROMPT_SCREENSHOT_JPEG_QUALITY: u8 = 60;

pub struct CognitionResult {
    pub raw_output: String,
    pub strategy_used: String,
}

mod prompt_assembly;
pub(crate) use prompt_assembly::*;

pub async fn think(
    service: &RuntimeAgentService,
    agent_state: &AgentState,
    perception: &PerceptionContext,
    session_id: [u8; 32],
) -> Result<CognitionResult, TransactionError> {
    // 1. Hydrate History
    let full_history = service.hydrate_session_history(session_id)?;

    let resolved_scope = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope)
        .unwrap_or(IntentScopeProfile::Unknown);
    let resolved_intent_summary = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| {
            format!(
                "{} (scope={:?} band={:?} score={:.3})",
                resolved.intent_id, resolved.scope, resolved.band, resolved.score
            )
        })
        .unwrap_or_else(|| "unknown".to_string());
    let session_prefix = hex::encode(&session_id[..4]);

    // Urgent Feedback Injection
    let urgent_feedback = if let Some(last) = full_history.last() {
        if last.role == "user" {
            let latest_user = last.content.trim();
            let current_goal = agent_state.goal.trim();
            if latest_user.is_empty() || latest_user == current_goal {
                String::new()
            } else {
                format!(
                    "\n\n⚠️ URGENT USER UPDATE: \"{}\"\nPrioritize this over previous plans.",
                    last.content
                )
            }
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    // 2. PREFLIGHT: Missing Capability Check (Code-Level Guardrail)
    let is_browser = is_browser_surface("", &perception.active_window_title);

    if let Some((missing_capability, reason)) = preflight_missing_capability(
        agent_state.resolved_intent.as_ref(),
        resolved_scope,
        is_browser,
        &perception.available_tools,
    ) {
        log::info!(
            "Preflight: Missing required capability '{}'. Forcing escalation.",
            missing_capability
        );
        let synthetic_call = json!({
            "name": "agent__escalate",
            "arguments": {
                "reason": reason,
                "missing_capability": missing_capability
            }
        });

        return Ok(CognitionResult {
            raw_output: synthetic_call.to_string(),
            strategy_used: "Preflight-Escalation".to_string(),
        });
    }

    let has_computer_tool = perception
        .available_tools
        .iter()
        .any(|t| t.name == "screen");
    let prefer_browser_semantics = reply_safe_browser_semantics_enabled(
        is_browser,
        &perception.available_tools,
        agent_state.resolved_intent.as_ref(),
    );

    // 3. System 1 Router
    // Use the latest user message for routing, as it might change the mode (e.g. "stop" -> Chat)
    let latest_user_message = full_history
        .iter()
        .rfind(|m| m.role == "user")
        .map(|m| m.content.as_str())
        .unwrap_or(agent_state.goal.as_str());
    let latest_user_hash = sha256(latest_user_message.as_bytes())
        .map(|digest| hex::encode(digest.as_ref()))
        .unwrap_or_else(|_| "sha256_error".to_string());
    let raw_enabled = super::helpers::should_log_raw_prompt_content();
    if raw_enabled {
        let latest_user_json = serde_json::to_string(latest_user_message)
            .unwrap_or_else(|_| "\"<latest-user-serialization-error>\"".to_string());
        log::info!(
            "CognitionInputHistory session={} history_items={} latest_user_chars={} latest_user_lines={} latest_user_hash={} latest_user_json={}",
            session_prefix,
            full_history.len(),
            latest_user_message.chars().count(),
            latest_user_message.lines().count(),
            latest_user_hash,
            latest_user_json
        );
    } else {
        log::info!(
            "CognitionInputHistory session={} history_items={} latest_user_chars={} latest_user_lines={} latest_user_hash={} latest_user_json=<omitted:raw_prompt_disabled>",
            session_prefix,
            full_history.len(),
            latest_user_message.chars().count(),
            latest_user_message.lines().count(),
            latest_user_hash
        );
    }

    let mode = determine_attention_mode(
        service,
        latest_user_message,
        &agent_state.goal,
        agent_state.step_count,
        None,
        Some(resolved_scope),
    )
    .await;

    // [FIX] Removed hardcoded chat short-circuit.
    // Even if the router thinks it's chat, we let System 2 (the main prompt) make the final decision.
    // This prevents the "Chat Trap" where commands like "Search X" get stuck in "Acknowledged" loops.

    // 4. System 2 Prompting

    // Visual Verification Hint
    let verify_instruction = if let Some(note) = &perception.visual_verification_note {
        format!("\n\n{}", note)
    } else {
        String::new()
    };

    let workspace_reply_ready = workspace_context_ready_for_reply(agent_state, resolved_scope);
    let web_reply_ready = web_context_ready_for_reply(agent_state, resolved_scope);
    let failure_block = if perception.consecutive_failures > 0 {
        let failure_reason = perception
            .last_failure_reason
            .as_deref()
            .unwrap_or("UnknownFailure");
        let recovery_hint = if matches!(resolved_scope, IntentScopeProfile::WorkspaceOps)
            && failure_reason.contains("NoEffectAfterAction")
        {
            if workspace_reply_ready {
                "Recovery hint: workspace evidence is already available. Use `chat__reply` only if the observed file/search/test evidence is sufficient to answer the user. Do not claim success for an edit or command that is not verified."
            } else {
                "Recovery hint: repeated workspace probing was blocked before enough evidence was gathered. Switch to a concrete alternate workspace action such as reading the target file, editing with the latest observed content, checking workspace-change status, running the verification command, or escalating if no available tool can satisfy the request. Do not finalize without observed file/test evidence."
            }
        } else if matches!(resolved_scope, IntentScopeProfile::WebResearch)
            && failure_reason.contains("NoEffectAfterAction")
        {
            if web_reply_ready {
                "Recovery hint: web evidence is already available. Use `chat__reply` only if the selected sources are sufficient to answer the user. Do not invent missing facts."
            } else {
                "Recovery hint: repeated web retrieval was blocked before enough evidence was gathered. Switch to a distinct query/source/read path, or escalate if fresh evidence cannot be obtained. Do not finalize without grounded web evidence."
            }
        } else if matches!(resolved_scope, IntentScopeProfile::UiInteraction)
            && (failure_reason.contains("Failed to parse tool call")
                || failure_reason.contains("UnexpectedState"))
        {
            "Recovery hint: the previous browser action was malformed or empty. Do not explain, do not repeat inspection, and do not escalate yet. Emit one corrected JSON tool call using the grounded browser action from RECENT BROWSER OBSERVATION or RECENT PENDING BROWSER STATE. If the goal requests a coordinate-style target, use `browser__click_at` with the grounded id."
        } else if failure_reason.contains("TargetNotFound")
            || failure_reason.contains("VisionTargetNotFound")
        {
            "Recovery hint: run `screen__find` or `browser__inspect` first to reacquire the target before clicking."
        } else if failure_reason.contains("TimeoutOrHang")
            || failure_reason.contains("NoEffectAfterAction")
            || failure_reason.contains("NonDeterministicUI")
        {
            "Recovery hint: switch tools/modality, then verify visible state change before retrying."
        } else if failure_reason.contains("ToolUnavailable")
            || failure_reason.contains("MissingDependency")
        {
            if matches!(resolved_scope, IntentScopeProfile::CommandExecution) {
                "Recovery hint: for command failures, use command history to revise commands and probe the environment before escalating."
            } else {
                "Recovery hint: choose an equivalent available tool; if none exists, call `agent__escalate` with missing capability."
            }
        } else if failure_reason.contains("PermissionOrApprovalRequired")
            || failure_reason.contains("UserInterventionNeeded")
        {
            "Recovery hint: do not loop retries; pause and request user intervention or approval."
        } else {
            "Recovery hint: do not repeat the exact same action; choose a different approach or escalate with `agent__escalate`."
        };

        format!(
            "\n=== FAILURE ANALYSIS REQUIRED ===\n\
             - Consecutive Failures: {}\n\
             - Last Failure Fingerprint: {}\n\
             - Mandatory Reflection:\n\
               1. Explain why the previous attempt failed.\n\
               2. Do not repeat the same failing action.\n\
               3. Pick a distinct recovery action for this step.\n\
             {}\n",
            perception.consecutive_failures, failure_reason, recovery_hint
        )
    } else {
        String::new()
    };

    // Use truncated history for context window
    let recent_history = if full_history.len() > MAX_PROMPT_HISTORY {
        &full_history[full_history.len() - MAX_PROMPT_HISTORY..]
    } else {
        &full_history[..]
    };
    let hist_str = contextual_recent_session_events_context(
        recent_history,
        prefer_browser_semantics,
        resolved_scope,
        &agent_state.goal,
    );
    let current_browser_snapshot = if prefer_browser_semantics {
        current_browser_observation_snapshot(service).await
    } else {
        None
    };
    let browser_observation_context = resolve_browser_observation_context(
        &full_history,
        current_browser_snapshot.as_deref(),
        prefer_browser_semantics,
    );
    let core_memory_section = prepare_prompt_memory_context(
        service,
        session_id,
        agent_state,
        perception,
        current_browser_snapshot.as_deref(),
    )
    .await?;
    let mut pending_browser_state_context =
        build_recent_pending_browser_state_context_with_snapshot(
            &full_history,
            current_browser_snapshot.as_deref(),
        );
    if pending_browser_state_context.is_empty() {
        if let Some(snapshot) = current_browser_snapshot.as_deref() {
            pending_browser_state_context =
                build_browser_snapshot_pending_state_context_with_history(snapshot, &full_history);
        }
    }
    let mut success_signal_context = build_recent_success_signal_context_with_snapshot(
        &full_history,
        current_browser_snapshot.as_deref(),
    );
    if success_signal_context.is_empty() {
        if let Some(snapshot) = current_browser_snapshot.as_deref() {
            success_signal_context = build_browser_snapshot_success_signal_context(snapshot);
        }
    }
    if prefer_browser_semantics {
        pending_browser_state_context.clear();
        success_signal_context.clear();
    }
    let browser_visual_grounding_required = browser_prompt_visual_grounding_required(
        prefer_browser_semantics,
        mode,
        current_browser_snapshot.as_deref(),
        &browser_observation_context,
    );
    let mut prompt_screenshot_base64 = perception.screenshot_base64.clone();
    if prefer_browser_semantics && matches!(mode, AttentionMode::VisualAction) {
        if !browser_visual_grounding_required {
            prompt_screenshot_base64 = None;
        } else if !has_meaningful_visual_context(prompt_screenshot_base64.as_deref()) {
            if let Some(browser_screenshot) = maybe_capture_browser_prompt_screenshot(
                service,
                current_browser_snapshot.as_deref(),
                &browser_observation_context,
            )
            .await
            {
                prompt_screenshot_base64 = Some(browser_screenshot);
            }
        }
    }
    let has_prompt_visual_context =
        has_meaningful_visual_context(prompt_screenshot_base64.as_deref());
    let suppress_browser_recovery_terminal_tools = prefer_browser_semantics
        && perception.consecutive_failures > 0
        && perception
            .last_failure_reason
            .as_deref()
            .map(|reason| {
                reason.contains("Failed to parse tool call") || reason.contains("UnexpectedState")
            })
            .unwrap_or(false);
    let cognition_tools = filter_cognition_tools_with_recovery(
        &perception.available_tools,
        agent_state.resolved_intent.as_ref(),
        prefer_browser_semantics,
        &agent_state.goal,
        &browser_observation_context,
        &pending_browser_state_context,
        CognitionToolRecovery {
            workspace_context_ready_for_reply: workspace_reply_ready,
            web_context_ready_for_reply: web_reply_ready,
            suppress_browser_recovery_terminal_tools,
        },
    );
    let strategy_instruction = build_strategy_instruction(
        perception.tier,
        resolved_scope,
        has_computer_tool,
        prefer_browser_semantics,
        has_prompt_visual_context,
    );
    let compact_browser_action_prompt = compact_browser_action_prompt_eligible(
        prefer_browser_semantics,
        has_prompt_visual_context,
        &agent_state.goal,
        &browser_observation_context,
        &pending_browser_state_context,
        &success_signal_context,
    );
    let mut cognition_tools = if compact_browser_action_prompt {
        compact_browser_action_prompt_tools(&cognition_tools)
    } else {
        cognition_tools
    };
    if let Some(action_phase_tools) =
        direct_file_write_action_phase_tools(agent_state, &perception.available_tools)
    {
        cognition_tools = action_phase_tools;
    } else if let Some(action_phase_tools) =
        direct_file_read_action_phase_tools(agent_state, &perception.available_tools)
    {
        cognition_tools = action_phase_tools;
    } else if let Some(action_phase_tools) =
        command_execution_action_phase_tools(agent_state, &cognition_tools)
    {
        cognition_tools = action_phase_tools;
    }
    let chat_reply_only_cognition =
        cognition_tools.len() == 1 && cognition_tools[0].name == "chat__reply";
    let cognition_tool_desc = format_tool_desc(
        &cognition_tools,
        prefer_browser_semantics,
        &agent_state.goal,
        agent_state.resolved_intent.as_ref(),
    );
    let som_instruction = if !prefer_browser_semantics
        && has_prompt_visual_context
        && perception.tier != ExecutionTier::DomHeadless
    {
        "VISUAL GROUNDING ACTIVE:\n\
         The image has a 'Set-of-Marks' overlay. Green boxes indicate interactive elements.\n\
         - Each box has a numeric ID tag starting at 1.\n\
         - You can refer to elements by ID (e.g., 'left_click_id': 5) for precision.\n\
         - IDs are unique to this specific screenshot. Do not guess IDs."
    } else {
        ""
    };
    let command_history_context =
        build_recent_command_history_context(&agent_state.command_history);
    let recent_session_events_section = if hist_str.trim().is_empty() {
        String::new()
    } else {
        format!("RECENT SESSION EVENTS:\n{} \n", hist_str)
    };
    let pending_web_evidence_context = agent_state
        .pending_search_completion
        .as_ref()
        .and_then(|pending| final_reply_pending_web_evidence_context(pending, &agent_state.goal))
        .map(|context| {
            format!(
                "PENDING WEB TOOL EVIDENCE:\n\
Use this typed tool-result evidence when deciding whether to answer with `chat__reply`. \
Do not replace it with search snippets, stale model memory, or deterministic summary templates.\n\n{}",
                context
            )
        })
        .unwrap_or_default();
    if !pending_web_evidence_context.trim().is_empty() {
        log::info!(
            "CognitionPendingWebEvidence session={} chars={} quote_metric_score={}",
            session_prefix,
            pending_web_evidence_context.chars().count(),
            final_reply_market_quote_context_metric_score(&pending_web_evidence_context)
        );
    }
    let command_history_section = if command_history_context.trim().is_empty() {
        String::new()
    } else {
        format!("COMMAND HISTORY:\n{}\n", command_history_context)
    };
    let operating_rules = build_operating_rules(
        prefer_browser_semantics,
        &agent_state.goal,
        &browser_observation_context,
        &pending_browser_state_context,
        &success_signal_context,
    );
    let tool_routing_contract =
        build_tool_routing_contract(prefer_browser_semantics, resolved_scope);
    let workspace_context = workspace_reference_context(prefer_browser_semantics, &perception);
    let workspace_change_context = render_workspace_change_context(agent_state);
    let workspace_change_lifecycle_instruction =
        render_workspace_change_lifecycle_instruction(agent_state);
    let kernel_guidance = "IMPORTANT: Use only the available tools and grounded evidence from this step.\n\
If an action requires approval, escalation, or missing capability handling, choose the corresponding tool path and let the runtime mediate it.\n\
Do not claim success for actions you did not verify.";
    log::info!(
        "CognitionPromptShape session={} is_browser={} meaningful_visual_context={} prefer_browser_semantics={} discovered_tool_count={} cognition_tool_count={}",
        session_prefix,
        is_browser,
        has_prompt_visual_context,
        prefer_browser_semantics,
        perception.available_tools.len(),
        cognition_tools.len()
    );
    let command_scope_instruction = if matches!(
        resolved_scope,
        IntentScopeProfile::CommandExecution
    ) {
        let discovery_timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let host_receipt = runtime_host_environment_evidence(discovery_timestamp_ms);
        let runtime_home_dir =
            runtime_home_directory().unwrap_or_else(|| host_receipt.observed_value.clone());
        let runtime_desktop_dir = runtime_desktop_directory().or(host_receipt.desktop_directory);
        let runtime_desktop_dir = runtime_desktop_dir.unwrap_or_else(|| "unavailable".to_string());

        format!(
            "COMMAND EXECUTION CONTRACT:\n\
             - Treat terminal output and command history as primary evidence.\n\
             - Follow capability-execution lifecycle: discovery -> policy route -> execution -> verification -> final response.\n\
             - Discovery must probe host capabilities in typed categories (apps/integrations, shell tools, permissions/approvals, and signal/notification channels when relevant).\n\
             - Route selection must be explicit and evidence-backed: `native_integration` | `enablement_request` | `script_backend`.\n\
             - Screenshot/visual artifacts are non-blocking for command workflows.\n\
             - Perform environment discovery with `shell__run`/`shell__start` when command availability is uncertain.\n\
             - Execute only after route selection and keep execution steps minimal.\n\
             - Runtime host facts (authoritative for command synthesis):\n\
               - runtime_home_dir={}\n\
               - runtime_desktop_dir={}\n\
               - discovery_probe={}\n\
               - discovery_timestamp_ms={}\n\
               - discovery_satisfied={}\n\
             - Never synthesize absolute paths under a different home owner than runtime_home_dir.\n\
             - Never run long blocking commands (for example `sleep`) in foreground mode; use `detach: true` or scheduler-style commands.\n\
             - Do not run more than 3 consecutive shell commands without either finalizing or escalating.\n\
             - If command history already shows the same command succeeded, do not rerun it; finalize instead.\n\
             - If tool output reports a duplicate/no-effect replay guard (for example `ERROR_CLASS=NoEffectAfterAction` or `duplicate_action_fingerprint_non_command_skipped=true`), do not repeat the same tool+arguments; switch to a different capability path or verify the updated state.\n\
             - After goal success, emit `chat__reply` exactly once, then call `agent__complete`.\n\
             - Final user response must be structured from evidence and include `Mechanism: ...`; include timestamps/handles/status controls whenever available.\n\
             - For time-sensitive tasks, include an absolute UTC timestamp in the final reply as `Target UTC: YYYY-MM-DDTHH:MM:SSZ`.\n\
             - For timer/alarm/countdown goals, the notification path must be deferred to fire at due time (for example `sleep ... && notify-send ...` or scheduler equivalent); immediate standalone `notify-send` does not satisfy the contract.\n\
             - If tool output reports `ERROR_CLASS=ExecutionContractViolation ... missing_keys=...`, do not retry or rewrite the command loop; surface a terminal contract failure via `agent__escalate`.\n\
             - Use `agent__escalate` only when command tooling is unavailable.",
            runtime_home_dir,
            runtime_desktop_dir,
            host_receipt.probe_source,
            host_receipt.timestamp_ms,
            host_receipt.satisfied
        )
    } else {
        String::new()
    };
    let workspace_scope_instruction = if matches!(resolved_scope, IntentScopeProfile::WorkspaceOps)
    {
        let selected_playbook_id =
            instruction_contract_slot_value(agent_state.resolved_intent.as_ref(), "playbook_id");
        let active_worker_assignment = perception.worker_assignment.as_ref();
        let has_filesystem_search = perception
            .available_tools
            .iter()
            .any(|tool| tool.name == "file__search");
        let has_filesystem_stat = perception
            .available_tools
            .iter()
            .any(|tool| tool.name == "file__info");
        let has_filesystem_list = perception
            .available_tools
            .iter()
            .any(|tool| tool.name == "file__list");
        let has_command_tool = perception
            .available_tools
            .iter()
            .any(|tool| matches!(tool.name.as_str(), "shell__run" | "shell__start"));
        render_workspace_scope_instruction(
            selected_playbook_id,
            has_filesystem_search,
            has_filesystem_stat,
            has_filesystem_list,
            has_command_tool,
            active_worker_assignment,
        )
    } else {
        String::new()
    };
    let automation_monitor_instruction = if agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.intent_id == "automation.monitor")
        .unwrap_or(false)
    {
        "AUTOMATION MONITOR CONTRACT:\n\
         - This goal is a durable local automation install, not a shell session.\n\
         - Use `monitor__create` to install the workflow.\n\
         - Do NOT use `shell__run`, `shell__start`, cron, systemd timers, launchd, or ad hoc sleep loops for this intent.\n\
         - Encode the workflow semantics directly in the tool arguments: keywords, optional title/description, poll interval, and source_prompt.\n\
         - After successful install, finalize with the installed workflow summary."
            .to_string()
    } else {
        String::new()
    };
    let selected_parent_playbook_instruction =
        render_selected_parent_playbook_instruction(agent_state.resolved_intent.as_ref());
    let active_worker_instruction = render_active_worker_instruction(
        perception.worker_assignment.as_ref(),
        &agent_state.working_directory,
    );

    let mailbox_instruction =
        mailbox_connector_instruction(&agent_state.goal, &perception.available_tools);
    let prompt_assembly = if compact_browser_action_prompt {
        build_compact_browser_action_prompt_assembly(
            kernel_guidance,
            &perception.active_window_title,
            &agent_state.goal,
            &resolved_intent_summary,
            &core_memory_section,
            &urgent_feedback,
            &failure_block,
            &strategy_instruction,
            &tool_routing_contract,
            &verify_instruction,
            &cognition_tool_desc,
            &browser_observation_context,
            &pending_browser_state_context,
            &success_signal_context,
            &operating_rules,
        )
    } else {
        build_standard_prompt_assembly(
            kernel_guidance,
            &perception.active_window_title,
            &agent_state.goal,
            &resolved_intent_summary,
            &core_memory_section,
            &urgent_feedback,
            &failure_block,
            &strategy_instruction,
            &tool_routing_contract,
            som_instruction,
            &verify_instruction,
            &command_scope_instruction,
            &workspace_change_lifecycle_instruction,
            &cognition_tool_desc,
            &browser_observation_context,
            &pending_browser_state_context,
            &success_signal_context,
            &pending_web_evidence_context,
            &recent_session_events_section,
            &command_history_section,
            &workspace_context,
            &workspace_change_context,
            &operating_rules,
            mailbox_instruction.as_deref(),
            selected_parent_playbook_instruction.as_deref(),
            active_worker_instruction.as_deref(),
            &workspace_scope_instruction,
            &automation_monitor_instruction,
        )
    };
    log::info!(
        "CognitionPromptAssembly session={} total_chars={} sections={}",
        session_prefix,
        prompt_assembly.report.total_chars,
        format_prompt_assembly_report(&prompt_assembly.report)
    );
    if let Some(memory_runtime) = service.memory_runtime.as_ref() {
        let diagnostics = build_prompt_memory_diagnostics(session_id, &prompt_assembly);
        if let Err(error) =
            persist_prompt_memory_diagnostics(memory_runtime.as_ref(), session_id, &diagnostics)
        {
            log::warn!("Failed to persist prompt memory diagnostics: {}", error);
        }
    }
    let system_instructions = prompt_assembly.system_instructions;

    let include_screenshot =
        has_prompt_visual_context && matches!(mode, AttentionMode::VisualAction);

    let final_reply_evidence_context_for_synthesis = if chat_reply_only_cognition {
        let mut evidence_context = final_reply_evidence_context(
            &full_history,
            &agent_state.goal,
            &recent_session_events_section,
        );
        if evidence_context.trim().is_empty() {
            evidence_context = "No structured tool evidence was retained.".to_string();
        }
        if let Some(pending_web_context) =
            agent_state
                .pending_search_completion
                .as_ref()
                .and_then(|pending| {
                    final_reply_pending_web_evidence_context(pending, &agent_state.goal)
                })
        {
            let evidence_score = final_reply_market_quote_context_metric_score(&evidence_context);
            let pending_score = final_reply_market_quote_context_metric_score(&pending_web_context);
            if pending_score >= 4 {
                evidence_context = if evidence_context.trim().is_empty()
                    || evidence_context.trim() == "No structured tool evidence was retained."
                    || evidence_context.contains(pending_web_context.trim())
                {
                    pending_web_context
                } else {
                    format!(
                        "{pending_web_context}\n\n---\n\nSupporting retrieved context:\n{evidence_context}"
                    )
                };
            } else if pending_score > evidence_score {
                evidence_context = pending_web_context;
            } else if evidence_score == 0 && {
                let evidence_lower = evidence_context.to_ascii_lowercase();
                !evidence_lower.contains("current market quote observations from tool results")
                    && !evidence_lower.contains("typed market quote evidence from tool results")
            } {
                evidence_context = if evidence_context.trim().is_empty()
                    || evidence_context.trim() == "No structured tool evidence was retained."
                {
                    pending_web_context
                } else {
                    format!("{pending_web_context}\n\n---\n\n{evidence_context}")
                };
            } else if !pending_web_context.trim().is_empty()
                && !evidence_context.contains(pending_web_context.trim())
                && !pending_web_context.contains(evidence_context.trim())
            {
                evidence_context = format!("{pending_web_context}\n\n---\n\n{evidence_context}");
            }
        }
        log::info!(
            "FinalReplyEvidenceContext session={} chars={} quote_metric_score={}",
            session_prefix,
            evidence_context.chars().count(),
            final_reply_market_quote_context_metric_score(&evidence_context)
        );
        evidence_context
    } else {
        String::new()
    };
    let final_reply_html_document_mode =
        chat_reply_only_cognition && final_reply_goal_requests_html_document(&agent_state.goal);
    let final_reply_system_content = if final_reply_html_document_mode {
        "FINAL RESPONSE MODE:\nUse the gathered tool evidence to satisfy the user's request directly.\nThe user is asking for a source document artifact. Return the complete source document only. Do not call tools. Do not output JSON. Do not expose hidden chain-of-thought, trace ids, receipt ids, raw payloads, or daemon scaffolding.\nFor HTML website/page requests, start exactly with <!DOCTYPE html>, include the full html/head/body structure, and end exactly with </html>. Do not wrap the document in Markdown fences. Do not add explanatory prose before or after the document.\nUse source facts from gathered evidence where helpful, but keep the document concise enough to finish in one pass."
    } else {
        "FINAL RESPONSE MODE:\nUse the gathered tool evidence to answer the user's request directly in natural Markdown.\nDo not call tools. Do not output JSON. Do not expose hidden chain-of-thought, trace ids, receipt ids, raw payloads, raw stdout/stderr, raw test logs, raw coordinates, or daemon scaffolding. Do not copy internal observation labels, run dates, timestamps, confidence labels, fixture markers, or evidence-packet wording into the final answer.\nFor command, test, and workspace-change tasks, give a concise handoff: what changed or was inspected, whether verification passed, and any remaining blocker. Do not paste TAP output, full stdout/stderr, or raw logs unless the user explicitly requested raw logs. If you cite the final contents of a changed file or a short command-created source snippet, put it in a fenced code block with a language tag instead of appending it inline to a sentence. When gathered evidence contains repeated observations of the same file or state, use the latest/highest-numbered observation as authoritative for the current state.\nFor research, current-events, web, source-backed, comparison, recommendation, and investment questions, produce a substantive model-authored synthesis instead of a terse source list. Use tables, bullets, and sections only when they naturally improve clarity; do not follow a fixed template.\nPreserve concrete source anchors that matter to the user's question, including file paths, symbol names, markdown heading labels, source titles, URLs, observed prices, market caps, volumes, percentages, and other measurements from the evidence.\nFor comparison or recommendation questions, synthesize the evidence into a direct answer with tradeoffs. Do not invent project adoption, investors, institutional interest, market leadership, enterprise use, competitive displacement, or performance claims unless those facts are present in the gathered evidence.\nFor finance or investment questions, be cautious and note that it is not financial advice. Treat current market quote observations from tool results as authoritative for current market values. Ignore conflicting current-price, market-cap, volume, or percentage snippets from broader search results. If current market quote observations include price, market cap, 24h trading volume, and 24h price change for compared assets, include those observed dimensions for each compared asset in compact bullets or a comparison table and do not say they are missing. Treat per-token price only as a quoted measurement; do not treat lower or higher nominal token price, entry price, affordability, cheapness, expensiveness, or price point as an investment advantage by itself.\nIf the user asks to find or provide sources, include source titles and URLs that support the answer. For source-backed web answers, include sources at the bottom in a short readable list when useful.\nIf the user asks about progress, stages, a plan, or a guide and the evidence includes a Markdown heading outline, explicitly name the relevant headings or stage labels instead of flattening them into generic prose.\nIf the evidence is incomplete, say what is known and state the limitation plainly."
    };
    let messages = if chat_reply_only_cognition {
        json!([
            {
                "role": "system",
                "content": final_reply_system_content
            },
            {
                "role": "user",
                "content": format!(
                    "Original user request:\n{}\n\nGathered evidence:\n{}\n\nWrite the final user-facing answer now.",
                    agent_state.goal,
                    final_reply_evidence_context_for_synthesis
                )
            }
        ])
    } else if include_screenshot {
        let b64 = prompt_screenshot_base64
            .as_ref()
            .expect("include_screenshot implies screenshot data");
        let user_instruction = if prefer_browser_semantics {
            "Use the goal, recent browser observations, and the current browser state to execute the next step. Prefer browser semantic tools."
        } else {
            "Observe the screen and execute the next step."
        };
        json!([
            { "role": "system", "content": system_instructions },
            { "role": "user", "content": [
                { "type": "text", "text": user_instruction },
                { "type": "image_url", "image_url": { "url": format!("data:image/jpeg;base64,{}", b64) } }
            ]}
        ])
    } else {
        let action_instruction = if agent_state
            .resolved_intent
            .as_ref()
            .map(|resolved| resolved.intent_id == "automation.monitor")
            .unwrap_or(false)
        {
            "Install the durable monitor workflow now using `monitor__create`. Do not use shell commands."
        } else if matches!(resolved_scope, IntentScopeProfile::CommandExecution) {
            "Execute the next step using command tools. Rely on terminal output and command history; visual artifacts are non-blocking."
        } else if compact_browser_action_prompt {
            "Choose the next grounded browser tool call from the browser state."
        } else if prefer_browser_semantics {
            "Use the goal, recent browser observations, and available browser tools to execute the next step."
        } else {
            "Execute the next step based on the goal and history."
        };
        let recent_tool_observations = recent_session_events_section.trim();
        let latest_failure_observation = failure_block.trim();
        let mut user_instruction = format!(
            "Goal:\n{}\n\nNext action:\n{}",
            agent_state.goal.trim(),
            action_instruction
        );
        if !recent_tool_observations.is_empty() {
            user_instruction.push_str("\n\nRecent tool observations:\n");
            user_instruction.push_str(recent_tool_observations);
        }
        if !latest_failure_observation.is_empty() {
            user_instruction.push_str("\n\nLatest failed action boundary:\n");
            user_instruction.push_str(latest_failure_observation);
        }
        user_instruction.push_str(
            "\n\nContinue the model -> tool -> result loop. Use the latest tool result as authoritative. Output exactly one valid JSON tool call; do not explain the plan in prose.",
        );
        json!([
            { "role": "system", "content": system_instructions },
            { "role": "user", "content": user_instruction }
        ])
    };

    // 5. Inference
    let model_hash = [0u8; 32];
    let options = InferenceOptions {
        temperature: if compact_browser_action_prompt {
            0.0
        } else if chat_reply_only_cognition {
            0.2
        } else {
            0.1
        },
        json_mode: !chat_reply_only_cognition,
        max_tokens: if compact_browser_action_prompt {
            96
        } else if chat_reply_only_cognition {
            FINAL_REPLY_MAX_TOKENS
        } else {
            256
        },
        tools: if chat_reply_only_cognition {
            Vec::new()
        } else {
            cognition_tools.clone()
        },
        ..Default::default()
    };
    let messages_payload = serde_json::to_string(&messages)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let payload_hash = sha256(messages_payload.as_bytes())
        .map(|digest| hex::encode(digest.as_ref()))
        .unwrap_or_else(|_| "sha256_error".to_string());
    if include_screenshot {
        log::info!(
            "CognitionInferencePayload session={} payload_bytes={} payload_hash={} payload_json=<omitted:screenshot_base64_present>",
            session_prefix,
            messages_payload.len(),
            payload_hash
        );
    } else {
        if raw_enabled {
            log::info!(
                "CognitionInferencePayload session={} payload_bytes={} payload_hash={} payload_json={}",
                session_prefix,
                messages_payload.len(),
                payload_hash,
                messages_payload
            );
        } else {
            log::info!(
                "CognitionInferencePayload session={} payload_bytes={} payload_hash={} payload_json=<omitted:raw_prompt_disabled>",
                session_prefix,
                messages_payload.len(),
                payload_hash
            );
        }
    }
    let input_bytes = messages_payload.into_bytes();

    // Use reasoning model for Visual modes
    let runtime = if perception.tier != ExecutionTier::DomHeadless {
        service.reasoning_inference.clone()
    } else {
        service.fast_inference.clone()
    };

    let inference_input = service
        .prepare_cloud_inference_input(
            Some(session_id),
            "desktop_agent",
            &format!("model_hash:{}", hex::encode(model_hash)),
            &input_bytes,
        )
        .await?;
    let inference_timeout = if final_reply_html_document_mode {
        cognition_inference_timeout_for_reply_mode(chat_reply_only_cognition).max(
            Duration::from_secs(FINAL_REPLY_SOURCE_DOCUMENT_TIMEOUT_SECS),
        )
    } else {
        cognition_inference_timeout_for_reply_mode(chat_reply_only_cognition)
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(1024);
    let event_sender_clone = service.event_sender.clone();
    let stream_final_answer = chat_reply_only_cognition;
    let stream_html_document = final_reply_html_document_mode;
    let streamed_final_answer_buffer = Arc::new(Mutex::new(String::new()));
    let streamed_final_answer_buffer_clone = Arc::clone(&streamed_final_answer_buffer);
    let stream_forwarder = tokio::spawn(async move {
        let mut held_source_prefix = String::new();
        let mut source_prefix_forwarding = false;
        let mut source_prefix_suppressed = false;
        if let Some(event_sender) = event_sender_clone {
            while let Some(token) = rx.recv().await {
                if stream_final_answer {
                    if let Ok(mut buffer) = streamed_final_answer_buffer_clone.lock() {
                        buffer.push_str(&token);
                    }
                }
                if stream_html_document && !source_prefix_forwarding {
                    held_source_prefix.push_str(&token);
                    let trimmed_lower = held_source_prefix.trim_start().to_ascii_lowercase();
                    if trimmed_lower.starts_with("<!doctype html")
                        || trimmed_lower.starts_with("<html")
                    {
                        source_prefix_forwarding = true;
                        let event = ioi_types::app::KernelEvent::AgentAnswerDelta {
                            session_id,
                            token: held_source_prefix.clone(),
                        };
                        let _ = event_sender.send(event);
                        held_source_prefix.clear();
                        continue;
                    }
                    if held_source_prefix.chars().count() > 256 {
                        source_prefix_suppressed = true;
                    }
                    if source_prefix_suppressed {
                        continue;
                    }
                    continue;
                }
                let event = if stream_final_answer {
                    ioi_types::app::KernelEvent::AgentAnswerDelta { session_id, token }
                } else {
                    ioi_types::app::KernelEvent::AgentThought { session_id, token }
                };
                let _ = event_sender.send(event);
            }
        }
    });

    let output_bytes = match tokio::time::timeout(
        inference_timeout,
        runtime.execute_inference_streaming(
            model_hash,
            &inference_input,
            options.clone(),
            Some(tx),
        ),
    )
    .await
    {
        Err(_) => {
            let timeout_ms = inference_timeout.as_millis();
            log::warn!(
                "Cognition inference timed out session={} timeout_ms={}",
                session_prefix,
                timeout_ms
            );
            if final_reply_html_document_mode {
                let partial_chars = streamed_final_answer_buffer
                    .lock()
                    .map(|buffer| buffer.chars().count())
                    .unwrap_or(0);
                log::warn!(
                    "Final HTML document synthesis timed out session={} partial_chars={} attempting fresh model-authored repair",
                    session_prefix,
                    partial_chars
                );
                let retry_messages = final_reply_html_document_repair_messages(
                    &agent_state.goal,
                    &final_reply_evidence_context_for_synthesis,
                    "timeout_before_complete_html_document",
                    1,
                );
                let retry_payload = serde_json::to_string(&retry_messages)
                    .map_err(|e| TransactionError::Serialization(e.to_string()))?;
                let retry_payload_hash = sha256(retry_payload.as_bytes())
                    .map(|digest| hex::encode(digest.as_ref()))
                    .unwrap_or_else(|_| "sha256_error".to_string());
                if raw_enabled {
                    log::info!(
                        "CognitionInferencePayload session={} retry=final_html_document_timeout_repair payload_bytes={} payload_hash={} payload_json={}",
                        session_prefix,
                        retry_payload.len(),
                        retry_payload_hash,
                        retry_payload
                    );
                } else {
                    log::info!(
                        "CognitionInferencePayload session={} retry=final_html_document_timeout_repair payload_bytes={} payload_hash={} payload_json=<omitted:raw_prompt_disabled>",
                        session_prefix,
                        retry_payload.len(),
                        retry_payload_hash
                    );
                }
                let retry_input_bytes = retry_payload.into_bytes();
                let retry_inference_input = service
                    .prepare_cloud_inference_input(
                        Some(session_id),
                        "desktop_agent",
                        &format!("model_hash:{}", hex::encode(model_hash)),
                        &retry_input_bytes,
                    )
                    .await?;
                let mut retry_options = options.clone();
                retry_options.temperature = 0.1;
                retry_options.max_tokens = FINAL_REPLY_MAX_TOKENS;
                retry_options.tools = Vec::new();
                retry_options.json_mode = false;
                let retry_output_bytes = match tokio::time::timeout(
                    inference_timeout,
                    runtime.execute_inference_streaming(
                        model_hash,
                        &retry_inference_input,
                        retry_options,
                        None,
                    ),
                )
                .await
                {
                    Err(_) => {
                        return Ok(CognitionResult {
                            raw_output: json!({
                                "name": "agent__escalate",
                                "arguments": {
                                    "reason": format!(
                                        "ERROR_CLASS=TimeoutOrHang Final HTML document repair timed out after {}ms.",
                                        timeout_ms
                                    )
                                }
                            })
                            .to_string(),
                            strategy_used: "FinalHtmlDocumentTimeoutRepairTimeout".to_string(),
                        });
                    }
                    Ok(result) => match result {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            let err_msg = e.to_string();
                            log::error!(
                                "Final HTML document timeout repair inference failed: {}",
                                err_msg
                            );
                            return Ok(CognitionResult {
                                raw_output: json!({
                                    "name": "agent__escalate",
                                    "arguments": {
                                        "reason": inference_error_system_fail_reason(&err_msg),
                                    }
                                })
                                .to_string(),
                                strategy_used: "FinalHtmlDocumentTimeoutRepairError".to_string(),
                            });
                        }
                    },
                };
                let retry_raw_output = String::from_utf8_lossy(&retry_output_bytes).to_string();
                let retry_message = sanitize_product_handoff_internal_markers(
                    &sanitize_direct_chat_reply_output(&retry_raw_output),
                );
                if let Some(reason) =
                    final_reply_html_document_reason(&retry_message, &agent_state.goal)
                        .or_else(|| final_reply_incomplete_reason(&retry_message))
                {
                    log::error!(
                        "Final HTML document timeout repair remained invalid session={} reason={} chars={}",
                        session_prefix,
                        reason,
                        retry_message.len()
                    );
                    return Ok(CognitionResult {
                        raw_output: json!({
                            "name": "agent__escalate",
                            "arguments": {
                                "reason": format!(
                                    "ERROR_CLASS=UserInterventionNeeded Final HTML document synthesis remained incomplete after timeout repair ({reason}). Verify provider output limits and resume."
                                )
                            }
                        })
                        .to_string(),
                        strategy_used: "FinalHtmlDocumentTimeoutRepairIncomplete".to_string(),
                    });
                }
                return Ok(CognitionResult {
                    raw_output: json!({
                        "name": "chat__reply",
                        "arguments": {
                            "message": retry_message
                        }
                    })
                    .to_string(),
                    strategy_used: "FinalHtmlDocumentTimeoutRepaired".to_string(),
                });
            }
            return Ok(CognitionResult {
                raw_output: json!({
                    "name": "agent__escalate",
                    "arguments": {
                        "reason": format!(
                            "ERROR_CLASS=TimeoutOrHang Cognition inference timed out after {}ms.",
                            timeout_ms
                        )
                    }
                })
                .to_string(),
                strategy_used: "InferenceTimeout".to_string(),
            });
        }
        Ok(result) => match result {
            Ok(bytes) => bytes,
            Err(e) => {
                let err_msg = e.to_string();
                // Handle Refusals (Pause)
                if err_msg.contains("LLM_REFUSAL") {
                    let reason = err_msg
                        .replace("Host function error: LLM_REFUSAL: ", "")
                        .replace("LLM_REFUSAL: ", "");
                    return Ok(CognitionResult {
                        raw_output: json!({
                            "name": "system::refusal",
                            "arguments": { "reason": reason }
                        })
                        .to_string(),
                        strategy_used: "Refusal".to_string(),
                    });
                }
                if inference_error_is_retryable_no_content(&err_msg) {
                    log::warn!(
                        "Cognition inference stream returned no content session={} retry=1",
                        session_prefix
                    );
                    let retry_inference_input = service
                        .prepare_cloud_inference_input(
                            Some(session_id),
                            "desktop_agent",
                            &format!("model_hash:{}", hex::encode(model_hash)),
                            &input_bytes,
                        )
                        .await?;
                    let retry_result = tokio::time::timeout(
                        inference_timeout,
                        runtime.execute_inference_streaming(
                            model_hash,
                            &retry_inference_input,
                            options.clone(),
                            None,
                        ),
                    )
                    .await;
                    match retry_result {
                        Ok(Ok(bytes)) if !String::from_utf8_lossy(&bytes).trim().is_empty() => {
                            bytes
                        }
                        Ok(Ok(_)) => {
                            log::error!(
                                "Cognition no-content retry returned empty output session={}",
                                session_prefix
                            );
                            return Ok(CognitionResult {
                                raw_output: json!({
                                    "name": "agent__escalate",
                                    "arguments": {
                                        "reason": "ERROR_CLASS=RuntimeRetryable Cognition inference returned empty output after one retry. Provider health is unstable; retry the turn or switch model."
                                    }
                                })
                                .to_string(),
                                strategy_used: "InferenceNoContentRetryEmpty".to_string(),
                            });
                        }
                        Ok(Err(retry_error)) => {
                            let retry_err_msg = retry_error.to_string();
                            log::error!(
                                "Cognition no-content retry failed session={} error={}",
                                session_prefix,
                                retry_err_msg
                            );
                            return Ok(CognitionResult {
                                raw_output: json!({
                                    "name": "agent__escalate",
                                    "arguments": {
                                        "reason": inference_error_system_fail_reason(&retry_err_msg),
                                    }
                                })
                                .to_string(),
                                strategy_used: "InferenceNoContentRetryError".to_string(),
                            });
                        }
                        Err(_) => {
                            let timeout_ms = inference_timeout.as_millis();
                            log::warn!(
                                "Cognition no-content retry timed out session={} timeout_ms={}",
                                session_prefix,
                                timeout_ms
                            );
                            return Ok(CognitionResult {
                                raw_output: json!({
                                    "name": "agent__escalate",
                                    "arguments": {
                                        "reason": format!(
                                            "ERROR_CLASS=TimeoutOrHang Cognition inference no-content retry timed out after {}ms.",
                                            timeout_ms
                                        )
                                    }
                                })
                                .to_string(),
                                strategy_used: "InferenceNoContentRetryTimeout".to_string(),
                            });
                        }
                    }
                } else {
                    log::error!("CRITICAL: Agent Inference Failed: {}", e);
                    return Ok(CognitionResult {
                        raw_output: json!({
                            "name": "agent__escalate",
                            "arguments": {
                                "reason": inference_error_system_fail_reason(&err_msg),
                            }
                        })
                        .to_string(),
                        strategy_used: "InferenceError".to_string(),
                    });
                }
            }
        },
    };

    if chat_reply_only_cognition {
        let _ = tokio::time::timeout(Duration::from_millis(500), stream_forwarder).await;
    }

    let raw_output_from_bytes = String::from_utf8_lossy(&output_bytes).to_string();
    let raw_output = if chat_reply_only_cognition {
        let streamed_output = streamed_final_answer_buffer
            .lock()
            .map(|buffer| buffer.clone())
            .unwrap_or_default();
        if !streamed_output.trim().is_empty()
            && (raw_output_from_bytes.trim().is_empty()
                || streamed_output.chars().count() >= raw_output_from_bytes.chars().count())
        {
            streamed_output
        } else {
            raw_output_from_bytes
        }
    } else {
        raw_output_from_bytes
    };
    if chat_reply_only_cognition {
        let mut message = sanitize_product_handoff_internal_markers(
            &sanitize_direct_chat_reply_output(&raw_output),
        );
        let mut strategy_used = "FinalReplySynthesis";
        if message.trim().is_empty() {
            log::error!(
                "CRITICAL: Agent final reply synthesis returned empty output session={}",
                session_prefix
            );
            return Ok(CognitionResult {
                raw_output: json!({
                    "name": "agent__escalate",
                    "arguments": {
                        "reason": "ERROR_CLASS=UserInterventionNeeded Final reply synthesis returned empty output. Verify provider health and resume."
                    }
                })
                .to_string(),
                strategy_used: "FinalReplySynthesisEmptyOutput".to_string(),
            });
        }
        if let Some(mut repair_reason) =
            final_reply_html_document_reason(&message, &agent_state.goal)
                .or_else(|| final_reply_incomplete_reason(&message))
                .or_else(|| final_reply_product_handoff_reason(&message, &agent_state.goal))
                .or_else(|| {
                    final_reply_evidence_contract_reason(
                        &message,
                        &final_reply_evidence_context_for_synthesis,
                        &agent_state.goal,
                    )
                })
        {
            let mut previous_answer = message.clone();
            let mut repaired = false;
            for attempt in 1..=FINAL_REPLY_REPAIR_ATTEMPTS {
                log::warn!(
                    "Agent final reply synthesis required repair session={} attempt={} reason={} chars={}",
                    session_prefix,
                    attempt,
                    repair_reason,
                    previous_answer.len()
                );
                let retry_messages = if final_reply_html_document_mode {
                    final_reply_html_document_repair_messages(
                        &agent_state.goal,
                        &final_reply_evidence_context_for_synthesis,
                        repair_reason,
                        attempt,
                    )
                } else {
                    final_reply_repair_messages(
                        &messages,
                        &previous_answer,
                        repair_reason,
                        attempt,
                        &agent_state.goal,
                        &final_reply_evidence_context_for_synthesis,
                    )
                };
                let retry_payload = serde_json::to_string(&retry_messages)
                    .map_err(|e| TransactionError::Serialization(e.to_string()))?;
                let retry_payload_hash = sha256(retry_payload.as_bytes())
                    .map(|digest| hex::encode(digest.as_ref()))
                    .unwrap_or_else(|_| "sha256_error".to_string());
                if raw_enabled {
                    log::info!(
                        "CognitionInferencePayload session={} retry=final_reply_repair attempt={} payload_bytes={} payload_hash={} payload_json={}",
                        session_prefix,
                        attempt,
                        retry_payload.len(),
                        retry_payload_hash,
                        retry_payload
                    );
                } else {
                    log::info!(
                        "CognitionInferencePayload session={} retry=final_reply_repair attempt={} payload_bytes={} payload_hash={} payload_json=<omitted:raw_prompt_disabled>",
                        session_prefix,
                        attempt,
                        retry_payload.len(),
                        retry_payload_hash
                    );
                }
                let retry_input_bytes = retry_payload.into_bytes();
                let retry_inference_input = service
                    .prepare_cloud_inference_input(
                        Some(session_id),
                        "desktop_agent",
                        &format!("model_hash:{}", hex::encode(model_hash)),
                        &retry_input_bytes,
                    )
                    .await?;
                let mut retry_options = options.clone();
                retry_options.temperature = 0.1;
                retry_options.max_tokens = if final_reply_html_document_mode {
                    FINAL_REPLY_MAX_TOKENS
                } else {
                    FINAL_REPLY_REPAIR_MAX_TOKENS
                };
                let retry_output_bytes = match tokio::time::timeout(
                    inference_timeout,
                    runtime.execute_inference_streaming(
                        model_hash,
                        &retry_inference_input,
                        retry_options,
                        None,
                    ),
                )
                .await
                {
                    Err(_) => {
                        let timeout_ms = inference_timeout.as_millis();
                        log::warn!(
                            "Final reply repair inference timed out session={} attempt={} timeout_ms={}",
                            session_prefix,
                            attempt,
                            timeout_ms
                        );
                        return Ok(CognitionResult {
                            raw_output: json!({
                                "name": "agent__escalate",
                                "arguments": {
                                    "reason": format!(
                                        "ERROR_CLASS=TimeoutOrHang Final reply repair timed out after {}ms.",
                                        timeout_ms
                                    )
                                }
                            })
                            .to_string(),
                            strategy_used: "FinalReplySynthesisRepairTimeout".to_string(),
                        });
                    }
                    Ok(result) => match result {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            let err_msg = e.to_string();
                            log::error!(
                                "Final reply repair inference failed attempt={}: {}",
                                attempt,
                                err_msg
                            );
                            return Ok(CognitionResult {
                                raw_output: json!({
                                    "name": "agent__escalate",
                                    "arguments": {
                                        "reason": inference_error_system_fail_reason(&err_msg),
                                    }
                                })
                                .to_string(),
                                strategy_used: "FinalReplySynthesisRepairError".to_string(),
                            });
                        }
                    },
                };
                let retry_raw_output = String::from_utf8_lossy(&retry_output_bytes).to_string();
                let retry_message = sanitize_product_handoff_internal_markers(
                    &sanitize_direct_chat_reply_output(&retry_raw_output),
                );
                if retry_message.trim().is_empty() {
                    log::error!(
                        "CRITICAL: Agent final reply repair returned empty output session={} attempt={}",
                        session_prefix,
                        attempt
                    );
                    return Ok(CognitionResult {
                        raw_output: json!({
                            "name": "agent__escalate",
                            "arguments": {
                                "reason": "ERROR_CLASS=UserInterventionNeeded Final reply repair returned empty output. Verify provider health and resume."
                            }
                        })
                        .to_string(),
                        strategy_used: "FinalReplySynthesisRepairEmptyOutput".to_string(),
                    });
                }
                if let Some(retry_reason) =
                    final_reply_html_document_reason(&retry_message, &agent_state.goal)
                        .or_else(|| final_reply_incomplete_reason(&retry_message))
                        .or_else(|| {
                            final_reply_product_handoff_reason(&retry_message, &agent_state.goal)
                        })
                        .or_else(|| {
                            final_reply_evidence_contract_reason(
                                &retry_message,
                                &final_reply_evidence_context_for_synthesis,
                                &agent_state.goal,
                            )
                        })
                {
                    log::warn!(
                        "Agent final reply repair still invalid session={} attempt={} reason={} chars={}",
                        session_prefix,
                        attempt,
                        retry_reason,
                        retry_message.len()
                    );
                    previous_answer = retry_message;
                    repair_reason = retry_reason;
                    continue;
                }
                message = retry_message;
                strategy_used = "FinalReplySynthesisRepaired";
                repaired = true;
                break;
            }
            if !repaired {
                log::error!(
                    "CRITICAL: Agent final reply repair remained invalid session={} reason={} attempts={}",
                    session_prefix,
                    repair_reason,
                    FINAL_REPLY_REPAIR_ATTEMPTS
                );
                return Ok(CognitionResult {
                    raw_output: json!({
                        "name": "agent__escalate",
                        "arguments": {
                            "reason": format!(
                                "ERROR_CLASS=UserInterventionNeeded Final reply synthesis remained incomplete after repair ({repair_reason}). Verify provider output limits and resume."
                            )
                        }
                    })
                    .to_string(),
                    strategy_used: "FinalReplySynthesisRepairIncomplete".to_string(),
                });
            }
        }
        return Ok(CognitionResult {
            raw_output: json!({
                "name": "chat__reply",
                "arguments": {
                    "message": message
                }
            })
            .to_string(),
            strategy_used: strategy_used.to_string(),
        });
    }

    if raw_output.trim().is_empty() {
        log::error!(
            "CRITICAL: Agent Inference Returned Empty Output session={}",
            session_prefix
        );
        return Ok(CognitionResult {
            raw_output: json!({
                "name": "agent__escalate",
                "arguments": {
                    "reason": "ERROR_CLASS=UserInterventionNeeded Cognition inference returned empty output. Verify provider health and credentials, then resume."
                }
            })
            .to_string(),
            strategy_used: "InferenceEmptyOutput".to_string(),
        });
    }

    Ok(CognitionResult {
        raw_output,
        strategy_used: format!("{:?}", perception.tier),
    })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
