use crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution;
use crate::agentic::runtime::types::{
    AgentState, PlanStep, PlannerDiscoveryRequirement, PlannerState, PlannerStatus,
    PlannerStepKind, PlannerStepStatus, PLANNER_SCHEMA_VERSION_V1,
};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, ResolvedIntentState};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use ioi_types::error::TransactionError;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

const MAX_PLAN_STEPS: usize = 256;
const MAX_TOTAL_TOOL_ACTIONS: usize = 512;
const MAX_SAME_TOOL_REPEATS: usize = 24;
const MAX_REPLAN_COUNT: u32 = 64;
const QUEUE_TOOL_NAME_KEY: &str = "__ioi_tool_name";

pub(crate) const PLANNER_FALLBACK_REASON_PLANNING_DISABLED: &str = "planning_disabled";
pub(crate) const PLANNER_FALLBACK_REASON_VALIDATION_FAILED: &str = "planner_validation_failed";
pub(crate) const PLANNER_FALLBACK_REASON_NO_DISPATCHABLE_STEP: &str =
    "planner_no_dispatchable_step";
pub(crate) const PLANNER_FALLBACK_REASON_DISCOVERY_REQUIREMENTS_UNSATISFIED: &str =
    "planner_discovery_requirements_unsatisfied";
pub(crate) const PLANNER_FALLBACK_REASON_DISPATCH_FAILED: &str = "planner_dispatch_failed";
pub(crate) const PLANNER_FALLBACK_REASON_EXECUTOR_MISMATCH: &str = "executor_dispatch_mismatch";

fn should_embed_queue_tool_name_metadata(target: &ActionTarget, tool_name: &str) -> bool {
    matches!(target, ActionTarget::FsRead | ActionTarget::FsWrite)
        || (matches!(target, ActionTarget::GuiClick | ActionTarget::UiClick)
            && tool_name == "screen__click")
        || matches!(target, ActionTarget::BrowserInteract)
        || (matches!(target, ActionTarget::SysExec)
            && matches!(tool_name, "shell__start" | "shell__reset"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlannerDispatchMatch {
    Matched {
        step_index: usize,
        step_id: String,
    },
    Mismatch {
        step_index: usize,
        step_id: String,
        expected_tool_name: String,
    },
}

fn canonicalize_json(input: &str) -> Result<String, TransactionError> {
    let parsed: serde_json::Value = serde_json::from_str(input).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=PlannerValidationFailed Invalid step arguments JSON: {}",
            e
        ))
    })?;
    let canonical =
        serde_jcs::to_vec(&parsed).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    String::from_utf8(canonical).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=PlannerValidationFailed Canonical JSON is not valid UTF-8: {}",
            e
        ))
    })
}

fn normalize_string_list(values: &mut Vec<String>) {
    let mut unique = BTreeSet::new();
    let mut out = Vec::new();
    for value in values.iter() {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if unique.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    out.sort();
    *values = out;
}

fn normalize_plan_step(step: &mut PlanStep) -> Result<(), TransactionError> {
    step.step_id = step.step_id.trim().to_string();
    step.tool_name = step
        .tool_name
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    step.arguments_json = step
        .arguments_json
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(args) = step.arguments_json.as_ref() {
        step.arguments_json = Some(canonicalize_json(args)?);
    }
    normalize_string_list(&mut step.depends_on);
    normalize_string_list(&mut step.receipts);
    Ok(())
}

fn normalize_discovery_requirements(values: &mut Vec<PlannerDiscoveryRequirement>) {
    let mut unique = BTreeSet::new();
    for value in values.iter().copied() {
        unique.insert(value);
    }
    *values = unique.into_iter().collect();
}

pub(crate) fn normalize_planner_state(planner: &mut PlannerState) -> Result<(), TransactionError> {
    planner.plan_id = planner.plan_id.trim().to_string();
    planner.plan_schema_version = planner.plan_schema_version.trim().to_string();
    if planner.plan_schema_version.is_empty() {
        planner.plan_schema_version = PLANNER_SCHEMA_VERSION_V1.to_string();
    }
    planner.last_replan_reason = planner
        .last_replan_reason
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    normalize_discovery_requirements(&mut planner.discovery_requirements);
    normalize_string_list(&mut planner.last_batch);
    for step in planner.steps.iter_mut() {
        normalize_plan_step(step)?;
    }
    if planner.cursor as usize > planner.steps.len() {
        planner.cursor = planner.steps.len() as u32;
    }
    Ok(())
}

pub(crate) fn validate_planner_state(
    planner: &PlannerState,
    resolved_intent: Option<&ResolvedIntentState>,
) -> Result<(), TransactionError> {
    if planner.plan_schema_version != PLANNER_SCHEMA_VERSION_V1 {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=PlannerValidationFailed Unsupported plan schema version '{}'",
            planner.plan_schema_version
        )));
    }
    if planner.plan_id.trim().is_empty() {
        return Err(TransactionError::Invalid(
            "ERROR_CLASS=PlannerValidationFailed Planner plan_id is required".to_string(),
        ));
    }
    if planner.steps.is_empty() {
        return Err(TransactionError::Invalid(
            "ERROR_CLASS=PlannerValidationFailed Planner must contain at least one step"
                .to_string(),
        ));
    }
    if planner.steps.len() > MAX_PLAN_STEPS {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=PlannerValidationFailed Planner exceeds max steps ({})",
            MAX_PLAN_STEPS
        )));
    }
    if planner.replan_count > MAX_REPLAN_COUNT {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=PlannerValidationFailed replan_count exceeds max ({})",
            MAX_REPLAN_COUNT
        )));
    }

    let mut step_ids = BTreeSet::new();
    let mut tool_step_count = 0usize;
    let mut tool_frequency = BTreeMap::<String, usize>::new();
    let mut requires_tool_gate = false;
    for step in &planner.steps {
        if step.step_id.trim().is_empty() {
            return Err(TransactionError::Invalid(
                "ERROR_CLASS=PlannerValidationFailed plan step_id is required".to_string(),
            ));
        }
        if !step_ids.insert(step.step_id.clone()) {
            return Err(TransactionError::Invalid(format!(
                "ERROR_CLASS=PlannerValidationFailed Duplicate plan step_id '{}'",
                step.step_id
            )));
        }
    }

    for step in &planner.steps {
        for dependency in &step.depends_on {
            if dependency == &step.step_id {
                return Err(TransactionError::Invalid(format!(
                    "ERROR_CLASS=PlannerValidationFailed Step '{}' depends on itself",
                    step.step_id
                )));
            }
            if !step_ids.contains(dependency) {
                return Err(TransactionError::Invalid(format!(
                    "ERROR_CLASS=PlannerValidationFailed Step '{}' references unknown dependency '{}'",
                    step.step_id, dependency
                )));
            }
        }

        if matches!(step.kind, PlannerStepKind::ToolCallIntent) {
            let tool_name = step.tool_name.as_ref().ok_or_else(|| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=PlannerValidationFailed Tool step '{}' missing tool_name",
                    step.step_id
                ))
            })?;
            requires_tool_gate = true;
            tool_step_count = tool_step_count.saturating_add(1);
            let frequency = tool_frequency.entry(tool_name.clone()).or_insert(0);
            *frequency = frequency.saturating_add(1);
            if *frequency > MAX_SAME_TOOL_REPEATS {
                return Err(TransactionError::Invalid(format!(
                    "ERROR_CLASS=PlannerValidationFailed Tool '{}' exceeds repeat ceiling ({})",
                    tool_name, MAX_SAME_TOOL_REPEATS
                )));
            }
        } else if step.tool_name.is_some() {
            return Err(TransactionError::Invalid(format!(
                "ERROR_CLASS=PlannerValidationFailed Non-tool step '{}' must not define tool_name",
                step.step_id
            )));
        }
    }

    if tool_step_count > MAX_TOTAL_TOOL_ACTIONS {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=PlannerValidationFailed Planner exceeds max tool actions ({})",
            MAX_TOTAL_TOOL_ACTIONS
        )));
    }

    if requires_tool_gate && resolved_intent.is_none() {
        return Err(TransactionError::Invalid(
            "ERROR_CLASS=PlannerValidationFailed Resolved intent required for tool gating"
                .to_string(),
        ));
    }
    if let Some(resolved) = resolved_intent {
        for step in &planner.steps {
            if !matches!(step.kind, PlannerStepKind::ToolCallIntent) {
                continue;
            }
            if let Some(tool_name) = step.tool_name.as_deref() {
                if !is_tool_allowed_for_resolution(Some(resolved), tool_name) {
                    return Err(TransactionError::Invalid(format!(
                        "ERROR_CLASS=PolicyBlocked Planner step '{}' proposes disallowed tool '{}'",
                        step.step_id, tool_name
                    )));
                }
            }
        }
    }

    for step_id in &planner.last_batch {
        if !step_ids.contains(step_id) {
            return Err(TransactionError::Invalid(format!(
                "ERROR_CLASS=PlannerValidationFailed last_batch references unknown step '{}'",
                step_id
            )));
        }
    }

    Ok(())
}

fn plan_hash_payload(planner: &PlannerState) -> serde_json::Value {
    json!({
        "plan_id": planner.plan_id,
        "plan_schema_version": planner.plan_schema_version,
        "goal_hash": planner.goal_hash,
        "intent_receipt_hash": planner.intent_receipt_hash,
        "discovery_requirements": planner.discovery_requirements,
        "steps": planner.steps,
        "cursor": planner.cursor,
        "replan_count": planner.replan_count,
        "status": planner.status,
        "last_replan_reason": planner.last_replan_reason,
        "last_batch": planner.last_batch,
    })
}

pub(crate) fn compute_plan_hash(planner: &PlannerState) -> Result<[u8; 32], TransactionError> {
    let mut normalized = planner.clone();
    normalize_planner_state(&mut normalized)?;
    let payload = plan_hash_payload(&normalized);
    let canonical =
        serde_jcs::to_vec(&payload).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = sha256(&canonical).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

pub(crate) fn validate_and_hash_planner_state(
    planner: &mut PlannerState,
    resolved_intent: Option<&ResolvedIntentState>,
) -> Result<(), TransactionError> {
    normalize_planner_state(planner)?;
    validate_planner_state(planner, resolved_intent)?;
    planner.plan_hash = compute_plan_hash(planner)?;
    Ok(())
}

fn canonicalize_value(value: &serde_json::Value) -> Result<String, TransactionError> {
    let canonical =
        serde_jcs::to_vec(value).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    String::from_utf8(canonical).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=PlannerValidationFailed Canonical JSON is not valid UTF-8: {}",
            e
        ))
    })
}

fn canonical_step_arguments(step: &PlanStep) -> Result<String, TransactionError> {
    if let Some(raw) = step.arguments_json.as_deref() {
        canonicalize_json(raw)
    } else {
        canonicalize_value(&json!({}))
    }
}

fn step_dependencies_satisfied(planner: &PlannerState, step: &PlanStep) -> bool {
    if step.depends_on.is_empty() {
        return true;
    }

    step.depends_on.iter().all(|dependency| {
        planner
            .steps
            .iter()
            .find(|candidate| candidate.step_id == *dependency)
            .map(|candidate| candidate.status == PlannerStepStatus::Succeeded)
            .unwrap_or(false)
    })
}

fn parse_step_arguments(step: &PlanStep) -> Result<serde_json::Value, TransactionError> {
    match step.arguments_json.as_deref() {
        Some(raw) => serde_json::from_str::<serde_json::Value>(raw).map_err(|e| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=PlannerValidationFailed Invalid step arguments JSON: {}",
                e
            ))
        }),
        None => Ok(json!({})),
    }
}

fn refresh_planner_status(planner: &mut PlannerState) {
    if planner.steps.iter().any(|step| {
        matches!(
            step.status,
            PlannerStepStatus::Blocked | PlannerStepStatus::TerminalFailed
        )
    }) {
        planner.status = PlannerStatus::Blocked;
        return;
    }

    if planner
        .steps
        .iter()
        .any(|step| step.status == PlannerStepStatus::Dispatched)
    {
        planner.status = PlannerStatus::Running;
        return;
    }

    let all_terminal_or_succeeded = planner.steps.iter().all(|step| {
        matches!(
            step.status,
            PlannerStepStatus::Succeeded
                | PlannerStepStatus::Blocked
                | PlannerStepStatus::TerminalFailed
        )
    });

    if all_terminal_or_succeeded
        || planner
            .steps
            .iter()
            .all(|step| step.status == PlannerStepStatus::Succeeded)
    {
        planner.status = PlannerStatus::Completed;
        return;
    }

    planner.status = PlannerStatus::Ready;
}

fn append_step_receipt(step: &mut PlanStep, receipt: String) {
    let trimmed = receipt.trim();
    if trimmed.is_empty() {
        return;
    }
    if !step.receipts.iter().any(|existing| existing == trimmed) {
        step.receipts.push(trimmed.to_string());
    }
}

pub(crate) fn planner_runtime_disabled() -> bool {
    std::env::var("IOI_PLANNING_DISABLED")
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

pub(crate) fn planner_runtime_disabled_for_policy(planning_enabled: bool) -> bool {
    !planning_enabled || planner_runtime_disabled()
}

fn discovery_requirement_label(requirement: PlannerDiscoveryRequirement) -> &'static str {
    match requirement {
        PlannerDiscoveryRequirement::ResolvedIntent => "resolved_intent",
        PlannerDiscoveryRequirement::InteractionTarget => "interaction_target",
        PlannerDiscoveryRequirement::VisualContext => "visual_context",
        PlannerDiscoveryRequirement::PendingSearchContext => "pending_search_context",
        PlannerDiscoveryRequirement::ActiveLens => "active_lens",
    }
}

fn is_discovery_requirement_satisfied(
    requirement: PlannerDiscoveryRequirement,
    agent_state: &AgentState,
) -> bool {
    match requirement {
        PlannerDiscoveryRequirement::ResolvedIntent => agent_state.resolved_intent.is_some(),
        PlannerDiscoveryRequirement::InteractionTarget => agent_state.target.is_some(),
        PlannerDiscoveryRequirement::VisualContext => {
            agent_state
                .last_screen_phash
                .map(|hash| hash != [0u8; 32])
                .unwrap_or(false)
                || agent_state
                    .visual_som_map
                    .as_ref()
                    .map(|map| !map.is_empty())
                    .unwrap_or(false)
        }
        PlannerDiscoveryRequirement::PendingSearchContext => {
            agent_state.pending_search_completion.is_some()
        }
        PlannerDiscoveryRequirement::ActiveLens => agent_state.active_lens.is_some(),
    }
}

pub(crate) fn planner_unmet_discovery_requirements(
    planner: &PlannerState,
    agent_state: &AgentState,
) -> Vec<String> {
    planner
        .discovery_requirements
        .iter()
        .copied()
        .filter(|requirement| !is_discovery_requirement_satisfied(*requirement, agent_state))
        .map(discovery_requirement_label)
        .map(str::to_string)
        .collect()
}

pub(crate) fn planner_has_open_work(planner: &PlannerState) -> bool {
    planner.steps.iter().any(|step| {
        matches!(
            step.status,
            PlannerStepStatus::Pending
                | PlannerStepStatus::Dispatched
                | PlannerStepStatus::RetryableFailed
        )
    })
}

pub(crate) fn mark_planner_fallback(
    planner: &mut PlannerState,
    reason: &str,
    resolved_intent: Option<&ResolvedIntentState>,
) -> bool {
    let normalized = reason.trim();
    if normalized.is_empty() {
        return false;
    }
    let changed = planner.last_replan_reason.as_deref() != Some(normalized);
    planner.last_replan_reason = Some(normalized.to_string());
    if changed {
        planner.replan_count = planner.replan_count.saturating_add(1);
    }
    planner.status = PlannerStatus::Blocked;
    if let Ok(hash) = compute_plan_hash(planner) {
        planner.plan_hash = hash;
    }
    let _ = validate_planner_state(planner, resolved_intent);
    changed
}

fn next_dispatchable_index(planner: &PlannerState) -> Option<usize> {
    if planner.steps.is_empty() {
        return None;
    }

    let cursor = (planner.cursor as usize).min(planner.steps.len());
    let mut candidates: Vec<usize> = (cursor..planner.steps.len()).collect();
    candidates.extend(0..cursor);

    candidates.into_iter().find(|idx| {
        let step = &planner.steps[*idx];
        step.status == PlannerStepStatus::Pending
            && matches!(step.kind, PlannerStepKind::ToolCallIntent)
            && step_dependencies_satisfied(planner, step)
    })
}

pub(crate) fn dispatch_next_planner_action(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    nonce: u64,
    resolved_intent: Option<&ResolvedIntentState>,
) -> Result<Option<String>, TransactionError> {
    let Some(planner) = agent_state.planner_state.as_mut() else {
        return Ok(None);
    };

    validate_and_hash_planner_state(planner, resolved_intent)?;
    let Some(step_index) = next_dispatchable_index(planner) else {
        return Ok(None);
    };

    let step = planner.steps.get(step_index).cloned().ok_or_else(|| {
        TransactionError::Invalid(
            "ERROR_CLASS=PlannerValidationFailed Dispatch index out of bounds".to_string(),
        )
    })?;
    let tool_name = step.tool_name.as_ref().ok_or_else(|| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=PlannerValidationFailed Tool step '{}' missing tool_name",
            step.step_id
        ))
    })?;
    let args_value = parse_step_arguments(&step)?;
    let tool = AgentTool::Dynamic(json!({
        "name": tool_name,
        "arguments": args_value,
    }));
    let target = tool.target();
    let mut queued_args = args_value.clone();
    if should_embed_queue_tool_name_metadata(&target, tool_name) {
        if let Some(obj) = queued_args.as_object_mut() {
            obj.insert(QUEUE_TOOL_NAME_KEY.to_string(), json!(tool_name));
        }
    }

    let params = serde_jcs::to_vec(&queued_args)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce,
    };
    let request_hash = hex::encode(request.hash());

    if let Some(step_mut) = planner.steps.get_mut(step_index) {
        step_mut.status = PlannerStepStatus::Dispatched;
        append_step_receipt(step_mut, format!("dispatch_nonce={}", nonce));
        append_step_receipt(step_mut, format!("dispatch_request_hash={}", request_hash));
    }
    planner.cursor = (step_index.saturating_add(1)) as u32;
    planner.last_batch = vec![step.step_id.clone()];
    planner.status = PlannerStatus::Running;
    validate_and_hash_planner_state(planner, resolved_intent)?;
    agent_state.execution_queue.push(request);
    Ok(Some(step.step_id))
}

fn active_dispatched_step_index(planner: &PlannerState) -> Option<usize> {
    for step_id in &planner.last_batch {
        if let Some((idx, step)) = planner
            .steps
            .iter()
            .enumerate()
            .find(|(_, step)| step.step_id == *step_id)
        {
            if step.status == PlannerStepStatus::Dispatched {
                return Some(idx);
            }
        }
    }

    planner
        .steps
        .iter()
        .enumerate()
        .find(|(_, step)| step.status == PlannerStepStatus::Dispatched)
        .map(|(idx, _)| idx)
}

pub(crate) fn match_dispatched_step_for_execution(
    planner: &PlannerState,
    tool_name: &str,
    tool_args: &serde_json::Value,
) -> Result<Option<PlannerDispatchMatch>, TransactionError> {
    let Some(step_index) = active_dispatched_step_index(planner) else {
        return Ok(None);
    };
    let Some(step) = planner.steps.get(step_index) else {
        return Ok(None);
    };
    let expected_tool_name = step.tool_name.clone().unwrap_or_default();
    let expected_args = canonical_step_arguments(step)?;
    let observed_args = canonicalize_value(tool_args)?;

    if expected_tool_name == tool_name && expected_args == observed_args {
        return Ok(Some(PlannerDispatchMatch::Matched {
            step_index,
            step_id: step.step_id.clone(),
        }));
    }

    Ok(Some(PlannerDispatchMatch::Mismatch {
        step_index,
        step_id: step.step_id.clone(),
        expected_tool_name,
    }))
}

pub(crate) fn record_planner_step_outcome(
    planner: &mut PlannerState,
    step_index: usize,
    success: bool,
    blocked: bool,
    terminal_failure: bool,
    error: Option<&str>,
    request_hash: Option<&str>,
    resolved_intent: Option<&ResolvedIntentState>,
) -> Result<(), TransactionError> {
    let step = planner.steps.get_mut(step_index).ok_or_else(|| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=PlannerValidationFailed Planner step index {} missing",
            step_index
        ))
    })?;

    step.status = if blocked {
        PlannerStepStatus::Blocked
    } else if success {
        PlannerStepStatus::Succeeded
    } else if terminal_failure {
        PlannerStepStatus::TerminalFailed
    } else {
        PlannerStepStatus::RetryableFailed
    };

    if let Some(hash) = request_hash {
        append_step_receipt(step, format!("execution_request_hash={}", hash));
    }
    append_step_receipt(step, format!("execution_status={:?}", step.status));
    if let Some(err) = error {
        let trimmed = err.trim();
        if !trimmed.is_empty() {
            append_step_receipt(step, format!("execution_error={}", trimmed));
        }
    }

    planner.cursor = planner
        .steps
        .iter()
        .position(|candidate| candidate.status == PlannerStepStatus::Pending)
        .unwrap_or(planner.steps.len()) as u32;
    refresh_planner_status(planner);
    validate_and_hash_planner_state(planner, resolved_intent)?;
    Ok(())
}

#[cfg(test)]
#[path = "planner/tests.rs"]
mod tests;
