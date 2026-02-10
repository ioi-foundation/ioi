// Path: crates/services/src/agentic/desktop/service/step/anti_loop.rs

use crate::agentic::desktop::keys::get_mutation_receipt_ptr_key;
use crate::agentic::desktop::types::{AgentState, AgentStatus, ExecutionTier};
use hex;
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{
    KernelEvent, RoutingFailureClass, RoutingPostStateSummary, RoutingReceiptEvent,
    RoutingStateSummary,
};
use serde::Serialize;
use serde_jcs;
use tokio::sync::broadcast::Sender;

pub const RETRY_GUARD_WINDOW: usize = 6;
pub const RETRY_GUARD_REPEAT_LIMIT: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FailureClass {
    FocusMismatch,
    TargetNotFound,
    VisionTargetNotFound,
    NoEffectAfterAction,
    TierViolation,
    MissingDependency,
    ContextDrift,
    PermissionOrApprovalRequired,
    ToolUnavailable,
    NonDeterministicUI,
    UnexpectedState,
    TimeoutOrHang,
    UserInterventionNeeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierRoutingDecision {
    pub tier: ExecutionTier,
    pub reason_code: &'static str,
    pub source_failure: Option<FailureClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttemptKey {
    pub intent_hash: String,
    pub tier: String,
    pub tool_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_fingerprint: Option<String>,
}

fn status_as_str(status: &AgentStatus) -> String {
    format!("{:?}", status)
        .split('(')
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

pub fn tier_as_str(tier: ExecutionTier) -> &'static str {
    match tier {
        ExecutionTier::DomHeadless => "ToolFirst",
        ExecutionTier::VisualBackground => "AxFirst",
        ExecutionTier::VisualForeground => "VisualLast",
    }
}

fn normalize_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

pub fn build_attempt_key(
    intent_hash: &str,
    tier: ExecutionTier,
    tool_name: &str,
    target_id: Option<&str>,
    window_fingerprint: Option<&str>,
) -> AttemptKey {
    AttemptKey {
        intent_hash: intent_hash.to_string(),
        tier: tier_as_str(tier).to_string(),
        tool_name: tool_name.to_string(),
        target_id: normalize_optional(target_id),
        window_fingerprint: normalize_optional(window_fingerprint),
    }
}

pub fn attempt_key_hash(attempt_key: &AttemptKey) -> String {
    let canonical_bytes = serde_jcs::to_vec(attempt_key).unwrap_or_else(|_| {
        format!(
            "{}::{}::{}::{}::{}",
            attempt_key.intent_hash,
            attempt_key.tier,
            attempt_key.tool_name,
            attempt_key.target_id.as_deref().unwrap_or(""),
            attempt_key.window_fingerprint.as_deref().unwrap_or("")
        )
        .into_bytes()
    });
    sha256(&canonical_bytes)
        .map(hex::encode)
        .unwrap_or_else(|_| String::new())
}

pub fn failure_attempt_fingerprint(failure_class: FailureClass, attempt_key_hash: &str) -> String {
    format!("attempt::{}::{}", failure_class.as_str(), attempt_key_hash)
}

pub fn register_failure_attempt(
    agent_state: &mut AgentState,
    failure_class: FailureClass,
    attempt_key: &AttemptKey,
) -> (usize, String) {
    let attempt_hash = attempt_key_hash(attempt_key);
    let fingerprint = failure_attempt_fingerprint(failure_class, &attempt_hash);
    let repeat_count = register_attempt(agent_state, fingerprint);
    (repeat_count, attempt_hash)
}

impl FailureClass {
    pub fn as_str(self) -> &'static str {
        match self {
            FailureClass::FocusMismatch => "FocusMismatch",
            FailureClass::TargetNotFound => "TargetNotFound",
            FailureClass::VisionTargetNotFound => "VisionTargetNotFound",
            FailureClass::NoEffectAfterAction => "NoEffectAfterAction",
            FailureClass::TierViolation => "TierViolation",
            FailureClass::MissingDependency => "MissingDependency",
            FailureClass::ContextDrift => "ContextDrift",
            FailureClass::PermissionOrApprovalRequired => "PermissionOrApprovalRequired",
            FailureClass::ToolUnavailable => "ToolUnavailable",
            FailureClass::NonDeterministicUI => "NonDeterministicUI",
            FailureClass::UnexpectedState => "UnexpectedState",
            FailureClass::TimeoutOrHang => "TimeoutOrHang",
            FailureClass::UserInterventionNeeded => "UserInterventionNeeded",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "FocusMismatch" => Some(FailureClass::FocusMismatch),
            "TargetNotFound" => Some(FailureClass::TargetNotFound),
            "VisionTargetNotFound" => Some(FailureClass::VisionTargetNotFound),
            "NoEffectAfterAction" => Some(FailureClass::NoEffectAfterAction),
            "TierViolation" => Some(FailureClass::TierViolation),
            "MissingDependency" => Some(FailureClass::MissingDependency),
            "ContextDrift" => Some(FailureClass::ContextDrift),
            "PermissionOrApprovalRequired" => Some(FailureClass::PermissionOrApprovalRequired),
            "ToolUnavailable" => Some(FailureClass::ToolUnavailable),
            "NonDeterministicUI" => Some(FailureClass::NonDeterministicUI),
            "UnexpectedState" => Some(FailureClass::UnexpectedState),
            "TimeoutOrHang" => Some(FailureClass::TimeoutOrHang),
            "UserInterventionNeeded" => Some(FailureClass::UserInterventionNeeded),
            _ => None,
        }
    }
}

pub fn classify_failure(error: Option<&str>, policy_decision: &str) -> Option<FailureClass> {
    if policy_decision == "require_approval" || policy_decision == "denied" {
        return Some(FailureClass::PermissionOrApprovalRequired);
    }

    let msg = error?.to_lowercase();

    if msg.contains("error_class=focusmismatch") {
        return Some(FailureClass::FocusMismatch);
    }
    if msg.contains("error_class=visiontargetnotfound") {
        return Some(FailureClass::VisionTargetNotFound);
    }
    if msg.contains("error_class=noeffectafteraction") {
        return Some(FailureClass::NoEffectAfterAction);
    }
    if msg.contains("error_class=tierviolation") {
        return Some(FailureClass::TierViolation);
    }
    if msg.contains("error_class=missingdependency") {
        return Some(FailureClass::MissingDependency);
    }
    if msg.contains("error_class=contextdrift") {
        return Some(FailureClass::ContextDrift);
    }
    if msg.contains("error_class=humanchallengerequired") {
        return Some(FailureClass::UserInterventionNeeded);
    }
    if msg.contains("error_class=targetnotfound") {
        return Some(FailureClass::TargetNotFound);
    }
    if msg.contains("error_class=permissionorapprovalrequired") {
        return Some(FailureClass::PermissionOrApprovalRequired);
    }

    if msg.contains("raw coordinate click is disabled outside visuallast")
        || msg.contains("vision localization is only allowed")
        || msg.contains("tier violation")
    {
        return Some(FailureClass::TierViolation);
    }

    if msg.contains("failed to execute wmctrl")
        || msg.contains("missing focus dependency")
        || msg.contains("missingdependency")
    {
        return Some(FailureClass::MissingDependency);
    }

    if msg.contains("visual context drifted") || msg.contains("context drift") {
        return Some(FailureClass::ContextDrift);
    }

    if msg.contains("ui state static after click")
        || msg.contains("ui state unchanged after click")
        || msg.contains("no effect after action")
    {
        return Some(FailureClass::NoEffectAfterAction);
    }

    if msg.contains("vision")
        && msg.contains("localization")
        && (msg.contains("not found")
            || msg.contains("confidence too low")
            || msg.contains("outside active window"))
    {
        return Some(FailureClass::VisionTargetNotFound);
    }

    // Prefer explicit target lookup failures before broad focus heuristics.
    if (msg.contains("target") || msg.contains("element") || msg.contains("ui tree"))
        && msg.contains("not found")
    {
        return Some(FailureClass::TargetNotFound);
    }

    if msg.contains("focus")
        || msg.contains("foreground")
        || msg.contains("context drift")
        || msg.contains("active window")
    {
        return Some(FailureClass::FocusMismatch);
    }

    if msg.contains("not found")
        || msg.contains("no window matched")
        || msg.contains("lookup failed")
        || msg.contains("unable to find")
    {
        return Some(FailureClass::TargetNotFound);
    }

    if msg.contains("approval")
        || msg.contains("blocked by policy")
        || msg.contains("firewall")
        || msg.contains("authorization")
    {
        return Some(FailureClass::PermissionOrApprovalRequired);
    }

    if msg.contains("missing capability")
        || msg.contains("tool is missing")
        || msg.contains("tool unavailable")
        || msg.contains("not handled by executor")
        || msg.contains("unsupported")
        || msg.contains("os driver missing")
    {
        return Some(FailureClass::ToolUnavailable);
    }

    if msg.contains("visual context drift")
        || msg.contains("screen has not changed")
        || msg.contains("non-deterministic")
        || msg.contains("stale screenshot")
    {
        return Some(FailureClass::NonDeterministicUI);
    }

    if msg.contains("timeout")
        || msg.contains("timed out")
        || msg.contains("deadline")
        || msg.contains("hang")
    {
        return Some(FailureClass::TimeoutOrHang);
    }

    if msg.contains("user input")
        || msg.contains("manual")
        || msg.contains("intervention")
        || msg.contains("waiting for user")
        || msg.contains("captcha")
        || msg.contains("recaptcha")
        || msg.contains("unusual traffic")
        || msg.contains("verify you are human")
        || msg.contains("/sorry/")
    {
        return Some(FailureClass::UserInterventionNeeded);
    }

    Some(FailureClass::UnexpectedState)
}

pub fn to_routing_failure_class(class: FailureClass) -> RoutingFailureClass {
    match class {
        FailureClass::FocusMismatch => RoutingFailureClass::FocusMismatch,
        FailureClass::TargetNotFound => RoutingFailureClass::TargetNotFound,
        FailureClass::VisionTargetNotFound => RoutingFailureClass::VisionTargetNotFound,
        FailureClass::NoEffectAfterAction => RoutingFailureClass::NoEffectAfterAction,
        FailureClass::TierViolation => RoutingFailureClass::TierViolation,
        FailureClass::MissingDependency => RoutingFailureClass::MissingDependency,
        FailureClass::ContextDrift => RoutingFailureClass::ContextDrift,
        FailureClass::PermissionOrApprovalRequired => {
            RoutingFailureClass::PermissionOrApprovalRequired
        }
        FailureClass::ToolUnavailable => RoutingFailureClass::ToolUnavailable,
        FailureClass::NonDeterministicUI => RoutingFailureClass::NonDeterministicUI,
        FailureClass::UnexpectedState => RoutingFailureClass::UnexpectedState,
        FailureClass::TimeoutOrHang => RoutingFailureClass::TimeoutOrHang,
        FailureClass::UserInterventionNeeded => RoutingFailureClass::UserInterventionNeeded,
    }
}

fn parse_failure_from_fingerprint(fingerprint: &str) -> Option<FailureClass> {
    let mut parts = fingerprint.split("::");
    let _scope = parts.next()?;
    let class = parts.next()?;
    FailureClass::from_str(class)
}

pub fn latest_failure_class(agent_state: &AgentState) -> Option<FailureClass> {
    agent_state
        .recent_actions
        .last()
        .and_then(|entry| parse_failure_from_fingerprint(entry))
}

pub fn choose_routing_tier(agent_state: &AgentState) -> TierRoutingDecision {
    let failures = agent_state.consecutive_failures as usize;
    let source_failure = latest_failure_class(agent_state);

    if failures == 0 {
        return TierRoutingDecision {
            tier: ExecutionTier::DomHeadless,
            reason_code: "tool_first_default",
            source_failure,
        };
    }

    if let Some(class) = source_failure {
        let (tier, reason_code) = match class {
            FailureClass::PermissionOrApprovalRequired | FailureClass::UserInterventionNeeded => (
                ExecutionTier::DomHeadless,
                "tool_first_waiting_for_policy_or_user",
            ),
            FailureClass::FocusMismatch => (ExecutionTier::VisualForeground, "visual_last_focus"),
            FailureClass::TargetNotFound => (
                ExecutionTier::VisualForeground,
                "visual_last_target_refresh",
            ),
            FailureClass::VisionTargetNotFound => (
                ExecutionTier::VisualForeground,
                "visual_last_vision_target_missing",
            ),
            FailureClass::NoEffectAfterAction => (
                ExecutionTier::VisualForeground,
                "visual_last_no_effect_recovery",
            ),
            FailureClass::TierViolation => (
                ExecutionTier::VisualForeground,
                "visual_last_tier_violation",
            ),
            FailureClass::MissingDependency => (
                ExecutionTier::VisualForeground,
                "visual_last_missing_dependency",
            ),
            FailureClass::ContextDrift => {
                (ExecutionTier::VisualForeground, "visual_last_context_drift")
            }
            FailureClass::NonDeterministicUI => {
                (ExecutionTier::VisualForeground, "visual_last_verify_state")
            }
            FailureClass::ToolUnavailable => {
                if failures >= 2 {
                    (ExecutionTier::VisualForeground, "visual_last_tool_gap")
                } else {
                    (ExecutionTier::VisualBackground, "ax_first_tool_gap")
                }
            }
            FailureClass::TimeoutOrHang | FailureClass::UnexpectedState => {
                if failures >= 3 {
                    (
                        ExecutionTier::VisualForeground,
                        "visual_last_repeated_runtime_failure",
                    )
                } else {
                    (ExecutionTier::VisualBackground, "ax_first_runtime_recovery")
                }
            }
        };

        return TierRoutingDecision {
            tier,
            reason_code,
            source_failure: Some(class),
        };
    }

    let (tier, reason_code) = if failures >= 3 {
        (
            ExecutionTier::VisualForeground,
            "visual_last_retry_budget_high",
        )
    } else {
        (
            ExecutionTier::VisualBackground,
            "ax_first_failure_observability",
        )
    };

    TierRoutingDecision {
        tier,
        reason_code,
        source_failure: None,
    }
}

pub fn build_state_summary(agent_state: &AgentState) -> RoutingStateSummary {
    RoutingStateSummary {
        agent_status: status_as_str(&agent_state.status),
        tier: tier_as_str(agent_state.current_tier).to_string(),
        step_index: agent_state.step_count,
        consecutive_failures: agent_state.consecutive_failures,
        target_hint: agent_state.target.as_ref().and_then(|t| t.app_hint.clone()),
    }
}

pub fn build_post_state_summary(
    agent_state: &AgentState,
    success: bool,
    verification_checks: Vec<String>,
) -> RoutingPostStateSummary {
    RoutingPostStateSummary {
        agent_status: status_as_str(&agent_state.status),
        tier: tier_as_str(agent_state.current_tier).to_string(),
        step_index: agent_state.step_count,
        consecutive_failures: agent_state.consecutive_failures,
        success,
        verification_checks,
    }
}

pub fn trailing_repetition_count(history: &[String], fingerprint: &str) -> usize {
    history
        .iter()
        .rev()
        .take_while(|entry| entry.as_str() == fingerprint)
        .count()
}

pub fn register_attempt(agent_state: &mut AgentState, fingerprint: String) -> usize {
    agent_state.recent_actions.push(fingerprint.clone());
    if agent_state.recent_actions.len() > RETRY_GUARD_WINDOW {
        let overflow = agent_state.recent_actions.len() - RETRY_GUARD_WINDOW;
        agent_state.recent_actions.drain(0..overflow);
    }
    trailing_repetition_count(&agent_state.recent_actions, &fingerprint)
}

pub fn should_trip_retry_guard(failure_class: FailureClass, repeat_count: usize) -> bool {
    if repeat_count < RETRY_GUARD_REPEAT_LIMIT {
        return false;
    }

    !matches!(
        failure_class,
        FailureClass::PermissionOrApprovalRequired | FailureClass::UserInterventionNeeded
    )
}

pub fn should_block_retry_without_change(failure_class: FailureClass, repeat_count: usize) -> bool {
    if repeat_count <= 1 {
        return false;
    }

    !matches!(
        failure_class,
        FailureClass::PermissionOrApprovalRequired | FailureClass::UserInterventionNeeded
    )
}

pub fn retry_budget_remaining(repeat_count: usize) -> usize {
    RETRY_GUARD_REPEAT_LIMIT.saturating_sub(repeat_count)
}

pub fn escalation_path_for_failure(failure_class: FailureClass) -> &'static str {
    match failure_class {
        FailureClass::FocusMismatch => {
            "Escalate to focused-window recovery via os__focus_window before retry."
        }
        FailureClass::TargetNotFound => {
            "Escalate to VisualForeground and refresh SoM/AX targeting."
        }
        FailureClass::VisionTargetNotFound => {
            "Visual grounding failed; request user guidance or a clearer target."
        }
        FailureClass::NoEffectAfterAction => {
            "Action had no observable effect; resnapshot and try an alternate interaction path."
        }
        FailureClass::TierViolation => {
            "Switch to VisualForeground tier before attempting visual/coordinate execution."
        }
        FailureClass::MissingDependency => {
            "Install missing platform dependency or continue with visual-only recovery paths."
        }
        FailureClass::ContextDrift => {
            "Context drift detected; refresh perception and retry with fresh grounding."
        }
        FailureClass::PermissionOrApprovalRequired => {
            "Wait for approval token or explicit user authorization."
        }
        FailureClass::ToolUnavailable => {
            "Request capability escalation or switch modality to an available tool."
        }
        FailureClass::NonDeterministicUI => {
            "Escalate to VisualForeground with post-action verification checks."
        }
        FailureClass::UnexpectedState => {
            "Request user clarification or refresh state with deterministic read tools."
        }
        FailureClass::TimeoutOrHang => {
            "Abort current attempt and retry after environment recovers."
        }
        FailureClass::UserInterventionNeeded => "Pause execution and wait for user intervention.",
    }
}

pub fn lineage_pointer(active_skill_hash: Option<[u8; 32]>) -> Option<String> {
    active_skill_hash.map(|hash| format!("scs://skill/{}", hex::encode(hash)))
}

pub fn policy_binding_hash(intent_hash: &str, policy_decision: &str) -> String {
    // Domain-separated canonical payload for routing policy attestation.
    let payload = format!(
        "ioi::routing-policy-binding::v1::{}::{}",
        intent_hash, policy_decision
    );
    sha256(payload.as_bytes())
        .map(hex::encode)
        .unwrap_or_else(|_| String::new())
}

pub fn mutation_receipt_pointer(state: &dyn StateAccess, session_id: &[u8; 32]) -> Option<String> {
    let key = get_mutation_receipt_ptr_key(session_id);
    let bytes = state.get(&key).ok()??;
    String::from_utf8(bytes).ok().filter(|v| !v.is_empty())
}

pub fn emit_routing_receipt(
    event_sender: Option<&Sender<KernelEvent>>,
    receipt: RoutingReceiptEvent,
) {
    if let Some(tx) = event_sender {
        let _ = tx.send(KernelEvent::RoutingReceipt(receipt));
    }
}

pub fn extract_artifacts(error: Option<&str>, history_entry: Option<&str>) -> Vec<String> {
    let mut artifacts = Vec::new();

    if let Some(err) = error {
        if let Some(path) = extract_grounding_path(err) {
            artifacts.push(path);
        }
    }

    if let Some(entry) = history_entry {
        if let Some(path) = extract_grounding_path(entry) {
            if !artifacts.iter().any(|p| p == &path) {
                artifacts.push(path);
            }
        }
    }

    artifacts
}

fn extract_grounding_path(input: &str) -> Option<String> {
    let marker = "grounding_debug=";
    let start = input.find(marker)?;
    let after = &input[start + marker.len()..];
    let end = after.find(']').unwrap_or(after.len());
    let candidate = after[..end].trim();
    if candidate.is_empty() {
        None
    } else {
        Some(candidate.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus};
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
            active_lens: None,
        }
    }

    #[test]
    fn classify_focus_mismatch() {
        let class = classify_failure(
            Some("FOCUS_REQUIRED: Foreground is 'Finder' but goal requires 'calculator'"),
            "allowed",
        );
        assert_eq!(class, Some(FailureClass::FocusMismatch));
    }

    #[test]
    fn classify_permission_from_policy_decision() {
        let class = classify_failure(Some("Blocked by Policy"), "denied");
        assert_eq!(class, Some(FailureClass::PermissionOrApprovalRequired));
    }

    #[test]
    fn classify_target_not_found_over_active_window_wording() {
        let class = classify_failure(
            Some("Target 'btn_5' not found in active window after lookup."),
            "allowed",
        );
        assert_eq!(class, Some(FailureClass::TargetNotFound));
    }

    #[test]
    fn classify_error_class_markers() {
        let focus = classify_failure(
            Some("ERROR_CLASS=FocusMismatch Focused window does not match target."),
            "allowed",
        );
        assert_eq!(focus, Some(FailureClass::FocusMismatch));

        let target = classify_failure(
            Some("ERROR_CLASS=TargetNotFound Target 'btn_5' not found in current UI tree."),
            "allowed",
        );
        assert_eq!(target, Some(FailureClass::TargetNotFound));

        let vision = classify_failure(
            Some("ERROR_CLASS=VisionTargetNotFound Visual localization confidence too low."),
            "allowed",
        );
        assert_eq!(vision, Some(FailureClass::VisionTargetNotFound));

        let no_effect = classify_failure(
            Some("ERROR_CLASS=NoEffectAfterAction UI state static after click."),
            "allowed",
        );
        assert_eq!(no_effect, Some(FailureClass::NoEffectAfterAction));

        let tier = classify_failure(
            Some("ERROR_CLASS=TierViolation Vision localization is only allowed in VisualForeground tier."),
            "allowed",
        );
        assert_eq!(tier, Some(FailureClass::TierViolation));

        let missing_dep = classify_failure(
            Some("ERROR_CLASS=MissingDependency Missing focus dependency 'wmctrl' on Linux."),
            "allowed",
        );
        assert_eq!(missing_dep, Some(FailureClass::MissingDependency));

        let context_drift = classify_failure(
            Some("ERROR_CLASS=ContextDrift Visual context drift detected before resume."),
            "allowed",
        );
        assert_eq!(context_drift, Some(FailureClass::ContextDrift));

        let human_challenge = classify_failure(
            Some(
                "ERROR_CLASS=HumanChallengeRequired reCAPTCHA challenge detected. Open in Local Browser.",
            ),
            "allowed",
        );
        assert_eq!(human_challenge, Some(FailureClass::UserInterventionNeeded));
    }

    #[test]
    fn routing_failure_mapping_is_exact_for_extended_classes() {
        assert_eq!(
            to_routing_failure_class(FailureClass::VisionTargetNotFound),
            RoutingFailureClass::VisionTargetNotFound
        );
        assert_eq!(
            to_routing_failure_class(FailureClass::NoEffectAfterAction),
            RoutingFailureClass::NoEffectAfterAction
        );
        assert_eq!(
            to_routing_failure_class(FailureClass::TierViolation),
            RoutingFailureClass::TierViolation
        );
        assert_eq!(
            to_routing_failure_class(FailureClass::MissingDependency),
            RoutingFailureClass::MissingDependency
        );
        assert_eq!(
            to_routing_failure_class(FailureClass::ContextDrift),
            RoutingFailureClass::ContextDrift
        );
    }

    #[test]
    fn retry_guard_only_trips_after_limit() {
        assert!(!should_trip_retry_guard(FailureClass::UnexpectedState, 2));
        assert!(should_trip_retry_guard(FailureClass::UnexpectedState, 3));
    }

    #[test]
    fn attempt_key_hash_is_stable() {
        let key_a = build_attempt_key(
            "deadbeef",
            ExecutionTier::DomHeadless,
            "sys__exec",
            Some("calculator"),
            Some("abcd"),
        );
        let key_b = build_attempt_key(
            "deadbeef",
            ExecutionTier::DomHeadless,
            "sys__exec",
            Some("calculator"),
            Some("abcd"),
        );
        assert_eq!(attempt_key_hash(&key_a), attempt_key_hash(&key_b));
    }

    #[test]
    fn stable_attempt_key_dedupes_and_resets_on_condition_change() {
        let mut state = test_agent_state();
        let key = build_attempt_key(
            "feedface",
            ExecutionTier::DomHeadless,
            "computer::left_click",
            Some("btn_submit"),
            Some("ff00"),
        );
        let (first, first_hash) =
            register_failure_attempt(&mut state, FailureClass::TargetNotFound, &key);
        let (second, second_hash) =
            register_failure_attempt(&mut state, FailureClass::TargetNotFound, &key);
        assert_eq!(first, 1);
        assert_eq!(second, 2);
        assert_eq!(first_hash, second_hash);
        assert!(should_block_retry_without_change(
            FailureClass::TargetNotFound,
            second
        ));
        assert_eq!(retry_budget_remaining(second), 1);

        let changed_tier_key = build_attempt_key(
            "feedface",
            ExecutionTier::VisualBackground,
            "computer::left_click",
            Some("btn_submit"),
            Some("ff00"),
        );
        let (third, _) =
            register_failure_attempt(&mut state, FailureClass::TargetNotFound, &changed_tier_key);
        assert_eq!(third, 1);
    }

    #[test]
    fn trailing_repeat_count_is_contiguous() {
        let history = vec![
            "a".to_string(),
            "b".to_string(),
            "b".to_string(),
            "b".to_string(),
        ];
        assert_eq!(trailing_repetition_count(&history, "b"), 3);
        assert_eq!(trailing_repetition_count(&history, "a"), 0);
    }

    #[test]
    fn extract_grounding_debug_artifact() {
        let artifacts = extract_artifacts(
            Some("Input injection failed [grounding_debug=/tmp/ioi-grounding/debug.json]"),
            None,
        );
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0], "/tmp/ioi-grounding/debug.json");
    }

    #[test]
    fn policy_binding_hash_is_stable() {
        let a = policy_binding_hash("abc", "allowed");
        let b = policy_binding_hash("abc", "allowed");
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn routing_defaults_to_tool_first() {
        let state = test_agent_state();
        let decision = choose_routing_tier(&state);
        assert_eq!(decision.tier, ExecutionTier::DomHeadless);
        assert_eq!(decision.reason_code, "tool_first_default");
        assert_eq!(decision.source_failure, None);
    }

    #[test]
    fn routing_escalates_focus_failures_to_visual_last() {
        let mut state = test_agent_state();
        state.consecutive_failures = 1;
        state
            .recent_actions
            .push("gui__click::FocusMismatch::abcd1234".to_string());
        let decision = choose_routing_tier(&state);
        assert_eq!(decision.tier, ExecutionTier::VisualForeground);
        assert_eq!(decision.reason_code, "visual_last_focus");
        assert_eq!(decision.source_failure, Some(FailureClass::FocusMismatch));
    }

    #[test]
    fn routing_keeps_permission_failures_tool_first() {
        let mut state = test_agent_state();
        state.consecutive_failures = 2;
        state
            .recent_actions
            .push("sys__exec::PermissionOrApprovalRequired::abcd1234".to_string());
        let decision = choose_routing_tier(&state);
        assert_eq!(decision.tier, ExecutionTier::DomHeadless);
        assert_eq!(
            decision.reason_code,
            "tool_first_waiting_for_policy_or_user"
        );
        assert_eq!(
            decision.source_failure,
            Some(FailureClass::PermissionOrApprovalRequired)
        );
    }

    #[test]
    fn routing_stages_tool_unavailable_before_visual_last() {
        let mut state = test_agent_state();
        state.consecutive_failures = 1;
        state
            .recent_actions
            .push("computer::ToolUnavailable::abcd1234".to_string());
        let first = choose_routing_tier(&state);
        assert_eq!(first.tier, ExecutionTier::VisualBackground);
        assert_eq!(first.reason_code, "ax_first_tool_gap");

        state.consecutive_failures = 2;
        let second = choose_routing_tier(&state);
        assert_eq!(second.tier, ExecutionTier::VisualForeground);
        assert_eq!(second.reason_code, "visual_last_tool_gap");
    }
}
