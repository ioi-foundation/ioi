use super::*;
use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
use ioi_types::app::RoutingFailureClass;
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
        working_directory: ".".to_string(),
        active_lens: None,
        pending_search_completion: None,
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

    let package_not_found = classify_failure(
        Some(
            "ERROR_CLASS=MissingDependency Failed to install 'calculator': E: Unable to locate package calculator",
        ),
        "allowed",
    );
    assert_eq!(
        package_not_found,
        Some(FailureClass::UserInterventionNeeded)
    );

    let context_drift = classify_failure(
        Some("ERROR_CLASS=ContextDrift Visual context drift detected before resume."),
        "allowed",
    );
    assert_eq!(context_drift, Some(FailureClass::ContextDrift));

    let human_challenge = classify_failure(
        Some(
            "ERROR_CLASS=HumanChallengeRequired reCAPTCHA challenge detected. Open in your browser/app.",
        ),
        "allowed",
    );
    assert_eq!(human_challenge, Some(FailureClass::UserInterventionNeeded));

    let tool_unavailable = classify_failure(
        Some("ERROR_CLASS=ToolUnavailable Tool is not installed on this host."),
        "allowed",
    );
    assert_eq!(tool_unavailable, Some(FailureClass::ToolUnavailable));

    let non_deterministic = classify_failure(
        Some("ERROR_CLASS=NonDeterministicUI Screen changed unexpectedly between retries."),
        "allowed",
    );
    assert_eq!(non_deterministic, Some(FailureClass::NonDeterministicUI));

    let timeout = classify_failure(
        Some("ERROR_CLASS=TimeoutOrHang Action exceeded its execution deadline."),
        "allowed",
    );
    assert_eq!(timeout, Some(FailureClass::TimeoutOrHang));

    let unexpected = classify_failure(
        Some("ERROR_CLASS=UnexpectedState State machine entered an invalid state."),
        "allowed",
    );
    assert_eq!(unexpected, Some(FailureClass::UnexpectedState));
}

#[test]
fn classify_plain_package_lookup_failures_as_user_intervention_needed() {
    let apt_missing = classify_failure(Some("E: Unable to locate package calculator"), "allowed");
    assert_eq!(apt_missing, Some(FailureClass::UserInterventionNeeded));

    let dnf_missing = classify_failure(Some("No match for argument: myapp"), "allowed");
    assert_eq!(dnf_missing, Some(FailureClass::UserInterventionNeeded));
}

#[test]
fn classify_marker_only_install_missing_dependency_as_user_intervention_needed() {
    let marker_only = classify_failure(
        Some(
            "ERROR_CLASS=MissingDependency Failed to install 'calculator' via 'apt-get': Command failed: exit status: 100",
        ),
        "allowed",
    );
    assert_eq!(marker_only, Some(FailureClass::UserInterventionNeeded));
}

#[test]
fn classify_launch_lookup_failures_as_user_intervention_needed() {
    let launch_missing = classify_failure(
        Some(
            "ERROR_CLASS=ToolUnavailable Failed to launch calculator after 5 attempt(s): gtk-launch calculator (non-zero exit: Command failed: exit status: 2) | calculator (Failed to spawn detached command 'calculator': No such file or directory (os error 2))",
        ),
        "allowed",
    );
    assert_eq!(launch_missing, Some(FailureClass::UserInterventionNeeded));
}

#[test]
fn clarification_gate_detects_marker_only_install_failures() {
    let msg =
        "ERROR_CLASS=MissingDependency Failed to install 'calculator' via 'apt-get': Command failed: exit status: 100";
    assert!(requires_wait_for_clarification("sys__install_package", msg));
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
