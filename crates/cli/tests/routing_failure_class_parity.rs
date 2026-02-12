// Path: crates/cli/tests/routing_failure_class_parity.rs

use ioi_services::agentic::desktop::service::step::anti_loop::{
    classify_failure, to_routing_failure_class, FailureClass,
};
use ioi_types::app::{
    RoutingFailureClass, RoutingPostStateSummary, RoutingReceiptEvent, RoutingStateSummary,
};

#[test]
fn routing_receipt_failure_class_preserves_internal_failure_signal() {
    let scenarios = vec![
        (
            "ERROR_CLASS=VisionTargetNotFound Visual localization confidence too low.",
            FailureClass::VisionTargetNotFound,
            RoutingFailureClass::VisionTargetNotFound,
        ),
        (
            "ERROR_CLASS=NoEffectAfterAction UI state unchanged after click.",
            FailureClass::NoEffectAfterAction,
            RoutingFailureClass::NoEffectAfterAction,
        ),
        (
            "ERROR_CLASS=TierViolation Vision localization is only allowed in VisualForeground tier.",
            FailureClass::TierViolation,
            RoutingFailureClass::TierViolation,
        ),
        (
            "ERROR_CLASS=MissingDependency Missing focus dependency 'wmctrl' on Linux.",
            FailureClass::MissingDependency,
            RoutingFailureClass::MissingDependency,
        ),
        (
            "ERROR_CLASS=ContextDrift Visual context drift detected before resume.",
            FailureClass::ContextDrift,
            RoutingFailureClass::ContextDrift,
        ),
        (
            "ERROR_CLASS=ToolUnavailable Tool 'browser__click' is not handled by executor.",
            FailureClass::ToolUnavailable,
            RoutingFailureClass::ToolUnavailable,
        ),
        (
            "ERROR_CLASS=NonDeterministicUI Screen changed unexpectedly between retries.",
            FailureClass::NonDeterministicUI,
            RoutingFailureClass::NonDeterministicUI,
        ),
        (
            "ERROR_CLASS=TimeoutOrHang Action exceeded deadline waiting for UI response.",
            FailureClass::TimeoutOrHang,
            RoutingFailureClass::TimeoutOrHang,
        ),
        (
            "ERROR_CLASS=UnexpectedState Executor returned invalid transition.",
            FailureClass::UnexpectedState,
            RoutingFailureClass::UnexpectedState,
        ),
        (
            "ERROR_CLASS=NavigationFallbackFailed Navigation failed via browser driver: timeout. Visual fallback failed: ERROR_CLASS=NavigationFallbackFailed Failed to derive browser viewport/url-bar geometry.",
            FailureClass::NonDeterministicUI,
            RoutingFailureClass::NonDeterministicUI,
        ),
    ];

    for (error, expected_internal, expected_public) in scenarios {
        let internal = classify_failure(Some(error), "allowed");
        assert_eq!(internal, Some(expected_internal));
        let mapped = internal.map(to_routing_failure_class);
        assert_eq!(mapped, Some(expected_public));
    }
}

#[test]
fn routing_receipt_for_explicit_tool_unavailable_marker_preserves_failure_class() {
    let internal = classify_failure(
        Some("ERROR_CLASS=ToolUnavailable Tool 'sys__install_package' is unavailable."),
        "allowed",
    )
    .expect("marker should classify");
    let mapped = to_routing_failure_class(internal);

    let receipt = RoutingReceiptEvent {
        session_id: [0x11; 32],
        step_index: 3,
        intent_hash: "intent_hash".to_string(),
        policy_decision: "allowed".to_string(),
        tool_name: "sys__install_package".to_string(),
        tool_version: "test-v1".to_string(),
        pre_state: RoutingStateSummary {
            agent_status: "Running".to_string(),
            tier: "ToolFirst".to_string(),
            step_index: 3,
            consecutive_failures: 1,
            target_hint: Some("terminal".to_string()),
        },
        action_json: "{\"name\":\"sys__install_package\"}".to_string(),
        post_state: RoutingPostStateSummary {
            agent_status: "Paused".to_string(),
            tier: "AxFirst".to_string(),
            step_index: 4,
            consecutive_failures: 2,
            success: false,
            verification_checks: vec![
                "policy_decision=allowed".to_string(),
                "failure_class=ToolUnavailable".to_string(),
            ],
        },
        artifacts: vec!["trace://agent_step/3".to_string()],
        failure_class: Some(mapped),
        stop_condition_hit: false,
        escalation_path: Some("Request capability escalation or switch modality.".to_string()),
        scs_lineage_ptr: None,
        mutation_receipt_ptr: None,
        policy_binding_hash: "binding".to_string(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert_eq!(
        receipt.failure_class,
        Some(RoutingFailureClass::ToolUnavailable)
    );
    assert_eq!(receipt.pre_state.tier, "ToolFirst");
    assert_eq!(receipt.post_state.tier, "AxFirst");
    assert!(receipt
        .post_state
        .verification_checks
        .iter()
        .any(|check| check == "failure_class=ToolUnavailable"));
}

#[test]
fn routing_receipt_for_navigation_fallback_failure_sets_nondeterministic_ui() {
    let internal = classify_failure(
        Some(
            "ERROR_CLASS=NavigationFallbackFailed Navigation failed via browser driver: timeout. Visual fallback failed: ERROR_CLASS=NavigationFallbackFailed Failed to derive browser viewport/url-bar geometry.",
        ),
        "allowed",
    )
    .expect("marker should classify");
    let mapped = to_routing_failure_class(internal);

    let receipt = RoutingReceiptEvent {
        session_id: [0x33; 32],
        step_index: 9,
        intent_hash: "intent_hash".to_string(),
        policy_decision: "allowed".to_string(),
        tool_name: "browser__navigate".to_string(),
        tool_version: "test-v1".to_string(),
        pre_state: RoutingStateSummary {
            agent_status: "Running".to_string(),
            tier: "AxFirst".to_string(),
            step_index: 9,
            consecutive_failures: 2,
            target_hint: Some("browser".to_string()),
        },
        action_json: "{\"name\":\"browser__navigate\"}".to_string(),
        post_state: RoutingPostStateSummary {
            agent_status: "Running".to_string(),
            tier: "VisualLast".to_string(),
            step_index: 10,
            consecutive_failures: 3,
            success: false,
            verification_checks: vec![
                "policy_decision=allowed".to_string(),
                "failure_class=NonDeterministicUI".to_string(),
            ],
        },
        artifacts: vec!["trace://agent_step/9".to_string()],
        failure_class: Some(mapped),
        stop_condition_hit: false,
        escalation_path: Some(
            "Escalate to VisualForeground with post-action verification checks.".to_string(),
        ),
        scs_lineage_ptr: None,
        mutation_receipt_ptr: None,
        policy_binding_hash: "binding".to_string(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert_eq!(
        receipt.failure_class,
        Some(RoutingFailureClass::NonDeterministicUI)
    );
    assert_eq!(receipt.pre_state.tier, "AxFirst");
    assert_eq!(receipt.post_state.tier, "VisualLast");
    assert!(receipt
        .post_state
        .verification_checks
        .iter()
        .any(|check| check == "failure_class=NonDeterministicUI"));
}

#[test]
fn routing_classifies_navigation_fallback_invalid_url_as_unexpected_state() {
    let internal = classify_failure(
        Some(
            "ERROR_CLASS=NavigationFallbackFailed Visual navigation requires an absolute http/https URL.",
        ),
        "allowed",
    );

    assert_eq!(internal, Some(FailureClass::UnexpectedState));
}
