// Path: crates/cli/tests/routing_failure_class_parity.rs

use ioi_services::agentic::desktop::service::step::anti_loop::{
    classify_failure, to_routing_failure_class, FailureClass,
};
use ioi_types::app::RoutingFailureClass;

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
    ];

    for (error, expected_internal, expected_public) in scenarios {
        let internal = classify_failure(Some(error), "allowed");
        assert_eq!(internal, Some(expected_internal));
        let mapped = internal.map(to_routing_failure_class);
        assert_eq!(mapped, Some(expected_public));
    }
}
