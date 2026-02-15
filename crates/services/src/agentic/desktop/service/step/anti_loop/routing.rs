use super::attempts::latest_failure_class;
use super::model::{tier_as_str, FailureClass, TierRoutingDecision};
use crate::agentic::desktop::types::{AgentState, AgentStatus, ExecutionTier};
use ioi_types::app::{RoutingPostStateSummary, RoutingStateSummary};

fn status_as_str(status: &AgentStatus) -> String {
    format!("{:?}", status)
        .split('(')
        .next()
        .unwrap_or("Unknown")
        .to_string()
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
