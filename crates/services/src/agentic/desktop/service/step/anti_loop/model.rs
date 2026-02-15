use crate::agentic::desktop::types::ExecutionTier;
use serde::Serialize;

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

pub fn tier_as_str(tier: ExecutionTier) -> &'static str {
    match tier {
        ExecutionTier::DomHeadless => "ToolFirst",
        ExecutionTier::VisualBackground => "AxFirst",
        ExecutionTier::VisualForeground => "VisualLast",
    }
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
