// Path: crates/services/src/agentic/desktop/service/step/ontology.rs

use super::anti_loop::FailureClass;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum IntentClass {
    OpenApp,
    InstallDependency,
    BrowserTask,
    FileTask,
    UIInteraction,
    CommandTask,
    DelegationTask,
    ConversationTask,
    Unknown,
}

impl IntentClass {
    pub fn as_str(self) -> &'static str {
        match self {
            IntentClass::OpenApp => "OpenApp",
            IntentClass::InstallDependency => "InstallDependency",
            IntentClass::BrowserTask => "BrowserTask",
            IntentClass::FileTask => "FileTask",
            IntentClass::UIInteraction => "UIInteraction",
            IntentClass::CommandTask => "CommandTask",
            IntentClass::DelegationTask => "DelegationTask",
            IntentClass::ConversationTask => "ConversationTask",
            IntentClass::Unknown => "Unknown",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "OpenApp" => IntentClass::OpenApp,
            "InstallDependency" => IntentClass::InstallDependency,
            "BrowserTask" => IntentClass::BrowserTask,
            "FileTask" => IntentClass::FileTask,
            "UIInteraction" => IntentClass::UIInteraction,
            "CommandTask" => IntentClass::CommandTask,
            "DelegationTask" => IntentClass::DelegationTask,
            "ConversationTask" => IntentClass::ConversationTask,
            _ => IntentClass::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum IncidentStage {
    New,
    Diagnose,
    Plan,
    AwaitApproval,
    ExecuteRemedy,
    RetryRoot,
    Resolved,
    Exhausted,
    PausedForUser,
}

impl IncidentStage {
    pub fn as_str(self) -> &'static str {
        match self {
            IncidentStage::New => "New",
            IncidentStage::Diagnose => "Diagnose",
            IncidentStage::Plan => "Plan",
            IncidentStage::AwaitApproval => "AwaitApproval",
            IncidentStage::ExecuteRemedy => "ExecuteRemedy",
            IncidentStage::RetryRoot => "RetryRoot",
            IncidentStage::Resolved => "Resolved",
            IncidentStage::Exhausted => "Exhausted",
            IncidentStage::PausedForUser => "PausedForUser",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "New" => IncidentStage::New,
            "Diagnose" => IncidentStage::Diagnose,
            "Plan" => IncidentStage::Plan,
            "AwaitApproval" => IncidentStage::AwaitApproval,
            "ExecuteRemedy" => IncidentStage::ExecuteRemedy,
            "RetryRoot" => IncidentStage::RetryRoot,
            "Resolved" => IncidentStage::Resolved,
            "Exhausted" => IncidentStage::Exhausted,
            "PausedForUser" => IncidentStage::PausedForUser,
            _ => IncidentStage::New,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum StrategyName {
    OpenAppRecovery,
    InstallRecovery,
    BrowserRecovery,
    FileRecovery,
    UIRecovery,
    CommandRecovery,
    DelegationRecovery,
    ConversationRecovery,
    GenericRecovery,
}

impl StrategyName {
    pub fn as_str(self) -> &'static str {
        match self {
            StrategyName::OpenAppRecovery => "OpenAppRecovery",
            StrategyName::InstallRecovery => "InstallRecovery",
            StrategyName::BrowserRecovery => "BrowserRecovery",
            StrategyName::FileRecovery => "FileRecovery",
            StrategyName::UIRecovery => "UIRecovery",
            StrategyName::CommandRecovery => "CommandRecovery",
            StrategyName::DelegationRecovery => "DelegationRecovery",
            StrategyName::ConversationRecovery => "ConversationRecovery",
            StrategyName::GenericRecovery => "GenericRecovery",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "OpenAppRecovery" => StrategyName::OpenAppRecovery,
            "InstallRecovery" => StrategyName::InstallRecovery,
            "BrowserRecovery" => StrategyName::BrowserRecovery,
            "FileRecovery" => StrategyName::FileRecovery,
            "UIRecovery" => StrategyName::UIRecovery,
            "CommandRecovery" => StrategyName::CommandRecovery,
            "DelegationRecovery" => StrategyName::DelegationRecovery,
            "ConversationRecovery" => StrategyName::ConversationRecovery,
            _ => StrategyName::GenericRecovery,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum StrategyNode {
    DiagnoseFailure,
    DiscoverRemedy,
    InstallDependency,
    RefreshContext,
    RetryRootAction,
    VerifyOutcome,
    PauseForUser,
    Complete,
    Exhausted,
}

impl StrategyNode {
    pub fn as_str(self) -> &'static str {
        match self {
            StrategyNode::DiagnoseFailure => "DiagnoseFailure",
            StrategyNode::DiscoverRemedy => "DiscoverRemedy",
            StrategyNode::InstallDependency => "InstallDependency",
            StrategyNode::RefreshContext => "RefreshContext",
            StrategyNode::RetryRootAction => "RetryRootAction",
            StrategyNode::VerifyOutcome => "VerifyOutcome",
            StrategyNode::PauseForUser => "PauseForUser",
            StrategyNode::Complete => "Complete",
            StrategyNode::Exhausted => "Exhausted",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "DiagnoseFailure" => StrategyNode::DiagnoseFailure,
            "DiscoverRemedy" => StrategyNode::DiscoverRemedy,
            "InstallDependency" => StrategyNode::InstallDependency,
            "RefreshContext" => StrategyNode::RefreshContext,
            "RetryRootAction" => StrategyNode::RetryRootAction,
            "VerifyOutcome" => StrategyNode::VerifyOutcome,
            "PauseForUser" => StrategyNode::PauseForUser,
            "Complete" => StrategyNode::Complete,
            "Exhausted" => StrategyNode::Exhausted,
            _ => StrategyNode::DiagnoseFailure,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum GateState {
    None,
    Pending,
    Approved,
    Denied,
    Cleared,
}

impl GateState {
    pub fn as_str(self) -> &'static str {
        match self {
            GateState::None => "None",
            GateState::Pending => "Pending",
            GateState::Approved => "Approved",
            GateState::Denied => "Denied",
            GateState::Cleared => "Cleared",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "Pending" => GateState::Pending,
            "Approved" => GateState::Approved,
            "Denied" => GateState::Denied,
            "Cleared" => GateState::Cleared,
            _ => GateState::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum ResolutionAction {
    None,
    WaitForUser,
    ExecuteRemedy,
    RetryRoot,
    Pause,
    Escalate,
    MarkResolved,
    MarkExhausted,
}

impl ResolutionAction {
    pub fn as_str(self) -> &'static str {
        match self {
            ResolutionAction::None => "none",
            ResolutionAction::WaitForUser => "wait_for_user",
            ResolutionAction::ExecuteRemedy => "execute_remedy",
            ResolutionAction::RetryRoot => "retry_root",
            ResolutionAction::Pause => "pause",
            ResolutionAction::Escalate => "escalate",
            ResolutionAction::MarkResolved => "mark_resolved",
            ResolutionAction::MarkExhausted => "mark_exhausted",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "wait_for_user" => ResolutionAction::WaitForUser,
            "execute_remedy" => ResolutionAction::ExecuteRemedy,
            "retry_root" => ResolutionAction::RetryRoot,
            "pause" => ResolutionAction::Pause,
            "escalate" => ResolutionAction::Escalate,
            "mark_resolved" => ResolutionAction::MarkResolved,
            "mark_exhausted" => ResolutionAction::MarkExhausted,
            _ => ResolutionAction::None,
        }
    }
}

pub fn classify_intent(goal: &str, root_tool_name: &str, target_hint: Option<&str>) -> IntentClass {
    let goal_lc = goal.to_ascii_lowercase();
    let tool_lc = root_tool_name.to_ascii_lowercase();
    let hint_lc = target_hint.unwrap_or("").to_ascii_lowercase();

    if tool_lc.contains("agent__delegate") || goal_lc.contains("delegate") {
        return IntentClass::DelegationTask;
    }
    if tool_lc.contains("chat__reply")
        || goal_lc.contains("ask")
        || goal_lc.contains("explain")
        || goal_lc.contains("summarize")
    {
        return IntentClass::ConversationTask;
    }
    if tool_lc.contains("os__launch_app")
        || goal_lc.contains("open ")
        || goal_lc.contains("launch ")
        || goal_lc.contains("start ")
        || !hint_lc.is_empty()
    {
        return IntentClass::OpenApp;
    }
    if tool_lc.contains("sys__install_package")
        || goal_lc.contains("install ")
        || goal_lc.contains("dependency")
    {
        return IntentClass::InstallDependency;
    }
    if tool_lc.contains("browser__")
        || goal_lc.contains("browser")
        || goal_lc.contains("search ")
        || goal_lc.contains("web ")
        || goal_lc.contains("http")
    {
        return IntentClass::BrowserTask;
    }
    if tool_lc.contains("filesystem__")
        || goal_lc.contains("file")
        || goal_lc.contains("directory")
        || goal_lc.contains("repo")
    {
        return IntentClass::FileTask;
    }
    if tool_lc.contains("gui__")
        || tool_lc.contains("computer")
        || goal_lc.contains("click")
        || goal_lc.contains("type")
        || goal_lc.contains("press")
        || goal_lc.contains("drag")
    {
        return IntentClass::UIInteraction;
    }
    if tool_lc.contains("sys__exec") || tool_lc.contains("sys__change_directory") {
        return IntentClass::CommandTask;
    }
    IntentClass::Unknown
}

pub fn default_strategy_for(
    intent: IntentClass,
    failure: FailureClass,
) -> (StrategyName, StrategyNode) {
    match intent {
        IntentClass::OpenApp => match failure {
            FailureClass::ToolUnavailable | FailureClass::MissingDependency => (
                StrategyName::OpenAppRecovery,
                StrategyNode::InstallDependency,
            ),
            FailureClass::PermissionOrApprovalRequired => {
                (StrategyName::OpenAppRecovery, StrategyNode::RetryRootAction)
            }
            FailureClass::UserInterventionNeeded => {
                (StrategyName::OpenAppRecovery, StrategyNode::PauseForUser)
            }
            _ => (StrategyName::OpenAppRecovery, StrategyNode::DiscoverRemedy),
        },
        IntentClass::InstallDependency => {
            (StrategyName::InstallRecovery, StrategyNode::RetryRootAction)
        }
        IntentClass::BrowserTask => match failure {
            FailureClass::UserInterventionNeeded => {
                (StrategyName::BrowserRecovery, StrategyNode::PauseForUser)
            }
            _ => (StrategyName::BrowserRecovery, StrategyNode::RefreshContext),
        },
        IntentClass::FileTask => (StrategyName::FileRecovery, StrategyNode::DiscoverRemedy),
        IntentClass::UIInteraction => (StrategyName::UIRecovery, StrategyNode::RefreshContext),
        IntentClass::CommandTask => (StrategyName::CommandRecovery, StrategyNode::DiscoverRemedy),
        IntentClass::DelegationTask => (
            StrategyName::DelegationRecovery,
            StrategyNode::RetryRootAction,
        ),
        IntentClass::ConversationTask => (
            StrategyName::ConversationRecovery,
            StrategyNode::PauseForUser,
        ),
        IntentClass::Unknown => (StrategyName::GenericRecovery, StrategyNode::DiagnoseFailure),
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_intent, default_strategy_for, IntentClass, StrategyNode};
    use crate::agentic::desktop::service::step::anti_loop::FailureClass;

    #[test]
    fn classify_open_app_by_goal_and_hint() {
        assert_eq!(
            classify_intent("open calculator", "os__launch_app", Some("calculator")),
            IntentClass::OpenApp
        );
    }

    #[test]
    fn classify_file_task() {
        assert_eq!(
            classify_intent("read file", "filesystem__read_file", None),
            IntentClass::FileTask
        );
    }

    #[test]
    fn open_app_unavailable_prefers_install_node() {
        let (_, node) = default_strategy_for(IntentClass::OpenApp, FailureClass::ToolUnavailable);
        assert_eq!(node, StrategyNode::InstallDependency);
    }
}
