//! Definitions for native driver tools and capabilities.
//!
//! This module is intentionally split into submodules to keep the core tool enum manageable.

mod agent_tool;
mod commerce;
mod pii;
mod screen;
mod target;

#[cfg(test)]
mod tests;

pub use agent_tool::{
    AgentFileEditOperation, AgentTool, AgentToolCall, ApprovalGateEvent, BrowserActionPlanRef,
    BrowserObservationReceipt, CommandEnvironmentBinding, CommandExecutionPlanRef, CommandReceipt,
    ExecutionStreamEvent, FileMutationPlanRef, FileMutationReceipt, HostDiscoverySnapshot,
    HostMutationScope, InstallApprovalEvent, InstallExecutionStreamEvent, InstallFinalReceipt,
    InstallResolutionEvent, InstallSourceCandidate, InstallVerificationEvent, RequiredCapability,
    ResolvedInstallPlan, RuntimeActionFrame, RuntimeIntentEvidence, RuntimeProgressEvent,
    RuntimeRouteFrame, SoftwareInstallRequestFrame, ToolFinalReceipt, VerificationReceipt,
};
pub use commerce::CommerceItem;
pub use pii::{PiiEgressField, PiiEgressRiskSurface, PiiEgressSpec};
pub use screen::ScreenAction;
