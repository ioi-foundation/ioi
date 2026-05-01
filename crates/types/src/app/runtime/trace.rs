//! Trace, prompt assembly, and GUI validation contract family.

pub use super::super::runtime_contracts::{
    AutopilotGuiHarnessValidationContract, AutopilotRetainedQuery, FileObservationState,
    FileReadStatus, PromptAssemblyContract, PromptConflictResolution, PromptLayerKind,
    PromptPrivacyClass, PromptSectionMutability, PromptSectionRecord, PromptTruncationStatus,
    SessionTraceBundle, AUTOPILOT_GUI_HARNESS_LAUNCH_COMMAND,
    AUTOPILOT_GUI_HARNESS_SCHEMA_VERSION_V1,
};
