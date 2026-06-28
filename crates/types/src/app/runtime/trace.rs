//! Trace, prompt assembly, and GUI validation contract family.

pub use super::super::runtime_contracts::{
    FileObservationState, FileReadStatus, HypervisorGuiHarnessValidationContract,
    HypervisorRetainedQuery, PromptAssemblyContract, PromptConflictResolution, PromptLayerKind,
    PromptPrivacyClass, PromptSectionMutability, PromptSectionRecord, PromptTruncationStatus,
    SessionTraceBundle, HYPERVISOR_GUI_HARNESS_LAUNCH_COMMAND,
    HYPERVISOR_GUI_HARNESS_SCHEMA_VERSION_V1,
};
