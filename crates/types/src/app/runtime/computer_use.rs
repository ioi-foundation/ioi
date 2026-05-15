//! Computer-use and browser-use harness contract family.

pub use super::super::runtime_contracts::{
    ActionProposal, ActionReceipt, AffordanceGraph, AffordanceRecord, CleanupReceipt, CommitGate,
    CommitGateStatus, ComputerAction, ComputerActionKind, ComputerControlAdapterContract,
    ComputerUseBounds, ComputerUseFailureClass, ComputerUseHarnessContract, ComputerUseLane,
    ComputerUseLease, ComputerUseLeaseStatus, ComputerUseObservationBundle,
    ComputerUseRecoveryAction, ComputerUseRunState, ComputerUseSessionMode, ComputerUseTargetEntry,
    ComputerUseTrajectoryBundle, ComputerUseTrajectoryEntry, ComputerUseVerificationReceipt,
    ComputerUseVerificationStatus, EnvironmentOptionRejection, EnvironmentSelectionReceipt,
    HumanHandoffState, InterfacePatternIndex, InterfacePatternKind, ObservationRetentionMode,
    OutcomeContract, RecoveryPolicy, TargetIndex, COMPUTER_USE_CONTRACT_SCHEMA_VERSION_V1,
};
