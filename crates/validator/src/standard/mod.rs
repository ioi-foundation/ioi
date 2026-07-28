// Path: crates/validator/src/standard/mod.rs
//! Standard validator implementations.

/// The Orchestration container logic.
pub mod orchestration;
/// The Compute Provider logic.
pub mod provider;
/// The Workload container logic.
pub mod workload;

pub use orchestration::Orchestrator;
pub use workload::ipc::WorkloadIpcServer;

/// Testing-harness escape hatch for AFT restart/resume over chains that
/// never persisted canonical collapse objects (GuardianMajority harness
/// chains: that publication lane runs only under the Asymptote sealed
/// path). Set exclusively by the stable-state-dir testing harness in
/// crates/cli/src/testing; never set in production, where behavior stays
/// byte-identical.
pub(crate) fn testing_trivial_aft_restart_anchor_enabled() -> bool {
    std::env::var("IOI_TESTING_AFT_TRIVIAL_RESTART_ANCHOR")
        .map(|value| value == "1")
        .unwrap_or(false)
}
