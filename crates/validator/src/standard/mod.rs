// Path: crates/validator/src/standard/mod.rs

pub mod orchestration;

// FIX: Publicly re-export the container so it's visible to binaries in the same crate.
pub use orchestration::OrchestrationContainer;