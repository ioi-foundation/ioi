//! Autopilot proof and harness entrypoints.
//!
//! These modules are validation surfaces. Product runtime code should not grow
//! new canonical execution behavior here.

pub mod chat_artifact;
pub mod file_context;
pub mod plugin;
pub mod repl;
pub mod workflow;
