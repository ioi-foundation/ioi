// Path: crates/services/src/agentic/desktop/mod.rs
pub mod execution;
pub mod keys;
pub mod service;
pub mod tools;
pub mod types;
pub mod utils;

pub use service::DesktopAgentService;
pub use types::{
    AgentState, AgentStatus, ResumeAgentParams, StartAgentParams, StepAgentParams, AgentMode, // [FIX] Added AgentMode
};