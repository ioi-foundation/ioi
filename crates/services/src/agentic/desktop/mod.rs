// Path: crates/services/src/agentic/desktop/mod.rs
pub mod execution;
pub mod keys;
pub mod service; 
pub mod tools;
pub mod types;
pub mod utils;
// [NEW] Register middleware module
pub mod middleware;

// Re-export the main struct from the new module location
pub use service::DesktopAgentService;
pub use types::{
    AgentState, AgentStatus, ResumeAgentParams, StartAgentParams, StepAgentParams, AgentMode,
};