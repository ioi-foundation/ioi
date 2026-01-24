pub mod execution;
pub mod keys;
pub mod service; // This now points to the directory
pub mod tools;
pub mod types;
pub mod utils;

// Re-export the main struct from the new module location
pub use service::DesktopAgentService;
pub use types::{
    AgentState, AgentStatus, ResumeAgentParams, StartAgentParams, StepAgentParams, AgentMode,
};