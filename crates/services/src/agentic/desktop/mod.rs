// crates/services/src/agentic/desktop/mod.rs

pub mod execution; // Points to execution/mod.rs now
pub mod keys;
pub mod middleware;
pub mod service;
pub mod tools;
pub mod types;
pub mod utils;

pub use service::DesktopAgentService;
pub use types::{
    AgentMode, AgentState, AgentStatus, ResumeAgentParams, StartAgentParams, StepAgentParams,
};
