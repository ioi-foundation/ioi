// Path: crates/services/src/agentic/desktop/service/actions/mod.rs

pub mod checks;
pub mod evaluation;
pub mod resume;
pub mod process;

// Re-export main functions to match the previous API surface
pub use resume::resume_pending_action;
pub use process::process_tool_output;
// Exporting helpers if needed elsewhere
pub use evaluation::evaluate_and_crystallize;
pub use checks::safe_truncate;