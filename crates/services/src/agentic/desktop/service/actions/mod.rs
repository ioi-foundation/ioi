// Path: crates/services/src/agentic/desktop/service/actions/mod.rs

pub mod checks;
pub mod evaluation;
pub mod resume;

// Re-export canonical runtime entrypoints.
pub use crate::agentic::desktop::service::step::action::process_tool_output;
pub use resume::resume_pending_action;
// Exporting helpers if needed elsewhere
pub use checks::safe_truncate;
pub use evaluation::evaluate_and_crystallize;
