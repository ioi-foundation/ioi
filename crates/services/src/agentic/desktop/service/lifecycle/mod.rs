// Path: crates/services/src/agentic/desktop/service/lifecycle/mod.rs

mod compaction;
mod delegation;
mod handlers;
mod runtime_locality;
mod sudo;

pub use compaction::perform_cognitive_compaction;
pub use delegation::spawn_delegated_child_session;
pub use handlers::{handle_delete_session, handle_post_message, handle_resume, handle_start};
