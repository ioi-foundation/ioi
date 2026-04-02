// Path: crates/services/src/agentic/desktop/service/lifecycle/mod.rs

mod compaction;
mod delegation;
mod handlers;
mod parent_playbook_receipts;
mod runtime_locality;
mod sudo;
mod worker_results;

pub use compaction::perform_cognitive_compaction;
pub use delegation::spawn_delegated_child_session;
pub use handlers::{handle_delete_session, handle_post_message, handle_resume, handle_start};
pub(crate) use runtime_locality::maybe_seed_runtime_locality_context;
pub(crate) use worker_results::{
    await_child_worker_result, load_worker_assignment, persist_worker_assignment,
    register_parent_playbook_step_spawn, resolve_worker_assignment,
};
