// Path: crates/services/src/agentic/runtime/service/lifecycle/mod.rs

mod browser_subagent;
mod compaction;
mod delegation;
mod handlers;
mod parent_playbook_receipts;
mod runtime_locality;
mod sudo;
mod worker_results;

pub(crate) use browser_subagent::{browser_subagent_request_from_dynamic, run_browser_subagent};
pub use compaction::perform_cognitive_compaction;
pub use delegation::spawn_delegated_child_session;
pub use handlers::{
    handle_cancel, handle_delete_session, handle_deny, handle_pause, handle_post_message,
    handle_register_approval_authority, handle_resume, handle_revoke_approval_authority,
    handle_start,
};
pub(crate) use runtime_locality::maybe_seed_runtime_locality_context;
pub(crate) use worker_results::{
    await_child_worker_result, load_child_state, load_worker_assignment,
    parse_child_session_id_hex, persist_worker_assignment, register_parent_playbook_step_spawn,
    resolve_worker_assignment,
};
