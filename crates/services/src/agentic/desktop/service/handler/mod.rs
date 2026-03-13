mod approvals;
mod execution;
mod focus;
mod pii;
mod wallet_mail;
mod web_research;

pub use execution::{handle_action_execution, select_runtime};
pub(crate) use execution::{resolve_window_binding_for_target, target_requires_window_binding};
pub(crate) use wallet_mail::try_execute_wallet_mail_dynamic_tool;
pub(crate) use web_research::{
    normalize_web_research_tool_call, reconcile_pending_web_research_tool_call,
};

pub(crate) use pii::{
    build_pii_review_request_for_tool, emit_pii_review_requested, persist_pii_review_request,
};
