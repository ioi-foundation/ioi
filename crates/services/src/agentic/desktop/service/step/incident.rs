// Path: crates/services/src/agentic/desktop/service/step/incident.rs

#[path = "incident/core.rs"]
mod core;
#[path = "incident/flow.rs"]
mod flow;
#[path = "incident/recovery.rs"]
mod recovery;
#[path = "incident/store.rs"]
mod store;

pub use core::{
    action_fingerprint_from_tool_jcs, ApprovalDirective, IncidentDirective, IncidentReceiptFields,
    IncidentState,
};
pub use flow::{
    advance_incident_after_action_outcome, emit_incident_chat_progress, incident_receipt_fields,
    mark_gate_approved, mark_gate_denied, mark_incident_retry_root, mark_incident_wait_for_user,
    register_pending_approval, should_enter_incident_recovery, start_or_continue_incident_recovery,
};
pub use store::{clear_incident_state, load_incident_state};

#[cfg(test)]
#[path = "incident/tests.rs"]
mod tests;
