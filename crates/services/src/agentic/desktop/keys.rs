// Path: crates/services/src/agentic/desktop/keys.rs

pub const AGENT_STATE_PREFIX: &[u8] = b"agent::state::";
pub const SKILL_INDEX_PREFIX: &[u8] = b"skills::vector::";
pub const TRACE_PREFIX: &[u8] = b"agent::trace::";
pub const AGENT_POLICY_PREFIX: &[u8] = b"agent::policy::";
// [NEW] Prefix for mutable skill statistics
pub const SKILL_STATS_PREFIX: &[u8] = b"skills::stats::";
// [NEW] Prefix for the latest mutation receipt pointer for a session.
pub const MUTATION_RECEIPT_PTR_PREFIX: &[u8] = b"agent::mutation_receipt_ptr::";
pub const REMEDIATION_PREFIX: &[u8] = b"agent::remediation::";
pub const INCIDENT_PREFIX: &[u8] = b"agent::incident::";

// [NEW] Prefix for storing results of completed child sessions
// Key: session::result::{child_session_id}
pub const SESSION_RESULT_PREFIX: &[u8] = b"session::result::";

pub mod pii {
    pub mod review {
        pub const REQUEST_PREFIX: &[u8] = b"pii::review::request::";
        pub const EXCEPTION_USAGE_PREFIX: &[u8] = b"pii::review::exception_usage::";

        pub fn request(decision_hash: &[u8; 32]) -> Vec<u8> {
            [REQUEST_PREFIX, decision_hash.as_slice()].concat()
        }

        pub fn exception_usage(exception_id: &str) -> Vec<u8> {
            [EXCEPTION_USAGE_PREFIX, exception_id.as_bytes()].concat()
        }
    }
}

pub fn get_state_key(session_id: &[u8; 32]) -> Vec<u8> {
    [AGENT_STATE_PREFIX, session_id.as_slice()].concat()
}

pub fn get_trace_key(session_id: &[u8; 32], step: u32) -> Vec<u8> {
    [TRACE_PREFIX, session_id.as_slice(), &step.to_le_bytes()].concat()
}

pub fn get_skill_stats_key(skill_hash: &[u8; 32]) -> Vec<u8> {
    [SKILL_STATS_PREFIX, skill_hash.as_slice()].concat()
}

pub fn get_session_result_key(session_id: &[u8; 32]) -> Vec<u8> {
    [SESSION_RESULT_PREFIX, session_id.as_slice()].concat()
}

pub fn get_mutation_receipt_ptr_key(session_id: &[u8; 32]) -> Vec<u8> {
    [MUTATION_RECEIPT_PTR_PREFIX, session_id.as_slice()].concat()
}

pub fn get_remediation_key(session_id: &[u8; 32]) -> Vec<u8> {
    [REMEDIATION_PREFIX, session_id.as_slice()].concat()
}

pub fn get_incident_key(session_id: &[u8; 32]) -> Vec<u8> {
    [INCIDENT_PREFIX, session_id.as_slice()].concat()
}
