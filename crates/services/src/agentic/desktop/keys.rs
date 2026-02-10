// Path: crates/services/src/agentic/desktop/keys.rs

pub const AGENT_STATE_PREFIX: &[u8] = b"agent::state::";
pub const SKILL_INDEX_PREFIX: &[u8] = b"skills::vector::";
pub const TRACE_PREFIX: &[u8] = b"agent::trace::";
pub const AGENT_POLICY_PREFIX: &[u8] = b"agent::policy::";
// [NEW] Prefix for mutable skill statistics
pub const SKILL_STATS_PREFIX: &[u8] = b"skills::stats::";

// [NEW] Prefix for storing results of completed child sessions
// Key: session::result::{child_session_id}
pub const SESSION_RESULT_PREFIX: &[u8] = b"session::result::";

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