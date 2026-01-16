pub const AGENT_STATE_PREFIX: &[u8] = b"agent::state::";
pub const SKILL_INDEX_PREFIX: &[u8] = b"skills::vector::";
pub const TRACE_PREFIX: &[u8] = b"agent::trace::";

pub fn get_state_key(session_id: &[u8; 32]) -> Vec<u8> {
    [AGENT_STATE_PREFIX, session_id.as_slice()].concat()
}

pub fn get_trace_key(session_id: &[u8; 32], step: u32) -> Vec<u8> {
    [TRACE_PREFIX, session_id.as_slice(), &step.to_le_bytes()].concat()
}