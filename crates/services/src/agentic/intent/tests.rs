use super::{decode_session_id_hex_compat, parse_prefixed_agent_start};
use crate::agentic::runtime::AgentMode;

#[test]
fn session_id_32_bytes_is_preserved() {
    let input = "ab".repeat(32);
    let parsed = decode_session_id_hex_compat(&input).expect("must decode");
    assert_eq!(hex::encode(parsed), input);
}

#[test]
fn session_id_16_bytes_is_zero_extended() {
    let input = "cd".repeat(16);
    let parsed = decode_session_id_hex_compat(&input).expect("must decode");
    assert_eq!(hex::encode(&parsed[..16]), input);
    assert_eq!(parsed[16..], [0u8; 16]);
}

#[test]
fn invalid_session_id_returns_none() {
    assert!(decode_session_id_hex_compat("xyz").is_none());
    assert!(decode_session_id_hex_compat(&"aa".repeat(15)).is_none());
}

#[test]
fn prefixed_agent_start_preserves_multiline_goal() {
    let sid = "ab".repeat(32);
    let prompt = format!(
        "SESSION:{} I'm testing privacy pruning.\nPlease summarize this note:\nLine 2 with key=value",
        sid
    );
    let (session_id, mode, goal) =
        parse_prefixed_agent_start(&prompt).expect("must parse prefixed prompt");
    assert_eq!(hex::encode(session_id), sid);
    assert_eq!(mode, AgentMode::Agent);
    assert_eq!(
        goal,
        "I'm testing privacy pruning.\nPlease summarize this note:\nLine 2 with key=value"
    );
}

#[test]
fn prefixed_agent_start_supports_chat_mode_prefix() {
    let sid = "cd".repeat(32);
    let prompt = format!("MODE:CHAT SESSION:{} draft reply", sid);
    let (session_id, mode, goal) =
        parse_prefixed_agent_start(&prompt).expect("must parse prefixed prompt");
    assert_eq!(hex::encode(session_id), sid);
    assert_eq!(mode, AgentMode::Chat);
    assert_eq!(goal, "draft reply");
}

#[test]
fn prefixed_agent_start_requires_session_prefix() {
    assert!(parse_prefixed_agent_start("hello world").is_none());
}
