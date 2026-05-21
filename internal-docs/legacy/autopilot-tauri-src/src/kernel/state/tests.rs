use super::{kernel_rpc_target_is_remote, normalize_kernel_history_message};

#[test]
fn rewrites_replied_tool_messages_into_agent_messages() {
    let message =
        normalize_kernel_history_message("tool".to_string(), "Replied: hello".to_string(), 42);
    assert_eq!(message.role, "agent");
    assert_eq!(message.text, "hello");
    assert_eq!(message.timestamp, 42);
}

#[test]
fn preserves_non_reply_tool_messages() {
    let message =
        normalize_kernel_history_message("tool".to_string(), "Opened artifact".to_string(), 7);
    assert_eq!(message.role, "tool");
    assert_eq!(message.text, "Opened artifact");
    assert_eq!(message.timestamp, 7);
}

#[test]
fn distinguishes_loopback_and_remote_kernel_targets() {
    assert!(!kernel_rpc_target_is_remote("http://127.0.0.1:9000"));
    assert!(!kernel_rpc_target_is_remote("http://[::1]:9000"));
    assert!(!kernel_rpc_target_is_remote("http://localhost:9000"));
    assert!(kernel_rpc_target_is_remote("https://kernel.example.com"));
    assert!(kernel_rpc_target_is_remote("http://192.168.1.10:9000"));
}
