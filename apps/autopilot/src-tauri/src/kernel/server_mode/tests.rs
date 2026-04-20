use super::build_server_snapshot;
use crate::kernel::state::KernelRpcTarget;
use crate::models::SessionSummary;

fn summary(session_id: &str, title: &str, timestamp: u64) -> SessionSummary {
    SessionSummary {
        session_id: session_id.to_string(),
        title: title.to_string(),
        timestamp,
        phase: None,
        current_step: None,
        resume_hint: None,
        workspace_root: None,
    }
}

fn attachable_summary(
    session_id: &str,
    title: &str,
    timestamp: u64,
    workspace_root: &str,
) -> SessionSummary {
    SessionSummary {
        session_id: session_id.to_string(),
        title: title.to_string(),
        timestamp,
        phase: None,
        current_step: None,
        resume_hint: None,
        workspace_root: Some(workspace_root.to_string()),
    }
}

#[test]
fn remote_kernel_snapshot_surfaces_remote_only_history() {
    let local = vec![
        summary("local-1", "Local task", 10),
        summary("shared", "Shared", 8),
    ];
    let remote = vec![
        summary("shared", "Shared remote", 11),
        attachable_summary("remote-2", "Remote task", 12, "/srv/ioi/project"),
    ];
    let snapshot = build_server_snapshot(
        Some("remote-2".to_string()),
        Some("/tmp/workspace".to_string()),
        KernelRpcTarget {
            url: "https://kernel.example.com".to_string(),
            source_label: "AUTOPILOT_KERNEL_RPC_URL".to_string(),
            configured: true,
            remote_hint: true,
        },
        local,
        remote,
        None,
    );

    assert_eq!(snapshot.continuity_mode_label, "Explicit remote kernel");
    assert_eq!(snapshot.continuity_status_label, "Remote history merged");
    assert!(snapshot.kernel_reachable);
    assert_eq!(snapshot.remote_only_session_count, 1);
    assert_eq!(snapshot.overlapping_session_count, 1);
    assert!(snapshot.current_session_visible_remotely);
    assert_eq!(snapshot.remote_attachable_session_count, 1);
    assert_eq!(snapshot.remote_history_only_session_count, 1);
    assert_eq!(
        snapshot.current_session_continuity_label,
        "Current session mirrored remotely"
    );
    assert_eq!(
        snapshot.recent_remote_sessions[0].source_label,
        "Remote-only history"
    );
    assert_eq!(
        snapshot.recent_remote_sessions[0].presence_label,
        "Remote-only attachable"
    );
}

#[test]
fn unreachable_configured_kernel_surfaces_attention_state() {
    let snapshot = build_server_snapshot(
        None,
        None,
        KernelRpcTarget {
            url: "https://kernel.example.com".to_string(),
            source_label: "AUTOPILOT_KERNEL_RPC_URL".to_string(),
            configured: true,
            remote_hint: true,
        },
        vec![summary("local-1", "Local task", 10)],
        Vec::new(),
        Some("Session history RPC timed out after 1500ms".to_string()),
    );

    assert!(!snapshot.kernel_reachable);
    assert_eq!(
        snapshot.continuity_status_label,
        "Configured but unreachable"
    );
    assert!(snapshot
        .kernel_connection_detail
        .contains("Session history RPC timed out"));
}

#[test]
fn current_session_without_remote_history_is_marked_local_only() {
    let snapshot = build_server_snapshot(
        Some("local-1".to_string()),
        Some("/tmp/repo".to_string()),
        KernelRpcTarget {
            url: "https://kernel.example.com".to_string(),
            source_label: "AUTOPILOT_KERNEL_RPC_URL".to_string(),
            configured: true,
            remote_hint: true,
        },
        vec![attachable_summary("local-1", "Local task", 10, "/tmp/repo")],
        vec![summary("remote-2", "Remote task", 12)],
        None,
    );

    assert_eq!(snapshot.current_session_continuity_state, "local_only");
    assert_eq!(
        snapshot.current_session_continuity_label,
        "Current session local only"
    );
    assert!(!snapshot.current_session_visible_remotely);
}
