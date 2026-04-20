use super::*;
use ioi_types::app::{CapabilityLease, CapabilityLeaseMode, NetMode};

fn mcp_spec(issued_at_ms: u64, expires_at_ms: u64) -> WorkloadSpec {
    WorkloadSpec {
        runtime_target: RuntimeTarget::Adapter,
        net_mode: NetMode::Disabled,
        capability_lease: Some(CapabilityLease {
            lease_id: [9u8; 32],
            issued_at_ms,
            expires_at_ms,
            mode: CapabilityLeaseMode::OneShot,
            capability_allowlist: vec!["echo_server__echo".to_string()],
            domain_allowlist: vec![],
        }),
        ui_surface: None,
    }
}

#[tokio::test]
async fn execute_tool_requires_workload_spec() {
    let manager = McpManager::new();
    let err = manager
        .execute_tool_with_spec("echo_server__echo", serde_json::json!({}), None)
        .await
        .expect_err("missing workload spec must fail");
    let rendered = format!("{:#}", err);
    assert!(rendered.contains("ERROR_CLASS=PolicyBlocked"));
    assert!(rendered.contains("Missing WorkloadSpec"));
}

#[tokio::test]
async fn execute_tool_rejects_wrong_runtime_target() {
    let manager = McpManager::new();
    let mut spec = mcp_spec(100, 1000);
    spec.runtime_target = RuntimeTarget::System;
    let err = manager
        .execute_tool_with_spec("echo_server__echo", serde_json::json!({}), Some(&spec))
        .await
        .expect_err("invalid runtime target must fail");
    let rendered = format!("{:#}", err);
    assert!(rendered.contains("ERROR_CLASS=PolicyBlocked"));
    assert!(rendered.contains("RuntimeTarget"));
}

#[tokio::test]
async fn execute_tool_rejects_expired_lease() {
    let manager = McpManager::new();
    let spec = mcp_spec(0, 1);
    let err = manager
        .execute_tool_with_spec("echo_server__echo", serde_json::json!({}), Some(&spec))
        .await
        .expect_err("expired lease must fail");
    let rendered = format!("{:#}", err);
    assert!(rendered.contains("ERROR_CLASS=PolicyBlocked"));
    assert!(rendered.contains("capability_lease_expired"));
}

#[test]
fn production_rejects_installer_command() {
    let cfg = McpServerConfig {
        command: "npx".to_string(),
        args: vec!["-y".to_string(), "@scope/server".to_string()],
        env: HashMap::new(),
        tier: McpServerTier::Verified,
        source: McpServerSource::PackageManager,
        integrity: McpIntegrityConfig {
            version: Some("1.0.0".to_string()),
            sha256: Some("a".repeat(64)),
            lockfile_sha256: None,
        },
        containment: McpContainmentConfig::default(),
        allowed_tools: vec!["echo".to_string()],
    };
    let err = validate_start_policy("demo", McpMode::Production, &cfg)
        .expect_err("installer command must fail");
    let rendered = format!("{:#}", err);
    assert!(rendered.contains("PolicyBlocked"));
}

#[test]
fn production_requires_allowed_tools() {
    let cfg = McpServerConfig {
        command: "/bin/echo".to_string(),
        args: vec!["ok".to_string()],
        env: HashMap::new(),
        tier: McpServerTier::Verified,
        source: McpServerSource::LocalBin,
        integrity: McpIntegrityConfig {
            version: Some("1.0.0".to_string()),
            sha256: Some("a".repeat(64)),
            lockfile_sha256: None,
        },
        containment: McpContainmentConfig::default(),
        allowed_tools: Vec::new(),
    };
    let err = validate_start_policy("demo", McpMode::Production, &cfg)
        .expect_err("production mode must require allowed_tools");
    let rendered = format!("{:#}", err);
    assert!(rendered.contains("allowed_tools"));
}

#[test]
fn path_scope_rejects_escape() {
    let root = tempfile::tempdir().expect("tempdir");
    let value = serde_json::json!({ "path": "/etc/passwd" });
    let err = enforce_json_path_scope(&value, root.path()).expect_err("escape must fail");
    let rendered = format!("{:#}", err);
    assert!(rendered.contains("PolicyBlocked"));
}
