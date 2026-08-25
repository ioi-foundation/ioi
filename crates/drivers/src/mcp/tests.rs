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

#[tokio::test(flavor = "current_thread")]
async fn stop_server_removes_live_routes_and_admission_cache() {
    let manager = McpManager::new();
    let fixture = std::fs::canonicalize(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/fixtures/mcp-stdio-echo-server.mjs"),
    )
    .expect("canonical fixture MCP server");
    manager
        .start_server(
            "fixture_stop",
            McpMode::Development,
            McpServerConfig {
                command: "node".to_string(),
                args: vec![fixture.to_string_lossy().to_string()],
                env: HashMap::new(),
                tier: McpServerTier::Unverified,
                source: McpServerSource::LocalBin,
                integrity: McpIntegrityConfig::default(),
                containment: McpContainmentConfig {
                    mode: McpContainmentMode::DeveloperUnconfined,
                    ..McpContainmentConfig::default()
                },
                allowed_tools: vec!["query".to_string()],
            },
        )
        .await
        .expect("start fixture MCP server");
    assert_eq!(manager.get_all_tools().await.len(), 1);
    assert_eq!(manager.get_server_receipts().await.len(), 1);

    assert!(manager
        .stop_server("fixture_stop")
        .await
        .expect("stop fixture MCP server"));
    assert!(manager.get_all_tools().await.is_empty());
    assert!(manager.get_server_receipts().await.is_empty());
    assert!(!manager
        .stop_server("fixture_stop")
        .await
        .expect("idempotent stop"));

    let mut spec = mcp_spec(0, u64::MAX);
    spec.capability_lease
        .as_mut()
        .expect("capability lease")
        .capability_allowlist = vec!["fixture_stop__query".to_string()];
    let error = manager
        .execute_tool_with_spec(
            "fixture_stop__query",
            serde_json::json!({ "q": "after-stop" }),
            Some(&spec),
        )
        .await
        .expect_err("stopped server must not remain routable");
    assert!(format!("{error:#}").contains("not found in any active MCP server"));
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
