use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ioi_types::config::{
    McpConfigEntry, McpContainmentMode, McpMode, McpServerTier, WorkloadConfig,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
pub struct McpArgs {
    /// Path to workload.toml.
    #[clap(long, default_value = "workload.toml")]
    pub workload: PathBuf,

    /// Emit machine-readable JSON.
    #[clap(long)]
    pub json: bool,

    #[clap(subcommand)]
    pub command: McpCommands,
}

#[derive(Subcommand, Debug)]
pub enum McpCommands {
    /// List configured MCP servers and containment posture.
    List,
    /// Inspect one configured MCP server.
    Inspect { server: String },
    /// Show declared MCP tool allowlists.
    Tools { server: String },
    /// Show receipt expectations for configured MCP servers.
    Receipts { server: Option<String> },
    /// Run static containment and production-readiness checks.
    Test { server: Option<String> },
    /// Explain live shutdown semantics for an MCP server.
    Kill { server: String },
}

#[derive(Debug, Serialize)]
struct McpServerSummary {
    name: String,
    command: String,
    tier: String,
    source: String,
    containment_mode: String,
    allow_network_egress: bool,
    allow_child_processes: bool,
    workspace_root: Option<String>,
    declared_allowed_tools: usize,
}

#[derive(Debug, Serialize)]
struct McpInspection {
    name: String,
    command: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    tier: String,
    source: String,
    integrity_version: Option<String>,
    integrity_sha256: Option<String>,
    containment_mode: String,
    allow_network_egress: bool,
    allow_child_processes: bool,
    workspace_root: Option<String>,
    allowed_tools: Vec<String>,
}

#[derive(Debug, Serialize)]
struct McpStaticCheck {
    server: String,
    code: String,
    severity: String,
    message: String,
}

pub fn run(args: McpArgs) -> Result<()> {
    let workload = read_workload(&args.workload)?;
    match args.command {
        McpCommands::List => print_list(&workload, args.json),
        McpCommands::Inspect { server } => print_inspect(&workload, &server, args.json),
        McpCommands::Tools { server } => print_tools(&workload, &server, args.json),
        McpCommands::Receipts { server } => print_receipts(&workload, server.as_deref(), args.json),
        McpCommands::Test { server } => print_static_test(&workload, server.as_deref(), args.json),
        McpCommands::Kill { server } => print_kill_explanation(&workload, &server, args.json),
    }
}

fn read_workload(path: &Path) -> Result<WorkloadConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read workload config at {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

fn print_list(workload: &WorkloadConfig, json: bool) -> Result<()> {
    let mut servers = workload
        .mcp_servers
        .iter()
        .map(|(name, config)| server_summary(name, config))
        .collect::<Vec<_>>();
    servers.sort_by(|left, right| left.name.cmp(&right.name));
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpMode": format!("{:?}", workload.mcp_mode),
                "servers": servers,
            }))?
        );
    } else if servers.is_empty() {
        println!("MCP mode: {:?}", workload.mcp_mode);
        println!("No MCP servers are configured.");
    } else {
        println!("MCP mode: {:?}", workload.mcp_mode);
        for server in servers {
            println!(
                "- {}: command={} tier={} containment={} allowed_tools={}",
                server.name,
                server.command,
                server.tier,
                server.containment_mode,
                server.declared_allowed_tools
            );
        }
    }
    Ok(())
}

fn print_inspect(workload: &WorkloadConfig, server: &str, json: bool) -> Result<()> {
    let config = server_config(workload, server)?;
    let inspection = server_inspection(server, config);
    if json {
        println!("{}", serde_json::to_string_pretty(&inspection)?);
    } else {
        println!("MCP server: {}", inspection.name);
        println!("  command: {}", inspection.command);
        println!("  args: {}", inspection.args.join(" "));
        println!("  tier: {}", inspection.tier);
        println!("  source: {}", inspection.source);
        println!("  containment: {}", inspection.containment_mode);
        println!("  network egress: {}", inspection.allow_network_egress);
        println!("  child processes: {}", inspection.allow_child_processes);
        println!(
            "  workspace root: {}",
            inspection.workspace_root.as_deref().unwrap_or("<none>")
        );
        println!("  env vars: {}", inspection.env.len());
        println!("  allowed tools: {}", inspection.allowed_tools.len());
    }
    Ok(())
}

fn print_tools(workload: &WorkloadConfig, server: &str, json: bool) -> Result<()> {
    let config = server_config(workload, server)?;
    let namespaced = config
        .allowed_tools
        .iter()
        .map(|tool| format!("{server}__{tool}"))
        .collect::<Vec<_>>();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "server": server,
                "declaredAllowedTools": config.allowed_tools,
                "namespacedTools": namespaced,
                "runtimeDiscoveryRequired": config.allowed_tools.is_empty(),
            }))?
        );
    } else if config.allowed_tools.is_empty() {
        println!(
            "MCP server '{server}' has no declared allowed_tools; runtime discovery receipts are required before tool exposure."
        );
    } else {
        for tool in namespaced {
            println!("{tool}");
        }
    }
    Ok(())
}

fn print_receipts(workload: &WorkloadConfig, server: Option<&str>, json: bool) -> Result<()> {
    let selected = selected_servers(workload, server)?;
    let receipts = selected
        .iter()
        .map(|(name, config)| {
            serde_json::json!({
                "server": name,
                "receiptKind": "mcp_server_receipt",
                "runtimeEmitter": "McpManager::start_server",
                "contains": [
                    "server_name",
                    "command_path",
                    "command_sha256",
                    "declared_version",
                    "tier",
                    "source",
                    "mode",
                    "started_at_ms",
                    "tools"
                ],
                "configuredAllowedTools": config.allowed_tools,
            })
        })
        .collect::<Vec<_>>();
    if json {
        println!("{}", serde_json::to_string_pretty(&receipts)?);
    } else {
        for receipt in receipts {
            println!(
                "{} -> emitted by {}",
                receipt["server"].as_str().unwrap_or("<unknown>"),
                receipt["runtimeEmitter"].as_str().unwrap_or("<unknown>")
            );
        }
    }
    Ok(())
}

fn print_static_test(workload: &WorkloadConfig, server: Option<&str>, json: bool) -> Result<()> {
    let selected = selected_servers(workload, server)?;
    let checks = selected
        .iter()
        .flat_map(|(name, config)| static_checks_for_server(workload.mcp_mode, name, config))
        .collect::<Vec<_>>();
    let ok = checks.iter().all(|check| check.severity != "error");
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": ok,
                "mcpMode": format!("{:?}", workload.mcp_mode),
                "checks": checks,
            }))?
        );
    } else if checks.is_empty() {
        println!("MCP static checks passed.");
    } else {
        for check in &checks {
            println!(
                "[{}] {} {}: {}",
                check.severity, check.server, check.code, check.message
            );
        }
    }
    if ok {
        Ok(())
    } else {
        Err(anyhow!("MCP static checks failed"))
    }
}

fn print_kill_explanation(workload: &WorkloadConfig, server: &str, json: bool) -> Result<()> {
    let _ = server_config(workload, server)?;
    let message = "No live MCP manager endpoint is configured for this CLI invocation; runtime-spawned MCP processes use kill_on_drop and are stopped by the owning runtime service.";
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "server": server,
                "signaled": false,
                "reason": message,
            }))?
        );
    } else {
        println!("MCP server '{server}' was not signaled.");
        println!("{message}");
    }
    Ok(())
}

fn server_config<'a>(workload: &'a WorkloadConfig, server: &str) -> Result<&'a McpConfigEntry> {
    workload
        .mcp_servers
        .get(server)
        .ok_or_else(|| anyhow!("MCP server '{}' is not configured", server))
}

fn selected_servers<'a>(
    workload: &'a WorkloadConfig,
    server: Option<&str>,
) -> Result<Vec<(&'a String, &'a McpConfigEntry)>> {
    if let Some(server) = server {
        let config = server_config(workload, server)?;
        if let Some((name, _)) = workload.mcp_servers.get_key_value(server) {
            Ok(vec![(name, config)])
        } else {
            Err(anyhow!("MCP server '{}' is not configured", server))
        }
    } else {
        Ok(workload.mcp_servers.iter().collect())
    }
}

fn server_summary(name: &str, config: &McpConfigEntry) -> McpServerSummary {
    McpServerSummary {
        name: name.to_string(),
        command: config.command.clone(),
        tier: format!("{:?}", config.tier),
        source: format!("{:?}", config.source),
        containment_mode: format!("{:?}", config.containment.mode),
        allow_network_egress: config.containment.allow_network_egress,
        allow_child_processes: config.containment.allow_child_processes,
        workspace_root: config.containment.workspace_root.clone(),
        declared_allowed_tools: config.allowed_tools.len(),
    }
}

fn server_inspection(name: &str, config: &McpConfigEntry) -> McpInspection {
    McpInspection {
        name: name.to_string(),
        command: config.command.clone(),
        args: config.args.clone(),
        env: config
            .env
            .iter()
            .map(|(key, value)| (key.clone(), redact_env_value(key, value)))
            .collect(),
        tier: format!("{:?}", config.tier),
        source: format!("{:?}", config.source),
        integrity_version: config.integrity.version.clone(),
        integrity_sha256: config.integrity.sha256.clone(),
        containment_mode: format!("{:?}", config.containment.mode),
        allow_network_egress: config.containment.allow_network_egress,
        allow_child_processes: config.containment.allow_child_processes,
        workspace_root: config.containment.workspace_root.clone(),
        allowed_tools: config.allowed_tools.clone(),
    }
}

fn static_checks_for_server(
    mode: McpMode,
    name: &str,
    config: &McpConfigEntry,
) -> Vec<McpStaticCheck> {
    let mut checks = Vec::new();
    if config.command.trim().is_empty() {
        checks.push(check(name, "empty_command", "error", "command is empty"));
    }
    if config
        .allowed_tools
        .iter()
        .any(|tool| tool.trim().is_empty())
    {
        checks.push(check(
            name,
            "empty_allowed_tool",
            "error",
            "allowed_tools contains an empty entry",
        ));
    }
    if mode == McpMode::Production {
        if config.tier == McpServerTier::Unverified {
            checks.push(check(
                name,
                "unverified_production_server",
                "error",
                "production MCP rejects unverified servers",
            ));
        }
        if config.containment.mode != McpContainmentMode::Strict {
            checks.push(check(
                name,
                "production_requires_strict_containment",
                "error",
                "production MCP requires strict containment",
            ));
        }
        if config.allowed_tools.is_empty() {
            checks.push(check(
                name,
                "production_requires_tool_allowlist",
                "error",
                "production MCP requires explicit allowed_tools",
            ));
        }
        if config.containment.allow_network_egress {
            checks.push(check(
                name,
                "network_egress_enabled",
                "warning",
                "network egress should be disabled unless explicitly justified",
            ));
        }
    }
    checks
}

fn check(server: &str, code: &str, severity: &str, message: &str) -> McpStaticCheck {
    McpStaticCheck {
        server: server.to_string(),
        code: code.to_string(),
        severity: severity.to_string(),
        message: message.to_string(),
    }
}

fn redact_env_value(key: &str, value: &str) -> String {
    let normalized = key.to_ascii_lowercase();
    if normalized.contains("key")
        || normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("password")
    {
        "<redacted>".to_string()
    } else if value.is_empty() {
        String::new()
    } else {
        "<configured>".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::config::{
        CommitmentSchemeType, ConsensusType, InferenceConfig, McpContainmentConfig,
        McpIntegrityConfig, McpServerSource, StateTreeType, VmFuelCosts, ZkConfig,
    };
    use std::collections::HashMap;

    fn workload(mode: McpMode, server: McpConfigEntry) -> WorkloadConfig {
        WorkloadConfig {
            runtimes: vec!["wasm".to_string()],
            state_tree: StateTreeType::IAVL,
            commitment_scheme: CommitmentSchemeType::Hash,
            consensus_type: ConsensusType::Aft,
            genesis_file: "./genesis.json".to_string(),
            state_file: "./data/state.db".to_string(),
            srs_file_path: None,
            fuel_costs: VmFuelCosts::default(),
            initial_services: Vec::new(),
            service_policies: ioi_types::config::default_service_policies(),
            min_finality_depth: 100,
            keep_recent_heights: 10_000,
            epoch_size: 5000,
            gc_interval_secs: 3600,
            zk_config: ZkConfig::default(),
            inference: InferenceConfig::default(),
            fast_inference: None,
            reasoning_inference: None,
            connectors: HashMap::new(),
            mcp_servers: HashMap::from([("filesystem_dev".to_string(), server)]),
            mcp_mode: mode,
        }
    }

    fn server(
        tier: McpServerTier,
        containment_mode: McpContainmentMode,
        allowed_tools: Vec<String>,
    ) -> McpConfigEntry {
        McpConfigEntry {
            command: "npx".to_string(),
            args: vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem".to_string(),
            ],
            env: HashMap::from([("API_TOKEN".to_string(), "secret".to_string())]),
            tier,
            source: McpServerSource::PackageManager,
            integrity: McpIntegrityConfig::default(),
            containment: McpContainmentConfig {
                mode: containment_mode,
                allow_network_egress: false,
                allow_child_processes: false,
                workspace_root: Some("./".to_string()),
            },
            allowed_tools,
        }
    }

    #[test]
    fn production_static_checks_reject_unverified_unconfined_servers() {
        let workload = workload(
            McpMode::Production,
            server(
                McpServerTier::Unverified,
                McpContainmentMode::DeveloperUnconfined,
                Vec::new(),
            ),
        );
        let checks = static_checks_for_server(
            workload.mcp_mode,
            "filesystem_dev",
            workload
                .mcp_servers
                .get("filesystem_dev")
                .expect("server exists"),
        );
        assert!(checks
            .iter()
            .any(|check| check.code == "unverified_production_server"));
        assert!(checks
            .iter()
            .any(|check| check.code == "production_requires_strict_containment"));
        assert!(checks
            .iter()
            .any(|check| check.code == "production_requires_tool_allowlist"));
    }

    #[test]
    fn inspection_redacts_secret_environment_values() {
        let config = server(
            McpServerTier::Verified,
            McpContainmentMode::Strict,
            vec!["read_file".to_string()],
        );
        let inspection = server_inspection("filesystem_dev", &config);
        assert_eq!(
            inspection.env.get("API_TOKEN").map(String::as_str),
            Some("<redacted>")
        );
    }
}
