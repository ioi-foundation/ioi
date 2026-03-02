// Path: crates/drivers/src/mcp/mod.rs

pub mod compression;
pub mod protocol;
pub mod transport; // [NEW] Register module

use anyhow::{anyhow, Result};
use ioi_types::app::agentic::LlmToolDefinition;
use ioi_types::app::{ActionTarget, RuntimeTarget, WorkloadSpec};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// [FIX] Removed unused McpToolInfo import
use self::transport::McpTransport;

/// Configuration for an external MCP server.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct McpServerConfig {
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
}

/// The Manager responsible for the lifecycle of all MCP child processes.
pub struct McpManager {
    /// Active connections to child processes, keyed by server name (e.g., "stripe", "filesystem").
    servers: RwLock<HashMap<String, Arc<McpTransport>>>,
    /// Flattened map of "tool_name" -> "server_name" for routing.
    /// e.g. "filesystem_read_file" -> "filesystem"
    tool_routing_table: RwLock<HashMap<String, String>>,
    /// Cache of tool definitions to prevent repeated IPC calls to child processes.
    tool_cache: RwLock<HashMap<String, Vec<LlmToolDefinition>>>,
}

impl McpManager {
    pub fn new() -> Self {
        Self {
            servers: RwLock::new(HashMap::new()),
            tool_routing_table: RwLock::new(HashMap::new()),
            tool_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Spawns a new MCP server and performs the initialization handshake.
    pub async fn start_server(&self, name: &str, config: McpServerConfig) -> Result<()> {
        log::info!(
            "Starting MCP Server '{}': {} {:?}",
            name,
            config.command,
            config.args
        );

        let transport = McpTransport::spawn(config.command, config.args, config.env).await?;

        // 1. Initialize Handshake (Client -> Server)
        transport.initialize().await?;

        // 2. List Tools (Server -> Client)
        // We do this ONCE at startup and cache the result.
        let tools = transport.list_tools().await?;

        // 3. Update Routing Table & Cache
        let mut table = self.tool_routing_table.write().await;
        let mut cache = self.tool_cache.write().await;

        let mut cached_definitions = Vec::new();

        for tool in tools {
            // Namespace the tool: "server_name__tool_name"
            // This prevents collision between "stripe::get" and "aws::get"
            let namespaced_name = format!("{}__{}", name, tool.name);
            table.insert(namespaced_name.clone(), name.to_string());

            cached_definitions.push(LlmToolDefinition {
                name: namespaced_name.clone(),
                description: tool.description.unwrap_or_default(),
                parameters: tool.input_schema.to_string(), // Raw JSON schema string
            });

            log::debug!("Registered MCP Tool: {}", namespaced_name);
        }

        cache.insert(name.to_string(), cached_definitions);

        let mut servers = self.servers.write().await;
        servers.insert(name.to_string(), Arc::new(transport));

        Ok(())
    }

    /// Discovers all tools exposed by connected MCP servers.
    /// This is aggregated into the System Prompt for the AI.
    ///
    /// OPTIMIZATION: Returns cached definitions instead of querying child processes.
    pub async fn get_all_tools(&self) -> Vec<LlmToolDefinition> {
        let cache = self.tool_cache.read().await;
        let mut all_tools = Vec::new();

        for tools in cache.values() {
            all_tools.extend(tools.clone());
        }

        all_tools
    }

    /// Routes a tool execution request to the correct underlying process.
    pub async fn execute_tool(&self, namespaced_tool: &str, args: Value) -> Result<String> {
        self.execute_tool_with_spec(namespaced_tool, args, None)
            .await
    }

    /// Routes a tool execution request to the correct underlying process with
    /// explicit workload substrate bindings.
    pub async fn execute_tool_with_spec(
        &self,
        namespaced_tool: &str,
        args: Value,
        workload_spec: Option<&WorkloadSpec>,
    ) -> Result<String> {
        let spec = workload_spec.ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=PolicyBlocked Missing WorkloadSpec for MCP tool '{}'",
                namespaced_tool
            )
        })?;
        if spec.runtime_target != RuntimeTarget::McpAdapter {
            return Err(anyhow!(
                "ERROR_CLASS=PolicyBlocked RuntimeTarget '{}' is invalid for MCP tool '{}'",
                spec.runtime_target.as_label(),
                namespaced_tool
            ));
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        let lease_check = spec.evaluate_lease(
            &ActionTarget::Custom(namespaced_tool.to_string()),
            None,
            now_ms,
        );
        if !lease_check.satisfied {
            return Err(anyhow!(
                "ERROR_CLASS=PolicyBlocked MCP lease validation failed for '{}': {}",
                namespaced_tool,
                lease_check
                    .reason
                    .unwrap_or_else(|| "unspecified_failure".to_string())
            ));
        }

        let table = self.tool_routing_table.read().await;

        // 1. Resolve Server
        let server_name = table.get(namespaced_tool).ok_or_else(|| {
            anyhow!(
                "Tool '{}' not found in any active MCP server",
                namespaced_tool
            )
        })?;

        // 2. Extract Raw Tool Name (remove prefix)
        // "stripe__refund" -> "refund"
        let prefix = format!("{}__{}", server_name, "");
        let raw_tool_name = namespaced_tool
            .strip_prefix(&prefix)
            .unwrap_or(namespaced_tool);

        let servers = self.servers.read().await;
        let transport = servers
            .get(server_name)
            .ok_or_else(|| anyhow!("MCP Server '{}' is dead or disconnected", server_name))?;

        // 3. Execute via Stdio
        let result_json = transport.call_tool(raw_tool_name, args).await?;

        // 4. Return result content (extract from MCP "content" array)
        Ok(result_json.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{CapabilityLease, CapabilityLeaseMode, NetMode};

    fn mcp_spec(issued_at_ms: u64, expires_at_ms: u64) -> WorkloadSpec {
        WorkloadSpec {
            runtime_target: RuntimeTarget::McpAdapter,
            net_mode: NetMode::Disabled,
            capability_lease: Some(CapabilityLease {
                lease_id: [9u8; 32],
                issued_at_ms,
                expires_at_ms,
                mode: CapabilityLeaseMode::OneShot,
                capability_allowlist: vec!["filesystem__read_file".to_string()],
                domain_allowlist: vec![],
            }),
            ui_surface: None,
        }
    }

    #[tokio::test]
    async fn execute_tool_requires_workload_spec() {
        let manager = McpManager::new();
        let err = manager
            .execute_tool_with_spec("filesystem__read_file", serde_json::json!({}), None)
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
            .execute_tool_with_spec("filesystem__read_file", serde_json::json!({}), Some(&spec))
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
            .execute_tool_with_spec("filesystem__read_file", serde_json::json!({}), Some(&spec))
            .await
            .expect_err("expired lease must fail");
        let rendered = format!("{:#}", err);
        assert!(rendered.contains("ERROR_CLASS=PolicyBlocked"));
        assert!(rendered.contains("capability_lease_expired"));
    }
}
