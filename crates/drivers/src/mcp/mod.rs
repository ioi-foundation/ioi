pub mod protocol;
pub mod transport;

use anyhow::{anyhow, Result};
use ioi_types::app::agentic::LlmToolDefinition;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

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
}

impl McpManager {
    pub fn new() -> Self {
        Self {
            servers: RwLock::new(HashMap::new()),
            tool_routing_table: RwLock::new(HashMap::new()),
        }
    }

    /// Spawns a new MCP server and performs the initialization handshake.
    pub async fn start_server(&self, name: &str, config: McpServerConfig) -> Result<()> {
        log::info!("Starting MCP Server '{}': {} {:?}", name, config.command, config.args);
        
        let transport = McpTransport::spawn(
            config.command,
            config.args,
            config.env
        ).await?;

        // 1. Initialize Handshake (Client -> Server)
        transport.initialize().await?;

        // 2. List Tools (Server -> Client)
        let tools = transport.list_tools().await?;
        
        // 3. Update Routing Table
        let mut table = self.tool_routing_table.write().await;
        for tool in tools {
            // Namespace the tool: "server_name__tool_name"
            // This prevents collision between "stripe::get" and "aws::get"
            let namespaced_name = format!("{}__{}", name, tool.name);
            table.insert(namespaced_name.clone(), name.to_string());
            log::debug!("Registered MCP Tool: {}", namespaced_name);
        }

        let mut servers = self.servers.write().await;
        servers.insert(name.to_string(), Arc::new(transport));

        Ok(())
    }

    /// Discovers all tools exposed by connected MCP servers.
    /// This is aggregated into the System Prompt for the AI.
    pub async fn get_all_tools(&self) -> Vec<LlmToolDefinition> {
        let servers = self.servers.read().await;
        let mut definitions = Vec::new();

        for (server_name, transport) in servers.iter() {
            if let Ok(tools) = transport.list_tools().await {
                for tool in tools {
                    let namespaced_name = format!("{}__{}", server_name, tool.name);
                    definitions.push(LlmToolDefinition {
                        name: namespaced_name,
                        description: tool.description.unwrap_or_default(),
                        parameters: tool.input_schema.to_string(), // Raw JSON schema string
                    });
                }
            }
        }
        definitions
    }

    /// Routes a tool execution request to the correct underlying process.
    pub async fn execute_tool(&self, namespaced_tool: &str, args: Value) -> Result<String> {
        let table = self.tool_routing_table.read().await;
        
        // 1. Resolve Server
        let server_name = table.get(namespaced_tool)
            .ok_or_else(|| anyhow!("Tool '{}' not found in any active MCP server", namespaced_tool))?;

        // 2. Extract Raw Tool Name (remove prefix)
        // "stripe__refund" -> "refund"
        let raw_tool_name = namespaced_tool.strip_prefix(&format!("{}__{}", server_name, ""))
            .unwrap_or(namespaced_tool); // Should logically handle split, fallback for safety

        let servers = self.servers.read().await;
        let transport = servers.get(server_name)
            .ok_or_else(|| anyhow!("MCP Server '{}' is dead or disconnected", server_name))?;

        // 3. Execute via Stdio
        let result_json = transport.call_tool(raw_tool_name, args).await?;
        
        // 4. Return result content (extract from MCP "content" array)
        Ok(result_json.to_string())
    }
}