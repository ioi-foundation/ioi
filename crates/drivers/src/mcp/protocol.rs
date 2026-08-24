// Path: crates/drivers/src/mcp/protocol.rs

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The one MCP wire revision this runtime currently admits for both stdio and
/// Streamable HTTP. Supporting another revision requires an explicit parser and
/// conformance fixture; transports must not silently negotiate divergent shapes.
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
pub const MCP_PROTOCOL_VERSION_HEADER: &str = "MCP-Protocol-Version";
pub const MCP_SESSION_ID_HEADER: &str = "Mcp-Session-Id";

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Option<Value>,
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct McpInitializeParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: Value,
    #[serde(rename = "clientInfo")]
    pub client_info: ClientInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

/// Information about a tool exposed by an MCP server.
/// (Redefined here for canonical usage, though transport.rs has a local version currently)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}
