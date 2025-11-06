// Path: crates/ioi-ipc/src/jsonrpc.rs
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum JsonRpcId {
    Num(i64),
    Str(String),
    Null, // Required for spec compliance on parse/invalid request errors
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcRequest {
    pub jsonrpc: String, // Must be "2.0"
    pub method: String,
    #[serde(default = "default_params")]
    pub params: serde_json::Value, // Treat missing/null as {}
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<JsonRpcId>, // If None, it's a notification
}

// Helper to ensure missing or null params are treated as an empty JSON object.
fn default_params() -> serde_json::Value {
    serde_json::Value::Object(Default::default())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcResponse<T = serde_json::Value> {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: JsonRpcId,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}
