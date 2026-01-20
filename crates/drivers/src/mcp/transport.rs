// Path: crates/drivers/src/mcp/transport.rs

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
// [FIX] Removed unused Child
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};

/// Handles the JSON-RPC 2.0 communication over Stdio.
pub struct McpTransport {
    request_id: AtomicU64,
    tx_sender: mpsc::Sender<Value>, // Send requests to the write loop
    // [FIX] Added explicit type annotation for the pending map
    pending_requests: std::sync::Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>>,
}

impl McpTransport {
    pub async fn spawn(cmd: String, args: Vec<String>, env: HashMap<String, String>) -> Result<Self> {
        let mut child = Command::new(cmd)
            .args(args)
            .envs(env) // SECURE ENCLAVE: Keys injected here!
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()) // Redirect stderr to parent for debugging
            .spawn()?;

        let stdin = child.stdin.take().ok_or(anyhow!("Failed to open stdin"))?;
        let stdout = child.stdout.take().ok_or(anyhow!("Failed to open stdout"))?;

        let (tx, mut rx) = mpsc::channel::<Value>(32);
        
        // [FIX] Explicitly specify the generic types for HashMap
        let pending: std::sync::Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>> = 
            std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
        let pending_clone = pending.clone();

        // 1. Write Loop (Kernel -> MCP)
        tokio::spawn(async move {
            let mut writer = stdin;
            while let Some(msg) = rx.recv().await {
                let json_str = msg.to_string();
                if let Err(e) = writer.write_all(format!("{}\n", json_str).as_bytes()).await {
                    log::error!("MCP Write Error: {}", e);
                    break;
                }
            }
        });

        // 2. Read Loop (MCP -> Kernel)
        tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            
            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(json) = serde_json::from_str::<Value>(&line) {
                    // Check if it's a response (has ID)
                    if let Some(id) = json.get("id").and_then(|i| i.as_u64()) {
                        let mut map = pending_clone.lock().unwrap();
                        if let Some(sender) = map.remove(&id) {
                            // Extract result or error
                            if let Some(err) = json.get("error") {
                                let _ = sender.send(Err(anyhow!("MCP Error: {}", err)));
                            } else if let Some(res) = json.get("result") {
                                let _ = sender.send(Ok(res.clone()));
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            request_id: AtomicU64::new(0),
            tx_sender: tx,
            pending_requests: pending,
        })
    }

    async fn send_request(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();

        {
            let mut map = self.pending_requests.lock().unwrap();
            map.insert(id, tx);
        }

        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });

        self.tx_sender.send(req).await
            .map_err(|_| anyhow!("MCP Server crashed (channel closed)"))?;

        // Wait for response
        rx.await.map_err(|_| anyhow!("MCP Server dropped response"))?
    }

    pub async fn initialize(&self) -> Result<()> {
        let params = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "roots": { "listChanged": true } },
            "clientInfo": { "name": "ioi-kernel", "version": "0.1.0" }
        });
        self.send_request("initialize", params).await?;
        // Required notification after init
        let notify = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        self.tx_sender.send(notify).await?;
        Ok(())
    }

    pub async fn list_tools(&self) -> Result<Vec<McpToolInfo>> {
        let res = self.send_request("tools/list", json!({})).await?;
        // Parse `res["tools"]` into Vec<McpToolInfo>
        serde_json::from_value(res["tools"].clone()).map_err(|e| anyhow!(e))
    }

    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value> {
        let params = json!({
            "name": name,
            "arguments": arguments
        });
        self.send_request("tools/call", params).await
    }
}

#[derive(serde::Deserialize)]
pub struct McpToolInfo {
    pub name: String,
    pub description: Option<String>,
    // [FIX] Map JSON "inputSchema" to Rust "input_schema"
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}