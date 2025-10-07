// Path: crates/client/src/workload_client/actor.rs

use crate::security::SecurityChannel;
use anyhow::Result;
use ipc_protocol::jsonrpc::{JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, RwLock};

/// A request sent from the main client handle to the actor task.
pub struct ClientRequest {
    pub request: JsonRpcRequest,
    /// The channel to send the response back to the waiting caller.
    pub response_tx: oneshot::Sender<Result<serde_json::Value, JsonRpcError>>,
}

/// The actor that manages the single mTLS connection.
pub struct ClientActor {
    channel: SecurityChannel,
    /// Receives requests from all `WorkloadClient` handles.
    from_client: mpsc::Receiver<ClientRequest>,
    /// Maps request IDs to the `oneshot` sender waiting for the response.
    pending:
        Arc<RwLock<HashMap<JsonRpcId, oneshot::Sender<Result<serde_json::Value, JsonRpcError>>>>>,
}

impl ClientActor {
    pub fn new(channel: SecurityChannel, from_client: mpsc::Receiver<ClientRequest>) -> Self {
        Self {
            channel,
            from_client,
            pending: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// The main I/O loop for the client.
    /// This method spawns two tasks: one for writing requests and one for reading responses,
    /// allowing for fully concurrent, multiplexed communication over the single connection.
    pub async fn run(mut self) {
        let stream = match self.channel.take_stream().await {
            Some(s) => s,
            None => {
                log::error!("[WorkloadClientActor] Failed to take ownership of the secure stream. Actor cannot run.");
                return;
            }
        };

        let (mut read_half, mut write_half) = tokio::io::split(stream);

        // --- Write Task ---
        // This task listens for requests from client handles and writes them to the socket.
        let pending_write = self.pending.clone();
        let mut from_client_rx = self.from_client;
        let write_task = tokio::spawn(async move {
            while let Some(req) = from_client_rx.recv().await {
                if let Some(id) = req.request.id.clone() {
                    let req_bytes = match serde_json::to_vec(&req.request) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            log::error!("[WorkloadClientActor] Failed to serialize request: {}", e);
                            continue;
                        }
                    };

                    // Insert the pending response sender *before* sending the request.
                    pending_write.write().await.insert(id, req.response_tx);

                    // Frame the message with a 4-byte length prefix.
                    if write_half.write_u32(req_bytes.len() as u32).await.is_err()
                        || write_half.write_all(&req_bytes).await.is_err()
                    {
                        log::error!("[WorkloadClientActor] Failed to write request to stream. Closing write task.");
                        break;
                    }
                }
            }
        });

        // --- Read Task ---
        // This task continuously reads from the socket and dispatches responses.
        let pending_read = self.pending.clone();
        let read_task = tokio::spawn(async move {
            loop {
                // Read the 4-byte length prefix.
                let len = match read_half.read_u32().await {
                    Ok(l) => l,
                    Err(_) => {
                        log::error!("[WorkloadClientActor] Failed to read response length. Closing read task.");
                        break;
                    }
                };

                let mut buf = vec![0; len as usize];
                if read_half.read_exact(&mut buf).await.is_err() {
                    log::error!(
                        "[WorkloadClientActor] Failed to read response body. Closing read task."
                    );
                    break;
                }

                let response: JsonRpcResponse = match serde_json::from_slice(&buf) {
                    Ok(res) => res,
                    Err(e) => {
                        log::error!("[WorkloadClientActor] Failed to parse response: {}", e);
                        continue;
                    }
                };

                // Find the pending request and send the response back.
                if let Some(response_tx) = pending_read.write().await.remove(&response.id) {
                    let result = match (response.result, response.error) {
                        (Some(r), None) => Ok(r),
                        (None, Some(e)) => Err(e),
                        _ => Err(JsonRpcError {
                            code: -32000,
                            message: "Invalid JSON-RPC response from server".into(),
                            data: None,
                        }),
                    };
                    if response_tx.send(result).is_err() {
                        log::warn!("[WorkloadClientActor] Receiver for request {:?} was dropped before response arrived.", response.id);
                    }
                } else {
                    log::warn!(
                        "[WorkloadClientActor] Received response for unknown request ID: {:?}",
                        response.id
                    );
                }
            }
        });

        // Wait for either task to finish (which indicates a connection error).
        tokio::select! {
            _ = write_task => {},
            _ = read_task => {},
        }

        // If the loop breaks (e.g., connection lost), notify all pending callers.
        let mut pending = self.pending.write().await;
        for (_id, response_tx) in pending.drain() {
            let _ = response_tx.send(Err(JsonRpcError {
                code: -32001,
                message: "Connection to Workload container was lost".into(),
                data: None,
            }));
        }
        log::info!("[WorkloadClientActor] I/O loop terminated.");
    }
}
