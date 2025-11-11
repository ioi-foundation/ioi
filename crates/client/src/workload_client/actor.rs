// Path: crates/client/src/workload_client/actor.rs

use crate::security::SecureStream;
use ioi_ipc::jsonrpc::{JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, RwLock};

type ResponseResult = Result<serde_json::Value, JsonRpcError>;
type ResponseTx = oneshot::Sender<ResponseResult>;
pub(super) type PendingRequestMap = Arc<RwLock<HashMap<JsonRpcId, ResponseTx>>>;

/// A request sent from the main client handle to the actor task.
pub struct ClientRequest {
    pub request: JsonRpcRequest,
    /// The channel to send the response back to the waiting caller.
    pub response_tx: ResponseTx,
}

/// The actor that manages I/O for a single active mTLS connection.
/// It is spawned and torn down by the WorkloadClient's main run loop.
pub struct ClientActor {
    stream: SecureStream,
    /// Receives requests from all `WorkloadClient` handles.
    from_client: mpsc::Receiver<ClientRequest>,
    /// Maps request IDs to the `oneshot` sender waiting for the response.
    pending: PendingRequestMap,
}

impl ClientActor {
    pub fn new(
        stream: SecureStream,
        from_client: mpsc::Receiver<ClientRequest>,
        pending: PendingRequestMap,
    ) -> Self {
        Self {
            stream,
            from_client,
            pending,
        }
    }

    /// The main I/O loop for the client actor.
    /// This method spawns two tasks: one for writing requests and one for reading responses,
    /// allowing for fully concurrent, multiplexed communication over the single connection.
    /// It returns an error if the connection is lost, signaling the main loop to reconnect.
    pub async fn run(mut self) -> anyhow::Result<()> {
        let (mut read_half, mut write_half) = tokio::io::split(self.stream);

        // --- Write Task ---
        // This task listens for requests from client handles and writes them to the socket.
        let pending_write = self.pending.clone();
        let write_task = tokio::spawn(async move {
            while let Some(req) = self.from_client.recv().await {
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

                    // --- FIX START: Implement length-prefixing ---
                    // Write the 4-byte length prefix first.
                    if let Err(e) = write_half.write_u32(req_bytes.len() as u32).await {
                        log::error!("[WorkloadClientActor] Failed to write request length prefix: {}. Closing write task.", e);
                        break;
                    }
                    // Then write the message payload.
                    if let Err(e) = write_half.write_all(&req_bytes).await {
                        log::error!("[WorkloadClientActor] Failed to write request payload: {}. Closing write task.", e);
                        break;
                    }
                    // --- FIX END ---
                }
            }
        });

        // --- Read Task ---
        // This task continuously reads from the socket and dispatches responses.
        let pending_read = self.pending.clone();
        let read_task = tokio::spawn(async move {
            // --- FIX START: Implement length-prefixed reading ---
            loop {
                // 1. Read the 4-byte length prefix. read_u32 handles partial reads.
                let len = match read_half.read_u32().await {
                    Ok(len) => len as usize,
                    Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        log::info!(
                            "[WorkloadClientActor] Connection closed by server. Closing read task."
                        );
                        break; // Clean EOF
                    }
                    Err(e) => {
                        log::error!("[WorkloadClientActor] Failed to read response length prefix: {}. Closing read task.", e);
                        break;
                    }
                };

                // 2. Sanity check the length to prevent allocation attacks.
                const MAX_IPC_MESSAGE_SIZE: usize = 1_048_576; // 1 MiB
                if len == 0 || len > MAX_IPC_MESSAGE_SIZE {
                    log::error!("[WorkloadClientActor] Received invalid message length: {}. Closing connection.", len);
                    break;
                }

                // 3. Read the exact number of bytes for the message payload.
                let mut response_buf = vec![0; len];
                if let Err(e) = read_half.read_exact(&mut response_buf).await {
                    log::error!("[WorkloadClientActor] Failed to read full response payload (len={}): {}. Closing read task.", len, e);
                    break;
                }

                // 4. Deserialize and dispatch the complete message.
                let response: JsonRpcResponse = match serde_json::from_slice(&response_buf) {
                    Ok(res) => res,
                    Err(e) => {
                        log::error!("[WorkloadClientActor] Failed to parse response: {}", e);
                        continue; // Don't break for a single malformed message.
                    }
                };
                // --- FIX END ---

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
        log::info!("[WorkloadClientActor] I/O loop terminated.");
        Err(anyhow::anyhow!("Client actor I/O loop terminated"))
    }
}
