// Path: crates/client/src/workload_client/actor.rs

use crate::security::SecureStream;
use ioi_ipc::jsonrpc::{JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::task::JoinHandle;

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
        let mut write_task: JoinHandle<()> = tokio::spawn(async move {
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

                    // --- FIX START: Combine length prefix and payload into a single write ---
                    // The AeadWrappedStream expects a single plaintext buffer to encrypt and frame.
                    // Writing the length and payload separately creates two independent, malformed frames.
                    let frame_len_bytes = (req_bytes.len() as u32).to_be_bytes();
                    let mut frame_to_write = Vec::with_capacity(4 + req_bytes.len());
                    frame_to_write.extend_from_slice(&frame_len_bytes);
                    frame_to_write.extend_from_slice(&req_bytes);

                    if let Err(e) = write_half.write_all(&frame_to_write).await {
                        log::error!("[WorkloadClientActor] Failed to write request frame: {}. Closing write task.", e);
                        // Immediately fail this in-flight request so the caller doesn't hang.
                        if let Some(tx) = pending_write
                            .write()
                            .await
                            .remove(&req.request.id.clone().unwrap())
                        {
                            let _ = tx.send(Err(JsonRpcError {
                                code: -32001,
                                message: "IPC connection lost; request canceled".into(),
                                data: None,
                            }));
                        }
                        break;
                    }
                    // --- FIX END ---
                }
            }
        });

        // --- Read Task ---
        // This task continuously reads from the socket and dispatches responses.
        let pending_read = self.pending.clone();
        let mut read_task: JoinHandle<()> = tokio::spawn(async move {
            loop {
                // Read the 4-byte length prefix.
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

                const MAX_IPC_MESSAGE_SIZE: usize = 1_048_576; // 1 MiB
                if len == 0 || len > MAX_IPC_MESSAGE_SIZE {
                    log::error!("[WorkloadClientActor] Received invalid message length: {}. Closing connection.", len);
                    break;
                }

                let mut response_buf = vec![0; len];
                if let Err(e) = read_half.read_exact(&mut response_buf).await {
                    log::error!("[WorkloadClientActor] Failed to read full response payload (len={}): {}. Closing read task.", len, e);
                    break;
                }

                let response: JsonRpcResponse = match serde_json::from_slice(&response_buf) {
                    Ok(res) => res,
                    Err(e) => {
                        log::error!("[WorkloadClientActor] Failed to parse response: {}", e);
                        continue; // Don't break for a single malformed message.
                    }
                };

                // Find the pending request and send the response back.
                if let Some(response_tx) = pending_read.write().await.remove(&response.id) {
                    let result = match (response.result, response.error) {
                        (Some(r), None) => Ok(r),
                        // FIX: Treat (None, None) as a valid success with Null value.
                        // This happens when the server returns Ok(()) -> result: null.
                        (None, None) => Ok(serde_json::Value::Null),
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

        // If either half ends, abort the sibling immediately so the actor can return and
        // the connection manager can reconnect right away.
        tokio::select! {
            res = &mut read_task => {
                match res {
                    Ok(()) => log::info!("[WorkloadClientActor] Read task finished; aborting write task."),
                    Err(e) if e.is_cancelled() => {},
                    Err(e) => log::warn!("[WorkloadClientActor] Read task join error: {}", e),
                }
                write_task.abort();
            }
            res = &mut write_task => {
                match res {
                    Ok(()) => log::info!("[WorkloadClientActor] Write task finished; aborting read task."),
                    Err(e) if e.is_cancelled() => {},
                    Err(e) => log::warn!("[WorkloadClientActor] Write task join error: {}", e),
                }
                read_task.abort();
            }
        }

        // *** Critical: fail all remaining in-flight requests on connection loss. ***
        {
            let mut pending = self.pending.write().await;
            if !pending.is_empty() {
                log::warn!(
                    "[WorkloadClientActor] Connection dropped; failing {} in-flight request(s).",
                    pending.len()
                );
            }
            for (_, tx) in pending.drain() {
                let _ = tx.send(Err(JsonRpcError {
                    code: -32001,
                    message: "IPC connection lost; request canceled".into(),
                    data: None,
                }));
            }
        }
        log::info!("[WorkloadClientActor] I/O loop terminated.");
        Err(anyhow::anyhow!("Client actor I/O loop terminated"))
    }
}