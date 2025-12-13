// Path: crates/networking/src/libp2p/sync.rs

//! The part of the libp2p implementation handling the BlockSync trait.

use crate::traits::{BlockSync, NodeState, SyncError};
use async_trait::async_trait;
use ioi_types::app::{Block, ChainId, ChainTransaction};
use ioi_types::codec;
// [FIX] Added AsyncReadExt/AsyncWriteExt for read_exact/write_all
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{
    // [FIX] Removed core::upgrade imports
    request_response::Codec,
    PeerId,
};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::Mutex;

use super::{Libp2pSync, SwarmCommand};

// --- Block Sync Protocol Definitions ---

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum SyncRequest {
    GetStatus,
    GetBlocks {
        since: u64,
        max_blocks: u32,
        max_bytes: u32,
    },
    AgenticPrompt(String),
    // [NEW] Request missing transactions for compact block reconstruction
    // Changed usize to u32 for deterministic SCALE encoding
    RequestMissingTxs(Vec<u32>),
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum SyncResponse {
    Status {
        height: u64,
        head_hash: [u8; 32],
        chain_id: ChainId,
        genesis_root: Vec<u8>,
    },
    Blocks(Vec<Block<ChainTransaction>>),
    AgenticAck,
    // [NEW] Response with missing transactions
    MissingTxs(Vec<ChainTransaction>),
}

#[derive(Debug, Clone, Default)]
pub struct SyncCodec;

// [FIX] Local implementation of length-prefixed reading (UVI varint)
async fn read_length_prefixed<T: AsyncRead + Unpin + Send>(
    io: &mut T,
    max_len: usize,
) -> std::io::Result<Vec<u8>> {
    let buf = [0u8; 10]; // Max varint size for u64
    let mut i = 0;
    let mut len: u64 = 0;
    let mut shift = 0;

    loop {
        if i >= buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Varint too long",
            ));
        }
        let mut b = [0u8; 1];
        io.read_exact(&mut b).await?;
        let byte = b[0];

        len |= ((byte & 0x7f) as u64) << shift;
        shift += 7;

        if (byte & 0x80) == 0 {
            break;
        }
        i += 1;
    }

    if len > max_len as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Message too large",
        ));
    }

    let mut vec = vec![0u8; len as usize];
    io.read_exact(&mut vec).await?;
    Ok(vec)
}

// [FIX] Local implementation of length-prefixed writing (UVI varint)
async fn write_length_prefixed<T: AsyncWrite + Unpin + Send>(
    io: &mut T,
    data: Vec<u8>,
) -> std::io::Result<()> {
    let mut len = data.len() as u64;
    let buf = [0u8; 10]; // [FIX] Removed unused mut
    let mut i = 0;

    // Use a separate buffer for encoding
    let mut encoded_len = [0u8; 10];

    loop {
        let mut byte = (len & 0x7f) as u8;
        len >>= 7;
        if len != 0 {
            byte |= 0x80;
        }
        encoded_len[i] = byte;
        i += 1;
        if len == 0 {
            break;
        }
    }

    io.write_all(&encoded_len[..i]).await?;
    io.write_all(&data).await?;
    Ok(())
}

#[async_trait]
impl Codec for SyncCodec {
    type Protocol = &'static str;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request> {
        let vec = read_length_prefixed(io, 1_000_000).await?;
        codec::from_bytes_canonical(&vec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response> {
        let vec = read_length_prefixed(io, 10_000_000).await?;
        codec::from_bytes_canonical(&vec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()> {
        let vec = codec::to_bytes_canonical(&req)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        write_length_prefixed(io, vec).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()> {
        let vec = codec::to_bytes_canonical(&res)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        write_length_prefixed(io, vec).await
    }
}

// --- BlockSync Trait Implementation ---

#[async_trait]
impl BlockSync for Libp2pSync {
    async fn start(&self) -> Result<(), SyncError> {
        log::info!("[Sync] Libp2pSync network service started.");
        Ok(())
    }

    async fn stop(&self) -> Result<(), SyncError> {
        log::info!("[Sync] Libp2pSync stopping...");
        self.shutdown_sender.send(true).ok();

        let mut handles = self.task_handles.lock().await;
        for handle in handles.drain(..) {
            handle
                .await
                .map_err(|e| SyncError::Internal(format!("Task panicked: {e}")))?;
        }
        Ok(())
    }

    async fn publish_block(&self, block: &Block<ChainTransaction>) -> Result<(), SyncError> {
        let data = codec::to_bytes_canonical(block).map_err(|e| SyncError::Decode(e))?;
        self.swarm_command_sender
            .send(SwarmCommand::PublishBlock(data))
            .await
            .map_err(|e| SyncError::Network(e.to_string()))
    }

    fn get_node_state(&self) -> Arc<Mutex<NodeState>> {
        self.node_state.clone()
    }

    fn get_local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    fn get_known_peers(&self) -> Arc<Mutex<HashSet<PeerId>>> {
        self.known_peers.clone()
    }
}
