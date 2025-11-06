// Path: crates/network/src/libp2p/sync.rs

//! The part of the libp2p implementation handling the BlockSync trait.

use crate::traits::{BlockSync, NodeState, SyncError};
use async_trait::async_trait;
use ioi_types::app::{Block, ChainId, ChainTransaction};
use ioi_types::codec;
use futures::io::{AsyncRead, AsyncWrite};
use libp2p::{
    core::upgrade::{read_length_prefixed, write_length_prefixed},
    request_response::Codec,
    PeerId,
};
// [+] ADD these imports
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::Mutex;

use super::{Libp2pSync, SwarmCommand};

// --- Block Sync Protocol Definitions ---

// [+] ADD all the derive macros here
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum SyncRequest {
    GetStatus,
    GetBlocks {
        since: u64,
        max_blocks: u32,
        max_bytes: u32,
    },
    // [NEW] Add a variant to carry a agentic prompt to a peer.
    AgenticPrompt(String),
}

// [+] ADD all the derive macros here
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum SyncResponse {
    Status {
        height: u64,
        head_hash: [u8; 32],
        chain_id: ChainId,
        genesis_root: Vec<u8>,
    },
    Blocks(Vec<Block<ChainTransaction>>),
    // [NEW] Add a simple acknowledgement for agentic prompts.
    AgenticAck,
}

#[derive(Debug, Clone, Default)]
pub struct SyncCodec;

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
