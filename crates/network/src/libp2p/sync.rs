// Path: crates/network/src/libp2p/sync.rs

//! The part of the libp2p implementation handling the BlockSync trait.

use crate::traits::{BlockSync, NodeState, SyncError};
use async_trait::async_trait;
use depin_sdk_core::app::{Block, ProtocolTransaction};
use futures::io::{AsyncRead, AsyncWrite};
use libp2p::{
    core::upgrade::{read_length_prefixed, write_length_prefixed},
    request_response::Codec,
    PeerId,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::Mutex;

use super::{Libp2pSync, SwarmCommand};

// --- Block Sync Protocol Definitions ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    GetStatus,
    GetBlocks(u64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    Status(u64),
    Blocks(Vec<Block<ProtocolTransaction>>),
}

#[derive(Debug, Clone, Default)]
pub struct SyncCodec;

#[async_trait]
impl Codec for SyncCodec {
    type Protocol = &'static str;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T: AsyncRead + Unpin + Send>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Request> {
        let vec = read_length_prefixed(io, 1_000_000).await?;
        serde_json::from_slice(&vec).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Response> {
        let vec = read_length_prefixed(io, 10_000_000).await?;
        serde_json::from_slice(&vec).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> std::io::Result<()> {
        let vec = serde_json::to_vec(&req)?;
        write_length_prefixed(io, vec).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(&mut self, _: &Self::Protocol, io: &mut T, res: Self::Response) -> std::io::Result<()> {
        let vec = serde_json::to_vec(&res)?;
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

    async fn publish_block(&self, block: &Block<ProtocolTransaction>) -> Result<(), SyncError> {
        let data = serde_json::to_vec(block).map_err(|e| SyncError::Decode(e.to_string()))?;
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