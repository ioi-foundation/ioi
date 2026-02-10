// Path: crates/networking/src/libp2p/types.rs

use ioi_consensus::admft::ViewChangeVote;
use ioi_types::app::{
    Block, ChainId, ChainTransaction, ConfidenceVote, ConsensusVote, EchoMessage,
    OracleAttestation, PanicMessage,
};
// [FIX] Removed unused codec import
use libp2p::{request_response::ResponseChannel, Multiaddr, PeerId};
// [FIX] Removed unused SyncRequest import
use crate::libp2p::sync::SyncResponse;

#[derive(Debug)]
pub enum SwarmCommand {
    Listen(Multiaddr),
    Dial(Multiaddr),
    PublishBlock(Vec<u8>),
    PublishTransaction(Vec<u8>),
    BroadcastVote(Vec<u8>),
    BroadcastViewChange(Vec<u8>),

    // Protocol Apex Commands
    BroadcastEcho(Vec<u8>),
    BroadcastPanic(Vec<u8>),
    BroadcastConfidence(Vec<u8>),

    // A-PMFT Sampling Commands
    SendSampleRequest {
        peer: PeerId,
        height: u64,
    },
    SendSampleResponse {
        channel: ResponseChannel<SyncResponse>,
        block_hash: [u8; 32],
        confidence: u32,
    },

    SendStatusRequest(PeerId),
    SendBlocksRequest {
        peer: PeerId,
        since: u64,
        max_blocks: u32,
        max_bytes: u32,
    },
    SendStatusResponse {
        channel: ResponseChannel<SyncResponse>,
        height: u64,
        head_hash: [u8; 32],
        chain_id: ChainId,
        genesis_root: Vec<u8>,
    },
    SendBlocksResponse(ResponseChannel<SyncResponse>, Vec<Block<ChainTransaction>>),
    BroadcastToCommittee(Vec<PeerId>, String),
    AgenticConsensusVote(String, Vec<u8>),
    SendAgenticAck(ResponseChannel<SyncResponse>),
    SimulateAgenticTx,
    GossipOracleAttestation(Vec<u8>),
    RequestMissingTxs {
        peer: PeerId,
        indices: Vec<u32>,
    },
}

#[derive(Debug)]
pub enum NetworkEvent {
    ConnectionEstablished(PeerId),
    ConnectionClosed(PeerId),
    GossipBlock {
        block: Block<ChainTransaction>,
        mirror_id: u8,
    },
    GossipTransaction(Box<ChainTransaction>),
    ConsensusVoteReceived {
        vote: ConsensusVote,
        from: PeerId,
    },
    ViewChangeVoteReceived {
        vote: ViewChangeVote,
        from: PeerId,
    },

    // Protocol Apex Events
    EchoReceived {
        echo: EchoMessage,
        from: PeerId,
    },
    PanicReceived {
        panic: PanicMessage,
        from: PeerId,
    },
    SampleRequestReceived {
        peer: PeerId,
        height: u64,
        channel: ResponseChannel<SyncResponse>,
    },
    SampleResponseReceived {
        peer: PeerId,
        block_hash: [u8; 32],
        confidence: u32,
    },
    ConfidenceVoteReceived(ConfidenceVote),

    StatusRequest(PeerId, ResponseChannel<SyncResponse>),
    BlocksRequest {
        peer: PeerId,
        since: u64,
        max_blocks: u32,
        max_bytes: u32,
        channel: ResponseChannel<SyncResponse>,
    },
    StatusResponse {
        peer: PeerId,
        height: u64,
        head_hash: [u8; 32],
        chain_id: ChainId,
        genesis_root: Vec<u8>,
    },
    BlocksResponse(PeerId, Vec<Block<ChainTransaction>>),
    AgenticPrompt {
        from: PeerId,
        prompt: String,
    },
    AgenticConsensusVote {
        from: PeerId,
        prompt_hash: String,
        vote_hash: Vec<u8>,
    },
    OracleAttestationReceived {
        from: PeerId,
        attestation: OracleAttestation,
    },
    OutboundFailure(PeerId),
    RequestMissingTxs {
        peer: PeerId,
        indices: Vec<u32>,
        channel: ResponseChannel<SyncResponse>,
    },
}

// Internal event type for swarm -> forwarder communication
#[derive(Debug)]
pub enum SwarmInternalEvent {
    ConnectionEstablished(PeerId),
    ConnectionClosed(PeerId),
    GossipBlock(Vec<u8>, PeerId, u8),
    GossipTransaction(Vec<u8>, PeerId),
    ConsensusVoteReceived(Vec<u8>, PeerId),
    ViewChangeVoteReceived(Vec<u8>, PeerId),

    EchoReceived(Vec<u8>, PeerId),
    PanicReceived(Vec<u8>, PeerId),

    SampleRequest(PeerId, u64, ResponseChannel<SyncResponse>),
    SampleResponse(PeerId, [u8; 32], u32),
    ConfidenceVoteReceived(Vec<u8>, PeerId),

    StatusRequest(PeerId, ResponseChannel<SyncResponse>),
    BlocksRequest {
        peer: PeerId,
        since: u64,
        max_blocks: u32,
        max_bytes: u32,
        channel: ResponseChannel<SyncResponse>,
    },
    StatusResponse {
        peer: PeerId,
        height: u64,
        head_hash: [u8; 32],
        chain_id: ChainId,
        genesis_root: Vec<u8>,
    },
    BlocksResponse(PeerId, Vec<Block<ChainTransaction>>),
    AgenticPrompt {
        from: PeerId,
        prompt: String,
        channel: ResponseChannel<SyncResponse>,
    },
    AgenticConsensusVote {
        from: PeerId,
        prompt_hash: String,
        vote_hash: Vec<u8>,
    },
    GossipOracleAttestation(Vec<u8>, PeerId),
    OutboundFailure(PeerId),
    RequestMissingTxs {
        peer: PeerId,
        indices: Vec<u32>,
        channel: ResponseChannel<SyncResponse>,
    },
}
