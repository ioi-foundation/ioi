// Path: crates/api/src/ibc/mod.rs
//! Defines traits for Inter-Blockchain Communication (IBC).

use crate::services::BlockchainService;
use depin_sdk_types::error::CoreError as Error;

/// A unique identifier for a blockchain.
pub type ChainId = String;
/// An identifier for a proof type.
pub type ProofType = String;

/// Represents a data packet for cross-chain communication.
pub struct Packet {
    /// The payload of the packet.
    pub data: Vec<u8>,
    /// The source chain's identifier.
    pub source: ChainId,
    /// The destination chain's identifier.
    pub destination: ChainId,
}

/// A trait for services that handle cross-chain communication.
pub trait CrossChainCommunication: BlockchainService {
    /// Verifies a proof from another chain.
    fn verify_proof(&self, proof: &dyn CrossChainProof) -> Result<bool, Error>;
    /// Creates a packet to be sent to another chain.
    fn create_packet(&self, data: &[u8], destination: ChainId) -> Result<Packet, Error>;
}

/// A trait for a proof that can be verified across chains.
pub trait CrossChainProof {
    /// The identifier of the source chain that generated the proof.
    fn source_chain(&self) -> ChainId;
    /// The type of the proof.
    fn proof_type(&self) -> ProofType;
}
