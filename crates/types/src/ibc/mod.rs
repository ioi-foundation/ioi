// Path: crates/types/src/ibc/mod.rs
//! Core data structures for Universal Interoperability.

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

// Chain-specific header types

/// A header from a Tendermint-based blockchain.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct TendermintHeader {
    /// The trusted height of the light client when this header was processed.
    pub trusted_height: u64,
    /// The protobuf-encoded Tendermint header data.
    pub data: Vec<u8>,
}

/// A header from an Ethereum beacon chain.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct EthereumHeader {
    /// The state root of the beacon block.
    pub state_root: [u8; 32],
    /* other beacon block header fields */
}

/// A header from a Solana blockchain.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SolanaHeader {
    /// A segment of the Proof of History ledger.
    pub poh_segment: Vec<u8>,
    /// The blockhash for the given segment.
    pub blockhash: [u8; 32],
}

/// A generic enum wrapping headers from different blockchain types.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum Header {
    /// A header from a Tendermint chain.
    Tendermint(TendermintHeader),
    /// A header from an Ethereum chain.
    Ethereum(EthereumHeader),
    /// A header from a Solana chain.
    Solana(SolanaHeader),
}

// Chain-specific inclusion proof schemes and types

/// The type of state proof scheme used (e.g., for EVM chains).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum StateProofScheme {
    /// Merkle-Patricia Trie proofs.
    Mpt,
    /// Verkle Tree proofs.
    Verkle,
}

/// An ICS23-compliant Merkle proof.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ICS23Proof {
    /// The raw bytes of the ICS-23 CommitmentProof (prost-encoded).
    pub proof_bytes: Vec<u8>,
    /// ICS-24 storage path **without** the store prefix (e.g. `clients/07-tendermint-0/clientState`).
    /// If you pass a full path including the store prefix, the verifier will detect and avoid double prefixing.
    pub path: String,
    /// The exact value committed at `path` (the right-hand side of the membership assertion).
    pub value: Vec<u8>,
}

/// A proof of a Solana account's state.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SolanaAccountProof {
    /// The raw bytes of the Solana getProof-style proof.
    pub proof_bytes: Vec<u8>,
}

/// A generic enum wrapping inclusion proofs from different blockchain types.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum InclusionProof {
    /// An ICS23 Merkle proof, typically from a Cosmos-SDK chain.
    Ics23(ICS23Proof),
    /// A state proof from an EVM-compatible chain.
    Evm {
        /// The specific proof scheme used (MPT or Verkle).
        scheme: StateProofScheme,
        /// The raw bytes of the proof.
        proof_bytes: Vec<u8>,
    },
    /// A proof for a Solana account.
    Solana(SolanaAccountProof),
}

// Finality Evidence

/// A generic enum wrapping finality evidence from different consensus mechanisms.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum Finality {
    /// A Tendermint commit and validator set proving finality.
    TendermintCommit {
        /// The protobuf-encoded commit and validator set data.
        commit_and_valset: Vec<u8>,
    },
    /// An Ethereum beacon chain sync committee update proving finality.
    EthereumBeaconUpdate {
        /// The SSZ-encoded sync committee update data.
        update_ssz: Vec<u8>,
    },
}

// IBC Packet Structure

/// Represents a standard IBC packet.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Packet {
    /// The sequence number of the packet.
    pub sequence: u64,
    /// The port on the source chain.
    pub source_port: String,
    /// The channel on the source chain.
    pub source_channel: String,
    /// The port on the destination chain.
    pub destination_port: String,
    /// The channel on the destination chain.
    pub destination_channel: String,
    /// The opaque data payload of the packet.
    pub data: Vec<u8>,
}