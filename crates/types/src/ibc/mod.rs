// Path: crates/types/src/ibc.rs
//! Core data structures for Universal Interoperability.

use crate::commitment::SchemeIdentifier;
use serde::{Deserialize, Serialize};

/// Specifies what is being proven within a foreign block.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProofTarget {
    /// Proves inclusion in the final state trie.
    State,
    /// Proves inclusion in the receipts trie.
    Receipts,
    /// Proves inclusion in the transactions trie.
    Transactions,
    /// Proves inclusion of a specific log within a specific transaction's receipt.
    Log {
        /// The index of the transaction in the block.
        tx_index: u32,
        /// The index of the log in the transaction receipt.
        log_index: u32,
    },
}

/// Contains the set of roots from a foreign block header, serving as trust anchors.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlockAnchor {
    /// The canonical hash of the foreign block.
    pub block_hash: [u8; 32],
    /// The height of the foreign block.
    pub block_number: u64,
    /// The root hash of the state trie.
    pub state_root: [u8; 32],
    /// The root hash of the transaction receipts trie.
    pub receipts_root: [u8; 32],
    /// The root hash of the transactions trie.
    pub transactions_root: [u8; 32],
}

/// Represents evidence that a block is final and not subject to reorgs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum FinalityEvidence {
    /// Finality evidence for Ethereum beacon chain light clients.
    EthBeaconFinality {
        /// The full SSZ-encoded `LightClientUpdate` structure.
        full_light_client_update: Vec<u8>,
    },
    /// Finality evidence for Tendermint-based chains.
    TendermintCommit {
        /// The serialized commit and validator set.
        commit_and_validator_set: Vec<u8>,
    },
    /// Finality based on a trusted, multi-signed checkpoint from a known authority set.
    TrustedCheckpoint {
        /// An identifier for the checkpoint being signed.
        checkpoint_id: String,
        /// The aggregated or multi-signatures.
        sigs: Vec<u8>,
    },
}

/// Specifies how to derive a trie key from a preimage, essential for interoperability.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum KeyCodec {
    /// The key preimage is the final trie key.
    Raw,
    /// The key preimage should be RLP-encoded as a scalar.
    RlpScalar,
    /// The key preimage should be hashed with Keccak256 to produce the final trie key.
    Keccak256,
}

/// A portable, unambiguous witness for proving membership of a value at a key path.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MembershipWitness {
    /// The data that is encoded/hashed to produce the final trie key (e.g., a transaction index).
    pub key_preimage: Vec<u8>,
    /// The codec that specifies how to transform the `key_preimage` into the final trie key.
    pub key_codec: KeyCodec,
    /// The value whose membership is being proven (e.g., an RLP-encoded receipt).
    pub value: Vec<u8>,
}

/// A universal, chain-agnostic container for a cryptographic state proof.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UniversalProofFormat {
    /// The identifier for the foreign chain's commitment scheme (e.g., "eth-mpt-keccak256").
    pub scheme_id: SchemeIdentifier,
    /// The opaque proof data, specific to the `scheme_id`.
    pub proof_data: Vec<u8>,
    /// The self-contained statement being proven.
    pub witness: MembershipWitness,
}

/// Specifies the hashing algorithm used for a digest.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DigestAlgo {
    /// The SHA-256 hashing algorithm.
    Sha256,
    /// The Keccak-256 hashing algorithm.
    Keccak256,
    /// The Blake3 hashing algorithm.
    Blake3,
}

/// The universal representation of an executed operation's outcome.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UniversalExecutionReceipt {
    /// A unique identifier for the source chain (e.g., "eth-mainnet").
    pub source_chain_id: String,
    /// The set of roots from the foreign block header against which the proof is verified.
    pub anchor: BlockAnchor,
    /// Specifies which of the anchor's roots to verify against.
    pub target: ProofTarget,
    /// Evidence that the anchored block is final.
    pub finality: Option<FinalityEvidence>,
    /// A globally unique identifier for this specific event or state transition.
    pub unique_leaf_id: Vec<u8>,
    // Canonical Operation Data
    /// The canonical, chain-agnostic identifier for the operation (e.g., "token.transfer@1.0").
    pub endpoint_id: String,
    /// The operation's parameters, serialized into a canonical JSON format (JCS/RFC 8785).
    pub params_jcs: Vec<u8>,
    /// A cryptographic digest of the operation's result.
    pub result_digest: [u8; 32],
    /// The algorithm used to compute the `result_digest`.
    pub result_digest_algo: DigestAlgo,
    /// The cryptographic hash of the Canonical Endpoint Mapping (CEM) used for this receipt's interpretation.
    pub cem_hash: [u8; 32],
}