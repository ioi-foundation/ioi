// Path: crates/api/src/app/mod.rs

use crate::transaction::TransactionModel;
use dcrypt::algorithms::hash::{HashFunction, Sha256 as DcryptSha256};
use dcrypt::algorithms::ByteSerializable;
use depin_sdk_types::codec;
use depin_sdk_types::error::CoreError; // Added for error type
use parity_scale_codec::Encode;
use serde::{Deserialize, Serialize};

/// Represents the current status of the blockchain.
#[derive(Serialize, Deserialize, Debug, Encode)]
pub struct ChainStatus {
    /// The current block height.
    pub height: u64,
    /// The timestamp of the latest block.
    pub latest_timestamp: u64,
    /// The total number of transactions processed.
    pub total_transactions: u64,
    /// A flag indicating if the chain is actively running.
    pub is_running: bool,
}

/// A block in the blockchain, generic over the transaction type.
#[derive(Serialize, Deserialize, Debug, Clone, Encode)]
pub struct Block<T: Clone + Encode> {
    /// The header of the block containing metadata.
    pub header: BlockHeader,
    /// A list of transactions included in the block.
    pub transactions: Vec<T>,
}

/// The header of a block, containing metadata and commitments.
#[derive(Serialize, Deserialize, Debug, Clone, Encode)]
pub struct BlockHeader {
    /// The height of this block.
    pub height: u64,
    /// The hash of the previous block's header.
    pub prev_hash: Vec<u8>,
    /// The root hash of the state tree after applying this block's transactions.
    pub state_root: Vec<u8>,
    /// The root hash of the transactions in this block.
    pub transactions_root: Vec<u8>,
    /// The timestamp when the block was created.
    pub timestamp: u64,
    /// The full, sorted list of PeerIds (in bytes) that constituted the validator
    /// set when this block was created.
    pub validator_set: Vec<Vec<u8>>,
    /// The public key (in bytes) of the block producer.
    pub producer: Vec<u8>,
    /// The signature of the block header's hash, signed by the producer.
    pub signature: Vec<u8>,
}

impl BlockHeader {
    /// Creates a hash of the header's core fields for signing.
    pub fn hash_for_signing(&self) -> Result<Vec<u8>, CoreError> {
        let mut temp = self.clone();
        // Clear the signature before hashing to create a stable payload.
        temp.signature = vec![];
        let serialized = codec::to_bytes_canonical(&temp);
        DcryptSha256::digest(&serialized)
            .map(|d| d.to_bytes())
            .map_err(|e| CoreError::Custom(e.to_string()))
    }
}

/// An input for a UTXO transaction, pointing to a previous output.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode)]
pub struct Input {
    /// The hash of the transaction containing the output being spent.
    pub tx_hash: Vec<u8>,
    /// The index of the output in the previous transaction.
    pub output_index: u32,
    /// The signature authorizing the spending of the output.
    pub signature: Vec<u8>,
}

/// An output for a UTXO transaction, creating a new unspent output.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode)]
pub struct Output {
    /// The value of the output.
    pub value: u64,
    /// The public key of the recipient.
    pub public_key: Vec<u8>,
}

/// A transaction following the UTXO model.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode)]
pub struct UTXOTransaction {
    /// A list of inputs to be spent.
    pub inputs: Vec<Input>,
    /// A list of new outputs to be created.
    pub outputs: Vec<Output>,
}

impl UTXOTransaction {
    /// Computes the hash of the transaction.
    #[deprecated(
        since = "0.2.0",
        note = "Hashing should be performed on the top-level `ChainTransaction` enum for consistency. Use `ChainTransaction::hash()` instead."
    )]
    pub fn hash(&self) -> Result<Vec<u8>, CoreError> {
        let serialized = codec::to_bytes_canonical(self);
        DcryptSha256::digest(&serialized)
            .map(|d| d.to_bytes())
            .map_err(|e| CoreError::Custom(e.to_string()))
    }
}

/// A top-level enum representing any transaction the chain can process.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode)]
pub enum ChainTransaction {
    /// A transaction initiated by a user or application.
    Application(ApplicationTransaction),
    /// A privileged transaction for system-level changes.
    System(SystemTransaction),
}

// NEW METHOD: Centralized hash function for all transaction types.
impl ChainTransaction {
    /// Computes a canonical, deterministic hash for any transaction variant.
    ///
    /// This is the single, preferred method for generating a transaction ID.
    /// It uses a canonical binary encoding to ensure the hash is consistent
    /// across all nodes and implementations.
    pub fn hash(&self) -> Result<Vec<u8>, CoreError> {
        let serialized = codec::to_bytes_canonical(self);
        DcryptSha256::digest(&serialized)
            .map(|d| d.to_bytes())
            .map_err(|e| CoreError::Custom(e.to_string()))
    }
}

/// An enum wrapping all possible user-level transaction models.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode)]
pub enum ApplicationTransaction {
    /// A transaction for a UTXO-based ledger.
    UTXO(UTXOTransaction),
    /// A transaction to deploy a new smart contract.
    DeployContract {
        /// The bytecode of the contract.
        code: Vec<u8>,
    },
    /// A transaction to call a method on an existing smart contract.
    CallContract {
        /// The address of the contract to call.
        address: Vec<u8>,
        /// The ABI-encoded input data for the contract call.
        input_data: Vec<u8>,
    },
}

/// A privileged transaction for performing system-level state changes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode)]
pub struct SystemTransaction {
    /// The specific action being requested.
    pub payload: SystemPayload,
    /// A signature authorizing the action.
    pub signature: Vec<u8>,
}

/// The specific action being requested by a SystemTransaction.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode)]
pub enum SystemPayload {
    /// Updates the set of authorities for a Proof-of-Authority chain.
    UpdateAuthorities {
        /// The new list of authority PeerIDs.
        new_authorities: Vec<Vec<u8>>,
    },
    /// Stakes a certain amount for a validator.
    Stake {
        /// The amount to stake.
        amount: u64,
    },
    /// Unstakes a certain amount for a validator.
    Unstake {
        /// The amount to unstake.
        amount: u64,
    },
}

/// A struct that holds the core, serializable state of a blockchain.
/// This is distinct from its logic, which is defined by the `AppChain` trait.
#[derive(Debug)]
pub struct ChainState<CS, TM: TransactionModel> {
    /// The cryptographic commitment scheme used by the chain.
    pub commitment_scheme: CS,
    /// The transaction model defining validation and application logic.
    pub transaction_model: TM,
    /// A unique identifier for the blockchain.
    pub chain_id: String,
    /// The current status of the chain.
    pub status: ChainStatus,
    /// A cache of recently processed blocks.
    pub recent_blocks: Vec<Block<ChainTransaction>>,
    /// The maximum number of recent blocks to keep in the cache.
    pub max_recent_blocks: usize,
}