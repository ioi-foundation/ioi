// Path: crates/core/src/app/mod.rs

use crate::error::StateError;
use crate::transaction::TransactionModel;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Serialize, Deserialize, Debug)]
pub struct ChainStatus {
    pub height: u64,
    pub latest_timestamp: u64,
    pub total_transactions: u64,
    pub is_running: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block<T: Clone> {
    pub header: BlockHeader,
    pub transactions: Vec<T>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockHeader {
    pub height: u64,
    pub prev_hash: Vec<u8>,
    pub state_root: Vec<u8>,
    pub transactions_root: Vec<u8>,
    pub timestamp: u64,
    /// The full, sorted list of PeerIds (in bytes) that constituted the validator
    /// set when this block was created.
    pub validator_set: Vec<Vec<u8>>,
}

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("Block processing error: {0}")]
    Block(String),
    #[error("Transaction processing error: {0}")]
    Transaction(String),
    #[error("State error: {0}")]
    State(#[from] StateError),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub tx_hash: Vec<u8>,
    pub output_index: u32,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub value: u64,
    pub public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UTXOTransaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

impl UTXOTransaction {
    pub fn hash(&self) -> Vec<u8> {
        let serialized = serde_json::to_vec(self).unwrap();
        Sha256::digest(&serialized).to_vec()
    }
}

/// A top-level enum representing any transaction the chain can process.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ProtocolTransaction {
    Application(ApplicationTransaction),
    System(SystemTransaction),
}

/// An enum wrapping all possible user-level transaction models.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ApplicationTransaction {
    UTXO(UTXOTransaction),
    DeployContract { code: Vec<u8> },
    CallContract { address: Vec<u8>, input_data: Vec<u8> },
}

/// A privileged transaction for performing system-level state changes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SystemTransaction {
    pub payload: SystemPayload,
    pub signature: Vec<u8>,
}

/// The specific action being requested by a SystemTransaction.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SystemPayload {
    UpdateAuthorities { new_authorities: Vec<Vec<u8>> },
    Stake { amount: u64 },
    Unstake { amount: u64 },
}

/// A struct that holds the core, serializable state of an application chain.
/// This is distinct from its logic, which is defined by the `SovereignChain` trait.
#[derive(Debug)]
pub struct AppChain<CS, TM: TransactionModel> {
    pub commitment_scheme: CS,
    pub transaction_model: TM,
    pub chain_id: String,
    pub status: ChainStatus,
    pub recent_blocks: Vec<Block<ProtocolTransaction>>,
    pub max_recent_blocks: usize,
}