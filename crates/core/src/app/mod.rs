// Path: crates/core/src/app/mod.rs

use crate::transaction::TransactionModel;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ChainStatus {
    pub height: u64,
    pub latest_timestamp: u64,
    pub total_transactions: u64,
    pub is_running: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block<T> {
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

#[derive(Debug)]
pub enum ChainError {
    Block(String),
    Transaction(String),
}

/// A struct that holds the core, serializable state of a sovereign chain.
/// This is distinct from its logic, which is defined by the `SovereignChain` trait.
#[derive(Debug)]
pub struct SovereignAppChain<CS, TM: TransactionModel> {
    pub commitment_scheme: CS,
    pub transaction_model: TM,
    pub chain_id: String,
    pub status: ChainStatus,
    pub recent_blocks: Vec<Block<TM::Transaction>>,
    pub max_recent_blocks: usize,
}