// Path: crates/api/src/chain/mod.rs
//! Defines the core `AppChain` trait for blockchain state machines.

use async_trait::async_trait;
use depin_sdk_types::app::{Block, ChainStatus, ChainTransaction};
use depin_sdk_types::error::ChainError;
use libp2p::identity::Keypair;
use std::collections::BTreeMap;
use std::fmt::Debug;

use crate::commitment::CommitmentScheme;
use crate::state::StateManager;
use crate::transaction::TransactionModel;
use crate::validator::WorkloadContainer;

/// The public key of a validator, represented as a Base58 string.
pub type PublicKey = String;
/// The amount of stake a validator has.
pub type StakeAmount = u64;

/// A trait that defines the logic and capabilities of an application-specific blockchain.
#[async_trait]
pub trait AppChain<CS, TM, ST>: Debug + Send
where
    CS: CommitmentScheme,
    TM: TransactionModel<CommitmentScheme = CS>,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    /// Returns the current status of the chain.
    fn status(&self) -> &ChainStatus;
    /// Returns a reference to the transaction model used by the chain.
    fn transaction_model(&self) -> &TM;

    /// Processes a single transaction against the current state.
    async fn process_transaction(
        &mut self,
        tx: &ChainTransaction,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>;

    /// Processes a full block of transactions, updating the chain state.
    // --- FIX START: Update the return type to match the implementation ---
    async fn process_block(
        &mut self,
        block: Block<ChainTransaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError>;
    // --- FIX END ---

    /// Creates a new block template to be filled by a block producer.
    ///
    /// # Arguments
    /// * `transactions` - A vector of protocol-level transactions to include in the block.
    /// * `current_validator_set` - The validator set from the last committed state.
    /// * `known_peers_bytes` - The current set of known validator peer IDs, as bytes,
    ///   used to propose an updated validator set for the new block.
    /// * `producer_keypair` - The keypair of the node producing the block, used for signing.
    fn create_block(
        &self,
        transactions: Vec<ChainTransaction>,
        current_validator_set: &[Vec<u8>],
        known_peers_bytes: &[Vec<u8>],
        producer_keypair: &Keypair,
    ) -> Block<ChainTransaction>;

    /// Retrieves a block by its height.
    fn get_block(&self, height: u64) -> Option<&Block<ChainTransaction>>;

    /// Retrieves all blocks since a given height.
    fn get_blocks_since(&self, height: u64) -> Vec<Block<ChainTransaction>>;

    /// Retrieves the active validator set from the committed state.
    async fn get_validator_set(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<Vec<Vec<u8>>, ChainError>;

    /// Retrieves the active authority set from the committed state for PoA.
    async fn get_authority_set(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<Vec<Vec<u8>>, ChainError>;

    /// Retrieves the map of staked validators for PoS.
    async fn get_staked_validators(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<BTreeMap<PublicKey, StakeAmount>, ChainError>;
}
