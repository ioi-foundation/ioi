// Path: crates/api/src/chain/mod.rs
//! Defines the core `AppChain` trait for blockchain state machines.

use crate::commitment::CommitmentScheme;
use crate::consensus::PenaltyMechanism;
use crate::state::StateChangeSet;
use crate::state::StateManager;
use crate::transaction::TransactionModel;
use crate::validator::WorkloadContainer;
use async_trait::async_trait;
use depin_sdk_types::app::{
    AccountId, ActiveKeyRecord, Block, ChainStatus, ChainTransaction, StateAnchor, StateRoot,
};
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::error::ChainError;
use libp2p::identity::Keypair;
use std::collections::BTreeMap;
use std::fmt::Debug;

/// A read-only view of the world state anchored to a specific state anchor.
#[async_trait]
pub trait StateView: Send + Sync {
    /// Returns the state anchor this view is anchored to.
    fn state_anchor(&self) -> &StateAnchor;
    /// [DEPRECATED] Returns the legacy, flat list of validator AccountIds.
    #[deprecated(note = "Use get_validator_set_blob_at for a complete, weighted view")]
    async fn validator_set_legacy(&self) -> Result<Vec<AccountId>, ChainError>;
    /// Gets a value by key from the state version this view is anchored to.
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ChainError>;
    /// Returns the active consensus key record for a given AccountId.
    async fn active_consensus_key(&self, acct: &AccountId) -> Option<ActiveKeyRecord>;
}

/// The public key of a validator, represented as a Base58 string.
pub type PublicKey = String;
/// The amount of stake a validator has.
pub type StakeAmount = u64;

/// A trait providing a read-only "view" of chain-level context that transaction models may need.
///
/// This acts as a facade, decoupling the `TransactionModel` from the concrete `AppChain` implementation.
/// It provides access to state-dependent data (like validator sets) and core mechanisms (like penalties)
/// without exposing mutable state or the full `AppChain` interface.
#[async_trait]
pub trait ChainView<CS, ST>: Debug + Send + Sync
where
    CS: CommitmentScheme,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    /// Obtain a read-only view anchored at a specific state anchor.
    async fn view_at(&self, anchor: &StateAnchor) -> Result<Box<dyn StateView>, ChainError>;

    /// Provides access to the consensus-specific penalty mechanism.
    /// This now returns a Box<dyn Trait> to be object-safe.
    fn get_penalty_mechanism(&self) -> Box<dyn PenaltyMechanism + Send + Sync + '_>;

    /// Returns the consensus type of the chain.
    fn consensus_type(&self) -> ConsensusType;

    /// Provides generic access to the validator's workload container for VM execution.
    fn workload_container(&self) -> &WorkloadContainer<ST>;
}

/// An intermediate artifact representing a block that has been fully processed and is ready for commitment.
/// This structure is the output of the `prepare_block` phase and the input to the `commit_block` phase.
#[derive(Debug)]
pub struct PreparedBlock {
    /// The block, potentially modified with coinbase transactions, ready for its header to be finalized.
    pub block: Block<ChainTransaction>,
    /// The complete, ordered set of state changes to be applied to the state tree.
    pub state_changes: StateChangeSet,
    /// The parent state root this block was prepared against, for TOCTOU protection.
    pub parent_state_root: StateRoot,
    /// The Merkle root of the transactions processed, for TOCTOU protection.
    pub transactions_root: Vec<u8>,
    /// The hash of the validator set used during preparation, for TOCTOU protection.
    pub validator_set_hash: [u8; 32],
}

/// A trait that defines the logic and capabilities of an application-specific blockchain.
#[async_trait]
pub trait AppChain<CS, TM, ST>: ChainView<CS, ST>
where
    CS: CommitmentScheme,
    TM: TransactionModel<CommitmentScheme = CS> + ?Sized,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static,
{
    /// Returns the current status of the chain.
    fn status(&self) -> &ChainStatus;
    /// Returns a reference to the transaction model used by the chain.
    fn transaction_model(&self) -> &TM;

    /// Phase 1: Prepares a block for commitment.
    /// This is a read-only operation on `self` and performs all expensive, async work,
    /// including transaction simulation and I/O.
    async fn prepare_block(
        &self,
        block: Block<ChainTransaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<PreparedBlock, ChainError>;

    /// Phase 2: Commits a prepared block to the state.
    /// This is a write operation on `self` and should be as fast and deterministic as possible,
    /// ideally without async I/O other than the final state commit.
    async fn commit_block(
        &mut self,
        prepared: PreparedBlock,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError>;

    /// Creates a new block template to be filled by a block producer.
    // FIX: Update trait signature to return a Result.
    fn create_block(
        &self,
        transactions: Vec<ChainTransaction>,
        current_validator_set: &[Vec<u8>],
        known_peers_bytes: &[Vec<u8>],
        producer_keypair: &Keypair,
    ) -> Result<Block<ChainTransaction>, ChainError>;

    /// Retrieves a block by its height.
    fn get_block(&self, height: u64) -> Option<&Block<ChainTransaction>>;

    /// Retrieves all blocks since a given height.
    fn get_blocks_since(&self, height: u64) -> Vec<Block<ChainTransaction>>;

    /// Retrieves the validator set that will be active for a specific block height.
    async fn get_validator_set_for(
        &self,
        workload: &WorkloadContainer<ST>,
        height: u64,
    ) -> Result<Vec<Vec<u8>>, ChainError>;

    /// Retrieves the map of staked validators for PoS.
    async fn get_staked_validators(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<BTreeMap<AccountId, StakeAmount>, ChainError>;

    /// Retrieves the map of staked validators for the next epoch for PoS.
    async fn get_next_staked_validators(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<BTreeMap<AccountId, StakeAmount>, ChainError>;
}
