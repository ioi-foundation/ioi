// Path: crates/api/src/chain/mod.rs
//! Defines the core `AppChain` trait for blockchain state machines.

use crate::app::{Block, ChainStatus, ChainTransaction};
use crate::commitment::CommitmentScheme;
use crate::consensus::PenaltyMechanism;
use crate::state::StateChangeSet;
use crate::state::{StateManager, Verifier};
use crate::transaction::TransactionModel;
use crate::validator::WorkloadContainer;
use async_trait::async_trait;
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::error::ChainError;
use depin_sdk_types::Result;
use libp2p::identity::Keypair;
use std::any::Any;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

/// Content-addressed handle to a specific, historical state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StateRef {
    /// The block height this state corresponds to.
    pub height: u64,
    /// The raw cryptographic root commitment of this state (can be variable length).
    pub state_root: Vec<u8>,
    /// The hash of the block that produced this state.
    pub block_hash: [u8; 32],
}

/// A base trait for a read-only, proof-verifying view of the world state.
#[async_trait]
pub trait RemoteStateView: Send + Sync {
    /// Fetches a value by key from this state view.
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ChainError>;
    /// Returns the block height of this state view.
    fn height(&self) -> u64;
    /// Returns the raw root commitment of this state view.
    fn state_root(&self) -> &[u8];
}

/// A marker trait for an immutable, anchored snapshot of the state.
pub trait AnchoredStateView: RemoteStateView {}

/// A marker trait for a read-through view that follows the chain's head.
pub trait LiveStateView: RemoteStateView {
    /// Returns the block hash of the current chain head.
    fn head_hash(&self) -> [u8; 32];
}

/// A handle to either an anchored or a live state view.
pub enum ViewHandle {
    /// A handle to a specific, historical state view.
    Anchored(Arc<dyn AnchoredStateView>),
    /// A handle to the current, live state view.
    Live(Arc<dyn LiveStateView>),
}

/// A trait for a component that can resolve state handles into concrete, usable views.
#[async_trait]
pub trait ViewResolver: Send + Sync {
    /// The concrete `Verifier` type used to check proofs for this state.
    type Verifier: Verifier;
    /// Resolves a `StateRef` into a usable `AnchoredStateView`.
    async fn resolve_anchored(
        &self,
        r: &StateRef,
    ) -> Result<Arc<dyn AnchoredStateView>, ChainError>;
    /// Resolves the current chain head into a `LiveStateView`.
    async fn resolve_live(&self) -> Result<Arc<dyn LiveStateView>, ChainError>;
    /// Fetches the raw root commitment of the genesis block.
    async fn genesis_root(&self) -> Result<Vec<u8>, ChainError>;
    /// Returns the workload client as a type-erased `Any` trait object.
    /// The caller is responsible for downcasting it to the concrete `WorkloadClient` type.
    /// This approach avoids a circular dependency between the `api` and `client` crates.
    fn workload_client(&self) -> &dyn Any;
    /// Provides access to the concrete type for downcasting.
    fn as_any(&self) -> &dyn Any;
}

/// A trait providing a read-only "view" of chain-level context that transaction models may need.
#[async_trait]
pub trait ChainView<CS, ST>: Debug + Send + Sync
where
    CS: CommitmentScheme,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    /// Creates a read-only, anchored view of the state at a specific historical point.
    async fn view_at(&self, state_ref: &StateRef)
        -> Result<Arc<dyn AnchoredStateView>, ChainError>;
    /// Gets the penalty mechanism specific to the chain's consensus rules.
    fn get_penalty_mechanism(&self) -> Box<dyn PenaltyMechanism + Send + Sync + '_>;
    /// Returns the type of consensus algorithm the chain is running.
    fn consensus_type(&self) -> ConsensusType;
    /// Provides read-only access to the workload container.
    fn workload_container(&self) -> &WorkloadContainer<ST>;
}

/// An intermediate artifact representing a block that has been fully processed and is ready for commitment.
#[derive(Debug)]
pub struct PreparedBlock {
    /// The full block, including header and transactions.
    pub block: Block<ChainTransaction>,
    /// The complete set of state modifications derived from executing the block's transactions.
    pub state_changes: Arc<StateChangeSet>,
    /// The raw state root of the parent block, for validation during commit.
    pub parent_state_root: Vec<u8>,
    /// The Merkle root of the transactions in the block.
    pub transactions_root: Vec<u8>,
    /// A hash of the validator set that was active for this block.
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
    /// Gets a read-only reference to the current chain status.
    fn status(&self) -> &ChainStatus;
    /// Gets a mutable reference to the current chain status.
    fn status_mut(&mut self) -> &mut ChainStatus;
    /// Gets a reference to the chain's transaction model.
    fn transaction_model(&self) -> &TM;

    /// Executes the transactions in a block against a state overlay to produce a `PreparedBlock`.
    async fn prepare_block(
        &self,
        block: Block<ChainTransaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<PreparedBlock, ChainError>;

    /// Applies the state changes from a `PreparedBlock` to the canonical state.
    async fn commit_block(
        &mut self,
        prepared: PreparedBlock,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError>;

    /// Constructs a new block template.
    fn create_block(
        &self,
        transactions: Vec<ChainTransaction>,
        current_validator_set: &[Vec<u8>],
        known_peers_bytes: &[Vec<u8>],
        producer_keypair: &Keypair,
    ) -> Result<Block<ChainTransaction>, ChainError>;

    /// Retrieves a block from the recent block cache by height.
    fn get_block(&self, height: u64) -> Option<&Block<ChainTransaction>>;
    /// Retrieves all blocks from the cache since a given height.
    fn get_blocks_since(&self, height: u64) -> Vec<Block<ChainTransaction>>;

    /// Retrieves the active validator set for a specific block height.
    async fn get_validator_set_for(
        &self,
        workload: &WorkloadContainer<ST>,
        height: u64,
    ) -> Result<Vec<Vec<u8>>, ChainError>;

    /// Retrieves the current set of staked validators and their stakes.
    async fn get_staked_validators(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<BTreeMap<depin_sdk_types::app::AccountId, u64>, ChainError>;

    /// Retrieves the pending next set of staked validators and their stakes.
    async fn get_next_staked_validators(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<BTreeMap<depin_sdk_types::app::AccountId, u64>, ChainError>;
}