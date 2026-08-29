// Path: crates/api/src/chain/mod.rs
//! Defines the core `ChainStateMachine` trait for blockchain state machines.

use crate::app::{Block, ChainStatus, ChainTransaction};
use crate::commitment::CommitmentScheme;
use crate::consensus::PenaltyMechanism;
use crate::state::{StateManager, Verifier};
use crate::transaction::TransactionModel;
use crate::validator::WorkloadContainer;
use async_trait::async_trait;
use ioi_types::app::{AccountId, Membership, StateAnchor, StateRoot};
use ioi_types::config::ConsensusType;
use ioi_types::error::ChainError;
use ioi_types::Result;
use libp2p::identity::Keypair;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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

/// The response structure for state queries via the Workload API.
#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub struct QueryStateResponse {
    /// The version of the response message format.
    pub msg_version: u32,
    /// The numeric ID of the commitment scheme used.
    pub scheme_id: u16,
    /// The version of the commitment scheme.
    pub scheme_version: u16,
    /// The proven membership outcome (Present or Absent).
    pub membership: Membership,
    /// The raw bytes of the cryptographic proof.
    pub proof_bytes: Vec<u8>,
}

/// A trait defining the interface for interacting with a Workload container (local or remote).
/// This abstracts the IPC client to prevent circular dependencies and runtime downcasting panics.
#[async_trait]
pub trait WorkloadClientApi: Send + Sync + Debug {
    /// Processes a block, updating the state and returning the processed block,
    /// events, and one deterministic receipt per included transaction.
    async fn process_block(
        &self,
        block: Block<ChainTransaction>,
    ) -> Result<
        (
            Block<ChainTransaction>,
            Vec<Vec<u8>>,
            Vec<BlockExecutionReceipt>,
        ),
        ChainError,
    >;

    /// Atomically replaces the current one-height AFT workload projection.
    ///
    /// The validator may call this only after proving that Agentgres has not
    /// admitted `expected_tip`. Implementations must revalidate the complete
    /// execution surface under the same lock used for rollback and replacement.
    async fn replace_unfinalized_tip(
        &self,
        _expected_tip: Block<ChainTransaction>,
        _replacement: Block<ChainTransaction>,
    ) -> Result<
        (
            Block<ChainTransaction>,
            Vec<Vec<u8>>,
            Vec<BlockExecutionReceipt>,
        ),
        ChainError,
    > {
        Err(ChainError::Transaction(
            "workload does not support fenced AFT tip replacement".into(),
        ))
    }

    /// Fetches a range of blocks.
    async fn get_blocks_range(
        &self,
        since: u64,
        max_blocks: u32,
        max_bytes: u32,
    ) -> Result<Vec<Block<ChainTransaction>>, ChainError>;

    /// Fetches a single block by height.
    async fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<Block<ChainTransaction>>, ChainError>;

    /// Performs pre-execution checks on transactions against a specific state anchor.
    async fn check_transactions_at(
        &self,
        anchor: StateAnchor,
        expected_timestamp_secs: u64,
        txs: Vec<ChainTransaction>,
    ) -> Result<Vec<Result<(), String>>, ChainError>;

    /// Queries the state at a specific root hash, returning a proof.
    async fn query_state_at(
        &self,
        root: StateRoot,
        key: &[u8],
    ) -> Result<QueryStateResponse, ChainError>;

    /// Queries the raw state value (without proof) for a key.
    async fn query_raw_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ChainError>;

    /// Scans keys with a given prefix.
    async fn prefix_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError>;

    /// Gets the current set of staked validators.
    async fn get_staked_validators(&self) -> Result<BTreeMap<AccountId, u64>, ChainError>;

    /// Gets the genesis status.
    async fn get_genesis_status(&self) -> Result<bool, ChainError>;

    /// [NEW] Updates the header of a stored block (used for adding signatures/oracle data after execution).
    async fn update_block_header(&self, block: Block<ChainTransaction>) -> Result<(), ChainError>;

    // [NEW] Added for Public API access via trait object
    async fn get_state_root(&self) -> Result<StateRoot, ChainError>;

    // [NEW] Added for Public API access via trait object
    async fn get_status(&self) -> Result<ChainStatus, ChainError>;

    /// Returns the client as a type-erased `Any` trait object.
    fn as_any(&self) -> &dyn Any;
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
#[async_trait]
pub trait AnchoredStateView: RemoteStateView {
    /// Returns the total gas used in the block corresponding to this state view.
    async fn gas_used(&self) -> Result<u64, ChainError>;
}

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
    /// The concrete verifier type used to check proofs for this state.
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

    /// Returns the workload client interface.
    fn workload_client(&self) -> &Arc<dyn WorkloadClientApi>;

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

/// Schema identifier bound into every block execution receipt.
pub const BLOCK_EXECUTION_RECEIPT_SCHEMA: &str = "ioi.block-execution-receipt";
/// Version of the block execution receipt schema bound into every receipt.
pub const BLOCK_EXECUTION_RECEIPT_VERSION: u32 = 1;
/// Hash-domain separator bound into every block execution receipt.
pub const BLOCK_EXECUTION_RECEIPT_DOMAIN: &str = "ioi.block-execution-receipt.v1";
/// Versioned state-journal schema used to recover committed receipt bytes after
/// the workload process has acknowledged its atomic state/block commit.
pub const BLOCK_EXECUTION_RECEIPT_JOURNAL_SCHEMA: &str = "ioi.block-execution-receipt-journal.v1";
pub const BLOCK_EXECUTION_RECEIPT_JOURNAL_VERSION: u16 = 1;
const BLOCK_EXECUTION_RECEIPT_JOURNAL_PREFIX: &[u8] = b"execution::block_receipts::v1::";

/// The largest integer a JCS (RFC 8785) encoder renders without loss.
///
/// `receipt-proof-bundle.v2` bounds its `sequence` field by exactly this value
/// for the same reason. A receipt body is hashed over its JCS encoding, so an
/// integer above this bound is refused rather than silently rounded into a
/// `body_hash` that no verifier could reproduce.
const JCS_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;

/// What actually happened to a transaction during block preparation.
///
/// Only `Success` exists because `prepare_block` is all-or-nothing: any
/// transaction that errors aborts preparation of the whole block, so no failed
/// transaction can ever reach a `PreparedBlock`. This is a NONCLAIM boundary,
/// not an oversight — a partial-failure execution model must add a variant
/// here rather than have a reader assume `Success` covers the failed case.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum TransactionExecutionOutcome {
    /// The transaction executed to completion against the prepared overlay.
    Success,
}

impl TransactionExecutionOutcome {
    /// The canonical wire spelling used inside a receipt body.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
        }
    }
}

/// Deterministic receipt material for exactly one prepared transaction.
///
/// One of these is emitted per successfully prepared transaction, in block
/// order, derived from that transaction's own execution result. It is
/// deliberately NOT derived from any block-level aggregate, so an individual
/// transaction stays individually verifiable (ADR 0039).
///
/// It binds no per-transaction state delta. The executor commits a joint state
/// transition for the whole block (a single ordered overlay batch) and cannot
/// isolate which write belongs to which transaction, so claiming a per-transaction
/// delta here would be an invention. The joint transition is bound elsewhere.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BlockExecutionReceipt {
    /// The receipt schema identifier (`BLOCK_EXECUTION_RECEIPT_SCHEMA`).
    pub schema: String,
    /// The receipt schema version (`BLOCK_EXECUTION_RECEIPT_VERSION`).
    pub version: u32,
    /// The receipt hash domain (`BLOCK_EXECUTION_RECEIPT_DOMAIN`).
    pub domain: String,
    /// The height of the block this transaction was prepared in.
    pub block_height: u64,
    /// The zero-based position of this transaction in the block's transaction list.
    pub transaction_index: u64,
    /// SHA-256 over the transaction's canonical encoding, i.e. `ChainTransaction::hash()`.
    pub transaction_hash: [u8; 32],
    /// The observed execution outcome.
    pub outcome: TransactionExecutionOutcome,
    /// Gas consumed by this transaction alone, as reported by its own execution.
    pub gas_used: u64,
    /// Whether execution emitted any proof bytes for this transaction.
    pub proof_present: bool,
    /// SHA-256 over the exact proof bytes emitted for this transaction.
    ///
    /// When `proof_present` is false this is the SHA-256 of the empty string —
    /// the honest hash of the bytes that were actually emitted, not a placeholder.
    pub proof_hash: [u8; 32],
}

impl BlockExecutionReceipt {
    /// Builds receipt material for a transaction that executed to completion.
    pub fn for_success(
        block_height: u64,
        transaction_index: u64,
        transaction_hash: [u8; 32],
        gas_used: u64,
        proof_bytes: &[u8],
    ) -> Self {
        Self {
            schema: BLOCK_EXECUTION_RECEIPT_SCHEMA.to_string(),
            version: BLOCK_EXECUTION_RECEIPT_VERSION,
            domain: BLOCK_EXECUTION_RECEIPT_DOMAIN.to_string(),
            block_height,
            transaction_index,
            transaction_hash,
            outcome: TransactionExecutionOutcome::Success,
            gas_used,
            proof_present: !proof_bytes.is_empty(),
            proof_hash: sha256(proof_bytes),
        }
    }

    /// The canonical JSON body of this receipt.
    pub fn body(&self) -> Result<Value, ChainError> {
        let block_height = jcs_safe_u64(self.block_height, "block_height")?;
        let transaction_index = jcs_safe_u64(self.transaction_index, "transaction_index")?;
        let gas_used = jcs_safe_u64(self.gas_used, "gas_used")?;

        Ok(json!({
            "schema": self.schema,
            "version": self.version,
            "domain": self.domain,
            "block_height": block_height,
            "transaction_index": transaction_index,
            "transaction_hash": hash_label(&self.transaction_hash),
            "outcome": self.outcome.as_str(),
            "gas_used": gas_used,
            "proof_present": self.proof_present,
            "proof_hash": hash_label(&self.proof_hash),
        }))
    }

    /// `sha256:<hex>` over the JCS (RFC 8785) encoding of [`Self::body`].
    pub fn body_hash(&self) -> Result<String, ChainError> {
        let bytes = serde_jcs::to_vec(&self.body()?).map_err(|error| {
            ChainError::Transaction(format!("Receipt body JCS encoding failed: {error}"))
        })?;
        Ok(hash_label(&sha256(&bytes)))
    }

    /// Renders this receipt in the registered `receipt-proof-bundle.v2` material
    /// shape: `{"sequence", "body", "body_hash"}`, with `sequence` bound to the
    /// transaction's block position.
    pub fn material(&self) -> Result<Value, ChainError> {
        let sequence = jcs_safe_u64(self.transaction_index, "transaction_index")?;
        let body = self.body()?;
        let body_hash = self.body_hash()?;

        Ok(json!({
            "sequence": sequence,
            "body": body,
            "body_hash": body_hash,
        }))
    }
}

/// State-rooted recovery envelope for the exact receipt vector committed with
/// one workload block.
///
/// This journal deliberately does not add a per-transaction state-delta claim.
/// The receipt vector was fully checked against transaction proof bytes before
/// commit; recovery can re-check its transaction order, hashes, and aggregate
/// gas against the durable block while the state root protects the original
/// committed bytes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BlockExecutionReceiptJournal {
    pub schema: String,
    pub version: u16,
    pub block_height: u64,
    pub transactions_root: Vec<u8>,
    pub receipts: Vec<BlockExecutionReceipt>,
    pub journal_hash: [u8; 32],
}

impl BlockExecutionReceiptJournal {
    pub fn new(
        block_height: u64,
        transactions_root: Vec<u8>,
        receipts: Vec<BlockExecutionReceipt>,
    ) -> Self {
        let mut journal = Self {
            schema: BLOCK_EXECUTION_RECEIPT_JOURNAL_SCHEMA.into(),
            version: BLOCK_EXECUTION_RECEIPT_JOURNAL_VERSION,
            block_height,
            transactions_root,
            receipts,
            journal_hash: [0; 32],
        };
        journal.journal_hash = journal.compute_hash();
        journal
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut preimage = self.clone();
        preimage.journal_hash = [0; 32];
        sha256(&preimage.encode())
    }

    pub fn validate_against(&self, block: &Block<ChainTransaction>) -> Result<(), ChainError> {
        if self.schema != BLOCK_EXECUTION_RECEIPT_JOURNAL_SCHEMA
            || self.version != BLOCK_EXECUTION_RECEIPT_JOURNAL_VERSION
            || self.block_height != block.header.height
            || self.transactions_root
                != ioi_types::app::canonical_transactions_root(&block.transactions)
                    .map_err(ChainError::Transaction)?
            || self.journal_hash != self.compute_hash()
        {
            return Err(ChainError::Transaction(format!(
                "Block {} execution receipt journal envelope mismatch",
                block.header.height
            )));
        }
        if self.receipts.len() != block.transactions.len() {
            return Err(ChainError::Transaction(format!(
                "Block {} execution receipt journal count mismatch",
                block.header.height
            )));
        }
        let mut gas = 0_u64;
        for (index, (receipt, transaction)) in
            self.receipts.iter().zip(&block.transactions).enumerate()
        {
            if receipt.schema != BLOCK_EXECUTION_RECEIPT_SCHEMA
                || receipt.version != BLOCK_EXECUTION_RECEIPT_VERSION
                || receipt.domain != BLOCK_EXECUTION_RECEIPT_DOMAIN
                || receipt.block_height != block.header.height
                || receipt.transaction_index != index as u64
                || receipt.transaction_hash
                    != transaction
                        .hash()
                        .map_err(|error| ChainError::Transaction(error.to_string()))?
            {
                return Err(ChainError::Transaction(format!(
                    "Block {} execution receipt journal transaction {index} mismatch",
                    block.header.height
                )));
            }
            gas = gas.checked_add(receipt.gas_used).ok_or_else(|| {
                ChainError::Transaction("Execution receipt journal gas overflow".into())
            })?;
        }
        if gas != block.header.gas_used {
            return Err(ChainError::Transaction(format!(
                "Block {} execution receipt journal gas mismatch",
                block.header.height
            )));
        }
        Ok(())
    }
}

pub fn block_execution_receipt_journal_key(height: u64) -> Vec<u8> {
    [
        BLOCK_EXECUTION_RECEIPT_JOURNAL_PREFIX,
        height.to_be_bytes().as_slice(),
    ]
    .concat()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hash_label(digest: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(digest))
}

fn jcs_safe_u64(value: u64, field: &str) -> Result<u64, ChainError> {
    if value > JCS_SAFE_INTEGER_MAX {
        return Err(ChainError::Transaction(format!(
            "Receipt field '{field}' value {value} exceeds the JCS-representable maximum {JCS_SAFE_INTEGER_MAX}"
        )));
    }
    Ok(value)
}

/// Checks that a receipt set is complete, in block order, and actually bound to
/// the transactions and proofs it claims to describe.
///
/// This rejects a missing, extra, reordered, duplicated, or altered receipt:
/// receipt `i` must carry `transaction_index == i`, so any permutation or
/// repetition of the sequence fails, and each receipt's transaction hash and
/// proof hash must match the material at that same position. The per-receipt
/// gas figures must also sum to `expected_gas_used`, which is what stops the
/// individual receipts and the block aggregate from silently drifting apart.
pub fn validate_block_execution_receipts(
    receipts: &[BlockExecutionReceipt],
    transactions: &[ChainTransaction],
    tx_proofs: &[Vec<u8>],
    block_height: u64,
    expected_gas_used: u64,
) -> Result<(), ChainError> {
    if receipts.len() != transactions.len() {
        return Err(ChainError::Transaction(format!(
            "Block {block_height} carries {} execution receipts for {} transactions",
            receipts.len(),
            transactions.len(),
        )));
    }
    if tx_proofs.len() != transactions.len() {
        return Err(ChainError::Transaction(format!(
            "Block {block_height} carries {} transaction proofs for {} transactions",
            tx_proofs.len(),
            transactions.len(),
        )));
    }

    let mut receipted_gas: u64 = 0;
    for (index, receipt) in receipts.iter().enumerate() {
        let index = index as u64;
        if receipt.transaction_index != index {
            return Err(ChainError::Transaction(format!(
                "Execution receipt at position {index} of block {block_height} claims transaction index {}",
                receipt.transaction_index,
            )));
        }
        if receipt.block_height != block_height {
            return Err(ChainError::Transaction(format!(
                "Execution receipt {index} claims block height {} but belongs to block {block_height}",
                receipt.block_height,
            )));
        }
        if receipt.schema != BLOCK_EXECUTION_RECEIPT_SCHEMA
            || receipt.version != BLOCK_EXECUTION_RECEIPT_VERSION
            || receipt.domain != BLOCK_EXECUTION_RECEIPT_DOMAIN
        {
            return Err(ChainError::Transaction(format!(
                "Execution receipt {index} of block {block_height} carries schema '{}' v{} domain '{}', expected '{BLOCK_EXECUTION_RECEIPT_SCHEMA}' v{BLOCK_EXECUTION_RECEIPT_VERSION} domain '{BLOCK_EXECUTION_RECEIPT_DOMAIN}'",
                receipt.schema, receipt.version, receipt.domain,
            )));
        }

        let expected_tx_hash = transactions[index as usize]
            .hash()
            .map_err(|error| ChainError::Transaction(error.to_string()))?;
        if receipt.transaction_hash != expected_tx_hash {
            return Err(ChainError::Transaction(format!(
                "Execution receipt {index} of block {block_height} binds transaction {} but position {index} holds {}",
                hex::encode(receipt.transaction_hash),
                hex::encode(expected_tx_hash),
            )));
        }

        let proof_bytes = &tx_proofs[index as usize];
        if receipt.proof_present != !proof_bytes.is_empty()
            || receipt.proof_hash != sha256(proof_bytes)
        {
            return Err(ChainError::Transaction(format!(
                "Execution receipt {index} of block {block_height} does not bind the proof emitted at that position"
            )));
        }

        receipted_gas = receipted_gas.checked_add(receipt.gas_used).ok_or_else(|| {
            ChainError::Transaction(format!(
                "Execution receipt gas overflows u64 at transaction {index} of block {block_height}"
            ))
        })?;
    }

    if receipted_gas != expected_gas_used {
        return Err(ChainError::Transaction(format!(
            "Block {block_height} execution receipts account for {receipted_gas} gas but the block reports {expected_gas_used}"
        )));
    }

    Ok(())
}

/// An intermediate artifact representing a block that has been fully processed and is ready for commitment.
#[derive(Debug)]
pub struct PreparedBlock {
    /// The full block, including header and transactions.
    pub block: Block<ChainTransaction>,
    /// The authoritative millisecond timestamp for the block on the live timing path.
    pub block_timestamp_ms: u64,
    /// The complete set of state modifications derived from executing the block's transactions.
    pub state_changes: Arc<StateChanges>,
    /// The raw state root of the parent block, for validation during commit.
    pub parent_state_root: Vec<u8>,
    /// The Merkle root of the transactions in the block.
    pub transactions_root: Vec<u8>,
    /// A hash of the validator set that was active for this block.
    pub validator_set_hash: [u8; 32],
    /// Canonically encoded proofs for each transaction in the block.
    pub tx_proofs: Vec<Vec<u8>>,
    /// The total gas consumed by transactions in this block.
    pub gas_used: u64,
    /// Exactly one receipt per successfully prepared transaction, in block order.
    ///
    /// An empty block carries zero receipts. A non-empty block carries exactly
    /// as many receipts as it has transactions; see
    /// [`validate_block_execution_receipts`].
    pub execution_receipts: Vec<BlockExecutionReceipt>,
}

impl PreparedBlock {
    /// Checks this block's receipt set against its own transactions and proofs.
    ///
    /// See [`validate_block_execution_receipts`] for what is actually checked.
    pub fn validate_execution_receipts(&self) -> Result<(), ChainError> {
        validate_block_execution_receipts(
            &self.execution_receipts,
            &self.block.transactions,
            &self.tx_proofs,
            self.block.header.height,
            self.gas_used,
        )
    }
}

type StateChanges = (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>);

/// A trait that defines the logic and capabilities of an application-specific blockchain.
#[async_trait]
pub trait ChainStateMachine<CS, TM, ST>: ChainView<CS, ST>
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
    ) -> Result<PreparedBlock, ChainError>;

    /// Applies the state changes from a `PreparedBlock` to the canonical state.
    async fn commit_block(
        &mut self,
        prepared: PreparedBlock,
    ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError>;

    /// Constructs a new block template.
    fn create_block(
        &self,
        transactions: Vec<ChainTransaction>,
        current_validator_set: &[Vec<u8>],
        known_peers_bytes: &[Vec<u8>],
        producer_keypair: &Keypair,
        expected_timestamp: u64,
        view: u64, // <--- NEW parameter
    ) -> Result<Block<ChainTransaction>, ChainError>;

    /// Retrieves a block from the recent block cache by height.
    fn get_block(&self, height: u64) -> Option<&Block<ChainTransaction>>;
    /// Retrieves all blocks from the cache since a given height.
    fn get_blocks_since(&self, height: u64) -> Vec<Block<ChainTransaction>>;

    /// Retrieves the active validator set for a specific block height.
    async fn get_validator_set_for(&self, height: u64) -> Result<Vec<Vec<u8>>, ChainError>;

    /// Retrieves the current set of staked validators and their stakes.
    async fn get_staked_validators(
        &self,
    ) -> Result<BTreeMap<ioi_types::app::AccountId, u64>, ChainError>;

    /// Retrieves the pending next set of staked validators and their stakes.
    async fn get_next_staked_validators(
        &self,
    ) -> Result<BTreeMap<ioi_types::app::AccountId, u64>, ChainError>;
}

#[cfg(test)]
mod tests;
