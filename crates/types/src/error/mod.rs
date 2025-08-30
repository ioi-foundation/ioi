// Path: crates/types/src/error/mod.rs
//! Core error types for the DePIN SDK.

use libp2p::PeerId;
use thiserror::Error;

/// Errors related to the state tree or state manager.
#[derive(Error, Debug)]
pub enum StateError {
    /// The requested key was not found in the state.
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    /// State validation failed.
    #[error("Validation failed: {0}")]
    Validation(String),
    /// Applying a state change failed.
    #[error("Apply failed: {0}")]
    Apply(String),
    /// An error occurred in the state backend.
    #[error("State backend error: {0}")]
    Backend(String),
    /// An error occurred while writing to the state.
    #[error("State write error: {0}")]
    WriteError(String),
    /// The provided value was invalid.
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

/// Errors related to block processing.
#[derive(Debug, Error)]
pub enum BlockError {
    /// The block's height is incorrect.
    #[error("Invalid block height. Expected {expected}, got {got}")]
    InvalidHeight {
        /// The expected block height.
        expected: u64,
        /// The height of the received block.
        got: u64,
    },
    /// The block's `prev_hash` does not match the hash of the previous block.
    #[error("Mismatched previous block hash. Expected {expected}, got {got}")]
    MismatchedPrevHash {
        /// The expected hash of the previous block.
        expected: String,
        /// The `prev_hash` from the received block.
        got: String,
    },
    /// The validator set in the block header does not match the expected set.
    #[error("Mismatched validator set")]
    MismatchedValidatorSet,
    /// The state root in the block header does not match the calculated state root.
    #[error("Mismatched state root. Expected {expected}, got {got}")]
    MismatchedStateRoot {
        /// The expected state root hash.
        expected: String,
        /// The state root from the received block.
        got: String,
    },
}

/// Errors related to the consensus engine.
#[derive(Debug, Error)]
pub enum ConsensusError {
    /// A proposed block failed verification.
    #[error("Block verification failed: {0}")]
    BlockVerificationFailed(String),
    /// The producer of a block was not the expected leader for the current round.
    #[error("Invalid block producer. Expected {expected}, got {got}")]
    InvalidLeader {
        /// The `PeerId` of the expected leader.
        expected: PeerId,
        /// The `PeerId` of the peer who produced the block.
        got: PeerId,
    },
    /// An error occurred while accessing the state.
    #[error("State access error: {0}")]
    StateAccess(#[from] StateError),
    /// An error occurred in the workload client.
    #[error("Workload client error: {0}")]
    ClientError(String),
    /// A signature in a consensus message was invalid.
    #[error("Invalid signature in consensus message")]
    InvalidSignature,
}

/// Errors related to the oracle service.
#[derive(Debug, Error)]
pub enum OracleError {
    /// The specified oracle request was not found or has already been processed.
    #[error("Oracle request not found or already processed: {0}")]
    RequestNotFound(u64),
    /// The total stake of validators who submitted attestations did not meet the required quorum.
    #[error("Quorum not met. Attested stake: {attested_stake}, Required: {required}")]
    QuorumNotMet {
        /// The total stake that attested.
        attested_stake: u64,
        /// The required stake for quorum.
        required: u64,
    },
    /// An attestation from a validator was invalid.
    #[error("Invalid attestation from signer {signer}: {reason}")]
    InvalidAttestation {
        /// The `PeerId` of the validator who sent the invalid attestation.
        signer: PeerId,
        /// The reason the attestation was considered invalid.
        reason: String,
    },
    /// Failed to fetch data from an external source.
    #[error("Failed to fetch external data: {0}")]
    DataFetchFailed(String),
}

/// Errors related to the governance service.
#[derive(Debug, Error)]
pub enum GovernanceError {
    /// The specified proposal ID does not exist.
    #[error("Proposal with ID {0} not found")]
    ProposalNotFound(u64),
    /// The proposal is not currently in its voting period.
    #[error("Proposal is not in its voting period")]
    NotVotingPeriod,
    /// A signature on a governance transaction (e.g., a vote) was invalid.
    #[error("Invalid signature from signer {signer}: {error}")]
    InvalidSignature {
        /// The `PeerId` of the signer.
        signer: PeerId,
        /// A description of the signature error.
        error: String,
    },
    /// The signer's public key could not be determined from the provided signature.
    #[error("Signer's public key could not be determined from the provided signature")]
    InvalidSigner,
    /// The governance key, required to authorize certain actions, was not found in the state.
    #[error("Governance key not found in state")]
    GovernanceKeyNotFound,
}

/// Errors related to the JSON-RPC server.
#[derive(Debug, Error)]
pub enum RpcError {
    /// The parameters provided in the RPC request were invalid.
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),
    /// An internal error occurred while processing the RPC request.
    #[error("Internal RPC error: {0}")]
    InternalError(String),
    /// The transaction submitted via RPC was rejected.
    #[error("Transaction submission failed: {0}")]
    TransactionSubmissionFailed(String),
}

/// Errors related to transaction processing.
#[derive(Error, Debug)]
pub enum TransactionError {
    /// An error occurred during serialization.
    #[error("Serialization error: {0}")]
    Serialization(String),
    /// An error occurred during deserialization.
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    /// The transaction is invalid for a model-specific reason.
    #[error("Invalid transaction: {0}")]
    Invalid(String),
    /// An error originating from the governance module.
    #[error("Governance error: {0}")]
    Governance(#[from] GovernanceError),
    /// An error originating from the oracle module.
    #[error("Oracle error: {0}")]
    Oracle(#[from] OracleError),
    /// An error originating from the state manager.
    #[error("State error: {0}")]
    State(#[from] StateError),
}

impl From<bcs::Error> for TransactionError {
    fn from(e: bcs::Error) -> Self {
        TransactionError::Serialization(e.to_string())
    }
}

impl From<serde_json::Error> for TransactionError {
    fn from(e: serde_json::Error) -> Self {
        TransactionError::Serialization(e.to_string())
    }
}

impl From<String> for TransactionError {
    fn from(s: String) -> Self {
        TransactionError::Invalid(s)
    }
}

impl From<prost::DecodeError> for TransactionError {
    fn from(e: prost::DecodeError) -> Self {
        TransactionError::Deserialization(e.to_string())
    }
}

impl From<parity_scale_codec::Error> for TransactionError {
    fn from(e: parity_scale_codec::Error) -> Self {
        TransactionError::State(StateError::InvalidValue(e.to_string()))
    }
}

impl From<libp2p::identity::DecodingError> for TransactionError {
    fn from(e: libp2p::identity::DecodingError) -> Self {
        TransactionError::Deserialization(e.to_string())
    }
}

/// Errors related to the virtual machine and contract execution.
#[derive(Error, Debug)]
pub enum VmError {
    /// The VM failed to initialize.
    #[error("VM initialization failed: {0}")]
    Initialization(String),
    /// The provided contract bytecode was invalid.
    #[error("Invalid bytecode: {0}")]
    InvalidBytecode(String),
    /// The contract execution trapped (e.g., out of gas, memory access error).
    #[error("Execution trapped (out of gas, memory access error, etc.): {0}")]
    ExecutionTrap(String),
    /// The requested function was not found in the contract.
    #[error("Function not found in contract: {0}")]
    FunctionNotFound(String),
    /// An error occurred within a host function called by the contract.
    #[error("Host function error: {0}")]
    HostError(String),
    /// A memory allocation or access error occurred within the VM.
    #[error("Memory allocation/access error in VM: {0}")]
    MemoryError(String),
}

/// Errors related to the validator and its containers.
#[derive(Error, Debug)]
pub enum ValidatorError {
    /// The container is already running.
    #[error("Container '{0}' is already running")]
    AlreadyRunning(String),
    /// An I/O error occurred.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// A configuration error occurred.
    #[error("Configuration error: {0}")]
    Config(String),
    /// An error occurred during VM execution.
    #[error("VM execution error: {0}")]
    Vm(#[from] VmError),
    /// An error occurred in the state manager.
    #[error("State error: {0}")]
    State(#[from] StateError),
    /// A miscellaneous validator error.
    #[error("Other error: {0}")]
    Other(String),
}

/// Errors related to blockchain-level processing.
#[derive(Debug, Error)]
pub enum ChainError {
    /// An error occurred during block processing.
    #[error("Block processing error: {0}")]
    Block(#[from] BlockError),
    /// An error occurred during transaction processing.
    #[error("Transaction processing error: {0}")]
    Transaction(String),
    /// An error occurred in the state manager.
    #[error("State error: {0}")]
    State(#[from] StateError),
}

/// Implement the conversion from TransactionError to ChainError.
impl From<TransactionError> for ChainError {
    fn from(err: TransactionError) -> Self {
        ChainError::Transaction(err.to_string())
    }
}

/// General errors for core SDK services.
#[derive(Debug, Error)]
pub enum CoreError {
    /// The requested service was not found.
    #[error("Service not found: {0}")]
    ServiceNotFound(String),
    /// An error occurred during a service upgrade.
    #[error("Upgrade error: {0}")]
    UpgradeError(String),
    /// A custom, unspecified error.
    #[error("Custom error: {0}")]
    Custom(String),
}

/// Errors related to service upgrades.
#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    /// The provided upgrade data (e.g., WASM blob) was invalid.
    #[error("Invalid upgrade: {0}")]
    InvalidUpgrade(String),
    /// The service failed to migrate its state to the new version.
    #[error("State migration failed: {0}")]
    MigrationFailed(String),
    /// The service to be upgraded was not found.
    #[error("Service not found")]
    ServiceNotFound,
    /// The service's health check failed after an upgrade.
    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),
    /// A service operation (e.g., start, stop) failed.
    #[error("Service operation failed: {0}")]
    OperationFailed(String),
}
