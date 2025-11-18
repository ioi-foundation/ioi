// Path: crates/types/src/error/mod.rs
//! Core error types for the IOI SDK.

use crate::app::AccountId;
use thiserror::Error;

/// A trait for assigning a stable, machine-readable string code to an error.
pub trait ErrorCode {
    /// Returns the unique, stable string identifier for this error variant.
    fn code(&self) -> &'static str;
}

/// Errors related to the state tree or state manager.
#[derive(Error, Debug)]
pub enum StateError {
    /// The requested key was not found in the state.
    #[error("Key not found in state")]
    KeyNotFound,
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
    /// An error occurred during state deserialization.
    #[error("Decode error: {0}")]
    Decode(String),
    /// A proof verification failed because it did not anchor to the requested root.
    #[error("Proof did not anchor to the requested state root")]
    ProofDidNotAnchor,
    /// The provided state anchor is not known and cannot be resolved to a state root.
    #[error("The provided state anchor is not known and cannot be resolved to a state root: {0}")]
    UnknownAnchor(String),
    /// An operation was attempted on a stale state anchor.
    #[error("The provided state anchor is stale and does not match the latest known root")]
    StaleAnchor,
    /// The operation was denied due to insufficient permissions on a state key.
    #[error("Permission denied for state key: {0}")]
    PermissionDenied(String),
}

impl ErrorCode for StateError {
    fn code(&self) -> &'static str {
        match self {
            Self::KeyNotFound => "STATE_KEY_NOT_FOUND",
            Self::Validation(_) => "STATE_VALIDATION_FAILED",
            Self::Apply(_) => "STATE_APPLY_FAILED",
            Self::Backend(_) => "STATE_BACKEND_ERROR",
            Self::WriteError(_) => "STATE_WRITE_ERROR",
            Self::InvalidValue(_) => "STATE_INVALID_VALUE",
            Self::Decode(_) => "STATE_DECODE_ERROR",
            Self::ProofDidNotAnchor => "STATE_PROOF_NO_ANCHOR",
            Self::UnknownAnchor(_) => "STATE_UNKNOWN_ANCHOR",
            Self::StaleAnchor => "STATE_STALE_ANCHOR",
            Self::PermissionDenied(_) => "STATE_PERMISSION_DENIED",
        }
    }
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
    /// A generic, unspecified block validation error.
    #[error("Invalid block: {0}")]
    Invalid(String),
    /// An error occurred while calculating a block or header hash.
    #[error("Failed to hash block components: {0}")]
    Hash(String),
}

impl ErrorCode for BlockError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidHeight { .. } => "BLOCK_INVALID_HEIGHT",
            Self::MismatchedPrevHash { .. } => "BLOCK_MISMATCHED_PREV_HASH",
            Self::MismatchedValidatorSet => "BLOCK_MISMATCHED_VALIDATOR_SET",
            Self::MismatchedStateRoot { .. } => "BLOCK_MISMATCHED_STATE_ROOT",
            Self::Invalid(_) => "BLOCK_INVALID",
            Self::Hash(_) => "BLOCK_HASH_FAILED",
        }
    }
}

/// Errors related to the consensus engine.
#[derive(Debug, Error)]
pub enum ConsensusError {
    /// A proposed block failed verification.
    #[error("Block verification failed: {0}")]
    BlockVerificationFailed(String),
    /// The producer of a block was not the expected leader for the current round.
    #[error("Invalid block producer. Expected {expected:?}, got {got:?}")]
    InvalidLeader {
        /// The `AccountId` of the expected leader.
        expected: AccountId,
        /// The `AccountId` of the peer who produced the block.
        got: AccountId,
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
    /// A required component (e.g., key) was not found in state.
    #[error("Consensus dependency not found in state: {0}")]
    DependencyNotFound(String),
}

impl ErrorCode for ConsensusError {
    fn code(&self) -> &'static str {
        match self {
            Self::BlockVerificationFailed(_) => "CONSENSUS_BLOCK_VERIFICATION_FAILED",
            Self::InvalidLeader { .. } => "CONSENSUS_INVALID_LEADER",
            Self::StateAccess(_) => "CONSENSUS_STATE_ACCESS_ERROR",
            Self::ClientError(_) => "CONSENSUS_CLIENT_ERROR",
            Self::InvalidSignature => "CONSENSUS_INVALID_SIGNATURE",
            Self::DependencyNotFound(_) => "CONSENSUS_DEPENDENCY_NOT_FOUND",
        }
    }
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
        signer: libp2p::PeerId,
        /// The reason the attestation was considered invalid.
        reason: String,
    },
    /// Failed to fetch data from an external source.
    #[error("Failed to fetch external data: {0}")]
    DataFetchFailed(String),
}

impl ErrorCode for OracleError {
    fn code(&self) -> &'static str {
        match self {
            Self::RequestNotFound(_) => "ORACLE_REQUEST_NOT_FOUND",
            Self::QuorumNotMet { .. } => "ORACLE_QUORUM_NOT_MET",
            Self::InvalidAttestation { .. } => "ORACLE_INVALID_ATTESTATION",
            Self::DataFetchFailed(_) => "ORACLE_DATA_FETCH_FAILED",
        }
    }
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
        signer: libp2p::PeerId,
        /// A description of the signature error.
        error: String,
    },
    /// The signer's public key could not be determined from the provided signature.
    #[error("Signer's public key could not be determined from the provided signature")]
    InvalidSigner,
    /// The governance key, required to authorize certain actions, was not found in the state.
    #[error("Governance key not found in state")]
    GovernanceKeyNotFound,
    /// A general validation error occurred.
    #[error("Invalid governance operation: {0}")]
    Invalid(String),
}

impl ErrorCode for GovernanceError {
    fn code(&self) -> &'static str {
        match self {
            Self::ProposalNotFound(_) => "GOVERNANCE_PROPOSAL_NOT_FOUND",
            Self::NotVotingPeriod => "GOVERNANCE_NOT_VOTING_PERIOD",
            Self::InvalidSignature { .. } => "GOVERNANCE_INVALID_SIGNATURE",
            Self::InvalidSigner => "GOVERNANCE_INVALID_SIGNER",
            Self::GovernanceKeyNotFound => "GOVERNANCE_KEY_NOT_FOUND",
            Self::Invalid(_) => "GOVERNANCE_INVALID_OPERATION",
        }
    }
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

impl ErrorCode for RpcError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidParams(_) => "RPC_INVALID_PARAMS",
            Self::InternalError(_) => "RPC_INTERNAL_ERROR",
            Self::TransactionSubmissionFailed(_) => "RPC_TX_SUBMISSION_FAILED",
        }
    }
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
    /// The transaction's fee was insufficient.
    #[error("Insufficient fee")]
    InsufficientFee,
    /// The account has insufficient funds to cover the transaction amount.
    #[error("Insufficient funds")]
    InsufficientFunds,

    /// The transaction nonce does not match the expected nonce for the account.
    #[error("Nonce mismatch. Expected: {expected}, Got: {got}")]
    NonceMismatch {
        /// The expected nonce from the on-chain state.
        expected: u64,
        /// The nonce provided in the transaction.
        got: u64,
    },
    /// The signature failed cryptographic verification.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    /// The signer's key is no longer valid for signing transactions (e.g., after a key rotation grace period).
    #[error("The key used for signing has expired")]
    ExpiredKey,
    /// The signer's key is not authorized by the account's on-chain credentials.
    #[error("Signer is not authorized by on-chain credentials")]
    UnauthorizedByCredentials,
    /// The AccountId in the transaction header does not correspond to the public key used for signing.
    #[error("The account ID in the header does not match the public key in the proof")]
    AccountIdMismatch,
    /// The transaction type requires a service that is not enabled on the chain.
    #[error("Unsupported transaction type: {0}")]
    Unsupported(String),
}

impl ErrorCode for TransactionError {
    fn code(&self) -> &'static str {
        match self {
            Self::Serialization(_) => "TX_SERIALIZATION_ERROR",
            Self::Deserialization(_) => "TX_DESERIALIZATION_ERROR",
            Self::Invalid(_) => "TX_INVALID",
            Self::Governance(_) => "TX_GOVERNANCE_ERROR",
            Self::Oracle(_) => "TX_ORACLE_ERROR",
            Self::State(_) => "TX_STATE_ERROR",
            Self::InsufficientFee => "TX_INSUFFICIENT_FEE",
            Self::InsufficientFunds => "TX_INSUFFICIENT_FUNDS",
            Self::NonceMismatch { .. } => "TX_NONCE_MISMATCH",
            Self::InvalidSignature(_) => "TX_INVALID_SIGNATURE",
            Self::ExpiredKey => "TX_EXPIRED_KEY",
            Self::UnauthorizedByCredentials => "TX_UNAUTHORIZED_BY_CREDENTIALS",
            Self::AccountIdMismatch => "TX_ACCOUNT_ID_MISMATCH",
            Self::Unsupported(_) => "TX_UNSUPPORTED",
        }
    }
}

impl From<CryptoError> for TransactionError {
    fn from(e: CryptoError) -> Self {
        TransactionError::Invalid(format!("Cryptographic operation failed: {}", e))
    }
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
        TransactionError::State(StateError::Decode(e.to_string()))
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

impl ErrorCode for VmError {
    fn code(&self) -> &'static str {
        match self {
            Self::Initialization(_) => "VM_INITIALIZATION_FAILED",
            Self::InvalidBytecode(_) => "VM_INVALID_BYTECODE",
            Self::ExecutionTrap(_) => "VM_EXECUTION_TRAP",
            Self::FunctionNotFound(_) => "VM_FUNCTION_NOT_FOUND",
            Self::HostError(_) => "VM_HOST_ERROR",
            Self::MemoryError(_) => "VM_MEMORY_ERROR",
        }
    }
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
    /// An error occurred during IPC communication.
    #[error("IPC error: {0}")]
    Ipc(String),
    /// The agentic attestation check failed.
    #[error("Agentic attestation failed: {0}")]
    Attestation(String),
}

impl ErrorCode for ValidatorError {
    fn code(&self) -> &'static str {
        match self {
            Self::AlreadyRunning(_) => "VALIDATOR_ALREADY_RUNNING",
            Self::Io(_) => "VALIDATOR_IO_ERROR",
            Self::Config(_) => "VALIDATOR_CONFIG_ERROR",
            Self::Vm(_) => "VALIDATOR_VM_ERROR",
            Self::State(_) => "VALIDATOR_STATE_ERROR",
            Self::Other(_) => "VALIDATOR_OTHER_ERROR",
            Self::Ipc(_) => "VALIDATOR_IPC_ERROR",
            Self::Attestation(_) => "VALIDATOR_ATTESTATION_FAILED",
        }
    }
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
    /// A system time error occurred.
    #[error("System time error: {0}")]
    Time(String),
    /// An attempt was made to resolve an unknown or pruned state anchor.
    #[error("Could not resolve unknown state anchor: {0}")]
    UnknownStateAnchor(String),
}

impl ErrorCode for ChainError {
    fn code(&self) -> &'static str {
        match self {
            Self::Block(_) => "CHAIN_BLOCK_ERROR",
            Self::Transaction(_) => "CHAIN_TRANSACTION_ERROR",
            Self::State(_) => "CHAIN_STATE_ERROR",
            Self::Time(_) => "CHAIN_TIME_ERROR",
            Self::UnknownStateAnchor(_) => "CHAIN_UNKNOWN_ANCHOR",
        }
    }
}

impl From<TransactionError> for ChainError {
    fn from(err: TransactionError) -> Self {
        ChainError::Transaction(err.to_string())
    }
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

impl ErrorCode for UpgradeError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidUpgrade(_) => "UPGRADE_INVALID",
            Self::MigrationFailed(_) => "UPGRADE_MIGRATION_FAILED",
            Self::ServiceNotFound => "UPGRADE_SERVICE_NOT_FOUND",
            Self::HealthCheckFailed(_) => "UPGRADE_HEALTH_CHECK_FAILED",
            Self::OperationFailed(_) => "UPGRADE_OPERATION_FAILED",
        }
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
    Upgrade(#[from] UpgradeError),
    /// A custom, unspecified error.
    #[error("Custom error: {0}")]
    Custom(String),
    /// The requested feature is not yet implemented.
    #[error("Feature not implemented")]
    NotImplemented,
    /// An error originating from a cryptographic operation.
    #[error("Crypto error: {0}")]
    Crypto(String),
}

impl ErrorCode for CoreError {
    fn code(&self) -> &'static str {
        match self {
            Self::ServiceNotFound(_) => "CORE_SERVICE_NOT_FOUND",
            Self::Upgrade(_) => "CORE_UPGRADE_ERROR",
            Self::Custom(_) => "CORE_CUSTOM_ERROR",
            Self::NotImplemented => "CORE_NOT_IMPLEMENTED",
            Self::Crypto(_) => "CORE_CRYPTO_ERROR",
        }
    }
}

impl From<CryptoError> for CoreError {
    fn from(e: CryptoError) -> Self {
        CoreError::Crypto(e.to_string())
    }
}

impl From<prost::DecodeError> for CoreError {
    fn from(e: prost::DecodeError) -> Self {
        CoreError::Custom(format!("Protobuf decoding error: {}", e))
    }
}

impl From<StateError> for CoreError {
    fn from(e: StateError) -> Self {
        CoreError::Custom(format!("State error: {}", e))
    }
}

impl From<String> for CoreError {
    fn from(s: String) -> Self {
        CoreError::Custom(s)
    }
}

/// Errors from cryptographic operations.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// The signature failed cryptographic verification.
    #[error("Signature verification failed")]
    VerificationFailed,
    /// The provided key material is malformed or invalid for the specified algorithm.
    #[error("Invalid cryptographic key: {0}")]
    InvalidKey(String),
    /// The provided signature material is malformed or invalid for the specified algorithm.
    #[error("Invalid signature format: {0}")]
    InvalidSignature(String),
    /// A hash digest had an unexpected length.
    #[error("Invalid hash length: expected {expected}, got {got}")]
    InvalidHashLength {
        /// The expected length in bytes.
        expected: usize,
        /// The actual length in bytes.
        got: usize,
    },
    /// An error occurred during deserialization of a cryptographic object.
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    /// A generic failure in an underlying cryptographic library.
    #[error("Cryptographic operation failed: {0}")]
    OperationFailed(String),
    /// The requested cryptographic operation or parameter is not supported by the current context.
    #[error("Unsupported cryptographic operation or parameter: {0}")]
    Unsupported(String),
    /// A Key Encapsulation Mechanism (KEM) failed to decapsulate a shared secret.
    #[error("Decapsulation of shared secret failed")]
    DecapsulationFailed,
    /// The Structured Reference String (SRS) used for a proof does not match the one used for verification.
    #[error("SRS mismatch between witness and parameters")]
    SrsMismatch,
    /// An input to a cryptographic operation was invalid.
    #[error("Invalid input for operation: {0}")]
    InvalidInput(String),
    /// A custom, unspecified cryptographic error.
    #[error("Custom crypto error: {0}")]
    Custom(String),
}

impl ErrorCode for CryptoError {
    fn code(&self) -> &'static str {
        match self {
            Self::VerificationFailed => "CRYPTO_VERIFICATION_FAILED",
            Self::InvalidKey(_) => "CRYPTO_INVALID_KEY",
            Self::InvalidSignature(_) => "CRYPTO_INVALID_SIGNATURE",
            Self::InvalidHashLength { .. } => "CRYPTO_INVALID_HASH_LENGTH",
            Self::Deserialization(_) => "CRYPTO_DESERIALIZATION_ERROR",
            Self::OperationFailed(_) => "CRYPTO_OPERATION_FAILED",
            Self::Unsupported(_) => "CRYPTO_UNSUPPORTED",
            Self::DecapsulationFailed => "CRYPTO_DECAPSULATION_FAILED",
            Self::SrsMismatch => "CRYPTO_SRS_MISMATCH",
            Self::InvalidInput(_) => "CRYPTO_INVALID_INPUT",
            Self::Custom(_) => "CRYPTO_CUSTOM_ERROR",
        }
    }
}

impl From<dcrypt::Error> for CryptoError {
    fn from(e: dcrypt::Error) -> Self {
        CryptoError::OperationFailed(e.to_string())
    }
}

/// Errors that can occur during proof verification.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    /// An error occurred during proof deserialization.
    #[error("Proof deserialization failed: {0}")]
    Deserialization(String),
    /// The recomputed root hash from the proof did not match the trusted root.
    #[error("Root hash mismatch")]
    RootMismatch,
    /// A proof of non-existence was structurally invalid.
    #[error("Invalid non-existence proof: {0}")]
    InvalidNonExistence(String),
    /// A proof of existence was structurally invalid.
    #[error("Invalid existence proof: {0}")]
    InvalidExistence(String),
    /// A cryptographic operation during verification failed.
    #[error("Crypto error during proof verification: {0}")]
    Crypto(String),
    /// A proof's hash length was invalid.
    #[error("Invalid hash length: expected {expected}, got {got}")]
    InvalidHashLength {
        /// The expected length in bytes.
        expected: usize,
        /// The actual length in bytes.
        got: usize,
    },
}

impl ErrorCode for ProofError {
    fn code(&self) -> &'static str {
        match self {
            Self::Deserialization(_) => "PROOF_DESERIALIZATION_FAILED",
            Self::RootMismatch => "PROOF_ROOT_MISMATCH",
            Self::InvalidNonExistence(_) => "PROOF_INVALID_NON_EXISTENCE",
            Self::InvalidExistence(_) => "PROOF_INVALID_EXISTENCE",
            Self::Crypto(_) => "PROOF_CRYPTO_ERROR",
            Self::InvalidHashLength { .. } => "PROOF_INVALID_HASH_LENGTH",
        }
    }
}

// Add this implementation to allow `?` to convert prost errors.
impl From<prost::EncodeError> for ProofError {
    fn from(e: prost::EncodeError) -> Self {
        ProofError::Deserialization(format!("Prost encode error: {}", e))
    }
}