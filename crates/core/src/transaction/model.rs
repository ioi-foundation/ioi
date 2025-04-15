//! Definition of the TransactionModel trait

use crate::commitment::CommitmentScheme;
use crate::state::StateManager;

/// Error type for transaction operations
#[derive(Debug)]
pub enum Error {
    /// Invalid transaction
    Invalid(String),
    /// Insufficient funds
    InsufficientFunds,
    /// Nonce mismatch
    NonceMismatch,
    /// Invalid signature
    InvalidSignature,
    /// Other error
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Invalid(msg) => write!(f, "Invalid transaction: {}", msg),
            Error::InsufficientFunds => write!(f, "Insufficient funds"),
            Error::NonceMismatch => write!(f, "Nonce mismatch"),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::Other(msg) => write!(f, "Other error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

/// Transaction model trait
pub trait TransactionModel<CS: CommitmentScheme> {
    /// Transaction type
    type Transaction;
    
    /// Proof type
    type Proof;
    
    /// Validate a transaction against a state commitment
    fn validate(&self, tx: &Self::Transaction, commitment: &CS::Commitment) -> bool;
    
    /// Apply a transaction to the state
    fn apply(&self, tx: &Self::Transaction, state: &mut dyn StateManager<CS>) -> Result<(), String>;
}
