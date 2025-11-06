// Path: crates/api/src/types/mod.rs
// Change: Removed the `where` clause from the StateManagerFor type alias.

//! Type aliases and common types for the IOI SDK

use crate::commitment::CommitmentScheme;
use crate::state::StateManager;
use crate::transaction::TransactionModel;

/// Type aliases for commitment schemes.
pub mod commitment {
    use super::*;

    /// The commitment type for a given commitment scheme.
    pub type CommitmentOf<CS> = <CS as CommitmentScheme>::Commitment;

    /// The proof type for a given commitment scheme.
    pub type ProofOf<CS> = <CS as CommitmentScheme>::Proof;

    /// The value type for a given commitment scheme.
    pub type ValueOf<CS> = <CS as CommitmentScheme>::Value;
}

/// Type aliases for state management.
pub mod state {
    use super::*;

    /// Type alias for a `StateManager` trait object that is compatible with a
    /// specific `CommitmentScheme`. This is now unambiguous because `StateManager`
    /// inherits its associated types directly from its `StateCommitment` supertrait.
    pub type StateManagerFor<CS> = dyn StateManager<
        Commitment = <CS as CommitmentScheme>::Commitment,
        Proof = <CS as CommitmentScheme>::Proof,
    >;
}

/// Type aliases for transaction models.
pub mod transaction {
    use super::*;

    /// The transaction type for a given transaction model.
    pub type TransactionOf<TM> = <TM as TransactionModel>::Transaction;

    /// The proof type for a given transaction model.
    pub type ProofOf<TM> = <TM as TransactionModel>::Proof;

    /// The commitment scheme type for a given transaction model.
    pub type CommitmentSchemeOf<TM> = <TM as TransactionModel>::CommitmentScheme;
}