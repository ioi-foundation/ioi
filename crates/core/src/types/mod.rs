// File: crates/core/src/types.rs

/// Type aliases for commitment schemes
pub mod commitment {
    use super::super::commitment::CommitmentScheme;

    /// The commitment type for a given commitment scheme
    pub type CommitmentOf<CS> = <CS as CommitmentScheme>::Commitment;

    /// The proof type for a given commitment scheme
    pub type ProofOf<CS> = <CS as CommitmentScheme>::Proof;

    /// The value type for a given commitment scheme
    pub type ValueOf<CS> = <CS as CommitmentScheme>::Value;
}

/// Type aliases for state management
pub mod state {
    use super::super::commitment::CommitmentScheme;
    use super::super::state::StateManager;

    /// Type alias for a state manager that uses a specific commitment scheme
    pub type StateManagerFor<CS>
    where
        CS: CommitmentScheme,
    = dyn StateManager<
        Commitment = <CS as CommitmentScheme>::Commitment,
        Proof = <CS as CommitmentScheme>::Proof,
    >;
}

/// Type aliases for transaction models
pub mod transaction {
    use super::super::transaction::TransactionModel;

    /// Transaction type for a transaction model
    pub type TransactionOf<TM> = <TM as TransactionModel>::Transaction;

    /// Proof type for a transaction model
    pub type ProofOf<TM> = <TM as TransactionModel>::Proof;

    /// Commitment scheme type for a transaction model
    pub type CommitmentSchemeOf<TM> = <TM as TransactionModel>::CommitmentScheme;
}
