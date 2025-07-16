//! State management interfaces for the DePIN SDK Core.

mod manager;
mod tree;

#[cfg(test)]
mod tests;

pub use manager::*;
pub use tree::*;

use crate::commitment::CommitmentScheme;

/// Type alias for a StateManager compatible with a specific CommitmentScheme
pub type StateManagerFor<CS> = dyn StateManager<
    Commitment = <CS as CommitmentScheme>::Commitment,
    Proof = <CS as CommitmentScheme>::Proof,
>;

/// Type alias for a StateTree compatible with a specific CommitmentScheme
pub type StateTreeFor<CS> = dyn StateTree<
    Commitment = <CS as CommitmentScheme>::Commitment,
    Proof = <CS as CommitmentScheme>::Proof,
>;
