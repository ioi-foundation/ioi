// Path: crates/api/src/state/commitment.rs
//! Defines the `VerifiableState` trait for data structures that produce a cryptographic commitment.

use std::any::Any;
use std::fmt::Debug;

/// A trait for any stateful data structure that can produce a single, verifiable
/// cryptographic commitment (e.g., a Merkle root) over its entire state.
///
/// This trait isolates the commitment generation logic from key-value access and
/// proof generation, allowing components to depend only on the capabilities they need.
pub trait VerifiableState: Debug + Send + Sync + 'static {
    /// The commitment type (e.g., a hash or an elliptic curve point).
    type Commitment: Clone + Send + Sync + 'static;

    /// The proof type (e.g., a Merkle proof or a Verkle proof).
    /// Although proof methods are in the `ProofProvider` trait, the associated type
    /// lives here as `Commitment` and `Proof` are fundamentally linked.
    type Proof: Clone + Send + Sync + 'static;

    /// Gets the root commitment of the state.
    fn root_commitment(&self) -> Self::Commitment;

    /// Provides access to the concrete type for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Provides mutable access to the concrete type for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

// Blanket implementation to allow `VerifiableState` to be used behind a `Box` trait object.
impl<T: VerifiableState + ?Sized> VerifiableState for Box<T> {
    type Commitment = T::Commitment;
    type Proof = T::Proof;

    fn root_commitment(&self) -> Self::Commitment {
        (**self).root_commitment()
    }

    fn as_any(&self) -> &dyn Any {
        (**self).as_any()
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        (**self).as_any_mut()
    }
}