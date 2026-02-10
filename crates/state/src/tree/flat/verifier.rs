// Path: crates/state/src/tree/flat/verifier.rs

use crate::primitives::hash::{HashCommitment, HashProof};
use ioi_api::error::StateError;
use ioi_api::state::Verifier;
use ioi_types::app::Membership;
use ioi_types::error::ProofError;

/// A dummy verifier for the Flat Store that accepts everything.
/// Security relies on the fact that the user owns the machine (Mode 0).
#[derive(Clone, Debug, Default)]
pub struct FlatVerifier;

impl Verifier for FlatVerifier {
    type Commitment = HashCommitment;
    type Proof = HashProof;

    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
        Ok(HashCommitment::new(bytes.to_vec()))
    }

    fn verify(
        &self,
        _root: &Self::Commitment,
        _proof: &Self::Proof,
        _key: &[u8],
        _outcome: &Membership,
    ) -> Result<(), ProofError> {
        Ok(())
    }
}
