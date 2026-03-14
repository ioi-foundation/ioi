use crate::primitives::hash::{HashCommitment, HashCommitmentScheme, HashProof};
use crate::tree::sparse_merkle::{SparseMerkleProof, SparseMerkleTree};
use ioi_api::error::StateError;
use ioi_api::state::Verifier;
use ioi_types::app::Membership;
use ioi_types::error::ProofError;
use parity_scale_codec::Decode;

#[derive(Clone, Debug, Default)]
pub struct SparseMerkleVerifier;

impl Verifier for SparseMerkleVerifier {
    type Commitment = HashCommitment;
    type Proof = HashProof;

    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
        Ok(HashCommitment::new(bytes.to_vec()))
    }

    fn verify(
        &self,
        root: &Self::Commitment,
        proof_obj: &Self::Proof,
        key: &[u8],
        outcome: &Membership,
    ) -> Result<(), ProofError> {
        let smt_proof = SparseMerkleProof::decode(&mut &*proof_obj.value()).map_err(|e| {
            log::warn!(
                "Failed to deserialize SparseMerkleProof from proof data during verification: {}",
                e
            );
            ProofError::Deserialization(e.to_string())
        })?;

        let value_to_verify = match outcome {
            Membership::Present(value) => Some(value.as_slice()),
            Membership::Absent => None,
        };

        match SparseMerkleTree::<HashCommitmentScheme>::verify_proof_static(
            root.as_ref(),
            key,
            value_to_verify,
            &smt_proof,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ProofError::RootMismatch),
            Err(err) => {
                log::warn!(
                    "[SMTVerifier] Proof verification failed with error: {}",
                    err
                );
                Err(err)
            }
        }
    }
}
