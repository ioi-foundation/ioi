// Path: crates/commitment/src/tree/verkle/verify.rs
use super::proof::{
    map_child_commitment_to_value, map_leaf_payload_to_value, SchemeId, Terminal, VerklePathProof,
};
use depin_sdk_api::commitment::{CommitmentScheme, ProofContext, Selector};

/// Verifies a serialized Verkle path proof against a root commitment.
pub fn verify_path_with_scheme<CS: CommitmentScheme>(
    scheme: &CS,
    root_commitment: &CS::Commitment,
    params_id_expected: &SchemeId,
    key_path: &[u8],
    proof_bytes: &[u8],
) -> bool
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: From<Vec<u8>>,
    CS::Value: From<Vec<u8>>,
{
    // FIX: Deserialize the proof structure at the beginning.
    let proof: VerklePathProof = match bincode::deserialize(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // 2. Perform sanity checks on the deserialized proof structure.
    if &proof.params_id != params_id_expected {
        return false;
    }
    if proof.node_commitments.is_empty() {
        return false;
    }
    if proof.node_commitments.len() != proof.per_level_proofs.len() + 1 {
        return false;
    }
    if root_commitment.as_ref() != proof.node_commitments[0].as_slice() {
        return false;
    }

    // 3. Verify each level of the proof using the deserialized fields.
    for (j, commitment_bytes) in proof.node_commitments[..proof.node_commitments.len() - 1]
        .iter()
        .enumerate()
    {
        let commitment: CS::Commitment = commitment_bytes.clone().into();
        let proof_bytes_for_level = &proof.per_level_proofs[j];
        let proof_for_level: CS::Proof = proof_bytes_for_level.clone().into();

        let selector = Selector::Position(key_path[j] as usize);

        let value_bytes = if j < proof.node_commitments.len() - 1 {
            // FIX: Access `node_commitments` from the deserialized `proof` struct.
            map_child_commitment_to_value(&proof.node_commitments[j + 1])
        } else {
            // FIX: Access `terminal` from the deserialized `proof` struct.
            match &proof.terminal {
                // FIX: Correctly borrow `payload` which is already a Vec<u8>.
                Terminal::Leaf(payload) => map_leaf_payload_to_value(payload),
                Terminal::Empty => [0u8; 32],
                Terminal::Neighbor { payload, .. } => map_leaf_payload_to_value(payload),
            }
        };
        let value: CS::Value = value_bytes.to_vec().into();

        if !scheme.verify(
            &commitment,
            &proof_for_level,
            &selector,
            &value,
            &ProofContext::default(),
        ) {
            return false;
        }
    }

    // Final check for non-membership proofs
    if let Terminal::Neighbor { key_stem, .. } = &proof.terminal {
        if key_path.starts_with(key_stem) {
            return false; // Key path matches neighbor's stem, proof is invalid.
        }
    }

    true
}
