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
    let proof: VerklePathProof = match bincode::deserialize(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if &proof.params_id != params_id_expected {
        return false;
    }
    if proof.node_commitments.is_empty() {
        return false;
    }
    if proof.node_commitments.len() != proof.per_level_proofs.len() + 1 {
        return false;
    }
    if proof.per_level_selectors.len() != proof.per_level_proofs.len() {
        return false;
    }
    if root_commitment.as_ref() != proof.node_commitments[0].as_slice() {
        return false;
    }

    let levels = proof.per_level_proofs.len();
    // The path cannot be deeper than the provided key.
    if key_path.len() < levels {
        return false;
    }

    // --- Bind selectors to the key ---
    match &proof.terminal {
        // Presence: we must have walked the full key, and every selector must match the key byte.
        Terminal::Leaf(_payload) => {
            if key_path.len() != levels {
                return false;
            }
            for (j, key_byte) in key_path.iter().enumerate().take(levels) {
                if proof.per_level_selectors[j] != *key_byte as u32 {
                    return false;
                }
            }
        }

        // Empty: walked up to the terminating empty slot; all selectors must match key bytes so far.
        Terminal::Empty => {
            for (j, key_byte) in key_path.iter().enumerate().take(levels) {
                if proof.per_level_selectors[j] != *key_byte as u32 {
                    return false;
                }
            }
        }

        // Neighbor: at the final level, we may open the neighbor slot instead of the query slot.
        Terminal::Neighbor { key_stem, .. } => {
            if levels == 0 {
                return false;
            }
            // Common prefix before divergence must match both key_path and key_stem.
            let common = levels - 1;
            if key_path.len() < levels || key_stem.len() < levels {
                return false;
            }
            for (j, (key_byte, stem_byte)) in key_path
                .iter()
                .zip(key_stem.iter())
                .enumerate()
                .take(common)
            {
                let sel = proof.per_level_selectors[j];
                if sel != *key_byte as u32 || sel != *stem_byte as u32 {
                    return false;
                }
            }
            // Final opening must be at the neighbor slot, not the query slot.
            let sel_last = proof.per_level_selectors[common];
            if sel_last != key_stem[common] as u32 {
                return false;
            }
            if sel_last == key_path[common] as u32 {
                return false;
            }
        }
    }
    // --- end selector binding checks ---

    // (existing pairing checks follow unchanged)
    for j in 0..levels {
        let commitment_bytes = &proof.node_commitments[j];
        let commitment: CS::Commitment = commitment_bytes.clone().into();
        let proof_bytes_for_level = &proof.per_level_proofs[j];
        let proof_for_level: CS::Proof = proof_bytes_for_level.clone().into();
        // MODIFICATION: Cast selector position to u64.
        let selector = Selector::Position(proof.per_level_selectors[j] as u64);

        let value_bytes = if j == levels - 1 {
            match &proof.terminal {
                Terminal::Leaf(payload) | Terminal::Neighbor { payload, .. } => {
                    map_leaf_payload_to_value(payload)
                }
                Terminal::Empty => map_child_commitment_to_value(&proof.node_commitments[j + 1]),
            }
        } else {
            map_child_commitment_to_value(&proof.node_commitments[j + 1])
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

    // Keep the existing neighbor sanity check
    if let Terminal::Neighbor { key_stem, .. } = &proof.terminal {
        if key_path.starts_with(key_stem) {
            return false;
        }
    }

    true
}