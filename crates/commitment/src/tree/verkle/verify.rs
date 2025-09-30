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
    // FIX: Use .get() to access the first element safely.
    if !proof
        .node_commitments
        .get(0)
        .is_some_and(|c| c.as_slice() == root_commitment.as_ref())
    {
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
                // FIX: Use .get() for safe access.
                if !proof
                    .per_level_selectors
                    .get(j)
                    .is_some_and(|&sel| sel == *key_byte as u32)
                {
                    return false;
                }
            }
        }

        // Empty: walked up to the terminating empty slot; all selectors must match key bytes so far.
        Terminal::Empty => {
            for (j, key_byte) in key_path.iter().enumerate().take(levels) {
                // FIX: Use .get() for safe access.
                if !proof
                    .per_level_selectors
                    .get(j)
                    .is_some_and(|&sel| sel == *key_byte as u32)
                {
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
                // FIX: Use .get() for safe access.
                let Some(&sel) = proof.per_level_selectors.get(j) else {
                    return false;
                };
                if sel != *key_byte as u32 || sel != *stem_byte as u32 {
                    return false;
                }
            }
            // Final opening must be at the neighbor slot, not the query slot.
            // FIX: Use .get() for safe access.
            let Some(&sel_last) = proof.per_level_selectors.get(common) else {
                return false;
            };
            // FIX: Use .get() for safe access.
            let Some(&stem_byte_last) = key_stem.get(common) else {
                return false;
            };
            if sel_last != stem_byte_last as u32 {
                return false;
            }
            // FIX: Use .get() for safe access.
            if proof
                .per_level_selectors
                .get(common)
                .zip(key_path.get(common))
                .is_some_and(|(sel, key_byte)| *sel == *key_byte as u32)
            {
                return false;
            }
        }
    }
    // --- end selector binding checks ---

    // (existing pairing checks follow unchanged)
    for j in 0..levels {
        // FIX: Use .get() for safe access on all indexed vectors.
        let (Some(commitment_bytes), Some(proof_bytes_for_level), Some(&selector_pos)) = (
            proof.node_commitments.get(j),
            proof.per_level_proofs.get(j),
            proof.per_level_selectors.get(j),
        ) else {
            return false;
        };
        let commitment: CS::Commitment = commitment_bytes.clone().into();
        let proof_for_level: CS::Proof = proof_bytes_for_level.clone().into();
        // MODIFICATION: Cast selector position to u64.
        let selector = Selector::Position(selector_pos as u64);

        let value_bytes_result = if j == levels - 1 {
            match &proof.terminal {
                Terminal::Leaf(payload) | Terminal::Neighbor { payload, .. } => {
                    map_leaf_payload_to_value(payload)
                }
                // FIX: Use .get() for safe access.
                Terminal::Empty => match proof.node_commitments.get(j + 1) {
                    Some(c) => map_child_commitment_to_value(c),
                    None => return false,
                },
            }
        } else {
            // FIX: Use .get() for safe access.
            match proof.node_commitments.get(j + 1) {
                Some(c) => map_child_commitment_to_value(c),
                None => return false,
            }
        };

        let value_bytes = match value_bytes_result {
            Ok(bytes) => bytes,
            Err(e) => {
                log::warn!(
                    "Failed to compute value hash during proof verification: {}",
                    e
                );
                return false;
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

    // Keep the existing neighbor sanity check
    if let Terminal::Neighbor { key_stem, .. } = &proof.terminal {
        if key_path.starts_with(key_stem) {
            return false;
        }
    }

    true
}
