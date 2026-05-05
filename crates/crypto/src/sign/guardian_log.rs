use crate::algorithms::hash::sha256;
use crate::error::CryptoError;
use ioi_types::app::{GuardianLogCheckpoint, GuardianTransparencyLogDescriptor, SignatureSuite};
use ioi_types::codec;
use libp2p::identity::PublicKey;

fn fold_root(mut root: [u8; 32], leaf_hashes: &[[u8; 32]]) -> Result<[u8; 32], CryptoError> {
    for leaf_hash in leaf_hashes {
        let mut mix = Vec::with_capacity(root.len() + leaf_hash.len());
        mix.extend_from_slice(&root);
        mix.extend_from_slice(leaf_hash);
        root = sha256(&mix)?;
    }
    Ok(root)
}

pub fn canonical_log_leaf_hash(entry: &[u8]) -> Result<[u8; 32], CryptoError> {
    sha256(entry)
}

pub fn checkpoint_signing_payload(
    checkpoint: &GuardianLogCheckpoint,
) -> Result<Vec<u8>, CryptoError> {
    codec::to_bytes_canonical(&(
        checkpoint.log_id.as_str(),
        checkpoint.tree_size,
        checkpoint.root_hash,
        checkpoint.timestamp_ms,
    ))
    .map_err(|e| CryptoError::Custom(e.to_string()))
}

pub fn checkpoint_root_from_leaf_hashes(leaf_hashes: &[[u8; 32]]) -> Result<[u8; 32], CryptoError> {
    fold_root([0u8; 32], leaf_hashes)
}

pub fn verify_checkpoint_signature(
    descriptor: &GuardianTransparencyLogDescriptor,
    checkpoint: &GuardianLogCheckpoint,
) -> Result<(), CryptoError> {
    if descriptor.log_id != checkpoint.log_id {
        return Err(CryptoError::InvalidInput(
            "checkpoint log id does not match descriptor".into(),
        ));
    }
    if descriptor.signature_suite != SignatureSuite::ED25519 {
        return Err(CryptoError::Unsupported(format!(
            "unsupported guardian log signature suite {:?}",
            descriptor.signature_suite
        )));
    }

    let public_key = PublicKey::try_decode_protobuf(&descriptor.public_key)
        .map_err(|_| CryptoError::InvalidKey("invalid guardian log public key".into()))?;
    let payload = checkpoint_signing_payload(checkpoint)?;
    if public_key.verify(&payload, &checkpoint.signature) {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn verify_checkpoint_proof(
    checkpoint: &GuardianLogCheckpoint,
    anchored_checkpoint: Option<&GuardianLogCheckpoint>,
    expected_leaf_hash: [u8; 32],
) -> Result<(), CryptoError> {
    if checkpoint.tree_size == 0 {
        return Err(CryptoError::InvalidInput(
            "checkpoint tree size must be non-zero".into(),
        ));
    }

    let proof = checkpoint.proof.as_ref().ok_or_else(|| {
        CryptoError::InvalidInput("checkpoint is missing append-only proof".into())
    })?;

    if proof.base_tree_size > checkpoint.tree_size {
        return Err(CryptoError::InvalidInput(
            "checkpoint proof base tree size exceeds checkpoint tree size".into(),
        ));
    }
    if proof.leaf_index >= checkpoint.tree_size {
        return Err(CryptoError::InvalidInput(
            "checkpoint proof leaf index exceeds checkpoint tree size".into(),
        ));
    }
    if proof.leaf_hash != expected_leaf_hash {
        return Err(CryptoError::InvalidInput(
            "checkpoint proof leaf hash does not match expected entry".into(),
        ));
    }

    let expected_extension_len = usize::try_from(checkpoint.tree_size - proof.base_tree_size)
        .map_err(|_| {
            CryptoError::InvalidInput("checkpoint extension length conversion failed".into())
        })?;
    if proof.extension_leaf_hashes.len() != expected_extension_len {
        return Err(CryptoError::InvalidInput(format!(
            "checkpoint proof expected {} extension leaves, got {}",
            expected_extension_len,
            proof.extension_leaf_hashes.len()
        )));
    }

    let proof_leaf_offset = proof
        .leaf_index
        .checked_sub(proof.base_tree_size)
        .ok_or_else(|| {
            CryptoError::InvalidInput("checkpoint proof leaf index predates base tree".into())
        })?;
    let proof_leaf_offset = usize::try_from(proof_leaf_offset).map_err(|_| {
        CryptoError::InvalidInput("checkpoint proof leaf offset conversion failed".into())
    })?;
    if proof
        .extension_leaf_hashes
        .get(proof_leaf_offset)
        .copied()
        .ok_or_else(|| {
            CryptoError::InvalidInput("checkpoint proof leaf offset outside extension".into())
        })?
        != expected_leaf_hash
    {
        return Err(CryptoError::InvalidInput(
            "checkpoint proof extension leaf does not match expected entry".into(),
        ));
    }

    let base_root = if proof.base_tree_size == 0 {
        [0u8; 32]
    } else {
        let anchored = anchored_checkpoint.ok_or_else(|| {
            CryptoError::InvalidInput(
                "checkpoint proof requires an anchored checkpoint for non-zero base".into(),
            )
        })?;
        if anchored.tree_size != proof.base_tree_size {
            return Err(CryptoError::InvalidInput(
                "checkpoint proof base tree size does not match anchored checkpoint".into(),
            ));
        }
        anchored.root_hash
    };

    let full_root = fold_root(base_root, &proof.extension_leaf_hashes)?;
    if full_root != checkpoint.root_hash {
        return Err(CryptoError::InvalidInput(
            "checkpoint proof does not reconstruct checkpoint root".into(),
        ));
    }

    if let Some(anchored) = anchored_checkpoint {
        if anchored.log_id != checkpoint.log_id {
            return Err(CryptoError::InvalidInput(
                "anchored checkpoint log id mismatch".into(),
            ));
        }
        if checkpoint.tree_size < anchored.tree_size {
            return Err(CryptoError::InvalidInput(
                "checkpoint tree size rolls back anchored checkpoint".into(),
            ));
        }
        if checkpoint.timestamp_ms < anchored.timestamp_ms {
            return Err(CryptoError::InvalidInput(
                "checkpoint timestamp predates anchored checkpoint".into(),
            ));
        }

        if proof.base_tree_size == 0 {
            let anchored_prefix_len = usize::try_from(anchored.tree_size).map_err(|_| {
                CryptoError::InvalidInput("anchored checkpoint tree size conversion failed".into())
            })?;
            if proof.extension_leaf_hashes.len() < anchored_prefix_len {
                return Err(CryptoError::InvalidInput(
                    "checkpoint proof does not cover anchored tree size".into(),
                ));
            }
            let Some(anchored_prefix) = proof.extension_leaf_hashes.get(..anchored_prefix_len)
            else {
                return Err(CryptoError::InvalidInput(
                    "checkpoint proof does not cover anchored tree size".into(),
                ));
            };
            let anchored_root = checkpoint_root_from_leaf_hashes(anchored_prefix)?;
            if anchored_root != anchored.root_hash {
                return Err(CryptoError::InvalidInput(
                    "checkpoint proof is inconsistent with anchored checkpoint".into(),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "guardian_log/tests.rs"]
mod tests;
