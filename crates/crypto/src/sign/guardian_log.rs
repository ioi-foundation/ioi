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
            let anchored_root = checkpoint_root_from_leaf_hashes(
                &proof.extension_leaf_hashes[..anchored_prefix_len],
            )?;
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
mod tests {
    use super::*;
    use crate::algorithms::hash::sha256;
    use ioi_types::app::GuardianLogProof;
    use libp2p::identity::Keypair;

    fn signed_checkpoint(
        log_id: &str,
        keypair: &Keypair,
        entries: &[&[u8]],
        leaf_index: usize,
    ) -> GuardianLogCheckpoint {
        let leaf_hashes = entries
            .iter()
            .map(|entry| canonical_log_leaf_hash(entry).unwrap())
            .collect::<Vec<_>>();
        let root_hash = checkpoint_root_from_leaf_hashes(&leaf_hashes).unwrap();
        let mut checkpoint = GuardianLogCheckpoint {
            log_id: log_id.into(),
            tree_size: leaf_hashes.len() as u64,
            root_hash,
            timestamp_ms: 5,
            signature: Vec::new(),
            proof: Some(GuardianLogProof {
                base_tree_size: 0,
                leaf_index: leaf_index as u64,
                leaf_hash: leaf_hashes[leaf_index],
                extension_leaf_hashes: leaf_hashes.clone(),
            }),
        };
        let payload = checkpoint_signing_payload(&checkpoint).unwrap();
        checkpoint.signature = keypair.sign(&payload).unwrap();
        checkpoint
    }

    #[test]
    fn verifies_signed_checkpoint_and_full_history_proof() {
        let keypair = Keypair::generate_ed25519();
        let checkpoint = signed_checkpoint("guardian-log", &keypair, &[b"a", b"b"], 1);
        let descriptor = GuardianTransparencyLogDescriptor {
            log_id: "guardian-log".into(),
            signature_suite: SignatureSuite::ED25519,
            public_key: keypair.public().encode_protobuf(),
        };

        verify_checkpoint_signature(&descriptor, &checkpoint).unwrap();
        verify_checkpoint_proof(
            &checkpoint,
            Some(&signed_checkpoint("guardian-log", &keypair, &[b"a"], 0)),
            canonical_log_leaf_hash(b"b").unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_checkpoint_with_wrong_expected_leaf() {
        let keypair = Keypair::generate_ed25519();
        let checkpoint = signed_checkpoint("guardian-log", &keypair, &[b"a"], 0);
        let err = verify_checkpoint_proof(
            &checkpoint,
            None,
            canonical_log_leaf_hash(b"wrong").unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::InvalidInput(_)));
    }

    fn reference_root_from_leaf_hashes(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
        let mut root = [0u8; 32];
        for leaf_hash in leaf_hashes {
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&root);
            data.extend_from_slice(leaf_hash);
            root = sha256(&data).unwrap();
        }
        root
    }

    fn reference_verify_checkpoint_proof(
        checkpoint: &GuardianLogCheckpoint,
        anchored_checkpoint: Option<&GuardianLogCheckpoint>,
        expected_leaf_hash: [u8; 32],
    ) -> bool {
        let Some(proof) = checkpoint.proof.as_ref() else {
            return false;
        };
        if checkpoint.tree_size == 0 {
            return false;
        }
        if proof.leaf_hash != expected_leaf_hash {
            return false;
        }

        let leaf_index = proof.leaf_index as usize;
        let tree_size = checkpoint.tree_size as usize;
        let base_tree_size = proof.base_tree_size as usize;
        let expected_extension_len = tree_size.saturating_sub(base_tree_size);
        if leaf_index >= tree_size || proof.extension_leaf_hashes.len() != expected_extension_len {
            return false;
        }
        let proof_leaf_offset = leaf_index.saturating_sub(base_tree_size);
        if leaf_index < base_tree_size || proof_leaf_offset >= proof.extension_leaf_hashes.len() {
            return false;
        }
        if proof.extension_leaf_hashes[proof_leaf_offset] != proof.leaf_hash {
            return false;
        }

        let base_root = if base_tree_size == 0 {
            [0u8; 32]
        } else {
            let Some(anchor) = anchored_checkpoint else {
                return false;
            };
            if anchor.tree_size as usize != base_tree_size {
                return false;
            }
            anchor.root_hash
        };

        let mut root = base_root;
        for leaf_hash in &proof.extension_leaf_hashes {
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&root);
            data.extend_from_slice(leaf_hash);
            root = sha256(&data).unwrap();
        }
        if root != checkpoint.root_hash {
            return false;
        }

        if let Some(anchor) = anchored_checkpoint {
            if anchor.log_id != checkpoint.log_id {
                return false;
            }
            if checkpoint.tree_size < anchor.tree_size
                || checkpoint.timestamp_ms < anchor.timestamp_ms
            {
                return false;
            }
            if base_tree_size == 0 {
                let anchored_prefix_len = anchor.tree_size as usize;
                if proof.extension_leaf_hashes.len() < anchored_prefix_len {
                    return false;
                }
                if reference_root_from_leaf_hashes(
                    &proof.extension_leaf_hashes[..anchored_prefix_len],
                ) != anchor.root_hash
                {
                    return false;
                }
            }
        } else if base_tree_size != 0 {
            return false;
        }

        true
    }

    #[test]
    fn checkpoint_proof_matches_reference_verifier() {
        let keypair = Keypair::generate_ed25519();
        for len in 1..=4usize {
            let entries = (0..len)
                .map(|idx| format!("entry-{idx}").into_bytes())
                .collect::<Vec<_>>();
            let refs = entries.iter().map(Vec::as_slice).collect::<Vec<_>>();
            for leaf_index in 0..len {
                let checkpoint = signed_checkpoint("guardian-log", &keypair, &refs, leaf_index);
                for anchor_len in 0..=len {
                    let anchored = if anchor_len == 0 {
                        None
                    } else {
                        Some(signed_checkpoint(
                            "guardian-log",
                            &keypair,
                            &refs[..anchor_len],
                            anchor_len - 1,
                        ))
                    };
                    let expected_leaf_hash = canonical_log_leaf_hash(&entries[leaf_index]).unwrap();
                    let actual =
                        verify_checkpoint_proof(&checkpoint, anchored.as_ref(), expected_leaf_hash)
                            .is_ok();
                    let reference = reference_verify_checkpoint_proof(
                        &checkpoint,
                        anchored.as_ref(),
                        expected_leaf_hash,
                    );
                    assert_eq!(
                        actual, reference,
                        "checkpoint proof mismatch for len={len}, leaf_index={leaf_index}, anchor_len={anchor_len}"
                    );
                }
            }
        }
    }
}
