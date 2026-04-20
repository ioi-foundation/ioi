use super::*;
use crate::primitives::hash::{HashCommitmentScheme, HashProof};
use crate::tree::jellyfish::verifier::JellyfishVerifier;
use ioi_api::state::{ProofProvider, StateAccess, Verifier};
use ioi_types::app::Membership;
use std::collections::BTreeSet;

#[test]
fn jellyfish_roundtrip_proof_verifies_for_present_and_absent_keys() {
    let scheme = HashCommitmentScheme::new();
    let mut tree = JellyfishMerkleTree::new(scheme);
    tree.insert(b"validator_set", b"vset").unwrap();
    tree.insert(b"epoch", b"1").unwrap();
    let root = tree.commit_version(1).unwrap();
    let commitment = crate::primitives::hash::HashCommitment::from(root.to_vec());
    let verifier = JellyfishVerifier;

    let present = tree.create_proof(b"validator_set").unwrap();
    let present = HashProof::from(present.as_ref().to_vec());
    verifier
        .verify(
            &commitment,
            &present,
            b"validator_set",
            &Membership::Present(b"vset".to_vec()),
        )
        .unwrap();

    let absent = tree.create_proof(b"missing").unwrap();
    let absent = HashProof::from(absent.as_ref().to_vec());
    verifier
        .verify(&commitment, &absent, b"missing", &Membership::Absent)
        .unwrap();
}

#[test]
fn jellyfish_clone_is_an_independent_snapshot() {
    let scheme = HashCommitmentScheme::new();
    let mut original = JellyfishMerkleTree::new(scheme);
    original.insert(b"validator_set", b"vset").unwrap();
    original.commit_version(0).unwrap();
    let cloned = original.clone();

    original.insert(b"status", b"height-1").unwrap();

    assert_eq!(cloned.get(b"status").unwrap(), None);
    assert_ne!(
        original.root_commitment().as_ref(),
        cloned.root_commitment().as_ref()
    );
}

#[test]
fn jellyfish_prune_batch_drops_old_unpinned_snapshots() {
    let scheme = HashCommitmentScheme::new();
    let mut tree = JellyfishMerkleTree::new(scheme);

    tree.insert(b"status", b"height-1").unwrap();
    let root1 = tree.commit_version(1).unwrap();
    tree.insert(b"status", b"height-2").unwrap();
    let root2 = tree.commit_version(2).unwrap();
    tree.insert(b"status", b"height-3").unwrap();
    let root3 = tree.commit_version(3).unwrap();

    let mut excluded = BTreeSet::new();
    excluded.insert(2);
    let removed = tree
        .prune_batch(
            &PrunePlan {
                cutoff_height: 3,
                excluded_heights: excluded,
            },
            16,
        )
        .unwrap();

    assert_eq!(removed, 1);
    let snapshots = tree.historical_snapshots.read().unwrap();
    assert!(!snapshots.contains_key(&root1));
    assert!(snapshots.contains_key(&root2));
    assert!(snapshots.contains_key(&root3));
}
