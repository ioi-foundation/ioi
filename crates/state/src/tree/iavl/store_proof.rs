// Path: crates/state/src/tree/iavl/store_proof.rs

use super::encode::decode_node;
use super::proof::{ExistenceProof, HashOp, InnerOp, LeafOp, LengthOp, NonExistenceProof, Side};
use super::tree::IAVLTree;
use ioi_api::commitment::{CommitmentScheme, Selector};
use ioi_api::storage::{NodeHash as StoreNodeHash, NodeStore};
use ioi_types::app::Membership;
use ioi_types::error::StateError;
use parity_scale_codec::Encode;

// FIX: Add the full, correct `where` clause to satisfy trait bounds for called methods.
impl<CS: CommitmentScheme> IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    /// Build a proof for `key` at `root_hash32` by lazily fetching nodes from `store`.
    /// Returns (Membership, Proof) on success.
    pub(super) fn build_proof_from_store_at<S: NodeStore + ?Sized>(
        &self,
        store: &S,
        root_hash32: [u8; 32],
        key: &[u8],
    ) -> Result<(Membership, CS::Proof), StateError> {
        let height = store
            .height_for_root(ioi_api::storage::RootHash(root_hash32))
            .map_err(|e| StateError::Backend(e.to_string()))?
            .ok_or_else(|| StateError::UnknownAnchor(hex::encode(root_hash32)))?;

        let epoch = store.epoch_of(height);

        let mut cur_hash = root_hash32;
        let mut path: Vec<InnerOp> = Vec::new();

        loop {
            let node_bytes = Self::fetch_node_any_epoch(store, epoch, cur_hash)?
                .ok_or_else(|| StateError::Backend("Missing node bytes in store".into()))?;

            let node = decode_node(&node_bytes)
                .ok_or_else(|| StateError::Decode("Invalid node encoding".into()))?;

            if node.is_leaf {
                if node.key.as_slice() == key {
                    path.reverse();
                    let existence = ExistenceProof {
                        key: node.key.clone(),
                        value: node.value.clone(),
                        leaf: LeafOp {
                            hash: HashOp::Sha256,
                            prehash_key: HashOp::NoHash,
                            prehash_value: HashOp::NoHash,
                            length: LengthOp::VarProto,
                            prefix: {
                                let mut p = Vec::new();
                                p.push(0x00);
                                p.extend_from_slice(&node.version.to_le_bytes());
                                p.extend_from_slice(&0i32.to_le_bytes());
                                p.extend_from_slice(&1u64.to_le_bytes());
                                p
                            },
                        },
                        path,
                    };
                    let proof_obj = super::proof::IavlProof::Existence(existence);
                    let proof_bytes = proof_obj.encode();
                    let proof_value = self.to_value(&proof_bytes);
                    let scheme_proof = self
                        .scheme
                        .create_proof(&Selector::Key(key.to_vec()), &proof_value)
                        .map_err(|e| StateError::Backend(format!("Failed to wrap proof: {}", e)))?;
                    return Ok((Membership::Present(node.value), scheme_proof));
                } else {
                    let (left_neighbor, right_neighbor) = self
                        .find_neighbors_from_store(store, epoch, root_hash32, key)
                        .map_err(StateError::Backend)?;

                    let non_existence = NonExistenceProof {
                        missing_key: key.to_vec(),
                        left: left_neighbor,
                        right: right_neighbor,
                    };

                    if non_existence.left.is_none() && non_existence.right.is_none() {
                        return Err(StateError::Backend(
                            "Unable to construct neighbor proof for non-existence".into(),
                        ));
                    }

                    let proof_obj = super::proof::IavlProof::NonExistence(non_existence);
                    let proof_bytes = proof_obj.encode();
                    let proof_value = self.to_value(&proof_bytes);
                    let scheme_proof = self
                        .scheme
                        .create_proof(&Selector::Key(key.to_vec()), &proof_value)
                        .map_err(|e| StateError::Backend(format!("Failed to wrap proof: {}", e)))?;
                    return Ok((Membership::Absent, scheme_proof));
                }
            } else {
                let (next_hash, side, sib_hash) = if key <= node.split_key.as_slice() {
                    (node.left_hash, Side::Right, node.right_hash)
                } else {
                    (node.right_hash, Side::Left, node.left_hash)
                };

                path.push(InnerOp {
                    version: node.version,
                    height: node.height,
                    size: node.size,
                    split_key: node.split_key.clone(),
                    side,
                    sibling_hash: sib_hash,
                });
                cur_hash = next_hash;
            }
        }
    }

    fn find_neighbors_from_store<S: NodeStore + ?Sized>(
        &self,
        store: &S,
        epoch: u64,
        root_hash: [u8; 32],
        key: &[u8],
    ) -> Result<(Option<ExistenceProof>, Option<ExistenceProof>), String> {
        let fetch = |h: [u8; 32]| -> Result<super::encode::DecodedNode, String> {
            let bytes = Self::fetch_node_any_epoch(store, epoch, h)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "Missing node".to_string())?;
            decode_node(&bytes).ok_or_else(|| "Decode error".to_string())
        };

        let build_extreme = |start_hash: [u8; 32],
                             mut base_path: Vec<InnerOp>,
                             go_right: bool|
         -> Result<ExistenceProof, String> {
            let mut n = fetch(start_hash)?;
            loop {
                if n.is_leaf {
                    break;
                }
                if go_right {
                    base_path.push(InnerOp {
                        version: n.version,
                        height: n.height,
                        size: n.size,
                        split_key: n.split_key.clone(),
                        side: Side::Left,
                        sibling_hash: n.left_hash,
                    });
                    n = fetch(n.right_hash)?;
                } else {
                    base_path.push(InnerOp {
                        version: n.version,
                        height: n.height,
                        size: n.size,
                        split_key: n.split_key.clone(),
                        side: Side::Right,
                        sibling_hash: n.right_hash,
                    });
                    n = fetch(n.left_hash)?;
                }
            }
            base_path.reverse();
            Ok(ExistenceProof {
                key: n.key.clone(),
                value: n.value.clone(),
                leaf: LeafOp {
                    hash: HashOp::Sha256,
                    prehash_key: HashOp::NoHash,
                    prehash_value: HashOp::NoHash,
                    length: LengthOp::VarProto,
                    prefix: {
                        let mut p = Vec::new();
                        p.push(0x00);
                        p.extend_from_slice(&n.version.to_le_bytes());
                        p.extend_from_slice(&0i32.to_le_bytes());
                        p.extend_from_slice(&1u64.to_le_bytes());
                        p
                    },
                },
                path: base_path,
            })
        };

        let mut current_hash = root_hash;
        let mut path: Vec<InnerOp> = Vec::new();
        let mut pred_candidate = None;
        let mut succ_candidate = None;

        while let Ok(node) = fetch(current_hash) {
            if node.is_leaf {
                break;
            }
            if key <= node.split_key.as_slice() {
                succ_candidate = Some((node.right_hash, path.clone()));
                path.push(InnerOp {
                    version: node.version,
                    height: node.height,
                    size: node.size,
                    split_key: node.split_key.clone(),
                    side: Side::Right,
                    sibling_hash: node.right_hash,
                });
                current_hash = node.left_hash;
            } else {
                pred_candidate = Some((node.left_hash, path.clone()));
                path.push(InnerOp {
                    version: node.version,
                    height: node.height,
                    size: node.size,
                    split_key: node.split_key.clone(),
                    side: Side::Left,
                    sibling_hash: node.left_hash,
                });
                current_hash = node.right_hash;
            }
        }

        let left_proof = pred_candidate.and_then(|(h, p)| build_extreme(h, p, true).ok());
        let right_proof = succ_candidate.and_then(|(h, p)| build_extreme(h, p, false).ok());

        Ok((left_proof, right_proof))
    }

    pub(super) fn fetch_node_any_epoch<S: NodeStore + ?Sized>(
        store: &S,
        prefer_epoch: u64,
        hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StateError> {
        if let Some(bytes) = store
            .get_node(prefer_epoch, StoreNodeHash(hash))
            .map_err(|e| StateError::Backend(e.to_string()))?
        {
            return Ok(Some(bytes));
        }

        let (head_h, _) = store
            .head()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        let head_epoch = store.epoch_of(head_h);

        let start = prefer_epoch.min(head_epoch);
        for e in (0..=start).rev() {
            if let Some(bytes) = store
                .get_node(e, StoreNodeHash(hash))
                .map_err(|e| StateError::Backend(e.to_string()))?
            {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }
}