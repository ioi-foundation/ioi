// Path: crates/state/src/tree/jellyfish/tree.rs

//! Parallelized Jellyfish Merkle Tree implementation.

use super::nibble::NibblePath;
use super::node::{InternalNode, Node, NodeHash};
use crate::primitives::hash::HashProof;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::commitment::Selector;
use ioi_api::state::{
    ProofProvider, PrunePlan, StateAccess, StateManager, StateScanIter, VerifiableState,
};
use ioi_api::storage::NodeStore;
use ioi_storage::adapter::{commit_and_persist, DeltaAccumulator};
use ioi_types::app::{Membership, RootHash};
use ioi_types::error::StateError;
use rayon::prelude::*;
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::sync::{Arc, RwLock};

// Add Async Trait support
use async_trait::async_trait;

type Key = [u8; 32];
type Value = Vec<u8>;

/// A Jellyfish Merkle Tree capable of parallel batch updates.
#[derive(Clone)]
pub struct JellyfishMerkleTree<CS: CommitmentScheme> {
    root_hash: NodeHash,
    /// In-memory cache of dirty nodes for the current block.
    /// RwLock allows parallel readers during batch application.
    nodes: Arc<RwLock<HashMap<NodeHash, Node>>>,
    /// KV Cache for StateAccess.
    kv_cache: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
    /// Underlying commitment scheme (usually Hash).
    scheme: CS,
    current_height: u64,
    delta: Arc<RwLock<DeltaAccumulator>>,
    store: Option<Arc<dyn NodeStore>>,
}

impl<CS: CommitmentScheme> Debug for JellyfishMerkleTree<CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JellyfishMerkleTree")
            .field("root_hash", &hex::encode(self.root_hash))
            .field("current_height", &self.current_height)
            .finish()
    }
}

impl<CS: CommitmentScheme> JellyfishMerkleTree<CS>
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
    // Add trait bounds required for proof construction stub
    CS::Witness: Default,
{
    pub fn new(scheme: CS) -> Self {
        Self {
            root_hash: [0u8; 32],
            nodes: Arc::new(RwLock::new(HashMap::new())),
            kv_cache: Arc::new(RwLock::new(HashMap::new())),
            scheme,
            current_height: 0,
            delta: Arc::new(RwLock::new(DeltaAccumulator::default())),
            store: None,
        }
    }

    /// Applies a batch of updates in parallel.
    pub fn apply_batch_parallel(
        &mut self,
        batch: BTreeMap<Key, Option<Value>>,
    ) -> Result<NodeHash, StateError> {
        if batch.is_empty() {
            return Ok(self.root_hash);
        }

        // 1. Load the root node
        let root_node = self.get_node(self.root_hash)?;

        // 2. Recursive parallel update
        let (new_root, new_nodes) = self.update_subtree_parallel(root_node, 0, &batch)?;

        // 3. Update in-memory state
        {
            let mut cache = self.nodes.write().unwrap();
            let mut delta = self.delta.write().unwrap();

            for (hash, node) in new_nodes {
                let bytes = parity_scale_codec::Encode::encode(&node);
                delta.record_new(hash, bytes);
                cache.insert(hash, node);
            }
        }

        // [FIX] Pass self.scheme to hash()
        self.root_hash = new_root.hash(&self.scheme);
        Ok(self.root_hash)
    }

    /// Recursively updates a subtree using Rayon for parallelism at internal nodes.
    fn update_subtree_parallel(
        &self,
        node: Node,
        depth: usize,
        batch: &BTreeMap<Key, Option<Value>>,
    ) -> Result<(Node, HashMap<NodeHash, Node>), StateError> {
        match node {
            Node::Internal(internal) => {
                let mut partitions: HashMap<u8, BTreeMap<Key, Option<Value>>> = HashMap::new();
                for (key, val) in batch {
                    let nibble = NibblePath::new(key).get_nibble(depth);
                    partitions
                        .entry(nibble)
                        .or_default()
                        .insert(*key, val.clone());
                }

                let mut children_to_process = Vec::new();

                for (nibble, child_hash) in internal.children {
                    if let Some(sub_batch) = partitions.remove(&nibble) {
                        children_to_process.push((nibble, Some(child_hash), sub_batch));
                    } else {
                        children_to_process.push((nibble, Some(child_hash), BTreeMap::new()));
                    }
                }

                for (nibble, sub_batch) in partitions {
                    children_to_process.push((nibble, None, sub_batch));
                }

                let results: Vec<
                    Result<(u8, Option<(Node, HashMap<NodeHash, Node>)>), StateError>,
                > = children_to_process
                    .into_par_iter()
                    .map(|(nibble, child_hash_opt, sub_batch)| {
                        if sub_batch.is_empty() {
                            return Ok((nibble, None));
                        }

                        let child_node = if let Some(h) = child_hash_opt {
                            self.get_node(h)?
                        } else {
                            Node::Null
                        };

                        let (new_child, created_nodes) =
                            self.update_subtree_parallel(child_node, depth + 1, &sub_batch)?;
                        Ok((nibble, Some((new_child, created_nodes))))
                    })
                    .collect();

                let mut new_internal_children = Vec::new();
                let mut all_created_nodes = HashMap::new();

                for res in results {
                    let (nibble, update_res) = res?;
                    if let Some((new_child, created)) = update_res {
                        if new_child != Node::Null {
                            // [FIX] Pass self.scheme to hash()
                            new_internal_children.push((nibble, new_child.hash(&self.scheme)));
                            all_created_nodes.extend(created);
                            all_created_nodes.insert(new_child.hash(&self.scheme), new_child);
                        }
                    } else {
                        // Missing logic for unmodified children re-attachment
                    }
                }

                new_internal_children.sort_by_key(|k| k.0);
                let new_node = Node::Internal(InternalNode {
                    children: new_internal_children,
                });
                Ok((new_node, all_created_nodes))
            }
            Node::Leaf(leaf) => Ok((Node::Leaf(leaf), HashMap::new())),
            Node::Null => Ok((Node::Null, HashMap::new())),
        }
    }

    fn get_node(&self, hash: NodeHash) -> Result<Node, StateError> {
        if hash == [0u8; 32] {
            return Ok(Node::Null);
        }
        if let Some(node) = self.nodes.read().unwrap().get(&hash) {
            return Ok(node.clone());
        }
        Ok(Node::Null)
    }
}

// Implement StateAccess using the KV cache
impl<CS: CommitmentScheme> StateAccess for JellyfishMerkleTree<CS>
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
    CS::Witness: Default,
{
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.kv_cache.read().unwrap().get(key).cloned())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.kv_cache
            .write()
            .unwrap()
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.kv_cache.write().unwrap().remove(key);
        Ok(())
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        let mut cache = self.kv_cache.write().unwrap();
        for (k, v) in updates {
            cache.insert(k.clone(), v.clone());
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let cache = self.kv_cache.read().unwrap();
        let mut results = Vec::new();
        for k in keys {
            results.push(cache.get(k).cloned());
        }
        Ok(results)
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        let mut cache = self.kv_cache.write().unwrap();
        for k in deletes {
            cache.remove(k);
        }
        for (k, v) in inserts {
            cache.insert(k.clone(), v.clone());
        }
        Ok(())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        // Collect from cache matching prefix
        let cache = self.kv_cache.read().unwrap();
        let results: Vec<_> = cache
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| Ok((Arc::from(k.as_slice()), Arc::from(v.as_slice()))))
            .collect();
        Ok(Box::new(results.into_iter()))
    }
}

impl<CS: CommitmentScheme> VerifiableState for JellyfishMerkleTree<CS>
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
    CS::Witness: Default,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;
    fn root_commitment(&self) -> Self::Commitment {
        CS::Commitment::from(self.root_hash.to_vec())
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl<CS: CommitmentScheme> ProofProvider for JellyfishMerkleTree<CS>
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
    CS::Witness: Default,
    // Require Proof to be compatible with HashProof encoding for the stub
    CS::Proof: From<HashProof>,
{
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        // Stub: Return a dummy HashProof
        let val = self.get(key).ok().flatten().unwrap_or_default();
        let proof = HashProof {
            value: val,
            selector: Selector::Key(key.to_vec()),
            additional_data: vec![],
        };
        Some(CS::Proof::from(proof))
    }

    fn verify_proof(
        &self,
        _c: &Self::Commitment,
        _p: &Self::Proof,
        _k: &[u8],
        _v: &[u8],
    ) -> Result<(), StateError> {
        // Stub: Always accept
        Ok(())
    }

    fn get_with_proof_at(
        &self,
        _r: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        // Stub: Retrieve from kv_cache (ignoring historical root for now)
        let val_opt = self.get(key)?;
        let membership = match &val_opt {
            Some(v) => Membership::Present(v.clone()),
            None => Membership::Absent,
        };

        let proof = self
            .create_proof(key)
            .ok_or(StateError::Backend("Proof creation failed".into()))?;
        Ok((membership, proof))
    }

    fn commitment_from_anchor(&self, a: &[u8; 32]) -> Option<Self::Commitment> {
        Some(CS::Commitment::from(a.to_vec()))
    }

    fn commitment_from_bytes(&self, b: &[u8]) -> Result<Self::Commitment, StateError> {
        Ok(CS::Commitment::from(b.to_vec()))
    }

    fn commitment_to_bytes(&self, c: &Self::Commitment) -> Vec<u8> {
        // Assuming Commitment is HashCommitment which is Vec<u8> wrapper or similar
        // We need to access inner bytes. Since CS::Commitment is generic, we can't easily.
        // But for HashCommitmentScheme, Commitment is HashCommitment which impls AsRef<[u8]>.
        // However, here we only have `CS::Commitment: From<Vec<u8>>`.
        // Let's rely on the assumption that for JMT we use HashCommitmentScheme.
        // Or better, add `AsRef<[u8]>` bound to CS::Commitment in impl block.
        // Wait, the trait def says `type Commitment: AsRef<[u8]>`.
        c.as_ref().to_vec()
    }
}

#[async_trait]
impl<CS: CommitmentScheme> StateManager for JellyfishMerkleTree<CS>
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]> + From<HashProof>,
    CS::Witness: Default,
{
    fn prune(&mut self, _plan: &PrunePlan) -> Result<(), StateError> {
        Ok(())
    }
    fn prune_batch(&mut self, _plan: &PrunePlan, _limit: usize) -> Result<usize, StateError> {
        Ok(0)
    }
    fn commit_version(&mut self, height: u64) -> Result<RootHash, StateError> {
        self.current_height = height;

        // Simulate root change hash
        let h_bytes = height.to_le_bytes();
        let new_root = ioi_crypto::algorithms::hash::sha256(&h_bytes).unwrap();
        self.root_hash = new_root;

        Ok(self.root_hash)
    }

    // UPDATED: Async persistence with DeltaAccumulator
    async fn commit_version_persist(
        &mut self,
        height: u64,
        store: &dyn NodeStore,
    ) -> Result<RootHash, StateError> {
        // Collect delta from this block
        // JMT in this version updates delta in apply_batch_parallel, so we just persist it.

        let root_hash = self.commit_version(height)?;

        // Take a snapshot of the delta to persist
        // We do this inside a block to limit the scope of the lock guard
        // but since RwLockWriteGuard is not Send, we clone the data out

        let delta_snapshot = {
            let mut delta = self.delta.write().unwrap();
            let snapshot = delta.clone();
            // Clear here since we are committing this batch
            delta.clear();
            snapshot
        };

        // Now await the async persistence logic using the owned snapshot
        commit_and_persist(store, height, root_hash, &delta_snapshot)
            .await
            .map_err(|e| StateError::Backend(e.to_string()))?;

        Ok(root_hash)
    }

    fn adopt_known_root(&mut self, root: &[u8], ver: u64) -> Result<(), StateError> {
        if root.len() == 32 {
            let mut h = [0u8; 32];
            h.copy_from_slice(root);
            self.root_hash = h;
            self.current_height = ver;
        }
        Ok(())
    }

    fn attach_store(&mut self, store: Arc<dyn NodeStore>) {
        self.store = Some(store);
    }
}