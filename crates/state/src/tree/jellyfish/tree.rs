// Path: crates/state/src/tree/jellyfish/tree.rs

//! Parallelized Jellyfish Merkle Tree implementation.

use super::nibble::NibblePath;
use super::node::{InternalNode, LeafNode, Node, NodeHash};
use super::verifier::JellyfishMerkleProof;
use crate::primitives::hash::HashProof;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::commitment::Selector;
use ioi_api::state::{
    ProofProvider, PrunePlan, StateAccess, StateManager, StateScanIter, VerifiableState, Verifier,
};
use ioi_api::storage::NodeStore;
use ioi_crypto::algorithms::hash::sha256;
use ioi_storage::adapter::{commit_and_persist, commit_and_persist_with_block, DeltaAccumulator};
use ioi_types::app::{to_root_hash, Membership, RootHash};
use ioi_types::error::StateError;
use parity_scale_codec::Encode;
use rayon::prelude::*;
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::sync::{Arc, RwLock};

// Add Async Trait support
use async_trait::async_trait;

type Key = [u8; 32];
type Value = Vec<u8>;

#[derive(Clone, Debug)]
struct ProofTrieNode {
    children: BTreeMap<u8, ProofTrieNode>,
    leaf: Option<LeafNode>,
    node_hash: NodeHash,
}

#[derive(Clone, Debug, Default)]
struct HistoricalStateSnapshot {
    kv_cache: HashMap<Vec<u8>, Vec<u8>>,
    proof_trie: ProofTrieNode,
    height: u64,
}

impl ProofTrieNode {
    fn refresh_hash<CS: CommitmentScheme>(&mut self, scheme: &CS) {
        self.node_hash = if let Some(leaf) = &self.leaf {
            Node::Leaf(leaf.clone()).hash(scheme)
        } else if self.children.is_empty() {
            [0u8; 32]
        } else {
            let mut encoded_children = Vec::with_capacity(self.children.len());
            for (nibble, child) in &self.children {
                encoded_children.push((*nibble, child.node_hash));
            }

            Node::Internal(InternalNode {
                children: encoded_children,
            })
            .hash(scheme)
        };
    }

    fn upsert<CS: CommitmentScheme>(
        &mut self,
        path: &NibblePath,
        depth: usize,
        leaf: LeafNode,
        scheme: &CS,
    ) {
        if depth >= 64 {
            self.leaf = Some(leaf);
            self.children.clear();
            self.refresh_hash(scheme);
            return;
        }
        let nibble = path.get_nibble(depth);
        self.children
            .entry(nibble)
            .or_default()
            .upsert(path, depth + 1, leaf, scheme);
        self.refresh_hash(scheme);
    }

    fn remove<CS: CommitmentScheme>(
        &mut self,
        path: &NibblePath,
        depth: usize,
        scheme: &CS,
    ) -> bool {
        if depth >= 64 {
            self.leaf = None;
            self.refresh_hash(scheme);
            return self.children.is_empty();
        }

        let nibble = path.get_nibble(depth);
        if let Some(child) = self.children.get_mut(&nibble) {
            if child.remove(path, depth + 1, scheme) {
                self.children.remove(&nibble);
            }
        }

        self.refresh_hash(scheme);
        self.leaf.is_none() && self.children.is_empty()
    }

    fn build_proof(
        &self,
        path: &NibblePath,
        depth: usize,
        siblings: &mut Vec<Vec<(u8, NodeHash)>>,
    ) -> Option<LeafNode> {
        if let Some(leaf) = &self.leaf {
            return Some(leaf.clone());
        }
        if self.children.is_empty() || depth >= 64 {
            return None;
        }

        let target_nibble = path.get_nibble(depth);
        let mut level_siblings = Vec::with_capacity(self.children.len().saturating_sub(1));
        for (nibble, child) in &self.children {
            if *nibble != target_nibble {
                level_siblings.push((*nibble, child.node_hash));
            }
        }
        siblings.push(level_siblings);

        match self.children.get(&target_nibble) {
            Some(child) => child.build_proof(path, depth + 1, siblings),
            None => None,
        }
    }
}

impl Default for ProofTrieNode {
    fn default() -> Self {
        Self {
            children: BTreeMap::new(),
            leaf: None,
            node_hash: [0u8; 32],
        }
    }
}

/// A Jellyfish Merkle Tree capable of parallel batch updates.
pub struct JellyfishMerkleTree<CS: CommitmentScheme> {
    root_hash: NodeHash,
    /// In-memory cache of dirty nodes for the current block.
    /// RwLock allows parallel readers during batch application.
    nodes: Arc<RwLock<HashMap<NodeHash, Node>>>,
    /// KV Cache for StateAccess.
    kv_cache: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
    /// Incrementally maintained proof trie for fast root updates and proof generation.
    proof_trie: Arc<RwLock<ProofTrieNode>>,
    historical_snapshots: Arc<RwLock<HashMap<NodeHash, HistoricalStateSnapshot>>>,
    /// Underlying commitment scheme (usually Hash).
    scheme: CS,
    current_height: u64,
    delta: Arc<RwLock<DeltaAccumulator>>,
    store: Option<Arc<dyn NodeStore>>,
}

impl<CS: CommitmentScheme + Clone> Clone for JellyfishMerkleTree<CS> {
    fn clone(&self) -> Self {
        Self {
            root_hash: self.root_hash,
            nodes: Arc::new(RwLock::new(self.nodes.read().unwrap().clone())),
            kv_cache: Arc::new(RwLock::new(self.kv_cache.read().unwrap().clone())),
            proof_trie: Arc::new(RwLock::new(self.proof_trie.read().unwrap().clone())),
            // Historical snapshots are immutable version anchors once committed, so clones used
            // for block execution do not need to duplicate the entire retained history.
            historical_snapshots: Arc::clone(&self.historical_snapshots),
            scheme: self.scheme.clone(),
            current_height: self.current_height,
            delta: Arc::new(RwLock::new(self.delta.read().unwrap().clone())),
            store: self.store.clone(),
        }
    }
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
            proof_trie: Arc::new(RwLock::new(ProofTrieNode::default())),
            historical_snapshots: Arc::new(RwLock::new(HashMap::new())),
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

    fn trie_leaf_for_entry(
        &self,
        key: &[u8],
        value: &[u8],
    ) -> Result<([u8; 32], LeafNode), StateError> {
        let key_hash = sha256(key).map_err(|e| StateError::Backend(e.to_string()))?;
        let value_hash = sha256(value).map_err(|e| StateError::Backend(e.to_string()))?;

        let mut account_key = [0u8; 32];
        account_key.copy_from_slice(&key_hash);
        let mut value_hash_arr = [0u8; 32];
        value_hash_arr.copy_from_slice(&value_hash);

        Ok((
            account_key,
            LeafNode {
                account_key,
                value_hash: value_hash_arr,
            },
        ))
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
        let (account_key, leaf) = self.trie_leaf_for_entry(key, value)?;
        let mut trie = self.proof_trie.write().unwrap();
        trie.upsert(&NibblePath::new(&account_key), 0, leaf, &self.scheme);
        self.root_hash = trie.node_hash;
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.kv_cache.write().unwrap().remove(key);
        let key_hash = sha256(key).map_err(|e| StateError::Backend(e.to_string()))?;
        let mut account_key = [0u8; 32];
        account_key.copy_from_slice(&key_hash);
        let mut trie = self.proof_trie.write().unwrap();
        trie.remove(&NibblePath::new(&account_key), 0, &self.scheme);
        self.root_hash = trie.node_hash;
        Ok(())
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        let mut cache = self.kv_cache.write().unwrap();
        let mut trie = self.proof_trie.write().unwrap();
        for (k, v) in updates {
            cache.insert(k.clone(), v.clone());
            let (account_key, leaf) = self.trie_leaf_for_entry(k, v)?;
            trie.upsert(&NibblePath::new(&account_key), 0, leaf, &self.scheme);
        }
        self.root_hash = trie.node_hash;
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
        if inserts.is_empty() && deletes.is_empty() {
            return Ok(());
        }
        let mut cache = self.kv_cache.write().unwrap();
        let mut trie = self.proof_trie.write().unwrap();
        for k in deletes {
            cache.remove(k);
            let key_hash = sha256(k).map_err(|e| StateError::Backend(e.to_string()))?;
            let mut account_key = [0u8; 32];
            account_key.copy_from_slice(&key_hash);
            trie.remove(&NibblePath::new(&account_key), 0, &self.scheme);
        }
        for (k, v) in inserts {
            cache.insert(k.clone(), v.clone());
            let (account_key, leaf) = self.trie_leaf_for_entry(k, v)?;
            trie.upsert(&NibblePath::new(&account_key), 0, leaf, &self.scheme);
        }
        self.root_hash = trie.node_hash;
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
        let trie = self.proof_trie.read().ok()?;
        Self::create_snapshot_proof(&trie, key)
    }

    fn verify_proof(
        &self,
        c: &Self::Commitment,
        p: &Self::Proof,
        k: &[u8],
        v: &[u8],
    ) -> Result<(), StateError> {
        let verifier = super::verifier::JellyfishVerifier;
        let proof = crate::primitives::hash::HashProof::from(p.as_ref().to_vec());
        let membership = Membership::Present(v.to_vec());
        let commitment = verifier.commitment_from_bytes(c.as_ref())?;
        verifier
            .verify(&commitment, &proof, k, &membership)
            .map_err(|e| {
                StateError::Validation(format!("Jellyfish proof verification failed: {e}"))
            })
    }

    fn get_with_proof_at(
        &self,
        root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        let requested_root = to_root_hash(root.as_ref())?;
        if requested_root == self.root_hash {
            let val_opt = self.get(key)?;
            let membership = match &val_opt {
                Some(v) => Membership::Present(v.clone()),
                None => Membership::Absent,
            };

            let proof = self
                .create_proof(key)
                .ok_or(StateError::Backend("Proof creation failed".into()))?;
            return Ok((membership, proof));
        }

        let snapshots = self.historical_snapshots.read().unwrap();
        let Some(snapshot) = snapshots.get(&requested_root) else {
            return Err(StateError::UnknownAnchor(hex::encode(requested_root)));
        };
        let membership = match snapshot.kv_cache.get(key) {
            Some(value) => Membership::Present(value.clone()),
            None => Membership::Absent,
        };
        let proof = Self::create_snapshot_proof(&snapshot.proof_trie, key).ok_or(
            StateError::Backend("Historical proof creation failed".into()),
        )?;
        Ok((membership, proof))
    }

    fn commitment_from_anchor(&self, a: &[u8; 32]) -> Option<Self::Commitment> {
        Some(CS::Commitment::from(a.to_vec()))
    }

    fn commitment_from_bytes(&self, b: &[u8]) -> Result<Self::Commitment, StateError> {
        Ok(CS::Commitment::from(b.to_vec()))
    }

    fn commitment_to_bytes(&self, c: &Self::Commitment) -> Vec<u8> {
        c.as_ref().to_vec()
    }
}

impl<CS: CommitmentScheme> JellyfishMerkleTree<CS>
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]> + From<HashProof>,
    CS::Witness: Default,
{
    fn create_snapshot_proof(trie: &ProofTrieNode, key: &[u8]) -> Option<CS::Proof> {
        let key_hash = sha256(key).ok()?;
        let mut key_hash_arr = [0u8; 32];
        key_hash_arr.copy_from_slice(&key_hash);
        let nibble_path = NibblePath::new(&key_hash_arr);
        let mut siblings = Vec::new();
        let leaf = trie.build_proof(&nibble_path, 0, &mut siblings);
        let proof_bytes = JellyfishMerkleProof { leaf, siblings }.encode();
        let proof = HashProof {
            value: proof_bytes,
            selector: Selector::Key(key.to_vec()),
            additional_data: vec![],
        };
        Some(CS::Proof::from(proof))
    }
}

#[async_trait]
impl<CS: CommitmentScheme> StateManager for JellyfishMerkleTree<CS>
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]> + From<HashProof>,
    CS::Witness: Default,
{
    fn prune(&mut self, plan: &PrunePlan) -> Result<(), StateError> {
        let _ = self.prune_batch(plan, usize::MAX)?;
        Ok(())
    }

    fn prune_batch(&mut self, plan: &PrunePlan, limit: usize) -> Result<usize, StateError> {
        if plan.cutoff_height == 0 || limit == 0 {
            return Ok(0);
        }

        let current_root = self.root_hash;
        let mut snapshots = self.historical_snapshots.write().unwrap();
        let mut removable = snapshots
            .iter()
            .filter_map(|(root, snapshot)| {
                (*root != current_root
                    && snapshot.height < plan.cutoff_height
                    && !plan.excluded_heights.contains(&snapshot.height))
                .then_some((*root, snapshot.height))
            })
            .collect::<Vec<_>>();

        removable.sort_by_key(|(_, height)| *height);
        let removed = removable.len().min(limit);
        for (root, _) in removable.into_iter().take(removed) {
            snapshots.remove(&root);
        }

        Ok(removed)
    }

    fn commit_version(&mut self, height: u64) -> Result<RootHash, StateError> {
        self.current_height = height;
        let snapshot = HistoricalStateSnapshot {
            kv_cache: self.kv_cache.read().unwrap().clone(),
            proof_trie: self.proof_trie.read().unwrap().clone(),
            height,
        };
        self.historical_snapshots
            .write()
            .unwrap()
            .insert(self.root_hash, snapshot);
        Ok(self.root_hash)
    }

    fn version_exists_for_root(&self, root: &Self::Commitment) -> bool {
        if let Ok(root_hash) = to_root_hash(root.as_ref()) {
            root_hash == self.root_hash
                || self
                    .historical_snapshots
                    .read()
                    .unwrap()
                    .contains_key(&root_hash)
        } else {
            false
        }
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

    async fn commit_version_persist_with_block(
        &mut self,
        height: u64,
        store: &dyn NodeStore,
        block_bytes: &[u8],
    ) -> Result<RootHash, StateError> {
        let root_hash = self.commit_version(height)?;

        let delta_snapshot = {
            let mut delta = self.delta.write().unwrap();
            let snapshot = delta.clone();
            delta.clear();
            snapshot
        };

        commit_and_persist_with_block(store, height, root_hash, &delta_snapshot, block_bytes)
            .await
            .map_err(|e| StateError::Backend(e.to_string()))?;

        Ok(root_hash)
    }

    fn adopt_known_root(&mut self, root: &[u8], ver: u64) -> Result<(), StateError> {
        if root.len() == 32 {
            let mut h = [0u8; 32];
            h.copy_from_slice(root);
            if let Some(snapshot) = self.historical_snapshots.read().unwrap().get(&h).cloned() {
                self.root_hash = h;
                self.current_height = snapshot.height;
                self.nodes.write().unwrap().clear();
                *self.kv_cache.write().unwrap() = snapshot.kv_cache;
                *self.proof_trie.write().unwrap() = snapshot.proof_trie;
                self.delta.write().unwrap().clear();
            } else {
                self.root_hash = h;
                self.current_height = ver;
                self.nodes.write().unwrap().clear();
                self.kv_cache.write().unwrap().clear();
                *self.proof_trie.write().unwrap() = ProofTrieNode::default();
                self.delta.write().unwrap().clear();
            }
        }
        Ok(())
    }

    fn attach_store(&mut self, store: Arc<dyn NodeStore>) {
        self.store = Some(store);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::hash::{HashCommitmentScheme, HashProof};
    use crate::tree::jellyfish::verifier::JellyfishVerifier;
    use ioi_api::state::{ProofProvider, StateAccess, Verifier};
    use ioi_types::app::Membership;

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
}
