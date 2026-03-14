//! Sparse Merkle tree implementation with cryptographic security.

pub mod verifier;

use async_trait::async_trait;
use ioi_api::commitment::{CommitmentScheme, Selector};
use ioi_api::state::{
    ProofProvider, PrunePlan, StateAccess, StateManager, StateScanIter, VerifiableState,
};
use ioi_api::storage::{NodeHash as StoreNodeHash, NodeStore};
use ioi_storage::adapter::{commit_and_persist, DeltaAccumulator};
use ioi_types::app::{to_root_hash, Membership, RootHash};
use ioi_types::error::{ProofError, StateError};
use parity_scale_codec::{Decode, Encode};
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Clone, PartialEq, Encode, Decode)]
enum Node {
    Empty,
    Leaf {
        key: Vec<u8>,
        value: Vec<u8>,
        created_at: u64,
    },
    Branch {
        left: Arc<Node>,
        right: Arc<Node>,
        hash: [u8; 32],
        created_at: u64,
    },
}

impl Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "Empty"),
            Self::Leaf {
                key,
                value,
                created_at,
            } => f
                .debug_struct("Leaf")
                .field("key", &hex::encode(key))
                .field("value", &hex::encode(value))
                .field("created_at", created_at)
                .finish(),
            Self::Branch {
                left,
                right,
                hash,
                created_at,
            } => f
                .debug_struct("Branch")
                .field("left", left)
                .field("right", right)
                .field("hash", &hex::encode(hash))
                .field("created_at", created_at)
                .finish(),
        }
    }
}

fn smt_encode_node(node: &Node) -> Vec<u8> {
    node.encode()
}

fn smt_decode_node(bytes: &[u8]) -> Option<Node> {
    Node::decode(&mut &*bytes).ok()
}

impl Node {
    fn hash(&self) -> [u8; 32] {
        match self {
            Node::Empty => [0u8; 32],
            Node::Leaf { key, value, .. } => {
                let mut data = Vec::new();
                data.push(0x00);
                data.extend_from_slice(key);
                data.extend_from_slice(value);
                ioi_crypto::algorithms::hash::sha256(&data).unwrap_or_else(|e| {
                    log::error!("CRITICAL: sha256 failed in Node::hash: {}", e);
                    [0u8; 32]
                })
            }
            Node::Branch { hash, .. } => *hash,
        }
    }

    fn compute_branch_hash(left: &Node, right: &Node) -> [u8; 32] {
        let mut data = Vec::new();
        data.push(0x01);
        data.extend_from_slice(&left.hash());
        data.extend_from_slice(&right.hash());
        ioi_crypto::algorithms::hash::sha256(&data).unwrap_or_else(|e| {
            log::error!(
                "CRITICAL: sha256 failed in Node::compute_branch_hash: {}",
                e
            );
            [0u8; 32]
        })
    }
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct SparseMerkleProof {
    pub siblings: Vec<Vec<u8>>,
    pub leaf: Option<(Vec<u8>, Vec<u8>)>,
}

#[derive(Clone)]
pub struct SparseMerkleTree<CS: CommitmentScheme> {
    root: Arc<Node>,
    scheme: CS,
    cache: HashMap<Vec<u8>, Vec<u8>>,
    indices: Indices,
    current_height: u64,
    delta: DeltaAccumulator,
    store: Option<Arc<dyn NodeStore>>,
}

impl<CS: CommitmentScheme> Debug for SparseMerkleTree<CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SparseMerkleTree")
            .field("root", &self.root)
            .field("scheme", &"...")
            .field("cache_len", &self.cache.len())
            .field("indices", &self.indices)
            .field("current_height", &self.current_height)
            .field("delta", &self.delta)
            .field("store_is_some", &self.store.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
struct Indices {
    versions_by_height: BTreeMap<u64, RootHash>,
    root_refcount: HashMap<RootHash, u32>,
    roots: HashMap<RootHash, Arc<Node>>,
}

impl<CS: CommitmentScheme> SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
    CS::Witness: Default,
{
    const TREE_HEIGHT: usize = 256;

    pub fn new(scheme: CS) -> Self {
        Self {
            root: Arc::new(Node::Empty),
            scheme,
            cache: HashMap::new(),
            indices: Indices::default(),
            current_height: 0,
            delta: DeltaAccumulator::default(),
            store: None,
        }
    }

    pub fn build_proof_from_store_at(
        &self,
        store: &dyn NodeStore,
        root_hash32: [u8; 32],
        key: &[u8],
    ) -> Result<SparseMerkleProof, StateError> {
        let height = store
            .height_for_root(ioi_api::storage::RootHash(root_hash32))
            .map_err(|e| StateError::Backend(e.to_string()))?
            .ok_or_else(|| StateError::UnknownAnchor(hex::encode(root_hash32)))?;
        let epoch = store.epoch_of(height);

        let mut siblings = Vec::new();
        let mut current_hash = root_hash32;

        for depth in 0..Self::TREE_HEIGHT {
            if current_hash == Node::Empty.hash() {
                break;
            }
            let node_bytes = Self::fetch_node_any_epoch(store, epoch, current_hash)?
                .ok_or_else(|| StateError::Backend("Missing node bytes in store".into()))?;

            let node = smt_decode_node(&node_bytes)
                .ok_or_else(|| StateError::Decode("Invalid node encoding".into()))?;

            match node {
                Node::Empty => break,
                Node::Leaf { .. } => break,
                Node::Branch { left, right, .. } => {
                    if Self::get_bit(key, depth) {
                        siblings.push(left.hash().to_vec());
                        current_hash = right.hash();
                    } else {
                        siblings.push(right.hash().to_vec());
                        current_hash = left.hash();
                    }
                }
            }
        }

        let leaf = if current_hash != Node::Empty.hash() {
            let node_bytes = Self::fetch_node_any_epoch(store, epoch, current_hash)?
                .ok_or_else(|| StateError::Backend("Missing leaf node bytes".into()))?;
            let node = smt_decode_node(&node_bytes)
                .ok_or_else(|| StateError::Decode("Invalid leaf node encoding".into()))?;
            if let Node::Leaf { key, value, .. } = node {
                Some((key, value))
            } else {
                None
            }
        } else {
            None
        };

        Ok(SparseMerkleProof { siblings, leaf })
    }

    fn fetch_node_any_epoch(
        store: &dyn NodeStore,
        prefer_epoch: u64,
        hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StateError> {
        if let Some(bytes) = store
            .get_node(prefer_epoch, StoreNodeHash(hash))
            .map_err(|e| StateError::Backend(e.to_string()))?
        {
            return Ok(Some(bytes));
        }
        let (head_height, _) = store
            .head()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        let head_epoch = store.epoch_of(head_height);
        let start = prefer_epoch.min(head_epoch);
        for epoch in (0..start).rev() {
            if let Some(bytes) = store
                .get_node(epoch, StoreNodeHash(hash))
                .map_err(|e| StateError::Backend(e.to_string()))?
            {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    fn decrement_refcount(&mut self, root_hash: RootHash) {
        if let Some(count) = self.indices.root_refcount.get_mut(&root_hash) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.indices.root_refcount.remove(&root_hash);
                self.indices.roots.remove(&root_hash);
            }
        }
    }

    fn to_value(&self, bytes: &[u8]) -> CS::Value {
        CS::Value::from(bytes.to_vec())
    }

    fn get_bit(key: &[u8], position: usize) -> bool {
        if position >= key.len() * 8 {
            return false;
        }
        let byte_index = position / 8;
        let bit_index = 7 - (position % 8);
        key.get(byte_index)
            .is_some_and(|&byte| (byte >> bit_index) & 1 == 1)
    }

    #[allow(clippy::only_used_in_recursion)]
    fn update_node(
        &self,
        node: &Arc<Node>,
        key: &[u8],
        value: Option<&[u8]>,
        depth: usize,
    ) -> Arc<Node> {
        if depth >= Self::TREE_HEIGHT {
            return if let Some(value) = value {
                Arc::new(Node::Leaf {
                    key: key.to_vec(),
                    value: value.to_vec(),
                    created_at: self.current_height,
                })
            } else {
                Arc::new(Node::Empty)
            };
        }

        match node.as_ref() {
            Node::Empty => {
                if value.is_none() {
                    return Arc::new(Node::Empty);
                }
                let child = self.update_node(&Arc::new(Node::Empty), key, value, depth + 1);
                let bit = Self::get_bit(key, depth);
                let (left, right) = if bit {
                    (Arc::new(Node::Empty), child)
                } else {
                    (child, Arc::new(Node::Empty))
                };
                let hash = Node::compute_branch_hash(&left, &right);
                Arc::new(Node::Branch {
                    left,
                    right,
                    hash,
                    created_at: self.current_height,
                })
            }
            Node::Leaf {
                key: leaf_key,
                value: leaf_value,
                ..
            } => {
                if leaf_key == key {
                    return if let Some(value) = value {
                        Arc::new(Node::Leaf {
                            key: key.to_vec(),
                            value: value.to_vec(),
                            created_at: self.current_height,
                        })
                    } else {
                        Arc::new(Node::Empty)
                    };
                }
                let new_branch = self.update_node(&Arc::new(Node::Empty), key, value, depth);
                self.update_node(&new_branch, leaf_key, Some(leaf_value), depth)
            }
            Node::Branch { left, right, .. } => {
                let bit = Self::get_bit(key, depth);
                let (new_left, new_right) = if bit {
                    (left.clone(), self.update_node(right, key, value, depth + 1))
                } else {
                    (self.update_node(left, key, value, depth + 1), right.clone())
                };

                if matches!(*new_left, Node::Empty) && matches!(*new_right, Node::Empty) {
                    Arc::new(Node::Empty)
                } else {
                    let hash = Node::compute_branch_hash(&new_left, &new_right);
                    Arc::new(Node::Branch {
                        left: new_left,
                        right: new_right,
                        hash,
                        created_at: self.current_height,
                    })
                }
            }
        }
    }

    fn get_from_snapshot(node: &Arc<Node>, key: &[u8], depth: usize) -> Option<Vec<u8>> {
        match node.as_ref() {
            Node::Empty => None,
            Node::Leaf {
                key: stored_key,
                value,
                ..
            } => (stored_key.as_slice() == key).then(|| value.clone()),
            Node::Branch { left, right, .. } => {
                if Self::get_bit(key, depth) {
                    Self::get_from_snapshot(right, key, depth + 1)
                } else {
                    Self::get_from_snapshot(left, key, depth + 1)
                }
            }
        }
    }

    fn generate_proof_from_snapshot(start: &Arc<Node>, key: &[u8]) -> SparseMerkleProof {
        let mut siblings = Vec::new();
        let mut current = start.clone();

        for depth in 0..Self::TREE_HEIGHT {
            match current.as_ref() {
                Node::Empty | Node::Leaf { .. } => break,
                Node::Branch { left, right, .. } => {
                    if Self::get_bit(key, depth) {
                        siblings.push(left.hash().to_vec());
                        current = right.clone();
                    } else {
                        siblings.push(right.hash().to_vec());
                        current = left.clone();
                    }
                }
            }
        }

        let leaf = match current.as_ref() {
            Node::Leaf { key, value, .. } => Some((key.clone(), value.clone())),
            _ => None,
        };

        SparseMerkleProof { siblings, leaf }
    }

    pub fn verify_proof_static(
        root_hash: &[u8],
        key: &[u8],
        value: Option<&[u8]>,
        proof: &SparseMerkleProof,
    ) -> Result<bool, ProofError> {
        let leaf_hash = match (&proof.leaf, value) {
            (Some((proof_key, proof_value)), Some(value)) => {
                if proof_key != key || proof_value != value {
                    return Ok(false);
                }
                let mut data = Vec::new();
                data.push(0x00);
                data.extend_from_slice(proof_key);
                data.extend_from_slice(proof_value);
                ioi_crypto::algorithms::hash::sha256(&data)
                    .map_err(|e| ProofError::Crypto(e.to_string()))?
                    .to_vec()
            }
            (None, None) => vec![0u8; 32],
            (Some((witness_key, witness_value)), None) => {
                if witness_key == key {
                    return Ok(false);
                }
                let mut data = Vec::new();
                data.push(0x00);
                data.extend_from_slice(witness_key);
                data.extend_from_slice(witness_value);
                ioi_crypto::algorithms::hash::sha256(&data)
                    .map_err(|e| ProofError::Crypto(e.to_string()))?
                    .to_vec()
            }
            _ => return Ok(false),
        };

        let mut acc = leaf_hash;
        let path_len = proof.siblings.len();
        for index in (0..path_len).rev() {
            let sibling = proof.siblings.get(index).ok_or_else(|| {
                ProofError::InvalidExistence("Proof has fewer siblings than path".into())
            })?;
            let mut data = Vec::new();
            data.push(0x01);
            if Self::get_bit(key, index) {
                data.extend_from_slice(sibling);
                data.extend_from_slice(&acc);
            } else {
                data.extend_from_slice(&acc);
                data.extend_from_slice(sibling);
            }
            acc = ioi_crypto::algorithms::hash::sha256(&data)
                .map_err(|e| ProofError::Crypto(e.to_string()))?
                .to_vec();
        }

        Ok(acc.as_slice() == root_hash)
    }

    fn collect_height_delta(&mut self) {
        let height = self.current_height;
        let root = self.root.clone();
        self.collect_from_node(&root, height);
    }

    fn collect_from_node(&mut self, node: &Arc<Node>, height: u64) {
        match node.as_ref() {
            Node::Empty => {}
            Node::Leaf { created_at, .. } | Node::Branch { created_at, .. } => {
                let bytes = smt_encode_node(node.as_ref());
                let node_hash = node.hash();
                if *created_at == height {
                    self.delta.record_new(node_hash, bytes);
                } else {
                    self.delta.record_touch(node_hash);
                }

                if let Node::Branch { left, right, .. } = node.as_ref() {
                    self.collect_from_node(left, height);
                    self.collect_from_node(right, height);
                }
            }
        }
    }

    pub async fn commit_version_with_store<S: NodeStore + ?Sized>(
        &mut self,
        height: u64,
        store: &S,
    ) -> Result<RootHash, StateError>
    where
        CS::Commitment: From<Vec<u8>>,
        CS::Proof: AsRef<[u8]>,
    {
        self.current_height = height;
        self.collect_height_delta();
        let root_hash = to_root_hash(self.root_commitment().as_ref())?;
        commit_and_persist(store, height, root_hash, &self.delta)
            .await
            .map_err(|e| StateError::Backend(e.to_string()))?;
        self.delta.clear();
        let _ = <Self as StateManager>::commit_version(self, height)?;
        Ok(root_hash)
    }
}

impl<CS: CommitmentScheme> StateAccess for SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
    CS::Witness: Default,
{
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        if let Some(value) = self.cache.get(key) {
            return Ok(Some(value.clone()));
        }
        Ok(Self::get_from_snapshot(&self.root, key, 0))
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.root = self.update_node(&self.root, key, Some(value), 0);
        self.cache.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.root = self.update_node(&self.root, key, None, 0);
        self.cache.remove(key);
        Ok(())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        let mut results: Vec<_> = self
            .cache
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        results.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let iter = results
            .into_iter()
            .map(|(key, value)| Ok((Arc::from(key), Arc::from(value))));
        Ok(Box::new(iter))
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            results.push(self.get(key)?);
        }
        Ok(results)
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        for key in deletes {
            self.delete(key)?;
        }
        for (key, value) in inserts {
            self.insert(key, value)?;
        }
        Ok(())
    }
}

impl<CS: CommitmentScheme> VerifiableState for SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
    CS::Witness: Default,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn root_commitment(&self) -> Self::Commitment {
        CS::Commitment::from(self.root.hash().to_vec())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl<CS: CommitmentScheme> ProofProvider for SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
    CS::Witness: Default,
{
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let merkle_proof = Self::generate_proof_from_snapshot(&self.root, key);
        let proof_data = merkle_proof.encode();
        let value = self.to_value(&proof_data);
        let witness = CS::Witness::default();
        self.scheme
            .create_proof(&witness, &Selector::Key(key.to_vec()), &value)
            .ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StateError> {
        let smt_proof = SparseMerkleProof::decode(&mut &*proof.as_ref())
            .map_err(|e| StateError::InvalidValue(e.to_string()))?;

        match Self::verify_proof_static(commitment.as_ref(), key, Some(value), &smt_proof) {
            Ok(true) => Ok(()),
            Ok(false) => Err(StateError::Validation(
                "SMT proof verification failed".into(),
            )),
            Err(e) => Err(StateError::Validation(e.to_string())),
        }
    }

    fn get_with_proof_at(
        &self,
        root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        let root_hash: RootHash = to_root_hash(root.as_ref())?;

        if let Some(historical_root) = self.indices.roots.get(&root_hash).cloned() {
            let membership = match Self::get_from_snapshot(&historical_root, key, 0) {
                Some(value) => Membership::Present(value),
                None => Membership::Absent,
            };
            let merkle_proof = Self::generate_proof_from_snapshot(&historical_root, key);
            if !Self::verify_proof_static(
                &root_hash,
                key,
                membership.clone().into_option().as_deref(),
                &merkle_proof,
            )
            .map_err(|e| StateError::Validation(e.to_string()))?
            {
                return Err(StateError::Backend("SMT self-verify failed".into()));
            }

            let proof_bytes = merkle_proof.encode();
            let proof_value = self.to_value(&proof_bytes);
            let witness = CS::Witness::default();
            let proof = self
                .scheme
                .create_proof(&witness, &Selector::Key(key.to_vec()), &proof_value)
                .map_err(|e| StateError::Backend(e.to_string()))?;
            return Ok((membership, proof));
        }

        if let Some(store) = &self.store {
            let merkle_proof = self.build_proof_from_store_at(store.as_ref(), root_hash, key)?;
            let membership = if let Some((proof_key, proof_value)) = &merkle_proof.leaf {
                if proof_key == key {
                    Membership::Present(proof_value.clone())
                } else {
                    Membership::Absent
                }
            } else {
                Membership::Absent
            };

            if !Self::verify_proof_static(
                &root_hash,
                key,
                membership.clone().into_option().as_deref(),
                &merkle_proof,
            )
            .map_err(|e| StateError::Validation(e.to_string()))?
            {
                return Err(StateError::Backend(
                    "SMT store-backed self-verify failed".into(),
                ));
            }

            let proof_bytes = merkle_proof.encode();
            let proof_value = self.to_value(&proof_bytes);
            let witness = CS::Witness::default();
            let proof = self
                .scheme
                .create_proof(&witness, &Selector::Key(key.to_vec()), &proof_value)
                .map_err(|e| StateError::Backend(e.to_string()))?;
            return Ok((membership, proof));
        }

        Err(StateError::StaleAnchor)
    }

    fn commitment_from_anchor(&self, anchor: &[u8; 32]) -> Option<Self::Commitment> {
        self.commitment_from_bytes(anchor).ok()
    }

    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
        Ok(CS::Commitment::from(bytes.to_vec()))
    }

    fn commitment_to_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        commitment.as_ref().to_vec()
    }
}

#[async_trait]
impl<CS: CommitmentScheme> StateManager for SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
    CS::Witness: Default,
{
    fn prune(&mut self, plan: &PrunePlan) -> Result<(), StateError> {
        let to_prune: Vec<u64> = self
            .indices
            .versions_by_height
            .range(..plan.cutoff_height)
            .filter_map(|(height, _)| {
                if plan.excludes(*height) {
                    None
                } else {
                    Some(*height)
                }
            })
            .collect();

        for height in to_prune {
            if let Some(root_hash) = self.indices.versions_by_height.remove(&height) {
                self.decrement_refcount(root_hash);
            }
        }
        Ok(())
    }

    fn prune_batch(&mut self, plan: &PrunePlan, limit: usize) -> Result<usize, StateError> {
        let to_prune: Vec<u64> = self
            .indices
            .versions_by_height
            .range(..plan.cutoff_height)
            .filter_map(|(height, _)| {
                if plan.excludes(*height) {
                    None
                } else {
                    Some(*height)
                }
            })
            .take(limit)
            .collect();

        let pruned_count = to_prune.len();
        if pruned_count > 0 {
            for height in to_prune {
                if let Some(root_hash) = self.indices.versions_by_height.remove(&height) {
                    self.decrement_refcount(root_hash);
                }
            }
        }
        Ok(pruned_count)
    }

    fn commit_version(&mut self, height: u64) -> Result<RootHash, StateError> {
        self.current_height = height;
        let root_hash = to_root_hash(self.root.hash())?;

        match self.indices.versions_by_height.insert(height, root_hash) {
            None => {
                let count = self.indices.root_refcount.entry(root_hash).or_insert(0);
                if *count == 0 {
                    self.indices.roots.insert(root_hash, self.root.clone());
                }
                *count += 1;
            }
            Some(previous_root) if previous_root != root_hash => {
                self.decrement_refcount(previous_root);
                let count = self.indices.root_refcount.entry(root_hash).or_insert(0);
                if *count == 0 {
                    self.indices.roots.insert(root_hash, self.root.clone());
                }
                *count += 1;
            }
            Some(_same_root) => {}
        }

        Ok(root_hash)
    }

    fn version_exists_for_root(&self, root: &Self::Commitment) -> bool {
        if let Ok(root_hash) = to_root_hash(root.as_ref()) {
            self.indices.roots.contains_key(&root_hash)
        } else {
            false
        }
    }

    async fn commit_version_persist(
        &mut self,
        height: u64,
        store: &dyn NodeStore,
    ) -> Result<RootHash, StateError> {
        self.commit_version_with_store(height, store).await
    }

    fn adopt_known_root(&mut self, root_bytes: &[u8], version: u64) -> Result<(), StateError> {
        let root_hash = to_root_hash(root_bytes)?;
        self.indices.versions_by_height.insert(version, root_hash);
        *self.indices.root_refcount.entry(root_hash).or_insert(0) += 1;
        if self.current_height < version {
            self.current_height = version;
        }
        Ok(())
    }

    fn attach_store(&mut self, store: Arc<dyn NodeStore>) {
        self.store = Some(store);
    }

    fn begin_block_writes(&mut self, height: u64) {
        self.current_height = height;
    }
}

#[cfg(test)]
mod tests;
