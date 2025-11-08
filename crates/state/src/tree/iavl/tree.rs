// Path: crates/state/src/tree/iavl/tree.rs

use super::indices::Indices;
use super::node::IAVLNode;
use super::{ops, proof};
use crate::tree::iavl::proof::IavlProof;
// FIX: Add `Decode` to scope, remove unused `Selector`.
use ioi_api::commitment::CommitmentScheme;
use ioi_api::state::{
    PrunePlan, ProofProvider, StateAccess, StateManager, StateScanIter, VerifiableState,
};
use ioi_api::storage::NodeStore;
use ioi_storage::adapter::{commit_and_persist, DeltaAccumulator};
use ioi_types::app::{to_root_hash, Membership, RootHash};
use ioi_types::error::StateError;
use ioi_types::prelude::OptionExt;
use parity_scale_codec::Decode;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

/// IAVL tree implementation
#[derive(Clone)]
pub struct IAVLTree<CS: CommitmentScheme> {
    pub(super) root: Option<Arc<IAVLNode>>,
    pub(super) current_height: u64,
    pub(super) indices: Indices,
    pub(super) scheme: CS,
    pub(super) cache: HashMap<Vec<u8>, Vec<u8>>,
    pub(super) delta: DeltaAccumulator,
    pub(super) store: Option<Arc<dyn NodeStore>>,
}

impl<CS: CommitmentScheme> std::fmt::Debug for IAVLTree<CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IAVLTree")
            .field("root", &self.root)
            .field("current_height", &self.current_height)
            .field("indices", &self.indices)
            .field("scheme", &"...")
            .field("cache_len", &self.cache.len())
            .field("delta", &self.delta)
            .field("store_is_some", &self.store.is_some())
            .finish()
    }
}

impl<CS: CommitmentScheme> IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    pub fn new(scheme: CS) -> Self {
        Self {
            root: None,
            current_height: 0,
            indices: Indices::default(),
            scheme,
            cache: HashMap::new(),
            delta: DeltaAccumulator::default(),
            store: None,
        }
    }

    pub(super) fn to_value(&self, value: &[u8]) -> CS::Value {
        CS::Value::from(value.to_vec())
    }

    fn get_from_cache(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.get(key).cloned()
    }

    fn collect_height_delta(&mut self) -> Result<(), StateError> {
        let h = self.current_height;
        if let Some(root) = self.root.clone() {
            self.collect_from_node(&root, h)?;
        }
        Ok(())
    }

    fn collect_from_node(&mut self, n: &Arc<IAVLNode>, h: u64) -> Result<(), StateError> {
        if n.version == h {
            let bytes = super::encode::encode_node_canonical(n)?;
            let mut nh = [0u8; 32];
            nh.copy_from_slice(&n.hash);
            self.delta.record_new(nh, bytes);
        } else {
            let mut nh = [0u8; 32];
            nh.copy_from_slice(&n.hash);
            self.delta.record_touch(nh);
        }
        if let Some(l) = &n.left {
            self.collect_from_node(l, h)?;
        }
        if let Some(r) = &n.right {
            self.collect_from_node(r, h)?;
        }
        Ok(())
    }

    pub fn commit_version_with_store<S: NodeStore + ?Sized>(
        &mut self,
        height: u64,
        store: &S,
    ) -> Result<[u8; 32], ioi_types::error::StateError> {
        self.current_height = height;
        self.collect_height_delta()?;
        let root_hash = to_root_hash(self.root_commitment().as_ref())?;
        commit_and_persist(store, height, root_hash, &self.delta)
            .map_err(|e| ioi_types::error::StateError::Backend(e.to_string()))?;
        self.delta.clear();
        let _ = <Self as ioi_api::state::StateManager>::commit_version(self, height)?;
        Ok(root_hash)
    }
}

impl<CS: CommitmentScheme> StateAccess for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        if let Some(value) = self.get_from_cache(key) {
            Ok(Some(value))
        } else {
            Ok(IAVLNode::get(&self.root, key))
        }
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.root = Some(ops::insert(
            self.root.clone(),
            key.to_vec(),
            value.to_vec(),
            self.current_height,
        )?);
        self.cache.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.root = ops::remove(self.root.clone(), key, self.current_height)?;
        self.cache.remove(key);
        Ok(())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        let mut results = Vec::new();
        IAVLNode::range_scan(&self.root, prefix, &mut results);
        results.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let iter = results
            .into_iter()
            .map(|(k, v)| Ok((Arc::from(k), Arc::from(v))));
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

impl<CS: CommitmentScheme> VerifiableState for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn root_commitment(&self) -> Self::Commitment {
        let root_hash = self
            .root
            .as_ref()
            .map(|n| n.hash.clone())
            .unwrap_or_else(IAVLNode::empty_hash);
        <CS as CommitmentScheme>::Commitment::from(root_hash)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl<CS: CommitmentScheme> ProofProvider for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        self.build_proof_for_root(self.root.clone(), key)
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StateError> {
        let root_hash: &[u8; 32] = commitment
            .as_ref()
            .try_into()
            .map_err(|_| StateError::InvalidValue("Commitment is not 32 bytes".into()))?;
        let proof_data = proof.as_ref();

        let iavl_proof = IavlProof::decode(&mut &*proof_data)
            .map_err(|e| StateError::Validation(e.to_string()))?;
        match proof::verify_iavl_proof(root_hash, key, Some(value), &iavl_proof) {
            Ok(true) => Ok(()),
            Ok(false) => Err(StateError::Validation(
                "IAVL proof verification failed".into(),
            )),
            Err(e) => {
                log::warn!("IAVL proof verification failed with error: {}", e);
                Err(StateError::Validation(e.to_string()))
            }
        }
    }

    fn get_with_proof_at(
        &self,
        root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        let root_hash: RootHash = to_root_hash(root.as_ref())?;

        if let Some(historical_root_node) = self.indices.roots.get(&root_hash).cloned() {
            if historical_root_node.is_some() {
                let membership = match IAVLNode::get(&historical_root_node, key) {
                    Some(value) => Membership::Present(value),
                    None => Membership::Absent,
                };
                let proof = self
                    .build_proof_for_root(historical_root_node.clone(), key)
                    .required(StateError::Backend(
                        "Failed to generate IAVL proof".to_string(),
                    ))?;

                let iavl_proof = IavlProof::decode(&mut proof.as_ref())
                    .map_err(|e| StateError::Validation(e.to_string()))?;
                if !proof::verify_iavl_proof(
                    &root_hash,
                    key,
                    membership.clone().into_option().as_deref(),
                    &iavl_proof,
                )
                .map_err(|e| StateError::Validation(e.to_string()))?
                {
                    return Err(StateError::Backend(
                        "Failed to generate anchored IAVL proof".to_string(),
                    ));
                }
                return Ok((membership, proof));
            }
        }

        if let Some(store) = &self.store {
            self.build_proof_from_store_at(store.as_ref(), root_hash, key)
        } else {
            Err(StateError::StaleAnchor)
        }
    }

    fn commitment_from_anchor(&self, anchor: &[u8; 32]) -> Option<Self::Commitment> {
        self.commitment_from_bytes(anchor).ok()
    }

    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
        Ok(<CS as CommitmentScheme>::Commitment::from(bytes.to_vec()))
    }

    fn commitment_to_bytes(&self, c: &Self::Commitment) -> Vec<u8> {
        c.as_ref().to_vec()
    }
}

impl<CS: CommitmentScheme> StateManager for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    fn prune(&mut self, plan: &PrunePlan) -> Result<(), StateError> {
        let to_prune: Vec<u64> = self
            .indices
            .versions_by_height
            .range(..plan.cutoff_height)
            .filter_map(|(h, _)| if plan.excludes(*h) { None } else { Some(*h) })
            .collect();

        for h in to_prune {
            if let Some(root_hash) = self.indices.versions_by_height.remove(&h) {
                self.indices.decrement_refcount(root_hash);
            }
        }
        Ok(())
    }

    fn prune_batch(&mut self, plan: &PrunePlan, limit: usize) -> Result<usize, StateError> {
        let to_prune: Vec<u64> = self
            .indices
            .versions_by_height
            .range(..plan.cutoff_height)
            .filter_map(|(h, _)| if plan.excludes(*h) { None } else { Some(*h) })
            .take(limit)
            .collect();

        let pruned_count = to_prune.len();
        if pruned_count > 0 {
            for h in to_prune {
                if let Some(root_hash) = self.indices.versions_by_height.remove(&h) {
                    self.indices.decrement_refcount(root_hash);
                }
            }
        }
        Ok(pruned_count)
    }

    fn commit_version(&mut self, height: u64) -> Result<RootHash, StateError> {
        let root_hash = to_root_hash(self.root_commitment().as_ref())?;

        match self.indices.versions_by_height.insert(height, root_hash) {
            None => {
                let count = self.indices.root_refcount.entry(root_hash).or_insert(0);
                if *count == 0 {
                    self.indices.roots.insert(root_hash, self.root.clone());
                }
                *count += 1;
            }
            Some(prev_root) if prev_root != root_hash => {
                self.indices.decrement_refcount(prev_root);
                let count = self.indices.root_refcount.entry(root_hash).or_insert(0);
                if *count == 0 {
                    self.indices.roots.insert(root_hash, self.root.clone());
                }
                *count += 1;
            }
            Some(_prev_same_root) => {}
        }

        self.current_height = height;
        Ok(root_hash)
    }

    fn version_exists_for_root(&self, root: &Self::Commitment) -> bool {
        if let Ok(root_hash) = to_root_hash(root.as_ref()) {
            self.indices.roots.contains_key(&root_hash)
        } else {
            false
        }
    }

    fn commit_version_persist(
        &mut self,
        height: u64,
        store: &dyn NodeStore,
    ) -> Result<RootHash, StateError> {
        self.commit_version_with_store(height, store)
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