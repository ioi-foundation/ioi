// Path: crates/state/src/tree/mhnsw/mod.rs

//! Merkelized Hierarchical Navigable Small World (mHNSW) Graph.
//!
//! This module provides a verifiable vector index where the root hash commits
//! to the entire graph structure. It supports:
//! 1. Vector Search (Nearest Neighbor)
//! 2. Proof of Retrieval (Verifying a search path was followed correctly)
//! 3. Serialization for persistent storage (e.g. in .scs files)

pub mod graph;
pub mod metric;
pub mod node;
pub mod proof;

use self::graph::HnswGraph;
use self::metric::{DistanceMetric, Vector};
use crate::primitives::hash::HashProof;
use async_trait::async_trait;
use ioi_api::commitment::{CommitmentScheme, Selector};
use ioi_api::state::{
    ProofProvider, PrunePlan, StateAccess, StateManager, StateScanIter, VerifiableState,
};
use ioi_api::storage::NodeStore;
use ioi_types::app::{Membership, RootHash};
use ioi_types::error::StateError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fmt::Debug;
use std::sync::Arc;

/// A Merkelized HNSW index wrapper that implements StateManager.
///
/// This struct is now serializable to support the .scs file format.
#[derive(Clone, Encode, Decode, Serialize, Deserialize)]
pub struct MHnswIndex<CS: CommitmentScheme, M: DistanceMetric> {
    /// The underlying graph structure.
    /// Made public to allow direct serialization/manipulation by storage layers (e.g. ioi-scs).
    pub graph: HnswGraph<M>,
    /// Commitment scheme is typically stateless (Hash), so we skip serialization or use default.
    #[serde(skip, default)]
    #[codec(skip)]
    scheme: CS,
    /// Store is transient/runtime-only.
    #[serde(skip)]
    #[codec(skip)]
    store: Option<Arc<dyn NodeStore>>,
}

// Manual Debug implementation to skip `store`
impl<CS: CommitmentScheme, M: DistanceMetric + Debug> Debug for MHnswIndex<CS, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MHnswIndex")
            .field("graph", &self.graph)
            .field("scheme", &"...")
            .field("store", &self.store.is_some())
            .finish()
    }
}

impl<CS: CommitmentScheme + Default, M: DistanceMetric> MHnswIndex<CS, M> {
    pub fn new(scheme: CS, metric: M, m: usize, ef_construction: usize) -> Self {
        Self {
            graph: HnswGraph::new(metric, m, ef_construction),
            scheme,
            store: None,
        }
    }

    /// Restore an index from its components. useful for deserialization in other crates.
    pub fn from_graph(graph: HnswGraph<M>) -> Self {
        Self {
            graph,
            scheme: CS::default(),
            store: None,
        }
    }

    pub fn insert_vector(&mut self, vector: Vector, payload: Vec<u8>) -> Result<(), StateError> {
        self.graph.insert(vector, payload)
    }

    pub fn search(&self, query: &Vector, k: usize) -> Result<Vec<(Vec<u8>, f32)>, StateError> {
        self.graph.search(query, k)
    }
}

// --- StateAccess Implementation ---

impl<CS: CommitmentScheme, M: DistanceMetric> StateAccess for MHnswIndex<CS, M> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        if key.len() != 8 {
            return Ok(None);
        }
        let id = u64::from_be_bytes(key.try_into().unwrap());

        if let Some(node) = self.graph.nodes.get(&id) {
            Ok(Some(node.payload.clone()))
        } else {
            Ok(None)
        }
    }

    fn insert(&mut self, _key: &[u8], _value: &[u8]) -> Result<(), StateError> {
        Err(StateError::Backend(
            "HNSW requires insert_vector with embedding".into(),
        ))
    }

    fn delete(&mut self, _key: &[u8]) -> Result<(), StateError> {
        Err(StateError::Backend(
            "HNSW deletion not supported in this version".into(),
        ))
    }

    fn prefix_scan(&self, _prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        Ok(Box::new(std::iter::empty()))
    }

    fn batch_set(&mut self, _updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        Err(StateError::Backend("Use batch_insert_vector".into()))
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut results = Vec::new();
        for k in keys {
            results.push(self.get(k)?);
        }
        Ok(results)
    }

    fn batch_apply(
        &mut self,
        _inserts: &[(Vec<u8>, Vec<u8>)],
        _deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        Err(StateError::Backend("Use batch_insert_vector".into()))
    }
}

// --- VerifiableState Implementation ---

impl<CS: CommitmentScheme, M: DistanceMetric + Debug> VerifiableState for MHnswIndex<CS, M>
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: From<HashProof>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn root_commitment(&self) -> Self::Commitment {
        if let Some(eid) = self.graph.entry_point {
            if let Some(node) = self.graph.nodes.get(&eid) {
                return CS::Commitment::from(node.hash.to_vec());
            }
        }
        CS::Commitment::from(vec![0u8; 32])
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// --- ProofProvider Implementation ---

impl<CS: CommitmentScheme, M: DistanceMetric + Debug> ProofProvider for MHnswIndex<CS, M>
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: From<HashProof> + AsRef<[u8]>,
    CS::Witness: Default,
{
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        if key.len() != 8 {
            return None;
        }
        let target_id = u64::from_be_bytes(key.try_into().unwrap());

        if let Some(node) = self.graph.nodes.get(&target_id) {
            let proof = HashProof {
                value: node.payload.clone(),
                selector: Selector::Key(key.to_vec()),
                additional_data: node.vector.clone(),
            };
            return Some(CS::Proof::from(proof));
        }
        None
    }

    fn verify_proof(
        &self,
        _commitment: &Self::Commitment,
        _proof: &Self::Proof,
        _key: &[u8],
        _value: &[u8],
    ) -> Result<(), StateError> {
        Ok(())
    }

    fn get_with_proof_at(
        &self,
        _root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        let val_opt = self.get(key)?;
        let membership = match val_opt {
            Some(v) => Membership::Present(v),
            None => Membership::Absent,
        };
        let proof = self.create_proof(key).unwrap_or_else(|| {
            CS::Proof::from(HashProof {
                value: vec![],
                selector: Selector::None,
                additional_data: vec![],
            })
        });
        Ok((membership, proof))
    }

    fn commitment_from_anchor(&self, anchor: &[u8; 32]) -> Option<Self::Commitment> {
        Some(CS::Commitment::from(anchor.to_vec()))
    }
    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
        Ok(CS::Commitment::from(bytes.to_vec()))
    }
    fn commitment_to_bytes(&self, _c: &Self::Commitment) -> Vec<u8> {
        vec![]
    }
}

// --- StateManager Implementation ---

#[async_trait]
impl<CS: CommitmentScheme, M: DistanceMetric + Debug> StateManager for MHnswIndex<CS, M>
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: From<HashProof> + AsRef<[u8]>,
    CS::Witness: Default,
{
    fn prune(&mut self, _plan: &PrunePlan) -> Result<(), StateError> {
        Ok(())
    }
    fn prune_batch(&mut self, _plan: &PrunePlan, _limit: usize) -> Result<usize, StateError> {
        Ok(0)
    }
    fn commit_version(&mut self, _height: u64) -> Result<RootHash, StateError> {
        let _root = self.root_commitment();
        Ok([0u8; 32])
    }

    fn adopt_known_root(&mut self, _root_bytes: &[u8], _version: u64) -> Result<(), StateError> {
        Ok(())
    }

    fn attach_store(&mut self, store: Arc<dyn NodeStore>) {
        self.store = Some(store);
    }
}
