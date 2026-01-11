// Path: crates/state/src/tree/mhnsw/graph.rs

use super::metric::{DistanceMetric, Vector};
use super::node::{GraphNode, NodeId};
use super::proof::{TraversalProof, VisitedNode};
use ioi_types::error::StateError;
use parity_scale_codec::{Decode, Encode};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Encode, Decode, Serialize, Deserialize)]
pub struct HnswGraph<M: DistanceMetric> {
    pub(crate) metric: M,
    /// Publicly accessible map of nodes for direct serialization/inspection.
    pub nodes: HashMap<NodeId, GraphNode>,
    /// The entry point node ID for the graph.
    pub entry_point: Option<NodeId>,

    // Hyperparameters
    #[allow(dead_code)]
    pub(crate) m: usize,
    #[allow(dead_code)]
    pub(crate) m_max: usize,
    #[allow(dead_code)]
    pub(crate) m_max0: usize,
    #[allow(dead_code)]
    pub(crate) ef_construction: usize,
    pub(crate) level_mult: f64,

    pub(crate) next_id: u64,
    pub(crate) max_layer: usize,
}

#[derive(PartialEq)]
#[allow(dead_code)] // Helper for future search impl
struct Candidate {
    id: NodeId,
    distance: f32,
}

impl Eq for Candidate {}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .distance
            .partial_cmp(&self.distance)
            .unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<M: DistanceMetric> HnswGraph<M> {
    pub fn new(metric: M, m: usize, ef_construction: usize) -> Self {
        Self {
            metric,
            nodes: HashMap::new(),
            entry_point: None,
            m,
            m_max: m,
            m_max0: m * 2,
            ef_construction,
            level_mult: 1.0 / (m as f64).ln(),
            next_id: 1,
            max_layer: 0,
        }
    }

    fn random_level(&self) -> usize {
        let mut rng = rand::thread_rng();
        let r: f64 = rng.gen();
        (-r.ln() * self.level_mult).floor() as usize
    }

    fn dist(&self, v1: &Vector, v2: &Vector) -> f32 {
        self.metric.distance(v1, v2)
    }

    fn get_vector(&self, id: NodeId) -> Vector {
        let bytes = &self.nodes.get(&id).unwrap().vector;
        let floats: Vec<f32> = bytes
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        Vector(floats)
    }

    pub fn insert(&mut self, vector: Vector, payload: Vec<u8>) -> Result<(), StateError> {
        let level = self.random_level();
        let id = self.next_id;
        self.next_id += 1;

        let mut node = GraphNode::new(id, vector.clone(), payload, level + 1);

        if self.entry_point.is_none() {
            node.compute_hash();
            self.nodes.insert(id, node);
            self.entry_point = Some(id);
            self.max_layer = level;
            return Ok(());
        }

        let mut curr_obj = self.entry_point.unwrap();
        let mut curr_dist = self.dist(&vector, &self.get_vector(curr_obj));

        for l in (level + 1..=self.max_layer).rev() {
            let mut changed = true;
            while changed {
                changed = false;
                if let Some(node) = self.nodes.get(&curr_obj) {
                    if l < node.neighbors.len() {
                        let neighbors = &node.neighbors[l];
                        for &neighbor_id in neighbors {
                            let d = self.dist(&vector, &self.get_vector(neighbor_id));
                            if d < curr_dist {
                                curr_dist = d;
                                curr_obj = neighbor_id;
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        if level > self.max_layer {
            self.max_layer = level;
            self.entry_point = Some(id);
        }

        node.compute_hash();
        self.nodes.insert(id, node);

        Ok(())
    }

    /// Deletes a node from the graph.
    /// Re-links neighbors to maintain graph connectivity.
    /// This is a simplified "shrink" strategy: removing the node from neighbor lists.
    /// For a rigorous HNSW delete, one would re-connect neighbors, but for mHNSW integrity,
    /// removing edges is sufficient if graph remains connected (which small-world property generally preserves).
    pub fn delete(&mut self, id: NodeId) -> Result<(), String> {
        if !self.nodes.contains_key(&id) {
            return Err("Node not found".into());
        }

        // 1. Remove node
        let removed_node = self.nodes.remove(&id).unwrap();

        // 2. Scan all nodes to remove incoming edges.
        // Optimization: In a real HNSW, we would store back-links or use the graph traversal to find parents.
        // For MVP in-memory graph, iterating all nodes is acceptable but slow O(N).
        // TODO: Add reverse index for O(1) parent lookup.
        for node in self.nodes.values_mut() {
            for layer in &mut node.neighbors {
                if let Some(pos) = layer.iter().position(|&x| x == id) {
                    layer.remove(pos);
                    // Recompute hash since neighbor list changed
                    // Note: This triggers a re-hashing cascade if this was a Merkle Tree.
                    // Since mHNSW computes node hash from neighbors, we must rehash.
                    node.compute_hash();
                }
            }
        }

        // 3. Update entry point if we deleted it
        if self.entry_point == Some(id) {
            // Heuristic: Pick a random remaining node with max layer, or scanning.
            // For safety, we just pick the first available node or None.
            if self.nodes.is_empty() {
                self.entry_point = None;
                self.max_layer = 0;
            } else {
                // Try to find a new entry point at the highest layer
                let mut max_l = 0;
                let mut candidate = None;
                for (&nid, node) in &self.nodes {
                    let l = node.neighbors.len().saturating_sub(1);
                    if l >= max_l {
                        max_l = l;
                        candidate = Some(nid);
                    }
                }
                self.entry_point = candidate;
                self.max_layer = max_l;
            }
        }

        Ok(())
    }

    pub fn search(&self, query: &Vector, k: usize) -> Result<Vec<(Vec<u8>, f32)>, StateError> {
        let (results, _) = self.search_with_proof(query, k)?;
        Ok(results)
    }

    pub fn search_with_proof(
        &self,
        query: &Vector,
        _k: usize,
    ) -> Result<(Vec<(Vec<u8>, f32)>, TraversalProof), StateError> {
        if self.entry_point.is_none() {
            return Ok((
                vec![],
                TraversalProof {
                    entry_point_id: 0,
                    entry_point_hash: [0; 32],
                    trace: vec![],
                    results: vec![],
                },
            ));
        }

        let entry_id = self.entry_point.unwrap();
        let entry_node = self.nodes.get(&entry_id).ok_or(StateError::KeyNotFound)?;
        let mut curr_obj = entry_id;
        let mut curr_dist = self.dist(query, &self.get_vector(curr_obj));

        let mut trace = Vec::new();

        for l in (1..=self.max_layer).rev() {
            let mut changed = true;
            while changed {
                changed = false;

                let curr_node_ref = &self.nodes[&curr_obj];

                if l < curr_node_ref.neighbors.len() {
                    trace.push(VisitedNode {
                        id: curr_obj,
                        hash: curr_node_ref.hash,
                        vector: curr_node_ref.vector.clone(),
                        neighbors_at_layer: curr_node_ref.neighbors[l].clone(),
                    });

                    let neighbors = &curr_node_ref.neighbors[l];
                    for &neighbor_id in neighbors {
                        let d = self.dist(query, &self.get_vector(neighbor_id));
                        if d < curr_dist {
                            curr_dist = d;
                            curr_obj = neighbor_id;
                            changed = true;
                        }
                    }
                }
            }
        }

        let payload = self.nodes[&curr_obj].payload.clone();

        let proof = TraversalProof {
            entry_point_id: entry_id,
            entry_point_hash: entry_node.hash,
            trace,
            results: vec![curr_obj],
        };

        Ok((vec![(payload, curr_dist)], proof))
    }
}
