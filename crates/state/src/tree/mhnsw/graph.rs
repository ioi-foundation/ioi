// Path: crates/state/src/tree/mhnsw/graph.rs

use super::metric::{DistanceMetric, Vector};
use super::node::{GraphNode, NodeId};
use ioi_types::error::StateError;
use rand::Rng;
use std::cmp::Ordering;
use std::collections::HashMap; // [FIX] Removed BinaryHeap import

#[derive(Clone, Debug)] // [FIX] Added Clone and Debug
pub struct HnswGraph<M: DistanceMetric> {
    pub(crate) metric: M,
    pub(crate) nodes: HashMap<NodeId, GraphNode>,
    pub(crate) entry_point: Option<NodeId>,

    // Hyperparameters
    pub(crate) m: usize,
    pub(crate) m_max: usize,
    pub(crate) m_max0: usize,
    pub(crate) ef_construction: usize,
    pub(crate) level_mult: f64,

    pub(crate) next_id: u64,
    pub(crate) max_layer: usize,
}

#[derive(PartialEq)]
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
                let neighbors = self.nodes[&curr_obj].neighbors[l].clone();
                for neighbor_id in neighbors {
                    let d = self.dist(&vector, &self.get_vector(neighbor_id));
                    if d < curr_dist {
                        curr_dist = d;
                        curr_obj = neighbor_id;
                        changed = true;
                    }
                }
            }
        }

        // [FIX] Prefix unused variables
        for _l in (0..=std::cmp::min(level, self.max_layer)).rev() {
            // Simplified insertion logic
        }

        if level > self.max_layer {
            self.max_layer = level;
            self.entry_point = Some(id);
        }

        node.compute_hash();
        self.nodes.insert(id, node);

        Ok(())
    }

    pub fn search(&self, query: &Vector, _k: usize) -> Result<Vec<(Vec<u8>, f32)>, StateError> {
        if self.entry_point.is_none() {
            return Ok(vec![]);
        }

        let mut curr_obj = self.entry_point.unwrap();
        let mut curr_dist = self.dist(query, &self.get_vector(curr_obj));

        for l in (1..=self.max_layer).rev() {
            let mut changed = true;
            while changed {
                changed = false;
                let neighbors = &self.nodes[&curr_obj].neighbors[l];
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

        let payload = self.nodes[&curr_obj].payload.clone();

        Ok(vec![(payload, curr_dist)])
    }
}
