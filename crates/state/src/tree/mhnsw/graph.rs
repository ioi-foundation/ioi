// Path: crates/state/src/tree/mhnsw/graph.rs

use super::metric::{DistanceMetric, Vector};
use super::node::{GraphNode, NodeId};
use super::proof::{CandidateScore, RetrievalSearchPolicy, TraversalProof, TraversalStep};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::error::StateError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Debug, Encode, Decode, Serialize, Deserialize)]
pub struct HnswGraph<M: DistanceMetric> {
    pub(crate) metric: M,
    /// Publicly accessible map of nodes for direct serialization/inspection.
    pub nodes: BTreeMap<NodeId, GraphNode>,
    /// The entry point node ID for the graph.
    pub entry_point: Option<NodeId>,

    // Hyperparameters
    #[allow(dead_code)]
    pub(crate) m: u32,
    #[allow(dead_code)]
    pub(crate) m_max: u32,
    #[allow(dead_code)]
    pub(crate) m_max0: u32,
    #[allow(dead_code)]
    pub(crate) ef_construction: u32,
    pub(crate) level_mult: f64,

    pub(crate) next_id: u64,
    pub(crate) max_layer: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Candidate {
    id: NodeId,
    distance: f32,
}

impl Eq for Candidate {}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_distance_then_id(other.distance, other.id, self.distance, self.id)
    }
}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn cmp_distance_then_id(
    left_distance: f32,
    left_id: NodeId,
    right_distance: f32,
    right_id: NodeId,
) -> Ordering {
    match left_distance
        .partial_cmp(&right_distance)
        .unwrap_or(Ordering::Equal)
    {
        Ordering::Equal => left_id.cmp(&right_id),
        ord => ord,
    }
}

fn hash32(bytes: &[u8]) -> [u8; 32] {
    match sha256(bytes) {
        Ok(digest) => {
            let mut out = [0u8; 32];
            let hash_bytes = digest.as_ref();
            let len = hash_bytes.len().min(32);
            out[..len].copy_from_slice(&hash_bytes[..len]);
            out
        }
        Err(_) => [0u8; 32],
    }
}

fn vector_to_bytes(vector: &Vector) -> Vec<u8> {
    vector
        .0
        .iter()
        .flat_map(|f| f.to_le_bytes().to_vec())
        .collect()
}

impl<M: DistanceMetric> HnswGraph<M> {
    /// Deterministic index root over graph structure and parameters.
    pub fn index_root(&self) -> [u8; 32] {
        let mut input = Vec::new();
        input.extend_from_slice(&(self.nodes.len() as u64).to_le_bytes());
        input.extend_from_slice(&self.m.to_le_bytes());
        input.extend_from_slice(&self.m_max.to_le_bytes());
        input.extend_from_slice(&self.m_max0.to_le_bytes());
        input.extend_from_slice(&self.ef_construction.to_le_bytes());
        input.extend_from_slice(&self.max_layer.to_le_bytes());
        input.extend_from_slice(&self.entry_point.unwrap_or_default().to_le_bytes());
        input.extend_from_slice(&(self.level_mult.to_bits()).to_le_bytes());
        input.extend_from_slice(std::any::type_name::<M>().as_bytes());

        for (&id, node) in &self.nodes {
            input.extend_from_slice(&id.to_le_bytes());
            input.extend_from_slice(&node.hash);
        }
        hash32(&input)
    }

    pub fn new(metric: M, m: usize, ef_construction: usize) -> Self {
        Self {
            metric,
            nodes: BTreeMap::new(),
            entry_point: None,
            m: m as u32,
            m_max: m as u32,
            m_max0: (m * 2) as u32,
            ef_construction: ef_construction as u32,
            level_mult: 1.0 / (m as f64).ln(),
            next_id: 1,
            max_layer: 0,
        }
    }

    fn deterministic_level(&self, id: NodeId, vector: &Vector, payload: &[u8]) -> usize {
        let mut seed = Vec::with_capacity(8 + payload.len() + vector.0.len() * 4);
        seed.extend_from_slice(&id.to_le_bytes());
        seed.extend_from_slice(&vector_to_bytes(vector));
        seed.extend_from_slice(payload);
        let digest = hash32(&seed);
        let mut sample = [0u8; 8];
        sample.copy_from_slice(&digest[..8]);
        let sample_u64 = u64::from_le_bytes(sample).max(1);
        let mut u = (sample_u64 as f64) / (u64::MAX as f64);
        if u <= 0.0 {
            u = f64::MIN_POSITIVE;
        }
        ((-u.ln() * self.level_mult).floor().max(0.0) as usize).min(32)
    }

    fn dist(&self, v1: &Vector, v2: &Vector) -> f32 {
        self.metric.distance(v1, v2)
    }

    fn get_vector(&self, id: NodeId) -> Option<Vector> {
        let node = self.nodes.get(&id)?;
        if node.vector.len() % 4 != 0 {
            return None;
        }
        let floats: Vec<f32> = node
            .vector
            .chunks_exact(4)
            .map(|c| {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(c);
                f32::from_le_bytes(bytes)
            })
            .collect();
        Some(Vector(floats))
    }

    fn candidate_cmp(left: Candidate, right: Candidate) -> Ordering {
        cmp_distance_then_id(left.distance, left.id, right.distance, right.id)
    }

    fn dedup_sorted_ids(ids: &mut Vec<NodeId>) {
        ids.sort_unstable();
        ids.dedup();
    }

    fn build_distance_commit(
        &self,
        query: &Vector,
        node_id: NodeId,
        layer: usize,
        neighbors: &[NodeId],
    ) -> [u8; 32] {
        let mut input = Vec::new();
        input.extend_from_slice(&vector_to_bytes(query));
        input.extend_from_slice(&node_id.to_le_bytes());
        input.extend_from_slice(&(layer as u32).to_le_bytes());
        for &neighbor_id in neighbors {
            input.extend_from_slice(&neighbor_id.to_le_bytes());
            if let Some(n_vec) = self.get_vector(neighbor_id) {
                let d = if let Some(curr_vec) = self.get_vector(node_id) {
                    self.dist(&curr_vec, &n_vec)
                } else {
                    f32::INFINITY
                };
                input.extend_from_slice(&d.to_le_bytes());
            }
        }
        hash32(&input)
    }

    fn compute_trace_commit(trace: &[TraversalStep]) -> [u8; 32] {
        let mut acc = [0u8; 32];
        for step in trace {
            let step_hash = hash32(&step.encode());
            let mut input = Vec::with_capacity(64);
            input.extend_from_slice(&acc);
            input.extend_from_slice(&step_hash);
            acc = hash32(&input);
        }
        acc
    }

    fn greedy_search_layer(
        &self,
        query: &Vector,
        entry: NodeId,
        layer: usize,
        trace: &mut Vec<TraversalStep>,
    ) -> NodeId {
        let mut current = entry;
        loop {
            let Some(current_vec) = self.get_vector(current) else {
                break;
            };
            let current_distance = self.dist(query, &current_vec);

            let Some(current_node) = self.nodes.get(&current) else {
                break;
            };
            if layer >= current_node.neighbors.len() {
                break;
            }

            let mut neighbors = current_node.neighbors[layer].clone();
            Self::dedup_sorted_ids(&mut neighbors);

            let mut best_id = current;
            let mut best_distance = current_distance;
            for &neighbor_id in &neighbors {
                if let Some(n_vec) = self.get_vector(neighbor_id) {
                    let d = self.dist(query, &n_vec);
                    if cmp_distance_then_id(d, neighbor_id, best_distance, best_id)
                        == Ordering::Less
                    {
                        best_id = neighbor_id;
                        best_distance = d;
                    }
                }
            }

            trace.push(TraversalStep {
                id: current,
                layer: layer as u32,
                hash: current_node.hash,
                vector: current_node.vector.clone(),
                neighbors_at_layer: neighbors.clone(),
                chosen_next: if best_id == current {
                    None
                } else {
                    Some(best_id)
                },
                distance_to_query: current_distance,
                distance_commit: self.build_distance_commit(query, current, layer, &neighbors),
            });

            if best_id == current {
                break;
            }
            current = best_id;
        }
        current
    }

    fn search_layer_candidates(
        &self,
        query: &Vector,
        entry: NodeId,
        ef: usize,
        layer: usize,
    ) -> Vec<Candidate> {
        if !self.nodes.contains_key(&entry) {
            return Vec::new();
        }

        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(entry);

        let visit_budget = ef.max(1).saturating_mul(8).max(64);
        let mut candidates = Vec::new();

        while !queue.is_empty() && visited.len() < visit_budget {
            let mut best_index = 0usize;
            let mut best_candidate = Candidate {
                id: queue[0],
                distance: self
                    .get_vector(queue[0])
                    .map(|v| self.dist(query, &v))
                    .unwrap_or(f32::INFINITY),
            };

            for idx in 1..queue.len() {
                let id = queue[idx];
                let distance = self
                    .get_vector(id)
                    .map(|v| self.dist(query, &v))
                    .unwrap_or(f32::INFINITY);
                let next = Candidate { id, distance };
                if Self::candidate_cmp(next, best_candidate) == Ordering::Less {
                    best_candidate = next;
                    best_index = idx;
                }
            }

            let Some(node_id) = queue.remove(best_index) else {
                continue;
            };
            if !visited.insert(node_id) {
                continue;
            }

            let distance = self
                .get_vector(node_id)
                .map(|v| self.dist(query, &v))
                .unwrap_or(f32::INFINITY);
            candidates.push(Candidate {
                id: node_id,
                distance,
            });

            let Some(node) = self.nodes.get(&node_id) else {
                continue;
            };
            if layer >= node.neighbors.len() {
                continue;
            }

            let mut neighbors = node.neighbors[layer].clone();
            Self::dedup_sorted_ids(&mut neighbors);
            for neighbor in neighbors {
                if !visited.contains(&neighbor) {
                    queue.push_back(neighbor);
                }
            }
        }

        candidates.sort_by(|a, b| Self::candidate_cmp(*a, *b));
        candidates.truncate(ef.max(1));
        candidates
    }

    fn select_neighbor_ids(&self, mut candidates: Vec<Candidate>, limit: usize) -> Vec<NodeId> {
        if limit == 0 {
            return Vec::new();
        }
        candidates.sort_by(|a, b| Self::candidate_cmp(*a, *b));
        let mut out = Vec::with_capacity(limit.min(candidates.len()));
        for candidate in candidates {
            if out.last().copied() == Some(candidate.id) || out.contains(&candidate.id) {
                continue;
            }
            out.push(candidate.id);
            if out.len() >= limit {
                break;
            }
        }
        out
    }

    fn prune_neighbors(&mut self, node_id: NodeId, layer: usize, max_neighbors: usize) {
        let Some(base_vec) = self.get_vector(node_id) else {
            return;
        };

        let current_neighbors = match self.nodes.get(&node_id) {
            Some(node) if layer < node.neighbors.len() => node.neighbors[layer].clone(),
            _ => return,
        };

        let mut scored = Vec::new();
        for neighbor_id in current_neighbors {
            if let Some(neighbor_vec) = self.get_vector(neighbor_id) {
                scored.push(Candidate {
                    id: neighbor_id,
                    distance: self.dist(&base_vec, &neighbor_vec),
                });
            }
        }

        scored.sort_by(|a, b| Self::candidate_cmp(*a, *b));

        let mut pruned = Vec::new();
        for candidate in scored {
            if pruned.contains(&candidate.id) {
                continue;
            }
            pruned.push(candidate.id);
            if pruned.len() >= max_neighbors {
                break;
            }
        }

        if let Some(node) = self.nodes.get_mut(&node_id) {
            if layer < node.neighbors.len() {
                node.neighbors[layer] = pruned;
                node.compute_hash();
            }
        }
    }

    pub fn insert(&mut self, vector: Vector, payload: Vec<u8>) -> Result<(), StateError> {
        let id = self.next_id;
        self.next_id += 1;

        let level = self.deterministic_level(id, &vector, &payload);
        let mut new_node = GraphNode::new(id, vector.clone(), payload, level + 1);

        if self.entry_point.is_none() {
            new_node.compute_hash();
            self.nodes.insert(id, new_node);
            self.entry_point = Some(id);
            self.max_layer = level as u32;
            return Ok(());
        }

        let mut enter = self.entry_point.unwrap_or(id);
        let max_existing_layer = self.max_layer as usize;

        if max_existing_layer > level {
            let mut trace = Vec::new();
            for l in ((level + 1)..=max_existing_layer).rev() {
                enter = self.greedy_search_layer(&vector, enter, l, &mut trace);
            }
        }

        new_node.compute_hash();
        self.nodes.insert(id, new_node);

        let max_link_layer = level.min(max_existing_layer);
        for layer in (0..=max_link_layer).rev() {
            let ef = self.ef_construction as usize;
            let candidates = self.search_layer_candidates(&vector, enter, ef.max(1), layer);
            let max_neighbors = if layer == 0 {
                self.m_max0 as usize
            } else {
                self.m_max as usize
            };

            let selected = self.select_neighbor_ids(candidates, max_neighbors.max(1));
            if let Some(node) = self.nodes.get_mut(&id) {
                if layer < node.neighbors.len() {
                    node.neighbors[layer] = selected.clone();
                }
            }

            for neighbor_id in selected {
                if neighbor_id == id {
                    continue;
                }

                if let Some(neighbor) = self.nodes.get_mut(&neighbor_id) {
                    if layer >= neighbor.neighbors.len() {
                        continue;
                    }
                    if !neighbor.neighbors[layer].contains(&id) {
                        neighbor.neighbors[layer].push(id);
                        neighbor.neighbors[layer].sort_unstable();
                    }
                }

                self.prune_neighbors(neighbor_id, layer, max_neighbors.max(1));
            }

            self.prune_neighbors(id, layer, max_neighbors.max(1));

            if let Some(next_enter) = self
                .nodes
                .get(&id)
                .and_then(|n| n.neighbors.get(layer))
                .and_then(|n| n.first())
                .copied()
            {
                enter = next_enter;
            }
        }

        if let Some(node) = self.nodes.get_mut(&id) {
            node.compute_hash();
        }

        if (level as u32) > self.max_layer {
            self.max_layer = level as u32;
            self.entry_point = Some(id);
        }

        Ok(())
    }

    pub fn delete(&mut self, id: NodeId) -> Result<(), String> {
        if !self.nodes.contains_key(&id) {
            return Err("Node not found".into());
        }

        self.nodes.remove(&id);

        // Scan all nodes to remove incoming edges.
        for node in self.nodes.values_mut() {
            let mut changed = false;
            for layer in &mut node.neighbors {
                if let Some(pos) = layer.iter().position(|&x| x == id) {
                    layer.remove(pos);
                    changed = true;
                }
            }
            if changed {
                node.compute_hash();
            }
        }

        // Update entry point if we deleted it.
        if self.entry_point == Some(id) {
            if self.nodes.is_empty() {
                self.entry_point = None;
                self.max_layer = 0;
            } else {
                let mut max_l = 0usize;
                let mut candidate = None;
                for (&nid, node) in &self.nodes {
                    let level = node.neighbors.len().saturating_sub(1);
                    if level >= max_l {
                        max_l = level;
                        candidate = Some(nid);
                    }
                }
                self.entry_point = candidate;
                self.max_layer = max_l as u32;
            }
        }

        Ok(())
    }

    pub fn search(&self, query: &Vector, k: usize) -> Result<Vec<(Vec<u8>, f32)>, StateError> {
        let policy = RetrievalSearchPolicy::default_for_k(k);
        self.search_with_policy(query, &policy)
    }

    pub fn search_with_policy(
        &self,
        query: &Vector,
        policy: &RetrievalSearchPolicy,
    ) -> Result<Vec<(Vec<u8>, f32)>, StateError> {
        let (results, _) = self.search_with_proof_policy(query, policy)?;
        Ok(results)
    }

    pub fn search_with_proof(
        &self,
        query: &Vector,
        k: usize,
    ) -> Result<(Vec<(Vec<u8>, f32)>, TraversalProof), StateError> {
        let policy = RetrievalSearchPolicy::default_for_k(k);
        self.search_with_proof_policy(query, &policy)
    }

    pub fn search_with_proof_policy(
        &self,
        query: &Vector,
        policy: &RetrievalSearchPolicy,
    ) -> Result<(Vec<(Vec<u8>, f32)>, TraversalProof), StateError> {
        let query_hash = hash32(&vector_to_bytes(query));
        let safe_k = policy.k.max(1) as usize;
        let ef_search = policy.ef_search.max(1) as usize;
        let candidate_limit = policy.candidate_limit.max(safe_k as u32).max(1) as usize;

        if self.entry_point.is_none() {
            return Ok((
                vec![],
                TraversalProof {
                    version: 1,
                    entry_point_id: 0,
                    entry_point_hash: [0; 32],
                    query_hash,
                    policy: policy.clone(),
                    trace: vec![],
                    trace_commit: [0; 32],
                    candidate_ids: vec![],
                    candidate_count_total: 0,
                    candidate_truncated: false,
                    reranked: vec![],
                    results: vec![],
                },
            ));
        }

        let entry_id = self.entry_point.unwrap_or(0);
        let entry_node = self.nodes.get(&entry_id).ok_or(StateError::KeyNotFound)?;
        let mut current = entry_id;
        let mut trace = Vec::new();

        for layer in (1..=self.max_layer as usize).rev() {
            current = self.greedy_search_layer(query, current, layer, &mut trace);
        }

        let mut candidate_scores = self.search_layer_candidates(query, current, ef_search, 0);
        candidate_scores.sort_by(|a, b| Self::candidate_cmp(*a, *b));

        let candidate_count_total = candidate_scores.len() as u32;
        let candidate_truncated = candidate_scores.len() > candidate_limit;
        if candidate_truncated {
            candidate_scores.truncate(candidate_limit);
        }

        let candidate_ids: Vec<NodeId> = candidate_scores.iter().map(|c| c.id).collect();

        let mut reranked = Vec::with_capacity(candidate_ids.len());
        for id in &candidate_ids {
            if let Some(vec) = self.get_vector(*id) {
                reranked.push(CandidateScore {
                    id: *id,
                    distance: self.dist(query, &vec),
                });
            }
        }

        reranked.sort_by(|a, b| cmp_distance_then_id(a.distance, a.id, b.distance, b.id));

        let topk_ids: Vec<NodeId> = reranked.iter().take(safe_k).map(|c| c.id).collect();

        let mut results = Vec::with_capacity(topk_ids.len());
        for id in &topk_ids {
            if let Some(node) = self.nodes.get(id) {
                let distance = reranked
                    .iter()
                    .find(|c| c.id == *id)
                    .map(|c| c.distance)
                    .unwrap_or(f32::INFINITY);
                results.push((node.payload.clone(), distance));
            }
        }

        let trace_commit = Self::compute_trace_commit(&trace);

        let proof = TraversalProof {
            version: 1,
            entry_point_id: entry_id,
            entry_point_hash: entry_node.hash,
            query_hash,
            policy: policy.clone(),
            trace,
            trace_commit,
            candidate_ids,
            candidate_count_total,
            candidate_truncated,
            reranked,
            results: topk_ids,
        };

        Ok((results, proof))
    }

    pub fn verify_traversal_proof(
        &self,
        query: &Vector,
        proof: &TraversalProof,
    ) -> Result<(), StateError> {
        if self.entry_point != Some(proof.entry_point_id) {
            return Err(StateError::Backend("Entry point mismatch".into()));
        }

        let entry = self
            .nodes
            .get(&proof.entry_point_id)
            .ok_or_else(|| StateError::Backend("Missing proof entrypoint".into()))?;
        if entry.hash != proof.entry_point_hash {
            return Err(StateError::Backend("Entrypoint hash mismatch".into()));
        }

        let expected_query_hash = hash32(&vector_to_bytes(query));
        if expected_query_hash != proof.query_hash {
            return Err(StateError::Backend("Query hash mismatch".into()));
        }

        let mut current = proof.entry_point_id;
        for step in &proof.trace {
            if step.id != current {
                return Err(StateError::Backend("Trace continuity mismatch".into()));
            }

            let node = self
                .nodes
                .get(&step.id)
                .ok_or_else(|| StateError::Backend("Trace node missing".into()))?;

            if step.hash != node.hash {
                return Err(StateError::Backend("Trace node hash mismatch".into()));
            }

            if step.vector != node.vector {
                return Err(StateError::Backend("Trace node vector mismatch".into()));
            }

            let layer = step.layer as usize;
            if layer >= node.neighbors.len() {
                return Err(StateError::Backend("Trace layer out of bounds".into()));
            }

            let mut expected_neighbors = node.neighbors[layer].clone();
            Self::dedup_sorted_ids(&mut expected_neighbors);
            let mut observed_neighbors = step.neighbors_at_layer.clone();
            Self::dedup_sorted_ids(&mut observed_neighbors);
            if expected_neighbors != observed_neighbors {
                return Err(StateError::Backend("Trace neighbors mismatch".into()));
            }

            let expected_distance_commit =
                self.build_distance_commit(query, step.id, layer, &observed_neighbors);
            if expected_distance_commit != step.distance_commit {
                return Err(StateError::Backend("Trace distance commit mismatch".into()));
            }

            let Some(curr_vec) = self.get_vector(step.id) else {
                return Err(StateError::Backend(
                    "Trace node vector decode failed".into(),
                ));
            };
            let expected_distance = self.dist(query, &curr_vec);
            if (expected_distance - step.distance_to_query).abs() > 1e-5 {
                return Err(StateError::Backend("Trace distance mismatch".into()));
            }

            if let Some(next_id) = step.chosen_next {
                if !observed_neighbors.contains(&next_id) {
                    return Err(StateError::Backend("Chosen next is not a neighbor".into()));
                }

                let Some(next_vec) = self.get_vector(next_id) else {
                    return Err(StateError::Backend(
                        "Chosen next vector decode failed".into(),
                    ));
                };
                let next_distance = self.dist(query, &next_vec);

                let mut best_id = step.id;
                let mut best_distance = expected_distance;
                for &neighbor in &observed_neighbors {
                    if let Some(n_vec) = self.get_vector(neighbor) {
                        let d = self.dist(query, &n_vec);
                        if cmp_distance_then_id(d, neighbor, best_distance, best_id)
                            == Ordering::Less
                        {
                            best_id = neighbor;
                            best_distance = d;
                        }
                    }
                }

                if best_id != next_id
                    || cmp_distance_then_id(next_distance, next_id, best_distance, best_id)
                        != Ordering::Equal
                {
                    return Err(StateError::Backend("Chosen next is not greedy-best".into()));
                }

                current = next_id;
            } else {
                current = step.id;
            }
        }

        if Self::compute_trace_commit(&proof.trace) != proof.trace_commit {
            return Err(StateError::Backend("Trace commit mismatch".into()));
        }

        let ef_search = proof.policy.ef_search.max(1) as usize;
        let candidate_limit = proof.policy.candidate_limit.max(proof.policy.k.max(1)) as usize;

        let mut expected_candidates = self.search_layer_candidates(query, current, ef_search, 0);
        expected_candidates.sort_by(|a, b| Self::candidate_cmp(*a, *b));
        let expected_total = expected_candidates.len() as u32;
        let expected_truncated = expected_candidates.len() > candidate_limit;
        if expected_truncated {
            expected_candidates.truncate(candidate_limit);
        }
        let expected_ids: Vec<NodeId> = expected_candidates.iter().map(|c| c.id).collect();

        if expected_total != proof.candidate_count_total {
            return Err(StateError::Backend("Candidate total mismatch".into()));
        }
        if expected_truncated != proof.candidate_truncated {
            return Err(StateError::Backend(
                "Candidate truncation flag mismatch".into(),
            ));
        }
        if expected_ids != proof.candidate_ids {
            return Err(StateError::Backend("Candidate ids mismatch".into()));
        }

        let mut expected_reranked = Vec::new();
        for id in &expected_ids {
            if let Some(v) = self.get_vector(*id) {
                expected_reranked.push(CandidateScore {
                    id: *id,
                    distance: self.dist(query, &v),
                });
            }
        }
        expected_reranked.sort_by(|a, b| cmp_distance_then_id(a.distance, a.id, b.distance, b.id));

        if expected_reranked.len() != proof.reranked.len() {
            return Err(StateError::Backend("Reranked length mismatch".into()));
        }

        for (expected, observed) in expected_reranked.iter().zip(&proof.reranked) {
            if expected.id != observed.id {
                return Err(StateError::Backend("Reranked id mismatch".into()));
            }
            if (expected.distance - observed.distance).abs() > 1e-5 {
                return Err(StateError::Backend("Reranked distance mismatch".into()));
            }
        }

        let expected_results: Vec<NodeId> = expected_reranked
            .iter()
            .take(proof.policy.k.max(1) as usize)
            .map(|c| c.id)
            .collect();
        if expected_results != proof.results {
            return Err(StateError::Backend("Top-k results mismatch".into()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::mhnsw::metric::{Euclidean, Vector};

    fn sample_graph() -> HnswGraph<Euclidean> {
        let mut graph = HnswGraph::new(Euclidean, 8, 32);
        for i in 0..24u32 {
            let vector = Vector(vec![i as f32, (i % 3) as f32, (i % 5) as f32]);
            let payload = format!("frame-{i}").into_bytes();
            graph
                .insert(vector, payload)
                .expect("inserting fixture vectors should succeed");
        }
        graph
    }

    fn policy(k: u32, ef_search: u32, candidate_limit: u32) -> RetrievalSearchPolicy {
        RetrievalSearchPolicy {
            k,
            ef_search,
            candidate_limit,
            distance_metric: "euclidean".to_string(),
            embedding_normalized: false,
        }
    }

    #[test]
    fn traversal_proof_roundtrip_verifies() {
        let graph = sample_graph();
        let query = Vector(vec![11.2, 2.0, 1.0]);
        let search_policy = policy(4, 32, 12);

        let (results, proof) = graph
            .search_with_proof_policy(&query, &search_policy)
            .expect("search_with_proof_policy should succeed");

        assert!(!results.is_empty());
        assert_eq!(results.len(), search_policy.k as usize);
        graph
            .verify_traversal_proof(&query, &proof)
            .expect("proof produced by the graph should verify");
    }

    #[test]
    fn traversal_proof_detects_topk_tampering() {
        let graph = sample_graph();
        let query = Vector(vec![7.9, 1.0, 2.0]);
        let search_policy = policy(3, 24, 10);

        let (_, mut proof) = graph
            .search_with_proof_policy(&query, &search_policy)
            .expect("search_with_proof_policy should succeed");
        assert_eq!(proof.results.len(), 3);

        // Mutating result order should invalidate strict top-k semantics.
        proof.results.swap(0, 1);

        let err = graph
            .verify_traversal_proof(&query, &proof)
            .expect_err("tampered top-k order must fail verification");
        assert!(format!("{err}").contains("Top-k results mismatch"));
    }

    #[test]
    fn candidate_truncation_semantics_are_committed() {
        let graph = sample_graph();
        let query = Vector(vec![15.0, 0.5, 4.0]);
        let search_policy = policy(2, 64, 3);

        let (_, proof) = graph
            .search_with_proof_policy(&query, &search_policy)
            .expect("search_with_proof_policy should succeed");

        assert!(proof.candidate_count_total >= proof.candidate_ids.len() as u32);
        assert_eq!(
            proof.candidate_ids.len(),
            (proof.candidate_count_total as usize).min(search_policy.candidate_limit as usize)
        );
        assert_eq!(
            proof.candidate_truncated,
            proof.candidate_count_total > search_policy.candidate_limit
        );
        graph
            .verify_traversal_proof(&query, &proof)
            .expect("candidate completeness metadata must verify");
    }
}
