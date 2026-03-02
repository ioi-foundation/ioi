// Path: crates/scs/src/index.rs

use crate::format::{FrameId, FrameType}; // [FIX] Import FrameType
use crate::{
    build_lower_bound_certificate, l2_distance, verify_lower_bound_certificate,
    CoarseQuantizerCluster, CoarseQuantizerManifest, LowerBoundCertificate, LowerBoundMetric,
};
use anyhow::{anyhow, Result};
use ioi_api::state::VerifiableState;
use ioi_crypto::algorithms::hash::sha256;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::mhnsw::{
    metric::{CosineSimilarity, Vector},
    proof::TraversalProof,
    MHnswIndex,
};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;

pub use ioi_state::tree::mhnsw::proof::RetrievalSearchPolicy;

/// A wrapper for the IOI mHNSW index that handles serialization for the SCS file format.
pub struct VectorIndex {
    /// The underlying mHNSW graph.
    /// We use HashCommitmentScheme (SHA-256) and CosineSimilarity.
    inner: MHnswIndex<HashCommitmentScheme, CosineSimilarity>,
    /// Optional coarse quantizer metadata used for single-level optimality certificates.
    coarse_quantizer: Option<CoarseQuantizerManifest>,
}

/// A serialized artifact of the Vector Index, ready to be written to disk.
#[derive(Debug, Encode, Decode, Serialize, Deserialize)]
pub struct VectorIndexArtifact {
    /// The raw bytes of the serialized mHNSW graph.
    pub bytes: Vec<u8>,
    /// The number of vectors in the index.
    pub count: u64,
    /// The dimension of the vectors.
    pub dimension: u32,
    /// The Merkle Root of the index.
    pub root_hash: [u8; 32],
    /// Optional coarse quantizer metadata for single-level optimality certificates.
    pub coarse_quantizer: Option<CoarseQuantizerManifest>,
}

/// A cryptographic proof that a search result was retrieved correctly from the index.
#[derive(Debug, Encode, Decode, Serialize, Deserialize)]
pub struct RetrievalProof {
    /// The Merkle Root of the index against which this proof is valid.
    pub root_hash: [u8; 32],
    /// The traversal trace proving the greedy search path.
    pub traversal: TraversalProof,
}

#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct CertifiedRetrievalProof {
    pub certificate: LowerBoundCertificate,
    pub quantizer_root: [u8; 32],
    pub visited_cluster_ids: Vec<u32>,
    pub candidate_count_total: u32,
}

#[derive(Debug, Clone)]
struct IndexedVectorPoint {
    frame_id: FrameId,
    frame_type: FrameType,
    visual_hash: [u8; 32],
    vector: Vec<f32>,
}

fn hash32(bytes: &[u8]) -> Result<[u8; 32]> {
    let digest = sha256(bytes).map_err(|e| anyhow!("sha256 failed: {e}"))?;
    let digest_ref = digest.as_ref();
    if digest_ref.len() < 32 {
        return Err(anyhow!("sha256 digest too short: {}", digest_ref.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest_ref[..32]);
    Ok(out)
}

fn decode_vector(vector_bytes: &[u8]) -> Result<Vec<f32>> {
    if vector_bytes.len() % 4 != 0 {
        return Err(anyhow!(
            "vector bytes length must be multiple of 4, got {}",
            vector_bytes.len()
        ));
    }

    let mut out = Vec::with_capacity(vector_bytes.len() / 4);
    for chunk in vector_bytes.chunks_exact(4) {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(chunk);
        out.push(f32::from_le_bytes(bytes));
    }
    Ok(out)
}

fn decode_payload(payload: &[u8]) -> Result<(FrameId, FrameType, [u8; 32])> {
    if payload.len() == 41 {
        let frame_id = FrameId::from_le_bytes(payload[0..8].try_into().unwrap());
        let frame_type = match payload[8] {
            0 => FrameType::Observation,
            1 => FrameType::Thought,
            2 => FrameType::Action,
            3 => FrameType::System,
            4 => FrameType::Skill,
            5 => FrameType::Overlay,
            _ => FrameType::Observation,
        };
        let mut visual_hash = [0u8; 32];
        visual_hash.copy_from_slice(&payload[9..41]);
        return Ok((frame_id, frame_type, visual_hash));
    }

    if payload.len() == 8 {
        let frame_id = FrameId::from_le_bytes(payload.try_into().unwrap());
        return Ok((frame_id, FrameType::Observation, [0u8; 32]));
    }

    Err(anyhow!(
        "corrupt index payload: expected 8 or 41 bytes, got {}",
        payload.len()
    ))
}

fn normalize_vector(values: &[f32]) -> Result<Vec<f32>> {
    let mut sum = 0.0f32;
    for v in values {
        if !v.is_finite() {
            return Err(anyhow!("non-finite vector value"));
        }
        sum += v * v;
    }
    if sum <= 1e-12 {
        return Ok(values.to_vec());
    }
    let inv_norm = 1.0 / sum.sqrt();
    Ok(values.iter().map(|v| v * inv_norm).collect())
}

fn cosine_distance(a: &[f32], b: &[f32]) -> Result<f32> {
    if a.len() != b.len() {
        return Err(anyhow!("dimension mismatch: {} vs {}", a.len(), b.len()));
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a <= 1e-12 || norm_b <= 1e-12 {
        return Ok(1.0);
    }
    Ok(1.0 - (dot / (norm_a * norm_b)).clamp(-1.0, 1.0))
}

fn cmp_distance_then_id(
    left_distance: f32,
    left_id: FrameId,
    right_distance: f32,
    right_id: FrameId,
) -> Ordering {
    match left_distance
        .partial_cmp(&right_distance)
        .unwrap_or(Ordering::Equal)
    {
        Ordering::Equal => left_id.cmp(&right_id),
        ord => ord,
    }
}

impl VectorIndex {
    /// Creates a new, empty Vector Index.
    pub fn new(m: usize, ef_construction: usize) -> Self {
        let scheme = HashCommitmentScheme::new();
        let metric = CosineSimilarity::default();
        Self {
            inner: MHnswIndex::new(scheme, metric, m, ef_construction),
            coarse_quantizer: None,
        }
    }

    /// Inserts a vector embedding associated with a frame.
    ///
    /// # Arguments
    /// * `frame_id` - The ID of the frame this vector belongs to.
    /// * `vector` - The float vector embedding.
    pub fn insert(&mut self, frame_id: FrameId, vector: Vec<f32>) -> Result<()> {
        // [COMPATIBILITY] Delegate to insert_with_metadata with default (Observation) type.
        self.insert_with_metadata(frame_id, vector, FrameType::Observation, [0u8; 32])
    }

    /// [NEW] Inserts a vector embedding with rich metadata (FrameType + Visual Hash).
    /// This enables "Hybrid Search" (filtering by type or visual similarity).
    ///
    /// The payload stored in the graph is:
    /// [FrameId (8)] || [FrameType (1)] || [VisualHash (32)]
    /// Total: 41 bytes.
    pub fn insert_with_metadata(
        &mut self,
        frame_id: FrameId,
        vector: Vec<f32>,
        frame_type: FrameType,
        visual_hash: [u8; 32],
    ) -> Result<()> {
        let vec = Vector(vector);

        let mut payload = Vec::with_capacity(41);
        payload.extend_from_slice(&frame_id.to_le_bytes());

        // Encode FrameType as u8. Assuming basic enum without data variants matches `as u8` or simple match.
        // FrameType implements Encode (SCALE), so we use that for stability.
        // Actually, for compact index, manual byte packing is safer/smaller.
        let type_byte = match frame_type {
            FrameType::Observation => 0,
            FrameType::Thought => 1,
            FrameType::Action => 2,
            FrameType::System => 3,
            FrameType::Skill => 4,
            FrameType::Overlay => 5, // [FIX] Added Overlay variant
        };
        payload.push(type_byte);

        payload.extend_from_slice(&visual_hash);

        self.inner
            .insert_vector(vec, payload)
            .map_err(|e| anyhow!("mHNSW insert failed: {}", e))
    }

    /// Searches the index for the nearest neighbors to a query vector.
    ///
    /// Returns a list of (FrameId, Distance) tuples.
    pub fn search(&self, query: &[f32], k: usize) -> Result<Vec<(FrameId, f32)>> {
        let policy = RetrievalSearchPolicy::default_for_k(k);
        self.search_with_policy(query, &policy)
    }

    /// Searches with an explicit ANN policy and exact rerank semantics.
    pub fn search_with_policy(
        &self,
        query: &[f32],
        policy: &RetrievalSearchPolicy,
    ) -> Result<Vec<(FrameId, f32)>> {
        let q_vec = Vector(query.to_vec());
        let results = self
            .inner
            .graph
            .search_with_policy(&q_vec, policy)
            .map_err(|e| anyhow!("mHNSW search failed: {}", e))?;

        let mut mapped_results = Vec::with_capacity(results.len());
        for (payload, dist) in results {
            // [FIX] Update parser to handle new expanded payload (41 bytes) OR legacy (8 bytes)
            if payload.len() == 8 {
                let frame_id = FrameId::from_le_bytes(payload.try_into().unwrap());
                mapped_results.push((frame_id, dist));
            } else if payload.len() == 41 {
                let frame_id = FrameId::from_le_bytes(payload[0..8].try_into().unwrap());
                mapped_results.push((frame_id, dist));
            } else {
                return Err(anyhow!(
                    "Corrupt index payload: expected 8 or 41 bytes, got {}",
                    payload.len()
                ));
            }
        }
        Ok(mapped_results)
    }

    /// [NEW] Performs a Hybrid Search, returning detailed metadata.
    /// Used by `retrieve_context` to filter results.
    ///
    /// Returns: (FrameId, Distance, FrameType, VisualHash)
    pub fn search_hybrid(
        &self,
        query: &[f32],
        k: usize,
    ) -> Result<Vec<(FrameId, f32, FrameType, [u8; 32])>> {
        let policy = RetrievalSearchPolicy::default_for_k(k);
        self.search_hybrid_with_policy(query, &policy)
    }

    /// Hybrid search with explicit ANN policy and exact rerank semantics.
    pub fn search_hybrid_with_policy(
        &self,
        query: &[f32],
        policy: &RetrievalSearchPolicy,
    ) -> Result<Vec<(FrameId, f32, FrameType, [u8; 32])>> {
        let q_vec = Vector(query.to_vec());
        let results = self
            .inner
            .graph
            .search_with_policy(&q_vec, policy)
            .map_err(|e| anyhow!("mHNSW search failed: {}", e))?;

        let mut mapped_results = Vec::with_capacity(results.len());
        for (payload, dist) in results {
            if payload.len() == 41 {
                let frame_id = FrameId::from_le_bytes(payload[0..8].try_into().unwrap());
                let type_byte = payload[8];
                let mut visual_hash = [0u8; 32];
                visual_hash.copy_from_slice(&payload[9..41]);

                let frame_type = match type_byte {
                    0 => FrameType::Observation,
                    1 => FrameType::Thought,
                    2 => FrameType::Action,
                    3 => FrameType::System,
                    4 => FrameType::Skill,
                    5 => FrameType::Overlay, // [FIX] Added Overlay variant
                    _ => FrameType::Observation, // Fallback
                };

                mapped_results.push((frame_id, dist, frame_type, visual_hash));
            } else if payload.len() == 8 {
                // Legacy fallback
                let frame_id = FrameId::from_le_bytes(payload.try_into().unwrap());
                mapped_results.push((frame_id, dist, FrameType::Observation, [0u8; 32]));
            }
        }
        Ok(mapped_results)
    }

    /// Generates a Proof of Retrieval for a search query.
    ///
    /// This is the key "Trust" feature. It proves that the agent actually searched
    /// this specific memory structure and didn't hallucinate or omit records.
    pub fn generate_proof(&self, query: &[f32], k: usize) -> Result<RetrievalProof> {
        let q_vec = Vector(query.to_vec());
        let policy = RetrievalSearchPolicy::default_for_k(k);

        // Delegate to the inner graph's proof generation logic.
        // We use the `search_with_proof` method which returns both results and the traversal trace.
        let (_, traversal_proof) = self
            .inner
            .graph
            .search_with_proof_policy(&q_vec, &policy)
            .map_err(|e| anyhow!("Proof generation failed: {}", e))?;

        let commitment = self.inner.root_commitment();
        let root_hash: [u8; 32] = commitment
            .as_ref()
            .try_into()
            .map_err(|_| anyhow!("Invalid root hash length"))?;

        Ok(RetrievalProof {
            root_hash,
            traversal: traversal_proof,
        })
    }

    /// Runs hybrid search with proof, returning both decoded hits and traversal proof.
    pub fn search_hybrid_with_proof(
        &self,
        query: &[f32],
        policy: &RetrievalSearchPolicy,
    ) -> Result<(Vec<(FrameId, f32, FrameType, [u8; 32])>, RetrievalProof)> {
        let q_vec = Vector(query.to_vec());
        let (results, traversal_proof) = self
            .inner
            .graph
            .search_with_proof_policy(&q_vec, policy)
            .map_err(|e| anyhow!("mHNSW search_with_proof failed: {}", e))?;

        let mut mapped_results = Vec::with_capacity(results.len());
        for (payload, dist) in results {
            if payload.len() == 41 {
                let frame_id = FrameId::from_le_bytes(payload[0..8].try_into().unwrap());
                let type_byte = payload[8];
                let mut visual_hash = [0u8; 32];
                visual_hash.copy_from_slice(&payload[9..41]);

                let frame_type = match type_byte {
                    0 => FrameType::Observation,
                    1 => FrameType::Thought,
                    2 => FrameType::Action,
                    3 => FrameType::System,
                    4 => FrameType::Skill,
                    5 => FrameType::Overlay,
                    _ => FrameType::Observation,
                };
                mapped_results.push((frame_id, dist, frame_type, visual_hash));
            } else if payload.len() == 8 {
                let frame_id = FrameId::from_le_bytes(payload.try_into().unwrap());
                mapped_results.push((frame_id, dist, FrameType::Observation, [0u8; 32]));
            }
        }

        let commitment = self.inner.root_commitment();
        let root_hash: [u8; 32] = commitment
            .as_ref()
            .try_into()
            .map_err(|_| anyhow!("Invalid root hash length"))?;

        Ok((
            mapped_results,
            RetrievalProof {
                root_hash,
                traversal: traversal_proof,
            },
        ))
    }

    fn collect_index_points(&self) -> Result<Vec<IndexedVectorPoint>> {
        let mut points = Vec::with_capacity(self.inner.graph.nodes.len());
        for node in self.inner.graph.nodes.values() {
            let (frame_id, frame_type, visual_hash) = decode_payload(&node.payload)?;
            let vector = normalize_vector(&decode_vector(&node.vector)?)?;
            points.push(IndexedVectorPoint {
                frame_id,
                frame_type,
                visual_hash,
                vector,
            });
        }

        points.sort_by_key(|point| point.frame_id);
        Ok(points)
    }

    fn build_deterministic_quantizer(
        points: &[IndexedVectorPoint],
    ) -> Result<(CoarseQuantizerManifest, BTreeMap<u32, Vec<usize>>)> {
        if points.is_empty() {
            return Err(anyhow!("cannot build quantizer for empty index"));
        }

        let dimensions = points[0].vector.len();
        if dimensions == 0 {
            return Err(anyhow!("cannot build quantizer for zero-dimension vectors"));
        }

        let cluster_count = points.len().min(16).max(1);
        let total = points.len();
        let base = total / cluster_count;
        let remainder = total % cluster_count;

        let mut cluster_members: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        let mut cursor = 0usize;
        for cluster_id in 0..cluster_count {
            let size = base + if cluster_id < remainder { 1 } else { 0 };
            if size == 0 {
                continue;
            }
            let members: Vec<usize> = (cursor..cursor + size).collect();
            cursor += size;
            cluster_members.insert(cluster_id as u32, members);
        }

        let mut clusters = Vec::with_capacity(cluster_members.len());
        for (cluster_id, members) in &cluster_members {
            let mut centroid = vec![0.0f32; dimensions];
            for &point_index in members {
                let vector = &points[point_index].vector;
                for (dim, value) in vector.iter().enumerate() {
                    centroid[dim] += *value;
                }
            }
            let inv_count = 1.0f32 / (members.len() as f32);
            for value in &mut centroid {
                *value *= inv_count;
            }
            centroid = normalize_vector(&centroid)?;

            let mut radius_l2 = 0.0f32;
            let mut membership_bytes = Vec::with_capacity(members.len() * 8);
            for &point_index in members {
                let vector = &points[point_index].vector;
                let distance = l2_distance(&centroid, vector)?;
                radius_l2 = radius_l2.max(distance);
                membership_bytes.extend_from_slice(&points[point_index].frame_id.to_le_bytes());
            }

            clusters.push(CoarseQuantizerCluster {
                cluster_id: *cluster_id,
                centroid,
                radius_l2,
                member_count: members.len() as u32,
                membership_root: hash32(&membership_bytes)?,
            });
        }

        let quantizer = CoarseQuantizerManifest::new(
            1,
            dimensions as u32,
            LowerBoundMetric::L2,
            true,
            clusters,
        )?;
        Ok((quantizer, cluster_members))
    }

    pub fn search_hybrid_with_certificate(
        &mut self,
        query: &[f32],
        policy: &RetrievalSearchPolicy,
    ) -> Result<(
        Vec<(FrameId, f32, FrameType, [u8; 32])>,
        CertifiedRetrievalProof,
    )> {
        let safe_k = policy.k.max(1) as usize;
        let points = self.collect_index_points()?;
        if points.is_empty() {
            return Err(anyhow!("cannot certify retrieval over empty index"));
        }

        let query_norm = normalize_vector(query)?;
        if query_norm.len() != points[0].vector.len() {
            return Err(anyhow!(
                "query dimension mismatch: {} vs {}",
                query_norm.len(),
                points[0].vector.len()
            ));
        }

        let (quantizer, cluster_members) = Self::build_deterministic_quantizer(&points)?;
        self.set_coarse_quantizer(quantizer.clone())?;

        #[derive(Clone)]
        struct ClusterBound {
            cluster_id: u32,
            lower_bound_l2: f32,
        }

        let mut bounds = Vec::with_capacity(quantizer.clusters.len());
        for cluster in &quantizer.clusters {
            let query_centroid_l2 = l2_distance(&query_norm, &cluster.centroid)?;
            let lb = (query_centroid_l2 - cluster.radius_l2).max(0.0);
            bounds.push(ClusterBound {
                cluster_id: cluster.cluster_id,
                lower_bound_l2: lb,
            });
        }
        bounds.sort_by(|left, right| {
            cmp_distance_then_id(
                left.lower_bound_l2,
                left.cluster_id as u64,
                right.lower_bound_l2,
                right.cluster_id as u64,
            )
        });

        #[derive(Clone)]
        struct ScoredHit {
            frame_id: FrameId,
            frame_type: FrameType,
            visual_hash: [u8; 32],
            cosine_distance: f32,
            l2_distance: f32,
        }

        let mut visited_cluster_ids = Vec::new();
        let mut scored_hits = Vec::<ScoredHit>::new();
        let mut scored_count: usize = 0;

        for bound in &bounds {
            if scored_hits.len() >= safe_k {
                let kth_l2 = scored_hits[safe_k - 1].l2_distance;
                if bound.lower_bound_l2 + 1e-6 >= kth_l2 {
                    break;
                }
            }

            visited_cluster_ids.push(bound.cluster_id);
            if let Some(member_indices) = cluster_members.get(&bound.cluster_id) {
                for point_index in member_indices {
                    let point = &points[*point_index];
                    let cosine_distance = cosine_distance(&query_norm, &point.vector)?;
                    let l2_distance = l2_distance(&query_norm, &point.vector)?;
                    scored_hits.push(ScoredHit {
                        frame_id: point.frame_id,
                        frame_type: point.frame_type,
                        visual_hash: point.visual_hash,
                        cosine_distance,
                        l2_distance,
                    });
                    scored_count += 1;
                }
            }

            scored_hits.sort_by(|left, right| {
                cmp_distance_then_id(
                    left.cosine_distance,
                    left.frame_id,
                    right.cosine_distance,
                    right.frame_id,
                )
            });
            if scored_hits.len() > safe_k {
                scored_hits.truncate(safe_k);
            }
        }

        if scored_hits.is_empty() {
            return Err(anyhow!(
                "certifying retrieval did not produce results for non-empty index"
            ));
        }

        let kth_distance_l2 = if scored_hits.len() >= safe_k {
            scored_hits[safe_k - 1].l2_distance
        } else {
            scored_hits[scored_hits.len() - 1].l2_distance
        };

        let returned_frame_ids: Vec<FrameId> = scored_hits.iter().map(|hit| hit.frame_id).collect();
        let certificate = self.build_lower_bound_certificate(
            &query_norm,
            safe_k as u32,
            kth_distance_l2,
            returned_frame_ids,
            visited_cluster_ids.clone(),
        )?;
        self.verify_lower_bound_certificate(&query_norm, &certificate)?;

        let hits = scored_hits
            .into_iter()
            .map(|hit| {
                (
                    hit.frame_id,
                    hit.cosine_distance,
                    hit.frame_type,
                    hit.visual_hash,
                )
            })
            .collect();

        Ok((
            hits,
            CertifiedRetrievalProof {
                certificate,
                quantizer_root: quantizer.quantizer_root,
                visited_cluster_ids,
                candidate_count_total: scored_count.min(u32::MAX as usize) as u32,
            },
        ))
    }

    /// Exposes traversal verification for callers that hold the query vector.
    pub fn verify_traversal_proof(&self, query: &[f32], proof: &RetrievalProof) -> Result<()> {
        let q_vec = Vector(query.to_vec());
        self.inner
            .graph
            .verify_traversal_proof(&q_vec, &proof.traversal)
            .map_err(|e| anyhow!("Traversal proof verification failed: {}", e))
    }

    /// Installs coarse quantizer metadata for lower-bound certificates.
    pub fn set_coarse_quantizer(&mut self, quantizer: CoarseQuantizerManifest) -> Result<()> {
        quantizer.validate()?;
        self.coarse_quantizer = Some(quantizer);
        Ok(())
    }

    /// Returns current coarse quantizer metadata, if present.
    pub fn coarse_quantizer(&self) -> Option<&CoarseQuantizerManifest> {
        self.coarse_quantizer.as_ref()
    }

    /// Builds a lower-bound certificate for certifying retrieval.
    ///
    /// `kth_distance_l2` must be provided in L2 space. If retrieval was done in
    /// cosine distance over unit vectors, convert via `unit_cosine_distance_to_l2`.
    pub fn build_lower_bound_certificate(
        &self,
        query: &[f32],
        k: u32,
        kth_distance_l2: f32,
        returned_frame_ids: Vec<FrameId>,
        visited_cluster_ids: Vec<u32>,
    ) -> Result<LowerBoundCertificate> {
        let quantizer = self
            .coarse_quantizer
            .as_ref()
            .ok_or_else(|| anyhow!("coarse quantizer not configured"))?;

        let commitment = self.inner.root_commitment();
        let index_root: [u8; 32] = commitment
            .as_ref()
            .try_into()
            .map_err(|_| anyhow!("Invalid root hash length"))?;

        build_lower_bound_certificate(
            index_root,
            quantizer,
            query,
            k,
            kth_distance_l2,
            returned_frame_ids,
            visited_cluster_ids,
        )
    }

    /// Verifies a lower-bound certificate against local committed state.
    pub fn verify_lower_bound_certificate(
        &self,
        query: &[f32],
        certificate: &LowerBoundCertificate,
    ) -> Result<()> {
        let quantizer = self
            .coarse_quantizer
            .as_ref()
            .ok_or_else(|| anyhow!("coarse quantizer not configured"))?;

        let commitment = self.inner.root_commitment();
        let index_root: [u8; 32] = commitment
            .as_ref()
            .try_into()
            .map_err(|_| anyhow!("Invalid root hash length"))?;

        verify_lower_bound_certificate(certificate, query, quantizer, index_root)
    }

    /// Serializes the index to a byte vector for storage in the .scs file.
    pub fn serialize_to_artifact(&self) -> Result<VectorIndexArtifact> {
        // Serialize the internal graph nodes using SCALE codec.
        let graph_bytes = self.inner.graph.encode();

        let count = self.inner.graph.nodes.len() as u64;

        // Infer dimension from the entry point or first node, or default to 0 if empty.
        let dimension = if let Some(eid) = self.inner.graph.entry_point {
            if let Some(node) = self.inner.graph.nodes.get(&eid) {
                // Vector bytes length / 4 (f32)
                (node.vector.len() / 4) as u32
            } else {
                0
            }
        } else {
            0
        };

        let commitment = self.inner.root_commitment();
        let root_hash: [u8; 32] = commitment
            .as_ref()
            .try_into()
            .map_err(|_| anyhow!("Invalid root hash length"))?;

        Ok(VectorIndexArtifact {
            bytes: graph_bytes,
            count,
            dimension,
            root_hash,
            coarse_quantizer: self.coarse_quantizer.clone(),
        })
    }

    /// Deserializes an index from an artifact read from disk.
    pub fn from_artifact(artifact: &VectorIndexArtifact) -> Result<Self> {
        // Reconstruct the graph from bytes
        let graph = ioi_state::tree::mhnsw::graph::HnswGraph::decode(&mut &*artifact.bytes)
            .map_err(|e| anyhow!("Failed to decode HNSW graph: {}", e))?;

        // Use the new public constructor to rebuild the index
        let index = MHnswIndex::from_graph(graph);

        Ok(Self {
            inner: index,
            coarse_quantizer: artifact.coarse_quantizer.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::{CoarseQuantizerCluster, LowerBoundMetric};

    fn sample_quantizer() -> CoarseQuantizerManifest {
        CoarseQuantizerManifest::new(
            1,
            2,
            LowerBoundMetric::L2,
            true,
            vec![
                CoarseQuantizerCluster {
                    cluster_id: 1,
                    centroid: vec![0.0, 0.0],
                    radius_l2: 0.5,
                    member_count: 2,
                    membership_root: [0x11; 32],
                },
                CoarseQuantizerCluster {
                    cluster_id: 2,
                    centroid: vec![8.0, 8.0],
                    radius_l2: 0.4,
                    member_count: 1,
                    membership_root: [0x22; 32],
                },
            ],
        )
        .expect("quantizer should build")
    }

    #[test]
    fn lower_bound_certificate_roundtrip_verifies() {
        let mut index = VectorIndex::new(8, 32);
        index
            .insert(1, vec![0.0, 0.0])
            .expect("insert should succeed");
        index
            .insert(2, vec![0.2, 0.1])
            .expect("insert should succeed");
        index
            .insert(3, vec![8.1, 8.0])
            .expect("insert should succeed");

        index
            .set_coarse_quantizer(sample_quantizer())
            .expect("quantizer should install");

        let query = vec![0.1, 0.1];
        let cert = index
            .build_lower_bound_certificate(&query, 1, 0.3, vec![1], vec![1])
            .expect("certificate should build");

        index
            .verify_lower_bound_certificate(&query, &cert)
            .expect("certificate should verify");
    }

    #[test]
    fn artifact_roundtrip_preserves_quantizer() {
        let mut index = VectorIndex::new(8, 32);
        index
            .set_coarse_quantizer(sample_quantizer())
            .expect("quantizer should install");

        let artifact = index
            .serialize_to_artifact()
            .expect("serialization should succeed");
        assert!(artifact.coarse_quantizer.is_some());

        let restored = VectorIndex::from_artifact(&artifact).expect("deserialization should work");
        assert!(restored.coarse_quantizer().is_some());
    }
}
