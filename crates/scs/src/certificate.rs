// Path: crates/scs/src/certificate.rs

//! Lower-bound certificates for corpus-optimality over committed SCS state.
//!
//! This module defines:
//! 1. A coarse quantizer (IVF-style) manifest committed into index artifacts.
//! 2. Lower-bound certificates that use triangle-inequality pruning:
//!    `LB(cluster) = max(0, ||q - c||_2 - R_cluster)`.
//! 3. Deterministic verification over the committed corpus/index state.

use crate::format::FrameId;
use anyhow::{anyhow, ensure, Result};
use ioi_crypto::algorithms::hash::sha256;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const FLOAT_EPSILON: f32 = 1e-5;

/// Metric allowed for lower-bound certificates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub enum LowerBoundMetric {
    /// Euclidean metric; triangle inequality applies directly.
    L2,
}

/// Committed summary for one IVF cluster.
#[derive(Clone, Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
pub struct CoarseQuantizerCluster {
    /// Stable identifier for the cluster.
    pub cluster_id: u32,
    /// Cluster centroid in embedding space.
    pub centroid: Vec<f32>,
    /// Radius bound: `max_x ||x - centroid||_2` over committed cluster members.
    pub radius_l2: f32,
    /// Number of committed members in this cluster.
    pub member_count: u32,
    /// Commitment to the exact membership set for this cluster.
    pub membership_root: [u8; 32],
}

/// Coarse quantizer manifest committed alongside the ANN index artifact.
#[derive(Clone, Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
pub struct CoarseQuantizerManifest {
    /// Manifest schema version.
    pub version: u8,
    /// Embedding dimensions expected by all centroids.
    pub dimensions: u32,
    /// Metric used for lower-bound math.
    pub metric: LowerBoundMetric,
    /// Whether embeddings are L2-normalized.
    pub embedding_normalized: bool,
    /// Cluster summaries. Semantics are order-independent.
    pub clusters: Vec<CoarseQuantizerCluster>,
    /// Commitment over manifest metadata and sorted cluster summaries.
    pub quantizer_root: [u8; 32],
}

/// Certificate data for one pruned cluster.
#[derive(Clone, Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
pub struct PrunedClusterBound {
    pub cluster_id: u32,
    /// `||q - centroid||_2`
    pub query_centroid_distance_l2: f32,
    /// Committed radius for cluster.
    pub radius_l2: f32,
    /// `max(0, query_centroid_distance_l2 - radius_l2)`
    pub lower_bound_l2: f32,
    /// Cluster membership commitment copied from manifest.
    pub membership_root: [u8; 32],
    /// Cluster member count copied from manifest.
    pub member_count: u32,
}

/// Certificate proving corpus-optimality over committed index state.
#[derive(Clone, Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
pub struct LowerBoundCertificate {
    /// Certificate schema version.
    pub version: u8,
    /// Root of the ANN index state tied to the retrieval.
    pub index_root: [u8; 32],
    /// Root of the committed coarse quantizer manifest.
    pub quantizer_root: [u8; 32],
    /// Hash of query vector bytes.
    pub query_hash: [u8; 32],
    /// Requested top-k.
    pub k: u32,
    /// Distance of returned k-th neighbor in L2 space.
    pub kth_distance_l2: f32,
    /// Returned result IDs from retrieval (optional for human/audit context).
    pub returned_frame_ids: Vec<FrameId>,
    /// Clusters searched directly by retrieval flow.
    pub visited_cluster_ids: Vec<u32>,
    /// Clusters pruned via triangle inequality with explicit bounds.
    pub pruned_clusters: Vec<PrunedClusterBound>,
}

fn hash32(bytes: &[u8]) -> Result<[u8; 32]> {
    let digest = sha256(bytes).map_err(|e| anyhow!("sha256 failed: {e}"))?;
    let digest_bytes = digest.as_ref();
    ensure!(
        digest_bytes.len() >= 32,
        "sha256 digest length too small: {}",
        digest_bytes.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest_bytes[..32]);
    Ok(out)
}

fn vector_to_bytes(vector: &[f32]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(vector.len() * 4);
    for value in vector {
        ensure!(value.is_finite(), "non-finite float in vector");
        out.extend_from_slice(&value.to_le_bytes());
    }
    Ok(out)
}

/// Computes `||a - b||_2`.
pub fn l2_distance(a: &[f32], b: &[f32]) -> Result<f32> {
    ensure!(
        a.len() == b.len(),
        "dimension mismatch: {} vs {}",
        a.len(),
        b.len()
    );
    let mut sum = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        ensure!(x.is_finite() && y.is_finite(), "non-finite vector entry");
        let d = x - y;
        sum += d * d;
    }
    Ok(sum.sqrt())
}

/// Triangle inequality lower bound for any point `x` in cluster:
/// `||q - x||_2 >= max(0, ||q - c||_2 - R)`.
pub fn lower_bound_l2(query_centroid_distance_l2: f32, radius_l2: f32) -> Result<f32> {
    ensure!(
        query_centroid_distance_l2.is_finite() && query_centroid_distance_l2 >= 0.0,
        "invalid query-centroid distance"
    );
    ensure!(
        radius_l2.is_finite() && radius_l2 >= 0.0,
        "invalid cluster radius"
    );
    Ok((query_centroid_distance_l2 - radius_l2).max(0.0))
}

/// Converts cosine distance on unit vectors to L2 distance.
/// For unit vectors, `||u-v||_2 = sqrt(2 * (1 - cos(u,v))) = sqrt(2 * cosine_distance)`.
pub fn unit_cosine_distance_to_l2(cosine_distance: f32) -> Result<f32> {
    ensure!(
        cosine_distance.is_finite() && (0.0..=2.0).contains(&cosine_distance),
        "cosine distance out of range [0, 2]"
    );
    Ok((2.0 * cosine_distance).sqrt())
}

/// Hashes query vector bytes using the same deterministic encoding used by retrieval proofs.
pub fn query_hash(query: &[f32]) -> Result<[u8; 32]> {
    hash32(&vector_to_bytes(query)?)
}

impl CoarseQuantizerManifest {
    /// Builds a manifest and computes a deterministic root commitment.
    pub fn new(
        version: u8,
        dimensions: u32,
        metric: LowerBoundMetric,
        embedding_normalized: bool,
        clusters: Vec<CoarseQuantizerCluster>,
    ) -> Result<Self> {
        let mut manifest = Self {
            version,
            dimensions,
            metric,
            embedding_normalized,
            clusters,
            quantizer_root: [0u8; 32],
        };
        manifest.quantizer_root = manifest.compute_root()?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Deterministic commitment over manifest metadata and sorted cluster summaries.
    pub fn compute_root(&self) -> Result<[u8; 32]> {
        let mut input = Vec::new();
        input.push(self.version);
        input.extend_from_slice(&self.dimensions.to_le_bytes());
        input.extend_from_slice(&(self.embedding_normalized as u8).to_le_bytes());
        input.push(match self.metric {
            LowerBoundMetric::L2 => 0,
        });

        let mut clusters = self.clusters.clone();
        clusters.sort_by_key(|c| c.cluster_id);
        input.extend_from_slice(&(clusters.len() as u32).to_le_bytes());

        for cluster in clusters {
            input.extend_from_slice(&cluster.cluster_id.to_le_bytes());
            input.extend_from_slice(&cluster.member_count.to_le_bytes());
            input.extend_from_slice(&cluster.radius_l2.to_le_bytes());
            input.extend_from_slice(&cluster.membership_root);
            input.extend_from_slice(&vector_to_bytes(&cluster.centroid)?);
        }

        hash32(&input)
    }

    /// Validates quantizer manifest integrity and commitment consistency.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.dimensions > 0, "quantizer dimensions must be > 0");
        ensure!(!self.clusters.is_empty(), "quantizer must contain clusters");

        let mut seen = BTreeSet::new();
        for cluster in &self.clusters {
            ensure!(
                seen.insert(cluster.cluster_id),
                "duplicate cluster_id {}",
                cluster.cluster_id
            );
            ensure!(
                cluster.centroid.len() as u32 == self.dimensions,
                "centroid dimension mismatch for cluster {}",
                cluster.cluster_id
            );
            ensure!(
                cluster.radius_l2.is_finite() && cluster.radius_l2 >= 0.0,
                "invalid radius_l2 for cluster {}",
                cluster.cluster_id
            );
            ensure!(
                cluster.member_count > 0,
                "member_count must be > 0 for cluster {}",
                cluster.cluster_id
            );
        }

        let computed_root = self.compute_root()?;
        ensure!(
            computed_root == self.quantizer_root,
            "quantizer root mismatch: expected {}, got {}",
            hex::encode(self.quantizer_root),
            hex::encode(computed_root)
        );
        Ok(())
    }

    pub fn cluster_by_id(&self, cluster_id: u32) -> Option<&CoarseQuantizerCluster> {
        self.clusters.iter().find(|c| c.cluster_id == cluster_id)
    }
}

/// Builds a lower-bound certificate for certifying retrieval mode.
pub fn build_lower_bound_certificate(
    index_root: [u8; 32],
    quantizer: &CoarseQuantizerManifest,
    query: &[f32],
    k: u32,
    kth_distance_l2: f32,
    returned_frame_ids: Vec<FrameId>,
    visited_cluster_ids: Vec<u32>,
) -> Result<LowerBoundCertificate> {
    quantizer.validate()?;
    ensure!(k > 0, "k must be > 0");
    ensure!(
        kth_distance_l2.is_finite() && kth_distance_l2 >= 0.0,
        "invalid kth_distance_l2"
    );
    ensure!(
        query.len() as u32 == quantizer.dimensions,
        "query dimensions do not match quantizer dimensions"
    );

    let visited: BTreeSet<u32> = visited_cluster_ids.iter().copied().collect();
    ensure!(
        visited.len() == visited_cluster_ids.len(),
        "visited_cluster_ids contains duplicates"
    );

    for cluster_id in &visited {
        ensure!(
            quantizer.cluster_by_id(*cluster_id).is_some(),
            "visited cluster {} not found in quantizer",
            cluster_id
        );
    }

    let mut pruned_clusters = Vec::new();
    for cluster in &quantizer.clusters {
        if visited.contains(&cluster.cluster_id) {
            continue;
        }

        let query_centroid_distance_l2 = l2_distance(query, &cluster.centroid)?;
        let lower_bound = lower_bound_l2(query_centroid_distance_l2, cluster.radius_l2)?;
        pruned_clusters.push(PrunedClusterBound {
            cluster_id: cluster.cluster_id,
            query_centroid_distance_l2,
            radius_l2: cluster.radius_l2,
            lower_bound_l2: lower_bound,
            membership_root: cluster.membership_root,
            member_count: cluster.member_count,
        });
    }

    Ok(LowerBoundCertificate {
        version: 1,
        index_root,
        quantizer_root: quantizer.quantizer_root,
        query_hash: query_hash(query)?,
        k,
        kth_distance_l2,
        returned_frame_ids,
        visited_cluster_ids,
        pruned_clusters,
    })
}

/// Verifies a lower-bound certificate against committed quantizer metadata.
pub fn verify_lower_bound_certificate(
    certificate: &LowerBoundCertificate,
    query: &[f32],
    quantizer: &CoarseQuantizerManifest,
    expected_index_root: [u8; 32],
) -> Result<()> {
    quantizer.validate()?;
    ensure!(
        certificate.index_root == expected_index_root,
        "index root mismatch"
    );
    ensure!(
        certificate.quantizer_root == quantizer.quantizer_root,
        "quantizer root mismatch"
    );
    ensure!(certificate.k > 0, "k must be > 0");
    ensure!(
        certificate.kth_distance_l2.is_finite() && certificate.kth_distance_l2 >= 0.0,
        "invalid kth_distance_l2"
    );
    ensure!(
        query_hash(query)? == certificate.query_hash,
        "query hash mismatch"
    );

    let visited: BTreeSet<u32> = certificate.visited_cluster_ids.iter().copied().collect();
    ensure!(
        visited.len() == certificate.visited_cluster_ids.len(),
        "visited_cluster_ids contains duplicates"
    );

    let mut pruned_ids = BTreeSet::new();
    for bound in &certificate.pruned_clusters {
        ensure!(
            pruned_ids.insert(bound.cluster_id),
            "duplicate pruned cluster {}",
            bound.cluster_id
        );
        ensure!(
            !visited.contains(&bound.cluster_id),
            "cluster {} is both visited and pruned",
            bound.cluster_id
        );

        let cluster = quantizer
            .cluster_by_id(bound.cluster_id)
            .ok_or_else(|| anyhow!("pruned cluster {} not found in quantizer", bound.cluster_id))?;

        ensure!(
            (cluster.radius_l2 - bound.radius_l2).abs() <= FLOAT_EPSILON,
            "radius mismatch for cluster {}",
            bound.cluster_id
        );
        ensure!(
            cluster.membership_root == bound.membership_root,
            "membership_root mismatch for cluster {}",
            bound.cluster_id
        );
        ensure!(
            cluster.member_count == bound.member_count,
            "member_count mismatch for cluster {}",
            bound.cluster_id
        );

        let expected_query_centroid = l2_distance(query, &cluster.centroid)?;
        ensure!(
            (expected_query_centroid - bound.query_centroid_distance_l2).abs() <= FLOAT_EPSILON,
            "query-centroid distance mismatch for cluster {}",
            bound.cluster_id
        );

        let expected_lb = lower_bound_l2(expected_query_centroid, cluster.radius_l2)?;
        ensure!(
            (expected_lb - bound.lower_bound_l2).abs() <= FLOAT_EPSILON,
            "lower bound mismatch for cluster {}",
            bound.cluster_id
        );
        ensure!(
            expected_lb + FLOAT_EPSILON >= certificate.kth_distance_l2,
            "pruned cluster {} violates LB >= d_k condition",
            bound.cluster_id
        );
    }

    for cluster_id in &visited {
        ensure!(
            quantizer.cluster_by_id(*cluster_id).is_some(),
            "visited cluster {} not found in quantizer",
            cluster_id
        );
    }

    let mut covered = visited;
    covered.extend(pruned_ids);
    let total_clusters = quantizer.clusters.len();
    ensure!(
        covered.len() == total_clusters,
        "cluster coverage mismatch: covered {}, expected {}",
        covered.len(),
        total_clusters
    );

    for cluster in &quantizer.clusters {
        ensure!(
            covered.contains(&cluster.cluster_id),
            "cluster {} missing from visited/pruned coverage",
            cluster.cluster_id
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_quantizer() -> CoarseQuantizerManifest {
        CoarseQuantizerManifest::new(
            1,
            2,
            LowerBoundMetric::L2,
            true,
            vec![
                CoarseQuantizerCluster {
                    cluster_id: 11,
                    centroid: vec![0.0, 0.0],
                    radius_l2: 0.4,
                    member_count: 10,
                    membership_root: [0x11; 32],
                },
                CoarseQuantizerCluster {
                    cluster_id: 42,
                    centroid: vec![10.0, 0.0],
                    radius_l2: 0.5,
                    member_count: 8,
                    membership_root: [0x22; 32],
                },
                CoarseQuantizerCluster {
                    cluster_id: 77,
                    centroid: vec![0.0, 10.0],
                    radius_l2: 0.6,
                    member_count: 9,
                    membership_root: [0x33; 32],
                },
            ],
        )
        .expect("quantizer should build")
    }

    #[test]
    fn quantizer_root_is_order_independent() {
        let q1 = sample_quantizer();

        let mut reversed_clusters = q1.clusters.clone();
        reversed_clusters.reverse();
        let q2 = CoarseQuantizerManifest::new(
            q1.version,
            q1.dimensions,
            q1.metric.clone(),
            q1.embedding_normalized,
            reversed_clusters,
        )
        .expect("quantizer should build");

        assert_eq!(q1.quantizer_root, q2.quantizer_root);
    }

    #[test]
    fn lower_bound_certificate_verifies() {
        let quantizer = sample_quantizer();
        let query = vec![0.2, 0.1];
        let cert = build_lower_bound_certificate(
            [0xAA; 32],
            &quantizer,
            &query,
            1,
            0.5,
            vec![1],
            vec![11],
        )
        .expect("certificate should build");

        verify_lower_bound_certificate(&cert, &query, &quantizer, [0xAA; 32])
            .expect("certificate should verify");
    }

    #[test]
    fn certificate_fails_when_lower_bound_is_too_low() {
        let quantizer = sample_quantizer();
        let query = vec![0.2, 0.1];
        let mut cert = build_lower_bound_certificate(
            [0xAA; 32],
            &quantizer,
            &query,
            1,
            0.5,
            vec![1],
            vec![11],
        )
        .expect("certificate should build");
        let max_lb = cert
            .pruned_clusters
            .iter()
            .map(|c| c.lower_bound_l2)
            .fold(0.0f32, f32::max);
        cert.kth_distance_l2 = max_lb + 1.0;

        let err = verify_lower_bound_certificate(&cert, &query, &quantizer, [0xAA; 32])
            .expect_err("verification should fail for invalid LB");
        assert!(
            err.to_string().contains("violates LB >= d_k"),
            "unexpected error: {err}"
        );
    }
}
