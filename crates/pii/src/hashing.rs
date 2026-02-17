// Submodule: hashing (deterministic digests)

use anyhow::Result;
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_types::app::agentic::EvidenceGraph;
use parity_scale_codec::Encode;

pub(crate) fn sha256_array(input: &[u8]) -> Result<[u8; 32]> {
    let digest = Sha256::digest(input)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

pub(crate) fn graph_hash(graph: &EvidenceGraph) -> [u8; 32] {
    sha256_array(&graph.encode()).unwrap_or([0u8; 32])
}
