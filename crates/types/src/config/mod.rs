// Path: crates/types/src/config/mod.rs

//! Shared configuration structures for core DePIN SDK components.

use serde::{Deserialize, Serialize}; // <-- Add Serialize here

pub mod consensus;
pub use consensus::*;

/// Selects the underlying data structure for the state manager.
#[derive(Debug, Serialize, Deserialize, Clone)] // <-- Add Serialize
#[serde(rename_all = "PascalCase")]
pub enum StateTreeType {
    /// A simple, file-backed B-Tree map. Good for development.
    File,
    /// An in-memory HashMap. Volatile but fast for testing.
    HashMap,
    /// An IAVL (Immutable AVL) tree, providing Merkle proofs.
    IAVL,
    /// A Sparse Merkle Tree, suitable for large key spaces.
    SparseMerkle,
    /// A Verkle Tree, offering smaller proof sizes.
    Verkle,
}

/// Selects the cryptographic commitment primitive to use with the state tree.
#[derive(Debug, Serialize, Deserialize, Clone)] // <-- Add Serialize
#[serde(rename_all = "PascalCase")]
pub enum CommitmentSchemeType {
    /// Simple SHA-256 hashing.
    Hash,
    /// Pedersen commitments, supporting homomorphic addition.
    Pedersen,
    /// KZG (Kate-Zaverucha-Goldberg) polynomial commitments.
    KZG,
    /// Lattice-based commitments, providing quantum resistance.
    Lattice,
}

/// Configuration for the Workload container (`workload.toml`).
#[derive(Debug, Serialize, Deserialize, Clone)] // <-- Add Serialize
pub struct WorkloadConfig {
    /// A list of VM identifiers that are enabled.
    pub enabled_vms: Vec<String>,
    /// The type of state tree to use for the state manager.
    pub state_tree: StateTreeType,
    /// The cryptographic commitment scheme to pair with the state tree.
    pub commitment_scheme: CommitmentSchemeType,
    /// The path to the genesis file for initial state.
    pub genesis_file: String,
    /// The path to the backing file or database for the state tree.
    pub state_file: String,
}
