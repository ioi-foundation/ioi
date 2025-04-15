#!/bin/bash

# setup.sh - Setup script for DePIN SDK development environment using a bottom-up approach

set -e  # Exit on error

echo "Setting up DePIN SDK development environment..."

# Create base directories
mkdir -p crates/{core,commitment_schemes,state_trees,transaction_models,validator,ibc,crypto,homomorphic,chain,test_utils}/src
mkdir -p integration_tests/{commitment_interop,cross_chain,homomorphic_operations,post_quantum,validator_containers}/src
mkdir -p examples/{simple_chain,cross_chain_verification,homomorphic_commitments,post_quantum_chain,validator_deployment}/src
mkdir -p docs/{architecture,guides,api,security,examples}
mkdir -p docker/{standard_validator,hybrid_validator}/config

# Create .devcontainer configuration for VSCode
mkdir -p .devcontainer
cat > .devcontainer/devcontainer.json << 'EOF'
{
    "name": "DePIN SDK Development",
    "image": "mcr.microsoft.com/devcontainers/rust:latest",
    "features": {
        "ghcr.io/devcontainers/features/docker-in-docker:2": {}
    },
    "customizations": {
        "vscode": {
            "extensions": [
                "rust-lang.rust-analyzer",
                "serayuzgur.crates",
                "tamasfe.even-better-toml",
                "vadimcn.vscode-lldb",
                "github.copilot"
            ],
            "settings": {
                "editor.formatOnSave": true,
                "rust-analyzer.checkOnSave.command": "clippy",
                "rust-analyzer.cargo.allFeatures": true
            }
        }
    },
    "remoteUser": "vscode",
    "postCreateCommand": "rustup component add rustfmt clippy"
}
EOF

# Create main Cargo.toml for workspace
cat > Cargo.toml << 'EOF'
[workspace]
members = [
    "crates/core",
    "crates/commitment_schemes",
    "crates/state_trees",
    "crates/transaction_models",
    "crates/validator",
    "crates/ibc",
    "crates/crypto",
    "crates/homomorphic",
    "crates/chain",
    "crates/test_utils",
    "integration_tests/commitment_interop",
    "integration_tests/cross_chain",
    "integration_tests/homomorphic_operations",
    "integration_tests/post_quantum",
    "integration_tests/validator_containers",
    "examples/simple_chain",
    "examples/cross_chain_verification",
    "examples/homomorphic_commitments",
    "examples/post_quantum_chain",
    "examples/validator_deployment",
]

[workspace.dependencies]
log = "0.4"
serde = { version = "1.0", features = ["derive"] }
thiserror = "1.0"
anyhow = "1.0"

# Cryptography
sha2 = "0.10"
ed25519-dalek = "2.0"
pqcrypto = "0.17"
curve25519-dalek = "4.1"

# Utils
bytes = "1.4"
rand = "0.8"
hex = "0.4"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
EOF

# Rust toolchain config
cat > rust-toolchain.toml << 'EOF'
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
EOF

# Rustfmt configuration
cat > rustfmt.toml << 'EOF'
edition = "2021"
max_width = 100
tab_spaces = 4
EOF

# Core crate - The foundation of the SDK
cat > crates/core/Cargo.toml << 'EOF'
[package]
name = "depin-sdk-core"
version = "0.1.0"
edition = "2021"
description = "Core traits and interfaces for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
log = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }
bytes = { workspace = true }
anyhow = { workspace = true }

[features]
default = []
post-quantum = []
homomorphic = []
EOF

# Core traits - CommitmentScheme and HomomorphicCommitmentScheme
cat > crates/core/src/lib.rs << 'EOF'
//! # DePIN SDK Core
//! 
//! Core traits and interfaces for the DePIN SDK.

pub mod commitment;
pub mod state;
pub mod transaction;
pub mod ibc;
pub mod crypto;
pub mod validator;
pub mod homomorphic;
pub mod component;

pub use commitment::*;
pub use state::*;
pub use transaction::*;
pub use ibc::*;
pub use crypto::*;
pub use validator::*;
pub use homomorphic::*;
pub use component::*;
EOF

mkdir -p crates/core/src/{commitment,state,transaction,ibc,crypto,validator,homomorphic,component}/tests

# Commitment module
cat > crates/core/src/commitment/mod.rs << 'EOF'
//! Commitment scheme trait definitions

mod scheme;
mod homomorphic;
mod identifiers;

#[cfg(test)]
mod tests;

pub use scheme::*;
pub use homomorphic::*;
pub use identifiers::*;
EOF

cat > crates/core/src/commitment/scheme.rs << 'EOF'
//! Definition of the CommitmentScheme trait

use std::fmt::Debug;

use crate::commitment::identifiers::SchemeIdentifier;

/// Core trait for all commitment schemes
pub trait CommitmentScheme: Debug + Send + Sync + 'static {
    /// The type of commitment produced
    type Commitment: AsRef<[u8]> + Clone + Send + Sync + 'static;
    
    /// The type of proof for this commitment scheme
    type Proof: Clone + Send + Sync + 'static;

    /// Commit to a vector of values
    fn commit(&self, values: &[Option<Vec<u8>>]) -> Self::Commitment;
    
    /// Create a proof for a specific position and value
    fn create_proof(&self, position: usize, value: &[u8]) -> Result<Self::Proof, String>;
    
    /// Verify a proof against a commitment
    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        position: usize,
        value: &[u8]
    ) -> bool;
    
    /// Get scheme identifier
    fn scheme_id() -> SchemeIdentifier;
}
EOF

cat > crates/core/src/commitment/homomorphic.rs << 'EOF'
//! Definition of the HomomorphicCommitmentScheme trait

use crate::commitment::scheme::CommitmentScheme;

/// Type of homomorphic operation supported
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomomorphicOperation {
    /// Addition of two commitments
    Addition,
    /// Scalar multiplication
    ScalarMultiplication,
    /// Custom operation
    Custom(u32),
}

/// Extended trait for commitment schemes supporting homomorphic operations
pub trait HomomorphicCommitmentScheme: CommitmentScheme {
    /// Add two commitments
    fn add(&self, a: &Self::Commitment, b: &Self::Commitment) -> Result<Self::Commitment, String>;
    
    /// Multiply a commitment by a scalar
    fn scalar_multiply(&self, a: &Self::Commitment, scalar: i32) -> Result<Self::Commitment, String>;
    
    /// Check if this commitment scheme supports specific homomorphic operations
    fn supports_operation(&self, operation: HomomorphicOperation) -> bool;
}
EOF

cat > crates/core/src/commitment/identifiers.rs << 'EOF'
//! Scheme identifier definitions for different commitment types

/// Identifier for commitment schemes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SchemeIdentifier(pub String);

impl SchemeIdentifier {
    /// Create a new scheme identifier
    pub fn new(value: &str) -> Self {
        Self(value.to_string())
    }
}
EOF

mkdir -p crates/core/src/commitment/tests
cat > crates/core/src/commitment/tests/mod.rs << 'EOF'
//! Tests for commitment scheme traits

mod commitment_tests;
EOF

cat > crates/core/src/commitment/tests/commitment_tests.rs << 'EOF'
//! Tests for the commitment scheme traits

#[cfg(test)]
mod tests {
    use crate::commitment::{CommitmentScheme, HomomorphicCommitmentScheme, HomomorphicOperation, SchemeIdentifier};

    // Define a mock commitment scheme for testing
    #[derive(Debug)]
    struct MockCommitmentScheme;

    #[derive(Debug, Clone)]
    struct MockCommitment(Vec<u8>);

    impl AsRef<[u8]> for MockCommitment {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Clone)]
    struct MockProof(Vec<u8>);

    impl CommitmentScheme for MockCommitmentScheme {
        type Commitment = MockCommitment;
        type Proof = MockProof;

        fn commit(&self, values: &[Option<Vec<u8>>]) -> Self::Commitment {
            // Simple mock implementation for testing
            let combined: Vec<u8> = values
                .iter()
                .flat_map(|v| v.clone().unwrap_or_default())
                .collect();
            MockCommitment(combined)
        }

        fn create_proof(&self, position: usize, value: &[u8]) -> Result<Self::Proof, String> {
            // Simple mock implementation for testing
            Ok(MockProof(value.to_vec()))
        }

        fn verify(
            &self,
            _commitment: &Self::Commitment,
            proof: &Self::Proof,
            _position: usize,
            value: &[u8],
        ) -> bool {
            // Simple mock implementation for testing
            proof.0 == value
        }

        fn scheme_id() -> SchemeIdentifier {
            SchemeIdentifier::new("mock")
        }
    }

    #[derive(Debug)]
    struct MockHomomorphicCommitmentScheme;

    impl CommitmentScheme for MockHomomorphicCommitmentScheme {
        type Commitment = MockCommitment;
        type Proof = MockProof;

        fn commit(&self, values: &[Option<Vec<u8>>]) -> Self::Commitment {
            // Simple mock implementation for testing
            let combined: Vec<u8> = values
                .iter()
                .flat_map(|v| v.clone().unwrap_or_default())
                .collect();
            MockCommitment(combined)
        }

        fn create_proof(&self, position: usize, value: &[u8]) -> Result<Self::Proof, String> {
            // Simple mock implementation for testing
            Ok(MockProof(value.to_vec()))
        }

        fn verify(
            &self,
            _commitment: &Self::Commitment,
            proof: &Self::Proof,
            _position: usize,
            value: &[u8],
        ) -> bool {
            // Simple mock implementation for testing
            proof.0 == value
        }

        fn scheme_id() -> SchemeIdentifier {
            SchemeIdentifier::new("mock-homomorphic")
        }
    }

    impl HomomorphicCommitmentScheme for MockHomomorphicCommitmentScheme {
        fn add(&self, a: &Self::Commitment, b: &Self::Commitment) -> Result<Self::Commitment, String> {
            // Simple mock implementation for testing
            let mut result = a.0.clone();
            result.extend_from_slice(&b.0);
            Ok(MockCommitment(result))
        }

        fn scalar_multiply(&self, a: &Self::Commitment, scalar: i32) -> Result<Self::Commitment, String> {
            // Simple mock implementation for testing
            if scalar <= 0 {
                return Err("Scalar must be positive".to_string());
            }
            
            let mut result = Vec::new();
            for _ in 0..scalar {
                result.extend_from_slice(&a.0);
            }
            
            Ok(MockCommitment(result))
        }

        fn supports_operation(&self, operation: HomomorphicOperation) -> bool {
            // Simple mock implementation for testing
            match operation {
                HomomorphicOperation::Addition | HomomorphicOperation::ScalarMultiplication => true,
                HomomorphicOperation::Custom(_) => false,
            }
        }
    }

    #[test]
    fn test_commitment_scheme() {
        let scheme = MockCommitmentScheme;
        
        // Test commit
        let values = vec![Some(vec![1, 2, 3]), Some(vec![4, 5, 6])];
        let commitment = scheme.commit(&values);
        
        // Test create_proof
        let proof = scheme.create_proof(0, &[1, 2, 3]).unwrap();
        
        // Test verify
        assert!(scheme.verify(&commitment, &proof, 0, &[1, 2, 3]));
        assert!(!scheme.verify(&commitment, &proof, 0, &[7, 8, 9]));
        
        // Test scheme_id
        assert_eq!(MockCommitmentScheme::scheme_id().0, "mock");
    }

    #[test]
    fn test_homomorphic_commitment_scheme() {
        let scheme = MockHomomorphicCommitmentScheme;
        
        // Test commit
        let values1 = vec![Some(vec![1, 2, 3])];
        let values2 = vec![Some(vec![4, 5, 6])];
        let commitment1 = scheme.commit(&values1);
        let commitment2 = scheme.commit(&values2);
        
        // Test add
        let sum = scheme.add(&commitment1, &commitment2).unwrap();
        assert_eq!(sum.0, vec![1, 2, 3, 4, 5, 6]);
        
        // Test scalar_multiply
        let product = scheme.scalar_multiply(&commitment1, 3).unwrap();
        assert_eq!(product.0, vec![1, 2, 3, 1, 2, 3, 1, 2, 3]);
        
        // Test supports_operation
        assert!(scheme.supports_operation(HomomorphicOperation::Addition));
        assert!(scheme.supports_operation(HomomorphicOperation::ScalarMultiplication));
        assert!(!scheme.supports_operation(HomomorphicOperation::Custom(42)));
    }
}
EOF

# State module - The next fundamental building block
cat > crates/core/src/state/mod.rs << 'EOF'
//! State tree interface definitions

mod tree;
mod manager;

#[cfg(test)]
mod tests;

pub use tree::*;
pub use manager::*;
EOF

cat > crates/core/src/state/tree.rs << 'EOF'
//! Definition of the StateTree trait

/// Generic state tree operations
pub trait StateTree {
    /// The commitment type this tree uses
    type Commitment;
    
    /// The proof type this tree uses
    type Proof;

    /// Insert a key-value pair
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), String>;
    
    /// Get a value by key
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    
    /// Delete a key-value pair
    fn delete(&mut self, key: &[u8]) -> Result<(), String>;
    
    /// Get the root commitment of the tree
    fn root_commitment(&self) -> Self::Commitment;
    
    /// Create a proof for a specific key
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof>;
    
    /// Verify a proof against the tree's root commitment
    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8]
    ) -> bool;
    
    /// Get the commitment scheme of this tree
    fn commitment_scheme(&self) -> &dyn std::any::Any;
}
EOF

cat > crates/core/src/state/manager.rs << 'EOF'
//! Definition of the StateManager trait

use crate::commitment::CommitmentScheme;

/// State manager trait for handling state operations
pub trait StateManager<CS: CommitmentScheme> {
    /// Get a value by key
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    
    /// Set a value for a key
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), String>;
    
    /// Delete a key-value pair
    fn delete(&mut self, key: &[u8]) -> Result<(), String>;
    
    /// Get the current root commitment
    fn root_commitment(&self) -> CS::Commitment;
    
    /// Create a proof for a specific key
    fn create_proof(&self, key: &[u8]) -> Option<CS::Proof>;
    
    /// Verify a proof against the root commitment
    fn verify_proof(
        &self,
        commitment: &CS::Commitment,
        proof: &CS::Proof,
        key: &[u8],
        value: &[u8]
    ) -> bool;
}
EOF

# Initial implementation for commitment schemes
cat > crates/commitment_schemes/Cargo.toml << 'EOF'
[package]
name = "depin-sdk-commitment-schemes"
version = "0.1.0"
edition = "2021"
description = "Commitment scheme implementations for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../core" }
log = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }
bytes = { workspace = true }
sha2 = { workspace = true }
curve25519-dalek = { workspace = true }
rand = { workspace = true }

[features]
default = []
merkle = []
pedersen = ["depin-sdk-core/homomorphic"]
kzg = []
lattice = ["depin-sdk-core/post-quantum"]
iavl = []
EOF

mkdir -p crates/commitment_schemes/src/{merkle,pedersen,kzg,lattice,iavl,universal}
cat > crates/commitment_schemes/src/lib.rs << 'EOF'
//! # DePIN SDK Commitment Schemes
//!
//! Implementations of various commitment schemes for the DePIN SDK.

pub mod merkle;
pub mod pedersen;
pub mod kzg;
pub mod lattice;
pub mod iavl;
pub mod universal;

use depin-sdk-core::commitment::{CommitmentScheme, HomomorphicCommitmentScheme, SchemeIdentifier};
EOF

# Simple Merkle tree implementation as an example
cat > crates/commitment_schemes/src/merkle/mod.rs << 'EOF'
//! Merkle tree commitment implementation

use std::fmt::Debug;
use sha2::{Sha256, Digest};
use depin-sdk-core::commitment::{CommitmentScheme, SchemeIdentifier};

/// Merkle tree commitment scheme
#[derive(Debug)]
pub struct MerkleCommitmentScheme;

/// Merkle tree commitment
#[derive(Debug, Clone)]
pub struct MerkleCommitment(Vec<u8>);

impl AsRef<[u8]> for MerkleCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Merkle tree proof
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Path from leaf to root
    pub path: Vec<Vec<u8>>,
    /// Indices indicating left/right direction
    pub indices: Vec<bool>,
    /// Position of the leaf
    pub position: usize,
}

impl CommitmentScheme for MerkleCommitmentScheme {
    type Commitment = MerkleCommitment;
    type Proof = MerkleProof;

    fn commit(&self, values: &[Option<Vec<u8>>]) -> Self::Commitment {
        // Simple implementation that hashes all values
        let mut hasher = Sha256::new();
        for value in values {
            if let Some(v) = value {
                hasher.update(v);
            } else {
                hasher.update([0u8]);
            }
        }
        MerkleCommitment(hasher.finalize().to_vec())
    }

    fn create_proof(&self, position: usize, value: &[u8]) -> Result<Self::Proof, String> {
        // Simplified implementation for initial setup
        Ok(MerkleProof {
            path: vec![Sha256::digest(value).to_vec()],
            indices: vec![position % 2 == 0],
            position,
        })
    }

    fn verify(&self, commitment: &Self::Commitment, proof: &Self::Proof, position: usize, value: &[u8]) -> bool {
        // Simplified verification for initial setup
        position == proof.position && !proof.path.is_empty()
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("merkle")
    }
}
EOF

# Initial implementation for state trees
cat > crates/state_trees/Cargo.toml << 'EOF'
[package]
name = "depin-sdk-state-trees"
version = "0.1.0"
edition = "2021"
description = "State tree implementations for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../core" }
depin-sdk-commitment-schemes = { path = "../commitment_schemes" }
log = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }
bytes = { workspace = true }

[features]
default = []
verkle = ["depin-sdk-commitment-schemes/lattice"]
sparse_merkle = ["depin-sdk-commitment-schemes/merkle"]
iavl_plus = ["depin-sdk-commitment-schemes/iavl"]
EOF

mkdir -p crates/state_trees/src/{verkle,sparse_merkle,iavl_plus,generic}
cat > crates/state_trees/src/lib.rs << 'EOF'
//! # DePIN SDK State Trees
//!
//! Implementations of various state tree structures for the DePIN SDK.

pub mod verkle;
pub mod sparse_merkle;
pub mod iavl_plus;
pub mod generic;

use std::any::Any;
use depin-sdk-core::state::StateTree;
use depin-sdk-core::commitment::CommitmentScheme;
EOF

# Basic implementation of sparse merkle tree
cat > crates/state_trees/src/sparse_merkle/mod.rs << 'EOF'
//! Sparse Merkle tree implementation

use std::collections::HashMap;
use std::any::Any;
use depin-sdk-core::state::StateTree;
use depin-sdk-commitment_schemes::merkle::{MerkleCommitmentScheme, MerkleCommitment, MerkleProof};

/// Sparse Merkle tree implementation
pub struct SparseMerkleTree {
    /// Data store
    data: HashMap<Vec<u8>, Vec<u8>>,
    /// Commitment scheme
    scheme: MerkleCommitmentScheme,
}

impl SparseMerkleTree {
    /// Create a new sparse Merkle tree
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            scheme: MerkleCommitmentScheme,
        }
    }
}

impl StateTree for SparseMerkleTree {
    type Commitment = MerkleCommitment;
    type Proof = MerkleProof;

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.data.get(key).cloned()
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), String> {
        self.data.remove(key);
        Ok(())
    }

    fn root_commitment(&self) -> Self::Commitment {
        // Convert data to format expected by commitment scheme
        let values: Vec<Option<Vec<u8>>> = self.data
            .values()
            .map(|v| Some(v.clone()))
            .collect();
        
        self.scheme.commit(&values)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let value = self.get(key)?;
        self.scheme.create_proof(0, &value).ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        _key: &[u8],
        value: &[u8],
    ) -> bool {
        self.scheme.verify(commitment, proof, proof.position, value)
    }

    fn commitment_scheme(&self) -> &dyn Any {
        &self.scheme
    }
}
EOF

# Create Docker configs for validators
mkdir -p docker/standard_validator/config
cat > docker/standard_validator/Dockerfile << 'EOF'
FROM rust:latest as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/depin-sdk-validator /usr/local/bin/

# Copy configuration files
COPY docker/standard_validator/config/* /app/config/

ENTRYPOINT ["depin-sdk-validator"]
EOF

# Create Docker configs for hybrid validator
mkdir -p docker/hybrid_validator/config
cat > docker/hybrid_validator/Dockerfile << 'EOF'
FROM rust:latest as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/depin-sdk-validator-hybrid /usr/local/bin/

# Copy configuration files
COPY docker/hybrid_validator/config/* /app/config/

ENTRYPOINT ["depin-sdk-validator-hybrid"]
EOF

# Create docker-compose for standard validator
cat > docker/standard_validator/docker-compose.yml << 'EOF'
version: '3.8'

services:
  guardian:
    build:
      context: ../..
      dockerfile: docker/standard_validator/Dockerfile
    command: ["guardian"]
    volumes:
      - guardian_data:/app/data
    networks:
      - validator_net

  orchestration:
    build:
      context: ../..
      dockerfile: docker/standard_validator/Dockerfile
    command: ["orchestration"]
    depends_on:
      - guardian
    volumes:
      - orchestration_data:/app/data
    networks:
      - validator_net

  workload:
    build:
      context: ../..
      dockerfile: docker/standard_validator/Dockerfile
    command: ["workload"]
    depends_on:
      - orchestration
    volumes:
      - workload_data:/app/data
    networks:
      - validator_net

networks:
  validator_net:
    driver: bridge

volumes:
  guardian_data:
  orchestration_data:
  workload_data:
EOF

# Create docker-compose for hybrid validator
cat > docker/hybrid_validator/docker-compose.yml << 'EOF'
version: '3.8'

services:
  guardian:
    build:
      context: ../..
      dockerfile: docker/hybrid_validator/Dockerfile
    command: ["guardian"]
    volumes:
      - guardian_data:/app/data
    networks:
      - validator_net

  orchestration:
    build:
      context: ../..
      dockerfile: docker/hybrid_validator/Dockerfile
    command: ["orchestration"]
    depends_on:
      - guardian
    volumes:
      - orchestration_data:/app/data
    networks:
      - validator_net

  workload:
    build:
      context: ../..
      dockerfile: docker/hybrid_validator/Dockerfile
    command: ["workload"]
    depends_on:
      - orchestration
    volumes:
      - workload_data:/app/data
    networks:
      - validator_net

  interface:
    build:
      context: ../..
      dockerfile: docker/hybrid_validator/Dockerfile
    command: ["interface"]
    depends_on:
      - orchestration
    volumes:
      - interface_data:/app/data
    networks:
      - validator_net
    ports:
      - "8080:8080"

  api:
    build:
      context: ../..
      dockerfile: docker/hybrid_validator/Dockerfile
    command: ["api"]
    depends_on:
      - interface
    volumes:
      - api_data:/app/data
    networks:
      - validator_net
    ports:
      - "9090:9090"

networks:
  validator_net:
    driver: bridge

volumes:
  guardian_data:
  orchestration_data:
  workload_data:
  interface_data:
  api_data:
EOF

# Add configuration examples for standard validator
cat > docker/standard_validator/config/guardian.toml << 'EOF'
# Guardian container configuration

[security]
# Security settings for attestation and verification
attestation_enabled = true
tpm_required = true

[boot]
# Boot process configuration
secure_boot_enabled = true
recovery_mode = false

[updates]
# Update management
auto_updates = true
update_channel = "stable"
EOF

cat > docker/standard_validator/config/orchestration.toml << 'EOF'
# Orchestration container configuration

[consensus]
# Consensus mechanism configuration
mechanism = "tendermint"
block_time = 5000  # milliseconds

[networking]
# Networking configuration
p2p_port = 26656
max_connections = 50
peers_file = "/app/data/peers.json"

[resources]
# Resource management
cpu_limit = 4
memory_limit = "4GB"
EOF

cat > docker/standard_validator/config/workload.toml << 'EOF'
# Workload container configuration

[execution]
# Execution environment configuration
vm_isolated = true
wasm_enabled = true

[storage]
# Storage configuration
db_path = "/app/data/blockchain"
db_backend = "rocksdb"
pruning_keep_recent = 100
pruning_interval = 10
EOF

# Add configuration examples for hybrid validator
cat > docker/hybrid_validator/config/guardian.toml << 'EOF'
# Guardian container configuration for hybrid validator

[security]
# Security settings for attestation and verification
attestation_enabled = true
tpm_required = true

[boot]
# Boot process configuration
secure_boot_enabled = true
recovery_mode = false

[updates]
# Update management
auto_updates = true
update_channel = "stable"
EOF

cat > docker/hybrid_validator/config/orchestration.toml << 'EOF'
# Orchestration container configuration for hybrid validator

[consensus]
# Consensus mechanism configuration
mechanism = "tendermint"
block_time = 5000  # milliseconds

[networking]
# Networking configuration
p2p_port = 26656
max_connections = 50
peers_file = "/app/data/peers.json"

[resources]
# Resource management
cpu_limit = 4
memory_limit = "4GB"
EOF

cat > docker/hybrid_validator/config/workload.toml << 'EOF'
# Workload container configuration for hybrid validator

[execution]
# Execution environment configuration
vm_isolated = true
wasm_enabled = true

[storage]
# Storage configuration
db_path = "/app/data/blockchain"
db_backend = "rocksdb"
pruning_keep_recent = 100
pruning_interval = 10
EOF

cat > docker/hybrid_validator/config/interface.toml << 'EOF'
# Interface container configuration for hybrid validator

[networking]
# Connection handling configuration
listen_addr = "0.0.0.0:8080"
max_concurrent = 1000
timeout_ms = 30000

[security]
# Security configuration
tls_enabled = true
cert_path = "/app/config/tls/cert.pem"
key_path = "/app/config/tls/key.pem"
EOF

cat > docker/hybrid_validator/config/api.toml << 'EOF'
# API container configuration for hybrid validator

[api]
# API configuration
listen_addr = "0.0.0.0:9090"
rate_limit = 100  # requests per second
max_body_size = "10MB"

[auth]
# Authentication configuration
auth_required = true
jwt_secret_path = "/app/config/jwt/secret.key"
token_expiry = 86400  # 24 hours in seconds
EOF

# Initial implementation for a simple example
mkdir -p examples/simple_chain/src
cat > examples/simple_chain/Cargo.toml << 'EOF'
[package]
name = "depin-sdk-example-simple-chain"
version = "0.1.0"
edition = "2021"
description = "Simple sovereign app chain example using DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../../crates/core" }
depin-sdk-commitment-schemes = { path = "../../crates/commitment_schemes" }
depin-sdk-state-trees = { path = "../../crates/state_trees" }
log = { workspace = true }
serde = { workspace = true }
anyhow = { workspace = true }
EOF

cat > examples/simple_chain/src/main.rs << 'EOF'
//! A simple example of a sovereign app chain using DePIN SDK
//!
//! This example demonstrates how to create a basic chain with a Merkle tree state

use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::state::StateTree;
use depin_sdk_commitment_schemes::merkle::MerkleCommitmentScheme;
use depin_sdk_state_trees::sparse_merkle::SparseMerkleTree;

fn main() {
    println!("DePIN SDK Simple Chain Example");
    
    // Create a new sparse Merkle tree for state storage
    let mut state_tree = SparseMerkleTree::new();
    
    // Insert some key-value pairs
    state_tree.insert(b"key1", b"value1").expect("Failed to insert key1");
    state_tree.insert(b"key2", b"value2").expect("Failed to insert key2");
    
    // Get the root commitment
    let root_commitment = state_tree.root_commitment();
    println!("Root commitment: {:?}", root_commitment.as_ref());
    
    // Create a proof for key1
    let proof = state_tree.create_proof(b"key1").expect("Failed to create proof");
    
    // Verify the proof
    let value = state_tree.get(b"key1").expect("Failed to get value");
    let verified = state_tree.verify_proof(&root_commitment, &proof, b"key1", &value);
    println!("Proof verification: {}", verified);
    
    // Get the commitment scheme used by the tree
    let scheme = state_tree.commitment_scheme();
    println!("Commitment scheme: {:?}", scheme);
}
EOF

# Create integration test example
mkdir -p integration_tests/commitment_interop/src
cat > integration_tests/commitment_interop/Cargo.toml << 'EOF'
[package]
name = "depin-sdk-integration-commitment-interop"
version = "0.1.0"
edition = "2021"
description = "Integration tests for commitment scheme interoperability"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../../crates/core" }
depin-sdk-commitment-schemes = { path = "../../crates/commitment_schemes" }
depin-sdk-state-trees = { path = "../../crates/state_trees" }
log = { workspace = true }
anyhow = { workspace = true }
EOF

cat > integration_tests/commitment_interop/src/main.rs << 'EOF'
//! Integration tests for commitment scheme interoperability
//!
//! This test demonstrates how different commitment schemes can interoperate
//! using the universal proof format.

use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_commitment_schemes::merkle::MerkleCommitmentScheme;

fn main() {
    println!("Running commitment scheme interoperability tests...");
    
    // Create an instance of MerkleCommitmentScheme
    let merkle_scheme = MerkleCommitmentScheme;
    
    // Test commit function
    let values = vec![Some(b"test data".to_vec())];
    let commitment = merkle_scheme.commit(&values);
    
    println!("Merkle commitment: {:?}", commitment.as_ref());
    
    // Test proof creation and verification
    match merkle_scheme.create_proof(0, b"test data") {
        Ok(proof) => {
            let verified = merkle_scheme.verify(&commitment, &proof, 0, b"test data");
            println!("Merkle proof verification: {}", verified);
            
            if !verified {
                panic!("Merkle proof verification failed");
            }
        },
        Err(e) => panic!("Failed to create Merkle proof: {}", e),
    }
    
    println!("All tests passed successfully!");
}
EOF

# Setup CI/CD workflow for GitHub Actions
mkdir -p .github/workflows
cat > .github/workflows/ci.yml << 'EOF'
name: DePIN SDK CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always

jobs:
  build_and_test:
    name: Build and Test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          profile: minimal
          toolchain: stable
          override: true
          components: rustfmt, clippy
      
      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
          
      - name: Check format
        uses: actions-rs/cargo@v1
        with:
          command: fmt
          args: --all -- --check
          
      - name: Clippy
        uses: actions-rs/cargo@v1
        with:
          command: clippy
          args: --all-targets --all-features -- -D warnings
          
      - name: Build
        uses: actions-rs/cargo@v1
        with:
          command: build
          args: --all-features
          
      - name: Run tests
        uses: actions-rs/cargo@v1
        with:
          command: test
          args: --all-features

  build_examples:
    name: Build Examples
    runs-on: ubuntu-latest
    needs: build_and_test
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          profile: minimal
          toolchain: stable
          override: true
      
      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-examples-${{ hashFiles('**/Cargo.lock') }}
          
      - name: Build examples
        run: |
          for example in examples/*; do
            if [ -d "$example" ]; then
              echo "Building example: $example"
              cargo build --release --manifest-path $example/Cargo.toml
            fi
          done
EOF

# Create documentation example
mkdir -p docs/architecture
cat > docs/architecture/overview.md << 'EOF'
# DePIN SDK Architecture Overview

## Core Architecture

DePIN SDK is a Rust-based, modular framework for building sovereign app chains with post-quantum cryptography, customizable consensus mechanisms, and a flexible container-based validator architecture. 

## Building from the Bottom Up

The DePIN SDK follows a "bottom-up" architecture where each layer builds upon the foundations established by lower layers:

1. **Core Traits and Interfaces**: Foundational traits like `CommitmentScheme` and `StateTree` that define the abstractions used throughout the SDK.

2. **Cryptographic Primitives**: Implementations of both traditional and post-quantum cryptographic algorithms.

3. **Commitment Schemes**: Various implementations of commitment schemes (Merkle, Pedersen, KZG, lattice-based).

4. **State Tree Implementations**: Different state tree structures built on top of commitment schemes.

5. **Transaction Models**: UTXO, account-based, and hybrid transaction models.

6. **Homomorphic Operations**: Support for operations on encrypted data.

7. **IBC Translation Layers**: Cross-chain interoperability mechanisms.

8. **Validator Architecture**: Container-based validator implementations.

9. **App Chain Implementation**: Complete sovereign app chain implementations.

## Polymorphic Design

The SDK uses Rust's trait system to provide a polymorphic architecture that allows components to be swapped out or upgraded without affecting dependent layers. For example, an app chain can change its underlying commitment scheme without modifying its transaction logic.

## Container Security

The validator architecture uses a multi-container approach to create strong security boundaries between components:

- Standard Validator: 3 containers (Guardian, Orchestration, Workload)
- Hybrid Validator: 5 containers (adds Interface and API containers)

## Post-Quantum Security

The SDK provides first-class support for post-quantum cryptographic algorithms:

- Kyber for key encapsulation
- Dilithium, Falcon, and SPHINCS+ for signatures
- Lattice-based vector commitments for Verkle trees

## Getting Started

See the [Getting Started Guide](../guides/getting_started.md) for instructions on setting up your development environment and creating your first app chain with DePIN SDK.
EOF

# Create development helper script
cat > dev-setup.sh << 'EOF'
#!/bin/bash

# dev-setup.sh - Setup development environment for DePIN SDK

set -e  # Exit on error

echo "Setting up DePIN SDK development environment..."

# Check if Rust is installed
if ! command -v rustc &> /dev/null; then
    echo "Rust is not installed. Installing now..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust is already installed."
fi

# Add necessary components
rustup component add rustfmt clippy

# Check if Docker is installed (for development containers)
if ! command -v docker &> /dev/null; then
    echo "WARNING: Docker is not installed. It is recommended for use with dev containers."
    echo "Please install Docker manually to use the container-based development environment."
else
    echo "Docker is installed."
fi

# Install additional dependencies
echo "Installing additional dependencies..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt-get update
    sudo apt-get install -y build-essential pkg-config libssl-dev
elif [[ "$OSTYPE" == "darwin"* ]]; then
    brew install openssl pkg-config
fi

# Initialize Git repository if not already initialized
if [ ! -d .git ]; then
    git init
    git add .
    git commit -m "Initial commit of DePIN SDK"
fi

# Create initial build
echo "Building DePIN SDK..."
cargo build

echo "Development environment setup completed successfully!"
echo "To start development with VSCode dev containers:"
echo "1. Open the project in VSCode"
echo "2. Install the 'Remote - Containers' extension"
echo "3. Click 'Reopen in Container' when prompted, or run the command manually"
echo ""
echo "To build the project:"
echo "cargo build"
echo ""
echo "To run tests:"
echo "cargo test"
EOF

chmod +x dev-setup.sh

# Create quick-start script
cat > quick-start.sh << 'EOF'
#!/bin/bash

# quick-start.sh - Quick start script for running the DePIN SDK example

set -e  # Exit on error

echo "Quick Start for DePIN SDK..."

# Build the simple chain example
echo "Building simple chain example..."
cargo build --manifest-path examples/simple_chain/Cargo.toml

# Run the example
echo "Running simple chain example..."
cargo run --manifest-path examples/simple_chain/Cargo.toml

echo "Example completed successfully!"
echo ""
echo "To explore more examples, check the 'examples/' directory."
echo "To learn more about the architecture, see the documentation in 'docs/'."
EOF

chmod +x quick-start.sh

# Create README file
cat > README.md << 'EOF'
# DePIN SDK

A Rust-based, modular framework for building sovereign app chains with post-quantum cryptography, customizable consensus mechanisms, and a flexible container-based validator architecture.

## Core Features

- **Polymorphic Trait-Based Modularity**: Components are designed as fully interchangeable plugins
- **Homomorphic Commitment Schemes**: Support for operations directly on commitments
- **Commitment Scheme Agility**: Runtime selection of different commitment schemes
- **Post-Quantum Security**: First-class support for PQC algorithms
- **Container Isolation**: Strong security boundaries between components
- **Flexible Transaction Models**: Support for UTXO, account-based, and hybrid models
- **Cross-Chain Interoperability**: Proof translation between different commitment schemes

## Getting Started

### Prerequisites

- Rust (stable channel)
- Docker (for container-based development and validators)
- VS Code with Remote Containers extension (optional but recommended)

### Quick Setup

1. Clone this repository
2. Run the setup script:

```bash
./dev-setup.sh
```

3. Run the quick start example:

```bash
./quick-start.sh
```

### Development with VS Code Dev Containers

This project is configured for development using VS Code's Remote Containers feature:

1. Open the project in VS Code
2. When prompted, click "Reopen in Container"
3. VS Code will build the dev container with all required dependencies

## Project Structure

The DePIN SDK follows a "bottom-up" architecture:

- `crates/core/`: Core traits and interfaces
- `crates/commitment_schemes/`: Commitment scheme implementations
- `crates/state_trees/`: State tree implementations
- `crates/transaction_models/`: Transaction model implementations
- `crates/validator/`: Validator implementation with container architecture
- `crates/ibc/`: Inter-Blockchain Communication implementation
- `crates/crypto/`: Cryptographic implementations including post-quantum
- `crates/homomorphic/`: Homomorphic operations implementation
- `crates/chain/`: Chain implementation components
- `crates/test_utils/`: Utilities for testing the SDK components

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- Architecture overview: `docs/architecture/overview.md`
- Getting started guides: `docs/guides/`
- API documentation: `docs/api/`
- Security documentation: `docs/security/`

## License

This project is licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
EOF

# Create CONTRIBUTING.md
cat > CONTRIBUTING.md << 'EOF'
# Contributing to DePIN SDK

Thank you for considering contributing to DePIN SDK! This document outlines the process for contributing to the project.

## Development Environment

We recommend using VS Code with Dev Containers for development. This ensures a consistent environment for all contributors.

1. Install [VS Code](https://code.visualstudio.com/) and the [Remote Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension
2. Clone the repository
3. Open the project in VS Code
4. When prompted, click "Reopen in Container"

Alternatively, you can set up your local environment:

1. Install Rust (stable channel)
2. Run `./dev-setup.sh` to install dependencies

## Development Workflow

1. Fork the repository
2. Create a new branch for your feature or bug fix
3. Make your changes
4. Ensure all tests pass with `cargo test`
5. Ensure code formatting is correct with `cargo fmt --all -- --check`
6. Ensure no clippy warnings with `cargo clippy --all-targets --all-features -- -D warnings`
7. Submit a pull request

## Bottom-Up Architecture

When implementing new features, follow the "bottom-up" approach:

1. Start with the foundational layers (core traits, cryptographic primitives)
2. Build higher-level components on top of these foundations
3. Ensure each layer has a well-defined API and thorough tests

## Coding Standards

- Follow Rust's official [style guidelines](https://doc.rust-lang.org/1.0.0/style/README.html)
- Use meaningful variable and function names
- Add comments explaining complex logic
- Write comprehensive unit tests
- Document public API with rustdoc comments

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code changes that neither fix bugs nor add features
- `perf`: Performance improvements
- `test`: Adding or fixing tests
- `chore`: Changes to the build process or auxiliary tools

## Pull Request Process

1. Update documentation for any changed functionality
2. Add or update tests for your changes
3. Ensure all CI checks pass
4. Request review from maintainers
5. Address any feedback from code review

## License

By contributing to DePIN SDK, you agree that your contributions will be licensed under both the MIT and Apache 2.0 licenses.
EOF

# Create SECURITY.md
cat > SECURITY.md << 'EOF'
# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in DePIN SDK, please follow these steps:

1. **Do not disclose the vulnerability publicly**
2. Email [security@example.com](mailto:security@example.com) with details about the vulnerability
3. Include steps to reproduce the vulnerability if possible
4. We will acknowledge receipt of your report within 48 hours
5. We will provide an estimated timeline for a fix
6. Once the vulnerability is fixed, we will notify you and publicly acknowledge your contribution (unless you prefer to remain anonymous)

## Security Principles

DePIN SDK follows these security principles:

1. **Defense in Depth**: Multiple layers of security controls
2. **Least Privilege**: Components only have access to what they strictly need
3. **Container Isolation**: Strong security boundaries between components
4. **Cryptographic Agility**: Ability to upgrade cryptographic algorithms
5. **Post-Quantum Security**: First-class support for post-quantum algorithms
6. **Regular Security Audits**: Ongoing review of code and architecture

## Post-Quantum Security

DePIN SDK provides post-quantum security through:

- Kyber for key encapsulation
- Dilithium, Falcon, and SPHINCS+ for signatures
- Lattice-based vector commitments for Verkle trees

For more details on our post-quantum strategy, see `docs/security/post_quantum.md`.
EOF

# Make scripts executable
chmod +x setup.sh dev-setup.sh quick-start.sh

echo "Setup completed! DePIN SDK initial structure created successfully."
echo "To start development with VSCode dev containers, open the project in VSCode and use the Remote Containers extension."
echo "To set up the development environment, run: ./dev-setup.sh"
echo "To run the simple chain example, run: ./quick-start.sh"