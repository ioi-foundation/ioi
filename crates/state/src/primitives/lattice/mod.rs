// Path: crates/commitment/src/primitives/lattice/mod.rs
//! Lattice-based commitment scheme implementation.
//!
//! This module implements a Matrix-Vector commitment scheme based on the hardness
//! of the Short Integer Solution (SIS) problem. It uses cryptographic primitives
//! from the `dcrypt` library, specifically its polynomial arithmetic engine tailored
//! for lattice-based cryptography.
//!
//! NOTE: This implementation provides a binding commitment but is NOT hiding. The opening
//! (the proof) reveals the secret vector `r`, which allows anyone to verify the
//! commitment. Future work could explore zero-knowledge openings if hiding properties are required.

use dcrypt::algorithms::poly::{
    params::{Kyber256Params, Modulus},
    polynomial::Polynomial,
    sampling::{CbdSampler, DefaultSamplers, UniformSampler},
};
use ioi_api::commitment::{
    CommitmentScheme, CommitmentStructure, ProofContext, SchemeIdentifier, Selector,
};
use ioi_api::error::CryptoError;
use ioi_crypto::algorithms::hash::sha256;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Public parameters for the lattice commitment scheme.
/// In a real system, these would be generated from a trusted setup or derived from a seed.
#[derive(Debug, Clone)]
pub struct LatticeParams {
    /// A public matrix `A` of polynomials. Dimensions: K x K.
    pub matrix_a: Vec<Vec<Polynomial<Kyber256Params>>>,
    /// A public vector `G` of polynomials.
    pub vector_g: Vec<Polynomial<Kyber256Params>>,
    /// The dimension of the module (K from Kyber).
    pub dimension_k: usize,
    /// The eta parameter for sampling the secret vector from a Centered Binomial Distribution.
    pub eta: u8,
}

impl LatticeParams {
    /// Creates a new, insecure set of parameters for testing purposes.
    /// In production, `A` and `G` MUST be generated from a secure random seed.
    pub fn new_insecure_for_testing(dimension_k: usize, eta: u8) -> Result<Self, CryptoError> {
        let mut rng = rand::rngs::OsRng;

        // Generate a random public matrix A
        let matrix_a = (0..dimension_k)
            .map(|_| {
                (0..dimension_k)
                    .map(|_| {
                        <DefaultSamplers as UniformSampler<Kyber256Params>>::sample_uniform(
                            &mut rng,
                        )
                    })
                    .collect::<Result<_, _>>()
            })
            .collect::<Result<_, _>>()
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;

        // Generate a random public vector G
        let vector_g = (0..dimension_k)
            .map(|_| <DefaultSamplers as UniformSampler<Kyber256Params>>::sample_uniform(&mut rng))
            .collect::<Result<_, _>>()
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;

        Ok(Self {
            matrix_a,
            vector_g,
            dimension_k,
            eta,
        })
    }
}

/// A lattice-based commitment, which is a vector of polynomials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LatticeCommitment {
    coeffs: Vec<Vec<u32>>,
    digest: [u8; 32],
}

impl LatticeCommitment {
    /// Returns the raw polynomial coefficients of the commitment.
    pub fn coeffs(&self) -> &[Vec<u32>] {
        &self.coeffs
    }
    /// Returns the 32-byte digest of the commitment, for tree compatibility.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    /// Provides a canonical serialization of the commitment's coefficients for hashing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.coeffs.len() as u32).to_le_bytes());
        for poly in &self.coeffs {
            out.extend_from_slice(&(poly.len() as u32).to_le_bytes());
            for &c in poly {
                out.extend_from_slice(&c.to_le_bytes());
            }
        }
        out
    }
}

impl AsRef<[u8]> for LatticeCommitment {
    fn as_ref(&self) -> &[u8] {
        // Return the digest so Merkle-style trees can treat this as a 32-byte root.
        &self.digest
    }
}

/// The opening information for a lattice commitment, which includes the message and the secret vector `r`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Encode, Decode)]
pub struct LatticeProof {
    message: Vec<u8>,
    secret_vector_r: Vec<Vec<u32>>,
}

/// The lattice-based commitment scheme.
#[derive(Debug, Clone)]
pub struct LatticeCommitmentScheme {
    params: LatticeParams,
}

impl LatticeCommitmentScheme {
    /// Creates a new lattice commitment scheme with the given parameters.
    pub fn new(params: LatticeParams) -> Self {
        Self { params }
    }
}

impl LatticeProof {
    /// Serializes the proof to a stable byte format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        serde_json::to_vec(self).map_err(|e| CryptoError::OperationFailed(e.to_string()))
    }
}

impl AsRef<[u8]> for LatticeProof {
    fn as_ref(&self) -> &[u8] {
        // This is a temporary solution to satisfy the trait bound.
        // A more robust implementation would serialize to a stable format.
        // For now, we return an empty slice as the raw proof data isn't directly used
        // by the tree structures in the same way a Merkle path is.
        // Callers should use to_bytes() for a meaningful representation.
        &[]
    }
}

/// Helper function to perform matrix-vector multiplication with polynomials.
fn mat_vec_mul(
    matrix: &[Vec<Polynomial<Kyber256Params>>],
    vector: &[Polynomial<Kyber256Params>],
) -> Vec<Polynomial<Kyber256Params>> {
    let k = matrix.len();
    let mut result = vec![Polynomial::<Kyber256Params>::zero(); k];

    for i in 0..k {
        for (j, vector_j) in vector.iter().enumerate().take(k) {
            if let (Some(matrix_ij), Some(result_i)) =
                (matrix.get(i).and_then(|row| row.get(j)), result.get_mut(i))
            {
                let product = matrix_ij.schoolbook_mul(vector_j);
                *result_i = result_i.add(&product);
            }
        }
    }
    result
}

/// Helper function to perform scalar-vector multiplication with polynomials.
fn scalar_vec_mul(
    scalar: &Polynomial<Kyber256Params>,
    vector: &[Polynomial<Kyber256Params>],
) -> Vec<Polynomial<Kyber256Params>> {
    vector.iter().map(|p| p.schoolbook_mul(scalar)).collect()
}

/// Helper to add two vectors of polynomials.
fn vec_add(
    vec_a: &[Polynomial<Kyber256Params>],
    vec_b: &[Polynomial<Kyber256Params>],
) -> Vec<Polynomial<Kyber256Params>> {
    vec_a
        .iter()
        .zip(vec_b.iter())
        .map(|(a, b)| a.add(b))
        .collect()
}

/// Expands a message into a polynomial's coefficients using a hash-based XOF.
fn expand_message_to_ring(msg: &[u8], n: usize, q: u32) -> Result<Vec<u32>, CryptoError> {
    let mut coeffs = Vec::with_capacity(n);
    let mut ctr = 0u32;
    while coeffs.len() < n {
        let mut buf = Vec::with_capacity(msg.len() + 4);
        buf.extend_from_slice(msg);
        buf.extend_from_slice(&ctr.to_le_bytes());
        let block = sha256(&buf)?;
        // Consume 16-bit chunks from the hash block as coefficients mod q.
        for chunk in block.chunks_exact(2) {
            if coeffs.len() < n {
                if let (Some(&byte1), Some(&byte2)) = (chunk.get(0), chunk.get(1)) {
                    let v_u16 = u16::from_le_bytes([byte1, byte2]);
                    let v_u32 = (v_u16 as u32) % q;
                    // Ensure coefficient is centered around 0 for some lattice schemes,
                    // although for basic SIS it's less critical. Here we keep it simple.
                    coeffs.push(v_u32);
                }
            }
        }
        ctr += 1;
    }
    Ok(coeffs)
}

impl CommitmentStructure for LatticeCommitmentScheme {
    fn commit_leaf(key: &[u8], value: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let hash = sha256([key, value].concat())?;
        Ok(hash.to_vec())
    }
    fn commit_branch(left: &[u8], right: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let hash = sha256([left, right].concat())?;
        Ok(hash.to_vec())
    }
}

impl CommitmentScheme for LatticeCommitmentScheme {
    type Commitment = LatticeCommitment;
    type Proof = LatticeProof;
    type Value = Vec<u8>;

    fn commit(&self, values: &[Option<Self::Value>]) -> Result<Self::Commitment, CryptoError> {
        let mut combined = Vec::new();
        for value in values.iter().flatten() {
            combined.extend_from_slice(value.as_ref());
        }
        let message_hash = sha256(&combined)?;

        let m_coeffs = expand_message_to_ring(&message_hash, Kyber256Params::N, Kyber256Params::Q)?;
        let m_poly = Polynomial::<Kyber256Params>::from_coeffs(&m_coeffs)
            .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;

        let mut rng = rand::rngs::OsRng;
        let r_vec: Vec<Polynomial<Kyber256Params>> = (0..self.params.dimension_k)
            .map(|_| {
                <DefaultSamplers as CbdSampler<Kyber256Params>>::sample_cbd(
                    &mut rng,
                    self.params.eta,
                )
            })
            .collect::<Result<_, _>>()
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;

        let ar_term = mat_vec_mul(&self.params.matrix_a, &r_vec);
        let mg_term = scalar_vec_mul(&m_poly, &self.params.vector_g);
        let commitment_vec = vec_add(&ar_term, &mg_term);

        let commitment_coeffs: Vec<Vec<u32>> =
            commitment_vec.into_iter().map(|p| p.coeffs).collect();

        // Calculate digest for tree compatibility
        let digest_bytes = {
            let temp_commit = LatticeCommitment {
                coeffs: commitment_coeffs.clone(),
                digest: [0; 32],
            };
            temp_commit.to_bytes()
        };
        let digest = sha256(&digest_bytes)?;
        Ok(LatticeCommitment {
            coeffs: commitment_coeffs,
            digest,
        })
    }

    fn create_proof(
        &self,
        _selector: &Selector,
        value: &Self::Value,
    ) -> Result<Self::Proof, CryptoError> {
        let mut rng = rand::rngs::OsRng;
        let r_vec: Vec<Polynomial<Kyber256Params>> = (0..self.params.dimension_k)
            .map(|_| {
                <DefaultSamplers as CbdSampler<Kyber256Params>>::sample_cbd(
                    &mut rng,
                    self.params.eta,
                )
            })
            .collect::<Result<_, _>>()
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
        let r_coeffs = r_vec.into_iter().map(|p| p.coeffs).collect();

        Ok(LatticeProof {
            message: value.clone(),
            secret_vector_r: r_coeffs,
        })
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        _selector: &Selector,
        value: &Self::Value,
        _context: &ProofContext,
    ) -> bool {
        if &proof.message != value {
            return false;
        }

        let message_hash = match sha256(value) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let m_coeffs =
            match expand_message_to_ring(&message_hash, Kyber256Params::N, Kyber256Params::Q) {
                Ok(c) => c,
                Err(_) => return false,
            };
        let m_poly = match Polynomial::<Kyber256Params>::from_coeffs(&m_coeffs) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let r_vec: Vec<Polynomial<Kyber256Params>> = match proof
            .secret_vector_r
            .iter()
            .map(|coeffs| Polynomial::<Kyber256Params>::from_coeffs(coeffs))
            .collect()
        {
            Ok(v) => v,
            Err(_) => return false,
        };

        let commitment_vec: Vec<Polynomial<Kyber256Params>> = match commitment
            .coeffs()
            .iter()
            .map(|coeffs| Polynomial::<Kyber256Params>::from_coeffs(coeffs))
            .collect()
        {
            Ok(v) => v,
            Err(_) => return false,
        };

        let ar_term = mat_vec_mul(&self.params.matrix_a, &r_vec);
        let mg_term = scalar_vec_mul(&m_poly, &self.params.vector_g);
        let recomputed_commitment_vec = vec_add(&ar_term, &mg_term);

        if recomputed_commitment_vec.len() != commitment_vec.len() {
            return false;
        }
        recomputed_commitment_vec
            .iter()
            .zip(commitment_vec.iter())
            .all(|(a, b)| a.as_coeffs_slice() == b.as_coeffs_slice())
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("lattice-sis-kyber512")
    }
}
