// Path: crates/commitment/src/primitives/kzg/mod.rs
//! KZG Polynomial Commitment Scheme Implementation using dcrypt's BLS12-381 curve.
//!
//! This module provides a working implementation of the KZG scheme, focusing on
//! the cryptographic operations for commitment, proof generation, and verification.
//! The polynomial arithmetic (interpolation, division) is represented by placeholder
//! logic and helper functions, which can be swapped with a dedicated polynomial library.

use depin_sdk_api::commitment::{
    CommitmentScheme, CommitmentStructure, ProofContext, SchemeIdentifier, Selector,
};
use depin_sdk_crypto::algorithms::hash::sha256;
use serde::{Deserialize, Serialize}; // <-- Import serde derives
use std::fmt::Debug;
use std::path::Path;

// Use the BLS12-381 curve from dcrypt for pairing-based cryptography.
use dcrypt::algorithms::ec::bls12_381::{
    pairing, Bls12_381Scalar, G1Affine, G1Projective, G2Affine, G2Projective,
};

// A domain separation tag (DST) is crucial for securely hashing to the scalar field.
const KZG_DST: &[u8] = b"DEP-SDK-KZG-HASH-TO-SCALAR-V1";

/// Structured Reference String (SRS) for the KZG scheme.
///
/// In a real network, this must be loaded from a secure, trusted source.
#[derive(Debug, Clone)]
pub struct KZGParams {
    /// Generator of G1, often denoted as `G`.
    pub g1: G1Affine,
    /// Generator of G2, often denoted as `H`.
    pub g2: G2Affine,
    /// The secret `s` from the trusted setup, multiplied by the G2 generator, i.e., `[s]H`.
    pub s_g2: G2Affine,
    /// Powers of `s` in G1: `[s^0]G`, `[s^1]G`, `[s^2]G`, ...
    /// These are required for committing to polynomials.
    pub g1_points: Vec<G1Affine>,
}

impl KZGParams {
    /// Creates a new, insecure SRS for testing purposes.
    ///
    /// # Panics
    /// This function is for testing only and should never be used in production.
    /// The secret `s` is known, making the scheme insecure.
    pub fn new_insecure_for_testing(s: u64, max_degree: usize) -> Self {
        log::warn!("Generating insecure KZG parameters for testing. DO NOT USE IN PRODUCTION.");

        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let s_scalar = Bls12_381Scalar::from(s);
        let s_g2 = G2Affine::from(G2Projective::from(g2) * s_scalar);

        let mut g1_points = Vec::with_capacity(max_degree + 1);
        let g1_proj = G1Projective::from(g1);
        let mut s_pow = Bls12_381Scalar::one();

        for _ in 0..=max_degree {
            let point = G1Affine::from(g1_proj * s_pow);
            g1_points.push(point);
            s_pow *= s_scalar;
        }

        Self {
            g1,
            g2,
            s_g2,
            g1_points,
        }
    }

    /// Loads the SRS from a file.
    /// The file should contain the serialized points in a predefined, secure format.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        log::warn!(
            "SRS loading from file '{}' is not implemented; using insecure testing parameters.",
            path.display()
        );
        Ok(KZGParams::new_insecure_for_testing(12345, 256))
    }
}

/// A KZG commitment to a polynomial, which is a point in G1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] // <-- FIX: Add Serialize, Deserialize
pub struct KZGCommitment(pub Vec<u8>);

impl AsRef<[u8]> for KZGCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A KZG proof, which is a commitment to the quotient polynomial (a point in G1).
/// This represents the witness `W`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] // <-- FIX: Add Serialize, Deserialize
pub struct KZGProof(pub Vec<u8>);

impl AsRef<[u8]> for KZGProof {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// KZG polynomial commitment scheme.
#[derive(Debug, Clone)]
pub struct KZGCommitmentScheme {
    /// Cryptographic parameters from the trusted setup (SRS).
    params: KZGParams,
}

impl KZGCommitmentScheme {
    /// Create a new KZG commitment scheme with the given parameters.
    pub fn new(params: KZGParams) -> Self {
        Self { params }
    }
}

/// Securely hashes a byte slice to a scalar field element using a domain separation tag.
fn hash_to_scalar(bytes: &[u8]) -> Result<Bls12_381Scalar, String> {
    Bls12_381Scalar::hash_to_field(bytes, KZG_DST)
        .map_err(|e| format!("Hash to scalar failed: {:?}", e))
}

/// Computes polynomial subtraction: `p(X) - y`.
fn poly_sub_scalar(poly: &[Bls12_381Scalar], y: Bls12_381Scalar) -> Vec<Bls12_381Scalar> {
    if poly.is_empty() {
        return vec![-y];
    }
    let mut result = poly.to_vec();
    result[0] -= y;
    result
}

/// Computes polynomial division `p(X) / (X - z)` using synthetic division.
fn poly_div_linear(
    poly: &[Bls12_381Scalar],
    z: Bls12_381Scalar,
) -> Result<Vec<Bls12_381Scalar>, String> {
    if poly.is_empty() {
        return Ok(Vec::new());
    }
    let degree = poly.len() - 1;
    let mut quotient = vec![Bls12_381Scalar::zero(); degree];

    let mut last = Bls12_381Scalar::zero();
    for i in (0..=degree).rev() {
        let coeff = poly[i] + last;
        if i > 0 {
            quotient[i - 1] = coeff;
        }
        last = coeff * z;
    }

    Ok(quotient)
}

impl CommitmentStructure for KZGCommitmentScheme {
    fn commit_leaf(key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut data = vec![0x00]; // Leaf prefix
        data.extend_from_slice(key);
        data.extend_from_slice(value);
        sha256(&data)
    }

    fn commit_branch(left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut data = vec![0x01]; // Branch prefix
        data.extend_from_slice(left);
        data.extend_from_slice(right);
        sha256(&data)
    }
}

impl CommitmentScheme for KZGCommitmentScheme {
    type Commitment = KZGCommitment;
    type Proof = KZGProof;
    type Value = Vec<u8>;

    fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
        let coefficients: Vec<Bls12_381Scalar> = values
            .iter()
            .map(|v| {
                v.as_ref()
                    .and_then(|val| hash_to_scalar(val.as_ref()).ok())
                    .unwrap_or_else(Bls12_381Scalar::zero)
            })
            .collect();

        if coefficients.len() > self.params.g1_points.len() {
            log::error!(
                "Cannot commit to {} coefficients with an SRS of size {}",
                coefficients.len(),
                self.params.g1_points.len()
            );
            return KZGCommitment(G1Affine::identity().to_compressed().to_vec());
        }

        // Use the efficient MSM algorithm from dcrypt.
        let commitment_point =
            G1Projective::msm(&self.params.g1_points[..coefficients.len()], &coefficients)
                .expect("MSM failed during commit");

        KZGCommitment(G1Affine::from(commitment_point).to_compressed().to_vec())
    }

    fn create_proof(
        &self,
        selector: &Selector,
        value: &Self::Value,
    ) -> Result<Self::Proof, String> {
        let p_of_x: Vec<Bls12_381Scalar> = vec![
            Bls12_381Scalar::from(3u64),
            Bls12_381Scalar::from(5u64),
            Bls12_381Scalar::from(2u64),
        ];
        log::warn!("KZG create_proof is using a placeholder polynomial.");

        let key_z = match selector {
            Selector::Key(k) => k.as_slice(),
            _ => return Err("KZG create_proof requires a Key selector.".to_string()),
        };
        let z = hash_to_scalar(key_z)?;
        let y = hash_to_scalar(value.as_ref())?;

        let numerator = poly_sub_scalar(&p_of_x, y);
        let q_of_x_coeffs = poly_div_linear(&numerator, z)?;

        if q_of_x_coeffs.len() > self.params.g1_points.len() {
            return Err(format!(
                "Quotient polynomial degree ({}) exceeds SRS size ({}).",
                q_of_x_coeffs.len(),
                self.params.g1_points.len()
            ));
        }

        // Use the efficient MSM algorithm to commit to the quotient polynomial.
        let proof_w = G1Projective::msm(
            &self.params.g1_points[..q_of_x_coeffs.len()],
            &q_of_x_coeffs,
        )
        .map_err(|e| e.to_string())?;

        Ok(KZGProof(G1Affine::from(proof_w).to_compressed().to_vec()))
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        selector: &Selector,
        value: &Self::Value,
        _context: &ProofContext,
    ) -> bool {
        let key_z = match selector {
            Selector::Key(k) => k,
            _ => {
                log::error!("KZG verify requires a Key selector.");
                return false;
            }
        };

        let commitment_c = {
            let mut bytes = [0u8; 48];
            if commitment.0.len() != 48 {
                log::error!(
                    "Invalid commitment length: expected 48, got {}",
                    commitment.0.len()
                );
                return false;
            }
            bytes.copy_from_slice(&commitment.0);
            match G1Affine::from_compressed(&bytes).ok() {
                Some(p) => p,
                None => {
                    log::error!("Failed to deserialize commitment C");
                    return false;
                }
            }
        };

        let proof_w = {
            let mut bytes = [0u8; 48];
            if proof.0.len() != 48 {
                log::error!("Invalid proof length: expected 48, got {}", proof.0.len());
                return false;
            }
            bytes.copy_from_slice(&proof.0);
            match G1Affine::from_compressed(&bytes).ok() {
                Some(p) => p,
                None => {
                    log::error!("Failed to deserialize proof W");
                    return false;
                }
            }
        };

        let (scalar_z, scalar_y) = match (hash_to_scalar(key_z), hash_to_scalar(value.as_ref())) {
            (Ok(z), Ok(y)) => (z, y),
            _ => return false,
        };

        let y_g1 = G1Projective::from(self.params.g1) * scalar_y;
        let lhs_p1 = G1Projective::from(commitment_c) - y_g1;
        let z_g2 = G2Projective::from(self.params.g2) * scalar_z;
        let rhs_p2 = G2Projective::from(self.params.s_g2) - z_g2;
        let lhs_p1_affine = G1Affine::from(lhs_p1);
        let rhs_p2_affine = G2Affine::from(rhs_p2);
        let lhs_gt = pairing(&lhs_p1_affine, &self.params.g2);
        let rhs_gt = pairing(&proof_w, &rhs_p2_affine);

        lhs_gt == rhs_gt
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("kzg-bls12-381")
    }
}
