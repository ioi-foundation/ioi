// Path: crates/commitment/src/primitives/kzg/mod.rs
//! KZG Polynomial Commitment Scheme Implementation using dcrypt's BLS12-381 curve.
//!
//! This module provides a working implementation of the KZG scheme, focusing on
//! the cryptographic operations for commitment, proof generation, and verification.
//! It uses the `poly_utils` module for polynomial arithmetic and relies on the
//! `dcrypt` library for all elliptic curve and pairing operations.

// Internal utilities for polynomial math
mod poly_utils;

use self::poly_utils::{poly_div_linear, poly_sub_scalar, Polynomial};
use dcrypt::algorithms::ec::bls12_381::{
    pairing, Bls12_381Scalar as Scalar, G1Affine, G1Projective, G2Affine, G2Projective,
};
// no fft here; we interpolate on x = 0..n-1 directly
use depin_sdk_api::commitment::{
    CommitmentScheme, CommitmentStructure, ProofContext, SchemeIdentifier, Selector,
};
use depin_sdk_api::error::CryptoError;
use depin_sdk_crypto::algorithms::hash::sha256 as crypto_sha256;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::io::{BufReader, Read, Write};
use std::path::Path;

/// A domain separation tag (DST) is crucial for securely hashing to the scalar field.
const KZG_DST_VALUE_TO_SCALAR: &[u8] = b"DEP-SDK-KZG-VALUE-TO-SCALAR-V1";
const KZG_DST_KEY_TO_SCALAR: &[u8] = b"DEP-SDK-KZG-KEY-TO-SCALAR-V1";

/// Opaque witness that lets you produce proofs later without re-supplying the entire input.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct KZGWitness {
    /// Coefficients of P(X) in little-endian field byte representation.
    pub coeffs: Vec<[u8; 32]>,
    /// A fingerprint of the SRS used to create this witness, for safety.
    pub srs_id: [u8; 32],
}

/// Structured Reference String (SRS) for the KZG scheme.
#[derive(Debug, Clone)]
pub struct KZGParams {
    pub g1: G1Affine,
    pub g2: G2Affine,
    pub s_g2: G2Affine,
    pub g1_points: Vec<G1Affine>,
}

impl KZGParams {
    /// Creates a deterministic fingerprint of the SRS parameters.
    pub fn fingerprint(&self) -> Result<[u8; 32], CryptoError> {
        let mut data = Vec::new();
        data.extend_from_slice(self.g1.to_compressed().as_ref());
        data.extend_from_slice(self.g2.to_compressed().as_ref());
        data.extend_from_slice(self.s_g2.to_compressed().as_ref());
        for p in &self.g1_points {
            data.extend_from_slice(p.to_compressed().as_ref());
        }
        crypto_sha256(&data)
    }

    /// Saves the SRS to a file in a canonical, compressed format.
    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        let mut file = std::fs::File::create(path).map_err(|e| e.to_string())?;
        let max_degree = (self.g1_points.len() - 1) as u32;

        // Write header: max_degree (u32)
        file.write_all(&max_degree.to_le_bytes())
            .map_err(|e| e.to_string())?;

        // Write fixed points
        file.write_all(self.g1.to_compressed().as_ref())
            .map_err(|e| e.to_string())?;
        file.write_all(self.g2.to_compressed().as_ref())
            .map_err(|e| e.to_string())?;
        file.write_all(self.s_g2.to_compressed().as_ref())
            .map_err(|e| e.to_string())?;

        // Write G1 points
        for point in &self.g1_points {
            file.write_all(point.to_compressed().as_ref())
                .map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    /// Loads an SRS from a file, performing necessary validation.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let mut reader = BufReader::new(file);

        // Read header
        let mut degree_buf = [0u8; 4];
        reader
            .read_exact(&mut degree_buf)
            .map_err(|e| e.to_string())?;
        let max_degree = u32::from_le_bytes(degree_buf);

        // Read fixed points
        let mut g1_buf = [0u8; 48];
        reader.read_exact(&mut g1_buf).map_err(|e| e.to_string())?;
        let g1 = G1Affine::from_compressed(&g1_buf)
            .map_err(|_| "Failed to decompress G1 point".to_string())?;

        let mut g2_buf = [0u8; 96];
        reader.read_exact(&mut g2_buf).map_err(|e| e.to_string())?;
        let g2 = G2Affine::from_compressed(&g2_buf)
            .into_option()
            .ok_or_else(|| "Failed to decompress G2 point".to_string())?;

        let mut s_g2_buf = [0u8; 96];
        reader
            .read_exact(&mut s_g2_buf)
            .map_err(|e| e.to_string())?;
        let s_g2 = G2Affine::from_compressed(&s_g2_buf)
            .into_option()
            .ok_or_else(|| "Failed to decompress s_G2 point".to_string())?;

        // Read G1 points
        let num_points = (max_degree + 1) as usize;
        let mut g1_points = Vec::with_capacity(num_points);
        for _ in 0..num_points {
            let mut point_buf = [0u8; 48];
            reader
                .read_exact(&mut point_buf)
                .map_err(|e| e.to_string())?;
            let point = G1Affine::from_compressed(&point_buf)
                .map_err(|_| "Failed to decompress G1 point".to_string())?;
            g1_points.push(point);
        }

        // Ensure no trailing data
        if reader.bytes().next().is_some() {
            return Err("Trailing data found in SRS file".to_string());
        }

        Ok(Self {
            g1,
            g2,
            s_g2,
            g1_points,
        })
    }

    pub fn new_insecure_for_testing(s: u64, max_degree: usize) -> Self {
        log::warn!("Generating insecure KZG parameters for testing. DO NOT USE IN PRODUCTION.");
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let s_scalar = Scalar::from(s);
        let s_g2 = G2Affine::from(G2Projective::from(g2) * s_scalar);
        let mut g1_points = Vec::with_capacity(max_degree + 1);
        let g1_proj = G1Projective::from(g1);
        let mut s_pow = Scalar::one();
        for _ in 0..=max_degree {
            g1_points.push(G1Affine::from(g1_proj * s_pow));
            s_pow *= s_scalar;
        }
        Self {
            g1,
            g2,
            s_g2,
            g1_points,
        }
    }
}

/// A KZG commitment to a polynomial, which is a point in G1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct KZGCommitment(pub Vec<u8>);

impl AsRef<[u8]> for KZGCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl KZGCommitment {
    /// Returns the compressed G1 point as a byte slice.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl From<Vec<u8>> for KZGCommitment {
    fn from(v: Vec<u8>) -> Self {
        KZGCommitment(v)
    }
}

/// A KZG proof, which is a commitment to the quotient polynomial (a point in G1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct KZGProof(pub Vec<u8>);

impl AsRef<[u8]> for KZGProof {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl KZGProof {
    /// Returns the compressed G1 point as a byte slice.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl From<Vec<u8>> for KZGProof {
    fn from(v: Vec<u8>) -> Self {
        KZGProof(v)
    }
}

/// KZG polynomial commitment scheme.
#[derive(Debug, Clone)]
pub struct KZGCommitmentScheme {
    pub params: KZGParams,
}

impl KZGCommitmentScheme {
    pub fn new(params: KZGParams) -> Self {
        Self { params }
    }

    fn value_to_scalar(bytes: &[u8]) -> Result<Scalar, String> {
        Scalar::hash_to_field(bytes, KZG_DST_VALUE_TO_SCALAR)
            .map_err(|e| format!("Hash to scalar for value failed: {:?}", e))
    }

    fn key_to_scalar(key: &[u8]) -> Result<Scalar, String> {
        Scalar::hash_to_field(key, KZG_DST_KEY_TO_SCALAR)
            .map_err(|e| format!("Hash to scalar for key failed: {:?}", e))
    }

    #[inline]
    fn position_to_scalar(pos: u64) -> Scalar {
        Scalar::from(pos)
    }

    fn reconstruct_poly(values: &[Option<&[u8]>]) -> Result<Polynomial, String> {
        // Interpolate P such that P(i) = value_to_scalar(values[i]) for i = 0..n-1.
        let ys: Vec<Scalar> = values
            .iter()
            .map(|v_opt| Self::value_to_scalar(v_opt.unwrap_or(&[])))
            .collect::<Result<_, _>>()?;

        let n = ys.len();
        if n == 0 {
            return Ok(Polynomial { coeffs: vec![] });
        }

        // --- Divided differences for x_i = i ---
        // dd[i] holds the i-th element of the current column of the divided-difference table.
        let mut dd = ys;
        let mut a: Vec<Scalar> = Vec::with_capacity(n);
        a.push(*dd.get(0).ok_or("dd cannot be empty here")?); // a0

        // For each order j = 1..n-1, update dd[0..n-j] and take dd[0] as the next Newton coeff
        for j in 1..n {
            // denominator is (x_{i+j} - x_i) = j for all i
            let denom = Scalar::from(j as u64);
            let denom_inv = denom
                .invert()
                .into_option()
                .ok_or_else(|| "Division by zero in Newton interpolation".to_string())?;

            for i in 0..(n - j) {
                let next_val = *dd.get(i + 1).ok_or("dd index out of bounds")?;
                let current_val = *dd.get(i).ok_or("dd index out of bounds")?;
                let new_val = (next_val - current_val) * denom_inv;
                let entry = dd.get_mut(i).ok_or("dd index out of bounds")?;
                *entry = new_val;
            }
            a.push(*dd.get(0).ok_or("dd should not be empty")?); // a_j
        }

        // --- Convert Newton form to monomial coefficients ---
        // P(x) = a[0] + a[1](x-0) + a[2](x-0)(x-1) + ... + a[n-1]∏_{k=0}^{n-2}(x-k)
        let mut coeffs = vec![Scalar::zero(); n];
        let mut basis: Vec<Scalar> = vec![Scalar::one()]; // starts as 1

        for (k, ak) in a.iter().enumerate() {
            // coeffs += ak * basis
            for d in 0..basis.len() {
                let basis_d = *basis.get(d).ok_or("basis index out of bounds")?;
                let coeffs_d = coeffs.get_mut(d).ok_or("coeffs index out of bounds")?;
                *coeffs_d += basis_d * *ak;
            }

            // basis *= (x - k)
            if k + 1 < n {
                let t = Scalar::from(k as u64);
                let mut next = vec![Scalar::zero(); basis.len() + 1];

                // multiply by x (shift right)
                for d in 0..basis.len() {
                    let basis_d = *basis.get(d).ok_or("basis index out of bounds")?;
                    *next.get_mut(d + 1).ok_or("next index out of bounds")? += basis_d;
                }
                // subtract t * basis (constant term)
                for d in 0..basis.len() {
                    let basis_d = *basis.get(d).ok_or("basis index out of bounds")?;
                    *next.get_mut(d).ok_or("next index out of bounds")? -= basis_d * t;
                }
                basis = next;
            }
        }

        Ok(Polynomial { coeffs })
    }

    /// Create a commitment and a witness from input evaluations.
    pub fn commit_with_witness(
        &self,
        values: &[Option<&[u8]>],
    ) -> Result<(KZGCommitment, KZGWitness), CryptoError> {
        let p_poly = Self::reconstruct_poly(values).map_err(CryptoError::Custom)?;

        if p_poly.coeffs.len() > self.params.g1_points.len() {
            return Err(CryptoError::InvalidInput(
                "Cannot commit to polynomial of degree that exceeds SRS size".into(),
            ));
        }

        let points_slice = self
            .params
            .g1_points
            .get(..p_poly.coeffs.len())
            .ok_or_else(|| {
                CryptoError::InvalidInput("SRS size insufficient for polynomial degree".into())
            })?;
        let commitment_point = G1Projective::msm(points_slice, &p_poly.coeffs)
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;

        let commitment = KZGCommitment(G1Affine::from(commitment_point).to_compressed().to_vec());
        let coeffs = p_poly.coeffs.iter().map(|s| s.to_bytes()).collect();
        let srs_id = self.params.fingerprint()?;
        let witness = KZGWitness { coeffs, srs_id };

        Ok((commitment, witness))
    }

    /// Create a proof using a witness (does NOT need the original values again).
    pub fn create_proof_from_witness(
        &self,
        witness: &KZGWitness,
        selector: &Selector,
        opened_value: &[u8],
    ) -> Result<KZGProof, CryptoError> {
        if witness.srs_id != self.params.fingerprint()? {
            return Err(CryptoError::SrsMismatch);
        }
        let coeffs = witness
            .coeffs
            .iter()
            .map(|b| {
                Scalar::from_bytes(b).into_option().ok_or_else(|| {
                    CryptoError::Deserialization(
                        "Failed to deserialize scalar from witness".to_string(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let p = Polynomial { coeffs };

        let z = match selector {
            Selector::Key(k) => Self::key_to_scalar(k),
            Selector::Position(pos) => Ok(Self::position_to_scalar(*pos)),
            _ => Err("KZG requires Selector::Key or Selector::Position".to_string()),
        }
        .map_err(CryptoError::Custom)?;

        let y = Self::value_to_scalar(opened_value).map_err(CryptoError::Custom)?;
        let num_poly = poly_sub_scalar(&p, y);
        let q_poly = poly_div_linear(&num_poly, z).map_err(CryptoError::OperationFailed)?;
        if q_poly.coeffs.len() > self.params.g1_points.len() {
            return Err(CryptoError::InvalidInput(format!(
                "Quotient polynomial degree ({}) exceeds SRS size ({}).",
                q_poly.coeffs.len(),
                self.params.g1_points.len()
            )));
        }
        let points_slice = self
            .params
            .g1_points
            .get(..q_poly.coeffs.len())
            .ok_or_else(|| {
                CryptoError::InvalidInput(
                    "SRS size insufficient for quotient polynomial degree".into(),
                )
            })?;
        let proof_w = G1Projective::msm(points_slice, &q_poly.coeffs)
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
        Ok(KZGProof(G1Affine::from(proof_w).to_compressed().to_vec()))
    }
}

impl CommitmentStructure for KZGCommitmentScheme {
    fn commit_leaf(key: &[u8], value: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok([key, value].concat())
    }
    fn commit_branch(left: &[u8], right: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok([left, right].concat())
    }
}

impl CommitmentScheme for KZGCommitmentScheme {
    type Commitment = KZGCommitment;
    type Proof = KZGProof;
    type Value = Vec<u8>;

    /// `commit(&[Option<Value>])` treats `Value` as **evaluation payload bytes** at positions `0..n-1`
    /// which are converted to field with `value_to_scalar(DST)`, then interpolated over points `0..n-1`.
    /// For production, **use** `commit_with_witness` and `create_proof_from_witness`.
    fn commit(&self, values: &[Option<Self::Value>]) -> Result<Self::Commitment, CryptoError> {
        let values_ref: Vec<_> = values.iter().map(|v| v.as_deref()).collect();
        self.commit_with_witness(&values_ref).map(|(c, _w)| c)
    }

    fn create_proof(
        &self,
        _selector: &Selector,
        value: &Self::Value,
    ) -> Result<Self::Proof, CryptoError> {
        // This implementation of the trait is problematic because it lacks the full
        // polynomial context (the witness). We deserialize the witness from the `value`
        // bytes as a workaround for simple test cases.
        // PRODUCTION USE: Call `commit_with_witness` and `create_proof_from_witness` directly.
        let (witness, selector, opened_value): (KZGWitness, Selector, Vec<u8>) =
            serde_json::from_slice(value.as_ref())
                .map_err(|e| CryptoError::Deserialization(e.to_string()))?;
        self.create_proof_from_witness(&witness, &selector, &opened_value)
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        selector: &Selector,
        value: &Self::Value,
        _context: &ProofContext,
    ) -> bool {
        let commitment_bytes: &[u8; 48] = match commitment.0.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };
        let commitment_c = match G1Affine::from_compressed(commitment_bytes) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let proof_bytes: &[u8; 48] = match proof.0.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };
        let proof_w = match G1Affine::from_compressed(proof_bytes) {
            Ok(w) => w,
            Err(_) => return false,
        };

        let (z, y) = match (
            match selector {
                Selector::Key(k) => Self::key_to_scalar(k),
                Selector::Position(pos) => Ok(Self::position_to_scalar(*pos)),
                _ => Err("KZG requires Selector::Key or Selector::Position".to_string()),
            },
            Self::value_to_scalar(value.as_ref()),
        ) {
            (Ok(z), Ok(y)) => (z, y),
            _ => return false,
        };

        let y_g1 = G1Projective::from(self.params.g1) * y;
        let lhs_p1 = G1Projective::from(commitment_c) - y_g1;
        let lhs_p1_affine = G1Affine::from(lhs_p1);

        let z_g2 = G2Projective::from(self.params.g2) * z;
        let rhs_p2 = G2Projective::from(self.params.s_g2) - z_g2;
        let rhs_p2_affine = G2Affine::from(rhs_p2);

        let lhs_gt = pairing(&lhs_p1_affine, &self.params.g2);
        let rhs_gt = pairing(&proof_w, &rhs_p2_affine);

        lhs_gt == rhs_gt
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("kzg-bls12-381")
    }
}