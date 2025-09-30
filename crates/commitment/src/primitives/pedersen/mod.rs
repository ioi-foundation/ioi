// Path: crates/commitment/src/primitives/pedersen/mod.rs
//! Pedersen Commitment Scheme implementation using the k256 elliptic curve.

use dcrypt::algorithms::ec::k256::{self as k256, Point, Scalar};
use dcrypt::algorithms::hash::{sha2::Sha256 as dcrypt_sha256, HashFunction};
use depin_sdk_api::commitment::{
    CommitmentScheme, CommitmentStructure, HomomorphicCommitmentScheme, HomomorphicOperation,
    ProofContext, SchemeIdentifier, Selector,
};
use depin_sdk_api::error::CryptoError;
use depin_sdk_crypto::algorithms::hash::sha256;
use parity_scale_codec::{Decode, Encode, Error};
use rand::{rngs::OsRng, RngCore};

/// A Pedersen commitment scheme over the k256 curve.
#[derive(Debug, Clone)]
pub struct PedersenCommitmentScheme {
    /// Generator points for values (G_i)
    value_generators: Vec<Point>,
    /// Generator point for the blinding factor (H)
    blinding_generator: Point,
}

/// A Pedersen commitment, which is a point on the elliptic curve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PedersenCommitment([u8; k256::K256_POINT_COMPRESSED_SIZE]);

impl AsRef<[u8]> for PedersenCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A proof for a Pedersen commitment, containing the value and blinding factor.
#[derive(Debug, Clone)]
pub struct PedersenProof {
    /// Blinding factor (r)
    blinding: Scalar,
    /// Position (i) in the commitment, corresponding to G_i
    position: u64,
    /// The committed value (v)
    value: Vec<u8>,
}

impl Encode for PedersenProof {
    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        // A scalar is always 32 bytes.
        let blinding_bytes = self.blinding.serialize();
        blinding_bytes.encode_to(dest);
        self.position.encode_to(dest);
        self.value.encode_to(dest);
    }
}

impl Decode for PedersenProof {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let blinding_bytes: [u8; 32] = <[u8; 32]>::decode(input)?;
        let blinding =
            Scalar::new(blinding_bytes).map_err(|_| Error::from("Invalid K256Scalar bytes"))?;
        let position = u64::decode(input)?;
        let value = Vec::<u8>::decode(input)?;

        Ok(Self {
            blinding,
            position,
            value,
        })
    }
}

impl PedersenCommitmentScheme {
    /// Create a new Pedersen commitment scheme with the specified number of value generators.
    pub fn new(num_value_generators: usize) -> Result<Self, CryptoError> {
        let mut value_generators = Vec::with_capacity(num_value_generators);
        let g = k256::base_point_g();

        // Generate G_0, G_1, ...
        for i in 0..num_value_generators {
            let scalar = Self::hash_to_scalar(format!("value-generator-{i}").as_bytes())?;
            value_generators.push(
                g.mul(&scalar)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?,
            );
        }

        // Generate H, the blinding generator, from a fixed string to ensure it's
        // deterministic and its discrete log relative to G is unknown.
        let h_scalar = Self::hash_to_scalar(b"depin-sdk-blinding-generator-H")?;
        let blinding_generator = g
            .mul(&h_scalar)
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;

        Ok(Self {
            value_generators,
            blinding_generator,
        })
    }

    /// Generate a random blinding factor
    fn random_blinding() -> k256::Scalar {
        let mut rng = OsRng;
        loop {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            if let Ok(scalar) = Scalar::new(bytes) {
                return scalar;
            }
        }
    }

    /// Convert a value to a scalar by hashing it.
    fn value_to_scalar(value: &impl AsRef<[u8]>) -> Result<k256::Scalar, CryptoError> {
        Self::hash_to_scalar(value.as_ref())
    }

    /// Helper to convert a hash to a valid scalar, re-hashing if necessary.
    fn hash_to_scalar(data: &[u8]) -> Result<k256::Scalar, CryptoError> {
        let mut hash_bytes = dcrypt_sha256::digest(data)
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))?
            .as_ref()
            .to_vec();
        loop {
            let mut array = [0u8; 32];
            array.copy_from_slice(&hash_bytes);
            if let Ok(scalar) = Scalar::new(array) {
                return Ok(scalar);
            }
            hash_bytes = dcrypt_sha256::digest(&hash_bytes)
                .map_err(|e| CryptoError::OperationFailed(e.to_string()))?
                .as_ref()
                .to_vec();
        }
    }
}

impl CommitmentStructure for PedersenCommitmentScheme {
    fn commit_leaf(key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut data = vec![0x00]; // Leaf prefix
        data.extend_from_slice(key);
        data.extend_from_slice(value);
        sha256(&data).map(|h| h.to_vec()).unwrap_or_else(|e| {
            log::error!("CRITICAL: sha256 failed: {}", e);
            vec![0; 32]
        })
    }

    fn commit_branch(left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut data = vec![0x01]; // Branch prefix
        data.extend_from_slice(left);
        data.extend_from_slice(right);
        sha256(&data).map(|h| h.to_vec()).unwrap_or_else(|e| {
            log::error!("CRITICAL: sha256 failed: {}", e);
            vec![0; 32]
        })
    }
}

impl CommitmentScheme for PedersenCommitmentScheme {
    type Commitment = PedersenCommitment;
    type Proof = PedersenProof;
    type Value = Vec<u8>;

    fn commit(&self, values: &[Option<Self::Value>]) -> Result<Self::Commitment, CryptoError> {
        let (position, value) = values
            .iter()
            .enumerate()
            .find_map(|(i, v)| v.as_ref().map(|val| (i, val)))
            .ok_or(CryptoError::InvalidInput(
                "Commitment requires one value".into(),
            ))?;

        if position >= self.value_generators.len() {
            return Err(CryptoError::InvalidInput(format!(
                "Position {} is out of bounds",
                position
            )));
        }

        let value_scalar = Self::value_to_scalar(value)?;
        let blinding_scalar = Self::random_blinding();

        // C = v*G_i + r*H
        let g_i = self.value_generators.get(position).ok_or_else(|| {
            CryptoError::InvalidInput(format!("Generator not found at position {}", position))
        })?;
        let h = &self.blinding_generator;

        let value_term = g_i
            .mul(&value_scalar)
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
        let blinding_term = h
            .mul(&blinding_scalar)
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
        let commitment_point = value_term.add(&blinding_term);

        Ok(PedersenCommitment(commitment_point.serialize_compressed()))
    }

    fn create_proof(
        &self,
        selector: &Selector,
        value: &Self::Value,
    ) -> Result<Self::Proof, CryptoError> {
        let position = match selector {
            Selector::Position(pos) => *pos,
            _ => {
                return Err(CryptoError::Unsupported(
                    "Only position-based selectors are supported".to_string(),
                ))
            }
        };

        if position >= self.value_generators.len() as u64 {
            return Err(CryptoError::InvalidInput(format!(
                "Position {} out of bounds",
                position
            )));
        }

        let blinding = Self::random_blinding();

        Ok(PedersenProof {
            blinding,
            position,
            value: value.clone(),
        })
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        selector: &Selector,
        value: &Self::Value,
        _context: &ProofContext,
    ) -> bool {
        let position = match selector {
            Selector::Position(pos) => *pos,
            _ => return false,
        };

        if position >= self.value_generators.len() as u64
            || position != proof.position
            || &proof.value != value
        {
            return false;
        }

        let commitment_point = match Point::deserialize_compressed(commitment.as_ref()) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let value_scalar = match Self::value_to_scalar(value) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let blinding_scalar = &proof.blinding;

        let g_i = match self.value_generators.get(position as usize) {
            Some(g) => g,
            None => return false,
        };
        let h = &self.blinding_generator;

        let value_term = match g_i.mul(&value_scalar) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let blinding_term = match h.mul(blinding_scalar) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let recomputed_point = value_term.add(&blinding_term);

        commitment_point == recomputed_point
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("pedersen_k256")
    }
}

impl HomomorphicCommitmentScheme for PedersenCommitmentScheme {
    fn add(
        &self,
        a: &Self::Commitment,
        b: &Self::Commitment,
    ) -> Result<Self::Commitment, CryptoError> {
        let point_a = Point::deserialize_compressed(a.as_ref())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let point_b = Point::deserialize_compressed(b.as_ref())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let result_point = point_a.add(&point_b);
        Ok(PedersenCommitment(result_point.serialize_compressed()))
    }

    fn scalar_multiply(
        &self,
        a: &Self::Commitment,
        scalar: i32,
    ) -> Result<Self::Commitment, CryptoError> {
        if scalar <= 0 {
            return Err(CryptoError::InvalidInput(
                "Scalar must be positive".to_string(),
            ));
        }
        let point = Point::deserialize_compressed(a.as_ref())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let mut scalar_bytes = [0u8; 32];
        // --- FIX: Use safe slice access ---
        if let Some(slice) = scalar_bytes.get_mut(..4) {
            slice.copy_from_slice(&scalar.to_le_bytes());
        }
        let s = Scalar::new(scalar_bytes).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let result_point = point
            .mul(&s)
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
        Ok(PedersenCommitment(result_point.serialize_compressed()))
    }

    fn supports_operation(&self, operation: HomomorphicOperation) -> bool {
        matches!(
            operation,
            HomomorphicOperation::Addition | HomomorphicOperation::ScalarMultiplication
        )
    }
}
