// Path: crates/commitment/src/primitives/elliptic_curve/mod.rs
//! Elliptic curve commitment implementation

use depin_sdk_api::commitment::{
    CommitmentScheme, HomomorphicCommitmentScheme, HomomorphicOperation, ProofContext,
    SchemeIdentifier, Selector,
};
use depin_sdk_crypto::algorithms::hash;
use dcrypt::algorithms::ec::k256::{self as k256, Point, Scalar};
use rand::{rngs::OsRng, RngCore};

/// Elliptic curve commitment scheme
#[derive(Debug, Clone)]
pub struct EllipticCurveCommitmentScheme {
    /// Generator points
    generators: Vec<Point>,
}

/// Elliptic curve commitment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EllipticCurveCommitment([u8; k256::K256_POINT_COMPRESSED_SIZE]);

impl AsRef<[u8]> for EllipticCurveCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Elliptic curve proof
#[derive(Debug, Clone)]
pub struct EllipticCurveProof {
    /// Blinding factor
    blinding: Scalar,
    /// Position in the commitment
    position: usize,
    /// Value
    value: Vec<u8>,
}

impl EllipticCurveCommitmentScheme {
    /// Create a new elliptic curve commitment scheme with the specified number of generators
    pub fn new(num_generators: usize) -> Self {
        // Generate deterministic generators for reproducible tests
        let mut generators = Vec::with_capacity(num_generators);
        let g = k256::base_point_g();
        for i in 0..num_generators {
            // Use a SHA-256 hash to derive a scalar for each generator point
            let scalar = Self::hash_to_scalar(format!("generator-{i}").as_bytes());
            generators.push(g.mul(&scalar).expect("Failed to create generator"));
        }

        Self { generators }
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

    /// Convert value to scalar
    fn value_to_scalar(value: &impl AsRef<[u8]>) -> k256::Scalar {
        Self::hash_to_scalar(value.as_ref())
    }

    /// Helper to convert a hash to a valid scalar, retrying if needed.
    fn hash_to_scalar(data: &[u8]) -> k256::Scalar {
        let mut hash_bytes = hash::sha256(data);
        loop {
            // Create a fixed-size array from the vector's slice to avoid moving hash_bytes.
            let mut array = [0u8; 32];
            array.copy_from_slice(&hash_bytes);
            if let Ok(scalar) = Scalar::new(array) {
                return scalar;
            }
            // Re-hash if the hash corresponds to an invalid scalar (e.g., zero)
            hash_bytes = hash::sha256(&hash_bytes);
        }
    }
}

impl CommitmentScheme for EllipticCurveCommitmentScheme {
    type Commitment = EllipticCurveCommitment;
    type Proof = EllipticCurveProof;
    type Value = Vec<u8>;

    fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
        // Start with identity point
        let mut commitment_point = Point::identity();

        // Use generators for each value
        for (i, value_opt) in values.iter().enumerate() {
            if i >= self.generators.len() {
                break; // Don't exceed available generators
            }

            if let Some(value) = value_opt {
                // Convert value to scalar
                let scalar = Self::value_to_scalar(value);

                // Add generator_i * value_scalar to the commitment point
                let term = self.generators[i].mul(&scalar).expect("Scalar mul failed");
                commitment_point = commitment_point.add(&term);
            }
        }

        // Add a random blinding factor with the last generator if we have one
        if !self.generators.is_empty() {
            let blinding = Self::random_blinding();
            let blinding_term = self.generators[self.generators.len() - 1]
                .mul(&blinding)
                .expect("Blinding failed");
            commitment_point = commitment_point.add(&blinding_term);
        }

        // Return the compressed point representation
        EllipticCurveCommitment(commitment_point.serialize_compressed())
    }

    fn create_proof(
        &self,
        selector: &Selector,
        value: &Self::Value,
    ) -> Result<Self::Proof, String> {
        // Extract position from selector
        let position = match selector {
            Selector::Position(pos) => *pos,
            // For now, we only support position-based selectors
            _ => return Err("Only position-based selectors are supported".to_string()),
        };

        if position >= self.generators.len() {
            return Err(format!("Position {position} out of bounds"));
        }

        // Create a random blinding factor
        let blinding = Self::random_blinding();

        // Return a proof with position, value, and blinding
        Ok(EllipticCurveProof {
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
        context: &ProofContext,
    ) -> bool {
        // Extract position from selector
        let position = match selector {
            Selector::Position(pos) => *pos,
            // For now, we only support position-based selectors
            _ => return false,
        };

        // Check position matches
        if position != proof.position || position >= self.generators.len() {
            return false;
        }

        // Check value matches
        if proof.value != *value {
            return false;
        }

        let strict_verification = context
            .get_data("strict_verification")
            .map(|v| !v.is_empty() && v[0] == 1)
            .unwrap_or(false);

        // Apply additional verification logic based on context
        if strict_verification {
            // In strict mode, we might perform additional checks
            // For example, ensure the commitment is not identity
            if commitment.as_ref() == [0u8; 32] {
                return false;
            }
        }

        // In a real implementation, we'd need to properly verify the commitment
        // with the blinding factor. This is a simplified implementation.

        // Convert value to scalar
        let value_scalar = Self::value_to_scalar(value);

        // Recreate the point for the value and blinding factor
        let blinding_generator = &self.generators[self.generators.len() - 1];
        let value_term = self.generators[position]
            .mul(&value_scalar)
            .expect("Scalar mul failed");
        let blinding_term = blinding_generator
            .mul(&proof.blinding)
            .expect("Blinding failed");
        let computed_point = value_term.add(&blinding_term);

        // Check if the computed commitment matches the provided one
        let computed_commitment = EllipticCurveCommitment(computed_point.serialize_compressed());

        // This is a simplified check - a real implementation would be more complex
        // for multiple values
        commitment.as_ref() == computed_commitment.as_ref()
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("elliptic_curve")
    }
}

impl HomomorphicCommitmentScheme for EllipticCurveCommitmentScheme {
    fn add(&self, a: &Self::Commitment, b: &Self::Commitment) -> Result<Self::Commitment, String> {
        // Decompress points
        let point_a = Point::deserialize_compressed(a.as_ref()).map_err(|e| e.to_string())?;
        let point_b = Point::deserialize_compressed(b.as_ref()).map_err(|e| e.to_string())?;

        // Homomorphic addition is point addition
        let result_point = point_a.add(&point_b);

        Ok(EllipticCurveCommitment(
            result_point.serialize_compressed(),
        ))
    }

    fn scalar_multiply(
        &self,
        a: &Self::Commitment,
        scalar: i32,
    ) -> Result<Self::Commitment, String> {
        if scalar <= 0 {
            return Err("Scalar must be positive".to_string());
        }

        // Decompress point
        let point = Point::deserialize_compressed(a.as_ref()).map_err(|e| e.to_string())?;

        // Convert i32 to Scalar. This is a simplified conversion for small, positive integers.
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes[..8].copy_from_slice(&(scalar as u64).to_le_bytes());
        let s = Scalar::new(scalar_bytes).map_err(|e| e.to_string())?;

        // Scalar multiplication
        let result_point = point.mul(&s).map_err(|e| e.to_string())?;

        Ok(EllipticCurveCommitment(
            result_point.serialize_compressed(),
        ))
    }

    fn supports_operation(&self, operation: HomomorphicOperation) -> bool {
        matches!(
            operation,
            HomomorphicOperation::Addition | HomomorphicOperation::ScalarMultiplication
        )
    }
}

// Add utility methods for EllipticCurveCommitment
impl EllipticCurveCommitment {
    /// Create a new EllipticCurveCommitment from a compressed point
    pub fn new(point: [u8; k256::K256_POINT_COMPRESSED_SIZE]) -> Self {
        Self(point)
    }

    /// Get the compressed point
    pub fn point(&self) -> &[u8; k256::K256_POINT_COMPRESSED_SIZE] {
        &self.0
    }

    /// Convert to a byte representation
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let array: [u8; k256::K256_POINT_COMPRESSED_SIZE] = bytes
            .try_into()
            .map_err(|_| "Invalid point length".to_string())?;
        Ok(Self(array))
    }
}

// Utility methods for EllipticCurveProof
impl EllipticCurveProof {
    /// Create a new proof
    pub fn new(blinding: Scalar, position: usize, value: Vec<u8>) -> Self {
        Self {
            blinding,
            position,
            value,
        }
    }

    /// Get the blinding factor
    pub fn blinding(&self) -> &Scalar {
        &self.blinding
    }

    /// Get the position
    pub fn position(&self) -> usize {
        self.position
    }

    /// Get the value
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Serialize the proof
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(32 + 8 + self.value.len() + 4);

        // Serialize blinding factor (32 bytes)
        result.extend_from_slice(self.blinding.serialize().as_ref());

        // Serialize position (8 bytes)
        result.extend_from_slice(&self.position.to_le_bytes());

        // Serialize value length and value
        result.extend_from_slice(&(self.value.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.value);

        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 44 {
            // 32 + 8 + 4 (minimum for blinding, position, and value length)
            return Err("Invalid proof length".to_string());
        }

        let mut pos = 0;

        // Read blinding
        let mut blinding_bytes = [0u8; 32];
        blinding_bytes.copy_from_slice(&bytes[pos..pos + 32]);
        let blinding = Scalar::new(blinding_bytes).map_err(|e| e.to_string())?;
        pos += 32;

        // Read position
        let mut position_bytes = [0u8; 8];
        position_bytes.copy_from_slice(&bytes[pos..pos + 8]);
        let position = usize::from_le_bytes(position_bytes);
        pos += 8;

        // Read value length
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
        let value_len = u32::from_le_bytes(len_bytes) as usize;
        pos += 4;

        // Read value
        if pos + value_len > bytes.len() {
            return Err("Invalid value length".to_string());
        }
        let value = bytes[pos..pos + value_len].to_vec();

        Ok(Self {
            blinding,
            position,
            value,
        })
    }
}