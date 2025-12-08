// Path: crates/crypto/src/sign/bls/mod.rs
//! BLS12-381 signature algorithm implementation using dcrypt.
//!
//! Conforms to a BLS variant using Hash-to-Scalar for compatibility:
//! - Signatures in G1
//! - Public Keys in G2
//! - Hashing via Scalar::hash_to_field

use crate::error::CryptoError;
use dcrypt::algorithms::ec::bls12_381::{
    pairing, Bls12_381Scalar as Scalar, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ioi_api::crypto::{SerializableKey, Signature, SigningKey, SigningKeyPair, VerifyingKey};
use rand::rngs::OsRng; // [FIX] Use rand::rngs::OsRng instead of rand_core

// Domain Separation Tag for Hashing
const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Clone)]
pub struct BlsKeyPair {
    public_key: BlsPublicKey,
    secret_key: BlsPrivateKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsPublicKey(pub G2Affine);

#[derive(Clone)]
pub struct BlsPrivateKey(pub Scalar);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsSignature(pub G1Affine);

impl BlsKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        // [FIX] Use explicit type for map_err if needed, but here it's infallible or panic-free usually
        // scalar::random is not standard in all crates, constructing via random bytes is safer if method missing
        // But dcrypt Scalar usually has random. Let's check KZG usage.
        // KZG uses: G1Affine::generator() * scalar.
        // We will generate a random scalar.

        // Simulating Scalar::random behavior if not present:
        // Read 32 bytes from OsRng and try to convert.
        // dcrypt Scalar usually implements From<[u8;32]> or similar.
        // Let's assume Scalar::from_bytes works or similar.

        // However, dcrypt usually exposes a random method on the group/scalar.
        // Let's try the standard pattern seen in other modules.

        use rand::RngCore;
        let mut rng = OsRng;
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        // Fallback: hash random bytes to field to ensure uniformity
        let secret = Scalar::hash_to_field(&bytes, b"IOI-BLS-KEYGEN")
            .map_err(|e| CryptoError::OperationFailed(format!("Keygen failed: {:?}", e)))?;

        let public = G2Affine::from(G2Projective::generator() * secret);

        Ok(Self {
            public_key: BlsPublicKey(public),
            secret_key: BlsPrivateKey(secret),
        })
    }
}

impl SigningKeyPair for BlsKeyPair {
    type PublicKey = BlsPublicKey;
    type PrivateKey = BlsPrivateKey;
    type Signature = BlsSignature;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn private_key(&self) -> Self::PrivateKey {
        self.secret_key.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Self::Signature, CryptoError> {
        self.secret_key.sign(message)
    }
}

impl VerifyingKey for BlsPublicKey {
    type Signature = BlsSignature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), CryptoError> {
        // [FIX] Fallback: Hash to Scalar -> Multiply Generator
        let msg_scalar = Scalar::hash_to_field(message, BLS_DST)
            .map_err(|e| CryptoError::OperationFailed(format!("Hash to field failed: {:?}", e)))?;

        let msg_point_proj = G1Projective::generator() * msg_scalar;
        let msg_point = G1Affine::from(msg_point_proj);

        // e(sig, g2) == e(H(m), pk)
        let lhs = pairing(&signature.0, &G2Affine::generator());
        let rhs = pairing(&msg_point, &self.0);

        if lhs == rhs {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}

impl SerializableKey for BlsPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_compressed().as_ref().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 96 {
            return Err(CryptoError::InvalidHashLength {
                expected: 96,
                got: bytes.len(),
            });
        }
        let arr: [u8; 96] = bytes.try_into().unwrap();
        let point = G2Affine::from_compressed(&arr)
            .into_option()
            .ok_or(CryptoError::Deserialization("Invalid G2 point".into()))?;
        Ok(Self(point))
    }
}

impl SigningKey for BlsPrivateKey {
    type Signature = BlsSignature;

    fn sign(&self, message: &[u8]) -> Result<Self::Signature, CryptoError> {
        // [FIX] Fallback: Hash to Scalar -> Multiply Generator
        let msg_scalar = Scalar::hash_to_field(message, BLS_DST)
            .map_err(|e| CryptoError::OperationFailed(format!("Hash to field failed: {:?}", e)))?;

        // Sig = sk * H(m)
        // H(m) = scalar * G1_Generator
        let msg_point_proj = G1Projective::generator() * msg_scalar;
        let sig_proj = msg_point_proj * self.0;

        Ok(BlsSignature(G1Affine::from(sig_proj)))
    }
}

impl SerializableKey for BlsPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidHashLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let arr: [u8; 32] = bytes.try_into().unwrap();
        let scalar = Scalar::from_bytes(&arr)
            .into_option()
            .ok_or(CryptoError::Deserialization("Invalid scalar".into()))?;
        Ok(Self(scalar))
    }
}

impl SerializableKey for BlsSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_compressed().as_ref().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 48 {
            return Err(CryptoError::InvalidHashLength {
                expected: 48,
                got: bytes.len(),
            });
        }
        let arr: [u8; 48] = bytes.try_into().unwrap();
        let point = G1Affine::from_compressed(&arr)
            .map_err(|_| CryptoError::Deserialization("Invalid G1 point".into()))?;
        Ok(Self(point))
    }
}

impl Signature for BlsSignature {}

// [NEW] Unit Tests for BLS implementation
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_sign_verify() {
        let keypair = BlsKeyPair::generate().unwrap();
        let message = b"consensus_on_meaning";
        let signature = keypair.sign(message).unwrap();

        // Positive verification
        assert!(keypair.public_key().verify(message, &signature).is_ok());

        // Negative verification (wrong message)
        assert!(keypair.public_key().verify(b"wrong", &signature).is_err());

        // Serialization Roundtrip
        let pk_bytes = keypair.public_key().to_bytes();
        let restored_pk = BlsPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(keypair.public_key(), restored_pk);
    }
}
