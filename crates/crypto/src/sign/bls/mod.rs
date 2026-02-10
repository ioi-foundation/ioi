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
use rand::rngs::OsRng;
use subtle::ConstantTimeEq; // Added for ct_eq

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
        use rand::RngCore;
        let mut rng = OsRng;
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        // Use hash_to_field directly to generate a uniform scalar from the random bytes
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
        // Hash to Scalar -> Multiply Generator
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
        // Use from_compressed with error handling
        let point = G2Affine::from_compressed(&arr)
            .into_option()
            .ok_or(CryptoError::Deserialization("Invalid G2 point".into()))?;
        Ok(Self(point))
    }
}

impl SigningKey for BlsPrivateKey {
    type Signature = BlsSignature;

    fn sign(&self, message: &[u8]) -> Result<Self::Signature, CryptoError> {
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
        // Use from_bytes which returns CtOption
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
        // Use from_compressed with error handling
        let point = G1Affine::from_compressed(&arr)
            .map_err(|_| CryptoError::Deserialization("Invalid G1 point".into()))?;
        Ok(Self(point))
    }
}

impl Signature for BlsSignature {}

// --- [NEW] BLS Aggregation Primitives ---

/// Aggregates multiple BLS signatures into a single signature.
/// This relies on the homomorphic property of BLS signatures:
/// S_agg = S_1 + S_2 + ... + S_n
pub fn aggregate_signatures(signatures: &[BlsSignature]) -> Result<BlsSignature, CryptoError> {
    if signatures.is_empty() {
        return Err(CryptoError::InvalidInput(
            "Cannot aggregate empty signatures".into(),
        ));
    }

    let mut agg_proj = G1Projective::from(signatures[0].0);

    for sig in &signatures[1..] {
        agg_proj = agg_proj + G1Projective::from(sig.0);
    }

    Ok(BlsSignature(G1Affine::from(agg_proj)))
}

/// Verifies an aggregated BLS signature against a list of public keys and a message.
/// e(S_agg, g2) == e(H(m), PK_agg) where PK_agg = sum(PK_i)
///
/// NOTE: This assumes all signers signed the SAME message.
/// This is vulnerable to rogue key attacks unless proof-of-possession is verified elsewhere (e.g. at registration).
/// In IOI, keys are registered on-chain, so PoP is assumed checked there.
pub fn verify_aggregate_fast(
    public_keys: &[BlsPublicKey],
    message: &[u8],
    aggregated_signature: &BlsSignature,
) -> Result<bool, CryptoError> {
    if public_keys.is_empty() {
        return Err(CryptoError::InvalidInput(
            "Cannot verify with empty public keys".into(),
        ));
    }

    // 1. Aggregate Public Keys
    let mut agg_pk_proj = G2Projective::from(public_keys[0].0);
    for pk in &public_keys[1..] {
        agg_pk_proj = agg_pk_proj + G2Projective::from(pk.0);
    }
    let agg_pk = G2Affine::from(agg_pk_proj);

    // 2. Hash Message to Curve
    let msg_scalar = Scalar::hash_to_field(message, BLS_DST)
        .map_err(|e| CryptoError::OperationFailed(format!("Hash to field failed: {:?}", e)))?;
    let msg_point_proj = G1Projective::generator() * msg_scalar;
    let msg_point = G1Affine::from(msg_point_proj);

    // 3. Pairing Check
    // e(sig, g2) == e(H(m), pk_agg)
    let lhs = pairing(&aggregated_signature.0, &G2Affine::generator());
    let rhs = pairing(&msg_point, &agg_pk);

    Ok(lhs == rhs)
}

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

    #[test]
    fn test_bls_aggregation() {
        let kp1 = BlsKeyPair::generate().unwrap();
        let kp2 = BlsKeyPair::generate().unwrap();
        let kp3 = BlsKeyPair::generate().unwrap();

        let message = b"aggregate_this";

        let s1 = kp1.sign(message).unwrap();
        let s2 = kp2.sign(message).unwrap();
        let s3 = kp3.sign(message).unwrap();

        let agg_sig = aggregate_signatures(&[s1, s2, s3]).unwrap();

        let pks = vec![kp1.public_key(), kp2.public_key(), kp3.public_key()];

        let valid = verify_aggregate_fast(&pks, message, &agg_sig).unwrap();
        assert!(valid, "Aggregate signature verification failed");
    }
}
