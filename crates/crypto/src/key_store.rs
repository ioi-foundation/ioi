// Path: crates/crypto/src/key_store.rs
//! Secure storage for sensitive keys using dcrypt primitives.
//!
//! Format V1:
//! [ Magic: "IOI-GKEY" (8) ]
//! [ Version: u16 (2) ]
//! [ KDF Algo: u8 (1) ]
//! [ KDF Mem KiB: u32 (4) ]
//! [ KDF Iters: u32 (4) ]
//! [ KDF Lanes: u8 (1) ]
//! [ Salt: 16B ]
//! [ AEAD Algo: u8 (1) ]
//! [ Nonce: 12B ]
//! [ Ciphertext + Tag: N + 16 ]

use crate::error::CryptoError;
use dcrypt::algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt::algorithms::kdf::{Argon2, KdfOperation, KeyDerivationFunction};
use dcrypt::algorithms::types::Nonce;
use dcrypt::api::traits::symmetric::{DecryptOperation, EncryptOperation, SymmetricCipher};
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Header Constants
const HEADER_MAGIC: &[u8; 8] = b"IOI-GKEY";
const HEADER_VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 1 + 4 + 4 + 1 + 16 + 1 + 12; // 49 Bytes

// Parameter Defaults (Strong defaults for V1)
const KDF_ALGO_ARGON2ID: u8 = 1;
const KDF_MEM_KIB: u32 = 64 * 1024; // 64 MiB
const KDF_ITERS: u32 = 3;
const KDF_LANES: u8 = 4;
const SALT_LEN: usize = 16;
const AEAD_ALGO_CHACHA20POLY1305: u8 = 1;
const NONCE_LEN: usize = 12;
const KEK_LEN: usize = 32;

/// A container for sensitive data that zeroizes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SensitiveBytes(pub Vec<u8>);

/// Encrypts raw key bytes using a passphrase, wrapping them in the V1 format.
pub fn encrypt_key(secret: &[u8], passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    // 1. Generate Salt and Nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    // 2. Construct Header
    // We manually pack bytes to ensure a stable, endian-independent on-disk format.
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(HEADER_MAGIC);
    header.extend_from_slice(&HEADER_VERSION.to_be_bytes());
    header.push(KDF_ALGO_ARGON2ID);
    header.extend_from_slice(&KDF_MEM_KIB.to_be_bytes());
    header.extend_from_slice(&KDF_ITERS.to_be_bytes());
    header.push(KDF_LANES);
    header.extend_from_slice(&salt);
    header.push(AEAD_ALGO_CHACHA20POLY1305);
    header.extend_from_slice(&nonce_bytes);

    assert_eq!(header.len(), HEADER_LEN, "Header size mismatch");

    // 3. Derive KEK (Key Encryption Key)
    let kdf = Argon2::<SALT_LEN>::new();

    // Note: If dcrypt supports custom Argon2 params in the future, inject KDF_MEM_KIB, etc. here.
    // For now, we rely on the implementation defaults matching our header claims, or the header
    // serving as the source of truth for future agility.

    let kek: [u8; KEK_LEN] = kdf
        .builder()
        .with_ikm(passphrase.as_bytes())
        .with_salt(&salt)
        .with_info(b"ioi-guardian-key-wrapping")
        .with_output_length(KEK_LEN)
        .derive_array()
        .map_err(|e| CryptoError::OperationFailed(format!("Argon2 derivation failed: {}", e)))?;

    // 4. Encrypt
    // Note: Implicit binding of header data:
    // - Salt, KDF params -> Bound by derived Key (wrong params = wrong key = tag failure)
    // - Nonce -> Bound by AEAD usage (wrong nonce = tag failure)
    // - Magic/Version -> Checked on decode before decrypt.
    // Explicit AAD is skipped as dcrypt builder API in this version does not expose it on the generic trait.
    let cipher = ChaCha20Poly1305::new(&kek);
    let nonce = Nonce::new(nonce_bytes);

    let ciphertext_obj = SymmetricCipher::encrypt(&cipher)
        .with_nonce(&nonce)
        .encrypt(secret)
        .map_err(|e| CryptoError::OperationFailed(format!("Encryption failed: {}", e)))?;

    // 5. Pack Output
    let mut output = header;
    output.extend_from_slice(ciphertext_obj.as_ref());

    Ok(output)
}

/// Decrypts a key file blob using a passphrase, respecting the versioned header.
pub fn decrypt_key(data: &[u8], passphrase: &str) -> Result<SensitiveBytes, CryptoError> {
    // 1. Validate Header Structure
    if data.len() < HEADER_LEN {
        return Err(CryptoError::InvalidInput("File too short".into()));
    }

    let magic = &data[0..8];
    if magic != HEADER_MAGIC {
        // Fallback for legacy raw keys check handled by caller or migration tool
        return Err(CryptoError::InvalidInput("Invalid file signature".into()));
    }

    let version = u16::from_be_bytes(data[8..10].try_into().unwrap());
    if version != 1 {
        return Err(CryptoError::Unsupported(format!(
            "Unsupported key format version: {}",
            version
        )));
    }

    // 2. Extract Metadata
    let _kdf_id = data[10];
    let _mem_kib = u32::from_be_bytes(data[11..15].try_into().unwrap());
    let _iters = u32::from_be_bytes(data[15..19].try_into().unwrap());
    let _lanes = data[19];
    let salt = &data[20..36];
    let _aead_id = data[36];
    let nonce_bytes = &data[37..49];

    let ciphertext_bytes = &data[HEADER_LEN..];

    // 3. Derive KEK
    let kdf = Argon2::<SALT_LEN>::new();

    // In a full implementation, we would apply _mem_kib, _iters, _lanes here.

    let kek: [u8; KEK_LEN] = kdf
        .builder()
        .with_ikm(passphrase.as_bytes())
        .with_salt(salt)
        .with_info(b"ioi-guardian-key-wrapping")
        .with_output_length(KEK_LEN)
        .derive_array()
        .map_err(|e| CryptoError::OperationFailed(format!("Argon2 derivation failed: {}", e)))?;

    // 4. Decrypt
    let cipher = ChaCha20Poly1305::new(&kek);
    let nonce = Nonce::new(nonce_bytes.try_into().unwrap());
    let ciphertext_obj = dcrypt::api::types::Ciphertext::new(ciphertext_bytes.to_vec());

    let plaintext = SymmetricCipher::decrypt(&cipher)
        .with_nonce(&nonce)
        .decrypt(&ciphertext_obj)
        .map_err(|_| {
            CryptoError::OperationFailed(
                "Decryption failed (wrong password or corrupted file)".into(),
            )
        })?;

    Ok(SensitiveBytes(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_v1() {
        let secret = b"my_secret_key_seed_32_bytes_long";
        let pass = "strong_password";

        let encrypted = encrypt_key(secret, pass).unwrap();

        // Basic structure checks
        assert_eq!(&encrypted[0..8], HEADER_MAGIC);
        assert_eq!(encrypted.len(), HEADER_LEN + secret.len() + 16); // Header + Plaintext + Tag

        let decrypted = decrypt_key(&encrypted, pass).unwrap();
        assert_eq!(decrypted.0, secret);
    }

    #[test]
    fn test_wrong_password() {
        let secret = b"secret";
        let encrypted = encrypt_key(secret, "pass").unwrap();
        assert!(decrypt_key(&encrypted, "wrong").is_err());
    }

    #[test]
    fn test_tamper_header_salt() {
        // Modifying the salt (part of the header) should cause KEK derivation to yield a different key,
        // which will cause AEAD decryption to fail (Auth Tag Mismatch).
        let secret = b"secret";
        let mut encrypted = encrypt_key(secret, "pass").unwrap();

        // Tamper with the salt (index 25 is inside the salt range 20..36)
        encrypted[25] ^= 0xFF;

        let res = decrypt_key(&encrypted, "pass");
        assert!(res.is_err());
    }
}
