//! Secure storage for sensitive keys using dcrypt primitives.
//!
//! Format: MAGIC_HEADER (10) || SALT (16) || NONCE (12) || CIPHERTEXT (N + 16 tag)

use crate::error::CryptoError;
use dcrypt::algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt::algorithms::kdf::{Argon2, KdfOperation, KeyDerivationFunction};
use dcrypt::algorithms::types::Nonce;
use dcrypt::api::traits::symmetric::{DecryptOperation, EncryptOperation, SymmetricCipher};
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAGIC_HEADER: &[u8] = b"IOI_ENC_V1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEK_LEN: usize = 32; // Key Encryption Key length

/// A container for sensitive data that zeroizes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SensitiveBytes(pub Vec<u8>);

/// Encrypts raw key bytes using a passphrase.
pub fn encrypt_key(secret: &[u8], passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    // 1. Generate Salt and Nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    // 2. Derive KEK using dcrypt Argon2 (Default is Argon2id)
    // We use the const generic <16> for the salt length as per dcrypt API patterns
    let kdf = Argon2::<SALT_LEN>::new();
    
    let kek: [u8; KEK_LEN] = kdf.builder()
        .with_ikm(passphrase.as_bytes())
        .with_salt(&salt)
        .with_info(b"ioi-guardian-key-wrapping")
        .with_output_length(KEK_LEN)
        .derive_array()
        .map_err(|e| CryptoError::OperationFailed(format!("Argon2 derivation failed: {}", e)))?;

    // 3. Encrypt using dcrypt ChaCha20Poly1305
    let cipher = ChaCha20Poly1305::new(&kek);
    let nonce = Nonce::new(nonce_bytes);

    // SymmetricCipher trait usage from dcrypt
    let ciphertext_obj = SymmetricCipher::encrypt(&cipher)
        .with_nonce(&nonce)
        .encrypt(secret)
        .map_err(|e| CryptoError::OperationFailed(format!("Encryption failed: {}", e)))?;

    // 4. Pack Output
    let mut output = Vec::new();
    output.extend_from_slice(MAGIC_HEADER);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(ciphertext_obj.as_ref());

    Ok(output)
}

/// Decrypts a key file blob using a passphrase.
pub fn decrypt_key(data: &[u8], passphrase: &str) -> Result<SensitiveBytes, CryptoError> {
    let mut cursor = 0;

    // 1. Validate Header
    if data.len() < MAGIC_HEADER.len() || &data[..MAGIC_HEADER.len()] != MAGIC_HEADER {
        return Err(CryptoError::InvalidInput("Invalid keystore format or not encrypted".into()));
    }
    cursor += MAGIC_HEADER.len();

    // 2. Extract Metadata
    if data.len() < cursor + SALT_LEN + NONCE_LEN {
        return Err(CryptoError::InvalidInput("File too short".into()));
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&data[cursor..cursor + SALT_LEN]);
    cursor += SALT_LEN;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&data[cursor..cursor + NONCE_LEN]);
    cursor += NONCE_LEN;

    let ciphertext_bytes = &data[cursor..];

    // 3. Derive KEK
    let kdf = Argon2::<SALT_LEN>::new();
    let kek: [u8; KEK_LEN] = kdf.builder()
        .with_ikm(passphrase.as_bytes())
        .with_salt(&salt)
        .with_info(b"ioi-guardian-key-wrapping")
        .with_output_length(KEK_LEN)
        .derive_array()
        .map_err(|e| CryptoError::OperationFailed(format!("Argon2 derivation failed: {}", e)))?;

    // 4. Decrypt
    let cipher = ChaCha20Poly1305::new(&kek);
    let nonce = Nonce::new(nonce_bytes);
    
    // dcrypt expects the ciphertext object wrapper, or bytes if implemented
    // We construct a Ciphertext object from raw bytes (assuming dcrypt exposes a way or From impl)
    // If dcrypt::api::types::Ciphertext doesn't have a public constructor for Vec<u8>, 
    // we rely on the implementation details matching the previous snapshot.
    let ciphertext_obj = dcrypt::api::types::Ciphertext::new(ciphertext_bytes.to_vec());

    let plaintext = SymmetricCipher::decrypt(&cipher)
        .with_nonce(&nonce)
        .decrypt(&ciphertext_obj)
        .map_err(|_| CryptoError::OperationFailed("Decryption failed (wrong password?)".into()))?;

    Ok(SensitiveBytes(plaintext))
}