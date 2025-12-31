// Path: crates/ipc/src/security.rs

use anyhow::{anyhow, Result};
use dcrypt::algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt::algorithms::hash::Sha256;
use dcrypt::algorithms::kdf::Hkdf;
use dcrypt::algorithms::kdf::KeyDerivationFunction;
use dcrypt::algorithms::types::Nonce;
use dcrypt::api::traits::symmetric::{DecryptOperation, EncryptOperation, SymmetricCipher};

/// Derives a session-specific symmetric key from the master shared secret (e.g. from TLS).
pub fn derive_session_key(master_secret: &[u8], session_id: &[u8]) -> Result<[u8; 32]> {
    // According to dcrypt documentation for HKDF:
    // Hkdf::extract returns Result<Zeroizing<Vec<u8>>> which is the PRK.
    // Hkdf::expand returns Result<Zeroizing<Vec<u8>>> which is the OKM.

    // Extract
    // Note: Hkdf::extract is a static method on the struct.
    let prk = Hkdf::<Sha256>::extract(Some(session_id), master_secret)
        .map_err(|e| anyhow!("HKDF extract failed: {:?}", e))?;

    // Expand
    // Note: Hkdf::expand is a static method on the struct that takes the PRK.
    let okm_vec = Hkdf::<Sha256>::expand(&prk, Some(b"ioi-context-slice-v1"), 32)
        .map_err(|e| anyhow!("HKDF expansion failed: {:?}", e))?;

    let mut okm = [0u8; 32];
    if okm_vec.len() != 32 {
        return Err(anyhow!("Derived key length mismatch"));
    }
    okm.copy_from_slice(&okm_vec);
    Ok(okm)
}

/// Encrypts a payload binding it to specific metadata (AAD).
pub fn encrypt_slice(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::new(*nonce_bytes);

    // Using the trait methods from `EncryptOperation`:
    // fn with_nonce(self, nonce: &'a C::Nonce) -> Self;
    // fn with_aad(self, aad: &'a [u8]) -> Self;
    // fn encrypt(self, plaintext: &'a [u8]) -> Result<C::Ciphertext>;

    let ciphertext_obj = SymmetricCipher::encrypt(&cipher)
        .with_nonce(&nonce)
        .with_aad(aad)
        .encrypt(plaintext)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    Ok(ciphertext_obj.as_ref().to_vec())
}

/// Decrypts a payload validating the bound metadata (AAD).
pub fn decrypt_slice(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::new(*nonce_bytes);

    let ct_obj = dcrypt::api::types::Ciphertext::new(ciphertext.to_vec());

    // Using the trait methods from `DecryptOperation`:
    // fn with_nonce(self, nonce: &'a C::Nonce) -> Self;
    // fn with_aad(self, aad: &'a [u8]) -> Self;
    // fn decrypt(self, ciphertext: &'a C::Ciphertext) -> Result<Vec<u8>>;

    let plaintext = SymmetricCipher::decrypt(&cipher)
        .with_nonce(&nonce)
        .with_aad(aad)
        .decrypt(&ct_obj)
        .map_err(|_| anyhow!("Decryption failed (auth tag mismatch)"))?;

    Ok(plaintext)
}
