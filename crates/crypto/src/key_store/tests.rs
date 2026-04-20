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
