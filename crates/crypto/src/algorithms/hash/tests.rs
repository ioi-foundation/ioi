//! Tests for hash function implementations

use super::{GenericHasher, HashFunction, Sha256Hash, Sha512Hash};

#[test]
fn test_hash_functions() {
    let message = b"test message";

    let sha256 = Sha256Hash;
    let sha512 = Sha512Hash;

    let sha256_hash = sha256.hash(message);
    let sha512_hash = sha512.hash(message);

    assert_eq!(sha256_hash.len(), sha256.digest_size());
    assert_eq!(sha512_hash.len(), sha512.digest_size());

    assert_eq!(sha256.digest_size(), 32);
    assert_eq!(sha512.digest_size(), 64);

    // Verify deterministic behavior
    assert_eq!(sha256.hash(message), sha256.hash(message));
    assert_eq!(sha512.hash(message), sha512.hash(message));
}

#[test]
fn test_generic_hasher() {
    let message = b"test message";

    let sha256_hasher = GenericHasher::new(Sha256Hash);
    let sha512_hasher = GenericHasher::new(Sha512Hash);

    let sha256_hash = sha256_hasher.hash(message);
    let sha512_hash = sha512_hasher.hash(message);

    assert_eq!(sha256_hash.len(), sha256_hasher.digest_size());
    assert_eq!(sha512_hash.len(), sha512_hasher.digest_size());

    assert_eq!(sha256_hasher.digest_size(), 32);
    assert_eq!(sha512_hasher.digest_size(), 64);
}
