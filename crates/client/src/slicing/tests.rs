use super::*;
use ioi_ipc::security::decrypt_slice;

#[test]
fn test_slice_roundtrip() {
    let packager = SlicePackager::new(SlicerConfig::default());

    let session_id = [1u8; 32];
    let policy_hash = [2u8; 32];
    let master_secret = [3u8; 32];
    let data = b"Hello world! This is a test of the context slicing system.";

    // Encrypt
    let slices = packager
        .package(session_id, policy_hash, &master_secret, data)
        .unwrap();
    assert_eq!(slices.len(), 1);

    let slice = &slices[0];

    // Decrypt
    let key = derive_session_key(&master_secret, &session_id).unwrap();
    let aad = EncryptedSlice::compute_aad(&session_id, &policy_hash, &slice.slice_id);

    let plaintext = decrypt_slice(&key, &slice.iv, &slice.ciphertext, &aad).unwrap();

    // Deserialize
    let archived = rkyv::check_archived_root::<ContextSlice>(&plaintext).unwrap();

    // Verify content
    assert_eq!(archived.chunks.len(), 1);
    // rkyv deserialized chunks access
    let chunk = &archived.chunks[0];
    // chunk is archived vector of u8, convert to slice for comparison
    assert_eq!(chunk.as_slice(), data);
}
