use super::*;
use std::collections::BTreeSet;

#[derive(Encode, Decode, Debug, PartialEq, Eq)]
struct TestStruct {
    id: u32,
    name: String,
    tags: Vec<u8>,
}

#[test]
fn test_canonical_codec_roundtrip() {
    // Test with a simple struct
    let original_struct = TestStruct {
        id: 42,
        name: "test-data".to_string(),
        tags: vec![1, 2, 3],
    };

    let encoded = to_bytes_canonical(&original_struct).unwrap();
    assert!(!encoded.is_empty());

    let decoded = from_bytes_canonical::<TestStruct>(&encoded).unwrap();
    assert_eq!(original_struct, decoded);

    // Test with a more complex structure (BTreeSet)
    let mut original_set = BTreeSet::new();
    original_set.insert([1u8; 32]);
    original_set.insert([2u8; 32]);
    original_set.insert([3u8; 32]);

    let encoded_set = to_bytes_canonical(&original_set).unwrap();
    let decoded_set = from_bytes_canonical::<BTreeSet<[u8; 32]>>(&encoded_set).unwrap();

    assert_eq!(original_set, decoded_set);
}

#[test]
fn test_canonical_decode_failure() {
    let original_struct = TestStruct {
        id: 99,
        name: "another-test".to_string(),
        tags: vec![10, 20, 30, 40, 50],
    };

    let mut encoded = to_bytes_canonical(&original_struct).unwrap();
    // Truncate the encoded data to make it invalid
    encoded.pop();
    encoded.pop();

    let result = from_bytes_canonical::<TestStruct>(&encoded);
    assert!(result.is_err());
    let error_msg = result.unwrap_err();

    // Assert that the error is wrapped correctly by our function.
    // We relax the check on the inner error string as it depends on `parity-scale-codec` implementation details.
    assert!(error_msg.contains("canonical decode failed"));
}
