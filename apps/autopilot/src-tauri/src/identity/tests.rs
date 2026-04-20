use super::*;

#[test]
fn ensure_identity_keypair_at_path_creates_and_reloads_key() {
    let temp_root =
        std::env::temp_dir().join(format!("autopilot-identity-test-{}", uuid::Uuid::new_v4()));
    let key_path = temp_root.join("identity.key");

    let created =
        ensure_identity_keypair_at_path(&key_path).expect("missing identity key should be created");
    assert!(
        key_path.exists(),
        "identity key file should exist after ensure"
    );

    let loaded =
        load_identity_keypair_from_file(&key_path).expect("created identity key should load");

    assert_eq!(
        created.public().encode_protobuf(),
        loaded.public().encode_protobuf(),
        "created and reloaded public keys should match"
    );

    let _ = std::fs::remove_dir_all(temp_root);
}
