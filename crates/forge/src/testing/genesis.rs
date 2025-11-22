// Path: crates/forge/src/testing/genesis.rs
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_api::state::service_namespace_prefix;
use ioi_types::{
    app::{account_id_from_key_material, AccountId, ActiveKeyRecord, Credential, SignatureSuite},
    codec,
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX},
};
use libp2p::identity::Keypair;
use serde_json::{json, Map, Value};

/// Adds a complete identity record for a standard Ed25519 libp2p keypair to the genesis state.
pub fn add_genesis_identity(genesis_map: &mut Map<String, Value>, keypair: &Keypair) -> AccountId {
    let suite = SignatureSuite::Ed25519;
    let pk_bytes = keypair.public().encode_protobuf();
    add_genesis_identity_custom(genesis_map, suite, &pk_bytes)
}

/// Adds a complete identity record for a custom key configuration (e.g., PQC) to the genesis state.
///
/// Writes records to BOTH the global namespace (for legacy/PoA lookups) AND the service namespace
/// (for IdentityHub), ensuring compatibility across all execution paths.
pub fn add_genesis_identity_custom(
    genesis_map: &mut Map<String, Value>,
    suite: SignatureSuite,
    public_key_bytes: &[u8],
) -> AccountId {
    let account_hash =
        account_id_from_key_material(suite, public_key_bytes).expect("Failed to derive account ID");
    let account_id = AccountId(account_hash);

    let ns = service_namespace_prefix("identity_hub");

    // --- 1. Credentials (Dual Write) ---
    let cred = Credential {
        suite,
        public_key_hash: account_hash,
        activation_height: 0,
        l2_location: None,
    };
    // Create the standard array [Active, Staged]
    let creds: [Option<Credential>; 2] = [Some(cred), None];
    let creds_bytes = codec::to_bytes_canonical(&creds).expect("Failed to encode credentials");

    // Base key (global)
    let creds_key_base = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();

    // A. Namespaced (IdentityHub service)
    let creds_key_ns = [ns.as_slice(), &creds_key_base].concat();
    genesis_map.insert(
        format!("b64:{}", BASE64_STANDARD.encode(&creds_key_ns)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
    );

    // B. Global (Legacy/Fallback)
    // Some paths in `verify_transaction_signature` might still check the global key if
    // the service lookup fails or behaves unexpectedly during bootstrap.
    genesis_map.insert(
        format!("b64:{}", BASE64_STANDARD.encode(&creds_key_base)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
    );

    // --- 2. ActiveKeyRecord (Dual Write) ---
    // Used for consensus key lookups within the service and by the engine.
    let record = ActiveKeyRecord {
        suite,
        public_key_hash: account_hash,
        since_height: 0,
    };
    let record_bytes =
        codec::to_bytes_canonical(&record).expect("Failed to encode ActiveKeyRecord");
    let record_key_base = [b"identity::key_record::", account_id.as_ref()].concat();

    // A. Namespaced
    let record_key_ns = [ns.as_slice(), &record_key_base].concat();
    genesis_map.insert(
        format!("b64:{}", BASE64_STANDARD.encode(&record_key_ns)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes))),
    );

    // B. Global
    genesis_map.insert(
        format!("b64:{}", BASE64_STANDARD.encode(&record_key_base)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes))),
    );

    // --- 3. PubKey Map (Dual Write) ---
    let pubkey_key_base = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();

    // A. Namespaced
    let pubkey_key_ns = [ns.as_slice(), &pubkey_key_base].concat();
    genesis_map.insert(
        format!("b64:{}", BASE64_STANDARD.encode(&pubkey_key_ns)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(public_key_bytes))),
    );

    // B. Global
    genesis_map.insert(
        format!("b64:{}", BASE64_STANDARD.encode(&pubkey_key_base)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(public_key_bytes))),
    );

    account_id
}
