// Path: crates/forge/src/testing/genesis.rs
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_api::state::service_namespace_prefix;
use ioi_types::{
    app::{account_id_from_key_material, AccountId, ActiveKeyRecord, Credential, SignatureSuite},
    codec,
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX},
};
use libp2p::identity::Keypair;
use serde::{Serialize, Serializer};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// A robust builder for the genesis state that handles binary-to-string encoding automatically.
///
/// This struct prevents errors related to manual `b64:` prefixing and ensures
/// consistent serialization of keys and values.
#[derive(Default, Debug, Clone)]
pub struct GenesisState {
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl GenesisState {
    /// Creates a new, empty genesis state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a key-value pair into the genesis state.
    ///
    /// Both key and value are raw bytes. They will be automatically encoded
    /// to base64 with the required prefix during serialization.
    pub fn insert(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> &mut Self {
        self.entries
            .insert(key.as_ref().to_vec(), value.as_ref().to_vec());
        self
    }

    /// Helper to add an identity to this state (wraps `add_genesis_identity`).
    pub fn add_identity(&mut self, keypair: &Keypair) -> AccountId {
        let suite = SignatureSuite::Ed25519;
        let pk_bytes = keypair.public().encode_protobuf();
        self.add_identity_custom(suite, &pk_bytes)
    }

    /// Helper to add a custom identity to this state (wraps `add_genesis_identity_custom`).
    pub fn add_identity_custom(
        &mut self,
        suite: SignatureSuite,
        public_key_bytes: &[u8],
    ) -> AccountId {
        // We adapt the logic from add_genesis_identity_custom to write to self.entries
        let account_hash = account_id_from_key_material(suite, public_key_bytes)
            .expect("Failed to derive account ID");
        let account_id = AccountId(account_hash);
        let ns = service_namespace_prefix("identity_hub");

        // 1. Credentials
        let cred = Credential {
            suite,
            public_key_hash: account_hash,
            activation_height: 0,
            l2_location: None,
        };
        let creds: [Option<Credential>; 2] = [Some(cred), None];
        let creds_bytes = codec::to_bytes_canonical(&creds).expect("Failed to encode credentials");
        let creds_key_base = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
        let creds_key_ns = [ns.as_slice(), &creds_key_base].concat();

        self.insert(&creds_key_ns, &creds_bytes);
        self.insert(&creds_key_base, &creds_bytes);

        // 2. ActiveKeyRecord
        let record = ActiveKeyRecord {
            suite,
            public_key_hash: account_hash,
            since_height: 0,
        };
        let record_bytes =
            codec::to_bytes_canonical(&record).expect("Failed to encode ActiveKeyRecord");
        let record_key_base = [b"identity::key_record::", account_id.as_ref()].concat();
        let record_key_ns = [ns.as_slice(), &record_key_base].concat();

        self.insert(&record_key_ns, &record_bytes);
        self.insert(&record_key_base, &record_bytes);

        // 3. PubKey Map
        let pubkey_key_base = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
        let pubkey_key_ns = [ns.as_slice(), &pubkey_key_base].concat();

        self.insert(&pubkey_key_ns, public_key_bytes);
        self.insert(&pubkey_key_base, public_key_bytes);

        account_id
    }
}

impl Serialize for GenesisState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.entries.len()))?;
        for (k, v) in &self.entries {
            let key_str = format!("b64:{}", BASE64_STANDARD.encode(k));
            let val_str = format!("b64:{}", BASE64_STANDARD.encode(v));
            map.serialize_entry(&key_str, &val_str)?;
        }
        map.end()
    }
}

/// Internal helper to safely insert bytes into a raw JSON map using the required format.
/// This preserves backward compatibility for existing tests using `Map<String, Value>`.
pub fn safe_insert_json(genesis_map: &mut Map<String, Value>, key: &[u8], value: &[u8]) {
    let k = format!("b64:{}", BASE64_STANDARD.encode(key));
    let v = format!("b64:{}", BASE64_STANDARD.encode(value));
    genesis_map.insert(k, json!(v));
}

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
    safe_insert_json(genesis_map, &creds_key_ns, &creds_bytes);

    // B. Global (Legacy/Fallback)
    safe_insert_json(genesis_map, &creds_key_base, &creds_bytes);

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
    safe_insert_json(genesis_map, &record_key_ns, &record_bytes);

    // B. Global
    safe_insert_json(genesis_map, &record_key_base, &record_bytes);

    // --- 3. PubKey Map (Dual Write) ---
    let pubkey_key_base = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();

    // A. Namespaced
    let pubkey_key_ns = [ns.as_slice(), &pubkey_key_base].concat();
    safe_insert_json(genesis_map, &pubkey_key_ns, public_key_bytes);

    // B. Global
    safe_insert_json(genesis_map, &pubkey_key_base, public_key_bytes);

    account_id
}
