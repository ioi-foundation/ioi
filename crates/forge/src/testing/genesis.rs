// Path: crates/forge/src/testing/genesis.rs
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_api::state::service_namespace_prefix;
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, Credential, SignatureSuite, ValidatorSetsV1,
    },
    codec,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY,
        GOVERNANCE_KEY, IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY,
    },
    service_configs::GovernancePolicy,
};
use libp2p::identity::Keypair;
use parity_scale_codec::Encode;
use serde::{Serialize, Serializer};
use std::collections::BTreeMap;

/// A strongly-typed builder for constructing the genesis state.
#[derive(Default, Debug, Clone)]
pub struct GenesisBuilder {
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl GenesisBuilder {
    /// Creates a new, empty genesis builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a raw byte key and value.
    pub fn insert_raw(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> &mut Self {
        self.entries
            .insert(key.as_ref().to_vec(), value.as_ref().to_vec());
        self
    }

    /// Inserts a typed value, automatically SCALE encoding it.
    pub fn insert_typed<V: Encode>(&mut self, key: impl AsRef<[u8]>, value: &V) -> &mut Self {
        let bytes = codec::to_bytes_canonical(value).expect("Failed to encode genesis value");
        self.insert_raw(key, bytes)
    }

    // --- Domain Specific Setters ---

    pub fn set_validators(&mut self, sets: &ValidatorSetsV1) -> &mut Self {
        let blob_bytes = ioi_types::app::write_validator_sets(sets)
            .expect("Failed to encode validator set blob");
        self.insert_raw(VALIDATOR_SET_KEY, blob_bytes)
    }

    pub fn set_block_timing(
        &mut self,
        params: &BlockTimingParams,
        runtime: &BlockTimingRuntime,
    ) -> &mut Self {
        self.insert_typed(BLOCK_TIMING_PARAMS_KEY, params);
        self.insert_typed(BLOCK_TIMING_RUNTIME_KEY, runtime);
        self
    }

    pub fn set_governance_policy(&mut self, policy: &GovernancePolicy) -> &mut Self {
        self.insert_typed(GOVERNANCE_KEY, policy)
    }

    // --- Identity Helpers ---

    pub fn add_identity(&mut self, keypair: &Keypair) -> AccountId {
        let suite = SignatureSuite::Ed25519;
        let pk_bytes = keypair.public().encode_protobuf();
        self.add_identity_custom(suite, &pk_bytes)
    }

    pub fn add_identity_custom(
        &mut self,
        suite: SignatureSuite,
        public_key_bytes: &[u8],
    ) -> AccountId {
        let account_hash = account_id_from_key_material(suite, public_key_bytes)
            .expect("Failed to derive account ID");
        let account_id = AccountId(account_hash);
        let ns = service_namespace_prefix("identity_hub");

        // 1. Credentials -> Namespaced (read by IdentityHub via NamespacedStateAccess)
        let cred = Credential {
            suite,
            public_key_hash: account_hash,
            activation_height: 0,
            l2_location: None,
            // [NEW] Explicitly set weight. Defaults to 1.
            // This prepares the state for future weighted voting/multisig features.
            weight: 1,
        };
        let creds: [Option<Credential>; 2] = [Some(cred), None];
        let creds_key = [
            ns.as_slice(),
            IDENTITY_CREDENTIALS_PREFIX,
            account_id.as_ref(),
        ]
        .concat();
        self.insert_typed(creds_key, &creds);

        // 2. ActiveKeyRecord -> Namespaced (internal bookkeeping)
        let record = ActiveKeyRecord {
            suite,
            public_key_hash: account_hash,
            since_height: 0,
        };
        let record_key = [
            ns.as_slice(),
            b"identity::key_record::",
            account_id.as_ref(),
        ]
        .concat();
        self.insert_typed(record_key, &record);

        // 3. PubKey Map -> GLOBAL (read by UnifiedTransactionModel via raw StateAccess)
        // FIX: Removed `ns` prefix here.
        let pubkey_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
        self.insert_raw(pubkey_key, public_key_bytes);

        account_id
    }
}

impl Serialize for GenesisBuilder {
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

// --- Standalone Helpers for Backward Compatibility ---

pub fn add_genesis_identity(builder: &mut GenesisBuilder, keypair: &Keypair) -> AccountId {
    builder.add_identity(keypair)
}

pub fn add_genesis_identity_custom(
    builder: &mut GenesisBuilder,
    suite: SignatureSuite,
    public_key_bytes: &[u8],
) -> AccountId {
    builder.add_identity_custom(suite, public_key_bytes)
}
