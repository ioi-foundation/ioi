//! Deterministic workload admission for AFT consequence manifests.
//!
//! This service does not execute an effect and does not produce finality. It
//! validates and roots at most one exact manifest per block so the runtime
//! finality coordinator can bind those same bytes into its Agentgres commit.

use async_trait::async_trait;
use ioi_api::{
    services::{BlockchainService, UpgradableService},
    state::StateAccess,
    transaction::context::TxContext,
};
use ioi_types::{
    app::{
        EffectManifestV1, AFT_EFFECT_REGISTRY_SERVICE_ID, REGISTER_AFT_EFFECT_MANIFEST_V1_METHOD,
    },
    error::{TransactionError, UpgradeError},
    service_configs::Capabilities,
};
use std::any::Any;

const LAST_HEIGHT_KEY: &[u8] = b"aft_effect_registry/v1/last_height";
const MANIFEST_KEY_PREFIX: &[u8] = b"aft_effect_registry/v1/manifest/";
const REGISTRY_PREFIX: &[u8] = b"aft_effect_registry/";
const SCHEMA_KEY: &[u8] = b"aft_effect_registry/schema";
const SCHEMA_V2: &[u8] = b"v2-unique-effect-identity";
const IDENTITY_KEY_PREFIX: &[u8] = b"aft_effect_registry/v2/identity/";

#[derive(Debug, Default, Clone)]
pub struct AftEffectRegistryService;

fn manifest_key(manifest: &EffectManifestV1) -> Result<Vec<u8>, TransactionError> {
    let root = manifest
        .commitment()
        .map_err(|error| TransactionError::Invalid(error.to_string()))?;
    let mut key = Vec::with_capacity(MANIFEST_KEY_PREFIX.len() + root.len());
    key.extend_from_slice(MANIFEST_KEY_PREFIX);
    key.extend_from_slice(&root);
    Ok(key)
}

fn identity_key(effect_id: &str) -> Vec<u8> {
    // The manifest's token validation bounds this exact key to 512 suffix
    // bytes. It is an opaque state key, not a filesystem path or prefix lookup.
    [IDENTITY_KEY_PREFIX, effect_id.as_bytes()].concat()
}

fn require_registry_schema(state: &dyn StateAccess) -> Result<(), TransactionError> {
    match state.get(SCHEMA_KEY).map_err(TransactionError::State)? {
        Some(schema) if schema == SCHEMA_V2 => Ok(()),
        Some(_) => Err(TransactionError::Invalid(
            "AFT effect registry schema is unsupported".into(),
        )),
        None => {
            // Only an empty namespace can initialize the new identity index.
            // Never infer completeness from an absent index in older state.
            let mut entries = state
                .prefix_scan(REGISTRY_PREFIX)
                .map_err(TransactionError::State)?;
            if let Some(entry) = entries.next() {
                entry.map_err(TransactionError::State)?;
                return Err(TransactionError::Invalid(
                    "AFT effect registry requires an explicit identity-index migration".into(),
                ));
            }
            Ok(())
        }
    }
}

#[async_trait]
impl BlockchainService for AftEffectRegistryService {
    fn id(&self) -> &str {
        AFT_EFFECT_REGISTRY_SERVICE_ID
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &str {
        "v2"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        if method != REGISTER_AFT_EFFECT_MANIFEST_V1_METHOD {
            return Err(TransactionError::Unsupported(format!(
                "AftEffectRegistry does not support method '{method}'"
            )));
        }
        let manifest: EffectManifestV1 = serde_json::from_slice(params)
            .map_err(|error| TransactionError::Invalid(error.to_string()))?;
        let canonical = serde_jcs::to_vec(&manifest)
            .map_err(|error| TransactionError::Invalid(error.to_string()))?;
        if canonical != params {
            return Err(TransactionError::Invalid(
                "AFT effect manifest is not canonical JCS".into(),
            ));
        }
        manifest
            .validate()
            .map_err(|error| TransactionError::Invalid(error.to_string()))?;


        let identity = identity_key(&manifest.effect_id);
        if state
            .get(&identity)
            .map_err(TransactionError::State)?
            .is_some()
        {
            return Err(TransactionError::Invalid(
                "AFT effect identity was already admitted".into(),
            ));
        }

        if state
            .get(LAST_HEIGHT_KEY)
            .map_err(TransactionError::State)?
            .is_some_and(|bytes| bytes == ctx.block_height.to_le_bytes())
        {
            return Err(TransactionError::Invalid(
                "only one AFT effect manifest may be admitted per block".into(),
            ));
        }
        let key = manifest_key(&manifest)?;
        if state.get(&key).map_err(TransactionError::State)?.is_some() {
            return Err(TransactionError::Invalid(
                "AFT effect manifest was already admitted".into(),
            ));
        }
        // These writes belong to the workload transaction's joint overlay.
        // A failed transaction must not commit a partial identity index.
        state
            .batch_set(&[
                (key.clone(), params.to_vec()),
                (identity, key),
                (
                    LAST_HEIGHT_KEY.to_vec(),
                    ctx.block_height.to_le_bytes().to_vec(),
                ),
                (SCHEMA_KEY.to_vec(), SCHEMA_V2.to_vec()),
            ])
            .map_err(TransactionError::State)
    }
}

#[async_trait]
impl UpgradableService for AftEffectRegistryService {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }

    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::{services::access::ServiceDirectory, state::StateScanIter};
    use ioi_types::{
        app::{
            AccountId, ChainId, EffectAuthorizationModeV1, EffectFenceV1, EffectManifestVersionV1,
            EffectResourceKeyV1, ExternalResourceContractV1, ExternalResourceProfileV1,
            ExternalizationModeV1, GuaranteeRequirementsV1, ReconciliationPolicyV1,
        },
        error::StateError,
    };
    use std::{collections::BTreeMap, sync::Arc};

    #[derive(Default)]
    struct MockState(BTreeMap<Vec<u8>, Vec<u8>>);

    impl StateAccess for MockState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.0.get(key).cloned())
        }

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.0.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.0.remove(key);
            Ok(())
        }

        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            keys.iter().map(|key| self.get(key)).collect()
        }

        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            for key in deletes {
                self.delete(key)?;
            }
            self.batch_set(inserts)
        }

        fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
            let rows = self
                .0
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
                .collect::<Vec<_>>();
            Ok(Box::new(rows.into_iter()))
        }
    }

    fn manifest(effect_id: &str, slot: u64) -> EffectManifestV1 {
        let mut manifest = EffectManifestV1 {
            schema_version: EffectManifestVersionV1::V1,
            effect_id: effect_id.into(),
            resource_id: "resource://test/pq-register".into(),
            conflict_domain_id: "domain://test/effect".into(),
            conflict_slot: slot,
            authorization_mode: EffectAuthorizationModeV1::OnlineQueryUnanimityV0,
            online_authorization_policy_root: Some([12; 32]),
            online_authorization_predecessor: Some([77; 32]),
            online_authorization_authority_mode: Some(ioi_types::app::QuvAuthorityModeV0::Unowned),
            read_set: vec![EffectResourceKeyV1 {
                key: "account/source".into(),
                predecessor: Some([1; 32]),
            }],
            write_set: vec![EffectResourceKeyV1 {
                key: format!("transfer/{slot}"),
                predecessor: None,
            }],
            idempotency_key: "pending".into(),
            request_root: [2; 32],
            predecessor_root: [3; 32],
            intent_root: [4; 32],
            expected_outcome_root: [5; 32],
            resource_profile: ExternalResourceProfileV1 {
                adapter_id: "test-pq-register".into(),
                adapter_version: "v1".into(),
                resource_profile_id: "resource-profile://test/pq-register/v1".into(),
                contract: ExternalResourceContractV1::AtomicPutIfAbsent,
                externalization_pq: true,
                endpoint_pq_key_hash: Some([9; 32]),
            },
            required_guarantees: GuaranteeRequirementsV1 {
                minimum_externalization: Some(ExternalizationModeV1::IdempotencyRegister),
                require_at_most_once: true,
                require_externalization_pq: true,
                ..Default::default()
            },
            fence: EffectFenceV1::ProtocolHeight {
                configuration_hash: [6; 32],
                minimum_height: 1,
                maximum_height: 20,
            },
            reconciliation: ReconciliationPolicyV1::LookupByIdempotencyKey {
                maximum_observations: 3,
            },
            irreversible: true,
        };
        manifest.idempotency_key = manifest.query_unanimity_idempotency_key().unwrap();
        manifest.validate().unwrap();
        manifest
    }

    async fn register(
        service: &AftEffectRegistryService,
        state: &mut MockState,
        manifest: &EffectManifestV1,
        height: u64,
    ) -> Result<(), TransactionError> {
        let services = ServiceDirectory::default();
        let mut context = TxContext {
            block_height: height,
            block_timestamp: 0,
            chain_id: ChainId(0),
            signer_account_id: AccountId([1; 32]),
            services: &services,
            simulation: false,
            is_internal: false,
        };
        service
            .handle_service_call(
                state,
                REGISTER_AFT_EFFECT_MANIFEST_V1_METHOD,
                &serde_jcs::to_vec(manifest).unwrap(),
                &mut context,
            )
            .await
    }

    #[tokio::test]
    async fn roots_one_exact_manifest_per_block_and_refuses_duplicates() {
        let service = AftEffectRegistryService;
        let mut state = MockState::default();
        let first = manifest("effect-1", 1);
        register(&service, &mut state, &first, 7).await.unwrap();
        assert_eq!(
            state.get(&manifest_key(&first).unwrap()).unwrap(),
            Some(serde_jcs::to_vec(&first).unwrap())
        );

        let second = manifest("effect-2", 2);
        assert!(register(&service, &mut state, &second, 7).await.is_err());
        register(&service, &mut state, &second, 8).await.unwrap();
        assert!(register(&service, &mut state, &second, 9).await.is_err());
    }

    #[tokio::test]
    async fn identity_substitution_refuses_without_invalidating_prior_admission() {
        let service = AftEffectRegistryService;
        let mut state = MockState::default();
        let first = manifest("stable-effect", 1);
        register(&service, &mut state, &first, 7).await.unwrap();
        let original = state.0.clone();
        let mut substituted = first.clone();
        substituted.request_root = [99; 32];
        assert_ne!(
            first.commitment().unwrap(),
            substituted.commitment().unwrap()
        );
        assert!(matches!(
            register(&service, &mut state, &substituted, 8).await,
            Err(TransactionError::Invalid(message)) if message == "AFT effect identity was already admitted"
        ));
        assert_eq!(state.0, original);
        assert_eq!(
            state.get(&identity_key(&first.effect_id)).unwrap(),
            Some(manifest_key(&first).unwrap())
        );
        // A refused substitution consumes neither the original identity nor
        // this block's sole admission opportunity for an unrelated effect.
        let second = manifest("unrelated-effect", 2);
        register(&service, &mut state, &second, 8).await.unwrap();
        let mut restored = MockState(state.0.clone());
        let before = restored.0.clone();
        assert!(matches!(
            register(&service, &mut restored, &substituted, 9).await,
            Err(TransactionError::Invalid(message)) if message == "AFT effect identity was already admitted"
        ));
        assert_eq!(restored.0, before);
        assert_eq!(
            restored.get(&manifest_key(&first).unwrap()).unwrap(),
            Some(serde_jcs::to_vec(&first).unwrap())
        );
    }

    #[tokio::test]
    async fn unindexed_or_unknown_registry_schema_refuses_without_reinitializing() {
        let service = AftEffectRegistryService;
        let first = manifest("older-effect", 1);
        let incoming = manifest("new-effect", 2);
        for (key, value) in [
            (LAST_HEIGHT_KEY.to_vec(), 7_u64.to_le_bytes().to_vec()),
            (
                manifest_key(&first).unwrap(),
                serde_jcs::to_vec(&first).unwrap(),
            ),
            (SCHEMA_KEY.to_vec(), b"unknown-schema".to_vec()),
            (
                identity_key(&first.effect_id),
                manifest_key(&first).unwrap(),
            ),
        ] {
            let mut state = MockState(BTreeMap::from([(key, value)]));
            let before = state.0.clone();
            assert!(matches!(
                register(&service, &mut state, &incoming, 8).await,
                Err(TransactionError::Invalid(_))
            ));
            assert_eq!(state.0, before);
        }
    }

    #[tokio::test]
    async fn refuses_noncanonical_or_unknown_method_input() {
        let service = AftEffectRegistryService;
        let mut state = MockState::default();
        let manifest = manifest("effect-1", 1);
        let services = ServiceDirectory::default();
        let mut context = TxContext {
            block_height: 7,
            block_timestamp: 0,
            chain_id: ChainId(0),
            signer_account_id: AccountId([1; 32]),
            services: &services,
            simulation: false,
            is_internal: false,
        };
        let pretty = serde_json::to_vec_pretty(&manifest).unwrap();
        assert!(service
            .handle_service_call(
                &mut state,
                REGISTER_AFT_EFFECT_MANIFEST_V1_METHOD,
                &pretty,
                &mut context,
            )
            .await
            .is_err());
        assert!(service
            .handle_service_call(&mut state, "unknown@v1", &[], &mut context)
            .await
            .is_err());
    }
}
