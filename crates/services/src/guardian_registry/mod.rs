use async_trait::async_trait;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{
    guardian_registry_committee_key, guardian_registry_log_key,
    guardian_registry_witness_fault_key, guardian_registry_witness_key,
    guardian_registry_witness_seed_key, guardian_registry_witness_set_key,
    GuardianCommitteeManifest, GuardianLogCheckpoint, GuardianMeasurementProfile,
    GuardianTransparencyLogDescriptor, GuardianWitnessCommitteeManifest, GuardianWitnessEpochSeed,
    GuardianWitnessFaultEvidence, GuardianWitnessSet, ProofOfDivergence,
    GUARDIAN_REGISTRY_CHECKPOINT_PREFIX, GUARDIAN_REGISTRY_EQUIVOCATION_PREFIX,
    GUARDIAN_REGISTRY_MEASUREMENT_PREFIX,
};
use ioi_types::codec;
use ioi_types::config::GuardianRegistryParams;
use ioi_types::error::{StateError, TransactionError, UpgradeError};
use ioi_types::service_configs::Capabilities;
use std::any::Any;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct GuardianRegistry {
    pub config: GuardianRegistryParams,
}

impl GuardianRegistry {
    pub fn new(config: GuardianRegistryParams) -> Self {
        Self { config }
    }

    pub fn manifest_hash(
        manifest: &GuardianCommitteeManifest,
    ) -> Result<[u8; 32], TransactionError> {
        let bytes = codec::to_bytes_canonical(manifest).map_err(TransactionError::Serialization)?;
        sha256(&bytes)
            .map_err(|e| TransactionError::Invalid(e.to_string()))
            .and_then(|digest| {
                digest
                    .try_into()
                    .map_err(|_| TransactionError::Invalid("invalid manifest hash length".into()))
            })
    }

    pub fn load_manifest_by_hash(
        state: &dyn StateAccess,
        manifest_hash: &[u8; 32],
    ) -> Result<Option<GuardianCommitteeManifest>, StateError> {
        let key = guardian_registry_committee_key(manifest_hash);
        match state.get(&key)? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_witness_manifest_by_hash(
        state: &dyn StateAccess,
        manifest_hash: &[u8; 32],
    ) -> Result<Option<GuardianWitnessCommitteeManifest>, StateError> {
        let key = guardian_registry_witness_key(manifest_hash);
        match state.get(&key)? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn profile_allows_measurement(
        state: &dyn StateAccess,
        measurement_root: &[u8; 32],
    ) -> Result<bool, StateError> {
        let Some(profile_bytes) =
            state.get(&[GUARDIAN_REGISTRY_MEASUREMENT_PREFIX, b"default"].concat())?
        else {
            return Ok(false);
        };
        let profile: GuardianMeasurementProfile = codec::from_bytes_canonical(&profile_bytes)
            .map_err(|e| StateError::InvalidValue(e.to_string()))?;
        Ok(profile
            .allowed_measurement_roots
            .iter()
            .any(|root| root == measurement_root))
    }

    fn validate_diversity(
        labels: impl Iterator<Item = Option<String>>,
        minimum: u16,
        field: &str,
    ) -> Result<(), TransactionError> {
        if minimum == 0 {
            return Ok(());
        }

        let distinct = labels
            .flatten()
            .filter(|value| !value.trim().is_empty())
            .collect::<BTreeSet<_>>();

        if distinct.len() < usize::from(minimum) {
            return Err(TransactionError::Invalid(format!(
                "guardian registry policy requires at least {} distinct {} labels, got {}",
                minimum,
                field,
                distinct.len()
            )));
        }
        Ok(())
    }

    fn validate_committee_manifest(
        &self,
        manifest: &GuardianCommitteeManifest,
    ) -> Result<(), TransactionError> {
        let member_count = manifest.members.len();
        if member_count < usize::from(self.config.minimum_committee_size) {
            return Err(TransactionError::Invalid(format!(
                "guardian committee size {} is below minimum {}",
                member_count, self.config.minimum_committee_size
            )));
        }
        if member_count == 0 {
            return Err(TransactionError::Invalid(
                "guardian committee must contain at least one member".into(),
            ));
        }
        if manifest.threshold == 0 || usize::from(manifest.threshold) > member_count {
            return Err(TransactionError::Invalid(format!(
                "guardian committee threshold {} is invalid for size {}",
                manifest.threshold, member_count
            )));
        }
        if usize::from(manifest.threshold) <= member_count / 2 {
            return Err(TransactionError::Invalid(
                "guardian committee threshold must be a strict majority".into(),
            ));
        }
        if self.config.require_even_committee_sizes && member_count % 2 != 0 {
            return Err(TransactionError::Invalid(
                "production guardian committees must be even-sized in registry policy".into(),
            ));
        }
        if self.config.require_checkpoint_anchoring
            && manifest.transparency_log_id.trim().is_empty()
        {
            return Err(TransactionError::Invalid(
                "guardian committee must declare a transparency log id".into(),
            ));
        }

        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.provider.clone()),
            self.config.minimum_provider_diversity,
            "provider",
        )?;
        Self::validate_diversity(
            manifest.members.iter().map(|member| member.region.clone()),
            self.config.minimum_region_diversity,
            "region",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.host_class.clone()),
            self.config.minimum_host_class_diversity,
            "host class",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.key_authority_kind.map(|kind| format!("{kind:?}"))),
            self.config.minimum_backend_diversity,
            "key authority",
        )?;

        Ok(())
    }

    fn validate_witness_manifest(
        &self,
        manifest: &GuardianWitnessCommitteeManifest,
    ) -> Result<(), TransactionError> {
        let member_count = manifest.members.len();
        if member_count < usize::from(self.config.minimum_witness_committee_size) {
            return Err(TransactionError::Invalid(format!(
                "witness committee size {} is below minimum {}",
                member_count, self.config.minimum_witness_committee_size
            )));
        }
        if manifest.threshold == 0 || usize::from(manifest.threshold) > member_count {
            return Err(TransactionError::Invalid(format!(
                "witness committee threshold {} is invalid for size {}",
                manifest.threshold, member_count
            )));
        }
        if usize::from(manifest.threshold) <= member_count / 2 {
            return Err(TransactionError::Invalid(
                "witness committee threshold must be a strict majority".into(),
            ));
        }
        if self.config.require_even_committee_sizes && member_count % 2 != 0 {
            return Err(TransactionError::Invalid(
                "production witness committees must be even-sized in registry policy".into(),
            ));
        }
        if self.config.require_checkpoint_anchoring
            && manifest.transparency_log_id.trim().is_empty()
        {
            return Err(TransactionError::Invalid(
                "witness committee must declare a transparency log id".into(),
            ));
        }

        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.provider.clone()),
            self.config.minimum_provider_diversity,
            "provider",
        )?;
        Self::validate_diversity(
            manifest.members.iter().map(|member| member.region.clone()),
            self.config.minimum_region_diversity,
            "region",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.host_class.clone()),
            self.config.minimum_host_class_diversity,
            "host class",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.key_authority_kind.map(|kind| format!("{kind:?}"))),
            self.config.minimum_backend_diversity,
            "key authority",
        )?;

        Ok(())
    }

    fn validate_log_descriptor(
        &self,
        descriptor: &GuardianTransparencyLogDescriptor,
    ) -> Result<(), TransactionError> {
        if descriptor.log_id.trim().is_empty() {
            return Err(TransactionError::Invalid(
                "guardian transparency log id must not be empty".into(),
            ));
        }
        if descriptor.public_key.is_empty() {
            return Err(TransactionError::Invalid(
                "guardian transparency log public key must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl BlockchainService for GuardianRegistry {
    fn id(&self) -> &str {
        "guardian_registry"
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &str {
        "guardian_registry/v1"
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
        _ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "register_guardian_transparency_log@v1" => {
                let descriptor: GuardianTransparencyLogDescriptor =
                    codec::from_bytes_canonical(params)?;
                self.validate_log_descriptor(&descriptor)?;
                state.insert(
                    &guardian_registry_log_key(&descriptor.log_id),
                    &codec::to_bytes_canonical(&descriptor)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "register_guardian_committee@v1" => {
                let manifest: GuardianCommitteeManifest = codec::from_bytes_canonical(params)?;
                self.validate_committee_manifest(&manifest)?;
                let manifest_hash = Self::manifest_hash(&manifest)?;
                state.insert(
                    &guardian_registry_committee_key(&manifest_hash),
                    &codec::to_bytes_canonical(&manifest)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_measurement_profile@v1" => {
                let profile: GuardianMeasurementProfile = codec::from_bytes_canonical(params)?;
                state.insert(
                    &[
                        GUARDIAN_REGISTRY_MEASUREMENT_PREFIX,
                        profile.profile_id.as_bytes(),
                    ]
                    .concat(),
                    &codec::to_bytes_canonical(&profile)
                        .map_err(TransactionError::Serialization)?,
                )?;
                if profile.profile_id == "default" {
                    state.insert(
                        &[GUARDIAN_REGISTRY_MEASUREMENT_PREFIX, b"default"].concat(),
                        &codec::to_bytes_canonical(&profile)
                            .map_err(TransactionError::Serialization)?,
                    )?;
                }
                Ok(())
            }
            "register_guardian_witness_committee@v1" => {
                let manifest: GuardianWitnessCommitteeManifest =
                    codec::from_bytes_canonical(params)?;
                self.validate_witness_manifest(&manifest)?;
                let manifest_hash = sha256(
                    &codec::to_bytes_canonical(&manifest)
                        .map_err(TransactionError::Serialization)?,
                )
                .map_err(|e| TransactionError::Invalid(e.to_string()))
                .and_then(|digest| {
                    digest.try_into().map_err(|_| {
                        TransactionError::Invalid("invalid witness manifest hash length".into())
                    })
                })?;
                state.insert(
                    &guardian_registry_witness_key(&manifest_hash),
                    &codec::to_bytes_canonical(&manifest)
                        .map_err(TransactionError::Serialization)?,
                )?;
                let active_key = guardian_registry_witness_set_key(manifest.epoch);
                let mut active_set = match state.get(&active_key)? {
                    Some(bytes) => codec::from_bytes_canonical::<GuardianWitnessSet>(&bytes)?,
                    None => GuardianWitnessSet {
                        epoch: manifest.epoch,
                        manifest_hashes: Vec::new(),
                        checkpoint_interval_blocks: 1,
                    },
                };
                if !active_set.manifest_hashes.contains(&manifest_hash) {
                    active_set.manifest_hashes.push(manifest_hash);
                    active_set.manifest_hashes.sort_unstable();
                }
                state.insert(
                    &active_key,
                    &codec::to_bytes_canonical(&active_set)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_witness_epoch_seed@v1" => {
                let seed: GuardianWitnessEpochSeed = codec::from_bytes_canonical(params)?;
                state.insert(
                    &guardian_registry_witness_seed_key(seed.epoch),
                    &codec::to_bytes_canonical(&seed).map_err(TransactionError::Serialization)?,
                )?;
                let active_key = guardian_registry_witness_set_key(seed.epoch);
                if state.get(&active_key)?.is_none() {
                    state.insert(
                        &active_key,
                        &codec::to_bytes_canonical(&GuardianWitnessSet {
                            epoch: seed.epoch,
                            manifest_hashes: Vec::new(),
                            checkpoint_interval_blocks: seed.checkpoint_interval_blocks,
                        })
                        .map_err(TransactionError::Serialization)?,
                    )?;
                }
                Ok(())
            }
            "anchor_guardian_checkpoint@v1" => {
                let checkpoint: GuardianLogCheckpoint = codec::from_bytes_canonical(params)?;
                state.insert(
                    &[
                        GUARDIAN_REGISTRY_CHECKPOINT_PREFIX,
                        checkpoint.log_id.as_bytes(),
                    ]
                    .concat(),
                    &codec::to_bytes_canonical(&checkpoint)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "report_guardian_equivocation@v1" => {
                let proof: ProofOfDivergence = codec::from_bytes_canonical(params)?;
                state.insert(
                    &[
                        GUARDIAN_REGISTRY_EQUIVOCATION_PREFIX,
                        proof.offender.as_ref(),
                    ]
                    .concat(),
                    &codec::to_bytes_canonical(&proof).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "report_guardian_witness_fault@v1" => {
                let evidence: GuardianWitnessFaultEvidence = codec::from_bytes_canonical(params)?;
                state.insert(
                    &guardian_registry_witness_fault_key(&evidence.evidence_id),
                    &codec::to_bytes_canonical(&evidence)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            _ => Err(TransactionError::Unsupported(format!(
                "GuardianRegistry does not support method '{}'",
                method
            ))),
        }
    }
}

#[async_trait]
impl UpgradableService for GuardianRegistry {
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
    use ioi_api::services::access::ServiceDirectory;
    use ioi_api::state::StateScanIter;
    use ioi_api::transaction::context::TxContext;
    use ioi_types::app::{
        guardian_registry_log_key, AccountId, ChainId, GuardianCommitteeMember,
        GuardianTransparencyLogDescriptor, GuardianWitnessEpochSeed, SignatureSuite,
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[derive(Default)]
    struct MockState {
        data: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl StateAccess for MockState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.data.remove(key);
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
            for (key, value) in inserts {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
            let rows: Vec<_> = self
                .data
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
                .collect();
            Ok(Box::new(rows.into_iter()))
        }
    }

    fn with_ctx<F>(f: F)
    where
        F: FnOnce(&mut TxContext<'_>),
    {
        let services = ServiceDirectory::new(Vec::new());
        let mut ctx = TxContext {
            block_height: 42,
            block_timestamp: 1_750_000_000_000_000_000,
            chain_id: ChainId(1),
            signer_account_id: AccountId([7u8; 32]),
            services: &services,
            simulation: false,
            is_internal: false,
        };
        f(&mut ctx);
    }

    fn run_async<F: std::future::Future<Output = T>, T>(future: F) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    fn production_registry() -> GuardianRegistry {
        GuardianRegistry::new(GuardianRegistryParams {
            enabled: true,
            ..Default::default()
        })
    }

    fn member(
        member_id: &str,
        provider: &str,
        region: &str,
        host_class: &str,
        key_authority_kind: ioi_types::app::KeyAuthorityKind,
    ) -> GuardianCommitteeMember {
        GuardianCommitteeMember {
            member_id: member_id.to_string(),
            signature_suite: SignatureSuite::BLS12_381,
            public_key: vec![1, 2, 3, member_id.len() as u8],
            endpoint: Some(format!("https://{}.example", member_id)),
            provider: Some(provider.to_string()),
            region: Some(region.to_string()),
            host_class: Some(host_class.to_string()),
            key_authority_kind: Some(key_authority_kind),
        }
    }

    #[test]
    fn rejects_unsafe_odd_sized_guardian_committee_under_production_policy() {
        let registry = production_registry();
        let manifest = GuardianCommitteeManifest {
            validator_account_id: AccountId([1u8; 32]),
            epoch: 7,
            threshold: 3,
            members: vec![
                member(
                    "a",
                    "aws",
                    "us-east-1",
                    "x86",
                    ioi_types::app::KeyAuthorityKind::CloudKms,
                ),
                member(
                    "b",
                    "gcp",
                    "us-west-1",
                    "arm",
                    ioi_types::app::KeyAuthorityKind::Tpm2,
                ),
                member(
                    "c",
                    "azure",
                    "eu-west-1",
                    "metal",
                    ioi_types::app::KeyAuthorityKind::Pkcs11,
                ),
                member(
                    "d",
                    "aws",
                    "eu-central-1",
                    "arm64",
                    ioi_types::app::KeyAuthorityKind::CloudKms,
                ),
                member(
                    "e",
                    "gcp",
                    "ap-southeast-1",
                    "x86_64",
                    ioi_types::app::KeyAuthorityKind::Tpm2,
                ),
            ],
            measurement_profile_root: [1u8; 32],
            policy_hash: [2u8; 32],
            transparency_log_id: "guardian-log".into(),
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            let err = run_async(registry.handle_service_call(
                &mut state,
                "register_guardian_committee@v1",
                &codec::to_bytes_canonical(&manifest).unwrap(),
                ctx,
            ))
            .unwrap_err();
            assert!(err.to_string().contains("even-sized"));
        });
    }

    #[test]
    fn registers_guardian_transparency_log_descriptor() {
        let registry = GuardianRegistry::new(Default::default());
        let descriptor = GuardianTransparencyLogDescriptor {
            log_id: "guardian-log".into(),
            signature_suite: SignatureSuite::ED25519,
            public_key: vec![1, 2, 3],
        };
        let mut state = MockState::default();

        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "register_guardian_transparency_log@v1",
                &codec::to_bytes_canonical(&descriptor).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let stored = state
            .get(&guardian_registry_log_key(&descriptor.log_id))
            .unwrap()
            .expect("log descriptor stored");
        let restored: GuardianTransparencyLogDescriptor =
            codec::from_bytes_canonical(&stored).unwrap();
        assert_eq!(restored, descriptor);
    }

    #[test]
    fn registering_witness_committee_updates_active_set_and_seed() {
        let registry = GuardianRegistry::new(GuardianRegistryParams {
            enabled: true,
            minimum_committee_size: 1,
            minimum_witness_committee_size: 1,
            minimum_provider_diversity: 1,
            minimum_region_diversity: 1,
            minimum_host_class_diversity: 1,
            minimum_backend_diversity: 1,
            require_even_committee_sizes: false,
            require_checkpoint_anchoring: true,
            max_checkpoint_staleness_ms: 120_000,
            max_committee_outage_members: 0,
        });
        let manifest = GuardianWitnessCommitteeManifest {
            committee_id: "witness-a".into(),
            epoch: 11,
            threshold: 1,
            members: vec![member(
                "w1",
                "aws",
                "us-east-1",
                "arm",
                ioi_types::app::KeyAuthorityKind::CloudKms,
            )],
            policy_hash: [3u8; 32],
            transparency_log_id: "witness-log".into(),
        };
        let seed = GuardianWitnessEpochSeed {
            epoch: 11,
            seed: [9u8; 32],
            checkpoint_interval_blocks: 3,
            max_reassignment_depth: 2,
        };

        let mut state = MockState::default();
        with_ctx(|ctx| {
            run_async(registry.handle_service_call(
                &mut state,
                "register_guardian_witness_committee@v1",
                &codec::to_bytes_canonical(&manifest).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_witness_epoch_seed@v1",
                &codec::to_bytes_canonical(&seed).unwrap(),
                ctx,
            ))
            .unwrap();
        });

        let active_set_bytes = state
            .get(&guardian_registry_witness_set_key(11))
            .expect("active set lookup")
            .expect("active set stored");
        let active_set: GuardianWitnessSet =
            codec::from_bytes_canonical(&active_set_bytes).unwrap();
        assert_eq!(active_set.epoch, 11);
        assert_eq!(active_set.manifest_hashes.len(), 1);
        assert_eq!(active_set.checkpoint_interval_blocks, 3);

        let seed_bytes = state
            .get(&guardian_registry_witness_seed_key(11))
            .expect("seed lookup")
            .expect("seed stored");
        let stored_seed: GuardianWitnessEpochSeed =
            codec::from_bytes_canonical(&seed_bytes).unwrap();
        assert_eq!(stored_seed.seed, [9u8; 32]);
        assert_eq!(stored_seed.max_reassignment_depth, 2);
    }
}
