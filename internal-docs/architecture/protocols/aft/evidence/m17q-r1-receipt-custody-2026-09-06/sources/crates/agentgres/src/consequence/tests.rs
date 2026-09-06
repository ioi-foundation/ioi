use super::*;
use ioi_crypto::{security::SecurityLevel, sign::dilithium::MldsaScheme};
use ioi_types::app::consensus::{
    guarantee_vector_of, CertificateOnlyGuaranteeVerifierV1, CertificateProfile,
    ExternalizationModeV1, GuaranteeRank, GuaranteeRequirementsV1,
};
use ioi_types::app::{EffectManifestVersionV1, EffectResourceKeyV1, ExternalResourceContractV1};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[derive(Clone, Copy)]
enum InvocationMode {
    Normal,
    AmbiguousAfterMutation,
    AmbiguousWithoutMutation,
}

struct AtomicRegister {
    profile: ExternalResourceProfileV1,
    records: BTreeMap<String, ExternalResourceRecordV1>,
    invocations: u32,
    mutations: u32,
    lookups: u32,
    mode: InvocationMode,
    ambiguous_lookup: bool,
    forced_conflict: Option<ExternalResourceRecordV1>,
}

struct TestOnlineAuthorization(OnlineEffectAuthorizationBindingV1, Instant);

impl ImmediateOnlineEffectAuthorizationV1 for TestOnlineAuthorization {
    fn consume(self) -> Result<ConsumedOnlineEffectAuthorizationV1, ConsequenceError> {
        let binding = self.0;
        let protocol_evidence = b"test-only live QUV observation".to_vec();
        Ok(ConsumedOnlineEffectAuthorizationV1 {
            audit: OnlineEffectAuthorizationAuditV1 {
                profile: "aft_quv_v0".into(),
                portable_final_receipt: false,
                binding: OnlineEffectAuthorizationAuditBindingV1::from(&binding),
                verifier_nonce: [29; 32],
                protocol_evidence_hash: online_authorization_audit_evidence_hash(
                    &protocol_evidence,
                )?,
                protocol_evidence,
            },
            binding,
            expires_at: self.1,
        })
    }
}

impl AtomicRegister {
    fn new(profile: ExternalResourceProfileV1) -> Self {
        Self {
            profile,
            records: BTreeMap::new(),
            invocations: 0,
            mutations: 0,
            lookups: 0,
            mode: InvocationMode::Normal,
            ambiguous_lookup: false,
            forced_conflict: None,
        }
    }

    fn expected_record(manifest: &EffectManifestV1) -> ExternalResourceRecordV1 {
        ExternalResourceRecordV1 {
            resource_id: manifest.resource_id.clone(),
            idempotency_key: manifest.idempotency_key.clone(),
            request_root: manifest.request_root,
            predecessor_root: manifest.predecessor_root,
            outcome_root: manifest.expected_outcome_root,
            mutation_sequence: 1,
            evidence: None,
            evidence_hash: None,
        }
    }
}

impl ExternalResourceV1 for AtomicRegister {
    fn profile(&self) -> &ExternalResourceProfileV1 {
        &self.profile
    }

    fn invoke_atomic(
        &mut self,
        manifest: &EffectManifestV1,
    ) -> Result<AtomicMutationResultV1, ResourceInvocationErrorV1> {
        self.invocations += 1;
        if let Some(conflict) = self.forced_conflict.clone() {
            return Err(ResourceInvocationErrorV1::Conflict(conflict));
        }
        if matches!(self.mode, InvocationMode::AmbiguousWithoutMutation) {
            return Err(ResourceInvocationErrorV1::Ambiguous);
        }
        if let Some(existing) = self.records.get(&manifest.idempotency_key) {
            return Ok(AtomicMutationResultV1::Existing(existing.clone()));
        }
        let record = Self::expected_record(manifest);
        self.records
            .insert(manifest.idempotency_key.clone(), record.clone());
        self.mutations += 1;
        if matches!(self.mode, InvocationMode::AmbiguousAfterMutation) {
            Err(ResourceInvocationErrorV1::Ambiguous)
        } else {
            Ok(AtomicMutationResultV1::Inserted(record))
        }
    }

    fn lookup(
        &mut self,
        _resource_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<ExternalResourceRecordV1>, ResourceLookupErrorV1> {
        self.lookups += 1;
        if let Some(conflict) = self.forced_conflict.clone() {
            return Err(ResourceLookupErrorV1::Conflict(conflict));
        }
        if self.ambiguous_lookup {
            return Err(ResourceLookupErrorV1::Ambiguous);
        }
        Ok(self.records.get(idempotency_key).cloned())
    }

    fn verify_record_evidence(&self, record: &ExternalResourceRecordV1) -> bool {
        record.evidence.as_deref() == Some(b"signed-resource-contradiction".as_slice())
            && record.evidence_hash == record.evidence.as_deref().map(evidence_hash)
    }
}

fn profile(contract: ExternalResourceContractV1) -> ExternalResourceProfileV1 {
    ExternalResourceProfileV1 {
        adapter_id: "adapter://atomic-test".into(),
        adapter_version: "v1".into(),
        resource_profile_id: "resource-profile://atomic-test-v1".into(),
        contract,
        externalization_pq: true,
        endpoint_pq_key_hash: Some([9; 32]),
    }
}

fn manifest(effect_id: impl Into<String>, profile: ExternalResourceProfileV1) -> EffectManifestV1 {
    let effect_id = effect_id.into();
    EffectManifestV1 {
        schema_version: EffectManifestVersionV1::V1,
        resource_id: "resource://test/register".into(),
        conflict_domain_id: "domain://test/register".into(),
        conflict_slot: 1,
        authorization_mode: ioi_types::app::EffectAuthorizationModeV1::Portable,
        online_authorization_policy_root: None,
        online_authorization_predecessor: None,
        online_authorization_authority_mode: None,
        read_set: vec![EffectResourceKeyV1 {
            key: "account/source".into(),
            predecessor: Some([1; 32]),
        }],
        write_set: vec![EffectResourceKeyV1 {
            key: "transfer/42".into(),
            predecessor: None,
        }],
        idempotency_key: format!("idem-{effect_id}"),
        request_root: [2; 32],
        predecessor_root: [3; 32],
        intent_root: [4; 32],
        expected_outcome_root: [5; 32],
        resource_profile: profile,
        required_guarantees: GuaranteeRequirementsV1 {
            configuration_hash: Some([6; 32]),
            minimum_externalization: Some(ExternalizationModeV1::IdempotencyRegister),
            require_at_most_once: true,
            ..Default::default()
        },
        fence: EffectFenceV1::ProtocolHeight {
            configuration_hash: [6; 32],
            minimum_height: 10,
            maximum_height: 10,
        },
        reconciliation: ReconciliationPolicyV1::LookupByIdempotencyKey {
            maximum_observations: 3,
        },
        irreversible: true,
        effect_id,
    }
}

fn verified_for(profile: &ExternalResourceProfileV1) -> VerifiedGuaranteeV1 {
    let mut vector = guarantee_vector_of(CertificateProfile::HashPcdReference);
    vector.externalization = profile.advertised_externalization().unwrap();
    vector.crypto.externalization_pq = profile.externalization_pq;
    vector.safety.configuration_hash = Some([6; 32]);
    CertificateOnlyGuaranteeVerifierV1::verify(&[vector]).unwrap()
}

fn authorize(store: &mut ConsequenceStore, manifest: EffectManifestV1) -> ConsequenceReceiptV1 {
    let verified = verified_for(&manifest.resource_profile);
    let authorization = accepted_for(&manifest, &verified);
    store
        .authorize(manifest, &verified, &authorization, 10)
        .unwrap()
}

fn accepted_for(
    manifest: &EffectManifestV1,
    verified: &VerifiedGuaranteeV1,
) -> AcceptedEffectAuthorizationV1 {
    AcceptedEffectAuthorizationV1 {
        effect_id: manifest.effect_id.clone(),
        manifest_root: manifest.commitment().unwrap(),
        achieved_guarantee_root: verified.achieved().commitment().unwrap(),
        authority_epoch: 0,
        authority_snapshot_root: [0; 32],
        authorization_receipt_root: [42; 32],
    }
}

#[test]
fn receipt_hash_view_preserves_canonical_bytes_and_optional_fields() {
    let temp = TempDir::new().unwrap();
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let baseline = authorize(&mut store, manifest("hash-view", profile));
    for attempts in [0, 1, u32::MAX] {
        for with_audit in [false, true] {
            let mut receipt = baseline.clone();
            receipt.reconciliation_attempts = attempts;
            if with_audit {
                receipt.online_authorization_audit = Some(
                    TestOnlineAuthorization(
                        OnlineEffectAuthorizationBindingV1 {
                            mode: EffectAuthorizationModeV1::OnlineQueryUnanimityV0,
                            payload_hash: [1; 32],
                            configuration_root: [2; 32],
                            conflict_domain_hash: [3; 32],
                            conflict_slot: u64::MAX,
                            policy_root: [4; 32],
                            predecessor: [5; 32],
                            authority_mode: ioi_types::app::QuvAuthorityModeV0::Unowned,
                        },
                        Instant::now(),
                    )
                    .consume()
                    .unwrap()
                    .audit,
                );
                receipt
                    .online_authorization_audit
                    .as_mut()
                    .unwrap()
                    .protocol_evidence = (0..=255_u8).cycle().take(16 * 1024).collect();
            }
            // These are serializer-shape probes, not valid authorization claims.
            let before = receipt.clone();
            let mut legacy = receipt.clone();
            legacy.receipt_root = [0; 32];
            let bytes = serde_jcs::to_vec(&legacy).unwrap();
            assert_eq!(
                receipt_root(&receipt).unwrap(),
                hash_parts(RECEIPT_DOMAIN, &[&bytes])
            );
            assert_ne!(
                receipt_root(&receipt).unwrap(),
                hash_parts(b"wrong-domain", &[&bytes])
            );
            assert_eq!(receipt, before);
        }
    }
}

#[test]
fn clear_execution_and_duplicate_delivery_mutate_the_resource_once() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let manifest = manifest("clear", profile.clone());
    let mut resource = AtomicRegister::new(profile);
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    let authorized = authorize(&mut store, manifest);
    assert_eq!(authorized.state.phase(), ConsequencePhaseV1::Authorized);

    let executed = store.execute("clear", &mut resource).unwrap();
    assert_eq!(executed.state.phase(), ConsequencePhaseV1::Executed);
    assert_eq!(resource.mutations, 1);
    assert!(matches!(
        store.execute("clear", &mut resource),
        Err(ConsequenceError::WrongState(ConsequencePhaseV1::Executed))
    ));
    let reconciled = store.reconcile("clear", &mut resource).unwrap();
    assert_eq!(reconciled.state.phase(), ConsequencePhaseV1::Reconciled);
    assert_eq!(resource.invocations, 1);
    assert_eq!(resource.mutations, 1);
    assert_eq!(store.reconcile("clear", &mut resource).unwrap(), reconciled);
}

#[test]
fn query_unanimity_effect_requires_matching_immediate_online_authorization() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let mut manifest = manifest("quv", profile.clone());
    manifest.authorization_mode = ioi_types::app::EffectAuthorizationModeV1::OnlineQueryUnanimityV0;
    manifest.online_authorization_policy_root = Some([19; 32]);
    manifest.online_authorization_predecessor = Some([77; 32]);
    manifest.online_authorization_authority_mode =
        Some(ioi_types::app::QuvAuthorityModeV0::Unowned);
    manifest.fence = EffectFenceV1::ProtocolHeight {
        configuration_hash: [88; 32],
        minimum_height: 10,
        maximum_height: 10,
    };
    manifest.idempotency_key = manifest.query_unanimity_idempotency_key().unwrap();
    let manifest_root = manifest.commitment().unwrap();
    let configuration_root = match manifest.fence {
        EffectFenceV1::ProtocolHeight {
            configuration_hash, ..
        } => configuration_hash,
        _ => unreachable!(),
    };
    let conflict_domain_hash = manifest.conflict_domain_commitment().unwrap();
    let conflict_slot = manifest.conflict_slot;
    let predecessor = manifest.online_authorization_predecessor.unwrap();
    let resource_predecessor = manifest.predecessor_root;
    assert_ne!(predecessor, resource_predecessor);
    let mut resource = AtomicRegister::new(profile);
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    authorize(&mut store, manifest);

    assert!(matches!(
        store.execute("quv", &mut resource),
        Err(ConsequenceError::OnlineAuthorizationRequired)
    ));
    let binding = OnlineEffectAuthorizationBindingV1 {
        mode: ioi_types::app::EffectAuthorizationModeV1::OnlineQueryUnanimityV0,
        payload_hash: manifest_root,
        configuration_root,
        conflict_domain_hash,
        conflict_slot,
        policy_root: [19; 32],
        predecessor,
        authority_mode: ioi_types::app::QuvAuthorityModeV0::Unowned,
    };
    assert_eq!(
        store.online_authorization_requirement("quv").unwrap(),
        binding
    );
    for wrong_authority in [false, true] {
        let mut mismatch = store.online_authorization_requirement("quv").unwrap();
        if wrong_authority {
            mismatch.authority_mode = ioi_types::app::QuvAuthorityModeV0::Owned;
        } else {
            mismatch.predecessor = resource_predecessor;
        }
        assert!(matches!(
            store.execute_with_online_authorization(
                "quv",
                &mut resource,
                TestOnlineAuthorization(mismatch, Instant::now() + Duration::from_secs(10)),
                10,
            ),
            Err(ConsequenceError::InvalidOnlineAuthorization)
        ));
        assert_eq!(resource.invocations, 0);
        assert_eq!(resource.mutations, 0);
        assert_eq!(
            store.load("quv").unwrap().state.phase(),
            ConsequencePhaseV1::Authorized
        );
    }
    let executed = store
        .execute_with_online_authorization(
            "quv",
            &mut resource,
            TestOnlineAuthorization(binding, Instant::now() + Duration::from_secs(1)),
            10,
        )
        .unwrap();
    assert_eq!(executed.state.phase(), ConsequencePhaseV1::Executed);
    let audit = executed.online_authorization_audit.unwrap();
    assert!(!audit.portable_final_receipt);
    assert_eq!(audit.profile, "aft_quv_v0");
    assert_eq!(resource.mutations, 1);
    assert!(matches!(
        store.online_authorization_requirement("quv"),
        Err(ConsequenceError::WrongState(ConsequencePhaseV1::Executed))
    ));
}

#[test]
fn nonexecutable_online_retry_preserves_audit_without_consuming_continuation() {
    struct MustNotConsume;
    impl ImmediateOnlineEffectAuthorizationV1 for MustNotConsume {
        fn consume(self) -> Result<ConsumedOnlineEffectAuthorizationV1, ConsequenceError> {
            panic!("non-executable retry consumed its continuation")
        }
    }

    fn check(store: &mut ConsequenceStore, resource: &mut AtomicRegister) {
        let before = store.load("quv-nonexecutable-retry").unwrap();
        let path = store.receipt_path("quv-nonexecutable-retry");
        let bytes = std::fs::read(&path).unwrap();
        let calls = resource.invocations;
        let mutations = resource.mutations;
        assert!(matches!(
            store.execute_with_online_authorization(
                "quv-nonexecutable-retry", resource, MustNotConsume, 10,
            ),
            Err(ConsequenceError::WrongState(phase)) if phase == before.state.phase()
        ));
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        assert_eq!(store.load("quv-nonexecutable-retry").unwrap(), before);
        assert_eq!(resource.invocations, calls);
        assert_eq!(resource.mutations, mutations);
    }

    for crash_before_call in [false, true] {
        let temp = TempDir::new().unwrap();
        let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
        let mut manifest = manifest("quv-nonexecutable-retry", profile.clone());
        manifest.authorization_mode = EffectAuthorizationModeV1::OnlineQueryUnanimityV0;
        manifest.online_authorization_policy_root = Some([19; 32]);
        manifest.online_authorization_predecessor = Some([77; 32]);
        manifest.online_authorization_authority_mode =
            Some(ioi_types::app::QuvAuthorityModeV0::Unowned);
        manifest.fence = EffectFenceV1::ProtocolHeight {
            configuration_hash: [88; 32],
            minimum_height: 10,
            maximum_height: 10,
        };
        manifest.idempotency_key = manifest.query_unanimity_idempotency_key().unwrap();
        let mut resource = AtomicRegister::new(profile);
        let mut store = ConsequenceStore::open(temp.path()).unwrap();
        authorize(&mut store, manifest);
        let binding = store
            .online_authorization_requirement("quv-nonexecutable-retry")
            .unwrap();
        if crash_before_call {
            store.arm_crash(ConsequenceCrashPoint::AfterInFlight);
        }
        let result = store.execute_with_online_authorization(
            "quv-nonexecutable-retry",
            &mut resource,
            TestOnlineAuthorization(binding, Instant::now() + Duration::from_secs(10)),
            10,
        );
        if crash_before_call {
            assert!(matches!(
                result,
                Err(ConsequenceError::InjectedCrash(
                    ConsequenceCrashPoint::AfterInFlight
                ))
            ));
            assert_eq!(
                store.load("quv-nonexecutable-retry").unwrap().state.phase(),
                ConsequencePhaseV1::InFlight
            );
        } else {
            assert_eq!(result.unwrap().state.phase(), ConsequencePhaseV1::Executed);
        }
        check(&mut store, &mut resource);
        drop(store);
        let mut store = ConsequenceStore::open(temp.path()).unwrap();
        check(&mut store, &mut resource);
        if crash_before_call {
            assert_eq!(
                store
                    .recover("quv-nonexecutable-retry")
                    .unwrap()
                    .state
                    .phase(),
                ConsequencePhaseV1::Unknown
            );
            check(&mut store, &mut resource);
        }
        assert_eq!(
            store
                .reconcile("quv-nonexecutable-retry", &mut resource)
                .unwrap()
                .state
                .phase(),
            ConsequencePhaseV1::Reconciled
        );
        check(&mut store, &mut resource);
        assert_eq!(resource.invocations, u32::from(!crash_before_call));
        assert_eq!(resource.mutations, u32::from(!crash_before_call));
    }
}

#[test]
fn online_readmission_returns_terminal_results_or_reconciles_without_reinvocation() {
    for scenario in 0..3 {
        let temp = TempDir::new().unwrap();
        let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
        let mut manifest = manifest("quv-result-retry", profile.clone());
        manifest.authorization_mode = EffectAuthorizationModeV1::OnlineQueryUnanimityV0;
        manifest.online_authorization_policy_root = Some([19; 32]);
        manifest.online_authorization_predecessor = Some([77; 32]);
        manifest.online_authorization_authority_mode =
            Some(ioi_types::app::QuvAuthorityModeV0::Unowned);
        manifest.fence = EffectFenceV1::ProtocolHeight {
            configuration_hash: [88; 32],
            minimum_height: 10,
            maximum_height: 10,
        };
        manifest.idempotency_key = manifest.query_unanimity_idempotency_key().unwrap();
        let mut resource = AtomicRegister::new(profile);
        let mut store = ConsequenceStore::open(temp.path()).unwrap();
        authorize(&mut store, manifest.clone());
        assert!(store
            .online_retry_result("quv-result-retry", &mut resource)
            .unwrap()
            .is_none());
        let binding = store.online_effect_binding("quv-result-retry").unwrap();
        if scenario == 1 {
            resource.mode = InvocationMode::AmbiguousAfterMutation;
        }
        if scenario == 2 {
            store.arm_crash(ConsequenceCrashPoint::AfterInFlight);
        }
        let executed = store.execute_with_online_authorization(
            "quv-result-retry",
            &mut resource,
            TestOnlineAuthorization(
                store.online_effect_binding("quv-result-retry").unwrap(),
                Instant::now() + Duration::from_secs(10),
            ),
            10,
        );
        match scenario {
            0 => {
                assert!(executed.is_ok());
            }
            1 => assert!(matches!(executed, Err(ConsequenceError::Ambiguous))),
            _ => assert!(matches!(
                executed,
                Err(ConsequenceError::InjectedCrash(
                    ConsequenceCrashPoint::AfterInFlight
                ))
            )),
        }
        drop(store);
        let mut store = ConsequenceStore::open(temp.path()).unwrap();
        let before = store.load("quv-result-retry").unwrap();
        let bytes = std::fs::read(store.receipt_path("quv-result-retry")).unwrap();
        let verified = verified_for(&manifest.resource_profile);
        let accepted = accepted_for(&manifest, &verified);
        let mut changed = accepted.clone();
        changed.authorization_receipt_root = [43; 32];
        assert!(matches!(
            store.authorize(manifest.clone(), &verified, &changed, 10),
            Err(ConsequenceError::ReplayConflict)
        ));
        assert!(matches!(
            store.authorize(manifest.clone(), &verified, &accepted, 11),
            Err(ConsequenceError::FenceExpired)
        ));
        assert_eq!(
            std::fs::read(store.receipt_path("quv-result-retry")).unwrap(),
            bytes
        );
        assert_eq!(
            store
                .authorize(manifest.clone(), &verified, &accepted, 10)
                .unwrap(),
            before
        );
        assert_eq!(
            store.online_effect_binding("quv-result-retry").unwrap(),
            binding
        );
        assert!(matches!(
            store.prepare_online_effect(manifest.clone(), &verified, &changed, 11),
            Err(ConsequenceError::ReplayConflict)
        ));
        assert_eq!(
            store
                .prepare_online_effect(manifest.clone(), &verified, &accepted, 11)
                .unwrap(),
            before
        );
        let calls = resource.invocations;
        let mutations = resource.mutations;
        let result = store
            .online_retry_result("quv-result-retry", &mut resource)
            .unwrap()
            .unwrap();
        if scenario == 0 {
            assert_eq!(result, before);
            assert_eq!(
                std::fs::read(store.receipt_path("quv-result-retry")).unwrap(),
                bytes
            );
        } else {
            assert_eq!(result.state.phase(), ConsequencePhaseV1::Reconciled);
        }
        assert_eq!(resource.lookups, 1);
        assert_eq!(resource.invocations, calls);
        assert_eq!(resource.mutations, mutations);
        assert_eq!(
            store
                .online_retry_result("quv-result-retry", &mut resource)
                .unwrap(),
            Some(result)
        );
        assert_eq!(resource.lookups, 2);
        assert_eq!(resource.invocations, calls);
        let terminal_bytes = std::fs::read(store.receipt_path("quv-result-retry")).unwrap();
        resource.ambiguous_lookup = true;
        assert!(matches!(
            store.online_retry_result("quv-result-retry", &mut resource),
            Err(ConsequenceError::Ambiguous)
        ));
        resource.ambiguous_lookup = false;
        let saved = resource.records.clone();
        if scenario == 2 {
            resource.records.insert(
                manifest.idempotency_key.clone(),
                AtomicRegister::expected_record(&manifest),
            );
        } else {
            resource.records.clear();
        }
        assert!(matches!(
            store.online_retry_result("quv-result-retry", &mut resource),
            Err(ConsequenceError::ReplayConflict)
        ));
        resource.records = saved;
        assert_eq!(
            std::fs::read(store.receipt_path("quv-result-retry")).unwrap(),
            terminal_bytes
        );
        assert_eq!(resource.invocations, calls);
        assert_eq!(resource.mutations, mutations);
    }
}

#[test]
fn expired_result_preparation_preserves_authority_identity_and_execution_fences() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let mut manifest = manifest("epoch-result", profile.clone());
    manifest.authorization_mode = EffectAuthorizationModeV1::OnlineQueryUnanimityV0;
    manifest.online_authorization_policy_root = Some([19; 32]);
    manifest.online_authorization_predecessor = Some([77; 32]);
    manifest.online_authorization_authority_mode =
        Some(ioi_types::app::QuvAuthorityModeV0::Unowned);
    manifest.fence = EffectFenceV1::AuthorityEpoch {
        authority_snapshot_hash: [88; 32],
        authority_epoch: 1,
        expires_at_height: 10,
    };
    manifest.idempotency_key = manifest.query_unanimity_idempotency_key().unwrap();
    let verified = verified_for(&profile);
    let mut accepted = accepted_for(&manifest, &verified);
    accepted.authority_epoch = 1;
    accepted.authority_snapshot_root = [88; 32];
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    let mut resource = AtomicRegister::new(profile);
    assert!(matches!(
        store.prepare_online_effect(manifest.clone(), &verified, &accepted, 11),
        Err(ConsequenceError::FenceExpired)
    ));
    assert!(!store.receipt_path("epoch-result").exists());
    store
        .prepare_online_effect(manifest.clone(), &verified, &accepted, 10)
        .unwrap();
    assert!(matches!(
        store.prepare_online_effect(manifest.clone(), &verified, &accepted, 11),
        Err(ConsequenceError::FenceExpired)
    ));
    let binding = store
        .online_authorization_requirement("epoch-result")
        .unwrap();
    let executed = store
        .execute_with_online_authorization(
            "epoch-result",
            &mut resource,
            TestOnlineAuthorization(binding, Instant::now() + Duration::from_secs(10)),
            10,
        )
        .unwrap();
    let bytes = std::fs::read(store.receipt_path("epoch-result")).unwrap();
    drop(store);
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    for wrong_epoch in [false, true] {
        let mut wrong = accepted.clone();
        if wrong_epoch {
            wrong.authority_epoch = 2;
        } else {
            wrong.authority_snapshot_root = [89; 32];
        }
        assert!(matches!(
            store.prepare_online_effect(manifest.clone(), &verified, &wrong, 11),
            Err(ConsequenceError::FenceExpired)
        ));
    }
    assert_eq!(
        store
            .prepare_online_effect(manifest.clone(), &verified, &accepted, 11)
            .unwrap(),
        executed
    );
    assert_eq!(
        store
            .online_retry_result("epoch-result", &mut resource)
            .unwrap(),
        Some(executed)
    );
    assert_eq!(
        std::fs::read(store.receipt_path("epoch-result")).unwrap(),
        bytes
    );
    assert_eq!(resource.invocations, 1);
    assert_eq!(resource.mutations, 1);
    assert!(matches!(
        store.authorize(manifest, &verified, &accepted, 11),
        Err(ConsequenceError::FenceExpired)
    ));
}

#[test]
fn online_effect_rechecks_height_fence_after_live_quv() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let mut manifest = manifest("quv-expired-fence", profile.clone());
    manifest.authorization_mode = EffectAuthorizationModeV1::OnlineQueryUnanimityV0;
    manifest.online_authorization_policy_root = Some([19; 32]);
    manifest.online_authorization_predecessor = Some([77; 32]);
    manifest.online_authorization_authority_mode =
        Some(ioi_types::app::QuvAuthorityModeV0::Unowned);
    manifest.fence = EffectFenceV1::ProtocolHeight {
        configuration_hash: [88; 32],
        minimum_height: 10,
        maximum_height: 10,
    };
    manifest.idempotency_key = manifest.query_unanimity_idempotency_key().unwrap();
    let mut resource = AtomicRegister::new(profile);
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    authorize(&mut store, manifest);
    let binding = store
        .online_authorization_requirement("quv-expired-fence")
        .unwrap();
    assert!(matches!(
        store.execute_with_online_authorization(
            "quv-expired-fence",
            &mut resource,
            TestOnlineAuthorization(binding, Instant::now() + Duration::from_secs(1)),
            11,
        ),
        Err(ConsequenceError::FenceExpired)
    ));
    assert_eq!(resource.mutations, 0);
    assert_eq!(
        store.load("quv-expired-fence").unwrap().state.phase(),
        ConsequencePhaseV1::Authorized
    );
}

#[test]
fn online_effect_rechecks_process_local_deadline_at_claim_transition() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let mut manifest = manifest("quv-expired-continuation", profile.clone());
    manifest.authorization_mode = EffectAuthorizationModeV1::OnlineQueryUnanimityV0;
    manifest.online_authorization_policy_root = Some([19; 32]);
    manifest.online_authorization_predecessor = Some([77; 32]);
    manifest.online_authorization_authority_mode =
        Some(ioi_types::app::QuvAuthorityModeV0::Unowned);
    manifest.fence = EffectFenceV1::ProtocolHeight {
        configuration_hash: [88; 32],
        minimum_height: 10,
        maximum_height: 10,
    };
    manifest.idempotency_key = manifest.query_unanimity_idempotency_key().unwrap();
    let mut resource = AtomicRegister::new(profile);
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    authorize(&mut store, manifest);
    let binding = store
        .online_authorization_requirement("quv-expired-continuation")
        .unwrap();
    assert!(matches!(
        store.execute_with_online_authorization(
            "quv-expired-continuation",
            &mut resource,
            TestOnlineAuthorization(binding, Instant::now() - Duration::from_millis(1)),
            10,
        ),
        Err(ConsequenceError::InvalidOnlineAuthorization)
    ));
    assert_eq!(resource.mutations, 0);
    assert_eq!(
        store
            .load("quv-expired-continuation")
            .unwrap()
            .state
            .phase(),
        ConsequencePhaseV1::Authorized
    );
}

#[test]
fn claimed_online_retry_requires_a_live_fence_and_continuation() {
    for (height, live_continuation) in [(11, true), (10, false), (10, true)] {
        let temp = TempDir::new().unwrap();
        let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
        let mut manifest = manifest("quv-claimed-retry", profile.clone());
        manifest.authorization_mode = EffectAuthorizationModeV1::OnlineQueryUnanimityV0;
        manifest.online_authorization_policy_root = Some([19; 32]);
        manifest.online_authorization_predecessor = Some([77; 32]);
        manifest.online_authorization_authority_mode =
            Some(ioi_types::app::QuvAuthorityModeV0::Unowned);
        manifest.fence = EffectFenceV1::ProtocolHeight {
            configuration_hash: [88; 32],
            minimum_height: 10,
            maximum_height: 10,
        };
        manifest.idempotency_key = manifest.query_unanimity_idempotency_key().unwrap();
        let mut resource = AtomicRegister::new(profile);
        let mut store = ConsequenceStore::open(temp.path()).unwrap();
        authorize(&mut store, manifest);
        let binding = store
            .online_authorization_requirement("quv-claimed-retry")
            .unwrap();
        store.arm_crash(ConsequenceCrashPoint::AfterClaimed);
        assert!(matches!(
            store.execute_with_online_authorization(
                "quv-claimed-retry",
                &mut resource,
                TestOnlineAuthorization(binding, Instant::now() + Duration::from_secs(10)),
                10,
            ),
            Err(ConsequenceError::InjectedCrash(
                ConsequenceCrashPoint::AfterClaimed
            ))
        ));
        assert_eq!(resource.invocations, 0);
        let receipt = store.load("quv-claimed-retry").unwrap();
        assert_eq!(receipt.state.phase(), ConsequencePhaseV1::Claimed);
        drop(store);
        let mut store = ConsequenceStore::open(temp.path()).unwrap();
        let verified = verified_for(&receipt.manifest.resource_profile);
        let accepted = accepted_for(&receipt.manifest, &verified);
        let durable_before = std::fs::read(store.receipt_path("quv-claimed-retry")).unwrap();
        let mut changed_admission = accepted.clone();
        changed_admission.authorization_receipt_root = [43; 32];
        assert!(matches!(
            store.authorize(receipt.manifest.clone(), &verified, &changed_admission, 10),
            Err(ConsequenceError::ReplayConflict)
        ));
        assert_eq!(
            std::fs::read(store.receipt_path("quv-claimed-retry")).unwrap(),
            durable_before
        );
        // Use the public admission/requirement path used by both executors.
        // The process-level live network retry remains a separate gate.
        assert!(matches!(
            store.prepare_online_effect(receipt.manifest.clone(), &verified, &accepted, 11),
            Err(ConsequenceError::FenceExpired)
        ));
        let readmitted = store
            .authorize(receipt.manifest.clone(), &verified, &accepted, 10)
            .unwrap();
        assert_eq!(readmitted, receipt);
        assert!(matches!(
            store.execute("quv-claimed-retry", &mut resource),
            Err(ConsequenceError::OnlineAuthorizationRequired)
        ));
        assert_eq!(resource.invocations, 0);
        let retry_binding = store
            .online_authorization_requirement("quv-claimed-retry")
            .unwrap();
        let deadline = if live_continuation {
            Instant::now() + Duration::from_secs(10)
        } else {
            Instant::now() - Duration::from_secs(1)
        };
        let result = store.execute_with_online_authorization(
            "quv-claimed-retry",
            &mut resource,
            TestOnlineAuthorization(retry_binding, deadline),
            height,
        );
        if height > 10 {
            assert!(matches!(result, Err(ConsequenceError::FenceExpired)));
        } else if !live_continuation {
            assert!(matches!(
                result,
                Err(ConsequenceError::InvalidOnlineAuthorization)
            ));
        } else {
            assert_eq!(result.unwrap().state.phase(), ConsequencePhaseV1::Executed);
        }
        let expected_calls = u32::from(height == 10 && live_continuation);
        assert_eq!(resource.invocations, expected_calls);
        assert_eq!(resource.mutations, expected_calls);
        if expected_calls == 0 {
            assert_eq!(
                store.load("quv-claimed-retry").unwrap().state.phase(),
                ConsequencePhaseV1::Claimed
            );
        }
    }
}

#[test]
fn permanently_stalled_seal_domain_does_not_block_unrelated_effects() {
    let temp = TempDir::new().unwrap();
    let resource_profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let mut store = ConsequenceStore::open(temp.path()).unwrap();

    // Domain A requires a unanimous terminal seal, but receives only ordering
    // evidence: this models the fail-closed result of one permanent
    // withholder. It never acquires an executable authorization.
    let mut stalled = manifest("stalled-ring", resource_profile.clone());
    stalled.conflict_domain_id = "domain://test/stalled-ring".into();
    stalled.required_guarantees.minimum_finality_rank = Some(GuaranteeRank::SealedAllButOne);
    let ordering_only = verified_for(&resource_profile);
    let stalled_authorization = accepted_for(&stalled, &ordering_only);
    assert!(matches!(
        store.authorize(stalled, &ordering_only, &stalled_authorization, 10),
        Err(ConsequenceError::PolicyUnsatisfied)
    ));

    // Domain B remains independent. Three distinct effects make progress; the
    // middle invocation loses its response after mutation and recovers only
    // through same-key lookup.
    let mut resource = AtomicRegister::new(resource_profile.clone());
    for index in 0..3 {
        let effect_id = format!("live-{index}");
        let mut live = manifest(&effect_id, resource_profile.clone());
        live.conflict_domain_id = "domain://test/live-ring".into();
        live.write_set[0].key = format!("transfer/{index}");
        authorize(&mut store, live);
        resource.mode = if index == 1 {
            InvocationMode::AmbiguousAfterMutation
        } else {
            InvocationMode::Normal
        };
        let result = store.execute(&effect_id, &mut resource);
        if index == 1 {
            assert!(matches!(result, Err(ConsequenceError::Ambiguous)));
        } else {
            assert_eq!(result.unwrap().state.phase(), ConsequencePhaseV1::Executed);
        }
        assert_eq!(
            store
                .reconcile(&effect_id, &mut resource)
                .unwrap()
                .state
                .phase(),
            ConsequencePhaseV1::Reconciled
        );
    }

    assert_eq!(resource.invocations, 3);
    assert_eq!(resource.mutations, 3);
    assert!(matches!(
        store.load("stalled-ring"),
        Err(ConsequenceError::Io(_))
    ));
}

#[test]
fn ambiguous_result_reconciles_same_key_without_blind_replay() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let manifest = manifest("ambiguous", profile.clone());
    let mut resource = AtomicRegister::new(profile);
    resource.mode = InvocationMode::AmbiguousAfterMutation;
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    authorize(&mut store, manifest);
    assert!(matches!(
        store.execute("ambiguous", &mut resource),
        Err(ConsequenceError::Ambiguous)
    ));
    assert_eq!(
        store.load("ambiguous").unwrap().state.phase(),
        ConsequencePhaseV1::Unknown
    );
    let reconciled = store.reconcile("ambiguous", &mut resource).unwrap();
    assert!(matches!(
        reconciled.state,
        ConsequenceStateV1::Reconciled {
            resolution: ReconciliationResolutionV1::Executed { .. },
            ..
        }
    ));
    assert_eq!(resource.invocations, 1);
    assert_eq!(resource.mutations, 1);
}

#[test]
fn unsupported_resource_cannot_authorize_irreversible_at_most_once_policy() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::UnsupportedBestEffort);
    let manifest = manifest("unsupported", profile.clone());
    let verified = verified_for(&profile);
    let authorization = accepted_for(&manifest, &verified);
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    assert!(matches!(
        store.authorize(manifest, &verified, &authorization, 10),
        Err(ConsequenceError::PolicyUnsatisfied)
    ));
}

#[test]
fn authorization_token_and_both_fence_forms_fail_closed() {
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let manifest = manifest("fenced", profile.clone());
    let verified = verified_for(&profile);
    let mut authorization = accepted_for(&manifest, &verified);
    authorization.effect_id = "substituted".into();
    let temp = TempDir::new().unwrap();
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    assert!(matches!(
        store.authorize(manifest.clone(), &verified, &authorization, 10),
        Err(ConsequenceError::ReplayConflict)
    ));

    let mut authority_manifest = manifest;
    authority_manifest.effect_id = "authority-fenced".into();
    authority_manifest.idempotency_key = "idem-authority-fenced".into();
    authority_manifest.fence = EffectFenceV1::AuthorityEpoch {
        authority_snapshot_hash: [8; 32],
        authority_epoch: 7,
        expires_at_height: 10,
    };
    let mut authorization = accepted_for(&authority_manifest, &verified);
    authorization.authority_epoch = 7;
    authorization.authority_snapshot_root = [8; 32];
    let temp = TempDir::new().unwrap();
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    assert!(store
        .authorize(authority_manifest.clone(), &verified, &authorization, 10,)
        .is_ok());

    let mut expired = authority_manifest;
    expired.effect_id = "authority-expired".into();
    expired.idempotency_key = "idem-authority-expired".into();
    let authorization = accepted_for(&expired, &verified);
    assert!(matches!(
        store.authorize(expired, &verified, &authorization, 11),
        Err(ConsequenceError::FenceExpired)
    ));
}

#[test]
fn crash_after_external_call_recovers_by_lookup_and_never_calls_twice() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let manifest = manifest("crash-after-call", profile.clone());
    let mut resource = AtomicRegister::new(profile);
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    authorize(&mut store, manifest);
    store.arm_crash(ConsequenceCrashPoint::AfterInvocation);
    assert!(matches!(
        store.execute("crash-after-call", &mut resource),
        Err(ConsequenceError::InjectedCrash(
            ConsequenceCrashPoint::AfterInvocation
        ))
    ));
    assert_eq!(resource.mutations, 1);
    drop(store);

    let mut restarted = ConsequenceStore::open(temp.path()).unwrap();
    let recovered = restarted.recover("crash-after-call").unwrap();
    assert_eq!(recovered.state.phase(), ConsequencePhaseV1::Unknown);
    restarted
        .reconcile("crash-after-call", &mut resource)
        .unwrap();
    assert_eq!(resource.invocations, 1);
    assert_eq!(resource.mutations, 1);
}

#[test]
fn every_persistence_and_invocation_boundary_is_restart_safe() {
    let points = [
        ConsequenceCrashPoint::AfterAuthorized,
        ConsequenceCrashPoint::AfterClaimed,
        ConsequenceCrashPoint::AfterInFlight,
        ConsequenceCrashPoint::AfterInvocation,
        ConsequenceCrashPoint::AfterExecuted,
        ConsequenceCrashPoint::AfterUnknown,
        ConsequenceCrashPoint::AfterLookupReserved,
        ConsequenceCrashPoint::AfterLookup,
        ConsequenceCrashPoint::AfterReconciled,
    ];
    for point in points {
        let temp = TempDir::new().unwrap();
        let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
        let effect_id = format!("crash-{point:?}");
        let manifest = manifest(effect_id.clone(), profile.clone());
        let verified = verified_for(&profile);
        let authorization = accepted_for(&manifest, &verified);
        let mut resource = AtomicRegister::new(profile);
        if point == ConsequenceCrashPoint::AfterUnknown {
            resource.mode = InvocationMode::AmbiguousAfterMutation;
        }
        let mut store = ConsequenceStore::open(temp.path()).unwrap();
        if point == ConsequenceCrashPoint::AfterAuthorized {
            store.arm_crash(point);
            assert!(matches!(
                store.authorize(manifest.clone(), &verified, &authorization, 10),
                Err(ConsequenceError::InjectedCrash(_))
            ));
        } else {
            store
                .authorize(manifest.clone(), &verified, &authorization, 10)
                .unwrap();
            store.arm_crash(point);
            if matches!(
                point,
                ConsequenceCrashPoint::AfterLookupReserved
                    | ConsequenceCrashPoint::AfterLookup
                    | ConsequenceCrashPoint::AfterReconciled
            ) {
                store.execute(&effect_id, &mut resource).unwrap();
                assert!(matches!(
                    store.reconcile(&effect_id, &mut resource),
                    Err(ConsequenceError::InjectedCrash(_))
                ));
            } else {
                assert!(matches!(
                    store.execute(&effect_id, &mut resource),
                    Err(ConsequenceError::InjectedCrash(_)) | Err(ConsequenceError::Ambiguous)
                ));
            }
        }
        drop(store);

        let mut restarted = ConsequenceStore::open(temp.path()).unwrap();
        let recovered = restarted.recover(&effect_id).unwrap();
        match recovered.state.phase() {
            ConsequencePhaseV1::Authorized | ConsequencePhaseV1::Claimed => {
                restarted.execute(&effect_id, &mut resource).unwrap();
                restarted.reconcile(&effect_id, &mut resource).unwrap();
            }
            ConsequencePhaseV1::Executed | ConsequencePhaseV1::Unknown => {
                restarted.reconcile(&effect_id, &mut resource).unwrap();
            }
            ConsequencePhaseV1::Reconciled => {}
            phase => panic!("unexpected recovered phase {phase:?}"),
        }
        assert_eq!(
            restarted.load(&effect_id).unwrap().state.phase(),
            ConsequencePhaseV1::Reconciled,
            "failed at {point:?}"
        );
        assert!(resource.mutations <= 1, "duplicate mutation at {point:?}");
        assert!(resource.invocations <= 1, "blind replay at {point:?}");
    }
}

#[test]
fn ambiguity_is_not_attributed_but_signed_contradiction_is_transferable() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let manifest = manifest("attribution", profile.clone());
    let mut resource = AtomicRegister::new(profile);
    resource.mode = InvocationMode::AmbiguousWithoutMutation;
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    authorize(&mut store, manifest.clone());
    assert!(matches!(
        store.execute("attribution", &mut resource),
        Err(ConsequenceError::Ambiguous)
    ));

    let temp = TempDir::new().unwrap();
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    authorize(&mut store, manifest.clone());
    let evidence = b"signed-resource-contradiction".to_vec();
    let evidence_hash = evidence_hash(&evidence);
    let conflict = ExternalResourceRecordV1 {
        resource_id: manifest.resource_id.clone(),
        idempotency_key: manifest.idempotency_key.clone(),
        request_root: [99; 32],
        predecessor_root: manifest.predecessor_root,
        outcome_root: manifest.expected_outcome_root,
        mutation_sequence: 9,
        evidence: Some(evidence),
        evidence_hash: Some(evidence_hash),
    };
    let mut resource = AtomicRegister::new(manifest.resource_profile.clone());
    resource.forced_conflict = Some(conflict);
    let proof = match store.execute("attribution", &mut resource) {
        Err(ConsequenceError::TransferableViolation(proof)) => proof,
        other => panic!("expected transferable contradiction, got {other:?}"),
    };
    proof.verify_with(&manifest, &resource).unwrap();
    assert_eq!(proof.kind, ResourceViolationKindV1::RequestSubstitution);
}

#[test]
fn receipt_commits_intent_outcome_and_reconciliation_evidence() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let manifest = manifest("receipt-roots", profile.clone());
    let mut resource = AtomicRegister::new(profile);
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    authorize(&mut store, manifest.clone());
    store.execute("receipt-roots", &mut resource).unwrap();
    let receipt = store.reconcile("receipt-roots", &mut resource).unwrap();
    let json = serde_json::to_value(receipt).unwrap();
    assert_eq!(
        json["manifest"]["intent_root"],
        serde_json::json!(manifest.intent_root)
    );
    assert_eq!(
        json["manifest"]["expected_outcome_root"],
        serde_json::json!(manifest.expected_outcome_root)
    );
    assert!(json["state"]["reconciliation_root"].is_array());
}

#[test]
fn runtime_traces_conform_to_the_formal_clear_and_ambiguous_paths() {
    let temp = TempDir::new().unwrap();
    let clear_profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let clear_manifest = manifest("formal-clear", clear_profile.clone());
    let mut resource = AtomicRegister::new(clear_profile);
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    authorize(&mut store, clear_manifest);
    store.execute("formal-clear", &mut resource).unwrap();
    let clear = store.reconcile("formal-clear", &mut resource).unwrap();
    assert_eq!(
        clear.trace.iter().map(|step| step.to).collect::<Vec<_>>(),
        vec![
            ConsequencePhaseV1::Authorized,
            ConsequencePhaseV1::Claimed,
            ConsequencePhaseV1::InFlight,
            ConsequencePhaseV1::Executed,
            ConsequencePhaseV1::Reconciled,
        ]
    );

    let temp = TempDir::new().unwrap();
    let ambiguous_profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let ambiguous_manifest = manifest("formal-ambiguous", ambiguous_profile.clone());
    let mut resource = AtomicRegister::new(ambiguous_profile);
    resource.mode = InvocationMode::AmbiguousAfterMutation;
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    authorize(&mut store, ambiguous_manifest);
    assert!(store.execute("formal-ambiguous", &mut resource).is_err());
    let ambiguous = store.reconcile("formal-ambiguous", &mut resource).unwrap();
    assert_eq!(
        ambiguous
            .trace
            .iter()
            .map(|step| step.to)
            .collect::<Vec<_>>(),
        vec![
            ConsequencePhaseV1::Authorized,
            ConsequencePhaseV1::Claimed,
            ConsequencePhaseV1::InFlight,
            ConsequencePhaseV1::Unknown,
            ConsequencePhaseV1::Reconciled,
        ]
    );
}

#[test]
fn reconciliation_reserves_attempts_across_crashes_before_and_after_lookup() {
    for unknown in [false, true] {
        for point in [
            ConsequenceCrashPoint::AfterLookupReserved,
            ConsequenceCrashPoint::AfterLookup,
        ] {
            let temp = TempDir::new().unwrap();
            let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
            let manifest = manifest("reserved-reconciliation", profile.clone());
            let mut resource = AtomicRegister::new(profile);
            if unknown {
                resource.mode = InvocationMode::AmbiguousWithoutMutation;
            }
            let mut store = ConsequenceStore::open(temp.path()).unwrap();
            authorize(&mut store, manifest);
            let initial = store.execute("reserved-reconciliation", &mut resource);
            if unknown {
                assert!(matches!(initial, Err(ConsequenceError::Ambiguous)));
            } else {
                assert!(initial.is_ok());
            }
            for attempt in 1..=3 {
                store.arm_crash(point);
                assert!(
                    matches!(store.reconcile("reserved-reconciliation", &mut resource),
                    Err(ConsequenceError::InjectedCrash(actual)) if actual == point)
                );
                drop(store);
                store = ConsequenceStore::open(temp.path()).unwrap();
                assert_eq!(
                    store
                        .load("reserved-reconciliation")
                        .unwrap()
                        .reconciliation_attempts,
                    attempt
                );
                assert_eq!(
                    resource.lookups,
                    if point == ConsequenceCrashPoint::AfterLookup {
                        attempt
                    } else {
                        0
                    }
                );
            }
            let before = std::fs::read(store.receipt_path("reserved-reconciliation")).unwrap();
            assert!(matches!(
                store.reconcile("reserved-reconciliation", &mut resource),
                Err(ConsequenceError::ReconciliationExhausted)
            ));
            assert_eq!(
                std::fs::read(store.receipt_path("reserved-reconciliation")).unwrap(),
                before
            );
            assert_eq!(resource.invocations, 1);
            assert_eq!(resource.mutations, u32::from(!unknown));
        }
    }
}

#[test]
fn reconciliation_legacy_counter_and_known_execution_are_preserved() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let manifest = manifest("legacy-reconciliation", profile.clone());
    let mut resource = AtomicRegister::new(profile);
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    let authorized = authorize(&mut store, manifest);
    let encoded = serde_jcs::to_vec(&authorized).unwrap();
    assert!(!String::from_utf8(encoded.clone())
        .unwrap()
        .contains("reconciliation_attempts"));
    assert_eq!(
        serde_json::from_slice::<ConsequenceReceiptV1>(&encoded).unwrap(),
        authorized
    );
    store
        .execute("legacy-reconciliation", &mut resource)
        .unwrap();
    resource.ambiguous_lookup = true;
    assert!(matches!(
        store.reconcile("legacy-reconciliation", &mut resource),
        Err(ConsequenceError::Ambiguous)
    ));
    let executed = store.load("legacy-reconciliation").unwrap();
    assert_eq!(executed.state.phase(), ConsequencePhaseV1::Executed);
    assert_eq!(executed.reconciliation_attempts, 1);

    // Model a legacy receipt with two recorded ambiguous observations and
    // no reservation field; upgrading must not grant three additional attempts.
    // Build the legacy trace through the normal ambiguity path.
    drop(store);
    let legacy_temp = TempDir::new().unwrap();
    let mut store = ConsequenceStore::open(legacy_temp.path()).unwrap();
    authorize(&mut store, executed.manifest.clone());
    resource.mode = InvocationMode::AmbiguousWithoutMutation;
    resource.records.clear();
    assert!(matches!(
        store.execute("legacy-reconciliation", &mut resource),
        Err(ConsequenceError::Ambiguous)
    ));
    for _ in 0..2 {
        assert!(matches!(
            store.reconcile("legacy-reconciliation", &mut resource),
            Err(ConsequenceError::Ambiguous)
        ));
    }
    let mut old = store.load("legacy-reconciliation").unwrap();
    old.reconciliation_attempts = 0;
    persist_receipt(&store.receipt_path("legacy-reconciliation"), &mut old).unwrap();
    assert!(matches!(
        store.reconcile("legacy-reconciliation", &mut resource),
        Err(ConsequenceError::ReconciliationExhausted)
    ));
    let mut exhausted = store.load("legacy-reconciliation").unwrap();
    assert_eq!(exhausted.reconciliation_attempts, 3);
    exhausted.reconciliation_attempts = 4;
    assert!(matches!(
        exhausted.validate(),
        Err(ConsequenceError::CorruptReceipt)
    ));
}

#[test]
fn reconciliation_is_bounded_and_never_becomes_mutation_authority() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let manifest = manifest("bounded-reconciliation", profile.clone());
    let mut resource = AtomicRegister::new(profile);
    resource.mode = InvocationMode::AmbiguousWithoutMutation;
    resource.ambiguous_lookup = true;
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    authorize(&mut store, manifest);
    assert!(matches!(
        store.execute("bounded-reconciliation", &mut resource),
        Err(ConsequenceError::Ambiguous)
    ));
    for expected in [
        ConsequenceError::Ambiguous,
        ConsequenceError::Ambiguous,
        ConsequenceError::ReconciliationExhausted,
    ] {
        let actual = store.reconcile("bounded-reconciliation", &mut resource);
        assert_eq!(
            std::mem::discriminant(&actual.unwrap_err()),
            std::mem::discriminant(&expected)
        );
    }
    assert_eq!(resource.lookups, 3);
    let exhausted = store.load("bounded-reconciliation").unwrap();
    assert_eq!(
        exhausted.trace.len() as u64,
        receipt_trace_limit(&exhausted.manifest)
    );
    let bytes = std::fs::read(store.receipt_path("bounded-reconciliation")).unwrap();
    // Clearing the transient resource fault cannot reset the durable budget.
    resource.ambiguous_lookup = false;
    for _ in 0..2 {
        assert!(matches!(
            store.reconcile("bounded-reconciliation", &mut resource),
            Err(ConsequenceError::ReconciliationExhausted)
        ));
    }
    drop(store);
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    assert!(matches!(
        store.reconcile("bounded-reconciliation", &mut resource),
        Err(ConsequenceError::ReconciliationExhausted)
    ));
    assert_eq!(resource.lookups, 3);
    assert_eq!(store.load("bounded-reconciliation").unwrap(), exhausted);
    assert_eq!(
        std::fs::read(store.receipt_path("bounded-reconciliation")).unwrap(),
        bytes
    );
    assert_eq!(resource.invocations, 1);
    assert_eq!(resource.mutations, 0);
}

#[test]
fn receipt_trace_bound_refuses_extra_ambiguity_without_mutating_state() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let manifest = manifest("trace-bound", profile.clone());
    let mut resource = AtomicRegister::new(profile);
    resource.mode = InvocationMode::AmbiguousWithoutMutation;
    resource.ambiguous_lookup = true;
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    authorize(&mut store, manifest);
    assert!(matches!(
        store.execute("trace-bound", &mut resource),
        Err(ConsequenceError::Ambiguous)
    ));
    for attempt in 1..=3 {
        let result = store.reconcile("trace-bound", &mut resource);
        if attempt < 3 {
            assert!(matches!(result, Err(ConsequenceError::Ambiguous)));
        } else {
            assert!(matches!(
                result,
                Err(ConsequenceError::ReconciliationExhausted)
            ));
        }
    }
    let mut receipt = store.load("trace-bound").unwrap();
    let before = receipt.clone();
    let next = receipt.state.clone();
    assert!(matches!(
        transition(&mut receipt, next),
        Err(ConsequenceError::CorruptReceipt)
    ));
    assert_eq!(receipt, before);
    // A synthetic extra legal phase edge with a recomputed receipt hash must
    // still fail recovery: a content hash is not a proof of a reachable budget.
    let mut extra = receipt.trace.last().unwrap().clone();
    extra.sequence += 1;
    extra.from = Some(ConsequencePhaseV1::Unknown);
    receipt.trace.push(extra);
    receipt.generation += 1;
    receipt.receipt_root = receipt_root(&receipt).unwrap();
    let raw = serde_jcs::to_vec(&receipt).unwrap();
    let path = store.receipt_path("trace-bound");
    fs::write(&path, &raw).unwrap();
    assert!(matches!(
        store.load("trace-bound"),
        Err(ConsequenceError::CorruptReceipt)
    ));
    assert_eq!(fs::read(&path).unwrap(), raw);
    assert_eq!(resource.invocations, 1);
    assert_eq!(resource.mutations, 0);
}

#[test]
fn forged_resource_evidence_cannot_create_transferable_attribution() {
    let temp = TempDir::new().unwrap();
    let profile = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
    let manifest = manifest("forged-evidence", profile.clone());
    let mut store = ConsequenceStore::open(temp.path()).unwrap();
    authorize(&mut store, manifest.clone());
    let forged = b"not-valid-resource-evidence".to_vec();
    let mut resource = AtomicRegister::new(profile);
    resource.forced_conflict = Some(ExternalResourceRecordV1 {
        resource_id: manifest.resource_id,
        idempotency_key: manifest.idempotency_key,
        request_root: [77; 32],
        predecessor_root: manifest.predecessor_root,
        outcome_root: manifest.expected_outcome_root,
        mutation_sequence: 2,
        evidence_hash: Some(evidence_hash(&forged)),
        evidence: Some(forged),
    });
    assert!(matches!(
        store.execute("forged-evidence", &mut resource),
        Err(ConsequenceError::UnattributedResourceConflict)
    ));
}

fn evidence_hash(evidence: &[u8]) -> ConsequenceHash {
    let canonical = serde_jcs::to_vec(evidence).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"ioi::aft::external-resource-evidence::v1\0");
    hasher.update(canonical);
    hasher.finalize().into()
}

#[test]
fn online_receipt_bound_covers_named_resource_execution_and_complete_budget() {
    let temp = TempDir::new().unwrap();
    let endpoint = MldsaScheme::new(SecurityLevel::Level2)
        .generate_keypair()
        .unwrap();
    let profile = DurablePqAtomicRegisterV1::profile_for(&endpoint).unwrap();
    let mut manifest = manifest("bounded-online-receipt", profile);
    assert_eq!(online_receipt_byte_bound(&manifest).unwrap(), None);
    manifest.authorization_mode = EffectAuthorizationModeV1::OnlineQueryUnanimityV0;
    manifest.online_authorization_policy_root = Some([19; 32]);
    manifest.online_authorization_predecessor = Some([77; 32]);
    manifest.online_authorization_authority_mode =
        Some(ioi_types::app::QuvAuthorityModeV0::Unowned);
    manifest.idempotency_key = manifest.query_unanimity_idempotency_key().unwrap();
    let bound = online_receipt_byte_bound(&manifest).unwrap().unwrap();
    let mut maximum = manifest.clone();
    maximum.reconciliation = ReconciliationPolicyV1::LookupByIdempotencyKey {
        maximum_observations: u32::MAX,
    };
    let extra_manifest_bytes =
        serde_jcs::to_vec(&maximum).unwrap().len() - serde_jcs::to_vec(&manifest).unwrap().len();
    assert_eq!(
        online_receipt_byte_bound(&maximum).unwrap().unwrap() - bound,
        extra_manifest_bytes as u64 + 512 * (u64::from(u32::MAX) - 3)
    );
    let mut resource =
        DurablePqAtomicRegisterV1::open(temp.path().join("resource"), endpoint).unwrap();
    let mut store = ConsequenceStore::open(temp.path().join("consequence")).unwrap();
    let authorized = authorize(&mut store, manifest.clone());
    assert!(serde_jcs::to_vec(&authorized).unwrap().len() as u64 <= bound);
    resource.prepare(&manifest).unwrap();
    store.prepare_online_storage(&manifest.effect_id).unwrap();
    let binding = store
        .online_authorization_requirement(&manifest.effect_id)
        .unwrap();
    eprintln!("AFT_RECEIPT_LIVE_BEGIN");
    let executed = store
        .execute_with_online_authorization(
            &manifest.effect_id,
            &mut resource,
            TestOnlineAuthorization(binding, Instant::now() + Duration::from_secs(5)),
            10,
        )
        .unwrap();
    eprintln!("AFT_RECEIPT_LIVE_END");
    assert!(serde_jcs::to_vec(&executed).unwrap().len() as u64 <= bound);
    let mut bad_record = match &executed.state {
        ConsequenceStateV1::Executed {
            resource_record, ..
        } => resource_record.clone(),
        _ => panic!("expected completed resource mutation"),
    };
    let excess = vec![0; PQ_REGISTER_EVIDENCE_MAX_BYTES + 1];
    bad_record.evidence_hash = Some(evidence_hash(&excess));
    bad_record.evidence = Some(excess);
    assert!(matches!(
        validate_resource_record(&manifest, &bad_record),
        Err(ConsequenceError::CorruptReceipt)
    ));
    let reconciled = store.reconcile(&manifest.effect_id, &mut resource).unwrap();
    assert!(serde_jcs::to_vec(&reconciled).unwrap().len() as u64 <= bound);
    drop(store);
    let reopened = ConsequenceStore::open(temp.path().join("consequence")).unwrap();
    assert_eq!(reopened.load(&manifest.effect_id).unwrap(), reconciled);
}

#[test]
fn pq_resource_format_bounds_cover_maximum_tokens_and_refuse_noncanonical_evidence() {
    let temp = TempDir::new().unwrap();
    let endpoint = MldsaScheme::new(SecurityLevel::Level2)
        .generate_keypair()
        .unwrap();
    let resource = DurablePqAtomicRegisterV1::open(temp.path(), endpoint).unwrap();
    let record = resource
        .sign_record(ExternalResourceRecordV1 {
            resource_id: "\\".repeat(512),
            idempotency_key: "\\".repeat(512),
            request_root: [255; 32],
            predecessor_root: [255; 32],
            outcome_root: [255; 32],
            mutation_sequence: u64::MAX,
            evidence: None,
            evidence_hash: None,
        })
        .unwrap();
    let evidence = record.evidence.as_ref().unwrap();
    assert!(evidence.len() <= PQ_REGISTER_EVIDENCE_MAX_BYTES);
    let envelope: DurablePqRegisterEvidenceV1 = serde_json::from_slice(evidence).unwrap();
    assert_eq!(
        BASE64
            .decode(&envelope.statement.endpoint_public_key_base64)
            .unwrap()
            .len(),
        1312
    );
    assert_eq!(
        BASE64.decode(&envelope.signature_base64).unwrap().len(),
        2420
    );
    assert!(resource.verify_record_evidence(&record));
    let raw = serde_jcs::to_vec(&record).unwrap();
    assert!(raw.len() <= PQ_REGISTER_RECORD_MAX_BYTES);
    let path = resource.record_path(&record.resource_id, &record.idempotency_key);
    fs::write(&path, &raw).unwrap();
    assert_eq!(
        resource
            .read_record(&record.resource_id, &record.idempotency_key)
            .unwrap(),
        Some(record.clone())
    );
    let mut alternate = record.clone();
    let mut whitespace = vec![b' '];
    whitespace.extend_from_slice(evidence);
    alternate.evidence_hash = Some(evidence_hash(&whitespace));
    alternate.evidence = Some(whitespace);
    assert!(!resource.verify_record_evidence(&alternate));
    let mut oversized = raw.clone();
    oversized.resize(PQ_REGISTER_RECORD_MAX_BYTES + 1, b' ');
    fs::write(&path, &oversized).unwrap();
    assert!(matches!(
        resource.read_record(&record.resource_id, &record.idempotency_key),
        Err(ConsequenceError::CorruptReceipt)
    ));
    assert_eq!(fs::read(&path).unwrap(), oversized);
    fs::write(&path, &raw).unwrap();
    assert_eq!(
        resource
            .read_record(&record.resource_id, &record.idempotency_key)
            .unwrap(),
        Some(record)
    );
    let other_suite = MldsaScheme::new(SecurityLevel::Level3)
        .generate_keypair()
        .unwrap();
    assert!(matches!(
        DurablePqAtomicRegisterV1::profile_for(&other_suite),
        Err(ConsequenceError::Invalid(_))
    ));
}

#[test]
fn durable_pq_register_is_cross_instance_at_most_once_and_evidence_verified() {
    let temp = TempDir::new().unwrap();
    let endpoint = MldsaScheme::new(SecurityLevel::Level2)
        .generate_keypair()
        .unwrap();
    let profile = DurablePqAtomicRegisterV1::profile_for(&endpoint).unwrap();
    let manifest = manifest("durable-pq-register", profile);
    let mut first = DurablePqAtomicRegisterV1::open(temp.path(), endpoint.clone()).unwrap();
    let mut second = DurablePqAtomicRegisterV1::open(temp.path(), endpoint).unwrap();

    let AtomicMutationResultV1::Inserted(inserted) = first.invoke_atomic(&manifest).unwrap() else {
        panic!("first mutation must insert");
    };
    assert!(first.verify_record_evidence(&inserted));
    let AtomicMutationResultV1::Existing(existing) = second.invoke_atomic(&manifest).unwrap()
    else {
        panic!("duplicate mutation must observe the existing record");
    };
    assert_eq!(existing, inserted);
    assert!(second.verify_record_evidence(&existing));
}

#[cfg(target_os = "linux")]
#[test]
fn online_pq_endpoint_consumes_reserved_inode_and_retains_active_authority() {
    use std::os::unix::fs::MetadataExt;
    let temp = TempDir::new().unwrap();
    let endpoint = MldsaScheme::new(SecurityLevel::Level2)
        .generate_keypair()
        .unwrap();
    let profile = DurablePqAtomicRegisterV1::profile_for(&endpoint).unwrap();
    let mut manifest = manifest("reserved-endpoint", profile);
    manifest.authorization_mode = EffectAuthorizationModeV1::OnlineQueryUnanimityV0;
    manifest.online_authorization_policy_root = Some([19; 32]);
    manifest.online_authorization_predecessor = Some([77; 32]);
    manifest.online_authorization_authority_mode =
        Some(ioi_types::app::QuvAuthorityModeV0::Unowned);
    manifest.idempotency_key = manifest.query_unanimity_idempotency_key().unwrap();
    manifest.validate().unwrap();
    let mut resource = DurablePqAtomicRegisterV1::open(temp.path(), endpoint.clone()).unwrap();
    let active = resource.record_path(&manifest.resource_id, &manifest.idempotency_key);
    let pending = resource_reservation::staged(&active).unwrap();
    // An online call cannot allocate missing capacity after its live interaction.
    assert_eq!(
        resource.invoke_atomic(&manifest),
        Err(ResourceInvocationErrorV1::Ambiguous)
    );
    assert!(!active.exists());
    assert!(!pending.exists());
    assert!(matches!(
        resource.prepare(&manifest),
        Err(ConsequenceError::ResourceRequiresReopen)
    ));
    drop(resource);
    let mut resource = DurablePqAtomicRegisterV1::open(temp.path(), endpoint.clone()).unwrap();
    resource.prepare(&manifest).unwrap();
    let reserved = File::open(&pending).unwrap();
    assert_eq!(
        reserved.metadata().unwrap().len(),
        PQ_REGISTER_RECORD_MAX_BYTES as u64
    );
    assert_eq!(
        reserved.allocated_size().unwrap(),
        PQ_REGISTER_RECORD_MAX_BYTES as u64
    );
    let inode = reserved.metadata().unwrap().ino();
    eprintln!("AFT_ENDPOINT_LIVE_BEGIN");
    let record = match resource.invoke_atomic(&manifest).unwrap() {
        AtomicMutationResultV1::Inserted(record) => record,
        other => panic!("expected one insertion: {other:?}"),
    };
    eprintln!("AFT_ENDPOINT_LIVE_END");
    assert!(!pending.exists());
    assert_eq!(fs::metadata(&active).unwrap().ino(), inode);
    assert_eq!(
        File::open(&active).unwrap().allocated_size().unwrap(),
        PQ_REGISTER_RECORD_MAX_BYTES as u64
    );
    assert_eq!(
        resource.invoke_atomic(&manifest).unwrap(),
        AtomicMutationResultV1::Existing(record.clone())
    );
    let active_bytes = fs::read(&active).unwrap();
    // An interrupted spare is never selected over the signed active value.
    fs::write(&pending, b"interrupted spare").unwrap();
    resource.prepare(&manifest).unwrap();
    assert_eq!(fs::read(&pending).unwrap(), b"interrupted spare");
    let mut conflict = manifest.clone();
    conflict.request_root = [91; 32];
    resource.prepare(&conflict).unwrap();
    assert_eq!(
        resource.invoke_atomic(&conflict),
        Err(ResourceInvocationErrorV1::Conflict(record.clone()))
    );
    assert_eq!(fs::read(&active).unwrap(), active_bytes);
    drop(resource);
    let mut resource = DurablePqAtomicRegisterV1::open(temp.path(), endpoint).unwrap();
    assert_eq!(
        resource
            .lookup(&manifest.resource_id, &manifest.idempotency_key)
            .unwrap(),
        Some(record)
    );
    fs::write(&active, b"corrupt active").unwrap();
    assert!(resource.prepare(&manifest).is_err());
    assert!(resource
        .lookup(&manifest.resource_id, &manifest.idempotency_key)
        .is_err());
    assert_eq!(fs::read(&active).unwrap(), b"corrupt active");
    assert_eq!(fs::read(&pending).unwrap(), b"interrupted spare");
}

#[cfg(target_os = "linux")]
#[test]
fn endpoint_reservation_refuses_lost_capacity_and_recovers_only_uncommitted_staging() {
    let temp = TempDir::new().unwrap();
    let active = temp.path().join("record.json");
    let pending = resource_reservation::staged(&active).unwrap();
    resource_reservation::prepare(&active).unwrap();
    let file = OpenOptions::new().write(true).open(&pending).unwrap();
    // Truncating zero length is insufficient on Linux: first expose a byte,
    // then truncate, so the regression actually releases reserved extents.
    file.set_len(1).unwrap();
    file.set_len(0).unwrap();
    assert_eq!(file.allocated_size().unwrap(), 0);
    assert!(matches!(
        resource_reservation::commit(&active, b"{}"),
        Err(ConsequenceError::ResourceCapacityNotPrepared)
    ));
    assert!(!active.exists());
    assert_eq!(fs::read(&pending).unwrap(), b"");
    resource_reservation::prepare(&active).unwrap();
    OpenOptions::new()
        .write(true)
        .open(&pending)
        .unwrap()
        .write_all(b"partial")
        .unwrap();
    assert!(matches!(
        resource_reservation::commit(&active, b"{}"),
        Err(ConsequenceError::ResourceCapacityNotPrepared)
    ));
    assert_eq!(&fs::read(&pending).unwrap()[..7], b"partial");
    resource_reservation::prepare(&active).unwrap();
    assert_eq!(
        fs::metadata(&pending).unwrap().len(),
        PQ_REGISTER_RECORD_MAX_BYTES as u64
    );
    assert_eq!(
        File::open(&pending).unwrap().allocated_size().unwrap(),
        PQ_REGISTER_RECORD_MAX_BYTES as u64
    );
    resource_reservation::commit(&active, b"{}").unwrap();
    let stored = fs::read(&active).unwrap();
    assert_eq!(&stored[..2], b"{}");
    assert!(stored[2..].iter().all(|byte| *byte == b' '));
}

#[cfg(target_os = "linux")]
#[test]
fn receipt_reserved_exchange_preserves_capacity_and_payload_when_length_shrinks() {
    use std::os::unix::fs::MetadataExt;
    let temp = TempDir::new().unwrap();
    let active = temp.path().join("receipt.json");
    let spare = resource_reservation::staged(&active).unwrap();
    let original = br#"{"value":"a longer original value"}"#;
    fs::write(&active, original).unwrap();
    receipt_reservation::prepare(&active, 16384).unwrap();
    let first = fs::metadata(&active).unwrap().ino();
    let second = fs::metadata(&spare).unwrap().ino();
    assert_ne!(first, second);
    for (index, bytes) in [
        br#"{"value":1}"#.as_slice(),
        br#"{"value":2}"#,
        br#"{"value":3}"#,
    ]
    .into_iter()
    .enumerate()
    {
        receipt_reservation::commit(&active, bytes, 16384).unwrap();
        assert_eq!(
            fs::metadata(&active).unwrap().ino(),
            if index % 2 == 0 { second } else { first }
        );
        assert_eq!(fs::metadata(&active).unwrap().len(), 20480);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &receipt_reservation::read(&active).unwrap().0
            )
            .unwrap(),
            serde_json::from_slice::<serde_json::Value>(bytes).unwrap()
        );
        for path in [&active, &spare] {
            assert_eq!(File::open(path).unwrap().allocated_size().unwrap(), 20480);
        }
    }
    let before = fs::read(&active).unwrap();
    OpenOptions::new()
        .write(true)
        .open(&spare)
        .unwrap()
        .set_len(0)
        .unwrap();
    assert!(matches!(
        receipt_reservation::commit(&active, b"{}", 16384),
        Err(ConsequenceError::ResourceCapacityNotPrepared)
    ));
    assert_eq!(fs::read(&active).unwrap(), before);
}

#[cfg(target_os = "linux")]
#[test]
fn online_receipt_lost_reservation_refuses_before_claim_and_requires_reopen() {
    let temp = TempDir::new().unwrap();
    let endpoint = MldsaScheme::new(SecurityLevel::Level2)
        .generate_keypair()
        .unwrap();
    let profile = DurablePqAtomicRegisterV1::profile_for(&endpoint).unwrap();
    let mut manifest = manifest("reserved-receipt", profile);
    manifest.authorization_mode = EffectAuthorizationModeV1::OnlineQueryUnanimityV0;
    manifest.online_authorization_policy_root = Some([19; 32]);
    manifest.online_authorization_predecessor = Some([77; 32]);
    manifest.online_authorization_authority_mode =
        Some(ioi_types::app::QuvAuthorityModeV0::Unowned);
    manifest.idempotency_key = manifest.query_unanimity_idempotency_key().unwrap();
    let mut resource =
        DurablePqAtomicRegisterV1::open(temp.path().join("resource"), endpoint).unwrap();
    let store_root = temp.path().join("consequence");
    let mut store = ConsequenceStore::open(&store_root).unwrap();
    let authorized = authorize(&mut store, manifest.clone());
    resource.prepare(&manifest).unwrap();
    store.prepare_online_storage(&manifest.effect_id).unwrap();
    let active = store.receipt_path(&manifest.effect_id);
    let spare = resource_reservation::staged(&active).unwrap();
    let bytes = fs::read(&active).unwrap();
    OpenOptions::new()
        .write(true)
        .open(&spare)
        .unwrap()
        .set_len(0)
        .unwrap();
    let binding = store
        .online_authorization_requirement(&manifest.effect_id)
        .unwrap();
    assert!(matches!(
        store.execute_with_online_authorization(
            &manifest.effect_id,
            &mut resource,
            TestOnlineAuthorization(binding, Instant::now() + Duration::from_secs(5)),
            10
        ),
        Err(ConsequenceError::ResourceCapacityNotPrepared)
    ));
    assert_eq!(fs::read(&active).unwrap(), bytes);
    assert!(resource
        .lookup(&manifest.resource_id, &manifest.idempotency_key)
        .unwrap()
        .is_none());
    assert!(matches!(
        store.load(&manifest.effect_id),
        Err(ConsequenceError::ResourceRequiresReopen)
    ));
    drop(store);
    let mut store = ConsequenceStore::open(&store_root).unwrap();
    assert_eq!(store.load(&manifest.effect_id).unwrap(), authorized);
    store.prepare_online_storage(&manifest.effect_id).unwrap();
    let binding = store
        .online_authorization_requirement(&manifest.effect_id)
        .unwrap();
    let executed = store
        .execute_with_online_authorization(
            &manifest.effect_id,
            &mut resource,
            TestOnlineAuthorization(binding, Instant::now() + Duration::from_secs(5)),
            10,
        )
        .unwrap();
    assert!(matches!(
        executed.state,
        ConsequenceStateV1::Executed { .. }
    ));
    let spare_bytes = fs::read(&spare).unwrap();
    fs::write(&active, b"corrupt authoritative receipt").unwrap();
    assert!(store.prepare_online_storage(&manifest.effect_id).is_err());
    assert_eq!(fs::read(&active).unwrap(), b"corrupt authoritative receipt");
    assert_eq!(fs::read(&spare).unwrap(), spare_bytes);
}

#[test]
fn checked_preparation_refuses_before_storage_and_keeps_terminal_readmission_non_authorizing() {
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    fn ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(Noop));
        let mut context = Context::from_waker(&waker);
        match std::pin::pin!(future).as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test preflight must complete synchronously"),
        }
    }
    let temp = TempDir::new().unwrap();
    let endpoint = MldsaScheme::new(SecurityLevel::Level2)
        .generate_keypair()
        .unwrap();
    let profile = DurablePqAtomicRegisterV1::profile_for(&endpoint).unwrap();
    let mut manifest = manifest("checked-preparation", profile);
    manifest.authorization_mode = EffectAuthorizationModeV1::OnlineQueryUnanimityV0;
    manifest.online_authorization_policy_root = Some([19; 32]);
    manifest.online_authorization_predecessor = Some([77; 32]);
    manifest.online_authorization_authority_mode =
        Some(ioi_types::app::QuvAuthorityModeV0::Unowned);
    manifest.idempotency_key = manifest.query_unanimity_idempotency_key().unwrap();
    let verified = verified_for(&manifest.resource_profile);
    let authorization = accepted_for(&manifest, &verified);
    let mut store = ConsequenceStore::open(temp.path().join("consequence")).unwrap();
    let binding = || OnlineEffectAuthorizationBindingV1::from_manifest(&manifest).unwrap();
    let mut wrong = binding();
    wrong.predecessor[0] ^= 1;
    assert!(matches!(
        ready(store.prepare_online_effect_checked(
            manifest.clone(),
            &verified,
            &authorization,
            10,
            wrong,
            std::future::ready(Ok(()))
        )),
        Err(ConsequenceError::InvalidOnlineAuthorization)
    ));
    assert!(!store.contains(&manifest.effect_id));
    assert!(matches!(
        ready(store.prepare_online_effect_checked(
            manifest.clone(),
            &verified,
            &authorization,
            10,
            binding(),
            std::future::ready(Err(ConsequenceError::Invalid(
                "rooted candidate rejected".into()
            )))
        )),
        Err(ConsequenceError::Invalid(_))
    ));
    assert_eq!(
        fs::read_dir(temp.path().join("consequence/effects"))
            .unwrap()
            .count(),
        0
    );
    assert!(ready(store.prepare_online_effect_checked(
        manifest.clone(),
        &verified,
        &authorization,
        10,
        binding(),
        std::future::ready(Ok(()))
    ))
    .unwrap());
    let mut resource =
        DurablePqAtomicRegisterV1::open(temp.path().join("resource"), endpoint).unwrap();
    resource.prepare(&manifest).unwrap();
    // Successful preparation still cannot execute without this executor's own
    // separately supplied live continuation.
    assert!(matches!(
        store.execute(&manifest.effect_id, &mut resource),
        Err(ConsequenceError::OnlineAuthorizationRequired)
    ));
    assert!(resource
        .lookup(&manifest.resource_id, &manifest.idempotency_key)
        .unwrap()
        .is_none());
    store.arm_crash(ConsequenceCrashPoint::AfterClaimed);
    assert!(matches!(
        store.execute_with_online_authorization(
            &manifest.effect_id,
            &mut resource,
            TestOnlineAuthorization(binding(), Instant::now() + Duration::from_secs(5)),
            10
        ),
        Err(ConsequenceError::InjectedCrash(
            ConsequenceCrashPoint::AfterClaimed
        ))
    ));
    let claimed = fs::read(store.receipt_path(&manifest.effect_id)).unwrap();
    assert!(matches!(
        ready(store.prepare_online_effect_checked(
            manifest.clone(),
            &verified,
            &authorization,
            10,
            binding(),
            std::future::ready(Err(ConsequenceError::Invalid(
                "claimed retry preflight rejected".into()
            )))
        )),
        Err(ConsequenceError::Invalid(_))
    ));
    assert_eq!(
        fs::read(store.receipt_path(&manifest.effect_id)).unwrap(),
        claimed
    );
    assert!(resource
        .lookup(&manifest.resource_id, &manifest.idempotency_key)
        .unwrap()
        .is_none());
    let receipt = store
        .execute_with_online_authorization(
            &manifest.effect_id,
            &mut resource,
            TestOnlineAuthorization(binding(), Instant::now() + Duration::from_secs(5)),
            10,
        )
        .unwrap();
    assert!(matches!(receipt.state, ConsequenceStateV1::Executed { .. }));
    let never_poll = std::future::poll_fn(|_| -> Poll<Result<(), ConsequenceError>> {
        panic!("terminal readmission must not require a new candidate preflight")
    });
    assert!(!ready(store.prepare_online_effect_checked(
        manifest.clone(),
        &verified,
        &authorization,
        999,
        binding(),
        never_poll
    ))
    .unwrap());
    assert!(store
        .online_retry_result(&manifest.effect_id, &mut resource)
        .unwrap()
        .is_some());
    let before = fs::read(store.receipt_path(&manifest.effect_id)).unwrap();
    let mut forged = accepted_for(&manifest, &verified);
    forged.manifest_root = [91; 32];
    assert!(matches!(
        ready(store.prepare_online_effect_checked(
            manifest.clone(),
            &verified,
            &forged,
            999,
            binding(),
            std::future::ready(Ok(()))
        )),
        Err(ConsequenceError::ReplayConflict)
    ));
    assert_eq!(
        fs::read(store.receipt_path(&manifest.effect_id)).unwrap(),
        before
    );
}

#[cfg(unix)]
#[test]
fn receipt_admission_preserves_invalid_active_and_staging_aliases() {
    use std::os::unix::fs::symlink;
    let endpoint = MldsaScheme::new(SecurityLevel::Level2)
        .generate_keypair()
        .unwrap();
    for case in ["active-dangling", "staging-symlink", "staging-hardlink"] {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("consequence");
        let mut store = ConsequenceStore::open(&root).unwrap();
        let mut manifest = manifest(
            case,
            DurablePqAtomicRegisterV1::profile_for(&endpoint).unwrap(),
        );
        manifest.authorization_mode = EffectAuthorizationModeV1::OnlineQueryUnanimityV0;
        manifest.online_authorization_policy_root = Some([19; 32]);
        manifest.online_authorization_predecessor = Some([77; 32]);
        manifest.online_authorization_authority_mode =
            Some(ioi_types::app::QuvAuthorityModeV0::Unowned);
        manifest.idempotency_key = manifest.query_unanimity_idempotency_key().unwrap();
        let verified = verified_for(&manifest.resource_profile);
        let authorization = accepted_for(&manifest, &verified);
        let active = store.receipt_path(&manifest.effect_id);
        let spare = resource_reservation::staged(&active).unwrap();
        let target = temp.path().join("fixture-target");
        let alias = if case == "active-dangling" {
            symlink(&target, &active).unwrap();
            active.clone()
        } else {
            fs::write(&target, b"preserve this fixture").unwrap();
            if case == "staging-symlink" {
                symlink(&target, &spare).unwrap();
            } else {
                fs::hard_link(&target, &spare).unwrap();
            }
            spare.clone()
        };
        let result = store.prepare_online_effect(manifest.clone(), &verified, &authorization, 10);
        assert!(
            matches!(
                result,
                Err(ConsequenceError::Io(_)) | Err(ConsequenceError::CorruptReceipt)
            ),
            "{case}: {result:?}"
        );
        if case == "active-dangling" {
            assert!(store.contains(&manifest.effect_id));
            assert!(fs::symlink_metadata(&active)
                .unwrap()
                .file_type()
                .is_symlink());
            assert!(!target.exists());
        } else {
            assert_eq!(fs::read(&target).unwrap(), b"preserve this fixture");
            assert!(fs::symlink_metadata(&alias).is_ok());
            assert!(!active.exists());
        }
        drop(store);
        // Removing the test's invalid alias and reopening restores ordinary
        // preparation; refusal must not invent an authoritative receipt.
        fs::remove_file(alias).unwrap();
        let mut reopened = ConsequenceStore::open(&root).unwrap();
        let receipt = reopened
            .prepare_online_effect(manifest.clone(), &verified, &authorization, 10)
            .unwrap();
        assert_eq!(reopened.load(&manifest.effect_id).unwrap(), receipt);
    }
}
