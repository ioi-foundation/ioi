use super::*;
use ioi_types::app::consensus::{
    guarantee_vector_of, CertificateOnlyGuaranteeVerifierV1, CertificateProfile,
    ExternalizationModeV1, GuaranteeRank, GuaranteeRequirementsV1,
};
use ioi_types::app::{EffectManifestVersionV1, EffectResourceKeyV1, ExternalResourceContractV1};
use std::collections::BTreeMap;
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
    mode: InvocationMode,
    ambiguous_lookup: bool,
    forced_conflict: Option<ExternalResourceRecordV1>,
}

impl AtomicRegister {
    fn new(profile: ExternalResourceProfileV1) -> Self {
        Self {
            profile,
            records: BTreeMap::new(),
            invocations: 0,
            mutations: 0,
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
                ConsequenceCrashPoint::AfterLookup | ConsequenceCrashPoint::AfterReconciled
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
