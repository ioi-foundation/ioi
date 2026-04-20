use super::*;
use crate::app::{
    ActiveKeyRecord, CanonicalOrderingCollapse, CanonicalSealingCollapse, QuorumCertificate,
    SignatureSuite, ValidatorV1,
};

fn build_validator_set(ids: &[[u8; 32]]) -> ValidatorSetV1 {
    ValidatorSetV1 {
        effective_from_height: 1,
        total_weight: ids.len() as u128,
        validators: ids
            .iter()
            .map(|id| ValidatorV1 {
                account_id: AccountId(*id),
                weight: 1,
                consensus_key: ActiveKeyRecord {
                    suite: SignatureSuite::ED25519,
                    public_key_hash: *id,
                    since_height: 1,
                },
            })
            .collect(),
    }
}

#[test]
fn derives_recovery_witness_certificate_from_signed_binding() {
    let statement = GuardianWitnessStatement {
        producer_account_id: AccountId([1u8; 32]),
        height: 33,
        view: 5,
        guardian_manifest_hash: [2u8; 32],
        guardian_decision_hash: [3u8; 32],
        guardian_counter: 7,
        guardian_trace_hash: [4u8; 32],
        guardian_measurement_root: [5u8; 32],
        guardian_checkpoint_root: [6u8; 32],
        recovery_binding: Some(GuardianWitnessRecoveryBinding {
            recovery_capsule_hash: [7u8; 32],
            share_commitment_hash: [8u8; 32],
        }),
    };
    let certificate = GuardianWitnessCertificate {
        manifest_hash: [9u8; 32],
        stratum_id: "stratum-a".into(),
        epoch: 11,
        statement_hash: [10u8; 32],
        signers_bitfield: vec![0b0000_0011],
        aggregated_signature: vec![0xAA],
        reassignment_depth: 0,
        recovery_binding: statement.recovery_binding.clone(),
        log_checkpoint: None,
    };

    let derived = derive_recovery_witness_certificate(&statement, &certificate)
        .expect("recovery witness certificate derivation")
        .expect("recovery witness certificate");

    assert_eq!(derived.height, statement.height);
    assert_eq!(derived.epoch, certificate.epoch);
    assert_eq!(derived.witness_manifest_hash, certificate.manifest_hash);
    assert_eq!(
        derived.recovery_capsule_hash,
        statement
            .recovery_binding
            .as_ref()
            .expect("binding")
            .recovery_capsule_hash
    );
    assert_eq!(
        derived.share_commitment_hash,
        statement
            .recovery_binding
            .as_ref()
            .expect("binding")
            .share_commitment_hash
    );
}

#[test]
fn rejects_recovery_witness_certificate_derivation_on_binding_mismatch() {
    let statement = GuardianWitnessStatement {
        producer_account_id: AccountId([1u8; 32]),
        height: 33,
        view: 5,
        guardian_manifest_hash: [2u8; 32],
        guardian_decision_hash: [3u8; 32],
        guardian_counter: 7,
        guardian_trace_hash: [4u8; 32],
        guardian_measurement_root: [5u8; 32],
        guardian_checkpoint_root: [6u8; 32],
        recovery_binding: Some(GuardianWitnessRecoveryBinding {
            recovery_capsule_hash: [7u8; 32],
            share_commitment_hash: [8u8; 32],
        }),
    };
    let certificate = GuardianWitnessCertificate {
        manifest_hash: [9u8; 32],
        stratum_id: "stratum-a".into(),
        epoch: 11,
        statement_hash: [10u8; 32],
        signers_bitfield: vec![0b0000_0011],
        aggregated_signature: vec![0xAA],
        reassignment_depth: 0,
        recovery_binding: Some(GuardianWitnessRecoveryBinding {
            recovery_capsule_hash: [17u8; 32],
            share_commitment_hash: [18u8; 32],
        }),
        log_checkpoint: None,
    };

    let err = derive_recovery_witness_certificate(&statement, &certificate)
        .expect_err("mismatched binding must fail");
    assert!(err.contains("must match"));
}

#[test]
fn derives_recovery_witness_certificate_from_header_guardian_certificate_pair() {
    let witness_certificate = GuardianWitnessCertificate {
        manifest_hash: [9u8; 32],
        stratum_id: "stratum-a".into(),
        epoch: 11,
        statement_hash: [10u8; 32],
        signers_bitfield: vec![0b0000_0011],
        aggregated_signature: vec![0xAA],
        reassignment_depth: 0,
        recovery_binding: Some(GuardianWitnessRecoveryBinding {
            recovery_capsule_hash: [17u8; 32],
            share_commitment_hash: [18u8; 32],
        }),
        log_checkpoint: Some(GuardianLogCheckpoint {
            log_id: "guardian-log".into(),
            tree_size: 3,
            root_hash: [19u8; 32],
            timestamp_ms: 1_700_000_000_000,
            signature: vec![0xBB],
            proof: None,
        }),
    };
    let header = BlockHeader {
        height: 33,
        view: 5,
        parent_hash: [1u8; 32],
        parent_state_root: crate::app::StateRoot(vec![2u8; 32]),
        state_root: crate::app::StateRoot(vec![3u8; 32]),
        transactions_root: vec![4u8; 32],
        timestamp: 1_700_000_000,
        timestamp_ms: 1_700_000_000_000,
        gas_used: 0,
        validator_set: vec![vec![5u8; 32]],
        producer_account_id: AccountId([6u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [7u8; 32],
        producer_pubkey: vec![8u8; 32],
        oracle_counter: 9,
        oracle_trace_hash: [10u8; 32],
        guardian_certificate: Some(GuardianQuorumCertificate {
            manifest_hash: [11u8; 32],
            epoch: 11,
            decision_hash: [12u8; 32],
            counter: 13,
            trace_hash: [14u8; 32],
            measurement_root: [15u8; 32],
            signers_bitfield: vec![0b0000_0011],
            aggregated_signature: vec![0xCC],
            log_checkpoint: Some(GuardianLogCheckpoint {
                log_id: "guardian-log".into(),
                tree_size: 7,
                root_hash: [16u8; 32],
                timestamp_ms: 1_700_000_000_500,
                signature: vec![0xDD],
                proof: None,
            }),
            experimental_witness_certificate: Some(witness_certificate.clone()),
        }),
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
        parent_qc: QuorumCertificate {
            height: 32,
            view: 4,
            block_hash: [20u8; 32],
            signatures: Vec::new(),
            aggregated_signature: vec![0xEE],
            signers_bitfield: vec![1],
        },
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        signature: vec![0xFF],
    };

    let guardian_certificate = header
        .guardian_certificate
        .as_ref()
        .expect("guardian certificate");
    let statement = guardian_witness_statement_for_header(&header, guardian_certificate);
    assert_eq!(
        statement.recovery_binding,
        witness_certificate.recovery_binding.clone()
    );
    assert_eq!(statement.guardian_checkpoint_root, [16u8; 32]);

    let derived = derive_recovery_witness_certificate_for_header(&header, guardian_certificate)
        .expect("header-bound recovery witness certificate derivation")
        .expect("recovery witness certificate");
    assert_eq!(derived.height, header.height);
    assert_eq!(derived.epoch, witness_certificate.epoch);
    assert_eq!(
        derived.witness_manifest_hash,
        witness_certificate.manifest_hash
    );
    assert_eq!(derived.recovery_capsule_hash, [17u8; 32]);
    assert_eq!(derived.share_commitment_hash, [18u8; 32]);
}

#[test]
fn derives_unique_equal_authority_observers_and_excludes_producer() {
    let validator_set =
        build_validator_set(&[[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]]);
    let assignments = derive_asymptote_observer_assignments(
        &GuardianWitnessEpochSeed {
            epoch: 7,
            seed: [9u8; 32],
            checkpoint_interval_blocks: 1,
            max_reassignment_depth: 0,
        },
        &validator_set,
        AccountId([1u8; 32]),
        11,
        2,
        2,
        2,
    )
    .unwrap();

    assert_eq!(assignments.len(), 4);
    let unique = assignments
        .iter()
        .map(|assignment| assignment.observer_account_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), assignments.len());
    assert!(assignments
        .iter()
        .all(|assignment| assignment.observer_account_id != AccountId([1u8; 32])));
    assert_eq!(
        assignments
            .iter()
            .map(|assignment| assignment.round)
            .collect::<Vec<_>>(),
        vec![0, 0, 1, 1]
    );
}

#[test]
fn derives_budgeted_equal_authority_observer_plan_entries() {
    let validator_set =
        build_validator_set(&[[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]]);
    let manifests = BTreeMap::from([
        (
            AccountId([2u8; 32]),
            GuardianCommitteeManifest {
                validator_account_id: AccountId([2u8; 32]),
                epoch: 7,
                threshold: 1,
                members: vec![GuardianCommitteeMember {
                    member_id: "m2".into(),
                    provider: Some("aws".into()),
                    region: Some("use1".into()),
                    host_class: Some("c6i".into()),
                    key_authority_kind: Some(KeyAuthorityKind::CloudKms),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ),
        (
            AccountId([3u8; 32]),
            GuardianCommitteeManifest {
                validator_account_id: AccountId([3u8; 32]),
                epoch: 7,
                threshold: 1,
                members: vec![GuardianCommitteeMember {
                    member_id: "m3".into(),
                    provider: Some("gcp".into()),
                    region: Some("usw1".into()),
                    host_class: Some("n2".into()),
                    key_authority_kind: Some(KeyAuthorityKind::CloudKms),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ),
        (
            AccountId([4u8; 32]),
            GuardianCommitteeManifest {
                validator_account_id: AccountId([4u8; 32]),
                epoch: 7,
                threshold: 1,
                members: vec![GuardianCommitteeMember {
                    member_id: "m4".into(),
                    provider: Some("oci".into()),
                    region: Some("use2".into()),
                    host_class: Some("m7g".into()),
                    key_authority_kind: Some(KeyAuthorityKind::Tpm2),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ),
        (
            AccountId([5u8; 32]),
            GuardianCommitteeManifest {
                validator_account_id: AccountId([5u8; 32]),
                epoch: 7,
                threshold: 1,
                members: vec![GuardianCommitteeMember {
                    member_id: "m5".into(),
                    provider: Some("azure".into()),
                    region: Some("eus".into()),
                    host_class: Some("d4".into()),
                    key_authority_kind: Some(KeyAuthorityKind::Pkcs11),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ),
    ]);
    let plan = derive_asymptote_observer_plan_entries(
        &GuardianWitnessEpochSeed {
            epoch: 7,
            seed: [9u8; 32],
            checkpoint_interval_blocks: 1,
            max_reassignment_depth: 0,
        },
        &validator_set,
        &manifests,
        AccountId([1u8; 32]),
        11,
        2,
        2,
        2,
        &AsymptoteObserverCorrelationBudget {
            max_per_provider: 1,
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(plan.len(), 4);
    let providers = plan
        .iter()
        .map(|entry| {
            entry.manifest.members[0]
                .provider
                .as_ref()
                .cloned()
                .unwrap_or_default()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(providers.len(), 4);
}

#[test]
fn http_egress_seal_object_verifies() {
    let canonical_collapse_object = CanonicalCollapseObject {
        height: 41,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering: CanonicalOrderingCollapse {
            height: 41,
            kind: CanonicalCollapseKind::Close,
            bulletin_commitment_hash: [21u8; 32],
            bulletin_availability_certificate_hash: [22u8; 32],
            bulletin_retrievability_profile_hash: [0u8; 32],
            bulletin_shard_manifest_hash: [0u8; 32],
            bulletin_custody_receipt_hash: [0u8; 32],
            bulletin_close_hash: [23u8; 32],
            canonical_order_certificate_hash: [24u8; 32],
        },
        sealing: Some(CanonicalSealingCollapse {
            epoch: 7,
            height: 41,
            view: 2,
            kind: CanonicalCollapseKind::Close,
            finality_tier: FinalityTier::SealedFinal,
            collapse_state: CollapseState::SealedFinal,
            transcripts_root: [0u8; 32],
            challenges_root: [0u8; 32],
            resolution_hash: [0u8; 32],
        }),
        transactions_root_hash: [31u8; 32],
        resulting_state_root_hash: [32u8; 32],
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
    };
    let sealed_finality_proof = SealedFinalityProof {
        epoch: 7,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: [1u8; 32],
        guardian_decision_hash: [2u8; 32],
        guardian_counter: 9,
        guardian_trace_hash: [3u8; 32],
        guardian_measurement_root: [4u8; 32],
        policy_hash: [5u8; 32],
        ..Default::default()
    };
    let seal_object = build_http_egress_seal_object(
        [6u8; 32],
        "api.example.com",
        "POST",
        "/v1/commit",
        [7u8; 32],
        &sealed_finality_proof,
        &canonical_collapse_object,
    )
    .unwrap();
    verify_seal_object(&seal_object).unwrap();
    assert_eq!(seal_object.intent.target, "api.example.com");
    assert_eq!(seal_object.intent.action, "POST");
}

#[test]
fn seal_object_rejects_mutated_proof_bytes() {
    let canonical_collapse_object = CanonicalCollapseObject {
        height: 52,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering: CanonicalOrderingCollapse {
            height: 52,
            kind: CanonicalCollapseKind::Close,
            bulletin_commitment_hash: [33u8; 32],
            bulletin_availability_certificate_hash: [34u8; 32],
            bulletin_retrievability_profile_hash: [0u8; 32],
            bulletin_shard_manifest_hash: [0u8; 32],
            bulletin_custody_receipt_hash: [0u8; 32],
            bulletin_close_hash: [35u8; 32],
            canonical_order_certificate_hash: [36u8; 32],
        },
        sealing: Some(CanonicalSealingCollapse {
            epoch: 11,
            height: 52,
            view: 3,
            kind: CanonicalCollapseKind::Close,
            finality_tier: FinalityTier::SealedFinal,
            collapse_state: CollapseState::SealedFinal,
            transcripts_root: [0u8; 32],
            challenges_root: [0u8; 32],
            resolution_hash: [0u8; 32],
        }),
        transactions_root_hash: [41u8; 32],
        resulting_state_root_hash: [42u8; 32],
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
    };
    let sealed_finality_proof = SealedFinalityProof {
        epoch: 11,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: [8u8; 32],
        guardian_decision_hash: [9u8; 32],
        guardian_counter: 12,
        guardian_trace_hash: [10u8; 32],
        guardian_measurement_root: [11u8; 32],
        policy_hash: [12u8; 32],
        ..Default::default()
    };
    let mut seal_object = build_http_egress_seal_object(
        [13u8; 32],
        "api.example.com",
        "POST",
        "/v1/commit",
        [14u8; 32],
        &sealed_finality_proof,
        &canonical_collapse_object,
    )
    .unwrap();
    seal_object.proof.proof_bytes[0] ^= 0x55;
    let err = verify_seal_object(&seal_object).unwrap_err();
    assert!(err.contains("hash-binding proof bytes are invalid"));
}
