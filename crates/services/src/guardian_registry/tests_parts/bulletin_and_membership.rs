#[test]
fn archived_recovered_history_retention_receipts_persist_by_checkpoint_hash() {
    let registry = production_registry();
    let mut state = MockState::default();
    let profile = seed_active_archived_recovered_history_profile(&mut state);
    let validator_sets = validator_sets(&[(18, 1), (145, 1), (19, 1)]);
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets).unwrap(),
        )
        .unwrap();
    let validator_sets = read_validator_sets(&state.get(VALIDATOR_SET_KEY).unwrap().unwrap())
        .expect("decode persisted validator set");

    let (_, _, _, recovered) = sample_recovered_publication_bundle_fixture(208, 0xB1);
    let segment = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered),
        None,
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("segment");
    let page = sample_archived_recovered_restart_page(&segment, [0x61; 32], [0x62; 32], 0x63);
    let checkpoint = sample_archived_recovered_history_checkpoint(&segment, &page, None);
    let checkpoint_hash =
        canonical_archived_recovered_history_checkpoint_hash(&checkpoint).expect("hash");
    let receipt =
        sample_archived_recovered_history_retention_receipt(&checkpoint, &profile, &validator_sets);

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_segment@v1",
            &codec::to_bytes_canonical(&segment).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_restart_page@v1",
            &codec::to_bytes_canonical(&page).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_checkpoint@v1",
            &codec::to_bytes_canonical(&checkpoint).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_retention_receipt@v1",
            &codec::to_bytes_canonical(&receipt).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    assert_eq!(
        GuardianRegistry::load_archived_recovered_history_retention_receipt(
            &state,
            &checkpoint_hash,
        )
        .unwrap(),
        Some(receipt.clone())
    );
    assert!(state
        .get(&aft_archived_recovered_history_retention_receipt_key(
            &checkpoint_hash,
        ))
        .unwrap()
        .is_some());
    assert_ne!(
        canonical_archived_recovered_history_retention_receipt_hash(&receipt)
            .expect("receipt hash"),
        [0u8; 32]
    );
}

#[test]
fn aft_recovered_state_surface_loads_ordinary_historical_retrievability_from_canonical_tip() {
    let registry = production_registry();
    let mut state = MockState::default();
    let profile = seed_active_archived_recovered_history_profile(&mut state);
    let activation = sample_bootstrap_archived_recovered_history_profile_activation(&profile);
    let validator_sets = validator_sets(&[(21, 1), (22, 1), (23, 1)]);
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets).unwrap(),
        )
        .unwrap();
    let validator_sets = read_validator_sets(&state.get(VALIDATOR_SET_KEY).unwrap().unwrap())
        .expect("decode persisted validator set");

    let (_, _, _, recovered) = sample_recovered_publication_bundle_fixture(144, 0xC1);
    let segment = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered),
        None,
        None,
        &profile,
        &activation,
    )
    .expect("segment");
    let page = sample_archived_recovered_restart_page(&segment, [0x71; 32], [0x72; 32], 0x73);
    let checkpoint = sample_archived_recovered_history_checkpoint(&segment, &page, None);
    let checkpoint_hash =
        canonical_archived_recovered_history_checkpoint_hash(&checkpoint).expect("hash");
    let receipt =
        sample_archived_recovered_history_retention_receipt(&checkpoint, &profile, &validator_sets);
    let receipt_hash =
        canonical_archived_recovered_history_retention_receipt_hash(&receipt).expect("hash");
    let activation_hash = canonical_archived_recovered_history_profile_activation_hash(&activation)
        .expect("activation hash");

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_segment@v1",
            &codec::to_bytes_canonical(&segment).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_restart_page@v1",
            &codec::to_bytes_canonical(&page).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_checkpoint@v1",
            &codec::to_bytes_canonical(&checkpoint).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_retention_receipt@v1",
            &codec::to_bytes_canonical(&receipt).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let mut collapse = CanonicalCollapseObject {
        height: checkpoint.covered_end_height,
        ..Default::default()
    };
    set_canonical_collapse_archived_recovered_history_anchor(
        &mut collapse,
        checkpoint_hash,
        activation_hash,
        receipt_hash,
    )
    .expect("set historical retrievability anchor");
    state
        .insert(
            &aft_canonical_collapse_object_key(collapse.height),
            &codec::to_bytes_canonical(&collapse).unwrap(),
        )
        .unwrap();

    let continuation = GuardianRegistry::load_aft_historical_retrievability_surface_for_height(
        &state,
        collapse.height,
    )
    .expect("load ordinary historical retrievability")
    .expect("historical retrievability present");
    assert_eq!(continuation.anchor.checkpoint_hash, checkpoint_hash);
    assert_eq!(continuation.anchor.profile_activation_hash, activation_hash);
    assert_eq!(continuation.anchor.retention_receipt_hash, receipt_hash);
    assert_eq!(continuation.checkpoint, checkpoint);
    assert_eq!(continuation.profile_activation, activation);
    assert_eq!(continuation.retention_receipt, receipt);
}

#[test]
fn publishing_conflicting_archived_recovered_history_retention_receipt_fails_closed() {
    let registry = production_registry();
    let mut state = MockState::default();
    let profile = seed_active_archived_recovered_history_profile(&mut state);
    let validator_sets = validator_sets(&[(7, 1), (11, 1), (12, 1)]);
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets).unwrap(),
        )
        .unwrap();
    let validator_sets = read_validator_sets(&state.get(VALIDATOR_SET_KEY).unwrap().unwrap())
        .expect("decode persisted validator set");

    let (_, _, _, recovered) = sample_recovered_publication_bundle_fixture(209, 0xB2);
    let segment = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered),
        None,
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("segment");
    let page = sample_archived_recovered_restart_page(&segment, [0x71; 32], [0x72; 32], 0x73);
    let checkpoint = sample_archived_recovered_history_checkpoint(&segment, &page, None);
    let receipt =
        sample_archived_recovered_history_retention_receipt(&checkpoint, &profile, &validator_sets);
    let conflicting_receipt = ArchivedRecoveredHistoryRetentionReceipt {
        retained_through_height: receipt.retained_through_height + 1,
        ..receipt.clone()
    };

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_segment@v1",
            &codec::to_bytes_canonical(&segment).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_restart_page@v1",
            &codec::to_bytes_canonical(&page).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_checkpoint@v1",
            &codec::to_bytes_canonical(&checkpoint).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_retention_receipt@v1",
            &codec::to_bytes_canonical(&receipt).unwrap(),
            ctx,
        ))
        .unwrap();
        let error = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_retention_receipt@v1",
            &codec::to_bytes_canonical(&conflicting_receipt).unwrap(),
            ctx,
        ))
        .expect_err("conflicting retention receipt must fail");
        let error_text = error.to_string();
        assert!(
                error_text.contains(
                    "conflicting aft archived recovered-history retention receipt already published for the same archived checkpoint"
                ) || error_text.contains(
                    "archived recovered-history retention receipt retained-through height"
                )
            );
    });

    let checkpoint_hash = canonical_archived_recovered_history_checkpoint_hash(&checkpoint)
        .expect("archived checkpoint hash");
    assert_eq!(
        GuardianRegistry::load_archived_recovered_history_retention_receipt(
            &state,
            &checkpoint_hash,
        )
        .unwrap(),
        Some(receipt)
    );
}

fn recovered_publication_frontier_header(
    payload: &ioi_types::app::RecoverableSlotPayloadV5,
) -> BlockHeader {
    BlockHeader {
        height: payload.height,
        view: payload.view,
        parent_hash: payload.parent_block_hash,
        parent_state_root: StateRoot(
            payload
                .canonical_order_certificate
                .resulting_state_root_hash
                .to_vec(),
        ),
        state_root: StateRoot(
            payload
                .canonical_order_certificate
                .resulting_state_root_hash
                .to_vec(),
        ),
        transactions_root: payload
            .canonical_order_certificate
            .ordered_transactions_root_hash
            .to_vec(),
        timestamp: payload
            .canonical_order_certificate
            .bulletin_commitment
            .cutoff_timestamp_ms
            / 1_000,
        timestamp_ms: payload
            .canonical_order_certificate
            .bulletin_commitment
            .cutoff_timestamp_ms,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: payload.producer_account_id,
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [0u8; 32],
        producer_pubkey: Vec::new(),
        signature: Vec::new(),
        oracle_counter: 0,
        oracle_trace_hash: [0u8; 32],
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: Some(payload.canonical_order_certificate.clone()),
        timeout_certificate: None,
    }
}

fn validator_sets(validators: &[(u8, u128)]) -> ValidatorSetsV1 {
    let mut entries = validators
        .iter()
        .map(|(account, weight)| validator(*account, *weight))
        .collect::<Vec<_>>();
    entries.sort_by_key(|validator| validator.account_id);
    ValidatorSetsV1 {
        current: ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: entries.iter().map(|validator| validator.weight).sum(),
            validators: entries,
        },
        next: None,
    }
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
    let restored: GuardianTransparencyLogDescriptor = codec::from_bytes_canonical(&stored).unwrap();
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
        asymptote_required_witness_strata: vec!["stratum-a".into()],
        asymptote_escalation_witness_strata: vec!["stratum-a".into()],
        asymptote_high_risk_effect_tier: ioi_types::app::FinalityTier::SealedFinal,
        apply_accountable_membership_updates: true,
    });
    let manifest = GuardianWitnessCommitteeManifest {
        committee_id: "witness-a".into(),
        stratum_id: "stratum-a".into(),
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
    let active_set: GuardianWitnessSet = codec::from_bytes_canonical(&active_set_bytes).unwrap();
    assert_eq!(active_set.epoch, 11);
    assert_eq!(active_set.manifest_hashes.len(), 1);
    assert_eq!(active_set.checkpoint_interval_blocks, 3);

    let seed_bytes = state
        .get(&guardian_registry_witness_seed_key(11))
        .expect("seed lookup")
        .expect("seed stored");
    let stored_seed: GuardianWitnessEpochSeed = codec::from_bytes_canonical(&seed_bytes).unwrap();
    assert_eq!(stored_seed.seed, [9u8; 32]);
    assert_eq!(stored_seed.max_reassignment_depth, 2);
}

#[test]
fn registering_effect_verifier_and_recording_sealed_effect_persists_both_keys() {
    let registry = production_registry();
    let verifier = EffectProofVerifierDescriptor {
        verifier_id: "aft-http-egress-hash-binding-v1".into(),
        effect_class: SealedEffectClass::HttpEgress,
        proof_system: EffectProofSystem::HashBindingV1,
        verifying_key_hash: [21u8; 32],
        enabled: true,
    };
    let record = SealedEffectRecord {
        nullifier: [22u8; 32],
        intent_hash: [23u8; 32],
        epoch: 7,
        effect_class: SealedEffectClass::HttpEgress,
        verifier_id: verifier.verifier_id.clone(),
        seal_hash: [24u8; 32],
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "register_effect_proof_verifier@v1",
            &codec::to_bytes_canonical(&verifier).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "record_sealed_effect@v1",
            &codec::to_bytes_canonical(&record).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let stored_verifier = state
        .get(&guardian_registry_effect_verifier_key(
            &verifier.verifier_id,
        ))
        .unwrap()
        .expect("effect verifier stored");
    let restored_verifier: EffectProofVerifierDescriptor =
        codec::from_bytes_canonical(&stored_verifier).unwrap();
    assert_eq!(restored_verifier, verifier);

    let nullifier_record = state
        .get(&guardian_registry_effect_nullifier_key(&record.nullifier))
        .unwrap()
        .expect("sealed effect nullifier record stored");
    let sealed_effect_record = state
        .get(&guardian_registry_sealed_effect_key(&record.intent_hash))
        .unwrap()
        .expect("sealed effect record stored");
    let restored_nullifier_record: SealedEffectRecord =
        codec::from_bytes_canonical(&nullifier_record).unwrap();
    let restored_effect_record: SealedEffectRecord =
        codec::from_bytes_canonical(&sealed_effect_record).unwrap();
    assert_eq!(restored_nullifier_record, record);
    assert_eq!(restored_effect_record, record);
}

#[test]
fn publishing_aft_canonical_order_artifact_bundle_persists_registry_state() {
    let registry = production_registry();
    let base_header = ioi_types::app::BlockHeader {
        height: 9,
        view: 2,
        parent_hash: [11u8; 32],
        parent_state_root: StateRoot(vec![1u8; 32]),
        state_root: StateRoot(vec![2u8; 32]),
        transactions_root: Vec::new(),
        timestamp: 1_760_000_111,
        timestamp_ms: 1_760_000_111_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([12u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [13u8; 32],
        producer_pubkey: Vec::new(),
        signature: Vec::new(),
        oracle_counter: 0,
        oracle_trace_hash: [0u8; 32],
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
    };
    let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([31u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_bulletin_commitment@v1".into(),
            params: vec![1],
        },
        signature_proof: SignatureProof::default(),
    }));
    let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([32u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
            params: vec![2],
        },
        signature_proof: SignatureProof::default(),
    }));

    let ordered_transactions =
        canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
    let tx_hashes: Vec<[u8; 32]> = ordered_transactions
        .iter()
        .map(|tx| tx.hash().unwrap())
        .collect();
    let mut header = base_header;
    header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
    let certificate =
        build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
            .unwrap();
    let bundle = canonical_order_publication_bundle_with_retrievability(
        &certificate,
        build_bulletin_surface_entries(header.height, &ordered_transactions).unwrap(),
    );

    let mut state = MockState::default();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_canonical_order_artifact_bundle@v1",
            &codec::to_bytes_canonical(&bundle).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let stored_bulletin = state
        .get(&aft_bulletin_commitment_key(header.height))
        .unwrap()
        .expect("bulletin stored");
    let restored_bulletin: BulletinCommitment =
        codec::from_bytes_canonical(&stored_bulletin).unwrap();
    assert_eq!(restored_bulletin, bundle.bulletin_commitment);

    let stored_entry = state
        .get(&aft_bulletin_entry_key(
            header.height,
            &bundle.bulletin_entries[0].tx_hash,
        ))
        .unwrap()
        .expect("bulletin entry stored");
    let restored_entry: BulletinSurfaceEntry = codec::from_bytes_canonical(&stored_entry).unwrap();
    assert_eq!(restored_entry, bundle.bulletin_entries[0]);

    let stored_availability = state
        .get(&aft_bulletin_availability_certificate_key(header.height))
        .unwrap()
        .expect("bulletin availability certificate stored");
    let restored_availability: BulletinAvailabilityCertificate =
        codec::from_bytes_canonical(&stored_availability).unwrap();
    assert_eq!(
        restored_availability,
        bundle.bulletin_availability_certificate
    );

    let stored_profile = state
        .get(&aft_bulletin_retrievability_profile_key(header.height))
        .unwrap()
        .expect("bulletin retrievability profile stored");
    let restored_profile: BulletinRetrievabilityProfile =
        codec::from_bytes_canonical(&stored_profile).unwrap();
    assert_eq!(restored_profile, bundle.bulletin_retrievability_profile);

    let stored_manifest = state
        .get(&aft_bulletin_shard_manifest_key(header.height))
        .unwrap()
        .expect("bulletin shard manifest stored");
    let restored_manifest: BulletinShardManifest =
        codec::from_bytes_canonical(&stored_manifest).unwrap();
    assert_eq!(restored_manifest, bundle.bulletin_shard_manifest);

    let stored_custody = state
        .get(&aft_bulletin_custody_receipt_key(header.height))
        .unwrap()
        .expect("bulletin custody receipt stored");
    let restored_custody: BulletinCustodyReceipt =
        codec::from_bytes_canonical(&stored_custody).unwrap();
    assert_eq!(restored_custody, bundle.bulletin_custody_receipt);

    let stored_certificate = state
        .get(&aft_order_certificate_key(header.height))
        .unwrap()
        .expect("order certificate stored");
    let restored_certificate: CanonicalOrderCertificate =
        codec::from_bytes_canonical(&stored_certificate).unwrap();
    assert_eq!(restored_certificate, certificate);

    let stored_close = state
        .get(&aft_canonical_bulletin_close_key(header.height))
        .unwrap()
        .expect("canonical bulletin close stored");
    let restored_close: CanonicalBulletinClose =
        codec::from_bytes_canonical(&stored_close).unwrap();
    let expected_close = verify_canonical_order_publication_bundle(&bundle).expect("verify bundle");
    assert_eq!(restored_close, expected_close);
    assert_eq!(
        restored_close.bulletin_retrievability_profile_hash,
        canonical_bulletin_retrievability_profile_hash(&bundle.bulletin_retrievability_profile)
            .unwrap()
    );
    assert_eq!(
        restored_close.bulletin_shard_manifest_hash,
        canonical_bulletin_shard_manifest_hash(&bundle.bulletin_shard_manifest).unwrap()
    );
    assert_eq!(
        restored_close.bulletin_custody_receipt_hash,
        canonical_bulletin_custody_receipt_hash(&bundle.bulletin_custody_receipt).unwrap()
    );
    assert_bulletin_reconstruction_certificate_present(
        &state,
        header.height,
        bundle.bulletin_entries.len() as u32,
    );

    assert!(state
        .get(&aft_canonical_order_abort_key(header.height))
        .unwrap()
        .is_none());
}

#[test]
fn extracting_published_bulletin_surface_returns_canonical_entries() {
    let registry = production_registry();
    let base_header = ioi_types::app::BlockHeader {
        height: 17,
        view: 3,
        parent_hash: [19u8; 32],
        parent_state_root: StateRoot(vec![1u8; 32]),
        state_root: StateRoot(vec![2u8; 32]),
        transactions_root: Vec::new(),
        timestamp: 1_760_000_123,
        timestamp_ms: 1_760_000_123_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([24u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [25u8; 32],
        producer_pubkey: Vec::new(),
        signature: Vec::new(),
        oracle_counter: 0,
        oracle_trace_hash: [0u8; 32],
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
    };
    let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([31u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_bulletin_commitment@v1".into(),
            params: vec![1],
        },
        signature_proof: SignatureProof::default(),
    }));
    let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([32u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
            params: vec![2],
        },
        signature_proof: SignatureProof::default(),
    }));

    let ordered_transactions =
        canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
    let tx_hashes: Vec<[u8; 32]> = ordered_transactions
        .iter()
        .map(|tx| tx.hash().unwrap())
        .collect();
    let mut header = base_header;
    header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();

    let certificate =
        build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
            .unwrap();
    let entries = build_bulletin_surface_entries(header.height, &ordered_transactions).unwrap();
    let bundle =
        canonical_order_publication_bundle_with_retrievability(&certificate, entries.clone());

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
        )
        .unwrap();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_canonical_order_artifact_bundle@v1",
            &codec::to_bytes_canonical(&bundle).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let extracted = GuardianRegistry::extract_published_bulletin_surface(&state, header.height)
        .unwrap()
        .expect("canonical bulletin surface extracted");
    assert_eq!(extracted, entries);
}

#[test]
fn extracting_published_bulletin_surface_requires_positive_reconstruction_certificate() {
    let registry = production_registry();
    let base_header = ioi_types::app::BlockHeader {
        height: 18,
        view: 4,
        parent_hash: [29u8; 32],
        parent_state_root: StateRoot(vec![1u8; 32]),
        state_root: StateRoot(vec![2u8; 32]),
        transactions_root: Vec::new(),
        timestamp: 1_760_000_223,
        timestamp_ms: 1_760_000_223_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([34u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [35u8; 32],
        producer_pubkey: Vec::new(),
        signature: Vec::new(),
        oracle_counter: 0,
        oracle_trace_hash: [0u8; 32],
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
    };
    let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([36u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_bulletin_commitment@v1".into(),
            params: vec![3],
        },
        signature_proof: SignatureProof::default(),
    }));
    let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([37u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
            params: vec![4],
        },
        signature_proof: SignatureProof::default(),
    }));

    let ordered_transactions =
        canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
    let tx_hashes: Vec<[u8; 32]> = ordered_transactions
        .iter()
        .map(|tx| tx.hash().unwrap())
        .collect();
    let mut header = base_header;
    header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();

    let certificate =
        build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
            .unwrap();
    let entries = build_bulletin_surface_entries(header.height, &ordered_transactions).unwrap();
    let bundle =
        canonical_order_publication_bundle_with_retrievability(&certificate, entries.clone());

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
        )
        .unwrap();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_canonical_order_artifact_bundle@v1",
            &codec::to_bytes_canonical(&bundle).unwrap(),
            ctx,
        ))
        .unwrap();
    });
    state
        .delete(&aft_bulletin_reconstruction_certificate_key(header.height))
        .unwrap();

    let error =
        GuardianRegistry::extract_published_bulletin_surface(&state, header.height).unwrap_err();
    assert!(error
        .to_string()
        .contains("positive bulletin reconstruction certificate"));
}

#[test]
fn publishing_aft_canonical_order_artifact_bundle_persists_extractable_close_surface() {
    let registry = production_registry();
    let base_header = ioi_types::app::BlockHeader {
        height: 27,
        view: 2,
        parent_hash: [11u8; 32],
        parent_state_root: StateRoot(vec![1u8; 32]),
        state_root: StateRoot(vec![2u8; 32]),
        transactions_root: Vec::new(),
        timestamp: 1_760_000_333,
        timestamp_ms: 1_760_000_333_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([21u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [22u8; 32],
        producer_pubkey: Vec::new(),
        signature: Vec::new(),
        oracle_counter: 0,
        oracle_trace_hash: [0u8; 32],
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
    };
    let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([31u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_bulletin_commitment@v1".into(),
            params: vec![1],
        },
        signature_proof: SignatureProof::default(),
    }));
    let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([32u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
            params: vec![2],
        },
        signature_proof: SignatureProof::default(),
    }));

    let ordered_transactions =
        canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
    let tx_hashes: Vec<[u8; 32]> = ordered_transactions
        .iter()
        .map(|tx| tx.hash().unwrap())
        .collect();
    let mut header = base_header;
    header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
    let certificate =
        build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
            .unwrap();
    let bundle = canonical_order_publication_bundle_with_retrievability(
        &certificate,
        build_bulletin_surface_entries(header.height, &ordered_transactions).unwrap(),
    );

    let mut state = MockState::default();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_canonical_order_artifact_bundle@v1",
            &codec::to_bytes_canonical(&bundle).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let extracted = GuardianRegistry::extract_published_bulletin_surface(&state, header.height)
        .unwrap()
        .expect("extractable close surface");
    assert_eq!(extracted, bundle.bulletin_entries);
    let required = GuardianRegistry::require_published_bulletin_surface(&state, header.height)
        .expect("strict extraction surface");
    assert_eq!(required, bundle.bulletin_entries);

    let stored_close = state
        .get(&aft_canonical_bulletin_close_key(header.height))
        .unwrap()
        .expect("canonical bulletin close stored");
    let restored_close: CanonicalBulletinClose =
        codec::from_bytes_canonical(&stored_close).unwrap();
    assert_eq!(
        restored_close,
        verified_canonical_bulletin_close_for_bundle(&bundle)
    );
}

#[test]
fn publishing_aft_order_certificate_legacy_method_is_rejected() {
    let registry = production_registry();
    let bulletin = BulletinCommitment {
        height: 41,
        cutoff_timestamp_ms: 1_760_000_444,
        bulletin_root: [71u8; 32],
        entry_count: 2,
    };
    let availability_certificate = BulletinAvailabilityCertificate {
        height: 41,
        bulletin_commitment_hash: ioi_types::app::canonical_bulletin_commitment_hash(&bulletin)
            .unwrap(),
        recoverability_root: [72u8; 32],
    };
    let certificate = CanonicalOrderCertificate {
        height: 41,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: availability_certificate.clone(),
        randomness_beacon: [73u8; 32],
        ordered_transactions_root_hash: [74u8; 32],
        resulting_state_root_hash: [75u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [76u8; 32],
            proof_bytes: vec![77u8; 32],
        },
        omission_proofs: Vec::new(),
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_bulletin_commitment@v1",
            &codec::to_bytes_canonical(&bulletin).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_bulletin_availability_certificate@v1",
            &codec::to_bytes_canonical(&availability_certificate).unwrap(),
            ctx,
        ))
        .unwrap();
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_order_certificate@v1",
            &codec::to_bytes_canonical(&certificate).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("publish_aft_order_certificate@v1 is retired"));
    });
}

#[test]
fn publishing_aft_canonical_order_abort_persists_registry_state() {
    let registry = production_registry();
    let abort = CanonicalOrderAbort {
        height: 44,
        reason: CanonicalOrderAbortReason::InvalidProofBinding,
        details: "proof-carried canonical-order certificate failed binding verification".into(),
        bulletin_commitment_hash: [101u8; 32],
        bulletin_availability_certificate_hash: [102u8; 32],
        bulletin_close_hash: [103u8; 32],
        canonical_order_certificate_hash: [104u8; 32],
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_canonical_order_abort@v1",
            &codec::to_bytes_canonical(&abort).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let stored_abort = state
        .get(&aft_canonical_order_abort_key(abort.height))
        .unwrap()
        .expect("canonical-order abort stored");
    let restored_abort: CanonicalOrderAbort = codec::from_bytes_canonical(&stored_abort).unwrap();
    assert_eq!(restored_abort, abort);
}

#[test]
fn publishing_aft_canonical_collapse_object_persists_registry_state() {
    let registry = production_registry();
    let base_header = ioi_types::app::BlockHeader {
        height: 2,
        view: 2,
        parent_hash: [121u8; 32],
        parent_state_root: StateRoot(vec![1u8; 32]),
        state_root: StateRoot(vec![2u8; 32]),
        transactions_root: Vec::new(),
        timestamp: 1_760_000_888,
        timestamp_ms: 1_760_000_888_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([122u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [123u8; 32],
        producer_pubkey: Vec::new(),
        signature: Vec::new(),
        oracle_counter: 0,
        oracle_trace_hash: [0u8; 32],
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
    };
    let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([124u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_bulletin_commitment@v1".into(),
            params: vec![1],
        },
        signature_proof: SignatureProof::default(),
    }));
    let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([125u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
            params: vec![2],
        },
        signature_proof: SignatureProof::default(),
    }));
    let ordered_transactions =
        canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two]).unwrap();
    let tx_hashes: Vec<[u8; 32]> = ordered_transactions
        .iter()
        .map(|tx| tx.hash().unwrap())
        .collect();
    let mut header = base_header;
    header.transactions_root = canonical_transaction_root_from_hashes(&tx_hashes).unwrap();
    header.canonical_order_certificate = Some(
        build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
            .unwrap(),
    );
    let mut previous = CanonicalCollapseObject {
        height: header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [201u8; 32],
        resulting_state_root_hash: [202u8; 32],
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
    };
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    header.parent_state_root = StateRoot(previous.resulting_state_root_hash.to_vec());
    header.previous_canonical_collapse_commitment_hash =
        ioi_types::app::canonical_collapse_commitment_hash_from_object(&previous)
            .expect("previous canonical collapse commitment hash");
    header.canonical_collapse_extension_certificate = Some(
        ioi_types::app::canonical_collapse_extension_certificate(header.height, &previous).unwrap(),
    );
    let collapse = ioi_types::app::derive_canonical_collapse_object_with_previous(
        &header,
        &ordered_transactions,
        Some(&previous),
    )
    .expect("collapse");

    let mut state = MockState::default();
    state
        .insert(
            &aft_canonical_collapse_object_key(previous.height),
            &codec::to_bytes_canonical(&previous).unwrap(),
        )
        .unwrap();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_canonical_collapse_object@v1",
            &codec::to_bytes_canonical(&collapse).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let stored = state
        .get(&aft_canonical_collapse_object_key(collapse.height))
        .unwrap()
        .expect("canonical collapse object stored");
    let restored: CanonicalCollapseObject = codec::from_bytes_canonical(&stored).unwrap();
    assert_eq!(restored, collapse);
}
