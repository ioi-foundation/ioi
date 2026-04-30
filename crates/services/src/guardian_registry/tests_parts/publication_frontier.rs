#[test]
fn publishing_conflicting_aft_canonical_collapse_object_is_rejected() {
    let registry = production_registry();
    let previous = CanonicalCollapseObject {
        height: 46,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [138u8; 32],
        resulting_state_root_hash: [139u8; 32],
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
    };
    let mut collapse = CanonicalCollapseObject {
        height: 47,
        previous_canonical_collapse_commitment_hash:
            ioi_types::app::canonical_collapse_commitment_hash_from_object(&previous).unwrap(),
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering: ioi_types::app::CanonicalOrderingCollapse {
            height: 47,
            kind: CanonicalCollapseKind::Abort,
            ..Default::default()
        },
        sealing: None,
        transactions_root_hash: [140u8; 32],
        resulting_state_root_hash: [141u8; 32],
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
    };
    ioi_types::app::bind_canonical_collapse_continuity(&mut collapse, Some(&previous)).unwrap();
    let mut conflicting = collapse.clone();
    conflicting.resulting_state_root_hash = [142u8; 32];
    ioi_types::app::bind_canonical_collapse_continuity(&mut conflicting, Some(&previous)).unwrap();

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
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_canonical_collapse_object@v1",
            &codec::to_bytes_canonical(&conflicting).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("conflicting canonical collapse object already published"));
    });
}

#[test]
fn publishing_aft_canonical_collapse_object_with_wrong_previous_hash_is_rejected() {
    let registry = production_registry();
    let previous = CanonicalCollapseObject {
        height: 46,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [150u8; 32],
        resulting_state_root_hash: [151u8; 32],
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
    };
    let mut collapse = CanonicalCollapseObject {
        height: 47,
        previous_canonical_collapse_commitment_hash: [0xFFu8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering: ioi_types::app::CanonicalOrderingCollapse {
            height: 47,
            kind: CanonicalCollapseKind::Abort,
            ..Default::default()
        },
        sealing: None,
        transactions_root_hash: [152u8; 32],
        resulting_state_root_hash: [153u8; 32],
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
    };
    ioi_types::app::bind_canonical_collapse_continuity(&mut collapse, Some(&previous)).unwrap();
    collapse.previous_canonical_collapse_commitment_hash = [0xFFu8; 32];

    let mut state = MockState::default();
    state
        .insert(
            &aft_canonical_collapse_object_key(previous.height),
            &codec::to_bytes_canonical(&previous).unwrap(),
        )
        .unwrap();
    with_ctx(|ctx| {
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_canonical_collapse_object@v1",
            &codec::to_bytes_canonical(&collapse).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("canonical collapse continuity commitment hash mismatch"));
    });
}

#[test]
fn publishing_aft_canonical_order_artifact_bundle_with_missing_entry_is_rejected() {
    let registry = production_registry();
    let base_header = ioi_types::app::BlockHeader {
        height: 42,
        view: 4,
        parent_hash: [81u8; 32],
        parent_state_root: StateRoot(vec![1u8; 32]),
        state_root: StateRoot(vec![2u8; 32]),
        transactions_root: Vec::new(),
        timestamp: 1_760_000_555,
        timestamp_ms: 1_760_000_555_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([82u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [83u8; 32],
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
            account_id: AccountId([84u8; 32]),
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
            account_id: AccountId([85u8; 32]),
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
    let mut bundle = canonical_order_publication_bundle_with_retrievability(
        &certificate,
        build_bulletin_surface_entries(header.height, &ordered_transactions).unwrap(),
    );
    bundle.bulletin_entries.pop();

    let mut state = MockState::default();
    with_ctx(|ctx| {
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_canonical_order_artifact_bundle@v1",
            &codec::to_bytes_canonical(&bundle).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("published bulletin surface does not rebuild the bulletin commitment"));
    });
}

#[test]
fn publishing_aft_canonical_order_artifact_bundle_with_wrong_height_is_rejected() {
    let registry = production_registry();
    let base_header = ioi_types::app::BlockHeader {
        height: 43,
        view: 4,
        parent_hash: [91u8; 32],
        parent_state_root: StateRoot(vec![1u8; 32]),
        state_root: StateRoot(vec![2u8; 32]),
        transactions_root: Vec::new(),
        timestamp: 1_760_000_666,
        timestamp_ms: 1_760_000_666_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([92u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [93u8; 32],
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
            account_id: AccountId([94u8; 32]),
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
            account_id: AccountId([95u8; 32]),
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
    let mut bundle = canonical_order_publication_bundle_with_retrievability(
        &certificate,
        build_bulletin_surface_entries(header.height, &ordered_transactions).unwrap(),
    );
    bundle.bulletin_entries[0].height = header.height + 1;

    let mut state = MockState::default();
    with_ctx(|ctx| {
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_canonical_order_artifact_bundle@v1",
            &codec::to_bytes_canonical(&bundle).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("bulletin surface entries do not match the target slot height"));
    });
}

#[test]
fn publishing_aft_canonical_order_artifact_bundle_after_abort_is_rejected() {
    let registry = production_registry();
    let base_header = ioi_types::app::BlockHeader {
        height: 45,
        view: 4,
        parent_hash: [111u8; 32],
        parent_state_root: StateRoot(vec![1u8; 32]),
        state_root: StateRoot(vec![2u8; 32]),
        transactions_root: Vec::new(),
        timestamp: 1_760_000_777,
        timestamp_ms: 1_760_000_777_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([112u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [113u8; 32],
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
            account_id: AccountId([114u8; 32]),
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
            account_id: AccountId([115u8; 32]),
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
    let abort = CanonicalOrderAbort {
        height: header.height,
        reason: CanonicalOrderAbortReason::MissingOrderCertificate,
        details: "slot already collapsed to abort".into(),
        bulletin_commitment_hash: [116u8; 32],
        bulletin_availability_certificate_hash: [117u8; 32],
        bulletin_close_hash: [0u8; 32],
        canonical_order_certificate_hash: [0u8; 32],
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
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_canonical_order_artifact_bundle@v1",
            &codec::to_bytes_canonical(&bundle).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("after canonical abort publication"));
    });
}

#[test]
fn publishing_contradictory_shard_manifest_challenge_materializes_abort() {
    let registry = production_registry();
    let base_header = ioi_types::app::BlockHeader {
        height: 46,
        view: 5,
        parent_hash: [121u8; 32],
        parent_state_root: StateRoot(vec![11u8; 32]),
        state_root: StateRoot(vec![12u8; 32]),
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
            params: vec![3],
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
    let bundle = canonical_order_publication_bundle_with_retrievability(
        &certificate,
        build_bulletin_surface_entries(header.height, &ordered_transactions).unwrap(),
    );
    let mut contradictory_manifest = bundle.bulletin_shard_manifest.clone();
    contradictory_manifest.shard_commitment_root[0] ^= 0x7f;
    let challenge = BulletinRetrievabilityChallenge {
        height: header.height,
        kind: BulletinRetrievabilityChallengeKind::ContradictoryShardManifest,
        bulletin_commitment_hash: ioi_types::app::canonical_bulletin_commitment_hash(
            &bundle.bulletin_commitment,
        )
        .unwrap(),
        bulletin_availability_certificate_hash:
            ioi_types::app::canonical_bulletin_availability_certificate_hash(
                &bundle.bulletin_availability_certificate,
            )
            .unwrap(),
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &bundle.bulletin_retrievability_profile,
        )
        .unwrap(),
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(
            &contradictory_manifest,
        )
        .unwrap(),
        bulletin_custody_assignment_hash: [0u8; 32],
        bulletin_custody_receipt_hash: [0u8; 32],
        bulletin_custody_response_hash: [0u8; 32],
        details: "published shard manifest contradicts the deterministic slot geometry".into(),
    };

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_commitment_key(bundle.bulletin_commitment.height),
            &codec::to_bytes_canonical(&bundle.bulletin_commitment).unwrap(),
        )
        .unwrap();
    for entry in &bundle.bulletin_entries {
        state
            .insert(
                &aft_bulletin_entry_key(entry.height, &entry.tx_hash),
                &codec::to_bytes_canonical(entry).unwrap(),
            )
            .unwrap();
    }
    state
        .insert(
            &aft_bulletin_availability_certificate_key(
                bundle.bulletin_availability_certificate.height,
            ),
            &codec::to_bytes_canonical(&bundle.bulletin_availability_certificate).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_retrievability_profile_key(bundle.bulletin_retrievability_profile.height),
            &codec::to_bytes_canonical(&bundle.bulletin_retrievability_profile).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_shard_manifest_key(contradictory_manifest.height),
            &codec::to_bytes_canonical(&contradictory_manifest).unwrap(),
        )
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_bulletin_retrievability_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let stored_challenge: BulletinRetrievabilityChallenge = codec::from_bytes_canonical(
        &state
            .get(&aft_bulletin_retrievability_challenge_key(header.height))
            .unwrap()
            .expect("challenge stored"),
    )
    .unwrap();
    assert_eq!(stored_challenge, challenge);

    let abort: CanonicalOrderAbort = codec::from_bytes_canonical(
        &state
            .get(&aft_canonical_order_abort_key(header.height))
            .unwrap()
            .expect("abort stored"),
    )
    .unwrap();
    assert_eq!(
        abort.reason,
        CanonicalOrderAbortReason::RetrievabilityChallengeDominated
    );
    assert!(GuardianRegistry::extract_published_bulletin_surface(&state, header.height).is_err());
}

#[test]
fn publishing_missing_retrievability_profile_challenge_materializes_abort() {
    let registry = production_registry();
    let bundle = sample_canonical_order_publication_bundle_with_retrievability(48, 7, 141);
    let challenge = BulletinRetrievabilityChallenge {
        height: bundle.bulletin_commitment.height,
        kind: BulletinRetrievabilityChallengeKind::MissingRetrievabilityProfile,
        bulletin_commitment_hash: ioi_types::app::canonical_bulletin_commitment_hash(
            &bundle.bulletin_commitment,
        )
        .unwrap(),
        bulletin_availability_certificate_hash:
            ioi_types::app::canonical_bulletin_availability_certificate_hash(
                &bundle.bulletin_availability_certificate,
            )
            .unwrap(),
        bulletin_retrievability_profile_hash: [0u8; 32],
        bulletin_shard_manifest_hash: [0u8; 32],
        bulletin_custody_assignment_hash: [0u8; 32],
        bulletin_custody_receipt_hash: [0u8; 32],
        bulletin_custody_response_hash: [0u8; 32],
        details: "closed slot is missing its endogenous retrievability profile".into(),
    };

    let mut state = MockState::default();
    seed_endogenous_bulletin_surface_state(
        &mut state,
        &bundle,
        &bundle.bulletin_entries,
        false,
        false,
        false,
    );

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_bulletin_retrievability_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let abort: CanonicalOrderAbort = codec::from_bytes_canonical(
        &state
            .get(&aft_canonical_order_abort_key(
                bundle.bulletin_commitment.height,
            ))
            .unwrap()
            .expect("abort stored"),
    )
    .unwrap();
    assert_eq!(
        abort.reason,
        CanonicalOrderAbortReason::RetrievabilityChallengeDominated
    );
    assert_bulletin_reconstruction_abort_present(
        &state,
        bundle.bulletin_commitment.height,
        BulletinRetrievabilityChallengeKind::MissingRetrievabilityProfile,
    );
    assert!(GuardianRegistry::extract_published_bulletin_surface(
        &state,
        bundle.bulletin_commitment.height
    )
    .is_err());
}

#[test]
fn publishing_missing_shard_manifest_challenge_materializes_abort() {
    let registry = production_registry();
    let bundle = sample_canonical_order_publication_bundle_with_retrievability(49, 8, 151);
    let challenge = BulletinRetrievabilityChallenge {
        height: bundle.bulletin_commitment.height,
        kind: BulletinRetrievabilityChallengeKind::MissingShardManifest,
        bulletin_commitment_hash: ioi_types::app::canonical_bulletin_commitment_hash(
            &bundle.bulletin_commitment,
        )
        .unwrap(),
        bulletin_availability_certificate_hash:
            ioi_types::app::canonical_bulletin_availability_certificate_hash(
                &bundle.bulletin_availability_certificate,
            )
            .unwrap(),
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &bundle.bulletin_retrievability_profile,
        )
        .unwrap(),
        bulletin_shard_manifest_hash: [0u8; 32],
        bulletin_custody_assignment_hash: [0u8; 32],
        bulletin_custody_receipt_hash: [0u8; 32],
        bulletin_custody_response_hash: [0u8; 32],
        details: "closed slot is missing its deterministic shard manifest".into(),
    };

    let mut state = MockState::default();
    seed_endogenous_bulletin_surface_state(
        &mut state,
        &bundle,
        &bundle.bulletin_entries,
        true,
        false,
        false,
    );

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_bulletin_retrievability_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let abort: CanonicalOrderAbort = codec::from_bytes_canonical(
        &state
            .get(&aft_canonical_order_abort_key(
                bundle.bulletin_commitment.height,
            ))
            .unwrap()
            .expect("abort stored"),
    )
    .unwrap();
    assert_eq!(
        abort.reason,
        CanonicalOrderAbortReason::RetrievabilityChallengeDominated
    );
    assert_bulletin_reconstruction_abort_present(
        &state,
        bundle.bulletin_commitment.height,
        BulletinRetrievabilityChallengeKind::MissingShardManifest,
    );
    assert!(GuardianRegistry::extract_published_bulletin_surface(
        &state,
        bundle.bulletin_commitment.height
    )
    .is_err());
}

#[test]
fn publishing_missing_custody_receipt_challenge_materializes_abort() {
    let registry = production_registry();
    let bundle = sample_canonical_order_publication_bundle_with_retrievability(50, 9, 161);
    let (assignment_hash, _) =
        sample_bulletin_custody_plane_hashes(&bundle, &bundle.bulletin_entries);
    let challenge = BulletinRetrievabilityChallenge {
        height: bundle.bulletin_commitment.height,
        kind: BulletinRetrievabilityChallengeKind::MissingCustodyReceipt,
        bulletin_commitment_hash: ioi_types::app::canonical_bulletin_commitment_hash(
            &bundle.bulletin_commitment,
        )
        .unwrap(),
        bulletin_availability_certificate_hash:
            ioi_types::app::canonical_bulletin_availability_certificate_hash(
                &bundle.bulletin_availability_certificate,
            )
            .unwrap(),
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &bundle.bulletin_retrievability_profile,
        )
        .unwrap(),
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(
            &bundle.bulletin_shard_manifest,
        )
        .unwrap(),
        bulletin_custody_assignment_hash: assignment_hash,
        bulletin_custody_receipt_hash: [0u8; 32],
        bulletin_custody_response_hash: [0u8; 32],
        details: "closed slot is missing its deterministic custody receipt".into(),
    };

    let mut state = MockState::default();
    seed_endogenous_bulletin_surface_state(
        &mut state,
        &bundle,
        &bundle.bulletin_entries,
        true,
        true,
        false,
    );

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_bulletin_retrievability_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let abort: CanonicalOrderAbort = codec::from_bytes_canonical(
        &state
            .get(&aft_canonical_order_abort_key(
                bundle.bulletin_commitment.height,
            ))
            .unwrap()
            .expect("abort stored"),
    )
    .unwrap();
    assert_eq!(
        abort.reason,
        CanonicalOrderAbortReason::RetrievabilityChallengeDominated
    );
    assert_bulletin_reconstruction_abort_present(
        &state,
        bundle.bulletin_commitment.height,
        BulletinRetrievabilityChallengeKind::MissingCustodyReceipt,
    );
    assert!(GuardianRegistry::extract_published_bulletin_surface(
        &state,
        bundle.bulletin_commitment.height
    )
    .is_err());
}

#[test]
fn publishing_missing_custody_assignment_challenge_materializes_abort() {
    let registry = production_registry();
    let bundle = sample_canonical_order_publication_bundle_with_retrievability(50, 12, 191);
    let challenge = BulletinRetrievabilityChallenge {
        height: bundle.bulletin_commitment.height,
        kind: BulletinRetrievabilityChallengeKind::MissingCustodyAssignment,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(&bundle.bulletin_commitment)
            .unwrap(),
        bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
            &bundle.bulletin_availability_certificate,
        )
        .unwrap(),
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &bundle.bulletin_retrievability_profile,
        )
        .unwrap(),
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(
            &bundle.bulletin_shard_manifest,
        )
        .unwrap(),
        bulletin_custody_assignment_hash: [0u8; 32],
        bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(
            &bundle.bulletin_custody_receipt,
        )
        .unwrap(),
        bulletin_custody_response_hash: [0u8; 32],
        details: "closed slot is missing its deterministic custody assignment".into(),
    };

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_commitment_key(bundle.bulletin_commitment.height),
            &codec::to_bytes_canonical(&bundle.bulletin_commitment).unwrap(),
        )
        .unwrap();
    for entry in &bundle.bulletin_entries {
        state
            .insert(
                &aft_bulletin_entry_key(entry.height, &entry.tx_hash),
                &codec::to_bytes_canonical(entry).unwrap(),
            )
            .unwrap();
    }
    state
        .insert(
            &aft_bulletin_availability_certificate_key(
                bundle.bulletin_availability_certificate.height,
            ),
            &codec::to_bytes_canonical(&bundle.bulletin_availability_certificate).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_retrievability_profile_key(bundle.bulletin_retrievability_profile.height),
            &codec::to_bytes_canonical(&bundle.bulletin_retrievability_profile).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_shard_manifest_key(bundle.bulletin_shard_manifest.height),
            &codec::to_bytes_canonical(&bundle.bulletin_shard_manifest).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_custody_receipt_key(bundle.bulletin_custody_receipt.height),
            &codec::to_bytes_canonical(&bundle.bulletin_custody_receipt).unwrap(),
        )
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_bulletin_retrievability_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    assert_bulletin_reconstruction_abort_present(
        &state,
        bundle.bulletin_commitment.height,
        BulletinRetrievabilityChallengeKind::MissingCustodyAssignment,
    );
    assert!(GuardianRegistry::extract_published_bulletin_surface(
        &state,
        bundle.bulletin_commitment.height
    )
    .is_err());
}

#[test]
fn publishing_missing_surface_entries_challenge_materializes_abort() {
    let registry = production_registry();
    let bundle = sample_canonical_order_publication_bundle_with_retrievability(51, 10, 171);
    let (assignment_hash, response_hash) = sample_bulletin_custody_plane_hashes(&bundle, &[]);
    let challenge = BulletinRetrievabilityChallenge {
        height: bundle.bulletin_commitment.height,
        kind: BulletinRetrievabilityChallengeKind::MissingSurfaceEntries,
        bulletin_commitment_hash: ioi_types::app::canonical_bulletin_commitment_hash(
            &bundle.bulletin_commitment,
        )
        .unwrap(),
        bulletin_availability_certificate_hash:
            ioi_types::app::canonical_bulletin_availability_certificate_hash(
                &bundle.bulletin_availability_certificate,
            )
            .unwrap(),
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &bundle.bulletin_retrievability_profile,
        )
        .unwrap(),
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(
            &bundle.bulletin_shard_manifest,
        )
        .unwrap(),
        bulletin_custody_assignment_hash: assignment_hash,
        bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(
            &bundle.bulletin_custody_receipt,
        )
        .unwrap(),
        bulletin_custody_response_hash: response_hash,
        details: "closed slot carries no protocol-visible bulletin entries".into(),
    };

    let mut state = MockState::default();
    seed_endogenous_bulletin_surface_state(&mut state, &bundle, &[], true, true, true);

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_bulletin_retrievability_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let abort: CanonicalOrderAbort = codec::from_bytes_canonical(
        &state
            .get(&aft_canonical_order_abort_key(
                bundle.bulletin_commitment.height,
            ))
            .unwrap()
            .expect("abort stored"),
    )
    .unwrap();
    assert_eq!(
        abort.reason,
        CanonicalOrderAbortReason::RetrievabilityChallengeDominated
    );
    assert_bulletin_reconstruction_abort_present(
        &state,
        bundle.bulletin_commitment.height,
        BulletinRetrievabilityChallengeKind::MissingSurfaceEntries,
    );
    assert!(GuardianRegistry::extract_published_bulletin_surface(
        &state,
        bundle.bulletin_commitment.height
    )
    .is_err());
}

#[test]
fn publishing_missing_custody_response_challenge_materializes_abort() {
    let registry = production_registry();
    let bundle = sample_canonical_order_publication_bundle_with_retrievability(52, 13, 201);
    let validator_sets = validator_sets(&[(18, 1), (145, 1), (19, 1)]);
    let assignment = build_bulletin_custody_assignment(
        &bundle.bulletin_retrievability_profile,
        &bundle.bulletin_shard_manifest,
        &validator_sets.current,
    )
    .unwrap();
    let challenge = BulletinRetrievabilityChallenge {
        height: bundle.bulletin_commitment.height,
        kind: BulletinRetrievabilityChallengeKind::MissingCustodyResponse,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(&bundle.bulletin_commitment)
            .unwrap(),
        bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
            &bundle.bulletin_availability_certificate,
        )
        .unwrap(),
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &bundle.bulletin_retrievability_profile,
        )
        .unwrap(),
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(
            &bundle.bulletin_shard_manifest,
        )
        .unwrap(),
        bulletin_custody_assignment_hash: canonical_bulletin_custody_assignment_hash(&assignment)
            .unwrap(),
        bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(
            &bundle.bulletin_custody_receipt,
        )
        .unwrap(),
        bulletin_custody_response_hash: [0u8; 32],
        details: "closed slot is missing its deterministic custody response".into(),
    };

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_commitment_key(bundle.bulletin_commitment.height),
            &codec::to_bytes_canonical(&bundle.bulletin_commitment).unwrap(),
        )
        .unwrap();
    for entry in &bundle.bulletin_entries {
        state
            .insert(
                &aft_bulletin_entry_key(entry.height, &entry.tx_hash),
                &codec::to_bytes_canonical(entry).unwrap(),
            )
            .unwrap();
    }
    state
        .insert(
            &aft_bulletin_availability_certificate_key(
                bundle.bulletin_availability_certificate.height,
            ),
            &codec::to_bytes_canonical(&bundle.bulletin_availability_certificate).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_retrievability_profile_key(bundle.bulletin_retrievability_profile.height),
            &codec::to_bytes_canonical(&bundle.bulletin_retrievability_profile).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_shard_manifest_key(bundle.bulletin_shard_manifest.height),
            &codec::to_bytes_canonical(&bundle.bulletin_shard_manifest).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_custody_assignment_key(assignment.height),
            &codec::to_bytes_canonical(&assignment).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_custody_receipt_key(bundle.bulletin_custody_receipt.height),
            &codec::to_bytes_canonical(&bundle.bulletin_custody_receipt).unwrap(),
        )
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_bulletin_retrievability_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    assert_bulletin_reconstruction_abort_present(
        &state,
        bundle.bulletin_commitment.height,
        BulletinRetrievabilityChallengeKind::MissingCustodyResponse,
    );
    assert!(GuardianRegistry::extract_published_bulletin_surface(
        &state,
        bundle.bulletin_commitment.height
    )
    .is_err());
}

#[test]
fn publishing_invalid_surface_entries_challenge_materializes_abort() {
    let registry = production_registry();
    let bundle = sample_canonical_order_publication_bundle_with_retrievability(52, 11, 181);
    let mut invalid_entries = bundle.bulletin_entries.clone();
    invalid_entries[0].tx_hash[0] ^= 0x21;
    let (assignment_hash, response_hash) =
        sample_bulletin_custody_plane_hashes(&bundle, &invalid_entries);
    let challenge = BulletinRetrievabilityChallenge {
        height: bundle.bulletin_commitment.height,
        kind: BulletinRetrievabilityChallengeKind::InvalidSurfaceEntries,
        bulletin_commitment_hash: ioi_types::app::canonical_bulletin_commitment_hash(
            &bundle.bulletin_commitment,
        )
        .unwrap(),
        bulletin_availability_certificate_hash:
            ioi_types::app::canonical_bulletin_availability_certificate_hash(
                &bundle.bulletin_availability_certificate,
            )
            .unwrap(),
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &bundle.bulletin_retrievability_profile,
        )
        .unwrap(),
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(
            &bundle.bulletin_shard_manifest,
        )
        .unwrap(),
        bulletin_custody_assignment_hash: assignment_hash,
        bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(
            &bundle.bulletin_custody_receipt,
        )
        .unwrap(),
        bulletin_custody_response_hash: response_hash,
        details: "published bulletin entries do not reconstruct the committed surface".into(),
    };

    let mut state = MockState::default();
    seed_endogenous_bulletin_surface_state(&mut state, &bundle, &invalid_entries, true, true, true);

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_bulletin_retrievability_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let abort: CanonicalOrderAbort = codec::from_bytes_canonical(
        &state
            .get(&aft_canonical_order_abort_key(
                bundle.bulletin_commitment.height,
            ))
            .unwrap()
            .expect("abort stored"),
    )
    .unwrap();
    assert_eq!(
        abort.reason,
        CanonicalOrderAbortReason::RetrievabilityChallengeDominated
    );
    assert_bulletin_reconstruction_abort_present(
        &state,
        bundle.bulletin_commitment.height,
        BulletinRetrievabilityChallengeKind::InvalidSurfaceEntries,
    );
    assert!(GuardianRegistry::extract_published_bulletin_surface(
        &state,
        bundle.bulletin_commitment.height
    )
    .is_err());
}

#[test]
fn publishing_invalid_custody_response_challenge_materializes_abort() {
    let registry = production_registry();
    let bundle = sample_canonical_order_publication_bundle_with_retrievability(53, 14, 211);
    let validator_sets = validator_sets(&[(18, 1), (145, 1), (19, 1)]);
    let assignment = build_bulletin_custody_assignment(
        &bundle.bulletin_retrievability_profile,
        &bundle.bulletin_shard_manifest,
        &validator_sets.current,
    )
    .unwrap();
    let mut invalid_response = build_bulletin_custody_response(
        &bundle.bulletin_commitment,
        &bundle.bulletin_retrievability_profile,
        &bundle.bulletin_shard_manifest,
        &assignment,
        &bundle.bulletin_custody_receipt,
        &bundle.bulletin_entries,
    )
    .unwrap();
    invalid_response.served_shards[0].served_shard_hash[0] ^= 0x11;
    let challenge = BulletinRetrievabilityChallenge {
        height: bundle.bulletin_commitment.height,
        kind: BulletinRetrievabilityChallengeKind::InvalidCustodyResponse,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(&bundle.bulletin_commitment)
            .unwrap(),
        bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
            &bundle.bulletin_availability_certificate,
        )
        .unwrap(),
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &bundle.bulletin_retrievability_profile,
        )
        .unwrap(),
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(
            &bundle.bulletin_shard_manifest,
        )
        .unwrap(),
        bulletin_custody_assignment_hash: canonical_bulletin_custody_assignment_hash(&assignment)
            .unwrap(),
        bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(
            &bundle.bulletin_custody_receipt,
        )
        .unwrap(),
        bulletin_custody_response_hash: canonical_bulletin_custody_response_hash(&invalid_response)
            .unwrap(),
        details:
            "published custody response contradicts deterministic shard-service reconstruction"
                .into(),
    };

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_commitment_key(bundle.bulletin_commitment.height),
            &codec::to_bytes_canonical(&bundle.bulletin_commitment).unwrap(),
        )
        .unwrap();
    for entry in &bundle.bulletin_entries {
        state
            .insert(
                &aft_bulletin_entry_key(entry.height, &entry.tx_hash),
                &codec::to_bytes_canonical(entry).unwrap(),
            )
            .unwrap();
    }
    state
        .insert(
            &aft_bulletin_availability_certificate_key(
                bundle.bulletin_availability_certificate.height,
            ),
            &codec::to_bytes_canonical(&bundle.bulletin_availability_certificate).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_retrievability_profile_key(bundle.bulletin_retrievability_profile.height),
            &codec::to_bytes_canonical(&bundle.bulletin_retrievability_profile).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_shard_manifest_key(bundle.bulletin_shard_manifest.height),
            &codec::to_bytes_canonical(&bundle.bulletin_shard_manifest).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_custody_assignment_key(assignment.height),
            &codec::to_bytes_canonical(&assignment).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_custody_receipt_key(bundle.bulletin_custody_receipt.height),
            &codec::to_bytes_canonical(&bundle.bulletin_custody_receipt).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_custody_response_key(invalid_response.height),
            &codec::to_bytes_canonical(&invalid_response).unwrap(),
        )
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_bulletin_retrievability_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    assert_bulletin_reconstruction_abort_present(
        &state,
        bundle.bulletin_commitment.height,
        BulletinRetrievabilityChallengeKind::InvalidCustodyResponse,
    );
    assert!(GuardianRegistry::extract_published_bulletin_surface(
        &state,
        bundle.bulletin_commitment.height
    )
    .is_err());
}

#[test]
fn publishing_contradictory_custody_receipt_challenge_materializes_abort() {
    let registry = production_registry();
    let base_header = ioi_types::app::BlockHeader {
        height: 47,
        view: 6,
        parent_hash: [131u8; 32],
        parent_state_root: StateRoot(vec![21u8; 32]),
        state_root: StateRoot(vec![22u8; 32]),
        transactions_root: Vec::new(),
        timestamp: 1_760_000_999,
        timestamp_ms: 1_760_000_999_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([132u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [133u8; 32],
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
            account_id: AccountId([134u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_bulletin_commitment@v1".into(),
            params: vec![5],
        },
        signature_proof: SignatureProof::default(),
    }));
    let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([135u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
            params: vec![6],
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
    let mut contradictory_receipt = bundle.bulletin_custody_receipt.clone();
    contradictory_receipt.custody_root[0] ^= 0x44;
    let validator_sets = validator_sets(&[(18, 1), (145, 1), (19, 1)]);
    let assignment = build_bulletin_custody_assignment(
        &bundle.bulletin_retrievability_profile,
        &bundle.bulletin_shard_manifest,
        &validator_sets.current,
    )
    .unwrap();
    let challenge = BulletinRetrievabilityChallenge {
        height: header.height,
        kind: BulletinRetrievabilityChallengeKind::ContradictoryCustodyReceipt,
        bulletin_commitment_hash: ioi_types::app::canonical_bulletin_commitment_hash(
            &bundle.bulletin_commitment,
        )
        .unwrap(),
        bulletin_availability_certificate_hash:
            ioi_types::app::canonical_bulletin_availability_certificate_hash(
                &bundle.bulletin_availability_certificate,
            )
            .unwrap(),
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &bundle.bulletin_retrievability_profile,
        )
        .unwrap(),
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(
            &bundle.bulletin_shard_manifest,
        )
        .unwrap(),
        bulletin_custody_assignment_hash: canonical_bulletin_custody_assignment_hash(&assignment)
            .unwrap(),
        bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(
            &contradictory_receipt,
        )
        .unwrap(),
        bulletin_custody_response_hash: [0u8; 32],
        details: "published custody receipt contradicts the deterministic manifest binding".into(),
    };

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_commitment_key(bundle.bulletin_commitment.height),
            &codec::to_bytes_canonical(&bundle.bulletin_commitment).unwrap(),
        )
        .unwrap();
    for entry in &bundle.bulletin_entries {
        state
            .insert(
                &aft_bulletin_entry_key(entry.height, &entry.tx_hash),
                &codec::to_bytes_canonical(entry).unwrap(),
            )
            .unwrap();
    }
    state
        .insert(
            &aft_bulletin_availability_certificate_key(
                bundle.bulletin_availability_certificate.height,
            ),
            &codec::to_bytes_canonical(&bundle.bulletin_availability_certificate).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_retrievability_profile_key(bundle.bulletin_retrievability_profile.height),
            &codec::to_bytes_canonical(&bundle.bulletin_retrievability_profile).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_shard_manifest_key(bundle.bulletin_shard_manifest.height),
            &codec::to_bytes_canonical(&bundle.bulletin_shard_manifest).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_custody_receipt_key(contradictory_receipt.height),
            &codec::to_bytes_canonical(&contradictory_receipt).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_custody_assignment_key(assignment.height),
            &codec::to_bytes_canonical(&assignment).unwrap(),
        )
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_bulletin_retrievability_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let stored_challenge: BulletinRetrievabilityChallenge = codec::from_bytes_canonical(
        &state
            .get(&aft_bulletin_retrievability_challenge_key(header.height))
            .unwrap()
            .expect("challenge stored"),
    )
    .unwrap();
    assert_eq!(stored_challenge, challenge);

    let abort: CanonicalOrderAbort = codec::from_bytes_canonical(
        &state
            .get(&aft_canonical_order_abort_key(header.height))
            .unwrap()
            .expect("abort stored"),
    )
    .unwrap();
    assert_eq!(
        abort.reason,
        CanonicalOrderAbortReason::RetrievabilityChallengeDominated
    );
    assert!(GuardianRegistry::extract_published_bulletin_surface(&state, header.height).is_err());
}

#[test]
fn publishing_contradictory_custody_assignment_challenge_materializes_abort() {
    let registry = production_registry();
    let bundle = sample_canonical_order_publication_bundle_with_retrievability(54, 15, 221);
    let validator_sets = validator_sets(&[(18, 1), (145, 1), (19, 1)]);
    let mut contradictory_assignment = build_bulletin_custody_assignment(
        &bundle.bulletin_retrievability_profile,
        &bundle.bulletin_shard_manifest,
        &validator_sets.current,
    )
    .unwrap();
    contradictory_assignment.assignments[0].custodian_account_id = AccountId([209u8; 32]);
    let challenge = BulletinRetrievabilityChallenge {
        height: bundle.bulletin_commitment.height,
        kind: BulletinRetrievabilityChallengeKind::ContradictoryCustodyAssignment,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(&bundle.bulletin_commitment)
            .unwrap(),
        bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
            &bundle.bulletin_availability_certificate,
        )
        .unwrap(),
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            &bundle.bulletin_retrievability_profile,
        )
        .unwrap(),
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(
            &bundle.bulletin_shard_manifest,
        )
        .unwrap(),
        bulletin_custody_assignment_hash: canonical_bulletin_custody_assignment_hash(
            &contradictory_assignment,
        )
        .unwrap(),
        bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(
            &bundle.bulletin_custody_receipt,
        )
        .unwrap(),
        bulletin_custody_response_hash: [0u8; 32],
        details: "published custody assignment contradicts the deterministic validator-set binding"
            .into(),
    };

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_commitment_key(bundle.bulletin_commitment.height),
            &codec::to_bytes_canonical(&bundle.bulletin_commitment).unwrap(),
        )
        .unwrap();
    for entry in &bundle.bulletin_entries {
        state
            .insert(
                &aft_bulletin_entry_key(entry.height, &entry.tx_hash),
                &codec::to_bytes_canonical(entry).unwrap(),
            )
            .unwrap();
    }
    state
        .insert(
            &aft_bulletin_availability_certificate_key(
                bundle.bulletin_availability_certificate.height,
            ),
            &codec::to_bytes_canonical(&bundle.bulletin_availability_certificate).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_retrievability_profile_key(bundle.bulletin_retrievability_profile.height),
            &codec::to_bytes_canonical(&bundle.bulletin_retrievability_profile).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_shard_manifest_key(bundle.bulletin_shard_manifest.height),
            &codec::to_bytes_canonical(&bundle.bulletin_shard_manifest).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_custody_assignment_key(contradictory_assignment.height),
            &codec::to_bytes_canonical(&contradictory_assignment).unwrap(),
        )
        .unwrap();
    state
        .insert(
            &aft_bulletin_custody_receipt_key(bundle.bulletin_custody_receipt.height),
            &codec::to_bytes_canonical(&bundle.bulletin_custody_receipt).unwrap(),
        )
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_bulletin_retrievability_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    assert_bulletin_reconstruction_abort_present(
        &state,
        bundle.bulletin_commitment.height,
        BulletinRetrievabilityChallengeKind::ContradictoryCustodyAssignment,
    );
    assert!(GuardianRegistry::extract_published_bulletin_surface(
        &state,
        bundle.bulletin_commitment.height
    )
    .is_err());
}

#[test]
fn publishing_conflicting_publication_frontier_materializes_contradiction_and_abort() {
    let registry = production_registry();
    let frontier = PublicationFrontier {
        height: 54,
        view: 2,
        counter: 54,
        parent_frontier_hash: [1u8; 32],
        bulletin_commitment_hash: [2u8; 32],
        ordered_transactions_root_hash: [3u8; 32],
        availability_receipt_hash: [4u8; 32],
    };
    let conflicting = PublicationFrontier {
        view: 3,
        bulletin_commitment_hash: [5u8; 32],
        availability_receipt_hash: [6u8; 32],
        ..frontier.clone()
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_publication_frontier@v1",
            &codec::to_bytes_canonical(&frontier).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_publication_frontier@v1",
            &codec::to_bytes_canonical(&conflicting).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let contradiction: PublicationFrontierContradiction = codec::from_bytes_canonical(
        &state
            .get(&aft_publication_frontier_contradiction_key(frontier.height))
            .unwrap()
            .expect("contradiction stored"),
    )
    .unwrap();
    assert_eq!(
        contradiction.kind,
        PublicationFrontierContradictionKind::ConflictingFrontier
    );
    assert_eq!(contradiction.candidate_frontier, conflicting);
    assert_eq!(contradiction.reference_frontier, frontier);

    let abort: CanonicalOrderAbort = codec::from_bytes_canonical(
        &state
            .get(&aft_canonical_order_abort_key(54))
            .unwrap()
            .expect("abort stored"),
    )
    .unwrap();
    assert_eq!(
        abort.reason,
        CanonicalOrderAbortReason::PublicationFrontierConflict
    );
    assert!(state
        .get(&aft_publication_frontier_key(54))
        .unwrap()
        .is_none());
}

#[test]
fn publishing_stale_publication_frontier_materializes_contradiction_and_abort() {
    let registry = production_registry();
    let previous = PublicationFrontier {
        height: 63,
        view: 1,
        counter: 63,
        parent_frontier_hash: [7u8; 32],
        bulletin_commitment_hash: [8u8; 32],
        ordered_transactions_root_hash: [9u8; 32],
        availability_receipt_hash: [10u8; 32],
    };
    let stale = PublicationFrontier {
        height: 64,
        view: 2,
        counter: 64,
        parent_frontier_hash: [11u8; 32],
        bulletin_commitment_hash: [12u8; 32],
        ordered_transactions_root_hash: [13u8; 32],
        availability_receipt_hash: [14u8; 32],
    };

    let mut state = MockState::default();
    state
        .insert(
            &aft_publication_frontier_key(previous.height),
            &codec::to_bytes_canonical(&previous).unwrap(),
        )
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_publication_frontier@v1",
            &codec::to_bytes_canonical(&stale).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let contradiction: PublicationFrontierContradiction = codec::from_bytes_canonical(
        &state
            .get(&aft_publication_frontier_contradiction_key(stale.height))
            .unwrap()
            .expect("contradiction stored"),
    )
    .unwrap();
    assert_eq!(
        contradiction.kind,
        PublicationFrontierContradictionKind::StaleParentLink
    );
    assert_eq!(contradiction.candidate_frontier, stale);
    assert_eq!(contradiction.reference_frontier, previous);

    let abort: CanonicalOrderAbort = codec::from_bytes_canonical(
        &state
            .get(&aft_canonical_order_abort_key(64))
            .unwrap()
            .expect("abort stored"),
    )
    .unwrap();
    assert_eq!(
        abort.reason,
        CanonicalOrderAbortReason::PublicationFrontierStale
    );
    assert!(state
        .get(&aft_publication_frontier_key(64))
        .unwrap()
        .is_none());
}

#[test]
fn publishing_recovery_registry_objects_round_trips_and_preserves_multiple_receipts() {
    let registry = production_registry();
    let capsule = sample_recovery_capsule(71);
    let witness_manifest_hash = [17u8; 32];
    let certificate =
        sample_recovery_witness_certificate(&capsule, witness_manifest_hash, [18u8; 32]);
    let receipt_a = RecoveryShareReceipt {
        height: capsule.height,
        witness_manifest_hash,
        block_commitment_hash: [19u8; 32],
        share_commitment_hash: certificate.share_commitment_hash,
    };
    let receipt_b = RecoveryShareReceipt {
        height: capsule.height,
        witness_manifest_hash,
        block_commitment_hash: [20u8; 32],
        share_commitment_hash: certificate.share_commitment_hash,
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        for (method, params) in [
            (
                "publish_aft_recovery_capsule@v1",
                codec::to_bytes_canonical(&capsule).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate).unwrap(),
            ),
            (
                "publish_aft_recovery_share_receipt@v1",
                codec::to_bytes_canonical(&receipt_a).unwrap(),
            ),
            (
                "publish_aft_recovery_share_receipt@v1",
                codec::to_bytes_canonical(&receipt_b).unwrap(),
            ),
        ] {
            run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
        }
    });

    assert_eq!(
        GuardianRegistry::load_recovery_capsule(&state, capsule.height).unwrap(),
        Some(capsule.clone())
    );
    assert_eq!(
        GuardianRegistry::load_recovery_witness_certificate(
            &state,
            capsule.height,
            &witness_manifest_hash,
        )
        .unwrap(),
        Some(certificate.clone())
    );
    assert_eq!(
        GuardianRegistry::load_recovery_share_receipts(
            &state,
            capsule.height,
            &witness_manifest_hash
        )
        .unwrap(),
        vec![receipt_a.clone(), receipt_b.clone()]
    );
    assert_eq!(
        GuardianRegistry::load_missing_recovery_share(
            &state,
            capsule.height,
            &witness_manifest_hash
        )
        .unwrap(),
        None
    );
    assert!(state
        .get(&aft_recovery_capsule_key(capsule.height))
        .unwrap()
        .is_some());
    assert!(state
        .get(&aft_recovery_witness_certificate_key(
            capsule.height,
            &witness_manifest_hash,
        ))
        .unwrap()
        .is_some());
    assert!(state
        .get(&aft_recovery_share_receipt_key(
            capsule.height,
            &witness_manifest_hash,
            &receipt_a.block_commitment_hash,
        ))
        .unwrap()
        .is_some());
    assert!(state
        .get(&aft_recovery_share_receipt_key(
            capsule.height,
            &witness_manifest_hash,
            &receipt_b.block_commitment_hash,
        ))
        .unwrap()
        .is_some());
}

